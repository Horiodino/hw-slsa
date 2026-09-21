//go:build cgo

package hslsa

// Signing with a key held in an HSM, through its PKCS#11 module. The key
// never leaves the HSM: the tool finds it by URI, refuses it unless the HSM
// marks it sensitive and not extractable, and asks the HSM for each signature.
// Everything that takes a key file takes such a key; see docs/hsm-signing.md.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// Each module is initialized once per process; C_Initialize fails if called twice.
var (
	p11Mu      sync.Mutex
	p11Modules = map[string]*pkcs11.Ctx{}
)

func openPKCS11Module(path string) (*pkcs11.Ctx, error) {
	p11Mu.Lock()
	defer p11Mu.Unlock()
	if ctx, ok := p11Modules[path]; ok {
		return ctx, nil
	}
	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, fmt.Errorf("cannot load PKCS#11 module %s", path)
	}
	if err := ctx.Initialize(); err != nil && !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		ctx.Destroy()
		return nil, fmt.Errorf("PKCS#11 module %s: %w", path, err)
	}
	p11Modules[path] = ctx
	return ctx, nil
}

func isCKR(err error, code uint) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && uint(e) == code
}

// openPKCS11Session opens a logged-in session on the one token the URI matches.
func openPKCS11Session(u *pkcs11URI) (*pkcs11.Ctx, pkcs11.SessionHandle, error) {
	ctx, err := openPKCS11Module(u.module)
	if err != nil {
		return nil, 0, err
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, 0, err
	}
	var match []uint
	for _, s := range slots {
		if u.slot != nil && s != *u.slot {
			continue
		}
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			return nil, 0, err
		}
		if u.token != "" && strings.TrimRight(info.Label, " \x00") != u.token {
			continue
		}
		if u.serial != "" && strings.TrimRight(info.SerialNumber, " \x00") != u.serial {
			continue
		}
		match = append(match, s)
	}
	switch {
	case len(match) == 0:
		return nil, 0, fmt.Errorf("no PKCS#11 token %q in %s", u.token, u.module)
	case len(match) > 1:
		return nil, 0, fmt.Errorf("%d PKCS#11 tokens match %q in %s; name one by serial= or slot-id=", len(match), u.token, u.module)
	}
	sh, err := ctx.OpenSession(match[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, 0, err
	}
	if u.pin == "" {
		ctx.CloseSession(sh)
		return nil, 0, fmt.Errorf("no PIN for PKCS#11 token %q: set %s or give pin-source in the URI", u.token, PKCS11PINEnv)
	}
	if err := ctx.Login(sh, pkcs11.CKU_USER, u.pin); err != nil && !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		ctx.CloseSession(sh)
		return nil, 0, fmt.Errorf("PKCS#11 login to token %q: %w", u.token, err)
	}
	return ctx, sh, nil
}

// findPKCS11Objects returns the EC objects of class that carry the URI's label and id.
func findPKCS11Objects(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle, class uint, label string, id []byte) ([]pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
	}
	if label != "" {
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if id != nil {
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if err := ctx.FindObjectsInit(sh, tmpl); err != nil {
		return nil, err
	}
	objs, _, err := ctx.FindObjects(sh, 2)
	if ferr := ctx.FindObjectsFinal(sh); err == nil {
		err = ferr
	}
	return objs, err
}

func attrBool(a *pkcs11.Attribute) bool { return len(a.Value) == 1 && a.Value[0] != 0 }

// Named curves by the DER of their OID, as CKA_EC_PARAMS holds them.
var p11Curves = []struct {
	oid   asn1.ObjectIdentifier
	curve elliptic.Curve
}{
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, elliptic.P256()},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 34}, elliptic.P384()},
	{asn1.ObjectIdentifier{1, 3, 132, 0, 35}, elliptic.P521()},
}

func p11PublicKey(params, point []byte) (*ecdsa.PublicKey, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil {
		return nil, fmt.Errorf("CKA_EC_PARAMS is not a named curve: %w", err)
	}
	var curve elliptic.Curve
	for _, c := range p11Curves {
		if c.oid.Equal(oid) {
			curve = c.curve
		}
	}
	if curve == nil {
		return nil, fmt.Errorf("unsupported curve %s", oid)
	}
	// CKA_EC_POINT is a DER OCTET STRING around the point; a few modules omit the wrapping.
	var raw []byte
	if rest, err := asn1.Unmarshal(point, &raw); err != nil || len(rest) > 0 {
		raw = point
	}
	return ecdsa.ParseUncompressedPublicKey(curve, raw)
}

// hsmKey is a crypto.Signer whose private half stays in the HSM.
type hsmKey struct {
	mu  sync.Mutex
	ctx *pkcs11.Ctx
	sh  pkcs11.SessionHandle
	obj pkcs11.ObjectHandle
	pub *ecdsa.PublicKey
}

func (k *hsmKey) Public() crypto.PublicKey { return k.pub }

// Sign signs a digest with CKM_ECDSA and returns the ASN.1 form crypto.Signer promises.
func (k *hsmKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ctx.SignInit(k.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, k.obj); err != nil {
		return nil, fmt.Errorf("PKCS#11 sign: %w", err)
	}
	rs, err := k.ctx.Sign(k.sh, digest)
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 sign: %w", err)
	}
	if len(rs) == 0 || len(rs)%2 != 0 {
		return nil, errors.New("PKCS#11 sign: malformed signature")
	}
	n := len(rs) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(rs[:n]), new(big.Int).SetBytes(rs[n:])})
}

// loadPKCS11Signer opens the private key a PKCS#11 URI names. It must be the
// only match, marked CKA_SENSITIVE and not CKA_EXTRACTABLE, with a public key
// object of the same label and id, and the two must make a valid signature.
func loadPKCS11Signer(uri string) (*Signer, error) {
	u, err := parsePKCS11URI(uri)
	if err != nil {
		return nil, err
	}
	return openPKCS11Key(u)
}

func openPKCS11Key(u *pkcs11URI) (*Signer, error) {
	ctx, sh, err := openPKCS11Session(u)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Signer, error) {
		ctx.CloseSession(sh)
		return nil, err
	}
	privs, err := findPKCS11Objects(ctx, sh, pkcs11.CKO_PRIVATE_KEY, u.object, u.id)
	if err != nil {
		return fail(err)
	}
	if len(privs) != 1 {
		return fail(fmt.Errorf("%d EC private keys on token %q match object=%q; want exactly one", len(privs), u.token, u.object))
	}
	attrs, err := ctx.GetAttributeValue(sh, privs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return fail(err)
	}
	if !attrBool(attrs[0]) || attrBool(attrs[1]) {
		return fail(fmt.Errorf("key %q on token %q can leave the HSM (CKA_SENSITIVE false or CKA_EXTRACTABLE true); generate one that cannot with hslsa hsm keygen", u.object, u.token))
	}
	if !attrBool(attrs[2]) {
		return fail(fmt.Errorf("key %q on token %q is not allowed to sign (CKA_SIGN false)", u.object, u.token))
	}
	pubs, err := findPKCS11Objects(ctx, sh, pkcs11.CKO_PUBLIC_KEY, string(attrs[3].Value), attrs[4].Value)
	if err != nil {
		return fail(err)
	}
	if len(pubs) != 1 {
		return fail(fmt.Errorf("key %q on token %q: found %d public key objects with its label and id, want one", u.object, u.token, len(pubs)))
	}
	pa, err := ctx.GetAttributeValue(sh, pubs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return fail(err)
	}
	pub, err := p11PublicKey(pa[0].Value, pa[1].Value)
	if err != nil {
		return fail(fmt.Errorf("key %q on token %q: %w", u.object, u.token, err))
	}
	key := &hsmKey{ctx: ctx, sh: sh, obj: privs[0], pub: pub}
	// A public key object that is not the private key's other half would make
	// every signature fail to verify, far from here; catch it now.
	probe := sha256.Sum256([]byte("hslsa pkcs11 key check"))
	sig, err := key.Sign(rand.Reader, probe[:], crypto.SHA256)
	if err != nil {
		return fail(err)
	}
	if !ecdsa.VerifyASN1(pub, probe[:], sig) {
		return fail(fmt.Errorf("key %q on token %q: its public key object does not match the private key", u.object, u.token))
	}
	return newSigner(key)
}

// HSMKeygen generates an ECDSA P-256 key for role on a token, as an HSM-held
// site key should be: sensitive, not extractable, usable only to sign. It
// writes <role>.pkcs11 (the key's URI, no PIN) and <role>.pub.pem to outDir.
// It refuses a role that already has a key on the token.
func HSMKeygen(module, token, pin, outDir, role string) (*Signer, error) {
	uri := PKCS11KeyURI(module, token, role)
	u, err := parsePKCS11URI(uri)
	if err != nil {
		return nil, err
	}
	if pin != "" {
		u.pin = pin
	}
	ctx, sh, err := openPKCS11Session(u)
	if err != nil {
		return nil, err
	}
	defer ctx.CloseSession(sh)
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		objs, err := findPKCS11Objects(ctx, sh, class, role, nil)
		if err != nil {
			return nil, err
		}
		if len(objs) > 0 {
			return nil, fmt.Errorf("token %q already has a key labelled %q", token, role)
		}
	}
	params, err := asn1.Marshal(p11Curves[0].oid)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, role),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, role),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	if _, _, err := ctx.GenerateKeyPair(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pubTmpl, privTmpl); err != nil {
		return nil, fmt.Errorf("PKCS#11 key generation on token %q: %w", token, err)
	}
	s, err := openPKCS11Key(u)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outDir, role+PKCS11RefSuffix), []byte(uri+"\n"), 0o644); err != nil {
		return nil, err
	}
	return s, os.WriteFile(filepath.Join(outDir, role+".pub.pem"), []byte(s.Key.PEM), 0o644)
}
