package hslsa

// Firmware reference values as a signed CoRIM (draft-ietf-rats-corim-11),
// encoded and decoded with Veraison's corim library, and the appraisal of
// DICE TcbInfo evidence against them.
//
// Each reference value is a CoMID reference-value triple. Its environment is
// the DICE layer a TcbInfo describes, and its measurement holds the FWIDs and
// SVN that layer may report:
//
//	TcbInfo field      CoMID
//	type               class-id, as tagged bytes (CBOR tag 560)
//	vendor, model      class vendor, model
//	layer, index       class layer, index
//	svn                svn, exact value
//	fwids              digests (sha-256, sha-384 or sha-512)
//
// A TcbInfo field that is absent is left out of the class. When appraising,
// a reference value applies to a TcbInfo when every class field it names has
// the same value there, as in CoRIM environment matching.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
)

const (
	// CoRIMProfile is the profile every HSLSA CoRIM names (spec: Firmware reference values).
	CoRIMProfile = NS + "/corim-profile/v0.1"
	// CoRIMMediaType is the media type of a signed CoRIM.
	CoRIMMediaType = "application/rim+cose"
)

// DiceEnv is the DICE layer a reference value applies to, from TcbInfo.
type DiceEnv struct {
	Type, Vendor, Model string
	Layer, Index        *uint64
}

func (e DiceEnv) String() string {
	parts := []string{}
	if e.Type != "" {
		parts = append(parts, "type "+e.Type)
	}
	if e.Vendor != "" {
		parts = append(parts, "vendor "+e.Vendor)
	}
	if e.Model != "" {
		parts = append(parts, "model "+e.Model)
	}
	if e.Layer != nil {
		parts = append(parts, fmt.Sprintf("layer %d", *e.Layer))
	}
	if e.Index != nil {
		parts = append(parts, fmt.Sprintf("index %d", *e.Index))
	}
	return strings.Join(parts, ", ")
}

// matches reports whether evidence from layer o is in e: every field e names has the same value in o.
// A field e leaves out matches anything, as in CoRIM environment matching.
func (e DiceEnv) matches(o DiceEnv) bool {
	opt := func(a, b *uint64) bool { return a == nil || (b != nil && *a == *b) }
	str := func(a, b string) bool { return a == "" || a == b }
	return str(e.Type, o.Type) && str(e.Vendor, o.Vendor) && str(e.Model, o.Model) && opt(e.Layer, o.Layer) && opt(e.Index, o.Index)
}

func (e DiceEnv) equal(o DiceEnv) bool {
	eq := func(a, b *uint64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	return e.Type == o.Type && e.Vendor == o.Vendor && e.Model == o.Model && eq(e.Layer, o.Layer) && eq(e.Index, o.Index)
}

// RefValue is one reference value: a DICE layer, the FWIDs it may report and its SVN.
type RefValue struct {
	Env     DiceEnv
	Digests []FWID
	SVN     *uint64
}

func (r RefValue) String() string {
	var ds []string
	for _, d := range r.Digests {
		ds = append(ds, hashName[d.HashAlg]+":"+d.Digest)
	}
	s := r.Env.String() + ": " + strings.Join(ds, ", ")
	if r.SVN != nil {
		s += fmt.Sprintf(", svn %d", *r.SVN)
	}
	return s
}

func (r RefValue) equal(o RefValue) bool {
	return r.Env.equal(o.Env) && slices.Equal(r.Digests, o.Digests) &&
		(r.SVN == nil) == (o.SVN == nil) && (r.SVN == nil || *r.SVN == *o.SVN)
}

// DICE FWID hash OIDs and their CoRIM (IANA Named Information) algorithm ids.
var (
	hashAlgID = map[string]int{
		"2.16.840.1.101.3.4.2.1": comid.Sha256,
		SHA384OID:                comid.Sha384,
		"2.16.840.1.101.3.4.2.3": comid.Sha512,
	}
	hashName = map[string]string{
		"2.16.840.1.101.3.4.2.1": "sha-256",
		SHA384OID:                "sha-384",
		"2.16.840.1.101.3.4.2.3": "sha-512",
	}
)

func hashOID(alg int) (string, bool) {
	for oid, id := range hashAlgID {
		if id == alg {
			return oid, true
		}
	}
	return "", false
}

// EnvOf is the DICE layer a TcbInfo describes.
func EnvOf(t TcbInfo) DiceEnv {
	return DiceEnv{Type: t.Type, Vendor: t.Vendor, Model: t.Model, Layer: t.Layer, Index: t.Index}
}

// CoRIM is a signed CoRIM, decoded.
type CoRIM struct {
	ID, Profile, Signer string
	RefValues           []RefValue
	signed              *corim.SignedCorim
}

// BuildCoRIM makes an unsigned CoRIM with one CoMID holding the reference values.
func BuildCoRIM(id, creator string, refs []RefValue) (*corim.UnsignedCorim, error) {
	c := comid.NewComid().
		SetTagIdentity(id, 0).
		AddEntity(creator, nil, comid.RoleCreator, comid.RoleTagCreator)
	if c == nil {
		return nil, errors.New("corim: bad tag identity or entity")
	}
	for _, r := range refs {
		class := &comid.Class{}
		if r.Env.Type != "" {
			cid, err := comid.NewBytesClassID([]byte(r.Env.Type))
			if err != nil {
				return nil, err
			}
			class.ClassID = cid
		}
		if r.Env.Vendor != "" {
			class.Vendor = &r.Env.Vendor
		}
		if r.Env.Model != "" {
			class.Model = &r.Env.Model
		}
		class.Layer, class.Index = r.Env.Layer, r.Env.Index
		m := &comid.Measurement{}
		for _, d := range r.Digests {
			alg, ok := hashAlgID[d.HashAlg]
			if !ok {
				return nil, fmt.Errorf("corim: unsupported FWID hash %s", d.HashAlg)
			}
			value, err := hex.DecodeString(d.Digest)
			if err != nil {
				return nil, fmt.Errorf("corim: digest %q: %w", d.Digest, err)
			}
			m.AddDigest(alg, value)
		}
		if r.SVN != nil {
			m.SetSVN(*r.SVN)
		}
		triple := &comid.ValueTriple{Environment: comid.Environment{Class: class}, Measurements: *comid.NewMeasurements().Add(m)}
		if c.AddReferenceValue(triple) == nil {
			return nil, fmt.Errorf("corim: invalid reference value for %s", r.Env)
		}
	}
	if err := c.Valid(); err != nil {
		return nil, fmt.Errorf("corim: %w", err)
	}
	uc := corim.NewUnsignedCorim().SetID(id).AddComid(c).SetProfile(CoRIMProfile)
	if uc == nil {
		return nil, errors.New("corim: bad id, CoMID or profile")
	}
	if uc.AddEntity(creator, nil, corim.RoleManifestCreator) == nil {
		return nil, errors.New("corim: bad entity")
	}
	return uc, uc.Valid()
}

func coseAlg(pub *ecdsa.PublicKey) (cose.Algorithm, error) {
	switch pub.Curve {
	case elliptic.P256():
		return cose.AlgorithmES256, nil
	case elliptic.P384():
		return cose.AlgorithmES384, nil
	case elliptic.P521():
		return cose.AlgorithmES512, nil
	}
	return 0, fmt.Errorf("unsupported curve %s", pub.Curve.Params().Name)
}

// SignCoRIM wraps an unsigned CoRIM in COSE_Sign1, signed by signer, whose
// DSSE keyid goes in the kid header and whose role name in corim-meta.
func SignCoRIM(uc *corim.UnsignedCorim, signer *Signer, role string) ([]byte, error) {
	alg, err := coseAlg(signer.Key.Public)
	if err != nil {
		return nil, err
	}
	cs, err := cose.NewSigner(alg, signer.priv)
	if err != nil {
		return nil, err
	}
	kid, err := hex.DecodeString(signer.Key.ID)
	if err != nil {
		return nil, err
	}
	sc := corim.SignedCorim{UnsignedCorim: *uc, KeyID: kid}
	if sc.Meta.SetSigner(role, nil) == nil {
		return nil, errors.New("corim: bad signer name")
	}
	return sc.Sign(cs)
}

// WriteCoRIM builds, signs and writes a CoRIM holding refs.
func WriteCoRIM(path, id, creator, role string, refs []RefValue, signer *Signer) error {
	uc, err := BuildCoRIM(id, creator, refs)
	if err != nil {
		return err
	}
	data, err := SignCoRIM(uc, signer, role)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ParseCoRIM decodes and validates a signed CoRIM without checking its signature.
func ParseCoRIM(data []byte) (*CoRIM, error) {
	sc, err := corim.UnmarshalAndValidateSignedCorimFromCBOR(data)
	if err != nil {
		return nil, err
	}
	out := &CoRIM{ID: sc.UnsignedCorim.GetID(), Signer: sc.Meta.Signer.Name, signed: sc}
	if sc.UnsignedCorim.Profile != nil {
		out.Profile = sc.UnsignedCorim.Profile.String()
	}
	for i, tag := range sc.UnsignedCorim.Tags {
		if tag.Number != corim.ComidTag {
			continue
		}
		c, err := corim.UnmarshalComidFromCBOR(tag.Content, sc.UnsignedCorim.Profile)
		if err != nil {
			return nil, fmt.Errorf("CoMID tag %d: %w", i, err)
		}
		for triple := range c.IterRefVals() {
			refs, err := refValues(triple)
			if err != nil {
				return nil, fmt.Errorf("CoMID tag %d: %w", i, err)
			}
			out.RefValues = append(out.RefValues, refs...)
		}
	}
	return out, nil
}

func refValues(t *comid.ValueTriple) ([]RefValue, error) {
	env := t.Environment
	if env.Instance != nil || env.Group != nil || env.Class == nil {
		return nil, errors.New("reference value for an instance or group; HSLSA firmware reference values name a class")
	}
	var e DiceEnv
	if cid := env.Class.ClassID; cid != nil {
		if cid.Type() != comid.BytesType {
			return nil, fmt.Errorf("class-id of type %s; the DICE type is tagged bytes", cid.Type())
		}
		e.Type = string(cid.Bytes())
	}
	if env.Class.Vendor != nil {
		e.Vendor = *env.Class.Vendor
	}
	if env.Class.Model != nil {
		e.Model = *env.Class.Model
	}
	e.Layer, e.Index = env.Class.Layer, env.Class.Index
	if e.matches(DiceEnv{}) {
		return nil, errors.New("reference value names no DICE layer")
	}
	var out []RefValue
	for _, m := range t.Measurements.Values {
		if m.Key != nil && m.Key.IsSet() {
			return nil, errors.New("measurement with a key; a DICE layer has one unkeyed measurement")
		}
		r := RefValue{Env: e}
		if m.Val.Digests != nil {
			for _, d := range *m.Val.Digests {
				oid, ok := hashOID(d.Algorithm.Int())
				if !ok {
					return nil, fmt.Errorf("unsupported digest algorithm %s", d.Algorithm)
				}
				r.Digests = append(r.Digests, FWID{HashAlg: oid, Digest: hex.EncodeToString(d.Value)})
			}
		}
		if m.Val.SVN != nil {
			svn, ok := m.Val.SVN.Value.(*comid.TaggedSVN)
			if !ok {
				return nil, fmt.Errorf("svn of type %s; HSLSA reference values give an exact SVN", m.Val.SVN.Value.Type())
			}
			v := svn.Uint64()
			r.SVN = &v
		}
		if len(r.Digests) == 0 {
			return nil, fmt.Errorf("reference value for %s has no digest", e)
		}
		out = append(out, r)
	}
	return out, nil
}

// OpenCoRIM reads a signed CoRIM, requires a valid signature from one of keys
// and the HSLSA profile, and returns its reference values.
func OpenCoRIM(path string, keys []Key, label string) (*CoRIM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, failf("%s: %v", label, err)
	}
	c, err := ParseCoRIM(data)
	if err != nil {
		return nil, failf("%s: not a valid signed CoRIM: %v", label, err)
	}
	verified := false
	for _, k := range keys {
		if c.signed.Verify(k.Public) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, failf("%s: signature does not verify with any allowed key", label)
	}
	if c.Profile != CoRIMProfile {
		return nil, failf("%s: profile is %q, not %s", label, c.Profile, CoRIMProfile)
	}
	return c, nil
}

// Appraise matches one TcbInfo the device reported against the reference
// values: some reference value for its layer must list one of its FWIDs under
// the same algorithm, list no other digest under that algorithm, and give the
// same SVN, when it gives one. It reports false when no reference value names
// the layer, so the caller decides whether the layer needs one.
func Appraise(refs []RefValue, tcb TcbInfo) (bool, error) {
	env := EnvOf(tcb)
	named := false
	for _, r := range refs {
		if !r.Env.matches(env) {
			continue
		}
		named = true
		if r.SVN != nil && (!tcb.HasSVN || tcb.SVN < 0 || uint64(tcb.SVN) != *r.SVN) {
			continue
		}
		if digestsMatch(r.Digests, tcb.FWIDs) {
			return true, nil
		}
	}
	if !named {
		return false, nil
	}
	return true, fmt.Errorf("measurement of %s matches no reference value", env)
}

// digestsMatch: every algorithm the evidence and reference share agrees, and they share at least one.
func digestsMatch(ref, ev []FWID) bool {
	shared := false
	for _, e := range ev {
		var want []string
		for _, r := range ref {
			if r.HashAlg == e.HashAlg {
				want = append(want, r.Digest)
			}
		}
		if len(want) == 0 {
			continue
		}
		if !slices.Contains(want, e.Digest) {
			return false
		}
		shared = true
	}
	return shared
}

// AppraiseCerts appraises every TcbInfo in the given DICE certificates against
// a CoRIM's reference values. It returns one line per TcbInfo, and fails when a
// TcbInfo that has reference values matches none, or when none has any.
func AppraiseCerts(refs []RefValue, certs []*x509.Certificate, names []string) ([]string, error) {
	var lines []string
	matched := 0
	for i, cert := range certs {
		infos, err := TcbInfos(cert)
		if err != nil {
			return lines, failf("%s: unreadable TcbInfo: %v", names[i], err)
		}
		for _, t := range infos {
			named, err := Appraise(refs, t)
			switch {
			case err != nil:
				return lines, failf("%s: %v", names[i], err)
			case named:
				matched++
				lines = append(lines, fmt.Sprintf("%s: %s matches a reference value", names[i], EnvOf(t)))
			default:
				lines = append(lines, fmt.Sprintf("%s: %s has no reference value in this CoRIM", names[i], EnvOf(t)))
			}
		}
	}
	if matched == 0 {
		return lines, failf("no measurement in the certificates has a reference value in the CoRIM")
	}
	return lines, nil
}
