package hslsa

// Die identities for the chip tracks at L3 (spec, "Core requirements"):
//
//	Wafer L3         identities provisioned at sort are rooted in an on-die
//	                 root of trust (DICE or Caliptra class) and issued by an
//	                 HSM-backed CA
//	Package/Test L3  every unit answers an identity challenge at final test,
//	                 rooted in hardware, and the shipped lot digest covers the
//	                 units' certificate digests; at lot receipt each unit
//	                 answers a challenge again
//
// The die's root of trust is simulated here, the way the FPGA board's root
// of trust is (rot.go): a DICE engine that holds a unique device secret (UDS)
// burned at wafer sort, derives its compound device identifier (CDI) from the
// UDS and the measurement of the design it runs, and derives its IDevID key
// from the CDI. The key never leaves the die: the sort station gets a CSR the
// die signed with it, the identity CA endorses the CSR, and every challenge
// after that is answered by the die signing a fresh nonce. A unit's device
// directory (devices/<serial>/die.json) is the physical part: what the buyer
// holds on its bench, not part of the bundle.

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// DieIdentities is wafer sort's list of the identities it provisioned, one per passing die.
	DieIdentities = "die-identities.json"
	// UnitIdentities maps each unit final test challenged to its certificate digest.
	UnitIdentities = "unit-identities.json"
	// IdentityChallenges holds final test's challenge to each unit and the unit's answer.
	IdentityChallenges = "identity-challenges.json"
	// IdentityDir holds the identity certificates in the bundle's artifacts, by die.
	IdentityDir = "identity"
	// ChallengeFormat names how a unit answers a challenge: an ECDSA
	// signature with its IDevID key over sha256(ChallengeFormat || 0x00 || nonce).
	ChallengeFormat = "hslsa-identity-challenge/v1"
	// IdentityCARole signs unit identity certificates.
	IdentityCARole = "identity-ca"
	dieFile        = "die.json"
)

// simDie is one simulated die: its UDS, burned at sort, and the measurement
// its DICE engine takes of the design at power on.
type simDie struct {
	UDS     []byte
	Measure string // sha256 of the released design the die was made from
	Cert    []byte // the IDevID certificate, written to the part once endorsed
}

func dieName(wafer any, x, y any) string { return fmt.Sprintf("%v-%v-%v", wafer, num(x), num(y)) }

// newDie burns a fresh UDS into a die of the released design.
func newDie(measure string) (*simDie, error) {
	uds := make([]byte, 32)
	if _, err := rand.Read(uds); err != nil {
		return nil, err
	}
	return &simDie{UDS: uds, Measure: measure}, nil
}

// cdi is the die's compound device identifier: HMAC-SHA256 keyed by the UDS
// over the measurement of what it runs.
func (d *simDie) cdi() []byte {
	m := hmac.New(sha256.New, d.UDS)
	m.Write([]byte("DICE CDI\x00" + d.Measure))
	return m.Sum(nil)
}

func (d *simDie) idevid() (*ecdsa.PrivateKey, error) { return deriveKey(d.cdi(), "IDevID") }

// UEID is the die's universal entity id: type 1 (random), then 16 bytes the
// die derives from its UDS.
func (d *simDie) UEID() []byte {
	h := sha256.Sum256(append([]byte("UEID\x00"), d.UDS...))
	return append([]byte{1}, h[:16]...)
}

// CSR is what the die hands the sort station: a request signed with its IDevID key.
func (d *simDie) CSR(model string) ([]byte, error) {
	key, err := d.idevid()
	if err != nil {
		return nil, err
	}
	name, err := utf8Name(fmt.Sprintf("%s IDevID %s", model, hex.EncodeToString(d.UEID())))
	if err != nil {
		return nil, err
	}
	ext, err := ueidExtension(d.UEID())
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject: name, ExtraExtensions: []pkix.Extension{ext}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
}

// Answer signs a challenge nonce with the die's IDevID key.
func (d *simDie) Answer(nonce []byte) ([]byte, error) {
	key, err := d.idevid()
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, key, challengeDigest(nonce))
}

func challengeDigest(nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte(ChallengeFormat))
	h.Write([]byte{0})
	h.Write(nonce)
	return h.Sum(nil)
}

func (d *simDie) save(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return WriteJSON(filepath.Join(dir, dieFile), Obj{
		"note":    "Simulated die: its UDS stands in for a secret no one can read out of real silicon. This file is the physical part, not a record.",
		"uds":     hex.EncodeToString(d.UDS),
		"measure": d.Measure,
		"idevid":  base64.StdEncoding.EncodeToString(d.Cert),
	})
}

func loadDie(dir string) (*simDie, error) {
	o, err := ReadObj(filepath.Join(dir, dieFile))
	if err != nil {
		return nil, err
	}
	uds, err := hex.DecodeString(S(o, "uds"))
	if err != nil || len(uds) == 0 {
		return nil, fmt.Errorf("%s: no UDS", dir)
	}
	cert, err := base64.StdEncoding.DecodeString(S(o, "idevid"))
	if err != nil {
		return nil, err
	}
	return &simDie{UDS: uds, Measure: S(o, "measure"), Cert: cert}, nil
}

// IdentityCA issues IDevID certificates from CSRs, with a key that a
// buyer-run trust root records as held in an HSM.
type identityCA struct {
	signer *Signer
	name   []byte
}

func loadIdentityCA(keysDir, caName string) (*identityCA, error) {
	s, err := LoadSigner(filepath.Join(keysDir, IdentityCARole+".key.pem"))
	if err != nil {
		return nil, fmt.Errorf("identity CA: %w", err)
	}
	name, err := utf8Name(caName)
	if err != nil {
		return nil, err
	}
	return &identityCA{signer: s, name: name}, nil
}

// endorse checks the CSR's own signature (the die holds the key) and issues
// the certificate, keeping the subject and the UEID the die asked for.
func (ca *identityCA) endorse(csrDER []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("identity CA: the CSR is not signed by the key it names: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial.Add(serial, big.NewInt(1)),
		RawSubject:         csr.RawSubject,
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		ExtraExtensions:    csr.Extensions,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	parent := &x509.Certificate{RawSubject: ca.name, PublicKey: ca.signer.Key.Public}
	return x509.CreateCertificate(rand.Reader, tmpl, parent, csr.PublicKey, ca.signer.priv)
}

// identityCert parses a unit identity certificate and finds the identity CA
// key in the trust root that signed it, which it returns with the cert.
func identityCert(trust *TrustRoot, der []byte, label string) (*x509.Certificate, Key, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, Key{}, failf("%s: identity certificate does not parse: %v", label, err)
	}
	for _, k := range trust.Roles[IdentityCARole] {
		if signedBy(cert, k.Public) {
			if _, _, ok := UEID(cert); !ok {
				return nil, Key{}, failf("%s: identity certificate carries no UEID", label)
			}
			return cert, k, nil
		}
	}
	return nil, Key{}, failf("%s: identity certificate is not signed by an identity CA in the trust root", label)
}

// answered reports whether sig answers the challenge nonce under the certificate's key.
func answered(cert *x509.Certificate, nonce, sig []byte) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && ecdsa.VerifyASN1(pub, challengeDigest(nonce), sig)
}

// newNonce is a fresh 32-byte challenge.
func newNonce() ([]byte, error) {
	n := make([]byte, 32)
	_, err := rand.Read(n)
	return n, err
}

// ChallengeUnit challenges the part in devDir with a fresh nonce, as a
// tester or a buyer's bench does, and returns its certificate and answer.
// A unit without a die that answers is an error.
func ChallengeUnit(devDir string) (nonce, cert, sig []byte, err error) {
	if nonce, err = newNonce(); err != nil {
		return nil, nil, nil, err
	}
	d, err := loadDie(devDir)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(d.Cert) == 0 {
		return nil, nil, nil, errors.New(devDir + ": the part holds no identity certificate")
	}
	sig, err = d.Answer(nonce)
	return nonce, d.Cert, sig, err
}

// ChallengeParts challenges every part in dir (one directory per part, as
// the buyer received them) and returns their unit names: the digests of the
// certificates they answered under, each signed by an identity CA in the
// trust root.
func ChallengeParts(trust *TrustRoot, dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var units []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d, err := checkChallenge(trust, filepath.Join(dir, e.Name()), "", "received part "+e.Name())
		if err != nil {
			return nil, err
		}
		units = append(units, d)
	}
	if len(units) == 0 {
		return nil, fmt.Errorf("%s: no parts to challenge", dir)
	}
	return units, nil
}

// checkChallenge challenges the part in devDir and checks the answer: the
// certificate is signed by an identity CA in the trust root and its digest
// is want, when want is set, and the signature over the fresh nonce verifies
// under the certificate's key. It returns the certificate's digest.
func checkChallenge(trust *TrustRoot, devDir, want, label string) (string, error) {
	nonce, der, sig, err := ChallengeUnit(devDir)
	if err != nil {
		return "", failf("%s: the part does not answer an identity challenge: %v", label, err)
	}
	cert, _, err := identityCert(trust, der, label)
	if err != nil {
		return "", err
	}
	d := sha256Bytes(der)
	if want != "" && d != want {
		return "", failf("%s: answers with identity certificate sha256:%s, not the one its records name (sha256:%s)", label, short(d), short(want))
	}
	if !answered(cert, nonce, sig) {
		return "", failf("%s: the answer to the identity challenge does not verify under its certificate's key", label)
	}
	return d, nil
}
