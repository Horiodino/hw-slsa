// Package hslsa is the reference tool for the Hardware Supply Chain Security
// Framework: it signs design, manufacturing, firmware and HBOM records as
// in-toto statements in DSSE envelopes, and walks the chain as a buyer would.
//
// Signing uses local ECDSA keys only. Nothing here requests an OIDC token or
// talks to a transparency log.
package hslsa

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ita1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	NS            = "https://github.com/Horiodino/hw-slsa"
	DesignFlow    = NS + "/design-flow/v0.1"
	MfgStep       = NS + "/manufacturing-step/v0.1"
	HBOMType      = NS + "/hbom/v0.1"
	VSAType       = "https://slsa.dev/verification_summary/v1"
	StatementType = "https://in-toto.io/Statement/v1"
	PayloadType   = "application/vnd.in-toto+json"
)

// DesignStepNames is the one list of design step names that hwFlow.step and
// the HBOM's design.flow[].step both use (spec: Design step names).
var DesignStepNames = []string{
	"source-freeze", "simulation", "synthesis", "floorplan", "place-cts", "routing",
	"signoff", "rom-merge", "gds-stream-out", "release", "rebuild", "other",
}

func designStepType(step string) string { return NS + "/design-flow/step/" + step + "@v1" }
func mfgStepType(step string) string    { return NS + "/mfg/step/" + step + "@v1" }

// VerificationError names the first broken link in a chain.
type VerificationError struct{ Msg string }

func (e *VerificationError) Error() string { return e.Msg }

func failf(format string, a ...any) error {
	return &VerificationError{Msg: fmt.Sprintf(format, a...)}
}

// IsVerificationError reports whether err is, or wraps, a VerificationError.
func IsVerificationError(err error) bool {
	var v *VerificationError
	return errors.As(err, &v)
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Bytes(data), nil
}

// fileDigest is the digest object of a file, or nil when it cannot be read,
// so a missing file fails a comparison rather than stopping a check.
func fileDigest(path string) Obj {
	d, err := sha256File(path)
	if err != nil {
		return nil
	}
	return Obj{"sha256": d}
}

// Now is the current UTC time in the records' format. Tests may replace it.
var Now = func() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

// rd is an in-toto ResourceDescriptor with a sha256 digest.
func rd(name, digest string) Obj {
	return Obj{"name": name, "digest": Obj{"sha256": digest}}
}

// fileRD describes a file; name defaults to its base name.
func fileRD(path, name string) (Obj, error) {
	d, err := sha256File(path)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = filepath.Base(path)
	}
	return rd(name, d), nil
}

// builder is the identity of the platform running a step, from GitHub Actions
// when present. HSLSA_BUILDER_ID overrides the id, for when one workflow hosts
// two parties, such as a flow and its rebuild.
func builder() Obj {
	run := Obj{"builder": Obj{"id": NS + "/local-run"}, "metadata": Obj{"invocationId": "local"}}
	server := os.Getenv("GITHUB_SERVER_URL")
	if server != "" && os.Getenv("GITHUB_WORKFLOW_REF") != "" {
		invocation := fmt.Sprintf("%s/%s/actions/runs/%s", server, os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID"))
		attempt, ok := os.LookupEnv("GITHUB_RUN_ATTEMPT")
		if !ok {
			attempt = "1"
		}
		run = Obj{
			"builder":  Obj{"id": server + "/" + os.Getenv("GITHUB_WORKFLOW_REF")},
			"metadata": Obj{"invocationId": invocation + "/attempts/" + attempt},
		}
	}
	if id := os.Getenv("HSLSA_BUILDER_ID"); id != "" {
		O(run, "builder")["id"] = id
	}
	return run
}

// githubSourceDep names this repository's commit when running in GitHub Actions.
func githubSourceDep() Obj {
	sha := os.Getenv("GITHUB_SHA")
	if sha == "" {
		return nil
	}
	return Obj{
		"name":   "hw-slsa",
		"digest": Obj{"gitCommit": sha},
		"uri":    "git+" + os.Getenv("GITHUB_SERVER_URL") + "/" + os.Getenv("GITHUB_REPOSITORY"),
	}
}

func statement(subjects []Obj, predicateType string, predicate Obj) (Obj, error) {
	stmt := Obj{
		"_type":         StatementType,
		"subject":       subjects,
		"predicateType": predicateType,
		"predicate":     predicate,
	}
	if err := validateStatement(stmt); err != nil {
		return nil, err
	}
	return stmt, nil
}

// validateStatement is a structural check with the in-toto attestation reference library.
func validateStatement(stmt any) error {
	var pb ita1.Statement
	if err := protojson.Unmarshal(compactJSON(stmt), &pb); err != nil {
		return failf("invalid in-toto statement: %v", err)
	}
	if err := pb.Validate(); err != nil {
		return failf("invalid in-toto statement: %v", err)
	}
	return nil
}

// Keys

// Key is a public key as the trust root and DSSE signatures name it.
type Key struct {
	ID     string
	Scheme string
	PEM    string
	Public *ecdsa.PublicKey
}

func schemeFor(pub *ecdsa.PublicKey) (string, error) {
	switch pub.Curve {
	case elliptic.P256():
		return "ecdsa-sha2-nistp256", nil
	case elliptic.P384():
		return "ecdsa-sha2-nistp384", nil
	case elliptic.P521():
		return "ecdsa-sha2-nistp521", nil
	}
	return "", fmt.Errorf("unsupported curve %s", pub.Curve.Params().Name)
}

func publicPEM(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// canonicalString is a string in OLPC canonical JSON: only \ and " are escaped.
func canonicalString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// NewKey describes a public key. Its keyid is the one securesystemslib
// computes: sha256 of the canonical JSON of keytype, scheme and PEM.
func NewKey(pub *ecdsa.PublicKey) (Key, error) {
	scheme, err := schemeFor(pub)
	if err != nil {
		return Key{}, err
	}
	p, err := publicPEM(pub)
	if err != nil {
		return Key{}, err
	}
	canon := `{"keytype":"ecdsa","keyval":{"public":` + canonicalString(p) + `},"scheme":` + canonicalString(scheme) + `}`
	return Key{ID: sha256Bytes([]byte(canon)), Scheme: scheme, PEM: p, Public: pub}, nil
}

// PublicKeyFromPEM parses a PEM public key.
func PublicKeyFromPEM(text string) (Key, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return Key{}, errors.New("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return Key{}, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return Key{}, errors.New("not an ECDSA public key")
	}
	return NewKey(ec)
}

func parsePrivatePEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ec, ok := k.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, errors.New("not an ECDSA private key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func privatePEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Signer signs DSSE envelopes with one ECDSA key.
type Signer struct {
	Key  Key
	priv *ecdsa.PrivateKey
	sv   *signerverifier.ECDSASignerVerifier
}

func newSigner(priv *ecdsa.PrivateKey) (*Signer, error) {
	key, err := NewKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	privPEM, err := privatePEM(priv)
	if err != nil {
		return nil, err
	}
	sv, err := signerverifier.NewECDSASignerVerifierFromSSLibKey(&signerverifier.SSLibKey{
		KeyID:   key.ID,
		KeyType: "ecdsa",
		Scheme:  key.Scheme,
		KeyVal:  signerverifier.KeyVal{Public: key.PEM, Private: string(privPEM)},
	})
	if err != nil {
		return nil, err
	}
	return &Signer{Key: key, priv: priv, sv: sv}, nil
}

// LoadSigner reads a PEM private key (PKCS#8 or SEC 1).
func LoadSigner(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	priv, err := parsePrivatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return newSigner(priv)
}

// Keygen writes <role>.key.pem (mode 0600) and <role>.pub.pem, ECDSA P-256.
func Keygen(outDir, role string) (*Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s, err := newSigner(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	privPEM, err := privatePEM(priv)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(outDir, role+".key.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return nil, err
	}
	return s, os.WriteFile(filepath.Join(outDir, role+".pub.pem"), []byte(s.Key.PEM), 0o644)
}

// Sign signs a statement into a DSSE envelope at path and describes the envelope file.
func Sign(stmt Obj, signer *Signer, path string) (Obj, error) {
	if err := validateStatement(stmt); err != nil {
		return nil, err
	}
	es, err := dsse.NewEnvelopeSigner(signer.sv)
	if err != nil {
		return nil, err
	}
	env, err := es.SignPayload(context.Background(), PayloadType, compactJSON(stmt))
	if err != nil {
		return nil, err
	}
	sigs := make([]any, 0, len(env.Signatures))
	for _, s := range env.Signatures {
		sigs = append(sigs, Obj{"keyid": s.KeyID, "sig": s.Sig})
	}
	out := Obj{"payload": env.Payload, "payloadType": env.PayloadType, "signatures": sigs}
	if err := WriteJSON(path, out); err != nil {
		return nil, err
	}
	return fileRD(path, "")
}

// DecodeEnvelope returns the statement in an envelope without checking its signature.
func DecodeEnvelope(path string) (Obj, error) {
	env, err := ReadObj(path)
	if err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(S(env, "payload"))
	if err != nil {
		return nil, fmt.Errorf("%s: payload is not base64: %w", path, err)
	}
	v, err := decodeJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("%s: payload: %w", path, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: payload is not a statement", path)
	}
	return m, nil
}

// TrustRoot says which public keys may sign for which role.
//
// File format: {"roles": {"<role>": ["<PEM public key>", ...]}}
type TrustRoot struct {
	Roles map[string][]Key
}

// LoadTrustRoot reads a trust root file.
func LoadTrustRoot(path string) (*TrustRoot, error) {
	data, err := ReadObj(path)
	if err != nil {
		return nil, err
	}
	t := &TrustRoot{Roles: map[string][]Key{}}
	for role := range O(data, "roles") {
		for _, p := range Strs(data, "roles", role) {
			k, err := PublicKeyFromPEM(p)
			if err != nil {
				return nil, fmt.Errorf("%s: role %s: %w", path, role, err)
			}
			t.Roles[role] = append(t.Roles[role], k)
		}
	}
	return t, nil
}

// BuildTrustRoot collects <role>.pub.pem files from pubDir into a trust root.
func BuildTrustRoot(pubDir, outPath string) error {
	pubs, err := filepath.Glob(filepath.Join(pubDir, "*.pub.pem"))
	if err != nil {
		return err
	}
	roles := Obj{}
	for _, p := range pubs {
		text, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		role := strings.TrimSuffix(filepath.Base(p), ".pub.pem")
		list, _ := roles[role].([]any)
		roles[role] = append(list, string(text))
	}
	return WriteJSON(outPath, Obj{"roles": roles})
}

// Open verifies that the envelope at path was signed by role and returns its
// statement, with any withheld fields put back from the bundle's disclosures.
// A record that withholds a field nobody disclosed fails to open.
func (t *TrustRoot) Open(path, role, predicateType string) (Obj, error) {
	name := filepath.Base(path)
	if _, err := os.Stat(path); err != nil {
		return nil, failf("missing attestation %s", name)
	}
	raw, err := ReadObj(path)
	if err != nil {
		return nil, failf("%s: not a DSSE envelope: %v", name, err)
	}
	if S(raw, "payloadType") != PayloadType {
		return nil, failf("%s: unexpected payload type %s", name, S(raw, "payloadType"))
	}
	env := &dsse.Envelope{PayloadType: S(raw, "payloadType"), Payload: S(raw, "payload")}
	for _, s := range Objs(raw, "signatures") {
		env.Signatures = append(env.Signatures, dsse.Signature{KeyID: S(s, "keyid"), Sig: S(s, "sig")})
	}
	var verifiers []dsse.Verifier
	for _, k := range t.Roles[role] {
		sv, err := signerverifier.NewECDSASignerVerifierFromSSLibKey(&signerverifier.SSLibKey{
			KeyID: k.ID, KeyType: "ecdsa", Scheme: k.Scheme, KeyVal: signerverifier.KeyVal{Public: k.PEM},
		})
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, sv)
	}
	noSig := failf("%s: no valid signature from role '%s'", name, role)
	if len(verifiers) == 0 {
		return nil, noSig
	}
	ev, err := dsse.NewEnvelopeVerifier(verifiers...)
	if err != nil {
		return nil, err
	}
	_, payload, err := ev.VerifyAndDecode(context.Background(), env)
	if err != nil {
		return nil, noSig
	}
	v, err := decodeJSON(payload)
	if err != nil {
		return nil, failf("%s: payload is not JSON: %v", name, err)
	}
	if err := validateStatement(v); err != nil {
		return nil, err
	}
	stmt := v.(map[string]any)
	if predicateType != "" && S(stmt, "predicateType") != predicateType {
		return nil, failf("%s: predicate type %s, want %s", name, S(stmt, "predicateType"), predicateType)
	}
	return reveal(path, stmt)
}
