//go:build cgo

package hslsa

// HSM signing against SoftHSM2. The tests skip when SoftHSM2 is not
// installed, unless HSLSA_REQUIRE_PKCS11 is set, as CI sets it.

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

const testTokenPIN = "1234"

type softToken struct{ module, label string }

// softHSM makes one SoftHSM2 token per test binary. SoftHSM reads its
// configuration when the module is first initialized, so it is set once here.
func softHSM(t *testing.T) softToken {
	t.Helper()
	module := os.Getenv("HSLSA_TEST_PKCS11_MODULE")
	if module == "" {
		for _, p := range []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so", "/opt/homebrew/lib/softhsm/libsofthsm2.so"} {
			if fileExists(p) {
				module = p
				break
			}
		}
	}
	_, utilErr := exec.LookPath("softhsm2-util")
	if module == "" || utilErr != nil {
		if os.Getenv("HSLSA_REQUIRE_PKCS11") != "" {
			t.Fatal("SoftHSM2 is not installed and HSLSA_REQUIRE_PKCS11 is set")
		}
		t.Skip("SoftHSM2 not installed (apt install softhsm2)")
	}
	shared(t, "softhsm", func(dir string) error {
		if err := os.MkdirAll(filepath.Join(dir, "tokens"), 0o755); err != nil {
			return err
		}
		conf := filepath.Join(dir, "softhsm2.conf")
		if err := os.WriteFile(conf, []byte("directories.tokendir = "+filepath.Join(dir, "tokens")+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0o644); err != nil {
			return err
		}
		os.Setenv("SOFTHSM2_CONF", conf)
		out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "hslsa-test", "--pin", testTokenPIN, "--so-pin", "5678").CombinedOutput()
		if err != nil {
			return fmt.Errorf("softhsm2-util --init-token: %v: %s", err, out)
		}
		return nil
	})
	t.Setenv(PKCS11PINEnv, testTokenPIN)
	t.Setenv(PKCS11ModuleEnv, "")
	return softToken{module: module, label: "hslsa-test"}
}

// keyName is a label no other test uses, so tests can share the token.
func keyName(t *testing.T, suffix string) string {
	return strings.NewReplacer("/", "-").Replace(t.Name()) + suffix
}

func TestHSMKeySignsRecords(t *testing.T) {
	tok := softHSM(t)
	keys := t.TempDir()
	role := keyName(t, "")
	gen := ok(HSMKeygen(tok.module, tok.label, "", keys, role))

	if fileExists(filepath.Join(keys, role+".key.pem")) {
		t.Fatal("hsm keygen wrote a private key file")
	}
	ref := string(ok(os.ReadFile(filepath.Join(keys, role+PKCS11RefSuffix))))
	if strings.Contains(ref, testTokenPIN) || strings.Contains(ref, "pin") {
		t.Fatalf("%s%s holds the PIN: %s", role, PKCS11RefSuffix, ref)
	}

	// The <role>.key.pem path every command takes finds the HSM key, as do the reference file and the URI.
	for _, key := range []string{filepath.Join(keys, role+".key.pem"), filepath.Join(keys, role+PKCS11RefSuffix), strings.TrimSpace(ref)} {
		s := ok(LoadSigner(key))
		if s.Key.ID != gen.Key.ID {
			t.Fatalf("%s: key id %s, want %s", key, s.Key.ID, gen.Key.ID)
		}
	}

	signer := ok(LoadSigner(filepath.Join(keys, role+".key.pem")))
	digest := sha256.Sum256([]byte("lot"))
	stmt := ok(statement([]Obj{{"name": "urn:hslsa:lot:HSM-1", "digest": Obj{"sha256": sha256Bytes(digest[:])}}}, MfgStep, Obj{"step": "final-test"}))
	env := filepath.Join(t.TempDir(), "final-test.intoto.json")
	ok(Sign(stmt, signer, env))

	pub := ok(PublicKeyFromPEM(string(ok(os.ReadFile(filepath.Join(keys, role+".pub.pem"))))))
	if _, err := trustWith("test-site", pub).Open(env, "test-site", MfgStep); err != nil {
		t.Fatalf("the HSM-signed record does not verify: %v", err)
	}
	other := ok(Keygen(t.TempDir(), "test-site"))
	rejects(t, ok2(trustWith("test-site", other.Key).Open(env, "test-site", MfgStep)), "no valid signature")
}

// ok2 keeps the error of a two-value call.
func ok2[T any](_ T, err error) error { return err }

func TestHSMKeySignsBlobsReportsAndCoRIMs(t *testing.T) {
	tok := softHSM(t)
	keys := t.TempDir()
	signer := ok(HSMKeygen(tok.module, tok.label, "", keys, keyName(t, "")))

	blob := ok(signBlob([]byte("boot manifest"), signer))
	if payload, _, err := openBlob(blob); err != nil || string(payload) != "boot manifest" {
		t.Fatalf("signed blob: %q, %v", payload, err)
	}

	for _, format := range []string{SFRFormatJWS, SFRFormatCoRIM} {
		r := signedReport(t, signer, format, nil)
		if err := r.Verify(signer.Key.Public); err != nil {
			t.Fatalf("%s report signed in the HSM: %v", format, err)
		}
	}

	path := filepath.Join(t.TempDir(), "fw.corim")
	must(t, WriteCoRIM(path, "test-fw", "test platform", "firmware-platform", CaliptraRefValues(fmcDigest, rtDigest, 1), signer))
	if _, err := OpenCoRIM(path, []Key{signer.Key}, "corim"); err != nil {
		t.Fatalf("CoRIM signed in the HSM: %v", err)
	}
}

// genRaw makes a key pair on the token directly, with attributes hsm keygen would not set.
func genRaw(t *testing.T, tok softToken, privLabel, pubLabel string, id []byte, sensitive, extractable bool) {
	t.Helper()
	ctx, sh := ok2s(openPKCS11Session(ok(parsePKCS11URI(PKCS11KeyURI(tok.module, tok.label, "x")))))
	params := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	_, _, err := ctx.GenerateKeyPair(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubLabel),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, sensitive),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, privLabel),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
	must(t, err)
	ctx.CloseSession(sh)
}

func ok2s[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func TestHSMRefusesKeysThatCanLeave(t *testing.T) {
	tok := softHSM(t)
	for name, attrs := range map[string][2]bool{"extractable": {true, true}, "not-sensitive": {false, false}} {
		label := keyName(t, name)
		genRaw(t, tok, label, label, []byte(label), attrs[0], attrs[1])
		_, err := LoadSigner(PKCS11KeyURI(tok.module, tok.label, label))
		if err == nil || !strings.Contains(err.Error(), "can leave the HSM") {
			t.Errorf("%s key: got %v, want a refusal", name, err)
		}
	}
}

func TestHSMRefusesMismatchedPublicKey(t *testing.T) {
	tok := softHSM(t)
	label := keyName(t, "")
	// The private key labelled label sits beside the public half of another pair with its label and id.
	genRaw(t, tok, label, label+"-unused", []byte("A"+label), true, false)
	genRaw(t, tok, label+"-other", label, []byte("A"+label), true, false)
	_, err := LoadSigner(PKCS11KeyURI(tok.module, tok.label, label))
	if err == nil || !strings.Contains(err.Error(), "does not match the private key") {
		t.Fatalf("got %v, want a mismatch", err)
	}
}

func TestHSMKeyLookupErrors(t *testing.T) {
	tok := softHSM(t)
	keys := t.TempDir()
	role := keyName(t, "")
	ok(HSMKeygen(tok.module, tok.label, "", keys, role))
	uri := PKCS11KeyURI(tok.module, tok.label, role)

	if _, err := HSMKeygen(tok.module, tok.label, "", keys, role); err == nil || !strings.Contains(err.Error(), "already has a key") {
		t.Errorf("second keygen for %s: got %v", role, err)
	}
	// A wrong PIN cannot be tested here: PKCS#11 logs a whole process in, and
	// earlier tests already have. e2e/run.sh hsm runs the tool as its own process.
	for what, c := range map[string]struct{ uri, pin, want string }{
		"no PIN":        {uri, "", "no PIN"},
		"unknown key":   {PKCS11KeyURI(tok.module, tok.label, role+"-missing"), testTokenPIN, "0 EC private keys"},
		"unknown token": {PKCS11KeyURI(tok.module, "no-such-token", role), testTokenPIN, "no PKCS#11 token"},
		"bad module":    {PKCS11KeyURI("/nonexistent/libpkcs11.so", tok.label, role), testTokenPIN, "cannot load"},
	} {
		t.Setenv(PKCS11PINEnv, c.pin)
		if _, err := LoadSigner(c.uri); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", what, err, c.want)
		}
	}
	// A key file still wins over a reference file beside it.
	t.Setenv(PKCS11PINEnv, testTokenPIN)
	file := ok(Keygen(keys, role))
	if s := ok(LoadSigner(filepath.Join(keys, role+".key.pem"))); s.Key.ID != file.Key.ID {
		t.Fatal("a <role>.pkcs11 file shadowed the <role>.key.pem beside it")
	}
}
