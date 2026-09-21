package hslsa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPKCS11URIParsing(t *testing.T) {
	t.Setenv(PKCS11ModuleEnv, "")
	t.Setenv(PKCS11PINEnv, "")
	pinFile := filepath.Join(t.TempDir(), "pin")
	must(t, os.WriteFile(pinFile, []byte("12 34\n"), 0o600))

	u := ok(parsePKCS11URI("pkcs11:token=Site%20A;object=fab-site;id=%01%02;slot-id=3;type=private?module-path=/opt/hsm/lib.so&pin-source=file://" + pinFile))
	if u.token != "Site A" || u.object != "fab-site" || string(u.id) != "\x01\x02" || *u.slot != 3 || u.module != "/opt/hsm/lib.so" || u.pin != "12 34" {
		t.Fatalf("parsed %+v", u)
	}

	// What the URI leaves out comes from the environment.
	t.Setenv(PKCS11ModuleEnv, "/env/lib.so")
	t.Setenv(PKCS11PINEnv, "env-pin")
	u = ok(parsePKCS11URI("pkcs11:object=k"))
	if u.module != "/env/lib.so" || u.pin != "env-pin" {
		t.Fatalf("parsed %+v", u)
	}

	// The URI keygen writes reads back as written, and carries no PIN.
	uri := PKCS11KeyURI("/usr/lib/soft hsm.so", "tok;en", "role/1")
	if strings.Contains(uri, "pin") {
		t.Fatalf("key URI carries a PIN: %s", uri)
	}
	u = ok(parsePKCS11URI(uri))
	if u.module != "/usr/lib/soft hsm.so" || u.token != "tok;en" || u.object != "role/1" {
		t.Fatalf("round trip of %s gave %+v", uri, u)
	}

	t.Setenv(PKCS11ModuleEnv, "")
	for uri, want := range map[string]string{
		"pkcs11:object=k;type=public?module-path=/m": "type=private",
		"pkcs11:token=t?module-path=/m":              "names no key",
		"pkcs11:object=k":                            "no module-path",
		"pkcs11:object=k;slot-id=x?module-path=/m":   "slot-id",
		"pkcs11:object=%zz?module-path=/m":           "object",
		"file:/k.pem":                                "not a PKCS#11 URI",
	} {
		if _, err := parsePKCS11URI(uri); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error about %q", uri, err, want)
		}
	}
}
