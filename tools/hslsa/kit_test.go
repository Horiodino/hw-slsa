package hslsa

// The pilot kit's provenance: signed by the kit owner, checked by the
// recipient, and a detached signature openssl can check.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKitProvenance(t *testing.T) {
	dir := t.TempDir()
	owner, err := Keygen(dir, "kit-signer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(dir, "other"); err != nil {
		t.Fatal(err)
	}
	tarball := filepath.Join(dir, "kit.tar.gz")
	bin := filepath.Join(dir, "hslsa-linux-amd64")
	for p, body := range map[string]string{tarball: "the tarball", bin: "a binary"} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files := []KitFile{{"kit.tar.gz", tarball}, {"bin/hslsa-linux-amd64", bin}}
	prov := filepath.Join(dir, "kit.provenance.json")
	sig := filepath.Join(dir, "kit.tar.gz.sig")
	commit := strings.Repeat("ab", 20)

	if err := SignKit(owner, "abc123", files, prov, sig); err == nil {
		t.Fatal("signed a kit for a short commit id")
	}
	if err := SignKit(owner, commit, files, prov, sig); err != nil {
		t.Fatal(err)
	}

	pub := filepath.Join(dir, "kit-signer.pub.pem")
	got, err := VerifyKit(pub, prov, files)
	if err != nil {
		t.Fatal(err)
	}
	if got != commit {
		t.Fatalf("commit %s, want %s", got, commit)
	}

	// The detached signature is what openssl dgst -sha256 -verify checks.
	data, _ := os.ReadFile(tarball)
	raw, _ := os.ReadFile(sig)
	sum := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(owner.Key.Public, sum[:], raw) {
		t.Fatal("detached signature does not verify over the tarball")
	}

	refuse := func(why, pubPath string, fs []KitFile, want string) {
		t.Helper()
		_, err := VerifyKit(pubPath, prov, fs)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got %v, want an error containing %q", why, err, want)
		}
	}
	refuse("another key", filepath.Join(dir, "other.pub.pem"), files, "no valid signature")
	refuse("a file the provenance does not name", pub, []KitFile{{"bin/extra", bin}}, "does not name")
	if err := os.WriteFile(bin, []byte("a changed binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	refuse("a changed binary", pub, files, "but the provenance says")
}
