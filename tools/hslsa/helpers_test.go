package hslsa

// Shared test helpers. Tests that need a produced bundle find it through an
// environment variable (defaulting to out/...) and skip when it is absent.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// root is the repository root; go test runs in tools/hslsa.
var root, _ = filepath.Abs("../..")

var (
	fixtureDir  string
	fixtureMu   sync.Mutex
	fixtures    = map[string]string{}
	fixtureErrs = map[string]error{}
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "hslsa-test-")
	if err != nil {
		panic(err)
	}
	fixtureDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// shared builds a fixture directory once per test binary, like a session-scoped pytest fixture.
func shared(t *testing.T, name string, build func(dir string) error) string {
	t.Helper()
	fixtureMu.Lock()
	defer fixtureMu.Unlock()
	if dir, ok := fixtures[name]; ok {
		if err := fixtureErrs[name]; err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		return dir
	}
	dir := filepath.Join(fixtureDir, name)
	err := build(dir)
	fixtures[name], fixtureErrs[name] = dir, err
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return dir
}

// copyOf copies a fixture into this test's own temporary directory.
func copyOf(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "w")
	must(t, copyTree(src, dst))
	return dst
}

// envPath is an environment variable's path, or def; relative paths are under the repository root.
func envPath(name, def string) string {
	p := os.Getenv(name)
	if p == "" {
		p = def
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, p)
}

func requireDir(t *testing.T, path, hint string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skip(hint)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ok returns v, and panics on a setup error that no test expects.
func ok[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// rejects asserts that err is a verification failure whose message contains reason.
func rejects(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("verification passed, want failure %q", reason)
	}
	if !IsVerificationError(err) {
		t.Fatalf("got a non-verification error %q, want failure %q", err, reason)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("got failure %q, want %q", err, reason)
	}
}

// resign decodes an envelope, lets mutate edit the statement, and signs it with keys/<role>.key.pem.
func resign(t *testing.T, path, keys, role string, mutate func(Obj)) {
	t.Helper()
	stmt := ok(DecodeEnvelope(path))
	if mutate != nil {
		mutate(stmt)
	}
	signer := ok(LoadSigner(filepath.Join(keys, role+".key.pem")))
	ok(Sign(stmt, signer, path))
}

// editPayload changes a statement without re-signing its envelope.
func editPayload(t *testing.T, path string, mutate func(Obj)) {
	t.Helper()
	env := ok(ReadObj(path))
	stmt := ok(DecodeEnvelope(path))
	mutate(stmt)
	data := ok(json.Marshal(stmt))
	env["payload"] = base64.StdEncoding.EncodeToString(data)
	must(t, WriteJSON(path, env))
}

func appendFile(t *testing.T, path, data string) {
	t.Helper()
	f := ok(os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0))
	defer f.Close()
	ok(f.WriteString(data))
}

func writeLines(t *testing.T, path string, lines []string) string {
	t.Helper()
	must(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	return path
}

// editJSON rewrites a JSON object file in place.
func editJSON(t *testing.T, path string, mutate func(Obj)) {
	t.Helper()
	v := ok(ReadObj(path))
	mutate(v)
	must(t, WriteJSON(path, v))
}

// makeKeys writes a key pair per role under keys, and copies the public keys to pub.
func makeKeys(keys, pub string, roles ...string) error {
	if err := os.MkdirAll(pub, 0o755); err != nil {
		return err
	}
	for _, role := range roles {
		if _, err := Keygen(keys, role); err != nil {
			return err
		}
		if err := copyFile(filepath.Join(keys, role+".pub.pem"), filepath.Join(pub, role+".pub.pem")); err != nil {
			return err
		}
	}
	return nil
}

// find returns the first object in list whose key equals value.
func find(list []Obj, key, value string) Obj {
	for _, o := range list {
		if S(o, key) == value {
			return o
		}
	}
	return nil
}
