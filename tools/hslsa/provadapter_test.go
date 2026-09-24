package hslsa

// Tests for the provisioning station adapter, on a second station model: the
// "Example SP-1", a single-socket programmer whose export looks nothing like
// the FPGA example's XG-8 (a recipe file, a semicolon-separated log with its
// own column names, time format and operation words, injected keys). Only the
// profile differs; the adapter code is the same. Each test builds its own
// small bundle, so none needs an example run.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var sp1Units = []string{"SP-0001", "SP-0002", "SP-0003"}

const sp1HSM = "urn:hslsa:hsm:example-osat:hsm-07"

func sp1Profile() Obj {
	return Obj{
		"model": "Example SP-1 single-socket programmer",
		"job": Obj{
			"file": "recipe.ini", "id": "recipe.name", "lot": "recipe.lot",
			"imageSection": "img", "imageFile": "path", "imageRegion": "addr", "imageSha256": "sha256",
		},
		"log": Obj{
			"file": "sp1.log", "delimiter": ";", "timeLayout": "2006/01/02 15:04:05", "pass": "OK",
			"columns": Obj{"time": "Time", "unit": "DUT", "op": "Step", "target": "Item", "value": "Data", "result": "Status"},
		},
		"ops": Obj{
			"begin": "START", "end": "DONE", "program": "WRITE_IMG", "verify": "READBACK",
			"fuseWrite": "OTP_PGM", "fuseRead": "OTP_RD", "keyInject": "INJECT", "csr": "GET_CSR", "certificate": "PUT_CERT",
		},
	}
}

func sp1Station() Obj {
	return Obj{
		"station": "urn:hslsa:station:example-osat:sp1-03",
		"site":    Obj{"name": "Example OSAT", "country": "US"},
		"stage":   "final-test",
		"lotId":   "LOT-SP-1",
		"hsm":     sp1HSM,
		"images": Obj{
			"boot.bin": Obj{"role": "boot", "storage": "on-die-flash", "provenance": "fw-boot.intoto.json", "signer": "firmware-platform"},
		},
		"fuseTypes": Obj{"ueid": "hex", "svn": "int", "lock": "bool", "lcs": "string"},
		"secrets":   []any{"dev_key"},
		"lifecycle": Obj{"fuse": "lcs", "production": "PROD", "debugLock": "lock"},
		"identity":  Obj{"scheme": "DICE", "ueidFuse": "ueid", "caRole": "identity-ca"},
	}
}

// sp1 is one test's bundle, keys and station export.
type sp1 struct {
	dir, bundle, keys, export, profile, station string
	image                                       []byte
}

func newSP1(t *testing.T) *sp1 {
	t.Helper()
	dir := t.TempDir()
	f := &sp1{
		dir: dir, bundle: filepath.Join(dir, "bundle"), keys: filepath.Join(dir, "keys"), export: filepath.Join(dir, "export"),
		profile: filepath.Join(dir, "sp1-profile.json"), station: filepath.Join(dir, "sp1-03.json"),
	}
	pub := filepath.Join(dir, "pub")
	must(t, makeKeys(f.keys, pub, "firmware-platform", "test-site", "other-ca"))
	must(t, IdentityCA(f.keys, "Example SP Identity CA"))
	must(t, copyFile(filepath.Join(f.keys, "identity-ca.pub.pem"), filepath.Join(pub, "identity-ca.pub.pem")))
	for _, d := range []string{"att", "artifacts"} {
		must(t, os.MkdirAll(filepath.Join(f.bundle, d), 0o755))
	}
	must(t, BuildTrustRoot(pub, filepath.Join(f.bundle, "trust-root.json")))
	must(t, writeUnits(filepath.Join(f.bundle, "artifacts", "shipped-lot.txt"), sp1Units))
	must(t, WriteJSON(f.profile, sp1Profile()))
	must(t, WriteJSON(f.station, sp1Station()))

	// The design release and the boot image's provenance, as the chain before the station would have them.
	signer := ok(LoadSigner(filepath.Join(f.keys, "firmware-platform.key.pem")))
	rel := ok(statement([]Obj{rd("sp1.gds", strings.Repeat("ab", 32))}, DesignFlow, Obj{"step": "release"}))
	ok(Sign(rel, signer, filepath.Join(f.bundle, "att", AttName("release"))))
	f.image = []byte("SP-1 boot image v1\n")
	prov := ok(statement([]Obj{rd("boot.bin", sha256Bytes(f.image))}, SLSAProvenance, Obj{
		"buildDefinition": Obj{"buildType": NS + "/firmware/test@v1", "externalParameters": Obj{}},
		"runDetails":      Obj{"builder": Obj{"id": "test"}},
	}))
	ok(Sign(prov, signer, filepath.Join(f.bundle, "att", "fw-boot.intoto.json")))

	// The site engineer's recipe, with the image it loads.
	must(t, os.MkdirAll(filepath.Join(f.export, "fw"), 0o755))
	must(t, os.WriteFile(filepath.Join(f.export, "fw", "boot.bin"), f.image, 0o644))
	f.recipe(t, sha256Bytes(f.image))
	return f
}

func (f *sp1) recipe(t *testing.T, digest string) {
	t.Helper()
	recipe := fmt.Sprintf("# SP-1 recipe\n[recipe]\nname = R-77\nlot = LOT-SP-1\n\n[img.0]\npath = fw/boot.bin\naddr = 0x08000000\nsha256 = %s\n", digest)
	must(t, os.WriteFile(filepath.Join(f.export, "recipe.ini"), []byte(recipe), 0o644))
}

func (f *sp1) gate() error { return ProvisionGate(f.bundle, f.profile, f.station, f.export) }

func (f *sp1) adapt() error {
	return ProvisionAdapt(f.bundle, f.profile, f.station, f.export, filepath.Join(f.keys, "test-site.key.pem"))
}

// run plays the station: each unit gets a session that writes the image,
// burns and reads the fuses, injects a key and exchanges its identity.
// edit may change a unit's rows before they are written.
func (f *sp1) run(t *testing.T, start time.Time, edit func(unit string, rows [][]string) [][]string) {
	t.Helper()
	caKey := ok(loadECKey(filepath.Join(f.keys, "identity-ca.key.pem")))
	must(t, os.MkdirAll(filepath.Join(f.export, "dumps"), 0o755))
	must(t, os.MkdirAll(filepath.Join(f.export, "id"), 0o755))
	var all [][]string
	clock := start
	for _, u := range sp1Units {
		ts := func() string { clock = clock.Add(time.Second); return clock.Format("2006/01/02 15:04:05") }
		dev := ok(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
		csrDER := ok(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: u}}, dev))
		cert := ok(Endorse(ok(x509.ParseCertificateRequest(csrDER)), caKey, "Example SP Identity CA"))
		must(t, os.WriteFile(filepath.Join(f.export, "id", u+".csr"), csrDER, 0o644))
		must(t, os.WriteFile(filepath.Join(f.export, "id", u+".cer"), cert, 0o644))
		must(t, os.WriteFile(filepath.Join(f.export, "dumps", u+".bin"), f.image, 0o644))
		ueid := fmt.Sprintf("01%x", u)
		rows := [][]string{
			{ts(), u, "START", "", "R-77", "OK"},
			{ts(), u, "WRITE_IMG", "0x08000000", "fw/boot.bin", "OK"},
			{ts(), u, "READBACK", "0x08000000", "dumps/" + u + ".bin", "OK"},
			{ts(), u, "INJECT", "dev_key", "hsm-07/slot2/" + u, "OK"},
			{ts(), u, "OTP_PGM", "ueid", ueid, "OK"},
			{ts(), u, "OTP_PGM", "svn", "3", "OK"},
			{ts(), u, "OTP_PGM", "lcs", "PROD", "OK"},
			{ts(), u, "OTP_PGM", "lock", "true", "OK"},
			{ts(), u, "OTP_RD", "ueid", ueid, "OK"},
			{ts(), u, "OTP_RD", "svn", "0x3", "OK"},
			{ts(), u, "OTP_RD", "lcs", "PROD", "OK"},
			{ts(), u, "OTP_RD", "lock", "1", "OK"},
			{ts(), u, "GET_CSR", "idevid", "id/" + u + ".csr", "OK"},
			{ts(), u, "PUT_CERT", "idevid", "id/" + u + ".cer", "OK"},
			{ts(), u, "DONE", "", "", "OK"},
		}
		if edit != nil {
			rows = edit(u, rows)
		}
		all = append(all, rows...)
	}
	file := ok(os.Create(filepath.Join(f.export, "sp1.log")))
	defer file.Close()
	w := csv.NewWriter(file)
	w.Comma = ';'
	must(t, w.Write([]string{"Time", "DUT", "Step", "Item", "Data", "Status"}))
	must(t, w.WriteAll(all))
}

// record opens a unit's signed record with the site's key.
func (f *sp1) record(t *testing.T, unit string) Obj {
	t.Helper()
	pub := filepath.Join(f.dir, "site-pub")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, copyFile(filepath.Join(f.keys, "test-site.pub.pem"), filepath.Join(pub, "test-site.pub.pem")))
	must(t, BuildTrustRoot(pub, filepath.Join(f.dir, "site-trust.json")))
	site := ok(LoadTrustRoot(filepath.Join(f.dir, "site-trust.json")))
	return ok(site.Open(filepath.Join(f.bundle, "att", ProvAtt(unit)), "test-site", FWProvisioning))
}

func checkResult(rec Obj, name string) string {
	return S(find(Objs(rec, "predicate", "hwProvision", "checks"), "name", name), "result")
}

func editRow(rows [][]string, step, item string, set func(r []string)) [][]string {
	for _, r := range rows {
		if r[2] == step && r[3] == item {
			set(r)
		}
	}
	return rows
}

func TestAdapterSignsRecordsFromSecondStationModel(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), nil)
	must(t, f.adapt())
	for _, u := range sp1Units {
		rec := f.record(t, u)
		hp := O(rec, "predicate", "hwProvision")
		if failed := failedChecks(Objs(hp, "checks")); len(failed) > 0 {
			t.Fatalf("%s: checks failed: %v", u, failed)
		}
		cert := ok(loadCert(filepath.Join(f.bundle, "artifacts", S(hp, "identity", "certificate", "name"))))
		if key := ok(spkiDigest(cert.PublicKey)); S(firstSubject(rec), "digest", "sha256") != key || S(firstSubject(rec), "name") != "urn:hslsa:unit:"+u {
			t.Fatalf("%s: subject %v is not the unit's IDevID key", u, firstSubject(rec))
		}
		fuses := O(hp, "fuses")
		if v, _ := Int(fuses, "svn"); v != 3 || fuses["lock"] != true || S(fuses, "lcs") != "PROD" {
			t.Fatalf("%s: fuses %v", u, fuses)
		}
		secrets := Objs(hp, "secrets")
		if len(secrets) != 1 || S(secrets[0], "keyId") != "hsm-07/slot2/"+u || S(secrets[0], "origin") != "injected by "+sp1HSM {
			t.Fatalf("%s: secrets %v", u, secrets)
		}
		if S(hp, "identity", "endorsingCa") != "Example SP Identity CA" || S(hp, "lot") != "urn:hslsa:lot:LOT-SP-1" {
			t.Fatalf("%s: identity or lot %v", u, hp)
		}
		// The record carries this unit's rows exactly, and nothing of the other units.
		logPath := filepath.Join(f.bundle, "artifacts", S(hp, "export", "log", "name"))
		if !jsonEqual(fileDigest(logPath), get(hp, "export", "log", "digest")) {
			t.Fatalf("%s: unit log does not match its digest", u)
		}
		text := string(ok(os.ReadFile(logPath)))
		for _, other := range sp1Units {
			if other != u && strings.Contains(text, other) {
				t.Fatalf("%s: unit log holds rows of %s", u, other)
			}
		}
	}
}

func TestAdapterUsesLastSessionAfterRetry(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), func(u string, rows [][]string) [][]string {
		if u != sp1Units[1] {
			return rows
		}
		// The first attempt fails its readback and stops; the second passes.
		failed := [][]string{append([]string{}, rows[0]...), append([]string{}, rows[1]...), append([]string{}, rows[2]...)}
		failed[2][5] = "NG"
		return append(failed, rows...)
	})
	must(t, f.adapt())
	if n, _ := Int(f.record(t, sp1Units[1]), "predicate", "hwProvision", "export", "sessions"); n != 2 {
		t.Fatalf("sessions = %d, want 2", n)
	}
}

func TestAdapterRecordsFailedReadback(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), nil)
	appendFile(t, filepath.Join(f.export, "dumps", sp1Units[0]+".bin"), "x")
	err := f.adapt()
	if err == nil || !strings.Contains(err.Error(), sp1Units[0]+" (image-readback)") {
		t.Fatalf("adapt: %v", err)
	}
	if checkResult(f.record(t, sp1Units[0]), "image-readback") != "fail" || checkResult(f.record(t, sp1Units[1]), "image-readback") != "pass" {
		t.Fatal("the readback failure is not recorded against the right unit")
	}
}

func TestAdapterRecordsFuseReadMismatch(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), func(u string, rows [][]string) [][]string {
		if u != sp1Units[2] {
			return rows
		}
		return editRow(rows, "OTP_RD", "svn", func(r []string) { r[4] = "2" })
	})
	if err := f.adapt(); err == nil || !strings.Contains(err.Error(), "fuse-readback") {
		t.Fatalf("adapt: %v", err)
	}
	if checkResult(f.record(t, sp1Units[2]), "fuse-readback") != "fail" {
		t.Fatal("a fuse read back with another value passed")
	}
}

func TestAdapterWithoutGate(t *testing.T) {
	f := newSP1(t)
	f.run(t, time.Now().UTC(), nil)
	if err := f.adapt(); err == nil || !strings.Contains(err.Error(), "image-provenance-verified") {
		t.Fatalf("adapt: %v", err)
	}
	rec := f.record(t, sp1Units[0])
	if checkResult(rec, "image-provenance-verified") != "fail" || Truthy(get(Objs(rec, "predicate", "hwProvision", "images")[0], "provenanceVerified")) {
		t.Fatal("a job nobody cleared counts as provenance-verified")
	}
}

func TestAdapterGateAfterFirstWrite(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(-time.Hour), nil)
	if err := f.adapt(); err == nil || !strings.Contains(err.Error(), "image-provenance-verified") {
		t.Fatalf("adapt: %v", err)
	}
	d := S(find(Objs(f.record(t, sp1Units[0]), "predicate", "hwProvision", "checks"), "name", "image-provenance-verified"), "detail")
	if !strings.Contains(d, "before the gate cleared the job") {
		t.Fatalf("detail %q", d)
	}
}

func TestAdapterJobChangedAfterGate(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	other := []byte("SP-1 boot image, patched\n")
	must(t, os.WriteFile(filepath.Join(f.export, "fw", "boot.bin"), other, 0o644))
	f.recipe(t, sha256Bytes(other))
	f.image = other
	f.run(t, time.Now().UTC().Add(time.Second), nil)
	if err := f.adapt(); err == nil || !strings.Contains(err.Error(), "image-provenance-verified") {
		t.Fatalf("adapt: %v", err)
	}
}

func TestGateRefusesImageWithoutProvenance(t *testing.T) {
	f := newSP1(t)
	other := []byte("not the released image\n")
	must(t, os.WriteFile(filepath.Join(f.export, "fw", "boot.bin"), other, 0o644))
	f.recipe(t, sha256Bytes(other))
	rejects(t, f.gate(), "boot.bin has no provenance")
	if _, err := os.Stat(filepath.Join(f.bundle, "artifacts", ProvisioningDir, gateName("R-77"))); err == nil {
		t.Fatal("the gate cleared a job it refused")
	}
}

func TestGateRefusesImageOtherThanTheJobNames(t *testing.T) {
	f := newSP1(t)
	appendFile(t, filepath.Join(f.export, "fw", "boot.bin"), "x")
	rejects(t, f.gate(), "is not the image the job file names")
}

func TestAdapterRefusesSecretValueInLog(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), func(u string, rows [][]string) [][]string {
		return append(rows[:len(rows)-1], []string{rows[0][0], u, "OTP_PGM", "dev_key", "00112233", "OK"}, rows[len(rows)-1])
	})
	rejects(t, f.adapt(), "holds a value for secret field dev_key")
	if _, err := os.Stat(filepath.Join(f.bundle, "att", ProvAtt(sp1Units[0]))); err == nil {
		t.Fatal("a record was signed from an export that leaks a secret")
	}
}

func TestAdapterRefusesKeyMaterialAsKeyID(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), func(u string, rows [][]string) [][]string {
		return editRow(rows, "INJECT", "dev_key", func(r []string) { r[4] = strings.Repeat("9f", 32) })
	})
	rejects(t, f.adapt(), "looks like key material")
}

func TestAdapterRefusesMissingUnit(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), func(u string, rows [][]string) [][]string {
		if u == sp1Units[1] {
			return nil
		}
		return rows
	})
	rejects(t, f.adapt(), "no session for "+sp1Units[1])
}

func TestAdapterCertificateFromAnotherCA(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), nil)
	// Someone at the station signs a certificate for the unit's key with a CA the buyer does not list.
	u := sp1Units[0]
	csr := ok(x509.ParseCertificateRequest(ok(os.ReadFile(filepath.Join(f.export, "id", u+".csr")))))
	cert := ok(Endorse(csr, ok(loadECKey(filepath.Join(f.keys, "other-ca.key.pem"))), "Example SP Identity CA"))
	must(t, os.WriteFile(filepath.Join(f.export, "id", u+".cer"), cert, 0o644))
	if err := f.adapt(); err == nil || !strings.Contains(err.Error(), "certificate-endorsed") {
		t.Fatalf("adapt: %v", err)
	}
}

func TestAdapterCertificateForAnotherKey(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), nil)
	must(t, copyFile(filepath.Join(f.export, "id", sp1Units[1]+".cer"), filepath.Join(f.export, "id", sp1Units[0]+".cer")))
	if err := f.adapt(); err == nil || !strings.Contains(err.Error(), sp1Units[0]+" (certificate-matches-csr)") {
		t.Fatalf("adapt: %v", err)
	}
}

func TestAdapterRefusesPathOutsideExport(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), func(u string, rows [][]string) [][]string {
		return editRow(rows, "GET_CSR", "idevid", func(r []string) { r[4] = "../../keys/test-site.key.pem" })
	})
	rejects(t, f.adapt(), "leaves the export")
}

func TestStationProfileNeedsEveryField(t *testing.T) {
	p := sp1Profile()
	delete(O(p, "log", "columns"), "result")
	path := filepath.Join(t.TempDir(), "p.json")
	must(t, WriteJSON(path, p))
	if _, err := ReadStationProfile(path); err == nil || !strings.Contains(err.Error(), "log.columns.result") {
		t.Fatalf("ReadStationProfile: %v", err)
	}
}

func TestParseINI(t *testing.T) {
	ini := ok(parseINI([]byte("; c\n[a]\nk = v = w\n# c\n[img 1]\nx=1\n")))
	if ini.get("a.k") != "v = w" || ini.get("img 1.x") != "1" || len(ini.sections) != 2 {
		t.Fatalf("parsed %+v", ini)
	}
	for _, bad := range []string{"k = v\n", "[a\n", "[a]\n[a]\n", "[a]\nnovalue\n"} {
		if _, err := parseINI([]byte(bad)); err == nil {
			t.Fatalf("parseINI accepted %q", bad)
		}
	}
}

func TestAdapterSessionSkipsAnImageOrFuse(t *testing.T) {
	f := newSP1(t)
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), func(u string, rows [][]string) [][]string {
		var kept [][]string
		for _, r := range rows {
			switch {
			case u == sp1Units[0] && (r[2] == "WRITE_IMG" || r[2] == "READBACK"):
			case u == sp1Units[1] && r[3] == "lock":
			default:
				kept = append(kept, r)
			}
		}
		return kept
	})
	if err := f.adapt(); err == nil {
		t.Fatal("adapt passed units that skipped an image and a fuse")
	}
	if checkResult(f.record(t, sp1Units[0]), "image-readback") != "fail" {
		t.Fatal("a unit that was never written passed image-readback")
	}
	if checkResult(f.record(t, sp1Units[1]), "fuse-readback") != "fail" {
		t.Fatal("a unit whose lock fuse was never burned passed fuse-readback")
	}
}
