package hslsa

// Tests for the provisioning adapter at a board station: the FPGA example's
// EMS, whose simulated in-circuit programmer (the "Example ICP-2") reads the
// root of trust it finds on each board. They use the example's own profile
// and station file (e2e/stations/icp2-profile.json,
// e2e/fpga/station/prog-01.json) on a small board bundle each test builds,
// with the root of trust vendor's records in parts/rot, so none needs an
// example run.

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

var (
	icp2Profile = filepath.Join(root, "e2e", "stations", "icp2-profile.json")
	prog01      = filepath.Join(root, "e2e", "fpga", "station", "prog-01.json")
	emsBoards   = []string{"FPGB-T-0001", "FPGB-T-0002", "FPGB-T-0003"}
	emsRoTs     = []string{"EXR01-T-00001", "EXR01-T-00002", "EXR01-T-00003", "EXR01-T-00004"}
)

const emsRoTCA = "Example RoT Co Test IDevID CA"

// ems is one test's board bundle, keys and station export.
type ems struct {
	dir, bundle, keys, rotKeys, export, station string
	flash                                       []byte
	rotKey                                      map[string]*ecdsa.PrivateKey // each root of trust unit's IDevID key
}

func newEMS(t *testing.T) *ems {
	t.Helper()
	dir := t.TempDir()
	f := &ems{
		dir: dir, bundle: filepath.Join(dir, "board"), keys: filepath.Join(dir, "keys"), rotKeys: filepath.Join(dir, "rot-keys"),
		export: filepath.Join(dir, "export"), station: prog01, rotKey: map[string]*ecdsa.PrivateKey{},
	}
	// The board owner's build platform and the EMS, in the board bundle's trust root.
	pub := filepath.Join(dir, "pub")
	must(t, makeKeys(f.keys, pub, "firmware-platform", "ems-site"))
	for _, d := range []string{"att", "artifacts", "design/att"} {
		must(t, os.MkdirAll(filepath.Join(f.bundle, d), 0o755))
	}
	must(t, BuildTrustRoot(pub, filepath.Join(f.bundle, "trust-root.json")))
	must(t, WriteJSON(filepath.Join(f.bundle, "artifacts", BoardDesign), Obj{"note": "test board"}))
	must(t, writeUnits(filepath.Join(f.bundle, "artifacts", BoardLot), emsBoards))
	ems := ok(LoadSigner(filepath.Join(f.keys, "ems-site.key.pem")))
	a1 := ok(statement([]Obj{rd("urn:hslsa:lot:BRD-EXAMPLE-FPGA-01", strings.Repeat("ab", 32))}, NS+"/mfg/v0.1", Obj{"step": "a1"}))
	ok(Sign(a1, ems, filepath.Join(f.bundle, "att", BoardA1)))
	// The flash image and its provenance, from the board owner's build platform.
	f.flash = []byte("FPGA board flash image v1\n")
	prov := ok(statement([]Obj{rd(FlashImage, sha256Bytes(f.flash))}, SLSAProvenance, Obj{
		"buildDefinition": Obj{"buildType": NS + "/firmware/test@v1", "externalParameters": Obj{}},
		"runDetails":      Obj{"builder": Obj{"id": "test"}},
	}))
	ok(Sign(prov, ok(LoadSigner(filepath.Join(f.keys, "firmware-platform.key.pem"))), filepath.Join(f.bundle, "design", "att", FlashAtt)))

	// The root of trust vendor's records in parts/rot: its identity CA, and
	// each unit's IDevID certificate and provisioning record.
	rotPub := filepath.Join(dir, "rot-pub")
	must(t, makeKeys(f.rotKeys, rotPub, "test-site"))
	must(t, IdentityCA(f.rotKeys, emsRoTCA))
	must(t, copyFile(filepath.Join(f.rotKeys, "identity-ca.pub.pem"), filepath.Join(rotPub, "identity-ca.pub.pem")))
	rot := filepath.Join(f.bundle, "parts", "rot")
	must(t, os.MkdirAll(filepath.Join(rot, "att"), 0o755))
	must(t, BuildTrustRoot(rotPub, filepath.Join(rot, "trust-root.json")))
	for _, u := range emsRoTs {
		f.rotKey[u] = ok(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
		f.endorse(t, u, filepath.Join(f.rotKeys, "identity-ca.key.pem"))
	}

	// The EMS's program file, with the image it loads.
	must(t, os.MkdirAll(filepath.Join(f.export, "images"), 0o755))
	must(t, os.WriteFile(filepath.Join(f.export, "images", FlashImage), f.flash, 0o644))
	program := fmt.Sprintf("; Example ICP-2 program\n[program]\nname = PRG-T\nlot = BRD-EXAMPLE-FPGA-01\n\n[load flash]\nimage = images/%s\ntarget = SPI0\nsha256 = %s\n",
		FlashImage, sha256Bytes(f.flash))
	must(t, os.WriteFile(filepath.Join(f.export, "program.ini"), []byte(program), 0o644))
	return f
}

// endorse issues unit's IDevID certificate with the CA key at caKey, and its
// vendor's provisioning record naming it.
func (f *ems) endorse(t *testing.T, unit, caKey string) {
	t.Helper()
	rot := filepath.Join(f.bundle, "parts", "rot")
	cert := ok(Endorse(ok(x509.ParseCertificateRequest(f.csr(t, f.rotKey[unit], unit))), ok(loadECKey(caKey)), emsRoTCA))
	name := "identity/" + unit + ".idevid.der"
	must(t, os.MkdirAll(filepath.Join(rot, "artifacts", "identity"), 0o755))
	must(t, os.WriteFile(filepath.Join(rot, "artifacts", name), cert, 0o644))
	rec := ok(statement([]Obj{rd("urn:hslsa:unit:"+unit, ok(spkiDigest(&f.rotKey[unit].PublicKey)))}, FWProvisioning,
		Obj{"hwProvision": Obj{"identity": Obj{"certificate": rd(name, sha256Bytes(cert))}}}))
	ok(Sign(rec, ok(LoadSigner(filepath.Join(f.rotKeys, "test-site.key.pem"))), filepath.Join(rot, "att", ProvAtt(unit))))
}

func (f *ems) csr(t *testing.T, key *ecdsa.PrivateKey, unit string) []byte {
	t.Helper()
	return ok(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: unit}}, key))
}

func (f *ems) gate() error { return ProvisionGate(f.bundle, icp2Profile, f.station, f.export) }

func (f *ems) adapt() error {
	return ProvisionAdapt(f.bundle, icp2Profile, f.station, f.export, filepath.Join(f.keys, "ems-site.key.pem"))
}

// run plays the EMS's station on each board, with the root of trust
// emsRoTs[i] on board i: it reads the part's serial, burns the owner fuses,
// writes and verifies the flash, reads the fuses back, asks the part for its
// CSR and powers the board on. edit may change a board's rows.
func (f *ems) run(t *testing.T, start time.Time, edit func(board string, rows [][]string) [][]string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Join(f.export, "identity"), 0o755))
	var all [][]string
	clock := start
	for i, b := range emsBoards {
		ts := func() string { clock = clock.Add(time.Second); return clock.Format("02.01.2006 15:04:05") }
		unit := emsRoTs[i]
		csr := "identity/" + b + "-U5.csr.der"
		must(t, os.WriteFile(filepath.Join(f.export, csr), f.csr(t, f.rotKey[unit], unit), 0o644))
		dump := "readback/" + b + "/SPI0.bin"
		must(t, os.MkdirAll(filepath.Join(f.export, "readback", b), 0o755))
		must(t, os.WriteFile(filepath.Join(f.export, dump), f.flash, 0o644))
		owner := strings.Repeat("c4", 32)
		rows := [][]string{
			{ts(), b, "OPEN", "", "PRG-T", "P"},
			{ts(), b, "ROT_SERIAL", "U5", unit, "P"},
			{ts(), b, "ROT_OTP_SET", "manifest_offset", "0x100000", "P"},
			{ts(), b, "ROT_OTP_SET", "owner_key_hash", owner, "P"},
			{ts(), b, "ROT_OTP_SET", "owner_min_svn", "1", "P"},
			{ts(), b, "SPI_PROG", "SPI0", "images/" + FlashImage, "P"},
			{ts(), b, "SPI_VERIFY", "SPI0", dump, "P"},
			{ts(), b, "ROT_OTP_GET", "manifest_offset", "1048576", "P"},
			{ts(), b, "ROT_OTP_GET", "owner_key_hash", owner, "P"},
			{ts(), b, "ROT_OTP_GET", "owner_min_svn", "1", "P"},
			{ts(), b, "ROT_CSR", "U5", csr, "P"},
			{ts(), b, "POWER_UP", "FPGA", "released", "P"},
			{ts(), b, "CLOSE", "", "", "P"},
		}
		if edit != nil {
			rows = edit(b, rows)
		}
		all = append(all, rows...)
	}
	file := ok(os.Create(filepath.Join(f.export, "icp2.log")))
	defer file.Close()
	w := csv.NewWriter(file)
	w.Comma = '\t'
	must(t, w.Write([]string{"When", "Board", "Step", "Ref", "Data", "Outcome"}))
	must(t, w.WriteAll(all))
}

// record opens a board's record with the EMS's key.
func (f *ems) record(t *testing.T, board string) Obj {
	t.Helper()
	trust := ok(LoadTrustRoot(filepath.Join(f.bundle, "trust-root.json")))
	return ok(trust.Open(filepath.Join(f.bundle, "att", BoardProvAtt(board)), "ems-site", FWProvisioning))
}

// produce runs the gate, the station and the adapter, with edit as in run.
func (f *ems) produce(t *testing.T, edit func(board string, rows [][]string) [][]string) error {
	t.Helper()
	must(t, f.gate())
	f.run(t, time.Now().UTC().Add(time.Second), edit)
	return f.adapt()
}

// adaptFailed says adapt signed the records but exited naming what failed.
func adaptFailed(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "recorded in the attestations") {
		t.Fatalf("adapt: %v, want %q", err, want)
	}
}

func TestBoardStationRecordNamesTheRootOfTrustItFound(t *testing.T) {
	f := newEMS(t)
	must(t, f.produce(t, nil))
	for i, b := range emsBoards {
		rec := f.record(t, b)
		hp := O(rec, "predicate", "hwProvision")
		if failed := failedChecks(Objs(hp, "checks")); len(failed) > 0 {
			t.Fatalf("%s: failed checks %v", b, failed)
		}
		for _, c := range []string{"image-provenance-verified", "image-readback", "fuse-readback", "csr-self-signature", "rot-identity", "certificate-endorsed", "first-boot-released", "station-log-passed"} {
			if checkResult(rec, c) != "pass" {
				t.Fatalf("%s: check %s is %q", b, c, checkResult(rec, c))
			}
		}
		unit := emsRoTs[i]
		key := ok(spkiDigest(&f.rotKey[unit].PublicKey))
		if S(hp, "unit") != boardURN("Example Board Co", b) || S(firstSubject(rec), "name") != S(hp, "unit") {
			t.Fatalf("%s: record is for %s", b, S(hp, "unit"))
		}
		if S(firstSubject(rec), "digest", "sha256") != key || S(hp, "identity", "idevidPublicKey", "sha256") != key {
			t.Fatalf("%s: the board's identity is not its root of trust's IDevID key", b)
		}
		rotRef := O(hp, "rootOfTrust")
		provRel := "parts/rot/att/" + ProvAtt(unit)
		if S(rotRef, "refDes") != "U5" || S(rotRef, "unit") != "urn:hslsa:unit:"+unit ||
			S(rotRef, "provisioningRef", "name") != provRel || !jsonEqual(get(rotRef, "provisioningRef", "digest"), fileDigest(filepath.Join(f.bundle, provRel))) {
			t.Fatalf("%s: rootOfTrust %v", b, rotRef)
		}
		if S(hp, "identity", "certificate", "name") != "parts/rot/artifacts/identity/"+unit+".idevid.der" || S(hp, "identity", "endorsingCa") != emsRoTCA {
			t.Fatalf("%s: identity %v", b, O(hp, "identity"))
		}
		if S(hp, "designRef", "name") != BoardDesign || S(hp, "designRef", "release", "name") != "att/"+BoardA1 {
			t.Fatalf("%s: designRef %v", b, O(hp, "designRef"))
		}
		if S(hp, "lot") != "urn:hslsa:lot:BRD-EXAMPLE-FPGA-01" || S(rec, "predicate", "buildDefinition", "externalParameters", "stage") != "board-programming" {
			t.Fatalf("%s: lot %s, stage %s", b, S(hp, "lot"), S(rec, "predicate", "buildDefinition", "externalParameters", "stage"))
		}
		if v, _ := Int(hp, "fuses", ownerFuseMan); v != 0x100000 || S(hp, "fuses", ownerFuseHash) != strings.Repeat("c4", 32) {
			t.Fatalf("%s: fuses %v", b, O(hp, "fuses"))
		}
		images := Objs(hp, "images")
		if len(images) != 1 || S(images[0], "name") != FlashImage || S(images[0], "readback", "sha256") != sha256Bytes(f.flash) {
			t.Fatalf("%s: images %v", b, images)
		}
		if S(hp, "export", "model") != "Example ICP-2 in-circuit programmer" || len(Objs(hp, "secrets")) != 0 {
			t.Fatalf("%s: export %v, secrets %v", b, O(hp, "export"), Objs(hp, "secrets"))
		}
		if !fileExists(filepath.Join(f.bundle, "artifacts", "identity", b+".csr.der")) {
			t.Fatalf("%s: the root of trust's CSR is not kept in the bundle", b)
		}
	}
}

func TestBoardStationPartAnswersWithAnotherKey(t *testing.T) {
	// The part at U5 reports a genuine unit's serial, but answers with a key
	// its vendor never endorsed: a relabelled or counterfeit part.
	f := newEMS(t)
	fake := ok(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		if b == emsBoards[1] {
			must(t, os.WriteFile(filepath.Join(f.export, "identity", b+"-U5.csr.der"), f.csr(t, fake, emsRoTs[1]), 0o644))
		}
		return rows
	})
	adaptFailed(t, err, emsBoards[1]+" (rot-identity)")
	rec := f.record(t, emsBoards[1])
	if checkResult(rec, "rot-identity") != "fail" || !strings.Contains(S(find(Objs(rec, "predicate", "hwProvision", "checks"), "name", "rot-identity"), "detail"), "another IDevID key") {
		t.Fatal("the record does not say the part answered with another key")
	}
	if checkResult(f.record(t, emsBoards[0]), "rot-identity") != "pass" {
		t.Fatal("the other boards' records failed too")
	}
}

func TestBoardStationReadNoRootOfTrust(t *testing.T) {
	f := newEMS(t)
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		if b != emsBoards[0] {
			return rows
		}
		var out [][]string
		for _, r := range rows {
			if r[2] != "ROT_SERIAL" {
				out = append(out, r)
			}
		}
		return out
	})
	adaptFailed(t, err, emsBoards[0]+" (rot-identity, certificate-endorsed)")
	if d := S(find(Objs(f.record(t, emsBoards[0]), "predicate", "hwProvision", "checks"), "name", "rot-identity"), "detail"); d != "the station read no part at U5" {
		t.Fatalf("detail %q", d)
	}
}

func TestBoardStationRootOfTrustReadFailed(t *testing.T) {
	f := newEMS(t)
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		return editRow(rows, "ROT_SERIAL", "U5", func(r []string) {
			if b == emsBoards[2] {
				r[5] = "F"
			}
		})
	})
	adaptFailed(t, err, emsBoards[2]+" (rot-identity, certificate-endorsed, station-log-passed)")
}

func TestBoardStationPartWithoutVendorRecord(t *testing.T) {
	// The serial the part reports is not a unit its vendor provisioned.
	f := newEMS(t)
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		return editRow(rows, "ROT_SERIAL", "U5", func(r []string) {
			if b == emsBoards[0] {
				r[4] = "EXR01-T-09999"
			}
		})
	})
	adaptFailed(t, err, emsBoards[0]+" (rot-identity, certificate-endorsed)")
	rec := f.record(t, emsBoards[0])
	if d := S(find(Objs(rec, "predicate", "hwProvision", "checks"), "name", "rot-identity"), "detail"); !strings.Contains(d, "has no provisioning record from its vendor") {
		t.Fatalf("detail %q", d)
	}
	if S(rec, "predicate", "hwProvision", "rootOfTrust", "unit") != "urn:hslsa:unit:EXR01-T-09999" {
		t.Fatal("the record does not name the part the station read")
	}
}

func TestBoardStationCertificateFromAnotherCA(t *testing.T) {
	f := newEMS(t)
	other := filepath.Join(f.dir, "other-ca")
	must(t, IdentityCA(other, emsRoTCA))
	f.endorse(t, emsRoTs[1], filepath.Join(other, "identity-ca.key.pem"))
	adaptFailed(t, f.produce(t, nil), emsBoards[1]+" (certificate-endorsed)")
}

func TestBoardStationFPGAHeldInReset(t *testing.T) {
	f := newEMS(t)
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		return editRow(rows, "POWER_UP", "FPGA", func(r []string) {
			if b == emsBoards[0] {
				r[4], r[5] = "held in reset", "F"
			}
		})
	})
	adaptFailed(t, err, emsBoards[0]+" (first-boot-released, station-log-passed)")
}

func TestBoardStationPoweredOnBeforeTheLastWrite(t *testing.T) {
	// A power-on before the flash was written does not show the root of trust accepting it.
	f := newEMS(t)
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		if b != emsBoards[0] {
			return rows
		}
		var power []string
		var out [][]string
		for _, r := range rows {
			if r[2] == "POWER_UP" {
				power = r
				continue
			}
			out = append(out, r)
		}
		// Move the power-on to just after OPEN, keeping the times in order.
		power[0] = out[0][0]
		return append([][]string{out[0], power}, out[1:]...)
	})
	adaptFailed(t, err, emsBoards[0]+" (first-boot-released)")
}

func TestBoardStationFuseBurnedAfterPowerOn(t *testing.T) {
	// An owner fuse burned after the power-on was not in force when the root of trust released the FPGA.
	f := newEMS(t)
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		if b != emsBoards[0] {
			return rows
		}
		var times []string
		var out, late [][]string
		for _, r := range rows {
			times = append(times, r[0])
			if strings.HasPrefix(r[2], "ROT_OTP_") && r[3] == ownerFuseSVN {
				late = append(late, r)
				continue
			}
			out = append(out, r)
		}
		// Burn and read back the anti-rollback fuse after POWER_UP, before CLOSE.
		out = append(out[:len(out)-1], append(late, out[len(out)-1])...)
		for i := range out {
			out[i][0] = times[i]
		}
		return out
	})
	adaptFailed(t, err, emsBoards[0]+" (first-boot-released)")
}

func TestBoardStationSerialThatIsAPath(t *testing.T) {
	// The serial names a file in the part vendor's bundle, so one holding a path is not read.
	f := newEMS(t)
	err := f.produce(t, func(b string, rows [][]string) [][]string {
		return editRow(rows, "ROT_SERIAL", "U5", func(r []string) {
			if b == emsBoards[1] {
				r[4] = "../../../att/" + emsRoTs[1]
			}
		})
	})
	adaptFailed(t, err, emsBoards[1]+" (rot-identity, certificate-endorsed)")
	if d := S(find(Objs(f.record(t, emsBoards[1]), "predicate", "hwProvision", "checks"), "name", "rot-identity"), "detail"); !strings.Contains(d, "which is not a unit serial") {
		t.Fatalf("detail %q", d)
	}
}

func TestStationFileRootOfTrustNeedsBoard(t *testing.T) {
	dir := t.TempDir()
	station := ok(ReadObj(prog01))
	delete(station, "board")
	path := filepath.Join(dir, "s.json")
	must(t, WriteJSON(path, station))
	if _, err := ReadStationFile(path); err == nil || !strings.Contains(err.Error(), "rootOfTrust is for a station that programs boards") {
		t.Fatalf("got %v", err)
	}
	station = ok(ReadObj(prog01))
	delete(O(station, "rootOfTrust"), "caRole")
	must(t, WriteJSON(path, station))
	if _, err := ReadStationFile(path); err == nil || !strings.Contains(err.Error(), "rootOfTrust does not set caRole") {
		t.Fatalf("got %v", err)
	}
	ok(ReadStationFile(prog01))
}
