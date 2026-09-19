package hslsa

// Selective disclosure and verifier escrow on the PicoRV32 chain.
//
// Needs a bundle from `e2e/run.sh produce`, like the other tamper tests. The
// fixture re-signs the lot's records with the fields in e2e/picorv32/withhold.json
// withheld, as e2e/escrow.sh produce does, and adds an auditor key and a
// buyer's trust root that lists only that key.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var e2eUnits = filepath.Join(e2eDir, "received-units.txt")

// escrowBundle is a fresh copy of the chip bundle with fields withheld.
func escrowBundle(t *testing.T) string {
	t.Helper()
	chip := chipBundle(t)
	valid := shared(t, "escrow", func(work string) error {
		if err := copyTree(filepath.Dir(chip), work); err != nil {
			return err
		}
		bundle, keys := filepath.Join(work, "bundle"), filepath.Join(work, "keys")
		w, err := LoadWithholding(filepath.Join(e2eDir, "withhold.json"))
		if err != nil {
			return err
		}
		if err := Mfg(bundle, e2eScenario, keys, w); err != nil {
			return err
		}
		if err := BuildHBOM(bundle, e2eLock, e2eScenario, filepath.Join(keys, "product-owner.key.pem"), w); err != nil {
			return err
		}
		if err := makeKeys(filepath.Join(work, "auditor"), filepath.Join(work, "buyer-pub"), AuditorRole); err != nil {
			return err
		}
		return BuildTrustRoot(filepath.Join(work, "buyer-pub"), filepath.Join(work, "buyer-trust-root.json"))
	})
	return filepath.Join(copyOf(t, valid), "bundle")
}

func escrowWork(bundle string) string { return filepath.Dir(bundle) }

// audit runs the auditor on bundle for units, into dir.
func audit(t *testing.T, bundle, units, dir string) error {
	t.Helper()
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	key := filepath.Join(escrowWork(bundle), "auditor", AuditorRole+".key.pem")
	return EscrowAudit(bundle, trust, e2ePolicy, units, key, filepath.Join(dir, "vsa"), filepath.Join(dir, "escrow-manifest.json"))
}

// buyerCheck is the buyer's check of the VSAs in dir.
func buyerCheck(t *testing.T, bundle, dir, policy, units string) error {
	t.Helper()
	trust := ok(LoadTrustRoot(filepath.Join(escrowWork(bundle), "buyer-trust-root.json")))
	return EscrowCheck(filepath.Join(dir, "vsa"), trust, policy, units)
}

func TestEscrowBundleWithholdsFields(t *testing.T) {
	bundle := escrowBundle(t)
	f4 := ok(DecodeEnvelope(filepath.Join(bundle, "att", MfgAtt["final-test"])))
	if Has(O(f4, "predicate", "hwMfg"), "yield") {
		t.Fatal("final test still shows its yield")
	}
	var paths []string
	for _, e := range Withheld(f4) {
		paths = append(paths, S(e, "path"))
	}
	if !equalStrings(paths, []string{"/buildDefinition/externalParameters/testProgram", "/hwMfg/yield"}) {
		t.Fatalf("final test withholds %v", paths)
	}
	hb := ok(DecodeEnvelope(filepath.Join(bundle, "att", "hbom.intoto.json")))
	must(t, ValidateHBOM(get(hb, "predicate")))
	if Has(Objs(hb, "predicate", "manufacturing", "waferLots")[0], "waferIds") {
		t.Fatal("the HBOM still shows the wafer ids")
	}
	for _, f := range []string{"wafer-maps.json", "genealogy.json", "final-test-results.json"} {
		if !saltedFile(filepath.Join(bundle, "artifacts", f)) {
			t.Fatalf("%s has no salt", f)
		}
	}
}

func TestEscrowBundleVerifiesWithItsDisclosures(t *testing.T) {
	bundle := escrowBundle(t)
	must(t, chipCheck(t, bundle, ok(ReadUnits(e2eUnits))))
}

func TestEscrowBundleWithoutDisclosures(t *testing.T) {
	bundle := escrowBundle(t)
	must(t, os.RemoveAll(filepath.Join(bundle, "disclosures")))
	rejects(t, chipCheck(t, bundle, nil),
		"mfg-f1-wafer-fab.intoto.json: /buildDefinition/externalParameters/maskSetId is withheld and no disclosure was given")
}

func TestForgedYieldDisclosure(t *testing.T) {
	// The test site's yield, disclosed with a scrapped unit left out: the
	// disclosure no longer matches the salted digest the site signed.
	bundle := escrowBundle(t)
	env := filepath.Join(bundle, "att", MfgAtt["final-test"])
	editJSON(t, disclosurePath(env), func(f Obj) {
		ds := A(f, "disclosures")
		ds[1] = disclosureFor(ok(newSalt()), "/hwMfg/yield", Obj{"in": 40, "passed": 38, "failed": []any{"PSOC130-A0-00007", "PSOC130-A0-00019"}})
	})
	rejects(t, chipCheck(t, bundle, nil), "mfg-f4-final-test.intoto.json: a disclosure matches no withheld field")
}

func TestDisclosuresOfAnotherRecord(t *testing.T) {
	bundle := escrowBundle(t)
	must(t, copyFile(disclosurePath(filepath.Join(bundle, "att", MfgAtt["wafer-sort"])),
		disclosurePath(filepath.Join(bundle, "att", MfgAtt["final-test"]))))
	rejects(t, chipCheck(t, bundle, nil), "mfg-f4-final-test.intoto.json: a disclosure matches no withheld field")
}

func TestWithheldGateRejected(t *testing.T) {
	// A site that lists its gate results as withheld hides whether a gate
	// failed; the verifier refuses the record even with a valid signature.
	bundle := escrowBundle(t)
	chipResign(t, bundle, MfgAtt["packaging"], "osat-site", func(s Obj) {
		delete(O(s, "predicate", "hwMfg"), "checks")
		O(s, "predicate", "hwMfg")["confidential"] = []any{Obj{"path": "/hwMfg/checks", "saltedDigest": Obj{"sha256": strings.Repeat("e", 64)}}}
	})
	rejects(t, chipCheck(t, bundle, nil), "mfg-f3-packaging.intoto.json: /hwMfg/checks cannot be withheld")
}

func TestEscrowAuditAndBuyerCheck(t *testing.T) {
	bundle := escrowBundle(t)
	dir := t.TempDir()
	must(t, audit(t, bundle, e2eUnits, dir))
	must(t, buyerCheck(t, bundle, dir, e2ePolicy, e2eUnits))

	// The buyer's VSAs name nothing but the manifest; the manifest, which the
	// auditor keeps, names every record, file and disclosure it checked.
	receipt := ok(DecodeEnvelope(filepath.Join(dir, "vsa", EscrowReceiptVSA)))
	in := Objs(receipt, "predicate", "inputAttestations")
	if len(in) != 1 || S(in[0], "uri") != "file:escrow-manifest.json" {
		t.Fatalf("receipt VSA inputs %v", in)
	}
	if S(firstSubject(receipt), "name") != "urn:hslsa:receipt:ASM-EXAMPLE-17" ||
		S(firstSubject(receipt), "digest", "sha256") != ok(LotDigest(ok(ReadUnits(e2eUnits)))) {
		t.Fatalf("receipt subject %v", firstSubject(receipt))
	}
	manifest := ok(ReadObj(filepath.Join(dir, "escrow-manifest.json")))
	if S(in[0], "digest", "sha256") != ok(sha256File(filepath.Join(dir, "escrow-manifest.json"))) {
		t.Fatal("the VSA does not name the manifest by digest")
	}
	if len(Objs(manifest, "disclosures")) != 4 || find(Objs(manifest, "records"), "name", "att/"+MfgAtt["final-test"]) == nil {
		t.Fatalf("manifest %v", manifest)
	}
}

func TestEscrowAuditRefusesAScrappedUnit(t *testing.T) {
	bundle := escrowBundle(t)
	units := writeLines(t, filepath.Join(t.TempDir(), "units.txt"), []string{"PSOC130-A0-00001", "PSOC130-A0-00007"})
	rejects(t, audit(t, bundle, units, t.TempDir()), "received unit PSOC130-A0-00007 is not in the shipped lot")
}

func TestEscrowBuyerRejects(t *testing.T) {
	bundle := escrowBundle(t)
	dir := t.TempDir()
	must(t, audit(t, bundle, e2eUnits, dir))
	keys := filepath.Join(escrowWork(bundle), "keys")
	auditorKeys := filepath.Join(escrowWork(bundle), "auditor")
	fresh := func(t *testing.T) string {
		d := filepath.Join(t.TempDir(), "audit")
		must(t, copyTree(dir, d))
		return d
	}
	resignVSA := func(t *testing.T, d, keyDir, role string, mutate func(Obj)) {
		resign(t, filepath.Join(d, "vsa", EscrowReceiptVSA), keyDir, role, mutate)
	}

	t.Run("receipt for other units", func(t *testing.T) {
		units := writeLines(t, filepath.Join(t.TempDir(), "u.txt"), []string{"PSOC130-A0-00001", "PSOC130-A0-00020"})
		rejects(t, buyerCheck(t, bundle, fresh(t), e2ePolicy, units), "receipt.vsa.intoto.json: covers other units than the 2 received")
	})
	t.Run("signed by a site instead of the auditor", func(t *testing.T) {
		d := fresh(t)
		resignVSA(t, d, keys, "test-site", nil)
		rejects(t, buyerCheck(t, bundle, d, e2ePolicy, e2eUnits), "no valid signature from role 'auditor'")
	})
	t.Run("under another policy", func(t *testing.T) {
		policy := filepath.Join(t.TempDir(), "policy.json")
		editJSON(t, ok(copyTo(e2ePolicy, policy)), func(p Obj) { O(p, "design")["allowedTools"] = []any{"yosys"} })
		rejects(t, buyerCheck(t, bundle, fresh(t), policy, e2eUnits), "design.vsa.intoto.json: verified under a policy other than the buyer's")
	})
	t.Run("a level missing", func(t *testing.T) {
		d := fresh(t)
		resignVSA(t, d, auditorKeys, AuditorRole, func(s Obj) {
			O(s, "predicate")["verifiedLevels"] = []any{"HSLSA_WAFER_LEVEL_2", "HSLSA_DESIGN_LEVEL_2"}
		})
		rejects(t, buyerCheck(t, bundle, d, e2ePolicy, e2eUnits), "receipt.vsa.intoto.json: does not state HSLSA_PACKAGE_TEST_LEVEL_2")
	})
	t.Run("a failed result", func(t *testing.T) {
		d := fresh(t)
		resignVSA(t, d, auditorKeys, AuditorRole, func(s Obj) { O(s, "predicate")["verificationResult"] = "FAILED" })
		rejects(t, buyerCheck(t, bundle, d, e2ePolicy, e2eUnits), "receipt.vsa.intoto.json: verification result FAILED")
	})
	t.Run("VSAs from two audits", func(t *testing.T) {
		// Another buyer's audit of the same lot: its receipt covers other units
		// and names another manifest, so it cannot pair with this design VSA.
		other := writeLines(t, filepath.Join(t.TempDir(), "u.txt"), []string{"PSOC130-A0-00002"})
		d2 := t.TempDir()
		must(t, audit(t, bundle, other, d2))
		d := fresh(t)
		must(t, copyFile(filepath.Join(d2, "vsa", EscrowReceiptVSA), filepath.Join(d, "vsa", EscrowReceiptVSA)))
		rejects(t, buyerCheck(t, bundle, d, e2ePolicy, other), "the design and receipt VSAs do not name the same escrow manifest")
	})
}

func copyTo(src, dst string) (string, error) { return dst, copyFile(src, dst) }

func TestLeaksOnEscrowBundle(t *testing.T) {
	bundle := escrowBundle(t)
	dir := t.TempDir()
	must(t, audit(t, bundle, e2eUnits, dir))
	rep := ok(Leaks(bundle, ok(ReadUnits(e2eUnits)), filepath.Join(dir, "vsa"), DefaultLeakLimits))
	r := O(rep, "records")
	if n := len(Objs(r, "withheld")); n != 9 {
		t.Fatalf("%d withheld fields", n)
	}
	if e := Objs(r, "exposed"); len(e) != 0 {
		t.Fatalf("withheld values shown elsewhere: %v", e)
	}
	for _, f := range Objs(r, "files") {
		if v, _ := get(f, "salted").(bool); !v {
			t.Fatalf("%s is not salted", S(f, "file"))
		}
	}
	// Salted fields do not hide the lots: at Package/Test L2 the lot digests
	// are over serials a buyer can guess from its own units.
	shipped := find(Objs(r, "lots"), "subject", "urn:hslsa:lot:ASM-EXAMPLE-17")
	if len(Strs(shipped, "units")) != 37 || !equalStrings(Strs(shipped, "missing"), []string{"PSOC130-A0-00007", "PSOC130-A0-00019", "PSOC130-A0-00033"}) {
		t.Fatalf("shipped lot %v", shipped)
	}
	if packaged := find(Objs(r, "lots"), "subject", "urn:hslsa:assembly-lot:ASM-EXAMPLE-17"); len(Strs(packaged, "units")) != 40 {
		t.Fatalf("packaged lot %v", packaged)
	}
	if d := Strs(r, "derived"); len(d) != 1 || !strings.Contains(d[0], "37 of 40") {
		t.Fatalf("derived %v", d)
	}
	// The buyer under escrow holds two VSAs, each naming one input.
	vsas := Objs(rep, "escrow", "vsas")
	if len(vsas) != 2 {
		t.Fatalf("escrow view %v", vsas)
	}
	for _, v := range vsas {
		if n, _ := Int(v, "inputs"); n != 1 {
			t.Fatalf("%s names %d inputs", S(v, "vsa"), n)
		}
	}
}
