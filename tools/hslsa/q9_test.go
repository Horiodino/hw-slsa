package hslsa

// Escrow auditors the buyer accredits, the per-unit commitment in final test,
// and manufacturing records in a transparency log, on the PicoRV32 chain.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// auditorTrustRoot is a buyer-run trust root that enrolls the escrow
// fixture's auditor key under acc (no accreditation when acc is empty).
func auditorTrustRoot(t *testing.T, bundle string, acc Accreditation) string {
	t.Helper()
	dir := t.TempDir()
	ok(Keygen(dir, "buyer-root"))
	e := Enrollment{Role: AuditorRole, OrgName: "Example Audit LLP", OrgID: "duns:100000077", Site: "Example Audit LLP", Custody: "file",
		Accreditation: acc, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	pub := filepath.Join(escrowWork(bundle), "buyer-pub", AuditorRole+".pub.pem")
	must(t, Enroll(filepath.Join(dir, "buyer-root.key.pem"), pub, e, filepath.Join(dir, "enrolled", AuditorRole+".intoto.json")))
	out := filepath.Join(dir, "trust-root.json")
	ok(BuildPilotTrustRoot(filepath.Join(dir, "buyer-root.pub.pem"), filepath.Join(dir, "enrolled"), time.Now(), out))
	return out
}

func auditorPolicy(t *testing.T, schemes ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	editJSON(t, ok(copyTo(e2ePolicy, path)), func(p Obj) { p["escrow"] = Obj{"auditorAccreditations": anyStrings(schemes)} })
	return path
}

func TestEscrowCheckAcceptsAnAccreditedAuditor(t *testing.T) {
	bundle := escrowBundle(t)
	dir := t.TempDir()
	policy := auditorPolicy(t, "iso-iec-17020", "iso-iec-17065")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	key := filepath.Join(escrowWork(bundle), "auditor", AuditorRole+".key.pem")
	must(t, EscrowAudit(bundle, trust, policy, e2eUnits, key, filepath.Join(dir, "vsa"), filepath.Join(dir, "escrow-manifest.json")))
	buyer := ok(LoadTrustRoot(auditorTrustRoot(t, bundle, Accreditation{Scheme: "iso-iec-17065", ID: "ANAB-0001"})))
	must(t, EscrowCheck(filepath.Join(dir, "vsa"), buyer, policy, e2eUnits))
}

func TestEscrowAuditorAccreditationRejects(t *testing.T) {
	bundle := escrowBundle(t)
	dir := t.TempDir()
	policy := auditorPolicy(t, "iso-iec-17065")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	key := filepath.Join(escrowWork(bundle), "auditor", AuditorRole+".key.pem")
	must(t, EscrowAudit(bundle, trust, policy, e2eUnits, key, filepath.Join(dir, "vsa"), filepath.Join(dir, "escrow-manifest.json")))
	check := func(trustRoot string) error {
		return EscrowCheck(filepath.Join(dir, "vsa"), ok(LoadTrustRoot(trustRoot)), policy, e2eUnits)
	}
	t.Run("auditor not enrolled", func(t *testing.T) {
		rejects(t, check(filepath.Join(escrowWork(bundle), "buyer-trust-root.json")), "which the trust root lists without an enrollment")
	})
	t.Run("auditor enrolled with no accreditation", func(t *testing.T) {
		rejects(t, check(auditorTrustRoot(t, bundle, Accreditation{})), "which is enrolled with no accreditation")
	})
	t.Run("auditor accredited under an unlisted scheme", func(t *testing.T) {
		rejects(t, check(auditorTrustRoot(t, bundle, Accreditation{Scheme: "iso-iec-17025", ID: "A2LA-1"})),
			`accredited under "iso-iec-17025", which the policy's escrow.auditorAccreditations do not list`)
	})
}

// committedBundle is a chip bundle whose final test commits to its units.
func committedBundle(t *testing.T) string {
	t.Helper()
	chip := chipBundle(t)
	valid := shared(t, "committed", func(work string) error {
		if err := copyTree(filepath.Dir(chip), work); err != nil {
			return err
		}
		sc, err := ReadObj(e2eScenario)
		if err != nil {
			return err
		}
		O(sc, "finalTest")["unitCommitment"] = true
		scenario := filepath.Join(work, "committed-scenario.json")
		if err := WriteJSON(scenario, sc); err != nil {
			return err
		}
		bundle, keys := filepath.Join(work, "bundle"), filepath.Join(work, "keys")
		if err := Mfg(bundle, scenario, keys, nil); err != nil {
			return err
		}
		return BuildHBOM(bundle, e2eLock, scenario, filepath.Join(keys, "product-owner.key.pem"), nil)
	})
	return filepath.Join(copyOf(t, valid), "bundle")
}

func commitPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	editJSON(t, ok(copyTo(e2ePolicy, path)), func(p Obj) { O(p, "manufacturing")["unitCommitment"] = true })
	return path
}

func TestUnitCommitmentVerifies(t *testing.T) {
	bundle := committedBundle(t)
	f4 := ok(DecodeEnvelope(filepath.Join(bundle, "att", MfgAtt["final-test"])))
	c := O(f4, "predicate", "hwMfg", "unitCommitment")
	if size, _ := Int(c, "treeSize"); S(c, "format") != UnitCommitmentFormat || size != 64 {
		t.Fatalf("commitment %v (37 shipped units pad to 64)", c)
	}
	// The receipt check with the policy's rule, for the received units and for the whole lot.
	units := ok(ReadUnits(e2eUnits))
	must(t, chipCheckPolicy(t, bundle, units, commitPolicy(t)))
	must(t, chipCheckPolicy(t, bundle, nil, commitPolicy(t)))
	// The buyer's own check: the F4 record and its units' proofs, nothing else.
	var proofs []string
	for _, u := range units {
		proofs = append(proofs, UnitProofPath(bundle, u))
	}
	must(t, UnitCheck(ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))), filepath.Join(bundle, "att", MfgAtt["final-test"]), proofs))
}

func TestUnitCommitmentRejects(t *testing.T) {
	trustOf := func(b string) *TrustRoot { return ok(LoadTrustRoot(filepath.Join(b, "trust-root.json"))) }
	f4Of := func(b string) string { return filepath.Join(b, "att", MfgAtt["final-test"]) }
	t.Run("a unit final test failed", func(t *testing.T) {
		bundle := committedBundle(t)
		// A proof for a scrapped unit, made up with the shape of a real one.
		p := ok(ReadObj(UnitProofPath(bundle, "PSOC130-A0-00001")))
		p["unit"] = "PSOC130-A0-00007"
		forged := filepath.Join(t.TempDir(), "PSOC130-A0-00007.json")
		must(t, WriteJSON(forged, p))
		rejects(t, UnitCheck(trustOf(bundle), f4Of(bundle), []string{forged}), "unit PSOC130-A0-00007 is not in the lot final test committed to")
	})
	t.Run("a proof from another lot's commitment", func(t *testing.T) {
		a, b := committedBundle(t), committedBundle(t)
		// Final test signs b's lot again: a new commitment, with fresh salts and order, so b's proof fails under a's root.
		must(t, Mfg(b, filepath.Join(filepath.Dir(b), "committed-scenario.json"), chipKeys(b), nil))
		must(t, copyFile(UnitProofPath(b, "PSOC130-A0-00001"), UnitProofPath(a, "PSOC130-A0-00001")))
		rejects(t, UnitCheck(trustOf(a), f4Of(a), []string{UnitProofPath(a, "PSOC130-A0-00001")}), "is not in the lot final test committed to")
	})
	t.Run("a proof for another unit", func(t *testing.T) {
		bundle := committedBundle(t)
		must(t, copyFile(UnitProofPath(bundle, "PSOC130-A0-00002"), UnitProofPath(bundle, "PSOC130-A0-00001")))
		rejects(t, chipCheckPolicy(t, bundle, []string{"PSOC130-A0-00001"}, commitPolicy(t)), "the proof is for unit PSOC130-A0-00002")
	})
	t.Run("a received unit with no proof", func(t *testing.T) {
		bundle := committedBundle(t)
		must(t, os.Remove(UnitProofPath(bundle, "PSOC130-A0-00001")))
		rejects(t, chipCheckPolicy(t, bundle, []string{"PSOC130-A0-00001"}, commitPolicy(t)), "no inclusion proof for unit PSOC130-A0-00001")
	})
	t.Run("final test without a commitment", func(t *testing.T) {
		rejects(t, chipCheckPolicy(t, chipBundle(t), nil, commitPolicy(t)), "final test carries no per-unit commitment")
	})
	t.Run("a commitment edited without re-signing", func(t *testing.T) {
		bundle := committedBundle(t)
		editPayload(t, f4Of(bundle), func(s Obj) { O(s, "predicate", "hwMfg", "unitCommitment")["treeSize"] = 128 })
		rejects(t, UnitCheck(trustOf(bundle), f4Of(bundle), []string{UnitProofPath(bundle, "PSOC130-A0-00001")}), "no valid signature from role 'test-site'")
	})
}

const mfgLogOrigin = "example buyer manufacturing log"

// loggedBundle is a chip bundle whose manufacturing records, transfers and
// HBOM are in a log the buyer runs, and the buyer's trust root with its key.
func loggedBundle(t *testing.T) string {
	t.Helper()
	chip := chipBundle(t)
	valid := shared(t, "mfg-logged", func(work string) error {
		if err := copyTree(filepath.Dir(chip), work); err != nil {
			return err
		}
		bundle, keys := filepath.Join(work, "bundle"), filepath.Join(work, "keys")
		if err := makeKeys(keys, filepath.Join(work, "pub"), TLogRole); err != nil {
			return err
		}
		if err := BuildTrustRoot(filepath.Join(work, "pub"), filepath.Join(bundle, "trust-root.json")); err != nil {
			return err
		}
		log := filepath.Join(work, "log")
		if err := TLogInit(log, mfgLogOrigin); err != nil {
			return err
		}
		records, err := filepath.Glob(filepath.Join(bundle, "att", "mfg-*.intoto.json"))
		if err != nil {
			return err
		}
		for _, r := range append(records, filepath.Join(bundle, "att", "hbom.intoto.json")) {
			if err := TLogAdd(log, filepath.Join(keys, TLogRole+".key.pem"), r); err != nil {
				return err
			}
		}
		return nil
	})
	return filepath.Join(copyOf(t, valid), "bundle")
}

func logPolicy(t *testing.T, origin string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	editJSON(t, ok(copyTo(e2ePolicy, path)), func(p Obj) { O(p, "manufacturing")["transparencyLog"] = Obj{"origin": origin} })
	return path
}

func TestManufacturingRecordsLoggedVerifies(t *testing.T) {
	bundle := loggedBundle(t)
	units := ok(ReadUnits(e2eUnits))
	must(t, chipCheckPolicy(t, bundle, units, logPolicy(t, mfgLogOrigin)))
	// The same bundle under the example's policy, which names no log.
	must(t, chipCheck(t, bundle, units))
	_, lot, err := Verify(bundle, ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))), logPolicy(t, mfgLogOrigin), "", "", "")
	must(t, err)
	if find(lot.Inputs, "name", "att/"+filepath.Base(TLogProofPath(MfgAtt["final-test"]))) == nil {
		t.Fatalf("the lot's inputs do not name final test's inclusion proof: %v", lot.Inputs)
	}
}

func TestManufacturingLogRejects(t *testing.T) {
	t.Run("a record not in the log", func(t *testing.T) {
		bundle := loggedBundle(t)
		must(t, os.Remove(TLogProofPath(filepath.Join(bundle, "att", MfgAtt["packaging"]))))
		rejects(t, chipCheckPolicy(t, bundle, nil, logPolicy(t, mfgLogOrigin)), "mfg-f3-packaging.intoto.json is not in a transparency log")
	})
	t.Run("a record signed again after it was logged", func(t *testing.T) {
		// The product owner signs a second HBOM for the lot; the log holds only the first.
		bundle := loggedBundle(t)
		chipResign(t, bundle, "hbom.intoto.json", "product-owner", func(s Obj) {
			O(s, "predicate", "product")["name"] = "PicoSoC, second edition"
		})
		rejects(t, chipCheckPolicy(t, bundle, nil, logPolicy(t, mfgLogOrigin)), "the log entry is not this record")
	})
	t.Run("logged in another log", func(t *testing.T) {
		rejects(t, chipCheckPolicy(t, loggedBundle(t), nil, logPolicy(t, "another log")), "not the log the policy names")
	})
}
