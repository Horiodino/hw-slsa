package hslsa

// After-sale records on the FPGA board example (spec, "After-sale records"):
// a field update, a return, a rework and a reshipment, each signed by its
// own role and chained to the record before it. The tests need the same
// fixture as fpga_test.go (`e2e/fpga/run.sh produce` and `boot`).
//
// The update built here keeps the shipped bitstream and firmware and raises
// the SVN, so the root of trust is booted again but the SoC is not: the
// policy copy drops requireSoCBoot. e2e/fpga/run.sh aftersale builds an
// update with new firmware and boots the SoC on it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var afterSaleSite = Obj{"name": "Example Board Co Field Service", "country": "US"}

// afterSaleWork is a copy of the produced example whose trust root also
// lists the field updater, the returns desk and the repair site, and a
// policy that does not ask for the SoC run.
func afterSaleWork(t *testing.T) (work, policy string) {
	t.Helper()
	work = fpgaWork(t)
	keys := filepath.Join(work, "keys")
	must(t, makeKeys(keys, filepath.Join(keys, "pub"), "field-updater", "returns-site", "repair-site"))
	must(t, BuildTrustRoot(filepath.Join(keys, "pub"), filepath.Join(work, "board", "trust-root.json")))
	policy = filepath.Join(work, "policy.json")
	editJSON(t, ok(copyTo(fpgaPolicy, policy)), func(p Obj) { O(p, "firmware")["requireSoCBoot"] = false })
	return work, policy
}

func afterSaleVerify(t *testing.T, work, policy string) error {
	t.Helper()
	bundle := filepath.Join(work, "board")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	return FPGAVerify(bundle, trust, policy, filepath.Join(root, "e2e", "fpga", "received-boards.txt"), filepath.Join(work, "boots"), "", "")
}

func afterSaleKey(work, role string) string {
	return filepath.Join(work, "keys", role+".key.pem")
}

// buildUpdate lays out updates/<id> from the shipped firmware and bitstream
// with a boot manifest at svn: the firmware platform's records for the
// firmware are the shipped ones, the flash image's are new.
func buildUpdate(t *testing.T, work, id string, svn int) string {
	t.Helper()
	design := filepath.Join(work, "board", FPGADesignDir)
	dir := filepath.Join(work, "board", UpdatesDir, id)
	lock := filepath.Join(work, id+".lock.json")
	editJSON(t, ok(copyTo(filepath.Join(design, "inputs.lock.json"), lock)), func(l Obj) { O(l, "firmware")["svn"] = svn })
	for _, f := range []string{"att/" + AttName("release"), "att/" + FPGAFWAtt, "artifacts/icebreaker.bin", "artifacts/" + FPGAFWImage,
		"artifacts/" + FPGAFWSBOM, "artifacts/firmware-build.log"} {
		must(t, copyFile(filepath.Join(design, f), filepath.Join(dir, f)))
	}
	must(t, FPGAImage(dir, lock, filepath.Join(root, "e2e", "fpga", "board-scenario.json"),
		afterSaleKey(work, "firmware-platform"), afterSaleKey(work, "code-signer")))
	return dir
}

func fieldUpdate(t *testing.T, work, serial, dir string) {
	t.Helper()
	must(t, FPGAFieldUpdate(filepath.Join(work, "board"), filepath.Join(work, "boards"), serial, dir, afterSaleKey(work, "field-updater"), afterSaleSite, nil))
	if !fpgaReboot(t, work, serial) {
		t.Fatalf("board %s did not release its FPGA after the update", serial)
	}
}

func TestFPGAFieldUpdateVerifies(t *testing.T) {
	work, policy := afterSaleWork(t)
	serial := fpgaReceived(t)[0]
	fieldUpdate(t, work, serial, buildUpdate(t, work, "U1", 2))
	must(t, afterSaleVerify(t, work, policy))
	rec := ok(DecodeEnvelope(filepath.Join(work, "board", "att", AfterSaleAtt(serial, 1))))
	hw := O(rec, "predicate", "hwAfterSale")
	if S(hw, "event") != "field-update" || S(hw, "previous", "name") != "att/"+BoardProvAtt(serial) {
		t.Fatalf("record 1: %v", hw)
	}
	if fuse, _ := Int(hw, "fuses", ownerFuseSVN); fuse != 2 {
		t.Fatalf("the record says the fuse reads %d, want 2", fuse)
	}
	// A second update chains to the first, and the board must hold the latest.
	fieldUpdate(t, work, serial, buildUpdate(t, work, "U2", 3))
	must(t, afterSaleVerify(t, work, policy))
	if prev := S(ok(DecodeEnvelope(filepath.Join(work, "board", "att", AfterSaleAtt(serial, 2)))), "predicate", "hwAfterSale", "previous", "name"); prev != "att/"+AfterSaleAtt(serial, 1) {
		t.Fatalf("record 2 follows %s", prev)
	}
}

func TestFPGAReturnReworkReshipVerifies(t *testing.T) {
	work, policy := afterSaleWork(t)
	bundle := filepath.Join(work, "board")
	serial := fpgaReceived(t)[1]
	must(t, FPGAReturn(bundle, serial, afterSaleKey(work, "returns-site"), Obj{"name": "Example Board Co Returns"}, nil,
		"Example Buyer", "3.3 V rail out of tolerance", "repair"))
	order := filepath.Join(work, "rework.json")
	must(t, WriteJSON(order, Obj{"reason": "U4 output at 3.05 V", "parts": []any{Obj{
		"refDes":  "U4",
		"removed": Obj{"manufacturer": "Texas Instruments", "mpn": "TLV75533PDBVR", "lot": "unknown"},
		"placed":  Obj{"manufacturer": "Texas Instruments", "mpn": "TLV75533PDBVR", "lot": "TI-LOT-RW-0042"},
	}}}))
	must(t, FPGARework(bundle, serial, afterSaleKey(work, "repair-site"), Obj{"name": "Example Repair Site"}, nil, order))
	// Returned and reworked but not shipped again: the buyer does not hold it in service.
	rejects(t, afterSaleVerify(t, work, policy), "board "+serial+": was returned to Example Repair Site and not shipped again")
	must(t, FPGAReship(bundle, serial, afterSaleKey(work, boardOwnerRole), Obj{"name": "Example Board Co"}, nil, "Example Buyer", "EXAMPLE-SHIP-0201"))
	must(t, afterSaleVerify(t, work, policy))
}

func TestFPGAAfterSaleRejects(t *testing.T) {
	serial := func(t *testing.T) string { return fpgaReceived(t)[0] }
	t.Run("firmware changed with no update record", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		dir := buildUpdate(t, work, "U1", 2)
		// Someone writes the update and raises the fuse, but signs nothing.
		must(t, copyFile(filepath.Join(dir, "artifacts", FlashImage), filepath.Join(work, "boards", s, FlashImage)))
		fuses := filepath.Join(work, "boards", s, "rot", "fuses.json")
		editJSON(t, fuses, func(f Obj) { f[ownerFuseSVN] = 2 })
		if !fpgaReboot(t, work, s) {
			t.Fatal("the root of trust held a validly signed update")
		}
		rejects(t, afterSaleVerify(t, work, policy), "in flash matches no reference value in the board CoRIM")
	})
	t.Run("an update signed by another role", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		must(t, FPGAFieldUpdate(filepath.Join(work, "board"), filepath.Join(work, "boards"), s, buildUpdate(t, work, "U1", 2),
			afterSaleKey(work, "ems-site"), afterSaleSite, nil))
		rejects(t, afterSaleVerify(t, work, policy), AfterSaleAtt(s, 1)+": no valid signature from role 'field-updater'")
	})
	t.Run("an update that rolls the board back", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		fieldUpdate(t, work, s, buildUpdate(t, work, "U1", 3))
		// A later update at a lower SVN: the root of trust holds the FPGA and the
		// updater's own gates fail. An updater who signs it as passed anyway is refused on the record.
		err := FPGAFieldUpdate(filepath.Join(work, "board"), filepath.Join(work, "boards"), s, buildUpdate(t, work, "U2", 2),
			afterSaleKey(work, "field-updater"), afterSaleSite, nil)
		if err == nil || !strings.Contains(err.Error(), "svn-fuse, boot-released failed") {
			t.Fatalf("the updater signed a rollback as passed: %v", err)
		}
		resign(t, filepath.Join(work, "board", "att", AfterSaleAtt(s, 2)), filepath.Join(work, "keys"), "field-updater", func(st Obj) {
			hw := O(st, "predicate", "hwAfterSale")
			hw["checks"] = passedChecks(Objs(hw, "checks"))
			O(hw, "fuses")[ownerFuseSVN] = 2
		})
		rejects(t, afterSaleVerify(t, work, policy), "rolls the board back from SVN 3 to 2")
	})
	t.Run("an update outside the updates directory", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		fieldUpdate(t, work, s, buildUpdate(t, work, "U1", 2))
		resign(t, filepath.Join(work, "board", "att", AfterSaleAtt(s, 1)), filepath.Join(work, "keys"), "field-updater", func(st Obj) {
			O(st, "predicate", "hwAfterSale", "update", "provenance")["name"] = FPGADesignDir + "/att/" + FlashAtt
		})
		rejects(t, afterSaleVerify(t, work, policy), "is not in an update directory")
	})
	t.Run("a record cut from the history", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		bundle := filepath.Join(work, "board")
		must(t, FPGAReturn(bundle, s, afterSaleKey(work, "returns-site"), Obj{"name": "Returns"}, nil, "Example Buyer", "dead on arrival", "repair"))
		must(t, FPGAReship(bundle, s, afterSaleKey(work, boardOwnerRole), Obj{"name": "Example Board Co"}, nil, "Example Buyer", "S-1"))
		must(t, os.Remove(filepath.Join(bundle, "att", AfterSaleAtt(s, 1))))
		rejects(t, afterSaleVerify(t, work, policy), "has 1 after-sale records, but record 1 is missing")
	})
	t.Run("records out of order", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		bundle := filepath.Join(work, "board")
		must(t, FPGAReturn(bundle, s, afterSaleKey(work, "returns-site"), Obj{"name": "Returns"}, nil, "Example Buyer", "dead on arrival", "repair"))
		must(t, FPGAReship(bundle, s, afterSaleKey(work, boardOwnerRole), Obj{"name": "Example Board Co"}, nil, "Example Buyer", "S-1"))
		att := filepath.Join(bundle, "att")
		must(t, os.Rename(filepath.Join(att, AfterSaleAtt(s, 1)), filepath.Join(att, "tmp")))
		must(t, os.Rename(filepath.Join(att, AfterSaleAtt(s, 2)), filepath.Join(att, AfterSaleAtt(s, 1))))
		must(t, os.Rename(filepath.Join(att, "tmp"), filepath.Join(att, AfterSaleAtt(s, 2))))
		rejects(t, afterSaleVerify(t, work, policy), "after-sale record 1 (reship): numbered 2")
	})
	t.Run("a reship of a board never returned", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		must(t, FPGAReship(filepath.Join(work, "board"), s, afterSaleKey(work, boardOwnerRole), Obj{"name": "Example Board Co"}, nil, "Someone", "S-1"))
		rejects(t, afterSaleVerify(t, work, policy), "ships a board that was not returned")
	})
	t.Run("a scrapped board", func(t *testing.T) {
		work, policy := afterSaleWork(t)
		s := serial(t)
		must(t, FPGAReturn(filepath.Join(work, "board"), s, afterSaleKey(work, "returns-site"), Obj{"name": "Returns"}, nil, "Example Buyer", "burnt", "scrap"))
		rejects(t, afterSaleVerify(t, work, policy), "board "+s+": was returned and scrapped")
	})
	for _, c := range []struct{ name, ref, mpn, reason string }{
		{"a rework of the root of trust", "U5", "EXR-01", "replaces the root of trust at U5"},
		{"a rework placing another part", "U4", "TLV75512PDBVR", "but the board design places Texas Instruments TLV75533PDBVR there"},
	} {
		t.Run(c.name, func(t *testing.T) {
			work, policy := afterSaleWork(t)
			s := serial(t)
			bundle := filepath.Join(work, "board")
			must(t, FPGAReturn(bundle, s, afterSaleKey(work, "returns-site"), Obj{"name": "Returns"}, nil, "Example Buyer", "fails", "repair"))
			mfr := "Texas Instruments"
			if c.ref == "U5" {
				mfr = "Example RoT Co"
			}
			order := filepath.Join(work, "rework.json")
			must(t, WriteJSON(order, Obj{"reason": "test", "parts": []any{Obj{
				"refDes":  c.ref,
				"removed": Obj{"manufacturer": mfr, "mpn": map[bool]string{true: "EXR-01", false: "TLV75533PDBVR"}[c.ref == "U5"], "lot": "x"},
				"placed":  Obj{"manufacturer": mfr, "mpn": c.mpn, "lot": "y"},
			}}}))
			must(t, FPGARework(bundle, s, afterSaleKey(work, "repair-site"), Obj{"name": "Repair"}, nil, order))
			must(t, FPGAReship(bundle, s, afterSaleKey(work, boardOwnerRole), Obj{"name": "Example Board Co"}, nil, "Example Buyer", "S-1"))
			rejects(t, afterSaleVerify(t, work, policy), c.reason)
		})
	}
}

// passedChecks is checks with every result set to passed.
func passedChecks(checks []Obj) []any {
	var out []any
	for _, c := range checks {
		c["result"] = "pass"
		out = append(out, c)
	}
	return out
}

func TestFPGAAfterSaleSimulatedMark(t *testing.T) {
	mark := ok(AfterSaleSimulated(filepath.Join(root, "e2e", "fpga", "board-scenario.json")))
	if !strings.Contains(S(mark, "standsIn"), "field updater") {
		t.Fatalf("mark %v", mark)
	}
	work, _ := afterSaleWork(t)
	s := fpgaReceived(t)[0]
	must(t, FPGAReturn(filepath.Join(work, "board"), s, afterSaleKey(work, "returns-site"), Obj{"name": "Returns"}, mark, "Example Buyer", "x", "repair"))
	// The buyer's policy refuses simulated evidence unless it opts in (fpgaPolicy does, for the board).
	rec := ok(DecodeEnvelope(filepath.Join(work, "board", "att", AfterSaleAtt(s, 1))))
	if simulatedOf(rec) == nil {
		t.Fatal("the after-sale record carries no simulated mark")
	}
}
