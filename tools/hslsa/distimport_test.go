package hslsa

// The distributor importer (distimport.go): shipments made from the
// shippers' packing lists, certificates of conformance and EPCIS events,
// carried by the distribution records and read again by the board check.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var shipmentExports = filepath.Join(boardDir, "distributor-exports")

// importedBoard is the board example produced again from the shippers'
// exports, with a policy that requires them.
func importedBoard(t *testing.T) (work, policy string) {
	t.Helper()
	work = boardWork(t)
	scenario := filepath.Join(work, "scenario.json")
	must(t, ImportShipments(filepath.Join(shipmentExports, "shipments.json"), boardScenario, scenario))
	must(t, boardProduce(work, scenario))
	policy = filepath.Join(work, "policy.json")
	editJSON(t, ok(copyTo(boardPolicy, policy)), func(p Obj) { p["requireShipmentExports"] = true })
	return work, policy
}

func importedCheck(t *testing.T, work, policy string) (*LotResult, error) {
	t.Helper()
	bundle := filepath.Join(work, "board")
	return BoardVerify(bundle, ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))), policy, "", "", "")
}

func TestImportedShipmentsVerifies(t *testing.T) {
	work, policy := importedBoard(t)
	res, err := importedCheck(t, work, policy)
	must(t, err)
	got := strings.Join(res.Exports, "\n")
	for _, want := range []string{
		"distribution mfg-distribution-EXAMPLE-SHIP-0001.intoto.json: matches packing-list-EXAMPLE-SHIP-0001.csv, coc-EXAMPLE-SHIP-0001.txt, epcis-EXAMPLE-SHIP-0001.json",
		"distribution mfg-distribution-EXAMPLE-SHIP-0002.intoto.json: matches packing-list-EXAMPLE-SHIP-0002.csv, coc-EXAMPLE-SHIP-0002.txt",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not say %q:\n%s", want, got)
		}
	}
	// The imported shipments carry the scenario's lines, plus each line's
	// certificate and the distributor's shipping event.
	ship := ok(ReadObj(filepath.Join(work, "board", "artifacts", "shipment-EXAMPLE-SHIP-0001.json")))
	sc := ok(ReadObj(boardScenario))
	want := Objs(sc, "shipments")[0]
	lines := Objs(ship, "lines")
	if len(lines) != len(Objs(want, "lines")) || S(ship, "epcis", "eventTime") != "2026-09-14T16:00:00Z" {
		t.Fatalf("shipment %v", ship)
	}
	for i, l := range Objs(want, "lines") {
		if S(lines[i], "lot") != S(l, "lot") || !jsonEqual(get(lines[i], "units"), get(l, "units")) || S(lines[i], "coc", "name") != "coc-EXAMPLE-SHIP-0001.txt" {
			t.Fatalf("line %d: %v, want %v", i, lines[i], l)
		}
	}
}

func TestImportedShipmentRejects(t *testing.T) {
	t.Run("a policy that requires exports, on shipments without them", func(t *testing.T) {
		work := boardWork(t)
		_, policy := importedBoard(t)
		_, err := importedCheck(t, work, policy)
		rejects(t, err, "the policy requires each shipment to carry its shipper's exports (requireShipmentExports)")
	})
	t.Run("a certificate changed after signing", func(t *testing.T) {
		work, policy := importedBoard(t)
		appendFile(t, filepath.Join(work, "board", "artifacts", "coc-EXAMPLE-SHIP-0001.txt"), "\nRevised.")
		_, err := importedCheck(t, work, policy)
		rejects(t, err, "export coc-EXAMPLE-SHIP-0001.txt is missing or does not match its attested digest")
	})
	t.Run("a shipment that differs from its packing list", func(t *testing.T) {
		// The distributor signs a shipment with another date code than its packing list.
		work, policy := importedBoard(t)
		data := filepath.Join(work, "board", "artifacts", "shipment-EXAMPLE-SHIP-0001.json")
		editJSON(t, data, func(v Obj) { Objs(v, "lines")[1]["dateCode"] = "EXAMPLE-2601" })
		boardResign(t, work, ShipAtt("EXAMPLE-SHIP-0001"), "dist-franchised", func(s Obj) { firstSubject(s)["digest"] = fileDigest(data) })
		_, err := importedCheck(t, work, policy)
		rejects(t, err, "distribution mfg-distribution-EXAMPLE-SHIP-0001.intoto.json: the shipment differs from its shipper's exports")
	})
	for _, c := range []struct{ name, file, from, to, reason string }{
		{"a line with no certificate", "packing-list-EXAMPLE-SHIP-0002.csv", ",coc-EXAMPLE-SHIP-0002.txt", ",", "names no certificate of conformance"},
		{"serials that do not match the quantity", "packing-list-EXAMPLE-SHIP-0001.csv", "PSOC130-A0-00009,", "PSOC130-A0-00009|PSOC130-A0-00010,", "lists 9 serials for a quantity of 8"},
		{"a shipping event on another day", "epcis-EXAMPLE-SHIP-0001.json", `"2026-09-14T16:00:00Z"`, `"2026-09-12T16:00:00Z"`, "the shipping event is on 2026-09-12, the packing list's ship date is 2026-09-14"},
		{"a second shipping event", "epcis-EXAMPLE-SHIP-0001.json", `"bizStep": "packing"`, `"bizStep": "urn:epcglobal:cbv:bizstep:shipping"`, "want one shipping ObjectEvent, found 2"},
		{"rows from two shipments", "packing-list-EXAMPLE-SHIP-0001.csv", "EXAMPLE-SHIP-0001,2026-09-14,Example Franchised Distributor,US,Winbond", "EXAMPLE-SHIP-0003,2026-09-14,Example Franchised Distributor,US,Winbond", "row 3 is in another shipment"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "exports")
			must(t, copyTree(shipmentExports, dir))
			editFile(t, filepath.Join(dir, c.file), func(s string) string {
				if !strings.Contains(s, c.from) {
					t.Fatalf("%s has no %q", c.file, c.from)
				}
				return strings.Replace(s, c.from, c.to, 1)
			})
			err := ImportShipments(filepath.Join(dir, "shipments.json"), boardScenario, filepath.Join(t.TempDir(), "scenario.json"))
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("the importer accepted it, or refused for another reason: %v", err)
			}
		})
	}
	t.Run("a certificate that covers no line", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "exports")
		must(t, copyTree(shipmentExports, dir))
		must(t, os.WriteFile(filepath.Join(dir, "coc-extra.txt"), []byte("another certificate"), 0o644))
		editJSON(t, filepath.Join(dir, "shipments.json"), func(v Obj) {
			s := Objs(v, "shipments")[1]
			s["exports"] = append(A(s, "exports"), Obj{"path": "coc-extra.txt", "format": FmtCoC})
		})
		err := ImportShipments(filepath.Join(dir, "shipments.json"), boardScenario, filepath.Join(t.TempDir(), "scenario.json"))
		if err == nil || !strings.Contains(err.Error(), "certificate of conformance coc-extra.txt covers no line of the packing list") {
			t.Fatalf("%v", err)
		}
	})
}
