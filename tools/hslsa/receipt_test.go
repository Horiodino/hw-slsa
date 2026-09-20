package hslsa

// Tamper tests for the EMS's receipt VSA for the chips it received, and for
// the board receipt check's gap report.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const chipReceipt = "receipt-ASM-EXAMPLE-17.vsa.intoto.json"

func TestMissingReceiptIsAGap(t *testing.T) {
	work := boardWork(t)
	must(t, os.Remove(filepath.Join(work, "board", "att", chipReceipt)))
	boardRejects(t, work, "board receipt check: 1 gap(s) in the chain: missing attestation "+chipReceipt+" (Assembly track)")
}

func TestBoardGapReportListsEveryGap(t *testing.T) {
	work := boardWork(t)
	must(t, os.Remove(filepath.Join(work, "board", "att", chipReceipt)))
	must(t, os.Remove(filepath.Join(work, "board", "att", ShipAtt("EXAMPLE-SHIP-0002"))))
	_, err := boardCheck(t, filepath.Join(work, "board"), nil)
	rejects(t, err, "board receipt check: 2 gap(s) in the chain")
	if !strings.Contains(err.Error(), "missing attestation "+ShipAtt("EXAMPLE-SHIP-0002")+" (Assembly track)") {
		t.Fatalf("gap report %q does not name the shipment record", err)
	}
}

func TestReceiptSignedByTheShipper(t *testing.T) {
	work := boardWork(t)
	boardResign(t, work, chipReceipt, "dist-franchised", nil)
	boardRejects(t, work, "no valid signature from role 'ems-site'")
}

func TestReceiptForOtherUnits(t *testing.T) {
	// The EMS signs a receipt for one unit fewer than it was shipped.
	work := boardWork(t)
	units := ok(ReadUnits(filepath.Join(work, "board", "parts", "picosoc", "artifacts", "shipped-lot.txt")))
	other := ok(ReceiptSubject("urn:hslsa:lot:ASM-EXAMPLE-17", units[:3]))
	boardResign(t, work, chipReceipt, emsRole, func(s Obj) { s["subject"] = []any{other} })
	boardRejects(t, work, "covers other units than the 8 shipped to the EMS")
}

func TestReceiptOfAFailedCheck(t *testing.T) {
	work := boardWork(t)
	boardResign(t, work, chipReceipt, emsRole, func(s Obj) { O(s, "predicate")["verificationResult"] = "FAILED" })
	boardRejects(t, work, "not a passed lot receipt check")
}

func TestA1DoesNotLinkTheReceipt(t *testing.T) {
	work := boardWork(t)
	reseal(t, work, func(s Obj) {
		var deps []any
		for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
			if S(d, "name") != "att/"+chipReceipt {
				deps = append(deps, d)
			}
		}
		O(s, "predicate", "buildDefinition")["resolvedDependencies"] = deps
	})
	boardRejects(t, work, "board-assembly: chain broken, resolvedDependencies do not include PSOC130-QFN64 lot, HBOM and receipt att/"+chipReceipt)
}
