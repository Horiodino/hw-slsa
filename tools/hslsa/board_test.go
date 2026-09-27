package hslsa

// Tamper tests for the board-level example: parts[], distributor lot data and A1.
//
// Needs the chip bundle from `e2e/run.sh produce` (HSLSA_BUNDLE, default
// out/bundle). The fixture builds the board on top of it with fresh test keys,
// so tests can forge validly signed records the way an insider at a
// distributor, the EMS or the board owner could.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	boardDir      = filepath.Join(root, "e2e", "board")
	boardScenario = filepath.Join(boardDir, "board-scenario.json")
	boardDesign   = filepath.Join(boardDir, "board-design.json")
	boardPolicy   = filepath.Join(boardDir, "policy.json")
	boardRoles    = []string{"ems-site", "board-owner", "dist-franchised", "dist-broker", "pcb-fab"}
)

const flash = "W25Q128JVSIQ"

func TestCommittedBoardExample(t *testing.T) {
	// The committed board HBOM validates, and its subjects are reproducible from committed files.
	example := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-devboard.hbom.intoto.json")))
	must(t, ValidateHBOM(example["predicate"]))
	subjects := Objs(example, "subject")
	if S(subjects[0], "digest", "sha256") != ok(sha256File(boardDesign)) {
		t.Fatal("design subject does not match board-design.json")
	}
	units := ok(ReadUnits(filepath.Join(root, "hbom", "picosoc-devboard.board-lot.txt")))
	if S(subjects[1], "digest", "sha256") != ok(LotDigest(units)) {
		t.Fatal("lot subject does not match the board lot list")
	}
}

// Schema: the level decides which manufacturing block is required.

func boardPredicate() Obj {
	return Obj{
		"hbomVersion":   "0.1",
		"product":       Obj{"name": "b", "level": "board", "manufacturer": Obj{"name": "m"}},
		"manufacturing": Obj{"boardAssembly": Obj{"ems": Obj{"name": "e"}}},
		"parts":         []any{Obj{"manufacturer": Obj{"name": "Winbond Electronics"}, "mpn": flash}},
	}
}

func TestSchemaAcceptsABoard(t *testing.T) {
	must(t, ValidateHBOM(boardPredicate()))
}

func TestSchemaRejectsMissingBlocks(t *testing.T) {
	for name, mutate := range map[string]func(Obj){
		"board-without-parts":    func(p Obj) { delete(p, "parts") },
		"board-without-assembly": func(p Obj) { delete(O(p, "manufacturing"), "boardAssembly") },
		"package-without-fab":    func(p Obj) { O(p, "product")["level"] = "package" },
	} {
		t.Run(name, func(t *testing.T) {
			p := boardPredicate()
			mutate(p)
			rejects(t, ValidateHBOM(p), "HBOM does not match its schema")
		})
	}
}

// Chain tests

func boardProduce(work, scenario string) error {
	return BoardProduce(filepath.Join(work, "board"), filepath.Join(work, "chip"), scenario, boardDesign, boardPolicy, filepath.Join(work, "keys"))
}

// boardWork is a fresh copy of a work directory holding chip/, board/ and keys/.
func boardWork(t *testing.T) string {
	t.Helper()
	chip := chipSource()
	requireDir(t, filepath.Join(chip, "att"), "run e2e/run.sh produce first")
	valid := shared(t, "board", func(work string) error {
		if err := copyTree(chip, filepath.Join(work, "chip")); err != nil {
			return err
		}
		if err := makeKeys(filepath.Join(work, "keys"), filepath.Join(work, "pub"), boardRoles...); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(work, "board"), 0o755); err != nil {
			return err
		}
		if err := BuildTrustRoot(filepath.Join(work, "pub"), filepath.Join(work, "board", "trust-root.json")); err != nil {
			return err
		}
		return boardProduce(work, boardScenario)
	})
	return copyOf(t, valid)
}

func boardCheck(t *testing.T, bundle string, boards []string) (*LotResult, error) {
	t.Helper()
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	received := ""
	if boards != nil {
		received = writeLines(t, filepath.Join(t.TempDir(), "boards.txt"), boards)
	}
	return BoardVerify(bundle, trust, boardPolicy, received, "", "")
}

func boardRejects(t *testing.T, work, reason string, boards ...string) {
	t.Helper()
	_, err := boardCheck(t, filepath.Join(work, "board"), boards)
	rejects(t, err, reason)
}

func boardResign(t *testing.T, work, name, role string, mutate func(Obj)) {
	t.Helper()
	resign(t, filepath.Join(work, "board", "att", name), filepath.Join(work, "keys"), role, mutate)
}

// reseal re-signs A1 over the current build records (an EMS insider), then the HBOM over that A1 (a trusting owner).
func reseal(t *testing.T, work string, a1Mutate func(Obj)) {
	t.Helper()
	bundle := filepath.Join(work, "board")
	build := ok(fileRD(filepath.Join(bundle, "artifacts", BoardBuild), ""))
	boardResign(t, work, BoardA1, emsRole, func(s Obj) {
		subjects := Objs(s, "subject")
		for i, x := range subjects {
			if S(x, "name") == BoardBuild {
				subjects[i] = build
			}
		}
		s["subject"] = subjects
		if a1Mutate != nil {
			a1Mutate(s)
		}
	})
	ref := fileRef(bundle, "att/"+BoardA1)
	boardResign(t, work, BoardHBOM, boardOwnerRole, func(s Obj) {
		O(s, "predicate", "manufacturing", "boardAssembly")["attestationRef"] = ref
	})
}

func editScenario(t *testing.T, work string, mutate func(Obj)) string {
	t.Helper()
	sc := ok(ReadObj(boardScenario))
	mutate(sc)
	path := filepath.Join(work, "scenario.json")
	must(t, WriteJSON(path, sc))
	return path
}

func part(s Obj, mpn string) Obj { return find(Objs(s, "predicate", "parts"), "mpn", mpn) }

func editBuilds(t *testing.T, work string, mutate func(Obj)) {
	t.Helper()
	editJSON(t, filepath.Join(work, "board", "artifacts", BoardBuild), mutate)
	reseal(t, work, nil)
}

func TestProducedBoardBundleVerifiesAsIs(t *testing.T) {
	produced := envPath("HSLSA_BOARD_BUNDLE", "out/board")
	requireDir(t, filepath.Join(produced, "att"), "run e2e/board/run.sh produce first")
	_, err := boardCheck(t, produced, nil)
	must(t, err)
}

func TestRebuiltBoardVerifies(t *testing.T) {
	work := boardWork(t)
	result, err := boardCheck(t, filepath.Join(work, "board"), []string{"DEVB-A-0001", "DEVB-A-0005"})
	must(t, err)
	if name := S(result.Lot, "name"); name != "urn:hslsa:lot:BRD-EXAMPLE-01" {
		t.Fatalf("board lot %s", name)
	}
}

// Files swapped after signing

func TestBoardModifiedArtifact(t *testing.T) {
	for _, artifact := range []string{BoardDesign, BoardBuild, "shipment-EXAMPLE-SHIP-0001.json", "shipment-EXAMPLE-SHIP-0002.json"} {
		t.Run(artifact, func(t *testing.T) {
			work := boardWork(t)
			appendFile(t, filepath.Join(work, "board", "artifacts", artifact), "\n")
			boardRejects(t, work, fmt.Sprintf("subject %s does not match its attested digest", artifact))
		})
	}
}

func TestBoardAddedToLot(t *testing.T) {
	work := boardWork(t)
	appendFile(t, filepath.Join(work, "board", "artifacts", BoardLot), "DEVB-A-9999\n")
	boardRejects(t, work, "board lot list does not match the attested lot digest")
}

func TestReceivedBoardFailedTest(t *testing.T) {
	work := boardWork(t)
	boardRejects(t, work, "received board DEVB-A-0004 is not in the board lot", "DEVB-A-0001", "DEVB-A-0004")
}

// Signatures

func TestA1SignedByBoardOwner(t *testing.T) {
	work := boardWork(t)
	boardResign(t, work, BoardA1, boardOwnerRole, nil)
	boardRejects(t, work, "no valid signature from role 'ems-site'")
}

func TestShipmentSignedByTheBroker(t *testing.T) {
	// A broker cannot pass its shipment off as the franchised distributor's.
	work := boardWork(t)
	boardResign(t, work, ShipAtt("EXAMPLE-SHIP-0001"), "dist-broker", nil)
	boardRejects(t, work, "no valid signature from role 'dist-franchised'")
}

func TestChipChainBrokenUnderTheBoard(t *testing.T) {
	work := boardWork(t)
	editPayload(t, filepath.Join(work, "board", "parts", "picosoc", "att", "mfg-f4-final-test.intoto.json"), func(s Obj) {
		O(s, "predicate", "hwMfg", "yield")["failed"] = []any{}
	})
	boardRejects(t, work, "PSOC130-QFN64 lot receipt check failed: mfg-f4-final-test.intoto.json: no valid signature")
}

// Distributor lot data

func TestHBOMPartLotSwapped(t *testing.T) {
	work := boardWork(t)
	boardResign(t, work, BoardHBOM, boardOwnerRole, func(s Obj) { part(s, flash)["lot"] = "EXAMPLE-WB-LOT-0666" })
	boardRejects(t, work, "parts: "+flash+" lot EXAMPLE-WB-LOT-0666 does not match the distributor's shipment")
}

func TestHBOMDateCodeChanged(t *testing.T) {
	work := boardWork(t)
	boardResign(t, work, BoardHBOM, boardOwnerRole, func(s Obj) { part(s, flash)["dateCode"] = "EXAMPLE-2601" })
	boardRejects(t, work, "parts: "+flash+" lot EXAMPLE-WB-LOT-0001 does not match the distributor's shipment")
}

func TestPartFromABroker(t *testing.T) {
	// Flash bought from a broker: the producer marks it unauthorized, and policy requires the authorized channel.
	work := boardWork(t)
	scenario := editScenario(t, work, func(sc Obj) {
		shipments := Objs(sc, "shipments")
		var lines []any
		var line Obj
		for _, ln := range Objs(shipments[0], "lines") {
			if S(ln, "mpn") == flash {
				line = ln
			} else {
				lines = append(lines, ln)
			}
		}
		shipments[0]["lines"] = lines
		sc["shipments"] = append(A(sc, "shipments"), Obj{
			"id":       "EXAMPLE-SHIP-0003",
			"shipper":  Obj{"name": "Example Components Broker", "country": "US"},
			"shipDate": "2026-09-16",
			"lines":    []any{line},
		})
	})
	must(t, boardProduce(work, scenario))
	boardRejects(t, work, "policy requires an authorized channel, and "+flash+" lot EXAMPLE-WB-LOT-0001 was not bought")
	boardResign(t, work, BoardHBOM, boardOwnerRole, func(s Obj) { part(s, flash)["authorized"] = true })
	boardRejects(t, work, "Example Components Broker is not an authorized channel for Winbond Electronics")
}

func TestMorePartsPlacedThanShipped(t *testing.T) {
	work := boardWork(t)
	scenario := editScenario(t, work, func(sc Obj) {
		find(Objs(Objs(sc, "shipments")[0], "lines"), "mpn", flash)["quantity"] = 4
	})
	must(t, boardProduce(work, scenario))
	boardRejects(t, work, "more "+flash+" lot EXAMPLE-WB-LOT-0001 placed than were shipped")
}

// The chip on the board

func TestBoardClaimsAChipLotItDidNotReceive(t *testing.T) {
	work := boardWork(t)
	scenario := editScenario(t, work, func(sc Obj) {
		Objs(Objs(sc, "shipments")[0], "lines")[0]["lot"] = "ASM-EXAMPLE-99"
	})
	must(t, boardProduce(work, scenario))
	boardRejects(t, work, "board claims PSOC130-QFN64 lot ASM-EXAMPLE-99, but its HBOM names urn:hslsa:lot:ASM-EXAMPLE-17")
}

func TestScrappedChipShippedToTheEMS(t *testing.T) {
	// PSOC130-A0-00007 failed final test. The EMS's own receipt check refuses it; skipping that check does not help.
	work := boardWork(t)
	scenario := editScenario(t, work, func(sc Obj) {
		units := A(Objs(Objs(sc, "shipments")[0], "lines")[0], "units")
		units[len(units)-1] = "PSOC130-A0-00007"
	})
	rejects(t, boardProduce(work, scenario), "PSOC130-A0-00007 is not in the shipped lot")
	real := ChipCheck
	ChipCheck = func(chip string, _ []string) (*LotResult, error) { return real(chip, nil) }
	err := boardProduce(work, scenario)
	ChipCheck = real
	must(t, err)
	boardRejects(t, work, "PSOC130-QFN64 lot receipt check failed: received unit PSOC130-A0-00007 is not in the shipped lot")
}

func placement(b Obj, board, ref string) Obj { return O(b, board, "placements", ref) }

func TestChipPlacedThatWasNeverShipped(t *testing.T) {
	work := boardWork(t)
	editBuilds(t, work, func(b Obj) { placement(b, "DEVB-A-0002", "U1")["unit"] = "PSOC130-A0-00010" })
	boardRejects(t, work, "board DEVB-A-0002 U1 unit PSOC130-A0-00010 was never shipped to the EMS")
}

func TestChipPlacedOnTwoBoards(t *testing.T) {
	work := boardWork(t)
	editBuilds(t, work, func(b Obj) { placement(b, "DEVB-A-0002", "U1")["unit"] = "PSOC130-A0-00001" })
	boardRejects(t, work, "unit PSOC130-A0-00001 is placed on more than one board")
}

func TestPartPlacedFromAnUnlistedLot(t *testing.T) {
	work := boardWork(t)
	editBuilds(t, work, func(b Obj) { placement(b, "DEVB-A-0003", "U2")["lot"] = "EXAMPLE-WB-LOT-0999" })
	boardRejects(t, work, "board DEVB-A-0003 U2 is "+flash+" lot EXAMPLE-WB-LOT-0999, which the HBOM does not list")
}

func TestHBOMRefToAnotherHBOM(t *testing.T) {
	// Pointing the chip at a different HBOM breaks its digest.
	work := boardWork(t)
	boardResign(t, work, BoardHBOM, boardOwnerRole, func(s Obj) {
		O(part(s, "PSOC130-QFN64"), "hbomRef", "digest")["sha256"] = strings.Repeat("3", 64)
	})
	boardRejects(t, work, "PSOC130-QFN64 hbomRef does not match its digest")
}

// A1 and the board HBOM

func TestA1NotLinkedToAShipment(t *testing.T) {
	work := boardWork(t)
	reseal(t, work, func(s Obj) {
		bd := O(s, "predicate", "buildDefinition")
		var keep []any
		for _, d := range Objs(bd, "resolvedDependencies") {
			if !strings.Contains(S(d, "name"), "distribution") {
				keep = append(keep, d)
			}
		}
		bd["resolvedDependencies"] = keep
	})
	boardRejects(t, work, "chain broken, resolvedDependencies do not include shipment record")
}

func TestA1YieldHidesAFailedBoard(t *testing.T) {
	work := boardWork(t)
	reseal(t, work, func(s Obj) { O(s, "predicate", "hwMfg", "yield")["failed"] = []any{} })
	boardRejects(t, work, "yield record does not account for every board built")
}

func TestA1NamesAnotherBoardDesign(t *testing.T) {
	work := boardWork(t)
	reseal(t, work, func(s Obj) {
		O(s, "predicate", "hwMfg", "designRef", "digest")["sha256"] = strings.Repeat("4", 64)
	})
	boardRejects(t, work, "designRef names a different board design")
}

func TestBoardHBOMNamesAnotherLot(t *testing.T) {
	work := boardWork(t)
	boardResign(t, work, BoardHBOM, boardOwnerRole, func(s Obj) {
		O(Objs(s, "subject")[1], "digest")["sha256"] = strings.Repeat("2", 64)
	})
	boardRejects(t, work, "lot subject does not match the A1 board lot")
}

func TestBoardHBOMOmitsAPart(t *testing.T) {
	work := boardWork(t)
	boardResign(t, work, BoardHBOM, boardOwnerRole, func(s Obj) {
		pred := O(s, "predicate")
		var keep []any
		for _, p := range Objs(pred, "parts") {
			if S(p, "mpn") != "RC0402FR-0710KL" {
				keep = append(keep, p)
			}
		}
		pred["parts"] = keep
	})
	boardRejects(t, work, "board design R1 (RC0402FR-0710KL) has no matching part in the HBOM")
}

// A part on a board is checked under the buyer's own trust root and policy
// when the buyer passes them, and under its bundle's only when it does not.
func TestPartTrustPrefersTheBuyers(t *testing.T) {
	dir := t.TempDir()
	chip := filepath.Join(dir, "parts", "rot")
	for _, d := range []string{filepath.Join(dir, "supplier"), filepath.Join(dir, "buyer"), chip} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	supplier, err := Keygen(filepath.Join(dir, "supplier"), "test-site")
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := Keygen(filepath.Join(dir, "buyer"), "test-site")
	if err != nil {
		t.Fatal(err)
	}
	if err := BuildTrustRoot(filepath.Join(dir, "supplier"), filepath.Join(chip, "trust-root.json")); err != nil {
		t.Fatal(err)
	}
	buyerTrust := filepath.Join(dir, "buyer-trust-root.json")
	if err := BuildTrustRoot(filepath.Join(dir, "buyer"), buyerTrust); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(filepath.Join(chip, "policy.json"), Obj{"from": "supplier"}); err != nil {
		t.Fatal(err)
	}
	buyerPolicy := filepath.Join(dir, "buyer-policy.json")
	if err := WriteJSON(buyerPolicy, Obj{"from": "buyer"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { PartRoots = map[string]PartRoot{} })

	check := func(why string, wantKey *Signer, wantPolicy string) {
		t.Helper()
		trust, policy, err := partTrust(chip)
		if err != nil {
			t.Fatal(err)
		}
		if keys := trust.Roles["test-site"]; len(keys) != 1 || keys[0].ID != wantKey.Key.ID {
			t.Fatalf("%s: trusted %v, want only %s", why, keys, wantKey.Key.ID)
		}
		if S(policy, "from") != wantPolicy {
			t.Fatalf("%s: policy from %s, want %s", why, S(policy, "from"), wantPolicy)
		}
	}
	check("nothing passed", supplier, "supplier")
	PartRoots["rot"] = PartRoot{TrustRoot: buyerTrust, Policy: buyerPolicy}
	check("the buyer's passed", buyer, "buyer")
	PartRoots["rot"] = PartRoot{TrustRoot: buyerTrust}
	check("only the buyer's trust root passed", buyer, "supplier")
}
