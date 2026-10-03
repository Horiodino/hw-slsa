# Tests of the board receipt check. testdata/board/data.json is the input
# e2e/rego/input.sh built from the board example bundle (e2e/board/run.sh
# produce, with e2e/board/received-boards.txt), with its part bundle left out:
# parts/picosoc is the same PicoRV32 bundle as testdata/chip, so the tests
# put that fixture back in its place.
package hslsa.board_test

import data.hslsa.board

board_input := object.union(data.testdata.board, {"parts": {"parts/picosoc": object.remove(data.testdata.chip, ["received"])}})

a1 := "att/mfg-a1-board-assembly.intoto.json"

ship1 := "att/mfg-distribution-EXAMPLE-SHIP-0001.intoto.json"

hbom := "att/hbom.intoto.json"

receipt := "att/receipt-ASM-EXAMPLE-17.vsa.intoto.json"

set(doc, path, value) := json.patch(doc, [{"op": "replace", "path": path, "value": value}])

stmt(file, rest) := array.concat(["files", file, "envelope", "statement"], rest)

part(rest) := array.concat(["parts", "parts/picosoc"], rest)

refused(doc, msg) if msg in board.deny with input as doc

test_valid_board_accepted if {
	count(board.deny) == 0 with input as board_input
	board.report.passed with input as board_input
	board.lot_subj.name == "urn:hslsa:lot:BRD-EXAMPLE-01" with input as board_input
}

test_part_bundle_missing_refused if {
	refused(data.testdata.board, "parts: PSOC130-QFN64 chain is not in the bundle at parts/picosoc")
}

test_altered_a1_refused if {
	refused(set(board_input, ["files", a1, "envelope", "signedBy"], []), "mfg-a1-board-assembly.intoto.json: no valid signature from role 'ems-site'")
}

test_hbom_by_another_role_refused if {
	refused(set(board_input, ["files", hbom, "envelope", "signedBy"], ["ems-site"]), "hbom.intoto.json: no valid signature from role 'board-owner'")
}

test_distribution_by_the_broker_refused if {
	# The policy gives the franchised distributor its own role; a broker's key does not do.
	refused(set(board_input, ["files", ship1, "envelope", "signedBy"], ["dist-broker"]), "mfg-distribution-EXAMPLE-SHIP-0001.intoto.json: no valid signature from role 'dist-franchised'")
}

test_shipment_link_broken_refused if {
	doc := set(board_input, ["files", "att/mfg-distribution-EXAMPLE-SHIP-0002.intoto.json", "sha256"], crypto.sha256("another shipment"))
	refused(doc, "board-assembly: chain broken, resolvedDependencies do not include shipment record att/mfg-distribution-EXAMPLE-SHIP-0002.intoto.json")
	refused(doc, "parts: PSOC-DEVB-01-PCB distribution reference does not match its digest")
}

test_unauthorized_channel_refused if {
	doc := set(board_input, ["policy", "shippers", "Example Franchised Distributor", "authorizedFor"], ["Example Open Silicon Group"])
	refused(doc, "parts: Example Franchised Distributor is not an authorized channel for Winbond Electronics, but W25Q128JVSIQ claims it is")
}

test_part_not_through_an_authorized_channel_refused if {
	doc := set(board_input, stmt(hbom, ["predicate", "parts", 2, "authorized"]), false)
	refused(doc, "parts: policy requires an authorized channel, and W25Q128JVSIQ lot EXAMPLE-WB-LOT-0001 was not bought through one")
}

test_part_not_through_an_authorized_channel_accepted_when_not_required if {
	doc := json.patch(board_input, [
		{"op": "replace", "path": stmt(hbom, ["predicate", "parts", 2, "authorized"]), "value": false},
		{"op": "replace", "path": ["policy", "requireAuthorizedChannel"], "value": false},
	])
	count(board.deny) == 0 with input as doc
}

test_date_code_not_the_shipments_refused if {
	doc := set(board_input, stmt(hbom, ["predicate", "parts", 2, "dateCode"]), "EXAMPLE-2701")
	refused(doc, "parts: W25Q128JVSIQ lot EXAMPLE-WB-LOT-0001 does not match the distributor's shipment EXAMPLE-SHIP-0001")
}

test_part_chain_broken_refused if {
	text := board_input.parts["parts/picosoc"].files["artifacts/shipped-lot.txt"].text
	doc := set(board_input, part(["files", "artifacts/shipped-lot.txt", "text"]), concat("", [text, "PSOC130-A0-00007\n"]))
	refused(doc, "parts: PSOC130-QFN64 lot receipt check failed: final-test: shipped lot list does not match the attested lot digest")
}

test_part_record_by_another_role_refused if {
	doc := set(board_input, part(["files", "att/mfg-f1-wafer-fab.intoto.json", "envelope", "signedBy"]), ["sort-site"])
	refused(doc, "parts: PSOC130-QFN64 lot receipt check failed: mfg-f1-wafer-fab.intoto.json: no valid signature from role 'fab-site'")
}

test_unit_shipped_to_the_ems_not_in_the_lot_refused if {
	# The distributor's shipment lists unit 7, which failed final test.
	doc := set(board_input, ["files", "artifacts/shipment-EXAMPLE-SHIP-0001.json", "json", "lines", 0, "units", 6], "PSOC130-A0-00007")
	refused(doc, "parts: PSOC130-QFN64 lot receipt check failed: received unit PSOC130-A0-00007 is not in the shipped lot")
}

test_part_hbom_of_another_part_refused if {
	doc := set(board_input, part(stmt(hbom, ["predicate", "product", "partNumber"])), "PSOC131-QFN64")
	refused(doc, "parts: PSOC130-QFN64 hbomRef is the HBOM of PSOC131-QFN64")
}

test_part_hbom_changed_refused if {
	doc := set(board_input, part(["files", hbom, "sha256"]), crypto.sha256("another hbom"))
	refused(doc, "parts: PSOC130-QFN64 hbomRef does not match its digest")
}

test_receipt_missing_refused if {
	refused(json.patch(board_input, [{"op": "remove", "path": ["files", receipt]}]), "missing attestation receipt-ASM-EXAMPLE-17.vsa.intoto.json")
}

test_receipt_for_other_units_refused if {
	doc := set(board_input, stmt(receipt, ["subject", 0, "digest", "sha256"]), crypto.sha256("PSOC130-A0-00001\n"))
	refused(doc, "PSOC130-QFN64 receipt receipt-ASM-EXAMPLE-17.vsa.intoto.json: covers other units than the 8 shipped to the EMS")
}

test_receipt_under_another_policy_refused if {
	doc := set(board_input, part(["files", "policy.json", "sha256"]), crypto.sha256("a laxer policy"))
	refused(doc, "PSOC130-QFN64 receipt receipt-ASM-EXAMPLE-17.vsa.intoto.json: checked under another policy than the chip's")
}

test_receipt_missing_a_level_refused if {
	doc := set(board_input, stmt(receipt, ["predicate", "verifiedLevels"]), ["HSLSA_WAFER_LEVEL_2", "HSLSA_PACKAGE_TEST_LEVEL_2", "HSLSA_SIMULATED"])
	refused(doc, "PSOC130-QFN64 receipt receipt-ASM-EXAMPLE-17.vsa.intoto.json: does not state HSLSA_DESIGN_LEVEL_3")
}

test_failed_receipt_refused if {
	doc := set(board_input, stmt(receipt, ["predicate", "verificationResult"]), "FAILED")
	refused(doc, "PSOC130-QFN64 receipt receipt-ASM-EXAMPLE-17.vsa.intoto.json: not a passed lot receipt check")
}

test_unit_placed_twice_refused if {
	doc := set(board_input, ["files", "artifacts/board-build.json", "json", "DEVB-A-0002", "placements", "U1", "unit"], "PSOC130-A0-00001")
	refused(doc, "board-assembly: unit PSOC130-A0-00001 is placed on more than one board")
}

test_unit_never_shipped_refused if {
	doc := set(board_input, ["files", "artifacts/board-build.json", "json", "DEVB-A-0002", "placements", "U1", "unit"], "PSOC130-A0-00007")
	refused(doc, "board-assembly: board DEVB-A-0002 U1 unit PSOC130-A0-00007 was never shipped to the EMS")
}

test_placement_of_an_unlisted_lot_refused if {
	doc := set(board_input, ["files", "artifacts/board-build.json", "json", "DEVB-A-0003", "placements", "U2", "lot"], "EXAMPLE-WB-LOT-0666")
	refused(doc, "board-assembly: board DEVB-A-0003 U2 is W25Q128JVSIQ lot EXAMPLE-WB-LOT-0666, which the HBOM does not list")
}

test_more_placed_than_shipped_refused if {
	doc := set(board_input, ["files", "artifacts/shipment-EXAMPLE-SHIP-0002.json", "json", "lines", 0, "quantity"], 5)
	refused(doc, "board-assembly: more PSOC-DEVB-01-PCB lot EXAMPLE-PCB-LOT-01 placed than were shipped")
}

test_extra_position_refused if {
	doc := set(board_input, stmt(hbom, ["predicate", "parts", 7, "refDes"]), ["R1", "R2", "R3"])
	refused(doc, "parts: HBOM lists R3, which the board design does not have")
}

test_missing_position_refused if {
	doc := set(board_input, stmt(hbom, ["predicate", "parts", 7, "refDes"]), ["R1"])
	refused(doc, "parts: board design R2 (RC0402FR-0710KL) has no matching part in the HBOM")
}

test_board_lot_list_edited_refused if {
	text := board_input.files["artifacts/board-lot.txt"].text
	doc := set(board_input, ["files", "artifacts/board-lot.txt", "text"], concat("", [text, "DEVB-A-0004\n"]))
	refused(doc, "board-assembly: board lot list does not match the attested lot digest")
	refused(doc, "board-assembly: board lot is not the set of boards that passed test")
}

test_yield_hiding_a_failed_board_refused if {
	doc := set(board_input, stmt(a1, ["predicate", "hwMfg", "yield", "failed"]), [])
	refused(doc, "board-assembly: yield record does not account for every board built")
}

test_received_board_not_in_the_lot_refused if {
	refused(set(board_input, ["received"], ["DEVB-A-0001", "DEVB-A-0004"]), "received board DEVB-A-0004 is not in the board lot")
}

test_not_a_board_refused if {
	doc := set(board_input, stmt(hbom, ["predicate", "product", "level"]), "chip")
	refused(doc, "board hbom: product level is chip, not a board")
}

test_assembly_l3_claim_refused if {
	doc := set(board_input, ["policy", "claims", "board"], ["HSLSA_ASSEMBLY_LEVEL_3"])
	refused(doc, "policy claims Assembly L3; these Rego policies check Assembly up to L2, and L3 stays with the reference tool")
}

board_claimed(doc, levels) := json.patch(doc, [{"op": "add", "path": stmt(hbom, ["predicate", "claimedLevels"]), "value": levels}])

test_board_hbom_claiming_the_verified_level_accepted if {
	# Firmware is not this check's track; the claim is left to the check that covers it.
	count(board.deny) == 0 with input as board_claimed(board_input, ["HSLSA_ASSEMBLY_LEVEL_2", "HSLSA_FIRMWARE_LEVEL_2"])
}

test_board_hbom_claiming_more_than_verified_refused if {
	refused(board_claimed(board_input, ["HSLSA_ASSEMBLY_LEVEL_3"]), "board hbom: the HBOM claims Assembly L3, but this check verified Assembly L2; an HBOM may not claim more than its checks verify")
}
