# Tests of the shared helpers: the lot digest, unit lists and claims.
package hslsa.lib_test

import data.hslsa.lib

test_fixtures_and_schema_loaded if {
	data.testdata.chip.files["att/hbom.intoto.json"].sha256
	data.testdata.board.files["att/hbom.intoto.json"].sha256
	data.hslsa.hbom_schema.title == "HBOM predicate v0.1"
}

# The lot digest of the spec: ids trimmed, sorted as bytes, newline-joined
# with a trailing newline.
test_lot_digest_is_canonical if {
	lib.lot_digest(["U2", " U10 ", "U1"]) == crypto.sha256("U1\nU10\nU2\n")
	lib.lot_digest(["U1", "U10", "U2"]) == lib.lot_digest(["U2", "U10", "U1"])
}

test_lot_digest_ignores_blank_ids if {
	lib.lot_digest(["A", "", "  ", "B"]) == crypto.sha256("A\nB\n")
}

test_lot_digest_refuses_duplicates if {
	not lib.lot_digest(["A", "B", "A "])
}

test_unit_lines_reads_any_line_ending if {
	lib.unit_lines("A\r\nB\rC\n\n  \nD") == ["A", "B", "C", "D"]
}

# The shipped lot list in the fixture hashes to the lot digest F4 attests.
test_lot_digest_of_the_example_lot if {
	f := data.testdata.chip.files
	lot := f["att/mfg-f4-final-test.intoto.json"].envelope.statement.subject[0]
	lib.lot_digest(lib.unit_lines(f["artifacts/shipped-lot.txt"].text)) == lot.digest.sha256
}

test_claims_valid if {
	count(lib.claim_errors("lot", ["WAFER", "PACKAGE_TEST", "DESIGN"])) == 0 with input as data.testdata.chip
	lib.track_claim("DESIGN") == 3 with input as data.testdata.chip
	lib.track_claim("WAFER") == 2 with input as data.testdata.chip
}

test_claims_unknown_value_refused if {
	errs := lib.claim_errors("lot", ["WAFER"]) with input.policy as {"claims": {"lot": ["HSLSA_WAFER_LEVEL_2", "HSLSA_GOLD"]}}
	errs == {"policy claims.lot: claim HSLSA_GOLD: not a level this framework defines"}
}

test_claims_other_track_refused if {
	errs := lib.claim_errors("board", ["ASSEMBLY"]) with input.policy as {"claims": {"board": ["HSLSA_FIRMWARE_LEVEL_1"]}}
	errs == {"policy claims.board: claim HSLSA_FIRMWARE_LEVEL_1: this check covers Assembly, not the Firmware track"}
}

test_claims_slsa_above_design_refused if {
	errs := lib.claim_errors("design", ["DESIGN"]) with input.policy as {"claims": {"design": ["HSLSA_DESIGN_LEVEL_2", "SLSA_BUILD_LEVEL_3"]}}
	errs == {"policy claims.design: claims SLSA Build L3 but no Design or Firmware level of at least L3 in the same list"}
}

test_claims_above_what_rego_checks_refused if {
	errs := lib.unchecked_claim_errors(["WAFER", "PACKAGE_TEST"]) with input.policy as {"claims": {"lot": ["HSLSA_WAFER_LEVEL_3"]}}
	errs == {"policy claims Wafer L3; these Rego policies check Wafer up to L2, and L3 stays with the reference tool"}
}

test_truthy_reads_flags_as_the_reference_tool_does if {
	lib.truthy(true)
	lib.truthy("yes")
	lib.truthy(1)
	lib.truthy([0])
	not lib.truthy(false)
	not lib.truthy("")
	not lib.truthy(0)
	not lib.truthy([])
	not lib.truthy({})
	not lib.truthy(null)
}

test_expired_trust_root_refused if {
	errs := lib.trust_root_errors with input.trustRoot as {"roles": [], "validUntil": "2020-01-01T00:00:00Z"}
	errs == {"trust root expired 2020-01-01T00:00:00Z, when its first enrollment ended"}
}
