# Tests of the lot receipt check, on the same fixture as tapeout_test.rego.
package hslsa.lot_test

import data.hslsa.lot

chip := data.testdata.chip

f1 := "att/mfg-f1-wafer-fab.intoto.json"

f4 := "att/mfg-f4-final-test.intoto.json"

set(doc, path, value) := json.patch(doc, [{"op": "replace", "path": path, "value": value}])

stmt(file, rest) := array.concat(["files", file, "envelope", "statement"], rest)

refused(doc, msg) if msg in lot.deny with input as doc

shipped_text := chip.files["artifacts/shipped-lot.txt"].text

test_valid_lot_accepted if {
	count(lot.deny) == 0 with input as chip
	lot.report.passed with input as chip
	lot.lot.name == "urn:hslsa:lot:ASM-EXAMPLE-17" with input as chip
	count(lot.simulated) == 7 with input as chip
}

test_failed_tapeout_stops_the_lot_check if {
	doc := set(chip, ["files", "att/design-release.intoto.json", "envelope", "signedBy"], [])
	refused(doc, "the tapeout check did not pass, so the lot cannot be checked against the design")
}

test_record_signed_by_another_site_refused if {
	refused(set(chip, ["files", f1, "envelope", "signedBy"], ["sort-site"]), "mfg-f1-wafer-fab.intoto.json: no valid signature from role 'fab-site'")
}

test_missing_record_refused if {
	refused(json.patch(chip, [{"op": "remove", "path": ["files", f4]}]), "missing attestation mfg-f4-final-test.intoto.json")
}

test_failed_gate_refused if {
	refused(set(chip, stmt(f1, ["predicate", "hwMfg", "checks", 0, "result"]), "fail"), "wafer-fab: gate failed: mask-vs-gds-xor")
}

test_wrong_build_type_refused if {
	refused(set(chip, stmt(f1, ["predicate", "buildDefinition", "buildType"]), "https://github.com/Horiodino/hw-slsa/mfg/step/packaging@v1"), "wafer-fab: wrong buildType")
}

test_broken_link_to_release_refused if {
	doc := set(chip, stmt(f1, ["predicate", "buildDefinition", "resolvedDependencies", 0, "digest", "sha256"]), crypto.sha256("another release"))
	refused(doc, "wafer-fab: chain broken, resolvedDependencies do not include previous step att/design-release.intoto.json")
}

test_broken_link_through_a_transfer_refused if {
	# A different wafer sort record than the one its transfer ships from.
	doc := set(chip, ["files", "att/mfg-f2-wafer-sort.intoto.json", "sha256"], crypto.sha256("another record"))
	refused(doc, "transfer from wafer-sort: chain broken, resolvedDependencies do not include shipping step att/mfg-f2-wafer-sort.intoto.json")
	refused(doc, "hbom: reference to mfg-f2-wafer-sort.intoto.json does not match its digest")
}

test_design_ref_to_another_release_refused if {
	doc := set(chip, stmt(f4, ["predicate", "hwMfg", "designRef", "release", "digest", "sha256"]), crypto.sha256("another release"))
	refused(doc, "final-test: designRef names a different design release")
}

test_required_transfer_missing_refused if {
	doc := json.patch(chip, [{"op": "remove", "path": ["files", "att/mfg-transfer-wafer-sort.intoto.json"]}])
	refused(doc, "missing attestation mfg-transfer-wafer-sort.intoto.json")
}

test_optional_transfer_missing_accepted if {
	doc := json.patch(chip, [
		{"op": "remove", "path": ["files", "att/mfg-transfer-wafer-sort.intoto.json"]},
		{"op": "replace", "path": ["policy", "manufacturing", "requireTransfers"], "value": false},
	])

	# The OSAT's record links the transfer, so without it the link breaks;
	# nothing else is refused.
	lot.deny == {"packaging: chain broken, resolvedDependencies do not include previous step att/mfg-f2-wafer-sort.intoto.json"} with input as doc
	lot.not_recorded == ["transfer from wafer-sort to packaging"] with input as doc
}

test_transfer_from_another_site_refused if {
	doc := set(chip, stmt("att/mfg-transfer-wafer-fab.intoto.json", ["predicate", "hwMfg", "site", "name"]), "Example Other Fab")
	refused(doc, "transfer from wafer-fab: shipped by Example Other Fab, not by Example Wafer Fab, which signed wafer-fab")
}

test_packing_list_with_another_wafer_refused if {
	doc := set(chip, ["files", "artifacts/transfer-wafer-fab.json", "json", "items", 1], "W99")
	refused(doc, "transfer from wafer-fab: packing list does not ship exactly urn:hslsa:wafer-lot:skywater:LOT-EXAMPLE-A")
}

test_shipped_lot_list_edited_refused if {
	doc := set(chip, ["files", "artifacts/shipped-lot.txt", "text"], concat("", [shipped_text, "PSOC130-A0-00007\n"]))
	refused(doc, "final-test: shipped lot list does not match the attested lot digest")
}

test_shipped_lot_list_reordered_accepted if {
	# The lot digest is over the sorted list, so order and blank lines do not matter.
	lines := split(trim_suffix(shipped_text, "\n"), "\n")
	reversed := concat("", [concat("\r\n", [lines[i] | some j in numbers.range(1, count(lines)); i := count(lines) - j]), "\n\n"])
	count(lot.deny) == 0 with input as set(chip, ["files", "artifacts/shipped-lot.txt", "text"], reversed)
}

test_unit_that_failed_shipped_refused if {
	doc := set(chip, stmt(f4, ["predicate", "hwMfg", "yield", "passed"]), 36)
	refused(doc, "final-test: yield record does not account for every packaged unit")
}

test_unit_on_a_failing_die_refused if {
	# W01 (2, 0) failed probe.
	doc := set(chip, ["files", "artifacts/genealogy.json", "json", "units", "PSOC130-A0-00003", "x"], 2)
	refused(doc, "packaging: genealogy for PSOC130-A0-00003 does not trace to a unique passing die")
}

test_two_units_on_one_die_refused if {
	doc := set(chip, ["files", "artifacts/genealogy.json", "json", "units", "PSOC130-A0-00002", "x"], 0)
	refused(doc, "packaging: genealogy for PSOC130-A0-00001 does not trace to a unique passing die")
	refused(doc, "packaging: genealogy for PSOC130-A0-00002 does not trace to a unique passing die")
}

test_received_unit_not_shipped_refused if {
	doc := set(chip, ["received"], ["PSOC130-A0-00001", "PSOC130-A0-00007"])
	refused(doc, "received unit PSOC130-A0-00007 is not in the shipped lot")
}

test_hbom_by_another_role_refused if {
	refused(set(chip, ["files", "att/hbom.intoto.json", "envelope", "signedBy"], ["test-site"]), "hbom.intoto.json: no valid signature from role 'product-owner'")
}

test_hbom_off_its_schema_refused if {
	doc := json.patch(chip, [{"op": "add", "path": stmt("att/hbom.intoto.json", ["predicate", "warranty"]), "value": "none"}])
	refused(doc, "hbom: HBOM does not match its schema: (Root): Additional property warranty is not allowed")
}

test_hbom_for_another_lot_refused if {
	doc := set(chip, stmt("att/hbom.intoto.json", ["subject", 1, "digest", "sha256"]), crypto.sha256("another lot"))
	refused(doc, "hbom: lot subject does not match the final test shipped lot")
}

test_hbom_pointing_at_another_record_refused if {
	doc := set(chip, stmt("att/hbom.intoto.json", ["predicate", "manufacturing", "fab", "attestationRef", "uri"]), "file:att/mfg-f2-wafer-sort.intoto.json")
	refused(doc, "hbom: reference for wafer-fab points at mfg-f2-wafer-sort.intoto.json")
}

test_rendering_changed_refused if {
	doc := set(chip, ["files", "att/hbom.cdx.json", "sha256"], crypto.sha256("edited"))
	refused(doc, "hbom: rendering att/hbom.cdx.json does not match its digest")
}

test_simulated_evidence_refused_without_simulated_accept if {
	doc := json.patch(chip, [{"op": "remove", "path": ["policy", "simulated"]}])
	some msg in lot.deny with input as doc
	startswith(msg, "lot receipt check: 7 record(s) made from simulated hardware, and the policy does not accept simulated evidence (simulated.accept)")
}

test_proxy_signed_record_refused if {
	doc := json.patch(chip, [{"op": "add", "path": stmt("att/mfg-f2-wafer-sort.intoto.json", ["predicate", "hwMfg", "proxy"]), "value": {"signer": {"name": "Example OSAT"}}}])
	refused(doc, "mfg-f2-wafer-sort.intoto.json: signed on a supplier's behalf (hwMfg.proxy); these Rego policies do not check proxy-signed or evidence records")
}

test_withheld_fields_refused if {
	doc := set(chip, stmt(f4, ["predicate", "hwMfg", "confidential"]), [{"path": "/hwMfg/yield", "saltedDigest": {"sha256": crypto.sha256("x")}}])
	refused(doc, "mfg-f4-final-test.intoto.json: withholds 1 field(s) (hwMfg.confidential); disclosures are not read by these Rego policies")
}

test_wafer_l3_claim_refused if {
	doc := set(chip, ["policy", "claims", "lot"], ["HSLSA_WAFER_LEVEL_3", "HSLSA_PACKAGE_TEST_LEVEL_2", "HSLSA_DESIGN_LEVEL_3"])
	refused(doc, "policy claims Wafer L3; these Rego policies check Wafer up to L2, and L3 stays with the reference tool")
}

claimed(doc, levels) := json.patch(doc, [{"op": "add", "path": stmt("att/hbom.intoto.json", ["predicate", "claimedLevels"]), "value": levels}])

test_hbom_claiming_the_verified_levels_accepted if {
	count(lot.deny) == 0 with input as claimed(chip, ["HSLSA_DESIGN_LEVEL_3", "HSLSA_WAFER_LEVEL_2", "HSLSA_PACKAGE_TEST_LEVEL_1"])
}

test_hbom_claiming_more_than_verified_refused if {
	refused(claimed(chip, ["HSLSA_WAFER_LEVEL_3"]), "hbom: the HBOM claims Wafer L3, but this check verified Wafer L2; an HBOM may not claim more than its checks verify")
}

test_hbom_claiming_a_track_the_policy_does_not_claim_refused if {
	doc := set(claimed(chip, ["HSLSA_PACKAGE_TEST_LEVEL_2"]), ["policy", "claims", "lot"], ["HSLSA_WAFER_LEVEL_2", "HSLSA_DESIGN_LEVEL_3"])
	refused(doc, "hbom: the HBOM claims Package/Test L2, but this check verified no Package/Test level")
}
