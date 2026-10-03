# Tests of the tapeout check. testdata/chip/data.json is the input
# e2e/rego/input.sh built from the PicoRV32 example bundle (e2e/run.sh
# produce, with e2e/picorv32/received-units.txt); each test that breaks it
# changes one thing.
package hslsa.tapeout_test

import data.hslsa.tapeout

chip := data.testdata.chip

synthesis := "att/design-2-synthesis.intoto.json"

# set(doc, path, value): doc with the value at path replaced.
set(doc, path, value) := json.patch(doc, [{"op": "replace", "path": path, "value": value}])

stmt(file, rest) := array.concat(["files", file, "envelope", "statement"], rest)

refused(doc, msg) if msg in tapeout.deny with input as doc

test_valid_bundle_accepted if {
	count(tapeout.deny) == 0 with input as chip
	tapeout.report.passed with input as chip
	tapeout.final.name == "picorv32.netlist.v" with input as chip
}

test_altered_step_refused if {
	# openssl verified no trust-root key's signature over the altered payload.
	refused(
		set(chip, ["files", synthesis, "envelope", "signedBy"], []),
		"design-2-synthesis.intoto.json: no valid signature from role 'flow-platform'",
	)
}

test_step_signed_by_another_role_refused if {
	refused(
		set(chip, ["files", synthesis, "envelope", "signedBy"], ["fab-site"]),
		"design-2-synthesis.intoto.json: no valid signature from role 'flow-platform'",
	)
}

test_missing_step_refused if {
	refused(json.patch(chip, [{"op": "remove", "path": ["files", synthesis]}]), "missing attestation design-2-synthesis.intoto.json")
}

test_wrong_payload_type_refused if {
	refused(
		set(chip, ["files", synthesis, "envelope", "payloadType"], "text/plain"),
		"design-2-synthesis.intoto.json: unexpected payload type text/plain",
	)
}

test_wrong_predicate_type_refused if {
	refused(
		set(chip, stmt(synthesis, ["predicateType"]), "https://slsa.dev/provenance/v1"),
		"design-2-synthesis.intoto.json: predicate type https://slsa.dev/provenance/v1, want https://github.com/Horiodino/hw-slsa/design-flow/v0.1",
	)
}

test_wrong_build_type_refused if {
	bt := "https://github.com/Horiodino/hw-slsa/design-flow/step/signoff@v1"
	refused(set(chip, stmt(synthesis, ["predicate", "buildDefinition", "buildType"]), bt), sprintf("design synthesis: wrong buildType %s", [bt]))
}

test_wrong_hwflow_step_refused if {
	refused(
		set(chip, stmt(synthesis, ["predicate", "hwFlow", "step"]), "signoff"),
		`design synthesis: hwFlow.step "signoff" is not the design step synthesis`,
	)
}

test_failed_gate_refused if {
	refused(
		set(chip, stmt(synthesis, ["predicate", "hwFlow", "checks", 0, "result"]), "fail"),
		"design synthesis: gate failed: synthesis-and-check-assert",
	)
}

test_tool_off_the_list_refused if {
	refused(
		set(chip, stmt(synthesis, ["predicate", "hwFlow", "tools", 0, "name"]), "abc"),
		"design synthesis: tool abc is not on the approved list",
	)
}

test_subject_file_changed_refused if {
	refused(
		set(chip, ["files", "artifacts/picorv32.netlist.v", "sha256"], crypto.sha256("another netlist")),
		"design synthesis: subject picorv32.netlist.v does not match its attested digest",
	)
}

test_consumed_subject_not_linked_refused if {
	refused(
		set(chip, stmt("att/design-1-simulation.intoto.json", ["predicate", "buildDefinition", "resolvedDependencies", 0, "digest", "sha256"]), crypto.sha256("x")),
		"design simulation: chain broken, resolvedDependencies do not include source-freeze subject source.tar",
	)
}

test_release_by_another_role_refused if {
	refused(
		set(chip, ["files", "att/design-release.intoto.json", "envelope", "signedBy"], ["flow-platform"]),
		"design-release.intoto.json: no valid signature from role 'tapeout-authority'",
	)
}

test_release_not_linking_a_step_envelope_refused if {
	# A different simulation record than the one the release names.
	refused(
		set(chip, ["files", "att/design-1-simulation.intoto.json", "sha256"], crypto.sha256("another record")),
		"design release: chain broken, resolvedDependencies do not include step attestation att/design-1-simulation.intoto.json",
	)
}

test_released_artifact_not_from_synthesis_refused if {
	doc := set(chip, stmt("att/design-release.intoto.json", ["subject", 0, "digest", "sha256"]), crypto.sha256("x"))
	refused(doc, "design release: released artifact is not an output of synthesis")
}

test_unsigned_source_tag_refused if {
	refused(set(chip, ["files", "artifacts/source-git/tag", "sshSignedBy"], []), "source tag: no valid signature from role 'source-owner'")
}

test_tag_for_another_commit_refused if {
	refused(set(chip, ["files", "artifacts/source-git/commit", "gitObject", "id"], "0000000000000000000000000000000000000000"), "source tag picosoc-rtl-v1.0 points at a different commit")
}

test_review_by_the_author_refused if {
	doc := set(chip, stmt("att/source-review.intoto.json", ["predicate", "reviewer"]), "Example RTL Engineer <RTL-Engineer@example.com>")
	refused(doc, "source review: reviewer is the commit's author")
}

test_review_not_approved_refused if {
	doc := set(chip, stmt("att/source-review.intoto.json", ["predicate", "decision"]), "changes-requested")
	refused(doc, "source review did not approve commit d9feac4a82a290458f04a26c3ae92e97d5d19488")
}

test_ip_file_not_the_vendors_refused if {
	doc := set(chip, ["files", "artifacts/source.tar", "members", "picorv32.v"], crypto.sha256("patched core"))
	refused(doc, "ip picorv32: picorv32.v in source.tar does not match the vendor's signed provenance")
}

test_ip_provenance_by_another_role_refused if {
	doc := set(chip, ["files", "att/ip-picorv32.intoto.json", "envelope", "signedBy"], ["source-owner"])
	refused(doc, "ip-picorv32.intoto.json: no valid signature from role 'ip-vendor'")
}

test_design_l3_step_not_isolated_refused if {
	doc := set(chip, stmt(synthesis, ["predicate", "hwFlow", "isolation", "signingKeyMounted"]), true)
	refused(doc, "Design L3: design synthesis: the signing key was within reach of the step")
}

test_design_l3_open_network_refused if {
	doc := set(chip, stmt(synthesis, ["predicate", "hwFlow", "network", "mode"]), "open")
	refused(doc, "Design L3: design synthesis: network access is open, so the step is not isolated")
}

test_design_l3_isolation_and_network_disagree_refused if {
	doc := set(chip, stmt(synthesis, ["predicate", "hwFlow", "isolation", "network"]), "license-server")
	refused(doc, "Design L3: design synthesis: hwFlow.isolation (network license-server) and hwFlow.network (mode isolated) disagree")
}

test_design_l3_unpinned_tool_refused if {
	doc := set(chip, stmt(synthesis, ["predicate", "hwFlow", "tools", 0, "digest", "sha256"]), crypto.sha256("another yosys"))
	refused(doc, sprintf("Design L3: design synthesis: tool yosys sha256:%s is not on the policy's pinned tool list (design.toolPins)", [crypto.sha256("another yosys")]))
}

test_design_l3_unpinned_package_refused if {
	doc := set(chip, stmt(synthesis, ["predicate", "hwFlow", "tools", 0, "package", "version"]), "0.34-1")
	refused(doc, "Design L3: design synthesis: tool yosys is the pinned binary, but its package yosys 0.34-1 is not the pinned one")
}

test_design_l3_no_equivalence_proof_refused if {
	doc := set(chip, stmt("att/design-3-signoff.intoto.json", ["predicate", "hwFlow", "checks", 0, "name"]), "lint")
	refused(doc, "Design L3: design signoff: no passing rtl-netlist-equivalence check, so no record proves the netlist equal to the RTL")
}

test_design_l3_equivalence_script_changed_refused if {
	doc := set(chip, ["files", "artifacts/equivalence.ys", "sha256"], crypto.sha256("weaker proof"))
	refused(doc, "Design L3: design signoff: the equivalence script equivalence.ys in the bundle is not the one the record names")
}

test_design_l4_claim_refused if {
	doc := set(chip, ["policy", "claims", "design"], ["HSLSA_DESIGN_LEVEL_4", "SLSA_BUILD_LEVEL_3"])
	refused(doc, "policy claims Design L4; these Rego policies check Design up to L3, and L4 stays with the reference tool")
}

test_design_l2_claim_without_source_rules_refused if {
	doc := json.patch(chip, [{"op": "remove", "path": ["policy", "design", "source"]}])
	refused(doc, "policy claims Design L3 but does not require a signed, reviewed source freeze")
}
