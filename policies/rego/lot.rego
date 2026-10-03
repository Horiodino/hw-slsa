# The lot receipt check (spec, "Where the chain is checked"), for a buyer
# who does not run the reference tool.
#
# Wafer L1 and L2 and Package/Test L1 and L2, as tools/hslsa/verify.go and
# gaps.go check them, after the tapeout check (tapeout.rego) passes:
#   F1 wafer fab, F2 wafer sort, F3 packaging and F4 final test, each signed
#   by its site's role, with its step's buildType, gates passed and file
#   subjects in the bundle, linking the record before it by digest (F1 links
#   the design release) and naming the released design and release in
#   designRef;
#   the transfer that leaves each step (required with
#   manufacturing.requireTransfers), signed by the shipping site, linking the
#   record that shipped, from that site to the site that signed the next
#   step, with a packing list that ships exactly the lot it names;
#   genealogy: every packaged unit traces to a unique passing die of the
#   wafer lot; the packaged and shipped lot lists match the attested lot
#   digests, recomputed here; yield accounts for every packaged unit;
#   the HBOM is signed by product-owner, matches its schema, binds the
#   released design and the shipped lot, and points at these records by
#   digest; every received unit is in the shipped lot.
#
# Refused here, and left to the reference tool: records signed on a
# supplier's behalf (proxy or evidence), records made from supplier exports
# (hwMfg.adapter), records that withhold fields, and Wafer or Package/Test
# claims above L2.
package hslsa.lot

import data.hslsa.lib
import data.hslsa.tapeout

mfg_steps := ["wafer-fab", "wafer-sort", "packaging", "final-test"]

mfg_att := {
	"wafer-fab": "att/mfg-f1-wafer-fab.intoto.json",
	"wafer-sort": "att/mfg-f2-wafer-sort.intoto.json",
	"packaging": "att/mfg-f3-packaging.intoto.json",
	"final-test": "att/mfg-f4-final-test.intoto.json",
}

mfg_signer := {"wafer-fab": "fab-site", "wafer-sort": "sort-site", "packaging": "osat-site", "final-test": "test-site"}

transfer_att(from) := sprintf("att/mfg-transfer-%s.intoto.json", [from])

# The step whose first subject names what a transfer ships.
transfer_lot := {"wafer-fab": "wafer-fab", "wafer-sort": "wafer-fab", "packaging": "packaging"}

hbom_path := "att/hbom.intoto.json"

require_transfers := lib.truthy(object.get(input.policy, ["manufacturing", "requireTransfers"], null))

# Steps and the transfers between them, each with the step before it.
before[step] := mfg_steps[i - 1] if {
	some i, step in mfg_steps
	i > 0
}

# The steps that ship to another site, in order.
shipping_steps := array.slice(mfg_steps, 0, 3)

# The transfers in the chain: those the bundle has, or all when the policy
# requires them.
transfers contains from if {
	some _, from in before
	lib.files[transfer_att(from)]
}

transfers contains from if {
	some _, from in before
	require_transfers
}

final := tapeout.final

release_rd := tapeout.release_rd

deny contains "the tapeout check did not pass, so the lot cannot be checked against the design" if count(tapeout.deny) > 0

deny contains msg if some msg in lib.claim_errors("lot", ["WAFER", "PACKAGE_TEST", "DESIGN"])

deny contains msg if some msg in lib.unchecked_claim_errors(["WAFER", "PACKAGE_TEST"])

deny contains "policy: manufacturing.requireExports asks for supplier exports to be read again, which these Rego policies do not do" if {
	lib.truthy(object.get(input.policy, ["manufacturing", "requireExports"], null))
}

# Records the reference tool reads with rules these policies do not have.
# The payload is read before its signature is checked, as the reference
# tool does to pick the role to check it against.
record_paths := array.concat([mfg_att[step] | some step in mfg_steps], [transfer_att(from) | some from in shipping_steps; from in transfers])

deny contains sprintf("%s: signed on a supplier's behalf (hwMfg.proxy); these Rego policies do not check proxy-signed or evidence records", [lib.base(p)]) if {
	some p in record_paths
	"proxy" in object.keys(lib.files[p].envelope.statement.predicate.hwMfg)
}

deny contains sprintf("%s: made from supplier exports (hwMfg.adapter), which these Rego policies do not read again", [lib.base(p)]) if {
	some p in record_paths
	"adapter" in object.keys(lib.files[p].envelope.statement.predicate.hwMfg)
}

deny contains msg if {
	some p in array.concat(record_paths, [hbom_path])
	msg := lib.withheld_error(lib.base(p), lib.files[p].envelope.statement)
}

# F1 to F4

stmts[step] := lib.stmt(mfg_att[step]) if {
	some step in mfg_steps
	lib.opened(mfg_att[step], mfg_signer[step], lib.mfg_step)
}

deny contains msg if {
	some step in mfg_steps
	msg := lib.open_error(mfg_att[step], mfg_signer[step], lib.mfg_step)
}

deny contains sprintf("%s: wrong buildType", [step]) if {
	some step, s in stmts
	lib.build_type(s) != lib.mfg_step_type(step)
}

deny contains msg if {
	some step, s in stmts
	msg := lib.provenance_error(step, s)
}

deny contains msg if {
	some step, s in stmts
	msg := lib.gate_error(step, s, "hwMfg")
}

deny contains msg if {
	some step, s in stmts
	some msg in lib.subject_file_errors(step, s)
}

# Each step links the record before it: the design release for F1, else the
# transfer into it, or the step before when there is no transfer.
prev(step) := tapeout.release_path if step == "wafer-fab"

prev(step) := transfer_att(before[step]) if before[step] in transfers

prev(step) := mfg_att[before[step]] if {
	before[step]
	not before[step] in transfers
}

deny contains msg if {
	some step, s in stmts
	msg := lib.link_error(step, s, [lib.env_rd(prev(step))], "previous step")
}

deny contains sprintf("%s: designRef names a different design release", [step]) if {
	some step, s in stmts
	not design_ref_ok(s)
}

design_ref_ok(s) if {
	ref := s.predicate.hwMfg.designRef
	ref.digest == final.digest
	ref.release.digest == release_rd.digest
}

# Transfers

transfer_stmts[from] := lib.stmt(transfer_att(from)) if {
	some from in transfers
	lib.opened(transfer_att(from), mfg_signer[from], lib.mfg_step)
}

deny contains msg if {
	some from in transfers
	msg := lib.open_error(transfer_att(from), mfg_signer[from], lib.mfg_step)
}

deny contains sprintf("transfer from %s: wrong buildType", [from]) if {
	some from, t in transfer_stmts
	lib.build_type(t) != lib.mfg_step_type("distribution")
}

deny contains msg if {
	some from, t in transfer_stmts
	msg := lib.provenance_error(sprintf("transfer from %s", [from]), t)
}

deny contains msg if {
	some from, t in transfer_stmts
	msg := lib.gate_error(sprintf("transfer from %s", [from]), t, "hwMfg")
}

deny contains msg if {
	some from, t in transfer_stmts
	some msg in lib.subject_file_errors(sprintf("transfer from %s", [from]), t)
}

deny contains msg if {
	some from, t in transfer_stmts
	msg := lib.link_error(sprintf("transfer from %s", [from]), t, [lib.env_rd(mfg_att[from])], "shipping step")
}

deny contains sprintf("transfer from %s: designRef names a different design release", [from]) if {
	some from, t in transfer_stmts
	not design_ref_ok(t)
}

# The site that ships, and the site that signed the step it ships to.
receiver_step[from] := step if some step, from in before

deny contains sprintf("transfer from %s: shipped by %s, not by %s, which signed %s", [from, object.get(t, ["predicate", "hwMfg", "site", "name"], ""), sender.name, from]) if {
	some from, t in transfer_stmts
	sender := stmts[from].predicate.hwMfg.site
	object.get(t, ["predicate", "hwMfg", "site"], null) != sender
}

deny contains sprintf("transfer from %s: shipped to %s, but %s signed the next step", [from, object.get(t, ["predicate", "hwMfg", "receiver", "name"], ""), to.name]) if {
	some from, t in transfer_stmts
	to := stmts[receiver_step[from]].predicate.hwMfg.site
	object.get(t, ["predicate", "hwMfg", "receiver"], null) != to
}

packing_list(t) := lib.files[concat("/", ["artifacts", t.subject[0].name])].json

deny contains sprintf("transfer from %s: packing list is missing or not JSON", [from]) if {
	some from, t in transfer_stmts
	not is_object(packing_list(t))
}

deny contains sprintf("transfer from %s: packing list names other sites than the record", [from]) if {
	some from, t in transfer_stmts
	list := packing_list(t)
	not packing_sites_ok(from, list)
}

packing_sites_ok(from, list) if {
	list.from == stmts[from].predicate.hwMfg.site
	list.to == stmts[receiver_step[from]].predicate.hwMfg.site
}

deny contains sprintf("transfer from %s: packing list does not ship exactly %s", [from, lot.name]) if {
	some from, t in transfer_stmts
	list := packing_list(t)
	lot := stmts[transfer_lot[from]].subject[0]
	not ships_exactly(list, lot)
}

ships_exactly(list, lot) if {
	list.lot == lot.name
	lib.lot_digest(list.items) == lot.digest.sha256
	list.quantity == count(list.items)
}

# Genealogy: every packaged unit came from a passing die of this wafer lot,
# each die used once.
wafer_lot := stmts["wafer-fab"].subject[0]

wafer_maps := lib.files["artifacts/wafer-maps.json"].json

genealogy := lib.files["artifacts/genealogy.json"].json.units

good_dies := {[d.wafer, d.x, d.y] | some d in wafer_maps.dies; d.bin == "pass"}

deny contains "wafer-sort: wafer maps: missing from the bundle or not JSON" if {
	stmts["wafer-sort"]
	not is_object(wafer_maps)
}

deny contains "wafer-sort: wafer maps name a different wafer lot" if {
	is_object(wafer_maps)
	object.get(wafer_maps, "waferLot", "") != wafer_lot.name
}

deny contains "packaging: genealogy: missing from the bundle or not JSON" if {
	stmts.packaging
	not is_object(genealogy)
}

deny contains sprintf("packaging: genealogy for %s does not trace to a unique passing die", [unit]) if {
	some unit, g in genealogy
	not traces_to_unique_passing_die(g)
}

traces_to_unique_passing_die(g) if {
	g.waferLot == wafer_lot.name
	die := [g.wafer, g.x, g.y]
	die in good_dies
	count([u | some u, h in genealogy; [h.wafer, h.x, h.y] == die]) == 1
}

# Lot lists: the lot digests the records attest are recomputed from the
# lists in the bundle.
packaged := lib.unit_lines(lib.files["artifacts/packaged-lot.txt"].text)

shipped := lib.unit_lines(lib.files["artifacts/shipped-lot.txt"].text)

packaged_lot := stmts.packaging.subject[0]

lot := stmts["final-test"].subject[0]

deny contains "packaging: packaged lot list does not match the attested lot digest and genealogy" if {
	stmts.packaging
	not packaged_ok
}

packaged_ok if {
	lib.lot_digest(packaged) == packaged_lot.digest.sha256
	{u | some u in packaged} == {u | some u, _ in genealogy}
}

deny contains "final-test: shipped lot list does not match the attested lot digest" if {
	stmts["final-test"]
	not lib.lot_digest(shipped) == lot.digest.sha256
}

deny contains "final-test: shipped lot contains units that were never packaged" if {
	stmts["final-test"]
	count({u | some u in shipped} - {u | some u in packaged}) > 0
}

deny contains "final-test: yield record does not account for every packaged unit" if {
	stmts["final-test"]
	not yield_ok(stmts["final-test"].predicate.hwMfg.yield)
}

yield_ok(y) if {
	sort({u | some u in packaged} - {u | some u in shipped}) == sort(y.failed)
	y.passed == count({u | some u in shipped})
}

deny contains sprintf("received unit %s is not in the shipped lot", [unit]) if {
	stmts["final-test"]
	some unit in object.get(input, "received", [])
	not unit in shipped
}

# HBOM: signed by the product owner, bound to the same design and lot,
# pointing at these records.
hb := lib.stmt(hbom_path) if lib.opened(hbom_path, "product-owner", lib.hbom_type)

deny contains msg if msg := lib.open_error(hbom_path, "product-owner", lib.hbom_type)

deny contains msg if msg := lib.hbom_schema_error("hbom", hb.predicate)

hbom_subjects := {s.name: s.digest | some s in hb.subject}

deny contains "hbom: design subject does not match the released design" if {
	hb
	object.get(hbom_subjects, final.name, null) != final.digest
}

deny contains "hbom: lot subject does not match the final test shipped lot" if {
	hb
	stmts["final-test"]
	object.get(hbom_subjects, lot.name, null) != lot.digest
}

hbom_tests := object.get(hb, ["predicate", "manufacturing", "test"], [])

deny contains "hbom: manufacturing.test does not list wafer sort and final test" if {
	hb
	count(hbom_tests) < 2
}

# Each reference: the record it must point at ("" for any), and its uri and digest.
hbom_refs contains ["wafer-fab", object.get(hb, ["predicate", "manufacturing", "fab", "attestationRef"], {})] if hb

hbom_refs contains ["packaging", object.get(hb, ["predicate", "manufacturing", "assembly", "attestationRef"], {})] if hb

hbom_refs contains ["wafer-sort", object.get(hbom_tests[0], "resultsRef", {})] if count(hbom_tests) >= 2

hbom_refs contains ["final-test", object.get(hbom_tests[1], "resultsRef", {})] if count(hbom_tests) >= 2

hbom_refs contains ["", object.get(f, "provenanceRef", {})] if {
	some f in object.get(hb, ["predicate", "design", "flow"], [])
}

ref_path(ref) := concat("/", ["att", trim_prefix(object.get(ref, "uri", ""), "file:att/")])

deny contains sprintf("hbom: reference for %s points at %s", [step, lib.base(ref_path(ref))]) if {
	some [step, ref] in hbom_refs
	step != ""
	ref_path(ref) != mfg_att[step]
}

deny contains sprintf("hbom: reference to %s does not match its digest", [lib.base(ref_path(ref))]) if {
	some [_, ref] in hbom_refs
	not lib.env_rd(ref_path(ref)).digest == object.get(ref, "digest", null)
}

deny contains msg if some msg in lib.rendering_errors("hbom", hb)

# Simulated evidence: refused unless the policy accepts it.
inputs := array.concat(record_paths, [hbom_path])

simulated := lib.simulated_records(inputs)

deny contains msg if msg := lib.simulated_error("lot receipt check", simulated)

not_recorded := [sprintf("transfer from %s to %s", [from, step]) |
	some step, from in before
	not from in transfers
]

checked := array.concat(
	[
	sprintf("%s: signed by %s, buildType, gates passed, file subjects match, links %s by digest, designRef names the release", [step, mfg_signer[step], lib.base(prev(step))]) |
		some step in mfg_steps
	],
	array.concat(
		[
		sprintf("transfer from %s: signed by %s, links %s, from its site to the next step's site, packing list ships exactly the lot (digest recomputed)", [from, mfg_signer[from], lib.base(mfg_att[from])]) |
			some from in shipping_steps
			from in transfers
		],
		[
			"genealogy: every packaged unit on a unique passing die of the wafer lot",
			"packaged and shipped lot lists: lot digests recomputed and equal to the attested ones; yield accounts for every packaged unit",
			"hbom: signed by product-owner, matches the HBOM schema, binds the released design and the shipped lot, points at F1 to F4 and every design step by digest",
			sprintf("received units: %d, all in the shipped lot", [count(object.get(input, "received", []))]),
		],
	),
)

report := {
	"check": "lot receipt check",
	"passed": count(deny) == 0,
	"subject": sprintf("%s sha256:%s", [object.get(lot, "name", "?"), object.get(lot, ["digest", "sha256"], "?")]),
	"levels": object.get(input.policy, ["claims", "lot"], []),
	"deny": sort(deny),
	"checked": checked,
	"simulated": simulated,
	"notRecorded": not_recorded,
}
