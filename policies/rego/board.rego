# The board receipt check (spec, "Where the chain is checked"), for a buyer
# who does not run the reference tool.
#
# Assembly L1 and L2, as tools/hslsa/board.go checks them:
#   the board HBOM is signed by board-owner, matches its schema, is a board
#   (or module or system), and names the board design and the board lot;
#   A1 is signed by ems-site, with its buildType, gates passed, file subjects
#   in the bundle, designRef and a link to the board design, and the HBOM
#   points at it by digest and names its board lot;
#   every part line traces to a distribution record signed by the role the
#   policy gives its shipper, linked from A1, whose shipment data match the
#   part's lot and date code, through an authorized channel when the policy
#   requires one;
#   a part with its own chain (hbomRef) passes the tapeout and lot receipt
#   checks (tapeout.rego, lot.rego) under the trust root and policy in its
#   own bundle, every unit shipped to the EMS is in its shipped lot, its HBOM
#   is of that part, and the EMS's receipt VSA covers exactly those units
#   under the part's policy and levels; A1 links the lot, the HBOM and the
#   receipt;
#   the HBOM lists exactly the board design's positions, every placement is
#   a listed lot, no chip is placed twice or was not shipped, no lot is
#   placed more often than shipped; the board lot list matches its attested
#   digest, recomputed here, and is the boards that passed test, yield
#   accounts for every board, every board is an A1 subject, and every
#   received board is in the lot.
#
# Refused here, and left to the reference tool: Assembly claims above L2
# (part attestations, platform certificates, inspection).
package hslsa.board

import data.hslsa.lib
import data.hslsa.lot
import data.hslsa.tapeout

a1_path := "att/mfg-a1-board-assembly.intoto.json"

hbom_path := "att/hbom.intoto.json"

pol := input.policy

shippers := object.get(pol, "shippers", {})

deny contains msg if some msg in lib.claim_errors("board", ["ASSEMBLY"])

deny contains msg if some msg in lib.unchecked_claim_errors(["ASSEMBLY"])

deny contains msg if some msg in lib.trust_root_errors

# Board HBOM

hb := lib.stmt(hbom_path) if lib.opened(hbom_path, "board-owner", lib.hbom_type)

deny contains msg if msg := lib.open_error(hbom_path, "board-owner", lib.hbom_type)

deny contains msg if msg := lib.hbom_schema_error("board hbom", hb.predicate)

deny contains msg if some msg in lib.hbom_claim_errors("board hbom", hb.predicate, "board", ["ASSEMBLY"])

deny contains msg if msg := lib.withheld_error("board hbom", hb)

deny contains sprintf("board hbom: product level is %s, not a board", [object.get(hb, ["predicate", "product", "level"], "")]) if {
	hb
	not object.get(hb, ["predicate", "product", "level"], "") in {"module", "board", "system"}
}

deny contains "board hbom: expected the board design and the board lot as subjects" if {
	hb
	count(hb.subject) != 2
}

design_subj := hb.subject[0] if count(hb.subject) == 2

lot_subj := hb.subject[1] if count(hb.subject) == 2

deny contains msg if some msg in lib.subject_file_errors("board hbom", {"subject": [design_subj]})

board_design := lib.files[concat("/", ["artifacts", design_subj.name])].json

deny contains sprintf("board hbom: board design %s is not JSON", [design_subj.name]) if {
	lib.files[concat("/", ["artifacts", design_subj.name])]
	not is_object(board_design)
}

deny contains msg if some msg in lib.rendering_errors("board hbom", hb)

# A1

a1 := lib.stmt(a1_path) if lib.opened(a1_path, "ems-site", lib.mfg_step)

deny contains msg if msg := lib.open_error(a1_path, "ems-site", lib.mfg_step)

deny contains "board-assembly: wrong buildType" if lib.build_type(a1) != lib.mfg_step_type("board-assembly")

deny contains msg if msg := lib.provenance_error("board-assembly", a1)

deny contains msg if msg := lib.gate_error("board-assembly", a1, "hwMfg")

deny contains msg if some msg in lib.subject_file_errors("board-assembly", a1)

deny contains msg if msg := lib.withheld_error("board-assembly", a1)

deny contains "board-assembly: designRef names a different board design" if {
	object.get(a1, ["predicate", "hwMfg", "designRef", "digest"], null) != design_subj.digest
}

deny contains msg if msg := lib.link_error("board-assembly", a1, [design_subj], "board design")

deny contains "board hbom: boardAssembly reference does not match the A1 record" if {
	hb
	not a1_ref_ok
}

a1_ref_ok if {
	ref := hb.predicate.manufacturing.boardAssembly.attestationRef
	ref.uri == concat(":", ["file", a1_path])
	ref.digest == lib.env_rd(a1_path).digest
}

deny contains "board hbom: lot subject does not match the A1 board lot" if {
	a1
	lot_subj != lib.first_subject(a1)
}

# Assembly L3 names a part-attestations file among A1's subjects; these
# policies do not read it.
deny contains "board-assembly: the record names part-attestations.json (Assembly L3), which these Rego policies do not check" if {
	some s in a1.subject
	s.digest.sha256 == lib.files["artifacts/part-attestations.json"].sha256
}

# Parts: every lot traces to a signed shipment whose data match, through an
# allowed channel.
parts := object.get(hb, ["predicate", "parts"], [])

dist_name(part) := object.get(part, ["distributor", "name"], "")

dist_rel(part) := trim_prefix(part.distributionRef.uri, "file:")

deny contains sprintf("parts: %s has no distribution record from a shipper in the policy", [object.get(part, "mpn", "")]) if {
	some part in parts
	not shipped_by_listed_shipper(part)
}

shipped_by_listed_shipper(part) if {
	part.distributionRef
	dist_name(part) in object.keys(shippers)
}

# Each distribution record, opened with the role of the shipper the part names.
ship_roles[rel] := role if {
	some part in parts
	shipped_by_listed_shipper(part)
	rel := dist_rel(part)
	role := object.get(shippers, [dist_name(part), "role"], "")
}

ships[rel] := lib.stmt(rel) if {
	some rel, role in ship_roles
	lib.opened(rel, role, lib.mfg_step)
}

deny contains msg if {
	some rel, role in ship_roles
	msg := lib.open_error(rel, role, lib.mfg_step)
}

deny contains "policy: requireShipmentExports asks for shipments to be read again from their shippers' exports, which these Rego policies do not do" if {
	lib.truthy(object.get(pol, "requireShipmentExports", null))
}

deny contains sprintf("distribution %s: made from its shipper's exports (hwMfg.importer), which these Rego policies do not read again", [lib.base(rel)]) if {
	some rel, s in ships
	"importer" in object.keys(object.get(s.predicate, "hwMfg", {}))
}

deny contains sprintf("distribution %s: wrong buildType", [lib.base(rel)]) if {
	some rel, s in ships
	lib.build_type(s) != lib.mfg_step_type("distribution")
}

deny contains msg if {
	some rel, s in ships
	msg := lib.provenance_error(sprintf("distribution %s", [lib.base(rel)]), s)
}

deny contains msg if {
	some rel, s in ships
	msg := lib.gate_error(sprintf("distribution %s", [lib.base(rel)]), s, "hwMfg")
}

deny contains msg if {
	some rel, s in ships
	some msg in lib.subject_file_errors(sprintf("distribution %s", [lib.base(rel)]), s)
}

shipment(rel) := lib.files[concat("/", ["artifacts", ships[rel].subject[0].name])].json

deny contains sprintf("distribution %s: shipment data is missing or not JSON", [lib.base(rel)]) if {
	some rel, _ in ships
	not is_object(shipment(rel))
}

deny contains sprintf("parts: %s distribution reference does not match its digest", [part.mpn]) if {
	some part in parts
	ships[dist_rel(part)]
	part.distributionRef.digest != lib.env_rd(dist_rel(part)).digest
}

deny contains msg if {
	some rel, _ in ships
	msg := lib.link_error("board-assembly", a1, [lib.env_rd(rel)], "shipment record")
}

deny contains sprintf("parts: %s names distributor %s but shipment %s came from %s", [part.mpn, dist_name(part), object.get(ship, "id", ""), object.get(ship, ["shipper", "name"], "")]) if {
	some part in parts
	ship := shipment(dist_rel(part))
	object.get(ship, ["shipper", "name"], "") != dist_name(part)
}

# line is the shipment line of a part: same mpn and manufacturer.
line(part) := lines[0] if {
	lines := [ln |
		some ln in shipment(dist_rel(part)).lines
		ln.mpn == part.mpn
		ln.manufacturer == part.manufacturer.name
	]
	count(lines) > 0
}

deny contains sprintf("parts: %s lot %v does not match the distributor's shipment %s", [part.mpn, object.get(part, "lot", ""), object.get(shipment(dist_rel(part)), "id", "")]) if {
	some part in parts
	shipment(dist_rel(part))
	not line_matches(part)
}

line_matches(part) if {
	ln := line(part)
	object.get(ln, "lot", null) == object.get(part, "lot", null)
	object.get(ln, "dateCode", null) == object.get(part, "dateCode", null)
}

authorized_channel(part) if part.manufacturer.name in object.get(shippers, [dist_name(part), "authorizedFor"], [])

deny contains sprintf("parts: %s is not an authorized channel for %s, but %s claims it is", [dist_name(part), part.manufacturer.name, part.mpn]) if {
	some part in parts
	ships[dist_rel(part)]
	lib.truthy(object.get(part, "authorized", null))
	not authorized_channel(part)
}

deny contains sprintf("parts: policy requires an authorized channel, and %s lot %v was not bought through one", [part.mpn, object.get(part, "lot", "")]) if {
	some part in parts
	lib.truthy(object.get(pol, "requireAuthorizedChannel", null))
	not lib.truthy(object.get(part, "authorized", null))
}

# Parts with their own chain (hbomRef)

chain_parts := [part | some part in parts; part.hbomRef]

hbom_rel(part) := trim_prefix(part.hbomRef.uri, "file:")

# part_dir is the part bundle a file of it sits in: parts/<name> for
# parts/<name>/att/hbom.intoto.json.
part_dir(rel) := concat("/", array.slice(p, 0, count(p) - 2)) if p := split(rel, "/")

part_path(rel) := concat("/", array.slice(p, count(p) - 2, count(p))) if p := split(rel, "/")

# part_file is a part bundle's file by its path in the board bundle.
part_file(rel) := input.parts[part_dir(rel)].files[part_path(rel)]

part_input(part) := object.union(input.parts[part_dir(hbom_rel(part))], {"received": object.get(line(part), "units", [])})

# The part's own checks, run on its bundle as a buyer of the part would.
part_deny(part) := t | l if {
	pi := part_input(part)
	t := tapeout.deny with input as pi
	l := lot.deny with input as pi
}

part_lot(part) := l if {
	pi := part_input(part)
	l := lot.lot with input as pi
}

deny contains sprintf("parts: %s chain is not in the bundle at %s", [part.mpn, part_dir(hbom_rel(part))]) if {
	some part in chain_parts
	not input.parts[part_dir(hbom_rel(part))]
}

deny contains sprintf("parts: %s hbomRef does not match its digest", [part.mpn]) if {
	some part in chain_parts
	part.hbomRef.digest != {"sha256": object.get(part_file(hbom_rel(part)), "sha256", "")}
}

deny contains sprintf("parts: %s lot receipt check failed: %s", [part.mpn, msg]) if {
	some part in chain_parts
	input.parts[part_dir(hbom_rel(part))]
	some msg in part_deny(part)
}

deny contains sprintf("parts: %s hbomRef is the HBOM of %s", [part.mpn, pn]) if {
	some part in chain_parts
	pn := object.get(part_file(hbom_rel(part)), ["envelope", "statement", "predicate", "product", "partNumber"], "")
	pn != part.mpn
}

deny contains sprintf("parts: board claims %s lot %s, but its HBOM names %s", [part.mpn, part.lot, part_lot(part).name]) if {
	some part in chain_parts
	part_lot(part).name != concat("", ["urn:hslsa:lot:", part.lot])
}

# The EMS's receipt VSA for the units of a chip lot it received.
receipt_rel(part) := sprintf("att/receipt-%s.vsa.intoto.json", [part.lot])

receipts[rel] := lib.stmt(rel) if {
	some part in chain_parts
	rel := receipt_rel(part)
	lib.opened(rel, "ems-site", lib.vsa_type)
}

deny contains msg if {
	some part in chain_parts
	msg := lib.open_error(receipt_rel(part), "ems-site", lib.vsa_type)
}

receipt_label(part) := sprintf("%s receipt %s", [part.mpn, lib.base(receipt_rel(part))])

deny contains sprintf("%s: not a passed lot receipt check", [receipt_label(part)]) if {
	some part in chain_parts
	p := receipts[receipt_rel(part)].predicate
	not passed_receipt(p)
}

passed_receipt(p) if {
	p.verifier.id == lib.verifier_id
	p.verificationResult == "PASSED"
}

deny contains sprintf("%s: checked under another policy than the chip's", [receipt_label(part)]) if {
	some part in chain_parts
	p := receipts[receipt_rel(part)].predicate
	object.get(p, ["policy", "digest", "sha256"], "") != input.parts[part_dir(hbom_rel(part))].files["policy.json"].sha256
}

deny contains sprintf("%s: summarizes simulated evidence (%s), and the policy does not accept it (simulated.accept)", [receipt_label(part), lib.simulated_level]) if {
	some part in chain_parts
	p := receipts[receipt_rel(part)].predicate
	lib.simulated_level in object.get(p, "verifiedLevels", [])
	not lib.accepts_simulated(input.parts[part_dir(hbom_rel(part))].policy)
}

deny contains sprintf("%s: does not state %s", [receipt_label(part), level]) if {
	some part in chain_parts
	p := receipts[receipt_rel(part)].predicate
	some level in object.get(input.parts[part_dir(hbom_rel(part))].policy, ["claims", "lot"], [])
	not level in object.get(p, "verifiedLevels", [])
}

deny contains sprintf("%s: covers other units than the %d shipped to the EMS", [receipt_label(part), count(units)]) if {
	some part in chain_parts
	r := receipts[receipt_rel(part)]
	units := object.get(line(part), "units", [])
	not receipt_covers(r, part_lot(part), units)
}

# The receipt's subject: urn:hslsa:receipt:<lot id>, with the lot digest of
# the units received (tools/hslsa ReceiptSubject).
receipt_covers(r, lot_rd, units) if {
	id := trim_prefix(lot_rd.name, "urn:hslsa:lot:")
	startswith(lot_rd.name, "urn:hslsa:lot:")
	id != ""
	count(units) > 0
	count(r.subject) == 1
	r.subject[0].name == concat("", ["urn:hslsa:receipt:", id])
	r.subject[0].digest == {"sha256": lib.lot_digest(units)}
	r.predicate.resourceUri == lot_rd.name
}

deny contains msg if {
	some part in chain_parts
	wanted := [part_lot(part), {"name": hbom_rel(part), "digest": {"sha256": part_file(hbom_rel(part)).sha256}}, lib.env_rd(receipt_rel(part))]
	msg := lib.link_error("board-assembly", a1, wanted, sprintf("%s lot, HBOM and receipt", [part.mpn]))
}

# The HBOM covers exactly the board design, and every placement is a listed lot.
design_ref_des := {r: item.mpn | some item in board_design.bom; some r in item.refDes}

by_ref_des := {r: part | some part in parts; some r in object.get(part, "refDes", [])}

deny contains sprintf("parts: board design %s (%s) has no matching part in the HBOM", [r, mpn]) if {
	some r, mpn in design_ref_des
	object.get(by_ref_des, [r, "mpn"], null) != mpn
}

deny contains sprintf("parts: HBOM lists %s, which the board design does not have", [concat(", ", extra)]) if {
	board_design
	extra := sort([r | some r, _ in by_ref_des; not design_ref_des[r]])
	count(extra) > 0
}

builds := lib.files["artifacts/board-build.json"].json

deny contains "board-assembly: build records: missing from the bundle or not JSON" if {
	a1
	not is_object(builds)
}

deny contains sprintf("board-assembly: board %s placements do not match the board design", [serial]) if {
	some serial, b in builds
	{r | some r, _ in object.get(b, "placements", {})} != {r | some r, _ in design_ref_des}
}

deny contains sprintf("board-assembly: board %s %s is %s lot %v, which the HBOM does not list", [serial, r, object.get(p, "mpn", ""), object.get(p, "lot", "")]) if {
	some serial, b in builds
	some r, p in b.placements
	part := by_ref_des[r]
	not placement_listed(p, part)
}

placement_listed(p, part) if {
	p.mpn == part.mpn
	object.get(p, "lot", null) == object.get(part, "lot", null)
}

# Chips (lines that list units): each placed unit was shipped to the EMS, once.
deny contains sprintf("board-assembly: board %s %s unit %v was never shipped to the EMS", [serial, r, object.get(p, "unit", "")]) if {
	some serial, b in builds
	some r, p in b.placements
	ln := line(by_ref_des[r])
	ln.units
	not object.get(p, "unit", null) in ln.units
}

deny contains sprintf("board-assembly: unit %s is placed on more than one board", [unit]) if {
	some unit in {p.unit | some _, b in builds; some _, p in b.placements}
	count([1 | some _, b in builds; some _, p in b.placements; p.unit == unit]) > 1
}

deny contains sprintf("board-assembly: more %s lot %v placed than were shipped", [part.mpn, object.get(part, "lot", "")]) if {
	some part in parts
	used := count([1 |
		some _, b in builds
		some _, p in b.placements
		p.mpn == part.mpn
		object.get(p, "lot", null) == object.get(part, "lot", null)
	])
	used > object.get(line(part), "quantity", 0)
}

# Board lot and yield.
boards := lib.unit_lines(lib.files["artifacts/board-lot.txt"].text)

good := sort([s | some s, b in builds; b.result == "pass"])

deny contains "board-assembly: board lot list does not match the attested lot digest" if {
	a1
	not lib.lot_digest(boards) == lot_subj.digest.sha256
}

deny contains "board-assembly: board lot is not the set of boards that passed test" if {
	is_object(builds)
	sort(boards) != good
}

deny contains "board-assembly: yield record does not account for every board built" if {
	a1
	is_object(builds)
	not yield_ok(a1.predicate.hwMfg.yield)
}

yield_ok(y) if {
	sort([s | some s, b in builds; b.result != "pass"]) == sort(y.failed)
	y.passed == count(good)
}

board_urn(mfr, serial) := sprintf("urn:hslsa:board:%s:%s", [lower(replace(mfr, " ", "-")), serial])

deny contains sprintf("board-assembly: board %s is not a subject of the A1 record", [serial]) if {
	a1
	mfr := hb.predicate.product.manufacturer.name
	subjects := {s.name: s.digest | some s in a1.subject}
	some serial in boards
	object.get(subjects, board_urn(mfr, serial), null) != {"sha256": crypto.sha256(serial)}
}

deny contains sprintf("received board %s is not in the board lot", [serial]) if {
	a1
	some serial in object.get(input, "received", [])
	not serial in boards
}

# Simulated evidence: refused unless the policy accepts it.
simulated := lib.simulated_records(array.concat([hbom_path, a1_path], sort([rel | some rel, _ in ship_roles])))

deny contains msg if msg := lib.simulated_error("board receipt check", simulated)

checked := array.concat(
	[
		"board hbom: signed by board-owner, matches the HBOM schema, a board, names the board design (file digest checked) and the board lot",
		"board-assembly (A1): signed by ems-site, buildType, gates passed, file subjects match, designRef and a link to the board design; the HBOM points at it by digest",
	],
	array.concat(
		[sprintf("distribution %s: signed by %s, buildType, gates passed, shipment file matches, linked from A1", [lib.base(rel), role]) | some rel, role in ship_roles],
		array.concat(
			[
				sprintf("parts: %d lines, each traced to its shipment line (lot, date code) through a channel the policy authorizes", [count(parts)]),
			],
			array.concat(
				[
				sprintf("part %s (%s): tapeout and lot receipt checks on its bundle under its own trust root and policy, %d shipped units in its lot, receipt VSA by ems-site covers them, A1 links lot, HBOM and receipt", [part.mpn, part_dir(hbom_rel(part)), count(object.get(line(part), "units", []))]) |
					some part in chain_parts
				],
				[
					"placements: every board position is a listed lot, no chip placed twice or unshipped, no lot used more than shipped",
					"board lot: lot digest recomputed and equal to A1's; the boards that passed test; yield accounts for every board; every board an A1 subject",
					sprintf("received boards: %d, all in the board lot", [count(object.get(input, "received", []))]),
				],
			),
		),
	),
)

report := {
	"check": "board receipt check",
	"passed": count(deny) == 0,
	"subject": sprintf("%s sha256:%s", [object.get(lot_subj, "name", "?"), object.get(lot_subj, ["digest", "sha256"], "?")]),
	"levels": object.get(input.policy, ["claims", "board"], []),
	"deny": sort(deny),
	"checked": checked,
	"simulated": simulated,
}
