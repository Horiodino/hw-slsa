# Helpers the HSLSA buyer checks in this directory share.
#
# The input is the document e2e/rego/input.sh builds from a bundle:
#
#   policy     the buyer's policy.json
#   trustRoot  the trust root's role names (and validUntil, when it has one)
#   files      every file by its path in the bundle: sha256 and size; for a
#              DSSE envelope, its payloadType, decoded statement, and the
#              roles whose keys verified one of its signatures (signedBy) by
#              key fingerprint (keys); JSON artifacts parsed (json), .txt
#              files as text; git objects' ids and the signed tag's signers
#              (sshSignedBy); a tar's members by sha256 (members)
#   received   optional: the units or boards the buyer received
#   parts      for a board: the same document for each part bundle
#
# openssl and ssh-keygen check the signatures; these policies only read
# which roles' keys verified each one, and decide everything else.
package hslsa.lib

ns := "https://github.com/Horiodino/hw-slsa"

design_flow := sprintf("%s/design-flow/v0.1", [ns])

mfg_step := sprintf("%s/manufacturing-step/v0.1", [ns])

hbom_type := sprintf("%s/hbom/v0.1", [ns])

source_review_type := sprintf("%s/source-review/v0.1", [ns])

slsa_provenance := "https://slsa.dev/provenance/v1"

vsa_type := "https://slsa.dev/verification_summary/v1"

statement_type := "https://in-toto.io/Statement/v1"

payload_type := "application/vnd.in-toto+json"

# The verifier id the reference tool puts in the receipt VSAs it signs.
verifier_id := sprintf("%s/tools/hslsa/verify@v0.1", [ns])

simulated_level := "HSLSA_SIMULATED"

design_step_type(step) := sprintf("%s/design-flow/step/%s@v1", [ns, step])

mfg_step_type(step) := sprintf("%s/mfg/step/%s@v1", [ns, step])

files := input.files

base(path) := name if {
	parts := split(path, "/")
	name := parts[count(parts) - 1]
}

# Opening a record

# open_error is why the envelope at path does not open as a statement of
# predicate type ptype signed by a key the trust root lists for role. It is
# undefined when the record opens.
open_error(path, role, ptype) := sprintf("missing attestation %s", [base(path)]) if {
	not files[path]
} else := sprintf("%s: not a DSSE envelope", [base(path)]) if {
	not files[path].envelope
} else := sprintf("%s: unexpected payload type %s", [base(path), files[path].envelope.payloadType]) if {
	files[path].envelope.payloadType != payload_type
} else := sprintf("%s: no valid signature from role '%s'", [base(path), role]) if {
	not role in files[path].envelope.signedBy
} else := sprintf("%s: payload is not an in-toto statement", [base(path)]) if {
	not statement_ok(files[path].envelope.statement)
} else := sprintf("%s: predicate type %s, want %s", [base(path), files[path].envelope.statement.predicateType, ptype]) if {
	files[path].envelope.statement.predicateType != ptype
}

statement_ok(s) if {
	s._type == statement_type
	is_string(s.predicateType)
	s.predicateType != ""
	count(s.subject) > 0
	every sub in s.subject {
		is_object(sub.digest)
		count(sub.digest) > 0
	}
}

opened(path, role, ptype) if {
	files[path]
	not open_error(path, role, ptype)
}

stmt(path) := files[path].envelope.statement

get(s, path) := object.get(s, path, null)

build_type(s) := object.get(s, ["predicate", "buildDefinition", "buildType"], "")

first_subject(s) := s.subject[0]

# The record's predicate is a superset of SLSA Provenance v1: it names a
# buildType and a builder.
provenance_error(label, s) := sprintf("%s: SLSA Provenance v1 needs buildType and builder.id", [label]) if {
	not provenance_ok(s)
}

provenance_ok(s) if {
	is_string(s.predicate.buildDefinition.buildType)
	s.predicate.buildDefinition.buildType != ""
	is_string(s.predicate.runDetails.builder.id)
	s.predicate.runDetails.builder.id != ""
}

# Gates: every check the record lists passed.
gate_error(label, s, block) := sprintf("%s: gate failed: %s", [label, concat(", ", failed)]) if {
	failed := [object.get(c, "name", "") |
		some c in object.get(s, ["predicate", block, "checks"], [])
		object.get(c, "result", "") != "pass"
	]
	count(failed) > 0
}

# Links: a record links a file or subject when its resolvedDependencies name
# that sha256.
dep_sha256s(s) := {d.digest.sha256 | some d in s.predicate.buildDefinition.resolvedDependencies}

missing_links(s, wanted) := [object.get(w, "name", "") |
	some w in wanted
	not object.get(w, ["digest", "sha256"], "") in dep_sha256s(s)
]

link_error(label, s, wanted, what) := sprintf("%s: chain broken, resolvedDependencies do not include %s %s", [label, what, concat(", ", missing)]) if {
	missing := missing_links(s, wanted)
	count(missing) > 0
}

# env_rd describes a file of the bundle as a resource descriptor, as a
# record names it when it links that file.
env_rd(path) := {"name": path, "digest": {"sha256": files[path].sha256}}

env_rd(path) := {"name": path, "digest": {}} if not files[path]

# Every file subject (not a urn:) is in artifacts/ with the attested sha256.
subject_file_errors(label, s) := {msg |
	some sub in s.subject
	not startswith(object.get(sub, "name", ""), "urn:")
	msg := subject_file_error(label, sub)
}

subject_file_error(label, sub) := sprintf("%s: subject %s is missing from the bundle", [label, sub.name]) if {
	not files[concat("/", ["artifacts", sub.name])]
} else := sprintf("%s: subject %s does not match its attested digest", [label, sub.name]) if {
	files[concat("/", ["artifacts", sub.name])].sha256 != object.get(sub, ["digest", "sha256"], "")
}

# Lot lists (spec, "Lot digest")

# unit_lines are the non-blank lines of a unit list, as written.
unit_lines(text) := [line |
	some line in split(replace(replace(text, "\r\n", "\n"), "\r", "\n"), "\n")
	trim_space(line) != ""
]

# lot_digest is the sha256 of the canonical unit list: ids trimmed, sorted
# as byte strings, joined with newlines, one trailing newline. It is
# undefined when an id repeats.
lot_digest(ids) := crypto.sha256(concat("", [concat("\n", sort(trimmed)), "\n"])) if {
	trimmed := [t | some id in ids; t := trim_space(id); t != ""]
	count({t | some t in trimmed}) == count(trimmed)
}

# Python's truth test for a JSON value, as the reference tool reads flags.
truthy(v) if v == true

truthy(v) if {
	is_string(v)
	v != ""
}

truthy(v) if {
	is_number(v)
	v != 0
}

truthy(v) if {
	is_array(v)
	count(v) > 0
}

truthy(v) if {
	is_object(v)
	count(v) > 0
}

# Claims (spec, "Core requirements")

tracks := ["DESIGN", "WAFER", "PACKAGE_TEST", "ASSEMBLY", "FIRMWARE"]

track_title := {"DESIGN": "Design", "WAFER": "Wafer", "PACKAGE_TEST": "Package/Test", "ASSEMBLY": "Assembly", "FIRMWARE": "Firmware"}

# The highest level of each track these policies check. A claim above it is
# refused, so a check never passes a level it did not establish. Design L4,
# and Wafer, Package/Test and Assembly L3 and L4, stay with the reference tool.
rego_checks := {"DESIGN": 3, "WAFER": 2, "PACKAGE_TEST": 2, "ASSEMBLY": 2, "FIRMWARE": -1}

claim_level(c, track) := to_number(n) if {
	prefix := sprintf("HSLSA_%s_LEVEL_", [track])
	startswith(c, prefix)
	n := trim_prefix(c, prefix)
	regex.match(`^[0-9]+$`, n)
}

slsa_build_level(c) := to_number(n) if {
	startswith(c, "SLSA_BUILD_LEVEL_")
	n := trim_prefix(c, "SLSA_BUILD_LEVEL_")
	regex.match(`^[0-3]$`, n)
}

# track_claim is the highest level of track any of the policy's claims names.
track_claim(track) := max({n |
	some list in object.get(input.policy, "claims", {})
	some c in list
	n := claim_level(c, track)
} | {0})

# claim_errors refuses a claims list a check cannot stand behind: a value the
# framework does not define, a level above 4, a track the check does not
# cover, or an SLSA build level above the Design or Firmware level of the
# same list. unchecked_claim_errors refuses a level these policies do not
# check.
claim_errors(name, covered) := {msg |
	some c in object.get(input.policy, ["claims", name], [])
	msg := claim_error(name, c, covered)
} | slsa_error(name)

claim_error(name, c, covered) := sprintf("policy claims.%s: claim %s: not a level this framework defines", [name, c]) if {
	c != simulated_level
	not slsa_build_level(c)
	not known_track_claim(c)
} else := sprintf("policy claims.%s: claim %s: levels run from 0 to 4", [name, c]) if {
	some t in tracks
	claim_level(c, t) > 4
} else := sprintf("policy claims.%s: claim %s: this check covers %s, not the %s track", [name, c, concat(", ", [track_title[x] | some x in covered]), track_title[t]]) if {
	some t in tracks
	claim_level(c, t)
	not t in covered
}

known_track_claim(c) if {
	some t in tracks
	claim_level(c, t)
}

slsa_error(name) := {sprintf("policy claims.%s: claims SLSA Build L%d but no Design or Firmware level of at least L%d in the same list", [name, slsa, slsa])} if {
	list := object.get(input.policy, ["claims", name], [])
	slsa := max({n | some c in list; n := slsa_build_level(c)} | {0})
	best := max({n | some c in list; some t in ["DESIGN", "FIRMWARE"]; n := claim_level(c, t)} | {0})
	slsa > best
} else := set()

# A level above what the policies check, claimed in any list, for a track a
# check covers: that check would have to run rules it does not have.
unchecked_claim_errors(covered) := {msg |
	some t in covered
	n := track_claim(t)
	n > rego_checks[t]
	msg := sprintf("policy claims %s L%d; these Rego policies check %s up to L%d, and L%d stays with the reference tool", [track_title[t], n, track_title[t], rego_checks[t], n])
}

# Trust root

trust_root_errors := {msg |
	until := input.trustRoot.validUntil
	is_string(until)
	time.parse_rfc3339_ns(until) <= time.now_ns()
	msg := sprintf("trust root expired %s, when its first enrollment ended", [until])
}

# Records made from simulated hardware (spec, "Records from simulated hardware")

accepts_simulated(policy) if truthy(object.get(policy, ["simulated", "accept"], null))

simulated_of(s) := s.predicate.hwMfg.simulated if {
	"simulated" in object.keys(s.predicate.hwMfg)
} else := s.predicate.hwProvision.simulated if {
	"simulated" in object.keys(s.predicate.hwProvision)
} else := s.predicate.hwInspection.simulated if {
	"simulated" in object.keys(s.predicate.hwInspection)
} else := {"simulator": "a verifier's summary of simulated evidence"} if {
	simulated_level in s.predicate.verifiedLevels
}

simulator(m) := m.simulator if is_string(m.simulator)

else := "unnamed"

# simulated_records lists the envelopes at paths made from simulated hardware.
simulated_records(paths) := sort([sprintf("%s (%s)", [p, simulator(m)]) |
	some p in paths
	m := simulated_of(files[p].envelope.statement)
])

simulated_error(what, recs) := sprintf("%s: %d record(s) made from simulated hardware, and the policy does not accept simulated evidence (simulated.accept): %s", [what, count(recs), concat(", ", recs)]) if {
	count(recs) > 0
	not accepts_simulated(input.policy)
}

# Fields a record withholds for selective disclosure. These policies do not
# read disclosures, so they refuse such a record.
withheld_error(label, s) := sprintf("%s: withholds %d field(s) (hwMfg.confidential); disclosures are not read by these Rego policies", [label, count(w)]) if {
	w := object.get(s, ["predicate", "hwMfg", "confidential"], [])
	count(w) > 0
} else := sprintf("%s: withholds %d field(s) (redactions); disclosures are not read by these Rego policies", [label, count(w)]) if {
	w := object.get(s, ["predicate", "redactions"], [])
	count(w) > 0
}

# HBOM

# hbom_schema_error checks an HBOM predicate against the HBOM JSON Schema,
# which run.sh loads as data.hslsa.hbom_schema from hbom/.
hbom_schema_error(label, pred) := sprintf("%s: the HBOM schema is not loaded (data.hslsa.hbom_schema)", [label]) if {
	not data.hslsa.hbom_schema
} else := sprintf("%s: HBOM does not match its schema: %s", [label, concat("; ", sort([e.error | some e in r[1]]))]) if {
	r := json.match_schema(pred, data.hslsa.hbom_schema)
	not r[0]
}

# Renderings the HBOM lists as files in the bundle have the digest it lists.
rendering_errors(label, s) := {msg |
	some r in object.get(s, ["predicate", "renderings"], [])
	startswith(object.get(r, "uri", ""), "file:")
	path := trim_prefix(r.uri, "file:")
	msg := rendering_error(label, path, r)
}

rendering_error(label, path, r) := sprintf("%s: rendering %s is missing from the bundle", [label, path]) if {
	not files[path]
} else := sprintf("%s: rendering %s does not match its digest", [label, path]) if {
	files[path].sha256 != object.get(r, ["digest", "sha256"], "")
}
