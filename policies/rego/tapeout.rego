# The tapeout check (spec, "Where the chain is checked"), for a buyer who
# does not run the reference tool.
#
# Design L1 to L3, as tools/hslsa/verify.go and source.go check them:
#   every design step the policy requires is signed by flow-platform, with
#   its step's buildType and hwFlow.step, its gates passed, its file
#   subjects in the bundle with the attested digests, only approved tools,
#   and links to the subjects of the steps it consumes;
#   the release is signed by tapeout-authority, links every step envelope by
#   digest, and releases an output of design.finalArtifactFrom;
#   Design L2: the source freeze names the commit of a tag signed by the
#   source owner's key, approved by a reviewer who is not its author, and
#   links the review and the IP vendor's signed provenance, whose files are
#   the ones in the source archive;
#   Design L3: every step that runs tools ran isolated, with every tool
#   pinned by digest, and an equivalence record proves the released netlist
#   equal to the frozen RTL.
#
# Not checked here, and left to the reference tool: that the source archive
# holds exactly the files of the tagged git tree (git's binary tree and tar
# formats), and Design L4. A policy that claims Design L4 is refused.
package hslsa.tapeout

import data.hslsa.lib

pol := object.get(input.policy, "design", {})

required := object.get(pol, "requiredSteps", [])

# Envelope file names, as tools/hslsa names them (AttName).
design_steps := ["source-freeze", "simulation", "synthesis", "signoff"]

# The step names hwFlow.step and the HBOM's design.flow[].step use.
design_step_names := {
	"source-freeze", "simulation", "synthesis", "floorplan", "place-cts", "routing",
	"signoff", "rom-merge", "gds-stream-out", "bitstream", "release", "rebuild", "other",
}

att(step) := sprintf("att/design-%d-%s.intoto.json", [i, step]) if {
	some i, s in design_steps
	s == step
} else := sprintf("att/design-%s.intoto.json", [step])

release_path := att("release")

design_claim := lib.track_claim("DESIGN")

# The required steps' statements that open as flow-platform records.
stmts[step] := lib.stmt(att(step)) if {
	some step in required
	lib.opened(att(step), "flow-platform", lib.design_flow)
}

rel := lib.stmt(release_path) if lib.opened(release_path, "tapeout-authority", lib.design_flow)

# The released artifact, and the release envelope the lot's records name.
final := lib.first_subject(rel)

release_rd := lib.env_rd(release_path)

deny contains msg if some msg in lib.claim_errors("design", ["DESIGN"])

deny contains msg if some msg in lib.unchecked_claim_errors(["DESIGN"])

deny contains msg if some msg in lib.trust_root_errors

deny contains "policy: design.requiredSteps lists no step" if count(required) == 0

# Design steps

deny contains msg if {
	some step in required
	msg := lib.open_error(att(step), "flow-platform", lib.design_flow)
}

deny contains sprintf("design %s: wrong buildType %s", [step, lib.build_type(s)]) if {
	some step, s in stmts
	lib.build_type(s) != lib.design_step_type(step)
}

deny contains sprintf("design %s: hwFlow.step %q is not the design step %s", [step, object.get(s, ["predicate", "hwFlow", "step"], ""), step]) if {
	some step, s in stmts
	not hwflow_step_ok(step, s)
}

hwflow_step_ok(step, s) if {
	step in design_step_names
	s.predicate.hwFlow.step == step
}

deny contains msg if {
	some step, s in stmts
	msg := lib.provenance_error(sprintf("design %s", [step]), s)
}

deny contains msg if {
	some step, s in stmts
	msg := lib.gate_error(sprintf("design %s", [step]), s, "hwFlow")
}

deny contains msg if {
	some step, s in stmts
	some msg in lib.subject_file_errors(sprintf("design %s", [step]), s)
}

deny contains sprintf("design %s: tool %s is not on the approved list", [step, t.name]) if {
	some step, s in stmts
	some t in object.get(s, ["predicate", "hwFlow", "tools"], [])
	not t.name in object.get(pol, "allowedTools", [])
}

deny contains msg if {
	some step, s in stmts
	some msg in network_errors(sprintf("design %s", [step]), s, object.get(pol, "network", {}))
}

deny contains msg if {
	some step in required
	some consumed in object.get(pol, ["consumes", step], [])
	msg := consume_error(step, consumed)
}

consume_error(step, consumed) := sprintf("design %s: consumes %s, which the policy does not require before it", [step, consumed]) if {
	not required_before(consumed, step)
} else := msg if {
	msg := lib.link_error(sprintf("design %s", [step]), stmts[step], stmts[consumed].subject, sprintf("%s subject", [consumed]))
}

required_before(a, b) if {
	some i, x in required
	x == a
	some j, y in required
	y == b
	i < j
}

# Release

deny contains msg if msg := lib.open_error(release_path, "tapeout-authority", lib.design_flow)

deny contains "design release: wrong buildType" if lib.build_type(rel) != lib.design_step_type("release")

deny contains msg if msg := lib.provenance_error("design release", rel)

deny contains msg if msg := lib.gate_error("design release", rel, "hwFlow")

deny contains msg if some msg in lib.subject_file_errors("design release", rel)

deny contains msg if {
	msg := lib.link_error("design release", rel, [lib.env_rd(att(step)) | some step in required], "step attestation")
}

deny contains sprintf("design release: released artifact is not an output of %s", [from]) if {
	rel
	from := object.get(pol, "finalArtifactFrom", "")
	not unopened_step(from)
	not final_from(from)
}

# A required step whose record did not open; its open error says why.
unopened_step(step) if {
	step in required
	not stmts[step]
}

final_from(from) if {
	some s in stmts[from].subject
	s.digest.sha256 == final.digest.sha256
}

# Design L2 (spec, "Core requirements"): the policy makes the check verify a
# signed, reviewed source freeze and signed provenance for every IP block the
# release lists.
deny contains sprintf("policy claims Design L%d but does not require a signed, reviewed source freeze", [design_claim]) if {
	design_claim >= 2
	not l2_source_rules
}

l2_source_rules if {
	pol.source.tagSigner != ""
	pol.source.reviewer != ""
}

deny contains sprintf("policy claims Design L%d but does not require signed provenance for IP block %s", [design_claim, ip.name]) if {
	design_claim >= 2
	some ip in object.get(rel, ["predicate", "buildDefinition", "externalParameters", "ipBlocks"], [])
	not ip.name in {x.name | some x in object.get(pol, "thirdPartyIP", [])}
}

# Design L2: the source freeze

source_rules := pol.source if "source-freeze" in required

freeze := stmts["source-freeze"] if source_rules

git_dir := "artifacts/source-git"

tag_file := lib.files[concat("/", [git_dir, "tag"])]

commit_file := lib.files[concat("/", [git_dir, "commit"])]

tree_file := lib.files[concat("/", [git_dir, "tree"])]

commit_id := commit_file.gitObject.id

deny contains sprintf("source tag: %s object is missing from the bundle", [name]) if {
	freeze
	some name in ["tag", "commit", "tree"]
	not lib.files[concat("/", [git_dir, name])]
}

# The tag's SSH signature was checked by ssh-keygen against the tag
# signer's keys in the trust root.
deny contains sprintf("source tag: no valid signature from role '%s'", [source_rules.tagSigner]) if {
	freeze
	tag_file
	not source_rules.tagSigner in object.get(tag_file, "sshSignedBy", [])
}

deny contains sprintf("source tag %s points at a different commit", [git_header(tag_file.text, "tag")]) if {
	freeze
	not tag_names_commit
}

tag_names_commit if {
	git_header(tag_file.text, "type") == "commit"
	git_header(tag_file.text, "object") == commit_id
}

deny contains sprintf("source commit %s: tree object does not match", [commit_id]) if {
	freeze
	git_header(commit_file.text, "tree") != tree_file.gitObject.id
}

# git_header is the first value of a header line of a git commit or tag.
git_header(raw, key) := vals[0] if {
	head := split(raw, "\n\n")[0]
	prefix := concat("", [key, " "])
	vals := [substring(line, count(prefix), -1) | some line in split(head, "\n"); startswith(line, prefix)]
}

ident_email(ident) := lower(trim_space(split(split(ident, "<")[1], ">")[0])) if contains(ident, "<")

else := ""

# Reviews: every source review in the bundle is signed by a key of the
# reviewer role, approves the tagged commit and is not by its author; no two
# share a key or a reviewer; at least design.source.minReviewers approve.
review_paths := sort([p |
	some p, _ in lib.files
	review_file(p)
])

review_file("att/source-review.intoto.json")

review_file(p) if {
	startswith(p, "att/source-review-")
	endswith(p, ".intoto.json")
}

reviews[p] := lib.stmt(p) if {
	freeze
	some p in review_paths
	lib.opened(p, source_rules.reviewer, lib.source_review_type)
}

deny contains "missing attestation source-review.intoto.json" if {
	freeze
	count(review_paths) == 0
}

deny contains msg if {
	freeze
	some p in review_paths
	msg := lib.open_error(p, source_rules.reviewer, lib.source_review_type)
}

deny contains sprintf("source review covers a different commit than tag %s", [git_header(tag_file.text, "tag")]) if {
	some _, r in reviews
	object.get(r, ["subject", 0, "digest", "gitCommit"], "") != commit_id
}

deny contains sprintf("source review did not approve commit %s", [commit_id]) if {
	some _, r in reviews
	object.get(r, ["predicate", "decision"], "") != "approved"
}

deny contains "source review: reviewer is the commit's author" if {
	some _, r in reviews
	ident_email(object.get(r, ["predicate", "reviewer"], "")) == ident_email(git_header(commit_file.text, "author"))
}

deny contains sprintf("source review %s is signed with the same %s key as %s; each review needs its reviewer's own key", [lib.base(b), source_rules.reviewer, lib.base(a)]) if {
	some a, _ in reviews
	some b, _ in reviews
	a < b
	count({k | some k in lib.files[a].envelope.keys} & {k | some k in lib.files[b].envelope.keys}) > 0
}

deny contains sprintf("source review %s is by %s, who also signed %s", [lib.base(b), ident_email(rb.predicate.reviewer), lib.base(a)]) if {
	some a, ra in reviews
	some b, rb in reviews
	a < b
	ident_email(ra.predicate.reviewer) == ident_email(rb.predicate.reviewer)
}

min_reviewers := max({1, object.get(source_rules, "minReviewers", 1)})

deny contains sprintf("source review: %d reviewer(s) approved commit %s; the policy requires %d (design.source.minReviewers)", [count(reviews), commit_id, min_reviewers]) if {
	freeze
	count(review_paths) > 0
	count(reviews) < min_reviewers
}

# IP: each required block's vendor provenance is signed by its signer role,
# and the archive carries exactly the files the vendor released.
archive := lib.files[concat("/", ["artifacts", freeze.subject[0].name])]

ip_path(name) := sprintf("att/ip-%s.intoto.json", [name])

ips[name] := lib.stmt(ip_path(name)) if {
	freeze
	some ip in object.get(pol, "thirdPartyIP", [])
	name := ip.name
	lib.opened(ip_path(name), ip.signer, lib.slsa_provenance)
}

deny contains msg if {
	freeze
	some ip in object.get(pol, "thirdPartyIP", [])
	msg := lib.open_error(ip_path(ip.name), ip.signer, lib.slsa_provenance)
}

deny contains msg if {
	some name, s in ips
	msg := lib.provenance_error(sprintf("ip %s", [name]), s)
}

deny contains sprintf("ip %s: %s in %s does not match the vendor's signed provenance", [ip.name, f, freeze.subject[0].name]) if {
	some ip in object.get(pol, "thirdPartyIP", [])
	s := ips[ip.name]
	some f in object.get(ip, "files", [])
	not ip_file_ok(s, f)
}

ip_file_ok(s, f) if {
	some sub in s.subject
	sub.name == f
	sub.digest.sha256 == archive.members[f]
}

deny contains sprintf("design source-freeze: chain broken, resolvedDependencies do not include the tagged commit %s", [commit_id]) if {
	freeze
	not commit_id in {d.digest.gitCommit | some d in freeze.predicate.buildDefinition.resolvedDependencies}
}

deny contains msg if {
	freeze
	msg := lib.link_error("design source-freeze", freeze, [lib.env_rd(p) | some p, _ in reviews], "source review")
}

deny contains msg if {
	freeze
	msg := lib.link_error("design source-freeze", freeze, [lib.env_rd(ip_path(name)) | some name, _ in ips], "IP provenance")
}

# Design L3 (spec, "Core requirements"): every step that runs tools ran in a
# sandbox of its own, with no network beyond the policy's license servers
# and no signing key in reach, and every tool it names is pinned by digest
# on design.toolPins. The source freeze only fetches the pinned sources.
l3_steps := [step | some step in required; step != "source-freeze"] if design_claim >= 3

deny contains msg if {
	some step in l3_steps
	s := stmts[step]
	strict := object.union(object.get(pol, "network", {}), {"requireIsolation": true})
	some msg in network_errors(sprintf("Design L3: design %s", [step]), s, strict)
}

deny contains msg if {
	some step in l3_steps
	msg := isolation_error(sprintf("Design L3: design %s", [step]), stmts[step])
}

deny contains sprintf("Design L3: design %s: the record names no tool, so nothing is pinned", [step]) if {
	some step in l3_steps
	count(object.get(stmts[step], ["predicate", "hwFlow", "tools"], [])) == 0
}

deny contains msg if {
	some step in l3_steps
	some t in object.get(stmts[step], ["predicate", "hwFlow", "tools"], [])
	msg := tool_pin_error(sprintf("Design L3: design %s", [step]), t, object.get(pol, "toolPins", []))
}

isolation_error(label, s) := sprintf("%s: no hwFlow.isolation, so the record does not say the step ran isolated", [label]) if {
	not is_object(s.predicate.hwFlow.isolation)
} else := sprintf("%s: the step did not run in a fresh working directory of its own", [label]) if {
	not fresh(s.predicate.hwFlow.isolation)
} else := sprintf("%s: the signing key was within reach of the step", [label]) if {
	not key_out_of_reach(s.predicate.hwFlow.isolation)
} else := sprintf("%s: the sandbox allowed network access %q", [label, object.get(s.predicate.hwFlow.isolation, "network", "")]) if {
	not object.get(s.predicate.hwFlow.isolation, "network", "") in {"none", "license-server"}
} else := sprintf("%s: hwFlow.isolation (network %s) and hwFlow.network (mode %s) disagree", [label, s.predicate.hwFlow.isolation.network, network_mode(s)]) if {
	not network_agrees(s)
}

# The sandbox had no network exactly when the record says the step ran isolated.
network_agrees(s) if {
	s.predicate.hwFlow.isolation.network == "none"
	network_mode(s) == "isolated"
}

network_agrees(s) if {
	s.predicate.hwFlow.isolation.network != "none"
	network_mode(s) != "isolated"
}

fresh(iso) if {
	iso.freshWorkdir == true
	iso.stepsShareNoFiles == true
}

key_out_of_reach(iso) if {
	iso.signingKeyMounted == false
	iso.signedOutsideStep == true
}

# A tool is pinned when design.toolPins lists its binary digest and, where
# the pin names a package, the same package, version and package digest.
tool_pin_error(label, t, pins) := sprintf("%s: tool %s is not pinned by digest", [label, object.get(t, "name", "")]) if {
	object.get(t, ["digest", "sha256"], "") == ""
} else := sprintf("%s: tool %s is the pinned binary, but its package %s %s is not the pinned one", [label, t.name, object.get(t, ["package", "name"], ""), object.get(t, ["package", "version"], "")]) if {
	not tool_pinned(t, pins)
	some p in pins
	p.name == t.name
	p.sha256 == t.digest.sha256
} else := sprintf("%s: tool %s sha256:%s is not on the policy's pinned tool list (design.toolPins)", [label, object.get(t, "name", ""), t.digest.sha256]) if {
	not tool_pinned(t, pins)
}

tool_pinned(t, pins) if {
	some p in pins
	p.name == t.name
	p.sha256 == t.digest.sha256
	not p.package
}

tool_pinned(t, pins) if {
	some p in pins
	p.name == t.name
	p.sha256 == t.digest.sha256
	t.package.name == p.package.name
	t.package.version == p.package.version
	t.package.treeDigest.sha256 == p.package.treeDigest
}

# Design L3: an equivalence record proves the released netlist equal to the
# frozen RTL, consuming both by digest, and carries its script.
equivalence_step := object.get(pol, ["equivalence", "step"], "")

eq_label := sprintf("Design L3: design %s", [equivalence_step])

eq := stmts[equivalence_step] if design_claim >= 3

deny contains "Design L3: the policy names no equivalence record (design.equivalence.step)" if {
	design_claim >= 3
	equivalence_step == ""
}

deny contains sprintf("Design L3: the equivalence record, design %s, is not one of the policy's required steps", [equivalence_step]) if {
	design_claim >= 3
	equivalence_step != ""
	not equivalence_step in required
}

deny contains sprintf("%s: no passing rtl-netlist-equivalence check, so no record proves the netlist equal to the RTL", [eq_label]) if {
	not passing_equivalence(eq)
}

passing_equivalence(s) if {
	some c in s.predicate.hwFlow.checks
	c.name == "rtl-netlist-equivalence"
	c.result == "pass"
}

deny contains msg if msg := lib.link_error(eq_label, eq, stmts["source-freeze"].subject, "frozen source")

deny contains msg if msg := lib.link_error(eq_label, eq, [final], "released design")

deny contains msg if msg := equivalence_script_error(eq)

equivalence_script_error(s) := sprintf("%s: the record does not carry its equivalence script, so the proof cannot be run again", [eq_label]) if {
	script := object.get(s, ["predicate", "buildDefinition", "externalParameters", "script"], "")
	not script in {object.get(d, "name", "") | some d in s.predicate.buildDefinition.resolvedDependencies}
} else := sprintf("%s: the equivalence script %s in the bundle is not the one the record names", [eq_label, script]) if {
	script := s.predicate.buildDefinition.externalParameters.script
	some d in s.predicate.buildDefinition.resolvedDependencies
	d.name == script
	d.digest != {"sha256": object.get(lib.files, [concat("/", ["artifacts", script]), "sha256"], "")}
}

# Network (spec, "Network access and licensed tools"): a step reaches
# declared license servers and nothing else.
network_mode(s) := object.get(s.predicate.hwFlow.network, "mode", "") if is_object(s.predicate.hwFlow.network)

else := "open"

network_errors(label, s, net_pol) := {msg | some msg in network_errors_open(label, s, net_pol)} if {
	network_mode(s) == "open"
} else := {sprintf("%s: unknown network mode %q", [label, network_mode(s)])} if {
	not network_mode(s) in {"isolated", "license-server"}
} else := license_server_errors(label, s, net_pol)

# The policy's list of license servers is checked when the policy requires
# isolation or lists any.
checks_server_list(net_pol) if object.get(net_pol, "requireIsolation", false) == true

checks_server_list(net_pol) if "allowedLicenseServers" in object.keys(net_pol)

network_errors_open(label, _, net_pol) := {sprintf("%s: network access is open, so the step is not isolated", [label])} if {
	object.get(net_pol, "requireIsolation", false) == true
} else := set()

license_server_errors(label, s, net_pol) := errs if {
	net := s.predicate.hwFlow.network
	servers := object.get(net, "licenseServers", [])
	listed := {x.address: object.get(x, "endpoints", []) | some x in object.get(net_pol, "allowedLicenseServers", [])}
	endpoints := {ep | some sv in servers; some ep in object.get(sv, "endpoints", [])}
	addresses := {object.get(sv, "address", "") | some sv in servers}
	sent := sum([object.get(o, "bytesSent", 0) | some o in object.get(net, "observed", []); o.allowed == true])
	errs := union({
		{msg |
			network_mode(s) == "isolated"
			count(servers) > 0
			msg := sprintf("%s: isolated step declares license servers", [label])
		},
		{msg |
			network_mode(s) == "license-server"
			count(servers) == 0
			msg := sprintf("%s: license-server mode declares no license server", [label])
		},
		{msg |
			some sv in servers
			count(object.get(sv, "endpoints", [])) == 0
			msg := sprintf("%s: license server %s declares no endpoints", [label, object.get(sv, "address", "")])
		},
		{msg |
			some sv in servers
			some ep in object.get(sv, "endpoints", [])
			checks_server_list(net_pol)
			not ep in object.get(listed, object.get(sv, "address", ""), [])
			msg := sprintf("%s: license server %s endpoint %s is not on the policy's list", [label, object.get(sv, "address", ""), ep])
		},
		{msg |
			some o in object.get(net, "observed", [])
			o.allowed == true
			not object.get(o, "endpoint", "") in endpoints
			msg := sprintf("%s: connected to %s, which is not a declared license server endpoint", [label, object.get(o, "endpoint", "")])
		},
		{msg |
			some f in object.get(net, "features", [])
			not object.get(f, "server", "") in addresses
			msg := sprintf("%s: license feature %s came from undeclared server %s", [label, object.get(f, "name", ""), object.get(f, "server", "")])
		},
		{msg |
			limit := net_pol.maxBytesSent
			sent > limit
			msg := sprintf("%s: sent %d bytes to license servers, over the policy's limit of %d", [label, sent, limit])
		},
	})
}

# What the check covered, for the report, in chain order.
checked := array.concat(
	array.concat(
		[sprintf("design %s: signed by flow-platform, buildType and hwFlow.step, gates passed, file subjects match, tools on design.allowedTools, consumes %s", [step, concat_or_none(object.get(pol, ["consumes", step], []))]) | some step in required],
		[sprintf("design release: signed by tapeout-authority, links %d step envelopes by digest, releases %s, an output of %s", [count(required), final.name, object.get(pol, "finalArtifactFrom", "")]) | final],
	),
	array.concat(
		[sprintf("Design L2 source freeze: tag signed by %s (ssh-keygen), tag -> commit -> tree by git object id, %d review(s) by %s approving the commit, IP provenance signed for %s, all linked from the source freeze", [source_rules.tagSigner, count(reviews), source_rules.reviewer, concat_or_none([ip.name | some ip in object.get(pol, "thirdPartyIP", [])])]) | freeze],
		[sprintf("Design L3: %s ran isolated with every tool pinned by digest; design %s proves the netlist equal to the RTL and carries its script", [concat(", ", l3_steps), equivalence_step]) | design_claim >= 3],
	),
)

concat_or_none(list) := concat(", ", list) if count(list) > 0

else := "nothing"

report := {
	"check": "tapeout check",
	"passed": count(deny) == 0,
	"subject": sprintf("%s sha256:%s", [object.get(final, "name", "?"), object.get(final, ["digest", "sha256"], "?")]),
	"levels": object.get(input.policy, ["claims", "design"], []),
	"deny": sort(deny),
	"checked": checked,
}
