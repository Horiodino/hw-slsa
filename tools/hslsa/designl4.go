package hslsa

// Design L4 (spec, "L4 defense profile"), on top of Design L3:
//
//	a second, independently operated builder rebuilds the release from the
//	same source and tools and reaches the same final artifact, and signs a
//	rebuild record; two-person review on the source freeze; the tapeout
//	release signed with an HSM key
//
// The rebuild here is for the flows this tool runs itself (the PicoRV32
// netlist and the FPGA bitstream); the OpenLane 2 example has its own
// (openlane.go, CheckRebuild). Waivers need no rule of their own: the
// reference tool accepts none, so a failed gate stops the tapeout check at
// every level.

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DesignRebuildAtt is the second builder's rebuild record in a design bundle.
	DesignRebuildAtt = "design-rebuild.intoto.json"
	// RebuilderRole signs rebuild records.
	RebuilderRole = "rebuilder"
)

// designRebuildSteps are the steps a rebuild re-runs to reach the final
// artifact: the PicoRV32 flow's synthesis makes its netlist; the FPGA flow
// synthesizes, places and routes, and packs the bitstream. Simulation and
// signoff make no part of the artifact, so a rebuild does not repeat them.
func designRebuildSteps(lock Obj) []string {
	if O(lock, "release") != nil {
		return []string{"synthesis", "routing", "bitstream"}
	}
	return []string{"synthesis"}
}

func runDesignStep(step, bundle, lockPath, key string, isolate bool, fpga bool) error {
	if !fpga {
		return Synthesis(bundle, lockPath, key, isolate)
	}
	run := map[string]func(string, string, string) error{"synthesis": FPGASynthesis, "routing": FPGARouting, "bitstream": FPGABitstream}
	return run[step](bundle, lockPath, key)
}

// DesignRebuild is the second builder. From the lock alone it fetches the
// pinned sources and freezes them as the flow did, re-runs the steps that
// make the final artifact in a bundle of its own, and compares what it got
// with the release in bundle. It signs a rebuild record with key and writes
// it to out: its subject is the released artifact, its dependencies the
// release record, the source archive and the tools it ran, and its checks
// say whether the two artifacts are the same. The builder id is whatever
// HSLSA_BUILDER_ID says, which must not be the flow's.
func DesignRebuild(bundle, lockPath, key, cache, out string, isolate bool) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	relPath := filepath.Join(bundle, "att", AttName("release"))
	rel, err := DecodeEnvelope(relPath)
	if err != nil {
		return err
	}
	final := firstSubject(rel)
	relRD, err := fileRD(relPath, "att/"+AttName("release"))
	if err != nil {
		return err
	}
	relRD["annotations"] = Obj{"kind": "release"}

	work, err := os.MkdirTemp("", "hslsa-rebuild-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	tmp := filepath.Join(work, "bundle")
	art := filepath.Join(tmp, "artifacts")
	if err := os.MkdirAll(filepath.Join(tmp, "att"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(art, 0o755); err != nil {
		return err
	}
	// The rebuilder's own copy of the source, from the pinned upstream.
	if _, err := fetchSources(lock, cache); err != nil {
		return err
	}
	if err := DeterministicTar(cache, sortedKeys(O(lock, "source", "files")), filepath.Join(art, "source.tar")); err != nil {
		return err
	}
	source, err := fileRD(filepath.Join(art, "source.tar"), "source.tar")
	if err != nil {
		return err
	}
	source["annotations"] = Obj{"kind": "source"}
	// The step records the rebuild makes on the way stay in its own bundle,
	// signed with a key that exists only for this run.
	if _, err := Keygen(work, "scratch"); err != nil {
		return err
	}
	scratch := filepath.Join(work, "scratch.key.pem")
	fpga := O(lock, "release") != nil
	steps := designRebuildSteps(lock)
	var tools []Obj
	var isolation Obj
	seen := map[string]bool{}
	for _, step := range steps {
		if err := runDesignStep(step, tmp, lockPath, scratch, isolate, fpga); err != nil {
			return fmt.Errorf("rebuild: %s: %w", step, err)
		}
		stmt, err := DecodeEnvelope(filepath.Join(tmp, "att", AttName(step)))
		if err != nil {
			return err
		}
		for _, t := range Objs(stmt, "predicate", "hwFlow", "tools") {
			if !seen[S(t, "name")] {
				seen[S(t, "name")] = true
				tools = append(tools, t)
			}
		}
		if iso := O(stmt, "predicate", "hwFlow", "isolation"); iso != nil && isolation == nil {
			isolation = iso
		}
	}
	rebuilt, err := fileRD(filepath.Join(art, S(final, "name")), "")
	if err != nil {
		return fmt.Errorf("rebuild: the steps made no %s: %w", S(final, "name"), err)
	}
	same := S(rebuilt, "digest", "sha256") == S(final, "digest", "sha256")
	deps := []Obj{relRD, source}
	for _, t := range tools {
		d := Obj{"name": get(t, "name"), "digest": get(t, "digest"), "annotations": Obj{"kind": "tool"}}
		deps = append(deps, d)
	}
	detail := "sha256:" + S(rebuilt, "digest", "sha256")
	pred := designPredicate("rebuild",
		Obj{"design": S(lock, "design"), "rebuilt": "att/" + AttName("release"), "steps": anyStrings(steps)},
		deps, tools,
		[]Obj{
			check("gds-bit-exact", same, detail),
			// The netlist and the bitstream carry no timestamps, so equal
			// ignoring timestamps is equal.
			check("gds-equal-ignoring-timestamps", same, detail),
		},
		[]Obj{{"name": "rebuild/" + S(final, "name"), "digest": get(rebuilt, "digest")}}, started)
	if isolation != nil {
		O(pred, "hwFlow")["isolation"] = isolation
		O(pred, "hwFlow")["network"] = IsolatedNetwork()
	}
	stmt, err := statement([]Obj{final}, DesignFlow, pred)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, out); err != nil {
		return err
	}
	if !same {
		fmt.Printf("rebuild: %s differs: released sha256:%s, rebuilt sha256:%s (recorded in %s)\n", S(final, "name"),
			short(S(final, "digest", "sha256")), short(S(rebuilt, "digest", "sha256")), filepath.Base(out))
		return nil
	}
	fmt.Printf("rebuild: %s is bit for bit the released one, sha256:%s, after re-running %s\n", S(final, "name"), short(S(final, "digest", "sha256")), pyList(anyStrings(steps)))
	return nil
}

// checkDesignRebuild accepts the rebuild record of a design bundle's release
// (rel, its final artifact final) when, as the spec's rebuild record asks:
// it is signed by a rebuilder whose key no design house role holds and whose
// enrollment names another organization than the flow platform's and the
// tapeout authority's; its builder id ran none of the flow's steps; its
// subject is the released artifact and it names this release; it rebuilt
// from the frozen source and with the tools the flow's records name; and the
// check the policy asks for (design.rebuild.require, gds-bit-exact by
// default) passed. It returns the record's envelope reference.
func checkDesignRebuild(bundle string, trust *TrustRoot, policy Obj, final Obj, label string) (Obj, error) {
	path := filepath.Join(bundle, "att", DesignRebuildAtt)
	require := S(policy, "design", "rebuild", "require")
	if require == "" {
		require = "gds-bit-exact"
	}
	if !contains(RebuildChecks, require) {
		return nil, fmt.Errorf("design.rebuild.require: unknown check %q (want one of %s)", require, pyList(anyStrings(RebuildChecks)))
	}
	if !fileExists(path) {
		return nil, failf("%s: no rebuild record (%s) from a second builder", label, DesignRebuildAtt)
	}
	stmt, err := trust.Open(path, RebuilderRole, DesignFlow)
	if err != nil {
		return nil, err
	}
	if err := asSLSAProvenance(stmt, label+": rebuild"); err != nil {
		return nil, err
	}
	if buildType(stmt) != designStepType("rebuild") || S(stmt, "predicate", "hwFlow", "step") != "rebuild" {
		return nil, failf("%s: %s is not a rebuild record", label, DesignRebuildAtt)
	}
	if err := independentOf(trust, path, RebuilderRole, []string{"flow-platform", "tapeout-authority"}, label+": the rebuild"); err != nil {
		return nil, err
	}
	rel, err := trust.Open(filepath.Join(bundle, "att", AttName("release")), "tapeout-authority", DesignFlow)
	if err != nil {
		return nil, err
	}
	id := S(stmt, "predicate", "runDetails", "builder", "id")
	ran := map[string]Obj{}
	for _, d := range Objs(rel, "predicate", "buildDefinition", "resolvedDependencies") {
		step := attStep(S(d, "name"))
		if step == "" {
			continue
		}
		rec, err := trust.Open(filepath.Join(bundle, "att", AttName(step)), "flow-platform", DesignFlow)
		if err != nil {
			return nil, err
		}
		ran[step] = rec
	}
	for _, rec := range append(mapValues(ran), rel) {
		if S(rec, "predicate", "runDetails", "builder", "id") == id {
			return nil, failf("%s: the rebuild ran on builder %s, which also ran the flow; it needs a second builder", label, id)
		}
	}
	if !jsonEqual(get(firstSubject(stmt), "digest"), get(final, "digest")) || S(firstSubject(stmt), "name") != S(final, "name") {
		return nil, failf("%s: the rebuild record is for another artifact than the released %s", label, S(final, "name"))
	}
	kinds := map[string][]Obj{}
	for _, d := range Objs(stmt, "predicate", "buildDefinition", "resolvedDependencies") {
		k := S(d, "annotations", "kind")
		kinds[k] = append(kinds[k], d)
	}
	if len(kinds["release"]) != 1 || !jsonEqual(get(kinds["release"][0], "digest"), fileDigest(filepath.Join(bundle, "att", AttName("release")))) {
		return nil, failf("%s: the rebuild record does not name this release", label)
	}
	freeze := ran["source-freeze"]
	if freeze == nil {
		return nil, failf("%s: the release names no source freeze to compare the rebuild's source with", label)
	}
	if len(kinds["source"]) != 1 || !jsonEqual(get(kinds["source"][0], "digest"), get(firstSubject(freeze), "digest")) {
		return nil, failf("%s: the rebuild did not build from the frozen source", label)
	}
	// The same tools: every tool the re-run steps' records name, and no other.
	want := map[string]string{}
	for _, step := range Strs(stmt, "predicate", "buildDefinition", "externalParameters", "steps") {
		rec := ran[step]
		if rec == nil {
			return nil, failf("%s: the rebuild re-ran %s, which the release does not name", label, step)
		}
		for _, t := range Objs(rec, "predicate", "hwFlow", "tools") {
			want[S(t, "name")] = S(t, "digest", "sha256")
		}
	}
	if len(want) == 0 {
		return nil, failf("%s: the rebuild names no step it re-ran", label)
	}
	got := map[string]string{}
	for _, d := range kinds["tool"] {
		got[S(d, "name")] = S(d, "digest", "sha256")
	}
	for _, name := range sortedKeys(anyStringMap(want)) {
		if got[name] != want[name] {
			return nil, failf("%s: the rebuild ran %s sha256:%s, not the flow's sha256:%s", label, name, short(got[name]), short(want[name]))
		}
	}
	if len(got) != len(want) {
		return nil, failf("%s: the rebuild ran tools the flow did not", label)
	}
	var c Obj
	for _, x := range Objs(stmt, "predicate", "hwFlow", "checks") {
		if S(x, "name") == require {
			c = x
		}
	}
	if c == nil {
		return nil, failf("%s: the rebuild record has no %s check", label, require)
	}
	if S(c, "result") != "pass" {
		return nil, failf("%s: the rebuild did not reproduce the release: %s failed (%s)", label, require, S(c, "detail"))
	}
	return envRD(bundle, DesignRebuildAtt), nil
}

// attStep is the design step whose record an att/ reference names, if any.
func attStep(name string) string {
	for _, step := range DesignStepNames {
		if name == "att/"+AttName(step) {
			return step
		}
	}
	return ""
}

func mapValues(m map[string]Obj) []Obj {
	var out []Obj
	for _, k := range sortedKeys(anyObjMap(m)) {
		out = append(out, m[k])
	}
	return out
}

func anyObjMap(m map[string]Obj) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

func anyStringMap(m map[string]string) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

// designL4 runs the Design L4 rules over a tapeout check that passed L3. It
// returns the rebuild record, which the design VSA lists among its inputs.
func designL4(bundle string, trust *TrustRoot, policy Obj, final Obj) (Obj, error) {
	if designClaim(policy) < 4 {
		return nil, nil
	}
	label := "Design L4"
	// Two-person review: the source freeze check counted the reviews against
	// this number, and L4 needs it to be at least two.
	if n, _ := Int(policy, "design", "source", "minReviewers"); n < 2 {
		return nil, failf("%s: the policy does not require two-person source review (design.source.minReviewers: 2)", label)
	}
	if err := keyInHSM(trust, filepath.Join(bundle, "att", AttName("release")), "tapeout-authority", label+": the tapeout release"); err != nil {
		return nil, err
	}
	return checkDesignRebuild(bundle, trust, policy, final, label)
}

// independentOf requires that the key of role that signed the record at path
// is enrolled, holds no other role in the trust root, and is enrolled under
// another organization than every key of the roles it must be independent
// of. Records cannot show who operates a key; the buyer's enrollment, made
// after checking, is what says so.
func independentOf(trust *TrustRoot, path, role string, of []string, what string) error {
	k, err := trust.SignerKey(path, role)
	if err != nil {
		return err
	}
	for _, other := range sortedKeys(anyRoles(trust.Roles)) {
		if other == role {
			continue
		}
		for _, o := range trust.Roles[other] {
			if o.ID == k.ID {
				return failf("%s is signed by %s key %s, which is also the trust root's %s key; L4 needs a party of its own", what, role, short(k.ID), other)
			}
		}
	}
	e := trust.Enrolled[k.ID]
	if e == nil {
		return failf("%s is signed by %s key %s, which the trust root lists without an enrollment; L4 needs a buyer-run trust root that records each key's organization (hslsa pilot trust-root)", what, role, short(k.ID))
	}
	org := S(e, "organization", "id")
	for _, r := range of {
		for _, o := range trust.Roles[r] {
			oe := trust.Enrolled[o.ID]
			if oe == nil {
				return failf("%s: the %s key %s has no enrollment, so nothing shows the two are different organizations; L4 needs a buyer-run trust root (hslsa pilot trust-root)", what, r, short(o.ID))
			}
			if S(oe, "organization", "id") == org {
				return failf("%s is signed by %s of %s, the organization that holds the %s key; L4 needs an independent party", what, role, S(e, "organization", "name"), r)
			}
		}
	}
	return nil
}

func anyRoles(m map[string][]Key) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}
