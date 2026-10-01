package hslsa

// The buyer's check: walk the chain by digest, then emit a signed SLSA VSA.
//
// Implements the tapeout check and the lot receipt check from the spec section
// "Where the chain is checked". The lot receipt check first reports every
// missing or undisclosed record at once (gaps.go); after that, any failure
// returns a VerificationError naming the first broken link. Nothing is
// emitted unless every check passes.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	provenance "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// VerifierID names this verifier in every VSA it signs.
const VerifierID = "https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1"

// envRD describes att/<name> in the bundle by its path relative to the bundle.
func envRD(bundle, name string) Obj {
	return Obj{"name": "att/" + name, "digest": fileDigest(filepath.Join(bundle, "att", name))}
}

func sha256Set(rds []Obj) map[string]bool {
	out := map[string]bool{}
	for _, d := range rds {
		if s, ok := get(d, "digest", "sha256").(string); ok {
			out[s] = true
		}
	}
	return out
}

func requireLink(stmt Obj, label string, wanted []Obj, what string) error {
	have := sha256Set(Objs(stmt, "predicate", "buildDefinition", "resolvedDependencies"))
	var missing []string
	for _, w := range wanted {
		if !have[S(w, "digest", "sha256")] {
			missing = append(missing, S(w, "name"))
		}
	}
	if len(missing) > 0 {
		return failf("%s: chain broken, resolvedDependencies do not include %s %s", label, what, strings.Join(missing, ", "))
	}
	return nil
}

func requireGates(stmt Obj, label, block string) error {
	if failed := failedChecks(Objs(stmt, "predicate", block, "checks")); len(failed) > 0 {
		return failf("%s: gate failed: %s", label, strings.Join(failed, ", "))
	}
	return nil
}

// requireFiles checks every file subject is in the bundle with the attested digest.
func requireFiles(bundle string, stmt Obj, label string) error {
	for _, s := range Objs(stmt, "subject") {
		name := S(s, "name")
		if strings.HasPrefix(name, "urn:") {
			continue
		}
		d := fileDigest(filepath.Join(bundle, "artifacts", name))
		if d == nil {
			return failf("%s: subject %s is missing from the bundle", label, name)
		}
		if d["sha256"] != S(s, "digest", "sha256") {
			return failf("%s: subject %s does not match its attested digest", label, name)
		}
	}
	return nil
}

// asSLSAProvenance parses a step predicate with the SLSA Provenance v1 reference
// schema: the step predicates are supersets of it.
func asSLSAProvenance(stmt Obj, label string) error {
	var pb provenance.Provenance
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(compactJSON(get(stmt, "predicate")), &pb); err != nil {
		return failf("%s: not a valid SLSA Provenance v1 superset: %v", label, err)
	}
	if pb.GetBuildDefinition().GetBuildType() == "" || pb.GetRunDetails().GetBuilder().GetId() == "" {
		return failf("%s: SLSA Provenance v1 needs buildType and builder.id", label)
	}
	return nil
}

func buildType(stmt Obj) string { return S(stmt, "predicate", "buildDefinition", "buildType") }

func firstSubject(stmt Obj) Obj {
	if s := Objs(stmt, "subject"); len(s) > 0 {
		return s[0]
	}
	return Obj{}
}

// DesignResult is what the tapeout check vouches for.
type DesignResult struct {
	Final   Obj   // the released artifact
	Release Obj   // the release envelope
	Inputs  []Obj // the step envelopes
}

// TapeoutCheck verifies the design steps the policy requires, then (with
// release) the tapeout release over them.
func TapeoutCheck(bundle string, trust *TrustRoot, policy Obj, release bool) (*DesignResult, error) {
	if err := checkPolicyClaims(policy); err != nil {
		return nil, err
	}
	pol := O(policy, "design")
	stmts := map[string]Obj{}
	required := Strs(pol, "requiredSteps")
	allowed := Strs(pol, "allowedTools")
	for _, step := range required {
		label := "design " + step
		stmt, err := trust.Open(filepath.Join(bundle, "att", AttName(step)), "flow-platform", DesignFlow)
		if err != nil {
			return nil, err
		}
		if buildType(stmt) != designStepType(step) {
			return nil, failf("%s: wrong buildType %s", label, buildType(stmt))
		}
		if !contains(DesignStepNames, step) || S(stmt, "predicate", "hwFlow", "step") != step {
			return nil, failf("%s: hwFlow.step %q is not the design step %s", label, S(stmt, "predicate", "hwFlow", "step"), step)
		}
		if err := asSLSAProvenance(stmt, label); err != nil {
			return nil, err
		}
		if err := requireGates(stmt, label, "hwFlow"); err != nil {
			return nil, err
		}
		if err := requireFiles(bundle, stmt, label); err != nil {
			return nil, err
		}
		for _, t := range Objs(stmt, "predicate", "hwFlow", "tools") {
			if !contains(allowed, S(t, "name")) {
				return nil, failf("%s: tool %s is not on the approved list", label, S(t, "name"))
			}
		}
		if err := checkNetwork(stmt, label, pol); err != nil {
			return nil, err
		}
		for _, consumed := range Strs(pol, "consumes", step) {
			prev, ok := stmts[consumed]
			if !ok {
				return nil, failf("%s: consumes %s, which the policy does not require before it", label, consumed)
			}
			if err := requireLink(stmt, label, Objs(prev, "subject"), consumed+" subject"); err != nil {
				return nil, err
			}
		}
		if step == "source-freeze" && Has(pol, "source") {
			if err := checkSourceFreezeL2(bundle, trust, pol, stmt); err != nil {
				return nil, err
			}
		}
		stmts[step] = stmt
	}
	if !release {
		return nil, nil
	}

	label := "design release"
	rel, err := trust.Open(filepath.Join(bundle, "att", AttName("release")), "tapeout-authority", DesignFlow)
	if err != nil {
		return nil, err
	}
	if buildType(rel) != designStepType("release") {
		return nil, failf("%s: wrong buildType", label)
	}
	if err := asSLSAProvenance(rel, label); err != nil {
		return nil, err
	}
	if err := requireGates(rel, label, "hwFlow"); err != nil {
		return nil, err
	}
	if err := requireFiles(bundle, rel, label); err != nil {
		return nil, err
	}
	var stepEnvs []Obj
	for _, s := range required {
		stepEnvs = append(stepEnvs, envRD(bundle, AttName(s)))
	}
	if err := requireLink(rel, label, stepEnvs, "step attestation"); err != nil {
		return nil, err
	}
	final := firstSubject(rel)
	from := S(pol, "finalArtifactFrom")
	if !sha256Set(Objs(stmts[from], "subject"))[S(final, "digest", "sha256")] {
		return nil, failf("%s: released artifact is not an output of %s", label, from)
	}
	if err := requireDesignL2Rules(policy, rel); err != nil {
		return nil, err
	}
	if err := designL3(bundle, policy, stmts, final); err != nil {
		return nil, err
	}
	return &DesignResult{Final: final, Release: envRD(bundle, AttName("release")), Inputs: stepEnvs}, nil
}

// designClaim is the highest Design level the policy's claims name.
func designClaim(policy Obj) int { return trackClaim(policy, "DESIGN") }

// requireDesignL2Rules refuses a Design L2 or higher claim unless the policy
// makes the tapeout check verify the signed, reviewed source freeze and signed
// provenance for every IP block the release lists.
func requireDesignL2Rules(policy, rel Obj) error {
	level := designClaim(policy)
	if level < 2 {
		return nil
	}
	pol := O(policy, "design")
	if S(pol, "source", "tagSigner") == "" || S(pol, "source", "reviewer") == "" {
		return failf("policy claims Design L%d but does not require a signed, reviewed source freeze", level)
	}
	required := map[string]bool{}
	for _, ip := range Objs(pol, "thirdPartyIP") {
		required[S(ip, "name")] = true
	}
	for _, ip := range Objs(rel, "predicate", "buildDefinition", "externalParameters", "ipBlocks") {
		if !required[S(ip, "name")] {
			return failf("policy claims Design L%d but does not require signed provenance for IP block %s", level, S(ip, "name"))
		}
	}
	return nil
}

// LotResult is what the lot receipt check vouches for.
type LotResult struct {
	Lot         Obj      // the shipped lot subject
	Inputs      []Obj    // the manufacturing envelopes and the HBOM
	NotRecorded []string // optional records the bundle does not have
	OnBehalf    []string // records signed on a supplier's behalf, which hold their track at L1
	Exports     []string // records checked against the supplier exports they carry
	Simulated   []string // records made from simulated hardware, which the policy accepted
}

// LotCheck verifies F1 to F4, any transfers between them (all of them when
// the policy's manufacturing.requireTransfers is set) and the HBOM against
// the design, and that every received unit is in the shipped lot (units may
// be nil).
func LotCheck(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, units []string) (*LotResult, error) {
	return lotCheck(bundle, trust, policy, design, units, false)
}

// lotCheck is LotCheck, told whether the received units answered an
// identity challenge (ChallengeParts) or were only listed.
func lotCheck(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, units []string, challenged bool) (*LotResult, error) {
	art := filepath.Join(bundle, "artifacts")
	gaps, notRecorded := chipGaps(bundle, policy)
	if err := gapError("lot receipt check", gaps); err != nil {
		return nil, err
	}
	stmts := map[string]Obj{}
	by := map[string]string{}
	capped := map[string]string{} // track -> the first record that holds it at L1
	var transfers []Obj
	var onBehalf []string
	prev := design.Release
	for i, step := range MfgSteps {
		label := step
		stmt, kind, err := openRecord(trust, filepath.Join(bundle, "att", MfgAtt[step]), MfgSigner[step], ProxySigner[step])
		if err != nil {
			return nil, err
		}
		want := mfgStepType(step)
		if kind == ByEvidence {
			want = mfgStepType("evidence")
		}
		if buildType(stmt) != want {
			return nil, failf("%s: wrong buildType", label)
		}
		if kind != "" {
			note, err := onBehalfCheck(bundle, policy, stmt, label, step, kind)
			if err != nil {
				return nil, err
			}
			by[step] = kind
			onBehalf = append(onBehalf, note)
			if _, ok := capped[mfgTrack(step)]; !ok {
				capped[mfgTrack(step)] = step
			}
		}
		if err := asSLSAProvenance(stmt, label); err != nil {
			return nil, err
		}
		if err := requireGates(stmt, label, "hwMfg"); err != nil {
			return nil, err
		}
		if err := requireFiles(bundle, stmt, label); err != nil {
			return nil, err
		}
		if i > 0 {
			t, note, err := transferCheck(bundle, trust, policy, design, MfgSteps[i-1], stmts, stmt, prev)
			if err != nil {
				return nil, err
			}
			if note != "" {
				onBehalf = append(onBehalf, note)
				if _, ok := capped[mfgTrack(MfgSteps[i-1])]; !ok {
					capped[mfgTrack(MfgSteps[i-1])] = "the transfer from " + MfgSteps[i-1]
				}
			}
			if t != nil {
				prev = t
				transfers = append(transfers, t)
			}
		}
		if err := requireLink(stmt, label, []Obj{prev}, "previous step"); err != nil {
			return nil, err
		}
		ref := O(stmt, "predicate", "hwMfg", "designRef")
		if !jsonEqual(get(ref, "digest"), get(design.Final, "digest")) ||
			!jsonEqual(get(ref, "release", "digest"), get(design.Release, "digest")) {
			return nil, failf("%s: designRef names a different design release", label)
		}
		stmts[step] = stmt
		prev = envRD(bundle, MfgAtt[step])
	}

	exports, err := exportsCheck(bundle, policy, stmts)
	if err != nil {
		return nil, err
	}

	// Genealogy: every packaged unit came from a passing die of this wafer lot,
	// each die used once. When wafer sort left only documents, there is no
	// wafer map to check the bins against.
	waferLot := firstSubject(stmts["wafer-fab"])
	bins := by["wafer-sort"] != ByEvidence
	good := map[string]bool{}
	if bins {
		maps, err := ReadObj(filepath.Join(art, "wafer-maps.json"))
		if err != nil {
			return nil, failf("wafer-sort: wafer maps: %v", err)
		}
		if S(maps, "waferLot") != S(waferLot, "name") {
			return nil, failf("wafer-sort: wafer maps name a different wafer lot")
		}
		for _, d := range Objs(maps, "dies") {
			if S(d, "bin") == "pass" {
				good[dieKey(d["wafer"], d["x"], d["y"])] = true
			}
		}
	} else {
		onBehalf = append(onBehalf, "packaging: genealogy checked without wafer maps, since an evidence record stands in for wafer sort")
	}
	genealogyFile, err := ReadObj(filepath.Join(art, "genealogy.json"))
	if err != nil {
		return nil, failf("packaging: genealogy: %v", err)
	}
	genealogy := O(genealogyFile, "units")
	used := map[string]bool{}
	for _, unit := range sortedKeys(genealogy) {
		g := O(genealogy, unit)
		die := dieKey(get(g, "wafer"), get(g, "x"), get(g, "y"))
		if S(g, "waferLot") != S(waferLot, "name") || (bins && !good[die]) || used[die] {
			return nil, failf("packaging: genealogy for %s does not trace to a unique passing die", unit)
		}
		used[die] = true
	}

	packagedRD := firstSubject(stmts["packaging"])
	packaged, err := ReadUnits(filepath.Join(art, "packaged-lot.txt"))
	if err != nil {
		return nil, failf("packaging: packaged lot list: %v", err)
	}
	if d, err := LotDigest(packaged); err != nil || d != S(packagedRD, "digest", "sha256") || !sameSet(packaged, sortedKeys(genealogy)) {
		return nil, failf("packaging: packaged lot list does not match the attested lot digest and genealogy")
	}

	lotRD := firstSubject(stmts["final-test"])
	shipped, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return nil, failf("final-test: shipped lot list: %v", err)
	}
	if d, err := LotDigest(shipped); err != nil || d != S(lotRD, "digest", "sha256") {
		return nil, failf("final-test: shipped lot list does not match the attested lot digest")
	}
	if len(minus(shipped, packaged)) > 0 {
		return nil, failf("final-test: shipped lot contains units that were never packaged")
	}
	yld := O(stmts["final-test"], "predicate", "hwMfg", "yield")
	passedCount, _ := Int(yld, "passed")
	if !equalStrings(minus(packaged, shipped), sortedCopy(Strs(yld, "failed"))) || passedCount != int64(len(shipped)) {
		return nil, failf("final-test: yield record does not account for every packaged unit")
	}

	// HBOM: signed by the product owner, bound to the same GDS and lot, pointing at these records.
	label := "hbom"
	hb, err := trust.Open(filepath.Join(bundle, "att", "hbom.intoto.json"), "product-owner", HBOMType)
	if err != nil {
		return nil, err
	}
	if err := ValidateHBOM(get(hb, "predicate")); err != nil {
		return nil, err
	}
	// A record signed on a supplier's behalf is signed by whoever received
	// from that supplier: the site of the next step, or the product owner,
	// named in the HBOM, after final test. Then no track claims more than L1.
	for i, step := range MfgSteps {
		if by[step] == "" {
			continue
		}
		want := get(hb, "predicate", "product", "manufacturer")
		if i+1 < len(MfgSteps) {
			want = get(stmts[MfgSteps[i+1]], "predicate", "hwMfg", "site")
		}
		if signer := get(stmts[step], "predicate", "hwMfg", "proxy", "signer"); !jsonEqual(signer, want) {
			return nil, failf("%s: signed on its supplier's behalf by %s, which did not receive from it", step, S(signer, "name"))
		}
	}
	subj := map[string]any{}
	for _, s := range Objs(hb, "subject") {
		subj[S(s, "name")] = get(s, "digest")
	}
	if !jsonEqual(subj[S(design.Final, "name")], get(design.Final, "digest")) {
		return nil, failf("%s: design subject does not match the released design", label)
	}
	if !jsonEqual(subj[S(lotRD, "name")], get(lotRD, "digest")) {
		return nil, failf("%s: lot subject does not match the final test shipped lot", label)
	}
	m := O(hb, "predicate", "manufacturing")
	tests := Objs(m, "test")
	if len(tests) < 2 {
		return nil, failf("%s: manufacturing.test does not list wafer sort and final test", label)
	}
	type ref struct {
		ref  Obj
		step string
	}
	refs := []ref{
		{O(m, "fab", "attestationRef"), "wafer-fab"},
		{O(m, "assembly", "attestationRef"), "packaging"},
		{O(tests[0], "resultsRef"), "wafer-sort"},
		{O(tests[1], "resultsRef"), "final-test"},
	}
	for _, f := range Objs(hb, "predicate", "design", "flow") {
		refs = append(refs, ref{O(f, "provenanceRef"), ""})
	}
	for _, r := range refs {
		name := strings.TrimPrefix(S(r.ref, "uri"), "file:att/")
		if r.step != "" && name != MfgAtt[r.step] {
			return nil, failf("%s: reference for %s points at %s", label, r.step, name)
		}
		if !jsonEqual(fileDigest(filepath.Join(bundle, "att", name)), get(r.ref, "digest")) {
			return nil, failf("%s: reference to %s does not match its digest", label, name)
		}
	}

	if err := capAtL1(policy, capped); err != nil {
		return nil, err
	}
	if err := chipL3(bundle, trust, policy, design, stmts, units, challenged); err != nil {
		return nil, err
	}

	for _, unit := range units {
		if !contains(shipped, unit) {
			return nil, failf("received unit %s is not in the shipped lot", unit)
		}
	}
	var inputs []Obj
	for _, s := range MfgSteps {
		inputs = append(inputs, envRD(bundle, MfgAtt[s]))
	}
	inputs = append(inputs, transfers...)
	inputs = append(inputs, envRD(bundle, "hbom.intoto.json"))
	sim, err := simulatedCheck(bundle, policy, inputs, "lot receipt check")
	if err != nil {
		return nil, err
	}
	return &LotResult{Lot: lotRD, Inputs: inputs, NotRecorded: notRecorded, OnBehalf: onBehalf, Exports: exports, Simulated: sim}, nil
}

// signVSA signs a SLSA Verification Summary Attestation for one subject.
func signVSA(subject Obj, resourceURI string, levels any, inputs []Obj, policyPath, key, out string) error {
	if err := checkClaimList(levels); err != nil {
		return err
	}
	policyDigest, err := sha256File(policyPath)
	if err != nil {
		return err
	}
	var in []Obj
	for _, i := range inputs {
		in = append(in, Obj{"uri": "file:" + S(i, "name"), "digest": get(i, "digest")})
	}
	predicate := Obj{
		"verifier":           Obj{"id": VerifierID},
		"timeVerified":       Now(),
		"resourceUri":        resourceURI,
		"policy":             Obj{"uri": "file:" + filepath.Base(policyPath), "digest": Obj{"sha256": policyDigest}},
		"inputAttestations":  nonNil(in),
		"verificationResult": "PASSED",
		"verifiedLevels":     levels,
	}
	stmt, err := statement([]Obj{subject}, VSAType, predicate)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	_, err = Sign(stmt, signer, out)
	return err
}

// Verify runs the tapeout and lot receipt checks, then signs VSAs when vsaKey is set.
func Verify(bundle string, trust *TrustRoot, policyPath, unitsPath, vsaKey, vsaDir string) (*DesignResult, *LotResult, error) {
	policy, err := ReadObj(policyPath)
	if err != nil {
		return nil, nil, err
	}
	design, err := TapeoutCheck(bundle, trust, policy, true)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("tapeout check: PASSED for %s sha256:%s\n", S(design.Final, "name"), S(design.Final, "digest", "sha256"))
	var units []string
	challenged := false
	if info, err := os.Stat(unitsPath); err == nil && info.IsDir() {
		if units, err = ChallengeParts(trust, unitsPath); err != nil {
			return nil, nil, err
		}
		challenged = true
	} else if unitsPath != "" {
		if units, err = ReadUnits(unitsPath); err != nil {
			return nil, nil, err
		}
	}
	lot, err := lotCheck(bundle, trust, policy, design, units, challenged)
	if err != nil {
		return nil, nil, err
	}
	msg := fmt.Sprintf("lot receipt check: PASSED for %s sha256:%s", S(lot.Lot, "name"), S(lot.Lot, "digest", "sha256"))
	switch {
	case challenged:
		msg += fmt.Sprintf(", %d received parts answered an identity challenge and are in the lot", len(units))
	case len(units) > 0:
		msg += fmt.Sprintf(", %d received units found in the lot", len(units))
	}
	fmt.Println(msg)
	if len(lot.NotRecorded) > 0 {
		fmt.Printf("not recorded, and not required by the policy: %s\n", strings.Join(lot.NotRecorded, "; "))
	}
	if len(lot.OnBehalf) > 0 {
		fmt.Println("signed on a supplier's behalf, so their tracks are held at L1:")
		for _, line := range lot.OnBehalf {
			fmt.Printf("  %s\n", line)
		}
	}
	if len(lot.Exports) > 0 {
		fmt.Println("read again from the supplier exports the records carry:")
		for _, line := range lot.Exports {
			fmt.Printf("  %s\n", line)
		}
	}
	printSimulated(lot.Simulated)
	if err := renderingsCheck(bundle, filepath.Join(bundle, "att", "hbom.intoto.json"), "hbom"); err != nil {
		return nil, nil, err
	}
	if vsaKey != "" {
		claims := O(policy, "claims")
		if err := signVSA(design.Final, "hslsa:design:"+S(design.Final, "name"), claims["design"],
			append([]Obj{design.Release}, design.Inputs...), policyPath, vsaKey,
			filepath.Join(vsaDir, "design.vsa.intoto.json")); err != nil {
			return nil, nil, err
		}
		if err := signVSA(lot.Lot, S(lot.Lot, "name"), vsaLevels(claims["lot"], len(lot.Simulated) > 0),
			append(append([]Obj{}, lot.Inputs...), design.Release), policyPath, vsaKey,
			filepath.Join(vsaDir, "lot.vsa.intoto.json")); err != nil {
			return nil, nil, err
		}
		fmt.Printf("VSAs written to %s: design %s, lot %s\n", vsaDir, pyList(claims["design"]), pyList(vsaLevels(claims["lot"], len(lot.Simulated) > 0)))
	}
	return design, lot, nil
}

// pyList formats a list of strings the way Python prints one.
func pyList(v any) string {
	var parts []string
	for _, s := range Strs(Obj{"v": v}, "v") {
		parts = append(parts, "'"+s+"'")
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// hasCheck reports whether checks hold a passing check of that name.
func hasCheck(checks []Obj, name string) bool {
	for _, c := range checks {
		if S(c, "name") == name && S(c, "result") == "pass" {
			return true
		}
	}
	return false
}

// designL3 runs the tapeout check's Design L3 rules (spec, "Core
// requirements" and "Where the chain is checked") when the policy claims
// Design L3: every step that runs tools ran in a sandbox of its own, with no
// network beyond declared license servers and no signing key in its reach;
// every tool it names is pinned by digest on the policy's list
// (design.toolPins); and an equivalence record proves the released netlist
// equal to the frozen RTL, consuming both by digest so it can be run again.
// The source freeze only fetches the pinned sources, and the release is the
// tapeout authority's decision; neither runs a design tool.
func designL3(bundle string, policy Obj, stmts map[string]Obj, final Obj) error {
	if designClaim(policy) < 3 {
		return nil
	}
	pol := O(policy, "design")
	// Isolation is required, so declared license servers must be on the policy's list (rule 4).
	strict := Obj{"network": Obj{}}
	for k, v := range O(pol, "network") {
		O(strict, "network")[k] = v
	}
	O(strict, "network")["requireIsolation"] = true
	pins := Objs(pol, "toolPins")
	for _, step := range Strs(pol, "requiredSteps") {
		if step == "source-freeze" {
			continue
		}
		stmt, label := stmts[step], "Design L3: design "+step
		if err := checkNetwork(stmt, label, strict); err != nil {
			return err
		}
		if err := isolationOK(stmt, label); err != nil {
			return err
		}
		tools := Objs(stmt, "predicate", "hwFlow", "tools")
		if len(tools) == 0 {
			return failf("%s: the record names no tool, so nothing is pinned", label)
		}
		for _, t := range tools {
			if err := toolPinned(t, pins, label); err != nil {
				return err
			}
		}
	}
	eq := S(pol, "equivalence", "step")
	if eq == "" {
		return failf("Design L3: the policy names no equivalence record (design.equivalence.step)")
	}
	stmt, ok := stmts[eq]
	if !ok {
		return failf("Design L3: the equivalence record, design %s, is not one of the policy's required steps", eq)
	}
	label := "Design L3: design " + eq
	if !hasCheck(Objs(stmt, "predicate", "hwFlow", "checks"), EquivalenceCheck) {
		return failf("%s: no passing %s check, so no record proves the netlist equal to the RTL", label, EquivalenceCheck)
	}
	if err := requireLink(stmt, label, Objs(stmts["source-freeze"], "subject"), "frozen source"); err != nil {
		return err
	}
	if err := requireLink(stmt, label, []Obj{final}, "released design"); err != nil {
		return err
	}
	// Enough to run the proof again: its script is in the bundle, by the digest the record names.
	script := S(stmt, "predicate", "buildDefinition", "externalParameters", "script")
	for _, d := range Objs(stmt, "predicate", "buildDefinition", "resolvedDependencies") {
		if S(d, "name") == script {
			if !jsonEqual(fileDigest(filepath.Join(bundle, "artifacts", script)), get(d, "digest")) {
				return failf("%s: the equivalence script %s in the bundle is not the one the record names", label, script)
			}
			return nil
		}
	}
	return failf("%s: the record does not carry its equivalence script, so the proof cannot be run again", label)
}
