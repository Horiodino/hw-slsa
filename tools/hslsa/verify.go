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
}

// LotCheck verifies F1 to F4, any transfers between them (all of them when
// the policy's manufacturing.requireTransfers is set) and the HBOM against
// the design, and that every received unit is in the shipped lot (units may
// be nil).
func LotCheck(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, units []string) (*LotResult, error) {
	art := filepath.Join(bundle, "artifacts")
	gaps, notRecorded := chipGaps(bundle, policy)
	if err := gapError("lot receipt check", gaps); err != nil {
		return nil, err
	}
	stmts := map[string]Obj{}
	var transfers []Obj
	prev := design.Release
	for i, step := range MfgSteps {
		label := step
		stmt, err := trust.Open(filepath.Join(bundle, "att", MfgAtt[step]), MfgSigner[step], MfgStep)
		if err != nil {
			return nil, err
		}
		if buildType(stmt) != mfgStepType(step) {
			return nil, failf("%s: wrong buildType", label)
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
			t, err := transferCheck(bundle, trust, design, MfgSteps[i-1], stmts, stmt, prev)
			if err != nil {
				return nil, err
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

	// Genealogy: every packaged unit came from a passing die of this wafer lot, each die used once.
	waferLot := firstSubject(stmts["wafer-fab"])
	maps, err := ReadObj(filepath.Join(art, "wafer-maps.json"))
	if err != nil {
		return nil, failf("wafer-sort: wafer maps: %v", err)
	}
	if S(maps, "waferLot") != S(waferLot, "name") {
		return nil, failf("wafer-sort: wafer maps name a different wafer lot")
	}
	good := map[string]bool{}
	for _, d := range Objs(maps, "dies") {
		if S(d, "bin") == "pass" {
			good[dieKey(d["wafer"], d["x"], d["y"])] = true
		}
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
		if S(g, "waferLot") != S(waferLot, "name") || !good[die] || used[die] {
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
	return &LotResult{Lot: lotRD, Inputs: inputs, NotRecorded: notRecorded}, nil
}

// signVSA signs a SLSA Verification Summary Attestation for one subject.
func signVSA(subject Obj, resourceURI string, levels any, inputs []Obj, policyPath, key, out string) error {
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
	if unitsPath != "" {
		if units, err = ReadUnits(unitsPath); err != nil {
			return nil, nil, err
		}
	}
	lot, err := LotCheck(bundle, trust, policy, design, units)
	if err != nil {
		return nil, nil, err
	}
	msg := fmt.Sprintf("lot receipt check: PASSED for %s sha256:%s", S(lot.Lot, "name"), S(lot.Lot, "digest", "sha256"))
	if len(units) > 0 {
		msg += fmt.Sprintf(", %d received units found in the lot", len(units))
	}
	fmt.Println(msg)
	if len(lot.NotRecorded) > 0 {
		fmt.Printf("not recorded, and not required by the policy: %s\n", strings.Join(lot.NotRecorded, "; "))
	}
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
		if err := signVSA(lot.Lot, S(lot.Lot, "name"), claims["lot"],
			append(append([]Obj{}, lot.Inputs...), design.Release), policyPath, vsaKey,
			filepath.Join(vsaDir, "lot.vsa.intoto.json")); err != nil {
			return nil, nil, err
		}
		fmt.Printf("VSAs written to %s: design %s, lot %s\n", vsaDir, pyList(claims["design"]), pyList(claims["lot"]))
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
