package hslsa

// Physical inspection, the L4 defense profile of the manufacturing tracks
// (spec, "L4 defense profile" and "Limits of physical inspection"):
//
//	Wafer         named regions of sampled die are delayered, imaged and
//	              compared against the signed design by an independent lab
//	Package/Test  sampled units are decapsulated and X-rayed, and each die is
//	              matched to its genealogy and the signed design
//	Assembly      sampled boards are X-rayed and their components
//	              authenticated, checked against the board HBOM
//
// The lab commits to a random seed before the lot is sealed: it signs a
// commitment that names the lot and carries the seed's digest, and the step
// that seals the lot (final test for a chip lot, board assembly for a board
// lot) consumes it, so the commitment provably existed before the producer
// knew which units the lot holds. After the lot ships the lab reveals the
// seed, draws its sample from it (each unit ranked by
// sha256(seed || 0x00 || unit), lowest first), inspects those units and
// signs an inspection record. A verifier draws the sample again from the
// seed and the lot, so neither side can steer which units are inspected.
//
// The lab is simulated here, as the parts are: it reads a sampled die's
// layout fingerprint (the design digest its DICE engine measures) and its
// identity from the part's die.json, and a board's placements from its
// board.json. Delayering and decapsulation destroy the sample, so the lab
// removes those parts; X-ray and component authentication do not.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// InspectionCommitmentType is the lab's commitment to its sampling seed.
	InspectionCommitmentType = NS + "/inspection-commitment/v0.1"
	// InspectionType is the lab's inspection record.
	InspectionType = NS + "/physical-inspection/v0.1"
	// InspectionLabRole signs commitments and inspection records.
	InspectionLabRole = "inspection-lab"
	// InspectionCommitmentAtt and InspectionAtt are their files in a bundle.
	InspectionCommitmentAtt = "inspection-commitment.intoto.json"
	InspectionAtt           = "inspection.intoto.json"
	// SampleMethod names how a sample is drawn from the seed.
	SampleMethod = "hslsa-seeded-sample/v1"
	// BoardPhysical is a built board's own description of what is on it, in
	// its directory: the physical board the lab X-rays, not a record.
	BoardPhysical = "board.json"
)

// The checks every sample must pass, by track.
var inspectionChecks = map[string][]string{
	"WAFER":        {"layout-matches-release"},
	"PACKAGE_TEST": {"package-xray", "die-matches-genealogy"},
	"ASSEMBLY":     {"x-ray-matches-hbom", "components-authenticated"},
}

// seedRank is a unit's place in the sample a seed draws: lowest first.
func seedRank(seed []byte, unit string) string {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte{0})
	h.Write([]byte(unit))
	return hex.EncodeToString(h.Sum(nil))
}

// SeededSample draws n units from a lot with a seed: every unit ranked by
// sha256(seed || 0x00 || unit), the n lowest. A lot of n or fewer is sampled whole.
func SeededSample(seed []byte, units []string, n int) []string {
	ranked := append([]string{}, units...)
	sort.Slice(ranked, func(i, j int) bool { return seedRank(seed, ranked[i]) < seedRank(seed, ranked[j]) })
	if n < len(ranked) {
		ranked = ranked[:n]
	}
	return ranked
}

func seedDigest(seed []byte) string { return sha256Bytes(seed) }

// InspectionCommit is the lab's commitment, made before the lot is sealed: it
// draws a fresh seed, writes it to seedOut for the lab alone, and signs a
// commitment to the lot named lotURN under the plan (the sample size and
// the tracks it serves) with the lab's key. The party that seals the lot
// puts the commitment in its bundle and consumes it.
func InspectionCommit(planPath, lotURN, key, seedOut, out string) error {
	plan, err := ReadObj(planPath)
	if err != nil {
		return err
	}
	n, _ := Int(plan, "sampleSize")
	if n < 1 || S(plan, "lab", "name") == "" || len(Strs(plan, "tracks")) == 0 {
		return fmt.Errorf("%s: an inspection plan names the lab (lab.name), the tracks it serves and a sample size", planPath)
	}
	if !strings.HasPrefix(lotURN, "urn:hslsa:lot:") {
		lotURN = "urn:hslsa:lot:" + lotURN
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(seedOut), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(seedOut, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return err
	}
	stmt, err := statement([]Obj{rd("urn:hslsa:inspection-commitment:"+strings.TrimPrefix(lotURN, "urn:hslsa:lot:"), seedDigest(seed))}, InspectionCommitmentType, Obj{
		"lab":            get(plan, "lab"),
		"lot":            lotURN,
		"tracks":         get(plan, "tracks"),
		"plan":           Obj{"method": SampleMethod, "sampleSize": n},
		"seedCommitment": Obj{"sha256": seedDigest(seed)},
		"committedAt":    Now(),
	})
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
	fmt.Printf("inspection commitment: %s commits to a seed for %s, %d samples\n", S(plan, "lab", "name"), lotURN, n)
	return nil
}

// consumeCommitment is what the party that seals a lot does with the lab's
// commitment: checks it names this lot, puts it in the bundle and returns
// the dependency its record adds. An empty path removes a stale one.
func consumeCommitment(bundle, path, lotURN string) (Obj, error) {
	dst := filepath.Join(bundle, "att", InspectionCommitmentAtt)
	if path == "" {
		return nil, removeStale(dst)
	}
	c, err := DecodeEnvelope(path)
	if err != nil {
		return nil, fmt.Errorf("inspection commitment: %w", err)
	}
	if S(c, "predicateType") != InspectionCommitmentType || S(c, "predicate", "lot") != lotURN {
		return nil, fmt.Errorf("inspection commitment %s is not a commitment for %s", path, lotURN)
	}
	if err := copyFile(path, dst); err != nil {
		return nil, err
	}
	return fileRD(dst, "att/"+InspectionCommitmentAtt)
}

func readSeed(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(b)))
}

// inspectionRun is what both labs share: the plan, the revealed seed checked
// against the commitment in the bundle, and the sample it draws.
type inspectionRun struct {
	plan, commitment Obj
	seed             []byte
	sample           []string
}

func startInspection(bundle, planPath, seedPath string, lot Obj, units []string) (*inspectionRun, error) {
	plan, err := ReadObj(planPath)
	if err != nil {
		return nil, err
	}
	if err := checkSimulated(O(plan, "simulated"), planPath); err != nil {
		return nil, err
	}
	seed, err := readSeed(seedPath)
	if err != nil {
		return nil, fmt.Errorf("inspection seed: %w", err)
	}
	c, err := DecodeEnvelope(filepath.Join(bundle, "att", InspectionCommitmentAtt))
	if err != nil {
		return nil, fmt.Errorf("the bundle holds no inspection commitment: %w", err)
	}
	if S(c, "predicate", "seedCommitment", "sha256") != seedDigest(seed) {
		return nil, fmt.Errorf("the seed is not the one the commitment in the bundle names")
	}
	if S(c, "predicate", "lot") != S(lot, "name") {
		return nil, fmt.Errorf("the commitment is for %s, not %s", S(c, "predicate", "lot"), S(lot, "name"))
	}
	n, _ := Int(c, "predicate", "plan", "sampleSize")
	return &inspectionRun{plan: plan, commitment: c, seed: seed, sample: SeededSample(seed, units, int(n))}, nil
}

// sign writes the inspection record: the lot and every sampled unit or
// board as subjects, and the hwInspection block.
func (r *inspectionRun) sign(bundle string, lot Obj, size int, design Obj, unitSubjects []Obj, samples []Obj, key string) error {
	hw := Obj{
		"lab":         get(r.plan, "lab"),
		"tracks":      get(r.plan, "tracks"),
		"lot":         Obj{"id": S(lot, "name"), "digest": get(lot, "digest"), "size": size},
		"designRef":   design,
		"commitment":  relRD(bundle, "att/"+InspectionCommitmentAtt),
		"seed":        hex.EncodeToString(r.seed),
		"plan":        get(r.commitment, "predicate", "plan"),
		"technique":   get(r.plan, "technique"),
		"regions":     get(r.plan, "regions"),
		"layers":      get(r.plan, "layers"),
		"destructive": Truthy(get(r.plan, "destructive")),
		"samples":     samples,
		"inspectedAt": Now(),
	}
	stmt, err := statement(append([]Obj{lot}, unitSubjects...), InspectionType, Obj{"hwInspection": markSimulated(hw, O(r.plan, "simulated"))})
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", InspectionAtt)); err != nil {
		return err
	}
	failed := 0
	for _, s := range samples {
		if S(s, "result") != "pass" {
			failed++
		}
	}
	fmt.Printf("inspection: %s inspected %d of %d in %s, %d failed\n", S(r.plan, "lab", "name"), len(samples), size, S(lot, "name"), failed)
	return nil
}

func sampleResult(checks []Obj) string {
	if len(failedChecks(checks)) > 0 {
		return "fail"
	}
	return "pass"
}

// InspectLot is the lab inspecting a shipped chip lot: it draws the sample
// from the seed, then for each unit takes the part from parts (by its marked
// serial), images the die's layout and compares it with the released design
// (Wafer), X-rays the package and matches the die to the genealogy's wafer
// and position and the identity wafer sort gave it (Package/Test). The
// sampled parts are destroyed.
func InspectLot(bundle, parts, planPath, seedPath, key string) error {
	art := filepath.Join(bundle, "artifacts")
	f4, err := DecodeEnvelope(filepath.Join(bundle, "att", MfgAtt["final-test"]))
	if err != nil {
		return err
	}
	lot := firstSubject(f4)
	units, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return err
	}
	r, err := startInspection(bundle, planPath, seedPath, lot, units)
	if err != nil {
		return err
	}
	rel, err := DecodeEnvelope(filepath.Join(bundle, "att", AttName("release")))
	if err != nil {
		return err
	}
	design := firstSubject(rel)
	gen, err := ReadObj(filepath.Join(art, "genealogy.json"))
	if err != nil {
		return err
	}
	ids, err := ReadObj(filepath.Join(art, DieIdentities))
	if err != nil {
		return err
	}
	byDie := map[string]Obj{}
	for _, e := range Objs(ids, "dies") {
		byDie[dieKey(e["wafer"], e["x"], e["y"])] = e
	}
	tracks := Strs(r.plan, "tracks")
	var samples, subjects []Obj
	for _, unit := range r.sample {
		g := O(gen, "units", unit)
		serial := S(g, "serial")
		var checks []Obj
		d, derr := loadDie(filepath.Join(parts, serial))
		if contains(tracks, "WAFER") {
			ok := derr == nil && d.Measure == S(design, "digest", "sha256")
			detail := fmt.Sprintf("%s of %s with %s; matches the released %s", strings.Join(Strs(r.plan, "layers"), ", "),
				strings.Join(Strs(r.plan, "regions"), ", "), S(r.plan, "technique"), S(design, "name"))
			if !ok {
				detail = "the imaged layout is not the released design"
				if derr != nil {
					detail = "the part was not available: " + derr.Error()
				}
			}
			checks = append(checks, check("layout-matches-release", ok, detail))
		}
		if contains(tracks, "PACKAGE_TEST") {
			checks = append(checks, check("package-xray", derr == nil, "one die in the package, marked "+serial))
			e := byDie[dieKey(get(g, "wafer"), get(g, "x"), get(g, "y"))]
			ok := derr == nil && e != nil && hex.EncodeToString(d.UEID()) == S(e, "ueid") && sha256Bytes(d.Cert) == unit
			checks = append(checks, check("die-matches-genealogy", ok,
				fmt.Sprintf("die %s, as the genealogy and wafer sort's identities name it", dieName(get(g, "wafer"), get(g, "x"), get(g, "y")))))
		}
		destroyed := Truthy(get(r.plan, "destructive"))
		samples = append(samples, Obj{"unit": unit, "serial": serial, "result": sampleResult(checks), "destroyed": destroyed, "checks": checks})
		subjects = append(subjects, unitRD(unit))
		if destroyed {
			if err := os.RemoveAll(filepath.Join(parts, serial)); err != nil {
				return err
			}
		}
	}
	return r.sign(bundle, lot, len(units), Obj{"name": S(design, "name"), "digest": get(design, "digest")}, subjects, samples, key)
}

// unitRD is a sampled unit as a subject: at L3 a unit is named by its
// identity certificate's digest.
func unitRD(unit string) Obj { return rd("urn:hslsa:unit:"+unit, unit) }

// InspectBoards is the lab inspecting a board lot: for each sampled board it
// X-rays what is placed where and compares that with the board HBOM, checks
// each component's marking against the HBOM line, and challenges each part
// with an identity, which must answer under the certificate the board's
// platform certificate names for its position. Nothing is destroyed.
func InspectBoards(bundle, boardsDir, planPath, seedPath, key string) error {
	art := filepath.Join(bundle, "artifacts")
	a1, err := DecodeEnvelope(filepath.Join(bundle, "att", BoardA1))
	if err != nil {
		return err
	}
	lot := firstSubject(a1)
	boards, err := ReadUnits(filepath.Join(art, BoardLot))
	if err != nil {
		return err
	}
	r, err := startInspection(bundle, planPath, seedPath, lot, boards)
	if err != nil {
		return err
	}
	hb, err := DecodeEnvelope(filepath.Join(bundle, "att", BoardHBOM))
	if err != nil {
		return err
	}
	lines := hbomLines(hb)
	mfr := S(hb, "predicate", "product", "manufacturer", "name")
	var samples, subjects []Obj
	for _, serial := range r.sample {
		dir := filepath.Join(boardsDir, serial)
		phys, perr := ReadObj(filepath.Join(dir, BoardPhysical))
		placed := O(phys, "placements")
		xray, detail := perr == nil && sameSet(sortedKeys(placed), sortedKeys(anyLines(lines))), "every position holds the part the HBOM lists"
		for _, ref := range sortedKeys(placed) {
			if l := lines[ref]; l == nil || S(placed, ref, "mpn") != S(l, "mpn") {
				xray, detail = false, ref+" holds "+S(placed, ref, "mpn")+", which the HBOM does not list there"
			}
		}
		if perr != nil {
			detail = "the board was not available: " + perr.Error()
		}
		auth, adetail := xray, "markings match the HBOM's lots and date codes; identity parts answer under their platform certificate"
		for _, ref := range sortedKeys(placed) {
			l, p := lines[ref], O(placed, ref)
			if l == nil || S(p, "manufacturer") != S(l, "manufacturer", "name") || !jsonEqual(get(p, "lot"), get(l, "lot")) || !jsonEqual(get(p, "dateCode"), get(l, "dateCode")) {
				auth, adetail = false, ref+": marking "+S(p, "manufacturer")+" lot "+num(get(p, "lot"))+" date code "+num(get(p, "dateCode"))+" is not the HBOM's"
			}
		}
		if pc, err := DecodeEnvelope(filepath.Join(bundle, "att", PlatformCertAtt(serial))); err == nil {
			for _, c := range Objs(pc, "predicate", "components") {
				want := S(c, "identity", "certificateDigest", "sha256")
				if want == "" {
					continue
				}
				nonce, der, sig, err := ChallengeUnit(filepath.Join(dir, S(c, "refDes")))
				cert, cerr := x509.ParseCertificate(der)
				if err != nil || cerr != nil || sha256Bytes(der) != want || !answered(cert, nonce, sig) {
					auth, adetail = false, S(c, "refDes")+" does not answer under the certificate its platform certificate names"
				}
			}
		} else {
			auth, adetail = false, "the board has no platform certificate to authenticate its identity parts against"
		}
		checks := []Obj{check("x-ray-matches-hbom", xray, detail), check("components-authenticated", auth, adetail)}
		samples = append(samples, Obj{"unit": serial, "serial": serial, "result": sampleResult(checks), "destroyed": false, "checks": checks})
		subjects = append(subjects, boardRD(mfr, serial))
	}
	design := O(a1, "predicate", "hwMfg", "designRef")
	return r.sign(bundle, lot, len(boards), Obj{"name": S(design, "name"), "digest": get(design, "digest")}, subjects, samples, key)
}

// hbomLines maps each reference designator of a board HBOM to its parts[] entry.
func hbomLines(hb Obj) map[string]Obj {
	out := map[string]Obj{}
	for _, p := range Objs(hb, "predicate", "parts") {
		for _, r := range Strs(p, "refDes") {
			out[r] = p
		}
	}
	return out
}

func anyLines(m map[string]Obj) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

// inspectionScope is what one lot's L4 inspection must cover.
type inspectionScope struct {
	label     string   // for messages
	tracks    []string // the tracks the policy claims at L4 here
	lot       Obj      // the lot subject
	units     []string // the lot's units or boards
	design    Obj      // what the samples are compared with
	sealer    string   // the record that sealed the lot, which consumes the commitment
	sealerRec Obj
	producers []string // the roles the lab must be independent of
	received  []string // what the buyer received: none may be a destroyed sample
}

// inspectionCheck is spec rule 6 of the lot receipt check, and the same for
// a board lot: an inspection record from an allowed, independent lab covers
// the lot, with an acceptable sampling plan and no failed sample. It
// returns the commitment and the record, for the VSA's inputs.
func inspectionCheck(bundle string, trust *TrustRoot, policy Obj, sc inspectionScope) ([]Obj, error) {
	label := sc.label
	pol := O(policy, "inspection")
	role := S(pol, "lab")
	if role == "" {
		role = InspectionLabRole
	}
	min, _ := Int(pol, "minSample")
	if min < 1 {
		return nil, failf("%s: the policy sets no minimum sample (inspection.minSample), so no sampling plan is acceptable", label)
	}
	cPath := filepath.Join(bundle, "att", InspectionCommitmentAtt)
	iPath := filepath.Join(bundle, "att", InspectionAtt)
	if !fileExists(iPath) {
		return nil, failf("%s: no inspection record (%s) from an independent lab", label, InspectionAtt)
	}
	c, err := trust.Open(cPath, role, InspectionCommitmentType)
	if err != nil {
		return nil, err
	}
	rec, err := trust.Open(iPath, role, InspectionType)
	if err != nil {
		return nil, err
	}
	kc, err := trust.SignerKey(cPath, role)
	if err != nil {
		return nil, err
	}
	ki, err := trust.SignerKey(iPath, role)
	if err != nil {
		return nil, err
	}
	if kc.ID != ki.ID {
		return nil, failf("%s: the inspection is signed by another lab key than the commitment", label)
	}
	if err := independentOf(trust, iPath, role, sc.producers, label+": the inspection"); err != nil {
		return nil, err
	}
	if err := labAccredited(trust, pol, ki, role, label+": the inspection"); err != nil {
		return nil, err
	}
	commitRD := relRD(bundle, "att/"+InspectionCommitmentAtt)
	if err := requireLink(sc.sealerRec, label+": "+sc.sealer, []Obj{commitRD}, "the lab's inspection commitment"); err != nil {
		return nil, failf("%s; without it nothing shows the lab committed to its seed before the lot was sealed", strings.TrimPrefix(err.Error(), "verification failed: "))
	}
	if S(c, "predicate", "lot") != S(sc.lot, "name") {
		return nil, failf("%s: the commitment is for %s, not %s", label, S(c, "predicate", "lot"), S(sc.lot, "name"))
	}
	hw := O(rec, "predicate", "hwInspection")
	seed, err := hex.DecodeString(S(hw, "seed"))
	if err != nil || len(seed) < 16 || seedDigest(seed) != S(c, "predicate", "seedCommitment", "sha256") {
		return nil, failf("%s: the seed the inspection reveals is not the one the lab committed to", label)
	}
	if !jsonEqual(get(hw, "commitment", "digest"), commitRD["digest"]) || !jsonEqual(get(hw, "plan"), get(c, "predicate", "plan")) {
		return nil, failf("%s: the inspection does not follow the plan it committed to", label)
	}
	if S(hw, "plan", "method") != SampleMethod {
		return nil, failf("%s: sample drawn by %q, not %s", label, S(hw, "plan", "method"), SampleMethod)
	}
	if S(hw, "lot", "id") != S(sc.lot, "name") || !jsonEqual(get(hw, "lot", "digest"), get(sc.lot, "digest")) {
		return nil, failf("%s: the inspection covers another lot than %s", label, S(sc.lot, "name"))
	}
	if size, _ := Int(hw, "lot", "size"); size != int64(len(sc.units)) {
		return nil, failf("%s: the inspection states a lot of %d, but %s holds %d", label, size, S(sc.lot, "name"), len(sc.units))
	}
	if !jsonEqual(get(hw, "designRef", "digest"), get(sc.design, "digest")) {
		return nil, failf("%s: the lab compared the samples with another design than %s", label, S(sc.design, "name"))
	}
	for _, t := range sc.tracks {
		if !contains(Strs(hw, "tracks"), t) {
			return nil, failf("%s: the inspection does not cover the %s track", label, TrackTitle[t])
		}
	}
	if S(hw, "technique") == "" {
		return nil, failf("%s: the inspection names no technique", label)
	}
	if contains(sc.tracks, "WAFER") {
		if len(Strs(hw, "regions")) == 0 || len(Strs(hw, "layers")) == 0 {
			return nil, failf("%s: the inspection does not name the regions and layers it imaged", label)
		}
		for _, l := range Strs(pol, "layers") {
			if !contains(Strs(hw, "layers"), l) {
				return nil, failf("%s: the lab did not image layer %s, which the policy requires (inspection.layers)", label, l)
			}
		}
		for _, g := range Strs(pol, "regions") {
			if !contains(Strs(hw, "regions"), g) {
				return nil, failf("%s: the lab did not image region %s, which the policy requires (inspection.regions)", label, g)
			}
		}
	}
	n, _ := Int(hw, "plan", "sampleSize")
	if n < min && n < int64(len(sc.units)) {
		return nil, failf("%s: a sample of %d, below the policy's minimum of %d (inspection.minSample)", label, n, min)
	}
	want := SeededSample(seed, sc.units, int(n))
	samples := Objs(hw, "samples")
	var got []string
	for _, s := range samples {
		got = append(got, S(s, "unit"))
	}
	if !equalStrings(got, want) {
		return nil, failf("%s: the units inspected are not the sample the committed seed draws", label)
	}
	destroyed := map[string]bool{}
	for _, s := range samples {
		if S(s, "result") != "pass" {
			return nil, failf("%s: sample %s failed inspection: %s", label, S(s, "serial"), strings.Join(failedDetails(Objs(s, "checks")), "; "))
		}
		for _, t := range sc.tracks {
			for _, name := range inspectionChecks[t] {
				if !hasCheck(Objs(s, "checks"), name) {
					return nil, failf("%s: sample %s has no passing %s check", label, S(s, "serial"), name)
				}
			}
		}
		if Truthy(get(s, "destroyed")) {
			destroyed[S(s, "unit")] = true
		}
	}
	for _, u := range sc.received {
		if destroyed[u] {
			return nil, failf("%s: received unit %s is one the lab destroyed in its inspection; a part that answers as it is a copy", label, short(u))
		}
	}
	fmt.Printf("%s: PASSED, %s inspected a seeded sample of %d of the %d in %s, none failed\n",
		label, orgOf(trust, iPath, role), len(samples), len(sc.units), S(sc.lot, "name"))
	return []Obj{commitRD, relRD(bundle, "att/"+InspectionAtt)}, nil
}

// labAccredited is the lab's half of the L3 site rule: the buyer enrolled the
// lab's key with an accreditation (for a testing lab, ISO/IEC 17025 or a
// scheme like it), and the policy's inspection.accreditations list that
// scheme. Independence says the lab is not the producer; accreditation says
// someone the buyer accepts has vetted its competence.
func labAccredited(trust *TrustRoot, pol Obj, k Key, role, what string) error {
	accepted := Strs(pol, "accreditations")
	if len(accepted) == 0 {
		return failf("%s: the policy accepts no lab accreditation (inspection.accreditations), so no lab qualifies", what)
	}
	e, ok := trust.Enrolled[k.ID]
	if !ok {
		return failf("%s is signed by %s key %s, which the trust root lists without an enrollment; L4 needs a buyer-run trust root that records the lab's accreditation", what, role, short(k.ID))
	}
	scheme := S(e, "accreditation", "scheme")
	if scheme == "" {
		return failf("%s is signed by %s key %s of %s, which is enrolled with no accreditation; L4 needs an accredited lab", what, role, short(k.ID), S(e, "organization", "name"))
	}
	if !contains(accepted, scheme) {
		return failf("%s is signed by %s, accredited under %q, which the policy's inspection.accreditations do not list", what, S(e, "organization", "name"), scheme)
	}
	return nil
}

func failedDetails(checks []Obj) []string {
	var out []string
	for _, c := range checks {
		if S(c, "result") != "pass" {
			out = append(out, S(c, "name")+" ("+S(c, "detail")+")")
		}
	}
	return out
}

// chipL4 runs the L4 inspection for the chip tracks the policy claims at L4.
func chipL4(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, stmts map[string]Obj, lot Obj, shipped, received []string) ([]Obj, error) {
	var tracks []string
	for _, t := range []string{"WAFER", "PACKAGE_TEST"} {
		if trackClaim(policy, t) >= 4 {
			tracks = append(tracks, t)
		}
	}
	if len(tracks) == 0 {
		return nil, nil
	}
	var names []string
	for _, t := range tracks {
		names = append(names, TrackTitle[t]+" L4")
	}
	return inspectionCheck(bundle, trust, policy, inspectionScope{
		label: strings.Join(names, " and "), tracks: tracks, lot: lot, units: shipped,
		design: design.Final, sealer: "final-test", sealerRec: stmts["final-test"],
		producers: []string{"fab-site", "sort-site", "osat-site", "test-site", "product-owner"},
		received:  received,
	})
}

// boardL4 runs the Assembly L4 inspection over a board lot.
func boardL4(bundle string, trust *TrustRoot, policy, a1, lot Obj, boards, received []string) ([]Obj, error) {
	if trackClaim(policy, "ASSEMBLY") < 4 {
		return nil, nil
	}
	design := O(a1, "predicate", "hwMfg", "designRef")
	return inspectionCheck(bundle, trust, policy, inspectionScope{
		label: "Assembly L4", tracks: []string{"ASSEMBLY"}, lot: lot, units: boards,
		design: design, sealer: "board-assembly", sealerRec: a1,
		producers: []string{emsRole, boardOwnerRole, platformCARole},
		received:  received,
	})
}
