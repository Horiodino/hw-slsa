package hslsa

// The MES and STDF adapter (roadmap phase 3): it reads the exports a fab, a
// sort house, an OSAT and a test house already produce, unchanged (MES lot
// histories, a unit genealogy, STDF V4 test results and SEMI E142 wafer
// maps), and turns them into the scenario the mfg command signs F1 to F4
// from. Each record then carries the exports it was made from, by digest,
// and names them in hwMfg.adapter, so a verifier can parse them again and
// check that the record says exactly what they say.
//
// A site that runs the adapter itself signs its own record. A site that
// does not hands its export to whoever received from it, who runs the
// adapter on it and proxy-signs the record (scenario.unsigned, as in
// proxy.go); the record then still carries the export, and its track is
// held at L1 as for any proxy-signed record.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// AdapterID names this adapter in hwMfg.adapter.id.
const AdapterID = NS + "/tools/hslsa/adapt/mes-stdf@v0.1"

// The export formats the adapter reads.
const (
	FmtMESHistory   = "mes-lot-history"
	FmtMESGenealogy = "mes-genealogy"
	FmtSTDF         = "stdf-v4"
	FmtE142         = "semi-e142"
)

// adapterFormats are the exports each step is made from. Every step takes
// one file of each, except the wafer maps, which may come one file per wafer.
var adapterFormats = map[string][]string{
	"wafer-fab":  {FmtMESHistory},
	"wafer-sort": {FmtSTDF, FmtE142},
	"packaging":  {FmtMESHistory, FmtMESGenealogy},
	"final-test": {FmtSTDF},
}

// adapterSettings are the settings each step may carry, which the verifier
// needs to read the exports the same way: for fab and packaging, which MES
// operations stand for which of the record's checks.
var adapterSettings = map[string][]string{"wafer-fab": {"checks"}, "packaging": {"checks"}}

// stepFiles groups a step's export paths by format and checks the step has
// what it needs.
func stepFiles(step string, sources []Obj, path func(Obj) string) (map[string][]string, error) {
	files := map[string][]string{}
	for _, s := range sources {
		f := S(s, "format")
		if !contains(adapterFormats[step], f) {
			return nil, fmt.Errorf("%s: the adapter does not read %q exports for this step (it reads %s)", step, f, strings.Join(adapterFormats[step], ", "))
		}
		files[f] = append(files[f], path(s))
	}
	for _, f := range adapterFormats[step] {
		if len(files[f]) == 0 || (f != FmtE142 && len(files[f]) > 1) {
			return nil, fmt.Errorf("%s: needs one %s export, has %d", step, f, len(files[f]))
		}
	}
	return files, nil
}

// adaptStep reads one step's exports and returns what the step's record
// says, in the shape the scenario uses:
//
//	wafer-fab   lotId, wafers, maskSetId, processNode, checks
//	wafer-sort  lotId, program, dies (wafer, x, y, bin), sorted by wafer, y, x
//	packaging   assemblyLot, packageType, sourceLot, genealogy (unit: wafer, x, y), checks
//	final-test  lotId, program, results (unit: pass or fail)
func adaptStep(step string, files map[string][]string, settings Obj) (Obj, error) {
	switch step {
	case "wafer-fab":
		path := files[FmtMESHistory][0]
		events, err := ReadMESHistory(path)
		if err != nil {
			return nil, err
		}
		start, err := lotStart(path, events)
		if err != nil {
			return nil, err
		}
		if len(start.Materials) == 0 || int64(len(start.Materials)) != start.Quantity {
			return nil, fmt.Errorf("%s: LOT_START of %s lists %d wafers for a quantity of %d", path, start.Lot, len(start.Materials), start.Quantity)
		}
		mask, process := start.Attrs["mask_set"], start.Attrs["process"]
		if start.Lot == "" || mask == "" || process == "" {
			return nil, fmt.Errorf("%s: LOT_START needs a lot_id and the attributes mask_set and process", path)
		}
		checks, err := operationChecks(path, events, start.Lot, Objs(settings, "checks"))
		if err != nil {
			return nil, err
		}
		return Obj{"lotId": start.Lot, "wafers": anyStrings(start.Materials), "maskSetId": mask, "processNode": process, "checks": checks}, nil

	case "wafer-sort":
		path := files[FmtSTDF][0]
		s, err := ReadSTDF(path)
		if err != nil {
			return nil, err
		}
		for _, p := range s.Parts {
			if p.Wafer == "" || p.X == -32768 || p.Y == -32768 {
				return nil, fmt.Errorf("%s: a sort result outside a wafer, or without die coordinates", path)
			}
		}
		results, _, err := s.Results(func(p STDFPart) string { return dieKey(p.Wafer, p.X, p.Y) })
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if s.LotID == "" || s.JobName == "" || s.JobRev == "" {
			return nil, fmt.Errorf("%s: the MIR needs LOT_ID, JOB_NAM and JOB_REV", path)
		}
		maps := map[string]WaferMap{}
		for _, mp := range files[FmtE142] {
			ms, err := ReadE142(mp)
			if err != nil {
				return nil, err
			}
			for _, m := range ms {
				if _, dup := maps[m.Wafer]; dup {
					return nil, fmt.Errorf("two wafer maps for wafer %s", m.Wafer)
				}
				if m.LotID != "" && m.LotID != s.LotID {
					return nil, fmt.Errorf("%s: wafer %s is in lot %s, the STDF file in %s", mp, m.Wafer, m.LotID, s.LotID)
				}
				maps[m.Wafer] = m
			}
		}
		var dies []STDFPart
		count := map[string]int{}
		for _, p := range results {
			m, ok := maps[p.Wafer]
			if !ok {
				return nil, fmt.Errorf("wafer %s has sort results but no wafer map", p.Wafer)
			}
			pass, ok := m.Pass[[2]int64{p.X, p.Y}]
			if !ok || pass == p.Failed {
				return nil, fmt.Errorf("wafer %s die (%d,%d): the wafer map and the STDF results disagree", p.Wafer, p.X, p.Y)
			}
			count[p.Wafer]++
			dies = append(dies, p)
		}
		for w, m := range maps {
			if count[w] != len(m.Pass) {
				return nil, fmt.Errorf("wafer %s: the wafer map has %d dies with a bin, the STDF file results for %d", w, len(m.Pass), count[w])
			}
		}
		sort.Slice(dies, func(i, j int) bool {
			a, b := dies[i], dies[j]
			if a.Wafer != b.Wafer {
				return a.Wafer < b.Wafer
			}
			if a.Y != b.Y {
				return a.Y < b.Y
			}
			return a.X < b.X
		})
		out := make([]any, len(dies))
		for i, p := range dies {
			bin := "pass"
			if p.Failed {
				bin = "fail"
			}
			out[i] = Obj{"wafer": p.Wafer, "x": p.X, "y": p.Y, "bin": bin}
		}
		return Obj{"lotId": s.LotID, "program": Obj{"name": s.JobName, "version": s.JobRev}, "dies": out}, nil

	case "packaging":
		path := files[FmtMESHistory][0]
		events, err := ReadMESHistory(path)
		if err != nil {
			return nil, err
		}
		start, err := lotStart(path, events)
		if err != nil {
			return nil, err
		}
		pkg, source := start.Attrs["package"], start.Attrs["source_lot"]
		if start.Lot == "" || pkg == "" || source == "" {
			return nil, fmt.Errorf("%s: LOT_START needs a lot_id and the attributes package and source_lot", path)
		}
		gpath := files[FmtMESGenealogy][0]
		rows, err := ReadMESGenealogy(gpath)
		if err != nil {
			return nil, err
		}
		genealogy := Obj{}
		for _, r := range rows {
			if r.Lot != start.Lot {
				continue
			}
			if r.SourceLot != source {
				return nil, fmt.Errorf("%s: unit %s comes from lot %s, but %s was started from %s", gpath, r.Unit, r.SourceLot, start.Lot, source)
			}
			if Has(genealogy, r.Unit) {
				return nil, fmt.Errorf("%s: unit %s is listed twice", gpath, r.Unit)
			}
			genealogy[r.Unit] = Obj{"wafer": r.Wafer, "x": r.X, "y": r.Y}
		}
		if int64(len(genealogy)) != start.Quantity {
			return nil, fmt.Errorf("%s: %d units of lot %s, and its LOT_START says %d", gpath, len(genealogy), start.Lot, start.Quantity)
		}
		checks, err := operationChecks(path, events, start.Lot, Objs(settings, "checks"))
		if err != nil {
			return nil, err
		}
		return Obj{"assemblyLot": start.Lot, "packageType": pkg, "sourceLot": source, "genealogy": genealogy, "checks": checks}, nil

	case "final-test":
		path := files[FmtSTDF][0]
		s, err := ReadSTDF(path)
		if err != nil {
			return nil, err
		}
		for _, p := range s.Parts {
			if p.PartID == "" {
				return nil, fmt.Errorf("%s: a final test result without a PART_ID", path)
			}
		}
		results, _, err := s.Results(func(p STDFPart) string { return p.PartID })
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if s.LotID == "" || s.JobName == "" || s.JobRev == "" {
			return nil, fmt.Errorf("%s: the MIR needs LOT_ID, JOB_NAM and JOB_REV", path)
		}
		units := Obj{}
		for id, p := range results {
			units[id] = "pass"
			if p.Failed {
				units[id] = "fail"
			}
		}
		return Obj{"lotId": s.LotID, "program": Obj{"name": s.JobName, "version": s.JobRev}, "results": units}, nil
	}
	return nil, fmt.Errorf("the adapter has no records for step %s", step)
}

// stepSettings keeps only the settings the step uses.
func stepSettings(step string, block Obj) Obj {
	out := Obj{}
	for _, k := range adapterSettings[step] {
		if v := get(block, k); v != nil {
			out[k] = v
		}
	}
	return out
}

// AdaptScenario reads an adapter configuration and every export it names,
// and returns the scenario mfg and hbom take. The configuration is what a
// site sets up once (its name, which file holds what, which MES operation
// is which check); every value in the records comes from the exports.
// Source paths in the result are absolute.
func AdaptScenario(configPath string) (Obj, error) {
	cfg, err := ReadObj(configPath)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(configPath)
	if S(cfg, "unsigned", "wafer-sort", "cover") == ByEvidence {
		return nil, fmt.Errorf("unsigned.wafer-sort: the adapter reads the sort house's exports; an evidence record is for a supplier that gives none")
	}
	frags, steps := map[string]Obj{}, Obj{}
	for _, step := range MfgSteps {
		block := O(cfg, scenarioKey[step])
		if O(block, "site") == nil {
			return nil, fmt.Errorf("%s: needs a site", scenarioKey[step])
		}
		var sources []any
		files, err := stepFiles(step, Objs(block, "sources"), func(s Obj) string {
			p := S(s, "path")
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			sources = append(sources, Obj{"path": p, "format": S(s, "format")})
			return p
		})
		if err != nil {
			return nil, err
		}
		settings := stepSettings(step, block)
		if frags[step], err = adaptStep(step, files, settings); err != nil {
			return nil, err
		}
		steps[step] = Obj{"sources": sources, "settings": settings}
	}
	fab, srt, pkg, ft := frags["wafer-fab"], frags["wafer-sort"], frags["packaging"], frags["final-test"]

	// The exports must describe one lot as it moved from site to site.
	wafers := Strs(fab, "wafers")
	if S(srt, "lotId") != S(fab, "lotId") {
		return nil, fmt.Errorf("wafer sort tested lot %s, the fab started %s", S(srt, "lotId"), S(fab, "lotId"))
	}
	good, sorted := map[string]bool{}, map[string]bool{}
	var failedDies []string
	for _, d := range Objs(srt, "dies") {
		sorted[S(d, "wafer")] = true
		if S(d, "bin") == "pass" {
			good[dieKey(d["wafer"], d["x"], d["y"])] = true
		} else {
			failedDies = append(failedDies, dieKey(d["wafer"], d["x"], d["y"]))
		}
	}
	if !sameSet(sortedKeys(sorted), wafers) {
		return nil, fmt.Errorf("wafer sort tested wafers %s, the fab started %s", strings.Join(sortedKeys(sorted), " "), strings.Join(wafers, " "))
	}
	if S(pkg, "sourceLot") != S(fab, "lotId") {
		return nil, fmt.Errorf("the OSAT started %s from lot %s, not %s", S(pkg, "assemblyLot"), S(pkg, "sourceLot"), S(fab, "lotId"))
	}
	genealogy := O(pkg, "genealogy")
	used := map[string]bool{}
	for _, unit := range sortedKeys(genealogy) {
		g := O(genealogy, unit)
		k := dieKey(g["wafer"], g["x"], g["y"])
		if !good[k] || used[k] {
			return nil, fmt.Errorf("unit %s: its die %s (%v,%v) did not pass wafer sort, or another unit holds it", unit, S(g, "wafer"), num(g["x"]), num(g["y"]))
		}
		used[k] = true
	}
	results := O(ft, "results")
	if !sameSet(sortedKeys(results), sortedKeys(genealogy)) {
		return nil, fmt.Errorf("final test results are for other units than the OSAT packaged")
	}
	if S(ft, "lotId") != S(pkg, "assemblyLot") {
		return nil, fmt.Errorf("final test tested lot %s, the OSAT packaged %s", S(ft, "lotId"), S(pkg, "assemblyLot"))
	}
	var failedUnits []string
	for _, u := range sortedKeys(results) {
		if results[u] == "fail" {
			failedUnits = append(failedUnits, u)
		}
	}

	block := func(step string) Obj { return O(cfg, scenarioKey[step]) }
	sc := Obj{
		"product": get(cfg, "product"),
		"fab": Obj{"id": S(block("wafer-fab"), "id"), "site": get(block("wafer-fab"), "site"),
			"processNode": fab["processNode"], "maskSetId": fab["maskSetId"], "checks": fab["checks"]},
		"waferLot": Obj{"lotId": fab["lotId"], "wafers": fab["wafers"]},
		"sort":     Obj{"site": get(block("wafer-sort"), "site"), "program": srt["program"], "dies": srt["dies"]},
		"packaging": Obj{"site": get(block("packaging"), "site"), "packageType": pkg["packageType"],
			"assemblyLot": pkg["assemblyLot"], "units": len(genealogy), "genealogy": genealogy, "checks": pkg["checks"]},
		"transfers": Truthy(get(cfg, "transfers")),
		"finalTest": Obj{"site": get(block("final-test"), "site"), "program": ft["program"], "lotId": ft["lotId"],
			"failedUnits": anyStrings(nonNilStrings(failedUnits))},
		"adapter": Obj{"id": AdapterID, "steps": steps},
	}
	if S(block("wafer-fab"), "id") == "" {
		return nil, fmt.Errorf("fab: needs an id, the fab's short name in wafer lot URNs")
	}
	if u := get(cfg, "unsigned"); u != nil {
		sc["unsigned"] = u
	}
	// Exports a simulator wrote (the virtual shuttle's) say so in the
	// configuration that comes with them, and every record made from them
	// carries it.
	if m := O(cfg, "simulated"); m != nil {
		if err := checkSimulated(m, configPath); err != nil {
			return nil, err
		}
		sc["simulated"] = m
	}
	fmt.Printf("adapted: lot %s, %d wafers, %d of %d dies failed sort, %d units packaged as %s, %d failed final test\n",
		S(fab, "lotId"), len(wafers), len(failedDies), len(Objs(srt, "dies")), len(genealogy), S(pkg, "assemblyLot"), len(failedUnits))
	return sc, nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Adapt writes the scenario for an adapter configuration to out, with
// source paths relative to out's directory.
func Adapt(configPath, out string) error {
	sc, err := AdaptScenario(configPath)
	if err != nil {
		return err
	}
	base, err := filepath.Abs(filepath.Dir(out))
	if err != nil {
		return err
	}
	for _, step := range MfgSteps {
		for _, s := range Objs(sc, "adapter", "steps", step, "sources") {
			abs, err := filepath.Abs(S(s, "path"))
			if err != nil {
				return err
			}
			if rel, err := filepath.Rel(base, abs); err == nil {
				s["path"] = filepath.ToSlash(rel)
			}
		}
	}
	return WriteJSON(out, sc)
}

// mfgOutputs are the files mfg writes to the bundle's artifacts, which an
// export copied there must not replace.
var mfgOutputs = []string{"wafer-maps.json", "genealogy.json", "packaged-lot.txt", "shipped-lot.txt", "final-test-results.json"}

// attachExports copies a step's exports into the bundle, adds them to the
// record's resolvedDependencies, and names them in hwMfg.adapter.
func attachExports(bundle, scenarioDir string, sc Obj, step string, deps []Obj, hw Obj) ([]Obj, error) {
	a := O(sc, "adapter", "steps", step)
	if a == nil {
		return deps, nil
	}
	var names []any
	for _, s := range Objs(a, "sources") {
		src := S(s, "path")
		if !filepath.IsAbs(src) {
			src = filepath.Join(scenarioDir, filepath.FromSlash(src))
		}
		name := filepath.Base(src)
		if contains(mfgOutputs, name) || strings.HasPrefix(name, "transfer-") || strings.HasPrefix(name, "supplier-export-") {
			return nil, fmt.Errorf("%s: export %s has the name of a file mfg writes", step, name)
		}
		dst := filepath.Join(bundle, "artifacts", name)
		if err := copyFile(src, dst); err != nil {
			return nil, err
		}
		r, err := fileRD(dst, "")
		if err != nil {
			return nil, err
		}
		deps = append(deps, r)
		names = append(names, Obj{"name": name, "format": S(s, "format")})
	}
	ad := Obj{"id": S(sc, "adapter", "id"), "sources": names}
	if len(O(a, "settings")) > 0 {
		ad["settings"] = O(a, "settings")
	}
	hw["adapter"] = ad
	return deps, nil
}

// exportsCheck parses again the exports each record names in hwMfg.adapter
// and checks the record says what they say. A record made by another
// adapter is checked as an ordinary record. With the policy's
// manufacturing.requireExports set, every step must carry exports this
// verifier can check. It returns a line per record for the check's output.
func exportsCheck(bundle string, policy Obj, stmts map[string]Obj) ([]string, error) {
	art := filepath.Join(bundle, "artifacts")
	var notes []string
	for _, step := range MfgSteps {
		stmt := stmts[step]
		pred := O(stmt, "predicate")
		hw, ext := O(pred, "hwMfg"), O(pred, "buildDefinition", "externalParameters")
		a := O(hw, "adapter")
		required := Truthy(get(policy, "manufacturing", "requireExports"))
		if a == nil {
			if required {
				return nil, failf("%s: the policy requires each record to carry its supplier's exports (manufacturing.requireExports), and this one carries none", step)
			}
			continue
		}
		if S(a, "id") != AdapterID {
			if required {
				return nil, failf("%s: made by adapter %q, which this verifier cannot run, and the policy requires its exports to be checked", step, S(a, "id"))
			}
			notes = append(notes, fmt.Sprintf("%s: made by adapter %s, which this verifier does not run; checked as an ordinary record", step, S(a, "id")))
			continue
		}
		deps := map[string]any{}
		for _, d := range Objs(pred, "buildDefinition", "resolvedDependencies") {
			deps[S(d, "name")] = get(d, "digest")
		}
		var names []string
		files, err := stepFiles(step, Objs(a, "sources"), func(s Obj) string {
			name := S(s, "name")
			names = append(names, name)
			return filepath.Join(art, name)
		})
		if err != nil {
			return nil, failf("%v", err)
		}
		for _, name := range names {
			if name == "" || strings.ContainsAny(name, `/\`) || !Has(deps, name) {
				return nil, failf("%s: export %q is not one of its resolvedDependencies", step, name)
			}
			d := fileDigest(filepath.Join(art, name))
			if d == nil {
				return nil, failf("%s: export %s is missing from the bundle", step, name)
			}
			if !jsonEqual(d, deps[name]) {
				return nil, failf("%s: export %s does not match its attested digest", step, name)
			}
		}
		frag, err := adaptStep(step, files, O(a, "settings"))
		if err != nil {
			return nil, failf("%s: its exports do not read: %v", step, err)
		}
		differs := func(what string) error { return failf("%s: %s differs from its supplier's exports", step, what) }
		switch step {
		case "wafer-fab":
			lot := firstSubject(stmt)
			d, err := LotDigest(Strs(frag, "wafers"))
			if err != nil || d != S(lot, "digest", "sha256") || !strings.HasSuffix(S(lot, "name"), ":"+S(frag, "lotId")) {
				return nil, differs("the wafer lot")
			}
			for _, k := range []string{"lotId", "maskSetId", "processNode"} {
				if S(ext, k) != S(frag, k) {
					return nil, differs("externalParameters." + k)
				}
			}
			if !jsonEqual(get(hw, "checks"), frag["checks"]) {
				return nil, differs("hwMfg.checks")
			}
		case "wafer-sort":
			if S(ext, "lotId") != S(frag, "lotId") || !jsonEqual(get(ext, "probeProgram"), frag["program"]) {
				return nil, differs("externalParameters")
			}
			maps, err := ReadObj(filepath.Join(art, "wafer-maps.json"))
			if err != nil || !jsonEqual(dieBins(Objs(maps, "dies")), dieBins(Objs(frag, "dies"))) {
				return nil, differs("the wafer maps")
			}
			bins := dieBins(Objs(frag, "dies"))
			passed := 0
			for _, b := range bins {
				if b == "pass" {
					passed++
				}
			}
			if !jsonEqual(get(hw, "yield"), Obj{"in": len(bins), "passed": passed, "failed": len(bins) - passed}) {
				return nil, differs("hwMfg.yield")
			}
		case "packaging":
			if S(ext, "lotId") != S(frag, "assemblyLot") || S(ext, "packageType") != S(frag, "packageType") {
				return nil, differs("externalParameters")
			}
			if S(stmts["wafer-fab"], "predicate", "buildDefinition", "externalParameters", "lotId") != S(frag, "sourceLot") {
				return nil, differs("the wafer lot it packaged")
			}
			waferLot := S(firstSubject(stmts["wafer-fab"]), "name")
			want := Obj{}
			for unit, g := range O(frag, "genealogy") {
				e := Obj{"waferLot": waferLot}
				for k, v := range g.(Obj) {
					e[k] = v
				}
				want[unit] = e
			}
			gen, err := ReadObj(filepath.Join(art, "genealogy.json"))
			if err != nil || !jsonEqual(get(gen, "units"), want) {
				return nil, differs("the genealogy")
			}
			if !jsonEqual(get(hw, "checks"), frag["checks"]) {
				return nil, differs("hwMfg.checks")
			}
		case "final-test":
			if S(ext, "lotId") != S(frag, "lotId") || !jsonEqual(get(ext, "testProgram"), frag["program"]) {
				return nil, differs("externalParameters")
			}
			res, err := ReadObj(filepath.Join(art, "final-test-results.json"))
			if err != nil || !jsonEqual(get(res, "units"), frag["results"]) {
				return nil, differs("the final test results")
			}
		}
		notes = append(notes, fmt.Sprintf("%s: matches %s", step, strings.Join(names, ", ")))
	}
	return notes, nil
}

// dieBins maps each die of a wafer map list to its bin.
func dieBins(dies []Obj) map[string]any {
	out := map[string]any{}
	for _, d := range dies {
		out[dieKey(d["wafer"], d["x"], d["y"])] = d["bin"]
	}
	return out
}
