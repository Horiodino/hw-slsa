package hslsa

// Wafer and Package/Test tracks: signed F1 to F4 records for a simulated lot,
// and, when the scenario asks, the transfers each site signs for what it
// ships to the next.
//
// No fab runs in CI, so the physical data (wafer maps, genealogy, test
// results) comes from a scenario file. Everything downstream of that data is
// real: each site signs with its own key, names its subjects the way the spec
// does, links to the previous step by digest, and copies the design release
// into designRef.

import (
	"fmt"
	"path/filepath"
	"strings"
)

// MfgSteps are the chip's manufacturing steps in order.
var MfgSteps = []string{"wafer-fab", "wafer-sort", "packaging", "final-test"}

// MfgAtt is the envelope file name of each manufacturing step.
var MfgAtt = map[string]string{
	"wafer-fab":  "mfg-f1-wafer-fab.intoto.json",
	"wafer-sort": "mfg-f2-wafer-sort.intoto.json",
	"packaging":  "mfg-f3-packaging.intoto.json",
	"final-test": "mfg-f4-final-test.intoto.json",
}

// MfgSigner is the trust-root role that signs each manufacturing step.
var MfgSigner = map[string]string{
	"wafer-fab": "fab-site", "wafer-sort": "sort-site", "packaging": "osat-site", "final-test": "test-site",
}

// TransferFrom names each shipment between two of the chip's manufacturing
// sites by the step that ships it: wafers from the fab to sort, wafers from
// sort to the OSAT, and packaged units from the OSAT to the test house.
var TransferFrom = []string{"wafer-fab", "wafer-sort", "packaging"}

// TransferAtt is the envelope file name of the transfer that leaves step from.
func TransferAtt(from string) string { return "mfg-transfer-" + from + ".intoto.json" }

// TransferList is the packing list file of the transfer that leaves step from.
func TransferList(from string) string { return "transfer-" + from + ".json" }

// transferLot is the step whose first subject names what a transfer ships:
// the wafer lot leaves the fab and sort, the packaged lot leaves the OSAT.
var transferLot = map[string]string{"wafer-fab": "wafer-fab", "wafer-sort": "wafer-fab", "packaging": "packaging"}

// mfgNames gives a manufacturing record's envelope file, signing role, build
// type and hwMfg.step. A transfer is a distribution record signed by the site
// that ships it, and "transfer-<from>" is its key in a withholding file.
func mfgNames(step string) (att, role, buildType, hwStep string) {
	if from, ok := strings.CutPrefix(step, "transfer-"); ok {
		return TransferAtt(from), MfgSigner[from], mfgStepType("distribution"), "distribution"
	}
	return MfgAtt[step], MfgSigner[step], mfgStepType(step), step
}

func slug(name string) string { return strings.ReplaceAll(strings.ToLower(name), " ", "-") }

// mfgRecord signs one manufacturing record with the site's own key, or,
// when by is set (see onBehalf), with the key of the party signing on the
// supplier's behalf.
func mfgRecord(bundle, step string, subjects []Obj, external Obj, deps []Obj, hw Obj, keys string, w *Withholding, by Obj) (Obj, error) {
	att, role, bt, hwStep := mfgNames(step)
	builderID := "urn:hslsa:site:" + slug(S(hw, "site", "name"))
	hwMfg := Obj{"step": hwStep, "confidential": []any{}}
	for k, v := range hw {
		hwMfg[k] = v
	}
	if by == nil || S(by, "kind") == ByEvidence {
		if err := removeStale(filepath.Join(bundle, "artifacts", ExportName(step))); err != nil {
			return nil, err
		}
	}
	if by != nil {
		if len(w.fields(step)) > 0 {
			return nil, fmt.Errorf("%s: a record signed on a supplier's behalf cannot withhold fields yet", step)
		}
		role, builderID = S(by, "role"), proxyBuilder(O(by, "signer"))
		proxy := Obj{"signer": O(by, "signer"), "reason": "supplier-does-not-sign"}
		if S(by, "kind") == ByEvidence {
			bt, hwMfg["step"] = mfgStepType("evidence"), "evidence"
		} else {
			export, err := writeExport(bundle, step, subjects, external, hw)
			if err != nil {
				return nil, err
			}
			proxy["source"] = []Obj{export}
		}
		hwMfg["proxy"] = proxy
	}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType":            bt,
			"externalParameters":   external,
			"resolvedDependencies": nonNil(deps),
		},
		"runDetails": Obj{
			"builder":  Obj{"id": builderID},
			"metadata": Obj{"invocationId": step + ":" + S(external, "lotId"), "finishedOn": Now()},
		},
		"hwMfg": hwMfg,
	}
	pred, disclosures, err := withhold(pred, MfgStep, w.fields(step))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", step, err)
	}
	signer, err := LoadSigner(filepath.Join(keys, role+".key.pem"))
	if err != nil {
		return nil, err
	}
	stmt, err := statement(subjects, MfgStep, pred)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(bundle, "att", att)
	env, err := Sign(stmt, signer, path)
	if err != nil {
		return nil, err
	}
	if err := writeDisclosures(path, disclosures); err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("%s: signed by %s", step, role)
	if by != nil {
		msg = fmt.Sprintf("%s: signed by %s on behalf of %s (%s)", step, role, S(hw, "site", "name"), S(by, "kind"))
	}
	if len(disclosures) > 0 {
		msg += fmt.Sprintf(", %d field(s) withheld", len(disclosures))
	}
	fmt.Println(msg)
	return rd("att/"+att, S(env, "digest", "sha256")), nil
}

// transfer signs the shipment that leaves step from, when the scenario
// records transfers, and returns the record the receiving step links to:
// the transfer, or prev itself when there is none. The packing list names
// what was shipped (wafer ids or unit serials), the lot they belong to and
// the receiving site.
func transfer(bundle, from string, enabled bool, prev, lot Obj, items []string, fromSite, toSite, designRef Obj, keys string, w *Withholding, by Obj) (Obj, error) {
	if !enabled {
		return prev, removeStale(filepath.Join(bundle, "att", TransferAtt(from)), filepath.Join(bundle, "artifacts", TransferList(from)),
			disclosurePath(filepath.Join(bundle, "att", TransferAtt(from))), filepath.Join(bundle, "artifacts", ExportName("transfer-"+from)))
	}
	path := filepath.Join(bundle, "artifacts", TransferList(from))
	id := from + ":" + S(lot, "name")
	if err := writeData(path, Obj{"id": id, "from": fromSite, "to": toSite, "lot": S(lot, "name"),
		"items": anyStrings(items), "quantity": len(items)}, w); err != nil {
		return nil, err
	}
	list, err := fileRD(path, "")
	if err != nil {
		return nil, err
	}
	return mfgRecord(bundle, "transfer-"+from, []Obj{list},
		Obj{"id": id, "lotId": S(lot, "name")},
		[]Obj{prev, lot},
		Obj{"site": fromSite, "receiver": toSite, "designRef": designRef, "checks": passed("packing-list-matches-lot")},
		keys, w, shipperProxy(by))
}

// writeData writes a data file a record names, with a random salt when the
// producer withholds it, so its digest cannot be confirmed by guessing.
func writeData(path string, v Obj, w *Withholding) error {
	if w.salts(filepath.Base(path)) {
		salt, err := newSalt()
		if err != nil {
			return err
		}
		v["salt"] = salt
	}
	return WriteJSON(path, v)
}

func passed(names ...string) []Obj {
	out := make([]Obj, len(names))
	for i, n := range names {
		out[i] = Obj{"name": n, "result": "pass"}
	}
	return out
}

func dieKey(wafer, x, y any) string { return fmt.Sprintf("%v\x00%v\x00%v", num(wafer), num(x), num(y)) }

// Mfg emits signed F1 to F4 records for the scenario lot. With w, each site
// withholds the fields w names and writes their disclosures to the bundle's
// disclosures directory.
func Mfg(bundle, scenarioPath, keys string, w *Withholding) error {
	art := filepath.Join(bundle, "artifacts")
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	releasePath := filepath.Join(bundle, "att", "design-release.intoto.json")
	release, err := DecodeEnvelope(releasePath)
	if err != nil {
		return err
	}
	releaseRD, err := fileRD(releasePath, "att/design-release.intoto.json")
	if err != nil {
		return err
	}
	finals := Objs(release, "subject")
	if len(finals) == 0 {
		return fmt.Errorf("design release has no subject")
	}
	final := finals[0]
	designRef := Obj{"name": S(final, "name"), "digest": O(final, "digest"), "release": releaseRD}
	by := map[string]Obj{}
	for _, step := range MfgSteps {
		if by[step], err = onBehalf(sc, step); err != nil {
			return err
		}
	}

	// F1: wafer fabrication
	fab, lot := O(sc, "fab"), O(sc, "waferLot")
	wafers := Strs(lot, "wafers")
	waferDigest, err := LotDigest(wafers)
	if err != nil {
		return err
	}
	waferLot := rd(fmt.Sprintf("urn:hslsa:wafer-lot:%s:%s", S(fab, "id"), S(lot, "lotId")), waferDigest)
	f1, err := mfgRecord(bundle, "wafer-fab", []Obj{waferLot},
		Obj{"lotId": S(lot, "lotId"), "maskSetId": S(fab, "maskSetId"), "processNode": S(fab, "processNode")},
		[]Obj{releaseRD},
		Obj{"site": O(fab, "site"), "designRef": designRef, "checks": passed("mask-vs-gds-xor", "inline-parametrics")},
		keys, w, by["wafer-fab"])
	if err != nil {
		return err
	}
	sort := O(sc, "sort")
	transfers := Truthy(get(sc, "transfers"))
	t1, err := transfer(bundle, "wafer-fab", transfers, f1, waferLot, wafers, O(fab, "site"), O(sort, "site"), designRef, keys, w, by["wafer-fab"])
	if err != nil {
		return err
	}

	// F2: wafer sort, one map entry per die
	failedDies := map[string]bool{}
	for _, d := range A(sort, "failedDies") {
		t, _ := d.([]any)
		if len(t) == 3 {
			failedDies[dieKey(t[0], t[1], t[2])] = true
		}
	}
	grid := A(sort, "grid")
	if len(grid) != 2 {
		return fmt.Errorf("scenario sort.grid must be [columns, rows]")
	}
	gx, _ := Int(grid[0])
	gy, _ := Int(grid[1])
	var dies, good []Obj
	for _, w := range wafers {
		for y := int64(0); y < gy; y++ {
			for x := int64(0); x < gx; x++ {
				bin := "pass"
				if failedDies[dieKey(w, x, y)] {
					bin = "fail"
				}
				d := Obj{"wafer": w, "x": x, "y": y, "bin": bin}
				dies = append(dies, d)
				if bin == "pass" {
					good = append(good, d)
				}
			}
		}
	}
	var f2, mapsRD Obj
	if S(by["wafer-sort"], "kind") == ByEvidence {
		// The sort house hands over paper only: its certificate and traveller
		// stand in for F2, and no wafer map enters the bundle.
		if err := removeStale(filepath.Join(art, "wafer-maps.json")); err != nil {
			return err
		}
		docs, entries, err := writeDocuments(bundle, "wafer-sort", sc)
		if err != nil {
			return err
		}
		f2, err = mfgRecord(bundle, "wafer-sort", docs,
			Obj{"lotId": S(lot, "lotId")},
			[]Obj{t1, waferLot},
			Obj{"site": O(sort, "site"), "designRef": designRef, "evidence": Obj{"covers": "wafer-sort", "documents": entries}},
			keys, w, by["wafer-sort"])
		if err != nil {
			return err
		}
	} else {
		if err := writeData(filepath.Join(art, "wafer-maps.json"), Obj{"waferLot": S(waferLot, "name"), "dies": nonNil(dies)}, w); err != nil {
			return err
		}
		if mapsRD, err = fileRD(filepath.Join(art, "wafer-maps.json"), ""); err != nil {
			return err
		}
		f2, err = mfgRecord(bundle, "wafer-sort", []Obj{mapsRD},
			Obj{"lotId": S(lot, "lotId"), "probeProgram": get(sort, "program")},
			[]Obj{t1, waferLot},
			Obj{
				"site":      O(sort, "site"),
				"designRef": designRef,
				"yield":     Obj{"in": len(dies), "passed": len(good), "failed": len(dies) - len(good)},
				"checks":    passed("probe"),
			},
			keys, w, by["wafer-sort"])
		if err != nil {
			return err
		}
	}

	pkg := O(sc, "packaging")
	t2, err := transfer(bundle, "wafer-sort", transfers, f2, waferLot, wafers, O(sort, "site"), O(pkg, "site"), designRef, keys, w, by["wafer-sort"])
	if err != nil {
		return err
	}

	// F3: packaging, with die-to-unit genealogy
	units, _ := Int(pkg, "units")
	genealogy := Obj{}
	var packagedUnits []string
	for i, d := range good {
		if int64(i) >= units {
			break
		}
		serial := fmt.Sprintf("%s%05d", S(pkg, "serialPrefix"), i+1)
		genealogy[serial] = Obj{"waferLot": S(waferLot, "name"), "wafer": d["wafer"], "x": d["x"], "y": d["y"]}
		packagedUnits = append(packagedUnits, serial)
	}
	if err := writeData(filepath.Join(art, "genealogy.json"), Obj{"units": genealogy}, w); err != nil {
		return err
	}
	if err := writeUnits(filepath.Join(art, "packaged-lot.txt"), packagedUnits); err != nil {
		return err
	}
	packagedDigest, err := LotDigest(packagedUnits)
	if err != nil {
		return err
	}
	packaged := rd("urn:hslsa:assembly-lot:"+S(pkg, "assemblyLot"), packagedDigest)
	genRD, err := fileRD(filepath.Join(art, "genealogy.json"), "")
	if err != nil {
		return err
	}
	f3Deps := []Obj{t2}
	if mapsRD != nil {
		f3Deps = append(f3Deps, mapsRD)
	}
	f3, err := mfgRecord(bundle, "packaging", []Obj{packaged, genRD},
		Obj{"lotId": S(pkg, "assemblyLot"), "packageType": S(pkg, "packageType")},
		f3Deps,
		Obj{
			"site":      O(pkg, "site"),
			"designRef": designRef,
			"checks":    passed("die-attach", "wire-bond", "x-ray-sample", "marking"),
		},
		keys, w, by["packaging"])
	if err != nil {
		return err
	}

	ft := O(sc, "finalTest")
	t3, err := transfer(bundle, "packaging", transfers, f3, packaged, packagedUnits, O(pkg, "site"), O(ft, "site"), designRef, keys, w, by["packaging"])
	if err != nil {
		return err
	}

	// F4: final test, names the shipped lot
	failedUnits := Strs(ft, "failedUnits")
	shipped := minus(packagedUnits, failedUnits)
	if err := writeUnits(filepath.Join(art, "shipped-lot.txt"), shipped); err != nil {
		return err
	}
	results := Obj{}
	for _, u := range packagedUnits {
		results[u] = "pass"
		if contains(failedUnits, u) {
			results[u] = "fail"
		}
	}
	if err := writeData(filepath.Join(art, "final-test-results.json"), Obj{"units": results}, w); err != nil {
		return err
	}
	shippedDigest, err := LotDigest(shipped)
	if err != nil {
		return err
	}
	shippedLot := rd("urn:hslsa:lot:"+S(ft, "lotId"), shippedDigest)
	resultsRD, err := fileRD(filepath.Join(art, "final-test-results.json"), "")
	if err != nil {
		return err
	}
	_, err = mfgRecord(bundle, "final-test", []Obj{shippedLot, resultsRD},
		Obj{"lotId": S(ft, "lotId"), "testProgram": get(ft, "program")},
		[]Obj{t3, packaged},
		Obj{
			"site":      O(ft, "site"),
			"designRef": designRef,
			"yield":     Obj{"in": len(packagedUnits), "passed": len(shipped), "failed": anyStrings(sortedCopy(failedUnits))},
			"checks":    passed("final-test-per-unit", "yield-within-limits"),
		},
		keys, w, by["final-test"])
	if err != nil {
		return err
	}
	fmt.Printf("shipped lot %s: %d units, digest %s\n", S(shippedLot, "name"), len(shipped), shippedDigest)
	return nil
}
