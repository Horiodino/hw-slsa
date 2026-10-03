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
	"errors"
	"fmt"
	"os"
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

// mfgKeys is where a run of mfg finds its signing keys, and which roles'
// records it signs (all of them when only is nil).
type mfgKeys struct {
	dir  string
	only map[string]bool
	// sim is the scenario's simulated block, which every record this run
	// signs carries in hwMfg.
	sim Obj
	// devices is where the parts are, when the scenario provisions unit
	// identities (mfgid.go).
	devices string
	// commitment is the inspection lab's commitment to its seed (inspect.go),
	// which final test consumes as it seals the lot.
	commitment string
}

func (k *mfgKeys) signs(role string) bool { return k.only == nil || k.only[role] }

// waitingFor stops a run of mfg at a record another party has not signed yet.
type waitingFor struct{ step, role string }

func (e *waitingFor) Error() string { return e.step + ": waiting for " + e.role }

// reuse returns the record another party already signed for step, after
// checking it names the subjects this run computed, so a later site's
// records link to exactly what the earlier site signed.
func (k *mfgKeys) reuse(bundle, step, att, role string, subjects []Obj) (Obj, error) {
	path := filepath.Join(bundle, "att", att)
	if _, err := os.Stat(path); err != nil {
		return nil, &waitingFor{step, role}
	}
	stmt, err := DecodeEnvelope(path)
	if err != nil {
		return nil, err
	}
	if !jsonEqual(A(stmt, "subject"), anyObjs(subjects)) {
		return nil, fmt.Errorf("%s: the record %s signed names other subjects than this scenario gives; was it signed from another scenario?", step, role)
	}
	fmt.Printf("%s: kept the record %s signed\n", step, role)
	return fileRD(path, "att/"+att)
}

func anyObjs(list []Obj) []any {
	out := make([]any, len(list))
	for i, o := range list {
		out[i] = o
	}
	return out
}

func slug(name string) string { return strings.ReplaceAll(strings.ToLower(name), " ", "-") }

// mfgRecord signs one manufacturing record with the site's own key, or,
// when by is set (see onBehalf), with the key of the party signing on the
// supplier's behalf.
func mfgRecord(bundle, step string, subjects []Obj, external Obj, deps []Obj, hw Obj, keys *mfgKeys, w *Withholding, by Obj) (Obj, error) {
	att, role, bt, hwStep := mfgNames(step)
	hw = markSimulated(hw, keys.sim)
	if by != nil {
		role = S(by, "role")
	}
	if !keys.signs(role) {
		return keys.reuse(bundle, step, att, role, subjects)
	}
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
	signer, err := LoadSigner(filepath.Join(keys.dir, role+".key.pem"))
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
func transfer(bundle, scenarioDir, from string, enabled bool, ev, prev, lot Obj, items []string, fromSite, toSite, designRef Obj, keys *mfgKeys, w *Withholding, by Obj) (Obj, error) {
	if !enabled {
		return prev, removeStale(filepath.Join(bundle, "att", TransferAtt(from)), filepath.Join(bundle, "artifacts", TransferList(from)),
			disclosurePath(filepath.Join(bundle, "att", TransferAtt(from))), filepath.Join(bundle, "artifacts", ExportName("transfer-"+from)))
	}
	path := filepath.Join(bundle, "artifacts", TransferList(from))
	id := from + ":" + S(lot, "name")
	data := Obj{"id": id, "from": fromSite, "to": toSite, "lot": S(lot, "name"), "items": anyStrings(items), "quantity": len(items)}
	hw := Obj{"site": fromSite, "receiver": toSite, "designRef": designRef, "checks": passed("packing-list-matches-lot")}
	deps, err := attachTransferExports(bundle, scenarioDir, ev, []Obj{prev, lot}, hw, data)
	if err != nil {
		return nil, err
	}
	if err := writeData(path, data, w); err != nil {
		return nil, err
	}
	list, err := fileRD(path, "")
	if err != nil {
		return nil, err
	}
	return mfgRecord(bundle, "transfer-"+from, []Obj{list}, Obj{"id": id, "lotId": S(lot, "name")}, deps, hw, keys, w, shipperProxy(by))
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
	return MfgAs(bundle, scenarioPath, keys, w, nil)
}

// MfgAs is Mfg for a party that holds only some of the lot's keys: it signs
// the records of the roles it names and reuses the records already in the
// bundle for the others, so each site signs its own steps with a key no
// other party holds. It stops, without error, at the first step whose
// record is neither its own nor in the bundle yet, and says whose it is.
// No roles means every role, with every key in keys.
func MfgAs(bundle, scenarioPath, keysDir string, w *Withholding, roles []string) error {
	return MfgWith(bundle, scenarioPath, keysDir, w, roles, "")
}

// MfgWith is MfgAs for a scenario that provisions unit identities: devices
// is the directory that holds the parts, one directory per die and then per
// unit, which wafer sort fills and final test challenges.
func MfgWith(bundle, scenarioPath, keysDir string, w *Withholding, roles []string, devices string) error {
	return MfgInspected(bundle, scenarioPath, keysDir, w, roles, devices, "")
}

// MfgInspected is MfgWith for a lot an independent lab will inspect (L4):
// final test consumes the lab's commitment to its sampling seed, at
// commitment, as it seals the lot.
func MfgInspected(bundle, scenarioPath, keysDir string, w *Withholding, roles []string, devices, commitment string) error {
	keys := &mfgKeys{dir: keysDir, devices: devices, commitment: commitment}
	if len(roles) > 0 {
		if w != nil && (len(w.Fields) > 0 || len(w.SaltFiles) > 0) {
			return fmt.Errorf("signing only some roles' records cannot withhold fields yet: each run rewrites the data files")
		}
		keys.only = setOf(roles)
	}
	err := mfg(bundle, scenarioPath, keys, w)
	var wait *waitingFor
	if errors.As(err, &wait) {
		fmt.Printf("stopped before %s: its record is signed by %s, whose key is not in this run\n", wait.step, wait.role)
		return nil
	}
	return err
}

func mfg(bundle, scenarioPath string, keys *mfgKeys, w *Withholding) error {
	art := filepath.Join(bundle, "artifacts")
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	scenarioDir := filepath.Dir(scenarioPath)
	keys.sim = O(sc, "simulated")
	if err := checkSimulated(keys.sim, "scenario"); err != nil {
		return err
	}
	if O(sc, "adapter") != nil && w != nil && (len(w.Fields) > 0 || len(w.SaltFiles) > 0) {
		return fmt.Errorf("a lot made from supplier exports cannot withhold fields yet: the exports it carries hold every value")
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
	var ident *identityRun
	if b := O(sc, "identity"); b != nil {
		if keys.devices == "" {
			return fmt.Errorf("the scenario provisions unit identities; name the directory that holds the parts (--devices)")
		}
		for _, step := range []string{"wafer-sort", "packaging", "final-test"} {
			if by[step] != nil {
				return fmt.Errorf("%s: provisioning unit identities needs the site's own record, not one signed on its behalf", step)
			}
		}
		ident = &identityRun{block: b, devices: keys.devices}
	}

	// F1: wafer fabrication
	fab, lot := O(sc, "fab"), O(sc, "waferLot")
	wafers := Strs(lot, "wafers")
	waferDigest, err := LotDigest(wafers)
	if err != nil {
		return err
	}
	waferLot := rd(fmt.Sprintf("urn:hslsa:wafer-lot:%s:%s", S(fab, "id"), S(lot, "lotId")), waferDigest)
	f1Checks := stepChecks(fab, "mask-vs-gds-xor", "inline-parametrics")
	f1Base := []Obj{releaseRD}
	// The fab's own check of the release (Wafer L3), when it ran one: F1
	// consumes it, and the mask XOR names the design it compared against.
	if rc := filepath.Join(bundle, "att", FabReleaseCheckAtt); fileExists(rc) {
		rcRD, err := fileRD(rc, "att/"+FabReleaseCheckAtt)
		if err != nil {
			return err
		}
		f1Base = append(f1Base, rcRD)
		for _, c := range f1Checks {
			if S(c, "name") == "mask-vs-gds-xor" {
				c["against"] = Obj{"name": S(final, "name"), "digest": O(final, "digest")}
			}
		}
	}
	f1HW := Obj{"site": O(fab, "site"), "designRef": designRef, "checks": f1Checks}
	f1Deps, err := attachExports(bundle, scenarioDir, sc, "wafer-fab", f1Base, f1HW)
	if err != nil {
		return err
	}
	f1, err := mfgRecord(bundle, "wafer-fab", []Obj{waferLot},
		Obj{"lotId": S(lot, "lotId"), "maskSetId": S(fab, "maskSetId"), "processNode": S(fab, "processNode")},
		f1Deps, f1HW, keys, w, by["wafer-fab"])
	if err != nil {
		return err
	}
	sort := O(sc, "sort")
	transfers := Truthy(get(sc, "transfers"))
	t1, err := transfer(bundle, scenarioDir, "wafer-fab", transfers, O(sc, "transferEvents", "wafer-fab"), f1, waferLot, wafers, O(fab, "site"), O(sort, "site"), designRef, keys, w, by["wafer-fab"])
	if err != nil {
		return err
	}

	// F2: wafer sort, one map entry per die
	dies, err := sortDies(sort, wafers)
	if err != nil {
		return err
	}
	var good []Obj
	for _, d := range dies {
		if d["bin"] == "pass" {
			good = append(good, d)
		}
	}
	var f2, mapsRD, idsRD Obj
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
		f2HW := Obj{
			"site":      O(sort, "site"),
			"designRef": designRef,
			"yield":     Obj{"in": len(dies), "passed": len(good), "failed": len(dies) - len(good)},
			"checks":    passed("probe"),
		}
		f2Subjects := []Obj{mapsRD}
		if ident != nil {
			if idsRD, err = ident.provision(bundle, good, S(waferLot, "name"), S(final, "digest", "sha256"), keys, w); err != nil {
				return err
			}
			f2Subjects = append(f2Subjects, idsRD)
			f2HW["identity"] = Obj{"rootOfTrust": S(ident.block, "rootOfTrust"), "ca": S(ident.block, "ca"), "provisioned": len(good)}
			f2HW["checks"] = passed("probe", "identity-provisioned")
		}
		f2Deps, err := attachExports(bundle, scenarioDir, sc, "wafer-sort", []Obj{t1, waferLot}, f2HW)
		if err != nil {
			return err
		}
		f2, err = mfgRecord(bundle, "wafer-sort", f2Subjects,
			Obj{"lotId": S(lot, "lotId"), "probeProgram": get(sort, "program")},
			f2Deps, f2HW, keys, w, by["wafer-sort"])
		if err != nil {
			return err
		}
	}

	pkg := O(sc, "packaging")
	t2, err := transfer(bundle, scenarioDir, "wafer-sort", transfers, O(sc, "transferEvents", "wafer-sort"), f2, waferLot, wafers, O(sort, "site"), O(pkg, "site"), designRef, keys, w, by["wafer-sort"])
	if err != nil {
		return err
	}

	// F3: packaging, with die-to-unit genealogy
	genealogy, packagedUnits, err := packageDies(pkg, good, S(waferLot, "name"))
	if err != nil {
		return err
	}
	// At L3 a unit is named by its die's certificate digest, not its serial.
	var bySerial map[string]string
	if ident != nil {
		if genealogy, packagedUnits, bySerial, err = ident.nameUnits(genealogy, packagedUnits, keys.signs(MfgSigner["packaging"])); err != nil {
			return err
		}
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
	f3HW := Obj{
		"site":      O(pkg, "site"),
		"designRef": designRef,
		"checks":    stepChecks(pkg, "die-attach", "wire-bond", "x-ray-sample", "marking"),
	}
	if idsRD != nil {
		f3Deps = append(f3Deps, idsRD)
		f3HW["identity"] = Obj{"lotNaming": "certificate"}
	}
	if f3Deps, err = attachExports(bundle, scenarioDir, sc, "packaging", f3Deps, f3HW); err != nil {
		return err
	}
	f3, err := mfgRecord(bundle, "packaging", []Obj{packaged, genRD},
		Obj{"lotId": S(pkg, "assemblyLot"), "packageType": S(pkg, "packageType")},
		f3Deps, f3HW, keys, w, by["packaging"])
	if err != nil {
		return err
	}

	ft := O(sc, "finalTest")
	t3, err := transfer(bundle, scenarioDir, "packaging", transfers, O(sc, "transferEvents", "packaging"), f3, packaged, packagedUnits, O(pkg, "site"), O(ft, "site"), designRef, keys, w, by["packaging"])
	if err != nil {
		return err
	}

	// F4: final test, names the shipped lot
	failedUnits := Strs(ft, "failedUnits")
	var transcript Obj
	if ident != nil {
		failedUnits = unitIDs(failedUnits, bySerial)
		var noAnswer []string
		if keys.signs(MfgSigner["final-test"]) {
			if transcript, noAnswer, err = ident.challenge(genealogy, packagedUnits); err != nil {
				return err
			}
			if err := writeData(filepath.Join(art, IdentityChallenges), transcript, w); err != nil {
				return err
			}
		} else if transcript, err = ReadObj(filepath.Join(art, IdentityChallenges)); err != nil {
			return &waitingFor{"final-test", MfgSigner["final-test"]}
		} else {
			noAnswer = minus(packagedUnits, sortedKeys(O(transcript, "units")))
		}
		failedUnits = append(minus(failedUnits, noAnswer), noAnswer...)
	}
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
	f4HW := Obj{
		"site":      O(ft, "site"),
		"designRef": designRef,
		"yield":     Obj{"in": len(packagedUnits), "passed": len(shipped), "failed": anyStrings(sortedCopy(failedUnits))},
		"checks":    passed("final-test-per-unit", "yield-within-limits"),
	}
	f4Subjects := []Obj{shippedLot, resultsRD}
	if transcript != nil {
		challengesRD, err := fileRD(filepath.Join(art, IdentityChallenges), "")
		if err != nil {
			return err
		}
		f4Subjects = append(f4Subjects, challengesRD)
		f4HW["identity"] = Obj{"lotNaming": "certificate", "challenge": ChallengeFormat}
		f4HW["checks"] = passed("final-test-per-unit", "yield-within-limits", "identity-challenge")
	}
	f4Deps, err := attachExports(bundle, scenarioDir, sc, "final-test", []Obj{t3, packaged}, f4HW)
	if err != nil {
		return err
	}
	if keys.signs(MfgSigner["final-test"]) {
		commit, err := consumeCommitment(bundle, keys.commitment, S(shippedLot, "name"))
		if err != nil {
			return err
		}
		if commit != nil {
			f4Deps = append(f4Deps, commit)
		}
		if Truthy(get(ft, "unitCommitment")) {
			if f4HW["unitCommitment"], err = commitUnits(bundle, S(shippedLot, "name"), shipped); err != nil {
				return err
			}
		}
	}
	_, err = mfgRecord(bundle, "final-test", f4Subjects,
		Obj{"lotId": S(ft, "lotId"), "testProgram": get(ft, "program")},
		f4Deps, f4HW, keys, w, by["final-test"])
	if err != nil {
		return err
	}
	fmt.Printf("shipped lot %s: %d units, digest %s\n", S(shippedLot, "name"), len(shipped), shippedDigest)
	return nil
}

// stepChecks is a step's checks as the scenario gives them (the adapter
// reads them from the MES), or the named checks, passed.
func stepChecks(block Obj, names ...string) []Obj {
	if c := Objs(block, "checks"); len(c) > 0 {
		return c
	}
	return passed(names...)
}

// sortDies is the wafer map: the scenario's sort.dies as the adapter read
// them from the tester, or a sort.grid of dies on every wafer with
// sort.failedDies failing.
func sortDies(sort Obj, wafers []string) ([]Obj, error) {
	var dies []Obj
	if Has(sort, "dies") {
		inLot := setOf(wafers)
		for _, d := range Objs(sort, "dies") {
			x, okX := Int(d, "x")
			y, okY := Int(d, "y")
			bin := S(d, "bin")
			if !inLot[S(d, "wafer")] || !okX || !okY || (bin != "pass" && bin != "fail") {
				return nil, fmt.Errorf("scenario sort.dies: each needs a wafer of the lot, integer x and y, and a bin of pass or fail")
			}
			dies = append(dies, Obj{"wafer": S(d, "wafer"), "x": x, "y": y, "bin": bin})
		}
		return dies, nil
	}
	failedDies := map[string]bool{}
	for _, d := range A(sort, "failedDies") {
		t, _ := d.([]any)
		if len(t) == 3 {
			failedDies[dieKey(t[0], t[1], t[2])] = true
		}
	}
	grid := A(sort, "grid")
	if len(grid) != 2 {
		return nil, fmt.Errorf("scenario sort.grid must be [columns, rows]")
	}
	gx, _ := Int(grid[0])
	gy, _ := Int(grid[1])
	for _, w := range wafers {
		for y := int64(0); y < gy; y++ {
			for x := int64(0); x < gx; x++ {
				bin := "pass"
				if failedDies[dieKey(w, x, y)] {
					bin = "fail"
				}
				dies = append(dies, Obj{"wafer": w, "x": x, "y": y, "bin": bin})
			}
		}
	}
	return dies, nil
}

// packageDies is the die-to-unit genealogy: the scenario's
// packaging.genealogy as the adapter read it from the OSAT's MES, each unit
// on a passing die no other unit holds, or packaging.units serials on the
// first passing dies.
func packageDies(pkg Obj, good []Obj, waferLot string) (Obj, []string, error) {
	genealogy := Obj{}
	var units []string
	if g := O(pkg, "genealogy"); g != nil {
		passing, used := map[string]bool{}, map[string]bool{}
		for _, d := range good {
			passing[dieKey(d["wafer"], d["x"], d["y"])] = true
		}
		for _, serial := range sortedKeys(g) {
			e := O(g, serial)
			x, _ := Int(e, "x")
			y, _ := Int(e, "y")
			k := dieKey(S(e, "wafer"), x, y)
			if !passing[k] || used[k] {
				return nil, nil, fmt.Errorf("scenario packaging.genealogy: %s is not on a passing die no other unit holds", serial)
			}
			used[k] = true
			genealogy[serial] = Obj{"waferLot": waferLot, "wafer": S(e, "wafer"), "x": x, "y": y}
			units = append(units, serial)
		}
		return genealogy, units, nil
	}
	n, _ := Int(pkg, "units")
	for i, d := range good {
		if int64(i) >= n {
			break
		}
		serial := fmt.Sprintf("%s%05d", S(pkg, "serialPrefix"), i+1)
		genealogy[serial] = Obj{"waferLot": waferLot, "wafer": d["wafer"], "x": d["x"], "y": d["y"]}
		units = append(units, serial)
	}
	return genealogy, units, nil
}
