package hslsa

// Assembly track: a board built from the example chip and off-the-shelf parts.
//
// The board carries the PicoSoC from the chip chain plus commodity parts that
// have no HBOM of their own. Every lot reaches the assembler through a signed
// distribution record (a distributor, or a manufacturer shipping direct), the
// EMS runs the chip's lot receipt check before placement and signs A1 against
// each board serial and the chip serial placed on it (after signing a receipt
// VSA for the chips it received), and the board owner
// signs a board HBOM whose parts[] points at those records.
//
// As with the chip, the physical data (shipments, placements, board test
// results) comes from a scenario file; every signature, digest link and check
// is real.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	BoardA1        = "mfg-a1-board-assembly.intoto.json"
	BoardHBOM      = "hbom.intoto.json"
	BoardDesign    = "board-design.json"
	BoardBuild     = "board-build.json"
	BoardLot       = "board-lot.txt"
	emsRole        = "ems-site"
	boardOwnerRole = "board-owner"
)

// ShipAtt is the envelope file name of one shipment's distribution record.
func ShipAtt(shipmentID string) string { return "mfg-distribution-" + shipmentID + ".intoto.json" }

// ReceiptAtt is the envelope file name of the receipt VSA the EMS signs for
// the units of one chip lot it received.
func ReceiptAtt(lotID string) string { return "receipt-" + lotID + ".vsa.intoto.json" }

// boardRD is a board subject: its URN plus the digest of its serial (UTF-8, no
// newline) until boards carry an identity certificate.
func boardRD(manufacturer, serial string) Obj {
	return rd(fmt.Sprintf("urn:hslsa:board:%s:%s", slug(manufacturer), serial), sha256Bytes([]byte(serial)))
}

// relRD describes a file in the bundle by its path relative to the bundle.
func relRD(bundle, rel string) Obj {
	return Obj{"name": rel, "digest": fileDigest(filepath.Join(bundle, rel))}
}

func boardRecord(bundle, step, name string, subjects []Obj, external Obj, deps []Obj, hw Obj, key string) (Obj, error) {
	hwMfg := Obj{"step": step, "confidential": []any{}}
	for k, v := range hw {
		hwMfg[k] = v
	}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType":            mfgStepType(step),
			"externalParameters":   external,
			"resolvedDependencies": nonNil(deps),
		},
		"runDetails": Obj{
			"builder":  Obj{"id": "urn:hslsa:site:" + slug(S(hw, "site", "name"))},
			"metadata": Obj{"invocationId": step + ":" + S(external, "id"), "finishedOn": Now()},
		},
		"hwMfg": hwMfg,
	}
	stmt, err := statement(subjects, MfgStep, pred)
	if err != nil {
		return nil, err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return nil, err
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", name)); err != nil {
		return nil, err
	}
	fmt.Printf("%s %s: signed by %s\n", step, S(external, "id"), strings.TrimSuffix(filepath.Base(key), ".key.pem"))
	return relRD(bundle, "att/"+name), nil
}

// ChipCheck is the buyer's tapeout and lot receipt check on a chip bundle,
// with the bundle's own trust root and policy. Tests may replace it.
var ChipCheck = func(chip string, units []string) (*LotResult, error) {
	trust, err := LoadTrustRoot(filepath.Join(chip, "trust-root.json"))
	if err != nil {
		return nil, err
	}
	policy, err := ReadObj(filepath.Join(chip, "policy.json"))
	if err != nil {
		return nil, err
	}
	design, err := TapeoutCheck(chip, trust, policy, true)
	if err != nil {
		return nil, err
	}
	return LotCheck(chip, trust, policy, design, units)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyTree copies a directory of regular files.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(path, target)
	})
}

type shipLine struct {
	ship Obj
	line Obj
}

// BoardProduce signs the shipments, A1 and the board HBOM for a board built on the chip bundle.
func BoardProduce(bundle, chipBundle, scenarioPath, designPath, policyPath, keys string) error {
	return boardProduceWith(bundle, chipBundle, scenarioPath, designPath, policyPath, keys, nil)
}

// boardProduceWith is BoardProduce with a hook that adds to the board HBOM's
// predicate before it is validated and signed.
func boardProduceWith(bundle, chipBundle, scenarioPath, designPath, policyPath, keys string, extend func(predicate Obj) error) error {
	art := filepath.Join(bundle, "artifacts")
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	pol, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	boardDesign, err := ReadObj(designPath)
	if err != nil {
		return err
	}
	for _, sub := range []string{"att", "artifacts", "parts"} {
		if err := os.RemoveAll(filepath.Join(bundle, sub)); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(art, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(bundle, "att"), 0o755); err != nil {
		return err
	}

	// The chip vendor's bundle travels with the chips.
	chipRel := S(sc, "chip", "bundle")
	chipMPN := S(sc, "chip", "mpn")
	chip := filepath.Join(bundle, chipRel)
	if err := copyTree(chipBundle, chip); err != nil {
		return err
	}
	if err := copyFile(designPath, filepath.Join(art, BoardDesign)); err != nil {
		return err
	}
	design, err := fileRD(filepath.Join(art, BoardDesign), "")
	if err != nil {
		return err
	}

	// Distribution: one signed record per shipment into the EMS.
	var ships []Obj
	lines := map[string]shipLine{}
	for _, s := range Objs(sc, "shipments") {
		id := S(s, "id")
		shipFile := filepath.Join(art, "shipment-"+id+".json")
		if err := WriteJSON(shipFile, s); err != nil {
			return err
		}
		var deps []Obj
		for _, line := range Objs(s, "lines") {
			lines[S(line, "mpn")] = shipLine{s, line}
			if S(line, "mpn") == chipMPN {
				units, err := ReadUnits(filepath.Join(chip, "artifacts", "shipped-lot.txt"))
				if err != nil {
					return err
				}
				d, err := LotDigest(units)
				if err != nil {
					return err
				}
				deps = append(deps, rd("urn:hslsa:lot:"+S(line, "lot"), d))
			}
		}
		subject, err := fileRD(shipFile, "")
		if err != nil {
			return err
		}
		role := S(pol, "shippers", S(s, "shipper", "name"), "role")
		env, err := boardRecord(bundle, "distribution", ShipAtt(id), []Obj{subject},
			Obj{"id": id, "shipDate": get(s, "shipDate")}, deps,
			Obj{"site": get(s, "shipper"), "checks": passed("certificate-of-conformance", "traceable-to-manufacturer")},
			filepath.Join(keys, role+".key.pem"))
		if err != nil {
			return err
		}
		ships = append(ships, env)
	}

	// A1: the EMS checks the chip lot before placement, then builds and tests each board.
	chipLine, ok := lines[chipMPN]
	if !ok {
		return fmt.Errorf("no shipment carries the chip %s", chipMPN)
	}
	chipUnits := Strs(chipLine.line, "units")
	chipResult, err := ChipCheck(chip, chipUnits)
	if err != nil {
		return err
	}
	chipLot := chipResult.Lot
	fmt.Printf("part lot receipt check: PASSED for %s, %d units received\n", S(chipLot, "name"), len(chipUnits))
	// The EMS records the receipt: a VSA over exactly the units it received,
	// under the chip bundle's policy, naming the chip records it checked.
	receipt, err := ReceiptSubject(S(chipLot, "name"), chipUnits)
	if err != nil {
		return err
	}
	chipPolicy, err := ReadObj(filepath.Join(chip, "policy.json"))
	if err != nil {
		return err
	}
	var checked []Obj
	for _, in := range chipResult.Inputs {
		checked = append(checked, Obj{"name": chipRel + "/" + S(in, "name"), "digest": get(in, "digest")})
	}
	receiptName := ReceiptAtt(S(chipLine.line, "lot"))
	if err := signVSA(receipt, S(chipLot, "name"), get(chipPolicy, "claims", "lot"), checked, filepath.Join(chip, "policy.json"),
		filepath.Join(keys, emsRole+".key.pem"), filepath.Join(bundle, "att", receiptName)); err != nil {
		return err
	}
	fmt.Printf("receipt %s: signed by %s for %d units\n", S(receipt, "name"), emsRole, len(chipUnits))
	asm := O(sc, "assembly")
	mfr := S(sc, "product", "manufacturer", "name")
	failedBoards := Strs(asm, "failedBoards")
	boardsBuilt, _ := Int(asm, "boards")
	next := 0
	builds := Obj{}
	var serials []string
	for i := int64(0); i < boardsBuilt; i++ {
		serial := fmt.Sprintf("%s%04d", S(asm, "serialPrefix"), i+1)
		placements := Obj{}
		for _, item := range Objs(boardDesign, "bom") {
			sl, ok := lines[S(item, "mpn")]
			if !ok {
				return fmt.Errorf("no shipment carries %s", S(item, "mpn"))
			}
			for _, refDes := range Strs(item, "refDes") {
				p := Obj{"mpn": get(sl.line, "mpn"), "lot": get(sl.line, "lot")}
				if S(sl.line, "mpn") == chipMPN {
					if next >= len(chipUnits) {
						return fmt.Errorf("more %s placed than were shipped", chipMPN)
					}
					p["unit"] = chipUnits[next]
					next++
				}
				placements[refDes] = p
			}
		}
		result := "pass"
		if contains(failedBoards, serial) {
			result = "fail"
		}
		builds[serial] = Obj{"placements": placements, "result": result}
		serials = append(serials, serial)
	}
	if err := WriteJSON(filepath.Join(art, BoardBuild), builds); err != nil {
		return err
	}
	var boards []string
	for _, s := range serials {
		if S(builds, s, "result") == "pass" {
			boards = append(boards, s)
		}
	}
	sort.Strings(boards)
	if err := writeUnits(filepath.Join(art, BoardLot), boards); err != nil {
		return err
	}
	boardLotDigest, err := LotDigest(boards)
	if err != nil {
		return err
	}
	boardLot := rd("urn:hslsa:lot:"+S(asm, "boardLot"), boardLotDigest)
	subjects := []Obj{boardLot}
	for _, s := range boards {
		subjects = append(subjects, boardRD(mfr, s))
	}
	buildRD, err := fileRD(filepath.Join(art, BoardBuild), "")
	if err != nil {
		return err
	}
	subjects = append(subjects, buildRD)
	deps := append([]Obj{}, ships...)
	deps = append(deps,
		relRD(bundle, chipRel+"/att/"+BoardHBOM),
		relRD(bundle, chipRel+"/att/mfg-f4-final-test.intoto.json"),
		relRD(bundle, "att/"+receiptName),
		chipLot, design)
	if _, err := boardRecord(bundle, "board-assembly", BoardA1, subjects,
		Obj{"id": S(asm, "boardLot"), "boardDesign": BoardDesign}, deps,
		Obj{
			"site":      get(asm, "site"),
			"designRef": Obj{"name": design["name"], "digest": design["digest"]},
			"yield":     Obj{"in": len(serials), "passed": len(boards), "failed": anyStrings(sortedCopy(failedBoards))},
			"checks":    passed("part-lot-receipt-check", "aoi", "x-ray-sample", "ict", "functional-test"),
		},
		filepath.Join(keys, emsRole+".key.pem")); err != nil {
		return err
	}

	// Board HBOM: parts[] carries the distributor lot data and points at each shipment record.
	var parts []Obj
	for _, item := range Objs(boardDesign, "bom") {
		sl := lines[S(item, "mpn")]
		shipper := S(sl.ship, "shipper", "name")
		part := Obj{
			"refDes":          get(item, "refDes"),
			"manufacturer":    Obj{"name": get(sl.line, "manufacturer")},
			"mpn":             get(sl.line, "mpn"),
			"dateCode":        get(sl.line, "dateCode"),
			"lot":             get(sl.line, "lot"),
			"distributor":     get(sl.ship, "shipper"),
			"authorized":      contains(Strs(pol, "shippers", shipper, "authorizedFor"), S(sl.line, "manufacturer")),
			"distributionRef": fileRef(bundle, "att/"+ShipAtt(S(sl.ship, "id"))),
		}
		if S(sl.line, "mpn") == chipMPN {
			part["hbomRef"] = fileRef(bundle, chipRel+"/att/"+BoardHBOM)
		}
		if Has(item, "rootOfTrust") {
			part["rootOfTrust"] = get(item, "rootOfTrust")
		}
		parts = append(parts, part)
	}
	predicate := Obj{
		"hbomVersion": "0.1",
		"product":     get(sc, "product"),
		"design":      Obj{"finalLayout": fileRef(bundle, "artifacts/"+BoardDesign)},
		"manufacturing": Obj{
			"boardAssembly": Obj{
				"ems":            get(asm, "site"),
				"boardLot":       get(asm, "boardLot"),
				"attestationRef": fileRef(bundle, "att/"+BoardA1),
			},
		},
		"parts": nonNil(parts),
	}
	if extend != nil {
		if err := extend(predicate); err != nil {
			return err
		}
	}
	if err := ValidateHBOM(predicate); err != nil {
		return err
	}
	stmt, err := statement([]Obj{design, boardLot}, HBOMType, predicate)
	if err != nil {
		return err
	}
	if err := addRenderings(stmt, filepath.Join(bundle, "att"), "file:att/"); err != nil {
		return err
	}
	if err := ValidateHBOM(predicate); err != nil {
		return err
	}
	owner, err := LoadSigner(filepath.Join(keys, boardOwnerRole+".key.pem"))
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, owner, filepath.Join(bundle, "att", BoardHBOM)); err != nil {
		return err
	}
	fmt.Printf("board hbom: signed, %d part lines, board lot %s of %d boards\n", len(parts), S(boardLot, "name"), len(boards))
	return nil
}

// The buyer's check for the board

type partLine struct {
	part Obj
	line Obj
}

// BoardCheck reports every missing record first, then verifies the board
// HBOM, A1, every shipment and part with the EMS's receipt for it, and the
// board lot; received may be nil.
func BoardCheck(bundle string, trust *TrustRoot, policyPath string, received []string) (*LotResult, error) {
	art := filepath.Join(bundle, "artifacts")
	pol, err := ReadObj(policyPath)
	if err != nil {
		return nil, err
	}
	if err := gapError("board receipt check", boardGaps(bundle)); err != nil {
		return nil, err
	}
	shippers := O(pol, "shippers")

	label := "board hbom"
	hb, err := trust.Open(filepath.Join(bundle, "att", BoardHBOM), boardOwnerRole, HBOMType)
	if err != nil {
		return nil, err
	}
	if err := ValidateHBOM(get(hb, "predicate")); err != nil {
		return nil, err
	}
	if level := S(hb, "predicate", "product", "level"); !contains([]string{"module", "board", "system"}, level) {
		return nil, failf("%s: product level is %s, not a board", label, level)
	}
	hbSubjects := Objs(hb, "subject")
	if len(hbSubjects) != 2 {
		return nil, failf("%s: expected the board design and the board lot as subjects", label)
	}
	designSubj, lotSubj := hbSubjects[0], hbSubjects[1]
	if err := requireFiles(bundle, Obj{"subject": []any{designSubj}}, label); err != nil {
		return nil, err
	}
	boardDesign, err := ReadObj(filepath.Join(art, S(designSubj, "name")))
	if err != nil {
		return nil, failf("%s: board design: %v", label, err)
	}

	label = "board-assembly"
	a1, err := trust.Open(filepath.Join(bundle, "att", BoardA1), emsRole, MfgStep)
	if err != nil {
		return nil, err
	}
	if buildType(a1) != mfgStepType("board-assembly") {
		return nil, failf("%s: wrong buildType", label)
	}
	if err := asSLSAProvenance(a1, label); err != nil {
		return nil, err
	}
	if err := requireGates(a1, label, "hwMfg"); err != nil {
		return nil, err
	}
	if err := requireFiles(bundle, a1, label); err != nil {
		return nil, err
	}
	hw := O(a1, "predicate", "hwMfg")
	if !jsonEqual(get(hw, "designRef", "digest"), get(designSubj, "digest")) {
		return nil, failf("%s: designRef names a different board design", label)
	}
	if err := requireLink(a1, label, []Obj{rd(S(designSubj, "name"), S(designSubj, "digest", "sha256"))}, "board design"); err != nil {
		return nil, err
	}
	a1RD := relRD(bundle, "att/"+BoardA1)
	asmRef := O(hb, "predicate", "manufacturing", "boardAssembly", "attestationRef")
	if S(asmRef, "uri") != "file:att/"+BoardA1 || !jsonEqual(get(asmRef, "digest"), a1RD["digest"]) {
		return nil, failf("board hbom: boardAssembly reference does not match the A1 record")
	}
	if !jsonEqual(lotSubj, firstSubject(a1)) {
		return nil, failf("board hbom: lot subject does not match the A1 board lot")
	}

	// parts[]: every lot traces to a signed shipment whose data matches, through an allowed channel.
	byRefDes := map[string]partLine{}
	shipments := map[string]Obj{}
	inputs := []Obj{a1RD}
	for _, part := range Objs(hb, "predicate", "parts") {
		mpn, lot, mfr := S(part, "mpn"), S(part, "lot"), S(part, "manufacturer", "name")
		dist := S(part, "distributor", "name")
		if !Has(part, "distributionRef") || !Has(shippers, dist) {
			return nil, failf("parts: %s has no distribution record from a shipper in the policy", mpn)
		}
		rel := strings.TrimPrefix(S(part, "distributionRef", "uri"), "file:")
		if _, seen := shipments[rel]; !seen {
			label := "distribution " + filepath.Base(rel)
			ship, err := trust.Open(filepath.Join(bundle, rel), S(shippers, dist, "role"), MfgStep)
			if err != nil {
				return nil, err
			}
			if buildType(ship) != mfgStepType("distribution") {
				return nil, failf("%s: wrong buildType", label)
			}
			if err := asSLSAProvenance(ship, label); err != nil {
				return nil, err
			}
			if err := requireGates(ship, label, "hwMfg"); err != nil {
				return nil, err
			}
			if err := requireFiles(bundle, ship, label); err != nil {
				return nil, err
			}
			data, err := ReadObj(filepath.Join(art, S(firstSubject(ship), "name")))
			if err != nil {
				return nil, failf("%s: shipment: %v", label, err)
			}
			shipments[rel] = data
			inputs = append(inputs, relRD(bundle, rel))
		}
		if !jsonEqual(get(part, "distributionRef", "digest"), relRD(bundle, rel)["digest"]) {
			return nil, failf("parts: %s distribution reference does not match its digest", mpn)
		}
		if err := requireLink(a1, "board-assembly", []Obj{relRD(bundle, rel)}, "shipment record"); err != nil {
			return nil, err
		}
		ship := shipments[rel]
		if S(ship, "shipper", "name") != dist {
			return nil, failf("parts: %s names distributor %s but shipment %s came from %s", mpn, dist, S(ship, "id"), S(ship, "shipper", "name"))
		}
		var line Obj
		for _, ln := range Objs(ship, "lines") {
			if S(ln, "mpn") == mpn && S(ln, "manufacturer") == mfr {
				line = ln
				break
			}
		}
		if line == nil || !jsonEqual(get(line, "lot"), get(part, "lot")) || !jsonEqual(get(line, "dateCode"), get(part, "dateCode")) {
			return nil, failf("parts: %s lot %s does not match the distributor's shipment %s", mpn, num(get(part, "lot")), S(ship, "id"))
		}
		channel := contains(Strs(shippers, dist, "authorizedFor"), mfr)
		if Truthy(get(part, "authorized")) && !channel {
			return nil, failf("parts: %s is not an authorized channel for %s, but %s claims it is", dist, mfr, mpn)
		}
		if Truthy(get(pol, "requireAuthorizedChannel")) && !Truthy(get(part, "authorized")) {
			return nil, failf("parts: policy requires an authorized channel, and %s lot %s was not bought through one", mpn, lot)
		}
		if Has(part, "hbomRef") {
			if err := partCheck(bundle, trust, a1, part, line); err != nil {
				return nil, err
			}
		}
		for _, r := range Strs(part, "refDes") {
			byRefDes[r] = partLine{part, line}
		}
	}

	// The HBOM covers exactly the board design, and every placement is a listed lot.
	designRefDes := map[string]string{}
	for _, item := range Objs(boardDesign, "bom") {
		for _, r := range Strs(item, "refDes") {
			designRefDes[r] = S(item, "mpn")
		}
	}
	for _, r := range sortedKeys(designRefDes) {
		pl, ok := byRefDes[r]
		if !ok || S(pl.part, "mpn") != designRefDes[r] {
			return nil, failf("parts: board design %s (%s) has no matching part in the HBOM", r, designRefDes[r])
		}
	}
	var extra []string
	for _, r := range sortedKeys(byRefDes) {
		if _, ok := designRefDes[r]; !ok {
			extra = append(extra, r)
		}
	}
	if len(extra) > 0 {
		return nil, failf("parts: HBOM lists %s, which the board design does not have", strings.Join(extra, ", "))
	}

	builds, err := ReadObj(filepath.Join(art, BoardBuild))
	if err != nil {
		return nil, failf("board-assembly: build records: %v", err)
	}
	used := map[string]int64{}
	units := map[string]bool{}
	for _, serial := range sortedKeys(builds) {
		placements := O(builds, serial, "placements")
		if !sameSet(sortedKeys(placements), sortedKeys(designRefDes)) {
			return nil, failf("board-assembly: board %s placements do not match the board design", serial)
		}
		for _, r := range sortedKeys(placements) {
			p := O(placements, r)
			pl := byRefDes[r]
			if S(p, "mpn") != S(pl.part, "mpn") || !jsonEqual(get(p, "lot"), get(pl.part, "lot")) {
				return nil, failf("board-assembly: board %s %s is %s lot %s, which the HBOM does not list", serial, r, S(p, "mpn"), num(get(p, "lot")))
			}
			used[S(p, "mpn")+"\x00"+num(get(p, "lot"))]++
			if Has(pl.line, "units") {
				unit := S(p, "unit")
				if !Has(p, "unit") || !contains(Strs(pl.line, "units"), unit) {
					return nil, failf("board-assembly: board %s %s unit %s was never shipped to the EMS", serial, r, num(get(p, "unit")))
				}
				if units[unit] {
					return nil, failf("board-assembly: unit %s is placed on more than one board", unit)
				}
				units[unit] = true
			}
		}
	}
	checked := map[string]bool{}
	for _, r := range sortedKeys(byRefDes) {
		pl := byRefDes[r]
		id := fmt.Sprintf("%p", pl.line)
		if checked[id] {
			continue
		}
		checked[id] = true
		qty, _ := Int(pl.line, "quantity")
		if used[S(pl.part, "mpn")+"\x00"+num(get(pl.part, "lot"))] > qty {
			return nil, failf("board-assembly: more %s lot %s placed than were shipped", S(pl.part, "mpn"), num(get(pl.part, "lot")))
		}
	}

	// Board lot and yield.
	boards, err := ReadUnits(filepath.Join(art, BoardLot))
	if err != nil {
		return nil, failf("board-assembly: board lot list: %v", err)
	}
	if d, err := LotDigest(boards); err != nil || d != S(lotSubj, "digest", "sha256") {
		return nil, failf("board-assembly: board lot list does not match the attested lot digest")
	}
	var good []string
	for _, s := range sortedKeys(builds) {
		if S(builds, s, "result") == "pass" {
			good = append(good, s)
		}
	}
	if !equalStrings(sortedCopy(boards), good) {
		return nil, failf("board-assembly: board lot is not the set of boards that passed test")
	}
	passedCount, _ := Int(hw, "yield", "passed")
	if !equalStrings(minus(sortedKeys(builds), good), sortedCopy(Strs(hw, "yield", "failed"))) || passedCount != int64(len(good)) {
		return nil, failf("board-assembly: yield record does not account for every board built")
	}
	mfr := S(hb, "predicate", "product", "manufacturer", "name")
	subjects := map[string]any{}
	for _, s := range Objs(a1, "subject") {
		subjects[S(s, "name")] = get(s, "digest")
	}
	for _, serial := range boards {
		b := boardRD(mfr, serial)
		if !jsonEqual(subjects[S(b, "name")], b["digest"]) {
			return nil, failf("board-assembly: board %s is not a subject of the A1 record", serial)
		}
	}

	for _, serial := range received {
		if !contains(boards, serial) {
			return nil, failf("received board %s is not in the board lot", serial)
		}
	}
	return &LotResult{Lot: lotSubj, Inputs: append([]Obj{relRD(bundle, "att/"+BoardHBOM)}, inputs...)}, nil
}

// partCheck runs a part's own chain checks when it has an HBOM, checks the
// EMS's receipt VSA for the units it received, and binds the lot, the HBOM
// and the receipt to A1.
func partCheck(bundle string, trust *TrustRoot, a1, part, line Obj) error {
	mpn := S(part, "mpn")
	rel := strings.TrimPrefix(S(part, "hbomRef", "uri"), "file:")
	chip := filepath.Dir(filepath.Dir(filepath.Join(bundle, rel)))
	if !jsonEqual(get(part, "hbomRef", "digest"), relRD(bundle, rel)["digest"]) {
		return failf("parts: %s hbomRef does not match its digest", mpn)
	}
	var units []string
	if Has(line, "units") {
		units = Strs(line, "units")
	}
	result, err := ChipCheck(chip, units)
	if err != nil {
		if IsVerificationError(err) {
			return failf("parts: %s lot receipt check failed: %s", mpn, err.Error())
		}
		return err
	}
	chipHBOM, err := DecodeEnvelope(filepath.Join(bundle, rel))
	if err != nil {
		return failf("parts: %s hbomRef: %v", mpn, err)
	}
	if pn := S(chipHBOM, "predicate", "product", "partNumber"); pn != mpn {
		return failf("parts: %s hbomRef is the HBOM of %s", mpn, pn)
	}
	if S(result.Lot, "name") != "urn:hslsa:lot:"+S(part, "lot") {
		return failf("parts: board claims %s lot %s, but its HBOM names %s", mpn, S(part, "lot"), S(result.Lot, "name"))
	}
	receiptRel := "att/" + ReceiptAtt(S(part, "lot"))
	if err := receiptCheck(bundle, trust, chip, receiptRel, result.Lot, units, mpn); err != nil {
		return err
	}
	return requireLink(a1, "board-assembly", []Obj{result.Lot, relRD(bundle, rel), relRD(bundle, receiptRel)}, mpn+" lot, HBOM and receipt")
}

// receiptCheck verifies the receipt VSA the EMS signed for the units of a
// chip lot it received: it passed under the chip bundle's policy, states
// that policy's lot levels, and covers exactly the units shipped to the EMS.
func receiptCheck(bundle string, trust *TrustRoot, chip, rel string, lot Obj, units []string, mpn string) error {
	label := mpn + " receipt " + filepath.Base(rel)
	stmt, err := trust.Open(filepath.Join(bundle, rel), emsRole, VSAType)
	if err != nil {
		return err
	}
	p := O(stmt, "predicate")
	if S(p, "verifier", "id") != VerifierID || S(p, "verificationResult") != "PASSED" {
		return failf("%s: not a passed lot receipt check", label)
	}
	policyPath := filepath.Join(chip, "policy.json")
	policyDigest, err := sha256File(policyPath)
	if err != nil {
		return err
	}
	if S(p, "policy", "digest", "sha256") != policyDigest {
		return failf("%s: checked under another policy than the chip's", label)
	}
	policy, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	for _, l := range Strs(policy, "claims", "lot") {
		if !contains(Strs(p, "verifiedLevels"), l) {
			return failf("%s: does not state %s", label, l)
		}
	}
	want, err := ReceiptSubject(S(lot, "name"), units)
	if err != nil {
		return failf("%s: %v", label, err)
	}
	got := Objs(stmt, "subject")
	if len(got) != 1 || S(got[0], "name") != S(want, "name") || !jsonEqual(get(got[0], "digest"), get(want, "digest")) ||
		S(p, "resourceUri") != S(lot, "name") {
		return failf("%s: covers other units than the %d shipped to the EMS", label, len(units))
	}
	return nil
}

// BoardVerify runs the board receipt check, then signs the board VSA when vsaKey is set.
func BoardVerify(bundle string, trust *TrustRoot, policyPath, boardsPath, vsaKey, vsaDir string) (*LotResult, error) {
	var received []string
	if boardsPath != "" {
		var err error
		if received, err = ReadUnits(boardsPath); err != nil {
			return nil, err
		}
	}
	result, err := BoardCheck(bundle, trust, policyPath, received)
	if err != nil {
		return nil, err
	}
	lot := result.Lot
	msg := fmt.Sprintf("board receipt check: PASSED for %s sha256:%s", S(lot, "name"), S(lot, "digest", "sha256"))
	if len(received) > 0 {
		msg += fmt.Sprintf(", %d received boards found in the lot", len(received))
	}
	fmt.Println(msg)
	if err := renderingsCheck(bundle, filepath.Join(bundle, "att", BoardHBOM), "board hbom"); err != nil {
		return nil, err
	}
	if vsaKey != "" {
		pol, err := ReadObj(policyPath)
		if err != nil {
			return nil, err
		}
		claims := get(pol, "claims", "board")
		out := filepath.Join(vsaDir, "board.vsa.intoto.json")
		if err := signVSA(lot, S(lot, "name"), claims, result.Inputs, policyPath, vsaKey, out); err != nil {
			return nil, err
		}
		fmt.Printf("VSA written to %s: board %s\n", out, pyList(claims))
	}
	return result, nil
}
