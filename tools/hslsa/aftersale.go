package hslsa

// Events after the first buyer (spec, "After-sale records"), on the FPGA
// board example: a firmware update in the field, a return, a rework at a
// repair site, and the board shipped out again. Each event is one signed
// record for one board, numbered from 1, linked by envelope digest to the
// one before it (the first to the board's provisioning record), so a board's
// history is a chain no one can reorder or cut short without breaking a link.
//
// The at-boot check reads the history and expects what its latest record
// says: after a field update, the update's images and reference values,
// checked the way the shipped images were; after a return, nothing until the
// board is shipped again. Firmware that changed with no update record shows
// up at boot, because the root of trust reports images the reference values
// do not hold.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// AfterSaleType is the predicate type of an after-sale record.
	AfterSaleType = NS + "/after-sale/v0.1"
	// UpdatesDir holds one directory per field update in the board bundle,
	// each laid out like the design directory: the firmware's and the flash
	// image's provenance, the flash image, its boot manifest and its CoRIM.
	UpdatesDir = "updates"
)

// AfterSaleEvents are the events, in the order a board usually meets them.
var AfterSaleEvents = []string{"field-update", "return", "rework", "reship"}

// AfterSaleSigner is the role that signs each event in the buyer's trust root.
var AfterSaleSigner = map[string]string{
	"field-update": "field-updater",
	"return":       "returns-site",
	"rework":       "repair-site",
	"reship":       boardOwnerRole,
}

func afterSaleBuildType(event string) string { return NS + "/after-sale/" + event + "@v1" }

// AfterSaleAtt is the envelope of a board's seq-th after-sale record.
func AfterSaleAtt(serial string, seq int) string {
	return fmt.Sprintf("after-sale-%s-%d.intoto.json", serial, seq)
}

// afterSaleCount is how many after-sale records a board has: 1, 2, ... until one is missing.
func afterSaleCount(bundle, serial string) int {
	n := 0
	for {
		if _, err := os.Stat(filepath.Join(bundle, "att", AfterSaleAtt(serial, n+1))); err != nil {
			return n
		}
		n++
	}
}

// afterSalePrev is the record the seq-th after-sale record links to.
func afterSalePrev(serial string, seq int) string {
	if seq == 1 {
		return "att/" + BoardProvAtt(serial)
	}
	return "att/" + AfterSaleAtt(serial, seq-1)
}

// AfterSale holds what one event's record says beyond the board and its link.
type AfterSale struct {
	Event  string
	Site   Obj   // who signs: name, country
	Body   Obj   // the event's own fields, merged into hwAfterSale
	Deps   []Obj // records and files the event used, besides the previous record
	Checks []Obj
}

// AfterSaleSimulated is the simulated mark for after-sale records, from the
// afterSale block of a scenario, or nil for records of real events.
func AfterSaleSimulated(scenarioPath string) (Obj, error) {
	if scenarioPath == "" {
		return nil, nil
	}
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return nil, err
	}
	mark := O(sc, "afterSale", "simulated")
	if err := checkSimulated(mark, "after-sale"); err != nil {
		return nil, err
	}
	return mark, nil
}

// signAfterSale signs the next record in a board's history with key.
func signAfterSale(bundle, serial string, ev AfterSale, key string, sim Obj) (string, error) {
	if AfterSaleSigner[ev.Event] == "" {
		return "", fmt.Errorf("unknown after-sale event %q (one of %s)", ev.Event, strings.Join(AfterSaleEvents, ", "))
	}
	prov, err := DecodeEnvelope(filepath.Join(bundle, "att", BoardProvAtt(serial)))
	if err != nil {
		return "", fmt.Errorf("board %s has no provisioning record: %v", serial, err)
	}
	seq := afterSaleCount(bundle, serial) + 1
	prev := afterSalePrev(serial, seq)
	board := firstSubject(prov)
	hw := Obj{
		"event":    ev.Event,
		"board":    S(board, "name"),
		"sequence": seq,
		"site":     ev.Site,
		"previous": relRD(bundle, prev),
		"checks":   nonNil(ev.Checks),
	}
	for k, v := range ev.Body {
		hw[k] = v
	}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType":            afterSaleBuildType(ev.Event),
			"externalParameters":   Obj{"board": serial, "event": ev.Event, "sequence": seq},
			"resolvedDependencies": append([]Obj{relRD(bundle, prev)}, ev.Deps...),
		},
		"runDetails": Obj{
			"builder":  Obj{"id": "urn:hslsa:site:" + slug(S(ev.Site, "name"))},
			"metadata": Obj{"invocationId": fmt.Sprintf("%s:%s:%d", ev.Event, serial, seq), "finishedOn": Now()},
		},
		"hwAfterSale": markSimulated(hw, sim),
	}
	stmt, err := statement([]Obj{board}, AfterSaleType, pred)
	if err != nil {
		return "", err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return "", err
	}
	path := filepath.Join(bundle, "att", AfterSaleAtt(serial, seq))
	if _, err := Sign(stmt, signer, path); err != nil {
		return "", err
	}
	if failed := failedChecks(ev.Checks); len(failed) > 0 {
		return path, fmt.Errorf("board %s %s: %s failed (recorded in the attestation)", serial, ev.Event, strings.Join(failed, ", "))
	}
	fmt.Printf("board %s: %s signed as record %d of its history\n", serial, ev.Event, seq)
	return path, nil
}

// FPGAUpdateBuild is the board owner building a field update in
// updates/<id> of the board bundle: the SoC firmware from lock, then a new
// flash image around it and the same released bitstream, its boot manifest
// signed by the code signer and its CoRIM, laid out as the design directory is.
func FPGAUpdateBuild(bundle, id, lockPath, scenarioPath, key, codeSigner, cache string, isolate bool) (string, error) {
	if id == "" || strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return "", fmt.Errorf("update id %q: one path element", id)
	}
	design := filepath.Join(bundle, FPGADesignDir)
	dir := filepath.Join(bundle, UpdatesDir, id)
	if _, err := os.Stat(dir); err == nil {
		return "", fmt.Errorf("%s exists; an update is built once", dir)
	}
	lock, err := ReadObj(lockPath)
	if err != nil {
		return "", err
	}
	bit := S(lock, "release", "artifact")
	for _, f := range []string{filepath.Join("att", AttName("release")), filepath.Join("artifacts", bit)} {
		if err := copyFile(filepath.Join(design, f), filepath.Join(dir, f)); err != nil {
			return "", err
		}
	}
	if err := copyFile(lockPath, filepath.Join(dir, "inputs.lock.json")); err != nil {
		return "", err
	}
	if err := FPGAFirmware(dir, lockPath, key, cache, isolate); err != nil {
		return "", err
	}
	if err := FPGAImage(dir, lockPath, scenarioPath, key, codeSigner); err != nil {
		return "", err
	}
	return dir, nil
}

// FPGAFieldUpdate is the field updater: it checks the update's flash image
// provenance, writes the image to the board's flash, raises the
// anti-rollback fuse to the update's SVN, powers the board on once and
// signs the record. update is the update's directory under the bundle.
func FPGAFieldUpdate(bundle, boards, serial, update, key string, site, sim Obj) error {
	rel, err := filepath.Rel(bundle, update)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("the update %s is not inside the bundle %s", update, bundle)
	}
	rel = filepath.ToSlash(rel)
	trust, err := LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))
	if err != nil {
		return err
	}
	flashPath := filepath.Join(update, "artifacts", FlashImage)
	flashRD := relRD(bundle, rel+"/artifacts/"+FlashImage)
	prov, provErr := trust.Open(filepath.Join(update, "att", FlashAtt), "firmware-platform", SLSAProvenance)
	provOK := provErr == nil && sha256Set(Objs(prov, "subject"))[S(flashRD, "digest", "sha256")]
	flash, err := os.ReadFile(flashPath)
	if err != nil {
		return err
	}
	manifest, err := ReadObj(filepath.Join(update, "artifacts", BootManifest))
	if err != nil {
		return err
	}
	payload, _, err := openBlob(manifest)
	if err != nil {
		return fmt.Errorf("boot manifest: %v", err)
	}
	m, err := decodeObj(payload)
	if err != nil {
		return err
	}
	svn, _ := Int(m, "svn")
	board := filepath.Join(boards, serial)
	rotDir, err := rotDirOf(board)
	if err != nil {
		return err
	}
	fuses, err := ReadObj(filepath.Join(rotDir, "fuses.json"))
	if err != nil {
		return err
	}
	if before, _ := Int(fuses, ownerFuseSVN); svn > before {
		fuses[ownerFuseSVN] = svn
		if err := WriteJSON(filepath.Join(rotDir, "fuses.json"), fuses); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(board, FlashImage), flash, 0o644); err != nil {
		return err
	}
	readback, err := sha256File(filepath.Join(board, FlashImage))
	if err != nil {
		return err
	}
	burned, err := ReadObj(filepath.Join(rotDir, "fuses.json"))
	if err != nil {
		return err
	}
	fuseSVN, _ := Int(burned, ownerFuseSVN)
	tmp, err := os.MkdirTemp("", "hslsa-update-boot-")
	if err != nil {
		return err
	}
	released, bootErr := RoTBoot(rotDir, filepath.Join(board, FlashImage), tmp)
	os.RemoveAll(tmp)
	if bootErr != nil {
		return bootErr
	}
	var images []Obj
	for _, img := range Objs(m, "images") {
		images = append(images, Obj{
			"name": get(img, "name"), "role": hbomRoleOf(S(img, "role")),
			"digest": Obj{"sha256": get(img, "sha256")}, "readback": Obj{"sha256": sha256Bytes(sliceOf(flash, img))},
		})
	}
	images = append(images, Obj{"name": FlashImage, "role": "configuration", "digest": get(flashRD, "digest"), "readback": Obj{"sha256": readback}})
	_, err = signAfterSale(bundle, serial, AfterSale{
		Event: "field-update",
		Site:  site,
		Body: Obj{
			"update": Obj{"provenance": relRD(bundle, rel+"/att/"+FlashAtt), "corim": relRD(bundle, rel+"/artifacts/"+BoardCoRIMFile), "svn": svn},
			"images": images,
			"fuses":  Obj{ownerFuseSVN: fuseSVN},
		},
		Deps: []Obj{relRD(bundle, rel+"/att/"+FlashAtt), flashRD},
		Checks: []Obj{
			check("image-provenance-verified", provOK, errDetail(provErr, "the update's flash provenance, signed by the firmware platform, names this image")),
			check("image-readback", readback == S(flashRD, "digest", "sha256"), ""),
			check("svn-fuse", fuseSVN == svn, fmt.Sprintf("anti-rollback fuse raised to the update's SVN %d", svn)),
			check("boot-released", released, "the root of trust verified the updated flash and released the FPGA"),
		},
	}, key, sim)
	return err
}

// FPGAReturn records that a board came back: from whom, why, and whether it
// will be repaired or scrapped.
func FPGAReturn(bundle, serial, key string, site, sim Obj, from, reason, disposition string) error {
	if disposition != "repair" && disposition != "scrap" {
		return fmt.Errorf("disposition %q: repair or scrap", disposition)
	}
	_, err := signAfterSale(bundle, serial, AfterSale{
		Event: "return", Site: site,
		Body:   Obj{"custody": Obj{"from": Obj{"name": from}, "to": site}, "reason": reason, "disposition": disposition},
		Checks: passed("board-received", "identity-read"),
	}, key, sim)
	return err
}

// FPGARework records parts removed from a board and placed on it, from a
// rework order: {"reason": ..., "parts": [{"refDes", "removed": {mpn,
// manufacturer, lot}, "placed": {mpn, manufacturer, lot}}]}.
func FPGARework(bundle, serial, key string, site, sim Obj, orderPath string) error {
	order, err := ReadObj(orderPath)
	if err != nil {
		return err
	}
	_, err = signAfterSale(bundle, serial, AfterSale{
		Event: "rework", Site: site,
		Body:   Obj{"reason": get(order, "reason"), "parts": A(order, "parts")},
		Checks: passed("rework-inspected", "functional-test"),
	}, key, sim)
	return err
}

// FPGAReship records the board owner shipping a board out again.
func FPGAReship(bundle, serial, key string, site, sim Obj, to, shipment string) error {
	_, err := signAfterSale(bundle, serial, AfterSale{
		Event: "reship", Site: site,
		Body:   Obj{"custody": Obj{"from": site, "to": Obj{"name": to}}, "shipment": shipment},
		Checks: passed("outgoing-inspection"),
	}, key, sim)
	return err
}

// BoardHistory is what a board's after-sale records say, as the buyer checked them.
type BoardHistory struct {
	Images  *FPGAImages // what the board should hold now
	Inputs  []Obj       // the after-sale records and the updates' provenance
	State   string      // in service, returned or scrapped
	Site    string      // where the latest record was signed
	Updates []string    // each field update's directory, relative to the bundle, oldest first
	Records int
}

// afterSaleCheck reads a board's history after its provisioning record:
// each record signed by the role for its event, numbered in order and linked
// to the one before it, each event allowed in the board's state at the time,
// each field update's images checked as the shipped ones were.
func afterSaleCheck(bundle string, trust *TrustRoot, policy, hb Obj, design *DesignResult, u *BoardUnit, shipped *FPGAImages) (*BoardHistory, error) {
	label := "board " + u.Serial
	h := &BoardHistory{Images: shipped, State: "in service"}
	bom, err := boardDesignBOM(bundle)
	if err != nil {
		return nil, err
	}
	for seq := 1; ; seq++ {
		name := AfterSaleAtt(u.Serial, seq)
		path := filepath.Join(bundle, "att", name)
		if _, err := os.Stat(path); err != nil {
			break
		}
		where := fmt.Sprintf("%s after-sale record %d", label, seq)
		raw, err := DecodeEnvelope(path)
		if err != nil {
			return nil, failf("%s: %v", where, err)
		}
		event := S(raw, "predicate", "hwAfterSale", "event")
		role := AfterSaleSigner[event]
		if role == "" {
			return nil, failf("%s: unknown event %q", where, event)
		}
		stmt, err := trust.Open(path, role, AfterSaleType)
		if err != nil {
			return nil, err
		}
		where += " (" + event + ")"
		hw := O(stmt, "predicate", "hwAfterSale")
		if buildType(stmt) != afterSaleBuildType(event) {
			return nil, failf("%s: wrong buildType", where)
		}
		if err := asSLSAProvenance(stmt, where); err != nil {
			return nil, err
		}
		if err := requireGates(stmt, where, "hwAfterSale"); err != nil {
			return nil, err
		}
		if !jsonEqual(firstSubject(stmt), firstSubject(u.Record)) || S(hw, "board") != S(firstSubject(u.Record), "name") {
			return nil, failf("%s: is about %s, not this board", where, S(hw, "board"))
		}
		if n, _ := Int(hw, "sequence"); n != int64(seq) {
			return nil, failf("%s: numbered %d", where, n)
		}
		prev := relRD(bundle, afterSalePrev(u.Serial, seq))
		if !jsonEqual(get(hw, "previous"), prev) {
			return nil, failf("%s: does not follow %s", where, S(prev, "name"))
		}
		if err := requireLink(stmt, where, []Obj{prev}, "previous record"); err != nil {
			return nil, err
		}
		if h.State == "scrapped" {
			return nil, failf("%s: comes after the board was scrapped", where)
		}
		switch event {
		case "field-update":
			images, dir, err := updateCheck(bundle, trust, policy, hb, design, stmt, h.Images, where)
			if err != nil {
				return nil, err
			}
			h.Images = images
			h.Updates = append(h.Updates, dir)
			h.Inputs = append(h.Inputs, Obj{"name": S(hw, "update", "provenance", "name"), "digest": get(hw, "update", "provenance", "digest")})
		case "return":
			if h.State != "in service" {
				return nil, failf("%s: returns a board that was not in service", where)
			}
			h.State = "returned"
			if S(hw, "disposition") == "scrap" {
				h.State = "scrapped"
			}
		case "rework":
			if h.State != "returned" {
				return nil, failf("%s: the board was not returned before it was reworked", where)
			}
			if err := reworkCheck(bom, stmt, where); err != nil {
				return nil, err
			}
		case "reship":
			if h.State != "returned" {
				return nil, failf("%s: ships a board that was not returned", where)
			}
			h.State = "in service"
		}
		h.Inputs = append(h.Inputs, relRD(bundle, "att/"+name))
		h.Site = S(hw, "site", "name")
		h.Records = seq
	}
	// A record after a gap belongs to a history someone cut: refuse it
	// rather than read the history up to the gap.
	all, err := filepath.Glob(filepath.Join(bundle, "att", "after-sale-"+u.Serial+"-*.intoto.json"))
	if err != nil {
		return nil, err
	}
	if len(all) != h.Records {
		return nil, failf("%s: has %d after-sale records, but record %d is missing", label, len(all), h.Records+1)
	}
	return h, nil
}

// inService refuses a board its history does not show in service: one
// returned and not shipped again, or scrapped.
func (h *BoardHistory) inService(serial string) error {
	switch h.State {
	case "returned":
		return failf("board %s: was returned to %s and not shipped again", serial, h.Site)
	case "scrapped":
		return failf("board %s: was returned and scrapped", serial)
	}
	return nil
}

// updateCheck checks a field update against the images the board held
// before it, and returns the images it holds now: the update's, checked as
// the shipped images were, for the same board and the same released
// bitstream, at an SVN no lower than before, written and read back.
func updateCheck(bundle string, trust *TrustRoot, policy, hb Obj, design *DesignResult, stmt Obj, before *FPGAImages, where string) (*FPGAImages, string, error) {
	hw := O(stmt, "predicate", "hwAfterSale")
	provRel := S(hw, "update", "provenance", "name")
	dir, ok := strings.CutSuffix(provRel, "/att/"+FlashAtt)
	if !ok || !strings.HasPrefix(dir, UpdatesDir+"/") || strings.Contains(dir, "..") {
		return nil, "", failf("%s: the update's flash provenance %s is not in an update directory", where, provRel)
	}
	if !jsonEqual(get(hw, "update", "provenance", "digest"), relRD(bundle, provRel)["digest"]) {
		return nil, "", failf("%s: the update's flash provenance does not match its digest", where)
	}
	set, err := fpgaImagesAt(filepath.Join(bundle, filepath.FromSlash(dir)), trust, policy, design, where+": ")
	if err != nil {
		return nil, "", err
	}
	m := set.Manifest
	if S(m, "product") != S(hb, "predicate", "product", "partNumber") || S(m, "vendor") != S(hb, "predicate", "product", "manufacturer", "name") {
		return nil, "", failf("%s: the update's boot manifest names %s %s, not this board", where, S(m, "vendor"), S(m, "product"))
	}
	svn, _ := Int(m, "svn")
	if old, _ := Int(before.Manifest, "svn"); svn < old {
		return nil, "", failf("%s: rolls the board back from SVN %d to %d", where, old, svn)
	}
	if fuse, _ := Int(hw, "fuses", ownerFuseSVN); fuse != svn {
		return nil, "", failf("%s: the anti-rollback fuse reads %d, not the update's SVN %d", where, fuse, svn)
	}
	var flash Obj
	for _, img := range Objs(hw, "images") {
		if S(img, "name") == FlashImage {
			flash = img
		}
	}
	if flash == nil || !jsonEqual(get(flash, "digest"), get(set.FlashRD, "digest")) || !jsonEqual(get(flash, "readback"), get(set.FlashRD, "digest")) {
		return nil, "", failf("%s: wrote another flash image than the update's", where)
	}
	if err := requireLink(stmt, where, []Obj{relRD(bundle, provRel)}, "update's flash provenance"); err != nil {
		return nil, "", err
	}
	return &FPGAImages{Flash: set.FlashRD, Manifest: m, RefValues: set.RefValues, Inputs: before.Inputs}, dir, nil
}

// boardDesignBOM is the board design's parts list by reference designator.
func boardDesignBOM(bundle string) (map[string]Obj, error) {
	d, err := ReadObj(filepath.Join(bundle, "artifacts", BoardDesign))
	if err != nil {
		return nil, failf("board design: %v", err)
	}
	out := map[string]Obj{}
	for _, item := range Objs(d, "bom") {
		for _, r := range Strs(item, "refDes") {
			out[r] = item
		}
	}
	return out, nil
}

// reworkCheck checks the parts a rework changed against the board design:
// each placement exists, the part removed and the part placed are the
// design's part there, and the root of trust is not among them, since a new
// root of trust is a new board identity that needs new provisioning.
func reworkCheck(bom map[string]Obj, stmt Obj, where string) error {
	parts := Objs(stmt, "predicate", "hwAfterSale", "parts")
	if len(parts) == 0 {
		return failf("%s: lists no parts", where)
	}
	for _, p := range parts {
		ref := S(p, "refDes")
		item, ok := bom[ref]
		if !ok {
			return failf("%s: %s is not a placement on this board", where, ref)
		}
		if Has(item, "rootOfTrust") {
			return failf("%s: replaces the root of trust at %s; a new root of trust is a new board identity, which needs new provisioning", where, ref)
		}
		for _, side := range []string{"removed", "placed"} {
			if S(p, side, "mpn") != S(item, "mpn") || S(p, side, "manufacturer") != S(item, "manufacturer") {
				return failf("%s: the part %s at %s is %s %s, but the board design places %s %s there", where, side, ref,
					S(p, side, "manufacturer"), S(p, side, "mpn"), S(item, "manufacturer"), S(item, "mpn"))
			}
		}
		if S(p, "placed", "lot") == "" {
			return failf("%s: the part placed at %s names no lot", where, ref)
		}
	}
	return nil
}
