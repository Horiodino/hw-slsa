package hslsa

// FPGA board example (e2e/fpga): the board, its root of trust and the checks.
//
// The board carries a Lattice iCE40UP5K (no secure-boot ROM, so the bare part
// stops at Firmware L1), a SPI flash holding its bitstream and the soft CPU's
// firmware, and EXR-01, a root of trust with its own chip chain (rot.go). The
// root of trust holds the FPGA's CRESET_B low until it has verified every
// image in flash against a boot manifest signed by the board owner's code
// signer. That makes the board, not the FPGA, a Firmware L2 claim under the
// spec's board-level root of trust rule.
//
//	produce    the board chain from board.go (shipments, A1, board HBOM) with
//	           the images and the root of trust in the board HBOM
//	provision  per board at the EMS: the owner fuses burned into the root of
//	           trust, the flash written, a first power-on, one signed record
//	boot       power on a board: the root of trust's ROM and firmware, then
//	           the SoC booting the firmware in RTL simulation
//	verify     every buyer check, then VSAs for the design, the board lot and
//	           each booted board

import (
	"bytes"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	FPGADesignDir  = "design"
	BootRecord     = "boot.json"
	ownerFuseHash  = "owner_key_hash"
	ownerFuseMan   = "manifest_offset"
	ownerFuseSVN   = "owner_min_svn"
	fpgaHBOMRoleBS = "configuration"
	fpgaHBOMRoleFW = "runtime"
)

// BoardProvAtt is the EMS's provisioning record for one board.
func BoardProvAtt(serial string) string { return "prov-board-" + serial + ".intoto.json" }

func boardURN(manufacturer, serial string) string {
	return fmt.Sprintf("urn:hslsa:board:%s:%s", slug(manufacturer), serial)
}

// rotPart finds the root of trust in a board design or HBOM: the one entry with a rootOfTrust block.
func rotPart(entries []Obj, label string) (Obj, error) {
	var found []Obj
	for _, e := range entries {
		if Has(e, "rootOfTrust") {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		return nil, failf("%s: expected one part marked as the board's root of trust, found %d", label, len(found))
	}
	if len(Strs(found[0], "refDes")) != 1 {
		return nil, failf("%s: the root of trust must be one placement", label)
	}
	return found[0], nil
}

// FPGABoardProduce copies the board owner's design bundle into the board
// bundle and signs the board chain, with the images in flash and the root of
// trust that verifies them in the board HBOM.
func FPGABoardProduce(bundle, rotBundle, designBundle, scenarioPath, designPath, policyPath, keys string, phys *BoardParts) error {
	design := filepath.Join(bundle, FPGADesignDir)
	if err := os.RemoveAll(design); err != nil {
		return err
	}
	if err := copyTree(designBundle, design); err != nil {
		return err
	}
	lock, err := ReadObj(filepath.Join(design, "inputs.lock.json"))
	if err != nil {
		return fmt.Errorf("design bundle: %v", err)
	}
	extend := func(p Obj) error {
		art := FPGADesignDir + "/artifacts/"
		bit := S(lock, "release", "artifact")
		corim := fileRef(bundle, art+BoardCoRIMFile)
		corim["mediaType"] = CoRIMMediaType
		p["firmware"] = []Obj{
			{
				"name": bit, "version": S(lock, "firmware", "version"), "role": fpgaHBOMRoleBS, "storage": "external-flash",
				"digest":             fileDigest(filepath.Join(bundle, art+bit)),
				"referenceValuesRef": corim,
				"provenanceRef":      fileRef(bundle, FPGADesignDir+"/att/"+AttName("release")),
			},
			{
				"name": FPGAFWImage, "version": S(lock, "firmware", "version"), "role": fpgaHBOMRoleFW, "storage": "external-flash",
				"digest":             fileDigest(filepath.Join(bundle, art+FPGAFWImage)),
				"sbomRef":            fileRef(bundle, art+FPGAFWSBOM),
				"referenceValuesRef": corim,
				"provenanceRef":      fileRef(bundle, FPGADesignDir+"/att/"+FPGAFWAtt),
			},
		}
		return nil
	}
	return boardProduceWith(bundle, rotBundle, scenarioPath, designPath, policyPath, keys, phys, extend)
}

// rotUnitOn is the root of trust unit the EMS placed on a board, from its build records.
func rotUnitOn(bundle, serial, refDes string) (string, error) {
	builds, err := ReadObj(filepath.Join(bundle, "artifacts", BoardBuild))
	if err != nil {
		return "", err
	}
	unit := S(builds, serial, "placements", refDes, "unit")
	if unit == "" {
		return "", fmt.Errorf("board %s has no root of trust unit at %s", serial, refDes)
	}
	return unit, nil
}

// The EMS's programming station, prog-01, is a simulated in-circuit
// programmer, the "Example ICP-2". Like a real one it knows nothing about
// HSLSA: it runs a program file and writes its own export (program.ini, a
// tab-separated log, readback/, identity/), and the provisioning adapter
// (provadapter.go) signs one record per board from it, with the root of
// trust the station found on each board. Its profile is
// e2e/stations/icp2-profile.json; the station file is
// e2e/fpga/station/prog-01.json.

const (
	icp2Program  = "program.ini"
	icp2Log      = "icp2.log"
	icp2Region   = "SPI0"
	icp2Time     = "02.01.2006 15:04:05"
	icp2Pass     = "P"
	icp2Fail     = "F"
	icp2RoTField = "rot"
)

// icp2OTPInt are the owner fuses the program file gives as numbers.
var icp2OTPInt = map[string]bool{ownerFuseMan: true, ownerFuseSVN: true}

// FPGABoardJob writes the EMS's program file for the board lot: the flash
// image to write, the owner fuses to burn into the root of trust (the hash of
// the board owner's code signer key, the boot manifest's offset and the
// anti-rollback value), and where the root of trust sits on the board.
func FPGABoardJob(bundle, scenarioPath, codeSigner, export string) error {
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	boardDesign, err := ReadObj(filepath.Join(art, BoardDesign))
	if err != nil {
		return err
	}
	rot, err := rotPart(Objs(boardDesign, "bom"), "board design")
	if err != nil {
		return err
	}
	design := filepath.Join(bundle, FPGADesignDir)
	lock, err := ReadObj(filepath.Join(design, "inputs.lock.json"))
	if err != nil {
		return err
	}
	ownerHash, err := keyHash(codeSigner)
	if err != nil {
		return err
	}
	svn, _ := Int(lock, "firmware", "svn")
	manOff, _ := Int(lock, "flash", "manifestOffset")
	if err := os.RemoveAll(export); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(export, "images"), 0o755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(design, "artifacts", FlashImage), filepath.Join(export, "images", FlashImage)); err != nil {
		return err
	}
	d, err := sha256File(filepath.Join(export, "images", FlashImage))
	if err != nil {
		return err
	}
	lot := S(sc, "assembly", "boardLot")
	name := "PRG-" + lot
	var b strings.Builder
	fmt.Fprintf(&b, "; Example ICP-2 program\n[program]\nname = %s\nassembly = %s rev %s\nlot = %s\n",
		name, S(sc, "product", "partNumber"), S(sc, "product", "revision"), lot)
	fmt.Fprintf(&b, "\n[load flash]\nimage = images/%s\ntarget = %s\nsha256 = %s\n", FlashImage, icp2Region, d)
	fmt.Fprintf(&b, "\n[otp]\n%s = %s\n%s = 0x%x\n%s = %d\n", ownerFuseHash, ownerHash, ownerFuseMan, manOff, ownerFuseSVN, svn)
	fmt.Fprintf(&b, "\n[parts]\n%s = %s\n", icp2RoTField, Strs(rot, "refDes")[0])
	if err := os.WriteFile(filepath.Join(export, icp2Program), []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("board program: %s writes %s and burns the owner fuses into the root of trust at %s\n", name, FlashImage, Strs(rot, "refDes")[0])
	return nil
}

// icp2Logger is the ICP-2's log as it writes it.
type icp2Logger struct {
	w    *csv.Writer
	last time.Time
}

func (l *icp2Logger) row(board, step, ref, data string, ok bool) error {
	t := time.Now().UTC().Truncate(time.Second)
	if t.Before(l.last) {
		t = l.last
	}
	l.last = t
	outcome := icp2Pass
	if !ok {
		outcome = icp2Fail
	}
	return l.w.Write([]string{t.Format(icp2Time), board, step, ref, data, outcome})
}

// FPGABoardStation runs the program on every board of the board lot: it
// reads the serial of the root of trust it finds on the board, burns the
// owner fuses into it, writes the flash and reads it back, reads the fuses
// back, asks the root of trust for its IDevID CSR, and powers the board once
// to see the root of trust release the FPGA. A board without its root of
// trust yet gets the unit the A1 record placed there, from devices, which
// stands in for the assembly line; a board that has one keeps it. boards
// gets each board's state; export gets what the station writes.
func FPGABoardStation(bundle, devices, boards, export string) error {
	data, err := os.ReadFile(filepath.Join(export, icp2Program))
	if err != nil {
		return err
	}
	job, err := parseINI(data)
	if err != nil {
		return err
	}
	rotRef := job.get("parts." + icp2RoTField)
	if rotRef == "" {
		return fmt.Errorf("%s: no [parts] %s", icp2Program, icp2RoTField)
	}
	lotBoards, err := ReadUnits(filepath.Join(bundle, "artifacts", BoardLot))
	if err != nil {
		return err
	}
	for _, d := range []string{"readback", "identity"} {
		if err := os.MkdirAll(filepath.Join(export, d), 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(filepath.Join(export, icp2Log))
	if err != nil {
		return err
	}
	defer f.Close()
	log := &icp2Logger{w: csv.NewWriter(f)}
	log.w.Comma = '\t'
	if err := log.w.Write([]string{"When", "Board", "Step", "Ref", "Data", "Outcome"}); err != nil {
		return err
	}
	load := job.values["load flash"]
	otp := job.values["otp"]
	for _, serial := range lotBoards {
		board := filepath.Join(boards, serial)
		rotDir, err := placedRoT(bundle, devices, board, serial, rotRef)
		if err != nil {
			return err
		}
		if err := log.row(serial, "OPEN", "", job.get("program.name"), true); err != nil {
			return err
		}
		// The root of trust tells the station which unit it is.
		fuses, err := ReadObj(filepath.Join(rotDir, "fuses.json"))
		if err != nil {
			return err
		}
		if err := log.row(serial, "ROT_SERIAL", rotRef, S(fuses, "serial"), S(fuses, "serial") != ""); err != nil {
			return err
		}
		for _, k := range sortedKeys(otp) {
			var v any = otp[k]
			if icp2OTPInt[k] {
				n, err := strconv.ParseInt(otp[k], 0, 64)
				if err != nil {
					return fmt.Errorf("%s: [otp] %s: %v", icp2Program, k, err)
				}
				v = n
			}
			fuses[k] = v
			if err := log.row(serial, "ROT_OTP_SET", k, otp[k], true); err != nil {
				return err
			}
		}
		if err := WriteJSON(filepath.Join(rotDir, "fuses.json"), fuses); err != nil {
			return err
		}
		image, err := os.ReadFile(filepath.Join(export, filepath.FromSlash(load["image"])))
		if err != nil {
			return err
		}
		flash := filepath.Join(board, FlashImage)
		if err := os.WriteFile(flash, image, 0o644); err != nil {
			return err
		}
		if err := log.row(serial, "SPI_PROG", load["target"], load["image"], true); err != nil {
			return err
		}
		back, err := os.ReadFile(flash)
		if err != nil {
			return err
		}
		dump := "readback/" + serial + "/" + load["target"] + ".bin"
		if err := os.MkdirAll(filepath.Join(export, "readback", serial), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(export, filepath.FromSlash(dump)), back, 0o644); err != nil {
			return err
		}
		if err := log.row(serial, "SPI_VERIFY", load["target"], dump, sha256Bytes(back) == load["sha256"]); err != nil {
			return err
		}
		burned, err := ReadObj(filepath.Join(rotDir, "fuses.json"))
		if err != nil {
			return err
		}
		for _, k := range sortedKeys(otp) {
			if err := log.row(serial, "ROT_OTP_GET", k, xg8Value(burned[k]), true); err != nil {
				return err
			}
		}
		// The root of trust answers with a CSR signed by its IDevID key.
		csrDER, err := RoTCSR(rotDir)
		if err != nil {
			return err
		}
		csrFile := "identity/" + serial + "-" + rotRef + ".csr.der"
		if err := os.WriteFile(filepath.Join(export, csrFile), csrDER, 0o644); err != nil {
			return err
		}
		if err := log.row(serial, "ROT_CSR", rotRef, csrFile, true); err != nil {
			return err
		}
		// First power-on: the root of trust must verify the flash and release the FPGA.
		tmp, err := os.MkdirTemp("", "hslsa-firstboot-")
		if err != nil {
			return err
		}
		released, err := RoTBoot(rotDir, flash, tmp)
		os.RemoveAll(tmp)
		if err != nil {
			return err
		}
		state := "released"
		if !released {
			state = "held in reset"
		}
		if err := log.row(serial, "POWER_UP", "FPGA", state, released); err != nil {
			return err
		}
		if err := log.row(serial, "CLOSE", "", "", true); err != nil {
			return err
		}
	}
	log.w.Flush()
	if err := log.w.Error(); err != nil {
		return err
	}
	fmt.Printf("station prog-01: %d boards programmed, export in %s\n", len(lotBoards), export)
	return nil
}

// placedRoT is the root of trust on a board: the part the EMS placed itself
// (Assembly L3), a copy put on the board earlier, or else the unit the A1
// record says was placed there, copied from devices as the line would have.
func placedRoT(bundle, devices, board, serial, refDes string) (string, error) {
	if dir := filepath.Join(board, refDes); hasDie(dir) {
		return dir, os.RemoveAll(filepath.Join(board, FlashImage))
	}
	if dir := filepath.Join(board, "rot"); fileExists(filepath.Join(dir, "fuses.json")) {
		return dir, nil
	}
	unit, err := rotUnitOn(bundle, serial, refDes)
	if err != nil {
		return "", err
	}
	if devices == "" {
		return "", fmt.Errorf("board %s has no root of trust yet, and no --devices to place %s from", serial, unit)
	}
	if err := os.RemoveAll(board); err != nil {
		return "", err
	}
	dir := filepath.Join(board, "rot")
	if err := copyTree(filepath.Join(devices, unit), dir); err != nil {
		return "", fmt.Errorf("board %s: root of trust %s: %v", serial, unit, err)
	}
	return dir, nil
}

func hbomRoleOf(manifestRole string) string {
	if manifestRole == RoleBitstream {
		return fpgaHBOMRoleBS
	}
	return fpgaHBOMRoleFW
}

func sliceOf(flash []byte, img Obj) []byte {
	off, _ := Int(img, "offset")
	n, _ := Int(img, "length")
	if off < 0 || n < 0 || off+n > int64(len(flash)) {
		return nil
	}
	return flash[off : off+n]
}

// FPGABoot powers on one board: the root of trust verifies the flash and, if
// it releases the FPGA, the SoC boots the firmware from that flash in RTL
// simulation of the frozen design. Everything the board returns goes to out:
// the root of trust's DICE certificates, its log, the SoC's UART output and
// boot.json. Set sim to nil to skip the SoC.
func FPGABoot(board string, sim *SoCSim, out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	flashPath := filepath.Join(board, FlashImage)
	rotDir, err := rotDirOf(board)
	if err != nil {
		return err
	}
	released, err := RoTBoot(rotDir, flashPath, out)
	if err != nil {
		return err
	}
	rec := Obj{"released": released}
	if released && sim != nil {
		flash, err := os.ReadFile(flashPath)
		if err != nil {
			return err
		}
		off, _ := Int(sim.lock, "flash", "firmwareOffset")
		if off > int64(len(flash)) {
			return fmt.Errorf("flash has no firmware region")
		}
		run, err := sim.Boot(flash[off:])
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "soc-uart.txt"), []byte(run.UART), 0o644); err != nil {
			return err
		}
		rec["soc"] = Obj{"simulated": "RTL", "finished": run.Finished, "uartBanner": run.BannerSeen}
	}
	return WriteJSON(filepath.Join(out, BootRecord), rec)
}

// rotDirOf is the root of trust on a board: rot/ where the EMS's station put
// a copy of the unit, or the placement holding the part the EMS placed.
func rotDirOf(board string) (string, error) {
	if _, err := os.Stat(filepath.Join(board, "rot")); err == nil {
		return filepath.Join(board, "rot"), nil
	}
	found, err := filepath.Glob(filepath.Join(board, "*", "fuses.json"))
	if err != nil {
		return "", err
	}
	if len(found) != 1 {
		return "", fmt.Errorf("%s: no root of trust on the board", board)
	}
	return filepath.Dir(found[0]), nil
}

// FPGABootAll boots every board listed in boardsPath; the SoC runs the
// frozen RTL from the board bundle's copy of the design bundle.
func FPGABootAll(bundle, boards, boardsPath, out string, soc bool) error {
	serials, err := ReadUnits(boardsPath)
	if err != nil {
		return err
	}
	var sim *SoCSim
	if soc {
		// Every board runs the same frozen RTL, so compile it once.
		design := filepath.Join(bundle, FPGADesignDir)
		lock, err := ReadObj(filepath.Join(design, "inputs.lock.json"))
		if err != nil {
			return err
		}
		sim, err = NewSoCSim(filepath.Join(design, "artifacts", "source.tar"), lock)
		if err != nil {
			return err
		}
		defer sim.Close()
	}
	for _, s := range serials {
		if err := FPGABoot(filepath.Join(boards, s), sim, filepath.Join(out, s)); err != nil {
			return err
		}
		rec, err := ReadObj(filepath.Join(out, s, BootRecord))
		if err != nil {
			return err
		}
		msg := "root of trust held the FPGA in reset"
		if Truthy(rec["released"]) {
			msg = "root of trust released the FPGA"
			if Has(rec, "soc") {
				msg += fmt.Sprintf("; SoC banner on UART: %v", Truthy(get(rec, "soc", "uartBanner")))
			}
		}
		fmt.Printf("boot %s: %s\n", s, msg)
	}
	return nil
}

// The buyer's checks

// RoTResult is what the root of trust check vouches for: its firmware and its vendor's keys.
type RoTResult struct {
	Part      Obj // the board HBOM's parts[] entry
	Bundle    string
	Trust     *TrustRoot
	Policy    Obj
	Design    *DesignResult
	RefValues []RefValue
	Image     Obj
	Signature Obj // the firmware's signature, which its ROM checks
	Inputs    []Obj
}

// RoTCheck is the board-level root of trust rule: the part the board HBOM
// marks as its root of trust has its own chain (HBOM, design, lot), its
// firmware has provenance, an SBOM, a CoRIM and a vendor signature at
// Firmware L2, it guards the parts that run the board's images, and it
// verifies every image the board HBOM lists.
func RoTCheck(bundle string, hb Obj, policy Obj) (*RoTResult, error) {
	label := "root of trust"
	part, err := rotPart(Objs(hb, "predicate", "parts"), "board hbom")
	if err != nil {
		return nil, err
	}
	if S(part, "mpn") != S(policy, "rootOfTrust", "mpn") {
		return nil, failf("%s: board names %s, the policy accepts %s", label, S(part, "mpn"), S(policy, "rootOfTrust", "mpn"))
	}
	if !Has(part, "hbomRef") {
		return nil, failf("%s: %s has no HBOM of its own, so it is not attested", label, S(part, "mpn"))
	}
	var parts []string
	for _, p := range Objs(hb, "predicate", "parts") {
		parts = append(parts, Strs(p, "refDes")...)
	}
	for _, g := range Strs(part, "rootOfTrust", "guards") {
		if !contains(parts, g) {
			return nil, failf("%s: guards %s, which is not on the board", label, g)
		}
	}
	for _, want := range Strs(policy, "rootOfTrust", "mustGuard") {
		if !contains(Strs(part, "rootOfTrust", "guards"), want) {
			return nil, failf("%s: does not hold %s in reset", label, want)
		}
	}
	var external []string
	for _, f := range Objs(hb, "predicate", "firmware") {
		if S(f, "storage") == "external-flash" {
			external = append(external, S(f, "name"))
		}
	}
	if len(external) == 0 || !sameSet(external, Strs(part, "rootOfTrust", "images")) {
		return nil, failf("%s: verifies %s, but the board's flash holds %s", label,
			strings.Join(Strs(part, "rootOfTrust", "images"), ", "), strings.Join(external, ", "))
	}

	// The part's own chain: BoardCheck already ran its lot receipt check through hbomRef.
	rel := strings.TrimPrefix(S(part, "hbomRef", "uri"), "file:")
	rotBundle := filepath.Dir(filepath.Dir(filepath.Join(bundle, rel)))
	trust, rotPolicy, err := partTrust(rotBundle)
	if err != nil {
		return nil, err
	}
	design, err := TapeoutCheck(rotBundle, trust, rotPolicy, true)
	if err != nil {
		return nil, err
	}

	// Firmware L2 for the root of trust itself.
	fl := "root of trust firmware"
	fw, err := trust.Open(filepath.Join(rotBundle, "att", RoTFWAtt), "firmware-platform", SLSAProvenance)
	if err != nil {
		return nil, err
	}
	if buildType(fw) != GoBuildType {
		return nil, failf("%s: wrong buildType", fl)
	}
	if err := asSLSAProvenance(fw, fl); err != nil {
		return nil, err
	}
	if err := requireFiles(rotBundle, fw, fl); err != nil {
		return nil, err
	}
	subjects := map[string]Obj{}
	for _, s := range Objs(fw, "subject") {
		subjects[S(s, "name")] = s
	}
	image, sigRD := subjects[RoTFWImage], subjects[RoTFWSig]
	if image == nil || sigRD == nil {
		return nil, failf("%s: provenance does not name the image and its signature", fl)
	}
	byproducts := map[string]Obj{}
	for _, b := range Objs(fw, "predicate", "runDetails", "byproducts") {
		byproducts[S(b, "name")] = b
		if d := fileDigest(filepath.Join(rotBundle, "artifacts", S(b, "name"))); d == nil || !jsonEqual(d, get(b, "digest")) {
			return nil, failf("%s: %s is missing or does not match its digest", fl, S(b, "name"))
		}
	}
	if byproducts[RoTSBOM] == nil || byproducts[RoTCoRIMFile] == nil {
		return nil, failf("%s: no SBOM or no CoRIM", fl)
	}
	sig, err := ReadObj(filepath.Join(rotBundle, "artifacts", RoTFWSig))
	if err != nil {
		return nil, failf("%s: signature: %v", fl, err)
	}
	payload, signerHash, err := openBlob(sig)
	if err != nil {
		return nil, failf("%s: signature: %v", fl, err)
	}
	vendorHash := ""
	for _, k := range trust.Roles["code-signer"] {
		if d, err := spkiDigest(k.Public); err == nil && d == signerHash {
			vendorHash = d
		}
	}
	if vendorHash == "" {
		return nil, failf("%s: not signed by the vendor's code signer", fl)
	}
	meta, err := decodeObj(payload)
	if err != nil || S(meta, "sha256") != S(image, "digest", "sha256") {
		return nil, failf("%s: the vendor signature names another image", fl)
	}
	rim, err := OpenCoRIM(filepath.Join(rotBundle, "artifacts", RoTCoRIMFile), trust.Roles["firmware-platform"], "root of trust CoRIM")
	if err != nil {
		return nil, err
	}
	svn, _ := Int(meta, "svn")
	s := uint64(svn)
	layer := uint64(1)
	want := []RefValue{{Env: DiceEnv{Type: RoTFWTcbType, Vendor: RoTVendor, Model: RoTModel, Layer: &layer}, Digests: []FWID{{SHA256OID, S(image, "digest", "sha256")}}, SVN: &s}}
	if !sameRefValues(rim.RefValues, want) {
		return nil, failf("root of trust CoRIM: reference values differ from the image provenance")
	}
	rotHBOM, err := trust.Open(filepath.Join(rotBundle, "att", BoardHBOM), "product-owner", HBOMType)
	if err != nil {
		return nil, err
	}
	listed := false
	for _, f := range Objs(rotHBOM, "predicate", "firmware") {
		if S(f, "name") == RoTFWImage && S(f, "digest", "sha256") == S(image, "digest", "sha256") {
			listed = true
		}
	}
	if !listed {
		return nil, failf("root of trust hbom: does not list the firmware with provenance")
	}
	return &RoTResult{
		Part: part, Bundle: rotBundle, Trust: trust, Policy: rotPolicy, Design: design,
		RefValues: rim.RefValues, Image: image, Signature: sigRD,
		Inputs: []Obj{relRD(bundle, filepath.Join(rel)), relRD(bundle, filepath.ToSlash(filepath.Join(filepath.Dir(filepath.Dir(rel)), "att", RoTFWAtt)))},
	}, nil
}

// rotUnitCheck checks the root of trust vendor's provisioning record for one
// unit: signed by its test site, every gate passed, the unit's IDevID
// endorsed by the vendor's identity CA, the firmware written is the one with
// provenance, and the vendor key hash fuse is the vendor's code signer.
func rotUnitCheck(r *RoTResult, unit string) (Obj, *x509.Certificate, error) {
	label := "root of trust " + unit
	rec, err := r.Trust.Open(filepath.Join(r.Bundle, "att", RoTProvAtt(unit)), S(r.Policy, "firmware", "provisioningSigner"), FWProvisioning)
	if err != nil {
		return nil, nil, err
	}
	if buildType(rec) != ProvisionType {
		return nil, nil, failf("%s: provisioning record has the wrong buildType", label)
	}
	if err := asSLSAProvenance(rec, label+" provisioning"); err != nil {
		return nil, nil, err
	}
	hp := O(rec, "predicate", "hwProvision")
	if failed := failedChecks(Objs(hp, "checks")); len(failed) > 0 {
		return nil, nil, failf("%s: provisioning gate failed: %s", label, strings.Join(failed, ", "))
	}
	if S(hp, "unit") != "urn:hslsa:unit:"+unit || S(firstSubject(rec), "name") != S(hp, "unit") {
		return nil, nil, failf("%s: provisioning record is for %s", label, S(hp, "unit"))
	}
	if !jsonEqual(get(hp, "designRef", "digest"), get(r.Design.Final, "digest")) {
		return nil, nil, failf("%s: provisioning record names a different design release", label)
	}
	// The station writes the firmware and the signature beside it, both
	// subjects of the firmware's provenance, and nothing else.
	withProvenance := map[string]Obj{RoTFWImage: r.Image, RoTFWSig: r.Signature}
	var fw Obj
	for _, w := range Objs(hp, "images") {
		want := withProvenance[S(w, "name")]
		if want == nil || S(w, "digest", "sha256") != S(want, "digest", "sha256") {
			return nil, nil, failf("%s: provisioning record wrote other firmware than the image with provenance", label)
		}
		if !Truthy(w["provenanceVerified"]) {
			return nil, nil, failf("%s: provisioning record wrote %s without checking its provenance", label, S(w, "name"))
		}
		if S(w, "name") == RoTFWImage {
			fw = w
		}
	}
	if fw == nil {
		return nil, nil, failf("%s: provisioning record wrote other firmware than the image with provenance", label)
	}
	var codeSigner string
	for _, k := range r.Trust.Roles["code-signer"] {
		codeSigner, _ = spkiDigest(k.Public)
	}
	if S(hp, "fuses", "vendor_key_hash") != codeSigner {
		return nil, nil, failf("%s: vendor key hash fuse is not the vendor's code signer", label)
	}
	if S(hp, "fuses", "lifecycle") != "production" || !Truthy(get(hp, "fuses", "debug_locked")) {
		return nil, nil, failf("%s: not in the production lifecycle with debug locked", label)
	}
	ident := O(hp, "identity")
	certPath := filepath.Join(r.Bundle, "artifacts", S(ident, "certificate", "name"))
	if d := fileDigest(certPath); d == nil || !jsonEqual(d, get(ident, "certificate", "digest")) {
		return nil, nil, failf("%s: IDevID certificate does not match the provisioning record", label)
	}
	cert, err := loadCert(certPath)
	if err != nil {
		return nil, nil, failf("%s: unreadable IDevID certificate: %v", label, err)
	}
	endorsed := false
	for _, k := range r.Trust.Roles["identity-ca"] {
		endorsed = endorsed || signedBy(cert, k.Public)
	}
	if !endorsed {
		return nil, nil, failf("%s: IDevID certificate is not endorsed by the vendor's identity CA", label)
	}
	if d, err := spkiDigest(cert.PublicKey); err != nil || d != S(firstSubject(rec), "digest", "sha256") {
		return nil, nil, failf("%s: provisioning record subject is not this IDevID key", label)
	}
	// A unit named by its certificate was provisioned with that certificate.
	if trackClaim(r.Policy, "PACKAGE_TEST") >= 3 && sha256Bytes(cert.Raw) != unit {
		return nil, nil, failf("%s: provisioned with IDevID certificate sha256:%s, not the one the unit is named by", label, short(sha256Bytes(cert.Raw)))
	}
	return rec, cert, nil
}

// FPGAImages is what the image check vouches for: the board's flash and the
// reference values its root of trust reports against.
type FPGAImages struct {
	Flash     Obj
	Manifest  Obj
	RefValues []RefValue
	Inputs    []Obj
}

// fpgaImageSet is one flash image as fpgaImagesAt checked it.
type fpgaImageSet struct {
	FW, Flash        Obj // the firmware's and the flash image's provenance
	FWImage, SBOM    Obj
	FlashRD, CoRIMRD Obj
	Manifest         Obj
	RefValues        []RefValue
	Want, Names      map[string]string // image digest and name by role
}

// FPGAImageCheck checks the images in the board's flash: the bitstream is the
// design release, the firmware has provenance and an SBOM, the boot manifest
// is signed by the board owner's code signer and lists exactly them, the
// board CoRIM holds their reference values, and the board HBOM lists them.
func FPGAImageCheck(bundle string, trust *TrustRoot, policy Obj, hb Obj, design *DesignResult) (*FPGAImages, error) {
	set, err := fpgaImagesAt(filepath.Join(bundle, FPGADesignDir), trust, policy, design, "")
	if err != nil {
		return nil, err
	}
	m, want, fwImage, sbom, corimRD := set.Manifest, set.Want, set.FWImage, set.SBOM, set.CoRIMRD
	if S(m, "product") != S(hb, "predicate", "product", "partNumber") || S(m, "vendor") != S(hb, "predicate", "product", "manufacturer", "name") {
		return nil, failf("boot manifest: names %s %s, not this board", S(m, "vendor"), S(m, "product"))
	}

	// The board HBOM lists both images, pointing at the records checked here.
	listed := map[string]Obj{}
	for _, f := range Objs(hb, "predicate", "firmware") {
		listed[S(f, "name")] = f
	}
	for _, e := range []struct {
		name, role, digest, prov string
	}{
		{S(design.Final, "name"), fpgaHBOMRoleBS, want[RoleBitstream], FPGADesignDir + "/att/" + AttName("release")},
		{S(fwImage, "name"), fpgaHBOMRoleFW, want[RoleSoCFW], FPGADesignDir + "/att/" + FPGAFWAtt},
	} {
		f := listed[e.name]
		if f == nil || S(f, "role") != e.role || S(f, "digest", "sha256") != e.digest {
			return nil, failf("board hbom: firmware entry %s does not match the released image", e.name)
		}
		if S(f, "provenanceRef", "uri") != "file:"+e.prov || !jsonEqual(get(f, "provenanceRef", "digest"), relRD(bundle, e.prov)["digest"]) {
			return nil, failf("board hbom: firmware entry %s does not point at its record", e.name)
		}
		if S(f, "referenceValuesRef", "uri") != "file:"+FPGADesignDir+"/artifacts/"+BoardCoRIMFile || !jsonEqual(get(f, "referenceValuesRef", "digest"), corimRD["digest"]) {
			return nil, failf("board hbom: firmware entry %s does not point at the board CoRIM", e.name)
		}
	}
	if len(listed) != 2 {
		return nil, failf("board hbom: lists %d firmware images, the boot manifest 2", len(listed))
	}
	if !jsonEqual(get(listed[FPGAFWImage], "sbomRef", "digest"), get(sbom, "digest")) {
		return nil, failf("board hbom: SBOM for %s does not match its provenance", FPGAFWImage)
	}
	return &FPGAImages{
		Flash: set.FlashRD, Manifest: m, RefValues: set.RefValues,
		Inputs: []Obj{relRD(bundle, FPGADesignDir+"/att/"+FPGAFWAtt), relRD(bundle, FPGADesignDir+"/att/"+FlashAtt)},
	}, nil
}

// fpgaImagesAt checks a flash image laid out in directory d (the board
// owner's design bundle, or an update's): the firmware's provenance and
// SBOM, the flash image's provenance linking the design release, the
// bitstream and the firmware, the boot manifest signed by the code signer
// and naming exactly those images where the flash holds them, the policy's
// minimum SVN, and the CoRIM's reference values. where prefixes messages.
func fpgaImagesAt(d string, trust *TrustRoot, policy Obj, design *DesignResult, where string) (*fpgaImageSet, error) {
	builder := S(policy, "firmware", "builder")
	label := where + "firmware " + FPGAFWImage
	fw, err := trust.Open(filepath.Join(d, "att", FPGAFWAtt), builder, SLSAProvenance)
	if err != nil {
		return nil, err
	}
	if buildType(fw) != FPGAFWBuildType {
		return nil, failf("%s: wrong buildType", label)
	}
	if err := asSLSAProvenance(fw, label); err != nil {
		return nil, err
	}
	if err := requireFiles(d, fw, label); err != nil {
		return nil, err
	}
	fwImage := firstSubject(fw)
	var sbom Obj
	for _, b := range Objs(fw, "predicate", "runDetails", "byproducts") {
		if S(b, "name") == FPGAFWSBOM {
			sbom = b
		}
	}
	if sbom == nil || !jsonEqual(fileDigest(filepath.Join(d, "artifacts", FPGAFWSBOM)), get(sbom, "digest")) {
		return nil, failf("%s: no SBOM, or the SBOM does not match its digest", label)
	}

	label = where + "flash image"
	fl, err := trust.Open(filepath.Join(d, "att", FlashAtt), builder, SLSAProvenance)
	if err != nil {
		return nil, err
	}
	if buildType(fl) != FlashBuildType {
		return nil, failf("%s: wrong buildType", label)
	}
	if err := asSLSAProvenance(fl, label); err != nil {
		return nil, err
	}
	if err := requireFiles(d, fl, label); err != nil {
		return nil, err
	}
	if err := requireLink(fl, label, []Obj{design.Release, envRD(d, FPGAFWAtt), rd(S(design.Final, "name"), S(design.Final, "digest", "sha256")), fwImage}, "design release, bitstream and firmware"); err != nil {
		return nil, err
	}
	var flashRD, manifestRD, corimRD Obj
	for _, s := range Objs(fl, "subject") {
		switch S(s, "name") {
		case FlashImage:
			flashRD = s
		case BootManifest:
			manifestRD = s
		}
	}
	for _, b := range Objs(fl, "predicate", "runDetails", "byproducts") {
		if S(b, "name") == BoardCoRIMFile {
			corimRD = b
		}
	}
	if flashRD == nil || manifestRD == nil || corimRD == nil {
		return nil, failf("%s: provenance does not name the flash image, its boot manifest and its CoRIM", label)
	}
	if !jsonEqual(fileDigest(filepath.Join(d, "artifacts", BoardCoRIMFile)), get(corimRD, "digest")) {
		return nil, failf("%s: the CoRIM does not match its digest", label)
	}
	blob, err := ReadObj(filepath.Join(d, "artifacts", BootManifest))
	if err != nil {
		return nil, failf("%sboot manifest: %v", where, err)
	}
	payload, signer, err := openBlob(blob)
	if err != nil {
		return nil, failf("%sboot manifest: %v", where, err)
	}
	ok := false
	for _, k := range trust.Roles[S(policy, "firmware", "imageSigner")] {
		if h, err := spkiDigest(k.Public); err == nil && h == signer {
			ok = true
		}
	}
	if !ok {
		return nil, failf("%sboot manifest: not signed by the board owner's code signer", where)
	}
	m, err := decodeObj(payload)
	if err != nil {
		return nil, failf("%sboot manifest: %v", where, err)
	}
	if S(m, "format") != BootManifestFormat {
		return nil, failf("%sboot manifest: format %q", where, S(m, "format"))
	}
	flash, err := os.ReadFile(filepath.Join(d, "artifacts", FlashImage))
	if err != nil {
		return nil, failf("%sflash image: %v", where, err)
	}
	// The manifest the root of trust reads is in the flash image.
	off, err := manifestOffsetOf(fl)
	if err != nil {
		return nil, err
	}
	inFlash, err := readBootManifest(flash, off)
	if err != nil || !jsonEqual(inFlash, blob) {
		return nil, failf("%sflash image: the boot manifest in flash is not the signed one", where)
	}
	want := map[string]string{RoleBitstream: S(design.Final, "digest", "sha256"), RoleSoCFW: S(fwImage, "digest", "sha256")}
	names := map[string]string{RoleBitstream: S(design.Final, "name"), RoleSoCFW: S(fwImage, "name")}
	images := Objs(m, "images")
	if len(images) != len(want) {
		return nil, failf("%sboot manifest: lists %d images, want the bitstream and the firmware", where, len(images))
	}
	for _, img := range images {
		role := S(img, "role")
		if want[role] == "" || S(img, "sha256") != want[role] || S(img, "name") != names[role] {
			return nil, failf("%sboot manifest: %s (%s) is not the released image", where, S(img, "name"), role)
		}
		if sha256Bytes(sliceOf(flash, img)) != want[role] {
			return nil, failf("%sflash image: %s at its manifest offset is not the released image", where, S(img, "name"))
		}
	}
	svn, _ := Int(m, "svn")
	if minSVN, _ := Int(policy, "firmware", "minSvn"); svn < minSVN {
		return nil, failf("%sboot manifest: SVN %d is below the policy minimum %d", where, svn, minSVN)
	}
	rim, err := OpenCoRIM(filepath.Join(d, "artifacts", BoardCoRIMFile), trust.Roles[builder], "board CoRIM")
	if err != nil {
		return nil, err
	}
	if !sameRefValues(rim.RefValues, BoardRefValues(images, S(m, "vendor"), S(m, "product"), svn)) {
		return nil, failf("%sboard CoRIM: reference values differ from the boot manifest", where)
	}
	return &fpgaImageSet{
		FW: fw, Flash: fl, FWImage: fwImage, SBOM: sbom, FlashRD: flashRD, CoRIMRD: corimRD,
		Manifest: m, RefValues: rim.RefValues, Want: want, Names: names,
	}, nil
}

func manifestOffsetOf(flashProv Obj) (int64, error) {
	off, ok := Int(flashProv, "predicate", "buildDefinition", "externalParameters", "layout", "manifestOffset")
	if !ok {
		return 0, failf("flash image: provenance gives no manifest offset")
	}
	return off, nil
}

// BoardUnit is one board's provisioning, as the buyer checked it.
type BoardUnit struct {
	Serial, RoTUnit string
	Record          Obj
	IDevID          *x509.Certificate
	Inputs          []Obj
}

// boardProvCheck checks the EMS's provisioning record for one board: every
// gate passed, the flash written is the checked image, the owner fuses name
// the board owner's code signer, and the root of trust is the unit the EMS
// placed on that board, as its vendor provisioned it.
func boardProvCheck(bundle string, trust *TrustRoot, policy Obj, hb Obj, rot *RoTResult, images *FPGAImages, serial string) (*BoardUnit, error) {
	label := "board " + serial
	rec, err := trust.Open(filepath.Join(bundle, "att", BoardProvAtt(serial)), S(policy, "firmware", "provisioningSigner"), FWProvisioning)
	if err != nil {
		return nil, err
	}
	if buildType(rec) != ProvisionType {
		return nil, failf("%s: provisioning record has the wrong buildType", label)
	}
	if err := asSLSAProvenance(rec, label+" provisioning"); err != nil {
		return nil, err
	}
	hp := O(rec, "predicate", "hwProvision")
	if failed := failedChecks(Objs(hp, "checks")); len(failed) > 0 {
		return nil, failf("%s: provisioning gate failed: %s", label, strings.Join(failed, ", "))
	}
	mfr := S(hb, "predicate", "product", "manufacturer", "name")
	if S(hp, "unit") != boardURN(mfr, serial) || S(firstSubject(rec), "name") != S(hp, "unit") {
		return nil, failf("%s: provisioning record is for %s", label, S(hp, "unit"))
	}
	var flash Obj
	for _, img := range Objs(hp, "images") {
		if S(img, "name") == FlashImage {
			flash = img
		}
	}
	if flash == nil || !jsonEqual(get(flash, "digest"), get(images.Flash, "digest")) || !jsonEqual(get(flash, "readback"), get(images.Flash, "digest")) {
		return nil, failf("%s: provisioning record wrote another flash image", label)
	}
	var ownerHash string
	for _, k := range trust.Roles[S(policy, "firmware", "imageSigner")] {
		ownerHash, _ = spkiDigest(k.Public)
	}
	if S(hp, "fuses", ownerFuseHash) != ownerHash {
		return nil, failf("%s: the owner key fuse is not the board owner's code signer", label)
	}
	svnFuse, _ := Int(hp, "fuses", ownerFuseSVN)
	if svn, _ := Int(images.Manifest, "svn"); svnFuse > svn {
		return nil, failf("%s: anti-rollback fuse %d is above the image SVN %d", label, svnFuse, svn)
	}
	refDes := Strs(rot.Part, "refDes")[0]
	unit, err := rotUnitOn(bundle, serial, refDes)
	if err != nil {
		return nil, failf("%s: %v", label, err)
	}
	if S(hp, "rootOfTrust", "unit") != "urn:hslsa:unit:"+unit || S(hp, "rootOfTrust", "refDes") != refDes {
		return nil, failf("%s: provisioning record names root of trust %s, but A1 placed %s at %s", label, S(hp, "rootOfTrust", "unit"), unit, refDes)
	}
	rotRec, cert, err := rotUnitCheck(rot, unit)
	if err != nil {
		return nil, err
	}
	idevid, err := spkiDigest(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	if S(firstSubject(rec), "digest", "sha256") != idevid || S(hp, "identity", "idevidPublicKey", "sha256") != idevid {
		return nil, failf("%s: the board's identity is not its root of trust's IDevID key", label)
	}
	_ = rotRec
	rotRel, _ := filepath.Rel(bundle, rot.Bundle)
	return &BoardUnit{
		Serial: serial, RoTUnit: unit, Record: rec, IDevID: cert,
		Inputs: []Obj{relRD(bundle, "att/"+BoardProvAtt(serial)), relRD(bundle, filepath.ToSlash(filepath.Join(rotRel, "att", RoTProvAtt(unit))))},
	}, nil
}

// FPGADeviceCheck is the at-boot check for one board, from what it returned
// when powered on: the root of trust's alias certificate chains to the
// IDevID its vendor endorsed and names the unit, its firmware measurement
// matches the root of trust CoRIM, the platform certificate it signed
// reports every image in flash, each matching the board CoRIM, and the SoC
// then booted.
func FPGADeviceCheck(u *BoardUnit, rot *RoTResult, images *FPGAImages, policy Obj, bootDir string) error {
	label := "board " + u.Serial
	rec, err := ReadObj(filepath.Join(bootDir, BootRecord))
	if err != nil {
		return failf("%s: no boot record: %v", label, err)
	}
	if !Truthy(rec["released"]) {
		return failf("%s: the root of trust held the FPGA in reset", label)
	}
	certs := map[string]*x509.Certificate{}
	for _, name := range []string{"alias", "platform"} {
		c, err := loadCert(filepath.Join(bootDir, name+".der"))
		if err != nil {
			return failf("%s: no %s certificate from the board: %v", label, name, err)
		}
		certs[name] = c
	}
	if err := checkSignedBy(certs["alias"], u.IDevID, label+" alias"); err != nil {
		return err
	}
	if err := checkSignedBy(certs["platform"], certs["alias"], label+" platform"); err != nil {
		return err
	}
	k, raw, ok := UEID(u.IDevID)
	if !ok {
		return failf("%s: the root of trust's IDevID certificate carries no UEID", label)
	}
	want := append([]byte{k}, raw...)
	for _, name := range []string{"alias", "platform"} {
		kind, raw, ok := UEID(certs[name])
		if !ok || !bytes.Equal(append([]byte{kind}, raw...), want) {
			return failf("%s: UEID in the %s certificate does not name root of trust %s", label, name, u.RoTUnit)
		}
	}
	tcb, err := tcbInfoOfType(certs["alias"], RoTFWTcbType, label)
	if err != nil {
		return err
	}
	if named, err := Appraise(rot.RefValues, tcb); !named || err != nil {
		return failf("%s: the root of trust's firmware measurement matches no reference value in its CoRIM", label)
	}
	infos, err := TcbInfos(certs["platform"])
	if err != nil {
		return failf("%s: unreadable platform TcbInfo: %v", label, err)
	}
	reported := map[string]bool{}
	for _, t := range infos {
		named, err := Appraise(images.RefValues, t)
		if !named {
			return failf("%s: the board reports %s, which has no reference value", label, EnvOf(t))
		}
		if err != nil {
			return failf("%s: %s in flash matches no reference value in the board CoRIM", label, t.Type)
		}
		reported[t.Type] = true
	}
	for _, r := range images.RefValues {
		if !reported[r.Env.Type] {
			return failf("%s: the root of trust did not report %s", label, r.Env.Type)
		}
	}
	if Truthy(get(policy, "firmware", "requireSoCBoot")) && !Truthy(get(rec, "soc", "uartBanner")) {
		return failf("%s: the SoC did not print its boot banner", label)
	}
	return nil
}

// FPGAVerify runs every buyer check on the board bundle, then signs VSAs when vsaKey is set.
func FPGAVerify(bundle string, trust *TrustRoot, policyPath, boardsPath, bootsDir, vsaKey, vsaDir string) error {
	policy, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	received, boardsDir, err := receivedBoardsAt(boardsPath)
	if err != nil {
		return err
	}
	if err := gapError("FPGA board check", fpgaGaps(bundle)); err != nil {
		return err
	}
	board, err := checkBoard(bundle, trust, policyPath, received, boardsDir)
	if err != nil {
		return err
	}
	fmt.Printf("board receipt check: PASSED for %s, root of trust lot checked through its own chain\n", S(board.Lot, "name"))
	hb, err := trust.Open(filepath.Join(bundle, "att", BoardHBOM), boardOwnerRole, HBOMType)
	if err != nil {
		return err
	}
	design, err := TapeoutCheck(filepath.Join(bundle, FPGADesignDir), trust, policy, true)
	if err != nil {
		return err
	}
	fmt.Printf("FPGA design check: PASSED for %s sha256:%s\n", S(design.Final, "name"), S(design.Final, "digest", "sha256"))
	images, err := FPGAImageCheck(bundle, trust, policy, hb, design)
	if err != nil {
		return err
	}
	fmt.Printf("image check: PASSED, boot manifest signed by the owner's code signer, svn %s\n", num(get(images.Manifest, "svn")))
	rot, err := RoTCheck(bundle, hb, policy)
	if err != nil {
		return err
	}
	fmt.Printf("root of trust check: PASSED, %s at %s guards %s and verifies %s\n", S(rot.Part, "mpn"),
		Strs(rot.Part, "refDes")[0], strings.Join(Strs(rot.Part, "rootOfTrust", "guards"), ", "), strings.Join(Strs(rot.Part, "rootOfTrust", "images"), ", "))
	lotBoards, err := ReadUnits(filepath.Join(bundle, "artifacts", BoardLot))
	if err != nil {
		return err
	}
	units := map[string]*BoardUnit{}
	var provInputs []Obj
	for _, serial := range lotBoards {
		u, err := boardProvCheck(bundle, trust, policy, hb, rot, images, serial)
		if err != nil {
			return err
		}
		units[serial] = u
		provInputs = append(provInputs, u.Inputs...)
	}
	fmt.Printf("provisioning check: PASSED for all %d boards in the lot\n", len(lotBoards))
	histories := map[string]*BoardHistory{}
	var afterInputs, updates []string
	var afterRDs []Obj
	for _, serial := range lotBoards {
		h, err := afterSaleCheck(bundle, trust, policy, hb, design, units[serial], images)
		if err != nil {
			return err
		}
		histories[serial] = h
		updates = append(updates, h.Updates...)
		afterRDs = append(afterRDs, h.Inputs...)
		if h.Records > 0 {
			afterInputs = append(afterInputs, fmt.Sprintf("%s (%d, %s)", serial, h.Records, h.State))
		}
	}
	for _, serial := range received {
		if err := histories[serial].inService(serial); err != nil {
			return err
		}
	}
	if len(afterInputs) > 0 {
		fmt.Printf("after-sale check: PASSED, records for %s, %d field update(s)\n", strings.Join(afterInputs, ", "), len(updates))
	}
	provSim, err := simulatedCheck(bundle, policy, append(append(append([]Obj{}, rot.Inputs...), provInputs...), afterRDs...), "provisioning check")
	if err != nil {
		return err
	}
	printSimulated(append(append([]string{}, board.Simulated...), provSim...))
	sim := len(board.Simulated) > 0 || len(provSim) > 0
	var fwL3Inputs []Obj
	if trackClaim(policy, "FIRMWARE") >= 3 {
		if fwL3Inputs, err = fpgaFirmwareLevels(bundle, trust, policy, design, rot, units, received, bootsDir, updates); err != nil {
			return err
		}
	}
	if bootsDir != "" {
		for _, serial := range received {
			if err := FPGADeviceCheck(units[serial], rot, histories[serial].Images, policy, filepath.Join(bootsDir, serial)); err != nil {
				return err
			}
		}
		fmt.Printf("at-boot check: PASSED for %d boards (%s)\n", len(received), strings.Join(received, ", "))
	}
	// The board receipt check covered Assembly; Firmware claims are this check's.
	left, err := claimedLevelsCheck(hb, get(policy, "claims", "board"), fpgaTracks, "board hbom")
	if err != nil {
		return err
	}
	printClaimsLeft(left, "board hbom")
	if err := renderingsCheck(bundle, filepath.Join(bundle, "att", BoardHBOM), "board hbom"); err != nil {
		return err
	}
	if vsaKey == "" {
		return nil
	}
	claims := O(policy, "claims")
	out := func(name string) string { return filepath.Join(vsaDir, name) }
	designInputs := []Obj{}
	for _, in := range append([]Obj{design.Release}, design.Inputs...) {
		designInputs = append(designInputs, Obj{"name": FPGADesignDir + "/" + S(in, "name"), "digest": get(in, "digest")})
	}
	if err := signVSA(designTracks, design.Final, "hslsa:design:"+S(design.Final, "name"), claims["design"], designInputs, policyPath, vsaKey, out("design.vsa.intoto.json")); err != nil {
		return err
	}
	common := append(append(append(append([]Obj{}, board.Inputs...), images.Inputs...), rot.Inputs...), fwL3Inputs...)
	common = append(common, designInputs[0])
	if err := signVSA(fpgaTracks, board.Lot, S(board.Lot, "name"), vsaLevels(claims["board"], sim), append(append(common, provInputs...), afterRDs...), policyPath, vsaKey, out("board.vsa.intoto.json")); err != nil {
		return err
	}
	n := 0
	if bootsDir != "" {
		mfr := S(hb, "predicate", "product", "manufacturer", "name")
		for _, serial := range received {
			u := units[serial]
			subject := rd(boardURN(mfr, serial), sha256Bytes(u.IDevID.Raw))
			if err := signVSA(fpgaTracks, subject, S(subject, "name"), vsaLevels(claims["device"], sim), append(append(append([]Obj{}, u.Inputs...), histories[serial].Inputs...), common...), policyPath, vsaKey,
				out("board-"+serial+".vsa.intoto.json")); err != nil {
				return err
			}
			n++
		}
	}
	fmt.Printf("VSAs written to %s: design, board lot and %d boards\n", vsaDir, n)
	return nil
}

// fpgaGaps lists every record the FPGA board checks need beyond the board
// chain: the design and image records, and a provisioning record for every
// board in the lot.
func fpgaGaps(bundle string) []string {
	d := filepath.Join(bundle, FPGADesignDir, "att")
	var gaps []string
	for _, name := range []string{AttName("release"), FPGAFWAtt, FlashAtt} {
		gaps = append(gaps, recordGaps(filepath.Join(d, name), "FPGA design and images")...)
	}
	boards, err := ReadUnits(filepath.Join(bundle, "artifacts", BoardLot))
	if err != nil {
		return gaps
	}
	for _, s := range boards {
		gaps = append(gaps, recordGaps(filepath.Join(bundle, "att", BoardProvAtt(s)), "Firmware track, board "+s)...)
	}
	return gaps
}
