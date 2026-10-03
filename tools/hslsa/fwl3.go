package hslsa

// Firmware L3 (spec, "Core requirements"): SLSA Build L3; every image
// independently reviewed, shown by a signed OCP S.A.F.E. report; releases in
// a transparency log, which may be private; the device reports firmware
// measurements under a DICE or Caliptra class identity that match the
// attested image digests; and, by rule 2, every provisioning site rated at
// least L3 in its own track.
//
// firmwareL3 checks the release records: each build ran isolated when it ran
// step code (a compiler), names every input by digest and every tool by a
// pin in the policy's firmware.toolPins, is in the log the policy names, and
// each image the policy marks for review has an accepted report. The caller
// runs the at-boot check, which a Firmware L3 claim makes mandatory, and
// provisioningSiteL3 for each provisioning record.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// fwRelease is one firmware release record a Firmware L3 claim covers.
type fwRelease struct {
	Image  string // the image's subject name in the record
	Bundle string // the bundle holding the record and its review directory
	Record string // the record, relative to Bundle
	Role   string // the role that signs the record
	Review bool   // the image is firmware a review covers, not a container of reviewed images
	// ReviewName is the image's name in the policy's firmware.review.images, when it differs from Image.
	ReviewName string
	// Rebuilt, when set, accepts another independent party's reproduction
	// of the image at Firmware L4 when the release has no rebuild record.
	Rebuilt func(rel Obj) (Obj, error)
}

func (r fwRelease) reviewName() string {
	if r.ReviewName != "" {
		return r.ReviewName
	}
	return r.Image
}

// fwBuildsRunNoStepCode are the firmware build types in which no tenant
// code runs: the build platform lays out images it already has.
var fwBuildsRunNoStepCode = map[string]bool{FlashBuildType: true}

// firmwareL3 runs the Firmware L3 rules over releases, under trust and the
// policy's firmware block. It returns the reviews and inclusion proofs it
// accepted, for the VSA's inputs.
func firmwareL3(trust *TrustRoot, policy Obj, releases []fwRelease, label string) ([]Obj, error) {
	fw := O(policy, "firmware")
	logRole := S(fw, "transparencyLog", "role")
	if logRole == "" {
		logRole = TLogRole
	}
	origin := S(fw, "transparencyLog", "origin")
	if origin == "" {
		return nil, failf("%s: the policy names no transparency log (firmware.transparencyLog.origin), so release inclusion cannot be checked", label)
	}
	pins := Objs(fw, "toolPins")
	var inputs []Obj
	reviews := map[string][]ReviewImage{}
	for _, r := range releases {
		where := label + ": " + r.Image
		path := filepath.Join(r.Bundle, r.Record)
		stmt, err := trust.Open(path, r.Role, SLSAProvenance)
		if err != nil {
			return nil, err
		}
		var image Obj
		for _, s := range Objs(stmt, "subject") {
			if S(s, "name") == r.Image {
				image = s
			}
		}
		if image == nil {
			return nil, failf("%s: %s does not name the image", where, filepath.Base(r.Record))
		}
		if err := buildL3(stmt, pins, where); err != nil {
			return nil, err
		}
		if _, err := CheckLogged(trust, path, logRole, origin, where); err != nil {
			return nil, err
		}
		inputs = append(inputs, Obj{"name": filepath.ToSlash(TLogProofPath(r.Record)), "digest": fileDigest(TLogProofPath(path))})
		if r.Review {
			reviews[r.Bundle] = append(reviews[r.Bundle], ReviewImage{Name: r.reviewName(), Subject: image})
		}
	}
	for _, b := range sortedKeys(anyImages(reviews)) {
		images := reviews[b]
		required := Strs(fw, "review", "images")
		for _, im := range images {
			if !contains(required, im.Name) {
				return nil, failf("%s: the policy claims Firmware L3 but does not require a S.A.F.E. review of %s (firmware.review.images)", label, im.Name)
			}
		}
		rev, err := ReviewCheck(b, trust, policy, images)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, rev.Inputs...)
	}
	return inputs, nil
}

func anyImages(m map[string][]ReviewImage) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

// buildL3 is SLSA Build L3 for one firmware record: a build that ran step
// code ran isolated, with no network and no signing key in reach; every
// input is named by digest; every tool is pinned by the policy.
func buildL3(stmt Obj, pins []Obj, where string) error {
	bd := O(stmt, "predicate", "buildDefinition")
	runsCode := !fwBuildsRunNoStepCode[S(bd, "buildType")]
	if runsCode {
		if err := isolationBlockOK(O(bd, "internalParameters"), "internalParameters", where+": SLSA Build L3", false); err != nil {
			return err
		}
	}
	tools := 0
	for _, d := range Objs(bd, "resolvedDependencies") {
		dg := O(d, "digest")
		if S(dg, "sha256") == "" && S(dg, "gitCommit") == "" {
			return failf("%s: SLSA Build L3: input %s is not pinned by digest", where, S(d, "name"))
		}
		if S(d, "annotations", "version") == "" {
			continue
		}
		tools++
		if err := fwToolPinned(d, pins, where); err != nil {
			return err
		}
	}
	if runsCode && tools == 0 {
		return failf("%s: SLSA Build L3: the record names no tool, so the toolchain is not pinned", where)
	}
	return nil
}

// fwToolPinned matches a tool a firmware record names against the policy's
// firmware.toolPins: the same binary, and the same package or toolchain
// tree where the pin names one.
func fwToolPinned(d Obj, pins []Obj, where string) error {
	name := S(d, "name")
	// A policy may pin one binary more than once, for each toolchain tree
	// it accepts; any pin that matches in full passes.
	var mismatch error
	for _, p := range pins {
		if S(p, "name") != name || S(p, "sha256") != S(d, "digest", "sha256") {
			continue
		}
		if pp := O(p, "package"); pp != nil {
			dp := O(d, "annotations", "package")
			if S(dp, "name") != S(pp, "name") || S(dp, "version") != S(pp, "version") || S(dp, "treeDigest", "sha256") != S(pp, "treeDigest") {
				mismatch = failf("%s: SLSA Build L3: tool %s is the pinned binary, but its package %s %s (files sha256:%s) is not the pinned one", where, name,
					S(dp, "name"), S(dp, "version"), short(S(dp, "treeDigest", "sha256")))
				continue
			}
		}
		if pt := O(p, "toolchain"); pt != nil {
			dt := O(d, "annotations", "toolchain")
			if S(dt, "treeDigest", "sha256") != S(pt, "treeDigest") {
				mismatch = failf("%s: SLSA Build L3: %s is the pinned binary, but its toolchain (files sha256:%s) is not the pinned one", where, name, short(S(dt, "treeDigest", "sha256")))
				continue
			}
		}
		return nil
	}
	if mismatch != nil {
		return mismatch
	}
	return failf("%s: SLSA Build L3: tool %s sha256:%s is not on the policy's pinned tool list (firmware.toolPins)", where, name, short(S(d, "digest", "sha256")))
}

// provisioningTrack is the track a provisioning site is rated in, by the stage it provisions at.
var provisioningTrack = map[string]string{
	"wafer-sort": "WAFER", "final-test": "PACKAGE_TEST", "board-programming": "ASSEMBLY",
}

// provisioningSiteL3 is rule 2 for one provisioning record: the site is
// rated at least L3 in its own track. The track's L3 checks ran under policy
// (it claims L3 there), and the site's key meets them: held in an HSM at an
// accredited site for Wafer and Package/Test, signed at an accredited site
// for Assembly.
func provisioningSiteL3(trust *TrustRoot, policy Obj, path, role, label string) error {
	return provisioningSite(trust, policy, path, role, label, 3)
}

// provisioningSite is rule 2 for Firmware L<level>: the site is rated at
// least L<level> in its own track, whose checks ran under policy, with a key
// that meets L3 there. At Firmware L4 the record must also show per-unit
// data read back as written.
func provisioningSite(trust *TrustRoot, policy Obj, path, role, label string, level int) error {
	rec, err := trust.Open(path, role, FWProvisioning)
	if err != nil {
		return err
	}
	stage := S(rec, "predicate", "buildDefinition", "externalParameters", "stage")
	track := provisioningTrack[stage]
	if track == "" {
		return failf("%s: provisioning at stage %q, which no track rates", label, stage)
	}
	if trackClaim(policy, track) < level {
		return failf("%s: provisioned at %s, which is rated %s L%d under its policy; Firmware L%d needs every provisioning site at L%d or higher in its own track (rule 2)",
			label, S(rec, "predicate", "hwProvision", "site", "name"), TrackTitle[track], trackClaim(policy, track), level, level)
	}
	what := fmt.Sprintf("%s: provisioning record", label)
	if track == "ASSEMBLY" {
		err = keyAccredited(trust, policy, path, role, what)
	} else {
		err = keyL3(trust, policy, path, role, what)
	}
	if err != nil || level < 4 {
		return err
	}
	return provisioningReadback(rec, label)
}

// firmwareL3Summary is the line the checks print after Firmware L3 passed.
func firmwareL3Summary(releases []fwRelease) string {
	var all, reviewed []string
	for _, r := range releases {
		all = append(all, r.Image)
		if r.Review {
			reviewed = append(reviewed, r.reviewName())
		}
	}
	return fmt.Sprintf("Firmware L3: PASSED, %s built isolated with pinned tools and in the transparency log; reviews accepted for %s",
		strings.Join(all, ", "), strings.Join(reviewed, ", "))
}

// fpgaFirmwareLevels runs Firmware L3 for the FPGA board, and Firmware L4
// when the policy claims it: the board owner's images and the root of
// trust's firmware, each under its own trust root and policy; the at-boot
// check for every received board; and rule 2 for the EMS's provisioning of
// each board and the root of trust vendor's provisioning of each unit on
// them. At L4 an independent rebuilder also reproduces the SoC firmware, the
// root of trust firmware and the bitstream, which is loaded from the same
// flash, and two people approve each release.
func fpgaFirmwareLevels(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, rot *RoTResult, units map[string]*BoardUnit, received []string, bootsDir string, updates []string) ([]Obj, error) {
	label := "Firmware L3"
	level := trackClaim(policy, "FIRMWARE")
	if bootsDir == "" || len(received) == 0 {
		return nil, failf("%s: the at-boot check is required; pass the received boards and what they returned at boot (--boards, --boots)", label)
	}
	designDir := filepath.Join(bundle, FPGADesignDir)
	builder := S(policy, "firmware", "builder")
	board := []fwRelease{
		{Image: FPGAFWImage, Bundle: designDir, Record: "att/" + FPGAFWAtt, Role: builder, Review: true},
		{Image: FlashImage, Bundle: designDir, Record: "att/" + FlashAtt, Role: builder},
	}
	boardInputs, err := firmwareL3(trust, policy, board, label+": board")
	if err != nil {
		return nil, err
	}
	// A field update is a release like the shipped one, and meets the same rules.
	updateDirs := map[string][]fwRelease{}
	updateInputs := map[string][]Obj{}
	for _, u := range updates {
		dir := filepath.Join(bundle, filepath.FromSlash(u))
		updateDirs[dir] = []fwRelease{
			{Image: FPGAFWImage, Bundle: dir, Record: "att/" + FPGAFWAtt, Role: builder, Review: true},
			{Image: FlashImage, Bundle: dir, Record: "att/" + FlashAtt, Role: builder},
		}
		if updateInputs[dir], err = firmwareL3(trust, policy, updateDirs[dir], label+": field update "+filepath.Base(dir)); err != nil {
			return nil, err
		}
	}
	rotFW := []fwRelease{{Image: RoTFWImage, Bundle: rot.Bundle, Record: "att/" + RoTFWAtt, Role: "firmware-platform", Review: true}}
	rotInputs, err := firmwareL3(rot.Trust, rot.Policy, rotFW, label+": root of trust")
	if err != nil {
		return nil, err
	}
	if level >= 4 {
		l4 := "Firmware L4"
		in, err := firmwareL4(trust, policy, board, l4+": board")
		if err != nil {
			return nil, err
		}
		bit, err := checkDesignRebuild(designDir, trust, policy, design.Final, l4+": bitstream")
		if err != nil {
			return nil, err
		}
		boardInputs = append(append(boardInputs, in...), bit)
		if in, err = firmwareL4(rot.Trust, rot.Policy, rotFW, l4+": root of trust"); err != nil {
			return nil, err
		}
		rotInputs = append(rotInputs, in...)
		for dir, rel := range updateDirs {
			if in, err = firmwareL4(trust, policy, rel, l4+": field update "+filepath.Base(dir)); err != nil {
				return nil, err
			}
			updateInputs[dir] = append(updateInputs[dir], in...)
		}
	}
	// Inputs are named relative to the board bundle.
	var inputs []Obj
	byDir := map[string][]Obj{designDir: boardInputs, rot.Bundle: rotInputs}
	for dir, list := range updateInputs {
		byDir[dir] = list
	}
	for dir, list := range byDir {
		rel, err := filepath.Rel(bundle, dir)
		if err != nil {
			return nil, err
		}
		for _, in := range list {
			inputs = append(inputs, Obj{"name": filepath.ToSlash(filepath.Join(rel, S(in, "name"))), "digest": get(in, "digest")})
		}
	}
	sortByName(inputs)
	site := fmt.Sprintf("Firmware L%d", min(level, 4))
	for _, serial := range sortedKeys(anyUnits(units)) {
		u := units[serial]
		if err := provisioningSite(trust, policy, filepath.Join(bundle, "att", BoardProvAtt(serial)), S(policy, "firmware", "provisioningSigner"), site+": board "+serial, level); err != nil {
			return nil, err
		}
		if err := provisioningSite(rot.Trust, rot.Policy, filepath.Join(rot.Bundle, "att", RoTProvAtt(u.RoTUnit)), S(rot.Policy, "firmware", "provisioningSigner"),
			site+": root of trust "+short(u.RoTUnit), level); err != nil {
			return nil, err
		}
	}
	fmt.Println(firmwareL3Summary(append(board, rotFW...)))
	if len(updates) > 0 {
		var ids []string
		for _, u := range updates {
			ids = append(ids, filepath.Base(u))
		}
		fmt.Printf("%s: field update %s held to the same rules as the shipped release\n", site, strings.Join(ids, ", "))
	}
	fmt.Printf("%s: every provisioning site is rated L%d in its own track (the EMS for %d boards, the root of trust's test house for their units)\n", site, min(level, 4), len(units))
	if level >= 4 {
		fmt.Println(firmwareL4Summary("Firmware L4", []string{FPGAFWImage, RoTFWImage, S(design.Final, "name")}))
	}
	return inputs, nil
}

func sortByName(list []Obj) {
	sort.Slice(list, func(i, j int) bool { return S(list[i], "name") < S(list[j], "name") })
}

func anyUnits(m map[string]*BoardUnit) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

// caliptraFirmwareLevels runs Firmware L3 for the Caliptra example, and
// Firmware L4 when the policy claims it: its ROM, FMC and runtime, and rule
// 2 for the test house that provisioned each unit. At L4 the ROM may be
// reproduced by the party that froze it instead of a rebuilder: step 6a's
// rom-matches-frozen check, passing against the Caliptra TAC's published
// digest, counts as its independent rebuild.
func caliptraFirmwareLevels(bundle string, trust *TrustRoot, policy Obj, units []string) ([]Obj, error) {
	label := "Firmware L3"
	level := trackClaim(policy, "FIRMWARE")
	var releases []fwRelease
	for _, im := range []struct{ image, record, review string }{
		{Images["rom"], FWAtt["rom"], "caliptra-rom"},
		{Images["fmc"], FWAtt["bundle"], "caliptra-fmc"},
		{Images["runtime"], FWAtt["bundle"], "caliptra-runtime"},
	} {
		releases = append(releases, fwRelease{Image: im.image, Bundle: bundle, Record: "att/" + im.record, Role: "firmware-platform", Review: true, ReviewName: im.review})
	}
	releases[0].Rebuilt = func(rel Obj) (Obj, error) { return romFrozen(bundle, trust, rel) }
	inputs, err := firmwareL3(trust, policy, releases, label)
	if err != nil {
		return nil, err
	}
	if level >= 4 {
		in, err := firmwareL4(trust, policy, releases, "Firmware L4")
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, in...)
	}
	site := fmt.Sprintf("Firmware L%d", min(level, 4))
	for _, u := range units {
		if err := provisioningSite(trust, policy, filepath.Join(bundle, "att", ProvAtt(u)), S(policy, "firmware", "provisioningSigner"), site+": unit "+u, level); err != nil {
			return nil, err
		}
	}
	fmt.Println(firmwareL3Summary(releases))
	if level >= 4 {
		fmt.Println(firmwareL4Summary("Firmware L4", []string{Images["rom"], Images["fmc"], Images["runtime"]}))
	}
	return inputs, nil
}

// romFrozen accepts the Caliptra ROM's reproduction by the party that froze
// it: the ROM merge record (step 6a), from the flow platform, names this ROM
// release and this image, and its rom-matches-frozen check passed.
func romFrozen(bundle string, trust *TrustRoot, rel Obj) (Obj, error) {
	where := "Firmware L4: " + Images["rom"]
	path := filepath.Join(bundle, "att", AttName("rom-merge"))
	if !fileExists(path) {
		return nil, failf("%s: no independent rebuild (%s), and no ROM merge record whose rom-matches-frozen check could stand in for one", where, FWRebuildAtt(FWAtt["rom"]))
	}
	merge, err := trust.Open(path, "flow-platform", DesignFlow)
	if err != nil {
		return nil, err
	}
	var image Obj
	for _, s := range Objs(rel, "subject") {
		if S(s, "name") == Images["rom"] {
			image = s
		}
	}
	namesRelease, namesImage := false, false
	for _, d := range Objs(merge, "predicate", "buildDefinition", "resolvedDependencies") {
		if S(d, "name") == "att/"+FWAtt["rom"] && jsonEqual(get(d, "digest"), fileDigest(filepath.Join(bundle, "att", FWAtt["rom"]))) {
			namesRelease = true
		}
		if S(d, "name") == Images["rom"] && S(d, "digest", "sha256") == S(image, "digest", "sha256") {
			namesImage = true
		}
	}
	if !namesRelease || !namesImage {
		return nil, failf("%s: the ROM merge record does not name this ROM release and image", where)
	}
	if !hasCheck(Objs(merge, "predicate", "hwFlow", "checks"), "rom-matches-frozen") {
		return nil, failf("%s: no independent rebuild (%s), and the ROM merge record has no passing rom-matches-frozen check", where, FWRebuildAtt(FWAtt["rom"]))
	}
	return envRD(bundle, AttName("rom-merge")), nil
}
