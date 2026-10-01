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
	for _, p := range pins {
		if S(p, "name") != name || S(p, "sha256") != S(d, "digest", "sha256") {
			continue
		}
		if pp := O(p, "package"); pp != nil {
			dp := O(d, "annotations", "package")
			if S(dp, "name") != S(pp, "name") || S(dp, "version") != S(pp, "version") || S(dp, "treeDigest", "sha256") != S(pp, "treeDigest") {
				return failf("%s: SLSA Build L3: tool %s is the pinned binary, but its package %s %s (files sha256:%s) is not the pinned one", where, name,
					S(dp, "name"), S(dp, "version"), short(S(dp, "treeDigest", "sha256")))
			}
		}
		if pt := O(p, "toolchain"); pt != nil {
			dt := O(d, "annotations", "toolchain")
			if S(dt, "treeDigest", "sha256") != S(pt, "treeDigest") {
				return failf("%s: SLSA Build L3: %s is the pinned binary, but its toolchain (files sha256:%s) is not the pinned one", where, name, short(S(dt, "treeDigest", "sha256")))
			}
		}
		return nil
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
	rec, err := trust.Open(path, role, FWProvisioning)
	if err != nil {
		return err
	}
	stage := S(rec, "predicate", "buildDefinition", "externalParameters", "stage")
	track := provisioningTrack[stage]
	if track == "" {
		return failf("%s: provisioning at stage %q, which no track rates", label, stage)
	}
	if trackClaim(policy, track) < 3 {
		return failf("%s: provisioned at %s, which is rated %s L%d under its policy; Firmware L3 needs every provisioning site at L3 or higher in its own track (rule 2)",
			label, S(rec, "predicate", "hwProvision", "site", "name"), TrackTitle[track], trackClaim(policy, track))
	}
	what := fmt.Sprintf("%s: provisioning record", label)
	if track == "ASSEMBLY" {
		return keyAccredited(trust, policy, path, role, what)
	}
	return keyL3(trust, policy, path, role, what)
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

// fpgaFirmwareL3 runs Firmware L3 for the FPGA board: the board owner's
// images and the root of trust's firmware, each under its own trust root
// and policy; the at-boot check for every received board; and rule 2 for
// the EMS's provisioning of each board and the root of trust vendor's
// provisioning of each unit on them.
func fpgaFirmwareL3(bundle string, trust *TrustRoot, policy Obj, rot *RoTResult, units map[string]*BoardUnit, received []string, bootsDir string) ([]Obj, error) {
	label := "Firmware L3"
	if bootsDir == "" || len(received) == 0 {
		return nil, failf("%s: the at-boot check is required; pass the received boards and what they returned at boot (--boards, --boots)", label)
	}
	design := filepath.Join(bundle, FPGADesignDir)
	builder := S(policy, "firmware", "builder")
	board := []fwRelease{
		{Image: FPGAFWImage, Bundle: design, Record: "att/" + FPGAFWAtt, Role: builder, Review: true},
		{Image: FlashImage, Bundle: design, Record: "att/" + FlashAtt, Role: builder},
	}
	boardInputs, err := firmwareL3(trust, policy, board, label+": board")
	if err != nil {
		return nil, err
	}
	rotFW := []fwRelease{{Image: RoTFWImage, Bundle: rot.Bundle, Record: "att/" + RoTFWAtt, Role: "firmware-platform", Review: true}}
	rotInputs, err := firmwareL3(rot.Trust, rot.Policy, rotFW, label+": root of trust")
	if err != nil {
		return nil, err
	}
	// Inputs are named relative to the board bundle.
	var inputs []Obj
	for dir, list := range map[string][]Obj{design: boardInputs, rot.Bundle: rotInputs} {
		rel, err := filepath.Rel(bundle, dir)
		if err != nil {
			return nil, err
		}
		for _, in := range list {
			inputs = append(inputs, Obj{"name": filepath.ToSlash(filepath.Join(rel, S(in, "name"))), "digest": get(in, "digest")})
		}
	}
	sortByName(inputs)
	for _, serial := range sortedKeys(anyUnits(units)) {
		u := units[serial]
		if err := provisioningSiteL3(trust, policy, filepath.Join(bundle, "att", BoardProvAtt(serial)), S(policy, "firmware", "provisioningSigner"), label+": board "+serial); err != nil {
			return nil, err
		}
		if err := provisioningSiteL3(rot.Trust, rot.Policy, filepath.Join(rot.Bundle, "att", RoTProvAtt(u.RoTUnit)), S(rot.Policy, "firmware", "provisioningSigner"),
			label+": root of trust "+short(u.RoTUnit)); err != nil {
			return nil, err
		}
	}
	fmt.Println(firmwareL3Summary(append(board, rotFW...)))
	fmt.Printf("Firmware L3: every provisioning site is rated L3 in its own track (the EMS for %d boards, the root of trust's test house for their units)\n", len(units))
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

// caliptraFirmwareL3 runs Firmware L3 for the Caliptra example: its ROM, FMC
// and runtime, and rule 2 for the test house that provisioned each unit.
func caliptraFirmwareL3(bundle string, trust *TrustRoot, policy Obj, units []string) ([]Obj, error) {
	label := "Firmware L3"
	var releases []fwRelease
	for _, im := range []struct{ image, record, review string }{
		{Images["rom"], FWAtt["rom"], "caliptra-rom"},
		{Images["fmc"], FWAtt["bundle"], "caliptra-fmc"},
		{Images["runtime"], FWAtt["bundle"], "caliptra-runtime"},
	} {
		releases = append(releases, fwRelease{Image: im.image, Bundle: bundle, Record: "att/" + im.record, Role: "firmware-platform", Review: true, ReviewName: im.review})
	}
	inputs, err := firmwareL3(trust, policy, releases, label)
	if err != nil {
		return nil, err
	}
	for _, u := range units {
		if err := provisioningSiteL3(trust, policy, filepath.Join(bundle, "att", ProvAtt(u)), S(policy, "firmware", "provisioningSigner"), label+": unit "+u); err != nil {
			return nil, err
		}
	}
	fmt.Println(firmwareL3Summary(releases))
	return inputs, nil
}
