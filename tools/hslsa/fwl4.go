package hslsa

// Firmware L4 (spec, "L4 defense profile"), on top of Firmware L3:
//
//	an independent party reproduces each image built from source bit for
//	bit; two-person review on releases; per-unit data is covered by
//	provisioning readback instead; a closed vendor binary caps the product
//	at Firmware L3 unless its vendor supplies an independent rebuild
//
// A rebuild record is the second builder's own SLSA provenance for the same
// build: the same build type and parameters, the same sources, tools the
// policy pins, and the release record it rebuilt among its inputs. Its
// subjects are the images the second builder got, and the verifier compares
// them with the release's. An image the build platform lays out from images
// it already has (the FPGA board's flash image, whose boot manifest the
// owner's code signer signs) runs no step code and is built from no source:
// its parts are rebuilt, and the root of trust checks its signature at boot.
// Release approvals are signed by people the buyer enrolled as release
// approvers, each with a key of their own.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// ReleaseApprovalType is a person's approval of a firmware release record.
	ReleaseApprovalType = NS + "/release-approval/v0.1"
	// ReleaseApproverRole signs release approvals.
	ReleaseApproverRole = "release-approver"
)

// FWRebuildAtt is the rebuild record of a firmware release record, kept beside it.
func FWRebuildAtt(record string) string { return "rebuild-" + filepath.Base(record) }

func recordStem(record string) string {
	return strings.TrimSuffix(filepath.Base(record), ".intoto.json")
}

// ApprovalAtt is one approver's approval of a release record, kept beside it.
func ApprovalAtt(record, approver string) string {
	return "approval-" + recordStem(record) + "-" + slug(approver) + ".intoto.json"
}

// FirmwareRebuild is the second builder for one firmware release record (a
// path inside bundle, such as att/fw-rot.intoto.json). build runs the same
// build again into a scratch bundle of its own, signing with a key that
// exists only for this run; the record it makes there becomes the rebuild
// record: the same build definition, with the release record added to its
// inputs, and the images named in images, as rebuilt, for subjects. It is
// signed with key and written to out. The builder id is whatever
// HSLSA_BUILDER_ID says, which must not be the release's.
func FirmwareRebuild(bundle, record string, images []string, key, out string, build func(tmp, scratchKey string) error) error {
	relPath := filepath.Join(bundle, record)
	rel, err := DecodeEnvelope(relPath)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "hslsa-fw-rebuild-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	tmp := filepath.Join(work, "bundle")
	for _, d := range []string{"att", "artifacts"} {
		if err := os.MkdirAll(filepath.Join(tmp, d), 0o755); err != nil {
			return err
		}
	}
	if _, err := Keygen(work, "scratch"); err != nil {
		return err
	}
	if err := build(tmp, filepath.Join(work, "scratch.key.pem")); err != nil {
		return fmt.Errorf("rebuild: %w", err)
	}
	got, err := DecodeEnvelope(filepath.Join(tmp, record))
	if err != nil {
		return fmt.Errorf("rebuild: the build made no %s: %w", record, err)
	}
	released, rebuilt := map[string]Obj{}, map[string]Obj{}
	for _, s := range Objs(rel, "subject") {
		released[S(s, "name")] = s
	}
	for _, s := range Objs(got, "subject") {
		rebuilt[S(s, "name")] = s
	}
	var subjects []Obj
	for _, im := range images {
		if released[im] == nil {
			return fmt.Errorf("rebuild: %s does not name %s", record, im)
		}
		if rebuilt[im] == nil {
			return fmt.Errorf("rebuild: the build made no %s", im)
		}
		subjects = append(subjects, rebuilt[im])
	}
	relRef := relRD(bundle, filepath.ToSlash(record))
	relRef["annotations"] = Obj{"kind": "release"}
	pred := O(got, "predicate")
	bd := O(pred, "buildDefinition")
	bd["resolvedDependencies"] = append([]any{relRef}, anyObjs(Objs(bd, "resolvedDependencies"))...)
	// What else the build made (logs, SBOMs) stays in the scratch bundle.
	delete(O(pred, "runDetails"), "byproducts")
	stmt, err := statement(subjects, SLSAProvenance, pred)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, out); err != nil {
		return err
	}
	for _, im := range images {
		a, b := S(released[im], "digest", "sha256"), S(rebuilt[im], "digest", "sha256")
		if a == b {
			fmt.Printf("rebuild: %s is bit for bit the released one, sha256:%s\n", im, short(a))
		} else {
			fmt.Printf("rebuild: %s differs: released sha256:%s, rebuilt sha256:%s (recorded in %s)\n", im, short(a), short(b), filepath.Base(out))
		}
	}
	return nil
}

// RoTFirmwareRebuild rebuilds the root of trust firmware of bundle from src,
// as RoTFirmware built it, at the release's security version.
func RoTFirmwareRebuild(bundle, src, key, out string, isolate bool) error {
	rel, err := DecodeEnvelope(filepath.Join(bundle, "att", RoTFWAtt))
	if err != nil {
		return err
	}
	svn, _ := Int(rel, "predicate", "buildDefinition", "externalParameters", "svn")
	return FirmwareRebuild(bundle, "att/"+RoTFWAtt, []string{RoTFWImage}, key, out, func(tmp, scratch string) error {
		// The rebuilder holds no code signing key: the signature is not part
		// of the image, so a scratch key signs it.
		return RoTFirmware(tmp, src, scratch, scratch, svn, isolate)
	})
}

// FPGAFirmwareRebuild rebuilds the FPGA board's SoC firmware of the design
// bundle from the sources the lock pins, as FPGAFirmware built it.
func FPGAFirmwareRebuild(bundle, lockPath, key, cache, out string, isolate bool) error {
	return FirmwareRebuild(bundle, "att/"+FPGAFWAtt, []string{FPGAFWImage}, key, out, func(tmp, scratch string) error {
		return FPGAFirmware(tmp, lockPath, scratch, cache, isolate)
	})
}

// CaliptraFirmwareRebuild makes the rebuild records of the Caliptra ROM and
// firmware bundle from buildDir, the second builder's own build of the
// caliptra-sw commit the lock pins, as CaliptraFirmware made the releases.
func CaliptraFirmwareRebuild(bundle, lockPath, buildDir, key string) error {
	for _, r := range []struct {
		record string
		images []string
	}{
		{FWAtt["rom"], []string{Images["rom"]}},
		{FWAtt["bundle"], []string{Images["bundle"], Images["fmc"], Images["runtime"]}},
	} {
		out := filepath.Join(bundle, "att", FWRebuildAtt(r.record))
		if err := FirmwareRebuild(bundle, "att/"+r.record, r.images, key, out, func(tmp, scratch string) error {
			return CaliptraFirmware(tmp, lockPath, buildDir, scratch)
		}); err != nil {
			return err
		}
	}
	return nil
}

// ReleaseApprove is one approver's sign-off of a firmware release record:
// its subject is the record, its predicate names the approver and the
// images the record releases. It is signed with the approver's own key.
func ReleaseApprove(bundle, record, approver, key, out string) error {
	if strings.TrimSpace(approver) == "" {
		return fmt.Errorf("an approval names its approver")
	}
	rel, err := DecodeEnvelope(filepath.Join(bundle, record))
	if err != nil {
		return err
	}
	relRef := relRD(bundle, filepath.ToSlash(record))
	stmt, err := statement([]Obj{relRef}, ReleaseApprovalType, Obj{
		"approver":   Obj{"name": approver},
		"decision":   "approve",
		"release":    relRef,
		"images":     anyObjs(Objs(rel, "subject")),
		"approvedAt": Now(),
	})
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	if out == "" {
		out = filepath.Join(bundle, filepath.Dir(record), ApprovalAtt(record, approver))
	}
	if _, err := Sign(stmt, signer, out); err != nil {
		return err
	}
	fmt.Printf("approval: %s approved %s\n", approver, record)
	return nil
}

// checkFirmwareRebuild accepts the independent rebuild of release r, whose
// record rel passed Firmware L3: the rebuild record beside it is signed by a
// rebuilder whose key no other role holds and whose enrollment names another
// organization than the build platform's; it ran on another builder; it
// names this release record; it is the same build (build type and
// parameters) of the same sources; it meets SLSA Build L3 itself, with tools
// the policy pins; and it reproduced the image bit for bit. It returns the
// rebuild record, named inside r.Bundle, for the VSA's inputs.
func checkFirmwareRebuild(trust *TrustRoot, policy Obj, r fwRelease, rel Obj, label string) (Obj, error) {
	where := label + ": " + r.Image
	recPath := filepath.Join(r.Bundle, r.Record)
	name := filepath.ToSlash(filepath.Join(filepath.Dir(r.Record), FWRebuildAtt(r.Record)))
	path := filepath.Join(r.Bundle, name)
	if !fileExists(path) {
		return nil, failf("%s: no independent rebuild (%s); an image nobody else has rebuilt from its source, such as a closed vendor binary, caps the product at Firmware L3", where, FWRebuildAtt(r.Record))
	}
	stmt, err := trust.Open(path, RebuilderRole, SLSAProvenance)
	if err != nil {
		return nil, err
	}
	if err := independentOf(trust, path, RebuilderRole, []string{r.Role}, where+": the rebuild"); err != nil {
		return nil, err
	}
	if id := S(stmt, "predicate", "runDetails", "builder", "id"); id == S(rel, "predicate", "runDetails", "builder", "id") {
		return nil, failf("%s: the rebuild ran on builder %s, which built the release; it needs a second builder", where, id)
	}
	named := false
	sources := func(s Obj, skipRelease bool) map[string]Obj {
		out := map[string]Obj{}
		for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
			if S(d, "annotations", "kind") == "release" {
				if skipRelease && S(d, "name") == filepath.ToSlash(r.Record) && jsonEqual(get(d, "digest"), fileDigest(recPath)) {
					named = true
				}
				continue
			}
			if S(d, "annotations", "version") == "" {
				out[S(d, "name")] = O(d, "digest")
			}
		}
		return out
	}
	got, want := sources(stmt, true), sources(rel, false)
	if !named {
		return nil, failf("%s: the rebuild record does not name this release (%s)", where, r.Record)
	}
	bd, rbd := O(stmt, "predicate", "buildDefinition"), O(rel, "predicate", "buildDefinition")
	if S(bd, "buildType") != S(rbd, "buildType") || !jsonEqual(get(bd, "externalParameters"), get(rbd, "externalParameters")) {
		return nil, failf("%s: the rebuild is another build than the release's: its build type or parameters differ", where)
	}
	for _, n := range sortedKeys(anyObjMap(want)) {
		if !jsonEqual(got[n], want[n]) {
			return nil, failf("%s: the rebuild did not build from the release's %s", where, n)
		}
	}
	for _, n := range sortedKeys(anyObjMap(got)) {
		if want[n] == nil {
			return nil, failf("%s: the rebuild used %s, which the release does not name", where, n)
		}
	}
	if err := buildL3(stmt, Objs(policy, "firmware", "toolPins"), where+": the rebuild"); err != nil {
		return nil, err
	}
	var released, rebuilt Obj
	for _, s := range Objs(rel, "subject") {
		if S(s, "name") == r.Image {
			released = s
		}
	}
	for _, s := range Objs(stmt, "subject") {
		if S(s, "name") == r.Image {
			rebuilt = s
		}
	}
	if rebuilt == nil {
		return nil, failf("%s: the rebuild record does not name the image", where)
	}
	if !jsonEqual(get(rebuilt, "digest"), get(released, "digest")) {
		return nil, failf("%s: the independent rebuild gave sha256:%s, not the released sha256:%s; the image does not reproduce from its source, or one of the two builds was tampered with",
			where, short(S(rebuilt, "digest", "sha256")), short(S(released, "digest", "sha256")))
	}
	return Obj{"name": name, "digest": fileDigest(path)}, nil
}

// checkReleaseApprovals is two-person review on one release record: at least
// firmware.release.minApprovers approvals of it, which L4 needs to be two or
// more, each signed by a release approver's own key, no two by one person,
// and none with the build platform's key. It returns the approvals, named
// inside r.Bundle.
func checkReleaseApprovals(trust *TrustRoot, policy Obj, r fwRelease, label string) ([]Obj, error) {
	where := label + ": " + filepath.Base(r.Record)
	min, _ := Int(policy, "firmware", "release", "minApprovers")
	if min < 2 {
		return nil, failf("%s: the policy does not require two-person review of firmware releases (firmware.release.minApprovers: 2)", label)
	}
	recPath := filepath.Join(r.Bundle, r.Record)
	files, err := filepath.Glob(filepath.Join(filepath.Dir(recPath), "approval-"+recordStem(r.Record)+"-*.intoto.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	byKey, byPerson := map[string]string{}, map[string]bool{}
	var inputs []Obj
	for _, f := range files {
		file := filepath.Base(f)
		stmt, err := trust.Open(f, ReleaseApproverRole, ReleaseApprovalType)
		if err != nil {
			return nil, err
		}
		k, err := trust.SignerKey(f, ReleaseApproverRole)
		if err != nil {
			return nil, err
		}
		for _, pk := range trust.Roles[r.Role] {
			if pk.ID == k.ID {
				return nil, failf("%s: approval %s is signed with the build platform's key; each approver needs a key of their own", where, file)
			}
		}
		sub := firstSubject(stmt)
		if S(sub, "name") != filepath.ToSlash(r.Record) || !jsonEqual(get(sub, "digest"), fileDigest(recPath)) {
			return nil, failf("%s: approval %s approves another release record", where, file)
		}
		if d := S(stmt, "predicate", "decision"); d != "approve" {
			return nil, failf("%s: approval %s does not approve the release (decision %q)", where, file, d)
		}
		who := S(stmt, "predicate", "approver", "name")
		if who == "" {
			return nil, failf("%s: approval %s names no approver", where, file)
		}
		if prev, ok := byKey[k.ID]; ok {
			return nil, failf("%s: the approvals by %s and %s are signed with the same key; each approver needs a key of their own", where, prev, who)
		}
		if byPerson[who] {
			return nil, failf("%s: %s approved the release twice; two-person review needs two people", where, who)
		}
		byKey[k.ID], byPerson[who] = who, true
		rel, _ := filepath.Rel(r.Bundle, f)
		inputs = append(inputs, Obj{"name": filepath.ToSlash(rel), "digest": fileDigest(f)})
	}
	if int64(len(byPerson)) < min {
		return nil, failf("%s: %d approver(s) signed off the release; the policy requires %d (firmware.release.minApprovers)", where, len(byPerson), min)
	}
	return inputs, nil
}

// firmwareL4 runs the Firmware L4 rules over releases that passed Firmware
// L3 under the same trust root and policy: an independent rebuild of each
// image built from source, or r.Rebuilt where the release has another
// independent party's reproduction, and two-person review of each release
// record. It returns the rebuild records and approvals, for the VSA's inputs.
func firmwareL4(trust *TrustRoot, policy Obj, releases []fwRelease, label string) ([]Obj, error) {
	var inputs []Obj
	approved := map[string]bool{}
	for _, r := range releases {
		rel, err := trust.Open(filepath.Join(r.Bundle, r.Record), r.Role, SLSAProvenance)
		if err != nil {
			return nil, err
		}
		if !fwBuildsRunNoStepCode[buildType(rel)] {
			var in Obj
			if r.Rebuilt != nil && !fileExists(filepath.Join(r.Bundle, filepath.Dir(r.Record), FWRebuildAtt(r.Record))) {
				in, err = r.Rebuilt(rel)
			} else {
				in, err = checkFirmwareRebuild(trust, policy, r, rel, label)
			}
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, in)
		}
		if id := r.Bundle + "\x00" + r.Record; !approved[id] {
			approved[id] = true
			in, err := checkReleaseApprovals(trust, policy, r, label)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, in...)
		}
	}
	return inputs, nil
}

// provisioningReadback is Firmware L4 for per-unit data, which no one can
// rebuild: the provisioning record's image-readback and fuse-readback checks
// passed, and every image it wrote was read back as written.
func provisioningReadback(rec Obj, label string) error {
	hp := O(rec, "predicate", "hwProvision")
	for _, name := range []string{"image-readback", "fuse-readback"} {
		if !hasCheck(Objs(hp, "checks"), name) {
			return failf("%s: the provisioning record has no passing %s check; at Firmware L4 per-unit data is covered by readback", label, name)
		}
	}
	images := Objs(hp, "images")
	if len(images) == 0 {
		return failf("%s: the provisioning record lists no image it wrote", label)
	}
	for _, im := range images {
		if S(im, "readback", "sha256") == "" || S(im, "readback", "sha256") != S(im, "digest", "sha256") {
			return failf("%s: %s was not read back as it was written", label, S(im, "name"))
		}
	}
	return nil
}

// firmwareL4Summary is the line the checks print after Firmware L4 passed.
func firmwareL4Summary(label string, rebuilt []string) string {
	return fmt.Sprintf("%s: PASSED, %s reproduced bit for bit by an independent rebuilder; every release approved by two people; per-unit data read back",
		label, strings.Join(rebuilt, ", "))
}
