package hslsa

// Firmware L4 rules on the Firmware L3 test release (fwl3_test.go): an
// independent rebuilder reproduces fw.bin, two people approve each release
// record, and the buyer's trust root enrolls every key under its company.
// image.bin is a layout of fw.bin with no step code, so it needs no rebuild.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fwl4Org = map[string][2]string{
	"firmware-platform": {"Example Firmware Co", "duns:100000051"},
	"review-provider":   {"Example Review Lab", "duns:100000052"},
	TLogRole:            {"Example Buyer", "duns:100000001"},
	RebuilderRole:       {"Example Rebuild Services", "duns:100000053"},
	"approver-alice":    {"Example Firmware Co", "duns:100000051"},
	"approver-bob":      {"Example Firmware Co", "duns:100000051"},
}

// fwl4Enroll builds a buyer-run trust root over the keys in keys: each key
// file (by its name in org) enrolled for its role under its company.
// approver-* keys are enrolled as release approvers.
func fwl4Enroll(t *testing.T, work, name string, org map[string][2]string) *TrustRoot {
	t.Helper()
	keys, dir := filepath.Join(work, "keys"), filepath.Join(work, name)
	must(t, os.MkdirAll(dir, 0o755))
	enroll := func(file, role string, o [2]string) {
		e := Enrollment{Role: role, OrgName: o[0], OrgID: o[1], Site: o[0], Custody: "file",
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		must(t, Enroll(filepath.Join(keys, "buyer-root.key.pem"), filepath.Join(keys, file+".pub.pem"), e, filepath.Join(dir, file+".intoto.json")))
	}
	for file, o := range org {
		role := file
		if strings.HasPrefix(file, "approver-") {
			role = ReleaseApproverRole
		}
		enroll(file, role, o)
	}
	out := filepath.Join(work, name+".json")
	ok(BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), out))
	return ok(LoadTrustRoot(out))
}

// fwl4Build is the build of fw.bin as the release ran it, by builder id, with
// content: the record it signs with key, in bundle.
func fwl4Build(bundle, key, id, content string) error {
	if err := os.MkdirAll(filepath.Join(bundle, "artifacts"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bundle, "artifacts", "fw.bin"), []byte(content), 0o644); err != nil {
		return err
	}
	fw, err := imageRD(filepath.Join(bundle, "artifacts", "fw.bin"))
	if err != nil {
		return err
	}
	goDep := Obj{"name": "go", "uri": "pkg:golang/go@1.25.14", "digest": Obj{"sha256": strings.Repeat("a", 64)},
		"annotations": Obj{"version": "1.25.14", "toolchain": Obj{"treeDigest": Obj{"sha256": strings.Repeat("b", 64)}}}}
	stmt, err := statement([]Obj{fw}, SLSAProvenance, Obj{
		"buildDefinition": Obj{
			"buildType":            GoBuildType,
			"externalParameters":   Obj{},
			"internalParameters":   isolationParams(&Sandbox{Version: "bubblewrap 0.9.0"}, Obj{"CGO_ENABLED": "0"}),
			"resolvedDependencies": []Obj{rd("main.go", strings.Repeat("c", 64)), goDep},
		},
		"runDetails": Obj{"builder": Obj{"id": id}, "byproducts": []Obj{rd("build.log", strings.Repeat("9", 64))}},
	})
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	_, err = Sign(stmt, signer, filepath.Join(bundle, "att", "fw.intoto.json"))
	return err
}

const fwRebuilderID = "https://example.org/rebuilder"

// fwl4Work is the Firmware L3 release with a rebuild of fw.bin and two
// approvals of each release record, under an enrolled trust root.
func fwl4Work(t *testing.T) (work string, trust *TrustRoot, policy Obj) {
	t.Helper()
	work, _, policy = fwl3Work(t)
	keys := filepath.Join(work, "keys")
	must(t, makeKeys(keys, filepath.Join(work, "pub"), RebuilderRole, "approver-alice", "approver-bob", "buyer-root"))
	trust = fwl4Enroll(t, work, "enrollments", fwl4Org)
	b := filepath.Join(work, "bundle")
	must(t, FirmwareRebuild(b, "att/fw.intoto.json", []string{"fw.bin"}, filepath.Join(keys, RebuilderRole+".key.pem"),
		filepath.Join(b, "att", FWRebuildAtt("fw.intoto.json")), func(tmp, scratch string) error {
			return fwl4Build(tmp, scratch, fwRebuilderID, "firmware")
		}))
	for _, rec := range []string{"att/fw.intoto.json", "att/image.intoto.json"} {
		must(t, ReleaseApprove(b, rec, "Alice", filepath.Join(keys, "approver-alice.key.pem"), ""))
		must(t, ReleaseApprove(b, rec, "Bob", filepath.Join(keys, "approver-bob.key.pem"), ""))
	}
	O(policy, "claims")["firmware"] = []any{"HSLSA_FIRMWARE_LEVEL_4"}
	O(policy, "firmware")["release"] = Obj{"minApprovers": 2}
	return work, trust, policy
}

func fwl4Check(t *testing.T, work string, trust *TrustRoot, policy Obj) ([]Obj, error) {
	t.Helper()
	if _, err := firmwareL3(trust, policy, fwl3Releases(work), "Firmware L3"); err != nil {
		t.Fatalf("Firmware L3 no longer passes: %v", err)
	}
	return firmwareL4(trust, policy, fwl3Releases(work), "Firmware L4")
}

func TestFirmwareL4Passes(t *testing.T) {
	work, trust, policy := fwl4Work(t)
	inputs := ok(fwl4Check(t, work, trust, policy))
	var names []string
	for _, in := range inputs {
		names = append(names, S(in, "name"))
	}
	want := []string{"att/rebuild-fw.intoto.json", "att/approval-fw-alice.intoto.json", "att/approval-fw-bob.intoto.json",
		"att/approval-image-alice.intoto.json", "att/approval-image-bob.intoto.json"}
	if !equalStrings(names, want) {
		t.Fatalf("inputs %v, want %v", names, want)
	}
	// The rebuild record is the second builder's own build, naming the release.
	rb := ok(DecodeEnvelope(filepath.Join(work, "bundle", "att", "rebuild-fw.intoto.json")))
	deps := Objs(rb, "predicate", "buildDefinition", "resolvedDependencies")
	if S(deps[0], "name") != "att/fw.intoto.json" || S(deps[0], "annotations", "kind") != "release" {
		t.Fatalf("the rebuild's first input is %v, not the release record", deps[0])
	}
	if Has(O(rb, "predicate", "runDetails"), "byproducts") {
		t.Fatal("the rebuild record names byproducts that stay in the rebuilder's scratch bundle")
	}
}

// TestFirmwareL4Accepts: releases that meet Firmware L4 in other ways than
// the fixture's still pass.
func TestFirmwareL4Accepts(t *testing.T) {
	// withCarol enrolls a third approver, from the buyer, and has her approve
	// both release records.
	withCarol := func(t *testing.T, w string) *TrustRoot {
		keys := filepath.Join(w, "keys")
		must(t, makeKeys(keys, filepath.Join(w, "pub"), "approver-carol"))
		org := map[string][2]string{"approver-carol": {"Example Buyer", "duns:100000001"}}
		for k, v := range fwl4Org {
			org[k] = v
		}
		for _, rec := range []string{"att/fw.intoto.json", "att/image.intoto.json"} {
			must(t, ReleaseApprove(filepath.Join(w, "bundle"), rec, "Carol", filepath.Join(keys, "approver-carol.key.pem"), ""))
		}
		return fwl4Enroll(t, w, "enrollments-carol", org)
	}
	cases := map[string]func(t *testing.T, work string, policy Obj) *TrustRoot{
		"three-approvers-where-the-policy-asks-two": func(t *testing.T, w string, _ Obj) *TrustRoot {
			return withCarol(t, w)
		},
		"a-policy-asking-three-approvers-and-three-approved": func(t *testing.T, w string, p Obj) *TrustRoot {
			O(p, "firmware", "release")["minApprovers"] = 3
			return withCarol(t, w)
		},
		"rebuilt-by-another-rebuilder-on-another-builder": func(t *testing.T, w string, _ Obj) *TrustRoot {
			b := filepath.Join(w, "bundle")
			must(t, FirmwareRebuild(b, "att/fw.intoto.json", []string{"fw.bin"}, filepath.Join(w, "keys", RebuilderRole+".key.pem"),
				filepath.Join(b, "att", FWRebuildAtt("fw.intoto.json")), func(tmp, scratch string) error {
					return fwl4Build(tmp, scratch, "https://second-rebuilder.example.org/builders/go@v1", "firmware")
				}))
			org := map[string][2]string{}
			for k, v := range fwl4Org {
				org[k] = v
			}
			org[RebuilderRole] = [2]string{"Example Second Rebuild Co", "duns:100000054"}
			return fwl4Enroll(t, w, "enrollments-second-rebuilder", org)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			work, _, policy := fwl4Work(t)
			trust := edit(t, work, policy)
			inputs := ok(fwl4Check(t, work, trust, policy))
			var names []string
			for _, in := range inputs {
				names = append(names, S(in, "name"))
			}
			if !contains(names, "att/rebuild-fw.intoto.json") {
				t.Fatalf("the release passed, but the inputs %v leave out the rebuild", names)
			}
		})
	}
}

func TestFirmwareL4Rejects(t *testing.T) {
	b := func(w string) string { return filepath.Join(w, "bundle") }
	rebuild := func(w string) string { return filepath.Join(b(w), "att", "rebuild-fw.intoto.json") }
	forgeRebuild := func(t *testing.T, w string, mutate func(bd Obj)) {
		resign(t, rebuild(w), filepath.Join(w, "keys"), RebuilderRole, func(s Obj) { mutate(O(s, "predicate", "buildDefinition")) })
	}
	cases := map[string]struct {
		edit   func(t *testing.T, work string, policy Obj) *TrustRoot
		reason string
	}{
		"no-rebuild": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			must(t, os.Remove(rebuild(w)))
			return nil
		}, "no independent rebuild (rebuild-fw.intoto.json); an image nobody else has rebuilt from its source, such as a closed vendor binary, caps the product at Firmware L3"},
		"rebuild-by-the-build-platform": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			resign(t, rebuild(w), filepath.Join(w, "keys"), "firmware-platform", nil)
			return nil
		}, "no valid signature from role 'rebuilder'"},
		"rebuilder-of-the-same-company": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			org := map[string][2]string{}
			for k, v := range fwl4Org {
				org[k] = v
			}
			org[RebuilderRole] = fwl4Org["firmware-platform"]
			return fwl4Enroll(t, w, "same-org", org)
		}, "the organization that holds the firmware-platform key; L4 needs an independent party"},
		"rebuilder-key-also-the-platform": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			// A buyer-run trust root refuses one key in two roles; a trust
			// root assembled another way may still list one.
			tr := ok(LoadTrustRoot(filepath.Join(w, "enrollments.json")))
			tr.Roles["firmware-platform"] = append(tr.Roles["firmware-platform"], tr.Roles[RebuilderRole]...)
			return tr
		}, "which is also the trust root's firmware-platform key; L4 needs a party of its own"},
		"same-builder": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			resign(t, rebuild(w), filepath.Join(w, "keys"), RebuilderRole, func(s Obj) {
				O(s, "predicate", "runDetails", "builder")["id"] = "https://example.com/builder"
			})
			return nil
		}, "the rebuild ran on builder https://example.com/builder, which built the release; it needs a second builder"},
		"release-not-named": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			forgeRebuild(t, w, func(bd Obj) { bd["resolvedDependencies"] = anyObjs(Objs(bd, "resolvedDependencies")[1:]) })
			return nil
		}, "the rebuild record does not name this release (att/fw.intoto.json)"},
		"release-changed-after-rebuild": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			fwl3Forge(t, w, func(s Obj) { O(s, "predicate", "buildDefinition", "internalParameters")["CGO_ENABLED"] = "0 " })
			return nil
		}, "the rebuild record does not name this release"},
		"other-source": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			forgeRebuild(t, w, func(bd Obj) {
				O(Objs(bd, "resolvedDependencies")[1], "digest")["sha256"] = strings.Repeat("4", 64)
			})
			return nil
		}, "the rebuild did not build from the release's main.go"},
		"extra-source": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			forgeRebuild(t, w, func(bd Obj) {
				bd["resolvedDependencies"] = append(anyObjs(Objs(bd, "resolvedDependencies")), rd("patch.go", strings.Repeat("5", 64)))
			})
			return nil
		}, "the rebuild used patch.go, which the release does not name"},
		"other-parameters": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			forgeRebuild(t, w, func(bd Obj) { bd["externalParameters"] = Obj{"tags": "debug"} })
			return nil
		}, "the rebuild is another build than the release's: its build type or parameters differ"},
		"rebuild-not-isolated": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			forgeRebuild(t, w, func(bd Obj) { delete(O(bd, "internalParameters"), "isolation") })
			return nil
		}, "Firmware L4: fw.bin: the rebuild: SLSA Build L3: no internalParameters.isolation"},
		"rebuild-tool-unpinned": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			forgeRebuild(t, w, func(bd Obj) {
				deps := Objs(bd, "resolvedDependencies")
				O(deps[len(deps)-1], "digest")["sha256"] = strings.Repeat("6", 64)
			})
			return nil
		}, "tool go sha256:6666666666666666 is not on the policy's pinned tool list"},
		"not-reproduced": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			bb := b(w)
			must(t, FirmwareRebuild(bb, "att/fw.intoto.json", []string{"fw.bin"}, filepath.Join(w, "keys", RebuilderRole+".key.pem"), rebuild(w),
				func(tmp, scratch string) error {
					return fwl4Build(tmp, scratch, fwRebuilderID, "firmware with a backdoor")
				}))
			return nil
		}, "the independent rebuild gave sha256:"},
		"one-approver-in-policy": {func(t *testing.T, w string, p Obj) *TrustRoot {
			O(p, "firmware", "release")["minApprovers"] = 1
			return nil
		}, "the policy does not require two-person review of firmware releases (firmware.release.minApprovers: 2)"},
		"one-approval": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			must(t, os.Remove(filepath.Join(b(w), "att", "approval-image-bob.intoto.json")))
			return nil
		}, "image.intoto.json: 1 approver(s) signed off the release; the policy requires 2"},
		"one-person-twice": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			resign(t, filepath.Join(b(w), "att", "approval-fw-bob.intoto.json"), filepath.Join(w, "keys"), "approver-bob", func(s Obj) {
				O(s, "predicate", "approver")["name"] = "Alice"
			})
			return nil
		}, "Alice approved the release twice; two-person review needs two people"},
		"one-key-for-two-people": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			resign(t, filepath.Join(b(w), "att", "approval-fw-bob.intoto.json"), filepath.Join(w, "keys"), "approver-alice", nil)
			return nil
		}, "the approvals by Alice and Bob are signed with the same key"},
		"approval-by-the-build-platform-key": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			resign(t, filepath.Join(b(w), "att", "approval-fw-bob.intoto.json"), filepath.Join(w, "keys"), "firmware-platform", nil)
			tr := ok(LoadTrustRoot(filepath.Join(w, "enrollments.json")))
			tr.Roles[ReleaseApproverRole] = append(tr.Roles[ReleaseApproverRole], tr.Roles["firmware-platform"]...)
			return tr
		}, "approval approval-fw-bob.intoto.json is signed with the build platform's key"},
		"approval-by-an-unenrolled-key": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			must(t, makeKeys(filepath.Join(w, "keys"), filepath.Join(w, "pub"), "mallory"))
			resign(t, filepath.Join(b(w), "att", "approval-fw-bob.intoto.json"), filepath.Join(w, "keys"), "mallory", nil)
			return nil
		}, "no valid signature from role 'release-approver'"},
		"approval-of-another-release": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			must(t, copyFile(filepath.Join(b(w), "att", "approval-image-bob.intoto.json"), filepath.Join(b(w), "att", "approval-fw-bob.intoto.json")))
			return nil
		}, "approval approval-fw-bob.intoto.json approves another release record"},
		"approval-of-an-earlier-record": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			// The release record changes after both approvals, and is rebuilt again.
			fwl3Forge(t, w, func(s Obj) { O(s, "predicate", "runDetails")["metadata"] = Obj{"invocationId": "second"} })
			must(t, FirmwareRebuild(b(w), "att/fw.intoto.json", []string{"fw.bin"}, filepath.Join(w, "keys", RebuilderRole+".key.pem"), rebuild(w),
				func(tmp, scratch string) error { return fwl4Build(tmp, scratch, fwRebuilderID, "firmware") }))
			return nil
		}, "approves another release record"},
		"approval-declined": {func(t *testing.T, w string, _ Obj) *TrustRoot {
			resign(t, filepath.Join(b(w), "att", "approval-fw-bob.intoto.json"), filepath.Join(w, "keys"), "approver-bob", func(s Obj) {
				O(s, "predicate")["decision"] = "reject"
			})
			return nil
		}, `approval approval-fw-bob.intoto.json does not approve the release (decision "reject")`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			work, trust, policy := fwl4Work(t)
			if tr := c.edit(t, work, policy); tr != nil {
				trust = tr
			}
			_, err := fwl4Check(t, work, trust, policy)
			rejects(t, err, c.reason)
		})
	}
}

// Rule 2 and readback at Firmware L4: the provisioning site rated L4 in its
// own track, and every image and the fuses read back as written.
func TestProvisioningSiteL4(t *testing.T) {
	work := t.TempDir()
	keys, pub := filepath.Join(work, "keys"), filepath.Join(work, "pub")
	must(t, makeKeys(keys, pub, "test-site", "buyer-root"))
	signer := ok(LoadSigner(filepath.Join(keys, "test-site.key.pem")))
	rec := func(name string, checks []Obj, images []Obj) string {
		path := filepath.Join(work, name+".intoto.json")
		ok(Sign(ok(statement([]Obj{rd("urn:hslsa:unit:u1", strings.Repeat("f", 64))}, FWProvisioning, Obj{
			"buildDefinition": Obj{"buildType": ProvisionType, "externalParameters": Obj{"stage": "final-test"}},
			"hwProvision":     Obj{"site": Obj{"name": "Example Test House"}, "checks": checks, "images": images},
		})), signer, path))
		return path
	}
	dir := filepath.Join(work, "enroll")
	must(t, os.MkdirAll(dir, 0o755))
	e := Enrollment{Role: "test-site", OrgName: "Example Test Services", OrgID: "duns:100000014", Site: "Example Test House", Custody: "hsm",
		Accreditation: Accreditation{Scheme: "iso-iec-20243", ID: "X-1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	must(t, Enroll(filepath.Join(keys, "buyer-root.key.pem"), filepath.Join(keys, "test-site.pub.pem"), e, filepath.Join(dir, "test-site.intoto.json")))
	ok(BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), filepath.Join(work, "tr.json")))
	trust := ok(LoadTrustRoot(filepath.Join(work, "tr.json")))

	l4 := Obj{"accreditations": []any{"iso-iec-20243"}, "claims": Obj{"lot": []any{"HSLSA_PACKAGE_TEST_LEVEL_4"}}}
	l3 := Obj{"accreditations": []any{"iso-iec-20243"}, "claims": Obj{"lot": []any{"HSLSA_PACKAGE_TEST_LEVEL_3"}}}
	readback := []Obj{check("image-readback", true, ""), check("fuse-readback", true, "")}
	image := func(readback string) []Obj {
		return []Obj{{"name": "fw.bin", "digest": Obj{"sha256": strings.Repeat("1", 64)}, "readback": Obj{"sha256": readback}}}
	}
	good := rec("good", readback, image(strings.Repeat("1", 64)))
	must(t, provisioningSite(trust, l4, good, "test-site", "Firmware L4: unit u1", 4))
	// The same record serves Firmware L3, which needs no readback.
	must(t, provisioningSite(trust, l3, rec("no-checks", nil, nil), "test-site", "Firmware L3: unit u1", 3))
	rejects(t, provisioningSite(trust, l3, good, "test-site", "Firmware L4: unit u1", 4),
		"rated Package/Test L3 under its policy; Firmware L4 needs every provisioning site at L4 or higher in its own track (rule 2)")
	rejects(t, provisioningSite(trust, l4, rec("no-checks", nil, image(strings.Repeat("1", 64))), "test-site", "Firmware L4: unit u1", 4),
		"the provisioning record has no passing image-readback check")
	rejects(t, provisioningSite(trust, l4, rec("fuses-failed", []Obj{check("image-readback", true, ""), check("fuse-readback", false, "")}, image(strings.Repeat("1", 64))),
		"test-site", "Firmware L4: unit u1", 4), "no passing fuse-readback check")
	rejects(t, provisioningSite(trust, l4, rec("no-images", readback, nil), "test-site", "Firmware L4: unit u1", 4), "lists no image it wrote")
	rejects(t, provisioningSite(trust, l4, rec("other-bytes", readback, image(strings.Repeat("2", 64))), "test-site", "Firmware L4: unit u1", 4),
		"fw.bin was not read back as it was written")
}

// The Caliptra ROM may count as independently rebuilt by the party that froze
// it: step 6a's rom-matches-frozen check, against the Caliptra TAC's digest.
func TestROMFrozenStandsInForRebuild(t *testing.T) {
	work := t.TempDir()
	keys, pub := filepath.Join(work, "keys"), filepath.Join(work, "pub")
	must(t, makeKeys(keys, pub, "firmware-platform", "flow-platform"))
	must(t, BuildTrustRoot(pub, filepath.Join(work, "trust-root.json")))
	trust := ok(LoadTrustRoot(filepath.Join(work, "trust-root.json")))
	b := filepath.Join(work, "bundle")
	must(t, os.MkdirAll(filepath.Join(b, "artifacts"), 0o755))
	must(t, os.WriteFile(filepath.Join(b, "artifacts", Images["rom"]), []byte("rom"), 0o644))
	romRD := ok(rd2(filepath.Join(b, "artifacts", Images["rom"]), ""))
	ok(Sign(ok(statement([]Obj{romRD}, SLSAProvenance, Obj{"buildDefinition": Obj{"buildType": "x"}})),
		ok(LoadSigner(filepath.Join(keys, "firmware-platform.key.pem"))), filepath.Join(b, "att", FWAtt["rom"])))
	rel := ok(DecodeEnvelope(filepath.Join(b, "att", FWAtt["rom"])))
	merge := func(frozen bool, deps []Obj) {
		ok(Sign(ok(statement([]Obj{rd("design.tar", strings.Repeat("7", 64))}, DesignFlow, Obj{
			"buildDefinition": Obj{"resolvedDependencies": deps},
			"hwFlow":          Obj{"step": "rom-merge", "checks": []Obj{check("rom-matches-frozen", frozen, "")}},
		})), ok(LoadSigner(filepath.Join(keys, "flow-platform.key.pem"))), filepath.Join(b, "att", AttName("rom-merge"))))
	}
	rejects(t, ok2(romFrozen(b, trust, rel)), "no ROM merge record whose rom-matches-frozen check could stand in")
	merge(true, []Obj{romRD, envRD(b, FWAtt["rom"])})
	in := ok(romFrozen(b, trust, rel))
	if S(in, "name") != "att/"+AttName("rom-merge") {
		t.Fatalf("input %v", in)
	}
	merge(false, []Obj{romRD, envRD(b, FWAtt["rom"])})
	rejects(t, ok2(romFrozen(b, trust, rel)), "the ROM merge record has no passing rom-matches-frozen check")
	merge(true, []Obj{rd(Images["rom"], strings.Repeat("8", 64)), envRD(b, FWAtt["rom"])})
	rejects(t, ok2(romFrozen(b, trust, rel)), "the ROM merge record does not name this ROM release and image")
}

// The root of trust firmware, built for real and rebuilt by a second
// builder: the Go build reproduces bit for bit, and the rebuild passes the
// Firmware L4 check; a rebuild from changed source does not.
func TestRoTFirmwareRebuildReproduces(t *testing.T) {
	if _, err := NewSandbox(); err != nil {
		t.Skipf("no sandbox: %v", err)
	}
	work := t.TempDir()
	keys := filepath.Join(work, "keys")
	must(t, makeKeys(keys, filepath.Join(work, "pub"), "firmware-platform", "code-signer", RebuilderRole, "approver-alice", "approver-bob", "buyer-root"))
	src := filepath.Join(root, "e2e", "fpga", "rot", "firmware")
	b := filepath.Join(work, "bundle")
	must(t, RoTFirmware(b, src, filepath.Join(keys, "firmware-platform.key.pem"), filepath.Join(keys, "code-signer.key.pem"), 3, true))
	t.Setenv("HSLSA_BUILDER_ID", "https://rebuild.example.org/rot")
	out := filepath.Join(b, "att", FWRebuildAtt(RoTFWAtt))
	must(t, RoTFirmwareRebuild(b, src, filepath.Join(keys, RebuilderRole+".key.pem"), out, true))

	org := map[string][2]string{"firmware-platform": fwl4Org["firmware-platform"], RebuilderRole: fwl4Org[RebuilderRole]}
	trust := fwl4Enroll(t, work, "enrollments", org)
	pin := ok(ToolPin("go"))
	policy := Obj{"firmware": Obj{"toolPins": []any{pin}}}
	r := fwRelease{Image: RoTFWImage, Bundle: b, Record: "att/" + RoTFWAtt, Role: "firmware-platform"}
	rel := ok(trust.Open(filepath.Join(b, "att", RoTFWAtt), "firmware-platform", SLSAProvenance))
	in := ok(checkFirmwareRebuild(trust, policy, r, rel, "Firmware L4"))
	if S(in, "name") != "att/"+FWRebuildAtt(RoTFWAtt) {
		t.Fatalf("input %v", in)
	}
	// The security version is the release's.
	rb := ok(DecodeEnvelope(out))
	if n, _ := Int(rb, "predicate", "buildDefinition", "externalParameters", "svn"); n != 3 {
		t.Fatalf("the rebuild ran at svn %d, not the release's 3", n)
	}

	// A second builder with other source gets another image, and says so.
	changed := filepath.Join(work, "changed")
	must(t, os.MkdirAll(changed, 0o755))
	data := ok(os.ReadFile(filepath.Join(src, "main.go")))
	must(t, os.WriteFile(filepath.Join(changed, "main.go"), append(data, []byte("\nvar backdoor []byte\n\nfunc init() {\n\tif len(backdoor) == 7 {\n\t\tprintln(\"backdoor\")\n\t}\n}\n")...), 0o644))
	must(t, RoTFirmwareRebuild(b, changed, filepath.Join(keys, RebuilderRole+".key.pem"), out, true))
	if S(firstSubject(ok(DecodeEnvelope(out))), "digest", "sha256") == S(firstSubject(rel), "digest", "sha256") {
		t.Fatal("changed source rebuilt to the released image")
	}
	rejects(t, ok2(checkFirmwareRebuild(trust, policy, r, rel, "Firmware L4")), "the rebuild did not build from the release's")
}
