package hslsa

// Firmware L3 rules on a small synthetic release: one image built isolated
// with a pinned toolchain, reviewed, and in the buyer's log; and one image
// container with no step code. Each case forges a record with a valid
// signature, as a compromised build platform could, or changes the policy.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fwl3Origin = "example buyer firmware log"

// fwl3Work is a bundle with fw.bin (a Go build) and image.bin (a layout of
// it), their reviews and log proofs, and the policy that accepts them.
func fwl3Work(t *testing.T) (work string, trust *TrustRoot, policy Obj) {
	t.Helper()
	work = t.TempDir()
	keys, pub := filepath.Join(work, "keys"), filepath.Join(work, "pub")
	must(t, makeKeys(keys, pub, "firmware-platform", "review-provider", TLogRole))
	must(t, BuildTrustRoot(pub, filepath.Join(work, "trust-root.json")))
	trust = ok(LoadTrustRoot(filepath.Join(work, "trust-root.json")))
	b := filepath.Join(work, "bundle")
	must(t, os.MkdirAll(filepath.Join(b, "artifacts"), 0o755))
	must(t, os.WriteFile(filepath.Join(b, "artifacts", "fw.bin"), []byte("firmware"), 0o644))
	must(t, os.WriteFile(filepath.Join(b, "artifacts", "image.bin"), []byte("image with firmware"), 0o644))
	fw := ok(imageRD(filepath.Join(b, "artifacts", "fw.bin")))
	goDep := Obj{"name": "go", "uri": "pkg:golang/go@1.25.14", "digest": Obj{"sha256": strings.Repeat("a", 64)},
		"annotations": Obj{"version": "1.25.14", "toolchain": Obj{"treeDigest": Obj{"sha256": strings.Repeat("b", 64)}}}}
	sb := &Sandbox{Version: "bubblewrap 0.9.0"}
	signer := ok(LoadSigner(filepath.Join(keys, "firmware-platform.key.pem")))
	ok(Sign(ok(statement([]Obj{fw}, SLSAProvenance, Obj{
		"buildDefinition": Obj{
			"buildType":            GoBuildType,
			"externalParameters":   Obj{},
			"internalParameters":   isolationParams(sb, Obj{"CGO_ENABLED": "0"}),
			"resolvedDependencies": []Obj{rd("main.go", strings.Repeat("c", 64)), goDep},
		},
		"runDetails": Obj{"builder": Obj{"id": "https://example.com/builder"}},
	})), signer, filepath.Join(b, "att", "fw.intoto.json")))
	ok(Sign(ok(statement([]Obj{ok(fileRD(filepath.Join(b, "artifacts", "image.bin"), ""))}, SLSAProvenance, Obj{
		"buildDefinition": Obj{
			"buildType":            FlashBuildType,
			"externalParameters":   Obj{},
			"resolvedDependencies": []Obj{envRD(b, "fw.intoto.json"), fw},
		},
		"runDetails": Obj{"builder": Obj{"id": "https://example.com/builder"}},
	})), signer, filepath.Join(b, "att", "image.intoto.json")))
	must(t, SimulateReview(b, "att/fw.intoto.json", "fw.bin", "Example", "EX-1", "1.0", filepath.Join(keys, "review-provider.key.pem"), SFRFormatJWS))
	must(t, TLogInit(filepath.Join(work, "log"), fwl3Origin))
	for _, r := range []string{"fw", "image"} {
		must(t, TLogAdd(filepath.Join(work, "log"), filepath.Join(keys, TLogRole+".key.pem"), filepath.Join(b, "att", r+".intoto.json")))
	}
	policy = Obj{
		"claims": Obj{"firmware": []any{"HSLSA_FIRMWARE_LEVEL_3"}},
		"firmware": Obj{
			"toolPins":        []any{Obj{"name": "go", "sha256": strings.Repeat("a", 64), "toolchain": Obj{"treeDigest": strings.Repeat("b", 64)}}},
			"review":          Obj{"images": []any{"fw.bin"}, "providers": []any{"review-provider"}, "minScope": 1, "maxOpenIssueCVSS": 3.9},
			"transparencyLog": Obj{"origin": fwl3Origin},
		},
	}
	return work, trust, policy
}

func fwl3Releases(work string) []fwRelease {
	b := filepath.Join(work, "bundle")
	return []fwRelease{
		{Image: "fw.bin", Bundle: b, Record: "att/fw.intoto.json", Role: "firmware-platform", Review: true},
		{Image: "image.bin", Bundle: b, Record: "att/image.intoto.json", Role: "firmware-platform"},
	}
}

func fwl3Check(t *testing.T, work string, trust *TrustRoot, policy Obj) error {
	t.Helper()
	_, err := firmwareL3(trust, policy, fwl3Releases(work), "Firmware L3")
	return err
}

// fwl3Forge re-signs fw.intoto.json after mutate and logs it again, as a
// build platform that controls its key and the log submission could.
func fwl3Forge(t *testing.T, work string, mutate func(Obj)) {
	t.Helper()
	path := filepath.Join(work, "bundle", "att", "fw.intoto.json")
	resign(t, path, filepath.Join(work, "keys"), "firmware-platform", mutate)
	must(t, TLogAdd(filepath.Join(work, "log"), filepath.Join(work, "keys", TLogRole+".key.pem"), path))
}

func TestFirmwareL3Passes(t *testing.T) {
	work, trust, policy := fwl3Work(t)
	inputs := ok(firmwareL3(trust, policy, fwl3Releases(work), "Firmware L3"))
	var names []string
	for _, in := range inputs {
		names = append(names, S(in, "name"))
	}
	for _, want := range []string{"att/fw.tlog.json", "att/image.tlog.json", "review/fw.bin.sfr.jws"} {
		if !contains(names, want) {
			t.Fatalf("inputs %v leave out %s", names, want)
		}
	}
}

func TestFirmwareL3Rejects(t *testing.T) {
	build := func(s Obj) Obj { return O(s, "predicate", "buildDefinition") }
	cases := map[string]struct {
		edit   func(t *testing.T, work string, policy Obj)
		reason string
	}{
		"not-isolated": {func(t *testing.T, w string, _ Obj) {
			fwl3Forge(t, w, func(s Obj) { delete(O(build(s), "internalParameters"), "isolation") })
		}, "SLSA Build L3: no internalParameters.isolation"},
		"network-open": {func(t *testing.T, w string, _ Obj) {
			fwl3Forge(t, w, func(s Obj) { O(build(s), "internalParameters", "isolation")["network"] = "host" })
		}, `the sandbox allowed network access "host"`},
		"key-in-reach": {func(t *testing.T, w string, _ Obj) {
			fwl3Forge(t, w, func(s Obj) { O(build(s), "internalParameters", "isolation")["signingKeyMounted"] = true })
		}, "the signing key was within reach of the step"},
		"input-unpinned": {func(t *testing.T, w string, _ Obj) {
			fwl3Forge(t, w, func(s Obj) { Objs(build(s), "resolvedDependencies")[0]["digest"] = Obj{} })
		}, "input main.go is not pinned by digest"},
		"tool-unpinned": {func(t *testing.T, w string, _ Obj) {
			fwl3Forge(t, w, func(s Obj) {
				O(Objs(build(s), "resolvedDependencies")[1], "digest")["sha256"] = strings.Repeat("d", 64)
			})
		}, "tool go sha256:dddddddddddddddd is not on the policy's pinned tool list"},
		"toolchain-tree-changed": {func(t *testing.T, w string, _ Obj) {
			fwl3Forge(t, w, func(s Obj) {
				O(Objs(build(s), "resolvedDependencies")[1], "annotations", "toolchain", "treeDigest")["sha256"] = strings.Repeat("e", 64)
			})
		}, "go is the pinned binary, but its toolchain (files sha256:eeeeeeeeeeeeeeee) is not the pinned one"},
		"no-tool-named": {func(t *testing.T, w string, _ Obj) {
			fwl3Forge(t, w, func(s Obj) { build(s)["resolvedDependencies"] = []any{Objs(build(s), "resolvedDependencies")[0]} })
		}, "the record names no tool"},
		"not-logged": {func(t *testing.T, w string, _ Obj) {
			must(t, os.Remove(filepath.Join(w, "bundle", "att", "image.tlog.json")))
		}, "image.intoto.json is not in a transparency log"},
		"changed-after-logging": {func(t *testing.T, w string, _ Obj) {
			resign(t, filepath.Join(w, "bundle", "att", "fw.intoto.json"), filepath.Join(w, "keys"), "firmware-platform", nil)
		}, "the log entry is not this record"},
		"logged-elsewhere": {func(t *testing.T, w string, p Obj) {
			O(p, "firmware", "transparencyLog")["origin"] = "another log"
		}, `logged in "example buyer firmware log", not the log the policy names`},
		"no-log-in-policy": {func(t *testing.T, w string, p Obj) {
			delete(O(p, "firmware"), "transparencyLog")
		}, "the policy names no transparency log"},
		"review-not-required": {func(t *testing.T, w string, p Obj) {
			O(p, "firmware", "review")["images"] = []any{}
		}, "does not require a S.A.F.E. review of fw.bin"},
		"no-review": {func(t *testing.T, w string, _ Obj) {
			must(t, os.RemoveAll(filepath.Join(w, "bundle", ReviewDir)))
		}, "no accepted S.A.F.E. report for fw.bin"},
		"review-of-another-image": {func(t *testing.T, w string, _ Obj) {
			// The image changes after review: the record names new bytes, the report the old ones.
			b := filepath.Join(w, "bundle")
			must(t, os.WriteFile(filepath.Join(b, "artifacts", "fw.bin"), []byte("other firmware"), 0o644))
			fw := ok(imageRD(filepath.Join(b, "artifacts", "fw.bin")))
			fwl3Forge(t, w, func(s Obj) { s["subject"] = []any{fw} })
		}, "no accepted S.A.F.E. report for fw.bin"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			work, trust, policy := fwl3Work(t)
			c.edit(t, work, policy)
			rejects(t, fwl3Check(t, work, trust, policy), c.reason)
		})
	}
}

// Rule 2: a provisioning record from a site not rated L3 in its own track.
func TestProvisioningSiteL3(t *testing.T) {
	work := t.TempDir()
	keys, pub := filepath.Join(work, "keys"), filepath.Join(work, "pub")
	must(t, makeKeys(keys, pub, "test-site", "ems-site", "buyer-root"))
	signer := ok(LoadSigner(filepath.Join(keys, "test-site.key.pem")))
	rec := func(stage string) string {
		path := filepath.Join(work, "prov-"+stage+".intoto.json")
		ok(Sign(ok(statement([]Obj{rd("urn:hslsa:unit:u1", strings.Repeat("f", 64))}, FWProvisioning, Obj{
			"buildDefinition": Obj{"buildType": ProvisionType, "externalParameters": Obj{"stage": stage}},
			"hwProvision":     Obj{"site": Obj{"name": "Example Test House"}},
		})), signer, path))
		return path
	}
	enroll := func(custody, scheme string) *TrustRoot {
		dir := filepath.Join(work, "enroll-"+custody+scheme)
		must(t, os.MkdirAll(dir, 0o755))
		e := Enrollment{Role: "test-site", OrgName: "Example Test Services", OrgID: "duns:100000014", Site: "Example Test House", Custody: custody,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		if scheme != "" {
			e.Accreditation = Accreditation{Scheme: scheme, ID: "X-1"}
		}
		must(t, Enroll(filepath.Join(keys, "buyer-root.key.pem"), filepath.Join(keys, "test-site.pub.pem"), e, filepath.Join(dir, "test-site.intoto.json")))
		out := filepath.Join(work, "tr-"+custody+scheme+".json")
		ok(BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), out))
		return ok(LoadTrustRoot(out))
	}
	l3 := Obj{"accreditations": []any{"iso-iec-20243"}, "claims": Obj{"lot": []any{"HSLSA_PACKAGE_TEST_LEVEL_3"}}}
	l2 := Obj{"accreditations": []any{"iso-iec-20243"}, "claims": Obj{"lot": []any{"HSLSA_PACKAGE_TEST_LEVEL_2"}}}
	good := enroll("hsm", "iso-iec-20243")
	must(t, provisioningSiteL3(good, l3, rec("final-test"), "test-site", "unit u1"))
	rejects(t, provisioningSiteL3(good, l2, rec("final-test"), "test-site", "unit u1"), "rated Package/Test L2 under its policy")
	rejects(t, provisioningSiteL3(good, l3, rec("bench"), "test-site", "unit u1"), `provisioning at stage "bench", which no track rates`)
	rejects(t, provisioningSiteL3(enroll("file", "iso-iec-20243"), l3, rec("final-test"), "test-site", "unit u1"), "L3 needs a key held in an HSM")
	rejects(t, provisioningSiteL3(enroll("hsm", ""), l3, rec("final-test"), "test-site", "unit u1"), "enrolled with no accreditation")
}
