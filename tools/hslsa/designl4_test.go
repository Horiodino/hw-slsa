package hslsa

// Tests for Design L4: the second builder's rebuild record, two-person source
// review and the tapeout key in an HSM. The fixture is the Design L3 bundle
// from e2e/run.sh produce with a second reviewer's approval, the source
// freeze and release signed again over both reviews, a buyer-run trust root
// that enrolls a rebuilder of another company and the tapeout key as held in
// an HSM, and a rebuild record made by re-running synthesis.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const secondReviewer = "Example Second Reviewer <second-reviewer@example.com>"

func e2eCache() string { return envPath("HSLSA_CACHE", "out/cache") }

// designL4Enroll enrolls every key of the design bundle's parties in dir: the
// design house's roles under its own company, the second reviewer's key as a
// source reviewer, the rebuilder under rebuilderOrg, and the tapeout key
// with the custody given.
func designL4Enroll(keys, dir, rebuilderOrg, tapeoutCustody string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	enroll := func(file, role, org, id, custody string) error {
		e := Enrollment{Role: role, OrgName: org, OrgID: id, Site: org + " site", Custody: custody,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
		return Enroll(filepath.Join(keys, "buyer-root.key.pem"), filepath.Join(keys, file+".pub.pem"), e, filepath.Join(dir, file+".intoto.json"))
	}
	for _, role := range e2eRoles {
		custody := "file"
		if role == "tapeout-authority" {
			custody = tapeoutCustody
		}
		if err := enroll(role, role, "Example Open Silicon Group", "duns:100000002", custody); err != nil {
			return err
		}
	}
	for _, reviewer := range []string{"second-reviewer", "third-reviewer"} {
		if err := enroll(reviewer, "source-reviewer", "Example Open Silicon Group", "duns:100000002", "file"); err != nil {
			return err
		}
	}
	id := "duns:100000031"
	if rebuilderOrg == "Example Open Silicon Group" {
		id = "duns:100000002"
	}
	return enroll(RebuilderRole, RebuilderRole, rebuilderOrg, id, "file")
}

func designL4TrustRoot(t *testing.T, bundle, name, rebuilderOrg, tapeoutCustody string) string {
	t.Helper()
	keys := chipKeys(bundle)
	dir := filepath.Join(filepath.Dir(bundle), name)
	must(t, designL4Enroll(keys, dir, rebuilderOrg, tapeoutCustody))
	out := filepath.Join(filepath.Dir(bundle), name+".json")
	ok(BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), out))
	return out
}

// designL4Policy is the example's Design L3 policy, claiming Design L4 with
// two reviewers.
func designL4Policy(t *testing.T) Obj {
	p := designL3Policy(t)
	O(p, "claims")["design"] = anyStrings([]string{"HSLSA_DESIGN_LEVEL_4", "SLSA_BUILD_LEVEL_3"})
	O(p, "design", "source")["minReviewers"] = 2
	return p
}

func writePolicy(t *testing.T, dir string, p Obj) string {
	t.Helper()
	path := filepath.Join(dir, "policy-"+strings.ReplaceAll(t.Name(), "/", "-")+".json")
	must(t, WriteJSON(path, p))
	return path
}

// rebuildAs runs the second builder under builder id id.
func rebuildAs(bundle, id string) error {
	prev, had := os.LookupEnv("HSLSA_BUILDER_ID")
	os.Setenv("HSLSA_BUILDER_ID", id)
	defer func() {
		if had {
			os.Setenv("HSLSA_BUILDER_ID", prev)
		} else {
			os.Unsetenv("HSLSA_BUILDER_ID")
		}
	}()
	keys := chipKeys(bundle)
	return DesignRebuild(bundle, e2eLock, filepath.Join(keys, RebuilderRole+".key.pem"), e2eCache(), filepath.Join(bundle, "att", DesignRebuildAtt), false)
}

const rebuilderID = "https://rebuild.example.org/builders/picorv32@v1"

func designL4Bundle(t *testing.T) string {
	t.Helper()
	requireYosys(t)
	base := designL3Bundle(t)
	requireDir(t, e2eCache(), "run e2e/run.sh produce first: the rebuild needs its source cache")
	valid := shared(t, "design-l4", func(work string) error {
		if err := copyTree(filepath.Dir(base), work); err != nil {
			return err
		}
		bundle, keys := filepath.Join(work, "bundle"), filepath.Join(work, "keys")
		for _, role := range []string{"buyer-root", "second-reviewer", "third-reviewer", RebuilderRole} {
			if _, err := Keygen(keys, role); err != nil {
				return err
			}
		}
		dir := filepath.Join(work, "enrollments")
		if err := designL4Enroll(keys, dir, "Example Rebuild Lab", "hsm"); err != nil {
			return err
		}
		tr := filepath.Join(bundle, "trust-root.json")
		if _, err := BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), tr); err != nil {
			return err
		}
		pol := filepath.Join(work, "policy-l4.json")
		p, err := ReadObj(e2ePolicy)
		if err != nil {
			return err
		}
		O(p, "claims")["design"] = anyStrings([]string{"HSLSA_DESIGN_LEVEL_4", "SLSA_BUILD_LEVEL_3"})
		O(p, "design", "source")["minReviewers"] = 2
		if err := WriteJSON(pol, p); err != nil {
			return err
		}
		if err := SourceReview(bundle, e2eLock, filepath.Join(keys, "second-reviewer.key.pem"), secondReviewer); err != nil {
			return err
		}
		if err := SourceFreezeL2(bundle, e2eLock, filepath.Join(keys, "flow-platform.key.pem"), e2eCache(), tr, pol); err != nil {
			return err
		}
		if err := DesignRelease(bundle, e2eLock, filepath.Join(keys, "tapeout-authority.key.pem"), tr, pol); err != nil {
			return err
		}
		return rebuildAs(bundle, rebuilderID)
	})
	return filepath.Join(copyOf(t, valid), "bundle")
}

func designL4Check(t *testing.T, bundle, trustPath string, policy Obj) error {
	t.Helper()
	trust := ok(LoadTrustRoot(trustPath))
	_, err := TapeoutCheck(bundle, trust, policy, true)
	return err
}

func TestDesignL4Passes(t *testing.T) {
	bundle := designL4Bundle(t)
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	design, err := TapeoutCheck(bundle, trust, designL4Policy(t), true)
	must(t, err)
	found := false
	for _, in := range design.Inputs {
		found = found || S(in, "name") == "att/"+DesignRebuildAtt
	}
	if !found {
		t.Fatal("the design VSA's inputs leave out the rebuild record")
	}
	rb := ok(DecodeEnvelope(filepath.Join(bundle, "att", DesignRebuildAtt)))
	if S(rb, "predicate", "runDetails", "builder", "id") != rebuilderID {
		t.Fatalf("the rebuild ran as %s", S(rb, "predicate", "runDetails", "builder", "id"))
	}
}

// forgeRebuild re-signs the rebuild record after mutate with the rebuilder's key.
func forgeRebuild(t *testing.T, bundle string, mutate func(Obj)) {
	t.Helper()
	resign(t, filepath.Join(bundle, "att", DesignRebuildAtt), chipKeys(bundle), RebuilderRole, mutate)
}

func rebuildDeps(s Obj) []Obj { return Objs(s, "predicate", "buildDefinition", "resolvedDependencies") }

func TestDesignL4Rejects(t *testing.T) {
	flowBuilder := func(bundle string) string {
		return S(ok(DecodeEnvelope(filepath.Join(bundle, "att", AttName("synthesis")))), "predicate", "runDetails", "builder", "id")
	}
	cases := map[string]struct {
		edit   func(t *testing.T, bundle string, policy Obj) string // returns the trust root to check under
		reason string
	}{
		"no-rebuild": {func(t *testing.T, b string, _ Obj) string {
			must(t, os.Remove(filepath.Join(b, "att", DesignRebuildAtt)))
			return ""
		}, "no rebuild record (design-rebuild.intoto.json) from a second builder"},
		"rebuild-by-an-unlisted-key": {func(t *testing.T, b string, _ Obj) string {
			resign(t, filepath.Join(b, "att", DesignRebuildAtt), chipKeys(b), "attacker", nil)
			return ""
		}, "no valid signature from role 'rebuilder'"},
		"rebuilder-of-the-design-house": {func(t *testing.T, b string, _ Obj) string {
			return designL4TrustRoot(t, b, "same-org", "Example Open Silicon Group", "hsm")
		}, "the organization that holds the flow-platform key; L4 needs an independent party"},
		"rebuilt-on-the-flow-builder": {func(t *testing.T, b string, _ Obj) string {
			id := flowBuilder(b)
			forgeRebuild(t, b, func(s Obj) { O(s, "predicate", "runDetails", "builder")["id"] = id })
			return ""
		}, "which also ran the flow; it needs a second builder"},
		"another-artifact": {func(t *testing.T, b string, _ Obj) string {
			forgeRebuild(t, b, func(s Obj) { O(firstSubject(s), "digest")["sha256"] = strings.Repeat("ab", 32) })
			return ""
		}, "the rebuild record is for another artifact than the released"},
		"another-release": {func(t *testing.T, b string, _ Obj) string {
			forgeRebuild(t, b, func(s Obj) { O(rebuildDeps(s)[0], "digest")["sha256"] = strings.Repeat("cd", 32) })
			return ""
		}, "the rebuild record does not name this release"},
		"another-source": {func(t *testing.T, b string, _ Obj) string {
			forgeRebuild(t, b, func(s Obj) { O(rebuildDeps(s)[1], "digest")["sha256"] = strings.Repeat("ef", 32) })
			return ""
		}, "the rebuild did not build from the frozen source"},
		"another-yosys": {func(t *testing.T, b string, _ Obj) string {
			forgeRebuild(t, b, func(s Obj) { O(rebuildDeps(s)[2], "digest")["sha256"] = strings.Repeat("12", 32) })
			return ""
		}, "the rebuild ran yosys sha256:1212121212121212, not the flow's"},
		"rebuild-differs": {func(t *testing.T, b string, _ Obj) string {
			forgeRebuild(t, b, func(s Obj) {
				for _, c := range Objs(s, "predicate", "hwFlow", "checks") {
					c["result"] = "fail"
				}
			})
			return ""
		}, "the rebuild did not reproduce the release: gds-bit-exact failed"},
		"policy-asks-one-reviewer": {func(t *testing.T, b string, p Obj) string {
			O(p, "design", "source")["minReviewers"] = 1
			return ""
		}, "the policy does not require two-person source review"},
		"one-review": {func(t *testing.T, b string, _ Obj) string {
			must(t, os.Remove(filepath.Join(b, "att", reviewAttOf(secondReviewer))))
			return ""
		}, "1 reviewer(s) approved commit"},
		"second-review-with-the-first-key": {func(t *testing.T, b string, _ Obj) string {
			resign(t, filepath.Join(b, "att", reviewAttOf(secondReviewer)), chipKeys(b), "source-reviewer", nil)
			return ""
		}, "is signed with the same source-reviewer key as source-review.intoto.json"},
		"one-person-twice": {func(t *testing.T, b string, _ Obj) string {
			first := S(ok(DecodeEnvelope(filepath.Join(b, "att", reviewAtt))), "predicate", "reviewer")
			resign(t, filepath.Join(b, "att", reviewAttOf(secondReviewer)), chipKeys(b), "second-reviewer", func(s Obj) {
				O(s, "predicate")["reviewer"] = first
			})
			return ""
		}, "who also signed source-review.intoto.json"},
		"tapeout-key-in-a-file": {func(t *testing.T, b string, _ Obj) string {
			return designL4TrustRoot(t, b, "file-tapeout", "Example Rebuild Lab", "file")
		}, `tapeout-authority key`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := designL4Bundle(t)
			policy := designL4Policy(t)
			trust := c.edit(t, bundle, policy)
			if trust == "" {
				trust = filepath.Join(bundle, "trust-root.json")
			}
			rejects(t, designL4Check(t, bundle, trust, policy), c.reason)
		})
	}
}

// Every review in the bundle must be one the source freeze consumed: a
// review added after the freeze breaks the chain.
func TestDesignL4ReviewAddedAfterTheFreeze(t *testing.T) {
	bundle := designL4Bundle(t)
	keys := chipKeys(bundle)
	third := "Example Third Reviewer <third-reviewer@example.com>"
	must(t, SourceReview(bundle, e2eLock, filepath.Join(keys, "third-reviewer.key.pem"), third))
	rejects(t, designL4Check(t, bundle, filepath.Join(bundle, "trust-root.json"), designL4Policy(t)),
		"resolvedDependencies do not include source review att/"+reviewAttOf(third))
}

// A compromised flow platform changes the netlist after the equivalence
// proof and signs a release over it; the second builder, building from the
// frozen source, does not get the same netlist, says so, and the check
// refuses the release.
func TestDesignRebuildCatchesAlteredNetlist(t *testing.T) {
	bundle := designL4Bundle(t)
	keys := chipKeys(bundle)
	appendFile(t, filepath.Join(bundle, "artifacts", "picorv32.netlist.v"), "// inserted after signoff\n")
	resign(t, filepath.Join(bundle, "att", AttName("synthesis")), keys, "flow-platform", func(s Obj) { refresh(bundle, s) })
	must(t, DesignRelease(bundle, e2eLock, filepath.Join(keys, "tapeout-authority.key.pem"), filepath.Join(bundle, "trust-root.json"), e2ePolicy))
	must(t, rebuildAs(bundle, rebuilderID))
	rb := ok(DecodeEnvelope(filepath.Join(bundle, "att", DesignRebuildAtt)))
	for _, c := range Objs(rb, "predicate", "hwFlow", "checks") {
		if S(c, "result") != "fail" {
			t.Fatalf("the rebuild record says %s passed for an altered netlist", S(c, "name"))
		}
	}
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	rel := ok(DecodeEnvelope(filepath.Join(bundle, "att", AttName("release"))))
	_, err := checkDesignRebuild(bundle, trust, designL4Policy(t), firstSubject(rel), "Design L4")
	rejects(t, err, "the rebuild did not reproduce the release: gds-bit-exact failed")
}
