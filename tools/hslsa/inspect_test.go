package hslsa

// Tests for Wafer L4 and Package/Test L4: the lab's commitment to its seed,
// consumed by final test, and its inspection of the sample the seed draws.
// The fixture is the L3 lot made again with an inspection lab enrolled under
// its own company: the lab commits, the sites sign the lot (final test
// consuming the commitment), the lab inspects and destroys its sample, and
// the buyer receives three of the parts left.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	l4Dir    = filepath.Join(e2eDir, "l4")
	l4Plan   = filepath.Join(l4Dir, "inspection-plan.json")
	l4Policy = filepath.Join(l4Dir, "policy.json")
)

var labOrg = [2]string{"Example Failure Analysis Lab", "duns:100000041"}

// labAccreditation is the testing-lab accreditation the example labs hold
// and the example L4 policies accept (inspection.accreditations).
var labAccreditation = Accreditation{Scheme: "iso-iec-17025", ID: "A2LA-4410.01"}

// l4TrustRoot is the L3 trust root plus the inspection lab, enrolled under
// org with the example lab accreditation.
func l4TrustRoot(keys, bundle, name string, org [2]string) (string, error) {
	return l4TrustRootAccredited(keys, bundle, name, org, labAccreditation)
}

// l4TrustRootAccredited is l4TrustRoot with the lab enrolled under acc (none when empty).
func l4TrustRootAccredited(keys, bundle, name string, org [2]string, acc Accreditation) (string, error) {
	dir := filepath.Join(filepath.Dir(bundle), name)
	if err := enrollL3(keys, dir, nil, l3Org); err != nil {
		return "", err
	}
	e := Enrollment{Role: InspectionLabRole, OrgName: org[0], OrgID: org[1], Site: org[0], Custody: "file",
		Accreditation: acc, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	if err := Enroll(filepath.Join(keys, "buyer-root.key.pem"), filepath.Join(keys, InspectionLabRole+".pub.pem"), e, filepath.Join(dir, InspectionLabRole+".intoto.json")); err != nil {
		return "", err
	}
	out := filepath.Join(filepath.Dir(bundle), name+".json")
	_, err := BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), out)
	return out, err
}

// chipL4Policy is the example's L4 policy with the design at L3, so these
// tests need only the lot.
func chipL4Policy(t *testing.T) Obj {
	p := ok(ReadObj(l4Policy))
	O(p, "claims")["design"] = anyStrings([]string{"HSLSA_DESIGN_LEVEL_3", "SLSA_BUILD_LEVEL_3"})
	O(p, "claims")["lot"] = anyStrings([]string{"HSLSA_WAFER_LEVEL_4", "HSLSA_PACKAGE_TEST_LEVEL_4", "HSLSA_DESIGN_LEVEL_3"})
	O(p, "design", "source")["minReviewers"] = 1
	return p
}

func labWork(bundle string) string { return filepath.Join(filepath.Dir(bundle), "lab") }

// chipL4Bundle is a fresh copy of the inspected lot. Beside it: parts (what
// is left after the lab destroyed its sample), parts-before (every shipped
// part, as they were before the inspection), received (three parts the
// buyer got) and lab (the seed and the commitment).
func chipL4Bundle(t *testing.T) string {
	t.Helper()
	base := chipL3Bundle(t)
	valid := shared(t, "chip-l4", func(work string) error {
		if err := copyTree(filepath.Dir(base), work); err != nil {
			return err
		}
		bundle, keys := filepath.Join(work, "bundle"), filepath.Join(work, "keys")
		if _, err := Keygen(keys, InspectionLabRole); err != nil {
			return err
		}
		tr, err := l4TrustRoot(keys, bundle, "enrollments-l4", labOrg)
		if err != nil {
			return err
		}
		if err := copyFile(tr, filepath.Join(bundle, "trust-root.json")); err != nil {
			return err
		}
		lab := filepath.Join(work, "lab")
		labKey := filepath.Join(keys, InspectionLabRole+".key.pem")
		if err := InspectionCommit(l4Plan, "ASM-EXAMPLE-17", labKey, filepath.Join(lab, "seed.hex"), filepath.Join(lab, "commitment.intoto.json")); err != nil {
			return err
		}
		parts := filepath.Join(work, "parts")
		for _, d := range []string{parts, filepath.Join(work, "received")} {
			if err := os.RemoveAll(d); err != nil {
				return err
			}
		}
		if err := MfgInspected(bundle, l3Scenario, keys, nil, nil, parts, filepath.Join(lab, "commitment.intoto.json")); err != nil {
			return err
		}
		if err := BuildHBOM(bundle, e2eLock, l3Scenario, filepath.Join(keys, "product-owner.key.pem"), nil); err != nil {
			return err
		}
		if err := copyTree(parts, filepath.Join(work, "parts-before")); err != nil {
			return err
		}
		if err := InspectLot(bundle, parts, l4Plan, filepath.Join(lab, "seed.hex"), labKey); err != nil {
			return err
		}
		left, err := os.ReadDir(parts)
		if err != nil {
			return err
		}
		var names []string
		for _, e := range left {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, serial := range names[:3] {
			if err := copyTree(filepath.Join(parts, serial), filepath.Join(work, "received", serial)); err != nil {
				return err
			}
		}
		return nil
	})
	return filepath.Join(copyOf(t, valid), "bundle")
}

func l4Check(t *testing.T, bundle string, policy Obj, parts string) error {
	t.Helper()
	return l3Check(t, bundle, filepath.Join(bundle, "trust-root.json"), policy, parts)
}

func inspection(bundle string) Obj {
	return O(ok(DecodeEnvelope(filepath.Join(bundle, "att", InspectionAtt))), "predicate", "hwInspection")
}

// forgeInspection re-signs the inspection record after mutate with the lab's key.
func forgeInspection(t *testing.T, bundle string, mutate func(hw Obj)) {
	t.Helper()
	resign(t, filepath.Join(bundle, "att", InspectionAtt), chipKeys(bundle), InspectionLabRole, func(s Obj) {
		mutate(O(s, "predicate", "hwInspection"))
	})
}

// lotInputs runs the tapeout and lot receipt checks on the received parts
// and returns the names of the records the lot VSA lists as its inputs.
func lotInputs(t *testing.T, bundle, trustPath string, policy Obj) []string {
	t.Helper()
	trust := ok(LoadTrustRoot(trustPath))
	design := ok(TapeoutCheck(bundle, trust, policy, true))
	units := ok(ChallengeParts(trust, received(bundle)))
	res := ok(lotCheck(bundle, trust, policy, design, units, true))
	var names []string
	for _, in := range res.Inputs {
		names = append(names, S(in, "name"))
	}
	return names
}

func TestChipL4Passes(t *testing.T) {
	bundle := chipL4Bundle(t)
	names := lotInputs(t, bundle, filepath.Join(bundle, "trust-root.json"), chipL4Policy(t))
	for _, want := range []string{"att/" + InspectionCommitmentAtt, "att/" + InspectionAtt} {
		if !contains(names, want) {
			t.Fatalf("the lot VSA's inputs %v leave out %s", names, want)
		}
	}
	hw := inspection(bundle)
	if len(Objs(hw, "samples")) != 5 {
		t.Fatalf("the lab inspected %d units, want 5", len(Objs(hw, "samples")))
	}
	// The destroyed sample is gone from the parts the producer still holds.
	for _, s := range Objs(hw, "samples") {
		if fileExists(filepath.Join(filepath.Dir(bundle), "parts", S(s, "serial"))) {
			t.Fatalf("sampled part %s was not destroyed", S(s, "serial"))
		}
	}
}

// TestChipL4Accepts: lots that meet Wafer L4 and Package/Test L4 in other
// ways than the fixture's still pass, so the checks ask for what the spec
// asks and no more. Under an L4 policy the lot VSA must list the inspection.
func TestChipL4Accepts(t *testing.T) {
	cases := map[string]struct {
		edit func(t *testing.T, bundle string, policy Obj) (trust string)
		l4   bool
	}{
		"a-policy-asking-fewer-samples-than-the-lab-took": {func(t *testing.T, b string, p Obj) string {
			O(p, "inspection")["minSample"] = 2
			return ""
		}, true},
		"a-policy-naming-no-layers-or-regions": {func(t *testing.T, b string, p Obj) string {
			delete(O(p, "inspection"), "layers")
			delete(O(p, "inspection"), "regions")
			return ""
		}, true},
		"another-independent-lab": {func(t *testing.T, b string, _ Obj) string {
			return ok(l4TrustRoot(chipKeys(b), b, "enrollments-second-lab", [2]string{"Example Second Lab", "duns:100000042"}))
		}, true},
		"a-lab-under-another-accepted-accreditation": {func(t *testing.T, b string, p Obj) string {
			O(p, "inspection")["accreditations"] = []any{"iso-iec-17025", "dmea-trusted-supplier"}
			return ok(l4TrustRootAccredited(chipKeys(b), b, "enrollments-dmea-lab", labOrg, Accreditation{Scheme: "dmea-trusted-supplier", ID: "DMEA-FA-0007"}))
		}, true},
		"a-buyer-at-wafer-l3-and-package-test-l3": {func(t *testing.T, b string, p Obj) string {
			l3 := ok(ReadObj(l3Policy))
			for k := range p {
				delete(p, k)
			}
			for k, v := range l3 {
				p[k] = v
			}
			return ""
		}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := chipL4Bundle(t)
			policy := chipL4Policy(t)
			trust := c.edit(t, bundle, policy)
			if trust == "" {
				trust = filepath.Join(bundle, "trust-root.json")
			}
			names := lotInputs(t, bundle, trust, policy)
			if c.l4 && !contains(names, "att/"+InspectionAtt) {
				t.Fatalf("the lot passed, but its VSA's inputs %v leave out the inspection", names)
			}
		})
	}
}

func TestSeededSampleIsStableAndSteeredBySeedOnly(t *testing.T) {
	units := []string{"a", "b", "c", "d", "e", "f"}
	seed := []byte("0123456789abcdef0123456789abcdef")
	one := SeededSample(seed, units, 3)
	shuffled := []string{"f", "e", "d", "c", "b", "a"}
	if !equalStrings(one, SeededSample(seed, shuffled, 3)) {
		t.Fatal("the sample depends on the order the lot is listed in")
	}
	if equalStrings(one, SeededSample([]byte("another seed of thirty-two bytes"), units, 3)) &&
		equalStrings(one, SeededSample([]byte("yet another seed, thirty-two b.."), units, 3)) {
		t.Fatal("three seeds drew the same sample")
	}
	if len(SeededSample(seed, units, 10)) != 6 {
		t.Fatal("a lot smaller than the sample is not sampled whole")
	}
}

func TestChipL4Rejects(t *testing.T) {
	cases := map[string]struct {
		edit   func(t *testing.T, bundle string, policy Obj) (trust, parts string)
		reason string
	}{
		"no-inspection": {func(t *testing.T, b string, _ Obj) (string, string) {
			must(t, os.Remove(filepath.Join(b, "att", InspectionAtt)))
			return "", ""
		}, "no inspection record (inspection.intoto.json) from an independent lab"},
		"policy-without-a-minimum": {func(t *testing.T, b string, p Obj) (string, string) {
			delete(O(p, "inspection"), "minSample")
			return "", ""
		}, "the policy sets no minimum sample"},
		"policy-without-inspection": {func(t *testing.T, b string, p Obj) (string, string) {
			delete(p, "inspection")
			return "", ""
		}, "the policy sets no minimum sample"},
		"trust-root-without-the-lab": {func(t *testing.T, b string, _ Obj) (string, string) {
			return filepath.Join(filepath.Dir(b), "enrollments.json"), ""
		}, "no valid signature from role 'inspection-lab'"},
		"sample-below-the-minimum": {func(t *testing.T, b string, p Obj) (string, string) {
			O(p, "inspection")["minSample"] = 10
			return "", ""
		}, "a sample of 5, below the policy's minimum of 10"},
		"lab-of-the-test-house": {func(t *testing.T, b string, _ Obj) (string, string) {
			tr := ok(l4TrustRoot(chipKeys(b), b, "same-org", [2]string{"Example Test Services", "duns:100000014"}))
			return tr, ""
		}, "the organization that holds the test-site key; L4 needs an independent party"},
		"lab-not-accredited": {func(t *testing.T, b string, _ Obj) (string, string) {
			return ok(l4TrustRootAccredited(chipKeys(b), b, "unaccredited-lab", labOrg, Accreditation{})), ""
		}, "which is enrolled with no accreditation; L4 needs an accredited lab"},
		"lab-accredited-under-an-unlisted-scheme": {func(t *testing.T, b string, _ Obj) (string, string) {
			return ok(l4TrustRootAccredited(chipKeys(b), b, "other-scheme-lab", labOrg, Accreditation{Scheme: "lab-self-declared", ID: "SELF-1"})), ""
		}, "accredited under \"lab-self-declared\", which the policy's inspection.accreditations do not list"},
		"policy-accepting-no-lab-accreditation": {func(t *testing.T, b string, p Obj) (string, string) {
			delete(O(p, "inspection"), "accreditations")
			return "", ""
		}, "the policy accepts no lab accreditation (inspection.accreditations)"},
		"inspection-by-an-unlisted-key": {func(t *testing.T, b string, _ Obj) (string, string) {
			resign(t, filepath.Join(b, "att", InspectionAtt), chipKeys(b), "attacker", nil)
			return "", ""
		}, "no valid signature from role 'inspection-lab'"},
		"commitment-not-consumed": {func(t *testing.T, b string, _ Obj) (string, string) {
			forge(t, b, MfgAtt["final-test"], func(s Obj) {
				var keep []any
				for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
					if S(d, "name") != "att/"+InspectionCommitmentAtt {
						keep = append(keep, d)
					}
				}
				O(s, "predicate", "buildDefinition")["resolvedDependencies"] = keep
			})
			return "", ""
		}, "nothing shows the lab committed to its seed before the lot was sealed"},
		"seed-not-the-committed-one": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { hw["seed"] = strings.Repeat("ab", 32) })
			return "", ""
		}, "the seed the inspection reveals is not the one the lab committed to"},
		"steered-sample": {func(t *testing.T, b string, _ Obj) (string, string) {
			drawn := map[string]bool{}
			for _, s := range Objs(inspection(b), "samples") {
				drawn[S(s, "unit")] = true
			}
			var other string
			for _, u := range ok(ReadUnits(filepath.Join(b, "artifacts", "shipped-lot.txt"))) {
				if !drawn[u] {
					other = u
				}
			}
			forgeInspection(t, b, func(hw Obj) { Objs(hw, "samples")[0]["unit"] = other })
			return "", ""
		}, "the units inspected are not the sample the committed seed draws"},
		"a-sample-failed": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) {
				s := Objs(hw, "samples")[1]
				s["result"] = "fail"
				Objs(s, "checks")[0]["result"] = "fail"
			})
			return "", ""
		}, "failed inspection: layout-matches-release"},
		"another-design": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { O(hw, "designRef", "digest")["sha256"] = strings.Repeat("3", 64) })
			return "", ""
		}, "compared the samples with another design"},
		"another-lot": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { O(hw, "lot", "digest")["sha256"] = strings.Repeat("4", 64) })
			return "", ""
		}, "the inspection covers another lot"},
		"another-lot-size": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { O(hw, "lot")["size"] = 1000 })
			return "", ""
		}, "the inspection states a lot of 1000"},
		"plan-changed-after-the-commitment": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { O(hw, "plan")["sampleSize"] = 2 })
			return "", ""
		}, "the inspection does not follow the plan it committed to"},
		"no-wafer-track": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { hw["tracks"] = []any{"PACKAGE_TEST"} })
			return "", ""
		}, "the inspection does not cover the Wafer track"},
		"layer-not-imaged": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { hw["layers"] = []any{"met1", "met2"} })
			return "", ""
		}, "the lab did not image layer met3"},
		"no-technique": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) { hw["technique"] = "" })
			return "", ""
		}, "the inspection names no technique"},
		"genealogy-not-checked": {func(t *testing.T, b string, _ Obj) (string, string) {
			forgeInspection(t, b, func(hw Obj) {
				for _, s := range Objs(hw, "samples") {
					var keep []any
					for _, c := range Objs(s, "checks") {
						if S(c, "name") != "die-matches-genealogy" {
							keep = append(keep, c)
						}
					}
					s["checks"] = keep
				}
			})
			return "", ""
		}, "has no passing die-matches-genealogy check"},
		"a-destroyed-unit-is-received": {func(t *testing.T, b string, _ Obj) (string, string) {
			sampled := S(Objs(inspection(b), "samples")[0], "serial")
			dir := filepath.Join(filepath.Dir(b), "copy-of-a-destroyed-part")
			must(t, copyTree(filepath.Join(filepath.Dir(b), "parts-before", sampled), filepath.Join(dir, sampled)))
			return "", dir
		}, "is one the lab destroyed in its inspection; a part that answers as it is a copy"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := chipL4Bundle(t)
			policy := chipL4Policy(t)
			trust, parts := c.edit(t, bundle, policy)
			if trust == "" {
				trust = filepath.Join(bundle, "trust-root.json")
			}
			if parts == "" {
				parts = received(bundle)
			}
			rejects(t, l3Check(t, bundle, trust, policy, parts), c.reason)
		})
	}
}

// reinspect runs the lab again on the parts as they were before the first
// inspection, after tamper changed them, and signs a new record.
func reinspect(t *testing.T, bundle string, tamper func(parts string)) {
	t.Helper()
	parts := filepath.Join(t.TempDir(), "parts")
	must(t, copyTree(filepath.Join(filepath.Dir(bundle), "parts-before"), parts))
	tamper(parts)
	must(t, InspectLot(bundle, parts, l4Plan, filepath.Join(labWork(bundle), "seed.hex"), filepath.Join(chipKeys(bundle), InspectionLabRole+".key.pem")))
}

// A mask substituted at the fab gives every die another layout; the lab's
// imaging finds it in the first sample, and the lot is refused.
func TestInspectionFindsSubstitutedMask(t *testing.T) {
	bundle := chipL4Bundle(t)
	reinspect(t, bundle, func(parts string) {
		entries := ok(os.ReadDir(parts))
		for _, e := range entries {
			editJSON(t, filepath.Join(parts, e.Name(), dieFile), func(d Obj) { d["measure"] = strings.Repeat("5", 64) })
		}
	})
	rejects(t, l4Check(t, bundle, chipL4Policy(t), received(bundle)), "failed inspection: layout-matches-release")
}

// A die swapped into another unit's package at the OSAT does not match the
// genealogy; X-ray and the die's identity show it.
func TestInspectionFindsSwappedDie(t *testing.T) {
	bundle := chipL4Bundle(t)
	hw := inspection(bundle)
	first := S(Objs(hw, "samples")[0], "serial")
	reinspect(t, bundle, func(parts string) {
		entries := ok(os.ReadDir(parts))
		for _, e := range entries {
			if e.Name() != first {
				must(t, copyFile(filepath.Join(parts, e.Name(), dieFile), filepath.Join(parts, first, dieFile)))
				return
			}
		}
	})
	rejects(t, l4Check(t, bundle, chipL4Policy(t), received(bundle)), "failed inspection: die-matches-genealogy")
}
