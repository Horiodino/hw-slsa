package hslsa

// Tests for claims above L2: the claim guards every VSA goes through, and the
// Design L3 rules of the tapeout check (isolated steps, pinned tools, the
// equivalence record). The Design L3 tamper tests need a bundle from
// `e2e/run.sh produce`, whose flow runs isolated and records the equivalence
// proof; the example's policy claims Design L3.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestClaimGuards(t *testing.T) {
	accepts := map[string][]string{
		"design-l3-with-slsa-l3": {"HSLSA_DESIGN_LEVEL_3", "SLSA_BUILD_LEVEL_3"},
		"lot-l2":                 {"HSLSA_WAFER_LEVEL_2", "HSLSA_PACKAGE_TEST_LEVEL_2", "HSLSA_DESIGN_LEVEL_3"},
		"simulated":              {"HSLSA_WAFER_LEVEL_1", SimulatedLevel},
		"slsa-below-design":      {"HSLSA_DESIGN_LEVEL_3", "SLSA_BUILD_LEVEL_2"},
	}
	for name, levels := range accepts {
		t.Run("accepts/"+name, func(t *testing.T) { must(t, checkClaimList(anyStrings(levels))) })
	}
	rejectCases := map[string]struct {
		levels []string
		reason string
	}{
		"unknown-track":     {[]string{"HSLSA_FAB_LEVEL_2"}, "not a level this framework defines"},
		"level-five":        {[]string{"HSLSA_DESIGN_LEVEL_5"}, "levels run from 0 to 4"},
		"padded-level":      {[]string{"HSLSA_DESIGN_LEVEL_02"}, "levels run from 0 to 4"},
		"slsa-level-four":   {[]string{"SLSA_BUILD_LEVEL_4"}, "SLSA build levels run from 0 to 3"},
		"slsa-above-design": {[]string{"HSLSA_DESIGN_LEVEL_2", "SLSA_BUILD_LEVEL_3"}, "claims SLSA Build L3 but no Design or Firmware level of at least L3"},
		"slsa-alone":        {[]string{"SLSA_BUILD_LEVEL_1"}, "claims SLSA Build L1 but no Design or Firmware level"},
	}
	for _, track := range LevelTracks {
		if n := levelUnchecked[track]; n <= 4 {
			rejectCases["unchecked-"+strings.ToLower(track)] = struct {
				levels []string
				reason string
			}{[]string{"HSLSA_" + track + "_LEVEL_" + strconv.Itoa(n)}, "the reference tool does not check " + TrackTitle[track]}
		}
	}
	for name, c := range rejectCases {
		t.Run("rejects/"+name, func(t *testing.T) { rejects(t, checkClaimList(anyStrings(c.levels)), c.reason) })
	}
}

func TestPolicyClaimsAreCheckedBeforeTheChain(t *testing.T) {
	policy := Obj{"claims": Obj{"design": anyStrings([]string{"HSLSA_DESIGN_LEVEL_2", "SLSA_BUILD_LEVEL_3"})}}
	_, err := TapeoutCheck(t.TempDir(), &TrustRoot{}, policy, true)
	rejects(t, err, "policy claims.design: claims SLSA Build L3")
}

func TestVSARefusesUncheckedLevel(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "policy.json"), []byte("{}"), 0o644))
	ok(Keygen(dir, "verifier"))
	sign := func(tracks []string, levels ...string) error {
		return signVSA(tracks, Obj{"name": "x", "digest": Obj{"sha256": strings.Repeat("0", 64)}}, "x",
			anyStrings(levels), nil, filepath.Join(dir, "policy.json"),
			filepath.Join(dir, "verifier.key.pem"), filepath.Join(dir, "vsa.json"))
	}
	for _, track := range LevelTracks {
		if n := levelUnchecked[track]; n <= 4 {
			level := "HSLSA_" + track + "_LEVEL_" + strconv.Itoa(n)
			rejects(t, sign(LevelTracks, level), "does not check "+TrackTitle[track]+" L"+strconv.Itoa(n))
		}
	}
	rejects(t, sign(designTracks, "HSLSA_DESIGN_LEVEL_5"), "levels run from 0 to 4")
	// A level in a track the check did not cover, such as Firmware on a lot.
	rejects(t, sign(lotTracks, "HSLSA_WAFER_LEVEL_2", "HSLSA_FIRMWARE_LEVEL_2"), "this check covers Wafer, Package/Test, Design, not the Firmware track")
	rejects(t, sign(boardTracks, "HSLSA_ASSEMBLY_LEVEL_2", "HSLSA_DESIGN_LEVEL_2"), "not the Design track")
	if _, err := os.Stat(filepath.Join(dir, "vsa.json")); err == nil {
		t.Fatal("a VSA was written for a level the tool does not check")
	}
	must(t, sign(fpgaTracks, "HSLSA_ASSEMBLY_LEVEL_3", "HSLSA_FIRMWARE_LEVEL_3", "SLSA_BUILD_LEVEL_3", SimulatedLevel))
}

// Design L3 tamper tests. Each forges a record with a valid flow-platform
// signature, as a compromised flow platform could, and the tapeout check
// must still refuse the Design L3 claim.

func designL3Bundle(t *testing.T) string {
	t.Helper()
	bundle := chipBundle(t)
	if _, err := os.Stat(filepath.Join(bundle, "att", AttName("signoff"))); err != nil {
		t.Skip("the bundle has no signoff record; run e2e/run.sh produce from this revision")
	}
	return bundle
}

func designCheck(t *testing.T, bundle string, policy Obj) error {
	t.Helper()
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, err := TapeoutCheck(bundle, trust, policy, true)
	return err
}

func designL3Policy(t *testing.T) Obj { return ok(ReadObj(e2ePolicy)) }

// resignStep re-signs one design step, then the release over the new step
// envelopes, so only the Design L3 rules can catch the change.
func resignStep(t *testing.T, bundle, step string, mutate func(Obj)) {
	t.Helper()
	chipResign(t, bundle, AttName(step), "flow-platform", mutate)
	keys := chipKeys(bundle)
	must(t, DesignRelease(bundle, e2eLock, filepath.Join(keys, "tapeout-authority.key.pem"), filepath.Join(bundle, "trust-root.json"), e2ePolicy))
}

func hwFlow(stmt Obj) Obj { return O(stmt, "predicate", "hwFlow") }

func TestDesignL3Passes(t *testing.T) {
	bundle := designL3Bundle(t)
	must(t, designCheck(t, bundle, designL3Policy(t)))
}

func TestDesignL3Rejects(t *testing.T) {
	cases := map[string]struct {
		step   string
		mutate func(Obj)
		reason string
	}{
		"step-not-isolated": {"synthesis", func(s Obj) { delete(hwFlow(s), "isolation") },
			"design synthesis: no hwFlow.isolation"},
		"key-in-reach": {"simulation", func(s Obj) { O(hwFlow(s), "isolation")["signingKeyMounted"] = true },
			"design simulation: the signing key was within reach of the step"},
		"shared-workdir": {"signoff", func(s Obj) { O(hwFlow(s), "isolation")["stepsShareNoFiles"] = false },
			"design signoff: the step did not run in a fresh working directory"},
		"network-open": {"synthesis", func(s Obj) { O(hwFlow(s), "network")["mode"] = "open" },
			"network access is open, so the step is not isolated"},
		"no-network-block": {"simulation", func(s Obj) { delete(hwFlow(s), "network") },
			"design simulation"},
		"sandbox-had-network": {"synthesis", func(s Obj) { O(hwFlow(s), "isolation")["network"] = "host" },
			"the sandbox allowed network access"},
		"unpinned-binary": {"synthesis", func(s Obj) {
			O(Objs(hwFlow(s), "tools")[0], "digest")["sha256"] = strings.Repeat("ab", 32)
		}, "tool yosys sha256:abababababababab is not on the policy's pinned tool list"},
		"tool-without-digest": {"simulation", func(s Obj) { delete(Objs(hwFlow(s), "tools")[0], "digest") },
			"tool iverilog is not pinned by digest"},
		"other-package-files": {"synthesis", func(s Obj) {
			O(Objs(hwFlow(s), "tools")[0], "package", "treeDigest")["sha256"] = strings.Repeat("cd", 32)
		}, "tool yosys is the pinned binary, but its package yosys 0.33-5build2"},
		"no-tools-named": {"signoff", func(s Obj) { hwFlow(s)["tools"] = []any{} },
			"design signoff: the record names no tool"},
		"no-equivalence-check": {"signoff", func(s Obj) { hwFlow(s)["checks"] = []any{} },
			"no passing rtl-netlist-equivalence check"},
		"equivalence-of-another-netlist": {"signoff", func(s Obj) {
			for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
				if S(d, "name") == "picorv32.netlist.v" {
					O(d, "digest")["sha256"] = strings.Repeat("ef", 32)
				}
			}
		}, "released design"},
		"script-not-carried": {"signoff", func(s Obj) {
			O(s, "predicate", "buildDefinition", "externalParameters")["script"] = "other.ys"
		}, "does not carry its equivalence script"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := designL3Bundle(t)
			resignStep(t, bundle, c.step, c.mutate)
			rejects(t, designCheck(t, bundle, designL3Policy(t)), c.reason)
			// The same records still pass a Design L2 policy: the change only matters at L3.
			l2 := designL3Policy(t)
			O(l2, "claims")["design"] = anyStrings([]string{"HSLSA_DESIGN_LEVEL_2", "SLSA_BUILD_LEVEL_2"})
			O(l2, "claims")["lot"] = anyStrings([]string{"HSLSA_WAFER_LEVEL_2"})
			if c.reason == "design simulation" || name == "network-open" {
				return // a record without the network block, or open, fails no L2 rule but is not what this asserts
			}
			must(t, designCheck(t, bundle, l2))
		})
	}
}

func TestDesignL3ScriptSwappedInBundle(t *testing.T) {
	bundle := designL3Bundle(t)
	appendFile(t, filepath.Join(bundle, "artifacts", EquivalenceScriptFile), "# proves nothing\n")
	rejects(t, designCheck(t, bundle, designL3Policy(t)), "the equivalence script equivalence.ys in the bundle is not the one the record names")
}

func TestDesignL3PolicyRules(t *testing.T) {
	bundle := designL3Bundle(t)
	cases := map[string]struct {
		mutate func(Obj)
		reason string
	}{
		"no-equivalence-step": {func(p Obj) { delete(O(p, "design"), "equivalence") },
			"the policy names no equivalence record"},
		"equivalence-step-not-required": {func(p Obj) {
			O(p, "design")["requiredSteps"] = anyStrings([]string{"source-freeze", "simulation", "synthesis"})
		}, "is not one of the policy's required steps"},
		"no-pins": {func(p Obj) { delete(O(p, "design"), "toolPins") },
			"is not on the policy's pinned tool list"},
		"pinned-other-version": {func(p Obj) {
			O(Objs(O(p, "design"), "toolPins")[2], "package")["version"] = "0.34-1"
		}, "tool yosys is the pinned binary, but its package"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := designL3Policy(t)
			c.mutate(p)
			rejects(t, designCheck(t, bundle, p), c.reason)
		})
	}
}

// The rerun proves the netlist equal to the RTL again with this machine's
// Yosys. A flow platform that inserts logic into the netlist and records a
// passing proof anyway gets past every check that reads records; the rerun
// catches it. Needs Yosys (and bubblewrap for the isolated rerun); CI sets
// HSLSA_REQUIRE_YOSYS so a missing tool fails instead of skipping.
func requireYosys(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("yosys"); err != nil {
		if os.Getenv("HSLSA_REQUIRE_YOSYS") != "" {
			t.Fatal("HSLSA_REQUIRE_YOSYS is set but yosys is not installed")
		}
		t.Skip("yosys is not installed")
	}
}

func TestRerunEquivalenceCatchesAlteredNetlist(t *testing.T) {
	requireYosys(t)
	bundle := designL3Bundle(t)
	netlist := filepath.Join(bundle, "artifacts", "picorv32.netlist.v")
	data := ok(os.ReadFile(netlist))
	// The insider inverts bit 2 of the address the core drives onto the memory bus.
	line := `  assign mem_addr[2] = \mem_addr_reg[2] ;`
	if !strings.Contains(string(data), line) {
		t.Fatal("the netlist does not drive mem_addr[2] the way this test expects")
	}
	altered := []byte(strings.Replace(string(data), line, `  assign mem_addr[2] = ~\mem_addr_reg[2] ;`, 1))
	must(t, os.WriteFile(netlist, altered, 0o644))
	// ...and re-signs synthesis, the signoff (claiming the proof passed) and the release over it.
	sum := sha256Bytes(altered)
	for _, step := range []string{"synthesis", "signoff"} {
		chipResign(t, bundle, AttName(step), "flow-platform", func(s Obj) {
			list := Objs(s, "subject")
			if step == "signoff" {
				list = Objs(s, "predicate", "buildDefinition", "resolvedDependencies")
			}
			for _, d := range list {
				if S(d, "name") == "picorv32.netlist.v" {
					O(d, "digest")["sha256"] = sum
				}
			}
		})
	}
	keys := chipKeys(bundle)
	must(t, DesignRelease(bundle, e2eLock, filepath.Join(keys, "tapeout-authority.key.pem"), filepath.Join(bundle, "trust-root.json"), e2ePolicy))
	must(t, designCheck(t, bundle, designL3Policy(t)))

	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, bwrapErr := exec.LookPath("bwrap")
	rejects(t, RerunEquivalence(bundle, trust, bwrapErr == nil), "equivalence rerun: the proof did not hold")
}
