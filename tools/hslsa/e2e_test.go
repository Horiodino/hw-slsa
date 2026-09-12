package hslsa

// Tamper tests: every broken link in the chain must fail verification, for the right reason.
//
// Needs a bundle from `e2e/run.sh produce` (HSLSA_BUNDLE, default out/bundle).
// The producer keys never leave the produce job, so the fixture re-signs the
// bundle's design records with fresh test keys and rebuilds the rest of the
// chain on top of them. Tests can then forge records that carry valid
// signatures and check that the verifier still catches the lie.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	e2eDir      = filepath.Join(root, "e2e", "picorv32")
	e2eLock     = filepath.Join(e2eDir, "inputs.lock.json")
	e2eScenario = filepath.Join(e2eDir, "mfg-scenario.json")
	e2ePolicy   = filepath.Join(e2eDir, "policy.json")
	e2eRoles    = []string{"flow-platform", "tapeout-authority", "fab-site", "sort-site", "osat-site", "test-site", "product-owner"}
)

func chipSource() string { return envPath("HSLSA_BUNDLE", "out/bundle") }

func TestLotDigestMatchesSpecExample(t *testing.T) {
	// The committed example's lot subject is reproducible from its unit list.
	example := ok(ReadObj(filepath.Join(root, "hbom", "picosoc-sky130.hbom.intoto.json")))
	var lot Obj
	for _, s := range Objs(example, "subject") {
		if strings.HasPrefix(S(s, "name"), "urn:hslsa:lot:") {
			lot = s
		}
	}
	units := ok(ReadUnits(filepath.Join(root, "hbom", "picosoc-sky130.shipped-lot.txt")))
	if got := ok(LotDigest(units)); got != S(lot, "digest", "sha256") {
		t.Fatalf("lot digest %s, example says %s", got, S(lot, "digest", "sha256"))
	}
}

func TestLotDigestIsOrderIndependentAndRejectsDuplicates(t *testing.T) {
	if ok(LotDigest([]string{"b", "a"})) != ok(LotDigest([]string{"a", "b"})) {
		t.Fatal("lot digest depends on order")
	}
	if _, err := LotDigest([]string{"a", "a"}); err == nil {
		t.Fatal("duplicate units accepted")
	}
}

func rebuildDownstream(bundle string) error {
	keys := filepath.Join(filepath.Dir(bundle), "keys")
	if err := DesignRelease(bundle, e2eLock, filepath.Join(keys, "tapeout-authority.key.pem"), filepath.Join(bundle, "trust-root.json"), e2ePolicy); err != nil {
		return err
	}
	if err := Mfg(bundle, e2eScenario, keys); err != nil {
		return err
	}
	return BuildHBOM(bundle, e2eLock, e2eScenario, filepath.Join(keys, "product-owner.key.pem"))
}

// chipBundle is a fresh copy of the re-signed chip bundle.
func chipBundle(t *testing.T) string {
	t.Helper()
	src := chipSource()
	requireDir(t, filepath.Join(src, "att"), "run e2e/run.sh produce first")
	valid := shared(t, "chip", func(work string) error {
		bundle := filepath.Join(work, "bundle")
		if err := copyTree(src, bundle); err != nil {
			return err
		}
		keys := filepath.Join(work, "keys")
		if _, err := Keygen(keys, "attacker"); err != nil {
			return err
		}
		if err := makeKeys(keys, filepath.Join(work, "pub"), e2eRoles...); err != nil {
			return err
		}
		if err := BuildTrustRoot(filepath.Join(work, "pub"), filepath.Join(bundle, "trust-root.json")); err != nil {
			return err
		}
		signer, err := LoadSigner(filepath.Join(keys, "flow-platform.key.pem"))
		if err != nil {
			return err
		}
		for _, step := range DesignSteps {
			path := filepath.Join(bundle, "att", AttName(step))
			stmt, err := DecodeEnvelope(path)
			if err != nil {
				return err
			}
			if _, err := Sign(stmt, signer, path); err != nil {
				return err
			}
		}
		return rebuildDownstream(bundle)
	})
	return filepath.Join(copyOf(t, valid), "bundle")
}

func chipCheck(t *testing.T, bundle string, units []string) error {
	t.Helper()
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	unitsFile := ""
	if units != nil {
		unitsFile = writeLines(t, filepath.Join(t.TempDir(), "units.txt"), units)
	}
	_, _, err := Verify(bundle, trust, e2ePolicy, unitsFile, "", "")
	return err
}

func chipKeys(bundle string) string { return filepath.Join(filepath.Dir(bundle), "keys") }

func chipResign(t *testing.T, bundle, name, role string, mutate func(Obj)) {
	t.Helper()
	resign(t, filepath.Join(bundle, "att", name), chipKeys(bundle), role, mutate)
}

func TestProducedBundleVerifiesAsIs(t *testing.T) {
	src := chipSource()
	requireDir(t, filepath.Join(src, "att"), "run e2e/run.sh produce first")
	must(t, chipCheck(t, src, ok(ReadUnits(filepath.Join(e2eDir, "received-units.txt")))))
}

func TestRebuiltBundleVerifies(t *testing.T) {
	bundle := chipBundle(t)
	must(t, chipCheck(t, bundle, ok(ReadUnits(filepath.Join(e2eDir, "received-units.txt")))))
}

// Files swapped after signing

func TestModifiedArtifact(t *testing.T) {
	for _, artifact := range []string{"picorv32.netlist.v", "source.tar", "simulation.log", "wafer-maps.json", "genealogy.json"} {
		t.Run(artifact, func(t *testing.T) {
			bundle := chipBundle(t)
			appendFile(t, filepath.Join(bundle, "artifacts", artifact), "\n")
			rejects(t, chipCheck(t, bundle, nil), fmt.Sprintf("subject %s does not match its attested digest", artifact))
		})
	}
}

func TestUnitAddedToShippedLot(t *testing.T) {
	bundle := chipBundle(t)
	appendFile(t, filepath.Join(bundle, "artifacts", "shipped-lot.txt"), "PSOC130-A0-99999\n")
	rejects(t, chipCheck(t, bundle, nil), "shipped lot list does not match the attested lot digest")
}

func TestReceivedUnitNotInLot(t *testing.T) {
	bundle := chipBundle(t)
	rejects(t, chipCheck(t, bundle, []string{"PSOC130-A0-00001", "PSOC130-A0-00007"}), "PSOC130-A0-00007 is not in the shipped lot")
}

// Signatures

func TestMissingStep(t *testing.T) {
	bundle := chipBundle(t)
	must(t, os.Remove(filepath.Join(bundle, "att", AttName("simulation"))))
	rejects(t, chipCheck(t, bundle, nil), "missing attestation")
}

func TestPayloadEditedWithoutResigning(t *testing.T) {
	bundle := chipBundle(t)
	editPayload(t, filepath.Join(bundle, "att", MfgAtt["final-test"]), func(s Obj) {
		O(s, "predicate", "hwMfg", "yield")["failed"] = []any{}
	})
	rejects(t, chipCheck(t, bundle, nil), "no valid signature from role 'test-site'")
}

func TestStepSignedByUnknownKey(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("synthesis"), "attacker", nil)
	rejects(t, chipCheck(t, bundle, nil), "no valid signature from role 'flow-platform'")
}

func TestReleaseSignedByFlowPlatform(t *testing.T) {
	// Separation of duties: the flow platform cannot release its own output.
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("release"), "flow-platform", nil)
	rejects(t, chipCheck(t, bundle, nil), "no valid signature from role 'tapeout-authority'")
}

func TestRecordFromTheWrongSite(t *testing.T) {
	bundle := chipBundle(t)
	must(t, copyFile(filepath.Join(bundle, "att", MfgAtt["wafer-sort"]), filepath.Join(bundle, "att", MfgAtt["wafer-fab"])))
	rejects(t, chipCheck(t, bundle, nil), "no valid signature from role 'fab-site'")
}

// Validly signed records that lie

func TestFailedGate(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("simulation"), "flow-platform", func(s Obj) {
		Objs(s, "predicate", "hwFlow", "checks")[1]["result"] = "fail"
	})
	rejects(t, chipCheck(t, bundle, nil), "design simulation: gate failed: testbench-finished")
}

func TestUnapprovedTool(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("synthesis"), "flow-platform", func(s Obj) {
		Objs(s, "predicate", "hwFlow", "tools")[0]["name"] = "yosys-patched"
	})
	rejects(t, chipCheck(t, bundle, nil), "tool yosys-patched is not on the approved list")
}

func TestStepNotLinkedToSource(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("synthesis"), "flow-platform", func(s Obj) {
		O(s, "predicate", "buildDefinition")["resolvedDependencies"] = []any{}
	})
	rejects(t, chipCheck(t, bundle, nil), "design synthesis: chain broken")
}

func TestReleaseOfAnArtifactTheFlowDidNotBuild(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("release"), "tapeout-authority", func(s Obj) {
		O(Objs(s, "subject")[0], "digest")["sha256"] = strings.Repeat("0", 64)
	})
	rejects(t, chipCheck(t, bundle, nil), "subject picorv32.netlist.v does not match its attested digest")
}

func TestMfgStepNamesAnotherDesign(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, MfgAtt["packaging"], "osat-site", func(s Obj) {
		O(s, "predicate", "hwMfg", "designRef", "digest")["sha256"] = strings.Repeat("1", 64)
	})
	rejects(t, chipCheck(t, bundle, nil), "packaging: designRef names a different design release")
}

func TestYieldDoesNotReconcile(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, MfgAtt["final-test"], "test-site", func(s Obj) {
		y := O(s, "predicate", "hwMfg", "yield")
		y["failed"] = A(y, "failed")[1:]
	})
	rejects(t, chipCheck(t, bundle, nil), "yield record does not account for every packaged unit")
}

func TestHBOMNamesAnotherLot(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, "hbom.intoto.json", "product-owner", func(s Obj) {
		O(Objs(s, "subject")[1], "digest")["sha256"] = strings.Repeat("2", 64)
	})
	rejects(t, chipCheck(t, bundle, nil), "hbom: lot subject does not match the final test shipped lot")
}

func TestHBOMMustMatchSchema(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, "hbom.intoto.json", "product-owner", func(s Obj) {
		O(s, "predicate", "product")["level"] = "wafer"
	})
	rejects(t, chipCheck(t, bundle, nil), "HBOM does not match its schema")
}
