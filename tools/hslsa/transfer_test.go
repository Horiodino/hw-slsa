package hslsa

// Tamper tests for the transfers between the chip's manufacturing sites, and
// for the gap report the lot receipt check gives before it walks the chain.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleHasEveryTransfer(t *testing.T) {
	bundle := chipBundle(t)
	for _, from := range TransferFrom {
		stmt := ok(DecodeEnvelope(filepath.Join(bundle, "att", TransferAtt(from))))
		if buildType(stmt) != mfgStepType("distribution") {
			t.Errorf("transfer from %s has build type %s", from, buildType(stmt))
		}
	}
}

func TestMissingTransferIsAGap(t *testing.T) {
	bundle := chipBundle(t)
	must(t, os.Remove(filepath.Join(bundle, "att", TransferAtt("wafer-sort"))))
	rejects(t, chipCheck(t, bundle, nil),
		"lot receipt check: 1 gap(s) in the chain: missing attestation mfg-transfer-wafer-sort.intoto.json (Wafer track)")
}

func TestGapReportListsEveryGap(t *testing.T) {
	// The check names every missing record and its track, not only the first.
	bundle := chipBundle(t)
	must(t, os.Remove(filepath.Join(bundle, "att", MfgAtt["wafer-sort"])))
	must(t, os.Remove(filepath.Join(bundle, "att", TransferAtt("packaging"))))
	must(t, os.Remove(filepath.Join(bundle, "att", "hbom.intoto.json")))
	err := chipCheck(t, bundle, nil)
	rejects(t, err, "lot receipt check: 3 gap(s) in the chain")
	for _, want := range []string{
		"missing attestation mfg-f2-wafer-sort.intoto.json (Wafer track)",
		"missing attestation mfg-transfer-packaging.intoto.json (Package/Test track)",
		"missing attestation hbom.intoto.json (product HBOM)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("gap report %q does not name %q", err, want)
		}
	}
}

func TestTransfersOptionalUnlessRequired(t *testing.T) {
	// Without requireTransfers, a chain with no transfers passes and says what was not recorded.
	bundle := chipBundle(t)
	policy := filepath.Join(t.TempDir(), "policy.json")
	must(t, copyFile(e2ePolicy, policy))
	editJSON(t, policy, func(p Obj) { delete(p, "manufacturing") })
	scenario := filepath.Join(t.TempDir(), "mfg-scenario.json")
	must(t, copyFile(e2eScenario, scenario))
	editJSON(t, scenario, func(s Obj) { delete(s, "transfers") })
	keys := chipKeys(bundle)
	must(t, Mfg(bundle, scenario, keys, nil))
	must(t, BuildHBOM(bundle, e2eLock, scenario, filepath.Join(keys, "product-owner.key.pem"), nil))
	for _, from := range TransferFrom {
		if _, err := os.Stat(filepath.Join(bundle, "att", TransferAtt(from))); err == nil {
			t.Fatalf("stale transfer from %s left in the bundle", from)
		}
	}
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, lot, err := Verify(bundle, trust, policy, "", "", "")
	must(t, err)
	if len(lot.NotRecorded) != 3 || !strings.Contains(lot.NotRecorded[0], "transfer from wafer-fab to wafer-sort") {
		t.Fatalf("not recorded: %v", lot.NotRecorded)
	}
	rejects(t, chipCheck(t, bundle, nil), "lot receipt check: 3 gap(s) in the chain: missing attestation mfg-transfer-wafer-fab.intoto.json")
}

func TestTransferSignedByTheReceiver(t *testing.T) {
	// The site that ships signs the transfer, not the one that receives it.
	bundle := chipBundle(t)
	chipResign(t, bundle, TransferAtt("wafer-fab"), "sort-site", nil)
	rejects(t, chipCheck(t, bundle, nil), "no valid signature from role 'fab-site'")
}

func TestTransferToAnotherSite(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, TransferAtt("wafer-sort"), "sort-site", func(s Obj) {
		O(s, "predicate", "hwMfg", "receiver")["name"] = "Unlisted Packaging Co"
	})
	rejects(t, chipCheck(t, bundle, nil), "transfer from wafer-sort: shipped to Unlisted Packaging Co, but Example OSAT signed the next step")
}

func TestTransferShipsOtherUnits(t *testing.T) {
	// A packing list that swaps one packaged unit for another, re-signed with its new digest.
	bundle := chipBundle(t)
	path := filepath.Join(bundle, "artifacts", TransferList("packaging"))
	editJSON(t, path, func(l Obj) { A(l, "items")[0] = "PSOC130-A0-99999" })
	chipResign(t, bundle, TransferAtt("packaging"), "osat-site", func(s Obj) {
		O(Objs(s, "subject")[0], "digest")["sha256"] = ok(sha256File(path))
	})
	rejects(t, chipCheck(t, bundle, nil), "transfer from packaging: packing list does not ship exactly urn:hslsa:assembly-lot:ASM-EXAMPLE-17")
}

func TestStepBypassesTransfer(t *testing.T) {
	// Once a transfer is recorded, the receiving step must link it, not the step before it.
	bundle := chipBundle(t)
	f1 := envRD(bundle, MfgAtt["wafer-fab"])
	chipResign(t, bundle, MfgAtt["wafer-sort"], "sort-site", func(s Obj) {
		deps := A(s, "predicate", "buildDefinition", "resolvedDependencies")
		deps[0] = f1
	})
	rejects(t, chipCheck(t, bundle, nil), "wafer-sort: chain broken, resolvedDependencies do not include previous step att/mfg-transfer-wafer-fab.intoto.json")
}
