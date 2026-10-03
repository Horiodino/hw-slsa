package hslsa

// Records signed on a supplier's behalf: the PicoRV32 lot again, with a sort
// house that hands over only paper (the OSAT signs an evidence record for
// it) and a test house that hands over its data but signs nothing (the
// product owner proxy-signs F4 and the transfers it would have signed).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	proxyScenario = filepath.Join(e2eDir, "proxy", "mfg-scenario.json")
	proxyPolicy   = filepath.Join(e2eDir, "proxy", "policy.json")
)

// proxyBundle is a fresh copy of the chip bundle with the proxy scenario's lot.
func proxyBundle(t *testing.T) string {
	t.Helper()
	chip := chipBundle(t)
	keys := chipKeys(chip)
	must(t, Mfg(chip, proxyScenario, keys, nil))
	must(t, BuildHBOM(chip, e2eLock, proxyScenario, filepath.Join(keys, "product-owner.key.pem"), nil))
	return chip
}

func proxyCheck(t *testing.T, bundle string) error {
	t.Helper()
	return chipCheckPolicy(t, bundle, nil, proxyPolicy)
}

func TestProxyExampleMatchesMainExample(t *testing.T) {
	// The proxy example differs from the main one only where it says so:
	// which suppliers sign nothing, and so the lower levels its HBOM claims.
	sc, base := ok(ReadObj(proxyScenario)), ok(ReadObj(e2eScenario))
	delete(sc, "unsigned")
	delete(sc, "claimedLevels")
	delete(base, "claimedLevels")
	if !jsonEqual(sc, base) {
		t.Error("proxy scenario differs from mfg-scenario.json beyond its unsigned block and claimed levels")
	}
	p, bp := ok(ReadObj(proxyPolicy)), ok(ReadObj(e2ePolicy))
	if !jsonEqual(p["design"], bp["design"]) || !jsonEqual(O(p, "claims")["design"], O(bp, "claims")["design"]) {
		t.Error("proxy policy's design rules differ from policy.json")
	}
}

func TestProxyChainVerifies(t *testing.T) {
	bundle := proxyBundle(t)
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, lot, err := Verify(bundle, trust, proxyPolicy, "", "", "")
	must(t, err)
	got := strings.Join(lot.OnBehalf, "\n")
	for _, want := range []string{
		"wafer-sort: evidence record signed by Example OSAT for Example Sort House",
		"transfer from wafer-sort: proxy-signed by Example OSAT for Example Sort House",
		"final-test: proxy-signed by Example Open Silicon Group for Example Test House",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not say %q:\n%s", want, got)
		}
	}
	if _, err := os.Stat(filepath.Join(bundle, "artifacts", "wafer-maps.json")); err == nil {
		t.Error("stale wafer maps left in a bundle whose sort house gave none")
	}
}

func TestMainExampleIsBackToSelfSigned(t *testing.T) {
	// Producing the main lot again over a proxy bundle leaves no proxy files behind.
	bundle := proxyBundle(t)
	must(t, rebuildDownstream(bundle))
	must(t, chipCheck(t, bundle, nil))
	for _, step := range MfgSteps {
		if _, err := os.Stat(filepath.Join(bundle, "artifacts", ExportName(step))); err == nil {
			t.Errorf("stale supplier export for %s", step)
		}
	}
}

func TestPolicyRefusesOnBehalfByDefault(t *testing.T) {
	bundle := proxyBundle(t)
	rejects(t, chipCheck(t, bundle, nil),
		"wafer-sort: signed by Example OSAT on behalf of Example Sort House, and the policy does not accept evidence records (manufacturing.acceptOnBehalf)")
	policy := filepath.Join(t.TempDir(), "policy.json")
	must(t, copyFile(proxyPolicy, policy))
	editJSON(t, policy, func(p Obj) { O(p, "manufacturing")["acceptOnBehalf"] = []any{"evidence"} })
	rejects(t, chipCheckPolicy(t, bundle, nil, policy), "and the policy does not accept proxy-signed records")
}

func TestOnBehalfHoldsTrackAtL1(t *testing.T) {
	bundle := proxyBundle(t)
	policy := filepath.Join(t.TempDir(), "policy.json")
	must(t, copyFile(proxyPolicy, policy))
	editJSON(t, policy, func(p Obj) {
		O(p, "claims")["lot"] = []any{"HSLSA_WAFER_LEVEL_1", "HSLSA_PACKAGE_TEST_LEVEL_2", "HSLSA_DESIGN_LEVEL_2"}
	})
	rejects(t, chipCheckPolicy(t, bundle, nil, policy),
		"policy claims Package/Test L2, but final-test was signed on its supplier's behalf, which holds the Package/Test track at L1")
	editJSON(t, policy, func(p Obj) {
		O(p, "claims")["lot"] = []any{"HSLSA_WAFER_LEVEL_2", "HSLSA_PACKAGE_TEST_LEVEL_1", "HSLSA_DESIGN_LEVEL_2"}
	})
	rejects(t, chipCheckPolicy(t, bundle, nil, policy), "policy claims Wafer L2, but wafer-sort was signed on its supplier's behalf")
}

func TestProxyHidesThatItIsAProxy(t *testing.T) {
	// A proxy's record without hwMfg.proxy is checked as the supplier's own, against the supplier's key.
	bundle := proxyBundle(t)
	chipResign(t, bundle, MfgAtt["final-test"], "product-owner", func(s Obj) {
		delete(O(s, "predicate", "hwMfg"), "proxy")
	})
	rejects(t, proxyCheck(t, bundle), "no valid signature from role 'test-site'")
}

func TestProxyIsNotWhoReceived(t *testing.T) {
	// Only the party that received from the supplier may sign for it.
	bundle := proxyBundle(t)
	chipResign(t, bundle, MfgAtt["final-test"], "osat-site", nil)
	rejects(t, proxyCheck(t, bundle), "no valid signature from role 'product-owner'")
}

func TestProxyNamesAnotherSigner(t *testing.T) {
	bundle := proxyBundle(t)
	chipResign(t, bundle, MfgAtt["final-test"], "product-owner", func(s Obj) {
		other := Obj{"name": "Unlisted Broker", "country": "US"}
		O(s, "predicate", "hwMfg", "proxy")["signer"] = other
		O(s, "predicate", "runDetails", "builder")["id"] = proxyBuilder(other)
	})
	rejects(t, proxyCheck(t, bundle), "final-test: signed on its supplier's behalf by Unlisted Broker, which did not receive from it")
}

func TestProxyPosesAsTheSupplier(t *testing.T) {
	// builder.id must name the proxy, so a SLSA verifier reading only builder.id is not misled.
	bundle := proxyBundle(t)
	chipResign(t, bundle, MfgAtt["final-test"], "product-owner", func(s Obj) {
		O(s, "predicate", "runDetails", "builder")["id"] = "urn:hslsa:site:example-test-house"
	})
	rejects(t, proxyCheck(t, bundle), "final-test: builder.id must be urn:hslsa:proxy:example-open-silicon-group")
}

func TestProxyAddsWhatTheSupplierDidNotReport(t *testing.T) {
	bundle := proxyBundle(t)
	chipResign(t, bundle, MfgAtt["final-test"], "product-owner", func(s Obj) {
		O(s, "predicate", "hwMfg")["checks"] = []any{Obj{"name": "burn-in", "result": "pass"}}
	})
	rejects(t, proxyCheck(t, bundle), "final-test: hwMfg.checks differs from the supplier's export")
}

func TestProxyChangesTheSuppliersData(t *testing.T) {
	// Results edited after the supplier exported them, re-signed with their new digest.
	bundle := proxyBundle(t)
	path := filepath.Join(bundle, "artifacts", "final-test-results.json")
	editJSON(t, path, func(r Obj) { O(r, "units")["PSOC130-A0-00007"] = "pass" })
	chipResign(t, bundle, MfgAtt["final-test"], "product-owner", func(s Obj) {
		O(Objs(s, "subject")[1], "digest")["sha256"] = ok(sha256File(path))
	})
	rejects(t, proxyCheck(t, bundle), "final-test: final-test-results.json differs from the supplier's export")
}

func TestSupplierExportSwapped(t *testing.T) {
	bundle := proxyBundle(t)
	editJSON(t, filepath.Join(bundle, "artifacts", ExportName("final-test")), func(e Obj) {
		O(e, "record", "yield")["passed"] = 40
	})
	rejects(t, proxyCheck(t, bundle), "final-test: the supplier's export supplier-export-final-test.json does not match its digest")
}

func TestEvidenceDocumentSwapped(t *testing.T) {
	bundle := proxyBundle(t)
	appendFile(t, filepath.Join(bundle, "artifacts", "wafer-sort-coc.txt"), "Amended: all 50 die pass.\n")
	rejects(t, proxyCheck(t, bundle), "wafer-sort: subject wafer-sort-coc.txt does not match its attested digest")
}

func TestEvidenceCoversAnotherStep(t *testing.T) {
	bundle := proxyBundle(t)
	chipResign(t, bundle, MfgAtt["wafer-sort"], "osat-site", func(s Obj) {
		O(s, "predicate", "hwMfg", "evidence")["covers"] = "packaging"
	})
	rejects(t, proxyCheck(t, bundle), `wafer-sort: evidence record covers "packaging", not wafer-sort`)
}

func TestEvidenceNamesAnUndeclaredSubject(t *testing.T) {
	bundle := proxyBundle(t)
	chipResign(t, bundle, MfgAtt["wafer-sort"], "osat-site", func(s Obj) {
		docs := A(s, "predicate", "hwMfg", "evidence", "documents")
		O(s, "predicate", "hwMfg", "evidence")["documents"] = docs[:1]
	})
	rejects(t, proxyCheck(t, bundle), "wafer-sort: every subject of an evidence record must be one of its documents")
}

func TestEvidenceCannotStandInForALot(t *testing.T) {
	// A document cannot name a lot by digest, so only wafer sort may be covered by one.
	sc := ok(ReadObj(proxyScenario))
	O(sc, "unsigned")["packaging"] = Obj{"cover": "evidence"}
	if _, err := onBehalf(sc, "packaging"); err == nil || !strings.Contains(err.Error(), "can stand in only for wafer-sort") {
		t.Fatalf("got %v", err)
	}
	stmt := Obj{"predicate": Obj{"hwMfg": Obj{"evidence": Obj{"covers": "final-test"}}}}
	rejects(t, evidenceCheck(stmt, "final-test", "final-test"), "an evidence record cannot stand in for final-test")
}

func TestTwoSuppliersInARowSignNothing(t *testing.T) {
	// Whoever receives from a supplier that signs nothing must sign itself.
	sc := ok(ReadObj(proxyScenario))
	O(sc, "unsigned")["packaging"] = Obj{"cover": "proxy"}
	if _, err := onBehalf(sc, "wafer-sort"); err == nil || !strings.Contains(err.Error(), "packaging receives from it but signs nothing either") {
		t.Fatalf("got %v", err)
	}
}
