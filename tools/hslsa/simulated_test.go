package hslsa

// Records made from simulated hardware: marked in every record, refused
// unless the policy accepts them, and stated in every VSA over them.

import (
	"path/filepath"
	"strings"
	"testing"
)

// realPartsPolicy is the example's policy as a buyer of real parts writes
// it: without simulated.accept.
func realPartsPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	must(t, copyFile(e2ePolicy, path))
	editJSON(t, path, func(p Obj) { delete(p, "simulated") })
	return path
}

func TestSimulatedLotRefusedWithoutOptIn(t *testing.T) {
	bundle := chipBundle(t)
	rejects(t, chipCheckPolicy(t, bundle, nil, realPartsPolicy(t)), "made from simulated hardware, and the policy does not accept simulated evidence")
}

func TestEveryLotRecordIsMarkedSimulated(t *testing.T) {
	bundle := chipBundle(t)
	for _, name := range append(mfgAttNames(), TransferAtt("wafer-fab"), TransferAtt("wafer-sort"), TransferAtt("packaging")) {
		stmt := ok(DecodeEnvelope(filepath.Join(bundle, "att", name)))
		if simulatedOf(stmt) == nil {
			t.Errorf("%s carries no simulated block", name)
		}
	}
}

func mfgAttNames() []string {
	var out []string
	for _, s := range MfgSteps {
		out = append(out, MfgAtt[s])
	}
	return out
}

func TestLotVSAStatesSimulated(t *testing.T) {
	bundle := chipBundle(t)
	dir := t.TempDir()
	ok(Keygen(dir, "verifier"))
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, _, err := Verify(bundle, trust, e2ePolicy, "", filepath.Join(dir, "verifier.key.pem"), dir)
	must(t, err)
	lot := ok(DecodeEnvelope(filepath.Join(dir, "lot.vsa.intoto.json")))
	if !contains(Strs(lot, "predicate", "verifiedLevels"), SimulatedLevel) {
		t.Errorf("lot VSA levels %v do not state %s", Strs(lot, "predicate", "verifiedLevels"), SimulatedLevel)
	}
	design := ok(DecodeEnvelope(filepath.Join(dir, "design.vsa.intoto.json")))
	if contains(Strs(design, "predicate", "verifiedLevels"), SimulatedLevel) {
		t.Errorf("design VSA states %s, but the design flow really ran", SimulatedLevel)
	}
	if err := refuseSimulatedVSA(lot, ok(ReadObj(realPartsPolicy(t))), "lot VSA"); err == nil {
		t.Error("a VSA over simulated evidence passed under a policy that does not accept it")
	}
	if err := refuseSimulatedVSA(lot, ok(ReadObj(e2ePolicy)), "lot VSA"); err != nil {
		t.Error(err)
	}
}

func TestSimulatedBlockNeedsSimulatorAndStandsIn(t *testing.T) {
	bundle := chipBundle(t)
	sc := filepath.Join(t.TempDir(), "scenario.json")
	must(t, copyFile(e2eScenario, sc))
	editJSON(t, sc, func(s Obj) { s["simulated"] = Obj{"simulator": "something"} })
	err := Mfg(bundle, sc, chipKeys(bundle), nil)
	if err == nil || !strings.Contains(err.Error(), "standsIn") {
		t.Fatalf("got %v", err)
	}
}
