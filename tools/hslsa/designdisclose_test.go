package hslsa

// Withheld fields in design records: a design house may withhold metrics, tool
// arguments, file paths and IP names, never what the checks read.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// designWithholding withholds the synthesis and signoff scripts and the
// signoff method, as a design house under an NDA with its EDA vendor might.
var designWithholding = &Withholding{Fields: map[string][]string{
	"synthesis": {"/buildDefinition/externalParameters/script"},
	"signoff":   {"/buildDefinition/externalParameters/script", "/buildDefinition/externalParameters/method"},
	"release":   {"/buildDefinition/externalParameters/ipBlocks/0/name"},
}}

// resignDesignStep signs a design step's record again through finish, with
// the fields w names withheld.
func resignDesignStep(t *testing.T, bundle, step string, w *Withholding) error {
	t.Helper()
	stmt := ok(DecodeEnvelope(filepath.Join(bundle, "att", AttName(step))))
	signer := ok(LoadSigner(filepath.Join(chipKeys(bundle), "flow-platform.key.pem")))
	return finish(bundle, step, Objs(stmt, "subject"), O(stmt, "predicate"), signer, w)
}

// withheldDesignBundle is a chip bundle whose synthesis, signoff and release
// records withhold fields, with every record downstream signed again.
func withheldDesignBundle(t *testing.T) string {
	t.Helper()
	bundle := chipBundle(t)
	for _, step := range []string{"synthesis", "signoff"} {
		must(t, resignDesignStep(t, bundle, step, designWithholding))
	}
	keys := chipKeys(bundle)
	must(t, DesignRelease(bundle, e2eLock, filepath.Join(keys, "tapeout-authority.key.pem"), filepath.Join(bundle, "trust-root.json"), e2ePolicy, designWithholding))
	must(t, Mfg(bundle, e2eScenario, keys, nil))
	must(t, BuildHBOM(bundle, e2eLock, e2eScenario, filepath.Join(keys, "product-owner.key.pem"), nil))
	return bundle
}

func TestDesignRecordWithheldFieldsVerifies(t *testing.T) {
	bundle := withheldDesignBundle(t)
	for step, paths := range designWithholding.Fields {
		stmt := ok(DecodeEnvelope(filepath.Join(bundle, "att", AttName(step))))
		var listed []string
		for _, e := range Withheld(stmt) {
			listed = append(listed, S(e, "path"))
		}
		if strings.Join(listed, ",") != strings.Join(paths, ",") {
			t.Fatalf("%s lists %v as withheld, want %v", step, listed, paths)
		}
		if Has(O(stmt, "predicate", "buildDefinition", "externalParameters"), "script") {
			t.Fatalf("%s still carries its script", step)
		}
	}
	// With the disclosures, the chain verifies as before, and the values come back.
	must(t, chipCheck(t, bundle, ok(ReadUnits(filepath.Join(e2eDir, "received-units.txt")))))
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	signoff := ok(trust.Open(filepath.Join(bundle, "att", AttName("signoff")), "flow-platform", DesignFlow))
	if S(signoff, "predicate", "buildDefinition", "externalParameters", "script") != "equivalence.ys" {
		t.Fatalf("revealed signoff script %v", get(signoff, "predicate", "buildDefinition", "externalParameters", "script"))
	}
	release := ok(trust.Open(filepath.Join(bundle, "att", AttName("release")), "tapeout-authority", DesignFlow))
	if S(Objs(release, "predicate", "buildDefinition", "externalParameters", "ipBlocks")[0], "name") != "picorv32" {
		t.Fatal("the release's IP block name did not come back from its disclosure")
	}
}

func TestDesignRecordWithheldFieldNeedsItsDisclosure(t *testing.T) {
	bundle := withheldDesignBundle(t)
	must(t, os.Remove(disclosurePath(filepath.Join(bundle, "att", AttName("signoff")))))
	rejects(t, chipCheck(t, bundle, nil), "design-3-signoff.intoto.json: /buildDefinition/externalParameters/script is withheld and no disclosure was given")
}

func TestDesignRecordRefusesWithholdingWhatChecksRead(t *testing.T) {
	bundle := chipBundle(t)
	cases := map[string]string{
		"/buildDefinition/resolvedDependencies/0/digest": "the chain needs /buildDefinition/resolvedDependencies",
		"/runDetails/byproducts":                         "the chain needs /runDetails/byproducts",
		"/hwFlow/tools/0/version":                        "the chain needs /hwFlow/tools",
		"/hwFlow/checks":                                 "the chain needs /hwFlow/checks",
		"/hwFlow/step":                                   "the chain needs /hwFlow/step",
		"/hwFlow/isolation":                              "the chain needs /hwFlow/isolation",
		"/buildDefinition/externalParameters":            "the record needs /buildDefinition/externalParameters",
	}
	for path, reason := range cases {
		t.Run(path, func(t *testing.T) {
			w := &Withholding{Fields: map[string][]string{"synthesis": {path}}}
			err := resignDesignStep(t, bundle, "synthesis", w)
			if err == nil || !strings.Contains(err.Error(), "cannot be withheld: "+reason) {
				t.Fatalf("got %v, want a refusal naming %q", err, reason)
			}
		})
	}
}

func TestDesignMetricsCanBeWithheld(t *testing.T) {
	// An OpenLane step record carries area, timing and power metrics.
	pred := normalize(Obj{
		"buildDefinition": Obj{"buildType": designStepType("place-and-route"), "externalParameters": Obj{"pdkRoot": "/opt/pdk/nda-node"}, "resolvedDependencies": []Obj{}},
		"runDetails":      Obj{"builder": Obj{"id": "urn:hslsa:builder:test"}, "byproducts": []Obj{}},
		"hwFlow":          Obj{"step": "place-and-route", "tools": []Obj{}, "checks": passed("step-completed"), "metrics": Obj{"design__instance__area": 1234.5}},
	}).(map[string]any)
	got, disclosures, err := withhold(pred, DesignFlow, []string{"/hwFlow/metrics", "/buildDefinition/externalParameters/pdkRoot"})
	must(t, err)
	if len(disclosures) != 2 || Has(O(got, "hwFlow"), "metrics") || len(A(got, "hwFlow", "confidential")) != 2 {
		t.Fatalf("withheld predicate %s", compactJSON(got))
	}
	env := filepath.Join(t.TempDir(), "att", "openlane-step.intoto.json")
	must(t, writeDisclosures(env, disclosures))
	stmt := normalize(ok(statement([]Obj{rd("picorv32.gds", strings.Repeat("c", 64))}, DesignFlow, got))).(map[string]any)
	revealed := ok(reveal(env, stmt))
	if !jsonEqual(get(revealed, "predicate", "hwFlow", "metrics"), Obj{"design__instance__area": 1234.5}) {
		t.Fatalf("revealed metrics %v", get(revealed, "predicate", "hwFlow", "metrics"))
	}
}
