package hslsa

// Withheld fields and their disclosures, on records built in the test: no bundle needed.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// finalTestPredicate is a final test record's predicate with values worth hiding.
func finalTestPredicate() Obj {
	return normalize(Obj{
		"buildDefinition": Obj{
			"buildType":            mfgStepType("final-test"),
			"externalParameters":   Obj{"lotId": "LOT-1", "testProgram": Obj{"name": "ft", "version": "1.2.0"}},
			"resolvedDependencies": []Obj{rd("att/mfg-f3-packaging.intoto.json", strings.Repeat("a", 64))},
		},
		"runDetails": Obj{"builder": Obj{"id": "urn:hslsa:site:test-house"}, "metadata": Obj{"finishedOn": "2026-09-30T00:00:00Z"}},
		"hwMfg": Obj{
			"step":         "final-test",
			"confidential": []any{},
			"yield":        Obj{"in": 40, "passed": 37, "failed": []any{"U7", "U19", "U33"}},
			"checks":       passed("final-test-per-unit"),
		},
	}).(map[string]any)
}

// withheldRecord withholds paths from a final test predicate and stores the
// disclosures where reveal looks for them. It returns the envelope path and
// the statement as signed.
func withheldRecord(t *testing.T, paths ...string) (string, Obj) {
	t.Helper()
	pred, disclosures, err := withhold(finalTestPredicate(), MfgStep, paths)
	must(t, err)
	env := filepath.Join(t.TempDir(), "att", "mfg-f4-final-test.intoto.json")
	must(t, writeDisclosures(env, disclosures))
	stmt := ok(statement([]Obj{rd("urn:hslsa:lot:LOT-1", strings.Repeat("b", 64))}, MfgStep, pred))
	return env, normalize(stmt).(map[string]any)
}

// disclosureFor builds a disclosure as a producer would, with any salt.
func disclosureFor(salt, path string, value any) string {
	return base64.RawURLEncoding.EncodeToString(compactJSON([]any{salt, path, normalize(value)}))
}

func TestWithholdAndReveal(t *testing.T) {
	env, stmt := withheldRecord(t, "/hwMfg/yield", "/buildDefinition/externalParameters/testProgram")
	if Has(O(stmt, "predicate", "hwMfg"), "yield") || Has(O(stmt, "predicate", "buildDefinition", "externalParameters"), "testProgram") {
		t.Fatal("withheld fields are still in the record")
	}
	entries := Withheld(stmt)
	if len(entries) != 2 || S(entries[0], "path") != "/hwMfg/yield" || len(S(entries[0], "saltedDigest", "sha256")) != 64 {
		t.Fatalf("withheld list %v", entries)
	}
	got := ok(reveal(env, stmt))
	want := finalTestPredicate()
	O(want, "hwMfg")["confidential"] = A(stmt, "predicate", "hwMfg", "confidential")
	if !jsonEqual(get(got, "predicate"), want) {
		t.Fatalf("revealed predicate differs from the original:\n%s\n%s", compactJSON(get(got, "predicate")), compactJSON(want))
	}
}

func TestSaltsAreFreshPerField(t *testing.T) {
	_, a := withheldRecord(t, "/hwMfg/yield")
	_, b := withheldRecord(t, "/hwMfg/yield")
	if S(Withheld(a)[0], "saltedDigest", "sha256") == S(Withheld(b)[0], "saltedDigest", "sha256") {
		t.Fatal("the same value withheld twice has the same salted digest")
	}
}

func TestRecordThatWithholdsNothingNeedsNoDisclosure(t *testing.T) {
	stmt := ok(statement([]Obj{rd("urn:hslsa:lot:LOT-1", strings.Repeat("b", 64))}, MfgStep, finalTestPredicate()))
	if _, err := reveal(filepath.Join(t.TempDir(), "att", "x.intoto.json"), stmt); err != nil {
		t.Fatal(err)
	}
}

func TestWithholdRefuses(t *testing.T) {
	for _, c := range []struct {
		paths  []string
		reason string
	}{
		{[]string{"/hwMfg/checks"}, "the chain needs /hwMfg/checks"},
		{[]string{"/hwMfg/designRef/digest"}, "the chain needs /hwMfg/designRef"},
		{[]string{"/buildDefinition/resolvedDependencies/0"}, "the chain needs /buildDefinition/resolvedDependencies"},
		{[]string{"/runDetails"}, "the chain needs /runDetails/builder"},
		{[]string{"/hwMfg"}, "it is the list of withheld fields"},
		{[]string{"/hwMfg/confidential"}, "it is the list of withheld fields"},
		{[]string{"/buildDefinition/externalParameters"}, "the record needs /buildDefinition/externalParameters"},
		{[]string{"/hwMfg/yield", "/hwMfg/yield/in"}, "overlaps"},
		{[]string{"/hwMfg/yield", "/hwMfg/yield"}, "overlaps"},
		{[]string{"hwMfg/yield"}, "does not start with /"},
		{[]string{"/hwMfg/"}, "empty token"},
		{[]string{"/hwMfg/nothing"}, `no member "nothing"`},
		{[]string{"/hwMfg/yield/failed/0"}, "must name an object member"},
		{[]string{"/hwMfg/checks/x/name"}, "the chain needs"},
	} {
		t.Run(strings.Join(c.paths, ","), func(t *testing.T) {
			_, _, err := withhold(finalTestPredicate(), MfgStep, c.paths)
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("got %v, want %q", err, c.reason)
			}
		})
	}
	if _, _, err := withhold(Obj{"hbomVersion": "0.1", "product": Obj{"level": "die"}}, HBOMType, []string{"/product/level"}); err == nil ||
		!strings.Contains(err.Error(), "the chain needs /product") {
		t.Fatalf("HBOM product.level withheld: %v", err)
	}
	if _, _, err := withhold(Obj{}, VSAType, []string{"/x"}); err == nil {
		t.Fatal("withheld a field from a predicate type with no list")
	}
}

// Each case starts from a record withholding the yield and the test program
// and breaks one thing a producer or a middleman could get wrong or forge.
func TestRevealRejects(t *testing.T) {
	yield := Obj{"in": 40, "passed": 37, "failed": []any{"U7", "U19", "U33"}}
	salt := ok(newSalt())
	for _, c := range []struct {
		name   string
		break_ func(env string, stmt Obj)
		reason string
	}{
		{"no disclosures", func(env string, _ Obj) { must(t, os.Remove(disclosurePath(env))) },
			"/buildDefinition/externalParameters/testProgram is withheld and no disclosure was given"},
		{"one disclosure missing", func(env string, _ Obj) {
			editJSON(t, disclosurePath(env), func(f Obj) { f["disclosures"] = A(f, "disclosures")[:1] })
		}, "/hwMfg/yield is withheld and no disclosure was given"},
		{"a value changed after signing", func(env string, _ Obj) {
			editJSON(t, disclosurePath(env), func(f Obj) {
				A(f, "disclosures")[1] = disclosureFor(salt, "/hwMfg/yield", Obj{"in": 40, "passed": 38, "failed": []any{"U7", "U19"}})
			})
		}, "a disclosure matches no withheld field"},
		{"a disclosure from another record", func(env string, _ Obj) {
			other, _ := withheldRecord(t, "/hwMfg/yield")
			must(t, copyFile(disclosurePath(other), disclosurePath(env)))
		}, "a disclosure matches no withheld field"},
		{"a salt shorter than 128 bits", func(env string, stmt Obj) {
			d := disclosureFor(base64.RawURLEncoding.EncodeToString([]byte("8 bytes!")), "/hwMfg/yield", yield)
			Withheld(stmt)[1]["saltedDigest"] = Obj{"sha256": sha256Bytes([]byte(d))}
			editJSON(t, disclosurePath(env), func(f Obj) { A(f, "disclosures")[1] = d })
		}, "a salt shorter than 128 bits"},
		{"a disclosure for another path", func(env string, stmt Obj) {
			d := disclosureFor(salt, "/hwMfg/notYield", yield)
			Withheld(stmt)[1]["saltedDigest"] = Obj{"sha256": sha256Bytes([]byte(d))}
			editJSON(t, disclosurePath(env), func(f Obj) { A(f, "disclosures")[1] = d })
		}, "disclosure for /hwMfg/notYield is listed as /hwMfg/yield"},
		{"a field both withheld and present", func(_ string, stmt Obj) {
			O(stmt, "predicate", "hwMfg")["yield"] = yield
		}, "/hwMfg/yield is both withheld and present"},
		{"two entries with one digest", func(_ string, stmt Obj) {
			Withheld(stmt)[1]["saltedDigest"] = Withheld(stmt)[0]["saltedDigest"]
		}, "two withheld fields share a salted digest"},
		{"a protected field listed as withheld", func(_ string, stmt Obj) {
			Withheld(stmt)[1]["path"] = "/hwMfg/checks"
		}, "/hwMfg/checks cannot be withheld"},
		{"a disclosure that is not base64url", func(env string, stmt Obj) {
			Withheld(stmt)[1]["saltedDigest"] = Obj{"sha256": sha256Bytes([]byte("not base64!"))}
			editJSON(t, disclosurePath(env), func(f Obj) { A(f, "disclosures")[1] = "not base64!" })
		}, "disclosure for /hwMfg/yield is not base64url"},
	} {
		t.Run(c.name, func(t *testing.T) {
			env, stmt := withheldRecord(t, "/buildDefinition/externalParameters/testProgram", "/hwMfg/yield")
			c.break_(env, stmt)
			_, err := reveal(env, stmt)
			rejects(t, err, c.reason)
		})
	}
}

func TestLoadWithholding(t *testing.T) {
	w := ok(LoadWithholding(filepath.Join(root, "e2e", "picorv32", "withhold.json")))
	if len(w.fields("final-test")) == 0 || !w.salts("genealogy.json") || w.salts("shipped-lot.txt") {
		t.Fatalf("withholding %+v", w)
	}
	var none *Withholding
	if none.fields("final-test") != nil || none.salts("genealogy.json") {
		t.Fatal("a nil withholding withholds something")
	}
	// Every path in the example must be one a producer may withhold.
	for record, paths := range w.Fields {
		pt := MfgStep
		if record == "hbom" {
			pt = HBOMType
		} else if !contains(MfgSteps, record) {
			t.Fatalf("withhold.json names %s, which is not a record the example signs", record)
		}
		if _, err := checkPaths(pt, paths); err != nil {
			t.Fatalf("%s: %v", record, err)
		}
	}
}
