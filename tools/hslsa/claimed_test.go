package hslsa

// Levels the HBOM claims (hbom.claimedLevels): the product owner's claim, which
// the receipt check holds to the levels it verified.

import (
	"path/filepath"
	"strings"
	"testing"
)

// resignHBOM is the product owner signing the HBOM again after mutate, with
// its renderings made again from it.
func resignHBOM(t *testing.T, bundle string, mutate func(p Obj)) {
	t.Helper()
	chipResign(t, bundle, "hbom.intoto.json", "product-owner", func(s Obj) {
		mutate(O(s, "predicate"))
		delete(O(s, "predicate"), "renderings")
		must(t, addRenderings(s, filepath.Join(bundle, "att"), "file:att/"))
	})
}

func setClaimedLevels(t *testing.T, bundle string, levels ...string) {
	t.Helper()
	resignHBOM(t, bundle, func(p Obj) { p["claimedLevels"] = anyStrings(levels) })
}

func TestHBOMClaimedLevelsVerifies(t *testing.T) {
	bundle := chipBundle(t)
	hb := ok(DecodeEnvelope(filepath.Join(bundle, "att", "hbom.intoto.json")))
	want := []string{"HSLSA_DESIGN_LEVEL_3", "HSLSA_WAFER_LEVEL_2", "HSLSA_PACKAGE_TEST_LEVEL_2"}
	if !equalStrings(Strs(hb, "predicate", "claimedLevels"), want) {
		t.Fatalf("the example HBOM claims %v, want %v from its scenario", Strs(hb, "predicate", "claimedLevels"), want)
	}
	units := ok(ReadUnits(e2eUnits))
	must(t, chipCheck(t, bundle, units))
	// Claiming less than the check verifies is allowed, and so is a claim in a
	// track the lot check does not cover, which it leaves to the check that does.
	setClaimedLevels(t, bundle, "HSLSA_WAFER_LEVEL_1", "HSLSA_FIRMWARE_LEVEL_2")
	_, lot, err := Verify(bundle, ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))), e2ePolicy, "", "", "")
	must(t, err)
	if !equalStrings(lot.ClaimsLeft, []string{"HSLSA_FIRMWARE_LEVEL_2"}) {
		t.Fatalf("claims left to another check: %v", lot.ClaimsLeft)
	}
	// An HBOM with no claimedLevels claims nothing, and passes as before.
	resignHBOM(t, bundle, func(p Obj) { delete(p, "claimedLevels") })
	must(t, chipCheck(t, bundle, units))
}

func TestHBOMClaimedLevelsRejects(t *testing.T) {
	cases := []struct {
		name   string
		levels []string
		reason string
	}{
		{"a level above the verified one", []string{"HSLSA_WAFER_LEVEL_3"},
			"hbom: the HBOM claims Wafer L3, but this check verified Wafer L2; an HBOM may not claim more than its checks verify"},
		{"a track claimed twice", []string{"HSLSA_WAFER_LEVEL_1", "HSLSA_WAFER_LEVEL_2"}, "claimedLevels"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bundle := chipBundle(t)
			setClaimedLevels(t, bundle, c.levels...)
			rejects(t, chipCheck(t, bundle, nil), c.reason)
		})
	}
	t.Run("a SLSA build level", func(t *testing.T) {
		// The renderer refuses to render it, so the HBOM is signed without new renderings; the schema check comes first.
		bundle := chipBundle(t)
		chipResign(t, bundle, "hbom.intoto.json", "product-owner", func(s Obj) {
			O(s, "predicate")["claimedLevels"] = []any{"SLSA_BUILD_LEVEL_3"}
		})
		rejects(t, chipCheck(t, bundle, nil), "HBOM does not match its schema at /claimedLevels/0")
	})
	t.Run("a level in a track the policy does not claim", func(t *testing.T) {
		bundle := chipBundle(t)
		policy := filepath.Join(t.TempDir(), "policy.json")
		editJSON(t, ok(copyTo(e2ePolicy, policy)), func(p Obj) {
			O(p, "claims")["lot"] = anyStrings([]string{"HSLSA_WAFER_LEVEL_2", "HSLSA_DESIGN_LEVEL_3"})
		})
		rejects(t, chipCheckPolicy(t, bundle, nil, policy), "the HBOM claims Package/Test L2, but this check verified no Package/Test level")
	})
}

func TestClaimedLevelsCheckRule(t *testing.T) {
	// The rule on its own, including what the schema would refuse first.
	hb := Obj{"predicate": Obj{"claimedLevels": []any{"HSLSA_DESIGN_LEVEL_3", "HSLSA_DESIGN_LEVEL_2"}}}
	_, err := claimedLevelsCheck(hb, []any{"HSLSA_DESIGN_LEVEL_3"}, lotTracks, "hbom")
	rejects(t, err, "hbom: claimedLevels claims the Design track twice")
	hb = Obj{"predicate": Obj{"claimedLevels": []any{"SLSA_BUILD_LEVEL_3"}}}
	_, err = claimedLevelsCheck(hb, nil, lotTracks, "hbom")
	rejects(t, err, "claimedLevels lists SLSA_BUILD_LEVEL_3, which is not an HSLSA track level")
	hb = Obj{"predicate": Obj{"claimedLevels": []any{"HSLSA_ASSEMBLY_LEVEL_2", "HSLSA_FIRMWARE_LEVEL_3"}}}
	left, err := claimedLevelsCheck(hb, []any{"HSLSA_ASSEMBLY_LEVEL_3", "HSLSA_FIRMWARE_LEVEL_3"}, fpgaTracks, "board hbom")
	must(t, err)
	if len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

func TestRenderingsCarryClaimedLevels(t *testing.T) {
	bundle := chipBundle(t)
	hb := ok(DecodeEnvelope(filepath.Join(bundle, "att", "hbom.intoto.json")))
	for _, format := range []string{FormatCycloneDX, FormatSPDX} {
		doc := string(ok(RenderHBOM(hb, format, "2026-10-07T00:00:00Z")))
		for _, c := range []string{"HSLSA_DESIGN_LEVEL_3", "HSLSA_WAFER_LEVEL_2", "HSLSA_PACKAGE_TEST_LEVEL_2"} {
			if !strings.Contains(doc, `"hbom:claimedLevel"`) || !strings.Contains(doc, `"`+c+`"`) {
				t.Fatalf("the %s rendering does not carry the claimed level %s", format, c)
			}
		}
	}
}
