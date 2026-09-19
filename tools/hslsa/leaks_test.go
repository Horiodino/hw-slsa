package hslsa

// The leak measurement on data built in the test: no bundle needed.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func serials(prefix string, from, to int, skip ...int) []string {
	var out []string
	for i := from; i <= to; i++ {
		if !containsInt(skip, i) {
			out = append(out, fmt.Sprintf("%s%05d", prefix, i))
		}
	}
	return out
}

func containsInt(list []int, x int) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func TestInvertLotRecoversSequentialSerials(t *testing.T) {
	shipped := serials("U-", 1, 40, 7, 19, 33)
	units, missing, guesses, reason := invertLot(ok(LotDigest(shipped)), []string{"U-00001", "U-00020", "U-00040"}, DefaultLeakLimits)
	if reason != "" || !equalStrings(units, shipped) || !equalStrings(missing, []string{"U-00007", "U-00019", "U-00033"}) {
		t.Fatalf("got %d units, missing %v, reason %q", len(units), missing, reason)
	}
	if guesses > 10000 {
		t.Fatalf("took %d guesses", guesses)
	}
	// A lot with no scrap is the first guess once the buyer holds its last serial.
	if _, _, guesses, _ := invertLot(ok(LotDigest(serials("U-", 1, 40))), []string{"U-00040"}, DefaultLeakLimits); guesses != 1 {
		t.Fatalf("full lot took %d guesses", guesses)
	}
}

func TestInvertLotLimits(t *testing.T) {
	// More scrap than the search allows: not found, and the report says how far it looked.
	_, _, _, reason := invertLot(ok(LotDigest(serials("U-", 1, 12, 2, 3, 4, 5))), []string{"U-00001"}, LeakLimits{MaxUnits: 20, MaxMissing: 3})
	if !strings.HasPrefix(reason, "not found in") {
		t.Fatalf("reason %q", reason)
	}
	// Identities that are certificate digests share no serial format.
	certs := []string{sha256Bytes([]byte("a")), sha256Bytes([]byte("b"))}
	if _, _, _, reason := invertLot(ok(LotDigest(certs)), certs, DefaultLeakLimits); reason != "the units held share no serial format" {
		t.Fatalf("reason %q", reason)
	}
}

func TestCombinations(t *testing.T) {
	calls := 0
	if _, hit := combinations(5, 2, func([]int) bool { calls++; return false }); hit || calls != 10 {
		t.Fatalf("C(5,2): %d calls, hit %v", calls, hit)
	}
	pick, hit := combinations(5, 0, func(p []int) bool { return len(p) == 0 })
	if !hit || len(pick) != 0 {
		t.Fatal("the empty subset is a subset")
	}
	pick, hit = combinations(4, 2, func(p []int) bool { return p[0] == 1 && p[1] == 3 })
	if !hit || pick[0] != 1 || pick[1] != 3 {
		t.Fatalf("pick %v", pick)
	}
}

// A value withheld in one record but shown in another is not hidden, and a
// site name withheld from hwMfg.site still shows in its builder id.
func TestLeaksFindsWithheldValuesShownElsewhere(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle")
	signer := ok(Keygen(filepath.Join(dir, "keys"), "site"))
	pred := finalTestPredicate()
	O(pred, "buildDefinition", "externalParameters")["maskSetId"] = "MS-SECRET-7"
	O(pred, "hwMfg")["site"] = Obj{"name": "Hidden Fab Co", "country": "US"}
	O(pred, "runDetails", "builder")["id"] = "urn:hslsa:site:hidden-fab-co"
	pred, disclosures, err := withhold(pred, MfgStep, []string{"/buildDefinition/externalParameters/maskSetId", "/hwMfg/site"})
	must(t, err)
	env := filepath.Join(bundle, "att", "mfg-f1-wafer-fab.intoto.json")
	ok(Sign(ok(statement([]Obj{rd("urn:hslsa:wafer-lot:fab:L1", strings.Repeat("c", 64))}, MfgStep, pred)), signer, env))
	must(t, writeDisclosures(env, disclosures))
	other := Obj{"hbomVersion": "0.1", "manufacturing": Obj{"fab": Obj{"maskSetId": "MS-SECRET-7"}}}
	ok(Sign(ok(statement([]Obj{rd("gds", strings.Repeat("d", 64))}, HBOMType, other)), signer, filepath.Join(bundle, "att", "hbom.intoto.json")))

	rep := ok(Leaks(bundle, nil, "", DefaultLeakLimits))
	exposed := Objs(rep, "records", "exposed")
	if len(exposed) != 2 {
		t.Fatalf("exposed %v", exposed)
	}
	for _, want := range []struct{ path, seen string }{
		{"/buildDefinition/externalParameters/maskSetId", "hbom.intoto.json /predicate/manufacturing/fab/maskSetId"},
		{"/hwMfg/site", "mfg-f1-wafer-fab.intoto.json /predicate/runDetails/builder/id"},
	} {
		e := find(exposed, "path", want.path)
		if e == nil || !contains(Strs(e, "seenIn"), want.seen) {
			t.Fatalf("%s not reported as shown in %s: %v", want.path, want.seen, exposed)
		}
	}
	md := LeaksMarkdown(rep)
	if !strings.Contains(md, "Withheld values shown elsewhere") || !strings.Contains(md, "not attempted: a buyer holds no wafer ids") {
		t.Fatalf("markdown:\n%s", md)
	}
}
