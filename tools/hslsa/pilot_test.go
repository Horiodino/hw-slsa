package hslsa

// The pilot's buyer-run trust root (enrollments and revocations), its lot
// measurement, and mfg signed in turns by sites that each hold only their
// own keys.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type pilotWorld struct {
	dir, buyerKey, buyerPub, ent string
}

func newPilot(t *testing.T) *pilotWorld {
	t.Helper()
	dir := t.TempDir()
	ok(Keygen(filepath.Join(dir, "buyer"), BuyerRootRole))
	must(t, os.MkdirAll(filepath.Join(dir, "ent"), 0o755))
	return &pilotWorld{dir, filepath.Join(dir, "buyer", BuyerRootRole+".key.pem"), filepath.Join(dir, "buyer", BuyerRootRole+".pub.pem"), filepath.Join(dir, "ent")}
}

// site makes a key pair for role and returns its public key path.
func (p *pilotWorld) site(t *testing.T, role string) string {
	t.Helper()
	ok(Keygen(filepath.Join(p.dir, "sites"), role))
	return filepath.Join(p.dir, "sites", role+".pub.pem")
}

func testEnrollment(role string, from, until time.Time) Enrollment {
	return Enrollment{Role: role, OrgName: "Example OSAT Group", OrgID: "duns:100000003", Site: "Example OSAT",
		Custody: "hsm", NotBefore: from, NotAfter: until}
}

func (p *pilotWorld) enroll(t *testing.T, pub, file string, e Enrollment) {
	t.Helper()
	must(t, Enroll(p.buyerKey, pub, e, filepath.Join(p.ent, file)))
}

func (p *pilotWorld) build(at time.Time) (Obj, error) {
	return BuildPilotTrustRoot(p.buyerPub, p.ent, at, filepath.Join(p.dir, "trust-root.json"))
}

var (
	pilotNow  = time.Now().UTC()
	pilotFrom = pilotNow.Add(-24 * time.Hour)
	pilotTill = pilotNow.Add(90 * 24 * time.Hour)
)

func TestPilotTrustRootListsEnrolledKeys(t *testing.T) {
	p := newPilot(t)
	osat, test := p.site(t, "osat-site"), p.site(t, "test-site")
	p.enroll(t, osat, "osat.intoto.json", testEnrollment("osat-site", pilotFrom, pilotTill))
	short := pilotNow.Add(30 * 24 * time.Hour)
	p.enroll(t, test, "test.intoto.json", testEnrollment("test-site", pilotFrom, short))
	tr := ok(p.build(pilotNow))
	if len(Strs(tr, "roles", "osat-site")) != 1 || len(Strs(tr, "roles", "test-site")) != 1 {
		t.Fatalf("roles %v", O(tr, "roles"))
	}
	if S(tr, "validUntil") != short.Format(timeFormat) {
		t.Errorf("validUntil %s, want the earliest notAfter %s", S(tr, "validUntil"), short.Format(timeFormat))
	}
	trust := ok(LoadTrustRoot(filepath.Join(p.dir, "trust-root.json")))
	if want := ok(readPublicKey(osat)).ID; trust.Roles["osat-site"][0].ID != want {
		t.Error("trust root lists another key for osat-site")
	}
}

func TestPilotTrustRootExcludesRevokedExpiredAndFutureKeys(t *testing.T) {
	p := newPilot(t)
	kept, lost, old, next := p.site(t, "test-site"), p.site(t, "osat-site"), p.site(t, "sort-site"), p.site(t, "fab-site")
	p.enroll(t, kept, "kept.intoto.json", testEnrollment("test-site", pilotFrom, pilotTill))
	p.enroll(t, lost, "lost.intoto.json", testEnrollment("osat-site", pilotFrom, pilotTill))
	p.enroll(t, old, "old.intoto.json", testEnrollment("sort-site", pilotNow.Add(-90*24*time.Hour), pilotFrom))
	p.enroll(t, next, "next.intoto.json", testEnrollment("fab-site", pilotTill, pilotTill.Add(time.Hour)))
	must(t, Revoke(p.buyerKey, lost, "key reported lost", filepath.Join(p.ent, "revoke.intoto.json")))
	tr := ok(p.build(pilotNow))
	if roles := sortedKeys(O(tr, "roles")); !equalStrings(roles, []string{"test-site"}) {
		t.Fatalf("trusted roles %v, want only test-site", roles)
	}
	reasons := map[string]string{}
	for _, e := range Objs(tr, "excluded") {
		reasons[S(e, "role")] = S(e, "reason")
	}
	for role, want := range map[string]string{"osat-site": "revoked: key reported lost", "sort-site": "expired", "fab-site": "not valid until"} {
		if !strings.HasPrefix(reasons[role], want) {
			t.Errorf("%s excluded for %q, want %q", role, reasons[role], want)
		}
	}
	if _, err := p.build(pilotTill.Add(48 * time.Hour)); err == nil || !strings.Contains(err.Error(), "no enrolled key is valid") {
		t.Errorf("built a trust root with no valid key: %v", err)
	}
}

func TestPilotTrustRootRefusesARecordTheBuyerDidNotSign(t *testing.T) {
	p := newPilot(t)
	p.enroll(t, p.site(t, "test-site"), "test.intoto.json", testEnrollment("test-site", pilotFrom, pilotTill))
	ok(Keygen(filepath.Join(p.dir, "other"), BuyerRootRole))
	must(t, Enroll(filepath.Join(p.dir, "other", BuyerRootRole+".key.pem"), p.site(t, "osat-site"),
		testEnrollment("osat-site", pilotFrom, pilotTill), filepath.Join(p.ent, "osat.intoto.json")))
	_, err := p.build(pilotNow)
	rejects(t, err, "osat.intoto.json: no valid signature from role 'buyer-root'")
}

func TestPilotTrustRootRefusesAKeyItsSubjectDoesNotName(t *testing.T) {
	// The buyer signed it, but the key it carries is not the key it names.
	p := newPilot(t)
	p.enroll(t, p.site(t, "test-site"), "test.intoto.json", testEnrollment("test-site", pilotFrom, pilotTill))
	other := ok(readPublicKey(p.site(t, "osat-site")))
	resign(t, filepath.Join(p.ent, "test.intoto.json"), filepath.Join(p.dir, "buyer"), BuyerRootRole, func(s Obj) {
		O(s, "predicate")["publicKey"] = other.PEM
	})
	_, err := p.build(pilotNow)
	rejects(t, err, "subject does not name the key it carries")
}

func TestPilotTrustRootRefusesOneKeyForTwoRolesOrCompanies(t *testing.T) {
	p := newPilot(t)
	key := p.site(t, "osat-site")
	p.enroll(t, key, "a.intoto.json", testEnrollment("osat-site", pilotFrom, pilotTill))
	p.enroll(t, key, "b.intoto.json", testEnrollment("test-site", pilotFrom, pilotTill))
	_, err := p.build(pilotNow)
	rejects(t, err, "is enrolled for both osat-site and test-site")

	must(t, os.Remove(filepath.Join(p.ent, "b.intoto.json")))
	e := testEnrollment("osat-site", pilotFrom, pilotTill)
	e.OrgID = "duns:100000009"
	p.enroll(t, key, "b.intoto.json", e)
	_, err = p.build(pilotNow)
	rejects(t, err, "is enrolled for two companies")
}

func TestPilotTrustRootRefusesOtherRecords(t *testing.T) {
	p := newPilot(t)
	p.enroll(t, p.site(t, "test-site"), "test.intoto.json", testEnrollment("test-site", pilotFrom, pilotTill))
	resign(t, filepath.Join(p.ent, "test.intoto.json"), filepath.Join(p.dir, "buyer"), BuyerRootRole, func(s Obj) {
		s["predicateType"] = MfgStep
	})
	_, err := p.build(pilotNow)
	rejects(t, err, "not an enrollment or a revocation")
}

func TestEnrollRefusesIncompleteEnrollments(t *testing.T) {
	p := newPilot(t)
	pub := p.site(t, "osat-site")
	for name, tc := range map[string]struct {
		edit func(*Enrollment)
		want string
	}{
		"org id":       {func(e *Enrollment) { e.OrgID = "acme" }, "is not lei:"},
		"custody":      {func(e *Enrollment) { e.Custody = "laptop" }, "key custody"},
		"dates":        {func(e *Enrollment) { e.NotAfter = e.NotBefore }, "ends before it starts"},
		"role":         {func(e *Enrollment) { e.Role = BuyerRootRole }, "needs a role"},
		"site":         {func(e *Enrollment) { e.Site = "" }, "name the company and the site"},
		"root as site": {nil, "cannot be enrolled as a site key"},
	} {
		t.Run(name, func(t *testing.T) {
			e, key := testEnrollment("osat-site", pilotFrom, pilotTill), pub
			if tc.edit != nil {
				tc.edit(&e)
			} else {
				key = p.buyerPub
			}
			err := Enroll(p.buyerKey, key, e, filepath.Join(t.TempDir(), "e.intoto.json"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestExpiredTrustRootIsRefused(t *testing.T) {
	p := newPilot(t)
	p.enroll(t, p.site(t, "test-site"), "test.intoto.json", testEnrollment("test-site", pilotNow.Add(-48*time.Hour), pilotFrom))
	ok(p.build(pilotNow.Add(-36 * time.Hour)))
	_, err := LoadTrustRoot(filepath.Join(p.dir, "trust-root.json"))
	rejects(t, err, "trust root expired")
}

func TestReadCosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "costs.json")
	must(t, os.WriteFile(path, []byte(`{"entries": [
		{"party": "OSAT", "hours": 2.5, "amount": 300, "currency": "USD"},
		{"party": "Vendor", "hours": 1},
		{"party": "Buyer", "amount": 50, "currency": "USD"}]}`), 0o644))
	c := ok(readCosts(path))
	if h, _ := floatOf(get(c, "total", "hours")); h != 3.5 {
		t.Errorf("hours %v, want 3.5", get(c, "total", "hours"))
	}
	if a, _ := floatOf(get(c, "total", "amount", "USD")); a != 350 {
		t.Errorf("amount %v, want 350 USD", get(c, "total", "amount"))
	}
	for _, bad := range []string{`{"entries": [{"hours": 1}]}`, `{"entries": [{"party": "X", "amount": 5}]}`, `{"entries": [{"party": "X", "hours": -1}]}`} {
		must(t, os.WriteFile(path, []byte(bad), 0o644))
		if _, err := readCosts(path); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// Sites signing in turns

// turnKeys copies the named roles' keys from the chip keys into their own directory.
func turnKeys(t *testing.T, bundle string, roles ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, r := range roles {
		must(t, copyFile(filepath.Join(chipKeys(bundle), r+".key.pem"), filepath.Join(dir, r+".key.pem")))
	}
	return dir
}

func clearLot(t *testing.T, bundle string) {
	t.Helper()
	files := ok(filepath.Glob(filepath.Join(bundle, "att", "mfg-*.intoto.json")))
	for _, f := range files {
		must(t, os.Remove(f))
	}
}

func TestMfgSignedInTurnsVerifies(t *testing.T) {
	bundle := chipBundle(t)
	clearLot(t, bundle)
	fab := turnKeys(t, bundle, "fab-site", "sort-site")
	must(t, MfgAs(bundle, e2eScenario, fab, nil, []string{"fab-site", "sort-site"}))
	if _, err := os.Stat(filepath.Join(bundle, "att", MfgAtt["packaging"])); err == nil {
		t.Fatal("the first turn signed packaging without the OSAT's key")
	}
	f2 := ok(sha256File(filepath.Join(bundle, "att", MfgAtt["wafer-sort"])))
	osat := turnKeys(t, bundle, "osat-site", "test-site")
	must(t, MfgAs(bundle, e2eScenario, osat, nil, []string{"osat-site", "test-site"}))
	if ok(sha256File(filepath.Join(bundle, "att", MfgAtt["wafer-sort"]))) != f2 {
		t.Error("the second turn re-signed the sort record")
	}
	must(t, BuildHBOM(bundle, e2eLock, e2eScenario, filepath.Join(chipKeys(bundle), "product-owner.key.pem"), nil))
	must(t, chipCheck(t, bundle, nil))
}

func TestMfgTurnRefusesARecordFromAnotherScenario(t *testing.T) {
	bundle := chipBundle(t)
	clearLot(t, bundle)
	must(t, MfgAs(bundle, e2eScenario, turnKeys(t, bundle, "fab-site", "sort-site"), nil, []string{"fab-site", "sort-site"}))
	chipResign(t, bundle, MfgAtt["wafer-sort"], "sort-site", func(s Obj) {
		Objs(s, "subject")[0]["digest"] = Obj{"sha256": strings.Repeat("0", 64)}
	})
	err := MfgAs(bundle, e2eScenario, turnKeys(t, bundle, "osat-site", "test-site"), nil, []string{"osat-site", "test-site"})
	if err == nil || !strings.Contains(err.Error(), "names other subjects") {
		t.Fatalf("got %v, want a refusal of the changed sort record", err)
	}
}

func TestMfgTurnCannotWithhold(t *testing.T) {
	err := MfgAs(t.TempDir(), e2eScenario, t.TempDir(), &Withholding{Fields: map[string][]string{"wafer-fab": {"/predicate/hwMfg/yield"}}}, []string{"fab-site"})
	if err == nil || !strings.Contains(err.Error(), "cannot withhold") {
		t.Fatalf("got %v", err)
	}
}

func TestPilotMeasureRecordsWhoSignedAndAFailure(t *testing.T) {
	bundle := chipBundle(t)
	p := newPilot(t)
	for _, role := range []string{"ip-vendor", "flow-platform", "tapeout-authority", "product-owner", "source-owner", "source-reviewer", "fab-site", "sort-site", "osat-site", "test-site"} {
		e := testEnrollment(role, pilotFrom, pilotTill)
		e.Site = map[string]string{"fab-site": "Example Wafer Fab", "sort-site": "Example Sort House", "test-site": "Example Test House"}[role]
		if e.Site == "" {
			e.Site = "Example OSAT"
		}
		p.enroll(t, filepath.Join(filepath.Dir(bundle), "pub", role+".pub.pem"), role+".intoto.json", e)
	}
	ok(p.build(pilotNow))
	trust := filepath.Join(p.dir, "trust-root.json")
	rep := ok(PilotMeasure(bundle, trust, e2ePolicy, "", ""))
	if S(rep, "check", "result") != "pass" {
		t.Fatalf("check %v", O(rep, "check"))
	}
	if len(Objs(rep, "parties")) != 1 || S(Objs(rep, "parties")[0], "organization", "id") != "duns:100000003" {
		t.Errorf("parties %v", Objs(rep, "parties"))
	}
	if Objs(rep, "siteMismatches") != nil {
		t.Errorf("site mismatches %v", Objs(rep, "siteMismatches"))
	}
	// A test record whose site differs from the key's enrollment is reported.
	chipResign(t, bundle, MfgAtt["final-test"], "test-site", func(s Obj) {
		O(s, "predicate", "hwMfg", "site")["name"] = "Another Test House"
	})
	rep = ok(PilotMeasure(bundle, trust, e2ePolicy, "", ""))
	m := Objs(rep, "siteMismatches")
	if len(m) != 1 || S(m[0], "names") != "Another Test House" {
		t.Errorf("site mismatches %v", m)
	}
	// A failed check is a result, not an error.
	must(t, os.Remove(filepath.Join(bundle, "att", MfgAtt["packaging"])))
	rep = ok(PilotMeasure(bundle, trust, e2ePolicy, "", ""))
	if S(rep, "check", "result") != "fail" || !strings.Contains(S(rep, "check", "failure"), "packaging") {
		t.Errorf("check %v", O(rep, "check"))
	}
	if !strings.Contains(PilotMeasurementMarkdown(rep), "Failed check") {
		t.Error("report does not show the failed check")
	}
}
