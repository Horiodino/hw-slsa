package hslsa

// Tamper tests for Wafer L3 and Package/Test L3. The fixture is the PicoRV32
// lot made again from e2e/picorv32/l3: a buyer-run trust root that enrolls
// each site key as held in an HSM at an accredited site, the fab's check of
// the release, die identities provisioned at sort, every unit challenged at
// final test, and three parts the buyer received. Each test forges what a
// compromised site could sign, re-links the chain after it, and checks that
// the L3 rules still refuse the lot for the right reason.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	l3Dir      = filepath.Join(e2eDir, "l3")
	l3Scenario = filepath.Join(l3Dir, "mfg-scenario.json")
	l3Policy   = filepath.Join(l3Dir, "policy.json")
)

// l3Org is the company and accreditation each role is enrolled with.
var l3Org = map[string][3]string{
	"fab-site":  {"Example Foundry", "duns:100000011", "dmea-trusted-supplier"},
	"sort-site": {"Example Sort Services", "duns:100000012", "iso-iec-20243"},
	"osat-site": {"Example OSAT Group", "duns:100000013", "dmea-trusted-supplier"},
	"test-site": {"Example Test Services", "duns:100000014", "iso-iec-20243"},
}

// enrollL3 enrolls every role's key in keys: sites and the identity CA with
// custody (hsm unless overridden), each site with its accreditation.
func enrollL3(keys, dir string, custody map[string]string, org map[string][3]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, role := range append(append([]string{}, e2eRoles...), IdentityCARole) {
		e := Enrollment{Role: role, OrgName: "Example Open Silicon Group", OrgID: "duns:100000002", Site: "Example Design Center",
			Custody: "file", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
		if o, ok := org[role]; ok {
			e.OrgName, e.OrgID, e.Site, e.Custody = o[0], o[1], o[0]+" site", "hsm"
			if o[2] != "" {
				e.Accreditation = Accreditation{Scheme: o[2], ID: strings.ToUpper(role) + "-1"}
			}
		}
		if role == IdentityCARole {
			e.Custody = "hsm"
		}
		if c, ok := custody[role]; ok {
			e.Custody = c
		}
		if err := Enroll(filepath.Join(keys, "buyer-root.key.pem"), filepath.Join(keys, role+".pub.pem"), e, filepath.Join(dir, role+".intoto.json")); err != nil {
			return err
		}
	}
	return nil
}

func l3TrustRoot(keys, bundle, name string, custody map[string]string, org map[string][3]string) (string, error) {
	dir := filepath.Join(filepath.Dir(bundle), name)
	if err := enrollL3(keys, dir, custody, org); err != nil {
		return "", err
	}
	out := filepath.Join(filepath.Dir(bundle), name+".json")
	_, err := BuildPilotTrustRoot(filepath.Join(keys, "buyer-root.pub.pem"), dir, time.Now(), out)
	return out, err
}

// chipL3Bundle is a fresh copy of the L3 lot; its parts are in ../parts and
// the three the buyer received in ../received.
func chipL3Bundle(t *testing.T) string {
	t.Helper()
	base := chipBundle(t)
	valid := shared(t, "chip-l3", func(work string) error {
		if err := copyTree(filepath.Dir(base), work); err != nil {
			return err
		}
		bundle, keys := filepath.Join(work, "bundle"), filepath.Join(work, "keys")
		for _, role := range []string{IdentityCARole, "buyer-root"} {
			if _, err := Keygen(keys, role); err != nil {
				return err
			}
		}
		tr, err := l3TrustRoot(keys, bundle, "enrollments", nil, l3Org)
		if err != nil {
			return err
		}
		if err := copyFile(tr, filepath.Join(bundle, "trust-root.json")); err != nil {
			return err
		}
		trust, err := LoadTrustRoot(tr)
		if err != nil {
			return err
		}
		if err := FabReleaseCheck(bundle, trust, e2ePolicy, filepath.Join(keys, "fab-site.key.pem")); err != nil {
			return err
		}
		if err := MfgWith(bundle, l3Scenario, keys, nil, nil, filepath.Join(work, "parts")); err != nil {
			return err
		}
		if err := BuildHBOM(bundle, e2eLock, l3Scenario, filepath.Join(keys, "product-owner.key.pem"), nil); err != nil {
			return err
		}
		for _, serial := range ok(ReadUnits(filepath.Join(e2eDir, "received-units.txt"))) {
			if err := copyTree(filepath.Join(work, "parts", serial), filepath.Join(work, "received", serial)); err != nil {
				return err
			}
		}
		return nil
	})
	return filepath.Join(copyOf(t, valid), "bundle")
}

func received(bundle string) string { return filepath.Join(filepath.Dir(bundle), "received") }

// l3Check runs the tapeout and lot receipt checks under the bundle's
// buyer-run trust root, challenging the parts in parts when it is set.
func l3Check(t *testing.T, bundle, trustPath string, policy Obj, parts string) error {
	t.Helper()
	trust := ok(LoadTrustRoot(trustPath))
	design, err := TapeoutCheck(bundle, trust, policy, true)
	if err != nil {
		return err
	}
	var units []string
	if parts != "" {
		if units, err = ChallengeParts(trust, parts); err != nil {
			return err
		}
	}
	_, err = lotCheck(bundle, trust, policy, design, units, parts != "")
	return err
}

func l3Default(t *testing.T, bundle string) error {
	t.Helper()
	return l3Check(t, bundle, filepath.Join(bundle, "trust-root.json"), ok(ReadObj(l3Policy)), received(bundle))
}

// chainOrder is every lot record after the design release, in chain order,
// with the role that signs it.
var chainOrder = [][2]string{
	{MfgAtt["wafer-fab"], "fab-site"}, {TransferAtt("wafer-fab"), "fab-site"},
	{MfgAtt["wafer-sort"], "sort-site"}, {TransferAtt("wafer-sort"), "sort-site"},
	{MfgAtt["packaging"], "osat-site"}, {TransferAtt("packaging"), "osat-site"},
	{MfgAtt["final-test"], "test-site"}, {"hbom.intoto.json", "product-owner"},
}

// forge re-signs one lot record after mutate, with every reference in it to
// a bundle file brought up to the file's digest, then re-signs every record
// after it in the chain with its links brought up to date, as a site that
// controls its own key and the next sites' cooperation could.
func forge(t *testing.T, bundle, name string, mutate func(Obj)) {
	t.Helper()
	keys := chipKeys(bundle)
	started := false
	for _, r := range chainOrder {
		started = started || r[0] == name
		path := filepath.Join(bundle, "att", r[0])
		if !started || !fileExists(path) {
			continue
		}
		stmt := ok(DecodeEnvelope(path))
		if r[0] == name && mutate != nil {
			mutate(stmt)
		}
		refresh(bundle, stmt)
		ok(Sign(stmt, ok(LoadSigner(filepath.Join(keys, r[1]+".key.pem"))), path))
	}
}

// refresh sets the digest of every reference in v to a file in the bundle
// (att/<name>, or a name in artifacts/) to that file's current digest.
func refresh(bundle string, v any) {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			refresh(bundle, e)
		}
	case map[string]any:
		ref := strings.TrimPrefix(S(x, "uri"), "file:")
		if ref == "" {
			ref = S(x, "name")
		}
		if d, isObj := x["digest"].(map[string]any); isObj && ref != "" && d["sha256"] != nil {
			for _, p := range []string{filepath.Join(bundle, ref), filepath.Join(bundle, "artifacts", ref)} {
				if info, err := os.Stat(p); err == nil && !info.IsDir() {
					d["sha256"] = ok(sha256File(p))
					break
				}
			}
		}
		for _, e := range x {
			refresh(bundle, e)
		}
	}
}

func TestL3LotPasses(t *testing.T) {
	bundle := chipL3Bundle(t)
	must(t, l3Default(t, bundle))
	// Every unit is named by its certificate digest, and the lot answers for it.
	for _, u := range ok(ReadUnits(filepath.Join(bundle, "artifacts", "shipped-lot.txt"))) {
		if len(u) != 64 {
			t.Fatalf("shipped unit %q is not a certificate digest", u)
		}
	}
}

func TestL3TamperRejects(t *testing.T) {
	cases := map[string]struct {
		edit   func(t *testing.T, bundle string)
		reason string
	}{
		"fab-skips-the-release-check": {func(t *testing.T, b string) {
			forge(t, b, MfgAtt["wafer-fab"], func(s Obj) {
				deps := Objs(s, "predicate", "buildDefinition", "resolvedDependencies")
				O(s, "predicate", "buildDefinition")["resolvedDependencies"] = anyObjs(deps[:1])
			})
		}, "the record does not consume the fab's check of the design release"},
		"release-check-after-the-wafers": {func(t *testing.T, b string) {
			resign(t, filepath.Join(b, "att", FabReleaseCheckAtt), chipKeys(b), "fab-site", func(s Obj) {
				O(s, "predicate")["timeVerified"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			})
			forge(t, b, MfgAtt["wafer-fab"], nil)
		}, "the fab's release check is not dated before the wafer lot"},
		"release-check-of-another-design": {func(t *testing.T, b string) {
			resign(t, filepath.Join(b, "att", FabReleaseCheckAtt), chipKeys(b), "fab-site", func(s Obj) {
				O(Objs(s, "subject")[0], "digest")["sha256"] = strings.Repeat("1", 64)
			})
			forge(t, b, MfgAtt["wafer-fab"], nil)
		}, "the fab's release check did not pass for the released design"},
		"xor-against-another-gds": {func(t *testing.T, b string) {
			forge(t, b, MfgAtt["wafer-fab"], func(s Obj) {
				c := find(Objs(s, "predicate", "hwMfg", "checks"), "name", "mask-vs-gds-xor")
				c["against"] = Obj{"name": "other.gds", "digest": Obj{"sha256": strings.Repeat("2", 64)}}
			})
		}, "the mask-vs-GDS XOR did not pass against the released design"},
		"passing-die-without-identity": {func(t *testing.T, b string) {
			editJSON(t, filepath.Join(b, "artifacts", DieIdentities), func(d Obj) { d["dies"] = A(d, "dies")[1:] })
			forge(t, b, MfgAtt["wafer-sort"], nil)
		}, "has no identity"},
		"identity-from-an-unlisted-ca": {func(t *testing.T, b string) {
			ids := ok(ReadObj(filepath.Join(b, "artifacts", DieIdentities)))
			e := Objs(ids, "dies")[0]
			die := ok(newDie("x"))
			ca := &identityCA{signer: ok(LoadSigner(filepath.Join(chipKeys(b), "attacker.key.pem"))), name: ok(utf8Name("Attacker CA"))}
			der := ok(ca.endorse(ok(die.CSR("PSOC130"))))
			must(t, os.WriteFile(filepath.Join(b, "artifacts", trimFileURI(S(e, "certificate", "uri"))), der, 0o644))
			editJSON(t, filepath.Join(b, "artifacts", DieIdentities), func(d Obj) {
				O(Objs(d, "dies")[0], "certificate", "digest")["sha256"] = sha256Bytes(der)
			})
			forge(t, b, MfgAtt["wafer-sort"], nil)
		}, "is not signed by an identity CA in the trust root"},
		"unit-on-another-die": {func(t *testing.T, b string) {
			// The OSAT names a unit by a certificate of another die than the one it packaged.
			editJSON(t, filepath.Join(b, "artifacts", "genealogy.json"), func(g Obj) {
				units := O(g, "units")
				keys := sortedKeys(units)
				a, c := O(units, keys[0]), O(units, keys[1])
				a["x"], c["x"] = c["x"], a["x"]
				a["y"], c["y"] = c["y"], a["y"]
				a["wafer"], c["wafer"] = c["wafer"], a["wafer"]
			})
			forge(t, b, MfgAtt["packaging"], nil)
		}, "is not named by the certificate of the die it was packaged from"},
		"lot-named-by-serial": {func(t *testing.T, b string) {
			forge(t, b, MfgAtt["final-test"], func(s Obj) { delete(O(s, "predicate", "hwMfg"), "identity") })
		}, "the shipped lot is not named by the units' certificate digests"},
		"shipped-unit-never-challenged": {func(t *testing.T, b string) {
			shipped := ok(ReadUnits(filepath.Join(b, "artifacts", "shipped-lot.txt")))
			editJSON(t, filepath.Join(b, "artifacts", IdentityChallenges), func(c Obj) { delete(O(c, "units"), shipped[0]) })
			forge(t, b, MfgAtt["final-test"], nil)
		}, "did not answer a challenge"},
		"answer-forged": {func(t *testing.T, b string) {
			shipped := ok(ReadUnits(filepath.Join(b, "artifacts", "shipped-lot.txt")))
			editJSON(t, filepath.Join(b, "artifacts", IdentityChallenges), func(c Obj) {
				a := O(c, "units", shipped[0])
				sig := ok(ok(newDie("x")).Answer([]byte("anything")))
				a["signature"] = base64.StdEncoding.EncodeToString(sig)
			})
			forge(t, b, MfgAtt["final-test"], nil)
		}, "the answer does not verify under its certificate"},
		"nonce-reused": {func(t *testing.T, b string) {
			shipped := ok(ReadUnits(filepath.Join(b, "artifacts", "shipped-lot.txt")))
			editJSON(t, filepath.Join(b, "artifacts", IdentityChallenges), func(c Obj) {
				O(c, "units", shipped[1])["nonce"] = S(c, "units", shipped[0], "nonce")
			})
			forge(t, b, MfgAtt["final-test"], nil)
		}, "is not a fresh nonce"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := chipL3Bundle(t)
			c.edit(t, bundle)
			rejects(t, l3Default(t, bundle), c.reason)
		})
	}
}

func TestL3KeysAndSites(t *testing.T) {
	cases := map[string]struct {
		custody map[string]string
		org     func() map[string][3]string
		reason  string
	}{
		"site-key-in-a-file": {map[string]string{"osat-site": "file"}, nil,
			`Package/Test L3: packaging is signed by osat-site key`},
		"identity-ca-key-in-a-file": {map[string]string{IdentityCARole: "file"}, nil,
			`identity CA: identity-ca key`},
		"site-not-accredited": {nil, func() map[string][3]string {
			o := copyOrgs()
			o["test-site"] = [3]string{o["test-site"][0], o["test-site"][1], ""}
			return o
		}, "which is enrolled with no accreditation"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := chipL3Bundle(t)
			org := l3Org
			if c.org != nil {
				org = c.org()
			}
			tr := ok(l3TrustRoot(chipKeys(bundle), bundle, "other", c.custody, org))
			rejects(t, l3Check(t, bundle, tr, ok(ReadObj(l3Policy)), received(bundle)), c.reason)
		})
	}
}

func copyOrgs() map[string][3]string {
	o := map[string][3]string{}
	for k, v := range l3Org {
		o[k] = v
	}
	return o
}

func TestL3AccreditationNotOnThePolicy(t *testing.T) {
	bundle := chipL3Bundle(t)
	p := ok(ReadObj(l3Policy))
	p["accreditations"] = []any{"iso-iec-20243"}
	rejects(t, l3Check(t, bundle, filepath.Join(bundle, "trust-root.json"), p, received(bundle)),
		`Wafer L3: wafer-fab is signed at Example Foundry site, accredited under "dmea-trusted-supplier"`)
}

func TestL3TransferBetweenCompaniesRequired(t *testing.T) {
	// Without transfers (and a policy that does not ask for them), L3 still
	// needs one wherever wafers or units go to another company's site; a
	// shipment inside one company needs none.
	bundle := chipL3Bundle(t)
	scenario := filepath.Join(t.TempDir(), "mfg-scenario.json")
	must(t, copyFile(l3Scenario, scenario))
	editJSON(t, scenario, func(s Obj) { delete(s, "transfers") })
	keys := chipKeys(bundle)
	parts := filepath.Join(t.TempDir(), "parts")
	must(t, MfgWith(bundle, scenario, keys, nil, nil, parts))
	must(t, BuildHBOM(bundle, e2eLock, scenario, filepath.Join(keys, "product-owner.key.pem"), nil))
	p := ok(ReadObj(l3Policy))
	delete(p, "manufacturing")
	rejects(t, l3Check(t, bundle, filepath.Join(bundle, "trust-root.json"), p, ""),
		"Wafer L3: the shipment from wafer-fab to wafer-sort goes to another company's site with no signed transfer")
	// One company runs the fab, sort, packaging and test: no shipment leaves it.
	one := map[string][3]string{}
	for role, o := range l3Org {
		one[role] = [3]string{"Example IDM", "duns:100000020", o[2]}
	}
	tr := ok(l3TrustRoot(keys, bundle, "idm", nil, one))
	must(t, l3Check(t, bundle, tr, p, ""))
}

func TestL3ReceivedParts(t *testing.T) {
	bundle := chipL3Bundle(t)
	trustPath := filepath.Join(bundle, "trust-root.json")
	policy := ok(ReadObj(l3Policy))
	// Serials typed into a list are not a receipt check at L3.
	trust := ok(LoadTrustRoot(trustPath))
	design := ok(TapeoutCheck(bundle, trust, policy, true))
	_, err := lotCheck(bundle, trust, policy, design, ok(ReadUnits(filepath.Join(e2eDir, "received-units.txt"))), false)
	rejects(t, err, "the received units were listed, not challenged")
	// A clone: a genuine part's certificate on a die with another secret.
	clone := filepath.Join(t.TempDir(), "clone")
	serial := ok(ReadUnits(filepath.Join(e2eDir, "received-units.txt")))[0]
	must(t, copyTree(filepath.Join(received(bundle), serial), filepath.Join(clone, serial)))
	editJSON(t, filepath.Join(clone, serial, dieFile), func(d Obj) { d["uds"] = strings.Repeat("ab", 32) })
	rejects(t, l3Check(t, bundle, trustPath, policy, clone), "does not verify under its certificate's key")
	// A part that failed final test, sold on.
	scrapped := filepath.Join(t.TempDir(), "scrapped")
	must(t, copyTree(filepath.Join(filepath.Dir(bundle), "parts", "PSOC130-A0-00007"), filepath.Join(scrapped, "PSOC130-A0-00007")))
	rejects(t, l3Check(t, bundle, trustPath, policy, scrapped), "is not in the shipped lot")
	// A part with no identity at all.
	blank := filepath.Join(t.TempDir(), "blank", "part")
	must(t, os.MkdirAll(blank, 0o755))
	rejects(t, l3Check(t, bundle, trustPath, policy, filepath.Dir(blank)), "does not answer an identity challenge")
}

func TestL3NeedsAllChipTracksChecked(t *testing.T) {
	// The main example's L2 lot under a policy that claims Wafer L3: no enrollments, no identities.
	bundle := chipBundle(t)
	p := ok(ReadObj(l3Policy))
	rejects(t, l3Check(t, bundle, filepath.Join(bundle, "trust-root.json"), p, ""), "L3 needs a buyer-run trust root")
}
