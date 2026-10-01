package hslsa

// The lot receipt check's L3 rules for the chip tracks (spec, "Core
// requirements"), run when the policy claims Wafer L3 or Package/Test L3:
//
//	Wafer L3         the fab, sort house and the transfers they sign use keys
//	                 held in HSMs at accredited sites; the fab checked the
//	                 design release before mask making (its own signed VSA,
//	                 consumed by F1) and its mask XOR names the released
//	                 design; every passing die has an identity rooted in its
//	                 own root of trust, endorsed by an identity CA whose key
//	                 is held in an HSM; every shipment of wafers to another
//	                 company's site has a signed transfer
//	Package/Test L3  the OSAT, test house and their transfers use keys held
//	                 in HSMs at accredited sites; every unit is named by its
//	                 die's certificate digest, and every shipped unit answered
//	                 final test's challenge under that certificate; every
//	                 shipment of wafers or units to another company's site
//	                 has a signed transfer; at receipt, the parts themselves
//	                 answer a challenge again (verify --units with a directory
//	                 of parts)

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"
)

// transferTracks are the tracks whose L3 requires the transfer that leaves
// each step: wafers leaving the fab and sort are the Wafer track's, and
// wafers reaching the OSAT and units reaching the test house are
// Package/Test's.
var transferTracks = map[string][]string{
	"wafer-fab":  {"WAFER"},
	"wafer-sort": {"WAFER", "PACKAGE_TEST"},
	"packaging":  {"PACKAGE_TEST"},
}

// chipL3 runs the L3 rules for the chip tracks the policy claims at L3.
// received are the units checked at receipt, and challenged says whether
// they answered an identity challenge there or were only listed.
func chipL3(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, stmts map[string]Obj, received []string, challenged bool) error {
	wafer, pt := trackClaim(policy, "WAFER") >= 3, trackClaim(policy, "PACKAGE_TEST") >= 3
	if !wafer && !pt {
		return nil
	}
	att := func(name string) string { return filepath.Join(bundle, "att", name) }
	sites := map[string]bool{"wafer-fab": wafer, "wafer-sort": wafer, "packaging": pt, "final-test": pt}
	for _, step := range MfgSteps {
		if sites[step] {
			if err := keyL3(trust, policy, att(MfgAtt[step]), MfgSigner[step], trackLabel(step)+": "+step); err != nil {
				return err
			}
		}
	}
	for _, from := range TransferFrom {
		need := false
		for _, t := range transferTracks[from] {
			need = need || trackClaim(policy, t) >= 3
		}
		if !need {
			continue
		}
		to := MfgSteps[indexOf(MfgSteps, from)+1]
		label := trackLabel(from) + ": the shipment from " + from + " to " + to
		if !fileExists(att(TransferAtt(from))) {
			same, err := sameCompany(trust, att(MfgAtt[from]), MfgSigner[from], att(MfgAtt[to]), MfgSigner[to])
			if err != nil {
				return err
			}
			if !same {
				return failf("%s goes to another company's site with no signed transfer", label)
			}
			continue
		}
		if err := keyL3(trust, policy, att(TransferAtt(from)), MfgSigner[from], label); err != nil {
			return err
		}
	}
	ids, err := dieIdentities(bundle, trust, stmts, wafer)
	if err != nil {
		return err
	}
	if wafer {
		if err := fabChecks(bundle, trust, design, stmts["wafer-fab"]); err != nil {
			return err
		}
	}
	if pt {
		if err := unitIdentities(bundle, stmts, ids); err != nil {
			return err
		}
		if len(received) > 0 && !challenged {
			return failf("Package/Test L3: the received units were listed, not challenged; at L3 each part answers a challenge at receipt (pass the directory of parts to --units)")
		}
	}
	return nil
}

func trackLabel(step string) string {
	if mfgTrack(step) == "Wafer track" {
		return "Wafer L3"
	}
	return "Package/Test L3"
}

// sameCompany reports whether the keys that signed two records are enrolled
// to the same organization; without enrollments it cannot tell, and says no.
func sameCompany(trust *TrustRoot, a, roleA, b, roleB string) (bool, error) {
	ka, err := trust.SignerKey(a, roleA)
	if err != nil {
		return false, err
	}
	kb, err := trust.SignerKey(b, roleB)
	if err != nil {
		return false, err
	}
	ea, eb := trust.Enrolled[ka.ID], trust.Enrolled[kb.ID]
	return ea != nil && eb != nil && S(ea, "organization", "id") == S(eb, "organization", "id"), nil
}

// fabChecks: F1 consumes the fab's own VSA over the released design, signed
// with the key F1 is signed with before F1 finished, and the mask XOR names
// the released design.
func fabChecks(bundle string, trust *TrustRoot, design *DesignResult, f1 Obj) error {
	label := "Wafer L3: wafer-fab"
	path := filepath.Join(bundle, "att", FabReleaseCheckAtt)
	var dep Obj
	for _, d := range Objs(f1, "predicate", "buildDefinition", "resolvedDependencies") {
		if S(d, "name") == "att/"+FabReleaseCheckAtt {
			dep = d
		}
	}
	if dep == nil {
		return failf("%s: the record does not consume the fab's check of the design release (%s), so nothing shows the fab verified the release before mask making", label, FabReleaseCheckAtt)
	}
	if !jsonEqual(fileDigest(path), get(dep, "digest")) {
		return failf("%s: %s is not the release check the record consumed", label, FabReleaseCheckAtt)
	}
	vsa, err := trust.Open(path, MfgSigner["wafer-fab"], VSAType)
	if err != nil {
		return err
	}
	kv, err := trust.SignerKey(path, MfgSigner["wafer-fab"])
	if err != nil {
		return err
	}
	kf, err := trust.SignerKey(filepath.Join(bundle, "att", MfgAtt["wafer-fab"]), MfgSigner["wafer-fab"])
	if err != nil {
		return err
	}
	if kv.ID != kf.ID {
		return failf("%s: the release check is signed by another fab-site key than F1", label)
	}
	p := O(vsa, "predicate")
	if S(p, "verificationResult") != "PASSED" || !jsonEqual(get(firstSubject(vsa), "digest"), get(design.Final, "digest")) {
		return failf("%s: the fab's release check did not pass for the released design", label)
	}
	inputs := false
	for _, in := range Objs(p, "inputAttestations") {
		inputs = inputs || jsonEqual(get(in, "digest"), get(design.Release, "digest"))
	}
	if !inputs {
		return failf("%s: the fab's release check did not read this release attestation", label)
	}
	checked, err1 := time.Parse(time.RFC3339, S(p, "timeVerified"))
	made, err2 := time.Parse(time.RFC3339, S(f1, "predicate", "runDetails", "metadata", "finishedOn"))
	if err1 != nil || err2 != nil || checked.After(made) {
		return failf("%s: the fab's release check is not dated before the wafer lot", label)
	}
	for _, c := range Objs(f1, "predicate", "hwMfg", "checks") {
		if S(c, "name") == "mask-vs-gds-xor" {
			if S(c, "result") != "pass" || !jsonEqual(get(c, "against", "digest"), get(design.Final, "digest")) {
				return failf("%s: the mask-vs-GDS XOR did not pass against the released design", label)
			}
			return nil
		}
	}
	return failf("%s: no mask-vs-GDS XOR is recorded", label)
}

// dieIdentities checks wafer sort's identities: every passing die has one,
// its certificate is in the bundle by the digest listed, is signed by an
// identity CA in the trust root (held in an HSM, when hsm is set) and
// carries a UEID no other die has. It returns the identities by die.
func dieIdentities(bundle string, trust *TrustRoot, stmts map[string]Obj, hsm bool) (map[string]Obj, error) {
	label := "Wafer L3: wafer-sort"
	if !hsm {
		label = "Package/Test L3: wafer-sort"
	}
	art := filepath.Join(bundle, "artifacts")
	if !sha256Set(Objs(stmts["wafer-sort"], "subject"))[S(fileDigest(filepath.Join(art, DieIdentities)), "sha256")] {
		return nil, failf("%s: the record names no %s, so no die identity was provisioned at sort", label, DieIdentities)
	}
	ids, err := ReadObj(filepath.Join(art, DieIdentities))
	if err != nil {
		return nil, failf("%s: %v", label, err)
	}
	if rot := S(ids, "rootOfTrust"); rot != "dice" && rot != "caliptra" {
		return nil, failf("%s: identities are rooted in %q, not a DICE or Caliptra class root of trust", label, rot)
	}
	maps, err := ReadObj(filepath.Join(art, "wafer-maps.json"))
	if err != nil {
		return nil, failf("%s: wafer maps: %v", label, err)
	}
	byDie, ueids, cas := map[string]Obj{}, map[string]bool{}, map[string]Key{}
	for _, e := range Objs(ids, "dies") {
		die := dieKey(e["wafer"], e["x"], e["y"])
		where := label + ": die " + dieName(e["wafer"], e["x"], e["y"])
		if byDie[die] != nil {
			return nil, failf("%s has two identities", where)
		}
		der, err := os.ReadFile(filepath.Join(art, trimFileURI(S(e, "certificate", "uri"))))
		if err != nil || sha256Bytes(der) != S(e, "certificate", "digest", "sha256") {
			return nil, failf("%s: its certificate is not in the bundle by the digest listed", where)
		}
		cert, ca, err := identityCert(trust, der, where)
		if err != nil {
			return nil, err
		}
		typ, rest, _ := UEID(cert)
		ueid := hex.EncodeToString(append([]byte{typ}, rest...))
		if ueids[ueid] || ueid != S(e, "ueid") {
			return nil, failf("%s: its UEID is another die's, or not the one listed", where)
		}
		ueids[ueid] = true
		cas[ca.ID] = ca
		byDie[die] = e
	}
	for _, d := range Objs(maps, "dies") {
		if S(d, "bin") == "pass" && byDie[dieKey(d["wafer"], d["x"], d["y"])] == nil {
			return nil, failf("%s: passing die %s has no identity", label, dieName(d["wafer"], d["x"], d["y"]))
		}
	}
	if hsm {
		for _, id := range sortedKeys(cas) {
			if err := enrolledInHSM(trust, cas[id], IdentityCARole, label+": the identity CA"); err != nil {
				return nil, err
			}
		}
	}
	return byDie, nil
}

func trimFileURI(u string) string {
	if len(u) > 5 && u[:5] == "file:" {
		return u[5:]
	}
	return u
}

// unitIdentities checks the Package/Test L3 naming: every packaged unit is
// the certificate digest of the die its genealogy names, and every shipped
// unit answered final test's challenge under that certificate.
func unitIdentities(bundle string, stmts map[string]Obj, byDie map[string]Obj) error {
	label := "Package/Test L3: final-test"
	art := filepath.Join(bundle, "artifacts")
	f4 := stmts["final-test"]
	if S(f4, "predicate", "hwMfg", "identity", "lotNaming") != "certificate" {
		return failf("%s: the shipped lot is not named by the units' certificate digests", label)
	}
	gen, err := ReadObj(filepath.Join(art, "genealogy.json"))
	if err != nil {
		return failf("%s: genealogy: %v", label, err)
	}
	genealogy := O(gen, "units")
	certs := map[string][]byte{}
	for _, unit := range sortedKeys(genealogy) {
		g := O(genealogy, unit)
		e := byDie[dieKey(get(g, "wafer"), get(g, "x"), get(g, "y"))]
		if e == nil || S(e, "certificate", "digest", "sha256") != unit {
			return failf("Package/Test L3: packaging: unit %s is not named by the certificate of the die it was packaged from", short(unit))
		}
		certs[unit], _ = os.ReadFile(filepath.Join(art, trimFileURI(S(e, "certificate", "uri"))))
	}
	if !sha256Set(Objs(f4, "subject"))[S(fileDigest(filepath.Join(art, IdentityChallenges)), "sha256")] {
		return failf("%s: the record names no %s, so no unit answered a challenge", label, IdentityChallenges)
	}
	tr, err := ReadObj(filepath.Join(art, IdentityChallenges))
	if err != nil {
		return failf("%s: %v", label, err)
	}
	if S(tr, "format") != ChallengeFormat {
		return failf("%s: challenges in format %q, not %s", label, S(tr, "format"), ChallengeFormat)
	}
	shipped, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return failf("%s: %v", label, err)
	}
	nonces := map[string]bool{}
	for _, unit := range shipped {
		a := O(tr, "units", unit)
		nonce, err1 := hex.DecodeString(S(a, "nonce"))
		sig, err2 := base64.StdEncoding.DecodeString(S(a, "signature"))
		cert, err3 := x509.ParseCertificate(certs[unit])
		switch {
		case a == nil:
			return failf("%s: shipped unit %s did not answer a challenge", label, short(unit))
		case err1 != nil || err2 != nil || len(nonce) < 16 || nonces[S(a, "nonce")]:
			return failf("%s: unit %s: the challenge is not a fresh nonce of 16 bytes or more", label, short(unit))
		case err3 != nil || !answered(cert, nonce, sig):
			return failf("%s: unit %s: the answer does not verify under its certificate", label, short(unit))
		}
		nonces[S(a, "nonce")] = true
	}
	return nil
}
