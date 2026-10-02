package hslsa

// Claims above L2 (spec sections "Core requirements" and "L4 defense
// profile"). A policy names the levels it claims; each check runs the extra
// requirements of L3 for a track whenever the policy claims L3 or more in
// that track, and fails when one is not met, so a VSA never states a level
// the check did not establish. This file holds what the tracks share: the
// claims' form, which key signed a record, and what a buyer-run trust root
// says about how that key is held.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

// LevelTracks are the tracks as claims name them (HSLSA_<TRACK>_LEVEL_<n>).
var LevelTracks = []string{"DESIGN", "WAFER", "PACKAGE_TEST", "ASSEMBLY", "FIRMWARE"}

// TrackTitle is a track's name in messages.
var TrackTitle = map[string]string{
	"DESIGN": "Design", "WAFER": "Wafer", "PACKAGE_TEST": "Package/Test", "ASSEMBLY": "Assembly", "FIRMWARE": "Firmware",
}

// levelUnchecked is the lowest level of each track this tool cannot check
// yet; a claim at or above it is refused.
var levelUnchecked = map[string]int{"DESIGN": 5, "WAFER": 5, "PACKAGE_TEST": 5, "ASSEMBLY": 5, "FIRMWARE": 4}

// parseClaim reads one verifiedLevels value: an HSLSA track level, an SLSA
// build level (track ""), or HSLSA_SIMULATED (ok false, no error).
func parseClaim(c string) (track string, n int, ok bool, err error) {
	if c == SimulatedLevel {
		return "", 0, false, nil
	}
	if rest, found := strings.CutPrefix(c, "SLSA_BUILD_LEVEL_"); found {
		if _, err := fmt.Sscanf(rest, "%d", &n); err != nil || fmt.Sprint(n) != rest || n < 0 || n > 3 {
			return "", 0, false, failf("claim %s: SLSA build levels run from 0 to 3", c)
		}
		return "", n, true, nil
	}
	for _, t := range LevelTracks {
		if rest, found := strings.CutPrefix(c, "HSLSA_"+t+"_LEVEL_"); found {
			if _, err := fmt.Sscanf(rest, "%d", &n); err != nil || fmt.Sprint(n) != rest || n < 0 || n > 4 {
				return "", 0, false, failf("claim %s: levels run from 0 to 4", c)
			}
			return t, n, true, nil
		}
	}
	return "", 0, false, failf("claim %s: not a level this framework defines (HSLSA_<TRACK>_LEVEL_<n>, SLSA_BUILD_LEVEL_<n> or %s)", c, SimulatedLevel)
}

// checkClaimList refuses a list of verifiedLevels the tool cannot stand
// behind: a value it does not know, a level it does not check yet, or an
// SLSA build level above the Design or Firmware level the same list claims
// (Design Ln and Firmware Ln meet SLSA Build Ln, not the other way round).
func checkClaimList(levels any) error {
	list := Strs(Obj{"v": levels}, "v")
	best := 0
	slsa := 0
	for _, c := range list {
		track, n, ok, err := parseClaim(c)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		switch track {
		case "":
			slsa = max(slsa, n)
		case "DESIGN", "FIRMWARE":
			best = max(best, n)
		}
		if track != "" && n >= levelUnchecked[track] {
			return failf("claim %s: the reference tool does not check %s L%d yet", c, TrackTitle[track], n)
		}
	}
	if slsa > best {
		return failf("claims SLSA Build L%d but no Design or Firmware level of at least L%d in the same list", slsa, slsa)
	}
	return nil
}

// The tracks each VSA covers: what the check behind it verified.
var (
	designTracks = []string{"DESIGN"}
	lotTracks    = []string{"WAFER", "PACKAGE_TEST", "DESIGN"}
	boardTracks  = []string{"ASSEMBLY"}
	fpgaTracks   = []string{"ASSEMBLY", "FIRMWARE"}
	fwTracks     = []string{"FIRMWARE"}
	deviceTracks = []string{"FIRMWARE", "WAFER", "PACKAGE_TEST", "DESIGN"}
)

// claimsInTracks refuses a level in a track the check did not cover: a lot
// receipt check, say, cannot state a Firmware level, whatever the policy claims.
func claimsInTracks(levels any, tracks []string) error {
	for _, c := range Strs(Obj{"v": levels}, "v") {
		track, _, ok, err := parseClaim(c)
		if err != nil {
			return err
		}
		if ok && track != "" && !contains(tracks, track) {
			var names []string
			for _, t := range tracks {
				names = append(names, TrackTitle[t])
			}
			return failf("claim %s: this check covers %s, not the %s track", c, strings.Join(names, ", "), TrackTitle[track])
		}
	}
	return nil
}

// checkPolicyClaims runs checkClaimList over every list in the policy's claims.
func checkPolicyClaims(policy Obj) error {
	claims := O(policy, "claims")
	for _, name := range sortedKeys(claims) {
		if err := checkClaimList(claims[name]); err != nil {
			return failf("policy claims.%s: %s", name, strings.TrimPrefix(err.Error(), "verification failed: "))
		}
	}
	return nil
}

// SignerKey returns the key of role whose signature on the envelope at path
// verifies. Open has already checked that one does.
func (t *TrustRoot) SignerKey(path, role string) (Key, error) {
	raw, err := ReadObj(path)
	if err != nil {
		return Key{}, err
	}
	env := &dsse.Envelope{PayloadType: S(raw, "payloadType"), Payload: S(raw, "payload")}
	for _, s := range Objs(raw, "signatures") {
		env.Signatures = append(env.Signatures, dsse.Signature{KeyID: S(s, "keyid"), Sig: S(s, "sig")})
	}
	for _, k := range t.Roles[role] {
		sv, err := signerverifier.NewECDSASignerVerifierFromSSLibKey(&signerverifier.SSLibKey{
			KeyID: k.ID, KeyType: "ecdsa", Scheme: k.Scheme, KeyVal: signerverifier.KeyVal{Public: k.PEM},
		})
		if err != nil {
			return Key{}, err
		}
		ev, err := dsse.NewEnvelopeVerifier(sv)
		if err != nil {
			return Key{}, err
		}
		if _, err := ev.Verify(context.Background(), env); err == nil {
			return k, nil
		}
	}
	return Key{}, failf("%s: no valid signature from role '%s'", filepath.Base(path), role)
}

// keyL3 is keyAccredited for a key the enrollment also records as held in
// an HSM: what Wafer L3 and Package/Test L3 ask of a site key.
func keyL3(trust *TrustRoot, policy Obj, path, role, what string) error {
	return siteKey(trust, policy, path, role, what, true)
}

// keyAccredited requires that the record at path was signed by a key of
// role that the buyer-run trust root enrolls at a site accredited under a
// scheme the policy's accreditations list: what Assembly L3 asks.
func keyAccredited(trust *TrustRoot, policy Obj, path, role, what string) error {
	return siteKey(trust, policy, path, role, what, false)
}

// siteKey finds the key of role that signed the envelope at path and its
// enrollment. Records cannot show how a key is held or where; the buyer's
// enrollment, made after checking with the site, is what says so.
func siteKey(trust *TrustRoot, policy Obj, path, role, what string, hsm bool) error {
	k, err := trust.SignerKey(path, role)
	if err != nil {
		return err
	}
	e, ok := trust.Enrolled[k.ID]
	if !ok {
		return failf("%s is signed by %s key %s, which the trust root lists without an enrollment; L3 needs a buyer-run trust root that records how each site key is held (hslsa pilot trust-root)", what, role, short(k.ID))
	}
	if hsm && S(e, "keyCustody") != "hsm" {
		return failf("%s is signed by %s key %s, enrolled with key custody %q; L3 needs a key held in an HSM", what, role, short(k.ID), S(e, "keyCustody"))
	}
	scheme := S(e, "accreditation", "scheme")
	if scheme == "" {
		return failf("%s is signed by %s key %s of %s, which is enrolled with no accreditation; L3 needs signing at an accredited site", what, role, short(k.ID), S(e, "site", "name"))
	}
	if !contains(Strs(policy, "accreditations"), scheme) {
		return failf("%s is signed at %s, accredited under %q, which the policy's accreditations do not list", what, S(e, "site", "name"), scheme)
	}
	return nil
}

// keyInHSM requires only that the key that signed the envelope at path for
// role is enrolled with key custody hsm (an identity CA, a platform CA, a
// tapeout authority), with no site accreditation.
func keyInHSM(trust *TrustRoot, path, role, what string) error {
	k, err := trust.SignerKey(path, role)
	if err != nil {
		return err
	}
	return enrolledInHSM(trust, k, role, what)
}

func enrolledInHSM(trust *TrustRoot, k Key, role, what string) error {
	e, ok := trust.Enrolled[k.ID]
	if !ok {
		return failf("%s: %s key %s is listed without an enrollment; the trust root must record that it is held in an HSM (hslsa pilot trust-root)", what, role, short(k.ID))
	}
	if S(e, "keyCustody") != "hsm" {
		return failf("%s: %s key %s is enrolled with key custody %q, not hsm", what, role, short(k.ID), S(e, "keyCustody"))
	}
	return nil
}
