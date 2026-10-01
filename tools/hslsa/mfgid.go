package hslsa

// Unit identities in the chip lot (Wafer L3 and Package/Test L3). When the
// scenario has an identity block, each site does its part on the simulated
// dies of dieid.go:
//
//	wafer sort   burns a UDS into every passing die, takes the CSR the die
//	             signs with its IDevID key, has the identity CA endorse it, and
//	             lists the certificates in die-identities.json, an F2 subject
//	packaging    names each unit by the sha256 of its die's certificate (the
//	             L3 unit name), keeping the marked serial in the genealogy
//	final test   challenges every packaged unit with a fresh nonce and keeps
//	             the answers in identity-challenges.json, an F4 subject; a
//	             unit that does not answer under its own certificate fails
//
// The fab's release check (Wafer L3) is separate: before mask making the fab
// runs the tapeout check and signs a verification summary with its site key,
// which F1 then consumes.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// FabReleaseCheckAtt is the fab's verification summary of the design release.
const FabReleaseCheckAtt = "fab-release-check.vsa.intoto.json"

// FabReleaseCheck is the fab's check of the design release before mask
// making: the tapeout check under the fab's own trust root and policy, and a
// VSA over the released design signed with the fab's site key.
func FabReleaseCheck(bundle string, trust *TrustRoot, policyPath, key string) error {
	policy, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	design, err := TapeoutCheck(bundle, trust, policy, true)
	if err != nil {
		return err
	}
	levels := O(policy, "claims")["design"]
	if err := signVSA(design.Final, "hslsa:design:"+S(design.Final, "name"), levels,
		append([]Obj{design.Release}, design.Inputs...), policyPath, key,
		filepath.Join(bundle, "att", FabReleaseCheckAtt)); err != nil {
		return err
	}
	fmt.Printf("fab release check: PASSED for %s sha256:%s, %s\n", S(design.Final, "name"), S(design.Final, "digest", "sha256"), pyList(levels))
	return nil
}

// identityRun is what a run of mfg needs to provision and name unit identities.
type identityRun struct {
	block   Obj    // the scenario's identity block
	devices string // where the parts are: one directory per die, then per unit
	// byDie maps a die (dieKey) to its identity entry in die-identities.json.
	byDie map[string]Obj
}

func (r *identityRun) dieDir(wafer, x, y any) string {
	return filepath.Join(r.devices, dieName(wafer, x, y))
}

// provision is wafer sort's part: an identity for every passing die, or,
// when another party signs sort, the identities it already provisioned.
func (r *identityRun) provision(bundle string, good []Obj, waferLot string, measure string, keys *mfgKeys, w *Withholding) (Obj, error) {
	art := filepath.Join(bundle, "artifacts")
	path := filepath.Join(art, DieIdentities)
	if keys.signs(MfgSigner["wafer-sort"]) {
		ca, err := loadIdentityCA(keys.dir, S(r.block, "ca"))
		if err != nil {
			return nil, err
		}
		if err := os.RemoveAll(filepath.Join(art, IdentityDir)); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Join(art, IdentityDir), 0o755); err != nil {
			return nil, err
		}
		var entries []Obj
		for _, d := range good {
			die, err := newDie(measure)
			if err != nil {
				return nil, err
			}
			csr, err := die.CSR(S(r.block, "model"))
			if err != nil {
				return nil, err
			}
			if die.Cert, err = ca.endorse(csr); err != nil {
				return nil, err
			}
			name := dieName(d["wafer"], d["x"], d["y"])
			rel := IdentityDir + "/" + name + ".der"
			if err := os.WriteFile(filepath.Join(art, rel), die.Cert, 0o644); err != nil {
				return nil, err
			}
			if err := die.save(r.dieDir(d["wafer"], d["x"], d["y"])); err != nil {
				return nil, err
			}
			entries = append(entries, Obj{
				"wafer": d["wafer"], "x": d["x"], "y": d["y"],
				"ueid":        hex.EncodeToString(die.UEID()),
				"certificate": Obj{"uri": "file:" + rel, "digest": Obj{"sha256": sha256Bytes(die.Cert)}},
			})
		}
		if err := writeData(path, Obj{
			"waferLot":    waferLot,
			"rootOfTrust": S(r.block, "rootOfTrust"),
			"ca":          S(r.block, "ca"),
			"dies":        nonNil(entries),
		}, w); err != nil {
			return nil, err
		}
		fmt.Printf("wafer-sort: provisioned %d die identities, endorsed by %s\n", len(entries), S(r.block, "ca"))
	}
	ids, err := ReadObj(path)
	if err != nil {
		return nil, &waitingFor{"wafer-sort", MfgSigner["wafer-sort"]}
	}
	r.byDie = map[string]Obj{}
	for _, e := range Objs(ids, "dies") {
		r.byDie[dieKey(e["wafer"], e["x"], e["y"])] = e
	}
	return fileRD(path, "")
}

// nameUnits is packaging's part: each unit takes the digest of its die's
// certificate as its name, and its part moves from the die's directory to
// one named by its marked serial.
func (r *identityRun) nameUnits(genealogy Obj, serials []string, moveParts bool) (Obj, []string, map[string]string, error) {
	named := Obj{}
	bySerial := map[string]string{}
	var units []string
	for _, serial := range serials {
		g := O(genealogy, serial)
		e := r.byDie[dieKey(g["wafer"], g["x"], g["y"])]
		if e == nil {
			return nil, nil, nil, fmt.Errorf("packaging: %s is on a die wafer sort gave no identity", serial)
		}
		id := S(e, "certificate", "digest", "sha256")
		entry := Obj{"serial": serial}
		for k, v := range g {
			entry[k] = v
		}
		named[id] = entry
		bySerial[serial] = id
		units = append(units, id)
		if moveParts {
			from, to := r.dieDir(g["wafer"], g["x"], g["y"]), filepath.Join(r.devices, serial)
			if _, err := os.Stat(from); err == nil {
				if err := os.RemoveAll(to); err != nil {
					return nil, nil, nil, err
				}
				if err := os.Rename(from, to); err != nil {
					return nil, nil, nil, err
				}
			}
		}
	}
	return named, units, bySerial, nil
}

// challenge is final test's part: every packaged unit answers a fresh nonce
// under its own certificate. It returns the transcript and the units that
// did not answer, which fail final test.
func (r *identityRun) challenge(genealogy Obj, units []string) (Obj, []string, error) {
	answers := Obj{}
	var failed []string
	for _, id := range units {
		serial := S(genealogy, id, "serial")
		nonce, der, sig, err := ChallengeUnit(filepath.Join(r.devices, serial))
		if err != nil || sha256Bytes(der) != id {
			failed = append(failed, id)
			fmt.Printf("final-test: %s does not answer under its own identity, failed\n", serial)
			continue
		}
		answers[id] = Obj{
			"serial":    serial,
			"nonce":     hex.EncodeToString(nonce),
			"signature": base64.StdEncoding.EncodeToString(sig),
		}
	}
	sort.Strings(failed)
	return Obj{"format": ChallengeFormat, "units": answers}, failed, nil
}

// unitIDs maps serials to the unit names nameUnits gave them.
func unitIDs(serials []string, bySerial map[string]string) []string {
	out := make([]string, 0, len(serials))
	for _, s := range serials {
		if id, ok := bySerial[s]; ok {
			out = append(out, id)
		} else {
			out = append(out, s)
		}
	}
	return out
}
