package hslsa

// Manufacturing records in a transparency log (spec, "Release log"): a buyer
// whose policy names a log (manufacturing.transparencyLog.origin) requires
// every manufacturing record, transfer and HBOM the lot receipt check relies
// on to be in it, as Firmware L3 requires of firmware releases. A site that
// signed two different records for one lot then shows both to whoever
// watches the log.

import (
	"path/filepath"
	"strings"
)

// mfgLogCheck checks each record in records (bundle-relative att/ names) for
// an inclusion proof in the log the policy names, and returns the proofs it
// accepted. A policy that names no log asks for none.
func mfgLogCheck(bundle string, trust *TrustRoot, policy Obj, records []Obj, label string) ([]Obj, error) {
	log := O(policy, "manufacturing", "transparencyLog")
	if log == nil {
		return nil, nil
	}
	origin := S(log, "origin")
	if origin == "" {
		return nil, failf("%s: manufacturing.transparencyLog names no origin", label)
	}
	role := S(log, "role")
	if role == "" {
		role = TLogRole
	}
	var proofs []Obj
	for _, r := range records {
		name := S(r, "name")
		if !strings.HasPrefix(name, "att/") || !strings.HasSuffix(name, ".intoto.json") {
			continue
		}
		path := filepath.Join(bundle, filepath.FromSlash(name))
		if _, err := CheckLogged(trust, path, role, origin, label); err != nil {
			return nil, err
		}
		proof := TLogProofPath(path)
		proofs = append(proofs, Obj{"name": strings.TrimSuffix(name, filepath.Base(name)) + filepath.Base(proof), "digest": fileDigest(proof)})
	}
	return proofs, nil
}
