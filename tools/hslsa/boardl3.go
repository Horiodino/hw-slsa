package hslsa

// Assembly L3 (spec, "Core requirements"): signing at accredited sites;
// every component with a hardware identity is checked by attestation at
// build; a platform certificate binds the system to those parts; parts
// without an identity stay at lot-level naming.
//
// At build the EMS challenges every chip it places, under the identity CA of
// the chip's own trust root, and keeps the answers in part-attestations.json,
// an A1 subject; the chips are then named by certificate digest, as their
// L3 lot names them. After A1 the board owner's platform CA signs a platform
// certificate per board: the board's serial and every component on it, by
// certificate digest where the part has an identity and by lot otherwise.
// At board receipt, the buyer challenges the identity parts on each board it
// received, and each must answer with the certificate its platform
// certificate names.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// PartAttestations holds the EMS's challenge to each identity part it placed, by board and reference designator.
	PartAttestations = "part-attestations.json"
	// PlatformCertType is the predicate type of a board's platform certificate.
	PlatformCertType = "https://github.com/Horiodino/hw-slsa/platform-certificate/v0.1"
	platformCARole   = "platform-ca"
)

// PlatformCertAtt is the envelope file name of a board's platform certificate.
func PlatformCertAtt(serial string) string { return "platform-" + serial + ".intoto.json" }

// BoardParts says where the physical parts are for a board build that
// checks component identities: the chips as shipped, one directory per part
// named by its marked serial, and where the built boards go, one directory
// per board holding one per placed identity part, named by reference
// designator.
type BoardParts struct {
	Chips, Boards string
}

// partAnswer is the EMS's challenge to one chip at build.
type partAnswer struct {
	serial, unit string
	nonce, sig   []byte
	cert         []byte
}

// attestComponents challenges each chip shipped to the EMS, as marked by
// serial, and checks the answer under the identity CAs of the chip's trust
// root. It returns the answers in shipping order.
func attestComponents(chip, chipParts string, serials []string) ([]partAnswer, error) {
	trust, _, err := partTrust(chip)
	if err != nil {
		return nil, err
	}
	var out []partAnswer
	for _, serial := range serials {
		nonce, der, sig, err := ChallengeUnit(filepath.Join(chipParts, serial))
		if err != nil {
			return nil, fmt.Errorf("board-assembly: chip %s does not answer an identity challenge: %w", serial, err)
		}
		cert, _, err := identityCert(trust, der, "board-assembly: chip "+serial)
		if err != nil {
			return nil, err
		}
		if !answered(cert, nonce, sig) {
			return nil, failf("board-assembly: chip %s does not answer under its certificate", serial)
		}
		out = append(out, partAnswer{serial: serial, unit: sha256Bytes(der), nonce: nonce, sig: sig, cert: der})
	}
	return out, nil
}

// identityCertRef is where a unit's certificate is in the chip bundle, from
// its die identities.
func identityCertRef(chip, unit string) (string, error) {
	ids, err := ReadObj(filepath.Join(chip, "artifacts", DieIdentities))
	if err != nil {
		return "", err
	}
	for _, e := range Objs(ids, "dies") {
		if S(e, "certificate", "digest", "sha256") == unit {
			return trimFileURI(S(e, "certificate", "uri")), nil
		}
	}
	return "", fmt.Errorf("unit %s has no identity in the chip bundle", short(unit))
}

// signPlatformCert signs the platform certificate of one board.
func signPlatformCert(bundle, keys, mfr string, product Obj, serial string, a1 Obj, placements Obj, mpnMfr map[string]string) error {
	var comps []any
	for _, ref := range sortedKeys(placements) {
		p := O(placements, ref)
		c := Obj{"refDes": ref, "manufacturer": mpnMfr[S(p, "mpn")], "mpn": get(p, "mpn"), "lot": get(p, "lot")}
		if Has(p, "unit") {
			c["identity"] = Obj{"certificateDigest": Obj{"sha256": get(p, "unit")}}
		}
		comps = append(comps, c)
	}
	stmt, err := statement([]Obj{boardRD(mfr, serial)}, PlatformCertType, Obj{
		"platform": Obj{
			"manufacturer": mfr, "model": S(product, "partNumber"), "revision": get(product, "revision"), "serial": serial,
		},
		"assemblyRef": Obj{"uri": "file:" + S(a1, "name"), "digest": get(a1, "digest")},
		"components":  comps,
	})
	if err != nil {
		return err
	}
	signer, err := LoadSigner(filepath.Join(keys, platformCARole+".key.pem"))
	if err != nil {
		return err
	}
	_, err = Sign(stmt, signer, filepath.Join(bundle, "att", PlatformCertAtt(serial)))
	return err
}

// boardAttestations reads the EMS's part attestations, when A1 names them,
// and returns them by board, then reference designator, with a map from each
// chip's marked serial to its unit name.
func boardAttestations(bundle string, a1 Obj) (Obj, map[string]string, error) {
	path := filepath.Join(bundle, "artifacts", PartAttestations)
	if !sha256Set(Objs(a1, "subject"))[S(fileDigest(path), "sha256")] {
		return nil, nil, nil
	}
	att, err := ReadObj(path)
	if err != nil {
		return nil, nil, failf("board-assembly: %v", err)
	}
	shippedAs := map[string]string{}
	for _, serial := range sortedKeys(O(att, "chips")) {
		shippedAs[serial] = S(att, "chips", serial, "unit")
	}
	return att, shippedAs, nil
}

// boardL3 runs the Assembly L3 rules over a board bundle BoardCheck has
// walked: the EMS and every shipper sign at accredited sites, every identity
// part on every board answered the EMS's challenge at build under its own
// certificate, every board in the lot has a platform certificate that names
// exactly what was placed on it, and, at receipt, the identity parts on each
// received board answer a challenge with the certificates it names.
func boardL3(bundle string, trust *TrustRoot, pol, a1 Obj, att Obj, builds Obj, mfr string, boards []string, idParts map[string]string, shipments []string, received []string, boardsDir string) error {
	if err := keyAccredited(trust, pol, filepath.Join(bundle, "att", BoardA1), emsRole, "Assembly L3: board-assembly"); err != nil {
		return err
	}
	for _, rel := range shipments {
		ship, err := DecodeEnvelope(filepath.Join(bundle, rel))
		if err != nil {
			return err
		}
		shipper := S(ship, "predicate", "hwMfg", "site", "name")
		if err := keyAccredited(trust, pol, filepath.Join(bundle, rel), S(pol, "shippers", shipper, "role"), "Assembly L3: "+filepath.Base(rel)); err != nil {
			return err
		}
	}
	if len(idParts) == 0 {
		return nil
	}
	if att == nil {
		return failf("Assembly L3: board-assembly: the record names no %s, so no part with a hardware identity was checked at build", PartAttestations)
	}
	for _, chipRel := range sortedKeys(anyMap(idParts)) {
		if err := keyAccredited(trust, pol, filepath.Join(bundle, "att", ReceiptAtt(idParts[chipRel])), emsRole, "Assembly L3: receipt of "+idParts[chipRel]); err != nil {
			return err
		}
	}
	// Every chip the EMS received answered its challenge under its own certificate.
	nonces := map[string]bool{}
	for _, chipSerial := range sortedKeys(O(att, "chips")) {
		e := O(att, "chips", chipSerial)
		where := "Assembly L3: chip " + chipSerial
		chip := filepath.Join(bundle, S(e, "chipBundle"))
		der, err := os.ReadFile(filepath.Join(chip, "artifacts", trimFileURI(S(e, "certificate"))))
		if err != nil || sha256Bytes(der) != S(e, "unit") {
			return failf("%s: the certificate it answered under is not in its chip's bundle", where)
		}
		ptrust, _, err := partTrust(chip)
		if err != nil {
			return err
		}
		cert, _, err := identityCert(ptrust, der, where)
		if err != nil {
			return err
		}
		nonce, err1 := hex.DecodeString(S(e, "nonce"))
		sig, err2 := base64.StdEncoding.DecodeString(S(e, "signature"))
		if err1 != nil || err2 != nil || len(nonce) < 16 || nonces[S(e, "nonce")] {
			return failf("%s: the challenge is not a fresh nonce of 16 bytes or more", where)
		}
		nonces[S(e, "nonce")] = true
		if !answered(cert, nonce, sig) {
			return failf("%s: the answer at build does not verify under the part's certificate", where)
		}
	}
	// Every identity part on every board is one of them.
	for _, serial := range sortedKeys(builds) {
		placements := O(builds, serial, "placements")
		for _, ref := range sortedKeys(placements) {
			p := O(placements, ref)
			if !Has(p, "unit") {
				continue
			}
			chipSerial := S(att, "boards", serial, ref)
			if chipSerial == "" || S(att, "chips", chipSerial, "unit") != S(p, "unit") {
				return failf("Assembly L3: board %s %s: the part was not checked by attestation at build", serial, ref)
			}
		}
	}
	a1RD := relRD(bundle, "att/"+BoardA1)
	certs := map[string]Obj{}
	for _, serial := range boards {
		where := "Assembly L3: board " + serial
		stmt, err := trust.Open(filepath.Join(bundle, "att", PlatformCertAtt(serial)), platformCARole, PlatformCertType)
		if err != nil {
			return err
		}
		if !jsonEqual(firstSubject(stmt), boardRD(mfr, serial)) {
			return failf("%s: the platform certificate is for another board", where)
		}
		p := O(stmt, "predicate")
		if S(p, "platform", "serial") != serial || !jsonEqual(get(p, "assemblyRef", "digest"), a1RD["digest"]) {
			return failf("%s: the platform certificate does not bind this board to this assembly record", where)
		}
		placements := O(builds, serial, "placements")
		comps := Objs(p, "components")
		if len(comps) != len(placements) {
			return failf("%s: the platform certificate lists %d components, but %d were placed", where, len(comps), len(placements))
		}
		for _, c := range comps {
			pl := O(placements, S(c, "refDes"))
			want := ""
			if Has(pl, "unit") {
				want = S(pl, "unit")
			}
			if pl == nil || S(c, "mpn") != S(pl, "mpn") || !jsonEqual(get(c, "lot"), get(pl, "lot")) || S(c, "identity", "certificateDigest", "sha256") != want {
				return failf("%s: the platform certificate's %s is not the part placed there", where, S(c, "refDes"))
			}
		}
		certs[serial] = p
	}
	if len(received) > 0 && boardsDir == "" {
		return failf("Assembly L3: the received boards were listed, not challenged; at L3 the identity parts on each board answer a challenge at receipt (pass the directory of boards to --boards)")
	}
	for _, serial := range received {
		for _, c := range Objs(certs[serial], "components") {
			want := S(c, "identity", "certificateDigest", "sha256")
			if want == "" {
				continue
			}
			where := fmt.Sprintf("received board %s %s", serial, S(c, "refDes"))
			chip := filepath.Join(bundle, S(att, "chips", S(att, "boards", serial, S(c, "refDes")), "chipBundle"))
			ptrust, _, err := partTrust(chip)
			if err != nil {
				return err
			}
			if _, err := checkChallenge(ptrust, filepath.Join(boardsDir, serial, S(c, "refDes")), want, where); err != nil {
				return err
			}
		}
	}
	return nil
}

func anyMap(m map[string]string) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}
