package hslsa

// Verifier escrow (spec section "Verifier escrow"). An auditor the buyer
// trusts receives the full bundle with its disclosures, runs the tapeout and
// lot receipt checks for the units one buyer received, under that buyer's
// policy, and signs two VSAs: one for the design and one for the received
// units. The buyer receives only those VSAs. Both name one input, the escrow
// manifest, which lists by digest everything the auditor checked; the auditor
// keeps it, so a dispute can later show what was checked without the buyer
// ever seeing how many records there were.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// AuditorRole signs escrow VSAs in the buyer's trust root.
	AuditorRole = "auditor"
	// EscrowDesignVSA and EscrowReceiptVSA are the escrow VSAs' file names.
	EscrowDesignVSA  = "design.vsa.intoto.json"
	EscrowReceiptVSA = "receipt.vsa.intoto.json"
)

// ReceiptSubject names the units a buyer received from a shipped lot:
// urn:hslsa:receipt:<lot-id>, digested with the lot digest formula over
// exactly those units, so the buyer can recompute it from its own list.
func ReceiptSubject(lotURN string, units []string) (Obj, error) {
	id, ok := strings.CutPrefix(lotURN, "urn:hslsa:lot:")
	if !ok || id == "" {
		return nil, fmt.Errorf("%s is not a shipped lot", lotURN)
	}
	if len(units) == 0 {
		return nil, fmt.Errorf("no received units")
	}
	d, err := LotDigest(units)
	if err != nil {
		return nil, err
	}
	return rd("urn:hslsa:receipt:"+id, d), nil
}

// treeRDs describes every file under dir by its path relative to bundle.
func treeRDs(bundle, dir string) ([]Obj, error) {
	var out []Obj
	root := filepath.Join(bundle, dir)
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return out, nil
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(bundle, path)
		if err != nil {
			return err
		}
		out = append(out, relRD(bundle, filepath.ToSlash(rel)))
		return nil
	})
	return out, err
}

// EscrowAudit is the auditor's side: the full tapeout and lot receipt checks
// on a bundle that carries its disclosures, for the units the buyer received
// under the buyer's policy, then the escrow manifest and the two VSAs.
func EscrowAudit(bundle string, trust *TrustRoot, policyPath, unitsPath, key, vsaDir, manifestPath string) error {
	policy, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	units, err := ReadUnits(unitsPath)
	if err != nil {
		return err
	}
	if len(units) == 0 {
		return fmt.Errorf("%s lists no received units", unitsPath)
	}
	design, lot, err := Verify(bundle, trust, policyPath, unitsPath, "", "")
	if err != nil {
		return err
	}
	receipt, err := ReceiptSubject(S(lot.Lot, "name"), units)
	if err != nil {
		return err
	}
	policyRD, err := fileRD(policyPath, "")
	if err != nil {
		return err
	}
	files, err := treeRDs(bundle, "artifacts")
	if err != nil {
		return err
	}
	disclosures, err := treeRDs(bundle, "disclosures")
	if err != nil {
		return err
	}
	records, err := treeRDs(bundle, "att")
	if err != nil {
		return err
	}
	manifest := Obj{
		"verifier":    Obj{"id": VerifierID},
		"policy":      policyRD,
		"design":      design.Final,
		"lot":         lot.Lot,
		"receipt":     receipt,
		"records":     records,
		"files":       nonNil(files),
		"disclosures": nonNil(disclosures),
	}
	if err := WriteJSON(manifestPath, manifest); err != nil {
		return err
	}
	manifestRD, err := fileRD(manifestPath, "")
	if err != nil {
		return err
	}
	claims := O(policy, "claims")
	if err := signVSA(designTracks, design.Final, "hslsa:design:"+S(design.Final, "name"), claims["design"], []Obj{manifestRD},
		policyPath, key, filepath.Join(vsaDir, EscrowDesignVSA)); err != nil {
		return err
	}
	if err := signVSA(lotTracks, receipt, S(lot.Lot, "name"), vsaLevels(claims["lot"], len(lot.Simulated) > 0), []Obj{manifestRD},
		policyPath, key, filepath.Join(vsaDir, EscrowReceiptVSA)); err != nil {
		return err
	}
	fmt.Printf("escrow audit: VSAs for the design and %d received units written to %s; manifest of %d records, %d files and %d disclosure files kept at %s\n",
		len(units), vsaDir, len(records), len(files), len(disclosures), manifestPath)
	return nil
}

// openEscrowVSA opens a VSA signed by the auditor and checks that it passed
// under the buyer's policy and states every level the buyer asks for.
func openEscrowVSA(path string, trust *TrustRoot, policy Obj, policyDigest string, levels []string) (Obj, error) {
	label := filepath.Base(path)
	stmt, err := trust.Open(path, AuditorRole, VSAType)
	if err != nil {
		return nil, err
	}
	p := O(stmt, "predicate")
	if S(p, "verifier", "id") != VerifierID {
		return nil, failf("%s: verifier %s, want %s", label, S(p, "verifier", "id"), VerifierID)
	}
	if S(p, "verificationResult") != "PASSED" {
		return nil, failf("%s: verification result %s", label, S(p, "verificationResult"))
	}
	if S(p, "policy", "digest", "sha256") != policyDigest {
		return nil, failf("%s: verified under a policy other than the buyer's", label)
	}
	if err := refuseSimulatedVSA(stmt, policy, label); err != nil {
		return nil, err
	}
	have := Strs(p, "verifiedLevels")
	for _, l := range levels {
		if !contains(have, l) {
			return nil, failf("%s: does not state %s", label, l)
		}
	}
	if len(Objs(stmt, "subject")) != 1 {
		return nil, failf("%s: a VSA names one subject", label)
	}
	return stmt, nil
}

// EscrowCheck is the buyer's side: the auditor's two VSAs verify under the
// auditor key in the buyer's trust root, passed under the buyer's own policy,
// state every level the policy claims, come from one audit, and the receipt
// covers exactly the units the buyer received.
func EscrowCheck(vsaDir string, trust *TrustRoot, policyPath, unitsPath string) error {
	policy, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	policyDigest, err := sha256File(policyPath)
	if err != nil {
		return err
	}
	units, err := ReadUnits(unitsPath)
	if err != nil {
		return err
	}
	claims := O(policy, "claims")
	design, err := openEscrowVSA(filepath.Join(vsaDir, EscrowDesignVSA), trust, policy, policyDigest, Strs(claims, "design"))
	if err != nil {
		return err
	}
	receipt, err := openEscrowVSA(filepath.Join(vsaDir, EscrowReceiptVSA), trust, policy, policyDigest, Strs(claims, "lot"))
	if err != nil {
		return err
	}
	lotURN := S(receipt, "predicate", "resourceUri")
	want, err := ReceiptSubject(lotURN, units)
	if err != nil {
		return failf("%s: %v", EscrowReceiptVSA, err)
	}
	got := firstSubject(receipt)
	if S(got, "name") != S(want, "name") || !jsonEqual(get(got, "digest"), get(want, "digest")) {
		return failf("%s: covers other units than the %d received from %s", EscrowReceiptVSA, len(units), lotURN)
	}
	in := A(design, "predicate", "inputAttestations")
	if len(in) != 1 || !jsonEqual(in, A(receipt, "predicate", "inputAttestations")) {
		return failf("the design and receipt VSAs do not name the same escrow manifest")
	}
	final := firstSubject(design)
	fmt.Printf("escrow check: PASSED, the auditor verified %s sha256:%s at %s and the %d received units of %s at %s\n",
		S(final, "name"), S(final, "digest", "sha256"), pyList(get(design, "predicate", "verifiedLevels")),
		len(units), lotURN, pyList(get(receipt, "predicate", "verifiedLevels")))
	return nil
}
