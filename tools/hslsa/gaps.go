package hslsa

// Gaps in the chain (spec section "Where the chain is checked"): before a
// receipt check walks the chain, it looks for every record it will need and
// reports all that are missing, or that withhold a field nobody disclosed,
// with the track each belongs to. The check still fails, but the buyer sees
// every gap at once instead of the first broken link. Records the policy
// does not require, and that the bundle does not have, are reported as not
// recorded, without failing.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// mfgTrack is the track a chip manufacturing record belongs to; a transfer
// belongs to the track of the step that ships it.
func mfgTrack(step string) string {
	if from, ok := strings.CutPrefix(step, "transfer-"); ok {
		step = from
	}
	switch step {
	case "wafer-fab", "wafer-sort":
		return "Wafer track"
	case "packaging", "final-test":
		return "Package/Test track"
	}
	return "Assembly track"
}

// recordGaps reports a record that is missing, or that withholds a field
// with no disclosure in the bundle. Anything else wrong with the record is
// left to the check that opens it.
func recordGaps(path, where string) []string {
	name := filepath.Base(path)
	if _, err := os.Stat(path); err != nil {
		return []string{fmt.Sprintf("missing attestation %s (%s)", name, where)}
	}
	stmt, err := DecodeEnvelope(path)
	if err != nil {
		return nil
	}
	entries := Withheld(stmt)
	if len(entries) == 0 {
		return nil
	}
	if _, err := os.Stat(disclosurePath(path)); err == nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		paths = append(paths, S(e, "path"))
	}
	if _, err := checkPaths(S(stmt, "predicateType"), paths); err != nil {
		return nil
	}
	var out []string
	for _, p := range paths {
		out = append(out, fmt.Sprintf("%s: %s is withheld and no disclosure was given (%s)", name, p, where))
	}
	return out
}

// gapError fails a check with every gap it found.
func gapError(check string, gaps []string) error {
	if len(gaps) == 0 {
		return nil
	}
	return failf("%s: %d gap(s) in the chain: %s", check, len(gaps), strings.Join(gaps, "; "))
}

// chipGaps scans a chip bundle for the lot receipt check: F1 to F4, the
// transfers between them, and the HBOM. It returns the gaps that fail the
// check and the optional records the bundle does not have.
func chipGaps(bundle string, policy Obj) (gaps, notRecorded []string) {
	required := Truthy(get(policy, "manufacturing", "requireTransfers"))
	for i, step := range MfgSteps {
		if i > 0 {
			from := MfgSteps[i-1]
			path := filepath.Join(bundle, "att", TransferAtt(from))
			if _, err := os.Stat(path); err == nil || required {
				gaps = append(gaps, recordGaps(path, mfgTrack(from))...)
			} else {
				notRecorded = append(notRecorded, fmt.Sprintf("transfer from %s to %s (%s)", from, step, mfgTrack(from)))
			}
		}
		gaps = append(gaps, recordGaps(filepath.Join(bundle, "att", MfgAtt[step]), mfgTrack(step))...)
	}
	gaps = append(gaps, recordGaps(filepath.Join(bundle, "att", "hbom.intoto.json"), "product HBOM")...)
	return gaps, notRecorded
}

// transferCheck verifies the transfer that leaves step from, when the bundle
// has one: signed by the shipping site, linked to the record that shipped,
// naming the same design release, from the site that signed that record to
// the site that signed receiver, and shipping exactly the lot it names. It
// returns the transfer's envelope for the receiving step to link to, or nil
// when there is no transfer. A shipper that signs nothing may have its
// transfer proxy-signed by the site that received the shipment; the check
// then also returns a line saying so.
func transferCheck(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, from string, stmts map[string]Obj, receiver, prev Obj) (Obj, string, error) {
	path := filepath.Join(bundle, "att", TransferAtt(from))
	if _, err := os.Stat(path); err != nil {
		return nil, "", nil
	}
	label := "transfer from " + from
	t, by, err := openRecord(trust, path, MfgSigner[from], ProxySigner[from])
	if err != nil {
		return nil, "", err
	}
	if buildType(t) != mfgStepType("distribution") {
		return nil, "", failf("%s: wrong buildType", label)
	}
	note := ""
	if by != "" {
		if note, err = onBehalfCheck(bundle, policy, t, label, "transfer-"+from, by); err != nil {
			return nil, "", err
		}
		if !jsonEqual(get(t, "predicate", "hwMfg", "proxy", "signer"), get(t, "predicate", "hwMfg", "receiver")) {
			return nil, "", failf("%s: signed on the shipper's behalf by %s, which did not receive the shipment", label, S(t, "predicate", "hwMfg", "proxy", "signer", "name"))
		}
	}
	if err := asSLSAProvenance(t, label); err != nil {
		return nil, "", err
	}
	if err := requireGates(t, label, "hwMfg"); err != nil {
		return nil, "", err
	}
	if err := requireFiles(bundle, t, label); err != nil {
		return nil, "", err
	}
	if err := requireLink(t, label, []Obj{prev}, "shipping step"); err != nil {
		return nil, "", err
	}
	hw := O(t, "predicate", "hwMfg")
	if !jsonEqual(get(hw, "designRef", "digest"), get(design.Final, "digest")) ||
		!jsonEqual(get(hw, "designRef", "release", "digest"), get(design.Release, "digest")) {
		return nil, "", failf("%s: designRef names a different design release", label)
	}
	sender := O(stmts[from], "predicate", "hwMfg", "site")
	to := O(receiver, "predicate", "hwMfg", "site")
	if !jsonEqual(get(hw, "site"), sender) {
		return nil, "", failf("%s: shipped by %s, not by %s, which signed %s", label, S(hw, "site", "name"), S(sender, "name"), from)
	}
	if !jsonEqual(get(hw, "receiver"), to) {
		return nil, "", failf("%s: shipped to %s, but %s signed the next step", label, S(hw, "receiver", "name"), S(to, "name"))
	}
	list, err := ReadObj(filepath.Join(bundle, "artifacts", S(firstSubject(t), "name")))
	if err != nil {
		return nil, "", failf("%s: packing list: %v", label, err)
	}
	if !jsonEqual(get(list, "from"), sender) || !jsonEqual(get(list, "to"), to) {
		return nil, "", failf("%s: packing list names other sites than the record", label)
	}
	lot := firstSubject(stmts[transferLot[from]])
	items := Strs(list, "items")
	quantity, _ := Int(list, "quantity")
	if d, err := LotDigest(items); S(list, "lot") != S(lot, "name") || err != nil || d != S(lot, "digest", "sha256") || quantity != int64(len(items)) {
		return nil, "", failf("%s: packing list does not ship exactly %s", label, S(lot, "name"))
	}
	return envRD(bundle, TransferAtt(from)), note, nil
}

// boardGaps scans a board bundle for the board receipt check: the board
// HBOM, A1, every shipment record the HBOM names, and the EMS's receipt VSA
// for each part with its own chain. A part's own chain is scanned by its lot
// receipt check.
func boardGaps(bundle string) []string {
	hbPath := filepath.Join(bundle, "att", BoardHBOM)
	gaps := recordGaps(hbPath, "board HBOM")
	gaps = append(gaps, recordGaps(filepath.Join(bundle, "att", BoardA1), "Assembly track")...)
	hb, err := DecodeEnvelope(hbPath)
	if err != nil {
		return gaps
	}
	seen := map[string]bool{}
	for _, part := range Objs(hb, "predicate", "parts") {
		var rels []string
		if Has(part, "distributionRef") {
			rels = append(rels, strings.TrimPrefix(S(part, "distributionRef", "uri"), "file:"))
		}
		if Has(part, "hbomRef") {
			rels = append(rels, "att/"+ReceiptAtt(S(part, "lot")))
		}
		for _, rel := range rels {
			if !seen[rel] {
				seen[rel] = true
				gaps = append(gaps, recordGaps(filepath.Join(bundle, rel), "Assembly track")...)
			}
		}
	}
	return gaps
}
