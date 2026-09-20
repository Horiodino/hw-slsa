package hslsa

// Records signed on a supplier's behalf (spec: Proxy signing). Suppliers
// will not sign at first, so the party that received from a supplier (the
// next site in the chain, or the product owner after final test) may sign
// for it, with its own key:
//
//   - a proxy-signed record is the step's full record, built from the
//     supplier's own data export, which the bundle carries by digest;
//   - an evidence record stands in for a step the supplier left no data for,
//     only a certificate, audit report or paper record, named by digest.
//
// Both carry hwMfg.proxy, which names the signer, so a buyer's policy can
// refuse them, and both hold their track at L1.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProxySigner is the trust-root role of the party that may sign each chip
// manufacturing step on its supplier's behalf: whoever received the step's
// output. After final test that is the product owner.
var ProxySigner = map[string]string{
	"wafer-fab": "sort-site", "wafer-sort": "osat-site", "packaging": "test-site", "final-test": "product-owner",
}

// EvidenceSteps are the steps an evidence record may stand in for. Every
// other chip step names a lot (the wafer lot, the packaged lot, the shipped
// lot) that later records and the HBOM bind to by digest, which a document
// cannot do; a supplier that signs none of those needs a proxy-signed record.
var EvidenceSteps = []string{"wafer-sort"}

// EvidenceKinds are the kinds of document an evidence record may name.
var EvidenceKinds = []string{"certificate", "audit-report", "paper-record", "other"}

// OnBehalfKinds are the values of the policy's manufacturing.acceptOnBehalf.
const (
	ByProxy    = "proxy"
	ByEvidence = "evidence"
)

// ExportName is the data file a supplier hands its proxy for step.
func ExportName(step string) string { return "supplier-export-" + step + ".json" }

// proxyBuilder is the builder.id of a record signed on a supplier's behalf,
// so a SLSA verifier that reads only builder.id does not take it for the
// supplier's own.
func proxyBuilder(signer Obj) string { return "urn:hslsa:proxy:" + slug(S(signer, "name")) }

// onBehalf is how the scenario says a step's supplier signs nothing:
// scenario.unsigned.<step>.cover is "proxy" or "evidence". It returns the
// signing details mfgRecord needs (kind, role, signer), or nil when the
// supplier signs its own record.
func onBehalf(sc Obj, step string) (Obj, error) {
	u := O(sc, "unsigned", step)
	if u == nil {
		return nil, nil
	}
	kind := S(u, "cover")
	if kind != ByProxy && kind != ByEvidence {
		return nil, fmt.Errorf("scenario unsigned.%s.cover must be %q or %q", step, ByProxy, ByEvidence)
	}
	if kind == ByEvidence && !contains(EvidenceSteps, step) {
		return nil, fmt.Errorf("scenario unsigned.%s: an evidence record can stand in only for %s", step, strings.Join(EvidenceSteps, ", "))
	}
	i := indexOf(MfgSteps, step)
	if i < 0 {
		return nil, fmt.Errorf("scenario unsigned.%s: not a manufacturing step", step)
	}
	signer := O(sc, "product", "manufacturer")
	if i+1 < len(MfgSteps) {
		next := MfgSteps[i+1]
		if O(sc, "unsigned", next) != nil {
			return nil, fmt.Errorf("scenario unsigned.%s: %s receives from it but signs nothing either", step, next)
		}
		signer = O(sc, scenarioKey[next], "site")
	}
	return Obj{"kind": kind, "role": ProxySigner[step], "signer": signer}, nil
}

// scenarioKey is the scenario block that describes each manufacturing step.
var scenarioKey = map[string]string{"wafer-fab": "fab", "wafer-sort": "sort", "packaging": "packaging", "final-test": "finalTest"}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// writeExport writes what the supplier handed its proxy for one record: its
// site, the step's parameters, every hwMfg field it reported, and the
// content of every data file the record names. The proxy signs only what
// this file says, and the verifier checks the record against it.
func writeExport(bundle, step string, subjects []Obj, external, hw Obj) (Obj, error) {
	record := Obj{}
	for k, v := range hw {
		if k != "site" && k != "designRef" {
			record[k] = v
		}
	}
	files := Obj{}
	for _, s := range subjects {
		name := S(s, "name")
		if strings.HasPrefix(name, "urn:") {
			continue
		}
		v, err := ReadObj(filepath.Join(bundle, "artifacts", name))
		if err != nil {
			return nil, fmt.Errorf("%s: supplier export: %w", step, err)
		}
		files[name] = v
	}
	path := filepath.Join(bundle, "artifacts", ExportName(step))
	if err := WriteJSON(path, Obj{"supplier": get(hw, "site"), "step": step, "externalParameters": external,
		"record": record, "files": files}); err != nil {
		return nil, err
	}
	return fileRD(path, "")
}

// writeDocuments writes the evidence documents the scenario gives as text
// (a scanned certificate or traveller in a real chain) and returns them as
// subjects, with their entries for hwMfg.evidence.documents.
func writeDocuments(bundle, step string, sc Obj) (subjects, docs []Obj, err error) {
	for _, d := range Objs(sc, "unsigned", step, "documents") {
		name := S(d, "name")
		if name == "" || strings.ContainsAny(name, `/\`) || !contains(EvidenceKinds, S(d, "kind")) {
			return nil, nil, fmt.Errorf("scenario unsigned.%s.documents: each needs a plain file name and a kind of %s", step, strings.Join(EvidenceKinds, ", "))
		}
		path := filepath.Join(bundle, "artifacts", name)
		if err := os.WriteFile(path, []byte(S(d, "text")), 0o644); err != nil {
			return nil, nil, err
		}
		s, err := fileRD(path, "")
		if err != nil {
			return nil, nil, err
		}
		subjects = append(subjects, s)
		docs = append(docs, Obj{"name": name, "kind": d["kind"], "issuer": d["issuer"]})
	}
	if len(subjects) == 0 {
		return nil, nil, fmt.Errorf("scenario unsigned.%s: an evidence record needs at least one document", step)
	}
	return subjects, docs, nil
}

// openRecord opens a manufacturing record: signed by role, or by proxyRole
// when the record says it was signed on its supplier's behalf. It returns
// "proxy", "evidence" or "" for a supplier's own record. Which role to check
// is read from the payload before its signature is checked, so a record
// cannot lie about it: a supplier's record that claims a proxy fails
// against the proxy's key, and a proxy's record that hides it fails against
// the supplier's.
func openRecord(trust *TrustRoot, path, role, proxyRole string) (Obj, string, error) {
	peek, err := DecodeEnvelope(path)
	if err == nil && Has(O(peek, "predicate", "hwMfg"), "proxy") {
		role = proxyRole
	}
	stmt, err := trust.Open(path, role, MfgStep)
	if err != nil {
		return nil, "", err
	}
	if !Has(O(stmt, "predicate", "hwMfg"), "proxy") {
		return stmt, "", nil
	}
	if buildType(stmt) == mfgStepType("evidence") {
		return stmt, ByEvidence, nil
	}
	return stmt, ByProxy, nil
}

// onBehalfCheck checks a record signed on its supplier's behalf, as far as
// the record alone allows: the policy accepts that kind of record, the
// builder says it is a proxy, and either the supplier's export backs every
// value (proxy) or the documents are named and of a known kind (evidence).
// Who signed it is checked by the caller once the receiving party is known.
// It returns a line for the check's output.
func onBehalfCheck(bundle string, policy, stmt Obj, label, step, kind string) (string, error) {
	hw := O(stmt, "predicate", "hwMfg")
	proxy := O(hw, "proxy")
	signer, supplier := S(proxy, "signer", "name"), S(hw, "site", "name")
	if !contains(Strs(policy, "manufacturing", "acceptOnBehalf"), kind) {
		what := "proxy-signed records"
		if kind == ByEvidence {
			what = "evidence records"
		}
		return "", failf("%s: signed by %s on behalf of %s, and the policy does not accept %s (manufacturing.acceptOnBehalf)", label, signer, supplier, what)
	}
	if signer == "" || supplier == "" || signer == supplier {
		return "", failf("%s: a record signed on a supplier's behalf must name the supplier as hwMfg.site and another party as hwMfg.proxy.signer", label)
	}
	if S(stmt, "predicate", "runDetails", "builder", "id") != proxyBuilder(O(proxy, "signer")) {
		return "", failf("%s: builder.id must be %s, the proxy that signed it", label, proxyBuilder(O(proxy, "signer")))
	}
	if kind == ByEvidence {
		if err := evidenceCheck(stmt, label, step); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s: evidence record signed by %s for %s", label, signer, supplier), nil
	}
	if err := exportCheck(bundle, stmt, label, step); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: proxy-signed by %s for %s", label, signer, supplier), nil
}

// evidenceCheck checks that an evidence record stands in for step, a step
// evidence may cover, and names each of its subjects as a document.
func evidenceCheck(stmt Obj, label, step string) error {
	ev := O(stmt, "predicate", "hwMfg", "evidence")
	if S(ev, "covers") != step {
		return failf("%s: evidence record covers %q, not %s", label, S(ev, "covers"), step)
	}
	if !contains(EvidenceSteps, step) {
		return failf("%s: an evidence record cannot stand in for %s, whose lot later records name; it needs a proxy-signed record", label, step)
	}
	docs := map[string]bool{}
	for _, d := range Objs(ev, "documents") {
		if !contains(EvidenceKinds, S(d, "kind")) || S(d, "issuer") == "" {
			return failf("%s: document %s needs an issuer and a kind of %s", label, S(d, "name"), strings.Join(EvidenceKinds, ", "))
		}
		docs[S(d, "name")] = true
	}
	subjects := Objs(stmt, "subject")
	if len(subjects) == 0 || len(subjects) != len(docs) {
		return failf("%s: every subject of an evidence record must be one of its documents", label)
	}
	for _, s := range subjects {
		if !docs[S(s, "name")] {
			return failf("%s: subject %s is not one of its documents", label, S(s, "name"))
		}
	}
	return nil
}

// exportCheck checks a proxy-signed record against the supplier's export it
// names: same supplier and step, same parameters, every hwMfg field the
// supplier reported, and every data file it names with the content the
// supplier gave. That shows the proxy added nothing the supplier did not
// report; it cannot show the supplier's data is true, which is why the
// track stays at L1.
func exportCheck(bundle string, stmt Obj, label, step string) error {
	pred := O(stmt, "predicate")
	hw := O(pred, "hwMfg")
	sources := Objs(hw, "proxy", "source")
	if len(sources) != 1 {
		return failf("%s: hwMfg.proxy.source must name the supplier's export", label)
	}
	name := S(sources[0], "name")
	d := fileDigest(filepath.Join(bundle, "artifacts", name))
	if d == nil {
		return failf("%s: the supplier's export %s is missing from the bundle", label, name)
	}
	if d["sha256"] != S(sources[0], "digest", "sha256") {
		return failf("%s: the supplier's export %s does not match its digest", label, name)
	}
	export, err := ReadObj(filepath.Join(bundle, "artifacts", name))
	if err != nil {
		return failf("%s: supplier export: %v", label, err)
	}
	if !jsonEqual(get(export, "supplier"), get(hw, "site")) || S(export, "step") != step {
		return failf("%s: the supplier's export is for another supplier or step", label)
	}
	if !jsonEqual(get(export, "externalParameters"), get(pred, "buildDefinition", "externalParameters")) {
		return failf("%s: externalParameters differ from the supplier's export", label)
	}
	record := O(export, "record")
	for _, k := range sortedKeys(record) {
		if !jsonEqual(get(hw, k), record[k]) {
			return failf("%s: hwMfg.%s differs from the supplier's export", label, k)
		}
	}
	files := O(export, "files")
	for _, s := range Objs(stmt, "subject") {
		n := S(s, "name")
		if strings.HasPrefix(n, "urn:") {
			continue
		}
		if !Has(files, n) {
			return failf("%s: subject %s is not in the supplier's export", label, n)
		}
		v, err := ReadObj(filepath.Join(bundle, "artifacts", n))
		if err != nil || !jsonEqual(v, files[n]) {
			return failf("%s: %s differs from the supplier's export", label, n)
		}
	}
	return nil
}

// trackLevelKey is how a policy claim names each chip manufacturing track.
var trackLevelKey = map[string]string{"Wafer track": "WAFER", "Package/Test track": "PACKAGE_TEST"}

// capAtL1 fails when the policy claims more than L1 for a track that has a
// record signed on a supplier's behalf.
func capAtL1(policy Obj, capped map[string]string) error {
	for _, track := range sortedKeys(capped) {
		if n := trackClaim(policy, trackLevelKey[track]); n > 1 {
			name := strings.TrimSuffix(track, " track")
			return failf("policy claims %s L%d, but %s was signed on its supplier's behalf, which holds the %s track at L1", name, n, capped[track], name)
		}
	}
	return nil
}

// shipperProxy is how a transfer is signed when the site shipping it signs
// nothing: by the same party that signs the shipping step for it, which is
// the site receiving the shipment, from the supplier's own packing list.
func shipperProxy(by Obj) Obj {
	if by == nil {
		return nil
	}
	return Obj{"kind": ByProxy, "role": by["role"], "signer": by["signer"]}
}

// removeStale removes files an earlier run left that this one does not write.
func removeStale(paths ...string) error {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
