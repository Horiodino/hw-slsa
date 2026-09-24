package hslsa

// What a pilot lot cost and revealed (roadmap phase 4, step 3): the buyer
// runs the receipt check on the lot and records whether it passed and why
// not, how long the check took, which company signed which records and
// which of their fields the buyer now holds, and the hours and money each
// party reports spending on the lot. One report per lot, and a summary
// over every lot measured into the same directory, to publish at the end.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MeasurementKind marks a pilot measurement report.
const MeasurementKind = "hslsa-pilot-measurement/v0.1"

type partyTally struct {
	org        Obj
	roles      map[string]bool
	records    int
	bytes      int64
	onBehalf   map[string]bool
	fields     map[string]bool
	recordList []string
}

// recordFields are the names of what a record tells its reader: its
// external parameters and every field of its hardware block (hwMfg,
// hwProvision and the like).
func recordFields(stmt Obj) []string {
	var out []string
	p := O(stmt, "predicate")
	for k := range O(p, "buildDefinition", "externalParameters") {
		out = append(out, "externalParameters."+k)
	}
	for block, v := range p {
		if !strings.HasPrefix(block, "hw") {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			for k := range m {
				out = append(out, block+"."+k)
			}
		}
	}
	return out
}

// PilotMeasure checks one lot as the buyer would and measures it.
func PilotMeasure(bundle, trustPath, policyPath, unitsPath, costsPath string) (Obj, error) {
	trustData, err := ReadObj(trustPath)
	if err != nil {
		return nil, err
	}
	trust, err := LoadTrustRoot(trustPath)
	if err != nil {
		return nil, err
	}
	policy, err := ReadObj(policyPath)
	if err != nil {
		return nil, err
	}

	// The receipt check, as the buyer runs it.
	start := time.Now()
	_, _, verr := Verify(bundle, trust, policyPath, unitsPath, "", "")
	elapsed := time.Since(start)
	check := Obj{"result": "pass", "seconds": float64(elapsed.Milliseconds()) / 1000, "claims": O(policy, "claims")}
	if verr != nil {
		if !IsVerificationError(verr) {
			return nil, verr
		}
		check["result"], check["failure"] = "fail", verr.Error()
	}

	// Who signed what: each signature's key, by its enrollment.
	type who struct{ role, org, orgName, site string }
	keys := map[string]who{}
	for role, list := range trust.Roles {
		for _, k := range list {
			keys[k.ID] = who{role: role, org: "unenrolled:" + role, orgName: "not enrolled (" + role + ")"}
		}
	}
	for _, e := range Objs(trustData, "enrollments") {
		keys[S(e, "keyid")] = who{S(e, "role"), S(e, "organization", "id"), S(e, "organization", "name"), S(e, "site", "name")}
	}
	parties := map[string]*partyTally{}
	var mismatches []any
	envs, err := filepath.Glob(filepath.Join(bundle, "att", "*.intoto.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(envs)
	for _, path := range envs {
		name := filepath.Base(path)
		raw, err := ReadObj(path)
		if err != nil {
			return nil, err
		}
		stmt, err := DecodeEnvelope(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		for _, sig := range Objs(raw, "signatures") {
			w, ok := keys[S(sig, "keyid")]
			if !ok {
				w = who{role: "unknown", org: "unknown", orgName: "key not in the trust root"}
			}
			t := parties[w.org]
			if t == nil {
				t = &partyTally{org: Obj{"name": w.orgName, "id": w.org}, roles: map[string]bool{}, onBehalf: map[string]bool{}, fields: map[string]bool{}}
				parties[w.org] = t
			}
			t.roles[w.role] = true
			t.records++
			t.bytes += info.Size()
			t.recordList = append(t.recordList, name)
			for _, f := range recordFields(stmt) {
				t.fields[f] = true
			}
			site := S(stmt, "predicate", "hwMfg", "site", "name")
			if Has(O(stmt, "predicate", "hwMfg"), "proxy") {
				t.onBehalf[site] = true
			} else if site != "" && w.site != "" && site != w.site {
				mismatches = append(mismatches, Obj{"record": name, "names": site, "keyEnrolledFor": w.site})
			}
		}
	}
	var partyList []any
	for _, id := range sortedKeys(parties) {
		t := parties[id]
		p := Obj{
			"organization":   t.org,
			"roles":          anyStrings(sortedKeys(t.roles)),
			"records":        t.records,
			"recordBytes":    t.bytes,
			"recordFiles":    anyStrings(t.recordList),
			"fieldsRevealed": anyStrings(sortedKeys(t.fields)),
		}
		if len(t.onBehalf) > 0 {
			p["signedOnBehalfOf"] = anyStrings(sortedKeys(t.onBehalf))
		}
		partyList = append(partyList, p)
	}
	var dataFiles int
	var dataBytes int64
	err = filepath.Walk(filepath.Join(bundle, "artifacts"), func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			dataFiles++
			dataBytes += fi.Size()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	lot := filepath.Base(bundle)
	if f4, err := DecodeEnvelope(filepath.Join(bundle, "att", MfgAtt["final-test"])); err == nil {
		if subs := Objs(f4, "subject"); len(subs) > 0 {
			lot = S(subs[0], "name")
		}
	}
	rep := Obj{
		"kind":       MeasurementKind,
		"lot":        lot,
		"measuredOn": Now(),
		"policy":     filepath.Base(policyPath),
		"trustRoot":  Obj{"builtAt": S(trustData, "builtAt"), "validUntil": S(trustData, "validUntil"), "keys": len(keys)},
		"check":      check,
		"parties":    nonNilAny(partyList),
		"dataFiles":  Obj{"count": dataFiles, "bytes": dataBytes},
	}
	if mismatches != nil {
		rep["siteMismatches"] = mismatches
	}
	if costsPath != "" {
		costs, err := readCosts(costsPath)
		if err != nil {
			return nil, err
		}
		rep["costs"] = costs
	}
	return rep, nil
}

// floatOf is a decoded JSON number as a float64.
func floatOf(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func nonNilAny(list []any) []any {
	if list == nil {
		return []any{}
	}
	return list
}

// readCosts reads what each party reports a lot cost it:
// {"entries": [{"party": "...", "hours": 2.5, "amount": 300, "currency": "USD", "note": "..."}]}
// and totals hours and money per currency.
func readCosts(path string) (Obj, error) {
	c, err := ReadObj(path)
	if err != nil {
		return nil, err
	}
	hours := 0.0
	money := map[string]float64{}
	for i, e := range Objs(c, "entries") {
		if S(e, "party") == "" {
			return nil, fmt.Errorf("%s: entry %d names no party", path, i)
		}
		h, okH := floatOf(e["hours"])
		a, okA := floatOf(e["amount"])
		if (Has(e, "hours") && (!okH || h < 0)) || (Has(e, "amount") && (!okA || a < 0 || S(e, "currency") == "")) {
			return nil, fmt.Errorf("%s: entry %d: hours and amount must be numbers of zero or more, and an amount needs a currency", path, i)
		}
		hours += h
		if okA {
			money[S(e, "currency")] += a
		}
	}
	totals := Obj{"hours": hours}
	if len(money) > 0 {
		m := Obj{}
		for k, v := range money {
			m[k] = v
		}
		totals["amount"] = m
	}
	return Obj{"entries": A(c, "entries"), "total": totals}, nil
}

// PilotMeasurementMarkdown is one lot's report for people.
func PilotMeasurementMarkdown(rep Obj) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Pilot lot %s\n\n", S(rep, "lot"))
	c := O(rep, "check")
	fmt.Fprintf(&b, "Receipt check: **%s** in %v s, under policy `%s` and a trust root built %s.\n",
		strings.ToUpper(S(c, "result")), get(c, "seconds"), S(rep, "policy"), orDash(S(rep, "trustRoot", "builtAt")))
	if f := S(c, "failure"); f != "" {
		fmt.Fprintf(&b, "\nFailed check: `%s`\n", f)
	}
	b.WriteString("\n| Company | Roles | Records | Bytes | Signed on behalf of | Fields the buyer holds |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, p := range Objs(rep, "parties") {
		fmt.Fprintf(&b, "| %s | %s | %v | %v | %s | %s |\n", S(p, "organization", "name"),
			strings.Join(Strs(p, "roles"), ", "), get(p, "records"), get(p, "recordBytes"),
			orDash(strings.Join(Strs(p, "signedOnBehalfOf"), ", ")), code(Strs(p, "fieldsRevealed")))
	}
	fmt.Fprintf(&b, "\nData files handed over with the records: %v, %v bytes.\n", get(rep, "dataFiles", "count"), get(rep, "dataFiles", "bytes"))
	for _, m := range Objs(rep, "siteMismatches") {
		fmt.Fprintf(&b, "\nSite mismatch: %s names %s, but its key is enrolled for %s.\n", S(m, "record"), S(m, "names"), S(m, "keyEnrolledFor"))
	}
	if costs := O(rep, "costs"); costs != nil {
		b.WriteString("\n| Party | Hours | Amount | Note |\n| --- | --- | --- | --- |\n")
		for _, e := range Objs(costs, "entries") {
			amount := "-"
			if Has(e, "amount") {
				amount = fmt.Sprintf("%v %s", get(e, "amount"), S(e, "currency"))
			}
			fmt.Fprintf(&b, "| %s | %v | %s | %s |\n", S(e, "party"), orDash(num(get(e, "hours"))), amount, orDash(S(e, "note")))
		}
		fmt.Fprintf(&b, "| **Total** | %v | %s | |\n", get(costs, "total", "hours"), moneyText(O(costs, "total", "amount")))
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" || s == "<nil>" {
		return "-"
	}
	return s
}

func moneyText(m Obj) string {
	var parts []string
	for _, cur := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%v %s", m[cur], cur))
	}
	return orDash(strings.Join(parts, ", "))
}

// PilotSummary reads every measurement in dir and writes summary.md: one
// row per lot, and how many lots passed.
func PilotSummary(dir string) (string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	var b strings.Builder
	b.WriteString("# Pilot summary\n\n| Lot | Check | Seconds | Records | Hours | Amount | Failed check |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	lots, passed := 0, 0
	for _, f := range files {
		rep, err := ReadObj(f)
		if err != nil || S(rep, "kind") != MeasurementKind {
			continue
		}
		lots++
		if S(rep, "check", "result") == "pass" {
			passed++
		}
		records := 0
		for _, p := range Objs(rep, "parties") {
			n, _ := Int(p, "records")
			records += int(n)
		}
		hours := "-"
		if Has(O(rep, "costs"), "total") {
			hours = num(get(rep, "costs", "total", "hours"))
		}
		fmt.Fprintf(&b, "| %s | %s | %v | %d | %s | %s | %s |\n", S(rep, "lot"), S(rep, "check", "result"), get(rep, "check", "seconds"),
			records, hours, moneyText(O(rep, "costs", "total", "amount")), orDash(S(rep, "check", "failure")))
	}
	if lots == 0 {
		return "", fmt.Errorf("%s: no measurements", dir)
	}
	fmt.Fprintf(&b, "\n%d of %d lots passed the receipt check.\n", passed, lots)
	s := b.String()
	return s, os.WriteFile(filepath.Join(dir, "summary.md"), []byte(s), 0o644)
}
