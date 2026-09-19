package hslsa

// What each view of a bundle reveals (spec section "What each view reveals"),
// measured on the bundle rather than argued. A producer runs it on its full
// bundle, with the disclosures, before handing anything out. It reports what a
// party holding only the signed records learns, including what it can recover
// by guessing, and what a buyer holding only an escrow auditor's VSAs learns.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// LeakLimits bounds the search for the units behind a lot digest.
type LeakLimits struct {
	MaxUnits   int // largest lot tried
	MaxMissing int // most units absent from a run of serials (scrapped units)
}

// DefaultLeakLimits cover lots of up to 100 units with up to 3 scrapped, a
// few million guesses at most.
var DefaultLeakLimits = LeakLimits{MaxUnits: 100, MaxMissing: 3}

// serialFormat reads a shared prefix and a fixed-width number from unit ids.
func serialFormat(ids []string) (prefix string, width int, nums []int, ok bool) {
	for i, u := range ids {
		j := len(u)
		for j > 0 && u[j-1] >= '0' && u[j-1] <= '9' {
			j--
		}
		if j == len(u) {
			return "", 0, nil, false
		}
		if i == 0 {
			prefix, width = u[:j], len(u)-j
		} else if u[:j] != prefix || len(u)-j != width {
			return "", 0, nil, false
		}
		n, err := strconv.Atoi(u[j:])
		if err != nil {
			return "", 0, nil, false
		}
		nums = append(nums, n)
	}
	return prefix, width, nums, len(ids) > 0
}

// invertLot tries to recover the units behind a lot digest the way a buyer
// holding a few of them could: it reads the serial format from the units it
// holds, then tries runs of serials from 1 (or 0) to n, smallest lot first,
// each with up to lim.MaxMissing units absent. It returns the units found and
// the serials missing from their run, and the number of guesses, or why it
// found none.
func invertLot(digest string, known []string, lim LeakLimits) (units, missing []string, guesses int, reason string) {
	prefix, width, nums, ok := serialFormat(known)
	if !ok {
		return nil, nil, 0, "the units held share no serial format"
	}
	start, top := 1, 0
	isKnown := map[int]bool{}
	for _, n := range nums {
		isKnown[n] = true
		if n == 0 {
			start = 0
		}
		if n > top {
			top = n
		}
	}
	ids := make([][]byte, 0, lim.MaxUnits)
	for i := 0; i < lim.MaxUnits && width < 10 && start+i < pow10(width); i++ {
		ids = append(ids, []byte(fmt.Sprintf("%s%0*d\n", prefix, width, start+i)))
	}
	h := sha256.New()
	removed := make([]bool, len(ids))
	for n := top - start + 1; n <= len(ids); n++ {
		var free []int
		for i := 0; i < n; i++ {
			if !isKnown[start+i] {
				free = append(free, i)
			}
		}
		for k := 0; k <= lim.MaxMissing && k <= len(free); k++ {
			found, hit := combinations(len(free), k, func(pick []int) bool {
				for _, p := range pick {
					removed[free[p]] = true
				}
				h.Reset()
				for i := 0; i < n; i++ {
					if !removed[i] {
						h.Write(ids[i])
					}
				}
				for _, p := range pick {
					removed[free[p]] = false
				}
				guesses++
				return hex.EncodeToString(h.Sum(nil)) == digest
			})
			if hit {
				skip := map[int]bool{}
				for _, p := range found {
					skip[free[p]] = true
				}
				for i := 0; i < n; i++ {
					id := strings.TrimSuffix(string(ids[i]), "\n")
					if skip[i] {
						missing = append(missing, id)
					} else {
						units = append(units, id)
					}
				}
				return units, missing, guesses, ""
			}
		}
	}
	return nil, nil, guesses, fmt.Sprintf("not found in %d guesses (lots of up to %d units with up to %d missing)", guesses, lim.MaxUnits, lim.MaxMissing)
}

func pow10(n int) int {
	p := 1
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}

// combinations calls try with each k-subset of 0..n-1 in lexical order, and
// returns the first subset for which try reports true.
func combinations(n, k int, try func([]int) bool) ([]int, bool) {
	pick := make([]int, k)
	for i := range pick {
		pick[i] = i
	}
	for {
		if try(pick) {
			return append([]int(nil), pick...), true
		}
		i := k - 1
		for i >= 0 && pick[i] == n-k+i {
			i--
		}
		if i < 0 {
			return nil, false
		}
		pick[i]++
		for j := i + 1; j < k; j++ {
			pick[j] = pick[j-1] + 1
		}
	}
}

// walkStrings calls fn with the JSON Pointer and value of every string in v.
func walkStrings(v any, ptr string, fn func(ptr, s string)) {
	switch x := v.(type) {
	case string:
		fn(ptr, x)
	case map[string]any:
		for _, k := range sortedKeys(x) {
			walkStrings(x[k], ptr+"/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(k), fn)
		}
	case []any:
		for i, e := range x {
			walkStrings(e, ptr+"/"+strconv.Itoa(i), fn)
		}
	}
}

var lotPrefixes = []string{"urn:hslsa:assembly-lot:", "urn:hslsa:lot:", "urn:hslsa:wafer-lot:"}

// Leaks measures what a bundle's views reveal. known are the unit ids the
// viewer holds (a buyer's received units); vsaDir, when set, holds the escrow
// VSAs the buyer receives.
func Leaks(bundle string, known []string, vsaDir string, lim LeakLimits) (Obj, error) {
	envs, err := filepath.Glob(filepath.Join(bundle, "att", "*.intoto.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(envs)
	byType := Obj{}
	keyids := map[string]bool{}
	var builders, urns, times []string
	var withheld, lots, files, exposed []Obj
	seen := map[string]bool{}
	visible := map[string][]string{} // string value -> where the records show it
	for _, env := range envs {
		name := filepath.Base(env)
		raw, err := ReadObj(env)
		if err != nil {
			return nil, err
		}
		stmt, err := DecodeEnvelope(env)
		if err != nil {
			return nil, err
		}
		for _, s := range Objs(raw, "signatures") {
			keyids[S(s, "keyid")] = true
		}
		pt := S(stmt, "predicateType")
		n, _ := Int(byType, pt)
		byType[pt] = n + 1
		if b := S(stmt, "predicate", "runDetails", "builder", "id"); b != "" && !contains(builders, b) {
			builders = append(builders, b)
		}
		if t := S(stmt, "predicate", "runDetails", "metadata", "finishedOn"); t != "" {
			times = append(times, t)
		}
		for _, e := range Withheld(stmt) {
			withheld = append(withheld, Obj{"record": name, "path": S(e, "path")})
		}
		walkStrings(stmt, "", func(ptr, s string) {
			visible[s] = append(visible[s], name+" "+ptr)
		})
		for _, subj := range Objs(stmt, "subject") {
			sn, sd := S(subj, "name"), S(subj, "digest", "sha256")
			if !strings.HasPrefix(sn, "urn:") {
				if pt == MfgStep {
					files = append(files, Obj{"record": name, "file": sn, "salted": saltedFile(filepath.Join(bundle, "artifacts", sn))})
				}
				continue
			}
			if !contains(urns, sn) {
				urns = append(urns, sn)
			}
			if seen[sn+" "+sd] {
				continue
			}
			seen[sn+" "+sd] = true
			for _, p := range lotPrefixes {
				if !strings.HasPrefix(sn, p) {
					continue
				}
				lot := Obj{"subject": sn}
				if p == "urn:hslsa:wafer-lot:" {
					lot["reason"] = "not attempted: a buyer holds no wafer ids"
				} else if units, missing, guesses, reason := invertLot(sd, known, lim); units != nil {
					lot["units"], lot["missing"], lot["guesses"] = anyStrings(units), anyStrings(missing), guesses
				} else {
					lot["reason"], lot["guesses"] = reason, guesses
				}
				lots = append(lots, lot)
			}
		}
	}
	sort.Strings(times)
	timeline := Obj{"records": len(times)}
	if len(times) > 0 {
		timeline["first"], timeline["last"] = times[0], times[len(times)-1]
	}

	// A withheld value is not hidden if another record shows it.
	discs, _ := filepath.Glob(filepath.Join(bundle, "disclosures", "*.disclosures.json"))
	sort.Strings(discs)
	for _, path := range discs {
		file, err := ReadObj(path)
		if err != nil {
			return nil, err
		}
		for _, d := range Strs(file, "disclosures") {
			raw, err := base64.RawURLEncoding.DecodeString(d)
			if err != nil {
				continue
			}
			v, err := decodeJSON(raw)
			arr, _ := v.([]any)
			if err != nil || len(arr) != 3 {
				continue
			}
			walkStrings(arr[2], "", func(_, s string) {
				if len(s) < 4 {
					return
				}
				where := visible[s]
				for vs, at := range visible {
					if strings.Contains(s, " ") && strings.Contains(vs, slug(s)) {
						where = append(where, at...)
					}
				}
				if len(where) > 0 {
					sort.Strings(where)
					exposed = append(exposed, Obj{"record": S(file, "envelope"), "path": arr[1], "value": s, "seenIn": anyStrings(where)})
				}
			})
		}
	}
	derived := derivedYield(lots)

	rep := Obj{
		"records": Obj{
			"count":       len(envs),
			"byType":      byType,
			"signingKeys": len(keyids),
			"builders":    anyStrings(builders),
			"subjectURNs": anyStrings(urns),
			"timeline":    timeline,
			"withheld":    nonNil(withheld),
			"exposed":     nonNil(exposed),
			"files":       nonNil(files),
			"lots":        nonNil(lots),
			"derived":     anyStrings(derived),
		},
	}
	if vsaDir != "" {
		vsas, err := filepath.Glob(filepath.Join(vsaDir, "*.vsa.intoto.json"))
		if err != nil {
			return nil, err
		}
		sort.Strings(vsas)
		var out []Obj
		for _, path := range vsas {
			stmt, err := DecodeEnvelope(path)
			if err != nil {
				return nil, err
			}
			p := O(stmt, "predicate")
			out = append(out, Obj{
				"vsa":          filepath.Base(path),
				"subject":      firstSubject(stmt),
				"resourceUri":  get(p, "resourceUri"),
				"levels":       get(p, "verifiedLevels"),
				"timeVerified": get(p, "timeVerified"),
				"inputs":       len(A(p, "inputAttestations")),
			})
		}
		rep["escrow"] = Obj{"vsas": nonNil(out)}
	}
	return rep, nil
}

// saltedFile reports whether a file is a JSON object with a salt of at least 128 bits.
func saltedFile(path string) bool {
	v, err := ReadObj(path)
	return err == nil && saltOK(S(v, "salt"))
}

// derivedYield states the yield a viewer learns from a recovered packaged lot
// and a recovered shipped lot with the same lot id.
func derivedYield(lots []Obj) []string {
	var out []string
	for _, a := range lots {
		id, ok := strings.CutPrefix(S(a, "subject"), "urn:hslsa:assembly-lot:")
		if !ok || A(a, "units") == nil {
			continue
		}
		for _, b := range lots {
			if S(b, "subject") != "urn:hslsa:lot:"+id || A(b, "units") == nil {
				continue
			}
			packaged, shipped := Strs(a, "units"), Strs(b, "units")
			if len(minus(shipped, packaged)) == 0 {
				out = append(out, fmt.Sprintf("final test yield of %s: %d of %d packaged units shipped; scrapped %s",
					id, len(shipped), len(packaged), strings.Join(minus(packaged, shipped), ", ")))
			}
		}
	}
	return out
}

// LeaksMarkdown renders a leak report as two tables.
func LeaksMarkdown(rep Obj) string {
	var b strings.Builder
	r := O(rep, "records")
	row := func(what, measured string) { fmt.Fprintf(&b, "| %s | %s |\n", what, measured) }
	b.WriteString("### What a party holding only the signed records learns\n\n| What | Measured |\n| --- | --- |\n")
	var types []string
	for _, t := range sortedKeys(O(r, "byType")) {
		n, _ := Int(r, "byType", t)
		types = append(types, fmt.Sprintf("%d `%s`", n, t))
	}
	count, _ := Int(r, "count")
	row("Records", fmt.Sprintf("%d envelopes: %s", count, strings.Join(types, ", ")))
	keys, _ := Int(r, "signingKeys")
	row("Signing keys", fmt.Sprintf("%d distinct key ids, each naming one party in every record it signs, across lots and buyers", keys))
	row("Builders", code(Strs(r, "builders")))
	row("Subject names", code(Strs(r, "subjectURNs")))
	tl := O(r, "timeline")
	if n, _ := Int(tl, "records"); n > 0 {
		row("Timeline", fmt.Sprintf("`finishedOn` on %d records, from %s to %s", n, S(tl, "first"), S(tl, "last")))
	} else {
		row("Timeline", "no record states when it was made")
	}
	var held []string
	for _, w := range Objs(r, "withheld") {
		held = append(held, fmt.Sprintf("`%s` in %s", S(w, "path"), strings.TrimSuffix(S(w, "record"), ".intoto.json")))
	}
	if len(held) == 0 {
		row("Withheld fields", "none")
	} else {
		row("Withheld fields", fmt.Sprintf("%d, values hidden: %s", len(held), strings.Join(held, ", ")))
	}
	var exp []string
	for _, e := range Objs(r, "exposed") {
		exp = append(exp, fmt.Sprintf("`%s` in %s is also in %s", S(e, "path"), strings.TrimSuffix(S(e, "record"), ".intoto.json"), strings.Join(Strs(e, "seenIn"), "; ")))
	}
	if len(exp) == 0 && len(held) > 0 {
		row("Withheld values shown elsewhere", "none")
	} else if len(exp) > 0 {
		row("Withheld values shown elsewhere", strings.Join(exp, "; "))
	}
	var fl []string
	for _, f := range Objs(r, "files") {
		state := "unsalted, so a guess of its content can be confirmed"
		if v, _ := get(f, "salted").(bool); v {
			state = "salted"
		}
		fl = append(fl, fmt.Sprintf("`%s` %s", S(f, "file"), state))
	}
	if len(fl) > 0 {
		row("Data files named by manufacturing records", strings.Join(fl, ", "))
	}
	for _, l := range Objs(r, "lots") {
		guesses, _ := Int(l, "guesses")
		if units := Strs(l, "units"); units != nil {
			found := fmt.Sprintf("%d units", len(units))
			if missing := Strs(l, "missing"); len(missing) > 0 {
				found += fmt.Sprintf(" (%d of the run missing)", len(missing))
			}
			row("`"+S(l, "subject")+"`", fmt.Sprintf("recovered from its digest by guessing: %s, serials %s to %s, found at guess %d",
				found, units[0], units[len(units)-1], guesses))
		} else {
			row("`"+S(l, "subject")+"`", S(l, "reason"))
		}
	}
	for _, d := range Strs(r, "derived") {
		row("Derived", d)
	}
	if e := O(rep, "escrow"); e != nil {
		b.WriteString("\n### What the buyer learns under escrow\n\n| VSA | Subject | Resource | Levels | Verified | Inputs |\n| --- | --- | --- | --- | --- | --- |\n")
		for _, v := range Objs(e, "vsas") {
			n, _ := Int(v, "inputs")
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %d |\n", S(v, "vsa"), S(v, "subject", "name"), S(v, "resourceUri"),
				strings.Join(Strs(v, "levels"), ", "), S(v, "timeVerified"), n)
		}
	}
	return b.String()
}

func code(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return "`" + strings.Join(list, "`, `") + "`"
}
