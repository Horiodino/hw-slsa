package hslsa

// Transfers from MES shipping events (docs/mes-stdf-adapter.md,
// "Transfers"). With "transfers": "mes" in its configuration, the adapter
// makes each transfer between two sites from the SHIP event in the sending
// site's lot history and the RECEIVE event in the receiving site's, from
// whichever of the two exports one. The transfer record then carries those
// exports by digest and names them in hwMfg.adapter, and the verifier reads
// them again, as it does for the step records.

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// TransfersFromMES is the value of the adapter configuration's transfers
// that makes each transfer from the sites' MES shipping events.
const TransfersFromMES = "mes"

// transferSides are the sending and the receiving step of each transfer.
var transferSides = map[string][2]string{
	"wafer-fab":  {"wafer-fab", "wafer-sort"},
	"wafer-sort": {"wafer-sort", "packaging"},
	"packaging":  {"packaging", "final-test"},
}

// mesTransfer reads one transfer from the MES lot histories of the two
// sites, by step (a site whose exports have no lot history is absent): the
// one SHIP of lot in the sender's history, addressed to the receiving site,
// and the one RECEIVE of lot in the receiver's, from the sending site. Each
// moves len(items) items, and the items themselves when the event lists
// them. At least one of the two must be there. It returns the packing list's
// shipped and received entries and the exports it read.
func mesTransfer(from string, histories map[string]string, lot string, items []string, fromSite, toSite string) (Obj, error) {
	sides := transferSides[from]
	label := "transfer from " + from
	out := Obj{}
	var sources []any
	var times [2]time.Time
	for i, kind := range []string{"SHIP", "RECEIVE"} {
		path := histories[sides[i]]
		if path == "" {
			continue
		}
		events, err := ReadMESHistory(path)
		if err != nil {
			return nil, err
		}
		var found []MESEvent
		for _, e := range events {
			if e.Event == kind && e.Lot == lot {
				found = append(found, e)
			}
		}
		if len(found) == 0 {
			continue
		}
		if len(found) > 1 {
			return nil, fmt.Errorf("%s: %s has %d %s events for lot %s; a transfer is one", label, filepath.Base(path), len(found), kind, lot)
		}
		e := found[0]
		where := fmt.Sprintf("%s: %s %s of lot %s", label, filepath.Base(path), kind, lot)
		if kind == "SHIP" && e.Attrs["ship_to"] != toSite {
			return nil, fmt.Errorf("%s ships to %q, but %s received it", where, e.Attrs["ship_to"], toSite)
		}
		if kind == "RECEIVE" && e.Attrs["from"] != fromSite {
			return nil, fmt.Errorf("%s is from %q, but %s shipped it", where, e.Attrs["from"], fromSite)
		}
		if e.Quantity != int64(len(items)) {
			return nil, fmt.Errorf("%s moves %d, the lot has %d", where, e.Quantity, len(items))
		}
		if len(e.Materials) > 0 && !sameSet(e.Materials, items) {
			return nil, fmt.Errorf("%s lists %s, not the lot's %s", where, strings.Join(e.Materials, " "), strings.Join(items, " "))
		}
		t, err := time.Parse(time.RFC3339, e.Time)
		if err != nil {
			return nil, fmt.Errorf("%s: timestamp %q is not RFC 3339", where, e.Time)
		}
		times[i] = t
		entry := map[string]string{"SHIP": "shipped", "RECEIVE": "received"}[kind]
		out[entry] = Obj{"time": e.Time, "facility": e.Facility, "quantity": e.Quantity}
		sources = append(sources, Obj{"name": filepath.Base(path), "format": FmtMESHistory, "step": sides[i]})
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("%s: neither %s's nor %s's exports record shipping lot %s (a SHIP or a RECEIVE event in an MES lot history)", label, sides[0], sides[1], lot)
	}
	if !times[0].IsZero() && !times[1].IsZero() && times[1].Before(times[0]) {
		return nil, fmt.Errorf("%s: received at %s, before it was shipped at %s", label, times[1].Format(time.RFC3339), times[0].Format(time.RFC3339))
	}
	out["sources"] = sources
	return out, nil
}

// adaptTransfers makes each transfer from the steps' MES lot histories, for
// the scenario's transferEvents.
func adaptTransfers(steps Obj, fab, pkg Obj, genealogy Obj, sites map[string]string) (Obj, error) {
	histories := map[string]string{}
	for _, step := range MfgSteps {
		for _, s := range Objs(steps, step, "sources") {
			if S(s, "format") == FmtMESHistory {
				histories[step] = S(s, "path")
			}
		}
	}
	wafers := Strs(fab, "wafers")
	lots := map[string]string{"wafer-fab": S(fab, "lotId"), "wafer-sort": S(fab, "lotId"), "packaging": S(pkg, "assemblyLot")}
	items := map[string][]string{"wafer-fab": wafers, "wafer-sort": wafers, "packaging": sortedKeys(genealogy)}
	out := Obj{}
	for _, from := range TransferFrom {
		sides := transferSides[from]
		ev, err := mesTransfer(from, histories, lots[from], items[from], sites[sides[0]], sites[sides[1]])
		if err != nil {
			return nil, err
		}
		for _, s := range Objs(ev, "sources") {
			s["path"] = histories[S(s, "step")]
			delete(s, "name")
		}
		out[from] = ev
	}
	return out, nil
}

// attachTransferExports copies a transfer's exports into the bundle, adds
// them to the record's resolvedDependencies, names them in hwMfg.adapter and
// puts the shipped and received entries on the packing list.
func attachTransferExports(bundle, scenarioDir string, ev Obj, deps []Obj, hw, list Obj) ([]Obj, error) {
	if ev == nil {
		return deps, nil
	}
	var names []any
	for _, s := range Objs(ev, "sources") {
		src := S(s, "path")
		if !filepath.IsAbs(src) {
			src = filepath.Join(scenarioDir, filepath.FromSlash(src))
		}
		name := filepath.Base(src)
		dst := filepath.Join(bundle, "artifacts", name)
		if err := copyFile(src, dst); err != nil {
			return nil, err
		}
		r, err := fileRD(dst, "")
		if err != nil {
			return nil, err
		}
		deps = append(deps, r)
		names = append(names, Obj{"name": name, "format": S(s, "format"), "step": S(s, "step")})
	}
	hw["adapter"] = Obj{"id": AdapterID, "sources": names}
	for _, k := range []string{"shipped", "received"} {
		if v := get(ev, k); v != nil {
			list[k] = v
		}
	}
	return deps, nil
}

// transferExportsCheck reads a transfer record's exports again, when it
// carries them, and checks its packing list says what they say. The policy's
// manufacturing.requireTransferExports refuses a transfer that carries none.
func transferExportsCheck(bundle string, policy, t, list Obj, from, fromSite, toSite string) (string, error) {
	label := "transfer from " + from
	a := O(t, "predicate", "hwMfg", "adapter")
	if a == nil {
		if Truthy(get(policy, "manufacturing", "requireTransferExports")) {
			return "", failf("%s: the policy requires each transfer to carry the sites' MES exports (manufacturing.requireTransferExports), and this one carries none", label)
		}
		return "", nil
	}
	if S(a, "id") != AdapterID {
		return "", failf("%s: made by adapter %q, which this verifier cannot run", label, S(a, "id"))
	}
	deps := map[string]any{}
	for _, d := range Objs(t, "predicate", "buildDefinition", "resolvedDependencies") {
		deps[S(d, "name")] = get(d, "digest")
	}
	art := filepath.Join(bundle, "artifacts")
	histories := map[string]string{}
	var names []string
	sides := transferSides[from]
	for _, s := range Objs(a, "sources") {
		name, step := S(s, "name"), S(s, "step")
		if name == "" || strings.ContainsAny(name, `/\`) || !Has(deps, name) {
			return "", failf("%s: export %q is not one of its resolvedDependencies", label, name)
		}
		if S(s, "format") != FmtMESHistory || (step != sides[0] && step != sides[1]) || histories[step] != "" {
			return "", failf("%s: export %s is not one MES lot history of the sending or the receiving site", label, name)
		}
		d := fileDigest(filepath.Join(art, name))
		if d == nil || !jsonEqual(d, deps[name]) {
			return "", failf("%s: export %s is missing or does not match its attested digest", label, name)
		}
		histories[step] = filepath.Join(art, name)
		names = append(names, name)
	}
	lot := S(list, "lot")
	if i := strings.LastIndex(lot, ":"); i >= 0 {
		lot = lot[i+1:]
	}
	ev, err := mesTransfer(from, histories, lot, Strs(list, "items"), fromSite, toSite)
	if err != nil {
		return "", failf("%v", err)
	}
	for _, k := range []string{"shipped", "received"} {
		if !jsonEqual(get(list, k), get(ev, k)) {
			return "", failf("%s: the packing list's %s entry differs from the sites' exports", label, k)
		}
	}
	return fmt.Sprintf("transfer from %s: matches %s", from, strings.Join(names, ", ")), nil
}
