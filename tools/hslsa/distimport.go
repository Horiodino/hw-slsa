package hslsa

// The distributor importer (docs/distributor-importer.md): it reads what a
// distributor, or a manufacturer shipping direct, already hands over with a
// shipment, unchanged, and turns it into the shipment a board scenario
// signs a distribution record from:
//
//   - a packing list (CSV), one row per line: the part, its lot and date
//     code, the quantity, the serials when the part has them, and the
//     certificate of conformance that covers the line;
//   - each certificate of conformance it names, carried by digest: the
//     importer does not read a certificate's contents, it checks that every
//     line names one and that the file is there;
//   - optionally, the shipment's EPCIS 2.0 events (JSON-LD), as supplemental
//     evidence: exactly one shipping ObjectEvent, on the ship date. Mapping
//     its GTINs to part numbers is left to the buyer.
//
// The distribution record then carries these files by digest and names them
// in hwMfg.importer, and the board receipt check reads them again and
// requires the shipment to say exactly what they say, as the MES and STDF
// adapter does for chip records.

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ImporterID names this importer in hwMfg.importer.id.
const ImporterID = NS + "/tools/hslsa/import/distributor@v0.1"

// The export formats the importer reads.
const (
	FmtPackingList = "packing-list-csv"
	FmtCoC         = "certificate-of-conformance"
	FmtEPCIS       = "epcis-2.0-json"
)

var packingListColumns = []string{"shipment_id", "ship_date", "shipper", "shipper_country", "manufacturer", "mpn", "lot", "date_code", "quantity", "serials", "coc"}

// importShipment reads one shipment's exports, by format, and returns the
// shipment: id, shipper, shipDate, lines (each with its certificate of
// conformance by name and digest) and, with EPCIS events, the shipping
// event's id and time.
func importShipment(files map[string][]string) (Obj, error) {
	if len(files[FmtPackingList]) != 1 {
		return nil, fmt.Errorf("a shipment needs one %s export, has %d", FmtPackingList, len(files[FmtPackingList]))
	}
	if len(files[FmtEPCIS]) > 1 {
		return nil, fmt.Errorf("a shipment takes at most one %s export, has %d", FmtEPCIS, len(files[FmtEPCIS]))
	}
	path := files[FmtPackingList][0]
	rows, err := readCSV(path, packingListColumns)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: no lines", path)
	}
	cocs := map[string]string{}
	for _, c := range files[FmtCoC] {
		d := fileDigest(c)
		if d == nil {
			return nil, fmt.Errorf("certificate of conformance %s is missing", c)
		}
		cocs[filepath.Base(c)] = S(d, "sha256")
	}
	head := rows[0]
	ship := Obj{
		"id":       head["shipment_id"],
		"shipper":  Obj{"name": head["shipper"], "country": head["shipper_country"]},
		"shipDate": head["ship_date"],
	}
	if _, err := time.Parse("2006-01-02", head["ship_date"]); err != nil || head["shipment_id"] == "" || head["shipper"] == "" {
		return nil, fmt.Errorf("%s: row 2 needs a shipment_id, a shipper and a ship_date (YYYY-MM-DD)", path)
	}
	used := map[string]bool{}
	var lines []any
	for i, r := range rows {
		row := i + 2
		for _, k := range []string{"shipment_id", "ship_date", "shipper", "shipper_country"} {
			if r[k] != head[k] {
				return nil, fmt.Errorf("%s: row %d is in another shipment (%s %q, not %q)", path, row, k, r[k], head[k])
			}
		}
		q, err := strconv.ParseInt(r["quantity"], 10, 64)
		if err != nil || q <= 0 || r["mpn"] == "" || r["manufacturer"] == "" || r["lot"] == "" {
			return nil, fmt.Errorf("%s: row %d needs a manufacturer, an mpn, a lot and a positive quantity", path, row)
		}
		line := Obj{"manufacturer": r["manufacturer"], "mpn": r["mpn"], "lot": r["lot"], "dateCode": r["date_code"], "quantity": q}
		if serials := splitList(r["serials"]); len(serials) > 0 {
			if int64(len(serials)) != q {
				return nil, fmt.Errorf("%s: row %d lists %d serials for a quantity of %d", path, row, len(serials), q)
			}
			line["units"] = anyStrings(serials)
		}
		coc := r["coc"]
		if coc == "" {
			return nil, fmt.Errorf("%s: row %d (%s lot %s) names no certificate of conformance", path, row, r["mpn"], r["lot"])
		}
		if cocs[coc] == "" {
			return nil, fmt.Errorf("%s: row %d names certificate of conformance %s, which is not among the shipment's exports", path, row, coc)
		}
		used[coc] = true
		line["coc"] = Obj{"name": coc, "digest": Obj{"sha256": cocs[coc]}}
		lines = append(lines, line)
	}
	for _, name := range sortedKeys(anyBools(cocs)) {
		if !used[name] {
			return nil, fmt.Errorf("certificate of conformance %s covers no line of the packing list", name)
		}
	}
	ship["lines"] = lines
	if len(files[FmtEPCIS]) == 1 {
		ev, err := epcisShipping(files[FmtEPCIS][0], head["ship_date"])
		if err != nil {
			return nil, err
		}
		ship["epcis"] = ev
	}
	return ship, nil
}

func anyBools(m map[string]string) Obj {
	o := Obj{}
	for k := range m {
		o[k] = true
	}
	return o
}

// epcisShipping reads an EPCIS 2.0 document and returns its one shipping
// ObjectEvent's id and time, which must fall on the ship date (UTC).
func epcisShipping(path, shipDate string) (Obj, error) {
	doc, err := ReadObj(path)
	if err != nil {
		return nil, err
	}
	if S(doc, "type") != "EPCISDocument" || !strings.HasPrefix(S(doc, "schemaVersion"), "2.") {
		return nil, fmt.Errorf("%s: not an EPCIS 2.0 document (type EPCISDocument, schemaVersion 2.x)", path)
	}
	var found []Obj
	for _, e := range Objs(doc, "epcisBody", "eventList") {
		step := strings.TrimPrefix(S(e, "bizStep"), "urn:epcglobal:cbv:bizstep:")
		if S(e, "type") == "ObjectEvent" && step == "shipping" {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("%s: want one shipping ObjectEvent, found %d", path, len(found))
	}
	e := found[0]
	t, err := time.Parse(time.RFC3339, S(e, "eventTime"))
	if err != nil {
		return nil, fmt.Errorf("%s: eventTime %q is not RFC 3339", path, S(e, "eventTime"))
	}
	if t.UTC().Format("2006-01-02") != shipDate {
		return nil, fmt.Errorf("%s: the shipping event is on %s, the packing list's ship date is %s", path, t.UTC().Format("2006-01-02"), shipDate)
	}
	return Obj{"eventID": get(e, "eventID"), "eventTime": S(e, "eventTime")}, nil
}

// importFiles groups a shipment's export paths by format.
func importFiles(sources []Obj, path func(Obj) string) (map[string][]string, error) {
	files := map[string][]string{}
	for _, s := range sources {
		f := S(s, "format")
		if f != FmtPackingList && f != FmtCoC && f != FmtEPCIS {
			return nil, fmt.Errorf("the importer does not read %q exports (it reads %s, %s and %s)", f, FmtPackingList, FmtCoC, FmtEPCIS)
		}
		files[f] = append(files[f], path(s))
	}
	return files, nil
}

// ImportShipments writes a board scenario whose shipments come from the
// distributors' exports. config lists, per shipment, its exports (path,
// format), with paths relative to the config; every other key of the
// scenario at scenarioPath is kept, and a shipment the config does not list
// stays as it is.
func ImportShipments(configPath, scenarioPath, out string) error {
	cfg, err := ReadObj(configPath)
	if err != nil {
		return err
	}
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	base, err := filepath.Abs(filepath.Dir(out))
	if err != nil {
		return err
	}
	dir := filepath.Dir(configPath)
	imported := map[string]Obj{}
	for _, s := range Objs(cfg, "shipments") {
		var sources []any
		files, err := importFiles(Objs(s, "exports"), func(e Obj) string {
			p := S(e, "path")
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			src := p
			if abs, err := filepath.Abs(p); err == nil {
				if rel, err := filepath.Rel(base, abs); err == nil {
					src = filepath.ToSlash(rel)
				}
			}
			sources = append(sources, Obj{"path": src, "format": S(e, "format")})
			return p
		})
		if err != nil {
			return fmt.Errorf("shipment %s: %w", S(s, "id"), err)
		}
		ship, err := importShipment(files)
		if err != nil {
			return fmt.Errorf("shipment %s: %w", S(s, "id"), err)
		}
		if S(ship, "id") != S(s, "id") {
			return fmt.Errorf("shipment %s: its packing list is for shipment %s", S(s, "id"), S(ship, "id"))
		}
		ship["importer"] = Obj{"id": ImporterID, "sources": sources}
		imported[S(s, "id")] = ship
		fmt.Printf("imported: shipment %s from %s, %d line(s), %s\n", S(ship, "id"), S(ship, "shipper", "name"), len(Objs(ship, "lines")),
			map[bool]string{true: "with its EPCIS shipping event", false: "no EPCIS events"}[Has(ship, "epcis")])
	}
	var shipments []any
	for _, s := range Objs(sc, "shipments") {
		if ship, ok := imported[S(s, "id")]; ok {
			shipments = append(shipments, ship)
			delete(imported, S(s, "id"))
		} else {
			shipments = append(shipments, s)
		}
	}
	for _, id := range sortedKeys(objsByKey(imported)) {
		shipments = append(shipments, imported[id])
	}
	sc["shipments"] = shipments
	return WriteJSON(out, sc)
}

func objsByKey(m map[string]Obj) Obj {
	o := Obj{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

// attachShipmentExports copies a shipment's exports into the bundle and
// returns the shipment data without its importer block, the exports as
// dependencies and the hwMfg.importer block naming them.
func attachShipmentExports(bundle, scenarioDir string, s Obj) (Obj, []Obj, Obj, error) {
	imp := O(s, "importer")
	if imp == nil {
		return s, nil, nil, nil
	}
	data := Obj{}
	for k, v := range s {
		if k != "importer" {
			data[k] = v
		}
	}
	var deps []Obj
	var names []any
	for _, src := range Objs(imp, "sources") {
		p := S(src, "path")
		if !filepath.IsAbs(p) {
			p = filepath.Join(scenarioDir, filepath.FromSlash(p))
		}
		name := filepath.Base(p)
		dst := filepath.Join(bundle, "artifacts", name)
		if err := copyFile(p, dst); err != nil {
			return nil, nil, nil, err
		}
		r, err := fileRD(dst, "")
		if err != nil {
			return nil, nil, nil, err
		}
		deps = append(deps, r)
		names = append(names, Obj{"name": name, "format": S(src, "format")})
	}
	return data, deps, Obj{"id": ImporterID, "sources": names}, nil
}

// shipmentExportsCheck reads a distribution record's exports again, when it
// carries them, and requires the shipment to say exactly what they say. The
// board policy's requireShipmentExports refuses a record that carries none.
func shipmentExportsCheck(bundle string, policy, ship, data Obj, label string) (string, error) {
	imp := O(ship, "predicate", "hwMfg", "importer")
	if imp == nil {
		if Truthy(get(policy, "requireShipmentExports")) {
			return "", failf("%s: the policy requires each shipment to carry its shipper's exports (requireShipmentExports), and this one carries none", label)
		}
		return "", nil
	}
	if S(imp, "id") != ImporterID {
		return "", failf("%s: made by importer %q, which this verifier cannot run", label, S(imp, "id"))
	}
	deps := map[string]any{}
	for _, d := range Objs(ship, "predicate", "buildDefinition", "resolvedDependencies") {
		deps[S(d, "name")] = get(d, "digest")
	}
	art := filepath.Join(bundle, "artifacts")
	var names []string
	files, err := importFiles(Objs(imp, "sources"), func(s Obj) string {
		names = append(names, S(s, "name"))
		return filepath.Join(art, S(s, "name"))
	})
	if err != nil {
		return "", failf("%s: %v", label, err)
	}
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, `/\`) || !Has(deps, name) {
			return "", failf("%s: export %q is not one of its resolvedDependencies", label, name)
		}
		if d := fileDigest(filepath.Join(art, name)); d == nil || !jsonEqual(d, deps[name]) {
			return "", failf("%s: export %s is missing or does not match its attested digest", label, name)
		}
	}
	want, err := importShipment(files)
	if err != nil {
		return "", failf("%s: its exports do not read: %v", label, err)
	}
	if !jsonEqual(want, data) {
		return "", failf("%s: the shipment differs from its shipper's exports", label)
	}
	return fmt.Sprintf("%s: matches %s", label, strings.Join(names, ", ")), nil
}
