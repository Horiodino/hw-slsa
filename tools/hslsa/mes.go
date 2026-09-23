package hslsa

// Readers for the two MES exports the MES and STDF adapter takes: a lot
// history (one row per lot transaction) and a unit genealogy (one row per
// packaged unit and the die it holds). Every MES names its columns
// differently; these are the column names the adapter documents
// (docs/mes-stdf-adapter.md), matched by header so their order is free.

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MESEvent is one row of a lot history.
type MESEvent struct {
	Time, Facility, Lot, Event, Operation string
	Quantity                              int64
	Materials                             []string          // wafer ids or unit serials, "|"-separated in the file
	Attrs                                 map[string]string // key=value pairs, "|"-separated in the file
}

// GenealogyRow is one row of a unit genealogy: a packaged unit, its assembly
// lot, and the die it holds.
type GenealogyRow struct {
	Unit, Lot, SourceLot, Wafer string
	X, Y                        int64
}

var (
	mesHistoryColumns   = []string{"timestamp", "facility", "lot_id", "event", "operation", "quantity", "material_ids", "attributes"}
	mesGenealogyColumns = []string{"unit_id", "lot_id", "source_lot_id", "wafer_id", "die_x", "die_y"}
)

// readCSV reads a CSV file with a header row and returns each row as a map
// from the wanted column names, failing when one is missing.
func readCSV(path string, columns []string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: empty", path)
	}
	index := map[string]int{}
	for i, h := range rows[0] {
		index[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, c := range columns {
		if _, ok := index[c]; !ok {
			return nil, fmt.Errorf("%s: no %s column (want %s)", path, c, strings.Join(columns, ", "))
		}
	}
	var out []map[string]string
	for _, row := range rows[1:] {
		m := map[string]string{}
		for _, c := range columns {
			m[c] = strings.TrimSpace(row[index[c]])
		}
		out = append(out, m)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, "|") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ReadMESHistory reads a lot history export.
func ReadMESHistory(path string) ([]MESEvent, error) {
	rows, err := readCSV(path, mesHistoryColumns)
	if err != nil {
		return nil, err
	}
	var out []MESEvent
	for i, r := range rows {
		e := MESEvent{Time: r["timestamp"], Facility: r["facility"], Lot: r["lot_id"], Event: strings.ToUpper(r["event"]),
			Operation: r["operation"], Materials: splitList(r["material_ids"]), Attrs: map[string]string{}}
		if r["quantity"] != "" {
			if e.Quantity, err = strconv.ParseInt(r["quantity"], 10, 64); err != nil {
				return nil, fmt.Errorf("%s: row %d: quantity %q", path, i+2, r["quantity"])
			}
		}
		for _, kv := range splitList(r["attributes"]) {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("%s: row %d: attribute %q is not key=value", path, i+2, kv)
			}
			e.Attrs[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		out = append(out, e)
	}
	return out, nil
}

// ReadMESGenealogy reads a unit genealogy export.
func ReadMESGenealogy(path string) ([]GenealogyRow, error) {
	rows, err := readCSV(path, mesGenealogyColumns)
	if err != nil {
		return nil, err
	}
	var out []GenealogyRow
	for i, r := range rows {
		x, errX := strconv.ParseInt(r["die_x"], 10, 64)
		y, errY := strconv.ParseInt(r["die_y"], 10, 64)
		if errX != nil || errY != nil || r["unit_id"] == "" {
			return nil, fmt.Errorf("%s: row %d: needs a unit_id and integer die_x, die_y", path, i+2)
		}
		out = append(out, GenealogyRow{Unit: r["unit_id"], Lot: r["lot_id"], SourceLot: r["source_lot_id"], Wafer: r["wafer_id"], X: x, Y: y})
	}
	return out, nil
}

// lotStart is the one LOT_START event in a lot history.
func lotStart(path string, events []MESEvent) (MESEvent, error) {
	var found []MESEvent
	for _, e := range events {
		if e.Event == "LOT_START" {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		return MESEvent{}, fmt.Errorf("%s: want one LOT_START event, found %d", path, len(found))
	}
	return found[0], nil
}

// operationChecks turns the TRACK_OUT events of lot into the record's checks,
// one per operation the settings map to a check name, in the settings'
// order. An operation passes when its last TRACK_OUT says result=PASS.
func operationChecks(path string, events []MESEvent, lot string, mapping []Obj) ([]Obj, error) {
	var out []Obj
	for _, m := range mapping {
		op, name := S(m, "operation"), S(m, "check")
		result := ""
		for _, e := range events {
			if e.Lot == lot && e.Event == "TRACK_OUT" && strings.EqualFold(e.Operation, op) {
				result = "fail"
				if strings.EqualFold(e.Attrs["result"], "PASS") {
					result = "pass"
				}
			}
		}
		if result == "" {
			return nil, fmt.Errorf("%s: lot %s has no TRACK_OUT for operation %q, which the %s check needs", path, lot, op, name)
		}
		out = append(out, Obj{"name": name, "result": result})
	}
	return out, nil
}
