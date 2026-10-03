package hslsa

// Transfers made from the sites' MES shipping events (mestransfer.go).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMESTransfersVerifies(t *testing.T) {
	bundle := adaptedBundle(t, exportsDir, "adapter.json")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, lot, err := Verify(bundle, trust, exportsPolicy, e2eUnits, "", "")
	must(t, err)
	got := strings.Join(lot.Exports, "\n")
	for _, want := range []string{
		"transfer from wafer-fab: matches fab-mes-lot-history.csv",
		"transfer from wafer-sort: matches osat-mes-lot-history.csv",
		"transfer from packaging: matches osat-mes-lot-history.csv",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not say %q:\n%s", want, got)
		}
	}
	// The fab's SHIP is on the first packing list, the OSAT's RECEIVE on the second.
	fab := ok(ReadObj(filepath.Join(bundle, "artifacts", TransferList("wafer-fab"))))
	if S(fab, "shipped", "time") != "2026-08-28T10:00:00Z" || Has(fab, "received") {
		t.Fatalf("wafer-fab packing list: %v", fab)
	}
	sortList := ok(ReadObj(filepath.Join(bundle, "artifacts", TransferList("wafer-sort"))))
	if S(sortList, "received", "facility") != "EOSAT-1" || Has(sortList, "shipped") {
		t.Fatalf("wafer-sort packing list: %v", sortList)
	}
}

func TestMESTransferRejects(t *testing.T) {
	t.Run("a packing list that differs from the SHIP event", func(t *testing.T) {
		bundle := adaptedBundle(t, exportsDir, "adapter.json")
		list := filepath.Join(bundle, "artifacts", TransferList("wafer-fab"))
		editJSON(t, list, func(v Obj) { O(v, "shipped")["time"] = "2026-08-27T10:00:00Z" })
		chipResign(t, bundle, TransferAtt("wafer-fab"), "fab-site", func(stmt Obj) {
			firstSubject(stmt)["digest"] = fileDigest(list)
		})
		rejects(t, chipCheckPolicy(t, bundle, nil, exportsPolicy), "transfer from wafer-fab: the packing list's shipped entry differs from the sites' exports")
	})
	t.Run("an export changed after signing", func(t *testing.T) {
		bundle := adaptedBundle(t, exportsDir, "adapter.json")
		appendFile(t, filepath.Join(bundle, "artifacts", "fab-mes-lot-history.csv"), "\n")
		rejects(t, chipCheckPolicy(t, bundle, nil, exportsPolicy), "transfer from wafer-fab: export fab-mes-lot-history.csv is missing or does not match its attested digest")
	})
	for _, c := range []struct{ name, file, from, to, reason string }{
		{"a SHIP to another site", "fab-mes-lot-history.csv", "ship_to=Example Sort House", "ship_to=Example Other Sort House",
			`ships to "Example Other Sort House", but Example Sort House received it`},
		{"a RECEIVE from another site", "osat-mes-lot-history.csv", "from=Example Sort House", "from=Example Wafer Fab",
			`is from "Example Wafer Fab", but Example Sort House shipped it`},
		{"a SHIP of fewer units", "osat-mes-lot-history.csv", "SHIP,SHIP,40,", "SHIP,SHIP,39,", "moves 39, the lot has 40"},
		{"a RECEIVE of other wafers", "osat-mes-lot-history.csv", "INCOMING,2,W01|W02", "INCOMING,2,W01|W03", "lists W01 W03, not the lot's W01 W02"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			must(t, copyTree(exportsDir, dir))
			editFile(t, filepath.Join(dir, c.file), func(s string) string {
				if !strings.Contains(s, c.from) {
					t.Fatalf("%s has no %q", c.file, c.from)
				}
				return strings.Replace(s, c.from, c.to, 1)
			})
			_, err := AdaptScenario(filepath.Join(dir, "adapter.json"))
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("adapter accepted it or refused for another reason: %v", err)
			}
		})
	}
}

func TestMESTransferRule(t *testing.T) {
	dir := t.TempDir()
	write := func(name, rows string) string {
		p := filepath.Join(dir, name)
		must(t, os.WriteFile(p, []byte("timestamp,facility,lot_id,event,operation,quantity,material_ids,attributes\n"+rows), 0o644))
		return p
	}
	items := []string{"W01", "W02"}
	ship := write("ship.csv", "2026-08-28T10:00:00Z,FAB,LOT-A,SHIP,SHIP,2,W01|W02,ship_to=Sort\n")
	recv := write("recv.csv", "2026-08-30T10:00:00Z,SORT,LOT-A,RECEIVE,INCOMING,2,,from=Fab\n")
	ev, err := mesTransfer("wafer-fab", map[string]string{"wafer-fab": ship, "wafer-sort": recv}, "LOT-A", items, "Fab", "Sort")
	must(t, err)
	if S(ev, "shipped", "facility") != "FAB" || S(ev, "received", "facility") != "SORT" || len(Objs(ev, "sources")) != 2 {
		t.Fatalf("both sides: %v", ev)
	}
	early := write("early.csv", "2026-08-27T10:00:00Z,SORT,LOT-A,RECEIVE,INCOMING,2,,from=Fab\n")
	_, err = mesTransfer("wafer-fab", map[string]string{"wafer-fab": ship, "wafer-sort": early}, "LOT-A", items, "Fab", "Sort")
	if err == nil || !strings.Contains(err.Error(), "received at 2026-08-27T10:00:00Z, before it was shipped") {
		t.Fatalf("received before shipped: %v", err)
	}
	twice := write("twice.csv", "2026-08-28T10:00:00Z,FAB,LOT-A,SHIP,SHIP,2,,ship_to=Sort\n2026-08-29T10:00:00Z,FAB,LOT-A,SHIP,SHIP,2,,ship_to=Sort\n")
	_, err = mesTransfer("wafer-fab", map[string]string{"wafer-fab": twice}, "LOT-A", items, "Fab", "Sort")
	if err == nil || !strings.Contains(err.Error(), "has 2 SHIP events for lot LOT-A") {
		t.Fatalf("two SHIP events: %v", err)
	}
	none := write("none.csv", "2026-08-28T10:00:00Z,FAB,LOT-B,SHIP,SHIP,2,,ship_to=Sort\n")
	_, err = mesTransfer("wafer-fab", map[string]string{"wafer-fab": none}, "LOT-A", items, "Fab", "Sort")
	if err == nil || !strings.Contains(err.Error(), "neither wafer-fab's nor wafer-sort's exports record shipping lot LOT-A") {
		t.Fatalf("no event: %v", err)
	}
}
