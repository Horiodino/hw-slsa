package hslsa

// The MES and STDF adapter: sample exports for the PicoRV32 lot, made from
// its scenario the way a fab, a sort house, an OSAT and a test house would
// write them; the adapter reading them back into the same lot; and the
// verifier reading them again from the bundle.
//
// The sample exports are committed, so the adapter is tested on files it
// did not write. TestSampleExportsAreCurrent regenerates them and fails on
// any difference; go test -run TestSampleExportsAreCurrent -update-exports
// rewrites them.

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateExports = flag.Bool("update-exports", false, "rewrite the sample supplier exports in e2e/picorv32/supplier-exports")

var (
	exportsDir          = filepath.Join(e2eDir, "supplier-exports")
	exportsConfig       = filepath.Join(exportsDir, "adapter.json")
	exportsProxyConfig  = filepath.Join(exportsDir, "adapter-proxy.json")
	exportsPolicy       = filepath.Join(exportsDir, "policy.json")
	exportsProxyPolicy  = filepath.Join(exportsDir, "policy-proxy.json")
	sortSTDF, finalSTDF = "sort-LOT-EXAMPLE-A.stdf", "ft-ASM-EXAMPLE-17.stdf"
)

func (f *stdfFile) header(start time.Time, lot, node, tester, job, rev, code string) {
	cpu := uint8(2)
	if f.big {
		cpu = 1
	}
	f.rec(0, 10, cpu, uint8(4))
	t := uint32(start.Unix())
	// MIR: SETUP_T START_T STAT_NUM MODE_COD RTST_COD PROT_COD BURN_TIM CMOD_COD LOT_ID PART_TYP
	// NODE_NAM TSTR_TYP JOB_NAM JOB_REV SBLOT_ID OPER_NAM EXEC_TYP EXEC_VER TEST_COD TST_TEMP
	f.rec(1, 10, t, t, uint8(1), uint8('P'), uint8(' '), uint8(' '), uint16(65535), uint8(' '),
		lot, "PSOC130", node, tester, job, rev, "", "op01", "sample-exec", "1.0", code, "25")
}

// stdfTest is one parametric test: a PTR per part, failing above hi.
type stdfTest struct {
	num        uint32
	name, unit string
	lo, hi     float32
}

func (f *stdfFile) part(tests []stdfTest, values []float32, failedBin, hardBin uint16, x, y int16, id string, start uint32) {
	f.rec(5, 10, uint8(1), uint8(1))
	failed := false
	for i, tst := range tests {
		flg := uint8(0)
		if values[i] < tst.lo || values[i] > tst.hi {
			flg, failed = 0x80, true
		}
		// PTR: TEST_NUM HEAD SITE TEST_FLG PARM_FLG RESULT TEST_TXT ALARM_ID OPT_FLAG RES_SCAL
		// LLM_SCAL HLM_SCAL LO_LIMIT HI_LIMIT UNITS
		f.rec(15, 10, tst.num, uint8(1), uint8(1), flg, uint8(0), values[i], tst.name, "", uint8(0x0e),
			int8(0), int8(0), int8(0), tst.lo, tst.hi, tst.unit)
	}
	partFlg, bin := uint8(0), hardBin
	if failed {
		partFlg, bin = 0x08, failedBin
	}
	// PRR: HEAD SITE PART_FLG NUM_TEST HARD_BIN SOFT_BIN X_COORD Y_COORD TEST_T PART_ID PART_TXT PART_FIX
	f.rec(5, 20, uint8(1), uint8(1), partFlg, uint16(len(tests)), bin, bin, x, y, start, id, "", uint8(0))
}

func (f *stdfFile) bins(bins map[uint16]uint32, names map[uint16]string) {
	for _, b := range []uint16{1, 5, 7} {
		if n, ok := bins[b]; ok {
			pf := uint8('F')
			if b == 1 {
				pf = 'P'
			}
			// HBR: HEAD_NUM 255 (all heads) SITE_NUM HBIN_NUM HBIN_CNT HBIN_PF HBIN_NAM
			f.rec(1, 40, uint8(255), uint8(0), b, n, pf, names[b])
		}
	}
}

// csvFile writes rows as CSV.
func csvFile(rows [][]string) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	noErr(w.WriteAll(rows))
	return b.Bytes()
}

// spread is a deterministic value between lo and hi for a part.
func spread(seed int, lo, hi float32) float32 {
	return lo + (hi-lo)*float32((seed*37+11)%100)/100
}

// sampleExports writes the exports each site of the PicoRV32 lot hands
// over, from the scenario: what its MES and testers would have written.
func sampleExports(dir string) error {
	sc, err := ReadObj(e2eScenario)
	if err != nil {
		return err
	}
	fab, lot, srt, pkg, ft := O(sc, "fab"), O(sc, "waferLot"), O(sc, "sort"), O(sc, "packaging"), O(sc, "finalTest")
	wafers, lotID := Strs(lot, "wafers"), S(lot, "lotId")
	day := func(month time.Month, d, h int) time.Time { return time.Date(2026, month, d, h, 0, 0, 0, time.UTC) }
	ts := func(t time.Time) string { return t.Format(time.RFC3339) }
	files := map[string][]byte{}

	// The fab's MES: the lot starts with its wafers, runs its operations
	// (two of which the record's checks name), and ships to sort.
	header := mesHistoryColumns
	join := strings.Join
	rows := [][]string{header,
		{ts(day(8, 3, 6)), "EWF-FAB1", lotID, "LOT_START", "LOT START", fmt.Sprint(len(wafers)), join(wafers, "|"),
			"product=PSOC130|process=" + S(fab, "processNode") + "|mask_set=" + S(fab, "maskSetId")},
		{ts(day(8, 3, 9)), "EWF-FAB1", lotID, "TRACK_OUT", "MASK GDS XOR", "1", "", "result=PASS|reticles=24"},
	}
	for i, op := range []string{"DIFFUSION", "PHOTO M1", "ETCH M1", "CMP", "PHOTO M5", "PASSIVATION"} {
		rows = append(rows, []string{ts(day(8, 5+3*i, 8)), "EWF-FAB1", lotID, "TRACK_OUT", op, fmt.Sprint(len(wafers)), join(wafers, "|"), "result=PASS"})
	}
	rows = append(rows,
		[]string{ts(day(8, 26, 14)), "EWF-FAB1", lotID, "TRACK_OUT", "INLINE PARAMETRICS", fmt.Sprint(len(wafers)), join(wafers, "|"), "result=PASS|sites=9"},
		[]string{ts(day(8, 28, 10)), "EWF-FAB1", lotID, "SHIP", "SHIP", fmt.Sprint(len(wafers)), join(wafers, "|"), "ship_to=" + S(srt, "site", "name")})
	files["fab-mes-lot-history.csv"] = csvFile(rows)

	// Wafer sort: one STDF file for the lot, and one SEMI E142 map per wafer.
	dies, err := sortDies(srt, wafers)
	if err != nil {
		return err
	}
	grid := A(srt, "grid")
	gx, _ := Int(grid[0])
	gy, _ := Int(grid[1])
	probe := []stdfTest{{100, "continuity", "V", -0.9, -0.3}, {110, "iddq", "uA", 0, 5}, {120, "vdd_leakage", "nA", 0, 50}}
	var sf stdfFile
	sortStart := day(9, 1, 8)
	sf.header(sortStart, lotID, "PRB-07", "J750", S(srt, "program", "name"), S(srt, "program", "version"), "WS1")
	bins := map[uint16]uint32{}
	seed := 0
	for wi, w := range wafers {
		wStart := uint32(sortStart.Add(time.Duration(wi) * time.Hour).Unix())
		sf.rec(2, 10, uint8(1), uint8(255), wStart, w)
		good := uint32(0)
		rowCodes := make([][]string, gy)
		for y := range rowCodes {
			rowCodes[y] = make([]string, gx)
		}
		count := map[string]int{}
		for _, d := range dies {
			if d["wafer"] != w {
				continue
			}
			seed++
			x, y := d["x"].(int64), d["y"].(int64)
			vals := []float32{spread(seed, -0.7, -0.5), spread(seed, 1.1, 2.9), spread(seed, 4, 21)}
			if d["bin"] == "fail" {
				vals[1] = 7.5 + float32(seed%3)
			}
			sf.part(probe, vals, 7, 1, int16(x), int16(y), fmt.Sprint(seed), 812)
			code := "01"
			if d["bin"] == "fail" {
				code = "07"
				bins[7]++
			} else {
				good++
				bins[1]++
			}
			rowCodes[y][x] = code
			count[code]++
		}
		n := uint32(gx * gy)
		// WRR: HEAD SITE_GRP FINISH_T PART_CNT RTST_CNT ABRT_CNT GOOD_CNT FUNC_CNT WAFER_ID
		sf.rec(2, 20, uint8(1), uint8(255), wStart+1800, n, uint32(0), uint32(0), good, uint32(math.MaxUint32), w)

		var x bytes.Buffer
		fmt.Fprintf(&x, `<?xml version="1.0" encoding="UTF-8"?>
<MapData xmlns="urn:semi-org:xsd.E142-1.V1005.SubstrateMap">
  <Layouts>
    <Layout LayoutId="WaferLayout" DefaultUnits="mm" TopLevel="true">
      <Dimension X="1" Y="1"/>
      <ChildLayouts>
        <ChildLayout LayoutId="Devices"/>
      </ChildLayouts>
    </Layout>
    <Layout LayoutId="Devices" DefaultUnits="mm">
      <Dimension X="%d" Y="%d"/>
    </Layout>
  </Layouts>
  <Substrates>
    <Substrate SubstrateType="Wafer" SubstrateId="%s">
      <LotId>%s</LotId>
    </Substrate>
  </Substrates>
  <SubstrateMaps>
    <SubstrateMap SubstrateType="Wafer" SubstrateId="%s" Orientation="0" OriginLocation="UpperLeft" AxisDirection="DownRight" LayoutSpecifier="WaferLayout/Devices">
      <Overlay MapName="SortGrade" MapVersion="1">
        <BinCodeMap BinType="HexaDecimal" NullBin="FF">
          <BinDefinitions>
            <BinDefinition BinCode="01" BinCount="%d" BinQuality="Pass" BinDescription="Good die"/>
            <BinDefinition BinCode="07" BinCount="%d" BinQuality="Fail" BinDescription="IDDQ over limit"/>
          </BinDefinitions>
`, gx, gy, w, lotID, w, count["01"], count["07"])
		for _, r := range rowCodes {
			fmt.Fprintf(&x, "          <BinCode>%s</BinCode>\n", strings.Join(r, ""))
		}
		x.WriteString("        </BinCodeMap>\n      </Overlay>\n    </SubstrateMap>\n  </SubstrateMaps>\n</MapData>\n")
		files[fmt.Sprintf("sort-%s-%s.xml", lotID, w)] = x.Bytes()
	}
	sf.bins(bins, map[uint16]string{1: "PASS", 7: "IDDQ"})
	sf.rec(1, 20, uint32(sortStart.Add(3*time.Hour).Unix()), uint8(' '), "", "")
	files[sortSTDF] = sf.Bytes()

	// The OSAT's MES: the wafers arrive, the assembly lot starts from them,
	// runs its operations and ships to test; and its unit genealogy.
	var good []Obj
	for _, d := range dies {
		if d["bin"] == "pass" {
			good = append(good, d)
		}
	}
	genealogy, units, err := packageDies(pkg, good, "")
	if err != nil {
		return err
	}
	asm, n := S(pkg, "assemblyLot"), fmt.Sprint(len(units))
	rows = [][]string{header,
		{ts(day(9, 4, 9)), "EOSAT-1", lotID, "RECEIVE", "INCOMING", fmt.Sprint(len(wafers)), join(wafers, "|"), "from=" + S(srt, "site", "name")},
		{ts(day(9, 5, 7)), "EOSAT-1", asm, "LOT_START", "LOT START", n, "", "source_lot=" + lotID + "|package=" + S(pkg, "packageType") + "|device=PSOC130-QFN64"},
	}
	for i, op := range []string{"WAFER SAW", "DIE ATTACH", "WIRE BOND", "MOLD", "XRAY SAMPLE", "MARK"} {
		attrs := "result=PASS"
		if op == "XRAY SAMPLE" {
			attrs += "|sample=5"
		}
		rows = append(rows, []string{ts(day(9, 5, 9+i)), "EOSAT-1", asm, "TRACK_OUT", op, n, "", attrs})
	}
	rows = append(rows, []string{ts(day(9, 6, 10)), "EOSAT-1", asm, "SHIP", "SHIP", n, "", "ship_to=" + S(ft, "site", "name")})
	files["osat-mes-lot-history.csv"] = csvFile(rows)
	rows = [][]string{mesGenealogyColumns}
	for _, u := range units {
		g := O(genealogy, u)
		rows = append(rows, []string{u, asm, lotID, S(g, "wafer"), num(g["x"]), num(g["y"])})
	}
	files["osat-mes-genealogy.csv"] = csvFile(rows)

	// Final test: one STDF file for the assembly lot, a PRR per unit by serial.
	ftTests := []stdfTest{{1000, "scan_chain", "", 1, 1}, {1010, "idd_active", "mA", 0, 12}, {1020, "fmax", "MHz", 50, 400}}
	var tf stdfFile
	ftStart := day(9, 8, 8)
	tf.header(ftStart, S(ft, "lotId"), "FT-03", "UltraFLEX", S(ft, "program", "name"), S(ft, "program", "version"), "FT1")
	failed := setOf(Strs(ft, "failedUnits"))
	bins = map[uint16]uint32{}
	for i, u := range units {
		vals := []float32{1, spread(i, 6, 9), spread(i, 82, 96)}
		if failed[u] {
			vals[2] = 41 + float32(i%5)
			bins[5]++
		} else {
			bins[1]++
		}
		tf.part(ftTests, vals, 5, 1, -32768, -32768, u, 1450)
	}
	tf.bins(bins, map[uint16]string{1: "PASS", 5: "FMAX"})
	tf.rec(1, 20, uint32(ftStart.Add(2*time.Hour).Unix()), uint8(' '), "", "")
	files[finalSTDF] = tf.Bytes()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// sampleExportNames are the generated files, as opposed to the hand-written
// configurations and policies next to them.
func sampleExportNames(dir string) []string {
	var out []string
	for _, e := range ok(os.ReadDir(dir)) {
		if !strings.HasSuffix(e.Name(), ".json") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestSampleExportsAreCurrent(t *testing.T) {
	if *updateExports {
		must(t, sampleExports(exportsDir))
	}
	dir := t.TempDir()
	must(t, sampleExports(dir))
	want, have := sampleExportNames(dir), sampleExportNames(exportsDir)
	if !equalStrings(want, have) {
		t.Fatalf("committed exports %v, generator writes %v; run go test -run TestSampleExportsAreCurrent -update-exports", have, want)
	}
	for _, name := range want {
		if !bytes.Equal(ok(os.ReadFile(filepath.Join(dir, name))), ok(os.ReadFile(filepath.Join(exportsDir, name)))) {
			t.Errorf("%s differs from what the generator writes; run go test -run TestSampleExportsAreCurrent -update-exports", name)
		}
	}
}

func TestAdapterReadsTheSameLot(t *testing.T) {
	// The exports, read back, are the lot the scenario describes.
	sc := ok(AdaptScenario(exportsConfig))
	base := ok(ReadObj(e2eScenario))
	for _, k := range []string{"product", "waferLot", "transfers"} {
		if !jsonEqual(sc[k], base[k]) {
			t.Errorf("%s differs: %s", k, compactJSON(sc[k]))
		}
	}
	for _, k := range []string{"id", "site", "processNode", "maskSetId"} {
		if !jsonEqual(get(sc, "fab", k), get(base, "fab", k)) {
			t.Errorf("fab.%s differs", k)
		}
	}
	if !jsonEqual(get(sc, "sort", "program"), get(base, "sort", "program")) || !jsonEqual(get(sc, "finalTest", "program"), get(base, "finalTest", "program")) {
		t.Error("test programs differ")
	}
	wafers := Strs(base, "waferLot", "wafers")
	if !jsonEqual(ok(sortDies(O(sc, "sort"), wafers)), ok(sortDies(O(base, "sort"), wafers))) {
		t.Error("wafer maps differ")
	}
	for _, k := range []string{"site", "packageType", "assemblyLot", "units"} {
		if !jsonEqual(get(sc, "packaging", k), get(base, "packaging", k)) {
			t.Errorf("packaging.%s differs", k)
		}
	}
	for _, k := range []string{"site", "lotId", "failedUnits"} {
		if !jsonEqual(get(sc, "finalTest", k), get(base, "finalTest", k)) {
			t.Errorf("finalTest.%s differs: %s", k, compactJSON(get(sc, "finalTest", k)))
		}
	}
	if !jsonEqual(get(sc, "fab", "checks"), passed("mask-vs-gds-xor", "inline-parametrics")) ||
		!jsonEqual(get(sc, "packaging", "checks"), passed("die-attach", "wire-bond", "x-ray-sample", "marking")) {
		t.Errorf("checks differ: %s %s", compactJSON(get(sc, "fab", "checks")), compactJSON(get(sc, "packaging", "checks")))
	}
}

func TestSTDFByteOrders(t *testing.T) {
	// A big-endian file (FAR CPU_TYPE 1) reads the same as a little-endian one.
	tests := []stdfTest{{1, "iddq", "uA", 0, 5}}
	write := func(big bool) []byte {
		f := stdfFile{big: big}
		f.header(time.Unix(1788249600, 0), "LOT-1", "node", "tester", "prog", "2.0", "WS1")
		f.rec(2, 10, uint8(1), uint8(255), uint32(0), "W07")
		f.part(tests, []float32{1}, 7, 1, 3, -2, "1", 0)
		f.part(tests, []float32{9}, 7, 1, 300, 4, "2", 0)
		f.rec(2, 20, uint8(1), uint8(255), uint32(0), uint32(2), uint32(0), uint32(0), uint32(1), uint32(0), "W07")
		f.rec(1, 20, uint32(0), uint8(' '), "", "")
		return f.Bytes()
	}
	le, be := ok(parseSTDF(write(false))), ok(parseSTDF(write(true)))
	want := []STDFPart{
		{Wafer: "W07", X: 3, Y: -2, PartID: "1", HardBin: 1},
		{Wafer: "W07", X: 300, Y: 4, PartID: "2", HardBin: 7, Failed: true},
	}
	for _, got := range []*STDF{le, be} {
		if got.LotID != "LOT-1" || got.JobName != "prog" || got.JobRev != "2.0" || fmt.Sprint(got.Parts) != fmt.Sprint(want) {
			t.Errorf("read %+v", *got)
		}
	}
	data := write(false)
	if _, err := parseSTDF(data[:len(data)-3]); err == nil {
		t.Error("a truncated file parsed")
	}
	if _, err := parseSTDF([]byte("not stdf")); err == nil {
		t.Error("a non-STDF file parsed")
	}
}

// adaptedExports copies the sample exports and configurations to a
// temporary directory, where a test may change them.
func adaptedExports(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "exports")
	must(t, copyTree(exportsDir, dir))
	return dir
}

func editFile(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	before := string(ok(os.ReadFile(path)))
	after := edit(before)
	if after == before {
		t.Fatalf("edit left %s unchanged", path)
	}
	must(t, os.WriteFile(path, []byte(after), 0o644))
}

func TestAdapterRefusesExportsThatDisagree(t *testing.T) {
	for _, c := range []struct {
		name, file, old, new, want string
	}{
		{"wafer map and STDF", "sort-LOT-EXAMPLE-A-W01.xml", "<BinCode>01", "<BinCode>07", "the wafer map and the STDF results disagree"},
		{"unit on a failed die", "osat-mes-genealogy.csv", "PSOC130-A0-00001,ASM-EXAMPLE-17,LOT-EXAMPLE-A,W01,0,0", "PSOC130-A0-00001,ASM-EXAMPLE-17,LOT-EXAMPLE-A,W01,2,0", "did not pass wafer sort"},
		{"assembly from another lot", "osat-mes-lot-history.csv", "source_lot=LOT-EXAMPLE-A", "source_lot=LOT-EXAMPLE-B", "was started from LOT-EXAMPLE-B"},
		{"missing MES operation", "osat-mes-lot-history.csv", "WIRE BOND", "BOND", `no TRACK_OUT for operation "WIRE BOND"`},
		{"quantity off", "fab-mes-lot-history.csv", "LOT_START,LOT START,2,", "LOT_START,LOT START,3,", "lists 2 wafers for a quantity of 3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := adaptedExports(t)
			editFile(t, filepath.Join(dir, c.file), func(s string) string { return strings.Replace(s, c.old, c.new, 1) })
			_, err := AdaptScenario(filepath.Join(dir, "adapter.json"))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestAdapterReportsAFailedOperation(t *testing.T) {
	// A failed MES operation becomes a failed check, which the verifier refuses.
	dir := adaptedExports(t)
	editFile(t, filepath.Join(dir, "osat-mes-lot-history.csv"), func(s string) string {
		return strings.Replace(s, "WIRE BOND,40,,result=PASS", "WIRE BOND,40,,result=FAIL", 1)
	})
	sc := ok(AdaptScenario(filepath.Join(dir, "adapter.json")))
	if failed := failedChecks(Objs(sc, "packaging", "checks")); !equalStrings(failed, []string{"wire-bond"}) {
		t.Fatalf("failed checks %v, want wire-bond", failed)
	}
}

// adaptedBundle is a fresh chip bundle whose lot was made from the exports
// under the adapter configuration config in dir.
func adaptedBundle(t *testing.T, dir, config string) string {
	t.Helper()
	bundle := chipBundle(t)
	keys := chipKeys(bundle)
	scenario := filepath.Join(t.TempDir(), "scenario.json")
	must(t, Adapt(filepath.Join(dir, config), scenario))
	must(t, Mfg(bundle, scenario, keys, nil))
	must(t, BuildHBOM(bundle, e2eLock, scenario, filepath.Join(keys, "product-owner.key.pem"), nil))
	return bundle
}

func TestAdaptedLotVerifies(t *testing.T) {
	bundle := adaptedBundle(t, exportsDir, "adapter.json")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, lot, err := Verify(bundle, trust, exportsPolicy, e2eUnits, "", "")
	must(t, err)
	got := strings.Join(lot.Exports, "\n")
	for _, want := range []string{
		"wafer-fab: matches fab-mes-lot-history.csv",
		"wafer-sort: matches sort-LOT-EXAMPLE-A.stdf, sort-LOT-EXAMPLE-A-W01.xml, sort-LOT-EXAMPLE-A-W02.xml",
		"packaging: matches osat-mes-lot-history.csv, osat-mes-genealogy.csv",
		"final-test: matches ft-ASM-EXAMPLE-17.stdf",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not say %q:\n%s", want, got)
		}
	}
	// The same lot as the scenario's: same units, same digest.
	main := chipBundle(t)
	for _, f := range []string{"shipped-lot.txt", "packaged-lot.txt", "wafer-maps.json", "genealogy.json", "final-test-results.json"} {
		if !bytes.Equal(ok(os.ReadFile(filepath.Join(bundle, "artifacts", f))), ok(os.ReadFile(filepath.Join(main, "artifacts", f)))) {
			t.Errorf("%s differs from the scenario's lot", f)
		}
	}
}

func TestPolicyCanRequireExports(t *testing.T) {
	// The main example's records carry no exports, so a policy that wants them refuses it.
	rejects(t, chipCheckPolicy(t, chipBundle(t), nil, exportsPolicy),
		"wafer-fab: the policy requires each record to carry its supplier's exports")
}

func TestChangedExportIsRejected(t *testing.T) {
	bundle := adaptedBundle(t, exportsDir, "adapter.json")
	appendFile(t, filepath.Join(bundle, "artifacts", finalSTDF), "\x00")
	rejects(t, chipCheckPolicy(t, bundle, nil, exportsPolicy), "final-test: export ft-ASM-EXAMPLE-17.stdf does not match its attested digest")
}

func TestRecordThatDiffersFromItsExportIsRejected(t *testing.T) {
	// The test house signs a record that passes a unit its own STDF file
	// failed: the signature is good, the export says otherwise.
	bundle := adaptedBundle(t, exportsDir, "adapter.json")
	results := filepath.Join(bundle, "artifacts", "final-test-results.json")
	editJSON(t, results, func(v Obj) { O(v, "units")["PSOC130-A0-00007"] = "pass" })
	chipResign(t, bundle, MfgAtt["final-test"], "test-site", func(stmt Obj) {
		for _, s := range Objs(stmt, "subject") {
			if S(s, "name") == "final-test-results.json" {
				s["digest"] = fileDigest(results)
			}
		}
	})
	rejects(t, chipCheckPolicy(t, bundle, nil, exportsPolicy), "final-test: the final test results differs from its supplier's exports")
}

func TestExportNotInDependenciesIsRejected(t *testing.T) {
	bundle := adaptedBundle(t, exportsDir, "adapter.json")
	chipResign(t, bundle, MfgAtt["final-test"], "test-site", func(stmt Obj) {
		bd := O(stmt, "predicate", "buildDefinition")
		var keep []any
		for _, d := range Objs(bd, "resolvedDependencies") {
			if S(d, "name") != finalSTDF {
				keep = append(keep, d)
			}
		}
		bd["resolvedDependencies"] = keep
	})
	rejects(t, chipCheckPolicy(t, bundle, nil, exportsPolicy), "final-test: export \"ft-ASM-EXAMPLE-17.stdf\" is not one of its resolvedDependencies")
}

func TestProxySignedFromSTDF(t *testing.T) {
	// The test house runs no adapter and signs nothing: it hands its STDF
	// file to the product owner, who runs the adapter and proxy-signs F4.
	bundle := adaptedBundle(t, exportsDir, "adapter-proxy.json")
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, lot, err := Verify(bundle, trust, exportsProxyPolicy, "", "", "")
	must(t, err)
	if got := strings.Join(lot.OnBehalf, "\n"); !strings.Contains(got, "final-test: proxy-signed by Example Open Silicon Group for Example Test House") {
		t.Errorf("output does not name the proxy:\n%s", got)
	}
	if got := strings.Join(lot.Exports, "\n"); !strings.Contains(got, "final-test: matches ft-ASM-EXAMPLE-17.stdf") {
		t.Errorf("the proxy-signed record was not checked against the STDF file:\n%s", got)
	}
	rejects(t, chipCheckPolicy(t, bundle, nil, exportsPolicy), "the policy does not accept proxy-signed records")
}

func TestAdapterExamplesMatch(t *testing.T) {
	// The proxy configuration and policies differ from the main ones only where they say so.
	a, p := ok(ReadObj(exportsConfig)), ok(ReadObj(exportsProxyConfig))
	delete(p, "unsigned")
	if !jsonEqual(a, p) {
		t.Error("adapter-proxy.json differs from adapter.json beyond its unsigned block")
	}
	base, req, proxy := ok(ReadObj(e2ePolicy)), ok(ReadObj(exportsPolicy)), ok(ReadObj(exportsProxyPolicy))
	if !jsonEqual(req["design"], base["design"]) || !jsonEqual(req["claims"], base["claims"]) || !jsonEqual(proxy["design"], base["design"]) {
		t.Error("the adapter policies' design rules or claims differ from policy.json")
	}
	if !Truthy(get(req, "manufacturing", "requireExports")) || !Truthy(get(proxy, "manufacturing", "requireExports")) {
		t.Error("the adapter policies do not require exports")
	}
}

func TestAdaptedLotCannotWithhold(t *testing.T) {
	bundle := chipBundle(t)
	scenario := filepath.Join(t.TempDir(), "scenario.json")
	must(t, Adapt(exportsConfig, scenario))
	err := Mfg(bundle, scenario, chipKeys(bundle), &Withholding{Fields: map[string][]string{"wafer-fab": {"/predicate/hwMfg/yield"}}})
	if err == nil || !strings.Contains(err.Error(), "cannot withhold fields yet") {
		t.Fatalf("got %v", err)
	}
}

func TestOtherAdapter(t *testing.T) {
	// A record from an adapter this verifier does not run is checked as an
	// ordinary record, unless the policy requires its exports checked.
	bundle := adaptedBundle(t, exportsDir, "adapter.json")
	chipResign(t, bundle, MfgAtt["final-test"], "test-site", func(stmt Obj) {
		O(stmt, "predicate", "hwMfg", "adapter")["id"] = "https://example.com/other-adapter"
	})
	scenario := filepath.Join(t.TempDir(), "scenario.json")
	must(t, Adapt(exportsConfig, scenario))
	must(t, BuildHBOM(bundle, e2eLock, scenario, filepath.Join(chipKeys(bundle), "product-owner.key.pem"), nil))
	trust := ok(LoadTrustRoot(filepath.Join(bundle, "trust-root.json")))
	_, lot, err := Verify(bundle, trust, e2ePolicy, "", "", "")
	must(t, err)
	if got := strings.Join(lot.Exports, "\n"); !strings.Contains(got, "final-test: made by adapter https://example.com/other-adapter, which this verifier does not run") {
		t.Errorf("output does not say so:\n%s", got)
	}
	rejects(t, chipCheckPolicy(t, bundle, nil, exportsPolicy), "which this verifier cannot run, and the policy requires its exports to be checked")
}
