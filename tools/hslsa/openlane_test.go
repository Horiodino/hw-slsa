package hslsa

// OpenLane step records: chain checks and the reproducibility classifier, on a synthetic run.
//
// No OpenLane needed: the tests lay out step directories the way OpenLane 2
// writes them (state_in.json, state_out.json, config.json, runtime.txt) and
// sign them with the same code the real run uses.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var olLock = filepath.Join(root, "openlane2", "spm", "flow.lock.json")

// gds is a minimal GDSII stream; stamp is the seconds field of its dates.
func gds(stamp int, geometry []byte) []byte {
	rec := func(rtype, dtype byte, payload []byte) []byte {
		out := binary.BigEndian.AppendUint16(nil, uint16(4+len(payload)))
		return append(append(out, rtype, dtype), payload...)
	}
	var dates []byte
	for range 2 {
		for _, x := range []int{2026, 9, 29, 8, 30, stamp} {
			dates = binary.BigEndian.AppendUint16(dates, uint16(x))
		}
	}
	return bytes.Join([][]byte{
		rec(0x00, 0x02, binary.BigEndian.AppendUint16(nil, 600)),
		rec(0x01, 0x02, dates),
		rec(0x02, 0x06, []byte("spm\x00")),
		rec(0x05, 0x02, dates),
		rec(0x06, 0x06, []byte("spm\x00")),
		rec(0x10, 0x03, bytes.Repeat(geometry, 4)),
		rec(0x07, 0x00, nil),
		rec(0x04, 0x00, nil),
	}, nil)
}

type olStep struct {
	slug     string
	produced [][2]string // view, file name
	metrics  Obj
}

// infinity stands in for a float metric OpenLane writes as a bare Infinity.
const infinity = "__inf__"

var olSteps = []olStep{
	{"yosys-synthesis", [][2]string{{"nl", "spm.nl.v"}}, Obj{"design__instance__count": 100}},
	{"openroad-floorplan", [][2]string{{"odb", "spm.odb"}, {"def", "spm.def"}}, Obj{}},
	{"openroad-globalplacement", [][2]string{{"odb", "spm.odb"}}, Obj{"timing__setup__ws": infinity}},
	{"openroad-detailedrouting", [][2]string{{"odb", "spm.odb"}, {"def", "spm.def"}}, Obj{"route__drc_errors": 0}},
	{"openroad-rcx", [][2]string{{"spef.nom_*", "spm.nom.spef"}}, Obj{}},
	{"magic-streamout", [][2]string{{"gds", "spm.gds"}}, Obj{}},
	{"magic-drc", nil, Obj{"magic__drc_error__count": 0}},
	{"netgen-lvs", nil, Obj{"design__lvs_error__count": 0}},
}

type tweak struct {
	slug string
	edit func([]byte) []byte
}

func writeState(t *testing.T, path string, state Obj) {
	t.Helper()
	data := ok(json.Marshal(state))
	data = bytes.ReplaceAll(data, []byte(`"`+infinity+`"`), []byte("Infinity"))
	must(t, os.WriteFile(path, data, 0o644))
}

func cloneObj(o Obj) Obj {
	var out Obj
	if err := json.Unmarshal(ok(json.Marshal(o)), &out); err != nil {
		panic(err)
	}
	return out
}

// fakeRun writes the step directories one by one, signing each as the watcher would.
func fakeRun(t *testing.T, f *Flow, steps []olStep, stamp int, tw *tweak) {
	t.Helper()
	state := Obj{"metrics": Obj{}}
	for i, step := range steps {
		d := filepath.Join(f.RunDir, fmt.Sprintf("%02d-%s", i+1, step.slug))
		must(t, os.MkdirAll(d, 0o755))
		writeState(t, filepath.Join(d, "state_in.json"), state)
		must(t, os.WriteFile(filepath.Join(d, "config.json"), ok(json.Marshal(Obj{"DESIGN_NAME": "spm", "step": step.slug})), 0o644))
		out := cloneObj(state)
		for _, p := range step.produced {
			view, name := p[0], p[1]
			var data []byte
			if strings.HasSuffix(name, ".gds") {
				data = gds(stamp, []byte{0, 1})
			} else {
				data = fmt.Appendf(nil, "%s %s generated 2026-09-29 08:30:%02d\n", step.slug, view, stamp)
			}
			if tw != nil && tw.slug == step.slug {
				data = tw.edit(data)
			}
			path := filepath.Join(d, name)
			must(t, os.WriteFile(path, data, 0o644))
			if top, key, nested := strings.Cut(view, "."); nested {
				if _, ok := out[top].(map[string]any); !ok {
					out[top] = Obj{}
				}
				O(out, top)[key] = path
			} else {
				out[view] = path
			}
		}
		for k, v := range step.metrics {
			O(out, "metrics")[k] = v
		}
		writeState(t, filepath.Join(d, "state_out.json"), out)
		must(t, os.WriteFile(filepath.Join(d, step.slug+".log"), fmt.Appendf(nil, "[08:30:%02d] ran %s\n", stamp, step.slug), 0o644))
		must(t, os.WriteFile(filepath.Join(d, "runtime.txt"), []byte("0:00:01"), 0o644))
		must(t, f.attestReady())
		state = out
	}
	ok(f.WriteSummary(0))
}

type olRun struct {
	bundle, runDir, keys string
}

// olProduce makes a signed bundle for a synthetic run under base, and returns the release error.
func olProduce(t *testing.T, base string, steps []olStep, stamp int, tw *tweak) (olRun, error) {
	t.Helper()
	keys, bundle, work := filepath.Join(base, "keys"), filepath.Join(base, "bundle"), filepath.Join(base, "work")
	must(t, makeKeys(keys, filepath.Join(keys, "pub"), "flow-platform", "tapeout-authority"))
	must(t, os.MkdirAll(bundle, 0o755))
	must(t, BuildTrustRoot(filepath.Join(keys, "pub"), filepath.Join(bundle, "trust-root.json")))

	lock := ok(ReadObj(olLock))
	cache := filepath.Join(base, "cache")
	files := O(lock, "source", "files")
	for name := range files {
		path := filepath.Join(cache, name)
		must(t, os.MkdirAll(filepath.Dir(path), 0o755))
		must(t, os.WriteFile(path, []byte("source "+name+"\n"), 0o644))
		files[name] = ok(sha256File(path))
	}
	lockPath := filepath.Join(base, "lock.json")
	must(t, WriteJSON(lockPath, lock))
	must(t, SourceFreeze(bundle, lockPath, filepath.Join(keys, "flow-platform.key.pem"), cache, nil))

	f := ok(NewFlow(bundle, lockPath, filepath.Join(keys, "flow-platform.key.pem"), work, base))
	must(t, os.MkdirAll(f.meta, 0o755))
	f.source = ok(fileRD(filepath.Join(bundle, "artifacts", "source.tar"), ""))
	f.source["annotations"] = Obj{"kind": "source"}
	f.tools = Obj{
		"openlane": Obj{"version": "2.3.10", "digest": strings.Repeat("aa", 32)},
		"yosys":    Obj{"version": "0.4", "digest": strings.Repeat("bb", 32)},
	}
	must(t, WriteJSON(filepath.Join(f.meta, "tools.json"), f.tools))
	f.pdk = Obj{"name": "sky130A", "digest": Obj{"sha256": strings.Repeat("cc", 32)}, "annotations": Obj{"kind": "pdk"}}
	f.overlay = Obj{"name": "openlane2-overlay", "digest": Obj{"sha256": strings.Repeat("ee", 32)}, "annotations": Obj{"kind": "overlay"}}
	image := f.imageRD()
	image["annotations"] = Obj{"kind": "toolchain"}
	f.commonDeps = []Obj{f.source, image, f.pdk, f.overlay}
	fakeRun(t, f, steps, stamp, tw)
	err := OpenLaneRelease(bundle, f.RunDir, filepath.Join(keys, "tapeout-authority.key.pem"), filepath.Join(bundle, "trust-root.json"), olLock)
	return olRun{bundle, f.RunDir, keys}, err
}

func olValid(t *testing.T) (olRun, *TrustRoot) {
	t.Helper()
	run, err := olProduce(t, t.TempDir(), olSteps, 0, nil)
	must(t, err)
	return run, ok(LoadTrustRoot(filepath.Join(run.bundle, "trust-root.json")))
}

func olResign(t *testing.T, run olRun, name, role string, mutate func(Obj)) {
	t.Helper()
	resign(t, filepath.Join(run.bundle, "att", name), run.keys, role, mutate)
}

func olEntries(t *testing.T, run olRun) []Obj {
	t.Helper()
	return Objs(ok(ReadObj(filepath.Join(run.bundle, "openlane", "run.json"))), "steps")
}

func TestValidRunVerifies(t *testing.T) {
	run, trust := olValid(t)
	records, final, err := OpenLaneVerify(run.bundle, run.runDir, trust)
	must(t, err)
	if len(records) != len(olSteps) {
		t.Fatalf("%d records, want %d", len(records), len(olSteps))
	}
	if S(final, "name") != "spm.gds" {
		t.Fatalf("final GDS %s", S(final, "name"))
	}
	var steps []string
	for _, r := range records {
		steps = append(steps, S(r.stmt, "predicate", "hwFlow", "step"))
	}
	want := []string{"synthesis", "floorplan", "place-cts", "routing", "signoff", "gds-stream-out", "signoff", "signoff"}
	if !equalStrings(steps, want) {
		t.Fatalf("spec steps %v, want %v", steps, want)
	}
	// inf metrics are carried as strings, and views link to the step that produced them
	if v := get(records[2].stmt, "predicate", "hwFlow", "metrics", "timing__setup__ws"); v != "inf" {
		t.Fatalf("timing__setup__ws = %v", v)
	}
	var views []string
	for _, d := range Objs(records[3].stmt, "predicate", "buildDefinition", "resolvedDependencies") {
		if S(d, "annotations", "kind") == "view" {
			views = append(views, S(d, "name"))
		}
	}
	if !sameSet(views, []string{"01-yosys-synthesis/spm.nl.v", "03-openroad-globalplacement/spm.odb", "02-openroad-floorplan/spm.def"}) {
		t.Fatalf("input views %v", views)
	}
}

func olRejects(t *testing.T, run olRun, trust *TrustRoot, reason string) {
	t.Helper()
	_, _, err := OpenLaneVerify(run.bundle, run.runDir, trust)
	rejects(t, err, reason)
}

func TestChangedOutputIsCaught(t *testing.T) {
	run, trust := olValid(t)
	must(t, os.WriteFile(filepath.Join(run.runDir, "04-openroad-detailedrouting", "spm.def"), []byte("rerouted\n"), 0o644))
	olRejects(t, run, trust, "subject 04-openroad-detailedrouting/spm.def")
}

func TestInputViewFromNowhereIsCaught(t *testing.T) {
	run, trust := olValid(t)
	olResign(t, run, S(olEntries(t, run)[3], "attestation"), "flow-platform", func(s Obj) {
		for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
			if strings.HasSuffix(S(d, "name"), "spm.odb") {
				O(d, "digest")["sha256"] = strings.Repeat("00", 32)
			}
		}
	})
	_, _, err := OpenLaneVerify(run.bundle, run.runDir, trust)
	rejects(t, err, "input view ")
	rejects(t, err, " is not an output of any earlier step")
}

func TestDroppedStepIsCaught(t *testing.T) {
	run, trust := olValid(t)
	editJSON(t, filepath.Join(run.bundle, "openlane", "run.json"), func(meta Obj) {
		steps := A(meta, "steps")
		meta["steps"] = append(steps[:2:2], steps[3:]...)
	})
	_, _, err := OpenLaneVerify(run.bundle, run.runDir, trust)
	if !IsVerificationError(err) {
		t.Fatalf("got %v, want a verification failure", err)
	}
}

func TestOtherPDKIsCaught(t *testing.T) {
	run, trust := olValid(t)
	olResign(t, run, S(olEntries(t, run)[0], "attestation"), "flow-platform", func(s Obj) {
		for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
			if S(d, "annotations", "kind") == "pdk" {
				O(d, "digest")["sha256"] = strings.Repeat("dd", 32)
			}
		}
	})
	olRejects(t, run, trust, "PDK")
}

func TestOtherOverlayIsCaught(t *testing.T) {
	run, trust := olValid(t)
	olResign(t, run, S(olEntries(t, run)[4], "attestation"), "flow-platform", func(s Obj) {
		for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
			if S(d, "annotations", "kind") == "overlay" {
				O(d, "digest")["sha256"] = strings.Repeat("dd", 32)
			}
		}
	})
	olRejects(t, run, trust, "does not name the flow's script overlay")
}

func TestOtherSourceDateEpochIsCaught(t *testing.T) {
	run, trust := olValid(t)
	olResign(t, run, S(olEntries(t, run)[5], "attestation"), "flow-platform", func(s Obj) {
		O(s, "predicate", "buildDefinition", "externalParameters")["sourceDateEpoch"] = 1
	})
	olRejects(t, run, trust, "SOURCE_DATE_EPOCH differs")
}

func TestOverlayMustMatchTheImage(t *testing.T) {
	dir := t.TempDir()
	overlay := filepath.Join(dir, "overlay")
	must(t, os.MkdirAll(filepath.Join(overlay, "magic"), 0o755))
	must(t, os.WriteFile(filepath.Join(overlay, "magic", "mag_gds.tcl"), []byte("gds datestamp 1\n"), 0o644))
	lockPath := filepath.Join(dir, "lock.json")
	upstream := strings.Repeat("ab", 32)
	must(t, WriteJSON(lockPath, Obj{"reproducibility": Obj{"overlay": Obj{"dir": "overlay", "replaces": Obj{"magic/mag_gds.tcl": upstream}}}}))
	newFlow := func() *Flow {
		return &Flow{lockPath: lockPath, lock: ok(ReadObj(lockPath))}
	}
	image := Obj{"magic/mag_gds.tcl": Obj{"path": "/nix/store/x-openlane/scripts/magic/mag_gds.tcl", "sha256": upstream}}

	f := newFlow()
	must(t, f.prepareOverlay(image))
	if len(f.mounts) != 1 || !strings.HasSuffix(f.mounts[0], ":/nix/store/x-openlane/scripts/magic/mag_gds.tcl:ro") {
		t.Fatalf("mounts %v", f.mounts)
	}
	if S(f.overlay, "digest", "sha256") != ok(TreeDigest(overlay)) {
		t.Fatalf("overlay digest %s", S(f.overlay, "digest", "sha256"))
	}

	changed := Obj{"magic/mag_gds.tcl": Obj{"path": "/x", "sha256": strings.Repeat("cd", 32)}}
	if err := newFlow().prepareOverlay(changed); err == nil || !strings.Contains(err.Error(), "the overlay was made from") {
		t.Fatalf("got %v, want an upstream mismatch", err)
	}
	must(t, os.WriteFile(filepath.Join(overlay, "extra.tcl"), nil, 0o644))
	if err := newFlow().prepareOverlay(image); err == nil || !strings.Contains(err.Error(), "not listed in the lock") {
		t.Fatalf("got %v, want an unlisted overlay file", err)
	}
}

func TestStepSignedByWrongRoleIsCaught(t *testing.T) {
	run, trust := olValid(t)
	olResign(t, run, S(olEntries(t, run)[1], "attestation"), "tapeout-authority", nil)
	olRejects(t, run, trust, "no valid signature from role 'flow-platform'")
}

func TestReleaseOfOtherGDSIsCaught(t *testing.T) {
	run, trust := olValid(t)
	path := filepath.Join(run.bundle, "artifacts", "spm.gds")
	must(t, os.WriteFile(path, gds(9, []byte{9, 9}), 0o644))
	olResign(t, run, OpenLaneReleaseAtt, "tapeout-authority", func(s Obj) {
		O(Objs(s, "subject")[0], "digest")["sha256"] = ok(sha256File(path))
	})
	olRejects(t, run, trust, "not the flow's final GDS")
}

func TestReleaseRefusesFailedSignoff(t *testing.T) {
	steps := append(append([]olStep{}, olSteps...), olStep{"checker-klayoutdrc", nil, Obj{"klayout__drc_error__count": 3}})
	_, err := olProduce(t, t.TempDir(), steps, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "klayout__drc_error__count") {
		t.Fatalf("release error %v, want a failed klayout__drc_error__count gate", err)
	}
}

func compareRuns(t *testing.T, a, b olRun) Obj {
	t.Helper()
	ta := ok(LoadTrustRoot(filepath.Join(a.bundle, "trust-root.json")))
	tb := ok(LoadTrustRoot(filepath.Join(b.bundle, "trust-root.json")))
	return ok(OpenLaneCompare(a.bundle, a.runDir, b.bundle, b.runDir, ta, tb))
}

func TestCompareIdenticalRuns(t *testing.T) {
	dir := t.TempDir()
	a, err := olProduce(t, filepath.Join(dir, "a"), olSteps, 0, nil)
	must(t, err)
	b, err := olProduce(t, filepath.Join(dir, "b"), olSteps, 0, nil)
	must(t, err)
	report := compareRuns(t, a, b)
	if c := S(report, "finalGds", "class"); c != "identical" {
		t.Fatalf("final GDS class %s", c)
	}
	exact, _ := Int(report, "subjects", "bitExact")
	total, _ := Int(report, "subjects", "total")
	if exact >= total { // state_out.json names the run dir
		t.Fatalf("bitExact %d of %d", exact, total)
	}
	if get(report, "firstContentDivergence") == nil {
		t.Fatal("no first content divergence")
	}
}

func TestCompareTimestampsAndContent(t *testing.T) {
	// Runs laid out at the same path, one second apart, with one real difference in routing.
	dir := t.TempDir()
	base := filepath.Join(dir, "same")
	moved := func(run olRun, to string) olRun {
		must(t, os.Rename(base, to))
		rel := ok(filepath.Rel(base, run.runDir))
		return olRun{filepath.Join(to, "bundle"), filepath.Join(to, rel), filepath.Join(to, "keys")}
	}
	a, err := olProduce(t, base, olSteps, 1, nil)
	must(t, err)
	a = moved(a, filepath.Join(dir, "a"))
	b, err := olProduce(t, base, olSteps, 2, &tweak{"openroad-detailedrouting", func(d []byte) []byte {
		return bytes.ReplaceAll(d, []byte("def"), []byte("DEF"))
	}})
	must(t, err)
	b = moved(b, filepath.Join(dir, "b"))
	report := compareRuns(t, a, b)
	rows := map[string]Obj{}
	for _, r := range Objs(report, "perStep") {
		rows[S(r, "step")] = r
	}
	for step, want := range map[string]string{
		"yosys-synthesis":          "timestamps",
		"magic-streamout":          "timestamps",
		"openroad-detailedrouting": "content",
	} {
		if got := S(rows[step], "subjectWorst"); got != want {
			t.Errorf("%s: subjectWorst %s, want %s", step, got, want)
		}
	}
	if got := S(report, "firstContentDivergence"); got != "openroad-detailedrouting" {
		t.Errorf("first content divergence %s", got)
	}
	if got := S(report, "finalGds", "class"); got != "timestamps" {
		t.Errorf("final GDS class %s", got)
	}
	md := ReproducibilityMarkdown(report)
	if !strings.Contains(md, "openroad-detailedrouting") || !strings.Contains(md, "| content |") {
		t.Errorf("markdown report misses the content row:\n%s", md)
	}
}

func TestClassify(t *testing.T) {
	mag := "magic\ntech sky130A\nmagscale 1 2\ntimestamp %d\n"
	cases := []struct {
		a, b  []byte
		name  string
		hosts []string
		want  string
	}{
		{gds(1, []byte{0, 1}), gds(2, []byte{0, 1}), "x.gds", nil, "timestamps"},
		{gds(1, []byte{0, 1}), gds(1, []byte{7, 7}), "x.gds", nil, "content"},
		{[]byte("a\nb\n"), []byte("b\na\n"), "x.rpt", nil, "ordering"},
		{[]byte("took 1.5 s on fv-az1\n"), []byte("took 2.25 s on fv-az2\n"), "x.log", []string{"fv-az1", "fv-az2"}, "timestamps"},
		{[]byte("\x00odb1"), []byte("\x00odb2"), "x.odb", nil, "content"},
		{fmt.Appendf(nil, mag, 1790671539), fmt.Appendf(nil, mag, 1790671554), "spm.mag", nil, "timestamps"},
	}
	for i, c := range cases {
		if got, _ := Classify(c.a, c.b, c.name, c.hosts...); got != c.want {
			t.Errorf("case %d (%s): %s, want %s", i, c.name, got, c.want)
		}
	}
}

func TestSpecStepMappingCoversClassicFlow(t *testing.T) {
	classic := []string{
		"verilator-lint", "checker-linttimingconstructs", "yosys-jsonheader", "yosys-synthesis",
		"checker-yosysunmappedcells", "openroad-checksdcfiles", "openroad-staprepnr", "openroad-floorplan",
		"odb-setpowerconnections", "openroad-tapendcapinsertion", "openroad-generatepdn",
		"openroad-globalplacementskipio", "openroad-ioplacement", "odb-customioplacement", "openroad-globalplacement",
		"odb-writeverilogheader", "checker-powergridviolations", "openroad-stamidpnr", "openroad-cts",
		"openroad-detailedplacement", "openroad-globalrouting", "openroad-detailedrouting", "checker-trdrc",
		"odb-reportwirelength", "openroad-fillinsertion", "openroad-rcx", "openroad-stapostpnr", "magic-streamout",
		"klayout-streamout", "magic-writelef", "klayout-xor", "magic-drc", "klayout-drc", "magic-spiceextraction",
		"netgen-lvs", "checker-lvs", "misc-reportmanufacturability",
	}
	for _, s := range classic {
		if SpecStep(s) == "other" {
			t.Errorf("%s maps to no spec step", s)
		}
	}
	if SpecStep("openroad-stamidpnr") != "signoff" || SpecStep("klayout-streamout") != "gds-stream-out" {
		t.Error("wrong spec step for openroad-stamidpnr or klayout-streamout")
	}
}

func TestDeterministicTarOfNestedSource(t *testing.T) {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "a", "b", "f.v"), []byte("module f; endmodule\n"), 0o644))
	must(t, DeterministicTar(dir, []string{"a/b/f.v"}, filepath.Join(dir, "1.tar")))
	must(t, DeterministicTar(dir, []string{"a/b/f.v"}, filepath.Join(dir, "2.tar")))
	if !bytes.Equal(ok(os.ReadFile(filepath.Join(dir, "1.tar"))), ok(os.ReadFile(filepath.Join(dir, "2.tar")))) {
		t.Fatal("tar output differs between runs")
	}
}

type olRebuilt struct {
	record, keys string
	trust        *TrustRoot
}

// olRebuild runs the flow again as a second builder with its own keys (and, if
// builderID is set, its own builder id), compares it with the release in a, and
// signs the rebuild record with a rebuilder key in a trust root of its own.
func olRebuild(t *testing.T, dir string, a olRun, stamp int, builderID string) olRebuilt {
	t.Helper()
	if builderID != "" {
		t.Setenv("HSLSA_BUILDER_ID", builderID)
	}
	b, err := olProduce(t, filepath.Join(dir, "rebuild"), olSteps, stamp, nil)
	must(t, err)
	keys := filepath.Join(dir, "rebuilder-keys")
	must(t, makeKeys(keys, filepath.Join(keys, "pub"), "rebuilder"))
	trustPath := filepath.Join(dir, "rebuilder-trust-root.json")
	must(t, BuildTrustRoot(filepath.Join(keys, "pub"), trustPath))
	record := filepath.Join(dir, "rebuild.intoto.json")
	must(t, RebuildRecord(compareRuns(t, a, b), a.bundle, b.bundle, filepath.Join(keys, "rebuilder.key.pem"), record))
	return olRebuilt{record, keys, ok(LoadTrustRoot(trustPath))}
}

func olCheckRebuild(t *testing.T, a olRun, r olRebuilt, require string) error {
	t.Helper()
	trust := ok(LoadTrustRoot(filepath.Join(a.bundle, "trust-root.json")))
	records, final, err := OpenLaneVerify(a.bundle, a.runDir, trust)
	must(t, err)
	_, err = CheckRebuild(a.bundle, trust, records, final, r.record, r.trust, require)
	return err
}

func olReleased(t *testing.T, dir string, stamp int) olRun {
	t.Helper()
	a, err := olProduce(t, filepath.Join(dir, "release"), olSteps, stamp, nil)
	must(t, err)
	return a
}

func TestRebuildVerifies(t *testing.T) {
	dir := t.TempDir()
	a := olReleased(t, dir, 0)
	r := olRebuild(t, dir, a, 0, NS+"/test-rebuilder")
	must(t, olCheckRebuild(t, a, r, "gds-bit-exact"))
	stmt := ok(DecodeEnvelope(r.record))
	if !jsonEqual(get(firstSubject(stmt), "digest"), fileDigest(filepath.Join(a.bundle, "artifacts", "spm.gds"))) {
		t.Fatal("the rebuild record's subject is not the released GDS")
	}
	if got := S(stmt, "predicate", "runDetails", "builder", "id"); got != NS+"/test-rebuilder" {
		t.Fatalf("rebuild builder id %s", got)
	}
}

func TestRebuildEqualIgnoringTimestampsNeedsThePolicy(t *testing.T) {
	dir := t.TempDir()
	a := olReleased(t, dir, 1)
	r := olRebuild(t, dir, a, 2, NS+"/test-rebuilder")
	rejects(t, olCheckRebuild(t, a, r, "gds-bit-exact"), "rebuild: gds-bit-exact failed")
	must(t, olCheckRebuild(t, a, r, "gds-equal-ignoring-timestamps"))
}

func TestRebuildSignedByDesignHouseKeyIsCaught(t *testing.T) {
	dir := t.TempDir()
	a := olReleased(t, dir, 0)
	r := olRebuild(t, dir, a, 0, NS+"/test-rebuilder")
	pub := filepath.Join(dir, "house-as-rebuilder")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, copyFile(filepath.Join(a.keys, "flow-platform.pub.pem"), filepath.Join(pub, "rebuilder.pub.pem")))
	must(t, BuildTrustRoot(pub, filepath.Join(dir, "house-trust-root.json")))
	resign(t, r.record, a.keys, "flow-platform", nil)
	r.trust = ok(LoadTrustRoot(filepath.Join(dir, "house-trust-root.json")))
	rejects(t, olCheckRebuild(t, a, r, "gds-bit-exact"), "is the design house's flow-platform key")
}

func TestRebuildBySameBuilderIsCaught(t *testing.T) {
	dir := t.TempDir()
	a := olReleased(t, dir, 0)
	r := olRebuild(t, dir, a, 0, "")
	rejects(t, olCheckRebuild(t, a, r, "gds-bit-exact"), "also ran the flow")
}

func TestRebuildTamperIsCaught(t *testing.T) {
	for _, c := range []struct {
		name, reason string
		mutate       func(Obj)
	}{
		{"other GDS", "rebuilt a different GDS", func(s Obj) {
			O(Objs(s, "subject")[0], "digest")["sha256"] = strings.Repeat("00", 32)
		}},
		{"other PDK", "used a different pdk", func(s Obj) {
			for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
				if S(d, "annotations", "kind") == "pdk" {
					O(d, "digest")["sha256"] = strings.Repeat("dd", 32)
				}
			}
		}},
		{"other release", "does not name this release", func(s Obj) {
			deps := Objs(s, "predicate", "buildDefinition", "resolvedDependencies")
			O(s, "predicate", "buildDefinition")["resolvedDependencies"] = deps[1:]
		}},
		{"other SOURCE_DATE_EPOCH", "different SOURCE_DATE_EPOCH", func(s Obj) {
			O(s, "predicate", "buildDefinition", "externalParameters")["sourceDateEpoch"] = 0
		}},
		{"no bit-exact check", "no gds-bit-exact check", func(s Obj) {
			O(s, "predicate", "hwFlow")["checks"] = Objs(s, "predicate", "hwFlow", "checks")[1:]
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			a := olReleased(t, dir, 0)
			r := olRebuild(t, dir, a, 0, NS+"/test-rebuilder")
			resign(t, r.record, r.keys, "rebuilder", c.mutate)
			rejects(t, olCheckRebuild(t, a, r, "gds-bit-exact"), c.reason)
		})
	}
}
