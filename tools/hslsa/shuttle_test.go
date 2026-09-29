package hslsa

// The virtual shuttle: its assembler, a small lot run twice (same exports
// byte for byte), the lot's records made from its exports and checked, and
// what it refuses.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRV32Encodings(t *testing.T) {
	var a rvAsm
	a.I("addi", 1, 0, 1)
	a.R("add", 3, 1, 2)
	a.Store("sw", 2, 1, 8)
	a.Branch("beq", 0, 0, "next")
	a.Lui(1, 0x12345)
	a.Label("next")
	a.Jal(1, "next")
	a.Load("lw", 5, 2, -4)
	a.I("srai", 6, 7, 3)
	words := ok(a.Words())
	// From the RISC-V spec's encodings, as GNU as assembles them.
	want := []uint32{0x00100093, 0x002081b3, 0x0020a423, 0x00000463, 0x123450b7, 0x000000ef, 0xffc12283, 0x4033d313}
	for i, w := range want {
		if words[i] != w {
			t.Errorf("instruction %d: %08x, want %08x", i, words[i], w)
		}
	}
	var b rvAsm
	b.Li(4, 0xdeadbeef)
	got := ok(b.Words())
	if len(got) != 2 || got[0] != 0xdeadc237 || got[1] != 0xeef20213 {
		t.Errorf("li 0xdeadbeef: %08x", got)
	}
}

// shuttleConfig is a small lot: one wafer of 3x3 dies with a defect on most.
func shuttleConfig(t *testing.T, dir string, edit func(Obj)) string {
	t.Helper()
	cfg := ok(ReadObj(filepath.Join(root, "e2e", "shuttle", "shuttle.json")))
	O(cfg, "fab")["wafers"] = 1
	O(cfg, "fab")["grid"] = []any{3, 3}
	O(cfg, "fab")["defectsPerDie"] = 1.2
	O(cfg, "packaging")["bondDefectRate"] = 0.2
	delete(O(cfg, "packaging"), "labelSwaps")
	if edit != nil {
		edit(cfg)
	}
	path := filepath.Join(dir, "shuttle.json")
	must(t, WriteJSON(path, cfg))
	return path
}

func requireShuttle(t *testing.T) string {
	t.Helper()
	for _, bin := range []string{"iverilog", "vvp"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	return chipBundle(t)
}

func runShuttle(t *testing.T, bundle, cfg, out string) error {
	t.Helper()
	return Shuttle(ShuttleOptions{Bundle: bundle, Lock: e2eLock, Config: cfg, Out: out})
}

func TestShuttleLotIsReproducibleAndVerifies(t *testing.T) {
	bundle := requireShuttle(t)
	dir := t.TempDir()
	cfg := shuttleConfig(t, dir, nil)
	one, two := filepath.Join(dir, "one"), filepath.Join(dir, "two")
	must(t, runShuttle(t, bundle, cfg, one))
	must(t, runShuttle(t, bundle, cfg, two))
	names := ok(os.ReadDir(one))
	for _, e := range names {
		a := ok(os.ReadFile(filepath.Join(one, e.Name())))
		b := ok(os.ReadFile(filepath.Join(two, e.Name())))
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between two runs of the same lot", e.Name())
		}
	}
	report := ok(ReadObj(filepath.Join(one, "report.json")))
	sum := O(report, "summary")
	if n, _ := Int(sum, "dies"); n != 9 {
		t.Fatalf("report: %d dies, want 9", n)
	}

	// The exports make records like any supplier's, and every one of them is marked.
	sc := filepath.Join(dir, "scenario.json")
	must(t, Adapt(filepath.Join(one, "adapter.json"), sc))
	keys := chipKeys(bundle)
	must(t, Mfg(bundle, sc, keys, nil))
	must(t, BuildHBOM(bundle, e2eLock, sc, filepath.Join(keys, "product-owner.key.pem"), nil))
	for _, step := range MfgSteps {
		stmt := ok(DecodeEnvelope(filepath.Join(bundle, "att", MfgAtt[step])))
		if S(stmt, "predicate", "hwMfg", "simulated", "simulator") != ShuttleID {
			t.Errorf("%s: not marked as made by the virtual shuttle", step)
		}
	}
	policy := filepath.Join(dir, "policy.json")
	must(t, copyFile(filepath.Join(exportsDir, "policy.json"), policy))
	must(t, chipCheckPolicy(t, bundle, nil, policy))
	shipped := ok(ReadUnits(filepath.Join(bundle, "artifacts", "shipped-lot.txt")))
	if n, _ := Int(sum, "shipped"); int(n) != len(shipped) {
		t.Errorf("report says %d shipped, the shipped lot has %d", n, len(shipped))
	}

	// A buyer of real parts leaves simulated.accept out, and the lot fails.
	editJSON(t, policy, func(p Obj) { delete(p, "simulated") })
	rejects(t, chipCheckPolicy(t, bundle, nil, policy), "made from simulated hardware")
}

func TestShuttleFinalTestCatchesSwappedDies(t *testing.T) {
	bundle := requireShuttle(t)
	dir := t.TempDir()
	cfg := shuttleConfig(t, dir, func(c Obj) {
		O(c, "fab")["defectsPerDie"] = 0
		O(c, "packaging")["bondDefectRate"] = 0
		O(c, "packaging")["labelSwaps"] = []any{[]any{"PSOC130-S-00002", "PSOC130-S-00003"}}
	})
	out := filepath.Join(dir, "out")
	must(t, runShuttle(t, bundle, cfg, out))
	report := ok(ReadObj(filepath.Join(out, "report.json")))
	for _, u := range Objs(report, "units") {
		swapped := S(u, "serial") == "PSOC130-S-00002" || S(u, "serial") == "PSOC130-S-00003"
		if swapped != (S(u, "finalBin") == "DIE-ID") || (!swapped && S(u, "finalBin") != "PASS") {
			t.Errorf("%s: final test bin %s", S(u, "serial"), S(u, "finalBin"))
		}
	}
	if n, _ := Int(report, "summary", "shippedWithDefect"); n != 0 {
		t.Errorf("%d defective units shipped from a lot without defects", n)
	}
}

func TestShuttleRefusesANetlistThatIsNotTheRelease(t *testing.T) {
	bundle := requireShuttle(t)
	dir := t.TempDir()
	appendFile(t, filepath.Join(bundle, "artifacts", "picorv32.netlist.v"), "\n// changed after tapeout\n")
	err := runShuttle(t, bundle, shuttleConfig(t, dir, nil), filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "is not the released design") {
		t.Fatalf("got %v", err)
	}
}
