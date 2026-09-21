package hslsa

// The EDA Tcl adapter: the hook in adapters/eda-tcl/hslsa.tcl, the signer
// around the tool, and the buyer's check. The flows here run in tclsh, or in
// Yosys's Tcl shell when tclsh is not installed, and skip without either.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var edaHook = filepath.Join(root, "adapters", "eda-tcl", "hslsa.tcl")

// tclShell is a command that runs a Tcl script file.
func tclShell(t *testing.T) []string {
	t.Helper()
	if p, err := exec.LookPath("tclsh"); err == nil {
		return []string{p}
	}
	if p, err := exec.LookPath("yosys"); err == nil {
		return []string{p, "-q", "-c"}
	}
	t.Skip("needs tclsh or yosys")
	return nil
}

// edaFlow is a two-step flow: "synthesis" reads a source file and writes a
// netlist, "floorplan" reads the netlist and a PDK file and writes a DEF.
const (
	edaPrelude = `
source $::env(HSLSA_HOOK)
set w $::env(WORK)
hslsa::configure -tool fake-eda -version "fake 1.0"
proc put {path text} { file mkdir [file dirname $path]; set f [open $path w]; puts -nonewline $f $text; close $f }
`
	edaStage1 = `
hslsa::step synthesis -label synth {
    hslsa::input $w/src/top.v
    put $w/out/top.nl.v "netlist of [string length [read [set f [open $w/src/top.v]]]] bytes"
    close $f
    hslsa::output $w/out/top.nl.v -view nl
    hslsa::metric design__instance__count 42
    hslsa::metric note "quoted \"text\"\n"
}
`
	edaStage2 = `
hslsa::step floorplan -label "init fp" {
    hslsa::input $w/out/top.nl.v
    hslsa::input $w/pdk/cells.lib -kind pdk
    hslsa::input $w/constraints.sdc -kind config
    put $w/out/top.def "DEF"
    hslsa::output $w/out/top.def -view def
    hslsa::check die-area pass "100x100"
}
`
	edaFlow = edaPrelude + edaStage1 + edaStage2
)

type edaFixture struct {
	dir, work, bundle, keys, pdk string
	trust                        *TrustRoot
}

// newEDAFixture lays out a work tree, a frozen source with its record, and keys.
func newEDAFixture(t *testing.T) *edaFixture {
	t.Helper()
	dir := t.TempDir()
	f := &edaFixture{dir: dir, work: filepath.Join(dir, "work"), bundle: filepath.Join(dir, "bundle"),
		keys: filepath.Join(dir, "keys"), pdk: filepath.Join(dir, "work", "pdk")}
	for _, d := range []string{"src", "pdk"} {
		must(t, os.MkdirAll(filepath.Join(f.work, d), 0o755))
	}
	must(t, os.MkdirAll(filepath.Join(f.bundle, "artifacts"), 0o755))
	must(t, os.WriteFile(filepath.Join(f.work, "src", "top.v"), []byte("module top; endmodule\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(f.work, "pdk", "cells.lib"), []byte("library(cells) {}\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(f.work, "constraints.sdc"), []byte("create_clock -period 10 clk\n"), 0o644))
	src := filepath.Join(f.bundle, "artifacts", "source.tar")
	must(t, DeterministicTar(filepath.Join(f.work, "src"), []string{"top.v"}, src))
	must(t, makeKeys(f.keys, filepath.Join(f.keys, "pub"), "flow-platform"))
	must(t, BuildTrustRoot(filepath.Join(f.keys, "pub"), filepath.Join(f.bundle, "trust-root.json")))
	f.trust = ok(LoadTrustRoot(filepath.Join(f.bundle, "trust-root.json")))
	srcRD := ok(fileRD(src, ""))
	stmt := ok(statement([]Obj{srcRD}, DesignFlow, Obj{
		"buildDefinition": Obj{"buildType": designStepType("source-freeze"), "externalParameters": Obj{}},
		"runDetails":      Obj{"builder": Obj{"id": NS + "/test"}},
		"hwFlow":          Obj{"step": "source-freeze"},
	}))
	ok(Sign(stmt, ok(LoadSigner(filepath.Join(f.keys, "flow-platform.key.pem"))), filepath.Join(f.bundle, "att", AttName("source-freeze"))))
	return f
}

// run runs script under the signer.
func (f *edaFixture) run(t *testing.T, script string) error {
	t.Helper()
	path := filepath.Join(f.dir, "flow.tcl")
	must(t, os.WriteFile(path, []byte(script), 0o644))
	t.Setenv("HSLSA_HOOK", edaHook)
	t.Setenv("WORK", f.work)
	return EDARun(EDAOptions{
		Bundle: f.bundle, Spool: filepath.Join(f.dir, "spool"), Key: filepath.Join(f.keys, "flow-platform.key.pem"),
		Root: f.work, PDK: f.pdk, Cmd: append(tclShell(t), path),
	})
}

func (f *edaFixture) verify() ([]Obj, error) {
	return EDAVerify(EDAVerifyOptions{Bundle: f.bundle, Trust: f.trust, Root: f.work, PDK: f.pdk, Hook: edaHook,
		RequireSteps: []string{"synthesis", "floorplan"}})
}

func (f *edaFixture) att(i int) string {
	steps := Objs(ok(ReadObj(filepath.Join(f.bundle, "eda", "run.json"))), "steps")
	return filepath.Join(f.bundle, "att", S(steps[i], "attestation"))
}

func TestEDASignsEachStep(t *testing.T) {
	f := newEDAFixture(t)
	must(t, f.run(t, edaFlow))
	records, err := f.verify()
	must(t, err)
	if len(records) != 2 {
		t.Fatalf("%d records, want 2", len(records))
	}
	if got := filepath.Base(f.att(1)); got != "eda-02-init-fp.intoto.json" {
		t.Errorf("second record is %s", got)
	}
	syn, fp := O(records[0], "predicate"), O(records[1], "predicate")
	if S(syn, "buildDefinition", "buildType") != edaStepType || S(fp, "hwFlow", "step") != "floorplan" {
		t.Errorf("wrong buildType or step")
	}
	if n, _ := Int(syn, "hwFlow", "metrics", "design__instance__count"); n != 42 {
		t.Errorf("numeric metric not kept as a number: %v", get(syn, "hwFlow", "metrics"))
	}
	if S(syn, "hwFlow", "metrics", "note") != "quoted \"text\"\n" {
		t.Errorf("string metric mangled: %q", S(syn, "hwFlow", "metrics", "note"))
	}
	tool := Objs(syn, "hwFlow", "tools")[0]
	if S(tool, "name") != "fake-eda" || S(tool, "digest", "sha256") == "" {
		t.Errorf("tool entry %v: want the configured name and the binary's digest", tool)
	}
	kinds := map[string]Obj{}
	for _, d := range Objs(fp, "buildDefinition", "resolvedDependencies") {
		kinds[S(d, "annotations", "kind")] = d
	}
	for _, k := range []string{"source", "pdk", "adapter", "step-config", "view", "pdk-file", "previous-step"} {
		if kinds[k] == nil {
			t.Errorf("floorplan names no %s dependency", k)
		}
	}
	if S(kinds["pdk-file"], "name") != "cells.lib" || S(kinds["view"], "name") != "out/top.nl.v" {
		t.Errorf("names not relative: pdk %q, view %q", S(kinds["pdk-file"], "name"), S(kinds["view"], "name"))
	}
	if find(Objs(fp, "hwFlow", "checks"), "name", "die-area") == nil {
		t.Errorf("the flow's own check is missing")
	}
}

// A flow that runs one tool session per stage gets one sequence of records.
func TestEDAOneSequenceAcrossSessions(t *testing.T) {
	f := newEDAFixture(t)
	first, second := filepath.Join(f.dir, "stage1.tcl"), filepath.Join(f.dir, "stage2.tcl")
	must(t, os.WriteFile(first, []byte(edaPrelude+edaStage1), 0o644))
	must(t, os.WriteFile(second, []byte(edaPrelude+edaStage2), 0o644))
	sh := strings.Join(tclShell(t), " ")
	t.Setenv("HSLSA_HOOK", edaHook)
	t.Setenv("WORK", f.work)
	must(t, EDARun(EDAOptions{
		Bundle: f.bundle, Spool: filepath.Join(f.dir, "spool"), Key: filepath.Join(f.keys, "flow-platform.key.pem"),
		Root: f.work, PDK: f.pdk,
		Cmd: []string{"sh", "-c", sh + " " + first + " && " + sh + " " + second},
	}))
	records, err := f.verify()
	must(t, err)
	if len(records) != 2 {
		t.Fatalf("%d records, want 2", len(records))
	}
}

func TestEDAHookIsInertWithoutSigner(t *testing.T) {
	f := newEDAFixture(t)
	path := filepath.Join(f.dir, "flow.tcl")
	must(t, os.WriteFile(path, []byte(edaFlow), 0o644))
	sh := tclShell(t)
	cmd := exec.Command(sh[0], append(sh[1:], path)...)
	cmd.Env = append(os.Environ(), "HSLSA_HOOK="+edaHook, "WORK="+f.work, "HSLSA_SPOOL=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("flow without a signer: %v\n%s", err, out)
	}
	if !isFile(filepath.Join(f.work, "out", "top.def")) {
		t.Fatal("the flow did not run")
	}
}

func TestEDARefusesUnlinkedInput(t *testing.T) {
	f := newEDAFixture(t)
	must(t, os.WriteFile(filepath.Join(f.work, "src", "top.v"), []byte("module top; wire trojan; endmodule\n"), 0o644))
	err := f.run(t, edaFlow)
	if err == nil || !strings.Contains(err.Error(), "not an output of an earlier record or a file of the frozen source") {
		t.Fatalf("got %v, want a refusal for the changed source file", err)
	}
	if isFile(filepath.Join(f.work, "out", "top.def")) {
		t.Fatal("the flow went on after the signer refused a step")
	}
}

func TestEDARefusesPDKFileOutsidePDK(t *testing.T) {
	f := newEDAFixture(t)
	err := f.run(t, strings.Replace(edaFlow, "$w/pdk/cells.lib -kind pdk", "$w/constraints.sdc -kind pdk", 1))
	if err == nil || !strings.Contains(err.Error(), "outside the pinned PDK") {
		t.Fatalf("got %v", err)
	}
}

func TestEDARecordsFailedStep(t *testing.T) {
	f := newEDAFixture(t)
	err := f.run(t, strings.Replace(edaFlow, `put $w/out/top.def "DEF"`, `error "placer crashed"`, 1))
	if err == nil {
		t.Fatal("a failed step passed")
	}
	stmt := ok(DecodeEnvelope(f.att(1)))
	if c := find(Objs(stmt, "predicate", "hwFlow", "checks"), "name", "step-completed"); S(c, "result") != "fail" {
		t.Fatalf("failed step recorded as %v", c)
	}
	_, err = f.verify()
	rejects(t, err, "check failed: step-completed")
}

func TestEDAReservedStep(t *testing.T) {
	f := newEDAFixture(t)
	err := f.run(t, strings.Replace(edaFlow, "hslsa::step floorplan", "hslsa::step release", 1))
	if err == nil {
		t.Fatal("a release step from the tool was accepted")
	}
	if isFile(filepath.Join(f.work, "out", "top.def")) {
		t.Fatal("the hook let a release step run")
	}
}

func TestEDAUnfinishedStep(t *testing.T) {
	f := newEDAFixture(t)
	err := f.run(t, edaFlow+"\nhslsa::step_begin routing\nexit 0\n")
	if err == nil || !strings.Contains(err.Error(), "unfinished ['3 routing']") {
		t.Fatalf("got %v, want the open step reported", err)
	}
	_, err = f.verify()
	rejects(t, err, "began and never ended")
}

func TestEDAVerifyTamper(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		tamper func(t *testing.T, f *edaFixture)
	}{
		{"output changed after signing", "subject out/top.def is missing or does not match", func(t *testing.T, f *edaFixture) {
			appendFile(t, filepath.Join(f.work, "out", "top.def"), "\nEXTRA")
		}},
		{"PDK changed", "the PDK tree does not match", func(t *testing.T, f *edaFixture) {
			appendFile(t, filepath.Join(f.pdk, "cells.lib"), "\n")
		}},
		{"input view swapped", "input view out/top.nl.v is not an output", func(t *testing.T, f *edaFixture) {
			resign(t, f.att(1), f.keys, "flow-platform", func(s Obj) {
				for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
					if S(d, "annotations", "kind") == "view" {
						d["digest"] = Obj{"sha256": strings.Repeat("0", 64)}
					}
				}
			})
		}},
		{"record dropped", "ordinal 2, want 1", func(t *testing.T, f *edaFixture) {
			editJSON(t, filepath.Join(f.bundle, "eda", "run.json"), func(m Obj) { m["steps"] = A(m, "steps")[1:] })
		}},
		{"chain broken", "not linked to the previous step record", func(t *testing.T, f *edaFixture) {
			resign(t, f.att(0), f.keys, "flow-platform", func(s Obj) { O(s, "predicate", "hwFlow")["metrics"] = Obj{"x": 1} })
		}},
		{"different hook", "names a different adapter", func(t *testing.T, f *edaFixture) {
			resign(t, f.att(1), f.keys, "flow-platform", func(s Obj) {
				for _, d := range Objs(s, "predicate", "buildDefinition", "resolvedDependencies") {
					if S(d, "annotations", "kind") == "adapter" {
						d["digest"] = Obj{"sha256": strings.Repeat("1", 64)}
					}
				}
			})
		}},
		{"reserved step", "not a design step a tool step may record", func(t *testing.T, f *edaFixture) {
			resign(t, f.att(1), f.keys, "flow-platform", func(s Obj) { O(s, "predicate", "hwFlow")["step"] = "release" })
		}},
		{"missing step", "spec steps with no eda record: floorplan", func(t *testing.T, f *edaFixture) {
			resign(t, f.att(1), f.keys, "flow-platform", func(s Obj) { O(s, "predicate", "hwFlow")["step"] = "other" })
		}},
		{"forged signature", "no valid signature", func(t *testing.T, f *edaFixture) {
			editPayload(t, f.att(0), func(s Obj) { O(s, "predicate", "hwFlow")["metrics"] = Obj{} })
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newEDAFixture(t)
			must(t, f.run(t, edaFlow))
			c.tamper(t, f)
			_, err := f.verify()
			rejects(t, err, c.reason)
		})
	}
}
