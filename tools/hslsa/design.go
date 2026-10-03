package hslsa

// Design track: run a real RTL flow with open tools and attest every step.
//
// Steps run here: 0 source freeze, 1 simulation (Icarus Verilog), 2 synthesis
// (Yosys), 6 signoff (a formal proof in Yosys that the netlist equals the
// RTL), and the tapeout release. Floorplan through GDS stream-out (steps 3 to
// 5 and 7) need OpenROAD and a PDK and run in the OpenLane example, so the
// release subject here is the gate-level netlist standing in for the GDS.
// With isolate, steps 1, 2 and 6 run their tools in a sandbox of their own
// (sandbox.go), as Design L3 asks.

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DesignSteps are the PicoRV32 example's design steps before the release.
var DesignSteps = []string{"source-freeze", "simulation", "synthesis", "signoff"}

// optionalSteps are design steps a flow may leave out: the equivalence proof
// is only required where the policy asks for it (Design L3).
var optionalSteps = map[string]bool{"signoff": true}

// stepsRun is DesignSteps without the optional steps the bundle has no record of.
func stepsRun(bundle string) []string {
	var out []string
	for _, s := range DesignSteps {
		if _, err := os.Stat(filepath.Join(bundle, "att", AttName(s))); err != nil && optionalSteps[s] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// AttName is the envelope file name for a design step.
func AttName(step string) string {
	for i, s := range DesignSteps {
		if s == step {
			return fmt.Sprintf("design-%d-%s.intoto.json", i, step)
		}
	}
	return fmt.Sprintf("design-%s.intoto.json", step)
}

type procResult struct {
	Stdout, Stderr string
	Code           int
}

// runCmd runs a command to completion. A non-zero exit is a result, not an error.
func runCmd(dir string, env []string, name string, args ...string) (procResult, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := procResult{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			r.Code = ee.ExitCode()
			return r, nil
		}
		return r, err
	}
	return r, nil
}

// tool identifies an installed tool by its version line and the digest of its binary.
func tool(name string, versionArgs ...string) (Obj, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed", name)
	}
	out, err := runCmd("", nil, name, versionArgs...)
	if err != nil {
		return nil, err
	}
	text := out.Stdout
	if text == "" {
		text = out.Stderr
	}
	version := ""
	if lines := splitLines(strings.TrimSpace(text)); len(lines) > 0 {
		version = lines[0]
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	digest, err := sha256File(real)
	if err != nil {
		return nil, err
	}
	return Obj{"name": name, "version": version, "digest": Obj{"sha256": digest}}, nil
}

func nonNil(list []Obj) []Obj {
	if list == nil {
		return []Obj{}
	}
	return list
}

func designPredicate(step string, external Obj, deps, tools, checks, byproducts []Obj, started string) Obj {
	run := builder()
	meta := O(run, "metadata")
	meta["startedOn"] = started
	meta["finishedOn"] = Now()
	run["byproducts"] = nonNil(byproducts)
	return Obj{
		"buildDefinition": Obj{
			"buildType":            designStepType(step),
			"externalParameters":   external,
			"resolvedDependencies": nonNil(deps),
		},
		"runDetails": run,
		"hwFlow":     Obj{"step": step, "tools": nonNil(tools), "checks": nonNil(checks)},
	}
}

func check(name string, ok bool, detail string) Obj {
	result := "fail"
	if ok {
		result = "pass"
	}
	return Obj{"name": name, "result": result, "detail": detail}
}

func failedChecks(checks []Obj) []string {
	var failed []string
	for _, c := range checks {
		if S(c, "result") != "pass" {
			failed = append(failed, S(c, "name"))
		}
	}
	return failed
}

// finish signs a step record, withholding the fields w names for the step,
// then refuses to continue if one of its gates failed.
func finish(bundle, step string, subjects []Obj, pred Obj, signer *Signer, w *Withholding) error {
	pred, disclosures, err := withhold(pred, DesignFlow, w.fields(step))
	if err != nil {
		return fmt.Errorf("%s: %w", step, err)
	}
	stmt, err := statement(subjects, DesignFlow, pred)
	if err != nil {
		return err
	}
	path := filepath.Join(bundle, "att", AttName(step))
	if _, err := Sign(stmt, signer, path); err != nil {
		return err
	}
	if err := writeDisclosures(path, disclosures); err != nil {
		return err
	}
	if failed := failedChecks(Objs(pred, "hwFlow", "checks")); len(failed) > 0 {
		return fmt.Errorf("%s: gate failed: %s (failure recorded in the attestation)", step, strings.Join(failed, ", "))
	}
	msg := fmt.Sprintf("%s: ok, %d subject(s)", step, len(subjects))
	if len(disclosures) > 0 {
		msg += fmt.Sprintf(", %d field(s) withheld", len(disclosures))
	}
	fmt.Println(msg)
	return nil
}

// DeterministicTar writes a tar that is byte-identical for identical inputs.
func DeterministicTar(srcDir string, files []string, out string) error {
	names := sortedCopy(files)
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(data)),
			Mode:     0o644,
			ModTime:  time.Unix(0, 0),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return f.Close()
}

// tarNames lists the member names of a tar.
func tarNames(archive string) ([]string, error) {
	var names []string
	err := walkTar(archive, func(h *tar.Header, _ io.Reader) error {
		names = append(names, h.Name)
		return nil
	})
	return names, err
}

// tarMember returns one member's contents.
func tarMember(archive, name string) ([]byte, error) {
	var data []byte
	found := false
	err := walkTar(archive, func(h *tar.Header, r io.Reader) error {
		if h.Name == name && !found {
			found = true
			var err error
			data, err = io.ReadAll(r)
			return err
		}
		return nil
	})
	if err == nil && !found {
		err = fmt.Errorf("%s has no member %s", archive, name)
	}
	return data, err
}

func walkTar(archive string, fn func(*tar.Header, io.Reader) error) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", archive, err)
		}
		if err := fn(h, tr); err != nil {
			return err
		}
	}
}

// unpack extracts regular files and directories, refusing any path outside dest.
func unpack(archive, dest string) error {
	return walkTar(archive, func(h *tar.Header, r io.Reader) error {
		name := filepath.Clean(h.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("%s: member %s is outside the archive root", archive, h.Name)
		}
		path := filepath.Join(dest, name)
		switch h.Typeflag {
		case tar.TypeDir:
			return os.MkdirAll(path, 0o755)
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, r); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		}
		return fmt.Errorf("%s: member %s is not a regular file or directory", archive, h.Name)
	})
}

func download(url, path string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// SourceFreeze is step 0: fetch the pinned RTL, check every digest, and freeze it into one archive.
func SourceFreeze(bundle, lockPath, key, cache string, w *Withholding) error {
	return sourceFreeze(bundle, lockPath, key, cache, "", "", w)
}

// SourceFreezeL2 is step 0 at Design L2: it also gates on the signed, reviewed
// tag and the IP vendor's provenance, and consumes all three by digest.
func SourceFreezeL2(bundle, lockPath, key, cache, trustRoot, policyPath string, w *Withholding) error {
	return sourceFreeze(bundle, lockPath, key, cache, trustRoot, policyPath, w)
}

func sourceFreeze(bundle, lockPath, key, cache, trustRoot, policyPath string, w *Withholding) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	src := O(lock, "source")
	files := O(src, "files")
	got, err := fetchSources(lock, cache)
	if err != nil {
		return err
	}
	var deps []Obj
	var mismatched []string
	for _, name := range sortedKeys(files) {
		want, _ := files[name].(string)
		if got[name] != want {
			mismatched = append(mismatched, fmt.Sprintf("%s (%s)", name, got[name]))
		}
		d := rd(name, got[name])
		d["uri"] = fmt.Sprintf("git+%s@%s#%s", S(src, "repo"), S(src, "commit"), name)
		deps = append(deps, d)
	}
	if gh := githubSourceDep(); gh != nil {
		deps = append(deps, gh)
	}
	art := filepath.Join(bundle, "artifacts")
	if err := os.MkdirAll(art, 0o755); err != nil {
		return err
	}
	tarPath := filepath.Join(art, "source.tar")
	if err := DeterministicTar(cache, sortedKeys(files), tarPath); err != nil {
		return err
	}
	detail := strings.Join(mismatched, "; ")
	if detail == "" {
		detail = "every file matches inputs.lock.json"
	}
	checks := []Obj{check("inputs-pinned", len(mismatched) == 0, detail)}
	external := Obj{"design": S(lock, "design"), "repo": S(src, "repo"), "commit": S(src, "commit")}
	if trustRoot != "" {
		l2deps, l2checks, err := sourceFreezeL2Inputs(bundle, trustRoot, policyPath, S(lock, "freeze", "repo"), tarPath)
		if err != nil {
			return err
		}
		deps = append(deps, l2deps...)
		checks = append(checks, l2checks...)
		external["tag"] = S(lock, "freeze", "tag")
	}
	pred := designPredicate("source-freeze", external, deps, nil, checks, nil, started)
	subject, err := fileRD(tarPath, "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "source-freeze", []Obj{subject}, pred, signer, w)
}

// stepRunner runs one design step's tools: in a sandbox of its own when the
// flow isolates its steps (Design L3), otherwise directly. Either way the
// step works in a fresh directory holding only its inputs.
type stepRunner struct {
	work string
	sb   *Sandbox
}

func newStepRunner(prefix string, isolate bool) (*stepRunner, error) {
	r := &stepRunner{}
	if isolate {
		sb, err := NewSandbox()
		if err != nil {
			return nil, err
		}
		r.sb = sb
	}
	work, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, err
	}
	r.work = work
	return r, nil
}

func (r *stepRunner) close() { os.RemoveAll(r.work) }

func (r *stepRunner) run(name string, args ...string) (procResult, error) {
	if r.sb != nil {
		return r.sb.Run(r.work, nil, name, args...)
	}
	return runCmd(r.work, nil, name, args...)
}

// record adds hwFlow.isolation and hwFlow.network to a step predicate when
// the step ran isolated.
func (r *stepRunner) record(pred Obj) Obj {
	if r.sb != nil {
		hw := O(pred, "hwFlow")
		hw["isolation"] = r.sb.Isolation()
		hw["network"] = IsolatedNetwork()
	}
	return pred
}

// collect copies a file the step wrote in its working directory into the bundle's artifacts.
func (r *stepRunner) collect(name, art string) error {
	if _, err := os.Stat(filepath.Join(r.work, name)); err != nil {
		return nil
	}
	return copyFile(filepath.Join(r.work, name), filepath.Join(art, name))
}

// Simulation is step 1: run the testbench on the frozen source.
func Simulation(bundle, lockPath, key string, isolate bool, w *Withholding) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	iverilog, err := pinnedTool("iverilog", "-V")
	if err != nil {
		return err
	}
	vvp, err := pinnedTool("vvp", "-V")
	if err != nil {
		return err
	}
	sim := O(lock, "simulation")
	r, err := newStepRunner("hslsa-sim-", isolate)
	if err != nil {
		return err
	}
	defer r.close()
	if err := unpack(filepath.Join(art, "source.tar"), r.work); err != nil {
		return err
	}
	build, err := r.run("iverilog", append([]string{"-o", "tb"}, Strs(sim, "files")...)...)
	if err != nil {
		return err
	}
	run := build
	if build.Code == 0 {
		if run, err = r.run("vvp", "-n", "tb"); err != nil {
			return err
		}
	}
	log := build.Stdout + build.Stderr + run.Stdout + run.Stderr
	if err := os.WriteFile(filepath.Join(art, "simulation.log"), []byte(log), 0o644); err != nil {
		return err
	}
	okRun := build.Code == 0 && run.Code == 0
	marker := S(sim, "activityMarker")
	minActivity, _ := Int(sim, "minActivity")
	activity := strings.Count(log, marker)
	source, err := fileRD(filepath.Join(art, "source.tar"), "")
	if err != nil {
		return err
	}
	pred := r.record(designPredicate(
		"simulation",
		Obj{"top": S(sim, "top"), "files": get(sim, "files")},
		[]Obj{source},
		[]Obj{iverilog, vvp},
		[]Obj{
			check("testbench-ran", okRun, fmt.Sprintf("exit %d", run.Code)),
			check("testbench-finished", strings.Contains(log, "$finish called"), S(sim, "passMarker")),
			check("activity", int64(activity) >= minActivity, fmt.Sprintf("%d x '%s'", activity, marker)),
		},
		nil, started,
	))
	subject, err := fileRD(filepath.Join(art, "simulation.log"), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "simulation", []Obj{subject}, pred, signer, w)
}

// synthesisScript is step 2's Yosys script. It reads the RTL the way the
// equivalence check reads it (equivalenceScript): case statements' full_case
// and parallel_case attributes dropped, so a case means what it says in
// simulation, and every undefined value (an 'x assignment) resolved to 0.
// That fixes everything the RTL leaves open before synthesis starts, so the
// netlist can be proven equal to the RTL, not only simulated against it.
func synthesisScript(files []string, top, stat, netlist string) string {
	return fmt.Sprintf(
		"read_verilog %s; attrmap -remove parallel_case -remove full_case; prep -flatten -top %s; memory_map; setundef -zero; "+
			"synth -top %s -flatten -nofsm; check -assert; tee -q -o %s stat; write_verilog -noattr %s",
		strings.Join(files, " "), top, top, stat, netlist,
	)
}

// Synthesis is step 2: synthesize the frozen RTL to a gate-level netlist.
func Synthesis(bundle, lockPath, key string, isolate bool, w *Withholding) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	syn := O(lock, "synthesis")
	art := filepath.Join(bundle, "artifacts")
	top := S(syn, "top")
	netlist := top + ".netlist.v"
	stat := "synthesis-stat.txt"
	script := synthesisScript(Strs(syn, "files"), top, stat, netlist)
	r, err := newStepRunner("hslsa-syn-", isolate)
	if err != nil {
		return err
	}
	defer r.close()
	if err := unpack(filepath.Join(art, "source.tar"), r.work); err != nil {
		return err
	}
	proc, err := r.run("yosys", "-q", "-p", script)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(art, "synthesis.log"), []byte(proc.Stdout+proc.Stderr), 0o644); err != nil {
		return err
	}
	for _, name := range []string{netlist, stat} {
		if err := os.Remove(filepath.Join(art, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := r.collect(name, art); err != nil {
			return err
		}
	}
	fi, statErr := os.Stat(filepath.Join(art, netlist))
	ok := proc.Code == 0 && statErr == nil && fi.Size() > 0
	yosys, err := pinnedTool("yosys", "-V")
	if err != nil {
		return err
	}
	source, err := fileRD(filepath.Join(art, "source.tar"), "")
	if err != nil {
		return err
	}
	logRD, err := fileRD(filepath.Join(art, "synthesis.log"), "")
	if err != nil {
		return err
	}
	pred := r.record(designPredicate(
		"synthesis",
		Obj{"top": top, "script": script},
		[]Obj{source},
		[]Obj{yosys},
		[]Obj{check("synthesis-and-check-assert", ok, fmt.Sprintf("exit %d", proc.Code))},
		[]Obj{logRD}, started,
	))
	netRD, err := fileRD(filepath.Join(art, netlist), "")
	if err != nil {
		return err
	}
	subjects := []Obj{netRD}
	if _, err := os.Stat(filepath.Join(art, stat)); err == nil {
		statRD, err := fileRD(filepath.Join(art, stat), "")
		if err != nil {
			return err
		}
		subjects = append(subjects, statRD)
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "synthesis", subjects, pred, signer, w)
}

// EquivalenceCheck is the check name of a formal equivalence proof between
// the RTL and a netlist (spec, Design L3).
const EquivalenceCheck = "rtl-netlist-equivalence"

// equivalenceScript proves the netlist equal to the RTL, read as synthesis
// read it (synthesisScript), with Yosys's equivalence checker: equiv_make
// pairs every signal the two designs share by name, and equiv_induct proves
// all the pairs equal at once by induction over the clock, so the proof
// holds in every cycle, not only those a testbench ran. equiv_status -assert
// fails the run if any pair is left unproven.
func equivalenceScript(files []string, top, netlist string) string {
	return strings.Join([]string{
		"read_verilog " + netlist,
		"proc",
		"rename " + top + " gate",
		"design -stash gate",
		"read_verilog " + strings.Join(files, " "),
		"attrmap -remove parallel_case -remove full_case",
		"prep -flatten -top " + top,
		"memory_map",
		"setundef -zero",
		"opt_clean",
		"rename " + top + " gold",
		"design -copy-from gate -as gate gate",
		"equiv_make gold gate equiv",
		"hierarchy -top equiv",
		"async2sync",
		"equiv_induct",
		"equiv_status -assert",
	}, "\n") + "\n"
}

// EquivalenceScriptFile and EquivalenceLog are the step's artifacts.
const (
	EquivalenceScriptFile = "equivalence.ys"
	EquivalenceLog        = "equivalence.log"
)

// Equivalence is step 6 (signoff) for a design released as a netlist: a
// formal proof that the netlist synthesis made is equal to the frozen RTL.
// The record carries the script and consumes the source archive and the
// netlist by digest, so anyone can run the same proof again
// (RerunEquivalence).
func Equivalence(bundle, lockPath, key string, isolate bool, w *Withholding) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	syn := O(lock, "synthesis")
	art := filepath.Join(bundle, "artifacts")
	top := S(syn, "top")
	netlist := top + ".netlist.v"
	script := equivalenceScript(Strs(syn, "files"), top, netlist)
	if err := os.WriteFile(filepath.Join(art, EquivalenceScriptFile), []byte(script), 0o644); err != nil {
		return err
	}
	r, err := newStepRunner("hslsa-eqv-", isolate)
	if err != nil {
		return err
	}
	defer r.close()
	proven, proc, err := runEquivalence(r, art, script, netlist)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(art, EquivalenceLog), []byte(proc.Stdout+proc.Stderr), 0o644); err != nil {
		return err
	}
	yosys, err := pinnedTool("yosys", "-V")
	if err != nil {
		return err
	}
	var deps []Obj
	for _, name := range []string{"source.tar", netlist, EquivalenceScriptFile} {
		d, err := fileRD(filepath.Join(art, name), "")
		if err != nil {
			return err
		}
		deps = append(deps, d)
	}
	ok := proc.Code == 0 && proven > 0
	pred := r.record(designPredicate(
		"signoff",
		Obj{"top": top, "gold": get(syn, "files"), "gate": netlist, "script": EquivalenceScriptFile,
			"method": "yosys equiv_make + equiv_induct (induction over the clock, every shared signal)"},
		deps,
		[]Obj{yosys},
		[]Obj{check(EquivalenceCheck, ok, fmt.Sprintf("%d signals proven equal, exit %d", proven, proc.Code))},
		nil, started,
	))
	logRD, err := fileRD(filepath.Join(art, EquivalenceLog), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "signoff", []Obj{logRD}, pred, signer, w)
}

// provenPattern is how equiv_status reports the proof.
var provenPattern = regexp.MustCompile(`Of those cells (\d+) are proven and (\d+) are unproven`)

// runEquivalence runs the equivalence script over the source archive and the
// netlist in art, and returns how many signal pairs it proved equal (0 when
// any is unproven).
func runEquivalence(r *stepRunner, art, script, netlist string) (int, procResult, error) {
	if err := unpack(filepath.Join(art, "source.tar"), r.work); err != nil {
		return 0, procResult{}, err
	}
	if err := copyFile(filepath.Join(art, netlist), filepath.Join(r.work, netlist)); err != nil {
		return 0, procResult{}, err
	}
	if err := os.WriteFile(filepath.Join(r.work, EquivalenceScriptFile), []byte(script), 0o644); err != nil {
		return 0, procResult{}, err
	}
	proc, err := r.run("yosys", "-l", "equivalence.full.log", "-q", EquivalenceScriptFile)
	if err != nil {
		return 0, proc, err
	}
	full, _ := os.ReadFile(filepath.Join(r.work, "equivalence.full.log"))
	proc.Stdout = equivalenceSummary(string(full)) + proc.Stdout
	m := provenPattern.FindStringSubmatch(string(full))
	if m == nil || m[2] != "0" || proc.Code != 0 {
		return 0, proc, nil
	}
	n, _ := strconv.Atoi(m[1])
	return n, proc, nil
}

// equivalenceSummary keeps the lines of a Yosys equivalence log that say
// what was paired and proven, not the thousands of per-signal lines.
func equivalenceSummary(log string) string {
	var out []string
	for _, l := range splitLines(log) {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Yosys ") || strings.Contains(t, "Executing EQUIV") || strings.HasPrefix(t, "Found ") ||
			strings.HasPrefix(t, "Of those") || strings.HasPrefix(t, "Proof for induction") || strings.HasPrefix(t, "Proved ") ||
			strings.HasPrefix(t, "Equivalence successfully") || strings.HasPrefix(t, "Unproven") || strings.HasPrefix(t, "ERROR") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// RerunEquivalence is the independent rerun Design L3 makes possible: it
// opens the bundle's equivalence record under the trust root, checks the
// script, source archive and netlist in the bundle against the digests the
// record names, runs the proof with this machine's Yosys and this tool's own
// recipe (not the script the record carries), and fails unless every pair is
// proven again.
func RerunEquivalence(bundle string, trust *TrustRoot, isolate bool) error {
	stmt, err := trust.Open(filepath.Join(bundle, "att", AttName("signoff")), "flow-platform", DesignFlow)
	if err != nil {
		return err
	}
	ext := O(stmt, "predicate", "buildDefinition", "externalParameters")
	art := filepath.Join(bundle, "artifacts")
	for _, d := range Objs(stmt, "predicate", "buildDefinition", "resolvedDependencies") {
		if !jsonEqual(fileDigest(filepath.Join(art, S(d, "name"))), get(d, "digest")) {
			return failf("equivalence rerun: %s in the bundle is not the file the record names", S(d, "name"))
		}
	}
	// The rerun proves with this tool's own recipe, not the script the flow
	// platform shipped, so a script that proves nothing cannot pass here.
	script := equivalenceScript(Strs(ext, "gold"), S(ext, "top"), S(ext, "gate"))
	if shipped, err := os.ReadFile(filepath.Join(art, S(ext, "script"))); err != nil || string(shipped) != script {
		fmt.Printf("equivalence rerun: the record's script %s is not this tool's recipe; proving with the recipe instead\n", S(ext, "script"))
	}
	r, err := newStepRunner("hslsa-eqv-", isolate)
	if err != nil {
		return err
	}
	defer r.close()
	proven, proc, err := runEquivalence(r, art, script, S(ext, "gate"))
	if err != nil {
		return err
	}
	if proven == 0 {
		return failf("equivalence rerun: the proof did not hold on this machine:\n%s", proc.Stdout)
	}
	fmt.Printf("equivalence rerun: PASSED, %d signals of %s proven equal to the RTL with %s\n", proven, S(ext, "gate"), firstLine(proc.Stdout))
	return nil
}

func firstLine(s string) string {
	if l := splitLines(strings.TrimSpace(s)); len(l) > 0 {
		return strings.TrimSpace(l[0])
	}
	return ""
}

// tapeoutGate runs the tapeout check over the design steps, as the release's gate.
func tapeoutGate(bundle, trustRoot, policyPath string) (Obj, error) {
	trust, err := LoadTrustRoot(trustRoot)
	if err != nil {
		return nil, err
	}
	policy, err := ReadObj(policyPath)
	if err != nil {
		return nil, err
	}
	if _, err := TapeoutCheck(bundle, trust, policy, false); err != nil {
		if IsVerificationError(err) {
			return check("tapeout-policy", false, err.Error()), nil
		}
		return nil, err
	}
	return check("tapeout-policy", true, "all design steps present, signed and linked"), nil
}

// DesignRelease is the tapeout release: run the tapeout check, then sign the final design artifact.
func DesignRelease(bundle, lockPath, key, trustRoot, policyPath string, w *Withholding) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	// A lock with a release block names the released artifact and the steps
	// before it (the FPGA example releases a bitstream); otherwise the
	// synthesized netlist stands in for the GDS.
	final := filepath.Join(bundle, "artifacts", S(lock, "synthesis", "top")+".netlist.v")
	kind := "gate-level netlist (stands in for GDS until steps 3 to 7 run)"
	steps := stepsRun(bundle)
	if rel := O(lock, "release"); rel != nil {
		final = filepath.Join(bundle, "artifacts", S(rel, "artifact"))
		kind = S(rel, "kind")
		steps = Strs(rel, "steps")
	}
	var deps []Obj
	for _, s := range steps {
		d, err := fileRD(filepath.Join(bundle, "att", AttName(s)), "att/"+AttName(s))
		if err != nil {
			return err
		}
		deps = append(deps, d)
	}
	gate, err := tapeoutGate(bundle, trustRoot, policyPath)
	if err != nil {
		return err
	}
	pred := designPredicate(
		"release",
		Obj{
			"design":            S(lock, "design"),
			"finalArtifact":     filepath.Base(final),
			"finalArtifactKind": kind,
			"ipBlocks":          ipBlocks(lock),
		},
		deps, nil, []Obj{gate}, nil, started,
	)
	subject, err := fileRD(final, "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "release", []Obj{subject}, pred, signer, w)
}

// ipBlocks lists the lock's third-party IP blocks for the release record.
func ipBlocks(lock Obj) []Obj {
	var out []Obj
	for _, ip := range Objs(lock, "ip") {
		out = append(out, Obj{"name": S(ip, "name"), "supplier": S(ip, "supplier"), "version": S(lock, "source", "commit")})
	}
	return nonNil(out)
}

// sortObjsBy sorts objects by a string field.
func sortObjsBy(list []Obj, key string) {
	sort.SliceStable(list, func(i, j int) bool { return S(list[i], key) < S(list[j], key) })
}
