package hslsa

// Design track: run a real RTL flow with open tools and attest every step.
//
// Steps run here: 0 source freeze, 1 simulation (Icarus Verilog), 2 synthesis
// (Yosys), and the tapeout release. Floorplan through GDS stream-out (steps 3
// to 7) need OpenROAD and a PDK and run in the OpenLane example, so the
// release subject here is the gate-level netlist standing in for the GDS.

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
	"sort"
	"strings"
	"time"
)

// DesignSteps are the PicoRV32 example's design steps before the release.
var DesignSteps = []string{"source-freeze", "simulation", "synthesis"}

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

// finish signs a step record, then refuses to continue if one of its gates failed.
func finish(bundle, step string, subjects []Obj, pred Obj, signer *Signer) error {
	stmt, err := statement(subjects, DesignFlow, pred)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", AttName(step))); err != nil {
		return err
	}
	if failed := failedChecks(Objs(pred, "hwFlow", "checks")); len(failed) > 0 {
		return fmt.Errorf("%s: gate failed: %s (failure recorded in the attestation)", step, strings.Join(failed, ", "))
	}
	fmt.Printf("%s: ok, %d subject(s)\n", step, len(subjects))
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
func SourceFreeze(bundle, lockPath, key, cache string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	src := O(lock, "source")
	files := O(src, "files")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	var deps []Obj
	var mismatched []string
	for _, name := range sortedKeys(files) {
		want, _ := files[name].(string)
		path := filepath.Join(cache, name)
		if _, err := os.Stat(path); err != nil {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			url := strings.NewReplacer("{commit}", S(src, "commit"), "{path}", name).Replace(S(src, "rawUrl"))
			if err := download(url, path); err != nil {
				return err
			}
		}
		got, err := sha256File(path)
		if err != nil {
			return err
		}
		if got != want {
			mismatched = append(mismatched, fmt.Sprintf("%s (%s)", name, got))
		}
		d := rd(name, got)
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
	pred := designPredicate(
		"source-freeze",
		Obj{"design": S(lock, "design"), "repo": S(src, "repo"), "commit": S(src, "commit")},
		deps, nil,
		[]Obj{check("inputs-pinned", len(mismatched) == 0, detail)},
		nil, started,
	)
	subject, err := fileRD(tarPath, "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "source-freeze", []Obj{subject}, pred, signer)
}

// Simulation is step 1: run the testbench on the frozen source.
func Simulation(bundle, lockPath, key string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	iverilog, err := tool("iverilog", "-V")
	if err != nil {
		return err
	}
	vvp, err := tool("vvp", "-V")
	if err != nil {
		return err
	}
	sim := O(lock, "simulation")
	work, err := os.MkdirTemp("", "hslsa-sim-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := unpack(filepath.Join(art, "source.tar"), work); err != nil {
		return err
	}
	build, err := runCmd(work, nil, "iverilog", append([]string{"-o", "tb"}, Strs(sim, "files")...)...)
	if err != nil {
		return err
	}
	run := build
	if build.Code == 0 {
		if run, err = runCmd(work, nil, "vvp", "-n", "tb"); err != nil {
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
	pred := designPredicate(
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
	)
	subject, err := fileRD(filepath.Join(art, "simulation.log"), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "simulation", []Obj{subject}, pred, signer)
}

// Synthesis is step 2: synthesize the frozen RTL to a gate-level netlist.
func Synthesis(bundle, lockPath, key string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	syn := O(lock, "synthesis")
	art, err := filepath.Abs(filepath.Join(bundle, "artifacts"))
	if err != nil {
		return err
	}
	top := S(syn, "top")
	netlist := filepath.Join(art, top+".netlist.v")
	stat := filepath.Join(art, "synthesis-stat.txt")
	script := fmt.Sprintf(
		"read_verilog %s; synth -top %s -flatten; check -assert; tee -q -o %s stat; write_verilog -noattr %s",
		strings.Join(Strs(syn, "files"), " "), top, stat, netlist,
	)
	work, err := os.MkdirTemp("", "hslsa-syn-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := unpack(filepath.Join(art, "source.tar"), work); err != nil {
		return err
	}
	proc, err := runCmd(work, nil, "yosys", "-q", "-p", script)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(art, "synthesis.log"), []byte(proc.Stdout+proc.Stderr), 0o644); err != nil {
		return err
	}
	fi, statErr := os.Stat(netlist)
	ok := proc.Code == 0 && statErr == nil && fi.Size() > 0
	yosys, err := tool("yosys", "-V")
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
	pred := designPredicate(
		"synthesis",
		Obj{"top": top, "script": strings.ReplaceAll(script, art+"/", "")},
		[]Obj{source},
		[]Obj{yosys},
		[]Obj{check("synthesis-and-check-assert", ok, fmt.Sprintf("exit %d", proc.Code))},
		[]Obj{logRD}, started,
	)
	netRD, err := fileRD(netlist, "")
	if err != nil {
		return err
	}
	subjects := []Obj{netRD}
	if _, err := os.Stat(stat); err == nil {
		statRD, err := fileRD(stat, "")
		if err != nil {
			return err
		}
		subjects = append(subjects, statRD)
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "synthesis", subjects, pred, signer)
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
func DesignRelease(bundle, lockPath, key, trustRoot, policyPath string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	final := filepath.Join(bundle, "artifacts", S(lock, "synthesis", "top")+".netlist.v")
	var deps []Obj
	for _, s := range DesignSteps {
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
			"finalArtifactKind": "gate-level netlist (stands in for GDS until steps 3 to 7 run)",
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
	return finish(bundle, "release", []Obj{subject}, pred, signer)
}

// sortObjsBy sorts objects by a string field.
func sortObjsBy(list []Obj, key string) {
	sort.SliceStable(list, func(i, j int) bool { return S(list[i], key) < S(list[j], key) })
}
