package hslsa

// Design track on a real RTL-to-GDS flow: OpenLane 2 with one signed attestation per step.
//
// OpenLane runs in its pinned container. This process stays outside it, holds
// the signing key, and watches the run directory: each time a step finishes
// (OpenLane writes runtime.txt after state_out.json), the step's outputs are
// hashed and a design-flow statement is signed before the next step's record.
// The key never enters the container.
//
// Each step record lists as resolvedDependencies the frozen source, the image,
// the PDK tree, the step's own resolved config, every design view it received
// (by digest, so they link to earlier subjects) and the previous record. Its
// subjects are the views it produced plus its state_out.json, which carries
// the metrics.
//
// OpenLaneCompare measures reproducibility between two runs of the same flow
// on different builders: which step outputs are bit-exact, which differ only
// in timestamps or line order, and which differ in content.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	openlaneStepType = designStepType("openlane2")
	stepDirRe        = regexp.MustCompile(`^(\d+)-(.+)$`)
)

// OpenLaneReleaseAtt is the envelope file name of the OpenLane tapeout release.
const OpenLaneReleaseAtt = "openlane-release.intoto.json"

// toolForPrefix is the binary in the image that does the work, by OpenLane step id prefix.
var toolForPrefix = map[string]string{
	"yosys": "yosys", "openroad": "openroad", "odb": "openroad", "magic": "magic",
	"klayout": "klayout", "netgen": "netgen", "verilator": "verilator",
}

// specSteps maps OpenLane step slugs onto the spec's design steps 1 to 7 (first match wins).
var specSteps = []struct {
	name string
	re   *regexp.Regexp
}{
	{"simulation", regexp.MustCompile(`^(verilator-lint|checker-lint)`)},
	{"synthesis", regexp.MustCompile(`^(yosys-(jsonheader|synthesis)|checker-(yosys|netlistassign)|openroad-stapre)`)},
	{"floorplan", regexp.MustCompile(`^(openroad-(checksdcfiles|checkmacroinstances|floorplan|cutrows|tapendcapinsertion|generatepdn)` +
		`|odb-(checkmacroantenna|setpower|manualmacro|addpdn|removepdn|addrouting)|checker-powergrid)`)},
	{"place-cts", regexp.MustCompile(`^(openroad-(globalplacement|ioplacement|repairdesignpostgpl|detailedplacement|cts|resizertimingpostcts)` +
		`|odb-(customio|applydef|writeverilog|manualglobal))`)},
	{"routing", regexp.MustCompile(`^(openroad-(globalrouting|checkantennas|repairdesignpostgrt|repairantennas|resizertimingpostgrt` +
		`|detailedrouting|fillinsertion)|odb-(diodes|heuristicdiode|removerouting|reportdisconnected` +
		`|reportwire|cellfrequency)|checker-(trdrc|disconnected|wirelength))`)},
	{"gds-stream-out", regexp.MustCompile(`^(magic-(streamout|writelef)|klayout-streamout)`)},
	{"signoff", regexp.MustCompile(`^(openroad-(rcx|sta|irdrop)|magic-|klayout-|netgen-|yosys-eqy|checker-|odb-check|misc-)`)},
}

// Signoff gates on the final metrics. Required ones must be present and zero;
// optional ones must be zero when the flow reported them.
var (
	signoffRequired = []string{"route__drc_errors", "magic__drc_error__count", "design__lvs_error__count"}
	signoffOptional = []string{
		"klayout__drc_error__count",
		"design__xor_difference__count",
		"magic__illegal_overlap__count",
		"design__critical_disconnected_pin__count",
	}
)

// probe runs inside the OpenLane image with the image's own interpreter and
// reports each tool's version line and the digest of its binary.
const probe = `
import hashlib, json, os, shutil, subprocess
out = {}
for name, args in [("openlane", ["--version"]), ("yosys", ["-V"]), ("openroad", ["-version"]),
                   ("magic", ["--version"]), ("klayout", ["-v"]), ("netgen", None), ("verilator", ["--version"])]:
    p = shutil.which(name)
    if not p:
        continue
    real = os.path.realpath(p)
    with open(real, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    version = ""
    if args:
        try:
            r = subprocess.run([name, *args], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            lines = (r.stdout + r.stderr).strip().splitlines()
            version = lines[0].strip() if lines else ""
        except Exception as e:
            version = "unknown (%s)" % e
    out[name] = {"version": version, "digest": digest, "path": real}
print(json.dumps(out))
`

type stepDir struct {
	ordinal int
	slug    string
	path    string
}

// stepDirs lists the flow's top-level step directories in execution order.
func stepDirs(runDir string) []stepDir {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil
	}
	var found []stepDir
	for _, e := range entries {
		m := stepDirRe.FindStringSubmatch(e.Name())
		if m == nil || !e.IsDir() {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		found = append(found, stepDir{n, m[2], filepath.Join(runDir, e.Name())})
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].ordinal != found[j].ordinal {
			return found[i].ordinal < found[j].ordinal
		}
		return found[i].slug < found[j].slug
	})
	return found
}

// SpecStep maps an OpenLane step slug onto a spec design step, or "other".
func SpecStep(slug string) string {
	for _, s := range specSteps {
		if s.re.MatchString(slug) {
			return s.name
		}
	}
	return "other"
}

type view struct{ key, path string }

// views lists (view key, path) for every string-valued design view in an OpenLane state, sorted by key.
func views(state Obj) []view {
	var out []view
	var walk func(v any, prefix string)
	walk = func(v any, prefix string) {
		switch x := v.(type) {
		case string:
			out = append(out, view{prefix, x})
		case map[string]any:
			for _, k := range sortedKeys(x) {
				if prefix == "" && k == "metrics" {
					continue
				}
				key := k
				if prefix != "" {
					key = prefix + "." + k
				}
				walk(x[k], key)
			}
		case []any:
			for i, item := range x {
				walk(item, fmt.Sprintf("%s.%d", prefix, i))
			}
		}
	}
	walk(state, "")
	return out
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

// TreeDigest is one digest over a directory tree: sorted relative paths, file
// digests and symlink targets, directory by directory.
func TreeDigest(root string) (string, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	var lines []string
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		var here, subdirs []string
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			if e.IsDir() {
				subdirs = append(subdirs, e.Name())
			} else if isSymlink(path) {
				here = append(here, e.Name())
			} else if fi, err := os.Stat(path); err == nil && fi.IsDir() {
				subdirs = append(subdirs, e.Name())
			} else {
				here = append(here, e.Name())
			}
		}
		sort.Strings(here)
		sort.Strings(subdirs)
		for _, name := range here {
			path := filepath.Join(dir, name)
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if isSymlink(path) {
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				lines = append(lines, "L "+rel+" "+target)
			} else {
				d, err := sha256File(path)
				if err != nil {
					return err
				}
				lines = append(lines, "F "+rel+" "+d)
			}
		}
		for _, name := range subdirs {
			if err := walk(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return "", err
	}
	return sha256Bytes([]byte(strings.Join(lines, "\n"))), nil
}

func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

type attested struct {
	ordinal int
	slug    string
	name    string
}

// Flow is everything one attested OpenLane run needs, and the per-step signer.
type Flow struct {
	bundle     string
	lock       Obj
	signer     *Signer
	work       string
	pdkRoot    string
	designDir  string
	RunDir     string
	meta       string
	attested   []attested
	source     Obj
	tools      Obj
	pdk        Obj
	commonDeps []Obj
}

// NewFlow prepares a flow over the frozen source in bundle.
func NewFlow(bundle, lockPath, key, work, pdkRoot string) (*Flow, error) {
	lock, err := ReadObj(lockPath)
	if err != nil {
		return nil, err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return nil, err
	}
	f := &Flow{bundle: bundle, lock: lock, signer: signer, work: resolvePath(work), pdkRoot: resolvePath(pdkRoot)}
	f.designDir = filepath.Join(f.work, "design", filepath.Dir(S(lock, "openlane", "config")))
	f.RunDir = filepath.Join(f.designDir, "runs", S(lock, "openlane", "runTag"))
	f.meta = filepath.Join(bundle, "openlane")
	return f, nil
}

func (f *Flow) image() string { return S(f.lock, "openlane", "image") }

func (f *Flow) imageRD() Obj {
	ref, digest, _ := strings.Cut(f.image(), "@sha256:")
	return Obj{"name": "openlane2-image", "uri": "docker://" + ref, "digest": Obj{"sha256": digest}}
}

func (f *Flow) probeTools() (Obj, error) {
	out, err := runCmd("", nil, "docker", "run", "--rm", f.image(), "python3", "-c", probe)
	if err != nil {
		return nil, err
	}
	if out.Code != 0 {
		return nil, fmt.Errorf("probing the OpenLane image: exit %d: %s", out.Code, strings.TrimSpace(out.Stderr))
	}
	lines := splitLines(strings.TrimSpace(out.Stdout))
	if len(lines) == 0 {
		return nil, fmt.Errorf("probing the OpenLane image: no output")
	}
	v, err := decodeJSON([]byte(lines[len(lines)-1]))
	if err != nil {
		return nil, err
	}
	tools, _ := v.(map[string]any)
	return tools, WriteJSON(filepath.Join(f.meta, "tools.json"), tools)
}

func (f *Flow) pdkRD() (Obj, error) {
	pdk := O(f.lock, "pdk")
	variant := filepath.Join(f.pdkRoot, S(pdk, "variant"))
	if _, err := os.Stat(variant); err != nil {
		return nil, fmt.Errorf("PDK %s is missing; enable it with ciel first", variant)
	}
	digest, err := TreeDigest(variant)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.Rel(f.pdkRoot, resolvePath(variant))
	if err != nil {
		return nil, err
	}
	info := Obj{
		"name":        S(pdk, "variant"),
		"uri":         fmt.Sprintf("%s#%s-%s", S(pdk, "source"), S(pdk, "family"), S(pdk, "openPdksCommit")),
		"digest":      Obj{"sha256": digest},
		"annotations": Obj{"kind": "pdk", "resolvedPath": resolved},
	}
	return info, WriteJSON(filepath.Join(f.meta, "pdk.json"), info)
}

// prepare unpacks the frozen source and records the image's tools and the PDK digest.
func (f *Flow) prepare() error {
	if err := os.MkdirAll(f.meta, 0o755); err != nil {
		return err
	}
	src := filepath.Join(f.bundle, "artifacts", "source.tar")
	if _, err := os.Stat(filepath.Join(f.work, "design")); err == nil {
		return fmt.Errorf("%s already exists; use a fresh work directory", filepath.Join(f.work, "design"))
	}
	if err := unpack(src, filepath.Join(f.work, "design")); err != nil {
		return err
	}
	source, err := fileRD(src, "")
	if err != nil {
		return err
	}
	source["annotations"] = Obj{"kind": "source"}
	f.source = source
	if f.tools, err = f.probeTools(); err != nil {
		return err
	}
	if f.pdk, err = f.pdkRD(); err != nil {
		return err
	}
	img := f.imageRD()
	img["annotations"] = Obj{"kind": "toolchain"}
	f.commonDeps = []Obj{f.source, img, f.pdk}
	return nil
}

func (f *Flow) command() ([]string, error) {
	ol, pdk := O(f.lock, "openlane"), O(f.lock, "pdk")
	tmp, err := os.MkdirTemp("", "hslsa-ol-")
	if err != nil {
		return nil, err
	}
	args := []string{"docker", "run", "--rm", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-w", f.designDir}
	for _, m := range []string{f.work + ":" + f.work, f.pdkRoot + ":" + f.pdkRoot, tmp + ":/tmp"} {
		args = append(args, "-v", m)
	}
	for _, e := range []string{"TMPDIR=/tmp", "HOME=/tmp", "PDK_ROOT=" + f.pdkRoot} {
		args = append(args, "-e", e)
	}
	args = append(args, f.image(), "openlane", "--manual-pdk", "--pdk-root", f.pdkRoot, "--pdk", S(pdk, "variant"),
		"--scl", S(pdk, "scl"), "--flow", S(ol, "flow"), "--run-tag", S(ol, "runTag"), filepath.Base(S(ol, "config")))
	return args, nil
}

// rel names a path relative to the run directory when it is inside it.
func (f *Flow) rel(path string) string {
	r, err := filepath.Rel(f.RunDir, path)
	if err != nil || strings.HasPrefix(r, "..") {
		return path
	}
	return r
}

func (f *Flow) relRD(path string, annotations Obj) (Obj, error) {
	d, err := sha256File(path)
	if err != nil {
		return nil, err
	}
	out := rd(f.rel(path), d)
	if annotations != nil {
		out["annotations"] = annotations
	}
	return out, nil
}

func (f *Flow) tool(name string) Obj {
	t := O(f.tools, name)
	version, ok := t["version"]
	if !ok {
		version = "not found in image"
	}
	digest, _ := t["digest"].(string)
	return Obj{"name": name, "version": version, "digest": Obj{"sha256": digest}, "uri": f.image()}
}

// componentLess orders paths by their components, as Python's Path ordering does.
func componentLess(a, b string) bool {
	pa, pb := strings.Split(a, string(filepath.Separator)), strings.Split(b, string(filepath.Separator))
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

func (f *Flow) attest(ordinal int, slug, dir string) error {
	stateIn, err := readLenientObj(filepath.Join(dir, "state_in.json"))
	if err != nil {
		return err
	}
	stateOut, err := readLenientObj(filepath.Join(dir, "state_out.json"))
	if err != nil {
		return err
	}
	before := map[string]string{}
	for _, v := range views(stateIn) {
		before[v.key] = v.path
	}

	var subjects []Obj
	produced := map[string]bool{}
	for _, v := range views(stateOut) {
		p := filepath.Clean(v.path)
		if prev, ok := before[v.key]; (ok && prev == v.path) || !isFile(p) || !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			continue
		}
		r, err := f.relRD(v.path, Obj{"view": v.key})
		if err != nil {
			return err
		}
		subjects = append(subjects, r)
		produced[resolvePath(p)] = true
	}
	stateRD, err := f.relRD(filepath.Join(dir, "state_out.json"), Obj{"view": "state"})
	if err != nil {
		return err
	}
	subjects = append(subjects, stateRD)
	produced[resolvePath(filepath.Join(dir, "state_out.json"))] = true

	deps := append([]Obj{}, f.commonDeps...)
	cfg, err := f.relRD(filepath.Join(dir, "config.json"), Obj{"kind": "step-config"})
	if err != nil {
		return err
	}
	deps = append(deps, cfg)
	for _, key := range sortedKeys(before) {
		if isFile(before[key]) {
			r, err := f.relRD(before[key], Obj{"kind": "view", "view": key})
			if err != nil {
				return err
			}
			deps = append(deps, r)
		}
	}
	if len(f.attested) > 0 {
		prev := f.attested[len(f.attested)-1].name
		d, err := fileRD(filepath.Join(f.bundle, "att", prev), "att/"+prev)
		if err != nil {
			return err
		}
		d["annotations"] = Obj{"kind": "previous-step"}
		deps = append(deps, d)
	}

	skip := map[string]bool{resolvePath(filepath.Join(dir, "config.json")): true}
	for k := range produced {
		skip[k] = true
	}
	var files []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && !skip[resolvePath(p)] {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return componentLess(files[i], files[j]) })
	var byproducts []Obj
	for _, p := range files {
		r, err := fileRD(p, f.rel(p))
		if err != nil {
			return err
		}
		byproducts = append(byproducts, r)
	}

	mIn, mOut := O(stateIn, "metrics"), O(stateOut, "metrics")
	metrics := Obj{}
	for k, v := range mOut {
		if !jsonEqual(mIn[k], v) {
			metrics[k] = v
		}
	}
	tools := []Obj{f.tool("openlane")}
	if t, ok := toolForPrefix[strings.SplitN(slug, "-", 2)[0]]; ok {
		tools = append(tools, f.tool(t))
	}

	run := builder()
	started := "1970-01-01T00:00:00Z"
	if fi, err := os.Stat(filepath.Join(dir, "state_in.json")); err == nil {
		started = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}
	meta := O(run, "metadata")
	meta["startedOn"] = started
	meta["finishedOn"] = Now()
	run["byproducts"] = nonNil(byproducts)
	pred := Obj{
		"buildDefinition": Obj{
			"buildType": openlaneStepType,
			"externalParameters": Obj{
				"design": get(f.lock, "design"),
				"flow":   get(f.lock, "openlane", "flow"),
				"config": get(f.lock, "openlane", "config"),
				"runTag": get(f.lock, "openlane", "runTag"),
				"step":   filepath.Base(dir),
			},
			"resolvedDependencies": deps,
		},
		"runDetails": run,
		"hwFlow": Obj{
			"step":         SpecStep(slug),
			"openlaneStep": slug,
			"ordinal":      ordinal,
			"tools":        tools,
			"checks":       []Obj{{"name": "step-completed", "result": "pass", "detail": "state_out.json and runtime.txt"}},
			"metrics":      metrics,
		},
	}
	name := fmt.Sprintf("openlane-%02d-%s.intoto.json", ordinal, slug)
	stmt, err := statement(subjects, DesignFlow, pred)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, f.signer, filepath.Join(f.bundle, "att", name)); err != nil {
		return err
	}
	f.attested = append(f.attested, attested{ordinal, slug, name})
	fmt.Printf("  signed %s: %d subject(s), %d dependencies\n", name, len(subjects), len(deps))
	return nil
}

// attestReady signs every finished step not yet signed, in order, and stops at the first unfinished one.
func (f *Flow) attestReady() error {
	done := map[int]bool{}
	for _, a := range f.attested {
		done[a.ordinal] = true
	}
	for _, s := range stepDirs(f.RunDir) {
		if done[s.ordinal] {
			continue
		}
		if !isFile(filepath.Join(s.path, "runtime.txt")) {
			break
		}
		if err := f.attest(s.ordinal, s.slug, s.path); err != nil {
			return err
		}
	}
	return nil
}

// Run runs OpenLane in its container and signs each step as it finishes.
func (f *Flow) Run(poll time.Duration) error {
	if err := f.prepare(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(f.bundle, "att"), 0o755); err != nil {
		return err
	}
	logPath := filepath.Join(f.meta, "openlane.log")
	fmt.Printf("running OpenLane %s (%s flow)\n", S(f.lock, "openlane", "version"), S(f.lock, "openlane", "flow"))
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	args, err := f.command()
	if err != nil {
		return err
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := false
	for !exited {
		select {
		case <-done:
			exited = true
		default:
		}
		if err := f.attestReady(); err != nil {
			_ = cmd.Process.Kill()
			return err
		}
		if !exited {
			time.Sleep(poll)
		}
	}
	code := cmd.ProcessState.ExitCode()
	unfinished, err := f.WriteSummary(code)
	if err != nil {
		return err
	}
	fmt.Printf("OpenLane exited %d; %d steps signed\n", code, len(f.attested))
	if code != 0 || len(unfinished) > 0 {
		return fmt.Errorf("OpenLane failed (exit %d, unfinished %s); see %s", code, pyList(anyStrings(unfinished)), logPath)
	}
	return nil
}

// WriteSummary writes run.json: the record list in order, the pinned inputs, and any step that never finished.
func (f *Flow) WriteSummary(code int) ([]string, error) {
	signed := map[int]bool{}
	var steps []Obj
	for _, a := range f.attested {
		signed[a.ordinal] = true
		steps = append(steps, Obj{"ordinal": a.ordinal, "step": a.slug, "attestation": a.name})
	}
	unfinished := []string{}
	for _, s := range stepDirs(f.RunDir) {
		if !signed[s.ordinal] {
			unfinished = append(unfinished, filepath.Base(s.path))
		}
	}
	host, _ := os.Hostname()
	summary := Obj{
		"exitCode":   code,
		"steps":      nonNil(steps),
		"unfinished": anyStrings(unfinished),
		"source":     f.source,
		"image":      f.imageRD(),
		"pdk":        f.pdk,
		"runDir":     f.RunDir,
		"workDir":    f.work,
		"host":       host,
	}
	return unfinished, WriteJSON(filepath.Join(f.meta, "run.json"), summary)
}

// OpenLaneRun runs and attests the flow.
func OpenLaneRun(bundle, lockPath, key, work, pdkRoot string) error {
	f, err := NewFlow(bundle, lockPath, key, work, pdkRoot)
	if err != nil {
		return err
	}
	return f.Run(2 * time.Second)
}

// Verification

type olRecord struct {
	entry Obj
	stmt  Obj
}

// checkChain verifies every step record in order.
func checkChain(bundle, runDir string, trust *TrustRoot) ([]olRecord, error) {
	meta, err := ReadObj(filepath.Join(bundle, "openlane", "run.json"))
	if err != nil {
		return nil, failf("openlane: run.json: %v", err)
	}
	src, err := trust.Open(filepath.Join(bundle, "att", AttName("source-freeze")), "flow-platform", DesignFlow)
	if err != nil {
		return nil, err
	}
	sourceDigest := fileDigest(filepath.Join(bundle, "artifacts", "source.tar"))
	if !jsonEqual(get(firstSubject(src), "digest"), sourceDigest) {
		return nil, failf("source-freeze: source.tar does not match its attested digest")
	}
	known := map[string]string{S(sourceDigest, "sha256"): "source.tar"}
	var records []olRecord
	prev := ""
	entries := Objs(meta, "steps")
	if len(entries) == 0 {
		return nil, failf("no OpenLane step records")
	}
	digestsOf := func(list []Obj) []any {
		out := []any{}
		for _, d := range list {
			out = append(out, get(d, "digest"))
		}
		return out
	}
	for _, entry := range entries {
		label := "openlane " + S(entry, "step")
		stmt, err := trust.Open(filepath.Join(bundle, "att", S(entry, "attestation")), "flow-platform", DesignFlow)
		if err != nil {
			return nil, err
		}
		if err := asSLSAProvenance(stmt, label); err != nil {
			return nil, err
		}
		if buildType(stmt) != openlaneStepType {
			return nil, failf("%s: wrong buildType", label)
		}
		if len(failedChecks(Objs(stmt, "predicate", "hwFlow", "checks"))) > 0 {
			return nil, failf("%s: a gate failed", label)
		}
		kinds := map[string][]Obj{}
		for _, d := range Objs(stmt, "predicate", "buildDefinition", "resolvedDependencies") {
			k := S(d, "annotations", "kind")
			kinds[k] = append(kinds[k], d)
		}
		if !jsonEqual(digestsOf(kinds["source"]), []any{sourceDigest}) {
			return nil, failf("%s: does not consume the frozen source", label)
		}
		if !jsonEqual(digestsOf(kinds["toolchain"]), []any{get(meta, "image", "digest")}) {
			return nil, failf("%s: does not name the pinned OpenLane image", label)
		}
		if !jsonEqual(digestsOf(kinds["pdk"]), []any{get(meta, "pdk", "digest")}) {
			return nil, failf("%s: does not name the PDK tree", label)
		}
		for _, d := range kinds["view"] {
			if _, ok := known[S(d, "digest", "sha256")]; !ok {
				return nil, failf("%s: input view %s is not an output of any earlier step", label, S(d, "name"))
			}
		}
		wantPrev := []any{}
		if prev != "" {
			wantPrev = append(wantPrev, fileDigest(filepath.Join(bundle, "att", prev)))
		}
		if !jsonEqual(digestsOf(kinds["previous-step"]), wantPrev) {
			return nil, failf("%s: not linked to the previous step record", label)
		}
		for _, s := range Objs(stmt, "subject") {
			path := filepath.Join(runDir, S(s, "name"))
			d := fileDigest(path)
			if !isFile(path) || d == nil || d["sha256"] != S(s, "digest", "sha256") {
				return nil, failf("%s: subject %s is missing or does not match its digest", label, S(s, "name"))
			}
			known[S(s, "digest", "sha256")] = S(s, "name")
		}
		records = append(records, olRecord{entry, stmt})
		prev = S(entry, "attestation")
	}
	have := map[string]bool{}
	for _, r := range records {
		have[S(r.stmt, "predicate", "hwFlow", "step")] = true
	}
	var missing []string
	for _, s := range []string{"synthesis", "floorplan", "place-cts", "routing", "signoff", "gds-stream-out"} {
		if !have[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, failf("spec steps with no OpenLane record: %s", strings.Join(missing, ", "))
	}
	return records, nil
}

// finalGDS is the last GDS view produced, and the record entry that produced it.
func finalGDS(records []olRecord) (Obj, Obj, error) {
	var gds, entry Obj
	for _, r := range records {
		for _, s := range Objs(r.stmt, "subject") {
			if S(s, "annotations", "view") == "gds" {
				gds, entry = s, r.entry
			}
		}
	}
	if gds == nil {
		return nil, nil, failf("no step produced a GDS view")
	}
	return gds, entry, nil
}

func isZero(v any) bool {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return err == nil && f == 0
	case string:
		return x == "0"
	case bool:
		return !x
	case float64:
		return x == 0
	case int:
		return x == 0
	}
	return false
}

func signoff(records []olRecord) []Obj {
	metrics := Obj{}
	for _, r := range records {
		for k, v := range O(r.stmt, "predicate", "hwFlow", "metrics") {
			metrics[k] = v
		}
	}
	var checks []Obj
	for _, name := range append(append([]string{}, signoffRequired...), signoffOptional...) {
		v, ok := metrics[name]
		if !ok {
			if contains(signoffRequired, name) {
				checks = append(checks, Obj{"name": name, "result": "fail", "detail": "not reported"})
			}
			continue
		}
		result := "fail"
		if isZero(v) {
			result = "pass"
		}
		checks = append(checks, Obj{"name": name, "result": result, "detail": num(v)})
	}
	return checks
}

// OpenLaneRelease is the tapeout release over an OpenLane run: check the chain
// and signoff, then sign the final GDS.
func OpenLaneRelease(bundle, runDir, key, trustRoot, lockPath string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	trust, err := LoadTrustRoot(trustRoot)
	if err != nil {
		return err
	}
	records, err := checkChain(bundle, runDir, trust)
	var gds, producer Obj
	if err == nil {
		gds, producer, err = finalGDS(records)
	}
	if err != nil {
		if IsVerificationError(err) {
			return fmt.Errorf("release refused: %s", err)
		}
		return err
	}
	checks := append([]Obj{{"name": "chain", "result": "pass", "detail": fmt.Sprintf("%d OpenLane step records linked", len(records))}},
		signoff(records)...)
	final := filepath.Join(bundle, "artifacts", S(lock, "design")+".gds")
	data, err := os.ReadFile(filepath.Join(runDir, S(gds, "name")))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(final, data, 0o644); err != nil {
		return err
	}
	srcAtt := AttName("source-freeze")
	d, err := fileRD(filepath.Join(bundle, "att", srcAtt), "att/"+srcAtt)
	if err != nil {
		return err
	}
	deps := []Obj{d}
	for _, r := range records {
		name := S(r.entry, "attestation")
		d, err := fileRD(filepath.Join(bundle, "att", name), "att/"+name)
		if err != nil {
			return err
		}
		deps = append(deps, d)
	}
	run := builder()
	meta := O(run, "metadata")
	meta["startedOn"] = started
	meta["finishedOn"] = Now()
	run["byproducts"] = []Obj{}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType": designStepType("release"),
			"externalParameters": Obj{
				"design":            get(lock, "design"),
				"finalArtifact":     filepath.Base(final),
				"finalArtifactKind": "GDSII",
				"producedBy":        get(producer, "attestation"),
				"producedAs":        get(gds, "name"),
			},
			"resolvedDependencies": deps,
		},
		"runDetails": run,
		"hwFlow":     Obj{"step": "release", "tools": []Obj{}, "checks": checks},
	}
	subject, err := fileRD(final, "")
	if err != nil {
		return err
	}
	stmt, err := statement([]Obj{subject}, DesignFlow, pred)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", OpenLaneReleaseAtt)); err != nil {
		return err
	}
	if failed := failedChecks(checks); len(failed) > 0 {
		return fmt.Errorf("release: signoff gate failed: %s (recorded in the attestation)", strings.Join(failed, ", "))
	}
	fmt.Printf("release: %s sha256:%s (%d gates passed)\n", filepath.Base(final), S(subject, "digest", "sha256"), len(checks))
	return nil
}

// OpenLaneVerify is the buyer-side tapeout check for an OpenLane bundle.
func OpenLaneVerify(bundle, runDir string, trust *TrustRoot) ([]olRecord, Obj, error) {
	records, err := checkChain(bundle, runDir, trust)
	if err != nil {
		return nil, nil, err
	}
	rel, err := trust.Open(filepath.Join(bundle, "att", OpenLaneReleaseAtt), "tapeout-authority", DesignFlow)
	if err != nil {
		return nil, nil, err
	}
	if buildType(rel) != designStepType("release") {
		return nil, nil, failf("release: wrong buildType")
	}
	if len(failedChecks(Objs(rel, "predicate", "hwFlow", "checks"))) > 0 {
		return nil, nil, failf("release: a gate failed")
	}
	got := sha256Set(Objs(rel, "predicate", "buildDefinition", "resolvedDependencies"))
	for _, r := range records {
		if !got[S(fileDigest(filepath.Join(bundle, "att", S(r.entry, "attestation"))), "sha256")] {
			return nil, nil, failf("release: does not cover every OpenLane step record")
		}
	}
	gds, _, err := finalGDS(records)
	if err != nil {
		return nil, nil, err
	}
	final := firstSubject(rel)
	if !jsonEqual(get(final, "digest"), get(gds, "digest")) {
		return nil, nil, failf("release: released GDS is not the flow's final GDS")
	}
	d := fileDigest(filepath.Join(bundle, "artifacts", S(final, "name")))
	if d == nil || d["sha256"] != S(final, "digest", "sha256") {
		return nil, nil, failf("release: GDS in the bundle does not match the release")
	}
	return records, final, nil
}

// Reproducibility

var tsPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?m)\d{4}-\d{2}-\d{2}[T _]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?`), "<t>"},
	{regexp.MustCompile(`(?m)(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\w* +(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w* +\d+` +
		` +\d{1,2}:\d{2}:\d{2}(?: +[A-Z]{3,4})? +\d{4}`), "<t>"},
	{regexp.MustCompile(`(?m)\d{1,2}/\d{1,2}/\d{2,4}(?: +\d{1,2}:\d{2}(?::\d{2})?)?`), "<t>"},
	{regexp.MustCompile(`(?m)\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b`), "<t>"},
	// Magic .mag files stamp each cell with Unix epoch seconds.
	{regexp.MustCompile(`(?m)^timestamp \d+$`), "timestamp <t>"},
	{regexp.MustCompile(`(?m)\b\d+(?:\.\d+)? ?(?:s|sec|secs|seconds|ms|MB|MiB|GB|KB|kB)\b`), "<t>"},
}

func normalizeText(data []byte, hosts []string) string {
	text := strings.ToValidUTF8(string(data), "�")
	for _, h := range hosts {
		if h != "" {
			text = strings.ReplaceAll(text, h, "<host>")
		}
	}
	for _, p := range tsPatterns {
		text = p.re.ReplaceAllString(text, p.repl)
	}
	return text
}

// gdsRecords splits a GDSII stream into records (type byte then payload); ok is false if it does not parse.
func gdsRecords(data []byte) ([]string, bool) {
	var out []string
	for i := 0; i+4 <= len(data); {
		length := int(data[i])<<8 | int(data[i+1])
		if length < 4 || i+length > len(data) {
			return nil, false
		}
		out = append(out, string(data[i+2:i+3])+string(data[i+4:i+length]))
		end := data[i+2] == 0x04 // ENDLIB
		i += length
		if end {
			break
		}
	}
	return out, true
}

// gdsWithoutTimestamps drops the payloads of BGNLIB (0x01) and BGNSTR (0x05), which carry dates.
func gdsWithoutTimestamps(data []byte) ([]string, bool) {
	recs, ok := gdsRecords(data)
	if !ok {
		return nil, false
	}
	for i, r := range recs {
		if r[0] == 0x01 || r[0] == 0x05 {
			recs[i] = r[:1]
		}
	}
	return recs, true
}

func isText(data []byte) bool {
	if len(data) > 8192 {
		data = data[:8192]
	}
	return !bytes.Contains(data, []byte{0})
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func pyRepr(s string) string {
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
	}
	return "'" + strings.NewReplacer(`\`, `\\`, "'", `\'`).Replace(s) + "'"
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// Classify says how two differing files differ, from least to most serious.
func Classify(a, b []byte, name string, hosts ...string) (string, string) {
	if strings.HasSuffix(name, ".gds") || strings.HasSuffix(name, ".gds2") || strings.HasSuffix(name, ".gdsii") {
		ga, okA := gdsWithoutTimestamps(a)
		gb, okB := gdsWithoutTimestamps(b)
		if okA && equalStrings(ga, gb) {
			return "timestamps", "GDS BGNLIB/BGNSTR dates only"
		}
		if okA && okB && equalStrings(sortedStrings(ga), sortedStrings(gb)) {
			return "ordering", "same GDS records in a different order"
		}
		return "content", "GDS geometry or structure differs"
	}
	if !isText(a) || !isText(b) {
		return "content", "binary content differs"
	}
	na, nb := normalizeText(a, hosts), normalizeText(b, hosts)
	if na == nb {
		return "timestamps", "only timestamps, durations, memory figures or host names differ"
	}
	la, lb := splitLines(na), splitLines(nb)
	if equalStrings(sortedStrings(la), sortedStrings(lb)) {
		return "ordering", "same lines in a different order"
	}
	for i := 0; i < len(la) && i < len(lb); i++ {
		if la[i] != lb[i] {
			return "content", fmt.Sprintf("line %d: %s vs %s", i+1,
				pyRepr(truncateRunes(strings.TrimSpace(la[i]), 100)), pyRepr(truncateRunes(strings.TrimSpace(lb[i]), 100)))
		}
	}
	return "content", fmt.Sprintf("%d vs %d lines", len(la), len(lb))
}

var severity = map[string]int{"identical": 0, "timestamps": 1, "ordering": 2, "content": 3, "missing": 4}

func countClasses(classes []string) Obj {
	out := Obj{}
	for _, c := range classes {
		n, _ := out[c].(int)
		out[c] = n + 1
	}
	return out
}

// OpenLaneCompare verifies both runs, then compares every step's subjects and byproducts.
func OpenLaneCompare(bundleA, runA, bundleB, runB string, trustA, trustB *TrustRoot) (Obj, error) {
	recA, _, err := OpenLaneVerify(bundleA, runA, trustA)
	if err != nil {
		return nil, err
	}
	recB, _, err := OpenLaneVerify(bundleB, runB, trustB)
	if err != nil {
		return nil, err
	}
	metaA, err := ReadObj(filepath.Join(bundleA, "openlane", "run.json"))
	if err != nil {
		return nil, err
	}
	metaB, err := ReadObj(filepath.Join(bundleB, "openlane", "run.json"))
	if err != nil {
		return nil, err
	}
	toolsA, _ := ReadJSON(filepath.Join(bundleA, "openlane", "tools.json"))
	toolsB, _ := ReadJSON(filepath.Join(bundleB, "openlane", "tools.json"))
	hosts := []string{S(metaA, "host"), S(metaB, "host")}
	byStepB := map[string]Obj{}
	for _, r := range recB {
		byStepB[S(r.entry, "step")] = r.stmt
	}
	inputs := Obj{
		"source": jsonEqual(get(metaA, "source", "digest"), get(metaB, "source", "digest")),
		"image":  jsonEqual(get(metaA, "image", "digest"), get(metaB, "image", "digest")),
		"pdk":    jsonEqual(get(metaA, "pdk", "digest"), get(metaB, "pdk", "digest")),
		"tools":  jsonEqual(toolsA, toolsB),
	}
	files := func(stmt Obj, kind string) map[string]string {
		out := map[string]string{}
		if stmt == nil {
			return out
		}
		items := Objs(stmt, "subject")
		if kind == "byproduct" {
			items = Objs(stmt, "predicate", "runDetails", "byproducts")
		}
		for _, i := range items {
			out[S(i, "name")] = S(i, "digest", "sha256")
		}
		return out
	}

	var steps []Obj
	var subjectClasses, byproductClasses []string
	var firstDivergence any
	subjTotal, subjSame, bitExactSteps := 0, 0, 0
	for _, r := range recA {
		sb := byStepB[S(r.entry, "step")]
		row := Obj{"ordinal": get(r.entry, "ordinal"), "step": S(r.entry, "step"), "specStep": S(r.stmt, "predicate", "hwFlow", "step")}
		for _, kind := range []string{"subject", "byproduct"} {
			fa, fb := files(r.stmt, kind), files(sb, kind)
			names := map[string]bool{}
			for n := range fa {
				names[n] = true
			}
			for n := range fb {
				names[n] = true
			}
			diffs := []Obj{}
			worst := "identical"
			for _, name := range sortedKeys(names) {
				da, inA := fa[name]
				db, inB := fb[name]
				if inA && inB && da == db {
					continue
				}
				var d Obj
				if !inA || !inB {
					d = Obj{"name": name, "class": "missing", "detail": "only in one run"}
				} else {
					a, errA := os.ReadFile(filepath.Join(runA, name))
					b, errB := os.ReadFile(filepath.Join(runB, name))
					if errA != nil || errB != nil {
						d = Obj{"name": name, "class": "missing", "detail": "file not in the run directory"}
					} else {
						cls, detail := Classify(a, b, name, hosts...)
						d = Obj{"name": name, "class": cls, "detail": detail}
					}
				}
				diffs = append(diffs, d)
				if severity[S(d, "class")] > severity[worst] {
					worst = S(d, "class")
				}
				if kind == "subject" {
					subjectClasses = append(subjectClasses, S(d, "class"))
				} else {
					byproductClasses = append(byproductClasses, S(d, "class"))
				}
			}
			row[kind+"s"] = Obj{"total": len(names), "identical": len(names) - len(diffs)}
			row[kind+"Worst"] = worst
			row[kind+"Diffs"] = diffs
			if kind == "subject" {
				subjTotal += len(names)
				subjSame += len(names) - len(diffs)
				if worst == "identical" {
					bitExactSteps++
				}
				if firstDivergence == nil && severity[worst] >= severity["ordering"] {
					firstDivergence = S(r.entry, "step")
				}
			}
		}
		steps = append(steps, row)
	}

	gdsA, _, err := finalGDS(recA)
	if err != nil {
		return nil, err
	}
	gdsB, _, err := finalGDS(recB)
	if err != nil {
		return nil, err
	}
	gdsClass := "identical"
	if !jsonEqual(get(gdsA, "digest"), get(gdsB, "digest")) {
		a, errA := os.ReadFile(filepath.Join(runA, S(gdsA, "name")))
		b, errB := os.ReadFile(filepath.Join(runB, S(gdsB, "name")))
		if errA != nil || errB != nil {
			gdsClass = "missing"
		} else {
			gdsClass, _ = Classify(a, b, ".gds")
		}
	}
	return Obj{
		"inputsMatch":               inputs,
		"finalGds":                  Obj{"a": S(gdsA, "digest", "sha256"), "b": S(gdsB, "digest", "sha256"), "class": gdsClass},
		"steps":                     len(steps),
		"stepsWithBitExactSubjects": bitExactSteps,
		"subjects":                  Obj{"total": subjTotal, "bitExact": subjSame},
		"subjectClasses":            countClasses(subjectClasses),
		"byproductClasses":          countClasses(byproductClasses),
		"firstContentDivergence":    firstDivergence,
		"hosts":                     anyStrings(hosts),
		"perStep":                   nonNil(steps),
	}, nil
}

// classCounts formats a class count the way Python prints a dict, most benign class first.
func classCounts(v any) string {
	m := O(Obj{"v": v}, "v")
	if len(m) == 0 {
		return "none"
	}
	keys := sortedKeys(m)
	sort.SliceStable(keys, func(i, j int) bool { return severity[keys[i]] < severity[keys[j]] })
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("'%s': %s", k, num(m[k])))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// ReproducibilityMarkdown renders a comparison report.
func ReproducibilityMarkdown(report Obj) string {
	r := normalize(report)
	var inputs []string
	for _, k := range []string{"source", "image", "pdk", "tools"} {
		v := "NO"
		if Truthy(get(r, "inputsMatch", k)) {
			v = "yes"
		}
		inputs = append(inputs, k+" "+v)
	}
	first := "none"
	if s := S(r, "firstContentDivergence"); s != "" {
		first = s
	}
	lines := []string{
		"## OpenLane 2 reproducibility: two runs on separate runners",
		"",
		"- Inputs identical: " + strings.Join(inputs, ", "),
		fmt.Sprintf("- Final GDS: **%s** (a `%s`, b `%s`)", S(r, "finalGds", "class"), short(S(r, "finalGds", "a")), short(S(r, "finalGds", "b"))),
		fmt.Sprintf("- Step outputs bit-exact: %s of %s; steps with every output bit-exact: %s of %s",
			num(get(r, "subjects", "bitExact")), num(get(r, "subjects", "total")), num(get(r, "stepsWithBitExactSubjects")), num(get(r, "steps"))),
		"- Differing outputs by class: " + classCounts(get(r, "subjectClasses")),
		"- Differing logs and reports by class: " + classCounts(get(r, "byproductClasses")),
		"- First step whose outputs differ beyond timestamps: " + first,
		"",
		"| # | OpenLane step | Spec step | Outputs bit-exact | Worst output diff | Logs, reports bit-exact | Worst |",
		"| --- | --- | --- | --- | --- | --- | --- |",
	}
	for _, s := range Objs(r, "perStep") {
		lines = append(lines, fmt.Sprintf("| %s | %s | %s | %s/%s | %s | %s/%s | %s |",
			num(get(s, "ordinal")), S(s, "step"), S(s, "specStep"),
			num(get(s, "subjects", "identical")), num(get(s, "subjects", "total")), S(s, "subjectWorst"),
			num(get(s, "byproducts", "identical")), num(get(s, "byproducts", "total")), S(s, "byproductWorst")))
	}
	var details []string
	for _, s := range Objs(r, "perStep") {
		for _, d := range Objs(s, "subjectDiffs") {
			details = append(details, fmt.Sprintf("| %s | `%s` | %s | %s |",
				S(s, "step"), S(d, "name"), S(d, "class"), strings.ReplaceAll(S(d, "detail"), "|", `\|`)))
		}
	}
	if len(details) > 0 {
		lines = append(lines, "", "### Differing outputs", "", "| Step | File | Class | Detail |", "| --- | --- | --- | --- |")
		lines = append(lines, details...)
	}
	return strings.Join(lines, "\n") + "\n"
}

// RebuildRecord signs a record of the second build, bound to the released GDS of the first.
func RebuildRecord(report Obj, bundleA, key, out string) error {
	relPath := filepath.Join(bundleA, "att", OpenLaneReleaseAtt)
	rel, err := DecodeEnvelope(relPath)
	if err != nil {
		return err
	}
	final := firstSubject(rel)
	relRD, err := fileRD(relPath, "att/"+OpenLaneReleaseAtt)
	if err != nil {
		return err
	}
	g := O(report, "finalGds")
	class := S(g, "class")
	pass := func(ok bool) string {
		if ok {
			return "pass"
		}
		return "fail"
	}
	run := builder()
	run["byproducts"] = []Obj{}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType":            designStepType("rebuild"),
			"externalParameters":   Obj{"comparedWith": "second OpenLane run, same inputs, separate runner"},
			"resolvedDependencies": []Obj{relRD},
		},
		"runDetails": run,
		"hwFlow": Obj{
			"step":  "rebuild",
			"tools": []Obj{},
			"checks": []Obj{
				{"name": "gds-bit-exact", "result": pass(class == "identical"), "detail": S(g, "b")},
				{"name": "gds-equal-ignoring-timestamps", "result": pass(class == "identical" || class == "timestamps"), "detail": class},
			},
			"reproducibility": Obj{
				"subjects":               report["subjects"],
				"subjectClasses":         report["subjectClasses"],
				"firstContentDivergence": report["firstContentDivergence"],
			},
		},
	}
	stmt, err := statement([]Obj{final}, DesignFlow, pred)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	_, err = Sign(stmt, signer, out)
	return err
}
