package hslsa

// Design records from inside an EDA tool's Tcl shell.
//
// adapters/eda-tcl/hslsa.tcl is a hook a flow script sources. It marks each
// design step and names the files the step read and wrote, and at the end of
// the step writes one JSON event into a spool directory. It holds no key and
// hashes nothing: Tcl shells have no digest built in, and the tool is not the
// party that signs.
//
// EDARun is that party. It starts the tool with the spool in its environment,
// stays outside the tool, and for each event hashes the files, checks that
// every input design view is an output of an earlier record or a file of the
// frozen source, and signs one design-flow record with buildType
// .../design-flow/step/eda-tcl@v1. With HSLSA_SYNC set the hook waits for the
// signer's answer before the tool goes on, so a step's outputs are hashed
// before the next step can touch them, and a refused step stops the flow.
//
// EDAVerify is the buyer's check of those records.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var edaStepType = designStepType("eda-tcl")

// EDAHook is the adapter's name in records.
const EDAHook = "hslsa.tcl"

// edaReserved are design steps whose records come from their own signers.
var edaReserved = []string{"source-freeze", "release", "rebuild"}

var (
	edaEventRe = regexp.MustCompile(`^(\d{4})\.json$`)
	edaBeginRe = regexp.MustCompile(`^(\d{4})\.begin$`)
	labelRe    = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
)

// EDAOptions configures one signed run of a Tcl-driven flow.
type EDAOptions struct {
	Bundle string // bundle the records go into; its artifacts/source.tar, if any, is the frozen source
	Spool  string // directory the hook writes events into; must not exist yet
	Key    string // flow-platform signing key
	Root   string // subjects and inputs are named relative to this directory
	PDK    string // pinned PDK tree; pdk inputs must be under it
	Image  string // container image the tool runs in, pinned by digest, if any
	Poll   time.Duration
	Cmd    []string // the tool, or a script that runs it
}

type edaSigned struct {
	ordinal int
	step    string
	label   string
	name    string
	failed  bool
}

type edaRun struct {
	opt     EDAOptions
	signer  *Signer
	runID   string
	known   map[string]string // sha256 -> where it came from
	common  []Obj
	pdkDir  string
	signed  []edaSigned
	seenPID map[int]Obj // tool binaries by process, hashed once
	refused bool        // once a step is refused, every later one is too
}

// EDARun runs a flow whose Tcl scripts source the hook and signs a record per step.
func EDARun(opt EDAOptions) error {
	if len(opt.Cmd) == 0 {
		return fmt.Errorf("eda run: no command to run")
	}
	if opt.Poll == 0 {
		opt.Poll = 50 * time.Millisecond
	}
	signer, err := LoadSigner(opt.Key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(opt.Spool); err == nil {
		return fmt.Errorf("spool %s already exists; use a fresh directory", opt.Spool)
	}
	if err := os.MkdirAll(opt.Spool, 0o755); err != nil {
		return err
	}
	opt.Spool = resolvePath(opt.Spool)
	if opt.Root == "" {
		opt.Root = "."
	}
	opt.Root = resolvePath(opt.Root)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	r := &edaRun{opt: opt, signer: signer, runID: hex.EncodeToString(nonce), known: map[string]string{},
		seenPID: map[int]Obj{}}
	if err := r.prepare(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(opt.Bundle, "att"), 0o755); err != nil {
		return err
	}

	cmd := exec.Command(opt.Cmd[0], opt.Cmd[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, nil
	cmd.Env = append(os.Environ(), "HSLSA_SPOOL="+opt.Spool, "HSLSA_SYNC=1", "HSLSA_RUN_ID="+r.runID)
	fmt.Printf("eda: running %s, signing each step from %s\n", strings.Join(opt.Cmd, " "), opt.Spool)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var signErr error
	for exited := false; !exited; {
		select {
		case <-done:
			exited = true
		default:
		}
		if err := r.signReady(); err != nil && signErr == nil {
			// The hook raises the refusal in the tool; keep reading so the run ends cleanly.
			signErr = err
		}
		if !exited {
			time.Sleep(opt.Poll)
		}
	}
	code := cmd.ProcessState.ExitCode()
	unfinished, err := r.summary(code)
	if err != nil {
		return err
	}
	var failed []string
	for _, s := range r.signed {
		if s.failed {
			failed = append(failed, s.label)
		}
	}
	fmt.Printf("eda: tool exited %d; %d step(s) signed\n", code, len(r.signed))
	switch {
	case signErr != nil:
		return signErr
	case code != 0 || len(unfinished) > 0 || len(failed) > 0:
		return fmt.Errorf("eda: flow failed (exit %d, unfinished %s, failed %s)", code, pyList(anyStrings(unfinished)), pyList(anyStrings(failed)))
	}
	return nil
}

// prepare collects what every record names: the frozen source and its files,
// the image, the PDK tree, and the subjects of records already in the bundle.
func (r *edaRun) prepare() error {
	src := filepath.Join(r.opt.Bundle, "artifacts", "source.tar")
	if isFile(src) {
		d, err := fileRD(src, "")
		if err != nil {
			return err
		}
		d["annotations"] = Obj{"kind": "source"}
		r.common = append(r.common, d)
		members, err := sourceMembers(src)
		if err != nil {
			return err
		}
		for digest, name := range members {
			r.known[digest] = "source.tar:" + name
		}
	}
	if r.opt.Image != "" {
		ref, digest, ok := strings.Cut(r.opt.Image, "@sha256:")
		if !ok {
			return fmt.Errorf("--image must be pinned by digest (name@sha256:...)")
		}
		r.common = append(r.common, Obj{"name": "tool-image", "uri": "docker://" + ref, "digest": Obj{"sha256": digest},
			"annotations": Obj{"kind": "toolchain"}})
	}
	if r.opt.PDK != "" {
		r.pdkDir = resolvePath(r.opt.PDK)
		digest, err := TreeDigest(r.pdkDir)
		if err != nil {
			return err
		}
		r.common = append(r.common, Obj{"name": filepath.Base(r.pdkDir), "digest": Obj{"sha256": digest},
			"annotations": Obj{"kind": "pdk"}})
	}
	// Outputs of records the flow platform already signed in this bundle count as known inputs.
	entries, _ := filepath.Glob(filepath.Join(r.opt.Bundle, "att", "*.intoto.json"))
	for _, p := range entries {
		env, err := DecodeEnvelope(p)
		if err != nil {
			continue
		}
		for _, s := range Objs(env, "subject") {
			if d := S(s, "digest", "sha256"); d != "" {
				r.known[d] = "att/" + filepath.Base(p)
			}
		}
	}
	return nil
}

// sourceMembers hashes each file of the frozen source.
func sourceMembers(archive string) (map[string]string, error) {
	names, err := tarNames(archive)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, n := range names {
		data, err := tarMember(archive, n)
		if err != nil {
			return nil, err
		}
		if len(data) > 0 || !strings.HasSuffix(n, "/") {
			out[sha256Bytes(data)] = n
		}
	}
	return out, nil
}

// name is a path relative to the run's root when it is inside it.
func (r *edaRun) name(path string) string {
	rel, err := filepath.Rel(r.opt.Root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return filepath.ToSlash(rel)
}

// signReady signs every finished event not yet signed, in order.
func (r *edaRun) signReady() error {
	for {
		next := len(r.signed) + 1
		path := filepath.Join(r.opt.Spool, fmt.Sprintf("%04d.json", next))
		if !isFile(path) {
			return nil
		}
		var name string
		err := fmt.Errorf("an earlier step was refused")
		if !r.refused {
			name, err = r.sign(next, path)
		}
		ack := "signed " + name
		if err != nil {
			ack = "refused " + err.Error()
		}
		if werr := os.WriteFile(path+".ack", []byte(ack+"\n"), 0o644); werr != nil {
			return werr
		}
		if err != nil {
			// Count the event as handled so a later one is not mistaken for it.
			r.signed = append(r.signed, edaSigned{ordinal: next, failed: true, label: fmt.Sprintf("%04d", next)})
			if r.refused {
				continue
			}
			r.refused = true
			return failf("eda step %d refused: %v", next, err)
		}
	}
}

func (r *edaRun) toolEntry(ev Obj) Obj {
	t := Obj{"name": S(ev, "tool", "name"), "version": S(ev, "tool", "version")}
	if S(t, "name") == "" {
		t["name"] = "unknown"
	}
	if r.opt.Image != "" {
		t["uri"] = r.opt.Image
	}
	pid, _ := Int(ev, "pid")
	if d, ok := r.seenPID[int(pid)]; ok {
		if d != nil {
			t["digest"] = d
		}
		return t
	}
	// The binary's digest, only for a process this run started: its environment carries the run id.
	var digest Obj
	environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err == nil && strings.Contains("\x00"+string(environ)+"\x00", "\x00HSLSA_RUN_ID="+r.runID+"\x00") {
		if d, err := sha256File(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			digest = Obj{"sha256": d}
		}
	}
	r.seenPID[int(pid)] = digest
	if digest != nil {
		t["digest"] = digest
	}
	return t
}

func (r *edaRun) sign(ordinal int, path string) (string, error) {
	ev, err := ReadObj(path)
	if err != nil {
		return "", err
	}
	if n, _ := Int(ev, "ordinal"); int(n) != ordinal {
		return "", fmt.Errorf("event %s carries ordinal %d", filepath.Base(path), n)
	}
	step, label, status := S(ev, "step"), S(ev, "label"), S(ev, "status")
	if !contains(DesignStepNames, step) {
		return "", fmt.Errorf("%q is not a design step name", step)
	}
	if contains(edaReserved, step) {
		return "", fmt.Errorf("a %s record is not signed from a tool step", step)
	}
	if status != "completed" && status != "failed" {
		return "", fmt.Errorf("status %q", status)
	}
	if label == "" {
		label = step
	}

	var subjects []Obj
	produced := map[string]bool{}
	for _, o := range Objs(ev, "outputs") {
		p := filepath.Clean(S(o, "path"))
		if !isFile(p) {
			if status == "failed" {
				continue
			}
			return "", fmt.Errorf("output %s is not a file", p)
		}
		if strings.HasPrefix(p, r.opt.Spool+string(filepath.Separator)) {
			return "", fmt.Errorf("output %s is inside the spool", p)
		}
		if produced[p] {
			continue
		}
		d, err := fileRD(p, r.name(p))
		if err != nil {
			return "", err
		}
		if v := S(o, "view"); v != "" {
			d["annotations"] = Obj{"view": v}
		}
		subjects = append(subjects, d)
		produced[p] = true
	}
	if len(subjects) == 0 {
		if status != "failed" {
			return "", fmt.Errorf("step %s names no output", label)
		}
		// A failed step may have written nothing; its record still says so.
		d := rd("event/"+filepath.Base(path), "")
		d["digest"] = fileDigest(path)
		subjects = append(subjects, d)
	}

	deps := append([]Obj{}, r.common...)
	if S(ev, "hook") == "" {
		return "", fmt.Errorf("the hook did not report its own path; set HSLSA_HOOK to the file the flow sources")
	}
	hook := filepath.Clean(S(ev, "hook"))
	hookText, err := os.ReadFile(hook)
	if err != nil {
		return "", fmt.Errorf("the hook %s: %v", hook, err)
	}
	if !strings.Contains(string(hookText), "namespace eval ::hslsa") {
		return "", fmt.Errorf("%s, which the hook reported as its own path, is not the hook; set HSLSA_HOOK to the file the flow sources", hook)
	}
	hd := rd(EDAHook, sha256Bytes(hookText))
	hd["annotations"] = Obj{"kind": "adapter", "version": S(ev, "hookVersion")}
	deps = append(deps, hd)
	if script := S(ev, "script"); script != "" {
		d, err := fileRD(script, r.name(script))
		if err != nil {
			return "", fmt.Errorf("the flow script %s: %v", script, err)
		}
		d["annotations"] = Obj{"kind": "step-config", "role": "flow-script"}
		deps = append(deps, d)
	}
	for _, in := range Objs(ev, "inputs") {
		p, kind := filepath.Clean(S(in, "path")), S(in, "kind")
		d, err := sha256File(p)
		if err != nil {
			return "", fmt.Errorf("input %s: %v", p, err)
		}
		var entry Obj
		switch kind {
		case "view":
			from, ok := r.known[d]
			if !ok {
				return "", fmt.Errorf("input view %s is not an output of an earlier record or a file of the frozen source", r.name(p))
			}
			entry = rd(r.name(p), d)
			entry["annotations"] = Obj{"kind": "view", "from": from}
		case "pdk":
			if r.pdkDir == "" {
				return "", fmt.Errorf("pdk input %s, but the run pins no PDK (--pdk)", p)
			}
			rel, err := filepath.Rel(r.pdkDir, resolvePath(p))
			if err != nil || strings.HasPrefix(rel, "..") {
				return "", fmt.Errorf("pdk input %s is outside the pinned PDK %s", p, r.pdkDir)
			}
			entry = rd(filepath.ToSlash(rel), d)
			entry["annotations"] = Obj{"kind": "pdk-file"}
		case "config":
			entry = rd(r.name(p), d)
			entry["annotations"] = Obj{"kind": "step-config"}
		default:
			return "", fmt.Errorf("input %s has kind %q", p, kind)
		}
		deps = append(deps, entry)
	}
	if len(r.signed) > 0 {
		prev := r.signed[len(r.signed)-1].name
		d, err := fileRD(filepath.Join(r.opt.Bundle, "att", prev), "att/"+prev)
		if err != nil {
			return "", err
		}
		d["annotations"] = Obj{"kind": "previous-step"}
		deps = append(deps, d)
	}

	checks := []Obj{}
	failed := status == "failed"
	for _, c := range Objs(ev, "checks") {
		checks = append(checks, Obj{"name": S(c, "name"), "result": S(c, "result"), "detail": S(c, "detail")})
	}
	if failed {
		checks = append(checks, check("step-completed", false, "the flow script ended the step as failed"))
	} else {
		checks = append(checks, check("step-completed", true, "step_end in "+S(ev, "tool", "name")))
	}

	run := builder()
	meta := O(run, "metadata")
	meta["startedOn"] = S(ev, "started")
	meta["finishedOn"] = S(ev, "finished")
	slug := strings.Trim(labelRe.ReplaceAllString(label, "-"), "-")
	params := Obj{"step": label}
	if script := S(ev, "script"); script != "" {
		params["flowScript"] = r.name(script)
	}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType":            edaStepType,
			"externalParameters":   params,
			"resolvedDependencies": deps,
		},
		"runDetails": run,
		"hwFlow": Obj{
			"step":     step,
			"toolStep": label,
			"ordinal":  ordinal,
			"tools":    []Obj{r.toolEntry(ev)},
			"checks":   checks,
			"metrics":  O(ev, "metrics"),
			"adapter":  Obj{"name": EDAHook, "version": S(ev, "hookVersion"), "tcl": S(ev, "tcl")},
		},
	}
	if O(ev, "metrics") == nil {
		O(pred, "hwFlow")["metrics"] = Obj{}
	}
	stmt, err := statement(subjects, DesignFlow, pred)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("eda-%02d-%s.intoto.json", ordinal, slug)
	if _, err := Sign(stmt, r.signer, filepath.Join(r.opt.Bundle, "att", name)); err != nil {
		return "", err
	}
	for _, s := range subjects {
		r.known[S(s, "digest", "sha256")] = "att/" + name
	}
	r.signed = append(r.signed, edaSigned{ordinal, step, label, name, failed})
	fmt.Printf("  signed %s (%s): %d subject(s), %d dependencies\n", name, step, len(subjects), len(deps))
	return name, nil
}

// summary writes eda/run.json and returns the steps that began but never ended.
func (r *edaRun) summary(code int) ([]string, error) {
	if err := r.signReady(); err != nil {
		return nil, err
	}
	signed := map[int]bool{}
	steps := []Obj{}
	for _, s := range r.signed {
		signed[s.ordinal] = true
		if s.name != "" {
			steps = append(steps, Obj{"ordinal": s.ordinal, "step": s.step, "label": s.label, "attestation": s.name})
		}
	}
	unfinished := []string{}
	entries, _ := os.ReadDir(r.opt.Spool)
	for _, e := range entries {
		if m := edaBeginRe.FindStringSubmatch(e.Name()); m != nil {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			if !signed[n] {
				data, _ := os.ReadFile(filepath.Join(r.opt.Spool, e.Name()))
				unfinished = append(unfinished, fmt.Sprintf("%d %s", n, strings.TrimSpace(string(data))))
			}
		}
	}
	sort.Strings(unfinished)
	out := Obj{
		"exitCode":   code,
		"command":    anyStrings(r.opt.Cmd),
		"root":       r.opt.Root,
		"steps":      steps,
		"unfinished": anyStrings(unfinished),
	}
	return unfinished, WriteJSON(filepath.Join(r.opt.Bundle, "eda", "run.json"), out)
}

// EDAVerifyOptions is what the buyer's check of a Tcl-hooked flow needs.
type EDAVerifyOptions struct {
	Bundle       string
	Trust        *TrustRoot
	Root         string   // if set, every subject is re-hashed under it
	PDK          string   // if set, the PDK tree and each PDK file are re-hashed under it
	RequireSteps []string // spec steps that must each have a record
	Hook         string   // if set, every record must name this hook file's digest
}

// EDAVerify checks the records of an eda run, in order, and returns them.
func EDAVerify(opt EDAVerifyOptions) ([]Obj, error) {
	meta, err := ReadObj(filepath.Join(opt.Bundle, "eda", "run.json"))
	if err != nil {
		return nil, failf("eda: run.json: %v", err)
	}
	entries := Objs(meta, "steps")
	if len(entries) == 0 {
		return nil, failf("eda: no step records")
	}
	if n := len(A(meta, "unfinished")); n > 0 {
		return nil, failf("eda: %d step(s) began and never ended: %s", n, pyList(get(meta, "unfinished")))
	}

	known := map[string]string{}
	var sourceDigest Obj
	src := filepath.Join(opt.Bundle, "artifacts", "source.tar")
	if isFile(src) {
		srcStmt, err := opt.Trust.Open(filepath.Join(opt.Bundle, "att", AttName("source-freeze")), "flow-platform", DesignFlow)
		if err != nil {
			return nil, err
		}
		sourceDigest = fileDigest(src)
		if !jsonEqual(get(firstSubject(srcStmt), "digest"), sourceDigest) {
			return nil, failf("source-freeze: source.tar does not match its attested digest")
		}
		members, err := sourceMembers(src)
		if err != nil {
			return nil, err
		}
		for d, n := range members {
			known[d] = "source.tar:" + n
		}
	}
	ours := map[string]bool{}
	for _, e := range entries {
		ours[S(e, "attestation")] = true
	}
	// Outputs of any other design record the flow platform signed in this bundle.
	others, _ := filepath.Glob(filepath.Join(opt.Bundle, "att", "*.intoto.json"))
	for _, p := range others {
		if ours[filepath.Base(p)] {
			continue
		}
		stmt, err := opt.Trust.Open(p, "flow-platform", DesignFlow)
		if err != nil {
			continue
		}
		for _, s := range Objs(stmt, "subject") {
			known[S(s, "digest", "sha256")] = "att/" + filepath.Base(p)
		}
	}
	var hookDigest Obj
	if opt.Hook != "" {
		hookDigest = fileDigest(opt.Hook)
		if hookDigest == nil {
			return nil, fmt.Errorf("hook %s: cannot read", opt.Hook)
		}
	}
	var pdkDigest Obj
	if opt.PDK != "" {
		d, err := TreeDigest(opt.PDK)
		if err != nil {
			return nil, err
		}
		pdkDigest = Obj{"sha256": d}
	}

	digestsOf := func(list []Obj) []any {
		out := []any{}
		for _, d := range list {
			out = append(out, get(d, "digest"))
		}
		return out
	}
	var records []Obj
	var first map[string][]any
	prev := ""
	have := map[string]bool{}
	for i, entry := range entries {
		name := S(entry, "attestation")
		label := "eda " + S(entry, "label")
		stmt, err := opt.Trust.Open(filepath.Join(opt.Bundle, "att", name), "flow-platform", DesignFlow)
		if err != nil {
			return nil, err
		}
		if err := asSLSAProvenance(stmt, label); err != nil {
			return nil, err
		}
		if buildType(stmt) != edaStepType {
			return nil, failf("%s: wrong buildType", label)
		}
		hw := O(stmt, "predicate", "hwFlow")
		step := S(hw, "step")
		if !contains(DesignStepNames, step) || contains(edaReserved, step) {
			return nil, failf("%s: hwFlow.step %q is not a design step a tool step may record", label, step)
		}
		if n, _ := Int(hw, "ordinal"); int(n) != i+1 {
			return nil, failf("%s: ordinal %d, want %d", label, n, i+1)
		}
		if failed := failedChecks(Objs(hw, "checks")); len(failed) > 0 {
			return nil, failf("%s: check failed: %s", label, strings.Join(failed, ", "))
		}
		kinds := map[string][]Obj{}
		for _, d := range Objs(stmt, "predicate", "buildDefinition", "resolvedDependencies") {
			k := S(d, "annotations", "kind")
			kinds[k] = append(kinds[k], d)
		}
		// Every record names the same source, image, PDK and hook.
		pinned := map[string][]any{}
		for _, k := range []string{"source", "toolchain", "pdk", "adapter"} {
			pinned[k] = digestsOf(kinds[k])
		}
		if first == nil {
			first = pinned
		} else {
			for _, k := range []string{"source", "toolchain", "pdk", "adapter"} {
				if !jsonEqual(pinned[k], first[k]) {
					return nil, failf("%s: names a different %s from the first record", label, k)
				}
			}
		}
		wantSource := []any{}
		if sourceDigest != nil {
			wantSource = append(wantSource, sourceDigest)
		}
		if !jsonEqual(pinned["source"], wantSource) {
			return nil, failf("%s: does not consume the frozen source", label)
		}
		if len(kinds["adapter"]) != 1 {
			return nil, failf("%s: does not name the hook", label)
		}
		if hookDigest != nil && !jsonEqual(pinned["adapter"], []any{hookDigest}) {
			return nil, failf("%s: ran a different hook from %s", label, opt.Hook)
		}
		if pdkDigest != nil && len(kinds["pdk-file"]) > 0 && !jsonEqual(pinned["pdk"], []any{pdkDigest}) {
			return nil, failf("%s: the PDK tree does not match %s", label, opt.PDK)
		}
		if len(kinds["pdk-file"]) > 0 && len(kinds["pdk"]) != 1 {
			return nil, failf("%s: reads PDK files but pins no PDK tree", label)
		}
		for _, d := range kinds["view"] {
			if _, ok := known[S(d, "digest", "sha256")]; !ok {
				return nil, failf("%s: input view %s is not an output of an earlier record or a file of the frozen source", label, S(d, "name"))
			}
		}
		if opt.PDK != "" {
			for _, d := range kinds["pdk-file"] {
				got := fileDigest(filepath.Join(opt.PDK, filepath.FromSlash(S(d, "name"))))
				if got == nil || !jsonEqual(got, get(d, "digest")) {
					return nil, failf("%s: PDK file %s does not match the PDK", label, S(d, "name"))
				}
			}
		}
		wantPrev := []any{}
		if prev != "" {
			wantPrev = append(wantPrev, fileDigest(filepath.Join(opt.Bundle, "att", prev)))
		}
		if !jsonEqual(digestsOf(kinds["previous-step"]), wantPrev) {
			return nil, failf("%s: not linked to the previous step record", label)
		}
		for _, s := range Objs(stmt, "subject") {
			if opt.Root != "" {
				p := S(s, "name")
				if !filepath.IsAbs(p) {
					p = filepath.Join(opt.Root, filepath.FromSlash(p))
				}
				if d := fileDigest(p); d == nil || !jsonEqual(d, get(s, "digest")) {
					return nil, failf("%s: subject %s is missing or does not match its digest", label, S(s, "name"))
				}
			}
			known[S(s, "digest", "sha256")] = "att/" + name
		}
		have[step] = true
		records = append(records, stmt)
		prev = name
	}
	var missing []string
	for _, s := range opt.RequireSteps {
		if !have[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return nil, failf("spec steps with no eda record: %s", strings.Join(missing, ", "))
	}
	return records, nil
}
