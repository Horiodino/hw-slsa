package hslsa

// Isolated steps (spec, Design L3 and SLSA Build L3 for firmware): the flow
// platform runs each step's tools in a sandbox of their own, then hashes the
// outputs and signs outside it.
//
// The sandbox is bubblewrap: new user, mount, PID, IPC, UTS and network
// namespaces, so the step has no network at all (not even DNS); the host's
// /usr read-only for the tools; and a fresh working directory holding only
// the step's inputs, which it shares with no other step. Nothing else of the
// host is mounted, so no signing key and no other step's files are in reach
// of step code. The record says all of this in hwFlow.isolation and
// hwFlow.network, and the tapeout check requires it at Design L3. As with
// every record, a buyer relies on the platform that signs it for its truth:
// the record makes the platform accountable for the isolation it states.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// SandboxWork is the step's working directory inside the sandbox.
const SandboxWork = "/work"

// Sandbox runs step tools in isolation.
type Sandbox struct {
	Path, Version string
	// ReadOnly are extra host directories mounted read-only at the same
	// path, for tools that live outside /usr (a Rust toolchain, say).
	ReadOnly []string
}

// NewSandbox finds bubblewrap.
func NewSandbox() (*Sandbox, error) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("an isolated step needs bubblewrap (bwrap) on the flow platform: %w", err)
	}
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("bwrap --version: %w", err)
	}
	s := &Sandbox{Path: path, Version: strings.TrimSpace(string(out))}
	// A sandbox that cannot start is a platform fault, not a failed step.
	if r, err := s.Run(os.TempDir(), nil, "true"); err != nil || r.Code != 0 {
		return nil, fmt.Errorf("bubblewrap cannot create a sandbox here (on Ubuntu 24.04, unprivileged user namespaces need kernel.apparmor_restrict_unprivileged_userns=0): %s%v", r.Stderr, err)
	}
	return s, nil
}

// Run runs name with args in the sandbox, with work mounted read-write as
// the working directory. A non-zero exit is a result, not an error.
func (s *Sandbox) Run(work string, env []string, name string, args ...string) (procResult, error) {
	abs, err := filepath.Abs(work)
	if err != nil {
		return procResult{}, err
	}
	bw := []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
		"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
		"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
	}
	for _, d := range s.ReadOnly {
		bw = append(bw, "--ro-bind", d, d)
	}
	bw = append(bw, "--bind", abs, SandboxWork, "--chdir", SandboxWork,
		"--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", SandboxWork, "--setenv", "LANG", "C.UTF-8")
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		bw = append(bw, "--setenv", k, v)
	}
	bw = append(bw, "--", name)
	return runCmd("", nil, s.Path, append(bw, args...)...)
}

// Isolation is the record's hwFlow.isolation block for a step run in s.
func (s *Sandbox) Isolation() Obj {
	mounts := []any{"/usr (read-only)", SandboxWork + " (the step's own working directory, holding only its inputs)"}
	for _, d := range s.ReadOnly {
		mounts = append(mounts, d+" (read-only)")
	}
	return Obj{
		"sandbox":           s.Version,
		"namespaces":        []any{"user", "mount", "pid", "ipc", "uts", "network", "cgroup"},
		"mounts":            mounts,
		"freshWorkdir":      true,
		"signingKeyMounted": false,
		"signedOutsideStep": true,
		"stepsShareNoFiles": true,
		"network":           "none",
	}
}

// IsolatedNetwork is the record's hwFlow.network block for a sandboxed step:
// no network namespace interface but loopback, so no connection was possible.
func IsolatedNetwork() Obj {
	return Obj{"mode": "isolated", "observed": []any{}}
}

// isolationOK is the Design L3 test of one record's hwFlow.isolation.
func isolationOK(stmt Obj, label string) error {
	return isolationBlockOK(O(stmt, "predicate", "hwFlow"), "hwFlow", label, true)
}

// isolationBlockOK tests the isolation and network blocks of a record
// under block (named where in messages). A design step may reach declared
// license servers; a firmware build may not.
func isolationBlockOK(block Obj, where, label string, licenseServers bool) error {
	iso := O(block, "isolation")
	switch {
	case iso == nil:
		return failf("%s: no %s.isolation, so the record does not say the step ran isolated", label, where)
	case get(iso, "freshWorkdir") != true || get(iso, "stepsShareNoFiles") != true:
		return failf("%s: the step did not run in a fresh working directory of its own", label)
	case get(iso, "signingKeyMounted") != false || get(iso, "signedOutsideStep") != true:
		return failf("%s: the signing key was within reach of the step", label)
	case S(iso, "network") != "none" && !(licenseServers && S(iso, "network") == "license-server"):
		return failf("%s: the sandbox allowed network access %q", label, S(iso, "network"))
	}
	mode := S(block, "network", "mode")
	if (S(iso, "network") == "none") != (mode == "isolated") {
		return failf("%s: %s.isolation (network %s) and %s.network (mode %s) disagree", label, where, S(iso, "network"), where, mode)
	}
	return nil
}

// Package pins

// packageExcluded are the parts of a package a tool does not run, and that
// minimal images often leave out, so they stay out of its digest.
var packageExcluded = []string{"/usr/share/doc/", "/usr/share/man/", "/usr/share/lintian/", "/usr/share/bug/", "/usr/share/info/"}

// toolPackage names the Debian package that installed the binary at path,
// with its version and one digest over every file the package installed
// (spec, "Pinning tools and PDKs"): one line per file, "F <path> <sha256>",
// or "L <path> <target>" for a symlink, sorted by path and joined with
// newlines. It returns nil where dpkg does not know the file.
func toolPackage(path string) (Obj, error) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		return nil, nil
	}
	out, err := exec.Command("dpkg-query", "-S", path).Output()
	if err != nil {
		return nil, nil
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	pkg, _, ok := strings.Cut(line, ": ")
	if !ok || strings.Contains(pkg, ",") || strings.HasPrefix(pkg, "diversion") {
		return nil, nil
	}
	pkg = strings.TrimSpace(pkg)
	version, err := exec.Command("dpkg-query", "-W", "-f=${Version}", pkg).Output()
	if err != nil {
		return nil, err
	}
	list, err := exec.Command("dpkg-query", "-L", pkg).Output()
	if err != nil {
		return nil, err
	}
	digest, files, err := packageDigest(splitLines(string(list)))
	if err != nil {
		return nil, err
	}
	return Obj{
		"manager":    "dpkg",
		"name":       strings.TrimSuffix(pkg, ":amd64"),
		"version":    strings.TrimSpace(string(version)),
		"files":      files,
		"treeDigest": Obj{"sha256": digest},
	}, nil
}

// packageDigest is the digest over a package's file list, and how many
// files and symlinks it covers. A listed file that is missing counts as
// "M <path>", so a removed file changes the digest.
func packageDigest(paths []string) (string, int, error) {
	var lines []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || p == "/." {
			continue
		}
		skip := false
		for _, ex := range packageExcluded {
			if strings.HasPrefix(p, ex) {
				skip = true
			}
		}
		if skip {
			continue
		}
		fi, err := os.Lstat(p)
		switch {
		case err != nil:
			lines = append(lines, "M "+p)
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return "", 0, err
			}
			lines = append(lines, "L "+p+" "+target)
		case fi.Mode().IsRegular():
			d, err := sha256File(p)
			if err != nil {
				return "", 0, err
			}
			lines = append(lines, "F "+p+" "+d)
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i][2:] < lines[j][2:] })
	return sha256Bytes([]byte(strings.Join(lines, "\n"))), len(lines), nil
}

// pinnedTool is tool() plus, for an isolated step, the package the binary
// came from, so a policy can pin everything the tool runs.
func pinnedTool(name string, versionArgs ...string) (Obj, error) {
	t, err := tool(name, versionArgs...)
	if err != nil {
		return nil, err
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	pkg, err := toolPackage(real)
	if err != nil {
		return nil, err
	}
	if pkg == nil {
		// usrmerge: dpkg may know the file by its /bin path.
		if alt := strings.TrimPrefix(real, "/usr"); alt != real {
			if pkg, err = toolPackage(alt); err != nil {
				return nil, err
			}
		}
	}
	if pkg != nil {
		t["package"] = pkg
	}
	return t, nil
}

// toolPinned is the Design L3 test of one tool a record names: the policy's
// design.toolPins lists it with the same binary digest and, where the pin
// names one, the same package and package digest.
func toolPinned(t Obj, pins []Obj, label string) error {
	name := S(t, "name")
	if S(t, "digest", "sha256") == "" {
		return failf("%s: tool %s is not pinned by digest", label, name)
	}
	for _, p := range pins {
		if S(p, "name") != name || S(p, "sha256") != S(t, "digest", "sha256") {
			continue
		}
		pp := O(p, "package")
		if pp == nil {
			return nil
		}
		tp := O(t, "package")
		if S(tp, "name") == S(pp, "name") && S(tp, "version") == S(pp, "version") && S(tp, "treeDigest", "sha256") == S(pp, "treeDigest") {
			return nil
		}
		return failf("%s: tool %s is the pinned binary, but its package %s %s (files sha256:%s) is not the pinned one", label, name, S(tp, "name"), S(tp, "version"), short(S(tp, "treeDigest", "sha256")))
	}
	return failf("%s: tool %s sha256:%s is not on the policy's pinned tool list (design.toolPins)", label, name, short(S(t, "digest", "sha256")))
}
