package hslsa

// Firmware builds at SLSA Build L3 (spec, Firmware L3). The build platform
// runs the compiler in the same sandbox as an isolated design step
// (sandbox.go): no network, a fresh working directory holding only the
// sources, nothing of the host but the toolchain, read-only, and no signing
// key in reach. It hashes the image and signs the provenance outside the
// sandbox. The provenance says so in buildDefinition.internalParameters
// (isolation and network), and names every tool by digest: a Debian
// package's tools with the digest of every file of the package, the Go
// toolchain with one digest over everything a build runs or reads in its
// GOROOT, so a policy can pin the whole toolchain (firmware.toolPins).

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// goTreeParts are the parts of GOROOT a build runs or reads.
var goTreeParts = []string{"bin", "pkg/tool", "src", "VERSION", "go.env"}

// goToolchain finds the Go toolchain and describes it as a dependency: the
// go command by digest, its version, and in annotations.toolchain one
// digest over goTreeParts, by path inside GOROOT: one line per file,
// "F <path> <sha256>", or "L <path> <target>" for a symlink, sorted by path.
func goToolchain() (string, Obj, error) {
	out, err := runCmd("", nil, "go", "env", "GOROOT")
	if err != nil || out.Code != 0 {
		return "", nil, fmt.Errorf("go env GOROOT: %v%s", err, out.Stderr)
	}
	goroot := strings.TrimSpace(out.Stdout)
	goBin := filepath.Join(goroot, "bin", "go")
	ver, err := runCmd("", nil, goBin, "env", "GOVERSION")
	if err != nil || ver.Code != 0 {
		return "", nil, fmt.Errorf("go env GOVERSION: %v%s", err, ver.Stderr)
	}
	version := strings.TrimPrefix(strings.TrimSpace(ver.Stdout), "go")
	bin, err := sha256File(goBin)
	if err != nil {
		return "", nil, err
	}
	var lines []string
	for _, part := range goTreeParts {
		top := filepath.Join(goroot, part)
		if _, err := os.Lstat(top); err != nil {
			continue
		}
		err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(goroot, p)
			rel = filepath.ToSlash(rel)
			switch {
			case d.Type()&fs.ModeSymlink != 0:
				target, err := os.Readlink(p)
				if err != nil {
					return err
				}
				lines = append(lines, "L "+rel+" "+target)
			case d.Type().IsRegular():
				h, err := sha256File(p)
				if err != nil {
					return err
				}
				lines = append(lines, "F "+rel+" "+h)
			}
			return nil
		})
		if err != nil {
			return "", nil, err
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i][2:] < lines[j][2:] })
	return goroot, Obj{
		"name": "go", "uri": "pkg:golang/go@" + version, "digest": Obj{"sha256": bin},
		"annotations": Obj{
			"version": version,
			"toolchain": Obj{
				"parts": stringsAny(goTreeParts), "files": len(lines),
				"treeDigest": Obj{"sha256": sha256Bytes([]byte(strings.Join(lines, "\n")))},
			},
		},
	}, nil
}

func stringsAny(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

// toolDep is a tool a firmware build ran, as a resolved dependency: its
// binary by digest and, from dpkg, the package it came from with the
// digest of all the package's files.
func toolDep(name string, versionArgs ...string) (Obj, error) {
	t, err := pinnedTool(name, versionArgs...)
	if err != nil {
		return nil, err
	}
	ann := Obj{"version": t["version"]}
	if p := O(t, "package"); p != nil {
		ann["package"] = p
	}
	return Obj{"name": t["name"], "uri": "file:" + name, "digest": t["digest"], "annotations": ann}, nil
}

// imageRD describes a firmware image by SHA-256 and SHA-384, the digest an
// OCP S.A.F.E. report names it by.
func imageRD(path string) (Obj, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s384 := sha512.Sum384(data)
	return Obj{"name": filepath.Base(path), "digest": Obj{"sha256": sha256Bytes(data), "sha384": hex.EncodeToString(s384[:])}}, nil
}

// fwBuild runs a firmware build's commands in work, isolated when sb is set.
// It returns their log.
func fwBuild(sb *Sandbox, work string, env []string, steps [][]string) (string, error) {
	var log strings.Builder
	for _, st := range steps {
		var p procResult
		var err error
		if sb != nil {
			p, err = sb.Run(work, env, st[0], st[1:]...)
		} else {
			p, err = runCmd(work, append(os.Environ(), env...), st[0], st[1:]...)
		}
		if err != nil {
			return log.String(), err
		}
		fmt.Fprintf(&log, "$ %s\n%s%s", strings.Join(st, " "), p.Stdout, p.Stderr)
		if p.Code != 0 {
			return log.String(), fmt.Errorf("%s failed:\n%s", filepath.Base(st[0]), log.String())
		}
	}
	return log.String(), nil
}

// isolationParams are the internalParameters an isolated build records.
func isolationParams(sb *Sandbox, params Obj) Obj {
	if params == nil {
		params = Obj{}
	}
	if sb != nil {
		params["isolation"] = sb.Isolation()
		params["network"] = IsolatedNetwork()
	}
	return params
}

// ToolPin is the pin a policy's toolPins lists for a tool on this machine:
// the binary's digest and, for a Debian package's tool, the package and the
// digest of all its files, or for go, the toolchain tree digest.
func ToolPin(name string, versionArgs ...string) (Obj, error) {
	if name == "go" {
		_, dep, err := goToolchain()
		if err != nil {
			return nil, err
		}
		return Obj{"name": "go", "sha256": S(dep, "digest", "sha256"), "toolchain": Obj{
			"version": S(dep, "annotations", "version"), "treeDigest": S(dep, "annotations", "toolchain", "treeDigest", "sha256"),
		}}, nil
	}
	t, err := pinnedTool(name, versionArgs...)
	if err != nil {
		return nil, err
	}
	pin := Obj{"name": S(t, "name"), "sha256": S(t, "digest", "sha256")}
	if p := O(t, "package"); p != nil {
		pin["package"] = Obj{"name": S(p, "name"), "version": S(p, "version"), "treeDigest": S(p, "treeDigest", "sha256")}
	}
	return pin, nil
}
