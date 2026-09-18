package hslsa

// Caliptra example: one chain from RTL to a booted device with a hardware identity.
//
// Producer side, in the order e2e/caliptra/run.sh calls it:
//
//	firmware     SLSA Provenance v1 and a CycloneDX SBOM for the ROM and the
//	             signed FMC + runtime bundle built by caliptra-builder
//	design       step 0 source freeze of the pinned Caliptra RTL, step 1 Verilator
//	             lint, step 6a ROM merge (with rom-readback), and the release
//	fab          the "silicon": the ROM taken out of the released design
//	provision    per unit: inject UDS and field entropy, burn fuses, export the
//	             IDevID CSR from the real ROM, endorse it, write the firmware to
//	             flash, then sign one fw-provisioning record per unit
//	hbom         the product owner's HBOM, with firmware[] filled in
//
// Buyer side, CaliptraVerify: the tapeout and lot receipt checks, then the
// Firmware track and the spec's at-boot check on every received unit that was
// booted, then SLSA VSAs.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	SLSAProvenance = "https://slsa.dev/provenance/v1"
	FWProvisioning = NS + "/fw-provisioning/v0.1"
	FWBuildType    = NS + "/firmware/caliptra-builder@v1"
	ProvisionType  = NS + "/fw-provisioning/step/provision@v1"
	RTLTar         = "caliptra-rtl.tar"
	DesignTar      = "caliptra-design.tar"
	ROMHex         = "caliptra-rom.hex"
)

// FWAtt is the envelope file name of each firmware provenance record.
var FWAtt = map[string]string{"rom": "fw-rom.intoto.json", "bundle": "fw-bundle.intoto.json"}

// Images are the firmware image file names.
var Images = map[string]string{
	"rom":     "caliptra-rom.bin",
	"bundle":  "caliptra-fw-bundle.bin",
	"fmc":     "caliptra-fmc.bin",
	"runtime": "caliptra-runtime.bin",
}

var lifecycleValue = map[string]int64{"manufacturing": 1, "production": 3}

func sha384Bytes(data []byte) string {
	sum := sha512.Sum384(data)
	return hex.EncodeToString(sum[:])
}

// rd2 describes a file with both sha256 (the chain's link digest) and sha384 (what Caliptra measures).
func rd2(path, name string) (Obj, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = filepath.Base(path)
	}
	return Obj{"name": name, "digest": Obj{"sha256": sha256Bytes(data), "sha384": sha384Bytes(data)}}, nil
}

func git(repo string, args ...string) (string, error) {
	out, err := runCmd("", nil, "git", append([]string{"-C", repo}, args...)...)
	if err != nil {
		return "", err
	}
	if out.Code != 0 {
		return "", fmt.Errorf("git -C %s %s: %s", repo, strings.Join(args, " "), strings.TrimSpace(out.Stderr))
	}
	return strings.TrimSpace(out.Stdout), nil
}

func srcDir(lockPath string) (string, error) {
	return filepath.Abs(filepath.Join(filepath.Dir(lockPath), ".src"))
}

// Firmware track: image builds

var treeLine = regexp.MustCompile(`^(\S+) v(\S+)(?P<macro> \(proc-macro\))?(?: \((?P<src>.+)\))?$`)

type crate struct {
	name, version, source string
	buildOnly             bool
}

// parseTree reads packages from `cargo tree --prefix none --format {p}`, deduplicated.
func parseTree(text, checkout string) []crate {
	byKey := map[string]crate{}
	for _, line := range splitLines(text) {
		line = strings.TrimSpace(strings.ReplaceAll(line, " (*)", ""))
		m := treeLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		src := m[treeLine.SubexpIndex("src")]
		if src == "" {
			src = "registry"
		}
		if strings.HasPrefix(src, checkout) {
			if rel, err := filepath.Rel(checkout, src); err == nil {
				src = "path:" + rel
			}
		}
		byKey[m[1]+"\x00"+m[2]] = crate{m[1], m[2], src, m[treeLine.SubexpIndex("macro")] != ""}
	}
	out := make([]crate, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].version < out[j].version
	})
	return out
}

func cargoLockChecksums(lockText string) (map[string]string, error) {
	var lock struct {
		Package []struct {
			Name, Version, Checksum string
		} `toml:"package"`
	}
	if _, err := toml.Decode(lockText, &lock); err != nil {
		return nil, fmt.Errorf("Cargo.lock: %w", err)
	}
	sums := map[string]string{}
	for _, p := range lock.Package {
		if p.Checksum != "" {
			sums[p.Name+"\x00"+p.Version] = p.Checksum
		}
	}
	return sums, nil
}

// cycloneDX is a CycloneDX 1.6 SBOM for one firmware image, from the crates cargo compiled into it.
func cycloneDX(image string, imageRD Obj, treeText, lockText string, sw Obj, checkout string) (Obj, error) {
	sums, err := cargoLockChecksums(lockText)
	if err != nil {
		return nil, err
	}
	components := []Obj{}
	for _, c := range parseTree(treeText, checkout) {
		purl := fmt.Sprintf("pkg:cargo/%s@%s", c.name, c.version)
		scope := "required"
		if c.buildOnly {
			scope = "excluded"
		}
		comp := Obj{"type": "library", "bom-ref": purl, "name": c.name, "version": c.version, "purl": purl, "scope": scope}
		switch {
		case strings.HasPrefix(c.source, "path:"):
			comp["externalReferences"] = []Obj{{"type": "vcs", "url": fmt.Sprintf("git+%s@%s#%s", S(sw, "repo"), S(sw, "commit"), c.source[5:])}}
		case strings.HasPrefix(c.source, "http"):
			comp["externalReferences"] = []Obj{{"type": "vcs", "url": "git+" + c.source}}
		default:
			if sum, ok := sums[c.name+"\x00"+c.version]; ok {
				comp["hashes"] = []Obj{{"alg": "SHA-256", "content": sum}}
			}
		}
		components = append(components, comp)
	}
	return Obj{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata": Obj{
			"component": Obj{
				"type":    "firmware",
				"bom-ref": image,
				"name":    image,
				"hashes": []Obj{
					{"alg": "SHA-256", "content": S(imageRD, "digest", "sha256")},
					{"alg": "SHA-384", "content": S(imageRD, "digest", "sha384")},
				},
			},
			"tools": Obj{"components": []Obj{{"type": "application", "name": "hslsa", "version": "0.1"}}},
		},
		"components": components,
	}, nil
}

func fwStatement(subjects []Obj, target string, external Obj, deps, byproducts []Obj, started string) (Obj, error) {
	run := builder()
	meta := O(run, "metadata")
	meta["startedOn"] = started
	meta["finishedOn"] = Now()
	run["byproducts"] = nonNil(byproducts)
	params := Obj{"target": target}
	for k, v := range external {
		params[k] = v
	}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType":            FWBuildType,
			"externalParameters":   params,
			"internalParameters":   Obj{"CALIPTRA_IMAGE_NO_GIT_REVISION": "1"},
			"resolvedDependencies": nonNil(deps),
		},
		"runDetails": run,
	}
	return statement(subjects, SLSAProvenance, pred)
}

// CaliptraFirmware signs SLSA provenance for the images caliptra-builder built in buildDir.
func CaliptraFirmware(bundle, lockPath, buildDir, key string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	sw := O(lock, "caliptraSw")
	src, err := srcDir(lockPath)
	if err != nil {
		return err
	}
	checkout := filepath.Join(src, "caliptra-sw")
	art := filepath.Join(bundle, "artifacts")
	for _, name := range Images {
		if err := copyFile(filepath.Join(buildDir, name), filepath.Join(art, name)); err != nil {
			return err
		}
	}
	if err := copyFile(filepath.Join(buildDir, "fw-manifest.json"), filepath.Join(art, "fw-manifest.json")); err != nil {
		return err
	}
	lockText, err := os.ReadFile(filepath.Join(checkout, "Cargo.lock"))
	if err != nil {
		return err
	}
	head, err := git(checkout, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if head != S(sw, "commit") {
		return fmt.Errorf("caliptra-sw checkout is at %s, lock pins %s", head, S(sw, "commit"))
	}
	rustc, err := os.ReadFile(filepath.Join(buildDir, "rustc-version.txt"))
	if err != nil {
		return err
	}
	deps := []Obj{
		{"name": "caliptra-sw", "digest": Obj{"gitCommit": S(sw, "commit")}, "uri": fmt.Sprintf("git+%s@%s", S(sw, "repo"), S(sw, "tag"))},
		rd("Cargo.lock", sha256Bytes(lockText)),
		{"name": "rust-toolchain", "uri": "rustup:" + strings.TrimSpace(string(rustc))},
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}

	sboms := map[string]Obj{}
	for _, image := range []string{"rom", "fmc", "runtime"} {
		imageRD, err := rd2(filepath.Join(art, Images[image]), "")
		if err != nil {
			return err
		}
		tree, err := os.ReadFile(filepath.Join(buildDir, "tree-"+image+".txt"))
		if err != nil {
			return err
		}
		sbom, err := cycloneDX(Images[image], imageRD, string(tree), string(lockText), sw, checkout)
		if err != nil {
			return err
		}
		path := filepath.Join(art, "sbom-"+image+".cdx.json")
		if err := WriteJSON(path, sbom); err != nil {
			return err
		}
		if sboms[image], err = fileRD(path, ""); err != nil {
			return err
		}
	}

	romRD, err := rd2(filepath.Join(art, Images["rom"]), "")
	if err != nil {
		return err
	}
	romLog, err := fileRD(filepath.Join(buildDir, "build-rom.log"), "")
	if err != nil {
		return err
	}
	rom, err := fwStatement([]Obj{romRD}, "rom-no-log",
		Obj{"source": S(sw, "repo"), "tag": S(sw, "tag"), "command": "caliptra-builder --rom-no-log", "features": []any{"cfi"}},
		deps, []Obj{sboms["rom"], romLog}, started)
	if err != nil {
		return err
	}
	if _, err := Sign(rom, signer, filepath.Join(bundle, "att", FWAtt["rom"])); err != nil {
		return err
	}
	manifest, err := ReadObj(filepath.Join(art, "fw-manifest.json"))
	if err != nil {
		return err
	}
	var subjects []Obj
	for _, i := range []string{"bundle", "fmc", "runtime"} {
		r, err := rd2(filepath.Join(art, Images[i]), "")
		if err != nil {
			return err
		}
		subjects = append(subjects, r)
	}
	manifestRD, err := fileRD(filepath.Join(art, "fw-manifest.json"), "")
	if err != nil {
		return err
	}
	fwLog, err := fileRD(filepath.Join(buildDir, "build-fw.log"), "")
	if err != nil {
		return err
	}
	fwSvn := get(lock, "firmware", "fwSvn")
	fw, err := fwStatement(subjects, "fw",
		Obj{
			"source":      S(sw, "repo"),
			"tag":         S(sw, "tag"),
			"command":     "caliptra-builder --fw --fw-svn " + num(fwSvn),
			"fwSvn":       fwSvn,
			"signingKeys": "caliptra-image-fake-keys (Caliptra's public test keys)",
		},
		deps, []Obj{sboms["fmc"], sboms["runtime"], manifestRD, fwLog}, started)
	if err != nil {
		return err
	}
	if _, err := Sign(fw, signer, filepath.Join(bundle, "att", FWAtt["bundle"])); err != nil {
		return err
	}
	fmt.Printf("firmware: ROM sha384:%s..., bundle svn %s, signed\n", S(romRD, "digest", "sha384")[:16], num(get(manifest, "svn")))
	return nil
}

// Design track

func rtlEnv(root string) [][2]string {
	return [][2]string{
		{"CALIPTRA_PRIM_ROOT", root + "/src/caliptra_prim_generic"},
		{"CALIPTRA_PRIM_MODULE_PREFIX", "caliptra_prim_generic"},
	}
}

// rtlFiles is every file the lint command reads: the file list, the files it
// names and everything in its include directories.
func rtlFiles(root, fileList string) ([]string, error) {
	return vfFiles(root, fileList, "")
}

// vfFiles reads a Verilator file list like rtlFiles, leaving out lines that
// contain skip (when not empty).
func vfFiles(root, fileList, skip string) ([]string, error) {
	env := append([][2]string{{"CALIPTRA_ROOT", root}}, rtlEnv(root)...)
	files := map[string]bool{fileList: true}
	text, err := os.ReadFile(filepath.Join(root, fileList))
	if err != nil {
		return nil, err
	}
	rel := func(p string) (string, error) {
		r, err := filepath.Rel(root, filepath.Clean(p))
		if err != nil || r == ".." || strings.HasPrefix(r, "../") {
			return "", fmt.Errorf("%s is not under %s", p, root)
		}
		return r, nil
	}
	for _, line := range splitLines(string(text)) {
		line = strings.TrimSpace(line)
		for _, kv := range env {
			line = strings.ReplaceAll(line, "${"+kv[0]+"}", kv[1])
		}
		if line == "" || strings.HasPrefix(line, "//") || (skip != "" && strings.Contains(line, skip)) {
			continue
		}
		if strings.HasPrefix(line, "+incdir+") {
			dir := strings.TrimPrefix(line, "+incdir+")
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				p := filepath.Join(dir, e.Name())
				if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
					r, err := rel(p)
					if err != nil {
						return nil, err
					}
					files[r] = true
				}
			}
		} else {
			r, err := rel(line)
			if err != nil {
				return nil, err
			}
			files[r] = true
		}
	}
	return sortedKeys(files), nil
}

// CaliptraSourceFreeze is step 0: check the RTL checkouts are the pinned
// commits and trees, and freeze what lint reads.
func CaliptraSourceFreeze(bundle, lockPath, key string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	src, err := srcDir(lockPath)
	if err != nil {
		return err
	}
	rtl, abr := O(lock, "caliptraRtl"), O(lock, "adamsBridge")
	root := filepath.Join(src, "caliptra-rtl")
	var mismatched []string
	for _, r := range []struct {
		dir string
		pin Obj
	}{{root, rtl}, {filepath.Join(root, "submodules", "adams-bridge"), abr}} {
		head, err := git(r.dir, "rev-parse", "HEAD")
		if err != nil {
			return err
		}
		tree, err := git(r.dir, "rev-parse", "HEAD^{tree}")
		if err != nil {
			return err
		}
		if head != S(r.pin, "commit") || tree != S(r.pin, "tree") {
			mismatched = append(mismatched, fmt.Sprintf("%s at %s tree %s", filepath.Base(r.dir), head, tree))
		}
	}
	files, err := rtlFiles(root, S(lock, "rtl", "fileList"))
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	if err := os.MkdirAll(art, 0o755); err != nil {
		return err
	}
	if err := DeterministicTar(root, files, filepath.Join(art, RTLTar)); err != nil {
		return err
	}
	deps := []Obj{
		{"name": "caliptra-rtl", "digest": Obj{"gitCommit": S(rtl, "commit")}, "uri": "git+" + S(rtl, "repo")},
		{"name": "adams-bridge", "digest": Obj{"gitCommit": S(abr, "commit")}, "uri": "git+" + S(abr, "repo")},
	}
	if gh := githubSourceDep(); gh != nil {
		deps = append(deps, gh)
	}
	detail := strings.Join(mismatched, "; ")
	if detail == "" {
		detail = "commits and trees match caliptra.lock.json"
	}
	pred := designPredicate("source-freeze",
		Obj{"design": "caliptra", "top": S(lock, "rtl", "top"), "fileList": S(lock, "rtl", "fileList"), "files": len(files)},
		deps, nil, []Obj{check("inputs-pinned", len(mismatched) == 0, detail)}, nil, started)
	subject, err := fileRD(filepath.Join(art, RTLTar), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "source-freeze", []Obj{subject}, pred, signer)
}

// CaliptraLint is step 1 (simulation): Verilator lint of the whole Caliptra top level from the frozen archive.
func CaliptraLint(bundle, lockPath, key string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	flags := Strs(lock, "rtl", "verilatorFlags")
	fileList, top := S(lock, "rtl", "fileList"), S(lock, "rtl", "top")
	work, err := os.MkdirTemp("", "hslsa-lint-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := unpack(filepath.Join(art, RTLTar), work); err != nil {
		return err
	}
	env := append(os.Environ(), "CALIPTRA_ROOT="+work, "CALIPTRA_AXI4PC_DIR="+work)
	for _, kv := range rtlEnv(work) {
		env = append(env, kv[0]+"="+kv[1])
	}
	args := append(append([]string{"--lint-only"}, flags...), "-f", fileList, "--top-module", top)
	proc, err := runCmd(work, env, "verilator", args...)
	if err != nil {
		return err
	}
	log := strings.ReplaceAll(proc.Stdout+proc.Stderr, work, "$CALIPTRA_ROOT")
	if err := os.WriteFile(filepath.Join(art, "rtl-lint.log"), []byte(log), 0o644); err != nil {
		return err
	}
	errs, warnings := strings.Count(log, "%Error"), strings.Count(log, "%Warning")
	verilator, err := tool("verilator", "--version")
	if err != nil {
		return err
	}
	rtlRD, err := fileRD(filepath.Join(art, RTLTar), "")
	if err != nil {
		return err
	}
	command := strings.Join(append([]string{"verilator"}, args[:len(args)-4]...), " ") + " -f <fileList> --top-module <top>"
	pred := designPredicate("simulation", Obj{"top": top, "command": command},
		[]Obj{rtlRD}, []Obj{verilator},
		[]Obj{check("verilator-lint", proc.Code == 0 && errs == 0, fmt.Sprintf("exit %d, %d errors", proc.Code, errs))},
		nil, started)
	names, err := tarNames(filepath.Join(art, RTLTar))
	if err != nil {
		return err
	}
	O(pred, "hwFlow")["metrics"] = Obj{"lintWarnings": warnings, "files": len(names)}
	subject, err := fileRD(filepath.Join(art, "rtl-lint.log"), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "simulation", []Obj{subject}, pred, signer)
}

// RomHex is the ROM in the format caliptra-rtl's testbench loads into its ROM
// macro ($readmemh, one byte per word).
func RomHex(data []byte) []byte {
	lines := []string{"@00000000"}
	for i := 0; i < len(data); i += 16 {
		end := min(i+16, len(data))
		var words []string
		for _, b := range data[i:end] {
			words = append(words, fmt.Sprintf("%02X", b))
		}
		lines = append(lines, strings.Join(words, " "))
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// ReadRomHex parses RomHex output back into bytes.
func ReadRomHex(text string) ([]byte, error) {
	var out []byte
	for _, line := range splitLines(text) {
		if line == "" || strings.HasPrefix(line, "@") {
			continue
		}
		for _, w := range strings.Fields(line) {
			b, err := strconv.ParseUint(w, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("ROM hex: %w", err)
			}
			out = append(out, byte(b))
		}
	}
	return out, nil
}

// frozenDigest is the ROM digest the Caliptra TAC froze, from
// FROZEN_IMAGES.sha384sum in the pinned caliptra-sw.
func frozenDigest(lockPath, name string) (string, error) {
	src, err := srcDir(lockPath)
	if err != nil {
		return "", err
	}
	text, err := os.ReadFile(filepath.Join(src, "caliptra-sw", "FROZEN_IMAGES.sha384sum"))
	if err != nil {
		return "", err
	}
	for _, line := range splitLines(string(text)) {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == name {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("%s is not listed in FROZEN_IMAGES.sha384sum", name)
}

// CaliptraRomMerge is step 6a: merge the ROM image into the design, and prove
// the merged design holds exactly that image.
func CaliptraRomMerge(bundle, lockPath, key string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	rom, err := os.ReadFile(filepath.Join(art, Images["rom"]))
	if err != nil {
		return err
	}
	romAtt, err := DecodeEnvelope(filepath.Join(bundle, "att", FWAtt["rom"]))
	if err != nil {
		return err
	}
	provenance := O(firstSubject(romAtt), "digest")
	sizeDefine := S(lock, "rom", "sizeDefine")

	work, err := os.MkdirTemp("", "hslsa-rom-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := unpack(filepath.Join(art, RTLTar), work); err != nil {
		return err
	}
	defines, err := os.ReadFile(filepath.Join(work, S(lock, "rom", "definesFile")))
	if err != nil {
		return err
	}
	m := regexp.MustCompile("`define\\s+" + regexp.QuoteMeta(sizeDefine) + `\s+(\d+)`).FindSubmatch(defines)
	if m == nil {
		return fmt.Errorf("%s is not defined in %s", sizeDefine, S(lock, "rom", "definesFile"))
	}
	size, _ := strconv.Atoi(string(m[1]))
	names, err := tarNames(filepath.Join(art, RTLTar))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(work, "rom"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(work, "rom", "program.hex"), RomHex(rom), 0o644); err != nil {
		return err
	}
	if err := DeterministicTar(work, append(names, "rom/program.hex"), filepath.Join(art, DesignTar)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(art, ROMHex), RomHex(rom), 0o644); err != nil {
		return err
	}
	// Readback: extract the ROM from the merged design itself, not from the file just written.
	hexText, err := tarMember(filepath.Join(art, DesignTar), "rom/program.hex")
	if err != nil {
		return err
	}
	readback, err := ReadRomHex(string(hexText))
	if err != nil {
		return err
	}
	frozenName := S(lock, "rom", "frozenName")
	frozen, err := frozenDigest(lockPath, frozenName)
	if err != nil {
		return err
	}
	rtlRD, err := fileRD(filepath.Join(art, RTLTar), "")
	if err != nil {
		return err
	}
	romRD, err := rd2(filepath.Join(art, Images["rom"]), "")
	if err != nil {
		return err
	}
	pred := designPredicate("rom-merge",
		Obj{"romMacro": "imem", "romFormat": "$readmemh bytes", "sizeDefine": sizeDefine},
		[]Obj{rtlRD, romRD, envRD(bundle, FWAtt["rom"])}, nil,
		[]Obj{
			check("rom-fits-macro", len(rom) == size, fmt.Sprintf("%d bytes, macro holds %d", len(rom), size)),
			check("rom-readback", sha384Bytes(readback) == S(provenance, "sha384"),
				"bits read back from the merged design: sha384:"+sha384Bytes(readback)),
			check("rom-matches-frozen", sha384Bytes(rom) == frozen,
				fmt.Sprintf("Caliptra TAC frozen %s: sha384:%s", frozenName, frozen)),
		},
		nil, started)
	designRD, err := fileRD(filepath.Join(art, DesignTar), "")
	if err != nil {
		return err
	}
	hexRD, err := fileRD(filepath.Join(art, ROMHex), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "rom-merge", []Obj{designRD, hexRD}, pred, signer)
}

// CaliptraRelease is the tapeout release: run the tapeout check on the steps, then sign the merged design.
func CaliptraRelease(bundle, key, trustRoot, policyPath string) error {
	started := Now()
	policy, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	gate, err := tapeoutGate(bundle, trustRoot, policyPath)
	if err != nil {
		return err
	}
	var deps []Obj
	for _, s := range Strs(policy, "design", "requiredSteps") {
		deps = append(deps, envRD(bundle, AttName(s)))
	}
	pred := designPredicate("release",
		Obj{
			"design":            "caliptra",
			"finalArtifact":     DesignTar,
			"finalArtifactKind": "RTL with the ROM merged (stands in for GDS until physical design runs)",
		},
		deps, nil, []Obj{gate}, nil, started)
	subject, err := fileRD(filepath.Join(bundle, "artifacts", DesignTar), "")
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	return finish(bundle, "release", []Obj{subject}, pred, signer)
}

// CaliptraFab writes the mask ROM every unit carries, exactly as the released design holds it.
func CaliptraFab(bundle, devices string) error {
	rel, err := releasedSubject(bundle)
	if err != nil {
		return err
	}
	design := filepath.Join(bundle, "artifacts", S(rel, "name"))
	if d, err := sha256File(design); err != nil || d != S(rel, "digest", "sha256") {
		return fmt.Errorf("released design does not match its release record")
	}
	hexText, err := tarMember(design, "rom/program.hex")
	if err != nil {
		return err
	}
	rom, err := ReadRomHex(string(hexText))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(devices, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(devices, "rom.bin"), rom, 0o644); err != nil {
		return err
	}
	fmt.Printf("fab: mask ROM sha384:%s... taken from the released design\n", sha384Bytes(rom)[:16])
	return nil
}

// CaliptraRTLModel lays out the sources of the Verilated device for the RTL
// boot: the released design, unpacked byte for byte, plus the testbench,
// coverage and assertion files caliptra-rtl's Verilator harness reads that are
// not part of the design. It refuses a bench file that would replace a
// released one, and writes rtl-model.json next to out naming both sets.
func CaliptraRTLModel(bundle, lockPath, out string) error {
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	src, err := srcDir(lockPath)
	if err != nil {
		return err
	}
	rel, err := releasedSubject(bundle)
	if err != nil {
		return err
	}
	design := filepath.Join(bundle, "artifacts", S(rel, "name"))
	if d, err := sha256File(design); err != nil || d != S(rel, "digest", "sha256") {
		return fmt.Errorf("released design does not match its release record")
	}
	released, err := tarNames(design)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := unpack(design, out); err != nil {
		return err
	}
	inRelease := map[string]bool{}
	for _, n := range released {
		inRelease[filepath.Clean(n)] = true
	}
	// Axi4PC.sv comes from caliptra-sw's harness directory, not from caliptra-rtl.
	root := filepath.Join(src, "caliptra-rtl")
	benchList := S(lock, "rtl", "benchFileList")
	names, err := vfFiles(root, benchList, "${CALIPTRA_AXI4PC_DIR}")
	if err != nil {
		return err
	}
	var bench []Obj
	for _, n := range names {
		if inRelease[n] {
			a, errA := sha256File(filepath.Join(root, n))
			b, errB := sha256File(filepath.Join(out, n))
			if errA != nil || errB != nil || a != b {
				return fmt.Errorf("%s: the pinned checkout differs from the released design", n)
			}
			continue
		}
		if err := copyFile(filepath.Join(root, n), filepath.Join(out, n)); err != nil {
			return err
		}
		d, err := sha256File(filepath.Join(out, n))
		if err != nil {
			return err
		}
		bench = append(bench, Obj{"name": n, "digest": Obj{"sha256": d}})
	}
	manifest := Obj{
		"release":       Obj{"name": S(rel, "name"), "digest": get(rel, "digest")},
		"releasedFiles": len(released),
		"benchFileList": benchList,
		"benchSource":   Obj{"uri": "git+" + S(lock, "caliptraRtl", "repo"), "digest": Obj{"gitCommit": S(lock, "caliptraRtl", "commit")}},
		"benchFiles":    bench,
	}
	if err := WriteJSON(filepath.Clean(out)+".json", manifest); err != nil {
		return err
	}
	fmt.Printf("rtl-model: %d files of the released design sha256:%s... plus %d bench files\n",
		len(released), S(rel, "digest", "sha256")[:16], len(bench))
	return nil
}

// Identity CA and provisioning

// IdentityCA creates the product line's IDevID endorsement CA (an HSM in
// production; a local P-384 key here).
func IdentityCA(keysDir, name string) error {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	privPEM, err := privatePEM(key)
	if err != nil {
		return err
	}
	pubPEM, err := publicPEM(&key.PublicKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		return err
	}
	keyPath := filepath.Join(keysDir, "identity-ca.key.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(keysDir, "identity-ca.pub.pem"), []byte(pubPEM), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(keysDir, "identity-ca.name.txt"), []byte(name), 0o644)
}

func loadECKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePrivatePEM(data)
}

// utf8Name is a Name with one UTF8String common name.
func utf8Name(cn string) ([]byte, error) {
	return asn1.Marshal(pkix.RDNSequence{{{
		Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
		Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(cn)},
	}}})
}

// Endorse issues the IDevID certificate for a CSR the device exported, keeping
// its subject and the extensions it asked for.
func Endorse(csr *x509.CertificateRequest, caKey *ecdsa.PrivateKey, caName string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	issuer, err := utf8Name(caName)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial.Add(serial, big.NewInt(1)),
		RawSubject:         csr.RawSubject,
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		ExtraExtensions:    csr.Extensions,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	parent := &x509.Certificate{RawSubject: issuer, PublicKey: &caKey.PublicKey}
	return x509.CreateCertificate(rand.Reader, tmpl, parent, csr.PublicKey, caKey)
}

// FuseMap is the fuse values a programming station burns, except secrets.
// Hex strings are what the device reads.
func FuseMap(unit string, manifest Obj, lifecycle string, fwSvnFuse any) Obj {
	ueid := make([]byte, max(16, len(unit)))
	copy(ueid, unit)
	return Obj{
		"vendor_pk_hash":        get(manifest, "vendorPkHash"),
		"owner_pk_hash":         get(manifest, "ownerPkHash"),
		"fuse_pqc_key_type":     get(manifest, "pqcKeyType"),
		"fw_svn":                fwSvnFuse,
		"anti_rollback_disable": false,
		"fuse_ecc_revocation":   0,
		"fuse_lms_revocation":   0,
		"fuse_mldsa_revocation": 0,
		"soc_manifest_svn":      0,
		"soc_manifest_max_svn":  128,
		"idevid_cert_attr.ueid": "01" + hex.EncodeToString(ueid),
		"life_cycle":            lifecycle,
		"debug_locked":          true,
	}
}

// deviceFuses is the JSON the device model reads: what is physically in this unit's fuse bank.
func deviceFuses(unit string, fuses Obj, secrets [][2]string) Obj {
	return Obj{
		"serial":       unit,
		"udsSeed":      secrets[0][1],
		"fieldEntropy": secrets[1][1],
		"vendorPkHash": fuses["vendor_pk_hash"],
		"ownerPkHash":  fuses["owner_pk_hash"],
		"fwSvnFuse":    fuses["fw_svn"],
		"pqcKeyType":   fuses["fuse_pqc_key_type"],
		"lifecycle":    fuses["life_cycle"],
	}
}

func canonicalDigest(v any) string { return sha256Bytes(compactJSON(v)) }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func uuid4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// CaliptraProvision programs every shipped unit at the final test station, then signs one record per unit.
func CaliptraProvision(bundle, devices, keysDir, deviceBin, scenarioPath, lockPath string) error {
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	station := O(sc, "provisioning")
	trust, err := LoadTrustRoot(filepath.Join(bundle, "trust-root.json"))
	if err != nil {
		return err
	}
	caKey, err := loadECKey(filepath.Join(keysDir, "identity-ca.key.pem"))
	if err != nil {
		return err
	}
	caNameBytes, err := os.ReadFile(filepath.Join(keysDir, "identity-ca.name.txt"))
	if err != nil {
		return err
	}
	caName := string(caNameBytes)
	manifest, err := ReadObj(filepath.Join(art, "fw-manifest.json"))
	if err != nil {
		return err
	}
	image := filepath.Join(art, Images["bundle"])

	// The station checks the image's provenance before it writes a single unit.
	fw, err := trust.Open(filepath.Join(bundle, "att", FWAtt["bundle"]), "firmware-platform", SLSAProvenance)
	if err != nil {
		return err
	}
	imageDigest, err := sha256File(image)
	if err != nil {
		return err
	}
	verified := sha256Set(Objs(fw, "subject"))[imageDigest]
	if !verified {
		return fmt.Errorf("provisioning: firmware bundle does not match its provenance; refusing to write")
	}
	imageRD, err := rd2(image, "")
	if err != nil {
		return err
	}

	for _, d := range []string{"identity", "provisioning"} {
		if err := os.MkdirAll(filepath.Join(art, d), 0o755); err != nil {
			return err
		}
	}
	units, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return err
	}
	for _, unit := range units {
		udir := filepath.Join(devices, unit)
		if err := os.MkdirAll(udir, 0o755); err != nil {
			return err
		}
		uds, err := randomHex(64)
		if err != nil {
			return err
		}
		entropy, err := randomHex(32)
		if err != nil {
			return err
		}
		secrets := [][2]string{{"uds_seed", uds}, {"field_entropy", entropy}}
		fuses := FuseMap(unit, manifest, "manufacturing", get(lock, "firmware", "fwSvnFuse"))
		if err := WriteJSON(filepath.Join(udir, "fuses.json"), deviceFuses(unit, fuses, secrets)); err != nil {
			return err
		}
		work, err := os.MkdirTemp("", "hslsa-csr-")
		if err != nil {
			return err
		}
		out, err := runCmd("", nil, deviceBin, "csr", "--rom", filepath.Join(devices, "rom.bin"),
			"--fuses", filepath.Join(udir, "fuses.json"), "--out", work)
		if err == nil && out.Code != 0 {
			err = fmt.Errorf("%s csr for %s exited %d: %s", deviceBin, unit, out.Code, strings.TrimSpace(out.Stderr))
		}
		var csrDER []byte
		if err == nil {
			csrDER, err = os.ReadFile(filepath.Join(work, "idevid-csr-ecc384.der"))
		}
		os.RemoveAll(work)
		if err != nil {
			return err
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return fmt.Errorf("%s IDevID CSR: %w", unit, err)
		}
		if err := csr.CheckSignature(); err != nil {
			return failf("%s IDevID CSR: CSR self-signature is invalid", unit)
		}
		cert, err := Endorse(csr, caKey, caName)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(art, "identity", unit+".csr.der"), csrDER, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(art, "identity", unit+".idevid.der"), cert, 0o644); err != nil {
			return err
		}

		if err := copyFile(image, filepath.Join(udir, "flash.bin")); err != nil {
			return err
		}
		fuses["life_cycle"] = "production"
		if err := WriteJSON(filepath.Join(udir, "fuses.json"), deviceFuses(unit, fuses, secrets)); err != nil {
			return err
		}
		burned, err := ReadObj(filepath.Join(udir, "fuses.json"))
		if err != nil {
			return err
		}
		readback := Obj{}
		for _, k := range []string{"vendorPkHash", "ownerPkHash", "fwSvnFuse", "pqcKeyType", "lifecycle"} {
			readback[k] = burned[k]
		}
		flash, err := sha256File(filepath.Join(udir, "flash.bin"))
		if err != nil {
			return err
		}
		idevidKey, err := spkiDigest(csr.PublicKey)
		if err != nil {
			return err
		}
		var secretList []Obj
		for _, s := range secrets {
			keyID, err := uuid4()
			if err != nil {
				return err
			}
			secretList = append(secretList, Obj{
				"field":  s[0],
				"keyId":  S(station, "hsm") + ":" + keyID,
				"origin": "injected by " + S(station, "hsm"),
			})
		}
		log := Obj{
			"unit":         unit,
			"lotId":        S(sc, "finalTest", "lotId"),
			"stage":        "final-test",
			"station":      station,
			"fuses":        fuses,
			"fuseReadback": Obj{"sha256": canonicalDigest(readback)},
			"secrets":      secretList,
			"images": []Obj{{
				"name":               Images["bundle"],
				"role":               "firmware bundle (FMC and runtime)",
				"storage":            "external-flash",
				"digest":             imageRD["digest"],
				"readback":           Obj{"sha256": flash},
				"provenanceVerified": verified,
			}},
			"identity": Obj{
				"scheme":          "Caliptra",
				"ueid":            fuses["idevid_cert_attr.ueid"],
				"idevidPublicKey": Obj{"sha256": idevidKey},
				"csr":             "identity/" + unit + ".csr.der",
				"certificate":     "identity/" + unit + ".idevid.der",
				"endorsingCa":     caName,
			},
		}
		if err := WriteJSON(filepath.Join(art, "provisioning", unit+".json"), log); err != nil {
			return err
		}
		fmt.Printf("provision: %s IDevID %s... endorsed\n", unit, idevidKey[:16])
	}
	return SignProvisioning(bundle, filepath.Join(keysDir, S(station, "signer")+".key.pem"))
}

// ProvAtt is the envelope file name of one unit's provisioning record.
func ProvAtt(unit string) string { return "prov-" + unit + ".intoto.json" }

// SignProvisioning signs one fw-provisioning record per unit, from the station's logs, with the site key.
func SignProvisioning(bundle, key string) error {
	art := filepath.Join(bundle, "artifacts")
	relRDv := envRD(bundle, AttName("release"))
	final, err := releasedSubject(bundle)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	logs, err := filepath.Glob(filepath.Join(art, "provisioning", "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(logs)
	for _, path := range logs {
		log, err := ReadObj(path)
		if err != nil {
			return err
		}
		unit, ident, fuses := S(log, "unit"), O(log, "identity"), O(log, "fuses")
		expected := Obj{
			"vendorPkHash": fuses["vendor_pk_hash"],
			"ownerPkHash":  fuses["owner_pk_hash"],
			"fwSvnFuse":    fuses["fw_svn"],
			"pqcKeyType":   fuses["fuse_pqc_key_type"],
			"lifecycle":    fuses["life_cycle"],
		}
		images := Objs(log, "images")
		if len(images) == 0 {
			return fmt.Errorf("%s: no images", path)
		}
		image := images[0]
		csrOK := false
		if der, err := os.ReadFile(filepath.Join(art, S(ident, "csr"))); err == nil {
			if csr, err := x509.ParseCertificateRequest(der); err == nil {
				csrOK = csr.CheckSignature() == nil
			}
		}
		checks := []Obj{
			check("image-provenance-verified", Truthy(image["provenanceVerified"]), ""),
			check("image-readback", S(image, "readback", "sha256") == S(image, "digest", "sha256"), ""),
			check("fuse-readback", S(log, "fuseReadback", "sha256") == canonicalDigest(expected), ""),
			check("csr-self-signature", csrOK, ""),
			check("lifecycle-production", S(fuses, "life_cycle") == "production" && Truthy(fuses["debug_locked"]), ""),
		}
		var deps []Obj
		for _, f := range []struct{ path, name string }{
			{filepath.Join(art, Images["bundle"]), ""},
			{filepath.Join(art, S(ident, "csr")), S(ident, "csr")},
			{filepath.Join(art, S(ident, "certificate")), S(ident, "certificate")},
		} {
			d, err := fileRD(f.path, f.name)
			if err != nil {
				return err
			}
			deps = append(deps, d)
		}
		deps = append([]Obj{envRD(bundle, FWAtt["bundle"])}, deps...)
		identity := Obj{"certificate": deps[3]}
		for _, k := range []string{"scheme", "ueid", "idevidPublicKey", "endorsingCa"} {
			identity[k] = ident[k]
		}
		pred := Obj{
			"buildDefinition": Obj{
				"buildType":            ProvisionType,
				"externalParameters":   Obj{"unit": unit, "lotId": get(log, "lotId"), "stage": get(log, "stage")},
				"resolvedDependencies": deps,
			},
			"runDetails": Obj{
				"builder":  Obj{"id": "urn:hslsa:site:" + slug(S(log, "station", "site", "name"))},
				"metadata": Obj{"invocationId": "provision:" + unit, "finishedOn": Now()},
			},
			"hwProvision": Obj{
				"station":   get(log, "station", "id"),
				"site":      get(log, "station", "site"),
				"unit":      "urn:hslsa:unit:" + unit,
				"lot":       "urn:hslsa:lot:" + S(log, "lotId"),
				"designRef": Obj{"name": final["name"], "digest": final["digest"], "release": relRDv},
				"images":    get(log, "images"),
				"fuses":     fuses,
				"secrets":   get(log, "secrets"),
				"identity":  identity,
				"checks":    checks,
			},
		}
		subject := []Obj{rd("urn:hslsa:unit:"+unit, S(ident, "idevidPublicKey", "sha256"))}
		stmt, err := statement(subject, FWProvisioning, pred)
		if err != nil {
			return err
		}
		if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", ProvAtt(unit))); err != nil {
			return err
		}
		if failed := failedChecks(checks); len(failed) > 0 {
			return fmt.Errorf("provisioning %s: %s failed (recorded in the attestation)", unit, strings.Join(failed, ", "))
		}
	}
	fmt.Printf("provisioning: %d records signed\n", len(logs))
	return nil
}

// HBOM

// CaliptraHBOM builds, validates and signs the Caliptra example's HBOM, with firmware[] filled in.
func CaliptraHBOM(bundle, lockPath, scenarioPath, key string) error {
	art := filepath.Join(bundle, "artifacts")
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	flow, err := flowEntries(bundle, []string{"source-freeze", "simulation", "rom-merge", "release"})
	if err != nil {
		return err
	}
	final, err := releasedSubject(bundle)
	if err != nil {
		return err
	}
	shipped, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return err
	}
	rtl, abr := O(lock, "caliptraRtl"), O(lock, "adamsBridge")
	tag := S(lock, "caliptraSw", "tag")
	fw := func(name, role, storage, image string) (Obj, error) {
		r, err := rd2(filepath.Join(art, Images[image]), "")
		if err != nil {
			return nil, err
		}
		return Obj{
			"name": name, "version": tag, "role": role, "storage": storage,
			"digest": r["digest"], "sbomRef": fileRef(bundle, "artifacts/sbom-"+image+".cdx.json"),
		}, nil
	}
	var firmware []Obj
	for _, f := range [][4]string{
		{"caliptra-rom", "boot-rom", "mask-rom", "rom"},
		{"caliptra-fmc", "bootloader", "external-flash", "fmc"},
		{"caliptra-runtime", "runtime", "external-flash", "runtime"},
	} {
		entry, err := fw(f[0], f[1], f[2], f[3])
		if err != nil {
			return err
		}
		firmware = append(firmware, entry)
	}
	ip := func(name string, pin Obj) Obj {
		return Obj{
			"name": name, "kind": "soft", "supplier": Obj{"name": "CHIPS Alliance"}, "license": "Apache-2.0",
			"source": Obj{"uri": get(pin, "repo"), "digest": Obj{"gitCommit": get(pin, "commit")}},
		}
	}
	src := func(pin Obj) Obj {
		return Obj{"repo": get(pin, "repo"), "digest": Obj{"gitCommit": get(pin, "commit")}, "language": "SystemVerilog"}
	}
	predicate := Obj{
		"hbomVersion": "0.1",
		"product":     get(sc, "product"),
		"design": Obj{
			"ipBlocks":    []Obj{ip("caliptra-rtl", rtl), ip("adams-bridge", abr)},
			"rtlSources":  []Obj{src(rtl), src(abr)},
			"flow":        flow,
			"finalLayout": Obj{"uri": "file:artifacts/" + S(final, "name"), "digest": get(final, "digest")},
		},
		"manufacturing": manufacturingBlock(bundle, sc),
		"firmware":      firmware,
	}
	if err := signHBOM(bundle, final, S(sc, "finalTest", "lotId"), shipped, predicate, key); err != nil {
		return err
	}
	fmt.Printf("hbom: signed, %d flow steps, %d firmware images, %d units\n", len(flow), len(firmware), len(shipped))
	return nil
}

// Buyer: Firmware track and the at-boot check

func openFW(bundle string, trust *TrustRoot, which string) (Obj, error) {
	label := "firmware " + which
	stmt, err := trust.Open(filepath.Join(bundle, "att", FWAtt[which]), "firmware-platform", SLSAProvenance)
	if err != nil {
		return nil, err
	}
	if buildType(stmt) != FWBuildType {
		return nil, failf("%s: wrong buildType", label)
	}
	if err := asSLSAProvenance(stmt, label); err != nil {
		return nil, err
	}
	if err := requireFiles(bundle, stmt, label); err != nil {
		return nil, err
	}
	for _, b := range Objs(stmt, "predicate", "runDetails", "byproducts") {
		name := S(b, "name")
		if strings.HasPrefix(name, "sbom-") {
			d := fileDigest(filepath.Join(bundle, "artifacts", name))
			if d == nil || d["sha256"] != S(b, "digest", "sha256") {
				return nil, failf("%s: SBOM %s is missing or does not match its digest", label, name)
			}
		}
	}
	return stmt, nil
}

// FirmwareResult is what the Firmware track check vouches for.
type FirmwareResult struct {
	ROM, FMC, Runtime, Bundle Obj
	Manifest                  Obj
	Inputs                    []Obj
}

// FirmwareCheck is the Firmware L1 and L2 image check: provenance, SBOMs, the
// frozen ROM, and the ROM merge that put it in silicon.
func FirmwareCheck(bundle string, trust *TrustRoot, policy Obj) (*FirmwareResult, error) {
	pol := O(policy, "firmware")
	rom, err := openFW(bundle, trust, "rom")
	if err != nil {
		return nil, err
	}
	fw, err := openFW(bundle, trust, "bundle")
	if err != nil {
		return nil, err
	}
	romImage := firstSubject(rom)
	if S(romImage, "digest", "sha384") != S(pol, "romSha384") {
		return nil, failf("firmware rom: image is not the ROM the Caliptra TAC froze")
	}
	subjects := map[string]Obj{}
	for _, s := range Objs(fw, "subject") {
		subjects[S(s, "name")] = s
	}
	for _, name := range []string{Images["bundle"], Images["fmc"], Images["runtime"]} {
		if subjects[name] == nil {
			return nil, failf("firmware bundle: provenance does not name %s", name)
		}
	}
	byproducts := Objs(fw, "predicate", "runDetails", "byproducts")
	var manifestRD Obj
	hasSBOM := false
	for _, b := range byproducts {
		if strings.HasPrefix(S(b, "name"), "sbom-") {
			hasSBOM = true
		}
		if S(b, "name") == "fw-manifest.json" && manifestRD == nil {
			manifestRD = b
		}
	}
	if !hasSBOM {
		return nil, failf("firmware bundle: no SBOM")
	}
	manifestPath := filepath.Join(bundle, "artifacts", "fw-manifest.json")
	if manifestRD == nil || !jsonEqual(fileDigest(manifestPath), get(manifestRD, "digest")) {
		return nil, failf("firmware bundle: fw-manifest.json does not match its provenance")
	}
	manifest, err := ReadObj(manifestPath)
	if err != nil {
		return nil, failf("firmware bundle: fw-manifest.json: %v", err)
	}
	for _, image := range []string{"fmc", "runtime"} {
		if S(manifest, image, "sha384") != S(subjects[Images[image]], "digest", "sha384") {
			return nil, failf("firmware bundle: manifest %s digest differs from the provenance subject", image)
		}
	}
	if !jsonEqual(get(manifest, "svn"), get(fw, "predicate", "buildDefinition", "externalParameters", "fwSvn")) {
		return nil, failf("firmware bundle: manifest SVN differs from the provenance")
	}
	if S(manifest, "vendorPkHash") != S(pol, "vendorPkHash") {
		return nil, failf("firmware bundle: signed with vendor keys the policy does not allow")
	}

	// The mask ROM is covered only through the Design track: the ROM merge step must consume this image.
	merge, err := DecodeEnvelope(filepath.Join(bundle, "att", AttName("rom-merge")))
	if err != nil {
		return nil, failf("rom-merge: %v", err)
	}
	got := sha256Set(Objs(merge, "predicate", "buildDefinition", "resolvedDependencies"))
	if !got[S(romImage, "digest", "sha256")] || !got[S(envRD(bundle, FWAtt["rom"]), "digest", "sha256")] {
		return nil, failf("rom-merge: does not consume the ROM image named by its firmware provenance")
	}

	// The HBOM lists the same images, each with its SBOM.
	hb, err := trust.Open(filepath.Join(bundle, "att", "hbom.intoto.json"), "product-owner", HBOMType)
	if err != nil {
		return nil, err
	}
	listed := map[string]Obj{}
	for _, f := range Objs(hb, "predicate", "firmware") {
		listed[S(f, "name")] = f
	}
	for _, pair := range []struct {
		name  string
		image Obj
	}{{"caliptra-rom", romImage}, {"caliptra-fmc", subjects[Images["fmc"]]}, {"caliptra-runtime", subjects[Images["runtime"]]}} {
		entry := listed[pair.name]
		if entry == nil || S(entry, "digest", "sha384") != S(pair.image, "digest", "sha384") {
			return nil, failf("hbom: firmware entry %s does not match the image with provenance", pair.name)
		}
		sbom := filepath.Join(bundle, strings.TrimPrefix(S(entry, "sbomRef", "uri"), "file:"))
		if d := fileDigest(sbom); d == nil || !jsonEqual(d, get(entry, "sbomRef", "digest")) {
			return nil, failf("hbom: SBOM for %s does not match its reference", pair.name)
		}
	}
	return &FirmwareResult{
		ROM:      romImage,
		FMC:      subjects[Images["fmc"]],
		Runtime:  subjects[Images["runtime"]],
		Bundle:   subjects[Images["bundle"]],
		Manifest: manifest,
		Inputs:   []Obj{envRD(bundle, FWAtt["rom"]), envRD(bundle, FWAtt["bundle"])},
	}, nil
}

func byteField(v any, name string) (byte, error) {
	n, ok := Int(v)
	if !ok || n < 0 || n > 255 {
		return 0, fmt.Errorf("%s is not a byte", name)
	}
	return byte(n), nil
}

// FuseInfoDigests is what the ROM measures about its fuses
// (CALIPTRA_2_X_FUSE_OWNER_INFO and _VENDOR_INFO TcbInfo): owner, then vendor.
func FuseInfoDigests(fuses, manifest Obj) (string, string, error) {
	owner, err := hex.DecodeString(S(fuses, "owner_pk_hash"))
	if err != nil {
		return "", "", fmt.Errorf("owner_pk_hash: %w", err)
	}
	vendor, err := hex.DecodeString(S(fuses, "vendor_pk_hash"))
	if err != nil {
		return "", "", fmt.Errorf("vendor_pk_hash: %w", err)
	}
	b := func(v any, name string) byte {
		x, e := byteField(v, name)
		if e != nil && err == nil {
			err = e
		}
		return x
	}
	lms, ok := Int(fuses, "fuse_lms_revocation")
	if !ok || lms < 0 || lms > 0xffffffff {
		return "", "", fmt.Errorf("fuse_lms_revocation is not a 32-bit value")
	}
	var lmsBytes [4]byte
	binary.LittleEndian.PutUint32(lmsBytes[:], uint32(lms))
	owner = append(owner, 1, b(fuses["anti_rollback_disable"], "anti_rollback_disable"), b(fuses["fuse_ecc_revocation"], "fuse_ecc_revocation"))
	owner = append(owner, lmsBytes[:]...)
	owner = append(owner, b(fuses["fuse_mldsa_revocation"], "fuse_mldsa_revocation"), b(fuses["fw_svn"], "fw_svn"),
		b(fuses["soc_manifest_svn"], "soc_manifest_svn"), b(fuses["soc_manifest_max_svn"], "soc_manifest_max_svn"))
	lc, ok := lifecycleValue[S(fuses, "life_cycle")]
	if !ok {
		return "", "", fmt.Errorf("unknown life_cycle %s", S(fuses, "life_cycle"))
	}
	vendor = append(vendor, b(fuses["fuse_pqc_key_type"], "fuse_pqc_key_type"), byte(lc), b(fuses["debug_locked"], "debug_locked"),
		b(manifest["svn"], "svn"), b(manifest["vendorEccKeyIndex"], "vendorEccKeyIndex"),
		b(manifest["vendorPqcKeyIndex"], "vendorPqcKeyIndex"),
		0, // passive mode, not subsystem mode
	)
	if err != nil {
		return "", "", err
	}
	return sha384Bytes(owner), sha384Bytes(vendor), nil
}

func fwid(tcb TcbInfo, label string) (string, error) {
	var ids []string
	for _, f := range tcb.FWIDs {
		if f.HashAlg == SHA384OID {
			ids = append(ids, f.Digest)
		}
	}
	if len(ids) != 1 {
		return "", failf("%s: expected one SHA-384 FWID", label)
	}
	return ids[0], nil
}

// DeviceResult is what the at-boot check vouches for.
type DeviceResult struct {
	Unit   Obj
	Inputs []Obj
}

// DeviceCheck is the spec's at-boot check for one unit, from what the booted device returned.
func DeviceCheck(bundle string, trust *TrustRoot, policy Obj, design *DesignResult, lot *LotResult,
	fw *FirmwareResult, unit, bootDir string) (*DeviceResult, error) {
	art := filepath.Join(bundle, "artifacts")
	label := "device " + unit
	certs := map[string]*x509.Certificate{}
	for _, name := range []string{"ldevid", "fmc-alias", "rt-alias"} {
		path := filepath.Join(bootDir, name+"-ecc384.der")
		if _, err := os.Stat(path); err != nil {
			return nil, failf("%s: no %s certificate from the device", label, name)
		}
		cert, err := loadCert(path)
		if err != nil {
			return nil, failf("%s: unreadable %s certificate: %v", label, name, err)
		}
		certs[name] = cert
	}

	// The identity the device proves names the unit, and the unit is in the shipped lot.
	want := make([]byte, max(16, len(unit)))
	copy(want, unit)
	for _, name := range []string{"ldevid", "fmc-alias", "rt-alias"} {
		kind, raw, ok := UEID(certs[name])
		if !ok || kind != 1 || !bytes.Equal(raw, want) {
			return nil, failf("%s: UEID in the %s certificate does not name this unit", label, name)
		}
	}
	shipped, err := ReadUnits(filepath.Join(art, "shipped-lot.txt"))
	if err != nil {
		return nil, failf("%s: shipped lot list: %v", label, err)
	}
	if !contains(shipped, unit) {
		return nil, failf("%s: unit is not in the shipped lot", label)
	}

	// 2. The provisioning record for this unit, signed by the site that programmed it.
	station := S(policy, "firmware", "provisioningSigner")
	rec, err := trust.Open(filepath.Join(bundle, "att", ProvAtt(unit)), station, FWProvisioning)
	if err != nil {
		return nil, err
	}
	if buildType(rec) != ProvisionType {
		return nil, failf("%s: provisioning record has the wrong buildType", label)
	}
	if err := asSLSAProvenance(rec, label+" provisioning"); err != nil {
		return nil, err
	}
	hp := O(rec, "predicate", "hwProvision")
	if failed := failedChecks(Objs(hp, "checks")); len(failed) > 0 {
		return nil, failf("%s: provisioning gate failed: %s", label, strings.Join(failed, ", "))
	}
	if S(hp, "unit") != "urn:hslsa:unit:"+unit || S(firstSubject(rec), "name") != S(hp, "unit") {
		return nil, failf("%s: provisioning record is for %s", label, S(hp, "unit"))
	}
	if S(hp, "lot") != S(lot.Lot, "name") {
		return nil, failf("%s: provisioning record names lot %s", label, S(hp, "lot"))
	}
	if !jsonEqual(get(hp, "designRef", "digest"), get(design.Final, "digest")) || !jsonEqual(get(hp, "designRef", "release"), design.Release) {
		return nil, failf("%s: provisioning record names a different design release", label)
	}

	// 1. Certificate chain: identity CA -> IDevID -> LDevID -> FMC alias -> RT alias.
	ident := O(hp, "identity")
	certPath := filepath.Join(art, S(ident, "certificate", "name"))
	if d := fileDigest(certPath); d == nil || !jsonEqual(d, get(ident, "certificate", "digest")) {
		return nil, failf("%s: IDevID certificate does not match the provisioning record", label)
	}
	idevid, err := loadCert(certPath)
	if err != nil {
		return nil, failf("%s: unreadable IDevID certificate: %v", label, err)
	}
	endorsed := false
	for _, k := range trust.Roles["identity-ca"] {
		if signedBy(idevid, k.Public) {
			endorsed = true
			break
		}
	}
	if !endorsed {
		return nil, failf("%s: IDevID certificate is not endorsed by the identity CA", label)
	}
	if d, err := spkiDigest(idevid.PublicKey); err != nil || d != S(firstSubject(rec), "digest", "sha256") {
		return nil, failf("%s: provisioning record subject is not this IDevID key", label)
	}
	for _, link := range []struct {
		child, parent *x509.Certificate
		name          string
	}{
		{certs["ldevid"], idevid, "LDevID"},
		{certs["fmc-alias"], certs["ldevid"], "FMC alias"},
		{certs["rt-alias"], certs["fmc-alias"], "RT alias"},
	} {
		if err := checkSignedBy(link.child, link.parent, label+" "+link.name); err != nil {
			return nil, err
		}
	}

	// 3. Every measurement matches an image with provenance.
	fmcTcb, err := tcbInfoOfType(certs["fmc-alias"], "CALIPTRA_2_X_FMC_FIRMWARE_INFO", label)
	if err != nil {
		return nil, err
	}
	rtTcb, err := tcbInfoOfType(certs["rt-alias"], "CALIPTRA_2_X_RT_FIRMWARE_INFO", label)
	if err != nil {
		return nil, err
	}
	if id, err := fwid(fmcTcb, label); err != nil {
		return nil, err
	} else if id != S(fw.FMC, "digest", "sha384") {
		return nil, failf("%s: FMC measurement matches no FMC image with provenance", label)
	}
	if id, err := fwid(rtTcb, label); err != nil {
		return nil, err
	} else if id != S(fw.Runtime, "digest", "sha384") {
		return nil, failf("%s: runtime measurement matches no runtime image with provenance", label)
	}
	var written Obj
	for _, i := range Objs(hp, "images") {
		if S(i, "name") == Images["bundle"] {
			written = i
		}
	}
	if written == nil || !jsonEqual(get(written, "digest"), get(fw.Bundle, "digest")) {
		return nil, failf("%s: provisioning record wrote a different firmware bundle", label)
	}

	// The device measured the fuses the station says it burned.
	fuses := O(hp, "fuses")
	owner, vendor, err := FuseInfoDigests(fuses, fw.Manifest)
	if err != nil {
		return nil, failf("%s: provisioning record fuses: %v", label, err)
	}
	for _, m := range []struct{ kind, want, what string }{
		{"CALIPTRA_2_X_FUSE_VENDOR_INFO", vendor, "vendor"},
		{"CALIPTRA_2_X_FUSE_OWNER_INFO", owner, "owner"},
	} {
		tcb, err := tcbInfoOfType(certs["fmc-alias"], m.kind, label)
		if err != nil {
			return nil, err
		}
		id, err := fwid(tcb, label)
		if err != nil {
			return nil, err
		}
		if id != m.want {
			return nil, failf("%s: %s fuses the device measured differ from the provisioning record", label, m.what)
		}
	}
	if S(fuses, "vendor_pk_hash") != S(policy, "firmware", "vendorPkHash") {
		return nil, failf("%s: vendor key hash fuse is not the policy's", label)
	}
	if S(fuses, "life_cycle") != "production" || !Truthy(fuses["debug_locked"]) {
		return nil, failf("%s: unit is not in the production lifecycle with debug locked", label)
	}

	// 5. Anti-rollback: the running SVN is the image's, and not below the fuse.
	svn, _ := Int(fw.Manifest, "svn")
	for _, tcb := range []TcbInfo{fmcTcb, rtTcb} {
		if tcb.SVN&0xff != svn {
			return nil, failf("%s: device reports SVN %d, image provenance says %d", label, tcb.SVN&0xff, svn)
		}
	}
	fuseSvn, _ := Int(fuses, "fw_svn")
	minSvn, _ := Int(policy, "firmware", "minSvn")
	if svn < fuseSvn || svn < minSvn {
		return nil, failf("%s: image SVN %d is below the anti-rollback fuse or policy minimum", label, svn)
	}

	// 4. The ROM that took the first measurement is covered by the design chain (checked in FirmwareCheck).
	certDigest, err := sha256File(certPath)
	if err != nil {
		return nil, err
	}
	return &DeviceResult{Unit: rd("urn:hslsa:unit:"+unit, certDigest), Inputs: []Obj{envRD(bundle, ProvAtt(unit))}}, nil
}

// CaliptraVerify runs every buyer check on the received units, then signs VSAs when vsaKey is set.
func CaliptraVerify(bundle string, trust *TrustRoot, policyPath, unitsPath, bootsDir, vsaKey, vsaDir string) error {
	policy, err := ReadObj(policyPath)
	if err != nil {
		return err
	}
	design, err := TapeoutCheck(bundle, trust, policy, true)
	if err != nil {
		return err
	}
	fmt.Printf("tapeout check: PASSED for %s sha256:%s\n", S(design.Final, "name"), S(design.Final, "digest", "sha256"))
	units, err := ReadUnits(unitsPath)
	if err != nil {
		return err
	}
	lot, err := LotCheck(bundle, trust, policy, design, units)
	if err != nil {
		return err
	}
	fmt.Printf("lot receipt check: PASSED for %s, %d received units found in the lot\n", S(lot.Lot, "name"), len(units))
	fw, err := FirmwareCheck(bundle, trust, policy)
	if err != nil {
		return err
	}
	fmt.Printf("firmware check: PASSED, ROM is the TAC-frozen image, FMC and runtime svn %s\n", num(get(fw.Manifest, "svn")))
	var devices []*DeviceResult
	for _, u := range units {
		dev, err := DeviceCheck(bundle, trust, policy, design, lot, fw, u, filepath.Join(bootsDir, u))
		if err != nil {
			return err
		}
		devices = append(devices, dev)
	}
	fmt.Printf("at-boot check: PASSED for %d booted units (%s)\n", len(devices), strings.Join(units, ", "))
	if vsaKey == "" {
		return nil
	}
	claims := O(policy, "claims")
	out := func(name string) string { return filepath.Join(vsaDir, name) }
	if err := signVSA(design.Final, "hslsa:design:"+S(design.Final, "name"), claims["design"],
		append([]Obj{design.Release}, design.Inputs...), policyPath, vsaKey, out("design.vsa.intoto.json")); err != nil {
		return err
	}
	lotInputs := append(append([]Obj{}, lot.Inputs...), design.Release)
	if err := signVSA(lot.Lot, S(lot.Lot, "name"), claims["lot"], lotInputs, policyPath, vsaKey, out("lot.vsa.intoto.json")); err != nil {
		return err
	}
	fwSubject := rd(S(fw.Bundle, "name"), S(fw.Bundle, "digest", "sha256"))
	if err := signVSA(fwSubject, "hslsa:firmware:"+S(fw.Bundle, "name"), claims["firmware"], fw.Inputs,
		policyPath, vsaKey, out("firmware.vsa.intoto.json")); err != nil {
		return err
	}
	for i, unit := range units {
		dev := devices[i]
		inputs := append(append(append(append([]Obj{}, dev.Inputs...), fw.Inputs...), lot.Inputs...), design.Release)
		if err := signVSA(dev.Unit, S(dev.Unit, "name"), claims["device"], inputs, policyPath, vsaKey,
			out("device-"+unit+".vsa.intoto.json")); err != nil {
			return err
		}
	}
	fmt.Printf("VSAs written to %s: design, lot, firmware and %d devices\n", vsaDir, len(devices))
	return nil
}
