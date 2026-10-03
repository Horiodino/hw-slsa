package hslsa

// FPGA board example (e2e/fpga): the board owner's FPGA design and the images
// it puts in the board's SPI flash.
//
// The design is PicoSoC (PicoRV32 with SPI flash and UART) in its iCEBreaker
// port, for a Lattice iCE40UP5K, built with open tools only:
//
//	firmware    PicoSoC's firmware with GCC for RISC-V: SLSA provenance and an SBOM
//	simulation  step 1: the frozen RTL boots that firmware in Icarus Verilog
//	synthesis   step 2: Yosys synth_ice40
//	routing     steps 3 to 5: nextpnr-ice40 packs, places and routes in one run
//	signoff     step 6: IceStorm's icetime checks the routed design at the board clock
//	bitstream   step 7: icepack, checked by unpacking it again
//	release     the tapeout authority's release over the bitstream (design.go)
//	image       the board's flash image: bitstream, firmware and a boot manifest
//	            signed by the code signer, plus a CoRIM with the reference values
//	            the board's root of trust reports at boot
//
// The source freeze and the release are the PicoRV32 example's steps, run
// with this example's lock file.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	FPGAFWImage        = "picosoc-fw.bin"
	FPGAFWAtt          = "fw-picosoc.intoto.json"
	FPGAFWSBOM         = "sbom-picosoc-fw.cdx.json"
	FPGAFWBuildType    = NS + "/firmware/riscv-gcc@v1"
	FlashImage         = "flash.bin"
	BootManifest       = "boot-manifest.json"
	FlashAtt           = "fw-flash.intoto.json"
	FlashBuildType     = NS + "/firmware/flash-image@v1"
	BoardCoRIMFile     = "board-images.corim"
	BootManifestFormat = "hslsa-boot-manifest/v1"
	// Image roles in the boot manifest, also the TcbInfo type the root of trust reports.
	RoleBitstream = "fpga-bitstream"
	RoleSoCFW     = "soc-firmware"
)

// fpgaTool identifies a tool that has no version option (Project IceStorm's)
// by the digest of its binary.
func fpgaTool(name string) (Obj, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed", name)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	d, err := sha256File(real)
	if err != nil {
		return nil, err
	}
	return Obj{"name": name, "version": "Project IceStorm (no version option)", "digest": Obj{"sha256": d}}, nil
}

// yosysShare is Yosys's data directory, which holds the iCE40 simulation models.
func yosysShare() (string, error) {
	if out, err := exec.Command("yosys-config", "--datdir").Output(); err == nil {
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return dir, nil
		}
	}
	path, err := exec.LookPath("yosys")
	if err != nil {
		return "", fmt.Errorf("yosys is not installed")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(real), "..", "share", "yosys")
	if _, err := os.Stat(filepath.Join(dir, "ice40", "cells_sim.v")); err != nil {
		return "", fmt.Errorf("cannot find Yosys's ice40/cells_sim.v")
	}
	return filepath.Clean(dir), nil
}

// icestormChipDB finds the iCE40 chip database icetime reads, for the record.
func icestormChipDB(device string) string {
	name := "chipdb-" + strings.TrimPrefix(strings.TrimPrefix(device, "up"), "hx") + ".txt"
	for _, dir := range []string{"/usr/share/fpga-icestorm/chipdb", "/usr/share/icebox", "/usr/local/share/icebox"} {
		if p := filepath.Join(dir, name); fileExists(p) {
			return p
		}
	}
	if path, err := exec.LookPath("icetime"); err == nil {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			if p := filepath.Join(filepath.Dir(real), "..", "share", "icebox", name); fileExists(p) {
				return filepath.Clean(p)
			}
		}
	}
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// riscvPrefix is the RISC-V GCC prefix to use: HSLSA_RISCV_PREFIX, or the first one installed.
func riscvPrefix() (string, error) {
	if p := os.Getenv("HSLSA_RISCV_PREFIX"); p != "" {
		return p, nil
	}
	for _, p := range []string{"riscv64-unknown-elf-", "riscv64-elf-", "riscv32-unknown-elf-"} {
		if _, err := exec.LookPath(p + "gcc"); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no RISC-V GCC found (riscv64-unknown-elf-gcc or riscv64-elf-gcc)")
}

// fpgaStep holds what every FPGA design step starts from.
type fpgaStep struct {
	lock    Obj
	art     string // the bundle's artifacts directory, absolute
	work    string // a scratch directory with the frozen source unpacked
	started string
	source  Obj // the source archive
}

func startFPGAStep(bundle, lockPath string) (*fpgaStep, error) {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return nil, err
	}
	art, err := filepath.Abs(filepath.Join(bundle, "artifacts"))
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp("", "hslsa-fpga-")
	if err != nil {
		return nil, err
	}
	if err := unpack(filepath.Join(art, "source.tar"), work); err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	source, err := fileRD(filepath.Join(art, "source.tar"), "")
	if err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	return &fpgaStep{lock: lock, art: art, work: work, started: started, source: source}, nil
}

func (s *fpgaStep) done() { os.RemoveAll(s.work) }

// sign finishes a step: sign its record, then stop if a gate failed.
func (s *fpgaStep) sign(bundle, step, key string, subjects []Obj, external Obj, deps, tools, checks, byproducts []Obj) error {
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	pred := designPredicate(step, external, deps, tools, checks, byproducts, s.started)
	return finish(bundle, step, subjects, pred, signer, nil)
}

// stepSubject is the first subject of an earlier design step, read from its record.
func stepSubject(bundle, step string) (Obj, error) {
	stmt, err := DecodeEnvelope(filepath.Join(bundle, "att", AttName(step)))
	if err != nil {
		return nil, err
	}
	sub := firstSubject(stmt)
	if sub == nil {
		return nil, fmt.Errorf("%s has no subject", AttName(step))
	}
	return Obj{"name": sub["name"], "digest": sub["digest"]}, nil
}

// Simulation of the SoC: the PicoSoC testbench with its SPI flash model.

var (
	uartChar = regexp.MustCompile(`^Serial data: '(.)'$`)
	uartCode = regexp.MustCompile(`^Serial data:\s+(\d+)$`)
)

// FlashHex is a region of flash as $readmemh input for the flash model.
func FlashHex(data []byte, offset int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "@%08x\n", offset)
	for i := 0; i < len(data); i += 16 {
		end := min(i+16, len(data))
		for j := i; j < end; j++ {
			if j > i {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%02X", data[j])
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// uartText turns the testbench's "Serial data" lines into the text the SoC sent.
func uartText(log string) string {
	var b strings.Builder
	for _, line := range splitLines(log) {
		line = strings.TrimSpace(line)
		if m := uartChar.FindStringSubmatch(line); m != nil {
			b.WriteString(m[1])
		} else if m := uartCode.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n < 256 {
				b.WriteByte(byte(n))
			}
		}
	}
	return b.String()
}

// SoCSim is a compiled PicoSoC testbench, ready to boot firmware.
type SoCSim struct {
	dir   string
	lock  Obj
	tools []Obj
	cells Obj
	build procResult
}

// NewSoCSim compiles the testbench from the frozen source archive with the
// iCE40 simulation models. Close removes it.
func NewSoCSim(sourceTar string, lock Obj) (*SoCSim, error) {
	dir, err := os.MkdirTemp("", "hslsa-soc-")
	if err != nil {
		return nil, err
	}
	if err := unpack(sourceTar, dir); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	share, err := yosysShare()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	cells := filepath.Join(share, "ice40", "cells_sim.v")
	cellsDigest, err := sha256File(cells)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	sim := O(lock, "simulation")
	args := []string{"-s", S(sim, "top"), "-o", "tb.vvp"}
	for _, d := range Strs(sim, "defines") {
		args = append(args, "-D"+d)
	}
	args = append(append(args, Strs(sim, "files")...), cells)
	build, err := runCmd(dir, nil, "iverilog", args...)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	var tools []Obj
	for _, t := range [][2]string{{"iverilog", "-V"}, {"vvp", "-V"}} {
		o, err := tool(t[0], t[1])
		if err != nil {
			os.RemoveAll(dir)
			return nil, err
		}
		tools = append(tools, o)
	}
	return &SoCSim{dir: dir, lock: lock, tools: tools, cells: rd("yosys/ice40/cells_sim.v", cellsDigest), build: build}, nil
}

func (s *SoCSim) Close() { os.RemoveAll(s.dir) }

// SoCRun is one boot of the SoC in simulation.
type SoCRun struct {
	Log, UART        string
	Ran, Finished    bool
	BannerSeen       bool
	MissingBanner    []string
	BuildExit, RunEx int
}

// Boot runs the testbench with flash holding the firmware at the firmware offset.
func (s *SoCSim) Boot(firmware []byte) (*SoCRun, error) {
	r := &SoCRun{BuildExit: s.build.Code}
	log := s.build.Stdout + s.build.Stderr
	if s.build.Code == 0 {
		off, _ := Int(s.lock, "flash", "firmwareOffset")
		hexPath := filepath.Join(s.dir, "firmware.hex")
		if err := os.WriteFile(hexPath, FlashHex(firmware, int(off)), 0o644); err != nil {
			return nil, err
		}
		// -none: no waveform file; the testbench asks for one.
		run, err := runCmd(s.dir, nil, "vvp", "-N", "tb.vvp", "-none", "+firmware=firmware.hex")
		if err != nil {
			return nil, err
		}
		r.RunEx = run.Code
		log += run.Stdout + run.Stderr
		r.Ran = run.Code == 0
	}
	r.Log = log
	r.Finished = strings.Contains(log, "$finish called")
	r.UART = uartText(log)
	for _, want := range Strs(s.lock, "simulation", "uartBanner") {
		if !strings.Contains(r.UART, want) {
			r.MissingBanner = append(r.MissingBanner, want)
		}
	}
	r.BannerSeen = len(r.MissingBanner) == 0
	return r, nil
}

// FPGASimulation is step 1: the frozen RTL boots the firmware build's image.
func FPGASimulation(bundle, lockPath, key string) error {
	s, err := startFPGAStep(bundle, lockPath)
	if err != nil {
		return err
	}
	defer s.done()
	fw, err := os.ReadFile(filepath.Join(s.art, FPGAFWImage))
	if err != nil {
		return fmt.Errorf("simulation needs the firmware image: %v", err)
	}
	fwRD, err := fileRD(filepath.Join(s.art, FPGAFWImage), "")
	if err != nil {
		return err
	}
	sim, err := NewSoCSim(filepath.Join(s.art, "source.tar"), s.lock)
	if err != nil {
		return err
	}
	defer sim.Close()
	run, err := sim.Boot(fw)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.art, "simulation.log"), []byte(run.Log), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.art, "simulation-uart.txt"), []byte(run.UART), 0o644); err != nil {
		return err
	}
	logRD, err := fileRD(filepath.Join(s.art, "simulation.log"), "")
	if err != nil {
		return err
	}
	uartRD, err := fileRD(filepath.Join(s.art, "simulation-uart.txt"), "")
	if err != nil {
		return err
	}
	sim0 := O(s.lock, "simulation")
	banner := strings.Join(Strs(sim0, "uartBanner"), " / ")
	if !run.BannerSeen {
		banner = "missing: " + strings.Join(run.MissingBanner, ", ")
	}
	return s.sign(bundle, "simulation", key, []Obj{logRD, uartRD},
		Obj{"top": S(sim0, "top"), "files": get(sim0, "files"), "defines": get(sim0, "defines"), "firmware": FPGAFWImage},
		[]Obj{s.source, fwRD, envRD(bundle, FPGAFWAtt), sim.cells}, sim.tools,
		[]Obj{
			check("testbench-ran", run.Ran, fmt.Sprintf("iverilog exit %d, vvp exit %d", run.BuildExit, run.RunEx)),
			check("testbench-finished", run.Finished, "$finish called"),
			check("uart-banner", run.BannerSeen, banner),
		}, nil)
}

// FPGASynthesis is step 2: Yosys maps the RTL onto iCE40 cells.
func FPGASynthesis(bundle, lockPath, key string) error {
	s, err := startFPGAStep(bundle, lockPath)
	if err != nil {
		return err
	}
	defer s.done()
	syn := O(s.lock, "synthesis")
	top := S(syn, "top")
	netlist := top + ".json"
	script := fmt.Sprintf("read_verilog %s; %s -json %s; check -assert", strings.Join(Strs(syn, "files"), " "), S(syn, "command"), netlist)
	proc, err := runCmd(s.work, nil, "yosys", "-q", "-l", "synthesis.log", "-p", script)
	if err != nil {
		return err
	}
	ok := proc.Code == 0 && fileExists(filepath.Join(s.work, netlist))
	for _, f := range []string{netlist, "synthesis.log"} {
		if fileExists(filepath.Join(s.work, f)) {
			if err := copyFile(filepath.Join(s.work, f), filepath.Join(s.art, f)); err != nil {
				return err
			}
		}
	}
	yosys, err := tool("yosys", "-V")
	if err != nil {
		return err
	}
	var subjects, byproducts []Obj
	if ok {
		n, err := fileRD(filepath.Join(s.art, netlist), "")
		if err != nil {
			return err
		}
		subjects = append(subjects, n)
	}
	if fileExists(filepath.Join(s.art, "synthesis.log")) {
		l, err := fileRD(filepath.Join(s.art, "synthesis.log"), "")
		if err != nil {
			return err
		}
		byproducts = append(byproducts, l)
	}
	if len(subjects) == 0 {
		subjects = byproducts
	}
	return s.sign(bundle, "synthesis", key, subjects, Obj{"top": top, "script": script}, []Obj{s.source}, []Obj{yosys},
		[]Obj{check("synthesis-and-check-assert", ok, fmt.Sprintf("exit %d %s", proc.Code, strings.TrimSpace(proc.Stderr)))}, byproducts)
}

// FPGARouting is steps 3 to 5: nextpnr packs, places and routes in one run,
// with the pin constraints from the frozen source.
func FPGARouting(bundle, lockPath, key string) error {
	s, err := startFPGAStep(bundle, lockPath)
	if err != nil {
		return err
	}
	defer s.done()
	pnr := O(s.lock, "pnr")
	top := S(s.lock, "synthesis", "top")
	netRD, err := stepSubject(bundle, "synthesis")
	if err != nil {
		return err
	}
	if err := copyFile(filepath.Join(s.art, top+".json"), filepath.Join(s.work, top+".json")); err != nil {
		return err
	}
	seed, _ := Int(pnr, "seed")
	freq, _ := Int(pnr, "freqMHz")
	asc, report := top+".asc", "nextpnr-report.json"
	args := []string{
		"-q", "--seed", strconv.FormatInt(seed, 10), "--freq", strconv.FormatInt(freq, 10),
		"--" + S(pnr, "device"), "--package", S(pnr, "package"), "--pcf", S(pnr, "pcf"),
		"--json", top + ".json", "--asc", asc, "--report", report, "--log", "routing.log",
	}
	proc, err := runCmd(s.work, nil, "nextpnr-ice40", args...)
	if err != nil {
		return err
	}
	ok := proc.Code == 0 && fileExists(filepath.Join(s.work, asc))
	for _, f := range []string{asc, report, "routing.log"} {
		if fileExists(filepath.Join(s.work, f)) {
			if err := copyFile(filepath.Join(s.work, f), filepath.Join(s.art, f)); err != nil {
				return err
			}
		}
	}
	// nextpnr's own timing estimate, against the target it placed for.
	timing, fmaxDetail := false, "no report"
	if rep, err := ReadObj(filepath.Join(s.art, report)); err == nil {
		var parts []string
		timing = len(O(rep, "fmax")) > 0
		for _, clk := range sortedKeys(O(rep, "fmax")) {
			got := num(get(rep, "fmax", clk, "achieved"))
			a, _ := strconv.ParseFloat(got, 64)
			want, _ := strconv.ParseFloat(num(get(rep, "fmax", clk, "constraint")), 64)
			timing = timing && a >= want
			parts = append(parts, fmt.Sprintf("%s %s MHz (target %s)", clk, got, num(get(rep, "fmax", clk, "constraint"))))
		}
		fmaxDetail = strings.Join(parts, "; ")
	}
	nextpnr, err := tool("nextpnr-ice40", "--version")
	if err != nil {
		return err
	}
	pcf, err := fileRD(filepath.Join(s.work, S(pnr, "pcf")), S(pnr, "pcf"))
	if err != nil {
		return err
	}
	// The routed design is the subject; nextpnr's report and log ride along.
	var subjects, byproducts []Obj
	for _, f := range []string{asc, report, "routing.log"} {
		if fileExists(filepath.Join(s.art, f)) {
			r, err := fileRD(filepath.Join(s.art, f), "")
			if err != nil {
				return err
			}
			if f == asc {
				subjects = append(subjects, r)
			} else {
				byproducts = append(byproducts, r)
			}
		}
	}
	if len(subjects) == 0 {
		if len(byproducts) == 0 {
			return fmt.Errorf("routing: nextpnr wrote nothing: %s", proc.Stderr)
		}
		subjects = byproducts[:1]
	}
	return s.sign(bundle, "routing", key, subjects,
		Obj{"tool": "nextpnr-ice40", "args": anyStrings(args), "placesAndRoutes": true},
		[]Obj{s.source, netRD, envRD(bundle, AttName("synthesis")), pcf}, []Obj{nextpnr},
		[]Obj{
			check("placed-and-routed", ok, fmt.Sprintf("exit %d", proc.Code)),
			check("timing-at-target", timing, fmaxDetail),
		}, byproducts)
}

// FPGASignoff is step 6: icetime analyzes the routed design on its own
// timing model and checks it against the board's clock.
func FPGASignoff(bundle, lockPath, key string) error {
	s, err := startFPGAStep(bundle, lockPath)
	if err != nil {
		return err
	}
	defer s.done()
	so := O(s.lock, "signoff")
	top := S(s.lock, "synthesis", "top")
	ascRD, err := stepSubject(bundle, "routing")
	if err != nil {
		return err
	}
	clock, _ := Int(so, "clockMHz")
	proc, err := runCmd(s.art, nil, "icetime", "-d", S(so, "device"), "-c", strconv.FormatInt(clock, 10), "-mtr", "timing-report.txt", top+".asc")
	if err != nil {
		return err
	}
	out := proc.Stdout + proc.Stderr
	estimate := ""
	if m := regexp.MustCompile(`Timing estimate: ([^\n]+)`).FindStringSubmatch(out); m != nil {
		estimate = m[1]
	}
	met := proc.Code == 0 && regexp.MustCompile(`clock constraint: PASSED`).MatchString(out)
	icetime, err := fpgaTool("icetime")
	if err != nil {
		return err
	}
	deps := []Obj{ascRD, envRD(bundle, AttName("routing"))}
	if db := icestormChipDB(S(so, "device")); db != "" {
		d, err := sha256File(db)
		if err != nil {
			return err
		}
		deps = append(deps, rd("icestorm/"+filepath.Base(db), d))
	}
	var subjects []Obj
	if fileExists(filepath.Join(s.art, "timing-report.txt")) {
		r, err := fileRD(filepath.Join(s.art, "timing-report.txt"), "")
		if err != nil {
			return err
		}
		subjects = append(subjects, r)
	}
	if len(subjects) == 0 {
		return fmt.Errorf("signoff: icetime wrote no report: %s", out)
	}
	return s.sign(bundle, "signoff", key, subjects, Obj{"device": S(so, "device"), "clockMHz": clock}, deps, []Obj{icetime},
		[]Obj{check("timing-met", met, fmt.Sprintf("%s against %d MHz", estimate, clock))}, nil)
}

// normalizedASC drops what icepack does not keep (comments, net names and
// blank lines) and the all-zero block RAM sections iceunpack adds for unused RAM.
func normalizedASC(data []byte) []byte {
	var out, section []string
	zero := true
	flush := func() {
		if len(section) > 0 && !(strings.HasPrefix(section[0], ".ram_data") && zero) {
			out = append(out, section...)
		}
		section, zero = nil, true
	}
	for _, line := range splitLines(string(data)) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, ".sym ") {
			continue
		}
		if strings.HasPrefix(line, ".") {
			flush()
			if strings.HasPrefix(line, ".comment") {
				continue
			}
		} else if strings.Trim(line, "0") != "" {
			zero = false
		}
		section = append(section, line)
	}
	flush()
	return []byte(strings.Join(out, "\n"))
}

// FPGABitstream is step 7: icepack writes the bitstream, and unpacking it
// again must give the routed design back.
func FPGABitstream(bundle, lockPath, key string) error {
	s, err := startFPGAStep(bundle, lockPath)
	if err != nil {
		return err
	}
	defer s.done()
	top := S(s.lock, "synthesis", "top")
	ascRD, err := stepSubject(bundle, "routing")
	if err != nil {
		return err
	}
	bin := S(s.lock, "release", "artifact")
	pack, err := runCmd(s.art, nil, "icepack", top+".asc", bin)
	if err != nil {
		return err
	}
	same := false
	if pack.Code == 0 {
		unpack, err := runCmd(s.work, nil, "iceunpack", filepath.Join(s.art, bin), "unpacked.asc")
		if err != nil {
			return err
		}
		if unpack.Code == 0 {
			a, err1 := os.ReadFile(filepath.Join(s.art, top+".asc"))
			b, err2 := os.ReadFile(filepath.Join(s.work, "unpacked.asc"))
			same = err1 == nil && err2 == nil && bytes.Equal(normalizedASC(a), normalizedASC(b))
		}
	}
	var tools []Obj
	for _, t := range []string{"icepack", "iceunpack"} {
		o, err := fpgaTool(t)
		if err != nil {
			return err
		}
		tools = append(tools, o)
	}
	binRD, err := fileRD(filepath.Join(s.art, bin), "")
	if err != nil {
		return err
	}
	return s.sign(bundle, "bitstream", key, []Obj{binRD}, Obj{"input": top + ".asc", "output": bin},
		[]Obj{ascRD, envRD(bundle, AttName("routing"))}, tools,
		[]Obj{
			check("bitstream-written", pack.Code == 0, fmt.Sprintf("icepack exit %d", pack.Code)),
			check("bitstream-matches-routed-design", same, "iceunpack gives back the routed design, apart from comments, net names and unused RAM"),
		}, nil)
}

// Firmware: PicoSoC's firmware, built with GCC for RISC-V

// FPGAFirmware builds PicoSoC's firmware from the pinned sources the way
// picosoc/Makefile does for the iCEBreaker, and signs its provenance and SBOM.
// With isolate the compiler runs in the sandbox, with no network (SLSA Build L3).
func FPGAFirmware(bundle, lockPath, key, cache string, isolate bool) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	fw := O(lock, "firmware")
	src := O(lock, "source")
	sub := Obj{"source": Obj{"repo": get(src, "repo"), "commit": get(src, "commit"), "rawUrl": get(src, "rawUrl"), "files": get(fw, "files")}}
	got, err := fetchSources(sub, cache)
	if err != nil {
		return err
	}
	var deps []Obj
	for _, name := range sortedKeys(O(fw, "files")) {
		if got[name] != S(fw, "files", name) {
			return fmt.Errorf("firmware: %s is %s, not the pinned %s", name, got[name], S(fw, "files", name))
		}
		d := rd(name, got[name])
		d["uri"] = fmt.Sprintf("git+%s@%s#%s", S(src, "repo"), S(src, "commit"), name)
		deps = append(deps, d)
	}
	prefix, err := riscvPrefix()
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "hslsa-fw-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	for _, name := range sortedKeys(O(fw, "files")) {
		if err := copyFile(filepath.Join(cache, name), filepath.Join(work, filepath.Base(name))); err != nil {
			return err
		}
	}
	var sb *Sandbox
	if isolate {
		if sb, err = NewSandbox(); err != nil {
			return err
		}
	}
	steps := [][]string{
		{prefix + "cpp", "-P", "-DICEBREAKER", "-o", "icebreaker_sections.lds", "sections.lds"},
		append(append([]string{prefix + "gcc"}, Strs(fw, "cflags")...), "-o", "firmware.elf", "start.s", "firmware.c"),
		{prefix + "objcopy", "-O", "binary", "firmware.elf", FPGAFWImage},
	}
	buildLog, err := fwBuild(sb, work, nil, steps)
	if err != nil {
		return fmt.Errorf("firmware: %w", err)
	}
	art := filepath.Join(bundle, "artifacts")
	if err := os.MkdirAll(art, 0o755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(work, FPGAFWImage), filepath.Join(art, FPGAFWImage)); err != nil {
		return err
	}
	image, err := imageRD(filepath.Join(art, FPGAFWImage))
	if err != nil {
		return err
	}
	var tools []Obj
	for _, t := range []string{"gcc", "cpp", "objcopy"} {
		o, err := toolDep(prefix+t, "--version")
		if err != nil {
			return err
		}
		tools = append(tools, o)
	}
	sbom := Obj{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata": Obj{
			"component": Obj{
				"type": "firmware", "bom-ref": FPGAFWImage, "name": S(fw, "name"), "version": S(fw, "version"),
				"hashes": []Obj{{"alg": "SHA-256", "content": S(image, "digest", "sha256")}},
			},
			"tools": Obj{"components": []Obj{{"type": "application", "name": "hslsa", "version": "0.1"}}},
		},
		"components": []Obj{},
	}
	var comps []Obj
	for _, d := range deps {
		comps = append(comps, Obj{
			"type": "file", "bom-ref": S(d, "name"), "name": S(d, "name"),
			"hashes":             []Obj{{"alg": "SHA-256", "content": S(d, "digest", "sha256")}},
			"externalReferences": []Obj{{"type": "vcs", "url": S(d, "uri")}},
			"licenses":           []Obj{{"license": Obj{"id": "ISC"}}},
		})
	}
	sbom["components"] = comps
	if err := WriteJSON(filepath.Join(art, FPGAFWSBOM), sbom); err != nil {
		return err
	}
	sbomRD, err := fileRD(filepath.Join(art, FPGAFWSBOM), "")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(art, "firmware-build.log"), []byte(buildLog), 0o644); err != nil {
		return err
	}
	logRD, err := fileRD(filepath.Join(art, "firmware-build.log"), "")
	if err != nil {
		return err
	}
	run := builder()
	O(run, "metadata")["startedOn"] = started
	O(run, "metadata")["finishedOn"] = Now()
	run["byproducts"] = []Obj{sbomRD, logRD}
	pred := Obj{
		"buildDefinition": Obj{
			"buildType": FPGAFWBuildType,
			"externalParameters": Obj{
				"target": FPGAFWImage, "version": get(fw, "version"), "svn": get(fw, "svn"),
				"cflags": get(fw, "cflags"), "linkerScript": "picosoc/sections.lds with -DICEBREAKER",
			},
			"internalParameters":   isolationParams(sb, nil),
			"resolvedDependencies": append(deps, tools...),
		},
		"runDetails": run,
	}
	stmt, err := statement([]Obj{image}, SLSAProvenance, pred)
	if err != nil {
		return err
	}
	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", FPGAFWAtt)); err != nil {
		return err
	}
	fmt.Printf("firmware: %s sha256:%s, %d bytes\n", FPGAFWImage, S(image, "digest", "sha256")[:16], fileSize(filepath.Join(art, FPGAFWImage)))
	return nil
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// The board's flash image

// BoardRefValues are the reference values for the images a board's root of
// trust verifies and measures: one per manifest image, at layer 2, in order.
func BoardRefValues(images []Obj, vendor, product string, svn int64) []RefValue {
	var refs []RefValue
	s := uint64(svn)
	layer := uint64(2)
	for i, img := range images {
		idx := uint64(i + 1)
		refs = append(refs, RefValue{
			Env:     DiceEnv{Type: S(img, "role"), Vendor: vendor, Model: product, Layer: &layer, Index: &idx},
			Digests: []FWID{{SHA256OID, S(img, "sha256")}},
			SVN:     &s,
		})
	}
	return refs
}

// FPGAImage lays out the board's flash: the released bitstream, the firmware
// and a boot manifest naming both, signed by the code signer for the root of
// trust. The firmware platform signs the image's provenance and the CoRIM
// with the reference values the root of trust will report.
func FPGAImage(bundle, lockPath, scenarioPath, key, codeSigner string) error {
	started := Now()
	lock, err := ReadObj(lockPath)
	if err != nil {
		return err
	}
	sc, err := ReadObj(scenarioPath)
	if err != nil {
		return err
	}
	art := filepath.Join(bundle, "artifacts")
	flash := O(lock, "flash")
	bitOff, _ := Int(flash, "bitstreamOffset")
	manOff, _ := Int(flash, "manifestOffset")
	manSize, _ := Int(flash, "manifestSize")
	fwOff, _ := Int(flash, "firmwareOffset")
	bitName := S(lock, "release", "artifact")
	bit, err := os.ReadFile(filepath.Join(art, bitName))
	if err != nil {
		return err
	}
	fw, err := os.ReadFile(filepath.Join(art, FPGAFWImage))
	if err != nil {
		return err
	}
	if bitOff+int64(len(bit)) > manOff || fwOff < manOff+manSize {
		return fmt.Errorf("flash layout: the bitstream (%d bytes) overlaps the manifest", len(bit))
	}
	svn, _ := Int(lock, "firmware", "svn")
	vendor := S(sc, "product", "manufacturer", "name")
	product := S(sc, "product", "partNumber")
	images := []Obj{
		{"name": bitName, "role": RoleBitstream, "offset": bitOff, "length": len(bit), "sha256": sha256Bytes(bit)},
		{"name": FPGAFWImage, "role": RoleSoCFW, "offset": fwOff, "length": len(fw), "sha256": sha256Bytes(fw)},
	}
	payload := compactJSON(Obj{"format": BootManifestFormat, "vendor": vendor, "product": product, "svn": svn, "images": images})
	cs, err := LoadSigner(codeSigner)
	if err != nil {
		return err
	}
	blob, err := signBlob(payload, cs)
	if err != nil {
		return err
	}
	if err := WriteJSON(filepath.Join(art, BootManifest), blob); err != nil {
		return err
	}
	manifestBytes := compactJSON(blob)
	if int64(len(manifestBytes))+4 > manSize {
		return fmt.Errorf("boot manifest is %d bytes, more than its %d byte slot", len(manifestBytes), manSize)
	}
	// Erased NOR flash reads 0xFF.
	img := bytes.Repeat([]byte{0xff}, int(fwOff)+len(fw))
	copy(img[bitOff:], bit)
	binary.BigEndian.PutUint32(img[manOff:], uint32(len(manifestBytes)))
	copy(img[manOff+4:], manifestBytes)
	copy(img[fwOff:], fw)
	if err := os.WriteFile(filepath.Join(art, FlashImage), img, 0o644); err != nil {
		return err
	}

	signer, err := LoadSigner(key)
	if err != nil {
		return err
	}
	var imgObjs []Obj
	for _, i := range images {
		imgObjs = append(imgObjs, i)
	}
	refs := BoardRefValues(imgObjs, vendor, product, svn)
	if err := WriteCoRIM(filepath.Join(art, BoardCoRIMFile), product+"-flash@sha256:"+sha256Bytes(img), vendor+" firmware build platform",
		"firmware-platform", refs, signer); err != nil {
		return err
	}
	var subjects, byproducts []Obj
	for _, f := range []string{FlashImage, BootManifest} {
		r, err := fileRD(filepath.Join(art, f), "")
		if err != nil {
			return err
		}
		subjects = append(subjects, r)
	}
	corimRD, err := fileRD(filepath.Join(art, BoardCoRIMFile), "")
	if err != nil {
		return err
	}
	byproducts = append(byproducts, corimRD)
	bitRD, err := fileRD(filepath.Join(art, bitName), "")
	if err != nil {
		return err
	}
	fwRD, err := fileRD(filepath.Join(art, FPGAFWImage), "")
	if err != nil {
		return err
	}
	run := builder()
	O(run, "metadata")["startedOn"] = started
	O(run, "metadata")["finishedOn"] = Now()
	run["byproducts"] = byproducts
	pred := Obj{
		"buildDefinition": Obj{
			"buildType": FlashBuildType,
			"externalParameters": Obj{
				"product": product, "svn": svn,
				"layout":     Obj{"bitstreamOffset": bitOff, "manifestOffset": manOff, "firmwareOffset": fwOff},
				"codeSigner": Obj{"keyHash": sha256OfPEM(cs.Key.PEM)},
			},
			"resolvedDependencies": []Obj{envRD(bundle, AttName("release")), bitRD, envRD(bundle, FPGAFWAtt), fwRD},
		},
		"runDetails": run,
	}
	stmt, err := statement(subjects, SLSAProvenance, pred)
	if err != nil {
		return err
	}
	if _, err := Sign(stmt, signer, filepath.Join(bundle, "att", FlashAtt)); err != nil {
		return err
	}
	fmt.Printf("flash image: %s, %d bytes; boot manifest signed by the code signer; %d reference values\n",
		FlashImage, len(img), len(refs))
	return nil
}

// sha256OfPEM is the sha256 of a PEM public key's SPKI DER, or "".
func sha256OfPEM(text string) string {
	k, err := PublicKeyFromPEM(text)
	if err != nil {
		return ""
	}
	d, err := spkiDigest(k.Public)
	if err != nil {
		return ""
	}
	return d
}

// readBootManifest reads the signed manifest from a flash image, as the root of trust does.
func readBootManifest(flash []byte, offset int64) (Obj, error) {
	if offset < 0 || offset+4 > int64(len(flash)) {
		return nil, fmt.Errorf("no boot manifest")
	}
	n := int64(binary.BigEndian.Uint32(flash[offset:]))
	if n == 0 || offset+4+n > int64(len(flash)) {
		return nil, fmt.Errorf("no boot manifest")
	}
	return decodeObj(flash[offset+4 : offset+4+n])
}

// decodeObj decodes JSON that must be an object.
func decodeObj(data []byte) (Obj, error) {
	v, err := decodeJSON(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not a JSON object")
	}
	return m, nil
}
