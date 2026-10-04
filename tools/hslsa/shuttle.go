package hslsa

// The virtual shuttle (roadmap phase 2, items 2 and 3, until a real
// open-PDK shuttle runs): it "fabricates" the released gate-level netlist,
// and every manufacturing fact it reports comes from simulating that
// netlist, not from a scenario file.
//
//   - Wafer fab: the fab checks that the netlist it builds is the released
//     one (the stand-in for the mask-vs-GDS XOR), then puts it on every die
//     of a wafer grid. Each die gets a random number of manufacturing
//     defects, each a stuck-at fault on one net of the netlist, drawn from a
//     seeded generator.
//   - Wafer sort: a short probe program runs on every die in Icarus Verilog,
//     with that die's faults forced on its nets. A die passes when it gives
//     the signature the same program gives on the RTL. The tester burns a
//     unique die id into each passing die's fuses.
//   - Packaging: passing dies become units with serials; a few units get a
//     bond defect (a stuck pin on the memory bus).
//   - Final test: a longer program runs on each unit's die with its faults
//     and its pin defect. It reads the die id back from the fuses, so the
//     tester confirms each serial holds the die the genealogy says, and its
//     signature must match the RTL's.
//
// The results come out as the files a fab, a sort house, an OSAT and a test
// house export (MES lot histories, a unit genealogy, STDF V4 and SEMI E142
// wafer maps), with an adapter configuration that marks them simulated, so
// the MES and STDF adapter (adapt.go) turns them into the lot's records like
// any supplier's exports. A report beside them holds what only a simulator
// knows: which dies were defective and which defects no test caught.
//
// Everything is deterministic: the same release, configuration and seed
// give the same exports byte for byte, so anyone can run the shuttle again
// and compare.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ShuttleID names the virtual shuttle in the simulated block of every record made from its exports.
const ShuttleID = NS + "/tools/hslsa/sim/shuttle@v0.1"

// Addresses the test programs use: RAM from 0, the tester's output port,
// and the die's fuse bank.
const (
	shuttleRAMWords = 4096
	shuttleOut      = 0x10000000 // write: the tester records the word
	shuttleDone     = 0x10000004 // write: the program is finished
	shuttleFuse     = 0x20000000 // read: fuse word 0, the die id
	shuttleCycles   = 200000     // the most cycles any run may take
)

// Bins the testers use, in STDF and in the wafer maps.
const (
	binPass    = 1
	binFunc    = 5 // wrong signature
	binHang    = 6 // no result: trapped or never finished
	binWrongID = 8 // final test read another die's id from the fuses
)

var binNames = map[int]string{binPass: "PASS", binFunc: "FUNCTIONAL", binHang: "HANG", binWrongID: "DIE-ID"}

// shuttleProbe is wafer sort's program: an ALU, load/store and branch loop,
// which leaves the shifter and byte lanes mostly untested, as a short probe
// program does. It writes one word, its signature.
func shuttleProbe() ([]uint32, error) {
	var a rvAsm
	a.Li(10, shuttleOut)
	a.Li(31, 0x5eed0001)
	a.Li(2, 0x9e3779b9)
	a.Li(3, 0x7f4a7c15)
	a.I("addi", 5, 0, 16)
	a.Label("loop")
	a.R("add", 4, 2, 3)
	a.R("xor", 31, 31, 4)
	a.R("sub", 2, 4, 31)
	a.R("or", 6, 2, 3)
	a.R("and", 7, 6, 31)
	a.R("add", 31, 31, 7)
	a.I("addi", 3, 3, 0x123)
	a.Store("sw", 31, 0, 0x200)
	a.Load("lw", 8, 0, 0x200)
	a.R("add", 31, 31, 8)
	a.I("addi", 5, 5, -1)
	a.Branch("bne", 5, 0, "loop")
	a.Store("sw", 31, 10, 0)
	a.Store("sw", 0, 10, 4)
	a.Label("halt")
	a.Jal(0, "halt")
	return a.Words()
}

// shuttleFinal is final test's program: it reads the die id from the fuses
// and writes it, then runs every RV32I instruction class (shifts, compares,
// byte and halfword loads and stores, calls and all branch kinds) and
// writes its signature.
func shuttleFinal() ([]uint32, error) {
	var a rvAsm
	a.Li(10, shuttleOut)
	a.Li(11, shuttleFuse)
	a.Load("lw", 12, 11, 0)
	a.Store("sw", 12, 10, 0)
	a.Li(31, 0x0badc0de)
	a.Li(2, 0x12345678)
	a.Li(3, 0x8badf00d)
	a.I("addi", 5, 0, 24)
	a.Label("loop")
	a.R("sll", 4, 2, 5)
	a.R("srl", 6, 3, 5)
	a.R("sra", 7, 3, 5)
	a.R("xor", 31, 31, 4)
	a.R("add", 31, 31, 6)
	a.R("xor", 31, 31, 7)
	a.R("slt", 8, 2, 3)
	a.R("sltu", 9, 2, 3)
	a.R("add", 31, 31, 8)
	a.I("slli", 9, 9, 3)
	a.R("add", 31, 31, 9)
	a.I("slli", 13, 31, 7)
	a.I("srli", 14, 31, 25)
	a.R("or", 31, 13, 14)
	a.Store("sw", 3, 0, 0x300)
	a.Store("sb", 31, 0, 0x300)
	a.Store("sh", 2, 0, 0x302)
	a.Load("lw", 15, 0, 0x300)
	a.R("add", 31, 31, 15)
	a.Load("lb", 15, 0, 0x301)
	a.R("add", 31, 31, 15)
	a.Load("lhu", 15, 0, 0x302)
	a.R("xor", 31, 31, 15)
	a.Load("lbu", 15, 0, 0x303)
	a.R("add", 31, 31, 15)
	a.Load("lh", 15, 0, 0x300)
	a.R("xor", 31, 31, 15)
	a.Jal(1, "mix")
	a.Branch("blt", 2, 3, "skip1")
	a.I("addi", 31, 31, 1)
	a.Label("skip1")
	a.Branch("bgeu", 2, 3, "skip2")
	a.I("addi", 31, 31, 3)
	a.Label("skip2")
	a.Branch("bge", 3, 2, "skip3")
	a.I("xori", 31, 31, 0x55)
	a.Label("skip3")
	a.Branch("bltu", 3, 2, "skip4")
	a.I("ori", 31, 31, 0x200)
	a.Label("skip4")
	a.R("add", 2, 2, 31)
	a.I("xori", 3, 3, -1)
	a.R("sub", 3, 3, 2)
	a.I("addi", 5, 5, -1)
	a.Branch("bne", 5, 0, "loop")
	a.Auipc(16, 0)
	a.R("add", 31, 31, 16)
	a.Store("sw", 31, 10, 0)
	a.Store("sw", 0, 10, 4)
	a.Label("halt")
	a.Jal(0, "halt")
	a.Label("mix")
	a.I("slti", 17, 31, 0)
	a.I("sltiu", 18, 31, 100)
	a.I("andi", 19, 31, 0x7f)
	a.I("ori", 19, 19, 0x100)
	a.R("add", 31, 31, 17)
	a.R("add", 31, 31, 18)
	a.R("xor", 31, 31, 19)
	a.Jalr(0, 1, 0)
	return a.Words()
}

// shuttleBench is the Verilog testbench both testers use: memory, the output
// port and the fuse bank around the die, the die's faults forced on its
// nets, and a pin defect on the memory bus. faults lists the nets a fault
// number forces; fault 2i+1 holds net i at 0 and 2i+2 holds it at 1.
func shuttleBench(top string, faults []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "`timescale 1ns/1ps\nmodule shuttle_tb;\n")
	b.WriteString(`  reg clk = 0, resetn = 0;
  always #5 clk = ~clk;
  wire trap, mem_valid, mem_instr;
  reg mem_ready = 0;
  wire [31:0] mem_addr, mem_wdata;
  wire [3:0] mem_wstrb;
  reg [31:0] mem_rdata = 0;
  reg [31:0] pin_sa0 = 0, pin_sa1 = 0, fuse = 0;
  wire [31:0] rdata_pin = (mem_rdata & ~pin_sa0) | pin_sa1;
  reg [31:0] mem [0:4095];
  reg [8*512-1:0] prog;
  integer cycles = 0, maxcycles = 200000, f, i;
`)
	fmt.Fprintf(&b, "  %s dut (.clk(clk), .resetn(resetn), .trap(trap), .mem_valid(mem_valid), .mem_instr(mem_instr),\n", top)
	b.WriteString(`    .mem_ready(mem_ready), .mem_addr(mem_addr), .mem_wdata(mem_wdata), .mem_wstrb(mem_wstrb), .mem_rdata(rdata_pin),
    .pcpi_wr(1'b0), .pcpi_rd(32'b0), .pcpi_wait(1'b0), .pcpi_ready(1'b0), .irq(32'b0));
  task inject(input integer id);
    case (id)
`)
	for i, net := range faults {
		fmt.Fprintf(&b, "      %d: force dut.%s = 1'b0;\n      %d: force dut.%s = 1'b1;\n", 2*i+1, net, 2*i+2, net)
	}
	b.WriteString(`      default: ;
    endcase
  endtask
  initial begin
    for (i = 0; i < 4096; i = i + 1) mem[i] = 0;
    if (!$value$plusargs("prog=%s", prog)) begin $display("NOPROG"); $finish; end
    $readmemh(prog, mem);
    if ($value$plusargs("fuse=%h", fuse)) ;
    if ($value$plusargs("maxcycles=%d", maxcycles)) ;
    if ($value$plusargs("sa0=%h", pin_sa0)) ;
    if ($value$plusargs("sa1=%h", pin_sa1)) ;
    if ($value$plusargs("f0=%d", f)) inject(f);
    if ($value$plusargs("f1=%d", f)) inject(f);
    if ($value$plusargs("f2=%d", f)) inject(f);
    if ($value$plusargs("f3=%d", f)) inject(f);
    repeat (10) @(posedge clk);
    resetn <= 1;
  end
  always @(posedge clk) begin
    cycles <= cycles + 1;
    if (cycles > maxcycles) begin $display("HANG %0d", cycles); $finish; end
    if (resetn && trap) begin $display("TRAP %0d", cycles); $finish; end
    mem_ready <= 0;
    if (mem_valid && !mem_ready) begin
      mem_ready <= 1;
      mem_rdata <= 0;
      if (mem_addr < 4*4096) begin
        if (mem_wstrb == 0) mem_rdata <= mem[mem_addr >> 2];
        if (mem_wstrb[0]) mem[mem_addr >> 2][7:0] <= mem_wdata[7:0];
        if (mem_wstrb[1]) mem[mem_addr >> 2][15:8] <= mem_wdata[15:8];
        if (mem_wstrb[2]) mem[mem_addr >> 2][23:16] <= mem_wdata[23:16];
        if (mem_wstrb[3]) mem[mem_addr >> 2][31:24] <= mem_wdata[31:24];
      end else if (mem_addr == 32'h20000000 && mem_wstrb == 0) begin
        mem_rdata <= fuse;
      end else if (mem_addr == 32'h10000000 && mem_wstrb != 0) begin
        $display("OUT %08x", mem_wdata);
      end else if (mem_addr == 32'h10000004 && mem_wstrb != 0) begin
        $display("DONE %0d", cycles);
        $finish;
      end
    end
  end
endmodule
`)
	return b.String()
}

// shuttleRun is what one run of a test program gave.
type shuttleRun struct {
	Out    []string // the words written to the output port, as hex
	Done   bool     // the program finished
	Cycles int
}

// shuttleSim is one compiled testbench and the programs it runs.
type shuttleSim struct {
	dir, vvp string
	progs    map[string]string // program name -> hex file
}

func newShuttleSim(dir, top string, sources []string, faults []string, progs map[string][]uint32) (*shuttleSim, error) {
	s := &shuttleSim{dir: dir, vvp: filepath.Join(dir, "tb.vvp"), progs: map[string]string{}}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	bench := filepath.Join(dir, "shuttle_tb.v")
	if err := os.WriteFile(bench, []byte(shuttleBench(top, faults)), 0o644); err != nil {
		return nil, err
	}
	for name, words := range progs {
		var hex strings.Builder
		for _, w := range words {
			fmt.Fprintf(&hex, "%08x\n", w)
		}
		p := filepath.Join(dir, name+".hex")
		if err := os.WriteFile(p, []byte(hex.String()), 0o644); err != nil {
			return nil, err
		}
		s.progs[name] = p
	}
	args := append([]string{"-g2005", "-o", s.vvp, "-s", "shuttle_tb", bench}, sources...)
	proc, err := runCmd(dir, nil, "iverilog", args...)
	if err != nil {
		return nil, err
	}
	if proc.Code != 0 {
		return nil, fmt.Errorf("iverilog could not build the shuttle testbench: %s", firstLines(proc.Stdout+proc.Stderr, 8))
	}
	return s, nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], "...")
	}
	return strings.Join(lines, "\n")
}

// run runs one program on one die: its faults (fault numbers as in
// shuttleBench), its fuse word and its pin defect.
func (s *shuttleSim) run(prog string, faults []int, fuse uint32, sa0, sa1 uint32) (shuttleRun, error) {
	return s.runFor(prog, shuttleCycles, faults, fuse, sa0, sa1)
}

// runFor is run with a cycle limit: a die still running after it has hung.
func (s *shuttleSim) runFor(prog string, limit int, faults []int, fuse uint32, sa0, sa1 uint32) (shuttleRun, error) {
	if len(faults) > 4 {
		return shuttleRun{}, fmt.Errorf("a die carries at most 4 faults in this testbench")
	}
	args := []string{"-n", s.vvp, "+prog=" + s.progs[prog], fmt.Sprintf("+fuse=%08x", fuse),
		fmt.Sprintf("+sa0=%08x", sa0), fmt.Sprintf("+sa1=%08x", sa1), fmt.Sprintf("+maxcycles=%d", limit)}
	for i, f := range faults {
		args = append(args, fmt.Sprintf("+f%d=%d", i, f))
	}
	proc, err := runCmd(s.dir, nil, "vvp", args...)
	if err != nil {
		return shuttleRun{}, err
	}
	var r shuttleRun
	for _, line := range strings.Split(proc.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "OUT":
			r.Out = append(r.Out, f[1])
		case "DONE":
			r.Done = true
			r.Cycles, _ = strconv.Atoi(f[1])
		case "HANG", "TRAP":
			r.Cycles, _ = strconv.Atoi(f[1])
		case "NOPROG":
			return r, fmt.Errorf("the testbench got no program")
		}
	}
	return r, nil
}

// shuttleDie is one die of the lot, with what the simulator knows about it.
type shuttleDie struct {
	Wafer      string
	X, Y       int
	Faults     []int  // fault numbers, as in shuttleBench
	ID         uint32 // the die id sort burns into the fuses
	SortBin    int
	SortCycles int
}

// shuttleUnit is one packaged die.
type shuttleUnit struct {
	Serial   string
	Die      *shuttleDie // the die in the package
	Labeled  *shuttleDie // the die the OSAT's genealogy says is in it
	SA0, SA1 uint32      // the pin defect, as stuck bits on the memory bus
	Bin      int
	Cycles   int
	ReadID   string
}

// shuttleRNG is the seeded generator for the lot's defects.
func shuttleRNG(seed string) *rand.Rand {
	h := sha256.Sum256([]byte(seed))
	return rand.New(rand.NewPCG(binary.BigEndian.Uint64(h[:8]), binary.BigEndian.Uint64(h[8:16])))
}

// poisson draws a defect count with mean lambda.
func poisson(r *rand.Rand, lambda float64) int {
	l, k, p := math.Exp(-lambda), 0, 1.0
	for {
		p *= r.Float64()
		if p <= l {
			return k
		}
		k++
	}
}

// netlistNets lists the netlist's single-bit internal wires, the nets a
// defect can hold stuck, in the order the netlist declares them.
func netlistNets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s*wire (_\d+_);`)
	var out []string
	for _, m := range re.FindAllSubmatch(data, -1) {
		out = append(out, string(m[1]))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no internal nets found; is it a flattened Yosys netlist?", path)
	}
	return out, nil
}

// dieID is the id sort burns into a die's fuses: a byte of the lot, the
// wafer's number and the die's position, so no two dies of a lot share one.
func dieID(lot string, wafer, x, y int) uint32 {
	h := sha256.Sum256([]byte(lot))
	return uint32(h[0])<<24 | uint32(wafer+1)<<16 | uint32(x)<<8 | uint32(y)
}

// ShuttleOptions are the inputs of one shuttle run.
type ShuttleOptions struct {
	Bundle string // the design bundle with the release
	Lock   string // the design's inputs lock (for the RTL top and files)
	Config string // the shuttle configuration
	Out    string // where the exports, the adapter configuration and the report go
}

// Shuttle runs the virtual shuttle.
func Shuttle(opt ShuttleOptions) error {
	cfg, err := ReadObj(opt.Config)
	if err != nil {
		return err
	}
	lock, err := ReadObj(opt.Lock)
	if err != nil {
		return err
	}
	cfgDigest, err := sha256File(opt.Config)
	if err != nil {
		return err
	}
	fab, srt, pkg, ft := O(cfg, "fab"), O(cfg, "sort"), O(cfg, "packaging"), O(cfg, "finalTest")
	for k, b := range map[string]Obj{"fab": fab, "sort": srt, "packaging": pkg, "finalTest": ft} {
		if O(b, "site") == nil || S(b, "facility") == "" {
			return fmt.Errorf("%s: %s needs a site and a facility", opt.Config, k)
		}
	}
	seed := S(cfg, "seed")
	start, err := time.Parse(time.RFC3339, S(cfg, "start"))
	if seed == "" || err != nil {
		return fmt.Errorf("%s: needs a seed and a start time (RFC 3339)", opt.Config)
	}
	lotID, asmLot := S(fab, "lotId"), S(pkg, "assemblyLot")
	nWafers, _ := Int(fab, "wafers")
	grid := A(fab, "grid")
	if lotID == "" || asmLot == "" || nWafers < 1 || nWafers > 25 || len(grid) != 2 {
		return fmt.Errorf("%s: fab needs lotId, wafers (1 to 25) and grid [columns, rows]; packaging needs assemblyLot", opt.Config)
	}
	gx, _ := Int(grid[0])
	gy, _ := Int(grid[1])
	if gx < 1 || gy < 1 || gx > 64 || gy > 64 {
		return fmt.Errorf("%s: fab.grid must be 1 to 64 dies each way", opt.Config)
	}
	lambda, okL := rate(fab, "defectsPerDie")
	bondRate, okB := rate(pkg, "bondDefectRate")
	if !okL || !okB || lambda > 4 || bondRate > 1 {
		return fmt.Errorf("%s: fab.defectsPerDie (0 to 4) and packaging.bondDefectRate (0 to 1) must be numbers", opt.Config)
	}
	maxUnits, _ := Int(pkg, "units")

	// The fab builds the released design, and checks first that the
	// netlist it was handed is the one the tapeout authority released.
	release, err := DecodeEnvelope(filepath.Join(opt.Bundle, "att", AttName("release")))
	if err != nil {
		return err
	}
	final := firstSubject(release)
	bundle, err := filepath.Abs(opt.Bundle)
	if err != nil {
		return err
	}
	netlist := filepath.Join(bundle, "artifacts", S(final, "name"))
	got, err := sha256File(netlist)
	if err != nil {
		return err
	}
	if got != S(final, "digest", "sha256") {
		return fmt.Errorf("%s is not the released design: sha256 %s, the release names %s", S(final, "name"), got, S(final, "digest", "sha256"))
	}
	if top := S(lock, "synthesis", "top"); top == "" || !strings.HasPrefix(S(final, "name"), top+".") {
		return fmt.Errorf("the release names %s, not a netlist of %s", S(final, "name"), S(lock, "synthesis", "top"))
	}
	for _, t := range []string{"iverilog", "vvp"} {
		if _, err := tool(t, "-V"); err != nil {
			return err
		}
	}
	work, err := os.MkdirTemp("", "hslsa-shuttle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	src := filepath.Join(work, "src")
	if err := unpack(filepath.Join(bundle, "artifacts", "source.tar"), src); err != nil {
		return err
	}
	var rtl []string
	for _, f := range Strs(lock, "synthesis", "files") {
		rtl = append(rtl, filepath.Join(src, f))
	}
	probe, err := shuttleProbe()
	if err != nil {
		return err
	}
	finalProg, err := shuttleFinal()
	if err != nil {
		return err
	}
	progs := map[string][]uint32{"probe": probe, "final": finalProg}

	// The lot's defects, drawn before anything runs.
	nets, err := netlistNets(netlist)
	if err != nil {
		return err
	}
	rng := shuttleRNG(seed)
	var wafers []string
	var dies []*shuttleDie
	sites := map[int]bool{}
	for w := 0; w < int(nWafers); w++ {
		wafers = append(wafers, fmt.Sprintf("W%02d", w+1))
		for y := 0; y < int(gy); y++ {
			for x := 0; x < int(gx); x++ {
				d := &shuttleDie{Wafer: wafers[w], X: x, Y: y, ID: dieID(lotID, w, x, y)}
				n := poisson(rng, lambda)
				for i := 0; i < n && i < 4; i++ {
					net := rng.IntN(len(nets))
					d.Faults = append(d.Faults, 2*net+1+rng.IntN(2))
					sites[net] = true
				}
				dies = append(dies, d)
			}
		}
	}
	// The testbench forces only the nets some die needs; fault numbers are
	// renumbered to that list.
	var used []int
	for n := range sites {
		used = append(used, n)
	}
	sort.Ints(used)
	index := map[int]int{}
	var faultNets []string
	for i, n := range used {
		index[n] = i
		faultNets = append(faultNets, nets[n])
	}
	benchFault := func(f int) int { net, v := (f-1)/2, (f-1)%2; return 2*index[net] + 1 + v }

	fmt.Printf("shuttle: %s, %d wafers of %dx%d dies, %d defects on %d of %d nets\n",
		lotID, nWafers, gx, gy, countFaults(dies), len(used), len(nets))
	gate, err := newShuttleSim(filepath.Join(work, "gate"), S(lock, "synthesis", "top"), []string{netlist}, faultNets, progs)
	if err != nil {
		return err
	}
	golden, err := newShuttleSim(filepath.Join(work, "rtl"), S(lock, "synthesis", "top"), rtl, nil, progs)
	if err != nil {
		return err
	}
	// The expected results come from the RTL, and the fault-free netlist
	// must give the same, or the testers would be comparing against nothing.
	want := map[string]shuttleRun{}
	for _, p := range []string{"probe", "final"} {
		r, err := golden.run(p, nil, 0x5a5a5a5a, 0, 0)
		if err != nil {
			return err
		}
		g, err := gate.run(p, nil, 0x5a5a5a5a, 0, 0)
		if err != nil {
			return err
		}
		if !r.Done || !g.Done || strings.Join(r.Out, " ") != strings.Join(g.Out, " ") {
			return fmt.Errorf("the %s program gives %v on the RTL and %v on the fault-free netlist", p, r.Out, g.Out)
		}
		want[p] = r
	}
	// A tester gives each die twice the cycles the program takes on a good
	// one; a die still running then has hung.
	limit := func(p string) int { return 2*want[p].Cycles + 1000 }
	wantSig := want["probe"].Out[len(want["probe"].Out)-1]
	wantFinal := want["final"].Out[len(want["final"].Out)-1]
	fmt.Printf("shuttle: RTL and fault-free netlist agree: probe signature %s in %d cycles, final test signature %s in %d cycles\n",
		wantSig, want["probe"].Cycles, wantFinal, want["final"].Cycles)

	// Wafer sort.
	if err := parallel(len(dies), func(i int) error {
		d := dies[i]
		var fs []int
		for _, f := range d.Faults {
			fs = append(fs, benchFault(f))
		}
		r, err := gate.runFor("probe", limit("probe"), fs, 0, 0, 0)
		if err != nil {
			return err
		}
		d.SortCycles = r.Cycles
		switch {
		case !r.Done || len(r.Out) != 1:
			d.SortBin = binHang
		case r.Out[0] != wantSig:
			d.SortBin = binFunc
		default:
			d.SortBin = binPass
		}
		return nil
	}); err != nil {
		return err
	}

	// Packaging, from the passing dies in wafer and map order.
	var units []*shuttleUnit
	for _, d := range dies {
		if d.SortBin != binPass || (maxUnits > 0 && int64(len(units)) >= maxUnits) {
			continue
		}
		u := &shuttleUnit{Serial: fmt.Sprintf("%s%05d", S(pkg, "serialPrefix"), len(units)+1), Die: d, Labeled: d}
		if rng.Float64() < bondRate {
			bit := uint32(1) << rng.IntN(32)
			if rng.IntN(2) == 0 {
				u.SA0 = bit
			} else {
				u.SA1 = bit
			}
		}
		units = append(units, u)
	}
	if len(units) == 0 {
		return fmt.Errorf("no die passed wafer sort")
	}
	// An OSAT mistake the configuration can ask for: two units whose dies
	// went into each other's packages, so the genealogy names the wrong die
	// for both.
	bySerial := map[string]*shuttleUnit{}
	for _, u := range units {
		bySerial[u.Serial] = u
	}
	for _, pair := range A(pkg, "labelSwaps") {
		p, _ := pair.([]any)
		if len(p) != 2 {
			return fmt.Errorf("%s: packaging.labelSwaps holds pairs of serials", opt.Config)
		}
		a, b := bySerial[fmt.Sprint(p[0])], bySerial[fmt.Sprint(p[1])]
		if a == nil || b == nil || a == b || a.Die != a.Labeled || b.Die != b.Labeled {
			return fmt.Errorf("%s: packaging.labelSwaps: %v is not two packaged serials, each swapped once", opt.Config, p)
		}
		a.Die, b.Die = b.Die, a.Die
	}

	// Final test: the die id the fuses hold must be the one the genealogy
	// says this serial carries, and the signature the RTL's.
	if err := parallel(len(units), func(i int) error {
		u := units[i]
		var fs []int
		for _, f := range u.Die.Faults {
			fs = append(fs, benchFault(f))
		}
		r, err := gate.runFor("final", limit("final"), fs, u.Die.ID, u.SA0, u.SA1)
		if err != nil {
			return err
		}
		u.Cycles = r.Cycles
		if len(r.Out) > 0 {
			u.ReadID = r.Out[0]
		}
		switch {
		case !r.Done || len(r.Out) != 2:
			u.Bin = binHang
		case r.Out[0] != fmt.Sprintf("%08x", u.Labeled.ID):
			u.Bin = binWrongID
		case r.Out[1] != wantFinal:
			u.Bin = binFunc
		default:
			u.Bin = binPass
		}
		return nil
	}); err != nil {
		return err
	}

	sim := Obj{
		"simulator": ShuttleID,
		"standsIn":  "an open-PDK shuttle: the wafer fab, sort house, OSAT and test house, and the dies they made; every result comes from simulating the released netlist with each die's defects",
		"config":    Obj{"name": filepath.Base(opt.Config), "digest": Obj{"sha256": cfgDigest}},
		"seed":      seed,
		"design":    Obj{"name": S(final, "name"), "digest": get(final, "digest")},
		"rerun":     "hslsa sim shuttle with the same release, configuration and seed writes the same exports byte for byte",
	}
	if err := os.MkdirAll(opt.Out, 0o755); err != nil {
		return err
	}
	ex := shuttleExports{cfg: cfg, start: start, lot: lotID, asm: asmLot, wafers: wafers, gx: int(gx), gy: int(gy),
		dies: dies, units: units, release: S(final, "digest", "sha256")}
	files, err := ex.write()
	if err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(opt.Out, name), data, 0o644); err != nil {
			return err
		}
	}
	adapter := ex.adapterConfig(sim)
	if err := WriteJSON(filepath.Join(opt.Out, "adapter.json"), adapter); err != nil {
		return err
	}
	report := ex.report(sim, faultNets, index, nets, wantSig, wantFinal)
	if err := WriteJSON(filepath.Join(opt.Out, "report.json"), report); err != nil {
		return err
	}
	s := O(report, "summary")
	fmt.Printf("shuttle: wafer sort passed %s of %d dies; %s units packaged, %s passed final test\n",
		num(get(s, "sortPassed")), len(dies), num(get(s, "packaged")), num(get(s, "shipped")))
	fmt.Printf("shuttle: %s shipped units carry a defect neither test program caught (see report.json; no record can show this)\n",
		num(get(s, "shippedWithDefect")))
	fmt.Printf("shuttle: exports and adapter.json written to %s\n", opt.Out)
	return nil
}

// rate reads a non-negative number from a configuration block.
func rate(block Obj, key string) (float64, bool) {
	n, ok := get(block, key).(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil && f >= 0
}

func countFaults(dies []*shuttleDie) int {
	n := 0
	for _, d := range dies {
		n += len(d.Faults)
	}
	return n
}

// parallel runs f(0..n-1) on every CPU and returns the first error.
func parallel(n int, f func(i int) error) error {
	var wg sync.WaitGroup
	errs := make([]error, n)
	next := make(chan int)
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				errs[i] = f(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// shuttleExports writes what each site of the shuttle exports.
type shuttleExports struct {
	cfg      Obj
	start    time.Time
	lot, asm string
	wafers   []string
	gx, gy   int
	dies     []*shuttleDie
	units    []*shuttleUnit
	release  string
}

func (e *shuttleExports) at(days, hours int) time.Time {
	return e.start.Add(time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour)
}

func (e *shuttleExports) ts(days, hours int) string {
	return e.at(days, hours).UTC().Format(time.RFC3339)
}

func csvBytes(rows [][]string) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.WriteAll(rows); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Export file names, by what writes them.
const (
	shuttleFabMES   = "fab-mes-lot-history.csv"
	shuttleOSATMES  = "osat-mes-lot-history.csv"
	shuttleGenealog = "osat-mes-genealogy.csv"
)

func (e *shuttleExports) sortSTDF() string { return "sort-" + e.lot + ".stdf" }
func (e *shuttleExports) ftSTDF() string   { return "ft-" + e.asm + ".stdf" }
func (e *shuttleExports) mapFile(w string) string {
	return fmt.Sprintf("sort-%s-%s.xml", e.lot, w)
}

func (e *shuttleExports) write() (map[string][]byte, error) {
	cfg := e.cfg
	fab, srt, pkg, ft := O(cfg, "fab"), O(cfg, "sort"), O(cfg, "packaging"), O(cfg, "finalTest")
	files := map[string][]byte{}
	wl := strings.Join(e.wafers, "|")
	nw := fmt.Sprint(len(e.wafers))
	ff := S(fab, "facility")

	// The fab's MES: the lot starts, the released design is checked against
	// what is built, the process runs, and the wafers ship to sort.
	rows := [][]string{mesHistoryColumns,
		{e.ts(0, 0), ff, e.lot, "LOT_START", "LOT START", nw, wl,
			"product=" + S(cfg, "product", "partNumber") + "|process=" + S(fab, "processNode") + "|mask_set=" + S(fab, "maskSetId")},
		{e.ts(0, 3), ff, e.lot, "TRACK_OUT", "MASK GDS XOR", "1", "", "result=PASS|released_sha256=" + e.release},
	}
	for i, op := range []string{"DIFFUSION", "PHOTO M1", "ETCH M1", "CMP", "PHOTO M5", "PASSIVATION"} {
		rows = append(rows, []string{e.ts(2+3*i, 2), ff, e.lot, "TRACK_OUT", op, nw, wl, "result=PASS"})
	}
	rows = append(rows,
		[]string{e.ts(21, 8), ff, e.lot, "TRACK_OUT", "INLINE PARAMETRICS", nw, wl, "result=PASS|sites=9"},
		[]string{e.ts(23, 4), ff, e.lot, "SHIP", "SHIP", nw, wl, "ship_to=" + S(srt, "site", "name")})
	var err error
	if files[shuttleFabMES], err = csvBytes(rows); err != nil {
		return nil, err
	}

	// Wafer sort: an STDF file for the lot and a SEMI E142 map per wafer.
	var sf stdfFile
	sortStart := e.at(27, 0)
	e.stdfHeader(&sf, sortStart, e.lot, S(srt, "facility"), "WS1", S(srt, "program", "name"), S(srt, "program", "version"))
	bins := map[int]uint32{}
	for wi, w := range e.wafers {
		wStart := uint32(sortStart.Add(time.Duration(wi) * time.Hour).Unix())
		sf.rec(2, 10, uint8(1), uint8(255), wStart, w)
		codes := make([][]string, e.gy)
		for y := range codes {
			codes[y] = make([]string, e.gx)
		}
		count, good := map[int]int{}, uint32(0)
		for _, d := range e.dies {
			if d.Wafer != w {
				continue
			}
			e.stdfPart(&sf, []shuttleTest{
				{100, "probe_signature", d.SortBin != binFunc && d.SortBin != binHang},
				{110, "probe_cycles", d.SortBin != binHang},
			}, float32(d.SortCycles), d.SortBin, int16(d.X), int16(d.Y), d.dieName())
			if d.SortBin == binPass {
				good++
			}
			bins[d.SortBin]++
			count[d.SortBin]++
			codes[d.Y][d.X] = fmt.Sprintf("%02X", d.SortBin)
		}
		// WRR: HEAD SITE_GRP FINISH_T PART_CNT RTST_CNT ABRT_CNT GOOD_CNT FUNC_CNT WAFER_ID
		sf.rec(2, 20, uint8(1), uint8(255), wStart+1800, uint32(e.gx*e.gy), uint32(0), uint32(0), good, uint32(math.MaxUint32), w)
		files[e.mapFile(w)] = e142Map(w, e.lot, e.gx, e.gy, codes, count)
	}
	e.stdfBins(&sf, bins)
	sf.rec(1, 20, uint32(sortStart.Add(time.Duration(len(e.wafers)+1)*time.Hour).Unix()), uint8(' '), "", "")
	files[e.sortSTDF()] = append([]byte(nil), sf.Bytes()...)

	// The OSAT's MES and genealogy.
	of := S(pkg, "facility")
	n := fmt.Sprint(len(e.units))
	rows = [][]string{mesHistoryColumns,
		{e.ts(30, 9), of, e.lot, "RECEIVE", "INCOMING", nw, wl, "from=" + S(srt, "site", "name")},
		{e.ts(31, 7), of, e.asm, "LOT_START", "LOT START", n, "",
			"source_lot=" + e.lot + "|package=" + S(pkg, "packageType") + "|device=" + S(cfg, "product", "partNumber")},
	}
	for i, op := range []string{"WAFER SAW", "DIE ATTACH", "WIRE BOND", "MOLD", "XRAY SAMPLE", "MARK"} {
		attrs := "result=PASS"
		if op == "XRAY SAMPLE" {
			attrs += "|sample=5"
		}
		rows = append(rows, []string{e.ts(31, 9+i), of, e.asm, "TRACK_OUT", op, n, "", attrs})
	}
	rows = append(rows, []string{e.ts(32, 10), of, e.asm, "SHIP", "SHIP", n, "", "ship_to=" + S(ft, "site", "name")})
	if files[shuttleOSATMES], err = csvBytes(rows); err != nil {
		return nil, err
	}
	rows = [][]string{mesGenealogyColumns}
	for _, u := range e.units {
		rows = append(rows, []string{u.Serial, e.asm, e.lot, u.Labeled.Wafer, fmt.Sprint(u.Labeled.X), fmt.Sprint(u.Labeled.Y)})
	}
	if files[shuttleGenealog], err = csvBytes(rows); err != nil {
		return nil, err
	}

	// Final test: an STDF file for the assembly lot, a result per serial.
	var tf stdfFile
	ftStart := e.at(34, 8)
	e.stdfHeader(&tf, ftStart, e.asm, S(ft, "facility"), "FT1", S(ft, "program", "name"), S(ft, "program", "version"))
	bins = map[int]uint32{}
	for _, u := range e.units {
		e.stdfPart(&tf, []shuttleTest{
			{1000, "die_id_readback", u.Bin != binWrongID && u.Bin != binHang},
			{1010, "final_signature", u.Bin == binPass},
			{1020, "final_cycles", u.Bin != binHang},
		}, float32(u.Cycles), u.Bin, -32768, -32768, u.Serial)
		bins[u.Bin]++
	}
	e.stdfBins(&tf, bins)
	tf.rec(1, 20, uint32(ftStart.Add(3*time.Hour).Unix()), uint8(' '), "", "")
	files[e.ftSTDF()] = append([]byte(nil), tf.Bytes()...)
	return files, nil
}

func (d *shuttleDie) dieName() string { return fmt.Sprintf("%s-%d-%d", d.Wafer, d.X, d.Y) }

// shuttleTest is one functional test result, written as a PTR of 1 (pass)
// or 0 (fail) against limits of 1.
type shuttleTest struct {
	num  uint32
	name string
	pass bool
}

func (e *shuttleExports) stdfHeader(f *stdfFile, start time.Time, lot, node, code, job, rev string) {
	f.rec(0, 10, uint8(2), uint8(4))
	t := uint32(start.Unix())
	// MIR: SETUP_T START_T STAT_NUM MODE_COD RTST_COD PROT_COD BURN_TIM CMOD_COD LOT_ID PART_TYP
	// NODE_NAM TSTR_TYP JOB_NAM JOB_REV SBLOT_ID OPER_NAM EXEC_TYP EXEC_VER TEST_COD TST_TEMP
	f.rec(1, 10, t, t, uint8(1), uint8('P'), uint8(' '), uint8(' '), uint16(65535), uint8(' '),
		lot, S(e.cfg, "product", "partNumber"), node, "hslsa-virtual-tester", job, rev, "", "sim", "hslsa-sim-shuttle", "0.1", code, "25")
}

func (e *shuttleExports) stdfPart(f *stdfFile, tests []shuttleTest, cycles float32, bin int, x, y int16, id string) {
	f.rec(5, 10, uint8(1), uint8(1))
	for _, t := range tests {
		flg, v := uint8(0), float32(1)
		if !t.pass {
			flg, v = 0x80, 0
		}
		if strings.HasSuffix(t.name, "_cycles") {
			v = cycles
		}
		// PTR: TEST_NUM HEAD SITE TEST_FLG PARM_FLG RESULT TEST_TXT ALARM_ID OPT_FLAG RES_SCAL
		// LLM_SCAL HLM_SCAL LO_LIMIT HI_LIMIT UNITS
		lo, hi, unit := float32(1), float32(1), ""
		if strings.HasSuffix(t.name, "_cycles") {
			lo, hi, unit = 1, shuttleCycles, "cycles"
		}
		f.rec(15, 10, t.num, uint8(1), uint8(1), flg, uint8(0), v, t.name, "", uint8(0x0e),
			int8(0), int8(0), int8(0), lo, hi, unit)
	}
	partFlg := uint8(0)
	if bin != binPass {
		partFlg = 0x08
	}
	// PRR: HEAD SITE PART_FLG NUM_TEST HARD_BIN SOFT_BIN X_COORD Y_COORD TEST_T PART_ID PART_TXT PART_FIX
	f.rec(5, 20, uint8(1), uint8(1), partFlg, uint16(len(tests)), uint16(bin), uint16(bin), x, y, uint32(cycles/100), id, "", uint8(0))
}

func (e *shuttleExports) stdfBins(f *stdfFile, bins map[int]uint32) {
	for _, b := range []int{binPass, binFunc, binHang, binWrongID} {
		if n, ok := bins[b]; ok {
			pf := uint8('F')
			if b == binPass {
				pf = 'P'
			}
			// HBR: HEAD_NUM 255 (all heads) SITE_NUM HBIN_NUM HBIN_CNT HBIN_PF HBIN_NAM
			f.rec(1, 40, uint8(255), uint8(0), uint16(b), n, pf, binNames[b])
		}
	}
}

// e142Map is one wafer's SEMI E142 sort map.
func e142Map(wafer, lot string, gx, gy int, codes [][]string, count map[int]int) []byte {
	var x bytes.Buffer
	fmt.Fprintf(&x, `<?xml version="1.0" encoding="UTF-8"?>
<MapData xmlns="urn:semi-org:xsd.E142-1.V1005.SubstrateMap">
  <Layouts>
    <Layout LayoutId="WaferLayout" DefaultUnits="mm" TopLevel="true">
      <Dimension X="1" Y="1"/>
      <ChildLayouts>
        <ChildLayout LayoutId="Devices"/>
      </ChildLayouts>
    </Layout>
    <Layout LayoutId="Devices" DefaultUnits="mm">
      <Dimension X="%d" Y="%d"/>
    </Layout>
  </Layouts>
  <Substrates>
    <Substrate SubstrateType="Wafer" SubstrateId="%s">
      <LotId>%s</LotId>
    </Substrate>
  </Substrates>
  <SubstrateMaps>
    <SubstrateMap SubstrateType="Wafer" SubstrateId="%s" Orientation="0" OriginLocation="UpperLeft" AxisDirection="DownRight" LayoutSpecifier="WaferLayout/Devices">
      <Overlay MapName="SortGrade" MapVersion="1">
        <BinCodeMap BinType="HexaDecimal" NullBin="FF">
          <BinDefinitions>
`, gx, gy, wafer, lot, wafer)
	for _, b := range []int{binPass, binFunc, binHang} {
		q := "Fail"
		if b == binPass {
			q = "Pass"
		}
		fmt.Fprintf(&x, "            <BinDefinition BinCode=\"%02X\" BinCount=\"%d\" BinQuality=\"%s\" BinDescription=\"%s\"/>\n", b, count[b], q, binNames[b])
	}
	x.WriteString("          </BinDefinitions>\n")
	for _, r := range codes {
		fmt.Fprintf(&x, "          <BinCode>%s</BinCode>\n", strings.Join(r, ""))
	}
	x.WriteString("        </BinCodeMap>\n      </Overlay>\n    </SubstrateMap>\n  </SubstrateMaps>\n</MapData>\n")
	return x.Bytes()
}

// adapterConfig is the MES and STDF adapter's configuration for the
// exports, marked simulated.
func (e *shuttleExports) adapterConfig(sim Obj) Obj {
	cfg := e.cfg
	block := func(key string) Obj { return O(cfg, key) }
	var maps []any
	for _, w := range e.wafers {
		maps = append(maps, Obj{"path": e.mapFile(w), "format": FmtE142})
	}
	out := Obj{
		"note":      "Written by hslsa sim shuttle. Every export here comes from simulating the released netlist; nothing was made.",
		"simulated": sim,
		"product":   get(cfg, "product"),
		"fab": Obj{
			"id": S(block("fab"), "id"), "site": get(block("fab"), "site"),
			"sources": []any{Obj{"path": shuttleFabMES, "format": FmtMESHistory}},
			"checks": []any{
				Obj{"operation": "MASK GDS XOR", "check": "mask-vs-gds-xor"},
				Obj{"operation": "INLINE PARAMETRICS", "check": "inline-parametrics"},
			},
		},
		"sort": Obj{
			"site":    get(block("sort"), "site"),
			"sources": append([]any{Obj{"path": e.sortSTDF(), "format": FmtSTDF}}, maps...),
		},
		"packaging": Obj{
			"site": get(block("packaging"), "site"),
			"sources": []any{
				Obj{"path": shuttleOSATMES, "format": FmtMESHistory},
				Obj{"path": shuttleGenealog, "format": FmtMESGenealogy},
			},
			"checks": []any{
				Obj{"operation": "DIE ATTACH", "check": "die-attach"},
				Obj{"operation": "WIRE BOND", "check": "wire-bond"},
				Obj{"operation": "XRAY SAMPLE", "check": "x-ray-sample"},
				Obj{"operation": "MARK", "check": "marking"},
			},
		},
		"transfers": shuttleTransfers(get(cfg, "transfers")),
		"finalTest": Obj{
			"site":    get(block("finalTest"), "site"),
			"sources": []any{Obj{"path": e.ftSTDF(), "format": FmtSTDF}},
		},
	}
	return out
}

// shuttleTransfers is the adapter's transfers setting for the shuttle's
// configuration: "mes" makes the transfers from the shipping events the
// shuttle writes into the fab's and the OSAT's lot histories; otherwise the
// adapter makes them from the lot, as before.
func shuttleTransfers(v any) any {
	if v == TransfersFromMES {
		return TransfersFromMES
	}
	return Truthy(v)
}

// report is what only the simulator knows: each die's defects and what
// became of it, and the defects that reached the shipped lot.
func (e *shuttleExports) report(sim Obj, faultNets []string, index map[int]int, nets []string, probeSig, finalSig string) Obj {
	describe := func(faults []int) []any {
		out := []any{}
		for _, f := range faults {
			out = append(out, fmt.Sprintf("%s stuck-at-%d", nets[(f-1)/2], (f-1)%2))
		}
		return out
	}
	var dies []any
	sortPassed, defective, caughtSort := 0, 0, 0
	for _, d := range e.dies {
		if d.SortBin == binPass {
			sortPassed++
		}
		if len(d.Faults) > 0 {
			defective++
			if d.SortBin != binPass {
				caughtSort++
			}
		}
		dies = append(dies, Obj{"die": d.dieName(), "id": fmt.Sprintf("%08x", d.ID), "defects": describe(d.Faults),
			"sortBin": binNames[d.SortBin]})
	}
	var units []any
	shipped, escapes, pinDefects, caughtFinal := 0, 0, 0, 0
	for _, u := range e.units {
		pin := ""
		if u.SA0|u.SA1 != 0 {
			pinDefects++
			v, bits := 0, u.SA0
			if u.SA1 != 0 {
				v, bits = 1, u.SA1
			}
			for i := 0; i < 32; i++ {
				if bits>>i&1 == 1 {
					pin = fmt.Sprintf("mem_rdata[%d] bond stuck-at-%d", i, v)
				}
			}
		}
		faulty := len(u.Die.Faults) > 0 || pin != "" || u.Die != u.Labeled
		if u.Bin == binPass {
			shipped++
			if faulty {
				escapes++
			}
		} else if faulty {
			caughtFinal++
		}
		entry := Obj{"serial": u.Serial, "die": u.Die.dieName(), "finalBin": binNames[u.Bin], "defects": describe(u.Die.Faults)}
		if pin != "" {
			entry["pinDefect"] = pin
		}
		if u.Die != u.Labeled {
			entry["genealogySays"] = u.Labeled.dieName()
		}
		units = append(units, entry)
	}
	return Obj{
		"note":      "Ground truth that only a simulator has. A real lot's records cannot carry this: they show what the testers saw, and a defect no test program reaches is invisible to them.",
		"simulated": sim,
		"expected":  Obj{"probeSignature": probeSig, "finalSignature": finalSig},
		"summary": Obj{
			"dies": len(e.dies), "defectiveDies": defective, "sortPassed": sortPassed, "caughtAtSort": caughtSort,
			"packaged": len(e.units), "pinDefects": pinDefects, "caughtAtFinalTest": caughtFinal,
			"shipped": shipped, "shippedWithDefect": escapes,
		},
		"faultNets": len(faultNets),
		"dies":      dies,
		"units":     units,
	}
}
