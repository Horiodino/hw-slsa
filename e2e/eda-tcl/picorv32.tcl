# PicoRV32 lint and synthesis in Yosys's Tcl shell, with the HSLSA step hook.
#
#   yosys -c picorv32.tcl
#
# with SRC the unpacked frozen source and OUT the directory for outputs.
# HSLSA_HOOK names the hook; run under `hslsa eda run`, each step below is
# signed as it ends. Run on its own, the hook does nothing and the flow is
# plain Yosys.

source $::env(HSLSA_HOOK)

set src $::env(SRC)
set out $::env(OUT)
file mkdir $out

# Yosys has no Tcl command that returns its version; ask this process's own binary.
set version [string trim [exec /proc/[pid]/exe -V]]
hslsa::configure -tool yosys -version $version

# Lint-only run: elaborate the RTL and require Yosys's design checks to pass.
hslsa::step simulation -label yosys-lint {
    hslsa::input $src/picorv32.v
    yosys design -reset
    yosys read_verilog $src/picorv32.v
    yosys hierarchy -check -top picorv32
    yosys proc
    yosys tee -q -o $out/lint.rpt check -assert
    hslsa::output $out/lint.rpt -view lint-report
    hslsa::check check-assert pass "hierarchy -check and check -assert"
}

# Generic synthesis to a flat gate-level netlist.
hslsa::step synthesis -label yosys-synth {
    hslsa::input $src/picorv32.v
    yosys design -reset
    yosys read_verilog $src/picorv32.v
    yosys synth -top picorv32 -flatten
    yosys tee -q -o $out/synth-check.rpt check -assert
    yosys tee -q -o $out/stat.json stat -json
    yosys write_verilog -noattr $out/picorv32.netlist.v

    set f [open $out/stat.json]
    set stat [read $f]
    close $f
    if {[regexp {"num_cells":\s*([0-9]+)} $stat -> cells]} {
        hslsa::metric design__instance__count $cells
    }
    hslsa::output $out/picorv32.netlist.v -view nl
    hslsa::output $out/stat.json -view stat
    hslsa::output $out/synth-check.rpt -view check-report
    hslsa::check check-assert pass "check -assert after synthesis"
}
