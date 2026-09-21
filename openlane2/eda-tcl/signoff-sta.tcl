# Signoff timing of the released spm layout in OpenROAD's Tcl shell, with the
# HSLSA step hook: an independent STA run on the views OpenLane signed.
#
#   openroad -exit -no_init signoff-sta.tcl
#
# Environment: HSLSA_HOOK (the hook), ODB, SDC, SPEF (views from OpenLane's
# final state), LIBS (Liberty files from the PDK) and OUT (report directory).
# openlane2/run.sh eda-sta sets them and runs this under `hslsa eda run`.

source $::env(HSLSA_HOOK)
if {[catch {ord::openroad_version} version]} {set version unknown}
hslsa::configure -tool openroad -version $version

set out $::env(OUT)
file mkdir $out

hslsa::step signoff -label openroad-sta {
    foreach lib $::env(LIBS) {
        hslsa::input $lib -kind pdk
        read_liberty $lib
    }
    hslsa::input $::env(ODB)
    hslsa::input $::env(SDC)
    hslsa::input $::env(SPEF)
    read_db $::env(ODB)
    read_sdc $::env(SDC)
    set_propagated_clock [all_clocks]
    read_spef $::env(SPEF)

    sta::redirect_file_begin $out/sta.rpt
    report_checks -path_delay min_max -fields {slew cap input_pins} -digits 4
    report_check_types -max_slew -max_capacitance -max_fanout -violators
    sta::redirect_file_end

    set setup [sta::worst_slack -max]
    set hold [sta::worst_slack -min]
    set f [open $out/sta-summary.txt w]
    puts $f "setup worst slack (ns): $setup"
    puts $f "hold worst slack (ns): $hold"
    close $f

    hslsa::output $out/sta.rpt -view sta-report
    hslsa::output $out/sta-summary.txt -view sta-summary
    hslsa::metric timing__setup__ws $setup
    hslsa::metric timing__hold__ws $hold
    hslsa::check setup-slack [expr {$setup >= 0 ? "pass" : "fail"}] "worst setup slack $setup ns"
    hslsa::check hold-slack [expr {$hold >= 0 ? "pass" : "fail"}] "worst hold slack $hold ns"
}
