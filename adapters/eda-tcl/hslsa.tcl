# HSLSA step hook for EDA tool Tcl shells.
#
# A flow script sources this file and wraps each design step:
#
#   source hslsa.tcl
#   hslsa::configure -tool openroad -version [ord::openroad_version]
#   hslsa::step signoff -label sta {
#       hslsa::input $odb
#       hslsa::input $lib -kind pdk
#       ... the tool's own commands ...
#       hslsa::output $report
#       hslsa::metric timing__setup__ws $wns
#       hslsa::check setup-slack [expr {$wns >= 0 ? "pass" : "fail"}]
#   }
#
# The hook signs nothing and holds no key. At the end of each step it writes
# one JSON event into the spool directory named by HSLSA_SPOOL. The signer,
# `hslsa eda run`, runs outside the tool, hashes the files the event names
# and signs the step record. When HSLSA_SYNC is set, step_end waits until the
# signer has signed the step, so the tool cannot change a step's outputs
# before they are hashed, and a step the signer refuses stops the flow.
#
# Without HSLSA_SPOOL the hook does nothing, so a flow script that sources it
# still runs unchanged outside a signed run.
#
# Pure Tcl 8.5, no packages: it runs in OpenROAD, Yosys, Innovus, Genus,
# ICC2, Fusion Compiler, PrimeTime and Calibre's Tcl shells alike.

namespace eval ::hslsa {
    variable version 0.1
    variable hook [file normalize [info script]]
    variable tool ""
    variable toolVersion ""
    variable ordinal 0
    variable current ""
    variable steps {source-freeze simulation synthesis floorplan place-cts routing
                    signoff rom-merge gds-stream-out bitstream release rebuild other}
    # Records for these come from other signers, never from a tool step.
    variable reserved {source-freeze release rebuild}
}

# configure -tool NAME -version STRING
#   Names the tool the flow runs in. The signer adds the binary's own digest
#   when it can see the process; the version is the tool's own report.
proc ::hslsa::configure {args} {
    variable tool
    variable toolVersion
    foreach {opt val} $args {
        switch -- $opt {
            -tool {set tool $val}
            -version {set toolVersion $val}
            default {error "hslsa::configure: unknown option $opt"}
        }
    }
}

proc ::hslsa::enabled {} {
    return [expr {[info exists ::env(HSLSA_SPOOL)] && $::env(HSLSA_SPOOL) ne ""}]
}

proc ::hslsa::now {} {
    return [clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%SZ} -gmt 1]
}

# step_begin STEP ?-label LABEL?
#   STEP is one of the spec's design step names. LABEL is the flow's own name
#   for the step, which tells apart several records of one spec step.
proc ::hslsa::step_begin {step args} {
    variable steps
    variable reserved
    variable current
    variable ordinal
    if {[lsearch -exact $steps $step] < 0} {
        error "hslsa: $step is not a design step name (one of: [join $steps {, }])"
    }
    if {[lsearch -exact $reserved $step] >= 0} {
        error "hslsa: a $step record is signed by its own party, not from a tool step"
    }
    if {$current ne ""} {
        error "hslsa: step [dict get $current step] is still open"
    }
    set label $step
    foreach {opt val} $args {
        switch -- $opt {
            -label {set label $val}
            default {error "hslsa::step_begin: unknown option $opt"}
        }
    }
    if {[enabled]} {
        # Number steps across every tool session of the run: a flow that runs
        # one shell per stage, as most commercial flows do, gets one sequence.
        # The begin marker also lets the signer report a step that never ended.
        set last 0
        foreach m [glob -nocomplain -tails -directory $::env(HSLSA_SPOOL) {[0-9][0-9][0-9][0-9].begin}] {
            scan $m %d n
            if {$n > $last} {set last $n}
        }
        set ordinal [expr {$last + 1}]
        if {[catch {open [file join $::env(HSLSA_SPOOL) [format %04d.begin $ordinal]] {WRONLY CREAT EXCL}} f]} {
            error "hslsa: step $ordinal is already open in another session; run steps one at a time"
        }
        puts $f $step
        close $f
    } else {
        incr ordinal
    }
    set script [info script]
    if {$script ne ""} {set script [file normalize $script]}
    set current [dict create step $step label $label started [now] script $script \
        inputs {} outputs {} metrics {} checks {}]
}

proc ::hslsa::require_open {what} {
    variable current
    if {$current eq ""} {
        error "hslsa::$what outside a step"
    }
}

# input PATH ?-kind view|pdk|config?
#   view (the default): a design view, which must be an output of an earlier
#   record or a file of the frozen source. pdk: a file under the pinned PDK.
#   config: anything else the step reads, such as a constraints file.
proc ::hslsa::input {path args} {
    variable current
    require_open input
    set kind view
    foreach {opt val} $args {
        switch -- $opt {
            -kind {set kind $val}
            default {error "hslsa::input: unknown option $opt"}
        }
    }
    if {[lsearch -exact {view pdk config} $kind] < 0} {
        error "hslsa::input: kind must be view, pdk or config"
    }
    dict lappend current inputs [list [file normalize $path] $kind]
}

# output PATH ?-view NAME?
proc ::hslsa::output {path args} {
    variable current
    require_open output
    set view ""
    foreach {opt val} $args {
        switch -- $opt {
            -view {set view $val}
            default {error "hslsa::output: unknown option $opt"}
        }
    }
    dict lappend current outputs [list [file normalize $path] $view]
}

proc ::hslsa::metric {name value} {
    variable current
    require_open metric
    dict set current metrics $name $value
}

# check NAME pass|fail ?DETAIL?
proc ::hslsa::check {name result {detail ""}} {
    variable current
    require_open check
    if {$result ne "pass" && $result ne "fail"} {
        error "hslsa::check: result must be pass or fail"
    }
    dict lappend current checks [list $name $result $detail]
}

proc ::hslsa::json_string {s} {
    set map [list \\ \\\\ \" \\\" \n \\n \r \\r \t \\t \b \\b \f \\f]
    set out [string map $map $s]
    # Any other control character.
    set esc ""
    foreach ch [split $out ""] {
        scan $ch %c code
        if {$code < 0x20} {
            append esc [format \\u%04x $code]
        } else {
            append esc $ch
        }
    }
    return "\"$esc\""
}

proc ::hslsa::json_value {v} {
    if {[string is double -strict $v] && ![string match -nocase *inf* $v] && ![string match -nocase *nan* $v]
        && ![string match 0x* $v] && [regexp {^-?[0-9]} $v]} {
        return $v
    }
    return [json_string $v]
}

# step_end ?-status completed|failed?
proc ::hslsa::step_end {args} {
    variable current
    variable ordinal
    variable tool
    variable toolVersion
    variable hook
    variable version
    require_open step_end
    set status completed
    foreach {opt val} $args {
        switch -- $opt {
            -status {set status $val}
            default {error "hslsa::step_end: unknown option $opt"}
        }
    }
    set ev $current
    set current ""
    if {![enabled]} {
        return
    }
    set j "\{\n"
    append j "  \"hook\": [json_string $hook],\n"
    append j "  \"hookVersion\": [json_string $version],\n"
    append j "  \"ordinal\": $ordinal,\n"
    append j "  \"step\": [json_string [dict get $ev step]],\n"
    append j "  \"label\": [json_string [dict get $ev label]],\n"
    append j "  \"status\": [json_string $status],\n"
    append j "  \"tool\": \{\"name\": [json_string $tool], \"version\": [json_string $toolVersion]\},\n"
    append j "  \"pid\": [pid],\n"
    append j "  \"executable\": [json_string [info nameofexecutable]],\n"
    append j "  \"tcl\": [json_string [info patchlevel]],\n"
    append j "  \"script\": [json_string [dict get $ev script]],\n"
    append j "  \"started\": [json_string [dict get $ev started]],\n"
    append j "  \"finished\": [json_string [now]],\n"
    set items {}
    foreach in [dict get $ev inputs] {
        lappend items "\{\"path\": [json_string [lindex $in 0]], \"kind\": [json_string [lindex $in 1]]\}"
    }
    append j "  \"inputs\": \[[join $items {, }]\],\n"
    set items {}
    foreach out [dict get $ev outputs] {
        lappend items "\{\"path\": [json_string [lindex $out 0]], \"view\": [json_string [lindex $out 1]]\}"
    }
    append j "  \"outputs\": \[[join $items {, }]\],\n"
    set items {}
    dict for {k v} [dict get $ev metrics] {
        lappend items "[json_string $k]: [json_value $v]"
    }
    append j "  \"metrics\": \{[join $items {, }]\},\n"
    set items {}
    foreach c [dict get $ev checks] {
        lappend items "\{\"name\": [json_string [lindex $c 0]], \"result\": [json_string [lindex $c 1]], \"detail\": [json_string [lindex $c 2]]\}"
    }
    append j "  \"checks\": \[[join $items {, }]\]\n"
    append j "\}\n"

    # Write then rename, so the signer never reads half an event.
    set name [format %04d.json $ordinal]
    set tmp [file join $::env(HSLSA_SPOOL) .$name.tmp]
    set f [open $tmp w]
    fconfigure $f -encoding utf-8
    puts -nonewline $f $j
    close $f
    file rename -force $tmp [file join $::env(HSLSA_SPOOL) $name]

    if {[info exists ::env(HSLSA_SYNC)] && $::env(HSLSA_SYNC) ne ""} {
        wait_signed $name
    }
}

# wait_signed waits for the signer's answer to one event: a line "signed
# <record>" or "refused <reason>". A refusal stops the flow.
proc ::hslsa::wait_signed {name} {
    set ack [file join $::env(HSLSA_SPOOL) $name.ack]
    set timeout 600
    if {[info exists ::env(HSLSA_SYNC_TIMEOUT)]} {set timeout $::env(HSLSA_SYNC_TIMEOUT)}
    set deadline [expr {[clock seconds] + $timeout}]
    while {![file exists $ack]} {
        if {[clock seconds] > $deadline} {
            error "hslsa: no answer from the signer for $name after $timeout s"
        }
        after 50
    }
    set f [open $ack r]
    set answer [string trim [read $f]]
    close $f
    if {![string match "signed *" $answer]} {
        error "hslsa: the signer refused step $name: $answer"
    }
}

# step STEP ?-label LABEL? BODY
#   Runs BODY in the caller's scope between step_begin and step_end. An error
#   in BODY ends the step as failed, so the signer records the failure, and
#   is then raised again.
proc ::hslsa::step {step args} {
    if {[llength $args] % 2 != 1} {
        error "usage: hslsa::step STEP ?-label LABEL? BODY"
    }
    set body [lindex $args end]
    step_begin $step {*}[lrange $args 0 end-1]
    set code [catch {uplevel 1 $body} result options]
    if {$code == 1} {
        catch {step_end -status failed}
        return -options $options $result
    }
    step_end
    return $result
}
