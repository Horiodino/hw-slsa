# EDA Tcl adapter

Design tools from every vendor are driven by Tcl scripts. This adapter puts
one small hook into those scripts so a flow emits a signed HSLSA
`design-flow` record for each step it runs, from inside the tool, without
changing how the flow works.

It has two halves:

| Part | Runs | Does |
| --- | --- | --- |
| [`hslsa.tcl`](hslsa.tcl) | Inside the tool's Tcl shell | Marks where each step begins and ends, and collects the files it read and wrote, its metrics and its checks. At the end of a step it writes one JSON event into a spool directory. It holds no key and hashes nothing |
| `hslsa eda run` | Outside the tool, on the flow platform | Starts the tool, reads each event as it lands, hashes the files, checks that every input links to an earlier record, and signs the step's record with the `flow-platform` key |

`hslsa eda verify` is the buyer's check of the records.

The split is the same as in the [OpenLane 2 example](../../docs/openlane2-flow.md):
the key stays with the platform and never enters the tool's process, so a
compromised tool or flow script cannot sign anything. It can only declare
files, and the signer checks what it declares.

## Using the hook

Source the hook at the top of a flow script, name the tool once, and wrap each
step:

```tcl
source $::env(HSLSA_HOOK)
hslsa::configure -tool openroad -version [ord::openroad_version]

hslsa::step signoff -label sta {
    hslsa::input $lib -kind pdk
    read_liberty $lib
    hslsa::input $odb
    read_db $odb
    ...
    hslsa::output $out/sta.rpt -view sta-report
    hslsa::metric timing__setup__ws $setup
    hslsa::check setup-slack [expr {$setup >= 0 ? "pass" : "fail"}]
}
```

| Command | Meaning |
| --- | --- |
| `hslsa::configure -tool NAME -version STRING` | The tool and its version, as the tool reports it |
| `hslsa::step STEP ?-label LABEL? BODY` | Run `BODY` as one step. `STEP` is a [design step name](../../spec/hslsa-v0.1.md#predicate-types) (`simulation`, `synthesis`, `floorplan`, `place-cts`, `routing`, `signoff`, `rom-merge`, `gds-stream-out`, `bitstream` or `other`); `LABEL` is the flow's own name for it. An error in `BODY` ends the step as failed and is raised again |
| `hslsa::step_begin` / `hslsa::step_end ?-status failed?` | The same, for flows that cannot wrap a step in one block |
| `hslsa::input PATH ?-kind view\|pdk\|config?` | A file the step read. `view` (the default) is a design view, which must be an output of an earlier record or a file of the frozen source. `pdk` is a file of the pinned PDK. `config` is anything else, such as constraints |
| `hslsa::output PATH ?-view NAME?` | A file the step produced; it becomes a subject of the record |
| `hslsa::metric NAME VALUE` | Goes to `hwFlow.metrics`; numbers stay numbers |
| `hslsa::check NAME pass\|fail ?DETAIL?` | Goes to `hwFlow.checks`; any `fail` fails the buyer's check |

`source-freeze`, `release` and `rebuild` are refused: each has its own signer.

The hook records its own digest and the flow script's, finding both with
`[info script]`. Shells built on OpenSTA, OpenROAD among them, run their main
script themselves and replace `source`, so `[info script]` is empty there:
set `HSLSA_HOOK` to the hook's path (flows source it from there anyway) and
`HSLSA_FLOW_SCRIPT` to the flow script's. Both take precedence when set. The
signer refuses a step whose reported hook path is not the hook.

Without `HSLSA_SPOOL` in the environment the hook does nothing, so the same
script runs unchanged outside a signed run. The hook is plain Tcl 8.5 with no
packages.

## Running a flow under the signer

```sh
hslsa eda run --bundle BUNDLE --spool NEW_DIR --key flow-platform.key.pem \
  --root WORK [--pdk PDK_TREE] [--image NAME@sha256:...] -- yosys -c flow.tcl
```

The signer sets `HSLSA_SPOOL`, `HSLSA_SYNC` and a random `HSLSA_RUN_ID` for
the tool. With `HSLSA_SYNC` set, `step_end` waits for the signer's answer, so:

- the step's outputs are hashed before the next step can touch them;
- a step the signer refuses (an input that links to nothing, a PDK file
  outside the pinned PDK, a missing output) raises an error in the tool and
  stops the flow.

Steps are numbered across every tool session in the run, so a flow that
starts one tool shell per stage, as most commercial flows do, still yields
one chain of records. Steps must run one at a time; a second session that
opens a step while another is open is refused.

Each record is a `design-flow` statement with buildType
`.../design-flow/step/eda-tcl@v1`:

- **subjects**: the declared outputs, named relative to `--root`, annotated
  with their view;
- **resolvedDependencies**: the frozen source (`BUNDLE/artifacts/source.tar`,
  when the bundle has one), the tool image (`--image`), the PDK tree
  (`--pdk`, by the spec's tree digest), the hook itself (`kind: adapter`), the
  flow script (`kind: step-config`), every declared input (each view with the
  record or source file it came from) and the previous record;
- **hwFlow**: the spec step, the flow's label as `toolStep`, the `ordinal`,
  the tool with its version and, when the signer can see the tool's process,
  the digest of its binary; the flow's checks plus `step-completed`; the
  metrics; and the hook's version and Tcl version under `adapter`.

`BUNDLE/eda/run.json` lists the records in order, with any step that began
and never ended.

## The buyer's check

```sh
hslsa eda verify --bundle BUNDLE --trust-root trust-root.json [--root WORK] \
  [--hook hslsa.tcl] [--pdk PDK_TREE] [--require-steps synthesis,signoff]
```

It requires every record to be signed by the flow platform, to use the
eda-tcl buildType and a design step a tool may record, to be numbered in
order and linked to the one before, and to have no failed check. Every
record must name the same source, image, PDK tree and hook (and, with
`--hook`, this hook's digest). Every input view must be an output of an
earlier eda record, a file of the frozen source, or a subject of another
design record the flow platform signed in the bundle. With `--root` it
re-hashes every subject; with `--pdk`, the PDK tree and each PDK file.

## Worked flows

| Flow | Tool shell | Steps | Where it runs |
| --- | --- | --- | --- |
| [`e2e/eda-tcl/picorv32.tcl`](../../e2e/eda-tcl/picorv32.tcl) | Yosys (`yosys -c`) | `simulation` (lint), `synthesis` of PicoRV32 from the frozen source | `e2e/eda-tcl/run.sh`, in the HSLSA end-to-end workflow and on any machine with Yosys |
| [`openlane2/eda-tcl/signoff-sta.tcl`](../../openlane2/eda-tcl/signoff-sta.tcl) | OpenROAD, in the pinned OpenLane 2 image | `signoff`: STA of the released `spm` layout, reading the views OpenLane's own records signed | `openlane2/run.sh eda-sta`, in the OpenLane 2 workflow; the buyer job runs `eda-verify` |

The OpenROAD flow shows the hook linking to records another signer made: its
inputs are the final ODB, SDC and SPEF of the OpenLane run, and the check
accepts them because the OpenLane step records list them as subjects. The
tool runs in a container, so the signer cannot see its process; the record
pins the tool by the image digest instead.

## Commercial tools

The hook needs nothing but a Tcl interpreter, so it sits in commercial tool
shells the same way. None of this has been tried against a licensed tool;
this project has no licenses, which is why the roadmap pairs this adapter
with a design-house partner.

| Tool | Where the hook goes |
| --- | --- |
| Cadence Genus, Innovus (Stylus Common UI) | Flow steps are Tcl bodies, so a step's body goes inside `hslsa::step`, or small steps that call `hslsa::step_begin` and `hslsa::step_end` are added before and after the existing ones. Pass the version from the tool's own version command to `hslsa::configure` |
| Synopsys Design Compiler, IC Compiler II, Fusion Compiler, PrimeTime | The reference methodology runs one shell per stage, each from its own Tcl script; wrap the body of each stage script, or put `step_begin` and `step_end` in the stage's pre and post plug-in scripts. Steps numbered across sessions make the stages one chain |
| Siemens Calibre | Batch DRC and LVS run from SVRF rule decks, not Tcl. Run them from a Tcl wrapper (`calibredrv` or a plain `tclsh`) that calls `exec calibre ...` inside `hslsa::step signoff`, with the rule deck and waivers as `config` inputs and the results database and summary as outputs. The tool entry is then the wrapper; name Calibre's version with `-version` |

Two things the hook cannot do for a commercial flow:

- **License servers.** A Design L3 step must record its network access in
  `hwFlow.network`, filled in by the platform that enforces it ([Network
  access and licensed tools](../../spec/hslsa-v0.1.md#network-access-and-licensed-tools)).
  The hook cannot see the network, so `hslsa eda run` would have to take that
  block from the platform; it does not yet.
- **Completeness.** A record lists the files the script declared. The signer
  checks that each declared input links to an earlier record and that each
  declared output exists, but it cannot see a file the script read without
  declaring it. A tool that logs every file it opens (most write their
  command log) can be checked against the record; that check is not built.
