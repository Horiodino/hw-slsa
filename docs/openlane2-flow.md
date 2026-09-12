# OpenLane 2 flow with a signed record per step

`.github/workflows/openlane2-flow.yml` runs a real RTL-to-GDS flow and signs
every step of it. It fills the gap the PicoRV32 test leaves: that test stops at
synthesis and uses the netlist in place of the GDS, while this one runs design
steps 1 to 7 of the spec and releases a real GDS.

## What runs

| Input | Pinned as |
| --- | --- |
| Design | OpenLane's bundled `spm` example, five files at openlane2 commit `b89f786` (tag 2.3.10), frozen into `source.tar` by the existing `source-freeze` step |
| Flow | OpenLane 2.3.10, `Classic` flow, image `ghcr.io/efabless/openlane2:2.3.10` pinned by index digest |
| PDK | SKY130A, `sky130_fd_sc_hd`, open_pdks `0fe599b2` (the version OpenLane 2.3.10 expects), enabled with ciel from `fossi-foundation/ciel-releases` |

All of it is in `openlane2/spm/flow.lock.json`. OpenLane 2 is in maintenance;
its successor is LibreLane, and the wrapper only depends on the run-directory
layout (`NN-step/state_in.json`, `state_out.json`, `config.json`,
`runtime.txt`), which LibreLane keeps.

## One record per step

`hslsa openlane run` starts the container and watches the run directory from
the host. When a step finishes, OpenLane writes `runtime.txt` after
`state_out.json`. The watcher then hashes the step's files and signs its record
before it looks at the next step. The `flow-platform` key stays on the host and
never enters the container.

Each record is a design-flow statement with buildType
`.../design-flow/step/openlane2@v1`:

- **subjects**: the design views the step produced (netlist, ODB, DEF, SDC,
  SPEF, GDS and so on, annotated with the view name), plus its
  `state_out.json`, which carries the metrics.
- **resolvedDependencies**: the frozen source, the image digest, a tree digest
  of the PDK, the step's resolved `config.json`, every input view by digest, and
  the previous step's record.
- **byproducts**: the step's logs and reports.
- **hwFlow**: the OpenLane step, the spec step it belongs to (`synthesis`,
  `floorplan`, `place-cts`, `routing`, `signoff`, `gds-stream-out`), the tool
  binaries with their digests inside the image, and the metrics the step
  changed.

`hslsa openlane release` then checks the chain and the signoff metrics (route
DRC, Magic DRC and LVS must be zero, and KLayout DRC, XOR, illegal overlap and
disconnected pins must be zero when reported). It signs the final GDS as the
tapeout release with the `tapeout-authority` key. `hslsa openlane verify` is the
buyer-side check. It requires every input view to be an output of an earlier
step, every step to name the same source, image and PDK, the records to be
linked in order, all six spec steps to be present, and the released GDS to be
the one the flow produced.

## Reproducibility

The `flow` job runs once on each of two runners (builders `a` and `b`) with the
same inputs and the same workspace path. The `compare` job verifies both chains.
It then compares every subject and byproduct of every step, and classifies each
difference as one of these:

| Class | Meaning |
| --- | --- |
| `timestamps` | Equal once dates, times, durations, memory figures and host names are masked. For GDS, equal once the BGNLIB and BGNSTR dates are cleared |
| `ordering` | Same lines or GDS records, in a different order |
| `content` | A real difference; the report shows the first differing line |
| `missing` | The file exists in only one run |

The report (`reproducibility.md`, which also appears in the job summary, and
`reproducibility.json`) names the first step whose outputs differ beyond
timestamps. That step is where the two builds actually diverge. The compare job
also signs a draft `rebuild` record for the released GDS, with the checks
`gds-bit-exact` and `gds-equal-ignoring-timestamps`. This is the kind of
evidence Design L4 asks for. Here it comes from a second runner of the same
operator, so it is not yet an independent rebuild.

### First measurement (CI run 36544446344, 2026-09-08)

Both runs used identical inputs: the same source, image, PDK tree digest and
tool binaries. The flow had 74 steps and 176 attested outputs.

- 157 of the 176 outputs are bit-exact, and 69 of the 74 steps have every output
  bit-exact. This includes every netlist, ODB, DEF, LEF and SDC, and the
  DRC, LVS and XOR results.
- The other 19 differ only in embedded timestamps: the SDF headers (STA pre-
  and post-PNR), the SPEF headers (RCX), the GDS BGNLIB/BGNSTR dates from Magic
  and KLayout, and the `timestamp` line in Magic's `.mag`.
- None of the outputs differ in content, so the final GDS is equal to the
  other run's once its dates are cleared. It is not byte-identical.
- The logs and reports differ as expected, in runtimes, memory figures, host
  names and dates.

So reaching bit-exact needs no change to placement or routing. The stream-out
and extraction steps only need a fixed date, for example by setting
`SOURCE_DATE_EPOCH` or by post-processing the GDS header, and the verifier could
then require `gds-bit-exact`.

[`tools/hslsa/openlane_test.go`](../tools/hslsa/openlane_test.go) exercises the chain checks and the classifier on a
synthetic run, so the lint job covers them without OpenLane.

## Running it locally

You need docker, Go, `pip install ciel==3.0.0` (the PDK manager), and the
PDK:

```
ciel enable --pdk-root "$PWD/pdk" --pdk-family sky130 0fe599b2afb6708d281543108caf8310912f54af
PDK_ROOT=$PWD/pdk openlane2/run.sh produce
```
