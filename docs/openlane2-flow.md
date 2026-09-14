# OpenLane 2 flow with a signed record per step

`.github/workflows/openlane2-flow.yml` runs a real RTL-to-GDS flow and signs
every step of it. It fills the gap the PicoRV32 test leaves: that test stops at
synthesis and uses the netlist in place of the GDS, while this one runs design
steps 1 to 7 of the spec and releases a real GDS. A second builder then
rebuilds the release byte for byte and signs the spec's `rebuild` record, and
the buyer's tapeout check requires it.

Three jobs play three parties:

| Job | Party | Holds | Does |
| --- | --- | --- | --- |
| `flow` | Design house | `flow-platform` and `tapeout-authority` keys | Runs the flow, signs every step and the release |
| `rebuild` | Second builder | Its own `flow-platform`, `tapeout-authority` and `rebuilder` keys, and its own builder id | Gets only the release bundle, runs the same flow from the pinned inputs, compares every step, signs the `rebuild` record |
| `verify` | Buyer | Both public trust roots | Runs the tapeout check and requires a bit-exact rebuild |

## What runs

| Input | Pinned as |
| --- | --- |
| Design | OpenLane's bundled `spm` example, five files at openlane2 commit `b89f786` (tag 2.3.10), frozen into `source.tar` by the existing `source-freeze` step |
| Flow | OpenLane 2.3.10, `Classic` flow, image `ghcr.io/efabless/openlane2:2.3.10` pinned by index digest |
| PDK | SKY130A, `sky130_fd_sc_hd`, open_pdks `0fe599b2` (the version OpenLane 2.3.10 expects), enabled with ciel from `fossi-foundation/ciel-releases` |
| Dates | `SOURCE_DATE_EPOCH` 1740144248 (the source commit's time) and a [script overlay](../openlane2/overlay/README.md) that makes Magic, KLayout, OpenSTA and OpenRCX use it or write no date |

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
  of the PDK, a tree digest of the script overlay, the step's resolved
  `config.json`, every input view by digest, and the previous step's record.
  `externalParameters.sourceDateEpoch` carries `SOURCE_DATE_EPOCH`.
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
step, every step to name the same source, image, PDK, overlay and
`SOURCE_DATE_EPOCH`, the records to be linked in order, all six spec steps to be
present, and the released GDS to be the one the flow produced.

## Reproducibility

Before this example pinned any dates, two runs on the same inputs matched on
157 of 176 outputs (CI run 36544446344). The other 19, including the final GDS,
differed only in dates that four tools write:

| Tool | Output | Date |
| --- | --- | --- |
| OpenSTA | SDF from STA before and after place and route (12 files) | `DATE` header |
| OpenRCX | SPEF (3 corners) | `*DATE` header |
| Magic | GDS (`spm.magic.gds` and its copy `spm.gds`), `.mag` | BGNLIB and BGNSTR dates; `timestamp` line |
| KLayout | GDS (`spm.klayout.gds`) | BGNLIB and BGNSTR dates |

None differed in content, so placement and routing were already
deterministic. The [script overlay](../openlane2/overlay/README.md) patches
the three OpenLane scripts that drive those tools, so each one writes
`SOURCE_DATE_EPOCH` or, where the tool has its own option, no date. The run
bind-mounts the patched files read-only over the image's copies, after
checking that each copy is the file the patch was made from. The overlay is
an input of every step record.

`hslsa openlane compare` verifies both chains, then compares every subject and
byproduct of every step and classifies each difference:

| Class | Meaning |
| --- | --- |
| `timestamps` | Equal once dates, times, durations, memory figures and host names are masked. For GDS, equal once the BGNLIB and BGNSTR dates are cleared |
| `ordering` | Same lines or GDS records, in a different order |
| `content` | A real difference; the report shows the first differing line |
| `missing` | The file exists in only one run |

The report (`reproducibility.md`, which also appears in the rebuild job's
summary, and `reproducibility.json`) names the first step whose outputs differ
beyond timestamps.

### With the overlay

Pending: the per-output result of the first CI run with the overlay goes here.

The logs and reports still differ, in runtimes, memory figures, host names and
dates. They are byproducts, not design outputs, and nothing downstream reads
them.

## The rebuild and the buyer's check

The rebuild job gets the release bundle and nothing else from the design
house: no keys and no workspace. It checks the release, runs the same flow from
the pinned inputs under its own keys, and compares every step with the
release. It then signs the `rebuild` record with a `rebuilder` key in a trust
root of its own (`rebuilder-trust-root.json`). The record's subject is the
released GDS, its dependencies are the release attestation and the source,
image, PDK and overlay the rebuild used, and `hwFlow.checks` has
`gds-bit-exact` and `gds-equal-ignoring-timestamps`. It signs under its own
builder id (`HSLSA_BUILDER_ID`, the workflow ref with `#rebuild`).

The buyer runs:

```
hslsa openlane verify --bundle RELEASE --run-dir RELEASE/run --trust-root RELEASE/trust-root.json \
  --rebuild REBUILD/rebuild.intoto.json --rebuild-trust-root REBUILD/rebuilder-trust-root.json
```

After the usual tapeout check it accepts the rebuild only if the record is
signed by the rebuilder's key, none of the rebuilder's keys is a key in the
design house's trust root, its builder id is not the builder of any flow step,
its subject is the released GDS, it names this release, it used the same
source, image, PDK, overlay and `SOURCE_DATE_EPOCH`, and the required check
passes. `--rebuild-check` names that check and defaults to `gds-bit-exact`; a
buyer whose policy accepts timestamp-only differences passes
`gds-equal-ignoring-timestamps`.

### What is and is not independent here

The rebuild runs on its own runner with its own keys, trust root and builder
id, and the verifier rejects it if any of those is the design house's. But
both jobs run in this repository under one GitHub account, so whoever controls
that account controls both builders. That is enough to show the record, the
checks and a byte-identical rebuild, not to claim an independently operated
second builder. Getting there means running the `rebuild` job under a
separate account or organization (a copy of the job plus the release bundle),
and giving the buyer that builder's trust root. Records cannot show who
operates a key, so the buyer has to establish that when it accepts the key.

[`tools/hslsa/openlane_test.go`](../tools/hslsa/openlane_test.go) exercises
the chain checks, the classifier, the overlay check and each rebuild rejection
on a synthetic run, so the lint job covers them without OpenLane.

## Running it locally

You need docker, Go, `pip install ciel==3.0.0` (the PDK manager), and the
PDK:

```
ciel enable --pdk-root "$PWD/pdk" --pdk-family sky130 0fe599b2afb6708d281543108caf8310912f54af
PDK_ROOT=$PWD/pdk openlane2/run.sh produce
mv out/openlane2/bundle release
PDK_ROOT=$PWD/pdk openlane2/run.sh rebuild release
openlane2/run.sh verify release out/openlane2/report
```

OpenLane writes absolute paths into its state and config files, so a rebuild
matches every output only when it runs at the same checkout and `PDK_ROOT`
paths as the release, as the two CI jobs do.
