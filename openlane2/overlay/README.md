# Script overlay for a bit-exact OpenLane 2 run

Two runs of the OpenLane 2.3.10 flow on the same inputs produce the same
layout, but 19 of their 176 outputs still differ, because four tools write the
current time into them. This overlay removes those dates. It is the only
change to the pinned flow, and every step record names it.

`scripts/` holds patched copies of three files from OpenLane's own `scripts`
directory, as the pinned image carries them. Two are the files at tag 2.3.10.
The image's `klayout/stream_out.py` differs from the tag in its first line
only: the image's Nix build rewrote `#!/usr/bin/env python3` to the store path
of its own Python, and OpenLane runs the script with its own interpreter, so
the line is not used. The overlay keeps the image's line, so each patched file
differs from the file it replaces only by the change below and a comment after its license header that names the change, as the Apache License 2.0 asks of a modified file. `hslsa openlane run` bind-mounts each one read-only
over the image's copy, after checking that the image's copy is the file the
patch was made from (`reproducibility.overlay.replaces` in
[`../spm/flow.lock.json`](../spm/flow.lock.json) pins the image's copy of each
file by sha256). It also passes `SOURCE_DATE_EPOCH` from the lock into the container.
Without `SOURCE_DATE_EPOCH`, each patched script behaves exactly like the
original.

| File | Tool and output | Change |
| --- | --- | --- |
| `openroad/common/io.tcl` | OpenSTA SDF (`DATE`) | Pass `-no_timestamp` to `write_sdf`, OpenSTA's own option, as OpenLane already does for `write_sdc` |
| `openroad/common/io.tcl` | OpenRCX SPEF (`*DATE`) | OpenRCX has no option, so rewrite that one header line with `SOURCE_DATE_EPOCH`, in the same format, in UTC |
| `magic/def/mag_gds.tcl` | Magic `.mag` (`timestamp`) | `cellname timestamp` sets the top cell's timestamp to `SOURCE_DATE_EPOCH` before `save` |
| `magic/def/mag_gds.tcl` | Magic GDS (BGNLIB and BGNSTR dates) | `gds datestamp` sets each creation date to `SOURCE_DATE_EPOCH`. Magic always writes the current time as the modification date, so after `gds write` each BGNLIB and BGNSTR record's creation date is copied over its modification date. Nothing else in the file changes |
| `klayout/stream_out.py` | KLayout GDS (BGNLIB and BGNSTR dates) | Write with `gds2_write_timestamps` off, KLayout's own option, which writes zero dates |

`SOURCE_DATE_EPOCH` is 1740144248 (2025-02-21 13:24:08 UTC), the committer
time of OpenLane commit `b89f786`, which the `spm` source is frozen from. This
follows the [reproducible-builds convention](https://reproducible-builds.org/specs/source-date-epoch/):
a build that must embed a date uses the source's last change, not the time it
ran.

## Why an overlay and not a post-processing step

Later steps read these files while the flow runs: KLayout XOR and the DRC and
LVS steps read the GDS, and STA reads the SPEF. Fixing the dates after the
flow would leave every step record naming files that no longer exist. Fixing
them inside the step that writes them keeps every record, every input digest
and the released GDS consistent.

## Moving to a new OpenLane version

The run stops if the image's copy of a replaced script is not the pinned
file, and its error names the image's digest and first line for each one that
differs. To move to a new image, copy the three files out of the new image,
reapply the changes above, and update the digests in the lock. Newer
Magic, OpenROAD or KLayout releases may honour `SOURCE_DATE_EPOCH` on their
own, and then the matching change can go.
