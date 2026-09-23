# MES and STDF adapter: records from what suppliers already export

A fab, a sort house, an OSAT and a test house already write down everything an HSLSA record says. Their MES keeps a lot history and a unit genealogy, and their testers write STDF files and wafer maps. The adapter reads those exports unchanged and turns them into the Wafer and Package/Test records (F1 to F4). Each record then carries the exports it was made from, so the buyer's verifier can read them again and check that the record says exactly what they say. This is the "MES and test sidecar" row of phase 3 in the [roadmap](roadmap.md).

There is no real tester or MES here. The example uses sample exports for the [PicoRV32 lot](e2e-test.md), written the way each site would write them, and the adapter turns them into the same lot, with the same 37 units and the same lot digest.

## Run it

```bash
e2e/run.sh produce   # the main example: design records, keys and the scenario's lot
e2e/run.sh adapt     # the same lot made from the exports, in out/adapted, then again with final test proxy-signed
```

Or one step at a time:

```bash
hslsa adapt --config e2e/picorv32/supplier-exports/adapter.json --out out/adapted/scenario.json
hslsa mfg   --bundle out/adapted --scenario out/adapted/scenario.json --keys out/keys
```

`hslsa adapt` writes the same kind of scenario `mfg` and `hbom` already take. Every value in it comes from the exports. The configuration only says which site hands over which file, and which MES operation stands for which of the record's checks.

## The exports

All of these are in [`e2e/picorv32/supplier-exports/`](../e2e/picorv32/supplier-exports/).

| Site | File | Format | The adapter reads |
| --- | --- | --- | --- |
| Example Wafer Fab | `fab-mes-lot-history.csv` | MES lot history | The `LOT_START` (lot id, wafer ids, `mask_set`, `process`), and the `TRACK_OUT` of `MASK GDS XOR` and `INLINE PARAMETRICS` |
| Example Sort House | `sort-LOT-EXAMPLE-A.stdf` | STDF V4 | The MIR (lot, probe program and revision), and a PRR per die inside each wafer's WIR and WRR (X, Y, pass or fail) |
| Example Sort House | `sort-LOT-EXAMPLE-A-W01.xml`, `-W02.xml` | SEMI E142 substrate maps | Each wafer's bin code map and which bins are `Pass` |
| Example OSAT | `osat-mes-lot-history.csv` | MES lot history | The assembly lot's `LOT_START` (`source_lot`, `package`), and the `TRACK_OUT` of die attach, wire bond, X-ray sample and marking |
| Example OSAT | `osat-mes-genealogy.csv` | MES unit genealogy | Each unit's serial, assembly lot, wafer lot, wafer and die |
| Example Test House | `ft-ASM-EXAMPLE-17.stdf` | STDF V4 | The MIR (assembly lot, test program and revision), and a PRR per unit by `PART_ID` |

The STDF files are binary and carry what a tester writes beyond what the adapter reads: parametric results (PTRs), bin summaries (HBRs) and wafer results (WRRs). The STDF reader takes either byte order, reads the records it needs, and skips any others. A part tested twice counts only when its second PRR is marked as a retest. The wafer maps follow the structure of E142's XML schema (layouts, substrates, a substrate map with a bin code map), and the reader matches element names without their namespace. They have not been validated against SEMI's schema file, which SEMI sells.

The two MES files use column names this adapter defines: `timestamp, facility, lot_id, event, operation, quantity, material_ids, attributes` for a lot history, and `unit_id, lot_id, source_lot_id, wafer_id, die_x, die_y` for a genealogy. Every MES names its columns differently, so a real site needs a report or a small mapping that writes these columns.

The samples are made from the main example's scenario by a generator in [`adapt_test.go`](../tools/hslsa/adapt_test.go), and a test fails if the committed files ever differ from what it writes (`go test ./tools/hslsa -run TestSampleExportsAreCurrent -update-exports` rewrites them).

Before it writes anything, the adapter checks that the exports describe one lot as it moved from site to site. The sort STDF tested the wafers the fab started. Each wafer map agrees with the STDF results die by die. The OSAT started its lot from that wafer lot, and each unit sits on a die that passed sort and that no other unit holds. Final test tested exactly the units the OSAT packaged. A failed MES operation becomes a failed check in the record, which the verifier refuses as a failed gate.

## What the records say

Each record is the same record the scenario makes, plus its exports:

- `buildDefinition.resolvedDependencies` lists each export by file digest, and the bundle carries the files in `artifacts/`;
- `hwMfg.adapter` names the adapter (`id`), each export by `name` and `format` (`mes-lot-history`, `mes-genealogy`, `stdf-v4` or `semi-e142`), and the settings it was read with (`settings.checks`, which operation is which check).

The signer is the site, as before. A site that runs the adapter signs its own record and its track can reach L2. The adapter does not change who signs or what level a track reaches.

## The buyer's check

The verifier runs the adapter again on the exports in the bundle and compares, step by step:

| Record | Must match the exports in |
| --- | --- |
| F1 | Wafer lot id and wafer list (through the wafer lot digest), mask set, process node, checks |
| F2 | Lot id, probe program, every die's bin in `wafer-maps.json`, yield |
| F3 | Assembly lot, package type, the wafer lot it came from, `genealogy.json` unit by unit, checks |
| F4 | Lot id, test program, every unit's result in `final-test-results.json` |

```
lot receipt check: PASSED for urn:hslsa:lot:ASM-EXAMPLE-17 sha256:4876860b..., 3 received units found in the lot
read again from the supplier exports the records carry:
  wafer-fab: matches fab-mes-lot-history.csv
  wafer-sort: matches sort-LOT-EXAMPLE-A.stdf, sort-LOT-EXAMPLE-A-W01.xml, sort-LOT-EXAMPLE-A-W02.xml
  packaging: matches osat-mes-lot-history.csv, osat-mes-genealogy.csv
  final-test: matches ft-ASM-EXAMPLE-17.stdf
```

A buyer that wants every record checkable this way sets `manufacturing.requireExports` in its policy ([`policy.json`](../e2e/picorv32/supplier-exports/policy.json)). The verifier then refuses a record that carries no exports, which is how `run.sh adapt` shows the main example's lot failing that policy.

The tests in [`adapt_test.go`](../tools/hslsa/adapt_test.go) cover:

- an export changed after signing;
- a test house that signs a record passing a unit its own STDF file failed (the signature is good, the export disagrees);
- an export left out of `resolvedDependencies`;
- a wafer map that disagrees with the STDF results;
- a unit on a die that failed sort;
- an assembly lot started from another wafer lot;
- an MES export missing an operation a check needs.

## A test house that signs nothing

[`adapter-proxy.json`](../e2e/picorv32/supplier-exports/adapter-proxy.json) is the same configuration plus `"unsigned": {"final-test": {"cover": "proxy"}}`. The test house runs no adapter and signs nothing. It hands its STDF file to the product owner, which runs the adapter and [proxy-signs](proxy-signing.md) F4. The record carries the STDF file like any other, so the verifier still checks every unit's result against it. The proxy's export is still there too. The Package/Test track is held at L1, as for any proxy-signed record, and [`policy-proxy.json`](../e2e/picorv32/supplier-exports/policy-proxy.json) accepts that. An evidence record cannot be made this way: it is for a supplier that hands over no data.

## Limits

- **The exports are samples.** They are written the way a site would write them, but no tester or MES wrote them. The roadmap's exit for this adapter is a real export turned into valid records without manual editing, which needs a site's real files (phase 4).
- **Carrying exports discloses them.** A buyer holding the bundle sees every parametric value, die position and MES operation. The tool refuses to combine exports with [withheld fields](selective-disclosure.md) for now, since the exports would show the withheld values. A supplier that will not disclose its data can still sign records without exports, and [verifier escrow](selective-disclosure.md#verifier-escrow) is the way to have an auditor check them.
- **Agreement is not truth.** The check shows that the record says what the supplier's own files say. It cannot show that the tester measured what its file reports, which is the same limit as for any signed record.
- **Transfers and receipts still come from the scenario.** The MES lot histories have `SHIP` and `RECEIVE` events, but the adapter does not yet read the packing lists of the [transfers](../spec/hslsa-v0.1.md#transfers-between-manufacturing-sites) from them.
- **Only the subset of E142 a sort map uses.** The adapter reads one bin code map per wafer, `HexaDecimal` or `ASCII` bin codes, and an origin at the upper or lower left.
