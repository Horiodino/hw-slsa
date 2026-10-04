# Distributor importer: shipments from what shippers already send

A distributor, or a manufacturer shipping direct, already sends a packing list and a certificate of conformance with every shipment, and some also publish GS1 EPCIS events. The importer reads those files unchanged and turns them into the shipments a board's [distribution records](../spec/hslsa-v0.1.md#distribution-record) are signed from. Each record then carries the files it was made from, so the buyer's board receipt check can read them again and check that the record says exactly what they say. This is the "Distributor importer" row of phase 3 in the [roadmap](roadmap.md), and spec revision 18 describes the record ([Records from a shipper's exports](../spec/hslsa-v0.1.md#distribution-record)).

There is no real distributor here. The example uses sample exports for the two shipments of the [board example](board-example.md), written the way a shipper would send them, and the importer turns them into the same shipments the board scenario lists.

## Run it

```bash
e2e/run.sh produce          # the chip lot the board is built on
e2e/board/run.sh produce    # the board example
e2e/board/run.sh import     # the board again, its shipments imported, in out/board-imported
```

Or by hand:

```bash
hslsa import-shipments --config e2e/board/distributor-exports/shipments.json \
  --scenario e2e/board/board-scenario.json --out out/board-imported/scenario.json
hslsa board produce --bundle out/board-imported/bundle --chip-bundle out/bundle \
  --scenario out/board-imported/scenario.json --design e2e/board/board-design.json \
  --policy e2e/board/policy.json --keys out/board-keys
```

`import-shipments` writes a board scenario: the one given, with each shipment the configuration lists replaced by what the importer read from its exports. Every other key, and any shipment the configuration does not list, stays as it was.

## The exports

All of these are in [`e2e/board/distributor-exports/`](../e2e/board/distributor-exports/). [`shipments.json`](../e2e/board/distributor-exports/shipments.json) lists each shipment's files and their formats.

| Format | File | The importer reads |
| --- | --- | --- |
| `packing-list-csv` | `packing-list-EXAMPLE-SHIP-0001.csv`, `-0002.csv` | One row per line, with the columns `shipment_id`, `ship_date`, `shipper`, `shipper_country`, `manufacturer`, `mpn`, `lot`, `date_code`, `quantity`, `serials` (separated by `\|`, for parts that have them) and `coc`, the file name of the certificate that covers the line |
| `certificate-of-conformance` | `coc-EXAMPLE-SHIP-0001.txt`, `-0002.txt` | Nothing inside: it is carried by digest |
| `epcis-2.0-json` | `epcis-EXAMPLE-SHIP-0001.json` (the distributor's only) | An EPCIS 2.0 document in JSON-LD; the one `ObjectEvent` whose `bizStep` is shipping, its `eventID` and `eventTime` |

Before it writes anything, the importer checks that the files describe one shipment:

- every row of the packing list is in the same shipment, from the same shipper on the same date;
- every line names a manufacturer, an MPN, a lot and a positive quantity, and a line with serials lists exactly its quantity of them;
- every line names a certificate of conformance that is among the shipment's files, and every certificate covers at least one line;
- the EPCIS document, when there is one, holds exactly one shipping event, on the packing list's ship date.

The importer does not read what a certificate says. A certificate is a document a person signs, in any layout; the importer only makes sure each line has one and that the file the record names is the file the shipper sent. It does not map the EPCIS event's GTINs to the lines' part numbers either, which needs the shipper's GTIN list; the event is supplemental evidence that the shipper recorded a shipment that day.

## What the records say

Each distribution record is the record the board scenario makes, plus its exports:

- `buildDefinition.resolvedDependencies` lists each export by file digest, and the bundle carries the files in `artifacts/`;
- `hwMfg.importer` names the importer (`id`) and each export by `name` and `format`.

The shipment data file the record names (`shipment-<id>.json`, its subject) holds exactly what the importer read: the shipment id, shipper and date, the lines with their lot, date code, quantity, serials and certificate by name and digest, and the EPCIS event's id and time. The signer is the shipper, as before.

## The buyer's check

The board receipt check runs the importer again on the exports in the bundle and requires the shipment data to be exactly what it reads:

```
read again from the shippers' exports the distribution records carry:
  distribution mfg-distribution-EXAMPLE-SHIP-0001.intoto.json: matches packing-list-EXAMPLE-SHIP-0001.csv, coc-EXAMPLE-SHIP-0001.txt, epcis-EXAMPLE-SHIP-0001.json
  distribution mfg-distribution-EXAMPLE-SHIP-0002.intoto.json: matches packing-list-EXAMPLE-SHIP-0002.csv, coc-EXAMPLE-SHIP-0002.txt
```

A buyer that wants every shipment checkable this way sets `requireShipmentExports` in its board policy. The verifier then refuses a distribution record that carries no exports, which is how `e2e/board/run.sh import` shows the main board bundle failing that policy.

The tests in [`distimport_test.go`](../tools/hslsa/distimport_test.go) accept the imported shipments and check that each line and the EPCIS event came through. They refuse:

- a policy that requires exports, on shipments without them;
- a certificate changed after the record was signed;
- a shipper that signs a shipment with another date code than its packing list says;
- a line with no certificate, and a certificate that covers no line;
- serials that do not match a line's quantity;
- an EPCIS shipping event on another day than the ship date, and a second shipping event;
- rows from two shipments in one packing list.

## Limits

- **The exports are samples.** They are written the way a shipper would write them, but no distributor sent them, and the certificates say so. The roadmap's exit for this importer is a real shipper's files turned into valid records without manual editing.
- **The packing list's columns are this importer's.** Every distributor lays out its packing list differently, so a real one needs a small mapping that writes these columns, as for the [MES adapter](mes-stdf-adapter.md).
- **Certificates are carried, not read.** The record proves which certificate the shipper sent, not what it certifies.
- **EPCIS is shipping only.** Receiving and storage events, and mapping GTINs to parts, are not done; storage is still not recorded anywhere in the chain ([Scope](../spec/hslsa-v0.1.md#overview)).
- **Agreement is not truth.** The check shows that the record says what the shipper's own files say, which is the limit of any signed record.
