# Board-level example

This example puts the PicoSoC from the [end-to-end test](e2e-test.md) on a small board, so the chain continues past the shipped chip lot into the Assembly track. It exercises the three board pieces of the spec that the chip example could not: the HBOM's `parts[]`, distributor lot data, and the A1 board assembly step. It runs in the same workflow, [`.github/workflows/hslsa-e2e.yml`](../.github/workflows/hslsa-e2e.yml), after the chip's produce and verify steps.

## The board

`PSOC-DEVB-01` rev A, defined in [`e2e/board/board-design.json`](../e2e/board/board-design.json). Its digest is the board HBOM's design subject, standing in for the full design package (schematic, Gerbers, pick-and-place) the way the netlist stands in for the GDS on the chip side.

| RefDes | Manufacturer | MPN | Part |
| --- | --- | --- | --- |
| PCB1 | Example PCB Fab | PSOC-DEVB-01-PCB | Bare board |
| U1 | Example Open Silicon Group | PSOC130-QFN64 | The example chip, with its own signed HBOM and chain |
| U2 | Winbond Electronics | W25Q128JVSIQ | 128 Mbit SPI NOR flash |
| U3 | Texas Instruments | TLV75518PDBVR | 1.8 V LDO |
| U4 | Texas Instruments | TLV75533PDBVR | 3.3 V LDO |
| Y1 | Abracon | ASE-12.000MHZ-LC-T | 12 MHz oscillator |
| C1 to C6 | Murata Electronics | GRM188R61A106KE69D | 10 uF 0603 |
| R1, R2 | YAGEO | RC0402FR-0710KL | 10 kOhm 0402 |

**Real:** the manufacturers and part numbers of the off-the-shelf parts, and everything about the chip, which comes from the chip chain. **Placeholders:** distributors, sites, shipment IDs, lot codes, date codes and dates in [`e2e/board/board-scenario.json`](../e2e/board/board-scenario.json); every one starts with `EXAMPLE` or `Example`.

## The chain

| Record | Signed by (trust root role) | Subject | Consumes (by digest) |
| --- | --- | --- | --- |
| Distribution, one per shipment | The shipper: `dist-franchised`, or `pcb-fab` shipping direct | The shipment's packing list (manufacturer, MPN, lot, date code, quantity; chip serials for the chip line) | The chip shipped lot, for the chip line |
| A1 board assembly | `ems-site` | The board lot `urn:hslsa:lot:BRD-EXAMPLE-01`, each board `urn:hslsa:board:<manufacturer>:<serial>`, and the per-serial build records | Every shipment record, the chip HBOM and F4 record, the chip shipped lot, the board design |
| Board HBOM | `board-owner` | The board design and the board lot | `parts[]` points at each shipment through `distributionRef` and at the chip's HBOM through `hbomRef`; `manufacturing.boardAssembly.attestationRef` points at A1 |

The EMS receives 8 chips from shipped lot `ASM-EXAMPLE-17`, runs the chip's tapeout and lot receipt checks on them before placement (the spec's "board assembly runs this same check on each part"), builds 6 boards and fails one at test, so the board lot holds 5 boards. The build records name the chip serial on U1 of every board and the lot of every other placement, which is the IPC-1782 style per-serial record the Assembly track asks for. The chip vendor's bundle travels inside the board bundle under `parts/picosoc/`.

## What the buyer checks

`hslsa board verify` ([`tools/hslsa/board.go`](../tools/hslsa/board.go)), then a signed SLSA VSA for the board lot checked with slsa-verifier:

1. The board HBOM is signed by the board owner, matches the schema, and its lot subject is A1's board lot.
2. A1 is signed by the EMS, passed its gates, names the same board design, and consumes every shipment record and the chip's lot and HBOM.
3. Every `parts[]` entry has a shipment record signed by the shipper the policy names, and its lot and date code match that shipment. `authorized: true` holds only if the policy lists the shipper as an authorized channel for that manufacturer, and the policy can require the authorized channel for every part.
4. The chip passes its own full chain check (tapeout and lot receipt) with its own trust root, every chip shipped to the EMS is in its shipped lot, and the board HBOM names the lot that chain proves.
5. `parts[]` covers exactly the board design's reference designators; every placement is a listed lot; no chip is placed twice or placed without being shipped; no lot is placed more often than it was shipped.
6. The board lot is the set of boards that passed test, A1's yield accounts for the rest, and every shipped board is an A1 subject. Received boards are in the lot.

[`tools/hslsa/board_test.go`](../tools/hslsa/board_test.go) breaks these links in 24 ways and requires each to fail for the stated reason, including a swapped part lot, a changed date code, flash bought from a broker (both marked unauthorized and falsely marked authorized), more parts placed than shipped, a board that claims a chip lot it did not receive, a chip that failed final test shipped to the EMS, a chip on two boards, a shipment signed by the wrong party, and a tampered record in the chip chain under the board.

## Levels claimed

The board VSA claims `HSLSA_ASSEMBLY_LEVEL_2`: A1 is signed with the EMS site key against each board serial and the serial of its key component. It is not Assembly L3, which needs an accredited site with an HSM-held key, component identities checked by attestation at build (the chip has serials, not a hardware identity) and a platform certificate. The chip keeps its own VSA with its own levels.

The board stays at Firmware L1 and records no firmware yet. The flash images would be written by the EMS in a `fw-provisioning` record, and the [board-level root of trust rule](../spec/hslsa-v0.1.md#core-requirements) for Firmware L2 does not apply because this board has no root of trust.

## Schema changes

[`hbom/hbom-predicate-v0.1.schema.json`](../hbom/hbom-predicate-v0.1.schema.json) changes in three additive ways, and the chip example still validates:

- `manufacturing.fab` is required only when `product.level` is `die` or `package`. For `module`, `board` and `system`, `manufacturing.boardAssembly` and `parts` are required instead.
- New `manufacturing.boardAssembly`: `ems`, `boardLot`, and `attestationRef` to A1.
- New `parts[].distributionRef`: the signed shipment record for that lot.

The board HBOM statement from one run is committed as [`hbom/picosoc-devboard.hbom.intoto.json`](../hbom/picosoc-devboard.hbom.intoto.json), with its board lot in [`hbom/picosoc-devboard.board-lot.txt`](../hbom/picosoc-devboard.board-lot.txt).

## Running it locally

After `e2e/run.sh produce`:

```sh
SLSA_VERIFIER=/path/to/slsa-verifier e2e/board/run.sh all
go test ./tools/hslsa/
```
