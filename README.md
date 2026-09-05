# HSLSA: Hardware Supply Chain Security Framework

HSLSA is a framework for proving how a chip or board was made, the way SLSA, SBOMs and in-toto do for software.

It has three parts:

- **Levels.** Five tracks (Design, Wafer, Package/Test, Assembly, Firmware), each rated L0 to L3, plus an optional L4 defense profile. A buyer asks for, say, Design L3 and Wafer L3 the way they ask for SLSA Build L3 today.
- **An attestation chain.** Signed in-toto statements for every step from RTL to a booted device, linked by digest, with physical lots and units named through device identity (DICE or Caliptra class).
- **A hardware bill of materials (HBOM).** One signed document whose subjects are the final GDS and the shipped lot, pointing at every record in the chain.

Status: working draft, version 0.1.

## Contents

| Path | What it is |
| --- | --- |
| [`spec/hslsa-v0.1.md`](spec/hslsa-v0.1.md) | The framework specification |
| [`hbom/hbom-predicate-v0.1.schema.json`](hbom/hbom-predicate-v0.1.schema.json) | JSON Schema (2020-12) for the HBOM predicate |
| [`hbom/picosoc-sky130.hbom.intoto.json`](hbom/picosoc-sky130.hbom.intoto.json) | Worked example: a PicoRV32 SoC on SkyWater SKY130 |
| [`hbom/picosoc-sky130.shipped-lot.txt`](hbom/picosoc-sky130.shipped-lot.txt) | The example's shipped-lot unit list, for recomputing its lot digest |
| [`hbom/picosoc-devboard.hbom.intoto.json`](hbom/picosoc-devboard.hbom.intoto.json) | Board-level example: the PicoSoC and off-the-shelf parts, with `parts[]` and distributor lot data |
| [`tools/hslsa/`](tools/hslsa) | Reference tooling: signs step records, builds the HBOM, and verifies the chain into SLSA VSAs |
| [`docs/e2e-test.md`](docs/e2e-test.md) | The end-to-end test in GitHub Actions: a real RTL flow, a signed lot, and verification with slsa-verifier |
| [`docs/board-example.md`](docs/board-example.md) | The board-level example: signed shipments, A1 board assembly and the board HBOM, checked in the same workflow |

## Identifiers

Predicate types and schema IDs live under `https://github.com/Horiodino/hw-slsa/`. They are identifiers and need not resolve; a custom domain can replace this prefix in a later version.
