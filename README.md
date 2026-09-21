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
| [`spec/nist-ir-8536-profile.md`](spec/nist-ir-8536-profile.md) | HSLSA as the semiconductor profile of NIST IR 8536: event and record mapping, profile requirements, gaps on both sides |
| [`hbom/hbom-predicate-v0.1.schema.json`](hbom/hbom-predicate-v0.1.schema.json) | JSON Schema (2020-12) for the HBOM predicate |
| [`hbom/picosoc-sky130.hbom.intoto.json`](hbom/picosoc-sky130.hbom.intoto.json) | Worked example: a PicoRV32 SoC on SkyWater SKY130 |
| [`hbom/picosoc-sky130.shipped-lot.txt`](hbom/picosoc-sky130.shipped-lot.txt) | The example's shipped-lot unit list, for recomputing its lot digest |
| [`hbom/picosoc-devboard.hbom.intoto.json`](hbom/picosoc-devboard.hbom.intoto.json) | Board-level example: the PicoSoC and off-the-shelf parts, with `parts[]` and distributor lot data |
| `hbom/*.cdx.json`, `hbom/*.spdx.json` | Each example HBOM rendered as CycloneDX 1.6 and SPDX 3.1-RC1 (`hslsa render`) |
| [`hbom/formats/`](hbom/formats/README.md) | The official CycloneDX 1.6 and SPDX 3.1-RC1 JSON Schemas every rendering is checked against |
| [`tools/hslsa/`](tools/hslsa) | Reference tooling in Go (`go run ./tools/hslsa/cmd/hslsa`): signs step records, builds the HBOM and renders it as CycloneDX and SPDX, and verifies the chain into SLSA VSAs |
| [`adapters/eda-tcl/`](adapters/eda-tcl/README.md) | The EDA Tcl adapter: a hook for a tool's Tcl shell that marks each design step, signed per step by `hslsa eda run` outside the tool; runs in Yosys and OpenROAD, with notes for commercial tools |
| [`docs/e2e-test.md`](docs/e2e-test.md) | The end-to-end test in GitHub Actions: a real RTL flow, a signed lot, and verification with slsa-verifier |
| [`docs/caliptra-e2e.md`](docs/caliptra-e2e.md) | The Caliptra example: from pinned RTL, ROM and firmware to units that boot and prove their identity, checked back to the RTL |
| [`docs/board-example.md`](docs/board-example.md) | The board-level example: signed shipments, A1 board assembly and the board HBOM, checked in the same workflow |
| [`docs/fpga-board-example.md`](docs/fpga-board-example.md) | The FPGA board example: an iCE40 design built with open tools, on a board whose attested root of trust verifies the flash before the FPGA runs, checked to Firmware L2 for the board |
| [`docs/selective-disclosure.md`](docs/selective-disclosure.md) | Withheld fields and verifier escrow: an auditor checks the full records, the buyer sees only the auditor's VSAs, and a measurement of what each view reveals |
| [`docs/roadmap.md`](docs/roadmap.md) | The roadmap from working draft to real-world use: phases, exit criteria and the decisions still open |

## Identifiers

Predicate types and schema IDs live under `https://github.com/Horiodino/hw-slsa/`. They are identifiers and need not resolve; a custom domain can replace this prefix in a later version.
