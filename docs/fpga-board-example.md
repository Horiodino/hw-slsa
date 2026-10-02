# FPGA board example: a board root of trust

This example is the first board that reaches Firmware L2. Its main part is an FPGA, a Lattice iCE40UP5K. Like the PicoSoC in the [chip example](e2e-test.md), the FPGA has no secure-boot ROM: when its reset pin (CRESET_B) rises, it loads whatever bitstream sits in its SPI flash and runs whatever firmware that bitstream's soft CPU finds there. On its own it stops at Firmware L1. The board adds a root of trust, EXR-01, that holds CRESET_B low until it has checked every image in the flash against a boot manifest signed by the board owner. That is the spec's [board-level root of trust rule](../spec/hslsa-v0.1.md#core-requirements): the root of trust is itself attested, it verifies before the SoC leaves reset, and the claim is the board's.

It runs in [`.github/workflows/fpga-board-e2e.yml`](../.github/workflows/fpga-board-e2e.yml) on pull requests and pushes that touch the tool or the example, in a few minutes, and with [`e2e/fpga/run.sh`](../e2e/fpga/run.sh) locally.

## What runs

| Stage | Plays | Does |
| --- | --- | --- |
| Root of trust vendor | Example RoT Co, its design house, fab, sort house, OSAT and test house | Runs the PicoRV32 example's design flow and lot under the name EXR-01 (its die is that design), builds the root of trust's firmware, has its code signer sign it for the part's ROM, and provisions every shipped unit at final test with a UDS, fuses, the firmware and an IDevID certificate from its identity CA. Its test station is a simulated gang programmer that writes its own export, and the [provisioning adapter](provisioning-adapter.md) signs the records from it |
| Board owner | Example Board Co, which is also the FPGA design house and firmware team | Builds PicoSoC for the iCE40 with signed records for every step, builds the SoC firmware, releases the bitstream, and builds the flash image with a boot manifest signed by its code signer and a CoRIM with the reference values its root of trust will report |
| EMS | Example EMS and its suppliers | Signs the shipments, runs the root of trust's lot receipt check before placement, signs A1 and the board HBOM, then programs each board: burns the owner fuses into its root of trust, writes the flash, powers it once, and signs one provisioning record per board |
| Boot | The buyer | Powers on each board it received: the root of trust's ROM and firmware run, then the SoC boots the firmware from that board's flash |
| Verify | The buyer | Runs every check below, signs VSAs for the FPGA design, the board lot and each booted board, and verifies them with slsa-verifier v2.7.1 |

```
e2e/fpga/run.sh produce   # root of trust vendor, board owner, EMS
e2e/fpga/run.sh boot      # power on the received boards
e2e/fpga/run.sh verify    # the buyer's checks and VSAs
e2e/fpga/run.sh l3        # the whole chain again at Firmware L3 and Assembly L3, then the refusals
e2e/fpga/run.sh l4        # and at Firmware L4 and Assembly L4, then the refusals
```

It needs Go, Yosys, nextpnr-ice40, IceStorm (with its chip database), Icarus Verilog, a RISC-V GCC (`gcc-riscv64-unknown-elf` on Ubuntu), git and ssh-keygen; `l3` and `l4` also need bubblewrap and SoftHSM2. Outputs go under `out/fpga/`.

## The board

`FPGA-DEVB-01` rev A, [`e2e/fpga/board-design.json`](../e2e/fpga/board-design.json): an iCEBreaker-like board with a root of trust added.

| RefDes | Manufacturer | MPN | Part |
| --- | --- | --- | --- |
| U1 | Lattice Semiconductor | ICE40UP5K-SG48ITR | The FPGA |
| U2 | Winbond Electronics | W25Q128JVSIQ | SPI flash: bitstream at 0, boot manifest at 0x0F0000, SoC firmware at 0x100000 |
| U5 | Example RoT Co | EXR-01 | The root of trust (simulated), with its own chain; holds U1's CRESET_B and owns the flash until it has verified it |
| U3, U4, Y1, C1 to C6, R1 to R3, PCB1 | Texas Instruments, Abracon, Murata, YAGEO, Example PCB Fab | Real part numbers | Regulators, the 12 MHz oscillator, passives, the bare board |

The board design marks U5 with `rootOfTrust`: it guards U1 and verifies `icebreaker.bin` and `picosoc-fw.bin`. The board HBOM copies that into U5's `parts[]` entry and lists both images in `firmware[]`, the bitstream with role `configuration`, each pointing at its record through `provenanceRef` and at the board CoRIM through `referenceValuesRef`.

## The FPGA design

[`e2e/fpga/inputs.lock.json`](../e2e/fpga/inputs.lock.json) pins PicoSoC and its iCEBreaker port from YosysHQ/picorv32, at the same commit the chip example uses, file by file. The board owner commits them to its own repository with the sources in their folders and freezes them with an SSH-signed tag and a review; PicoRV32 and PicoSoC each arrive with IP provenance signed by a key standing in for YosysHQ. That is Design L2, as in the chip example.

| Step | Tool | Record's gates |
| --- | --- | --- |
| `source-freeze` | git, SSH-signed tag | Inputs pinned; signed, reviewed tag; IP provenance |
| `simulation` | Icarus Verilog 12, with Yosys's iCE40 cell models | The frozen RTL boots the firmware build's image: the testbench runs, finishes, and the SoC prints its banner on the UART |
| `synthesis` | Yosys `synth_ice40 -dsp` | Synthesis and `check -assert` pass |
| `routing` | nextpnr-ice40 0.6, seed 1, for the SG48 package and the iCEBreaker pin map | Placed and routed in one run; nextpnr's own timing estimate meets its 13 MHz target (about 15 MHz) |
| `signoff` | IceStorm `icetime` | Timing met at the board's 12 MHz clock on IceStorm's timing model (about 15 MHz) |
| `bitstream` | IceStorm `icepack`, then `iceunpack` | Unpacking the bitstream gives back the routed design, apart from comments, net names and unused RAM |
| `release` | Tapeout authority | The tapeout policy check over every step, with the bitstream as the final artifact |

The design uses 4,172 of the part's 5,280 logic cells. With the same tools and seed, two runs gave the same bitstream bit for bit. Each IceStorm tool is pinned by the digest of its binary, since none prints a version.

The SoC firmware is PicoSoC's own `firmware.c`, built the way PicoSoC's Makefile builds it for the iCEBreaker, with SLSA provenance and a CycloneDX SBOM signed by the firmware build platform.

**The flash image.** The firmware build platform lays out the released bitstream and the firmware, and the board owner's code signer signs a boot manifest that lists each by offset, length and sha256. The image's provenance consumes the release record, the bitstream, the firmware's provenance and the firmware, and its byproduct is the board CoRIM: one reference value per image, at DICE layer 2, with the board's vendor and model.

## The root of trust

EXR-01 is a model, in [`tools/hslsa/rot.go`](../tools/hslsa/rot.go), of a small root of trust chip:

- **Mask ROM.** At power on it reads the firmware from its internal flash and the signature next to it, checks the signer against the vendor key hash in its fuses and the image against the signature, and refuses to run anything else. It derives its IDevID key from the UDS in its fuses, a DICE CDI from the UDS and the firmware's measurement, and from that the alias key. It issues the alias certificate, with the firmware's measurement as a TcbInfo, and hands the alias key to the firmware.
- **Firmware.** [`e2e/fpga/rot/firmware`](../e2e/fpga/rot/firmware/main.go), a real program with only the Go standard library, built reproducibly. It reads the boot manifest from the board's flash at the offset in the owner fuses, checks that its signer's key hash is the owner key hash in the fuses, checks its signature, its SVN against the owner anti-rollback fuse, and each image's digest, and only then releases CRESET_B. It reports what it verified in a platform certificate signed with the alias key: one TcbInfo per image. On a real part the same logic would run on the root of trust's own core; here the model runs it as a program.
- **Its chain.** A chip HBOM listing the firmware, firmware provenance with an SBOM and a CoRIM holding the firmware's reference value, and one provisioning record per unit from its test site, with the IDevID certificate endorsed by the vendor's identity CA. The test station is a simulated gang programmer that runs a job file and writes its own log, readback dumps and identity files; the [provisioning adapter](provisioning-adapter.md) clears the job's images against their provenance before it runs and signs the records from that export afterwards.

## What the buyer checks

`hslsa fpga verify`, in [`tools/hslsa/fpgaboard.go`](../tools/hslsa/fpgaboard.go). Before it walks the chain it lists every record it needs that is missing.

1. **Board receipt.** The [board receipt check](board-example.md#what-the-buyer-checks) from the board example, unchanged: board HBOM, A1, every shipment, the authorized channel for every part, and the root of trust's own tapeout and lot receipt checks with its vendor's trust root, plus the EMS's receipt for its lot.
2. **FPGA design.** The tapeout check on the board owner's design records, under the buyer's policy: every step signed by the flow platform, linked by digest, with allowed tools and passed gates, and the Design L2 source and IP rules.
3. **Images.** The firmware has provenance and an SBOM. The boot manifest is signed by the owner's code signer, lists exactly the released bitstream and that firmware, and is the manifest in the flash image at the offset its provenance states. The flash image's provenance consumes the release and both images, the board CoRIM holds exactly the manifest's reference values, and the board HBOM's `firmware[]` entries match and point at their records.
4. **Root of trust rule.** One part is marked as root of trust, the policy accepts it, it has its own HBOM (so step 1 checked its chain), it guards U1, and it verifies every image in the flash. Its firmware has provenance, an SBOM and a CoRIM with exactly that image's reference value, its vendor's code signer signed it, and its HBOM lists it.
5. **Provisioning, every board in the lot.** Signed by the EMS station, every gate passed (including a first boot in which the root of trust released the FPGA), wrote the checked flash image, burned the owner's code signer as owner key, and names the root of trust unit A1 placed on that board. That unit's own provisioning record is signed by its vendor's test site, passed, wrote the firmware with provenance, has its vendor's code signer in the key fuse, and has an IDevID certificate endorsed by the vendor's identity CA. The board's subject is that IDevID key.
6. **At boot, every received board.** The root of trust released the FPGA. Its alias certificate is signed by that unit's IDevID key and the platform certificate by the alias key, both naming the unit's UEID. The root of trust's firmware measurement matches its CoRIM, and the platform certificate reports both images, each matching the board CoRIM. The SoC then printed its boot banner.
7. **Renderings.** The board HBOM's CycloneDX and SPDX renderings are what it renders to.

The board VSA claims `HSLSA_ASSEMBLY_LEVEL_2` and `HSLSA_FIRMWARE_LEVEL_2` for the board lot, and each booted board gets its own VSA for the same levels, whose subject is the board's URN with the sha256 of its root of trust's IDevID certificate. The FPGA design gets `HSLSA_DESIGN_LEVEL_2` and `SLSA_BUILD_LEVEL_2`. Nothing here claims Firmware L2 for the iCE40 itself.

## At Firmware L3

`e2e/fpga/run.sh l3` makes the whole chain again under the buyer's L3 policies, [`e2e/fpga/l3/policy.json`](../e2e/fpga/l3/policy.json) for the board and [`e2e/fpga/l3/rot-policy.json`](../e2e/fpga/l3/rot-policy.json) for the root of trust, and the board VSAs then state `HSLSA_ASSEMBLY_LEVEL_3` and `HSLSA_FIRMWARE_LEVEL_3`. What changes ([levels](levels.md#firmware-l3)):

- **Every site that provisions the board is rated L3 in its own track.** The root of trust's lot is at Wafer L3 and Package/Test L3: site keys in an HSM (SoftHSM), the fab's check of the release, an identity for every die at wafer sort that the part's ROM then uses as its IDevID, and units named by their certificate. The board is at Assembly L3: the EMS challenges each root of trust before placing it, and the board owner's platform CA signs a platform certificate per board. Both trust roots are buyer-run, with every key enrolled.
- **Both firmware builds run in the sandbox.** `fpga firmware --isolate` and `fpga rot-firmware --isolate` build with no network and nothing of the host but read-only tools. The SoC firmware's record pins the RISC-V GCC and binutils packages, and the root of trust's the Go toolchain; the buyer's policies pin the same in `firmware.toolPins`. The images come out bit for bit the same as outside the sandbox.
- **Each image is reviewed.** A review lab, enrolled in both trust roots, signs a S.A.F.E. report for the SoC firmware and for the root of trust firmware (simulated: no review took place).
- **Every release is in the buyer's release log.** The root of trust firmware, the SoC firmware and the flash image each go into a private log with `hslsa tlog add`, and each carries its inclusion proof. The buyer keeps a checkpoint from its first look and later checks that the log only grew.
- **Boot evidence is required.** The buyer passes the boards it received, which answer a challenge, and what they reported at boot.

Then it shows what Firmware L3 refuses: a flash image not in the log, releases in a log the buyer does not read, firmware built with a compiler the policy does not pin, firmware no lab reviewed, boards with no boot evidence, a root of trust provisioned at a test house the buyer rates below L3, and a log that rewrote a release it had shown. The CI job `l3` runs it with the RISC-V packages at the versions the policy pins.

## At Firmware L4

`e2e/fpga/run.sh l4` makes the chain once more under [`e2e/fpga/l4/policy.json`](../e2e/fpga/l4/policy.json) and [`e2e/fpga/l4/rot-policy.json`](../e2e/fpga/l4/rot-policy.json), and the board VSAs state `HSLSA_ASSEMBLY_LEVEL_4` and `HSLSA_FIRMWARE_LEVEL_4`. On top of L3 ([levels](levels.md#firmware-l4)):

- **A second builder reproduces every image built from source.** A rebuilder the buyer enrolls under its own company rebuilds the root of trust firmware (`fpga rot-firmware-rebuild`), the SoC firmware (`fpga firmware-rebuild`) and the bitstream (`design rebuild`), isolated, from the pinned sources, and each comes out bit for bit the released one. The flash image is laid out from those and signed by the code signer, so it is not rebuilt; the root of trust checks its signature at boot.
- **Two people approve every release.** Two release managers each sign an approval of each firmware release record with `hslsa release approve`.
- **An independent lab inspects both lots.** It commits to a seed before final test seals the root of trust's lot and before the EMS seals the board lot, then delayers two units of the root of trust (Wafer L4 and Package/Test L4) and X-rays two boards (Assembly L4). The boards are built from the units the lab left.
- **Per-unit data is read back.** Every provisioning record's image and fuse readback must pass, and every provisioning site must be rated L4 in its own track.

Then it shows what L4 refuses: a flash image only one person approved, SoC firmware nobody else rebuilt, a rebuild by the board owner itself, boards inspected by the EMS's own lab, and a root of trust provisioned at a test house the buyer rates below L4. The same CI job runs it after `l3`.

## What the tamper tests prove

[`tools/hslsa/fpga_test.go`](../tools/hslsa/fpga_test.go) breaks the chain in 20 ways on a copy of the produced example, with the keys the run made, and requires each to fail for the stated reason. Four of them change a programmed board and power it on again, so the root of trust itself has to refuse:

- one bit flipped in the bitstream in flash;
- a boot manifest signed by another key, over the same images;
- the root of trust's own firmware patched, which its ROM refuses to run;
- the owner anti-rollback fuse raised above the image's SVN.

The others forge records or evidence: boot certificates copied from another board, a SoC that never printed its banner, an unreadable platform certificate; a root of trust with no chain of its own, one that does not guard the FPGA, one that skips an image, and a board with none marked; a board HBOM naming another bitstream; a missing board provisioning record; an EMS record naming another root of trust unit, another owner key, or a failed gate; a root of trust unit whose vendor recorded a failed fuse readback, or whose record writes an image no provenance names or one it did not check; root of trust firmware signed by a key that is not its vendor's; a board CoRIM signed by someone else; and a flash image built around a bitstream the tapeout authority never released.

## What is simulated

- **The board.** Nothing here touches hardware. The bitstream is built for the real part, but no FPGA loads it; the SoC boots in RTL simulation of the frozen design (the same testbench as the `simulation` step, with the firmware read from each board's flash). A simulation of the routed design would tie the boot to the bitstream itself, but it did not run here: Icarus is too slow for it, and the routed netlist uses iCE40 RAM and DSP cells with no simulation models in the open tools.
- **The root of trust.** EXR-01 is a model. Its die is the PicoRV32 example's design under another name, and its ROM, fuses and DICE derivation are Go code in the tool. Its firmware is real code, but runs on the host, not on a root of trust core.
- **Manufacturing.** As in the other examples, shipments, lots, yields, test results and every site are placeholders, and every party's key is generated per run.

## Moving to a real board

The FPGA and tools were picked so a real board can follow: the iCEBreaker (1BitSquared, about $70) carries the same iCE40UP5K-SG48 and flash, and this flow already builds its bitstream. Two things stand in the way of a real Firmware L2 board:

1. **The board's own programmer.** An iCEBreaker's FTDI chip can write the flash and pulse CRESET_B by itself, which bypasses any root of trust. A real board for this example needs the root of trust wired between them: it owns CRESET_B and the flash's chip select, and the FTDI path is removed or goes through it.
2. **An attested root of trust.** The rule needs a root of trust with its own chain at Firmware L2. Microcontrollers with secure boot that could do this job exist (an RP2350, for example), but no vendor signs HSLSA records for them, and a chain signed on a vendor's behalf is held at L1 under rule 4 of the spec. So with a real off-the-shelf root of trust, the board would stay at Firmware L1 until that vendor signs, even though the check itself would run unchanged.

The at-boot evidence would then come from the real root of trust over its debug UART or USB, on the self-hosted runner with the board attached, and the boot step would read the SoC's real UART instead of a simulation.

## Keys and privacy

As in every example: local ECDSA P-256 keys in DSSE envelopes, no OIDC token, nothing sent to a public transparency log; the L3 run's release log is a private one in `out/fpga/l3/release-log`. The CI job deletes every private key, the root of trust units (whose fuses hold their UDS) and the programmed boards before it uploads the board bundle and the boot evidence for the buyer's job.
