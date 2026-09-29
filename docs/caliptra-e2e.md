# Caliptra example: RTL to a booted device

The workflow in [`.github/workflows/caliptra-e2e.yml`](../.github/workflows/caliptra-e2e.yml) runs the whole HSLSA chain on a part with a hardware identity. It starts from the pinned [Caliptra](https://github.com/chipsalliance/caliptra-rtl) RTL and ends with a buyer powering on the units it received, reading each unit's DICE certificates, and walking by digest from those certificates back to the RTL, the ROM and every firmware image. It is the example the spec's [at-boot check](../spec/hslsa-v0.1.md#where-the-chain-is-checked) was written for, and it goes past the PicoRV32 example's Firmware L1 cap because Caliptra's ROM verifies firmware before running it.

## What runs

| Job | Plays | Does |
| --- | --- | --- |
| Produce | Firmware team, design house, tapeout authority, fab, sort house, OSAT, test house and its programming station, product owner | Builds the ROM and the signed FMC + runtime bundle with `caliptra-builder`, lints the RTL, merges the ROM into the design, releases it, signs F1 to F4 for a lot, programs every shipped unit and exports its IDevID CSR from the real ROM, endorses it, signs one `fw-provisioning` record per unit, signs a CoRIM with the reference values for the FMC and runtime, builds the HBOM and its CycloneDX and SPDX renderings, signs simulated S.A.F.E. review reports for the ROM, FMC and runtime |
| Verify | Buyer | Boots the three units it received, checks that the ROM refuses tampered firmware, runs the tapeout, lot, firmware, firmware review and at-boot checks and the renderings check, appraises each unit's measurements against the CoRIM and has Veraison's cocli decode it, signs six SLSA VSAs, verifies them with slsa-verifier v2.7.1, then runs the tamper tests |
| Verify on the RTL | Buyer, with the device built from the released design | Verilates the released design, then for one received unit (`rtl-units` sets how many) either runs the ROM until it exports the IDevID CSR and checks the key against the endorsed IDevID certificate (`rtl-stage: identity`, the default), or boots to runtime and runs the same checks and slsa-verifier calls as Verify (`rtl-stage: boot`). Runs only when dispatched by hand with `rtl` set; see [Booting on the RTL](#booting-on-the-rtl) |

All sources are pinned in [`e2e/caliptra/caliptra.lock.json`](../e2e/caliptra/caliptra.lock.json): caliptra-sw at tag `fw-2.1.3`, and the caliptra-rtl and adams-bridge commits that tag uses, each checked by commit and git tree.

**Real:**

- **ROM and firmware.** Built by Caliptra's own `caliptra-builder` with the recipe of its frozen-image check. The ROM comes out bit for bit equal to the digest the Caliptra TAC froze in `FROZEN_IMAGES.sha384sum`, and the `rom-merge` step records that as the `rom-matches-frozen` check. That is an independent rebuild of the mask ROM, done by a second party (CHIPS Alliance's CI) with the same result.
- **RTL.** Step 0 freezes the 671 files Verilator reads for `caliptra_top`, and step 1 lints them with Verilator using the flags caliptra-sw's own verilated build uses.
- **ROM merge.** Step 6a writes the ROM in the `$readmemh` format caliptra-rtl loads into its ROM macro, checks it fits the macro size defined in the frozen RTL (`CALIPTRA_IMEM_BYTE_SIZE`, 98304 bytes), and reads the bits back out of the merged design before signing (`rom-readback`).
- **The device.** In every run each unit is Caliptra's emulator from caliptra-sw (`caliptra-hw-model`), running the ROM taken out of the released design and the firmware bundle written to that unit's flash, with that unit's fuses. The RTL job runs the same ROM, flash and fuses on the released design itself, Verilated. The IDevID CSR at provisioning and the LDevID, FMC alias and RT alias certificates at boot all come from that ROM and firmware; [`e2e/caliptra/device`](../e2e/caliptra/device/src/main.rs) only sets fuses, uploads firmware and asks for certificates.
- **Identity.** Each unit gets its own UDS seed and field entropy, and its serial goes into the UEID fuses, so every certificate the device issues names the unit. The buyer checks the chain identity CA, IDevID, LDevID, FMC alias, RT alias.
- **Secure boot.** The verify job flips one bit in a unit's runtime image and boots it: the ROM refuses it with `IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH`. A unit fused for another vendor key is refused with `IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID`.
- **Reference values.** The firmware build signs a [CoRIM](#firmware-reference-values-corim) with the FMC and runtime measurements a unit booting this bundle must report, and the at-boot check compares each unit's alias certificates against it. Veraison's `cocli`, which this project did not write, decodes it.

**Simulated:** wafer maps, genealogy and test results come from [`e2e/caliptra/mfg-scenario.json`](../e2e/caliptra/mfg-scenario.json) (8 units packaged, 1 fails final test, 7 shipped). The programming station's HSM is `os.urandom`, and fuse and flash readback re-reads the files it wrote. The identity CA is a local P-384 key. The [firmware review](#firmware-review-simulated) is simulated: no review provider has reviewed these images, and the reports say so.

**Not run yet:**

- Physical design. Caliptra's SystemVerilog does not go through Yosys, so there is no synthesis, place and route or GDS. The release subject is the RTL with the ROM merged, standing in for the GDS.
- A full boot on the RTL in every run. It takes hours, so it runs on demand on a self-hosted runner, where one unit has booted to runtime; see [Booting on the RTL](#booting-on-the-rtl). Pull requests and pushes boot the emulator.
- Only the ECC P-384 half of Caliptra's certificate chain is checked. Caliptra 2.x also issues an ML-DSA-87 chain; Go's `crypto/x509`, which the verifier uses, cannot verify ML-DSA certificates.

## Booting on the RTL

The emulator is a software model of the RTL, so a chain that ends at it ends at a model of the design. The RTL job ends at the design.

**The device is the released design.** `hslsa caliptra rtl-model` unpacks the released design (`caliptra-design.tar`, checked against the release record) and adds only what caliptra-rtl's Verilator harness reads that is not part of the design: 51 testbench, coverage and assertion files from `caliptra_top_tb.vf` at the pinned caliptra-rtl commit. It refuses a bench file that would replace a released one, and lists every bench file with its digest in `rtl.json`, which the job uploads. caliptra-sw's `hw-model` then Verilates that tree in place of its own caliptra-rtl submodule. GitHub's runners Verilate it on every run. A self-hosted runner keeps its three newest models and reuses one only when `rtl.json` (the released design's digest and every bench file's), the caliptra-sw commit, the device tool's sources, the Rust, C++ and Verilator versions, the build options and the CPU model all match; the job summary says whether the model was built or reused. The unit runs the mask ROM taken out of the released design, with the fuses and flash the programming station wrote.

The job has two stages, picked with `rtl-stage`:

| Stage | What runs on the RTL | What the buyer checks | Result |
| --- | --- | --- | --- |
| `identity` (default) | The ROM, with the unit's fuses in the manufacturing lifecycle, until it exports the IDevID CSR | The CSR verifies under its own key, and that key is the one in the IDevID certificate the identity CA endorsed from the CSR read at test | Passed on a hosted runner with Verilator 5.020 (Actions run 36622030110 in this repository): CSR after 3 hours 4 minutes (3.67 million polling steps; the tool then counted steps, each with a bus read, not clock cycles), byte for byte the CSR the emulator exported at test. The whole job, with a 25-minute model build, took about 3.5 hours for one unit |
| `boot` | The ROM, the firmware upload and verification, then FMC and runtime | The same tapeout, lot, firmware and at-boot checks as Verify, the same VSAs, and slsa-verifier. The LDevID certificate must verify under the endorsed IDevID key | Passed for CLP-00002 on the self-hosted `archlinux` runner with Verilator 5.052 on four threads (Actions run 36696743021 in this repository): the ROM asked for firmware after 5.48 million cycles (17 minutes), accepted it after 21.0 million (73 minutes), and runtime was ready after 35.8 million cycles and 2 hours 24 minutes, about 4,130 cycles a second. The whole job, with an 8-minute model build, took 2 hours 34 minutes. The emulator reaches runtime in 8.1 million cycles; on a hosted runner with Verilator 5.020 the ROM was still verifying firmware at six hours. With the faster build below (Actions run 36976915191), CLP-00002 reached runtime on the same runner after 36.1 million cycles and 1 hour 55 minutes, and passed the same checks; the whole job took 2 hours 8 minutes |

The `identity` stage shows that the design itself derives the identity the chain was endorsed with: the key the identity CA certified, and every certificate the buyer later trusts from it, comes from the released RTL and ROM with that unit's fuses, not only from the emulator's model of them.

The `boot` stage goes further: the released RTL and mask ROM verify the unit's firmware and run FMC and runtime, and the LDevID, FMC alias and RT alias certificates the at-boot check verifies come from that boot. So the booted device at the end of the chain is the design itself, not a model of it.

A boot runs past a hosted runner's six-hour job limit, so it needs a self-hosted runner: set `rtl-runner` to its label, and the job then allows up to five days. [`rtl-runner-setup.sh`](../e2e/caliptra/rtl-runner-setup.sh) prepares an x86_64 runner, installing missing packages with apt or pacman only when sudo needs no password and otherwise printing the one command to run. The setup step prints the runner's CPU model, frequency governor and load average. The device tool prints the cycle count, rate, Caliptra's boot and error status and the machine's load average every minute, and the cycle count at each stage.

The secure-boot refusal checks stay on the emulator, since each refused boot would take hours more on the RTL.

Speed is the cost. Caliptra 2.1 has ML-DSA, ML-KEM and AES engines. Built with Verilator 5.020, its model ran at 330 to 1,000 clock cycles a second on a four-core hosted runner, and more cores barely helped: on one four-core machine it ran 700 cycles a second on one thread, 840 on two and 870 on four. Verilator 5.052 runs the same model at about 3,450 cycles a second on two threads and 4,570 on four on that machine, and there it exported CLP-00002's IDevID CSR after about 11.4 million cycles, in one hour, byte for byte the CSR read at test. So the job uses 5.052 and builds it from source when the runner lacks it. For 5.052, `build-rtl` changes two lines in caliptra-sw's harness, which is not part of the design: two `memcpy` calls take the wide signal's `data()`. The job builds the model with Verilator's `-O3`, the C++ compiler's `-O3 -march=native` and one Verilator thread per core, up to 4 (the `rtl-threads` input sets another count), in place of caliptra-sw's `-Os` on one thread. That changes compile options, not the design. The device tool checks whether a stage is done every 64 cycles, prints the model's own cycle count and rate every minute and the count at each stage, and the job summary shows the stage lines and the last progress line.

**Where a boot's time goes.** To reach runtime the design runs about 36 million clock cycles: 5.5 million in the ROM before it asks for firmware, 15.5 million while the ROM verifies the firmware, and 15 million in FMC and runtime. Most of them are probably spent in its ECC and ML-DSA engines, which the emulator does not time; it reaches runtime in 8.1 million. A simulator has to run every one of those cycles, so only the model's speed and the machine running it can shorten a boot; a boot in seconds needs the design on an FPGA, as in phase 2 of the [roadmap](roadmap.md).

- **Build options.** Measured five minutes into a boot on a four-core cloud Xeon, Verilator's `-O3` with the C++ compiler's `-O3 -march=native` ran about 10% more cycles than the C++ `-O3` build alone. Turning off the unique-case checks Verilator 5.052 adds by default made no measurable difference, and GCC's profile-guided optimization was slower, so the job uses neither. On that machine, otherwise idle, CLP-00002 booted to runtime in 68 minutes at a steady 8,700 cycles a second.
- **Threads.** On `archlinux` (an Intel Core i7-11800H laptop processor, 8 cores and 16 threads), 8 Verilator threads were no faster than 4.
- **The machine.** The threads wait on each other every cycle, so the model slows down many times over when other work shares its cores (171 cycles a second in one test). In the `archlinux` boot above the load average was already 4 to 7 before the job started, and minute by minute the model ran a median 6,000 cycles a second while the load average was 5 to 7 and 4,100 while it was 7 or more (the model's own four threads count for about 4). At a steady 7,000 cycles a second that boot would take about 85 minutes. Keep a self-hosted runner plugged in, awake and otherwise idle during a boot; a `performance` CPU governor or power profile may help too, since that runner reports `powersave`.

To run it, dispatch the workflow from the Actions tab with `rtl` set, or locally after `produce`:

```sh
e2e/caliptra/run.sh build-rtl
RTL_UNITS=1 RTL_STAGE=identity e2e/caliptra/run.sh verify-rtl
RTL_UNITS=1 RTL_STAGE=boot SLSA_VERIFIER=/path/to/slsa-verifier e2e/caliptra/run.sh verify-rtl
```

## Levels claimed

| VSA subject | `verifiedLevels` |
| --- | --- |
| Released design (`caliptra-design.tar`) | `HSLSA_DESIGN_LEVEL_1`, `SLSA_BUILD_LEVEL_1` |
| Shipped lot (`urn:hslsa:lot:ASM-CLP-03`) | `HSLSA_WAFER_LEVEL_2`, `HSLSA_PACKAGE_TEST_LEVEL_2`, `HSLSA_DESIGN_LEVEL_1` |
| Firmware bundle (`caliptra-fw-bundle.bin`) | `HSLSA_FIRMWARE_LEVEL_2`, `SLSA_BUILD_LEVEL_2` |
| Each booted unit (`urn:hslsa:unit:<serial>`, digest of its IDevID certificate) | `HSLSA_FIRMWARE_LEVEL_2`, `HSLSA_PACKAGE_TEST_LEVEL_2`, `HSLSA_WAFER_LEVEL_2`, `HSLSA_DESIGN_LEVEL_1` |

Design stays at L1 for the same reasons as the PicoRV32 example, and because there is no GDS. Wafer and Package/Test reach L2 as there.

Firmware reaches L2. Every image has SLSA provenance signed by the firmware build platform and a CycloneDX SBOM. The mask ROM is covered through the Design track's ROM merge. Caliptra's ROM verifies the FMC and runtime against the vendor key hash in fuses before running them, and the verify job shows it refusing tampered firmware. The provisioning site, the test house, is itself at Package/Test L2.

Two caveats apply to the L2 claim. The firmware is signed with Caliptra's public test keys (`caliptra-image-fake-keys`), so anyone could sign firmware these units accept. A real product fuses the hash of its own HSM-held vendor keys, and the policy pins that hash. Also, as in the PicoRV32 test, the platform key is generated per run and its trust root travels with the bundle.

Firmware L3 is out of reach: it needs SLSA Build L3, an independent review, and releases in a transparency log. Its device requirement is already met, though. The units report firmware measurements under a Caliptra identity, and the verifier matches each one to an image with provenance. The review check runs too, on simulated reports, but the reference tool refuses a Firmware L3 claim until it also checks SLSA Build L3 and log inclusion.

## The at-boot check

`hslsa caliptra verify` runs the spec's five at-boot steps on every received unit that was booted:

1. **Certificate chain.** The IDevID certificate is endorsed by the identity CA in the trust root. LDevID, FMC alias and RT alias each verify under their parent, and every certificate's UEID names the unit, which must be in the shipped lot.
2. **Provisioning record.** The `fw-provisioning` record whose subject is the digest of that IDevID public key is signed by the test house. It names this unit, this lot and this design release, and all its gates passed.
3. **Measurements.** The FMC TcbInfo in the FMC alias certificate and the runtime TcbInfo in the RT alias certificate each match a reference value in the firmware CoRIM: the same SHA-384 FWID and SVN. The firmware check has already required that the CoRIM is signed by the firmware build platform, is a byproduct of the bundle's provenance, and holds exactly that provenance's FMC and runtime digests and SVN, so a match ties the measurement to an image with provenance. The fuse measurements Caliptra takes (`CALIPTRA_2_X_FUSE_VENDOR_INFO` and `_OWNER_INFO`) are recomputed from the fuses the provisioning record says were burned, and must match.
4. **ROM coverage.** The ROM's provenance names the TAC-frozen image, the `rom-merge` step consumed that image and its provenance, and `rom-readback` passed.
5. **Anti-rollback.** The SVN the device reports equals the image's SVN, and it is not below the fuse or the policy minimum.

## Firmware reference values (CoRIM)

`hslsa caliptra firmware` signs `artifacts/caliptra-fw.corim` along with the bundle's provenance, which lists it as a byproduct. It is a signed CoRIM (a COSE_Sign1 envelope, [draft-ietf-rats-corim-11](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/)), signed with the firmware platform's key and naming the profile `https://github.com/Horiodino/hw-slsa/corim-profile/v0.1`. It holds one CoMID with two reference values, one for each layer Caliptra measures:

| Environment (class-id, tagged bytes) | Measured by | Digest | SVN |
| --- | --- | --- | --- |
| `CALIPTRA_2_X_FMC_FIRMWARE_INFO` | ROM, reported in the FMC alias certificate | SHA-384 of the FMC image | 257 |
| `CALIPTRA_2_X_RT_FIRMWARE_INFO` | FMC, reported in the RT alias certificate | SHA-384 of the runtime image | 257 |

The SVN is 257 for firmware SVN 1 because that is the number the device reports: Caliptra writes `0x100 | svn` into TcbInfo so that the DER integer has a fixed width. A reference value holds what the device reports, so a verifier that maps TcbInfo onto CoRIM directly needs no Caliptra knowledge to match it. The HBOM's `caliptra-fmc` and `caliptra-runtime` entries point at the CoRIM with `referenceValuesRef`.

What it leaves out: the mask ROM, which nothing on the device measures (it is covered by the ROM merge), and the fuse measurements (`CALIPTRA_2_X_FUSE_*`), which depend on each unit's fuses and stay in its provisioning record.

The reference tool can show a CoRIM and appraise any DICE certificates against it:

```sh
hslsa corim show --corim out/caliptra/bundle/artifacts/caliptra-fw.corim \
  --trust-root out/caliptra/bundle/trust-root.json --role firmware-platform
hslsa corim appraise --corim out/caliptra/bundle/artifacts/caliptra-fw.corim \
  --trust-root out/caliptra/bundle/trust-root.json --role firmware-platform \
  out/caliptra/boots/CLP-00002/fmc-alias-ecc384.der out/caliptra/boots/CLP-00002/rt-alias-ecc384.der
```

The verify job runs both, then decodes the file with [Veraison's `cocli`](https://github.com/veraison/cocli) (`corim display`), a CoRIM tool from outside this project, and fails if cocli does not read it as a signed CoRIM with one CoMID. cocli does not check the signature here: its `corim verify` loads a JWK through a function that accepts only private keys, so a buyer holding the public key cannot use it. The reference tool checks the signature instead. The reference tool and cocli both use [Veraison's corim library](https://github.com/veraison/corim), whose last release (v1.1.2, April 2024) predates draft 11, so both are pinned to commits on its main branch.

## Firmware review (simulated)

Firmware L3 takes a signed [OCP S.A.F.E.](https://github.com/opencomputeproject/OCP-Security-SAFE) short-form report for each image ([spec](../spec/hslsa-v0.1.md#firmware-review)). No review provider has reviewed the images this example builds, so `hslsa caliptra review` signs one report per image with a key named `review-provider`, generated per run like every other key. Each report names its image by SHA-384, gives the provider as "SIMULATED review provider (not an OCP S.A.F.E. approved provider; no review took place)", states scope 1, and lists one placeholder issue at CVSS 1.6. The ROM's report is the JSON report signed as a JWS, the form review providers publish today; the FMC's and runtime's use the S.A.F.E. CoRIM profile, so the verifier reads both.

The policy's `firmware.review` names the images that need a report, the trust root roles allowed to sign one, the minimum scope (1) and the highest CVSS score an open issue may have (3.9). For each image, `hslsa caliptra verify` looks in `review/` for a report that verifies under an allowed key, names the image's digest under an algorithm its provenance also lists, and meets the scope and issue limits. The verify job also shows the FMC's report with `hslsa safe show`, checks two reports on their own with `hslsa safe check`, and requires the FMC's report to fail for the ROM.

Real reports exist for Caliptra: NCC Group reviewed the ROM, FMC and runtime of `release_v20231014_0` in 2023, and IOActive reviewed the firmware at a 2024 commit. The unit tests verify both under the providers' published keys, and check that neither can count here. The 2023 FMC report names the SHA-384 and SHA-512 of an FMC ELF from that older release, and its framework version (0.3) predates scope numbers; the 2024 report names commits and pull requests, not an image. A real Firmware L3 claim for this bundle would need a report naming these images, and if the report also gives a SHA-512, provenance that lists one. The tests also read reports signed by OCP's own [`OcpReportLib`](https://github.com/opencomputeproject/OCP-Security-SAFE/tree/main/shortform_report-main) in both forms; see [`tools/hslsa/testdata/safe`](../tools/hslsa/testdata/safe/README.md).

## What the tamper tests prove

[`tools/hslsa/caliptra_test.go`](../tools/hslsa/caliptra_test.go) breaks the chain in 33 ways and requires each to fail for the stated reason. As in the PicoRV32 tests, the fixture re-signs the bundle with test keys so it can forge validly signed records:

- **The device:** a certificate from another unit, a missing alias certificate, an LDevID certificate with the right names signed by the wrong key, a received unit that failed final test.
- **Provisioning:** another unit's record, a record signed by the wrong site, a record edited without re-signing, an IDevID endorsed by another CA. Also records that lie about the vendor fuses, the SVN fuse or the design release, and a policy minimum SVN above the image.
- **Firmware:** provenance, manifest and HBOM that all agree on an FMC the device did not run, and a CoRIM re-issued for it (only the device's measurement catches it), a ROM that is not the frozen image, firmware signed by the design flow platform, a swapped SBOM, an HBOM listing another runtime.
- **The CoRIM:** one signed by a key outside the firmware platform's role, one edited after the build, one whose runtime digest, SVN or runtime entry differs from the provenance, and an HBOM pointing at another CoRIM.
- **The mask ROM:** a ROM merge that does not consume the ROM, a failed `rom-readback`, a swapped released design, a failed lint, a unit added to the lot.
- **The firmware review:** the FMC's report put in place of the runtime's, reports signed by a key the policy does not list, no reports at all, a policy that allows no open issue as severe as the placeholder one, and a policy claiming Firmware L3.

The verify job also runs slsa-verifier three times expecting failure: Firmware L3 for a unit verified at L2, SLSA Build L3 for the firmware, and one unit's VSA presented for another unit.

## Keys and privacy

The same rules as [the PicoRV32 test](e2e-test.md#keys-and-privacy) apply. Nothing is uploaded to a transparency log, no job requests an OIDC token, producer keys never leave the produce job, and `HSLSA_VSA_SIGNING_KEY` makes the buyer's key stable. The `hslsa-caliptra-devices` artifact holds each unit's simulated UDS seed and field entropy, which in silicon never leave the die. They are test values, and the repository is private.

## Running it locally

You need Go (the version in [`go.mod`](../go.mod)), Verilator, rustup and a slsa-verifier binary. The first build takes about 15 minutes.

```sh
SLSA_VERIFIER=/path/to/slsa-verifier e2e/caliptra/run.sh all
go test ./tools/hslsa/
```

Sources are checked out into `e2e/caliptra/.src/` and output goes to `out/caliptra/`.
