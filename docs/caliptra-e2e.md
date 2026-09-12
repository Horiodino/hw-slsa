# Caliptra example: RTL to a booted device

The workflow in [`.github/workflows/caliptra-e2e.yml`](../.github/workflows/caliptra-e2e.yml) runs the whole HSLSA chain on a part with a hardware identity. It starts from the pinned [Caliptra](https://github.com/chipsalliance/caliptra-rtl) RTL and ends with a buyer powering on the units it received, reading each unit's DICE certificates, and walking by digest from those certificates back to the RTL, the ROM and every firmware image. It is the example the spec's [at-boot check](../spec/hslsa-v0.1.md#where-the-chain-is-checked) was written for, and it goes past the PicoRV32 example's Firmware L1 cap because Caliptra's ROM verifies firmware before running it.

## What runs

| Job | Plays | Does |
| --- | --- | --- |
| Produce | Firmware team, design house, tapeout authority, fab, sort house, OSAT, test house and its programming station, product owner | Builds the ROM and the signed FMC + runtime bundle with `caliptra-builder`, lints the RTL, merges the ROM into the design, releases it, signs F1 to F4 for a lot, programs every shipped unit and exports its IDevID CSR from the real ROM, endorses it, signs one `fw-provisioning` record per unit, builds the HBOM |
| Verify | Buyer | Boots the three units it received, checks that the ROM refuses tampered firmware, runs the tapeout, lot, firmware and at-boot checks, signs six SLSA VSAs, verifies them with slsa-verifier v2.7.1, then runs the tamper tests |

All sources are pinned in [`e2e/caliptra/caliptra.lock.json`](../e2e/caliptra/caliptra.lock.json): caliptra-sw at tag `fw-2.1.3`, and the caliptra-rtl and adams-bridge commits that tag uses, each checked by commit and git tree.

**Real:**

- **ROM and firmware.** Built by Caliptra's own `caliptra-builder` with the recipe of its frozen-image check. The ROM comes out bit for bit equal to the digest the Caliptra TAC froze in `FROZEN_IMAGES.sha384sum`, and the `rom-merge` step records that as the `rom-matches-frozen` check. That is an independent rebuild of the mask ROM, done by a second party (CHIPS Alliance's CI) with the same result.
- **RTL.** Step 0 freezes the 671 files Verilator reads for `caliptra_top`, and step 1 lints them with Verilator using the flags caliptra-sw's own verilated build uses.
- **ROM merge.** Step 6a writes the ROM in the `$readmemh` format caliptra-rtl loads into its ROM macro, checks it fits the macro size defined in the frozen RTL (`CALIPTRA_IMEM_BYTE_SIZE`, 98304 bytes), and reads the bits back out of the merged design before signing (`rom-readback`).
- **The device.** Each unit is Caliptra's emulator from caliptra-sw (`caliptra-hw-model`), running the ROM taken out of the released design and the firmware bundle written to that unit's flash, with that unit's fuses. The IDevID CSR at provisioning and the LDevID, FMC alias and RT alias certificates at boot all come from that ROM and firmware; [`e2e/caliptra/device`](../e2e/caliptra/device/src/main.rs) only sets fuses, uploads firmware and asks for certificates.
- **Identity.** Each unit gets its own UDS seed and field entropy, and its serial goes into the UEID fuses, so every certificate the device issues names the unit. The buyer checks the chain identity CA, IDevID, LDevID, FMC alias, RT alias.
- **Secure boot.** The verify job flips one bit in a unit's runtime image and boots it: the ROM refuses it with `IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH`. A unit fused for another vendor key is refused with `IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID`.

**Simulated:** wafer maps, genealogy and test results come from [`e2e/caliptra/mfg-scenario.json`](../e2e/caliptra/mfg-scenario.json) (8 units packaged, 1 fails final test, 7 shipped). The programming station's HSM is `os.urandom`, and fuse and flash readback re-reads the files it wrote. The identity CA is a local P-384 key.

**Not run yet:**

- Physical design. Caliptra's SystemVerilog does not go through Yosys, so there is no synthesis, place and route or GDS. The release subject is the RTL with the ROM merged, standing in for the GDS.
- Booting on the RTL. Caliptra's emulator models the RTL. Booting the same ROM on caliptra-sw's Verilator model would make the booted device the RTL itself, but it needs Verilator 5.006 built from source and a much larger runner than a standard one.
- Only the ECC P-384 half of Caliptra's certificate chain is checked. Caliptra 2.x also issues an ML-DSA-87 chain; Go's `crypto/x509`, which the verifier uses, cannot verify ML-DSA certificates.

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

Firmware L3 is out of reach: it needs SLSA Build L3, an independent review, and releases in a transparency log. Its device requirement is already met, though. The units report firmware measurements under a Caliptra identity, and the verifier matches each one to an image with provenance.

## The at-boot check

`hslsa caliptra verify` runs the spec's five at-boot steps on every received unit that was booted:

1. **Certificate chain.** The IDevID certificate is endorsed by the identity CA in the trust root. LDevID, FMC alias and RT alias each verify under their parent, and every certificate's UEID names the unit, which must be in the shipped lot.
2. **Provisioning record.** The `fw-provisioning` record whose subject is the digest of that IDevID public key is signed by the test house. It names this unit, this lot and this design release, and all its gates passed.
3. **Measurements.** The FMC FWID in the FMC alias certificate and the runtime FWID in the RT alias certificate equal the SHA-384 subjects of the firmware provenance. The fuse measurements Caliptra takes (`CALIPTRA_2_X_FUSE_VENDOR_INFO` and `_OWNER_INFO`) are recomputed from the fuses the provisioning record says were burned, and must match.
4. **ROM coverage.** The ROM's provenance names the TAC-frozen image, the `rom-merge` step consumed that image and its provenance, and `rom-readback` passed.
5. **Anti-rollback.** The SVN the device reports equals the image's SVN, and it is not below the fuse or the policy minimum.

## What the tamper tests prove

[`tools/hslsa/caliptra_test.go`](../tools/hslsa/caliptra_test.go) breaks the chain in 22 ways and requires each to fail for the stated reason. As in the PicoRV32 tests, the fixture re-signs the bundle with test keys so it can forge validly signed records:

- **The device:** a certificate from another unit, a missing alias certificate, an LDevID certificate with the right names signed by the wrong key, a received unit that failed final test.
- **Provisioning:** another unit's record, a record signed by the wrong site, a record edited without re-signing, an IDevID endorsed by another CA. Also records that lie about the vendor fuses, the SVN fuse or the design release, and a policy minimum SVN above the image.
- **Firmware:** provenance, manifest and HBOM that all agree on an FMC the device did not run (only the device's measurement catches it), a ROM that is not the frozen image, firmware signed by the design flow platform, a swapped SBOM, an HBOM listing another runtime.
- **The mask ROM:** a ROM merge that does not consume the ROM, a failed `rom-readback`, a swapped released design, a failed lint, a unit added to the lot.

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
