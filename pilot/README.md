# HSLSA pilot kit

This kit is what the owner of this repository hands one buyer for [roadmap phase 4](../docs/roadmap.md#phase-4-pilots-with-one-buyer-who-needs-this): one buyer, one root of trust part, one supplier signing its own records, and a measured result. It is aimed at the roadmap's first candidate, a hyperscaler in the Open Compute Project that already requires a Caliptra-class root of trust and reads OCP S.A.F.E. reports, because the [viability assessment](../docs/viability.md) found the Firmware track and board checks ready now and Package/Test plausible with a large customer behind it.

The repository is public, but the kit is not published: the buyer gets it as a tarball (`pilot/make-kit.sh`) from the owner; nothing in it needs a public transparency log or a network service.

## Checking the kit you received

A tarball kit arrives as four files: `hslsa-pilot-kit-<commit>.tar.gz`, its `.tar.gz.sig`, its `.provenance.json`, and the kit owner's `.pub.pem`. The owner also sends the public key's sha256 over a different channel, such as a call or a separate email. Check, in order:

1. **The key.** `sha256sum hslsa-pilot-kit-*.pub.pem` prints the value the owner sent you. If it differs, stop.
2. **The tarball**, with openssl alone, so nothing in the kit is trusted yet:

   ```
   openssl dgst -sha256 -verify hslsa-pilot-kit-*.pub.pem \
     -signature hslsa-pilot-kit-*.tar.gz.sig hslsa-pilot-kit-*.tar.gz
   ```

   It prints `Verified OK`.
3. **Unpack it and check each binary against the provenance.** From the unpacked directory, with the binary for your platform:

   ```
   bin/hslsa-linux-amd64 kit verify --pub ../hslsa-pilot-kit-*.pub.pem \
     --provenance ../hslsa-pilot-kit-*.provenance.json bin/hslsa-*
   sha256sum -c SHA256SUMS
   ```

   The first command names the commit the kit was built from, which `KIT.txt` also gives. The provenance is a SLSA provenance statement in a DSSE envelope, so any in-toto verifier can read it too.

The same `hslsa` tool also ships as a private container image on GHCR for anyone the owner grants access to; [docs/release.md](../docs/release.md#the-container-image) says how to pull and run it.

The code in the kit is under the [Apache License 2.0](../LICENSE) and the specification and documentation under [CC BY 4.0](../LICENSE-CC-BY-4.0). `licenses/` holds the license of every Go module in the binaries, and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) lists the third-party files in the source. The macOS binaries are not notarized, so macOS may ask you to allow them, or you can build from the source with `go build ./tools/hslsa/cmd/hslsa`.

## Scope

| | In the pilot | Out of the pilot |
| --- | --- | --- |
| Part | One root of trust part (Caliptra or a Caliptra-class RoT), on one board the buyer already buys | Every other part on the board |
| Tracks | **Package/Test L2**, signed by the OSAT with its own keys; **Firmware L2** for the RoT's firmware and per-unit provisioning; the **at-boot check** in the buyer's fleet | Wafer above L1 (the foundry signs nothing; the sort site signs its record on the foundry's behalf); Design above what the RoT vendor already signs; Assembly; L3 and L4 |
| Parties | The buyer; the RoT vendor (design house, firmware build, code signing, product owner); one OSAT group running sort, assembly and test, and the programming station at test | The foundry, distributors, the board's EMS |
| Trust | The buyer runs the trust root: it enrolls every key it accepts and can revoke any of them ([spec](../spec/hslsa-v0.1.md#buyer-run-trust-roots)) | An industry PKI or accreditor-issued keys |

## The three steps

The roadmap's pilot has three steps. Each maps to commands in this kit.

1. **The buyer is the trust root.** The buyer makes one root key, and enrolls each site key with `hslsa pilot enroll` after checking it with the company that holds it. `hslsa pilot trust-root` builds the trust root its verifier reads from those records alone, and `hslsa pilot revoke` withdraws a key. See [buyer.md](buyer.md).
2. **One supplier signs with its own key.** The OSAT makes its site keys (in an HSM where it has one), sends the buyer only the public halves, turns its own MES and tester exports into records with `hslsa adapt`, and signs its steps with `hslsa mfg --sign`, which signs only the roles it names and keeps every earlier site's record. Its programming station's export becomes per-unit provisioning records through `hslsa provision`. See [supplier.md](supplier.md).
3. **Measure and publish.** For every lot, the buyer runs `hslsa pilot measure`: the receipt check and why it failed if it did, how long it took, which company signed which records and which of their fields the buyer now holds, and the hours and money each party reports. It keeps a summary across lots for the pilot report.

**Exit, from the roadmap:** one external supplier signs one record type for a real product, and one buyer verifies it before accepting parts.

## What is in the kit

| Path | For |
| --- | --- |
| [`buyer.md`](buyer.md) | The buyer's steps: root key, enrollments, policy, receipt and at-boot checks, measurement |
| [`supplier.md`](supplier.md) | The OSAT's and the RoT vendor's steps: keys, exports to records, provisioning, handing over a lot |
| [`agreement.md`](agreement.md) | What the parties settle before the first lot: data, keys, retention, what gets published |
| [`make-kit.sh`](make-kit.sh) | Builds the tarball: the repository at one commit, `hslsa` binaries for common platforms, the licenses of the Go modules in them, checksums; then signs it and writes its provenance |
| [`vendor.md`](vendor.md) | Where a chip vendor starts when it receives the kit before any buyer is involved |
| [`../e2e/pilot/`](../e2e/pilot) | The rehearsal: the buyer's policy for the part, the adapter configuration, a cost sheet template, and `run.sh` |
| [`../spec/hslsa-v0.1.md`](../spec/hslsa-v0.1.md) | The specification, at the revision of the kit's commit; `main` is at revision 19. No release is published now, so a kit is built from `main` (`pilot/make-kit.sh`) |
| [`../tools/hslsa`](../tools/hslsa) | The reference tool and verifier, in Go |

## The rehearsal

`e2e/pilot/run.sh` plays the whole pilot on one machine, and CI runs it on every change:

- **`chip`**, after the PicoRV32 example: the buyer enrolls the vendor's and the OSAT group's keys; the OSAT group makes its own sort, assembly and test keys, builds the lot from the sample MES, STDF and SEMI E142 exports, proxy-signs the foundry's record from the foundry's export, and signs its own records with only its keys; the vendor signs the HBOM; the buyer checks the lot under the buyer-run trust root and measures it. The lot is simulated and its records say so, so the buyer's policy for real parts refuses it, and the rehearsal checks that first and then runs under a copy of the policy that accepts simulated evidence. Then the buyer's trust root must refuse: the vendor's own trust root (which never saw the OSAT's keys), a key the buyer did not enroll, a revoked key, enrollments read after they ended, a trust root kept past its `validUntil`, an enrollment the buyer did not sign, and one key enrolled for two roles.
- **`board`**, after the FPGA board example: the buyer rebuilds the root of trust vendor's trust root and the board's from its own enrollments, and the board receipt check, the root of trust's Firmware L2 check, its provisioning records and the at-boot check of every booted board pass under them. Revoking the RoT vendor's test site key makes the same check fail.

The rehearsal's companies, organization ids and cost figures are made up. The FPGA board is the stand-in for the buyer's board until a real one is in the pilot; the [Caliptra example](../docs/caliptra-e2e.md) is the stand-in for a Caliptra RoT, with the same at-boot check against its CoRIM.

## What the pilot can and cannot show

- It shows whether a real OSAT can sign real records from exports it already has without editing them, what that costs per lot, and whether a buyer can check them before accepting parts. That is the roadmap's exit.
- It cannot show that the records are true. A signature proves who claimed something, not that it happened ([Threat model](../spec/hslsa-v0.1.md#what-a-signed-record-proves)). The buyer still decides, before enrolling a key, that the site holding it runs the steps the levels ask for.
- Every adapter in Phase 3 was built on sample exports. The pilot's first lot is where each meets a real file; expect a profile or a column mapping to change, and record it in the report.
- One buyer-run trust root serves one buyer. A supplier selling to many buyers enrolls with each, which is fine for a pilot and is the reason Phase 5 looks for accreditors that issue site keys.

## Before handing the kit out

These are the owner's decisions, not the kit's:

1. **Which buyer.** The kit defaults to an OCP-member hyperscaler. A defense program, a server OEM or an open silicon project would change the part and the tracks (see the roadmap's table), not the commands.
2. **Tarball or invitation.** The repository stays private either way. A tarball carries one commit; an invitation lets the buyer follow changes and file issues. A tarball is signed with the owner's key (`HSLSA_KIT_KEY=<key> pilot/make-kit.sh`); send the printed public key sha256 separately from the kit.
3. **What gets published at the end.** Step 3 says "publish the result". [agreement.md](agreement.md) lists what each party has to approve first.
