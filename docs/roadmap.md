# Roadmap to real-world use

This roadmap turns HSLSA from a working draft with simulated supply chain data into something suppliers and buyers can run. It follows from the [viability assessment](viability.md) of 2026-09-12, whose short version is: the design is technically sound, but nobody outside this repository signs the records yet.

The phases are ordered by dependency, not by date. Each ends with an exit criterion that can be checked, and the first two can be done entirely in this repository.

## Where we start

What works today, all in CI with local keys:

- The four examples (PicoRV32, board, OpenLane 2, Caliptra) sign every record, run the tapeout, lot receipt, board receipt and at-boot checks, and pass their VSAs through slsa-verifier.
- Verified levels: Design L1, Wafer L2, Package/Test L2, Assembly L2, Firmware L2. Since spec revision 16, L3 in every track ([levels.md](levels.md)): Design L3 in the PicoRV32 example, Wafer L3 and Package/Test L3 on a second run of its lot, Assembly L3 on the board example, and Assembly L3 and Firmware L3 on the FPGA board, all on simulated manufacturing.

What the assessment found missing or weak:

| Gap | Why it matters | Phase |
| --- | --- | --- |
| No threat model saying what signed records cannot prove | A buyer could read Wafer L3 as "no trojans" | 0 |
| No example above Design L1; GDS not bit-exact; no independent rebuild | The spec's own Design L2 to L4 are untested | 0 |
| L3 isolation conflicts with network license servers | Commercial flows cannot reach Design L3 as written | 0 |
| Overlap with NIST IR 8536, SEMI T26, CISA HBOM | A standalone framework competes for attention | 1 |
| Salted digests hide values but not volumes and timing | Foundries and OSATs will not accept the disclosure | 1 |
| All physical data is simulated (since spec revision 15 every such record says so, and the virtual shuttle derives it from the netlist) | Nothing shows a real supplier's data fits the records | 2 |
| Commercial EDA, MES and test systems emit nothing | Every supplier would need custom integration | 3 |
| No buyer requires it; no trust root for sites | Suppliers have cost and no benefit | 4 |
| Spec lives in one person's private repository | Industry will not adopt it from there | 5 |

## Phase 0: Make the spec honest and complete

Work that needs no partner. Target: spec v0.2.

1. **Threat model.** Add a section that states, per track and level, which attacks the records stop and which they only make accountable. It says plainly that a site's signature proves the site made a claim, not that the claim is physically true; that L1 to L3 give tamper evidence for records; and that only L4 sampling checks physical parts, statistically, and cannot see every change (dopant-level trojans evade optical inspection).
2. **Scope statement.** The full chain, down to the at-boot check, applies to parts with a hardware identity. Every other part on a board gets a distribution record and lot-level naming, which cannot stop a swap inside a lot. Say so in the overview and in Assembly L2 and L3.
3. **Design L2 example.** A signed, reviewed source freeze (a signed tag plus a review attestation) and signed provenance for one third-party IP block, verified at tapeout.
4. **Bit-exact GDS.** Pin the dates Magic, KLayout, OpenSTA and RCX embed in the OpenLane 2 flow so two runs match byte for byte, then make the verifier require `gds-bit-exact` by default.
5. **Independent rebuild.** A second builder under a separate trust root (a different CI account and key) signs the `rebuild` record, so the OpenLane 2 example shows real Design L4 evidence.
6. **Boot on the RTL.** Boot the Caliptra ROM on the Verilated RTL instead of the emulator, so the booted device is the design itself. Done: on a self-hosted runner a unit boots to runtime on the Verilated released design in about 2.5 hours and passes the buyer checks ([caliptra-e2e.md](caliptra-e2e.md#booting-on-the-rtl)).
7. **Licensed tools at L3.** Allow a declared license server as the only permitted network egress for a Design L3 step, with its address and the checked-out features recorded in `hwFlow`.
8. **Close the blocking open questions.** Decide the board-level root of trust rule for Firmware L2, whether `fw-review` is needed, and one shared step list for `hwFlow.step` and the HBOM's `design.flow[].step`. Done in spec revision 4: the board-level rule is adopted as written, the `fw-review` wrapper is dropped in favor of the signed S.A.F.E. report, and both fields use one list of design step names.

**Exit:** spec v0.2 with a threat model, and CI verifying Design L2 and a Design L4 rebuild record from a separate trust root.

## Phase 1: Build on existing standards instead of competing

Target: spec v0.3 and a profile document.

1. **HSLSA as a NIST IR 8536 profile.** Map each HSLSA record onto the IR 8536 meta-framework's provenance chain and event model, and check that its open-source reference implementation can ingest HSLSA records, or that a thin adapter can. Publish the mapping as `spec/nist-ir-8536-profile.md`. The mapping is published in [nist-ir-8536-profile.md](../spec/nist-ir-8536-profile.md); the ingest check waits for NIST to publish the reference implementation. Spec revision 6 settles the ten gaps the profile found: transfers between manufacturing sites and receipt records are recorded, the receipt checks report every gap at once, and evidence records, fetchable references and retention are in the spec. Storage, events after the first buyer and GS1 EPCIS are deferred to the items below.
2. **Selective disclosure.** Design a verifier-escrow mode: an accredited auditor sees full records, the buyer sees only check results and a signed VSA. Measure what salted digests still leak (record counts, lot sizes, timing) and say what the escrow mode hides. Done in spec revision 5 ([selective-disclosure.md](selective-disclosure.md)): records withhold fields with SD-JWT style salted digests, and an auditor signs a design VSA and a receipt VSA for the buyer's units. On the PicoRV32 lot, a party holding the records still recovered both lot sizes and the scrapped serials from the lot digests, and saw site names, lot ids and timing; the escrow buyer saw only the design digest, the lot id, the levels and the auditor.
3. **Output formats.** Emit the HBOM as CycloneDX 1.6 and as SPDX 3.1 once 3.1 is final. Publish firmware reference measurements as CoRIM, so standard RATS verifiers can run part of the at-boot check. The CoRIM half is done: the Caliptra example signs the reference values for its FMC and runtime as a CoRIM, the at-boot check appraises each unit against it, and Veraison's cocli decodes it in CI ([caliptra-e2e.md](caliptra-e2e.md#firmware-reference-values-corim)). The CycloneDX and SPDX renderings are done in spec revision 7 ([Renderings](../spec/hslsa-v0.1.md#renderings)): `hslsa render` writes both from a signed HBOM, the product owner lists them in the HBOM by digest, and the buyer's check re-renders the HBOM and requires the same bytes. The CycloneDX 1.6 rendering passes the CycloneDX project's validator in CI. SPDX 3.1 is still a release candidate, so the SPDX rendering targets 3.1-RC1 and moves to 3.1 when it is final.
4. **Transparency logs.** Show SEMI T26 (ledger-based traceability) or a private RFC 9162 log as the L3 log for manufacturing records. The firmware half is done in spec revision 16: the [release log](../spec/hslsa-v0.1.md#release-log) is a private RFC 9162 log that Firmware L3 checks, with inclusion proofs beside each release and consistency proofs between checkpoints ([levels.md](levels.md#firmware-l3)). Manufacturing records do not go into it yet.
5. **Policy examples.** Ship buyer policies for each check in a standard policy language (Rego or in-toto layouts), so buyers do not have to use the reference tool.

**Exit:** a published IR 8536 profile, and one HSLSA chain verified by a tool this project did not write.

## Phase 2: Touch real silicon and real hardware

Target: the first chain where physical records come from a real run.

**Simulated stand-ins: done in spec revision 15.** Real hardware waits on the owner, so every item that needs it has a software stand-in, and every record made from one says so ([simulated-hardware.md](simulated-hardware.md)): a record from simulated hardware carries `simulated`, the verifier refuses it unless the buyer's policy sets `simulated.accept`, and every VSA over it states `HSLSA_SIMULATED`. The stand-ins prove that the records, adapters and checks work on data that comes out of a running design; they prove nothing about real parts, so the items below stay open until real hardware replaces them.

1. **Real board boot.** Run the at-boot check on a physical board: OpenTitan or Caliptra on an FPGA board, provisioned by a script that signs `fw-provisioning` records, then booted and checked against them. Everything short of the hardware is done in spec revision 9: [fpga-board-example.md](fpga-board-example.md) builds PicoSoC for an iCE40UP5K with open tools and signed records, puts it on a simulated board whose attested root of trust verifies the flash before the FPGA leaves reset, provisions and boots each board, and verifies Firmware L2 for the board, the first example to use the board-level root of trust rule. The bitstream is built for the iCEBreaker's FPGA, so a real board can follow; it needs a board where the root of trust owns the FPGA's reset and flash, and a root of trust whose vendor signs its chain, since a proxy-signed one holds Firmware at L1. The simulated board's records are marked as simulated since revision 15.
2. **Open-PDK tapeout.** Put a small design with a unique ID through an open-PDK shuttle (SKY130 or GF180), with the Design chain from phase 0. Simulated stand-in done: the virtual shuttle (`hslsa sim shuttle`) fabricates the PicoRV32 release on 72 dies with seeded stuck-at defects, checks the netlist it builds against the release, and burns a unique die id into each die that passes sort. The real tapeout is still open.
3. **Real package and test data.** Turn the packaging and test data the shuttle returns (unit lists, test logs, wafer maps where available) into F2 to F4 records. Simulated stand-in done: wafer sort and final test run test programs on every die in Icarus Verilog against the RTL's results, final test reads each unit's die id back, and the shuttle writes the MES, STDF and SEMI E142 exports that the phase 3 adapter turns into the lot's records. Real shuttle data is still open.
4. **Proxy signing.** Suppliers will not sign at first. Define a `proxy` signer role: this project signs a record on a supplier's behalf from the supplier's own data, and the record says so. A proxy-signed step caps its track at L1, but the chain shape is real. The reference tool accepts the spec's L1 evidence records at the same time. Done in spec revision 8: the proxy is whoever received from the supplier (the next site, or the product owner after final test), the tool accepts proxy-signed records and evidence records when the buyer's policy opts in, and [proxy-signing.md](proxy-signing.md) runs the PicoRV32 lot with two suppliers that sign nothing. Real supplier data replaces the simulated export with items 2 and 3.
5. **Real board build.** Assemble a small batch of boards and record A1 from the real build and the real distributor invoices. The board examples' A1 and shipment records are simulated, and marked so.
6. **After the first buyer.** With a real board booting, define records for what happens to it in the field: a firmware update signed by the updater and linked to the unit's provisioning record, rework, and returns. This is IR 8536's principle 6 and an open question in the spec.

**Exit:** a public or buyer-shared chain from RTL to a real booted device, with every simulated record replaced by a real or proxy-signed one, so that the chain passes under a policy without `simulated.accept`.

## Phase 3: Adapters for tools suppliers already run

Target: turn an unchanged supplier export into signed records. This is what makes adoption cheap enough.

| Adapter | Reads | Emits |
| --- | --- | --- |
| Commercial EDA wrapper | Tcl hooks in the flow scripts (Innovus, ICC2, Fusion Compiler, Calibre) | `design-flow` records per step |
| MES and test sidecar | Lot events, SEMI E142 wafer maps, STDF test results | F1 to F4 records |
| Provisioning station plugin | Station logs and readback | `fw-provisioning` records |
| Distributor importer | Certificates of conformance, packing lists, GS1 EPCIS shipping, receiving and storage events | Distribution records, with EPCIS events kept as supplemental evidence |
| HSM signing | PKCS#11 | Site-key signatures at L3 |

**HSM signing: done.** Every key the reference tool takes can be an HSM key named by a PKCS#11 URI, or a `<role>.pkcs11` file in place of `<role>.key.pem`; `hslsa hsm keygen` makes non-extractable site keys on a token, and the tool refuses a key the HSM would let out. CI signs the PicoRV32 release and lot with the sites' keys in SoftHSM2 and checks them. See [hsm-signing.md](hsm-signing.md). A real HSM, and the buyer's means of knowing a key is in one (accreditation, audit or the vendor's key attestation), come with a pilot site.

**MES and test sidecar: built on sample data.** `hslsa adapt` reads MES lot histories and a unit genealogy, STDF V4 results and SEMI E142 wafer maps, the records carry those exports by digest, and the verifier reads them again and checks the records against them (spec revision 11). It runs on sample exports for the PicoRV32 lot, so its exit still needs a real site's files. SEMI E142 is read only as far as a sort map uses it, and lot events are not yet turned into transfers. See [mes-stdf-adapter.md](mes-stdf-adapter.md).

**Provisioning station adapter: built, waiting on a real station's export.** Spec revision 12. `hslsa provision gate` checks a job's images against their provenance before the job runs, and `hslsa provision adapt` reads the station's own export (job file, log, readback dumps, identity files) through a per-model profile and signs one record per unit. The FPGA example's root of trust vendor uses it, and its records pass the board receipt and at-boot checks. The station models are simulated, so the exit criterion needs a real station's export ([provisioning-adapter.md](provisioning-adapter.md)).

The EDA wrapper needs a design-house partner with licenses. The rest can be built against sample data from phase 2.

**EDA wrapper: done for open tools.** In spec revision 10, [`adapters/eda-tcl`](../adapters/eda-tcl/README.md) is a hook a flow's Tcl script sources to mark each step, and `hslsa eda run` signs one `design-flow` record per step from outside the tool, refusing a step whose inputs link to nothing. It runs in Yosys's Tcl shell for PicoRV32 and in OpenROAD's for signoff STA on the OpenLane 2 release, in CI. Its README says where the same hook goes in Innovus, Genus, ICC2, Fusion Compiler, PrimeTime and Calibre; trying it there, and adding the license-server `network` block from the platform, still waits on a partner with licenses.

**Exit:** each adapter produces valid records from a real export without manual editing, and the reference verifier accepts them.

## Phase 4: Pilots with one buyer who needs this

No supplier signs records until a customer requires it. Pick one buyer, not the whole market.

| Candidate | Why they would say yes | Pilot scope |
| --- | --- | --- |
| A hyperscaler, through OCP | Already requires a Caliptra root of trust and runs OCP S.A.F.E. reviews | Firmware and Package/Test for one root-of-trust part, plus the at-boot check in their fleet |
| A defense program | DoD is moving from Trusted Foundry to quantifiable assurance and needs evidence from commercial fabs | All five tracks, including one L4 inspection |
| A server OEM | Already sells factory-signed component verification | Assembly and Firmware for one server board |
| An open silicon project (lowRISC, CHIPS Alliance) | Open RTL and tools, nothing to hide | Design L3 to L4 and Firmware |

In the pilot:

1. Start with the buyer as the trust root for every site key, which avoids waiting for an industry PKI.
2. Get one supplier (most likely the OSAT, whose per-unit traceability data already exists) to sign its records with its own key.
3. Measure the cost per lot, what data each party had to disclose, and which checks failed, and publish the result.

**Exit:** one external supplier signs one record type for a real product, and one buyer verifies it before accepting parts.

**Pilot kit: ready to hand to a buyer.** Spec revision 13. The [pilot kit](../pilot/README.md) is aimed at the first row, an OCP hyperscaler, for one root of trust part: Package/Test L2 signed by one OSAT group with its own keys, Firmware L2 for the part, and the at-boot check. For step 1, `hslsa pilot enroll`, `revoke` and `trust-root` let the buyer run the trust root from its own signed enrollments ([Buyer-run trust roots](../spec/hslsa-v0.1.md#buyer-run-trust-roots)). For step 2, `hslsa mfg --sign` lets each site sign only its own records into a lot, with keys no other party holds. For step 3, `hslsa pilot measure` records each lot's check result, who signed what and which fields the buyer holds, and each party's reported cost, with a summary across lots. Since revision 14 the board check also runs each part's chain under the buyer's own trust root and policy for that part (`--part-trust-root`, `--part-policy`), and the kit is signed with SLSA provenance for its binaries. `e2e/pilot/run.sh` rehearses all of it in CI on the PicoRV32 lot and the FPGA board. Still needed, and only the owner can start it: a buyer and its OSAT willing to run it on a real part, and the decisions below.

## Phase 5: A neutral home and v1.0

1. **Choose a home.** OpenSSF (where SLSA lives), CHIPS Alliance (where Caliptra lives), or the OCP security project. Present the IR 8536 profile and pilot results at NIST's traceability work as well.
2. **Open the repository.** Adoption needs a public spec. This repository is private and signs nothing publicly by the owner's choice; opening it is the owner's decision.
3. **Neutral identifiers.** Move predicate URIs from this repository to the new home's domain, with a mapping from the v0.x names.
4. **Trust roots.** Work with accreditors that already vet sites (DMEA Trusted Supplier, O-TTPS) on issuing and revoking site keys.
5. **v1.0 criteria.** At least two independent verifier implementations, one production pilot, and every open question in the spec either closed or explicitly deferred.

**Exit:** v1.0 published under neutral governance.

## Running alongside: the L4 defense profile

L4 is expensive and mostly matters to defense and root-of-trust buyers, so it runs as research alongside the phases rather than blocking them:

- Sampling plans: what sample size makes an L4 claim meaningful for a given lot size.
- Inspection limits: which attacks delayering and imaging find, and which they miss, with references.
- Lab accreditation: who accredits inspection labs, and how a lab's key is trusted separately from the producer's.

## Decisions the owner needs to make

| Decision | Needed by |
| --- | --- |
| Whether to accept proxy-signed records at L1 | Phase 2 |
| Which buyer to offer the pilot kit to first, and whether by tarball (`pilot/make-kit.sh`) or a private invitation | Phase 4 |
| Whether to make the repository and spec public | Phase 5 (the pilot kit works while it stays private) |
| Which neutral home to approach first | Phase 5 |
