# Hardware Supply Chain Security Framework v0.1

**Status:** working draft, version 0.1, revision 3 (2026-09-13). See the [changelog](#changelog).

## Overview

HSLSA is a framework for proving how a chip or board was made, the way SLSA, SBOMs and in-toto do for software. It has three parts: a level scheme a buyer can ask for, one chain of signed attestations from RTL to a booted device, and a hardware bill of materials (HBOM) that ties the chain to the product.

This is version 0.1, a working draft. It consolidates the project's earlier drafts (the unified level scheme, a standards gap analysis, design provenance for RTL-to-GDS flows, fabrication and assembly attestations, firmware attestations, and the HBOM schema) into one text, and supersedes them where they disagree. Revision 2 writes in what the four [worked examples](#worked-examples-and-reference-implementation) needed: records for board parts, per-tool design steps, rebuilds and provisioning, and the checks a buyer runs on a board and on a booted device. Where the spec and the examples differ, the spec now matches what the examples, the HBOM schema and the reference tool do.

**Scope.** Digital ASIC and SoC design from RTL to GDSII, mask making, wafer fabrication and sort, packaging and final test, board assembly, and all firmware that ships in the part or on the board, through to the device proving what it booted. Out of scope for 0.1: distribution after the first buyer, the internals of secure boot and update protocols, and firmware for off-chip components (their vendors attest it, and it enters here as a dependency). Whether analog and mixed-signal flows can reach Design L3 is an open question.

**Conventions.** MUST, SHOULD and MAY carry their RFC 2119 meaning in requirement tables. Every predicate and schema URI lives under `https://github.com/Horiodino/hw-slsa/`, the repository that hosts this spec. URIs are identifiers and need not resolve; a custom domain can replace this prefix in a later version.

## Terminology

These terms mean the same thing in every section and every predicate.

| Term | Meaning |
| --- | --- |
| Track | One stage of the supply chain rated on its own: Design, Wafer, Package/Test, Assembly or Firmware. A product states one level per track. |
| Level | What a buyer can verify about a track: L0 (no claim) to L3 in the core, plus an optional L4 defense profile. Levels are cumulative within a track. |
| Step | One attested unit of work, run by one party: a design flow step (0 to 7, plus 6a ROM merge), a rebuild, a manufacturing step (F1 to F4, A1), a distribution (D), an inspection (X), a firmware build, or a provisioning pass. |
| Site | The organization and physical location that runs a manufacturing or provisioning step, identified by its site key. |
| Subject | What an attestation is about. Files are named by digest; physical things are named by a URN plus the digest of a canonical list that defines them. |
| Wafer lot | The wafers a fab started together. Subject of F1. |
| Packaged lot | Every unit that left the package line. Subject of F3. |
| Shipped lot | The units that passed final test. Subject of F4 and the lot subject of the HBOM; its digest is the lot digest. |
| Unit | One packaged part. Named by serial at Package/Test L2, and by the digest of its device identity certificate at L3. |
| Shipment | Parts one party ships to another, described by a packing list (manufacturer, part number, lot, date code, quantity, and serials where the part has them). Subject of a distribution record. |
| Board lot | The boards from one A1 build that passed test. Named and digested like a shipped lot, with board serials as the unit identifiers. |
| Device identity | A per-unit key rooted in hardware (DICE or Caliptra class), provisioned at sort or final test and endorsed by a CA. At L3 it is the unit's name in every attestation. |
| Release attestation | The tapeout authority's signed statement over the final GDS. Every manufacturing step points at it through `designRef`. |
| Provisioning | Writing images, fuses and keys into a part at a fab, OSAT or board line. It is Firmware work, recorded in `fw-provisioning`. |
| HBOM | The signed hardware bill of materials for a product: an in-toto statement whose subjects are the design (the GDS for a chip, the board design for a board) and the lot (the shipped lot or the board lot). |
| Rebuild | A second build of a released design from the same inputs, compared against the first. Recorded in a `rebuild` record; evidence for Design L4. |
| Hierarchy level | The HBOM's `product.level` field (die, package, module, board, system). It says what kind of product this is, not how assured it is. |
| Defense profile | The optional L4 requirements: a second, independent party reaches the same result as the first. |

## Tracks and levels

A product is rated per track, never overall: for example Design L3, Wafer L3, Package/Test L2, Assembly L1, Firmware L2. Each level is defined by what a buyer can verify, and a track's level is the lowest level all of its steps reach.

| Track | Covers | Who runs it | Steps |
| --- | --- | --- | --- |
| Design | RTL, IP, PDK, EDA flow to GDSII, mask ROM contents | Design house | 0 to 7, plus 6a ROM merge |
| Wafer | Mask making, wafer fabrication, wafer sort | Foundry, mask shop, sort house | F1, F2 |
| Package/Test | Packaging, final test | OSAT, test house | F3, F4 |
| Assembly | Part shipments to the assembler, PCB, board and system build | Distributors, EMS or contract manufacturer | D, A1 |
| Firmware | Boot ROM, device and board firmware, provisioning | Firmware team, programming stations at fab, OSAT and EMS | Image builds, provisioning passes |

Wafer and Package/Test are separate tracks because foundry and OSAT are usually different companies, and one rating hid the weaker of them.

| Level | Name | What the buyer can verify | Status |
| --- | --- | --- | --- |
| L0 | No claim | Nothing | Core |
| L1 | Provenance exists | A complete record of how the item was made, in a standard format | Core |
| L2 | Signed by the producer | The record was produced and signed by a controlled platform or site, not typed by hand | Core |
| L3 | Hardened | Signing keys and build steps are isolated, inputs are pinned, and the subject is rooted in a hardware identity | Core |
| L4 | Independently verified | A second, independent party rebuilt or physically inspected the item and got the same answer | Optional defense profile |

Claims are written as track plus level, such as `Design L3`. An L4 claim is written `Design L4 (defense profile)` and requires L3 in the same track; tooling that checks only the core reads it as L3.

### Core requirements

Each cell adds to the one on its left.

| Track | L1: Provenance exists | L2: Signed by the producer | L3: Hardened |
| --- | --- | --- | --- |
| Design | Every flow step emits a `design-flow` attestation (tools, PDK, parameters, subject digests) and the chain from GDS back to RTL is complete; the release record lists IP blocks and versions and the GDS digest; an HBOM is published | Steps run on a managed flow platform, not a workstation, and the platform identity signs each attestation; source freeze is a signed, reviewed tag; waivers are signed by a signoff owner; third-party IP arrives with signed provenance | Steps are isolated from each other and from the network; tools and PDK are pinned by digest and on an allow-list (a container image digest and a [PDK tree digest](#pinning-tools-and-pdks) count as pins); signing keys are unreachable from step code; formal equivalence between RTL and final netlist is recorded, and enough is attested for an independent party to rerun equivalence and LVS |
| Wafer | Lot record names the fab, mask set revision, GDS digest and probe program version | Each step signs with a site key; wafer fab names the wafer lot as subject; from sort onward, records name each unit | Keys held in HSMs at accredited sites (for example DMEA or O-TTPS); the fab verifies the design release attestation before mask making and records the mask-vs-GDS XOR; identities provisioned at sort are rooted in an on-die RoT (DICE or Caliptra class) and issued by an HSM-backed CA |
| Package/Test | Record names the OSAT, assembly lot and test program version for each lot | Each step signs with a site key; records name each unit, with genealogy to wafer and die position; every unit has a unique identity by final test; final test signs the shipped lot digest | Keys held in HSMs at accredited sites; every unit answers an identity challenge at final test, rooted in hardware; the shipped lot digest covers the units' certificate digests |
| Assembly | Board HBOM with lot and date code for every part, plus IPC-1782 style build records per serial number | Each assembly step signs its record against the board serial and the identities of its key components; every part lot arrives with a [distribution record](#distribution-record) signed by its shipper, and the assembler runs the lot receipt check on each chip before placement | Signing at accredited sites; component identities are checked by attestation at build; a platform certificate binds the system to its parts |
| Firmware | SLSA Build L1 provenance and an SBOM for every image; mask ROM content is proven by the Design track's ROM merge step | SLSA Build L2; images are signed and verified before the SoC runs them, by a secure-boot ROM on the silicon or by an attested board-level root of trust (proposed); a part with neither stops at Firmware L1 | SLSA Build L3; firmware is independently reviewed (S.A.F.E. style); releases appear in a transparency log; the device reports firmware measurements under a DICE or Caliptra class identity, and they match the attested image digests |

Three rules apply across tracks:

1. **Transparency logs may be private.** Every L3 log requirement is met by a private log (a private Rekor instance, or an RFC 9162 style log run by the buyer or a consortium), since no foundry will publish lot IDs or yields.
2. **Provisioning is Firmware, rated by its site.** Firmware Ln needs every provisioning site rated at least Ln in its own track (Wafer, Package/Test or Assembly).
3. **One check for the buyer.** At every level the buyer collects the attestations, confirms each subject matches the identity the device proves at boot, and compares the stated levels against policy. From Design L3, the tapeout check also requires the equivalence record.

**Firmware L2 through a board-level root of trust (proposed resolution).** A part without a secure-boot ROM MAY reach Firmware L2 on a board whose root of trust verifies the external flash, but only when that root of trust is itself attested (its own HBOM entry, Firmware provenance and provisioning record at L2 or higher) and it verifies each image before the SoC is released from reset. The claim is made for the board, not the bare part. This answers the open question in the level scheme and still needs the owner's sign-off.

### L4 defense profile

L4 is opt-in because its costs (a second builder, destructive part sampling) only make sense for root-of-trust, secure-element and defense parts.

| Track | L4 requirement (on top of L3) | Stops |
| --- | --- | --- |
| Design | A second, independently operated builder rebuilds from the same source and inputs and reaches a bit-exact or equivalent result, including the ROM macro, and signs a [`rebuild` record](#rebuild-record); two-person review on source freeze and waivers; tapeout release signed with an HSM key | A compromised flow platform or an insider on one builder |
| Wafer | Named regions of sampled die are delayered, imaged and compared against the signed GDS by an independent lab | Layout-level trojans and mask substitution at the foundry |
| Package/Test | Sampled units are decapsulated and X-rayed by an independent lab, and each die is matched to its genealogy and the signed GDS | Die swapped or remarked at the OSAT |
| Assembly | Sampled boards are X-rayed and components authenticated (SAE AS6171 style) by an independent lab, checked against the board HBOM | Counterfeit or substituted components that pass electrical test |
| Firmware | An independent party reproduces each image built from source bit for bit; two-person review on releases; per-unit data is covered by provisioning readback instead; a closed vendor binary caps the product at Firmware L3 unless its vendor supplies an independent rebuild | A compromised firmware build system or insider |

Wafer and Package/Test samples are drawn from the shipped lot after final test, so one inspection can serve both tracks. The lab commits to a random seed before the lot is sealed, states the lot size and sampling plan, and signs under a trust root separate from the producer's.

**SLSA and DoD alignment.** Design Ln and Firmware Ln each meet SLSA Build Ln for n from 1 to 3. From L2, Firmware adds device and review requirements SLSA does not have, so tooling must not treat the two as equal. How HSLSA lines up with DoD Microelectronics Levels of Assurance is inferred, not established: L3 in all tracks may approach LoA2, and the L4 profile may approach LoA3.

## Attestation model

Every record in HSLSA is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) in a DSSE envelope. The step predicates are strict supersets of SLSA Provenance v1: `buildDefinition` and `runDetails` keep their SLSA meaning, and hardware fields sit in one extra block, so an unmodified SLSA verifier can check signer, subjects and inputs.

### Predicate types

| Predicate | URI | Extra block | Emitted by | Subject |
| --- | --- | --- | --- | --- |
| Design flow step | `https://github.com/Horiodino/hw-slsa/design-flow/v0.1` | `hwFlow` | Flow platform, per step and once as a run summary | Output files of the step; the final GDS for the summary |
| Tapeout release | `https://github.com/Horiodino/hw-slsa/design-flow/v0.1`, buildType `.../design-flow/step/release@v1` | `hwFlow` | Tapeout authority | Final GDS |
| Source review | `https://github.com/Horiodino/hw-slsa/source-review/v0.1` | none | Reviewer, who is not the commit's author | The reviewed commit (`gitCommit` digest) |
| Third-party IP release | `https://slsa.dev/provenance/v1` (unchanged), buildType `.../ip-release@v1` or the vendor's own | none | IP vendor | The released IP files |
| Rebuild (L4) | `https://github.com/Horiodino/hw-slsa/design-flow/v0.1`, buildType `.../design-flow/step/rebuild@v1` | `hwFlow` | Second builder | Final GDS of the release it rebuilt |
| Manufacturing step | `https://github.com/Horiodino/hw-slsa/manufacturing-step/v0.1` | `hwMfg` | Fab, sort, OSAT, test and EMS sites | Wafer lot, packaged lot, shipped lot, or board lot and boards |
| Distribution | `https://github.com/Horiodino/hw-slsa/manufacturing-step/v0.1`, buildType `.../mfg/step/distribution@v1` | `hwMfg` | The shipper: a distributor, or a manufacturer shipping direct | The shipment's packing list |
| Physical inspection (L4) | `https://github.com/Horiodino/hw-slsa/physical-inspection/v0.1` | none | Independent lab | Shipped lot and each sampled unit or board |
| Firmware image build | `https://slsa.dev/provenance/v1` (unchanged), buildType named for the builder (for example `.../firmware/caliptra-builder@v1`) | none | Firmware build platform | Image digest |
| Firmware provisioning | `https://github.com/Horiodino/hw-slsa/fw-provisioning/v0.1`, buildType `.../fw-provisioning/step/provision@v1` | `hwProvision` | Programming station at fab, OSAT or EMS | Each unit written |
| Firmware review | `https://github.com/Horiodino/hw-slsa/fw-review/v0.1`, wrapping an OCP S.A.F.E. report | none | Review provider | Image digest |
| HBOM | `https://github.com/Horiodino/hw-slsa/hbom/v0.1` | none | Product owner | Design (final GDS or board design) and lot (shipped lot or board lot) |
| Verification summary | `https://slsa.dev/verification_summary/v1` | none | Vendor or buyer verifier | Any subject above |

Step types are named `https://github.com/Horiodino/hw-slsa/design-flow/step/<step>@v1` and `https://github.com/Horiodino/hw-slsa/mfg/step/<step>@v1`. A flow platform MAY instead name the tool that ran the step, as in `.../design-flow/step/openlane2@v1`, when it also states the spec step in `hwFlow.step` (see [Per-tool design steps](#per-tool-design-steps)). A verification summary reports levels as `HSLSA_<TRACK>_LEVEL_<n>` (for example `HSLSA_WAFER_LEVEL_3`); SLSA allows custom `verifiedLevels` values that do not start with `SLSA_`.

### Naming subjects

Files are named by sha256 (sha384 where a device reports SHA-384 measurements, as Caliptra does). Physical things have no file digest, so each one is a URN plus the digest of the canonical list that defines it. All physical names use one URN prefix, `urn:hslsa:`.

| Thing | Name | Digest over |
| --- | --- | --- |
| Wafer lot | `urn:hslsa:wafer-lot:<fab-id>:<lot-id>` | Its sorted wafer IDs |
| Wafer map | The map file (SEMI E142 or the foundry's format) | File digest |
| Packaged lot | `urn:hslsa:assembly-lot:<lot-id>` | Every unit that left the package line |
| Shipped lot | `urn:hslsa:lot:<lot-id>` | The lot digest (below) |
| Unit | `urn:hslsa:unit:<serial>` | In the lot: the serial at Package/Test L2, the DER identity certificate at L3. As the subject of a record about one device, see below |
| Shipment | The packing list file | File digest |
| Board lot | `urn:hslsa:lot:<board-lot-id>` | The lot digest (below), over the serials of the boards that passed test |
| Board | `urn:hslsa:board:<manufacturer>:<serial>` | The DER identity certificate once the board has one; until then the serial itself, as UTF-8 bytes with no trailing newline |

`<manufacturer>` in a board URN is the manufacturer's name in lowercase with spaces replaced by hyphens.

A record about one device names it by its strongest identity, whatever level the lot claims:

- A `fw-provisioning` record for a unit with a device identity uses the sha256 of its IDevID public key (the DER SubjectPublicKeyInfo) as the digest, because the station signs before the certificate is used and the key is what the device proves at boot.
- A verification summary for a booted unit (a unit VSA) uses the sha256 of its DER IDevID certificate when the unit has a device identity, and the serial otherwise. The Caliptra example does this while its lot is still named by serials at Package/Test L2.

### Lot digest

The shipped lot digest is the single binding between the HBOM and the physical units. It is computed the same way wherever it appears (F4, the HBOM, inspection records):

```math
\mathrm{lotDigest} = \mathrm{SHA256}\big(\mathrm{join}(\mathrm{sort}(u_1, \dots, u_n), \texttt{\textbackslash n}) \,\|\, \texttt{\textbackslash n}\big)
```

Each unit identifier is the serial (Package/Test L2) or the lowercase hex sha256 of the unit's identity certificate in DER (Package/Test L3), sorted as byte strings, joined with newlines and ending in one newline. Yield loss changes the lot between packaging and shipment, so F3 names the packaged lot and F4 names the shipped lot; the verifier checks that shipped units are a subset of packaged ones and that F4's yield record accounts for the rest.

### Signing and keys

Platforms and sites sign step records; people sign only decisions.

| Signer | Signs | Key model |
| --- | --- | --- |
| Design flow platform | Every design step and the run summary | Sigstore keyless (OIDC workload identity to Fulcio), a private Sigstore, or an HSM-held or local key for air-gapped or private flows |
| Second builder (L4) | `rebuild` records | Its own key, under a trust root separate from the first builder's |
| Design engineer | Source freeze tag, ECO attestations | Personal key, or keyless with corporate SSO |
| Signoff owner | Waivers, signoff approval | Hardware token (FIDO2 or smart card) |
| Tapeout authority | Release attestation over the GDS | Offline or HSM-held key |
| IP and PDK vendors | Their own deliverables | Vendor key in a trust root (open question) |
| Distributor, or a manufacturer shipping direct | Distribution records for the shipments it sends | Its own site key; the buyer's policy lists which shippers are authorized channels for which manufacturers |
| Foundry, sort, OSAT, test and EMS sites | Every manufacturing step | X.509 site key, in an HSM from L3; the certificate names the site and its accreditation |
| Process or quality engineer | Deviations, rework orders, bin-limit waivers | Hardware token |
| Identity provisioning CA | Unit identity certificates | HSM-held CA key per product line |
| Firmware build platform | Image provenance and SBOM | As for the design flow platform |
| Programming station | `fw-provisioning` records | The site key of the site it sits in |
| Independent lab (L4) | Inspection records | Lab's own key under a trust root separate from the producer's |

None of these key models requires a public transparency log. The reference tool signs every record as a DSSE envelope with a local ECDSA P-256 key, publishes nothing, and hands the buyer a trust root of public keys by role; that meets every requirement up to L2, and L3 logs may be private (see the rules under [Core requirements](#core-requirements)).

### Rules every step follows

1. **Decisions are inputs.** Waivers, process deviations, rework orders and bin-limit waivers are `externalParameters` with their own digest and signer.
2. **Edits and rework are steps.** An ECO, manual layout fix, reworked wafer or re-marked package gets its own attestation; anything that re-enters the chain without one breaks it on purpose.
3. **Nothing disappears silently.** Scrap is recorded in the yield block, so a lot cannot gain or swap units unnoticed.
4. **Confidential values are digests.** A field a supplier will not disclose (recipe, yield, fab site, wafer IDs, third-party IP) is replaced by a salted digest and listed by JSON Pointer (`hwMfg.confidential[]` in step records, `redactions[]` in the HBOM). An auditor given the salt can confirm the value.
5. **Third-party inputs are dependencies.** Hard IP, cell libraries, PDKs and vendor firmware are pinned by digest in `resolvedDependencies`, with the vendor's own attestation linked when one exists.

### Record shapes

The examples needed four record shapes the drafts left open. Each is still an in-toto Statement whose predicate is a superset of SLSA Provenance v1.

#### Pinning tools and PDKs

A tool MAY be pinned by the digest of the container image it runs in, as a `resolvedDependencies` entry with a `docker://` URI and the image's index digest; the step then lists each tool binary it used with its digest inside that image in `hwFlow.tools`. A PDK or any other directory tree MAY be pinned by one tree digest:

- Walk the tree from its root, directory by directory. In each directory take the entries that are files or symlinks, sorted by name, then descend into the subdirectories, sorted by name.
- Write one line per file, `F <path> <sha256>`, and one per symlink, `L <path> <target>`, where `<path>` is relative to the root with `/` separators.
- The tree digest is the sha256 of those lines joined with newlines, with no trailing newline.

Every step of one flow MUST name the same source, image and PDK digests, so a verifier can check that nothing changed mid-flow. The [OpenLane 2 example](../docs/openlane2-flow.md) pins the SKY130A variant this way.

A flow MAY replace files inside a pinned image, for example so that tools stop writing the build time into their outputs. The replacement files are then one more `resolvedDependencies` entry, pinned by tree digest, annotated `kind: overlay` and listing the digest of each image file they replace. A `SOURCE_DATE_EPOCH` the flow passes to its tools goes in `externalParameters.sourceDateEpoch`. Every step MUST name the same overlay and the same `SOURCE_DATE_EPOCH`. The OpenLane 2 example needs both for a byte-identical GDS ([its overlay](../openlane2/overlay/README.md)).

#### Per-tool design steps

A flow tool usually runs many small steps for each spec step (OpenLane 2's Classic flow runs 74 for steps 1 to 7). A flow platform MAY sign one record per tool step, with buildType `.../design-flow/step/<tool>@v1`, as long as each record:

- states the spec step it belongs to in `hwFlow.step` (`simulation`, `synthesis`, `floorplan`, `place-cts`, `routing`, `signoff` or `gds-stream-out`), and the tool's own step name in a tool-specific field (`hwFlow.openlaneStep` with its `ordinal`);
- lists every input design view by digest, each an output of an earlier record, and the previous record itself;
- carries the step's resolved configuration by digest, and the metrics the step changed in `hwFlow.metrics`.

The verifier requires every spec step from synthesis to stream-out to be covered by at least one record, the records to be linked in order, and the released GDS to be a subject of the last stream-out record. The mapping from OpenLane 2 step names to spec steps is in [`tools/hslsa/openlane.go`](../tools/hslsa/openlane.go).

#### Rebuild record

A `rebuild` record is a design-flow statement with buildType `.../design-flow/step/rebuild@v1`, signed by the second builder. Its subject is the released final GDS. Its `resolvedDependencies` are the release attestation it rebuilt (`kind: release`) and the source, image, PDK and any overlay it built from, and `hwFlow.checks` carries two results:

| Check | Passes when |
| --- | --- |
| `gds-bit-exact` | The second build's final GDS is byte-identical to the released one |
| `gds-equal-ignoring-timestamps` | The two are equal once the GDS BGNLIB and BGNSTR dates are cleared |

`hwFlow.reproducibility` MAY add a per-output comparison and the first step whose outputs differ in content. A Design L4 claim needs a rebuild record from an independently operated builder in which `gds-bit-exact` passes; a buyer's policy MAY accept `gds-equal-ignoring-timestamps` instead, and says so. At tapeout the verifier accepts a rebuild record only when:

- it is signed by a key the buyer lists for the `rebuilder` role, in a trust root of its own, and none of the rebuilder's keys is a key of the design house;
- its `runDetails.builder.id` is not the builder of any step record in the flow;
- its subject is the released GDS, and it names that release attestation;
- it built from the same source, image, PDK, overlay and `SOURCE_DATE_EPOCH` as the flow;
- the check the policy requires passes.

Records cannot show who operates a key. That the second builder is independently operated is something the buyer establishes before listing its key, as for any site key. The [OpenLane 2 example](../docs/openlane2-flow.md#the-rebuild-and-the-buyers-check) rebuilds its release bit for bit on a separate runner, with its own keys, trust root and builder id, and its tapeout check requires `gds-bit-exact`. Both builders still run under one GitHub account, so it is not yet an independently operated rebuild.

#### Distribution record

A distribution record is a manufacturing-step statement with buildType `.../mfg/step/distribution@v1`, signed by whoever ships a lot of parts to the assembler. Its subject is the shipment's packing list, by file digest. For a part that has its own chain, it consumes that part's shipped lot (the URN and lot digest), and the packing list names the serials shipped. `hwMfg.site` names the shipper, and `hwMfg.checks` carries at least `certificate-of-conformance` and `traceable-to-manufacturer`. The board HBOM points at it from `parts[].distributionRef`. See the [board example](../docs/board-example.md).

#### Firmware provisioning record

A `fw-provisioning` record is SLSA Provenance v1 with buildType `.../fw-provisioning/step/provision@v1` and one extra block, `hwProvision`:

| Field | Holds |
| --- | --- |
| `station`, `site` | The programming station and the site it sits in |
| `unit`, `lot` | `urn:hslsa:unit:<serial>` and the shipped lot it belongs to |
| `designRef` | The released design and its release attestation |
| `images[]` | Each image written: name, role, storage, digest, readback digest, and whether its provenance was verified before writing |
| `fuses` | Every fuse value burned, except secrets |
| `secrets[]` | Each secret by field, key id and origin (`generated-on-die`, or the injecting HSM), never its value |
| `identity` | For a part with a device identity: scheme, UEID, IDevID public key digest, the endorsed certificate by digest, and the endorsing CA |
| `checks[]` | At least `image-provenance-verified`, `image-readback` and `fuse-readback`; `lifecycle-production` where the part has a lifecycle state |

`resolvedDependencies` lists each image's provenance and the images, and for a part with an identity the exported CSR and the endorsed certificate. The subject is the unit, named as in [Naming subjects](#naming-subjects). The [Caliptra example](../docs/caliptra-e2e.md) signs one per unit.

## The attestation chain

A verifier holding a booted device can walk by digest alone from its identity certificate to the shipped lot, back through packaging and the wafer lot to the signed GDS, and from there to reviewed RTL and every tool and PDK used. Each step lists the previous step's subjects in `resolvedDependencies`, and every manufacturing step copies the GDS release into `hwMfg.designRef`.

```mermaid
flowchart TD
  FW["Firmware builds<br/>SLSA provenance and SBOM"]
  D["Design · steps 0 to 7<br/>design-flow record per step"]
  R["Design · tapeout release<br/>subject: final GDS digest"]
  F1["Wafer · F1 wafer fab<br/>wafer lot; designRef = GDS"]
  F2["Wafer · F2 wafer sort<br/>wafer maps; units named"]
  F3["Package/Test · F3 package<br/>packaged lot, die genealogy"]
  F4["Package/Test · F4 test<br/>subject: shipped lot digest"]
  DI["Assembly · D distribution<br/>subject: packing list"]
  A1["Assembly · A1 board build<br/>board lot, boards, build records"]
  RB["Design · rebuild (L4)<br/>second builder, same GDS"]
  DEV(["Booted device<br/>IDevID and FWIDs, per boot"])
  P["Provisioning<br/>fw-provisioning record per unit"]
  H["HBOM<br/>subjects: final GDS, shipped lot"]
  FW -- "mask ROM image" --> D
  D --> R --> F1 --> F2 --> F3 --> F4 --> DI --> A1 --> DEV
  RB --> R
  FW --> P
  P --> F2
  P --> F4
  P --> A1
  H --> R
  H --> F4
  DEV -. "IDevID matches record" .-> P
  DEV -. "verifier walks back" .-> H
```

Each arrow is a digest link. A board has its own HBOM, with the board design and board lot as subjects, that points at A1, at each distribution record and at each chip's HBOM. Firmware joins twice: mask ROM content through the Design flow, everything else through provisioning records. The dashed lines are the checks a verifier runs from a live device.

### Steps

| Step | Track | Consumes (by digest) | Produces (subject) | Key gates in `checks` |
| --- | --- | --- | --- | --- |
| 0. Source freeze | Design | RTL tree, testbenches, constraints, IP manifests; at L2 the signed tag's commit, its source review and each IP block's provenance | Source archive | At L2, signed tag, source review and IP provenance verified; two-person review at L4 |
| 1. Simulation and lint | Design | Source archive, testbenches, IP models | Coverage and log reports | Tests pass, coverage threshold |
| 2. Synthesis | Design | Source archive, liberty files | Gate-level netlist, SDC | Lint clean; netlist vs RTL equivalence |
| 3. Floorplan and power | Design | Netlist, SDC, tech and cell LEF | ODB/DEF | Macro placement check |
| 4. Placement and CTS | Design | Floorplan ODB | Placed ODB | Post-CTS timing |
| 5. Routing | Design | Placed ODB | Routed ODB/DEF, SPEF | Route DRC count = 0 |
| 6. Signoff | Design | Routed layout, SPEF, DRC and LVS decks | Timing, DRC, LVS reports | STA met, DRC clean, LVS match, waivers digest |
| 6a. ROM merge (mask ROM only) | Design, for Firmware | ROM image (by its SLSA provenance digest), ROM compiler, empty ROM macro | Programmed ROM macro GDS, merged layout | `rom-readback`: bits extracted from layout match the image digest; optional `rom-matches-frozen` (see [Mask ROM](#mask-rom)) |
| 7. GDS stream-out | Design | Routed layout, cell, IP and ROM macro GDS | Final GDSII/OASIS | GDS vs DEF XOR clean |
| Release | Design | Run summary over steps 0 to 7 | Final GDS | Tapeout policy check (below) |
| Source review | `https://github.com/Horiodino/hw-slsa/source-review/v0.1` | none | Reviewer, who is not the commit's author | The reviewed commit (`gitCommit` digest) |
| Third-party IP release | `https://slsa.dev/provenance/v1` (unchanged), buildType `.../ip-release@v1` or the vendor's own | none | IP vendor | The released IP files |
| Rebuild (L4) | Design | Release attestation, the same pinned inputs | Final GDS of the release | `gds-bit-exact`, `gds-equal-ignoring-timestamps` |
| F1. Wafer fabrication | Wafer | GDS release, mask set record | Wafer lot | Mask data vs GDS XOR; inline parametrics |
| F2. Wafer sort | Wafer | F1, wafer lot | Wafer maps; unit identities if provisioned here | Probe pass; identity provisioning log |
| F3. Packaging | Package/Test | F2, wafer maps, package material certificates | Packaged lot, die-to-unit genealogy | Die attach, wire bond, X-ray sample, marking |
| F4. Final test | Package/Test | F3, packaged lot | Shipped lot, unit identities, STDF results | Final test per unit; identity challenge; yield within limits |
| Firmware build | Firmware | Firmware source and toolchain | Image and its SBOM | As for any SLSA build |
| Provisioning | Firmware | Images (after verifying their provenance), fuse map, key origins | Each unit written | Readback digest per image and fuse field |
| D. Distribution | Assembly | For a part with its own chain, its shipped lot | The shipment's packing list | Certificate of conformance; traceable to the manufacturer |
| A1. Board assembly | Assembly | Every distribution record, the HBOM and F4 record of each chip with its own chain, the chip shipped lots, the board design | Board lot, each board, the per-serial build records; platform certificate at L3 | Part lot receipt check; AOI, BGA X-ray, ICT, functional test; yield; component identity check at L3 |
| X. Inspection (L4) | Wafer, Package/Test or Assembly | Sampled units or boards, committed seed | Result over lot and sampled identities | Per-unit pass, fail or inconclusive |

The design steps stop at the signed GDS release; mask data preparation (OPC, fracturing) happens inside the foundry and is recorded in F1. On a multi-project wafer, F1 is issued once per customer design, so no customer sees another's GDS digest. Wafer lots and assembly lots are many-to-many, so F3 records (wafer lot, wafer, X, Y) for every unit.

### Mask ROM

A mask ROM is firmware by build and silicon by delivery, and nothing on the running device can check it, because it does the checking. Its trust therefore runs through the Design track: the image carries ordinary SLSA provenance, and step 6a proves with `rom-readback` that the layout holds exactly that image. Three rules follow. The ROM image's provenance must exist before step 6a, so ROM firmware reaches Firmware L1 no later than the chip reaches Design L1. ROM patches held in OTP are provisioned data, recorded in `fw-provisioning`. At Design L4 the independent rebuild must reproduce the ROM macro, which needs the image to rebuild bit for bit.

When a third party has published a digest for the ROM image (the Caliptra TAC's frozen-image list, for example), step 6a MAY also record `rom-matches-frozen`, which passes when the image built from source equals that published digest. It is an independent rebuild of the ROM image by the party that froze it, so it counts toward the Firmware L4 rebuild requirement for the ROM, but not toward Design L4, which is about the layout.

### Provisioning

The programming station is the firmware's last builder. For every part it writes it MUST verify each image's provenance before writing, read back every image and fuse field and record the readback digest, name secrets only by key id and origin (`generated-on-die`, or the injecting HSM), record the IDevID public key digest and endorsing CA for DICE or Caliptra parts, and sign with its site's key. The record's shape is defined under [Firmware provisioning record](#firmware-provisioning-record). One record MAY cover a lot programmed in one pass for a part without a device identity; a part with one gets a record per unit, whose subject is that unit's IDevID public key digest, because the at-boot check starts from it.

| Stage | Site | Typically written |
| --- | --- | --- |
| Wafer sort | Fab or test house | Identity seed (UDS), lifecycle state, trim and calibration fuses |
| Final test | OSAT | Remaining fuses, on-die flash images, IDevID CSR export for endorsement |
| Board assembly | EMS | External flash images, board-level keys, platform certificate inputs |

### Where the chain is checked

**At tapeout**, before the GDS leaves for the foundry:

1. The GDS digest matches the release attestation, signed by an allowed tapeout authority.
2. Every step from source freeze to stream-out is present, signed by an allowed builder, and linked by digest. With [per-tool records](#per-tool-design-steps), each spec step is covered by at least one record and every input view is an output of an earlier record.
3. Every tool and PDK digest (or the image and PDK tree digests that pin them) is on the approved list, and every step names the same ones.
4. Every required gate passed, every waiver is signed by a signoff owner, and a chip with a mask ROM passed `rom-readback`.
5. From Design L2, the source freeze consumes a tag signed by an allowed source owner and a source review of the same commit by someone other than its author, and the verifier walks git's object hashes from the tag to every file in the source archive. Every IP block the release lists has provenance signed by its vendor, and the IP files in the archive match it.
6. From Design L3, an equivalence record between RTL and final netlist exists; at Design L4, a [`rebuild` record](#rebuild-record) from an independent builder also exists and passes the check the policy asks for (`gds-bit-exact` by default).

**At lot receipt**, by the buyer, OEM or EMS:

1. The HBOM's lot subject equals the F4 shipped lot digest, and every received unit is in it (at L3, each unit answers a challenge with a certificate whose digest is in the lot).
2. F1 to F4 are all present, signed by allowed sites, and linked by digest.
3. Every step's `designRef` names the same GDS, and its release attestation verifies at the buyer's minimum Design level.
4. Genealogy is complete and yields reconcile from F2 to F4.
5. Every required gate passed and every deviation or rework is signed.
6. For an L4 claim, an inspection record from an allowed lab covers the lot, with an acceptable sampling plan and no failed sample.

Board assembly runs this same check on each part before placement, then adds A1, so a system integrator verifies the board and, through it, every part.

**At board receipt**, by the system integrator or board buyer:

1. The board HBOM is signed by the board owner and valid against the schema, and its lot subject is A1's board lot.
2. A1 is signed by an allowed EMS site, its gates passed, it names the same board design, and it consumes every distribution record and each chip's shipped lot and HBOM.
3. Every `parts[]` entry has a distribution record signed by a shipper the policy names, with the same lot and date code. `authorized: true` holds only where the policy lists that shipper as an authorized channel for the manufacturer, and the policy MAY require an authorized channel for every part.
4. Each chip with its own chain passes the lot receipt check above under its own trust root, every chip shipped to the EMS is in its shipped lot, and the board HBOM names the lot that chain proves.
5. `parts[]` covers exactly the board design's reference designators; every placement in the build records is a listed lot; no serialized part is placed twice or placed without being shipped, and no lot is placed more often than it was shipped.
6. The board lot is the set of boards that passed test, A1's yield accounts for the rest, every board in the lot is an A1 subject, and every received board is in the lot.

The [board example](../docs/board-example.md) runs these checks and breaks each one in its tamper tests.

**At boot**, on every unit with a device identity (required for a Firmware L3 claim, and available from Firmware L2):

1. Check the device's certificate chain to the identity CA in the trust root, as any DICE verifier does, and check that every certificate names the unit (its UEID) and that the unit is in the shipped lot.
2. Find the `fw-provisioning` record whose subject is the IDevID public key digest. It must be signed by an allowed station site, name this unit, this lot and this design release, and have all its gates passed; it gives the site, fuse state and images written.
3. For each FWID in the alias certificates (TCG DICE TcbInfo), find image provenance with that digest as subject, and check its level (and, for L3, review and log inclusion). Where the device also measures its fuses (Caliptra's vendor and owner fuse info, for example), recompute those measurements from the fuses the provisioning record says were burned; they must match what the device reports.
4. Confirm the HBOM's GDS has a Design chain whose ROM merge step consumed the ROM image named by its provenance and passed `rom-readback`; that is the only way the mask ROM, which took the first measurement, is covered. If the policy asks for it, `rom-matches-frozen` must also have passed.
5. Check that the SVN the device reports equals the image's SVN in its provenance, and that it is not below the anti-rollback fuse value in the provisioning record or the policy minimum.

A verifier that passes these steps MAY sign a unit VSA, whose subject is named as in [Naming subjects](#naming-subjects). The [Caliptra example](../docs/caliptra-e2e.md#the-at-boot-check) runs these five steps on emulated units at Firmware L2.

Policy can be written in existing in-toto tooling (layouts, witness policies or Rego), because the envelopes are standard.

## Hardware bill of materials

The HBOM is the one document a buyer starts from: it lists what the product is made of and who made each part, and points by digest at every attestation in the chain rather than copying them. It is required from Design L1.

**Format.** The HBOM is a CycloneDX 1.6 document at its core, with every extension also mapped to SPDX 3.1 so either can be emitted. SPDX 3.0 has no hardware profile; the mapping targets the SPDX 3.1 release candidate (Hardware classes `PhysicalHardware`, `BulkHardware`, `VirtualHardware`; SupplyChain classes `ManufactureProcess`, `AssemblyProcess`, `TestProcess`, `ResponsibilityChangeProcess`) and will be rechecked when 3.1 is final. New fields live in one `hbom:` namespace; in CycloneDX they travel as properties prefixed `hbom:`.

**Envelope and subjects.** The HBOM ships as the predicate of an in-toto Statement with predicate type `https://github.com/Horiodino/hw-slsa/hbom/v0.1` and two subjects:

1. **Design subject:** the final GDS, by sha256, for a die or package. Every part from this tapeout shares it. For a module, board or system it is the board design package (schematic, Gerbers, pick-and-place and BOM), by sha256.
2. **Lot subject:** `urn:hslsa:lot:<lot-id>` with the lot digest as its digest: the shipped lot from F4 for a die or package, the board lot from A1 for a module, board or system. A verifier holding one part or board checks its serial or identity certificate against that lot.

**Predicate.** What is required depends on the hierarchy level, so a shuttle chip or a small board with little data still validates; the rest fills in as a supplier climbs levels.

| `product.level` | Required |
| --- | --- |
| Any | `hbomVersion`, `product`, `manufacturing` |
| `die`, `package` | `manufacturing.fab` |
| `module`, `board`, `system` | `manufacturing.boardAssembly` and `parts[]`; no fab data, which lives in each part's own HBOM |

| Block | Holds | Points at |
| --- | --- | --- |
| `product` | Name, hierarchy level (die, package, module, board, system), part number, revision, manufacturer, purl, device identity scheme | Nothing |
| `renderings[]` | Full CycloneDX or SPDX documents for the same product | Each by digest |
| `design` | IP blocks (kind, supplier, license, IEEE 1735 flag), RTL sources by commit, PDK, flow steps and tools, final layout | Each flow step's `design-flow` attestation via `provenanceRef` |
| `manufacturing` | Foundry, process node, mask set, shuttle, wafer lots, OSAT and package, test stages and programs; for boards, the EMS and board lot in `boardAssembly` | F1 via `fab.attestationRef`, F3 via `assembly.attestationRef`, F2 and F4 results via `test[].resultsRef`, A1 via `boardAssembly.attestationRef` |
| `firmware[]` | Each image's name, role, storage (mask-rom, otp, on-die-flash, external-flash) and digest | Its SBOM via `sbomRef` |
| `parts[]` | For boards: reference designators, manufacturer, MPN, date code, lot, distributor, authorized channel | The part's own HBOM via `hbomRef`; the shipment via `distributionRef` |
| `redactions[]` | JSON Pointers to withheld fields and their salted digests | Nothing |

**Changes from the HBOM draft.** This spec makes these changes to the draft schema so it fits the rest of the chain:

1. The lot subject is renamed from `urn:hbom:lot:` to `urn:hslsa:lot:` and names the shipped lot, with the lot digest defined above (serials at Package/Test L2, certificate digests at L3).
2. The supplier slices the draft left undefined are the `manufacturing-step` records defined here: `fab.attestationRef` points at F1, `assembly.attestationRef` at F3, and `test[].resultsRef` at the F2 or F4 results that record signs.
3. `flowStep.step` gains `rom-merge` and `release`, so the HBOM can reference every Design step.
4. `product.level` keeps its name but is documented as the hierarchy level only; assurance levels are not stated in the HBOM (see open questions).
5. `manufacturing.fab` is required only for dies and packages; boards, modules and systems require `manufacturing.boardAssembly` and `parts[]` instead.
6. New `manufacturing.boardAssembly` block: `ems`, `boardLot`, and `attestationRef` to A1.
7. New `parts[].distributionRef`: the signed distribution record for that part's lot.

The JSON Schema and the worked examples are in this repository at [`hbom/hbom-predicate-v0.1.schema.json`](../hbom/hbom-predicate-v0.1.schema.json), [`hbom/picosoc-sky130.hbom.intoto.json`](../hbom/picosoc-sky130.hbom.intoto.json) and [`hbom/picosoc-devboard.hbom.intoto.json`](../hbom/picosoc-devboard.hbom.intoto.json), all current with these changes. [`hbom/picosoc-sky130.shipped-lot.txt`](../hbom/picosoc-sky130.shipped-lot.txt) and [`hbom/picosoc-devboard.board-lot.txt`](../hbom/picosoc-devboard.board-lot.txt) are their canonical unit and board lists, so both lot digests can be recomputed.

**Worked example.** The PicoRV32-based PicoSoC on SkyWater SKY130, packaged in QFN-64, uses serial identities, so it can claim at most Package/Test L2. Its test verifies Design L2: the flow platform signs every step, the source freeze is an SSH-signed git tag with a source review by someone other than the author, and PicoRV32 arrives with IP provenance signed by a key standing in for its vendor. It stops at Firmware L1: both images live in external SPI flash and the silicon has no secure-boot ROM, so a provisioning record for it would carry empty `fuses`, `secrets` and `identity` fields, showing a buyer that nothing in the part anchors the firmware. Under the proposed board-level root of trust rule, a board carrying it could reach Firmware L2; the example board has no root of trust, so it stays at Firmware L1.

## Relationship to existing standards

HSLSA reuses an existing standard wherever one fits and adds only the glue: per-step predicates for hardware, the physical subject naming, and the rules that tie device identity to supply chain records. Citations were checked on 2026-09-02.

| Software concept | HSLSA element | Standards reused |
| --- | --- | --- |
| SLSA Build track | Design and Firmware levels; step predicates are SLSA Provenance v1 supersets | [SLSA v1.2](https://slsa.dev/spec/v1.2/) |
| in-toto attestations | Every record in the chain | [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), DSSE |
| SBOM | HBOM; per-image firmware SBOMs | [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) (ECMA-424), [SPDX 3.1 RC](https://spdx.dev/spdx-3-1-ontology-and-schema-available-for-review/), [CISA HBOM framework](https://www.cisa.gov/resources-tools/resources/hardware-bill-materials-hbom-framework-supply-chain-risk-management) |
| Artifact digest | Device identity as the subject of a physical part | [TCG DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/), [Caliptra](https://www.chipsalliance.org/news/caliptra2-1/), [DMTF SPDM](https://www.dmtf.org/standards/spdm) |
| Sigstore, Rekor | Keyless signing for design and firmware platforms; public or private logs | Sigstore, [IETF SCITT (RFC 9943)](https://www.rfc-editor.org/rfc/rfc9943), RFC 9162 |
| Verification before use | Tapeout, lot receipt and boot checks | [IETF RATS (RFC 9334)](https://www.rfc-editor.org/rfc/rfc9334), [TCG Platform Certificate](https://trustedcomputinggroup.org/resource/tcg-platform-certificate-profile/), [CoRIM](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/) (still an Internet-Draft) |
| Independent review | Firmware L3 review; `fw-review` | [OCP S.A.F.E.](https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Documentation/framework.md) |
| Build records | Wafer, Package/Test and Assembly step records | [IPC-1782](https://standards.globalspec.com/std/14358527/ipc-1782) traceability, SEMI E142 wafer maps, STDF test results |
| Supplier assessment | L3 accredited sites | [DMEA Trusted Supplier](https://www.acq.osd.mil/asds/dmea/tapo/trusted-supplier-programs.html), [O-TTPS (ISO/IEC 20243)](https://www.opengroup.org/open-trusted-technology-provider%E2%84%A2-standard-o-ttps-approved-isoiec-international-standard), SEMI E187 for equipment |
| Dependency integrity | Signed IP provenance; encrypted IP flag | [IEEE 1735-2023](https://standards.ieee.org/standard/1735-2014.html), [Accellera SA-EDI](https://www.accellera.org/news/press-releases/373-accelleras-security-annotation-for-electronic-design-integration-standard-1-0-moves-toward-ieee-standardization) |
| Counterfeit detection | Assembly L4 inspection | SAE AS5553, AS6171, AS6081 |
| Assurance tiers | L3 and the L4 profile (alignment inferred) | [DoD Microelectronics Levels of Assurance](https://media.defense.gov/2022/Jul/14/2003034921/-1/-1/0/CTR_DOD_MICROELECTRONICS_LEVELS_OF_ASSURANCE_DEFINITIONS_AND_APPLICATIONS_20220714.PDF) |

Traceability work under way at [NIST IR 8536](https://www.semiconductors.org/wp-content/uploads/2025/10/SIA-Final-Comments-on-NIST-IR-8536-2pd_10.03.pdf) and [STAMP](https://csrc.nist.gov/csrc/media/Presentations/2025/semiconductor-traceability/images-media/WedAM2.2-STAMP_Intro_NIST_SSCA.pdf) could become the data layer under the manufacturing records; that is not yet decided.

## Worked examples and reference implementation

Four examples run in this repository's GitHub Actions and exercise the spec end to end. Each signs every record, checks the chain the way a buyer would, and hands the resulting verification summaries to the official slsa-verifier. Each also runs tamper tests that forge or break a link and require the check to fail for the stated reason.

| Example | Exercises | Levels verified | Docs |
| --- | --- | --- | --- |
| PicoRV32 on SKY130 | Signed source tag, source review and IP provenance, design steps 0 to 2, release, F1 to F4, chip HBOM, tapeout and lot receipt checks | Design L2, Wafer L2, Package/Test L2 | [e2e-test.md](../docs/e2e-test.md) |
| Board with the PicoSoC | Distribution records, A1, board HBOM with `parts[]`, board receipt check | Assembly L2 | [board-example.md](../docs/board-example.md) |
| OpenLane 2 `spm` on SKY130 | Per-tool records for design steps 1 to 7, image, PDK tree and script overlay pins, release of a real GDS, a bit-exact `rebuild` record from a second builder under its own trust root, checked at tapeout | Design L4 rebuild evidence from the same operator, not an L4 claim | [openlane2-flow.md](../docs/openlane2-flow.md) |
| Caliptra | ROM merge with `rom-readback` and `rom-matches-frozen`, firmware provenance and SBOMs, per-unit `fw-provisioning`, the at-boot check on emulated units, unit VSAs | Design L1, Wafer L2, Package/Test L2, Firmware L2 | [caliptra-e2e.md](../docs/caliptra-e2e.md) |

The reference tool is written in Go, in [`tools/hslsa/`](../tools/hslsa), and runs as `go run ./tools/hslsa/cmd/hslsa`. It signs step records, builds and validates HBOMs against the schema, runs the tapeout, lot receipt, board receipt and at-boot checks, and signs VSAs. It uses the in-toto attestation library to validate every statement and parses every step predicate as SLSA Provenance v1. Where this spec and the tool disagree, the disagreement is a bug to fix in one of them.

What the examples do not show yet: no example reaches Design L3 or above, the IP vendor's key is simulated, and the OpenLane 2 rebuild comes from a second builder under the same GitHub account, not an independent operator. Nothing runs on silicon: fab, sort, package and test data are simulated, and Caliptra units run on its emulator rather than on the RTL.

## Decisions and open questions

### Where the drafts disagreed

The source drafts were not edited; this spec settles each difference as follows.

| Topic | The drafts said | This spec |
| --- | --- | --- |
| Predicate namespace | `hwslsa.dev` (design, fab, firmware) vs `hw-slsa.example` (HBOM) | `https://github.com/Horiodino/hw-slsa/` everywhere; a custom domain can replace it later |
| Physical names | `urn:hbom:lot:` and `urn:hbom:unit:` in the HBOM and firmware docs; `urn:hslsa:` for wafer lots, assembly lots and boards | One prefix, `urn:hslsa:`, for every physical subject |
| Lot subject and digest | HBOM: "the assembly lot", digest of its unit list, format undefined; fab doc: shipped lot from F4 with an exact formula | The shipped lot, with the fab doc's lot digest as the only definition |
| Unit naming | HBOM: serials or certificate digests; fab doc: serial at Package/Test L2, certificate digest at L3 | Tied to the level, as in the fab doc |
| Firmware L2 without a secure-boot ROM | Open question in the level scheme | Allowed through an attested board-level root of trust that verifies before the SoC runs, claimed for the board (proposed) |
| Supplier predicates for fab, assembly and test | HBOM left them open | The `manufacturing-step` predicate, referenced from the HBOM's `attestationRef` fields |
| Tapeout release record | Design doc names it but gives no step type | `design-flow` with buildType `.../step/release@v1` |
| Verification summary levels | Firmware doc defines `HSLSA_FIRMWARE_LEVEL_n` only | `HSLSA_<TRACK>_LEVEL_<n>` for all five tracks |
| HBOM flow steps | HBOM enum lacks the ROM merge and release | `rom-merge` and `release` added |

### Open questions

- [ ] Where do IP, PDK and site signing keys live, and who runs the trust roots: each buyer, an industry body, or the accreditors (DMEA, The Open Group)?
- [ ] Should the board-level root of trust rule for Firmware L2 be adopted as written?
- [ ] Should source integrity (reviewed RTL) and dependency integrity (IP, PDK, cell libraries) become their own tracks, as SLSA did with Source? Today they sit inside Design L2 and L3.
- [ ] Can analog and mixed-signal flows, mostly manual layout, reach Design L3?
- [ ] What sampling rate makes an L4 claim meaningful for a given lot size, and who accredits the inspection labs?
- [ ] Should the HBOM carry claimed levels per track, so one document states them, or should levels live only in verification summaries?
- [ ] Should HBOM `firmware[]` entries gain a provenance reference and expected boot measurement, and should reference values be published as CoRIM?
- [ ] Is the `fw-review` wrapper needed, given S.A.F.E. reports are already signed and defined as a CoRIM profile?
- [ ] Who endorses IDevID certificates when the OSAT, not the chip vendor, holds the provisioning station?
- [ ] Should the foundry verify provenance at GDS intake, or only the design house before release? (Wafer L3 already asks the fab to verify the release.)
- [ ] How much of `hwFlow.metrics` and `hwMfg` data is safe to disclose to the next party, and are salted digests enough for encrypted IP and NDA-bound PDKs, or is verifier escrow needed?
- [ ] Can an MES emit these records natively, or does it need a signing sidecar?
- [ ] Which neutral home should own the spec long term (OpenSSF, CHIPS Alliance, OCP or a joint group), beyond the owner's repository?
- [ ] Track SPDX 3.1 from release candidate to final, and CoRIM from Internet-Draft to RFC.
- [ ] Should Design L4 accept `gds-equal-ignoring-timestamps` by default, or only `gds-bit-exact`? This spec requires bit-exact unless the policy says otherwise.
- [ ] The HBOM's `design.flow[].step` enum (`place-and-route`, `sta`, `drc`, `lvs`, ...) is coarser than and named differently from `hwFlow.step` (`place-cts`, `routing`, `gds-stream-out`, ...). Should the two share one list?
- [ ] How should a verifier treat post-quantum identity chains (Caliptra 2.x also issues ML-DSA-87 certificates) until common X.509 libraries can verify them?
- [ ] What identity should a board carry once it has one: a platform certificate, a board-level DICE identity, or the identity of its root of trust?

### Next steps

The longer path to real-world use, with suppliers, buyers and a neutral home, is in the [roadmap](../docs/roadmap.md).

- [x] Regenerate the HBOM schema and PicoSoC example for the changes above.
- [x] Prototype: wrap an OpenLane 2 run of a small SKY130 design so each step emits a signed attestation, and measure how close a second run gets to bit-exact ([openlane2-flow.md](../docs/openlane2-flow.md)).
- [x] Write one end-to-end example on a part with a hardware identity, from RTL to a booted device ([caliptra-e2e.md](../docs/caliptra-e2e.md)).
- [x] Add a board-level example to exercise `parts[]`, distributor lot data and A1 ([board-example.md](../docs/board-example.md)).
- [x] Pin the dates Magic, KLayout, STA and RCX embed, so the OpenLane 2 GDS is bit-exact and the verifier can require `gds-bit-exact` ([overlay](../openlane2/overlay/README.md)).
- [x] Have a second builder, with its own keys and trust root, sign a `rebuild` record for a released design, and check it at tapeout ([openlane2-flow.md](../docs/openlane2-flow.md#the-rebuild-and-the-buyers-check)).
- [ ] Run that second builder under a separate operator, such as another CI account or organization.
- [ ] Boot the Caliptra ROM on the Verilated RTL instead of the emulator, so the booted device is the design itself.
- [x] Reach Design L2 in an example: a signed, reviewed source freeze and signed IP provenance ([e2e-test.md](../docs/e2e-test.md)).

## Changelog

### Revision 3 (2026-09-13)

Starts phase 0 of the [roadmap](../docs/roadmap.md), toward v0.2.

- **Bit-exact design flows.** A flow MAY replace files inside a pinned image, pinned as a `kind: overlay` dependency, and pass tools a `SOURCE_DATE_EPOCH` in `externalParameters`; every step names the same ones (see [Pinning tools and PDKs](#pinning-tools-and-pdks)). The OpenLane 2 example uses both to make its GDS byte-identical across builders.
- **Rebuild record.** The record lists the inputs it built from next to the release it rebuilt, and the spec lists what the verifier checks before it accepts one: a rebuilder key in its own trust root that is not a design-house key, a builder other than the flow's, the released GDS, the same inputs, and the check the policy requires. The OpenLane 2 example's tapeout check now requires a bit-exact rebuild from a second builder under its own trust root.

### Revision 2 (2026-09-12)

Brings the spec in line with the board, OpenLane 2 and Caliptra examples, the HBOM schema and the Go reference tool.

- **Boards.** Added the distribution record (`.../mfg/step/distribution@v1`) and step D, signed by whoever ships a lot to the assembler. A1 now names the board lot, each board and the per-serial build records as subjects. A board's digest is the sha256 of its serial until it has an identity certificate. The board HBOM's subjects are the board design and the board lot. Added the board receipt check. Assembly L2 now asks for signed distribution records and a lot receipt check on each chip before placement.
- **HBOM.** Required fields depend on `product.level`: `manufacturing.fab` for dies and packages, `manufacturing.boardAssembly` and `parts[]` for modules, boards and systems. Added `manufacturing.boardAssembly` and `parts[].distributionRef`. These match the schema already on main.
- **Design flow.** Allowed per-tool step types such as `.../design-flow/step/openlane2@v1`, mapped onto design steps 1 to 7 through `hwFlow.step`. Container image digests and a defined PDK tree digest count as tool and PDK pins. Added the `rebuild` record (`.../design-flow/step/rebuild@v1`) with the checks `gds-bit-exact` and `gds-equal-ignoring-timestamps`, and made it the Design L4 evidence at tapeout.
- **Firmware.** Defined the `fw-provisioning` record: SLSA Provenance v1 with buildType `.../fw-provisioning/step/provision@v1` and an `hwProvision` block. A part with a device identity gets one record per unit, whose subject is its IDevID public key digest. The at-boot check now applies to any unit with an identity (it was Firmware L3 only), also compares the device's fuse measurements with the provisioning record, and checks the policy's minimum SVN. Step 6a MAY record `rom-matches-frozen` against a published ROM digest.
- **Naming.** A unit VSA's subject digest is the IDevID certificate digest when the unit has a device identity, even while its lot is named by serials.
- **Signing.** Stated that no key model needs a public transparency log, and that the reference tool signs with local keys and publishes nothing.
- **Reference.** Added [Worked examples and reference implementation](#worked-examples-and-reference-implementation), which points at the four examples and the Go tool, and checked off the three example next steps.
- Still open and unchanged: the board-level root of trust rule for Firmware L2 (proposed), and whether the `fw-review` wrapper is needed.

### Revision 1 (2026-09-02)

First version: consolidated the project's six drafts into one spec.
