# HSLSA as the semiconductor profile of NIST IR 8536

**Status:** draft, 2026-09-20; the ten gaps it found in HSLSA were decided on 2026-09-20 and applied in spec revision 6. Written against the final [NIST IR 8536](https://doi.org/10.6028/NIST.IR.8536), *Supply Chain Traceability: Manufacturing Meta-Framework* (September 2026), and [HSLSA v0.1](hslsa-v0.1.md). This is item 1 of phase 1 in the [roadmap](../docs/roadmap.md).

## Summary

IR 8536 is a meta-framework. It gives nine principles, six supply chain event categories (Make, Assemble, Store, Ship, Receive, Employ), the elements every traceability record carries, and an architecture of records held in federated repositories and joined by cryptographic links. It deliberately leaves the payload, the templates and the data standards to each industry: consortia, standards bodies and manufacturers tailor the templates for their sector.

HSLSA fills that slot for semiconductors and the boards built from them:

- Every HSLSA record is already an IR 8536 traceability record. It has a data type identifier (its predicate type), an encapsulated payload, attribution through its signing key, a time, and hash links to the records before it.
- HSLSA's step predicates are the semiconductor payload templates, and its tracks and levels are the risk scale that IR 8536's principle 2 asks for but does not define.
- This profile adds four requirements on top of HSLSA (organization identifiers, event times, record-digest links, and how another ecosystem carries an HSLSA record unchanged), maps every HSLSA step to an IR 8536 event, and lists what each side lacks.

The largest gaps this profile found in HSLSA were that receipt and transfers between fab and OSAT were not recorded as events, that a missing record failed the chain instead of being reported as a gap, that storage was not recorded, and that nothing is recorded after the first buyer. Spec revision 6 closes the first two, states the third in the scope, and leaves the last as an open question. The largest gaps in IR 8536, for this sector, are design provenance, assurance levels with pass or fail checks, and the binding of a booted device to its records. Both lists are below with a proposal for each.

The roadmap also asks whether IR 8536's reference implementation can ingest HSLSA records. It cannot be checked yet: NIST says the Python reference implementation is in final approval and its repository will be public when that completes, and it was not public on 2026-09-18. [Reference implementation](#reference-implementation) says what will be done once it is.

## What "profile" means here

IR 8536 is voluntary and defines no conformance process, so no body certifies a profile. In this document a profile is what IR 8536 section 4 leaves to each sector: which payload formats to encapsulate, how the record elements are filled, and which events the sector records.

A set of records conforms to this profile when it meets HSLSA at the levels it claims and also meets the [profile requirements](#profile-requirements). The requirements are additions for exchange with IR 8536 ecosystems; they do not change any HSLSA level.

## Terms

| IR 8536 | HSLSA |
| --- | --- |
| Traceability record | One step record: an in-toto Statement v1 in a DSSE envelope, signed by the party that ran the step |
| Traceability chain | The [attestation chain](hslsa-v0.1.md#the-attestation-chain) from a booted device back to RTL |
| Provenance (history of origins, changes and transfers) | The step records, walked in order |
| Pedigree (internal composition) | The [HBOM](hslsa-v0.1.md#hardware-bill-of-materials) |
| Supply chain event | A step; see [Events](#events) |
| Encapsulation | Hardware fields in one extra block (`hwFlow`, `hwMfg`, `hwProvision`) inside a SLSA Provenance v1 predicate |
| Traceability link | A `resolvedDependencies` entry, `hwMfg.designRef`, or an HBOM `*Ref`, each by digest |
| Traceback | The buyer's checks, which walk links backward from a device, lot or board |
| Cyber-physical linkage | Physical subject names (`urn:hslsa:`), the [lot digest](hslsa-v0.1.md#lot-digest), and device identity at L3 |
| Selective disclosure | [Withheld fields](hslsa-v0.1.md#withheld-fields) listed with salted digests in `hwMfg.confidential[]` and the HBOM's `redactions[]`, and [verifier escrow](hslsa-v0.1.md#verifier-escrow), where an auditor checks the full records and the buyer receives only its VSAs |
| Acquirer | Buyer, OEM, EMS or system integrator |
| Manufacturer, supplier | Site: design house, IP vendor, foundry, sort house, OSAT, test house, distributor, EMS |
| Alternative evidence | Certificates the records point at: site accreditation, OCP S.A.F.E. reports, certificates of conformance, signed waivers |

## Record elements

IR 8536 section 4.2 names the core elements of a traceability record, among them a data type identifier, the tracked entity data (payload) and supplemental data references. Section 4.3 adds cryptographic links to prior records, and the principles add organization attribution (principle 7) and a digital anchor to the item (principle 8). A chain is a chronological history, so each record also carries a time. HSLSA fills each from fields it already has.

| IR 8536 element | HSLSA field | Notes |
| --- | --- | --- |
| Data type identifier | `predicateType`, refined by `predicate.buildDefinition.buildType` | Values in [Data types](#data-types) |
| Tracked entity data (payload) | `subject[]` names the entity; the predicate carries the pedigree data | Physical entities by URN and canonical-list digest, files by digest |
| Supplemental data references | `externalParameters` decisions (waivers, deviations, rework orders), each by digest and signer; the S.A.F.E. report for Firmware L3; inspection records for L4; `renderings[]` in the HBOM | Each is signed evidence of its own, not a free-form attachment |
| Organization attribution | The signing key, whose certificate names the site; `runDetails.builder.id`; `hwMfg.site` | [P1](#profile-requirements) adds a standard organization identifier |
| Time | `runDetails.metadata.startedOn` and `finishedOn` | [P2](#profile-requirements) makes `finishedOn` required |
| Links to prior records | `resolvedDependencies`: the previous record's envelope digest and that record's subjects; every manufacturing step also names the design release in `hwMfg.designRef` | [P3](#profile-requirements) makes the envelope digest required |
| Digital anchor to the item | Subject names and digests; at L3, the unit's identity certificate digest in the lot and a challenge at test, receipt and boot | Stronger than IR 8536 asks; see [what HSLSA adds](#where-hslsa-goes-further-than-ir-8536) |

In IR 8536 the records and their hash links, not a central store, are what prove integrity. HSLSA works the same way: every record is signed, and a verifier needs nothing from the store but the bytes. Transparency logs are optional up to L2 and may be private at L3.

### Data types

The data type identifier of an HSLSA record is its predicate type. Where several records share one predicate type, the build type says which step it is.

| HSLSA record | Data type identifier | Build type |
| --- | --- | --- |
| Design flow step | `https://github.com/Horiodino/hw-slsa/design-flow/v0.1` | `.../design-flow/step/<step>@v1` or `.../design-flow/step/<tool>@v1` |
| Tapeout release | `https://github.com/Horiodino/hw-slsa/design-flow/v0.1` | `.../design-flow/step/release@v1` |
| Rebuild (L4) | `https://github.com/Horiodino/hw-slsa/design-flow/v0.1` | `.../design-flow/step/rebuild@v1` |
| Source review | `https://github.com/Horiodino/hw-slsa/source-review/v0.1` | None |
| Third-party IP release | `https://slsa.dev/provenance/v1` | The vendor's, or `.../ip-release@v1` |
| Manufacturing step | `https://github.com/Horiodino/hw-slsa/manufacturing-step/v0.1` | `.../mfg/step/<step>@v1` |
| Distribution | `https://github.com/Horiodino/hw-slsa/manufacturing-step/v0.1` | `.../mfg/step/distribution@v1`, also for transfers between manufacturing sites |
| Proxy-signed step (L1 only) | As the step it records | As the step it records, with `hwMfg.proxy` naming the signer and the supplier's export |
| Evidence (L1 only) | `https://github.com/Horiodino/hw-slsa/manufacturing-step/v0.1` | `.../mfg/step/evidence@v1` |
| Physical inspection (L4) | `https://github.com/Horiodino/hw-slsa/physical-inspection/v0.1` | None |
| Firmware image build | `https://slsa.dev/provenance/v1` | Named for the builder |
| Firmware provisioning | `https://github.com/Horiodino/hw-slsa/fw-provisioning/v0.1` | `.../fw-provisioning/step/provision@v1` |
| Firmware review | The OCP S.A.F.E. short-form report's own CoRIM profile | None |
| Firmware reference values | The HSLSA CoRIM profile, `https://github.com/Horiodino/hw-slsa/corim-profile/v0.1` | None |
| HBOM | `https://github.com/Horiodino/hw-slsa/hbom/v0.1` | None |
| Platform certificate (Assembly L3) | `https://github.com/Horiodino/hw-slsa/platform-certificate/v0.1` | None; it binds a board to the components placed on it, and names A1 |
| Release log checkpoint (Firmware L3) | `https://github.com/Horiodino/hw-slsa/tlog-checkpoint/v0.1` | None; a signed tree head of the buyer's private release log, not a supply chain event |
| Site key enrollment, key revocation | `https://github.com/Horiodino/hw-slsa/site-enrollment/v0.1`, `https://github.com/Horiodino/hw-slsa/key-revocation/v0.1` | None; these are the buyer's own trust root records, not supply chain events, and stay with the buyer |
| Verification summary | `https://slsa.dev/verification_summary/v1` | None; a receipt record is one whose subject is `urn:hslsa:receipt:<lot-id>` |

## Events

IR 8536 defines six event categories: Make, Assemble, Store, Ship, Receive and Employ. It separates a company's internal event data from the supply chain events it shares (sections 2.1 and 4.1.2), and it looks at the handoffs between organizations.

Most HSLSA steps are run by a different company from the step before them, so they are shared events. The design steps are the exception: steps 0 to 7 all run inside the design house. Under this profile the tapeout release is the shared Make event for the design, and the per-step design records are internal records the design house discloses as supplemental evidence, to the buyer or to an auditor, as its policy allows. From Design L2 the tapeout check needs them, so a buyer who asks for Design L2 or above asks for that disclosure.

| HSLSA step | IR 8536 event | Shared or internal | Notes |
| --- | --- | --- | --- |
| 0. Source freeze | Make | Internal | The signed tag and source review are its evidence |
| 1. Simulation and lint | Make | Internal | |
| 2. Synthesis | Make | Internal | |
| 3. Floorplan and power | Make | Internal | |
| 4. Placement and CTS | Make | Internal | |
| 5. Routing | Make | Internal | |
| 6. Signoff | Make | Internal | |
| 6a. ROM merge (mask ROM only) | Assemble | Internal | A firmware image is combined into the layout |
| 7. GDS stream-out | Make | Internal | |
| 7. Bitstream (FPGA, instead of stream-out) | Make | Internal | For an FPGA design; the released bitstream is the design as a digital object |
| Release | Make | Shared | The design as a digital object; every manufacturing step links to it |
| Rebuild (L4) | None | Supplemental evidence | An independent check of the release, not a transformation |
| F1. Wafer fabrication | Make | Shared | Includes mask making, which HSLSA does not record separately |
| T. Transfer | Ship | Shared | Signed by the site that ships wafers or units to the next manufacturing site; the receiving site's next record links it, which records the matching Receive |
| F2. Wafer sort | Make | Shared | |
| F3. Packaging | Assemble | Shared | Die into package |
| F4. Final test | Make | Shared | Produces the shipped lot |
| Firmware build | Make | Shared | A digital object |
| Provisioning | Make | Shared | Changes the unit: images, fuses, identity |
| D. Distribution | Ship | Shared | Signed by the shipper |
| R. Receipt | Receive | Shared | Signed by the receiver after its lot receipt check; from Assembly L2 the EMS signs one for each chip lot and A1 links it |
| A1. Board assembly | Assemble | Shared | |
| X. Inspection (L4) | None | Supplemental evidence | Independent physical verification |

Two events have no HSLSA step of their own:

- **Store.** Nothing records a warehouse or a die bank, and the spec's scope says so. See [H3](#gaps-in-hslsa).
- **Employ.** The at-boot check is the closest: a verifier MAY sign a unit verification summary for a booted device. Under this profile that summary is the Employ record.

Some records are not events. The HBOM is pedigree: what the product is made of, pointing at the events. The verification summary is a decision over a chain, which is what IR 8536's principle 1 says the chain is for. The source review, IP release and S.A.F.E. report are supplemental evidence for the steps that consume them. The firmware reference values are supplemental evidence for Employ: the measurements a firmware build should produce on a device, which the at-boot check compares the device against.

## Principles

| IR 8536 principle | How HSLSA meets it | Status |
| --- | --- | --- |
| 1. Decision-centric traceability | Four checks (tapeout, lot receipt, board receipt, at boot), each a buyer's decision, ending in a signed verification summary | Met |
| 2. Proportional, risk-scaled traceability | Levels per track, L0 to L3, with an optional L4 defense profile for root-of-trust and defense parts; a buyer asks for the level the part's risk needs | Met; HSLSA supplies the scale IR 8536 leaves open |
| 3. Incentive-aligned participation | L1 needs no signing infrastructure, and a product states a level per track, so one weak supplier does not block the others. A supplier who will not sign can have its record [proxy-signed](hslsa-v0.1.md#proxy-signed-record) at L1 by whoever received from it | Partial: incentives are commercial, not something a spec can supply |
| 4. Evidence-based provenance, not perfect transparency | Accreditation (DMEA, O-TTPS), S.A.F.E. reports, certificates of conformance and signed waivers count as evidence; salted digests give bounded disclosure | Met: at L1 an [evidence record](hslsa-v0.1.md#evidence-record) puts a certificate or paper record in place of a missing step ([H6](#gaps-in-hslsa)) |
| 5. Measure and communicate traceability gaps | The track level is the lowest level of its steps, so the weakest link shows; the threat model states what each level leaves open; parts without identity are named as such | Met: the receipt checks list every missing record and every undisclosed withheld field with its track, and name optional records that were not recorded ([H5](#gaps-in-hslsa)) |
| 6. Lifecycle-oriented provenance | The at-boot check covers what a device runs now, including its SVN against anti-rollback fuses | Gap: nothing after the first buyer, no record of field updates, rework or return; an open question in the spec, taken up in phase 2 ([H4](#gaps-in-hslsa)) |
| 7. Verifiable organization attribution | Every step is signed by a site key whose certificate names the site; buyers list allowed signers by role | Met with [P1](#profile-requirements), which adds a standard identifier |
| 8. Cyber-physical and digital linkage | Files by digest; lots by URN and canonical-list digest; units by serial at L2 and by hardware identity at L3, challenged at test, receipt and boot | Met, and stronger than IR 8536 asks |
| 9. Interoperability over uniformity | in-toto, DSSE, SLSA Provenance, CycloneDX, SPDX, CoRIM, SEMI E142 and STDF are reused unchanged; a plain SLSA verifier can check every step record | Met; GS1 EPCIS is left to the supplier adapters of phase 3 ([H9](#gaps-in-hslsa)) |

## Profile requirements

These apply on top of HSLSA at every level. They are what an IR 8536 ecosystem needs to read HSLSA records without knowing HSLSA.

**P1. Organization identifiers.** Every organization named in a record (`hwMfg.site`, a distribution record's shipper, and every `org` in the HBOM) MUST carry `id`, one of `lei:`, `duns:`, `cage:`, `uei:` or `gln:` followed by the identifier. A site certificate SHOULD carry the same identifier. HSLSA's HBOM schema already has an optional `org.id`; this profile makes it required and adds UEI and GLN, which IR 8536 names. The worked examples do not carry identifiers yet, so they do not meet P1.

**P2. Event time.** Every step record MUST set `runDetails.metadata.finishedOn`, and SHOULD set `startedOn` when the step has a meaningful start. The reference tool sets `finishedOn` on every step record, including, since this profile, the rebuild record.

**P3. Record links.** A record MUST list, in `resolvedDependencies`, the envelope digest of every record it follows, and not only that record's subjects. HSLSA requires the subjects, so a verifier can match outputs to inputs; IR 8536 links records to records. The reference tool already lists both for manufacturing steps, and the spec requires it for per-tool design steps.

**P4. Carried unchanged.** When an IR 8536 ecosystem uses its own record container, it carries the HSLSA DSSE envelope byte for byte as the payload and declares the envelope's `predicateType` as the data type identifier. The HSLSA signature then still verifies, and HSLSA checks run on the payload as if it had never been wrapped. See [Carrying HSLSA records in another ecosystem](#carrying-hslsa-records-in-another-ecosystem).

## Carrying HSLSA records in another ecosystem

IR 8536 defines record elements, not a wire format, so an ecosystem such as the reference implementation, a GS1 EPCIS repository or a distributed ledger will have its own container. An adapter fills that container from the HSLSA record:

| Container element | Filled from |
| --- | --- |
| Event category | [Events](#events), by build type |
| Data type identifier | `predicateType` |
| Tracked entity | `subject[]` |
| Organization | `hwMfg.site.id` (P1), or the certificate of the signing key |
| Time | `runDetails.metadata.finishedOn` (P2) |
| Links | The envelope digests in `resolvedDependencies` (P3), each with a URI where the record can be [fetched](hslsa-v0.1.md#fetching-records) |
| Payload | The DSSE envelope, unchanged (P4) |

For example, F3 packaging in such a container might look like this. The container's field names here are illustrative; the ecosystem defines its own.

```json
{
  "eventCategory": "Assemble",
  "dataType": "https://github.com/Horiodino/hw-slsa/manufacturing-step/v0.1",
  "organization": {"id": "duns:000000000", "name": "Example OSAT"},
  "eventTime": "2026-09-30T12:00:00Z",
  "trackedEntity": [{"name": "urn:hslsa:assembly-lot:AL-0001", "digest": {"sha256": "<packaged lot digest>"}}],
  "links": [{"uri": "<where F2 can be fetched>", "digest": {"sha256": "<F2 envelope digest>"}}],
  "payload": {"mediaType": "application/vnd.dsse.envelope.v1+json", "envelope": {"payloadType": "application/vnd.in-toto+json", "payload": "...", "signatures": ["..."]}}
}
```

The adapter adds nothing a buyer must trust: every value in the container except the event category is copied from the signed envelope, and the category follows from the build type. A consumer that trusts only the container still gets IR 8536's chain; one that checks the envelope gets HSLSA's levels.

## Gaps in HSLSA

Each gap is something IR 8536 expects and HSLSA did not do. The decisions were made on 2026-09-20 and applied in spec revision 6 (see its [changelog](hslsa-v0.1.md#changelog)).

| | Gap | IR 8536 | Decision |
| --- | --- | --- | --- |
| H1 | Receipt was checked but not recorded | Receive event | Adopted. Whoever runs the lot receipt check MAY sign a [receipt record](hslsa-v0.1.md#receipt-record), a VSA over exactly the units it received; that is the Receive record. From Assembly L2 the EMS signs one for each chip lot before placement, A1 links it, and the board receipt check verifies it |
| H2 | No record of wafers or units moving between fab, sort house, OSAT and test house; each step linked straight to the one before | Ship and Receive at every handoff between organizations | Adopted. The shipping site MAY sign a [transfer](hslsa-v0.1.md#transfers-between-manufacturing-sites), a distribution record whose packing list names the lot and exactly what was sent, and the next step links it. Required at Wafer L3 and Package/Test L3 between companies, or when a buyer's policy asks; the PicoRV32 example records all three and requires them |
| H3 | No record of storage at a distributor or die bank | Store event | Deferred. The spec's scope and the Assembly threat model now say that storage is not recorded, so a swap in storage is a stated residual risk. Revisit with distributors in phase 4 |
| H4 | Nothing after the first buyer: field firmware updates, rework, returns | Principle 6; post-Employ events are future work in IR 8536 too | Deferred. An open question in the spec and a phase 2 roadmap item, once a real board boots and a field update can be tried; the at-boot check still covers what finally runs |
| H5 | A missing or withheld record failed the check at the first broken link | Principle 5 | Adopted. Before they walk the chain, the lot receipt and board receipt checks list every missing record and every withheld field with no disclosure, each with its track, and name optional records that were not recorded |
| H6 | No place for paper or audit evidence in place of a record | Principle 4 | Adopted in the spec. At L1 only, the next party MAY cover a supplier's step with an [evidence record](hslsa-v0.1.md#evidence-record) naming the certificate or document by digest; the track is then at L1. The reference tool accepts them, with proxy-signed records, from spec revision 8 |
| H7 | Organization identifiers optional | Principle 7 | Done in this profile: P1 above, and the HBOM schema accepts `uei:` and `gln:` and checks the prefix |
| H8 | References were digests with bundle-relative URIs; no way to fetch a record from its owner | Federated repositories, traceback links (section 4.3.2) and link-based querying (section 4.4.3) | Adopted as spec text: a reference MAY carry an `https` URI into its holder's repository, which may require access, and a site SHOULD serve each record at an address ending in its digest ([Fetching records](hslsa-v0.1.md#fetching-records)). Finding records by subject waits for the transparency log item of phase 1 |
| H9 | Nothing maps to GS1 EPCIS, a widely used event format for shipping, receiving and storage | Principle 9 | Deferred to the supplier adapters of phase 3: accept an EPCIS event as supplemental evidence for Ship, Receive and Store from distributors that already emit it, without replacing the distribution record |
| H10 | No retention period or access rule for records | Controlled access and data retention (section 4.4.2) | Adopted. Signers keep records, data files, salts and disclosures for at least the product's support life, and give full records only to the buyers and auditors they choose ([Retention and access](hslsa-v0.1.md#retention-and-access)) |

The Semiconductor Industry Association's [comments on the second draft](https://www.semiconductors.org/wp-content/uploads/2025/10/SIA-Final-Comments-on-NIST-IR-8536-2pd_10.03.pdf) asked that a traceability system link to data its owner controls rather than collect it, and stay out of each company's internal systems. H8 and H10 follow that: records stay with their owners, and the internal design steps are disclosed only as the design house chooses.

## Where HSLSA goes further than IR 8536

IR 8536 is sector-neutral by design, so these are not faults in it. They are what a semiconductor profile has to supply.

| | IR 8536 leaves open | HSLSA supplies |
| --- | --- | --- |
| I1 | Provenance of the design: RTL, IP, PDK, EDA tools and flow | The Design track, from signed source freeze to a signed GDS release, and `hwFlow` records naming every tool and PDK by digest |
| I2 | One design linked to every physical step | Every manufacturing and provisioning record names the release in `designRef`, and the fab checks it at Wafer L3 |
| I3 | A scale for "proportional" and the checks that decide it | Per-track levels with required evidence, and four checks with pass or fail rules |
| I4 | What a signed record does and does not prove | The [threat model](hslsa-v0.1.md#threat-model): which attacks each level stops, which it only makes accountable, and which no record can show |
| I5 | Lot semantics | Exact lot names, one lot digest, yield reconciliation from sort to final test, and wafer-to-unit genealogy across many-to-many lots |
| I6 | Binding a running device to its records | Hardware identity at L3 and the at-boot check, which compares the device's own firmware and fuse measurements with the provisioning record and image provenance |
| I7 | Independent verification | An independent rebuild of the GDS or firmware and sampled physical inspection by a lab, each under its own trust root |
| I8 | Firmware as part of the product | The Firmware track, mask ROM proven through the layout, and per-unit provisioning records |
| I9 | A concrete format and signature | in-toto Statements in DSSE envelopes, supersets of SLSA Provenance, which existing verifiers check |

## Reference implementation

Roadmap item 1 asks whether IR 8536's open-source reference implementation can ingest HSLSA records, or whether a thin adapter can make it. NIST's [announcement of the final report](https://www.nccoe.nist.gov/news-insights/finalized-manufacturing-supply-chain-traceability-meta-framework) says the Python reference implementation is in final approval and its GitHub repository will be public when that completes. It was not public on 2026-09-18, so the check is open.

When it is published, the plan is:

1. Write the adapter described in [Carrying HSLSA records in another ecosystem](#carrying-hslsa-records-in-another-ecosystem) in Go, in the reference tool, for the reference implementation's record format.
2. Load the PicoRV32 chain (design release, F1 to F4, HBOM) and the board chain into one of its ecosystems and run its traceback from the board lot.
3. Record here whether its traceback reaches the design release, and which HSLSA fields it cannot carry.

That run is also one half of phase 1's exit criterion: one HSLSA chain checked by a tool this project did not write.

## Sources

- NIST IR 8536, *Supply Chain Traceability: Manufacturing Meta-Framework*, final, September 2026: <https://doi.org/10.6028/NIST.IR.8536>; publication page <https://csrc.nist.gov/pubs/ir/8536/final>.
- NCCoE, *Finalized Manufacturing Supply Chain Traceability Meta-Framework*, 2026-09-09: <https://www.nccoe.nist.gov/news-insights/finalized-manufacturing-supply-chain-traceability-meta-framework>.
- Semiconductor Industry Association, comments on NIST IR 8536 second public draft, 2025-10-03: <https://www.semiconductors.org/wp-content/uploads/2025/10/SIA-Final-Comments-on-NIST-IR-8536-2pd_10.03.pdf>.

Section and principle numbers refer to the final report. This profile was checked against it on 2026-09-18.
