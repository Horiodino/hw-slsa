# Viability assessment (2026-09-12)

The [roadmap](roadmap.md) follows from this assessment of whether HSLSA can work outside this repository. It was written on 2026-09-12, before phase 0; the roadmap records what has changed since.

**Short version:** the design is technically sound, but nobody outside this repository signs the records yet.

## Track by track

| Readiness | Tracks | Why |
| --- | --- | --- |
| Ready now | Firmware | Firmware builds already run in CI, code signing and measured boot exist, and OCP S.A.F.E. reviews are published |
| Plausible with a large customer behind it | Package/Test; Design L1 to L2; Assembly and board checks for key parts | OSATs and board lines already export MES and test data; a big buyer can ask them to sign it |
| Hard | Wafer; Design L3 with commercial EDA; the L4 defense profile | Foundries sign nothing for customers today; EDA license servers need network access, which L3 isolation forbids, and PDKs are under NDA; physical inspection is expensive |

## The core limit

A signature proves who made a claim and that nobody changed it afterwards, not that the claim is physically true. A dopant-level trojan, for example, is invisible to every record. Only sampled physical inspection (L4) looks at the parts themselves. The spec's [threat model](../spec/hslsa-v0.1.md#threat-model) states this track by track.

## Recommended path

1. Lead with parts that carry a hardware root of trust (Caliptra class), where the Firmware track and the at-boot check work today.
2. Put one small design through an open-PDK shuttle.
3. Position HSLSA as the semiconductor profile of NIST IR 8536 (final, 2026-09-09) instead of a competing framework.
4. Find one buyer who needs this, a hyperscaler or a defense program, for a pilot.
5. Move the spec to a neutral home, OpenSSF or CHIPS Alliance.

## Context checked at the time

- SEMI T26 (traceability on distributed ledgers) was published in September 2025.
- The EU Cyber Resilience Act's reporting duties apply from 2026-09-11 and its main requirements from 2027-12-11; it asks for software bills of materials only.
- ERAI recorded 1,055 counterfeit part reports in 2024.
- Dell ships factory-signed platform certificates (Secured Component Verification), and OpenTitan ships in Chromebooks.
