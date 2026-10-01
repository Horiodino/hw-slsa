# Levels L3 and L4: what the reference tool checks

The spec defines four levels per track ([Tracks and levels](../spec/hslsa-v0.1.md#tracks-and-levels)). L1 and L2 are checked for all five tracks by the checks the other pages describe. This page covers L3, which every track now reaches, and the L4 defense profile, which is still being built. For each level it says what the tool checks, which command makes the records, which example shows it end to end, and what the tests make it refuse.

Everything in the examples is simulated: the sites, their HSMs (SoftHSM), the accreditations, and the dies with their on-die root of trust. The records say so (see [Simulated hardware](simulated-hardware.md)). What the examples prove is that the checks work and refuse what they should, not that any real part meets a level.

## How a level is claimed

A buyer's policy names the levels it claims in `claims`. Each check runs the extra requirements of a level whenever the policy claims that level in that track, and fails if one is not met. A VSA states only claimed levels, and only after the check passed, so it never states a level the check did not establish.

Two guards stop a claim the tool cannot stand behind (`tools/hslsa/levels.go`):

- A claim of a level the tool does not check yet is refused before any record is read, and again when a VSA is signed. Today that is L4 in every track.
- `SLSA_BUILD_LEVEL_n` needs a Design or Firmware level of at least n in the same list, since Design Ln and Firmware Ln meet SLSA Build Ln and not the other way round.

### Buyer-run trust roots record how keys are held

From L3, the Wafer, Package/Test and Assembly tracks ask where a key is held and who runs the site: in an HSM, at an accredited site. A plain trust root of public keys cannot say that, so L3 needs a buyer-run trust root ([pilot kit](../pilot/README.md)): the buyer signs one enrollment per key, and the enrollment records

- `keyCustody`: `hsm` or `file`, as the buyer checked it (a key ceremony, an HSM vendor's key attestation);
- `accreditation`: the scheme and the certificate number of the site (for example `dmea-trusted-supplier`, `iso-iec-20243`, `ipc-1791`, `sae-as6496`);
- the company, by name and an organization id such as a DUNS number.

The policy lists the accreditation schemes it accepts in `accreditations`. Make enrollments with `hslsa pilot enroll --custody hsm --accreditation <scheme> --accreditation-id <number>`, and the trust root with `hslsa pilot trust-root`.

## L3

### Design L3

What the spec asks: isolated steps with no network (except declared license servers), tools pinned by digest and on an allow-list, signing keys out of reach of step code, a formal equivalence proof between RTL and the final netlist, and enough recorded for an independent party to run the proof again.

What the tool does:

- `hslsa design <step> --isolate` runs each step's tools in a bubblewrap sandbox (`tools/hslsa/sandbox.go`): new user, mount, PID, IPC, UTS and network namespaces, `/usr` read-only, and a fresh working directory with only the step's inputs. Nothing else of the host is mounted, so no signing key is in reach; the record is hashed and signed outside the sandbox. The record says so in `hwFlow.isolation` and `hwFlow.network`.
- Every tool a step runs is recorded with its binary digest and, from dpkg, the digest of every file of the package it came from. The policy pins them in `design.toolPins`.
- `hslsa design signoff` is the equivalence step: Yosys `equiv_make`, `equiv_simple` and `equiv_induct` between the frozen RTL and the released netlist. The record (`design-3-signoff`) carries a passing `rtl-netlist-equivalence` check and the proof script by digest.
- `hslsa design rerun-equivalence` is the independent rerun: it takes the source and netlist from the bundle by digest and runs the proof with the tool's own recipe, not the script the flow platform shipped.

The tapeout check at Design L3 (`designL3` in `tools/hslsa/verify.go`) requires every one of these in every required step. Example: `e2e/run.sh produce` (the PicoRV32 policy claims Design L3) and `e2e/run.sh rerun`. Tests: `levels_test.go`, including a netlist with one inverted address bit, which the rerun catches.

### Wafer L3 and Package/Test L3

What the spec asks: site keys in HSMs at accredited sites; the fab verifies the design release before mask making and records the mask-vs-GDS XOR; identities provisioned at sort are rooted in an on-die root of trust and issued by an HSM-backed CA; every unit answers an identity challenge at final test; the shipped lot digest covers the units' certificate digests; every shipment between companies is a signed transfer.

What the tool does (`tools/hslsa/chipl3.go`, `dieid.go`, `mfgid.go`):

- `hslsa fab-check` is the fab's release check: the tapeout check under the fab's own trust root and policy, signed as a verification summary with the fab's site key. F1 consumes it, and its `mask-vs-gds-xor` check names the released design it compared against.
- With an `identity` block in the scenario, `hslsa mfg --devices DIR` gives every passing die at wafer sort a simulated DICE engine: a unique device secret, a CDI over the measurement of the design, and an IDevID key derived from it that never leaves the die. Sort gets a CSR, the identity CA (its key in the HSM) endorses it, and `die-identities.json`, an F2 subject, lists the certificates.
- Packaging names each unit by the sha256 of its die's certificate, keeping the marked serial in the genealogy. Final test challenges every unit with a fresh nonce; a unit that does not answer under its own certificate fails. The answers are `identity-challenges.json`, an F4 subject.
- At receipt the buyer challenges the parts it received: `hslsa verify --units DIR`, where DIR holds the parts, not a list of serials. `hslsa challenge` challenges one part.

The lot receipt check at L3 then requires the buyer-run trust root, HSM custody and an accepted accreditation for every site key, the release check before F1, the identity chain, the challenges at final test and at receipt, and a transfer for every shipment between companies (judged by the organization id in the enrollments). Example: `e2e/run.sh l3`, which also shows six refusals: a cloned part carrying a genuine certificate, a part that failed final test, serials typed into a list, a trust root without enrollments, keys held in files, and accreditations the policy does not list. Tests: `chipl3_test.go`.

### Assembly L3

What the spec asks: signing at accredited sites; every component with a hardware identity checked by attestation at build; a platform certificate binding the system to those parts; parts without an identity stay at lot-level naming.

What the tool does (`tools/hslsa/boardl3.go`):

- `hslsa board produce --chip-parts DIR --boards-out DIR`: the EMS challenges every chip it received under the identity CA of the chip's own trust root before it places it, and keeps the answers in `part-attestations.json`, an A1 subject.
- After A1 the board owner's platform CA (role `platform-ca`) signs a platform certificate per board: the board's serial and every component on it, by certificate digest where the part has an identity and by lot otherwise.
- At receipt, `hslsa board verify --boards DIR` challenges the identity parts on each received board, and each must answer with the certificate its platform certificate names.

The board receipt check at Assembly L3 requires the EMS and every shipper to sign at accredited sites, every identity part on every board to have answered at build, a platform certificate for every board that names exactly what was placed on it, and the challenge at receipt. Example: `e2e/board/run.sh l3`, on the L3 chip lot, with three refusals: a chip swapped for another genuine one after build, a board whose chip was taken off, and serials typed into a list. Tests: `boardl3_test.go`.

### Firmware L3

Being built: SLSA Build L3 for every image (isolated builds, provenance signed outside the build), the S.A.F.E. review check that already exists, release inclusion in a private RFC 9162 transparency log, the at-boot check made mandatory, and every provisioning site rated at least L3 in its own track. Until it is done, a Firmware L3 claim is refused.

## L4 defense profile

Not checked yet; every L4 claim is refused. Planned: for Design, a rebuild under a separate trust root, two-person review of source freeze and waivers, and an HSM-held tapeout key; for Wafer, Package/Test and Assembly, a physical inspection record signed by an independent lab under its own trust root, with a seed committed before the lot is sealed and a sampling plan; for Firmware, an independent bit-for-bit rebuild of every image and two-person review of releases.
