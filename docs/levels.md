# Levels L3 and L4: what the reference tool checks

The spec defines four levels per track ([Tracks and levels](../spec/hslsa-v0.1.md#tracks-and-levels)). L1 and L2 are checked for all five tracks by the checks the other pages describe. This page covers L3, which every track now reaches, and the L4 defense profile, which is still being built. For each level it says what the tool checks, which command makes the records, which example shows it end to end, and what the tests make it refuse.

Everything in the examples is simulated: the sites, their HSMs (SoftHSM), the accreditations, and the dies with their on-die root of trust. The records say so (see [Simulated hardware](simulated-hardware.md)). What the examples prove is that the checks work and refuse what they should, not that any real part meets a level.

## How a level is claimed

A buyer's policy names the levels it claims in `claims`. Each check runs the extra requirements of a level whenever the policy claims that level in that track, and fails if one is not met. A VSA states only claimed levels, and only after the check passed, so it never states a level the check did not establish.

Three guards stop a claim the tool cannot stand behind (`tools/hslsa/levels.go`):

- A claim of a level the tool does not check yet is refused before any record is read, and again when a VSA is signed. Today that is L4 in every track.
- `SLSA_BUILD_LEVEL_n` needs a Design or Firmware level of at least n in the same list, since Design Ln and Firmware Ln meet SLSA Build Ln and not the other way round.
- A VSA states levels only in the tracks its check covers: a lot receipt check cannot state a Firmware or Assembly level, whatever the policy claims.

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

The board receipt check at Assembly L3 requires the EMS and every shipper to sign at accredited sites, every identity part on every board to have answered at build, a platform certificate for every board that names exactly what was placed on it, and the challenge at receipt. Example: `e2e/board/run.sh l3`, on the L3 chip lot, with three refusals: a chip swapped for another genuine one after build, serials typed into a list, and an EMS enrolled with no accreditation. Tests: `boardl3_test.go`, which also takes a chip off a board.

### Firmware L3

What the spec asks: SLSA Build L3 for every image; every image independently reviewed, shown by a signed OCP S.A.F.E. report; releases in a transparency log, which may be private; the device reports measurements under a DICE or Caliptra class identity that match the attested image digests; and every site that provisions the device rated at least L3 in its own track (rule 2).

What the tool does (`tools/hslsa/fwl3.go`, `fwbuild.go`, `tlog.go`):

- `--isolate` on a firmware build (`hslsa fpga firmware`, `hslsa fpga rot-firmware`) runs the compiler in the same bubblewrap sandbox as an isolated design step: no network, a fresh working directory with only the pinned sources, `/usr` read-only, no signing key in reach. The image is hashed and the record signed outside the sandbox, and the record says so in `buildDefinition.internalParameters.isolation` and `.network`.
- Every tool is a resolved dependency with its binary digest: a Debian package's tool with the digest of every file of the package, and the Go toolchain with one digest over everything a build runs or reads in its GOROOT. The policy pins them in `firmware.toolPins`; `hslsa pin <tool>...` prints the pins for the tools on a machine. Every input is named by digest.
- Images carry a SHA-384 digest as well, the one a S.A.F.E. report names them by. `hslsa safe simulate` signs a simulated report as a review provider would ([firmware review](caliptra-e2e.md#firmware-review-simulated)); the policy's `firmware.review` says which images need one and from which providers.
- `hslsa tlog` is a private transparency log: an append-only list of release records under RFC 9162 Merkle hashing, with checkpoints signed by the log operator's key (role `transparency-log`). `tlog add` puts a record in the log and writes its inclusion proof beside it (`<record>.tlog.json`); `tlog check` checks one; `tlog consistency` and `tlog verify-consistency` show that the log today extends the log a buyer saw before, so a release cannot be swapped after it was logged. Nothing goes to a public log.
- The at-boot check becomes mandatory: the buyer passes what each received device returned at boot, and its reported measurements must match the attested images under its DICE identity.
- Rule 2: for every provisioning record, the stage it was made at (`wafer-sort`, `final-test` or `board-programming`) names a track, the policy must claim L3 in that track, and the site's key must meet that track's L3 key rule (HSM custody and accreditation for Wafer and Package/Test, accreditation for Assembly).

The Firmware L3 check (`firmwareL3`) refuses a build that ran step code without the sandbox, with the network open or a key mounted; an input not pinned by digest; a tool not on the pin list or from another package or toolchain than the pinned one; a release not in the log the policy names, or whose log entry is another record; an image the policy does not require a review of, or with no accepted report; no boot evidence; and a provisioning site rated below L3 in its own track.

Example: `e2e/fpga/run.sh l3` makes the FPGA board's whole chain again at L3. The root of trust's lot is at Wafer L3 and Package/Test L3 (its ROM uses the die identity from wafer sort as its IDevID), the board at Assembly L3 (the EMS challenges each root of trust before placement), both firmware builds run isolated with pinned tools, a review lab signs a report for each, and every release is logged. The buyer checks the two boards it received with their boot evidence, and slsa-verifier checks the VSAs at `HSLSA_FIRMWARE_LEVEL_3`. It then shows seven refusals: a flash image not in the log, releases in a log the buyer does not read, firmware built with a compiler the policy does not pin, firmware no lab reviewed, boards with no boot evidence, a root of trust provisioned at a test house rated below L3, and a log that rewrote a release it had shown. Tests: `fwl3_test.go` (each refusal on a forged but validly signed record) and `tlog_test.go` (the RFC 6962 test vectors, inclusion and consistency proofs, tampered proofs and a forked log).

The Caliptra example's policy stays at Firmware L2: its firmware is built by the Caliptra build scripts outside the sandbox, so a Firmware L3 claim on it is refused, and `caliptra_test.go` checks that.

## L4 defense profile

Not checked yet; every L4 claim is refused. Planned: for Design, a rebuild under a separate trust root, two-person review of source freeze and waivers, and an HSM-held tapeout key; for Wafer, Package/Test and Assembly, a physical inspection record signed by an independent lab under its own trust root, with a seed committed before the lot is sealed and a sampling plan; for Firmware, an independent bit-for-bit rebuild of every image and two-person review of releases.
