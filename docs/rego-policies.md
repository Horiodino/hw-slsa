# Buyer policies in Rego

A buyer should not have to trust this project's code to check an HSLSA chain. [`policies/rego/`](../policies/rego) holds the buyer's rules for three of the spec's checks ([Where the chain is checked](../spec/hslsa-v0.1.md#where-the-chain-is-checked)) as Rego policies:

- the tapeout check, on the PicoRV32 design;
- the lot receipt check, on its shipped lot;
- the board receipt check, on the board built from that lot.

The official [Open Policy Agent](https://www.openpolicyagent.org/) release evaluates the policies, openssl and ssh-keygen verify the signatures, and nothing from `tools/hslsa` runs. CI runs this path on the bundles of the [PicoRV32 example](e2e-test.md) and the [board example](board-example.md), next to the reference tool.

This is item 5 of phase 1 in the [roadmap](roadmap.md). It covers the PicoRV32 and board chains up to the levels listed below. The at-boot check is not written in Rego and stays with the reference tool.

## How it works

| Piece | What it does |
| --- | --- |
| [`e2e/rego/input.sh`](../e2e/rego/input.sh) | Glue: bash, jq, openssl, ssh-keygen, tar and coreutils. It turns a bundle into one JSON input document. It decides no rule. |
| [`policies/rego/`](../policies/rego) | Every rule. `lib.rego` holds the shared helpers. `tapeout.rego`, `lot.rego` and `board.rego` each hold one check, and each check has a `*_test.rego`. |
| [`e2e/rego/run.sh`](../e2e/rego/run.sh) | Builds the input, runs `opa eval` and prints what was checked or why the bundle was refused. Then it runs the refusal cases below. |

`input.sh` writes the following into the input document:

- **Envelopes.** For each DSSE envelope, the decoded statement, plus the trust-root roles whose keys verified one of its signatures. The script builds the DSSE pre-authentication encoding and runs `openssl dgst -verify` against every key in the trust root.
- **Git objects.** For the signed git tag, the roles whose keys made its SSH signature (`ssh-keygen -Y verify`, namespace `git`). It also records the git object id of the tag, commit and tree.
- **Files.** The sha256 and size of every file, the sha256 of every member of a `.tar`, JSON artifacts parsed, and `.txt` lot lists as text.
- **Policy and receipt.** The policy, the trust root's role names and `validUntil`, and the units or boards received (`--received`).
- **Parts.** For a board, the same document for each part bundle under `parts/`, built from that part's own trust root and policy.

Everything else is decided in Rego:

- which role must have signed which record;
- every digest link between records;
- every gate, site and policy rule;
- lot digests, which Rego recomputes from the lot lists (sorted, trimmed, newline-joined, `crypto.sha256`; see [Lot digest](../spec/hslsa-v0.1.md#lot-digest));
- the HBOM's JSON Schema, checked with `json.match_schema`.

The board check runs the tapeout and lot rules on each part bundle with `with input as`, so a chip on the board passes the same rules as a chip bought on its own.

The policies fail closed. A policy that claims a level beyond what they check is refused with a message naming the level, so a pass never means more than these rules checked.

## Run it

You need [OPA](https://github.com/open-policy-agent/opa/releases) (`$OPA`, or `opa` on the PATH), openssl, ssh-keygen (OpenSSH 8.2+), jq and GNU coreutils. First produce the bundles as the examples do ([running it locally](e2e-test.md#running-it-locally)), then:

```sh
e2e/run.sh produce          # out/bundle: the PicoRV32 design and lot
e2e/board/run.sh produce    # out/board: the board, with the chip's bundle under parts/
e2e/rego/run.sh --received e2e/picorv32/received-units.txt out/bundle
e2e/rego/run.sh --received e2e/board/received-boards.txt out/board
opa test policies/rego hslsa.hbom_schema:hbom/hbom-predicate-v0.1.schema.json
```

`run.sh` takes the policy and trust root from the bundle, as the reference tool's `verify` step does. Use `--policy` and `--trust-root` to give your own, and `--check-only` to skip the refusal cases. The script exits non-zero unless every check passes and every refusal case is refused for its stated reason.

The chip bundle's report starts like this:

```
== independent check of out/bundle: OpenSSL 3.0.13, OPA 1.21.1, policies/rego
Signatures, checked against the trust root's keys (each part's own, for a part bundle):
  att/design-0-source-freeze.intoto.json: verified with a key of flow-platform
  ...
  artifacts/source-git/tag (git tag, ssh-keygen -Y verify): verified with a key of source-owner
tapeout check: PASSED for picorv32.netlist.v sha256:c0a9..., at HSLSA_DESIGN_LEVEL_3, SLSA_BUILD_LEVEL_3
  checked: design synthesis: signed by flow-platform, buildType and hwFlow.step, gates passed, ...
  ...
lot receipt check: PASSED for urn:hslsa:lot:ASM-EXAMPLE-17 sha256:4876..., at HSLSA_WAFER_LEVEL_2, HSLSA_PACKAGE_TEST_LEVEL_2, HSLSA_DESIGN_LEVEL_3
```

## What each check covers

### Tapeout check: Design L1 to L3 ([`tapeout.rego`](../policies/rego/tapeout.rego))

- **Design steps.** Each step in `design.requiredSteps` is signed by `flow-platform`, with:
  - its step's `buildType` and `hwFlow.step`;
  - every gate passed;
  - every file subject in the bundle with the attested digest;
  - only tools on `design.allowedTools`;
  - links, by digest, to the subjects of the steps it consumes (`design.consumes`).
- **Network.** Each step's network record is consistent and meets the policy's `design.network` rules: isolation when required, license servers and endpoints on the policy's list when it has one, and the limit on bytes sent.
- **Release.** The design release is signed by `tapeout-authority` and links every step envelope by digest. The artifact it releases is an output of `design.finalArtifactFrom`.
- **Design L2.**
  - The source tag is signed by the policy's `tagSigner` role (ssh-keygen).
  - The tag names the commit, and the commit names the tree, both by git object id, recomputed here.
  - Enough reviews (`minReviewers`) approve that commit. Each is signed by the reviewer role, and the reviewers are distinct and are not the commit's author.
  - Each third-party IP block has provenance signed by its vendor's role. Its files in the source archive have the digests that provenance names.
  - The source freeze links the commit, the reviews and the IP provenance.
- **Design L3.**
  - Every step after the source freeze ran isolated: a fresh working directory, the signing key out of reach, and no network, or only an allowed license server.
  - Every tool is pinned by binary digest, and by package name, version and file-tree digest where the pin names a package (`design.toolPins`).
  - The equivalence step proves the released netlist equal to the frozen RTL, and the bundle carries the script that record names.

### Lot receipt check: Wafer and Package/Test L1 and L2 ([`lot.rego`](../policies/rego/lot.rego))

It runs only after the tapeout check passes.

- **F1 to F4.**
  - Each record is signed by its site's role (`fab-site`, `sort-site`, `osat-site`, `test-site`), with its `buildType`, every gate passed and its file subjects in the bundle.
  - Each links the record before it by digest: the transfer that brought its input when there is one, otherwise the previous step. F1 links the design release.
  - Each names the released design and release in `designRef`.
- **Transfers.**
  - Each transfer is signed by the shipping site and links the record that shipped.
  - It goes from that site to the site that signed the next step.
  - Its packing list ships exactly the lot it names, by a lot digest recomputed here.
  - Transfers are required when `manufacturing.requireTransfers` is set.
- **Genealogy.** Every packaged unit traces to its own passing die on the wafer maps.
- **Lot lists.** The packaged and shipped lot lists hash to the attested lot digests. The yield record accounts for every packaged unit, and every received unit is in the shipped lot.
- **HBOM.**
  - It is signed by `product-owner` and matches the HBOM schema.
  - It binds the released design and the shipped lot.
  - It points by digest at F1 to F4 and at every design step's record.
  - Its renderings have the digests it lists.
- **Simulated evidence.** Records made from simulated hardware are refused unless the policy sets `simulated.accept`. When it does, the report lists them.

### Board receipt check: Assembly L1 and L2 ([`board.rego`](../policies/rego/board.rego))

- **Board HBOM.**
  - It is signed by `board-owner` and matches the HBOM schema.
  - It describes a board, module or system.
  - It names the board design, whose file digest is checked, and the board lot.
- **A1.**
  - The A1 record is signed by `ems-site`, with its `buildType`, every gate passed and its file subjects in the bundle.
  - Its `designRef` names the board design, and it links the design.
  - The HBOM points at A1 by digest and names A1's board lot.
- **Parts.**
  - Every part line traces to a distribution record signed by the role the policy gives that shipper (`shippers`), and A1 links that record.
  - The shipment data match the part's lot and date code.
  - A part the HBOM marks as bought through an authorized channel came from a shipper the policy authorizes for its manufacturer. With `requireAuthorizedChannel`, every part must be marked so.
- **Parts with their own chain (`hbomRef`).**
  - The part's bundle passes the tapeout and lot receipt checks above, under its own trust root and policy.
  - Every unit shipped to the EMS is in its shipped lot.
  - Its HBOM is of that part number.
  - The EMS's receipt VSA covers exactly those units, under the part's policy and levels.
  - A1 links the lot, the part HBOM and the receipt.
- **Placements.**
  - The HBOM lists exactly the board design's positions.
  - Every placement is a listed lot.
  - No chip is placed twice, and every placed chip was shipped to the EMS.
  - No lot is placed more often than it was shipped.
- **Board lot.**
  - The board lot list hashes to the attested lot digest, recomputed here.
  - It is the set of boards that passed test, and the yield accounts for every board.
  - Every board is an A1 subject, and every received board is in the lot.

## What stays with the reference tool

| Not done in Rego | What these policies do instead | Why |
| --- | --- | --- |
| The at-boot check (Firmware track, provisioning records, CoRIM appraisal) | Not written | Out of scope for this path. The at-boot check stays with the reference tool. |
| Design L4; Wafer and Package/Test L3 and L4; Assembly L3 and L4; any Firmware level | Refuse a policy that claims them | These levels read evidence the policies do not model: HSM key custody in the trust root's enrollments, die-identity challenges, part attestations and platform certificates, rebuilds, release approvals, the private release log, and inspection reports. |
| That the source archive holds exactly the files of the tagged git tree | Recompute the tag, commit and tree ids, and check the IP files in the archive and the archive's digest | Not feasible in Rego. Walking a git tree means parsing git's binary tree objects, which Rego has no builtin for. Doing it in the glue would move a rule out of Rego. |
| Proxy-signed and evidence records; records made from supplier exports (`hwMfg.adapter`); a policy that requires exports | Refuse them, naming the record | Each is its own rule set ([proxy-signing.md](proxy-signing.md), [mes-stdf-adapter.md](mes-stdf-adapter.md)), not written here. |
| Withheld fields and their disclosures ([selective-disclosure.md](selective-disclosure.md)) | Refuse records that withhold fields | Checking a disclosure means recomputing salted digests over canonical JSON. That is feasible, but not written here. |
| Re-rendering the HBOM as CycloneDX and SPDX and comparing bytes ([Renderings](../spec/hslsa-v0.1.md#renderings)) | Check each rendering's digest against the HBOM | Rendering is a converter. Writing a second one in Rego would only duplicate it. |
| Signing VSAs | Print the reports, sign nothing | This path only checks. The receipt VSA the board check reads is the EMS's, signed with the reference tool. |
| The FPGA, Caliptra and OpenLane 2 examples | Not covered | Only the PicoRV32 and board bundles have policies here. |

Where the two paths differ in detail:

- **Trust root.** Of a trust root, the policies read only the role names and `validUntil`. An expired trust root is refused. Enrollment details matter only to the L3 and L4 rules above.
- **keyid.** The policies ignore a DSSE signature's `keyid`. `input.sh` tries every trust-root key against every signature, and a record counts as signed by a role when any of that role's keys verifies one of its signatures.
- **HBOM schema.** The HBOM schema is JSON Schema 2020-12, and OPA's `json.match_schema` implements draft-07. The schema uses only keywords both drafts share (`$ref` into `$defs`, `if`/`then`, `const`), so the two validators agree on its structure. OPA also asserts `format` (`date`, `uri`), which the reference tool treats as an annotation. On a malformed date or URI, OPA refuses an HBOM that the reference tool accepts.
- **Messages.** Refusal messages follow the reference tool's where the rule is the same, but they are not guaranteed to be identical.

## Refusal cases

After the bundle passes, `run.sh` breaks copies of it and requires each copy to be refused for the stated reason. It makes the keys these cases sign with in a temporary directory and deletes them at the end.

| Bundle | Broken copy | Refused with |
| --- | --- | --- |
| Chip | The synthesis record edited after signing | `design-2-synthesis.intoto.json: no valid signature from role 'flow-platform'` |
| Chip | The HBOM re-signed with a new key the trust root lists for `test-site` | `hbom.intoto.json: no valid signature from role 'product-owner'` |
| Chip | F1 re-signed by a new, enrolled `fab-site` key, with a different digest for the design release | `wafer-fab: chain broken, resolvedDependencies do not include previous step att/design-release.intoto.json` |
| Chip | A failed unit appended to `shipped-lot.txt` | `final-test: shipped lot list does not match the attested lot digest` |
| Board | A1 edited after signing | `mfg-a1-board-assembly.intoto.json: no valid signature from role 'ems-site'` |
| Board | A shipment re-signed with a key the trust root lists for the broker | `mfg-distribution-EXAMPLE-SHIP-0001.intoto.json: no valid signature from role 'dist-franchised'` |
| Board | A1 re-signed by a new, enrolled `ems-site` key, linking a different shipment digest | `board-assembly: chain broken, resolvedDependencies do not include shipment record att/mfg-distribution-EXAMPLE-SHIP-0002.intoto.json` |
| Board | A failed board appended to `board-lot.txt` | `board-assembly: board lot list does not match the attested lot digest` |
| Board | A failed unit appended to the chip's `shipped-lot.txt` under `parts/` | `parts: PSOC130-QFN64 lot receipt check failed: final-test: shipped lot list does not match the attested lot digest` |

## Tests

`opa test` runs the unit tests in `policies/rego/*_test.rego` on two fixtures, [`testdata/chip`](../policies/rego/testdata/chip/data.json) and [`testdata/board`](../policies/rego/testdata/board/data.json). These are the input documents `input.sh` built from the example bundles.

Each check has a test that requires the valid fixture to pass with no refusal. Every other test changes one thing and requires the specific refusal. Examples:

- a record signed by the wrong role;
- a failed gate;
- a broken link;
- a unit on a failing die;
- an edited lot list;
- a part bought outside an authorized channel;
- a chip placed twice;
- a receipt over other units;
- a claim above what the policies check.

To rebuild the fixtures after the examples change:

```sh
e2e/rego/input.sh --received e2e/picorv32/received-units.txt out/bundle | jq -S --indent 1 . > policies/rego/testdata/chip/data.json
e2e/rego/input.sh --received e2e/board/received-boards.txt out/board | jq -S --indent 1 '.parts = {}' > policies/rego/testdata/board/data.json
```

The board fixture leaves its part bundle out, because that bundle is the chip fixture without `received`. The board tests put the chip fixture back in its place. A few tests name values from the fixture, such as the source commit id, so a rebuilt fixture may need those values updated.

## In CI

The `verify` job of [`hslsa-e2e.yml`](../.github/workflows/hslsa-e2e.yml) runs this path after the reference tool has checked the same bundles:

1. It downloads OPA v1.21.1 (`opa_linux_amd64_static`) from OPA's GitHub release and checks it against the sha256 pinned in the workflow, as it does for slsa-verifier.
2. It runs `opa check --strict`, `opa fmt` and `opa test`.
3. It runs `e2e/rego/run.sh` on the chip bundle and on the board bundle.

The reports go into the job summary with the reference tool's.
