# Selective disclosure and verifier escrow

This example takes the PicoRV32 lot from the [end-to-end test](e2e-test.md) and has its sites withhold the values a real foundry, test house or OSAT would keep secret, and its flow platform a value a design house would. An auditor then checks the full chain for a buyer, and the buyer receives only the auditor's two verification summaries. It implements [Selective disclosure](../spec/hslsa-v0.1.md#selective-disclosure) in the spec and runs as the `escrow` job of [`.github/workflows/hslsa-e2e.yml`](../.github/workflows/hslsa-e2e.yml).

## Who holds what

| Party | Holds | Does |
| --- | --- | --- |
| Flow platform, tapeout authority, sites and product owner | Their keys, the full records and the disclosures | Sign synthesis, the release, F1 to F4 and the HBOM once, with fields withheld |
| Auditor | The full bundle with its disclosures, the sites' trust root, its own key, the escrow manifest | Runs the tapeout and lot receipt checks for the buyer's units under the buyer's policy, signs a design VSA and a receipt VSA |
| Buyer | Its policy, the serials of the three units it received, its own trust root enrolling the auditor's key with the auditor's accreditation, the two VSAs | Checks the VSAs with `hslsa escrow check` and with slsa-verifier |

The buyer never sees a site's record, key or data file.

## What is withheld

[`e2e/picorv32/withhold.json`](../e2e/picorv32/withhold.json) lists, per record, the JSON Pointers to withhold, and the data files to salt:

| Record | Withheld |
| --- | --- |
| Synthesis (a design record) | The Yosys script, which holds the tool's arguments |
| F1 wafer fab | The mask set id |
| F2 wafer sort | The probe program and the yield |
| F4 final test | The test program and the yield, which lists the scrapped serials |
| HBOM | The mask set id, the wafer ids and both test programs |
| Data files | `wafer-maps.json`, `genealogy.json` and `final-test-results.json` each get a random 128-bit `salt` member |

The HBOM withholds the same values as the records, because a value withheld in one record and written in another is not hidden. The `leaks` command checks for that.

A signed F4 record then carries, in place of its yield:

```json
"confidential": [
  {"path": "/buildDefinition/externalParameters/testProgram", "saltedDigest": {"sha256": "288c1606..."}},
  {"path": "/hwMfg/yield", "saltedDigest": {"sha256": "5cc098a8..."}}
]
```

The disclosure for the yield, in `disclosures/mfg-f4-final-test.disclosures.json`, is a base64url string whose sha256 is that `saltedDigest`, and which decodes to the salt, the path and the value:

```json
["Fe3FbOUhukklt74rC1Ytyg","/hwMfg/yield",{"failed":["PSOC130-A0-00007","PSOC130-A0-00019","PSOC130-A0-00033"],"in":40,"passed":37}]
```

The verifier restores every withheld field from its disclosure when it opens a record, so the tapeout and lot receipt checks run unchanged on the restored records. A design record lists what it withholds in `hwFlow.confidential[]`, in the same form. It may withhold metrics, a tool's script or arguments, file paths and IP names, never a digest, its step, its pinned tools, its checks or how it ran ([Withheld fields](../spec/hslsa-v0.1.md#withheld-fields)). Here synthesis runs again with its script withheld, producing the same netlist, and the tapeout authority signs the release again over that record.

## The runs

[`e2e/escrow.sh`](../e2e/escrow.sh) plays each party in turn:

```sh
e2e/run.sh produce            # the signed chain, keys still present
e2e/escrow.sh produce         # synthesis, the release and the lot signed again with fields withheld, into out/escrow/bundle
e2e/escrow.sh audit           # the auditor: full check, then out/buyer/vsa/{design,receipt}.vsa.intoto.json
SLSA_VERIFIER=/path/to/slsa-verifier e2e/escrow.sh buyer   # the buyer: checks the two VSAs
e2e/escrow.sh leaks           # the measurement below, into out/leaks
e2e/escrow.sh direct          # without an auditor: the per-unit commitment and the buyer's log, below
```

The auditor's run:

```
tapeout check: PASSED for picorv32.netlist.v sha256:f9c3b9d9...
lot receipt check: PASSED for urn:hslsa:lot:ASM-EXAMPLE-17 sha256:4876860b..., 3 received units found in the lot
escrow audit: VSAs for the design and 3 received units written to out/buyer/vsa; manifest of 14 records, 16 files and 4 disclosure files kept at out/auditor/escrow-manifest.json
ok: rejects a received unit that was scrapped at final test
```

The receipt VSA's subject is `urn:hslsa:receipt:ASM-EXAMPLE-17`, digested with the lot digest formula over the buyer's three serials, and its `resourceUri` is the shipped lot. The buyer computes the same digest from its own list (`hslsa lot-digest received-units.txt`) and checks the VSA with slsa-verifier, with no HSLSA record in hand:

```sh
slsa-verifier verify-vsa \
  --attestation-path receipt.vsa.intoto.json \
  --subject-digest "sha256:$(hslsa lot-digest received-units.txt)" \
  --resource-uri urn:hslsa:lot:ASM-EXAMPLE-17 \
  --verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1 \
  --verified-level HSLSA_PACKAGE_TEST_LEVEL_2 \
  --public-key-path auditor.pub.pem \
  --public-key-id "$(hslsa keyid --key auditor.pub.pem)"
```

`hslsa escrow check` adds what slsa-verifier does not check: both VSAs passed under the buyer's own policy (by digest), state every level it claims and name the same escrow manifest. The buyer's policy also accepts only an auditor accredited under ISO/IEC 17065 (`escrow.auditorAccreditations`), so the buyer runs its own trust root and enrolls the auditor's key with that accreditation (`hslsa pilot enroll --accreditation iso-iec-17065`), as it would enroll a site. The script also checks that slsa-verifier and the buyer's check reject the receipt for another set of units, that slsa-verifier rejects a level above the one verified, and that the buyer's check rejects the VSAs under a plain trust root that lists the auditor's key without an enrollment.

## What each view reveals

`hslsa leaks` reads the full bundle, as its producer would, and reports what a party holding only the signed records learns and what the buyer under escrow learns. It tries to recover each lot from its digest the way a buyer could: it reads the serial format from the buyer's three units and tries runs of serials, smallest lot first, with up to three scrapped. This is its report for the example, from a local run; CI writes the same report to the escrow job's summary.

### What a party holding only the signed records learns

| What | Measured |
| --- | --- |
| Records | 14 envelopes: 4 `design-flow`, 1 `hbom`, 7 `manufacturing-step` (F1 to F4 and the three transfers between them), 1 `source-review`, 1 SLSA Provenance (the IP release) |
| Signing keys | 9 distinct key ids, each naming one party in every record it signs, across lots and buyers |
| Builders | the flow platform, `urn:hslsa:site:example-wafer-fab`, `urn:hslsa:site:example-sort-house`, `urn:hslsa:site:example-osat`, `urn:hslsa:site:example-test-house` |
| Subject names | `urn:hslsa:lot:ASM-EXAMPLE-17`, `urn:hslsa:wafer-lot:skywater:LOT-EXAMPLE-A`, `urn:hslsa:assembly-lot:ASM-EXAMPLE-17` |
| Timeline | `finishedOn` on 12 records |
| Withheld fields | 9, values hidden |
| Withheld values shown elsewhere | none |
| Data files named by manufacturing records | `wafer-maps.json`, `genealogy.json`, `final-test-results.json` and the three transfer packing lists, all salted |
| `urn:hslsa:assembly-lot:ASM-EXAMPLE-17` | recovered from its digest by guessing: 40 units, serials PSOC130-A0-00001 to PSOC130-A0-00040, found at guess 1 |
| `urn:hslsa:lot:ASM-EXAMPLE-17` | recovered from its digest by guessing: 37 units (3 of the run missing), serials PSOC130-A0-00001 to PSOC130-A0-00040, found at guess 3802 |
| `urn:hslsa:wafer-lot:skywater:LOT-EXAMPLE-A` | not attempted: a buyer holds no wafer ids |
| Derived | final test yield of ASM-EXAMPLE-17: 37 of 40 packaged units shipped; scrapped PSOC130-A0-00007, PSOC130-A0-00019, PSOC130-A0-00033 |

### What the buyer learns under escrow

| VSA | Subject | Resource | Levels | Inputs |
| --- | --- | --- | --- | --- |
| `design.vsa.intoto.json` | `picorv32.netlist.v` | `hslsa:design:picorv32.netlist.v` | HSLSA_DESIGN_LEVEL_2, SLSA_BUILD_LEVEL_2 | 1 (the manifest) |
| `receipt.vsa.intoto.json` | `urn:hslsa:receipt:ASM-EXAMPLE-17` | `urn:hslsa:lot:ASM-EXAMPLE-17` | HSLSA_WAFER_LEVEL_2, HSLSA_PACKAGE_TEST_LEVEL_2, HSLSA_DESIGN_LEVEL_2 | 1 (the manifest) |

So withheld fields hid every value they covered, and no other record showed one of them, but the lots were recovered from their digests in about 3 ms, and with them the final test yield and the scrapped serials that F4 withholds. Site names, the fab and the timeline stayed visible. Under escrow the buyer learned only the design digest, the lot id, the levels and the auditor. The spec draws the same conclusions in [What each view reveals](../spec/hslsa-v0.1.md#what-each-view-reveals).

The lot recovery works because these units are named by sequential serials, as at Package/Test L2. At L3 the lot is taken over certificate digests, and the search stops at once: the units share no serial format.

## Without an auditor

A buyer that wants to check its own units, and not hand the check to an auditor, can do so against a commitment final test makes to its lot ([Per-unit commitment](../spec/hslsa-v0.1.md#per-unit-commitment)). `e2e/escrow.sh direct` runs it on a copy of the produced lot:

1. Final test signs the lot again with `unitCommitment` set in its scenario. Its record now carries the root of a Merkle tree over the 37 shipped units, each leaf salted and the tree padded with random leaves to 64, and the tool writes one inclusion proof per unit to `artifacts/unit-proofs/`.
2. The buyer holds final test's record, the test site's public key and the proofs that shipped with its three units, and runs `hslsa unit-check`. It learns that its units are in the lot, and that the lot has at most 64 units.
3. A proof made up for a unit that failed final test is refused.
4. The buyer also runs its own log (`hslsa tlog`), and its policy requires every manufacturing record, transfer and the HBOM in it, and a proof for every received unit (`manufacturing.transparencyLog`, `manufacturing.unitCommitment`). The lot receipt check passes, and is refused once one record's inclusion proof is taken away.

Final test's record still names the lot by its lot digest, which at Package/Test L2 is taken over guessable serials, so the buyer can still recover the lot as below. The commitment adds a check the buyer can run alone; it keeps the lot's size and members from the buyer only at Package/Test L3.

## Tests

- [`tools/hslsa/disclose_test.go`](../tools/hslsa/disclose_test.go) withholds and restores fields on records built in the test, refuses 15 paths a producer may not withhold (the gates, the links, the design release, whole blocks, the list itself, overlapping or malformed pointers), and breaks disclosures in 10 ways: missing, one of two missing, a changed value, one from another record, a salt shorter than 128 bits, a disclosure for another path, a field both withheld and present, two entries with one digest, a protected field listed as withheld, and a disclosure that is not base64url.
- [`tools/hslsa/escrow_test.go`](../tools/hslsa/escrow_test.go) builds the escrow bundle from the produced chain, as the job does, and checks that the chain verifies with its disclosures and fails without them, with a yield disclosure that hides a scrapped unit, with another record's disclosures, and with a gate result listed as withheld. It runs the auditor and the buyer, and the buyer rejects a receipt for other units, a VSA signed by a site key, a VSA under another policy, a missing level, a failed result, and a design VSA and a receipt VSA from two different audits. The auditor refuses a scrapped unit.
- [`tools/hslsa/designdisclose_test.go`](../tools/hslsa/designdisclose_test.go) withholds the synthesis and signoff scripts, the signoff method and an IP block's name from design records, checks that the chain verifies with the disclosures and the values come back, and withholds a step's metrics and PDK path and brings them back. It refuses to withhold an input digest, the byproducts, a tool pin, the checks, the step, the isolation block or the whole `externalParameters` block, and refuses a design record whose disclosure is missing.
- [`tools/hslsa/q9_test.go`](../tools/hslsa/q9_test.go) accepts an auditor enrolled with an accreditation the policy lists and refuses one not enrolled, enrolled without an accreditation, or accredited under another scheme. It accepts every shipped unit's proof under final test's commitment and refuses a unit final test failed, a proof from another lot's commitment, a proof for another unit, a received unit with no proof, final test without a commitment and a commitment edited without re-signing. It accepts a lot whose records are all in the buyer's log and refuses a record not in it, a record signed again after it was logged and a record logged in another log.
- [`tools/hslsa/leaks_test.go`](../tools/hslsa/leaks_test.go) checks the lot recovery on its own (found, bounded, and not attempted for certificate digests) and that the report finds a withheld mask set id written in another record and a withheld site name spelled out in a builder id.

## Limits

- The physical data is simulated, as in the rest of the example, and every party runs under one GitHub account.
- The auditor's key is made per run. A real auditor's key is long-lived and in the buyer's trust root before any lot ships. The buyer enrolls its auditors itself, and the accreditation in the example is made up.
- The at-boot check does not run under escrow yet.
- The lot recovery tries sequential serials only. It shows that guessable serials leak volumes; it is not a bound on what a determined party could guess.
