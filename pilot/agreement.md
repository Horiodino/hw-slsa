# What the parties settle before the first lot

A checklist, not a contract: each line is a question the buyer, the RoT vendor and the OSAT group answer together and write down before any records move. Where the spec or the tool already decides, the line says so.

## Scope

- [ ] The part (vendor part number and revision), the board it goes on, and how many lots the pilot covers.
- [ ] The levels claimed, as the buyer's policy states them. The kit's default is Package/Test L2 and Firmware L2, with Wafer at L1 because the foundry's record is proxy-signed.
- [ ] Which sites sign which roles, one key per role ([buyer.md](buyer.md#2-enroll-each-key-you-accept)).
- [ ] The exit, from the roadmap: one external supplier signs one record type for a real product, and one buyer verifies it before accepting parts. Agree what happens to a lot that fails its check: held, or accepted on the old process while the failure is fixed.

## Keys

- [ ] How the buyer checks each key before enrolling it: key ceremony, fingerprint read back over a second channel, or an HSM vendor's key attestation.
- [ ] Key custody per role: HSM or file. Package/Test L3 needs an HSM.
- [ ] Enrollment length, and who tells whom when a key is lost, rotated or a person with access leaves. The buyer revokes; a revoked key counts for none of its records.
- [ ] Where the buyer's root key lives, and who may use it.

## Data

- [ ] Which records and data files the buyer receives. By default, everything in the bundle: records, the exports they were made from, wafer maps, genealogy, test results. `hslsa pilot measure` lists the fields per company.
- [ ] Which fields, if any, the OSAT or the vendor needs withheld, and whether an escrow auditor checks the full records instead ([selective disclosure](../spec/hslsa-v0.1.md#selective-disclosure)). A lot made from exports cannot withhold fields yet.
- [ ] How bundles move: the kit assumes files handed over with the parts or through a channel the parties already use. Nothing is uploaded to a public transparency log; the reference tool never does.
- [ ] How long each party keeps the records, the exports and the parts' identity data ([Retention and access](../spec/hslsa-v0.1.md#retention-and-access)).

## Measurement and publication

- [ ] Each party fills in the cost sheet per lot: hours, and money where it will share it ([`e2e/pilot/costs.json`](../e2e/pilot/costs.json)).
- [ ] What the pilot report may name: companies, part, lot counts, cost figures, failed checks. Each party approves the report before it leaves the pilot. Anonymized figures are an acceptable default.
- [ ] Where the report goes: the roadmap's phase 5 presents pilot results at NIST's traceability work and to the neutral home. Whether this repository becomes public is its owner's decision, separate from the report.
