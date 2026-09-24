# The suppliers' steps

Two companies produce records in this pilot: the **OSAT group**, which runs wafer sort, assembly, final test and the programming station at test, and signs its own records for the first time; and the **RoT vendor**, which already signs its design and firmware records and adds the HBOM. Nothing here sends data anywhere: each party hands over files, in a bundle, to the next.

## The OSAT group

### 1. Keys, one per role, that never leave you

```sh
# With an HSM (a PKCS#11 token): keys that cannot be exported.
hslsa hsm keygen --token osat-pilot --out keys sort-site osat-site test-site
# Without one, at L2 only:
hslsa keygen --out keys sort-site osat-site test-site
```

Send the buyer `keys/<role>.pub.pem` for each role and confirm the fingerprint (`hslsa keyid --key keys/<role>.pub.pem`) when the buyer calls back. Tell the buyer how each key is held; the buyer records it in your enrollment, and Package/Test L3 needs an HSM. The private keys, or the token, stay with the sites that sign. See [hsm-signing.md](../docs/hsm-signing.md) for the module and PIN settings.

### 2. Records from the exports you already have

You do not change what your MES and testers write. Describe once, in an adapter configuration, which file holds what and which MES operation is which check ([MES and STDF adapter](../docs/mes-stdf-adapter.md)); [`e2e/pilot/adapter.json`](../e2e/pilot/adapter.json) is the rehearsal's. For each lot:

```sh
hslsa adapt --config adapter.json --out scenario.json
```

The adapter reads MES lot histories and the unit genealogy, STDF V4 from sort and final test, and SEMI E142 wafer maps, and refuses exports that do not describe one lot moving from site to site. The foundry signs nothing in this pilot, so the configuration's `"unsigned": {"wafer-fab": {"cover": "proxy"}}` makes your sort site sign the foundry's record from the foundry's own MES export, which the record carries and the buyer reads again.

### 3. Sign your steps, and only yours

The RoT vendor sends you its bundle with the design release in it. Sign the lot into it:

```sh
hslsa mfg --bundle lot --scenario scenario.json --keys keys --sign sort-site,osat-site,test-site
```

`--sign` names the roles whose records this run signs, with the keys in `keys`. A record of any other role must already be in the bundle, signed by its own site; the run keeps it, after checking it names exactly what this lot gives, and stops with a message at the first record nobody has signed yet. So if sort and final test run at separate sites, the sort site signs first and hands the bundle on:

```sh
hslsa mfg --bundle lot --scenario scenario.json --keys sort-keys --sign sort-site            # stops before packaging
hslsa mfg --bundle lot --scenario scenario.json --keys assembly-keys --sign osat-site,test-site
```

### 4. Provisioning at final test

The programming station at final test writes the RoT's firmware, fuses and identity, and logs it in its own format. Two commands around each job turn its export into one signed record per unit ([provisioning adapter](../docs/provisioning-adapter.md)):

```sh
hslsa provision gate  --bundle lot --profile <station-model>.json --station <station>.json --export EXPORT
# ... the station runs the job ...
hslsa provision adapt --bundle lot --profile <station-model>.json --station <station>.json --export EXPORT --key keys/test-site.key.pem
```

The gate checks every image the job loads against the vendor's firmware provenance before the job runs; if it fails, do not run the job. A new station model needs a profile describing its export; the RoT vendor's station file says which images, fuses and identity scheme the part takes.

### 5. Hand the bundle back

Return the bundle to the RoT vendor for the HBOM. Keep your exports for as long as the agreement says ([agreement.md](agreement.md)); the records carry their digests, so a copy kept elsewhere can be checked against them.

## The RoT vendor

1. Send the buyer the public key for every role you sign with (see the table in [buyer.md](buyer.md#2-enroll-each-key-you-accept)), with the same fingerprint check.
2. Send the OSAT group the bundle with your design release and firmware provenance, and the station file for the part.
3. When the bundle comes back, sign the HBOM over the shipped lot (`hslsa hbom`, or `hslsa fpga rot-hbom` for a part with firmware listed) and ship the bundle to the buyer with the parts. Do not include a `trust-root.json` the buyer is meant to rely on: the buyer builds its own.
4. Fill in your hours for the lot in the cost sheet.

## What the buyer will see

`hslsa pilot measure` lists, per company, the fields of your records the buyer now holds: lot ids, test and probe program names, yields, check results, the sites and the exports' contents. If some of that is confidential, say so before the first lot: the spec's [selective disclosure](../spec/hslsa-v0.1.md#selective-disclosure) can withhold fields or hand the records to an escrow auditor instead, though a lot made from exports cannot withhold fields yet, because the exports it carries hold every value. [agreement.md](agreement.md) is where this gets settled.
