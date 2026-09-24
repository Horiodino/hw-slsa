# Provisioning station adapter

A programming station at a fab, OSAT or EMS writes fuses, keys and images into each part and logs what it did, in its own format. It knows nothing about HSLSA. The adapter in `tools/hslsa/provadapter.go` reads that export as the station wrote it and signs one [`fw-provisioning` record](../spec/hslsa-v0.1.md#firmware-provisioning-record) per unit with the site's key. It is the provisioning row of [roadmap phase 3](roadmap.md#phase-3-adapters-for-tools-suppliers-already-run).

The [FPGA board example](fpga-board-example.md) uses it at the root of trust vendor's test house: a simulated gang programmer runs a job and writes its export, and the adapter's records are what the board receipt and at-boot checks read.

## Two commands around the job

```sh
# Before the job runs: check each image the job file loads against its provenance.
hslsa provision gate  --bundle B --profile xg8-profile.json --station ps-02.json --export EXPORT

# ... the station runs the job and writes its export ...

# After the job: read the export and sign one record per unit of the shipped lot.
hslsa provision adapt --bundle B --profile xg8-profile.json --station ps-02.json --export EXPORT --key test-site.key.pem
```

The spec requires the station to verify each image's provenance before it writes a part. A station cannot, so the **gate** does it when the job is loaded: for every image in the job file, the file the job loads must have the digest the job names, and that digest must be a subject of the image's provenance, signed by the role the station file names. If any image fails, the gate writes nothing and the job must not run. Otherwise it writes `artifacts/provisioning/gate-<job>.json` to the bundle with the job file's digest, the images it cleared and the time. The adapter later records `image-provenance-verified` only when that gate cleared this exact job file, and cleared it before the unit's first write.

**adapt** reads the job file and the log through the profile and builds each unit's record from its last session in the log (a station retries a unit by starting a new session; the record counts the sessions). It copies into the bundle the job file, each unit's own log rows (one CSV per unit, so a record never points at another unit's data) and the identity files, and names them by digest in the record's `resolvedDependencies` and in `hwProvision.export`.

## Two configuration files

| File | Describes | Example |
| --- | --- | --- |
| Profile | One station model's export: the job file's name and layout (which INI keys hold the job id, the lot, and each image's file, region and sha256), the log file, its delimiter, column names and time format, the word for a passed operation, and the word for each operation | [`e2e/fpga/rot/station/xg8-profile.json`](../e2e/fpga/rot/station/xg8-profile.json) |
| Station file | One station at one site programming one part: the station id, site, stage and lot; each image's role, storage and provenance envelope with its signer; the type of each fuse field (`string`, `hex`, `int`, `bool`); which fields are secrets; the lifecycle fuse and its production value; the identity scheme, the fuse holding the UEID, and the trust root role of the identity CA; and the injecting HSM, if keys are injected | [`e2e/fpga/rot/station/ps-02.json`](../e2e/fpga/rot/station/ps-02.json) |

A second station model needs only a new profile. The tests in `provadapter_test.go` run the same adapter on a second, made-up model, the "Example SP-1": a recipe file instead of a job file, a semicolon-separated log with other column names, another time format, `OK` for a pass and its own words for each operation, and keys injected from an HSM instead of generated on the die.

The operations a profile names:

| Operation | Log row means | Profile key |
| --- | --- | --- |
| Begin, end | A session on one unit starts or finishes | `begin`, `end` |
| Program, verify | An image written to a region; the region read back, with the value naming the readback dump in the export | `program`, `verify` |
| Fuse write, fuse read | A fuse field burned or read back, with its value | `fuseWrite`, `fuseRead` |
| Key inject, key generate | A secret written from an HSM or generated on the die, with its key id as the value | `keyInject`, `keyGenerate` |
| CSR, certificate | The CSR the part exported and the certificate the CA returned, each naming a file in the export | `csr`, `certificate` |

## What each record checks

| Check | Passes when |
| --- | --- |
| `image-provenance-verified` | The gate cleared this job file before the unit's first write, and cleared every image it loads |
| `image-readback` | Every image the job loads was written, and has a passing verify of its region whose readback dump has the image's digest |
| `fuse-readback` | Every fuse field the station file types was written, and every fuse written was read back, after the write, with the same value |
| `csr-self-signature` | The exported CSR is signed by its own key |
| `certificate-matches-csr` | The certificate the station stored is for the CSR's key |
| `certificate-endorsed` | The certificate is signed by a key the trust root lists under the station file's CA role |
| `lifecycle-production` | The lifecycle fuse holds the production value and the debug lock fuse is set |
| `station-log-passed` | Every row of the unit's last session passed and the session ended |

The record's subject is the unit with its IDevID public key digest, as the spec's [naming rules](../spec/hslsa-v0.1.md#naming-subjects) ask; for a part without an identity it is the serial. A unit that fails a check still gets its record, with the check failed, and `adapt` then exits with an error naming the unit, so a failure is written down rather than left out.

## What the adapter refuses

It signs nothing, and exits with the reason, when:

- the log holds a value for a field the station file calls a secret, or a key id that looks like key material (32 or more hex digits, or a long base64 run);
- a unit of the shipped lot has no session in the log;
- a log row programs a region the job does not load, or names an identity file outside the export (a readback dump outside it fails `image-readback` instead);
- the export does not read as the profile describes (a missing column, a time in another format, a job without images).

A unit in the log that is not in the shipped lot, such as one that failed final test, gets no record, and the adapter says so.

## Where the signing key comes from

The adapter signs through one function, `stationSigner`, which opens the key with `LoadSigner`. Since the [HSM signing adapter](hsm-signing.md), that takes a PEM file, a PKCS#11 URI or a `<role>.pkcs11` file, so `--key` can name a key in the HSM the spec requires for a site from L3. `stationSigner` is the one place to change if a station needs anything more; nothing else in the adapter depends on where the key lives.

## Limits

- The stations are simulated. Both profiles describe made-up station models, close to what gang programmers log but not any vendor's format. The roadmap's exit criterion, records from a real export without manual editing, needs a real station's export, which waits for a supplier (phase 4). Writing its profile should be the only work.
- The Caliptra example's test station and the FPGA example's EMS still sign their records directly, without an export. The EMS record also names the root of trust unit A1 placed on each board, which comes from the chain rather than from the station, so the adapter would need that added.
- The gate is a procedure at the site: it shows the job was cleared before the first write, by the times the station logged. A site that runs a job without the gate gets records whose `image-provenance-verified` check fails, which the buyer's checks refuse.
