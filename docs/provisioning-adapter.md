# Provisioning station adapter

A programming station at a fab, OSAT or EMS writes fuses, keys and images into each part and logs what it did, in its own format. It knows nothing about HSLSA. The adapter in `tools/hslsa/provadapter.go` reads that export as the station wrote it and signs one [`fw-provisioning` record](../spec/hslsa-v0.1.md#firmware-provisioning-record) per unit with the site's key. It is the provisioning row of [roadmap phase 3](roadmap.md#phase-3-adapters-for-tools-suppliers-already-run).

Every station in the examples goes through it, each a simulated station that runs a job and writes its export:

| Station | Example | Station model | Programs | Configuration |
| --- | --- | --- | --- | --- |
| ps-02 at the root of trust vendor's test house | [FPGA board](fpga-board-example.md) | Example XG-8 gang programmer | Root of trust parts | [`xg8-profile.json`](../e2e/stations/xg8-profile.json), [`ps-02.json`](../e2e/fpga/rot/station/ps-02.json) |
| prog-01 at the EMS | [FPGA board](fpga-board-example.md) | Example ICP-2 in-circuit programmer | Assembled boards, with the root of trust on each | [`icp2-profile.json`](../e2e/stations/icp2-profile.json), [`prog-01.json`](../e2e/fpga/station/prog-01.json) |
| ps-01 at Caliptra's test house | [Caliptra](caliptra-e2e.md) | Example XG-8 gang programmer | Caliptra parts, with keys from the site's HSM | [`xg8-profile.json`](../e2e/stations/xg8-profile.json), [`ps-01.json`](../e2e/caliptra/station/ps-01.json) |

The adapter's records are what the board receipt, the Caliptra receipt and the at-boot checks read. The two XG-8 stations share one profile: a second station of the same model needs only its own station file.

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
| Profile | One station model's export: the job file's name and layout (which INI keys hold the job id, the lot, and each image's file, region and sha256), the log file, its delimiter, column names and time format, the word for a passed operation, and the word for each operation | [`e2e/stations/xg8-profile.json`](../e2e/stations/xg8-profile.json) |
| Station file | One station at one site programming one part or board: the station id, site, stage and lot; each image's role, storage and provenance envelope with its signer; the type of each fuse field (`string`, `hex`, `int`, `bool`); which fields are secrets; the lifecycle fuse and its production value; the identity scheme, the fuse holding the UEID, and the trust root role of the identity CA; the injecting HSM, if keys are injected; and, at an EMS, the board's maker and where the board's root of trust sits | [`e2e/fpga/rot/station/ps-02.json`](../e2e/fpga/rot/station/ps-02.json) |

An image's `provenance` is a file name in the bundle's `att/`, or a path from the bundle's root when the envelope is elsewhere, such as `design/att/fw-flash.intoto.json` for the flash image a board bundle carries in its design bundle.

A second station model needs only a new profile. The tests in `provadapter_test.go` run the same adapter on a second, made-up model, the "Example SP-1": a recipe file instead of a job file, a semicolon-separated log with other column names, another time format, `OK` for a pass and its own words for each operation, and keys injected from an HSM instead of generated on the die.

The operations a profile names:

| Operation | Log row means | Profile key |
| --- | --- | --- |
| Begin, end | A session on one unit starts or finishes | `begin`, `end` |
| Program, verify | An image written to a region; the region read back, with the value naming the readback dump in the export | `program`, `verify` |
| Fuse write, fuse read | A fuse field burned or read back, with its value | `fuseWrite`, `fuseRead` |
| Key inject, key generate | A secret written from an HSM or generated on the die, with its key id as the value | `keyInject`, `keyGenerate` |
| CSR, certificate | The CSR the part exported and the certificate the CA returned, each naming a file in the export | `csr`, `certificate` |
| Identify | The serial a part on the board answered with, at the reference designator in the target column | `identify` |
| Power on | The board powered once, and whether its root of trust released the main device | `powerOn` |

## Boards and the root of trust on them

A station at an EMS programs assembled boards. Its station file has a `board` block naming the board's maker, and the adapter then signs one record per board of the board lot (`artifacts/board-lot.txt`): the subject is `urn:hslsa:board:<maker>:<serial>`, the record is `att/prov-board-<serial>.intoto.json`, and the design it names is the board design with the A1 record that built it.

A board with a root of trust also has a `rootOfTrust` block: the part's reference designator, where the part vendor's records are in the bundle (the vendor's bundle the board bundle carries, `parts/rot` in the example), the identity scheme, and the trust root role of the vendor's identity CA. The station reads the part's serial at that reference designator and asks the part for its IDevID CSR. The adapter then opens the vendor's provisioning record for that serial and the certificate it names, and records what it found in `hwProvision.rootOfTrust`: the reference designator, the unit it found there, and the vendor's record. The board's identity is the root of trust's IDevID key.

This is what lets the buyer catch a swapped part: the buyer's board check compares the unit the EMS's station found at U5 with the unit the A1 record says was placed there, and refuses the board when they differ. The EMS's record carries the station's own reading, not a copy of the A1 record.

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
| `rot-identity` | On a board: the part at the root of trust's reference designator answered with the IDevID key its vendor endorsed for the serial it reported |
| `first-boot-released` | On a board: the board was powered after the last image and fuse were written, and its root of trust released the main device |
| `station-log-passed` | Every row of the unit's last session passed and the session ended |

On a board, `csr-self-signature` and `certificate-endorsed` apply to the root of trust's CSR and its vendor's certificate. The record's subject is the unit or board with its IDevID public key digest, as the spec's [naming rules](../spec/hslsa-v0.1.md#naming-subjects) ask; for a part without an identity it is the serial. A unit that fails a check still gets its record, with the check failed, and `adapt` then exits with an error naming the unit, so a failure is written down rather than left out.

## What the adapter refuses

It signs nothing, and exits with the reason, when:

- the log holds a value for a field the station file calls a secret, or a key id that looks like key material (32 or more hex digits, or a long base64 run);
- a unit of the shipped lot, or a board of the board lot, has no session in the log;
- a board's session has no CSR row for its root of trust;
- a log row programs a region the job does not load, or names an identity file outside the export (a readback dump outside it fails `image-readback` instead);
- the export does not read as the profile describes (a missing column, a time in another format, a job without images).

A unit in the log that is not in the shipped lot, such as one that failed final test, gets no record, and the adapter says so.

## Where the signing key comes from

The adapter signs through one function, `stationSigner`, which opens the key with `LoadSigner`. Since the [HSM signing adapter](hsm-signing.md), that takes a PEM file, a PKCS#11 URI or a `<role>.pkcs11` file, so `--key` can name a key in the HSM the spec requires for a site from L3. `stationSigner` is the one place to change if a station needs anything more; nothing else in the adapter depends on where the key lives.

## Limits

- The stations are simulated. The profiles describe made-up station models, close to what gang and in-circuit programmers log but not any vendor's format. The roadmap's exit criterion, records from a real export without manual editing, needs a real station's export, which waits for a supplier (phase 4). Writing its profile should be the only work.
- The gate is a procedure at the site: it shows the job was cleared before the first write, by the times the station logged. A site that runs a job without the gate gets records whose `image-provenance-verified` check fails, which the buyer's checks refuse.
