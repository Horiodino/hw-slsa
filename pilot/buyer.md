# The buyer's steps

You run the trust root, write the policy, and check every lot before you accept it. Everything here runs offline with the `hslsa` binary from the kit (or `go run ./tools/hslsa/cmd/hslsa` from the repository).

## 1. Your root key

```sh
hslsa keygen --out buyer buyer-root
```

`buyer/buyer-root.key.pem` signs every enrollment and revocation, so keep it where you keep other signing keys that gate production: an HSM is best. `hslsa hsm keygen --token <label> --out buyer buyer-root` makes it non-extractable on a PKCS#11 token, and every command below accepts the `buyer-root.pkcs11` file it writes in place of the `.pem` ([hsm-signing.md](../docs/hsm-signing.md)). Only `buyer/buyer-root.pub.pem` goes to your verifiers.

## 2. Enroll each key you accept

Each company sends you the public half of every key it signs with, one key per role. Check each key with the company over a second channel before you enroll it: read the fingerprint back by phone, attend the key ceremony, or check the HSM vendor's key attestation. `hslsa keyid --key <pub>` prints the fingerprint to read back.

```sh
hslsa pilot enroll --buyer-key buyer/buyer-root.key.pem \
  --pub osat-test-site.pub.pem --role test-site \
  --org-name "Example OSAT Group" --org-id duns:100000003 \
  --site "Example Test House" --country US --custody hsm \
  --not-after 2027-03-31 \
  --note "fingerprint read back by phone to the site's security lead on 2026-10-14" \
  --out enrollments/osat-test-site.intoto.json
```

The roles in this pilot:

| Company | Roles | What they sign |
| --- | --- | --- |
| RoT vendor | `source-owner`, `source-reviewer`, `flow-platform`, `tapeout-authority` | The design records the tapeout check reads (Design L2, as the vendor already runs it) |
| RoT vendor | `ip-vendor`, or the IP vendor itself | Provenance of third-party IP in the design |
| RoT vendor | `firmware-platform`, `code-signer`, `identity-ca` | Firmware provenance and CoRIM; the firmware signature its ROM checks; unit identity certificates |
| RoT vendor | `product-owner` | The HBOM |
| OSAT group | `sort-site`, `osat-site`, `test-site` | Wafer sort (and the foundry's record on its behalf), assembly, final test, and the transfers between them; `test-site` also signs the provisioning records from the station at final test |

Use the organization identifier you already hold for the company (LEI, DUNS, CAGE, UEI or GLN). `--custody` is what the company showed you, `hsm` or `file`; Package/Test L3 needs `hsm`, L2 does not. `--not-after` is when you want to see the key again: a quarter or a pilot's length is a reasonable default.

To withdraw a key, for example one the company reports lost:

```sh
hslsa pilot revoke --buyer-key buyer/buyer-root.key.pem --pub osat-test-site.pub.pem \
  --reason "key reported lost by the site" --out enrollments/revoke-osat-test-site.intoto.json
```

A revoked key counts for nothing it ever signed, earlier records included, since a compromised key can sign any date. Lots you already accepted keep the VSAs you signed for them.

## 3. Build the trust root, at every receipt

```sh
hslsa pilot trust-root --buyer-pub buyer/buyer-root.pub.pem --enrollments enrollments --out trust-root.json
```

It prints every key it trusts and every key it leaves out, and why (revoked, expired, not yet valid). It stops on any file in `enrollments/` that your root key did not sign, and on one key enrolled for two roles or two companies. The result carries `validUntil`, the end of its first enrollment to expire, and the verifier refuses it after that, so rebuild it for each receipt rather than keeping one.

## 4. Your policy

Start from [`e2e/pilot/policy.json`](../e2e/pilot/policy.json) and change the design section to the vendor's flow. What it asks for:

| Field | Value in the pilot | Why |
| --- | --- | --- |
| `claims.lot` | `HSLSA_WAFER_LEVEL_1`, `HSLSA_PACKAGE_TEST_LEVEL_2`, `HSLSA_DESIGN_LEVEL_2` | Package/Test is what the OSAT signs; Wafer stays at L1 because the foundry's record is proxy-signed |
| `manufacturing.acceptOnBehalf` | `["proxy"]` | Accept the foundry's record signed by the sort site from the foundry's own export ([proxy signing](../docs/proxy-signing.md)) |
| `manufacturing.requireExports` | `true` | Every chip record carries the export it was made from, and the check reads it again ([MES and STDF adapter](../docs/mes-stdf-adapter.md)) |
| `manufacturing.requireTransfers` | `true` | Every shipment between sites is a signed record |
| `firmware.provisioningSigner` | `test-site` | For the root of trust part's provisioning records, in the board policy (see [the FPGA example's](../e2e/fpga/rot/policy.json)) |

## 5. Check each lot before accepting it

The vendor hands you the lot's bundle (records and the data files they name) with the parts, and you list the serials or identity digests of the units you received.

```sh
hslsa verify --bundle lot --trust-root trust-root.json --policy policy.json --units received.txt \
  --vsa-key verifier.key.pem --vsa-out vsa
```

For the board with the root of trust on it, the board check runs the part's own chain, its Firmware L2 check and each unit's provisioning record, then the at-boot check on the boards you power on ([FPGA board example](../docs/fpga-board-example.md#what-the-buyer-checks)):

```sh
hslsa fpga verify --bundle board --trust-root trust-root.json --policy policy.json \
  --boards received-boards.txt --boots boots --vsa-key verifier.key.pem --vsa-out vsa
```

The board check reads the root of trust part's trust root from inside the bundle (`parts/<part>/trust-root.json`), and the board's from `trust-root.json` and `design/trust-root.json`. Replace all of them with trust roots you built from your own enrollments before you run it, as `e2e/pilot/run.sh board` does: a trust root that arrives in the supplier's bundle is the supplier's word about whose keys to trust, not yours.

For a Caliptra part, the at-boot check reads each unit's DICE certificates and appraises its measurements against the vendor's CoRIM ([Caliptra example](../docs/caliptra-e2e.md#the-at-boot-check)). In your fleet, the same appraisal runs in whatever RATS verifier you already have: `hslsa corim appraise` shows what it checks.

The VSAs `verify` signs are ordinary SLSA verification summaries; `slsa-verifier verify-vsa` checks them, as each example's `run.sh` does.

## 6. Measure every lot

```sh
hslsa pilot measure --bundle lot --trust-root trust-root.json --policy policy.json \
  --units received.txt --costs costs.json --out report
```

It writes `report/<lot>.json` and `.md` and rewrites `report/summary.md` across every lot measured there. A lot that fails its check still gets its report, with the failed check, and the command exits with an error so a script stops. Ask each party to fill `costs.json` per lot, in the shape of [`e2e/pilot/costs.json`](../e2e/pilot/costs.json): hours, and money where they are willing to share it. The report also lists, per company, which record fields you now hold and whether a record names a site other than the one its key is enrolled for.
