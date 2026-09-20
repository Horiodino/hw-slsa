# Proxy signing: suppliers that sign nothing

Suppliers will not sign HSLSA records until a customer requires it. Until then, a chain can still have its real shape: whoever received a supplier's output signs the supplier's record for it, and the record says so. The spec calls that party the step's proxy ([Proxy-signed record](../spec/hslsa-v0.1.md#proxy-signed-record), [Evidence record](../spec/hslsa-v0.1.md#evidence-record)). This is item 4 of phase 2 in the [roadmap](roadmap.md).

This example runs the [PicoRV32 lot](e2e-test.md) again with two suppliers that sign nothing:

| Step | The supplier hands over | Signed by | Record |
| --- | --- | --- | --- |
| Wafer sort | Only paper: a certificate of conformance and a scanned lot traveller | Example OSAT, which received the wafers | Evidence record naming both documents by digest |
| Transfer from sort to the OSAT | Nothing signed | Example OSAT, which received the shipment | Proxy-signed transfer, from the sort house's packing list |
| Final test | Its test data, as an export, but no signature | Example Open Silicon Group, the product owner, which received the shipped lot | Proxy-signed F4, with the export by digest |

The fab and the OSAT sign their own records as in the main example. The lot, its 37 units and its lot digest are the same.

## Run it

```bash
e2e/run.sh produce   # the main example: design records, keys and the self-signed lot
e2e/run.sh proxy     # the same lot with proxies, in out/proxy, checked under both policies
```

The scenario is [`e2e/picorv32/proxy/mfg-scenario.json`](../e2e/picorv32/proxy/mfg-scenario.json): the main scenario plus an `unsigned` block that says which supplier signs nothing and how its step is covered (`proxy` or `evidence`, with the documents). A test checks that the two scenarios differ only there. The policy is [`e2e/picorv32/proxy/policy.json`](../e2e/picorv32/proxy/policy.json).

## What the records say

A proxy-signed record is the step's full record, with the step's own buildType, and:

- `hwMfg.site` is still the supplier, Example Test House;
- `hwMfg.proxy` names the signer (`{"name": "Example Open Silicon Group", ...}`), the reason (`supplier-does-not-sign`) and the supplier's export, `supplier-export-final-test.json`, by digest;
- `runDetails.builder.id` is `urn:hslsa:proxy:example-open-silicon-group`, so a SLSA verifier that reads only the builder does not take it for the test house's own record.

The export is what the supplier handed over: its site, the step's parameters, every `hwMfg` field it reported (yield and checks) and the content of each data file the record names (the per-unit results). The proxy signs exactly that.

The evidence record for wafer sort has buildType `.../mfg/step/evidence@v1`, the two documents as its only subjects, and `hwMfg.evidence` with `covers: wafer-sort` and each document's name, kind (`certificate`, `paper-record`) and issuer. There is no wafer map in the bundle.

## The buyer's check

```
lot receipt check: PASSED for urn:hslsa:lot:ASM-EXAMPLE-17 sha256:4876860b..., 3 received units found in the lot
signed on a supplier's behalf, so their tracks are held at L1:
  wafer-sort: evidence record signed by Example OSAT for Example Sort House
  transfer from wafer-sort: proxy-signed by Example OSAT for Example Sort House
  final-test: proxy-signed by Example Open Silicon Group for Example Test House
  packaging: genealogy checked without wafer maps, since an evidence record stands in for wafer sort
```

On top of the usual lot receipt check, the reference tool:

1. Refuses any record signed on a supplier's behalf unless the policy lists its kind in `manufacturing.acceptOnBehalf` (`proxy`, `evidence` or both). The main example's policy lists neither, so it refuses this lot.
2. Checks the signature against the proxy's own key: the role that signed the next step (`osat-site` for wafer sort, `test-site` for packaging, `sort-site` for wafer fab) or `product-owner` after final test. Which key to use follows from whether the record carries `hwMfg.proxy`, so a proxy that leaves it out is checked against the supplier's key and fails, and a supplier key cannot sign a record that claims a proxy.
3. Checks that `hwMfg.proxy.signer` is the party that received: the site of the next step, the receiver of a transfer, or the HBOM's manufacturer after final test; and that `builder.id` names the proxy.
4. For a proxy-signed record, checks it against the supplier's export: same supplier, step and parameters, every reported field, and every data file byte for byte as JSON.
5. For an evidence record, checks that it covers the step it stands in for, that the step is one evidence may cover (wafer sort only, because every other chip step names a lot that later records bind to), and that its subjects are exactly its documents.
6. Refuses a policy that claims more than L1 for a track with any such record. This lot verifies as `HSLSA_WAFER_LEVEL_1` and `HSLSA_PACKAGE_TEST_LEVEL_1`.

The tamper tests in [`tools/hslsa/proxy_test.go`](../tools/hslsa/proxy_test.go) break each of these: a proxy that hides that it is one, a record signed by a party that did not receive from the supplier, a builder that names the supplier, a proxy that adds a check or changes a result the supplier did not report, a swapped export or document, an evidence record that covers another step or names an undeclared subject, and a policy that claims L2.

## What it does not show

A proxy-signed record proves that the proxy signed what the export says, and an evidence record that the proxy held the documents. Neither proves the supplier wrote them, which is why both hold their track at L1. The export and the documents here are generated from the scenario, as all physical data in the examples is; a real one comes from the supplier's MES or its paperwork. Assembly-track records (distribution records and A1) cannot be proxy-signed in the tool yet.
