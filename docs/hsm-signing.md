# Signing with keys held in an HSM

The spec asks for site keys in an HSM from L3, and for the tapeout authority's and the identity CA's keys to be offline or HSM-held (see [Signing and keys](../spec/hslsa-v0.1.md#signing-and-keys) and item 2, key custody, under [Threat model](../spec/hslsa-v0.1.md#threat-model)). This is the Phase 3 HSM adapter: the reference tool signs with a key that stays inside an HSM, through the HSM's PKCS#11 module. File keys keep working, and nothing in the records or the checks changes.

## Using an HSM key

Every place the tool takes a private key also takes an HSM key, in any of three forms:

- a PKCS#11 URI ([RFC 7512](https://www.rfc-editor.org/rfc/rfc7512)), for example `pkcs11:token=site-a;object=fab-site;type=private?module-path=/usr/lib/softhsm/libsofthsm2.so`;
- a file holding such a URI;
- a `<role>.key.pem` path that does not exist, with a `<role>.pkcs11` file beside it holding the URI. This is how commands that take a keys directory (`mfg`, the programming stations) find a site's key, so moving one site's key into an HSM changes no scenario and no command line.

The URI names the token by `token=` (or `serial=` or `slot-id=`) and the key by `object=` (its label) or `id=`. The module comes from `module-path=` or `HSLSA_PKCS11_MODULE`, and the user PIN from `pin-source=` (a file), `pin-value=` or `HSLSA_PKCS11_PIN`. Keep the PIN out of the URI: `<role>.pkcs11` files are not secret, and keygen never writes a PIN into one.

To make keys for some roles on a token:

```sh
export HSLSA_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so HSLSA_PKCS11_PIN=...
hslsa hsm keygen --token site-a --out keys fab-site sort-site
```

This generates an ECDSA P-256 pair per role on the token, labelled with the role, with the private half marked sensitive, not extractable and for signing only. It writes `keys/<role>.pkcs11` and `keys/<role>.pub.pem`, prints each role's DSSE key id, and refuses a role that already has a key on the token. `hslsa trust-root`, `pubkey` and `keyid` take the results like any other key.

## What the tool checks when it opens an HSM key

- Exactly one EC private key on exactly one token matches the URI.
- The HSM marks the key `CKA_SENSITIVE` and not `CKA_EXTRACTABLE`. A key the HSM would hand out is refused, since it gives none of the protection L3 asks the HSM for.
- The key may sign, and a public key object with the same label and id exists. The tool signs a probe with the private key and checks it with that public key, so a mismatched pair fails when it is opened, not at the buyer.

Signing asks the HSM for a raw ECDSA signature (`CKM_ECDSA`) over the hash the key's scheme uses, so DSSE envelopes, signed blobs, S.A.F.E. reports (JWS and COSE) and CoRIMs come out exactly as with a file key. The one exception is the SSH-signed git tag (`design source-tag`): git hands `ssh-keygen` a key file, so the source owner's key stays a file there.

PKCS#11 needs cgo, which `go build` uses by default where a C compiler is installed. A binary built with `CGO_ENABLED=0` still signs with file keys and says why it cannot open an HSM key.

## What the buyer can and cannot see

A signature made in an HSM looks like any other. The records cannot show that a key is HSM-held, just as they cannot show who operates it, so the buyer establishes custody before listing the key in its trust root: from the site's accreditation, an audit, or the HSM vendor's key attestation where the HSM offers one. An HSM stops a key from being copied, not from being misused by the people allowed to use it.

## Tests

- [`tools/hslsa/pkcs11_test.go`](../tools/hslsa/pkcs11_test.go) runs against SoftHSM2. It generates keys with `HSMKeygen`, finds them through each of the three forms, signs a DSSE record that the trust root accepts (and another key's trust root refuses), a signed blob, S.A.F.E. reports in both forms and a CoRIM, and checks the refusals: an extractable key, a key that is not sensitive, a public key object from another pair, a second keygen for a role, a missing PIN, an unknown key, token or module. It also checks that a `<role>.key.pem` file wins over a `<role>.pkcs11` beside it. The tests skip without SoftHSM2, except in CI, which sets `HSLSA_REQUIRE_PKCS11`.
- `e2e/run.sh hsm` runs after `produce`. It puts the tapeout authority's, every manufacturing site's and the product owner's keys on a throwaway SoftHSM2 token, replaces each `<role>.key.pem` with a `<role>.pkcs11`, rebuilds the trust root, signs the release, the lot and the HBOM again with the same commands, runs the tapeout and lot receipt checks, and confirms each record carries the HSM key's signature. Set `HSLSA_PKCS11_TOKEN` (with the module and PIN variables) to run it against a real HSM instead.

Both run in the `produce` job of the HSLSA end-to-end workflow.
