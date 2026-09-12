# End-to-end test

The workflow in [`.github/workflows/hslsa-e2e.yml`](../.github/workflows/hslsa-e2e.yml) builds one attestation chain from RTL to a shipped lot, checks it the way a buyer would, and hands the result to the official [slsa-verifier](https://github.com/slsa-framework/slsa-verifier). It runs on every pull request and every push to `main`. The same workflow then builds a board on the shipped chips and checks it; see [board-example.md](board-example.md).

## What runs

| Job | Plays | Does |
| --- | --- | --- |
| Lint and unit tests | | `gofmt`, `go vet` and `go test` (bundle-free tests only), validates the committed HBOM examples against their schema, and checks the example's lot digest can be recomputed from its unit list |
| Produce | Design house, tapeout authority, fab, sort house, OSAT, test house, product owner | Runs the design flow, signs each step, releases the design, signs F1 to F4 for a lot, builds and signs the HBOM. Uploads the bundle without any private key |
| Verify | Buyer | Receives only the bundle, runs the tapeout check and the lot receipt check, signs two SLSA Verification Summary Attestations, verifies them with slsa-verifier v2.7.1, then runs the tamper tests |

**Real:** the design is [PicoRV32](https://github.com/YosysHQ/picorv32) at a pinned commit, with every file checked against [`e2e/picorv32/inputs.lock.json`](../e2e/picorv32/inputs.lock.json). Step 1 runs its testbench in Icarus Verilog and step 2 synthesizes it with Yosys; the netlist is byte-for-byte reproducible. Every signature, digest link and check is real, and the verifier uses the in-toto attestation library to validate every statement and to parse every step predicate as SLSA Provenance v1.

**Simulated:** there is no fab, so wafer maps, genealogy and test results come from [`e2e/picorv32/mfg-scenario.json`](../e2e/picorv32/mfg-scenario.json). The scenario packages 40 units and fails 3 at final test, which gives exactly the shipped lot in [`hbom/picosoc-sky130.shipped-lot.txt`](../hbom/picosoc-sky130.shipped-lot.txt), so the lot digest matches the spec's worked example.

**Not run yet:** design steps 3 to 7 (floorplan to GDS stream-out) need OpenROAD and a PDK. Until they run, the release subject is the gate-level netlist standing in for the final GDS.

## Levels claimed

The verifier only emits VSAs when every check passes, and it claims the levels in [`e2e/picorv32/policy.json`](../e2e/picorv32/policy.json):

| VSA subject | `verifiedLevels` |
| --- | --- |
| Released design (netlist digest) | `HSLSA_DESIGN_LEVEL_1`, `SLSA_BUILD_LEVEL_1` |
| Shipped lot (`urn:hslsa:lot:ASM-EXAMPLE-17`, lot digest) | `HSLSA_WAFER_LEVEL_2`, `HSLSA_PACKAGE_TEST_LEVEL_2`, `HSLSA_DESIGN_LEVEL_1` |

Design stops at L1 even though the flow platform signs every step, because Design L2 also needs a signed, reviewed source-freeze tag and signed provenance for third-party IP, and PicoRV32 has neither. Wafer and Package/Test reach L2 because each site signs with its own key, units are named with genealogy, and final test signs the shipped lot digest.

## What the tamper tests prove

[`tools/hslsa/e2e_test.go`](../tools/hslsa/e2e_test.go) breaks the chain in 24 ways and requires each to fail for the stated reason. The fixture re-signs the bundle with test keys so it can also forge records with valid signatures, which is what an insider at one site could do:

- files swapped after signing (netlist, source archive, simulation log, wafer maps, genealogy), a unit added to the shipped lot, a received unit that was scrapped at final test
- a missing step, a payload edited without re-signing, a step signed by an unknown key, a release signed by the flow platform instead of the tapeout authority, a record copied from another site
- validly signed lies: a failed gate, an unapproved tool, a step that does not consume the frozen source, a release of an artifact the flow did not build, a packaging record that names another design, a yield record that hides a failed unit, an HBOM that names another lot or does not match its schema

The verify job also runs slsa-verifier four times expecting failure: a level above the claim, an SLSA build level above the claim, another subject's digest, and another verifier's key.

## Keys and privacy

Nothing is uploaded to a transparency log. Signatures are DSSE envelopes with ECDSA P-256 keys (securesystemslib), no job requests an OIDC token, and nothing contacts Sigstore. This follows the spec's rule that L3 transparency logs may be private.

Producer keys are generated per run and never leave the produce job; the buyer gets their public halves in `trust-root.json`. In this test the trust root travels with the bundle, which is fine for a test but not for a buyer: a real buyer pins the trust root before receiving anything.

The VSA signing key is the one outsiders would check. Without a secret, the verify job uses a new key each run. To make it stable:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out verifier.key.pem
openssl pkey -in verifier.key.pem -pubout -out verifier.pub.pem
```

Add the private key as the repository secret `HSLSA_VSA_SIGNING_KEY`, commit or publish `verifier.pub.pem`, and delete the local private key.

## Checking a VSA yourself

Download the `hslsa-vsa` artifact from a run, then:

```sh
slsa-verifier verify-vsa \
  --attestation-path lot.vsa.intoto.json \
  --subject-digest sha256:4876860b247bffbd0ceedf5bb53d278f9a25251619cd68dee4d740a4c73cbaf1 \
  --resource-uri urn:hslsa:lot:ASM-EXAMPLE-17 \
  --verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1 \
  --verified-level HSLSA_PACKAGE_TEST_LEVEL_2 \
  --public-key-path verifier.pub.pem \
  --public-key-id "$(go run ./tools/hslsa/cmd/hslsa keyid --key verifier.pub.pem)"
```

## Running it locally

Needs Go (the version in [`go.mod`](../go.mod)), Yosys, Icarus Verilog and a slsa-verifier binary. The scripts build the reference tool into `bin/hslsa`; set `HSLSA` to use a binary you built yourself.

```sh
SLSA_VERIFIER=/path/to/slsa-verifier e2e/run.sh all
go test ./...
```

## Moving to public Sigstore later

If the repository goes public, or keyless signing is otherwise acceptable, the change is small:

1. Add a job that calls `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml` with the released netlist (later the GDS) as its subject, and check it with `slsa-verifier verify-artifact --source-uri github.com/Horiodino/hw-slsa`. That proves SLSA Build L3 for the design flow platform; the HSLSA records stay as they are.
2. Optionally sign the HSLSA envelopes keylessly too, and have `TrustRoot` match Fulcio certificate identities (workflow path and repository) instead of public keys.

Both upload to Sigstore's public Rekor log, which permanently publishes the repository name, workflow path and commit. The generator's `private-repository: true` input exists to acknowledge that; it should only be set by the repository owner's decision.
