# End-to-end test

The workflow in [`.github/workflows/hslsa-e2e.yml`](../.github/workflows/hslsa-e2e.yml) builds one attestation chain from RTL to a shipped lot, checks it the way a buyer would, and hands the result to the official [slsa-verifier](https://github.com/slsa-framework/slsa-verifier). It runs on every pull request and every push to `main`. The same workflow then builds a board on the shipped chips and checks it; see [board-example.md](board-example.md).

## What runs

| Job | Plays | Does |
| --- | --- | --- |
| Lint and unit tests | | `gofmt`, `go vet` and `go test` (bundle-free tests only), validates the committed HBOM examples against their schema, checks their committed CycloneDX and SPDX renderings, and checks the example's lot digest can be recomputed from its unit list |
| Produce | IP vendor, design lead, reviewer, flow platform, tapeout authority, fab, sort house, OSAT, test house, product owner | Signs the IP provenance, the source tag and its review, runs the design flow, signs each step, releases the design, signs F1 to F4 for a lot and the three transfers between the four sites, builds the HBOM, renders it as CycloneDX 1.6 and SPDX 3.1-RC1 and signs it with both renderings listed by digest, and signs the lot again with fields withheld for the escrow job. Uploads the bundles without any private key |
| Verify | Buyer | Receives only the bundle, runs the tapeout check and the lot receipt check, then re-renders the HBOM and requires its two renderings byte for byte, signs two SLSA Verification Summary Attestations, verifies them with slsa-verifier v2.7.1, validates the chip and board CycloneDX renderings with the CycloneDX project's `cyclonedx` CLI, then runs the tamper tests |
| Escrow | Auditor, then buyer | The auditor receives the same lot re-signed with confidential fields withheld, plus their disclosures, checks it for the buyer's units and signs two VSAs; the buyer checks only those VSAs, with slsa-verifier. Then measures what the records and the VSAs reveal. See [selective-disclosure.md](selective-disclosure.md) |

**Real:** the design is [PicoRV32](https://github.com/YosysHQ/picorv32) at a pinned commit, with every file checked against [`e2e/picorv32/inputs.lock.json`](../e2e/picorv32/inputs.lock.json). Step 1 runs its testbench in Icarus Verilog and step 2 synthesizes it with Yosys; the netlist is byte-for-byte reproducible. Every signature, digest link and check is real, and the verifier uses the in-toto attestation library to validate every statement and to parse every step predicate as SLSA Provenance v1.

**Design L2 inputs:** the design house vendors PicoRV32 into its own RTL repository, which exists only inside the produce job and has no public URL. Three parties sign, each with its own key:

- The IP vendor signs SLSA Provenance v1 (buildType `.../ip-release@v1`) for the IP release, with `picorv32.v` as its subject. YosysHQ does not publish signed provenance, so an `ip-vendor` key plays that part, the same way site keys play the fab and test house.
- The design lead commits the RTL and signs a release tag with git's own SSH signing (`gpg.format=ssh`, `git tag -s`). The tag, commit and tree objects go into the bundle under `artifacts/source-git/`.
- A reviewer who is not the commit's author signs a `source-review` record (`https://github.com/Horiodino/hw-slsa/source-review/v0.1`) whose subject is the tagged commit.

The source freeze step checks all three before it signs, records the results as the gates `signed-reviewed-tag` and `third-party-ip-provenance`, and lists the tagged commit, the review and the IP provenance in its `resolvedDependencies`. The buyer's tapeout check repeats every check itself instead of trusting those gates: it verifies the SSH signature on the tag against the `source-owner` key in the trust root, recomputes git's object hashes from the tag through the commit and tree down to every file in `source.tar`, opens the review and IP records under their own roles, and requires the IP files in the archive to match the vendor's subjects. So a flow platform that swaps RTL under the tag is caught even though it signs its own record. Git names objects with SHA-1; that is what the tag signs, and a SHA-256 git repository would remove that weakness.

The release record lists the IP blocks, and the verifier refuses a Design L2 claim unless the policy requires signed provenance for every one of them and a signed, reviewed tag. The example has no waivers, so the L2 rule that waivers are signed by a signoff owner is not exercised.

**Simulated:** there is no fab, so wafer maps, genealogy and test results come from [`e2e/picorv32/mfg-scenario.json`](../e2e/picorv32/mfg-scenario.json). The scenario packages 40 units and fails 3 at final test, which gives exactly the shipped lot in [`hbom/picosoc-sky130.shipped-lot.txt`](../hbom/picosoc-sky130.shipped-lot.txt), so the lot digest matches the spec's worked example. Each site also signs a [transfer](../spec/hslsa-v0.1.md#transfers-between-manufacturing-sites) for what it ships to the next (the wafers from fab to sort and from sort to the OSAT, the packaged units from the OSAT to the test house), and the policy sets `manufacturing.requireTransfers`, so the lot receipt check needs all three.

**Not run yet:** design steps 3 to 7 (floorplan to GDS stream-out) need OpenROAD and a PDK. Until they run, the release subject is the gate-level netlist standing in for the final GDS.

## Levels claimed

The verifier only emits VSAs when every check passes, and it claims the levels in [`e2e/picorv32/policy.json`](../e2e/picorv32/policy.json):

| VSA subject | `verifiedLevels` |
| --- | --- |
| Released design (netlist digest) | `HSLSA_DESIGN_LEVEL_2`, `SLSA_BUILD_LEVEL_2` |
| Shipped lot (`urn:hslsa:lot:ASM-EXAMPLE-17`, lot digest) | `HSLSA_WAFER_LEVEL_2`, `HSLSA_PACKAGE_TEST_LEVEL_2`, `HSLSA_DESIGN_LEVEL_2` |

Design reaches L2: every step runs on GitHub Actions and is signed by the flow platform's key, the source freeze is a signed, reviewed tag, and the one third-party IP block arrives with signed provenance. It stops short of L3 because the steps are not isolated from each other or the network, the signing key is reachable from the job that runs the tools, and there is no equivalence record. Wafer and Package/Test reach L2 because each site signs with its own key, units are named with genealogy, and final test signs the shipped lot digest.

## What the tamper tests prove

[`tools/hslsa/e2e_test.go`](../tools/hslsa/e2e_test.go) breaks the chain in 25 ways, and [`tools/hslsa/source_test.go`](../tools/hslsa/source_test.go) in 15 more for the Design L2 inputs, and [`tools/hslsa/transfer_test.go`](../tools/hslsa/transfer_test.go) in 6 more for the transfers and the gap report, and each must fail for the stated reason. [`tools/hslsa/escrow_test.go`](../tools/hslsa/escrow_test.go) and [`tools/hslsa/disclose_test.go`](../tools/hslsa/disclose_test.go) break withheld fields, disclosures and escrow VSAs; see [selective-disclosure.md](selective-disclosure.md#tests). The fixture re-signs the bundle with test keys so it can also forge records with valid signatures, which is what an insider at one site could do:

- files swapped after signing (netlist, source archive, simulation log, wafer maps, genealogy), a unit added to the shipped lot, a received unit that was scrapped at final test
- a missing step, a payload edited without re-signing, a step signed by an unknown key, a release signed by the flow platform instead of the tapeout authority, a record copied from another site
- the Design L2 inputs: a tag signed by an unknown key or edited after signing, a validly signed tag that points at another commit, a source archive that is not the tagged tree (re-signed by the flow platform), a review signed by an unknown key, of another commit, not approving, or by the commit's author, a source freeze that does not consume the review, IP provenance that is missing, signed by the design house instead of the vendor, or for other file contents, and a policy that claims Design L2 without the source or IP rules
- the transfers: one missing, several records missing at once (the check names all of them with their tracks), a transfer signed by the receiving site, one shipped to a site that did not sign the next step, a packing list that swaps a unit, and a step that links past its transfer to the step before
- validly signed lies: a failed gate, a record whose `hwFlow.step` is not the step it claims to be, an unapproved tool, a step that does not consume the frozen source, a release of an artifact the flow did not build, a packaging record that names another design, a yield record that hides a failed unit, an HBOM that names another lot or does not match its schema
- the HBOM renderings: one edited after signing, one missing, one listed outside the bundle, and a CycloneDX rendering put where the SPDX one should be ([`tools/hslsa/render_test.go`](../tools/hslsa/render_test.go), which also checks that every HBOM field reaches both formats and that the official schemas reject bad renderings)

The verify job also runs slsa-verifier four times expecting failure: a level above the claim, an SLSA build level above the claim (L3), another subject's digest, and another verifier's key.

## HBOM renderings

The HBOM is also written as a CycloneDX 1.6 BOM (`att/hbom.cdx.json`) and an SPDX 3.1-RC1 document (`att/hbom.spdx.json`), so SBOM tools can read it; the spec's [Renderings](../spec/hslsa-v0.1.md#renderings) section has the rules and the field mapping. The product owner renders the HBOM before signing it and lists both files in `renderings[]` by digest. The renderings are of the HBOM as signed: in the escrow bundle they leave out the withheld fields too. After the tapeout and lot receipt checks pass, the buyer's check re-renders the signed HBOM and requires both files byte for byte; it comes last because the renderings are derived from the HBOM, so a broken record is reported as itself.

`hslsa render` does the same for any HBOM statement or envelope. It does not check the envelope's signature, so verify the HBOM first:

```sh
hslsa render --hbom out/bundle/att/hbom.intoto.json --format cyclonedx --out hbom.cdx.json
hslsa render --hbom out/bundle/att/hbom.intoto.json --format spdx --out hbom.spdx.json
hslsa render --hbom out/bundle/att/hbom.intoto.json --check out/bundle/att/hbom.spdx.json
```

The creation time is `--created`, else `SOURCE_DATE_EPOCH`, else now; `--check` reads it from the file it checks. Every rendering passes the format's official JSON Schema before it is written ([`hbom/formats/`](../hbom/formats/README.md)).

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

Needs Go (the version in [`go.mod`](../go.mod)), git, ssh-keygen (OpenSSH 8.2 or later, for SSH-signed tags), Yosys, Icarus Verilog and a slsa-verifier binary. The scripts build the reference tool into `bin/hslsa`; set `HSLSA` to use a binary you built yourself.

```sh
SLSA_VERIFIER=/path/to/slsa-verifier e2e/run.sh all
go test ./...
```

## Moving to public Sigstore later

If the repository goes public, or keyless signing is otherwise acceptable, the change is small:

1. Add a job that calls `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml` with the released netlist (later the GDS) as its subject, and check it with `slsa-verifier verify-artifact --source-uri github.com/Horiodino/hw-slsa`. That proves SLSA Build L3 for the design flow platform; the HSLSA records stay as they are.
2. Optionally sign the HSLSA envelopes keylessly too, and have `TrustRoot` match Fulcio certificate identities (workflow path and repository) instead of public keys.

Both upload to Sigstore's public Rekor log, which permanently publishes the repository name, workflow path and commit. The generator's `private-repository: true` input exists to acknowledge that; it should only be set by the repository owner's decision.
