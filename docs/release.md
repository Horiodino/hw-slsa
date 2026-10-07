# Releases and the container image

[`.github/workflows/release.yml`](../.github/workflows/release.yml) makes a release from one tag. It runs every test the repository has, then publishes three things: the signed pilot kit, the `hslsa` container image on GitHub Container Registry (GHCR), and a GitHub release that lists both.

## Making a release

1. Merge everything the release should carry into `main`.
2. Tag the commit and push the tag:

   ```sh
   git tag v0.1.0-pilot.2 origin/main
   git push origin v0.1.0-pilot.2
   ```

   `make release VERSION=v0.1.0-pilot.2` does the same: it refuses a tag that exists or is not a `v*` version, shows the commit, and asks before it pushes.

   Creating the tag in GitHub's **Releases > Draft a new release** also works. If the workflow does not start on its own, run it by hand: **Actions > Release > Run workflow**, with "Use workflow from" set to the tag. When the release already exists, the workflow adds its files to it instead of creating a new one.
3. The workflow runs the four test workflows on the tagged commit: the end-to-end test (lint, unit tests, the PicoRV32 chain, the board example, verifier escrow), the FPGA board example, the OpenLane 2 flow with its rebuild, and the Caliptra example. It publishes only if all four pass.

A tag with a hyphen, such as `v0.1.0-pilot.2`, is marked as a pre-release.

Run from a branch instead of a tag, the workflow is a dry run: the same tests, a kit signed with a throwaway key and checked, the image built and run locally, and nothing published. A pull request that changes the release files runs the dry run without the tests, since the tests run on the pull request anyway.

`make release-dry-run` runs the same dry run on your machine (the kit and the image; `make e2e` runs the tests), and `make version` and `make labels` print the version, commit, spec revision and image labels a release from your checkout would carry.

## The kit key

The kit is signed with the owner's kit key, from the repository secret `HSLSA_KIT_KEY`: the PEM text of the private key, as `hslsa keygen --out <dir> kit-signer` writes it.

- With the secret set, the release carries the kit, its signature, its provenance and the public key. It also carries `hslsa-image.provenance.json`, which signs the image's digest with the same key, so anyone who checked the key can pull exactly that image.
- Without it, the release carries the image only, and the workflow warns. The owner can then build and sign the kit on their own machine with [`pilot/make-kit.sh`](../pilot/make-kit.sh) and attach it by hand. This keeps the key off GitHub entirely.

Either way, send the public key's sha256 (printed in the release notes) to each recipient over a second channel.

## The container image

The image is `ghcr.io/horiodino/hw-slsa`, tagged with the release tag, for `linux/amd64` and `linux/arm64`. It holds only the static `hslsa` binary, its licenses, and the spec, pilot docs and pilot templates under `/usr/share/hslsa`. There is no shell. It runs as an unprivileged user in `/work`, so mount the files it should read or write there:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/horiodino/hw-slsa:v0.1.0-pilot.2 \
  verify --bundle lot --trust-root trust-root.json --policy policy.json --units received.txt
```

Pull it by the digest in the release notes (`ghcr.io/horiodino/hw-slsa@sha256:...`) rather than by tag, since a tag can be moved. The per-platform tags (`<tag>-linux-amd64`, `<tag>-linux-arm64`) are what the multi-platform tag is built from.

Commands that drive other tools (`hslsa design` steps that run a simulator or Yosys, `hslsa openlane run`, `hslsa eda run`, the FPGA and Caliptra examples) need those tools, so they do not run in this image. Signing with an HSM needs a cgo build, as in [hsm-signing.md](hsm-signing.md). Everything a buyer runs (`verify`, `board verify`, `fpga verify`, `pilot`, `kit verify`, `render`, `corim`, `safe check`) and everything a supplier signs with file keys does.

## Who can pull it

This repository is private, so the image is a private package too, and nothing is public. The workflow links the package to the repository, so by default everyone who can read the repository can pull the image.

To give someone else access, such as a pilot vendor:

1. Open the package: the repository's page, **Packages > hw-slsa > Package settings**.
2. Under **Manage access**, add their GitHub account or organization with the **Read** role.
3. They log in with a personal access token (classic) that has the `read:packages` scope, then pull:

   ```sh
   echo "$TOKEN" | docker login ghcr.io -u <their-github-login> --password-stdin
   docker pull ghcr.io/horiodino/hw-slsa@sha256:...
   ```

Access to the package does not give access to the repository. Making the package public is a separate switch in the same settings; leave it off while the repository is private.
