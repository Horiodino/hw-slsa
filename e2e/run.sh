#!/usr/bin/env bash
# End-to-end HSLSA test for the PicoRV32 example.
#
#   e2e/run.sh produce   run the design flow and the simulated lot, sign every record
#   e2e/run.sh verify    check the chain, emit VSAs, verify them with slsa-verifier
#
# Nothing here uploads to a transparency log: every signature is a DSSE
# envelope made with a local ECDSA P-256 key.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
E2E=$ROOT/e2e/picorv32
OUT=${OUT:-$ROOT/out}
BUNDLE=$OUT/bundle
KEYS=$OUT/keys
# The Go reference tool; set HSLSA to use a prebuilt binary instead of building it here.
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

produce() {
  rm -rf "$BUNDLE" "$KEYS"
  mkdir -p "$BUNDLE" "$KEYS"
  # One key per party. In a real chain each lives with its own site; here they are
  # generated per run and only their public halves leave this job.
  hslsa keygen --out "$KEYS" ip-vendor source-owner source-reviewer flow-platform tapeout-authority fab-site sort-site osat-site test-site product-owner
  mkdir -p "$KEYS/pub" && cp "$KEYS"/*.pub.pem "$KEYS/pub/"
  hslsa trust-root --keys "$KEYS/pub" --out "$BUNDLE/trust-root.json"
  cp "$E2E/policy.json" "$BUNDLE/policy.json"

  # Design L2 inputs, each from its own party: the IP vendor's provenance, the
  # design lead's SSH-signed git tag, and the reviewer's approval of that commit.
  hslsa design ip-release    --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/ip-vendor.key.pem" --cache "$OUT/cache"
  hslsa design source-tag    --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/source-owner.key.pem" --cache "$OUT/cache"
  hslsa design review        --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/source-reviewer.key.pem"
  hslsa design source-freeze --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem" --cache "$OUT/cache" \
    --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json"
  hslsa design simulation    --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem"
  hslsa design synthesis     --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem"
  hslsa design release       --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/tapeout-authority.key.pem" \
    --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json"
  hslsa mfg  --bundle "$BUNDLE" --scenario "$E2E/mfg-scenario.json" --keys "$KEYS"
  hslsa hbom --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --scenario "$E2E/mfg-scenario.json" --key "$KEYS/product-owner.key.pem"
}

expect_fail() {
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: slsa-verifier accepted $what" >&2
    exit 1
  fi
  echo "ok: slsa-verifier rejects $what"
}

verify() {
  local vsa_dir=$OUT/vsa vkey=$OUT/verifier-key
  rm -rf "$vsa_dir" "$vkey" && mkdir -p "$vsa_dir" "$vkey"
  if [[ -n "${HSLSA_VSA_SIGNING_KEY:-}" ]]; then
    echo "VSA signing key: repository secret HSLSA_VSA_SIGNING_KEY"
    (umask 077 && printf '%s\n' "$HSLSA_VSA_SIGNING_KEY" > "$vkey/verifier.key.pem")
  else
    echo "VSA signing key: ephemeral (set the HSLSA_VSA_SIGNING_KEY secret for a stable key)"
    hslsa keygen --out "$vkey" verifier
  fi
  hslsa pubkey --key "$vkey/verifier.key.pem" --out "$vsa_dir/verifier.pub.pem"

  hslsa verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json" \
    --units "$E2E/received-units.txt" --vsa-key "$vkey/verifier.key.pem" --vsa-out "$vsa_dir"

  local sv=${SLSA_VERIFIER:-slsa-verifier}
  local keyid final lot
  keyid=$(hslsa keyid --key "$vsa_dir/verifier.pub.pem")
  final=$(hslsa subject "$vsa_dir/design.vsa.intoto.json")
  lot=$(hslsa subject "$vsa_dir/lot.vsa.intoto.json")
  local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                --public-key-path "$vsa_dir/verifier.pub.pem" --public-key-id "$keyid")

  echo "== slsa-verifier verify-vsa: design"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/design.vsa.intoto.json" \
    --subject-digest "sha256:${final#* }" --resource-uri "hslsa:design:${final% *}" \
    --verified-level HSLSA_DESIGN_LEVEL_2 --verified-level SLSA_BUILD_LEVEL_2
  echo "== slsa-verifier verify-vsa: shipped lot"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/lot.vsa.intoto.json" \
    --subject-digest "sha256:${lot#* }" --resource-uri "${lot% *}" \
    --verified-level HSLSA_WAFER_LEVEL_2 --verified-level HSLSA_PACKAGE_TEST_LEVEL_2 --verified-level HSLSA_DESIGN_LEVEL_2

  echo "== slsa-verifier negative cases"
  local lotargs=("${common[@]}" --attestation-path "$vsa_dir/lot.vsa.intoto.json" --resource-uri "${lot% *}")
  expect_fail "a level the lot was not verified at" "$sv" verify-vsa "${lotargs[@]}" \
    --subject-digest "sha256:${lot#* }" --verified-level HSLSA_PACKAGE_TEST_LEVEL_3
  expect_fail "a different lot digest" "$sv" verify-vsa "${lotargs[@]}" \
    --subject-digest "sha256:${final#* }" --verified-level HSLSA_WAFER_LEVEL_2
  expect_fail "an SLSA build level above the claim" "$sv" verify-vsa "${common[@]}" \
    --attestation-path "$vsa_dir/design.vsa.intoto.json" --subject-digest "sha256:${final#* }" \
    --resource-uri "hslsa:design:${final% *}" --verified-level SLSA_BUILD_LEVEL_3
  hslsa keygen --out "$vkey/other" verifier
  hslsa pubkey --key "$vkey/other/verifier.key.pem" --out "$vkey/other.pub.pem"
  expect_fail "a VSA checked against another verifier's key" "$sv" verify-vsa \
    --verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1 \
    --public-key-path "$vkey/other.pub.pem" --public-key-id "$keyid" \
    --attestation-path "$vsa_dir/lot.vsa.intoto.json" --resource-uri "${lot% *}" --subject-digest "sha256:${lot#* }" --verified-level HSLSA_WAFER_LEVEL_2
  rm -rf "$vkey"
}

case "${1:-}" in
  produce) produce ;;
  verify) verify ;;
  all) produce; verify ;;
  *) echo "usage: $0 produce|verify|all" >&2; exit 2 ;;
esac
