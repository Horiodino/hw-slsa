#!/usr/bin/env bash
# End-to-end HSLSA test for the PicoRV32 example.
#
#   e2e/run.sh produce   run the design flow and the simulated lot, sign every record
#   e2e/run.sh verify    check the chain, emit VSAs, verify them with slsa-verifier
#   e2e/run.sh proxy     after produce: the same lot with two suppliers that sign nothing
#   e2e/run.sh hsm       after produce: the release and the lot again, signed with keys in an HSM
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

# The lot again, with two suppliers that sign nothing (docs/proxy-signing.md):
# the sort house hands over only a certificate and a paper traveller, which the
# OSAT covers with an evidence record, and the test house hands over its data,
# which the product owner signs on its behalf. Reuses produce's design records
# and keys, so it runs after produce, in the same job.
proxy() {
  local pb=$OUT/proxy
  rm -rf "$pb" && cp -r "$BUNDLE" "$pb"
  cp "$E2E/proxy/policy.json" "$pb/policy.json"
  hslsa mfg  --bundle "$pb" --scenario "$E2E/proxy/mfg-scenario.json" --keys "$KEYS"
  hslsa hbom --bundle "$pb" --lock "$E2E/inputs.lock.json" --scenario "$E2E/proxy/mfg-scenario.json" --key "$KEYS/product-owner.key.pem"
  hslsa verify --bundle "$pb" --trust-root "$pb/trust-root.json" --policy "$pb/policy.json" --units "$E2E/received-units.txt"
  # The main example's policy claims Wafer and Package/Test L2 and accepts no
  # record signed on a supplier's behalf, so it must refuse this lot.
  if hslsa verify --bundle "$pb" --trust-root "$pb/trust-root.json" --policy "$E2E/policy.json" >/dev/null 2>&1; then
    echo "FAIL: the L2 policy accepted a lot with proxy-signed records" >&2
    exit 1
  fi
  echo "ok: the L2 policy refuses the proxy-signed lot"
}

# The release and the lot again, with the tapeout authority's and every site's
# key in an HSM (docs/hsm-signing.md). Each <role>.key.pem is replaced by a
# <role>.pkcs11 file naming the key on the token, and nothing else changes: the
# same commands sign and the same check passes. With no HSLSA_PKCS11_TOKEN set,
# a throwaway SoftHSM2 token stands in for the HSM. Runs after produce.
hsm() {
  local hb=$OUT/hsm
  local roles=(tapeout-authority fab-site sort-site osat-site test-site product-owner)
  rm -rf "$hb" && mkdir -p "$hb"
  cp -r "$BUNDLE" "$hb/bundle"
  cp -r "$KEYS" "$hb/keys"
  local b=$hb/bundle k=$hb/keys
  if [[ -z "${HSLSA_PKCS11_TOKEN:-}" ]]; then
    export HSLSA_PKCS11_TOKEN=hslsa-e2e
    export HSLSA_PKCS11_MODULE=${HSLSA_PKCS11_MODULE:-$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)}
    export HSLSA_PKCS11_PIN
    HSLSA_PKCS11_PIN=$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')
    export SOFTHSM2_CONF=$hb/softhsm2.conf
    mkdir -p "$hb/tokens"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$hb/tokens" > "$SOFTHSM2_CONF"
    softhsm2-util --init-token --free --label "$HSLSA_PKCS11_TOKEN" --pin "$HSLSA_PKCS11_PIN" \
      --so-pin "$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')" > /dev/null
  fi
  for r in "${roles[@]}"; do rm "$k/$r.key.pem"; done
  hslsa hsm keygen --token "$HSLSA_PKCS11_TOKEN" --out "$k" "${roles[@]}" > /dev/null
  cp "$k"/*.pub.pem "$k/pub/"
  hslsa trust-root --keys "$k/pub" --out "$b/trust-root.json"

  hslsa design release --bundle "$b" --lock "$E2E/inputs.lock.json" --key "$k/tapeout-authority.key.pem" \
    --trust-root "$b/trust-root.json" --policy "$b/policy.json"
  hslsa mfg  --bundle "$b" --scenario "$E2E/mfg-scenario.json" --keys "$k"
  hslsa hbom --bundle "$b" --lock "$E2E/inputs.lock.json" --scenario "$E2E/mfg-scenario.json" --key "$k/product-owner.key.pem"
  hslsa verify --bundle "$b" --trust-root "$b/trust-root.json" --policy "$b/policy.json" --units "$E2E/received-units.txt"

  # The records must carry the HSM keys' signatures, not the file keys' from produce.
  local r keyid
  for r in tapeout-authority:design-release fab-site:mfg-f1-wafer-fab sort-site:mfg-f2-wafer-sort \
           osat-site:mfg-f3-packaging test-site:mfg-f4-final-test product-owner:hbom; do
    keyid=$(hslsa keyid --key "$k/${r%%:*}.pub.pem")
    grep -q "\"keyid\": *\"$keyid\"" "$b/att/${r#*:}.intoto.json" \
      || { echo "FAIL: ${r#*:} is not signed by ${r%%:*}'s HSM key" >&2; exit 1; }
  done
  echo "ok: release and lot signed with HSM-held keys, and the check passes"
  rm -rf "$hb/keys" "$hb/tokens"
}

case "${1:-}" in
  produce) produce ;;
  verify) verify ;;
  proxy) proxy ;;
  hsm) hsm ;;
  all) produce; verify; proxy; hsm ;;
  *) echo "usage: $0 produce|verify|proxy|hsm|all" >&2; exit 2 ;;
esac
