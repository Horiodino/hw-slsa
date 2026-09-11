#!/usr/bin/env bash
# Board-level HSLSA example: the PicoSoC from e2e/run.sh on a small board.
#
#   e2e/board/run.sh produce   sign the shipments, A1 and the board HBOM (needs e2e/run.sh produce first)
#   e2e/board/run.sh verify    board receipt check, board VSA, slsa-verifier
#
# Same privacy rules as the chip test: local ECDSA P-256 keys in DSSE
# envelopes, nothing uploaded to a transparency log.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/e2e/board
OUT=${OUT:-$ROOT/out}
CHIP=$OUT/bundle
BUNDLE=$OUT/board
KEYS=$OUT/board-keys
# The Go reference tool; set HSLSA to use a prebuilt binary instead of building it here.
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

produce() {
  rm -rf "$BUNDLE" "$KEYS"
  mkdir -p "$BUNDLE" "$KEYS/pub"
  # The EMS, the board owner and every shipper sign with their own key. The broker
  # is trusted to sign but is not an authorized channel for any manufacturer.
  hslsa keygen --out "$KEYS" ems-site board-owner dist-franchised dist-broker pcb-fab
  cp "$KEYS"/*.pub.pem "$KEYS/pub/"
  hslsa trust-root --keys "$KEYS/pub" --out "$BUNDLE/trust-root.json"
  cp "$HERE/policy.json" "$BUNDLE/policy.json"
  hslsa board produce --bundle "$BUNDLE" --chip-bundle "$CHIP" --scenario "$HERE/board-scenario.json" \
    --design "$HERE/board-design.json" --policy "$HERE/policy.json" --keys "$KEYS"
}

verify() {
  local vsa_dir=$OUT/vsa vkey=$OUT/board-verifier-key
  rm -rf "$vkey" && mkdir -p "$vsa_dir" "$vkey"
  if [[ -n "${HSLSA_VSA_SIGNING_KEY:-}" ]]; then
    (umask 077 && printf '%s\n' "$HSLSA_VSA_SIGNING_KEY" > "$vkey/verifier.key.pem")
  else
    hslsa keygen --out "$vkey" verifier
  fi
  hslsa pubkey --key "$vkey/verifier.key.pem" --out "$vsa_dir/board-verifier.pub.pem"

  hslsa board verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json" \
    --boards "$HERE/received-boards.txt" --vsa-key "$vkey/verifier.key.pem" --vsa-out "$vsa_dir"

  local sv=${SLSA_VERIFIER:-slsa-verifier} keyid lot
  keyid=$(hslsa keyid --key "$vsa_dir/board-verifier.pub.pem")
  lot=$(hslsa subject "$vsa_dir/board.vsa.intoto.json")
  local args=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
              --public-key-path "$vsa_dir/board-verifier.pub.pem" --public-key-id "$keyid"
              --attestation-path "$vsa_dir/board.vsa.intoto.json" --resource-uri "${lot% *}")
  echo "== slsa-verifier verify-vsa: board lot"
  "$sv" verify-vsa "${args[@]}" --subject-digest "sha256:${lot#* }" --verified-level HSLSA_ASSEMBLY_LEVEL_2
  echo "== slsa-verifier negative case"
  if "$sv" verify-vsa "${args[@]}" --subject-digest "sha256:${lot#* }" --verified-level HSLSA_ASSEMBLY_LEVEL_3 >/dev/null 2>&1; then
    echo "FAIL: slsa-verifier accepted Assembly L3 for the board lot" >&2
    exit 1
  fi
  echo "ok: slsa-verifier rejects a level the board lot was not verified at"
  rm -rf "$vkey"
}

case "${1:-}" in
  produce) produce ;;
  verify) verify ;;
  all) produce; verify ;;
  *) echo "usage: $0 produce|verify|all" >&2; exit 2 ;;
esac
