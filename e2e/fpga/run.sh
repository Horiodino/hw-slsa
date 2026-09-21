#!/usr/bin/env bash
# FPGA board example: an iCE40 board whose root of trust verifies the
# bitstream and firmware in flash before it lets the FPGA out of reset.
#
#   e2e/fpga/run.sh produce   the root of trust vendor's chain, the board owner's FPGA design and
#                             flash image, the board chain and the EMS's per-board provisioning
#   e2e/fpga/run.sh boot      power on the received boards (root of trust, then the SoC in RTL simulation)
#   e2e/fpga/run.sh verify    every buyer check, VSAs, slsa-verifier
#
# Needs: Go, yosys, nextpnr-ice40, icestorm (icepack, iceunpack, icetime and
# its chip database), iverilog, a RISC-V GCC, git and ssh-keygen. Same privacy
# rules as the other examples: local ECDSA P-256 keys in DSSE envelopes,
# nothing uploaded to a transparency log.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/e2e/fpga
OUT=${OUT:-$ROOT/out}/fpga
ROT=$OUT/rot
ROT_KEYS=$OUT/rot-keys
DESIGN=$OUT/design
BUNDLE=$OUT/board
KEYS=$OUT/keys
CACHE=${CACHE:-$ROOT/out/cache}
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

# The root of trust vendor: its die is the PicoRV32 example's design, so its
# chip chain is that example's flow under its own product name, plus its
# firmware, its per-unit provisioning and a chip HBOM with the firmware listed.
produce_rot() {
  local lock=$ROOT/e2e/picorv32/inputs.lock.json
  rm -rf "$ROT" "$ROT_KEYS" "$OUT/rot-devices"
  mkdir -p "$ROT" "$ROT_KEYS/pub"
  hslsa keygen --out "$ROT_KEYS" ip-vendor source-owner source-reviewer flow-platform tapeout-authority \
    fab-site sort-site osat-site test-site product-owner firmware-platform code-signer
  hslsa caliptra ca --keys "$ROT_KEYS" --name "Example RoT Co EXR-01 IDevID CA"
  cp "$ROT_KEYS"/*.pub.pem "$ROT_KEYS/pub/"
  hslsa trust-root --keys "$ROT_KEYS/pub" --out "$ROT/trust-root.json"
  cp "$HERE/rot/policy.json" "$ROT/policy.json"
  hslsa design ip-release    --bundle "$ROT" --lock "$lock" --key "$ROT_KEYS/ip-vendor.key.pem" --cache "$CACHE"
  hslsa design source-tag    --bundle "$ROT" --lock "$lock" --key "$ROT_KEYS/source-owner.key.pem" --cache "$CACHE"
  hslsa design review        --bundle "$ROT" --lock "$lock" --key "$ROT_KEYS/source-reviewer.key.pem"
  hslsa design source-freeze --bundle "$ROT" --lock "$lock" --key "$ROT_KEYS/flow-platform.key.pem" --cache "$CACHE" \
    --trust-root "$ROT/trust-root.json" --policy "$ROT/policy.json"
  hslsa design simulation    --bundle "$ROT" --lock "$lock" --key "$ROT_KEYS/flow-platform.key.pem"
  hslsa design synthesis     --bundle "$ROT" --lock "$lock" --key "$ROT_KEYS/flow-platform.key.pem"
  hslsa design release       --bundle "$ROT" --lock "$lock" --key "$ROT_KEYS/tapeout-authority.key.pem" \
    --trust-root "$ROT/trust-root.json" --policy "$ROT/policy.json"
  hslsa mfg --bundle "$ROT" --scenario "$HERE/rot/mfg-scenario.json" --keys "$ROT_KEYS"
  hslsa fpga rot-firmware  --bundle "$ROT" --src "$HERE/rot/firmware" --key "$ROT_KEYS/firmware-platform.key.pem" \
    --code-signer "$ROT_KEYS/code-signer.key.pem" --svn 1
  hslsa fpga rot-provision --bundle "$ROT" --devices "$OUT/rot-devices" --keys "$ROT_KEYS" --scenario "$HERE/rot/mfg-scenario.json"
  hslsa fpga rot-hbom      --bundle "$ROT" --lock "$lock" --scenario "$HERE/rot/mfg-scenario.json" --key "$ROT_KEYS/product-owner.key.pem"
  # The identity CA's private key stays with the vendor.
  rm -f "$ROT_KEYS/identity-ca.key.pem"
}

# The board owner: its FPGA design, the SoC firmware and the flash image.
produce_design() {
  local lock=$HERE/inputs.lock.json
  rm -rf "$DESIGN" "$KEYS"
  mkdir -p "$DESIGN" "$KEYS/pub"
  # One trust root for the board owner (also the FPGA design house), the EMS and the shippers.
  hslsa keygen --out "$KEYS" ip-vendor source-owner source-reviewer flow-platform tapeout-authority \
    firmware-platform code-signer board-owner ems-site dist-franchised pcb-fab
  cp "$KEYS"/*.pub.pem "$KEYS/pub/"
  hslsa trust-root --keys "$KEYS/pub" --out "$DESIGN/trust-root.json"
  cp "$HERE/policy.json" "$DESIGN/policy.json"
  cp "$lock" "$DESIGN/inputs.lock.json"
  hslsa design ip-release    --bundle "$DESIGN" --lock "$lock" --key "$KEYS/ip-vendor.key.pem" --cache "$CACHE"
  hslsa design source-tag    --bundle "$DESIGN" --lock "$lock" --key "$KEYS/source-owner.key.pem" --cache "$CACHE"
  hslsa design review        --bundle "$DESIGN" --lock "$lock" --key "$KEYS/source-reviewer.key.pem"
  hslsa design source-freeze --bundle "$DESIGN" --lock "$lock" --key "$KEYS/flow-platform.key.pem" --cache "$CACHE" \
    --trust-root "$DESIGN/trust-root.json" --policy "$DESIGN/policy.json"
  hslsa fpga firmware        --bundle "$DESIGN" --lock "$lock" --key "$KEYS/firmware-platform.key.pem" --cache "$CACHE"
  for step in simulation synthesis routing signoff bitstream; do
    hslsa fpga design "$step" --bundle "$DESIGN" --lock "$lock" --key "$KEYS/flow-platform.key.pem"
  done
  hslsa design release --bundle "$DESIGN" --lock "$lock" --key "$KEYS/tapeout-authority.key.pem" \
    --trust-root "$DESIGN/trust-root.json" --policy "$DESIGN/policy.json"
  hslsa fpga image --bundle "$DESIGN" --lock "$lock" --scenario "$HERE/board-scenario.json" \
    --key "$KEYS/firmware-platform.key.pem" --code-signer "$KEYS/code-signer.key.pem"
}

# The EMS: shipments, A1, the board HBOM and one provisioning record per board.
produce_board() {
  rm -rf "$BUNDLE" "$OUT/boards"
  mkdir -p "$BUNDLE"
  cp "$DESIGN/trust-root.json" "$BUNDLE/trust-root.json"
  cp "$HERE/policy.json" "$BUNDLE/policy.json"
  hslsa fpga produce --bundle "$BUNDLE" --rot-bundle "$ROT" --design-bundle "$DESIGN" \
    --scenario "$HERE/board-scenario.json" --design "$HERE/board-design.json" --policy "$HERE/policy.json" --keys "$KEYS"
  hslsa fpga provision --bundle "$BUNDLE" --devices "$OUT/rot-devices" --boards "$OUT/boards" \
    --scenario "$HERE/board-scenario.json" --keys "$KEYS"
}

boot() {
  rm -rf "$OUT/boots"
  hslsa fpga boot --bundle "$BUNDLE" --boards "$OUT/boards" --list "$HERE/received-boards.txt" --out "$OUT/boots"
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
    (umask 077 && printf '%s\n' "$HSLSA_VSA_SIGNING_KEY" > "$vkey/verifier.key.pem")
  else
    hslsa keygen --out "$vkey" verifier
  fi
  hslsa pubkey --key "$vkey/verifier.key.pem" --out "$vsa_dir/verifier.pub.pem"

  hslsa fpga verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json" \
    --boards "$HERE/received-boards.txt" --boots "$OUT/boots" --vsa-key "$vkey/verifier.key.pem" --vsa-out "$vsa_dir"

  local sv=${SLSA_VERIFIER:-slsa-verifier} keyid design lot board
  keyid=$(hslsa keyid --key "$vsa_dir/verifier.pub.pem")
  local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                --public-key-path "$vsa_dir/verifier.pub.pem" --public-key-id "$keyid")
  design=$(hslsa subject "$vsa_dir/design.vsa.intoto.json")
  echo "== slsa-verifier verify-vsa: FPGA design"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/design.vsa.intoto.json" --resource-uri "hslsa:design:${design% *}" \
    --subject-digest "sha256:${design#* }" --verified-level HSLSA_DESIGN_LEVEL_2 --verified-level SLSA_BUILD_LEVEL_2
  lot=$(hslsa subject "$vsa_dir/board.vsa.intoto.json")
  echo "== slsa-verifier verify-vsa: board lot"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/board.vsa.intoto.json" --resource-uri "${lot% *}" \
    --subject-digest "sha256:${lot#* }" --verified-level HSLSA_ASSEMBLY_LEVEL_2 --verified-level HSLSA_FIRMWARE_LEVEL_2
  while read -r serial; do
    [[ -z "$serial" ]] && continue
    board=$(hslsa subject "$vsa_dir/board-$serial.vsa.intoto.json")
    echo "== slsa-verifier verify-vsa: board $serial"
    "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/board-$serial.vsa.intoto.json" --resource-uri "${board% *}" \
      --subject-digest "sha256:${board#* }" --verified-level HSLSA_FIRMWARE_LEVEL_2
  done < "$HERE/received-boards.txt"
  echo "== slsa-verifier negative case"
  expect_fail "Firmware L3 for the board lot" "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/board.vsa.intoto.json" \
    --resource-uri "${lot% *}" --subject-digest "sha256:${lot#* }" --verified-level HSLSA_FIRMWARE_LEVEL_3
  rm -rf "$vkey"
}

case "${1:-}" in
  produce) produce_rot; produce_design; produce_board ;;
  boot) boot ;;
  verify) verify ;;
  all) produce_rot; produce_design; produce_board; boot; verify ;;
  *) echo "usage: $0 produce|boot|verify|all" >&2; exit 2 ;;
esac
