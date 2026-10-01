#!/usr/bin/env bash
# Board-level HSLSA example: the PicoSoC from e2e/run.sh on a small board.
#
#   e2e/board/run.sh produce   sign the shipments, A1 and the board HBOM (needs e2e/run.sh produce first)
#   e2e/board/run.sh verify    board receipt check, board VSA, slsa-verifier
#   e2e/board/run.sh l3        Assembly L3 on the chips from e2e/run.sh l3: challenged at build,
#                              a platform certificate per board, the boards challenged at receipt
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

# Assembly L3 (docs/levels.md), on the L3 chip lot e2e/run.sh l3 made: the
# EMS challenges every chip before placement under the chip's own identity CA,
# the board owner's platform CA signs a platform certificate per board, and the
# buyer, under its own trust root that enrolls each signer at an accredited
# site, challenges the chips on the boards it received.
l3() {
  local l=$OUT/board-l3 chip=$OUT/l3
  [[ -d $chip/parts ]] || { echo "run e2e/run.sh l3 first" >&2; exit 1; }
  rm -rf "$l" && mkdir -p "$l/keys"
  local k=$l/keys
  hslsa keygen --out "$k" ems-site board-owner dist-franchised dist-broker pcb-fab platform-ca buyer-root
  local not_after ent=$l/enrollments
  not_after=$(date -u -d '+90 days' +%Y-%m-%d)
  enroll() { # <dir> <role> <org> <org id> <site> [flags]
    local dir=$1 role=$2 org=$3 id=$4 site=$5; shift 5
    mkdir -p "$dir"
    hslsa pilot enroll --buyer-key "$k/buyer-root.key.pem" --pub "$k/$role.pub.pem" --role "$role" \
      --org-name "$org" --org-id "$id" --site "$site" --country US --custody file \
      --not-after "$not_after" --out "$dir/$role.intoto.json" "$@" > /dev/null
  }
  enroll_all() { # <dir> <EMS accreditation>
    enroll "$1" board-owner "Example Open Silicon Group" duns:100000002 "Example Design Center"
    enroll "$1" platform-ca "Example Open Silicon Group" duns:100000002 "Example Platform CA"
    enroll "$1" ems-site "Example EMS" duns:100000021 "Example EMS" "${@:2}"
    enroll "$1" dist-franchised "Example Franchised Distributor" duns:100000022 "Example Franchised Distributor" \
      --accreditation sae-as6496 --accreditation-id AS6496-0311
    enroll "$1" dist-broker "Example Components Broker" duns:100000023 "Example Components Broker"
    enroll "$1" pcb-fab "Example PCB Fab" duns:100000024 "Example PCB Fab" --accreditation ipc-1791 --accreditation-id IPC1791-0057
  }
  enroll_all "$ent" --accreditation ipc-1791 --accreditation-id IPC1791-0042
  hslsa pilot trust-root --buyer-pub "$k/buyer-root.pub.pem" --enrollments "$ent" --out "$l/trust-root.json" > /dev/null
  local b=$l/board
  mkdir -p "$b" && cp "$HERE/l3/policy.json" "$b/policy.json" && cp "$l/trust-root.json" "$b/trust-root.json"
  # The chip vendor's L3 lot, checked under the buyer's own trust root and L3 policy for it.
  local parts=(--part-trust-root "picosoc=$chip/trust-root.json" --part-policy "picosoc=$chip/bundle/policy.json")

  echo "== the EMS challenges each chip before placement, then the board owner signs a platform certificate per board"
  hslsa board produce --bundle "$b" --chip-bundle "$chip/bundle" --scenario "$HERE/board-scenario.json" \
    --design "$HERE/board-design.json" --policy "$HERE/l3/policy.json" --keys "$k" \
    --chip-parts "$chip/parts" --boards-out "$l/boards" "${parts[@]}"

  echo "== the buyer receives two boards and challenges the chips on them"
  mkdir -p "$l/received"
  local s
  while read -r s; do cp -r "$l/boards/$s" "$l/received/"; done < "$HERE/received-boards.txt"
  hslsa keygen --out "$l/verifier" verifier
  hslsa board verify --bundle "$b" --trust-root "$l/trust-root.json" --policy "$b/policy.json" --boards "$l/received" \
    --vsa-key "$l/verifier/verifier.key.pem" --vsa-out "$l/vsa" "${parts[@]}"
  if command -v "${SLSA_VERIFIER:-slsa-verifier}" > /dev/null; then
    local sv=${SLSA_VERIFIER:-slsa-verifier} keyid lot
    hslsa pubkey --key "$l/verifier/verifier.key.pem" --out "$l/vsa/verifier.pub.pem"
    keyid=$(hslsa keyid --key "$l/vsa/verifier.pub.pem")
    lot=$(hslsa subject "$l/vsa/board.vsa.intoto.json")
    echo "== slsa-verifier verify-vsa: the L3 board lot"
    "$sv" verify-vsa --verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1 \
      --public-key-path "$l/vsa/verifier.pub.pem" --public-key-id "$keyid" \
      --attestation-path "$l/vsa/board.vsa.intoto.json" --subject-digest "sha256:${lot#* }" --resource-uri "${lot% *}" \
      --verified-level HSLSA_ASSEMBLY_LEVEL_3
  fi

  echo "== what Assembly L3 refuses"
  refuses() { # <what> <reason> <command...>
    local what=$1 reason=$2 out; shift 2
    if out=$("$@" 2>&1); then echo "FAIL: accepted $what" >&2; exit 1; fi
    grep -qF -- "$reason" <<< "$out" || { echo "FAIL: refused $what, but not because $reason: $out" >&2; exit 1; }
    echo "ok: refuses $what"
  }
  local check=(--bundle "$b" --policy "$b/policy.json" "${parts[@]}")
  # A chip swapped after the board was built: another genuine chip of the lot in U1.
  local first; first=$(head -1 "$HERE/received-boards.txt")
  mkdir -p "$l/swapped" && cp -r "$l/received/$first" "$l/swapped/"
  rm -rf "$l/swapped/$first/U1" && cp -r "$chip/parts/PSOC130-A0-00030" "$l/swapped/$first/U1"
  refuses "a board whose chip was swapped after build" "not the one its records name" \
    hslsa board verify "${check[@]}" --trust-root "$l/trust-root.json" --boards "$l/swapped"
  refuses "received boards listed by serial, not challenged" "listed, not challenged" \
    hslsa board verify "${check[@]}" --trust-root "$l/trust-root.json" --boards "$HERE/received-boards.txt"
  # The same signers, the EMS enrolled with no accreditation.
  enroll_all "$l/unaccredited"
  hslsa pilot trust-root --buyer-pub "$k/buyer-root.pub.pem" --enrollments "$l/unaccredited" --out "$l/unaccredited.json" > /dev/null
  refuses "an EMS at a site with no accreditation" "enrolled with no accreditation" \
    hslsa board verify "${check[@]}" --trust-root "$l/unaccredited.json" --boards "$l/received"
  rm -rf "$k"
}

case "${1:-}" in
  produce) produce ;;
  verify) verify ;;
  l3) l3 ;;
  all) produce; verify ;;
  *) echo "usage: $0 produce|verify|l3|all" >&2; exit 2 ;;
esac
