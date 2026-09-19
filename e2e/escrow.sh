#!/usr/bin/env bash
# Verifier escrow on the PicoRV32 example: an auditor sees the full records,
# the buyer sees only the auditor's verification summaries. See
# docs/selective-disclosure.md.
#
#   e2e/escrow.sh produce   the sites re-sign the lot with fields withheld (after e2e/run.sh produce, keys still present)
#   e2e/escrow.sh audit     the auditor: full check with the disclosures, then a design VSA and a receipt VSA
#   e2e/escrow.sh buyer     the buyer: checks the two VSAs, holding nothing else from the supply chain
#   e2e/escrow.sh leaks     measure what the signed records and the escrow VSAs reveal
#
# Same privacy rules as e2e/run.sh: local ECDSA P-256 keys in DSSE envelopes,
# nothing uploaded to a transparency log.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
E2E=$ROOT/e2e/picorv32
OUT=${OUT:-$ROOT/out}
KEYS=$OUT/keys
ESCROW=$OUT/escrow/bundle   # what the auditor receives: every record, file and disclosure
AUDITOR=$OUT/auditor        # the auditor's key and escrow manifest, kept by the auditor
BUYER=$OUT/buyer            # what the buyer receives: two VSAs and the auditor's public key
# The lot id printed on the parts' reel label; the buyer needs nothing else to name the lot.
LOT=urn:hslsa:lot:ASM-EXAMPLE-17
VERIFIER_ID=https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
# The Go reference tool; set HSLSA to use a prebuilt binary instead of building it here.
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

expect_fail() {
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: accepted $what" >&2
    exit 1
  fi
  echo "ok: rejects $what"
}

produce() {
  rm -rf "$OUT/escrow" && mkdir -p "$OUT/escrow"
  # The design records stay as they are. Each site re-signs its record of the same
  # lot with the fields in withhold.json removed and their salted digests listed,
  # and keeps the disclosures in the bundle's disclosures/ directory.
  cp -R "$OUT/bundle" "$ESCROW"
  hslsa mfg  --bundle "$ESCROW" --scenario "$E2E/mfg-scenario.json" --keys "$KEYS" --withhold "$E2E/withhold.json"
  hslsa hbom --bundle "$ESCROW" --lock "$E2E/inputs.lock.json" --scenario "$E2E/mfg-scenario.json" \
    --key "$KEYS/product-owner.key.pem" --withhold "$E2E/withhold.json"
}

audit() {
  rm -rf "$AUDITOR" "$BUYER" && mkdir -p "$AUDITOR/key" "$BUYER"
  # A real auditor's key is long-lived and in the buyer's trust root before any
  # lot ships; this one is made per run.
  hslsa keygen --out "$AUDITOR/key" auditor
  # The buyer sends the auditor its policy and the serials it received.
  hslsa escrow audit --bundle "$ESCROW" --trust-root "$ESCROW/trust-root.json" \
    --policy "$E2E/policy.json" --units "$E2E/received-units.txt" \
    --key "$AUDITOR/key/auditor.key.pem" --vsa-out "$BUYER/vsa" --manifest "$AUDITOR/escrow-manifest.json"
  cp "$AUDITOR/key/auditor.pub.pem" "$BUYER/auditor.pub.pem"
  printf 'PSOC130-A0-00001\nPSOC130-A0-00007\n' > "$AUDITOR/scrapped-unit.txt"
  expect_fail "a received unit that was scrapped at final test" \
    hslsa escrow audit --bundle "$ESCROW" --trust-root "$ESCROW/trust-root.json" \
    --policy "$E2E/policy.json" --units "$AUDITOR/scrapped-unit.txt" \
    --key "$AUDITOR/key/auditor.key.pem" --vsa-out "$AUDITOR/refused" --manifest "$AUDITOR/refused.json"
}

buyer() {
  # The buyer holds the auditor's VSAs and public key, its own policy, and the
  # serials on the parts it received. It never sees a site's record or key.
  rm -rf "$BUYER/pub" && mkdir -p "$BUYER/pub"
  cp "$BUYER/auditor.pub.pem" "$BUYER/pub/auditor.pub.pem"
  hslsa trust-root --keys "$BUYER/pub" --out "$BUYER/trust-root.json"
  hslsa escrow check --vsa-dir "$BUYER/vsa" --trust-root "$BUYER/trust-root.json" \
    --policy "$E2E/policy.json" --units "$E2E/received-units.txt"

  local sv=${SLSA_VERIFIER:-slsa-verifier} keyid receipt final
  keyid=$(hslsa keyid --key "$BUYER/auditor.pub.pem")
  # The receipt's digest is the lot digest formula over the buyer's own serials.
  receipt=$(hslsa lot-digest "$E2E/received-units.txt")
  final=$(hslsa subject "$BUYER/vsa/design.vsa.intoto.json")
  local common=(--verifier-id "$VERIFIER_ID" --public-key-path "$BUYER/auditor.pub.pem" --public-key-id "$keyid")
  echo "== slsa-verifier verify-vsa: design, from the auditor"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$BUYER/vsa/design.vsa.intoto.json" \
    --subject-digest "sha256:${final#* }" --resource-uri "hslsa:design:${final% *}" \
    --verified-level HSLSA_DESIGN_LEVEL_2 --verified-level SLSA_BUILD_LEVEL_2
  echo "== slsa-verifier verify-vsa: received units, from the auditor"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$BUYER/vsa/receipt.vsa.intoto.json" \
    --subject-digest "sha256:$receipt" --resource-uri "$LOT" \
    --verified-level HSLSA_WAFER_LEVEL_2 --verified-level HSLSA_PACKAGE_TEST_LEVEL_2 --verified-level HSLSA_DESIGN_LEVEL_2

  echo "== negative cases"
  printf 'PSOC130-A0-00001\nPSOC130-A0-00020\n' > "$BUYER/other-units.txt"
  expect_fail "a receipt checked against other units" "$sv" verify-vsa "${common[@]}" \
    --attestation-path "$BUYER/vsa/receipt.vsa.intoto.json" --resource-uri "$LOT" \
    --subject-digest "sha256:$(hslsa lot-digest "$BUYER/other-units.txt")" --verified-level HSLSA_PACKAGE_TEST_LEVEL_2
  expect_fail "a receipt for other units in the buyer's check" hslsa escrow check --vsa-dir "$BUYER/vsa" \
    --trust-root "$BUYER/trust-root.json" --policy "$E2E/policy.json" --units "$BUYER/other-units.txt"
  expect_fail "a level the lot was not verified at" "$sv" verify-vsa "${common[@]}" \
    --attestation-path "$BUYER/vsa/receipt.vsa.intoto.json" --resource-uri "$LOT" \
    --subject-digest "sha256:$receipt" --verified-level HSLSA_PACKAGE_TEST_LEVEL_3
}

leaks() {
  rm -rf "$OUT/leaks" && mkdir -p "$OUT/leaks"
  # Run on the full bundle, as its producer would before handing anything out.
  hslsa leaks --bundle "$ESCROW" --units "$E2E/received-units.txt" --vsa-dir "$BUYER/vsa" --out "$OUT/leaks"
}

case "${1:-}" in
  produce) produce ;;
  audit) audit ;;
  buyer) buyer ;;
  leaks) leaks ;;
  all) produce; audit; buyer; leaks ;;
  *) echo "usage: $0 produce|audit|buyer|leaks|all" >&2; exit 2 ;;
esac
