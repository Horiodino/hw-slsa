#!/usr/bin/env bash
# Verifier escrow on the PicoRV32 example: an auditor sees the full records,
# the buyer sees only the auditor's verification summaries. See
# docs/selective-disclosure.md.
#
#   e2e/escrow.sh produce   the design house and the sites re-sign with fields withheld (after e2e/run.sh produce, keys still present)
#   e2e/escrow.sh audit     the auditor: full check with the disclosures, then a design VSA and a receipt VSA
#   e2e/escrow.sh buyer     the buyer: checks the two VSAs, holding nothing else from the supply chain
#   e2e/escrow.sh leaks     measure what the signed records and the escrow VSAs reveal
#   e2e/escrow.sh direct    without an auditor: final test commits to its units, the buyer checks its own
#                           units' proofs, and the lot's records sit in the buyer's log (keys still present)
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
  # The flow platform runs synthesis again with its Yosys script (the tool's
  # arguments) withheld, and the tapeout authority signs the release again over
  # that record; the netlist is the same file. Each site then re-signs its
  # record of the same lot with the fields in withhold.json removed and their
  # salted digests listed, and keeps the disclosures in the bundle's
  # disclosures/ directory.
  cp -R "$OUT/bundle" "$ESCROW"
  hslsa design synthesis --bundle "$ESCROW" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem" --isolate \
    --withhold "$E2E/withhold.json"
  hslsa design release --bundle "$ESCROW" --lock "$E2E/inputs.lock.json" --key "$KEYS/tapeout-authority.key.pem" \
    --trust-root "$ESCROW/trust-root.json" --policy "$ESCROW/policy.json" --withhold "$E2E/withhold.json"
  hslsa mfg  --bundle "$ESCROW" --scenario "$E2E/mfg-scenario.json" --keys "$KEYS" --withhold "$E2E/withhold.json"
  hslsa hbom --bundle "$ESCROW" --lock "$E2E/inputs.lock.json" --scenario "$E2E/mfg-scenario.json" \
    --key "$KEYS/product-owner.key.pem" --withhold "$E2E/withhold.json"
}

audit() {
  rm -rf "$AUDITOR" "$BUYER" && mkdir -p "$AUDITOR/key" "$BUYER"
  # A real auditor's key is long-lived and in the buyer's trust root before any
  # lot ships; this one is made per run.
  hslsa keygen --out "$AUDITOR/key" auditor
  # The buyer's policy is the example's, and accepts only an auditor accredited
  # under ISO/IEC 17065 (escrow.auditorAccreditations). The buyer sends the
  # auditor that policy and the serials it received.
  jq '. + {escrow: {auditorAccreditations: ["iso-iec-17065"]}}' "$E2E/policy.json" > "$BUYER/policy.json"
  hslsa escrow audit --bundle "$ESCROW" --trust-root "$ESCROW/trust-root.json" \
    --policy "$BUYER/policy.json" --units "$E2E/received-units.txt" \
    --key "$AUDITOR/key/auditor.key.pem" --vsa-out "$BUYER/vsa" --manifest "$AUDITOR/escrow-manifest.json"
  cp "$AUDITOR/key/auditor.pub.pem" "$BUYER/auditor.pub.pem"
  printf 'PSOC130-A0-00001\nPSOC130-A0-00007\n' > "$AUDITOR/scrapped-unit.txt"
  expect_fail "a received unit that was scrapped at final test" \
    hslsa escrow audit --bundle "$ESCROW" --trust-root "$ESCROW/trust-root.json" \
    --policy "$BUYER/policy.json" --units "$AUDITOR/scrapped-unit.txt" \
    --key "$AUDITOR/key/auditor.key.pem" --vsa-out "$AUDITOR/refused" --manifest "$AUDITOR/refused.json"
}

buyer() {
  # The buyer holds the auditor's VSAs and public key, its own policy, and the
  # serials on the parts it received. It never sees a site's record or key. It
  # enrolls the auditor's key with the auditor's accreditation, signed with its
  # own root key, which is made per run here.
  rm -rf "${BUYER:?}/pub" "${BUYER:?}/root" "${BUYER:?}/enrolled" && mkdir -p "$BUYER/pub" "$BUYER/enrolled"
  cp "$BUYER/auditor.pub.pem" "$BUYER/pub/auditor.pub.pem"
  hslsa keygen --out "$BUYER/root" buyer-root
  hslsa pilot enroll --buyer-key "$BUYER/root/buyer-root.key.pem" --pub "$BUYER/auditor.pub.pem" --role auditor \
    --org-name "Example Audit LLP" --org-id duns:100000077 --site "Example Audit LLP" --custody file \
    --accreditation iso-iec-17065 --accreditation-id ANAB-0001 \
    --not-after "$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ)" --out "$BUYER/enrolled/auditor.intoto.json"
  hslsa pilot trust-root --buyer-pub "$BUYER/root/buyer-root.pub.pem" --enrollments "$BUYER/enrolled" \
    --out "$BUYER/trust-root.json" > /dev/null
  rm -f "$BUYER/root/buyer-root.key.pem"
  hslsa escrow check --vsa-dir "$BUYER/vsa" --trust-root "$BUYER/trust-root.json" \
    --policy "$BUYER/policy.json" --units "$E2E/received-units.txt"

  local sv=${SLSA_VERIFIER:-slsa-verifier} keyid receipt final
  keyid=$(hslsa keyid --key "$BUYER/auditor.pub.pem")
  # The receipt's digest is the lot digest formula over the buyer's own serials.
  receipt=$(hslsa lot-digest "$E2E/received-units.txt")
  final=$(hslsa subject "$BUYER/vsa/design.vsa.intoto.json")
  local common=(--verifier-id "$VERIFIER_ID" --public-key-path "$BUYER/auditor.pub.pem" --public-key-id "$keyid")
  echo "== slsa-verifier verify-vsa: design, from the auditor"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$BUYER/vsa/design.vsa.intoto.json" \
    --subject-digest "sha256:${final#* }" --resource-uri "hslsa:design:${final% *}" \
    --verified-level HSLSA_DESIGN_LEVEL_3 --verified-level SLSA_BUILD_LEVEL_3
  echo "== slsa-verifier verify-vsa: received units, from the auditor"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$BUYER/vsa/receipt.vsa.intoto.json" \
    --subject-digest "sha256:$receipt" --resource-uri "$LOT" \
    --verified-level HSLSA_WAFER_LEVEL_2 --verified-level HSLSA_PACKAGE_TEST_LEVEL_2 --verified-level HSLSA_DESIGN_LEVEL_3

  echo "== negative cases"
  printf 'PSOC130-A0-00001\nPSOC130-A0-00020\n' > "$BUYER/other-units.txt"
  expect_fail "a receipt checked against other units" "$sv" verify-vsa "${common[@]}" \
    --attestation-path "$BUYER/vsa/receipt.vsa.intoto.json" --resource-uri "$LOT" \
    --subject-digest "sha256:$(hslsa lot-digest "$BUYER/other-units.txt")" --verified-level HSLSA_PACKAGE_TEST_LEVEL_2
  expect_fail "a receipt for other units in the buyer's check" hslsa escrow check --vsa-dir "$BUYER/vsa" \
    --trust-root "$BUYER/trust-root.json" --policy "$BUYER/policy.json" --units "$BUYER/other-units.txt"
  hslsa trust-root --keys "$BUYER/pub" --out "$BUYER/plain-trust-root.json"
  expect_fail "an auditor key the buyer did not enroll with an accreditation" hslsa escrow check --vsa-dir "$BUYER/vsa" \
    --trust-root "$BUYER/plain-trust-root.json" --policy "$BUYER/policy.json" --units "$E2E/received-units.txt"
  expect_fail "a level the lot was not verified at" "$sv" verify-vsa "${common[@]}" \
    --attestation-path "$BUYER/vsa/receipt.vsa.intoto.json" --resource-uri "$LOT" \
    --subject-digest "sha256:$receipt" --verified-level HSLSA_PACKAGE_TEST_LEVEL_3
}

leaks() {
  rm -rf "$OUT/leaks" && mkdir -p "$OUT/leaks"
  # Run on the full bundle, as its producer would before handing anything out.
  hslsa leaks --bundle "$ESCROW" --units "$E2E/received-units.txt" --vsa-dir "$BUYER/vsa" --out "$OUT/leaks"
}

direct() {
  local d=${OUT:?}/direct
  local b=$d/bundle
  rm -rf "${d:?}" && mkdir -p "$d/log-key" "$d/pub" "$d/test-site"
  cp -R "$OUT/bundle" "$b"
  # Final test signs the lot again, now with a Merkle root over the shipped
  # units, and writes one inclusion proof per unit; the product owner signs the
  # HBOM again over that record.
  jq '.finalTest.unitCommitment = true' "$E2E/mfg-scenario.json" > "$d/mfg-scenario.json"
  hslsa mfg  --bundle "$b" --scenario "$d/mfg-scenario.json" --keys "$KEYS"
  hslsa hbom --bundle "$b" --lock "$E2E/inputs.lock.json" --scenario "$d/mfg-scenario.json" --key "$KEYS/product-owner.key.pem"

  # The buyer holds final test's record, the test site's public key, and the
  # proofs that shipped with its own units: no unit list, no auditor.
  cp "$KEYS/test-site.pub.pem" "$d/test-site/"
  hslsa trust-root --keys "$d/test-site" --out "$d/test-site.trust-root.json"
  local proofs=() u
  while read -r u; do proofs+=("$b/artifacts/unit-proofs/$u.json"); done < "$E2E/received-units.txt"
  hslsa unit-check --record "$b/att/mfg-f4-final-test.intoto.json" --trust-root "$d/test-site.trust-root.json" "${proofs[@]}"
  # A proof made up for a unit that failed final test, from a real one.
  jq '.unit = "PSOC130-A0-00007"' "${proofs[0]}" > "$d/scrapped-unit.json"
  expect_fail "a proof for a unit final test scrapped" \
    hslsa unit-check --record "$b/att/mfg-f4-final-test.intoto.json" --trust-root "$d/test-site.trust-root.json" "$d/scrapped-unit.json"

  # The buyer also runs a log for the lot's records (its key made per run
  # here), and its policy requires every manufacturing record, transfer and
  # the HBOM in it, and a proof for every received unit.
  local origin="example buyer manufacturing log"
  hslsa keygen --out "$d/log-key" transparency-log
  cp "$KEYS"/pub/*.pub.pem "$d/log-key/transparency-log.pub.pem" "$d/pub/"
  hslsa trust-root --keys "$d/pub" --out "$d/trust-root.json"
  hslsa tlog init --log "$d/log" --origin "$origin"
  for r in "$b"/att/mfg-*.intoto.json "$b/att/hbom.intoto.json"; do
    hslsa tlog add --log "$d/log" --key "$d/log-key/transparency-log.key.pem" --record "$r"
  done
  jq --arg o "$origin" '.manufacturing.transparencyLog = {origin: $o} | .manufacturing.unitCommitment = true' \
    "$E2E/policy.json" > "$d/policy.json"
  hslsa verify --bundle "$b" --trust-root "$d/trust-root.json" --policy "$d/policy.json" --units "$E2E/received-units.txt"
  mv "$b/att/mfg-f3-packaging.tlog.json" "$d/"
  expect_fail "a manufacturing record that is not in the buyer's log" \
    hslsa verify --bundle "$b" --trust-root "$d/trust-root.json" --policy "$d/policy.json" --units "$E2E/received-units.txt"
  mv "$d/mfg-f3-packaging.tlog.json" "$b/att/"
  rm -f "$d/log-key/transparency-log.key.pem"
}

case "${1:-}" in
  produce) produce ;;
  audit) audit ;;
  buyer) buyer ;;
  leaks) leaks ;;
  direct) direct ;;
  all) produce; audit; buyer; leaks ;;
  *) echo "usage: $0 produce|audit|buyer|leaks|direct|all" >&2; exit 2 ;;
esac
