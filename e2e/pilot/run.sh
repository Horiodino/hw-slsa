#!/usr/bin/env bash
# A rehearsal of the phase 4 pilot (pilot/README.md), with every party played
# on one machine: the buyer runs the trust root, the OSAT signs its own
# records with keys only it holds, and the buyer checks and measures the lot.
#
#   e2e/pilot/run.sh chip    after e2e/run.sh produce: the chip lot from the
#                            suppliers' exports, under a buyer-run trust root
#   e2e/pilot/run.sh board   after e2e/fpga/run.sh produce and boot: the board
#                            check and the at-boot check, under buyer-run trust roots
#
# The organization ids are made up, in the forms the spec accepts. Same
# privacy rules as the other examples: local keys, DSSE envelopes, nothing
# uploaded to a transparency log.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/e2e/pilot
OUT=${OUT:-$ROOT/out}
PILOT=$OUT/pilot
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

NOT_AFTER=$(date -u -d '+90 days' +%Y-%m-%d)

refuses() {
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: accepted $what" >&2
    exit 1
  fi
  echo "ok: refuses $what"
}

# enroll <dir> <pub> <role> <org name> <org id> <site> [extra flags]: the buyer
# signs one enrollment, after checking the key with the site out of band.
enroll() {
  local dir=$1 pub=$2 role=$3 org=$4 id=$5 site=$6; shift 6
  hslsa pilot enroll --buyer-key "$PILOT/buyer/buyer-root.key.pem" --pub "$pub" --role "$role" \
    --org-name "$org" --org-id "$id" --site "$site" --country US --custody file --not-after "$NOT_AFTER" \
    --note "rehearsal: key fingerprint read back to the site by phone" --out "$dir/$role.intoto.json" "$@" > /dev/null
}

chip() {
  local keys=$OUT/keys bundle=$OUT/bundle
  [[ -d $bundle/att ]] || { echo "run e2e/run.sh produce first" >&2; exit 1; }
  local ent=$PILOT/enrollments lot=$PILOT/lot osat=$PILOT/osat-keys
  rm -rf "$PILOT" && mkdir -p "$PILOT" "$ent"

  echo "== the buyer makes its root key; the OSAT Group makes its site keys, which never leave it"
  hslsa keygen --out "$PILOT/buyer" buyer-root
  hslsa keygen --out "$osat" sort-site osat-site test-site

  echo "== the buyer enrolls each key it was handed"
  local vendor=("Example Open Silicon Group" duns:100000002)
  enroll "$ent" "$keys/ip-vendor.pub.pem" ip-vendor "Example IP Vendor" duns:100000001 "Example IP Vendor"
  for role in source-owner source-reviewer flow-platform tapeout-authority product-owner; do
    enroll "$ent" "$keys/$role.pub.pem" "$role" "${vendor[@]}" "Example Design Center"
  done
  local group=("Example OSAT Group" duns:100000003)
  enroll "$ent" "$osat/sort-site.pub.pem" sort-site "${group[@]}" "Example Sort House"
  enroll "$ent" "$osat/osat-site.pub.pem" osat-site "${group[@]}" "Example OSAT"
  enroll "$ent" "$osat/test-site.pub.pem" test-site "${group[@]}" "Example Test House"
  hslsa pilot trust-root --buyer-pub "$PILOT/buyer/buyer-root.pub.pem" --enrollments "$ent" --out "$PILOT/trust-root.json"

  echo "== the OSAT Group signs the lot from its exports, with its keys only"
  rm -rf "$lot" && cp -r "$bundle" "$lot"
  rm -f "$lot/trust-root.json" "$lot"/att/mfg-*.intoto.json "$lot"/att/hbom*.json
  hslsa adapt --config "$HERE/adapter.json" --out "$PILOT/scenario.json"
  hslsa mfg --bundle "$lot" --scenario "$PILOT/scenario.json" --keys "$osat" --sign sort-site,osat-site,test-site
  echo "== the vendor signs the HBOM"
  hslsa hbom --bundle "$lot" --lock "$ROOT/e2e/picorv32/inputs.lock.json" --scenario "$PILOT/scenario.json" \
    --key "$keys/product-owner.key.pem"

  echo "== the buyer checks and measures the lot"
  local units=$ROOT/e2e/picorv32/received-units.txt
  # The kit's policy is for real parts and refuses records made from simulated
  # hardware; the rehearsal's lot is simulated, so it runs under a copy that
  # accepts them.
  local policy=$PILOT/rehearsal-policy.json
  sed '1a\  "simulated": {"accept": true, "note": "rehearsal only: the lot is simulated"},' "$HERE/policy.json" > "$policy"
  refuses "the simulated lot under the policy for real parts" \
    hslsa verify --bundle "$lot" --trust-root "$PILOT/trust-root.json" --policy "$HERE/policy.json" --units "$units"
  hslsa verify --bundle "$lot" --trust-root "$PILOT/trust-root.json" --policy "$policy" --units "$units"
  hslsa pilot measure --bundle "$lot" --trust-root "$PILOT/trust-root.json" --policy "$policy" \
    --units "$units" --costs "$HERE/costs.json" --out "$PILOT/report" > /dev/null
  echo "ok: report in $PILOT/report"

  echo "== what the buyer-run trust root refuses"
  local check=(--bundle "$lot" --policy "$policy" --units "$units")
  # The vendor's own trust root, the one produce wrote, does not list the OSAT's keys.
  refuses "the lot under the vendor's trust root, which never saw the OSAT's keys" \
    hslsa verify "${check[@]}" --trust-root "$bundle/trust-root.json"
  # A key the buyer never enrolled: the test site's enrollment left out.
  local partial=$PILOT/partial && mkdir -p "$partial"
  cp "$ent"/*.intoto.json "$partial/" && rm "$partial/test-site.intoto.json"
  hslsa pilot trust-root --buyer-pub "$PILOT/buyer/buyer-root.pub.pem" --enrollments "$partial" --out "$PILOT/partial.json" > /dev/null
  refuses "final test signed by a key the buyer did not enroll" hslsa verify "${check[@]}" --trust-root "$PILOT/partial.json"
  # A revoked key: the OSAT reports its assembly key lost.
  local rev=$PILOT/revoked && mkdir -p "$rev" && cp "$ent"/*.intoto.json "$rev/"
  hslsa pilot revoke --buyer-key "$PILOT/buyer/buyer-root.key.pem" --pub "$osat/osat-site.pub.pem" \
    --reason "key reported lost by the site" --out "$rev/revoke-osat-site.intoto.json" > /dev/null
  # Read the whole listing before matching: grep -q in a pipe would stop at the
  # match, and the tool, still writing, would die of SIGPIPE under pipefail.
  local listing
  listing=$(hslsa pilot trust-root --buyer-pub "$PILOT/buyer/buyer-root.pub.pem" --enrollments "$rev" --out "$PILOT/revoked.json")
  grep -q "excluded osat-site.*revoked" <<< "$listing" || { echo "FAIL: revoked key not excluded" >&2; exit 1; }
  refuses "packaging signed by a revoked key" hslsa verify "${check[@]}" --trust-root "$PILOT/revoked.json"
  refuses "a measured lot that fails its check, without saying so" hslsa pilot measure "${check[@]}" \
    --trust-root "$PILOT/revoked.json" --out "$PILOT/report-revoked"
  grep -q '"result": "fail"' "$PILOT"/report-revoked/*.json || { echo "FAIL: report does not record the failed check" >&2; exit 1; }
  echo "ok: the report records the failed check"
  # Enrollments read after they end.
  refuses "a trust root built after every enrollment ended" hslsa pilot trust-root \
    --buyer-pub "$PILOT/buyer/buyer-root.pub.pem" --enrollments "$ent" --at "$(date -u -d '+120 days' +%Y-%m-%d)" --out "$PILOT/late.json"
  # A trust root kept past the end of its first enrollment.
  local old=$PILOT/old && mkdir -p "$old"
  enroll "$old" "$osat/test-site.pub.pem" test-site "${group[@]}" "Example Test House" --not-before 2025-01-01 --not-after 2025-12-31
  hslsa pilot trust-root --buyer-pub "$PILOT/buyer/buyer-root.pub.pem" --enrollments "$old" --at 2025-06-01 --out "$PILOT/old.json" > /dev/null
  refuses "a trust root past its validUntil" hslsa verify "${check[@]}" --trust-root "$PILOT/old.json"
  # A record the buyer did not sign, slipped into its enrollment directory.
  local forged=$PILOT/forged && mkdir -p "$forged" && cp "$ent"/*.intoto.json "$forged/"
  hslsa keygen --out "$PILOT/intruder" buyer-root > /dev/null
  hslsa pilot enroll --buyer-key "$PILOT/intruder/buyer-root.key.pem" --pub "$keys/flow-platform.pub.pem" --role fab-site \
    --org-name Intruder --org-id duns:999999999 --site Intruder --custody file --not-after "$NOT_AFTER" --out "$forged/fab-site.intoto.json" > /dev/null
  refuses "an enrollment signed by anyone but the buyer" hslsa pilot trust-root \
    --buyer-pub "$PILOT/buyer/buyer-root.pub.pem" --enrollments "$forged" --out "$PILOT/forged.json"
  # One key enrolled for two roles.
  local twice=$PILOT/twice && mkdir -p "$twice" && cp "$ent"/*.intoto.json "$twice/"
  enroll "$twice" "$osat/osat-site.pub.pem" test-site "${group[@]}" "Example Test House"
  refuses "one key enrolled for two roles" hslsa pilot trust-root \
    --buyer-pub "$PILOT/buyer/buyer-root.pub.pem" --enrollments "$twice" --out "$PILOT/twice.json"
  rm -rf "$osat" "$PILOT/intruder" "$PILOT/buyer/buyer-root.key.pem"
}

# The board pilot: the FPGA board example's buyer checks, with the root of
# trust vendor's trust root and the board's rebuilt from the buyer's
# enrollments. The public keys are the bundles' own, standing in for keys
# each company hands the buyer directly.
board() {
  local fpga=$OUT/fpga
  [[ -d $fpga/boots ]] || { echo "run e2e/fpga/run.sh produce and boot first" >&2; exit 1; }
  local work=$PILOT/board
  rm -rf "$work" && mkdir -p "$work/keys" "$work/rot" "$work/board"
  hslsa keygen --out "$work/buyer" buyer-root > /dev/null
  local PILOT=$work
  local b=$work/bundle
  cp -r "$fpga/board" "$b"

  # enroll_all <trust root> <dir> <org name> <org id> <site>
  enroll_all() {
    local tr=$1 dir=$2; shift 2
    local role
    for role in $(jq -r '.roles | keys[]' "$tr"); do
      [[ $(jq -r --arg r "$role" '.roles[$r] | length' "$tr") == 1 ]] || { echo "FAIL: $role has several keys" >&2; exit 1; }
      jq -r --arg r "$role" '.roles[$r][0]' "$tr" > "$work/keys/$role-$(basename "$dir").pub.pem"
      enroll "$dir" "$work/keys/$role-$(basename "$dir").pub.pem" "$role" "$@"
    done
  }
  enroll_all "$b/parts/rot/trust-root.json" "$work/rot" "Example RoT Co" duns:100000004 "Example RoT Co"
  enroll_all "$b/trust-root.json" "$work/board" "Example Board Co" duns:100000005 "Example Board Co"
  # The buyer's trust roots and the part's policy stay with the buyer, outside
  # the bundle; the trust roots that came in the bundle are left as the
  # suppliers sent them, and the check must not use them.
  hslsa pilot trust-root --buyer-pub "$work/buyer/buyer-root.pub.pem" --enrollments "$work/rot" --out "$work/rot-trust-root.json" > /dev/null
  hslsa pilot trust-root --buyer-pub "$work/buyer/buyer-root.pub.pem" --enrollments "$work/board" --out "$work/board-trust-root.json" > /dev/null
  cp "$b/parts/rot/policy.json" "$work/rot-policy.json"

  echo "== the buyer's board and at-boot checks under its own trust roots"
  local check=(--bundle "$b" --trust-root "$work/board-trust-root.json" --policy "$b/policy.json"
               --part-trust-root "rot=$work/rot-trust-root.json" --part-policy "rot=$work/rot-policy.json"
               --boards "$ROOT/e2e/fpga/received-boards.txt" --boots "$fpga/boots")
  hslsa fpga verify "${check[@]}" | tee "$work/verify.log"
  if grep -q "in its own bundle" "$work/verify.log"; then
    echo "FAIL: the check used a trust root or policy from the supplier's bundle" >&2
    exit 1
  fi
  echo "ok: board lot, root of trust firmware and every boot pass under buyer-run trust roots"

  # The root of trust vendor's test site key revoked: its provisioning records
  # no longer count, although the bundle's own trust root still lists the key.
  hslsa pilot revoke --buyer-key "$work/buyer/buyer-root.key.pem" --pub "$work/keys/test-site-rot.pub.pem" \
    --reason "station key rotated" --out "$work/rot/revoke-test-site.intoto.json" > /dev/null
  hslsa pilot trust-root --buyer-pub "$work/buyer/buyer-root.pub.pem" --enrollments "$work/rot" --out "$work/rot-trust-root.json" > /dev/null
  refuses "a root of trust whose test site key was revoked" hslsa fpga verify "${check[@]}"
  rm -f "$work/buyer/buyer-root.key.pem"
}

case "${1:-}" in
  chip) chip ;;
  board) board ;;
  *) echo "usage: $0 chip|board" >&2; exit 2 ;;
esac
