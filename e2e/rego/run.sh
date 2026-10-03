#!/usr/bin/env bash
# The independent check of an HSLSA bundle: openssl and ssh-keygen verify the
# signatures, OPA evaluates the buyer rules in policies/rego, and nothing
# from tools/hslsa runs. See docs/rego-policies.md.
#
#   e2e/rego/run.sh [--check-only] [--policy FILE] [--trust-root FILE] [--received FILE] <bundle>
#
# A chip bundle (out/bundle) gets the tapeout and lot receipt checks, a board
# bundle (out/board) the board receipt check, which runs both chip checks on
# each part bundle it carries. The bundle must pass. Then, unless
# --check-only, broken copies of it must each be refused for the stated
# reason: a record altered after signing, a record signed by another role's
# key, a record that links a different digest, and a lot list edited after
# signing. The keys those cases sign with are made here and deleted at the end.
#
# OPA is $OPA, or opa on the PATH.
set -euo pipefail
export LC_ALL=C

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OPA=${OPA:-opa}
check_only=0
args=()
while [[ $# -gt 1 ]]; do
  case $1 in
    --check-only) check_only=1; shift ;;
    --policy | --trust-root | --received) args+=("$1" "$2"); shift 2 ;;
    *) break ;;
  esac
done
[[ $# -eq 1 && -d $1 ]] || { echo "usage: $0 [--check-only] [--policy FILE] [--trust-root FILE] [--received FILE] <bundle>" >&2; exit 2; }
bundle=${1%/}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

board=0
[[ -f $bundle/att/mfg-a1-board-assembly.intoto.json ]] && board=1
if ((board)); then
  query='[data.hslsa.board.report]'
else
  query='[data.hslsa.tapeout.report, data.hslsa.lot.report]'
fi

# check <bundle> <input out> [input.sh args]: build the input, evaluate the
# policies, print the reports. Fails unless every check passed.
check() {
  local b=$1 in=$2; shift 2
  "$ROOT/e2e/rego/input.sh" "$@" "$b" > "$in"
  "$OPA" eval -f json --ignore '*_test.rego' --ignore testdata -d "$ROOT/policies/rego" \
    -d "hslsa.hbom_schema:$ROOT/hbom/hbom-predicate-v0.1.schema.json" -i "$in" "$query" > "$work/result.json"
  jq -r '.result[0].expressions[0].value[] |
    if .passed then
      "\(.check): PASSED for \(.subject), at \(.levels | join(", "))",
      (.checked[] | "  checked: \(.)"),
      (if (.simulated // []) != [] then "  made from simulated hardware, accepted by the policy (simulated.accept):", (.simulated[] | "    \(.)") else empty end),
      (if (.notRecorded // []) != [] then "  not recorded, and not required by the policy: \(.notRecorded | join("; "))" else empty end)
    else
      "\(.check): FAILED", (.deny[] | "  refused: \(.)")
    end' "$work/result.json"
  jq -e '.result[0].expressions[0].value | length > 0 and all(.passed)' "$work/result.json" > /dev/null
}

# signatures <input>: which trust-root role verified each envelope, as openssl found.
signatures() {
  jq -r '
    def lines($prefix): .files | to_entries[] | select(.value.envelope) |
      "  \($prefix)\(.key): " + (.value.envelope.signedBy | if length > 0 then "verified with a key of " + join(", ") else "no trust-root key verifies its signature" end);
    def tag($prefix): .files | to_entries[] | select(.value.sshSignedBy) |
      "  \($prefix)\(.key) (git tag, ssh-keygen -Y verify): " + (.value.sshSignedBy | if length > 0 then "verified with a key of " + join(", ") else "no trust-root key made its signature" end);
    lines(""), tag(""), (.parts | to_entries[] | .key as $p | .value | lines("\($p)/"), tag("\($p)/"))' "$1"
}

echo "== independent check of $bundle: $(openssl version | cut -d' ' -f1-2), OPA $("$OPA" version | sed -n 's/^Version: //p'), policies/rego"
passed=1
check "$bundle" "$work/input.json" "${args[@]}" > "$work/report.txt" || passed=0
echo "Signatures, checked against the trust root's keys (each part's own, for a part bundle):"
signatures "$work/input.json"
cat "$work/report.txt"
if ((!passed)); then
  echo "FAIL: the bundle did not pass the independent check" >&2
  exit 1
fi
((check_only)) && exit 0

# Refusal cases

echo "== refusal cases: each broken copy of $bundle must be refused, for the stated reason"
keys=$work/keys
mkdir -p "$keys"

# keygen <name>: a P-256 key made for this run only.
keygen() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$keys/$1.key.pem" 2> /dev/null
  openssl pkey -in "$keys/$1.key.pem" -pubout -out "$keys/$1.pub.pem"
}

# enroll <case dir> <role> <name>: list key <name> under <role> in the case's trust root.
enroll() {
  jq --arg role "$2" --rawfile pem "$keys/$3.pub.pem" '.roles[$role] += [$pem]' "$1/trust-root.json" > "$1/trust-root.next"
  mv "$1/trust-root.next" "$1/trust-root.json"
}

# edit <envelope> <jq filter>: rewrite the statement and keep the old signatures.
edit() {
  jq -r .payload "$1" | base64 -d | jq -c "$2" | tr -d '\n' | base64 -w0 > "$work/payload"
  jq --rawfile p "$work/payload" '.payload = $p' "$1" > "$1.next" && mv "$1.next" "$1"
}

# sign <envelope> <key name>: replace the signatures with one by the key, over the DSSE PAE.
sign() {
  local type
  type=$(jq -r .payloadType "$1")
  jq -r .payload "$1" | base64 -d > "$work/body"
  { printf 'DSSEv1 %d %s %d ' "${#type}" "$type" "$(stat -c %s "$work/body")"; cat "$work/body"; } > "$work/pae"
  openssl dgst -sha256 -sign "$keys/$2.key.pem" "$work/pae" | base64 -w0 > "$work/sig"
  jq --rawfile sig "$work/sig" '.signatures = [{keyid: "", sig: $sig}]' "$1" > "$1.next" && mv "$1.next" "$1"
}

# copy <name>: a copy of the bundle, with the trust root and policy the check used.
copy() {
  local c=$work/cases/$1 i
  mkdir -p "$work/cases"
  cp -r "$bundle" "$c"
  for ((i = 0; i < ${#args[@]}; i += 2)); do
    case ${args[i]} in
      --trust-root) cp "${args[i + 1]}" "$c/trust-root.json" ;;
      --policy) cp "${args[i + 1]}" "$c/policy.json" ;;
    esac
  done
  echo "$c"
}

# refuses <what> <reason> <case dir>: the check must fail on the case, naming the reason.
refuses() {
  local what=$1 reason=$2 c=$3 out received=()
  for ((i = 0; i < ${#args[@]}; i += 2)); do
    [[ ${args[i]} == --received ]] && received=(--received "${args[i + 1]}")
  done
  if out=$(check "$c" "$work/case-input.json" "${received[@]}" 2>&1); then
    echo "FAIL: accepted $what" >&2
    exit 1
  fi
  if ! grep -qF -- "refused: $reason" <<< "$out"; then
    echo "FAIL: refused $what, but not because $reason:" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "ok: refuses $what: $reason"
}

keygen other-role
keygen same-role

if ((board)); then
  ship=att/mfg-distribution-EXAMPLE-SHIP-0001.intoto.json
  c=$(copy forged)
  edit "$c/att/mfg-a1-board-assembly.intoto.json" '.predicate.hwMfg.yield.failed = []'
  refuses "an A1 record altered after signing (openssl rejects its signature)" \
    "mfg-a1-board-assembly.intoto.json: no valid signature from role 'ems-site'" "$c"

  c=$(copy wrong-role)
  enroll "$c" dist-broker other-role
  sign "$c/$ship" other-role
  refuses "a distribution record re-signed with a key the trust root lists for the broker" \
    "mfg-distribution-EXAMPLE-SHIP-0001.intoto.json: no valid signature from role 'dist-franchised'" "$c"

  c=$(copy broken-link)
  enroll "$c" ems-site same-role
  edit "$c/att/mfg-a1-board-assembly.intoto.json" \
    '(.predicate.buildDefinition.resolvedDependencies[] | select(.name == "att/mfg-distribution-EXAMPLE-SHIP-0002.intoto.json") | .digest.sha256) |= ("0" * 64)'
  sign "$c/att/mfg-a1-board-assembly.intoto.json" same-role
  refuses "an A1 record, signed by an ems-site key, that links another digest for a shipment" \
    "board-assembly: chain broken, resolvedDependencies do not include shipment record att/mfg-distribution-EXAMPLE-SHIP-0002.intoto.json" "$c"

  c=$(copy board-lot)
  echo DEVB-A-0004 >> "$c/artifacts/board-lot.txt"
  refuses "a board lot list edited after signing (a failed board added)" \
    "board-assembly: board lot list does not match the attested lot digest" "$c"

  c=$(copy part-lot)
  echo PSOC130-A0-00007 >> "$c/parts/picosoc/artifacts/shipped-lot.txt"
  refuses "the chip's shipped lot list edited after signing (a failed unit added)" \
    "parts: PSOC130-QFN64 lot receipt check failed: final-test: shipped lot list does not match the attested lot digest" "$c"
else
  c=$(copy forged)
  edit "$c/att/design-2-synthesis.intoto.json" '.predicate.hwFlow.tools[0].name = "yosys-patched"'
  refuses "a design step altered after signing (openssl rejects its signature)" \
    "design-2-synthesis.intoto.json: no valid signature from role 'flow-platform'" "$c"

  c=$(copy wrong-role)
  enroll "$c" test-site other-role
  sign "$c/att/hbom.intoto.json" other-role
  refuses "an HBOM re-signed with a key the trust root lists for the test site" \
    "hbom.intoto.json: no valid signature from role 'product-owner'" "$c"

  c=$(copy broken-link)
  enroll "$c" fab-site same-role
  edit "$c/att/mfg-f1-wafer-fab.intoto.json" '.predicate.buildDefinition.resolvedDependencies[0].digest.sha256 = ("0" * 64)'
  sign "$c/att/mfg-f1-wafer-fab.intoto.json" same-role
  refuses "a wafer fab record, signed by a fab-site key, that links another digest for the design release" \
    "wafer-fab: chain broken, resolvedDependencies do not include previous step att/design-release.intoto.json" "$c"

  c=$(copy shipped-lot)
  echo PSOC130-A0-00007 >> "$c/artifacts/shipped-lot.txt"
  refuses "a shipped lot list edited after signing (a failed unit added)" \
    "final-test: shipped lot list does not match the attested lot digest" "$c"
fi
rm -rf "$keys"
echo "every broken copy refused; the keys made for these cases are deleted"
