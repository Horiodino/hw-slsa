#!/usr/bin/env bash
# OpenLane 2 flow for the spm example with a signed record per step.
#
#   openlane2/run.sh produce   freeze the source, run OpenLane, sign each step as it finishes, sign the release
#   openlane2/run.sh compare A B   verify two produced runs and measure how close they are to bit-exact
#
# Needs docker, the pinned image and the SKY130 PDK enabled under $PDK_ROOT
# (see .github/workflows/openlane2-flow.yml). Signing uses local ECDSA P-256
# keys in DSSE envelopes; nothing is uploaded to a transparency log.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK=$ROOT/openlane2/spm/flow.lock.json
OUT=${OUT:-$ROOT/out/openlane2}
export PYTHONPATH=$ROOT/tools
hslsa() { python3 -m hslsa "$@"; }

produce() {
  local bundle=$OUT/bundle keys=$OUT/keys work=$OUT/work
  : "${PDK_ROOT:?set PDK_ROOT to the directory ciel enabled the PDK in}"
  rm -rf "$bundle" "$keys" "$work"
  mkdir -p "$bundle" "$keys/pub" "$work"
  hslsa keygen --out "$keys" flow-platform tapeout-authority
  cp "$keys"/*.pub.pem "$keys/pub/"
  hslsa trust-root --keys "$keys/pub" --out "$bundle/trust-root.json"

  hslsa design source-freeze --bundle "$bundle" --lock "$LOCK" --key "$keys/flow-platform.key.pem" --cache "$OUT/cache"
  hslsa openlane run --bundle "$bundle" --lock "$LOCK" --key "$keys/flow-platform.key.pem" \
    --work "$work" --pdk-root "$PDK_ROOT"
  local run_dir
  run_dir=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['runDir'])" "$bundle/openlane/run.json")
  hslsa openlane release --bundle "$bundle" --run-dir "$run_dir" --lock "$LOCK" \
    --key "$keys/tapeout-authority.key.pem" --trust-root "$bundle/trust-root.json"
  hslsa openlane verify --bundle "$bundle" --run-dir "$run_dir" --trust-root "$bundle/trust-root.json"
  # The run directory travels with the bundle so a second party can check every subject.
  rm -rf "$bundle/run" && cp -a "$run_dir" "$bundle/run"
}

compare() {
  local a=${1:?first run} b=${2:?second run} report=$OUT/report
  rm -rf "$report" && mkdir -p "$report"
  hslsa keygen --out "$report/keys" rebuilder
  hslsa openlane compare --bundle "$a" --run-dir "$a/run" --trust-root "$a/trust-root.json" \
    --other-bundle "$b" --other-run-dir "$b/run" --key "$report/keys/rebuilder.key.pem" --report "$report"
  cp "$report/keys/rebuilder.pub.pem" "$report/" && rm -rf "$report/keys"
}

case "${1:-}" in
  produce) produce ;;
  compare) shift; compare "$@" ;;
  *) echo "usage: $0 produce | compare <bundle-a> <bundle-b>" >&2; exit 2 ;;
esac
