#!/usr/bin/env bash
# OpenLane 2 flow for the spm example with a signed record per step.
#
#   openlane2/run.sh produce                     freeze the source, run OpenLane, sign each step as it finishes, sign the release
#   openlane2/run.sh rebuild RELEASE             as a second builder with its own keys: rebuild the release in bundle RELEASE,
#                                                compare every step, and sign the rebuild record
#   openlane2/run.sh verify RELEASE REBUILD      the buyer's tapeout check, with the rebuild record in REBUILD as Design L4 evidence
#
# Needs docker, the pinned image and the SKY130 PDK enabled under $PDK_ROOT
# (see .github/workflows/openlane2-flow.yml). Signing uses local ECDSA P-256
# keys in DSSE envelopes; nothing is uploaded to a transparency log.
#
# OpenLane writes absolute paths into its state files, so a rebuild matches the
# release byte for byte only when it runs at the same checkout and PDK_ROOT paths.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LOCK=$ROOT/openlane2/spm/flow.lock.json
OUT=${OUT:-$ROOT/out/openlane2}
# The Go reference tool; set HSLSA to use a prebuilt binary instead of building it here.
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

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
  run_dir=$(jq -r .runDir "$bundle/openlane/run.json")
  hslsa openlane release --bundle "$bundle" --run-dir "$run_dir" --lock "$LOCK" \
    --key "$keys/tapeout-authority.key.pem" --trust-root "$bundle/trust-root.json"
  hslsa openlane verify --bundle "$bundle" --run-dir "$run_dir" --trust-root "$bundle/trust-root.json"
  # The run directory travels with the bundle so a second party can check every subject.
  rm -rf "$bundle/run" && cp -a "$run_dir" "$bundle/run"
}

rebuild() {
  local release=${1:?the released bundle to rebuild} report=$OUT/report
  release=$(cd "$release" && pwd)
  mkdir -p "$OUT"
  case $release/ in "$(cd "$OUT" && pwd)"/*)
    echo "move the release bundle out of $OUT first; the rebuild runs there" >&2; exit 2 ;;
  esac
  # The rebuilder signs as itself, not as the platform that ran the flow.
  export HSLSA_BUILDER_ID=${HSLSA_BUILDER_ID:-https://github.com/Horiodino/hw-slsa/local-rebuild}

  # Check the release before spending a build on it, then run the same flow
  # from the pinned inputs under this builder's own flow and release keys.
  hslsa openlane verify --bundle "$release" --run-dir "$release/run" --trust-root "$release/trust-root.json"
  produce

  # The rebuild record is signed with a key only the rebuilder holds, in a trust root of its own.
  rm -rf "$report" "$OUT/rebuilder-keys" && mkdir -p "$report"
  hslsa keygen --out "$OUT/rebuilder-keys" rebuilder
  mkdir -p "$OUT/rebuilder-keys/pub" && cp "$OUT/rebuilder-keys/rebuilder.pub.pem" "$OUT/rebuilder-keys/pub/"
  hslsa trust-root --keys "$OUT/rebuilder-keys/pub" --out "$report/rebuilder-trust-root.json"
  hslsa openlane compare --bundle "$release" --run-dir "$release/run" --trust-root "$release/trust-root.json" \
    --other-bundle "$OUT/bundle" --other-run-dir "$OUT/bundle/run" \
    --key "$OUT/rebuilder-keys/rebuilder.key.pem" --report "$report"
  rm -rf "$OUT/rebuilder-keys"
}

verify() {
  local release=${1:?the released bundle} rebuild=${2:?the rebuild report directory}
  hslsa openlane verify --bundle "$release" --run-dir "$release/run" --trust-root "$release/trust-root.json" \
    --rebuild "$rebuild/rebuild.intoto.json" --rebuild-trust-root "$rebuild/rebuilder-trust-root.json" \
    --rebuild-check "${REBUILD_CHECK:-gds-bit-exact}"
}

case "${1:-}" in
  produce) produce ;;
  rebuild) shift; rebuild "$@" ;;
  verify) shift; verify "$@" ;;
  *) echo "usage: $0 produce | rebuild <release-bundle> | verify <release-bundle> <rebuild-dir>" >&2; exit 2 ;;
esac
