#!/usr/bin/env bash
# OpenLane 2 flow for the spm example with a signed record per step.
#
#   openlane2/run.sh produce                     freeze the source, run OpenLane, sign each step as it finishes, sign the release
#   openlane2/run.sh rebuild RELEASE             as a second builder with its own keys: rebuild the release in bundle RELEASE,
#                                                compare every step, and sign the rebuild record
#   openlane2/run.sh verify RELEASE REBUILD      the buyer's tapeout check, with the rebuild record in REBUILD as Design L4 evidence
#   openlane2/run.sh eda-sta                     after produce: signoff STA in OpenROAD's Tcl shell, signed from the
#                                                EDA Tcl hook (adapters/eda-tcl), into the same bundle
#   openlane2/run.sh eda-verify RELEASE          the buyer's check of those records
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

# Signoff STA on OpenLane's final views, run by a Tcl script in OpenROAD with
# the HSLSA hook. The hook writes one event per step; `hslsa eda run` signs it
# on the host, with the same flow-platform key, so the key stays out of the
# container here too. OpenROAD runs its main script itself and replaces Tcl's
# `source`, so neither script can find its own path: HSLSA_HOOK and
# HSLSA_FLOW_SCRIPT name them.
eda_sta() {
  local bundle=$OUT/bundle keys=$OUT/keys
  : "${PDK_ROOT:?set PDK_ROOT to the directory ciel enabled the PDK in}"
  local run_dir last state variant scl hook=$ROOT/adapters/eda-tcl/hslsa.tcl script=$ROOT/openlane2/eda-tcl/signoff-sta.tcl
  run_dir=$(jq -r .runDir "$bundle/openlane/run.json")
  last=$(ls "$run_dir" | grep -E '^[0-9]+-' | sort -n | tail -1)
  state=$run_dir/$last/state_out.json
  variant=$(jq -r .pdk.variant "$LOCK") scl=$(jq -r .pdk.scl "$LOCK")
  export ODB SDC SPEF LIBS OUT_STA=$run_dir/eda-sta HSLSA_HOOK=$hook
  ODB=$(jq -r .odb "$state")
  SDC=$(jq -r .sdc "$state")
  SPEF=$(jq -r '.spef | to_entries[] | select(.key | startswith("nom")) | .value' "$state" | head -n 1)
  LIBS=$PDK_ROOT/$variant/libs.ref/$scl/lib/${scl}__tt_025C_1v80.lib
  rm -rf "$OUT/eda-spool" "$OUT_STA" "$bundle/eda" && mkdir -p "$OUT_STA"
  hslsa eda run --bundle "$bundle" --spool "$OUT/eda-spool" --key "$keys/flow-platform.key.pem" \
    --root "$run_dir" --pdk "$PDK_ROOT/$variant" --image "$(jq -r .openlane.image "$LOCK")" -- \
    docker run --rm --user "$(id -u):$(id -g)" -w /tmp \
      -v "$OUT/work:$OUT/work" -v "$PDK_ROOT:$PDK_ROOT:ro" \
      -v "$hook:$hook:ro" -v "$script:$script:ro" -v "$OUT/eda-spool:$OUT/eda-spool" \
      -e HSLSA_SPOOL -e HSLSA_SYNC -e HSLSA_RUN_ID -e HSLSA_HOOK -e HSLSA_FLOW_SCRIPT="$script" -e ODB -e SDC -e SPEF -e LIBS -e OUT="$OUT_STA" -e HOME=/tmp \
      "$(jq -r .openlane.image "$LOCK")" openroad -exit -no_init "$script"
  # The report travels with the bundle's copy of the run directory.
  rm -rf "$bundle/run/eda-sta" && cp -a "$OUT_STA" "$bundle/run/eda-sta"
  hslsa eda verify --bundle "$bundle" --trust-root "$bundle/trust-root.json" --root "$run_dir" \
    --hook "$hook" --pdk "$PDK_ROOT/$variant" --require-steps signoff
}

eda_verify() {
  local release=${1:?the released bundle}
  hslsa eda verify --bundle "$release" --trust-root "$release/trust-root.json" --root "$release/run" \
    --hook "$ROOT/adapters/eda-tcl/hslsa.tcl" --require-steps signoff
}

case "${1:-}" in
  produce) produce ;;
  eda-sta) eda_sta ;;
  eda-verify) shift; eda_verify "$@" ;;
  rebuild) shift; rebuild "$@" ;;
  verify) shift; verify "$@" ;;
  *) echo "usage: $0 produce | rebuild <release-bundle> | verify <release-bundle> <rebuild-dir> | eda-sta | eda-verify <release-bundle>" >&2; exit 2 ;;
esac
