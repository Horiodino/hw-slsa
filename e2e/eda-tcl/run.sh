#!/usr/bin/env bash
# The EDA Tcl adapter on PicoRV32: lint and synthesis in Yosys's Tcl shell,
# each step signed from the hook as it ends, then the buyer's check.
#
#   e2e/eda-tcl/run.sh            freeze the source, run the flow under the signer, check the records
#
# Needs yosys. Signing uses a local ECDSA P-256 key; nothing is uploaded.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/e2e/eda-tcl
LOCK=$ROOT/e2e/picorv32/inputs.lock.json
OUT=${OUT:-$ROOT/out}/eda-tcl
HOOK=$ROOT/adapters/eda-tcl/hslsa.tcl
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

bundle=$OUT/bundle keys=$OUT/keys work=$OUT/work
rm -rf "$bundle" "$keys" "$work" "$OUT/spool"
mkdir -p "$bundle" "$keys/pub" "$work/src"
hslsa keygen --out "$keys" flow-platform
cp "$keys"/*.pub.pem "$keys/pub/"
hslsa trust-root --keys "$keys/pub" --out "$bundle/trust-root.json"

hslsa design source-freeze --bundle "$bundle" --lock "$LOCK" --key "$keys/flow-platform.key.pem" --cache "${OUT%/eda-tcl}/cache"
tar -xf "$bundle/artifacts/source.tar" -C "$work/src"

# The flow runs in the tool; the signer runs around it and holds the key.
SRC=$work/src OUT=$work/out HSLSA_HOOK=$HOOK \
  hslsa eda run --bundle "$bundle" --spool "$OUT/spool" --key "$keys/flow-platform.key.pem" --root "$work" \
    -- yosys -q -c "$HERE/picorv32.tcl"
rm -rf "$keys"

hslsa eda verify --bundle "$bundle" --trust-root "$bundle/trust-root.json" --root "$work" \
  --hook "$HOOK" --require-steps simulation,synthesis
