#!/usr/bin/env bash
# End-to-end HSLSA example on a Caliptra part, from RTL to a booted device.
#
#   e2e/caliptra/run.sh fetch     check out caliptra-sw, caliptra-rtl and adams-bridge at the pinned commits
#   e2e/caliptra/run.sh build     build the ROM and firmware with caliptra-builder, and the device model
#   e2e/caliptra/run.sh produce   design steps, firmware provenance, lot, provisioning, HBOM; sign everything
#   e2e/caliptra/run.sh verify    boot the received units, run every check, emit VSAs, verify them with slsa-verifier
#   e2e/caliptra/run.sh all       all of the above
#
# Nothing here uploads to a transparency log: every signature is a DSSE
# envelope made with a local key, as in e2e/run.sh.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
E2E=$ROOT/e2e/caliptra
SRC=$E2E/.src
OUT=${OUT:-$ROOT/out/caliptra}
BUILD=$OUT/build
BUNDLE=$OUT/bundle
DEVICES=$OUT/devices
KEYS=$OUT/keys
DEVICE_BIN=${DEVICE_BIN:-$BUILD/hslsa-caliptra-device}
export PYTHONPATH=$ROOT/tools
hslsa() { python3 -m hslsa "$@"; }
pin() { python3 -c "import json,sys;d=json.load(open('$E2E/caliptra.lock.json'));print(d[sys.argv[1]][sys.argv[2]])" "$@"; }

checkout() {
  local dir=$1 repo=$2 commit=$3
  if [[ ! -d $dir/.git ]]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "$repo"
  fi
  if [[ $(git -C "$dir" rev-parse -q --verify HEAD 2>/dev/null || true) != "$commit" ]]; then
    git -C "$dir" fetch -q --depth 1 origin "$commit"
    git -C "$dir" checkout -q --detach FETCH_HEAD
  fi
  [[ $(git -C "$dir" rev-parse HEAD) == "$commit" ]] || { echo "$dir is not at $commit" >&2; exit 1; }
}

fetch() {
  mkdir -p "$SRC"
  checkout "$SRC/caliptra-sw" "$(pin caliptraSw repo)" "$(pin caliptraSw commit)"
  checkout "$SRC/caliptra-rtl" "$(pin caliptraRtl repo)" "$(pin caliptraRtl commit)"
  checkout "$SRC/caliptra-rtl/submodules/adams-bridge" "$(pin adamsBridge repo)" "$(pin adamsBridge commit)"
  echo "fetch: sources at the pinned commits"
}

# Crates compiled into one firmware image, for its SBOM (same features caliptra-builder passes).
tree() {
  (cd "$SRC/caliptra-sw" && cargo tree -q --locked -p "$1" --target riscv32imc-unknown-none-elf \
    --no-default-features --features "$2" -e normal --prefix none --format '{p}') | sort -u > "$BUILD/tree-$3.txt"
}

build() {
  mkdir -p "$BUILD"
  local sw=$SRC/caliptra-sw
  local cfg="target.'cfg(all())'.rustflags = [\"-Dwarnings\"]"
  # Same recipe as caliptra-sw's own frozen-image check (ci.sh build_rom_images).
  (cd "$sw" && rustc --version > "$BUILD/rustc-version.txt" && rm -rf target/riscv32imc-unknown-none-elf &&
    CALIPTRA_IMAGE_NO_GIT_REVISION=1 cargo --config "$cfg" run -q --locked -p caliptra-builder -- \
      --rom-no-log "$BUILD/caliptra-rom.bin") > "$BUILD/build-rom.log" 2>&1 || { cat "$BUILD/build-rom.log"; exit 1; }
  (cd "$sw" && CALIPTRA_IMAGE_NO_GIT_REVISION=1 cargo --config "$cfg" run -q --locked -p caliptra-builder -- \
      --fw "$BUILD/caliptra-fw-bundle.bin" --fw-svn "$(pin firmware fwSvn)") > "$BUILD/build-fw.log" 2>&1 ||
    { cat "$BUILD/build-fw.log"; exit 1; }
  tree caliptra-rom cfi,riscv rom
  tree caliptra-fmc emu,cfi,riscv fmc
  tree caliptra-runtime emu,fips_self_test,ocp-lock,cfi,riscv runtime

  (cd "$E2E/device" && cargo build -q --locked --release)
  cp "$E2E/device/target/release/hslsa-caliptra-device" "$DEVICE_BIN"
  "$DEVICE_BIN" inspect --fw "$BUILD/caliptra-fw-bundle.bin" --out "$BUILD"
  echo "build: ROM sha384 $(sha384sum "$BUILD/caliptra-rom.bin" | cut -d' ' -f1)"
}

produce() {
  rm -rf "$BUNDLE" "$KEYS" "$DEVICES"
  mkdir -p "$BUNDLE" "$KEYS" "$DEVICES"
  # One key per party; only public halves leave this job.
  hslsa keygen --out "$KEYS" flow-platform tapeout-authority firmware-platform \
    fab-site sort-site osat-site test-site product-owner
  hslsa caliptra ca --keys "$KEYS"
  mkdir -p "$KEYS/pub" && cp "$KEYS"/*.pub.pem "$KEYS/pub/"
  hslsa trust-root --keys "$KEYS/pub" --out "$BUNDLE/trust-root.json"
  cp "$E2E/policy.json" "$BUNDLE/policy.json"

  local lock=$E2E/caliptra.lock.json
  hslsa caliptra firmware --bundle "$BUNDLE" --lock "$lock" --build-dir "$BUILD" --key "$KEYS/firmware-platform.key.pem"
  hslsa caliptra design source-freeze --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/flow-platform.key.pem"
  hslsa caliptra design lint          --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/flow-platform.key.pem"
  hslsa caliptra design rom-merge     --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/flow-platform.key.pem"
  hslsa caliptra design release       --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/tapeout-authority.key.pem" \
    --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json"
  hslsa mfg --bundle "$BUNDLE" --scenario "$E2E/mfg-scenario.json" --keys "$KEYS"
  hslsa caliptra fab --bundle "$BUNDLE" --devices "$DEVICES"
  hslsa caliptra provision --bundle "$BUNDLE" --devices "$DEVICES" --keys "$KEYS" --device-bin "$DEVICE_BIN" \
    --scenario "$E2E/mfg-scenario.json" --lock "$lock"
  hslsa caliptra hbom --bundle "$BUNDLE" --lock "$lock" --scenario "$E2E/mfg-scenario.json" \
    --key "$KEYS/product-owner.key.pem"
}

expect_fail() {
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: accepted $what" >&2
    exit 1
  fi
  echo "ok: rejects $what"
}

boot() {
  "$DEVICE_BIN" boot --rom "$DEVICES/rom.bin" --fw "$2" --fuses "$3" --out "$1" > "$1.trace" 2>&1
}

# The ROM must refuse to load the firmware, with the given Caliptra error code.
expect_refused() {
  local what=$1 code=$2; shift 2
  if boot "$@"; then
    echo "FAIL: the device booted $what" >&2
    exit 1
  fi
  grep -q "fw_err=$((code))\b" "$1.trace" || { echo "FAIL: $what was refused, but not with error $code" >&2; tail -20 "$1.trace" >&2; exit 1; }
  echo "ok: ROM refuses $what (error $code)"
}

verify() {
  local boots=$OUT/boots vsa_dir=$OUT/vsa vkey=$OUT/verifier-key
  rm -rf "$boots" "$vsa_dir" "$vkey" && mkdir -p "$boots" "$vsa_dir" "$vkey"

  echo "== power on the received units"
  while read -r unit; do
    [[ -n $unit ]] || continue
    boot "$boots/$unit" "$DEVICES/$unit/flash.bin" "$DEVICES/$unit/fuses.json"
    echo "$unit: booted to runtime, $(grep -c . "$boots/$unit/boot.log") lines of UART log"
  done < "$E2E/received-units.txt"

  echo "== secure boot refuses altered firmware or fuses"
  local unit tampered=$OUT/tampered
  unit=$(head -1 "$E2E/received-units.txt")
  mkdir -p "$tampered"
  python3 - "$DEVICES/$unit/flash.bin" "$tampered/flash.bin" "$BUNDLE/artifacts/fw-manifest.json" <<'EOF'
import json, sys
data = bytearray(open(sys.argv[1], "rb").read())
rt = json.load(open(sys.argv[3]))["runtime"]
at = len(data) - rt["size"] // 2  # a byte inside the runtime image
data[at] ^= 0x01
open(sys.argv[2], "wb").write(data)
EOF
  expect_refused "a runtime image with one bit flipped" 0x000b0016 "$tampered/rt" "$tampered/flash.bin" "$DEVICES/$unit/fuses.json"
  python3 -c "import json,sys;f=json.load(open(sys.argv[1]));f['vendorPkHash']='00'*48;json.dump(f,open(sys.argv[2],'w'))" \
    "$DEVICES/$unit/fuses.json" "$tampered/fuses.json"
  expect_refused "firmware on a unit fused for another vendor key" 0x000b0003 "$tampered/vk" "$DEVICES/$unit/flash.bin" "$tampered/fuses.json"

  echo "== buyer checks"
  if [[ -n "${HSLSA_VSA_SIGNING_KEY:-}" ]]; then
    echo "VSA signing key: repository secret HSLSA_VSA_SIGNING_KEY"
    (umask 077 && printf '%s\n' "$HSLSA_VSA_SIGNING_KEY" > "$vkey/verifier.key.pem")
  else
    echo "VSA signing key: ephemeral (set the HSLSA_VSA_SIGNING_KEY secret for a stable key)"
    hslsa keygen --out "$vkey" verifier
  fi
  hslsa pubkey --key "$vkey/verifier.key.pem" --out "$vsa_dir/verifier.pub.pem"
  hslsa caliptra verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json" \
    --units "$E2E/received-units.txt" --boots "$boots" --vsa-key "$vkey/verifier.key.pem" --vsa-out "$vsa_dir"

  local sv=${SLSA_VERIFIER:-slsa-verifier} keyid
  keyid=$(hslsa keyid --key "$vsa_dir/verifier.pub.pem")
  local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                --public-key-path "$vsa_dir/verifier.pub.pem" --public-key-id "$keyid")
  subject() { python3 -c "import sys;from hslsa.verify import decode;s=decode(sys.argv[1])['subject'][0];print(s['name'],s['digest']['sha256'])" "$1"; }
  check_vsa() {
    local file=$1 uri=$2; shift 2
    local s; s=$(subject "$vsa_dir/$file")
    local levels=(); for l in "$@"; do levels+=(--verified-level "$l"); done
    "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/$file" --subject-digest "sha256:${s#* }" \
      --resource-uri "${uri:-${s% *}}" "${levels[@]}"
  }
  echo "== slsa-verifier verify-vsa"
  local design_name; design_name=$(subject "$vsa_dir/design.vsa.intoto.json"); design_name=${design_name% *}
  check_vsa design.vsa.intoto.json "hslsa:design:$design_name" HSLSA_DESIGN_LEVEL_1 SLSA_BUILD_LEVEL_1
  check_vsa lot.vsa.intoto.json "" HSLSA_WAFER_LEVEL_2 HSLSA_PACKAGE_TEST_LEVEL_2 HSLSA_DESIGN_LEVEL_1
  check_vsa firmware.vsa.intoto.json "hslsa:firmware:caliptra-fw-bundle.bin" HSLSA_FIRMWARE_LEVEL_2 SLSA_BUILD_LEVEL_2
  while read -r unit; do
    [[ -n $unit ]] || continue
    check_vsa "device-$unit.vsa.intoto.json" "" HSLSA_FIRMWARE_LEVEL_2 HSLSA_PACKAGE_TEST_LEVEL_2
  done < "$E2E/received-units.txt"

  echo "== slsa-verifier negative cases"
  local first; first=$(head -1 "$E2E/received-units.txt")
  [[ -f $vsa_dir/device-$first.vsa.intoto.json ]] || { echo "FAIL: no VSA for $first" >&2; exit 1; }
  expect_fail "Firmware L3 for a device verified at L2" check_vsa "device-$first.vsa.intoto.json" "" HSLSA_FIRMWARE_LEVEL_3
  expect_fail "SLSA Build L3 for the firmware" check_vsa firmware.vsa.intoto.json "hslsa:firmware:caliptra-fw-bundle.bin" SLSA_BUILD_LEVEL_3
  expect_fail "one unit's VSA for another unit" check_vsa "device-$first.vsa.intoto.json" "urn:hslsa:unit:CLP-00006" HSLSA_FIRMWARE_LEVEL_2
  rm -rf "$vkey"
}

case "${1:-}" in
  fetch) fetch ;;
  build) build ;;
  produce) produce ;;
  verify) verify ;;
  all) fetch; build; produce; verify ;;
  *) echo "usage: $0 fetch|build|produce|verify|all" >&2; exit 2 ;;
esac
