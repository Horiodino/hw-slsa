#!/usr/bin/env bash
# End-to-end HSLSA example on a Caliptra part, from RTL to a booted device.
#
#   e2e/caliptra/run.sh fetch     check out caliptra-sw, caliptra-rtl and adams-bridge at the pinned commits
#   e2e/caliptra/run.sh build     build the ROM and firmware with caliptra-builder, and the device model
#   e2e/caliptra/run.sh produce   design steps, firmware provenance, lot, provisioning, HBOM; sign everything
#   e2e/caliptra/run.sh verify    boot the received units, run every check, emit VSAs, verify them with slsa-verifier
#   e2e/caliptra/run.sh all       all of the above
#
#   e2e/caliptra/run.sh build-rtl   Verilate the released design into a second device model (after produce)
#   e2e/caliptra/run.sh verify-rtl  on the RTL, for RTL_UNITS received units (default 1): with RTL_STAGE=identity
#                                   (default) run the ROM until it exports the IDevID CSR and check the key;
#                                   with RTL_STAGE=boot boot to runtime and run the same checks as verify
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
DEVICE_RTL_BIN=${DEVICE_RTL_BIN:-$BUILD/hslsa-caliptra-device-rtl}
# The Go reference tool; set HSLSA to use a prebuilt binary instead of building it here.
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }
# Veraison's CoRIM command line tool, at a commit on its main branch (it has no release yet).
COCLI_VERSION=${COCLI_VERSION:-v1.0.0-alpha0.0.20260924140712-c8c31ce6af05}
pin() { jq -r --arg a "$1" --arg b "$2" '.[$a][$b]' "$E2E/caliptra.lock.json"; }

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
  rm -rf "$BUNDLE" "$KEYS" "$DEVICES" "$OUT/station"
  mkdir -p "$BUNDLE" "$KEYS" "$DEVICES"
  # One key per party; only public halves leave this job.
  hslsa keygen --out "$KEYS" flow-platform tapeout-authority firmware-platform \
    fab-site sort-site osat-site test-site product-owner review-provider
  hslsa caliptra ca --keys "$KEYS"
  mkdir -p "$KEYS/pub" && cp "$KEYS"/*.pub.pem "$KEYS/pub/"
  hslsa trust-root --keys "$KEYS/pub" --out "$BUNDLE/trust-root.json"
  cp "$E2E/policy.json" "$BUNDLE/policy.json"

  local lock=$E2E/caliptra.lock.json
  hslsa caliptra firmware --bundle "$BUNDLE" --lock "$lock" --build-dir "$BUILD" --key "$KEYS/firmware-platform.key.pem"
  hslsa caliptra design source-freeze --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/flow-platform.key.pem"
  hslsa caliptra design simulation    --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/flow-platform.key.pem"
  hslsa caliptra design rom-merge     --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/flow-platform.key.pem"
  hslsa caliptra design release       --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/tapeout-authority.key.pem" \
    --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json"
  hslsa mfg --bundle "$BUNDLE" --scenario "$E2E/mfg-scenario.json" --keys "$KEYS"
  hslsa caliptra fab --bundle "$BUNDLE" --devices "$DEVICES"
  # Final test: the test house's station runs a job and writes its own export;
  # the provisioning adapter clears the job's image before it runs and signs
  # one record per unit from the export afterwards.
  local station=(--profile "$ROOT/e2e/stations/xg8-profile.json" --station "$E2E/station/ps-01.json" --export "$OUT/station")
  hslsa caliptra job     --bundle "$BUNDLE" --scenario "$E2E/mfg-scenario.json" --export "$OUT/station"
  hslsa provision gate   --bundle "$BUNDLE" "${station[@]}"
  hslsa caliptra station --bundle "$BUNDLE" --devices "$DEVICES" --keys "$KEYS" --device-bin "$DEVICE_BIN" \
    --scenario "$E2E/mfg-scenario.json" --lock "$lock" --export "$OUT/station"
  hslsa provision adapt  --bundle "$BUNDLE" "${station[@]}" --key "$KEYS/test-site.key.pem"
  hslsa caliptra hbom --bundle "$BUNDLE" --lock "$lock" --scenario "$E2E/mfg-scenario.json" \
    --key "$KEYS/product-owner.key.pem"
  # Simulated: no review provider has reviewed these images. See docs/caliptra-e2e.md.
  hslsa caliptra review --bundle "$BUNDLE" --lock "$lock" --key "$KEYS/review-provider.key.pem"
}

# The fab for the RTL boot: build the device from the released design itself.
# hslsa unpacks the released design and adds the testbench, coverage and
# assertion files caliptra-rtl's Verilator harness reads, refusing any that
# would replace a released file. caliptra-sw's hw-model then Verilates that
# tree in place of its own caliptra-rtl submodule.
build_rtl() {
  local model=$BUILD/rtl-model sw=$SRC/caliptra-sw
  hslsa caliptra rtl-model --bundle "$BUNDLE" --lock "$E2E/caliptra.lock.json" --out "$model/rtl"
  [[ -L $sw/hw/latest/rtl ]] || rmdir "$sw/hw/latest/rtl"
  ln -sfn "$model/rtl" "$sw/hw/latest/rtl"
  # Never reuse a model Verilated from another tree.
  rm -rf "$sw/hw/verilated/out"
  # caliptra-sw fw-2.1.3's harness, not part of the design, passes two wide
  # inputs to memcpy as pointers; Verilator 5.052 wraps wide signals in VlWide,
  # so pass its data(), which 5.020 also has.
  sed -i 's/memcpy(result->v\.\(cptra_obf_key\|cptra_csr_hmac_key\), /memcpy(result->v.\1.data(), /' \
    "$sw/hw/verilated/caliptra_verilated.cpp"
  # caliptra-sw's harness builds one thread with -Os. A thread per core, up
  # to 4, Verilator's -O3 and the C++ compiler's -O3 -march=native boot
  # faster: on four cores two threads ran 3,450 cycles a second and four
  # 4,570, and the two -O3s with -march=native added about 10%. The model
  # runs on the machine that built it. None of this changes the design.
  local threads=${RTL_THREADS:-$(( $(nproc) < 4 ? $(nproc) : 4 ))}
  local vflags="--threads $threads -O3" cflags="-O3 -march=native"
  { verilator --version; echo "Verilator $vflags, C++ $cflags"; } | tee "$BUILD/verilator-version.txt"

  # With RTL_MODEL_CACHE set, a model built earlier on this machine is reused
  # when everything it was built from is the same: the released design's
  # digest and every bench file's, the caliptra-sw commit and harness change,
  # the device tool, the compilers, the build options and the CPU model.
  local key cached=
  if [[ -n ${RTL_MODEL_CACHE:-} ]]; then
    key=$({ cat "$model/rtl.json" "$BUILD/verilator-version.txt"
            git -C "$sw" rev-parse HEAD && git -C "$sw" diff
            (cd "$E2E/device" && cat Cargo.toml Cargo.lock rust-toolchain.toml src/*.rs && rustc -Vv)
            g++ --version | sed -n 1p; grep -m1 '^model name' /proc/cpuinfo; } | sha256sum | cut -c1-64)
    cached=$RTL_MODEL_CACHE/$key/hslsa-caliptra-device
  fi
  if [[ -n $cached && -x $cached ]]; then
    cp "$cached" "$DEVICE_RTL_BIN"
    echo "model: reused, built $(date -u -r "$cached" +%FT%TZ) from the same inputs (key $key)" | tee -a "$BUILD/verilator-version.txt"
    echo "build-rtl: device model Verilated from the released design, reused from this machine's cache"
    return
  fi
  (cd "$E2E/device" &&
    MAKEFLAGS="VERILATOR_MAKE_FLAGS=OPT_FAST=\"${cflags// /\\ }\" EXTRA_VERILATOR_FLAGS=${vflags// /\\ }" \
    CALIPTRA_VERILATOR_JOBS=$(nproc) cargo build -q --locked --release --features verilator --target-dir "$BUILD/rtl-target")
  cp "$BUILD/rtl-target/release/hslsa-caliptra-device" "$DEVICE_RTL_BIN"
  if [[ -n $cached ]]; then
    mkdir -p "${cached%/*}"
    cp "$DEVICE_RTL_BIN" "$cached.tmp" && mv "$cached.tmp" "$cached"
    # Keep the three newest models.
    ls -1dt "$RTL_MODEL_CACHE"/*/ | tail -n +4 | xargs -r rm -rf
    echo "model: built now, cached (key $key)" | tee -a "$BUILD/verilator-version.txt"
  fi
  echo "build-rtl: device model Verilated from the released design"
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
  if [[ -n ${RTL:-} ]]; then
    # An RTL boot takes hours; show its progress lines as they come.
    "$DEVICE_BIN" boot --rom "$DEVICES/rom.bin" --fw "$2" --fuses "$3" --out "$1" 2>&1 | tee "$1.trace" | grep --line-buffered '^boot:'
    return "${PIPESTATUS[0]}"
  fi
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
  local units=${UNITS:-$E2E/received-units.txt} boots=$OUT/boots${RTL:+-rtl} vsa_dir=$OUT/vsa${RTL:+-rtl} vkey=$OUT/verifier-key
  rm -rf "$boots" "$vsa_dir" "$vkey" && mkdir -p "$boots" "$vsa_dir" "$vkey"

  echo "== power on the received units"
  while read -r unit; do
    [[ -n $unit ]] || continue
    boot "$boots/$unit" "$DEVICES/$unit/flash.bin" "$DEVICES/$unit/fuses.json"
    echo "$unit: booted to runtime on $(jq -r .model "$boots/$unit/device.json"), $(grep -c . "$boots/$unit/boot.log") lines of UART log"
  done < "$units"

  # On the RTL each refused boot would take hours more; the emulator run covers them.
  [[ -n ${RTL:-} ]] || refusals
  buyer_checks "$units" "$boots" "$vsa_dir" "$vkey"
}

refusals() {
  echo "== secure boot refuses altered firmware or fuses"
  local unit tampered=$OUT/tampered
  unit=$(head -1 "$E2E/received-units.txt")
  mkdir -p "$tampered"
  # Flip one bit in a byte inside the runtime image.
  cp "$DEVICES/$unit/flash.bin" "$tampered/flash.bin"
  local at byte
  at=$(( $(stat -c %s "$tampered/flash.bin") - $(jq .runtime.size "$BUNDLE/artifacts/fw-manifest.json") / 2 ))
  byte=$(od -An -tu1 -j "$at" -N1 "$tampered/flash.bin" | tr -d ' ')
  printf "$(printf '\\x%02x' $(( byte ^ 1 )))" | dd of="$tampered/flash.bin" bs=1 seek="$at" conv=notrunc status=none
  expect_refused "a runtime image with one bit flipped" 0x000b0016 "$tampered/rt" "$tampered/flash.bin" "$DEVICES/$unit/fuses.json"
  jq --arg zero "$(printf '0%.0s' $(seq 96))" '.vendorPkHash = $zero' "$DEVICES/$unit/fuses.json" > "$tampered/fuses.json"
  expect_refused "firmware on a unit fused for another vendor key" 0x000b0003 "$tampered/vk" "$DEVICES/$unit/flash.bin" "$tampered/fuses.json"
}

# The firmware CoRIM on its own: the reference values, each booted unit's
# alias certificates appraised against them, and the same file decoded and
# validated by Veraison's cocli, a CoRIM tool this project did not write.
corim_checks() {
  local units=$1 boots=$2 unit corim=$BUNDLE/artifacts/caliptra-fw.corim
  echo "== the firmware CoRIM"
  hslsa corim show --corim "$corim" --trust-root "$BUNDLE/trust-root.json" --role firmware-platform
  while read -r unit; do
    [[ -n $unit ]] || continue
    hslsa corim appraise --corim "$corim" --trust-root "$BUNDLE/trust-root.json" --role firmware-platform \
      "$boots/$unit/fmc-alias-ecc384.der" "$boots/$unit/rt-alias-ecc384.der" | sed "s/^/$unit: /"
  done < "$units"
  echo "== Veraison cocli reads the CoRIM"
  local shown=$boots/cocli-corim-display.txt
  # Outside this module, so go run builds cocli from its own go.mod.
  (cd "${TMPDIR:-/tmp}" && go run "github.com/veraison/cocli@$COCLI_VERSION" corim display --file "$corim" --show-tags) > "$shown" 2>&1 ||
    { cat "$shown" >&2; echo "FAIL: cocli $COCLI_VERSION could not decode the CoRIM" >&2; exit 1; }
  # cocli falls back to an unsigned CoRIM, and skips a CoMID it cannot decode, without failing.
  if ! grep -q '^Meta:' "$shown" || grep -q 'skipping malformed\|unmatched CBOR tag' "$shown"; then
    cat "$shown" >&2; echo "FAIL: cocli $COCLI_VERSION did not read a signed CoRIM with one CoMID" >&2; exit 1
  fi
  echo "cocli $COCLI_VERSION: decoded the signed CoRIM and its CoMID, $(grep -c '"environment"' "$shown") reference values (${shown#"$ROOT/"})"
}

# The simulated S.A.F.E. reports on their own: each is shown, and checked
# against its image; a report for one image must not pass for another.
review_checks() {
  local trust=$BUNDLE/trust-root.json policy=$BUNDLE/policy.json rom fmc
  echo "== S.A.F.E. reports (simulated review provider)"
  hslsa safe show --report "$BUNDLE/review/caliptra-fmc.sfr.cose" --trust-root "$trust"
  fmc=$(jq -r '.subject[] | select(.name == "caliptra-fmc.bin") | .digest.sha384' <(hslsa_payload "$BUNDLE/att/fw-bundle.intoto.json"))
  rom=$(jq -r '.subject[0].digest.sha384' <(hslsa_payload "$BUNDLE/att/fw-rom.intoto.json"))
  hslsa safe check --report "$BUNDLE/review/caliptra-fmc.sfr.cose" --trust-root "$trust" --policy "$policy" --digest "sha384:$fmc"
  hslsa safe check --report "$BUNDLE/review/caliptra-rom.sfr.jws" --trust-root "$trust" --policy "$policy" --digest "sha384:$rom"
  expect_fail "the FMC's report for the ROM" hslsa safe check --report "$BUNDLE/review/caliptra-fmc.sfr.cose" \
    --trust-root "$trust" --policy "$policy" --digest "sha384:$rom"
}

# The in-toto statement inside a DSSE envelope.
hslsa_payload() { jq -r .payload "$1" | base64 -d; }

buyer_checks() {
  local units=$1 boots=$2 vsa_dir=$3 vkey=$4
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
    --units "$units" --boots "$boots" --vsa-key "$vkey/verifier.key.pem" --vsa-out "$vsa_dir"
  corim_checks "$units" "$boots"
  review_checks


  local sv=${SLSA_VERIFIER:-slsa-verifier} keyid
  keyid=$(hslsa keyid --key "$vsa_dir/verifier.pub.pem")
  local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                --public-key-path "$vsa_dir/verifier.pub.pem" --public-key-id "$keyid")
  subject() { hslsa subject "$1"; }
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
  done < "$units"

  echo "== slsa-verifier negative cases"
  local first; first=$(head -1 "$units")
  [[ -f $vsa_dir/device-$first.vsa.intoto.json ]] || { echo "FAIL: no VSA for $first" >&2; exit 1; }
  expect_fail "Firmware L3 for a device verified at L2" check_vsa "device-$first.vsa.intoto.json" "" HSLSA_FIRMWARE_LEVEL_3
  expect_fail "SLSA Build L3 for the firmware" check_vsa firmware.vsa.intoto.json "hslsa:firmware:caliptra-fw-bundle.bin" SLSA_BUILD_LEVEL_3
  expect_fail "one unit's VSA for another unit" check_vsa "device-$first.vsa.intoto.json" "urn:hslsa:unit:CLP-00006" HSLSA_FIRMWARE_LEVEL_2
  rm -rf "$vkey"
}

# The ROM alone, on the RTL: each unit, in the Manufacturing lifecycle,
# derives its IDevID key from its fuses and exports a CSR. The key must be the
# one the identity CA endorsed from the CSR the programming station read.
rtl_identity() {
  local units=$1 dir=$OUT/identity-rtl unit csr cert
  rm -rf "$dir" && mkdir -p "$dir"
  echo "== the RTL derives each unit's IDevID key"
  while read -r unit; do
    [[ -n $unit ]] || continue
    jq '.lifecycle = "manufacturing"' "$DEVICES/$unit/fuses.json" > "$dir/$unit.fuses.json"
    "$DEVICE_BIN" csr --rom "$DEVICES/rom.bin" --fuses "$dir/$unit.fuses.json" --out "$dir/$unit" 2>&1 |
      tee "$dir/$unit.trace" | grep --line-buffered '^boot:\|^csr:'
    [[ ${PIPESTATUS[0]} == 0 ]] || { echo "FAIL: $unit exported no IDevID CSR on the RTL" >&2; tail -20 "$dir/$unit.trace" >&2; exit 1; }
    csr=$dir/$unit/idevid-csr-ecc384.der cert=$BUNDLE/artifacts/identity/$unit.idevid.der
    openssl req -inform der -in "$csr" -verify -noout 2>/dev/null ||
      { echo "FAIL: $unit: the RTL's CSR does not verify under its own key" >&2; exit 1; }
    if [[ $(openssl req -inform der -in "$csr" -pubkey -noout) != $(openssl x509 -inform der -in "$cert" -pubkey -noout) ]]; then
      echo "FAIL: $unit: the RTL derives a different IDevID key from the one the identity CA endorsed" >&2
      exit 1
    fi
    if cmp -s "$csr" "$BUNDLE/artifacts/identity/$unit.csr.der"; then
      echo "$unit: the RTL derives the endorsed IDevID key; its CSR is byte for byte the one read at test"
    else
      echo "$unit: the RTL derives the endorsed IDevID key"
    fi
  done < "$units"
}

verify_rtl() {
  local units=$OUT/rtl-units.txt
  head -"${RTL_UNITS:-1}" "$E2E/received-units.txt" > "$units"
  DEVICE_BIN=$DEVICE_RTL_BIN
  case ${RTL_STAGE:-identity} in
    identity) rtl_identity "$units" ;;
    boot) RTL=1 UNITS=$units verify ;;
    *) echo "RTL_STAGE must be identity or boot" >&2; exit 2 ;;
  esac
}

case "${1:-}" in
  fetch) fetch ;;
  build) build ;;
  produce) produce ;;
  verify) verify ;;
  all) fetch; build; produce; verify ;;
  build-rtl) build_rtl ;;
  verify-rtl) verify_rtl ;;
  *) echo "usage: $0 fetch|build|produce|verify|all|build-rtl|verify-rtl" >&2; exit 2 ;;
esac
