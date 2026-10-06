#!/usr/bin/env bash
# FPGA board example: an iCE40 board whose root of trust verifies the
# bitstream and firmware in flash before it lets the FPGA out of reset.
#
#   e2e/fpga/run.sh produce   the root of trust vendor's chain, the board owner's FPGA design and
#                             flash image, the board chain and the EMS's per-board provisioning
#   e2e/fpga/run.sh boot      power on the received boards (root of trust, then the SoC in RTL simulation)
#   e2e/fpga/run.sh verify    every buyer check, VSAs, slsa-verifier
#   e2e/fpga/run.sh l3        the whole chain again at Firmware L3 and Assembly L3, with the root of
#                             trust's lot at Wafer L3 and Package/Test L3, and what Firmware L3 refuses
#   e2e/fpga/run.sh l4        the chain at Firmware L4 and Assembly L4, with the root of trust's lot at
#                             Wafer L4 and Package/Test L4: an independent rebuilder and an inspection lab
#   e2e/fpga/run.sh aftersale on a copy of produce and boot: a field update with new firmware, a board
#                             returned, reworked and shipped again, and what the after-sale check refuses
#
# Needs: Go, yosys, nextpnr-ice40, icestorm (icepack, iceunpack, icetime and
# its chip database), iverilog, a RISC-V GCC, git and ssh-keygen; l3 and l4
# also need bubblewrap and SoftHSM2. Same privacy
# rules as the other examples: local ECDSA P-256 keys in DSSE envelopes,
# nothing uploaded to a transparency log.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/e2e/fpga
OUT=${OUT:-$ROOT/out}/fpga
ROT=$OUT/rot
ROT_KEYS=$OUT/rot-keys
DESIGN=$OUT/design
BUNDLE=$OUT/board
KEYS=$OUT/keys
CACHE=${CACHE:-$ROOT/out/cache}
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

# The root of trust vendor: its die is the PicoRV32 example's design, so its
# chip chain is that example's flow under its own product name, plus its
# firmware, its per-unit provisioning and a chip HBOM with the firmware listed.
produce_rot() {
  rm -rf "$ROT" "$ROT_KEYS" "$OUT/rot-devices" "$OUT/rot-station"
  mkdir -p "$ROT" "$ROT_KEYS/pub"
  hslsa keygen --out "$ROT_KEYS" ip-vendor source-owner source-reviewer flow-platform tapeout-authority \
    fab-site sort-site osat-site test-site product-owner firmware-platform code-signer
  hslsa caliptra ca --keys "$ROT_KEYS" --name "Example RoT Co EXR-01 IDevID CA"
  cp "$ROT_KEYS"/*.pub.pem "$ROT_KEYS/pub/"
  hslsa trust-root --keys "$ROT_KEYS/pub" --out "$ROT/trust-root.json"
  cp "$HERE/rot/policy.json" "$ROT/policy.json"
  rot_design "$ROT" "$ROT_KEYS"
  hslsa mfg --bundle "$ROT" --scenario "$HERE/rot/mfg-scenario.json" --keys "$ROT_KEYS"
  hslsa fpga rot-firmware  --bundle "$ROT" --src "$HERE/rot/firmware" --key "$ROT_KEYS/firmware-platform.key.pem" \
    --code-signer "$ROT_KEYS/code-signer.key.pem" --svn 1
  rot_station "$ROT" "$ROT_KEYS" "$OUT/rot-devices" "$OUT/rot-station" "$HERE/rot/mfg-scenario.json"
  # The identity CA's private key stays with the vendor.
  rm -f "$ROT_KEYS/identity-ca.key.pem"
}

# rot_design <bundle> <keys>: the root of trust vendor's design flow, up to the release.
rot_design() {
  local b=$1 k=$2 lock=$ROOT/e2e/picorv32/inputs.lock.json
  hslsa design ip-release    --bundle "$b" --lock "$lock" --key "$k/ip-vendor.key.pem" --cache "$CACHE"
  hslsa design source-tag    --bundle "$b" --lock "$lock" --key "$k/source-owner.key.pem" --cache "$CACHE"
  hslsa design review        --bundle "$b" --lock "$lock" --key "$k/source-reviewer.key.pem"
  hslsa design source-freeze --bundle "$b" --lock "$lock" --key "$k/flow-platform.key.pem" --cache "$CACHE" \
    --trust-root "$b/trust-root.json" --policy "$b/policy.json"
  hslsa design simulation    --bundle "$b" --lock "$lock" --key "$k/flow-platform.key.pem"
  hslsa design synthesis     --bundle "$b" --lock "$lock" --key "$k/flow-platform.key.pem"
  hslsa design release       --bundle "$b" --lock "$lock" --key "$k/tapeout-authority.key.pem" \
    --trust-root "$b/trust-root.json" --policy "$b/policy.json"
}

# rot_station <bundle> <keys> <devices> <export> <scenario>: final test. The
# test house's station runs a job and writes its own export; the provisioning
# adapter clears the job's images before it runs and signs one record per unit
# from the export afterwards. Then the vendor's chip HBOM.
rot_station() {
  local b=$1 k=$2 devices=$3 export=$4 scenario=$5
  local station=(--profile "$ROOT/e2e/stations/xg8-profile.json" --station "$HERE/rot/station/ps-02.json" --export "$export")
  hslsa fpga rot-job       --bundle "$b" --scenario "$scenario" --export "$export"
  hslsa provision gate     --bundle "$b" "${station[@]}"
  hslsa fpga rot-station   --bundle "$b" --devices "$devices" --keys "$k" --export "$export"
  hslsa provision adapt    --bundle "$b" "${station[@]}" --key "$k/test-site.key.pem"
  hslsa fpga rot-hbom      --bundle "$b" --lock "$ROOT/e2e/picorv32/inputs.lock.json" --scenario "$scenario" --key "$k/product-owner.key.pem"
}

# The board owner: its FPGA design, the SoC firmware and the flash image.
produce_design() {
  rm -rf "$DESIGN" "$KEYS"
  mkdir -p "$DESIGN" "$KEYS/pub"
  # One trust root for the board owner (also the FPGA design house), the EMS and the shippers.
  hslsa keygen --out "$KEYS" ip-vendor source-owner source-reviewer flow-platform tapeout-authority \
    firmware-platform code-signer board-owner ems-site dist-franchised pcb-fab
  cp "$KEYS"/*.pub.pem "$KEYS/pub/"
  hslsa trust-root --keys "$KEYS/pub" --out "$DESIGN/trust-root.json"
  cp "$HERE/policy.json" "$DESIGN/policy.json"
  board_design "$DESIGN" "$KEYS"
}

# board_design <bundle> <keys> [--isolate]: the FPGA design flow, the SoC
# firmware (built in the sandbox with --isolate) and the flash image.
board_design() {
  local b=$1 k=$2 lock=$HERE/inputs.lock.json
  shift 2
  cp "$lock" "$b/inputs.lock.json"
  hslsa design ip-release    --bundle "$b" --lock "$lock" --key "$k/ip-vendor.key.pem" --cache "$CACHE"
  hslsa design source-tag    --bundle "$b" --lock "$lock" --key "$k/source-owner.key.pem" --cache "$CACHE"
  hslsa design review        --bundle "$b" --lock "$lock" --key "$k/source-reviewer.key.pem"
  hslsa design source-freeze --bundle "$b" --lock "$lock" --key "$k/flow-platform.key.pem" --cache "$CACHE" \
    --trust-root "$b/trust-root.json" --policy "$b/policy.json"
  hslsa fpga firmware        --bundle "$b" --lock "$lock" --key "$k/firmware-platform.key.pem" --cache "$CACHE" "$@"
  for step in simulation synthesis routing signoff bitstream; do
    hslsa fpga design "$step" --bundle "$b" --lock "$lock" --key "$k/flow-platform.key.pem"
  done
  hslsa design release --bundle "$b" --lock "$lock" --key "$k/tapeout-authority.key.pem" \
    --trust-root "$b/trust-root.json" --policy "$b/policy.json"
  hslsa fpga image --bundle "$b" --lock "$lock" --scenario "$HERE/board-scenario.json" \
    --key "$k/firmware-platform.key.pem" --code-signer "$k/code-signer.key.pem"
}

# The EMS: shipments, A1, the board HBOM and one provisioning record per board.
produce_board() {
  rm -rf "$BUNDLE" "$OUT/boards" "$OUT/ems-station"
  mkdir -p "$BUNDLE"
  cp "$DESIGN/trust-root.json" "$BUNDLE/trust-root.json"
  cp "$HERE/policy.json" "$BUNDLE/policy.json"
  hslsa fpga produce --bundle "$BUNDLE" --rot-bundle "$ROT" --design-bundle "$DESIGN" \
    --scenario "$HERE/board-scenario.json" --design "$HERE/board-design.json" --policy "$HERE/policy.json" --keys "$KEYS"
  ems_station "$BUNDLE" "$KEYS" "$OUT/rot-devices" "$OUT/boards" "$OUT/ems-station" "$HERE/board-scenario.json"
}

# ems_station <bundle> <keys> <devices> <boards> <export> <scenario>: board
# programming. The EMS's in-circuit programmer runs a program on every board
# and writes its own export, with the serial and the CSR of the root of trust
# it found on each board; the provisioning adapter clears the program's image
# before it runs and signs one record per board from the export afterwards.
ems_station() {
  local b=$1 k=$2 devices=$3 boards=$4 export=$5 scenario=$6
  local station=(--profile "$ROOT/e2e/stations/icp2-profile.json" --station "$HERE/station/prog-01.json" --export "$export")
  hslsa fpga board-job     --bundle "$b" --scenario "$scenario" --code-signer "$k/code-signer.pub.pem" --export "$export"
  hslsa provision gate     --bundle "$b" "${station[@]}"
  hslsa fpga board-station --bundle "$b" --devices "$devices" --boards "$boards" --export "$export"
  hslsa provision adapt    --bundle "$b" "${station[@]}" --key "$k/ems-site.key.pem"
}

boot() {
  rm -rf "$OUT/boots"
  hslsa fpga boot --bundle "$BUNDLE" --boards "$OUT/boards" --list "$HERE/received-boards.txt" --out "$OUT/boots"
}

expect_fail() {
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: slsa-verifier accepted $what" >&2
    exit 1
  fi
  echo "ok: slsa-verifier rejects $what"
}

verify() {
  local vsa_dir=$OUT/vsa vkey=$OUT/verifier-key
  rm -rf "$vsa_dir" "$vkey" && mkdir -p "$vsa_dir" "$vkey"
  if [[ -n "${HSLSA_VSA_SIGNING_KEY:-}" ]]; then
    (umask 077 && printf '%s\n' "$HSLSA_VSA_SIGNING_KEY" > "$vkey/verifier.key.pem")
  else
    hslsa keygen --out "$vkey" verifier
  fi
  hslsa pubkey --key "$vkey/verifier.key.pem" --out "$vsa_dir/verifier.pub.pem"

  hslsa fpga verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json" \
    --boards "$HERE/received-boards.txt" --boots "$OUT/boots" --vsa-key "$vkey/verifier.key.pem" --vsa-out "$vsa_dir"

  local sv=${SLSA_VERIFIER:-slsa-verifier} keyid design lot board
  keyid=$(hslsa keyid --key "$vsa_dir/verifier.pub.pem")
  local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                --public-key-path "$vsa_dir/verifier.pub.pem" --public-key-id "$keyid")
  design=$(hslsa subject "$vsa_dir/design.vsa.intoto.json")
  echo "== slsa-verifier verify-vsa: FPGA design"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/design.vsa.intoto.json" --resource-uri "hslsa:design:${design% *}" \
    --subject-digest "sha256:${design#* }" --verified-level HSLSA_DESIGN_LEVEL_2 --verified-level SLSA_BUILD_LEVEL_2
  lot=$(hslsa subject "$vsa_dir/board.vsa.intoto.json")
  echo "== slsa-verifier verify-vsa: board lot"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/board.vsa.intoto.json" --resource-uri "${lot% *}" \
    --subject-digest "sha256:${lot#* }" --verified-level HSLSA_ASSEMBLY_LEVEL_2 --verified-level HSLSA_FIRMWARE_LEVEL_2
  while read -r serial; do
    [[ -z "$serial" ]] && continue
    board=$(hslsa subject "$vsa_dir/board-$serial.vsa.intoto.json")
    echo "== slsa-verifier verify-vsa: board $serial"
    "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/board-$serial.vsa.intoto.json" --resource-uri "${board% *}" \
      --subject-digest "sha256:${board#* }" --verified-level HSLSA_FIRMWARE_LEVEL_2
  done < "$HERE/received-boards.txt"
  echo "== slsa-verifier negative case"
  expect_fail "Firmware L3 for the board lot" "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/board.vsa.intoto.json" \
    --resource-uri "${lot% *}" --subject-digest "sha256:${lot#* }" --verified-level HSLSA_FIRMWARE_LEVEL_3
  rm -rf "$vkey"
}

# A throwaway SoftHSM2 token stands in for the sites' HSMs, as in e2e/run.sh.
softhsm_token() {
  [[ -z "${HSLSA_PKCS11_TOKEN:-}" ]] || return 0
  export HSLSA_PKCS11_TOKEN=hslsa-fpga-e2e
  export HSLSA_PKCS11_MODULE=${HSLSA_PKCS11_MODULE:-$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)}
  export HSLSA_PKCS11_PIN
  HSLSA_PKCS11_PIN=$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')
  export SOFTHSM2_CONF=$1/softhsm2.conf
  mkdir -p "$1/tokens"
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$1/tokens" > "$SOFTHSM2_CONF"
  softhsm2-util --init-token --free --label "$HSLSA_PKCS11_TOKEN" --pin "$HSLSA_PKCS11_PIN" \
    --so-pin "$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')" > /dev/null
}

# Firmware L3 (docs/levels.md) on the FPGA board. Rule 2 asks that every site
# that provisions the device be rated L3 in its own track, so the root of
# trust's lot is made again at Wafer L3 and Package/Test L3 (site keys in an
# HSM, an identity per die from wafer sort) and the board at Assembly L3 (the
# EMS challenges each root of trust before placement). Both firmware builds
# run in the sandbox with pinned tools, a review lab signs a S.A.F.E. report for
# each image, and every release goes into the buyer's private transparency
# log. The buyer checks the boards it received with what they reported at
# boot, then the cases Firmware L3 refuses, and a field update held to the
# same rules as the shipped release. Runs on its own, without produce.
l3() {
  local l=$OUT/l3
  rm -rf "$l" && mkdir -p "$l"
  local rot=$l/rot rk=$l/rot-keys design=$l/design k=$l/keys b=$l/board buyer=$l/buyer
  local log=$l/release-log origin="Example Buyer firmware release log"
  mkdir -p "$rot" "$rk/pub" "$design" "$k/pub" "$b"
  softhsm_token "$l"
  hslsa keygen --out "$rk" ip-vendor source-owner source-reviewer flow-platform tapeout-authority product-owner \
    firmware-platform code-signer
  hslsa hsm keygen --token "$HSLSA_PKCS11_TOKEN" --out "$rk" fab-site sort-site osat-site test-site identity-ca > /dev/null
  hslsa keygen --out "$k" ip-vendor source-owner source-reviewer flow-platform tapeout-authority \
    firmware-platform code-signer board-owner ems-site dist-franchised pcb-fab platform-ca
  hslsa keygen --out "$buyer" buyer-root transparency-log review-provider

  echo "== the buyer enrolls every key, with how it is held and the site's accreditation"
  local not_after
  not_after=$(date -u -d '+90 days' +%Y-%m-%d)
  enroll() { # <dir> <keys> <role> <custody> <org> <org id> <site> [flags]
    local dir=$1 keys=$2 role=$3 custody=$4 org=$5 id=$6 site=$7; shift 7
    mkdir -p "$dir"
    hslsa pilot enroll --buyer-key "$buyer/buyer-root.key.pem" --pub "$keys/$role.pub.pem" --role "$role" \
      --org-name "$org" --org-id "$id" --site "$site" --country US \
      --custody "$custody" --not-after "$not_after" --out "$dir/$role.intoto.json" "$@" > /dev/null
  }
  # The buyer's own release log, and the review lab it contracts.
  buyer_services() { # <dir>
    enroll "$1" "$buyer" transparency-log file "Example Buyer" duns:100000040 "Example Buyer Release Log"
    enroll "$1" "$buyer" review-provider file "Example Firmware Review Lab" duns:100000041 "Example Firmware Review Lab"
  }
  rot_enroll() { # <dir> [test house accreditation flags]
    local dir=$1 r; shift
    for r in ip-vendor source-owner source-reviewer flow-platform tapeout-authority product-owner firmware-platform code-signer; do
      enroll "$dir" "$rk" "$r" file "Example RoT Co" duns:100000031 "Example RoT Design Center"
    done
    enroll "$dir" "$rk" identity-ca hsm "Example RoT Co" duns:100000031 "Example RoT Identity CA"
    enroll "$dir" "$rk" fab-site hsm "Example Foundry" duns:100000011 "Example Wafer Fab" --accreditation dmea-trusted-supplier --accreditation-id DMEA-TF-0042
    enroll "$dir" "$rk" sort-site hsm "Example Sort Services" duns:100000012 "Example Sort House" --accreditation iso-iec-20243 --accreditation-id OTTPS-0107
    enroll "$dir" "$rk" osat-site hsm "Example OSAT Group" duns:100000013 "Example OSAT" --accreditation dmea-trusted-supplier --accreditation-id DMEA-TA-0213
    enroll "$dir" "$rk" test-site hsm "Example Test Services" duns:100000014 "Example Test House" "$@"
    buyer_services "$dir"
  }
  board_enroll() { # <dir>
    local dir=$1 r
    for r in ip-vendor source-owner source-reviewer flow-platform tapeout-authority firmware-platform code-signer board-owner; do
      enroll "$dir" "$k" "$r" file "Example Board Co" duns:100000026 "Example Board Design Center"
    done
    enroll "$dir" "$k" platform-ca file "Example Board Co" duns:100000026 "Example Board Platform CA"
    enroll "$dir" "$k" ems-site file "Example EMS" duns:100000021 "Example EMS" --accreditation ipc-1791 --accreditation-id IPC1791-0042
    enroll "$dir" "$k" dist-franchised file "Example Franchised Distributor" duns:100000022 "Example Franchised Distributor" \
      --accreditation sae-as6496 --accreditation-id AS6496-0311
    enroll "$dir" "$k" pcb-fab file "Example PCB Fab" duns:100000024 "Example PCB Fab" --accreditation ipc-1791 --accreditation-id IPC1791-0057
    buyer_services "$dir"
  }
  rot_enroll "$l/rot-enrollments" --accreditation iso-iec-20243 --accreditation-id OTTPS-0233
  hslsa pilot trust-root --buyer-pub "$buyer/buyer-root.pub.pem" --enrollments "$l/rot-enrollments" --out "$l/rot-trust-root.json" > /dev/null
  board_enroll "$l/enrollments"
  hslsa pilot trust-root --buyer-pub "$buyer/buyer-root.pub.pem" --enrollments "$l/enrollments" --out "$l/trust-root.json" > /dev/null
  hslsa tlog init --log "$log" --origin "$origin"
  local logkey=(--log "$log" --key "$buyer/transparency-log.key.pem")

  echo "== the root of trust vendor: the fab checks the release, sort gives each die an identity, the firmware is built isolated"
  cp "$rk"/*.pub.pem "$rk/pub/"
  hslsa trust-root --keys "$rk/pub" --out "$rot/trust-root.json"
  cp "$HERE/l3/rot-policy.json" "$rot/policy.json"
  rot_design "$rot" "$rk"
  hslsa fab-check --bundle "$rot" --trust-root "$rot/trust-root.json" --policy "$HERE/rot/policy.json" --key "$rk/fab-site.key.pem"
  hslsa mfg --bundle "$rot" --scenario "$HERE/l3/rot-mfg-scenario.json" --keys "$rk" --devices "$l/rot-parts"
  hslsa fpga rot-firmware --bundle "$rot" --src "$HERE/rot/firmware" --key "$rk/firmware-platform.key.pem" \
    --code-signer "$rk/code-signer.key.pem" --svn 1 --isolate
  hslsa safe simulate --bundle "$rot" --record att/fw-rot.intoto.json --image rot-fw \
    --vendor "Example RoT Co" --product EXR-01 --version 1 --key "$buyer/review-provider.key.pem"
  hslsa tlog add "${logkey[@]}" --record "$rot/att/fw-rot.intoto.json"
  # The buyer keeps the checkpoint it saw, to check later that the log only grew.
  hslsa tlog checkpoint "${logkey[@]}" --out "$l/checkpoint-seen.json"
  rot_station "$rot" "$rk" "$l/rot-parts" "$l/rot-station" "$HERE/l3/rot-mfg-scenario.json"

  echo "== the board owner: the FPGA design, the SoC firmware built isolated, the flash image"
  cp "$k"/*.pub.pem "$k/pub/"
  hslsa trust-root --keys "$k/pub" --out "$design/trust-root.json"
  cp "$HERE/l3/policy.json" "$design/policy.json"
  board_design "$design" "$k" --isolate
  hslsa safe simulate --bundle "$design" --record att/fw-picosoc.intoto.json --image picosoc-fw.bin \
    --vendor "Example Board Co" --product FPGA-DEVB-01 --version 1.0.0 --key "$buyer/review-provider.key.pem"
  hslsa tlog add "${logkey[@]}" --record "$design/att/fw-picosoc.intoto.json"
  hslsa tlog add "${logkey[@]}" --record "$design/att/fw-flash.intoto.json"

  echo "== the EMS challenges each root of trust before placement, then builds and programs the boards"
  cp "$l/trust-root.json" "$b/trust-root.json" && cp "$HERE/l3/policy.json" "$b/policy.json"
  local parts=(--part-trust-root "rot=$l/rot-trust-root.json" --part-policy "rot=$HERE/l3/rot-policy.json")
  hslsa fpga produce --bundle "$b" --rot-bundle "$rot" --design-bundle "$design" --scenario "$HERE/board-scenario.json" \
    --design "$HERE/board-design.json" --policy "$HERE/l3/policy.json" --keys "$k" \
    --chip-parts "$l/rot-parts" --boards-out "$l/boards" "${parts[@]}"
  ems_station "$b" "$k" "$l/rot-parts" "$l/boards" "$l/ems-station" "$HERE/board-scenario.json"
  hslsa fpga boot --bundle "$b" --boards "$l/boards" --list "$HERE/received-boards.txt" --out "$l/boots"

  echo "== the buyer receives two boards and checks them at Assembly L3 and Firmware L3"
  mkdir -p "$l/received"
  local s
  while read -r s; do cp -r "$l/boards/$s" "$l/received/"; done < "$HERE/received-boards.txt"
  hslsa keygen --out "$l/verifier" verifier
  local check=(--bundle "$b" --trust-root "$l/trust-root.json" --boards "$l/received" --boots "$l/boots" "${parts[@]}")
  hslsa fpga verify "${check[@]}" --policy "$b/policy.json" --vsa-key "$l/verifier/verifier.key.pem" --vsa-out "$l/vsa"
  if command -v "${SLSA_VERIFIER:-slsa-verifier}" > /dev/null; then
    local sv=${SLSA_VERIFIER:-slsa-verifier} keyid lot board
    hslsa pubkey --key "$l/verifier/verifier.key.pem" --out "$l/vsa/verifier.pub.pem"
    keyid=$(hslsa keyid --key "$l/vsa/verifier.pub.pem")
    local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                  --public-key-path "$l/vsa/verifier.pub.pem" --public-key-id "$keyid")
    lot=$(hslsa subject "$l/vsa/board.vsa.intoto.json")
    echo "== slsa-verifier verify-vsa: the board lot at Assembly L3 and Firmware L3"
    "$sv" verify-vsa "${common[@]}" --attestation-path "$l/vsa/board.vsa.intoto.json" --resource-uri "${lot% *}" \
      --subject-digest "sha256:${lot#* }" --verified-level HSLSA_ASSEMBLY_LEVEL_3 --verified-level HSLSA_FIRMWARE_LEVEL_3
    while read -r s; do
      board=$(hslsa subject "$l/vsa/board-$s.vsa.intoto.json")
      echo "== slsa-verifier verify-vsa: board $s at Firmware L3"
      "$sv" verify-vsa "${common[@]}" --attestation-path "$l/vsa/board-$s.vsa.intoto.json" --resource-uri "${board% *}" \
        --subject-digest "sha256:${board#* }" --verified-level HSLSA_FIRMWARE_LEVEL_3
    done < "$HERE/received-boards.txt"
  fi

  echo "== the release log: each release is in it, and it only grew since the buyer last looked"
  hslsa tlog check --trust-root "$l/trust-root.json" --origin "$origin" --record "$b/design/att/fw-flash.intoto.json"
  hslsa tlog checkpoint "${logkey[@]}" --out "$l/checkpoint-now.json"
  hslsa tlog consistency --log "$log" --from 1 --out "$l/consistency.json"
  hslsa tlog verify-consistency --trust-root "$l/trust-root.json" --older "$l/checkpoint-seen.json" \
    --newer "$l/checkpoint-now.json" --proof "$l/consistency.json"

  echo "== what Firmware L3 refuses"
  refuses() { # <what> <reason> <command...>: the command fails, and says why
    local what=$1 reason=$2 out; shift 2
    if out=$("$@" 2>&1); then echo "FAIL: accepted $what" >&2; exit 1; fi
    grep -qF -- "$reason" <<< "$out" || { echo "FAIL: refused $what, but not because $reason: $out" >&2; exit 1; }
    echo "ok: refuses $what"
  }
  # A release the build platform never put in the log.
  mv "$b/design/att/fw-flash.tlog.json" "$l/fw-flash.tlog.json"
  refuses "a flash image that is not in the release log" "fw-flash.intoto.json is not in a transparency log" \
    hslsa fpga verify "${check[@]}" --policy "$b/policy.json"
  mv "$l/fw-flash.tlog.json" "$b/design/att/fw-flash.tlog.json"
  # The records are in a log, but not the one the buyer reads.
  sed 's/"origin": "Example Buyer firmware release log"/"origin": "Example Board Co release log"/' "$b/policy.json" > "$l/other-log.json"
  refuses "releases in a log the buyer does not read" "not the log the policy names" \
    hslsa fpga verify "${check[@]}" --policy "$l/other-log.json"
  # The buyer pins another build of the compiler than the one the build ran.
  sed 's/"sha256": "8c7a8599f3e56e6abe23d4d54025f77ad03efd4113394eac16f1d6060b626974"/"sha256": "0000000000000000000000000000000000000000000000000000000000000000"/' \
    "$b/policy.json" > "$l/other-compiler.json"
  refuses "firmware built with a compiler the policy does not pin" "is not on the policy's pinned tool list" \
    hslsa fpga verify "${check[@]}" --policy "$l/other-compiler.json"
  # No lab reviewed the SoC firmware.
  mv "$b/design/review" "$l/review"
  refuses "firmware no lab reviewed" "no accepted S.A.F.E. report for picosoc-fw.bin" \
    hslsa fpga verify "${check[@]}" --policy "$b/policy.json"
  mv "$l/review" "$b/design/review"
  # No boot evidence: nothing shows the boards run the attested images.
  refuses "boards with no boot evidence" "the at-boot check is required" \
    hslsa fpga verify --bundle "$b" --trust-root "$l/trust-root.json" --policy "$b/policy.json" --boards "$l/received" "${parts[@]}"
  # The root of trust's test house is rated only Package/Test L2 by the buyer's policy for it.
  sed 's/HSLSA_PACKAGE_TEST_LEVEL_3/HSLSA_PACKAGE_TEST_LEVEL_2/' "$HERE/l3/rot-policy.json" > "$l/rot-pt-l2.json"
  refuses "a root of trust provisioned at a test house rated below L3" "Firmware L3 needs every provisioning site at L3" \
    hslsa fpga verify "${check[@]}" --policy "$b/policy.json" --part-policy "rot=$l/rot-pt-l2.json"
  # A field update at Firmware L3: built in the sandbox, reviewed and logged
  # like the shipped release, and written to a board by an enrolled field updater.
  echo "== a field update at Firmware L3"
  local s1
  read -r s1 < "$HERE/received-boards.txt"
  hslsa keygen --out "$k" field-updater
  enroll "$l/enrollments" "$k" field-updater file "Example Board Co" duns:100000026 "Example Board Co Field Service"
  hslsa pilot trust-root --buyer-pub "$buyer/buyer-root.pub.pem" --enrollments "$l/enrollments" --out "$l/trust-root.json" > /dev/null
  cp "$l/trust-root.json" "$b/trust-root.json"
  jq '.firmware.version = "1.1.0" | .firmware.svn = 2 | .firmware.cflags += ["-Os"]' "$HERE/inputs.lock.json" > "$l/update.lock.json"
  hslsa fpga update-build --bundle "$b" --id U1 --lock "$l/update.lock.json" --scenario "$HERE/board-scenario.json" \
    --key "$k/firmware-platform.key.pem" --code-signer "$k/code-signer.key.pem" --cache "$CACHE" --isolate
  hslsa safe simulate --bundle "$b/updates/U1" --record att/fw-picosoc.intoto.json --image picosoc-fw.bin \
    --vendor "Example Board Co" --product FPGA-DEVB-01 --version 1.1.0 --key "$buyer/review-provider.key.pem"
  hslsa fpga after-sale field-update --bundle "$b" --board "$s1" --boards "$l/received" --update "$b/updates/U1" \
    --key "$k/field-updater.key.pem" --site "Example Board Co Field Service" --country US --scenario "$HERE/board-scenario.json"
  echo "$s1" > "$l/one.txt"
  hslsa fpga boot --bundle "$b" --boards "$l/received" --list "$l/one.txt" --out "$l/boots-update"
  rm -rf "${l:?}/boots/$s1" && mv "$l/boots-update/$s1" "$l/boots/$s1"
  refuses "a field update that is not in the release log" "Firmware L3: field update U1: picosoc-fw.bin: fw-picosoc.intoto.json is not in a transparency log" \
    hslsa fpga verify "${check[@]}" --policy "$b/policy.json"
  hslsa tlog add "${logkey[@]}" --record "$b/updates/U1/att/fw-picosoc.intoto.json"
  hslsa tlog add "${logkey[@]}" --record "$b/updates/U1/att/fw-flash.intoto.json"
  hslsa fpga verify "${check[@]}" --policy "$b/policy.json"
  # The log operator rewrites the first release and signs a new checkpoint.
  jq '.entries[0].record.digest.sha256 = "'"$(printf 'another release' | sha256sum | cut -c1-64)"'"' "$log/log.json" > "$l/forked.json"
  mv "$l/forked.json" "$log/log.json"
  hslsa tlog checkpoint "${logkey[@]}" --out "$l/checkpoint-forked.json"
  hslsa tlog consistency --log "$log" --from 1 --out "$l/consistency-forked.json"
  refuses "a log that rewrote a release it had shown" "does not extend the log of 1" \
    hslsa tlog verify-consistency --trust-root "$l/trust-root.json" --older "$l/checkpoint-seen.json" \
      --newer "$l/checkpoint-forked.json" --proof "$l/consistency-forked.json"
  rm -rf "$k" "$rk" "$buyer" "$l/tokens"
}

# Firmware L4 and Assembly L4 (docs/levels.md) on the FPGA board: the L3
# chain again, plus an independent rebuilder who reproduces the root of trust
# firmware, the SoC firmware and the bitstream bit for bit, two people who
# approve each firmware release, and an independent lab that commits to a
# seed before each lot is sealed: it delayers and images two units of the root
# of trust's lot (Wafer L4 and Package/Test L4, which rule 2 asks of the test
# house that provisions it) and X-rays two boards (Assembly L4, which rule 2
# asks of the EMS). Runs on its own, without produce.
l4() {
  local l=$OUT/l4
  rm -rf "${l:?}" && mkdir -p "$l"
  local rot=$l/rot rk=$l/rot-keys design=$l/design k=$l/keys b=$l/board buyer=$l/buyer
  local rb=$l/rebuilder lab=$l/lab
  local log=$l/release-log origin="Example Buyer firmware release log"
  mkdir -p "$rot" "$rk/pub" "$design" "$k/pub" "$b"
  softhsm_token "$l"
  hslsa keygen --out "$rk" ip-vendor source-owner source-reviewer flow-platform tapeout-authority product-owner \
    firmware-platform code-signer approver-a approver-b
  hslsa hsm keygen --token "$HSLSA_PKCS11_TOKEN" --out "$rk" fab-site sort-site osat-site test-site identity-ca > /dev/null
  hslsa keygen --out "$k" ip-vendor source-owner source-reviewer flow-platform tapeout-authority \
    firmware-platform code-signer board-owner ems-site dist-franchised pcb-fab platform-ca approver-a approver-b
  hslsa keygen --out "$buyer" buyer-root transparency-log review-provider
  hslsa keygen --out "$rb" rebuilder
  hslsa keygen --out "$lab" inspection-lab

  echo "== the buyer enrolls every key: the rebuilder and the lab each under its own company"
  local not_after
  not_after=$(date -u -d '+90 days' +%Y-%m-%d)
  enroll() { # <dir> <keys> <key file> <role> <custody> <org> <org id> <site> [flags]
    local dir=$1 keys=$2 file=$3 role=$4 custody=$5 org=$6 id=$7 site=$8; shift 8
    mkdir -p "$dir"
    hslsa pilot enroll --buyer-key "$buyer/buyer-root.key.pem" --pub "$keys/$file.pub.pem" --role "$role" \
      --org-name "$org" --org-id "$id" --site "$site" --country US \
      --custody "$custody" --not-after "$not_after" --out "$dir/$file.intoto.json" "$@" > /dev/null
  }
  # The buyer's release log, the review lab, the rebuilder and the inspection lab.
  third_parties() { # <dir> <lab org> <lab org id> <rebuilder org> <rebuilder org id>
    enroll "$1" "$buyer" transparency-log transparency-log file "Example Buyer" duns:100000040 "Example Buyer Release Log"
    enroll "$1" "$buyer" review-provider review-provider file "Example Firmware Review Lab" duns:100000041 "Example Firmware Review Lab"
    enroll "$1" "$lab" inspection-lab inspection-lab file "$2" "$3" "$2" --accreditation iso-iec-17025 --accreditation-id A2LA-4410.01
    enroll "$1" "$rb" rebuilder rebuilder file "$4" "$5" "$4"
  }
  rot_enroll() { # <dir> <third_parties args>
    local dir=$1 r; shift
    for r in ip-vendor source-owner source-reviewer flow-platform tapeout-authority product-owner firmware-platform code-signer; do
      enroll "$dir" "$rk" "$r" "$r" file "Example RoT Co" duns:100000031 "Example RoT Design Center"
    done
    enroll "$dir" "$rk" approver-a release-approver file "Example RoT Co" duns:100000031 "Example RoT Design Center"
    enroll "$dir" "$rk" approver-b release-approver file "Example RoT Co" duns:100000031 "Example RoT Design Center"
    enroll "$dir" "$rk" identity-ca identity-ca hsm "Example RoT Co" duns:100000031 "Example RoT Identity CA"
    enroll "$dir" "$rk" fab-site fab-site hsm "Example Foundry" duns:100000011 "Example Wafer Fab" --accreditation dmea-trusted-supplier --accreditation-id DMEA-TF-0042
    enroll "$dir" "$rk" sort-site sort-site hsm "Example Sort Services" duns:100000012 "Example Sort House" --accreditation iso-iec-20243 --accreditation-id OTTPS-0107
    enroll "$dir" "$rk" osat-site osat-site hsm "Example OSAT Group" duns:100000013 "Example OSAT" --accreditation dmea-trusted-supplier --accreditation-id DMEA-TA-0213
    enroll "$dir" "$rk" test-site test-site hsm "Example Test Services" duns:100000014 "Example Test House" --accreditation iso-iec-20243 --accreditation-id OTTPS-0233
    third_parties "$dir" "$@"
  }
  board_enroll() { # <dir> <third_parties args>
    local dir=$1 r; shift
    for r in ip-vendor source-owner source-reviewer flow-platform tapeout-authority firmware-platform code-signer board-owner; do
      enroll "$dir" "$k" "$r" "$r" file "Example Board Co" duns:100000026 "Example Board Design Center"
    done
    enroll "$dir" "$k" approver-a release-approver file "Example Board Co" duns:100000026 "Example Board Design Center"
    enroll "$dir" "$k" approver-b release-approver file "Example Board Co" duns:100000026 "Example Board Design Center"
    enroll "$dir" "$k" platform-ca platform-ca file "Example Board Co" duns:100000026 "Example Board Platform CA"
    enroll "$dir" "$k" ems-site ems-site file "Example EMS" duns:100000021 "Example EMS" --accreditation ipc-1791 --accreditation-id IPC1791-0042
    enroll "$dir" "$k" dist-franchised dist-franchised file "Example Franchised Distributor" duns:100000022 "Example Franchised Distributor" \
      --accreditation sae-as6496 --accreditation-id AS6496-0311
    enroll "$dir" "$k" pcb-fab pcb-fab file "Example PCB Fab" duns:100000024 "Example PCB Fab" --accreditation ipc-1791 --accreditation-id IPC1791-0057
    third_parties "$dir" "$@"
  }
  local independent=("Example Failure Analysis Lab" duns:100000061 "Example Rebuild Services" duns:100000053)
  rot_enroll "$l/rot-enrollments" "${independent[@]}"
  hslsa pilot trust-root --buyer-pub "$buyer/buyer-root.pub.pem" --enrollments "$l/rot-enrollments" --out "$l/rot-trust-root.json" > /dev/null
  board_enroll "$l/enrollments" "${independent[@]}"
  hslsa pilot trust-root --buyer-pub "$buyer/buyer-root.pub.pem" --enrollments "$l/enrollments" --out "$l/trust-root.json" > /dev/null
  hslsa tlog init --log "$log" --origin "$origin"
  local logkey=(--log "$log" --key "$buyer/transparency-log.key.pem")
  # approve <bundle> <keys> <record>: two people sign off a release record.
  approve() {
    hslsa release approve --bundle "$1" --record "$3" --approver "Example Release Manager A" --key "$2/approver-a.key.pem"
    hslsa release approve --bundle "$1" --record "$3" --approver "Example Release Manager B" --key "$2/approver-b.key.pem"
  }

  echo "== the root of trust vendor: the lab commits to its seed, final test consumes the commitment as it seals the lot"
  cp "$rk"/*.pub.pem "$rk/pub/"
  hslsa trust-root --keys "$rk/pub" --out "$rot/trust-root.json"
  cp "$HERE/l4/rot-policy.json" "$rot/policy.json"
  rot_design "$rot" "$rk"
  hslsa fab-check --bundle "$rot" --trust-root "$rot/trust-root.json" --policy "$HERE/rot/policy.json" --key "$rk/fab-site.key.pem"
  hslsa inspect commit --plan "$HERE/l4/rot-inspection-plan.json" --key "$lab/inspection-lab.key.pem" --lot ASM-EXR-01 \
    --seed-out "$lab/rot-seed.hex" --out "$lab/rot-commitment.intoto.json"
  hslsa mfg --bundle "$rot" --scenario "$HERE/l3/rot-mfg-scenario.json" --keys "$rk" --devices "$l/rot-parts" \
    --inspection-commitment "$lab/rot-commitment.intoto.json"
  echo "== the root of trust firmware: built isolated, rebuilt bit for bit by the rebuilder, reviewed, approved by two people, logged"
  hslsa fpga rot-firmware --bundle "$rot" --src "$HERE/rot/firmware" --key "$rk/firmware-platform.key.pem" \
    --code-signer "$rk/code-signer.key.pem" --svn 1 --isolate
  hslsa fpga rot-firmware-rebuild --bundle "$rot" --src "$HERE/rot/firmware" --key "$rb/rebuilder.key.pem" \
    --builder-id https://rebuild.example.org/builders/exr-01-firmware --isolate
  hslsa safe simulate --bundle "$rot" --record att/fw-rot.intoto.json --image rot-fw \
    --vendor "Example RoT Co" --product EXR-01 --version 1 --key "$buyer/review-provider.key.pem"
  approve "$rot" "$rk" att/fw-rot.intoto.json
  hslsa tlog add "${logkey[@]}" --record "$rot/att/fw-rot.intoto.json"
  rot_station "$rot" "$rk" "$l/rot-parts" "$l/rot-station" "$HERE/l3/rot-mfg-scenario.json"
  echo "== the lab draws two units of the root of trust lot with its seed, inspects them and destroys them"
  cp -r "$l/rot-parts" "$l/rot-parts-before"
  hslsa inspect lot --plan "$HERE/l4/rot-inspection-plan.json" --key "$lab/inspection-lab.key.pem" --bundle "$rot" \
    --parts "$l/rot-parts" --seed "$lab/rot-seed.hex"
  # The vendor ships the five shipped units left to the EMS (EXR01-A0-00005 failed final test).
  local left
  left=$(ls "$l/rot-parts" | grep -vx EXR01-A0-00005 | jq -R . | jq -cs .)
  jq --argjson units "$left" '.shipments[0].lines[0].units = $units' "$HERE/board-scenario.json" > "$l/board-scenario.json"

  echo "== the board owner: the SoC firmware and the bitstream, each rebuilt bit for bit; every release approved by two people"
  cp "$k"/*.pub.pem "$k/pub/"
  hslsa trust-root --keys "$k/pub" --out "$design/trust-root.json"
  cp "$HERE/l4/policy.json" "$design/policy.json"
  board_design "$design" "$k" --isolate
  hslsa fpga firmware-rebuild --bundle "$design" --lock "$HERE/inputs.lock.json" --key "$rb/rebuilder.key.pem" \
    --cache "$l/rebuild-cache" --builder-id https://rebuild.example.org/builders/picosoc-firmware --isolate
  hslsa design rebuild --bundle "$design" --lock "$HERE/inputs.lock.json" --key "$rb/rebuilder.key.pem" \
    --cache "$l/rebuild-cache" --builder-id https://rebuild.example.org/builders/fpga-devb-bitstream
  hslsa safe simulate --bundle "$design" --record att/fw-picosoc.intoto.json --image picosoc-fw.bin \
    --vendor "Example Board Co" --product FPGA-DEVB-01 --version 1.0.0 --key "$buyer/review-provider.key.pem"
  approve "$design" "$k" att/fw-picosoc.intoto.json
  approve "$design" "$k" att/fw-flash.intoto.json
  hslsa tlog add "${logkey[@]}" --record "$design/att/fw-picosoc.intoto.json"
  hslsa tlog add "${logkey[@]}" --record "$design/att/fw-flash.intoto.json"

  echo "== the lab commits to a seed for the board lot; the EMS builds the boards and consumes the commitment as it seals the lot"
  hslsa inspect commit --plan "$HERE/l4/board-inspection-plan.json" --key "$lab/inspection-lab.key.pem" --lot BRD-EXAMPLE-FPGA-01 \
    --seed-out "$lab/board-seed.hex" --out "$lab/board-commitment.intoto.json"
  cp "$l/trust-root.json" "$b/trust-root.json" && cp "$HERE/l4/policy.json" "$b/policy.json"
  local parts=(--part-trust-root "rot=$l/rot-trust-root.json" --part-policy "rot=$HERE/l4/rot-policy.json")
  hslsa fpga produce --bundle "$b" --rot-bundle "$rot" --design-bundle "$design" --scenario "$l/board-scenario.json" \
    --design "$HERE/board-design.json" --policy "$HERE/l4/policy.json" --keys "$k" \
    --chip-parts "$l/rot-parts" --boards-out "$l/boards" --inspection-commitment "$lab/board-commitment.intoto.json" "${parts[@]}"
  ems_station "$b" "$k" "$l/rot-parts" "$l/boards" "$l/ems-station" "$l/board-scenario.json"
  echo "== the lab X-rays the two boards its seed draws, checks every marking and challenges every identity part"
  hslsa inspect boards --plan "$HERE/l4/board-inspection-plan.json" --key "$lab/inspection-lab.key.pem" --bundle "$b" \
    --boards "$l/boards" --seed "$lab/board-seed.hex"
  hslsa fpga boot --bundle "$b" --boards "$l/boards" --list "$HERE/received-boards.txt" --out "$l/boots"

  echo "== the buyer receives two boards and checks them at Assembly L4 and Firmware L4"
  mkdir -p "$l/received"
  local s
  while read -r s; do cp -r "$l/boards/$s" "$l/received/"; done < "$HERE/received-boards.txt"
  hslsa keygen --out "$l/verifier" verifier
  local check=(--bundle "$b" --trust-root "$l/trust-root.json" --boards "$l/received" --boots "$l/boots" "${parts[@]}")
  hslsa fpga verify "${check[@]}" --policy "$b/policy.json" --vsa-key "$l/verifier/verifier.key.pem" --vsa-out "$l/vsa"
  if command -v "${SLSA_VERIFIER:-slsa-verifier}" > /dev/null; then
    local sv=${SLSA_VERIFIER:-slsa-verifier} keyid lot board
    hslsa pubkey --key "$l/verifier/verifier.key.pem" --out "$l/vsa/verifier.pub.pem"
    keyid=$(hslsa keyid --key "$l/vsa/verifier.pub.pem")
    local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                  --public-key-path "$l/vsa/verifier.pub.pem" --public-key-id "$keyid")
    lot=$(hslsa subject "$l/vsa/board.vsa.intoto.json")
    echo "== slsa-verifier verify-vsa: the board lot at Assembly L4 and Firmware L4"
    "$sv" verify-vsa "${common[@]}" --attestation-path "$l/vsa/board.vsa.intoto.json" --resource-uri "${lot% *}" \
      --subject-digest "sha256:${lot#* }" --verified-level HSLSA_ASSEMBLY_LEVEL_4 --verified-level HSLSA_FIRMWARE_LEVEL_4
    while read -r s; do
      board=$(hslsa subject "$l/vsa/board-$s.vsa.intoto.json")
      echo "== slsa-verifier verify-vsa: board $s at Firmware L4"
      "$sv" verify-vsa "${common[@]}" --attestation-path "$l/vsa/board-$s.vsa.intoto.json" --resource-uri "${board% *}" \
        --subject-digest "sha256:${board#* }" --verified-level HSLSA_FIRMWARE_LEVEL_4
    done < "$HERE/received-boards.txt"
  fi

  echo "== what Firmware L4 and Assembly L4 refuse"
  refuses() { # <what> <reason> <command...>: the command fails, and says why
    local what=$1 reason=$2 out; shift 2
    if out=$("$@" 2>&1); then echo "FAIL: accepted $what" >&2; exit 1; fi
    grep -qF -- "$reason" <<< "$out" || { echo "FAIL: refused $what, but not because $reason: $out" >&2; exit 1; }
    echo "ok: refuses $what"
  }
  # A release only one person approved.
  mv "$b/design/att/approval-fw-flash-example-release-manager-b.intoto.json" "$l/approval-b.intoto.json"
  refuses "a flash image only one person approved" "1 approver(s) signed off the release; the policy requires 2" \
    hslsa fpga verify "${check[@]}" --policy "$b/policy.json"
  mv "$l/approval-b.intoto.json" "$b/design/att/approval-fw-flash-example-release-manager-b.intoto.json"
  # No one else rebuilt the SoC firmware: a closed binary stays at Firmware L3.
  mv "$b/design/att/rebuild-fw-picosoc.intoto.json" "$l/rebuild.intoto.json"
  refuses "SoC firmware nobody else rebuilt" "no independent rebuild (rebuild-fw-picosoc.intoto.json)" \
    hslsa fpga verify "${check[@]}" --policy "$b/policy.json"
  mv "$l/rebuild.intoto.json" "$b/design/att/rebuild-fw-picosoc.intoto.json"
  # The rebuilder and the lab enrolled under the board owner's company.
  board_enroll "$l/same-company" "Example Failure Analysis Lab" duns:100000061 "Example Board Co" duns:100000026
  hslsa pilot trust-root --buyer-pub "$buyer/buyer-root.pub.pem" --enrollments "$l/same-company" --out "$l/same-company.json" > /dev/null
  refuses "a rebuild by the board owner itself" "the organization that holds the firmware-platform key; L4 needs an independent party" \
    hslsa fpga verify --bundle "$b" --trust-root "$l/same-company.json" --boards "$l/received" --boots "$l/boots" "${parts[@]}" --policy "$b/policy.json"
  board_enroll "$l/ems-lab" "Example EMS" duns:100000021 "Example Rebuild Services" duns:100000053
  hslsa pilot trust-root --buyer-pub "$buyer/buyer-root.pub.pem" --enrollments "$l/ems-lab" --out "$l/ems-lab.json" > /dev/null
  refuses "boards inspected by the EMS's own lab" "the organization that holds the ems-site key; L4 needs an independent party" \
    hslsa fpga verify --bundle "$b" --trust-root "$l/ems-lab.json" --boards "$l/received" --boots "$l/boots" "${parts[@]}" --policy "$b/policy.json"
  # The root of trust's lot rated only Package/Test L3: its test house is not rated L4.
  sed 's/HSLSA_PACKAGE_TEST_LEVEL_4/HSLSA_PACKAGE_TEST_LEVEL_3/' "$HERE/l4/rot-policy.json" > "$l/rot-pt-l3.json"
  refuses "a root of trust provisioned at a test house rated below L4" "Firmware L4 needs every provisioning site at L4" \
    hslsa fpga verify --bundle "$b" --trust-root "$l/trust-root.json" --boards "$l/received" --boots "$l/boots" \
    --part-trust-root "rot=$l/rot-trust-root.json" --part-policy "rot=$l/rot-pt-l3.json" --policy "$b/policy.json"
  rm -rf "${k:?}" "${rk:?}" "${buyer:?}" "${rb:?}" "${lab:?}" "${l:?}/tokens"
}

# After-sale records (spec, "After-sale records") on a copy of what produce
# and boot made. The board owner builds a field update with new firmware
# (1.1.0 at SVN 2, the same bitstream); its field updater writes it to one
# board, raises the anti-rollback fuse and signs. Another board comes back, a
# repair site replaces a regulator, and the board owner ships it again. Both
# boards are powered on again, the SoC on the new firmware too, and the buyer
# checks the lot, then the cases the after-sale check refuses.
aftersale() {
  local a=$OUT/aftersale
  rm -rf "$a" && mkdir -p "$a/keys/pub"
  cp -r "$BUNDLE" "$a/board" && cp -r "$OUT/boards" "$a/boards"
  local b=$a/board k=$a/keys s1 s2
  { read -r s1; read -r s2; } < "$HERE/received-boards.txt"
  hslsa keygen --out "$k" field-updater returns-site repair-site
  cp "$KEYS"/pub/*.pub.pem "$k"/*.pub.pem "$k/pub/"
  hslsa trust-root --keys "$k/pub" --out "$b/trust-root.json"
  local sim=(--scenario "$HERE/board-scenario.json")

  echo "== the board owner builds update U1: firmware 1.1.0 at SVN 2, around the same bitstream"
  jq '.firmware.version = "1.1.0" | .firmware.svn = 2 | .firmware.cflags += ["-Os"]' "$HERE/inputs.lock.json" > "$a/update.lock.json"
  hslsa fpga update-build --bundle "$b" --id U1 --lock "$a/update.lock.json" --scenario "$HERE/board-scenario.json" \
    --key "$KEYS/firmware-platform.key.pem" --code-signer "$KEYS/code-signer.key.pem" --cache "$CACHE"
  echo "== the field updater writes U1 to board $s1"
  hslsa fpga after-sale field-update --bundle "$b" --board "$s1" --boards "$a/boards" --update "$b/updates/U1" \
    --key "$k/field-updater.key.pem" --site "Example Board Co Field Service" --country US "${sim[@]}"
  echo "== board $s2 comes back, is reworked and shipped again"
  hslsa fpga after-sale return --bundle "$b" --board "$s2" --key "$k/returns-site.key.pem" --site "Example Board Co Returns" \
    --country US --from "Example Buyer" --reason "3.3 V rail out of tolerance" --disposition repair "${sim[@]}"
  hslsa fpga after-sale rework --bundle "$b" --board "$s2" --key "$k/repair-site.key.pem" --site "Example Repair Site" \
    --country US --order "$HERE/rework-order.json" "${sim[@]}"
  hslsa fpga after-sale reship --bundle "$b" --board "$s2" --key "$KEYS/board-owner.key.pem" --site "Example Board Co" \
    --country US --to "Example Buyer" --shipment EXAMPLE-SHIP-0201 "${sim[@]}"

  echo "== the buyer powers both boards on again and checks the lot"
  hslsa fpga boot --bundle "$b" --boards "$a/boards" --list "$HERE/received-boards.txt" --out "$a/boots"
  local check=(--bundle "$b" --trust-root "$b/trust-root.json" --policy "$b/policy.json" --boards "$HERE/received-boards.txt")
  hslsa fpga verify "${check[@]}" --boots "$a/boots"

  echo "== what the after-sale check refuses"
  refuses() { # <what> <reason> <command...>: the command fails, and says why
    local what=$1 reason=$2 out; shift 2
    if out=$("$@" 2>&1); then echo "FAIL: accepted $what" >&2; exit 1; fi
    grep -qF -- "$reason" <<< "$out" || { echo "FAIL: refused $what, but not because $reason: $out" >&2; exit 1; }
    echo "ok: refuses $what"
  }
  # U1 written to the other board too, fuse and all, with no record: the root
  # of trust boots it, and the buyer sees images the board's history does not name.
  cp -r "$a/boards/$s2" "$a/$s2.saved"
  cp "$b/updates/U1/artifacts/flash.bin" "$a/boards/$s2/flash.bin"
  jq '.owner_min_svn = 2' "$a/$s2.saved/rot/fuses.json" > "$a/boards/$s2/rot/fuses.json"
  echo "$s2" > "$a/one.txt"
  hslsa fpga boot --bundle "$b" --boards "$a/boards" --list "$a/one.txt" --out "$a/boots-unrecorded" --no-soc
  mv "$a/boots/$s2" "$a/$s2.boot" && cp -r "$a/boots-unrecorded/$s2" "$a/boots/$s2"
  refuses "firmware changed with no update record" "in flash matches no reference value in the board CoRIM" \
    hslsa fpga verify "${check[@]}" --boots "$a/boots"
  rm -rf "${a:?}/boots/$s2" "${a:?}/boards/$s2" && mv "$a/$s2.boot" "$a/boots/$s2" && mv "$a/$s2.saved" "$a/boards/$s2"
  # The reshipment record is not there: the board is still at the repair site.
  mv "$b/att/after-sale-$s2-3.intoto.json" "$a/reship.intoto.json"
  refuses "a board returned and not shipped again" "board $s2: was returned to Example Repair Site and not shipped again" \
    hslsa fpga verify "${check[@]}" --boots "$a/boots"
  mv "$a/reship.intoto.json" "$b/att/after-sale-$s2-3.intoto.json"
  # The return record is not there, so the rework follows nothing it may follow.
  mv "$b/att/after-sale-$s2-1.intoto.json" "$a/return.intoto.json"
  refuses "a history with its first record cut" "has 2 after-sale records, but record 1 is missing" \
    hslsa fpga verify "${check[@]}" --boots "$a/boots"
  mv "$a/return.intoto.json" "$b/att/after-sale-$s2-1.intoto.json"
  # The return signed by the repair site's key instead of the returns desk's.
  cp "$b/att/after-sale-$s2-1.intoto.json" "$a/return.intoto.json"
  hslsa fpga after-sale return --bundle "$a/board" --board "$s1" --key "$k/repair-site.key.pem" --site "Example Repair Site" \
    --from "Example Buyer" --disposition repair "${sim[@]}" > /dev/null
  refuses "a return signed by the wrong role" "after-sale-$s1-2.intoto.json: no valid signature from role 'returns-site'" \
    hslsa fpga verify "${check[@]}" --boots "$a/boots"
  rm -f "$b/att/after-sale-$s1-2.intoto.json" "$a/return.intoto.json"
  hslsa fpga verify "${check[@]}" --boots "$a/boots" > /dev/null
  echo "ok: the lot passes again once the cases are undone"
  rm -rf "${k:?}"
}

case "${1:-}" in
  produce) produce_rot; produce_design; produce_board ;;
  boot) boot ;;
  verify) verify ;;
  l3) l3 ;;
  l4) l4 ;;
  aftersale) aftersale ;;
  all) produce_rot; produce_design; produce_board; boot; verify; aftersale; l3; l4 ;;
  *) echo "usage: $0 produce|boot|verify|aftersale|l3|l4|all" >&2; exit 2 ;;
esac
