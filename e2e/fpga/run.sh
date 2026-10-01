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
#
# Needs: Go, yosys, nextpnr-ice40, icestorm (icepack, iceunpack, icetime and
# its chip database), iverilog, a RISC-V GCC, git and ssh-keygen; l3 also
# needs bubblewrap and SoftHSM2. Same privacy
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
  local station=(--profile "$HERE/rot/station/xg8-profile.json" --station "$HERE/rot/station/ps-02.json" --export "$export")
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
  rm -rf "$BUNDLE" "$OUT/boards"
  mkdir -p "$BUNDLE"
  cp "$DESIGN/trust-root.json" "$BUNDLE/trust-root.json"
  cp "$HERE/policy.json" "$BUNDLE/policy.json"
  hslsa fpga produce --bundle "$BUNDLE" --rot-bundle "$ROT" --design-bundle "$DESIGN" \
    --scenario "$HERE/board-scenario.json" --design "$HERE/board-design.json" --policy "$HERE/policy.json" --keys "$KEYS"
  hslsa fpga provision --bundle "$BUNDLE" --devices "$OUT/rot-devices" --boards "$OUT/boards" \
    --scenario "$HERE/board-scenario.json" --keys "$KEYS"
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
# boot, then the cases Firmware L3 refuses. Runs on its own, without produce.
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
  hslsa fpga provision --bundle "$b" --devices "$l/rot-parts" --boards "$l/boards" --scenario "$HERE/board-scenario.json" --keys "$k"
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

case "${1:-}" in
  produce) produce_rot; produce_design; produce_board ;;
  boot) boot ;;
  verify) verify ;;
  l3) l3 ;;
  all) produce_rot; produce_design; produce_board; boot; verify; l3 ;;
  *) echo "usage: $0 produce|boot|verify|l3|all" >&2; exit 2 ;;
esac
