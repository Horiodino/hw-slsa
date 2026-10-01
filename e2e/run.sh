#!/usr/bin/env bash
# End-to-end HSLSA test for the PicoRV32 example.
#
#   e2e/run.sh produce   run the design flow and the simulated lot, sign every record
#   e2e/run.sh verify    check the chain, emit VSAs, verify them with slsa-verifier
#   e2e/run.sh proxy     after produce: the same lot with two suppliers that sign nothing
#   e2e/run.sh adapt     after produce: the same lot made from the suppliers' MES and STDF exports
#   e2e/run.sh hsm       after produce: the release and the lot again, signed with keys in an HSM
#   e2e/run.sh shuttle   after produce: a lot from the virtual shuttle, every die simulated gate-level
#   e2e/run.sh rerun     after produce: prove the netlist equal to the RTL again, as an independent party would
#   e2e/run.sh l3        after produce: the lot at Wafer L3 and Package/Test L3, under a buyer-run trust root
#
# Nothing here uploads to a transparency log: every signature is a DSSE
# envelope made with a local ECDSA P-256 key.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
E2E=$ROOT/e2e/picorv32
OUT=${OUT:-$ROOT/out}
BUNDLE=$OUT/bundle
KEYS=$OUT/keys
# The Go reference tool; set HSLSA to use a prebuilt binary instead of building it here.
if [[ -z "${HSLSA:-}" ]]; then
  HSLSA=$ROOT/bin/hslsa
  (cd "$ROOT" && go build -o "$HSLSA" ./tools/hslsa/cmd/hslsa)
fi
hslsa() { "$HSLSA" "$@"; }

produce() {
  rm -rf "$BUNDLE" "$KEYS"
  mkdir -p "$BUNDLE" "$KEYS"
  # One key per party. In a real chain each lives with its own site; here they are
  # generated per run and only their public halves leave this job.
  hslsa keygen --out "$KEYS" ip-vendor source-owner source-reviewer flow-platform tapeout-authority fab-site sort-site osat-site test-site product-owner
  mkdir -p "$KEYS/pub" && cp "$KEYS"/*.pub.pem "$KEYS/pub/"
  hslsa trust-root --keys "$KEYS/pub" --out "$BUNDLE/trust-root.json"
  cp "$E2E/policy.json" "$BUNDLE/policy.json"

  # Design L2 inputs, each from its own party: the IP vendor's provenance, the
  # design lead's SSH-signed git tag, and the reviewer's approval of that commit.
  hslsa design ip-release    --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/ip-vendor.key.pem" --cache "$OUT/cache"
  hslsa design source-tag    --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/source-owner.key.pem" --cache "$OUT/cache"
  hslsa design review        --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/source-reviewer.key.pem"
  hslsa design source-freeze --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem" --cache "$OUT/cache" \
    --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json"
  # Steps 1, 2 and 6 run their tools isolated (no network, no key in reach), and
  # step 6 proves the netlist equal to the RTL: what Design L3 asks of the flow.
  hslsa design simulation    --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem" --isolate
  hslsa design synthesis     --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem" --isolate
  hslsa design signoff       --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/flow-platform.key.pem" --isolate
  hslsa design release       --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --key "$KEYS/tapeout-authority.key.pem" \
    --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json"
  hslsa mfg  --bundle "$BUNDLE" --scenario "$E2E/mfg-scenario.json" --keys "$KEYS"
  hslsa hbom --bundle "$BUNDLE" --lock "$E2E/inputs.lock.json" --scenario "$E2E/mfg-scenario.json" --key "$KEYS/product-owner.key.pem"
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
    echo "VSA signing key: repository secret HSLSA_VSA_SIGNING_KEY"
    (umask 077 && printf '%s\n' "$HSLSA_VSA_SIGNING_KEY" > "$vkey/verifier.key.pem")
  else
    echo "VSA signing key: ephemeral (set the HSLSA_VSA_SIGNING_KEY secret for a stable key)"
    hslsa keygen --out "$vkey" verifier
  fi
  hslsa pubkey --key "$vkey/verifier.key.pem" --out "$vsa_dir/verifier.pub.pem"

  hslsa verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$BUNDLE/policy.json" \
    --units "$E2E/received-units.txt" --vsa-key "$vkey/verifier.key.pem" --vsa-out "$vsa_dir"

  local sv=${SLSA_VERIFIER:-slsa-verifier}
  local keyid final lot
  keyid=$(hslsa keyid --key "$vsa_dir/verifier.pub.pem")
  final=$(hslsa subject "$vsa_dir/design.vsa.intoto.json")
  lot=$(hslsa subject "$vsa_dir/lot.vsa.intoto.json")
  local common=(--verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1
                --public-key-path "$vsa_dir/verifier.pub.pem" --public-key-id "$keyid")

  echo "== slsa-verifier verify-vsa: design"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/design.vsa.intoto.json" \
    --subject-digest "sha256:${final#* }" --resource-uri "hslsa:design:${final% *}" \
    --verified-level HSLSA_DESIGN_LEVEL_3 --verified-level SLSA_BUILD_LEVEL_3
  echo "== slsa-verifier verify-vsa: shipped lot"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/lot.vsa.intoto.json" \
    --subject-digest "sha256:${lot#* }" --resource-uri "${lot% *}" \
    --verified-level HSLSA_WAFER_LEVEL_2 --verified-level HSLSA_PACKAGE_TEST_LEVEL_2 --verified-level HSLSA_DESIGN_LEVEL_3

  # The lot is simulated (its scenario says so in every record), the policy
  # accepts that, and the lot VSA says so for anyone reading only the VSA.
  echo "== slsa-verifier verify-vsa: the shipped lot's evidence is simulated"
  "$sv" verify-vsa "${common[@]}" --attestation-path "$vsa_dir/lot.vsa.intoto.json" \
    --subject-digest "sha256:${lot#* }" --resource-uri "${lot% *}" --verified-level HSLSA_SIMULATED
  # The same policy without simulated.accept, as a buyer of real parts writes it.
  grep -v '"simulated"' "$BUNDLE/policy.json" > "$OUT/real-parts-policy.json"
  if hslsa verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$OUT/real-parts-policy.json" >/dev/null 2>&1; then
    echo "FAIL: a policy without simulated.accept accepted the simulated lot" >&2
    exit 1
  fi
  echo "ok: a policy without simulated.accept refuses the simulated lot"

  echo "== slsa-verifier negative cases"
  local lotargs=("${common[@]}" --attestation-path "$vsa_dir/lot.vsa.intoto.json" --resource-uri "${lot% *}")
  expect_fail "a level the lot was not verified at" "$sv" verify-vsa "${lotargs[@]}" \
    --subject-digest "sha256:${lot#* }" --verified-level HSLSA_PACKAGE_TEST_LEVEL_3
  expect_fail "a different lot digest" "$sv" verify-vsa "${lotargs[@]}" \
    --subject-digest "sha256:${final#* }" --verified-level HSLSA_WAFER_LEVEL_2
  expect_fail "a design level above the claim" "$sv" verify-vsa "${common[@]}" \
    --attestation-path "$vsa_dir/design.vsa.intoto.json" --subject-digest "sha256:${final#* }" \
    --resource-uri "hslsa:design:${final% *}" --verified-level HSLSA_DESIGN_LEVEL_4
  hslsa keygen --out "$vkey/other" verifier
  hslsa pubkey --key "$vkey/other/verifier.key.pem" --out "$vkey/other.pub.pem"
  expect_fail "a VSA checked against another verifier's key" "$sv" verify-vsa \
    --verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1 \
    --public-key-path "$vkey/other.pub.pem" --public-key-id "$keyid" \
    --attestation-path "$vsa_dir/lot.vsa.intoto.json" --resource-uri "${lot% *}" --subject-digest "sha256:${lot#* }" --verified-level HSLSA_WAFER_LEVEL_2
  rm -rf "$vkey"
}

# The lot again, with two suppliers that sign nothing (docs/proxy-signing.md):
# the sort house hands over only a certificate and a paper traveller, which the
# OSAT covers with an evidence record, and the test house hands over its data,
# which the product owner signs on its behalf. Reuses produce's design records
# and keys, so it runs after produce, in the same job.
proxy() {
  local pb=$OUT/proxy
  rm -rf "$pb" && cp -r "$BUNDLE" "$pb"
  cp "$E2E/proxy/policy.json" "$pb/policy.json"
  hslsa mfg  --bundle "$pb" --scenario "$E2E/proxy/mfg-scenario.json" --keys "$KEYS"
  hslsa hbom --bundle "$pb" --lock "$E2E/inputs.lock.json" --scenario "$E2E/proxy/mfg-scenario.json" --key "$KEYS/product-owner.key.pem"
  hslsa verify --bundle "$pb" --trust-root "$pb/trust-root.json" --policy "$pb/policy.json" --units "$E2E/received-units.txt"
  # The main example's policy claims Wafer and Package/Test L2 and accepts no
  # record signed on a supplier's behalf, so it must refuse this lot.
  if hslsa verify --bundle "$pb" --trust-root "$pb/trust-root.json" --policy "$E2E/policy.json" >/dev/null 2>&1; then
    echo "FAIL: the L2 policy accepted a lot with proxy-signed records" >&2
    exit 1
  fi
  echo "ok: the L2 policy refuses the proxy-signed lot"
}

# The lot again, made from what each site's MES and testers export
# (docs/mes-stdf-adapter.md): lot histories, a unit genealogy, STDF V4 test
# results and SEMI E142 wafer maps. The verifier reads the exports again from
# the bundle. Then the test house signs nothing and the product owner
# proxy-signs final test from its STDF file. Runs after produce, in the same job.
adapt() {
  local ex=$E2E/supplier-exports ab=$OUT/adapted
  for variant in adapter adapter-proxy; do
    local policy=$ex/policy.json
    [[ $variant == adapter-proxy ]] && policy=$ex/policy-proxy.json
    echo "== $variant"
    rm -rf "$ab" && cp -r "$BUNDLE" "$ab"
    cp "$policy" "$ab/policy.json"
    hslsa adapt --config "$ex/$variant.json" --out "$ab/scenario.json"
    hslsa mfg  --bundle "$ab" --scenario "$ab/scenario.json" --keys "$KEYS"
    hslsa hbom --bundle "$ab" --lock "$E2E/inputs.lock.json" --scenario "$ab/scenario.json" --key "$KEYS/product-owner.key.pem"
    hslsa verify --bundle "$ab" --trust-root "$ab/trust-root.json" --policy "$ab/policy.json" --units "$E2E/received-units.txt"
    if ! cmp -s "$ab/artifacts/shipped-lot.txt" "$BUNDLE/artifacts/shipped-lot.txt"; then
      echo "FAIL: the lot made from the exports is not the scenario's lot" >&2
      exit 1
    fi
    echo "ok: the exports make the same shipped lot as the scenario"
  done
  # The main bundle's records carry no exports, so a policy that requires them refuses it.
  if hslsa verify --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --policy "$ex/policy.json" >/dev/null 2>&1; then
    echo "FAIL: a policy that requires exports accepted records without them" >&2
    exit 1
  fi
  echo "ok: a policy that requires exports refuses records without them"
}

# A lot from the virtual shuttle (docs/simulated-hardware.md): the released
# netlist is "fabricated" on two wafers of dies with seeded defects, and wafer
# sort and final test run test programs on each die in Icarus Verilog. Its
# exports go through the same adapter as a supplier's, every record says it
# was made from simulated hardware, and the policy accepts that. Runs after
# produce, in the same job.
shuttle() {
  local sb=$OUT/shuttle ex=$OUT/shuttle/exports
  rm -rf "$sb" && mkdir -p "$sb"
  cp -r "$BUNDLE" "$sb/bundle"
  cp "$ROOT/e2e/shuttle/policy.json" "$sb/bundle/policy.json"
  hslsa sim shuttle --bundle "$sb/bundle" --lock "$E2E/inputs.lock.json" --config "$ROOT/e2e/shuttle/shuttle.json" --out "$ex"
  hslsa adapt --config "$ex/adapter.json" --out "$sb/scenario.json"
  hslsa mfg  --bundle "$sb/bundle" --scenario "$sb/scenario.json" --keys "$KEYS"
  hslsa hbom --bundle "$sb/bundle" --lock "$E2E/inputs.lock.json" --scenario "$sb/scenario.json" --key "$KEYS/product-owner.key.pem"
  hslsa verify --bundle "$sb/bundle" --trust-root "$sb/bundle/trust-root.json" --policy "$sb/bundle/policy.json"
  grep -v '"simulated"' "$sb/bundle/policy.json" > "$sb/real-parts-policy.json"
  if hslsa verify --bundle "$sb/bundle" --trust-root "$sb/bundle/trust-root.json" --policy "$sb/real-parts-policy.json" >/dev/null 2>&1; then
    echo "FAIL: a policy without simulated.accept accepted the shuttle's lot" >&2
    exit 1
  fi
  echo "ok: a policy without simulated.accept refuses the shuttle's lot"
}

# softhsm_token <dir>: with no HSLSA_PKCS11_TOKEN set, a throwaway SoftHSM2
# token under <dir> stands in for the HSM.
softhsm_token() {
  [[ -z "${HSLSA_PKCS11_TOKEN:-}" ]] || return 0
  export HSLSA_PKCS11_TOKEN=hslsa-e2e
  export HSLSA_PKCS11_MODULE=${HSLSA_PKCS11_MODULE:-$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)}
  export HSLSA_PKCS11_PIN
  HSLSA_PKCS11_PIN=$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')
  export SOFTHSM2_CONF=$1/softhsm2.conf
  mkdir -p "$1/tokens"
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$1/tokens" > "$SOFTHSM2_CONF"
  softhsm2-util --init-token --free --label "$HSLSA_PKCS11_TOKEN" --pin "$HSLSA_PKCS11_PIN" \
    --so-pin "$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')" > /dev/null
}

# The release and the lot again, with the tapeout authority's and every site's
# key in an HSM (docs/hsm-signing.md). Each <role>.key.pem is replaced by a
# <role>.pkcs11 file naming the key on the token, and nothing else changes: the
# same commands sign and the same check passes. With no HSLSA_PKCS11_TOKEN set,
# a throwaway SoftHSM2 token stands in for the HSM. Runs after produce.
hsm() {
  local hb=$OUT/hsm
  local roles=(tapeout-authority fab-site sort-site osat-site test-site product-owner)
  rm -rf "$hb" && mkdir -p "$hb"
  cp -r "$BUNDLE" "$hb/bundle"
  cp -r "$KEYS" "$hb/keys"
  local b=$hb/bundle k=$hb/keys
  softhsm_token "$hb"
  for r in "${roles[@]}"; do rm "$k/$r.key.pem"; done
  hslsa hsm keygen --token "$HSLSA_PKCS11_TOKEN" --out "$k" "${roles[@]}" > /dev/null
  cp "$k"/*.pub.pem "$k/pub/"
  hslsa trust-root --keys "$k/pub" --out "$b/trust-root.json"

  hslsa design release --bundle "$b" --lock "$E2E/inputs.lock.json" --key "$k/tapeout-authority.key.pem" \
    --trust-root "$b/trust-root.json" --policy "$b/policy.json"
  hslsa mfg  --bundle "$b" --scenario "$E2E/mfg-scenario.json" --keys "$k"
  hslsa hbom --bundle "$b" --lock "$E2E/inputs.lock.json" --scenario "$E2E/mfg-scenario.json" --key "$k/product-owner.key.pem"
  hslsa verify --bundle "$b" --trust-root "$b/trust-root.json" --policy "$b/policy.json" --units "$E2E/received-units.txt"

  # The records must carry the HSM keys' signatures, not the file keys' from produce.
  local r keyid
  for r in tapeout-authority:design-release fab-site:mfg-f1-wafer-fab sort-site:mfg-f2-wafer-sort \
           osat-site:mfg-f3-packaging test-site:mfg-f4-final-test product-owner:hbom; do
    keyid=$(hslsa keyid --key "$k/${r%%:*}.pub.pem")
    grep -q "\"keyid\": *\"$keyid\"" "$b/att/${r#*:}.intoto.json" \
      || { echo "FAIL: ${r#*:} is not signed by ${r%%:*}'s HSM key" >&2; exit 1; }
  done
  echo "ok: release and lot signed with HSM-held keys, and the check passes"
  rm -rf "$hb/keys" "$hb/tokens"
}

# Wafer L3 and Package/Test L3 (docs/levels.md): the lot again, under a
# buyer-run trust root that records each site key as held in an HSM at an
# accredited site. The fab checks the design release before mask making;
# wafer sort gives every passing die an identity rooted in its own (simulated)
# DICE engine and endorsed by an identity CA whose key is in the HSM; final
# test challenges every unit and names the shipped lot by certificate digest;
# and the buyer challenges the parts it received. Runs after produce.
l3() {
  local l=$OUT/l3
  rm -rf "$l" && mkdir -p "$l"
  cp -r "$BUNDLE" "$l/bundle" && cp -r "$KEYS" "$l/keys"
  local b=$l/bundle k=$l/keys
  local sites=(fab-site sort-site osat-site test-site)
  softhsm_token "$l"
  for r in "${sites[@]}"; do rm "$k/$r.key.pem"; done
  hslsa hsm keygen --token "$HSLSA_PKCS11_TOKEN" --out "$k" "${sites[@]}" identity-ca > /dev/null

  echo "== the buyer enrolls each key, with how it is held and the site's accreditation"
  local ent=$l/enrollments not_after
  not_after=$(date -u -d '+90 days' +%Y-%m-%d)
  hslsa keygen --out "$l/buyer" buyer-root
  enroll() { # <dir> <role> <custody> <org> <org id> <site> [flags]
    local dir=$1 role=$2 custody=$3 org=$4 id=$5 site=$6; shift 6
    hslsa pilot enroll --buyer-key "$l/buyer/buyer-root.key.pem" --pub "$k/$role.pub.pem" --role "$role" \
      --org-name "$org" --org-id "$id" --site "$site" --country US \
      --custody "$custody" --not-after "$not_after" --out "$dir/$role.intoto.json" "$@" > /dev/null
  }
  enroll_all() { # <dir> <site custody>
    mkdir -p "$1"
    local r
    for r in ip-vendor source-owner source-reviewer flow-platform tapeout-authority product-owner; do
      enroll "$1" "$r" file "Example Open Silicon Group" duns:100000002 "Example Design Center"
    done
    enroll "$1" identity-ca hsm "Example Open Silicon Group" duns:100000002 "Example Identity CA"
    enroll "$1" fab-site "$2" "Example Foundry" duns:100000011 "Example Wafer Fab" --accreditation dmea-trusted-supplier --accreditation-id DMEA-TF-0042
    enroll "$1" sort-site "$2" "Example Sort Services" duns:100000012 "Example Sort House" --accreditation iso-iec-20243 --accreditation-id OTTPS-0107
    enroll "$1" osat-site "$2" "Example OSAT Group" duns:100000013 "Example OSAT" --accreditation dmea-trusted-supplier --accreditation-id DMEA-TA-0213
    enroll "$1" test-site "$2" "Example Test Services" duns:100000014 "Example Test House" --accreditation iso-iec-20243 --accreditation-id OTTPS-0233
  }
  enroll_all "$ent" hsm
  hslsa pilot trust-root --buyer-pub "$l/buyer/buyer-root.pub.pem" --enrollments "$ent" --out "$l/trust-root.json" > /dev/null
  cp "$E2E/l3/policy.json" "$b/policy.json"

  echo "== the fab checks the release under its own trust root and policy, then the sites sign the lot"
  hslsa fab-check --bundle "$b" --trust-root "$BUNDLE/trust-root.json" --policy "$E2E/policy.json" --key "$k/fab-site.key.pem"
  hslsa mfg  --bundle "$b" --scenario "$E2E/l3/mfg-scenario.json" --keys "$k" --devices "$l/parts"
  hslsa hbom --bundle "$b" --lock "$E2E/inputs.lock.json" --scenario "$E2E/l3/mfg-scenario.json" --key "$k/product-owner.key.pem"

  echo "== the buyer receives three parts and challenges each"
  mkdir -p "$l/received"
  local s
  while read -r s; do cp -r "$l/parts/$s" "$l/received/"; done < "$E2E/received-units.txt"
  local vkey=$l/verifier
  hslsa keygen --out "$vkey" verifier
  hslsa verify --bundle "$b" --trust-root "$l/trust-root.json" --policy "$b/policy.json" --units "$l/received" \
    --vsa-key "$vkey/verifier.key.pem" --vsa-out "$l/vsa"
  if command -v "${SLSA_VERIFIER:-slsa-verifier}" > /dev/null; then
    local sv=${SLSA_VERIFIER:-slsa-verifier} keyid lot
    hslsa pubkey --key "$vkey/verifier.key.pem" --out "$l/vsa/verifier.pub.pem"
    keyid=$(hslsa keyid --key "$l/vsa/verifier.pub.pem")
    lot=$(hslsa subject "$l/vsa/lot.vsa.intoto.json")
    echo "== slsa-verifier verify-vsa: the L3 lot"
    "$sv" verify-vsa --verifier-id https://github.com/Horiodino/hw-slsa/tools/hslsa/verify@v0.1 \
      --public-key-path "$l/vsa/verifier.pub.pem" --public-key-id "$keyid" \
      --attestation-path "$l/vsa/lot.vsa.intoto.json" --subject-digest "sha256:${lot#* }" --resource-uri "${lot% *}" \
      --verified-level HSLSA_WAFER_LEVEL_3 --verified-level HSLSA_PACKAGE_TEST_LEVEL_3 --verified-level HSLSA_DESIGN_LEVEL_3
  fi

  echo "== what Wafer L3 and Package/Test L3 refuse"
  local check=(--bundle "$b" --policy "$b/policy.json")
  refuses() { # <what> <reason> <command...>: the command fails, and says why
    local what=$1 reason=$2 out; shift 2
    if out=$("$@" 2>&1); then echo "FAIL: accepted $what" >&2; exit 1; fi
    grep -qF -- "$reason" <<< "$out" || { echo "FAIL: refused $what, but not because $reason: $out" >&2; exit 1; }
    echo "ok: refuses $what"
  }
  # A clone: a copy of a genuine part's certificate on a die with another secret.
  mkdir -p "$l/clone" && cp -r "$l/received/$(head -1 "$E2E/received-units.txt")" "$l/clone/part"
  sed -i "s/\"uds\": \"[0-9a-f]*\"/\"uds\": \"$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')\"/" "$l/clone/part/die.json"
  refuses "a cloned part that carries a genuine certificate" "does not verify under its certificate's key" hslsa verify "${check[@]}" --trust-root "$l/trust-root.json" --units "$l/clone"
  # A part final test failed, sold on as if it had passed.
  mkdir -p "$l/scrapped" && cp -r "$l/parts/PSOC130-A0-00007" "$l/scrapped/"
  refuses "a part that failed final test" "is not in the shipped lot" hslsa verify "${check[@]}" --trust-root "$l/trust-root.json" --units "$l/scrapped"
  # Serials typed into a list instead of parts answering a challenge.
  refuses "received units listed by serial, not challenged" "listed, not challenged" hslsa verify "${check[@]}" --trust-root "$l/trust-root.json" \
    --units "$E2E/received-units.txt"
  # A trust root of the same keys that says nothing of how they are held.
  mkdir -p "$l/pub" && cp "$k"/*.pub.pem "$l/pub/"
  hslsa trust-root --keys "$l/pub" --out "$l/plain-trust-root.json"
  refuses "a trust root without enrollments" "L3 needs a buyer-run trust root" hslsa verify "${check[@]}" --trust-root "$l/plain-trust-root.json"
  # The same keys enrolled as held in files, not an HSM.
  enroll_all "$l/file-custody" file
  hslsa pilot trust-root --buyer-pub "$l/buyer/buyer-root.pub.pem" --enrollments "$l/file-custody" --out "$l/file-custody.json" > /dev/null
  refuses "site keys held in files" "L3 needs a key held in an HSM" hslsa verify "${check[@]}" --trust-root "$l/file-custody.json"
  # A policy that accepts neither site accreditation.
  sed 's/"accreditations": \[[^]]*\]/"accreditations": ["semi-e187"]/' "$b/policy.json" > "$l/other-accreditation.json"
  refuses "sites accredited under schemes the policy does not list" "which the policy's accreditations do not list" hslsa verify --bundle "$b" \
    --policy "$l/other-accreditation.json" --trust-root "$l/trust-root.json"
  rm -rf "$k" "$l/tokens"
}

# Design L3 makes an independent rerun of the equivalence proof possible: the
# signoff record carries the frozen source and the netlist by digest. Anyone
# holding the bundle and the trust root runs it with their own Yosys and this
# tool's own recipe, not the script the flow platform shipped.
rerun() {
  hslsa design rerun-equivalence --bundle "$BUNDLE" --trust-root "$BUNDLE/trust-root.json" --isolate
}

case "${1:-}" in
  produce) produce ;;
  verify) verify ;;
  proxy) proxy ;;
  adapt) adapt ;;
  hsm) hsm ;;
  shuttle) shuttle ;;
  rerun) rerun ;;
  l3) l3 ;;
  all) produce; verify; proxy; adapt; hsm; shuttle; rerun; l3 ;;
  *) echo "usage: $0 produce|verify|proxy|adapt|hsm|shuttle|rerun|l3|all" >&2; exit 2 ;;
esac
