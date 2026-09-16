#!/usr/bin/env bash
# Prepares the runner for the RTL job: Verilator 5.004 or later (caliptra-sw's
# minimum), a C++ toolchain, jq, openssl and rustup.
#
# GitHub's Ubuntu runners get missing packages from apt. A self-hosted runner,
# such as an Arch Linux machine, gets them from pacman, but only when the runner
# can use sudo without a password; otherwise the job stops and prints the one
# command to run on it. rustup needs no package: when the runner has none, it is
# installed into the runner's tool cache, leaving the user's home alone.
set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

os=$( (. /etc/os-release && echo "${PRETTY_NAME:-$ID}") 2>/dev/null || uname -s)
echo "runner: $os, $(uname -m), $(nproc) CPUs, $(awk '/^MemTotal:/ {printf "%d GB", $2 / 1048576}' /proc/meminfo) RAM"
if [[ $(uname -m) != x86_64 ]]; then
  echo "::error::The RTL job needs an x86_64 runner; slsa-verifier is fetched for linux-amd64."
  exit 1
fi

verilator_ok() {
  have verilator || return 1
  local v
  v=$(verilator --version | awk '{print $2}')
  [[ $v =~ ^5\.([0-9]+) ]] && ((10#${BASH_REMATCH[1]} >= 4))
}

missing=()
for tool in make g++ pkg-config perl jq openssl git curl; do
  have "$tool" || missing+=("$tool")
done
verilator_ok || missing+=(verilator)

if ((${#missing[@]})); then
  echo "missing: ${missing[*]}"
  if have apt-get; then
    update=(apt-get update -q)
    install=(apt-get install -y -q --no-install-recommends verilator build-essential pkg-config jq openssl git curl)
  elif have pacman; then
    update=()
    install=(pacman -S --needed --noconfirm verilator base-devel jq openssl git curl)
  else
    echo "::error::No apt-get or pacman on this runner. Install: ${missing[*]}"
    exit 1
  fi
  if ((EUID == 0)); then
    sudo=()
  elif have sudo && sudo -n true 2>/dev/null; then
    sudo=(sudo -n)
  else
    echo "::error::The runner cannot install packages without a password. Run once on it, then re-run the job: sudo $(sed "s/ --noconfirm//" <<< "${install[*]}")"
    exit 1
  fi
  if ((${#update[@]})); then "${sudo[@]}" "${update[@]}"; fi
  "${sudo[@]}" "${install[@]}"
fi

if ! have rustup; then
  tools=${RUNNER_TOOL_CACHE:-$HOME/.cache}
  export RUSTUP_HOME=$tools/rustup CARGO_HOME=$tools/cargo PATH=$tools/cargo/bin:$PATH
  if [[ ! -x $CARGO_HOME/bin/rustup ]]; then
    echo "installing rustup into $tools"
    curl -sSfL https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain none --no-modify-path
  fi
  if [[ -n ${GITHUB_ENV:-} ]]; then
    printf 'RUSTUP_HOME=%s\nCARGO_HOME=%s\n' "$RUSTUP_HOME" "$CARGO_HOME" >> "$GITHUB_ENV"
    echo "$CARGO_HOME/bin" >> "$GITHUB_PATH"
  fi
fi

verilator_ok || { echo "::error::Verilator 5.004 or later is needed; found: $(verilator --version 2>&1)"; exit 1; }
verilator --version
g++ --version | head -1
rustup --version 2>/dev/null || true
