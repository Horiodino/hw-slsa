#!/usr/bin/env bash
# Prepares the runner for the RTL job: Verilator 5.052, a C++ toolchain, jq,
# openssl and rustup.
#
# Every RTL run uses Verilator 5.052. On this design it runs about four times
# as many cycles a second as 5.020, the version in GitHub's ubuntu-24.04 image,
# which the identity run used. A runner without 5.052 builds it from its git
# tag into the runner's tool cache, once on a self-hosted runner, which then
# reuses it.
#
# GitHub's Ubuntu runners get missing packages from apt, and an Arch Linux
# runner from pacman, but only when the runner can use sudo without a password;
# otherwise the job stops and prints the one command to run on it. rustup needs
# no package: when the runner has none, it is installed into the tool cache.
set -euo pipefail

VERILATOR_VERSION=5.052

have() { command -v "$1" >/dev/null 2>&1; }
verilator_is() { [[ $("${1:-verilator}" --version 2>/dev/null | awk '{print $2}') == "$VERILATOR_VERSION" ]]; }

os=$( (. /etc/os-release && echo "${PRETTY_NAME:-$ID}") 2>/dev/null || uname -s)
echo "runner: $os, $(uname -m), $(nproc) CPUs, $(awk '/^MemTotal:/ {printf "%d GB", $2 / 1048576}' /proc/meminfo) RAM"
# A boot's speed depends on the CPU, its frequency governor and whatever else
# is running, so say what they are.
echo "cpu: $(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo)," \
  "governor $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)," \
  "load average $(cut -d' ' -f1-3 /proc/loadavg)"
if [[ $(uname -m) != x86_64 ]]; then
  echo "::error::The RTL job needs an x86_64 runner; slsa-verifier is fetched for linux-amd64."
  exit 1
fi

tools=${RUNNER_TOOL_CACHE:-$HOME/.cache}
prefix=$tools/verilator/$VERILATOR_VERSION
use_prefix= build_verilator=
if ! verilator_is; then
  use_prefix=1
  verilator_is "$prefix/bin/verilator" || build_verilator=1
fi

missing=()
needed=(make g++ pkg-config perl jq openssl git curl)
[[ -z $build_verilator ]] || needed+=(autoconf flex bison python3)
for tool in "${needed[@]}"; do
  have "$tool" || missing+=("$tool")
done
# Verilator's lexer needs flex's C++ header (Arch's flex, Debian's libfl-dev).
[[ -z $build_verilator || -e /usr/include/FlexLexer.h ]] || missing+=(FlexLexer.h)

if ((${#missing[@]})); then
  echo "missing: ${missing[*]}"
  if have apt-get; then
    update=(apt-get update -q)
    install=(apt-get install -y -q --no-install-recommends build-essential pkg-config autoconf flex libfl-dev bison python3 jq openssl git curl)
  elif have pacman; then
    update=()
    install=(pacman -S --needed --noconfirm base-devel python perl jq openssl git curl)
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

if [[ -n $build_verilator ]]; then
  echo "building Verilator $VERILATOR_VERSION into $prefix (runner has: $(verilator --version 2>/dev/null || echo none))"
  src=$tools/verilator/src-$VERILATOR_VERSION
  rm -rf "$src" "$prefix"
  git -c advice.detachedHead=false clone -q --depth 1 -b "v$VERILATOR_VERSION" https://github.com/verilator/verilator "$src"
  # No man pages: those need help2man, and the job does not read them.
  (cd "$src" && autoconf && ./configure -q --prefix="$prefix" &&
    make -s -j"$(nproc)" verilator_exe && make -s installbin installdata) > "$tools/verilator/build-$VERILATOR_VERSION.log" 2>&1 ||
    { tail -40 "$tools/verilator/build-$VERILATOR_VERSION.log"; echo "::error::Building Verilator $VERILATOR_VERSION failed"; exit 1; }
  rm -rf "$src"
fi
if [[ -n $use_prefix ]]; then
  export PATH=$prefix/bin:$PATH PKG_CONFIG_PATH=$prefix/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
  if [[ -n ${GITHUB_ENV:-} ]]; then
    echo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH" >> "$GITHUB_ENV"
    echo "$prefix/bin" >> "$GITHUB_PATH"
  fi
fi

if ! have rustup; then
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

verilator_is || { echo "::error::Verilator $VERILATOR_VERSION is needed; found: $(verilator --version 2>&1)"; exit 1; }
[[ $(pkg-config --modversion verilator) == "$VERILATOR_VERSION" ]] ||
  { echo "::error::pkg-config finds Verilator $(pkg-config --modversion verilator), not $VERILATOR_VERSION"; exit 1; }
verilator --version
g++ --version | head -1
rustup --version 2>/dev/null || true
