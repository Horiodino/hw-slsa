#!/usr/bin/env bash
# Builds the pilot kit a buyer or supplier gets when it has no access to this
# private repository: the repository's files at one commit, hslsa binaries for
# common platforms, the license of every Go module in them, and their
# checksums. Then signs it with the kit owner's key.
#
#   HSLSA_KIT_KEY=<key> pilot/make-kit.sh [out-dir]     default out-dir: out/kit
#
# HSLSA_KIT_KEY is the kit owner's private key file or PKCS#11 URI (make one
# with `hslsa keygen --out <dir> kit-signer`). Next to the tarball the script
# writes:
#   <kit>.provenance.json  SLSA provenance over the tarball and each binary
#   <kit>.tar.gz.sig       signature over the tarball, for openssl
#   <kit>.pub.pem          the public key that checks both
#   <kit>.tar.gz.sha256    the tarball's sha256
# Send the public key's sha256 to the recipient over a different channel from
# the kit itself; pilot/README.md says how they check it.
#
# The binaries are built without cgo, so they cannot use a PKCS#11 HSM; a
# party that signs with an HSM builds hslsa from the source in the kit with
# cgo on (docs/hsm-signing.md). The same commit and Go toolchain give the same
# tarball, byte for byte.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/out/kit}
cd "$ROOT"

if [[ -z ${HSLSA_KIT_KEY:-} ]]; then
  echo "set HSLSA_KIT_KEY to the kit owner's signing key: the kit is signed" >&2
  exit 1
fi
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo "commit or stash your changes first: the kit is one commit" >&2
  exit 1
fi
want_go=$(sed -n 's/^toolchain //p' go.mod)
have_go=$(go env GOVERSION)
if [[ $have_go != "$want_go" ]]; then
  echo "go.mod pins $want_go, but go runs $have_go (is GOTOOLCHAIN=local set?)" >&2
  exit 1
fi
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
commit=$(git rev-parse HEAD)
epoch=$(git log -1 --format=%ct HEAD)
name=hslsa-pilot-kit-$(git rev-parse --short=12 HEAD)
stage=$OUT/$name
rm -rf "$stage" && mkdir -p "$stage/bin" "$stage/licenses"

git archive --format=tar --prefix="$name/" HEAD | tar -x -C "$OUT"
bins=()
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os=${target%/*} arch=${target#*/} ext=""
  [[ $os == windows ]] && ext=.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" \
    -o "$stage/bin/hslsa-$os-$arch$ext" ./tools/hslsa/cmd/hslsa
  bins+=("bin/hslsa-$os-$arch$ext")
done

# The license, notice and patent files of Go and of every module the binaries link.
"$ROOT/pilot/collect-licenses.sh" "$stage/licenses"

spec_rev=$(sed -n 's/.*revision \([0-9]*\) (.*/\1/p' spec/hslsa-v0.1.md | head -1)
cat > "$stage/KIT.txt" <<EOF
HSLSA pilot kit
commit:        $commit
spec revision: $spec_rev
committed:     $(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)
go:            $have_go
license:       code Apache-2.0 (LICENSE), spec and docs CC-BY-4.0 (LICENSE-CC-BY-4.0); licenses/ for the Go modules in bin/
start here:    pilot/README.md
EOF
(cd "$stage" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)

# Same commit and toolchain, same bytes: fixed order, owners, dates and gzip header.
tar -C "$OUT" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  --format=gnu -cf - "$name" | gzip -n -9 > "$OUT/$name.tar.gz"

sign_args=("$name.tar.gz=$OUT/$name.tar.gz")
for b in "${bins[@]}"; do sign_args+=("$b=$stage/$b"); done
go run ./tools/hslsa/cmd/hslsa kit sign --key "$HSLSA_KIT_KEY" --commit "$commit" \
  --provenance "$OUT/$name.provenance.json" --sig "$OUT/$name.tar.gz.sig" "${sign_args[@]}"
go run ./tools/hslsa/cmd/hslsa pubkey --key "$HSLSA_KIT_KEY" --out "$OUT/$name.pub.pem"
rm -rf "$stage"

(cd "$OUT" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
echo "kit:        $OUT/$name.tar.gz"
echo "provenance: $OUT/$name.provenance.json"
echo "signature:  $OUT/$name.tar.gz.sig"
echo "public key: $OUT/$name.pub.pem"
echo "send this over a second channel, the public key's sha256:"
sha256sum "$OUT/$name.pub.pem" | cut -d' ' -f1
