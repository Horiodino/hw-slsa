#!/usr/bin/env bash
# Builds the pilot kit a buyer gets when it has no access to this private
# repository: the repository's files at one commit, hslsa binaries for common
# platforms, and their checksums.
#
#   pilot/make-kit.sh [out-dir]     default out-dir: out/kit
#
# The binaries are built without cgo, so they cannot use a PKCS#11 HSM; a
# party that signs with an HSM builds hslsa from the source in the kit with
# cgo on (docs/hsm-signing.md). Send the tarball's sha256 to the buyer over a
# different channel from the tarball itself.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/out/kit}
cd "$ROOT"

if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo "commit or stash your changes first: the kit is one commit" >&2
  exit 1
fi
commit=$(git rev-parse HEAD)
name=hslsa-pilot-kit-$(git rev-parse --short=12 HEAD)
stage=$OUT/$name
rm -rf "$stage" && mkdir -p "$stage/bin"

git archive --format=tar --prefix="$name/" HEAD | tar -x -C "$OUT"
for target in linux/amd64 linux/arm64 darwin/arm64 windows/amd64; do
  os=${target%/*} arch=${target#*/} ext=""
  [[ $os == windows ]] && ext=.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" \
    -o "$stage/bin/hslsa-$os-$arch$ext" ./tools/hslsa/cmd/hslsa
done
spec_rev=$(sed -n 's/.*revision \([0-9]*\) (.*/\1/p' spec/hslsa-v0.1.md | head -1)
cat > "$stage/KIT.txt" <<EOF
HSLSA pilot kit
commit:        $commit
spec revision: $spec_rev
built:         $(date -u +%Y-%m-%dT%H:%M:%SZ)
start here:    pilot/README.md
EOF
(cd "$stage" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
rm -rf "$stage"
(cd "$OUT" && sha256sum "$name.tar.gz" | tee "$name.tar.gz.sha256")
