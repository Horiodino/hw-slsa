#!/usr/bin/env bash
# Copies the license, notice and patent files of Go and of every module the
# hslsa binaries link into <dest>, one directory per module path. Stops on a
# module that has none, since its binary could not then be shipped.
#
#   pilot/collect-licenses.sh <dest>
#
# Used by make-kit.sh for the kit's licenses/ and by the release workflow for
# the container image.
set -euo pipefail

dest=${1:?usage: $0 <dest>}
cd "$(dirname "$0")/.."
mkdir -p "$dest"
cp "$(go env GOROOT)/LICENSE" "$dest/go.LICENSE"
[[ -f $(go env GOROOT)/PATENTS ]] && cp "$(go env GOROOT)/PATENTS" "$dest/go.PATENTS"
for target in linux/amd64 linux/arm64 darwin/arm64 windows/amd64; do
  CGO_ENABLED=0 GOOS=${target%/*} GOARCH=${target#*/} go list -deps \
    -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}{{end}}' ./tools/hslsa/cmd/hslsa
done | sort -u | while read -r mod dir; do
  found=0
  for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/PATENTS*; do
    [[ -f $f ]] || continue
    mkdir -p "$dest/${mod%@*}" && cp "$f" "$dest/${mod%@*}/" && found=1
  done
  [[ $found == 1 ]] || { echo "no license file in $mod ($dir)" >&2; exit 1; }
done
chmod -R u+w "$dest"
