#!/usr/bin/env bash
# Build the documentation website into site/public and check its links.
#
#   site/build.sh            # build once; open site/public/index.html
#   site/build.sh serve      # build, then serve it at http://localhost:1313
#
# Needs Go and curl. Hugo and mermaid are downloaded once into site/.cache at
# the versions pinned below and checked against their sha256 sums.
set -euo pipefail

HUGO_VERSION=0.151.0
# sha256 of hugo_0.151.0_linux-amd64.tar.gz, from hugo_0.151.0_checksums.txt on the release
HUGO_SHA256_linux_amd64=1fea04cb0d467a90981f9837ad6ab171fe27e0d6d1bdd5fa4ba54a3464c90114
MERMAID_VERSION=11.17.2
# sha256 of mermaid-11.17.2.tgz from registry.npmjs.org (its npm integrity is
# sha512-V6K3C8EBdEsPFZXSKMJe6ppQOENxuHARr9GvHX4hh47lAbhMRD9qf4oEK7LoaRQxULMa80/qt5gHO73aCleBBg==)
MERMAID_SHA256=6ad2f42c3fc26bbf9e45cbb6d11898972573ea52b33a5f4ff51952899f950ffd

cd "$(dirname "$0")/.."
site=site
cache=$site/.cache
mkdir -p "$cache" bin

fetch() { # url sha256 file
  if [[ ! -f $3 ]] || ! echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null; then
    curl -fsSL --retry 3 -o "$3.part" "$1"
    echo "$2  $3.part" | sha256sum -c --quiet -
    mv "$3.part" "$3"
  fi
}

hugo=$(command -v hugo || true)
if [[ -z $hugo ]] || [[ $("$hugo" version) != *"v$HUGO_VERSION"* ]]; then
  [[ $(uname -s)-$(uname -m) == Linux-x86_64 ]] || {
    echo "install Hugo $HUGO_VERSION (https://gohugo.io/installation/) and run again" >&2; exit 1; }
  fetch "https://github.com/gohugoio/hugo/releases/download/v$HUGO_VERSION/hugo_${HUGO_VERSION}_linux-amd64.tar.gz" \
    "$HUGO_SHA256_linux_amd64" "$cache/hugo.tar.gz"
  tar -xzf "$cache/hugo.tar.gz" -C "$cache" hugo
  hugo=$cache/hugo
fi

fetch "https://registry.npmjs.org/mermaid/-/mermaid-$MERMAID_VERSION.tgz" "$MERMAID_SHA256" "$cache/mermaid.tgz"
mkdir -p "$site/static/js"
tar -xzf "$cache/mermaid.tgz" -O package/dist/mermaid.min.js > "$site/static/js/mermaid.min.js"

go build -o bin/hslsa ./tools/hslsa/cmd/hslsa
go run ./site/gen -hslsa bin/hslsa -out "$site/content"

export HUGO_PARAMS_COMMIT=${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}
rm -rf "$site/public"
"$hugo" --source "$site" --minify --panicOnWarning --printPathWarnings
go run ./site/gen -check "$site/public"

if [[ ${1:-} == serve ]]; then
  exec "$hugo" server --source "$site" --disableFastRender
fi
