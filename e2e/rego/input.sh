#!/usr/bin/env bash
# Builds the input document for the Rego policies in policies/rego from an
# HSLSA bundle. It uses openssl, ssh-keygen, jq, tar and coreutils, and
# nothing from tools/hslsa.
#
#   e2e/rego/input.sh [--policy FILE] [--trust-root FILE] [--received FILE] <bundle> > input.json
#
# The policy and trust root default to the bundle's own. --received lists the
# units (or boards) the buyer received, one per line.
#
# The input holds, by path in the bundle:
#   every file's sha256 and size
#   for each DSSE envelope (att/*.intoto.json): its payload type, decoded
#     statement, and the trust-root roles whose keys verified one of its
#     signatures, as openssl checked them over the DSSE pre-authentication
#     encoding (PAE)
#   JSON files under artifacts/ parsed, and .txt files as text
#   for a signed git tag, the roles whose keys made its SSH signature
#     (ssh-keygen -Y verify), and each git object's id
#   for a .tar file, the sha256 of each member
# and, for a board, the same document for each part bundle under parts/,
# made from that part's own trust root and policy.
#
# It decides nothing: the policies do.
set -euo pipefail
export LC_ALL=C

policy= trust= received=
while [[ $# -gt 1 ]]; do
  case $1 in
    --policy) policy=$2; shift 2 ;;
    --trust-root) trust=$2; shift 2 ;;
    --received) received=$2; shift 2 ;;
    *) break ;;
  esac
done
[[ $# -eq 1 && -d $1 ]] || { echo "usage: $0 [--policy FILE] [--trust-root FILE] [--received FILE] <bundle>" >&2; exit 2; }
bundle=${1%/}
policy=${policy:-$bundle/policy.json}
trust=${trust:-$bundle/trust-root.json}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# json_of <file> <out>: the file's one JSON value, or null.
json_of() { jq -c -s 'if length == 1 then .[0] else null end' "$1" > "$2" 2> /dev/null || echo null > "$2"; }

# One PEM file per trust-root key, listed with its role, the hash its curve
# signs with, and its fingerprint (sha256 of the DER public key).
mkdir -p "$work/keys"
: > "$work/keys.tsv"
n=0
while IFS=$'\t' read -r role pem; do
  n=$((n + 1))
  k=$work/keys/$n.pem
  base64 -d <<< "$pem" > "$k"
  case $(openssl pkey -pubin -in "$k" -noout -text 2> /dev/null | sed -n 's/^ASN1 OID: //p') in
    prime256v1) hash=sha256 ;;
    secp384r1) hash=sha384 ;;
    secp521r1) hash=sha512 ;;
    *) echo "trust root: a key of role $role is not an ECDSA P-256, P-384 or P-521 key; it verifies nothing" >&2; continue ;;
  esac
  fp=$(openssl pkey -pubin -in "$k" -outform DER | sha256sum | cut -d' ' -f1)
  printf '%s\t%s\t%s\t%s\n' "$k" "$role" "$hash" "$fp" >> "$work/keys.tsv"
done < <(jq -r '.roles | to_entries[] | .key as $role | .value[] | [$role, @base64] | @tsv' "$trust")

# envelope <file> <out>: payload type, statement, and which roles' keys verified a signature.
envelope() {
  local f=$1 type body=$work/body pae=$work/pae sig=$work/sig
  type=$(jq -r '.payloadType // ""' "$f" 2> /dev/null || true)
  if ! jq -r '.payload // ""' "$f" 2> /dev/null | base64 -d > "$body" 2> /dev/null; then
    : > "$body"
  fi
  # PAE = "DSSEv1" SP len(type) SP type SP len(body) SP body, lengths in bytes.
  { printf 'DSSEv1 %d %s %d ' "${#type}" "$type" "$(stat -c %s "$body")"; cat "$body"; } > "$pae"
  : > "$work/verified.tsv"
  while read -r s; do
    base64 -d <<< "$s" > "$sig" 2> /dev/null || continue
    while IFS=$'\t' read -r k role hash fp; do
      if openssl dgst "-$hash" -verify "$k" -signature "$sig" "$pae" > /dev/null 2>&1; then
        printf '%s\t%s\n' "$role" "$fp" >> "$work/verified.tsv"
      fi
    done < "$work/keys.tsv"
  done < <(jq -r '.signatures[]?.sig // empty' "$f" 2> /dev/null || true)
  json_of "$body" "$work/statement.json"
  jq -n --arg type "$type" --slurpfile statement "$work/statement.json" --rawfile v "$work/verified.tsv" '
    ($v | split("\n") | map(select(length > 0) | split("\t"))) as $rows
    | {payloadType: $type, statement: $statement[0],
       signedBy: ($rows | map(.[0]) | unique), keys: ($rows | map(.[1]) | unique)}' > "$2"
}

# ssh_signed <tag object> <out>: roles whose key made the tag's SSH signature, namespace git.
ssh_signed() {
  local tag=$1
  sed -n '/^-----BEGIN SSH SIGNATURE-----$/,$p' "$tag" > "$work/tag.sig"
  sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' "$tag" > "$work/tag.payload"
  : > "$work/tag.roles"
  if [[ -s $work/tag.sig ]]; then
    while IFS=$'\t' read -r k role hash fp; do
      ssh-keygen -i -m PKCS8 -f "$k" > "$work/key.ssh" 2> /dev/null || continue
      printf 'signer namespaces="git" %s\n' "$(cat "$work/key.ssh")" > "$work/allowed"
      if ssh-keygen -Y verify -f "$work/allowed" -I signer -n git -s "$work/tag.sig" < "$work/tag.payload" > /dev/null 2>&1; then
        echo "$role" >> "$work/tag.roles"
      fi
    done < "$work/keys.tsv"
  fi
  jq -R -s 'split("\n") | map(select(length > 0)) | unique' "$work/tag.roles" > "$2"
}

# git_id <type> <file>: the git object id of a raw object.
git_id() { { printf '%s %d\0' "$1" "$(stat -c %s "$2")"; cat "$2"; } | sha1sum | cut -d' ' -f1; }

# tar_members <file> <out>: sha256 of each regular member.
tar_members() {
  tar -tf "$1" | while IFS= read -r m; do
    [[ $m == */ ]] && continue
    printf '%s\t%s\n' "$m" "$(tar -xOf "$1" -- "$m" | sha256sum | cut -d' ' -f1)"
  done | jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}' > "$2"
}

: > "$work/files.jsonl"
while IFS= read -r rel; do
  f=$bundle/$rel
  e=$work/entry.json x=$work/extra.json
  jq -n --arg sha "$(sha256sum < "$f" | cut -d' ' -f1)" --argjson size "$(stat -c %s "$f")" '{sha256: $sha, size: $size}' > "$e"
  echo '{}' > "$x"
  case $rel in
    att/*.intoto.json)
      envelope "$f" "$work/env.json"
      jq '{envelope: .}' "$work/env.json" > "$x" ;;
    artifacts/source-git/tag)
      ssh_signed "$f" "$work/by.json"
      jq -n --arg id "$(git_id tag "$f")" --slurpfile by "$work/by.json" '{gitObject: {type: "tag", id: $id}, sshSignedBy: $by[0]}' > "$x" ;;
    artifacts/source-git/commit)
      jq -n --arg id "$(git_id commit "$f")" '{gitObject: {type: "commit", id: $id}}' > "$x" ;;
    artifacts/source-git/tree*)
      jq -n --arg id "$(git_id tree "$f")" '{gitObject: {type: "tree", id: $id}}' > "$x" ;;
    artifacts/*.json)
      json_of "$f" "$work/v.json"
      jq '{json: .}' "$work/v.json" > "$x" ;;
    artifacts/*.tar)
      tar_members "$f" "$work/m.json"
      jq '{members: .}' "$work/m.json" > "$x" ;;
  esac
  case $rel in
    *.txt | artifacts/source-git/tag | artifacts/source-git/commit)
      jq --rawfile text "$f" '. + {text: $text}' "$x" > "$x.next" && mv "$x.next" "$x" ;;
  esac
  jq -c -n --arg path "$rel" --slurpfile e "$e" --slurpfile x "$x" '{($path): ($e[0] + $x[0])}' >> "$work/files.jsonl"
done < <(cd "$bundle" && find . -path ./parts -prune -o -type f -print | sed 's|^\./||' | sort)

# Part bundles that travel with a board, each under its own trust root and policy.
echo '{}' > "$work/parts.json"
for part in "$bundle"/parts/*/; do
  [[ -f $part/trust-root.json && -f $part/policy.json ]] || continue
  "$0" "${part%/}" > "$work/part.json"
  jq --arg name "parts/$(basename "$part")" --slurpfile p "$work/part.json" '. + {($name): $p[0]}' "$work/parts.json" > "$work/parts.next"
  mv "$work/parts.next" "$work/parts.json"
done

if [[ -n $received ]]; then
  jq -R -s '[splits("\r\n|\r|\n")] | map(select(test("\\S")))' "$received" > "$work/received.json"
else
  echo null > "$work/received.json"
fi

jq -s 'add // {}' "$work/files.jsonl" > "$work/files.json"
jq -n --slurpfile policy "$policy" --slurpfile trust "$trust" --slurpfile parts "$work/parts.json" \
  --slurpfile received "$work/received.json" --slurpfile files "$work/files.json" '
  {
    policy: $policy[0],
    trustRoot: {roles: ($trust[0].roles | keys), validUntil: ($trust[0].validUntil // null)},
    files: $files[0],
    parts: $parts[0]
  } + (if $received[0] == null then {} else {received: $received[0]} end)'
