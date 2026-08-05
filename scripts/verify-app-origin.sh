#!/usr/bin/env bash
set -euo pipefail

# verify-app-origin.sh — confirm the bytes a Zellij app origin is serving match
# a published, reproducible release.
#
# What it proves:
#   Each GitHub release publishes a RELEASE_HASHES.txt asset listing the sha256
#   of every file the app origin should serve (index.html, everything under
#   assets/, and the versioned application bundle under v/<version>/...). This
#   script downloads that manifest for <release-tag>, fetches
#   each file from the live <app-origin> over HTTPS, and compares hashes. If
#   every file matches, the live origin is serving exactly the audited release.
#
# What it relies on:
#   The host must NOT rewrite bytes in transit. Any CDN content-mutation feature
#   (Cloudflare Rocket Loader, Auto Minify for JS/CSS/HTML, Email Obfuscation,
#   Mirage, etc.) changes the served bytes and will cause spurious MISMATCH —
#   and also breaks Subresource Integrity. Such features MUST be OFF on the app
#   origin. A clean rebuild with the pinned toolchain + pinned wasm-opt version
#   reproduces RELEASE_HASHES.txt byte-for-byte; see docs/THREAT_MODEL.md.
#
# Usage:
#   verify-app-origin.sh <release-tag> [app-origin-base-url]
#   verify-app-origin.sh v0.43.0
#   verify-app-origin.sh v0.43.0 https://zellij.example.com

usage() {
  echo "usage: $(basename "$0") <release-tag> [app-origin-base-url]" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage

TAG="$1"
ORIGIN="${2:-https://zellij.online}"
ORIGIN="${ORIGIN%/}"

MANIFEST_URL="https://github.com/zellij-org/zellij/releases/download/${TAG}/RELEASE_HASHES.txt"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
manifest="$tmpdir/RELEASE_HASHES.txt"

echo ">> fetching manifest: $MANIFEST_URL"
if ! curl -fsSL "$MANIFEST_URL" -o "$manifest"; then
  echo "ERROR: could not download RELEASE_HASHES.txt for tag '$TAG'" >&2
  exit 1
fi

ok=0
fail=0

while IFS= read -r line || [ -n "$line" ]; do
  # Skip blank lines.
  [ -n "${line//[[:space:]]/}" ] || continue

  # Format is "<sha256hex>  <relpath>" (two-space separator, sha256sum-style).
  want="${line%%[[:space:]]*}"
  path="${line#*[[:space:]]}"
  # Strip any leading whitespace left from the separator.
  path="${path#"${path%%[![:space:]]*}"}"

  if [ -z "$want" ] || [ -z "$path" ]; then
    echo "WARN  skipping unparseable line: $line" >&2
    continue
  fi

  # index.html is served at the origin root; assets/... and v/<version>/...
  # map directly.
  if [ "$path" = "index.html" ]; then
    url="$ORIGIN/"
  else
    url="$ORIGIN/$path"
  fi

  if ! got="$(curl -fsSL "$url" | sha256sum | cut -d' ' -f1)"; then
    echo "UNREACHABLE  $path  ($url)"
    fail=$((fail + 1))
    continue
  fi

  if [ "$got" = "$want" ]; then
    echo "OK           $path"
    ok=$((ok + 1))
  else
    echo "MISMATCH     $path"
    echo "                 want $want"
    echo "                 got  $got"
    fail=$((fail + 1))
  fi
done < "$manifest"

echo
echo ">> origin:   $ORIGIN"
echo ">> tag:      $TAG"
echo ">> verified: $ok ok, $fail failed"

if [ "$fail" -ne 0 ]; then
  echo ">> RESULT: FAILED — the origin is not serving the published bytes" >&2
  exit 1
fi

echo ">> RESULT: OK — the origin matches the published release"
