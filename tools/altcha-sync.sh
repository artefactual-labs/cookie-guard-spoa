#!/usr/bin/env bash
set -euo pipefail

# Fetch and stage ALTCHA JS assets locally under web/assets/altcha/<version>/
# Also generate a .lf file with HTTP headers for HAProxy to serve directly.
#
# usage: ./tools/altcha-sync.sh v2.5.0

ver="${1:-}"
if [[ -z "$ver" || "$ver" == "unset" ]]; then
  echo "error: specify version tag, e.g. v2.5.0 or set web/assets/altcha/VERSION" >&2
  exit 2
fi

root="web/assets/altcha/$ver"
mkdir -p "$root"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Try multiple sources (npm CDN first), then GH tree as a fallback.
echo "Downloading ALTCHA JS $ver…" >&2
try_fetch() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmpdir/altcha.min.js" && return 0
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmpdir/altcha.min.js" "$url" && return 0
  fi
  return 1
}

sources=(
  "https://cdn.jsdelivr.net/npm/altcha@${ver#v}/dist/altcha.min.js"
  "https://cdn.jsdelivr.net/gh/altcha-org/altcha@${ver}/dist/altcha.min.js"
  "https://raw.githubusercontent.com/altcha-org/altcha/${ver}/dist/altcha.min.js"
)

for s in "${sources[@]}"; do
  echo "  -> $s" >&2
  if try_fetch "$s"; then
    ok=1
    break
  fi
done

if [[ -z "${ok:-}" ]]; then
  echo "error: failed to download altcha.min.js for $ver from known sources" >&2
  exit 1
fi

install -m0644 "$tmpdir/altcha.min.js" "$root/altcha.min.js"

chmod +x tools/mk-lf.sh || true
tools/mk-lf.sh application/javascript "$root/altcha.min.js" > "$root/altcha.min.js.lf"

# Update active symlink for easy, stable path in HAProxy and HTML
ln -sfn "$ver" web/assets/altcha/active
echo "$ver" > web/assets/altcha/VERSION

echo "ALTCHA assets staged under $root and active symlink updated." >&2
