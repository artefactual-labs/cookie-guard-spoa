#!/usr/bin/env bash
set -euo pipefail

# Fetch BotD (FingerprintJS) ESM bundle from npm and stage it locally under
# web/assets/botd/<version>/ so it can be served first-party like ALTCHA.
#
# usage: ./tools/botd-sync.sh v2.0.0

ver="${1:-}"
if [[ -z "$ver" || "$ver" == "unset" ]]; then
  echo "error: specify version, e.g. v2.0.0 or set web/assets/botd/VERSION" >&2
  exit 2
fi
plain_ver="${ver#v}"

root="web/assets/botd/$ver"
mkdir -p "$root"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

tarball="https://registry.npmjs.org/@fingerprintjs/botd/-/botd-${plain_ver}.tgz"
echo "Downloading BotD agent $ver…" >&2
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$tarball" -o "$tmpdir/botd.tgz"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmpdir/botd.tgz" "$tarball"
else
  echo "error: need curl or wget" >&2
  exit 1
fi

tar -xzf "$tmpdir/botd.tgz" -C "$tmpdir"
if [ ! -f "$tmpdir/package/dist/botd.esm.js" ]; then
  echo "error: botd.esm.js not found in tarball" >&2
  exit 1
fi

install -m0644 "$tmpdir/package/dist/botd.esm.js" "$root/botd.esm.js"

chmod +x tools/mk-lf.sh || true
tools/mk-lf.sh application/javascript "$root/botd.esm.js" > "$root/botd.esm.js.lf"

ln -sfn "$ver" web/assets/botd/active
echo "$ver" > web/assets/botd/VERSION

echo "BotD assets staged under $root and active symlink updated." >&2
