#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <content-type> <source-file> [<status-line>]" >&2
  echo "example: $0 application/javascript dist/altcha.min.js > altcha.min.js.lf" >&2
  exit 2
fi

ctype="$1"; shift
src="$1"; shift
status="${1:-HTTP/1.1 200 OK}"

echo "$status"
echo "Content-Type: $ctype"
if [[ "$ctype" == application/javascript* ]]; then
  echo "Cache-Control: public, max-age=604800"
else
  echo "Cache-Control: no-store"
fi
echo
cat "$src"
