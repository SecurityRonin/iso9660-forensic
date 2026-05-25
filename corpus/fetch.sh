#!/usr/bin/env bash
# Generate ISO 9660 corpus image using genisoimage.
# Requires: genisoimage (sudo apt-get install -y genisoimage)
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"
SRC="${DEST}/_src"

mkdir -p "${SRC}"
echo "ISO 9660 corpus test file" > "${SRC}/hello.txt"

# Joliet + Rock Ridge extensions (common real-world combination)
genisoimage \
  -o  "${DEST}/test.iso" \
  -V  CORPUS \
  -J  \
  -R  \
  "${SRC}"

rm -rf "${SRC}"
