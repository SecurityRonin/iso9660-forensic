#!/usr/bin/env bash
# Generate ISO 9660 corpus image using xorriso.
#
# xorriso is a completely independent ISO 9660 / Rock Ridge / Joliet
# implementation (libburn project) — distinct from the genisoimage/mkisofs
# lineage. Using a different creation tool reduces the risk of symmetric
# parser bugs that genisoimage-only testing would miss.
#
# Requires: xorriso (sudo apt-get install -y xorriso)
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"
SRC="${DEST}/_src"

mkdir -p "${SRC}"
printf 'ISO 9660 corpus test file\n' > "${SRC}/hello.txt"
printf 'A second entry\n' > "${SRC}/second.txt"

# -as mkisofs compatibility mode: Joliet (-J) + Rock Ridge (-r)
xorriso -as mkisofs \
  -o  "${DEST}/test.iso" \
  -V  CORPUS \
  -J  \
  -r  \
  "${SRC}"

rm -rf "${SRC}"
