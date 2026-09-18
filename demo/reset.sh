#!/usr/bin/env bash
# Idempotent reset for the Assay demo.
#
# Removes every artifact the demo produces and nothing else. It never touches tracked files,
# so running it between takes cannot smuggle a hand-edit into a recording. Safe to run any
# number of times, including when nothing exists yet.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ASSAY_DEMO_OUT:-$HERE/out}"

rm -rf "$OUT"
mkdir -p "$OUT"

# Byte-compiled caches can mask an import error that a clean clone would hit.
find "$HERE/.." -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "reset: $OUT is empty and ready"
