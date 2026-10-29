#!/usr/bin/env bash
# Verify an experiment bundle offline. Thin wrapper; see REPRODUCIBILITY.md.
#   scripts/verify-experiment.sh BUNDLE_DIR [--expect-commit SHA] [--require-signature ...]
set -euo pipefail
if [ "$#" -lt 1 ]; then
  echo "usage: $0 BUNDLE_DIR [verify-artifacts options]" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$here/src${PYTHONPATH:+:$PYTHONPATH}"
bundle="$1"; shift
python3 -m assay_bench verify-artifacts "$bundle" "$@"
