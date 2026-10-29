#!/usr/bin/env bash
# Run an experiment config into a bundle and verify it. Thin wrapper; see REPRODUCIBILITY.md.
#   scripts/reproduce-experiment.sh CONFIG [OUT_DIR] [extra args, e.g. --allow-billable-calls]
set -euo pipefail
if [ "$#" -lt 1 ]; then
  echo "usage: $0 CONFIG [OUT_DIR] [--allow-billable-calls] [--configuration NAME ...]" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="$1"; shift
out="${1:-$here/experiments/runs}"
if [ "$#" -gt 0 ]; then shift; fi
export PYTHONPATH="$here/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m assay_bench experiment validate-config --config "$config"
python3 -m assay_bench experiment run --config "$config" --out "$out" "$@"
