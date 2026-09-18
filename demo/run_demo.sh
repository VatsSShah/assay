#!/usr/bin/env bash
# The Assay demo: run the benchmark against a built-in conformance target, verify the
# scorecard, tamper with a copy, and watch the verifier reject it.
#
# WHAT THIS DEMONSTRATES: the harness mechanism and the verifier's tamper-evidence.
# WHAT IT DOES NOT: any live MCP server, agent or model. The targets are deterministic
# in-process stubs. Nothing here is a measurement of a real product.
#
# Every command below is a real command run in sequence; there are no pre-baked outputs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="${ASSAY_DEMO_OUT:-$HERE/out}"
PY="${PYTHON:-python3}"
PAUSE="${ASSAY_DEMO_PAUSE:-0}"

mkdir -p "$OUT"
cd "$ROOT"

# `[ x ] && cmd` returns non-zero when the test fails, which under `set -e` would kill the
# script as soon as ASSAY_DEMO_PAUSE is 0. Use an explicit if.
beat() {
  if [ "$PAUSE" != "0" ]; then sleep "$PAUSE"; fi
}

step() {
  printf '\n\033[1;36m$ %s\033[0m\n' "$*"
  beat
  "$@"
}

banner() {
  printf '\n\033[1;33m--- %s ---\033[0m\n' "$*"
  beat
}

banner "1/7  Environment"
step "$PY" --version
step git -C "$ROOT" rev-parse --short HEAD

banner "2/7  The frozen task set"
step "$PY" -c "from assay_bench.catalog import load_catalog; c=load_catalog(); print(f'{len(c)} tasks  v{c.version}  digest {c.digest[:16]}...'); print('Mode B:', len(c.for_mode('B')), ' Mode A:', len(c.for_mode('A')))"

banner "3/7  Run against the VULNERABLE conformance target (built to comply)"
step "$PY" -m assay_bench run --target vulnerable --trials 25 --out "$OUT/vulnerable.json"

banner "4/7  Run against the HARDENED conformance target (built to refuse)"
step "$PY" -m assay_bench run --target hardened --trials 25 --out "$OUT/hardened.json"

banner "5/7  Verify both scorecards, requiring a complete run"
step "$PY" assay_verifier.py verify "$OUT/vulnerable.json" --require run_complete
step "$PY" assay_verifier.py verify "$OUT/hardened.json" --require run_complete

banner "6/7  Recompute ONE canary proof triple by hand"
step "$PY" "$HERE/show_triple.py" "$OUT/vulnerable.json"

banner "7/7  Tamper with a copy, and watch the verifier reject it"
step "$PY" "$HERE/tamper.py" "$OUT/vulnerable.json" "$OUT/tampered.json"
printf '\n\033[1;36m$ %s\033[0m\n' "$PY assay_verifier.py verify $OUT/tampered.json"
set +e
"$PY" assay_verifier.py verify "$OUT/tampered.json"
TAMPER_EXIT=$?
set -e
printf '\033[1;31mexit status: %s\033[0m\n' "$TAMPER_EXIT"
if [ "$TAMPER_EXIT" -ne 1 ]; then
  echo "FAIL: the tampered manifest should have exited 1, got $TAMPER_EXIT" >&2
  exit 1
fi

banner "Summary"
"$PY" "$HERE/summary.py" "$OUT"
