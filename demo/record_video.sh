#!/usr/bin/env bash
# Record the Assay demo to demo/out/assay-demo.webm, then validate the recording.
#
# Requires node >= 18 (built-in WebSocket/fetch), a Chromium build, and an ffmpeg with
# image2pipe + libvpx. Override the binaries with ASSAY_CHROME / ASSAY_FFMPEG.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ASSAY_DEMO_OUT:-$HERE/out}"
PY="${PYTHON:-python3}"

bash "$HERE/reset.sh"
node "$HERE/record.mjs" "$OUT/assay-demo.webm" "$OUT/transcript.txt" "$OUT/frames"
"$PY" "$HERE/validate_video.py" "$OUT/assay-demo.webm" "$OUT/frames" --out "$OUT/validation.json"
