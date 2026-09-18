# Assay demo runbook

## What this demo is, and what it is not

**It is:** a conformance-and-verifier demonstration. It runs the frozen 31-task set against two
built-in **deterministic in-process** targets, verifies both scorecards, recomputes one canary
proof triple by hand, then makes one scripted edit to a copy and shows the verifier reject it
with exit status 1.

**It is not:** a live MCP target run. No MCP server, agent or model is involved at any point.
There is no real MCP adapter in this repository. Every number on screen is a property of the
harness and its own stubs, and the recording says so in the footer of every frame and in the
closing summary.

The demo deliberately shows the trust boundary as well as the mechanism: step 6 prints, on
screen, that recomputing a triple proves the tag is present in *that submitted string* and does
not prove a target emitted it.

## Files

| file | purpose |
|---|---|
| `reset.sh` | idempotent reset; removes `demo/out/` and byte-compiled caches, touches no tracked file |
| `run_demo.sh` | the demo itself, `set -euo pipefail`; every line is a real command |
| `tamper.py` | makes one controlled edit (a fired canary's `observed`) and **reseals** the manifest, so the only defect is that the digest no longer recomputes |
| `show_triple.py` | prints the secret, preimage, digest and the digest's position in the observed egress |
| `summary.py` | final state: artifacts, scores, verification levels, SHA-256s |
| `terminal.html` | the 1920×1080 terminal surface used for recording |
| `record.mjs` | live capture: spawns the demo, streams its real output, grabs frames, encodes |
| `record_video.sh` | reset → record → validate, in one command |
| `validate_video.py` | proves the recording is time-varying |

## Run it

```bash
bash demo/reset.sh
bash demo/run_demo.sh
```

Takes about half a second with no pacing. For a presentation, pace it:

```bash
ASSAY_DEMO_PAUSE=1.1 bash demo/run_demo.sh
```

`ASSAY_DEMO_PAUSE` inserts a real `sleep` before each step. It changes the *pace*, never the
commands or their output.

## Record the video

```bash
bash demo/record_video.sh
```

Writes `demo/out/assay-demo.webm`, `transcript.txt`, `frames/`, `ffmpeg.log` and
`validation.json`.

`demo/out/` is the **working** directory and is gitignored: `reset.sh` wipes it and
`run_demo.sh` rewrites it on every run, so tracking it would mean a demo run dirties the tree
and breaks the `git diff --exit-code` gate. The **published** recording — the one
`VIDEO_VALIDATION.md` reports on — is copied into `demo/recording/`, which is tracked.

### Capture settings

| setting | value |
|---|---|
| Resolution | 1920 × 1080, `deviceScaleFactor: 1` |
| Frame rate | 10 fps (`ASSAY_FPS`) |
| Terminal font | DejaVu Sans Mono, 22 px, line-height 1.34 (≈ 110 columns, ≈ 32 rows visible) |
| Capture | Chromium CDP `Page.captureScreenshot`, JPEG quality 82 |
| Encoder | ffmpeg `image2pipe` → `libvpx` VP8, 4 Mbit/s, `yuv420p`, `-auto-alt-ref 0` |
| Container | WebM |
| Pacing | `ASSAY_DEMO_PAUSE=1.1` |
| Sampled frames | every 7th frame (0.7 s) — see below |

### Two non-obvious details, recorded because they cost real debugging time

1. **`-i pipe:0`, not `-i -`.** ffmpeg 7 maps `-` to the `fd:` protocol. The minimal ffmpeg
   shipped with Playwright does not enable it, and fails with
   `Protocol not found. Did you mean file:fd:?`. The `pipe` protocol *is* enabled.
2. **`-vcodec mjpeg` on the input.** `image2pipe` cannot sniff the codec of a raw JPEG stream and
   fails with `no decoder found for: none`.
3. **Sampling at 0.7 s, not 1.0 s.** The cursor blinks with a 1 s period. Sampling once per
   second aliases against it and produces identical samples for a screen that is in fact moving.
   An earlier take reported 4 "frozen" pairs purely from that aliasing.

### Environment used for the published recording

| item | value |
|---|---|
| OS / arch | Linux x86_64 |
| Python | 3.11.15 (CPython) |
| Node | v22.22.2 (built-in `WebSocket` and `fetch`; no npm packages) |
| Chromium | Playwright `chromium_headless_shell-1194` |
| ffmpeg | `n7.0.1-playwright-build-1011` |
| Network | not used; the demo is stdlib-only and touches no network |

Override the binaries with `ASSAY_CHROME` and `ASSAY_FFMPEG` if yours live elsewhere.

## Repeatability

Three consecutive runs from reset, with the environment stripped (`env -i`, no proxy variables
set), pacing disabled:

| run | exit | duration |
|---|---|---|
| 1 | 0 | 0.489 s |
| 2 | 0 | 0.483 s |
| 3 | 0 | 0.501 s |

No file was edited between runs; `reset.sh` was the only thing that touched `demo/out/`.

**File hashes differ between runs, and that is correct.** Each run mints a fresh 32-byte secret,
so every digest, envelope, integrity hash and timestamp legitimately changes. What must not
change is the *run invariants* — the per-task fired/ASR vector, the scores, the target
fingerprint, the task-set digest — and those were byte-identical across all three:

| target | invariants digest (all three runs) |
|---|---|
| vulnerable | `76fd2f39201330c8997e859ecf503c25…` |
| hardened | `ef7074e79658a07e130918dde40fd093…` |

This is the same invariants comparison a maintainer attestation uses, and it is the reason
attestation compares invariants rather than bytes.

## What each step shows

| step | on screen | why it is in the demo |
|---|---|---|
| 1 | Python version, repo commit | the recording is pinned to a specific tree |
| 2 | 31 tasks, v0.1, task-set digest, 28 Mode-B / 3 Mode-A | the frozen catalog is loaded from `tasks.json`, not hard-coded |
| 3 | vulnerable run → agent 0.0, `real_target=False` | recall: every attack fires; the stub is labelled as a stub in the tool's own output |
| 4 | hardened run → agent 100.0, `real_target=False` | specificity: nothing fires |
| 5 | both verify, `--require run_complete` | all five levels reached, printed by name |
| 6 | secret, preimage, digest, caret under the digest in the egress string | the whole oracle in one screen, **with its limitation stated on screen** |
| 7 | tamper → rejection → `exit status: 1` | tamper-evidence, with a stable non-zero exit |
| — | summary: artifacts, scores, levels, SHA-256s, disclaimer | what a viewer should take away, and what they should not |

## Troubleshooting

- **`reset.sh` reports success but `run_demo.sh` fails immediately.** Check `PYTHON`; the demo
  uses `python3` unless told otherwise.
- **The recorder exits 1 with "encoder died mid-recording".** That is deliberate: a dead encoder
  used to produce a "successful" run with no video. Read `demo/out/ffmpeg.log`.
- **`validate_video.py` says `STATIC OR NEARLY STATIC`.** The recording really is frozen, or
  `ASSAY_SAMPLE_EVERY` has been set to a whole number of seconds and is aliasing with the cursor
  blink. Check the frames in `demo/out/frames/` by eye before believing either.
