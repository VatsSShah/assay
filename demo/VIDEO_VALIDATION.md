# Video validation report

The previous 18-second "demo video" shipped with this project was a **frozen terminal screen in
a video container**. It was rejected, is not reused here in any form, and was not upscaled,
re-encoded or animated. This recording was made from scratch by running the demo live.

## Where the artifacts are

This is a public repository and a screen recording can capture more than its author intended, so
**the video and its frames are not committed.** They are delivered out of band and regenerated
with one command:

```bash
bash demo/record_video.sh        # writes demo/out/, then validates it
```

What *is* committed is the evidence needed to check every claim below:
`demo/recording/transcript.txt` (the exact text that appeared on screen) and
`demo/recording/validation.json` (a SHA-256 for the video and for each of the 31 sampled
frames). A test asserts the numbers in this file match that report, and that the binaries are
not tracked.

## The recording

| property | value |
|---|---|
| File | `demo/recording/assay-demo.webm` |
| Container / codec | WebM / VP8 |
| Resolution | 1920 × 1080 |
| Frame rate | 10 fps |
| Frames encoded | 216 |
| Duration | 21.6 s |
| Size | 3,236,663 bytes |
| SHA-256 | `2e8764bc3507ec0335c6fab24296d36baea09603efeec3516b51b2d7ac93abc7` |
| Demo exit status | 0 |
| ffmpeg exit status | 0 |
| Produced by | `bash demo/record_video.sh` |

## How it was captured

`demo/record.mjs` spawns `bash demo/run_demo.sh` and streams the process's **actual
stdout/stderr into the terminal page as it arrives**, while a capture loop grabs a frame every
1/10 s on its own clock. Frames differ because the process is producing output while the camera
is rolling. There is no pre-baked log, no typing animation, and no jump cut: the only pacing is
a real `sleep` between steps, which changes the pace and nothing else.

The capture loop runs independently of the output, so a quiet stretch still produces frames and
the timeline stays honest rather than skipping ahead.

## Frame-change analysis

`demo/validate_video.py` compares the sampled frames (every 7th frame = 0.7 s) by SHA-256, and
by a histogram over each JPEG's entropy stream as a coarse change magnitude. The histogram is a
**difference detector, not a perceptual metric**, and is not presented as one.

| measure | result |
|---|---|
| Frames sampled | 31 |
| Distinct frames (by SHA-256) | **31 / 31** |
| Adjacent pairs that are byte-identical | **0** |
| Longest run of identical consecutive samples | **0** |
| Fraction of adjacent pairs showing visible change | **0.9667** |
| Mean signature distance | 0.0639 |
| Min / max signature distance | 0.0005 / 0.2675 |
| Mean distance, first half of timeline | 0.0706 |
| Mean distance, second half of timeline | 0.0572 |

### Gate

| check | threshold | result |
|---|---|---|
| `most_pairs_change` | ≥ 75 % of adjacent pairs differ | ✅ 97% |
| `no_long_frozen_stretch` | ≤ 1 consecutive identical sample | ✅ 0 |
| `change_spread_across_timeline` | both halves show movement | ✅ 0.071 / 0.057 |
| `enough_distinct_frames` | ≥ 80 % of samples distinct | ✅ 100 % |

**Verdict: `time-varying`.**

The gate is deliberately *not* "every frame must differ". A real terminal demo pauses while a
command runs, and a rule demanding universal per-frame change would only push an author toward
decorative animation, which the recording does not have. What it does demand is that the screen
never sits still for long and that movement is spread across the whole timeline — which is
exactly what the rejected frozen-screen video failed.

The one piece of continuous motion is the footer clock, and it is information rather than
decoration: it shows the **real elapsed wall-clock of the process being recorded**, ticking from
`t+0.0s` to `t+21.2s`.

Full per-frame data, including every frame's SHA-256, is in `demo/recording/validation.json`; the sampled frames themselves are in `demo/recording/frames/` so the hashes can be recomputed.

## Human visual inspection

Frames were opened and read, not merely hashed.

| frame | t | what is on screen | legible at conference size? |
|---|---|---|---|
| `recording/frames/frame-00000.jpg` | 0.0 s | title bar, `$ bash demo/run_demo.sh`, step 1 banner, blinking cursor, footer disclaimer, `t+0.0s` | yes — 22 px mono, high contrast |
| `frame-00035.jpg` | 3.5 s | Python version and repo commit resolved; step 2 beginning | yes |
| `frame-00105.jpg` | 10.7 s | catalog loaded (31 tasks, v0.1, digest, 28 B / 3 A); vulnerable run → `agent=0.0 server=0.0 completion=complete real_target=False`; hardened run → `agent=100.0 server=100.0`; step 5 banner | yes |
| `frame-00140.jpg` | 14 s | verifier JSON: all five levels listed by name, `target_is_real: false` | yes |
| `frame-00168.jpg` | 17.0 s | the oracle in full: secret, commitment, preimage, digest, observed egress with a caret row under the digest, `recomputes: True`, and the on-screen caveat that this does not prove a target emitted it | yes |
| `frame-00210.jpg` | 21.2 s | tamper diff (before/after), rejection message, red `exit status: 1`, summary table with levels and SHA-256s, closing disclaimer | yes |

**Inspection notes.**

- Text is white/light-slate on `#0b0e14`; banners amber, commands cyan, the failure line red.
  Contrast is adequate for a projected slide.
- No content is clipped: long paths wrap rather than truncating, and the view pins to the last
  line so the newest output is always visible.
- The disclaimer *"Targets are built-in deterministic stubs — no live MCP server, agent or
  model."* is present in the footer of **every** frame, so no still frame taken from this video
  can be misread as a product measurement.
- Dead time is bounded: the longest gap between visible output is one 1.1 s pacing sleep.
- Nothing on screen is mocked. Every command, path, hash and exit code is what the process
  actually produced; `demo/out/transcript.txt` is the byte-for-byte text that was displayed.

## What a viewer may conclude from this video

- The harness runs all 31 frozen tasks against a target and produces a schema-valid scorecard.
- The verifier reports named evidence levels, not a verdict.
- A canary proof triple recomputes from the revealed secret, and where the digest sits in the
  egress string is visible.
- A single altered character class in a resealed manifest is rejected, with exit status 1.

## What a viewer may **not** conclude

- That any MCP server, agent or model was tested. None was.
- That the scores describe any real system. They describe stubs written for this repository.
- That verification proves a run occurred. Step 6 says the opposite, on screen.
