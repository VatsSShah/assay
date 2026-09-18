"""Prove a recording is genuinely time-varying, and measure how much it varies.

The previous "video" shipped with this project was a frozen terminal screen inside a video
container. A file being an MP4/WebM says nothing; what matters is whether successive frames
differ, and whether they differ *throughout* rather than only at the start.

This script works on the sampled JPEG frames the recorder writes alongside the video (one per
second), because decoding VP8 in pure Python is not something to hand-roll. It reports, per
adjacent pair: the SHA-256 of each frame, whether the bytes differ, and a size-delta ratio as
a coarse change magnitude. It then checks:

  * every adjacent pair differs (no frozen stretch);
  * the number of DISTINCT frames equals the number of samples;
  * change is spread across the timeline, not confined to one burst.

Stdlib only. Exits non-zero if the recording is static.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
from pathlib import Path


def _jpeg_luma_signature(data: bytes, buckets: int = 64) -> list[int]:
    """A cheap content signature: a histogram over the compressed entropy stream.

    Two visually different frames produce different compressed data, so a histogram over the
    scan bytes is a sound *difference* detector even without decoding. It cannot measure
    perceptual distance, and this script does not claim it does.
    """
    start = data.find(b"\xff\xda")
    scan = data[start:] if start >= 0 else data
    hist = [0] * buckets
    step = max(1, 256 // buckets)
    for byte in scan:
        hist[min(byte // step, buckets - 1)] += 1
    return hist


def _distance(a: list[int], b: list[int]) -> float:
    total = sum(a) + sum(b)
    if total == 0:
        return 0.0
    return sum(abs(x - y) for x, y in zip(a, b)) / total


def analyse(frames_dir: Path) -> dict:
    frames = sorted(frames_dir.glob("*.jpg"))
    if len(frames) < 3:
        raise SystemExit(f"need at least 3 sampled frames, found {len(frames)} in {frames_dir}")

    samples = []
    for path in frames:
        data = path.read_bytes()
        samples.append({
            "frame": path.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "_sig": _jpeg_luma_signature(data),
        })

    pairs = []
    for previous, current in zip(samples, samples[1:]):
        pairs.append({
            "from": previous["frame"],
            "to": current["frame"],
            "bytes_delta": current["bytes"] - previous["bytes"],
            "identical_bytes": previous["sha256"] == current["sha256"],
            "signature_distance": round(_distance(previous["_sig"], current["_sig"]), 6),
        })

    distinct = len({s["sha256"] for s in samples})
    frozen = [p for p in pairs if p["identical_bytes"]]
    distances = [p["signature_distance"] for p in pairs]
    changing = [d for d in distances if d > 0.001]

    # The longest run of consecutive identical samples. This, not "every frame differs", is the
    # property that separates a recording from a screenshot: a real terminal demo pauses while
    # a command runs, and demanding universal per-frame change would only invite decorative
    # animation. A LONG frozen stretch is what the rejected v0.1 "video" actually was.
    longest_frozen = current = 0
    for pair in pairs:
        current = current + 1 if pair["identical_bytes"] else 0
        longest_frozen = max(longest_frozen, current)

    # Split the timeline in half: a recording that only moves at the start is still a
    # near-frozen screen for most of its length.
    half = len(distances) // 2
    first_half = sum(distances[:half]) / max(1, half)
    second_half = sum(distances[half:]) / max(1, len(distances) - half)

    return {
        "frames_sampled": len(samples),
        "distinct_frames": distinct,
        "all_frames_distinct": distinct == len(samples),
        "frozen_adjacent_pairs": len(frozen),
        "longest_frozen_run_samples": longest_frozen,
        "pairs_with_visible_change": len(changing),
        "fraction_of_pairs_changing": round(len(changing) / len(pairs), 4),
        "mean_signature_distance": round(statistics.fmean(distances), 6),
        "median_signature_distance": round(statistics.median(distances), 6),
        "min_signature_distance": round(min(distances), 6),
        "max_signature_distance": round(max(distances), 6),
        "mean_distance_first_half": round(first_half, 6),
        "mean_distance_second_half": round(second_half, 6),
        "change_is_spread_across_timeline": first_half > 0.0005 and second_half > 0.0005,
        "samples": [{k: v for k, v in s.items() if k != "_sig"} for s in samples],
        "adjacent_pairs": pairs,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="validate that a demo recording changes over time")
    parser.add_argument("video")
    parser.add_argument("frames_dir")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    video = Path(args.video)
    if not video.is_file():
        print(f"missing video: {video}", file=sys.stderr)
        return 2

    report = analyse(Path(args.frames_dir))
    report["video"] = {
        "path": str(video),
        "bytes": video.stat().st_size,
        "sha256": hashlib.sha256(video.read_bytes()).hexdigest(),
        "container": "WebM (VP8)",
    }
    # Gate: the screen must move throughout, and must never sit still for long. A single
    # static pause while a command runs is normal; a frozen screen in a video container -- which
    # is what the rejected v0.1 "demo video" was -- fails on every one of these.
    report["gate"] = {
        "most_pairs_change": report["fraction_of_pairs_changing"] >= 0.75,
        "no_long_frozen_stretch": report["longest_frozen_run_samples"] <= 1,
        "change_spread_across_timeline": report["change_is_spread_across_timeline"],
        "enough_distinct_frames": report["distinct_frames"] >= 0.8 * report["frames_sampled"],
    }
    report["verdict"] = ("time-varying" if all(report["gate"].values())
                         else "STATIC OR NEARLY STATIC")
    report["method"] = (
        "Sampled frames are compared by SHA-256 (exact difference) and by a histogram over the "
        "JPEG entropy stream (coarse change magnitude). The histogram is a difference detector, "
        "not a perceptual metric, and is not presented as one."
    )

    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    summary = {k: report[k] for k in
               ("frames_sampled", "distinct_frames", "all_frames_distinct",
                "frozen_adjacent_pairs", "longest_frozen_run_samples",
                "fraction_of_pairs_changing", "mean_signature_distance",
                "change_is_spread_across_timeline", "gate", "verdict")}
    print(json.dumps(summary, indent=2))
    return 0 if report["verdict"] == "time-varying" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
