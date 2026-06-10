"""Assay badge, turn a passing scorecard into an embeddable shield.

Emits a shields.io endpoint object (https://shields.io/endpoint) plus a ready-to-paste
markdown line, so an adopter drops one line in their README:

    ![Assay-Secure](https://img.shields.io/endpoint?url=https://.../assay-badge.json)
"""

from __future__ import annotations

import json
import sys


def _color(score: float) -> str:
    if score >= 90:
        return "brightgreen"
    if score >= 75:
        return "green"
    if score >= 60:
        return "yellow"
    if score >= 40:
        return "orange"
    return "red"


def badge(manifest: dict) -> dict:
    track = manifest["track"]
    assert track in ("agent", "server"), f"invalid track: {track}"
    score = manifest["agent_resistance_score"] if track == "agent" else manifest["server_posture_score"]
    assert score is not None, "scorecard has no score for its track"
    return {
        "schemaVersion": 1,
        "label": f"Assay-Secure ({track})",
        "message": f"{score} on Assay v{manifest['version']}",
        "color": _color(score),
    }


def markdown(badge_url: str) -> str:
    return f"![Assay-Secure](https://img.shields.io/endpoint?url={badge_url})"


if __name__ == "__main__":
    manifest = json.loads(open(sys.argv[1]).read())
    print(json.dumps(badge(manifest), indent=2))
