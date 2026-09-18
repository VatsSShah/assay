"""Assay badge: turn a verified scorecard into an embeddable shield.

Emits a shields.io endpoint object (https://shields.io/endpoint) plus a ready-to-paste
markdown line.

The badge label carries the evidence level, not just the number. A score from a run that
only reached ``internally_consistent`` says so, because a badge that reads the same for a
coherent document and for an independently reran measurement is the single most misleading
surface this project could ship.

Refuses outright to badge a run against a built-in deterministic conformance stub: those
validate the harness and are not results about anything.
"""

from __future__ import annotations

import json
import sys

import assay_verifier


class BadgeError(ValueError):
    """The manifest cannot be represented as a badge."""


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


#: Shortest honest suffix for each achievable level, most-to-least evidential.
_LEVEL_SUFFIX = [
    ("run_complete", "complete run"),
    ("catalog_bound", "catalog-bound"),
    ("canary_correspondence_verified", "canary-checked"),
    ("internally_consistent", "self-consistent"),
]


def badge(manifest: dict, *, attestation: dict | None = None) -> dict:
    track = manifest.get("track")
    if track not in ("agent", "server"):
        raise BadgeError(f"invalid track: {track!r}")

    result = assay_verifier.verify_manifest(manifest)
    provenance = manifest.get("provenance") or {}
    if provenance.get("target_is_real") is False:
        raise BadgeError(
            "this manifest is a built-in deterministic conformance run, not a measurement "
            "of a real target; badging it would present harness validation as a product "
            "result. Refusing.")

    # Validity rule V8: a partial run has no comparable headline number, so it gets no badge.
    validity = manifest.get("validity") or {}
    completion = (validity.get("assessment") or {}).get("completion")
    if completion is None:
        completion = (manifest.get("scope") or {}).get("completion")
    if completion == "partial":
        raise BadgeError(
            "this run is partial ("
            + (validity.get("explanation") or "see validity.assessment.reasons")
            + "). A partial run has no comparable score; cite "
              "validity.*_lower_bound instead. Refusing to badge it.")

    score = manifest["agent_resistance_score"] if track == "agent" else manifest["server_posture_score"]
    if score is None:
        raise BadgeError(f"scorecard has no {track} score to badge")

    suffix = next((label for level, label in _LEVEL_SUFFIX
                   if level in result["levels_verified"]), "unverified")
    if attestation is not None and attestation.get("status") == "match":
        suffix = "maintainer-rerun"

    return {
        "schemaVersion": 1,
        "label": f"Assay {track}",
        "message": f"{score} - v{manifest['version']} ({suffix})",
        "color": _color(float(score)),
    }


def markdown(badge_url: str) -> str:
    return f"![Assay](https://img.shields.io/endpoint?url={badge_url})"


def _main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python badge.py <manifest.json>", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        manifest = json.load(fh)
    try:
        print(json.dumps(badge(manifest), indent=2))
    except (BadgeError, assay_verifier.VerifierError) as exc:
        print(f"badge: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
