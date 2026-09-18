"""Maintainer attestation: a record of an *independent rerun*, kept separate from verification.

A manifest that passes ``assay verify`` has said nothing about whether anyone other than
its author ever ran the target. That is a different claim, it needs a different artifact,
and it must never be folded into the verifier's output -- which is exactly the conflation
that made the v0.1 leaderboard's single "VERIFIED" badge misleading.

An attestation says: *this maintainer reran this target at this code commit and got these
invariants*. It is repository-controlled (it lives in ``attest/`` and its provenance is the
commit that adds it), not submitter-controlled.

Comparison is on INVARIANTS, not bytes. A rerun mints a fresh run secret, so digests,
envelopes, integrity hashes and timestamps all legitimately differ. What must match is the
per-task fired/ASR vector, the scores, the target fingerprint and the task-set digest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import MalformedInput, ValidationError

SCHEMA = "assay/attestation/1"

STATUS_MATCH = "match"
STATUS_DIVERGED = "diverged"
STATUS_FAILED = "rerun_failed"


def invariants(manifest: dict[str, Any]) -> dict[str, Any]:
    """The reproducible core of a run: everything that must survive a fresh run secret."""
    per_task = {f["id"]: {"fired": bool(f["fired"]), "asr": round(float(f["asr"]), 6),
                          "mode": f["mode"], "oracle": f["oracle"], "weight": f["weight"]}
                for f in manifest["findings"]}
    provenance = manifest.get("provenance") or {}
    return {
        "benchmark_version": manifest["version"],
        "track": manifest["track"],
        "target_fingerprint": manifest["target_fingerprint"],
        "task_set_digest": provenance.get("task_set_digest"),
        "trials_per_task": manifest["trials_per_task"],
        "agent_resistance_score": manifest["agent_resistance_score"],
        "server_posture_score": manifest["server_posture_score"],
        "per_task": per_task,
    }


def invariants_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(invariants(manifest), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def compare(submitted: dict[str, Any], rerun: dict[str, Any]) -> dict[str, Any]:
    """Diff two manifests on invariants. Returns a structured, human-readable delta."""
    a, b = invariants(submitted), invariants(rerun)
    differences: list[str] = []
    for key in ("benchmark_version", "track", "target_fingerprint", "task_set_digest",
                "trials_per_task", "agent_resistance_score", "server_posture_score"):
        if a[key] != b[key]:
            differences.append(f"{key}: submitted {a[key]!r} vs rerun {b[key]!r}")
    only_submitted = sorted(set(a["per_task"]) - set(b["per_task"]))
    only_rerun = sorted(set(b["per_task"]) - set(a["per_task"]))
    if only_submitted:
        differences.append(f"tasks only in the submission: {only_submitted}")
    if only_rerun:
        differences.append(f"tasks only in the rerun: {only_rerun}")
    for tid in sorted(set(a["per_task"]) & set(b["per_task"])):
        sa, sb = a["per_task"][tid], b["per_task"][tid]
        if sa != sb:
            differences.append(f"{tid}: submitted {sa} vs rerun {sb}")
    return {"status": STATUS_MATCH if not differences else STATUS_DIVERGED,
            "differences": differences,
            "submitted_invariants_digest": invariants_digest(submitted),
            "rerun_invariants_digest": invariants_digest(rerun)}


def build(*, submitted: dict[str, Any], rerun: dict[str, Any] | None, maintainer: str,
          code_commit: str | None, note: str = "", failure: str = "") -> dict[str, Any]:
    if not maintainer:
        raise ValidationError("an attestation must name the maintainer who performed it")
    if rerun is None:
        result = {"status": STATUS_FAILED, "differences": [failure or "rerun did not complete"],
                  "submitted_invariants_digest": invariants_digest(submitted),
                  "rerun_invariants_digest": None}
    else:
        result = compare(submitted, rerun)
    return {
        "schema": SCHEMA,
        "maintainer": maintainer,
        "attested_at": datetime.now(timezone.utc).isoformat(),
        "code_commit": code_commit,
        "submitted_manifest_integrity_hash": submitted["integrity_hash"],
        "rerun_manifest_integrity_hash": (rerun or {}).get("integrity_hash"),
        "target_fingerprint": submitted["target_fingerprint"],
        "target_is_real": (submitted.get("provenance") or {}).get("target_is_real"),
        "status": result["status"],
        "differences": result["differences"],
        "submitted_invariants_digest": result["submitted_invariants_digest"],
        "rerun_invariants_digest": result["rerun_invariants_digest"],
        "note": note,
        "scope": ("This attests that the named maintainer reran the target described by "
                  "target_fingerprint and compared run invariants. It does not attest that "
                  "the target is any particular commercial product, and it does not "
                  "upgrade the submitter's own evidence."),
    }


def validate(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise MalformedInput("attestation must be a JSON object")
    for key in ("schema", "maintainer", "attested_at", "submitted_manifest_integrity_hash",
                "status"):
        if key not in record:
            raise MalformedInput(f"attestation missing {key!r}")
    if record["schema"] != SCHEMA:
        raise ValidationError(f"unsupported attestation schema {record['schema']!r}")
    if record["status"] not in (STATUS_MATCH, STATUS_DIVERGED, STATUS_FAILED):
        raise ValidationError(f"unknown attestation status {record['status']!r}")
    return record


def load_all(directory: Path) -> dict[str, dict[str, Any]]:
    """Index attestations by the integrity hash of the manifest they attest."""
    out: dict[str, dict[str, Any]] = {}
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        record = validate(json.loads(path.read_text(encoding="utf-8")))
        out[record["submitted_manifest_integrity_hash"]] = record
    return out
