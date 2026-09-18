"""Shared fixtures for the Assay test suite. Standard library only."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURES = ROOT / "tests" / "fixtures"
LEGACY = FIXTURES / "legacy_v0_1"
MANIFESTS = ROOT / "leaderboard" / "manifests"

import assay_verifier as V  # noqa: E402


def is_source_checkout() -> bool:
    """True in a git checkout, false in a tree unpacked from an sdist.

    An sdist deliberately omits git history and the recording binaries, so tests that need
    either are checkout-only. They skip with a reason rather than failing, which keeps the
    "does the distribution work?" signal meaningful instead of noisy.
    """
    return (ROOT / ".git").exists() and not (ROOT / "PKG-INFO").is_file()


def require_source_checkout(case) -> None:
    if not is_source_checkout():
        case.skipTest("checkout-only: this tree was unpacked from an sdist")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def reference(name: str) -> dict:
    return load(MANIFESTS / f"reference_{name}.json")


def legacy(name: str) -> dict:
    return load(LEGACY / f"reference_{name}.json")


def reseal(manifest: dict) -> dict:
    """Recompute the integrity hash after mutating a manifest, so tests exercise the rule
    under test rather than tripping the hash check first."""
    manifest.pop("integrity_hash", None)
    manifest["integrity_hash"] = V.integrity_hash(manifest)
    return manifest


CATALOG_DOC = load(ROOT / "tasks.json")


def rescore(manifest: dict, *, catalog: dict | None = CATALOG_DOC) -> dict:
    """Restate the scores so they match the (mutated) findings, then reseal.

    Uses the same fixed-catalog denominator the verifier does (validity rule V2), so a test
    exercising some other rule is not tripped by the score check first. Pass ``catalog=None``
    to restate over the reported findings instead.
    """
    findings = manifest["findings"]
    if catalog is None:
        manifest["agent_resistance_score"] = V._resistance(
            [f for f in findings if f["mode"] == "B"])
        manifest["server_posture_score"] = V._resistance(
            [f for f in findings if f["mode"] == "A"])
    else:
        manifest["agent_resistance_score"] = V._fixed_denominator_score(catalog, findings, "B")
        manifest["server_posture_score"] = V._fixed_denominator_score(catalog, findings, "A")
    if "validity" in manifest:
        # Keep the lower bound consistent too, or the validity check fires before the rule
        # under test does.
        block = manifest["validity"]
        per_task = block.get("per_task_outcomes") or {}
        not_conclusive = {tid for tid, tally in per_task.items()
                          if not any(k in ("resisted", "exploited") for k in (tally or {}))}
        charged = [f for f in findings if f["id"] not in not_conclusive]
        if block.get("agent_resistance_lower_bound") is not None:
            block["agent_resistance_lower_bound"] = V._fixed_denominator_score(
                catalog, charged, "B", missing_asr=1.0)
        if block.get("server_posture_lower_bound") is not None:
            block["server_posture_lower_bound"] = V._fixed_denominator_score(
                catalog, charged, "A", missing_asr=1.0)
    return reseal(manifest)


def mutate(manifest: dict, fn) -> dict:
    """Deep-copy, apply fn, then restate scores and reseal."""
    m = copy.deepcopy(manifest)
    fn(m)
    return rescore(m)


def first_fired_canary(manifest: dict) -> dict:
    for f in manifest["findings"]:
        if f.get("canary"):
            return f
    raise AssertionError("manifest has no fired canary finding")


def synthetic_manifest(*, secret: str = "ab" * 32, findings: list | None = None,
                       version: str = "0.1", track: str = "agent") -> dict:
    """A minimal, internally consistent manifest, built from scratch."""
    m = {
        "benchmark": "Assay",
        "version": version,
        "track": track,
        "target": {"kind": "synthetic", "model_snapshot": None, "note": "test fixture"},
        "target_fingerprint": "0123456789abcdef",
        "trials_per_task": 25,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "harness": {"engine": "test", "assay_version": version},
        "over_refusal_rate": None,
        "findings": findings if findings is not None else [],
        "run_secret_reveal": secret,
    }
    m["run_secret_commitment"] = V.commitment(secret)
    return rescore(m)


def canary_finding(task_id: str, secret: str, *, mode: str = "B", weight: float = 0.7,
                   asr: float = 1.0, origin: str | None = None, tool: str = "t",
                   step: int = 0, observed: str | None = None) -> dict:
    origin = origin or f"assay/{task_id}"
    if observed is None:
        observed = "egress " + V.digest(secret, f"{origin}|{tool}|{step}")
    f = {"id": task_id, "attack": "x", "mode": mode, "oracle": "canary",
         "evidence_type": "canary", "fired": asr > 0, "asr": asr,
         "asr_ci": [0.0, 1.0], "weight": weight}
    if asr > 0:
        f["canary"] = {"origin": origin, "tool": tool, "step": step, "observed": observed}
    return f
