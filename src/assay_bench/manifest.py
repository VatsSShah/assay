"""Manifest construction, canonical integrity hashing, and strict structural validation.

The integrity hash is SHA-256 over the document with ``integrity_hash`` removed, encoded
as JSON with sorted keys. That is the frozen v0.1 rule and stays unchanged, so a v0.1
manifest keeps verifying byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from .errors import MalformedInput, ValidationError

REQUIRED_TOP_LEVEL = (
    "benchmark", "version", "track", "target", "target_fingerprint", "trials_per_task",
    "generated_at", "harness", "agent_resistance_score", "server_posture_score",
    "over_refusal_rate", "findings", "run_secret_commitment", "run_secret_reveal",
    "integrity_hash",
)
OPTIONAL_TOP_LEVEL = ("scope", "validity", "provenance", "precommitment", "attestation",
                      "utility", "diagnostics", "contamination")

REQUIRED_FINDING = ("id", "attack", "mode", "oracle", "evidence_type", "fired", "asr",
                    "asr_ci", "weight")

MODES = ("A", "B")
ORACLES = ("canary", "protocol", "behavioral")
EVIDENCE = ("canary", "protocol-fact", "behavioral")
EVIDENCE_FOR_ORACLE = {"canary": "canary", "protocol": "protocol-fact", "behavioral": "behavioral"}


def integrity_hash(manifest: dict[str, Any]) -> str:
    body = {k: v for k, v in manifest.items() if k != "integrity_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def seal(manifest: dict[str, Any]) -> dict[str, Any]:
    manifest.pop("integrity_hash", None)
    manifest["integrity_hash"] = integrity_hash(manifest)
    return manifest


def _number(value: Any, where: str, *, lo: float | None = None, hi: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{where}: expected a number, got {type(value).__name__}")
    v = float(value)
    if math.isnan(v) or math.isinf(v):
        raise ValidationError(f"{where}: {value!r} is not finite")
    if lo is not None and v < lo:
        raise ValidationError(f"{where}: {v} is below the minimum {lo}")
    if hi is not None and v > hi:
        raise ValidationError(f"{where}: {v} is above the maximum {hi}")
    return v


def validate_structure(manifest: Any) -> dict[str, Any]:
    """Structural validation equivalent to ``manifest_schema.json``.

    Hand-written on purpose: no JSON Schema engine ships with this project, so claiming
    schema enforcement at runtime would be a false claim. The schema file remains the
    published contract and ``tests/test_schema_parity.py`` keeps the two in step.
    """
    if not isinstance(manifest, dict):
        raise MalformedInput("manifest must be a JSON object")
    for key in REQUIRED_TOP_LEVEL:
        if key not in manifest:
            raise MalformedInput(f"manifest missing required field {key!r}")
    unknown = set(manifest) - set(REQUIRED_TOP_LEVEL) - set(OPTIONAL_TOP_LEVEL)
    if unknown:
        raise MalformedInput(f"manifest has unknown field(s): {sorted(unknown)}")
    if manifest["benchmark"] != "Assay":
        raise ValidationError(f"not an Assay manifest: benchmark={manifest['benchmark']!r}")
    if not isinstance(manifest["version"], str) or not manifest["version"]:
        raise ValidationError("version must be a non-empty string")
    if manifest["track"] not in ("agent", "server"):
        raise ValidationError(f"invalid track {manifest['track']!r}")

    target = manifest["target"]
    if not isinstance(target, dict):
        raise MalformedInput("target must be an object")
    for key in ("kind", "model_snapshot", "note"):
        if key not in target:
            raise MalformedInput(f"target missing required field {key!r}")
    if not isinstance(target["kind"], str) or not target["kind"]:
        raise ValidationError("target.kind must be a non-empty string")

    if not isinstance(manifest["target_fingerprint"], str) or not manifest["target_fingerprint"]:
        raise ValidationError("target_fingerprint must be a non-empty string")
    n = manifest["trials_per_task"]
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValidationError(f"trials_per_task must be a positive integer, got {n!r}")
    if not isinstance(manifest["generated_at"], str) or not manifest["generated_at"]:
        raise ValidationError("generated_at must be a non-empty string")

    harness = manifest["harness"]
    if not isinstance(harness, dict) or "engine" not in harness or "assay_version" not in harness:
        raise MalformedInput("harness must be an object with 'engine' and 'assay_version'")

    for key in ("agent_resistance_score", "server_posture_score", "over_refusal_rate"):
        if manifest[key] is not None:
            _number(manifest[key], key, lo=0.0, hi=100.0)

    for key in ("run_secret_commitment", "run_secret_reveal", "integrity_hash"):
        value = manifest[key]
        if not isinstance(value, str) or not value:
            raise ValidationError(f"{key} must be a non-empty string")

    block = manifest.get("validity")
    if block is not None:
        if not isinstance(block, dict):
            raise MalformedInput("validity must be an object")
        for key in ("rules_version", "assessment", "explanation"):
            if key not in block:
                raise MalformedInput(f"validity missing required key {key!r}")
        assessment = block["assessment"]
        if not isinstance(assessment, dict):
            raise MalformedInput("validity.assessment must be an object")
        if assessment.get("completion") not in ("complete", "partial"):
            raise ValidationError(
                f"validity.assessment.completion must be 'complete' or 'partial', got "
                f"{assessment.get('completion')!r}")
        for key in ("agent_resistance_lower_bound", "server_posture_lower_bound"):
            if block.get(key) is not None:
                _number(block[key], f"validity.{key}", lo=0.0, hi=100.0)

    findings = manifest["findings"]
    if not isinstance(findings, list):
        raise MalformedInput("findings must be an array")

    seen: set[str] = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            raise MalformedInput(f"{where}: must be an object")
        for key in REQUIRED_FINDING:
            if key not in f:
                raise MalformedInput(f"{where}: missing required field {key!r}")
        extra = set(f) - set(REQUIRED_FINDING) - {"canary"}
        if extra:
            raise MalformedInput(f"{where}: unknown field(s) {sorted(extra)}")
        tid = f["id"]
        if not isinstance(tid, str) or not tid:
            raise ValidationError(f"{where}: id must be a non-empty string")
        if tid in seen:
            raise ValidationError(f"{where}: duplicate finding for task id {tid!r}")
        seen.add(tid)
        if f["mode"] not in MODES:
            raise ValidationError(f"{where} ({tid}): invalid mode {f['mode']!r}")
        if f["oracle"] not in ORACLES:
            raise ValidationError(f"{where} ({tid}): invalid oracle {f['oracle']!r}")
        if f["evidence_type"] not in EVIDENCE:
            raise ValidationError(f"{where} ({tid}): invalid evidence_type {f['evidence_type']!r}")
        if not isinstance(f["fired"], bool):
            raise ValidationError(f"{where} ({tid}): fired must be a boolean")
        _number(f["asr"], f"{where} ({tid}).asr", lo=0.0, hi=1.0)
        _number(f["weight"], f"{where} ({tid}).weight", lo=0.0, hi=1.0)
        ci = f["asr_ci"]
        if not isinstance(ci, list) or len(ci) != 2:
            raise ValidationError(f"{where} ({tid}): asr_ci must be a 2-element array")
        lo = _number(ci[0], f"{where} ({tid}).asr_ci[0]", lo=0.0, hi=1.0)
        hi = _number(ci[1], f"{where} ({tid}).asr_ci[1]", lo=0.0, hi=1.0)
        if lo > hi:
            raise ValidationError(f"{where} ({tid}): asr_ci lower bound {lo} exceeds upper {hi}")
        if "canary" in f:
            c = f["canary"]
            if not isinstance(c, dict):
                raise MalformedInput(f"{where} ({tid}).canary must be an object")
            for key in ("origin", "tool", "step", "observed"):
                if key not in c:
                    raise MalformedInput(f"{where} ({tid}).canary missing {key!r}")
            if set(c) - {"origin", "tool", "step", "observed"}:
                raise MalformedInput(f"{where} ({tid}).canary has unknown fields")
            if isinstance(c["step"], bool) or not isinstance(c["step"], int):
                raise ValidationError(f"{where} ({tid}).canary.step must be an integer")
            for key in ("origin", "tool", "observed"):
                if not isinstance(c[key], str):
                    raise ValidationError(f"{where} ({tid}).canary.{key} must be a string")
    return manifest
