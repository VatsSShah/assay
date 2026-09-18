"""The canonical frozen task catalog.

``tasks.json`` at the repository root is the single source of truth for task ids,
modes, oracle classes and severity weights (SPEC.md §9 freezes all four within a
MAJOR.MINOR line). Nothing else in the tree may hold a second copy of a weight or
a mode; every consumer -- runner, scorer, manifest builder, verifier -- loads it
from here.

``assay_bench/data/tasks.json`` is a *generated* copy so the installed wheel is
self-contained. It is produced by ``python -m assay_bench.sync_data`` and CI fails
if it drifts from the root file (byte-for-byte).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any

from .errors import MalformedInput, ValidationError

MODES = ("A", "B")
ORACLES = ("canary", "protocol", "behavioral")
EVIDENCE_FOR_ORACLE = {"canary": "canary", "protocol": "protocol-fact", "behavioral": "behavioral"}
TRACK_MODE = {"agent": "B", "server": "A"}

_PKG = Path(__file__).resolve().parent
_REPO = _PKG.parent


class Task:
    """One frozen task. All five frozen fields are read-only attributes."""

    __slots__ = ("id", "attack", "title", "oracle", "evidence_type", "mode", "weight", "crosswalk")

    def __init__(self, raw: dict[str, Any]) -> None:
        self.id = raw["id"]
        self.attack = raw["attack"]
        self.title = raw["title"]
        self.oracle = raw["oracle"]
        self.evidence_type = raw["evidence_type"]
        self.mode = raw["mode"]
        self.weight = raw["weight"]
        self.crosswalk = raw.get("crosswalk", {})

    @property
    def track(self) -> str:
        return "agent" if self.mode == "B" else "server"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Task {self.id} mode={self.mode} oracle={self.oracle} w={self.weight}>"


class Catalog:
    """A validated task set plus its digest."""

    def __init__(self, doc: dict[str, Any], source: Path | None = None) -> None:
        self.source = source
        self.benchmark = doc["benchmark"]
        self.version = doc["version"]
        self.split = doc["split"]
        self.weights = doc["weights"]
        self.oracle_classes = doc["oracle_classes"]
        self.tasks = [Task(t) for t in doc["tasks"]]
        self.by_id = {t.id: t for t in self.tasks}
        self.digest = task_set_digest(doc)
        self._raw = doc

    def __len__(self) -> int:
        return len(self.tasks)

    def __iter__(self):
        return iter(self.tasks)

    def for_mode(self, mode: str) -> list[Task]:
        return [t for t in self.tasks if t.mode == mode]

    def for_track(self, track: str) -> list[Task]:
        if track not in TRACK_MODE:
            raise ValidationError(f"unknown track {track!r}; expected one of {sorted(TRACK_MODE)}")
        return self.for_mode(TRACK_MODE[track])

    def require(self, task_id: str) -> Task:
        try:
            return self.by_id[task_id]
        except KeyError:
            raise ValidationError(f"unknown task id {task_id!r}: not in the frozen catalog") from None


def task_set_digest(doc: dict[str, Any]) -> str:
    """A canonical digest over exactly the frozen fields.

    Deliberately excludes titles and the taxonomy crosswalk: those are editorial and
    may be corrected without breaking result comparability. Including them would make
    every typo fix look like a task-set change.
    """
    frozen = [
        {"id": t["id"], "mode": t["mode"], "oracle": t["oracle"],
         "evidence_type": t["evidence_type"], "weight": t["weight"]}
        for t in doc["tasks"]
    ]
    frozen.sort(key=lambda t: t["id"])
    payload = {"benchmark": doc["benchmark"], "version": doc["version"],
               "split": doc["split"], "weights": doc["weights"], "tasks": frozen}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def _finite(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{where}: expected a number, got {type(value).__name__}")
    v = float(value)
    if math.isnan(v) or math.isinf(v):
        raise ValidationError(f"{where}: {value!r} is not a finite number")
    return v


def validate_catalog_document(doc: Any) -> dict[str, Any]:
    """Strict structural + semantic validation of a task-set document.

    This is hand-written rather than JSON Schema driven: the repo ships no schema
    engine, so claiming "JSON Schema enforcement" at runtime would be false. The
    schema files remain the published contract; this is the executable check.
    """
    if not isinstance(doc, dict):
        raise MalformedInput("task set must be a JSON object")
    for key in ("benchmark", "version", "split", "weights", "oracle_classes", "n_tasks", "tasks"):
        if key not in doc:
            raise MalformedInput(f"task set missing required key {key!r}")
    if doc["benchmark"] != "Assay":
        raise ValidationError(f"not an Assay task set: benchmark={doc['benchmark']!r}")
    if not isinstance(doc["version"], str) or not doc["version"]:
        raise ValidationError("task set version must be a non-empty string")
    if doc["split"] not in ("public", "held-out"):
        raise ValidationError(f"unknown split {doc['split']!r}")

    weights = doc["weights"]
    if not isinstance(weights, dict) or not weights:
        raise ValidationError("weights must be a non-empty object")
    allowed_weights = set()
    for name, w in weights.items():
        val = _finite(w, f"weights[{name!r}]")
        if not 0 < val <= 1:
            raise ValidationError(f"weights[{name!r}]={val} must be in (0, 1]")
        allowed_weights.add(round(val, 6))

    tasks = doc["tasks"]
    if not isinstance(tasks, list) or not tasks:
        raise ValidationError("tasks must be a non-empty array")
    if doc["n_tasks"] != len(tasks):
        raise ValidationError(f"n_tasks={doc['n_tasks']!r} but the array holds {len(tasks)} tasks")

    seen: set[str] = set()
    for i, t in enumerate(tasks):
        where = f"tasks[{i}]"
        if not isinstance(t, dict):
            raise MalformedInput(f"{where}: must be an object")
        for key in ("id", "attack", "title", "oracle", "evidence_type", "mode", "weight"):
            if key not in t:
                raise MalformedInput(f"{where}: missing required key {key!r}")
        tid = t["id"]
        if not isinstance(tid, str) or not tid.strip():
            raise ValidationError(f"{where}: id must be a non-empty string")
        if tid in seen:
            raise ValidationError(f"{where}: duplicate task id {tid!r}")
        seen.add(tid)
        if t["mode"] not in MODES:
            raise ValidationError(f"{where} ({tid}): mode {t['mode']!r} not in {MODES}")
        if t["oracle"] not in ORACLES:
            raise ValidationError(f"{where} ({tid}): oracle {t['oracle']!r} not in {ORACLES}")
        expected_evidence = EVIDENCE_FOR_ORACLE[t["oracle"]]
        if t["evidence_type"] != expected_evidence:
            raise ValidationError(
                f"{where} ({tid}): oracle {t['oracle']!r} requires evidence_type "
                f"{expected_evidence!r}, got {t['evidence_type']!r}")
        w = _finite(t["weight"], f"{where} ({tid}).weight")
        if round(w, 6) not in allowed_weights:
            raise ValidationError(
                f"{where} ({tid}): weight {w} is not one of the published severity "
                f"weights {sorted(allowed_weights)}")
    return doc


def _candidate_paths() -> list[Path]:
    override = os.environ.get("ASSAY_TASKS")
    paths = [Path(override)] if override else []
    paths += [_REPO / "tasks.json", _PKG / "data" / "tasks.json"]
    return paths


def load_catalog(path: str | os.PathLike[str] | None = None) -> Catalog:
    """Load and validate the frozen catalog.

    Search order: explicit ``path``, then ``$ASSAY_TASKS``, then the repository root
    (source checkout), then the packaged copy (installed wheel).
    """
    candidates = [Path(path)] if path is not None else _candidate_paths()
    for candidate in candidates:
        if candidate.is_file():
            try:
                doc = json.loads(candidate.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise MalformedInput(f"{candidate}: not valid JSON: {exc}") from None
            return Catalog(validate_catalog_document(doc), source=candidate)
    raise MalformedInput("could not locate tasks.json; tried: " + ", ".join(str(c) for c in candidates))
