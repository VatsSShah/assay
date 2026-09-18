"""Run provenance and target fingerprinting.

The v0.1 schema described ``target_fingerprint`` as a "hash of tool catalog + transport +
task set", which is not a specification: it names no canonical serialization and no field
list, so two honest harnesses would disagree. This module fixes that.

``target_fingerprint`` = SHA-256 over the UTF-8 JSON below, keys sorted, no whitespace,
truncated to 16 hex characters (the width the v0.1 manifests already carry):

    {"adapter": <adapter.name>,
     "adapter_version": <adapter.version>,
     "kind": <adapter.kind>,
     "transport": <capabilities.transport>,
     "is_real_target": <capabilities.is_real_target>,
     "capabilities": <capabilities.to_json(), keys sorted>,
     "task_set_digest": <catalog.digest>,
     "benchmark_version": <catalog.version>,
     "material": <adapter.fingerprint_material(), keys sorted>}

Two runs share a fingerprint iff every one of those fields matches. Tests assert both
directions: stability across repeated construction, and sensitivity to a change in each
contributing field.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from typing import Any

FINGERPRINT_HEX = 16

#: Document-format revision of the manifest. Distinct from the benchmark version, which
#: names the frozen task-set line and must not move when only the document grows fields.
MANIFEST_FORMAT = "2"


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def target_fingerprint(adapter, catalog) -> str:
    caps = adapter.capabilities()
    material = {
        "adapter": adapter.name,
        "adapter_version": adapter.version,
        "kind": adapter.kind,
        "transport": caps.transport,
        "is_real_target": caps.is_real_target,
        "capabilities": caps.to_json(),
        "task_set_digest": catalog.digest,
        "benchmark_version": catalog.version,
        "material": adapter.fingerprint_material(),
    }
    return hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()[:FINGERPRINT_HEX]


def fingerprint_material(adapter, catalog) -> dict[str, Any]:
    """The exact pre-image, so a third party can recompute the fingerprint by hand."""
    caps = adapter.capabilities()
    return {
        "adapter": adapter.name,
        "adapter_version": adapter.version,
        "kind": adapter.kind,
        "transport": caps.transport,
        "is_real_target": caps.is_real_target,
        "capabilities": caps.to_json(),
        "task_set_digest": catalog.digest,
        "benchmark_version": catalog.version,
        "material": adapter.fingerprint_material(),
    }


def code_commit() -> str | None:
    """The commit this harness ran from, read from .git without invoking git."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    head = root / ".git" / "HEAD"
    if not head.is_file():
        return None
    try:
        ref = head.read_text(encoding="utf-8").strip()
        if ref.startswith("ref: "):
            target = root / ".git" / ref[5:]
            if target.is_file():
                return target.read_text(encoding="utf-8").strip()
            packed = root / ".git" / "packed-refs"
            if packed.is_file():
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line.endswith(" " + ref[5:]):
                        return line.split(" ", 1)[0]
            return None
        return ref or None
    except OSError:  # pragma: no cover - unreadable .git
        return None


def environment_summary() -> dict[str, Any]:
    """Coarse environment facts. Deliberately excludes usernames, hostnames, paths and
    environment variables: provenance must never become an accidental secret channel."""
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "argv0": sys.argv[0].rsplit("/", 1)[-1] if sys.argv else "",
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build(adapter, catalog, *, run_id: str, trials: int, command: str,
          started_at: str, ended_at: str, errors: list[dict[str, Any]],
          timeouts: int, completion: str, runner_version: str,
          tasks_planned: int, tasks_completed: int) -> dict[str, Any]:
    """The provenance block embedded in every generated manifest."""
    caps = adapter.capabilities()
    return {
        "run_id": run_id,
        "benchmark_version": catalog.version,
        "task_set_digest": catalog.digest,
        "task_set_split": catalog.split,
        "runner_version": runner_version,
        "manifest_format": MANIFEST_FORMAT,
        "code_commit": code_commit(),
        "adapter": {"name": adapter.name, "version": adapter.version, "kind": adapter.kind,
                    "capabilities": caps.to_json()},
        "target_is_real": caps.is_real_target,
        "transport": caps.transport,
        "target_fingerprint_material": fingerprint_material(adapter, catalog),
        "command": command,
        "environment": environment_summary(),
        "started_at": started_at,
        "ended_at": ended_at,
        "trials_per_task": trials,
        "tasks_planned": tasks_planned,
        "tasks_completed": tasks_completed,
        "timeouts": timeouts,
        "errors": errors,
        "completion": completion,
        "deterministic_target": not caps.is_real_target,
    }
