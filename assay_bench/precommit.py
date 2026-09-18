"""Pre-run commitment: creation, binding, and temporally-enforced verification.

THE PROBLEM THIS SOLVES
-----------------------
v0.1 put ``run_secret_commitment`` and ``run_secret_reveal`` in the same document. Checking
``SHA-256(reveal) == commitment`` then proves only that the submitter owns a SHA-256
implementation. It establishes no ordering, so it cannot limit result grinding: run the
benchmark fifty times with fifty secrets, publish the best one.

THE TRUST MODEL
---------------
A commitment is only evidence if a party the submitter does not control witnessed it
before the results existed. This module therefore separates three things that v0.1
conflated, and is explicit about which authority supplies each:

  1. ``local_commitment_consistency`` -- the reveal hashes to the commitment and the
     commitment's bound parameters match the manifest. Authority: arithmetic. Available
     offline. Proves NO ordering. This is all v0.1 ever had.
  2. ``repository_ordering_verified`` -- the commit that introduced the registry record is
     a strict ancestor of the commit that introduced the manifest, and is strictly earlier
     by committer date. Authority: the git history of this repository. A submitter who
     owns their fork can forge this; it is evidence only for history a third party
     observed being pushed.
  3. ``precommitment_verified`` -- (2) plus the ordering being witnessed by the forge
     (GitHub push/event records for this repository, checked in CI, where the submitter
     cannot backdate). This is the only level that may be called "externally timestamped
     precommitment".

An offline run can reach (1) and, in a local clone, (2). It can never reach (3), and
``assay precommit-verify`` says so rather than quietly upgrading the label.

WHAT EVEN (3) DOES NOT PROVE
----------------------------
That every run was published. A submitter can register N commitments, run N times, and
reveal one. Duplicate-registration detection makes that visible in the registry (all N
records are public), which is a deterrent, not a proof. The claim wording permitted by
this implementation is therefore "unpublished runs are visible as unrevealed registry
records", never "kills cherry-picking".

OPERATIONAL EDGE CASES (all covered by tests)
---------------------------------------------
  * rebase / amend / force-push  -- verification reads the commit that *currently*
    introduces the record; a rewritten history simply fails the ancestry check.
  * clock skew                   -- committer dates are advisory; ancestry is the primary
    test and a date inversion is reported, not silently tolerated.
  * retries                      -- a registry record may bind at most one manifest.
    A second binding attempt is rejected as reuse.
  * abandoned commitments        -- records with no revealed manifest stay in the registry
    and are listed by ``assay precommit-list``; that is the anti-grinding signal.
  * multiple targets             -- the record binds one target fingerprint; a manifest for
    a different target cannot claim it.
  * secret rotation              -- a new run means a new secret means a new record.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canary import commitment as secret_commitment
from .errors import MalformedInput, PrecommitmentError, ValidationError

REGISTRY_DIRNAME = "precommit/registry"
RECORD_SCHEMA = "assay/precommit-record/1"

LEVEL_LOCAL = "local_commitment_consistency"
LEVEL_REPO = "repository_ordering_verified"
LEVEL_EXTERNAL = "precommitment_verified"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def bound_digest(record: dict[str, Any]) -> str:
    """Digest over exactly the fields a commitment binds, canonically serialised."""
    payload = {k: record[k] for k in ("commitment", "benchmark_version", "task_set_digest",
                                      "target_fingerprint", "trial_plan", "run_id", "nonce")}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def create_record(*, run_secret: str, benchmark_version: str, task_set_digest: str,
                  target_fingerprint: str, trials: int, run_id: str | None = None,
                  note: str = "") -> dict[str, Any]:
    """Build a pre-run commitment record.

    ``created_at`` is recorded for human reading only. It is submitter-controlled and is
    never consulted by verification -- ordering comes from the repository, not from a
    timestamp inside a file the submitter wrote.
    """
    if not isinstance(trials, int) or isinstance(trials, bool) or trials < 1:
        raise ValidationError(f"trial_plan.trials must be a positive integer, got {trials!r}")
    record = {
        "schema": RECORD_SCHEMA,
        "run_id": run_id or str(uuid.uuid4()),
        "commitment": secret_commitment(run_secret),
        "benchmark_version": benchmark_version,
        "task_set_digest": task_set_digest,
        "target_fingerprint": target_fingerprint,
        "trial_plan": {"trials_per_task": trials, "scope": "full"},
        "nonce": uuid.uuid4().hex,
        "created_at_submitter_clock": _utc(),
        "note": note,
        "bound_manifest_integrity_hash": None,
    }
    record["record_digest"] = bound_digest(record)
    return record


def validate_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise MalformedInput("precommitment record must be a JSON object")
    required = ("schema", "run_id", "commitment", "benchmark_version", "task_set_digest",
                "target_fingerprint", "trial_plan", "nonce", "record_digest")
    for key in required:
        if key not in record:
            raise MalformedInput(f"precommitment record missing {key!r}")
    if record["schema"] != RECORD_SCHEMA:
        raise PrecommitmentError(
            f"unsupported precommitment record schema {record['schema']!r}; "
            f"this build understands {RECORD_SCHEMA!r}")
    if bound_digest(record) != record["record_digest"]:
        raise PrecommitmentError(
            f"precommitment record {record['run_id']} was altered: its record_digest does "
            f"not match the bound fields")
    plan = record["trial_plan"]
    if not isinstance(plan, dict) or "trials_per_task" not in plan:
        raise MalformedInput("trial_plan must be an object with trials_per_task")
    return record


def load_registry(registry_dir: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not registry_dir.is_dir():
        return out
    for path in sorted(registry_dir.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise MalformedInput(f"{path}: not valid JSON: {exc}") from None
        validate_record(record)
        commitment_value = record["commitment"]
        if commitment_value in out:
            raise PrecommitmentError(
                f"duplicate commitment {commitment_value[:16]}... registered twice: "
                f"{out[commitment_value]['run_id']} and {record['run_id']}")
        record["_path"] = str(path)
        out[commitment_value] = record
    return out


# ------------------------------------------------------------------- git time authority

def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                            timeout=30)
    if result.returncode != 0:
        raise PrecommitmentError(
            f"git {' '.join(args)} failed: {result.stderr.strip() or 'unknown error'}")
    return result.stdout.strip()


def introducing_commit(repo: Path, path: str) -> tuple[str, int]:
    """The commit that added ``path``, with its committer timestamp."""
    out = _git(repo, "log", "--diff-filter=A", "--follow", "--format=%H %ct", "-1", "--", path)
    if not out:
        raise PrecommitmentError(
            f"{path} has no commit that introduces it; an uncommitted file carries no "
            f"repository ordering evidence")
    sha, ts = out.split()
    return sha, int(ts)


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise PrecommitmentError(f"git merge-base failed: {result.stderr.strip()}")


def verify(manifest: dict[str, Any], *, repo: Path, registry_dir: Path | None = None,
           manifest_path: str | None = None,
           external_witness: dict[str, Any] | None = None) -> dict[str, Any]:
    """Verify a manifest's precommitment and report the highest level actually reached."""
    registry_dir = registry_dir or (repo / REGISTRY_DIRNAME)
    levels: list[str] = []
    notes: dict[str, str] = {}

    reveal = manifest.get("run_secret_reveal")
    if not isinstance(reveal, str) or not reveal:
        raise PrecommitmentError("manifest has no run_secret_reveal")
    stated = manifest.get("run_secret_commitment")
    computed = secret_commitment(reveal)
    if computed != stated:
        raise PrecommitmentError("the manifest's own commitment does not bind its reveal")

    registry = load_registry(registry_dir)
    record = registry.get(computed)
    if record is None:
        raise PrecommitmentError(
            f"no registry record for commitment {computed[:16]}...: the commitment was "
            f"never registered before the run, so no ordering evidence exists")

    # --- level 1: the record actually binds THIS run ---------------------------------
    mismatches = []
    if record["benchmark_version"] != manifest["version"]:
        mismatches.append(f"benchmark_version {record['benchmark_version']!r} != "
                          f"{manifest['version']!r}")
    if record["target_fingerprint"] != manifest["target_fingerprint"]:
        mismatches.append(f"target_fingerprint {record['target_fingerprint']!r} != "
                          f"{manifest['target_fingerprint']!r}")
    planned = record["trial_plan"]["trials_per_task"]
    if planned != manifest["trials_per_task"]:
        mismatches.append(f"trials_per_task {planned} != {manifest['trials_per_task']}")
    provenance = manifest.get("provenance") or {}
    if provenance.get("task_set_digest") and record["task_set_digest"] != provenance["task_set_digest"]:
        mismatches.append("task_set_digest differs from the run's provenance")
    if provenance.get("run_id") and record["run_id"] != provenance["run_id"]:
        mismatches.append(f"run_id {record['run_id']!r} != {provenance['run_id']!r}")
    if mismatches:
        raise PrecommitmentError(
            f"registry record {record['run_id']} does not bind this manifest: "
            + "; ".join(mismatches))

    bound = record.get("bound_manifest_integrity_hash")
    if bound not in (None, manifest["integrity_hash"]):
        raise PrecommitmentError(
            f"commitment reuse: record {record['run_id']} is already bound to manifest "
            f"{bound[:16]}..., it cannot also authenticate {manifest['integrity_hash'][:16]}...")
    levels.append(LEVEL_LOCAL)

    # --- level 2: repository ordering --------------------------------------------------
    record_path = record.get("_path")
    if manifest_path is None:
        notes[LEVEL_REPO] = ("no manifest path given, so the commit that introduces the "
                             "manifest is unknown")
    else:
        try:
            rel_record = str(Path(record_path).resolve().relative_to(repo.resolve()))
            rel_manifest = str(Path(manifest_path).resolve().relative_to(repo.resolve()))
            c_sha, c_ts = introducing_commit(repo, rel_record)
            m_sha, m_ts = introducing_commit(repo, rel_manifest)
            if c_sha == m_sha:
                notes[LEVEL_REPO] = (
                    f"the commitment and the manifest were introduced by the same commit "
                    f"{c_sha[:12]}; a same-commit commitment carries no ordering evidence")
            elif not is_ancestor(repo, c_sha, m_sha):
                notes[LEVEL_REPO] = (
                    f"the commitment commit {c_sha[:12]} is not an ancestor of the manifest "
                    f"commit {m_sha[:12]}: the commitment is not provably earlier")
            elif c_ts >= m_ts:
                notes[LEVEL_REPO] = (
                    f"committer dates are inverted (commitment {c_ts} >= manifest {m_ts}); "
                    f"ancestry holds but the clock disagrees, so ordering is not asserted")
            else:
                levels.append(LEVEL_REPO)
        except (ValueError, PrecommitmentError) as exc:
            notes[LEVEL_REPO] = str(exc)

    # --- level 3: external witness -----------------------------------------------------
    if LEVEL_REPO not in levels:
        notes[LEVEL_EXTERNAL] = "requires repository ordering first"
    elif not external_witness:
        notes[LEVEL_EXTERNAL] = (
            "no forge witness supplied. Repository ancestry alone can be rewritten by "
            "whoever owns the history; external timestamping requires the push/event record "
            "for this repository, which CI supplies")
    else:
        witness_sha = external_witness.get("commitment_commit")
        if witness_sha != c_sha:
            notes[LEVEL_EXTERNAL] = (
                f"witness names commit {witness_sha!r}, not the commit that introduced the "
                f"registry record")
        else:
            levels.append(LEVEL_EXTERNAL)

    return {
        "run_id": record["run_id"],
        "commitment": computed,
        "levels_verified": levels,
        "levels_not_established": notes,
        "registry_record": record_path,
        "note": ("Even at precommitment_verified, this proves one commitment predated one "
                 "result. It does not prove every run was published; unrevealed registry "
                 "records are the visible signal for that."),
    }


def bind_record(record_path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Bind a registry record to the manifest it authenticated. Refuses to rebind."""
    record = validate_record(json.loads(record_path.read_text(encoding="utf-8")))
    existing = record.get("bound_manifest_integrity_hash")
    if existing not in (None, manifest["integrity_hash"]):
        raise PrecommitmentError(
            f"record {record['run_id']} is already bound to a different manifest")
    record["bound_manifest_integrity_hash"] = manifest["integrity_hash"]
    record["bound_at_submitter_clock"] = _utc()
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record
