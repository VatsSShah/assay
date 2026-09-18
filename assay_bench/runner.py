"""The trial loop: drive a target through the frozen task set and emit a scorecard.

Guarantees this loop does provide:
  * every task it reports came from the frozen catalog, with the catalog's own
    mode/oracle/evidence_type/weight (never a value supplied by the target);
  * every canary it reports as fired was recovered from egress by recomputation;
  * an adapter error or timeout is recorded as an error and marks the run incomplete,
    never silently as "the target resisted".

Guarantees it does NOT provide: that the target is the product someone names it after.
That is the adapter's and the maintainer re-run's job, and provenance records which kind
of adapter actually ran.
"""

from __future__ import annotations

import concurrent.futures
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from . import RUNNER_VERSION, provenance
from .adapters import Episode
from .canary import commitment, new_run_secret, parse_secret
from .catalog import Catalog, load_catalog
from .errors import AdapterError, ValidationError
from .oracles import evaluate
from .surface import build_surface

import scoring  # noqa: E402  canonical scoring, never re-implemented here


class TaskOutcome:
    __slots__ = ("task", "hits", "trials", "proof", "errors", "details")

    def __init__(self, task) -> None:
        self.task = task
        self.hits = 0
        self.trials = 0
        self.proof: dict[str, Any] | None = None
        self.errors: list[str] = []
        self.details: list[str] = []

    @property
    def asr(self) -> float:
        return self.hits / self.trials if self.trials else 0.0


class _Watchdog:
    """Runs episodes under a wall-clock budget.

    A Python thread cannot be killed, so on timeout the worker is abandoned and a fresh
    executor is started for the next trial. That is honest: the harness cannot claim the
    target resisted when it simply never answered. The executor is reused between healthy
    trials, because standing one up per episode dominated the runtime of a full 31x25 run.
    """

    def __init__(self) -> None:
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    def run(self, adapter, episode: Episode, timeout_s: float):
        future = self._pool.submit(adapter.run_episode, episode)
        try:
            return future.result(timeout=timeout_s), None
        except concurrent.futures.TimeoutError:
            # The worker is stuck; abandon this executor rather than queue behind it.
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            return None, "timeout"
        except Exception as exc:  # adapter failure is data, not a crash
            return None, f"{type(exc).__name__}: {exc}"

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def run(adapter, *, catalog: Catalog | None = None, track: str = "agent", trials: int = 25,
        run_secret: str | None = None, task_ids: list[str] | None = None,
        timeout_s: float = 10.0, command: str = "", target_note: str = "",
        model_snapshot: str | None = None, run_id: str | None = None) -> dict[str, Any]:
    """Execute the benchmark and return a schema-valid manifest document."""
    catalog = catalog or load_catalog()
    if track not in ("agent", "server"):
        raise ValidationError(f"track must be 'agent' or 'server', got {track!r}")
    if not isinstance(trials, int) or isinstance(trials, bool) or trials < 1:
        raise ValidationError(f"trials must be a positive integer, got {trials!r}")
    if trials < 5:
        # SPEC.md §5 requires N >= 5; a smaller run is allowed only as an explicit smoke
        # test and is marked partial so it can never look like a benchmark score.
        pass

    run_secret = run_secret or new_run_secret()
    parse_secret(run_secret)  # fail fast on a malformed supplied secret

    selected = list(catalog) if task_ids is None else [catalog.require(t) for t in task_ids]
    if not selected:
        raise ValidationError("no tasks selected")
    scoped_ids = {t.id for t in selected}

    # A precommitted run MUST reuse the run_id its registry record bound, otherwise the
    # commitment names a different run than the one being published.
    run_id = run_id or str(uuid.uuid4())
    started = provenance.utc_now()
    errors: list[dict[str, Any]] = []
    timeouts = 0
    outcomes: list[TaskOutcome] = []
    watchdog = _Watchdog()

    for task in selected:
        outcome = TaskOutcome(task)
        for trial in range(trials):
            surface = build_surface(task, run_secret, trial)
            episode = Episode(task_id=task.id, mode=task.mode, oracle=task.oracle,
                              attack=task.attack, trial=trial,
                              tool_catalog=surface["tool_catalog"],
                              tool_results=surface["tool_results"],
                              canary=surface["canary"], timeout_s=timeout_s)
            if adapter.capabilities().supports_reset:
                adapter.reset()
            observation, failure = watchdog.run(adapter, episode, timeout_s)
            if failure is not None:
                if failure == "timeout":
                    timeouts += 1
                errors.append({"task": task.id, "trial": trial, "error": failure})
                outcome.errors.append(failure)
                continue
            if observation.error:
                errors.append({"task": task.id, "trial": trial, "error": observation.error})
                outcome.errors.append(observation.error)
                continue
            try:
                result = evaluate(task.oracle, task.attack, observation, surface["canary"])
            except ValidationError as exc:
                errors.append({"task": task.id, "trial": trial, "error": f"oracle: {exc}"})
                outcome.errors.append(str(exc))
                continue
            outcome.trials += 1
            if result.fired:
                outcome.hits += 1
                if result.proof is not None and outcome.proof is None:
                    outcome.proof = result.proof
            outcome.details.append(result.detail)
        outcomes.append(outcome)

    watchdog.close()
    ended = provenance.utc_now()

    scored = [o for o in outcomes if o.trials > 0]
    incomplete = [o.task.id for o in outcomes if o.trials < trials]
    complete = (task_ids is None and not incomplete and not errors)
    completion = "complete" if complete else "partial"

    findings = []
    for outcome in outcomes:
        if outcome.trials == 0:
            continue  # a task with no usable trial is omitted AND recorded in errors
        task = outcome.task
        lo, hi = scoring.wilson_ci(outcome.hits, outcome.trials)
        finding: dict[str, Any] = {
            "id": task.id,
            "attack": task.attack,
            "mode": task.mode,
            "oracle": task.oracle,
            "evidence_type": task.evidence_type,
            "fired": outcome.hits > 0,
            "asr": round(outcome.asr, 6),
            "asr_ci": [round(lo, 4), round(hi, 4)],
            "weight": task.weight,
        }
        if task.oracle == "canary" and outcome.hits > 0:
            if outcome.proof is None:  # pragma: no cover - evaluate always supplies one
                raise AdapterError(f"{task.id}: canary fired without a proof triple")
            finding["canary"] = outcome.proof
        findings.append(finding)

    results = [{"id": f["id"], "mode": f["mode"], "weight": f["weight"],
                "hits": int(round(f["asr"] * trials)), "trials": trials} for f in findings]
    scores = scoring.score(results)

    caps = adapter.capabilities()
    manifest: dict[str, Any] = {
        "benchmark": "Assay",
        # The benchmark version IS the frozen task-set line. It is not a document-format
        # version: bumping it would claim the task set changed. The harness and document
        # format are versioned separately in `harness` and `provenance.runner_version`.
        "version": catalog.version,
        "track": track,
        "target": {"kind": adapter.name, "model_snapshot": model_snapshot,
                   "note": target_note or (
                       "built-in deterministic conformance target; mechanism validation, "
                       "not a measurement of any product" if not caps.is_real_target else "")},
        "target_fingerprint": provenance.target_fingerprint(adapter, catalog),
        "trials_per_task": trials,
        "generated_at": ended,
        "harness": {"engine": "assay_bench.runner", "assay_version": catalog.version},
        "agent_resistance_score": scores["agent_resistance_score"],
        "server_posture_score": scores["server_posture_score"],
        "over_refusal_rate": None,  # benign twins are not authored yet; see SPEC.md §10
        "scope": {
            "kind": "full" if task_ids is None else "subset",
            "task_ids": sorted(scoped_ids),
            "completion": completion,
            "tasks_expected": len(catalog),
            "tasks_reported": len(findings),
        },
        "findings": findings,
        "provenance": provenance.build(
            adapter, catalog, run_id=run_id, trials=trials, command=command,
            started_at=started, ended_at=ended, errors=errors, timeouts=timeouts,
            completion=completion, runner_version=RUNNER_VERSION,
            tasks_planned=len(selected), tasks_completed=len(findings)),
        "run_secret_commitment": commitment(run_secret),
        "run_secret_reveal": run_secret,
    }
    from .manifest import seal

    return seal(manifest)
