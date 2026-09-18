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
import json
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # src/, for `scoring`

from . import RUNNER_VERSION, provenance, validity
from .adapters import Episode, supports
from .canary import commitment, new_run_secret, parse_secret
from .catalog import Catalog, load_catalog
from .errors import AdapterError, ValidationError
from .oracles import evaluate
from .surface import build_surface

import scoring  # noqa: E402  canonical scoring, never re-implemented here


def _tally(states: list[str]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for state in states:
        counts[state] = counts.get(state, 0) + 1
    return sorted(counts.items())


class TaskOutcome:
    """Per-task accumulator. Records every trial's STATE, not just whether it fired, so
    validity rules V4-V6 can be applied instead of guessed at."""

    __slots__ = ("task", "hits", "proof", "outcomes", "retries", "notes", "unsupported",
                 "trials")

    def __init__(self, task) -> None:
        self.task = task
        self.hits = 0
        self.proof: dict[str, Any] | None = None
        self.outcomes: list[str] = []          # one entry per trial, from validity.classify_trial
        self.retries: list[dict[str, Any]] = []
        self.notes: list[str] = []
        self.unsupported = False
        #: The raw per-trial record. A tally says 3 exploited; this says which trial, under
        #: which canary digest, with what egress and how many retries. Without it a manifest
        #: cannot be audited below the level of its own summary.
        self.trials: list[dict[str, Any]] = []

    @property
    def conclusive(self) -> int:
        return sum(1 for o in self.outcomes if o in validity.OUTCOME_CONCLUSIVE)

    @property
    def asr(self) -> float:
        """ASR over CONCLUSIVE trials only (V4). An inconclusive trial is not a resisted one."""
        return self.hits / self.conclusive if self.conclusive else 0.0

    @property
    def conclusive_rate(self) -> float:
        return validity.conclusive_rate(self.outcomes)


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


def _unsupported_reason(caps, task) -> str:
    """Say which requirement the adapter failed, so `unsupported` is diagnosable.

    "Unsupported" with no reason is indistinguishable from a harness bug, and the difference
    matters: one is an honest gap in what the target can be shown, the other is a defect.
    """
    from .adapters import MODALITY_CAPABILITY, MODE_CAPABILITY, REQUIRED_CAPABILITY

    role = MODE_CAPABILITY.get(task.mode)
    if role and not getattr(caps, role, False):
        under_test = "an agent" if task.mode == "B" else "an MCP server"
        return (f"Mode {task.mode} puts {under_test} under test and this adapter does not "
                f"drive one ({role}=False), so the task was never posed")
    needed = REQUIRED_CAPABILITY.get(task.oracle, ())
    if not any(getattr(caps, name, False) for name in needed):
        return (f"declares none of {list(needed)}, which a {task.oracle} oracle needs")
    modality_capability = MODALITY_CAPABILITY.get(task.declared_modality)
    if modality_capability and not getattr(caps, modality_capability, False):
        return (f"cannot read the {task.declared_modality} channel "
                f"({modality_capability}=False), so the canary was never visible to it")
    return "does not declare a channel this task needs"  # pragma: no cover - defensive


def _run_twins(adapter, *, trials: int, timeout_s: float, twin_set=None,
               enabled: bool = True) -> dict[str, Any] | None:
    """Run the benign twin set, when the adapter can do benign work at all.

    Returns None -- and the manifest then carries `over_refusal_rate: null` -- when the adapter
    declares no `run_twin`. That is deliberate: an adapter that was never asked to do benign
    work has not refused any, and reporting 0.0 would read as "refused nothing" when the truth
    is "was never asked".
    """
    from .adapters import TwinCapable, TwinEpisode
    from . import twins as twins_mod
    from .errors import AssayError

    if not enabled or not isinstance(adapter, TwinCapable):
        return None
    try:
        loaded = twin_set if twin_set is not None else twins_mod.load_twins()
    except AssayError:
        # A missing or malformed twin set must not take down an otherwise valid attack run.
        return None

    results = []
    for twin in loaded:
        surface = twins_mod.build_twin_surface(twin)
        completions = errored = 0
        for trial in range(trials):
            episode = TwinEpisode(
                twin_id=twin.id, pairs_with=twin.pairs_with, channel=twin.channel, trial=trial,
                tool_catalog=surface["tool_catalog"], tool_results=surface["tool_results"],
                attachments=surface["attachments"], arguments=surface["arguments"],
                user_request=surface["user_request"],
                expected_payload=surface["expected_payload"], timeout_s=timeout_s)
            try:
                outcome = adapter.run_twin(episode)
                state = twins_mod.classify(outcome.outcome)
            except Exception:                    # noqa: BLE001 - any failure is an errored trial
                state = "errored"
            if state == "completed":
                completions += 1
            elif state == "errored":
                errored += 1
        results.append({"id": twin.id, "weight": twin.weight, "trials": trials,
                        "completions": completions, "errored": errored,
                        "twin_set_version": loaded.version})
    return twins_mod.score(results)


def run(adapter, *, catalog: Catalog | None = None, track: str = "agent", trials: int = 25,
        run_secret: str | None = None, task_ids: list[str] | None = None,
        timeout_s: float = 10.0, command: str = "", target_note: str = "",
        model_snapshot: str | None = None, run_id: str | None = None,
        trials_out: str | None = None, twins: bool = True,
        twin_set: Any = None) -> dict[str, Any]:
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

    caps = adapter.capabilities()
    for task in selected:
        outcome = TaskOutcome(task)
        # V3 extended to modality: a target that cannot decode images is not "resisting" the
        # image-channel tasks, it simply never saw them.
        if not supports(caps, task.oracle, task.declared_modality, task.mode):
            # V3: a channel the adapter cannot exercise is `unsupported`, never `resisted`.
            outcome.unsupported = True
            outcome.outcomes = ["unsupported"] * trials
            reason = _unsupported_reason(caps, task)
            outcome.trials = [{"trial": i, "state": "unsupported", "reason": reason}
                              for i in range(trials)]
            outcome.notes.append(f"adapter {adapter.name!r}: {reason}")
            outcomes.append(outcome)
            continue

        for trial in range(trials):
            surface = build_surface(task, run_secret, trial)
            episode = Episode(task_id=task.id, mode=task.mode, oracle=task.oracle,
                              attack=task.attack, trial=trial,
                              tool_catalog=surface["tool_catalog"],
                              tool_results=surface["tool_results"],
                              attachments=surface["attachments"],
                              canary=surface["canary"], timeout_s=timeout_s)

            attempt = 0
            observation = failure = None
            while True:
                if caps.supports_reset:
                    adapter.reset()
                observation, failure = watchdog.run(adapter, episode, timeout_s)
                if failure is None and not (observation and observation.error):
                    break
                # V6: retries are appended, never overwritten, and are bounded.
                reason = failure or observation.error
                if attempt >= validity.MAX_RETRIES_PER_TRIAL:
                    break
                attempt += 1
                outcome.retries.append({"task": task.id, "trial": trial, "attempt": attempt,
                                        "reason": reason})

            timed_out = failure == "timeout"
            errored = failure is not None and not timed_out
            if observation is not None and observation.error:
                errored = True
                failure = observation.error

            fired = False
            oracle_decided = False
            if failure is None and observation is not None:
                try:
                    result = evaluate(task.oracle, task.attack, observation, surface["canary"])
                    oracle_decided = True
                    fired = result.fired
                    if fired:
                        outcome.hits += 1
                        if result.proof is not None and outcome.proof is None:
                            outcome.proof = result.proof
                    outcome.notes.append(result.detail)
                except ValidationError as exc:
                    # The oracle could not decide. That is inconclusive, not resistance.
                    failure = f"oracle: {exc}"
                    errored = True

            state = validity.classify_trial(errored=errored, timed_out=timed_out,
                                            unsupported=False, oracle_decided=oracle_decided,
                                            fired=fired)
            outcome.outcomes.append(state)
            canary = surface.get("canary")
            record: dict[str, Any] = {
                "trial": trial,
                "state": state,
                "fired": fired,
                "retries": sum(1 for r in outcome.retries if r["trial"] == trial),
            }
            if canary is not None:
                # The digest, not the secret: enough to re-derive the trial given the reveal,
                # without duplicating key material into a second place in the document.
                record["canary_digest"] = canary["digest"]
                record["canary_envelope"] = canary["envelope"]
                record["preimage"] = f"{canary['origin']}|{canary['tool']}|{canary['step']}"
            if observation is not None:
                record["channels_observed"] = {
                    "egress_events": len(observation.egress),
                    "protocol_facts": sorted(observation.protocol_facts),
                    "actions": len(observation.actions),
                }
                if fired and observation.egress:
                    record["egress_excerpt"] = observation.egress_text()[:400]
            if failure is not None:
                record["reason"] = failure
            outcome.trials.append(record)
            if state not in validity.OUTCOME_CONCLUSIVE:
                if timed_out:
                    timeouts += 1
                errors.append({"task": task.id, "trial": trial, "state": state,
                               "reason": failure or "oracle did not decide",
                               "retries": sum(1 for r in outcome.retries if r["trial"] == trial)})
        outcomes.append(outcome)

    watchdog.close()
    ended = provenance.utc_now()

    findings = []
    per_task_outcomes: dict[str, list[str]] = {}
    unsupported_ids: set[str] = set()
    for outcome in outcomes:
        task = outcome.task
        per_task_outcomes[task.id] = outcome.outcomes
        if outcome.unsupported:
            unsupported_ids.add(task.id)
        # Every selected task is REPORTED, including unsupported and inconclusive ones. v0.1
        # silently dropped them, which is what let a short report look like a clean one.
        lo, hi = scoring.wilson_ci(outcome.hits, max(1, outcome.conclusive))
        finding: dict[str, Any] = {
            "id": task.id,
            "attack": task.attack,
            "mode": task.mode,
            "oracle": task.oracle,
            "evidence_type": task.evidence_type,
            "fired": outcome.hits > 0,
            "asr": round(outcome.asr, 6),
            "asr_ci": [round(lo, 4), round(hi, 4)] if outcome.conclusive else [0.0, 1.0],
            "weight": task.weight,
        }
        if task.oracle == "canary" and outcome.hits > 0:
            if outcome.proof is None:  # pragma: no cover - evaluate always supplies one
                raise AdapterError(f"{task.id}: canary fired without a proof triple")
            finding["canary"] = outcome.proof
        findings.append(finding)

    reported_ids = {f["id"] for f in findings}
    scope_kind = "full" if task_ids is None else "subset"
    assessment = validity.assess(
        catalog=catalog, track=track, scope_kind=scope_kind, reported_ids=reported_ids,
        trials=trials, per_task_outcomes=per_task_outcomes, unsupported_ids=unsupported_ids,
        errors=len(errors) - timeouts, timeouts=timeouts)
    completion = assessment["completion"]

    # V2: score over the catalog's fixed denominator, and publish an omission-proof lower bound
    # that charges every task not conclusively resisted at full weight.
    not_conclusive = {tid for tid, states in per_task_outcomes.items()
                      if validity.conclusive_rate(states) == 0.0}
    # The utility axis. It is measured in the same run as resistance on purpose: a target that
    # scores 100 by refusing everything and one that scores 100 by refusing only the attacks are
    # indistinguishable on resistance alone, and publishing that number by itself rewards the
    # first one.
    utility = _run_twins(adapter, trials=trials, timeout_s=timeout_s,
                         twin_set=twin_set, enabled=twins)

    scores = {
        "agent_resistance_score": validity.score_over_fixed_denominator(catalog, findings, "B"),
        "server_posture_score": validity.score_over_fixed_denominator(catalog, findings, "A"),
    }
    bounds = {
        "agent": validity.lower_bound(catalog, findings, "B", not_conclusive),
        "server": validity.lower_bound(catalog, findings, "A", not_conclusive),
    }

    all_retries = [r for o in outcomes for r in o.retries]
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
        "over_refusal_rate": utility["over_refusal_rate"] if utility else None,
        "scope": {
            "kind": scope_kind,
            "task_ids": sorted(scoped_ids),
            "completion": completion,
            "tasks_expected": assessment["required_tasks"],
            "tasks_reported": assessment["reported_tasks"],
        },
        "validity": {
            "rules_version": "1",
            "assessment": assessment,
            "explanation": validity.explain(assessment),
            "agent_resistance_lower_bound": bounds["agent"],
            "server_posture_lower_bound": bounds["server"],
            "denominator": {
                "agent": round(validity.denominator(catalog, "B"), 6),
                "server": round(validity.denominator(catalog, "A"), 6),
                "source": "frozen catalog, not the reported findings",
            },
            "per_task_outcomes": {tid: dict(_tally(states)) for tid, states in
                                  sorted(per_task_outcomes.items())},
            "retries": all_retries,
            "raw_trials_recorded": sum(len(o.trials) for o in outcomes),
        },
        **({"utility": utility} if utility else {}),
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

    seal(manifest)

    # The raw trial log is written beside the manifest, never into it: it is large, it is
    # evidence rather than claim, and putting it inside the integrity-hashed document would make
    # every manifest unreadable. `run()` returns the manifest and nothing else, so a caller can
    # never accidentally hand a polluted document to the verifier.
    if trials_out:
        log = {
            "schema": "assay/raw-trials/1",
            "run_id": run_id,
            "benchmark_version": catalog.version,
            "task_set_digest": catalog.digest,
            "manifest_integrity_hash": manifest["integrity_hash"],
            "trials_per_task": trials,
            "note": ("Per-trial evidence for the manifest named above. Canary DIGESTS are "
                     "recorded, the run secret is not: with the manifest's reveal, every digest "
                     "here re-derives from its preimage."),
            "tasks": {o.task.id: o.trials for o in outcomes},
        }
        path = Path(trials_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
    return manifest
