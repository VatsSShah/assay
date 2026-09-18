"""The ``assay`` / ``assay-bench`` command line.

Every documented command in this repository resolves here or to ``assay_verifier``.
Legacy invocations kept working on purpose: ``assay <manifest.json>`` and
``assay triple ...`` behave exactly as they did in v0.1.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import RUNNER_VERSION
from .errors import AssayError, EXIT_OK, EXIT_USAGE, UsageError

REPO = Path(__file__).resolve().parent.parent


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=False))


def _write(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


# ------------------------------------------------------------------------------ run

def cmd_run(args) -> int:
    from .adapters.conformance import build as build_builtin
    from .catalog import load_catalog
    from .runner import run

    catalog = load_catalog(args.tasks)
    adapter = build_builtin(args.target)
    command = "assay run " + " ".join(sys.argv[2:])
    manifest = run(adapter, catalog=catalog, track=args.track, trials=args.trials,
                   run_secret=args.run_secret, task_ids=args.task or None,
                   timeout_s=args.timeout, command=command, target_note=args.note or "",
                   run_id=args.run_id)
    if args.out:
        _write(Path(args.out), manifest)
        caps = adapter.capabilities()
        print(f"wrote {args.out}: {len(manifest['findings'])}/{len(catalog)} tasks, "
              f"agent={manifest['agent_resistance_score']} "
              f"server={manifest['server_posture_score']} "
              f"completion={manifest['scope']['completion']} "
              f"real_target={caps.is_real_target}")
    else:
        _print(manifest)
    return EXIT_OK


# ------------------------------------------------------------------------ reference

REFERENCE_TARGETS = {
    "vulnerable": "reference_vulnerable.json",
    "hardened": "reference_hardened.json",
    "mixed": "reference_mixed.json",
}

#: Fields that legitimately differ between two honest reference runs. A reference
#: regeneration is "reproducible" modulo exactly this list, and nothing else.
NONDETERMINISTIC_FIELDS = (
    "run_secret_reveal", "run_secret_commitment", "integrity_hash", "generated_at",
    "findings[].canary.observed", "provenance.run_id", "provenance.started_at",
    "provenance.ended_at", "provenance.code_commit", "provenance.environment",
    "provenance.command",
)

#: The published run secret used for the committed reference fixtures. Publishing it is
#: correct and deliberate: these are conformance fixtures, not results, so there is no
#: secret to protect and byte-level reproducibility is worth more than secrecy. A real
#: submission MUST mint a fresh secret (the runner does so unless --run-secret is given).
REFERENCE_RUN_SECRET = "a5" * 32
REFERENCE_FROZEN_TIME = "2026-09-18T00:00:00+00:00"


def _reference_run(target: str, trials: int, catalog, *, frozen: bool):
    from .adapters.conformance import build as build_builtin
    from .runner import run

    adapter = build_builtin(target)
    manifest = run(adapter, catalog=catalog, track="agent", trials=trials,
                   run_secret=REFERENCE_RUN_SECRET,
                   command=f"assay reference --target {target} --trials {trials}",
                   target_note=("built-in deterministic conformance target; this run "
                                "validates the harness mechanism and is NOT a measurement "
                                "of any product"))
    if frozen:
        from .manifest import seal

        manifest["generated_at"] = REFERENCE_FROZEN_TIME
        manifest["provenance"]["started_at"] = REFERENCE_FROZEN_TIME
        manifest["provenance"]["ended_at"] = REFERENCE_FROZEN_TIME
        manifest["provenance"]["run_id"] = "00000000-0000-0000-0000-00000000000" + str(
            sorted(REFERENCE_TARGETS).index(target))
        manifest["provenance"]["code_commit"] = None
        manifest["provenance"]["environment"] = {"note": "frozen for the committed fixture"}
        seal(manifest)
    return adapter, manifest


def _conformance_matrix(runs: dict[str, dict], catalog, trials: int) -> dict[str, Any]:
    from .adapters.conformance import MIXED_SUSCEPTIBLE

    vulnerable = {f["id"]: f for f in runs["vulnerable"]["findings"]}
    hardened = {f["id"]: f for f in runs["hardened"]["findings"]}
    mixed = {f["id"]: f for f in runs["mixed"]["findings"]}
    rows = []
    for task in catalog:
        v, h, m = vulnerable[task.id], hardened[task.id], mixed[task.id]
        rows.append({
            "task_id": task.id,
            "attack": task.attack,
            "oracle": task.oracle,
            "mode": task.mode,
            "weight": task.weight,
            "trials": trials,
            "vulnerable_fired": v["fired"],
            "vulnerable_asr": v["asr"],
            "hardened_fired": h["fired"],
            "hardened_asr": h["asr"],
            "mixed_fired": m["fired"],
            "mixed_expected_susceptible": task.id in MIXED_SUSCEPTIBLE,
            "recall_ok": v["fired"] is True,
            "specificity_ok": h["fired"] is False,
            "discrimination_ok": m["fired"] == (task.id in MIXED_SUSCEPTIBLE),
        })
    canary_rows = [r for r in rows if r["oracle"] == "canary"]
    return {
        "schema": "assay/conformance-matrix/1",
        "what_this_is": (
            "Mechanism conformance for the Assay harness against three built-in "
            "DETERMINISTIC in-process targets. Every cell is a property of the harness and "
            "its stub targets. This is not a measurement of any real MCP server, agent or "
            "model, and must not be cited as one."),
        "why_there_are_no_confidence_intervals": (
            "The targets are deterministic by construction, so each cell is exactly 0 or 1 "
            "and repeated trials are copies, not independent draws. A Wilson interval over "
            "such a cell describes the trial count, not uncertainty about a population. "
            "v0.1 published such intervals; they have been withdrawn as meaningless here."),
        "benchmark_version": catalog.version,
        "task_set_digest": catalog.digest,
        "runner_version": RUNNER_VERSION,
        "trials_per_cell": trials,
        "deterministic_targets": True,
        "n_tasks": len(catalog),
        "summary": {
            "recall_all_attacks_fire_on_vulnerable": all(r["recall_ok"] for r in rows),
            "specificity_nothing_fires_on_hardened": all(r["specificity_ok"] for r in rows),
            "discrimination_mixed_matches_published_subset": all(
                r["discrimination_ok"] for r in rows),
            "canary_tasks": len(canary_rows),
            "canary_false_positives_on_hardened": sum(
                1 for r in canary_rows if r["hardened_fired"]),
        },
        "rows": rows,
    }


def _invariants(manifest: dict) -> dict:
    from . import attest

    return attest.invariants(manifest)


def cmd_reference(args) -> int:
    from .catalog import load_catalog
    from assay_verifier import verify_manifest

    catalog = load_catalog(args.tasks)
    out_dir = Path(args.out_dir)
    runs: dict[str, dict] = {}
    for target in sorted(REFERENCE_TARGETS):
        _, manifest = _reference_run(target, args.trials, catalog, frozen=True)
        verify_manifest(manifest, catalog=catalog._raw,
                        require=("internally_consistent", "canary_correspondence_verified",
                                 "catalog_bound", "run_complete"))
        runs[target] = manifest

    matrix = _conformance_matrix(runs, catalog, args.trials)

    if args.check:
        problems = []
        for target, filename in REFERENCE_TARGETS.items():
            committed_path = out_dir / filename
            if not committed_path.is_file():
                problems.append(f"{committed_path}: missing")
                continue
            committed = json.loads(committed_path.read_text(encoding="utf-8"))
            if _invariants(committed) != _invariants(runs[target]):
                problems.append(f"{committed_path}: run invariants differ from a fresh run")
        matrix_path = Path(args.matrix)
        if matrix_path.is_file():
            old = json.loads(matrix_path.read_text(encoding="utf-8"))
            if old.get("rows") != matrix["rows"] or old.get("summary") != matrix["summary"]:
                problems.append(f"{matrix_path}: conformance rows differ from a fresh run")
        else:
            problems.append(f"{matrix_path}: missing")
        print(json.dumps({
            "check": "reference-regeneration",
            "compared": "run invariants (per-task fired/asr, scores, fingerprint, task-set digest)",
            "expected_to_differ": list(NONDETERMINISTIC_FIELDS),
            "problems": problems,
            "ok": not problems,
        }, indent=2))
        return EXIT_OK if not problems else 1

    for target, filename in REFERENCE_TARGETS.items():
        _write(out_dir / filename, runs[target])
    _write(Path(args.matrix), matrix)
    print(f"wrote {len(REFERENCE_TARGETS)} reference manifests to {out_dir} "
          f"and {args.matrix}")
    print(f"  recall={matrix['summary']['recall_all_attacks_fire_on_vulnerable']} "
          f"specificity={matrix['summary']['specificity_nothing_fires_on_hardened']} "
          f"discrimination={matrix['summary']['discrimination_mixed_matches_published_subset']}")
    return EXIT_OK


# ------------------------------------------------------------------------ precommit

def cmd_precommit(args) -> int:
    from .adapters.conformance import build as build_builtin
    from .catalog import load_catalog
    from .canary import new_run_secret
    from .precommit import REGISTRY_DIRNAME, create_record
    from .provenance import target_fingerprint

    catalog = load_catalog(args.tasks)
    adapter = build_builtin(args.target)
    secret = args.run_secret or new_run_secret()
    record = create_record(run_secret=secret, benchmark_version=catalog.version,
                           task_set_digest=catalog.digest,
                           target_fingerprint=target_fingerprint(adapter, catalog),
                           trials=args.trials, note=args.note or "")
    registry = Path(args.registry or (REPO / REGISTRY_DIRNAME))
    _write(registry / f"{record['run_id']}.json", record)
    if args.secret_out:
        Path(args.secret_out).write_text(secret + "\n", encoding="utf-8")
        print(f"run secret written to {args.secret_out} -- keep it private until the reveal")
    else:
        print(f"run secret (keep private until reveal): {secret}")
    print(f"registry record: {registry / (record['run_id'] + '.json')}")
    print("Commit and push this record BEFORE running. Its ordering evidence is the commit "
          "that introduces it, not the timestamp inside it.")
    return EXIT_OK


def cmd_precommit_verify(args) -> int:
    from .precommit import verify

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    witness = json.loads(Path(args.witness).read_text(encoding="utf-8")) if args.witness else None
    result = verify(manifest, repo=Path(args.repo), manifest_path=args.manifest,
                    registry_dir=Path(args.registry) if args.registry else None,
                    external_witness=witness)
    _print(result)
    if args.require and args.require not in result["levels_verified"]:
        reason = result["levels_not_established"].get(args.require, "not established")
        print(f"assay: required level {args.require!r} not reached: {reason}", file=sys.stderr)
        return 1
    return EXIT_OK


def cmd_precommit_list(args) -> int:
    from .precommit import REGISTRY_DIRNAME, load_registry

    registry = Path(args.registry or (REPO / REGISTRY_DIRNAME))
    records = load_registry(registry)
    rows = [{"run_id": r["run_id"], "target_fingerprint": r["target_fingerprint"],
             "trials": r["trial_plan"]["trials_per_task"],
             "bound_manifest": r.get("bound_manifest_integrity_hash"),
             "state": "revealed" if r.get("bound_manifest_integrity_hash") else "UNREVEALED"}
            for r in records.values()]
    _print({"registry": str(registry), "records": rows,
            "unrevealed": sum(1 for r in rows if r["state"] == "UNREVEALED"),
            "note": ("Unrevealed records are the anti-grinding signal: a submitter who "
                     "registers many commitments and publishes one leaves the rest visible "
                     "here. This is a deterrent, not a proof that every run was published.")})
    return EXIT_OK


# -------------------------------------------------------------------------- attest

def cmd_attest(args) -> int:
    from . import attest
    from .provenance import code_commit

    submitted = json.loads(Path(args.submitted).read_text(encoding="utf-8"))
    rerun = json.loads(Path(args.rerun).read_text(encoding="utf-8")) if args.rerun else None
    record = attest.build(submitted=submitted, rerun=rerun, maintainer=args.maintainer,
                          code_commit=code_commit(), note=args.note or "",
                          failure=args.failure or "")
    if args.out:
        _write(Path(args.out), record)
        print(f"wrote {args.out}: status={record['status']}")
    else:
        _print(record)
    return EXIT_OK if record["status"] == attest.STATUS_MATCH else 1


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assay",
                                description="Assay: run the MCP security benchmark and verify scorecards.")
    p.add_argument("--version", action="version", version=f"assay-bench {RUNNER_VERSION}")
    sub = p.add_subparsers(dest="command")

    r = sub.add_parser("run", help="run the frozen task set against a target")
    r.add_argument("--target", default="vulnerable",
                   help="built-in conformance target: vulnerable, hardened, mixed")
    r.add_argument("--track", default="agent", choices=["agent", "server"])
    r.add_argument("--trials", type=int, default=25)
    r.add_argument("--timeout", type=float, default=10.0)
    r.add_argument("--task", action="append", help="run only this task id (repeatable); "
                                                   "marks the run partial")
    r.add_argument("--run-secret", help="use this secret instead of minting one (for a "
                                        "precommitted run)")
    r.add_argument("--run-id", help="reuse the run id from a precommitment record; required "
                                    "for the commitment to bind this run")
    r.add_argument("--tasks", help="path to tasks.json")
    r.add_argument("--note", help="free-text target note recorded in the manifest")
    r.add_argument("--out", help="write the manifest here instead of stdout")
    r.set_defaults(func=cmd_run)

    ref = sub.add_parser("reference", help="regenerate the built-in conformance artifacts")
    ref.add_argument("--out-dir", default=str(REPO / "leaderboard" / "manifests"))
    ref.add_argument("--matrix", default=str(REPO / "reference" / "conformance_matrix.json"))
    ref.add_argument("--trials", type=int, default=25)
    ref.add_argument("--tasks", help="path to tasks.json")
    ref.add_argument("--check", action="store_true",
                     help="regenerate in memory and compare invariants against the "
                          "committed artifacts instead of overwriting them")
    ref.set_defaults(func=cmd_reference)

    pc = sub.add_parser("precommit", help="register a pre-run commitment")
    pc.add_argument("--target", default="vulnerable")
    pc.add_argument("--trials", type=int, default=25)
    pc.add_argument("--run-secret")
    pc.add_argument("--secret-out")
    pc.add_argument("--registry")
    pc.add_argument("--tasks")
    pc.add_argument("--note")
    pc.set_defaults(func=cmd_precommit)

    pv = sub.add_parser("precommit-verify", help="verify a manifest's precommitment ordering")
    pv.add_argument("--manifest", required=True)
    pv.add_argument("--repo", default=str(REPO))
    pv.add_argument("--registry")
    pv.add_argument("--witness", help="JSON forge witness naming the commitment commit")
    pv.add_argument("--require", choices=["local_commitment_consistency",
                                          "repository_ordering_verified",
                                          "precommitment_verified"])
    pv.set_defaults(func=cmd_precommit_verify)

    pl = sub.add_parser("precommit-list", help="list registry records and their state")
    pl.add_argument("--registry")
    pl.set_defaults(func=cmd_precommit_list)

    at = sub.add_parser("attest", help="record a maintainer rerun of a submitted manifest")
    at.add_argument("--submitted", required=True)
    at.add_argument("--rerun")
    at.add_argument("--maintainer", required=True)
    at.add_argument("--note")
    at.add_argument("--failure")
    at.add_argument("--out")
    at.set_defaults(func=cmd_attest)

    return p


VERIFIER_COMMANDS = {"verify", "triple", "levels"}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Delegate the verifier's own vocabulary, including the legacy bare-path form, so every
    # invocation documented for v0.1 keeps working byte for byte.
    if argv and (argv[0] in VERIFIER_COMMANDS or argv[0].endswith(".json")):
        from assay_verifier import _main as verifier_main, VerifierError

        try:
            return verifier_main(argv)
        except VerifierError as exc:
            print(f"assay: {exc}", file=sys.stderr)
            return exc.exit_code

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        print("\nVerification subcommands (handled by assay_verifier): "
              + ", ".join(sorted(VERIFIER_COMMANDS)))
        return EXIT_USAGE
    try:
        return args.func(args)
    except AssayError as exc:
        print(f"assay: {exc}", file=sys.stderr)
        return exc.exit_code
    except UsageError as exc:  # pragma: no cover - argparse handles most of these
        print(f"assay: {exc}", file=sys.stderr)
        return EXIT_USAGE


def cli() -> None:
    raise SystemExit(main())
