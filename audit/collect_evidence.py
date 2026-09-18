"""Regenerate the machine-readable audit summaries.

Run from the repository root:

    python audit/collect_evidence.py

Writes ``audit/TEST_SUMMARY.json`` and ``audit/RUN_SUMMARY.json``. Everything in them is measured
by running the thing, never transcribed by hand -- which is the point of having them.

These two files are **not** part of the `git diff --exit-code` gate, for one honest reason:
``RUN_SUMMARY.json`` records the commit it was generated from, which cannot equal the committed
value until the next commit lands. CI runs this script and requires it to exit 0 (i.e. the suite
passes and every manifest verifies); refreshing the files is a release step.

Everything else generated in this repository -- COVERAGE.md, the leaderboard page, the reference
manifests, the conformance matrix, the packaged catalog -- IS byte-stable and IS gated.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True,
                           timeout=30)
        return r.stdout.strip() if r.returncode == 0 else None
    except OSError:  # pragma: no cover
        return None


def collect_tests() -> dict:
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))

    per_module: dict[str, int] = {}

    def walk(s):
        for item in s:
            if isinstance(item, unittest.TestSuite):
                walk(item)
            else:
                module = type(item).__module__
                per_module[module] = per_module.get(module, 0) + 1

    walk(suite)

    runner = unittest.TextTestRunner(stream=open("/dev/null", "w"), verbosity=0)
    result = runner.run(suite)

    # Deliberately no duration: it is timing noise, and a file regenerated in CI must be
    # byte-stable or the `git diff --exit-code` gate becomes a coin toss.
    return {
        "runner": "unittest (standard library); pytest also collects this suite",
        "command": "python -m unittest discover -s tests -t .",
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "passed": result.wasSuccessful(),
        "tests_per_module": dict(sorted(per_module.items())),
        "third_party_dependencies": [],
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
    }


def collect_runs() -> dict:
    from assay_bench import attest
    from assay_bench.catalog import load_catalog

    import assay_verifier as V

    catalog = load_catalog()
    runs = []
    for path in sorted((ROOT / "leaderboard" / "manifests").glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        result = V.verify_manifest(manifest, catalog=catalog._raw)
        provenance = manifest.get("provenance") or {}
        runs.append({
            "artifact": str(path.relative_to(ROOT)),
            "sha256": _sha(path),
            "target": manifest["target"]["kind"],
            "target_is_real": provenance.get("target_is_real"),
            "deterministic_target": provenance.get("deterministic_target"),
            "adapter": (provenance.get("adapter") or {}).get("name"),
            "transport": provenance.get("transport"),
            "benchmark_version": manifest["version"],
            "manifest_format": provenance.get("manifest_format"),
            "runner_version": provenance.get("runner_version"),
            "task_set_digest": provenance.get("task_set_digest"),
            "target_fingerprint": manifest["target_fingerprint"],
            "trials_per_task": manifest["trials_per_task"],
            "tasks_reported": len(manifest["findings"]),
            "completion": (manifest.get("scope") or {}).get("completion"),
            "errors": len(provenance.get("errors") or []),
            "timeouts": provenance.get("timeouts"),
            "agent_resistance_score": manifest["agent_resistance_score"],
            "server_posture_score": manifest["server_posture_score"],
            "over_refusal_rate": manifest["over_refusal_rate"],
            "canary_findings": result["canary_findings"],
            "canary_confirmed": result["canary_confirmed"],
            "levels_verified": result["levels_verified"],
            "invariants_digest": attest.invariants_digest(manifest),
        })

    legacy = []
    for path in sorted((ROOT / "tests" / "fixtures" / "legacy_v0_1").glob("reference_*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        result = V.verify_manifest(manifest, catalog=catalog._raw)
        legacy.append({
            "artifact": str(path.relative_to(ROOT)),
            "sha256": _sha(path),
            "benchmark_version": manifest["version"],
            "levels_verified": result["levels_verified"],
            "note": "v0.1 artifact retained as a backwards-compatibility fixture",
        })

    other = {}
    for rel in ("reference/conformance_matrix.json", "tasks.json", "COVERAGE.md",
                "leaderboard/index.md", "demo/recording/assay-demo.webm",
                "demo/recording/validation.json"):
        path = ROOT / rel
        if path.is_file():
            other[rel] = _sha(path)

    return {
        "benchmark_version": catalog.version,
        "task_set": {
            "tasks": len(catalog),
            "digest": catalog.digest,
            "split": catalog.split,
            "mode_b": len(catalog.for_mode("B")),
            "mode_a": len(catalog.for_mode("A")),
            "oracles": {o: sum(1 for t in catalog if t.oracle == o)
                        for o in ("canary", "protocol", "behavioral")},
        },
        # The commit these artifacts were generated FROM. It necessarily differs from the
        # committed value until the next commit lands, so this file is regenerated as part of a
        # release rather than gated by `git diff --exit-code` on every push.
        "code_commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "generated_runs": runs,
        "legacy_fixtures": legacy,
        "artifact_hashes": other,
        "caveat": ("Every generated run above used a built-in DETERMINISTIC conformance target. "
                   "target_is_real is false for all of them. None is a measurement of any real "
                   "MCP server, agent or model."),
    }


def main() -> int:
    tests = collect_tests()
    (Path(__file__).parent / "TEST_SUMMARY.json").write_text(
        json.dumps(tests, indent=2) + "\n", encoding="utf-8")
    runs = collect_runs()
    (Path(__file__).parent / "RUN_SUMMARY.json").write_text(
        json.dumps(runs, indent=2) + "\n", encoding="utf-8")
    print(f"tests: {tests['tests_run']} run, {tests['failures']} failures, "
          f"{tests['errors']} errors, {tests['skipped']} skipped, passed={tests['passed']}")
    print(f"runs:  {len(runs['generated_runs'])} generated manifests, "
          f"{len(runs['legacy_fixtures'])} legacy fixtures")
    return 0 if tests["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
