"""The trial loop against the built-in deterministic conformance targets."""

from __future__ import annotations

import unittest

from .helpers import V
from assay_bench.adapters import Capabilities, Episode, Observation
from assay_bench.adapters.conformance import (MIXED_SUSCEPTIBLE, FlakyTarget, build)
from assay_bench.catalog import load_catalog
from assay_bench.errors import AdapterError, ValidationError
from assay_bench.manifest import validate_structure
from assay_bench.runner import run

CATALOG = load_catalog()
TRIALS = 5


class ConformanceOutcomes(unittest.TestCase):
    def test_vulnerable_target_fires_every_one_of_the_31_tasks(self):
        m = run(build("vulnerable"), catalog=CATALOG, trials=TRIALS, command="test")
        self.assertEqual(len(m["findings"]), 31)
        self.assertTrue(all(f["fired"] for f in m["findings"]))
        self.assertEqual(m["agent_resistance_score"], 0.0)
        self.assertEqual(m["server_posture_score"], 0.0)

    def test_hardened_target_fires_nothing(self):
        m = run(build("hardened"), catalog=CATALOG, trials=TRIALS, command="test")
        self.assertEqual(len(m["findings"]), 31)
        self.assertFalse(any(f["fired"] for f in m["findings"]))
        self.assertEqual(m["agent_resistance_score"], 100.0)
        self.assertEqual(m["server_posture_score"], 100.0)

    def test_mixed_target_fires_exactly_the_published_subset(self):
        """Proves the evaluator decides per task. A harness that merely echoed a global
        'vulnerable' flag would score mixed identically to vulnerable or hardened."""
        m = run(build("mixed"), catalog=CATALOG, trials=TRIALS, command="test")
        fired = {f["id"] for f in m["findings"] if f["fired"]}
        self.assertEqual(fired, set(MIXED_SUSCEPTIBLE))
        self.assertNotIn(m["agent_resistance_score"], (0.0, 100.0))

    def test_every_oracle_class_is_actually_exercised(self):
        m = run(build("vulnerable"), catalog=CATALOG, trials=TRIALS, command="test")
        by_oracle = {}
        for f in m["findings"]:
            by_oracle.setdefault(f["oracle"], []).append(f)
        self.assertEqual(len(by_oracle["canary"]), 25)
        self.assertEqual(len(by_oracle["behavioral"]), 4)
        self.assertEqual(len(by_oracle["protocol"]), 2)

    def test_fired_canaries_carry_a_proof_that_recomputes(self):
        m = run(build("vulnerable"), catalog=CATALOG, trials=TRIALS, command="test")
        secret = m["run_secret_reveal"]
        proofs = [f for f in m["findings"] if f["oracle"] == "canary" and f["fired"]]
        self.assertEqual(len(proofs), 25)
        for f in proofs:
            c = f["canary"]
            self.assertTrue(V.verify_triple(secret, c["origin"], c["tool"], c["step"],
                                            c["observed"]), f"{f['id']} does not recompute")

    def test_non_canary_findings_never_carry_a_proof(self):
        m = run(build("vulnerable"), catalog=CATALOG, trials=TRIALS, command="test")
        for f in m["findings"]:
            if f["oracle"] != "canary":
                self.assertNotIn("canary", f)

    def test_generated_manifests_are_schema_valid_and_verify(self):
        for target in ("vulnerable", "hardened", "mixed"):
            with self.subTest(target=target):
                m = run(build(target), catalog=CATALOG, trials=TRIALS, command="test")
                validate_structure(m)
                out = V.verify_manifest(m, require=("run_complete",))
                self.assertIn("catalog_bound", out["levels_verified"])


class FrozenFieldsComeFromTheCatalog(unittest.TestCase):
    def test_findings_restate_the_catalog_never_redefine_it(self):
        m = run(build("mixed"), catalog=CATALOG, trials=TRIALS, command="test")
        for f in m["findings"]:
            task = CATALOG.require(f["id"])
            self.assertEqual((f["mode"], f["oracle"], f["evidence_type"], f["weight"]),
                             (task.mode, task.oracle, task.evidence_type, task.weight))

    def test_the_runner_has_no_second_copy_of_the_weights(self):
        """A grep-style guard: weights must not be literal anywhere in the runner."""
        from pathlib import Path
        source = (Path(__file__).resolve().parent.parent / "assay_bench" / "runner.py").read_text()
        for literal in ("0.7", "0.4", "1.0,", "critical", "high\"", "medium\""):
            self.assertNotIn(f"weight = {literal}", source)
        self.assertIn("task.weight", source)


class ErrorsTimeoutsAndIsolation(unittest.TestCase):
    def test_adapter_failure_is_recorded_not_scored_as_resistance(self):
        m = run(FlakyTarget("M4"), catalog=CATALOG, trials=3, command="test")
        self.assertEqual(m["scope"]["completion"], "partial")
        self.assertNotIn("M4", {f["id"] for f in m["findings"]})
        self.assertEqual(len(m["provenance"]["errors"]), 3)
        self.assertTrue(all(e["task"] == "M4" for e in m["provenance"]["errors"]))

    def test_a_partial_run_cannot_reach_run_complete(self):
        m = run(FlakyTarget("M4"), catalog=CATALOG, trials=3, command="test")
        out = V.verify_manifest(m)
        self.assertNotIn("run_complete", out["levels_verified"])
        with self.assertRaises(V.VerifierError):
            V.verify_manifest(m, require=("run_complete",))

    def test_timeouts_are_counted_and_do_not_look_like_resistance(self):
        class Sleeper:
            name, version, kind = "sleeper", "1.0", "test-stub"

            def capabilities(self):
                return Capabilities(supports_reset=True, emits_network_egress=True)

            def reset(self):
                pass

            def fingerprint_material(self):
                return {"kind": "sleeper"}

            def run_episode(self, episode):
                import time
                time.sleep(2.0)
                return Observation(task_id=episode.task_id, trial=episode.trial)

        m = run(Sleeper(), catalog=CATALOG, trials=1, task_ids=["M1"], timeout_s=0.05,
                command="test")
        self.assertEqual(m["provenance"]["timeouts"], 1)
        self.assertEqual(m["findings"], [])
        self.assertEqual(m["scope"]["completion"], "partial")

    def test_state_leaking_between_trials_is_an_error_not_a_silent_result(self):
        target = build("vulnerable")
        target._residue = {"stale": True}
        with self.assertRaisesRegex(AdapterError, "state leaked"):
            target.run_episode(Episode(task_id="M1", mode="B", oracle="canary",
                                       attack="a", trial=0))

    def test_reset_clears_residue_deterministically(self):
        target = build("vulnerable")
        target._residue = {"stale": True}
        target.reset()
        self.assertEqual(target._residue, {})

    def test_an_unwinnable_episode_is_an_error_not_a_pass(self):
        """If the canary never reached the adversarial surface the task could never fire;
        reporting that as 'resisted' would be a silent false negative."""
        target = build("vulnerable")
        with self.assertRaisesRegex(AdapterError, "never actually placed"):
            target.run_episode(Episode(
                task_id="M1", mode="B", oracle="canary", attack="a", trial=0,
                tool_catalog=[{"name": "a", "description": "clean"}], tool_results=[],
                canary={"value": "sk-missing", "tool": "a", "step": 0, "digest": "0" * 16}))


class RunnerInputValidation(unittest.TestCase):
    def test_bad_track_trials_and_task_ids_are_rejected(self):
        for kwargs, pattern in (
            ({"track": "both"}, "track must be"),
            ({"trials": 0}, "positive integer"),
            ({"trials": True}, "positive integer"),
            ({"task_ids": ["NOPE"]}, "unknown task id"),
        ):
            with self.subTest(**kwargs):
                call = {"trials": 1, "command": "t"}
                call.update(kwargs)
                with self.assertRaisesRegex(ValidationError, pattern):
                    run(build("hardened"), catalog=CATALOG, **call)

    def test_a_malformed_supplied_run_secret_fails_fast(self):
        with self.assertRaises(ValidationError):
            run(build("hardened"), catalog=CATALOG, trials=1, run_secret="nothex", command="t")

    def test_a_task_subset_is_marked_partial(self):
        m = run(build("vulnerable"), catalog=CATALOG, trials=2, task_ids=["M1", "M2"],
                command="t")
        self.assertEqual(m["scope"]["kind"], "subset")
        self.assertEqual(m["scope"]["completion"], "partial")
        self.assertEqual(len(m["findings"]), 2)


class Determinism(unittest.TestCase):
    def test_the_same_secret_reproduces_the_same_evidence(self):
        a = run(build("vulnerable"), catalog=CATALOG, trials=3, run_secret="7a" * 32,
                command="t")
        b = run(build("vulnerable"), catalog=CATALOG, trials=3, run_secret="7a" * 32,
                command="t")
        self.assertEqual([f["canary"] for f in a["findings"] if "canary" in f],
                         [f["canary"] for f in b["findings"] if "canary" in f])

    def test_a_fresh_secret_changes_every_digest(self):
        a = run(build("vulnerable"), catalog=CATALOG, trials=1, command="t")
        b = run(build("vulnerable"), catalog=CATALOG, trials=1, command="t")
        self.assertNotEqual(a["run_secret_reveal"], b["run_secret_reveal"])
        self.assertNotEqual([f.get("canary") for f in a["findings"]],
                            [f.get("canary") for f in b["findings"]])


if __name__ == "__main__":
    unittest.main()
