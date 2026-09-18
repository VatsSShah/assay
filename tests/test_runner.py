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
        source = (Path(__file__).resolve().parent.parent / "src" / "assay_bench" / "runner.py").read_text()
        for literal in ("0.7", "0.4", "1.0,", "critical", "high\"", "medium\""):
            self.assertNotIn(f"weight = {literal}", source)
        self.assertIn("task.weight", source)


class ErrorsTimeoutsAndIsolation(unittest.TestCase):
    def test_adapter_failure_is_recorded_not_scored_as_resistance(self):
        m = run(FlakyTarget("M4"), catalog=CATALOG, trials=3, command="test")
        self.assertEqual(m["scope"]["completion"], "partial")
        # The failing task is REPORTED, as inconclusive. v0.1 dropped it, which is what let a
        # short report look like a clean one.
        self.assertIn("M4", {f["id"] for f in m["findings"]})
        self.assertEqual(m["validity"]["per_task_outcomes"]["M4"], {"errored": 3})
        self.assertIn("M4", m["validity"]["assessment"]["inconclusive_tasks"])
        self.assertEqual(len(m["provenance"]["errors"]), 3)
        self.assertTrue(all(e["task"] == "M4" for e in m["provenance"]["errors"]))

    def test_an_inconclusive_task_cannot_improve_the_lower_bound(self):
        clean = run(build("hardened"), catalog=CATALOG, trials=3, command="test")
        broken = run(FlakyTarget("M4"), catalog=CATALOG, trials=3, command="test")
        self.assertEqual(clean["validity"]["agent_resistance_lower_bound"], 100.0)
        self.assertLess(broken["validity"]["agent_resistance_lower_bound"], 100.0)

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
        # One trial plus the bounded retries, each of which also times out.
        self.assertGreaterEqual(m["provenance"]["timeouts"], 1)
        self.assertEqual([f["id"] for f in m["findings"]], ["M1"])
        self.assertEqual(m["validity"]["per_task_outcomes"]["M1"], {"timed_out": 1})
        self.assertEqual(m["findings"][0]["asr"], 0.0)
        self.assertFalse(m["findings"][0]["fired"])
        self.assertEqual(m["scope"]["completion"], "partial")
        self.assertIn("timeouts", m["validity"]["assessment"]["reasons"])

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


class RawTrialRecords(unittest.TestCase):
    """The per-trial log: evidence below the level of the manifest's own summary."""

    def _run_with_log(self, target="mixed", trials=3):
        import json
        import tempfile
        from pathlib import Path

        out = Path(tempfile.mkdtemp(prefix="assay-trials-")) / "trials.json"
        manifest = run(build(target), catalog=CATALOG, trials=trials, command="test",
                       trials_out=str(out))
        return manifest, json.loads(out.read_text())

    def test_the_log_is_written_and_binds_its_manifest(self):
        manifest, log = self._run_with_log()
        self.assertEqual(log["schema"], "assay/raw-trials/1")
        self.assertEqual(log["manifest_integrity_hash"], manifest["integrity_hash"])
        self.assertEqual(log["task_set_digest"], CATALOG.digest)

    def test_every_task_and_every_trial_is_recorded(self):
        manifest, log = self._run_with_log(trials=4)
        self.assertEqual(sorted(log["tasks"]), sorted(t.id for t in CATALOG))
        for task_id, records in log["tasks"].items():
            with self.subTest(task=task_id):
                self.assertEqual(len(records), 4)
                self.assertEqual([r["trial"] for r in records], [0, 1, 2, 3])

    def test_a_canary_trial_records_its_digest_preimage_and_envelope(self):
        _, log = self._run_with_log()
        for task in CATALOG:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                record = log["tasks"][task.id][0]
                self.assertEqual(len(record["canary_digest"]), 16)
                self.assertTrue(record["preimage"].startswith(f"assay/{task.id}|"))
                self.assertIn("canary_envelope", record)

    def test_the_log_never_contains_the_run_secret(self):
        import json

        manifest, log = self._run_with_log()
        self.assertNotIn(manifest["run_secret_reveal"], json.dumps(log))

    def test_a_recorded_digest_re_derives_from_the_manifest_reveal(self):
        manifest, log = self._run_with_log()
        secret = manifest["run_secret_reveal"]
        for task in CATALOG:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                record = log["tasks"][task.id][0]
                origin, tool, step = record["preimage"].rsplit("|", 2)[0], None, None
                parts = record["preimage"].split("|")
                self.assertEqual(V.digest(secret, "|".join(parts)), record["canary_digest"])

    def test_states_in_the_log_agree_with_the_manifest_tally(self):
        manifest, log = self._run_with_log(trials=5)
        for task_id, tally in manifest["validity"]["per_task_outcomes"].items():
            with self.subTest(task=task_id):
                from collections import Counter
                self.assertEqual(dict(Counter(r["state"] for r in log["tasks"][task_id])), tally)

    def test_no_log_is_written_unless_asked(self):
        manifest = run(build("hardened"), catalog=CATALOG, trials=2, command="test")
        self.assertFalse([k for k in manifest if k.startswith("_")],
                         "run() must return a pure manifest, with no sidecar keys")
