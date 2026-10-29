"""Experiment configs and the ``assay/experiment-manifest/1`` document, end to end.

The synthetic example config is run once into a temp directory (scripted mock model, loopback
MCP only, no network) and the resulting bundle is verified with ``bundle.verify_bundle``. The
manifest tests then break one thing at a time and assert on the specific problem.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tests import helpers

from assay_bench import experiment
from assay_bench.errors import UsageError, ValidationError

ROOT = helpers.ROOT
SYNTHETIC = ROOT / "experiments" / "examples" / "synthetic-local" / "experiment.json"
LIVE = ROOT / "experiments" / "examples" / "live-openrouter" / "experiment.json"
HAVE_PIPELINE = all(importlib.util.find_spec(f"assay_bench.{m}") is not None
                    for m in ("trace", "redaction", "bundle"))


@unittest.skipUnless(HAVE_PIPELINE, "trace/redaction/bundle modules unavailable")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="assay-exp-")
        cls.bundle = experiment.run_experiment(experiment.load_config(SYNTHETIC), cls.tmp)
        cls.manifest = json.loads((cls.bundle / "experiment.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_the_bundle_verifies(self):
        from assay_bench import bundle
        result = bundle.verify_bundle(self.bundle)
        self.assertTrue(result["ok"], [c for c in result["checks"] if not c["ok"]])

    def test_layout(self):
        for rel in ("experiment.json", "config.json", "redaction_report.json",
                    "artifact_index.json"):
            self.assertTrue((self.bundle / rel).is_file(), rel)
        for conf in ("baseline", "confirmation_gated", "egress_restricted", "tool_restricted",
                     "policy_validated"):
            for rel in ("scorecard.json", "trials.json", "traces.jsonl"):
                self.assertTrue((self.bundle / "configurations" / conf / rel).is_file())

    def test_valid_manifest_and_honest_labels(self):
        self.assertEqual(experiment.validate_experiment_manifest(self.manifest), [])
        self.assertTrue(self.manifest["experiment"]["synthetic"])
        self.assertFalse(self.manifest["model"]["live"])
        self.assertFalse(self.manifest["model"]["identity_verified"])
        gaps = {g["field"] for g in self.manifest["metadata_gaps"]}
        self.assertIn("model.model_revision", gaps)
        self.assertIn("model.seed", gaps)
        self.assertIsNone(self.manifest["model"]["seed"])

    def test_controls_separate_attempt_from_execution(self):
        runs = {r["configuration"]: r for r in self.manifest["runs"]}
        self.assertEqual(runs["baseline"]["executed"], runs["baseline"]["model_attempted"])
        for name in ("confirmation_gated", "policy_validated", "egress_restricted"):
            self.assertEqual(runs[name]["model_attempted"], runs["baseline"]["model_attempted"])
            self.assertLess(runs[name]["executed"], runs["baseline"]["executed"], name)
            self.assertGreater(runs[name]["outcome_detail_counts"]["blocked_by_control"], 0)
        self.assertEqual(runs["tool_restricted"]["model_attempted"], 0)

    def test_missing_required_field(self):
        doc = copy.deepcopy(self.manifest)
        del doc["model"]["api_model_id"]
        self.assertTrue(any("api_model_id" in p
                            for p in experiment.validate_experiment_manifest(doc)))

    def test_unsupported_schema_version(self):
        doc = copy.deepcopy(self.manifest)
        doc["schema"] = "assay/experiment-manifest/2"
        problems = experiment.validate_experiment_manifest(doc)
        self.assertTrue(problems and "unsupported schema" in problems[0])

    def test_inconsistent_trial_count(self):
        doc = copy.deepcopy(self.manifest)
        doc["runs"][0]["attack_succeeded"] += 1
        self.assertTrue(any("trials_executed" in p
                            for p in experiment.validate_experiment_manifest(doc)))

    def test_null_without_a_gap_is_rejected(self):
        doc = copy.deepcopy(self.manifest)
        doc["metadata_gaps"] = [g for g in doc["metadata_gaps"]
                                if g["field"] != "model.model_revision"]
        self.assertTrue(any("model.model_revision is null" in p
                            for p in experiment.validate_experiment_manifest(doc)))

    def test_inconsistent_experiment_id(self):
        from assay_bench import bundle
        copy_dir = Path(self.tmp) / "id-tamper"
        shutil.copytree(self.bundle, copy_dir)
        path = copy_dir / "experiment.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        original = doc["experiment"]["experiment_id"]
        doc["experiment"]["experiment_id"] = original[:-8] + "deadbeef"
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        bundle.build_index(copy_dir, experiment_id=original)   # index keeps the real id
        result = bundle.verify_bundle(copy_dir)
        self.assertIn("experiment_id_consistent", result["failed"])

    def test_wrong_repository_commit(self):
        from assay_bench import bundle
        result = bundle.verify_bundle(self.bundle, expect_commit="0123456789abcdef")
        self.assertIn("repository_commit", result["failed"])


@unittest.skipUnless(HAVE_PIPELINE and importlib.util.find_spec("assay_bench.witness_receipt"),
                     "witness_receipt module unavailable")
class WitnessedRun(unittest.TestCase):
    """A loopback witness sink receives the relayed sink-call bytes and returns receipts.

    The operator registered the canaries itself (same host), so the manifest must NOT claim the
    run was independently witnessed, whatever the receipts say about themselves.
    """

    def test_relayed_egress_is_receipted_and_verifies(self):
        from assay_bench import bundle
        from assay_bench.witness_receipt import WitnessSink, trusted_keys_document
        with tempfile.TemporaryDirectory() as d:
            sink = WitnessSink(bytes(range(1, 33)), witness_name="local-sink",
                               state_dir=Path(d) / "sink").start()
            try:
                keys = Path(d) / "trusted.json"
                keys.write_text(json.dumps(trusted_keys_document(
                    [{"name": "local-sink", "public_key": sink.public_key,
                      "independent": False}])), encoding="utf-8")
                cfg = experiment.load_config(SYNTHETIC)
                cfg["trials"] = 2
                cfg["attack"]["task_ids"] = ["M1"]
                cfg["configurations"] = [{"name": "baseline"}]
                cfg["witness"] = {"url": sink.url, "register_canaries": True,
                                  "trusted_keys": str(keys)}
                path = experiment.run_experiment(cfg, Path(d) / "out")
            finally:
                sink.stop()
            self.assertTrue((path / "witness" / "receipts.jsonl").is_file())
            manifest = json.loads((path / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["evidence"]["witness"]["receipts"], 2)
            self.assertFalse(manifest["evidence"]["level_attributes"]["independently_witnessed"])
            result = bundle.verify_bundle(path, trusted_witness_keys=str(keys))
            self.assertTrue(result["ok"], result["failed"])
            traces = (path / "configurations" / "baseline" / "traces.jsonl").read_text()
            self.assertIn("egress_observed_at_sink", traces)
            self.assertIn("network_egress_attempted", traces)


class Configs(unittest.TestCase):
    def test_example_configs_parse(self):
        self.assertEqual(experiment.validate_config(experiment.load_config(SYNTHETIC)), [])

    def test_placeholder_model_is_rejected(self):
        problems = experiment.validate_config(experiment.load_config(LIVE))
        self.assertTrue(any("placeholder" in p for p in problems), problems)

    def test_live_without_opt_in_is_refused_before_any_call(self):
        cfg = experiment.load_config(LIVE)
        cfg["model"]["api_model_id"] = "vendor/some-model"
        self.assertEqual(experiment.validate_config(cfg), [])
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(UsageError) as ctx:
                experiment.run_experiment(cfg, d, allow_billable=False)
            self.assertIn("upper bound", str(ctx.exception).lower())
            self.assertIn("--allow-billable-calls", str(ctx.exception))
            self.assertEqual(list(Path(d).iterdir()), [], "nothing is written on refusal")
        cfg["model"]["live"] = False
        self.assertTrue(any("live = true" in p for p in experiment.validate_config(cfg)))

    def test_estimate_is_the_documented_product(self):
        cfg = experiment.load_config(LIVE)
        est = experiment.estimate_calls(cfg)
        self.assertEqual(est["attack_calls"], 6 * 5 * 5 * 6)

    def test_yaml_is_refused_with_a_reason(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "exp.yaml"
            p.write_text("name: x\n", encoding="utf-8")
            with self.assertRaises(UsageError) as ctx:
                experiment.load_config(p)
            self.assertIn("standard", str(ctx.exception))
            self.assertIn("JSON", str(ctx.exception))

    def test_keys_never_belong_in_a_config(self):
        cfg = experiment.load_config(SYNTHETIC)
        cfg["model"]["api_key"] = "sk-whatever"
        self.assertTrue(any("never put a key" in p for p in experiment.validate_config(cfg)))

    def test_invalid_config_raises(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValidationError):
            experiment.run_experiment({"name": "x"}, d)


if __name__ == "__main__":
    unittest.main()
