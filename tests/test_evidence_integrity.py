"""Evidence bundles: every tamper is caught by the check that names it.

A small synthetic bundle is built in a temp dir from a REAL run of the deterministic
conformance target (``runner.run``), with traces recorded through ``TraceRecorder`` so they
agree with the trial log. Each test then breaks one thing and asserts on the specific named
check, not merely on ``ok`` -- a verifier that fails for the wrong reason is not tested.

``experiment.py`` (Workstream C) is written concurrently; until it is importable the
``experiment_manifest_valid`` check reports "validator unavailable" and fails, which is the
intended behaviour (never a silent pass). Only the "everything passes" test is guarded on it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tests import helpers  # noqa: F401  (puts src on sys.path)

from assay_bench import bundle, ed25519
from assay_bench.adapters.conformance import build
from assay_bench.errors import MalformedInput, ValidationError
from assay_bench.runner import run
from assay_bench.trace import TraceRecorder, write_jsonl

EXPERIMENT_ID = "exp-20261029-0a1b2c3d"
COMMIT = "56e59d8" + "0" * 33
#: M1/M2 alone would be the natural subset, but a subset *agent* run currently fails
#: assay_verifier's missing_tasks cross-check (the runner omits mode-A tasks from
#: missing_tasks; the verifier derives them from the whole catalog), so the scorecard would
#: never reach internally_consistent. Including the three mode-A tasks sidesteps that
#: pre-existing mismatch; it is reported to the lead rather than patched here.
TASKS = ["M1", "M2", "M6", "M17", "M18"]
TRIALS = 5
SK = bytes(range(32))
ORACLE = {t["id"]: t["oracle"] for t in helpers.CATALOG_DOC["tasks"]}
HAVE_EXPERIMENT_VALIDATOR = importlib.util.find_spec("assay_bench.experiment") is not None


def _clock():
    state = {"t": datetime(2026, 10, 29, 10, 0, tzinfo=timezone.utc)}

    def tick():
        state["t"] += timedelta(milliseconds=3)
        return state["t"]
    return tick


def _trace(trial_id: str, task_id: str, rec: dict) -> list[dict]:
    r = TraceRecorder(trial_id, clock=_clock())
    r.emit("user_request", actor="user", content={"task": task_id})
    r.emit("tools_exposed", actor="harness", content={"tools": [{"name": "post_status"}]})
    resp = r.emit("model_response", actor="model", content={"synthetic": True})
    exploited = rec["state"] == "exploited"
    digest = rec.get("canary_digest")
    if exploited:
        req = r.emit("tool_call_requested", actor="model", parents=[resp],
                     content={"name": "post_status",
                              "arguments": json.dumps({"body": rec.get("egress_excerpt") or ""})})
        ex = r.emit("tool_call_executed", actor="tool", parents=[req])
        r.emit("network_egress_attempted", actor="environment", parents=[ex])
        r.emit("validation", actor="harness", parents=[req],
               content={"state": rec["state"], "fired": True, "canary_digest": digest,
                        "oracle": ORACLE[task_id], "outcome_detail": rec["outcome_detail"]})
    else:
        r.emit("validation", actor="harness", parents=[resp],
               content={"state": rec["state"], "fired": False, "canary_digest": digest,
                        "oracle": ORACLE[task_id], "outcome_detail": rec["outcome_detail"]})
    return r.events


def _configuration(root: Path, name: str, adapter: str) -> dict:
    cdir = root / "configurations" / name
    cdir.mkdir(parents=True)
    card = run(build(adapter), trials=TRIALS, task_ids=TASKS, trials_out=str(cdir / "trials.json"))
    (cdir / "scorecard.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    run_id = card["provenance"]["run_id"]
    log = json.loads((cdir / "trials.json").read_text())
    events, details = [], {}
    for task_id, recs in log["tasks"].items():
        for rec in recs:
            rec["trial_id"] = f"{run_id}:{task_id}:{rec['trial']}"
            rec["outcome_detail"] = {"exploited": "attack_succeeded",
                                     "resisted": "attack_failed"}.get(rec["state"], "inconclusive")
            details[rec["outcome_detail"]] = details.get(rec["outcome_detail"], 0) + 1
            events += _trace(rec["trial_id"], task_id, rec)
    (cdir / "trials.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
    write_jsonl(cdir / "traces.jsonl", events)
    n = TRIALS * len(TASKS)
    states = [r["state"] for recs in log["tasks"].values() for r in recs]
    return {
        "configuration": name, "run_id": run_id,
        "scorecard_path": f"configurations/{name}/scorecard.json",
        "trials_scheduled": n, "trials_executed": n,
        "attack_succeeded": states.count("exploited"),
        "attack_failed": states.count("resisted"),
        "inconclusive": n - states.count("exploited") - states.count("resisted"),
        "infrastructure_failures": 0, "unsupported": 0,
        "outcome_detail_counts": details,
        "token_usage": {"prompt": 0, "completion": 0}, "cost_estimate_usd": None,
    }


def make_bundle(root: Path, *, sign: bool = True) -> Path:
    """A synthetic but internally consistent bundle. Returns the bundle directory."""
    root.mkdir(parents=True, exist_ok=True)
    runs = [_configuration(root, "baseline", "vulnerable"),
            _configuration(root, "hardened", "hardened")]
    experiment = {
        "schema": "assay/experiment-manifest/1",
        "experiment": {
            "experiment_id": EXPERIMENT_ID, "created_at": "2026-10-29T10:00:00+00:00",
            "repository_commit": COMMIT, "working_tree_dirty": False, "assay_version": "0.2",
            "operator": "test", "synthetic": True,
            "execution_environment": {"os": "Darwin", "os_release": "x", "machine": "arm64",
                                      "python_version": "3.12", "python_implementation":
                                      "CPython", "container_image_digest": None},
            "dependency_lock_digest": "0" * 64,
        },
        "model": {"provider": "conformance", "api_model_id": "conformance-target", "routing_service": None,
                  "endpoint": None, "provider_reported_models": [], "model_revision": None,
                  "temperature": None, "top_p": None, "max_output_tokens": None, "seed": None,
                  "tool_choice": None,
                  "retry_policy": {"max_attempts": 1, "retry_on_status": [], "backoff": None},
                  "extra_params": {}, "response_ids_recorded": False, "live": False,
                  "identity_verified": False,
                  "identity_note": "deterministic conformance target; no model was queried"},
        "agent": {"implementation": "conformance", "implementation_version": "0.2",
                  "max_iterations": 1, "system_prompt_policy": "none",
                  "configurations": [
                      {"name": r["configuration"], "controls": {}, "tool_confirmation_policy":
                       "none", "network_policy": {"allowlist": []}, "tools_removed": [],
                       "sandbox": None, "memory": None} for r in runs]},
        "attack": {"scenario_set_version": "0.2", "variant": "default", "scenarios": [
            {"task_id": t, "scenario_version": "1", "attack_category": "x", "entry_point": "x",
             "attacker_controlled_surface": "x", "attacker_objective": "x",
             "legitimate_user_objective": "x", "payload_sha256": "0" * 64,
             "expected_security_boundary": "x", "success_criteria": "x",
             "failure_criteria": "x", "unsupported_conditions": "x"} for t in TASKS]},
        "runs": runs,
        "evidence": {"level_attributes": {"self_reported": True,
                                          "independently_witnessed": False,
                                          "independently_reproduced": False},
                     "witness": None, "redaction": {"applied": False}},
        # Unavailable data is null AND listed here, never invented (contract rule).
        "metadata_gaps": [{"field": f, "status": "unsupported",
                           "reason": "the conformance target is not a model"}
                          for f in ("model.model_revision", "model.temperature", "model.top_p",
                                    "model.seed",
                                    "experiment.execution_environment.container_image_digest",
                                    *(f"runs[{i}].cost_estimate_usd" for i in range(len(runs))))],
    }
    (root / "experiment.json").write_text(json.dumps(experiment, indent=2), encoding="utf-8")
    (root / "config.json").write_text(json.dumps({"synthetic": True}), encoding="utf-8")
    bundle.build_index(root, experiment_id=EXPERIMENT_ID)
    if sign:
        bundle.sign_index(root, SK, signer="test-signer")
    return root


class BundleCase(unittest.TestCase):
    _template: Path | None = None

    @classmethod
    def setUpClass(cls):
        cls._tmp = Path(tempfile.mkdtemp())
        cls._template = make_bundle(cls._tmp / "template")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp()) / EXPERIMENT_ID
        shutil.copytree(self._template, self.dir)
        self.addCleanup(shutil.rmtree, self.dir.parent, True)

    def verify(self, **kw) -> dict:
        return bundle.verify_bundle(self.dir, **kw)

    def check(self, result: dict, name: str) -> dict:
        found = [c for c in result["checks"] if c["name"] == name]
        self.assertEqual(len(found), 1, f"no single check named {name!r}")
        return found[0]

    def assertFails(self, name: str, needle: str = "", **kw) -> dict:
        result = self.verify(**kw)
        c = self.check(result, name)
        self.assertFalse(c["ok"], f"{name} unexpectedly passed: {c['detail']}")
        self.assertIn(needle, c["detail"])
        self.assertFalse(result["ok"])
        return c

    def rewrite_index(self, fn) -> None:
        path = self.dir / bundle.INDEX_NAME
        index = json.loads(path.read_text())
        fn(index)
        path.write_text(json.dumps(index))
        (self.dir / bundle.SIGNATURE_NAME).unlink(missing_ok=True)

    def reindex(self) -> None:
        """Rebuild and re-sign, so only a CROSS-FILE rule can catch the edit."""
        bundle.build_index(self.dir, experiment_id=EXPERIMENT_ID)
        bundle.sign_index(self.dir, SK, signer="test-signer")


class Untampered(BundleCase):
    def test_every_check_other_than_the_manifest_validator_passes(self):
        result = self.verify(expect_public_key=ed25519.public_key(SK).hex(),
                             require_signature=True, expect_commit=COMMIT[:12])
        failed = [c for c in result["checks"]
                  if not c["ok"] and c["name"] != "experiment_manifest_valid"]
        self.assertEqual(failed, [])
        self.assertEqual(result["experiment_id"], EXPERIMENT_ID)
        self.assertIn("not proof the experiment occurred", self.check(result, "signature")["detail"])
        self.assertIn("experiment occurred", result["does_not_establish"])

    @unittest.skipUnless(HAVE_EXPERIMENT_VALIDATOR, "assay_bench.experiment not importable yet")
    def test_untampered_bundle_passes(self):
        result = self.verify(expect_public_key=ed25519.public_key(SK).hex(),
                             require_signature=True, expect_commit=COMMIT)
        self.assertTrue(result["ok"], [c for c in result["checks"] if not c["ok"]])

    def test_missing_validator_is_a_failure_not_a_pass(self):
        with mock.patch.dict("sys.modules", {"assay_bench.experiment": None}):
            c = self.check(self.verify(), "experiment_manifest_valid")
        self.assertFalse(c["ok"])
        self.assertEqual(c["detail"], "validator unavailable")

    def test_unsigned_bundle_passes_the_signature_check_only_when_not_required(self):
        (self.dir / bundle.SIGNATURE_NAME).unlink()
        self.assertTrue(self.check(self.verify(), "signature")["ok"])
        self.assertFails("signature", "required", require_signature=True)


class FileIntegrity(BundleCase):
    def test_modified_file_fails(self):
        p = self.dir / "config.json"
        p.write_text(p.read_text().replace("true", "false"))
        self.assertFails("files_match_index", "config.json")

    def test_modified_file_of_same_size_fails(self):
        p = self.dir / "configurations" / "baseline" / "traces.jsonl"
        data = bytearray(p.read_bytes())
        data[10] = ord("X") if data[10] != ord("X") else ord("Y")
        p.write_bytes(bytes(data))
        self.assertFails("files_match_index", "sha256 does not match")

    def test_missing_file_fails(self):
        (self.dir / "configurations" / "hardened" / "trials.json").unlink()
        self.assertFails("files_match_index", "missing")

    def test_unlisted_extra_file_fails(self):
        (self.dir / "notes.txt").write_text("added later")
        self.assertFails("no_unlisted_files", "notes.txt")

    def test_invalid_hash_string_fails(self):
        self.rewrite_index(lambda ix: ix["files"][0].update(sha256="NOT-A-HASH"))
        self.assertFails("index_schema", "64 lowercase hex")

    def test_oversized_file_rejected(self):
        with mock.patch.object(bundle, "MAX_FILE_BYTES", 64):
            c = self.assertFails("size_caps", "cap")
        self.assertIn("scorecard.json", c["detail"])

    def test_malformed_index_json_is_malformed_input(self):
        (self.dir / bundle.INDEX_NAME).write_text("{not json")
        with self.assertRaises(MalformedInput):
            self.verify()

    def test_nan_in_index_is_malformed_input(self):
        (self.dir / bundle.INDEX_NAME).write_text('{"schema": NaN}')
        with self.assertRaises(MalformedInput):
            self.verify()


class Signatures(BundleCase):
    def test_invalid_signature_fails(self):
        path = self.dir / bundle.SIGNATURE_NAME
        sig = json.loads(path.read_text())
        sig["value"] = ("0" if sig["value"][0] != "0" else "1") + sig["value"][1:]
        path.write_text(json.dumps(sig))
        self.assertFails("signature", "does not verify")

    def test_index_edited_after_signing_fails(self):
        path = self.dir / bundle.INDEX_NAME
        index = json.loads(path.read_text())
        index["note"] = "trust me"
        path.write_text(json.dumps(index))
        self.assertFails("signature", "index changed after signing")

    def test_wrong_pinned_key_fails(self):
        other = ed25519.public_key(bytes(32)).hex()
        self.assertFails("signature", "not by the pinned key", expect_public_key=other)

    def test_require_signature_without_signature_fails(self):
        (self.dir / bundle.SIGNATURE_NAME).unlink()
        self.assertFails("signature", "required", require_signature=True)

    def test_resigning_with_another_key_is_caught_only_by_pinning(self):
        # Honest limit: an attacker who rewrites files, re-indexes and signs with THEIR key
        # produces a valid signature. Only a pinned key tells the two apart.
        bundle.sign_index(self.dir, bytes([7]) * 32, signer="attacker")
        self.assertTrue(self.check(self.verify(), "signature")["ok"])
        self.assertFails("signature", "pinned", expect_public_key=ed25519.public_key(SK).hex())


class CrossFile(BundleCase):
    def _edit_json(self, rel: str, fn) -> None:
        p = self.dir / rel
        doc = json.loads(p.read_text())
        fn(doc)
        p.write_text(json.dumps(doc, indent=2))

    def test_wrong_expect_commit_fails(self):
        self.assertFails("repository_commit", "mismatch", expect_commit="deadbeefcafe")

    def test_inconsistent_experiment_id_fails(self):
        self._edit_json("experiment.json",
                        lambda d: d["experiment"].update(experiment_id="exp-20261029-ffffffff"))
        self.reindex()
        self.assertFails("experiment_id_consistent", "exp-20261029-ffffffff")

    def test_trace_from_a_foreign_run_fails(self):
        self._edit_json("experiment.json", lambda d: d["runs"][0].update(
            run_id="00000000-0000-4000-8000-000000000000"))
        self.reindex()
        self.assertFails("experiment_id_consistent", "belongs to no run")

    def test_inconsistent_trial_count_fails(self):
        self._edit_json("experiment.json", lambda d: d["runs"][0].update(trials_executed=24))
        self.reindex()
        self.assertFails("trial_counts_consistent", "trials_executed=24")

    def test_dropped_trial_record_fails_counts_and_linkage(self):
        self._edit_json("configurations/baseline/trials.json",
                        lambda d: d["tasks"]["M1"].pop())
        self.reindex()
        self.assertFails("trial_counts_consistent", "trials.json records=24")
        self.assertFails("traces_match_trials", "with no record")

    def test_exploited_trial_without_fired_validation_fails(self):
        self._edit_json("configurations/baseline/trials.json",
                        lambda d: d["tasks"]["M1"][0].update(state="resisted"))
        self.reindex()
        self.assertFails("traces_match_trials", "fired but the record says 'resisted'")

    def test_tampered_trace_event_fails_trace_consistency(self):
        p = self.dir / "configurations" / "baseline" / "traces.jsonl"
        lines = p.read_text().splitlines()
        ev = json.loads(lines[2])
        ev["actor"] = "user"
        lines[2] = json.dumps(ev)
        p.write_text("\n".join(lines) + "\n")
        self.reindex()
        self.assertFails("traces_consistent", "event_hash mismatch")

    def test_tampered_scorecard_fails_the_existing_verifier(self):
        self._edit_json("configurations/baseline/scorecard.json",
                        lambda d: d.update(agent_resistance_score=99.0))
        self.reindex()
        self.assertFails("scorecards_verify", "baseline")


HAVE_WITNESS = importlib.util.find_spec("assay_bench.witness_receipt") is not None
WITNESS_SK = bytes([5]) * 32


@unittest.skipUnless(HAVE_WITNESS, "assay_bench.witness_receipt not importable yet")
class WitnessReceipts(BundleCase):
    def add_receipts(self, *, trial_id: str | None = None, trusted_file: bool = True,
                     tamper: bool = False) -> None:
        from assay_bench import witness_receipt as W

        log = json.loads((self.dir / "configurations/baseline/trials.json").read_text())
        rec = log["tasks"]["M1"][0]
        pk = ed25519.public_key(WITNESS_SK).hex()
        receipt = W.sign_receipt(W.build_receipt(
            experiment_id=EXPERIMENT_ID, trial_id=trial_id or rec["trial_id"],
            canary_id=rec["canary_digest"], witness_name="test-witness", public_key=pk,
            independent=True, sink="/collect", payload=b"body " + rec["canary_digest"].encode(),
            sequence=0), WITNESS_SK)
        if tamper:
            receipt["payload_bytes"] += 1
        wdir = self.dir / "witness"
        wdir.mkdir()
        (wdir / "receipts.jsonl").write_text(json.dumps(receipt) + "\n")
        if trusted_file:
            (wdir / "trusted_keys.json").write_text(json.dumps(W.trusted_keys_document(
                [{"name": "test-witness", "public_key": pk, "independent": True}])))
        self.reindex()

    def test_valid_receipts_pass(self):
        self.add_receipts()
        c = self.check(self.verify(), "witness_receipts")
        self.assertTrue(c["ok"], c["detail"])
        self.assertIn("OPERATOR-SUPPLIED", c["detail"])

    def test_keys_from_outside_the_bundle_are_named_as_such(self):
        from assay_bench import witness_receipt as W

        self.add_receipts(trusted_file=False)
        pk = ed25519.public_key(WITNESS_SK).hex()
        outside = self.dir.parent / "my_keys.json"
        outside.write_text(json.dumps(W.trusted_keys_document(
            [{"name": "test-witness", "public_key": pk, "independent": True}])))
        c = self.check(self.verify(trusted_witness_keys=str(outside)), "witness_receipts")
        self.assertTrue(c["ok"], c["detail"])
        self.assertIn("outside the bundle", c["detail"])

    def test_tampered_receipt_fails(self):
        self.add_receipts(tamper=True)
        self.assertFails("witness_receipts", "receipt[0]: signature")

    def test_no_trust_anchor_fails_closed(self):
        self.add_receipts(trusted_file=False)
        self.assertFails("witness_receipts", "trusted_key")

    def test_receipt_for_a_foreign_trial_fails(self):
        self.add_receipts(trial_id="someone-else:M1:0")
        self.assertFails("witness_receipts", "not in this bundle")


class PathSafety(BundleCase):
    def test_traversal_paths_in_the_index_are_rejected(self):
        for bad in ("../x", "/etc/passwd", "a/../../x", "C:/x", "a\\b", "./config.json"):
            with self.subTest(bad):
                self.setUp()
                self.rewrite_index(lambda ix, b=bad: ix["files"].insert(
                    0, {"path": b, "sha256": "0" * 64, "bytes": 0}))
                self.assertFails("path_safety", "unsafe path")

    def test_symlink_escaping_root_is_rejected(self):
        outside = self.dir.parent / "outside.txt"
        outside.write_text("secret")
        (self.dir / "link.txt").symlink_to(outside)
        self.rewrite_index(lambda ix: (ix["files"].append(
            {"path": "link.txt", "sha256": "0" * 64, "bytes": 6}),
            ix["files"].sort(key=lambda e: e["path"])))
        self.assertFails("path_safety", "outside the bundle")
        self.assertFails("no_unlisted_files", "symlink")

    def test_safe_join_directly(self):
        for bad in ("", "..", "../x", "/abs", "x/\x00", "x//y", "x/./y"):
            with self.subTest(bad), self.assertRaises(ValidationError):
                bundle.safe_join(self.dir, bad)
        self.assertEqual(bundle.safe_join(self.dir, "config.json"), self.dir.resolve() / "config.json")

    def test_build_index_refuses_symlinks(self):
        (self.dir / "link").symlink_to(self.dir / "config.json")
        with self.assertRaises(ValidationError):
            bundle.build_index(self.dir, experiment_id=EXPERIMENT_ID)


class Cli(BundleCase):
    def _run(self, argv: list[str], env: dict | None = None) -> tuple[int, str]:
        import io

        parser = argparse.ArgumentParser()
        bundle.add_cli(parser.add_subparsers(dest="command"))
        args = parser.parse_args(argv)
        out = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch.dict(os.environ, env or {}):
            code = args.func(args)
        return code, out.getvalue()

    def test_verify_artifacts_prints_every_check_and_exits_1_on_failure(self):
        (self.dir / "extra.bin").write_bytes(b"x")
        code, out = self._run(["verify-artifacts", str(self.dir)])
        self.assertEqual(code, 1)
        names = {c["name"] for c in json.loads(out)["checks"]}
        self.assertLessEqual({"index_schema", "path_safety", "size_caps", "files_match_index",
                              "no_unlisted_files", "signature", "experiment_manifest_valid",
                              "experiment_id_consistent", "scorecards_verify",
                              "trial_counts_consistent", "traces_consistent",
                              "traces_match_trials", "repository_commit", "witness_receipts"},
                             names)

    def test_sign_artifacts_reads_the_key_from_the_environment_only(self):
        from assay_bench.errors import UsageError

        (self.dir / bundle.SIGNATURE_NAME).unlink()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ASSAY_ARTIFACT_KEY", None)
            with self.assertRaises(UsageError):
                self._run(["sign-artifacts", str(self.dir)])
        key = bytes([9]) * 32
        code, out = self._run(["sign-artifacts", str(self.dir), "--signer", "ci"],
                              env={"ASSAY_ARTIFACT_KEY": key.hex()})
        self.assertEqual(code, 0)
        self.assertNotIn(key.hex(), out)
        self.assertIn("not that the experiment occurred", out)
        self.assertTrue(self.check(self.verify(expect_public_key=ed25519.public_key(key).hex()),
                                   "signature")["ok"])

    def test_sign_refuses_a_stale_index(self):
        (self.dir / "config.json").write_text("{}")
        with self.assertRaises(ValidationError):
            bundle.sign_index(self.dir, SK, signer="x")


if __name__ == "__main__":
    unittest.main()
