"""Precommitment ordering, tested against real git repositories.

Each test builds a throwaway repo, commits artifacts in a chosen order, and asserts which
verification level the result reaches. Nothing is mocked, because the whole point of the
design is that the ordering authority is git history rather than a timestamp a submitter
wrote into a file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from .helpers import V
from assay_bench import precommit
from assay_bench.adapters.conformance import build as build_target
from assay_bench.catalog import load_catalog
from assay_bench.errors import MalformedInput, PrecommitmentError
from assay_bench.provenance import target_fingerprint
from assay_bench.runner import run

CATALOG = load_catalog()
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Assay Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Assay Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


class _RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="assay-precommit-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._git("init", "-q", "-b", "main")
        (self.tmp / "precommit" / "registry").mkdir(parents=True)
        (self.tmp / "leaderboard" / "manifests").mkdir(parents=True)
        (self.tmp / "README").write_text("seed\n")
        self._git("add", "-A")
        self._git("commit", "-qm", "seed")

    def _git(self, *args, when: int | None = None):
        env = dict(GIT_ENV)
        if when is not None:
            stamp = f"{when} +0000"
            env["GIT_AUTHOR_DATE"] = stamp
            env["GIT_COMMITTER_DATE"] = stamp
        result = subprocess.run(["git", "-C", str(self.tmp), *args], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def _make_run(self, target="vulnerable", trials=2, secret=None):
        adapter = build_target(target)
        fingerprint = target_fingerprint(adapter, CATALOG)
        secret = secret or "9f" * 32
        record = precommit.create_record(
            run_secret=secret, benchmark_version=CATALOG.version,
            task_set_digest=CATALOG.digest, target_fingerprint=fingerprint, trials=trials)
        manifest = run(adapter, catalog=CATALOG, trials=trials, run_secret=secret,
                       command="test", run_id=record["run_id"])
        return record, manifest

    def _write_record(self, record):
        path = self.tmp / "precommit" / "registry" / f"{record['run_id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2) + "\n")
        return path

    def _write_manifest(self, manifest, name="result.json"):
        path = self.tmp / "leaderboard" / "manifests" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        return path

    def _verify(self, manifest, manifest_path, **kw):
        return precommit.verify(manifest, repo=self.tmp, manifest_path=str(manifest_path),
                                registry_dir=self.tmp / "precommit" / "registry", **kw)


class ValidOrdering(_RepoCase):
    def test_commitment_committed_before_the_manifest_verifies_ordering(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)

        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)

        out = self._verify(manifest, path)
        self.assertIn(precommit.LEVEL_LOCAL, out["levels_verified"])
        self.assertIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertNotIn(precommit.LEVEL_EXTERNAL, out["levels_verified"],
                         "a local clone cannot establish external timestamping")
        self.assertIn("forge witness", out["levels_not_established"][precommit.LEVEL_EXTERNAL])

    def test_a_forge_witness_upgrades_to_precommitment_verified(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)
        commitment_commit = self._git("rev-parse", "HEAD")

        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)

        out = self._verify(manifest, path,
                           external_witness={"commitment_commit": commitment_commit,
                                             "source": "test-forge"})
        self.assertIn(precommit.LEVEL_EXTERNAL, out["levels_verified"])

    def test_a_witness_naming_the_wrong_commit_does_not_upgrade(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)
        out = self._verify(manifest, path,
                           external_witness={"commitment_commit": "0" * 40})
        self.assertNotIn(precommit.LEVEL_EXTERNAL, out["levels_verified"])


class InvalidOrdering(_RepoCase):
    def test_same_commit_commitment_and_reveal_prove_nothing(self):
        """This is exactly the v0.1 situation, and it must not read as verified."""
        record, manifest = self._make_run()
        self._write_record(record)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both at once", when=1_700_000_000)

        out = self._verify(manifest, path)
        self.assertIn(precommit.LEVEL_LOCAL, out["levels_verified"])
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("same commit", out["levels_not_established"][precommit.LEVEL_REPO])

    def test_commitment_committed_after_the_manifest_is_rejected(self):
        record, manifest = self._make_run()
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result first", when=1_700_000_000)

        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "late commitment", when=1_700_000_600)

        out = self._verify(manifest, path)
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("not an ancestor", out["levels_not_established"][precommit.LEVEL_REPO])

    def test_clock_inversion_is_reported_even_when_ancestry_holds(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_600)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_000)  # earlier date, later commit

        out = self._verify(manifest, path)
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("inverted", out["levels_not_established"][precommit.LEVEL_REPO])

    def test_an_uncommitted_record_carries_no_ordering(self):
        record, manifest = self._make_run()
        self._write_record(record)  # never committed
        path = self._write_manifest(manifest)
        self._git("add", "leaderboard")
        self._git("commit", "-qm", "result only")
        out = self._verify(manifest, path)
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])

    def test_history_rewrite_destroys_the_ordering_evidence(self):
        """Ancestry is read from the history that exists now. A rewrite that collapses the
        two commits into one leaves the files intact but the evidence gone -- and the
        result must degrade to 'not established', never stay verified on inertia."""
        record, manifest = self._make_run()
        record_path = self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)
        self.assertIn(precommit.LEVEL_REPO, self._verify(manifest, path)["levels_verified"])

        saved_record = record_path.read_text()
        saved_manifest = path.read_text()
        self._git("reset", "-q", "--hard", "HEAD~2")
        self._write_record(record).write_text(saved_record)
        self._write_manifest(manifest).write_text(saved_manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "squashed rewrite", when=1_700_001_000)

        out = self._verify(manifest, path)
        self.assertIn(precommit.LEVEL_LOCAL, out["levels_verified"])
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("same commit", out["levels_not_established"][precommit.LEVEL_REPO])


class BindingAndReuse(_RepoCase):
    def test_missing_registry_record_is_an_error(self):
        _, manifest = self._make_run()
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result")
        with self.assertRaisesRegex(PrecommitmentError, "never registered"):
            self._verify(manifest, path)

    def test_a_record_for_a_different_target_cannot_be_claimed(self):
        record, manifest = self._make_run(target="vulnerable")
        record["target_fingerprint"] = target_fingerprint(build_target("hardened"), CATALOG)
        record["record_digest"] = precommit.bound_digest(record)
        self._write_record(record)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both")
        with self.assertRaisesRegex(PrecommitmentError, "target_fingerprint"):
            self._verify(manifest, path)

    def test_a_record_with_a_different_trial_plan_cannot_be_claimed(self):
        record, manifest = self._make_run(trials=2)
        record["trial_plan"]["trials_per_task"] = 25
        record["record_digest"] = precommit.bound_digest(record)
        self._write_record(record)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both")
        with self.assertRaisesRegex(PrecommitmentError, "trials_per_task"):
            self._verify(manifest, path)

    def test_reusing_one_commitment_for_a_second_manifest_is_rejected(self):
        record, manifest = self._make_run()
        path = self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)

        precommit.bind_record(path, manifest)
        # A second run of the SAME target with the SAME secret and run id: every binding
        # field matches, so only the reuse rule can stop it. It must.
        second = run(build_target("vulnerable"), catalog=CATALOG, trials=2,
                     run_secret=manifest["run_secret_reveal"], command="test",
                     run_id=record["run_id"], target_note="a second publication")
        self.assertNotEqual(second["integrity_hash"], manifest["integrity_hash"])
        with self.assertRaisesRegex(PrecommitmentError, "reuse"):
            self._verify(second, self._write_manifest(second, "second.json"))

    def test_binding_the_same_manifest_twice_is_idempotent(self):
        record, manifest = self._make_run()
        path = self._write_record(record)
        precommit.bind_record(path, manifest)
        precommit.bind_record(path, manifest)
        self.assertEqual(json.loads(path.read_text())["bound_manifest_integrity_hash"],
                         manifest["integrity_hash"])

    def test_binding_a_second_manifest_to_a_bound_record_is_refused(self):
        record, manifest = self._make_run()
        path = self._write_record(record)
        precommit.bind_record(path, manifest)
        other = dict(manifest, integrity_hash="ff" * 32)
        with self.assertRaisesRegex(PrecommitmentError, "already bound"):
            precommit.bind_record(path, other)

    def test_a_manifest_whose_own_commitment_is_wrong_is_rejected_first(self):
        record, manifest = self._make_run()
        self._write_record(record)
        manifest["run_secret_commitment"] = "00" * 32
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both")
        with self.assertRaisesRegex(PrecommitmentError, "does not bind its reveal"):
            self._verify(manifest, path)


class PrecommitCommandLine(unittest.TestCase):
    """The documented `assay precommit` flow, driven through the real CLI.

    It is excused from the documentation runner because it writes a registry record into the
    repository; here it writes into a temporary one instead, so the command itself is still
    covered.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="assay-precommit-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.registry = self.tmp / "registry"

    def _cli(self, *args):
        import sys
        return subprocess.run([sys.executable, "-m", "assay_bench", *args],
                              cwd=Path(__file__).resolve().parent.parent,
                              capture_output=True, text=True, timeout=120)

    def test_precommit_writes_a_valid_record_and_keeps_the_secret_out_of_it(self):
        secret_file = self.tmp / "run.secret"
        r = self._cli("precommit", "--target", "vulnerable", "--trials", "25",
                      "--registry", str(self.registry), "--secret-out", str(secret_file))
        self.assertEqual(r.returncode, 0, r.stderr)

        records = list(self.registry.glob("*.json"))
        self.assertEqual(len(records), 1)
        record = precommit.validate_record(json.loads(records[0].read_text()))

        secret = secret_file.read_text().strip()
        self.assertEqual(len(secret), 64)
        self.assertEqual(record["commitment"], precommit.secret_commitment(secret))
        self.assertNotIn(secret, records[0].read_text(),
                         "the registry record must never contain the secret it commits to")
        self.assertIsNone(record["bound_manifest_integrity_hash"])

    def test_precommit_list_flags_unrevealed_records(self):
        self._cli("precommit", "--target", "vulnerable", "--trials", "25",
                  "--registry", str(self.registry), "--secret-out", str(self.tmp / "s"))
        r = self._cli("precommit-list", "--registry", str(self.registry))
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["unrevealed"], 1)
        self.assertEqual(payload["records"][0]["state"], "UNREVEALED")

    def test_precommit_verify_reports_a_missing_record_rather_than_passing(self):
        manifest = Path(__file__).resolve().parent.parent / "leaderboard" / "manifests" / "reference_vulnerable.json"
        r = self._cli("precommit-verify", "--manifest", str(manifest),
                      "--registry", str(self.registry))
        self.assertEqual(r.returncode, 1)
        self.assertIn("never registered", r.stderr)

    def test_the_repository_registry_is_empty_as_documented(self):
        """precommit/README.md explains why: the conformance runs use a published fixed secret,
        so a commitment over it would be theatre. If a record appears here, that text is stale."""
        repo_registry = Path(__file__).resolve().parent.parent / "precommit" / "registry"
        self.assertEqual(sorted(p.name for p in repo_registry.glob("*.json")), [])


class RecordIntegrity(unittest.TestCase):
    def test_a_tampered_record_is_detected(self):
        record = precommit.create_record(run_secret="ab" * 32, benchmark_version="0.1",
                                         task_set_digest="d" * 64,
                                         target_fingerprint="cafe", trials=25)
        precommit.validate_record(record)
        record["target_fingerprint"] = "beef"
        with self.assertRaisesRegex(PrecommitmentError, "was altered"):
            precommit.validate_record(record)

    def test_unknown_schema_is_refused(self):
        record = precommit.create_record(run_secret="ab" * 32, benchmark_version="0.1",
                                         task_set_digest="d" * 64,
                                         target_fingerprint="cafe", trials=25)
        record["schema"] = "assay/precommit-record/99"
        with self.assertRaisesRegex(PrecommitmentError, "unsupported"):
            precommit.validate_record(record)

    def test_missing_fields_are_malformed(self):
        with self.assertRaises(MalformedInput):
            precommit.validate_record({"schema": precommit.RECORD_SCHEMA})

    def test_a_bad_trial_plan_is_refused_at_creation(self):
        from assay_bench.errors import ValidationError
        with self.assertRaises(ValidationError):
            precommit.create_record(run_secret="ab" * 32, benchmark_version="0.1",
                                    task_set_digest="d" * 64, target_fingerprint="x", trials=0)

    def test_duplicate_commitments_in_one_registry_are_detected(self):
        tmp = Path(tempfile.mkdtemp(prefix="assay-registry-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        for name in ("a", "b"):
            record = precommit.create_record(run_secret="cd" * 32, benchmark_version="0.1",
                                             task_set_digest="d" * 64,
                                             target_fingerprint="x", trials=5)
            (tmp / f"{name}.json").write_text(json.dumps(record))
        with self.assertRaisesRegex(PrecommitmentError, "registered twice"):
            precommit.load_registry(tmp)


if __name__ == "__main__":
    unittest.main()
