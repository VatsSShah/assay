"""The demo is a deliverable, so it is tested like one.

These run the real scripts, not a transcript of them. If `run_demo.sh` breaks, or the tamper
step stops being rejected, or the demo starts claiming a real target was involved, this fails.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .helpers import ROOT, V

DEMO = ROOT / "demo"
TIMEOUT = 300


def _bash(script: str, out_dir: Path, **extra_env):
    env = {**os.environ, "ASSAY_DEMO_OUT": str(out_dir), "ASSAY_DEMO_PAUSE": "0",
           "PYTHON": "python3", **extra_env}
    return subprocess.run(["bash", str(DEMO / script)], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=TIMEOUT)


class DemoRuns(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="assay-demo-test-"))
        self.addCleanup(shutil.rmtree, self.out, True)

    def test_reset_is_idempotent_and_leaves_an_empty_directory(self):
        for _ in range(3):
            r = _bash("reset.sh", self.out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(self.out.is_dir())
            self.assertEqual(list(self.out.iterdir()), [])

    def test_the_demo_runs_end_to_end_and_exits_zero(self):
        _bash("reset.sh", self.out)
        r = _bash("run_demo.sh", self.out)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        for name in ("vulnerable.json", "hardened.json", "tampered.json"):
            self.assertTrue((self.out / name).is_file(), f"{name} was not produced")

    def test_the_demo_produces_verifiable_and_rejected_artifacts(self):
        _bash("reset.sh", self.out)
        self.assertEqual(_bash("run_demo.sh", self.out).returncode, 0)

        for name, expected in (("vulnerable.json", 0.0), ("hardened.json", 100.0)):
            with self.subTest(artifact=name):
                manifest = json.loads((self.out / name).read_text())
                out = V.verify_manifest(manifest, require=("run_complete",))
                self.assertEqual(len(out["levels_verified"]), 5)
                self.assertEqual(manifest["agent_resistance_score"], expected)

        tampered = json.loads((self.out / "tampered.json").read_text())
        with self.assertRaisesRegex(V.InconsistentManifest, "does not recompute"):
            V.verify_manifest(tampered)

    def test_the_tampered_copy_differs_by_exactly_one_observed_string(self):
        _bash("reset.sh", self.out)
        _bash("run_demo.sh", self.out)
        original = json.loads((self.out / "vulnerable.json").read_text())
        tampered = json.loads((self.out / "tampered.json").read_text())

        differing = [k for k in original if original[k] != tampered.get(k)]
        self.assertEqual(sorted(differing), ["findings", "integrity_hash"],
                         "the tamper step must change only a finding and the reseal")
        changed = [(a["id"], k) for a, b in zip(original["findings"], tampered["findings"])
                   for k in a if a[k] != b.get(k)]
        self.assertEqual(changed, [("M1", "canary")])

    def test_the_demo_never_claims_a_real_target(self):
        _bash("reset.sh", self.out)
        r = _bash("run_demo.sh", self.out)
        self.assertIn("real_target=False", r.stdout)
        self.assertIn("DETERMINISTIC conformance stubs", r.stdout)
        self.assertIn("No live MCP server", r.stdout)
        for manifest in ("vulnerable.json", "hardened.json"):
            doc = json.loads((self.out / manifest).read_text())
            self.assertIs(doc["provenance"]["target_is_real"], False)

    def test_the_demo_states_the_trust_boundary_on_screen(self):
        _bash("reset.sh", self.out)
        r = _bash("run_demo.sh", self.out)
        self.assertIn("does not prove a", r.stdout)
        self.assertIn("keyholder could have typed it", r.stdout)

    def test_a_paced_run_produces_the_same_outcome_as_an_unpaced_one(self):
        """The pacing knob must change the pace and nothing else."""
        _bash("reset.sh", self.out)
        _bash("run_demo.sh", self.out)
        fast = json.loads((self.out / "vulnerable.json").read_text())

        _bash("reset.sh", self.out)
        slow_run = _bash("run_demo.sh", self.out, ASSAY_DEMO_PAUSE="0.05")
        self.assertEqual(slow_run.returncode, 0, slow_run.stderr[-2000:])
        slow = json.loads((self.out / "vulnerable.json").read_text())

        from assay_bench import attest
        self.assertEqual(attest.invariants_digest(fast), attest.invariants_digest(slow))

    def test_repeated_runs_agree_on_invariants_with_fresh_secrets(self):
        from assay_bench import attest

        digests, secrets = [], []
        for _ in range(3):
            _bash("reset.sh", self.out)
            self.assertEqual(_bash("run_demo.sh", self.out).returncode, 0)
            manifest = json.loads((self.out / "vulnerable.json").read_text())
            digests.append(attest.invariants_digest(manifest))
            secrets.append(manifest["run_secret_reveal"])
        self.assertEqual(len(set(digests)), 1, "invariants must be stable across runs")
        self.assertEqual(len(set(secrets)), 3, "each run must mint a fresh secret")


class PublishedRecording(unittest.TestCase):
    """The committed recording must remain what VIDEO_VALIDATION.md says it is."""

    RECORDING = DEMO / "recording"

    def test_the_recording_and_its_frames_are_committed(self):
        self.assertTrue((self.RECORDING / "assay-demo.webm").is_file())
        self.assertTrue((self.RECORDING / "validation.json").is_file())
        self.assertTrue((self.RECORDING / "transcript.txt").is_file())
        self.assertGreaterEqual(len(list((self.RECORDING / "frames").glob("*.jpg"))), 20)

    def test_the_recorded_video_hash_matches_the_validation_report(self):
        import hashlib
        report = json.loads((self.RECORDING / "validation.json").read_text())
        actual = hashlib.sha256((self.RECORDING / "assay-demo.webm").read_bytes()).hexdigest()
        self.assertEqual(actual, report["video"]["sha256"])

    def test_every_sampled_frame_hash_matches_the_report(self):
        import hashlib
        report = json.loads((self.RECORDING / "validation.json").read_text())
        for sample in report["samples"]:
            with self.subTest(frame=sample["frame"]):
                path = self.RECORDING / "frames" / sample["frame"]
                self.assertTrue(path.is_file())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                                 sample["sha256"])

    def test_the_recording_revalidates_as_time_varying(self):
        r = subprocess.run(
            ["python3", str(DEMO / "validate_video.py"),
             str(self.RECORDING / "assay-demo.webm"), str(self.RECORDING / "frames")],
            cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        summary = json.loads(r.stdout)
        self.assertEqual(summary["verdict"], "time-varying")
        self.assertEqual(summary["longest_frozen_run_samples"], 0)
        self.assertTrue(all(summary["gate"].values()))

    def test_the_transcript_shows_the_tamper_rejection(self):
        transcript = (self.RECORDING / "transcript.txt").read_text()
        self.assertIn("does not recompute", transcript)
        self.assertIn("exit status: 1", transcript)
        self.assertIn("demo exit status: 0", transcript)


if __name__ == "__main__":
    unittest.main()
