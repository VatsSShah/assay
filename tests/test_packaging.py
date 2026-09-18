"""Build the wheel, install it into a clean virtual environment, and drive the CLIs from
OUTSIDE the checkout.

Running from the source tree hides packaging defects: a missing package, an unshipped data
file or a broken entry point all still "work" because the current directory is on sys.path.
These tests deliberately run from a temporary directory with no such luck.

They are skipped, with a stated reason, when the environment cannot build a wheel offline.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from .helpers import ROOT

BUILD_TIMEOUT = 300


def _can_build() -> tuple[bool, str]:
    try:
        import setuptools  # noqa: F401
        import wheel  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        return False, f"no offline build backend available: {exc}"
    return True, ""


class Packaging(unittest.TestCase):
    wheel_path: Path | None = None
    venv: Path | None = None
    tmp: Path | None = None

    @classmethod
    def setUpClass(cls):
        ok, reason = _can_build()
        if not ok:  # pragma: no cover - environment dependent
            raise unittest.SkipTest(reason)
        cls.tmp = Path(tempfile.mkdtemp(prefix="assay-pkg-"))

        # Build and install inside a fresh venv. Distro-patched system setuptools can fail
        # bdist_wheel with AttributeError: install_layout; the venv gets the upstream
        # setuptools that ensurepip bundles, so this needs no network either way.
        cls.venv = cls.tmp / "venv"
        venv = subprocess.run([sys.executable, "-m", "venv", str(cls.venv)],
                              capture_output=True, text=True, timeout=BUILD_TIMEOUT)
        if venv.returncode != 0:  # pragma: no cover
            raise unittest.SkipTest(f"venv creation failed: {venv.stderr}")
        python = cls.venv / "bin" / "python"

        out = cls.tmp / "dist"
        out.mkdir()
        build = subprocess.run(
            [str(python), "-c",
             "import sys, setuptools.build_meta as b; print(b.build_wheel(sys.argv[1]))",
             str(out)],
            cwd=ROOT, capture_output=True, text=True, timeout=BUILD_TIMEOUT)
        if build.returncode != 0:  # pragma: no cover - environment dependent
            raise unittest.SkipTest(f"wheel build failed:\n{build.stdout}\n{build.stderr}")
        wheels = sorted(out.glob("*.whl"))
        if not wheels:  # pragma: no cover
            raise unittest.SkipTest("build produced no wheel")
        cls.wheel_path = wheels[0]

        pip = cls.venv / "bin" / "pip"
        install = subprocess.run(
            [str(pip), "install", "--no-index", "--no-build-isolation", str(cls.wheel_path)],
            capture_output=True, text=True, timeout=BUILD_TIMEOUT)
        if install.returncode != 0:  # pragma: no cover
            raise unittest.SkipTest(f"wheel install failed:\n{install.stdout}\n{install.stderr}")

    @classmethod
    def tearDownClass(cls):
        if cls.tmp:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- helpers ------------------------------------------------------------------
    def _outside(self, *args, binary="assay"):
        """Run an installed console script from a directory that is NOT the checkout."""
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "ASSAY_TASKS")}
        return subprocess.run([str(self.venv / "bin" / binary), *args],
                              cwd=elsewhere, capture_output=True, text=True, env=env,
                              timeout=BUILD_TIMEOUT)

    def _python(self, code):
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "ASSAY_TASKS")}
        return subprocess.run([str(self.venv / "bin" / "python"), "-c", code],
                              cwd=elsewhere, capture_output=True, text=True, env=env,
                              timeout=BUILD_TIMEOUT)

    # -- wheel contents -----------------------------------------------------------
    def test_wheel_ships_every_module_the_cli_needs(self):
        names = zipfile.ZipFile(self.wheel_path).namelist()
        for expected in ("assay_verifier.py", "scoring.py", "badge.py",
                         "assay_bench/__init__.py", "assay_bench/cli.py",
                         "assay_bench/runner.py", "assay_bench/catalog.py",
                         "assay_bench/precommit.py", "assay_bench/attest.py",
                         "assay_bench/adapters/__init__.py",
                         "assay_bench/adapters/conformance.py"):
            with self.subTest(member=expected):
                self.assertIn(expected, names)

    def test_wheel_ships_the_frozen_task_set(self):
        names = zipfile.ZipFile(self.wheel_path).namelist()
        self.assertIn("assay_bench/data/tasks.json", names,
                      "without the packaged catalog an installed verifier cannot reach "
                      "catalog_bound")

    def test_the_packaged_task_set_is_byte_identical_to_the_canonical_one(self):
        packaged = zipfile.ZipFile(self.wheel_path).read("assay_bench/data/tasks.json")
        self.assertEqual(packaged, (ROOT / "tasks.json").read_bytes())

    # -- imports and CLIs from outside the checkout -------------------------------
    def test_imports_work_outside_the_checkout(self):
        r = self._python(
            "import assay_verifier, scoring, badge, assay_bench, assay_bench.cli, "
            "assay_bench.runner, assay_bench.precommit, assay_bench.attest; "
            "from assay_bench.catalog import load_catalog; "
            "print(len(load_catalog()))")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "31")

    def test_both_console_scripts_exist_and_respond(self):
        for binary in ("assay", "assay-bench"):
            with self.subTest(binary=binary):
                r = self._outside("--help", binary=binary)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("reference", r.stdout)

    def test_levels_vocabulary_is_available_from_the_installed_cli(self):
        r = self._outside("levels")
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertIn("internally_consistent", payload["verifiable_here"])
        self.assertIn("maintainer_attested", payload["out_of_scope_for_this_tool"])

    def test_a_full_run_and_verify_cycle_works_outside_the_checkout(self):
        out = self.tmp / "elsewhere" / "scorecard.json"
        run = self._outside("run", "--target", "vulnerable", "--trials", "5",
                            "--out", str(out))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(out.is_file())

        verify = self._outside("verify", str(out), "--require", "run_complete")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        result = json.loads(verify.stdout)
        self.assertIn("catalog_bound", result["levels_verified"],
                      "the installed wheel must reach catalog_bound from its packaged "
                      "tasks.json, with no source checkout in sight")
        self.assertIn("run_complete", result["levels_verified"])

    def test_the_installed_verifier_rejects_a_tampered_manifest_with_exit_one(self):
        out = self.tmp / "elsewhere" / "tamper.json"
        self.assertEqual(self._outside("run", "--target", "vulnerable", "--trials", "3",
                                       "--out", str(out)).returncode, 0)
        manifest = json.loads(out.read_text())
        for finding in manifest["findings"]:
            if "canary" in finding:
                finding["canary"]["observed"] = "TAMPERED"
                break
        out.write_text(json.dumps(manifest))
        r = self._outside("verify", str(out))
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_legacy_invocations_still_work_from_the_installed_cli(self):
        out = self.tmp / "elsewhere" / "legacy.json"
        self.assertEqual(self._outside("run", "--target", "hardened", "--trials", "2",
                                       "--out", str(out)).returncode, 0)
        bare = self._outside(str(out))                      # v0.1 bare-path form
        self.assertEqual(bare.returncode, 0, bare.stderr)

        digest = self._python(
            "import assay_verifier as V; print(V.digest('ab'*32, 'o|t|0'))")
        self.assertEqual(digest.returncode, 0, digest.stderr)
        d = digest.stdout.strip()
        triple = self._outside("triple", "ab" * 32, "o", "t", "0", f"leak {d}")
        self.assertEqual(triple.returncode, 0, triple.stderr)
        self.assertIn("DIGEST PRESENT", triple.stdout)

    def test_the_version_flag_reports_the_runner_version(self):
        r = self._outside("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("assay-bench", r.stdout)


if __name__ == "__main__":
    unittest.main()
