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

from .helpers import ROOT, is_source_checkout

BUILD_TIMEOUT = 300


def _can_build() -> tuple[bool, str]:
    if not is_source_checkout():
        return False, ("checkout-only: this tree was unpacked from an sdist, and rebuilding a "
                       "distribution from a distribution is not what this suite checks")
    try:
        import setuptools  # noqa: F401
        import wheel  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        return False, f"no offline build backend available: {exc}"
    return True, ""


#: An environment with PYTHONPATH and ASSAY_TASKS removed.
#:
#: This is not hygiene, it is correctness. `src/` contains `assay_bench.egg-info`, so with
#: `PYTHONPATH=src` pip sees assay_bench 0.2.0 already on the path, reports "requirement already
#: satisfied", installs NOTHING and exits 0. Every test here then failed with
#: ModuleNotFoundError against a venv that looked successfully populated. CI sets PYTHONPATH=src
#: globally, which is why this only ever broke there.
def _clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "ASSAY_TASKS")}


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
                              capture_output=True, text=True, timeout=BUILD_TIMEOUT,
                              env=_clean_env())
        if venv.returncode != 0:  # pragma: no cover
            raise unittest.SkipTest(f"venv creation failed: {venv.stderr}")
        python = cls.venv / "bin" / "python"

        out = cls.tmp / "dist"
        out.mkdir()
        build = subprocess.run(
            [str(python), "-c",
             "import sys, setuptools.build_meta as b; print(b.build_wheel(sys.argv[1]))",
             str(out)],
            cwd=ROOT, capture_output=True, text=True, timeout=BUILD_TIMEOUT,
            env=_clean_env())
        if build.returncode != 0:  # pragma: no cover - environment dependent
            raise unittest.SkipTest(f"wheel build failed:\n{build.stdout}\n{build.stderr}")
        wheels = sorted(out.glob("*.whl"))
        if not wheels:  # pragma: no cover
            raise unittest.SkipTest("build produced no wheel")
        cls.wheel_path = wheels[0]
        cls.build_output = build.stdout + build.stderr

        sdist = subprocess.run(
            [str(python), "-c",
             "import sys, setuptools.build_meta as b; print(b.build_sdist(sys.argv[1]))",
             str(out)],
            cwd=ROOT, capture_output=True, text=True, timeout=BUILD_TIMEOUT,
            env=_clean_env())
        cls.sdist_path = next(iter(sorted(out.glob("*.tar.gz"))), None) if sdist.returncode == 0 else None

        pip = cls.venv / "bin" / "pip"
        install = subprocess.run(
            [str(pip), "install", "--no-index", "--no-build-isolation", str(cls.wheel_path)],
            capture_output=True, text=True, timeout=BUILD_TIMEOUT, env=_clean_env())
        if install.returncode != 0:  # pragma: no cover
            raise unittest.SkipTest(f"wheel install failed:\n{install.stdout}\n{install.stderr}")
        # An install that exits 0 having done nothing is the failure mode this suite exists to
        # catch, so check the artefact rather than the exit code.
        if not (cls.venv / "bin" / "assay").exists():  # pragma: no cover
            raise AssertionError(
                f"pip exited 0 but installed no console script. Output:\n{install.stdout}\n"
                f"{install.stderr}")

    @classmethod
    def tearDownClass(cls):
        if cls.tmp:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- helpers ------------------------------------------------------------------
    def _outside(self, *args, binary="assay"):
        """Run an installed console script from a directory that is NOT the checkout."""
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        env = _clean_env()
        return subprocess.run([str(self.venv / "bin" / binary), *args],
                              cwd=elsewhere, capture_output=True, text=True, env=env,
                              timeout=BUILD_TIMEOUT)

    def _python(self, code):
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        env = _clean_env()
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
                         "assay_bench/adapters/conformance.py",
                         "assay_bench/validity.py"):
            with self.subTest(member=expected):
                self.assertIn(expected, names)

    def test_the_wheel_carries_every_subpackage_in_the_source_tree(self):
        """A hand-kept package list silently drops new subpackages.

        `packages` used to be a literal list, and `assay_bench.mcp` and `assay_bench.servers`
        were simply missing from the wheel: an installed copy could not run against a real MCP
        server at all while the source checkout could, and nothing failed until someone
        installed the wheel and reached for the feature. Derived from the tree rather than
        listed, so a new subpackage cannot be forgotten.
        """
        source = ROOT / "src" / "assay_bench"
        expected = {f"assay_bench/{path.parent.relative_to(source)}/__init__.py".replace(
                        "assay_bench/./", "assay_bench/")
                    for path in source.rglob("__init__.py")}
        names = set(zipfile.ZipFile(self.wheel_path).namelist())
        missing = sorted(name for name in expected if name not in names)
        self.assertEqual(missing, [], f"the wheel is missing subpackages: {missing}")

    def test_every_module_in_the_source_tree_ships(self):
        """Not just packages: a module added to an existing package must travel too."""
        source = ROOT / "src" / "assay_bench"
        expected = {f"assay_bench/{path.relative_to(source)}"
                    for path in source.rglob("*.py")}
        names = set(zipfile.ZipFile(self.wheel_path).namelist())
        missing = sorted(name for name in expected if name not in names)
        self.assertEqual(missing, [], f"the wheel is missing modules: {missing}")

    def test_the_installed_package_can_reach_a_real_mcp_server(self):
        """The end-to-end shape of the bug: the feature must work from the wheel, not just src."""
        r = self._python(
            "from assay_bench.mcp.server import HttpMCPServer; "
            "from assay_bench.servers.reference import build_server; "
            "from assay_bench.adapters.mcp_probe import build; "
            "adapter, stop = build('insecure'); "
            "print(adapter.fingerprint_material()['remote']['server_name']); "
            "stop()")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "assay-reference-insecure")

    def test_the_build_emits_no_deprecation_warning(self):
        """The old `license = {file = ...}` table made setuptools warn on every build."""
        lowered = self.build_output.lower()
        for phrase in ("deprecated", "setuptoolsdeprecationwarning", "will be removed"):
            self.assertNotIn(phrase, lowered,
                             f"build emitted a deprecation notice:\n{self.build_output[-800:]}")

    def test_the_wheel_declares_an_spdx_license(self):
        import zipfile
        metadata = zipfile.ZipFile(self.wheel_path).read(
            f"assay_bench-{self._version()}.dist-info/METADATA").decode()
        self.assertIn("License-Expression: MIT", metadata)
        self.assertIn("License-File: LICENSE", metadata)

    def test_an_sdist_builds_and_carries_what_a_rebuild_needs(self):
        if self.sdist_path is None:  # pragma: no cover - environment dependent
            self.skipTest("sdist build not available in this environment")
        import tarfile
        with tarfile.open(self.sdist_path) as tar:
            names = {n.split("/", 1)[1] for n in tar.getnames() if "/" in n}
        for expected in ("pyproject.toml", "tasks.json", "manifest_schema.json", "LICENSE",
                         "README.md", "src/assay_verifier.py",
                         "src/assay_bench/runner.py", "src/assay_bench/data/tasks.json",
                         "tests/test_verifier.py", "leaderboard/build_site.py"):
            with self.subTest(member=expected):
                self.assertIn(expected, names)
        # The recording binaries must never travel in a distribution.
        self.assertFalse([n for n in names if n.endswith((".webm", ".mp4", ".jpg"))])

    def test_wheel_ships_the_published_schema(self):
        import zipfile
        self.assertIn("assay_bench/data/manifest_schema.json",
                      zipfile.ZipFile(self.wheel_path).namelist())

    @classmethod
    def _version(cls):
        import tomllib
        with open(ROOT / "pyproject.toml", "rb") as fh:
            return tomllib.load(fh)["project"]["version"]

    def test_wheel_ships_the_frozen_task_set(self):
        names = zipfile.ZipFile(self.wheel_path).namelist()
        self.assertIn("assay_bench/data/tasks.json", names,
                      "without the packaged catalog an installed verifier cannot reach "
                      "catalog_bound")

    def test_the_packaged_task_set_is_byte_identical_to_the_canonical_one(self):
        packaged = zipfile.ZipFile(self.wheel_path).read("assay_bench/data/tasks.json")
        self.assertEqual(packaged, (ROOT / "tasks.json").read_bytes())

    # -- imports and CLIs from outside the checkout -------------------------------
    def test_nothing_is_importable_from_the_repository_root(self):
        """The src/ layout exists so a passing test cannot be an accident of cwd."""
        for name in ("assay_verifier", "scoring", "badge", "assay_bench"):
            with self.subTest(module=name):
                self.assertFalse((ROOT / f"{name}.py").exists())
                self.assertFalse((ROOT / name).is_dir())

    def test_imports_work_outside_the_checkout(self):
        r = self._python(
            "import assay_verifier, scoring, badge, assay_bench, assay_bench.cli, "
            "assay_bench.runner, assay_bench.precommit, assay_bench.attest, "
            "assay_bench.validity, assay_bench.media, assay_bench.twins, "
            "assay_bench.diagnostics, assay_bench.contamination, assay_bench.mcp.client, "
            "assay_bench.mcp.server, assay_bench.servers.reference, "
            "assay_bench.adapters.mcp_probe; "
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
