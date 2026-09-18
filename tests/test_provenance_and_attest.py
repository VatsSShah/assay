"""Target fingerprinting, provenance hygiene, and maintainer attestation."""

from __future__ import annotations

import copy
import json
import unittest

from .helpers import ROOT
from assay_bench import attest, provenance
from assay_bench.adapters import Capabilities
from assay_bench.adapters.conformance import build
from assay_bench.catalog import load_catalog
from assay_bench.errors import MalformedInput, ValidationError
from assay_bench.runner import run

CATALOG = load_catalog()


class _Stub:
    name, version, kind = "stub", "1.0", "test"

    def __init__(self, **caps):
        self._caps = Capabilities(**caps)
        self._material = {"x": 1}

    def capabilities(self):
        return self._caps

    def reset(self):
        pass

    def fingerprint_material(self):
        return self._material

    def run_episode(self, episode):  # pragma: no cover - not exercised here
        raise NotImplementedError


class Fingerprint(unittest.TestCase):
    def test_stable_across_repeated_construction(self):
        a = provenance.target_fingerprint(build("vulnerable"), CATALOG)
        b = provenance.target_fingerprint(build("vulnerable"), CATALOG)
        self.assertEqual(a, b)

    def test_distinct_targets_fingerprint_differently(self):
        prints = {provenance.target_fingerprint(build(n), CATALOG)
                  for n in ("vulnerable", "hardened", "mixed")}
        self.assertEqual(len(prints), 3)

    def test_sensitive_to_every_contributing_field(self):
        base = _Stub(transport="in-process", is_real_target=False)
        original = provenance.target_fingerprint(base, CATALOG)

        changed_transport = _Stub(transport="stdio", is_real_target=False)
        self.assertNotEqual(provenance.target_fingerprint(changed_transport, CATALOG), original)

        changed_real = _Stub(transport="in-process", is_real_target=True)
        self.assertNotEqual(provenance.target_fingerprint(changed_real, CATALOG), original)

        changed_caps = _Stub(transport="in-process", is_real_target=False,
                             emits_network_egress=True)
        self.assertNotEqual(provenance.target_fingerprint(changed_caps, CATALOG), original)

        changed_material = _Stub(transport="in-process", is_real_target=False)
        changed_material._material = {"x": 2}
        self.assertNotEqual(provenance.target_fingerprint(changed_material, CATALOG), original)

        changed_version = _Stub(transport="in-process", is_real_target=False)
        changed_version.version = "2.0"
        self.assertNotEqual(provenance.target_fingerprint(changed_version, CATALOG), original)

    def test_sensitive_to_the_task_set(self):
        class Fork:
            pass
        forked = copy.deepcopy(CATALOG)
        forked.digest = "0" * 64
        self.assertNotEqual(provenance.target_fingerprint(build("vulnerable"), forked),
                            provenance.target_fingerprint(build("vulnerable"), CATALOG))

    def test_the_preimage_is_published_so_anyone_can_recompute_it(self):
        import hashlib
        m = run(build("hardened"), catalog=CATALOG, trials=1, command="t")
        material = m["provenance"]["target_fingerprint_material"]
        blob = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(hashlib.sha256(blob.encode()).hexdigest()[:16],
                         m["target_fingerprint"])


class ProvenanceHygiene(unittest.TestCase):
    def test_no_secret_or_host_detail_leaks_into_provenance(self):
        m = run(build("vulnerable"), catalog=CATALOG, trials=2, run_secret="4d" * 32,
                command="assay run --target vulnerable")
        blob = json.dumps(m["provenance"])
        self.assertNotIn("4d" * 32, blob, "the run secret must never appear in provenance")
        for leak in ("/home/", "/root/", "HOME", "USER", "PATH="):
            self.assertNotIn(leak, blob, f"provenance leaked {leak!r}")

    def test_provenance_records_what_a_reader_needs(self):
        m = run(build("mixed"), catalog=CATALOG, trials=2, command="t")
        p = m["provenance"]
        for key in ("run_id", "benchmark_version", "task_set_digest", "runner_version",
                    "manifest_format", "adapter", "target_is_real", "transport",
                    "started_at", "ended_at", "trials_per_task", "tasks_planned",
                    "tasks_completed", "timeouts", "errors", "completion",
                    "deterministic_target"):
            self.assertIn(key, p)
        self.assertIs(p["target_is_real"], False)
        self.assertIs(p["deterministic_target"], True)

    def test_the_task_set_digest_in_provenance_matches_the_catalog(self):
        m = run(build("hardened"), catalog=CATALOG, trials=1, command="t")
        self.assertEqual(m["provenance"]["task_set_digest"], CATALOG.digest)


class Attestation(unittest.TestCase):
    def _pair(self, a="vulnerable", b="vulnerable"):
        return (run(build(a), catalog=CATALOG, trials=2, command="t"),
                run(build(b), catalog=CATALOG, trials=2, command="t"))

    def test_a_rerun_with_a_fresh_secret_still_matches(self):
        submitted, rerun = self._pair()
        self.assertNotEqual(submitted["run_secret_reveal"], rerun["run_secret_reveal"])
        self.assertEqual(attest.compare(submitted, rerun)["status"], attest.STATUS_MATCH)

    def test_a_different_target_diverges(self):
        submitted, rerun = self._pair("vulnerable", "hardened")
        result = attest.compare(submitted, rerun)
        self.assertEqual(result["status"], attest.STATUS_DIVERGED)
        self.assertTrue(any("target_fingerprint" in d for d in result["differences"]))

    def test_a_single_flipped_task_is_reported_per_task(self):
        submitted, rerun = self._pair()
        rerun["findings"][0]["fired"] = False
        rerun["findings"][0]["asr"] = 0.0
        result = attest.compare(submitted, rerun)
        self.assertEqual(result["status"], attest.STATUS_DIVERGED)
        self.assertTrue(any(d.startswith("M1:") for d in result["differences"]))

    def test_a_failed_rerun_is_its_own_status(self):
        submitted, _ = self._pair()
        record = attest.build(submitted=submitted, rerun=None, maintainer="m@example",
                              code_commit=None, failure="target unreachable")
        self.assertEqual(record["status"], attest.STATUS_FAILED)
        self.assertIn("target unreachable", record["differences"][0])

    def test_an_attestation_must_name_a_maintainer(self):
        submitted, rerun = self._pair()
        with self.assertRaises(ValidationError):
            attest.build(submitted=submitted, rerun=rerun, maintainer="", code_commit=None)

    def test_attestations_validate_and_reject_unknown_schemas(self):
        submitted, rerun = self._pair()
        record = attest.build(submitted=submitted, rerun=rerun, maintainer="m@example",
                              code_commit="abc")
        attest.validate(record)
        record["schema"] = "assay/attestation/99"
        with self.assertRaises(ValidationError):
            attest.validate(record)
        with self.assertRaises(MalformedInput):
            attest.validate({"schema": attest.SCHEMA})

    def test_attestation_records_whether_the_target_was_real(self):
        submitted, rerun = self._pair()
        record = attest.build(submitted=submitted, rerun=rerun, maintainer="m@example",
                              code_commit=None)
        self.assertIs(record["target_is_real"], False)

    def test_invariants_ignore_the_fields_that_must_change(self):
        submitted, rerun = self._pair()
        for field in ("run_secret_reveal", "integrity_hash", "generated_at"):
            self.assertNotEqual(submitted[field], rerun[field])
        self.assertEqual(attest.invariants_digest(submitted), attest.invariants_digest(rerun))


if __name__ == "__main__":
    unittest.main()
