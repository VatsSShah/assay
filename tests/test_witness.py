"""The egress witness: the only level in this repository a keyholder cannot satisfy alone.

Gap G2 is that a submitter who holds the run secret can compute a valid digest, paste it into an
invented string, and the verifier will confirm it. `tests/test_trust_boundary.py` pins that as a
*passing* test, because it is a property of self-reporting rather than a bug.

A witness changes who runs what: a party the submitter does not control mints the secret, plants
the canaries, observes egress at its own sink, and signs what it saw. The submitter never holds
the signing key, so `witnessed_egress` is the one level a fabrication cannot reach.

The tests that matter are the ones bounding the claim. A signature says the holder of a key
signed a statement. It does not say the witness is honest, or independent, or that the key
belongs to who you think — and a self-witnessed run must be visibly self-witnessed rather than
quietly counted as evidence.
"""

from __future__ import annotations

import copy
import json
import unittest

from .helpers import V, reseal
from assay_bench import ed25519, witness as W
from assay_bench.adapters.conformance import build
from assay_bench.catalog import load_catalog
from assay_bench.errors import MalformedInput, ValidationError
from assay_bench.runner import run

CATALOG = load_catalog()


def witnessed(manifest, *, signing_key=None, independent=True, fired=None, **overrides):
    """Attach a signed witness statement to a manifest and re-seal it."""
    signing_key = signing_key or ed25519.generate_keypair(bytes([3]) * 32)[0]
    statement = W.build_statement(
        run_id=manifest["provenance"]["run_id"],
        target_fingerprint=manifest["target_fingerprint"],
        task_set_digest=CATALOG.digest, benchmark_version=CATALOG.version,
        fired_task_ids=(fired if fired is not None
                        else [f["id"] for f in manifest["findings"] if f["fired"]]),
        trials_per_task=manifest["trials_per_task"],
        run_secret_commitment=manifest["run_secret_commitment"],
        witness_name="test-witness", independent=independent)
    statement.update(overrides)
    manifest = copy.deepcopy(manifest)
    manifest["witness"] = W.sign_statement(statement, signing_key)
    return reseal(manifest)


class AWitnessedRunReachesTheExtraLevel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = run(build("vulnerable"), catalog=CATALOG, trials=5, command="test")

    def test_an_unwitnessed_run_does_not_reach_it(self):
        out = V.verify_manifest(self.raw)
        self.assertNotIn("witnessed_egress", out["levels_verified"])
        self.assertIsNone(out["witness"])

    def test_a_witnessed_run_does(self):
        out = V.verify_manifest(witnessed(self.raw))
        self.assertIn("witnessed_egress", out["levels_verified"])
        self.assertEqual(out["witness"]["witness"], "test-witness")

    def test_it_is_reported_separately_from_canary_correspondence(self):
        """They rest on different evidence and must never be collapsed into one word."""
        out = V.verify_manifest(witnessed(self.raw))
        self.assertIn("canary_correspondence_verified", out["levels_verified"])
        self.assertIn("witnessed_egress", out["levels_verified"])
        self.assertNotEqual("canary_correspondence_verified", "witnessed_egress")

    def test_the_level_is_in_the_published_vocabulary(self):
        self.assertIn("witnessed_egress", V.LEVELS)


class TheSignatureActuallyBinds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = run(build("vulnerable"), catalog=CATALOG, trials=5, command="test")
        cls.signed = witnessed(cls.raw)

    def _rejects(self, mutate, pattern):
        doc = copy.deepcopy(self.signed)
        mutate(doc)
        with self.assertRaisesRegex(Exception, pattern):
            V.verify_manifest(reseal(doc))

    def test_forged_signature_bytes_are_rejected(self):
        self._rejects(lambda d: d["witness"]["signature"].update(value="00" * 64),
                      "does not verify")

    def test_editing_the_statement_after_signing_is_rejected(self):
        self._rejects(lambda d: d["witness"].update(fired_task_ids=["M1"]), "does not verify")

    def test_renaming_the_witness_after_signing_is_rejected(self):
        self._rejects(lambda d: d["witness"].update(witness="a-more-impressive-name"),
                      "does not verify")

    def test_flipping_independent_after_signing_is_rejected(self):
        """The most tempting single-field edit, so it must be inside the signed bytes."""
        doc = copy.deepcopy(self.signed)
        doc["witness"]["independent"] = not doc["witness"]["independent"]
        with self.assertRaisesRegex(Exception, "does not verify"):
            V.verify_manifest(reseal(doc))

    def test_a_signature_from_a_different_key_over_the_same_statement_is_still_bound(self):
        """Re-signing is allowed -- it just names a different witness, which the output shows."""
        other_key, other_public = ed25519.generate_keypair(bytes([5]) * 32)
        doc = copy.deepcopy(self.signed)
        body = {k: v for k, v in doc["witness"].items() if k != "signature"}
        doc["witness"] = W.sign_statement(body, other_key)
        out = V.verify_manifest(reseal(doc))
        self.assertEqual(out["witness"]["public_key"], other_public.hex())

    def test_an_unknown_algorithm_is_refused_rather_than_ignored(self):
        self._rejects(lambda d: d["witness"]["signature"].update(algorithm="trust-me"),
                      "unsupported signature algorithm")

    def test_a_non_hex_signature_is_malformed(self):
        self._rejects(lambda d: d["witness"]["signature"].update(value="zz" * 64),
                      "hexadecimal")

    def test_an_unknown_schema_is_refused(self):
        self._rejects(lambda d: d["witness"].update(schema="assay/witness-statement/99"),
                      "unsupported witness schema")

    def test_the_domain_tag_stops_a_signature_being_reused_elsewhere(self):
        statement = {k: v for k, v in self.signed["witness"].items() if k != "signature"}
        self.assertTrue(W.statement_bytes(statement).startswith(W.DOMAIN))

    def test_signing_is_over_a_canonical_rendering_not_the_object(self):
        """A verifier that re-serialises differently must still check the same bytes."""
        statement = {k: v for k, v in self.signed["witness"].items() if k != "signature"}
        shuffled = dict(reversed(list(statement.items())))
        self.assertEqual(W.statement_bytes(statement), W.statement_bytes(shuffled))


class ADisagreeingWitnessFailsTheDocument(unittest.TestCase):
    """Attaching a witness must never be strictly safe for a dishonest submitter."""

    @classmethod
    def setUpClass(cls):
        cls.raw = run(build("vulnerable"), catalog=CATALOG, trials=5, command="test")

    def test_under_reporting_is_caught_by_the_witness(self):
        """The failure the fixed denominator could make unprofitable but never detectable.

        The fabrication here is a competent one: the finding is flipped, its proof removed, and
        the scores restated so the document is internally coherent. Every offline level still
        passes -- that is the point of the trust boundary. Only the witness, which saw the
        egress the manifest denies, catches it.
        """
        from .helpers import rescore

        hidden = copy.deepcopy(self.raw)
        for finding in hidden["findings"]:
            if finding["id"] == "M1":
                finding["fired"] = False
                finding["asr"] = 0.0
                finding.pop("canary", None)
        hidden = rescore(hidden)
        # Without a witness it verifies, which is exactly gap G2.
        self.assertIn("internally_consistent",
                      V.verify_manifest(hidden)["levels_verified"])

        signed = witnessed(hidden, fired=[f["id"] for f in self.raw["findings"] if f["fired"]])
        with self.assertRaisesRegex(Exception, "under-reported"):
            V.verify_manifest(signed)

    def test_over_reporting_is_caught_too(self):
        signed = witnessed(self.raw, fired=["M2"])
        with self.assertRaisesRegex(Exception, "over-reported"):
            V.verify_manifest(signed)

    def test_a_witness_for_a_different_run_is_caught(self):
        signed = witnessed(self.raw)
        body = {k: v for k, v in signed["witness"].items() if k != "signature"}
        body["run_id"] = "00000000-0000-4000-8000-000000000000"
        signed["witness"] = W.sign_statement(body, ed25519.generate_keypair(bytes([3]) * 32)[0])
        with self.assertRaisesRegex(Exception, "run_id"):
            V.verify_manifest(reseal(signed))

    def test_a_witness_for_a_different_target_is_caught(self):
        signed = witnessed(self.raw)
        body = {k: v for k, v in signed["witness"].items() if k != "signature"}
        body["target_fingerprint"] = "deadbeefdeadbeef"
        signed["witness"] = W.sign_statement(body, ed25519.generate_keypair(bytes([3]) * 32)[0])
        with self.assertRaisesRegex(Exception, "target_fingerprint"):
            V.verify_manifest(reseal(signed))

    def test_a_witness_that_committed_to_a_different_secret_is_caught(self):
        signed = witnessed(self.raw)
        body = {k: v for k, v in signed["witness"].items() if k != "signature"}
        body["run_secret_commitment"] = "00" * 32
        signed["witness"] = W.sign_statement(body, ed25519.generate_keypair(bytes([3]) * 32)[0])
        with self.assertRaisesRegex(Exception, "different secret"):
            V.verify_manifest(reseal(signed))

    def test_an_honest_manifest_and_witness_agree(self):
        self.assertEqual(W.agrees_with_manifest(witnessed(self.raw)["witness"], self.raw), [])


class TheClaimIsBounded(unittest.TestCase):
    """What a signature says, and the four things it does not."""

    @classmethod
    def setUpClass(cls):
        cls.raw = run(build("vulnerable"), catalog=CATALOG, trials=5, command="test")

    def test_a_self_witnessed_run_is_visibly_self_witnessed(self):
        out = V.verify_manifest(witnessed(self.raw, independent=False))
        self.assertIn("witnessed_egress", out["levels_verified"])
        self.assertFalse(out["witness"]["independent"],
                         "a run the submitter witnessed for itself must say so")

    def test_the_result_states_what_it_does_not_establish(self):
        out = V.verify_manifest(witnessed(self.raw))
        limits = out["witness"]["does_not_establish"].lower()
        for phrase in ("honest", "independent", "belongs to who you think"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, limits)

    def test_the_statement_carries_its_own_scope_text(self):
        signed = witnessed(self.raw)
        scope = signed["witness"]["scope"].lower()
        self.assertIn("does not establish", scope)
        self.assertIn("key custody", scope)

    def test_independence_is_a_declaration_and_the_module_says_so(self):
        self.assertIn("declaration and not a proof", W.__doc__ or "")

    def test_pinning_a_key_rejects_a_statement_from_another_witness(self):
        signed = witnessed(self.raw)
        real = signed["witness"]["signature"]["public_key"]
        W.verify_statement(signed["witness"], expect_public_key=real)
        with self.assertRaisesRegex(ValidationError, "not by the pinned key"):
            W.verify_statement(signed["witness"], expect_public_key="ab" * 32)

    def test_an_unpinned_verification_says_only_that_some_keyholder_signed(self):
        out = W.verify_statement(witnessed(self.raw)["witness"])
        self.assertFalse(out["pinned"])
        self.assertIn("the holder of this key", out["establishes"])


class MalformedStatementsAreRefused(unittest.TestCase):
    def test_a_statement_that_is_not_an_object(self):
        with self.assertRaises(MalformedInput):
            W.verify_statement(["not", "an", "object"])

    def test_a_statement_missing_a_required_field(self):
        raw = run(build("hardened"), catalog=CATALOG, trials=5, command="test")
        statement = witnessed(raw)["witness"]
        for field in ("schema", "witness", "run_id", "target_fingerprint", "fired_task_ids",
                      "signature"):
            broken = {k: v for k, v in statement.items() if k != field}
            with self.subTest(missing=field):
                with self.assertRaises(MalformedInput):
                    W.verify_statement(broken)

    def test_a_statement_with_no_witness_name_cannot_be_built(self):
        with self.assertRaisesRegex(ValidationError, "must name the witness"):
            W.build_statement(run_id="r", target_fingerprint="f", task_set_digest="d",
                              benchmark_version="0.1", fired_task_ids=[], trials_per_task=5,
                              run_secret_commitment="c", witness_name="", independent=True)

    def test_fired_task_ids_must_be_an_array(self):
        with self.assertRaises(MalformedInput):
            W.build_statement(run_id="r", target_fingerprint="f", task_set_digest="d",
                              benchmark_version="0.1", fired_task_ids="M1", trials_per_task=5,
                              run_secret_commitment="c", witness_name="w", independent=True)


class TheTrustBoundaryStillHoldsWithoutAWitness(unittest.TestCase):
    """The G2 fabrication must still succeed at the levels it always did -- and stop short."""

    def test_a_fabrication_reaches_run_complete_but_not_witnessed_egress(self):
        from .helpers import synthetic_manifest

        fabricated = synthetic_manifest()
        out = V.verify_manifest(fabricated)
        self.assertIn("internally_consistent", out["levels_verified"])
        self.assertNotIn("witnessed_egress", out["levels_verified"],
                         "a document a keyholder wrote alone reached the witnessed level")


if __name__ == "__main__":
    unittest.main()
