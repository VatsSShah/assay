"""Canary minting: envelopes, determinism, and the parity with the shipped verifier."""

from __future__ import annotations

import unittest

from .helpers import V
from assay_bench import canary as C
from assay_bench.errors import ValidationError

SECRET = "3e" * 32


class Minting(unittest.TestCase):
    def test_every_envelope_family_carries_a_detectable_digest(self):
        """A canary the oracle cannot see is a silent 100% false negative, so minting
        self-checks rather than discovering it as a 'resistant' target."""
        seen = set()
        for i in range(200):
            tid = f"T{i}"
            c = C.plant(SECRET, tid, f"assay/{tid}", "tool", 0)
            C.self_check(c, SECRET)
            seen.add(c["envelope"])
            self.assertTrue(C.detects(c["digest"], c["value"]), c)
        self.assertEqual(seen, set(C.ENVELOPES), "all five envelope shapes must occur")

    def test_envelope_choice_is_deterministic_per_secret_and_task(self):
        a = C.choose_envelope(SECRET, "M7")
        b = C.choose_envelope(SECRET, "M7")
        self.assertEqual(a, b)

    def test_envelope_choice_rotates_with_the_run_secret(self):
        choices_a = [C.choose_envelope("aa" * 32, f"M{i}") for i in range(1, 32)]
        choices_b = [C.choose_envelope("bb" * 32, f"M{i}") for i in range(1, 32)]
        self.assertNotEqual(choices_a, choices_b, "a fixed shape would be a sentinel")

    def test_the_value_carries_no_fixed_benchmark_sentinel(self):
        values = [C.plant(SECRET, f"T{i}", "o", "t", 0)["value"] for i in range(50)]
        for marker in ("assay", "ASSAY", "canary", "CANARY", "benchmark"):
            self.assertFalse(any(marker in v for v in values),
                             f"minted values must not contain the marker {marker!r}")

    def test_self_check_rejects_an_envelope_that_lost_its_digest(self):
        c = C.plant(SECRET, "M1", "o", "t", 0)
        c["value"] = "sk-nothing-useful-here"
        with self.assertRaisesRegex(ValidationError, "silent false negative"):
            C.self_check(c, SECRET)

    def test_self_check_rejects_a_digest_that_does_not_recompute(self):
        c = C.plant(SECRET, "M1", "o", "t", 0)
        c["origin"] = "different"
        with self.assertRaisesRegex(ValidationError, "does not recompute"):
            C.self_check(c, SECRET)

    def test_distinct_steps_produce_distinct_digests(self):
        digests = {C.plant(SECRET, "M1", "o", "t", step)["digest"] for step in range(50)}
        self.assertEqual(len(digests), 50, "per-trial canaries must not collide")

    def test_filler_never_reveals_the_secret(self):
        value = C.plant(SECRET, "M1", "o", "t", 0)["value"]
        self.assertNotIn(SECRET, value)
        self.assertNotIn(SECRET[:32], value)


class SecretHandling(unittest.TestCase):
    def test_a_fresh_secret_is_32_bytes(self):
        s = C.new_run_secret()
        self.assertEqual(len(s), 64)
        self.assertEqual(len(C.parse_secret(s)), 32)

    def test_two_fresh_secrets_differ(self):
        self.assertNotEqual(C.new_run_secret(), C.new_run_secret())

    def test_wrong_length_and_non_hex_secrets_are_rejected(self):
        for bad in ("ab" * 16, "ab" * 64, "zz" * 32, "", "abc"):
            with self.subTest(secret=bad[:10]):
                with self.assertRaises(ValidationError):
                    C.parse_secret(bad)

    def test_commitment_binds_and_is_not_invertible_by_inspection(self):
        s = C.new_run_secret()
        self.assertEqual(len(C.commitment(s)), 64)
        self.assertNotEqual(C.commitment(s), C.commitment(C.new_run_secret()))


class ParityWithTheShippedVerifier(unittest.TestCase):
    """The runner and the standalone verifier implement the oracle separately so the
    verifier can be a single file. They must agree on every input."""

    def test_digest_parity(self):
        for step in range(25):
            pre = f"assay/M{step}|tool|{step}"
            self.assertEqual(C.digest(SECRET, pre), V.digest(SECRET, pre))

    def test_forms_parity(self):
        for step in range(25):
            d = C.digest(SECRET, f"o|t|{step}")
            self.assertEqual(C.forms(d), V.forms(d))

    def test_verify_triple_parity_over_minted_canaries(self):
        for i in range(100):
            tid = f"T{i}"
            c = C.plant(SECRET, tid, f"assay/{tid}", "tool", i % 7)
            egress = f"POST /x body={c['value']}"
            self.assertEqual(
                C.verify_triple(SECRET, c["origin"], c["tool"], c["step"], egress),
                V.verify_triple(SECRET, c["origin"], c["tool"], c["step"], egress))

    def test_commitment_parity(self):
        for _ in range(20):
            s = C.new_run_secret()
            self.assertEqual(C.commitment(s), V.commitment(s))


if __name__ == "__main__":
    unittest.main()
