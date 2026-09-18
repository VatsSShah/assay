"""Ed25519, checked against RFC 8032 rather than against itself.

A hand-written crypto primitive that is only tested against its own output proves nothing, so
every vector here comes from RFC 8032 §7.1. The edge cases are the ones that separate a
signature check from something that merely usually says yes: non-canonical encodings, points
that are not on the curve, small-order points, and an S value at or above the group order
(without which signatures are malleable).
"""

from __future__ import annotations

import unittest

from .helpers import ROOT
from assay_bench import ed25519 as E

#: RFC 8032 §7.1, Test 1, 2, 3 and 1024. (secret key, public key, message, signature), all hex.
RFC_8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e"
     "39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f"
     "3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67"
     "f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


class RFC8032Vectors(unittest.TestCase):
    def test_public_keys_match(self):
        for i, (sk, pk, _, _) in enumerate(RFC_8032):
            with self.subTest(vector=i):
                self.assertEqual(E.public_key(bytes.fromhex(sk)).hex(), pk)

    def test_signatures_match_byte_for_byte(self):
        """Ed25519 is deterministic, so a correct implementation reproduces the exact bytes."""
        for i, (sk, _, msg, sig) in enumerate(RFC_8032):
            with self.subTest(vector=i):
                self.assertEqual(E.sign(bytes.fromhex(sk), bytes.fromhex(msg)).hex(), sig)

    def test_every_vector_verifies(self):
        for i, (_, pk, msg, sig) in enumerate(RFC_8032):
            with self.subTest(vector=i):
                self.assertTrue(E.verify(bytes.fromhex(pk), bytes.fromhex(msg),
                                         bytes.fromhex(sig)))

    def test_a_long_message_round_trips(self):
        """The 1024-byte vector exercises the SHA-512 multi-block path."""
        sk, _ = E.generate_keypair(bytes(range(32)))
        message = bytes(range(256)) * 4
        self.assertTrue(E.verify(E.public_key(sk), message, E.sign(sk, message)))


class ItRejectsWhatItShould(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = E.generate_keypair(bytes([7]) * 32)
        self.message = b"assay witness statement"
        self.signature = E.sign(self.sk, self.message)

    def test_the_honest_case_verifies(self):
        self.assertTrue(E.verify(self.pk, self.message, self.signature))

    def test_a_changed_message_fails(self):
        self.assertFalse(E.verify(self.pk, self.message + b"!", self.signature))

    def test_a_changed_signature_fails(self):
        for index in (0, 31, 32, 63):
            flipped = bytearray(self.signature)
            flipped[index] ^= 1
            with self.subTest(byte=index):
                self.assertFalse(E.verify(self.pk, self.message, bytes(flipped)))

    def test_another_keys_signature_fails(self):
        other_sk, _ = E.generate_keypair(bytes([9]) * 32)
        self.assertFalse(E.verify(self.pk, self.message, E.sign(other_sk, self.message)))

    def test_wrong_lengths_are_refused_rather_than_padded(self):
        self.assertFalse(E.verify(self.pk[:31], self.message, self.signature))
        self.assertFalse(E.verify(self.pk, self.message, self.signature[:63]))
        self.assertFalse(E.verify(self.pk, self.message, self.signature + b"\x00"))

    def test_an_s_at_or_above_the_group_order_is_refused(self):
        """Without this check signatures are malleable: a third party can mint a variant."""
        q = 2 ** 252 + 27742317777372353535851937790883648493
        s = int.from_bytes(self.signature[32:], "little")
        malleable = self.signature[:32] + int.to_bytes(s + q, 32, "little")
        self.assertEqual(len(malleable), 64)
        self.assertFalse(E.verify(self.pk, self.message, malleable))

    def test_a_public_key_that_is_not_a_curve_point_is_refused(self):
        self.assertFalse(E.verify(b"\xff" * 32, self.message, self.signature))

    def test_a_non_canonical_y_of_one_with_the_sign_bit_set_is_refused(self):
        """y = 1 with sign 1 encodes no point; a permissive decoder waves it through."""
        bad = bytearray(32)
        bad[0] = 1
        bad[31] |= 0x80
        self.assertFalse(E.verify(bytes(bad), self.message, self.signature))

    def test_a_y_at_or_above_the_field_prime_is_refused(self):
        p = 2 ** 255 - 19
        self.assertFalse(E.verify(int.to_bytes(p, 32, "little"), self.message, self.signature))
        self.assertFalse(E.verify(int.to_bytes(p + 1, 32, "little"), self.message,
                                  self.signature))

    def test_a_malformed_secret_key_raises_rather_than_signing_something(self):
        with self.assertRaises(E.InvalidSignature):
            E.sign(b"too short", b"message")
        with self.assertRaises(E.InvalidSignature):
            E.generate_keypair(b"\x00" * 31)


class KeyHandling(unittest.TestCase):
    def test_generated_keys_differ(self):
        keys = {E.generate_keypair()[0] for _ in range(16)}
        self.assertEqual(len(keys), 16, "the key generator repeated itself")

    def test_a_key_from_the_environment_is_parsed_or_refused_clearly(self):
        import os

        os.environ["ASSAY_TEST_WITNESS_KEY"] = "ab" * 32
        self.addCleanup(os.environ.pop, "ASSAY_TEST_WITNESS_KEY", None)
        self.assertEqual(E.signing_key_from_env("ASSAY_TEST_WITNESS_KEY"), bytes([0xAB]) * 32)

        os.environ["ASSAY_TEST_WITNESS_KEY"] = "not hex"
        with self.assertRaises(E.InvalidSignature):
            E.signing_key_from_env("ASSAY_TEST_WITNESS_KEY")

        os.environ["ASSAY_TEST_WITNESS_KEY"] = "ab" * 16
        with self.assertRaisesRegex(E.InvalidSignature, "32 bytes"):
            E.signing_key_from_env("ASSAY_TEST_WITNESS_KEY")

    def test_an_absent_key_is_none_rather_than_an_error(self):
        self.assertIsNone(E.signing_key_from_env("ASSAY_DEFINITELY_NOT_SET_12345"))

    def test_no_signing_key_is_committed_to_the_repository(self):
        """A witness key in the tree would make every signature it produced worthless."""
        import re
        import subprocess

        from .helpers import require_source_checkout

        require_source_checkout(self)
        pattern = re.compile(r"ASSAY_WITNESS_KEY\s*[=:]\s*['\"]?[0-9a-fA-F]{64}")
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.split()
        offenders = [path for path in tracked
                     if pattern.search((ROOT / path).read_text(encoding="utf-8", errors="ignore"))]
        self.assertEqual(offenders, [], f"a witness signing key is committed in {offenders}")


class TheCaveatStays(unittest.TestCase):
    """A pure-Python crypto module that loses its caveat is worse than none at all."""

    def test_the_module_says_it_is_not_constant_time(self):
        doc = E.__doc__ or ""
        self.assertIn("constant-time", doc)
        self.assertIn("not", doc.lower())

    def test_it_says_where_signing_is_and_is_not_appropriate(self):
        doc = E.__doc__ or ""
        self.assertIn("Do not sign on a machine where an attacker can measure your", doc)
        self.assertIn("verification", doc.lower())


if __name__ == "__main__":
    unittest.main()
