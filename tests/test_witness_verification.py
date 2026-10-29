"""Per-observation witness receipts: what a verifier holding only the public key can check.

The run-level witness statement (``tests/test_witness.py``) answers "did a key the submitter does
not hold sign this?". These tests are about the per-observation protocol that lets a separate
party hold that key: the sink signs a receipt each time a registered canary arrives, and anyone
with the public key can check it.

The tests that matter are the rejections. A receipt verifier that says yes to a flipped byte, an
unpinned key, a different trial, a stale or future-dated receipt, or the same receipt twice is
worse than none, because it turns a copied file into "independent evidence". So each of those
has its own test, and the operator's verification path is run with signing made impossible.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from . import helpers  # noqa: F401  (puts src on sys.path)
from assay_bench import canary, ed25519
from assay_bench import witness_receipt as WR
from assay_bench.errors import MalformedInput, UsageError, ValidationError

KEY = ed25519.generate_keypair(bytes([7]) * 32)[0]
PUB = ed25519.public_key(KEY).hex()
OTHER_KEY = ed25519.generate_keypair(bytes([9]) * 32)[0]
OTHER_PUB = ed25519.public_key(OTHER_KEY).hex()

T0 = datetime(2026, 10, 29, 10, 0, 0, tzinfo=timezone.utc)
EXP = "exp-20261029-0a1b2c3d"
TRIAL = "6f1c0d2e-0000-4000-8000-000000000001:M3:0"
CANARY = "0123456789abcdef"
TRUSTED = {"schema": WR.TRUSTED_KEYS_SCHEMA,
           "keys": [{"name": "test-witness", "public_key": PUB, "independent": True}]}


def make(*, key=KEY, sign=True, **overrides):
    fields = dict(experiment_id=EXP, trial_id=TRIAL, canary_id=CANARY,
                  witness_name="test-witness", public_key=ed25519.public_key(key).hex(),
                  independent=True, sink="/egress/post_status",
                  payload=b'{"token":"REF-0123456789abcdef"}', sequence=0, observed_at=T0)
    fields.update(overrides)
    receipt = WR.build_receipt(**fields)
    return WR.sign_receipt(receipt, key) if sign else receipt


def verify(receipt, **kwargs):
    kwargs.setdefault("trusted_keys", TRUSTED)
    kwargs.setdefault("now", T0 + timedelta(seconds=30))
    return WR.verify_receipt(receipt, **kwargs)


def failed(result):
    return [c["name"] for c in result["checks"] if not c["ok"]]


def resign(receipt, key=KEY):
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return WR.sign_receipt(body, key)


class ASignedReceiptVerifies(unittest.TestCase):
    def test_a_correct_receipt_passes_every_check(self):
        result = verify(make(), expect_experiment_id=EXP, expect_trial_id=TRIAL,
                        expect_canary_id=CANARY, max_age_seconds=600)
        self.assertTrue(result["ok"], failed(result))
        names = {c["name"] for c in result["checks"]}
        self.assertEqual(names, {"format", "signature", "trusted_key", "experiment_id",
                                 "trial_id", "canary", "freshness"})

    def test_the_result_says_what_it_does_not_establish(self):
        result = verify(make())
        self.assertIn("independent", result["does_not_establish"])
        self.assertIn("decided", result["does_not_establish"])

    def test_signed_bytes_are_domain_separated(self):
        self.assertTrue(WR.receipt_bytes(make()).startswith(b"assay/witness-receipt/1\x00"))
        self.assertNotEqual(WR.DOMAIN, b"assay/witness-statement/1\x00")

    def test_unchecked_expectations_are_reported_as_not_checked(self):
        result = verify(make())
        by_name = {c["name"]: c for c in result["checks"]}
        self.assertFalse(by_name["trial_id"]["checked"])
        self.assertIn("not checked", by_name["trial_id"]["detail"])


class TheSignatureBinds(unittest.TestCase):
    def test_a_flipped_signature_byte_is_rejected(self):
        receipt = make()
        value = bytearray(bytes.fromhex(receipt["signature"]["value"]))
        value[5] ^= 0x01
        receipt["signature"]["value"] = value.hex()
        self.assertIn("signature", failed(verify(receipt)))

    def test_a_flipped_payload_hash_is_rejected(self):
        receipt = make()
        h = receipt["payload_sha256"]
        receipt["payload_sha256"] = ("0" if h[0] != "0" else "1") + h[1:]
        self.assertEqual(failed(verify(receipt)), ["signature"])

    def test_flipping_independent_after_signing_is_rejected(self):
        receipt = make()
        receipt["witness"]["independent"] = False
        self.assertIn("signature", failed(verify(receipt)))

    def test_relabelling_the_signature_version_is_rejected(self):
        receipt = make()
        receipt["signature"]["version"] = 2
        self.assertIn("format", failed(verify(receipt)))
        self.assertIn("signature", failed(verify(receipt)))

    def test_a_signature_block_naming_another_key_is_rejected(self):
        receipt = make()
        receipt["signature"]["public_key"] = OTHER_PUB
        self.assertIn("signature", failed(verify(receipt, trusted_keys=[PUB, OTHER_PUB])))

    def test_signing_refuses_a_receipt_that_names_a_different_key(self):
        body = make(sign=False)
        with self.assertRaisesRegex(ValidationError, "different witness key"):
            WR.sign_receipt(body, OTHER_KEY)


class WhichKeySigned(unittest.TestCase):
    def test_an_incorrect_pinned_public_key_is_rejected(self):
        result = verify(make(), trusted_keys=None, expect_public_key=OTHER_PUB)
        self.assertEqual(failed(result), ["trusted_key"])

    def test_a_correct_pinned_key_without_a_trust_file_passes(self):
        self.assertTrue(verify(make(), trusted_keys=None, expect_public_key=PUB.upper())["ok"])

    def test_a_key_not_in_the_trusted_set_is_rejected(self):
        """A validly-signed receipt from an unknown key: anyone can mint a key and sign."""
        receipt = make(key=OTHER_KEY)
        result = verify(receipt)
        self.assertEqual(failed(result), ["trusted_key"])
        self.assertIn("not in the trusted set", result["checks"][2]["detail"])

    def test_no_trust_anchor_fails_closed(self):
        result = verify(make(), trusted_keys=None)
        self.assertEqual(failed(result), ["trusted_key"])

    def test_a_pin_and_a_trust_file_must_both_agree(self):
        result = verify(make(), expect_public_key=OTHER_PUB)
        self.assertEqual(failed(result), ["trusted_key"])

    def test_declared_independence_the_trust_file_does_not_grant_is_flagged(self):
        trusted = copy.deepcopy(TRUSTED)
        trusted["keys"][0]["independent"] = False
        result = verify(make(), trusted_keys=trusted)
        self.assertTrue(result["ok"])
        self.assertTrue(result["independent_declared"])
        self.assertFalse(result["independent_granted_by_trust_file"])
        self.assertTrue(any("independent" in w for w in result["warnings"]))


class WhatTheReceiptIsAbout(unittest.TestCase):
    def test_an_incorrect_experiment_id_is_rejected(self):
        self.assertEqual(failed(verify(make(), expect_experiment_id="exp-20261029-ffffffff")),
                         ["experiment_id"])

    def test_an_incorrect_trial_id_is_rejected(self):
        self.assertEqual(failed(verify(make(), expect_trial_id=TRIAL.replace(":0", ":1"))),
                         ["trial_id"])

    def test_an_incorrect_canary_is_rejected(self):
        self.assertEqual(failed(verify(make(), expect_canary_id="fedcba9876543210")), ["canary"])

    def test_the_canary_comparison_ignores_hex_case(self):
        self.assertTrue(verify(make(), expect_canary_id=CANARY.upper())["ok"])


class Freshness(unittest.TestCase):
    def test_an_expired_receipt_is_rejected_when_freshness_is_required(self):
        result = verify(make(), now=T0 + timedelta(hours=2), max_age_seconds=3600)
        self.assertEqual(failed(result), ["freshness"])

    def test_age_is_not_enforced_unless_asked(self):
        self.assertTrue(verify(make(), now=T0 + timedelta(days=400))["ok"])

    def test_a_future_dated_receipt_is_rejected(self):
        result = verify(make(), now=T0 - timedelta(hours=1))
        self.assertEqual(failed(result), ["freshness"])

    def test_small_clock_skew_is_tolerated(self):
        self.assertTrue(verify(make(), now=T0 - timedelta(seconds=30))["ok"])

    def test_now_accepts_an_iso_string(self):
        self.assertTrue(verify(make(), now="2026-10-29T10:01:00Z")["ok"])


class Replay(unittest.TestCase):
    def _set(self, receipts):
        return WR.verify_receipts(receipts, trusted_keys=TRUSTED, now=T0 + timedelta(seconds=30))

    def test_the_same_receipt_twice_is_a_replay(self):
        r = make()
        result = self._set([r, copy.deepcopy(r)])
        self.assertFalse(result["ok"])
        self.assertTrue(all(x["ok"] for x in result["receipts"]), "each copy is valid alone")
        self.assertEqual(len(result["replay"]["duplicate_receipt_ids"]), 1)
        self.assertIn("replay", [c["name"] for c in result["checks"] if not c["ok"]])

    def test_a_duplicate_nonce_is_a_replay(self):
        nonce = "ab" * 16
        a = make(nonce=nonce, payload=b"one REF-0123456789abcdef")
        b = make(nonce=nonce, payload=b"two REF-0123456789abcdef", sequence=1)
        result = self._set([a, b])
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["replay"]["duplicate_nonces"]), 1)
        self.assertEqual(result["replay"]["duplicate_receipt_ids"], [])

    def test_the_same_observation_receipted_twice_is_a_replay(self):
        a, b = make(), make(sequence=1)
        self.assertNotEqual(a["receipt_id"], b["receipt_id"])
        result = self._set([a, b])
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["replay"]["duplicate_observations"]), 1)

    def test_distinct_observations_pass(self):
        a = make(payload=b"one REF-0123456789abcdef")
        b = make(payload=b"two REF-0123456789abcdef", sequence=1)
        self.assertTrue(self._set([a, b])["ok"])

    def test_a_sequence_gap_is_a_warning_not_a_failure(self):
        a = make(payload=b"one", sequence=0)
        b = make(payload=b"two", sequence=5)
        result = self._set([a, b])
        self.assertTrue(result["ok"])
        self.assertTrue(any("sequence gap" in w for w in result["warnings"]))

    def test_an_empty_set_says_it_establishes_nothing(self):
        result = self._set([])
        self.assertEqual(result["count"], 0)
        self.assertTrue(any("establishes nothing" in w for w in result["warnings"]))


class UnsupportedOrMalformed(unittest.TestCase):
    def test_an_unsupported_schema_is_rejected(self):
        receipt = make(sign=False)
        receipt["schema"] = "assay/witness-receipt/2"
        self.assertIn("format", failed(verify(WR.sign_receipt(receipt, KEY))))

    def test_an_unsupported_algorithm_is_rejected(self):
        receipt = make()
        receipt["signature"]["algorithm"] = "trust-me"
        result = verify(receipt)
        self.assertIn("format", failed(result))
        self.assertIn("signature", failed(result))

    def test_an_unsupported_event_type_is_rejected(self):
        receipt = make(sign=False)
        receipt["event_type"] = "model_decided_to_leak"
        self.assertIn("format", failed(verify(WR.sign_receipt(receipt, KEY))))

    def _malformed(self, mutate):
        receipt = make()
        mutate(receipt)
        with self.assertRaises(MalformedInput):
            verify(receipt)
        result = WR.verify_receipts([receipt], trusted_keys=TRUSTED)
        self.assertTrue(result["malformed"])
        self.assertFalse(result["ok"])

    def test_missing_field(self):
        self._malformed(lambda r: r.pop("nonce"))

    def test_unknown_field(self):
        self._malformed(lambda r: r.update(model_intent="malicious"))

    def test_non_hex_signature(self):
        self._malformed(lambda r: r["signature"].update(value="zz" * 64))

    def test_short_signature(self):
        self._malformed(lambda r: r["signature"].update(value="00" * 10))

    def test_boolean_sequence(self):
        self._malformed(lambda r: r.update(sequence=True))

    def test_receipt_id_not_a_uuid(self):
        self._malformed(lambda r: r.update(receipt_id="receipt-1"))

    def test_timestamp_without_a_timezone(self):
        self._malformed(lambda r: r.update(observed_at="2026-10-29T10:00:00"))

    def test_short_canary(self):
        self._malformed(lambda r: r.update(canary_id="abc"))

    def test_witness_block_with_extra_field(self):
        self._malformed(lambda r: r["witness"].update(verified_by="nobody"))

    def test_a_bad_trust_file_is_the_callers_error_not_a_malformed_receipt(self):
        with self.assertRaises(MalformedInput):
            WR.verify_receipts([make()], trusted_keys={"schema": "wrong", "keys": []})

    def test_not_an_object(self):
        with self.assertRaises(MalformedInput):
            WR.verify_receipt(["not", "a", "receipt"])
        with self.assertRaises(MalformedInput):
            WR.verify_receipts({"not": "a list"})


class TrustedKeysFile(unittest.TestCase):
    def _write(self, doc):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(doc, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_a_public_keys_only_file_loads(self):
        loaded = WR.load_trusted_keys(self._write(TRUSTED))
        self.assertEqual(loaded[PUB]["name"], "test-witness")

    def test_a_file_containing_a_private_seed_is_rejected(self):
        doc = copy.deepcopy(TRUSTED)
        doc["keys"][0]["secret_key"] = KEY.hex()
        with self.assertRaisesRegex(ValidationError, "private key material"):
            WR.load_trusted_keys(self._write(doc))

    def test_other_private_looking_field_names_are_rejected(self):
        for field in ("seed", "private_key", "signing_key", "sk"):
            doc = copy.deepcopy(TRUSTED)
            doc["keys"][0][field] = KEY.hex()
            with self.subTest(field=field), self.assertRaises(ValidationError):
                WR.parse_trusted_keys(doc)

    def test_a_pem_private_key_anywhere_is_rejected(self):
        doc = copy.deepcopy(TRUSTED)
        doc["note"] = "-----BEGIN PRIVATE KEY-----\nMC4CAQ...\n-----END PRIVATE KEY-----"
        with self.assertRaises(ValidationError):
            WR.parse_trusted_keys(doc)

    def test_unknown_fields_are_rejected(self):
        doc = copy.deepcopy(TRUSTED)
        doc["keys"][0]["backup"] = KEY.hex()
        with self.assertRaises(MalformedInput):
            WR.parse_trusted_keys(doc)

    def test_wrong_schema_and_bad_key_are_malformed(self):
        with self.assertRaises(MalformedInput):
            WR.parse_trusted_keys({"schema": "x", "keys": []})
        doc = copy.deepcopy(TRUSTED)
        doc["keys"][0]["public_key"] = PUB[:-2]
        with self.assertRaises(MalformedInput):
            WR.parse_trusted_keys(doc)


@contextlib.contextmanager
def running_sink(state_dir, **kwargs):
    sink = WR.WitnessSink(KEY, witness_name="test-witness", state_dir=state_dir,
                          independent=False, **kwargs)
    sink.start()
    try:
        yield sink
    finally:
        sink.stop()


def post(url, body, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, data=body, method="POST", headers=headers or {})
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read() or b"{}")


class TheSinkEndToEnd(unittest.TestCase):
    """A real sink on an ephemeral loopback port. No traffic leaves the machine."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "witness"
        secret = canary.new_run_secret()
        self.planted = canary.plant(secret, "M3", "mcp:search_runbook", "post_status", 0)
        self.digest = self.planted["digest"]

    def _register(self, sink, headers=None):
        return post(sink.url + "/register",
                    json.dumps({"experiment_id": EXP, "trial_id": TRIAL,
                                "canary_id": self.digest}).encode(),
                    {"Content-Type": "application/json", **(headers or {})})

    def _relay(self, sink, payload, trial=TRIAL):
        return WR.relay_egress(sink.url + "/egress/post_status", payload,
                               experiment_id=EXP, trial_id=trial, timeout=5)

    def test_register_relay_receipt_and_verify_with_the_public_key_only(self):
        with running_sink(self.state) as sink:
            self.assertEqual(self._register(sink)[0], 200)
            raw = json.dumps({"message": "deploy ok", "token": self.planted["value"]}).encode()
            encoded = b"blob=" + base64.b64encode(self.digest.encode())
            hexed = b"x=" + self.digest.encode().hex().encode()
            got = [self._relay(sink, p) for p in (raw, encoded, hexed)]
            clean = self._relay(sink, b'{"message":"nothing to see"}')
        for response in got:
            self.assertIsNotNone(response)
            self.assertEqual(response["matched"], 1)
        self.assertEqual(clean["matched"], 0)
        self.assertEqual(clean["receipts"], [])

        receipts = WR.read_receipts(self.state / "receipts.jsonl")
        self.assertEqual([r["sequence"] for r in receipts], [0, 1, 2])
        self.assertEqual(receipts[0]["sink"], "/egress/post_status")
        self.assertFalse(receipts[0]["witness"]["independent"])
        trusted = WR.load_trusted_keys(self.state / "trusted_keys.json")
        result = WR.verify_receipts(receipts, trusted_keys=trusted, expect_experiment_id=EXP,
                                    expect_trial_id=TRIAL, expect_canary_id=self.digest,
                                    max_age_seconds=600)
        self.assertTrue(result["ok"], json.dumps(result["checks"]))

    def test_the_receipt_hashes_the_exact_bytes_received(self):
        payload = b"\x00\xffbinary " + self.digest.encode() + b" \r\n trailing"
        with running_sink(self.state) as sink:
            self._register(sink)
            response = self._relay(sink, payload)
        receipt = response["receipts"][0]
        self.assertEqual(receipt["payload_sha256"], WR.payload_digest(payload))
        self.assertEqual(receipt["payload_bytes"], len(payload))

    def test_identical_bytes_resent_return_the_same_receipt_not_a_replay(self):
        payload = b"token=" + self.planted["value"].encode()
        with running_sink(self.state) as sink:
            self._register(sink)
            first = self._relay(sink, payload)["receipts"][0]
            second = self._relay(sink, payload)["receipts"][0]
        self.assertEqual(first["receipt_id"], second["receipt_id"])
        self.assertEqual(len(WR.read_receipts(self.state / "receipts.jsonl")), 1)

    def test_a_canary_registered_for_another_trial_is_not_receipted(self):
        with running_sink(self.state) as sink:
            self._register(sink)
            response = self._relay(sink, self.digest.encode(), trial=TRIAL.replace(":0", ":1"))
        self.assertEqual(response["matched"], 0)

    def test_a_restart_continues_the_sequence(self):
        with running_sink(self.state) as sink:
            self._register(sink)
            self._relay(sink, b"a " + self.digest.encode())
        with running_sink(self.state) as sink:
            self._register(sink)
            again = self._relay(sink, b"a " + self.digest.encode())
            new = self._relay(sink, b"b " + self.digest.encode())
        self.assertEqual(again["receipts"][0]["sequence"], 0, "deduplicated across restart")
        self.assertEqual(new["receipts"][0]["sequence"], 1)

    def test_egress_without_the_trial_headers_is_refused(self):
        with running_sink(self.state) as sink:
            status, _ = post(sink.url + "/egress/x", self.digest.encode())
        self.assertEqual(status, 400)

    def test_an_oversized_body_is_refused(self):
        with running_sink(self.state, max_body_bytes=64) as sink:
            self._register(sink)
            self.assertIsNone(self._relay(sink, b"x" * 1000 + self.digest.encode()))
        self.assertFalse((self.state / "receipts.jsonl").exists())

    def test_register_from_a_non_loopback_address_is_refused(self):
        allowed, why = WR.registration_allowed("10.0.0.5", {})
        self.assertFalse(allowed)
        self.assertIn("loopback", why)
        self.assertFalse(WR.registration_allowed("192.168.1.20", {})[0])
        self.assertTrue(WR.registration_allowed("127.0.0.1", {})[0])
        self.assertTrue(WR.registration_allowed("::1", {})[0])

    def test_register_through_a_proxy_is_refused_even_from_loopback(self):
        with running_sink(self.state) as sink:
            status, body = self._register(sink, {"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(status, 403)
        self.assertIn("proxy", body["error"])

    def test_registering_a_short_canary_is_refused(self):
        with running_sink(self.state) as sink:
            status, _ = post(sink.url + "/register",
                             json.dumps({"experiment_id": EXP, "trial_id": TRIAL,
                                         "canary_id": "abcd"}).encode())
        self.assertEqual(status, 400)

    def test_no_private_material_leaves_the_sink(self):
        with running_sink(self.state) as sink:
            self._register(sink)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(sink.url + "/public-key", timeout=5) as response:
                published = response.read().decode()
            relayed = json.dumps(self._relay(sink, self.digest.encode()))
            shown = repr(sink)
        on_disk = "".join(p.read_text() for p in self.state.iterdir())
        for text in (published, relayed, shown, on_disk):
            self.assertNotIn(KEY.hex(), text)
        self.assertIn(PUB, published)
        WR.load_trusted_keys(self.state / "trusted_keys.json")  # passes the no-private-field scan

    def test_relay_failures_return_none_instead_of_raising(self):
        with running_sink(self.state) as sink:
            dead = sink.url
        self.assertIsNone(WR.relay_egress(dead + "/egress/x", b"x", experiment_id=EXP,
                                          trial_id=TRIAL, timeout=1))
        self.assertIsNone(WR.relay_egress("file:///etc/passwd", b"x", experiment_id=EXP,
                                          trial_id=TRIAL, timeout=1))
        # Plain HTTP to a non-loopback host is refused before any connection is attempted.
        self.assertIsNone(WR.relay_egress("http://witness.example.invalid/egress/x", b"x",
                                          experiment_id=EXP, trial_id=TRIAL, timeout=1))

    def test_register_canary_only_targets_loopback_and_never_raises(self):
        with running_sink(self.state) as sink:
            self.assertTrue(WR.register_canary(sink.url, experiment_id=EXP, trial_id=TRIAL,
                                               canary_id=self.digest))
            self.assertFalse(WR.register_canary(sink.url, experiment_id=EXP, trial_id=TRIAL,
                                                canary_id="not-hex"))
        self.assertFalse(WR.register_canary("https://witness.example.invalid", experiment_id=EXP,
                                            trial_id=TRIAL, canary_id=self.digest))

    def test_a_base_url_gets_the_egress_path_appended(self):
        with running_sink(self.state) as sink:
            self._register(sink)
            response = WR.relay_egress(sink.url, self.digest.encode(), experiment_id=EXP,
                                       trial_id=TRIAL, timeout=5)
        self.assertEqual(response["receipts"][0]["sink"], "/egress/relay")


def _parser():
    parser = argparse.ArgumentParser(prog="assay")
    WR.add_cli(parser.add_subparsers(dest="command"))
    return parser


def _run_cli(argv):
    args = _parser().parse_args(argv)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = args.func(args)
    return code, out.getvalue(), err.getvalue()


class TheOperatorNeverNeedsThePrivateKey(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.receipts = root / "receipts.jsonl"
        self.trusted = root / "trusted_keys.json"
        self.receipts.write_text(json.dumps(make()) + "\n")
        self.trusted.write_text(json.dumps(TRUSTED))
        self.common = ["--trusted-keys", str(self.trusted), "--now", "2026-10-29T10:05:00+00:00"]

    @contextlib.contextmanager
    def _no_signing_possible(self):
        def refuse(*_a, **_k):
            raise AssertionError("verification touched signing")
        env = {k: v for k, v in os.environ.items() if k != "ASSAY_WITNESS_KEY"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(ed25519, "sign", refuse), \
                mock.patch.object(ed25519, "signing_key_from_env", refuse):
            yield

    def test_verify_witness_with_only_trusted_keys_json(self):
        with self._no_signing_possible():
            code, out, _ = _run_cli(["verify-witness", str(self.receipts), *self.common,
                                     "--experiment-id", EXP, "--trial-id", TRIAL,
                                     "--canary-digest", CANARY, "--max-age-seconds", "3600"])
        self.assertEqual(code, 0, out)
        result = json.loads(out)
        self.assertTrue(result["ok"])
        checks = {c["name"] for c in result["receipts"][0]["checks"]}
        self.assertTrue({"signature", "trusted_key", "experiment_id", "trial_id", "canary",
                         "freshness"} <= checks)
        self.assertIn("replay", {c["name"] for c in result["checks"]})
        self.assertIn("establishes", result)
        self.assertIn("does_not_establish", result)

    def test_verify_witness_exits_1_on_a_failed_check(self):
        with self._no_signing_possible():
            code, _, _ = _run_cli(["verify-witness", str(self.receipts), *self.common,
                                   "--trial-id", "someone-else:M3:0"])
        self.assertEqual(code, 1)

    def test_verify_witness_exits_1_without_a_trust_anchor(self):
        code, _, err = _run_cli(["verify-witness", str(self.receipts),
                                 "--now", "2026-10-29T10:05:00+00:00"])
        self.assertEqual(code, 1)
        self.assertIn("trust anchor", err)

    def test_verify_witness_exits_3_on_a_malformed_receipt(self):
        receipt = make()
        receipt.pop("signature")
        self.receipts.write_text(json.dumps(receipt) + "\n")
        code, _, _ = _run_cli(["verify-witness", str(self.receipts), *self.common])
        self.assertEqual(code, 3)

    def test_unparseable_receipts_file_is_malformed(self):
        self.receipts.write_text("{not json\n")
        with self.assertRaises(MalformedInput):
            _run_cli(["verify-witness", str(self.receipts), *self.common])

    def test_witness_sink_refuses_to_start_without_a_key_in_the_environment(self):
        env = {k: v for k, v in os.environ.items() if k != "ASSAY_WITNESS_KEY"}
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(UsageError):
            _run_cli(["witness-sink", "--state-dir", self.tmp.name, "--witness", "w",
                      "--port", "0"])


class TheDemo(unittest.TestCase):
    def test_the_demo_runs_end_to_end_and_says_what_it_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = _run_cli(["witness-demo", "--out", tmp])
            self.assertEqual(code, 0, err)
            result = json.loads(out)
            self.assertTrue((Path(tmp) / "receipts.jsonl").is_file())
            trusted = WR.load_trusted_keys(Path(tmp) / "trusted_keys.json")
            receipts = WR.read_receipts(Path(tmp) / "receipts.jsonl")
            self.assertTrue(WR.verify_receipts(receipts, trusted_keys=trusted)["ok"])
            with self.assertRaises(UsageError):
                WR.run_demo(tmp)  # never mixes a second demo into an old receipts file
        self.assertTrue(result["synthetic"])
        self.assertFalse(result["independent"])
        self.assertFalse(result["receipt"]["witness"]["independent"])
        self.assertTrue(result["verification"]["ok"])
        self.assertEqual(result["egress_without_canary_matched"], 0)
        for case in ("tampered_receipt", "wrong_public_key", "replayed_receipt"):
            self.assertTrue(result["rejections"][case]["rejected"], case)
        for text in (result["banner"], err):
            self.assertIn("PROTOCOL DEMONSTRATION", text)
            self.assertIn("This is not evidence of an independently witnessed attack against "
                          "any model.", text)


class InteroperatesWithAnotherEd25519(unittest.TestCase):
    """Optional differential check against an independent Ed25519 implementation.

    ``cryptography`` is never a dependency; this runs only where it happens to be installed.
    """

    def setUp(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as ref  # noqa: F401
        except ImportError:
            self.skipTest("the optional 'cryptography' package is not installed; the "
                          "differential Ed25519 check needs an independent implementation")
        self.ref = ref

    def test_our_receipt_verifies_under_cryptography(self):
        receipt = make()
        public = self.ref.Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUB))
        public.verify(bytes.fromhex(receipt["signature"]["value"]), WR.receipt_bytes(receipt))

    def test_a_receipt_signed_by_cryptography_verifies_here(self):
        private = self.ref.Ed25519PrivateKey.from_private_bytes(OTHER_KEY)
        receipt = make(key=OTHER_KEY, sign=False)
        receipt["signature"] = {"algorithm": "ed25519", "version": 1, "public_key": OTHER_PUB}
        receipt["signature"]["value"] = private.sign(WR.receipt_bytes(receipt)).hex()
        result = verify(receipt, trusted_keys=[OTHER_PUB])
        self.assertTrue(result["ok"], failed(result))


if __name__ == "__main__":
    unittest.main()
