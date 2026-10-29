"""Redaction: secrets go, synthetic canaries stay, and the output is deterministic.

Every secret below is a FAKE built for this test (repeated characters, documentation domains).
Canary envelopes are minted with ``canary.plant`` so the preservation test exercises the real
shapes the adversarial surfaces hand to targets.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import helpers  # noqa: F401  (puts src on sys.path)

from assay_bench import canary
from assay_bench.errors import ValidationError
from assay_bench.redaction import (REPORT_SCHEMA, Redactor, add_cli, collect_canary_digests,
                                   marker)
from assay_bench.trace import TraceRecorder, check_trace, read_jsonl, write_jsonl

FAKE = {
    "openai": "sk-proj-" + "A1b2C3d4" * 5,
    "openrouter": "sk-or-v1-" + "0123456789abcdef" * 4,
    "anthropic": "sk-ant-api03-" + "Zz9_" * 10,
    "google": "AIza" + "B" * 35,
    "github": "ghp_" + "c" * 36,
    "github_pat": "github_pat_" + "D" * 30,
    "slack": "xoxb-" + "1234567890-abcdef",
}
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiJ1c2VyLTEyMyIsIm5hbWUiOiJKb2UifQ."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
PEM = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAfakefakefakefake\n"
       "fakefakefakefakefake==\n-----END RSA PRIVATE KEY-----")


def kinds(report: dict) -> dict:
    return report["counts"]


class EachKind(unittest.TestCase):
    def test_api_keys(self):
        for label, value in FAKE.items():
            with self.subTest(label):
                r = Redactor()
                out = r.redact_text(f"key: {value} end")
                self.assertNotIn(value, out)
                self.assertEqual(out, f"key: {marker('api_key', value)} end")
                self.assertEqual(kinds(r.report), {"api_key": 1})

    def test_aws_bearer_jwt_private_key(self):
        cases = [("aws_access_key", f"id={AWS}", AWS),
                 ("bearer_token", "Authorization: Bearer abcDEF123456.ghi-jkl_mno", "abcDEF123456.ghi-jkl_mno"),
                 ("jwt", f"token {JWT}", JWT),
                 ("private_key", f"pem:\n{PEM}\n", PEM)]
        for kind, text, secret in cases:
            with self.subTest(kind):
                r = Redactor()
                out = r.redact_text(text)
                self.assertNotIn(secret, out)
                self.assertIn(marker(kind, secret), out)
                self.assertEqual(kinds(r.report), {kind: 1})
        # "Bearer " itself survives, so a reader still sees what kind of header it was.
        self.assertIn("Bearer [REDACTED:bearer_token:", Redactor().redact_text(cases[1][1]))

    def test_email_and_home_paths(self):
        r = Redactor()
        out = r.redact_text("mail alice.smith@acme-corp.io from /Users/alice/proj and "
                            "/home/bob/.ssh and C:\\Users\\carol\\x")
        self.assertNotIn("alice.smith@acme-corp.io", out)
        self.assertIn(marker("email", "alice.smith@acme-corp.io"), out)
        self.assertIn("/Users/<redacted>/proj", out)
        self.assertIn("/home/<redacted>/.ssh", out)
        self.assertIn("C:\\Users\\<redacted>\\x", out)
        self.assertEqual(kinds(r.report), {"email": 1, "home_path": 3})

    def test_documentation_emails_are_kept(self):
        text = ("ops@example.com, a@sub.example.org, b@example.net, c@host.invalid, "
                "d@foo.test")
        r = Redactor()
        self.assertEqual(r.redact_text(text), text)
        self.assertEqual(r.report["total"], 0)

    def test_env_values_present_at_redaction_time(self):
        fake = "fake-env-secret-value-0123456789"
        with mock.patch.dict(os.environ, {"ASSAY_TEST_FAKE_API_KEY": fake}):
            r = Redactor()
            out = r.redact({"log": f"called with {fake}"})
        self.assertEqual(out, {"log": f"called with {marker('env_value', fake)}"})
        self.assertIn("ASSAY_TEST_FAKE_API_KEY", r.report["env_var_names_matched"])
        self.assertNotIn(fake, json.dumps(r.report))
        # Once the variable is gone, the same value is no longer known to be a secret.
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ASSAY_TEST_FAKE_API_KEY", None)
            self.assertIn(fake, Redactor().redact_text(f"x {fake}"))

    def test_extra_values_are_always_redacted(self):
        live = "live-key-held-in-memory-42"
        r = Redactor(extra_values=[live])
        self.assertEqual(r.redact_text(f"k={live}"), f"k={marker('configured_secret', live)}")


class Determinism(unittest.TestCase):
    DOC = {"a": f"{FAKE['openai']} and {FAKE['openai']}", "b": [AWS, {"c": JWT}]}

    def test_same_input_same_output(self):
        self.assertEqual(Redactor().redact(self.DOC), Redactor().redact(self.DOC))

    def test_same_value_same_marker(self):
        out = Redactor().redact(self.DOC)
        m = marker("api_key", FAKE["openai"])
        self.assertEqual(out["a"], f"{m} and {m}")
        self.assertEqual(len(m), len("[REDACTED:api_key:") + 12 + 1)

    def test_redaction_is_idempotent(self):
        once = Redactor().redact(self.DOC)
        self.assertEqual(Redactor().redact(once), once)

    def test_non_string_scalars_untouched(self):
        self.assertEqual(Redactor().redact([1, 2.5, True, None]), [1, 2.5, True, None])


def _every_envelope() -> dict[str, dict]:
    secret = "5c" * 32
    found: dict[str, dict] = {}
    for i in range(400):
        c = canary.plant(secret, f"M{i}", f"assay/M{i}", "tool", 0)
        found.setdefault(c["envelope"], c)
        if len(found) == len(canary.ENVELOPES):
            return found
    raise AssertionError(f"could not mint every envelope: {sorted(found)}")


class Canaries(unittest.TestCase):
    def test_every_envelope_is_preserved_by_value_or_by_digest(self):
        for env, c in _every_envelope().items():
            text = json.dumps({"arguments": json.dumps({"key": c["value"]})})
            for preserve in ([c["value"]], [c["digest"]]):
                with self.subTest(envelope=env, preserve="value" if preserve[0] == c["value"]
                                  else "digest"):
                    r = Redactor(preserve=preserve)
                    self.assertEqual(r.redact_text(c["value"]), c["value"])
                    self.assertEqual(r.redact_text(text), text)
                    self.assertTrue(canary.detects(c["digest"], r.redact_text(text)))

    def test_without_preserve_secret_shaped_canaries_would_be_erased(self):
        # Why preservation is load-bearing: the oracle's evidence looks like a secret.
        envs = _every_envelope()
        for env in ("openai_sk", "jwt"):
            with self.subTest(env):
                self.assertNotIn(envs[env]["digest"], Redactor().redact_text(envs[env]["value"]))

    def test_preservation_does_not_shield_neighbouring_secrets(self):
        c = _every_envelope()["openai_sk"]
        r = Redactor(preserve=[c["digest"]])
        out = r.redact_text(f"{c['value']} {FAKE['github']}")
        self.assertIn(c["value"], out)
        self.assertNotIn(FAKE["github"], out)
        self.assertEqual(r.report["preserved_matches"], 1)

    def test_bad_preserve_lists_are_refused(self):
        with self.assertRaises(ValidationError):
            Redactor(preserve=["abc"])
        with self.assertRaises(ValidationError):
            Redactor(preserve=["same-value-123"], extra_values=["same-value-123"])

    def test_digests_are_collected_from_trial_records(self):
        doc = {"tasks": {"M1": [{"canary_digest": "0123456789abcdef"},
                                {"canary_digest": None}]}}
        self.assertEqual(collect_canary_digests(doc), {"0123456789abcdef"})


class NestedJson(unittest.TestCase):
    def test_nested_structures(self):
        doc = {"req": {"headers": {"Authorization": f"Bearer {FAKE['openai']}"},
                       "items": [{"deep": [FAKE["google"]]}]},
               FAKE["github"]: "keys are redacted too"}
        out = json.dumps(Redactor().redact(doc))
        for v in (FAKE["openai"], FAKE["google"], FAKE["github"]):
            self.assertNotIn(v, out)

    def test_json_encoded_tool_arguments(self):
        # Tool-call arguments arrive as JSON *strings*; redaction must reach inside them and
        # leave them parseable.
        quoted = 'pa"ss\\word-with-quotes'
        args = json.dumps({"api_key": FAKE["anthropic"], "note": "ok", "pw": quoted})
        event = {"name": "post_status", "arguments": args,
                 "double": json.dumps(json.dumps({"k": FAKE["openrouter"], "pw": quoted}))}
        out = Redactor(extra_values=[quoted]).redact(event)
        inner = json.loads(out["arguments"])
        self.assertEqual(inner["api_key"], marker("api_key", FAKE["anthropic"]))
        self.assertEqual(inner["pw"], marker("configured_secret", quoted))
        self.assertEqual(inner["note"], "ok")
        twice = json.loads(json.loads(out["double"]))
        self.assertEqual(twice["k"], marker("api_key", FAKE["openrouter"]))
        self.assertEqual(twice["pw"], marker("configured_secret", quoted))
        self.assertNotIn(FAKE["anthropic"], json.dumps(out))


class Report(unittest.TestCase):
    def test_counts_and_impact(self):
        r = Redactor()
        r.redact({"a": [FAKE["openai"], FAKE["openai"], AWS], "b": "x@acme-corp.io"})
        rep = r.report
        self.assertEqual(rep["schema"], REPORT_SCHEMA)
        self.assertEqual(rep["counts"], {"api_key": 2, "aws_access_key": 1, "email": 1})
        self.assertEqual(rep["total"], 4)
        for phrase in ("content_sha256", "ORIGINAL", "UNKEYED", "not a guarantee"):
            self.assertIn(phrase, rep["impact"])


class Cli(unittest.TestCase):
    def _run(self, argv: list[str]) -> int:
        parser = argparse.ArgumentParser()
        add_cli(parser.add_subparsers(dest="command"))
        args = parser.parse_args(argv)
        with mock.patch("sys.stdout"):
            return args.func(args)

    def test_redacting_a_trace_keeps_its_chain_and_its_canary(self):
        tmp = Path(tempfile.mkdtemp())
        c = _every_envelope()["openai_sk"]
        rec = TraceRecorder("run:M1:0")
        req = rec.emit("tool_call_requested", actor="model",
                       content={"name": "post", "arguments": json.dumps(
                           {"body": c["value"], "auth": FAKE["openai"]})})
        rec.emit("tool_call_executed", actor="tool", parents=[req])
        rec.emit("validation", actor="harness", parents=[req],
                 content={"fired": True, "canary_digest": c["digest"], "state": "exploited"})
        write_jsonl(tmp / "in.jsonl", rec.events)
        self.assertEqual(self._run(["redact", str(tmp / "in.jsonl"), str(tmp / "out.jsonl"),
                                    "--report", str(tmp / "rep.json")]), 0)
        out = read_jsonl(tmp / "out.jsonl")
        text = (tmp / "out.jsonl").read_text()
        self.assertNotIn(FAKE["openai"], text)
        self.assertIn(c["value"], text)                  # auto-preserved via canary_digest
        self.assertTrue(out[0]["redacted"])
        self.assertEqual(out[0]["content_sha256"], rec.events[0]["content_sha256"])
        self.assertEqual(check_trace(out), [])
        self.assertEqual(json.loads((tmp / "rep.json").read_text())["counts"], {"api_key": 1})

    def test_redacting_plain_json(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "in.json").write_text(json.dumps({"k": FAKE["slack"]}))
        self._run(["redact", str(tmp / "in.json"), str(tmp / "out.json")])
        self.assertEqual(json.loads((tmp / "out.json").read_text()),
                         {"k": marker("api_key", FAKE["slack"])})


if __name__ == "__main__":
    unittest.main()
