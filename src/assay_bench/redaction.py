"""Deterministic redaction of secrets in evidence, without destroying the evidence.

Published traces contain whatever the model and tools saw: real API keys an operator pasted,
bearer tokens in HTTP logs, home-directory paths, e-mail addresses. Those must not be published.
But Assay's canaries are *deliberately secret-shaped* (``sk-...``, ``AKIA...``, JWTs; see
``canary.py``) because a target that only leaks things that look like secrets must be tested
with things that look like secrets. A naive scrubber would erase exactly the strings the
oracle's findings rest on. So:

* values in ``preserve`` (the synthetic canary values and their digests) are never redacted,
  and neither is any match that *overlaps* a preserved value -- a canary envelope that merely
  contains a preserved digest stays visible;
* everything else that matches a known secret shape is replaced by a deterministic marker
  ``[REDACTED:<kind>:<first 12 hex of sha256(value)>]``. The same value always gets the same
  marker, so a reader can still see that the key in request 3 is the key in request 9 without
  learning it.

**What redaction does not establish.** It is pattern-based. A secret in a shape it does not
know (an AWS *secret* key, a password typed into prose, a key split across two strings) is not
found. And the marker is an *unkeyed* hash prefix: for a low-entropy value -- an e-mail
address, a username -- anyone can confirm a guess by hashing it. The ``report`` says this
explicitly so a reader never mistakes a redacted artifact for a scrubbed one.

**What it does to verifiability.** A trace event's ``content_sha256`` is over the ORIGINAL
content. After redaction a reader can still verify the hash chain and every unredacted event,
and can verify a redacted event only if given its original. ``report["impact"]`` states this.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from .errors import UsageError, ValidationError

REPORT_SCHEMA = "assay/redaction-report/1"
MARKER_FORMAT = "[REDACTED:<kind>:<first 12 hex of sha256(value)>]"

#: Environment variable names whose VALUES are treated as secrets when present at redaction time.
ENV_NAME_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD")
#: Values shorter than this are not redacted by env/extra matching: redacting "1" or "true"
#: everywhere would destroy the artifact without protecting anything.
MIN_SECRET_VALUE = 8
#: A preserved value shorter than this would suppress redaction far too broadly.
MIN_PRESERVE = 8

#: Domains that are reserved for documentation/testing (RFC 2606 / RFC 6761) and so are never
#: real people's addresses.
_SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
_SAFE_EMAIL_TLDS = ("invalid", "test", "example", "localhost")

# (kind, pattern, group). ``group`` is the part replaced: for a bearer token only the token,
# not the word "Bearer"; for a home path only the user name. Order is the tie-break priority.
_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("private_key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL), 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+"), 0),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{8,}=*)"), 1),
    ("api_key", re.compile(
        r"(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{20,}"          # OpenAI, sk-proj-, sk-or-v1-, sk-ant-
        r"|AIza[0-9A-Za-z_-]{35}"                              # Google
        r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"   # GitHub
        r"|xox[bpoas]-[A-Za-z0-9-]{10,})"), 0),                # Slack
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0),
    ("email", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"), 0),
    ("home_path", re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)([^/\\\s\"'<>]+)"), 1),
)


def marker(kind: str, value: str) -> str:
    """The deterministic replacement for ``value``."""
    return f"[REDACTED:{kind}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}]"


def _safe_email(addr: str) -> bool:
    domain = addr.rsplit("@", 1)[-1].lower()
    if any(domain == d or domain.endswith("." + d) for d in _SAFE_EMAIL_DOMAINS):
        return True
    return domain.rsplit(".", 1)[-1] in _SAFE_EMAIL_TLDS


def _escaped_forms(value: str) -> list[str]:
    """``value`` as it appears raw, inside one JSON string, and inside a JSON string in a JSON
    string -- tool arguments are JSON-encoded strings, and those are often nested again."""
    forms = [value]
    cur = value
    for _ in range(2):
        for ascii_only in (False, True):
            enc = json.dumps(cur, ensure_ascii=ascii_only)[1:-1]
            if enc not in forms:
                forms.append(enc)
        cur = json.dumps(cur, ensure_ascii=False)[1:-1]
    return forms


def _env_secrets() -> dict[str, str]:
    return {name: value for name, value in os.environ.items()
            if any(h in name.upper() for h in ENV_NAME_HINTS)
            and isinstance(value, str) and len(value) >= MIN_SECRET_VALUE}


class Redactor:
    """Deep, deterministic redaction over JSON-shaped values.

    ``preserve``: synthetic canary values and digests that MUST stay visible (they are the
    evidence). ``extra_values``: exact strings always redacted (e.g. the live API key held in
    memory), under kind ``configured_secret``; an explicit instruction beats preservation, so
    a value may not be in both.
    """

    def __init__(self, *, preserve: Iterable[str] = (), extra_values: Iterable[str] = ()) -> None:
        preserve = [p for p in preserve if p]
        for p in preserve:
            if not isinstance(p, str) or len(p) < MIN_PRESERVE:
                raise ValidationError(
                    f"preserve entries must be strings of at least {MIN_PRESERVE} characters; a "
                    f"shorter one would switch redaction off for too much text")
        self._preserve = sorted(set(preserve), key=len, reverse=True)
        self._extra = sorted({v for v in extra_values if v}, key=len, reverse=True)
        clash = set(self._extra) & set(self._preserve)
        if clash:
            raise ValidationError("a value cannot be both preserved and always-redacted")
        self._counts: dict[str, int] = {}
        self._preserved_hits = 0
        self._env_names: set[str] = set()

    # -- text ----------------------------------------------------------------------------

    def _preserved_spans(self, text: str) -> list[tuple[int, int]]:
        spans = []
        for p in self._preserve:
            for form in _escaped_forms(p):
                start = text.find(form)
                while start != -1:
                    spans.append((start, start + len(form)))
                    start = text.find(form, start + 1)
        return spans

    def redact_text(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            return text
        env = _env_secrets()
        candidates: list[tuple[int, int, int, str, str]] = []  # start, end, priority, kind, value

        # Exact values first (highest priority): configured secrets, then env values.
        exact = [(v, "configured_secret") for v in self._extra]
        for name, value in sorted(env.items()):
            if value not in self._preserve:
                exact.append((value, "env_value"))
        for prio, (value, kind) in enumerate(exact):
            for form in _escaped_forms(value):
                start = text.find(form)
                while start != -1:
                    candidates.append((start, start + len(form), prio, kind, value))
                    if kind == "env_value":
                        self._env_names.update(n for n, v in env.items() if v == value)
                    start = text.find(form, start + 1)

        base = len(exact)
        for prio, (kind, pattern, group) in enumerate(_PATTERNS, start=base):
            for m in pattern.finditer(text):
                value = m.group(group)
                if kind == "email" and _safe_email(value):
                    continue
                if kind == "home_path" and value in ("<redacted>", "Shared"):
                    continue
                candidates.append((m.start(group), m.end(group), prio, kind, value))

        if not candidates:
            return text
        preserved = self._preserved_spans(text) if self._preserve else []
        exact_kinds = ("configured_secret",)

        # Resolve overlaps deterministically: earliest start, then priority, then longest.
        candidates.sort(key=lambda c: (c[0], c[2], -(c[1] - c[0])))
        chosen: list[tuple[int, int, str, str]] = []
        cursor = 0
        for start, end, _prio, kind, value in candidates:
            if start < cursor:
                continue
            if kind not in exact_kinds and any(s < end and start < e for s, e in preserved):
                # Overlaps a synthetic canary or digest: this is evidence, not a leak.
                self._preserved_hits += 1
                continue
            chosen.append((start, end, kind, value))
            cursor = end

        out, last = [], 0
        for start, end, kind, value in chosen:
            out.append(text[last:start])
            out.append("<redacted>" if kind == "home_path" else marker(kind, value))
            self._counts[kind] = self._counts.get(kind, 0) + 1
            last = end
        out.append(text[last:])
        return "".join(out)

    # -- structures ----------------------------------------------------------------------

    def redact(self, value: Any) -> Any:
        """Redact every string (keys included) in a JSON-shaped value; other scalars unchanged.

        JSON-encoded strings (tool-call arguments) are handled at the text level, with escaped
        forms of exact values searched too, so their formatting is preserved byte for byte
        outside the replaced spans and they still parse afterwards.
        """
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        if isinstance(value, tuple):
            return [self.redact(v) for v in value]
        if isinstance(value, dict):
            return {(self.redact_text(k) if isinstance(k, str) else k): self.redact(v)
                    for k, v in value.items()}
        return value

    @property
    def report(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA,
            "marker_format": MARKER_FORMAT,
            "counts": dict(sorted(self._counts.items())),
            "total": sum(self._counts.values()),
            "preserved_matches": self._preserved_hits,
            "preserved_values": len(self._preserve),
            "env_var_names_matched": sorted(self._env_names),
            "impact": (
                "Each redacted span was replaced by a deterministic marker: equal values share a "
                "marker, so occurrences can be correlated without revealing the value. Markers are "
                "UNKEYED hash prefixes, so a low-entropy value (an e-mail address, a username) can "
                "be confirmed by anyone who guesses it. Trace events keep content_sha256 over the "
                "ORIGINAL content: a reader can still verify the hash chain and every unredacted "
                "event, but can re-verify a redacted event only if given its original. Synthetic "
                "canary values and digests listed for preservation were left verbatim, so canary "
                "correspondence remains re-checkable. Redaction is pattern-based: a secret in a "
                "shape it does not recognise may remain, so this is not a guarantee that the "
                "artifact contains no secret."),
        }


# ------------------------------------------------------------------------- trace files

_DIGEST_KEYS = ("canary_digest", "canary_id", "digest")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")


def collect_canary_digests(doc: Any) -> set[str]:
    """16-hex canary digests named under well-known keys anywhere in ``doc``.

    The ``redact`` command preserves these automatically, so redacting a trial log or a trace
    can never erase the digests its findings rest on.
    """
    found: set[str] = set()
    stack = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in _DIGEST_KEYS and isinstance(v, str) and _HEX16.match(v):
                    found.add(v)
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return found


def redact_trace_events(events: list[dict[str, Any]], redactor: Redactor) -> list[dict[str, Any]]:
    """Redact the ``content`` of trace events and re-seal each trial's hash chain.

    ``content_sha256`` is left untouched (it commits to the original). The chain is
    recomputed because the redacted events are different bytes; the new chain therefore does
    NOT match any index or signature made over the unredacted trace, which is the honest result.
    """
    from .trace import SCHEMA, canonical, seal_chain

    out = []
    for ev in events:
        ev = dict(ev)
        if ev.get("schema") == SCHEMA and ev.get("content") is not None:
            new = redactor.redact(ev["content"])
            if canonical(new) != canonical(ev["content"]):
                ev["content"] = new
                ev["redacted"] = True
        out.append(ev)
    return seal_chain(out)


# ------------------------------------------------------------------------- CLI

def _cmd_redact(args: argparse.Namespace) -> int:
    from .trace import read_bounded, read_jsonl, strict_loads, write_jsonl

    src, dst = Path(args.input), Path(args.output)
    if src.resolve() == dst.resolve():
        raise UsageError("refusing to redact in place: OUT must differ from IN")
    jsonl = src.suffix.lower() == ".jsonl"
    doc: Any = read_jsonl(src) if jsonl else strict_loads(
        read_bounded(src, max_bytes=50_000_000), where=str(src))
    preserve = set(args.preserve or []) | collect_canary_digests(doc)
    redactor = Redactor(preserve=preserve)
    if jsonl:
        is_trace = all(isinstance(e, dict) and e.get("schema") == "assay/trace/1" for e in doc)
        result = redact_trace_events(doc, redactor) if is_trace and doc else redactor.redact(doc)
        write_jsonl(dst, result)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(redactor.redact(doc), indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    report = redactor.report
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"wrote": str(dst), **report}, indent=2))
    return 0


def add_cli(sub: Any) -> None:
    """Register ``assay redact IN OUT``."""
    p = sub.add_parser("redact", help="redact secrets from a JSON or JSONL artifact "
                                      "(deterministic markers; canary digests preserved)")
    p.add_argument("input", metavar="IN", help=".json or .jsonl file to redact")
    p.add_argument("output", metavar="OUT", help="where to write the redacted copy")
    p.add_argument("--preserve", action="append", metavar="VALUE",
                   help="a synthetic canary value or digest to keep visible (repeatable). "
                        "Digests under canary_digest/canary_id keys are preserved automatically.")
    p.add_argument("--report", metavar="PATH", help="also write the redaction report here")
    p.set_defaults(func=_cmd_redact)


__all__ = ["Redactor", "marker", "REPORT_SCHEMA", "MARKER_FORMAT", "collect_canary_digests",
           "redact_trace_events", "add_cli"]
