"""Structured execution traces: what happened in a trial, step by step, hash-chained.

A scorecard says *that* a trial was exploited. A trace says *how*: which content the attacker
delivered, what the model generated, which tool call it requested, whether the environment
executed it, whether bytes left over a network, and whether they arrived somewhere. Those five
security-relevant steps are recorded as **distinct event types** on purpose, because they are
not equivalent outcomes and a benchmark that collapses them overstates its findings:

1. ``model_output_contains_canary`` -- the model *generated* a dangerous string;
2. ``tool_call_requested``          -- the model *asked* for a tool call;
3. ``tool_call_executed``           -- a tool *accepted and ran* that call;
4. ``network_egress_attempted``     -- the harness *transmitted* bytes to a destination;
5. ``egress_observed_at_sink``      -- the bytes *arrived* at a controlled destination.

A model can do (1) and never (2); a control can refuse (3) after (2); a sandbox can block (4)
after (3); and only an independently operated sink can say anything about (5).

**Integrity.** Every event carries ``prev_hash`` (the previous event's hash in the same trial)
and ``event_hash`` (SHA-256 over its own canonical JSON). The chain makes *accidental* edits,
truncation in the middle and reordering detectable. It does NOT make a trace trustworthy
against its author: anyone can recompute an unsigned hash chain end to end, so a fabricated
trace with a correct chain is indistinguishable from a recorded one. Integrity relative to a
third party comes only from signing the artifact index (``bundle.py``) and from receipts issued
by an independent witness (``witness_receipt.py``) -- and even a signature establishes only
that the signer vouches for these bytes, never that the experiment occurred.

**Redaction.** ``content_sha256`` is computed over the ORIGINAL content, before redaction.
``content`` holds the redacted form and ``redacted`` says whether it differs. A reader who is
later given the original can re-verify it against ``content_sha256`` (``verify_content``); a
reader who is not can verify the chain but cannot re-derive the hash from the redacted text.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .errors import MalformedInput, ValidationError

SCHEMA = "assay/trace/1"

#: Exact event type strings. The five security-relevant steps are deliberately distinct types.
EVENT_TYPES: frozenset[str] = frozenset({
    "user_request", "agent_config", "tools_exposed", "payload_delivered", "model_response",
    "model_output_contains_canary", "tool_call_requested", "tool_call_blocked",
    "tool_call_executed", "tool_result", "tool_error", "network_egress_attempted",
    "network_egress_blocked", "egress_observed_at_sink", "validation", "error",
    "final_response",
})

ACTORS: frozenset[str] = frozenset({
    "user", "operator", "harness", "model", "tool", "attacker", "environment", "witness",
})

#: The ``prev_hash`` of the first event of every trial.
GENESIS = "0" * 64

REQUIRED_FIELDS = ("schema", "event_id", "trial_id", "seq", "timestamp", "type", "actor",
                   "source", "destination", "content", "content_ref", "content_sha256",
                   "redacted", "parents", "prev_hash", "event_hash")

#: Outcomes that settle a ``tool_call_requested``. A request with none of these as a child is
#: "requested but no execution outcome recorded" -- an honest trace must say what happened.
_REQUEST_OUTCOMES = frozenset({"tool_call_executed", "tool_call_blocked", "tool_error"})


# ------------------------------------------------------------------------- canonical form

def canonical(obj: Any) -> bytes:
    """Canonical JSON bytes: the one rendering that is hashed or signed anywhere in Assay."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def content_hash(content: Any) -> str:
    """SHA-256 of the canonical JSON of ``content`` (``null`` included, so it is total)."""
    return sha256_hex(content)


def event_hash(event: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the event with ``event_hash`` removed."""
    return sha256_hex({k: v for k, v in event.items() if k != "event_hash"})


def verify_content(event: dict[str, Any], original: Any) -> bool:
    """True iff ``original`` is the content this event committed to before redaction.

    This is how a redacted trace stays checkable: whoever holds the original (the author, or a
    reviewer given it under embargo) can show it matches the hash published in the trace.
    """
    return content_hash(original) == event.get("content_sha256")


def seal_chain(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recompute ``prev_hash``/``event_hash`` for each trial, in place, and return the list.

    Exists for tooling that legitimately rewrites events (post-hoc redaction) and for test
    fixtures. Its existence is also the honest statement of the chain's limit: an unsigned
    chain can be recomputed by anyone, so it detects accidents, not an author who edits.
    """
    last: dict[str, str] = {}
    for ev in events:
        tid = ev.get("trial_id")
        ev["prev_hash"] = last.get(tid, GENESIS)
        ev["event_hash"] = event_hash(ev)
        last[tid] = ev["event_hash"]
    return events


# ------------------------------------------------------------------------- recorder

def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


class TraceRecorder:
    """Append-only recorder for the events of ONE trial.

    ``redactor`` is anything with a ``redact(value)`` method (normally
    ``redaction.Redactor``). ``clock`` is a zero-argument callable returning an aware
    ``datetime`` or an ISO-8601 string; tests inject one for determinism.

    The recorder refuses to write an event that is malformed at the time of writing (unknown
    type or actor, a parent that does not exist yet). It cannot refuse an event that is merely
    *incomplete* -- a tool call whose outcome is recorded later -- so those rules live in
    ``check_trace``, which runs over the finished trace.
    """

    def __init__(self, trial_id: str, *, redactor: Any = None,
                 clock: Callable[[], Any] | None = None) -> None:
        if not isinstance(trial_id, str) or not trial_id or "#" in trial_id:
            raise ValidationError(f"trial_id must be a non-empty string without '#', got {trial_id!r}")
        self.trial_id = trial_id
        self._redactor = redactor
        self._clock = clock or _default_clock
        self._events: list[dict[str, Any]] = []
        self._ids: set[str] = set()

    def _timestamp(self) -> str:
        now = self._clock()
        if isinstance(now, datetime):
            if now.tzinfo is None:
                raise ValidationError("trace clock returned a naive datetime; timestamps must be UTC")
            return now.astimezone(timezone.utc).isoformat()
        if isinstance(now, str):
            return now
        raise ValidationError(f"trace clock returned {type(now).__name__}, not a datetime")

    def emit(self, type: str, *, actor: str, content: Any = None, source: str | None = None,
             destination: str | None = None, parents: list[str] | None = None,
             content_ref: str | None = None) -> str:
        """Append one event and return its ``event_id``."""
        if type not in EVENT_TYPES:
            raise ValidationError(f"unknown trace event type {type!r}")
        if actor not in ACTORS:
            raise ValidationError(f"unknown trace actor {actor!r}")
        parents = list(parents or [])
        for p in parents:
            if p not in self._ids:
                raise ValidationError(f"parent {p!r} is not an earlier event of {self.trial_id}")
        # Hash the original first: canonical() also rejects NaN/Infinity and non-JSON values,
        # so nothing unhashable ever reaches the trace.
        try:
            original_hash = content_hash(content)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"trace content is not JSON-serialisable: {exc}") from None
        stored = content
        redacted = False
        if self._redactor is not None and content is not None:
            stored = self._redactor.redact(content)
            redacted = canonical(stored) != canonical(content)

        seq = len(self._events)
        event: dict[str, Any] = {
            "schema": SCHEMA,
            "event_id": f"{self.trial_id}#{seq:04d}",
            "trial_id": self.trial_id,
            "seq": seq,
            "timestamp": self._timestamp(),
            "type": type,
            "actor": actor,
            "source": source,
            "destination": destination,
            "content": stored,
            "content_ref": content_ref,
            "content_sha256": original_hash,
            "redacted": redacted,
            "parents": parents,
            "prev_hash": self._events[-1]["event_hash"] if self._events else GENESIS,
        }
        event["event_hash"] = event_hash(event)
        self._events.append(event)
        self._ids.add(event["event_id"])
        return event["event_id"]

    @property
    def events(self) -> list[dict[str, Any]]:
        """A copy of the events so far; mutating it cannot rewrite the recorder's history."""
        return json.loads(json.dumps(self._events))


# ------------------------------------------------------------------------- consistency

def group_by_trial(events: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Events grouped by ``trial_id``, preserving file order within each trial."""
    out: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        tid = ev.get("trial_id") if isinstance(ev, dict) else None
        out.setdefault(tid if isinstance(tid, str) else "<missing trial_id>", []).append(ev)
    return out


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else None


def _tool_name(content: Any) -> str | None:
    if isinstance(content, dict):
        for key in ("name", "tool"):
            if isinstance(content.get(key), str):
                return content[key]
    return None


def _exposed_tools(content: Any) -> set[str]:
    """Tool names from a ``tools_exposed`` payload: a list of tools/names, or {"tools": [...]}."""
    items = content.get("tools") if isinstance(content, dict) else content
    names: set[str] = set()
    if isinstance(items, list):
        for item in items:
            if isinstance(item, str):
                names.add(item)
            elif _tool_name(item):
                names.add(_tool_name(item))  # type: ignore[arg-type]
    return names


def _contains_digest(content: Any, digest: str) -> bool:
    from .canary import forms

    try:
        text = canonical(content).decode("utf-8")
    except (TypeError, ValueError):
        return False
    return any(f in text for f in forms(digest))


def _check_one_trial(trial_id: str, events: list[dict[str, Any]], *,
                     known_tools: set[str] | None, seen_ids: set[str]) -> list[str]:
    problems: list[str] = []
    by_id: dict[str, int] = {}
    children: dict[str, list[dict[str, Any]]] = {}
    exposed: set[str] | None = None
    prev_hash = GENESIS
    prev_ts: datetime | None = None

    for idx, ev in enumerate(events):
        where = f"{trial_id}[{idx}]"
        eid = ev.get("event_id")
        if isinstance(eid, str):
            where = eid
        if ev.get("seq") != idx or isinstance(ev.get("seq"), bool):
            problems.append(f"{where}: seq is {ev.get('seq')!r}, expected {idx} "
                            f"(seq must increase from 0 with no gaps)")
        if not isinstance(eid, str):
            problems.append(f"{where}: event_id must be a string")
        else:
            if eid in seen_ids:
                problems.append(f"{where}: duplicate event_id")
            seen_ids.add(eid)
            prefix, _, _ = eid.rpartition("#")
            if prefix != ev.get("trial_id"):
                problems.append(f"{where}: event_id names trial {prefix!r} but trial_id is "
                                f"{ev.get('trial_id')!r}")
            if isinstance(ev.get("seq"), int) and eid != f"{ev.get('trial_id')}#{ev['seq']:04d}":
                problems.append(f"{where}: event_id does not match '<trial_id>#<seq:04d>'")
        if ev.get("schema") != SCHEMA:
            problems.append(f"{where}: unknown schema {ev.get('schema')!r}")
        missing = [k for k in REQUIRED_FIELDS if k not in ev]
        if missing:
            problems.append(f"{where}: missing field(s) {missing}")
        etype = ev.get("type")
        if etype not in EVENT_TYPES:
            problems.append(f"{where}: unknown event type {etype!r}")
        if ev.get("actor") not in ACTORS:
            problems.append(f"{where}: unknown actor {ev.get('actor')!r}")

        ts = _parse_ts(ev.get("timestamp"))
        if ts is None:
            problems.append(f"{where}: timestamp {ev.get('timestamp')!r} is not timezone-aware ISO-8601")
        elif prev_ts is not None and ts < prev_ts:
            problems.append(f"{where}: timestamp goes backwards")
        prev_ts = ts or prev_ts

        # Hash chain. Reported per event so a reader sees WHERE the break is.
        if ev.get("prev_hash") != prev_hash:
            problems.append(f"{where}: hash chain break (prev_hash does not match the previous "
                            f"event's event_hash)")
        try:
            recomputed = event_hash(ev)
        except (TypeError, ValueError):
            recomputed = None
        if ev.get("event_hash") != recomputed:
            problems.append(f"{where}: event_hash mismatch: the event was altered after recording")
        prev_hash = ev.get("event_hash") if isinstance(ev.get("event_hash"), str) else ""

        if ev.get("redacted") is False and ev.get("content_ref") is None:
            try:
                if content_hash(ev.get("content")) != ev.get("content_sha256"):
                    problems.append(f"{where}: content_sha256 does not match unredacted content")
            except (TypeError, ValueError):
                problems.append(f"{where}: content is not canonical JSON")

        parents = ev.get("parents")
        if not isinstance(parents, list):
            problems.append(f"{where}: parents must be an array")
            parents = []
        for p in parents:
            if p in by_id:
                children.setdefault(p, []).append(ev)
            elif isinstance(p, str) and any(isinstance(e.get("event_id"), str)
                                            and e.get("event_id") == p for e in events[idx:]):
                problems.append(f"{where}: parent {p!r} is the event itself or a LATER event")
            else:
                problems.append(f"{where}: parent {p!r} does not exist in this trial")
        if isinstance(eid, str):
            by_id.setdefault(eid, idx)
        if etype == "tools_exposed":
            exposed = (exposed or set()) | _exposed_tools(ev.get("content"))

    def ancestors(ev: dict[str, Any]) -> list[dict[str, Any]]:
        out, stack, seen = [], list(ev.get("parents") or []), set()
        while stack:
            pid = stack.pop()
            if pid in seen or pid not in by_id:
                continue
            seen.add(pid)
            parent = events[by_id[pid]]
            out.append(parent)
            stack.extend(parent.get("parents") or [])
        return out

    def parent_types(ev: dict[str, Any]) -> set[Any]:
        return {events[by_id[p]].get("type") for p in (ev.get("parents") or []) if p in by_id}

    for ev in events:
        etype, where = ev.get("type"), ev.get("event_id", trial_id)
        if etype == "tool_call_requested":
            name = _tool_name(ev.get("content"))
            outcomes = {c.get("type") for c in children.get(ev.get("event_id"), [])}
            # A model that REQUESTS a tool it was never shown is real model behaviour (a
            # hallucinated name) and an honest trace must be able to record it, answered by a
            # tool_error or a block. What cannot happen is that call being EXECUTED: there was no
            # such tool to run, so a trace claiming otherwise disagrees with itself.
            if "tool_call_executed" in outcomes:
                for label, allowed in (("the known tool set", known_tools),
                                       ("tools_exposed", exposed)):
                    if allowed is not None and name not in allowed:
                        problems.append(f"{where}: executed tool {name!r} is not in {label}")
            if not outcomes & _REQUEST_OUTCOMES:
                problems.append(f"{where}: tool call requested but no execution outcome recorded "
                                f"(no tool_call_executed, tool_call_blocked or tool_error child)")
        elif etype in ("tool_call_executed", "tool_call_blocked"):
            if "tool_call_requested" not in parent_types(ev):
                problems.append(f"{where}: {etype} without a tool_call_requested parent")
        elif etype == "network_egress_attempted":
            if not any(a.get("type") == "tool_call_executed" for a in ancestors(ev)):
                problems.append(f"{where}: network egress without a tool_call_executed ancestor")
        elif etype == "egress_observed_at_sink":
            content = ev.get("content")
            independent = isinstance(content, dict) and content.get("observed_independently") is True
            if not independent and not any(a.get("type") == "network_egress_attempted"
                                           for a in ancestors(ev)):
                problems.append(f"{where}: sink observation without a network_egress_attempted "
                                f"ancestor (and not marked observed_independently)")
        elif etype == "validation":
            content = ev.get("content") if isinstance(ev.get("content"), dict) else {}
            if content.get("fired") is True:
                digest = content.get("canary_digest")
                if isinstance(digest, str) and digest:
                    requests = [e for e in events if e.get("type") == "tool_call_requested"]
                    if not any(_contains_digest(r.get("content"), digest) for r in requests):
                        problems.append(f"{where}: validation fired but no tool_call_requested "
                                        f"carries the canary digest")
                elif content.get("oracle") in (None, "canary"):
                    problems.append(f"{where}: validation fired on the canary oracle but names "
                                    f"no canary_digest")
    return problems


def check_trace(events: Iterable[dict[str, Any]], *, known_tools: Iterable[str] | None = None,
                expect_trial_id: str | None = None) -> list[str]:
    """Human-readable consistency problems in a trace; an empty list means consistent.

    ``events`` may span several trials (they are grouped by ``trial_id``). Consistency is a
    property of the record, not of the world: a consistent trace is one whose parts agree with
    each other, which an author can achieve for an invented trace as easily as for a real one.
    """
    events = list(events)
    problems: list[str] = []
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            problems.append(f"event[{i}] is not a JSON object")
    events = [e for e in events if isinstance(e, dict)]
    tools = set(known_tools) if known_tools is not None else None
    seen: set[str] = set()
    for tid, group in group_by_trial(events).items():
        if expect_trial_id is not None and tid != expect_trial_id:
            problems.append(f"trial {tid!r}: expected trial_id {expect_trial_id!r}")
        problems += _check_one_trial(tid, group, known_tools=tools, seen_ids=seen)
    return problems


# ------------------------------------------------------------------------- safe JSON I/O

def _reject_constant(name: str) -> Any:
    raise MalformedInput(f"non-finite number {name} is not valid JSON evidence")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            # Two parsers can disagree on which duplicate wins; evidence must be unambiguous.
            raise MalformedInput(f"duplicate JSON key {k!r}")
        out[k] = v
    return out


def strict_loads(text: str | bytes, *, where: str = "input") -> Any:
    """``json.loads`` that rejects NaN/Infinity and duplicate keys, raising ``MalformedInput``."""
    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        return json.loads(text, parse_constant=_reject_constant,
                          object_pairs_hook=_no_duplicate_keys)
    except UnicodeDecodeError:
        raise MalformedInput(f"{where}: not valid UTF-8") from None
    except json.JSONDecodeError as exc:
        raise MalformedInput(f"{where}: not valid JSON: {exc}") from None
    except RecursionError:
        raise MalformedInput(f"{where}: JSON nested too deeply") from None


def read_bounded(path: str | Path, *, max_bytes: int) -> bytes:
    """Read a regular file, refusing anything larger than ``max_bytes`` BEFORE reading it all."""
    p = Path(path)
    try:
        with p.open("rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        raise MalformedInput(f"cannot read {p}: {exc.strerror}") from None
    if len(data) > max_bytes:
        raise MalformedInput(f"{p}: larger than the {max_bytes}-byte cap")
    return data


def read_jsonl(path: str | Path, *, max_bytes: int = 50_000_000,
               max_line_bytes: int = 5_000_000) -> list[dict[str, Any]]:
    """Read a JSON Lines file defensively: size caps, one JSON object per line, no NaN.

    A blank line other than the trailing newline is rejected rather than skipped: silently
    tolerating gaps is how a truncated or spliced file ends up looking whole.
    """
    data = read_bounded(path, max_bytes=max_bytes)
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    out: list[dict[str, Any]] = []
    for n, raw in enumerate(lines, start=1):
        if len(raw) > max_line_bytes:
            raise MalformedInput(f"{path}:{n}: line longer than the {max_line_bytes}-byte cap")
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw.strip():
            raise MalformedInput(f"{path}:{n}: blank line")
        obj = strict_loads(raw, where=f"{path}:{n}")
        if not isinstance(obj, dict):
            raise MalformedInput(f"{path}:{n}: each line must be a JSON object")
        out.append(obj)
    return out


def write_jsonl(path: str | Path, events: Iterable[dict[str, Any]]) -> None:
    """Write one canonical JSON object per line (sorted keys, UTF-8, no NaN)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = b"".join(canonical(ev) + b"\n" for ev in events)
    p.write_bytes(body)


__all__ = ["SCHEMA", "EVENT_TYPES", "ACTORS", "GENESIS", "TraceRecorder", "check_trace",
           "read_jsonl", "write_jsonl", "group_by_trial", "canonical", "content_hash",
           "event_hash", "verify_content", "seal_chain", "strict_loads", "read_bounded"]
