"""JSON-RPC 2.0, as MCP uses it.

MCP is JSON-RPC 2.0 with two framings: stdio delimits messages by newline (so a message may
never contain an unescaped newline), and Streamable HTTP puts one message in a POST body. Both
carry exactly the same objects, which is why the framing lives here with the objects rather
than in each transport.

Nothing here is MCP-specific beyond the version constant; the MCP semantics -- `initialize`,
`tools/list`, `tools/call` -- are in :mod:`assay_bench.mcp.client`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

JSONRPC_VERSION = "2.0"

#: The standard JSON-RPC 2.0 error codes. MCP adds its own above -32000; a server is free to
#: use application codes there and this client passes them through untouched.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class JsonRpcError(Exception):
    """An error *returned by the peer*, distinct from a transport or decoding failure.

    The distinction matters to the harness: a peer that answers "method not found" is alive and
    speaking the protocol, which is a protocol fact; a socket that closes is a transport
    failure, which makes a trial inconclusive rather than resisted.
    """

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            out["data"] = self.data
        return out


@dataclass
class Request:
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    id: int | str = 0

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": self.id, "method": self.method}
        if self.params:
            out["params"] = self.params
        return out


@dataclass
class Notification:
    """A request with no id, to which the peer must not reply."""

    method: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": self.method}
        if self.params:
            out["params"] = self.params
        return out


@dataclass
class Response:
    id: int | str | None
    result: Any = None
    error: JsonRpcError | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": self.id}
        if self.error is not None:
            out["error"] = self.error.to_json()
        else:
            out["result"] = self.result if self.result is not None else {}
        return out

    def raise_for_error(self) -> Any:
        if self.error is not None:
            raise self.error
        return self.result


class ProtocolViolation(Exception):
    """The peer sent something that is not a well-formed JSON-RPC 2.0 message.

    Separate from :class:`JsonRpcError` on purpose. A malformed frame means the thing on the
    other end is not speaking the protocol, which is a different observation from a peer that
    speaks it and refuses.
    """


def encode_message(message: Request | Notification | Response) -> bytes:
    """Serialise one message. No embedded newline: the stdio framing forbids it.

    `separators` removes insignificant whitespace and `ensure_ascii` escapes every non-ASCII
    character, which together guarantee a single-line frame for any input.
    """
    text = json.dumps(message.to_json(), separators=(",", ":"), ensure_ascii=True)
    if "\n" in text:  # pragma: no cover - ensure_ascii makes this unreachable
        raise ProtocolViolation("encoded message contains a newline")
    return text.encode("ascii")


def decode_message(raw: bytes | str) -> Response | Request | Notification:
    """Parse one message, validating the envelope the way a strict peer would.

    A lenient parser here would let a non-compliant server look compliant, which is the exact
    failure mode the Mode-A tasks exist to detect.
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolViolation(f"message is not valid UTF-8: {exc}") from None
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolViolation(f"message is not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise ProtocolViolation(f"message is a JSON {type(doc).__name__}, not an object")
    if doc.get("jsonrpc") != JSONRPC_VERSION:
        raise ProtocolViolation(f"jsonrpc field is {doc.get('jsonrpc')!r}, not {JSONRPC_VERSION!r}")

    has_id = "id" in doc
    if "method" in doc:
        method = doc["method"]
        if not isinstance(method, str):
            raise ProtocolViolation("method must be a string")
        params = doc.get("params", {})
        if not isinstance(params, dict):
            # JSON-RPC allows positional params; MCP does not use them, and accepting them
            # would mean guessing names later.
            raise ProtocolViolation("params must be an object (MCP does not use positional params)")
        if has_id:
            return Request(method=method, params=params, id=doc["id"])
        return Notification(method=method, params=params)

    if not has_id:
        raise ProtocolViolation("a response must carry an id")
    if "error" in doc:
        err = doc["error"]
        if not isinstance(err, dict) or "code" not in err or "message" not in err:
            raise ProtocolViolation("error must be an object with code and message")
        if not isinstance(err["code"], int):
            raise ProtocolViolation("error code must be an integer")
        return Response(id=doc["id"], error=JsonRpcError(err["code"], err["message"],
                                                         err.get("data")))
    if "result" not in doc:
        raise ProtocolViolation("a response must carry either result or error")
    return Response(id=doc["id"], result=doc["result"])
