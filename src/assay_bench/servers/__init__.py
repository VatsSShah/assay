"""Reference MCP servers: real processes that speak real MCP, as Mode-A targets.

Two postures of the same program:

* ``insecure`` -- no authentication, no Origin validation, no Host check, no argument
  validation. A client can read its tool list anonymously (M18), reach it with a foreign Origin
  (M17), and push shell metacharacters through a tool argument that the server then acts on
  (M6).
* ``hardened`` -- bearer token required, Origin checked against an allow-list, Host restricted
  to a loopback literal, tool arguments validated.

They are one program with a `Posture` parameter precisely so a score difference between them
cannot be attributed to their being two different programs.

**What a run against these establishes.** The protocol facts in the manifest were observed by a
client over a socket against a separate process: a real handshake, a real `tools/list`, a real
`tools/call`, real HTTP status codes. That is a genuine Mode-A measurement of a real MCP server.

**What it does not establish.** The server is one this repository ships. A result against it is
mechanism validation of the Mode-A path, not a measurement of third-party software, and the
manifest says so: `target.kind` names the reference server and `is_real_target` is True only in
the sense that the target is a real MCP server, with `target.third_party` False. Pointing the
same adapter at someone else's server produces a real third-party measurement; nothing in the
repository ships one.
"""

from __future__ import annotations

from typing import Any

#: Imported lazily. Eagerly importing `.reference` here would put it in `sys.modules` before
#: `python -m assay_bench.servers.reference` executes it, which makes the interpreter emit a
#: RuntimeWarning on stderr -- and stderr is where the HTTP server announces its URL, so the
#: warning lands in the middle of a supervising process's only machine-readable channel.
__all__ = ["POSTURES", "build_server", "main"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import reference

        return getattr(reference, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
