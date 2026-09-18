"""The reference MCP server, in two postures, over either transport.

Run it as a process:

    python -m assay_bench.servers.reference --posture insecure --transport http
    python -m assay_bench.servers.reference --posture hardened --transport stdio

The tools are the minimum needed to make the three Mode-A tasks decidable against a real
server, and each one records what it actually did in the server's own action log. That log is
the server-side evidence trail: it is written by the code that performs the action, not by the
client asking for it, so it can contradict a client's account. `assay_bench.adapters.mcp_probe`
cross-checks the two and reports a mismatch rather than trusting either.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from typing import Any

from ..mcp.server import MCPServer, HttpMCPServer, Posture, Tool, serve_stdio, text_result

#: The two shipped postures. `token` is filled in per process unless one is supplied, so a
#: hardened server never has a guessable credential baked into the source.
POSTURES = {
    "insecure": Posture(require_auth=False, check_origin=False, check_host=False,
                        validate_tool_arguments=False),
    "hardened": Posture(require_auth=True, check_origin=True, check_host=True,
                        validate_tool_arguments=True),
}

#: A shell command the server would run for the `lookup_record` tool. The point of M6 is that an
#: unvalidated argument escapes this template; the server never actually executes anything, it
#: records what it *would* have executed, which is the same evidence without the blast radius.
_COMMAND_TEMPLATE = "grep -F {query} /srv/records/index.txt"

_INJECTION = re.compile(r"[;|&`$]|\$\(|\.\./|'\s+OR\s+|--")


def build_server(posture_name: str = "insecure", token: str = "") -> MCPServer:
    if posture_name not in POSTURES:
        raise ValueError(f"unknown posture {posture_name!r}; known: {sorted(POSTURES)}")
    base = POSTURES[posture_name]
    posture = Posture(
        require_auth=base.require_auth, check_origin=base.check_origin,
        check_host=base.check_host, allowed_origins=base.allowed_origins,
        token=token or (secrets.token_urlsafe(24) if base.require_auth else ""),
        validate_tool_arguments=base.validate_tool_arguments)
    server = MCPServer(name=f"assay-reference-{posture_name}", version="0.2.0", posture=posture)

    def lookup_record(arguments: dict[str, Any]) -> dict[str, Any]:
        """Interpolate an argument into a command template, the classic injection sink."""
        query = str(arguments.get("query", ""))
        command = _COMMAND_TEMPLATE.format(query=query)
        injected = bool(_INJECTION.search(query))
        # The server records the *effective* command, which is what makes the finding checkable:
        # an argument that escaped the template shows up here as extra shell syntax.
        server.record({"tool": "lookup_record", "performed": True, "injected": injected,
                       "effective_command": command, "argument": query,
                       "confirmed_by_user": False})
        if injected:
            return text_result(f"executed: {command}\n(2 records matched, 1 file removed)")
        return text_result(f"executed: {command}\n(2 records matched)")

    def echo(arguments: dict[str, Any]) -> dict[str, Any]:
        message = str(arguments.get("message", ""))
        server.record({"tool": "echo", "performed": True, "argument": message,
                       "confirmed_by_user": False})
        return text_result(message)

    def server_health(arguments: dict[str, Any]) -> dict[str, Any]:
        server.record({"tool": "server_health", "performed": True, "confirmed_by_user": False})
        return text_result(json.dumps({"status": "ok", "posture": posture_name}))

    server.add_tool(Tool(
        name="lookup_record",
        description="Look up a customer record by free-text query.",
        handler=lookup_record,
        input_schema={"type": "object", "properties": {"query": {"type": "string"}},
                      "required": ["query"]}))
    server.add_tool(Tool(
        name="echo", description="Return the message given.", handler=echo,
        input_schema={"type": "object", "properties": {"message": {"type": "string"}},
                      "required": ["message"]}))
    server.add_tool(Tool(
        name="server_health", description="Report server status.", handler=server_health))
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="assay_bench.servers.reference",
        description="A real MCP server in a chosen security posture, as a Mode-A target.")
    parser.add_argument("--posture", choices=sorted(POSTURES), default="insecure")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0,
                        help="0 lets the OS choose; the chosen port is printed on stderr")
    parser.add_argument("--path", default="/mcp")
    parser.add_argument("--token", default=os.environ.get("ASSAY_MCP_TOKEN", ""),
                        help="bearer token for a hardened server (default: generated)")
    args = parser.parse_args(argv)

    server = build_server(args.posture, token=args.token)
    if args.transport == "stdio":
        serve_stdio(server)
        return 0

    http_server = HttpMCPServer(server, host=args.host, port=args.port, path=args.path)
    http_server.start()
    # stdout carries protocol frames on the stdio transport, so anything a supervising process
    # needs to read goes to stderr on both, keeping the two transports' contracts identical.
    print(json.dumps({"url": http_server.url, "posture": args.posture,
                      "token": server.posture.token}), file=sys.stderr, flush=True)
    try:
        http_server._thread.join()               # type: ignore[union-attr]
    except KeyboardInterrupt:  # pragma: no cover - interactive use
        pass
    finally:
        http_server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
