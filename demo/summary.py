"""Print the demo's final state: artifacts, scores, verification levels, and SHA-256s."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import assay_verifier as V  # noqa: E402


def main(argv: list[str]) -> int:
    out = Path(argv[0] if argv else "out")
    rows = []
    for path in sorted(out.glob("*.json")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        try:
            result = V.verify_manifest(manifest)
            levels = ",".join(result["levels_verified"])
            verdict = "accepted"
        except V.VerifierError as exc:
            levels = f"REJECTED: {exc}"
            verdict = "rejected"
        rows.append((path.name, manifest.get("agent_resistance_score"), verdict, levels,
                     digest[:16]))

    width = max(len(r[0]) for r in rows) if rows else 10
    print(f"{'artifact'.ljust(width)}  {'agent':>6}  {'verdict':<9}  sha256")
    for name, score, verdict, levels, digest in rows:
        print(f"{name.ljust(width)}  {str(score):>6}  {verdict:<9}  {digest}...")
        print(f"{' ' * width}  {'':>6}  {levels}")
    print()
    print("Targets were built-in DETERMINISTIC conformance stubs. No live MCP server, agent")
    print("or model was involved, and none of these numbers describes a real product.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
