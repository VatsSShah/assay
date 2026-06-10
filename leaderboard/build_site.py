"""Build the leaderboard, re-verify every entry's manifest, then render the board.

Anti-gaming: the verifier recomputes the score from the findings and re-checks every canary
proof (commitment binds the secret, every triple recomputes, integrity hash matches), so a score
cannot be inflated or self-reported. An entry whose manifest fails verification never reaches the board. Run
``python build_site.py`` to regenerate ``index.md``. Stdlib only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from assay_verifier import verify_manifest  # noqa: E402

SCORE_KEY = {"agent": "agent_resistance_score", "server": "server_posture_score"}


def _row(entry: dict) -> dict:
    manifest = json.loads((HERE / entry["manifest"]).read_text())
    verify_manifest(manifest)  # asserts; a bad manifest aborts the build, never silently passes
    return {
        "target": entry["target_name"],
        "track": entry["track"],
        "score": manifest[SCORE_KEY[entry["track"]]],
        "version": manifest["version"],
        "submitter": entry["submitter"],
        "date": entry["date"],
        "manifest": entry["manifest"],
        "notes": entry.get("notes", ""),
    }


def _table(rows: list[dict], track: str) -> str:
    kind = "Agent Resistance" if track == "agent" else "Server Posture"
    picked = sorted([r for r in rows if r["track"] == track], key=lambda r: -r["score"])
    lines = [f"### {kind} (Mode {'B' if track == 'agent' else 'A'})", "",
             "| Rank | Target | Score | Assay | Submitter | Proof | Notes |",
             "|------|--------|-------|-------|-----------|-------|-------|"]
    for i, r in enumerate(picked, 1):
        lines.append(f"| {i} | {r['target']} | **{r['score']}** | v{r['version']} | "
                     f"{r['submitter']} | [manifest]({r['manifest']}) | {r['notes']} |")
    return "\n".join(lines)


def build() -> str:
    entries = json.loads((HERE / "entries.json").read_text())
    rows = [_row(e) for e in entries]
    return (
        "# Assay leaderboard\n\n"
        "Every row links to a manifest with re-verifiable canary triples. The verifier recomputes "
        "the score from the findings, so it cannot be self-reported; a maintainer re-runs the target. "
        "Submit via PR (see [SUBMIT.md](SUBMIT.md)); a maintainer re-runs before merge.\n\n"
        + _table(rows, "agent") + "\n\n" + _table(rows, "server") + "\n"
    )


if __name__ == "__main__":
    out = HERE / "index.md"
    out.write_text(build())
    print(f"wrote {out}, {len(json.loads((HERE / 'entries.json').read_text()))} entries verified")
