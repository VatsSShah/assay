"""Render COVERAGE.md, every frozen task mapped to the recognised MCP taxonomies.

Reads the frozen tasks.json (the baked-in, already-verified crosswalk) and writes a
skimmable matrix. Stdlib only; run ``python coverage.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).parent
TASKS = json.loads((HERE / "tasks.json").read_text())["tasks"]

# (crosswalk key, column header, how to shorten an entry to its leading id)
COLUMNS = [
    ("owasp_mcp_top10", "OWASP MCP", lambda e: e.split(":")[0]),
    ("adversa_mcp_top25", "Adversa-25", lambda e: (m.group() if (m := re.search(r"#\d+", e)) else e)),
    ("owasp_agentic_asi", "OWASP ASI", lambda e: e.split(":")[0]),
    ("mitre_atlas", "MITRE ATLAS", lambda e: e.split(" ")[0]),
]


def _cell(crosswalk: dict, key: str, shorten) -> str:
    entries = crosswalk.get(key, [])
    return ", ".join(shorten(e) for e in entries) if entries else "-"


def build() -> str:
    header = "| ID | Task | Mode | Oracle | " + " | ".join(c[1] for c in COLUMNS) + " |"
    rule = "|----|------|------|--------|" + "|".join(["------"] * len(COLUMNS)) + "|"
    rows = [header, rule]
    for t in TASKS:
        cells = [_cell(t["crosswalk"], key, fn) for key, _, fn in COLUMNS]
        rows.append(f"| {t['id']} | {t['title']} | {t['mode']} | {t['oracle']} | " + " | ".join(cells) + " |")
    return (
        "# Assay coverage matrix\n\n"
        f"{len(TASKS)} frozen tasks. Mode A = MCP server under test; Mode B = agent under test. "
        "Oracle `canary` = structural-zero-FP cryptographic proof. Mappings are rendered from the "
        "engine's verified crosswalk, no id is hand-copied.\n\n"
        + "\n".join(rows) + "\n"
    )


if __name__ == "__main__":
    out = HERE / "COVERAGE.md"
    out.write_text(build())
    print(f"wrote {out}: {len(TASKS)} tasks")
