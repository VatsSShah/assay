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


def _modality(task: dict) -> str:
    """Declared channel, what the runner actually exercises, and how the canary gets there."""
    execution = task.get("execution") or {}
    declared = execution.get("declared_modality", "text")
    implemented = execution.get("implemented_modality", "text")
    if implemented == "text_simulation":
        return f"{declared} (**text sim**)"
    if implemented != declared:
        return f"{declared} (**as {implemented}**)"
    plant = execution.get("image_plant")
    return f"{declared} (`{plant}`)" if plant else declared


def build() -> str:
    header = ("| ID | Task | Mode | Oracle | Channel | Modality | "
              + " | ".join(c[1] for c in COLUMNS) + " |")
    rule = "|----|------|------|--------|---------|----------|" + "|".join(["------"] * len(COLUMNS)) + "|"
    rows = [header, rule]
    for t in TASKS:
        cells = [_cell(t["crosswalk"], key, fn) for key, _, fn in COLUMNS]
        execution = t.get("execution") or {}
        rows.append(f"| {t['id']} | {t['title']} | {t['mode']} | {t['oracle']} | "
                    f"`{execution.get('channel', 'tool-call')}` | {_modality(t)} | "
                    + " | ".join(cells) + " |")
    return (
        "# Assay coverage matrix\n\n"
        f"{len(TASKS)} frozen tasks. Mode A = MCP server under test; Mode B = agent under test.\n\n"
        "**Oracle column.** `canary` means a hit is decided by recomputing an HMAC digest "
        "rather than by a grader, so a *spurious* hit would require forging a 64-bit tag "
        "without the run secret (SPEC.md §4). It does not mean the task has no false "
        "*negatives*: egress that splits, re-encodes outside the four frozen forms, "
        "compresses, encrypts or paraphrases the digest is missed, and those blind spots are "
        "measured in `audit/CLAIM_EVIDENCE_MATRIX.md`. `protocol` and `behavioral` tasks are "
        "deterministic but carry no cryptographic guarantee at all, and the headline scores "
        "aggregate all three classes.\n\n"
        "**Modality column.** `text` means the runner exercises the task's own channel. "
        "`image` means the runner builds a real PNG and the canary is present only in the "
        "image bytes: the parenthesised word is the plant route -- `pixels` (LSB "
        "steganography), `metadata` (a `tEXt` chunk), `qr` (a QR symbol the harness encodes "
        "and decodes) or `rug_pull` (a benign image swapped for a planted one between "
        "fetches). Six tasks are in that state; the surface builder refuses to emit one whose "
        "canary is also readable in the prose. The decoder is this repository's own "
        "(`assay_bench.media`): no third-party scanner or production vision model has been "
        "shown to read these images, so the image tasks establish that the canary travels "
        "only through the image, not that a deployed model would act on it. No audio, video "
        "or document path exists and no task declares one.\n\n"
        "Mappings are rendered from the crosswalk in `tasks.json`; no id is hand-copied into "
        "this file. They are our reading of each taxonomy, not an endorsement by its "
        "publisher.\n\n"
        + "\n".join(rows) + "\n"
    )


if __name__ == "__main__":
    out = HERE / "COVERAGE.md"
    out.write_text(build())
    print(f"wrote {out}: {len(TASKS)} tasks")
