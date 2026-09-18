"""Keep the packaged copy of the frozen task set byte-identical to the canonical one.

``tasks.json`` at the repository root is canonical. The wheel needs its own copy so an
installed ``assay`` can bind findings to the catalog without a source checkout. Rather than
letting two files drift, this module copies root -> package and CI runs it followed by
``git diff --exit-code``, so a stale copy fails the build.

    python -m assay_bench.sync_data            # copy and report
    python -m assay_bench.sync_data --check    # verify only; non-zero if stale
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent
ROOT = PKG.parent.parent          # src/assay_bench -> src -> repository root
#: Canonical -> packaged. Both files are needed by an installed copy: the catalog to bind
#: findings to frozen tasks, the schema so the published contract travels with the code.
SYNCED = {
    ROOT / "tasks.json": PKG / "data" / "tasks.json",
    ROOT / "manifest_schema.json": PKG / "data" / "manifest_schema.json",
    # The twin set travels too: without it an installed copy silently has no utility axis and
    # reports over_refusal_rate: null, which reads as "refused nothing".
    ROOT / "twins.json": PKG / "data" / "twins.json",
}
CANONICAL = ROOT / "tasks.json"
PACKAGED = PKG / "data" / "tasks.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    check = "--check" in argv
    stale: list[str] = []
    for canonical, packaged in SYNCED.items():
        if not canonical.is_file():
            print(f"canonical file missing: {canonical}", file=sys.stderr)
            return 3
        packaged.parent.mkdir(parents=True, exist_ok=True)
        canonical_sha = _sha(canonical)
        if check:
            if not packaged.is_file() or _sha(packaged) != canonical_sha:
                stale.append(f"  {canonical.name}: {canonical_sha[:16]} != "
                             f"{_sha(packaged)[:16] if packaged.is_file() else 'MISSING'}")
            continue
        shutil.copyfile(canonical, packaged)
        print(f"synced {canonical.name} -> {packaged.relative_to(ROOT)} "
              f"({canonical_sha[:16]}...)")
    if check:
        if stale:
            print("packaged data is stale:\n" + "\n".join(stale)
                  + "\nrun: python -m assay_bench.sync_data", file=sys.stderr)
            return 1
        print(f"packaged data is current ({len(SYNCED)} file(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
