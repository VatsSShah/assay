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
ROOT = PKG.parent
CANONICAL = ROOT / "tasks.json"
PACKAGED = PKG / "data" / "tasks.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    check = "--check" in argv
    if not CANONICAL.is_file():
        print(f"canonical task set missing: {CANONICAL}", file=sys.stderr)
        return 3
    PACKAGED.parent.mkdir(parents=True, exist_ok=True)
    canonical_sha = _sha(CANONICAL)
    if check:
        if not PACKAGED.is_file():
            print(f"packaged copy missing: {PACKAGED}", file=sys.stderr)
            return 1
        packaged_sha = _sha(PACKAGED)
        if packaged_sha != canonical_sha:
            print(f"packaged task set is stale\n  {CANONICAL}: {canonical_sha}\n"
                  f"  {PACKAGED}: {packaged_sha}\nrun: python -m assay_bench.sync_data",
                  file=sys.stderr)
            return 1
        print(f"packaged task set is current ({canonical_sha[:16]}...)")
        return 0
    shutil.copyfile(CANONICAL, PACKAGED)
    print(f"synced {CANONICAL.name} -> {PACKAGED.relative_to(ROOT)} ({canonical_sha[:16]}...)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
