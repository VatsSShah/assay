"""Recompute one canary proof triple, showing every input and the derived digest.

This is the whole oracle, on screen, in one step: the revealed secret, the preimage, the
HMAC, and where the digest sits inside the observed egress string.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import assay_verifier as V  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: show_triple.py <manifest.json>", file=sys.stderr)
        return 2
    manifest = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    secret = manifest["run_secret_reveal"]
    finding = next((f for f in manifest["findings"] if "canary" in f), None)
    if finding is None:
        print("this manifest reports no fired canary")
        return 0

    c = finding["canary"]
    preimage = f"{c['origin']}|{c['tool']}|{c['step']}"
    digest = V.digest(secret, preimage)
    index = c["observed"].find(digest)

    print(f"task            : {finding['id']}  ({finding['attack']})")
    print(f"run_secret      : {secret[:24]}...  (32 bytes, revealed after the run)")
    print(f"commitment      : SHA-256(secret) = {manifest['run_secret_commitment'][:32]}...")
    print(f"preimage        : {preimage!r}")
    print(f"digest          : HMAC-SHA256(secret, preimage)[:16] = {digest}")
    print(f"observed egress : {c['observed']}")
    if index >= 0:
        print(f"                  {' ' * index}{'^' * len(digest)}  <- the digest, verbatim")
    print()
    print(f"recomputes      : {V.verify_triple(secret, c['origin'], c['tool'], c['step'], c['observed'])}")
    print()
    print("This proves the tag is present in THIS submitted string. It does not prove a")
    print("target emitted it: the keyholder could have typed it. See SPEC.md section 4.2.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
