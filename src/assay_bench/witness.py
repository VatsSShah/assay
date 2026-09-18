"""An egress witness: the structural answer to "a keyholder can fabricate a passing manifest".

Gap G2 is not a bug in the verifier. It is a property of who runs what. In a self-reported run
the submitter mints the run secret, plants the canaries, observes the egress and writes the
document — so they hold every input to the check, and a coherence check on a document cannot
distinguish a real run from a well-formed invention. `run_complete` forces a fabrication to
cover all 31 tasks, which raises the cost slightly and nothing more.

The fix is to move the adversarial side to a party the submitter does not control.

A **witness** is whoever operates the adversarial MCP server and the egress sink the target
leaks to. In a hosted deployment that is the leaderboard; in a client engagement it is the
assessor. The witness:

1. mints the run secret itself and never gives it to the submitter before the run;
2. plants the canaries, so the submitter cannot choose what they are;
3. observes egress at its *own* sink, so what reaches the record is what the target actually
   sent rather than what the submitter says it sent;
4. signs a statement naming the run, the target fingerprint, and which task ids fired;
5. publishes its Ed25519 public key.

Anyone can then check the signature without holding the key. A submitter cannot forge one,
because they never had it, and cannot invent a leak, because the digest they would have to
produce was never revealed to them.

**What this does and does not establish.**

It establishes that the named witness key signed *this* statement about *this* run. It does not
establish that the witness is honest, that the witness is independent of the submitter, or that
the key belongs to who you think. Those are questions about key custody and who you trust, and
no signature answers them: a submitter who runs their own witness has signed their own homework,
and the manifest says so through `witness.independent`, which is a declaration and not a proof.
The value is that a *third-party* witness becomes checkable rather than merely asserted, and
that a self-witnessed run is visibly self-witnessed.

`witnessed_egress` is therefore its own verification level, separate from
`canary_correspondence_verified`, and the verifier reports which key signed rather than
collapsing it to a verdict.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from . import ed25519
from .errors import MalformedInput, ValidationError

#: Schema of a witness statement. Versioned separately from the manifest, because the two move
#: for different reasons.
SCHEMA = "assay/witness-statement/1"

#: Domain separation. A signature over a witness statement must never be reusable as a signature
#: over anything else this project signs later, so every message starts with this tag.
DOMAIN = b"assay/witness-statement/1\x00"


def statement_bytes(statement: dict[str, Any]) -> bytes:
    """The exact bytes that are signed.

    Canonical JSON with sorted keys and no insignificant whitespace, prefixed with the domain
    tag. Signing a *rendering* rather than the object is what makes the signature checkable by
    someone who re-serialises the JSON differently.
    """
    body = {k: v for k, v in statement.items() if k != "signature"}
    return DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_statement(*, run_id: str, target_fingerprint: str, task_set_digest: str,
                    benchmark_version: str, fired_task_ids: list[str], trials_per_task: int,
                    run_secret_commitment: str, witness_name: str,
                    independent: bool, note: str = "") -> dict[str, Any]:
    """The unsigned statement. Everything in it is something the witness itself observed."""
    if not witness_name:
        raise ValidationError("a witness statement must name the witness")
    if not isinstance(fired_task_ids, list):
        raise MalformedInput("fired_task_ids must be an array")
    return {
        "schema": SCHEMA,
        "witness": witness_name,
        # A declaration, not a proof. A witness operated by the submitter is self-witnessing,
        # and saying so plainly is worth more than a signature that hides it.
        "independent": bool(independent),
        "run_id": run_id,
        "benchmark_version": benchmark_version,
        "task_set_digest": task_set_digest,
        "target_fingerprint": target_fingerprint,
        "trials_per_task": trials_per_task,
        "run_secret_commitment": run_secret_commitment,
        "fired_task_ids": sorted(set(fired_task_ids)),
        "note": note,
        "scope": (
            "The witness minted the run secret, planted the canaries and observed egress at its "
            "own sink, so the fired task ids here are what the witness saw rather than what the "
            "submitter reported. This does NOT establish that the witness is honest, that it is "
            "independent of the submitter, or that the signing key belongs to who you think. "
            "Those are questions of key custody and trust, and no signature answers them."),
    }


def sign_statement(statement: dict[str, Any], signing_key: bytes) -> dict[str, Any]:
    """Return the statement with a `signature` block attached."""
    public = ed25519.public_key(signing_key)
    signed = dict(statement)
    signed.pop("signature", None)
    signature = ed25519.sign(signing_key, statement_bytes(signed))
    signed["signature"] = {
        "algorithm": "ed25519",
        "public_key": public.hex(),
        "value": signature.hex(),
    }
    return signed


def verify_statement(statement: Any, *, expect_public_key: str | None = None) -> dict[str, Any]:
    """Check a witness statement's signature, and report what it does and does not show.

    `expect_public_key` is how a caller pins a witness they already trust. Without it, a valid
    signature says only that *whoever holds the key in the document* signed it -- which is worth
    reporting and worth not over-reading, so the result says so.
    """
    if not isinstance(statement, dict):
        raise MalformedInput("a witness statement must be a JSON object")
    for key in ("schema", "witness", "run_id", "target_fingerprint", "fired_task_ids",
                "signature"):
        if key not in statement:
            raise MalformedInput(f"witness statement missing {key!r}")
    if statement["schema"] != SCHEMA:
        raise ValidationError(f"unsupported witness schema {statement['schema']!r}")

    block = statement["signature"]
    if not isinstance(block, dict):
        raise MalformedInput("witness signature must be an object")
    for key in ("algorithm", "public_key", "value"):
        if key not in block:
            raise MalformedInput(f"witness signature missing {key!r}")
    if block["algorithm"] != "ed25519":
        raise ValidationError(f"unsupported signature algorithm {block['algorithm']!r}")
    try:
        public = bytes.fromhex(block["public_key"])
        signature = bytes.fromhex(block["value"])
    except (TypeError, ValueError):
        raise MalformedInput("witness signature fields must be hexadecimal") from None

    if expect_public_key is not None and block["public_key"].lower() != expect_public_key.lower():
        raise ValidationError(
            f"witness statement is signed by {block['public_key'][:16]}…, not by the pinned "
            f"key {expect_public_key[:16]}…")

    valid = ed25519.verify(public, statement_bytes(statement), signature)
    if not valid:
        raise ValidationError("witness signature does not verify")
    return {
        "witness": statement["witness"],
        "public_key": block["public_key"],
        "independent": bool(statement.get("independent")),
        "run_id": statement["run_id"],
        "fired_task_ids": list(statement["fired_task_ids"]),
        "pinned": expect_public_key is not None,
        "establishes": (
            "the holder of this key signed this statement about this run"
            if expect_public_key is None else
            "the pinned witness key signed this statement about this run"),
        "does_not_establish": (
            "that the witness is honest, that it is independent of the submitter, or that the "
            "key belongs to who you think. A self-witnessed run is marked independent=false."),
    }


def agrees_with_manifest(statement: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    """Differences between what the witness saw and what the manifest claims.

    An empty list means they agree. A non-empty one is the interesting case and must never be
    silently resolved in the manifest's favour: the whole point of a witness is that it is the
    side the submitter does not control.
    """
    problems: list[str] = []
    provenance = manifest.get("provenance") or {}
    if statement["run_id"] != provenance.get("run_id"):
        problems.append(
            f"run_id: witness says {statement['run_id']!r}, manifest says "
            f"{provenance.get('run_id')!r}")
    if statement["target_fingerprint"] != manifest.get("target_fingerprint"):
        problems.append(
            f"target_fingerprint: witness says {statement['target_fingerprint']!r}, manifest "
            f"says {manifest.get('target_fingerprint')!r}")
    commitment = statement.get("run_secret_commitment")
    if commitment and commitment != manifest.get("run_secret_commitment"):
        problems.append("run_secret_commitment: the witness committed to a different secret")

    witness_fired = set(statement["fired_task_ids"])
    manifest_fired = {f["id"] for f in manifest.get("findings", []) if f.get("fired")}
    only_witness = sorted(witness_fired - manifest_fired)
    only_manifest = sorted(manifest_fired - witness_fired)
    if only_witness:
        problems.append(
            f"the witness observed egress on {only_witness} that the manifest reports as "
            f"resisted; the submitter under-reported")
    if only_manifest:
        problems.append(
            f"the manifest claims {only_manifest} fired but the witness saw no egress for them; "
            f"the submitter over-reported")
    return problems


def commitment(run_secret: str) -> str:
    return hashlib.sha256(run_secret.encode()).hexdigest()


__all__ = ["SCHEMA", "DOMAIN", "statement_bytes", "build_statement", "sign_statement",
           "verify_statement", "agrees_with_manifest", "commitment"]
