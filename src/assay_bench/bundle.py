"""Tamper-evident experiment bundles, and an offline verifier anyone can run.

An experiment directory holds the manifest, per-configuration scorecards, raw trial logs and
traces. ``build_index`` hashes every file into ``artifact_index.json``; ``sign_index``
optionally signs that index with Ed25519; ``verify_bundle`` re-derives everything it can from
the files alone -- hashes, sizes, path safety, cross-file agreement on ids and counts, trace
consistency, scorecard verification, signature, witness receipts -- and reports each named
check separately rather than collapsing them into a verdict.

**What this establishes, and what it does not.**

A passing verification establishes that the files are exactly the ones the index lists, that
they agree with each other, and -- if signed -- that the holder of the signing key vouches for
this index. That is *integrity relative to the signer*. It is NOT proof that the experiment
occurred, that the model was the one named, or that nothing was left out before indexing: an
author can fabricate a whole directory and index and sign it. Only an independent witness
(``witness_receipt.py``) or an independent rerun narrows that gap, and the verifier reports the
witness check separately for that reason. An unsigned index is weaker still: anyone able to
rewrite the directory can rewrite the index.

The verifier never contacts the network and never executes anything in the bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from . import ed25519
from .errors import MalformedInput, UsageError, ValidationError
from .trace import canonical, check_trace, group_by_trial, read_bounded, read_jsonl, strict_loads

INDEX_SCHEMA = "assay/artifact-index/1"
SIGNATURE_SCHEMA = "assay/artifact-signature/1"
INDEX_NAME = "artifact_index.json"
SIGNATURE_NAME = "artifact_index.sig.json"

#: Domain separation: a signature over an index is never valid over anything else Assay signs.
DOMAIN = b"assay/artifact-index/1\x00"

#: Per-file cap for hashing. Module-level so a test can lower it rather than write 200 MB.
MAX_FILE_BYTES = 200 * 1024 * 1024
#: Cap on any JSON document that is parsed (the index, the manifest, scorecards, trial logs).
MAX_JSON_BYTES = 50_000_000
#: Cap on the index itself; an index is small, and a huge one is an attack on the verifier.
MAX_INDEX_BYTES = 20_000_000

INDEX_NOTE = ("integrity relative to whoever produced/signed this index; not proof the "
              "experiment occurred")

ESTABLISHES = ("the files are exactly those the index lists and agree with each other; if "
               "signed, the holder of the signing key vouches for this index")
DOES_NOT_ESTABLISH = ("that the experiment occurred, that the named model was the one queried, "
                      "or that nothing was omitted before indexing: an author can fabricate, "
                      "index and sign a whole directory. Only independent witness receipts or "
                      "an independent rerun narrow that gap")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EXPERIMENT_ID = re.compile(r"^exp-\d{8}-[0-9a-f]{8}$")


# ------------------------------------------------------------------------- paths

def safe_join(root: str | os.PathLike[str], relpath: Any) -> Path:
    """Resolve ``relpath`` under ``root``, refusing anything that could escape it.

    Rejects non-strings, empty paths, NUL bytes, backslashes (ambiguous across platforms),
    absolute paths, drive letters, ``.``/``..``/empty components, and any path whose resolved
    location -- after following symlinks -- lies outside ``root``.
    """
    if not isinstance(relpath, str) or not relpath:
        raise ValidationError(f"unsafe path {relpath!r}: must be a non-empty string")
    if "\x00" in relpath or "\\" in relpath:
        raise ValidationError(f"unsafe path {relpath!r}: NUL or backslash")
    if relpath.startswith("/") or re.match(r"^[A-Za-z]:", relpath):
        raise ValidationError(f"unsafe path {relpath!r}: absolute")
    parts = relpath.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValidationError(f"unsafe path {relpath!r}: empty, '.' or '..' component")
    base = Path(root).resolve()
    target = base.joinpath(*parts)
    resolved = target.resolve()
    if resolved != base and base not in resolved.parents:
        raise ValidationError(f"unsafe path {relpath!r}: resolves outside the bundle (symlink?)")
    return target


def _walk(root: Path) -> tuple[list[str], list[str]]:
    """(regular files, symlinks/specials) under root as POSIX relpaths. Never follows links."""
    files, odd = [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        for d in list(dirnames):
            if (here / d).is_symlink():
                odd.append((here / d).relative_to(root).as_posix())
                dirnames.remove(d)
        for f in filenames:
            p = here / f
            rel = p.relative_to(root).as_posix()
            (files if p.is_file() and not p.is_symlink() else odd).append(rel)
    return sorted(files), sorted(odd)


def _file_digest(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            n += len(chunk)
            if n > MAX_FILE_BYTES:
                raise ValidationError(f"{path.name}: larger than the {MAX_FILE_BYTES}-byte cap")
            h.update(chunk)
    return h.hexdigest(), n


# ------------------------------------------------------------------------- build & sign

def build_index(bundle_dir: str | os.PathLike[str], *, experiment_id: str) -> dict[str, Any]:
    """Hash every file in the bundle into ``artifact_index.json`` and return the index.

    Refuses symlinks and special files: their content is not something a hash of "this file"
    can pin down. Any existing signature is deleted, because it was over a previous index and
    would only fail verification confusingly.
    """
    root = Path(bundle_dir)
    if not root.is_dir():
        raise UsageError(f"{root} is not a directory")
    if not isinstance(experiment_id, str) or not _EXPERIMENT_ID.match(experiment_id):
        raise ValidationError(f"experiment_id {experiment_id!r} does not match exp-YYYYMMDD-xxxxxxxx")
    files, odd = _walk(root)
    if odd:
        raise ValidationError(f"refusing to index symlinks or special files: {odd[:5]}")
    entries = []
    for rel in files:
        if rel in (INDEX_NAME, SIGNATURE_NAME):
            continue
        digest, size = _file_digest(root / rel)
        entries.append({"path": rel, "sha256": digest, "bytes": size})
    index = {
        "schema": INDEX_SCHEMA,
        "experiment_id": experiment_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": entries,
        "note": INDEX_NOTE,
    }
    (root / SIGNATURE_NAME).unlink(missing_ok=True)
    (root / INDEX_NAME).write_text(json.dumps(index, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
    return index


def index_sha256(index: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(index)).hexdigest()


def signature_message(index: dict[str, Any]) -> bytes:
    """The exact signed bytes: domain tag + canonical JSON of the index."""
    return DOMAIN + canonical(index)


def _load_index(root: Path) -> dict[str, Any]:
    path = root / INDEX_NAME
    if path.is_symlink() or not path.is_file():
        raise MalformedInput(f"{path}: no artifact index (run build_index / sign-artifacts --build-index)")
    doc = strict_loads(read_bounded(path, max_bytes=MAX_INDEX_BYTES), where=str(path))
    if not isinstance(doc, dict):
        raise MalformedInput(f"{path}: the index must be a JSON object")
    return doc


def sign_index(bundle_dir: str | os.PathLike[str], signing_key: bytes, *,
               signer: str) -> dict[str, Any]:
    """Sign ``artifact_index.json`` and write ``artifact_index.sig.json``.

    The signature binds the signer to the index, and through its hashes to every file. It says
    nothing about whether the experiment those files describe happened: a signature is a
    statement of who vouches, not evidence of what occurred.
    """
    if not isinstance(signer, str) or not signer:
        raise ValidationError("signer must be a non-empty name")
    if not isinstance(signing_key, bytes) or len(signing_key) != ed25519.KEY_SIZE:
        raise ValidationError(f"signing key must be {ed25519.KEY_SIZE} bytes")
    root = Path(bundle_dir)
    index = _load_index(root)
    problems = _index_structure(index)
    if problems:
        raise ValidationError("refusing to sign a malformed index: " + "; ".join(problems[:3]))
    unsafe, mismatch, oversize, _bad = _check_files(root, index)
    stale = unsafe + mismatch + oversize
    if stale:
        raise ValidationError("refusing to sign: the index does not match the directory ("
                              + "; ".join(stale[:3]) + "); rebuild it first")
    public = ed25519.public_key(signing_key)
    sig = {
        "schema": SIGNATURE_SCHEMA,
        "algorithm": "ed25519",
        "public_key": public.hex(),
        "value": ed25519.sign(signing_key, signature_message(index)).hex(),
        "signer": signer,
        "index_sha256": index_sha256(index),
    }
    (root / SIGNATURE_NAME).write_text(json.dumps(sig, indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8")
    return sig


# ------------------------------------------------------------------------- verification

def _check(name: str, ok: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def _summarise(problems: list[str], ok_detail: str, limit: int = 8) -> tuple[bool, str]:
    if not problems:
        return True, ok_detail
    more = f" (+{len(problems) - limit} more)" if len(problems) > limit else ""
    return False, "; ".join(problems[:limit]) + more


def _index_structure(index: dict[str, Any]) -> list[str]:
    problems = []
    if index.get("schema") != INDEX_SCHEMA:
        problems.append(f"schema is {index.get('schema')!r}, expected {INDEX_SCHEMA!r}")
    if not isinstance(index.get("experiment_id"), str) or not _EXPERIMENT_ID.match(
            index.get("experiment_id") or ""):
        problems.append(f"experiment_id {index.get('experiment_id')!r} is not exp-YYYYMMDD-xxxxxxxx")
    if not isinstance(index.get("created_at"), str):
        problems.append("created_at must be a string")
    files = index.get("files")
    if not isinstance(files, list):
        return problems + ["files must be an array"]
    paths = []
    for i, entry in enumerate(files):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            problems.append(f"files[{i}] must be an object with exactly path, sha256, bytes")
            continue
        if not isinstance(entry["path"], str):
            problems.append(f"files[{i}].path must be a string")
            continue
        paths.append(entry["path"])
        if not isinstance(entry["sha256"], str) or not _HEX64.match(entry["sha256"]):
            problems.append(f"{entry['path']}: sha256 {entry['sha256']!r} is not 64 lowercase hex")
        b = entry["bytes"]
        if isinstance(b, bool) or not isinstance(b, int) or b < 0:
            problems.append(f"{entry['path']}: bytes must be a non-negative integer")
        if entry["path"] in (INDEX_NAME, SIGNATURE_NAME):
            problems.append(f"{entry['path']}: the index may not list itself or its signature")
    if paths != sorted(paths):
        problems.append("files are not sorted by path")
    if len(set(paths)) != len(paths):
        problems.append("files lists a path more than once")
    return problems


def _check_files(root: Path, index: dict[str, Any]
                 ) -> tuple[list[str], list[str], list[str], set[str]]:
    """(unsafe paths, hash/size/existence mismatches, size-cap violations, every bad path)."""
    unsafe, mismatch, oversize = [], [], []
    bad: set[str] = set()
    for entry in index.get("files") or []:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("path")
        try:
            path = safe_join(root, rel)
        except ValidationError as exc:
            unsafe.append(str(exc))
            bad.add(rel)
            continue
        if path.is_symlink() or not path.is_file():
            mismatch.append(f"{rel}: listed but missing (or not a regular file)")
            bad.add(rel)
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            oversize.append(f"{rel}: {size} bytes exceeds the {MAX_FILE_BYTES}-byte cap")
            bad.add(rel)
            continue
        try:
            digest, n = _file_digest(path)
        except ValidationError as exc:
            oversize.append(f"{rel}: {exc}")
            bad.add(rel)
            continue
        if n != entry.get("bytes"):
            mismatch.append(f"{rel}: size {n} != indexed {entry.get('bytes')}")
            bad.add(rel)
        if digest != entry.get("sha256"):
            mismatch.append(f"{rel}: sha256 does not match the index (file modified)")
            bad.add(rel)
    return unsafe, mismatch, oversize, bad


def _load_member(root: Path, rel: str, listed: set[str]) -> Any:
    """Parse a JSON member, but only one the index lists: unlisted bytes are never trusted."""
    if rel not in listed:
        raise ValidationError(f"{rel}: not listed in the index")
    path = safe_join(root, rel)
    if not path.is_file():
        raise ValidationError(f"{rel}: missing")
    return strict_loads(read_bounded(path, max_bytes=MAX_JSON_BYTES), where=rel)


def _verify_signature(root: Path, index: dict[str, Any], *, expect_public_key: str | None,
                      require_signature: bool) -> dict[str, Any]:
    path = root / SIGNATURE_NAME
    if not path.exists():
        if require_signature or expect_public_key:
            return _check("signature", False, "no artifact_index.sig.json, but a signature was "
                                              "required" + (" (a key was pinned)" if expect_public_key else ""))
        return _check("signature", True, "unsigned: integrity holds only against accidental "
                                         "change; anyone able to rewrite the directory can "
                                         "rewrite the index")
    sig = strict_loads(read_bounded(path, max_bytes=1_000_000), where=SIGNATURE_NAME)
    if not isinstance(sig, dict):
        raise MalformedInput(f"{SIGNATURE_NAME}: must be a JSON object")
    problems = []
    if sig.get("schema") != SIGNATURE_SCHEMA:
        problems.append(f"schema is {sig.get('schema')!r}")
    if sig.get("algorithm") != "ed25519":
        problems.append(f"unsupported algorithm {sig.get('algorithm')!r}")
    pk, value = sig.get("public_key"), sig.get("value")
    if not (isinstance(pk, str) and _HEX64.match(pk)):
        problems.append("public_key must be 64 lowercase hex")
    if not (isinstance(value, str) and re.match(r"^[0-9a-f]{128}$", value)):
        problems.append("value must be 128 lowercase hex")
    if sig.get("index_sha256") != index_sha256(index):
        problems.append("index_sha256 does not match the index (index changed after signing)")
    if not problems and not ed25519.verify(bytes.fromhex(pk), signature_message(index),
                                           bytes.fromhex(value)):
        problems.append("Ed25519 signature does not verify over this index")
    if expect_public_key is not None and isinstance(pk, str) \
            and pk.lower() != expect_public_key.strip().lower():
        problems.append(f"signed by {pk[:16]}..., not by the pinned key "
                        f"{expect_public_key.strip()[:16]}...")
    if problems:
        return _check("signature", False, "; ".join(problems))
    who = f"{sig.get('signer')!r} key {pk[:16]}..."
    return _check("signature", True,
                  (f"valid signature by the pinned key ({who})" if expect_public_key else
                   f"valid signature by {who}, which was NOT pinned: it shows only that whoever "
                   f"holds this key signed this index")
                  + "; integrity relative to the signer, not proof the experiment occurred")


def _configurations(listed: set[str], manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """name -> {scorecard, trials, traces, run} from the index and the manifest's runs."""
    out: dict[str, dict[str, Any]] = {}
    for rel in listed:
        parts = PurePosixPath(rel).parts
        if len(parts) == 3 and parts[0] == "configurations":
            out.setdefault(parts[1], {})[parts[2]] = rel
    runs = (manifest or {}).get("runs")
    for run in runs if isinstance(runs, list) else []:
        if isinstance(run, dict) and isinstance(run.get("configuration"), str):
            out.setdefault(run["configuration"], {})["run"] = run
    return out


def verify_bundle(bundle_dir: str | os.PathLike[str], *, expect_public_key: str | None = None,
                  require_signature: bool = False, expect_commit: str | None = None,
                  trusted_witness_keys: Any = None) -> dict[str, Any]:
    """Verify an experiment bundle offline and report every named check.

    Returns ``{"ok", "checks": [{"name", "ok", "detail"}], "experiment_id", ...}``. ``ok`` is
    true only if every check passed. Raises ``MalformedInput`` only when the index or its
    signature cannot be parsed at all; everything else is reported as a failed check, so a
    reader sees all the problems at once rather than the first.

    ``trusted_witness_keys`` (a loaded mapping or a path) overrides ``witness/trusted_keys.json``
    -- which, being inside the bundle, is the author's own claim about whom to trust.
    """
    root = Path(bundle_dir)
    if not root.is_dir():
        raise MalformedInput(f"{root} is not a directory")
    index = _load_index(root)
    checks: list[dict[str, Any]] = []
    add = checks.append

    structure = _index_structure(index)
    add(_check("index_schema", *_summarise(structure, f"{INDEX_SCHEMA}, "
                                                      f"{len(index.get('files') or [])} files")))
    unsafe, mismatch, oversize, bad = _check_files(root, index)
    add(_check("path_safety", *_summarise(unsafe, "every indexed path stays inside the bundle")))
    add(_check("size_caps", *_summarise(oversize, f"every file is within {MAX_FILE_BYTES} bytes")))
    add(_check("files_match_index", *_summarise(mismatch, "every listed file exists with the "
                                                          "indexed size and sha256")))
    listed = {e["path"] for e in index.get("files") or []
              if isinstance(e, dict) and isinstance(e.get("path"), str)}
    present, odd = _walk(root)
    unlisted = [f"{p}: present but not indexed (unverified)" for p in present
                if p not in listed and p not in (INDEX_NAME, SIGNATURE_NAME)]
    unlisted += [f"{p}: symlink or special file" for p in odd]
    add(_check("no_unlisted_files", *_summarise(unlisted, "no file outside the index")))
    add(_verify_signature(root, index, expect_public_key=expect_public_key,
                          require_signature=require_signature))
    # Only members whose bytes match the index are parsed: anything else is already a failure,
    # and reasoning about unverified bytes would report conclusions about the wrong file.
    trusted = listed - bad

    # -- experiment manifest -----------------------------------------------------------------
    manifest: dict[str, Any] | None = None
    try:
        doc = _load_member(root, "experiment.json", trusted)
        manifest = doc if isinstance(doc, dict) else None
        if manifest is None:
            raise ValidationError("experiment.json must be a JSON object")
    except (MalformedInput, ValidationError) as exc:
        manifest_error = str(exc)
    else:
        manifest_error = ""
    try:
        from .experiment import validate_experiment_manifest  # Workstream C; lazy on purpose
    except ImportError:
        add(_check("experiment_manifest_valid", False, "validator unavailable"))
    else:
        if manifest is None:
            add(_check("experiment_manifest_valid", False, manifest_error))
        else:
            add(_check("experiment_manifest_valid",
                       *_summarise(list(validate_experiment_manifest(manifest)),
                                   "assay/experiment-manifest/1 valid")))

    meta = (manifest or {}).get("experiment") if isinstance((manifest or {}).get("experiment"), dict) else {}
    exp_id = meta.get("experiment_id")
    configs = _configurations(trusted, manifest)
    run_ids = {c["run"].get("run_id") for c in configs.values() if "run" in c}

    # -- per-configuration documents ------------------------------------------------------------
    scorecards: dict[str, dict[str, Any]] = {}
    trial_logs: dict[str, dict[str, Any]] = {}
    traces: dict[str, list[dict[str, Any]]] = {}
    load_problems: list[str] = []
    for name, c in sorted(configs.items()):
        for key, store in (("scorecard.json", scorecards), ("trials.json", trial_logs)):
            if key in c:
                try:
                    doc = _load_member(root, c[key], trusted)
                    if not isinstance(doc, dict):
                        raise ValidationError(f"{c[key]}: must be a JSON object")
                    store[name] = doc
                except (MalformedInput, ValidationError) as exc:
                    load_problems.append(str(exc))
            else:
                load_problems.append(f"configuration {name!r}: no {key}")
        if "traces.jsonl" in c:
            try:
                traces[name] = read_jsonl(safe_join(root, c["traces.jsonl"]),
                                          max_bytes=min(MAX_FILE_BYTES, 50_000_000))
            except (MalformedInput, ValidationError) as exc:
                load_problems.append(str(exc))
        else:
            load_problems.append(f"configuration {name!r}: no traces.jsonl")
    if not configs:
        load_problems.append("no configurations found (configurations/<name>/...)")

    # -- ids ------------------------------------------------------------------------------------
    id_problems = []
    if manifest is None:
        id_problems.append("experiment.json unreadable: " + manifest_error)
    elif exp_id != index.get("experiment_id"):
        id_problems.append(f"experiment.json says {exp_id!r}, the index says "
                           f"{index.get('experiment_id')!r}")
    for name, c in sorted(configs.items()):
        run = c.get("run")
        if run is None:
            id_problems.append(f"configuration {name!r} has files but no run in experiment.json")
            continue
        rid = run.get("run_id")
        card = scorecards.get(name)
        if card is not None and (card.get("provenance") or {}).get("run_id") != rid:
            id_problems.append(f"{name}: scorecard run_id differs from experiment.json")
        log = trial_logs.get(name)
        if log is not None and log.get("run_id") != rid:
            id_problems.append(f"{name}: trials.json run_id differs from experiment.json")
        for tid in group_by_trial(traces.get(name, [])):
            if tid.split(":", 1)[0] not in run_ids:
                id_problems.append(f"{name}: trace trial {tid!r} belongs to no run in experiment.json")
            elif tid.split(":", 1)[0] != rid:
                id_problems.append(f"{name}: trace trial {tid!r} belongs to another configuration's run")
    add(_check("experiment_id_consistent", *_summarise(
        id_problems, f"{exp_id} agrees across experiment.json, the index, scorecards, trial "
                     f"logs and traces")))

    # -- scorecards (reuse the existing verifier, never reimplement it) -------------------------
    card_problems = []
    try:
        import assay_verifier
    except ImportError:
        assay_verifier = None  # type: ignore[assignment]
        card_problems.append("validator unavailable (assay_verifier)")
    if assay_verifier is not None:
        for name, card in sorted(scorecards.items()):
            try:
                result = assay_verifier.verify_manifest(card)
            except Exception as exc:  # the verifier's own typed errors, or malformed shapes
                card_problems.append(f"{name}: {type(exc).__name__}: {exc}")
                continue
            if "internally_consistent" not in result["levels_verified"]:
                card_problems.append(f"{name}: not internally_consistent")
    if not scorecards and not card_problems:
        card_problems.append("no scorecard could be read")
    add(_check("scorecards_verify", *_summarise(
        card_problems, "every scorecard reaches internally_consistent under assay_verifier")))

    # -- trial records, counts, traces ---------------------------------------------------------
    count_problems = list(load_problems)
    trace_problems: list[str] = []
    link_problems: list[str] = []
    for name, c in sorted(configs.items()):
        run, card, log = c.get("run") or {}, scorecards.get(name), trial_logs.get(name)
        records: dict[str, dict[str, Any]] = {}
        if log is not None:
            tasks = log.get("tasks")
            if not isinstance(tasks, dict):
                count_problems.append(f"{name}: trials.json has no tasks object")
                tasks = {}
            for task_id, recs in tasks.items():
                for rec in recs if isinstance(recs, list) else []:
                    if not isinstance(rec, dict):
                        continue
                    tid = rec.get("trial_id") or f"{log.get('run_id')}:{task_id}:{rec.get('trial')}"
                    if tid in records:
                        count_problems.append(f"{name}: duplicate trial record {tid}")
                    records[tid] = rec
        by_trial = group_by_trial(traces.get(name, []))
        counts = {"trials.json records": len(records) if log is not None else None,
                  "distinct trace trials": len(by_trial) if name in traces else None,
                  "experiment.json trials_executed": run.get("trials_executed")}
        known = {k: v for k, v in counts.items() if v is not None}
        if len(set(known.values())) > 1:
            count_problems.append(f"{name}: " + ", ".join(f"{k}={v}" for k, v in known.items()))
        if card is not None:
            scope = card.get("scope") or {}
            n_tasks = len(scope.get("task_ids") or card.get("findings") or [])
            per = card.get("trials_per_task")
            if isinstance(per, int) and run.get("trials_scheduled") != per * n_tasks:
                count_problems.append(f"{name}: trials_scheduled={run.get('trials_scheduled')} "
                                      f"but the scorecard implies {per} x {n_tasks} = {per * n_tasks}")

        for tid, events in by_trial.items():
            trace_problems += check_trace(events, expect_trial_id=tid)

        if log is not None and name in traces:
            missing = sorted(set(records) - set(by_trial))
            extra = sorted(set(by_trial) - set(records))
            if missing:
                link_problems.append(f"{name}: {len(missing)} trial(s) with no trace, e.g. {missing[0]}")
            if extra:
                link_problems.append(f"{name}: {len(extra)} traced trial(s) with no record, e.g. {extra[0]}")
            for tid in sorted(set(records) & set(by_trial)):
                fired = any(e.get("type") == "validation" and isinstance(e.get("content"), dict)
                            and e["content"].get("fired") is True for e in by_trial[tid])
                exploited = records[tid].get("state") == "exploited"
                if exploited and not fired:
                    link_problems.append(f"{tid}: recorded exploited but no validation event fired")
                elif fired and not exploited:
                    link_problems.append(f"{tid}: a validation event fired but the record says "
                                         f"{records[tid].get('state')!r}")
    add(_check("trial_counts_consistent", *_summarise(
        count_problems, "experiment.json, trials.json, traces and scorecards agree on trial counts")))
    add(_check("traces_consistent", *_summarise(trace_problems, "every trial's trace is "
                                                                "internally consistent")))
    add(_check("traces_match_trials", *_summarise(
        link_problems, "every exploited trial has a fired validation event, and vice versa")))

    # -- commit ---------------------------------------------------------------------------------
    commit = meta.get("repository_commit")
    if expect_commit is None:
        add(_check("repository_commit", True, f"not pinned (experiment.json declares {commit!r})"))
    else:
        want = expect_commit.strip().lower()
        ok = isinstance(commit, str) and len(want) >= 7 and commit.lower().startswith(want)
        add(_check("repository_commit", ok, f"declared {commit!r}, expected {expect_commit!r}"
                                            + ("" if ok else " (mismatch)")))

    # -- witness receipts -----------------------------------------------------------------------
    all_trials = {tid for evs in traces.values() for tid in group_by_trial(evs)}
    add(_verify_witness(root, trusted, listed, exp_id, trusted_witness_keys, all_trials))

    ok = all(c["ok"] for c in checks)
    return {
        "ok": ok,
        "experiment_id": exp_id if exp_id is not None else index.get("experiment_id"),
        "checks": checks,
        "failed": [c["name"] for c in checks if not c["ok"]],
        "establishes": ESTABLISHES,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def _verify_witness(root: Path, trusted: set[str], listed: set[str], exp_id: Any,
                    trusted_witness_keys: Any, all_trials: set[str]) -> dict[str, Any]:
    rel = "witness/receipts.jsonl"
    if rel not in listed:
        return _check("witness_receipts", True, "no witness receipts: nothing in this bundle was "
                                                "observed by an independent party")
    if rel not in trusted:
        return _check("witness_receipts", False, "receipts file does not match the index")
    try:
        from .witness_receipt import load_trusted_keys, read_receipts, verify_receipts
    except ImportError:
        return _check("witness_receipts", False, "validator unavailable")
    source = "trusted keys supplied by the verifier from outside the bundle"
    keys = trusted_witness_keys
    try:
        if isinstance(keys, (str, os.PathLike)):
            keys = load_trusted_keys(keys)
        elif keys is None and "witness/trusted_keys.json" in trusted:
            keys = load_trusted_keys(safe_join(root, "witness/trusted_keys.json"))
            source = ("OPERATOR-SUPPLIED key file witness/trusted_keys.json from inside the bundle "
                      "-- the author's own claim about whom to trust, so a pass here shows only "
                      "self-consistency; pass --trusted-witness-keys from outside the bundle "
                      "for real trust")
        elif keys is None:
            source = "no trusted keys: signatures checked only against the keys they name"
        receipts = read_receipts(safe_join(root, rel))
        result = verify_receipts(receipts, trusted_keys=keys, expect_experiment_id=exp_id)
    except Exception as exc:  # typed Assay errors from Workstream B, or malformed input
        return _check("witness_receipts", False, f"{type(exc).__name__}: {exc}")
    failed = [c["name"] for c in result.get("checks", []) if not c.get("ok")]
    for r in result.get("receipts", []) or []:
        bad = [c.get("name") for c in r.get("checks", []) if not c.get("ok")]
        if bad:
            failed.append(f"receipt[{r.get('index')}]: {', '.join(map(str, bad))}")
    # A receipt must be about a trial this bundle actually contains; a receipt for some other
    # trial is not evidence about this experiment, however valid its signature.
    foreign = sorted({r.get("trial_id") for r in receipts if isinstance(r, dict)}
                     - all_trials, key=str)
    if foreign:
        failed.append(f"receipts for trial(s) not in this bundle, e.g. {foreign[0]!r}")
    detail = (f"{result.get('count')} receipt(s); trust source: {source}"
              + (f"; failed: {failed}" if failed else ""))
    return _check("witness_receipts", bool(result.get("ok")) and not foreign, detail)


# ------------------------------------------------------------------------- CLI

def _cmd_verify_artifacts(args: argparse.Namespace) -> int:
    result = verify_bundle(args.dir, expect_public_key=args.expect_public_key,
                           require_signature=args.require_signature,
                           expect_commit=args.expect_commit,
                           trusted_witness_keys=args.trusted_witness_keys)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def _cmd_sign_artifacts(args: argparse.Namespace) -> int:
    try:
        key = ed25519.signing_key_from_env("ASSAY_ARTIFACT_KEY")
    except ed25519.InvalidSignature as exc:
        raise UsageError(str(exc)) from None
    if key is None:
        raise UsageError(
            "no signing key: set $ASSAY_ARTIFACT_KEY to a 64-hex-character Ed25519 seed (mint one "
            "with `assay witness-key`). It is deliberately not a command-line argument, because "
            "arguments land in shell history and process listings.")
    root = Path(args.dir)
    built = False
    if args.build_index:
        manifest = strict_loads(read_bounded(root / "experiment.json", max_bytes=MAX_JSON_BYTES),
                                where="experiment.json")
        exp_id = ((manifest or {}).get("experiment") or {}).get("experiment_id") \
            if isinstance(manifest, dict) else None
        build_index(root, experiment_id=exp_id)
        built = True
    elif not (root / INDEX_NAME).is_file():
        raise UsageError(f"{root} has no {INDEX_NAME}; pass --build-index to create one")
    sig = sign_index(root, key, signer=args.signer)
    print(json.dumps({
        "signed": str(root / SIGNATURE_NAME),
        "index_rebuilt": built,
        "public_key": sig["public_key"],
        "signer": sig["signer"],
        "index_sha256": sig["index_sha256"],
        "note": ("integrity relative to this signer only: the signature shows the key holder "
                 "vouches for these files, not that the experiment occurred"),
    }, indent=2))
    return 0


def add_cli(sub: Any) -> None:
    """Register ``verify-artifacts`` and ``sign-artifacts``."""
    v = sub.add_parser("verify-artifacts",
                       help="verify an experiment bundle offline (integrity relative to the "
                            "signer; not proof the experiment occurred)")
    v.add_argument("dir", metavar="DIR")
    v.add_argument("--expect-public-key", metavar="HEX",
                   help="pin the index signer's Ed25519 public key")
    v.add_argument("--require-signature", action="store_true",
                   help="fail if the index is unsigned")
    v.add_argument("--expect-commit", metavar="SHA",
                   help="fail unless experiment.json declares this repository commit")
    v.add_argument("--trusted-witness-keys", metavar="FILE",
                   help="witness keys you trust, instead of the bundle's own trusted_keys.json")
    v.set_defaults(func=_cmd_verify_artifacts)

    s = sub.add_parser("sign-artifacts",
                       help="sign a bundle's artifact index (key from $ASSAY_ARTIFACT_KEY)")
    s.add_argument("dir", metavar="DIR")
    s.add_argument("--signer", default="unspecified",
                   help="a label for who signs; a self-declared name, not an identity proof")
    s.add_argument("--build-index", action="store_true",
                   help="(re)build artifact_index.json from the directory before signing")
    s.set_defaults(func=_cmd_sign_artifacts)


__all__ = ["INDEX_SCHEMA", "SIGNATURE_SCHEMA", "DOMAIN", "INDEX_NAME", "SIGNATURE_NAME",
           "MAX_FILE_BYTES", "MAX_JSON_BYTES", "build_index", "sign_index", "verify_bundle",
           "safe_join", "index_sha256", "signature_message", "add_cli"]
