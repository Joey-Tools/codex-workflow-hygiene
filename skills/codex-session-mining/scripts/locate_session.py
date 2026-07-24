#!/usr/bin/env python3
"""Locate one Codex session without loading transcript records into stdout."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, BinaryIO, Iterator


MAX_RECORD_BYTES = 1024 * 1024
DRAIN_CHUNK_BYTES = 64 * 1024
MAX_FIELD_CHARS = 320
MAX_PATH_CHARS = 4096
MAX_SELECTOR_CHARS = 512
UUID_PATTERN = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)


def _bounded_text(value: object, limit: int = MAX_FIELD_CHARS) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _bounded_path(path: Path) -> str:
    return os.fspath(path)[:MAX_PATH_CHARS]


def _normalize_session_id(value: str) -> str:
    return value.lower() if UUID_PATTERN.fullmatch(value) else value


def _bounded_jsonl(handle: BinaryIO) -> Iterator[tuple[int, bytes, bool]]:
    line_number = 0
    while True:
        raw_line = handle.readline(MAX_RECORD_BYTES + 1)
        if not raw_line:
            return
        line_number += 1
        if len(raw_line) <= MAX_RECORD_BYTES:
            yield line_number, raw_line, False
            continue
        while raw_line and not raw_line.endswith(b"\n"):
            raw_line = handle.readline(DRAIN_CHUNK_BYTES)
        yield line_number, b"", True


def _empty_source(kind: str, path: Path) -> dict[str, Any]:
    return {
        "kind": kind,
        "malformed_records": 0,
        "match_count": 0,
        "matches": [],
        "matches_truncated": False,
        "oversized_records": 0,
        "path": _bounded_path(path),
        "records_scanned": 0,
        "status": "checked",
    }


def _open_regular_nofollow(path: Path) -> int:
    required = ("O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        raise OSError("required no-follow/nonblocking open flags are unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise OSError("source is not a regular file")
    return descriptor


def _index_matches(
    row: dict[str, Any],
    *,
    session_id: str | None,
    thread_query: str | None,
) -> bool:
    if session_id is not None:
        expected = _normalize_session_id(session_id)
        for key in ("id", "session_id"):
            value = row.get(key)
            if isinstance(value, str) and _normalize_session_id(value) == expected:
                return True
        return False
    assert thread_query is not None
    needle = thread_query.casefold()
    return any(
        needle in value.casefold()
        for key in ("thread_name", "text")
        if isinstance((value := row.get(key)), str)
    )


def _project_index_match(
    path: Path, line_number: int, row: dict[str, Any]
) -> dict[str, Any]:
    projection: dict[str, Any] = {
        "line": line_number,
        "path": _bounded_path(path),
    }
    for key in (
        "id",
        "session_id",
        "thread_name",
        "updated_at",
        "ts",
        "cwd",
        "text",
    ):
        value = _bounded_text(row.get(key))
        if value:
            projection[key] = value
    return projection


def _scan_index(
    path: Path,
    *,
    session_id: str | None,
    thread_query: str | None,
    limit: int,
) -> dict[str, Any]:
    source = _empty_source("index", path)
    if not path.exists():
        source["status"] = "unavailable"
        source["reason"] = "missing"
        return source
    try:
        descriptor = _open_regular_nofollow(path)
    except OSError as error:
        source["status"] = "partial"
        source["reason"] = f"open-failed:{type(error).__name__}"
        return source

    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            for line_number, raw_line, oversized in _bounded_jsonl(handle):
                source["records_scanned"] += 1
                if oversized:
                    source["oversized_records"] += 1
                    continue
                try:
                    row = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                    source["malformed_records"] += 1
                    continue
                if not isinstance(row, dict):
                    source["malformed_records"] += 1
                    continue
                if not _index_matches(
                    row,
                    session_id=session_id,
                    thread_query=thread_query,
                ):
                    continue
                source["match_count"] += 1
                if len(source["matches"]) < limit:
                    source["matches"].append(
                        _project_index_match(path, line_number, row)
                    )
    except OSError as error:
        source["status"] = "partial"
        source["reason"] = f"read-failed:{type(error).__name__}"
        return source

    if source["malformed_records"] or source["oversized_records"]:
        source["status"] = "partial"
        source["reason"] = "malformed-or-oversized-records"
    source["matches_truncated"] = source["match_count"] > len(source["matches"])
    return source


def _rollout_name_matches(name: str, session_id: str) -> bool:
    if not name.startswith("rollout-") or not name.endswith(".jsonl"):
        return False
    expected = _normalize_session_id(session_id)
    candidate = name.lower() if UUID_PATTERN.fullmatch(session_id) else name
    return expected in candidate


def _scan_rollout_root(root: Path, *, session_id: str, limit: int) -> dict[str, Any]:
    source = _empty_source("rollout-root", root)
    source["directories_scanned"] = 0
    source["entries_scanned"] = 0
    if not root.exists():
        source["status"] = "unavailable"
        source["reason"] = "missing"
        return source
    try:
        root_metadata = root.lstat()
    except OSError as error:
        source["status"] = "partial"
        source["reason"] = f"stat-failed:{type(error).__name__}"
        return source
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        source["status"] = "partial"
        source["reason"] = "root-not-real-directory"
        return source

    pending = [root]
    while pending:
        directory = pending.pop()
        source["directories_scanned"] += 1
        try:
            entries = os.scandir(directory)
        except OSError as error:
            source["status"] = "partial"
            source.setdefault("errors", []).append(
                {
                    "path": _bounded_path(directory),
                    "reason": f"scan-failed:{type(error).__name__}",
                }
            )
            continue
        try:
            with entries:
                for entry in entries:
                    source["entries_scanned"] += 1
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                    except OSError as error:
                        source["status"] = "partial"
                        source.setdefault("errors", []).append(
                            {
                                "path": _bounded_path(Path(entry.path)),
                                "reason": f"entry-stat-failed:{type(error).__name__}",
                            }
                        )
                        continue
                    if not _rollout_name_matches(entry.name, session_id):
                        continue
                    source["match_count"] += 1
                    if len(source["matches"]) < limit:
                        source["matches"].append(
                            {"path": _bounded_path(Path(entry.path))}
                        )
        except OSError as error:
            source["status"] = "partial"
            source.setdefault("errors", []).append(
                {
                    "path": _bounded_path(directory),
                    "reason": f"iterate-failed:{type(error).__name__}",
                }
            )

    source["matches_truncated"] = source["match_count"] > len(source["matches"])
    if source.get("errors"):
        errors = source["errors"]
        source["errors_truncated"] = len(errors) > limit
        source["errors"] = errors[:limit]
    return source


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Locate exact or narrowly indexed Codex sessions."
    )
    parser.add_argument(
        "--codex-home",
        type=Path,
        default=Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser(),
    )
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--session-id")
    selector.add_argument("--thread-query")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.limit <= 100:
        parser.error("--limit must be between 1 and 100")
    if args.session_id is not None and not args.session_id:
        parser.error("--session-id must not be empty")
    if args.session_id is not None and len(args.session_id) > MAX_SELECTOR_CHARS:
        parser.error(f"--session-id must be at most {MAX_SELECTOR_CHARS} characters")
    if args.thread_query is not None and not args.thread_query.strip():
        parser.error("--thread-query must not be blank")
    if args.thread_query is not None and len(args.thread_query) > MAX_SELECTOR_CHARS:
        parser.error(f"--thread-query must be at most {MAX_SELECTOR_CHARS} characters")
    return args


def main() -> int:
    args = _parse_args()
    codex_home = args.codex_home.expanduser()
    sources = [
        _scan_index(
            codex_home / "session_index.jsonl",
            session_id=args.session_id,
            thread_query=args.thread_query,
            limit=args.limit,
        ),
        _scan_index(
            codex_home / "history.jsonl",
            session_id=args.session_id,
            thread_query=args.thread_query,
            limit=args.limit,
        ),
    ]
    if args.session_id is not None:
        sources.extend(
            _scan_rollout_root(root, session_id=args.session_id, limit=args.limit)
            for root in (
                codex_home / "sessions",
                codex_home / "archived_sessions",
            )
        )

    statuses = {source["status"] for source in sources}
    if "partial" in statuses:
        status = "partial"
    elif statuses == {"unavailable"}:
        status = "unavailable"
    else:
        status = "checked"

    selector = (
        {"kind": "session-id", "value": args.session_id}
        if args.session_id is not None
        else {"kind": "thread-query", "value": args.thread_query}
    )
    document = {
        "codex_home": _bounded_path(codex_home),
        "retained_match_limit_per_source": args.limit,
        "schema_version": 1,
        "selector": selector,
        "sources": sources,
        "status": status,
        "total_matches": sum(source["match_count"] for source in sources),
    }
    print(json.dumps(document, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
