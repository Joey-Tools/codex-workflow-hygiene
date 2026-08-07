"""Private authenticated worker protocol and bounded source discovery."""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
from dataclasses import dataclass
import errno
import hashlib
import hmac
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any, Callable, Mapping, Sequence
import zlib

try:
    from . import catalog
    from .contracts import (
        JsonValue,
        RefType,
        SourceCellStatus,
        SourceKind,
        canonical_json_bytes,
        parse_typed_ref,
        strict_json_loads,
    )
    from .transport_capture import _validate_source_transport_relay
    from .transport_contracts import (
        SOURCE_TRANSPORT_ACTIVE_LOOKBACK_DAYS,
        SOURCE_TRANSPORT_BOUNDARY_PROBE_BYTES,
        SOURCE_TRANSPORT_MAX_RECORD_BYTES,
        SOURCE_TRANSPORT_RESUME_SCHEMA,
        SOURCE_TRANSPORT_SCAN_CHUNK_BYTES,
        SOURCE_TRANSPORT_STREAM_SCHEMA,
        TransportValidationError,
        _REASON_RE,
        _TOKEN_RE,
        _canonical_commitment,
        _normalize_source_resume_position,
        _read_bounded_line,
        _sha256,
        _source_transport_inventory_commitment,
        _stream_frame,
    )
    from .transport_paths import (
        ACTIVE_ROLLOUT_RELATIVE_RE,
        ARCHIVED_ROLLOUT_RELATIVE_RE,
        ROOT_ROLLOUT_RELATIVE_RE,
    )
    from .transport_remote import (
        _relay_remote_host_context_command,
        _remote_host_context_command,
    )
except (ImportError, ModuleNotFoundError):
    import catalog  # type: ignore[no-redef]
    from contracts import (  # type: ignore[no-redef]
        JsonValue,
        RefType,
        SourceCellStatus,
        SourceKind,
        canonical_json_bytes,
        parse_typed_ref,
        strict_json_loads,
    )
    from transport_capture import (  # type: ignore[no-redef]
        _validate_source_transport_relay,
    )
    from transport_contracts import (  # type: ignore[no-redef]
        SOURCE_TRANSPORT_ACTIVE_LOOKBACK_DAYS,
        SOURCE_TRANSPORT_BOUNDARY_PROBE_BYTES,
        SOURCE_TRANSPORT_MAX_RECORD_BYTES,
        SOURCE_TRANSPORT_RESUME_SCHEMA,
        SOURCE_TRANSPORT_SCAN_CHUNK_BYTES,
        SOURCE_TRANSPORT_STREAM_SCHEMA,
        TransportValidationError,
        _REASON_RE,
        _TOKEN_RE,
        _canonical_commitment,
        _normalize_source_resume_position,
        _read_bounded_line,
        _sha256,
        _source_transport_inventory_commitment,
        _stream_frame,
    )
    from transport_paths import (  # type: ignore[no-redef]
        ACTIVE_ROLLOUT_RELATIVE_RE,
        ARCHIVED_ROLLOUT_RELATIVE_RE,
        ROOT_ROLLOUT_RELATIVE_RE,
    )
    from transport_remote import (  # type: ignore[no-redef]
        _relay_remote_host_context_command,
        _remote_host_context_command,
    )

SOURCE_TRANSPORT_MIN_FRAME_BYTES = 4096


def _local_codex_root() -> pathlib.Path:
    return pathlib.Path.home() / ".codex"


@dataclass(slots=True)
class _AnchoredCodexRoot:
    path: pathlib.Path
    descriptor: int
    identity: tuple[int, int]

    def close(self) -> None:
        if self.descriptor != -1:
            os.close(self.descriptor)
            self.descriptor = -1

    def __del__(self) -> None:
        self.close()


def _open_lexical_codex_root(codex_root: pathlib.Path) -> _AnchoredCodexRoot:
    """Anchor an absolute lexical root without following any path component."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    supports_dir_fd = getattr(os, "supports_dir_fd", frozenset())
    if not nofollow or not directory or os.open not in supports_dir_fd:
        raise ValueError("source transport secure openat traversal is unsupported")
    root = pathlib.Path(os.path.abspath(os.fspath(codex_root.expanduser())))
    if not root.is_absolute() or root.parent == root or not root.name:
        raise ValueError("Codex root must name a lexical child directory")
    walk_root = root
    if sys.platform == "darwin" and root.parts[1:2] in {
        ("var",),
        ("tmp",),
        ("etc",),
    }:
        walk_root = pathlib.Path("/private").joinpath(*root.parts[1:])
    parts = walk_root.parts[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Codex root lexical path is invalid")

    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    flags = os.O_RDONLY | directory | nofollow | close_on_exec
    current_fd = os.open(root.anchor, flags)
    try:
        for index, name in enumerate(parts):
            try:
                opened_fd = os.open(name, flags, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        "Codex root must be a real directory; lexical path contains "
                        "a symlink or non-directory component"
                    ) from exc
                raise
            try:
                opened = os.fstat(opened_fd)
                if not stat.S_ISDIR(opened.st_mode):
                    raise ValueError("Codex root path component is not a directory")
                hook = globals().get("_SOURCE_TRANSPORT_OPEN_COMPONENT_HOOK")
                if callable(hook):
                    hook(index, name, opened_fd)
                common_hook = globals().get("_CODEX_ROOT_OPEN_COMPONENT_HOOK")
                if callable(common_hook):
                    common_hook(index, name, opened_fd)
            except BaseException:
                os.close(opened_fd)
                raise
            os.close(current_fd)
            current_fd = opened_fd
        root_stat = os.fstat(current_fd)
        descriptor = current_fd
        current_fd = -1
        return _AnchoredCodexRoot(
            path=root,
            descriptor=descriptor,
            identity=(root_stat.st_dev, root_stat.st_ino),
        )
    finally:
        if current_fd != -1:
            os.close(current_fd)


def _resolve_safe_codex_root(codex_root: pathlib.Path) -> pathlib.Path:
    anchor = _open_lexical_codex_root(codex_root)
    try:
        return anchor.path
    finally:
        anchor.close()


def _safe_relative_path(
    codex_root: pathlib.Path,
    relative_path: pathlib.PurePosixPath,
    *,
    expect_directory: bool = False,
    expect_regular_file: bool = False,
) -> pathlib.Path:
    anchor = _open_lexical_codex_root(codex_root)
    try:
        descriptor, _identities = _open_relative_from_codex_root(
            anchor,
            relative_path,
            expect_directory=expect_directory,
            expect_regular_file=expect_regular_file,
        )
        os.close(descriptor)
        return anchor.path.joinpath(*relative_path.parts)
    finally:
        anchor.close()


def _safe_rollout_path(
    codex_root: pathlib.Path, rollout_relative_path: pathlib.PurePosixPath
) -> pathlib.Path:
    return _safe_relative_path(
        codex_root, rollout_relative_path, expect_regular_file=True
    )


def _source_transport_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _source_transport_header(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "frame": "header",
        "host": args.reported_host or args.host,
        "lease_ref": args.lease_ref,
        "limits": {
            "frame_bytes": args.max_frame_bytes,
            "records": args.max_records,
            "source_bytes": args.max_source_bytes,
        },
        "process_nonce": args.process_nonce,
        "resume_position": args.resume_position,
        "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
        "session_selector_commitment": args.session_selector_commitment,
        "source_kind": args.source_kind,
        "cursor": {
            "ref": args.source_cursor,
            "time": args.cursor_time,
        },
        "window": {"end": args.window_end, "start": args.window_start},
    }


def _emit_source_transport_frame(
    value: dict[str, Any], *, max_frame_bytes: int
) -> None:
    encoded = _source_transport_json_bytes(value)
    if len(encoded) > max_frame_bytes:
        raise ValueError("source transport frame exceeds --max-frame-bytes")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


@dataclass(frozen=True, slots=True)
class _SourceCandidateDiscovery:
    candidates: tuple[tuple[pathlib.Path, str], ...]
    source_exists: bool
    gap_reason: str | None = None
    root: pathlib.Path | None = None
    candidate_identities: tuple[tuple[str, tuple[tuple[int, int], ...]], ...] = ()
    candidate_tokens: tuple[tuple[str, str], ...] = ()
    root_anchor: _AnchoredCodexRoot | None = None

    def close(self) -> None:
        if self.root_anchor is not None:
            self.root_anchor.close()


def _open_relative_from_codex_root(
    anchor: _AnchoredCodexRoot,
    relative_path: pathlib.PurePosixPath | None,
    *,
    expect_directory: bool = False,
    expect_regular_file: bool = False,
    expected_identities: Sequence[tuple[int, int]] | None = None,
    hook_name: str = "_SOURCE_TRANSPORT_OPEN_COMPONENT_HOOK",
    component_hook: Callable[[int, str, int], None] | None = None,
) -> tuple[int, tuple[tuple[int, int], ...]]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | directory | nofollow | close_on_exec
    file_flags = os.O_RDONLY | nofollow | close_on_exec
    relative_parts = () if relative_path is None else relative_path.parts
    if relative_path is not None and (
        not relative_parts or any(part in {"", ".", ".."} for part in relative_parts)
    ):
        raise ValueError("source path must stay under Codex root")

    current_fd = os.dup(anchor.descriptor)
    identities: list[tuple[int, int]] = [anchor.identity]
    try:
        for index, name in enumerate(relative_parts, start=1):
            final = index == len(relative_parts)
            flags = directory_flags if not final or expect_directory else file_flags
            try:
                opened_fd = os.open(name, flags, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        "source path uses a symlink or non-directory ancestor"
                    ) from exc
                raise
            try:
                opened = os.fstat(opened_fd)
                identity = (opened.st_dev, opened.st_ino)
                if final and expect_directory and not stat.S_ISDIR(opened.st_mode):
                    raise ValueError("source entry is not a directory")
                if final and expect_regular_file and not stat.S_ISREG(opened.st_mode):
                    raise ValueError("source entry is not a regular file")
                if not final and not stat.S_ISDIR(opened.st_mode):
                    raise ValueError("source path ancestor is not a directory")
                if expected_identities is not None and (
                    index >= len(expected_identities)
                    or identity != tuple(expected_identities[index])
                ):
                    raise ValueError(
                        "source path identity changed after candidate discovery"
                    )
                hook = component_hook or globals().get(hook_name)
                if callable(hook):
                    hook(index - 1, name, opened_fd)
                identities.append(identity)
            except BaseException:
                os.close(opened_fd)
                raise
            os.close(current_fd)
            current_fd = opened_fd
        if expected_identities is not None and len(identities) != len(
            expected_identities
        ):
            raise ValueError("source path identity chain changed")
        descriptor = current_fd
        current_fd = -1
        return descriptor, tuple(identities)
    finally:
        if current_fd != -1:
            os.close(current_fd)


def _open_source_transport_path(
    codex_root: pathlib.Path,
    relative_path: pathlib.PurePosixPath | None,
    *,
    expect_directory: bool = False,
    expect_regular_file: bool = False,
    expected_identities: Sequence[tuple[int, int]] | None = None,
) -> tuple[int, tuple[tuple[int, int], ...]]:
    anchor = _open_lexical_codex_root(codex_root)
    try:
        return _open_relative_from_codex_root(
            anchor,
            relative_path,
            expect_directory=expect_directory,
            expect_regular_file=expect_regular_file,
            expected_identities=expected_identities,
        )
    finally:
        anchor.close()


def _open_source_transport_candidate(
    codex_root: pathlib.Path | _AnchoredCodexRoot,
    relative_path: pathlib.PurePosixPath,
    *,
    expected_identities: Sequence[tuple[int, int]] | None = None,
) -> tuple[int, tuple[tuple[int, int], ...]]:
    """Open one source through an anchored no-follow component walk."""

    if isinstance(codex_root, _AnchoredCodexRoot):
        return _open_relative_from_codex_root(
            codex_root,
            relative_path,
            expect_regular_file=True,
            expected_identities=expected_identities,
        )
    return _open_source_transport_path(
        codex_root,
        relative_path,
        expect_regular_file=True,
        expected_identities=expected_identities,
    )


def _source_transport_instant(value: str, *, label: str) -> dt.datetime:
    try:
        canonical = catalog.canonical_utc_timestamp(value, label)
    except catalog.CatalogValidationError as exc:
        raise ValueError(f"{label} is invalid") from exc
    return dt.datetime.fromisoformat(canonical.removesuffix("Z") + "+00:00")


def _window_dates(start: dt.datetime, end: dt.datetime) -> tuple[dt.date, ...]:
    if start >= end:
        raise ValueError("source transport window is empty")
    final = (end - dt.timedelta(microseconds=1)).date()
    count = (final - start.date()).days + 1
    if count < 1 or count > 366:
        raise ValueError("source transport window exceeds the discovery bound")
    return tuple(start.date() + dt.timedelta(days=index) for index in range(count))


def _source_transport_candidate_token(metadata: os.stat_result) -> str:
    return _canonical_commitment(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": metadata.st_mode,
            "schema": "source_transport_candidate_v2",
        }
    )


def _source_transport_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return tuple(int(getattr(metadata, field)) for field in fields)


def _source_transport_range_digest(descriptor: int, start: int, end: int) -> str:
    digest = hashlib.sha256()
    scanned = start
    while scanned < end:
        chunk = os.pread(
            descriptor,
            min(SOURCE_TRANSPORT_SCAN_CHUNK_BYTES, end - scanned),
            scanned,
        )
        if not chunk:
            raise ValueError("source transport committed range is truncated")
        digest.update(chunk)
        scanned += len(chunk)
    return "sha256:" + digest.hexdigest()


def _source_transport_boundary_probe(
    descriptor: int,
    byte_offset: int,
) -> tuple[int, str]:
    probe_start = max(0, byte_offset - SOURCE_TRANSPORT_BOUNDARY_PROBE_BYTES)
    return probe_start, _source_transport_range_digest(
        descriptor, probe_start, byte_offset
    )


def _source_transport_candidate_paths(
    codex_root: pathlib.Path,
    source_kind: str,
    *,
    window_start: dt.datetime,
    window_end: dt.datetime,
    max_candidates: int,
) -> _SourceCandidateDiscovery:
    window_dates = _window_dates(window_start, window_end)
    anchor = _open_lexical_codex_root(codex_root)
    root = anchor.path
    candidates: list[tuple[pathlib.Path, str]] = []
    candidate_identities: dict[str, tuple[tuple[int, int], ...]] = {}
    candidate_tokens: dict[str, str] = {}
    seen: set[str] = set()
    entry_limit = max(4096, max_candidates * 64)
    entries_seen = 0

    class DiscoveryStop(Exception):
        def __init__(self, reason: str) -> None:
            self.reason = reason

    def result(
        *,
        source_exists: bool,
        gap_reason: str | None = None,
    ) -> _SourceCandidateDiscovery:
        ordered = tuple(sorted(candidates, key=lambda item: item[1].encode("utf-8")))
        return _SourceCandidateDiscovery(
            candidates=ordered,
            source_exists=source_exists,
            gap_reason=gap_reason,
            root=root,
            candidate_identities=tuple(
                (relative, candidate_identities[relative])
                for _path, relative in ordered
            ),
            candidate_tokens=tuple(
                (relative, candidate_tokens[relative]) for _path, relative in ordered
            ),
            root_anchor=anchor,
        )

    def directory_entries(descriptor: int) -> list[tuple[str, bool, bool, bool]]:
        nonlocal entries_seen
        rows: list[tuple[str, bool, bool, bool]] = []
        with os.scandir(os.dup(descriptor)) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > entry_limit:
                    raise DiscoveryStop("candidate_discovery_limit_reached")
                rows.append(
                    (
                        entry.name,
                        entry.is_symlink(),
                        entry.is_dir(follow_symlinks=False),
                        entry.is_file(follow_symlinks=False),
                    )
                )
        rows.sort(key=lambda item: item[0].encode("utf-8"))
        return rows

    def open_directory(relative: str) -> int:
        descriptor, _identities = _open_relative_from_codex_root(
            anchor,
            pathlib.PurePosixPath(relative),
            expect_directory=True,
        )
        return descriptor

    def add_candidate(relative: str) -> None:
        if relative in seen:
            return
        if len(candidates) >= max_candidates:
            raise DiscoveryStop("candidate_discovery_limit_reached")
        descriptor, identities = _open_source_transport_candidate(
            anchor,
            pathlib.PurePosixPath(relative),
        )
        metadata = os.fstat(descriptor)
        os.close(descriptor)
        seen.add(relative)
        candidates.append((root / relative, relative))
        candidate_identities[relative] = identities
        candidate_tokens[relative] = _source_transport_candidate_token(metadata)

    def scan_candidate_directory(
        descriptor: int,
        prefix: str,
        pattern: re.Pattern[str],
    ) -> None:
        for name, is_symlink, _is_directory, is_file in directory_entries(descriptor):
            relative = f"{prefix}/{name}" if prefix else name
            if pattern.fullmatch(relative) is None:
                continue
            if is_symlink or not is_file:
                raise DiscoveryStop("source_enumeration_failed")
            add_candidate(relative)

    try:
        if source_kind in {"session_index", "history"}:
            relative = (
                "session_index.jsonl"
                if source_kind == "session_index"
                else "history.jsonl"
            )
            try:
                add_candidate(relative)
            except FileNotFoundError:
                return result(source_exists=False)
            return result(source_exists=True)

        base_name = (
            "sessions" if source_kind == "active_rollout" else "archived_sessions"
        )
        try:
            base_fd = open_directory(base_name)
        except FileNotFoundError:
            base_fd = -1
            if source_kind == "active_rollout":
                return result(source_exists=False)
        try:
            pattern = (
                ACTIVE_ROLLOUT_RELATIVE_RE
                if source_kind == "active_rollout"
                else ARCHIVED_ROLLOUT_RELATIVE_RE
            )
            if base_fd != -1:
                selected_dates = set(window_dates)
                if source_kind == "active_rollout":
                    selected_dates.update(
                        window_start.date() - dt.timedelta(days=offset)
                        for offset in range(
                            1,
                            SOURCE_TRANSPORT_ACTIVE_LOOKBACK_DAYS + 1,
                        )
                    )
                for selected_date in sorted(selected_dates):
                    day_path = (
                        f"{base_name}/{selected_date.year:04d}/"
                        f"{selected_date.month:02d}/{selected_date.day:02d}"
                    )
                    try:
                        day_fd = open_directory(day_path)
                    except FileNotFoundError:
                        continue
                    try:
                        scan_candidate_directory(day_fd, day_path, pattern)
                    finally:
                        os.close(day_fd)
                if source_kind == "archived_rollout":
                    scan_candidate_directory(base_fd, base_name, pattern)
            if source_kind == "archived_rollout":
                scan_candidate_directory(
                    anchor.descriptor,
                    "",
                    ROOT_ROLLOUT_RELATIVE_RE,
                )
        finally:
            if base_fd != -1:
                os.close(base_fd)
        return result(source_exists=base_fd != -1 or bool(candidates))
    except DiscoveryStop as exc:
        return result(source_exists=True, gap_reason=exc.reason)
    except BaseException:
        anchor.close()
        raise


def _source_inventory_row(
    *,
    source_locator: str,
    record_index: int,
    byte_start: int,
    byte_end: int,
    payload: bytes | None,
    accounting_class: str,
    reason: str,
    event_time: str | None,
    session_commitment: str | None,
    source_occurrence: str,
) -> dict[str, JsonValue]:
    return {
        "accounting_class": accounting_class,
        "byte_end": byte_end,
        "byte_start": byte_start,
        "content_commitment": (
            None if payload is None else "sha256:" + hashlib.sha256(payload).hexdigest()
        ),
        "event_time": event_time,
        "frame": "inventory",
        "reason": reason,
        "record_index": record_index,
        "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
        "session_commitment": session_commitment,
        "source_occurrence": source_occurrence,
        "source_locator": source_locator,
    }


def session_selector_commitment(session_id: str) -> str:
    if (
        not isinstance(session_id, str)
        or not session_id
        or len(session_id.encode("utf-8")) > 512
        or any(ord(character) < 0x20 for character in session_id)
    ):
        raise TransportValidationError("session selector is invalid")
    return (
        "sha256:"
        + hashlib.sha256(
            b"codex-session-retrospective/session-selector/v2\x00"
            + session_id.encode("utf-8")
        ).hexdigest()
    )


def _source_record_session_identifiers(
    record: Mapping[str, Any],
    *,
    source_kind: SourceKind,
) -> tuple[str, ...]:
    identifiers: set[str] = set()
    nodes: list[tuple[Mapping[str, Any], int]] = [(record, 0)]
    visited = 0
    explicit_keys = {
        "conversation_id",
        "sessionId",
        "session_id",
        "threadId",
        "thread_id",
    }
    while nodes:
        node, depth = nodes.pop()
        visited += 1
        if visited > 4096 or depth > 16:
            raise TransportValidationError(
                "source record identity structure exceeds bounds"
            )
        for key in explicit_keys:
            candidate = node.get(key)
            if (
                isinstance(candidate, str)
                and 1 <= len(candidate.encode("utf-8")) <= 512
                and not any(ord(character) < 0x20 for character in candidate)
            ):
                identifiers.add(candidate)
        if source_kind is SourceKind.SESSION_INDEX:
            candidate = node.get("id")
            if (
                isinstance(candidate, str)
                and 1 <= len(candidate.encode("utf-8")) <= 512
            ):
                identifiers.add(candidate)
        if node.get("type") == "session_meta":
            payload = node.get("payload")
            if isinstance(payload, Mapping):
                for key in ("id", "session_id"):
                    candidate = payload.get(key)
                    if (
                        isinstance(candidate, str)
                        and 1 <= len(candidate.encode("utf-8")) <= 512
                    ):
                        identifiers.add(candidate)
        for child in node.values():
            if isinstance(child, Mapping):
                nodes.append((child, depth + 1))
    if len(identifiers) > 32:
        raise TransportValidationError(
            "source record contains too many session identifiers"
        )
    return tuple(sorted(identifiers, key=lambda value: value.encode("utf-8")))


def _source_structural_exclusion(
    record: Mapping[str, Any],
    *,
    source_kind: SourceKind,
) -> str | None:
    if not record:
        return "empty_structural_unit"
    if source_kind is SourceKind.SESSION_INDEX:
        return "non_evidence_wrapper"
    payload = record.get("payload")
    record_type = record.get("type")
    if record_type in {
        "session_meta",
        "turn_context",
        "compacted",
        "metadata",
        "wrapper",
    }:
        return "non_evidence_wrapper"
    nodes = [record, payload] if isinstance(payload, Mapping) else [record]
    role_values = {
        str(node.get(key)).lower()
        for node in nodes
        for key in ("agent_role", "kind", "name", "role", "source")
        if isinstance(node.get(key), str)
    }
    if role_values & {
        "coordinator",
        "retrospective_coordinator",
        "session_retrospective_coordinator",
    }:
        return "retrospective_coordinator"
    if role_values & {
        "retrospective_worker",
        "session_retrospective_worker",
        "worker",
    }:
        return "retrospective_worker"
    if isinstance(payload, Mapping) and not payload:
        return "empty_structural_unit"
    metadata_fields = {
        "conversation_id",
        "created_at",
        "id",
        "sessionId",
        "session_id",
        "threadId",
        "thread_id",
        "time",
        "timestamp",
        "ts",
        "type",
        "updated_at",
    }
    if set(record) <= metadata_fields:
        return "non_evidence_wrapper"
    return None


def _source_transport_discovery_commitment(
    discovery: _SourceCandidateDiscovery,
) -> str:
    return _canonical_commitment(
        {
            "candidates": [
                {"source_locator": locator, "source_token": token}
                for locator, token in discovery.candidate_tokens
            ],
            "schema": "source_transport_discovery_v2",
            "source_exists": discovery.source_exists,
        }
    )


_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_SOURCE = "\n".join(
    (
        "import base64,hashlib,importlib.abc,importlib.util,json,os,sys,zlib",
        "marker,digest,snapshot_path=sys.argv[1:4]\nwith open(snapshot_path,'rb') as handle: payload=handle.read(4194305)",
        "if marker!='source_transport_worker_snapshot_v1' or 'sha256:'+hashlib.sha256(payload).hexdigest()!=digest: raise SystemExit('source transport snapshot authentication failed')\nif len(payload)>4194304: raise SystemExit('source transport snapshot exceeds its bound')",
        "snapshot=json.loads(zlib.decompress(payload))\nruntime=snapshot['python_runtime']",
        "path=os.path.realpath(sys.executable)\nwith open(path,'rb') as handle: executable=handle.read(67108865)",
        "component={'content_commitment':'sha256:'+hashlib.sha256(executable).hexdigest(),'path':path,'role':'python_interpreter','state':'present'}\nactual={'component':component,'executable':sys.executable,'implementation':sys.implementation.name,'schema':'source_transport_python_runtime_v1','version':list(sys.version_info)}",
        "if len(executable)>67108864 or actual!=runtime: raise SystemExit('source transport Python authority changed')",
        "sources={name.removesuffix('.py'):base64.b64decode(content,validate=True) for name,content in snapshot['modules'].items()}\npaths={name.removesuffix('.py'):snapshot['package_dir']+'/'+name for name in snapshot['modules']}",
        "class _Loader(importlib.abc.Loader):\n def __init__(self,name): self.name=name\n def create_module(self,spec): return None\n def exec_module(self,module): module.__file__=paths[self.name]; exec(compile(sources[self.name],paths[self.name],'exec'),module.__dict__)",
        "class _Finder(importlib.abc.MetaPathFinder):\n def find_spec(self,fullname,path=None,target=None): return importlib.util.spec_from_loader(fullname,_Loader(fullname)) if fullname in sources else None",
        "sys.meta_path.insert(0,_Finder())\nsys.argv=[sys.argv[4],*sys.argv[5:]]",
        "sys._retrospective_v2_transport_snapshot=digest\nglobals()['__file__']=paths['transport_worker']\nexec(compile(sources['transport_worker'],paths['transport_worker'],'exec'),globals())",
    )
)
_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_B64 = base64.b64encode(
    _SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_SOURCE.encode("utf-8")
).decode("ascii")
SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP = (
    "import base64;exec(compile(base64.b64decode("
    + repr(_SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP_B64)
    + "),'<source-transport-snapshot>','exec'))"
)


def _source_transport_snapshot_path(cache: pathlib.Path, digest: str) -> pathlib.Path:
    value = digest.removeprefix("sha256:")
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise TransportValidationError("source transport snapshot digest is invalid")
    return cache / f"{value}.snapshot"


def _source_transport_snapshot_flags(
    *,
    package_dir: pathlib.Path,
    components: Sequence[Mapping[str, JsonValue]],
    module_manifest: Sequence[str],
    python_runtime: Mapping[str, JsonValue],
    base_flags: Sequence[str],
    schema: str,
    cache: pathlib.Path,
    maximum_bytes: int,
) -> tuple[str, ...]:
    try:
        from . import safe_io as snapshot_io
    except ImportError:
        import safe_io as snapshot_io  # type: ignore[no-redef]

    snapshot = {
        "modules": {
            name: str(component["content_b64"])
            for name, component in zip(module_manifest, components, strict=True)
        },
        "package_dir": str(package_dir),
        "python_runtime": dict(python_runtime),
        "schema": schema,
    }
    payload = zlib.compress(canonical_json_bytes(snapshot), level=9)
    if not payload or len(payload) > maximum_bytes:
        raise TransportValidationError("source transport program snapshot is too large")
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    snapshot_path = _source_transport_snapshot_path(cache, digest)
    snapshot_io.ensure_owner_only_directory(snapshot_path.parent)
    try:
        snapshot_io.atomic_create_bytes(
            snapshot_path,
            payload,
            create_parents=False,
        )
    except FileExistsError:
        try:
            existing = snapshot_io.read_bounded_bytes(
                snapshot_path,
                max_bytes=maximum_bytes,
                require_owner_only=True,
            )
        except (OSError, snapshot_io.UnsafePathError) as exc:
            raise TransportValidationError(
                "source transport program snapshot is invalid"
            ) from exc
        if not hmac.compare_digest(existing, payload):
            raise TransportValidationError(
                "source transport program snapshot digest changed"
            )
    return (
        *base_flags,
        "-c",
        SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP,
        schema,
        digest,
        str(snapshot_path),
    )


def _source_transport_decode_snapshot(
    argv: tuple[str, ...],
    *,
    prefix: tuple[str, ...],
    cache: pathlib.Path,
    maximum_bytes: int,
    component_reader: Callable[..., Mapping[str, JsonValue]],
) -> tuple[dict[str, JsonValue], int, str]:
    try:
        from . import safe_io as snapshot_io
    except ImportError:
        import safe_io as snapshot_io  # type: ignore[no-redef]

    if argv[: len(prefix)] != prefix or len(argv) < len(prefix) + 4:
        raise TransportValidationError("source transport command is incomplete")
    digest = argv[len(prefix)]
    snapshot_path = pathlib.Path(argv[len(prefix) + 1])
    if snapshot_path != _source_transport_snapshot_path(cache, digest):
        raise TransportValidationError("source transport snapshot path is invalid")
    try:
        snapshot_io.recover_atomic_create(snapshot_path)
        component = component_reader(
            snapshot_path,
            role="program_snapshot",
            allow_missing=False,
            maximum_bytes=maximum_bytes,
            include_content=True,
        )
        payload = base64.b64decode(str(component["content_b64"]), validate=True)
        snapshot = strict_json_loads(zlib.decompress(payload))
    except (OSError, ValueError, zlib.error, snapshot_io.UnsafePathError) as exc:
        raise TransportValidationError("source transport snapshot is invalid") from exc
    if digest != "sha256:" + hashlib.sha256(payload).hexdigest() or not isinstance(
        snapshot, dict
    ):
        raise TransportValidationError("source transport snapshot digest changed")
    return snapshot, len(prefix) + 2, digest


def encode_source_resume_position(value: Mapping[str, object]) -> str:
    normalized = _normalize_source_resume_position(value)
    if normalized is None:
        raise TransportValidationError("source transport resume position is missing")
    return (
        base64.urlsafe_b64encode(canonical_json_bytes(normalized))
        .decode("ascii")
        .rstrip("=")
    )


def decode_source_resume_position(value: str) -> dict[str, JsonValue]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise TransportValidationError("source transport resume position is invalid")
    try:
        payload = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
        decoded = strict_json_loads(payload)
    except (binascii.Error, ValueError) as exc:
        raise TransportValidationError(
            "source transport resume position is invalid"
        ) from exc
    if not isinstance(decoded, Mapping):
        raise TransportValidationError("source transport resume position is invalid")
    normalized = _normalize_source_resume_position(decoded)
    if normalized is None or canonical_json_bytes(normalized) != payload:
        raise TransportValidationError(
            "source transport resume position is not canonical"
        )
    return normalized


def _source_transport_scan(args: argparse.Namespace) -> int:
    if args.max_source_bytes < 1:
        raise ValueError("--max-source-bytes must be positive")
    if args.max_records < 1:
        raise ValueError("--max-records must be positive")
    if args.max_frame_bytes < SOURCE_TRANSPORT_MIN_FRAME_BYTES:
        raise ValueError("--max-frame-bytes is below the protocol minimum")
    header = _source_transport_header(args)
    _emit_source_transport_frame(header, max_frame_bytes=args.max_frame_bytes)

    window_start = _source_transport_instant(
        args.window_start,
        label="source transport window start",
    )
    window_end = _source_transport_instant(
        args.window_end,
        label="source transport window end",
    )
    if window_start >= window_end:
        raise ValueError("source transport window is empty")
    if (args.source_cursor is None) != (args.cursor_time is None):
        raise ValueError("source cursor ref and time must be supplied together")
    cursor_time = (
        None
        if args.cursor_time is None
        else _source_transport_instant(
            args.cursor_time,
            label="source transport cursor time",
        )
    )
    inventory: list[dict[str, Any]] = []
    emitted_bytes = 0
    emitted_records = 0
    transport_scan_bytes = 0
    oversized_record_count = 0
    oversized_byte_count = 0
    terminal_reason = "authoritative_eof"
    terminal_status: str | None = None
    resume_position: dict[str, JsonValue] | None = None
    root = (
        pathlib.Path(args.direct_root)
        if args.direct_root is not None
        else _local_codex_root()
    )
    try:
        discovery = _source_transport_candidate_paths(
            root,
            args.source_kind,
            window_start=window_start,
            window_end=window_end,
            max_candidates=args.max_records,
        )
    except FileNotFoundError:
        discovery = _SourceCandidateDiscovery((), False)
    except (OSError, ValueError):
        discovery = _SourceCandidateDiscovery(
            (),
            True,
            "source_enumeration_failed",
        )
    candidates = discovery.candidates
    candidate_identities = dict(discovery.candidate_identities)
    candidate_tokens = dict(discovery.candidate_tokens)
    source_exists = discovery.source_exists
    discovery_gap_reason = discovery.gap_reason
    discovery_commitment = _source_transport_discovery_commitment(discovery)
    start_candidate_index = 0
    normalized_resume: dict[str, JsonValue] | None = None
    if args.resume_position is not None:
        normalized_resume = _normalize_source_resume_position(args.resume_position)
        assert normalized_resume is not None
        start_candidate_index = int(normalized_resume["candidate_index"])
        if (
            normalized_resume["discovery_commitment"] != discovery_commitment
            or start_candidate_index >= len(candidates)
            or candidates[start_candidate_index][1]
            != normalized_resume["source_locator"]
            or candidate_tokens.get(str(normalized_resume["source_locator"]))
            != normalized_resume["source_token"]
        ):
            terminal_status = "gap"
            terminal_reason = "source_resume_invalid"

    raw_fragment_bytes = min(
        256 * 1024,
        max(1, ((args.max_frame_bytes - 3072) * 3) // 4),
    )
    stop = terminal_status is not None
    reserve_bytes = min(
        SOURCE_TRANSPORT_MAX_RECORD_BYTES + 1,
        max(1, args.max_source_bytes // 4),
    )
    for candidate_index, (_path, relative) in enumerate(candidates):
        if candidate_index < start_candidate_index:
            continue
        if stop:
            break
        try:
            expected_identities = candidate_identities[relative]
            if discovery.root_anchor is None:
                raise ValueError("source discovery lost its anchored root")
            descriptor, _identities = _open_source_transport_candidate(
                discovery.root_anchor,
                pathlib.PurePosixPath(relative),
                expected_identities=expected_identities,
            )
        except (KeyError, OSError, ValueError):
            terminal_status = "gap"
            terminal_reason = "source_read_failed"
            break
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("source entry is not a regular file")
            source_token = candidate_tokens[relative]
            if source_token != _source_transport_candidate_token(before):
                raise ValueError("source entry changed after discovery")
            source_occurrence = (
                "sha256:"
                + hashlib.sha256(
                    _source_transport_json_bytes(
                        {
                            "device": before.st_dev,
                            "inode": before.st_ino,
                            "schema": "source_occurrence_v2",
                        }
                    )
                ).hexdigest()
            )
            digest = hashlib.sha256()
            is_resume_candidate = (
                normalized_resume is not None
                and candidate_index == start_candidate_index
            )
            scanned = (
                int(normalized_resume["byte_offset"])
                if is_resume_candidate and normalized_resume is not None
                else 0
            )
            scan_start = scanned
            file_record_index = (
                int(normalized_resume["record_index"])
                if is_resume_candidate and normalized_resume is not None
                else 0
            )
            source_size = (
                int(normalized_resume["source_size"])
                if is_resume_candidate and normalized_resume is not None
                else before.st_size
            )
            if source_size > before.st_size or scanned > source_size:
                terminal_status = "gap"
                terminal_reason = "source_resume_invalid"
                stop = True
                continue
            if is_resume_candidate and normalized_resume is not None:
                frozen_prefix = _source_transport_range_digest(descriptor, 0, scanned)
                if frozen_prefix != normalized_resume["frozen_prefix_commitment"]:
                    terminal_status = "gap"
                    terminal_reason = "source_resume_invalid"
                    stop = True
                    continue
            boundary_probe = _source_transport_boundary_probe(descriptor, source_size)
            locator_session_ids: set[str] = set()
            source_kind = SourceKind(args.source_kind)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                handle.seek(scanned)
                while True:
                    remaining_source_bytes = (
                        args.max_source_bytes - transport_scan_bytes
                    )
                    if scanned >= source_size:
                        break
                    if len(inventory) >= args.max_records or (
                        transport_scan_bytes > 0
                        and remaining_source_bytes <= reserve_bytes
                    ):
                        frozen_prefix = _source_transport_range_digest(
                            descriptor, 0, scanned
                        )
                        resume_position = {
                            "byte_offset": scanned,
                            "candidate_index": candidate_index,
                            "discovery_commitment": discovery_commitment,
                            "frozen_prefix_commitment": frozen_prefix,
                            "record_index": file_record_index,
                            "schema": SOURCE_TRANSPORT_RESUME_SCHEMA,
                            "source_locator": relative,
                            "source_size": source_size,
                            "source_token": source_token,
                        }
                        terminal_status = "gap"
                        terminal_reason = (
                            "source_record_limit_reached"
                            if len(inventory) >= args.max_records
                            else "source_byte_limit_reached"
                        )
                        stop = True
                        break
                    if remaining_source_bytes <= 0:
                        terminal_status = "gap"
                        terminal_reason = "source_invocation_budget_too_small"
                        stop = True
                        break
                    line = _read_bounded_line(
                        handle,
                        max_payload_bytes=SOURCE_TRANSPORT_MAX_RECORD_BYTES,
                        max_scan_bytes=min(
                            remaining_source_bytes,
                            source_size - scanned,
                        ),
                        hasher=digest,
                    )
                    if line.byte_count == 0:
                        break
                    byte_start = scanned
                    scanned += line.byte_count
                    transport_scan_bytes += line.byte_count
                    payload = line.payload
                    event_time: str | None = None
                    record_session_commitment: str | None = None
                    accounting_class = catalog.AccountingClass.EXPLICIT_GAP.value
                    reason = "source_record_unparseable"
                    if line.oversized:
                        terminal_status = "gap"
                        terminal_reason = "source_record_oversized"
                        oversized_record_count = 1
                        oversized_byte_count = line.byte_count
                        stop = True
                        reason = "source_record_oversized"
                    elif not line.complete:
                        terminal_status = "gap"
                        terminal_reason = "source_record_crosses_invocation_budget"
                        stop = True
                        reason = "source_record_crosses_invocation_budget"
                    else:
                        assert payload is not None
                        try:
                            record_value = _stream_frame(payload.rstrip(b"\r\n"))
                            direct_session_ids = _source_record_session_identifiers(
                                record_value,
                                source_kind=source_kind,
                            )
                            locator_session_ids.update(direct_session_ids)
                            event_time = catalog.event_time_from_record(
                                record_value,
                                stable_event_time=(
                                    catalog.stable_event_time_from_locator(relative)
                                ),
                            )
                        except (
                            catalog.CatalogValidationError,
                            TransportValidationError,
                        ):
                            record_value = None
                            direct_session_ids = ()
                        if record_value is None:
                            terminal_status = "gap"
                            terminal_reason = "source_record_unparseable"
                            stop = True
                        elif event_time is None:
                            accounting_class = (
                                catalog.AccountingClass.EXPLICIT_GAP.value
                            )
                            reason = "source_event_time_unavailable"
                            terminal_status = "gap"
                            terminal_reason = reason
                            stop = True
                        else:
                            instant = _source_transport_instant(
                                event_time,
                                label="source record event time",
                            )
                            effective_session_ids = (
                                set(direct_session_ids) or locator_session_ids
                            )
                            if len(effective_session_ids) == 1:
                                record_session_commitment = session_selector_commitment(
                                    next(iter(effective_session_ids))
                                )
                            if (
                                args.session_selector_commitment is not None
                                and len(effective_session_ids) != 1
                            ):
                                accounting_class = (
                                    catalog.AccountingClass.EXPLICIT_GAP.value
                                )
                                reason = "session_identity_unresolved"
                                terminal_status = "gap"
                                terminal_reason = reason
                                stop = True
                            elif (
                                args.session_selector_commitment is not None
                                and session_selector_commitment(
                                    next(iter(effective_session_ids))
                                )
                                != args.session_selector_commitment
                            ):
                                accounting_class = (
                                    catalog.AccountingClass.STRUCTURALLY_EXCLUDED.value
                                )
                                reason = "session_target_mismatch"
                            elif cursor_time is not None and instant < cursor_time:
                                accounting_class = (
                                    catalog.AccountingClass.STRUCTURALLY_EXCLUDED.value
                                )
                                reason = "before_cursor"
                            elif instant < window_start:
                                accounting_class = (
                                    catalog.AccountingClass.STRUCTURALLY_EXCLUDED.value
                                )
                                reason = "before_window"
                            elif instant >= window_end:
                                accounting_class = (
                                    catalog.AccountingClass.STRUCTURALLY_EXCLUDED.value
                                )
                                reason = "after_window"
                            elif (
                                structural_reason := _source_structural_exclusion(
                                    record_value,
                                    source_kind=source_kind,
                                )
                            ) is not None:
                                accounting_class = (
                                    catalog.AccountingClass.STRUCTURALLY_EXCLUDED.value
                                )
                                reason = structural_reason
                            else:
                                accounting_class = (
                                    catalog.AccountingClass.CONSUMED_CANDIDATE.value
                                )
                                reason = "inside_window"
                    inventory_row = _source_inventory_row(
                        source_locator=relative,
                        record_index=file_record_index,
                        byte_start=byte_start,
                        byte_end=scanned,
                        payload=payload,
                        accounting_class=accounting_class,
                        reason=reason,
                        event_time=event_time,
                        session_commitment=record_session_commitment,
                        source_occurrence=source_occurrence,
                    )
                    inventory.append(inventory_row)
                    _emit_source_transport_frame(
                        inventory_row,
                        max_frame_bytes=args.max_frame_bytes,
                    )
                    if accounting_class == catalog.AccountingClass.CONSUMED_CANDIDATE:
                        assert payload is not None
                        fragment_count = max(
                            1,
                            (len(payload) + raw_fragment_bytes - 1)
                            // raw_fragment_bytes,
                        )
                        for fragment_index in range(fragment_count):
                            fragment = payload[
                                fragment_index * raw_fragment_bytes : (
                                    fragment_index + 1
                                )
                                * raw_fragment_bytes
                            ]
                            frame = {
                                "byte_end": scanned,
                                "byte_start": byte_start,
                                "fragment_count": fragment_count,
                                "fragment_index": fragment_index,
                                "frame": "record_fragment",
                                "payload_b64": base64.b64encode(fragment).decode(
                                    "ascii"
                                ),
                                "record_index": file_record_index,
                                "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
                                "source_locator": relative,
                            }
                            _emit_source_transport_frame(
                                frame,
                                max_frame_bytes=args.max_frame_bytes,
                            )
                        emitted_bytes += len(payload)
                        emitted_records += 1
                    file_record_index += 1
                    if stop:
                        break
            proof_before = os.fstat(descriptor)
            if proof_before.st_size < max(source_size, scanned):
                after_boundary_probe = None
                scanned_range_commitment = None
                resumed_prefix_commitment = None
            else:
                after_boundary_probe = _source_transport_boundary_probe(
                    descriptor,
                    source_size,
                )
                scanned_range_commitment = _source_transport_range_digest(
                    descriptor,
                    scan_start,
                    scanned,
                )
                resumed_prefix_commitment = (
                    _source_transport_range_digest(descriptor, 0, scan_start)
                    if is_resume_candidate
                    else None
                )
            after = os.fstat(descriptor)
            read_range_commitment = "sha256:" + digest.hexdigest()
            stable = (
                before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_mode == after.st_mode
                and _source_transport_file_identity(proof_before)
                == _source_transport_file_identity(after)
                and after.st_size >= source_size
                and boundary_probe == after_boundary_probe
                and scanned_range_commitment == read_range_commitment
                and (
                    not is_resume_candidate
                    or resumed_prefix_commitment
                    == normalized_resume["frozen_prefix_commitment"]
                )
                and (
                    after.st_size > before.st_size
                    or (
                        before.st_size == after.st_size
                        and before.st_ctime_ns == after.st_ctime_ns
                        and before.st_mtime_ns == after.st_mtime_ns
                    )
                )
                and (
                    scanned == source_size
                    or (
                        resume_position is not None
                        and resume_position["candidate_index"] == candidate_index
                        and resume_position["byte_offset"] == scanned
                    )
                )
            )
            if not stable:
                terminal_status = "gap"
                terminal_reason = "source_changed_during_scan"
                resume_position = None
                stop = True
        finally:
            os.close(descriptor)

    discovery.close()

    if terminal_status is None and discovery_gap_reason is not None:
        terminal_status = "gap"
        terminal_reason = discovery_gap_reason
    if terminal_status is None:
        if not source_exists:
            terminal_status = "verified_absent"
            terminal_reason = "source_verified_absent"
        elif emitted_records == 0:
            terminal_status = "no_activity"
            terminal_reason = "authoritative_empty_snapshot"
        else:
            terminal_status = "complete"
    inventory_commitment = _source_transport_inventory_commitment(inventory)
    inventory_accounting = {
        value.value: sum(item["accounting_class"] == value.value for item in inventory)
        for value in catalog.AccountingClass
    }
    terminal = {
        "complete": terminal_status in {"complete", "no_activity", "verified_absent"},
        "emitted_byte_count": emitted_bytes,
        "emitted_record_count": emitted_records,
        "frame": "terminal",
        "inventory_commitment": inventory_commitment,
        "inventory_accounting": inventory_accounting,
        "inventory_count": len(inventory),
        "oversized_byte_count": oversized_byte_count,
        "oversized_record_count": oversized_record_count,
        "reason": terminal_reason,
        "resume_position": resume_position,
        "scan_byte_count": transport_scan_bytes,
        "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
        "status": terminal_status,
    }
    _emit_source_transport_frame(terminal, max_frame_bytes=args.max_frame_bytes)
    return 0


def _emit_source_transport_gap(args: argparse.Namespace, *, reason: str) -> None:
    if _REASON_RE.fullmatch(reason) is None:
        raise ValueError("source transport gap reason is invalid")
    _emit_source_transport_frame(
        _source_transport_header(args),
        max_frame_bytes=args.max_frame_bytes,
    )
    _emit_source_transport_frame(
        {
            "complete": False,
            "emitted_byte_count": 0,
            "emitted_record_count": 0,
            "frame": "terminal",
            "inventory_accounting": {
                value.value: 0 for value in catalog.AccountingClass
            },
            "inventory_commitment": _source_transport_inventory_commitment(()),
            "inventory_count": 0,
            "oversized_byte_count": 0,
            "oversized_record_count": 0,
            "reason": reason,
            "resume_position": None,
            "scan_byte_count": 0,
            "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
            "status": SourceCellStatus.GAP.value,
        },
        max_frame_bytes=args.max_frame_bytes,
    )


def _source_transport_remote_arguments(args: argparse.Namespace) -> tuple[str, ...]:
    arguments = [
        "--source-kind",
        str(args.source_kind),
        "--window-start",
        str(args.window_start),
        "--window-end",
        str(args.window_end),
        "--lease-ref",
        str(args.lease_ref),
        "--process-nonce",
        str(args.process_nonce),
        "--max-source-bytes",
        str(args.max_source_bytes),
        "--max-records",
        str(args.max_records),
        "--max-frame-bytes",
        str(args.max_frame_bytes),
    ]
    if args.source_cursor is not None:
        arguments.extend(("--source-cursor", str(args.source_cursor)))
    if args.cursor_time is not None:
        arguments.extend(("--cursor-time", str(args.cursor_time)))
    if args.resume_position is not None:
        arguments.extend(
            (
                "--resume-position",
                encode_source_resume_position(args.resume_position),
            )
        )
    if args.session_selector_commitment is not None:
        arguments.extend(
            (
                "--session-selector-commitment",
                str(args.session_selector_commitment),
            )
        )
    return tuple(arguments)


_PRIVATE_WORKER_PROTOCOL_MARKER = "source-transport"


def _run_private_transport_worker(argv: Sequence[str] | None = None) -> int:
    """Run the lease-bound worker protocol without publishing a coordinator verb."""

    parser = argparse.ArgumentParser(
        prog="transport_worker.py",
        add_help=False,
        allow_abbrev=False,
    )
    parser.add_argument("_protocol_marker", help=argparse.SUPPRESS)
    parser.add_argument("--host", required=True)
    parser.add_argument(
        "--source-kind",
        required=True,
        choices=tuple(source_kind.value for source_kind in SourceKind),
    )
    parser.add_argument("--window-start", required=True)
    parser.add_argument("--window-end", required=True)
    parser.add_argument("--lease-ref", required=True)
    parser.add_argument("--process-nonce", required=True)
    parser.add_argument("--max-source-bytes", required=True, type=int)
    parser.add_argument("--max-records", required=True, type=int)
    parser.add_argument("--max-frame-bytes", required=True, type=int)
    parser.add_argument("--source-cursor")
    parser.add_argument("--cursor-time")
    parser.add_argument("--resume-position")
    parser.add_argument("--session-selector-commitment")
    parser.add_argument("--reported-host")
    parser.add_argument("--direct-root")
    parser.add_argument("--remote-helper")
    args = parser.parse_args(argv)
    if args._protocol_marker != _PRIVATE_WORKER_PROTOCOL_MARKER:
        parser.error("private source transport protocol marker is invalid")
    if (
        _TOKEN_RE.fullmatch(args.host) is None
        or _TOKEN_RE.fullmatch(args.process_nonce) is None
        or args.max_source_bytes < 1
        or args.max_records < 1
        or args.max_frame_bytes < SOURCE_TRANSPORT_MIN_FRAME_BYTES
    ):
        parser.error("source transport arguments are outside protocol bounds")
    if (args.source_cursor is None) != (args.cursor_time is None):
        parser.error("source cursor ref and time must be supplied together")
    if (
        args.source_cursor is not None
        and _TOKEN_RE.fullmatch(args.source_cursor) is None
    ):
        parser.error("source cursor is invalid")
    if args.resume_position is not None:
        try:
            args.resume_position = decode_source_resume_position(args.resume_position)
        except TransportValidationError:
            parser.error("source resume position is invalid")
    if args.session_selector_commitment is not None:
        try:
            _sha256(
                args.session_selector_commitment,
                "source transport session selector commitment",
            )
        except TransportValidationError:
            parser.error("session selector commitment is invalid")
    try:
        args.window_start = catalog.canonical_utc_timestamp(
            args.window_start,
            "source transport window start",
        )
        args.window_end = catalog.canonical_utc_timestamp(
            args.window_end,
            "source transport window end",
        )
        if args.cursor_time is not None:
            args.cursor_time = catalog.canonical_utc_timestamp(
                args.cursor_time,
                "source transport cursor time",
            )
    except catalog.CatalogValidationError:
        parser.error("source transport time bound is invalid")
    try:
        parse_typed_ref(args.lease_ref, expected=RefType.LEASE)
    except (TypeError, ValueError):
        parser.error("source transport lease reference is invalid")
    if args.host == "local":
        if args.remote_helper is not None:
            parser.error("local source transport cannot bind a remote helper")
        return _source_transport_scan(args)
    if args.direct_root is not None or args.reported_host is not None:
        parser.error("remote source transport cannot override its source root or host")
    command = _remote_host_context_command(
        args,
        "source-transport",
        _source_transport_remote_arguments(args),
    )
    wire_limit = (
        args.max_source_bytes * 2 + args.max_records * 4096 + args.max_frame_bytes * 2
    )
    try:
        _relay_remote_host_context_command(
            command,
            max_output_bytes=wire_limit,
            validator=lambda output: _validate_source_transport_relay(args, output),
        )
    except RuntimeError:
        _emit_source_transport_gap(
            args,
            reason="remote_host_context_transport_unavailable",
        )
    return 0
