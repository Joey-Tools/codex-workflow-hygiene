"""Private authenticated worker protocol and bounded source discovery."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
from dataclasses import dataclass
import errno
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any, Callable, Mapping, NoReturn, Sequence

try:
    from . import catalog
    from .contracts import (
        JsonValue,
        RefType,
        SourceCellStatus,
        SourceKind,
        is_valid_session_identifier,
        parse_typed_ref,
    )
    from .transport_capture import _validate_source_transport_relay
    from . import transport_discovery
    from .transport_contracts import (
        SOURCE_TRANSPORT_MAX_RECORD_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BUDGET_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
        SOURCE_TRANSPORT_STREAM_SCHEMA,
        TransportValidationError,
        _REASON_RE,
        _TOKEN_RE,
        _canonical_commitment,
        _derive_source_resume_position,
        _normalize_source_resume_position,
        _read_bounded_line,
        _sha256,
        _source_transport_inventory_commitment,
        _source_transport_resume_probe,
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
    from .transport_resume import (
        _SourceTransportResumeProbeBudget,
        _SourceTransportResumeProbeBudgetExhausted,
        _source_transport_candidate_token,
        _source_transport_file_identity,
        _source_transport_range_digest,
        decode_source_resume_position,
        encode_source_resume_position,
    )
except (ImportError, ModuleNotFoundError):
    import catalog  # type: ignore[no-redef]
    from contracts import (  # type: ignore[no-redef]
        JsonValue,
        RefType,
        SourceCellStatus,
        SourceKind,
        is_valid_session_identifier,
        parse_typed_ref,
    )
    from transport_capture import (  # type: ignore[no-redef]
        _validate_source_transport_relay,
    )
    import transport_discovery  # type: ignore[no-redef]
    from transport_contracts import (  # type: ignore[no-redef]
        SOURCE_TRANSPORT_MAX_RECORD_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BUDGET_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
        SOURCE_TRANSPORT_STREAM_SCHEMA,
        TransportValidationError,
        _REASON_RE,
        _TOKEN_RE,
        _canonical_commitment,
        _derive_source_resume_position,
        _normalize_source_resume_position,
        _read_bounded_line,
        _sha256,
        _source_transport_inventory_commitment,
        _source_transport_resume_probe,
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
    from transport_resume import (  # type: ignore[no-redef]
        _SourceTransportResumeProbeBudget,
        _SourceTransportResumeProbeBudgetExhausted,
        _source_transport_candidate_token,
        _source_transport_file_identity,
        _source_transport_range_digest,
        decode_source_resume_position,
        encode_source_resume_position,
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


def _open_lexical_codex_root(
    codex_root: pathlib.Path,
    *,
    checkpoint: Callable[[], None] = lambda: None,
) -> _AnchoredCodexRoot:
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
    checkpoint()
    current_fd = os.open(root.anchor, flags)
    try:
        checkpoint()
        for index, name in enumerate(parts):
            checkpoint()
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
                checkpoint()
            except BaseException:
                os.close(opened_fd)
                raise
            os.close(current_fd)
            current_fd = opened_fd
        checkpoint()
        root_stat = os.fstat(current_fd)
        checkpoint()
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
    directory_snapshots: tuple[transport_discovery.SourceDirectorySnapshot, ...] = ()
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


def _emit_source_transport_resume_probe(
    payload: bytes,
    *,
    byte_offset: int,
    max_frame_bytes: int,
    source_locator: str,
) -> None:
    probe = _source_transport_resume_probe(payload, byte_offset=byte_offset)
    fragment_bytes = max(1, ((max_frame_bytes - 1024) * 3) // 4)
    fragment_count = max(1, (len(payload) + fragment_bytes - 1) // fragment_bytes)
    for fragment_index in range(fragment_count):
        fragment = payload[
            fragment_index * fragment_bytes : (fragment_index + 1) * fragment_bytes
        ]
        _emit_source_transport_frame(
            {
                "byte_end": probe["byte_end"],
                "byte_start": probe["byte_start"],
                "fragment_count": fragment_count,
                "fragment_index": fragment_index,
                "frame": "resume_probe_fragment",
                "payload_b64": base64.b64encode(fragment).decode("ascii"),
                "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
                "source_locator": source_locator,
            },
            max_frame_bytes=max_frame_bytes,
        )


def _discover_source_kind_candidates(
    source_kind: str,
    root_entries: Sequence[transport_discovery.DirectoryEntry],
    candidates: Sequence[tuple[pathlib.Path, str]],
    *,
    read_entries: Callable[
        [int, str, tuple[tuple[int, int], ...]],
        Sequence[transport_discovery.DirectoryEntry],
    ],
    open_directory: Callable[[str], tuple[int, tuple[tuple[int, int], ...]]],
    add_candidate: Callable[[str], None],
    scan_candidate_entries: Callable[
        [Sequence[transport_discovery.DirectoryEntry], str, re.Pattern[str]], None
    ],
    reject_active_entry: Callable[[], NoReturn],
) -> bool:
    if source_kind in {"session_index", "history"}:
        relative = {
            "history": "history.jsonl",
            "session_index": "session_index.jsonl",
        }[source_kind]
        scan_candidate_entries(root_entries, "", re.compile(re.escape(relative)))
        return bool(candidates)

    base_name = {
        "active_rollout": "sessions",
        "archived_rollout": "archived_sessions",
    }[source_kind]
    base_entry = next(filter(lambda entry: entry[0] == base_name, root_entries), None)
    if base_entry is None:
        base_fd = -1
    else:
        _name, is_symlink, is_directory, _is_file = base_entry
        if is_symlink or not is_directory:
            reject_active_entry()
        base_fd, base_identities = open_directory(base_name)
    try:
        if base_fd != -1:
            pattern = {
                "active_rollout": ACTIVE_ROLLOUT_RELATIVE_RE,
                "archived_rollout": ARCHIVED_ROLLOUT_RELATIVE_RE,
            }[source_kind]
            transport_discovery.walk_dated_rollout_tree(
                base_fd,
                base_identities,
                base_name,
                read_entries=read_entries,
                open_directory=open_directory,
                add_candidate=add_candidate,
                candidate_matches=lambda relative: pattern.fullmatch(relative)
                is not None,
                reject_entry=reject_active_entry,
            )
        if source_kind == "archived_rollout":
            scan_candidate_entries(root_entries, "", ROOT_ROLLOUT_RELATIVE_RE)
    finally:
        if base_fd != -1:
            os.close(base_fd)
    return base_fd != -1 or bool(candidates)


def _source_transport_candidate_paths(
    codex_root: pathlib.Path,
    source_kind: str,
    *,
    window_start: dt.datetime,
    window_end: dt.datetime,
    max_candidates: int,
) -> _SourceCandidateDiscovery:
    transport_discovery.window_dates(window_start, window_end)
    budget = transport_discovery.SourceDiscoveryBudget()
    anchor = _open_lexical_codex_root(codex_root, checkpoint=budget.checkpoint)
    root = anchor.path
    candidates: list[tuple[pathlib.Path, str]] = []
    candidate_identities: dict[str, tuple[tuple[int, int], ...]] = {}
    candidate_tokens: dict[str, str] = {}
    directory_snapshots: list[transport_discovery.SourceDirectorySnapshot] = []
    seen: set[str] = set()

    class DiscoveryStop(Exception):
        def __init__(self, reason: str) -> None:
            self.reason = reason

    def result(
        *,
        source_exists: bool,
        gap_reason: str | None = None,
    ) -> _SourceCandidateDiscovery:
        ordered = tuple(sorted(candidates, key=lambda item: os.fsencode(item[1])))
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
            directory_snapshots=tuple(directory_snapshots),
            root_anchor=anchor,
        )

    def successful_result(*, source_exists: bool) -> _SourceCandidateDiscovery:
        budget.checkpoint()
        completed = result(source_exists=source_exists)
        budget.checkpoint()
        return completed

    def directory_entries(
        descriptor: int,
        *,
        relative: str | None = None,
        identities: tuple[tuple[int, int], ...] | None = None,
    ) -> list[tuple[str, bool, bool, bool]]:
        def observe_entry(name: str) -> None:
            budget.observe("" if relative is None else relative, name)

        rows = transport_discovery.read_directory_entries(
            descriptor,
            observe_entry=observe_entry,
        )
        if relative is not None and identities is not None:
            directory_snapshots.append(
                transport_discovery.SourceDirectorySnapshot(
                    relative,
                    identities,
                    rows,
                )
            )
        return list(rows)

    def open_directory(
        relative: str,
    ) -> tuple[int, tuple[tuple[int, int], ...]]:
        budget.checkpoint()
        descriptor, identities = _open_relative_from_codex_root(
            anchor,
            pathlib.PurePosixPath(relative),
            expect_directory=True,
        )
        with contextlib.ExitStack() as custody:
            custody.callback(os.close, descriptor)
            budget.checkpoint()
            custody.pop_all()
        return descriptor, identities

    def add_candidate(relative: str) -> None:
        if relative in seen:
            return
        if len(candidates) >= max_candidates:
            raise DiscoveryStop("source_discovery_candidate_limit_reached")
        budget.checkpoint()
        descriptor, identities = _open_source_transport_candidate(
            anchor,
            pathlib.PurePosixPath(relative),
        )
        with contextlib.ExitStack() as custody:
            custody.callback(os.close, descriptor)
            metadata = os.fstat(descriptor)
            budget.checkpoint()
        seen.add(relative)
        candidates.append((root / relative, relative))
        candidate_identities[relative] = identities
        candidate_tokens[relative] = _source_transport_candidate_token(metadata)

    def scan_candidate_entries(
        entries: Sequence[transport_discovery.DirectoryEntry],
        prefix: str,
        pattern: re.Pattern[str],
    ) -> None:
        for entry in entries:
            name, is_symlink, _is_directory, is_file = entry[:4]
            relative = f"{prefix}/{name}" if prefix else name
            if pattern.fullmatch(relative) is None:
                continue
            if is_symlink or not is_file:
                raise DiscoveryStop("source_enumeration_failed")
            add_candidate(relative)

    def reject_active_entry() -> NoReturn:
        raise DiscoveryStop("source_enumeration_failed")

    try:
        root_entries = directory_entries(
            anchor.descriptor,
            relative="",
            identities=(anchor.identity,),
        )
        source_exists = _discover_source_kind_candidates(
            source_kind,
            root_entries,
            candidates,
            read_entries=lambda descriptor, relative, identities: directory_entries(
                descriptor,
                relative=relative,
                identities=identities,
            ),
            open_directory=open_directory,
            add_candidate=add_candidate,
            scan_candidate_entries=scan_candidate_entries,
            reject_active_entry=reject_active_entry,
        )
        return successful_result(source_exists=source_exists)
    except (
        DiscoveryStop,
        transport_discovery.SourceDiscoveryBudgetExceeded,
    ) as exc:
        return result(source_exists=True, gap_reason=exc.reason)
    except FileNotFoundError:
        return result(source_exists=True, gap_reason="source_enumeration_changed")
    except BaseException:
        anchor.close()
        raise


def _source_inventory_row(
    *,
    candidate_index: int,
    discovery_commitment: str,
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
    source_size: int,
    source_token: str,
) -> dict[str, JsonValue]:
    return {
        "accounting_class": accounting_class,
        "byte_end": byte_end,
        "byte_start": byte_start,
        "candidate_index": candidate_index,
        "content_commitment": (
            None if payload is None else "sha256:" + hashlib.sha256(payload).hexdigest()
        ),
        "discovery_commitment": discovery_commitment,
        "event_time": event_time,
        "frame": "inventory",
        "reason": reason,
        "record_index": record_index,
        "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
        "session_commitment": session_commitment,
        "source_occurrence": source_occurrence,
        "source_locator": source_locator,
        "source_size": source_size,
        "source_token": source_token,
    }


def session_selector_commitment(session_id: str) -> str:
    if not is_valid_session_identifier(session_id):
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
            if isinstance(candidate, str) and not is_valid_session_identifier(
                candidate
            ):
                raise TransportValidationError(
                    "source record session identity is invalid"
                )
            if is_valid_session_identifier(candidate):
                identifiers.add(candidate)
        if source_kind is SourceKind.SESSION_INDEX:
            candidate = node.get("id")
            if isinstance(candidate, str) and not is_valid_session_identifier(
                candidate
            ):
                raise TransportValidationError(
                    "source record session identity is invalid"
                )
            if is_valid_session_identifier(candidate):
                identifiers.add(candidate)
        if node.get("type") == "session_meta":
            payload = node.get("payload")
            if isinstance(payload, Mapping):
                for key in ("id", "session_id"):
                    candidate = payload.get(key)
                    if isinstance(candidate, str) and not is_valid_session_identifier(
                        candidate
                    ):
                        raise TransportValidationError(
                            "source record session identity is invalid"
                        )
                    if is_valid_session_identifier(candidate):
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
            "discovery_limits": {
                "directory_entries": transport_discovery.SOURCE_DISCOVERY_MAX_DIRECTORY_ENTRIES,
                "path_bytes": transport_discovery.SOURCE_DISCOVERY_MAX_PATH_BYTES,
                "timeout_milliseconds": int(
                    transport_discovery.SOURCE_DISCOVERY_TIMEOUT_SECONDS * 1000
                ),
            },
            "schema": "source_transport_discovery_v3",
            "source_exists": discovery.source_exists,
        }
    )


@dataclass(frozen=True, slots=True)
class _SourceTransportScanSetup:
    window_start: dt.datetime
    window_end: dt.datetime
    cursor_time: dt.datetime | None
    discovery: _SourceCandidateDiscovery
    discovery_commitment: str
    start_candidate_index: int
    normalized_resume: dict[str, JsonValue] | None
    terminal_status: str | None
    terminal_reason: str


def _prepare_source_transport_scan(
    args: argparse.Namespace,
) -> _SourceTransportScanSetup:
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
    except transport_discovery.SourceDiscoveryBudgetExceeded as exc:
        discovery = _SourceCandidateDiscovery((), True, exc.reason)
    except (OSError, ValueError):
        discovery = _SourceCandidateDiscovery((), True, "source_enumeration_failed")
    candidates = discovery.candidates
    candidate_tokens = dict(discovery.candidate_tokens)
    discovery_commitment = _source_transport_discovery_commitment(discovery)
    start_candidate_index = 0
    normalized_resume: dict[str, JsonValue] | None = None
    terminal_status: str | None = None
    terminal_reason = "authoritative_eof"
    try:
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
    except BaseException:
        discovery.close()
        raise
    return _SourceTransportScanSetup(
        window_start=window_start,
        window_end=window_end,
        cursor_time=cursor_time,
        discovery=discovery,
        discovery_commitment=discovery_commitment,
        start_candidate_index=start_candidate_index,
        normalized_resume=normalized_resume,
        terminal_status=terminal_status,
        terminal_reason=terminal_reason,
    )


def _emit_source_transport_terminal(
    args: argparse.Namespace,
    *,
    inventory: Sequence[Mapping[str, Any]],
    terminal_status: str | None,
    terminal_reason: str,
    discovery_gap_reason: str | None,
    source_exists: bool,
    emitted_records: int,
    emitted_bytes: int,
    transport_scan_bytes: int,
    oversized_record_count: int,
    oversized_byte_count: int,
    resume_position: Mapping[str, JsonValue] | None,
) -> None:
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
    inventory_accounting = {
        value.value: sum(item["accounting_class"] == value.value for item in inventory)
        for value in catalog.AccountingClass
    }
    _emit_source_transport_frame(
        {
            "complete": terminal_status
            in {"complete", "no_activity", "verified_absent"},
            "emitted_byte_count": emitted_bytes,
            "emitted_record_count": emitted_records,
            "frame": "terminal",
            "inventory_commitment": _source_transport_inventory_commitment(inventory),
            "inventory_accounting": inventory_accounting,
            "inventory_count": len(inventory),
            "oversized_byte_count": oversized_byte_count,
            "oversized_record_count": oversized_record_count,
            "reason": terminal_reason,
            "resume_position": resume_position,
            "scan_byte_count": transport_scan_bytes,
            "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
            "status": terminal_status,
        },
        max_frame_bytes=args.max_frame_bytes,
    )


def _terminal_source_discovery_gap(discovery: _SourceCandidateDiscovery) -> str | None:
    anchor = discovery.root_anchor
    if anchor is None:
        return discovery.gap_reason or "source_enumeration_revalidation_failed"

    return transport_discovery.classify_terminal_source_discovery(
        lambda: transport_discovery.terminal_revalidate_source_discovery(
            snapshots=discovery.directory_snapshots,
            root_authority=anchor,
            open_relative=_open_relative_from_codex_root,
            candidate_identities=discovery.candidate_identities,
            candidate_tokens=discovery.candidate_tokens,
            open_candidate=lambda relative,
            identities: _open_source_transport_candidate(
                anchor, pathlib.PurePosixPath(relative), expected_identities=identities
            )[0],
            candidate_token=_source_transport_candidate_token,
        )
    )


def _source_transport_scan(args: argparse.Namespace) -> int:
    setup = _prepare_source_transport_scan(args)
    window_start = setup.window_start
    window_end = setup.window_end
    cursor_time = setup.cursor_time
    discovery = setup.discovery
    discovery_commitment = setup.discovery_commitment
    start_candidate_index = setup.start_candidate_index
    normalized_resume = setup.normalized_resume
    terminal_status = setup.terminal_status
    terminal_reason = setup.terminal_reason
    candidates = discovery.candidates
    candidate_identities = dict(discovery.candidate_identities)
    candidate_tokens = dict(discovery.candidate_tokens)
    source_exists = discovery.source_exists
    discovery_gap_reason = discovery.gap_reason
    inventory: list[dict[str, Any]] = []
    emitted_bytes = 0
    emitted_records = 0
    transport_scan_bytes = 0
    oversized_record_count = 0
    oversized_byte_count = 0
    resume_position: dict[str, JsonValue] | None = None
    resume_probe_budget = _SourceTransportResumeProbeBudget(
        SOURCE_TRANSPORT_RESUME_PROBE_BUDGET_BYTES
    )

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
            accepted_prefix_tail = bytearray()
            incoming_probe = b""
            if is_resume_candidate and normalized_resume is not None:
                raw_probe = normalized_resume["resume_probe"]
                assert isinstance(raw_probe, Mapping)
                try:
                    incoming_probe = resume_probe_budget.read(
                        descriptor,
                        start=int(raw_probe["byte_start"]),
                        end=int(raw_probe["byte_end"]),
                    )
                except _SourceTransportResumeProbeBudgetExhausted:
                    terminal_status = "gap"
                    terminal_reason = "source_resume_probe_budget_exhausted"
                    stop = True
                    continue
                except (OSError, ValueError):
                    terminal_status = "gap"
                    terminal_reason = "source_resume_invalid"
                    stop = True
                    continue
                if (
                    _source_transport_resume_probe(
                        incoming_probe,
                        byte_offset=scanned,
                    )
                    != raw_probe
                ):
                    terminal_status = "gap"
                    terminal_reason = "source_resume_invalid"
                    stop = True
                    continue
                accepted_prefix_tail.extend(incoming_probe)
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
                    if payload is not None:
                        accepted_prefix_tail.extend(payload)
                        if (
                            len(accepted_prefix_tail)
                            > SOURCE_TRANSPORT_RESUME_PROBE_BYTES
                        ):
                            del accepted_prefix_tail[
                                :-SOURCE_TRANSPORT_RESUME_PROBE_BYTES
                            ]
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
                        candidate_index=candidate_index,
                        discovery_commitment=discovery_commitment,
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
                        source_size=source_size,
                        source_token=source_token,
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
            remaining_source_bytes = args.max_source_bytes - transport_scan_bytes
            if (
                not stop
                and scanned == source_size
                and candidate_index + 1 < len(candidates)
                and (
                    len(inventory) >= args.max_records
                    or (
                        transport_scan_bytes > 0
                        and remaining_source_bytes <= reserve_bytes
                    )
                )
            ):
                terminal_status = "gap"
                terminal_reason = (
                    "source_record_limit_reached"
                    if len(inventory) >= args.max_records
                    else "source_byte_limit_reached"
                )
                stop = True
            proof_before = os.fstat(descriptor)
            resume_probe_stable = True
            probe_failure_reason: str | None = None
            if proof_before.st_size < max(source_size, scanned):
                scanned_range_commitment = None
            else:
                scanned_range_commitment = _source_transport_range_digest(
                    descriptor,
                    scan_start,
                    scanned,
                )
                if is_resume_candidate and normalized_resume is not None:
                    raw_probe = normalized_resume["resume_probe"]
                    assert isinstance(raw_probe, Mapping)
                    try:
                        resume_probe_stable = (
                            resume_probe_budget.read(
                                descriptor,
                                start=int(raw_probe["byte_start"]),
                                end=int(raw_probe["byte_end"]),
                            )
                            == incoming_probe
                        )
                    except _SourceTransportResumeProbeBudgetExhausted:
                        resume_probe_stable = False
                        probe_failure_reason = "source_resume_probe_budget_exhausted"
                    except (OSError, ValueError):
                        resume_probe_stable = False
            after = os.fstat(descriptor)
            read_range_commitment = "sha256:" + digest.hexdigest()
            stable = (
                before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_mode == after.st_mode
                and _source_transport_file_identity(proof_before)
                == _source_transport_file_identity(after)
                and after.st_size >= source_size
                and scanned_range_commitment == read_range_commitment
                and resume_probe_stable
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
                        terminal_status == "gap"
                        and terminal_reason
                        in {
                            "source_byte_limit_reached",
                            "source_record_limit_reached",
                        }
                    )
                )
            )
            if not stable:
                terminal_status = "gap"
                terminal_reason = probe_failure_reason or "source_changed_during_scan"
                resume_position = None
                stop = True
            elif terminal_reason in {
                "source_byte_limit_reached",
                "source_record_limit_reached",
            }:
                outgoing_probe = bytes(accepted_prefix_tail)
                expected_probe_size = min(
                    SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
                    scanned,
                )
                if len(outgoing_probe) != expected_probe_size:
                    terminal_status = "gap"
                    terminal_reason = "source_resume_probe_unavailable"
                    resume_position = None
                    stop = True
                else:
                    resume_probe = _source_transport_resume_probe(
                        outgoing_probe,
                        byte_offset=scanned,
                    )
                    resume_position = _derive_source_resume_position(
                        prior_position=normalized_resume,
                        inventory=inventory,
                        resume_probe=resume_probe,
                    )
                    _emit_source_transport_resume_probe(
                        outgoing_probe,
                        byte_offset=scanned,
                        max_frame_bytes=args.max_frame_bytes,
                        source_locator=relative,
                    )
        finally:
            os.close(descriptor)

    revalidation_gap = _terminal_source_discovery_gap(discovery)
    if revalidation_gap is not None:
        terminal_status = "gap"
        terminal_reason = revalidation_gap
        resume_position = None
    discovery.close()

    _emit_source_transport_terminal(
        args,
        inventory=inventory,
        terminal_status=terminal_status,
        terminal_reason=terminal_reason,
        discovery_gap_reason=discovery_gap_reason,
        source_exists=source_exists,
        emitted_records=emitted_records,
        emitted_bytes=emitted_bytes,
        transport_scan_bytes=transport_scan_bytes,
        oversized_record_count=oversized_record_count,
        oversized_byte_count=oversized_byte_count,
        resume_position=resume_position,
    )
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
    parser.add_argument("--remote-helper-commitment")
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
        if args.remote_helper is not None or args.remote_helper_commitment is not None:
            parser.error("local source transport cannot bind a remote helper")
        return _source_transport_scan(args)
    if args.remote_helper is None or args.remote_helper_commitment is None:
        parser.error("remote source transport helper binding is incomplete")
    if args.direct_root is not None or args.reported_host is not None:
        parser.error("remote source transport cannot override its source root or host")
    command = _remote_host_context_command(
        args,
        "source-transport",
        _source_transport_remote_arguments(args),
    )
    wire_limit = (
        args.max_source_bytes * 2
        + args.max_records * 4096
        + args.max_frame_bytes * 2
        + SOURCE_TRANSPORT_RESUME_PROBE_BYTES * 2
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
