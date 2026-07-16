#!/usr/bin/env python3
"""Build a bounded, cross-root Codex rollout corpus without losing suffixes."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable


UTC = dt.timezone.utc
SESSION_ID_RE = re.compile(
    r"(?P<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)
ROLLOUT_DATE_RE = re.compile(
    r"^rollout-(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})(?:-|\.jsonl$)"
)
ROLLOUT_TIMESTAMP_RE = re.compile(
    r"^rollout-(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2})-(?P<minute>\d{2})-(?P<second>\d{2})(?:-|\.jsonl$)"
)
TIMESTAMP_KEYS = ("timestamp", "ts", "time", "created_at", "updated_at")
VOLATILE_KEYS = frozenset(TIMESTAMP_KEYS)
REPLAY_EVIDENCE_TYPES = frozenset(
    {
        "agent_message",
        "computer_call",
        "computer_call_output",
        "computer_tool_call",
        "computer_tool_call_output",
        "custom_tool_call",
        "custom_tool_call_output",
        "function_call",
        "function_call_output",
        "reasoning",
        "task_complete",
        "web_search_call",
    }
)
GENERATED_ID_RECORD_TYPES = REPLAY_EVIDENCE_TYPES | frozenset(
    {"event_msg", "message", "response_item", "task_started", "user_message"}
)
CALL_DEFINITION_TYPES = frozenset(
    {
        "computer_call",
        "computer_tool_call",
        "custom_tool_call",
        "function_call",
        "web_search_call",
    }
)
CALL_REFERENCE_TYPES = frozenset(
    {
        "computer_call_output",
        "computer_tool_call_output",
        "custom_tool_call_output",
        "function_call_output",
    }
)


class CorpusError(RuntimeError):
    """A corpus cannot be trusted because an input or inventory step failed."""


@dataclass(frozen=True, slots=True)
class Record:
    line_no: int
    fingerprint: str
    timestamp: dt.datetime | None
    replay_evidence: bool


@dataclass(frozen=True, slots=True)
class RolloutCandidate:
    path: Path
    root: Path
    relative_parts: tuple[str, ...]
    root_device: int
    root_inode: int
    file_device: int
    file_inode: int
    file_size: int


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    name: str
    device: int
    inode: int
    file_type: int


@dataclass(frozen=True, slots=True)
class InventoryDirectory:
    device: int
    inode: int
    entries: tuple[InventoryEntry, ...] | None


def capture_inventory_entry(
    name: str,
    metadata: os.stat_result,
) -> InventoryEntry:
    return InventoryEntry(
        name=name,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        file_type=stat.S_IFMT(metadata.st_mode),
    )


@dataclass(frozen=True, slots=True)
class RolloutMetadata:
    candidate: RolloutCandidate
    source: str
    lifecycle_ids: frozenset[str]
    first_lifecycle_id: str | None
    filename_session_id: str | None
    content_sha256: str
    source_bytes: int
    fallback_timestamp: dt.datetime | None
    first_timestamp: dt.datetime | None
    has_record_timestamp: bool
    has_in_window_record: bool
    fallback_accepted: bool
    record_count: int

    @property
    def path(self) -> Path:
        return self.candidate.path

    @property
    def accepted(self) -> bool:
        return self.has_in_window_record or self.fallback_accepted

    @property
    def lifecycle_id(self) -> str | None:
        if len(self.lifecycle_ids) != 1:
            return None
        return next(iter(self.lifecycle_ids))

    @property
    def owner_id(self) -> str | None:
        if self.first_lifecycle_id is None:
            return None
        if self.filename_session_id is None:
            return self.first_lifecycle_id
        if self.first_lifecycle_id == self.filename_session_id:
            return self.filename_session_id
        return None

    @property
    def identity_ambiguous(self) -> bool:
        return bool(self.lifecycle_ids) and self.owner_id is None


@dataclass(frozen=True, slots=True)
class Rollout:
    path: Path
    source: str
    records: tuple[Record, ...]
    lifecycle_ids: frozenset[str]
    first_lifecycle_id: str | None
    filename_session_id: str | None
    content_sha256: str
    fallback_timestamp: dt.datetime | None
    first_timestamp: dt.datetime | None
    window_accepted: bool

    @property
    def lifecycle_id(self) -> str | None:
        if len(self.lifecycle_ids) != 1:
            return None
        return next(iter(self.lifecycle_ids))

    @property
    def owner_id(self) -> str | None:
        if self.first_lifecycle_id is None:
            return None
        if self.filename_session_id is None:
            return self.first_lifecycle_id
        if self.first_lifecycle_id == self.filename_session_id:
            return self.filename_session_id
        return None

    @property
    def identity_ambiguous(self) -> bool:
        return bool(self.lifecycle_ids) and self.owner_id is None


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parents = list(range(size))

    def find(self, item: int) -> int:
        parent = self.parents[item]
        if parent != item:
            self.parents[item] = self.find(parent)
        return self.parents[item]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parents[right_root] = left_root


class GeneratedIdCanonicalizer:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, int]] = {}

    def define(self, namespace: str, value: object) -> object:
        if not isinstance(value, str) or not value:
            return value
        mapping = self.values.setdefault(namespace, {})
        ordinal = mapping.setdefault(value, len(mapping) + 1)
        return {"$generated_id": namespace, "ordinal": ordinal}

    def reference(self, namespace: str, value: object) -> object:
        if not isinstance(value, str) or not value:
            return value
        ordinal = self.values.get(namespace, {}).get(value)
        if ordinal is None:
            return value
        return {"$generated_id": namespace, "ordinal": ordinal}


def parse_instant(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid ISO-8601 timestamp: {value}"
        ) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def maybe_instant(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return parse_instant(value)
    except argparse.ArgumentTypeError:
        return None


def normalized_fingerprint_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): normalized_fingerprint_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [normalized_fingerprint_value(item) for item in value]
    return value


def normalize_generated_ids(
    container: dict[str, object],
    record_type: object,
    canonicalizer: GeneratedIdCanonicalizer,
) -> None:
    if not isinstance(record_type, str) or record_type not in GENERATED_ID_RECORD_TYPES:
        return
    if "id" in container:
        container["id"] = canonicalizer.define("item", container["id"])
    if "item_id" in container:
        container["item_id"] = canonicalizer.reference("item", container["item_id"])
    if "response_id" in container:
        container["response_id"] = canonicalizer.define(
            "response", container["response_id"]
        )
    if "call_id" in container:
        if record_type in CALL_DEFINITION_TYPES:
            container["call_id"] = canonicalizer.define("call", container["call_id"])
        elif record_type in CALL_REFERENCE_TYPES:
            container["call_id"] = canonicalizer.reference("call", container["call_id"])
    if "turn_id" in container:
        container["turn_id"] = canonicalizer.define("turn", container["turn_id"])
    metadata = container.get("internal_chat_message_metadata_passthrough")
    if isinstance(metadata, dict) and "turn_id" in metadata:
        metadata["turn_id"] = canonicalizer.define("turn", metadata["turn_id"])


def record_fingerprint(
    row: dict[str, Any],
    canonicalizer: GeneratedIdCanonicalizer | None = None,
) -> str:
    normalized = normalized_fingerprint_value(row)
    if not isinstance(normalized, dict):
        raise TypeError("normalized rollout record must remain an object")
    stable: dict[str, object] = normalized
    stable_payload = stable.get("payload")
    for key in VOLATILE_KEYS:
        stable.pop(key, None)
        if isinstance(stable_payload, dict):
            stable_payload.pop(key, None)
    payload_type = (
        stable_payload.get("type") if isinstance(stable_payload, dict) else None
    )
    record_type = payload_type or stable.get("type")
    if record_type == "session_meta":
        stable = {
            "type": "session_meta",
            "lifecycle_ids": record_lifecycle_ids(stable),
        }
    elif record_type == "turn_context":
        stable = {"type": "turn_context"}
    else:
        state = canonicalizer or GeneratedIdCanonicalizer()
        normalize_generated_ids(stable, record_type, state)
        if isinstance(stable_payload, dict):
            normalize_generated_ids(stable_payload, record_type, state)
    encoded = json.dumps(
        stable,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def record_timestamp(row: dict[str, Any]) -> dt.datetime | None:
    payload = row.get("payload")
    sources = [row]
    if isinstance(payload, dict):
        sources.append(payload)
    for source in sources:
        for key in TIMESTAMP_KEYS:
            parsed = maybe_instant(source.get(key))
            if parsed is not None:
                return parsed
    return None


def record_lifecycle_ids(row: dict[str, Any]) -> tuple[str, ...]:
    payload = row.get("payload")
    payload_type = payload.get("type") if isinstance(payload, dict) else None
    if row.get("type") != "session_meta" and payload_type != "session_meta":
        return ()
    values: list[str] = []
    if isinstance(payload, dict):
        sources = [payload]
    else:
        sources = [row]
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("id", "session_id", "thread_id"):
            value = source.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            normalized = value.strip()
            if match := SESSION_ID_RE.fullmatch(normalized):
                normalized = match.group("id").lower()
            if normalized not in values:
                values.append(normalized)
    return tuple(values)


def record_replay_evidence(row: dict[str, Any]) -> bool:
    payload = row.get("payload")
    sources = [payload, row]
    for source in sources:
        if not isinstance(source, dict):
            continue
        role = source.get("role")
        if role == "assistant":
            return True
        record_type = source.get("type")
        if isinstance(record_type, str) and record_type in REPLAY_EVIDENCE_TYPES:
            return True
    return False


def filename_session_id(path: Path) -> str | None:
    match = SESSION_ID_RE.search(path.name)
    return match.group("id").lower() if match else None


def fallback_path_timestamp(path: Path, root: Path) -> dt.datetime | None:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return None
    timestamp_match = ROLLOUT_TIMESTAMP_RE.search(path.name)
    if timestamp_match is not None:
        try:
            return dt.datetime(
                int(timestamp_match.group("year")),
                int(timestamp_match.group("month")),
                int(timestamp_match.group("day")),
                int(timestamp_match.group("hour")),
                int(timestamp_match.group("minute")),
                int(timestamp_match.group("second")),
                tzinfo=UTC,
            )
        except ValueError:
            pass
    date_match = ROLLOUT_DATE_RE.search(path.name)
    if date_match is not None:
        try:
            return dt.datetime(
                int(date_match.group("year")),
                int(date_match.group("month")),
                int(date_match.group("day")),
                tzinfo=UTC,
            )
        except ValueError:
            pass
    for index in range(max(0, len(relative_parts) - 3)):
        year, month, day = relative_parts[index : index + 3]
        if not (year.isdigit() and month.isdigit() and day.isdigit()):
            continue
        try:
            return dt.datetime(int(year), int(month), int(day), tzinfo=UTC)
        except ValueError:
            continue
    return None


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.normpath(os.fspath(path.absolute())))


def path_has_non_printable_characters(path: Path) -> bool:
    return any(not character.isprintable() for character in os.fspath(path))


def capture_rollout_candidate(
    path: Path,
    root: Path,
    *,
    root_metadata: os.stat_result | None = None,
    file_metadata: os.stat_result | None = None,
) -> RolloutCandidate:
    root = lexical_absolute(root)
    path = lexical_absolute(path)
    if path_has_non_printable_characters(root):
        raise CorpusError("rollout root path contains non-printable characters")
    if path_has_non_printable_characters(path):
        raise CorpusError("rollout candidate path contains non-printable characters")
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError as error:
        raise CorpusError(f"rollout candidate escapes root: {path}") from error
    if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
        raise CorpusError(f"unsafe rollout candidate path: {path}")
    try:
        root_metadata = root_metadata or root.lstat()
        file_metadata = file_metadata or path.lstat()
    except OSError as error:
        raise CorpusError(
            f"unable to inspect rollout candidate {path}: {error}"
        ) from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise CorpusError(f"unsafe rollout root: {root}")
    if stat.S_ISLNK(file_metadata.st_mode) or not stat.S_ISREG(file_metadata.st_mode):
        raise CorpusError(f"unsafe rollout candidate: {path}")
    return RolloutCandidate(
        path=path,
        root=root,
        relative_parts=relative_parts,
        root_device=root_metadata.st_dev,
        root_inode=root_metadata.st_ino,
        file_device=file_metadata.st_dev,
        file_inode=file_metadata.st_ino,
        file_size=file_metadata.st_size,
    )


def open_rollout_candidate(
    candidate: RolloutCandidate,
) -> tuple[int, os.stat_result]:
    try:
        root_fd = os.open(candidate.root, directory_open_flags())
    except OSError as error:
        raise CorpusError(
            f"rollout root changed after inventory: {candidate.root}: {error}"
        ) from error
    current_fd = root_fd
    try:
        root_metadata = os.fstat(root_fd)
        if (root_metadata.st_dev, root_metadata.st_ino) != (
            candidate.root_device,
            candidate.root_inode,
        ):
            raise CorpusError(f"rollout root changed after inventory: {candidate.root}")
        for component in candidate.relative_parts[:-1]:
            try:
                next_fd = os.open(component, directory_open_flags(), dir_fd=current_fd)
            except OSError as error:
                raise CorpusError(
                    f"rollout candidate changed after inventory: {candidate.path}: {error}"
                ) from error
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(
                candidate.relative_parts[-1],
                flags,
                dir_fd=current_fd,
            )
        except OSError as error:
            raise CorpusError(
                f"rollout candidate changed after inventory: {candidate.path}: {error}"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or (
                metadata.st_dev,
                metadata.st_ino,
            ) != (candidate.file_device, candidate.file_inode):
                raise CorpusError(
                    f"rollout candidate changed after inventory: {candidate.path}"
                )
            if metadata.st_size < candidate.file_size:
                raise CorpusError(
                    f"rollout was truncated after inventory: {candidate.path}"
                )
            return descriptor, metadata
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)


def validate_inventory_directories(
    root: Path,
    snapshots: dict[tuple[str, ...], InventoryDirectory],
) -> None:
    try:
        root_fd = os.open(root, directory_open_flags())
    except OSError as error:
        raise CorpusError(
            f"rollout inventory changed during traversal: {root}: {error}"
        ) from error
    try:
        for relative_parts, snapshot in sorted(snapshots.items()):
            if snapshot.entries is None:
                path = root.joinpath(*relative_parts)
                raise CorpusError(
                    f"rollout inventory did not visit listed directory: {path}"
                )
            current_fd = root_fd
            try:
                for component in relative_parts:
                    try:
                        next_fd = os.open(
                            component,
                            directory_open_flags(),
                            dir_fd=current_fd,
                        )
                    except OSError as error:
                        path = root.joinpath(*relative_parts)
                        raise CorpusError(
                            "rollout inventory changed during traversal: "
                            f"{path}: {error}"
                        ) from error
                    if current_fd != root_fd:
                        os.close(current_fd)
                    current_fd = next_fd
                metadata = os.fstat(current_fd)
                path = root.joinpath(*relative_parts)
                if (metadata.st_dev, metadata.st_ino) != (
                    snapshot.device,
                    snapshot.inode,
                ):
                    raise CorpusError(
                        f"rollout inventory changed during traversal: {path}"
                    )
                try:
                    current_entries = []
                    for name in sorted(os.listdir(current_fd)):
                        entry_metadata = os.stat(
                            name,
                            dir_fd=current_fd,
                            follow_symlinks=False,
                        )
                        current_entries.append(
                            capture_inventory_entry(name, entry_metadata)
                        )
                except OSError as error:
                    raise CorpusError(
                        "unable to revalidate rollout inventory directory "
                        f"{path}: {error}"
                    ) from error
                if tuple(current_entries) != snapshot.entries:
                    raise CorpusError(
                        f"rollout inventory changed during traversal: {path}"
                    )
            finally:
                if current_fd != root_fd:
                    os.close(current_fd)
    finally:
        os.close(root_fd)


def inventory_root(root: Path) -> list[RolloutCandidate]:
    root = lexical_absolute(root)
    if path_has_non_printable_characters(root):
        raise CorpusError("rollout root path contains non-printable characters")
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return []
    except OSError as error:
        raise CorpusError(f"unable to inspect rollout root {root}: {error}") from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise CorpusError(f"unsafe rollout root: {root}")
    resolved_root = root.resolve(strict=True)
    candidates: list[RolloutCandidate] = []
    directory_snapshots: dict[tuple[str, ...], InventoryDirectory] = {
        (): InventoryDirectory(
            device=root_metadata.st_dev,
            inode=root_metadata.st_ino,
            entries=None,
        )
    }

    def traversal_error(error: OSError) -> None:
        raise CorpusError(
            f"unable to inventory rollout root {root}: {error}"
        ) from error

    try:
        for current, directories, filenames in os.walk(
            root,
            topdown=True,
            onerror=traversal_error,
            followlinks=False,
        ):
            directories.sort()
            filenames.sort()
            current_path = lexical_absolute(Path(current))
            try:
                current_parts = current_path.relative_to(root).parts
                current_metadata = current_path.lstat()
            except (OSError, ValueError) as error:
                raise CorpusError(
                    f"unable to inspect rollout directory {current_path}: {error}"
                ) from error
            expected_current = directory_snapshots.get(current_parts)
            if expected_current is not None and (
                current_metadata.st_dev,
                current_metadata.st_ino,
            ) != (expected_current.device, expected_current.inode):
                raise CorpusError(
                    f"rollout inventory changed during traversal: {current_path}"
                )
            if stat.S_ISLNK(current_metadata.st_mode) or not stat.S_ISDIR(
                current_metadata.st_mode
            ):
                raise CorpusError(f"unsafe rollout directory: {current_path}")
            directory_names = set(directories)
            entry_metadata: dict[str, os.stat_result] = {}
            entries: list[InventoryEntry] = []
            for name in sorted([*directories, *filenames]):
                metadata = (current_path / name).lstat()
                if name in directory_names:
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
                        metadata.st_mode
                    ):
                        raise CorpusError(
                            f"unsafe rollout directory: {current_path / name}"
                        )
                elif stat.S_ISDIR(metadata.st_mode):
                    raise CorpusError(
                        "rollout inventory changed during traversal: "
                        f"{current_path / name}"
                    )
                entry_metadata[name] = metadata
                entries.append(capture_inventory_entry(name, metadata))
            directory_snapshots[current_parts] = InventoryDirectory(
                device=current_metadata.st_dev,
                inode=current_metadata.st_ino,
                entries=tuple(entries),
            )
            for directory in directories:
                path = current_path / directory
                metadata = entry_metadata[directory]
                relative_parts = path.relative_to(root).parts
                expected = directory_snapshots.get(relative_parts)
                if expected is not None and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) != (expected.device, expected.inode):
                    raise CorpusError(
                        f"rollout inventory changed during traversal: {path}"
                    )
                directory_snapshots[relative_parts] = InventoryDirectory(
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    entries=expected.entries if expected is not None else None,
                )
            for filename in filenames:
                if not filename.startswith("rollout-") or not filename.endswith(
                    ".jsonl"
                ):
                    continue
                if filename.startswith("rollout-summary"):
                    continue
                path = current_path / filename
                file_metadata = entry_metadata[filename]
                if stat.S_ISLNK(file_metadata.st_mode) or not stat.S_ISREG(
                    file_metadata.st_mode
                ):
                    raise CorpusError(f"unsafe rollout candidate: {path}")
                try:
                    path.resolve(strict=True).relative_to(resolved_root)
                except (OSError, ValueError) as error:
                    raise CorpusError(
                        f"rollout candidate escapes root: {path}"
                    ) from error
                candidates.append(
                    capture_rollout_candidate(
                        path,
                        root,
                        root_metadata=root_metadata,
                        file_metadata=file_metadata,
                    )
                )
    except OSError as error:
        raise CorpusError(
            f"unable to inventory rollout root {root}: {error}"
        ) from error
    validate_inventory_directories(root, directory_snapshots)
    return sorted(candidates, key=lambda candidate: candidate.path.as_posix())


def scan_rollout_metadata(
    path: Path | RolloutCandidate,
    source: str,
    root: Path,
    start: dt.datetime,
    end: dt.datetime,
) -> RolloutMetadata:
    candidate = (
        path
        if isinstance(path, RolloutCandidate)
        else capture_rollout_candidate(path, root)
    )
    if candidate.root != lexical_absolute(root):
        raise CorpusError(f"rollout candidate root mismatch: {candidate.path}")
    rollout_path = candidate.path
    lifecycle_ids: set[str] = set()
    first_lifecycle_id: str | None = None
    saw_lifecycle_record = False
    digest = hashlib.sha256()
    captured_bytes = 0
    source_bytes = 0
    first_timestamp: dt.datetime | None = None
    has_record_timestamp = False
    has_in_window_record = False
    record_count = 0
    ignored_trailing_fragment = False
    try:
        descriptor, opened_metadata = open_rollout_candidate(candidate)
        snapshot_bytes = opened_metadata.st_size
        try:
            rollout_handle = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with rollout_handle as handle:
            remaining = snapshot_bytes
            line_no = 0
            while remaining:
                raw_line = handle.readline(remaining)
                if not raw_line:
                    raise CorpusError(
                        f"rollout was truncated during metadata scan: {rollout_path}"
                    )
                remaining -= len(raw_line)
                line_no += 1
                captured_bytes += len(raw_line)
                if not raw_line.strip():
                    digest.update(raw_line)
                    source_bytes += len(raw_line)
                    continue
                try:
                    row = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    if (
                        source == "active"
                        and remaining == 0
                        and not raw_line.endswith(b"\n")
                    ):
                        ignored_trailing_fragment = True
                        break
                    raise CorpusError(
                        f"invalid rollout JSON at {rollout_path}:{line_no}"
                    ) from error
                if not isinstance(row, dict):
                    raise CorpusError(
                        f"non-object rollout record at {rollout_path}:{line_no}"
                    )
                digest.update(raw_line)
                source_bytes += len(raw_line)
                record_ids = record_lifecycle_ids(row)
                if record_ids:
                    if not saw_lifecycle_record:
                        first_lifecycle_id = (
                            record_ids[0] if len(record_ids) == 1 else None
                        )
                        saw_lifecycle_record = True
                    lifecycle_ids.update(record_ids)
                timestamp = record_timestamp(row)
                record_count += 1
                if timestamp is not None:
                    has_record_timestamp = True
                    first_timestamp = (
                        timestamp
                        if first_timestamp is None
                        else min(first_timestamp, timestamp)
                    )
                    has_in_window_record = has_in_window_record or in_window(
                        timestamp,
                        start,
                        end,
                    )
            final_metadata = os.fstat(handle.fileno())
    except OSError as error:
        raise CorpusError(f"unable to read rollout {rollout_path}: {error}") from error
    if (
        (final_metadata.st_dev, final_metadata.st_ino)
        != (candidate.file_device, candidate.file_inode)
        or final_metadata.st_size < snapshot_bytes
        or captured_bytes != snapshot_bytes
        or source_bytes > snapshot_bytes
        or (source_bytes != snapshot_bytes and not ignored_trailing_fragment)
    ):
        raise CorpusError(f"rollout changed during metadata scan: {rollout_path}")
    scanned_candidate = replace(
        candidate,
        file_size=source_bytes,
    )
    fallback_timestamp = fallback_path_timestamp(rollout_path, candidate.root)
    return RolloutMetadata(
        candidate=scanned_candidate,
        source=source,
        lifecycle_ids=frozenset(lifecycle_ids),
        first_lifecycle_id=first_lifecycle_id,
        filename_session_id=filename_session_id(rollout_path),
        content_sha256=digest.hexdigest(),
        source_bytes=source_bytes,
        fallback_timestamp=fallback_timestamp,
        first_timestamp=first_timestamp or fallback_timestamp,
        has_record_timestamp=has_record_timestamp,
        has_in_window_record=has_in_window_record,
        fallback_accepted=(
            record_count > 0
            and not has_record_timestamp
            and in_window(fallback_timestamp, start, end)
        ),
        record_count=record_count,
    )


def load_rollout_records(metadata: RolloutMetadata) -> Rollout:
    records: list[Record] = []
    digest = hashlib.sha256()
    fingerprint_ids = GeneratedIdCanonicalizer()
    try:
        descriptor, _ = open_rollout_candidate(metadata.candidate)
        try:
            rollout_handle = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with rollout_handle as handle:
            remaining = metadata.source_bytes
            line_no = 0
            while remaining:
                raw_line = handle.readline(remaining)
                if not raw_line:
                    raise CorpusError(
                        f"rollout was truncated during corpus construction: {metadata.path}"
                    )
                remaining -= len(raw_line)
                line_no += 1
                digest.update(raw_line)
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise CorpusError(
                        f"rollout changed or became invalid at {metadata.path}:{line_no}"
                    ) from error
                if not isinstance(row, dict):
                    raise CorpusError(
                        f"rollout changed or became non-object at {metadata.path}:{line_no}"
                    )
                records.append(
                    Record(
                        line_no=line_no,
                        fingerprint=record_fingerprint(row, fingerprint_ids),
                        timestamp=record_timestamp(row),
                        replay_evidence=record_replay_evidence(row),
                    )
                )
            final_metadata = os.fstat(handle.fileno())
    except OSError as error:
        raise CorpusError(
            f"unable to reread rollout {metadata.path}: {error}"
        ) from error
    if (
        (final_metadata.st_dev, final_metadata.st_ino)
        != (metadata.candidate.file_device, metadata.candidate.file_inode)
        or final_metadata.st_size < metadata.source_bytes
        or digest.hexdigest() != metadata.content_sha256
        or len(records) != metadata.record_count
    ):
        raise CorpusError(
            f"rollout prefix changed during corpus construction: {metadata.path}"
        )
    return Rollout(
        path=metadata.path,
        source=metadata.source,
        records=tuple(records),
        lifecycle_ids=metadata.lifecycle_ids,
        first_lifecycle_id=metadata.first_lifecycle_id,
        filename_session_id=metadata.filename_session_id,
        content_sha256=metadata.content_sha256,
        fallback_timestamp=metadata.fallback_timestamp,
        first_timestamp=metadata.first_timestamp,
        window_accepted=metadata.accepted,
    )


def common_prefix_length(left: Rollout, right: Rollout) -> int:
    count = 0
    for left_record, right_record in zip(left.records, right.records):
        if left_record.fingerprint != right_record.fingerprint:
            break
        count += 1
    return count


def confirmed_replay_prefix_length(left: Rollout, right: Rollout) -> int:
    prefix = common_prefix_length(left, right)
    if prefix == 0:
        return 0
    if left.content_sha256 == right.content_sha256:
        return prefix
    for index in range(prefix - 1, -1, -1):
        if left.records[index].replay_evidence and right.records[index].replay_evidence:
            return index + 1
    return 0


def filename_candidates_compatible(
    left_owner: str | None,
    right_owner: str | None,
    left_ambiguous: bool,
    right_ambiguous: bool,
) -> bool:
    if left_ambiguous or right_ambiguous:
        return False
    return len({owner for owner in (left_owner, right_owner) if owner}) <= 1


def content_identity(
    owner_id: str | None,
    lifecycle_ids: frozenset[str],
    filename_id: str | None,
    identity_ambiguous: bool,
) -> tuple[str, str] | None:
    if lifecycle_ids:
        return ("lifecycle-set", "\0".join(sorted(lifecycle_ids)))
    if owner_id is not None:
        return ("owner", owner_id)
    if identity_ambiguous:
        return ("ambiguous-lifecycles", "\0".join(sorted(lifecycle_ids)))
    if filename_id is not None:
        return ("filename", filename_id)
    return None


def group_metadata(metadata: list[RolloutMetadata]) -> list[list[RolloutMetadata]]:
    """Build broad groups before loading fingerprint sequences.

    Filename IDs are candidate keys at this stage. The second pass splits candidates
    whose ordered fingerprints do not actually match.
    """

    union_find = UnionFind(len(metadata))
    lifecycle_owner: dict[str, int] = {}
    content_owner: dict[tuple[tuple[str, str], str], int] = {}
    filename_members: dict[str, list[int]] = {}
    for index, rollout in enumerate(metadata):
        if rollout.owner_id is not None:
            owner = lifecycle_owner.setdefault(rollout.owner_id, index)
            union_find.union(owner, index)
        identity = content_identity(
            rollout.owner_id,
            rollout.lifecycle_ids,
            rollout.filename_session_id,
            rollout.identity_ambiguous,
        )
        if identity is not None:
            owner = content_owner.setdefault(
                (identity, rollout.content_sha256),
                index,
            )
            union_find.union(owner, index)
        if rollout.filename_session_id is not None:
            filename_members.setdefault(rollout.filename_session_id, []).append(index)
    for members in filename_members.values():
        for offset, left_index in enumerate(members):
            for right_index in members[offset + 1 :]:
                if filename_candidates_compatible(
                    metadata[left_index].owner_id,
                    metadata[right_index].owner_id,
                    metadata[left_index].identity_ambiguous,
                    metadata[right_index].identity_ambiguous,
                ):
                    union_find.union(left_index, right_index)
    groups: dict[int, list[RolloutMetadata]] = {}
    for index, rollout in enumerate(metadata):
        groups.setdefault(union_find.find(index), []).append(rollout)
    return list(groups.values())


def group_rollouts(rollouts: list[Rollout]) -> list[list[Rollout]]:
    union_find = UnionFind(len(rollouts))
    component_owners = [
        {rollout.owner_id} if rollout.owner_id is not None else set()
        for rollout in rollouts
    ]

    def union_components(left: int, right: int) -> None:
        left_root = union_find.find(left)
        right_root = union_find.find(right)
        if left_root == right_root:
            return
        union_find.union(left_root, right_root)
        component_owners[left_root].update(component_owners[right_root])

    lifecycle_owner: dict[str, int] = {}
    content_owner: dict[tuple[tuple[str, str], str], int] = {}
    filename_members: dict[str, list[int]] = {}
    for index, rollout in enumerate(rollouts):
        if rollout.owner_id is not None:
            owner = lifecycle_owner.setdefault(rollout.owner_id, index)
            union_components(owner, index)
        identity = content_identity(
            rollout.owner_id,
            rollout.lifecycle_ids,
            rollout.filename_session_id,
            rollout.identity_ambiguous,
        )
        if identity is not None:
            owner = content_owner.setdefault(
                (identity, rollout.content_sha256),
                index,
            )
            union_components(owner, index)
        if rollout.filename_session_id is not None:
            filename_members.setdefault(rollout.filename_session_id, []).append(index)
    for members in filename_members.values():
        for offset, left_index in enumerate(members):
            for right_index in members[offset + 1 :]:
                left_owners = component_owners[union_find.find(left_index)]
                right_owners = component_owners[union_find.find(right_index)]
                if not filename_candidates_compatible(
                    next(iter(left_owners), None),
                    next(iter(right_owners), None),
                    rollouts[left_index].identity_ambiguous,
                    rollouts[right_index].identity_ambiguous,
                ):
                    continue
                if (
                    common_prefix_length(rollouts[left_index], rollouts[right_index])
                    > 0
                ):
                    union_components(left_index, right_index)
    groups: dict[int, list[Rollout]] = {}
    for index, rollout in enumerate(rollouts):
        groups.setdefault(union_find.find(index), []).append(rollout)
    return list(groups.values())


def in_window(value: dt.datetime | None, start: dt.datetime, end: dt.datetime) -> bool:
    return value is not None and start <= value < end


def line_ranges(lines: list[int]) -> list[list[int]]:
    ranges: list[list[int]] = []
    for line in lines:
        if not ranges or line != ranges[-1][1] + 1:
            ranges.append([line, line])
        else:
            ranges[-1][1] = line
    return ranges


def rollout_sort_key(
    rollout: Rollout,
) -> tuple[
    tuple[bool, dt.datetime],
    tuple[tuple[bool, dt.datetime], ...],
    int,
    int,
    str,
]:
    missing_timestamp = dt.datetime.max.replace(tzinfo=UTC)
    record_timestamps = tuple(
        record.timestamp
        for record in rollout.records
        if record.timestamp is not None
    )
    has_record_timestamp = bool(record_timestamps)
    if record_timestamps:
        provenance_start = (False, min(record_timestamps))
    elif rollout.fallback_timestamp is not None:
        provenance_start = (False, rollout.fallback_timestamp)
    else:
        provenance_start = (True, missing_timestamp)
    if rollout.records and not has_record_timestamp:
        fallback_timestamp = rollout.fallback_timestamp or missing_timestamp
        timestamp_source = tuple(
            (rollout.fallback_timestamp is None, fallback_timestamp)
            for _record in rollout.records
        )
    else:
        timestamp_source = tuple(
            (record.timestamp is None, record.timestamp or missing_timestamp)
            for record in rollout.records
        )
    if not timestamp_source:
        timestamp_source = (
            (
                rollout.fallback_timestamp is None,
                rollout.fallback_timestamp or missing_timestamp,
            ),
        )
    source_rank = 0 if rollout.source == "active" else 1
    return (
        provenance_start,
        timestamp_source,
        len(rollout.records),
        source_rank,
        rollout.path.as_posix(),
    )


def union_entries(
    groups: list[list[Rollout]],
    start: dt.datetime,
    end: dt.datetime,
    group_start: int,
) -> tuple[list[dict[str, object]], int, int, int, int]:
    entries: list[dict[str, object]] = []
    replayed_record_count = 0
    collapsed_rollout_count = 0
    accepted_group_count = 0
    cross_root_duplicate_group_count = 0
    ordered_groups = sorted(groups, key=lambda item: min(map(rollout_sort_key, item)))
    for group_index, group in enumerate(ordered_groups, group_start):
        histories: list[Rollout] = []
        group_accepted = False
        group_window_accepted = any(rollout.window_accepted for rollout in group)
        group_replayed_record_count = 0
        group_collapsed_rollout_count = 0
        group_cross_root_duplicate = False
        for rollout in sorted(group, key=rollout_sort_key):
            previous_prefixes = [
                (confirmed_replay_prefix_length(rollout, previous), previous)
                for previous in histories
            ]
            prefix = max((length for length, _ in previous_prefixes), default=0)
            group_cross_root_duplicate = group_cross_root_duplicate or any(
                length > 0 and previous.source != rollout.source
                for length, previous in previous_prefixes
            )
            group_replayed_record_count += prefix
            unique_records = rollout.records[prefix:]
            relevant_lines = [
                record.line_no
                for record in unique_records
                if in_window(record.timestamp, start, end)
            ]
            fallback_accepted = (
                not any(record.timestamp is not None for record in rollout.records)
                and in_window(rollout.fallback_timestamp, start, end)
                and bool(unique_records)
                and not (histories and prefix == len(rollout.records))
            )
            if fallback_accepted:
                relevant_lines = [record.line_no for record in unique_records]
            if prefix == len(rollout.records) and histories:
                group_collapsed_rollout_count += 1
            if relevant_lines or fallback_accepted:
                group_accepted = True
                entries.append(
                    {
                        "accepted_line_ranges": line_ranges(relevant_lines),
                        "accepted_record_count": len(relevant_lines),
                        "fallback_date_used": fallback_accepted,
                        "group": group_index,
                        "lifecycle_id": rollout.lifecycle_id,
                        "lifecycle_ids": sorted(rollout.lifecycle_ids),
                        "owner_id": rollout.owner_id,
                        "path": rollout.path.as_posix(),
                        "replayed_prefix_records": prefix,
                        "root": rollout.source,
                        "unique_suffix_records": len(unique_records),
                    }
                )
            histories.append(rollout)
        if group_accepted:
            accepted_group_count += 1
        if group_window_accepted:
            replayed_record_count += group_replayed_record_count
            collapsed_rollout_count += group_collapsed_rollout_count
            if group_cross_root_duplicate:
                cross_root_duplicate_group_count += 1
    return (
        entries,
        replayed_record_count,
        collapsed_rollout_count,
        accepted_group_count,
        cross_root_duplicate_group_count,
    )


def write_artifact(directory_fd: int, name: str, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def write_lines(directory_fd: int, name: str, values: Iterable[str]) -> None:
    content = "".join(f"{value}\n" for value in values)
    write_artifact(directory_fd, name, content)


def write_json(directory_fd: int, name: str, value: object) -> None:
    content = f"{json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)}\n"
    write_artifact(directory_fd, name, content)


def directory_open_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    return flags | getattr(os, "O_NOFOLLOW", 0)


def unsafe_symlink_at(parent_fd: int, name: str) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISLNK(metadata.st_mode)


def open_or_create_directory_at(parent_fd: int, name: str, path: Path) -> int:
    flags = directory_open_flags()
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    except OSError as error:
        if unsafe_symlink_at(parent_fd, name):
            raise CorpusError(f"unsafe output path uses a symlink: {path}") from error
        raise CorpusError(f"unable to open output ancestor {path}: {error}") from error
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        try:
            return os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            if unsafe_symlink_at(parent_fd, name):
                raise CorpusError(
                    f"unsafe output path uses a symlink: {path}"
                ) from error
            raise CorpusError(
                f"unable to open output ancestor {path}: {error}"
            ) from error
    except OSError as error:
        raise CorpusError(
            f"unable to create output ancestor {path}: {error}"
        ) from error
    try:
        expected = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise CorpusError(
            f"unable to open created output ancestor {path}: {error}"
        ) from error
    actual = os.fstat(descriptor)
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
        os.close(descriptor)
        raise CorpusError(f"output ancestor changed during creation: {path}")
    return descriptor


def expand_trusted_root_symlinks(root_fd: int, components: list[str]) -> list[str]:
    expanded = list(components)
    for _ in range(8):
        if not expanded:
            return expanded
        try:
            metadata = os.stat(expanded[0], dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return expanded
        except OSError as error:
            raise CorpusError(
                f"unable to inspect output path /{expanded[0]}: {error}"
            ) from error
        if not stat.S_ISLNK(metadata.st_mode):
            return expanded
        if metadata.st_uid != 0:
            raise CorpusError(f"unsafe output path uses a symlink: /{expanded[0]}")
        try:
            target = os.readlink(expanded[0], dir_fd=root_fd)
        except OSError as error:
            raise CorpusError(
                f"unable to inspect output path /{expanded[0]}: {error}"
            ) from error
        normalized = Path(os.path.normpath(f"/{target.lstrip('/')}"))
        expanded = [*normalized.parts[1:], *expanded[1:]]
    raise CorpusError("too many trusted root symlinks in output path")


def create_fresh_directory_at(parent_fd: int, name: str, path: Path) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError as error:
        if unsafe_symlink_at(parent_fd, name):
            raise CorpusError(f"unsafe output path uses a symlink: {path}") from error
        raise CorpusError(
            f"output directory must be fresh and nonexistent: {path}"
        ) from error
    except OSError as error:
        raise CorpusError(
            f"unable to create output directory {path}: {error}"
        ) from error
    try:
        expected = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, directory_open_flags(), dir_fd=parent_fd)
    except OSError as error:
        raise CorpusError(
            f"unable to open created output directory {path}: {error}"
        ) from error
    actual = os.fstat(descriptor)
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
        os.close(descriptor)
        raise CorpusError(f"output directory changed during creation: {path}")
    return descriptor


def create_output_directory(output: Path) -> int:
    absolute = Path(os.path.normpath(os.fspath(output.absolute())))
    components = list(absolute.parts[1:])
    if not components:
        raise CorpusError("output directory must not be the filesystem root")
    try:
        root_fd = os.open("/", directory_open_flags())
    except OSError as error:
        raise CorpusError(f"unable to open filesystem root: {error}") from error
    try:
        components = expand_trusted_root_symlinks(root_fd, components)
        if not components:
            raise CorpusError("output directory resolves to the filesystem root")
        current_fd = root_fd
        try:
            current_path = Path("/")
            for component in components[:-1]:
                current_path /= component
                next_fd = open_or_create_directory_at(
                    current_fd,
                    component,
                    current_path,
                )
                if current_fd != root_fd:
                    os.close(current_fd)
                current_fd = next_fd
            return create_fresh_directory_at(
                current_fd,
                components[-1],
                absolute,
            )
        finally:
            if current_fd != root_fd:
                os.close(current_fd)
    finally:
        os.close(root_fd)


def build_corpus(
    codex_home: Path,
    start: dt.datetime,
    end: dt.datetime,
    output: Path,
    sample_limit: int,
) -> dict[str, object]:
    if start >= end:
        raise CorpusError("window start must be earlier than window end")
    active_root = codex_home / "sessions"
    archived_root = codex_home / "archived_sessions"
    active_candidates = inventory_root(active_root)
    archived_candidates = inventory_root(archived_root)
    active_metadata = [
        scan_rollout_metadata(candidate, "active", active_root, start, end)
        for candidate in active_candidates
    ]
    archived_metadata = [
        scan_rollout_metadata(candidate, "archived", archived_root, start, end)
        for candidate in archived_candidates
    ]
    metadata = active_metadata + archived_metadata
    active_accepted = [rollout for rollout in active_metadata if rollout.accepted]
    archived_accepted = [rollout for rollout in archived_metadata if rollout.accepted]
    entries: list[dict[str, object]] = []
    replayed_count = 0
    collapsed_count = 0
    accepted_group_count = 0
    cross_root_duplicate_groups = 0
    next_group = 1
    broad_groups = sorted(
        group_metadata(metadata),
        key=lambda group: min(rollout.path.as_posix() for rollout in group),
    )
    for broad_group in broad_groups:
        if not any(rollout.accepted for rollout in broad_group):
            continue
        refined_groups = group_rollouts(
            [load_rollout_records(rollout) for rollout in broad_group]
        )
        for refined_group in refined_groups:
            (
                new_entries,
                new_replayed,
                new_collapsed,
                new_accepted_groups,
                new_cross_root_duplicates,
            ) = union_entries(
                [refined_group],
                start,
                end,
                next_group,
            )
            entries.extend(new_entries)
            replayed_count += new_replayed
            collapsed_count += new_collapsed
            accepted_group_count += new_accepted_groups
            cross_root_duplicate_groups += new_cross_root_duplicates
            next_group += 1
    counts = {
        "active_accepted": len(active_accepted),
        "active_candidate": len(active_candidates),
        "active_parsed": len(active_metadata),
        "archived_accepted": len(archived_accepted),
        "archived_candidate": len(archived_candidates),
        "archived_parsed": len(archived_metadata),
        "cross_root_duplicate_groups": cross_root_duplicate_groups,
        "duplicate_rollouts_collapsed": collapsed_count,
        "replayed_prefix_records": replayed_count,
        "union_accepted": len(entries),
        "union_accepted_groups": accepted_group_count,
        "union_candidate": len(metadata),
        "union_parsed": len(metadata),
    }
    manifest: dict[str, object] = {
        "counts": counts,
        "window": {
            "end_exclusive": end.isoformat().replace("+00:00", "Z"),
            "start_inclusive": start.isoformat().replace("+00:00", "Z"),
        },
    }
    directory_fd = create_output_directory(output)
    try:
        write_lines(
            directory_fd,
            "active-paths.txt",
            (candidate.path.as_posix() for candidate in active_candidates),
        )
        write_lines(
            directory_fd,
            "archived-paths.txt",
            (candidate.path.as_posix() for candidate in archived_candidates),
        )
        write_lines(
            directory_fd,
            "active-accepted-paths.txt",
            (rollout.path.as_posix() for rollout in active_accepted),
        )
        write_lines(
            directory_fd,
            "archived-accepted-paths.txt",
            (rollout.path.as_posix() for rollout in archived_accepted),
        )
        write_lines(
            directory_fd,
            "corpus-paths.txt",
            (str(entry["path"]) for entry in entries),
        )
        write_lines(
            directory_fd,
            "corpus.jsonl",
            (
                json.dumps(entry, ensure_ascii=True, sort_keys=True)
                for entry in entries
            ),
        )
        write_json(directory_fd, "manifest.json", manifest)
    except OSError as error:
        raise CorpusError(
            f"unable to write corpus artifacts under {output}: {error}"
        ) from error
    finally:
        os.close(directory_fd)
    for key in (
        "active_candidate",
        "archived_candidate",
        "union_candidate",
        "active_parsed",
        "archived_parsed",
        "union_parsed",
        "active_accepted",
        "archived_accepted",
        "union_accepted",
        "cross_root_duplicate_groups",
        "duplicate_rollouts_collapsed",
        "replayed_prefix_records",
    ):
        print(f"{key.replace('_', ' ')} count: {counts[key]}")
    for entry in entries[:sample_limit]:
        ranges = entry["accepted_line_ranges"]
        range_sample = ranges[:3] if isinstance(ranges, list) else []
        print(
            "sample: "
            f"{entry['root']}:{entry['path']}:"
            f"accepted_records={entry['accepted_record_count']}:"
            f"line_ranges={range_sample}:"
            f"replayed_prefix={entry['replayed_prefix_records']}"
        )
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--codex-home", type=Path, required=True)
    result.add_argument("--start", type=parse_instant, required=True)
    result.add_argument("--end", type=parse_instant, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--sample-limit", type=int, default=20)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.sample_limit < 0:
        parser().error("--sample-limit must be non-negative")
    try:
        build_corpus(
            args.codex_home.expanduser(),
            args.start,
            args.end,
            args.output.expanduser(),
            args.sample_limit,
        )
    except CorpusError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
