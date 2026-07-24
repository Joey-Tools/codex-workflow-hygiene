#!/usr/bin/env python3
"""Locate one Codex session without loading transcript records into stdout."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, BinaryIO, Iterator


MAX_RECORD_BYTES = 1024 * 1024
DRAIN_CHUNK_BYTES = 64 * 1024
PREFIX_HASH_CHUNK_BYTES = 64 * 1024
MAX_FIELD_CHARS = 320
MAX_PATH_CHARS = 4096
MAX_SELECTOR_CHARS = 512
MAX_ROLLOUT_INVENTORY_ENTRIES = 100_000
UUID_PATTERN = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)


class CoveragePartial(RuntimeError):
    """A source could not prove the protected lookup coverage."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ObjectBinding:
    device: int
    inode: int
    file_type: int
    owner: int
    group: int
    permissions: int


@dataclass(frozen=True, order=True, slots=True)
class InventoryEntry:
    name: str
    device: int
    inode: int
    file_type: int


@dataclass(frozen=True, slots=True)
class DirectorySnapshot:
    binding: ObjectBinding
    entries: tuple[InventoryEntry, ...]


@dataclass(slots=True)
class DirectoryChain:
    path: Path
    descriptors: list[int]
    bindings: tuple[ObjectBinding, ...]

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    def close(self) -> None:
        while self.descriptors:
            os.close(self.descriptors.pop())

    def __enter__(self) -> DirectoryChain:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _bounded_text(value: object, limit: int = MAX_FIELD_CHARS) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _bounded_path(path: Path) -> str:
    return os.fspath(path)[:MAX_PATH_CHARS]


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _normalize_session_id(value: str) -> str:
    return value.lower() if UUID_PATTERN.fullmatch(value) else value


def _binding(metadata: os.stat_result) -> ObjectBinding:
    return ObjectBinding(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        file_type=stat.S_IFMT(metadata.st_mode),
        owner=metadata.st_uid,
        group=metadata.st_gid,
        permissions=stat.S_IMODE(metadata.st_mode),
    )


def _inventory_entry(name: str, metadata: os.stat_result) -> InventoryEntry:
    return InventoryEntry(
        name=name,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        file_type=stat.S_IFMT(metadata.st_mode),
    )


def _directory_open_flags() -> int:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        raise CoveragePartial("required-directory-open-flags-unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK


def _regular_open_flags() -> int:
    required = ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        raise CoveragePartial("required-file-open-flags-unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def _open_directory_at(parent_fd: int, name: str) -> tuple[int, ObjectBinding]:
    descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise CoveragePartial("source-not-directory")
        return descriptor, _binding(metadata)
    except BaseException:
        os.close(descriptor)
        raise


def _open_absolute_directory_chain(path: Path) -> DirectoryChain:
    absolute = _lexical_absolute(path)
    if absolute.anchor != os.sep:
        raise CoveragePartial("codex-home-not-absolute")
    components = absolute.parts[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise CoveragePartial("codex-home-path-not-contained")

    descriptors: list[int] = []
    bindings: list[ObjectBinding] = []
    try:
        root_fd = os.open(os.sep, _directory_open_flags())
        descriptors.append(root_fd)
        root_metadata = os.fstat(root_fd)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise CoveragePartial("filesystem-root-not-directory")
        bindings.append(_binding(root_metadata))
        for component in components:
            descriptor, binding = _open_directory_at(
                descriptors[-1],
                component,
            )
            descriptors.append(descriptor)
            bindings.append(binding)
    except BaseException:
        while descriptors:
            os.close(descriptors.pop())
        raise
    return DirectoryChain(
        path=absolute,
        descriptors=descriptors,
        bindings=tuple(bindings),
    )


def _validated_fresh_directory_chain(chain: DirectoryChain) -> DirectoryChain:
    try:
        held_bindings = tuple(
            _binding(os.fstat(descriptor)) for descriptor in chain.descriptors
        )
    except OSError as error:
        raise CoveragePartial(
            f"directory-revalidation-unreadable:{type(error).__name__}"
        ) from error
    if held_bindings != chain.bindings:
        raise CoveragePartial("directory-identity-or-access-policy-changed")

    try:
        fresh = _open_absolute_directory_chain(chain.path)
    except FileNotFoundError as error:
        raise CoveragePartial("directory-chain-replaced-or-missing") from error
    except CoveragePartial:
        raise
    except OSError as error:
        raise CoveragePartial(
            f"directory-chain-reopen-failed:{type(error).__name__}"
        ) from error
    if fresh.bindings != chain.bindings:
        fresh.close()
        raise CoveragePartial("directory-chain-replaced-or-access-policy-changed")
    return fresh


def _open_regular_at(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    descriptor = os.open(name, _regular_open_flags(), dir_fd=parent_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CoveragePartial("source-not-regular")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def _bounded_jsonl(
    handle: BinaryIO,
    prefix_bytes: int,
    digest: Any,
) -> Iterator[tuple[int, bytes, bool]]:
    line_number = 0
    remaining = prefix_bytes
    while remaining:
        read_limit = min(remaining, MAX_RECORD_BYTES + 1)
        raw_line = handle.readline(read_limit)
        if not raw_line:
            raise CoveragePartial("source-truncated-during-scan")
        digest.update(raw_line)
        remaining -= len(raw_line)
        line_number += 1
        if len(raw_line) <= MAX_RECORD_BYTES:
            yield line_number, raw_line, False
            continue
        while remaining and not raw_line.endswith(b"\n"):
            raw_line = handle.readline(min(remaining, DRAIN_CHUNK_BYTES))
            if not raw_line:
                raise CoveragePartial("source-truncated-during-scan")
            digest.update(raw_line)
            remaining -= len(raw_line)
        yield line_number, b"", True


def _hash_prefix(descriptor: int, prefix_bytes: int) -> str:
    if not hasattr(os, "pread"):
        raise CoveragePartial("descriptor-prefix-revalidation-unavailable")
    digest = hashlib.sha256()
    offset = 0
    while offset < prefix_bytes:
        try:
            chunk = os.pread(
                descriptor,
                min(PREFIX_HASH_CHUNK_BYTES, prefix_bytes - offset),
                offset,
            )
        except OSError as error:
            raise CoveragePartial(
                f"prefix-revalidation-unreadable:{type(error).__name__}"
            ) from error
        if not chunk:
            raise CoveragePartial("source-truncated-during-revalidation")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _validate_index_completion(
    chain: DirectoryChain,
    name: str,
    descriptor: int,
    initial_metadata: os.stat_result,
    prefix_bytes: int,
    expected_digest: str,
) -> int:
    initial_binding = _binding(initial_metadata)
    try:
        current_metadata = os.fstat(descriptor)
    except OSError as error:
        raise CoveragePartial(
            f"source-revalidation-unreadable:{type(error).__name__}"
        ) from error
    if _binding(current_metadata) != initial_binding:
        raise CoveragePartial("source-identity-or-access-policy-changed")
    if current_metadata.st_size < prefix_bytes:
        raise CoveragePartial("source-truncated-during-revalidation")
    if _hash_prefix(descriptor, prefix_bytes) != expected_digest:
        raise CoveragePartial("source-prefix-mutated")

    fresh_chain = _validated_fresh_directory_chain(chain)
    try:
        try:
            fresh_descriptor, fresh_metadata = _open_regular_at(
                fresh_chain.descriptor,
                name,
            )
        except FileNotFoundError as error:
            raise CoveragePartial("source-rotated-or-replaced") from error
        except CoveragePartial as error:
            raise CoveragePartial("source-rotated-or-replaced") from error
        except OSError as error:
            raise CoveragePartial(
                f"source-reopen-failed:{type(error).__name__}"
            ) from error
        try:
            if _binding(fresh_metadata) != initial_binding:
                raise CoveragePartial("source-rotated-or-replaced")
            if fresh_metadata.st_size < prefix_bytes:
                raise CoveragePartial("source-truncated-during-revalidation")
            if _hash_prefix(fresh_descriptor, prefix_bytes) != expected_digest:
                raise CoveragePartial("source-prefix-mutated")
            try:
                final_metadata = os.fstat(fresh_descriptor)
            except OSError as error:
                raise CoveragePartial(
                    f"source-revalidation-unreadable:{type(error).__name__}"
                ) from error
            if _binding(final_metadata) != initial_binding:
                raise CoveragePartial("source-identity-or-access-policy-changed")
            if final_metadata.st_size < prefix_bytes:
                raise CoveragePartial("source-truncated-during-revalidation")
            return final_metadata.st_size
        finally:
            os.close(fresh_descriptor)
    finally:
        fresh_chain.close()


def _empty_source(kind: str, path: Path) -> dict[str, Any]:
    return {
        "error_count": 0,
        "errors": [],
        "errors_truncated": False,
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


def _mark_partial(source: dict[str, Any], reason: str) -> None:
    source["status"] = "partial"
    reasons = source.setdefault("reasons", [])
    if reason not in reasons:
        reasons.append(reason)
    source["reason"] = reasons[0]


def _record_error(
    source: dict[str, Any],
    *,
    path: Path,
    reason: str,
    limit: int,
) -> None:
    source["error_count"] += 1
    if len(source["errors"]) < limit:
        source["errors"].append(
            {
                "path": _bounded_path(path),
                "reason": reason,
            }
        )
    source["errors_truncated"] = source["error_count"] > len(source["errors"])


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
    path: Path,
    line_number: int,
    row: dict[str, Any],
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
    codex_home: Path,
    name: str,
    *,
    session_id: str | None,
    thread_query: str | None,
    limit: int,
) -> dict[str, Any]:
    codex_home = _lexical_absolute(codex_home)
    path = codex_home / name
    source = _empty_source("index", path)
    source["append_after_boundary"] = False
    source["content_scope"] = "unverified"

    try:
        chain = _open_absolute_directory_chain(codex_home)
    except FileNotFoundError:
        source["status"] = "unavailable"
        source["reason"] = "missing-parent"
        return source
    except CoveragePartial as error:
        _mark_partial(source, error.reason)
        return source
    except OSError as error:
        _mark_partial(source, f"parent-open-failed:{type(error).__name__}")
        return source

    with chain:
        try:
            descriptor, initial_metadata = _open_regular_at(chain.descriptor, name)
        except FileNotFoundError:
            source["status"] = "unavailable"
            source["reason"] = "missing"
            return source
        except CoveragePartial as error:
            _mark_partial(source, error.reason)
            return source
        except OSError as error:
            _mark_partial(source, f"open-failed:{type(error).__name__}")
            return source

        try:
            prefix_bytes = initial_metadata.st_size
            source["captured_prefix_bytes"] = prefix_bytes
            digest = hashlib.sha256()
            try:
                with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
                    for line_number, raw_line, oversized in _bounded_jsonl(
                        handle,
                        prefix_bytes,
                        digest,
                    ):
                        source["records_scanned"] += 1
                        if oversized:
                            source["oversized_records"] += 1
                            continue
                        try:
                            row = json.loads(raw_line)
                        except (
                            UnicodeDecodeError,
                            json.JSONDecodeError,
                            RecursionError,
                        ):
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
            except CoveragePartial as error:
                _mark_partial(source, error.reason)
            except OSError as error:
                _mark_partial(source, f"read-failed:{type(error).__name__}")

            try:
                final_size = _validate_index_completion(
                    chain,
                    name,
                    descriptor,
                    initial_metadata,
                    prefix_bytes,
                    digest.hexdigest(),
                )
            except CoveragePartial as error:
                _mark_partial(source, error.reason)
            except OSError as error:
                _mark_partial(
                    source,
                    f"source-revalidation-failed:{type(error).__name__}",
                )
            else:
                source["final_size_bytes"] = final_size
                source["append_after_boundary"] = final_size > prefix_bytes
                source["content_scope"] = (
                    "stable-captured-prefix-with-later-append"
                    if final_size > prefix_bytes
                    else "stable-complete-file"
                )
        finally:
            os.close(descriptor)

    if source["malformed_records"] or source["oversized_records"]:
        _mark_partial(source, "malformed-or-oversized-records")
    source["matches_truncated"] = source["match_count"] > len(source["matches"])
    return source


def _rollout_name_matches(name: str, session_id: str) -> bool:
    if not name.startswith("rollout-") or not name.endswith(".jsonl"):
        return False
    expected = _normalize_session_id(session_id)
    candidate = name.lower() if UUID_PATTERN.fullmatch(session_id) else name
    return expected in candidate


def _open_relative_directory(
    root_fd: int,
    relative_parts: tuple[str, ...],
    expected: dict[tuple[str, ...], ObjectBinding],
) -> int:
    if any(part in {"", ".", ".."} or os.sep in part for part in relative_parts):
        raise CoveragePartial("rollout-path-not-contained")
    current_fd = os.dup(root_fd)
    try:
        for index, component in enumerate(relative_parts):
            next_fd, actual = _open_directory_at(current_fd, component)
            os.close(current_fd)
            current_fd = next_fd
            prefix = relative_parts[: index + 1]
            if actual != expected[prefix]:
                raise CoveragePartial(
                    "rollout-directory-identity-or-access-policy-changed"
                )
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _capture_directory_inventory(
    descriptor: int,
    *,
    display_path: Path,
    source: dict[str, Any],
    limit: int,
    remaining_budget: int,
) -> tuple[tuple[InventoryEntry, ...], bool]:
    names: list[str] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                source["entries_scanned"] += 1
                names.append(entry.name)
                if len(names) > remaining_budget:
                    return (), False
    except OSError as error:
        _record_error(
            source,
            path=display_path,
            reason=f"scan-failed:{type(error).__name__}",
            limit=limit,
        )
        return (), False

    inventory: list[InventoryEntry] = []
    complete = True
    for name in sorted(names):
        entry_path = display_path / name
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            _record_error(
                source,
                path=entry_path,
                reason=f"entry-stat-failed:{type(error).__name__}",
                limit=limit,
            )
            complete = False
            continue
        inventory.append(_inventory_entry(name, metadata))
    return tuple(inventory), complete


def _revalidate_rollout_tree(
    home_chain: DirectoryChain,
    root_name: str,
    root_fd: int,
    expected_directories: dict[tuple[str, ...], ObjectBinding],
    snapshots: dict[tuple[str, ...], DirectorySnapshot],
) -> None:
    try:
        held_root_binding = _binding(os.fstat(root_fd))
    except OSError as error:
        raise CoveragePartial(
            f"rollout-root-revalidation-unreadable:{type(error).__name__}"
        ) from error
    if held_root_binding != expected_directories[()]:
        raise CoveragePartial("rollout-root-identity-or-access-policy-changed")

    fresh_home = _validated_fresh_directory_chain(home_chain)
    try:
        try:
            fresh_root_fd, fresh_root_binding = _open_directory_at(
                fresh_home.descriptor,
                root_name,
            )
        except (FileNotFoundError, CoveragePartial) as error:
            raise CoveragePartial("rollout-root-replaced-or-escaped") from error
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise CoveragePartial("rollout-root-replaced-or-escaped") from error
            raise CoveragePartial(
                f"rollout-root-reopen-failed:{type(error).__name__}"
            ) from error
        try:
            if fresh_root_binding != expected_directories[()]:
                raise CoveragePartial("rollout-root-replaced-or-escaped")
            revalidated_entries = 0
            for relative_parts in sorted(snapshots):
                snapshot = snapshots[relative_parts]
                if relative_parts:
                    try:
                        directory_fd = _open_relative_directory(
                            fresh_root_fd,
                            relative_parts,
                            expected_directories,
                        )
                    except (FileNotFoundError, KeyError, CoveragePartial) as error:
                        raise CoveragePartial(
                            "rollout-directory-replaced-or-escaped"
                        ) from error
                    except OSError as error:
                        raise CoveragePartial(
                            "rollout-directory-revalidation-failed:"
                            f"{type(error).__name__}"
                        ) from error
                else:
                    directory_fd = os.dup(fresh_root_fd)
                try:
                    try:
                        actual_binding = _binding(os.fstat(directory_fd))
                    except OSError as error:
                        raise CoveragePartial(
                            "rollout-directory-revalidation-unreadable:"
                            f"{type(error).__name__}"
                        ) from error
                    if actual_binding != snapshot.binding:
                        raise CoveragePartial(
                            "rollout-directory-identity-or-access-policy-changed"
                        )

                    entries: list[InventoryEntry] = []
                    try:
                        with os.scandir(directory_fd) as iterator:
                            for entry in iterator:
                                revalidated_entries += 1
                                if revalidated_entries > MAX_ROLLOUT_INVENTORY_ENTRIES:
                                    raise CoveragePartial(
                                        "rollout-inventory-cap-exceeded"
                                    )
                                metadata = os.stat(
                                    entry.name,
                                    dir_fd=directory_fd,
                                    follow_symlinks=False,
                                )
                                entries.append(_inventory_entry(entry.name, metadata))
                    except CoveragePartial:
                        raise
                    except OSError as error:
                        raise CoveragePartial(
                            "rollout-inventory-revalidation-failed:"
                            f"{type(error).__name__}"
                        ) from error
                    if tuple(sorted(entries)) != snapshot.entries:
                        raise CoveragePartial("rollout-entry-inventory-changed")
                finally:
                    os.close(directory_fd)
        finally:
            os.close(fresh_root_fd)
    finally:
        fresh_home.close()


def _scan_rollout_root(
    codex_home: Path,
    root_name: str,
    *,
    session_id: str,
    limit: int,
) -> dict[str, Any]:
    codex_home = _lexical_absolute(codex_home)
    root_path = codex_home / root_name
    source = _empty_source("rollout-root", root_path)
    source["directories_scanned"] = 0
    source["entries_scanned"] = 0
    source["inventory_entry_limit"] = MAX_ROLLOUT_INVENTORY_ENTRIES

    try:
        home_chain = _open_absolute_directory_chain(codex_home)
    except FileNotFoundError:
        source["status"] = "unavailable"
        source["reason"] = "missing-parent"
        return source
    except CoveragePartial as error:
        _mark_partial(source, error.reason)
        return source
    except OSError as error:
        _mark_partial(source, f"parent-open-failed:{type(error).__name__}")
        return source

    with home_chain:
        try:
            root_fd, root_binding = _open_directory_at(
                home_chain.descriptor,
                root_name,
            )
        except FileNotFoundError:
            source["status"] = "unavailable"
            source["reason"] = "missing"
            return source
        except CoveragePartial as error:
            _mark_partial(source, error.reason)
            return source
        except OSError as error:
            _mark_partial(source, f"root-open-failed:{type(error).__name__}")
            return source

        expected_directories: dict[tuple[str, ...], ObjectBinding] = {(): root_binding}
        snapshots: dict[tuple[str, ...], DirectorySnapshot] = {}
        pending: list[tuple[str, ...]] = [()]
        inventory_entries = 0
        inventory_complete = True
        try:
            while pending:
                relative_parts = heapq.heappop(pending)
                display_path = root_path.joinpath(*relative_parts)
                if relative_parts:
                    try:
                        directory_fd = _open_relative_directory(
                            root_fd,
                            relative_parts,
                            expected_directories,
                        )
                    except CoveragePartial as error:
                        _record_error(
                            source,
                            path=display_path,
                            reason=error.reason,
                            limit=limit,
                        )
                        inventory_complete = False
                        continue
                    except OSError as error:
                        _record_error(
                            source,
                            path=display_path,
                            reason=f"directory-open-failed:{type(error).__name__}",
                            limit=limit,
                        )
                        inventory_complete = False
                        continue
                else:
                    directory_fd = os.dup(root_fd)
                try:
                    source["directories_scanned"] += 1
                    remaining_budget = MAX_ROLLOUT_INVENTORY_ENTRIES - inventory_entries
                    entries, complete = _capture_directory_inventory(
                        directory_fd,
                        display_path=display_path,
                        source=source,
                        limit=limit,
                        remaining_budget=remaining_budget,
                    )
                    inventory_entries = source["entries_scanned"]
                    if not complete:
                        inventory_complete = False
                        if source["entries_scanned"] > MAX_ROLLOUT_INVENTORY_ENTRIES:
                            _mark_partial(
                                source,
                                "rollout-inventory-cap-exceeded",
                            )
                            break
                    directory_binding = _binding(os.fstat(directory_fd))
                    snapshots[relative_parts] = DirectorySnapshot(
                        binding=directory_binding,
                        entries=entries,
                    )

                    for entry in entries:
                        entry_path = display_path / entry.name
                        entry_binding = ObjectBinding(
                            device=entry.device,
                            inode=entry.inode,
                            file_type=entry.file_type,
                            owner=-1,
                            group=-1,
                            permissions=-1,
                        )
                        if entry.file_type == stat.S_IFLNK:
                            _record_error(
                                source,
                                path=entry_path,
                                reason="symlink-entry-not-followed",
                                limit=limit,
                            )
                            inventory_complete = False
                            continue
                        if entry.file_type == stat.S_IFDIR:
                            try:
                                child_fd, child_binding = _open_directory_at(
                                    directory_fd,
                                    entry.name,
                                )
                            except CoveragePartial as error:
                                _record_error(
                                    source,
                                    path=entry_path,
                                    reason=error.reason,
                                    limit=limit,
                                )
                                inventory_complete = False
                                continue
                            except OSError as error:
                                _record_error(
                                    source,
                                    path=entry_path,
                                    reason=(
                                        f"directory-open-failed:{type(error).__name__}"
                                    ),
                                    limit=limit,
                                )
                                inventory_complete = False
                                continue
                            try:
                                if (
                                    child_binding.device,
                                    child_binding.inode,
                                    child_binding.file_type,
                                ) != (
                                    entry_binding.device,
                                    entry_binding.inode,
                                    entry_binding.file_type,
                                ):
                                    _record_error(
                                        source,
                                        path=entry_path,
                                        reason="directory-replaced-during-inventory",
                                        limit=limit,
                                    )
                                    inventory_complete = False
                                    continue
                            finally:
                                os.close(child_fd)
                            child_parts = (*relative_parts, entry.name)
                            expected_directories[child_parts] = child_binding
                            heapq.heappush(pending, child_parts)
                            continue
                        if not _rollout_name_matches(entry.name, session_id):
                            continue
                        if entry.file_type != stat.S_IFREG:
                            _record_error(
                                source,
                                path=entry_path,
                                reason="matching-entry-not-regular",
                                limit=limit,
                            )
                            inventory_complete = False
                            continue
                        source["match_count"] += 1
                        if len(source["matches"]) < limit:
                            source["matches"].append(
                                {"path": _bounded_path(entry_path)}
                            )
                except OSError as error:
                    _record_error(
                        source,
                        path=display_path,
                        reason=f"inventory-failed:{type(error).__name__}",
                        limit=limit,
                    )
                    inventory_complete = False
                finally:
                    os.close(directory_fd)

            if inventory_complete:
                try:
                    _revalidate_rollout_tree(
                        home_chain,
                        root_name,
                        root_fd,
                        expected_directories,
                        snapshots,
                    )
                except CoveragePartial as error:
                    _mark_partial(source, error.reason)
                except OSError as error:
                    _mark_partial(
                        source,
                        f"inventory-revalidation-failed:{type(error).__name__}",
                    )
            else:
                _mark_partial(source, "rollout-inventory-incomplete")
        finally:
            os.close(root_fd)

    source["matches_truncated"] = source["match_count"] > len(source["matches"])
    source["errors_truncated"] = source["error_count"] > len(source["errors"])
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
    codex_home = _lexical_absolute(args.codex_home)
    sources = [
        _scan_index(
            codex_home,
            "session_index.jsonl",
            session_id=args.session_id,
            thread_query=args.thread_query,
            limit=args.limit,
        ),
        _scan_index(
            codex_home,
            "history.jsonl",
            session_id=args.session_id,
            thread_query=args.thread_query,
            limit=args.limit,
        ),
    ]
    if args.session_id is not None:
        sources.extend(
            _scan_rollout_root(
                codex_home,
                root_name,
                session_id=args.session_id,
                limit=args.limit,
            )
            for root_name in ("sessions", "archived_sessions")
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
        "retained_error_limit_per_source": args.limit,
        "retained_match_limit_per_source": args.limit,
        "schema_version": 2,
        "selector": selector,
        "sources": sources,
        "status": status,
        "total_errors": sum(source["error_count"] for source in sources),
        "total_matches": sum(source["match_count"] for source in sources),
    }
    print(json.dumps(document, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
