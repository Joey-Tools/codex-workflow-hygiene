"""Bounded directory snapshots for source candidate discovery."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
import datetime as dt
import os
import pathlib
import stat
import time
from typing import NoReturn

try:
    from .transport_contracts import (
        SOURCE_DISCOVERY_MAX_DIRECTORY_ENTRIES,
        SOURCE_DISCOVERY_MAX_PATH_BYTES,
        SOURCE_DISCOVERY_TIMEOUT_SECONDS,
    )
except (ImportError, ModuleNotFoundError):
    from transport_contracts import (  # type: ignore[no-redef]
        SOURCE_DISCOVERY_MAX_DIRECTORY_ENTRIES,
        SOURCE_DISCOVERY_MAX_PATH_BYTES,
        SOURCE_DISCOVERY_TIMEOUT_SECONDS,
    )


DirectoryIdentity = tuple[int, int]
DirectoryEntry = tuple[str, bool, bool, bool]


def window_dates(start: dt.datetime, end: dt.datetime) -> tuple[dt.date, ...]:
    if start >= end:
        raise ValueError("source transport window is empty")
    count = ((end - dt.timedelta(microseconds=1)).date() - start.date()).days + 1
    if count < 1 or count > 366:
        raise ValueError("source transport window exceeds the discovery bound")
    return tuple(start.date() + dt.timedelta(days=index) for index in range(count))


@dataclass(frozen=True, slots=True)
class SourceDirectorySnapshot:
    relative: str
    identities: tuple[DirectoryIdentity, ...]
    entries: tuple[DirectoryEntry, ...]


def _ignore_directory_entry(_name: str) -> None:
    pass


def read_directory_entries(
    descriptor: int,
    *,
    observe_entry: Callable[[str], None] = _ignore_directory_entry,
) -> tuple[DirectoryEntry, ...]:
    rows: list[DirectoryEntry] = []
    scan_descriptor = os.dup(descriptor)
    try:
        with os.scandir(scan_descriptor) as entries:
            for entry in entries:
                observe_entry(entry.name)
                metadata = entry.stat(follow_symlinks=False)
                rows.append(
                    (
                        entry.name,
                        stat.S_ISLNK(metadata.st_mode),
                        stat.S_ISDIR(metadata.st_mode),
                        stat.S_ISREG(metadata.st_mode),
                    )
                )
    finally:
        os.close(scan_descriptor)
    rows.sort(key=lambda item: os.fsencode(item[0]))
    return tuple(rows)


def walk_dated_rollout_tree(
    descriptor: int,
    identities: tuple[DirectoryIdentity, ...],
    prefix: str,
    *,
    read_entries: Callable[
        [int, str, tuple[DirectoryIdentity, ...]], Sequence[DirectoryEntry]
    ],
    open_directory: Callable[[str], tuple[int, tuple[DirectoryIdentity, ...]]],
    add_candidate: Callable[[str], None],
    candidate_matches: Callable[[str], bool],
    reject_entry: Callable[[], NoReturn],
    depth: int = 0,
) -> None:
    component_width = (4, 2, 2)[depth] if depth < 3 else 0
    for entry in read_entries(
        descriptor,
        prefix,
        identities,
    ):
        name, is_symlink, is_directory, is_file = entry[:4]
        relative = f"{prefix}/{name}"
        if candidate_matches(relative):
            if is_symlink or not is_file:
                reject_entry()
            add_candidate(relative)
            continue
        if depth >= 3:
            continue
        if len(name) != component_width or not name.isascii() or not name.isdigit():
            continue
        if is_symlink or not is_directory:
            reject_entry()
        child_fd, child_identities = open_directory(relative)
        try:
            walk_dated_rollout_tree(
                child_fd,
                child_identities,
                relative,
                read_entries=read_entries,
                open_directory=open_directory,
                add_candidate=add_candidate,
                candidate_matches=candidate_matches,
                reject_entry=reject_entry,
                depth=depth + 1,
            )
        finally:
            os.close(child_fd)


class SourceDiscoveryBudgetExceeded(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(slots=True)
class SourceDiscoveryBudget:
    entry_limit: int = SOURCE_DISCOVERY_MAX_DIRECTORY_ENTRIES
    path_byte_limit: int = SOURCE_DISCOVERY_MAX_PATH_BYTES
    timeout_seconds: float = SOURCE_DISCOVERY_TIMEOUT_SECONDS
    clock: Callable[[], float] = time.monotonic
    entries_seen: int = 0
    path_bytes_seen: int = 0
    deadline: float = field(init=False)

    def __post_init__(self) -> None:
        if self.entry_limit < 1 or self.path_byte_limit < 1:
            raise ValueError("source discovery limits must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("source discovery timeout must be positive")
        self.deadline = self.clock() + self.timeout_seconds

    def checkpoint(self) -> None:
        if self.clock() >= self.deadline:
            raise SourceDiscoveryBudgetExceeded("source_discovery_deadline_reached")

    def observe(self, relative: str, name: str) -> None:
        self.checkpoint()
        path_bytes = len(os.fsencode(name))
        if relative:
            path_bytes += len(os.fsencode(relative)) + 1
        if self.entries_seen + 1 > self.entry_limit:
            raise SourceDiscoveryBudgetExceeded("source_discovery_entry_limit_reached")
        if self.path_bytes_seen + path_bytes > self.path_byte_limit:
            raise SourceDiscoveryBudgetExceeded("source_discovery_path_limit_reached")
        self.entries_seen += 1
        self.path_bytes_seen += path_bytes
        self.checkpoint()


def revalidate_directory_snapshots(
    snapshots: Sequence[SourceDirectorySnapshot],
    *,
    budget: SourceDiscoveryBudget,
    open_directory: Callable[[str, Sequence[DirectoryIdentity]], int],
) -> None:
    for snapshot in snapshots:
        budget.checkpoint()
        descriptor = open_directory(snapshot.relative, snapshot.identities)
        try:
            current = read_directory_entries(
                descriptor,
                observe_entry=lambda name, relative=snapshot.relative: (
                    budget.observe(relative, name)
                ),
            )
            budget.checkpoint()
            if current != snapshot.entries:
                raise ValueError("source directory entries changed after discovery")
        finally:
            os.close(descriptor)


def terminal_revalidate_source_discovery(
    *,
    snapshots: Sequence[SourceDirectorySnapshot],
    root_authority: object,
    open_relative: Callable[..., tuple[int, object]],
    candidate_identities: Sequence[tuple[str, Sequence[DirectoryIdentity]]],
    candidate_tokens: Sequence[tuple[str, str]],
    open_candidate: Callable[[str, Sequence[DirectoryIdentity]], int],
    candidate_token: Callable[[os.stat_result], str],
) -> None:
    active_budget = SourceDiscoveryBudget()

    def open_directory(relative: str, identities: Sequence[DirectoryIdentity]) -> int:
        return open_relative(
            root_authority,
            None if relative == "" else pathlib.PurePosixPath(relative),
            expect_directory=True,
            expected_identities=identities,
        )[0]

    revalidate_directory_snapshots(
        snapshots,
        budget=active_budget,
        open_directory=open_directory,
    )
    expected_tokens = dict(candidate_tokens)
    for relative, identities in candidate_identities:
        active_budget.checkpoint()
        descriptor = open_candidate(relative, identities)
        try:
            if expected_tokens.get(relative) != candidate_token(os.fstat(descriptor)):
                raise ValueError(
                    "source candidate identity or access policy changed after discovery"
                )
        finally:
            os.close(descriptor)
    active_budget.checkpoint()


def classify_terminal_source_discovery(operation: Callable[[], None]) -> str | None:
    try:
        operation()
    except SourceDiscoveryBudgetExceeded as exc:
        return exc.reason
    except (FileNotFoundError, NotADirectoryError, ValueError):
        return "source_enumeration_changed"
    except OSError:
        return "source_enumeration_revalidation_failed"
    return None
