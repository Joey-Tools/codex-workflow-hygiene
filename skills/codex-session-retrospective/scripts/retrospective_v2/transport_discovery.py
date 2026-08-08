"""Bounded directory snapshots for source candidate discovery."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import os
import pathlib
from typing import NoReturn


DirectoryIdentity = tuple[int, int]
DirectoryEntry = tuple[str, bool, bool, bool]


@dataclass(frozen=True, slots=True)
class SourceDirectorySnapshot:
    relative: str
    identities: tuple[DirectoryIdentity, ...]
    entries: tuple[DirectoryEntry, ...]


def read_directory_entries(
    descriptor: int,
    *,
    observe_entry: Callable[[], None] | None = None,
) -> tuple[DirectoryEntry, ...]:
    rows: list[DirectoryEntry] = []
    with os.scandir(os.dup(descriptor)) as entries:
        for entry in entries:
            if observe_entry is not None:
                observe_entry()
            rows.append(
                (
                    entry.name,
                    entry.is_symlink(),
                    entry.is_dir(follow_symlinks=False),
                    entry.is_file(follow_symlinks=False),
                )
            )
    rows.sort(key=lambda item: os.fsencode(item[0]))
    return tuple(rows)


def walk_active_rollout_tree(
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
    component_width = (4, 2, 2)[depth]
    for name, is_symlink, is_directory, _is_file in read_entries(
        descriptor,
        prefix,
        identities,
    ):
        if len(name) != component_width or not name.isascii() or not name.isdigit():
            continue
        if is_symlink or not is_directory:
            reject_entry()
        relative = f"{prefix}/{name}"
        child_fd, child_identities = open_directory(relative)
        try:
            if depth < 2:
                walk_active_rollout_tree(
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
                continue
            for child_name, child_symlink, _child_directory, child_file in read_entries(
                child_fd, relative, child_identities
            ):
                candidate_relative = f"{relative}/{child_name}"
                if not candidate_matches(candidate_relative):
                    continue
                if child_symlink or not child_file:
                    reject_entry()
                add_candidate(candidate_relative)
        finally:
            os.close(child_fd)


def revalidate_directory_snapshots(
    snapshots: Sequence[SourceDirectorySnapshot],
    *,
    entry_limit: int,
    open_directory: Callable[[str, Sequence[DirectoryIdentity]], int],
) -> None:
    if not snapshots:
        return
    if entry_limit < 1:
        raise ValueError("source discovery lost its directory snapshot authority")
    entries_seen = 0

    def observe_entry() -> None:
        nonlocal entries_seen
        entries_seen += 1
        if entries_seen > entry_limit:
            raise ValueError("source directory revalidation exceeded its entry bound")

    for snapshot in snapshots:
        descriptor = open_directory(snapshot.relative, snapshot.identities)
        try:
            if (
                read_directory_entries(descriptor, observe_entry=observe_entry)
                != snapshot.entries
            ):
                raise ValueError("source directory entries changed after discovery")
        finally:
            os.close(descriptor)


def revalidate_rooted_directory_snapshots(
    snapshots: Sequence[SourceDirectorySnapshot],
    *,
    entry_limit: int,
    root_authority: object | None,
    open_relative: Callable[..., tuple[int, object]],
) -> None:
    if root_authority is None:
        raise ValueError("source discovery lost its root authority")

    def open_directory(relative: str, identities: Sequence[DirectoryIdentity]) -> int:
        return open_relative(
            root_authority,
            None if relative == "" else pathlib.PurePosixPath(relative),
            expect_directory=True,
            expected_identities=identities,
        )[0]

    revalidate_directory_snapshots(
        snapshots,
        entry_limit=entry_limit,
        open_directory=open_directory,
    )
