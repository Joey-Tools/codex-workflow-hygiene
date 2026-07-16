"""Closed path grammar shared by source and session-shard transport."""

from __future__ import annotations

import os
import pathlib
import re

try:
    from .transport_contracts import TransportValidationError
except (ImportError, ModuleNotFoundError):
    from transport_contracts import TransportValidationError  # type: ignore[no-redef]

ACTIVE_ROLLOUT_RELATIVE_RE = re.compile(
    r"^sessions/\d{4}/\d{2}/\d{2}/rollout-(?!summary)[^/]+\.jsonl$"
)

ARCHIVED_ROLLOUT_RELATIVE_RE = re.compile(
    r"^archived_sessions/(?:\d{4}/\d{2}/\d{2}/)?rollout-(?!summary)[^/]+\.jsonl$"
)

ROOT_ROLLOUT_RELATIVE_RE = re.compile(r"^rollout-(?!summary)[^/]+\.jsonl$")


def _program_stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _program_named_identity(
    parent_fd: int, name: str, *, role: str, phase: str
) -> tuple[int, ...]:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise TransportValidationError(
            f"source transport {role} changed while {phase}"
        ) from exc
    return _program_stat_identity(metadata)


def _read_program_component(descriptor: int, maximum: int, role: str) -> bytes:
    retained = bytearray()
    while len(retained) <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(retained)))
        if not chunk:
            return bytes(retained)
        retained.extend(chunk)
    raise TransportValidationError(
        f"source transport {role} exceeds the program component bound"
    )


def _resolve_rollout_relative_path(value: str) -> pathlib.PurePosixPath:
    candidate = pathlib.PurePosixPath(value)
    normalized = candidate.as_posix()
    if not (
        ACTIVE_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ARCHIVED_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ROOT_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
    ):
        raise ValueError("rollout path is outside the closed rollout path schema")
    return candidate
