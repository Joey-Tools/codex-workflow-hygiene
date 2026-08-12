"""Closed path grammar shared by source and session-shard transport."""

from __future__ import annotations

import os
import pathlib
import re
import stat

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
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode")
    if not stat.S_ISDIR(metadata.st_mode):
        fields += ("st_nlink",)
    return tuple(int(getattr(metadata, field)) for field in fields)


def _require_program_component_policy(metadata: os.stat_result, role: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise TransportValidationError(
            f"source transport {role} must be a regular non-symlink file"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if not all((metadata.st_uid in {0, os.geteuid()}, not mode & 0o022)):
        raise TransportValidationError(
            f"source transport {role} has an unsafe access policy"
        )
    if metadata.st_nlink != 1:
        raise TransportValidationError(
            f"source transport {role} must have exactly one link"
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
