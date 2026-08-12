"""Bounded source-object probes and canonical continuation positions."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import os
from typing import Mapping

try:
    from .contracts import JsonValue, canonical_json_bytes, strict_json_loads
    from .transport_contracts import (
        SOURCE_TRANSPORT_BOUNDARY_PROBE_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
        SOURCE_TRANSPORT_SCAN_CHUNK_BYTES,
        TransportValidationError,
        _canonical_commitment,
        _normalize_source_resume_position,
    )
except (ImportError, ModuleNotFoundError):
    from contracts import (  # type: ignore[no-redef]
        JsonValue,
        canonical_json_bytes,
        strict_json_loads,
    )
    from transport_contracts import (  # type: ignore[no-redef]
        SOURCE_TRANSPORT_BOUNDARY_PROBE_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
        SOURCE_TRANSPORT_SCAN_CHUNK_BYTES,
        TransportValidationError,
        _canonical_commitment,
        _normalize_source_resume_position,
    )


_SOURCE_ACCESS_POLICY_FLAG_MASK = 0x001E0096  # BSD write/delete restriction flags.


def _source_object_generation(metadata: os.stat_result) -> tuple[int, int]:
    birthtime_ns = getattr(metadata, "st_birthtime_ns", None)
    if birthtime_ns is None:
        birthtime = getattr(metadata, "st_birthtime", None)
        birthtime_ns = (
            -1 if birthtime is None else int(round(float(birthtime) * 1_000_000_000))
        )
    return int(getattr(metadata, "st_gen", -1)), int(birthtime_ns)


def _source_transport_candidate_token(metadata: os.stat_result) -> str:
    generation, birthtime_ns = _source_object_generation(metadata)
    return _canonical_commitment(
        {
            "birthtime_ns": birthtime_ns,
            "device": metadata.st_dev,
            "generation": generation,
            "gid": metadata.st_gid,
            "inode": metadata.st_ino,
            "mode": metadata.st_mode,
            "schema": "source_transport_candidate_v4",
            "uid": metadata.st_uid,
        }
    )


def _source_transport_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink")
    return tuple(int(getattr(metadata, field)) for field in fields) + (
        int(getattr(metadata, "st_flags", 0)) & _SOURCE_ACCESS_POLICY_FLAG_MASK,
        int(getattr(metadata, "st_gen", -1)),
    )


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


class _SourceTransportResumeProbeBudgetExhausted(ValueError):
    pass


@dataclass(slots=True)
class _SourceTransportResumeProbeBudget:
    limit: int
    used: int = 0

    def read(self, descriptor: int, *, start: int, end: int) -> bytes:
        if start < 0 or end < start:
            raise ValueError("source transport resume probe range is invalid")
        requested = end - start
        if requested > SOURCE_TRANSPORT_RESUME_PROBE_BYTES:
            raise ValueError("source transport resume probe exceeds 64 KiB")
        if self.used + requested > self.limit:
            raise _SourceTransportResumeProbeBudgetExhausted(
                "source transport resume probe budget is exhausted"
            )
        self.used += requested
        retained = bytearray()
        scanned = start
        while scanned < end:
            chunk = os.pread(
                descriptor,
                min(SOURCE_TRANSPORT_SCAN_CHUNK_BYTES, end - scanned),
                scanned,
            )
            if not chunk:
                raise ValueError("source transport resume probe is truncated")
            retained.extend(chunk)
            scanned += len(chunk)
        return bytes(retained)


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
