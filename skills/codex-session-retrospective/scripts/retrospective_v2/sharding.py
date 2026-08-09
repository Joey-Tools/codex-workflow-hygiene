from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import hmac
import os
from pathlib import Path
import re
from typing import Iterable, Sequence

try:
    from .catalog import (
        AccountingClass,
        CatalogRecord,
        ExplicitGap,
        StableSourceCoordinate,
        canonical_json_bytes,
        catalog_record_sort_key,
        content_commitment,
    )
except (
    ImportError,
    ModuleNotFoundError,
):  # Supports direct early-stage module loading.
    from catalog import (  # type: ignore[no-redef]
        AccountingClass,
        CatalogRecord,
        ExplicitGap,
        StableSourceCoordinate,
        canonical_json_bytes,
        catalog_record_sort_key,
        content_commitment,
    )

try:
    from .contracts import JobKind as _CommonJobKind
except (ImportError, ModuleNotFoundError):
    _CommonJobKind = None

try:
    from .contracts import MAX_RUN_RAW_SHARDS
except (ImportError, ModuleNotFoundError):
    from contracts import MAX_RUN_RAW_SHARDS  # type: ignore[no-redef]

try:
    from . import safe_io as _safe_io
except (ImportError, ModuleNotFoundError):
    _safe_io = None


RAW_SHARD_SCHEMA_VERSION = 1
SHARD_SET_SCHEMA_VERSION = 1
JOB_MANIFEST_SCHEMA_VERSION = 1
DEFAULT_MAX_SHARD_TURNS = 20
DEFAULT_MAX_SHARD_BYTES = 512 * 1024
DEFAULT_RECORD_PROCESSING_BUDGET = 64 * 1024 * 1024
HARD_RECORD_PROCESSING_CEILING = 256 * 1024 * 1024
RAW_SHARDS_MANIFEST_FILE = "raw-shards.json"
_MAX_FRAGMENT_ORDINAL = 999_999_999
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_JOB_REF_RE = re.compile(r"^job_ref_v2:[0-9a-f]{64}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


class ShardingValidationError(ValueError):
    """Raised when raw data cannot satisfy the deterministic shard contract."""


class _FallbackJobKind(str, Enum):
    EXTRACTOR_REDACTOR = "extractor_redactor"
    EVIDENCE_VERIFIER = "evidence_verifier"
    BOUNDARY_VERIFIER = "boundary_verifier"
    RECORD_REDUCER = "record_reducer"


JobKind = _CommonJobKind or _FallbackJobKind


def _bounded_text(value: object, label: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ShardingValidationError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ShardingValidationError(f"{label} must not contain control characters")
    return value


def _code(value: object, label: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        raise ShardingValidationError(f"{label} must be a lower_snake_case code")
    return value


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ShardLimits:
    max_turns: int = DEFAULT_MAX_SHARD_TURNS
    max_bytes: int = DEFAULT_MAX_SHARD_BYTES
    record_processing_budget: int = DEFAULT_RECORD_PROCESSING_BUDGET

    def __post_init__(self) -> None:
        for name, value in (
            ("max_turns", self.max_turns),
            ("max_bytes", self.max_bytes),
            ("record_processing_budget", self.record_processing_budget),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ShardingValidationError(f"{name} must be a positive integer")
        if self.max_turns > DEFAULT_MAX_SHARD_TURNS:
            raise ShardingValidationError(
                f"max_turns cannot exceed {DEFAULT_MAX_SHARD_TURNS}"
            )
        if self.max_bytes > DEFAULT_MAX_SHARD_BYTES:
            raise ShardingValidationError(
                f"max_bytes cannot exceed {DEFAULT_MAX_SHARD_BYTES}"
            )
        if self.record_processing_budget > HARD_RECORD_PROCESSING_CEILING:
            raise ShardingValidationError(
                f"record_processing_budget cannot exceed {HARD_RECORD_PROCESSING_CEILING}"
            )


@dataclass(frozen=True)
class RawEvidenceRecord:
    catalog_record: CatalogRecord
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.catalog_record, CatalogRecord):
            raise ShardingValidationError("catalog_record must be a CatalogRecord")
        if (
            self.catalog_record.accounting_class
            is not AccountingClass.CONSUMED_CANDIDATE
        ):
            raise ShardingValidationError(
                "raw records may be created only for consumed_candidate units"
            )
        if not isinstance(self.payload, bytes):
            raise ShardingValidationError("raw record payload must be bytes")
        if len(self.payload) != self.catalog_record.byte_count:
            raise ShardingValidationError(
                "raw record payload length does not match its exact source range"
            )
        if content_commitment(self.payload) != self.catalog_record.content_commitment:
            raise ShardingValidationError(
                "raw record payload does not match its catalog commitment"
            )

    @property
    def unit_ref(self) -> str:
        return self.catalog_record.unit_ref


RawRecord = RawEvidenceRecord


@dataclass(frozen=True)
class RawRangeDescriptor:
    unit_ref: str
    source_kind: str
    coordinate: StableSourceCoordinate
    range_start: int
    range_end: int
    fragment_index: int
    fragment_count: int
    payload_offset: int
    payload_length: int
    fragment_commitment: str
    record_commitment: str
    event_time: str | None
    turn_count: int

    def __post_init__(self) -> None:
        _bounded_text(self.unit_ref, "range.unit_ref")
        _bounded_text(self.source_kind, "range.source_kind")
        if not isinstance(self.coordinate, StableSourceCoordinate):
            raise ShardingValidationError(
                "range.coordinate must be a StableSourceCoordinate"
            )
        if (
            self.range_start < self.coordinate.byte_start
            or self.range_end > self.coordinate.byte_end
        ):
            raise ShardingValidationError(
                "range must stay inside its catalog source coordinate"
            )
        if self.range_end < self.range_start:
            raise ShardingValidationError("range_end must be at least range_start")
        if (
            self.fragment_index < 0
            or self.fragment_count < 1
            or self.fragment_index >= self.fragment_count
        ):
            raise ShardingValidationError("fragment index/count are inconsistent")
        if (
            self.payload_offset < 0
            or self.payload_length != self.range_end - self.range_start
        ):
            raise ShardingValidationError(
                "payload offsets must match the exact source range"
            )
        if _SHA256_RE.fullmatch(self.fragment_commitment) is None:
            raise ShardingValidationError(
                "fragment_commitment must be sha256:<64 lowercase hex>"
            )
        if _SHA256_RE.fullmatch(self.record_commitment) is None:
            raise ShardingValidationError(
                "record_commitment must be sha256:<64 lowercase hex>"
            )
        if self.turn_count < 1:
            raise ShardingValidationError("range.turn_count must be positive")

    @property
    def byte_count(self) -> int:
        return self.range_end - self.range_start

    def to_dict(self) -> dict[str, object]:
        return {
            "unit_ref": self.unit_ref,
            "source_kind": self.source_kind,
            "coordinate": self.coordinate.to_dict(),
            "range": {"start": self.range_start, "end": self.range_end},
            "fragment_index": self.fragment_index,
            "fragment_count": self.fragment_count,
            "payload_offset": self.payload_offset,
            "payload_length": self.payload_length,
            "fragment_commitment": self.fragment_commitment,
            "record_commitment": self.record_commitment,
            "event_time": self.event_time,
            "turn_count": self.turn_count,
        }


@dataclass(frozen=True)
class RawGapDescriptor:
    unit_ref: str
    coordinate: StableSourceCoordinate
    content_commitment: str
    reason: str
    stage: str = "sharding"
    repairable: bool = True

    def __post_init__(self) -> None:
        _bounded_text(self.unit_ref, "raw_gap.unit_ref")
        if not isinstance(self.coordinate, StableSourceCoordinate):
            raise ShardingValidationError(
                "raw_gap.coordinate must be a StableSourceCoordinate"
            )
        if _SHA256_RE.fullmatch(self.content_commitment) is None:
            raise ShardingValidationError(
                "raw_gap.content_commitment must be sha256:<64 lowercase hex>"
            )
        _code(self.reason, "raw_gap.reason")
        _code(self.stage, "raw_gap.stage")
        if not isinstance(self.repairable, bool):
            raise ShardingValidationError("raw_gap.repairable must be a boolean")

    @property
    def byte_count(self) -> int:
        return self.coordinate.byte_count

    def to_dict(self) -> dict[str, object]:
        return {
            "unit_ref": self.unit_ref,
            "coordinate": self.coordinate.to_dict(),
            "content_commitment": self.content_commitment,
            "byte_count": self.byte_count,
            "gap": {
                "reason": self.reason,
                "stage": self.stage,
                "repairable": self.repairable,
            },
        }

    def as_catalog_gap(self, record: CatalogRecord) -> CatalogRecord:
        if record.unit_ref != self.unit_ref or record.coordinate != self.coordinate:
            raise ShardingValidationError(
                "raw gap does not belong to the supplied catalog record"
            )
        return replace(
            record,
            accounting_class=AccountingClass.EXPLICIT_GAP,
            exclusion_reason=None,
            duplicate_of=None,
            gap=ExplicitGap(
                reason=self.reason, stage=self.stage, repairable=self.repairable
            ),
        )


@dataclass(frozen=True)
class ShardManifest:
    ordinal: int
    shard_ref: str
    file_name: str
    content_sha256: str
    byte_count: int
    raw_byte_count: int
    turn_count: int
    ranges: tuple[RawRangeDescriptor, ...]
    schema_version: int = RAW_SHARD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RAW_SHARD_SCHEMA_VERSION:
            raise ShardingValidationError(
                f"shard schema_version must be {RAW_SHARD_SCHEMA_VERSION}"
            )
        if self.ordinal < 0:
            raise ShardingValidationError("shard ordinal must be non-negative")
        if (
            not self.shard_ref.startswith("raw_shard_sha256:")
            or len(self.shard_ref) != 81
        ):
            raise ShardingValidationError(
                "shard_ref must be raw_shard_sha256:<64 lowercase hex>"
            )
        digest = self.shard_ref.removeprefix("raw_shard_sha256:")
        if (
            digest != self.content_sha256
            or _SHA256_RE.fullmatch(f"sha256:{digest}") is None
        ):
            raise ShardingValidationError(
                "shard_ref and content_sha256 must contain the same SHA-256"
            )
        expected_name = f"raw-shard-{self.ordinal:05d}-{digest[:16]}.bin"
        if self.file_name != expected_name:
            raise ShardingValidationError("shard file_name is not deterministic")
        if (
            self.byte_count < 1
            or self.raw_byte_count < 0
            or self.raw_byte_count > self.byte_count
        ):
            raise ShardingValidationError("shard byte counts are inconsistent")
        if self.byte_count > DEFAULT_MAX_SHARD_BYTES:
            raise ShardingValidationError(
                "shard exceeds the compiled 512 KiB byte limit"
            )
        if self.turn_count < 1 or self.turn_count > DEFAULT_MAX_SHARD_TURNS:
            raise ShardingValidationError("shard turn_count must be between 1 and 20")
        ranges = tuple(self.ranges)
        if not ranges:
            raise ShardingValidationError("a shard must contain at least one range")
        object.__setattr__(self, "ranges", ranges)
        expected_raw_bytes = sum(item.byte_count for item in ranges)
        if expected_raw_bytes != self.raw_byte_count:
            raise ShardingValidationError(
                "shard raw_byte_count does not match its ranges"
            )
        expected_turns = sum(
            ranges[index].turn_count
            for index in range(len(ranges))
            if index == 0
            or ranges[index].unit_ref not in {item.unit_ref for item in ranges[:index]}
        )
        if expected_turns != self.turn_count:
            raise ShardingValidationError(
                "shard turn_count does not match its unique units"
            )
        expected_offset = 0
        for item in ranges:
            if item.payload_offset != expected_offset:
                raise ShardingValidationError(
                    "shard payload ranges must be contiguous and ordered"
                )
            expected_offset += item.payload_length

    @property
    def shard_id(self) -> str:
        return self.shard_ref

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "ordinal": self.ordinal,
            "shard_ref": self.shard_ref,
            "file_name": self.file_name,
            "content_sha256": self.content_sha256,
            "byte_count": self.byte_count,
            "raw_byte_count": self.raw_byte_count,
            "turn_count": self.turn_count,
            "range_count": len(self.ranges),
            "ranges": [item.to_dict() for item in self.ranges],
        }


@dataclass(frozen=True)
class RawShardArtifact:
    manifest: ShardManifest
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise ShardingValidationError("raw shard data must be bytes")
        if len(self.data) != self.manifest.byte_count:
            raise ShardingValidationError(
                "raw shard data length does not match manifest"
            )
        if _sha256_hex(self.data) != self.manifest.content_sha256:
            raise ShardingValidationError(
                "raw shard data does not match manifest content hash"
            )


@dataclass(frozen=True)
class MaterializationResult:
    shards: tuple[RawShardArtifact, ...]
    gaps: tuple[RawGapDescriptor, ...]
    source_record_count: int
    source_byte_count: int
    schema_version: int = SHARD_SET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SHARD_SET_SCHEMA_VERSION:
            raise ShardingValidationError(
                f"shard set schema_version must be {SHARD_SET_SCHEMA_VERSION}"
            )
        if self.source_record_count < 0 or self.source_byte_count < 0:
            raise ShardingValidationError("source totals must be non-negative")
        shards = tuple(self.shards)
        gaps = tuple(self.gaps)
        object.__setattr__(self, "shards", shards)
        object.__setattr__(self, "gaps", gaps)
        if [item.manifest.ordinal for item in shards] != list(range(len(shards))):
            raise ShardingValidationError("shard ordinals must be contiguous from zero")
        if len({item.unit_ref for item in gaps}) != len(gaps):
            raise ShardingValidationError(
                "a source unit cannot have multiple whole-record gaps"
            )
        shard_units = {
            descriptor.unit_ref
            for shard in shards
            for descriptor in shard.manifest.ranges
        }
        gap_units = {item.unit_ref for item in gaps}
        if shard_units & gap_units:
            raise ShardingValidationError(
                "a source unit cannot be both materialized and gapped"
            )
        if len(shard_units | gap_units) != self.source_record_count:
            raise ShardingValidationError(
                "source_record_count does not match materialized and gapped units"
            )
        if self.materialized_raw_bytes + self.gap_bytes != self.source_byte_count:
            raise ShardingValidationError(
                "shard set byte totals do not conserve the source corpus"
            )

    @property
    def materialized_raw_bytes(self) -> int:
        return sum(item.manifest.raw_byte_count for item in self.shards)

    @property
    def gap_bytes(self) -> int:
        return sum(item.byte_count for item in self.gaps)

    def to_manifest_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_record_count": self.source_record_count,
            "source_byte_count": self.source_byte_count,
            "materialized_raw_bytes": self.materialized_raw_bytes,
            "gap_bytes": self.gap_bytes,
            "shards": [item.manifest.to_dict() for item in self.shards],
            "gaps": [item.to_dict() for item in self.gaps],
        }

    def canonical_manifest_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_manifest_dict())


@dataclass(frozen=True)
class _RangePiece:
    descriptor: RawRangeDescriptor
    payload: bytes


def _piece_for_record(
    raw_record: RawEvidenceRecord,
    local_start: int,
    local_end: int,
    *,
    fragment_index: int,
    fragment_count: int,
) -> _RangePiece:
    payload = raw_record.payload[local_start:local_end]
    record = raw_record.catalog_record
    descriptor = RawRangeDescriptor(
        unit_ref=record.unit_ref,
        source_kind=str(record.source_kind),
        coordinate=record.coordinate,
        range_start=record.coordinate.byte_start + local_start,
        range_end=record.coordinate.byte_start + local_end,
        fragment_index=fragment_index,
        fragment_count=fragment_count,
        payload_offset=0,
        payload_length=len(payload),
        fragment_commitment=content_commitment(payload),
        record_commitment=record.content_commitment or "",
        event_time=record.event_time,
        turn_count=record.turn_count,
    )
    return _RangePiece(descriptor=descriptor, payload=payload)


def _serialize_pieces(
    pieces: Sequence[_RangePiece],
) -> tuple[bytes, tuple[RawRangeDescriptor, ...]]:
    offset = 0
    descriptors: list[RawRangeDescriptor] = []
    payload_parts: list[bytes] = []
    for piece in pieces:
        descriptor = replace(piece.descriptor, payload_offset=offset)
        descriptors.append(descriptor)
        payload_parts.append(piece.payload)
        offset += len(piece.payload)
    header = {
        "schema_version": RAW_SHARD_SCHEMA_VERSION,
        "format": "session_retrospective_raw_shard_v2",
        "ranges": [item.to_dict() for item in descriptors],
    }
    return canonical_json_bytes(header) + b"\n" + b"".join(payload_parts), tuple(
        descriptors
    )


def _artifact_from_pieces(
    pieces: Sequence[_RangePiece], ordinal: int
) -> RawShardArtifact:
    data, descriptors = _serialize_pieces(pieces)
    digest = _sha256_hex(data)
    seen_units: set[str] = set()
    turn_count = 0
    for descriptor in descriptors:
        if descriptor.unit_ref not in seen_units:
            seen_units.add(descriptor.unit_ref)
            turn_count += descriptor.turn_count
    manifest = ShardManifest(
        ordinal=ordinal,
        shard_ref=f"raw_shard_sha256:{digest}",
        file_name=f"raw-shard-{ordinal:05d}-{digest[:16]}.bin",
        content_sha256=digest,
        byte_count=len(data),
        raw_byte_count=sum(len(piece.payload) for piece in pieces),
        turn_count=turn_count,
        ranges=descriptors,
    )
    return RawShardArtifact(manifest=manifest, data=data)


def _utf8_boundary_at_or_before(payload: bytes, position: int, minimum: int) -> int:
    position = min(position, len(payload))
    while (
        position > minimum
        and position < len(payload)
        and payload[position] & 0xC0 == 0x80
    ):
        position -= 1
    return position


def _largest_fitting_end(
    raw_record: RawEvidenceRecord, start: int, max_bytes: int
) -> int | None:
    low = start + 1
    high = len(raw_record.payload)
    best: int | None = None
    while low <= high:
        midpoint = (low + high) // 2
        end = _utf8_boundary_at_or_before(raw_record.payload, midpoint, start)
        if end <= start:
            low = midpoint + 1
            continue
        probe = _piece_for_record(
            raw_record,
            start,
            end,
            fragment_index=_MAX_FRAGMENT_ORDINAL - 1,
            fragment_count=_MAX_FRAGMENT_ORDINAL,
        )
        size = len(_serialize_pieces((probe,))[0])
        if size <= max_bytes:
            best = end
            low = midpoint + 1
        else:
            high = midpoint - 1
    return best


def _gap_for_record(record: RawEvidenceRecord, reason: str) -> RawGapDescriptor:
    return RawGapDescriptor(
        unit_ref=record.unit_ref,
        coordinate=record.catalog_record.coordinate,
        content_commitment=record.catalog_record.content_commitment or "",
        reason=reason,
    )


def _split_record(
    raw_record: RawEvidenceRecord,
    limits: ShardLimits,
) -> tuple[tuple[_RangePiece, ...], RawGapDescriptor | None]:
    """Return a whole record, exact UTF-8 byte ranges, or one whole-record gap.

    Oversized valid UTF-8 records are split only at code-point boundaries. No
    partial pieces escape when a record cannot be represented within the shard
    or processing limits, so later records remain independently materializable.
    """

    record = raw_record.catalog_record
    if len(raw_record.payload) > limits.record_processing_budget:
        return (), _gap_for_record(raw_record, "oversized_record_budget_exceeded")
    if record.turn_count > limits.max_turns:
        return (), _gap_for_record(raw_record, "record_turn_limit_exceeded")

    whole = _piece_for_record(
        raw_record, 0, len(raw_record.payload), fragment_index=0, fragment_count=1
    )
    if len(_serialize_pieces((whole,))[0]) <= limits.max_bytes:
        return (whole,), None
    if not raw_record.payload:
        return (), _gap_for_record(raw_record, "shard_metadata_budget_exceeded")

    try:
        raw_record.payload.decode("utf-8")
    except UnicodeDecodeError:
        return (), _gap_for_record(raw_record, "invalid_utf8_oversized_record")

    boundaries: list[tuple[int, int]] = []
    start = 0
    while start < len(raw_record.payload):
        end = _largest_fitting_end(raw_record, start, limits.max_bytes)
        if end is None or end <= start:
            return (), _gap_for_record(raw_record, "shard_metadata_budget_exceeded")
        boundaries.append((start, end))
        if len(boundaries) >= _MAX_FRAGMENT_ORDINAL:
            return (), _gap_for_record(raw_record, "fragment_count_limit_exceeded")
        start = end

    fragment_count = len(boundaries)
    pieces = tuple(
        _piece_for_record(
            raw_record,
            start,
            end,
            fragment_index=index,
            fragment_count=fragment_count,
        )
        for index, (start, end) in enumerate(boundaries)
    )
    if any(len(_serialize_pieces((piece,))[0]) > limits.max_bytes for piece in pieces):
        return (), _gap_for_record(raw_record, "shard_metadata_budget_exceeded")
    return pieces, None


def _piece_turn_count(pieces: Sequence[_RangePiece]) -> int:
    seen: set[str] = set()
    count = 0
    for piece in pieces:
        if piece.descriptor.unit_ref not in seen:
            seen.add(piece.descriptor.unit_ref)
            count += piece.descriptor.turn_count
    return count


def _validate_conservation(
    records: Sequence[RawEvidenceRecord],
    shards: Sequence[RawShardArtifact],
    gaps: Sequence[RawGapDescriptor],
) -> None:
    covered: dict[str, list[tuple[RawRangeDescriptor, bytes]]] = {}
    for shard in shards:
        serialized_header, separator, shard_payload = shard.data.partition(b"\n")
        if not separator:
            raise ShardingValidationError("raw shard is missing its header boundary")
        expected_header = canonical_json_bytes(
            {
                "schema_version": RAW_SHARD_SCHEMA_VERSION,
                "format": "session_retrospective_raw_shard_v2",
                "ranges": [item.to_dict() for item in shard.manifest.ranges],
            }
        )
        if serialized_header != expected_header:
            raise ShardingValidationError(
                "raw shard header does not match its manifest ranges"
            )
        if len(shard_payload) != shard.manifest.raw_byte_count:
            raise ShardingValidationError(
                "raw shard payload length does not match raw_byte_count"
            )
        for descriptor in shard.manifest.ranges:
            fragment = shard_payload[
                descriptor.payload_offset : descriptor.payload_offset
                + descriptor.payload_length
            ]
            if len(fragment) != descriptor.payload_length:
                raise ShardingValidationError(
                    "raw shard range exceeds its serialized payload"
                )
            if content_commitment(fragment) != descriptor.fragment_commitment:
                raise ShardingValidationError(
                    "raw shard fragment does not match its commitment"
                )
            covered.setdefault(descriptor.unit_ref, []).append((descriptor, fragment))
    gap_by_unit = {gap.unit_ref: gap for gap in gaps}
    for raw_record in records:
        record = raw_record.catalog_record
        materialized = sorted(
            covered.get(record.unit_ref, ()),
            key=lambda item: (item[0].range_start, item[0].range_end),
        )
        descriptors = [item[0] for item in materialized]
        gap = gap_by_unit.get(record.unit_ref)
        if gap is not None:
            if descriptors:
                raise ShardingValidationError(
                    "a gapped record must not leave partial shard ranges"
                )
            if (
                gap.coordinate != record.coordinate
                or gap.content_commitment != record.content_commitment
                or gap.byte_count != len(raw_record.payload)
            ):
                raise ShardingValidationError(
                    "gap does not cover the exact source record"
                )
            continue
        if not descriptors:
            raise ShardingValidationError(
                "a source record has neither a shard range nor an explicit gap"
            )
        if {item.fragment_count for item in descriptors} != {len(descriptors)}:
            raise ShardingValidationError(
                "fragment_count does not match exact record coverage"
            )
        if sorted(item.fragment_index for item in descriptors) != list(
            range(len(descriptors))
        ):
            raise ShardingValidationError(
                "fragment indexes do not form one complete exact record"
            )
        expected = record.coordinate.byte_start
        for descriptor, fragment in materialized:
            start, end = descriptor.range_start, descriptor.range_end
            if start != expected or end < start:
                raise ShardingValidationError(
                    "materialized ranges are not contiguous and non-overlapping"
                )
            if (
                descriptor.coordinate != record.coordinate
                or descriptor.source_kind != str(record.source_kind)
                or descriptor.record_commitment != record.content_commitment
                or descriptor.event_time != record.event_time
                or descriptor.turn_count != record.turn_count
            ):
                raise ShardingValidationError(
                    "materialized range metadata does not match its catalog record"
                )
            local_start = start - record.coordinate.byte_start
            local_end = end - record.coordinate.byte_start
            if fragment != raw_record.payload[local_start:local_end]:
                raise ShardingValidationError(
                    "materialized range bytes do not match the source record"
                )
            expected = end
        if expected != record.coordinate.byte_end:
            raise ShardingValidationError(
                "materialized ranges silently lost source bytes"
            )
    if sum(item.manifest.raw_byte_count for item in shards) + sum(
        item.byte_count for item in gaps
    ) != sum(item.catalog_record.byte_count for item in records):
        raise ShardingValidationError(
            "materialized and gap bytes do not conserve the source corpus"
        )


def build_raw_shards(
    records: Iterable[RawEvidenceRecord],
    *,
    limits: ShardLimits | None = None,
) -> MaterializationResult:
    selected_limits = limits or ShardLimits()
    supplied = tuple(records)
    if any(not isinstance(item, RawEvidenceRecord) for item in supplied):
        raise ShardingValidationError("records must contain RawEvidenceRecord values")
    ordered = tuple(
        sorted(supplied, key=lambda item: catalog_record_sort_key(item.catalog_record))
    )
    unit_refs = [item.unit_ref for item in ordered]
    if len(set(unit_refs)) != len(unit_refs):
        raise ShardingValidationError("raw records must have unique unit_ref values")

    pieces: list[_RangePiece] = []
    gaps: list[RawGapDescriptor] = []
    for record in ordered:
        record_pieces, gap = _split_record(record, selected_limits)
        if gap is not None:
            gaps.append(gap)
        else:
            pieces.extend(record_pieces)

    shards: list[RawShardArtifact] = []
    current: list[_RangePiece] = []
    for piece in pieces:
        candidate = (*current, piece)
        fits_turns = _piece_turn_count(candidate) <= selected_limits.max_turns
        fits_bytes = len(_serialize_pieces(candidate)[0]) <= selected_limits.max_bytes
        if current and (not fits_turns or not fits_bytes):
            if len(shards) >= MAX_RUN_RAW_SHARDS:
                raise ShardingValidationError(
                    "raw shard count exceeds cleanup capacity"
                )
            shards.append(_artifact_from_pieces(current, len(shards)))
            current = [piece]
        else:
            current.append(piece)
        if len(_serialize_pieces(current)[0]) > selected_limits.max_bytes:
            raise ShardingValidationError(
                "internal error: a prevalidated range exceeded the shard limit"
            )
    if current:
        if len(shards) >= MAX_RUN_RAW_SHARDS:
            raise ShardingValidationError("raw shard count exceeds cleanup capacity")
        shards.append(_artifact_from_pieces(current, len(shards)))

    _validate_conservation(ordered, shards, gaps)
    result = MaterializationResult(
        shards=tuple(shards),
        gaps=tuple(gaps),
        source_record_count=len(ordered),
        source_byte_count=sum(item.catalog_record.byte_count for item in ordered),
    )
    for shard in result.shards:
        if shard.manifest.turn_count > selected_limits.max_turns:
            raise ShardingValidationError("materialized shard exceeds the turn limit")
        if shard.manifest.byte_count > selected_limits.max_bytes:
            raise ShardingValidationError("materialized shard exceeds the byte limit")
    return result


def _ensure_private_directory(path: Path) -> Path:
    if _safe_io is None:
        raise ShardingValidationError("secure raw shard I/O is unavailable")
    return _safe_io.ensure_owner_only_directory(path)


def _write_private_bytes(path: Path, data: bytes) -> Path:
    if _safe_io is None:
        raise ShardingValidationError("secure raw shard I/O is unavailable")
    return _safe_io.atomic_write_bytes(path, data, create_parents=False)


def materialize_raw_shards(
    records: Iterable[RawEvidenceRecord],
    run_directory: str | os.PathLike[str],
    *,
    limits: ShardLimits | None = None,
) -> MaterializationResult:
    """Build and persist deterministic owner-only raw shards and their manifest."""

    result = build_raw_shards(records, limits=limits)
    run_path = _ensure_private_directory(Path(run_directory))
    for artifact in result.shards:
        _write_private_bytes(run_path / artifact.manifest.file_name, artifact.data)
    _write_private_bytes(
        run_path / RAW_SHARDS_MANIFEST_FILE,
        result.canonical_manifest_bytes() + b"\n",
    )
    return result


@dataclass(frozen=True)
class JobManifest:
    job_ref: str
    job_kind: str
    shard_ref: str
    shard_content_sha256: str
    shard_byte_count: int
    framing_sha256: str
    framing_byte_count: int
    input_byte_count: int
    prompt_version: str
    result_schema_version: str
    policy_version: str
    retry_ordinal: int
    schema_version: int = JOB_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != JOB_MANIFEST_SCHEMA_VERSION:
            raise ShardingValidationError(
                f"job schema_version must be {JOB_MANIFEST_SCHEMA_VERSION}"
            )
        if _JOB_REF_RE.fullmatch(self.job_ref) is None:
            raise ShardingValidationError(
                "job_ref must be job_ref_v2:<64 lowercase hex>"
            )
        _code(self.job_kind, "job.job_kind")
        _bounded_text(self.shard_ref, "job.shard_ref")
        if _HEX_SHA256_RE.fullmatch(self.shard_content_sha256) is None:
            raise ShardingValidationError(
                "job.shard_content_sha256 must be 64 lowercase hex"
            )
        if _HEX_SHA256_RE.fullmatch(self.framing_sha256) is None:
            raise ShardingValidationError("job.framing_sha256 must be 64 lowercase hex")
        for name, value in (
            ("shard_byte_count", self.shard_byte_count),
            ("framing_byte_count", self.framing_byte_count),
            ("input_byte_count", self.input_byte_count),
            ("retry_ordinal", self.retry_ordinal),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ShardingValidationError(
                    f"job.{name} must be a non-negative integer"
                )
        if self.input_byte_count != self.shard_byte_count + self.framing_byte_count:
            raise ShardingValidationError(
                "job.input_byte_count must include shard and framing bytes"
            )
        if self.input_byte_count > DEFAULT_MAX_SHARD_BYTES:
            raise ShardingValidationError(
                "job input exceeds the complete 512 KiB envelope limit"
            )
        _bounded_text(self.prompt_version, "job.prompt_version")
        _bounded_text(self.result_schema_version, "job.result_schema_version")
        _bounded_text(self.policy_version, "job.policy_version")

    def identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "job_kind": self.job_kind,
            "shard_ref": self.shard_ref,
            "shard_content_sha256": self.shard_content_sha256,
            "shard_byte_count": self.shard_byte_count,
            "framing_sha256": self.framing_sha256,
            "framing_byte_count": self.framing_byte_count,
            "input_byte_count": self.input_byte_count,
            "prompt_version": self.prompt_version,
            "result_schema_version": self.result_schema_version,
            "policy_version": self.policy_version,
            "retry_ordinal": self.retry_ordinal,
        }

    def to_dict(self) -> dict[str, object]:
        return {"job_ref": self.job_ref, **self.identity_payload()}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def build_job_manifest(
    shard: ShardManifest | RawShardArtifact,
    *,
    job_kind: JobKind | str,
    prompt_version: str,
    result_schema_version: str,
    policy_version: str,
    framing: bytes,
    job_key: object,
    retry_ordinal: int = 0,
) -> JobManifest:
    manifest = shard.manifest if isinstance(shard, RawShardArtifact) else shard
    if not isinstance(manifest, ShardManifest):
        raise ShardingValidationError(
            "shard must be a ShardManifest or RawShardArtifact"
        )
    if not isinstance(framing, bytes):
        raise ShardingValidationError(
            "framing must be the exact serialized framing bytes"
        )
    kind = job_kind.value if isinstance(job_kind, Enum) else job_kind
    _code(kind, "job_kind")
    preimage = {
        "schema_version": JOB_MANIFEST_SCHEMA_VERSION,
        "job_kind": kind,
        "shard_ref": manifest.shard_ref,
        "shard_content_sha256": manifest.content_sha256,
        "shard_byte_count": manifest.byte_count,
        "framing_sha256": _sha256_hex(framing),
        "framing_byte_count": len(framing),
        "input_byte_count": manifest.byte_count + len(framing),
        "prompt_version": prompt_version,
        "result_schema_version": result_schema_version,
        "policy_version": policy_version,
        "retry_ordinal": retry_ordinal,
    }
    if hasattr(job_key, "derive_ref"):
        try:
            job_ref = str(job_key.derive_ref("job_ref_v2", preimage))
        except (TypeError, ValueError) as exc:
            raise ShardingValidationError(
                "job_key could not derive a job_ref_v2 reference"
            ) from exc
    elif isinstance(job_key, bytes) and job_key:
        digest = hmac.new(
            job_key, canonical_json_bytes(preimage), hashlib.sha256
        ).hexdigest()
        job_ref = f"job_ref_v2:{digest}"
    else:
        raise ShardingValidationError(
            "job_key must be non-empty bytes or an identity key"
        )
    return JobManifest(job_ref=job_ref, **preimage)


create_job_manifest = build_job_manifest
make_job_manifest = build_job_manifest


def write_job_manifest(manifest: JobManifest, path: str | os.PathLike[str]) -> Path:
    if not isinstance(manifest, JobManifest):
        raise ShardingValidationError("manifest must be a JobManifest")
    target = Path(path)
    _ensure_private_directory(target.parent)
    return _write_private_bytes(target, manifest.canonical_bytes() + b"\n")
