from __future__ import annotations

from dataclasses import dataclass, field, replace
import datetime as dt
from enum import Enum
import hashlib
import json
import math
import re
from typing import Any, Iterable, Mapping, Sequence

try:
    from .contracts import SourceCellStatus as _CommonSourceCellStatus
    from .contracts import SourceKind as _CommonSourceKind
except (
    ImportError,
    ModuleNotFoundError,
):  # Supports direct early-stage module loading.
    _CommonSourceCellStatus = None
    _CommonSourceKind = None


CATALOG_SCHEMA_VERSION = 2
TRANSPORT_MANIFEST_VERSION = 1
REQUIRED_SOURCE_KINDS = (
    "session_index",
    "history",
    "active_rollout",
    "archived_rollout",
)

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_ROLLOUT_NAME_TIMESTAMP_RE = re.compile(
    r"(?:^|/)rollout-"
    r"(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<hour>\d{2})-(?P<minute>\d{2})-(?P<second>\d{2})"
    r"(?P<fraction>\.\d{1,6})?"
    r"(?P<timezone>Z|[+-]\d{2}-\d{2})?"
    r"(?=-|\.jsonl(?:$|[?#]))"
)
_ROLLOUT_RECORD_REF_RE = re.compile(r"^record-v2:([0-9a-f]{64}):([0-9a-f]{64})$")


class CatalogValidationError(ValueError):
    """Raised when source catalog data violates the v2 transport contract."""


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class TransportKind(_StringEnum):
    LOCAL = "local"
    REMOTE = "remote"


if _CommonSourceKind is None:

    class SourceKind(_StringEnum):
        SESSION_INDEX = "session_index"
        HISTORY = "history"
        ACTIVE_ROLLOUT = "active_rollout"
        ARCHIVED_ROLLOUT = "archived_rollout"
else:
    SourceKind = _CommonSourceKind


if _CommonSourceCellStatus is None:

    class SourceCellStatus(_StringEnum):
        COMPLETE = "complete"
        NO_ACTIVITY = "no_activity"
        VERIFIED_ABSENT = "verified_absent"
        GAP = "gap"
else:
    SourceCellStatus = _CommonSourceCellStatus


class AccountingClass(_StringEnum):
    CONSUMED_CANDIDATE = "consumed_candidate"
    STRUCTURALLY_EXCLUDED = "structurally_excluded"
    EXPLICIT_GAP = "explicit_gap"


class StructuralExclusionReason(_StringEnum):
    """Closed, versioned deterministic exclusion reasons."""

    DUPLICATE_OF = "duplicate_of"
    RETROSPECTIVE_COORDINATOR = "retrospective_coordinator"
    RETROSPECTIVE_WORKER = "retrospective_worker"
    NON_EVIDENCE_WRAPPER = "non_evidence_wrapper"
    EMPTY_STRUCTURAL_UNIT = "empty_structural_unit"
    OUTSIDE_REQUESTED_WINDOW = "outside_requested_window"
    SOURCE_POLICY_EXCLUDED = "source_policy_excluded"


def _enum_value(enum_type: type[Enum], value: Enum | str, label: str) -> Enum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise CatalogValidationError(f"{label} must be one of: {allowed}") from exc


def _bounded_text(value: object, label: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CatalogValidationError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise CatalogValidationError(f"{label} must not contain control characters")
    return value


def _reason_code(value: object, label: str) -> str:
    if not isinstance(value, str) or _REASON_RE.fullmatch(value) is None:
        raise CatalogValidationError(f"{label} must be a lower_snake_case reason code")
    return value


def _require_exact_keys(
    value: Mapping[str, object], expected: Iterable[str], label: str
) -> None:
    expected_keys = frozenset(expected)
    actual_keys = frozenset(value)
    if actual_keys == expected_keys:
        return
    missing = sorted(expected_keys - actual_keys)
    unknown = sorted(str(key) for key in actual_keys - expected_keys)
    details: list[str] = []
    if missing:
        details.append("missing=" + ",".join(missing))
    if unknown:
        details.append("unknown=" + ",".join(unknown))
    raise CatalogValidationError(
        f"{label} must contain exactly its closed key set ({'; '.join(details)})"
    )


def _non_negative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CatalogValidationError(f"{label} must be a non-negative integer")
    return value


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CatalogValidationError("value is not canonical JSON data") from exc


def _utc_instant(value: str | dt.datetime, label: str = "timestamp") -> dt.datetime:
    if isinstance(value, dt.datetime):
        parsed = value
    elif isinstance(value, str) and value:
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = dt.datetime.fromisoformat(text)
        except ValueError as exc:
            raise CatalogValidationError(
                f"{label} must be an ISO-8601 timestamp"
            ) from exc
    else:
        raise CatalogValidationError(f"{label} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CatalogValidationError(f"{label} must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def canonical_utc_timestamp(value: str | dt.datetime, label: str = "timestamp") -> str:
    parsed = _utc_instant(value, label)
    timespec = "microseconds" if parsed.microsecond else "seconds"
    return parsed.isoformat(timespec=timespec).replace("+00:00", "Z")


def content_commitment(payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def transcript_descriptor_commitment(
    raw_records: Mapping[str, Mapping[str, Any]], *, source_marker: str
) -> str:
    rows: list[dict[str, Any]] = []
    for unit_ref, descriptor in sorted(raw_records.items()):
        byte_count = descriptor.get("byte_count")
        commitment = descriptor.get("content_commitment")
        if (
            not isinstance(unit_ref, str)
            or isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count < 0
            or not isinstance(commitment, str)
            or _SHA256_RE.fullmatch(commitment) is None
        ):
            raise CatalogValidationError(
                "source transport transcript descriptor is invalid"
            )
        rows.append(
            {
                "byte_count": byte_count,
                "content_commitment": commitment,
                "unit_ref": unit_ref,
            }
        )
    return content_commitment(
        canonical_json_bytes(
            {
                "records": rows,
                "schema": "source_transport_transcript_v2",
                "source": source_marker,
            }
        )
    )


def transcript_commitment(
    raw_records: Mapping[str, bytes], *, source_marker: str
) -> str:
    return transcript_descriptor_commitment(
        {
            unit_ref: {
                "byte_count": len(payload),
                "content_commitment": content_commitment(payload),
            }
            for unit_ref, payload in raw_records.items()
        },
        source_marker=source_marker,
    )


def event_time_from_record(
    record: Mapping[str, Any],
    *,
    stable_event_time: str | dt.datetime | None = None,
    mtime: float | dt.datetime | None = None,
) -> str | None:
    """Return canonical source event time without consulting filesystem mtime.

    ``mtime`` is accepted to make the non-fallback contract explicit to source
    adapters. Archive or path movement must not change event semantics.
    """

    del mtime
    payload = record.get("payload")
    payload_mapping = payload if isinstance(payload, Mapping) else {}
    for key in ("timestamp", "updated_at", "time", "created_at", "ts"):
        value = record.get(key)
        if value is None:
            value = payload_mapping.get(key)
        if isinstance(value, (str, dt.datetime)):
            try:
                return canonical_utc_timestamp(value, f"record.{key}")
            except CatalogValidationError:
                continue
        if (
            key == "ts"
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        ):
            try:
                parsed = dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
            except (OverflowError, OSError, ValueError):
                continue
            return canonical_utc_timestamp(parsed, "record.ts")
    if stable_event_time is not None:
        return canonical_utc_timestamp(stable_event_time, "stable_event_time")
    return None


def stable_event_time_from_locator(source_locator: str) -> str | None:
    """Return the complete UTC timestamp encoded in a rollout filename."""

    if not isinstance(source_locator, str) or not source_locator:
        return None
    match = _ROLLOUT_NAME_TIMESTAMP_RE.search(source_locator)
    if match is None:
        return None
    timezone = match.group("timezone")
    if timezone is None or timezone == "Z":
        offset = "+00:00"
    else:
        offset = timezone[:3] + ":" + timezone[4:]
    timestamp = (
        f"{match.group('date')}T{match.group('hour')}:"
        f"{match.group('minute')}:{match.group('second')}"
        f"{match.group('fraction') or ''}{offset}"
    )
    try:
        return canonical_utc_timestamp(timestamp, "source_locator")
    except CatalogValidationError:
        return None


@dataclass(frozen=True, order=True)
class StableSourceCoordinate:
    """A source coordinate carrying stable logical and physical identities."""

    host_ref: str
    source_ref: str
    record_ref: str
    byte_start: int
    byte_end: int

    def __post_init__(self) -> None:
        _bounded_text(self.host_ref, "coordinate.host_ref", maximum=512)
        _bounded_text(self.source_ref, "coordinate.source_ref")
        _bounded_text(self.record_ref, "coordinate.record_ref")
        if (
            isinstance(self.byte_start, bool)
            or not isinstance(self.byte_start, int)
            or self.byte_start < 0
        ):
            raise CatalogValidationError(
                "coordinate.byte_start must be a non-negative integer"
            )
        if (
            isinstance(self.byte_end, bool)
            or not isinstance(self.byte_end, int)
            or self.byte_end < self.byte_start
        ):
            raise CatalogValidationError(
                "coordinate.byte_end must be at least byte_start"
            )

    @property
    def byte_count(self) -> int:
        return self.byte_end - self.byte_start

    def to_dict(self) -> dict[str, object]:
        return {
            "host_ref": self.host_ref,
            "source_ref": self.source_ref,
            "record_ref": self.record_ref,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> StableSourceCoordinate:
        _require_exact_keys(
            value,
            {"host_ref", "source_ref", "record_ref", "byte_start", "byte_end"},
            "coordinate",
        )
        return cls(
            host_ref=value["host_ref"],  # type: ignore[arg-type]
            source_ref=value["source_ref"],  # type: ignore[arg-type]
            record_ref=value["record_ref"],  # type: ignore[arg-type]
            byte_start=value["byte_start"],  # type: ignore[arg-type]
            byte_end=value["byte_end"],  # type: ignore[arg-type]
        )


SourceCoordinate = StableSourceCoordinate


def rollout_record_identity(record_ref: str) -> tuple[str, str] | None:
    """Return physical-occurrence and canonical-equivalence digests."""

    match = _ROLLOUT_RECORD_REF_RE.fullmatch(record_ref)
    if match is None:
        return None
    return match.group(1), match.group(2)


@dataclass(frozen=True)
class ExplicitGap:
    reason: str
    stage: str
    repairable: bool = True

    def __post_init__(self) -> None:
        _reason_code(self.reason, "gap.reason")
        _reason_code(self.stage, "gap.stage")
        if not isinstance(self.repairable, bool):
            raise CatalogValidationError("gap.repairable must be a boolean")

    def to_dict(self) -> dict[str, object]:
        return {
            "reason": self.reason,
            "stage": self.stage,
            "repairable": self.repairable,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ExplicitGap:
        _require_exact_keys(value, {"reason", "stage", "repairable"}, "gap")
        return cls(
            reason=value["reason"],  # type: ignore[arg-type]
            stage=value["stage"],  # type: ignore[arg-type]
            repairable=value["repairable"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class CatalogRecord:
    unit_ref: str
    source_kind: SourceKind | str
    coordinate: StableSourceCoordinate
    accounting_class: AccountingClass | str = AccountingClass.CONSUMED_CANDIDATE
    event_time: str | None = None
    content_commitment: str | None = None
    turn_count: int = 1
    exclusion_reason: StructuralExclusionReason | str | None = None
    duplicate_of: str | None = None
    gap: ExplicitGap | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.unit_ref, "catalog_record.unit_ref")
        source_kind = _enum_value(
            SourceKind, self.source_kind, "catalog_record.source_kind"
        )
        accounting_class = _enum_value(
            AccountingClass,
            self.accounting_class,
            "catalog_record.accounting_class",
        )
        object.__setattr__(self, "source_kind", source_kind)
        object.__setattr__(self, "accounting_class", accounting_class)
        if not isinstance(self.coordinate, StableSourceCoordinate):
            raise CatalogValidationError(
                "catalog_record.coordinate must be a StableSourceCoordinate"
            )
        if self.event_time is not None:
            object.__setattr__(
                self,
                "event_time",
                canonical_utc_timestamp(self.event_time, "catalog_record.event_time"),
            )
        if (
            self.content_commitment is not None
            and _SHA256_RE.fullmatch(self.content_commitment) is None
        ):
            raise CatalogValidationError(
                "catalog_record.content_commitment must be sha256:<64 lowercase hex>"
            )
        if (
            isinstance(self.turn_count, bool)
            or not isinstance(self.turn_count, int)
            or self.turn_count < 0
        ):
            raise CatalogValidationError(
                "catalog_record.turn_count must be a non-negative integer"
            )

        exclusion_reason: StructuralExclusionReason | None = None
        if self.exclusion_reason is not None:
            exclusion_reason = _enum_value(
                StructuralExclusionReason,
                self.exclusion_reason,
                "catalog_record.exclusion_reason",
            )
            object.__setattr__(self, "exclusion_reason", exclusion_reason)

        if accounting_class is AccountingClass.CONSUMED_CANDIDATE:
            if self.content_commitment is None:
                raise CatalogValidationError(
                    "consumed_candidate requires content_commitment"
                )
            if self.turn_count < 1:
                raise CatalogValidationError(
                    "consumed_candidate requires a positive turn_count"
                )
            if (
                exclusion_reason is not None
                or self.duplicate_of is not None
                or self.gap is not None
            ):
                raise CatalogValidationError(
                    "consumed_candidate cannot carry exclusion or gap fields"
                )
        elif accounting_class is AccountingClass.STRUCTURALLY_EXCLUDED:
            if exclusion_reason is None:
                raise CatalogValidationError(
                    "structurally_excluded requires a closed exclusion_reason"
                )
            if self.gap is not None:
                raise CatalogValidationError("structurally_excluded cannot carry a gap")
            if exclusion_reason is StructuralExclusionReason.DUPLICATE_OF:
                _bounded_text(self.duplicate_of, "catalog_record.duplicate_of")
                if self.duplicate_of == self.unit_ref:
                    raise CatalogValidationError(
                        "duplicate_of must name a different unit"
                    )
            elif self.duplicate_of is not None:
                raise CatalogValidationError(
                    "duplicate_of is valid only for the duplicate_of exclusion reason"
                )
        else:
            if not isinstance(self.gap, ExplicitGap):
                raise CatalogValidationError("explicit_gap requires gap metadata")
            if exclusion_reason is not None or self.duplicate_of is not None:
                raise CatalogValidationError(
                    "explicit_gap cannot carry exclusion fields"
                )

    @property
    def byte_count(self) -> int:
        return self.coordinate.byte_count

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "unit_ref": self.unit_ref,
            "source_kind": str(self.source_kind),
            "coordinate": self.coordinate.to_dict(),
            "accounting_class": str(self.accounting_class),
            "event_time": self.event_time,
            "content_commitment": self.content_commitment,
            "turn_count": self.turn_count,
        }
        if self.exclusion_reason is not None:
            result["exclusion_reason"] = str(self.exclusion_reason)
        if self.duplicate_of is not None:
            result["duplicate_of"] = self.duplicate_of
        if self.gap is not None:
            result["gap"] = self.gap.to_dict()
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> CatalogRecord:
        accounting_class = _enum_value(
            AccountingClass,
            value.get("accounting_class"),  # type: ignore[arg-type]
            "catalog_record.accounting_class",
        )
        expected_keys = {
            "unit_ref",
            "source_kind",
            "coordinate",
            "accounting_class",
            "event_time",
            "content_commitment",
            "turn_count",
        }
        if accounting_class is AccountingClass.STRUCTURALLY_EXCLUDED:
            expected_keys.add("exclusion_reason")
            exclusion_reason = _enum_value(
                StructuralExclusionReason,
                value.get("exclusion_reason"),  # type: ignore[arg-type]
                "catalog_record.exclusion_reason",
            )
            if exclusion_reason is StructuralExclusionReason.DUPLICATE_OF:
                expected_keys.add("duplicate_of")
        elif accounting_class is AccountingClass.EXPLICIT_GAP:
            expected_keys.add("gap")
        _require_exact_keys(value, expected_keys, "catalog_record")

        coordinate = value["coordinate"]
        if not isinstance(coordinate, Mapping):
            raise CatalogValidationError("catalog_record.coordinate must be an object")
        gap_value = value.get("gap")
        if gap_value is not None and not isinstance(gap_value, Mapping):
            raise CatalogValidationError("catalog_record.gap must be an object")
        return cls(
            unit_ref=value["unit_ref"],  # type: ignore[arg-type]
            source_kind=value["source_kind"],  # type: ignore[arg-type]
            coordinate=StableSourceCoordinate.from_dict(coordinate),
            accounting_class=accounting_class,
            event_time=value["event_time"],  # type: ignore[arg-type]
            content_commitment=value["content_commitment"],  # type: ignore[arg-type]
            turn_count=value["turn_count"],  # type: ignore[arg-type]
            exclusion_reason=value.get("exclusion_reason"),  # type: ignore[arg-type]
            duplicate_of=value.get("duplicate_of"),  # type: ignore[arg-type]
            gap=ExplicitGap.from_dict(gap_value)
            if isinstance(gap_value, Mapping)
            else None,
        )


_SOURCE_PRECEDENCE = {
    SourceKind.ACTIVE_ROLLOUT: 0,
    SourceKind.ARCHIVED_ROLLOUT: 1,
    SourceKind.HISTORY: 2,
    SourceKind.SESSION_INDEX: 3,
}


def catalog_record_sort_key(record: CatalogRecord) -> tuple[object, ...]:
    identity = rollout_record_identity(record.coordinate.record_ref)
    physical_occurrence = "" if identity is None else identity[0]
    return (
        record.coordinate.host_ref,
        record.coordinate.source_ref,
        physical_occurrence,
        record.coordinate.byte_start,
        record.coordinate.byte_end,
        record.coordinate.record_ref,
        _SOURCE_PRECEDENCE.get(SourceKind(record.source_kind), 99),
        record.unit_ref,
    )


def _coordinate_conflict(record: CatalogRecord) -> CatalogRecord:
    return replace(
        record,
        accounting_class=AccountingClass.EXPLICIT_GAP,
        exclusion_reason=None,
        duplicate_of=None,
        gap=ExplicitGap(
            reason="source_coordinate_conflict", stage="catalog", repairable=True
        ),
    )


def deduplicate_active_archived(
    records: Iterable[CatalogRecord],
) -> tuple[CatalogRecord, ...]:
    """Apply the closed active/archive canonical-equivalence rule.

    Physical coordinates always remain distinct. An archived occurrence is
    excluded only when exactly one active occurrence has the same canonical
    rollout-record identity, byte range, content, turn count, and compatible
    event time. Multiple active occurrences are intentionally never collapsed.
    A reused physical coordinate with conflicting evidence remains an explicit
    gap.
    """

    ordered = sorted(tuple(records), key=catalog_record_sort_key)
    physical_groups: dict[tuple[object, ...], list[CatalogRecord]] = {}
    for record in ordered:
        if (
            record.accounting_class is AccountingClass.CONSUMED_CANDIDATE
            and record.source_kind
            in {
                SourceKind.ACTIVE_ROLLOUT,
                SourceKind.ARCHIVED_ROLLOUT,
            }
        ):
            identity = rollout_record_identity(record.coordinate.record_ref)
            physical_occurrence = (
                record.coordinate.record_ref if identity is None else identity[0]
            )
            physical_key = (
                record.coordinate.host_ref,
                record.coordinate.source_ref,
                physical_occurrence,
                record.coordinate.byte_start,
                record.coordinate.byte_end,
            )
            physical_groups.setdefault(physical_key, []).append(record)

    replacements: dict[str, CatalogRecord] = {}
    for group in physical_groups.values():
        if len(group) == 1:
            continue
        signatures = {
            (
                (
                    rollout_record_identity(record.coordinate.record_ref)
                    or ("", record.coordinate.record_ref)
                )[1],
                record.content_commitment,
                record.byte_count,
                record.turn_count,
            )
            for record in group
        }
        known_event_times = {
            record.event_time for record in group if record.event_time is not None
        }
        if len(signatures) != 1 or len(known_event_times) > 1:
            for record in group:
                replacements[record.unit_ref] = _coordinate_conflict(record)
    equivalence_groups: dict[tuple[object, ...], list[CatalogRecord]] = {}
    for record in ordered:
        if (
            record.unit_ref in replacements
            or record.accounting_class is not AccountingClass.CONSUMED_CANDIDATE
            or record.source_kind
            not in {SourceKind.ACTIVE_ROLLOUT, SourceKind.ARCHIVED_ROLLOUT}
        ):
            continue
        identity = rollout_record_identity(record.coordinate.record_ref)
        canonical_identity = (
            record.coordinate.record_ref if identity is None else identity[1]
        )
        key = (
            record.coordinate.host_ref,
            record.coordinate.source_ref,
            canonical_identity,
            record.coordinate.byte_start,
            record.coordinate.byte_end,
            record.content_commitment,
            record.turn_count,
        )
        equivalence_groups.setdefault(key, []).append(record)

    for group in equivalence_groups.values():
        active = [
            record
            for record in group
            if record.source_kind is SourceKind.ACTIVE_ROLLOUT
        ]
        archived = [
            record
            for record in group
            if record.source_kind is SourceKind.ARCHIVED_ROLLOUT
        ]
        if len(active) != 1 or not archived:
            continue
        known_event_times = {
            record.event_time for record in group if record.event_time is not None
        }
        if len(known_event_times) > 1:
            for record in group:
                replacements[record.unit_ref] = _coordinate_conflict(record)
            continue
        canonical = active[0]
        merged_event_time = next(iter(known_event_times), None)
        if canonical.event_time != merged_event_time:
            replacements[canonical.unit_ref] = replace(
                canonical, event_time=merged_event_time
            )
        for record in archived:
            replacements[record.unit_ref] = replace(
                record,
                accounting_class=AccountingClass.STRUCTURALLY_EXCLUDED,
                event_time=merged_event_time,
                exclusion_reason=StructuralExclusionReason.DUPLICATE_OF,
                duplicate_of=canonical.unit_ref,
                gap=None,
            )
    return tuple(replacements.get(record.unit_ref, record) for record in ordered)


@dataclass(frozen=True)
class RemoteTransportBinding:
    process_nonce: str
    forced_command_argv: tuple[str, ...]
    no_child_policy: bool = True

    def __post_init__(self) -> None:
        _bounded_text(self.process_nonce, "remote.process_nonce", maximum=512)
        argv = tuple(self.forced_command_argv)
        if not argv:
            raise CatalogValidationError("remote.forced_command_argv must not be empty")
        for index, argument in enumerate(argv):
            _bounded_text(
                argument, f"remote.forced_command_argv[{index}]", maximum=4096
            )
        object.__setattr__(self, "forced_command_argv", argv)
        if self.no_child_policy is not True:
            raise CatalogValidationError("remote.no_child_policy must be true")

    def to_dict(self) -> dict[str, object]:
        return {
            "process_nonce": self.process_nonce,
            "forced_command_argv": list(self.forced_command_argv),
            "no_child_policy": self.no_child_policy,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> RemoteTransportBinding:
        _require_exact_keys(
            value,
            {
                "process_nonce",
                "forced_command_argv",
                "no_child_policy",
            },
            "remote",
        )
        argv = value["forced_command_argv"]
        if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
            raise CatalogValidationError("remote.forced_command_argv must be an array")
        return cls(
            process_nonce=value["process_nonce"],  # type: ignore[arg-type]
            forced_command_argv=tuple(argv),  # type: ignore[arg-type]
            no_child_policy=value["no_child_policy"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class SourceTransportManifest:
    host_ref: str
    transport_kind: TransportKind | str
    source_kind: SourceKind | str
    window_start: str
    window_end: str
    status: SourceCellStatus | str
    records: tuple[CatalogRecord, ...] = field(default_factory=tuple)
    snapshot_commitment: str | None = None
    absence_proof: str | None = None
    enumeration_gap: ExplicitGap | None = None
    remote: RemoteTransportBinding | None = None
    total_records: int | None = None
    total_bytes: int | None = None
    schema_version: int = CATALOG_SCHEMA_VERSION
    transport_version: int = TRANSPORT_MANIFEST_VERSION

    def __post_init__(self) -> None:
        _bounded_text(self.host_ref, "manifest.host_ref", maximum=512)
        transport_kind = _enum_value(
            TransportKind, self.transport_kind, "manifest.transport_kind"
        )
        source_kind = _enum_value(SourceKind, self.source_kind, "manifest.source_kind")
        status = _enum_value(SourceCellStatus, self.status, "manifest.status")
        object.__setattr__(self, "transport_kind", transport_kind)
        object.__setattr__(self, "source_kind", source_kind)
        object.__setattr__(self, "status", status)
        if self.schema_version != CATALOG_SCHEMA_VERSION:
            raise CatalogValidationError(
                f"manifest.schema_version must be {CATALOG_SCHEMA_VERSION}"
            )
        if self.transport_version != TRANSPORT_MANIFEST_VERSION:
            raise CatalogValidationError(
                f"manifest.transport_version must be {TRANSPORT_MANIFEST_VERSION}"
            )

        window_start_instant = _utc_instant(self.window_start, "manifest.window_start")
        window_end_instant = _utc_instant(self.window_end, "manifest.window_end")
        if window_start_instant >= window_end_instant:
            raise CatalogValidationError(
                "manifest window must be a non-empty half-open interval"
            )
        window_start = canonical_utc_timestamp(window_start_instant)
        window_end = canonical_utc_timestamp(window_end_instant)
        object.__setattr__(self, "window_start", window_start)
        object.__setattr__(self, "window_end", window_end)

        records = tuple(self.records)
        if any(not isinstance(record, CatalogRecord) for record in records):
            raise CatalogValidationError(
                "manifest.records must contain CatalogRecord values"
            )
        if list(records) != sorted(records, key=catalog_record_sort_key):
            raise CatalogValidationError(
                "manifest.records must be in deterministic source-coordinate order"
            )
        unit_refs: set[str] = set()
        for record in records:
            if record.unit_ref in unit_refs:
                raise CatalogValidationError(
                    f"duplicate catalog unit_ref: {record.unit_ref}"
                )
            unit_refs.add(record.unit_ref)
            if record.source_kind is not source_kind:
                raise CatalogValidationError(
                    "every manifest record must match manifest.source_kind"
                )
            if record.coordinate.host_ref != self.host_ref:
                raise CatalogValidationError(
                    "every manifest record must match manifest.host_ref"
                )
        object.__setattr__(self, "records", records)

        expected_records = len(records)
        expected_bytes = sum(record.byte_count for record in records)
        if self.total_records is not None and (
            isinstance(self.total_records, bool)
            or not isinstance(self.total_records, int)
            or self.total_records < 0
        ):
            raise CatalogValidationError(
                "manifest.total_records must be a non-negative integer"
            )
        if self.total_bytes is not None and (
            isinstance(self.total_bytes, bool)
            or not isinstance(self.total_bytes, int)
            or self.total_bytes < 0
        ):
            raise CatalogValidationError(
                "manifest.total_bytes must be a non-negative integer"
            )
        if self.total_records is None:
            object.__setattr__(self, "total_records", expected_records)
        elif self.total_records != expected_records:
            raise CatalogValidationError(
                "manifest.total_records does not match records"
            )
        if self.total_bytes is None:
            object.__setattr__(self, "total_bytes", expected_bytes)
        elif self.total_bytes != expected_bytes:
            raise CatalogValidationError(
                "manifest.total_bytes does not match record byte ranges"
            )

        if (
            self.snapshot_commitment is not None
            and _SHA256_RE.fullmatch(self.snapshot_commitment) is None
        ):
            raise CatalogValidationError(
                "manifest.snapshot_commitment must be sha256:<64 lowercase hex>"
            )
        if self.absence_proof is not None:
            _bounded_text(self.absence_proof, "manifest.absence_proof")
        if self.enumeration_gap is not None and not isinstance(
            self.enumeration_gap, ExplicitGap
        ):
            raise CatalogValidationError("manifest.enumeration_gap must be ExplicitGap")

        if status in {SourceCellStatus.COMPLETE, SourceCellStatus.NO_ACTIVITY}:
            if self.snapshot_commitment is None:
                raise CatalogValidationError(
                    "complete enumeration requires a catalog snapshot commitment; "
                    "authenticated terminal proof is verified by the coordinator"
                )
            expected_snapshot = snapshot_commitment_for_records(records)
            if self.snapshot_commitment != expected_snapshot:
                raise CatalogValidationError(
                    "complete enumeration snapshot_commitment does not match records"
                )
            if self.enumeration_gap is not None:
                raise CatalogValidationError(
                    "complete enumeration cannot carry enumeration_gap"
                )
        if status is SourceCellStatus.COMPLETE and not records:
            raise CatalogValidationError(
                "complete manifest must contain records; use no_activity otherwise"
            )
        if status is SourceCellStatus.COMPLETE:
            if any(
                record.accounting_class is AccountingClass.EXPLICIT_GAP
                for record in records
            ):
                raise CatalogValidationError(
                    "complete manifest cannot contain explicit-gap records"
                )
            for record in records:
                if record.accounting_class is not AccountingClass.CONSUMED_CANDIDATE:
                    continue
                if record.event_time is None:
                    raise CatalogValidationError(
                        "complete manifest consumed records require event_time"
                    )
                event_instant = _utc_instant(
                    record.event_time, "catalog_record.event_time"
                )
                if not (window_start_instant <= event_instant < window_end_instant):
                    raise CatalogValidationError(
                        "complete manifest consumed record event_time must be inside "
                        "the half-open window"
                    )
        if status is SourceCellStatus.NO_ACTIVITY and records:
            raise CatalogValidationError(
                "no_activity manifest must not contain records"
            )
        if status is SourceCellStatus.VERIFIED_ABSENT:
            if records or self.absence_proof is None:
                raise CatalogValidationError(
                    "verified_absent requires no records and an absence_proof"
                )
            if self.enumeration_gap is not None:
                raise CatalogValidationError(
                    "verified_absent cannot carry enumeration_gap"
                )
        if status is SourceCellStatus.GAP and self.enumeration_gap is None:
            if not any(
                record.accounting_class is AccountingClass.EXPLICIT_GAP
                for record in records
            ):
                raise CatalogValidationError(
                    "gap manifest requires an enumeration or unit gap"
                )

        if transport_kind is TransportKind.LOCAL:
            if self.remote is not None:
                raise CatalogValidationError(
                    "local manifest cannot carry a remote binding"
                )
        elif not isinstance(self.remote, RemoteTransportBinding):
            raise CatalogValidationError(
                "remote manifest requires a RemoteTransportBinding"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "transport_version": self.transport_version,
            "host_ref": self.host_ref,
            "transport_kind": str(self.transport_kind),
            "source_kind": str(self.source_kind),
            "window": {"start": self.window_start, "end": self.window_end},
            "status": str(self.status),
            "snapshot_commitment": self.snapshot_commitment,
            "absence_proof": self.absence_proof,
            "enumeration_gap": self.enumeration_gap.to_dict()
            if self.enumeration_gap
            else None,
            "remote": self.remote.to_dict() if self.remote else None,
            "total_records": self.total_records,
            "total_bytes": self.total_bytes,
            "records": [record.to_dict() for record in self.records],
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def create(cls, **kwargs: object) -> SourceTransportManifest:
        records = tuple(kwargs.pop("records", ()))
        kwargs["records"] = tuple(sorted(records, key=catalog_record_sort_key))
        return cls(**kwargs)  # type: ignore[arg-type]

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SourceTransportManifest:
        _require_exact_keys(
            value,
            {
                "schema_version",
                "transport_version",
                "host_ref",
                "transport_kind",
                "source_kind",
                "window",
                "status",
                "snapshot_commitment",
                "absence_proof",
                "enumeration_gap",
                "remote",
                "total_records",
                "total_bytes",
                "records",
            },
            "manifest",
        )
        window = value["window"]
        if not isinstance(window, Mapping):
            raise CatalogValidationError("manifest.window must be an object")
        _require_exact_keys(window, {"start", "end"}, "manifest.window")
        records_value = value["records"]
        if not isinstance(records_value, Sequence) or isinstance(
            records_value, (str, bytes)
        ):
            raise CatalogValidationError("manifest.records must be an array")
        records: list[CatalogRecord] = []
        for record in records_value:
            if not isinstance(record, Mapping):
                raise CatalogValidationError("manifest.records entries must be objects")
            records.append(CatalogRecord.from_dict(record))
        gap_value = value["enumeration_gap"]
        remote_value = value["remote"]
        if gap_value is not None and not isinstance(gap_value, Mapping):
            raise CatalogValidationError("manifest.enumeration_gap must be an object")
        if remote_value is not None and not isinstance(remote_value, Mapping):
            raise CatalogValidationError("manifest.remote must be an object")
        total_records = _non_negative_integer(
            value["total_records"], "manifest.total_records"
        )
        total_bytes = _non_negative_integer(
            value["total_bytes"], "manifest.total_bytes"
        )
        return cls(
            schema_version=value["schema_version"],  # type: ignore[arg-type]
            transport_version=value["transport_version"],  # type: ignore[arg-type]
            host_ref=value["host_ref"],  # type: ignore[arg-type]
            transport_kind=value["transport_kind"],  # type: ignore[arg-type]
            source_kind=value["source_kind"],  # type: ignore[arg-type]
            window_start=window["start"],  # type: ignore[arg-type]
            window_end=window["end"],  # type: ignore[arg-type]
            status=value["status"],  # type: ignore[arg-type]
            snapshot_commitment=value["snapshot_commitment"],  # type: ignore[arg-type]
            absence_proof=value["absence_proof"],  # type: ignore[arg-type]
            enumeration_gap=ExplicitGap.from_dict(gap_value)
            if isinstance(gap_value, Mapping)
            else None,
            remote=RemoteTransportBinding.from_dict(remote_value)
            if isinstance(remote_value, Mapping)
            else None,
            total_records=total_records,
            total_bytes=total_bytes,
            records=tuple(records),
        )


TransportSourceManifest = SourceTransportManifest
SessionShardsTransportManifest = SourceTransportManifest


@dataclass(frozen=True)
class SourceCatalog:
    manifests: tuple[SourceTransportManifest, ...]
    schema_version: int = CATALOG_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CATALOG_SCHEMA_VERSION:
            raise CatalogValidationError(
                f"catalog.schema_version must be {CATALOG_SCHEMA_VERSION}"
            )
        manifests = tuple(self.manifests)
        if any(
            not isinstance(manifest, SourceTransportManifest) for manifest in manifests
        ):
            raise CatalogValidationError(
                "catalog.manifests must contain SourceTransportManifest values"
            )
        expected = sorted(
            manifests, key=lambda item: (item.host_ref, str(item.source_kind))
        )
        if list(manifests) != expected:
            raise CatalogValidationError(
                "catalog.manifests must be in deterministic host/source order"
            )
        windows = {
            (manifest.window_start, manifest.window_end) for manifest in manifests
        }
        if len(windows) > 1:
            raise CatalogValidationError(
                "catalog manifests must belong to one retrospective window"
            )
        cells: set[tuple[str, SourceKind]] = set()
        unit_refs: set[str] = set()
        candidates: dict[StableSourceCoordinate, list[CatalogRecord]] = {}
        for manifest in manifests:
            cell = (manifest.host_ref, SourceKind(manifest.source_kind))
            if cell in cells:
                raise CatalogValidationError(
                    "catalog contains a duplicate host/source-kind cell"
                )
            cells.add(cell)
            for record in manifest.records:
                if record.unit_ref in unit_refs:
                    raise CatalogValidationError(
                        f"catalog contains duplicate unit_ref: {record.unit_ref}"
                    )
                unit_refs.add(record.unit_ref)
                if record.accounting_class is AccountingClass.CONSUMED_CANDIDATE:
                    candidates.setdefault(record.coordinate, []).append(record)
        for group in candidates.values():
            rollout_group = [
                record
                for record in group
                if record.source_kind
                in {SourceKind.ACTIVE_ROLLOUT, SourceKind.ARCHIVED_ROLLOUT}
            ]
            if len(rollout_group) > 1:
                raise CatalogValidationError(
                    "rollout copies must be deduplicated before catalog freeze"
                )
        object.__setattr__(self, "manifests", manifests)

    @classmethod
    def create(cls, manifests: Iterable[SourceTransportManifest]) -> SourceCatalog:
        return cls(
            tuple(
                sorted(
                    manifests, key=lambda item: (item.host_ref, str(item.source_kind))
                )
            )
        )

    def validate_required_matrix(self, hosts: Iterable[str]) -> None:
        cells = {
            (manifest.host_ref, str(manifest.source_kind))
            for manifest in self.manifests
        }
        missing = [
            f"{host}/{source_kind}"
            for host in sorted(set(hosts))
            for source_kind in REQUIRED_SOURCE_KINDS
            if (host, source_kind) not in cells
        ]
        if missing:
            raise CatalogValidationError(
                "catalog is missing required cells: " + ", ".join(missing)
            )

    def accounting_counts(self) -> dict[str, int]:
        counts = {item.value: 0 for item in AccountingClass}
        for manifest in self.manifests:
            for record in manifest.records:
                counts[str(record.accounting_class)] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "manifests": [manifest.to_dict() for manifest in self.manifests],
            "accounting_counts": self.accounting_counts(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SourceCatalog:
        _require_exact_keys(
            value,
            {"schema_version", "manifests", "accounting_counts"},
            "catalog",
        )
        if value["schema_version"] != CATALOG_SCHEMA_VERSION:
            raise CatalogValidationError(
                f"catalog.schema_version must be {CATALOG_SCHEMA_VERSION}"
            )
        manifests_value = value["manifests"]
        if not isinstance(manifests_value, Sequence) or isinstance(
            manifests_value, (str, bytes)
        ):
            raise CatalogValidationError("catalog.manifests must be an array")
        manifests: list[SourceTransportManifest] = []
        for manifest in manifests_value:
            if not isinstance(manifest, Mapping):
                raise CatalogValidationError(
                    "catalog.manifests entries must be objects"
                )
            manifests.append(SourceTransportManifest.from_dict(manifest))
        restored = cls(tuple(manifests))
        supplied_counts = value["accounting_counts"]
        if not isinstance(supplied_counts, Mapping):
            raise CatalogValidationError("catalog.accounting_counts must be an object")
        expected_counts = restored.accounting_counts()
        _require_exact_keys(
            supplied_counts,
            expected_counts,
            "catalog.accounting_counts",
        )
        normalized_counts = {
            key: _non_negative_integer(
                supplied_counts[key], f"catalog.accounting_counts.{key}"
            )
            for key in expected_counts
        }
        if normalized_counts != expected_counts:
            raise CatalogValidationError(
                "catalog.accounting_counts does not match its manifests"
            )
        return restored


def snapshot_commitment_for_records(records: Iterable[CatalogRecord]) -> str:
    ordered = sorted(tuple(records), key=catalog_record_sort_key)
    return content_commitment(
        canonical_json_bytes([record.to_dict() for record in ordered])
    )


CatalogClassification = AccountingClass
SourceRecord = CatalogRecord
CatalogGap = ExplicitGap
