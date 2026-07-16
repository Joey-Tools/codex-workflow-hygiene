"""Closed data contracts for authenticated source transport."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, replace
from typing import Any, Mapping, Sequence

try:
    from . import catalog
    from .contracts import (
        JsonValue,
        RefType,
        SourceCellStatus,
        SourceKind,
        canonical_json_bytes,
        parse_typed_ref,
        strict_json_loads,
    )
except (ImportError, ModuleNotFoundError):
    import catalog  # type: ignore[no-redef]
    from contracts import (  # type: ignore[no-redef]
        JsonValue,
        RefType,
        SourceCellStatus,
        SourceKind,
        canonical_json_bytes,
        parse_typed_ref,
        strict_json_loads,
    )

TRANSPORT_LEASE_SCHEMA = "source_transport_lease_v2"
SOURCE_SNAPSHOT_SCHEMA = "authoritative_source_snapshot_v2"
TRANSPORT_RECEIPT_SCHEMA = "source_transport_receipt_v2"
TRANSPORT_LEASE_AUTH_PREFIX = "source_transport_lease_auth_v2:"
SOURCE_SNAPSHOT_REF_PREFIX = "source_snapshot_v2:"
TRANSPORT_RECEIPT_REF_PREFIX = "source_transport_receipt_v2:"
SOURCE_TRANSPORT_STREAM_SCHEMA = "source_transport_stream_v2"
SOURCE_TRANSPORT_RESUME_SCHEMA = "source_transport_resume_v3"
SOURCE_TRANSPORT_MAX_RECORD_BYTES = 8 * 1024 * 1024
SOURCE_TRANSPORT_SCAN_CHUNK_BYTES = 64 * 1024
SOURCE_TRANSPORT_BOUNDARY_PROBE_BYTES = 64 * 1024
SOURCE_TRANSPORT_ACTIVE_LOOKBACK_DAYS = 7
SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST = (
    "catalog.py",
    "contracts.py",
    "safe_io.py",
    "transport_capture.py",
    "transport_contracts.py",
    "transport_paths.py",
    "transport_program.py",
    "transport_remote.py",
    "transport_source.py",
    "transport_worker.py",
)
SOURCE_TRANSPORT_PROGRAM_MODULE_ALLOWLIST = SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_AUTH_RE = re.compile(rf"{re.escape(TRANSPORT_LEASE_AUTH_PREFIX)}[0-9a-f]{{64}}\Z")
_SNAPSHOT_REF_RE = re.compile(
    rf"{re.escape(SOURCE_SNAPSHOT_REF_PREFIX)}[0-9a-f]{{64}}\Z"
)
_RECEIPT_REF_RE = re.compile(
    rf"{re.escape(TRANSPORT_RECEIPT_REF_PREFIX)}[0-9a-f]{{64}}\Z"
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,511}\Z")
_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_LOCATOR_RE = re.compile(r"(?!/)(?!.*(?:^|/)\.\.(?:/|$))[^\x00-\x1f\x7f]{1,1024}\Z")


class TransportValidationError(ValueError):
    """Raised when authenticated source transport evidence is not closed."""


@dataclass(frozen=True, slots=True)
class CapturedSourceRecord:
    source_locator: str
    record_index: int
    byte_start: int
    byte_end: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class SourceTransportCapture:
    records: tuple[CapturedSourceRecord, ...]
    terminal_status: SourceCellStatus
    terminal_reason: str
    inventory_commitment: str
    inventory_count: int
    scan_byte_count: int
    oversized_record_count: int
    oversized_byte_count: int
    terminal_proof_commitment: str
    resume_position: dict[str, JsonValue] | None = None
    inventory: tuple[dict[str, JsonValue], ...] = ()


@dataclass(frozen=True, slots=True)
class _BoundedLine:
    payload: bytes | None
    byte_count: int
    complete: bool
    oversized: bool


def _read_bounded_line(
    handle: Any,
    *,
    max_payload_bytes: int,
    max_scan_bytes: int,
    hasher: Any | None = None,
) -> _BoundedLine:
    """Read at most one line without ever retaining more than the payload cap."""

    retained = bytearray()
    byte_count = 0
    oversized = False
    complete = False
    while byte_count < max_scan_bytes:
        chunk = handle.readline(
            min(SOURCE_TRANSPORT_SCAN_CHUNK_BYTES, max_scan_bytes - byte_count)
        )
        if not chunk:
            break
        if hasher is not None:
            hasher.update(chunk)
        byte_count += len(chunk)
        if not oversized:
            if len(retained) + len(chunk) <= max_payload_bytes:
                retained.extend(chunk)
            else:
                retained.clear()
                oversized = True
        if chunk.endswith(b"\n"):
            complete = True
            break
    return _BoundedLine(
        payload=None if oversized else bytes(retained),
        byte_count=byte_count,
        complete=complete,
        oversized=oversized,
    )


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual == expected:
        return
    missing = ",".join(sorted(expected - actual))
    unknown = ",".join(sorted(actual - expected))
    detail = ";".join(
        part
        for part in (
            f"missing={missing}" if missing else "",
            f"unknown={unknown}" if unknown else "",
        )
        if part
    )
    raise TransportValidationError(
        f"{label} must contain its closed field set ({detail})"
    )


def _bounded_token(value: object, label: str) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise TransportValidationError(f"{label} must be a bounded transport token")
    return value


def _non_negative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TransportValidationError(f"{label} must be a non-negative integer")
    return value


def _positive_int(value: object, label: str) -> int:
    result = _non_negative_int(value, label)
    if result < 1:
        raise TransportValidationError(f"{label} must be a positive integer")
    return result


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise TransportValidationError(
            f"{label} must be sha256:<64 lowercase hexadecimal characters>"
        )
    return value


def _canonical_commitment(value: JsonValue) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _normalize_source_resume_position(
    value: Mapping[str, object] | None,
) -> dict[str, JsonValue] | None:
    if value is None:
        return None
    _exact_keys(
        value,
        {
            "byte_offset",
            "candidate_index",
            "discovery_commitment",
            "frozen_prefix_commitment",
            "record_index",
            "schema",
            "source_locator",
            "source_size",
            "source_token",
        },
        "source transport resume position",
    )
    if value.get("schema") != SOURCE_TRANSPORT_RESUME_SCHEMA:
        raise TransportValidationError("source transport resume schema changed")
    locator = value.get("source_locator")
    if not isinstance(locator, str) or _LOCATOR_RE.fullmatch(locator) is None:
        raise TransportValidationError("source transport resume locator is invalid")
    normalized: dict[str, JsonValue] = {
        "byte_offset": _non_negative_int(
            value.get("byte_offset"),
            "source transport resume byte_offset",
        ),
        "candidate_index": _non_negative_int(
            value.get("candidate_index"),
            "source transport resume candidate_index",
        ),
        "discovery_commitment": _sha256(
            value.get("discovery_commitment"),
            "source transport resume discovery_commitment",
        ),
        "frozen_prefix_commitment": _sha256(
            value.get("frozen_prefix_commitment"),
            "source transport resume frozen_prefix_commitment",
        ),
        "record_index": _non_negative_int(
            value.get("record_index"),
            "source transport resume record_index",
        ),
        "schema": SOURCE_TRANSPORT_RESUME_SCHEMA,
        "source_locator": locator,
        "source_size": _non_negative_int(
            value.get("source_size"),
            "source transport resume source_size",
        ),
        "source_token": _sha256(
            value.get("source_token"),
            "source transport resume source_token",
        ),
    }
    byte_offset = int(normalized["byte_offset"])
    if byte_offset > int(normalized["source_size"]):
        raise TransportValidationError(
            "source transport resume frozen prefix is invalid"
        )
    return normalized


@dataclass(frozen=True, slots=True)
class TransportLease:
    lease_ref: str
    run_ref: str
    job_ref: str
    host: str
    host_ref: str
    source_kind: SourceKind | str
    window_start: str
    window_end: str
    process_nonce: str
    command_argv: tuple[str, ...]
    transport_program_commitment: str
    source_byte_limit: int
    record_limit: int
    frame_byte_limit: int
    session_target: str | None
    session_selector_commitment: str | None
    source_cursor: str | None
    cursor_time: str | None
    resume_position: Mapping[str, object] | None
    authentication_tag: str
    schema: str = TRANSPORT_LEASE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TRANSPORT_LEASE_SCHEMA:
            raise TransportValidationError(
                f"transport lease schema must be {TRANSPORT_LEASE_SCHEMA}"
            )
        for value, kind, label in (
            (self.lease_ref, RefType.LEASE, "lease_ref"),
            (self.run_ref, RefType.RUN, "run_ref"),
            (self.job_ref, RefType.JOB, "job_ref"),
            (self.host_ref, RefType.HOST, "host_ref"),
        ):
            try:
                parse_typed_ref(value, expected=kind)
            except (TypeError, ValueError) as exc:
                raise TransportValidationError(
                    f"transport lease {label} is invalid"
                ) from exc
        if self.session_target is not None:
            try:
                parse_typed_ref(self.session_target, expected=RefType.SESSION)
            except (TypeError, ValueError) as exc:
                raise TransportValidationError(
                    "transport lease session_target is invalid"
                ) from exc
        if (self.session_target is None) != (self.session_selector_commitment is None):
            raise TransportValidationError(
                "transport lease session target and selector commitment must be paired"
            )
        if self.session_selector_commitment is not None:
            _sha256(
                self.session_selector_commitment,
                "transport lease session_selector_commitment",
            )
        if self.source_cursor is not None:
            _bounded_token(self.source_cursor, "transport lease source_cursor")
        if self.cursor_time is not None:
            try:
                cursor_time = catalog.canonical_utc_timestamp(
                    self.cursor_time,
                    "transport lease cursor_time",
                )
            except catalog.CatalogValidationError as exc:
                raise TransportValidationError(
                    "transport lease cursor_time is invalid"
                ) from exc
            object.__setattr__(self, "cursor_time", cursor_time)
        object.__setattr__(
            self,
            "resume_position",
            _normalize_source_resume_position(self.resume_position),
        )
        _bounded_token(self.host, "transport lease host")
        _bounded_token(self.process_nonce, "transport lease process_nonce")
        try:
            source_kind = SourceKind(self.source_kind)
        except (TypeError, ValueError) as exc:
            raise TransportValidationError(
                "transport lease source_kind is invalid"
            ) from exc
        object.__setattr__(self, "source_kind", source_kind)
        argv = tuple(self.command_argv)
        if not argv or len(argv) > 64:
            raise TransportValidationError(
                "transport lease command_argv must contain 1 to 64 arguments"
            )
        for index, argument in enumerate(argv):
            if (
                not isinstance(argument, str)
                or not argument
                or "\x00" in argument
                or len(argument.encode("utf-8")) > 4096
            ):
                raise TransportValidationError(
                    f"transport lease command_argv[{index}] is invalid"
                )
        object.__setattr__(self, "command_argv", argv)
        _sha256(
            self.transport_program_commitment,
            "transport lease transport_program_commitment",
        )
        _positive_int(self.source_byte_limit, "transport lease source_byte_limit")
        _positive_int(self.record_limit, "transport lease record_limit")
        _positive_int(self.frame_byte_limit, "transport lease frame_byte_limit")
        if not isinstance(self.window_start, str) or not isinstance(
            self.window_end, str
        ):
            raise TransportValidationError("transport lease window is invalid")
        if _AUTH_RE.fullmatch(self.authentication_tag) is None:
            raise TransportValidationError(
                "transport lease authentication_tag is invalid"
            )

    def unsigned_dict(self) -> dict[str, JsonValue]:
        return {
            "command_argv": list(self.command_argv),
            "frame_byte_limit": self.frame_byte_limit,
            "host": self.host,
            "host_ref": self.host_ref,
            "job_ref": self.job_ref,
            "lease_ref": self.lease_ref,
            "process_nonce": self.process_nonce,
            "record_limit": self.record_limit,
            "resume_position": self.resume_position,
            "run_ref": self.run_ref,
            "schema": self.schema,
            "session_target": self.session_target,
            "session_selector_commitment": self.session_selector_commitment,
            "source_cursor": self.source_cursor,
            "cursor_time": self.cursor_time,
            "source_byte_limit": self.source_byte_limit,
            "source_kind": self.source_kind.value,
            "transport_program_commitment": self.transport_program_commitment,
            "window": {"end": self.window_end, "start": self.window_start},
        }

    @property
    def binding(self) -> str:
        return _canonical_commitment(self.unsigned_dict())

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            **self.unsigned_dict(),
            "authentication_tag": self.authentication_tag,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "TransportLease":
        _exact_keys(
            value,
            {
                "authentication_tag",
                "command_argv",
                "frame_byte_limit",
                "host",
                "host_ref",
                "job_ref",
                "lease_ref",
                "process_nonce",
                "record_limit",
                "resume_position",
                "run_ref",
                "schema",
                "session_target",
                "session_selector_commitment",
                "source_cursor",
                "cursor_time",
                "source_byte_limit",
                "source_kind",
                "transport_program_commitment",
                "window",
            },
            "transport lease",
        )
        window = value["window"]
        if not isinstance(window, Mapping):
            raise TransportValidationError("transport lease window must be an object")
        _exact_keys(window, {"end", "start"}, "transport lease window")
        argv = value["command_argv"]
        if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
            raise TransportValidationError(
                "transport lease command_argv must be an array"
            )
        return cls(
            authentication_tag=value["authentication_tag"],  # type: ignore[arg-type]
            command_argv=tuple(argv),  # type: ignore[arg-type]
            frame_byte_limit=value["frame_byte_limit"],  # type: ignore[arg-type]
            host=value["host"],  # type: ignore[arg-type]
            host_ref=value["host_ref"],  # type: ignore[arg-type]
            job_ref=value["job_ref"],  # type: ignore[arg-type]
            lease_ref=value["lease_ref"],  # type: ignore[arg-type]
            process_nonce=value["process_nonce"],  # type: ignore[arg-type]
            record_limit=value["record_limit"],  # type: ignore[arg-type]
            resume_position=value["resume_position"],  # type: ignore[arg-type]
            run_ref=value["run_ref"],  # type: ignore[arg-type]
            schema=value["schema"],  # type: ignore[arg-type]
            session_target=value["session_target"],  # type: ignore[arg-type]
            session_selector_commitment=value["session_selector_commitment"],  # type: ignore[arg-type]
            source_cursor=value["source_cursor"],  # type: ignore[arg-type]
            cursor_time=value["cursor_time"],  # type: ignore[arg-type]
            source_byte_limit=value["source_byte_limit"],  # type: ignore[arg-type]
            source_kind=value["source_kind"],  # type: ignore[arg-type]
            transport_program_commitment=value["transport_program_commitment"],  # type: ignore[arg-type]
            window_start=window["start"],  # type: ignore[arg-type]
            window_end=window["end"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class AuthoritativeSourceSnapshot:
    snapshot_ref: str
    host_ref: str
    source_kind: SourceKind | str
    window_start: str
    window_end: str
    session_target: str | None
    source_content_commitment: str
    source_byte_count: int
    terminal_byte_offset: int
    catalog_record_count: int
    catalog_byte_count: int
    catalog_commitment: str | None
    transcript_commitment: str
    terminal_proof_commitment: str
    terminal_status: SourceCellStatus | str
    terminal_reason: str
    complete: bool
    resume_position: Mapping[str, object] | None
    schema: str = SOURCE_SNAPSHOT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SOURCE_SNAPSHOT_SCHEMA:
            raise TransportValidationError(
                f"source snapshot schema must be {SOURCE_SNAPSHOT_SCHEMA}"
            )
        if _SNAPSHOT_REF_RE.fullmatch(self.snapshot_ref) is None:
            raise TransportValidationError("source snapshot ref is invalid")
        try:
            parse_typed_ref(self.host_ref, expected=RefType.HOST)
        except (TypeError, ValueError) as exc:
            raise TransportValidationError(
                "source snapshot host_ref is invalid"
            ) from exc
        if self.session_target is not None:
            try:
                parse_typed_ref(self.session_target, expected=RefType.SESSION)
            except (TypeError, ValueError) as exc:
                raise TransportValidationError(
                    "source snapshot session_target is invalid"
                ) from exc
        try:
            source_kind = SourceKind(self.source_kind)
            terminal_status = SourceCellStatus(self.terminal_status)
        except (TypeError, ValueError) as exc:
            raise TransportValidationError(
                "source snapshot enum value is invalid"
            ) from exc
        object.__setattr__(self, "source_kind", source_kind)
        object.__setattr__(self, "terminal_status", terminal_status)
        _sha256(
            self.source_content_commitment,
            "source snapshot source_content_commitment",
        )
        _sha256(self.transcript_commitment, "source snapshot transcript_commitment")
        _sha256(
            self.terminal_proof_commitment,
            "source snapshot terminal_proof_commitment",
        )
        if self.catalog_commitment is not None:
            _sha256(self.catalog_commitment, "source snapshot catalog_commitment")
        for value, label in (
            (self.source_byte_count, "source_byte_count"),
            (self.terminal_byte_offset, "terminal_byte_offset"),
            (self.catalog_record_count, "catalog_record_count"),
            (self.catalog_byte_count, "catalog_byte_count"),
        ):
            _non_negative_int(value, f"source snapshot {label}")
        if not isinstance(self.complete, bool):
            raise TransportValidationError("source snapshot complete must be boolean")
        if _REASON_RE.fullmatch(self.terminal_reason) is None:
            raise TransportValidationError(
                "source snapshot terminal_reason must be a reason code"
            )
        normalized_resume = _normalize_source_resume_position(self.resume_position)
        object.__setattr__(self, "resume_position", normalized_resume)
        terminal = terminal_status in {
            SourceCellStatus.COMPLETE,
            SourceCellStatus.NO_ACTIVITY,
            SourceCellStatus.VERIFIED_ABSENT,
        }
        if self.complete != terminal:
            raise TransportValidationError(
                "source snapshot completeness does not match terminal status"
            )
        continuation_reason = self.terminal_reason in {
            "source_byte_limit_reached",
            "source_record_limit_reached",
        }
        if (normalized_resume is None) != (not continuation_reason):
            raise TransportValidationError(
                "source snapshot continuation reason and resume position must be paired"
            )
        if (
            normalized_resume is not None
            and terminal_status is not SourceCellStatus.GAP
        ):
            raise TransportValidationError(
                "source snapshot continuation must use an incomplete gap status"
            )
        if self.complete and self.terminal_byte_offset != self.source_byte_count:
            raise TransportValidationError(
                "complete source snapshot must prove the authoritative terminal offset"
            )
        if terminal_status is SourceCellStatus.COMPLETE:
            if self.catalog_record_count < 1 or self.catalog_commitment is None:
                raise TransportValidationError(
                    "complete source snapshot requires catalog records and commitment"
                )
        if terminal_status is SourceCellStatus.NO_ACTIVITY:
            if (
                self.catalog_record_count != 0
                or self.catalog_byte_count != 0
                or self.catalog_commitment is None
            ):
                raise TransportValidationError(
                    "no-activity source snapshot must prove an empty catalog"
                )
        if terminal_status is SourceCellStatus.VERIFIED_ABSENT:
            if self.source_byte_count != 0 or self.catalog_record_count != 0:
                raise TransportValidationError(
                    "verified-absent snapshot must prove an absent empty source"
                )

    def unsigned_dict(self) -> dict[str, JsonValue]:
        return {
            "catalog_byte_count": self.catalog_byte_count,
            "catalog_commitment": self.catalog_commitment,
            "catalog_record_count": self.catalog_record_count,
            "complete": self.complete,
            "host_ref": self.host_ref,
            "resume_position": self.resume_position,
            "schema": self.schema,
            "session_target": self.session_target,
            "source_byte_count": self.source_byte_count,
            "source_content_commitment": self.source_content_commitment,
            "source_kind": self.source_kind.value,
            "terminal_byte_offset": self.terminal_byte_offset,
            "terminal_reason": self.terminal_reason,
            "terminal_status": self.terminal_status.value,
            "terminal_proof_commitment": self.terminal_proof_commitment,
            "transcript_commitment": self.transcript_commitment,
            "window": {"end": self.window_end, "start": self.window_start},
        }

    def to_dict(self) -> dict[str, JsonValue]:
        return {**self.unsigned_dict(), "snapshot_ref": self.snapshot_ref}

    @classmethod
    def create(cls, **kwargs: Any) -> "AuthoritativeSourceSnapshot":
        placeholder = SOURCE_SNAPSHOT_REF_PREFIX + "0" * 64
        snapshot = cls(snapshot_ref=placeholder, **kwargs)
        digest = hashlib.sha256(
            canonical_json_bytes(snapshot.unsigned_dict())
        ).hexdigest()
        return replace(snapshot, snapshot_ref=SOURCE_SNAPSHOT_REF_PREFIX + digest)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "AuthoritativeSourceSnapshot":
        _exact_keys(
            value,
            {
                "catalog_byte_count",
                "catalog_commitment",
                "catalog_record_count",
                "complete",
                "host_ref",
                "resume_position",
                "schema",
                "session_target",
                "snapshot_ref",
                "source_byte_count",
                "source_content_commitment",
                "source_kind",
                "terminal_byte_offset",
                "terminal_reason",
                "terminal_status",
                "terminal_proof_commitment",
                "transcript_commitment",
                "window",
            },
            "source snapshot",
        )
        window = value["window"]
        if not isinstance(window, Mapping):
            raise TransportValidationError("source snapshot window must be an object")
        _exact_keys(window, {"end", "start"}, "source snapshot window")
        snapshot = cls(
            snapshot_ref=value["snapshot_ref"],  # type: ignore[arg-type]
            host_ref=value["host_ref"],  # type: ignore[arg-type]
            resume_position=value["resume_position"],  # type: ignore[arg-type]
            source_kind=value["source_kind"],  # type: ignore[arg-type]
            window_start=window["start"],  # type: ignore[arg-type]
            window_end=window["end"],  # type: ignore[arg-type]
            session_target=value["session_target"],  # type: ignore[arg-type]
            source_content_commitment=value["source_content_commitment"],  # type: ignore[arg-type]
            source_byte_count=value["source_byte_count"],  # type: ignore[arg-type]
            terminal_byte_offset=value["terminal_byte_offset"],  # type: ignore[arg-type]
            catalog_record_count=value["catalog_record_count"],  # type: ignore[arg-type]
            catalog_byte_count=value["catalog_byte_count"],  # type: ignore[arg-type]
            catalog_commitment=value["catalog_commitment"],  # type: ignore[arg-type]
            transcript_commitment=value["transcript_commitment"],  # type: ignore[arg-type]
            terminal_proof_commitment=value["terminal_proof_commitment"],  # type: ignore[arg-type]
            terminal_status=value["terminal_status"],  # type: ignore[arg-type]
            terminal_reason=value["terminal_reason"],  # type: ignore[arg-type]
            complete=value["complete"],  # type: ignore[arg-type]
            schema=value["schema"],  # type: ignore[arg-type]
        )
        expected_ref = (
            SOURCE_SNAPSHOT_REF_PREFIX
            + hashlib.sha256(canonical_json_bytes(snapshot.unsigned_dict())).hexdigest()
        )
        if not hmac.compare_digest(expected_ref, snapshot.snapshot_ref):
            raise TransportValidationError(
                "source snapshot ref does not commit its body"
            )
        return snapshot


@dataclass(frozen=True, slots=True)
class TransportReceipt:
    receipt_ref: str
    lease_ref: str
    lease_authentication_tag: str
    lease_binding: str
    manifest_commitment: str
    source_snapshot: AuthoritativeSourceSnapshot
    schema: str = TRANSPORT_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TRANSPORT_RECEIPT_SCHEMA:
            raise TransportValidationError(
                f"transport receipt schema must be {TRANSPORT_RECEIPT_SCHEMA}"
            )
        if _RECEIPT_REF_RE.fullmatch(self.receipt_ref) is None:
            raise TransportValidationError("transport receipt ref is invalid")
        try:
            parse_typed_ref(self.lease_ref, expected=RefType.LEASE)
        except (TypeError, ValueError) as exc:
            raise TransportValidationError(
                "transport receipt lease_ref is invalid"
            ) from exc
        if _AUTH_RE.fullmatch(self.lease_authentication_tag) is None:
            raise TransportValidationError(
                "transport receipt lease authentication is invalid"
            )
        _sha256(self.lease_binding, "transport receipt lease_binding")
        _sha256(self.manifest_commitment, "transport receipt manifest_commitment")
        if not isinstance(self.source_snapshot, AuthoritativeSourceSnapshot):
            raise TransportValidationError(
                "transport receipt source_snapshot is invalid"
            )

    def unsigned_dict(self) -> dict[str, JsonValue]:
        return {
            "lease_authentication_tag": self.lease_authentication_tag,
            "lease_binding": self.lease_binding,
            "lease_ref": self.lease_ref,
            "manifest_commitment": self.manifest_commitment,
            "schema": self.schema,
            "source_snapshot": self.source_snapshot.to_dict(),
        }

    def to_dict(self) -> dict[str, JsonValue]:
        return {**self.unsigned_dict(), "receipt_ref": self.receipt_ref}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "TransportReceipt":
        _exact_keys(
            value,
            {
                "lease_authentication_tag",
                "lease_binding",
                "lease_ref",
                "manifest_commitment",
                "receipt_ref",
                "schema",
                "source_snapshot",
            },
            "transport receipt",
        )
        snapshot = value["source_snapshot"]
        if not isinstance(snapshot, Mapping):
            raise TransportValidationError(
                "transport receipt source_snapshot must be an object"
            )
        return cls(
            receipt_ref=value["receipt_ref"],  # type: ignore[arg-type]
            lease_ref=value["lease_ref"],  # type: ignore[arg-type]
            lease_authentication_tag=value["lease_authentication_tag"],  # type: ignore[arg-type]
            lease_binding=value["lease_binding"],  # type: ignore[arg-type]
            manifest_commitment=value["manifest_commitment"],  # type: ignore[arg-type]
            source_snapshot=AuthoritativeSourceSnapshot.from_dict(snapshot),
            schema=value["schema"],  # type: ignore[arg-type]
        )


def transcript_commitment(
    raw_records: Mapping[str, bytes], *, source_marker: str
) -> str:
    rows: list[JsonValue] = []
    for unit_ref, payload in sorted(raw_records.items()):
        rows.append(
            {
                "byte_count": len(payload),
                "content_commitment": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "unit_ref": unit_ref,
            }
        )
    return _canonical_commitment(
        {
            "records": rows,
            "schema": "source_transport_transcript_v2",
            "source": source_marker,
        }
    )


def _stream_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise TransportValidationError(
                "source transport frame contains duplicate keys"
            )
        value[key] = item
    return value


def _reject_stream_constant(_: str) -> None:
    raise TransportValidationError("source transport frame contains non-finite JSON")


def _stream_frame(value: bytes | str) -> Mapping[str, object]:
    try:
        decoded = strict_json_loads(value)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TransportValidationError(
            "source transport frame is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(decoded, Mapping):
        raise TransportValidationError("source transport frame must be an object")
    return decoded


def _source_transport_inventory_commitment(
    inventory: Sequence[Mapping[str, Any]],
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(
                {
                    "inventory": [dict(item) for item in inventory],
                    "schema": "source_transport_inventory_v2",
                }
            )
        ).hexdigest()
    )
