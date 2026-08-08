from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import hmac
import json
import math
from pathlib import PurePosixPath
import re
from typing import Mapping, Sequence, TypeAlias


JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

SHA256_HEX_LENGTH = 64
CHECKPOINT_FORMAT_VERSION = 2
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTENT_COMMITMENT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")

RAW_RECORD_FILE_SET_SCHEMA = "raw_record_file_set_v2"
AGENT_FAILURE_SCHEMA = "agent_failure_v2"
SESSION_SHARDS_SCHEMA = "session-shards-v1"
SESSION_SHARDS_SOURCE_TOKEN_PREFIX = "session_shards_source_v2:"
SESSION_SHARDS_RESUME_CURSOR_PREFIX = "session_shards_resume_v1:"
SESSION_SHARDS_REQUEST_BINDING_PREFIX = "session_shards_request_v1:"
SESSION_SHARDS_RESUME_SIGNATURE_DOMAIN = b"session-shards-resume-signature-v1\0"
SESSION_SHARDS_PREFIX_COMMITMENT_DOMAIN = b"session-shards-prefix-commitment-v1\0"
SESSION_SHARDS_CURSOR_KINDS = frozenset({"descriptor_continue", "records"})
SESSION_SHARDS_EMPTY_PREFIX_COMMITMENT = (
    "sha256:"
    + hashlib.sha256(SESSION_SHARDS_PREFIX_COMMITMENT_DOMAIN + b"bytes\0").hexdigest()
)
MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES = 4 * 1024 * 1024
MAX_SESSION_RECORD_PROCESSING_BUDGET_BYTES = 256 * 1024 * 1024
MAX_SESSION_SHARD_BYTES = 512 * 1024
MAX_SESSION_SHARDS_PER_PAGE = 1024
MAX_JSON_INTEGER = (1 << 63) - 1


class StrictJsonError(ValueError):
    pass


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("duplicate JSON object key")
        result[key] = value
    return result


def _strict_json_int(token: str) -> int:
    if len(token) > 20:
        raise StrictJsonError("JSON integer exceeds the signed 64-bit model")
    try:
        value = int(token)
    except ValueError as exc:
        raise StrictJsonError("JSON integer is malformed") from exc
    if abs(value) > MAX_JSON_INTEGER:
        raise StrictJsonError("JSON integer exceeds the signed 64-bit model")
    return value


def _strict_json_float(token: str) -> float:
    try:
        value = float(token)
    except (OverflowError, ValueError) as exc:
        raise StrictJsonError("JSON float is malformed") from exc
    if not math.isfinite(value):
        raise StrictJsonError("JSON float is not finite")
    return value


def _strict_json_constant(_token: str) -> None:
    raise StrictJsonError("JSON constant is not finite")


def strict_json_loads(value: bytes | str) -> object:
    try:
        text = value.decode("utf-8") if isinstance(value, bytes) else value
        return json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_strict_json_constant,
            parse_float=_strict_json_float,
            parse_int=_strict_json_int,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise StrictJsonError("invalid strict UTF-8 JSON") from exc


def _validate_json_value(value: object, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_JSON_INTEGER:
            raise ValueError(f"integer at {path} exceeds the signed 64-bit model")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"float at {path} is not finite")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"canonical JSON object key at {path} is not a string")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise TypeError(f"value at {path} is not canonical JSON data")


def canonical_json(value: JsonValue) -> str:
    """Serialize a JSON value with one deterministic UTF-8 representation."""

    _validate_json_value(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_json_bytes(value: JsonValue) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(data: bytes | bytearray | memoryview) -> str:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sha256 input must be bytes-like")
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: JsonValue) -> str:
    return sha256_hex(canonical_json_bytes(value))


canonical_hash = canonical_sha256
hash_json = canonical_sha256
canonical_json_dumps = canonical_json
sha256_json = canonical_sha256


class RunMode(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    BASELINE = "baseline"
    SESSION = "session"


class RunStage(StrEnum):
    SOURCE_CATALOG = "source_catalog"
    SHARDING = "sharding"
    EXTRACTION = "extraction"
    EPISODE_REVIEW = "episode_review"
    TOPIC_REDUCTION = "topic_reduction"
    GLOBAL_SYNTHESIS = "global_synthesis"
    EXPORT = "export"
    FINALIZE = "finalize"
    COMPLETE = "complete"
    BLOCKED = "blocked"

    CATALOG = SOURCE_CATALOG
    EXTRACT = EXTRACTION
    TOPIC_REDUCE = TOPIC_REDUCTION
    SYNTHESIS = GLOBAL_SYNTHESIS


class JobKind(StrEnum):
    EXTRACTOR_REDACTOR = "extractor_redactor"
    EVIDENCE_VERIFIER = "evidence_verifier"
    BOUNDARY_VERIFIER = "boundary_verifier"
    RECORD_REDUCER = "record_reducer"
    EPISODE_REVIEWER = "episode_reviewer"
    INDEPENDENT_RISK_REVIEWER = "independent_risk_reviewer"
    ADJUDICATOR = "adjudicator"
    TOPIC_REDUCER = "topic_reducer"
    GLOBAL_SYNTHESIS = "global_synthesis"

    EXTRACTOR = EXTRACTOR_REDACTOR
    EPISODE_REVIEW = EPISODE_REVIEWER
    TOPIC_REDUCTION = TOPIC_REDUCER


class AgentFailureKind(StrEnum):
    CRASH = "crash"
    TIMEOUT = "timeout"


class SourceKind(StrEnum):
    SESSION_INDEX = "session_index"
    HISTORY = "history"
    ACTIVE_ROLLOUT = "active_rollout"
    ARCHIVED_ROLLOUT = "archived_rollout"
    CALIBRATION_CORPUS = "calibration_corpus"


class SourceCellStatus(StrEnum):
    COMPLETE = "complete"
    NO_ACTIVITY = "no_activity"
    VERIFIED_ABSENT = "verified_absent"
    GAP = "gap"


class ControlledGapReason(StrEnum):
    MISSING_HOST_HOLDOUT = "missing_host_holdout"
    SHADOW_MISSING_HOST_HOLDOUT = "shadow_missing_host_holdout"


class RefType(StrEnum):
    HOST = "host_ref_v2"
    SOURCE = "source_ref_v2"
    SOURCE_UNIT = "source_unit_ref_v2"
    SESSION = "session_ref_v2"
    TURN = "turn_ref_v2"
    EPISODE = "episode_ref_v2"
    EPISODE_REVISION = "episode_revision_ref_v2"
    EPISODE_HEAD_SET = "episode_head_set_ref_v2"
    WORKSTREAM = "workstream_ref_v2"
    GOAL = "goal_ref_v2"
    TOPIC = "topic_ref_v2"
    TOPIC_CANDIDATE = "topic_candidate_ref_v2"
    JOB = "job_ref_v2"
    RUN_INPUT = "run_input_ref_v2"
    RUN = "run_ref_v2"
    ATTEMPT = "attempt_ref_v2"
    CLAIM = "claim_ref_v2"
    RESULT = "result_ref_v2"
    LEASE = "lease_ref_v2"
    REVIEWER = "reviewer_ref_v2"
    EVIDENCE = "evidence_ref_v2"
    SPAN_COMMITMENT = "span_commitment_ref_v2"
    MODEL_CONFIGURATION = "model_configuration_ref_v2"
    CONFIGURATION = "configuration_ref_v2"


RefKind = RefType
Mode = RunMode
Stage = RunStage


def validate_sha256_hex(value: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError("expected exactly 64 lowercase hexadecimal characters")
    return value


@dataclass(frozen=True, slots=True)
class TypedRef:
    kind: RefType
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RefType):
            try:
                kind = RefType(self.kind)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"unknown reference type: {self.kind!r}") from exc
            object.__setattr__(self, "kind", kind)
        validate_sha256_hex(self.digest)

    @property
    def ref_type(self) -> RefType:
        return self.kind

    @property
    def value(self) -> str:
        return self.digest

    @property
    def hex(self) -> str:
        return self.digest

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.digest}"

    def as_string(self) -> str:
        return str(self)

    @classmethod
    def parse(cls, value: str) -> "TypedRef":
        if not isinstance(value, str):
            raise TypeError("reference must be a string")
        prefix, separator, digest = value.partition(":")
        if not separator or ":" in digest:
            raise ValueError("reference must have the form <type>:<64 lowercase hex>")
        try:
            kind = RefType(prefix)
        except ValueError as exc:
            raise ValueError(f"unknown reference type: {prefix!r}") from exc
        return cls(kind=kind, digest=digest)

    from_string = parse


Ref256 = TypedRef
OpaqueRef = TypedRef


def _require_exact_keys(
    value: Mapping[str, object],
    expected: set[str],
    *,
    label: str,
) -> None:
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
    raise ValueError(f"{label} must contain its closed field set ({detail})")


@dataclass(frozen=True, slots=True)
class RawRecordFile:
    unit_ref: str
    path: str
    byte_count: int
    content_commitment: str

    def __post_init__(self) -> None:
        parse_typed_ref(self.unit_ref, expected=RefType.SOURCE_UNIT)
        if (
            not isinstance(self.path, str)
            or not self.path
            or "\x00" in self.path
            or len(self.path.encode("utf-8")) > 4096
        ):
            raise ValueError("raw record path must be a bounded non-empty path")
        if (
            not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 0
        ):
            raise ValueError("raw record byte_count must be a non-negative integer")
        if (
            not isinstance(self.content_commitment, str)
            or _CONTENT_COMMITMENT_RE.fullmatch(self.content_commitment) is None
        ):
            raise ValueError(
                "raw record content_commitment must be sha256:<64 lowercase hex>"
            )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "byte_count": self.byte_count,
            "content_commitment": self.content_commitment,
            "path": self.path,
            "unit_ref": self.unit_ref,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RawRecordFile":
        _require_exact_keys(
            value,
            {"byte_count", "content_commitment", "path", "unit_ref"},
            label="raw record file",
        )
        return cls(
            unit_ref=value["unit_ref"],  # type: ignore[arg-type]
            path=value["path"],  # type: ignore[arg-type]
            byte_count=value["byte_count"],  # type: ignore[arg-type]
            content_commitment=value["content_commitment"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class RawRecordFileSet:
    records: tuple[RawRecordFile, ...]
    schema: str = RAW_RECORD_FILE_SET_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != RAW_RECORD_FILE_SET_SCHEMA:
            raise ValueError(
                f"raw record file set schema must be {RAW_RECORD_FILE_SET_SCHEMA}"
            )
        records = tuple(self.records)
        if any(not isinstance(item, RawRecordFile) for item in records):
            raise TypeError("raw record file set must contain RawRecordFile values")
        refs = [item.unit_ref for item in records]
        if len(refs) != len(set(refs)):
            raise ValueError("raw record file set contains a duplicate unit_ref")
        if list(records) != sorted(records, key=lambda item: item.unit_ref):
            raise ValueError("raw record files must be sorted by unit_ref")
        object.__setattr__(self, "records", records)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "records": [item.to_dict() for item in self.records],
            "schema": self.schema,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RawRecordFileSet":
        _require_exact_keys(value, {"records", "schema"}, label="raw record file set")
        records_value = value["records"]
        if not isinstance(records_value, Sequence) or isinstance(
            records_value, (str, bytes)
        ):
            raise ValueError("raw record file set records must be an array")
        records: list[RawRecordFile] = []
        for item in records_value:
            if not isinstance(item, Mapping):
                raise ValueError("raw record file entries must be objects")
            records.append(RawRecordFile.from_dict(item))
        return cls(
            schema=value["schema"],  # type: ignore[arg-type]
            records=tuple(records),
        )


@dataclass(frozen=True, slots=True)
class AgentFailure:
    failure_kind: AgentFailureKind
    schema: str = AGENT_FAILURE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != AGENT_FAILURE_SCHEMA:
            raise ValueError(f"agent failure schema must be {AGENT_FAILURE_SCHEMA}")
        if not isinstance(self.failure_kind, AgentFailureKind):
            try:
                failure_kind = AgentFailureKind(self.failure_kind)
            except (TypeError, ValueError) as exc:
                raise ValueError("agent failure_kind is not closed") from exc
            object.__setattr__(self, "failure_kind", failure_kind)

    def to_dict(self) -> dict[str, JsonValue]:
        return {"failure_kind": self.failure_kind.value, "schema": self.schema}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "AgentFailure":
        _require_exact_keys(value, {"failure_kind", "schema"}, label="agent failure")
        return cls(
            schema=value["schema"],  # type: ignore[arg-type]
            failure_kind=value["failure_kind"],  # type: ignore[arg-type]
        )


def _session_shards_source_token(value: object) -> str:
    token_pattern = re.escape(SESSION_SHARDS_SOURCE_TOKEN_PREFIX) + r"[0-9a-f]{64}\Z"
    if not isinstance(value, str) or re.fullmatch(token_pattern, value) is None:
        raise ValueError("session-shards source token is invalid")
    return value


def _session_shards_prefix_commitment(value: object) -> str:
    if not isinstance(value, str) or _CONTENT_COMMITMENT_RE.fullmatch(value) is None:
        raise ValueError("session-shards prefix commitment is invalid")
    return value


def _session_shards_resume_signature(source_token: str, payload: bytes) -> str:
    token = _session_shards_source_token(source_token)
    key = hashlib.sha256(
        SESSION_SHARDS_RESUME_SIGNATURE_DOMAIN + token.encode("ascii")
    ).digest()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def session_shards_resume_cursor(
    source_token: str,
    *,
    cursor_kind: str,
    frozen_byte_end: int,
    byte_offset: int,
    next_record_index: int,
    prefix_commitment: str,
) -> str:
    """Build one canonical cursor bound to a frozen source prefix."""

    token = _session_shards_source_token(source_token)
    if cursor_kind not in SESSION_SHARDS_CURSOR_KINDS:
        raise ValueError("session-shards cursor kind is not closed")
    for value, label in (
        (frozen_byte_end, "frozen_byte_end"),
        (byte_offset, "byte_offset"),
        (next_record_index, "next_record_index"),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= MAX_JSON_INTEGER
        ):
            raise ValueError(f"session-shards {label} must be non-negative")
    if byte_offset > frozen_byte_end:
        raise ValueError("session-shards cursor exceeds its frozen byte end")
    commitment = _session_shards_prefix_commitment(prefix_commitment)
    payload = canonical_json_bytes(
        {
            "byte_offset": byte_offset,
            "cursor_kind": cursor_kind,
            "frozen_byte_end": frozen_byte_end,
            "next_record_index": next_record_index,
            "prefix_commitment": commitment,
            "source_token": token,
        }
    )
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = _session_shards_resume_signature(token, payload)
    return SESSION_SHARDS_RESUME_CURSOR_PREFIX + encoded_payload + "." + signature


def session_shards_resume_cursor_value(cursor: object) -> dict[str, JsonValue]:
    """Parse and authenticate one closed canonical session-shards cursor."""

    if not isinstance(cursor, str) or not cursor.startswith(
        SESSION_SHARDS_RESUME_CURSOR_PREFIX
    ):
        raise ValueError("session-shards resume cursor is invalid")
    encoded = cursor.removeprefix(SESSION_SHARDS_RESUME_CURSOR_PREFIX)
    if len(encoded) > 4096 or encoded.count(".") != 1:
        raise ValueError("session-shards resume cursor is invalid")
    payload_text, signature = encoded.split(".", 1)
    try:
        payload = base64.b64decode(
            payload_text + "=" * (-len(payload_text) % 4),
            altchars=b"-_",
            validate=True,
        )
        value = strict_json_loads(payload)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("session-shards resume cursor is invalid") from exc
    expected_fields = {
        "byte_offset",
        "cursor_kind",
        "frozen_byte_end",
        "next_record_index",
        "prefix_commitment",
        "source_token",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or canonical_json_bytes(value) != payload
        or base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=") != payload_text
        or _SHA256_RE.fullmatch(signature) is None
    ):
        raise ValueError("session-shards resume cursor is invalid")
    source_token = _session_shards_source_token(value["source_token"])
    cursor_kind = value["cursor_kind"]
    frozen_byte_end = value["frozen_byte_end"]
    byte_offset = value["byte_offset"]
    next_record_index = value["next_record_index"]
    prefix_commitment = _session_shards_prefix_commitment(value["prefix_commitment"])
    if (
        not isinstance(cursor_kind, str)
        or cursor_kind not in SESSION_SHARDS_CURSOR_KINDS
    ):
        raise ValueError("session-shards cursor kind is not closed")
    for coordinate in (frozen_byte_end, byte_offset, next_record_index):
        if (
            isinstance(coordinate, bool)
            or not isinstance(coordinate, int)
            or not 0 <= coordinate <= MAX_JSON_INTEGER
        ):
            raise ValueError("session-shards resume cursor is invalid")
    if byte_offset > frozen_byte_end:
        raise ValueError("session-shards resume cursor exceeds its frozen byte end")
    expected_signature = _session_shards_resume_signature(source_token, payload)
    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("session-shards resume cursor signature is invalid")
    return {
        "byte_offset": byte_offset,
        "cursor_kind": cursor_kind,
        "frozen_byte_end": frozen_byte_end,
        "next_record_index": next_record_index,
        "prefix_commitment": prefix_commitment,
        "source_token": source_token,
    }


@dataclass(frozen=True, slots=True)
class SessionShardsRequest:
    rollout: str
    mode: str
    source_token: str | None
    byte_start: int
    byte_end: int | None
    shard_bytes: int
    max_shards: int
    record_processing_budget_bytes: int
    resume_cursor: str | None

    @staticmethod
    def _resume_coordinates(cursor: str) -> tuple[str, int, int]:
        value = session_shards_resume_cursor_value(cursor)
        return (
            str(value["source_token"]),
            int(value["byte_offset"]),
            int(value["next_record_index"]),
        )

    def __post_init__(self) -> None:
        path = PurePosixPath(self.rollout)
        if (
            not self.rollout
            or path.is_absolute()
            or str(path) != self.rollout
            or any(part in {"", ".", ".."} for part in path.parts)
            or "\\" in self.rollout
        ):
            raise ValueError(
                "session-shards rollout must be a normalized relative path"
            )
        if self.mode not in {"descriptors", "records"}:
            raise ValueError("session-shards mode is not closed")
        if (
            isinstance(self.byte_start, bool)
            or not isinstance(self.byte_start, int)
            or self.byte_start < 0
        ):
            raise ValueError("session-shards byte_start must be non-negative")
        if self.byte_end is not None and (
            isinstance(self.byte_end, bool)
            or not isinstance(self.byte_end, int)
            or self.byte_end <= self.byte_start
        ):
            raise ValueError("session-shards byte_end must be greater than byte_start")
        if (
            isinstance(self.shard_bytes, bool)
            or not isinstance(self.shard_bytes, int)
            or not 1 <= self.shard_bytes <= MAX_SESSION_SHARD_BYTES
        ):
            raise ValueError("session-shards shard_bytes is outside protocol bounds")
        if (
            isinstance(self.max_shards, bool)
            or not isinstance(self.max_shards, int)
            or not 1 <= self.max_shards <= MAX_SESSION_SHARDS_PER_PAGE
        ):
            raise ValueError("session-shards max_shards is outside protocol bounds")
        if (
            isinstance(self.record_processing_budget_bytes, bool)
            or not isinstance(self.record_processing_budget_bytes, int)
            or self.record_processing_budget_bytes
            < max(self.shard_bytes, MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES)
            or self.record_processing_budget_bytes
            > MAX_SESSION_RECORD_PROCESSING_BUDGET_BYTES
        ):
            raise ValueError(
                "session-shards record processing budget is outside protocol bounds"
            )
        if self.source_token is not None:
            _session_shards_source_token(self.source_token)
        resume_value: dict[str, JsonValue] | None = None
        if self.resume_cursor is not None:
            if not isinstance(self.resume_cursor, str):
                raise ValueError("session-shards resume cursor is invalid")
            resume_value = session_shards_resume_cursor_value(self.resume_cursor)
        if self.resume_cursor is not None and self.source_token is None:
            raise ValueError("session-shards resume cursor requires a source token")
        if resume_value is not None and (
            resume_value["source_token"] != self.source_token
            or resume_value["byte_offset"] != self.byte_start
        ):
            raise ValueError(
                "session-shards resume cursor is not bound to token and byte_start"
            )
        if self.mode == "records":
            if (
                self.byte_end is None
                or self.source_token is None
                or self.resume_cursor is None
            ):
                raise ValueError(
                    "session-shards records request requires byte_end, token, and cursor"
                )
            assert resume_value is not None
            if (
                resume_value["cursor_kind"] != "records"
                or int(resume_value["frozen_byte_end"]) < self.byte_end
            ):
                raise ValueError(
                    "session-shards records range exceeds its frozen byte end"
                )
        elif self.byte_end is not None:
            raise ValueError("descriptor request cannot bind byte_end")
        elif self.resume_cursor is None and self.byte_start:
            raise ValueError("descriptor continuation requires a resume cursor")
        elif resume_value is not None and resume_value["cursor_kind"] != (
            "descriptor_continue"
        ):
            raise ValueError("descriptor request requires a continuation cursor")

    @property
    def record_start(self) -> int:
        if self.resume_cursor is None:
            return 0
        return self._resume_coordinates(self.resume_cursor)[2]

    @property
    def request_binding(self) -> str:
        digest = canonical_sha256(
            {
                "byte_end": self.byte_end,
                "byte_start": self.byte_start,
                "max_shards": self.max_shards,
                "mode": self.mode,
                "record_processing_budget_bytes": self.record_processing_budget_bytes,
                "rollout": self.rollout,
                "resume_cursor": self.resume_cursor,
                "schema": SESSION_SHARDS_SCHEMA,
                "shard_bytes": self.shard_bytes,
                "source_token": self.source_token,
            }
        )
        return SESSION_SHARDS_REQUEST_BINDING_PREFIX + digest

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "byte_end": self.byte_end,
            "byte_start": self.byte_start,
            "max_shards": self.max_shards,
            "mode": self.mode,
            "record_processing_budget_bytes": self.record_processing_budget_bytes,
            "resume_cursor": self.resume_cursor,
            "rollout": self.rollout,
            "shard_bytes": self.shard_bytes,
            "source_token": self.source_token,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "SessionShardsRequest":
        _require_exact_keys(
            value,
            {
                "byte_end",
                "byte_start",
                "max_shards",
                "mode",
                "record_processing_budget_bytes",
                "resume_cursor",
                "rollout",
                "shard_bytes",
                "source_token",
            },
            label="session-shards request",
        )
        return cls(
            rollout=value["rollout"],  # type: ignore[arg-type]
            mode=value["mode"],  # type: ignore[arg-type]
            source_token=value["source_token"],  # type: ignore[arg-type]
            byte_start=value["byte_start"],  # type: ignore[arg-type]
            byte_end=value["byte_end"],  # type: ignore[arg-type]
            shard_bytes=value["shard_bytes"],  # type: ignore[arg-type]
            max_shards=value["max_shards"],  # type: ignore[arg-type]
            record_processing_budget_bytes=value["record_processing_budget_bytes"],  # type: ignore[arg-type]
            resume_cursor=value["resume_cursor"],  # type: ignore[arg-type]
        )


def parse_typed_ref(value: str, *, expected: RefType | str | None = None) -> TypedRef:
    reference = TypedRef.parse(value)
    if expected is not None:
        expected_kind = expected if isinstance(expected, RefType) else RefType(expected)
        if reference.kind is not expected_kind:
            raise ValueError(
                f"expected {expected_kind.value}, got {reference.kind.value}"
            )
    return reference


def format_typed_ref(kind: RefType | str, digest: str) -> str:
    return str(TypedRef(kind=kind, digest=digest))
