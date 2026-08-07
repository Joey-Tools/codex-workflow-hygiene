"""Strict source-frame and session-shards consumption contracts."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from . import catalog, safe_io, sharding
from .contracts import (
    MAX_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
    MAX_SESSION_SHARD_BYTES,
    MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
    SESSION_SHARDS_SCHEMA,
    SESSION_SHARDS_SOURCE_TOKEN_PREFIX,
    SessionShardsRequest,
    SourceKind,
)
from .orchestrator_core import EXTRACTOR_SHARD_MAX_BYTES, InvalidInputError
from .session_shards_relay import MAX_SESSION_SHARDS_RECORD_DATA_FRAMES

SESSION_SHARDS_CONSERVATION_SCHEMA = "session-shards-conservation-v1"
SESSION_SHARDS_RECORD_FRAGMENT_BYTES = 256 * 1024
SESSION_SHARDS_FIXED_MEMORY_ENVELOPE_BYTES = MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
SESSION_SHARDS_MAX_JSON_NESTING_DEPTH = 512
SESSION_SHARDS_MAX_FRAME_CHARS = (
    4 * ((max(MAX_SESSION_SHARD_BYTES, SESSION_SHARDS_RECORD_FRAGMENT_BYTES) + 2) // 3)
    + 16 * 1024
)
SESSION_SHARDS_PROTOCOL_FEATURES = (
    "oversized_record_fragments_v1",
    "terminal_conservation_v1",
    "request_binding_v1",
    "resume_cursor_v1",
    "record_data_frame_limit_v1",
)
SOURCE_TRANSPORT_MAX_RECORDS = 100_000
SOURCE_TRANSPORT_MAX_SOURCE_BYTES = 256 * 1024 * 1024
SOURCE_TRANSPORT_MAX_FRAME_BYTES = SESSION_SHARDS_MAX_FRAME_CHARS

_SOURCE_TOKEN_RE = re.compile(
    rf"{re.escape(SESSION_SHARDS_SOURCE_TOKEN_PREFIX)}[0-9a-f]{{64}}\Z"
)


def _source_record_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("source record contains duplicate JSON keys")
        value[key] = item
    return value


def _strict_source_record(payload: bytes) -> Mapping[str, Any]:
    try:
        value = safe_io.decode_json_bytes(payload, label="source record")
    except safe_io.InvalidJsonError as exc:
        raise ValueError("source record is not strict JSON") from exc
    if not isinstance(value, Mapping):
        raise ValueError("source record root must be an object")
    return value


def _source_session_identifiers(
    record: Mapping[str, Any],
    *,
    source_kind: SourceKind,
) -> tuple[str, ...]:
    identifiers: set[str] = set()
    nodes: list[tuple[Mapping[str, Any], int]] = [(record, 0)]
    visited = 0
    explicit_keys = {
        "conversation_id",
        "sessionId",
        "session_id",
        "threadId",
        "thread_id",
    }
    while nodes:
        node, depth = nodes.pop()
        visited += 1
        if visited > 4096 or depth > 16:
            raise ValueError("source record identity structure exceeds bounds")
        for key in explicit_keys:
            candidate = node.get(key)
            if (
                isinstance(candidate, str)
                and 1 <= len(candidate) <= 512
                and not any(ord(character) < 0x20 for character in candidate)
            ):
                identifiers.add(candidate)
        if source_kind is SourceKind.SESSION_INDEX:
            candidate = node.get("id")
            if isinstance(candidate, str) and 1 <= len(candidate) <= 512:
                identifiers.add(candidate)
        if node.get("type") == "session_meta":
            payload = node.get("payload")
            if isinstance(payload, Mapping):
                for key in ("id", "session_id"):
                    candidate = payload.get(key)
                    if isinstance(candidate, str) and 1 <= len(candidate) <= 512:
                        identifiers.add(candidate)
        for child in node.values():
            if isinstance(child, Mapping):
                nodes.append((child, depth + 1))
    if len(identifiers) > 32:
        raise ValueError("source record contains too many session identifiers")
    return tuple(sorted(identifiers, key=lambda value: value.encode("utf-8")))


def _require_frame_keys(
    frame: Mapping[str, Any],
    expected: Iterable[str],
    *,
    label: str,
) -> None:
    expected_keys = set(expected)
    actual_keys = set(frame)
    if actual_keys != expected_keys:
        raise InvalidInputError(f"{label} does not use its closed field set")


def _frame_integer(
    frame: Mapping[str, Any],
    key: str,
    *,
    minimum: int = 0,
) -> int:
    value = frame.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise InvalidInputError(f"session-shards frame has invalid {key}")
    return value


def _content_commitment(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _decode_transport_payload(frame: Mapping[str, Any], key: str) -> bytes:
    if frame.get("record_encoding") != "base64":
        raise InvalidInputError("session-shards payload encoding must be base64")
    encoded = frame.get(key)
    if not isinstance(encoded, str):
        raise InvalidInputError("session-shards payload must be a base64 string")
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidInputError("session-shards payload is not valid base64") from error


def _transport_accounting_bytes(frame: Mapping[str, Any]) -> bytes:
    common_keys = (
        "kind",
        "schema",
        "mode",
        "source_token",
        "request_binding",
        "byte_start",
        "byte_end",
        "byte_count",
        "record_start",
        "record_end",
        "delimiter_bytes",
    )
    kind = frame.get("kind")
    if kind == "record":
        keys = common_keys + ("record_encoding", "record_commitment")
    elif kind == "record_fragment":
        keys = common_keys + (
            "record_byte_start",
            "record_byte_end",
            "record_byte_count",
            "fragment_index",
            "fragment_count",
            "record_encoding",
            "fragment_commitment",
            "record_commitment",
        )
    elif kind == "gap":
        keys = common_keys + ("reason",)
    else:
        raise InvalidInputError("unsupported session-shards accounting frame")
    try:
        accounting = {key: frame[key] for key in keys}
    except KeyError as error:
        raise InvalidInputError("session-shards accounting field is missing") from error
    for key in (
        "record_processing_budget_bytes",
        "hard_record_processing_ceiling_bytes",
        "processing_ceiling_kind",
        "processing_ceiling_limit",
        "processing_ceiling_observed",
    ):
        if key in frame:
            accounting[key] = frame[key]
    return (
        json.dumps(
            accounting,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _argv_option(argv: Sequence[str], option: str) -> str:
    positions = [index for index, item in enumerate(argv) if item == option]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise InvalidInputError(f"remote source command must bind {option}")
    return argv[positions[0] + 1]


@dataclass(frozen=True)
class SessionShardConsumption:
    source_ref: str
    source_token: str
    raw_records: tuple[sharding.RawEvidenceRecord, ...]
    gap_unit_refs: tuple[str, ...]
    record_count: int
    byte_count: int


@dataclass(frozen=True)
class SourcePreparation:
    lease_ref: str
    host: str
    manifest: dict[str, Any]
    receipt: dict[str, Any]
    raw_records: dict[str, bytes]


class _SessionShardStreamConsumer:
    """Strict consumer for one exact session-shards records stream."""

    _META_FIELDS = {
        "kind",
        "schema",
        "mode",
        "source_token",
        "request_rollout",
        "request_source_token",
        "request_resume_cursor",
        "request_binding",
        "source_bytes",
        "byte_start",
        "byte_end",
        "record_start",
        "shard_bytes",
        "max_shards",
        "record_processing_budget_bytes",
        "fixed_memory_envelope_bytes",
        "hard_record_processing_ceiling_bytes",
        "record_fragment_bytes",
        "json_nesting_depth_limit",
        "max_remote_frame_chars",
        "max_record_data_frames",
        "protocol_features",
    }
    _RECORD_FIELDS = {
        "kind",
        "schema",
        "mode",
        "source_token",
        "request_binding",
        "record_start",
        "record_end",
        "delimiter_bytes",
        "byte_start",
        "byte_end",
        "byte_count",
        "record_encoding",
        "record_b64",
        "record_commitment",
    }
    _FRAGMENT_FIELDS = {
        "kind",
        "schema",
        "mode",
        "source_token",
        "request_binding",
        "record_start",
        "record_end",
        "delimiter_bytes",
        "byte_start",
        "byte_end",
        "byte_count",
        "record_byte_start",
        "record_byte_end",
        "record_byte_count",
        "fragment_index",
        "fragment_count",
        "record_encoding",
        "fragment_b64",
        "fragment_commitment",
        "record_commitment",
    }
    _GAP_FIELDS = {
        "kind",
        "schema",
        "mode",
        "source_token",
        "request_binding",
        "byte_start",
        "byte_end",
        "byte_count",
        "record_start",
        "record_end",
        "delimiter_bytes",
        "reason",
    }
    _TERMINAL_FIELDS = {
        "kind",
        "schema",
        "mode",
        "source_token",
        "request_binding",
        "complete",
        "reason",
        "emitted_records",
        "emitted_gaps",
        "emitted_fragments",
        "emitted_record_bytes",
        "emitted_gap_bytes",
        "emitted_fragment_bytes",
        "byte_start",
        "byte_end",
        "record_start",
        "record_end",
        "conservation_proof",
    }
    _PROOF_FIELDS = {
        "schema",
        "source_token",
        "request_binding",
        "byte_start",
        "byte_end",
        "byte_count",
        "accounted_byte_count",
        "record_start",
        "record_end",
        "record_count",
        "accounted_record_count",
        "accounting_commitment",
    }

    def __init__(
        self,
        manifest: catalog.SourceTransportManifest,
        source_ref: str,
        request: SessionShardsRequest | Mapping[str, Any],
        limits: sharding.ShardLimits,
    ) -> None:
        try:
            restored_request = (
                request
                if isinstance(request, SessionShardsRequest)
                else SessionShardsRequest.from_dict(request)
            )
        except (TypeError, ValueError) as error:
            raise InvalidInputError(
                "session-shards request violates its closed contract"
            ) from error
        if restored_request.mode != "records":
            raise InvalidInputError("session-shards consumer requires records mode")
        if (
            limits.record_processing_budget < MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
            or limits.record_processing_budget < limits.max_bytes
            or limits.record_processing_budget
            > MAX_SESSION_RECORD_PROCESSING_BUDGET_BYTES
        ):
            raise InvalidInputError(
                "record processing budget is outside session-shards bounds"
            )
        if (
            restored_request.shard_bytes != limits.max_bytes
            or restored_request.record_processing_budget_bytes
            != limits.record_processing_budget
        ):
            raise InvalidInputError(
                "session-shards request is not bound to the run limits"
            )
        self.manifest = manifest
        self.source_ref = source_ref
        self.request = restored_request
        self.limits = limits
        self.records = tuple(
            sorted(
                (
                    record
                    for record in manifest.records
                    if record.coordinate.source_ref == source_ref
                ),
                key=lambda record: (
                    record.coordinate.byte_start,
                    record.coordinate.byte_end,
                    record.coordinate.record_ref,
                    record.unit_ref,
                ),
            )
        )
        if not self.records:
            raise InvalidInputError("session-shards stream has no catalog records")
        if (
            restored_request.byte_start != self.records[0].coordinate.byte_start
            or restored_request.byte_end != self.records[-1].coordinate.byte_end
        ):
            raise InvalidInputError(
                "session-shards request does not match catalog coordinates"
            )
        for previous, current in zip(self.records, self.records[1:]):
            if previous.coordinate.byte_end != current.coordinate.byte_start:
                raise InvalidInputError(
                    "session-shards catalog coordinates must be contiguous"
                )
        self.meta: dict[str, Any] | None = None
        self.terminal_seen = False
        self.next_byte: int | None = None
        self.next_record: int | None = None
        self.catalog_index = 0
        self.fragment_state: dict[str, Any] | None = None
        self.raw_records: list[sharding.RawEvidenceRecord] = []
        self.gap_unit_refs: list[str] = []
        self.emitted_records = 0
        self.emitted_gaps = 0
        self.emitted_fragments = 0
        self.emitted_record_bytes = 0
        self.emitted_gap_bytes = 0
        self.emitted_fragment_bytes = 0
        self.accounting_hasher = hashlib.sha256()

    def _check_frame_bound(self, frame: Mapping[str, Any]) -> None:
        try:
            encoded = json.dumps(
                dict(frame),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError) as error:
            raise InvalidInputError(
                "session-shards frame is not finite JSON"
            ) from error
        bound = (
            SESSION_SHARDS_MAX_FRAME_CHARS
            if self.meta is None
            else self.meta["max_remote_frame_chars"]
        )
        if len(encoded) > bound:
            raise InvalidInputError("session-shards frame exceeds its advertised bound")

    def accept(self, frame: Mapping[str, Any]) -> None:
        if not isinstance(frame, Mapping):
            raise InvalidInputError("session-shards frame must be an object")
        self._check_frame_bound(frame)
        kind = frame.get("kind")
        if kind == "stream_meta":
            self._accept_meta(frame)
            return
        if self.meta is None:
            raise InvalidInputError("session-shards data precedes stream_meta")
        if self.terminal_seen:
            raise InvalidInputError("session-shards data follows stream_end")
        if kind == "record":
            self._accept_record(frame)
        elif kind == "record_fragment":
            self._accept_fragment(frame)
        elif kind == "gap":
            self._accept_gap(frame)
        elif kind == "stream_end":
            self._accept_terminal(frame)
        else:
            raise InvalidInputError("session-shards frame kind is not supported")

    def _accept_meta(self, frame: Mapping[str, Any]) -> None:
        if self.meta is not None or self.terminal_seen:
            raise InvalidInputError("session-shards emitted duplicate stream_meta")
        _require_frame_keys(frame, self._META_FIELDS, label="stream_meta")
        if (
            frame.get("schema") != SESSION_SHARDS_SCHEMA
            or frame.get("mode") != "records"
        ):
            raise InvalidInputError(
                "session-shards stream_meta contract is unsupported"
            )
        source_token = frame.get("source_token")
        if (
            not isinstance(source_token, str)
            or _SOURCE_TOKEN_RE.fullmatch(source_token) is None
        ):
            raise InvalidInputError("session-shards source token is invalid")
        source_bytes = _frame_integer(frame, "source_bytes")
        byte_start = _frame_integer(frame, "byte_start")
        byte_end = _frame_integer(frame, "byte_end", minimum=byte_start + 1)
        record_start = _frame_integer(frame, "record_start")
        shard_bytes = _frame_integer(frame, "shard_bytes", minimum=1)
        max_shards = _frame_integer(frame, "max_shards", minimum=1)
        processing_budget = _frame_integer(
            frame,
            "record_processing_budget_bytes",
            minimum=MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
        )
        fixed_memory = _frame_integer(
            frame,
            "fixed_memory_envelope_bytes",
            minimum=MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
        )
        hard_ceiling = _frame_integer(
            frame,
            "hard_record_processing_ceiling_bytes",
            minimum=processing_budget,
        )
        fragment_bytes = _frame_integer(frame, "record_fragment_bytes", minimum=1)
        nesting_limit = _frame_integer(frame, "json_nesting_depth_limit", minimum=1)
        frame_limit = _frame_integer(frame, "max_remote_frame_chars", minimum=1)
        data_frame_limit = _frame_integer(frame, "max_record_data_frames", minimum=1)
        if (
            source_bytes < byte_end
            or source_token != self.request.source_token
            or frame.get("request_rollout") != self.request.rollout
            or frame.get("request_source_token") != self.request.source_token
            or frame.get("request_resume_cursor") != self.request.resume_cursor
            or frame.get("request_binding") != self.request.request_binding
            or byte_start != self.request.byte_start
            or byte_end != self.request.byte_end
            or record_start != self.request.record_start
            or shard_bytes != self.request.shard_bytes
            or max_shards != self.request.max_shards
            or processing_budget != self.request.record_processing_budget_bytes
            or fixed_memory != SESSION_SHARDS_FIXED_MEMORY_ENVELOPE_BYTES
            or hard_ceiling != sharding.HARD_RECORD_PROCESSING_CEILING
            or fragment_bytes != SESSION_SHARDS_RECORD_FRAGMENT_BYTES
            or nesting_limit != SESSION_SHARDS_MAX_JSON_NESTING_DEPTH
            or frame_limit != SESSION_SHARDS_MAX_FRAME_CHARS
            or data_frame_limit != MAX_SESSION_SHARDS_RECORD_DATA_FRAMES
            or frame.get("protocol_features") != list(SESSION_SHARDS_PROTOCOL_FEATURES)
            or byte_start != self.records[0].coordinate.byte_start
            or byte_end != self.records[-1].coordinate.byte_end
        ):
            raise InvalidInputError(
                "session-shards stream_meta is not bound to the run"
            )
        if self.manifest.transport_kind is catalog.TransportKind.REMOTE:
            assert self.manifest.remote is not None
            argv = self.manifest.remote.forced_command_argv
            if "source-transport" not in argv:
                expected_options = {
                    "--emit": "records",
                    "--rollout": self.request.rollout,
                    "--byte-start": str(byte_start),
                    "--byte-end": str(byte_end),
                    "--shard-bytes": str(self.request.shard_bytes),
                    "--max-shards": str(self.request.max_shards),
                    "--record-processing-budget-bytes": str(
                        self.request.record_processing_budget_bytes
                    ),
                    "--source-token": source_token,
                    "--resume-cursor": self.request.resume_cursor,
                }
                for option, expected in expected_options.items():
                    if _argv_option(argv, option) != expected:
                        raise InvalidInputError(
                            "remote source command does not bind the session-shards stream"
                        )
        self.meta = dict(frame)
        self.next_byte = byte_start
        self.next_record = record_start

    def _validate_response_binding(self, frame: Mapping[str, Any]) -> None:
        assert self.meta is not None
        if (
            frame.get("schema") != SESSION_SHARDS_SCHEMA
            or frame.get("mode") != "records"
            or frame.get("source_token") != self.meta["source_token"]
            or frame.get("request_binding") != self.request.request_binding
        ):
            raise InvalidInputError("session-shards response binding changed")

    def _whole_record_range(
        self, frame: Mapping[str, Any]
    ) -> tuple[int, int, int, int, int]:
        if self.next_byte is None or self.next_record is None:
            raise InvalidInputError("session-shards accounting is uninitialized")
        byte_start = _frame_integer(frame, "byte_start")
        byte_end = _frame_integer(frame, "byte_end", minimum=byte_start + 1)
        byte_count = _frame_integer(frame, "byte_count", minimum=1)
        record_start = _frame_integer(frame, "record_start")
        record_end = _frame_integer(frame, "record_end", minimum=record_start + 1)
        delimiter_bytes = _frame_integer(frame, "delimiter_bytes")
        if (
            byte_start != self.next_byte
            or byte_count != byte_end - byte_start
            or record_start != self.next_record
            or record_end != record_start + 1
            or delimiter_bytes not in (0, 1, 2)
        ):
            raise InvalidInputError("session-shards record range is not contiguous")
        return byte_start, byte_end, byte_count, record_end, delimiter_bytes

    def _catalog_record(self, byte_start: int, byte_end: int) -> catalog.CatalogRecord:
        if self.catalog_index >= len(self.records):
            raise InvalidInputError("session-shards emitted an undeclared record")
        record = self.records[self.catalog_index]
        if (
            record.coordinate.byte_start != byte_start
            or record.coordinate.byte_end != byte_end
        ):
            raise InvalidInputError(
                "session-shards record coordinates do not match the catalog"
            )
        return record

    @staticmethod
    def _validate_json_record(payload: bytes, delimiter_bytes: int) -> None:
        if delimiter_bytes == 2:
            if not payload.endswith(b"\r\n"):
                raise InvalidInputError("session-shards CRLF delimiter is inconsistent")
        elif delimiter_bytes == 1:
            if not payload.endswith(b"\n") or payload.endswith(b"\r\n"):
                raise InvalidInputError("session-shards LF delimiter is inconsistent")
        elif payload.endswith((b"\n", b"\r")):
            raise InvalidInputError(
                "session-shards delimiter accounting is inconsistent"
            )
        json_bytes = payload[:-delimiter_bytes] if delimiter_bytes else payload
        try:
            safe_io.decode_json_bytes(json_bytes, label="session-shards record")
        except safe_io.InvalidJsonError as error:
            raise InvalidInputError(
                "invalid JSON must be represented by a content-free gap"
            ) from error

    def _complete_payload(
        self,
        record: catalog.CatalogRecord,
        payload: bytes,
        delimiter_bytes: int,
        record_commitment: Any,
    ) -> None:
        commitment = _content_commitment(payload)
        if record_commitment != commitment:
            raise InvalidInputError("session-shards record commitment mismatch")
        if (
            record.content_commitment is not None
            and record.content_commitment != commitment
        ):
            raise InvalidInputError(
                "session-shards payload does not match the catalog commitment"
            )
        if record.accounting_class is catalog.AccountingClass.EXPLICIT_GAP:
            raise InvalidInputError("explicit-gap catalog unit carried record content")
        self._validate_json_record(payload, delimiter_bytes)
        if record.accounting_class is catalog.AccountingClass.CONSUMED_CANDIDATE:
            self.raw_records.append(
                sharding.RawEvidenceRecord(catalog_record=record, payload=payload)
            )

    def _advance_record(self, byte_end: int, record_end: int) -> None:
        self.next_byte = byte_end
        self.next_record = record_end
        self.catalog_index += 1

    def _accept_record(self, frame: Mapping[str, Any]) -> None:
        if self.fragment_state is not None:
            raise InvalidInputError("session-shards interrupted a fragmented record")
        _require_frame_keys(frame, self._RECORD_FIELDS, label="record frame")
        self._validate_response_binding(frame)
        byte_start, byte_end, byte_count, record_end, delimiter = (
            self._whole_record_range(frame)
        )
        if byte_count > self.limits.max_bytes:
            raise InvalidInputError(
                "oversized session-shards record was not fragmented"
            )
        payload = _decode_transport_payload(frame, "record_b64")
        if len(payload) != byte_count:
            raise InvalidInputError("session-shards record byte count mismatch")
        record = self._catalog_record(byte_start, byte_end)
        self._complete_payload(
            record,
            payload,
            delimiter,
            frame.get("record_commitment"),
        )
        self.accounting_hasher.update(_transport_accounting_bytes(frame))
        self._advance_record(byte_end, record_end)
        self.emitted_records += 1
        self.emitted_record_bytes += byte_count

    def _accept_fragment(self, frame: Mapping[str, Any]) -> None:
        _require_frame_keys(frame, self._FRAGMENT_FIELDS, label="record_fragment frame")
        self._validate_response_binding(frame)
        if self.next_byte is None or self.next_record is None:
            raise InvalidInputError("session-shards accounting is uninitialized")
        byte_start = _frame_integer(frame, "byte_start")
        byte_end = _frame_integer(frame, "byte_end", minimum=byte_start + 1)
        byte_count = _frame_integer(frame, "byte_count", minimum=1)
        record_byte_start = _frame_integer(frame, "record_byte_start")
        record_byte_end = _frame_integer(
            frame, "record_byte_end", minimum=record_byte_start + 1
        )
        record_byte_count = _frame_integer(frame, "record_byte_count", minimum=1)
        record_start = _frame_integer(frame, "record_start")
        record_end = _frame_integer(frame, "record_end", minimum=record_start + 1)
        fragment_index = _frame_integer(frame, "fragment_index")
        fragment_count = _frame_integer(frame, "fragment_count", minimum=1)
        delimiter_bytes = _frame_integer(frame, "delimiter_bytes")
        expected_count = (
            record_byte_count + SESSION_SHARDS_RECORD_FRAGMENT_BYTES - 1
        ) // SESSION_SHARDS_RECORD_FRAGMENT_BYTES
        expected_start = (
            record_byte_start + fragment_index * SESSION_SHARDS_RECORD_FRAGMENT_BYTES
        )
        expected_end = min(
            expected_start + SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
            record_byte_end,
        )
        if (
            byte_count != byte_end - byte_start
            or byte_count > SESSION_SHARDS_RECORD_FRAGMENT_BYTES
            or record_byte_count != record_byte_end - record_byte_start
            or record_byte_count <= self.limits.max_bytes
            or record_byte_count > self.limits.record_processing_budget
            or record_start != self.next_record
            or record_end != record_start + 1
            or delimiter_bytes not in (0, 1, 2)
            or fragment_index >= fragment_count
            or fragment_count != expected_count
            or byte_start != expected_start
            or byte_end != expected_end
        ):
            raise InvalidInputError("session-shards fragment coordinates are invalid")
        if fragment_index == 0:
            if self.fragment_state is not None or record_byte_start != self.next_byte:
                raise InvalidInputError(
                    "session-shards fragment sequence did not start contiguously"
                )
            record = self._catalog_record(record_byte_start, record_byte_end)
            if record.accounting_class is catalog.AccountingClass.EXPLICIT_GAP:
                raise InvalidInputError("explicit-gap catalog unit carried fragments")
            self.fragment_state = {
                "delimiter_bytes": delimiter_bytes,
                "fragment_count": fragment_count,
                "next_byte": record_byte_start,
                "next_index": 0,
                "payload": bytearray(),
                "record": record,
                "record_byte_count": record_byte_count,
                "record_byte_end": record_byte_end,
                "record_byte_start": record_byte_start,
                "record_commitment": frame.get("record_commitment"),
                "record_end": record_end,
                "record_start": record_start,
            }
        state = self.fragment_state
        if state is None:
            raise InvalidInputError(
                "session-shards fragment sequence lacks its first frame"
            )
        stable = {
            "record_byte_start": record_byte_start,
            "record_byte_end": record_byte_end,
            "record_byte_count": record_byte_count,
            "record_start": record_start,
            "record_end": record_end,
            "fragment_count": fragment_count,
            "delimiter_bytes": delimiter_bytes,
            "record_commitment": frame.get("record_commitment"),
        }
        if (
            any(state[key] != value for key, value in stable.items())
            or fragment_index != state["next_index"]
            or byte_start != state["next_byte"]
        ):
            raise InvalidInputError(
                "session-shards fragment sequence is not stable and contiguous"
            )
        payload = _decode_transport_payload(frame, "fragment_b64")
        if len(payload) != byte_count:
            raise InvalidInputError("session-shards fragment byte count mismatch")
        if frame.get("fragment_commitment") != _content_commitment(payload):
            raise InvalidInputError("session-shards fragment commitment mismatch")
        state["payload"].extend(payload)
        state["next_byte"] = byte_end
        state["next_index"] = fragment_index + 1
        self.accounting_hasher.update(_transport_accounting_bytes(frame))
        self.emitted_fragments += 1
        self.emitted_fragment_bytes += byte_count
        if fragment_index + 1 == fragment_count:
            reassembled = bytes(state["payload"])
            if len(reassembled) != record_byte_count or byte_end != record_byte_end:
                raise InvalidInputError(
                    "session-shards fragmented record is incomplete"
                )
            self._complete_payload(
                state["record"],
                reassembled,
                delimiter_bytes,
                state["record_commitment"],
            )
            self._advance_record(record_byte_end, record_end)
            self.emitted_records += 1
            self.emitted_record_bytes += record_byte_count
            self.fragment_state = None

    def _accept_gap(self, frame: Mapping[str, Any]) -> None:
        if self.fragment_state is not None:
            raise InvalidInputError("session-shards interrupted a fragmented record")
        reason = frame.get("reason")
        expected_fields = set(self._GAP_FIELDS)
        if reason == "record_processing_budget_exceeded":
            expected_fields.update(
                {
                    "record_processing_budget_bytes",
                    "hard_record_processing_ceiling_bytes",
                    "processing_ceiling_kind",
                    "processing_ceiling_limit",
                    "processing_ceiling_observed",
                }
            )
        _require_frame_keys(frame, expected_fields, label="gap frame")
        if reason not in {"invalid_json", "record_processing_budget_exceeded"}:
            raise InvalidInputError("session-shards gap reason is not closed")
        self._validate_response_binding(frame)
        byte_start, byte_end, byte_count, record_end, _delimiter = (
            self._whole_record_range(frame)
        )
        if reason == "record_processing_budget_exceeded":
            budget = _frame_integer(
                frame,
                "record_processing_budget_bytes",
                minimum=MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
            )
            hard_ceiling = _frame_integer(
                frame,
                "hard_record_processing_ceiling_bytes",
                minimum=budget,
            )
            processing_kind = frame.get("processing_ceiling_kind")
            processing_limit = _frame_integer(
                frame,
                "processing_ceiling_limit",
                minimum=1,
            )
            processing_observed = _frame_integer(
                frame,
                "processing_ceiling_observed",
                minimum=processing_limit + 1,
            )
            if processing_kind == "record_bytes":
                valid_ceiling = (
                    processing_limit == budget
                    and processing_observed == byte_count
                    and byte_count > budget
                )
            elif processing_kind == "json_nesting_depth":
                valid_ceiling = (
                    processing_limit == SESSION_SHARDS_MAX_JSON_NESTING_DEPTH
                    and processing_observed == processing_limit + 1
                    and byte_count <= budget
                )
            else:
                valid_ceiling = False
            if (
                budget != self.request.record_processing_budget_bytes
                or hard_ceiling != sharding.HARD_RECORD_PROCESSING_CEILING
                or not valid_ceiling
            ):
                raise InvalidInputError(
                    "session-shards processing-budget gap is inconsistent"
                )
        record = self._catalog_record(byte_start, byte_end)
        if (
            record.accounting_class is not catalog.AccountingClass.EXPLICIT_GAP
            or record.gap is None
            or record.gap.reason != reason
            or record.content_commitment is not None
        ):
            raise InvalidInputError(
                "content-free session-shards gap does not match the catalog"
            )
        self.accounting_hasher.update(_transport_accounting_bytes(frame))
        self.gap_unit_refs.append(record.unit_ref)
        self._advance_record(byte_end, record_end)
        self.emitted_gaps += 1
        self.emitted_gap_bytes += byte_count

    def _accept_terminal(self, frame: Mapping[str, Any]) -> None:
        if self.fragment_state is not None:
            raise InvalidInputError("session-shards ended inside a fragmented record")
        _require_frame_keys(frame, self._TERMINAL_FIELDS, label="stream_end")
        assert self.meta is not None
        self._validate_response_binding(frame)
        if (
            frame.get("schema") != SESSION_SHARDS_SCHEMA
            or frame.get("mode") != "records"
            or frame.get("complete") is not True
            or frame.get("reason") != "range_complete"
        ):
            raise InvalidInputError("session-shards terminal is not complete")
        expected_counts = {
            "emitted_records": self.emitted_records,
            "emitted_gaps": self.emitted_gaps,
            "emitted_fragments": self.emitted_fragments,
            "emitted_record_bytes": self.emitted_record_bytes,
            "emitted_gap_bytes": self.emitted_gap_bytes,
            "emitted_fragment_bytes": self.emitted_fragment_bytes,
        }
        if any(frame.get(key) != value for key, value in expected_counts.items()):
            raise InvalidInputError("session-shards terminal counters do not conserve")
        byte_start = _frame_integer(frame, "byte_start")
        byte_end = _frame_integer(frame, "byte_end", minimum=byte_start + 1)
        record_start = _frame_integer(frame, "record_start")
        record_end = _frame_integer(frame, "record_end", minimum=record_start + 1)
        if (
            self.next_byte != byte_end
            or self.next_record != record_end
            or byte_start != self.meta["byte_start"]
            or byte_end != self.meta["byte_end"]
            or record_start != self.meta["record_start"]
            or self.catalog_index != len(self.records)
            or self.emitted_record_bytes + self.emitted_gap_bytes
            != byte_end - byte_start
            or self.emitted_records + self.emitted_gaps != record_end - record_start
        ):
            raise InvalidInputError(
                "session-shards terminal coordinates do not conserve"
            )
        proof = frame.get("conservation_proof")
        if not isinstance(proof, Mapping):
            raise InvalidInputError("session-shards conservation proof is missing")
        _require_frame_keys(proof, self._PROOF_FIELDS, label="conservation proof")
        expected_proof = {
            "schema": SESSION_SHARDS_CONSERVATION_SCHEMA,
            "source_token": self.meta["source_token"],
            "request_binding": self.request.request_binding,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "byte_count": byte_end - byte_start,
            "accounted_byte_count": self.emitted_record_bytes + self.emitted_gap_bytes,
            "record_start": record_start,
            "record_end": record_end,
            "record_count": record_end - record_start,
            "accounted_record_count": self.emitted_records + self.emitted_gaps,
            "accounting_commitment": ("sha256:" + self.accounting_hasher.hexdigest()),
        }
        if dict(proof) != expected_proof:
            raise InvalidInputError("session-shards conservation proof mismatch")
        self.terminal_seen = True

    def finish(self) -> SessionShardConsumption:
        if self.meta is None or not self.terminal_seen:
            raise InvalidInputError("session-shards stream is truncated")
        return SessionShardConsumption(
            source_ref=self.source_ref,
            source_token=self.meta["source_token"],
            raw_records=tuple(self.raw_records),
            gap_unit_refs=tuple(self.gap_unit_refs),
            record_count=self.emitted_records + self.emitted_gaps,
            byte_count=self.emitted_record_bytes + self.emitted_gap_bytes,
        )


def consume_session_shard_frames(
    manifest: catalog.SourceTransportManifest,
    source_ref: str,
    frames: Iterable[Mapping[str, Any]],
    *,
    request: SessionShardsRequest | Mapping[str, Any],
    limits: sharding.ShardLimits | None = None,
) -> SessionShardConsumption:
    """Validate one stream and fully reassemble records before local sharding."""

    consumer = _SessionShardStreamConsumer(
        manifest,
        source_ref,
        request,
        limits or sharding.ShardLimits(max_bytes=EXTRACTOR_SHARD_MAX_BYTES),
    )
    for frame in frames:
        consumer.accept(frame)
    return consumer.finish()
