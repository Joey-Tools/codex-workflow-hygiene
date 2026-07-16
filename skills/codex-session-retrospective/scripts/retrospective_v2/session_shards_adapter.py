from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping

from .contracts import SESSION_SHARDS_SCHEMA, SessionShardsRequest


class SessionShardsAdapterError(ValueError):
    """Raised when canonical session-shards output is not closed and complete."""


_META_FIELDS = frozenset(
    {
        "byte_end",
        "byte_start",
        "fixed_memory_envelope_bytes",
        "hard_record_processing_ceiling_bytes",
        "json_nesting_depth_limit",
        "kind",
        "max_remote_frame_chars",
        "max_shards",
        "mode",
        "protocol_features",
        "record_fragment_bytes",
        "record_processing_budget_bytes",
        "record_start",
        "request_binding",
        "request_resume_cursor",
        "request_rollout",
        "request_source_token",
        "schema",
        "shard_bytes",
        "source_bytes",
        "source_token",
    }
)
_SHARD_FIELDS = frozenset(
    {
        "byte_end",
        "byte_start",
        "kind",
        "mode",
        "page_shard_index",
        "record_count",
        "record_end",
        "record_start",
        "request_binding",
        "resume_cursor",
        "schema",
        "source_token",
        "status",
    }
)
_GAP_FIELDS = frozenset({"byte_count", "gap_reason"})
_PROCESSING_FIELDS = frozenset(
    {
        "hard_record_processing_ceiling_bytes",
        "processing_ceiling_kind",
        "processing_ceiling_limit",
        "processing_ceiling_observed",
        "record_processing_budget_bytes",
    }
)
_OVERSIZED_FIELDS = frozenset(
    {
        "oversized_record",
        "record_fragment_bytes",
        "record_processing_budget_bytes",
        "record_transport",
    }
)
_TERMINAL_FIELDS = frozenset(
    {
        "accounted_byte_count",
        "accounted_record_count",
        "byte_end",
        "byte_start",
        "complete",
        "emitted_shards",
        "kind",
        "mode",
        "next_byte_start",
        "next_record_start",
        "next_resume_cursor",
        "reason",
        "record_end",
        "record_start",
        "request_binding",
        "schema",
        "source_token",
    }
)


@dataclass(frozen=True, slots=True)
class SessionShardsDescriptorPlan:
    descriptor_request: SessionShardsRequest
    records_request: SessionShardsRequest | None
    source_token: str
    source_bytes: int
    shard_count: int
    record_count: int
    host: str | None


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SessionShardsAdapterError(f"session-shards {label} is invalid")
    return value


def _exact(frame: Mapping[str, Any], fields: frozenset[str], label: str) -> None:
    if frozenset(frame) != fields:
        raise SessionShardsAdapterError(
            f"session-shards {label} violates its closed field schema"
        )


def _unwrap(
    frame: Mapping[str, Any],
    *,
    expected_host: str | None,
    expected_rollout: str | None,
) -> tuple[dict[str, Any], str | None]:
    item = dict(frame)
    has_host = "host" in item
    has_rollout = "rollout" in item
    if has_host != has_rollout:
        raise SessionShardsAdapterError(
            "session-shards wrapper must bind host and rollout together"
        )
    if expected_host is not None and not has_host:
        raise SessionShardsAdapterError(
            "session-shards wrapper is required for a host-bound stream"
        )
    observed_host: str | None = None
    if has_host:
        observed_host = item.pop("host")
        observed_rollout = item.pop("rollout")
        if (
            not isinstance(observed_host, str)
            or not isinstance(observed_rollout, str)
            or (expected_host is not None and observed_host != expected_host)
            or (expected_rollout is not None and observed_rollout != expected_rollout)
        ):
            raise SessionShardsAdapterError(
                "session-shards wrapper does not match its requested host/rollout"
            )
    return item, observed_host


def descriptor_plan_from_frames(
    frames: Iterable[Mapping[str, Any]],
    *,
    expected_host: str | None = None,
) -> SessionShardsDescriptorPlan:
    iterator = iter(frames)
    try:
        first_raw = next(iterator)
    except StopIteration as exc:
        raise SessionShardsAdapterError(
            "session-shards descriptor stream is empty"
        ) from exc
    first, wrapper_host = _unwrap(
        first_raw,
        expected_host=expected_host,
        expected_rollout=None,
    )
    _exact(first, _META_FIELDS, "descriptor stream_meta")
    if (
        first.get("kind") != "stream_meta"
        or first.get("schema") != SESSION_SHARDS_SCHEMA
        or first.get("mode") != "descriptors"
        or first.get("byte_end") is not None
    ):
        raise SessionShardsAdapterError(
            "session-shards descriptor stream_meta is unsupported"
        )
    rollout = first.get("request_rollout")
    source_token = first.get("source_token")
    if not isinstance(rollout, str) or not isinstance(source_token, str):
        raise SessionShardsAdapterError(
            "session-shards descriptor stream identity is invalid"
        )
    descriptor_request = SessionShardsRequest(
        rollout=rollout,
        mode="descriptors",
        source_token=first.get("request_source_token"),
        byte_start=_integer(first.get("byte_start"), "descriptor byte_start"),
        byte_end=None,
        shard_bytes=_integer(
            first.get("shard_bytes"), "descriptor shard_bytes", minimum=1
        ),
        max_shards=_integer(
            first.get("max_shards"), "descriptor max_shards", minimum=1
        ),
        record_processing_budget_bytes=_integer(
            first.get("record_processing_budget_bytes"),
            "descriptor processing budget",
            minimum=1,
        ),
        resume_cursor=first.get("request_resume_cursor"),
    )
    if first.get("request_binding") != descriptor_request.request_binding:
        raise SessionShardsAdapterError(
            "session-shards descriptor stream_meta is not request-bound"
        )
    source_bytes = _integer(first.get("source_bytes"), "source_bytes")
    next_byte = descriptor_request.byte_start
    next_record = descriptor_request.record_start
    first_cursor: str | None = None
    shard_count = 0
    terminal: dict[str, Any] | None = None
    for raw_frame in iterator:
        frame, observed_host = _unwrap(
            raw_frame,
            expected_host=wrapper_host or expected_host,
            expected_rollout=rollout,
        )
        if wrapper_host is None and observed_host is not None:
            raise SessionShardsAdapterError(
                "session-shards wrapper presence changed within the stream"
            )
        if frame.get("kind") == "stream_end":
            _exact(frame, _TERMINAL_FIELDS, "descriptor terminal")
            terminal = frame
            break
        if frame.get("kind") != "shard":
            raise SessionShardsAdapterError(
                "session-shards descriptor stream contains an unknown frame"
            )
        status = frame.get("status")
        expected_fields = set(_SHARD_FIELDS)
        if status == "gap":
            expected_fields.update(_GAP_FIELDS)
            reason = frame.get("gap_reason")
            if reason == "record_processing_budget_exceeded":
                expected_fields.update(_PROCESSING_FIELDS)
            elif reason != "invalid_json":
                raise SessionShardsAdapterError(
                    "session-shards descriptor gap reason is not closed"
                )
        elif status == "ready":
            if frame.get("oversized_record") is True:
                expected_fields.update(_OVERSIZED_FIELDS)
        else:
            raise SessionShardsAdapterError(
                "session-shards descriptor status is not closed"
            )
        _exact(frame, frozenset(expected_fields), "descriptor")
        byte_start = _integer(frame.get("byte_start"), "descriptor byte_start")
        byte_end = _integer(
            frame.get("byte_end"), "descriptor byte_end", minimum=byte_start + 1
        )
        record_start = _integer(frame.get("record_start"), "descriptor record_start")
        record_end = _integer(
            frame.get("record_end"),
            "descriptor record_end",
            minimum=record_start + 1,
        )
        record_count = _integer(
            frame.get("record_count"), "descriptor record_count", minimum=1
        )
        cursor = frame.get("resume_cursor")
        if (
            frame.get("schema") != SESSION_SHARDS_SCHEMA
            or frame.get("mode") != "descriptors"
            or frame.get("source_token") != source_token
            or frame.get("request_binding") != descriptor_request.request_binding
            or frame.get("page_shard_index") != shard_count
            or byte_start != next_byte
            or record_start != next_record
            or record_count != record_end - record_start
            or not isinstance(cursor, str)
        ):
            raise SessionShardsAdapterError(
                "session-shards descriptors are not contiguous and request-bound"
            )
        cursor_token, cursor_byte, cursor_record = (
            SessionShardsRequest._resume_coordinates(cursor)
        )
        if (
            cursor_token != source_token
            or cursor_byte != byte_start
            or cursor_record != record_start
        ):
            raise SessionShardsAdapterError(
                "session-shards descriptor cursor coordinates are invalid"
            )
        if first_cursor is None:
            first_cursor = cursor
        next_byte = byte_end
        next_record = record_end
        shard_count += 1
    if terminal is None:
        raise SessionShardsAdapterError("session-shards descriptor stream is truncated")
    try:
        extra = next(iterator)
    except StopIteration:
        extra = None
    if extra is not None:
        raise SessionShardsAdapterError(
            "session-shards descriptor stream contains data after terminal"
        )
    if (
        terminal.get("schema") != SESSION_SHARDS_SCHEMA
        or terminal.get("mode") != "descriptors"
        or terminal.get("source_token") != source_token
        or terminal.get("request_binding") != descriptor_request.request_binding
        or terminal.get("complete") is not True
        or terminal.get("reason") != "eof"
        or terminal.get("emitted_shards") != shard_count
        or terminal.get("byte_start") != descriptor_request.byte_start
        or terminal.get("byte_end") != next_byte
        or terminal.get("record_start") != descriptor_request.record_start
        or terminal.get("record_end") != next_record
        or terminal.get("next_byte_start") is not None
        or terminal.get("next_record_start") is not None
        or terminal.get("next_resume_cursor") is not None
        or terminal.get("accounted_byte_count")
        != next_byte - descriptor_request.byte_start
        or terminal.get("accounted_record_count")
        != next_record - descriptor_request.record_start
        or next_byte != source_bytes
    ):
        raise SessionShardsAdapterError(
            "session-shards descriptor terminal does not prove authoritative EOF"
        )
    records_request = None
    if shard_count:
        assert first_cursor is not None
        records_request = SessionShardsRequest(
            rollout=rollout,
            mode="records",
            source_token=source_token,
            byte_start=descriptor_request.byte_start,
            byte_end=next_byte,
            shard_bytes=descriptor_request.shard_bytes,
            max_shards=descriptor_request.max_shards,
            record_processing_budget_bytes=(
                descriptor_request.record_processing_budget_bytes
            ),
            resume_cursor=first_cursor,
        )
    return SessionShardsDescriptorPlan(
        descriptor_request=descriptor_request,
        records_request=records_request,
        source_token=source_token,
        source_bytes=source_bytes,
        shard_count=shard_count,
        record_count=next_record - descriptor_request.record_start,
        host=wrapper_host,
    )


def normalize_record_frames(
    frames: Iterable[Mapping[str, Any]],
    *,
    expected_host: str | None,
    expected_rollout: str,
) -> Iterator[dict[str, Any]]:
    wrapper_mode: bool | None = None
    for raw_frame in frames:
        frame, observed_host = _unwrap(
            raw_frame,
            expected_host=expected_host,
            expected_rollout=expected_rollout,
        )
        wrapped = observed_host is not None
        if wrapper_mode is None:
            wrapper_mode = wrapped
        elif wrapper_mode is not wrapped:
            raise SessionShardsAdapterError(
                "session-shards wrapper presence changed within the stream"
            )
        yield frame
