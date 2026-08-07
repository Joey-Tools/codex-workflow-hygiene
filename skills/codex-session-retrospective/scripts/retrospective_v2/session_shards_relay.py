"""Streaming validation for remote session-shards protocol output."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Mapping

from .contracts import SESSION_SHARDS_SCHEMA, strict_json_loads


REMOTE_RECORD_METADATA_BASE_BYTES = 64 * 1024
REMOTE_RECORD_METADATA_MAX_BYTES = 16 * 1024 * 1024
REMOTE_WRAPPER_ALLOWANCE_BYTES = 512
MAX_SESSION_SHARDS_RECORD_DATA_FRAMES = 1024


def remote_output_limit(
    *,
    mode: str,
    byte_start: int,
    byte_end: int | None,
    max_shards: int,
    frame_metadata_bytes: int,
) -> int:
    """Return a request-derived wire bound, including compact frame metadata."""

    if mode == "descriptors":
        return (max_shards + 2) * (
            frame_metadata_bytes + REMOTE_WRAPPER_ALLOWANCE_BYTES
        )
    if byte_end is None or byte_end <= byte_start:
        raise ValueError("record relay range is invalid")
    source_bytes = byte_end - byte_start
    encoded_bytes = 4 * source_bytes
    max_data_frames = min(MAX_SESSION_SHARDS_RECORD_DATA_FRAMES, source_bytes)
    metadata_bytes = min(
        REMOTE_RECORD_METADATA_MAX_BYTES,
        (max_data_frames + 2)
        * (frame_metadata_bytes + REMOTE_WRAPPER_ALLOWANCE_BYTES + 1),
    )
    return encoded_bytes + metadata_bytes


def accounting_bytes(frame: Mapping[str, Any]) -> bytes:
    """Return the canonical record-accounting commitment input."""

    kind = frame.get("kind")
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
        raise ValueError(f"unsupported session-shards accounting frame: {kind}")
    try:
        value = {key: frame[key] for key in keys}
    except KeyError as exc:
        raise ValueError(
            f"session-shards {kind} frame is missing {exc.args[0]}"
        ) from exc
    for optional_key in (
        "record_processing_budget_bytes",
        "hard_record_processing_ceiling_bytes",
        "processing_ceiling_kind",
        "processing_ceiling_limit",
        "processing_ceiling_observed",
    ):
        if optional_key in frame:
            value[optional_key] = frame[optional_key]
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"session-shards {label} is invalid")
    return value


def _decode_payload(frame: Mapping[str, Any], field: str, commitment: str) -> bytes:
    encoded = frame.get(field)
    if not isinstance(encoded, str):
        raise ValueError("session-shards base64 payload is missing")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("session-shards base64 payload is invalid") from exc
    expected = "sha256:" + hashlib.sha256(payload).hexdigest()
    if frame.get(commitment) != expected:
        raise ValueError("session-shards payload commitment is invalid")
    return payload


class RemoteSessionShardsFilter:
    """Validate, conserve, and host-bind one remote JSONL stream incrementally."""

    def __init__(
        self,
        *,
        host: str,
        rollout: str,
        mode: str,
        source_token: str | None,
        resume_cursor: str | None,
        request_binding: str,
        byte_start: int,
        byte_end: int | None,
        shard_bytes: int,
        max_shards: int,
        record_processing_budget_bytes: int,
        max_frame_chars: int,
    ) -> None:
        self.host = host
        self.rollout = rollout
        self.mode = mode
        self.source_token_request = source_token
        self.resume_cursor = resume_cursor
        self.request_binding = request_binding
        self.byte_start = byte_start
        self.byte_end = byte_end
        self.shard_bytes = shard_bytes
        self.max_shards = max_shards
        self.record_processing_budget_bytes = record_processing_budget_bytes
        self.max_frame_chars = max_frame_chars
        self.buffer = bytearray()
        self.wrapper_mode: bool | None = None
        self.source_token: str | None = None
        self.source_bytes: int | None = None
        self.next_byte: int | None = None
        self.next_record: int | None = None
        self.initial_record: int | None = None
        self.meta_seen = False
        self.terminal_seen = False
        self.shards = 0
        self.records = 0
        self.gaps = 0
        self.fragments = 0
        self.data_frames = 0
        self.record_bytes = 0
        self.gap_bytes = 0
        self.fragment_bytes = 0
        self.fragment_state: dict[str, Any] | None = None
        self.accounting_hasher = hashlib.sha256()

    def feed(self, chunk: bytes) -> bytes:
        if not isinstance(chunk, bytes):
            raise ValueError("session-shards relay requires bytes")
        self.buffer.extend(chunk)
        output: list[bytes] = []
        while True:
            newline = self.buffer.find(b"\n")
            if newline < 0:
                if len(self.buffer) > self.max_frame_chars:
                    raise ValueError("session-shards frame exceeds its size bound")
                break
            line = bytes(self.buffer[:newline])
            del self.buffer[: newline + 1]
            output.append(self._accept_line(line))
        return b"".join(output)

    def finish(self) -> bytes:
        if self.buffer:
            raise ValueError("session-shards stream has an unterminated frame")
        if not self.meta_seen or not self.terminal_seen:
            raise ValueError("session-shards stream is truncated")
        return b""

    def _accept_line(self, line: bytes) -> bytes:
        if not line or len(line) > self.max_frame_chars:
            raise ValueError("session-shards frame exceeds its size bound")
        decoded = strict_json_loads(line)
        if not isinstance(decoded, Mapping):
            raise ValueError("session-shards frame must be an object")
        frame = dict(decoded)
        has_host = "host" in frame
        has_rollout = "rollout" in frame
        if has_host != has_rollout:
            raise ValueError("session-shards wrapper is incomplete")
        wrapped = has_host
        if self.wrapper_mode is None:
            self.wrapper_mode = wrapped
        elif self.wrapper_mode is not wrapped:
            raise ValueError("session-shards mixed wrapped and unwrapped frames")
        if wrapped and (
            frame.pop("host") != self.host or frame.pop("rollout") != self.rollout
        ):
            raise ValueError("session-shards wrapper is cross-host or cross-rollout")
        self._accept_frame(frame)
        frame["host"] = self.host
        frame["rollout"] = self.rollout
        return (
            json.dumps(
                frame,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    def _accept_frame(self, frame: Mapping[str, Any]) -> None:
        if self.terminal_seen:
            raise ValueError("session-shards stream has data after its terminal")
        if not self.meta_seen:
            self._accept_meta(frame)
            return
        if (
            frame.get("schema") != SESSION_SHARDS_SCHEMA
            or frame.get("mode") != self.mode
            or frame.get("source_token") != self.source_token
            or frame.get("request_binding") != self.request_binding
        ):
            raise ValueError("session-shards response binding changed")
        if frame.get("kind") == "stream_end":
            self._accept_terminal(frame)
        elif self.mode == "descriptors":
            self._accept_descriptor(frame)
        else:
            self._accept_record_frame(frame)

    def _accept_meta(self, frame: Mapping[str, Any]) -> None:
        expected_end = self.byte_end if self.mode == "records" else None
        if (
            frame.get("kind") != "stream_meta"
            or frame.get("schema") != SESSION_SHARDS_SCHEMA
            or frame.get("mode") != self.mode
            or frame.get("request_rollout") != self.rollout
            or frame.get("request_source_token") != self.source_token_request
            or frame.get("request_resume_cursor") != self.resume_cursor
            or frame.get("request_binding") != self.request_binding
            or frame.get("byte_start") != self.byte_start
            or frame.get("byte_end") != expected_end
            or frame.get("shard_bytes") != self.shard_bytes
            or frame.get("max_shards") != self.max_shards
            or frame.get("record_processing_budget_bytes")
            != self.record_processing_budget_bytes
            or frame.get("max_record_data_frames")
            != MAX_SESSION_SHARDS_RECORD_DATA_FRAMES
        ):
            raise ValueError("session-shards stream_meta is not request-bound")
        source_token = frame.get("source_token")
        if not isinstance(source_token, str) or (
            self.source_token_request is not None
            and source_token != self.source_token_request
        ):
            raise ValueError("session-shards source token is invalid")
        source_bytes = _integer(frame.get("source_bytes"), "source_bytes")
        if expected_end is not None and source_bytes < expected_end:
            raise ValueError(
                "session-shards source is shorter than the requested range"
            )
        self.source_token = source_token
        self.source_bytes = source_bytes
        self.next_byte = self.byte_start
        self.next_record = _integer(frame.get("record_start"), "record_start")
        self.initial_record = self.next_record
        self.meta_seen = True

    def _accept_descriptor(self, frame: Mapping[str, Any]) -> None:
        if frame.get("kind") != "shard" or self.shards >= self.max_shards:
            raise ValueError("session-shards descriptor page is invalid")
        byte_start = _integer(frame.get("byte_start"), "descriptor byte_start")
        byte_end = _integer(frame.get("byte_end"), "descriptor byte_end", minimum=1)
        record_start = _integer(frame.get("record_start"), "descriptor record_start")
        record_end = _integer(frame.get("record_end"), "descriptor record_end")
        if (
            byte_start != self.next_byte
            or byte_end <= byte_start
            or record_start != self.next_record
            or record_end <= record_start
            or frame.get("record_count") != record_end - record_start
            or record_end - record_start > MAX_SESSION_SHARDS_RECORD_DATA_FRAMES
            or frame.get("page_shard_index") != self.shards
        ):
            raise ValueError("session-shards descriptors are not contiguous")
        self.next_byte = byte_end
        self.next_record = record_end
        self.shards += 1

    def _accept_record_frame(self, frame: Mapping[str, Any]) -> None:
        if self.data_frames >= MAX_SESSION_SHARDS_RECORD_DATA_FRAMES:
            raise ValueError("session-shards record data-frame limit exceeded")
        self.data_frames += 1
        kind = frame.get("kind")
        if kind == "record_fragment":
            self._accept_fragment(frame)
            return
        if self.fragment_state is not None or kind not in {"record", "gap"}:
            raise ValueError("session-shards record sequence is invalid")
        byte_start, byte_end, record_end = self._whole_record(frame)
        byte_count = byte_end - byte_start
        if kind == "record":
            payload = _decode_payload(frame, "record_b64", "record_commitment")
            if len(payload) != byte_count:
                raise ValueError("session-shards record byte count is invalid")
            self.records += 1
            self.record_bytes += byte_count
        else:
            if frame.get("reason") not in {
                "invalid_json",
                "record_processing_budget_exceeded",
            }:
                raise ValueError("session-shards gap reason is invalid")
            self.gaps += 1
            self.gap_bytes += byte_count
        self.accounting_hasher.update(accounting_bytes(frame))
        self.next_byte = byte_end
        self.next_record = record_end

    def _whole_record(self, frame: Mapping[str, Any]) -> tuple[int, int, int]:
        byte_start = _integer(frame.get("byte_start"), "record byte_start")
        byte_end = _integer(frame.get("byte_end"), "record byte_end", minimum=1)
        record_start = _integer(frame.get("record_start"), "record_start")
        record_end = _integer(frame.get("record_end"), "record_end")
        if (
            byte_start != self.next_byte
            or byte_end <= byte_start
            or frame.get("byte_count") != byte_end - byte_start
            or record_start != self.next_record
            or record_end != record_start + 1
        ):
            raise ValueError("session-shards record coordinates do not conserve")
        return byte_start, byte_end, record_end

    def _accept_fragment(self, frame: Mapping[str, Any]) -> None:
        byte_start = _integer(frame.get("byte_start"), "fragment byte_start")
        byte_end = _integer(frame.get("byte_end"), "fragment byte_end", minimum=1)
        record_start = _integer(frame.get("record_start"), "fragment record_start")
        record_end = _integer(frame.get("record_end"), "fragment record_end")
        index = _integer(frame.get("fragment_index"), "fragment index")
        count = _integer(frame.get("fragment_count"), "fragment count", minimum=1)
        record_byte_start = _integer(
            frame.get("record_byte_start"), "fragment record byte_start"
        )
        record_byte_end = _integer(
            frame.get("record_byte_end"), "fragment record byte_end", minimum=1
        )
        record_byte_count = record_byte_end - record_byte_start
        if self.fragment_state is None:
            if (
                index != 0
                or record_byte_start != self.next_byte
                or record_start != self.next_record
                or record_end != record_start + 1
                or frame.get("record_byte_count") != record_byte_count
            ):
                raise ValueError("session-shards fragmented record binding is invalid")
            self.fragment_state = {
                "count": count,
                "index": 0,
                "next_byte": record_byte_start,
                "record_byte_end": record_byte_end,
                "record_byte_count": record_byte_count,
                "record_commitment": frame.get("record_commitment"),
                "record_end": record_end,
                "hasher": hashlib.sha256(),
            }
        state = self.fragment_state
        assert state is not None
        payload = _decode_payload(frame, "fragment_b64", "fragment_commitment")
        if (
            count != state["count"]
            or index != state["index"]
            or byte_start != state["next_byte"]
            or byte_end <= byte_start
            or len(payload) != byte_end - byte_start
            or frame.get("byte_count") != len(payload)
            or record_byte_end != state["record_byte_end"]
            or frame.get("record_commitment") != state["record_commitment"]
        ):
            raise ValueError("session-shards fragments do not conserve")
        state["hasher"].update(payload)
        state["index"] += 1
        state["next_byte"] = byte_end
        self.fragments += 1
        self.fragment_bytes += len(payload)
        self.accounting_hasher.update(accounting_bytes(frame))
        if state["index"] == state["count"]:
            if (
                byte_end != state["record_byte_end"]
                or "sha256:" + state["hasher"].hexdigest() != state["record_commitment"]
            ):
                raise ValueError("session-shards fragmented record is incomplete")
            self.next_byte = byte_end
            self.next_record = state["record_end"]
            self.records += 1
            self.record_bytes += state["record_byte_count"]
            self.fragment_state = None

    def _accept_terminal(self, frame: Mapping[str, Any]) -> None:
        if self.fragment_state is not None:
            raise ValueError("session-shards ended inside a fragmented record")
        if self.mode == "descriptors":
            self._accept_descriptor_terminal(frame)
        else:
            self._accept_record_terminal(frame)
        self.terminal_seen = True

    def _accept_descriptor_terminal(self, frame: Mapping[str, Any]) -> None:
        assert self.initial_record is not None and self.source_bytes is not None
        complete = frame.get("complete") is True
        if (
            frame.get("emitted_shards") != self.shards
            or frame.get("byte_start") != self.byte_start
            or frame.get("byte_end") != self.next_byte
            or frame.get("record_start") != self.initial_record
            or frame.get("record_end") != self.next_record
            or frame.get("accounted_byte_count") != self.next_byte - self.byte_start
            or frame.get("accounted_record_count")
            != self.next_record - self.initial_record
        ):
            raise ValueError("session-shards descriptor terminal does not conserve")
        if complete:
            valid = (
                frame.get("reason") == "eof"
                and self.next_byte == self.source_bytes
                and frame.get("next_byte_start") is None
                and frame.get("next_record_start") is None
                and frame.get("next_resume_cursor") is None
            )
        else:
            valid = (
                frame.get("reason") == "max_shards"
                and self.shards == self.max_shards
                and frame.get("next_byte_start") == self.next_byte
                and frame.get("next_record_start") == self.next_record
                and isinstance(frame.get("next_resume_cursor"), str)
            )
        if not valid:
            raise ValueError("session-shards descriptor terminal is invalid")

    def _accept_record_terminal(self, frame: Mapping[str, Any]) -> None:
        assert self.initial_record is not None and self.byte_end is not None
        expected = {
            "emitted_records": self.records,
            "emitted_gaps": self.gaps,
            "emitted_fragments": self.fragments,
            "emitted_record_bytes": self.record_bytes,
            "emitted_gap_bytes": self.gap_bytes,
            "emitted_fragment_bytes": self.fragment_bytes,
        }
        if (
            frame.get("complete") is not True
            or frame.get("reason") != "range_complete"
            or any(frame.get(key) != value for key, value in expected.items())
            or frame.get("byte_start") != self.byte_start
            or frame.get("byte_end") != self.byte_end
            or self.next_byte != self.byte_end
            or frame.get("record_start") != self.initial_record
            or frame.get("record_end") != self.next_record
            or self.record_bytes + self.gap_bytes != self.byte_end - self.byte_start
            or self.records + self.gaps != self.next_record - self.initial_record
        ):
            raise ValueError("session-shards record terminal does not conserve")
        proof = frame.get("conservation_proof")
        expected_proof = {
            "schema": "session-shards-conservation-v1",
            "source_token": self.source_token,
            "request_binding": self.request_binding,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "byte_count": self.byte_end - self.byte_start,
            "accounted_byte_count": self.record_bytes + self.gap_bytes,
            "record_start": self.initial_record,
            "record_end": self.next_record,
            "record_count": self.next_record - self.initial_record,
            "accounted_record_count": self.records + self.gaps,
            "accounting_commitment": "sha256:" + self.accounting_hasher.hexdigest(),
        }
        if not isinstance(proof, Mapping) or dict(proof) != expected_proof:
            raise ValueError("session-shards conservation proof is invalid")
