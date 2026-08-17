#!/usr/bin/env python3
"""Scan one Codex rollout with bounded input, output, and retained state."""

from __future__ import annotations

import argparse
import codecs
from dataclasses import dataclass
import heapq
import hashlib
import json
import os
import stat
import sys
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Sequence
import uuid


SCHEMA = "codex.rollout-scan/v1"

MAX_RECORD_BYTES = 1024 * 1024
MAX_READ_BYTES = 192 * 1024 * 1024
MAX_RECORDS = 250_000
READ_CHUNK_BYTES = 64 * 1024

MAX_LITERAL_BYTES = 1024
DEFAULT_MAX_RESULTS = 20
HARD_MAX_RESULTS = 250
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
HARD_MAX_OUTPUT_BYTES = 256 * 1024
MIN_MAX_OUTPUT_BYTES = 512

MAX_HITS_PER_RECORD = 4
CONTEXT_BEFORE_CHARS = 180
CONTEXT_AFTER_CHARS = 220
MAX_METADATA_CHARS = 80
MAX_FIELD_PATH_CHARS = 512
MAX_SOURCE_PATH_UTF8_BYTES = 4096
SOURCE_PATH_DIGEST_CHARS = 16

MAX_RETAINED_SHAPES = 20
MAX_SHAPE_DEPTH = 8
MAX_SHAPE_PATHS = 32
MAX_SHAPE_KEY_CHARS = 80
MAX_SHAPE_PATH_CHARS = 128
MAX_SHAPE_OUTPUT_BYTES = 64 * 1024

EXIT_INTERNAL = 70
EXIT_IO = 74

CATEGORY_ORDER = (
    "user",
    "assistant",
    "tool_call",
    "tool_output",
    "task_complete",
    "event",
    "metadata",
)
DEFAULT_EVIDENCE_CATEGORIES = (
    "user",
    "assistant",
    "tool_call",
    "tool_output",
    "task_complete",
)

METADATA_FIELDS = (
    "id",
    "session_id",
    "thread_id",
    "turn_id",
    "cwd",
    "model",
    "model_id",
    "model_provider",
    "current_date",
    "timezone",
    "approval_policy",
    "sandbox_policy",
    "permission_profile",
    "originator",
    "source",
    "timestamp",
    "time",
    "ts",
    "created_at",
    "updated_at",
)
METADATA_OUTER_FIELDS = ("timestamp", "time", "ts", "created_at", "updated_at")

TOOL_CALL_FIELDS = {
    "function_call": ("name", "arguments"),
    "custom_tool_call": ("name", "input"),
    "computer_call": ("action",),
    "computer_tool_call": ("action",),
    "web_search_call": ("action",),
}

TOOL_OUTPUT_FIELDS = {
    "function_call_output": ("output", "content", "result"),
    "custom_tool_call_output": ("output", "content", "result"),
    "computer_call_output": ("output", "content", "result"),
    "computer_tool_call_output": ("output", "content", "result"),
}

EVENT_MSG_FIELDS = {
    "task_started": ("turn_id", "trace_id", "collaboration_mode_kind"),
    "turn_aborted": ("turn_id", "reason"),
    "stream_error": ("message", "additional_details"),
    "error": ("message",),
    "entered_review_mode": ("target", "user_facing_hint", "turn_id", "item_id"),
    "exited_review_mode": ("turn_id", "item_id", "review_output"),
}
EVENT_CONTEXT_FIELDS = ("turn_id", "item_id", "trace_id")


class OutputFailure(Exception):
    """The JSONL stream could not be written completely."""


@dataclass(frozen=True)
class Source:
    fd: int
    path: str
    device: int
    inode: int
    observed_size_bytes: int
    prefix_end_bytes: int


@dataclass(frozen=True)
class Record:
    number: int
    byte_start: int
    byte_end: int
    value: dict[str, Any]


@dataclass(frozen=True)
class Coverage:
    status: str
    stop_reason: str | None
    bytes_read: int
    complete_records: int
    complete_record_prefix_bytes: int
    tail_deferred_bytes: int


@dataclass(frozen=True)
class Evidence:
    category: str
    role: str | None
    field_path: str
    text: str


class EventWriter:
    """Write one independently parseable JSON object per flushed line."""

    def __init__(self, stream: BinaryIO | None = None, run_id: str | None = None) -> None:
        self.stream = stream if stream is not None else sys.stdout.buffer
        self.run_id = run_id or uuid.uuid4().hex
        self.seq = 0

    def encode(self, payload: dict[str, Any]) -> bytes:
        event = {
            "schema": SCHEMA,
            "event": payload["event"],
            "run_id": self.run_id,
            "seq": self.seq,
        }
        event.update({key: value for key, value in payload.items() if key != "event"})
        return (
            json.dumps(
                event,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )

    def write_encoded(self, encoded: bytes) -> None:
        try:
            written = self.stream.write(encoded)
            if written != len(encoded):
                raise OSError("short stdout write")
            self.stream.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            raise OutputFailure(str(error)) from error
        self.seq += 1

    def emit(self, payload: dict[str, Any]) -> int:
        encoded = self.encode(payload)
        self.write_encoded(encoded)
        return len(encoded)


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a base-10 integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return parsed


def _max_results(value: str) -> int:
    parsed = _nonnegative_int(value)
    if not 1 <= parsed <= HARD_MAX_RESULTS:
        raise argparse.ArgumentTypeError(
            f"expected a value from 1 through {HARD_MAX_RESULTS}"
        )
    return parsed


def _max_output_bytes(value: str) -> int:
    parsed = _nonnegative_int(value)
    if not MIN_MAX_OUTPUT_BYTES <= parsed <= HARD_MAX_OUTPUT_BYTES:
        raise argparse.ArgumentTypeError(
            f"expected a value from {MIN_MAX_OUTPUT_BYTES} through "
            f"{HARD_MAX_OUTPUT_BYTES}"
        )
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Boundedly inspect one exact Codex rollout JSONL file."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    search = subparsers.add_parser("search", help="Search selected evidence fields.")
    search.add_argument("--path", required=True)
    search.add_argument("--literal", required=True)
    search.add_argument("--mode", choices=("evidence", "user-text"), default="evidence")
    search.add_argument("--category", choices=CATEGORY_ORDER, action="append")
    search.add_argument("--result-offset", type=_nonnegative_int, default=0)
    search.add_argument(
        "--max-results", type=_max_results, default=DEFAULT_MAX_RESULTS
    )
    search.add_argument(
        "--max-output-bytes",
        type=_max_output_bytes,
        default=DEFAULT_MAX_OUTPUT_BYTES,
    )
    search.add_argument("--prefix-end-bytes", type=_nonnegative_int)

    shapes = subparsers.add_parser("shapes", help="Count bounded structural shapes.")
    shapes.add_argument("--path", required=True)
    shapes.add_argument("--prefix-end-bytes", type=_nonnegative_int)
    return parser


def _normalize_whitespace(value: str) -> str:
    return " ".join(value.split())


def _selected_categories(
    parser: argparse.ArgumentParser, mode: str, requested: list[str] | None
) -> tuple[str, ...]:
    if mode == "user-text":
        if requested and any(category != "user" for category in requested):
            parser.error("--mode user-text accepts only --category user")
        return ("user",)
    if not requested:
        return DEFAULT_EVIDENCE_CATEGORIES
    requested_set = set(requested)
    return tuple(category for category in CATEGORY_ORDER if category in requested_set)


def _validate_args(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> argparse.Namespace:
    if not os.path.isabs(args.path):
        parser.error("--path must be absolute")
    try:
        path_bytes = args.path.encode("utf-8")
    except UnicodeEncodeError:
        parser.error("--path must be valid UTF-8")
    path_digest = hashlib.sha256(path_bytes).hexdigest()
    args.source_path_utf8_bytes = len(path_bytes)
    args.source_path_sha256 = path_digest
    args.source_path_truncated = len(path_bytes) > MAX_SOURCE_PATH_UTF8_BYTES
    if args.source_path_truncated:
        prefix_budget = MAX_SOURCE_PATH_UTF8_BYTES - 4 - SOURCE_PATH_DIGEST_CHARS
        prefix = path_bytes[:prefix_budget].decode("utf-8", errors="ignore")
        args.source_path_display = f"{prefix}...#{path_digest[:SOURCE_PATH_DIGEST_CHARS]}"
    else:
        args.source_path_display = args.path
    if args.command == "search":
        normalized = _normalize_whitespace(args.literal)
        if not normalized:
            parser.error("--literal must remain nonblank after whitespace normalization")
        try:
            literal_bytes = normalized.encode("utf-8")
        except UnicodeEncodeError:
            parser.error("--literal must be valid UTF-8")
        if len(literal_bytes) > MAX_LITERAL_BYTES:
            parser.error(
                f"--literal may be at most {MAX_LITERAL_BYTES} UTF-8 bytes"
            )
        if args.result_offset > MAX_RECORDS:
            parser.error(f"--result-offset may be at most {MAX_RECORDS}")
        args.normalized_literal = normalized
        args.literal_utf8_bytes = len(literal_bytes)
        args.categories = _selected_categories(parser, args.mode, args.category)
    return args


def _open_source(path: str, prefix_end: int | None) -> tuple[Source | None, str | None]:
    flags = os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, flag_name, 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, "source_missing"
    except PermissionError:
        return None, "source_unreadable"
    except OSError:
        return None, "source_open_refused"

    try:
        source_stat = os.fstat(fd)
        if not stat.S_ISREG(source_stat.st_mode):
            os.close(fd)
            return None, "source_not_regular"
        if source_stat.st_size < 0:
            os.close(fd)
            return None, "source_size_invalid"
        selected_end = source_stat.st_size if prefix_end is None else prefix_end
        if selected_end > source_stat.st_size:
            os.close(fd)
            return None, "prefix_exceeds_source"
        return (
            Source(
                fd=fd,
                path=path,
                device=source_stat.st_dev,
                inode=source_stat.st_ino,
                observed_size_bytes=source_stat.st_size,
                prefix_end_bytes=selected_end,
            ),
            None,
        )
    except OSError:
        os.close(fd)
        return None, "source_stat_failed"


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _decode_record(raw_record: bytes) -> tuple[dict[str, Any] | None, str | None]:
    if raw_record.startswith(
        (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE, codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)
    ):
        return None, "foreign_encoding"
    if b"\x00" in raw_record[:64]:
        return None, "foreign_encoding"
    try:
        text = raw_record.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        return None, "invalid_utf8"
    if text.startswith("\ufeff"):
        return None, "second_leading_bom"
    try:
        value = json.loads(text, parse_constant=_reject_nonfinite)
    except (ValueError, RecursionError):
        return None, "malformed_json"
    if not isinstance(value, dict):
        return None, "non_object_record"
    return value, None


def _finish_at_record_budget(
    source: Source,
    buffer: bytearray,
    bytes_read: int,
    complete_records: int,
    complete_prefix: int,
) -> Coverage:
    """Classify the bounded suffix after the final eligible complete record."""

    while True:
        newline = buffer.find(b"\n")
        if newline >= 0:
            stop_reason = (
                "oversized_record"
                if newline + 1 > MAX_RECORD_BYTES
                else "record_budget_exhausted"
            )
            return Coverage(
                "partial",
                stop_reason,
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )
        if len(buffer) > MAX_RECORD_BYTES:
            return Coverage(
                "partial",
                "oversized_record",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )
        if bytes_read == source.prefix_end_bytes:
            return Coverage(
                "checked",
                None,
                bytes_read,
                complete_records,
                complete_prefix,
                len(buffer),
            )
        if bytes_read == MAX_READ_BYTES:
            return Coverage(
                "partial",
                "read_budget_exhausted",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )

        remaining = source.prefix_end_bytes - bytes_read
        budget_remaining = MAX_READ_BYTES - bytes_read
        record_lookahead = MAX_RECORD_BYTES + 1 - len(buffer)
        read_size = min(
            READ_CHUNK_BYTES, remaining, budget_remaining, record_lookahead
        )
        if read_size <= 0:
            return Coverage(
                "partial",
                "read_budget_exhausted",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )
        try:
            chunk = os.read(source.fd, read_size)
        except OSError:
            return Coverage(
                "partial",
                "source_read_failed",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )
        if not chunk:
            return Coverage(
                "partial",
                "source_truncated",
                bytes_read,
                complete_records,
                complete_prefix,
                len(buffer),
            )
        bytes_read += len(chunk)
        buffer.extend(chunk)


def _scan_records(
    source: Source, on_record: Callable[[Record], None]
) -> Coverage:
    buffer = bytearray()
    buffer_offset = 0
    bytes_read = 0
    complete_records = 0
    complete_prefix = 0

    while True:
        while True:
            newline = buffer.find(b"\n", buffer_offset)
            if newline < 0:
                break
            record_bytes = newline + 1 - buffer_offset
            if record_bytes > MAX_RECORD_BYTES:
                return Coverage(
                    "partial",
                    "oversized_record",
                    bytes_read,
                    complete_records,
                    complete_prefix,
                    0,
                )
            raw_line = bytes(buffer[buffer_offset : newline + 1])
            buffer_offset = newline + 1
            value, decode_error = _decode_record(raw_line[:-1])
            if decode_error is not None:
                return Coverage(
                    "partial",
                    decode_error,
                    bytes_read,
                    complete_records,
                    complete_prefix,
                    0,
                )
            assert value is not None
            record = Record(
                number=complete_records + 1,
                byte_start=complete_prefix,
                byte_end=complete_prefix + record_bytes,
                value=value,
            )
            on_record(record)
            complete_records += 1
            complete_prefix += record_bytes
            if complete_records == MAX_RECORDS:
                if buffer_offset:
                    del buffer[:buffer_offset]
                return _finish_at_record_budget(
                    source,
                    buffer,
                    bytes_read,
                    complete_records,
                    complete_prefix,
                )

        if buffer_offset:
            del buffer[:buffer_offset]
            buffer_offset = 0
        if len(buffer) > MAX_RECORD_BYTES:
            return Coverage(
                "partial",
                "oversized_record",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )
        if bytes_read == source.prefix_end_bytes:
            return Coverage(
                "checked",
                None,
                bytes_read,
                complete_records,
                complete_prefix,
                len(buffer),
            )
        if bytes_read == MAX_READ_BYTES:
            return Coverage(
                "partial",
                "read_budget_exhausted",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )

        remaining = source.prefix_end_bytes - bytes_read
        budget_remaining = MAX_READ_BYTES - bytes_read
        record_lookahead = MAX_RECORD_BYTES + 1 - len(buffer)
        read_size = min(
            READ_CHUNK_BYTES, remaining, budget_remaining, record_lookahead
        )
        if read_size <= 0:
            return Coverage(
                "partial",
                "read_budget_exhausted",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )
        try:
            chunk = os.read(source.fd, read_size)
        except OSError:
            return Coverage(
                "partial",
                "source_read_failed",
                bytes_read,
                complete_records,
                complete_prefix,
                0,
            )
        if not chunk:
            return Coverage(
                "partial",
                "source_truncated",
                bytes_read,
                complete_records,
                complete_prefix,
                len(buffer),
            )
        bytes_read += len(chunk)
        buffer.extend(chunk)


def _json_pointer_part(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


class _BoundedPathState:
    """Retain a fixed path prefix plus the digest of the complete logical path."""

    __slots__ = ("prefix", "char_count", "digest", "max_chars")

    def __init__(
        self, prefix: str, char_count: int, digest: Any, max_chars: int
    ) -> None:
        self.prefix = prefix
        self.char_count = char_count
        self.digest = digest
        self.max_chars = max_chars

    @classmethod
    def root(
        cls, value: str, max_chars: int = MAX_FIELD_PATH_CHARS
    ) -> "_BoundedPathState":
        digest = hashlib.sha256()
        digest.update(value.encode("utf-8", errors="surrogatepass"))
        return cls(value[:max_chars], len(value), digest, max_chars)

    def child(self, component: object) -> "_BoundedPathState":
        fragment = f"/{_json_pointer_part(component)}"
        digest = self.digest.copy()
        digest.update(fragment.encode("utf-8", errors="surrogatepass"))
        if len(self.prefix) < self.max_chars:
            prefix = (self.prefix + fragment)[: self.max_chars]
        else:
            prefix = self.prefix
        return _BoundedPathState(
            prefix,
            self.char_count + len(fragment),
            digest,
            self.max_chars,
        )

    def render(self) -> str:
        if self.char_count <= self.max_chars:
            return self.prefix
        return (
            f"{self.prefix[: self.max_chars - 20]}...#"
            f"{self.digest.hexdigest()[:16]}"
        )


def _iter_string_leaves(
    value: object,
    base_path: str,
    *,
    skip_structural_keys: bool = False,
) -> Iterator[tuple[str, str]]:
    def children(
        current: object, current_path: _BoundedPathState
    ) -> Iterator[tuple[object, _BoundedPathState]]:
        if isinstance(current, list):
            for index, nested in enumerate(current):
                yield nested, current_path.child(index)
        elif isinstance(current, dict):
            for key, nested in current.items():
                if skip_structural_keys and key in ("type", "role"):
                    continue
                yield nested, current_path.child(key)

    stack: list[Iterator[tuple[object, _BoundedPathState]]] = [
        iter(((value, _BoundedPathState.root(base_path)),))
    ]
    while stack:
        try:
            current, current_path = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(current, str):
            yield current_path.render(), current
            continue
        if isinstance(current, (list, dict)):
            stack.append(children(current, current_path))


def _payload_and_type(value: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    payload = value.get("payload")
    if not isinstance(payload, dict):
        return {}, None
    payload_type = payload.get("type")
    return payload, payload_type if isinstance(payload_type, str) else None


def _role(payload: dict[str, Any]) -> str | None:
    value = payload.get("role")
    if not isinstance(value, str):
        return None
    return value[:MAX_METADATA_CHARS]


def _iter_aliases(
    payload: dict[str, Any],
    aliases: Iterable[str],
    category: str,
    role: str | None,
    *,
    skip_structural_keys: bool = False,
) -> Iterator[Evidence]:
    for alias in aliases:
        if alias not in payload:
            continue
        path = f"/payload/{_json_pointer_part(alias)}"
        for field_path, text in _iter_string_leaves(
            payload[alias], path, skip_structural_keys=skip_structural_keys
        ):
            yield Evidence(category, role, field_path, text)


MESSAGE_TEXT_PART_TYPES = frozenset(("input_text", "output_text", "text"))
MESSAGE_CONTAINER_TYPES = frozenset(("message", "user_message", "agent_message"))


def _iter_message_texts(value: object, base_path: str) -> Iterator[tuple[str, str]]:
    """Yield only structurally identified message text, never arbitrary part fields."""

    def children(
        current: object, current_path: _BoundedPathState
    ) -> Iterator[tuple[object, _BoundedPathState]]:
        if isinstance(current, list):
            for index, nested in enumerate(current):
                yield nested, current_path.child(index)
            return
        if not isinstance(current, dict):
            return
        part_type = current.get("type")
        if part_type is not None and not isinstance(part_type, str):
            return
        if part_type in MESSAGE_TEXT_PART_TYPES:
            text = current.get("text")
            if isinstance(text, str):
                yield text, current_path.child("text")
            return
        if part_type is not None and part_type not in MESSAGE_CONTAINER_TYPES:
            return
        for alias in ("content", "message", "text"):
            nested = current.get(alias)
            if isinstance(nested, (str, list, dict)):
                yield nested, current_path.child(alias)

    stack: list[Iterator[tuple[object, _BoundedPathState]]] = [
        iter(((value, _BoundedPathState.root(base_path)),))
    ]
    while stack:
        try:
            current, current_path = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(current, str):
            yield current_path.render(), current
        elif isinstance(current, (list, dict)):
            stack.append(children(current, current_path))


def _iter_message_aliases(
    payload: dict[str, Any],
    aliases: Iterable[str],
    category: str,
    role: str | None,
) -> Iterator[Evidence]:
    for alias in aliases:
        if alias not in payload:
            continue
        path = f"/payload/{_json_pointer_part(alias)}"
        for field_path, text in _iter_message_texts(payload[alias], path):
            yield Evidence(category, role, field_path, text)


def _effective_type(
    value: dict[str, Any],
    payload: dict[str, Any],
    payload_type: object,
) -> str | None:
    if "type" in payload:
        return payload_type if isinstance(payload_type, str) else None
    outer_type = value.get("type")
    return outer_type if isinstance(outer_type, str) else None


def _iter_event_evidence(
    value: dict[str, Any],
    payload: dict[str, Any],
    payload_type: str | None,
) -> Iterator[Evidence]:
    if value.get("type") != "event_msg" or payload_type not in EVENT_MSG_FIELDS:
        return
    assert payload_type is not None
    yield Evidence("event", None, "/payload/type", payload_type)
    yield from _iter_aliases(
        payload,
        EVENT_MSG_FIELDS[payload_type],
        "event",
        None,
    )
    timestamp = value.get("timestamp")
    if isinstance(timestamp, str):
        yield Evidence("event", None, "/timestamp", timestamp)


def _iter_evidence(value: dict[str, Any]) -> Iterator[Evidence]:
    payload, payload_type = _payload_and_type(value)
    effective_type = _effective_type(value, payload, payload_type)
    role = _role(payload)

    if effective_type == "user_message":
        yield from _iter_message_aliases(
            payload,
            ("message", "text", "content"),
            "user",
            "user",
        )
    elif effective_type == "message" and role in ("user", "assistant"):
        yield from _iter_message_aliases(
            payload,
            ("content", "message", "text"),
            role,
            role,
        )
    elif effective_type == "agent_message":
        yield from _iter_message_aliases(
            payload,
            ("content", "message", "text"),
            "assistant",
            role or "assistant",
        )

    call_fields = TOOL_CALL_FIELDS.get(effective_type)
    if call_fields is not None:
        yield from _iter_aliases(payload, call_fields, "tool_call", role)
    output_fields = TOOL_OUTPUT_FIELDS.get(effective_type)
    if output_fields is not None:
        yield from _iter_aliases(payload, output_fields, "tool_output", role)
    if effective_type == "task_complete":
        yield from _iter_aliases(
            payload,
            ("last_agent_message", "message", "text", "content"),
            "task_complete",
            role,
        )
    if effective_type in ("session_meta", "turn_context"):
        yield from _iter_aliases(payload, METADATA_FIELDS, "metadata", role)
        for alias in METADATA_OUTER_FIELDS:
            nested = value.get(alias)
            if not isinstance(nested, str):
                continue
            yield Evidence("metadata", role, f"/{alias}", nested)
    yield from _iter_event_evidence(value, payload, payload_type)


def _bounded_scalar(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return _normalize_whitespace(value)[:MAX_METADATA_CHARS]


def _record_metadata(record: Record) -> dict[str, Any]:
    payload, payload_type = _payload_and_type(record.value)
    outer_type = _bounded_scalar(record.value.get("type"))
    metadata: dict[str, Any] = {
        "number": record.number,
        "line_number": record.number,
        "byte_start": record.byte_start,
        "byte_end": record.byte_end,
        "outer_type": outer_type,
        "payload_type": _bounded_scalar(payload_type),
    }
    role = _role(payload)
    if role is not None:
        metadata["role"] = role
    effective_type = _effective_type(record.value, payload, payload_type)
    if effective_type == "user_message" or (
        effective_type == "message" and role == "user"
    ):
        raw_origin_hint = payload.get("origin_hint")
        if isinstance(raw_origin_hint, str):
            origin_hint = _normalize_whitespace(raw_origin_hint)
            if origin_hint:
                metadata["origin_hint"] = origin_hint[:MAX_METADATA_CHARS]
                if len(origin_hint) > MAX_METADATA_CHARS:
                    metadata["origin_hint_truncated"] = True
    if (
        record.value.get("type") == "event_msg"
        and payload_type in EVENT_MSG_FIELDS
    ):
        for key in EVENT_CONTEXT_FIELDS:
            context_value = _bounded_scalar(payload.get(key))
            if context_value:
                metadata[key] = context_value
    timestamp = None
    for key in ("timestamp", "time", "created_at", "updated_at", "ts"):
        candidate = record.value.get(key)
        if candidate is None:
            candidate = payload.get(key)
        if isinstance(candidate, str):
            timestamp = _normalize_whitespace(candidate)[:MAX_METADATA_CHARS]
            break
    if timestamp:
        metadata["timestamp"] = timestamp
    return metadata


def _snippet(text: str, literal: str) -> dict[str, Any]:
    index = text.find(literal)
    before_start = max(0, index - CONTEXT_BEFORE_CHARS)
    after_end = min(len(text), index + len(literal) + CONTEXT_AFTER_CHARS)
    return {
        "snippet": text[before_start:after_end],
        "truncated_before": before_start > 0,
        "truncated_after": after_end < len(text),
    }


def _match_record(
    record: Record, literal: str, categories: set[str]
) -> tuple[list[dict[str, Any]], int, set[str]]:
    retained: list[dict[str, Any]] = []
    observed = 0
    matched_categories: set[str] = set()
    for evidence in _iter_evidence(record.value):
        if evidence.category not in categories:
            continue
        normalized = _normalize_whitespace(evidence.text)
        if literal not in normalized:
            continue
        observed += 1
        matched_categories.add(evidence.category)
        if len(retained) >= MAX_HITS_PER_RECORD:
            continue
        hit = {
            "category": evidence.category,
            "field_path": evidence.field_path,
            "role": evidence.role,
        }
        hit.update(_snippet(normalized, literal))
        retained.append(hit)
    return retained, observed, matched_categories


def _compact_match_event(
    record: Record,
    result_index: int,
    hits_observed: int,
    matched_categories: set[str],
    full_event_bytes: int,
) -> dict[str, Any]:
    """Retain result identity and category coverage when details cannot fit."""

    return {
        "event": "match",
        "result_index": result_index,
        "record": {
            "number": record.number,
            "line_number": record.number,
            "byte_start": record.byte_start,
            "byte_end": record.byte_end,
        },
        "matched_categories": [
            category
            for category in CATEGORY_ORDER
            if category in matched_categories
        ],
        "hits": [],
        "hits_observed": hits_observed,
        "hits_truncated": True,
        "details_truncated": True,
        "full_event_bytes": full_event_bytes,
    }


def _start_payload(
    args: argparse.Namespace, source: Source | None, unavailable_reason: str | None
) -> dict[str, Any]:
    source_payload: dict[str, Any] = {
        "path": args.source_path_display,
        "path_sha256": args.source_path_sha256,
        "path_truncated": args.source_path_truncated,
        "path_utf8_bytes": args.source_path_utf8_bytes,
    }
    if source is not None:
        source_payload.update(
            {
                "device": source.device,
                "inode": source.inode,
                "observed_size_bytes": source.observed_size_bytes,
                "frozen_prefix_bytes": source.prefix_end_bytes,
            }
        )
    payload: dict[str, Any] = {
        "event": "start",
        "command": args.command,
        "source": source_payload,
        "observation": {
            "basis": "descriptor-prefix-observation",
            "content_stability": "not-proven",
        },
        "limits": {
            "max_record_bytes": MAX_RECORD_BYTES,
            "max_read_bytes": MAX_READ_BYTES,
            "max_records": MAX_RECORDS,
            "max_source_path_utf8_bytes": MAX_SOURCE_PATH_UTF8_BYTES,
        },
    }
    if unavailable_reason is not None:
        payload["source_status"] = unavailable_reason
    if args.command == "search":
        payload["query"] = {
            "categories": list(args.categories),
            "literal_sha256": hashlib.sha256(
                args.normalized_literal.encode("utf-8")
            ).hexdigest(),
            "literal_utf8_bytes": args.literal_utf8_bytes,
            "mode": args.mode,
        }
        payload["window"] = {
            "max_output_bytes": args.max_output_bytes,
            "max_results": args.max_results,
            "result_offset": args.result_offset,
        }
    else:
        payload["limits"]["max_shape_output_bytes"] = MAX_SHAPE_OUTPUT_BYTES
    return payload


def _coverage_payload(source: Source | None, coverage: Coverage | None) -> dict[str, Any]:
    if coverage is None:
        return {
            "bytes_read": 0,
            "complete_record_prefix_bytes": 0,
            "complete_records": 0,
            "tail_deferred_bytes": 0,
        }
    return {
        "bytes_read": coverage.bytes_read,
        "complete_record_prefix_bytes": coverage.complete_record_prefix_bytes,
        "complete_records": coverage.complete_records,
        "tail_deferred_bytes": coverage.tail_deferred_bytes,
    }


def _end_base(
    source: Source | None,
    coverage: Coverage | None,
    status: str,
    stop_reason: str | None,
) -> dict[str, Any]:
    return {
        "event": "end",
        "status": status,
        "stop_reason": stop_reason,
        "continuity": "independent-descriptor-prefix-observation",
        "frozen_prefix_bytes": source.prefix_end_bytes if source is not None else None,
        "coverage": _coverage_payload(source, coverage),
    }


def _run_search(
    args: argparse.Namespace, source: Source | None, reason: str | None, writer: EventWriter
) -> int:
    writer.emit(_start_payload(args, source, reason))
    if source is None:
        end = _end_base(None, None, "unavailable", reason)
        end.update(
            {
                "next_result_offset": None,
                "search": {
                    "emitted_records": 0,
                    "matched_records": 0,
                    "result_bytes": 0,
                    "result_offset": args.result_offset,
                    "suppressed_records": 0,
                },
                "category_stats": {
                    category: {
                        "matched_records": 0,
                        "emitted_records": 0,
                        "suppressed_records": 0,
                    }
                    for category in CATEGORY_ORDER
                },
            }
        )
        writer.emit(end)
        return 0

    selected = set(args.categories)
    category_matched = {category: 0 for category in CATEGORY_ORDER}
    category_emitted = {category: 0 for category in CATEGORY_ORDER}
    matched_records = 0
    emitted_records = 0
    emitted_bytes = 0
    presentation_open = True

    def on_record(record: Record) -> None:
        nonlocal matched_records, emitted_records, emitted_bytes, presentation_open
        hits, hits_observed, matched_categories = _match_record(
            record, args.normalized_literal, selected
        )
        if not matched_categories:
            return
        result_index = matched_records
        matched_records += 1
        for category in matched_categories:
            category_matched[category] += 1
        if result_index < args.result_offset or not presentation_open:
            return
        if emitted_records >= args.max_results:
            presentation_open = False
            return
        event = {
            "event": "match",
            "result_index": result_index,
            "record": _record_metadata(record),
            "hits": hits,
            "hits_observed": hits_observed,
            "hits_truncated": hits_observed > len(hits),
        }
        encoded = writer.encode(event)
        emitted_hit_categories = {hit["category"] for hit in hits}
        if emitted_bytes + len(encoded) > args.max_output_bytes:
            if emitted_records:
                presentation_open = False
                return
            compact_event = _compact_match_event(
                record,
                result_index,
                hits_observed,
                matched_categories,
                len(encoded),
            )
            encoded = writer.encode(compact_event)
            if len(encoded) > args.max_output_bytes:
                raise RuntimeError(
                    "compact match event exceeded the legal output budget"
                )
            emitted_hit_categories = matched_categories
        writer.write_encoded(encoded)
        emitted_bytes += len(encoded)
        emitted_records += 1
        for category in emitted_hit_categories:
            category_emitted[category] += 1

    coverage = _scan_records(source, on_record)
    end = _end_base(
        source, coverage, coverage.status, coverage.stop_reason
    )
    next_offset = args.result_offset + emitted_records
    if matched_records <= next_offset:
        next_offset_value: int | None = None
    else:
        next_offset_value = next_offset
    category_stats = {}
    for category in CATEGORY_ORDER:
        matched = category_matched[category]
        emitted = category_emitted[category]
        category_stats[category] = {
            "matched_records": matched,
            "emitted_records": emitted,
            "suppressed_records": matched - emitted,
        }
    end.update(
        {
            "next_result_offset": next_offset_value,
            "search": {
                "emitted_records": emitted_records,
                "matched_records": matched_records,
                "result_bytes": emitted_bytes,
                "result_offset": args.result_offset,
                "suppressed_records": matched_records - emitted_records,
            },
            "category_stats": category_stats,
        }
    )
    writer.emit(end)
    return 0


def _shape_scalar(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = _normalize_whitespace(value)
    if len(normalized) <= MAX_SHAPE_KEY_CHARS:
        return normalized
    digest = hashlib.sha256(normalized.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]
    return f"{normalized[: MAX_SHAPE_KEY_CHARS - 20]}...#{digest}"


def _value_kind(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _shape_of(value: dict[str, Any]) -> dict[str, Any]:
    payload, payload_type = _payload_and_type(value)
    paths: list[dict[str, str]] = []
    paths_truncated = False
    stack: list[tuple[object, _BoundedPathState, int]] = [
        (value, _BoundedPathState.root("", MAX_SHAPE_PATH_CHARS), 0)
    ]
    while stack:
        current, current_path, depth = stack.pop()
        if len(paths) >= MAX_SHAPE_PATHS:
            paths_truncated = True
            break
        if current_path.char_count:
            paths.append(
                {"path": current_path.render(), "kind": _value_kind(current)}
            )
        if depth >= MAX_SHAPE_DEPTH:
            if isinstance(current, (dict, list)) and current:
                paths_truncated = True
            continue
        remaining = MAX_SHAPE_PATHS - len(paths)
        if isinstance(current, dict):
            if len(current) > remaining:
                paths_truncated = True
            items = heapq.nsmallest(remaining, current.items(), key=lambda item: item[0])
            for key, nested in reversed(items):
                stack.append(
                    (
                        nested,
                        current_path.child(key),
                        depth + 1,
                    )
                )
        elif isinstance(current, list):
            if len(current) > remaining:
                paths_truncated = True
            for index in range(min(len(current), remaining) - 1, -1, -1):
                stack.append((current[index], current_path.child(index), depth + 1))
    paths.sort(key=lambda item: (item["path"], item["kind"]))
    return {
        "outer_type": _shape_scalar(value.get("type")),
        "payload_type": _shape_scalar(payload_type),
        "role": _shape_scalar(payload.get("role")),
        "field_paths": paths,
        "paths_truncated": paths_truncated,
    }


def _run_shapes(
    args: argparse.Namespace, source: Source | None, reason: str | None, writer: EventWriter
) -> int:
    writer.emit(_start_payload(args, source, reason))
    if source is None:
        end = _end_base(None, None, "unavailable", reason)
        end["shapes"] = {
            "emitted_shapes": 0,
            "output_bytes": 0,
            "output_truncated": False,
            "retained_distinct_shapes": 0,
            "suppressed_shapes": 0,
            "unretained_records": 0,
        }
        writer.emit(end)
        return 0

    retained: dict[str, dict[str, Any]] = {}
    retained_order: list[str] = []
    unretained_records = 0

    def on_record(record: Record) -> None:
        nonlocal unretained_records
        shape = _shape_of(record.value)
        key = json.dumps(
            shape,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        existing = retained.get(key)
        if existing is not None:
            existing["records_observed"] += 1
            return
        if len(retained_order) < MAX_RETAINED_SHAPES:
            retained[key] = {"shape": shape, "records_observed": 1}
            retained_order.append(key)
            return
        unretained_records += 1

    coverage = _scan_records(source, on_record)
    emitted_shapes = 0
    shape_output_bytes = 0
    presentation_open = True
    for shape_index, key in enumerate(retained_order):
        if not presentation_open:
            continue
        retained_shape = retained[key]
        event = {
            "event": "shape",
            "shape_index": shape_index,
            "shape": retained_shape["shape"],
            "records_observed": retained_shape["records_observed"],
        }
        encoded = writer.encode(event)
        if shape_output_bytes + len(encoded) > MAX_SHAPE_OUTPUT_BYTES:
            presentation_open = False
            continue
        writer.write_encoded(encoded)
        shape_output_bytes += len(encoded)
        emitted_shapes += 1
    end = _end_base(source, coverage, coverage.status, coverage.stop_reason)
    end["shapes"] = {
        "emitted_shapes": emitted_shapes,
        "output_bytes": shape_output_bytes,
        "output_truncated": emitted_shapes < len(retained_order),
        "retained_distinct_shapes": len(retained_order),
        "suppressed_shapes": len(retained_order) - emitted_shapes,
        "unretained_records": unretained_records,
    }
    writer.emit(end)
    return 0


def main(argv: Sequence[str] | None = None, stream: BinaryIO | None = None) -> int:
    parser = _build_parser()
    args = _validate_args(parser, parser.parse_args(argv))
    writer = EventWriter(stream=stream)
    source, reason = _open_source(args.path, args.prefix_end_bytes)
    try:
        if args.command == "search":
            return _run_search(args, source, reason, writer)
        return _run_shapes(args, source, reason, writer)
    except OutputFailure:
        return EXIT_IO
    except Exception as error:
        print(f"scan_rollout internal error: {type(error).__name__}", file=sys.stderr)
        return EXIT_INTERNAL
    finally:
        if source is not None:
            try:
                os.close(source.fd)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
