"""Local structured sharding and remote session-shard delegation."""

from __future__ import annotations

import argparse
import base64
import codecs
import contextlib
from dataclasses import dataclass
import hashlib
import json
import math
import os
import pathlib
import sys
import tempfile
from typing import Any, Callable, Iterable

from . import safe_io
from .contracts import (
    MAX_JSON_INTEGER,
    SESSION_SHARDS_PREFIX_COMMITMENT_DOMAIN,
    session_shards_resume_cursor,
    session_shards_resume_cursor_value,
)
from .session_shards_relay import (
    MAX_SESSION_SHARDS_RECORD_DATA_FRAMES,
    RemoteSessionShardsFilter,
    accounting_bytes as _session_shards_accounting_bytes,
    descriptor_data_frames as _session_shards_descriptor_data_frames,
    remote_output_limit as _session_shards_remote_output_limit,
)
from .transport_contracts import (
    _TOKEN_RE,
)
from .transport_paths import _resolve_rollout_relative_path
from .transport_remote import (
    _relay_remote_host_context_command,
    _remote_host_context_command,
)
from .transport_resume import _source_object_generation
from .transport_source import (
    _AnchoredCodexRoot,
    _local_codex_root,
    _open_lexical_codex_root,
    _open_relative_from_codex_root,
)

DEFAULT_SESSION_SHARD_BYTES = 512 * 1024
MAX_SESSION_SHARD_BYTES = 512 * 1024
DEFAULT_SESSION_SHARDS_PER_PAGE = 64
MAX_SESSION_SHARDS_PER_PAGE = 1024
DEFAULT_SESSION_RECORD_PROCESSING_BUDGET_BYTES = 64 * 1024 * 1024
HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES = 256 * 1024 * 1024
MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES = 4 * 1024 * 1024
MAX_SESSION_SHARDS_RANGE_BYTES = HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES
SESSION_SHARDS_RECORD_FRAGMENT_BYTES = 256 * 1024
SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES = 64 * 1024
SESSION_SHARDS_RECORD_SPOOL_MEMORY_BYTES = 64 * 1024
SESSION_SHARDS_JSON_VALIDATION_CHUNK_BYTES = 64 * 1024
SESSION_SHARDS_MAX_JSON_NESTING_DEPTH = 512
SESSION_SHARDS_FRAME_METADATA_CHARS = 16 * 1024
MAX_SESSION_SHARDS_FRAME_CHARS = (
    4 * ((max(MAX_SESSION_SHARD_BYTES, SESSION_SHARDS_RECORD_FRAGMENT_BYTES) + 2) // 3)
    + SESSION_SHARDS_FRAME_METADATA_CHARS
)
SESSION_SHARDS_SCHEMA = "session-shards-v1"
SESSION_SHARDS_SOURCE_TOKEN_PREFIX = "session_shards_source_v2:"
SESSION_SHARDS_RESUME_CURSOR_PREFIX = "session_shards_resume_v1:"
SESSION_SHARDS_REQUEST_BINDING_PREFIX = "session_shards_request_v1:"
SESSION_SHARDS_SOURCE_TOKEN_DOMAIN = b"session-shards-source-token-v2\0"

SESSION_SHARDS_PROTOCOL_FEATURES = (
    "oversized_record_fragments_v1",
    "terminal_conservation_v1",
    "request_binding_v1",
    "resume_cursor_v1",
    "record_data_frame_limit_v1",
    "descriptor_page_frame_limit_v1",
)


@dataclass
class SessionShardRecord:
    byte_start: int
    byte_end: int
    record_index: int
    record_storage: Any | None
    record_commitment: str | None
    delimiter_bytes: int
    gap_reason: str | None
    processing_ceiling_kind: str | None
    processing_ceiling_limit: int | None
    processing_ceiling_observed: int | None


class _SessionShardsProcessingBudgetExceeded(ValueError):
    def __init__(self, *, kind: str, limit: int, observed: int) -> None:
        super().__init__(f"{kind} processing ceiling exceeded: {observed} > {limit}")
        self.kind = kind
        self.limit = limit
        self.observed = observed


class _IncrementalJSONObjectValidator:
    _WHITESPACE = frozenset(" \t\r\n")
    _HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
    _SIMPLE_ESCAPES = frozenset('"\\/bfnrt')
    _NUMBER_TERMINAL_STATES = frozenset(
        {"zero", "integer", "fraction", "exponent_digits"}
    )

    def __init__(self) -> None:
        self.stack: list[list[str]] = []
        self.root_started = False
        self.root_complete = False
        self.token_kind: str | None = None
        self.string_is_key = False
        self.string_escape = False
        self.unicode_escape_remaining = 0
        self.literal_remaining = ""
        self.number_state: str | None = None
        self.number_token = ""
        self.position = 0

    def _invalid(self, detail: str) -> None:
        raise ValueError(f"invalid JSON object at character {self.position}: {detail}")

    def _push_container(self, kind: str, state: str) -> None:
        if len(self.stack) >= SESSION_SHARDS_MAX_JSON_NESTING_DEPTH:
            raise _SessionShardsProcessingBudgetExceeded(
                kind="json_nesting_depth",
                limit=SESSION_SHARDS_MAX_JSON_NESTING_DEPTH,
                observed=len(self.stack) + 1,
            )
        self.stack.append([kind, state])

    def _complete_value(self) -> None:
        if not self.stack:
            self.root_complete = True
            return
        frame = self.stack[-1]
        if frame[1] != "value":
            self._invalid("value appeared in an invalid container state")
        frame[1] = "comma_or_end"

    def _close_container(self, kind: str) -> None:
        if not self.stack or self.stack[-1][0] != kind:
            self._invalid("mismatched container terminator")
        self.stack.pop()
        self._complete_value()

    def _start_string(self, *, is_key: bool) -> None:
        self.token_kind = "string"
        self.string_is_key = is_key
        self.string_escape = False
        self.unicode_escape_remaining = 0

    def _start_value(self, character: str) -> None:
        if character in self._WHITESPACE:
            return
        if character == "{":
            self._push_container("object", "key_or_end")
        elif character == "[":
            self._push_container("array", "value_or_end")
        elif character == '"':
            self._start_string(is_key=False)
        elif character in "tfn":
            self.token_kind = "literal"
            self.literal_remaining = {
                "t": "rue",
                "f": "alse",
                "n": "ull",
            }[character]
        elif character == "-":
            self.token_kind = "number"
            self.number_state = "sign"
            self.number_token = character
        elif character == "0":
            self.token_kind = "number"
            self.number_state = "zero"
            self.number_token = character
        elif "1" <= character <= "9":
            self.token_kind = "number"
            self.number_state = "integer"
            self.number_token = character
        else:
            self._invalid("expected a JSON value")

    def _consume_string(self, character: str) -> None:
        if self.unicode_escape_remaining:
            if character not in self._HEX_DIGITS:
                self._invalid("invalid unicode escape")
            self.unicode_escape_remaining -= 1
            return
        if self.string_escape:
            self.string_escape = False
            if character == "u":
                self.unicode_escape_remaining = 4
            elif character not in self._SIMPLE_ESCAPES:
                self._invalid("invalid string escape")
            return
        if character == "\\":
            self.string_escape = True
            return
        if character == '"':
            self.token_kind = None
            if self.string_is_key:
                if (
                    not self.stack
                    or self.stack[-1][0] != "object"
                    or self.stack[-1][1] not in ("key", "key_or_end")
                ):
                    self._invalid("object key appeared in an invalid state")
                self.stack[-1][1] = "colon"
            else:
                self._complete_value()
            return
        if ord(character) < 0x20:
            self._invalid("unescaped control character in string")

    def _consume_literal(self, character: str) -> None:
        if not self.literal_remaining or character != self.literal_remaining[0]:
            self._invalid("invalid literal")
        self.literal_remaining = self.literal_remaining[1:]
        if not self.literal_remaining:
            self.token_kind = None
            self._complete_value()

    def _consume_number(self, character: str) -> bool:
        state = self.number_state
        if state == "sign":
            if character == "0":
                self.number_state = "zero"
            elif "1" <= character <= "9":
                self.number_state = "integer"
            else:
                self._invalid("minus must be followed by a digit")
            self.number_token += character
            return True
        if state == "zero":
            if character == ".":
                self.number_state = "decimal_point"
                self.number_token += character
                return True
            if character in "eE":
                self.number_state = "exponent"
                self.number_token += character
                return True
            if "0" <= character <= "9":
                self._invalid("leading zero in number")
            return False
        if state == "integer":
            if "0" <= character <= "9":
                self.number_token += character
                return True
            if character == ".":
                self.number_state = "decimal_point"
                self.number_token += character
                return True
            if character in "eE":
                self.number_state = "exponent"
                self.number_token += character
                return True
            return False
        if state == "decimal_point":
            if "0" <= character <= "9":
                self.number_state = "fraction"
                self.number_token += character
                return True
            self._invalid("decimal point must be followed by a digit")
        if state == "fraction":
            if "0" <= character <= "9":
                self.number_token += character
                return True
            if character in "eE":
                self.number_state = "exponent"
                self.number_token += character
                return True
            return False
        if state == "exponent":
            if character in "+-":
                self.number_state = "exponent_sign"
            elif "0" <= character <= "9":
                self.number_state = "exponent_digits"
            else:
                self._invalid("exponent must contain a digit")
            self.number_token += character
            return True
        if state == "exponent_sign":
            if not "0" <= character <= "9":
                self._invalid("exponent sign must be followed by a digit")
            self.number_state = "exponent_digits"
            self.number_token += character
            return True
        if state == "exponent_digits":
            if "0" <= character <= "9":
                self.number_token += character
                return True
            return False
        self._invalid("invalid number state")
        return False

    def _finish_number(self) -> None:
        if self.number_state not in self._NUMBER_TERMINAL_STATES:
            self._invalid("incomplete number")
        token = self.number_token
        if len(token) > 128:
            self._invalid("number exceeds the strict numeric token bound")
        try:
            if any(character in token for character in ".eE"):
                value = float(token)
                if not math.isfinite(value):
                    self._invalid("number is not finite")
            elif abs(int(token)) > MAX_JSON_INTEGER:
                self._invalid("integer exceeds the signed 64-bit model")
        except (OverflowError, ValueError):
            self._invalid("number is malformed")
        self.token_kind = None
        self.number_state = None
        self.number_token = ""
        self._complete_value()

    def _consume_structure(self, character: str) -> None:
        if self.root_complete:
            if character not in self._WHITESPACE:
                self._invalid("trailing data after root object")
            return
        if not self.root_started:
            if character in self._WHITESPACE or (
                self.position == 0 and character == "\ufeff"
            ):
                return
            if character != "{":
                self._invalid("JSONL record must be an object")
            self.root_started = True
            self._push_container("object", "key_or_end")
            return
        if not self.stack:
            self._invalid("unexpected data after root object")
        frame = self.stack[-1]
        kind, state = frame
        if kind == "object":
            if state in ("key", "key_or_end"):
                if character in self._WHITESPACE:
                    return
                if state == "key_or_end" and character == "}":
                    self._close_container("object")
                elif character == '"':
                    self._start_string(is_key=True)
                else:
                    self._invalid("expected an object key")
            elif state == "colon":
                if character in self._WHITESPACE:
                    return
                if character != ":":
                    self._invalid("expected colon after object key")
                frame[1] = "value"
            elif state == "value":
                self._start_value(character)
            elif state == "comma_or_end":
                if character in self._WHITESPACE:
                    return
                if character == ",":
                    frame[1] = "key"
                elif character == "}":
                    self._close_container("object")
                else:
                    self._invalid("expected comma or object terminator")
            else:
                self._invalid("invalid object parser state")
            return
        if kind == "array":
            if state in ("value", "value_or_end"):
                if character in self._WHITESPACE:
                    return
                if state == "value_or_end" and character == "]":
                    self._close_container("array")
                else:
                    frame[1] = "value"
                    self._start_value(character)
            elif state == "comma_or_end":
                if character in self._WHITESPACE:
                    return
                if character == ",":
                    frame[1] = "value"
                elif character == "]":
                    self._close_container("array")
                else:
                    self._invalid("expected comma or array terminator")
            else:
                self._invalid("invalid array parser state")
            return
        self._invalid("invalid container kind")

    def feed(self, text: str) -> None:
        for character in text:
            while True:
                if self.token_kind == "string":
                    self._consume_string(character)
                    break
                if self.token_kind == "literal":
                    self._consume_literal(character)
                    break
                if self.token_kind == "number":
                    if self._consume_number(character):
                        break
                    self._finish_number()
                    continue
                self._consume_structure(character)
                break
            self.position += 1

    def finish(self) -> None:
        if self.token_kind == "number":
            self._finish_number()
        elif self.token_kind is not None:
            self._invalid("incomplete JSON token")
        if not self.root_complete or self.stack:
            self._invalid("incomplete root object")


def _validate_session_shards_json_storage(storage: Any) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    validator = _IncrementalJSONObjectValidator()
    storage.seek(0)
    while True:
        chunk = storage.read(SESSION_SHARDS_JSON_VALIDATION_CHUNK_BYTES)
        if not chunk:
            break
        validator.feed(decoder.decode(chunk, final=False))
    validator.feed(decoder.decode(b"", final=True))
    validator.finish()
    storage.seek(0)


def _session_shards_source_identity(stat_result: os.stat_result) -> tuple[int, ...]:
    generation, birthtime_ns = _source_object_generation(stat_result)
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat_result.st_mode),
        int(stat_result.st_uid),
        int(stat_result.st_gid),
        generation,
        birthtime_ns,
    )


def _session_shards_source_identity_bytes(identity: tuple[int, ...]) -> bytes:
    return json.dumps(identity, separators=(",", ":")).encode("ascii")


def _session_shards_source_token(identity: tuple[int, ...]) -> str:
    encoded = (
        SESSION_SHARDS_SOURCE_TOKEN_DOMAIN
        + _session_shards_source_identity_bytes(identity)
    )
    return SESSION_SHARDS_SOURCE_TOKEN_PREFIX + hashlib.sha256(encoded).hexdigest()


def _session_shards_resume_cursor(
    source_token: str,
    *,
    cursor_kind: str,
    frozen_byte_end: int,
    byte_offset: int,
    next_record_index: int,
    prefix_commitment: str,
) -> str:
    return session_shards_resume_cursor(
        source_token,
        cursor_kind=cursor_kind,
        frozen_byte_end=frozen_byte_end,
        byte_offset=byte_offset,
        next_record_index=next_record_index,
        prefix_commitment=prefix_commitment,
    )


def _session_shards_decode_resume_cursor(
    cursor: str,
) -> tuple[bytes, str, dict[str, Any]]:
    try:
        value = session_shards_resume_cursor_value(cursor)
    except ValueError as exc:
        raise ValueError("invalid session-shards resume cursor") from exc
    payload = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    signature = cursor.rsplit(".", 1)[1]
    return payload, signature, value


def _session_shards_parse_resume_cursor(
    cursor: str,
    expected_source_token: str,
) -> dict[str, Any]:
    _payload, _signature, value = _session_shards_decode_resume_cursor(cursor)
    if value.get("source_token") != expected_source_token:
        raise ValueError("invalid session-shards resume cursor")
    return value


def _session_shards_request_binding(
    *,
    rollout: str,
    mode: str,
    source_token: str | None,
    byte_start: int,
    byte_end: int | None,
    shard_bytes: int,
    max_shards: int,
    record_processing_budget_bytes: int,
    resume_cursor: str | None,
) -> str:
    payload = json.dumps(
        {
            "byte_end": byte_end,
            "byte_start": byte_start,
            "max_shards": max_shards,
            "mode": mode,
            "record_processing_budget_bytes": record_processing_budget_bytes,
            "rollout": rollout,
            "resume_cursor": resume_cursor,
            "schema": SESSION_SHARDS_SCHEMA,
            "shard_bytes": shard_bytes,
            "source_token": source_token,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return SESSION_SHARDS_REQUEST_BINDING_PREFIX + hashlib.sha256(payload).hexdigest()


def _open_session_shard_source(
    codex_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
    *,
    component_hook: Callable[[int, str, int], None] | None = None,
) -> Any:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    supports_dir_fd = getattr(os, "supports_dir_fd", frozenset())
    if not nofollow or not directory or os.open not in supports_dir_fd:
        raise RuntimeError("session-shards secure openat traversal is unsupported")

    anchor: _AnchoredCodexRoot | None = None
    try:
        anchor = _open_lexical_codex_root(codex_root)
        file_fd, _identities = _open_relative_from_codex_root(
            anchor,
            rollout_relative_path,
            expect_regular_file=True,
            hook_name="_SESSION_SHARDS_OPEN_COMPONENT_HOOK",
            component_hook=component_hook,
        )
        return os.fdopen(file_fd, "rb")
    finally:
        if anchor is not None:
            anchor.close()


def _validate_session_shards_boundary(
    handle: Any,
    *,
    byte_offset: int,
    source_bytes: int,
    option: str,
) -> None:
    if byte_offset < 0 or byte_offset > source_bytes:
        raise ValueError(f"{option} must stay between 0 and {source_bytes}")
    if byte_offset in (0, source_bytes):
        return
    handle.seek(byte_offset - 1)
    if handle.read(1) != b"\n":
        raise ValueError(f"{option} must be on a JSONL record boundary")


def _session_shards_prefix_hasher() -> Any:
    hasher = hashlib.sha256()
    hasher.update(SESSION_SHARDS_PREFIX_COMMITMENT_DOMAIN)
    hasher.update(b"bytes\0")
    return hasher


def _session_shards_frozen_prefix_commitment(
    handle: Any,
    *,
    frozen_byte_end: int,
) -> str:
    hasher = _session_shards_prefix_hasher()
    handle.seek(0)
    remaining = frozen_byte_end
    while remaining:
        chunk = handle.read(min(SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES, remaining))
        if not chunk:
            raise ValueError("rollout ended before its frozen prefix was committed")
        hasher.update(chunk)
        remaining -= len(chunk)
    return "sha256:" + hasher.hexdigest()


def _spool_verified_session_shards_range(
    handle: Any,
    *,
    frozen_byte_end: int,
    records_byte_start: int,
    records_byte_end: int,
    expected_record_start: int,
    expected_prefix_commitment: str,
) -> Any:
    storage = tempfile.TemporaryFile(mode="w+b")
    try:
        safe_io.harden_created_owner_only_file_descriptor(
            storage.fileno(),
            pathlib.Path("<session-shards-verified-spool>"),
            single_link=False,
        )
        handle.seek(0)
        byte_offset = 0
        record_index = 0
        prefix_hasher = _session_shards_prefix_hasher()
        observed_record_start: int | None = None
        while byte_offset < frozen_byte_end:
            if byte_offset == records_byte_start:
                observed_record_start = record_index
            total_bytes = 0
            final_segment = b""
            while byte_offset + total_bytes < frozen_byte_end:
                remaining = frozen_byte_end - byte_offset - total_bytes
                segment = handle.readline(
                    min(SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES, remaining)
                )
                if not segment:
                    raise ValueError(
                        "rollout ended before the frozen prefix was verified"
                    )
                segment_start = byte_offset + total_bytes
                segment_end = segment_start + len(segment)
                spool_start = max(segment_start, records_byte_start)
                spool_end = min(segment_end, records_byte_end)
                if spool_start < spool_end:
                    storage.write(
                        segment[spool_start - segment_start : spool_end - segment_start]
                    )
                prefix_hasher.update(segment)
                total_bytes += len(segment)
                final_segment = segment
                if segment.endswith(b"\n"):
                    break
            if (
                not final_segment.endswith(b"\n")
                and byte_offset + total_bytes < frozen_byte_end
            ):
                raise ValueError("frozen byte end is inside a JSONL record")
            byte_offset += total_bytes
            record_index += 1
        if byte_offset != frozen_byte_end:
            raise ValueError("frozen session-shards prefix did not conserve bytes")
        if records_byte_start == frozen_byte_end:
            observed_record_start = record_index
        if observed_record_start != expected_record_start:
            raise ValueError(
                "records cursor does not match the frozen JSONL record boundary"
            )
        if "sha256:" + prefix_hasher.hexdigest() != expected_prefix_commitment:
            raise ValueError("frozen rollout prefix commitment mismatch")
        if storage.tell() != records_byte_end - records_byte_start:
            raise RuntimeError("session-shards verified range spool lost source bytes")
        storage.flush()
        storage.seek(0)
        return storage
    except BaseException:
        storage.close()
        raise


def _iter_session_shard_records(
    handle: Any,
    *,
    byte_start: int,
    byte_end: int,
    record_start: int,
    record_processing_budget_bytes: int,
    coordinate_offset: int = 0,
) -> Iterable[SessionShardRecord]:
    handle.seek(byte_start)
    byte_offset = byte_start
    record_index = record_start
    while byte_offset < byte_end:
        storage: Any | None = tempfile.SpooledTemporaryFile(
            max_size=SESSION_SHARDS_RECORD_SPOOL_MEMORY_BYTES,
            mode="w+b",
        )
        try:
            storage.rollover()
            safe_io.harden_created_owner_only_file_descriptor(
                storage.fileno(),
                pathlib.Path("<session-shards-record-spool>"),
                single_link=False,
            )
            record_hasher = hashlib.sha256()
            total_bytes = 0
            over_processing_budget = False
            final_segment = b""
            record_tail = b""
            while byte_offset + total_bytes < byte_end:
                remaining = byte_end - byte_offset - total_bytes
                segment = handle.readline(
                    min(SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES, remaining)
                )
                if not segment:
                    raise ValueError(
                        "rollout ended before the requested byte range was read"
                    )
                total_bytes += len(segment)
                final_segment = segment
                record_tail = (record_tail + segment)[-2:]
                if not over_processing_budget:
                    if total_bytes <= record_processing_budget_bytes:
                        assert storage is not None
                        storage.write(segment)
                        record_hasher.update(segment)
                    else:
                        storage.close()
                        storage = None
                        over_processing_budget = True
                if segment.endswith(b"\n"):
                    break

            if (
                not final_segment.endswith(b"\n")
                and byte_offset + total_bytes < byte_end
            ):
                raise ValueError("rollout ended inside a JSONL record")

            gap_reason: str | None = None
            record_commitment: str | None = None
            processing_ceiling_kind: str | None = None
            processing_ceiling_limit: int | None = None
            processing_ceiling_observed: int | None = None
            delimiter_bytes = (
                2 if record_tail == b"\r\n" else int(record_tail.endswith(b"\n"))
            )
            if over_processing_budget:
                gap_reason = "record_processing_budget_exceeded"
                processing_ceiling_kind = "record_bytes"
                processing_ceiling_limit = record_processing_budget_bytes
                processing_ceiling_observed = total_bytes
            else:
                assert storage is not None
                if storage.tell() != total_bytes:
                    raise RuntimeError("session-shards record spool lost source bytes")
                try:
                    _validate_session_shards_json_storage(storage)
                except _SessionShardsProcessingBudgetExceeded as exc:
                    gap_reason = "record_processing_budget_exceeded"
                    processing_ceiling_kind = exc.kind
                    processing_ceiling_limit = exc.limit
                    processing_ceiling_observed = exc.observed
                    storage.close()
                    storage = None
                except (UnicodeDecodeError, ValueError):
                    gap_reason = "invalid_json"
                    storage.close()
                    storage = None
                else:
                    record_commitment = "sha256:" + record_hasher.hexdigest()

            yield SessionShardRecord(
                byte_start=coordinate_offset + byte_offset,
                byte_end=coordinate_offset + byte_offset + total_bytes,
                record_index=record_index,
                record_storage=storage,
                record_commitment=record_commitment,
                delimiter_bytes=delimiter_bytes,
                gap_reason=gap_reason,
                processing_ceiling_kind=processing_ceiling_kind,
                processing_ceiling_limit=processing_ceiling_limit,
                processing_ceiling_observed=processing_ceiling_observed,
            )
            byte_offset += total_bytes
            record_index += 1
            handle.seek(byte_offset)
        finally:
            if storage is not None:
                storage.close()

    if byte_offset != byte_end:
        raise ValueError("requested byte range did not end on a JSONL record boundary")


def _session_shards_processing_gap_metadata(
    item: SessionShardRecord,
    record_processing_budget_bytes: int,
) -> dict[str, Any]:
    kind = item.processing_ceiling_kind
    limit = item.processing_ceiling_limit
    observed = item.processing_ceiling_observed
    byte_count = item.byte_end - item.byte_start
    if kind == "record_bytes":
        valid = (
            limit == record_processing_budget_bytes
            and observed == byte_count
            and byte_count > limit
        )
    elif kind == "json_nesting_depth":
        valid = (
            limit == SESSION_SHARDS_MAX_JSON_NESTING_DEPTH
            and observed == limit + 1
            and byte_count <= record_processing_budget_bytes
        )
    else:
        valid = False
    if not valid:
        raise RuntimeError("session-shards processing gap metadata is inconsistent")
    return {
        "record_processing_budget_bytes": record_processing_budget_bytes,
        "hard_record_processing_ceiling_bytes": (
            HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES
        ),
        "processing_ceiling_kind": kind,
        "processing_ceiling_limit": limit,
        "processing_ceiling_observed": observed,
    }


def _iter_session_shard_descriptors(
    records: Iterable[SessionShardRecord],
    *,
    shard_bytes: int,
    record_processing_budget_bytes: int,
) -> Iterable[dict[str, Any]]:
    current: dict[str, Any] | None = None
    for item in records:
        if item.gap_reason is not None:
            if current is not None:
                yield current
                current = None
            descriptor = {
                "kind": "shard",
                "status": "gap",
                "gap_reason": item.gap_reason,
                "byte_start": item.byte_start,
                "byte_end": item.byte_end,
                "record_start": item.record_index,
                "record_end": item.record_index + 1,
                "record_count": 1,
                "byte_count": item.byte_end - item.byte_start,
            }
            if item.gap_reason == "record_processing_budget_exceeded":
                descriptor.update(
                    _session_shards_processing_gap_metadata(
                        item,
                        record_processing_budget_bytes,
                    )
                )
            yield descriptor
            continue

        item_bytes = item.byte_end - item.byte_start
        if current is not None:
            remaining_bytes = shard_bytes - (
                current["byte_end"] - current["byte_start"]
            )
            remaining_frames = (
                MAX_SESSION_SHARDS_RECORD_DATA_FRAMES - current["record_count"]
            )
            if min(remaining_bytes - item_bytes, remaining_frames - 1) < 0:
                yield current
                current = None
        if current is None:
            current = {
                "kind": "shard",
                "status": "ready",
                "byte_start": item.byte_start,
                "byte_end": item.byte_end,
                "record_start": item.record_index,
                "record_end": item.record_index + 1,
                "record_count": 1,
            }
            if item_bytes > shard_bytes:
                current.update(
                    {
                        "oversized_record": True,
                        "record_transport": "base64_fragments",
                        "record_fragment_bytes": SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
                        "record_processing_budget_bytes": (
                            record_processing_budget_bytes
                        ),
                    }
                )
        else:
            current["byte_end"] = item.byte_end
            current["record_end"] = item.record_index + 1
            current["record_count"] += 1
    if current is not None:
        yield current


def _session_shards_content_commitment(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _iter_session_record_transport_frames(
    item: SessionShardRecord,
    *,
    shard_bytes: int,
    source_token: str,
    request_binding: str,
) -> Iterable[dict[str, Any]]:
    if item.record_storage is None or item.record_commitment is None:
        raise RuntimeError("valid session-shards record lost its payload")
    record_storage = item.record_storage
    record_byte_count = item.byte_end - item.byte_start
    common = {
        "schema": SESSION_SHARDS_SCHEMA,
        "mode": "records",
        "source_token": source_token,
        "request_binding": request_binding,
        "record_start": item.record_index,
        "record_end": item.record_index + 1,
        "delimiter_bytes": item.delimiter_bytes,
    }
    if record_byte_count <= shard_bytes:
        record_storage.seek(0)
        record_bytes = record_storage.read(record_byte_count)
        if len(record_bytes) != record_byte_count:
            raise RuntimeError("session-shards record spool ended unexpectedly")
        yield {
            "kind": "record",
            **common,
            "byte_start": item.byte_start,
            "byte_end": item.byte_end,
            "byte_count": len(record_bytes),
            "record_encoding": "base64",
            "record_b64": base64.b64encode(record_bytes).decode("ascii"),
            "record_commitment": item.record_commitment,
        }
        return

    fragment_count = (
        record_byte_count + SESSION_SHARDS_RECORD_FRAGMENT_BYTES - 1
    ) // SESSION_SHARDS_RECORD_FRAGMENT_BYTES
    for fragment_index in range(fragment_count):
        local_start = fragment_index * SESSION_SHARDS_RECORD_FRAGMENT_BYTES
        local_end = min(
            local_start + SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
            record_byte_count,
        )
        record_storage.seek(local_start)
        fragment = record_storage.read(local_end - local_start)
        if len(fragment) != local_end - local_start:
            raise RuntimeError("session-shards record spool ended unexpectedly")
        yield {
            "kind": "record_fragment",
            **common,
            "byte_start": item.byte_start + local_start,
            "byte_end": item.byte_start + local_end,
            "byte_count": len(fragment),
            "record_byte_start": item.byte_start,
            "record_byte_end": item.byte_end,
            "record_byte_count": record_byte_count,
            "fragment_index": fragment_index,
            "fragment_count": fragment_count,
            "record_encoding": "base64",
            "fragment_b64": base64.b64encode(fragment).decode("ascii"),
            "fragment_commitment": _session_shards_content_commitment(fragment),
            "record_commitment": item.record_commitment,
        }


def _iter_local_session_shard_frames(
    *,
    codex_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
    emit: str,
    byte_start: int,
    byte_end: int | None,
    shard_bytes: int,
    max_shards: int,
    source_token: str | None,
    resume_cursor: str | None = None,
    record_processing_budget_bytes: int = (
        DEFAULT_SESSION_RECORD_PROCESSING_BUDGET_BYTES
    ),
    component_hook: Callable[[int, str, int], None] | None = None,
    source_identity_reader: Callable[[os.stat_result], tuple[int, ...]] = (
        _session_shards_source_identity
    ),
    source_opener: Callable[..., Any] = _open_session_shard_source,
) -> Iterable[dict[str, Any]]:
    with contextlib.ExitStack() as cleanup:
        handle = cleanup.enter_context(
            source_opener(
                codex_root,
                rollout_relative_path,
                component_hook=component_hook,
            )
        )
        source_stat = os.fstat(handle.fileno())
        source_identity = source_identity_reader(source_stat)
        current_token = _session_shards_source_token(source_identity)
        current_source_bytes = int(source_stat.st_size)
        if (
            record_processing_budget_bytes
            < max(shard_bytes, MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES)
            or record_processing_budget_bytes
            > HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES
        ):
            raise ValueError(
                "record processing budget must cover the fixed memory envelope "
                f"of {MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES} bytes and be at "
                f"most {HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES}"
            )
        if source_token is not None and source_token != current_token:
            raise ValueError("source token does not match current rollout")

        _validate_session_shards_boundary(
            handle,
            byte_offset=byte_start,
            source_bytes=current_source_bytes,
            option="--byte-start",
        )
        cursor_value: dict[str, Any] | None = None
        if resume_cursor is not None:
            cursor_value = _session_shards_parse_resume_cursor(
                resume_cursor,
                current_token,
            )
            if int(cursor_value["byte_offset"]) != byte_start:
                raise ValueError(
                    "resume cursor byte offset does not match --byte-start"
                )

        records_handle = handle
        records_scan_start = byte_start
        records_scan_end = current_source_bytes
        record_coordinate_offset = 0
        if emit == "descriptors":
            if byte_end is not None:
                raise ValueError("--byte-end is only valid with --emit records")
            if byte_start and source_token is None:
                raise ValueError(
                    "--source-token is required when --byte-start is non-zero"
                )
            if cursor_value is None:
                if byte_start:
                    raise ValueError(
                        "--resume-cursor is required when --byte-start is non-zero"
                    )
                frozen_byte_end = current_source_bytes
                record_start = 0
                frozen_prefix_commitment = _session_shards_frozen_prefix_commitment(
                    handle,
                    frozen_byte_end=frozen_byte_end,
                )
            else:
                if cursor_value["cursor_kind"] != "descriptor_continue":
                    raise ValueError(
                        "descriptor pagination requires a continuation cursor"
                    )
                frozen_byte_end = int(cursor_value["frozen_byte_end"])
                record_start = int(cursor_value["next_record_index"])
                frozen_prefix_commitment = str(cursor_value["prefix_commitment"])
            if frozen_byte_end > current_source_bytes:
                raise ValueError("rollout is shorter than its frozen byte end")
            _validate_session_shards_boundary(
                handle,
                byte_offset=frozen_byte_end,
                source_bytes=current_source_bytes,
                option="--frozen-byte-end",
            )
            effective_end = frozen_byte_end
            records_scan_end = effective_end
        else:
            if byte_end is None:
                raise ValueError("--byte-end is required with --emit records")
            if source_token is None:
                raise ValueError("--source-token is required with --emit records")
            if cursor_value is None:
                raise ValueError("--resume-cursor is required with --emit records")
            if byte_end <= byte_start:
                raise ValueError("--byte-end must be greater than --byte-start")
            if byte_end - byte_start > MAX_SESSION_SHARDS_RANGE_BYTES:
                raise ValueError(
                    f"record range too large: {byte_end - byte_start} bytes > {MAX_SESSION_SHARDS_RANGE_BYTES}"
                )
            if cursor_value["cursor_kind"] != "records":
                raise ValueError("records mode requires a records resume cursor")
            frozen_byte_end = int(cursor_value["frozen_byte_end"])
            if byte_end > frozen_byte_end:
                raise ValueError("--byte-end exceeds the frozen byte end")
            if frozen_byte_end > current_source_bytes:
                raise ValueError("rollout is shorter than its frozen byte end")
            _validate_session_shards_boundary(
                handle,
                byte_offset=byte_end,
                source_bytes=current_source_bytes,
                option="--byte-end",
            )
            _validate_session_shards_boundary(
                handle,
                byte_offset=frozen_byte_end,
                source_bytes=current_source_bytes,
                option="--frozen-byte-end",
            )
            record_start = int(cursor_value["next_record_index"])
            frozen_prefix_commitment = str(cursor_value["prefix_commitment"])
            verified_storage = _spool_verified_session_shards_range(
                handle,
                frozen_byte_end=frozen_byte_end,
                records_byte_start=byte_start,
                records_byte_end=byte_end,
                expected_record_start=record_start,
                expected_prefix_commitment=frozen_prefix_commitment,
            )
            cleanup.callback(verified_storage.close)
            final_stat = os.fstat(handle.fileno())
            if (
                source_identity_reader(final_stat) != source_identity
                or int(final_stat.st_size) < frozen_byte_end
            ):
                raise RuntimeError("source changed before session-shards verification")
            _validate_session_shards_boundary(
                handle,
                byte_offset=frozen_byte_end,
                source_bytes=int(final_stat.st_size),
                option="--frozen-byte-end",
            )
            with source_opener(
                codex_root,
                rollout_relative_path,
                component_hook=component_hook,
            ) as revalidated_handle:
                revalidated_stat = os.fstat(revalidated_handle.fileno())
                if (
                    source_identity_reader(revalidated_stat) != source_identity
                    or int(revalidated_stat.st_size) < frozen_byte_end
                ):
                    raise RuntimeError(
                        "source object changed before session-shards emission"
                    )
            records_handle = verified_storage
            records_scan_start = 0
            records_scan_end = byte_end - byte_start
            record_coordinate_offset = byte_start
            effective_end = byte_end
        request_binding = _session_shards_request_binding(
            rollout=rollout_relative_path.as_posix(),
            mode=emit,
            source_token=source_token,
            byte_start=byte_start,
            byte_end=byte_end,
            shard_bytes=shard_bytes,
            max_shards=max_shards,
            record_processing_budget_bytes=record_processing_budget_bytes,
            resume_cursor=resume_cursor,
        )
        yield {
            "kind": "stream_meta",
            "schema": SESSION_SHARDS_SCHEMA,
            "mode": emit,
            "source_token": current_token,
            "request_rollout": rollout_relative_path.as_posix(),
            "request_source_token": source_token,
            "request_resume_cursor": resume_cursor,
            "request_binding": request_binding,
            "source_bytes": frozen_byte_end,
            "byte_start": byte_start,
            "byte_end": effective_end if emit == "records" else None,
            "record_start": record_start,
            "shard_bytes": shard_bytes,
            "max_shards": max_shards,
            "record_processing_budget_bytes": record_processing_budget_bytes,
            "fixed_memory_envelope_bytes": (MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES),
            "hard_record_processing_ceiling_bytes": (
                HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES
            ),
            "record_fragment_bytes": SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
            "json_nesting_depth_limit": SESSION_SHARDS_MAX_JSON_NESTING_DEPTH,
            "max_remote_frame_chars": MAX_SESSION_SHARDS_FRAME_CHARS,
            "max_record_data_frames": MAX_SESSION_SHARDS_RECORD_DATA_FRAMES,
            "protocol_features": list(SESSION_SHARDS_PROTOCOL_FEATURES),
        }

        records = _iter_session_shard_records(
            records_handle,
            byte_start=records_scan_start,
            byte_end=records_scan_end,
            record_start=record_start,
            record_processing_budget_bytes=record_processing_budget_bytes,
            coordinate_offset=record_coordinate_offset,
        )
        if emit == "descriptors":
            descriptors = iter(
                _iter_session_shard_descriptors(
                    records,
                    shard_bytes=shard_bytes,
                    record_processing_budget_bytes=(record_processing_budget_bytes),
                )
            )
            emitted = 0
            emitted_data_frames = 0
            page_limit_reason: str | None = None
            last_byte_end = byte_start
            last_record_end = record_start
            for page_index in range(max_shards):
                try:
                    descriptor = next(descriptors)
                except StopIteration:
                    break
                descriptor_data_frames = _session_shards_descriptor_data_frames(
                    descriptor
                )
                if descriptor_data_frames > MAX_SESSION_SHARDS_RECORD_DATA_FRAMES:
                    raise RuntimeError(
                        "session-shards descriptor exceeds the data-frame limit"
                    )
                if (
                    emitted_data_frames + descriptor_data_frames
                    > MAX_SESSION_SHARDS_RECORD_DATA_FRAMES
                ):
                    page_limit_reason = "max_record_data_frames"
                    break
                descriptor["page_shard_index"] = page_index
                descriptor["schema"] = SESSION_SHARDS_SCHEMA
                descriptor["mode"] = emit
                descriptor["source_token"] = current_token
                descriptor["request_binding"] = request_binding
                descriptor["resume_cursor"] = _session_shards_resume_cursor(
                    current_token,
                    cursor_kind="descriptor_continue",
                    frozen_byte_end=frozen_byte_end,
                    byte_offset=int(descriptor["byte_start"]),
                    next_record_index=int(descriptor["record_start"]),
                    prefix_commitment=frozen_prefix_commitment,
                )
                yield descriptor
                emitted += 1
                emitted_data_frames += descriptor_data_frames
                last_byte_end = int(descriptor["byte_end"])
                last_record_end = int(descriptor["record_end"])
            complete = last_byte_end == frozen_byte_end
            if emitted < max_shards and not complete and page_limit_reason is None:
                raise RuntimeError(
                    "session-shards descriptors ended before the source was accounted"
                )
            terminal = {
                "kind": "stream_end",
                "schema": SESSION_SHARDS_SCHEMA,
                "mode": emit,
                "source_token": current_token,
                "request_binding": request_binding,
                "complete": complete,
                "reason": ("eof" if complete else page_limit_reason or "max_shards"),
                "emitted_shards": emitted,
                "byte_start": byte_start,
                "byte_end": last_byte_end,
                "record_start": record_start,
                "record_end": last_record_end,
                "next_byte_start": None if complete else last_byte_end,
                "next_record_start": None if complete else last_record_end,
                "next_resume_cursor": None
                if complete
                else _session_shards_resume_cursor(
                    current_token,
                    cursor_kind="descriptor_continue",
                    frozen_byte_end=frozen_byte_end,
                    byte_offset=last_byte_end,
                    next_record_index=last_record_end,
                    prefix_commitment=frozen_prefix_commitment,
                ),
                "records_resume_cursor": _session_shards_resume_cursor(
                    current_token,
                    cursor_kind="records",
                    frozen_byte_end=frozen_byte_end,
                    byte_offset=byte_start,
                    next_record_index=record_start,
                    prefix_commitment=frozen_prefix_commitment,
                ),
                "accounted_byte_count": last_byte_end - byte_start,
                "accounted_record_count": last_record_end - record_start,
            }
        else:
            emitted_records = 0
            emitted_gaps = 0
            emitted_fragments = 0
            emitted_record_bytes = 0
            emitted_gap_bytes = 0
            emitted_fragment_bytes = 0
            emitted_data_frames = 0
            accounting_hasher = hashlib.sha256()
            last_record_end = record_start
            for item in records:
                common = {
                    "schema": SESSION_SHARDS_SCHEMA,
                    "mode": emit,
                    "source_token": current_token,
                    "request_binding": request_binding,
                    "byte_start": item.byte_start,
                    "byte_end": item.byte_end,
                    "record_start": item.record_index,
                    "record_end": item.record_index + 1,
                }
                if item.gap_reason is None:
                    for frame in _iter_session_record_transport_frames(
                        item,
                        shard_bytes=shard_bytes,
                        source_token=current_token,
                        request_binding=request_binding,
                    ):
                        if emitted_data_frames >= MAX_SESSION_SHARDS_RECORD_DATA_FRAMES:
                            raise RuntimeError(
                                "session-shards record data-frame limit exceeded"
                            )
                        emitted_data_frames += 1
                        accounting_hasher.update(
                            _session_shards_accounting_bytes(frame)
                        )
                        if frame["kind"] == "record_fragment":
                            emitted_fragments += 1
                            emitted_fragment_bytes += int(frame["byte_count"])
                        yield frame
                    emitted_records += 1
                    emitted_record_bytes += item.byte_end - item.byte_start
                else:
                    if emitted_data_frames >= MAX_SESSION_SHARDS_RECORD_DATA_FRAMES:
                        raise RuntimeError(
                            "session-shards record data-frame limit exceeded"
                        )
                    emitted_data_frames += 1
                    frame = {
                        "kind": "gap",
                        **common,
                        "byte_count": item.byte_end - item.byte_start,
                        "delimiter_bytes": item.delimiter_bytes,
                        "reason": item.gap_reason,
                    }
                    if item.gap_reason == "record_processing_budget_exceeded":
                        frame.update(
                            _session_shards_processing_gap_metadata(
                                item,
                                record_processing_budget_bytes,
                            )
                        )
                    accounting_hasher.update(_session_shards_accounting_bytes(frame))
                    yield frame
                    emitted_gaps += 1
                    emitted_gap_bytes += item.byte_end - item.byte_start
                last_record_end = item.record_index + 1
            accounted_byte_count = emitted_record_bytes + emitted_gap_bytes
            expected_byte_count = effective_end - byte_start
            accounted_record_count = emitted_records + emitted_gaps
            expected_record_count = last_record_end - record_start
            if (
                accounted_byte_count != expected_byte_count
                or accounted_record_count != expected_record_count
            ):
                raise RuntimeError(
                    "session-shards record transport failed byte conservation"
                )
            terminal = {
                "kind": "stream_end",
                "schema": SESSION_SHARDS_SCHEMA,
                "mode": emit,
                "source_token": current_token,
                "request_binding": request_binding,
                "complete": True,
                "reason": "range_complete",
                "emitted_records": emitted_records,
                "emitted_gaps": emitted_gaps,
                "emitted_fragments": emitted_fragments,
                "emitted_record_bytes": emitted_record_bytes,
                "emitted_gap_bytes": emitted_gap_bytes,
                "emitted_fragment_bytes": emitted_fragment_bytes,
                "byte_start": byte_start,
                "byte_end": effective_end,
                "record_start": record_start,
                "record_end": last_record_end,
                "conservation_proof": {
                    "schema": "session-shards-conservation-v1",
                    "source_token": current_token,
                    "request_binding": request_binding,
                    "byte_start": byte_start,
                    "byte_end": effective_end,
                    "byte_count": expected_byte_count,
                    "accounted_byte_count": accounted_byte_count,
                    "record_start": record_start,
                    "record_end": last_record_end,
                    "record_count": expected_record_count,
                    "accounted_record_count": accounted_record_count,
                    "accounting_commitment": (
                        "sha256:" + accounting_hasher.hexdigest()
                    ),
                },
            }

        if emit == "descriptors":
            final_stat = os.fstat(handle.fileno())
            if (
                source_identity_reader(final_stat) != source_identity
                or int(final_stat.st_size) < frozen_byte_end
            ):
                raise RuntimeError("source changed during session-shards read")
            _validate_session_shards_boundary(
                handle,
                byte_offset=frozen_byte_end,
                source_bytes=int(final_stat.st_size),
                option="--frozen-byte-end",
            )
        yield terminal


def _session_shards_remote_arguments(args: argparse.Namespace) -> tuple[str, ...]:
    values = [
        "--rollout",
        str(args.rollout),
        "--emit",
        str(args.emit),
        "--byte-start",
        str(args.byte_start),
        "--shard-bytes",
        str(args.shard_bytes),
        "--max-shards",
        str(args.max_shards),
        "--record-processing-budget-bytes",
        str(args.record_processing_budget_bytes),
    ]
    for option, value in (
        ("--byte-end", args.byte_end),
        ("--source-token", args.source_token),
        ("--resume-cursor", args.resume_cursor),
    ):
        if value is not None:
            values.extend((option, str(value)))
    return tuple(values)


def cmd_session_shards(
    args: argparse.Namespace,
    *,
    codex_root: pathlib.Path | None = None,
    component_hook: Callable[[int, str, int], None] | None = None,
    source_identity_reader: Callable[[os.stat_result], tuple[int, ...]] = (
        _session_shards_source_identity
    ),
    source_opener: Callable[..., Any] = _open_session_shard_source,
    relay_command: Callable[..., None] = _relay_remote_host_context_command,
    max_range_bytes: int = MAX_SESSION_SHARDS_RANGE_BYTES,
) -> int:
    """Backward-compatible local sharder with remote-host-context delegation."""

    host = str(args.host)
    rollout_text = str(args.rollout)
    try:
        if _TOKEN_RE.fullmatch(host) is None:
            raise ValueError("--host must be a bounded transport token")
        rollout = _resolve_rollout_relative_path(rollout_text)
        if args.emit not in {"descriptors", "records"}:
            raise ValueError("--emit must be descriptors or records")
        if isinstance(args.byte_start, bool) or args.byte_start < 0:
            raise ValueError("--byte-start must be non-negative")
        if not 1 <= args.shard_bytes <= MAX_SESSION_SHARD_BYTES:
            raise ValueError(
                f"--shard-bytes must stay between 1 and {MAX_SESSION_SHARD_BYTES}"
            )
        if not 1 <= args.max_shards <= MAX_SESSION_SHARDS_PER_PAGE:
            raise ValueError(
                f"--max-shards must stay between 1 and {MAX_SESSION_SHARDS_PER_PAGE}"
            )
        if (
            isinstance(args.record_processing_budget_bytes, bool)
            or args.record_processing_budget_bytes
            < max(args.shard_bytes, MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES)
            or args.record_processing_budget_bytes
            > HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES
        ):
            raise ValueError(
                "--record-processing-budget-bytes is outside the fixed memory envelope"
            )
        if args.resume_cursor is not None and not args.source_token:
            raise ValueError("--source-token is required with --resume-cursor")
        if args.emit == "descriptors":
            if args.byte_end is not None:
                raise ValueError("--byte-end is only valid with --emit records")
            if args.byte_start and not args.source_token:
                raise ValueError(
                    "--source-token is required when --byte-start is non-zero"
                )
            if args.byte_start and args.resume_cursor is None:
                raise ValueError(
                    "--resume-cursor is required when --byte-start is non-zero"
                )
        else:
            if args.byte_end is None:
                raise ValueError("--byte-end is required with --emit records")
            if args.byte_end <= args.byte_start:
                raise ValueError("--byte-end must be greater than --byte-start")
            if args.byte_end - args.byte_start > max_range_bytes:
                raise ValueError(
                    f"record range too large: {args.byte_end - args.byte_start} bytes"
                )
            if not args.source_token:
                raise ValueError("--source-token is required with --emit records")
            if args.resume_cursor is None:
                raise ValueError("--resume-cursor is required with --emit records")

        if host != "local":
            command = _remote_host_context_command(
                args,
                "session-shards",
                _session_shards_remote_arguments(args),
            )
            request_binding = _session_shards_request_binding(
                rollout=rollout.as_posix(),
                mode=args.emit,
                source_token=args.source_token,
                byte_start=args.byte_start,
                byte_end=args.byte_end,
                shard_bytes=args.shard_bytes,
                max_shards=args.max_shards,
                record_processing_budget_bytes=args.record_processing_budget_bytes,
                resume_cursor=args.resume_cursor,
            )
            max_output_bytes = _session_shards_remote_output_limit(
                mode=args.emit,
                byte_start=args.byte_start,
                byte_end=args.byte_end,
                max_shards=args.max_shards,
                frame_metadata_bytes=SESSION_SHARDS_FRAME_METADATA_CHARS,
            )
            relay_command(
                command,
                max_output_bytes=max_output_bytes,
                stream_filter=RemoteSessionShardsFilter(
                    host=host,
                    rollout=rollout.as_posix(),
                    mode=args.emit,
                    source_token=args.source_token,
                    resume_cursor=args.resume_cursor,
                    request_binding=request_binding,
                    byte_start=args.byte_start,
                    byte_end=args.byte_end,
                    shard_bytes=args.shard_bytes,
                    max_shards=args.max_shards,
                    record_processing_budget_bytes=(
                        args.record_processing_budget_bytes
                    ),
                    max_frame_chars=MAX_SESSION_SHARDS_FRAME_CHARS,
                ),
            )
            return 0

        frames = _iter_local_session_shard_frames(
            codex_root=_local_codex_root() if codex_root is None else codex_root,
            rollout_relative_path=rollout,
            emit=args.emit,
            byte_start=args.byte_start,
            byte_end=args.byte_end,
            shard_bytes=args.shard_bytes,
            max_shards=args.max_shards,
            source_token=args.source_token,
            resume_cursor=args.resume_cursor,
            record_processing_budget_bytes=args.record_processing_budget_bytes,
            component_hook=component_hook,
            source_identity_reader=source_identity_reader,
            source_opener=source_opener,
        )
        for frame in frames:
            item = dict(frame)
            item["host"] = host
            item["rollout"] = rollout.as_posix()
            print(
                json.dumps(
                    item,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                flush=True,
            )
    except FileNotFoundError:
        message = "rollout not found"
    except OSError:
        message = "rollout unreadable"
    except (RuntimeError, ValueError) as exc:
        message = str(exc)
    else:
        return 0
    print(f"host={host}", file=sys.stderr)
    print(f"rollout={rollout_text}", file=sys.stderr)
    print(f"error={message}", file=sys.stderr)
    return 1


# Deterministic source scanner; remote access is delegated to remote-host-context.
