"""Bounded decoded source batches for extractor overlap validation."""

from __future__ import annotations

import codecs
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass


_MAX_CLASSIFIED_KEY_CHARS = 256
_NON_PROSE_VALUE_KEYS = frozenset(
    {
        "approval_policy",
        "cwd",
        "host",
        "id",
        "kind",
        "model",
        "outcome",
        "phase",
        "provider",
        "role",
        "sandbox_policy",
        "schema",
        "state",
        "status",
        "timestamp",
        "ts",
        "type",
        "version",
    }
)
_NON_PROSE_VALUE_SUFFIXES = (
    "_at",
    "_commitment",
    "_digest",
    "_id",
    "_ref",
    "_timestamp",
)


def _key_carries_control_value(value: str) -> bool:
    normalized = value.casefold()
    return normalized in _NON_PROSE_VALUE_KEYS or normalized.endswith(
        _NON_PROSE_VALUE_SUFFIXES
    )


@dataclass(slots=True)
class _ContainerFrame:
    kind: str
    state: str
    inherited_control_value: bool
    next_value_is_control: bool = False


def decoded_utf8_chunks(fragments: Iterable[bytes]) -> Iterator[str]:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    for fragment in fragments:
        decoded = decoder.decode(fragment, final=False)
        if decoded:
            yield decoded
    tail = decoder.decode(b"", final=True)
    if tail:
        yield tail


class _NormalizedValueWindows:
    def __init__(self, *, query_chars: int, maximum_chars: int) -> None:
        if query_chars < 1 or maximum_chars < 1:
            raise ValueError("source overlap window limits must be positive")
        self.maximum_chars = maximum_chars
        self.overlap = min(query_chars - 1, maximum_chars - 1)
        self.step = maximum_chars - self.overlap
        self._chunks: deque[str] = deque()
        self._buffered_chars = 0
        self._pending: list[str] = []
        self._pending_chars = 0
        self._flush_chars = min(8_192, maximum_chars)
        self.last_window: str | None = None
        self.emitted_character = False
        self.pending_space = False

    def _prefix(self, count: int) -> str:
        if not 0 <= count <= self._buffered_chars:
            raise ValueError("source overlap prefix is outside the buffered range")
        remaining = count
        pieces: list[str] = []
        for chunk in self._chunks:
            if remaining == 0:
                break
            selected = chunk[:remaining]
            pieces.append(selected)
            remaining -= len(selected)
        if remaining != 0:
            raise ValueError("source overlap buffer accounting is inconsistent")
        return "".join(pieces)

    def _discard_prefix(self, count: int) -> None:
        if not 0 <= count <= self._buffered_chars:
            raise ValueError("source overlap discard is outside the buffered range")
        remaining = count
        while remaining:
            chunk = self._chunks[0]
            if len(chunk) <= remaining:
                self._chunks.popleft()
                remaining -= len(chunk)
            else:
                self._chunks[0] = chunk[remaining:]
                remaining = 0
        self._buffered_chars -= count

    def _append_chunk(self, value: str) -> list[str]:
        windows: list[str] = []
        if value:
            self._chunks.append(value)
            self._buffered_chars += len(value)
        while self._buffered_chars >= self.maximum_chars:
            window = self._prefix(self.maximum_chars)
            windows.append(window)
            self.last_window = window
            self._discard_prefix(self.step)
        return windows

    def _flush_pending(self) -> list[str]:
        if not self._pending:
            return []
        value = "".join(self._pending)
        self._pending.clear()
        self._pending_chars = 0
        return self._append_chunk(value)

    def _queue_normalized(self, value: str) -> list[str]:
        self._pending.append(value)
        self._pending_chars += len(value)
        if self._pending_chars < self._flush_chars:
            return []
        return self._flush_pending()

    def feed(self, value: str) -> list[str]:
        windows: list[str] = []
        for character in value.casefold():
            if character.isspace():
                if self.emitted_character:
                    self.pending_space = True
                continue
            if self.pending_space:
                windows.extend(self._queue_normalized(" "))
                self.pending_space = False
            windows.extend(self._queue_normalized(character))
            self.emitted_character = True
        return windows

    def finish(self) -> list[str]:
        windows = self._flush_pending()
        buffer = self._prefix(self._buffered_chars)
        if self.last_window is None:
            if buffer:
                windows.append(buffer)
            return windows
        if len(buffer) <= self.overlap:
            return windows
        final_window = (self.last_window + buffer[self.overlap :])[
            -self.maximum_chars :
        ]
        if final_window != self.last_window:
            windows.append(final_window)
        return windows


def _decoded_json_string_value_windows(
    chunks: Iterable[str],
    *,
    query_chars: int,
    maximum_chars: int,
) -> Iterator[str]:
    stack: list[_ContainerFrame] = []
    root_state = "value"
    in_string = False
    string_is_value = False
    string_is_control = False
    escaped = False
    unicode_digits: str | None = None
    pending_high_surrogate: int | None = None
    primitive_kind: str | None = None
    primitive_literal = ""
    primitive_literal_index = 0
    number_state = ""
    windows: _NormalizedValueWindows | None = None
    key_characters: list[str] = []
    key_overflow = False
    escapes = {
        '"': '"',
        "/": "/",
        "\\": "\\",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }

    def state() -> str:
        return stack[-1].state if stack else root_state

    def expects_value() -> bool:
        return state() in {"value", "value_or_end"}

    def complete_value() -> None:
        nonlocal root_state
        if not stack:
            root_state = "done"
        else:
            stack[-1].state = "comma_or_end"
            stack[-1].next_value_is_control = False

    def current_value_is_control() -> bool:
        if not stack:
            return False
        frame = stack[-1]
        return frame.inherited_control_value or (
            frame.kind == "object" and frame.next_value_is_control
        )

    def emit(decoded: str) -> list[str]:
        nonlocal key_overflow
        if not string_is_value:
            if not key_overflow:
                remaining = _MAX_CLASSIFIED_KEY_CHARS - len(key_characters)
                if len(decoded) > remaining:
                    key_characters.clear()
                    key_overflow = True
                else:
                    key_characters.extend(decoded)
            return []
        if string_is_control or windows is None:
            return []
        return windows.feed(decoded)

    def start_primitive(character: str) -> None:
        nonlocal primitive_kind
        nonlocal primitive_literal
        nonlocal primitive_literal_index
        nonlocal number_state
        if character in "tfn":
            primitive_kind = "literal"
            primitive_literal = {"t": "true", "f": "false", "n": "null"}[character]
            primitive_literal_index = 1
            return
        primitive_kind = "number"
        if character == "-":
            number_state = "minus"
        elif character == "0":
            number_state = "zero"
        elif character in "123456789":
            number_state = "integer"
        else:
            raise ValueError("source JSON primitive is invalid")

    def feed_primitive(character: str) -> None:
        nonlocal primitive_literal_index
        nonlocal number_state
        if primitive_kind == "literal":
            if (
                primitive_literal_index >= len(primitive_literal)
                or character != primitive_literal[primitive_literal_index]
            ):
                raise ValueError("source JSON primitive is invalid")
            primitive_literal_index += 1
            return
        transitions = {
            "minus": (
                ("0", "zero"),
                ("123456789", "integer"),
            ),
            "zero": ((".", "decimal_point"), ("eE", "exponent")),
            "integer": (
                ("0123456789", "integer"),
                (".", "decimal_point"),
                ("eE", "exponent"),
            ),
            "decimal_point": (("0123456789", "fraction"),),
            "fraction": (
                ("0123456789", "fraction"),
                ("eE", "exponent"),
            ),
            "exponent": (
                ("+-", "exponent_sign"),
                ("0123456789", "exponent_digits"),
            ),
            "exponent_sign": (("0123456789", "exponent_digits"),),
            "exponent_digits": (("0123456789", "exponent_digits"),),
        }
        for accepted, next_state in transitions[number_state]:
            if character in accepted:
                number_state = next_state
                return
        raise ValueError("source JSON primitive is invalid")

    def primitive_is_complete() -> bool:
        if primitive_kind == "literal":
            return primitive_literal_index == len(primitive_literal)
        return number_state in {"zero", "integer", "fraction", "exponent_digits"}

    for chunk in chunks:
        for character in chunk:
            if in_string:
                if unicode_digits is not None:
                    if character not in "0123456789abcdefABCDEF":
                        raise ValueError(
                            "source JSON string has an invalid Unicode escape"
                        )
                    unicode_digits += character
                    if len(unicode_digits) == 4:
                        code_unit = int(unicode_digits, 16)
                        unicode_digits = None
                        escaped = False
                        if 0xD800 <= code_unit <= 0xDBFF:
                            if pending_high_surrogate is not None:
                                raise ValueError(
                                    "source JSON string has nested surrogates"
                                )
                            pending_high_surrogate = code_unit
                        elif 0xDC00 <= code_unit <= 0xDFFF:
                            if pending_high_surrogate is None:
                                raise ValueError(
                                    "source JSON string has a low surrogate"
                                )
                            scalar = 0x10000 + (
                                (pending_high_surrogate - 0xD800) * 0x400
                                + code_unit
                                - 0xDC00
                            )
                            pending_high_surrogate = None
                            yield from emit(chr(scalar))
                        else:
                            if pending_high_surrogate is not None:
                                raise ValueError(
                                    "source JSON string has a lone surrogate"
                                )
                            yield from emit(chr(code_unit))
                    continue
                if escaped:
                    if character == "u":
                        unicode_digits = ""
                        continue
                    escaped = False
                    if pending_high_surrogate is not None or character not in escapes:
                        raise ValueError("source JSON string has an invalid escape")
                    yield from emit(escapes[character])
                    continue
                if character == "\\":
                    escaped = True
                    continue
                if character == '"':
                    if pending_high_surrogate is not None:
                        raise ValueError("source JSON string has a lone surrogate")
                    in_string = False
                    if string_is_value:
                        if windows is not None:
                            yield from windows.finish()
                        complete_value()
                    else:
                        frame = stack[-1]
                        frame.next_value_is_control = frame.inherited_control_value or (
                            not key_overflow
                            and _key_carries_control_value("".join(key_characters))
                        )
                        frame.state = "colon"
                    windows = None
                    continue
                if ord(character) < 0x20 or pending_high_surrogate is not None:
                    raise ValueError("source JSON string contains an invalid character")
                yield from emit(character)
                continue

            if primitive_kind is not None:
                if character.isspace() or character in ",]}":
                    if not primitive_is_complete():
                        raise ValueError("source JSON primitive is incomplete")
                    primitive_kind = None
                    complete_value()
                    if character.isspace():
                        continue
                else:
                    feed_primitive(character)
                    continue

            if character.isspace():
                continue
            current = state()
            if character == '"':
                string_is_value = expects_value()
                if not string_is_value and current not in {"key", "key_or_end"}:
                    raise ValueError(
                        "source JSON string appears outside a value or key"
                    )
                in_string = True
                escaped = False
                unicode_digits = None
                pending_high_surrogate = None
                key_characters = []
                key_overflow = False
                string_is_control = (
                    current_value_is_control() if string_is_value else False
                )
                windows = (
                    _NormalizedValueWindows(
                        query_chars=query_chars,
                        maximum_chars=maximum_chars,
                    )
                    if string_is_value and not string_is_control
                    else None
                )
            elif character in "{[":
                if not expects_value():
                    raise ValueError("source JSON container appears outside a value")
                stack.append(
                    _ContainerFrame(
                        kind="object" if character == "{" else "array",
                        state="key_or_end" if character == "{" else "value_or_end",
                        inherited_control_value=current_value_is_control(),
                    )
                )
            elif character in "}]":
                expected_kind = "object" if character == "}" else "array"
                initial_state = "key_or_end" if character == "}" else "value_or_end"
                if (
                    not stack
                    or stack[-1].kind != expected_kind
                    or current not in {initial_state, "comma_or_end"}
                ):
                    raise ValueError("source JSON container is unbalanced")
                stack.pop()
                complete_value()
            elif character == ":":
                if not stack or stack[-1].kind != "object" or current != "colon":
                    raise ValueError("source JSON colon appears outside an object key")
                stack[-1].state = "value"
            elif character == ",":
                if not stack or current != "comma_or_end":
                    raise ValueError("source JSON comma appears outside a container")
                stack[-1].state = "key" if stack[-1].kind == "object" else "value"
            elif expects_value():
                start_primitive(character)
            else:
                raise ValueError("source JSON token appears outside a value")

    if primitive_kind is not None:
        if not primitive_is_complete():
            raise ValueError("source JSON primitive is incomplete")
        complete_value()
    if (
        in_string
        or escaped
        or unicode_digits is not None
        or stack
        or root_state != "done"
    ):
        raise ValueError("source JSON value is incomplete")


def json_string_value_batches(
    chunks: Iterable[str],
    *,
    query_chars: int,
    maximum_batch_chars: int,
    maximum_batch_items: int,
) -> Iterator[tuple[str, ...]]:
    if min(query_chars, maximum_batch_chars, maximum_batch_items) < 1:
        raise ValueError("source overlap batch limits must be positive")
    batch: list[str] = []
    batch_set: set[str] = set()
    batch_chars = 0
    for candidate in _decoded_json_string_value_windows(
        chunks,
        query_chars=query_chars,
        maximum_chars=maximum_batch_chars,
    ):
        if not candidate or candidate in batch_set:
            continue
        if batch and (
            len(batch) >= maximum_batch_items
            or batch_chars + len(candidate) > maximum_batch_chars
        ):
            yield tuple(batch)
            batch.clear()
            batch_set.clear()
            batch_chars = 0
        batch.append(candidate)
        batch_set.add(candidate)
        batch_chars += len(candidate)
    if batch:
        yield tuple(batch)
