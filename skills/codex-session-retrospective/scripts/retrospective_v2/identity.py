from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets

from .contracts import JsonValue, RefType, TypedRef, canonical_json_bytes
from .safe_io import (
    InvalidJsonError,
    atomic_create_json,
    read_recoverable_atomic_json,
)


IDENTITY_SCHEMA_VERSION = 2
IDENTITY_KEY_BYTES = 32
IDENTITY_KEY_FILE = "identity-v2.key"
IDENTITY_KEY_ID_PREFIX = "identity_key_v2"
IDENTITY_FILE_MAX_BYTES = 4096
IDENTITY_ROOT_DOMAIN = b"codex-session-retrospective/identity/v2"

_KEY_ID_RE = re.compile(rf"{IDENTITY_KEY_ID_PREFIX}:[0-9a-f]{{64}}\Z")
_IDENTITY_FIELDS = frozenset({"schema_version", "key_id", "secret_b64"})


class IdentityKeyError(RuntimeError):
    pass


class IdentityKeyFormatError(IdentityKeyError):
    pass


class IdentityKeyMismatchError(IdentityKeyError):
    pass


class IdentityKeyMissingError(IdentityKeyMismatchError):
    pass


IdentityMismatchError = IdentityKeyMismatchError


def identity_key_path() -> Path:
    return Path.home() / ".codex" / "session-retrospective" / IDENTITY_KEY_FILE


default_identity_key_path = identity_key_path


def _frame(*parts: bytes) -> bytes:
    framed = bytearray()
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError("HMAC framing accepts bytes only")
        framed.extend(len(part).to_bytes(8, "big"))
        framed.extend(part)
    return bytes(framed)


def _derive_key_id(secret: bytes) -> str:
    digest = hmac.new(
        secret,
        _frame(IDENTITY_ROOT_DOMAIN, b"key-id"),
        hashlib.sha256,
    ).hexdigest()
    return f"{IDENTITY_KEY_ID_PREFIX}:{digest}"


def _validated_expected_key_id(expected_key_id: str | None) -> str | None:
    if expected_key_id is None:
        return None
    if (
        not isinstance(expected_key_id, str)
        or _KEY_ID_RE.fullmatch(expected_key_id) is None
    ):
        raise IdentityKeyMismatchError("expected identity key_id has an invalid format")
    return expected_key_id


def _coerce_ref_type(kind: RefType | str) -> RefType:
    if isinstance(kind, RefType):
        return kind
    try:
        return RefType(kind)
    except ValueError:
        normalized_name = kind.upper().replace("-", "_")
        try:
            return RefType[normalized_name]
        except KeyError as exc:
            raise ValueError(f"unknown reference type: {kind!r}") from exc


def _validate_domain(domain: str) -> bytes:
    if not isinstance(domain, str):
        raise TypeError("HMAC domain must be a string")
    if not domain or len(domain.encode("utf-8")) > 256:
        raise ValueError("HMAC domain must contain 1 to 256 UTF-8 bytes")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in domain):
        raise ValueError("HMAC domain must contain visible ASCII characters only")
    return domain.encode("ascii")


@dataclass(frozen=True, slots=True, init=False)
class IdentityKey:
    _secret: bytes = field(repr=False)
    key_id: str
    path: Path | None = field(default=None, compare=False)

    def __init__(
        self,
        secret: bytes | bytearray | memoryview,
        *,
        key_id: str | None = None,
        path: str | os.PathLike[str] | None = None,
    ) -> None:
        if not isinstance(secret, (bytes, bytearray, memoryview)):
            raise TypeError("identity secret must be bytes-like")
        secret_bytes = bytes(secret)
        if len(secret_bytes) != IDENTITY_KEY_BYTES:
            raise ValueError(
                f"identity secret must be exactly {IDENTITY_KEY_BYTES} bytes"
            )
        derived_key_id = _derive_key_id(secret_bytes)
        validated_key_id = _validated_expected_key_id(key_id)
        if validated_key_id is not None and not hmac.compare_digest(
            validated_key_id,
            derived_key_id,
        ):
            raise IdentityKeyMismatchError(
                "identity key_id does not match the supplied key material"
            )
        object.__setattr__(self, "_secret", secret_bytes)
        object.__setattr__(self, "key_id", derived_key_id)
        object.__setattr__(
            self,
            "path",
            None if path is None else Path(path).expanduser().absolute(),
        )

    @property
    def secret(self) -> bytes:
        return self._secret

    @property
    def key(self) -> bytes:
        return self._secret

    @property
    def key_bytes(self) -> bytes:
        return self._secret

    @classmethod
    def generate(cls) -> "IdentityKey":
        return cls(secrets.token_bytes(IDENTITY_KEY_BYTES))

    @classmethod
    def create(
        cls,
        path: str | os.PathLike[str] | None = None,
        *,
        secret: bytes | bytearray | memoryview | None = None,
    ) -> "IdentityKey":
        target = (
            identity_key_path() if path is None else Path(path).expanduser().absolute()
        )
        generated = cls(
            secrets.token_bytes(IDENTITY_KEY_BYTES) if secret is None else secret
        )
        atomic_create_json(target, generated._file_record())
        return cls.load(target, expected_key_id=generated.key_id)

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str] | None = None,
        *,
        expected_key_id: str | None = None,
    ) -> "IdentityKey":
        target = (
            identity_key_path() if path is None else Path(path).expanduser().absolute()
        )
        expected_key_id = _validated_expected_key_id(expected_key_id)
        try:
            record = read_recoverable_atomic_json(
                target,
                max_bytes=IDENTITY_FILE_MAX_BYTES,
            )
        except InvalidJsonError as exc:
            raise IdentityKeyFormatError(
                "identity key file is not strict UTF-8 JSON"
            ) from exc
        if not isinstance(record, dict) or set(record) != _IDENTITY_FIELDS:
            raise IdentityKeyFormatError("identity key file has an invalid field set")
        schema_version = record.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != IDENTITY_SCHEMA_VERSION
        ):
            raise IdentityKeyFormatError(
                "identity key file has an unsupported schema version"
            )

        stored_key_id = record.get("key_id")
        encoded_secret = record.get("secret_b64")
        if (
            not isinstance(stored_key_id, str)
            or _KEY_ID_RE.fullmatch(stored_key_id) is None
        ):
            raise IdentityKeyFormatError("identity key file has an invalid key_id")
        if not isinstance(encoded_secret, str):
            raise IdentityKeyFormatError("identity key file has invalid key material")
        try:
            secret = base64.b64decode(encoded_secret, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise IdentityKeyFormatError(
                "identity key material is not valid base64"
            ) from exc
        if len(secret) != IDENTITY_KEY_BYTES:
            raise IdentityKeyFormatError(
                f"identity key material must decode to {IDENTITY_KEY_BYTES} bytes"
            )

        derived_key_id = _derive_key_id(secret)
        if not hmac.compare_digest(stored_key_id, derived_key_id):
            raise IdentityKeyMismatchError(
                "identity key file key_id does not match its key material"
            )
        if expected_key_id is not None and not hmac.compare_digest(
            expected_key_id,
            derived_key_id,
        ):
            raise IdentityKeyMismatchError(
                f"identity key mismatch: expected {expected_key_id}, found {derived_key_id}"
            )
        return cls(secret, key_id=derived_key_id, path=target)

    @classmethod
    def load_or_create(
        cls,
        path: str | os.PathLike[str] | None = None,
        *,
        expected_key_id: str | None = None,
    ) -> "IdentityKey":
        target = (
            identity_key_path() if path is None else Path(path).expanduser().absolute()
        )
        expected_key_id = _validated_expected_key_id(expected_key_id)
        try:
            return cls.load(target, expected_key_id=expected_key_id)
        except FileNotFoundError as exc:
            if expected_key_id is not None:
                raise IdentityKeyMissingError(
                    "identity key is missing; refusing to create a replacement for an "
                    f"expected key_id ({expected_key_id})"
                ) from exc
        try:
            return cls.create(target)
        except FileExistsError:
            return cls.load(target, expected_key_id=expected_key_id)

    def _file_record(self) -> dict[str, JsonValue]:
        return {
            "schema_version": IDENTITY_SCHEMA_VERSION,
            "key_id": self.key_id,
            "secret_b64": base64.b64encode(self._secret).decode("ascii"),
        }

    def derive_digest(self, domain: str, value: JsonValue) -> str:
        domain_bytes = _validate_domain(domain)
        subkey = hmac.new(
            self._secret,
            _frame(IDENTITY_ROOT_DOMAIN, b"subkey", domain_bytes),
            hashlib.sha256,
        ).digest()
        return hmac.new(
            subkey,
            _frame(IDENTITY_ROOT_DOMAIN, b"value", canonical_json_bytes(value)),
            hashlib.sha256,
        ).hexdigest()

    hmac_digest = derive_digest

    def derive_ref(
        self,
        kind: RefType | str,
        value: JsonValue,
        *additional_values: JsonValue,
    ) -> TypedRef:
        ref_type = _coerce_ref_type(kind)
        payload: JsonValue = {"parts": [value, *additional_values]}
        digest = self.derive_digest(f"stable-ref/{ref_type.value}", payload)
        return TypedRef(kind=ref_type, digest=digest)

    derive_id = derive_ref


def load_identity_key(
    path: str | os.PathLike[str] | None = None,
    *,
    expected_key_id: str | None = None,
) -> IdentityKey:
    return IdentityKey.load(path, expected_key_id=expected_key_id)


def load_or_create_identity_key(
    path: str | os.PathLike[str] | None = None,
    *,
    expected_key_id: str | None = None,
) -> IdentityKey:
    return IdentityKey.load_or_create(path, expected_key_id=expected_key_id)


def derive_stable_ref(
    identity: IdentityKey,
    kind: RefType | str,
    value: JsonValue,
    *additional_values: JsonValue,
) -> TypedRef:
    return identity.derive_ref(kind, value, *additional_values)
