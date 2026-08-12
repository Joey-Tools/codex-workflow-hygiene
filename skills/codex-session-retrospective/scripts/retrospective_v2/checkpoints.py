from __future__ import annotations

import copy
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import re
from typing import Any, Callable, Generic, Mapping, TypeVar

from . import contracts as common_contracts
from . import safe_io as common_safe_io
from .identity import IdentityKey


CHECKPOINT_FORMAT_VERSION = common_contracts.CHECKPOINT_FORMAT_VERSION
DEFAULT_MAX_CHECKPOINT_BYTES = 32 * 1024 * 1024
DEFAULT_CHECKPOINT_TERMINAL_RESERVE_BYTES = 512 * 1024
_LOCK_FILE = ".checkpoint.lock"
_ENVELOPE_BODY_FIELDS = frozenset({"format_version", "revision", "key_id", "state"})
_ENVELOPE_FIELDS = _ENVELOPE_BODY_FIELDS | {"envelope_hmac"}
_ENVELOPE_HMAC_PREFIX = "checkpoint_hmac_v2:"
_KEY_ID_RE = re.compile(r"identity_key_v2:[0-9a-f]{64}\Z")
_ENVELOPE_HMAC_RE = re.compile(rf"{re.escape(_ENVELOPE_HMAC_PREFIX)}[0-9a-f]{{64}}\Z")


class CheckpointError(RuntimeError):
    """Base error for checkpoint persistence failures."""


class CheckpointNotFoundError(CheckpointError):
    """Raised when a run has no committed checkpoint."""


class CheckpointConflictError(CheckpointError):
    """Raised when compare-and-swap or initialization observes another state."""


class CheckpointIntegrityError(CheckpointError):
    """Raised when a checkpoint envelope is malformed or has the wrong digest."""


class CheckpointPermissionError(CheckpointError):
    """Raised when a checkpoint path is not private to its owner."""


@dataclass(frozen=True)
class CheckpointSnapshot:
    revision: int
    state: dict[str, Any]
    key_id: str


T = TypeVar("T")
S = TypeVar("S")


@dataclass(frozen=True)
class TransactionResult(Generic[T]):
    snapshot: CheckpointSnapshot
    value: T
    changed: bool


def canonical_json_bytes(value: object) -> bytes:
    return common_contracts.canonical_json_bytes(value)  # type: ignore[arg-type]


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _copy_state(state: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(state))


def _validated_key_id(key_id: str) -> str:
    if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
        raise ValueError("checkpoint key_id must be an identity_key_v2 reference")
    return key_id


def _validated_expected_revision(revision: int | None) -> int | None:
    if revision is None:
        return None
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise ValueError("expected_revision must be a non-negative integer or None")
    return revision


def _canonical_state_bytes(state: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json_bytes(dict(state))
    except (TypeError, ValueError, OverflowError) as exc:
        raise CheckpointIntegrityError(
            "checkpoint state must be finite canonical JSON data"
        ) from exc


def _states_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return _canonical_state_bytes(left) == _canonical_state_bytes(right)


def _envelope_body(
    *,
    revision: int,
    key_id: str,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "format_version": CHECKPOINT_FORMAT_VERSION,
        "revision": revision,
        "key_id": key_id,
        "state": dict(state),
    }


def _envelope_authentication(identity: IdentityKey, body: Mapping[str, Any]) -> str:
    return _ENVELOPE_HMAC_PREFIX + identity.derive_digest(
        "checkpoint-envelope-v2",
        dict(body),
    )


class AtomicCheckpointStore:
    """Owner-only JSON checkpoint store with identity-bound CAS updates."""

    def __init__(
        self,
        run_dir: str | os.PathLike[str],
        *,
        identity: IdentityKey,
        filename: str = "checkpoint.json",
        max_bytes: int = DEFAULT_MAX_CHECKPOINT_BYTES,
    ) -> None:
        if (
            not filename
            or filename in {".", "..", _LOCK_FILE}
            or Path(filename).name != filename
        ):
            raise ValueError("checkpoint filename must be one path component")
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes <= 0
        ):
            raise ValueError("max_bytes must be positive")
        if not isinstance(identity, IdentityKey):
            raise TypeError("checkpoint identity must be an IdentityKey")
        self.identity = identity
        self.key_id = _validated_key_id(identity.key_id)
        self.run_dir = Path(run_dir).expanduser().absolute()
        self.path = self.run_dir / filename
        self.lock_path = self.run_dir / _LOCK_FILE
        self.max_bytes = max_bytes

    def exists(self) -> bool:
        try:
            with self._locked(create_directory=False) as locked:
                return self._exists_unlocked(locked.directory_fd)
        except CheckpointNotFoundError:
            return False

    def initialize(self, state: Mapping[str, Any]) -> CheckpointSnapshot:
        initial = _copy_state(state)
        _canonical_state_bytes(initial)
        with self._locked(create_directory=True) as locked:
            if self._exists_unlocked(locked.directory_fd):
                current = self._read_unlocked(locked.directory_fd)
                if _states_equal(current.state, initial):
                    return current
                raise CheckpointConflictError("checkpoint is already initialized")
            return self._write_unlocked(
                locked.directory_fd,
                initial,
                revision=1,
            )

    def load(self) -> dict[str, Any]:
        return self.read().state

    def payload_size(
        self,
        state: Mapping[str, Any],
        *,
        revision: int = common_contracts.MAX_JSON_INTEGER,
    ) -> int:
        """Return the exact authenticated envelope size without writing it."""

        body = _envelope_body(
            revision=revision,
            key_id=self.key_id,
            state=state,
        )
        envelope = dict(body)
        envelope["envelope_hmac"] = _envelope_authentication(self.identity, body)
        try:
            return len(canonical_json_bytes(envelope)) + 1
        except (TypeError, ValueError, OverflowError) as exc:
            raise CheckpointIntegrityError(
                "checkpoint state must be finite canonical JSON data"
            ) from exc

    def has_operating_capacity(self, state: Mapping[str, Any]) -> bool:
        return self.payload_size(state) <= (
            self.max_bytes - DEFAULT_CHECKPOINT_TERMINAL_RESERVE_BYTES
        )

    def read(self) -> CheckpointSnapshot:
        with self._locked(create_directory=False) as locked:
            return self._read_unlocked(locked.directory_fd)

    def save(
        self,
        state: Mapping[str, Any],
        *,
        expected_revision: int | None = None,
    ) -> CheckpointSnapshot:
        expected_revision = _validated_expected_revision(expected_revision)
        desired = _copy_state(state)
        _canonical_state_bytes(desired)
        with self._locked(create_directory=True) as locked:
            if not self._exists_unlocked(locked.directory_fd):
                if expected_revision not in (None, 0):
                    raise CheckpointConflictError(
                        f"expected revision {expected_revision}, found no checkpoint"
                    )
                return self._write_unlocked(
                    locked.directory_fd,
                    desired,
                    revision=1,
                )

            current = self._read_unlocked(locked.directory_fd)
            if expected_revision is not None and expected_revision != current.revision:
                raise CheckpointConflictError(
                    f"expected revision {expected_revision}, found {current.revision}"
                )
            if _states_equal(current.state, desired):
                return current
            return self._write_unlocked(
                locked.directory_fd,
                desired,
                revision=current.revision + 1,
            )

    def compare_and_swap(
        self,
        expected_revision: int,
        state: Mapping[str, Any],
    ) -> CheckpointSnapshot:
        return self.save(state, expected_revision=expected_revision)

    def transaction(
        self,
        mutator: Callable[[dict[str, Any]], tuple[Mapping[str, Any], T]],
        *,
        expected_revision: int | None = None,
    ) -> TransactionResult[T]:
        expected_revision = _validated_expected_revision(expected_revision)
        with self._locked(create_directory=False) as locked:
            current = self._read_unlocked(locked.directory_fd)
            if expected_revision is not None and expected_revision != current.revision:
                raise CheckpointConflictError(
                    f"expected revision {expected_revision}, found {current.revision}"
                )

            candidate, value = mutator(_copy_state(current.state))
            desired = _copy_state(candidate)
            if _states_equal(desired, current.state):
                return TransactionResult(current, value, False)
            committed = self._write_unlocked(
                locked.directory_fd,
                desired,
                revision=current.revision + 1,
            )
            return TransactionResult(committed, value, True)

    def staged_transaction(
        self,
        mutator: Callable[[dict[str, Any]], tuple[Mapping[str, Any], T]],
        *,
        stage: Callable[[], S],
        rollback: Callable[[S], None],
        expected_revision: int | None = None,
    ) -> TransactionResult[T]:
        """Commit state only after its exact envelope and staged files are valid."""

        expected_revision = _validated_expected_revision(expected_revision)
        with self._locked(create_directory=False) as locked:
            current = self._read_unlocked(locked.directory_fd)
            if expected_revision is not None and expected_revision != current.revision:
                raise CheckpointConflictError(
                    f"expected revision {expected_revision}, found {current.revision}"
                )
            candidate, value = mutator(_copy_state(current.state))
            desired = _copy_state(candidate)
            if _states_equal(desired, current.state):
                return TransactionResult(current, value, False)

            next_revision = current.revision + 1
            self._checkpoint_payload(desired, revision=next_revision)
            staged = stage()
            try:
                committed = self._write_unlocked(
                    locked.directory_fd,
                    desired,
                    revision=next_revision,
                )
            except BaseException as error:
                try:
                    observed = self._read_unlocked(locked.directory_fd)
                except BaseException as read_error:
                    if hasattr(error, "add_note"):
                        error.add_note(
                            "staged checkpoint commit could not be re-read; "
                            f"staged files retained ({type(read_error).__name__})"
                        )
                    raise error from read_error
                if observed.revision == next_revision and _states_equal(
                    observed.state, desired
                ):
                    if hasattr(error, "add_note"):
                        error.add_note(
                            "staged checkpoint candidate is committed; staged files retained"
                        )
                    raise
                if observed.revision != current.revision or not _states_equal(
                    observed.state, current.state
                ):
                    if hasattr(error, "add_note"):
                        error.add_note(
                            "staged checkpoint disposition is inconsistent; staged files retained"
                        )
                    raise
                try:
                    rollback(staged)
                except BaseException as rollback_error:
                    if hasattr(error, "add_note"):
                        error.add_note(
                            "staged checkpoint rollback failed; "
                            f"files retained ({type(rollback_error).__name__})"
                        )
                raise
            return TransactionResult(committed, value, True)

    def update(
        self,
        mutator: Callable[[dict[str, Any]], Mapping[str, Any]],
        *,
        expected_revision: int | None = None,
    ) -> CheckpointSnapshot:
        result = self.transaction(
            lambda state: (mutator(state), None),
            expected_revision=expected_revision,
        )
        return result.snapshot

    def _exists_unlocked(self, directory_fd: int) -> bool:
        try:
            descriptor = common_safe_io.open_checked_file_at(
                directory_fd,
                self.path.name,
                display_path=self.path,
                require_owner_only=True,
            )
        except FileNotFoundError:
            return False
        except common_safe_io.UnsafePathError as exc:
            raise CheckpointPermissionError(
                f"checkpoint path is not owner-only: {self.path}"
            ) from exc
        else:
            os.close(descriptor)
            return True

    def _locked(self, *, create_directory: bool) -> "_CheckpointLock":
        return _CheckpointLock(self, create_directory=create_directory)

    def _read_unlocked(self, directory_fd: int) -> CheckpointSnapshot:
        try:
            payload = common_safe_io.read_bounded_bytes_at(
                directory_fd,
                self.path.name,
                display_path=self.path,
                max_bytes=self.max_bytes,
                require_owner_only=True,
            )
        except FileNotFoundError as exc:
            raise CheckpointNotFoundError(
                f"checkpoint does not exist: {self.path}"
            ) from exc
        except common_safe_io.ReadLimitExceeded as exc:
            raise CheckpointIntegrityError(
                "checkpoint exceeds the configured size limit"
            ) from exc
        except common_safe_io.UnsafePathError as exc:
            raise CheckpointPermissionError(
                f"checkpoint path is not owner-only: {self.path}"
            ) from exc

        try:
            envelope = common_safe_io.decode_json_bytes(
                payload,
                label=str(self.path),
            )
        except common_safe_io.InvalidJsonError as exc:
            raise CheckpointIntegrityError("checkpoint is not strict JSON") from exc
        if not isinstance(envelope, dict):
            raise CheckpointIntegrityError("checkpoint envelope must be an object")
        if set(envelope) != _ENVELOPE_FIELDS:
            raise CheckpointIntegrityError(
                "checkpoint envelope has an invalid field set"
            )
        format_version = envelope.get("format_version")
        if (
            not isinstance(format_version, int)
            or isinstance(format_version, bool)
            or format_version != CHECKPOINT_FORMAT_VERSION
        ):
            raise CheckpointIntegrityError("unsupported checkpoint format version")

        revision = envelope.get("revision")
        key_id = envelope.get("key_id")
        state = envelope.get("state")
        authentication = envelope.get("envelope_hmac")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise CheckpointIntegrityError(
                "checkpoint revision must be a positive integer"
            )
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise CheckpointIntegrityError("checkpoint key_id is invalid")
        if not hmac.compare_digest(key_id, self.key_id):
            raise CheckpointIntegrityError(
                "checkpoint key_id does not match this store"
            )
        if not isinstance(state, dict):
            raise CheckpointIntegrityError("checkpoint state must be an object")
        if (
            not isinstance(authentication, str)
            or _ENVELOPE_HMAC_RE.fullmatch(authentication) is None
        ):
            raise CheckpointIntegrityError(
                "checkpoint envelope authentication is invalid"
            )

        body = {field: envelope[field] for field in _ENVELOPE_BODY_FIELDS}
        if not hmac.compare_digest(
            authentication,
            _envelope_authentication(self.identity, body),
        ):
            raise CheckpointIntegrityError(
                "checkpoint envelope authentication mismatch"
            )
        try:
            canonical_payload = canonical_json_bytes(envelope) + b"\n"
        except (TypeError, ValueError, OverflowError) as exc:
            raise CheckpointIntegrityError(
                "checkpoint contains non-canonical JSON data"
            ) from exc
        if payload != canonical_payload:
            raise CheckpointIntegrityError(
                "checkpoint bytes are not in canonical JSON form"
            )
        return CheckpointSnapshot(
            revision=revision,
            state=_copy_state(state),
            key_id=key_id,
        )

    def _write_unlocked(
        self,
        directory_fd: int,
        state: dict[str, Any],
        *,
        revision: int,
    ) -> CheckpointSnapshot:
        payload = self._checkpoint_payload(state, revision=revision)
        try:
            common_safe_io.atomic_write_bytes_at(
                directory_fd,
                self.path.name,
                payload,
                display_path=self.path,
                replace_at=self._replace,
            )
        except common_safe_io.UnsafePathError as exc:
            raise CheckpointPermissionError(
                f"checkpoint path is not owner-only: {self.path}"
            ) from exc
        return CheckpointSnapshot(
            revision=revision,
            state=_copy_state(state),
            key_id=self.key_id,
        )

    def _checkpoint_payload(self, state: dict[str, Any], *, revision: int) -> bytes:
        body = _envelope_body(
            revision=revision,
            key_id=self.key_id,
            state=state,
        )
        envelope = dict(body)
        envelope["envelope_hmac"] = _envelope_authentication(self.identity, body)
        try:
            payload = canonical_json_bytes(envelope) + b"\n"
        except (TypeError, ValueError, OverflowError) as exc:
            raise CheckpointIntegrityError(
                "checkpoint state must be finite canonical JSON data"
            ) from exc
        if len(payload) > self.max_bytes:
            raise CheckpointIntegrityError(
                "checkpoint exceeds the configured size limit"
            )
        return payload

    @staticmethod
    def _replace(directory_fd: int, source_name: str, destination_name: str) -> None:
        os.replace(
            source_name,
            destination_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )


class _CheckpointLock:
    def __init__(
        self,
        store: AtomicCheckpointStore,
        *,
        create_directory: bool,
    ) -> None:
        self.store = store
        self.create_directory = create_directory
        self.directory_fd: int = -1
        self.descriptor: int = -1

    def __enter__(self) -> "_CheckpointLock":
        try:
            _, self.directory_fd = common_safe_io.open_owner_only_directory(
                self.store.run_dir,
                create=self.create_directory,
            )
        except FileNotFoundError as exc:
            raise CheckpointNotFoundError(
                f"checkpoint directory does not exist: {self.store.run_dir}"
            ) from exc
        except (OSError, ValueError) as exc:
            raise CheckpointPermissionError(
                f"checkpoint directory is not owner-only: {self.store.run_dir}"
            ) from exc

        try:
            self.descriptor = common_safe_io.open_lock_file_at(
                self.directory_fd,
                _LOCK_FILE,
                display_path=self.store.lock_path,
            )
            common_safe_io.validate_owner_only_file_descriptor(
                self.descriptor,
                self.store.lock_path,
                directory_fd=self.directory_fd,
                name=_LOCK_FILE,
            )
            fcntl.flock(self.descriptor, fcntl.LOCK_EX)
            common_safe_io.validate_owner_only_file_descriptor(
                self.descriptor,
                self.store.lock_path,
                directory_fd=self.directory_fd,
                name=_LOCK_FILE,
            )
            return self
        except BaseException as exc:
            if self.descriptor >= 0:
                os.close(self.descriptor)
                self.descriptor = -1
            os.close(self.directory_fd)
            self.directory_fd = -1
            if isinstance(exc, common_safe_io.UnsafePathError):
                raise CheckpointPermissionError(
                    f"checkpoint lock is not owner-only: {self.store.lock_path}"
                ) from exc
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if self.descriptor >= 0:
                try:
                    fcntl.flock(self.descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(self.descriptor)
                    self.descriptor = -1
        finally:
            if self.directory_fd >= 0:
                os.close(self.directory_fd)
                self.directory_fd = -1
