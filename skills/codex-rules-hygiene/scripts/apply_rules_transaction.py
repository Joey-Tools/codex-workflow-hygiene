#!/usr/bin/env python3
"""Apply a validated default.rules candidate with bound recovery evidence."""

from __future__ import annotations

import argparse
from array import array
from collections.abc import Callable
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, field
import errno
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import select
import selectors
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata


SCHEMA_VERSION = 4
SUPPORTED_SCHEMA_VERSIONS = frozenset((1, 2, 3, SCHEMA_VERSION))
RECOVERY_TERMINAL_SCHEMA_VERSION = 1
RECOVERY_TERMINAL_RESERVED = "reserved"
RECOVERY_TERMINAL_RESTORED = "restored"
RULES_PLACEHOLDER = "{rules}"
MAX_RULES_BYTES = 8 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_DIAGNOSTIC_CHARS = 4_000
DEFAULT_VALIDATOR_TIMEOUT_SECONDS = 60.0
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
MAX_VALIDATOR_OUTPUT_BYTES = 128 * 1024
MAX_XATTR_NAME_BYTES = 64 * 1024
MAX_STAGE_DIRECTORY_ENTRIES = 1024
PRIVATE_STAGE_NAME = ".default.rules.transaction-stage"
PREPARED_CANDIDATE_SUFFIX = ".prepared-candidate"
RECOVERY_TERMINAL_RESULT_SUFFIX = ".result"
RECOVERY_TERMINAL_TEMP_MARKER = ".result-pending-"
PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON = "private_stage_descriptor_close_failed"
# The legacy stage_cleanup_retained quarantine status is intentionally not emitted.
VALIDATOR_TERM_GRACE_SECONDS = 0.25
VALIDATOR_KILL_DRAIN_SECONDS = 1.0
MANAGED_VALIDATOR_SIGNALS = tuple(
    getattr(signal, name)
    for name in ("SIGINT", "SIGTERM", "SIGHUP")
    if hasattr(signal, name)
)

LINUX_FS_IOC_GETFLAGS = 0x80086601
LINUX_AUTOMATIC_FILE_FLAGS = (
    0x00000100  # FS_DIRTY_FL
    | 0x00000200  # FS_COMPRBLK_FL
    | 0x00040000  # FS_HUGE_FILE_FL
    | 0x00080000  # FS_EXTENT_FL
    | 0x00200000  # FS_EA_INODE_FL
    | 0x00400000  # FS_EOFBLOCKS_FL
    | 0x10000000  # FS_INLINE_DATA_FL
)

EXIT_VALIDATION_FAILED = 10
EXIT_LIVE_CONFLICT = 20
EXIT_POST_REPLACE_FAILED = 30
EXIT_RECOVERY_REFUSED = 40
EXIT_RUNTIME_ERROR = 50


class TransactionError(RuntimeError):
    def __init__(
        self,
        status: str,
        message: str,
        *,
        exit_code: int = EXIT_RUNTIME_ERROR,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.exit_code = exit_code
        self.details = details or {}


class ForwardedValidatorSignal(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum
        self.cleanup_errors: list[dict[str, object]] = []


class ValidatorSignalGate:
    """Latch one managed signal until the validator PGID is parent-bound."""

    def __init__(self) -> None:
        self._armed = False
        self._interrupt_raised = False
        self._pending: int | None = None

    def handle(self, signum: int, _frame: object) -> None:
        if self._pending is None:
            self._pending = signum
        self._raise_pending_once()

    def _raise_pending_once(self) -> None:
        if self._armed and not self._interrupt_raised and self._pending is not None:
            self._interrupt_raised = True
            raise ForwardedValidatorSignal(self._pending)

    def arm(self) -> None:
        self._armed = True
        self._raise_pending_once()

    def close(self) -> None:
        self._armed = False


@dataclass(frozen=True)
class Snapshot:
    device: int
    inode: int
    size: int
    sha256: str
    mode: int
    uid: int
    gid: int
    nlink: int | None

    @classmethod
    def from_stat(cls, file_stat: os.stat_result, payload: bytes) -> Snapshot:
        return cls(
            device=file_stat.st_dev,
            inode=file_stat.st_ino,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            mode=stat.S_IMODE(file_stat.st_mode),
            uid=file_stat.st_uid,
            gid=file_stat.st_gid,
            nlink=file_stat.st_nlink,
        )

    @classmethod
    def from_json(
        cls,
        value: object,
        *,
        label: str,
        require_object_policy: bool = True,
        legacy_historical_object_policy: bool = False,
    ) -> Snapshot:
        if not isinstance(value, dict):
            raise TransactionError("receipt_invalid", f"{label} is not an object")
        identity = value.get("identity")
        content = value.get("content")
        access = value.get("access_policy")
        object_policy = value.get("object_policy")
        if not all(isinstance(item, dict) for item in (identity, content, access)):
            raise TransactionError(
                "receipt_invalid",
                f"{label} is missing a protected-property group",
            )
        assert isinstance(identity, dict)
        assert isinstance(content, dict)
        assert isinstance(access, dict)
        if require_object_policy and not isinstance(object_policy, dict):
            raise TransactionError(
                "receipt_invalid",
                f"{label} is missing object_policy",
            )
        if legacy_historical_object_policy and object_policy is not None:
            if not isinstance(object_policy, dict):
                raise TransactionError(
                    "receipt_invalid",
                    f"{label}.object_policy is invalid",
                )
            legacy_nlink = object_policy.get("nlink")
            if (
                not isinstance(legacy_nlink, int)
                or isinstance(legacy_nlink, bool)
                or legacy_nlink != 1
            ):
                raise TransactionError(
                    "receipt_invalid",
                    (
                        f"{label}.object_policy.nlink must be 1 when present "
                        "in a schema-v1 receipt"
                    ),
                )
        nlink = (
            None
            if legacy_historical_object_policy
            else (
                object_policy.get("nlink") if isinstance(object_policy, dict) else None
            )
        )
        fields = {
            "device": identity.get("device"),
            "inode": identity.get("inode"),
            "size": content.get("size"),
            "sha256": content.get("sha256"),
            "mode": access.get("mode"),
            "uid": access.get("uid"),
            "gid": access.get("gid"),
            "nlink": nlink,
        }
        for name in ("device", "inode", "size", "mode", "uid", "gid"):
            if not isinstance(fields[name], int) or isinstance(fields[name], bool):
                raise TransactionError(
                    "receipt_invalid",
                    f"{label}.{name} is not an integer",
                )
        digest = fields["sha256"]
        if not isinstance(digest, str) or not valid_sha256(digest):
            raise TransactionError(
                "receipt_invalid",
                f"{label}.sha256 is invalid",
            )
        if fields["nlink"] is not None and (
            not isinstance(fields["nlink"], int)
            or isinstance(fields["nlink"], bool)
            or fields["nlink"] < 0
        ):
            raise TransactionError(
                "receipt_invalid",
                f"{label}.nlink is invalid",
            )
        return cls(**fields)  # type: ignore[arg-type]

    def to_json(self) -> dict[str, object]:
        return {
            "identity": {"device": self.device, "inode": self.inode},
            "content": {"size": self.size, "sha256": self.sha256},
            "access_policy": {
                "mode": self.mode,
                "uid": self.uid,
                "gid": self.gid,
            },
            **(
                {"object_policy": {"nlink": self.nlink}}
                if self.nlink is not None
                else {}
            ),
        }


@dataclass(frozen=True)
class ValidatorResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limit_exceeded: bool = False
    descendants_terminated: bool = False

    @property
    def valid(self) -> bool:
        return (
            self.returncode == 0
            and not self.timed_out
            and not self.output_limit_exceeded
            and not self.descendants_terminated
        )

    def to_json(self) -> dict[str, object]:
        return {
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "output_limit_exceeded": self.output_limit_exceeded,
            "descendants_terminated": self.descendants_terminated,
            "stdout": compact(self.stdout),
            "stderr": compact(self.stderr),
        }


@dataclass
class BoundFile:
    path: Path
    name: str
    fd: int
    snapshot: Snapshot


@dataclass
class BoundDirectory:
    path: Path
    fd: int
    snapshot: Snapshot
    label: str
    require_owner_private: bool = False


@dataclass
class RecoveryMutationTracker:
    """Record when recovery may have changed receipt-bound transaction state."""

    locators: dict[str, str]
    mutation_started: bool = False
    events: list[dict[str, str]] = field(default_factory=list)
    last_observed: dict[str, object] | None = None
    cleanup_failures: list[dict[str, object]] = field(default_factory=list)
    deferred_mutation_events: list[dict[str, str]] = field(default_factory=list)

    def enter(self, operation: str, *, state: str) -> None:
        self.mutation_started = True
        self.events.append(
            {
                "operation": operation,
                "phase": "entry",
                "state": state,
            }
        )

    def complete(self, operation: str, *, state: str) -> None:
        self.events.append(
            {
                "operation": operation,
                "phase": "completion",
                "state": state,
            }
        )

    def observe_prior_mutation(self, operation: str, *, state: str) -> None:
        """Record durable evidence that an earlier recovery may have mutated state."""

        self.mutation_started = True
        event = {
            "operation": operation,
            "phase": "observed",
            "state": state,
        }
        if event not in self.events:
            self.events.append(event)

    def defer_possible_prior_mutation(
        self,
        operation: str,
        *,
        state: str,
    ) -> None:
        event = {
            "operation": operation,
            "phase": "observed",
            "state": state,
        }
        if event not in self.deferred_mutation_events:
            self.deferred_mutation_events.append(event)

    def promote_deferred_mutation(self) -> None:
        if not self.deferred_mutation_events:
            return
        self.mutation_started = True
        for event in self.deferred_mutation_events:
            if event not in self.events:
                self.events.append(event)
        self.deferred_mutation_events.clear()

    def clear_deferred_mutation(self) -> None:
        self.deferred_mutation_events.clear()

    def observe(self, observed: dict[str, object]) -> None:
        self.last_observed = observed

    def record_cleanup_failures(
        self,
        failures: list[dict[str, object]],
    ) -> None:
        self.cleanup_failures.extend(failures)

    def take_cleanup_failures(self) -> list[dict[str, object]]:
        failures = list(self.cleanup_failures)
        self.cleanup_failures.clear()
        return failures

    def details(
        self,
        *,
        state: str | None = None,
        observed: dict[str, object] | None = None,
    ) -> dict[str, object]:
        effective_observed = observed if observed is not None else self.last_observed
        if state is None and effective_observed is not None:
            observed_state = effective_observed.get("transaction_state")
            observed_hint = effective_observed.get("transaction_state_hint")
            candidate = observed_state or observed_hint
            if isinstance(candidate, str):
                state = candidate
        return {
            "mutation_journal": list(self.events),
            "recovery_locators": dict(self.locators),
            **({"transaction_state": state} if state is not None else {}),
            **(
                {"observed_state": effective_observed}
                if effective_observed is not None
                else {}
            ),
        }


def valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def compact(value: str) -> str:
    if len(value) <= MAX_DIAGNOSTIC_CHARS:
        return value
    return value[: MAX_DIAGNOSTIC_CHARS - 3] + "..."


def structured_operation_failure(
    operation: str,
    descriptor: str,
    error: BaseException,
    *,
    release_uncertain: bool = False,
) -> dict[str, object]:
    failure: dict[str, object] = {
        "operation": operation,
        "descriptor": descriptor,
        "error_type": type(error).__name__,
        "message": compact(str(error)),
    }
    if isinstance(error, OSError) and error.errno is not None:
        failure["errno"] = error.errno
        failure["errno_name"] = errno.errorcode.get(error.errno, "UNKNOWN")
    if release_uncertain:
        failure["release_uncertain"] = True
    return failure


def close_descriptors_best_effort(
    descriptors: list[tuple[str, int]],
    *,
    release_uncertain: bool = False,
) -> list[dict[str, object]]:
    """Attempt every distinct descriptor close exactly once.

    POSIX leaves the descriptor state after an interrupted ``close`` unsuitable
    for a blind retry. Record the uncertainty instead of risking a later,
    reused descriptor number.
    """

    failures: list[dict[str, object]] = []
    attempted: set[int] = set()
    for descriptor, fd in descriptors:
        if fd in attempted:
            continue
        attempted.add(fd)
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(
                structured_operation_failure(
                    "close",
                    descriptor,
                    error,
                    release_uncertain=release_uncertain,
                )
            )
    return failures


def attach_cleanup_failures_to_payload(
    payload: dict[str, object],
    failures: list[dict[str, object]],
) -> None:
    if not failures:
        return
    existing = payload.get("cleanup_failures")
    if isinstance(existing, list):
        existing.extend(failures)
    else:
        payload["cleanup_failures"] = list(failures)


def attach_failures_to_exception(
    error: BaseException,
    key: str,
    failures: list[dict[str, object]],
) -> None:
    if not failures:
        return
    if isinstance(error, TransactionError):
        existing = error.details.get(key)
        if isinstance(existing, list):
            existing.extend(failures)
        else:
            error.details[key] = list(failures)
    else:
        existing = getattr(error, key, None)
        if isinstance(existing, list):
            existing.extend(failures)
        else:
            setattr(error, key, list(failures))
    error.add_note(
        "descriptor cleanup also failed: "
        + "; ".join(
            f"{failure['descriptor']}: {failure['error_type']}: {failure['message']}"
            for failure in failures
        )
    )


def descriptor_cleanup_error(
    failures: list[dict[str, object]],
    *,
    status: str = "descriptor_cleanup_failed",
    message: str = "descriptor cleanup could not be completed",
) -> TransactionError:
    return TransactionError(
        status,
        message,
        details={"cleanup_failures": list(failures)},
    )


def finalize_descriptor_cleanup(
    descriptors: list[tuple[str, int]],
    *,
    primary_error: BaseException | None = None,
    payload: dict[str, object] | None = None,
    status: str = "descriptor_cleanup_failed",
    message: str = "descriptor cleanup could not be completed",
) -> list[dict[str, object]]:
    """Close every descriptor without displacing an established outcome."""

    failures = close_descriptors_best_effort(descriptors)
    if not failures:
        return []
    if primary_error is not None:
        attach_failures_to_exception(
            primary_error,
            "cleanup_failures",
            failures,
        )
    elif payload is not None:
        attach_cleanup_failures_to_payload(payload, failures)
    else:
        raise descriptor_cleanup_error(
            failures,
            status=status,
            message=message,
        )
    return failures


def private_stage_descriptor_cleanup_failures(
    warnings: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Normalize stage-close warnings for durable result payloads."""

    normalized: list[dict[str, object]] = []
    for warning in warnings:
        if warning.get("status") != "descriptor_cleanup_failed":
            continue
        failures = warning.get("cleanup_failures")
        if not isinstance(failures, list):
            continue
        for failure in failures:
            if not isinstance(failure, dict):
                continue
            descriptor = failure.get("descriptor")
            descriptor_class = (
                descriptor.split(":", 1)[0]
                if isinstance(descriptor, str)
                else "private_stage"
            )
            normalized.append(
                {
                    **failure,
                    "cleanup_reason": PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
                    "descriptor_class": descriptor_class,
                }
            )
    return normalized


def current_nlink_mismatches(expected: Snapshot, actual_nlink: int | None) -> bool:
    """Enforce current link policy even when a legacy receipt omitted it.

    Schema-v1 omitted historical ``nlink`` evidence. That omission cannot
    authorize a currently hard-linked transaction object, so every current
    regular-file observation still has to prove one link.
    """

    required_nlink = 1 if expected.nlink is None else expected.nlink
    return actual_nlink != required_nlink


def property_mismatches(expected: Snapshot, actual: Snapshot) -> list[str]:
    mismatches: list[str] = []
    if (expected.device, expected.inode) != (actual.device, actual.inode):
        mismatches.append("object_identity")
    if expected.size != actual.size or not hmac.compare_digest(
        expected.sha256,
        actual.sha256,
    ):
        mismatches.append("content")
    if (expected.mode, expected.uid, expected.gid) != (
        actual.mode,
        actual.uid,
        actual.gid,
    ):
        mismatches.append("access_policy")
    if current_nlink_mismatches(expected, actual.nlink):
        mismatches.append("object_policy")
    return mismatches


def content_access_and_object_policy_match(
    expected: Snapshot,
    actual: Snapshot,
) -> bool:
    return (
        expected.size == actual.size
        and hmac.compare_digest(expected.sha256, actual.sha256)
        and (expected.mode, expected.uid, expected.gid)
        == (actual.mode, actual.uid, actual.gid)
        and not current_nlink_mismatches(expected, actual.nlink)
    )


def identity_access_and_object_policy_mismatches(
    expected: Snapshot,
    actual: Snapshot,
) -> list[str]:
    mismatches: list[str] = []
    if (expected.device, expected.inode) != (actual.device, actual.inode):
        mismatches.append("object_identity")
    if (expected.mode, expected.uid, expected.gid) != (
        actual.mode,
        actual.uid,
        actual.gid,
    ):
        mismatches.append("access_policy")
    if current_nlink_mismatches(expected, actual.nlink):
        mismatches.append("object_policy")
    return mismatches


def stat_property_mismatches(
    expected: Snapshot,
    actual: os.stat_result,
) -> list[str]:
    mismatches: list[str] = []
    if (expected.device, expected.inode) != (actual.st_dev, actual.st_ino):
        mismatches.append("object_identity")
    if expected.size != actual.st_size:
        mismatches.append("content")
    if (expected.mode, expected.uid, expected.gid) != (
        stat.S_IMODE(actual.st_mode),
        actual.st_uid,
        actual.st_gid,
    ):
        mismatches.append("access_policy")
    if current_nlink_mismatches(expected, actual.st_nlink):
        mismatches.append("object_policy")
    return mismatches


def directory_property_mismatches(
    expected: Snapshot,
    actual: os.stat_result,
) -> list[str]:
    """Compare the protected properties of a directory object.

    Directory size and link count can change during ordinary child-entry churn.
    The protected property is the bound directory identity and access policy;
    exact leaf bindings are checked separately for transaction-owned entries.
    """

    mismatches: list[str] = []
    if (expected.device, expected.inode) != (actual.st_dev, actual.st_ino):
        mismatches.append("object_identity")
    if (expected.mode, expected.uid, expected.gid) != (
        stat.S_IMODE(actual.st_mode),
        actual.st_uid,
        actual.st_gid,
    ):
        mismatches.append("access_policy")
    return mismatches


def stat_identity(file_stat: os.stat_result) -> dict[str, int]:
    return {
        "device": file_stat.st_dev,
        "inode": file_stat.st_ino,
    }


def observe_directory_entry(
    directory_fd: int,
    name: str,
    *,
    expected: Snapshot | None = None,
) -> dict[str, object]:
    try:
        actual = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return {"state": "missing"}
    except OSError as error:
        return {
            "state": "unreadable",
            "errno": error.errno,
            "message": str(error),
        }
    observation: dict[str, object] = {
        "state": "present",
        "identity": stat_identity(actual),
        "size": actual.st_size,
        "access_policy": {
            "mode": stat.S_IMODE(actual.st_mode),
            "uid": actual.st_uid,
            "gid": actual.st_gid,
        },
        "object_policy": {"nlink": actual.st_nlink},
        "file_type": stat.S_IFMT(actual.st_mode),
    }
    if expected is not None:
        observation["mismatched_properties"] = stat_property_mismatches(
            expected,
            actual,
        )
    return observation


def observation_matches(observation: dict[str, object]) -> bool:
    return (
        observation.get("state") == "present"
        and observation.get("mismatched_properties") == []
    )


def _atomic_rename_function(
    operation: str,
) -> tuple[object, int, int]:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError as error:
        raise TransactionError(
            "atomic_rename_unsupported",
            f"cannot load the platform C library: {error}",
            details={"operation": operation, "platform": sys.platform},
        ) from error
    if sys.platform == "darwin":
        function_name = "renameatx_np"
        no_replace_flag = 0x00000004
        exchange_flag = 0x00000002
    elif sys.platform.startswith("linux"):
        function_name = "renameat2"
        no_replace_flag = 0x00000001
        exchange_flag = 0x00000002
    else:
        raise TransactionError(
            "atomic_rename_unsupported",
            f"atomic rename is unavailable on {sys.platform}",
            details={"operation": operation, "platform": sys.platform},
        )
    try:
        function = getattr(libc, function_name)
    except AttributeError as error:
        raise TransactionError(
            "atomic_rename_unsupported",
            f"{function_name} is unavailable on {sys.platform}",
            details={"operation": operation, "platform": sys.platform},
        ) from error
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    return function, no_replace_flag, exchange_flag


def _atomic_rename(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
    *,
    operation: str,
) -> None:
    if operation not in ("no_replace", "exchange"):
        raise TransactionError(
            "atomic_rename_operation_invalid",
            f"unsupported atomic rename operation: {operation}",
        )
    for label, name in (
        ("source", source_name),
        ("destination", destination_name),
    ):
        encoded = os.fsencode(name)
        if name in ("", ".", "..") or Path(name).name != name or b"\x00" in encoded:
            raise TransactionError(
                "path_invalid",
                f"atomic rename {label} must be one NUL-free basename",
            )
    function, no_replace_flag, exchange_flag = _atomic_rename_function(operation)
    flag = no_replace_flag if operation == "no_replace" else exchange_flag
    ctypes.set_errno(0)
    result = function(
        source_directory_fd,
        os.fsencode(source_name),
        destination_directory_fd,
        os.fsencode(destination_name),
        flag,
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        unsupported_errors = {
            errno.EINVAL,
            errno.ENOSYS,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        if error_number in unsupported_errors:
            raise TransactionError(
                "atomic_rename_unsupported",
                f"the filesystem does not support atomic {operation}",
                details={
                    "operation": operation,
                    "platform": sys.platform,
                    "errno": error_number,
                },
            )
        raise OSError(
            error_number,
            os.strerror(error_number),
            f"{source_name} -> {destination_name}",
        )


def atomic_rename_no_replace(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    _atomic_rename(
        source_directory_fd,
        source_name,
        destination_directory_fd,
        destination_name,
        operation="no_replace",
    )


def atomic_rename_exchange(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    _atomic_rename(
        source_directory_fd,
        source_name,
        destination_directory_fd,
        destination_name,
        operation="exchange",
    )


def codex_rules_path() -> Path:
    raw_root = os.environ.get("CODEX_HOME")
    root = Path(raw_root).expanduser() if raw_root else Path.home() / ".codex"
    if not root.is_absolute():
        root = Path.cwd() / root
    candidate = root / "rules" / "default.rules"
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as error:
        raise TransactionError(
            "rules_directory_unreadable",
            f"cannot resolve the Codex rules directory: {error}",
        ) from error
    return parent / "default.rules"


def resolved_leaf(raw_path: str, *, label: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.name in ("", ".", ".."):
        raise TransactionError("path_invalid", f"{label} must name one file")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise TransactionError(
            "path_parent_unreadable",
            f"cannot resolve {label} parent: {error}",
        ) from error
    return parent / path.name


def canonical_namespace_path(path: Path, *, label: str) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise TransactionError(
            "path_invalid",
            f"cannot resolve {label} for transaction namespace admission: {error}",
        ) from error


def path_namespaces_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def normalized_namespace_component(component: str) -> str:
    """Return a conservative case/Unicode-insensitive component key."""

    normalized = unicodedata.normalize("NFKC", component)
    return unicodedata.normalize("NFKC", normalized.casefold())


def component_namespaces_overlap(
    left: tuple[str, ...],
    right: tuple[str, ...],
) -> bool:
    shorter = min(len(left), len(right))
    return left[:shorter] == right[:shorter]


def bound_namespace_directory_identity(
    path: Path,
    *,
    label: str,
) -> tuple[int, int, int] | None:
    """Bind one existing directory without following its final symlink."""

    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
            return None
        raise TransactionError(
            "path_invalid",
            f"cannot bind {label} directory identity: {error}",
        ) from error
    primary_error: BaseException | None = None
    identity: tuple[int, int, int] | None = None
    try:
        descriptor_stat = os.fstat(fd)
        path_stat = os.stat(path, follow_symlinks=False)
        descriptor_identity = (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
            stat.S_IFMT(descriptor_stat.st_mode),
        )
        path_identity = (
            path_stat.st_dev,
            path_stat.st_ino,
            stat.S_IFMT(path_stat.st_mode),
        )
        if descriptor_identity != path_identity:
            raise TransactionError(
                "path_invalid",
                f"{label} directory identity changed during namespace admission",
            )
        identity = descriptor_identity
        return identity
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [(f"namespace_directory:{label}", fd)],
            primary_error=primary_error,
        )


def bound_namespace_ancestor_identities(
    path: Path,
    *,
    label: str,
) -> set[tuple[int, int, int]]:
    identities: set[tuple[int, int, int]] = set()
    for index, candidate in enumerate((path, *path.parents)):
        identity = bound_namespace_directory_identity(
            candidate,
            label=f"{label}_ancestor_{index}",
        )
        if identity is not None:
            identities.add(identity)
    return identities


def namespace_components_under_bound_parent(
    path: Path,
    *,
    bound_parent_identity: tuple[int, int, int],
    label: str,
) -> set[tuple[str, ...]]:
    sequences: set[tuple[str, ...]] = set()
    forms = (
        path,
        canonical_namespace_path(path, label=label),
    )
    for form_index, form in enumerate(forms):
        for ancestor_index, ancestor in enumerate((form, *form.parents)):
            identity = bound_namespace_directory_identity(
                ancestor,
                label=f"{label}_form_{form_index}_ancestor_{ancestor_index}",
            )
            if identity != bound_parent_identity:
                continue
            relative = form.relative_to(ancestor)
            sequences.add(
                tuple(
                    normalized_namespace_component(component)
                    for component in relative.parts
                )
            )
            break
    return sequences


def reject_fixed_stage_namespace_overlap(
    rules_parent: Path,
    paths: list[tuple[str, Path]],
) -> None:
    """Reject string, identity, case, and Unicode aliases of the fixed stage."""

    fixed_stage = rules_parent / PRIVATE_STAGE_NAME
    stage_forms = (
        fixed_stage,
        canonical_namespace_path(fixed_stage, label="fixed_stage"),
    )
    rules_parent_identity = bound_namespace_directory_identity(
        rules_parent,
        label="rules_parent",
    )
    if rules_parent_identity is None:
        raise TransactionError(
            "path_invalid",
            "rules parent disappeared during transaction namespace admission",
        )
    stage_identity = next(
        (
            identity
            for index, stage_form in enumerate(stage_forms)
            if (
                identity := bound_namespace_directory_identity(
                    stage_form,
                    label=f"fixed_stage_form_{index}",
                )
            )
            is not None
        ),
        None,
    )
    stage_ancestor_identities: set[tuple[int, int, int]] = set()
    for index, stage_form in enumerate(stage_forms):
        stage_ancestor_identities.update(
            bound_namespace_ancestor_identities(
                stage_form,
                label=f"fixed_stage_form_{index}",
            )
        )
    normalized_stage = (normalized_namespace_component(PRIVATE_STAGE_NAME),)
    for label, path in paths:
        path_forms = (
            path,
            canonical_namespace_path(path, label=label),
        )
        string_overlap = any(
            path_namespaces_overlap(path_form, stage_form)
            for path_form in path_forms
            for stage_form in stage_forms
        )
        path_ancestor_identities: set[tuple[int, int, int]] = set()
        path_leaf_identities: set[tuple[int, int, int]] = set()
        for index, path_form in enumerate(path_forms):
            path_ancestor_identities.update(
                bound_namespace_ancestor_identities(
                    path_form,
                    label=f"{label}_form_{index}",
                )
            )
            identity = bound_namespace_directory_identity(
                path_form,
                label=f"{label}_form_{index}",
            )
            if identity is not None:
                path_leaf_identities.add(identity)
        identity_overlap = (
            stage_identity is not None and stage_identity in path_ancestor_identities
        ) or bool(path_leaf_identities & stage_ancestor_identities)
        component_overlap = any(
            component_namespaces_overlap(components, normalized_stage)
            for components in namespace_components_under_bound_parent(
                path,
                bound_parent_identity=rules_parent_identity,
                label=label,
            )
        )
        if string_overlap or identity_overlap or component_overlap:
            raise TransactionError(
                "path_invalid",
                (
                    f"{label} overlaps the fixed transaction-stage namespace "
                    "by leaf, ancestor, descendant, canonical identity, "
                    "case folding, or Unicode normalization"
                ),
                details={
                    "path": str(path),
                    "canonical_path": str(path_forms[1]),
                    "fixed_stage": str(fixed_stage),
                    "canonical_fixed_stage": str(stage_forms[1]),
                },
            )


def read_fd(fd: int, *, label: str, max_bytes: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    retained = 0
    while True:
        chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - retained))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        retained += len(chunk)
        if retained > max_bytes:
            raise TransactionError(
                f"{label}_too_large",
                f"{label} exceeds the {max_bytes}-byte limit",
            )


def read_bound_fd(
    fd: int,
    *,
    label: str,
    max_bytes: int = MAX_RULES_BYTES,
) -> tuple[bytes, Snapshot]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise TransactionError(
            f"{label}_not_regular",
            f"{label} is not a regular file",
        )
    first = read_fd(fd, label=label, max_bytes=max_bytes)
    second = read_fd(fd, label=label, max_bytes=max_bytes)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise TransactionError(
            f"{label}_identity_changed",
            f"{label} identity changed while it was read",
        )
    if first != second or after.st_size != len(second):
        raise TransactionError(
            f"{label}_content_changed",
            f"{label} content changed while it was read",
        )
    before_access = (stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid)
    after_access = (stat.S_IMODE(after.st_mode), after.st_uid, after.st_gid)
    if before_access != after_access:
        raise TransactionError(
            f"{label}_access_policy_changed",
            f"{label} access policy changed while it was read",
        )
    if before.st_nlink != after.st_nlink:
        raise TransactionError(
            f"{label}_object_policy_changed",
            f"{label} link count changed while it was read",
        )
    return second, Snapshot.from_stat(after, second)


def verify_entry_binding(
    directory_fd: int,
    name: str,
    expected: Snapshot,
    *,
    label: str,
) -> None:
    try:
        entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise TransactionError(
            f"{label}_missing",
            f"{label} path is missing",
        ) from error
    mismatches = stat_property_mismatches(expected, entry_stat)
    if mismatches:
        raise TransactionError(
            f"{label}_changed",
            f"{label} path no longer names the bound object",
            details={"mismatched_properties": mismatches},
        )


def open_untrusted_regular_file(
    path: str | Path,
    *,
    label: str,
    writable: bool = False,
    dir_fd: int | None = None,
) -> int:
    """Open one untrusted pathname without waiting on a FIFO replacement."""

    flags = (
        (os.O_RDWR if writable else os.O_RDONLY)
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise TransactionError(
                f"{label}_not_regular",
                f"{label} is not a regular file",
            )
    except BaseException as error:
        finalize_descriptor_cleanup(
            [(label, fd)],
            primary_error=error,
        )
        raise
    return fd


def read_stable(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_RULES_BYTES,
    require_modeled_metadata: bool = False,
) -> tuple[bytes, Snapshot]:
    try:
        fd = open_untrusted_regular_file(path, label=label)
    except FileNotFoundError as error:
        raise TransactionError(f"{label}_missing", f"{label} is missing") from error
    except PermissionError as error:
        raise TransactionError(
            f"{label}_unreadable",
            f"{label} is unreadable: {error}",
        ) from error
    except OSError as error:
        raise TransactionError(
            f"{label}_unreadable",
            f"cannot open {label}: {error}",
        ) from error
    primary_error: BaseException | None = None
    outcome: tuple[bytes, Snapshot] | None = None
    try:
        payload, snapshot = read_bound_fd(
            fd,
            label=label,
            max_bytes=max_bytes,
        )
        if require_modeled_metadata:
            reject_unmodeled_metadata_fd(fd, label=label)
        try:
            path_stat = os.stat(path, follow_symlinks=False)
        except FileNotFoundError as error:
            raise TransactionError(
                f"{label}_missing",
                f"{label} disappeared after it was read",
            ) from error
        if not stat.S_ISREG(path_stat.st_mode):
            raise TransactionError(
                f"{label}_not_regular",
                f"{label} path no longer names a regular file",
            )
        mismatches = stat_property_mismatches(snapshot, path_stat)
        if mismatches:
            if "object_identity" in mismatches:
                status = f"{label}_identity_changed"
            elif "content" in mismatches:
                status = f"{label}_content_changed"
            else:
                status = f"{label}_access_policy_changed"
            raise TransactionError(
                status,
                f"{label} path changed after it was read",
                details={"mismatched_properties": mismatches},
            )
        if require_modeled_metadata:
            reject_unmodeled_metadata_fd(fd, label=label)
        outcome = (payload, snapshot)
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [(label, fd)],
            primary_error=primary_error,
        )


def revalidate_candidate_source(
    path: Path,
    expected: Snapshot,
    *,
    candidate_sha256: str,
) -> bytes:
    payload, actual = read_stable(
        path,
        label="candidate_source",
        require_modeled_metadata=True,
    )
    mismatches = property_mismatches(expected, actual)
    if not hmac.compare_digest(actual.sha256, candidate_sha256):
        if "content" not in mismatches:
            mismatches.append("content")
    if mismatches:
        raise TransactionError(
            "candidate_source_changed",
            "candidate source changed after its audited bytes were admitted",
            exit_code=EXIT_VALIDATION_FAILED,
            details={
                "mismatched_properties": mismatches,
                "expected_candidate_sha256": candidate_sha256,
                "actual_candidate_sha256": actual.sha256,
            },
        )
    return payload


def directory_snapshot(path: Path) -> Snapshot:
    try:
        file_stat = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise TransactionError(
            "rules_directory_unreadable",
            f"cannot inspect rules directory: {error}",
        ) from error
    if not stat.S_ISDIR(file_stat.st_mode):
        raise TransactionError(
            "rules_directory_not_directory",
            "rules parent is not a directory",
        )
    return Snapshot.from_stat(file_stat, b"")


def _metadata_inspection_error(
    label: str,
    message: str,
    *,
    error: OSError | None = None,
) -> TransactionError:
    details: dict[str, object] = {"platform": sys.platform}
    if error is not None:
        details.update({"errno": error.errno, "error": str(error)})
    return TransactionError(
        "metadata_inspection_unsupported",
        f"{label} metadata cannot be inspected safely: {message}",
        details=details,
    )


def _bound_file_flags(fd: int, *, label: str) -> int:
    file_stat = os.fstat(fd)
    stat_flags = getattr(file_stat, "st_flags", None)
    if stat_flags is not None:
        return int(stat_flags)
    if not sys.platform.startswith("linux"):
        raise _metadata_inspection_error(
            label,
            "descriptor-backed file flags are unavailable",
        )
    raw_flags = array("I", [0])
    try:
        fcntl.ioctl(fd, LINUX_FS_IOC_GETFLAGS, raw_flags, True)
    except OSError as error:
        raise _metadata_inspection_error(
            label,
            "FS_IOC_GETFLAGS failed",
            error=error,
        ) from error
    return int(raw_flags[0]) & ~LINUX_AUTOMATIC_FILE_FLAGS


def _list_bound_xattrs(fd: int, *, label: str) -> tuple[bytes, ...]:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.flistxattr
    except (OSError, AttributeError) as error:
        raise _metadata_inspection_error(
            label,
            "flistxattr is unavailable",
        ) from error
    function.restype = ctypes.c_ssize_t
    if sys.platform == "darwin":
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]

        def invoke(buffer: object, size: int) -> int:
            return int(function(fd, buffer, size, 0))

    elif sys.platform.startswith("linux"):
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]

        def invoke(buffer: object, size: int) -> int:
            return int(function(fd, buffer, size))

    else:
        raise _metadata_inspection_error(
            label,
            "descriptor-backed xattr inspection is unavailable",
        )

    ctypes.set_errno(0)
    needed = invoke(None, 0)
    if needed < 0:
        error_number = ctypes.get_errno() or errno.EIO
        error = OSError(error_number, os.strerror(error_number))
        raise _metadata_inspection_error(
            label,
            "flistxattr size query failed",
            error=error,
        )
    if needed == 0:
        return ()
    if needed > MAX_XATTR_NAME_BYTES:
        return (b"<xattr-name-list-exceeds-limit>",)
    buffer = ctypes.create_string_buffer(needed)
    ctypes.set_errno(0)
    received = invoke(buffer, needed)
    if received < 0:
        error_number = ctypes.get_errno() or errno.EIO
        if error_number == errno.ERANGE:
            return (b"<xattr-name-list-raced-limit>",)
        error = OSError(error_number, os.strerror(error_number))
        raise _metadata_inspection_error(
            label,
            "flistxattr read failed",
            error=error,
        )
    if received == 0:
        return ()
    return tuple(name for name in bytes(buffer.raw[:received]).split(b"\0") if name)


def _bound_has_extended_acl(fd: int, *, label: str) -> bool:
    if sys.platform.startswith("linux"):
        # Linux access ACLs are descriptor-listed system.posix_acl_* or NFSv4
        # xattrs and are rejected by the same bound xattr admission pass.
        return False
    if sys.platform != "darwin":
        raise _metadata_inspection_error(
            label,
            "descriptor-backed ACL inspection is unavailable",
        )
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        acl_get_fd_np = libc.acl_get_fd_np
        acl_free = libc.acl_free
    except (OSError, AttributeError) as error:
        raise _metadata_inspection_error(
            label,
            "Darwin ACL descriptor APIs are unavailable",
        ) from error
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(fd, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return False
        error = OSError(
            error_number or errno.EIO, os.strerror(error_number or errno.EIO)
        )
        raise _metadata_inspection_error(
            label,
            "acl_get_fd_np failed",
            error=error,
        )
    try:
        return True
    finally:
        if acl_free(acl) != 0:
            error_number = ctypes.get_errno() or errno.EIO
            error = OSError(error_number, os.strerror(error_number))
            raise TransactionError(
                f"{label}_metadata_unreadable",
                f"{label} ACL handle could not be released: {error}",
            )


def reject_unmodeled_metadata_fd(
    fd: int,
    *,
    label: str = "live_rules",
    require_directory: bool = False,
) -> None:
    try:
        file_stat = os.fstat(fd)
    except OSError as error:
        raise TransactionError(
            f"{label}_metadata_unreadable",
            f"{label} bound metadata is unreadable: {error}",
        ) from error
    expected_type_matches = (
        stat.S_ISDIR(file_stat.st_mode)
        if require_directory
        else stat.S_ISREG(file_stat.st_mode)
    )
    if not expected_type_matches:
        expected_type = "directory" if require_directory else "regular file"
        status_suffix = "not_directory" if require_directory else "not_regular"
        raise TransactionError(
            f"{label}_{status_suffix}",
            f"{label} is not a {expected_type} while metadata is inspected",
        )
    file_flags = _bound_file_flags(fd, label=label)
    if file_flags:
        raise TransactionError(
            "unsupported_file_flags",
            f"{label} uses file flags that this helper does not preserve",
            details={"st_flags": file_flags},
        )
    extended_attributes = _list_bound_xattrs(fd, label=label)
    acl_attributes = tuple(
        name
        for name in extended_attributes
        if b"acl" in name.lower() or name == b"com.apple.system.Security"
    )
    if acl_attributes or _bound_has_extended_acl(fd, label=label):
        raise TransactionError(
            "unsupported_access_control_list",
            f"{label} uses an ACL that this helper does not preserve",
            details={
                "acl_extended_attributes": sorted(
                    os.fsdecode(name) for name in acl_attributes
                )
            },
        )
    # Darwin attaches a kernel-managed provenance record to ordinary created
    # files and may recreate it after removal. Its opaque value is deliberately
    # outside the protected content/access policy; every caller-created xattr
    # remains unmodeled and is rejected.
    modeled_platform_attributes = (
        {b"com.apple.provenance"} if sys.platform == "darwin" else set()
    )
    unmodeled_attributes = tuple(
        name for name in extended_attributes if name not in modeled_platform_attributes
    )
    if unmodeled_attributes:
        raise TransactionError(
            "unsupported_extended_attributes",
            f"{label} uses extended attributes that this helper does not preserve",
            details={
                "extended_attributes": sorted(
                    os.fsdecode(name) for name in unmodeled_attributes
                )
            },
        )


def reject_unmodeled_metadata(path: Path, *, label: str = "live_rules") -> None:
    try:
        read_stable(
            path,
            label=label,
            require_modeled_metadata=True,
        )
    except PermissionError as error:
        raise TransactionError(
            f"{label}_unreadable",
            f"{label} metadata is unreadable: {error}",
        ) from error


def validate_bound_directory(binding: BoundDirectory) -> Snapshot:
    try:
        descriptor_actual = os.fstat(binding.fd)
        path_actual = os.stat(binding.path, follow_symlinks=False)
    except OSError as error:
        raise TransactionError(
            f"{binding.label}_parent_changed",
            f"{binding.label} parent binding is unavailable: {error}",
        ) from error
    if not stat.S_ISDIR(descriptor_actual.st_mode) or not stat.S_ISDIR(
        path_actual.st_mode
    ):
        raise TransactionError(
            f"{binding.label}_parent_changed",
            f"{binding.label} parent no longer names a directory",
        )
    mismatches = directory_property_mismatches(
        binding.snapshot,
        descriptor_actual,
    )
    mismatches.extend(
        mismatch
        for mismatch in directory_property_mismatches(
            binding.snapshot,
            path_actual,
        )
        if mismatch not in mismatches
    )
    if mismatches:
        raise TransactionError(
            f"{binding.label}_parent_changed",
            f"{binding.label} parent identity or access policy changed",
            details={"mismatched_properties": mismatches},
        )
    if binding.require_owner_private and (
        descriptor_actual.st_uid != os.geteuid()
        or stat.S_IMODE(descriptor_actual.st_mode) & 0o077
    ):
        raise TransactionError(
            f"{binding.label}_parent_not_private",
            f"{binding.label} parent directory must remain owner-only",
        )
    reject_unmodeled_metadata_fd(
        binding.fd,
        label=f"{binding.label}_parent",
        require_directory=True,
    )
    try:
        descriptor_final = os.fstat(binding.fd)
        path_final = os.stat(binding.path, follow_symlinks=False)
    except OSError as error:
        raise TransactionError(
            f"{binding.label}_parent_changed",
            f"{binding.label} parent binding changed during metadata admission: {error}",
        ) from error
    final_mismatches = directory_property_mismatches(
        binding.snapshot,
        descriptor_final,
    )
    final_mismatches.extend(
        mismatch
        for mismatch in directory_property_mismatches(
            binding.snapshot,
            path_final,
        )
        if mismatch not in final_mismatches
    )
    if final_mismatches:
        raise TransactionError(
            f"{binding.label}_parent_changed",
            f"{binding.label} parent changed during metadata admission",
            details={"mismatched_properties": final_mismatches},
        )
    reject_unmodeled_metadata_fd(
        binding.fd,
        label=f"{binding.label}_parent",
        require_directory=True,
    )
    return Snapshot.from_stat(descriptor_final, b"")


def bind_directory(
    path: Path,
    *,
    label: str,
    require_owner_private: bool = False,
    expected: Snapshot | None = None,
) -> BoundDirectory:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise TransactionError(
            f"{label}_parent_unreadable",
            f"cannot bind {label} parent directory: {error}",
        ) from error
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISDIR(file_stat.st_mode):
            raise TransactionError(
                f"{label}_parent_not_directory",
                f"{label} parent is not a directory",
            )
        binding = BoundDirectory(
            path=path,
            fd=fd,
            snapshot=(
                expected if expected is not None else Snapshot.from_stat(file_stat, b"")
            ),
            label=label,
            require_owner_private=require_owner_private,
        )
        validate_bound_directory(binding)
        return binding
    except BaseException as error:
        finalize_descriptor_cleanup(
            [(f"{label}_parent", fd)],
            primary_error=error,
        )
        raise


def validate_bound_regular_file(
    binding: BoundFile,
    parent: BoundDirectory,
    *,
    label: str,
    max_bytes: int = MAX_RULES_BYTES,
) -> tuple[bytes, Snapshot]:
    validate_bound_directory(parent)
    _payload, actual = read_bound_fd(
        binding.fd,
        label=label,
        max_bytes=max_bytes,
    )
    reject_unmodeled_metadata_fd(binding.fd, label=label)
    mismatches = property_mismatches(binding.snapshot, actual)
    if mismatches:
        raise TransactionError(
            f"{label}_changed",
            f"{label} protected properties changed",
            details={"mismatched_properties": mismatches},
        )
    verify_entry_binding(
        parent.fd,
        binding.name,
        binding.snapshot,
        label=label,
    )
    reject_unmodeled_metadata_fd(binding.fd, label=label)
    final_payload, final = read_bound_fd(
        binding.fd,
        label=label,
        max_bytes=max_bytes,
    )
    reject_unmodeled_metadata_fd(binding.fd, label=label)
    final_mismatches = property_mismatches(binding.snapshot, final)
    if final_mismatches:
        raise TransactionError(
            f"{label}_changed",
            f"{label} protected properties changed during final admission",
            details={"mismatched_properties": final_mismatches},
        )
    verify_entry_binding(
        parent.fd,
        binding.name,
        binding.snapshot,
        label=label,
    )
    validate_bound_directory(parent)
    return final_payload, final


def bind_regular_file(
    path: Path,
    parent: BoundDirectory,
    *,
    label: str,
    max_bytes: int = MAX_RULES_BYTES,
    writable: bool = False,
) -> BoundFile:
    if path.parent != parent.path or Path(path.name).name != path.name:
        raise TransactionError(
            "path_invalid",
            f"{label} must be one child of its bound parent",
        )
    try:
        fd = open_untrusted_regular_file(
            path.name,
            label=label,
            writable=writable,
            dir_fd=parent.fd,
        )
    except FileNotFoundError as error:
        raise TransactionError(f"{label}_missing", f"{label} is missing") from error
    except OSError as error:
        raise TransactionError(
            f"{label}_unreadable",
            f"cannot bind {label}: {error}",
        ) from error
    try:
        payload, snapshot = read_bound_fd(
            fd,
            label=label,
            max_bytes=max_bytes,
        )
        binding = BoundFile(
            path=path,
            name=path.name,
            fd=fd,
            snapshot=snapshot,
        )
        validate_bound_regular_file(
            binding,
            parent,
            label=label,
            max_bytes=max_bytes,
        )
        return binding
    except BaseException as error:
        finalize_descriptor_cleanup(
            [(label, fd)],
            primary_error=error,
        )
        raise


def read_bound_regular_child(
    path: Path,
    parent: BoundDirectory,
    *,
    label: str,
    max_bytes: int = MAX_RULES_BYTES,
) -> tuple[bytes, Snapshot]:
    binding = bind_regular_file(
        path,
        parent,
        label=label,
        max_bytes=max_bytes,
    )
    primary_error: BaseException | None = None
    outcome: tuple[bytes, Snapshot] | None = None
    try:
        outcome = validate_bound_regular_file(
            binding,
            parent,
            label=label,
            max_bytes=max_bytes,
        )
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [(label, binding.fd)],
            primary_error=primary_error,
        )


def write_exclusive(
    path: Path,
    payload: bytes,
    *,
    mode: int = 0o600,
    uid: int | None = None,
    gid: int | None = None,
) -> Snapshot:
    fd, snapshot = _write_exclusive_bound(
        path,
        payload,
        mode=mode,
        uid=uid,
        gid=gid,
    )
    finalize_descriptor_cleanup([("exclusive_write", fd)])
    return snapshot


def retained_created_object(
    fd: int,
    path: Path,
    *,
    directory_fd: int | None = None,
    name: str | None = None,
) -> dict[str, object]:
    created = os.fstat(fd)
    if directory_fd is None:
        try:
            current = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            observation: dict[str, object] = {"state": "missing"}
        except OSError as error:
            observation = {
                "state": "unreadable",
                "errno": error.errno,
                "message": str(error),
            }
        else:
            observation = {
                "state": "present",
                "identity": stat_identity(current),
            }
    else:
        assert name is not None
        observation = observe_directory_entry(directory_fd, name)
    created_identity = stat_identity(created)
    path_matches = observation.get("identity") == created_identity
    return {
        "created_object": {
            "identity": created_identity,
            "size": created.st_size,
            "access_policy": {
                "mode": stat.S_IMODE(created.st_mode),
                "uid": created.st_uid,
                "gid": created.st_gid,
            },
            "object_policy": {"nlink": created.st_nlink},
        },
        "last_known_path": str(path),
        "path_observation": observation,
        "recovery_locator": str(path) if path_matches else None,
        "retention_status": (
            "verified_namespace_link"
            if path_matches and created.st_nlink > 0
            else "descriptor_only_or_unlocatable"
        ),
        "cleanup_policy": (
            "retained_no_pathname_unlink"
            if path_matches and created.st_nlink > 0
            else "no_false_retention_claim"
        ),
    }


def _write_exclusive_bound(
    path: Path,
    payload: bytes,
    *,
    mode: int = 0o600,
    uid: int | None = None,
    gid: int | None = None,
    directory_fd: int | None = None,
    name: str | None = None,
) -> tuple[int, Snapshot]:
    flags = (
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    open_path: str | Path = path
    if directory_fd is not None:
        if name is None or Path(name).name != name:
            raise TransactionError(
                "path_invalid",
                "directory-relative exclusive write requires one basename",
            )
        open_path = name
    try:
        fd = os.open(open_path, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as error:
        raise TransactionError(
            "path_exists",
            f"refusing to replace existing path: {path}",
        ) from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise TransactionError("write_failed", f"short write to {path}")
            offset += written
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
        os.fchmod(fd, mode)
        os.fsync(fd)
        _written, snapshot = read_bound_fd(fd, label="staged_file")
        if directory_fd is None:
            path_stat = os.stat(path, follow_symlinks=False)
            mismatches = stat_property_mismatches(snapshot, path_stat)
            if mismatches:
                raise TransactionError(
                    "staged_file_changed",
                    "exclusive-write path no longer names the created object",
                    details={"mismatched_properties": mismatches},
                )
        else:
            assert name is not None
            verify_entry_binding(
                directory_fd,
                name,
                snapshot,
                label="staged_file",
            )
        return fd, snapshot
    except BaseException as error:
        try:
            retained = retained_created_object(
                fd,
                path,
                directory_fd=directory_fd,
                name=name,
            )
        except OSError as inspection_error:
            retained = {
                "last_known_path": str(path),
                "recovery_locator": None,
                "retention_status": "inspection_failed",
                "cleanup_policy": "no_false_retention_claim",
                "inspection_error": str(inspection_error),
            }
        cleanup_failures = close_descriptors_best_effort([("exclusive_write", fd)])
        if isinstance(error, TransactionError):
            error.details.setdefault("retained_created_object", retained)
            attach_failures_to_exception(
                error,
                "cleanup_failures",
                cleanup_failures,
            )
            raise
        if isinstance(error, Exception):
            retained_status = retained.get("retention_status")
            details: dict[str, object] = {
                "retained_created_object": retained,
            }
            if cleanup_failures:
                details["cleanup_failures"] = cleanup_failures
            raise TransactionError(
                "write_failed",
                (
                    "exclusive write failed; created object has a verified "
                    f"namespace link: {error}"
                    if retained_status == "verified_namespace_link"
                    else (
                        "exclusive write failed; persistent retention could not "
                        f"be proved: {error}"
                    )
                ),
                details=details,
            ) from error
        attach_failures_to_exception(
            error,
            "cleanup_failures",
            cleanup_failures,
        )
        raise


def bounded_directory_entries(
    directory_fd: int,
    *,
    limit: int = MAX_STAGE_DIRECTORY_ENTRIES,
) -> tuple[list[str], bool]:
    """Read at most ``limit + 1`` directory entry names."""

    names: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > limit:
                return names, True
    return names, False


class PrivateStage:
    def __init__(
        self,
        rules_parent: Path,
        *,
        rules_parent_expected: Snapshot | None = None,
        recovery_stage_expected: Snapshot | None = None,
        recovery_candidate_expected: Snapshot | None = None,
    ) -> None:
        recovery_mode = recovery_stage_expected is not None
        if recovery_candidate_expected is not None and not recovery_mode:
            raise TransactionError(
                "receipt_invalid",
                "recovery candidate binding requires a stage snapshot",
            )
        directory_flags = (
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        self.rules_parent = rules_parent
        self.rules_parent_fd = os.open(rules_parent, directory_flags)
        try:
            parent_stat = os.fstat(self.rules_parent_fd)
            parent_path_stat = os.stat(rules_parent, follow_symlinks=False)
            parent_snapshot = (
                rules_parent_expected
                if rules_parent_expected is not None
                else Snapshot.from_stat(parent_stat, b"")
            )
            parent_mismatches = directory_property_mismatches(
                parent_snapshot,
                parent_stat,
            )
            parent_mismatches.extend(
                mismatch
                for mismatch in directory_property_mismatches(
                    parent_snapshot,
                    parent_path_stat,
                )
                if mismatch not in parent_mismatches
            )
            if parent_mismatches:
                raise TransactionError(
                    "rules_directory_changed",
                    "rules directory no longer matches the bound transaction directory",
                    details={"mismatched_properties": parent_mismatches},
                )
            self.rules_parent_snapshot = parent_snapshot
            self.rules_parent_binding = BoundDirectory(
                path=rules_parent,
                fd=self.rules_parent_fd,
                snapshot=self.rules_parent_snapshot,
                label="rules",
            )
            validate_bound_directory(self.rules_parent_binding)
        except BaseException as error:
            finalize_descriptor_cleanup(
                [("rules_parent", self.rules_parent_fd)],
                primary_error=error,
            )
            raise
        self.stage_name = PRIVATE_STAGE_NAME
        if not recovery_mode:
            try:
                os.mkdir(self.stage_name, 0o700, dir_fd=self.rules_parent_fd)
            except FileExistsError:
                pass
            except OSError as error:
                transaction_error = TransactionError(
                    "private_stage_unavailable",
                    f"cannot create the private staging directory: {error}",
                )
                finalize_descriptor_cleanup(
                    [("rules_parent", self.rules_parent_fd)],
                    primary_error=transaction_error,
                )
                raise transaction_error from error
            except BaseException as error:
                finalize_descriptor_cleanup(
                    [("rules_parent", self.rules_parent_fd)],
                    primary_error=error,
                )
                raise
        self.path = rules_parent / self.stage_name
        try:
            self.stage_fd = os.open(
                self.stage_name,
                directory_flags,
                dir_fd=self.rules_parent_fd,
            )
            stage_stat = os.fstat(self.stage_fd)
            stage_path_stat = os.stat(
                self.stage_name,
                dir_fd=self.rules_parent_fd,
                follow_symlinks=False,
            )
            stage_snapshot = (
                recovery_stage_expected
                if recovery_stage_expected is not None
                else Snapshot.from_stat(stage_stat, b"")
            )
            if (
                not stat.S_ISDIR(stage_stat.st_mode)
                or stage_stat.st_uid != os.geteuid()
                or stat.S_IMODE(stage_stat.st_mode) != 0o700
                or directory_property_mismatches(
                    stage_snapshot,
                    stage_stat,
                )
                or directory_property_mismatches(
                    stage_snapshot,
                    stage_path_stat,
                )
            ):
                raise TransactionError(
                    "private_stage_invalid",
                    "staging directory is not the bound owner-only directory",
                )
            reject_unmodeled_metadata_fd(
                self.stage_fd,
                label="private_stage",
                require_directory=True,
            )
            stage_entries, entries_exceeded = bounded_directory_entries(self.stage_fd)
            if entries_exceeded:
                raise TransactionError(
                    "private_stage_retained",
                    "private staging evidence exceeds the inspection bound",
                    details={"entry_count_lower_bound": len(stage_entries)},
                )
            expected_entries = (
                ["candidate"] if recovery_candidate_expected is not None else []
            )
            if sorted(stage_entries) != expected_entries:
                raise TransactionError(
                    "private_stage_retained",
                    (
                        "private staging evidence does not match the receipt-bound "
                        "recovery candidate"
                        if recovery_mode
                        else (
                            "private staging evidence from an unfinished transaction "
                            "requires recovery before a new apply"
                        )
                    ),
                    details={
                        "retained_entries": sorted(stage_entries),
                        "expected_entries": expected_entries,
                        "stage_path": str(self.path),
                    },
                )
        except BaseException as error:
            stage_identity_details: dict[str, object] = {
                "last_known_path": str(self.path),
                "cleanup_policy": "retained_no_pathname_remove",
            }
            try:
                stage_identity_details["identity"] = stat_identity(
                    os.stat(
                        self.stage_name,
                        dir_fd=self.rules_parent_fd,
                        follow_symlinks=False,
                    )
                )
            except OSError:
                pass
            finalize_descriptor_cleanup(
                [
                    *(
                        [("private_stage", self.stage_fd)]
                        if hasattr(self, "stage_fd")
                        else []
                    ),
                    ("rules_parent", self.rules_parent_fd),
                ],
                primary_error=error,
            )
            if isinstance(error, TransactionError):
                error.details.setdefault("retained_stage", stage_identity_details)
            raise
        self.stage_snapshot = stage_snapshot
        self.files: dict[Path, BoundFile] = {}
        self.extra_fds: list[int] = []
        self.known_parent_names: set[str] = {"default.rules"}
        self.mutation_uncertain = False
        self.closed = False
        if recovery_candidate_expected is not None:
            recovery_candidate = self.path / "candidate"
            stage_parent = BoundDirectory(
                path=self.path,
                fd=self.stage_fd,
                snapshot=self.stage_snapshot,
                label="private_stage",
                require_owner_private=True,
            )
            try:
                binding = bind_regular_file(
                    recovery_candidate,
                    stage_parent,
                    label="staged_backup",
                )
                _payload, actual = validate_bound_regular_file(
                    binding,
                    stage_parent,
                    label="staged_backup",
                )
                mismatches = property_mismatches(
                    recovery_candidate_expected,
                    actual,
                )
                if mismatches:
                    raise TransactionError(
                        "staged_backup_changed",
                        "staged recovery candidate no longer matches the receipt",
                        exit_code=EXIT_RECOVERY_REFUSED,
                        details={"mismatched_properties": mismatches},
                    )
            except BaseException as error:
                self.closed = True
                finalize_descriptor_cleanup(
                    [
                        *(
                            [("staged_backup", binding.fd)]
                            if "binding" in locals()
                            else []
                        ),
                        ("private_stage", self.stage_fd),
                        ("rules_parent", self.rules_parent_fd),
                    ],
                    primary_error=error,
                )
                raise
            binding.snapshot = actual
            self.files[recovery_candidate] = binding

    def _rules_parent_path_is_bound(self) -> bool:
        try:
            descriptor_actual = os.fstat(self.rules_parent_fd)
            path_actual = os.stat(self.rules_parent, follow_symlinks=False)
        except OSError:
            return False
        return (
            stat.S_ISDIR(descriptor_actual.st_mode)
            and stat.S_ISDIR(path_actual.st_mode)
            and not directory_property_mismatches(
                self.rules_parent_snapshot,
                descriptor_actual,
            )
            and not directory_property_mismatches(
                self.rules_parent_snapshot,
                path_actual,
            )
        )

    def _validate_rules_parent(self) -> None:
        if not self._rules_parent_path_is_bound():
            raise TransactionError(
                "rules_directory_changed",
                "rules directory descriptor and pathname no longer bind the same "
                "identity and access policy",
            )
        validate_bound_directory(self.rules_parent_binding)

    def _validate_stage_root(self) -> None:
        actual = os.fstat(self.stage_fd)
        mismatches = directory_property_mismatches(self.stage_snapshot, actual)
        try:
            path_actual = os.stat(
                self.stage_name,
                dir_fd=self.rules_parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise TransactionError(
                "private_stage_changed",
                f"staging directory path is unavailable: {error}",
            ) from error
        mismatches.extend(
            item
            for item in directory_property_mismatches(
                self.stage_snapshot,
                path_actual,
            )
            if item not in mismatches
        )
        if mismatches:
            raise TransactionError(
                "private_stage_changed",
                "staging directory identity or access policy changed",
                details={"mismatched_properties": mismatches},
            )
        reject_unmodeled_metadata_fd(
            self.stage_fd,
            label="private_stage",
            require_directory=True,
        )
        try:
            final_actual = os.fstat(self.stage_fd)
            final_path_actual = os.stat(
                self.stage_name,
                dir_fd=self.rules_parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise TransactionError(
                "private_stage_changed",
                f"staging directory changed during metadata admission: {error}",
            ) from error
        final_mismatches = directory_property_mismatches(
            self.stage_snapshot,
            final_actual,
        )
        final_mismatches.extend(
            item
            for item in directory_property_mismatches(
                self.stage_snapshot,
                final_path_actual,
            )
            if item not in final_mismatches
        )
        if final_mismatches:
            raise TransactionError(
                "private_stage_changed",
                "staging directory changed during metadata admission",
                details={"mismatched_properties": final_mismatches},
            )
        reject_unmodeled_metadata_fd(
            self.stage_fd,
            label="private_stage",
            require_directory=True,
        )

    def _binding(self, path: Path) -> BoundFile:
        try:
            return self.files[path]
        except KeyError as error:
            raise TransactionError(
                "private_candidate_unbound",
                f"staged path is not bound to this transaction: {path}",
            ) from error

    def create(self, name: str, payload: bytes) -> tuple[Path, Snapshot]:
        if Path(name).name != name:
            raise TransactionError(
                "path_invalid",
                "staged file name must be one basename",
            )
        self._validate_rules_parent()
        self._validate_stage_root()
        path = self.path / name
        fd, snapshot = _write_exclusive_bound(
            path,
            payload,
            directory_fd=self.stage_fd,
            name=name,
        )
        binding = BoundFile(path=path, name=name, fd=fd, snapshot=snapshot)
        self.files[path] = binding
        file_stat = os.fstat(fd)
        if (
            file_stat.st_nlink != 1
            or snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
        ):
            raise TransactionError(
                "private_candidate_invalid",
                "staged file is not an owner-only, single-link regular file",
            )
        return path, snapshot

    def update_snapshot(self, path: Path, snapshot: Snapshot) -> None:
        self._binding(path).snapshot = snapshot

    def validate(self, path: Path, expected: Snapshot, *, label: str) -> Snapshot:
        self._validate_rules_parent()
        self._validate_stage_root()
        binding = self._binding(path)
        _payload, actual = read_bound_fd(binding.fd, label=label)
        reject_unmodeled_metadata_fd(binding.fd, label=label)
        mismatches = property_mismatches(expected, actual)
        if mismatches:
            raise TransactionError(
                f"{label}_changed",
                f"{label} changed after staging",
                details={"mismatched_properties": mismatches},
            )
        verify_entry_binding(
            self.stage_fd,
            binding.name,
            expected,
            label=label,
        )
        reject_unmodeled_metadata_fd(binding.fd, label=label)
        return actual

    def set_policy(
        self,
        path: Path,
        expected: Snapshot,
        policy: Snapshot,
    ) -> Snapshot:
        binding = self._binding(path)
        self.validate(path, expected, label="private_candidate")
        if policy.uid != os.geteuid():
            raise TransactionError(
                "unsupported_rules_owner",
                "live rules are not owned by the current user",
            )
        os.fchown(binding.fd, policy.uid, policy.gid)
        os.fchmod(binding.fd, policy.mode)
        os.fsync(binding.fd)
        _payload, actual = read_bound_fd(binding.fd, label="private_candidate")
        reject_unmodeled_metadata_fd(
            binding.fd,
            label="private_candidate",
        )
        protected_mismatches: list[str] = []
        if (actual.device, actual.inode) != (expected.device, expected.inode):
            protected_mismatches.append("object_identity")
        if actual.size != expected.size or not hmac.compare_digest(
            actual.sha256,
            expected.sha256,
        ):
            protected_mismatches.append("content")
        if actual.nlink != expected.nlink:
            protected_mismatches.append("object_policy")
        if protected_mismatches:
            raise TransactionError(
                "private_candidate_changed",
                "staged identity, content, or object policy changed while applying "
                "access policy",
                details={"mismatched_properties": protected_mismatches},
            )
        verify_entry_binding(
            self.stage_fd,
            binding.name,
            actual,
            label="private_candidate",
        )
        reject_unmodeled_metadata_fd(
            binding.fd,
            label="private_candidate",
        )
        binding.snapshot = actual
        return actual

    def _bind_target(self, target: Path, expected: Snapshot) -> BoundFile:
        if target.parent != self.rules_parent or Path(target.name).name != target.name:
            raise TransactionError(
                "path_invalid",
                "exchange target must be one rules-directory child",
            )
        try:
            fd = open_untrusted_regular_file(
                target.name,
                label="live_rules",
                dir_fd=self.rules_parent_fd,
            )
        except OSError as error:
            raise TransactionError(
                "live_rules_unreadable",
                f"cannot bind exchange target: {error}",
            ) from error
        try:
            _payload, actual = read_bound_fd(fd, label="live_rules")
            reject_unmodeled_metadata_fd(fd, label="live_rules")
            mismatches = property_mismatches(expected, actual)
            if mismatches:
                raise TransactionError(
                    "live_changed_before_replace",
                    "exchange target changed before it was bound",
                    exit_code=EXIT_LIVE_CONFLICT,
                    details={"mismatched_properties": mismatches},
                )
            verify_entry_binding(
                self.rules_parent_fd,
                target.name,
                expected,
                label="live_rules",
            )
            reject_unmodeled_metadata_fd(fd, label="live_rules")
        except BaseException as error:
            finalize_descriptor_cleanup(
                [("live_rules", fd)],
                primary_error=error,
            )
            raise
        self.known_parent_names.add(target.name)
        return BoundFile(
            path=target,
            name=target.name,
            fd=fd,
            snapshot=actual,
        )

    def _preserve_bound_file(
        self,
        binding: BoundFile,
        *,
        role: str,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "role": role,
            "origin_expected": binding.snapshot.to_json(),
            "retention_status": "not_persistently_retained",
        }
        try:
            payload, origin_before = read_bound_fd(
                binding.fd,
                label=f"{role}_bound_object",
            )
            reject_unmodeled_metadata_fd(
                binding.fd,
                label=f"{role}_bound_object",
            )
            result["origin_actual"] = origin_before.to_json()
            result["origin_mismatched_properties"] = property_mismatches(
                binding.snapshot,
                origin_before,
            )
            recovery_name = f".recovery-{role}-{secrets.token_hex(8)}"
            recovery_path, recovery_snapshot = self.create(recovery_name, payload)
            recovery_snapshot = self.set_policy(
                recovery_path,
                recovery_snapshot,
                origin_before,
            )
            os.fsync(self.stage_fd)
            os.fsync(self.rules_parent_fd)
            locator = self._locator_for_snapshot(recovery_snapshot)
            if locator is None:
                raise TransactionError(
                    "recovery_copy_unlocatable",
                    f"{role} recovery copy has no verified locator",
                )
            origin_payload, origin_after = read_bound_fd(
                binding.fd,
                label=f"{role}_bound_object",
            )
            reject_unmodeled_metadata_fd(
                binding.fd,
                label=f"{role}_bound_object",
            )
            recovery_binding = self._binding(recovery_path)
            recovery_payload, recovery_actual = read_bound_fd(
                recovery_binding.fd,
                label=f"{role}_recovery_copy",
            )
            reject_unmodeled_metadata_fd(
                recovery_binding.fd,
                label=f"{role}_recovery_copy",
            )
            origin_mismatches = property_mismatches(origin_before, origin_after)
            recovery_mismatches = property_mismatches(
                recovery_snapshot,
                recovery_actual,
            )
            if origin_payload != payload and "content" not in origin_mismatches:
                origin_mismatches.append("content")
            if recovery_payload != payload and "content" not in recovery_mismatches:
                recovery_mismatches.append("content")
            if origin_mismatches or recovery_mismatches:
                raise TransactionError(
                    "recovery_copy_changed",
                    f"{role} or its recovery copy changed during locator binding",
                    details={
                        "origin_mismatched_properties": origin_mismatches,
                        "recovery_mismatched_properties": recovery_mismatches,
                    },
                )
            self._validate_rules_parent()
            self._validate_stage_root()
            verify_entry_binding(
                self.stage_fd,
                recovery_binding.name,
                recovery_actual,
                label=f"{role}_recovery_copy",
            )
            reject_unmodeled_metadata_fd(
                recovery_binding.fd,
                label=f"{role}_recovery_copy",
            )
            final_locator = self._locator_for_snapshot(recovery_actual)
            if final_locator is None or final_locator != locator:
                raise TransactionError(
                    "recovery_copy_unlocatable",
                    f"{role} recovery locator changed during final binding",
                )
            result.update(
                {
                    "recovery_copy": recovery_actual.to_json(),
                    "recovery_locator": str(final_locator),
                    "retention_status": "verified_recovery_copy",
                }
            )
        except (OSError, TransactionError) as error:
            result["retention_error"] = {
                "status": (
                    error.status
                    if isinstance(error, TransactionError)
                    else "recovery_copy_failed"
                ),
                "message": str(error),
            }
            if isinstance(error, TransactionError) and error.details:
                result["retention_error"]["details"] = error.details
        return result

    def _uncertain_mutation(
        self,
        *,
        operation: str,
        source: BoundFile,
        destination_binding: BoundFile | None,
        destination: Path,
        source_observation: dict[str, object],
        destination_observation: dict[str, object],
        destination_expected: Snapshot | None = None,
        error: OSError | None = None,
    ) -> TransactionError:
        self.mutation_uncertain = True
        source_locator = self._locator_for_snapshot(source.snapshot)
        source_retention = self._preserve_bound_file(source, role="source")
        retention: dict[str, object] = {"source": source_retention}
        required_retention = [source_retention]
        if destination_binding is not None:
            destination_retention = self._preserve_bound_file(
                destination_binding,
                role="destination",
            )
            retention["destination"] = destination_retention
            required_retention.append(destination_retention)
        retention_complete = all(
            item.get("retention_status") == "verified_recovery_copy"
            for item in required_retention
        )
        details: dict[str, object] = {
            "mutation_status": f"atomic_{operation}_uncertain",
            "source_last_known_path": str(source.path),
            "destination_path": str(destination),
            "source_expected": source.snapshot.to_json(),
            "source_recovery_locator": (
                str(source_locator) if source_locator is not None else None
            ),
            "source_observation": source_observation,
            "destination_observation": destination_observation,
            "retention": retention,
            "retention_status": (
                "bound_objects_copied" if retention_complete else "retention_incomplete"
            ),
            "cleanup_policy": (
                "retain_verified_recovery_copies"
                if retention_complete
                else "retention_incomplete_no_false_claim"
            ),
        }
        if destination_expected is not None:
            destination_locator = self._locator_for_snapshot(destination_expected)
            details["destination_expected"] = destination_expected.to_json()
            details["destination_recovery_locator"] = (
                str(destination_locator) if destination_locator is not None else None
            )
        if error is not None:
            details["atomic_error"] = {
                "errno": error.errno,
                "message": str(error),
            }
        return TransactionError(
            "recovery_required",
            (
                f"cannot prove the outcome of atomic {operation}; bound objects "
                "were copied to verified recovery files"
                if retention_complete
                else (
                    f"cannot prove the outcome of atomic {operation}; at least one "
                    "bound object could not be persistently retained"
                )
            ),
            exit_code=EXIT_POST_REPLACE_FAILED,
            details=details,
        )

    def move_to(
        self,
        path: Path,
        target: Path,
        target_expected: Snapshot,
        *,
        pre_exchange_revalidate: Callable[[], None] | None = None,
    ) -> Snapshot:
        source = self._binding(path)
        expected = source.snapshot
        self.validate(path, expected, label="private_candidate")
        self._validate_rules_parent()
        target_binding = self._bind_target(target, target_expected)
        self.extra_fds.append(target_binding.fd)
        self.validate(path, expected, label="private_candidate")
        reject_unmodeled_metadata_fd(
            target_binding.fd,
            label="live_rules",
        )
        self.validate(path, expected, label="private_candidate")
        reject_unmodeled_metadata_fd(
            target_binding.fd,
            label="live_rules",
        )
        verify_entry_binding(
            self.rules_parent_fd,
            target_binding.name,
            target_expected,
            label="live_rules",
        )
        self._validate_rules_parent()
        if pre_exchange_revalidate is not None:
            pre_exchange_revalidate()
        atomic_error: OSError | None = None
        self.mutation_uncertain = True
        try:
            atomic_rename_exchange(
                self.stage_fd,
                source.name,
                self.rules_parent_fd,
                target.name,
            )
        except TransactionError:
            self.mutation_uncertain = False
            raise
        except OSError as error:
            atomic_error = error

        source_observation = observe_directory_entry(
            self.stage_fd,
            source.name,
            expected=target_expected,
        )
        destination_observation = observe_directory_entry(
            self.rules_parent_fd,
            target.name,
            expected=expected,
        )
        if atomic_error is not None:
            initial_source = observe_directory_entry(
                self.stage_fd,
                source.name,
                expected=expected,
            )
            initial_destination = observe_directory_entry(
                self.rules_parent_fd,
                target.name,
                expected=target_expected,
            )
            if observation_matches(initial_source) and observation_matches(
                initial_destination
            ):
                self.mutation_uncertain = False
                self.extra_fds.remove(target_binding.fd)
                transaction_error = TransactionError(
                    "atomic_exchange_failed",
                    f"atomic exchange failed without changing either side: {atomic_error}",
                    details={
                        "source_observation": initial_source,
                        "destination_observation": initial_destination,
                    },
                )
                finalize_descriptor_cleanup(
                    [("live_rules", target_binding.fd)],
                    primary_error=transaction_error,
                )
                raise transaction_error from atomic_error
            raise self._uncertain_mutation(
                operation="exchange",
                source=source,
                destination_binding=target_binding,
                destination=target,
                source_observation=source_observation,
                destination_observation=destination_observation,
                destination_expected=target_expected,
                error=atomic_error,
            ) from atomic_error

        try:
            _source_payload, source_actual = read_bound_fd(
                source.fd,
                label="private_candidate",
            )
            _target_payload, target_actual = read_bound_fd(
                target_binding.fd,
                label="displaced_live_rules",
            )
            reject_unmodeled_metadata_fd(
                source.fd,
                label="installed_rules",
            )
            reject_unmodeled_metadata_fd(
                target_binding.fd,
                label="displaced_live_rules",
            )
        except TransactionError as error:
            raise self._uncertain_mutation(
                operation="exchange",
                source=source,
                destination_binding=target_binding,
                destination=target,
                source_observation=source_observation,
                destination_observation=destination_observation,
                destination_expected=target_expected,
            ) from error
        if (
            property_mismatches(expected, source_actual)
            or property_mismatches(target_expected, target_actual)
            or not observation_matches(source_observation)
            or not observation_matches(destination_observation)
        ):
            raise self._uncertain_mutation(
                operation="exchange",
                source=source,
                destination_binding=target_binding,
                destination=target,
                source_observation=source_observation,
                destination_observation=destination_observation,
                destination_expected=target_expected,
            )

        displaced_source_fd = source.fd
        self.extra_fds.append(displaced_source_fd)
        self.files[path] = BoundFile(
            path=source.path,
            name=source.name,
            fd=target_binding.fd,
            snapshot=target_actual,
        )
        self.extra_fds.remove(target_binding.fd)
        self.mutation_uncertain = False
        return expected

    def publish_backup(self, path: Path, backup: Path) -> BoundFile:
        source = self._binding(path)
        expected = source.snapshot
        if backup.parent != self.rules_parent or Path(backup.name).name != backup.name:
            raise TransactionError(
                "path_invalid",
                "backup must be one rules-directory child",
            )
        self.validate(path, expected, label="private_backup")
        self._validate_rules_parent()
        destination_before = observe_directory_entry(
            self.rules_parent_fd,
            backup.name,
        )
        if destination_before.get("state") != "missing":
            raise TransactionError(
                "backup_exists",
                f"backup already exists: {backup}",
                details={"backup_observation": destination_before},
            )
        self.validate(path, expected, label="private_backup")
        atomic_error: OSError | None = None
        self.mutation_uncertain = True
        try:
            atomic_rename_no_replace(
                self.stage_fd,
                source.name,
                self.rules_parent_fd,
                backup.name,
            )
        except TransactionError:
            self.mutation_uncertain = False
            raise
        except OSError as error:
            atomic_error = error
        source_observation = observe_directory_entry(
            self.stage_fd,
            source.name,
            expected=expected,
        )
        destination_observation = observe_directory_entry(
            self.rules_parent_fd,
            backup.name,
            expected=expected,
        )
        if atomic_error is not None:
            if atomic_error.errno == errno.EEXIST and observation_matches(
                source_observation
            ):
                self.mutation_uncertain = False
                raise TransactionError(
                    "backup_exists",
                    f"backup already exists: {backup}",
                    details={"backup_observation": destination_observation},
                ) from atomic_error
            if (
                observation_matches(source_observation)
                and destination_observation.get("state") == "missing"
            ):
                self.mutation_uncertain = False
                raise TransactionError(
                    "atomic_no_replace_failed",
                    f"atomic backup publication failed without moving the source: {atomic_error}",
                    details={
                        "source_observation": source_observation,
                        "destination_observation": destination_observation,
                    },
                ) from atomic_error
            raise self._uncertain_mutation(
                operation="no_replace",
                source=source,
                destination_binding=None,
                destination=backup,
                source_observation=source_observation,
                destination_observation=destination_observation,
                error=atomic_error,
            ) from atomic_error
        try:
            _payload, actual = read_bound_fd(source.fd, label="backup")
            reject_unmodeled_metadata_fd(source.fd, label="backup")
        except TransactionError as error:
            raise self._uncertain_mutation(
                operation="no_replace",
                source=source,
                destination_binding=None,
                destination=backup,
                source_observation=source_observation,
                destination_observation=destination_observation,
            ) from error
        if (
            source_observation.get("state") != "missing"
            or not observation_matches(destination_observation)
            or property_mismatches(expected, actual)
        ):
            raise self._uncertain_mutation(
                operation="no_replace",
                source=source,
                destination_binding=None,
                destination=backup,
                source_observation=source_observation,
                destination_observation=destination_observation,
            )
        self.extra_fds.append(source.fd)
        self.files.pop(path, None)
        source.path = backup
        source.name = backup.name
        source.snapshot = actual
        self.known_parent_names.add(backup.name)
        self.mutation_uncertain = False
        return source

    def _find_bound_entry(
        self,
        directory_fd: int,
        expected: Snapshot,
    ) -> str | None:
        try:
            entries = os.scandir(directory_fd)
        except OSError:
            return None
        inspected = 0
        with entries:
            for item in entries:
                inspected += 1
                if inspected > MAX_STAGE_DIRECTORY_ENTRIES:
                    return None
                try:
                    entry = os.stat(
                        item.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except OSError:
                    continue
                if (entry.st_dev, entry.st_ino) == (
                    expected.device,
                    expected.inode,
                ):
                    return item.name
        return None

    @staticmethod
    def _entry_identity_matches(
        directory_fd: int,
        name: str,
        expected: Snapshot,
    ) -> bool:
        try:
            actual = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError:
            return False
        return (actual.st_dev, actual.st_ino) == (
            expected.device,
            expected.inode,
        )

    def _locator_for_snapshot(self, expected: Snapshot) -> Path | None:
        if not self._rules_parent_path_is_bound():
            return None
        root_name = (
            self.stage_name
            if self._entry_identity_matches(
                self.rules_parent_fd,
                self.stage_name,
                self.stage_snapshot,
            )
            else self._find_bound_entry(
                self.rules_parent_fd,
                self.stage_snapshot,
            )
        )
        stage_name: str | None = None
        for binding in self.files.values():
            if (binding.snapshot.device, binding.snapshot.inode) == (
                expected.device,
                expected.inode,
            ) and self._entry_identity_matches(
                self.stage_fd,
                binding.name,
                expected,
            ):
                stage_name = binding.name
                break
        if stage_name is None:
            stage_name = self._find_bound_entry(self.stage_fd, expected)
        if root_name is not None and stage_name is not None:
            locator = self.rules_parent / root_name / stage_name
            if (
                self._entry_identity_matches(
                    self.rules_parent_fd,
                    root_name,
                    self.stage_snapshot,
                )
                and self._entry_identity_matches(
                    self.stage_fd,
                    stage_name,
                    expected,
                )
                and self._rules_parent_path_is_bound()
            ):
                return locator
            return None
        parent_name: str | None = None
        for known_name in sorted(self.known_parent_names):
            if self._entry_identity_matches(
                self.rules_parent_fd,
                known_name,
                expected,
            ):
                parent_name = known_name
                break
        if parent_name is None:
            parent_name = self._find_bound_entry(
                self.rules_parent_fd,
                expected,
            )
        if parent_name is not None:
            locator = self.rules_parent / parent_name
            if (
                self._entry_identity_matches(
                    self.rules_parent_fd,
                    parent_name,
                    expected,
                )
                and self._rules_parent_path_is_bound()
            ):
                return locator
        return None

    def _close_bindings(self) -> list[dict[str, object]]:
        descriptors = [
            *(
                (f"stage_file:{binding.name}", binding.fd)
                for binding in self.files.values()
            ),
            *((f"stage_extra:{index}", fd) for index, fd in enumerate(self.extra_fds)),
        ]
        try:
            return close_descriptors_best_effort(descriptors)
        finally:
            self.files.clear()
            self.extra_fds.clear()

    def _close_all_descriptors(self) -> list[dict[str, object]]:
        failures = self._close_bindings()
        self.closed = True
        failures.extend(
            close_descriptors_best_effort(
                [
                    ("private_stage", self.stage_fd),
                    ("rules_parent", self.rules_parent_fd),
                ]
            )
        )
        return failures

    def _cleanup_fixed_stage(self) -> list[dict[str, object]]:
        """Close an empty persistent stage without pathname deletion.

        The fixed owner-private stage is infrastructure shared by serialized
        transactions.  A successful apply moves its only child to the formal
        backup path, so cleanup merely proves that the bound root is unchanged
        and empty.  Any remaining or replacement entry is recovery/uncertain
        evidence and is retained without unlink, rmdir, or inode reuse.
        """

        warnings: list[dict[str, object]] = []
        primary_error: BaseException | None = None
        try:
            self._validate_rules_parent()
            self._validate_stage_root()
            entries, entries_exceeded = bounded_directory_entries(self.stage_fd)
            if entries_exceeded:
                raise TransactionError(
                    "stage_cleanup_refused",
                    "private staging evidence exceeds the cleanup inspection bound",
                    details={"entry_count_lower_bound": len(entries)},
                )
            if entries:
                raise TransactionError(
                    "stage_cleanup_refused",
                    "private stage still contains retained recovery or uncertain "
                    "objects",
                    details={
                        "retained_entries": sorted(entries),
                        "stage_path": str(self.path),
                    },
                )
            self._validate_stage_root()
            self._validate_rules_parent()
        except (OSError, TransactionError) as error:
            locator = self._locator_for_snapshot(self.stage_snapshot)
            warnings.append(
                {
                    "status": "stage_cleanup_refused",
                    "reason": (
                        error.status
                        if isinstance(error, TransactionError)
                        else "stage_cleanup_failed"
                    ),
                    "message": str(error),
                    "last_known_path": str(self.path),
                    "recovery_locator": (str(locator) if locator is not None else None),
                    "cleanup_policy": "persistent_stage_retain_without_path_delete",
                }
            )
            if isinstance(error, TransactionError) and error.details:
                warnings[-1]["details"] = error.details
        except BaseException as error:
            primary_error = error
            raise
        finally:
            failures = self._close_all_descriptors()
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            elif failures:
                warnings.append(
                    {
                        "status": "descriptor_cleanup_failed",
                        "cleanup_failures": failures,
                    }
                )
        return warnings

    def cleanup(self, *, retain: bool = True) -> list[dict[str, object]]:
        if self.closed:
            return []
        if not retain:
            return self._cleanup_fixed_stage()
        warnings: list[dict[str, object]] = []
        inspected_fds: set[int] = set()
        primary_error: BaseException | None = None
        try:
            root_locator = self._locator_for_snapshot(self.stage_snapshot)
            for binding in self.files.values():
                inspected_fds.add(binding.fd)
                try:
                    locator = self._locator_for_snapshot(binding.snapshot)
                    current_stat = os.fstat(binding.fd)
                    persistently_retained = (
                        locator is not None and current_stat.st_nlink > 0
                    )
                    current_observation = observe_directory_entry(
                        self.stage_fd,
                        binding.name,
                        expected=binding.snapshot,
                    )
                except OSError as error:
                    warnings.append(
                        {
                            "status": "unretained_bound_file",
                            "retention_status": "inspection_failed",
                            "last_known_path": str(binding.path),
                            "message": str(error),
                        }
                    )
                    continue
                warnings.append(
                    {
                        "status": (
                            "retained_staged_file"
                            if persistently_retained
                            else "unretained_bound_file"
                        ),
                        "retention_status": (
                            "verified_namespace_link"
                            if persistently_retained
                            else "descriptor_only_or_unlocatable"
                        ),
                        "bound_object": binding.snapshot.to_json(),
                        "current_nlink": current_stat.st_nlink,
                        "recovery_locator": (
                            str(locator) if locator is not None else None
                        ),
                        "last_known_path": str(binding.path),
                        "last_known_path_observation": current_observation,
                    }
                )
            for fd in self.extra_fds:
                if fd in inspected_fds:
                    continue
                inspected_fds.add(fd)
                try:
                    file_stat = os.fstat(fd)
                    locator = self._locator_for_snapshot(
                        Snapshot.from_stat(file_stat, b""),
                    )
                    persistently_retained = (
                        locator is not None and file_stat.st_nlink > 0
                    )
                except OSError as error:
                    warnings.append(
                        {
                            "status": "unretained_bound_file",
                            "retention_status": "inspection_failed",
                            "message": str(error),
                        }
                    )
                    continue
                warnings.append(
                    {
                        "status": (
                            "retained_bound_file"
                            if persistently_retained
                            else "unretained_bound_file"
                        ),
                        "retention_status": (
                            "verified_namespace_link"
                            if persistently_retained
                            else "descriptor_only_or_unlocatable"
                        ),
                        "bound_identity": stat_identity(file_stat),
                        "current_nlink": file_stat.st_nlink,
                        "recovery_locator": (
                            str(locator) if locator is not None else None
                        ),
                    }
                )
            warnings.append(
                {
                    "status": (
                        "retained_staging_directory"
                        if root_locator is not None
                        else "unretained_staging_directory"
                    ),
                    "retention_status": (
                        "verified_namespace_link"
                        if root_locator is not None
                        else "descriptor_only_or_unlocatable"
                    ),
                    "bound_identity": {
                        "device": self.stage_snapshot.device,
                        "inode": self.stage_snapshot.inode,
                    },
                    "recovery_locator": (
                        str(root_locator) if root_locator is not None else None
                    ),
                    "last_known_path": str(self.path),
                    "cleanup_policy": "retained_no_compare_then_delete",
                }
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            failures = self._close_all_descriptors()
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            elif failures:
                warnings.append(
                    {
                        "status": "descriptor_cleanup_failed",
                        "cleanup_failures": failures,
                    }
                )
        return warnings


def validate_existing_fixed_stage_is_empty(
    rules_parent: Path,
    *,
    rules_parent_expected: Snapshot | None = None,
) -> None:
    rules_parent_binding = bind_directory(
        rules_parent,
        label="rules",
        expected=rules_parent_expected,
    )
    try:
        stage_stat = os.stat(
            PRIVATE_STAGE_NAME,
            dir_fd=rules_parent_binding.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        primary_error: BaseException | None = None
        try:
            validate_bound_directory(rules_parent_binding)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            finalize_descriptor_cleanup(
                [("rules_parent", rules_parent_binding.fd)],
                primary_error=primary_error,
            )
        return
    except OSError as error:
        transaction_error = TransactionError(
            "recovery_required",
            f"cannot inspect existing fixed transaction stage: {error}",
            exit_code=EXIT_POST_REPLACE_FAILED,
            details={"stage_status": "private_stage_unreadable"},
        )
        finalize_descriptor_cleanup(
            [("rules_parent", rules_parent_binding.fd)],
            primary_error=transaction_error,
        )
        raise transaction_error from error

    stage: PrivateStage | None = None
    primary_error = None
    try:
        stage = PrivateStage(
            rules_parent,
            rules_parent_expected=rules_parent_binding.snapshot,
            recovery_stage_expected=Snapshot.from_stat(stage_stat, b""),
        )
    except (OSError, TransactionError) as error:
        error_status = (
            error.status
            if isinstance(error, TransactionError)
            else "private_stage_unreadable"
        )
        error_details = error.details if isinstance(error, TransactionError) else {}
        transaction_error = TransactionError(
            "recovery_required",
            "existing fixed transaction stage requires recovery before no-change",
            exit_code=EXIT_POST_REPLACE_FAILED,
            details={
                "stage_status": error_status,
                "stage_message": str(error),
                **error_details,
            },
        )
        primary_error = transaction_error
        raise transaction_error from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [("rules_parent", rules_parent_binding.fd)],
            primary_error=primary_error,
        )
    assert stage is not None
    warnings = stage.cleanup(retain=False)
    if warnings:
        descriptor_failures = private_stage_descriptor_cleanup_failures(warnings)
        raise TransactionError(
            "recovery_required",
            "existing fixed transaction stage cleanup could not be verified",
            exit_code=EXIT_POST_REPLACE_FAILED,
            details={
                "cleanup_refusals": warnings,
                **(
                    {
                        "cleanup_reason": (PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON),
                        "cleanup_failures": descriptor_failures,
                    }
                    if descriptor_failures
                    else {}
                ),
            },
        )


def lock_snapshot(path: Path, file_stat: os.stat_result) -> Snapshot:
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_nlink != 1
        or file_stat.st_uid != os.geteuid()
        or stat.S_IMODE(file_stat.st_mode) != 0o600
    ):
        raise TransactionError(
            "lock_invalid",
            "transaction lock is not an owner-only, single-link regular file",
        )
    path_stat = os.stat(path, follow_symlinks=False)
    if (path_stat.st_dev, path_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino):
        raise TransactionError(
            "lock_identity_changed",
            "transaction lock path was replaced",
        )
    return Snapshot.from_stat(path_stat, b"")


def lock_property_mismatches(
    expected: Snapshot,
    actual: os.stat_result,
) -> list[str]:
    mismatches: list[str] = []
    if not stat.S_ISREG(actual.st_mode):
        mismatches.append("file_type")
    if (expected.device, expected.inode) != (actual.st_dev, actual.st_ino):
        mismatches.append("object_identity")
    if (expected.mode, expected.uid, expected.gid) != (
        stat.S_IMODE(actual.st_mode),
        actual.st_uid,
        actual.st_gid,
    ):
        mismatches.append("access_policy")
    if expected.nlink != actual.st_nlink:
        mismatches.append("object_policy")
    return mismatches


@contextmanager
def shared_lock(
    path: Path,
    *,
    timeout_seconds: float,
    before_release: Callable[[], None] | None = None,
):
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise TransactionError(
            "arguments_invalid",
            "lock timeout must be finite and positive",
        )
    flags = (
        os.O_RDWR
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = -1
    locked = False
    binding: BoundFile | None = None
    primary_error: BaseException | None = None
    primary_traceback: object | None = None
    try:
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            fd = open_untrusted_regular_file(
                path,
                label="transaction_lock",
                writable=True,
            )
        opened_lock = os.fstat(fd)
        if not stat.S_ISREG(opened_lock.st_mode):
            raise TransactionError(
                "lock_invalid",
                "transaction lock is not a regular file",
            )
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TransactionError(
                        "lock_busy",
                        "transaction lock remained busy",
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        binding = BoundFile(
            path=path,
            name=path.name,
            fd=fd,
            snapshot=lock_snapshot(path, os.fstat(fd)),
        )
        revalidate_lock(binding)
        yield binding
    except BaseException as error:
        primary_error = error
        primary_traceback = error.__traceback__
    finally:
        finalization_errors: list[tuple[str, BaseException]] = []
        if locked and binding is not None:
            finalizers: list[tuple[str, Callable[[], None]]] = [
                ("pre-release-revalidation", lambda: revalidate_lock(binding)),
            ]
            if before_release is not None:
                finalizers.append(("before-release", before_release))
            finalizers.append(
                ("final-release-revalidation", lambda: revalidate_lock(binding))
            )
            for label, finalizer in finalizers:
                try:
                    finalizer()
                except BaseException as error:
                    finalization_errors.append((label, error))

        if primary_error is None and finalization_errors:
            _label, primary_error = finalization_errors.pop(0)
            primary_traceback = primary_error.__traceback__
        if primary_error is not None and finalization_errors:
            attach_failures_to_exception(
                primary_error,
                "lock_finalization_failures",
                [
                    structured_operation_failure(
                        "lock-finalization",
                        label,
                        error,
                    )
                    for label, error in finalization_errors
                ],
            )

        close_failures = (
            close_descriptors_best_effort(
                [("transaction_lock", fd)],
                release_uncertain=True,
            )
            if fd >= 0
            else []
        )
        if close_failures:
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    close_failures,
                )
            else:
                primary_error = descriptor_cleanup_error(
                    close_failures,
                    status="lock_close_failed",
                    message=(
                        "transaction lock descriptor close failed; lock release "
                        "cannot be proven"
                    ),
                )
                primary_traceback = primary_error.__traceback__

        if primary_error is not None:
            raise primary_error.with_traceback(primary_traceback)


def revalidate_lock(
    binding: BoundFile,
    parent: BoundDirectory | None = None,
) -> None:
    if parent is not None:
        validate_bound_directory(parent)
    try:
        descriptor_stat = os.fstat(binding.fd)
        path_stat = (
            os.stat(
                binding.name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            if parent is not None
            else os.stat(binding.path, follow_symlinks=False)
        )
    except FileNotFoundError as error:
        raise TransactionError(
            "lock_missing", "transaction lock disappeared"
        ) from error
    except OSError as error:
        raise TransactionError(
            "lock_unreadable",
            f"transaction lock binding is unreadable: {error}",
        ) from error
    mismatches = lock_property_mismatches(binding.snapshot, descriptor_stat)
    mismatches.extend(
        mismatch
        for mismatch in lock_property_mismatches(
            binding.snapshot,
            path_stat,
        )
        if mismatch not in mismatches
    )
    if mismatches:
        raise TransactionError(
            "lock_changed",
            "transaction lock changed",
            details={"mismatched_properties": mismatches},
        )
    reject_unmodeled_metadata_fd(binding.fd, label="lock")
    try:
        descriptor_final = os.fstat(binding.fd)
        path_final = (
            os.stat(
                binding.name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            if parent is not None
            else os.stat(binding.path, follow_symlinks=False)
        )
    except OSError as error:
        raise TransactionError(
            "lock_unreadable",
            f"transaction lock changed during metadata admission: {error}",
        ) from error
    final_mismatches = lock_property_mismatches(
        binding.snapshot,
        descriptor_final,
    )
    final_mismatches.extend(
        mismatch
        for mismatch in lock_property_mismatches(
            binding.snapshot,
            path_final,
        )
        if mismatch not in final_mismatches
    )
    if final_mismatches:
        raise TransactionError(
            "lock_changed",
            "transaction lock changed during metadata admission",
            details={"mismatched_properties": final_mismatches},
        )
    reject_unmodeled_metadata_fd(binding.fd, label="lock")
    if parent is not None:
        validate_bound_directory(parent)


class _DarwinProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _darwin_live_process_group_members(
    process_group_id: int,
    *,
    leader_pid: int,
) -> tuple[int, ...]:
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        proc_listpids = libproc.proc_listpids
        proc_pidinfo = libproc.proc_pidinfo
    except (OSError, AttributeError) as error:
        raise TransactionError(
            "validator_cleanup_failed",
            "Darwin process-group membership APIs are unavailable",
        ) from error
    proc_listpids.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    proc_listpids.restype = ctypes.c_int
    proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    proc_pidinfo.restype = ctypes.c_int

    pid_capacity = 64
    while True:
        pid_buffer = (ctypes.c_int * pid_capacity)()
        ctypes.set_errno(0)
        received = proc_listpids(
            2,  # PROC_PGRP_ONLY
            process_group_id,
            pid_buffer,
            ctypes.sizeof(pid_buffer),
        )
        if received < 0:
            error_number = ctypes.get_errno() or errno.EIO
            raise TransactionError(
                "validator_cleanup_failed",
                "cannot enumerate the validator process group",
                details={"errno": error_number},
            )
        if received < ctypes.sizeof(pid_buffer):
            break
        if pid_capacity >= 16_384:
            raise TransactionError(
                "validator_cleanup_failed",
                "validator process group exceeds the inspection bound",
            )
        pid_capacity *= 2

    live: list[int] = []
    pid_count = received // ctypes.sizeof(ctypes.c_int)
    for pid in pid_buffer[:pid_count]:
        if pid <= 0 or pid == leader_pid:
            continue
        info = _DarwinProcBsdInfo()
        ctypes.set_errno(0)
        info_bytes = proc_pidinfo(
            pid,
            3,  # PROC_PIDTBSDINFO
            0,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if info_bytes == 0 and ctypes.get_errno() in (0, errno.ESRCH):
            continue
        if info_bytes != ctypes.sizeof(info):
            error_number = ctypes.get_errno() or errno.EIO
            raise TransactionError(
                "validator_cleanup_failed",
                f"cannot inspect validator process-group member {pid}",
                details={"errno": error_number},
            )
        if info.pbi_pgid == process_group_id and info.pbi_status != 5:
            live.append(pid)
    return tuple(sorted(live))


def _linux_live_process_group_members(
    process_group_id: int,
    *,
    leader_pid: int,
) -> tuple[int, ...]:
    live: list[int] = []
    inspected = 0
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise TransactionError(
            "validator_cleanup_failed",
            f"cannot enumerate Linux processes: {error}",
        ) from error
    with entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            inspected += 1
            if inspected > 131_072:
                raise TransactionError(
                    "validator_cleanup_failed",
                    "Linux process inventory exceeds the inspection bound",
                )
            pid = int(entry.name)
            if pid == leader_pid:
                continue
            try:
                with open(
                    f"/proc/{entry.name}/stat",
                    "rb",
                    buffering=0,
                ) as handle:
                    raw = handle.read(4097)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except OSError as error:
                raise TransactionError(
                    "validator_cleanup_failed",
                    f"cannot inspect validator process-group candidate {pid}: {error}",
                ) from error
            if len(raw) > 4096:
                raise TransactionError(
                    "validator_cleanup_failed",
                    f"validator process metadata for {pid} exceeds the bound",
                )
            close_paren = raw.rfind(b")")
            fields = raw[close_paren + 2 :].split() if close_paren >= 0 else []
            if len(fields) < 3:
                raise TransactionError(
                    "validator_cleanup_failed",
                    f"validator process metadata for {pid} is malformed",
                )
            try:
                member_group = int(fields[2])
            except ValueError as error:
                raise TransactionError(
                    "validator_cleanup_failed",
                    f"validator process group for {pid} is malformed",
                ) from error
            if member_group == process_group_id and fields[0] != b"Z":
                live.append(pid)
    return tuple(sorted(live))


def _live_validator_group_member_pids(
    process_group_id: int,
    *,
    leader_pid: int,
) -> tuple[int, ...]:
    if sys.platform == "darwin":
        return _darwin_live_process_group_members(
            process_group_id,
            leader_pid=leader_pid,
        )
    if sys.platform.startswith("linux"):
        return _linux_live_process_group_members(
            process_group_id,
            leader_pid=leader_pid,
        )
    raise TransactionError(
        "validator_cleanup_failed",
        f"process-group membership inspection is unavailable on {sys.platform}",
    )


def _signal_validator_group(
    process_group_id: int,
    signum: int,
    *,
    allow_zombie_only: bool = False,
) -> None:
    try:
        os.killpg(process_group_id, signum)
    except ProcessLookupError:
        return
    except OSError as error:
        if allow_zombie_only and isinstance(error, PermissionError):
            return
        raise TransactionError(
            "validator_cleanup_failed",
            f"cannot signal validator process group {process_group_id}: {error}",
            details={"errno": error.errno},
        ) from error


def _validator_exit_observer_supported() -> bool:
    waitid_supported = all(
        hasattr(os, name)
        for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
    )
    kqueue_supported = all(
        hasattr(select, name)
        for name in (
            "kqueue",
            "kevent",
            "KQ_FILTER_PROC",
            "KQ_EV_ADD",
            "KQ_EV_ONESHOT",
            "KQ_NOTE_EXIT",
        )
    )
    return waitid_supported or kqueue_supported


class _ValidatorExitObserver:
    """Observe child exit without reaping its process-group leader."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.exited = False
        self.kqueue: object | None = None
        if hasattr(os, "waitid"):
            self.strategy = "waitid"
            return

        self.strategy = "kqueue"
        try:
            self.kqueue = select.kqueue()
            event = select.kevent(
                process.pid,
                filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT,
            )
            self.kqueue.control([event], 0, 0)
        except OSError as error:
            self.close()
            raise TransactionError(
                "validator_launch_failed",
                f"cannot bind validator exit observer: {error}",
            ) from error

    def child_exited(self) -> bool:
        if self.exited:
            return True
        if self.strategy == "waitid":
            try:
                result = os.waitid(
                    os.P_PID,
                    self.process.pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError as error:
                raise TransactionError(
                    "validator_cleanup_failed",
                    "validator child was reaped outside its supervisor",
                ) from error
            self.exited = result is not None
            return self.exited

        assert self.kqueue is not None
        try:
            events = self.kqueue.control(None, 1, 0)
        except OSError as error:
            raise TransactionError(
                "validator_cleanup_failed",
                f"cannot observe validator child exit: {error}",
            ) from error
        self.exited = bool(events)
        return self.exited

    def close(self) -> None:
        if self.kqueue is not None:
            self.kqueue.close()
            self.kqueue = None


def _read_validator_events(
    selector: selectors.BaseSelector,
    buffers: dict[str, bytearray],
    *,
    max_output_bytes: int,
    timeout_seconds: float,
    retain: bool,
) -> tuple[bool, bool]:
    overflow = False
    progressed = False
    for key, _events in selector.select(timeout_seconds):
        stream = key.fileobj
        label = str(key.data)
        try:
            chunk = os.read(stream.fileno(), 64 * 1024)
        except BlockingIOError:
            continue
        progressed = True
        if not chunk:
            selector.unregister(stream)
            stream.close()
            continue
        if not retain:
            continue
        retained = sum(len(buffer) for buffer in buffers.values())
        available = max(0, max_output_bytes - retained)
        if len(chunk) > available:
            buffers[label].extend(chunk[:available])
            overflow = True
        else:
            buffers[label].extend(chunk)
    return overflow, progressed


def _emergency_stop_validator_process_group(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector | None,
    buffers: dict[str, bytearray],
    *,
    max_output_bytes: int,
) -> list[dict[str, object]]:
    """Bound cleanup that does not depend on waitid, proc, or libproc.

    This path is used after supervisor setup, observation, signal-handler, or
    process-inventory failures.  The protected properties are process-group
    quiescence and PGID identity: the unreaped ``start_new_session`` leader
    pins its numeric PID/PGID until all group signals finish.  Reaping is the
    terminal action; no numeric PGID operation is permitted afterwards.
    """

    cleanup_errors: list[dict[str, object]] = []

    def record(label: str, error: BaseException) -> None:
        cleanup_errors.append(
            {
                "operation": label,
                "error_type": type(error).__name__,
                "message": compact(str(error)),
            }
        )

    if process.returncode is not None:
        record(
            "process-group-identity-anchor",
            RuntimeError(
                "validator leader was already reaped; refusing numeric PGID cleanup"
            ),
        )
        return cleanup_errors

    def signal_group(signum: int) -> None:
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            return
        except BaseException as error:
            record(f"killpg:{signum}", error)
            try:
                # Popen.send_signal() polls first and can reap a zombie leader.
                # Direct os.kill preserves the unreaped PID/PGID identity anchor.
                os.kill(process.pid, signum)
            except ProcessLookupError:
                return
            except BaseException as direct_error:
                record(f"signal-direct-child:{signum}", direct_error)

    def drain_until(deadline: float) -> None:
        while time.monotonic() < deadline:
            try:
                has_streams = selector is not None and bool(selector.get_map())
            except BaseException as error:
                record("inspect-validator-output", error)
                break
            if not has_streams:
                try:
                    time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
                except BaseException as error:
                    record("wait-for-validator-exit", error)
                    break
                continue
            try:
                _read_validator_events(
                    selector,
                    buffers,
                    max_output_bytes=max_output_bytes,
                    timeout_seconds=min(
                        0.02,
                        max(0.0, deadline - time.monotonic()),
                    ),
                    retain=False,
                )
            except BaseException as error:
                record("drain-validator-output", error)
                break

    signal_group(signal.SIGTERM)
    drain_until(time.monotonic() + VALIDATOR_TERM_GRACE_SECONDS)
    signal_group(signal.SIGKILL)
    kill_deadline = time.monotonic() + VALIDATOR_KILL_DRAIN_SECONDS
    drain_until(kill_deadline)
    # Reissue the group kill before, never after, releasing the unreaped
    # leader that pins this transaction's numeric PGID.
    signal_group(signal.SIGKILL)
    try:
        process.wait(timeout=max(0.0, kill_deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        record("reap-direct-child", error)
        try:
            process.kill()
            process.wait(timeout=0.1)
        except BaseException as final_error:
            record("kill-and-reap-direct-child", final_error)
    except BaseException as error:
        record("reap-direct-child", error)
    return cleanup_errors


def _stop_validator_process_group(
    process: subprocess.Popen[bytes],
    exit_observer: _ValidatorExitObserver,
    selector: selectors.BaseSelector,
    buffers: dict[str, bytearray],
    *,
    max_output_bytes: int,
) -> tuple[int, bool]:
    process_group_id = process.pid

    def signal_group_with_zombie_refresh(
        signum: int,
        *,
        child_was_exited: bool,
        known_members: tuple[int, ...],
    ) -> tuple[bool, tuple[int, ...]]:
        try:
            _signal_validator_group(
                process_group_id,
                signum,
                allow_zombie_only=child_was_exited,
            )
            return child_was_exited, known_members
        except TransactionError as error:
            if error.details.get("errno") != errno.EPERM:
                raise
            # Darwin can report EPERM for a group whose only remaining member
            # became a zombie between the nonreaping exit probe and killpg.
            # Refresh that exact unreaped leader and the group inventory before
            # accepting the signal as unnecessary.
            refresh_deadline = time.monotonic() + 0.02
            while True:
                refreshed_exit = exit_observer.child_exited()
                refreshed_members = _live_validator_group_member_pids(
                    process_group_id,
                    leader_pid=process.pid,
                )
                if refreshed_exit and not refreshed_members:
                    return refreshed_exit, refreshed_members
                if refreshed_members or time.monotonic() >= refresh_deadline:
                    raise
                time.sleep(
                    min(
                        0.001,
                        max(0.0, refresh_deadline - time.monotonic()),
                    )
                )

    child_exited = exit_observer.child_exited()
    live_members = _live_validator_group_member_pids(
        process_group_id,
        leader_pid=process.pid,
    )
    descendants_detected = bool(live_members)
    if not (child_exited and not selector.get_map() and not live_members):
        child_exited, live_members = signal_group_with_zombie_refresh(
            signal.SIGTERM,
            child_was_exited=child_exited,
            known_members=live_members,
        )
        descendants_detected = descendants_detected or bool(live_members)
    term_deadline = time.monotonic() + VALIDATOR_TERM_GRACE_SECONDS
    while time.monotonic() < term_deadline:
        remaining = term_deadline - time.monotonic()
        _read_validator_events(
            selector,
            buffers,
            max_output_bytes=max_output_bytes,
            timeout_seconds=min(0.02, remaining),
            retain=False,
        )
        child_exited = exit_observer.child_exited()
        live_members = _live_validator_group_member_pids(
            process_group_id,
            leader_pid=process.pid,
        )
        descendants_detected = descendants_detected or bool(live_members)
        if child_exited and not selector.get_map() and not live_members:
            break
    quiescent = child_exited and not selector.get_map() and not live_members
    if not quiescent:
        child_exited, live_members = signal_group_with_zombie_refresh(
            signal.SIGKILL,
            child_was_exited=child_exited,
            known_members=live_members,
        )
        descendants_detected = descendants_detected or bool(live_members)

    kill_deadline = time.monotonic() + VALIDATOR_KILL_DRAIN_SECONDS
    while time.monotonic() < kill_deadline:
        remaining = kill_deadline - time.monotonic()
        if selector.get_map():
            _read_validator_events(
                selector,
                buffers,
                max_output_bytes=max_output_bytes,
                timeout_seconds=min(0.02, remaining),
                retain=False,
            )
        else:
            time.sleep(min(0.01, max(0.0, remaining)))
        child_exited = exit_observer.child_exited()
        live_members = _live_validator_group_member_pids(
            process_group_id,
            leader_pid=process.pid,
        )
        descendants_detected = descendants_detected or bool(live_members)
        if child_exited and not selector.get_map() and not live_members:
            break

    child_exited = exit_observer.child_exited()
    surviving_members = _live_validator_group_member_pids(
        process_group_id,
        leader_pid=process.pid,
    )
    descendants_detected = descendants_detected or bool(surviving_members)
    if not child_exited or surviving_members or selector.get_map():
        raise TransactionError(
            "validator_cleanup_failed",
            "validator process group did not become quiescent before leader reap",
            details={
                "direct_child_exited": child_exited,
                "surviving_pids": list(surviving_members),
                "open_output_streams": len(selector.get_map()),
            },
        )
    try:
        returncode = process.wait(timeout=max(0.0, kill_deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        raise TransactionError(
            "validator_cleanup_failed",
            "validator direct child could not be reaped after group quiescence",
        ) from error
    return returncode, descendants_detected


def _start_validator_signal_supervision() -> tuple[
    ValidatorSignalGate,
    dict[int, signal.Handlers],
    set[signal.Signals],
    set[signal.Signals],
]:
    """Install a first-signal gate before any validator process can exist."""

    pthread_sigmask = getattr(signal, "pthread_sigmask", None)
    if (
        not callable(pthread_sigmask)
        or threading.current_thread() is not threading.main_thread()
        or threading.active_count() != 1
    ):
        raise TransactionError(
            "validator_supervision_unsupported",
            (
                "validator signal supervision requires a standalone "
                "single-threaded POSIX main thread"
            ),
        )
    sigchld = getattr(signal, "SIGCHLD", None)
    if sigchld is None or signal.getsignal(sigchld) != signal.SIG_DFL:
        raise TransactionError(
            "validator_supervision_unsupported",
            (
                "validator signal supervision requires the default SIGCHLD "
                "disposition so only its final wait can reap the PGID leader"
            ),
        )
    try:
        # Reinstall the default disposition to clear any inherited auto-reap
        # flags that a native caller may have paired with SIG_DFL.
        signal.signal(sigchld, signal.SIG_DFL)
    except (OSError, ValueError) as error:
        raise TransactionError(
            "validator_supervision_unsupported",
            f"cannot normalize SIGCHLD supervision: {error}",
        ) from error

    inherited_mask = pthread_sigmask(
        signal.SIG_BLOCK,
        MANAGED_VALIDATOR_SIGNALS,
    )
    supervisor_mask = set(inherited_mask).difference(MANAGED_VALIDATOR_SIGNALS)
    gate = ValidatorSignalGate()
    previous_handlers: dict[int, signal.Handlers] = {}
    try:
        for signum in MANAGED_VALIDATOR_SIGNALS:
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, gate.handle)
    except BaseException as error:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        pthread_sigmask(signal.SIG_SETMASK, inherited_mask)
        raise TransactionError(
            "validator_supervision_unsupported",
            f"cannot install validator signal supervision: {error}",
        ) from error

    # Popen and its child inherit the launcher's original mask.  The gate is
    # deliberately unarmed here: a signal delivered before Popen returns is
    # latched, not raised before the parent owns the child's PID/PGID.
    try:
        pthread_sigmask(signal.SIG_SETMASK, inherited_mask)
    except BaseException:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        pthread_sigmask(signal.SIG_SETMASK, inherited_mask)
        raise
    return gate, previous_handlers, set(inherited_mask), supervisor_mask


def _arm_validator_signal_supervision(
    gate: ValidatorSignalGate,
    supervisor_mask: set[signal.Signals],
) -> None:
    pthread_sigmask = signal.pthread_sigmask
    try:
        gate.arm()
    finally:
        # If the launcher blocked a managed signal, unblocking it here causes
        # the now-armed handler to raise only after Popen returned a bound PID.
        pthread_sigmask(signal.SIG_SETMASK, supervisor_mask)


def _quiesce_validator_signal_supervision(gate: ValidatorSignalGate) -> None:
    """Prevent later managed signals from interrupting synchronous cleanup."""

    gate.close()
    for signum in MANAGED_VALIDATOR_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def _restore_validator_signal_supervision(
    gate: ValidatorSignalGate,
    previous_handlers: dict[int, signal.Handlers],
    inherited_mask: set[signal.Signals],
) -> None:
    pthread_sigmask = signal.pthread_sigmask
    pthread_sigmask(signal.SIG_BLOCK, MANAGED_VALIDATOR_SIGNALS)
    try:
        gate.close()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    finally:
        pthread_sigmask(signal.SIG_SETMASK, inherited_mask)


class AnonymousValidatorInput:
    """Descriptor-backed, unnamed copy used only by the first validator."""

    def __init__(self, payload: bytes) -> None:
        self._file = tempfile.TemporaryFile(mode="w+b", buffering=0)
        self.fd = self._file.fileno()
        if self.fd < 3:
            duplicate = fcntl.fcntl(
                self.fd,
                fcntl.F_DUPFD_CLOEXEC,
                3,
            )
            self._file.close()
            self._file = os.fdopen(duplicate, "w+b", buffering=0)
            self.fd = duplicate
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(self.fd, payload[offset:])
                if written <= 0:
                    raise TransactionError(
                        "validator_input_write_failed",
                        "short write to anonymous validator input",
                        exit_code=EXIT_VALIDATION_FAILED,
                    )
                offset += written
            os.fchmod(self.fd, 0o600)
            os.fsync(self.fd)
            reject_unmodeled_metadata_fd(
                self.fd,
                label="validator_input",
            )
            actual_payload, snapshot = read_bound_fd(
                self.fd,
                label="validator_input",
            )
            if (
                actual_payload != payload
                or snapshot.uid != os.geteuid()
                or snapshot.mode != 0o600
                or snapshot.nlink != 0
            ):
                raise TransactionError(
                    "validator_input_unsupported",
                    (
                        "platform did not provide an owner-only, unlinked regular "
                        "validator input"
                    ),
                    exit_code=EXIT_VALIDATION_FAILED,
                    details={"actual": snapshot.to_json()},
                )
            self.expected = snapshot
            if (
                sys.platform.startswith("linux")
                and Path(f"/proc/self/fd/{self.fd}").exists()
            ):
                self.path = Path(f"/proc/self/fd/{self.fd}")
            elif Path(f"/dev/fd/{self.fd}").exists():
                self.path = Path(f"/dev/fd/{self.fd}")
            else:
                raise TransactionError(
                    "validator_fd_path_unsupported",
                    "platform has no validator-visible descriptor path",
                    exit_code=EXIT_VALIDATION_FAILED,
                )
            self.validate()
        except BaseException:
            self.close()
            raise

    def validate(self) -> Snapshot:
        _payload, actual = read_bound_fd(
            self.fd,
            label="validator_input",
        )
        try:
            reject_unmodeled_metadata_fd(
                self.fd,
                label="validator_input",
            )
        except TransactionError as error:
            raise TransactionError(
                "validator_input_changed",
                "anonymous validator input acquired unsupported metadata",
                exit_code=EXIT_VALIDATION_FAILED,
                details={
                    "metadata_status": error.status,
                    **error.details,
                },
            ) from error
        mismatches = property_mismatches(self.expected, actual)
        try:
            path_fd = os.open(
                self.path,
                os.O_RDONLY | os.O_CLOEXEC,
            )
        except OSError as error:
            raise TransactionError(
                "validator_fd_path_unsupported",
                f"validator descriptor path is unavailable: {error}",
                exit_code=EXIT_VALIDATION_FAILED,
            ) from error
        path_error: BaseException | None = None
        try:
            path_actual = os.fstat(path_fd)
        except BaseException as error:
            path_error = error
            raise
        finally:
            finalize_descriptor_cleanup(
                [("validator_input_path", path_fd)],
                primary_error=path_error,
            )
        mismatches.extend(
            mismatch
            for mismatch in stat_property_mismatches(
                self.expected,
                path_actual,
            )
            if mismatch not in mismatches
        )
        if mismatches:
            raise TransactionError(
                "validator_input_changed",
                "anonymous validator input changed during validation",
                exit_code=EXIT_VALIDATION_FAILED,
                details={"mismatched_properties": mismatches},
            )
        try:
            reject_unmodeled_metadata_fd(
                self.fd,
                label="validator_input",
            )
        except TransactionError as error:
            raise TransactionError(
                "validator_input_changed",
                "anonymous validator input metadata changed during admission",
                exit_code=EXIT_VALIDATION_FAILED,
                details={
                    "metadata_status": error.status,
                    **error.details,
                },
            ) from error
        _final_payload, final_actual = read_bound_fd(
            self.fd,
            label="validator_input",
        )
        final_mismatches = property_mismatches(
            self.expected,
            final_actual,
        )
        try:
            final_path_fd = os.open(
                self.path,
                os.O_RDONLY | os.O_CLOEXEC,
            )
        except OSError as error:
            raise TransactionError(
                "validator_fd_path_unsupported",
                f"validator descriptor path is unavailable: {error}",
                exit_code=EXIT_VALIDATION_FAILED,
            ) from error
        final_path_error: BaseException | None = None
        try:
            final_path_actual = os.fstat(final_path_fd)
        except BaseException as error:
            final_path_error = error
            raise
        finally:
            finalize_descriptor_cleanup(
                [("validator_input_final_path", final_path_fd)],
                primary_error=final_path_error,
            )
        final_mismatches.extend(
            mismatch
            for mismatch in stat_property_mismatches(
                self.expected,
                final_path_actual,
            )
            if mismatch not in final_mismatches
        )
        if final_mismatches:
            raise TransactionError(
                "validator_input_changed",
                "anonymous validator input changed during final revalidation",
                exit_code=EXIT_VALIDATION_FAILED,
                details={"mismatched_properties": final_mismatches},
            )
        try:
            reject_unmodeled_metadata_fd(
                self.fd,
                label="validator_input",
            )
        except TransactionError as error:
            raise TransactionError(
                "validator_input_changed",
                "anonymous validator input metadata changed during final revalidation",
                exit_code=EXIT_VALIDATION_FAILED,
                details={
                    "metadata_status": error.status,
                    **error.details,
                },
            ) from error
        os.lseek(self.fd, 0, os.SEEK_SET)
        return final_actual

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    def __enter__(self) -> AnonymousValidatorInput:
        return self

    def __exit__(
        self,
        _exc_type: object,
        _exc_value: object,
        _traceback: object,
    ) -> None:
        self.close()


def run_validator(
    command_template: list[str],
    rules_path: Path,
    *,
    timeout_seconds: float,
    pass_fds: tuple[int, ...] = (),
) -> ValidatorResult:
    if (
        not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or os.name != "posix"
        or not _validator_exit_observer_supported()
    ):
        raise TransactionError(
            "validator_command_invalid",
            "validator timeout must be finite and positive on POSIX",
        )
    if command_template.count(RULES_PLACEHOLDER) != 1:
        raise TransactionError(
            "validator_command_invalid",
            f"validator argv must contain exactly one {RULES_PLACEHOLDER!r} argument",
        )
    command = [
        str(rules_path) if argument == RULES_PLACEHOLDER else argument
        for argument in command_template
    ]
    deadline = time.monotonic() + timeout_seconds
    (
        signal_gate,
        previous_signal_handlers,
        inherited_signal_mask,
        supervisor_signal_mask,
    ) = _start_validator_signal_supervision()
    process: subprocess.Popen[bytes] | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exit_observer: _ValidatorExitObserver | None = None
    selector: selectors.BaseSelector | None = None
    timed_out = False
    output_limit_exceeded = False
    descendants_terminated = False
    try:
        try:
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=pass_fds,
                )
            except OSError as error:
                _arm_validator_signal_supervision(
                    signal_gate,
                    supervisor_signal_mask,
                )
                raise TransactionError(
                    "validator_launch_failed",
                    f"cannot launch validator: {error}",
                ) from error
            except BaseException:
                _arm_validator_signal_supervision(
                    signal_gate,
                    supervisor_signal_mask,
                )
                raise
            _arm_validator_signal_supervision(
                signal_gate,
                supervisor_signal_mask,
            )

            exit_observer = _ValidatorExitObserver(process)
            assert process.stdout is not None
            assert process.stderr is not None
            selector = selectors.DefaultSelector()
            for stream, label in (
                (process.stdout, "stdout"),
                (process.stderr, "stderr"),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                overflow, _progressed = _read_validator_events(
                    selector,
                    buffers,
                    max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
                    timeout_seconds=min(0.05, remaining),
                    retain=True,
                )
                if overflow:
                    output_limit_exceeded = True
                    break
                if not exit_observer.child_exited():
                    continue

                # Reap every byte already made readable by the direct child.
                # A still-open pipe or surviving group member then belongs to
                # a descendant and is not an acceptable terminal state.
                while selector.get_map():
                    overflow, progressed = _read_validator_events(
                        selector,
                        buffers,
                        max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
                        timeout_seconds=0.01,
                        retain=True,
                    )
                    if overflow:
                        output_limit_exceeded = True
                        break
                    if not progressed:
                        break
                if output_limit_exceeded:
                    break
                returncode, cleanup_descendants = _stop_validator_process_group(
                    process,
                    exit_observer,
                    selector,
                    buffers,
                    max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
                )
                descendants_terminated = descendants_terminated or cleanup_descendants
                if descendants_terminated:
                    return ValidatorResult(
                        125,
                        bytes(buffers["stdout"]).decode("utf-8", "replace"),
                        bytes(buffers["stderr"]).decode("utf-8", "replace"),
                        descendants_terminated=True,
                    )
                return ValidatorResult(
                    returncode,
                    bytes(buffers["stdout"]).decode("utf-8", "replace"),
                    bytes(buffers["stderr"]).decode("utf-8", "replace"),
                )

            assert exit_observer is not None
            assert selector is not None
            _returncode, cleanup_descendants = _stop_validator_process_group(
                process,
                exit_observer,
                selector,
                buffers,
                max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
            )
            descendants_terminated = descendants_terminated or cleanup_descendants
            return ValidatorResult(
                124 if timed_out else 125,
                bytes(buffers["stdout"]).decode("utf-8", "replace"),
                bytes(buffers["stderr"]).decode("utf-8", "replace"),
                timed_out=timed_out,
                output_limit_exceeded=output_limit_exceeded,
                descendants_terminated=descendants_terminated,
            )
        except ForwardedValidatorSignal as event:
            _quiesce_validator_signal_supervision(signal_gate)
            if process is not None:
                event.cleanup_errors = _emergency_stop_validator_process_group(
                    process,
                    selector,
                    buffers,
                    max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
                )
            raise
        except BaseException as error:
            _quiesce_validator_signal_supervision(signal_gate)
            cleanup_errors = (
                _emergency_stop_validator_process_group(
                    process,
                    selector,
                    buffers,
                    max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
                )
                if process is not None
                else []
            )
            if cleanup_errors and isinstance(error, TransactionError):
                error.details.setdefault(
                    "emergency_cleanup_errors",
                    cleanup_errors,
                )
            raise
        finally:
            if exit_observer is not None:
                exit_observer.close()
            if selector is not None:
                selector.close()
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
    finally:
        _restore_validator_signal_supervision(
            signal_gate,
            previous_signal_handlers,
            inherited_signal_mask,
        )


def fsync_file_and_parent(path: Path) -> None:
    fd = open_untrusted_regular_file(
        path,
        label="fsync_file",
    )
    primary_error: BaseException | None = None
    try:
        os.fsync(fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [("fsync_file", fd)],
            primary_error=primary_error,
        )
    parent_fd = os.open(
        path.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    primary_error = None
    try:
        os.fsync(parent_fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [("fsync_parent", parent_fd)],
            primary_error=primary_error,
        )


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
    primary_error: BaseException | None = None
    try:
        os.fsync(fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [("fsync_directory", fd)],
            primary_error=primary_error,
        )


def require_owner_private_directory(path: Path, *, label: str) -> None:
    binding = bind_directory(
        path,
        label=label,
        require_owner_private=True,
    )
    finalize_descriptor_cleanup([(f"{label}_parent", binding.fd)])


def prepared_candidate_path(receipt: Path) -> Path:
    return receipt.with_name(f"{receipt.name}{PREPARED_CANDIDATE_SUFFIX}")


def write_prepared_candidate(
    path: Path,
    payload: bytes,
    *,
    parent: BoundDirectory,
    policy: Snapshot,
) -> BoundFile:
    if path.parent != parent.path or Path(path.name).name != path.name:
        raise TransactionError(
            "path_invalid",
            "prepared candidate must be one child of its bound parent",
        )
    if policy.uid != os.geteuid() or policy.nlink != 1:
        raise TransactionError(
            "unsupported_rules_policy",
            "prepared candidate requires current-user, single-link live policy",
        )
    validate_bound_directory(parent)
    fd, snapshot = _write_exclusive_bound(
        path,
        payload,
        mode=policy.mode,
        uid=policy.uid,
        gid=policy.gid,
        directory_fd=parent.fd,
        name=path.name,
    )
    binding = BoundFile(
        path=path,
        name=path.name,
        fd=fd,
        snapshot=snapshot,
    )
    try:
        validate_bound_regular_file(
            binding,
            parent,
            label="prepared_candidate",
        )
        os.fsync(parent.fd)
        _persisted, actual = validate_bound_regular_file(
            binding,
            parent,
            label="prepared_candidate",
        )
        if property_mismatches(snapshot, actual):
            raise TransactionError(
                "prepared_candidate_changed",
                "prepared candidate changed while its recovery locator was persisted",
                details={
                    "mismatched_properties": property_mismatches(
                        snapshot,
                        actual,
                    )
                },
            )
        binding.snapshot = actual
        return binding
    except BaseException as error:
        finalize_descriptor_cleanup(
            [("prepared_candidate", fd)],
            primary_error=error,
        )
        raise


def move_prepared_candidate_to_stage(
    *,
    stage: PrivateStage,
    prepared: BoundFile,
    prepared_parent: BoundDirectory,
) -> tuple[Path, Snapshot]:
    validate_bound_directory(prepared_parent)
    validate_bound_regular_file(
        prepared,
        prepared_parent,
        label="prepared_candidate",
    )
    stage._validate_rules_parent()
    stage._validate_stage_root()
    destination = stage.path / "candidate"
    destination_before = observe_directory_entry(
        stage.stage_fd,
        destination.name,
    )
    if destination_before.get("state") != "missing":
        raise TransactionError(
            "recovery_required",
            "fixed stage candidate exists before prepared publication",
            exit_code=EXIT_POST_REPLACE_FAILED,
            details={
                "prepared_candidate_path": str(prepared.path),
                "staged_candidate_path": str(destination),
                "staged_candidate_observation": destination_before,
            },
        )
    atomic_error: BaseException | None = None
    stage.mutation_uncertain = True
    try:
        atomic_rename_no_replace(
            prepared_parent.fd,
            prepared.name,
            stage.stage_fd,
            destination.name,
        )
    except (OSError, TransactionError) as error:
        atomic_error = error
    source_observation = observe_directory_entry(
        prepared_parent.fd,
        prepared.name,
        expected=prepared.snapshot,
    )
    destination_observation = observe_directory_entry(
        stage.stage_fd,
        destination.name,
        expected=prepared.snapshot,
    )
    if atomic_error is not None:
        stage.mutation_uncertain = not (
            observation_matches(source_observation)
            and destination_observation.get("state") == "missing"
        )
        raise TransactionError(
            "recovery_required",
            "prepared candidate publication did not reach a verified committed state",
            exit_code=EXIT_POST_REPLACE_FAILED,
            details={
                "reason": (
                    atomic_error.status
                    if isinstance(atomic_error, TransactionError)
                    else "prepared_candidate_move_failed"
                ),
                "message": str(atomic_error),
                "prepared_candidate_path": str(prepared.path),
                "staged_candidate_path": str(destination),
                "source_observation": source_observation,
                "destination_observation": destination_observation,
            },
        ) from atomic_error
    try:
        _payload, actual = read_bound_fd(
            prepared.fd,
            label="prepared_candidate",
        )
        reject_unmodeled_metadata_fd(
            prepared.fd,
            label="prepared_candidate",
        )
        stage._validate_rules_parent()
        stage._validate_stage_root()
    except TransactionError as error:
        raise TransactionError(
            "recovery_required",
            "prepared candidate move could not be verified",
            exit_code=EXIT_POST_REPLACE_FAILED,
            details={
                "reason": error.status,
                "message": str(error),
                **error.details,
                "source_observation": source_observation,
                "destination_observation": destination_observation,
            },
        ) from error
    mismatches = property_mismatches(prepared.snapshot, actual)
    if (
        source_observation.get("state") != "missing"
        or not observation_matches(destination_observation)
        or mismatches
    ):
        raise TransactionError(
            "recovery_required",
            "prepared candidate move changed a bound protected property",
            exit_code=EXIT_POST_REPLACE_FAILED,
            details={
                "mismatched_properties": mismatches,
                "source_observation": source_observation,
                "destination_observation": destination_observation,
            },
        )
    prepared.path = destination
    prepared.name = destination.name
    prepared.snapshot = actual
    stage.files[destination] = prepared
    stage.mutation_uncertain = False
    return destination, actual


def receipt_payload(
    *,
    transaction_id: str,
    rules: Path,
    lock: Path,
    backup: Path,
    expected_sha256: str,
    candidate_sha256: str,
    parent: Snapshot,
    original: Snapshot,
    installed: Snapshot,
    backup_snapshot: Snapshot,
    staged_backup: Path,
    staged_backup_parent: Snapshot | None,
    prepared_candidate: Path,
    prepared_candidate_parent: Snapshot,
    recovery_terminal: Path,
    recovery_terminal_snapshot: Snapshot,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "transaction_id": transaction_id,
        "created_unix_ns": time.time_ns(),
        "rules_path": str(rules),
        "lock_path": str(lock),
        "backup_path": str(backup),
        "recovery_terminal_path": str(recovery_terminal),
        "expected_sha256": expected_sha256,
        "candidate_sha256": candidate_sha256,
        "rules_parent": parent.to_json(),
        "original": original.to_json(),
        "installed": installed.to_json(),
        "backup": backup_snapshot.to_json(),
        "staged_backup_path": str(staged_backup),
        "staged_backup_parent": (
            staged_backup_parent.to_json() if staged_backup_parent is not None else None
        ),
        "prepared_candidate_path": str(prepared_candidate),
        "prepared_candidate_parent": prepared_candidate_parent.to_json(),
        "recovery_terminal": recovery_terminal_snapshot.to_json(),
    }


def recovery_terminal_path(receipt: Path) -> Path:
    return receipt.with_name(f"{receipt.name}.recovered")


def write_receipt(
    path: Path,
    payload: dict[str, object],
    parent: BoundDirectory,
) -> BoundFile:
    if path.parent != parent.path or Path(path.name).name != path.name:
        raise TransactionError(
            "path_invalid",
            "receipt must be one child of its bound parent",
        )
    validate_bound_directory(parent)
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise TransactionError("receipt_too_large", "recovery receipt is too large")
    fd, snapshot = _write_exclusive_bound(
        path,
        encoded,
        directory_fd=parent.fd,
        name=path.name,
    )
    binding = BoundFile(
        path=path,
        name=path.name,
        fd=fd,
        snapshot=snapshot,
    )
    try:
        validate_bound_regular_file(
            binding,
            parent,
            label="receipt",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if (
            snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
            or snapshot.nlink != 1
        ):
            raise TransactionError(
                "receipt_invalid",
                "recovery receipt is not owner-only and single-link",
            )
        os.fsync(parent.fd)
        validate_bound_regular_file(
            binding,
            parent,
            label="receipt",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        return binding
    except BaseException as error:
        finalize_descriptor_cleanup(
            [("receipt", fd)],
            primary_error=error,
        )
        raise


def decode_receipt(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError(
            "receipt_invalid",
            f"cannot parse recovery receipt: {error}",
        ) from error
    schema_version = value.get("schema_version") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in SUPPORTED_SCHEMA_VERSIONS
    ):
        raise TransactionError(
            "receipt_invalid",
            "unsupported recovery receipt schema",
        )
    return value


@dataclass
class RecoveryReceiptEvidence:
    """Keep exact receipt bytes and their parent namespace bound through recovery."""

    parent: BoundDirectory
    binding: BoundFile
    value: dict[str, object]
    closed: bool = False

    def validate(self) -> dict[str, object]:
        payload, snapshot = validate_bound_regular_file(
            self.binding,
            self.parent,
            label="receipt",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if (
            snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
            or snapshot.nlink != 1
        ):
            raise TransactionError(
                "receipt_invalid",
                "recovery receipt is not owner-only and single-link",
            )
        value = decode_receipt(payload)
        if value != self.value:
            raise TransactionError(
                "receipt_changed",
                "recovery receipt decoded value changed",
                details={"mismatched_properties": ["content"]},
            )
        validate_bound_directory(self.parent)
        return value

    def close(self) -> list[dict[str, object]]:
        if self.closed:
            return []
        self.closed = True
        return close_descriptors_best_effort(
            [
                ("recovery_receipt", self.binding.fd),
                ("receipt_parent", self.parent.fd),
            ]
        )


def bind_recovery_receipt(path: Path) -> RecoveryReceiptEvidence:
    parent = bind_directory(
        path.parent,
        label="receipt",
        require_owner_private=True,
    )
    binding: BoundFile | None = None
    try:
        binding = bind_regular_file(
            path,
            parent,
            label="receipt",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        payload, snapshot = validate_bound_regular_file(
            binding,
            parent,
            label="receipt",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if (
            snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
            or snapshot.nlink != 1
        ):
            raise TransactionError(
                "receipt_invalid",
                "recovery receipt is not owner-only and single-link",
            )
        evidence = RecoveryReceiptEvidence(
            parent=parent,
            binding=binding,
            value=decode_receipt(payload),
        )
        evidence.validate()
        return evidence
    except BaseException as error:
        failures = close_descriptors_best_effort(
            [
                *(([("recovery_receipt", binding.fd)]) if binding is not None else []),
                ("receipt_parent", parent.fd),
            ]
        )
        attach_failures_to_exception(error, "cleanup_failures", failures)
        raise


def read_receipt_with_parent_snapshot(
    path: Path,
) -> tuple[dict[str, object], Snapshot]:
    evidence = bind_recovery_receipt(path)
    result: tuple[dict[str, object], Snapshot] | None = None
    primary_error: BaseException | None = None
    try:
        result = evidence.validate(), evidence.parent.snapshot
        return result
    except BaseException as error:
        primary_error = error
        raise
    finally:
        failures = evidence.close()
        if failures:
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            elif result is not None:
                attach_cleanup_failures_to_payload(result[0], failures)
            else:
                raise descriptor_cleanup_error(failures)


def read_receipt(path: Path) -> dict[str, object]:
    value, _parent_snapshot = read_receipt_with_parent_snapshot(path)
    return value


def decode_recovery_terminal(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError(
            "recovery_terminal_invalid",
            f"cannot parse recovery terminal evidence: {error}",
        ) from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != RECOVERY_TERMINAL_SCHEMA_VERSION
        or not isinstance(value.get("transaction_id"), str)
    ):
        raise TransactionError(
            "recovery_terminal_invalid",
            "unsupported recovery terminal evidence",
        )
    state = value.get("state")
    if state is None and "restored" in value:
        state = RECOVERY_TERMINAL_RESTORED
        value = {**value, "state": state}
    if state not in (RECOVERY_TERMINAL_RESERVED, RECOVERY_TERMINAL_RESTORED):
        raise TransactionError(
            "recovery_terminal_invalid",
            "recovery terminal state is invalid",
        )
    if state == RECOVERY_TERMINAL_RESTORED:
        Snapshot.from_json(
            value.get("restored"),
            label="recovery_terminal.restored",
            require_object_policy=True,
        )
    elif "restored" in value:
        raise TransactionError(
            "recovery_terminal_invalid",
            "reserved recovery terminal unexpectedly contains restored evidence",
        )
    return value


def recovery_terminal_result_path(path: Path) -> Path:
    return path.with_name(f"{path.name}{RECOVERY_TERMINAL_RESULT_SUFFIX}")


@dataclass
class RecoveryTerminalEvidence:
    """Bind the immutable reservation and optional atomically published result."""

    path: Path
    parent: BoundDirectory
    reservation: BoundFile
    expected_reservation: Snapshot
    transaction_id: str
    result: BoundFile | None = None
    closed: bool = False

    @property
    def result_path(self) -> Path:
        return recovery_terminal_result_path(self.path)

    @staticmethod
    def _require_private_single_link(
        snapshot: Snapshot,
        *,
        label: str,
    ) -> None:
        if (
            snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
            or snapshot.nlink != 1
        ):
            raise TransactionError(
                f"{label}_invalid",
                f"{label} is not owner-only and single-link",
            )

    def validate(self) -> dict[str, object]:
        reservation_payload, reservation_snapshot = validate_bound_regular_file(
            self.reservation,
            self.parent,
            label="recovery_terminal",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        self._require_private_single_link(
            reservation_snapshot,
            label="recovery_terminal",
        )
        reservation = decode_recovery_terminal(reservation_payload)
        if reservation.get("state") == RECOVERY_TERMINAL_RESERVED:
            reservation_mismatches = property_mismatches(
                self.expected_reservation,
                reservation_snapshot,
            )
        else:
            # Legacy receipts may have rewritten this exact inode before the
            # crash-safe two-slot protocol was introduced.
            reservation_mismatches = identity_access_and_object_policy_mismatches(
                self.expected_reservation,
                reservation_snapshot,
            )
        if reservation_mismatches:
            raise TransactionError(
                "recovery_terminal_binding_changed",
                "recovery terminal no longer names the receipt-bound object",
                details={"mismatched_properties": reservation_mismatches},
            )
        if reservation.get("transaction_id") != self.transaction_id:
            raise TransactionError(
                "recovery_terminal_transaction_mismatch",
                "recovery terminal belongs to another transaction",
            )

        if self.result is None:
            result_observation = observe_directory_entry(
                self.parent.fd,
                self.result_path.name,
            )
            if result_observation.get("state") != "missing":
                raise TransactionError(
                    "recovery_terminal_result_changed",
                    "recovery terminal result appeared outside the bound publication",
                    details={"result_observation": result_observation},
                )
            validate_bound_directory(self.parent)
            return reservation

        result_payload, result_snapshot = validate_bound_regular_file(
            self.result,
            self.parent,
            label="recovery_terminal_result",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        self._require_private_single_link(
            result_snapshot,
            label="recovery_terminal_result",
        )
        result = decode_recovery_terminal(result_payload)
        if (
            result.get("transaction_id") != self.transaction_id
            or result.get("state") != RECOVERY_TERMINAL_RESTORED
        ):
            raise TransactionError(
                "recovery_terminal_conflict",
                "published recovery terminal result is not restored evidence for "
                "this transaction",
            )
        validate_bound_directory(self.parent)
        return result

    def close(self) -> list[dict[str, object]]:
        if self.closed:
            return []
        self.closed = True
        return close_descriptors_best_effort(
            [
                *(
                    [("recovery_terminal_result", self.result.fd)]
                    if self.result is not None
                    else []
                ),
                ("recovery_terminal_reservation", self.reservation.fd),
            ]
        )


def bind_recovery_terminal_evidence(
    path: Path,
    *,
    parent: BoundDirectory,
    expected_reservation: Snapshot,
    transaction_id: str,
) -> RecoveryTerminalEvidence:
    reservation = bind_regular_file(
        path,
        parent,
        label="recovery_terminal",
        max_bytes=MAX_RECEIPT_BYTES,
    )
    evidence = RecoveryTerminalEvidence(
        path=path,
        parent=parent,
        reservation=reservation,
        expected_reservation=expected_reservation,
        transaction_id=transaction_id,
    )
    try:
        # Initial recovery may adopt a result left durably published by a prior
        # process. After this point, absence/presence is descriptor-bound.
        result_path = evidence.result_path
        observation = observe_directory_entry(parent.fd, result_path.name)
        if observation.get("state") != "missing":
            evidence.result = bind_regular_file(
                result_path,
                parent,
                label="recovery_terminal_result",
                max_bytes=MAX_RECEIPT_BYTES,
            )
        evidence.validate()
        return evidence
    except BaseException as error:
        attach_failures_to_exception(
            error,
            "cleanup_failures",
            evidence.close(),
        )
        raise


def read_recovery_terminal_with_snapshot(
    path: Path,
) -> tuple[dict[str, object], Snapshot]:
    parent = bind_directory(
        path.parent,
        label="recovery_terminal",
        require_owner_private=True,
    )
    reservation: BoundFile | None = None
    result: BoundFile | None = None
    outcome: tuple[dict[str, object], Snapshot] | None = None
    primary_error: BaseException | None = None
    try:
        reservation = bind_regular_file(
            path,
            parent,
            label="recovery_terminal",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        reservation_payload, snapshot = validate_bound_regular_file(
            reservation,
            parent,
            label="recovery_terminal",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        RecoveryTerminalEvidence._require_private_single_link(
            snapshot,
            label="recovery_terminal",
        )
        value = decode_recovery_terminal(reservation_payload)
        result_path = recovery_terminal_result_path(path)
        if (
            observe_directory_entry(parent.fd, result_path.name).get("state")
            != "missing"
        ):
            result = bind_regular_file(
                result_path,
                parent,
                label="recovery_terminal_result",
                max_bytes=MAX_RECEIPT_BYTES,
            )
            result_payload, result_snapshot = validate_bound_regular_file(
                result,
                parent,
                label="recovery_terminal_result",
                max_bytes=MAX_RECEIPT_BYTES,
            )
            RecoveryTerminalEvidence._require_private_single_link(
                result_snapshot,
                label="recovery_terminal_result",
            )
            value = decode_recovery_terminal(result_payload)
            if value.get("state") != RECOVERY_TERMINAL_RESTORED:
                raise TransactionError(
                    "recovery_terminal_conflict",
                    "recovery terminal result is not restored evidence",
                )
        outcome = (value, snapshot)
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [
                *(
                    [("recovery_terminal_result", result.fd)]
                    if result is not None
                    else []
                ),
                *(
                    [("recovery_terminal_reservation", reservation.fd)]
                    if reservation is not None
                    else []
                ),
                ("recovery_terminal_parent", parent.fd),
            ],
            primary_error=primary_error,
            payload=outcome[0] if outcome is not None else None,
        )


def read_recovery_terminal(path: Path) -> dict[str, object]:
    value, _snapshot = read_recovery_terminal_with_snapshot(path)
    return value


def reserve_recovery_terminal(
    path: Path,
    *,
    transaction_id: str,
    parent: BoundDirectory,
) -> BoundFile:
    if path.parent != parent.path or Path(path.name).name != path.name:
        raise TransactionError(
            "path_invalid",
            "recovery terminal must be one child of its bound parent",
        )
    payload: dict[str, object] = {
        "schema_version": RECOVERY_TERMINAL_SCHEMA_VERSION,
        "transaction_id": transaction_id,
        "created_unix_ns": time.time_ns(),
        "state": RECOVERY_TERMINAL_RESERVED,
    }
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    validate_bound_directory(parent)
    try:
        fd, snapshot = _write_exclusive_bound(
            path,
            encoded,
            directory_fd=parent.fd,
            name=path.name,
        )
    except TransactionError as error:
        if error.status == "path_exists":
            raise TransactionError(
                "recovery_terminal_exists",
                "recovery terminal path already exists before this transaction",
                exit_code=EXIT_LIVE_CONFLICT,
            ) from error
        raise
    binding = BoundFile(
        path=path,
        name=path.name,
        fd=fd,
        snapshot=snapshot,
    )
    try:
        if (
            snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
            or snapshot.nlink != 1
        ):
            raise TransactionError(
                "recovery_terminal_invalid",
                "reserved recovery terminal is not owner-only and single-link",
            )
        validate_bound_regular_file(
            binding,
            parent,
            label="recovery_terminal",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        os.fsync(parent.fd)
        persisted, _actual = validate_bound_regular_file(
            binding,
            parent,
            label="recovery_terminal",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        decoded = decode_recovery_terminal(persisted)
        if (
            decoded.get("transaction_id") != transaction_id
            or decoded.get("state") != RECOVERY_TERMINAL_RESERVED
        ):
            raise TransactionError(
                "recovery_terminal_conflict",
                "reserved recovery terminal is not bound to this transaction",
            )
        return binding
    except BaseException as error:
        finalize_descriptor_cleanup(
            [("recovery_terminal_reservation", fd)],
            primary_error=error,
        )
        raise


def publish_recovery_terminal_result(
    evidence: RecoveryTerminalEvidence,
    payload: bytes,
) -> BoundFile:
    if len(payload) > MAX_RECEIPT_BYTES:
        raise TransactionError(
            "recovery_terminal_invalid",
            "recovery terminal result exceeds the receipt byte limit",
        )
    if evidence.result is not None:
        evidence.validate()
        return evidence.result

    current = evidence.validate()
    if current.get("state") != RECOVERY_TERMINAL_RESERVED:
        raise TransactionError(
            "recovery_terminal_conflict",
            "only a reserved recovery terminal can publish a result slot",
        )

    result_path = evidence.result_path
    temporary_name = (
        f"{result_path.name}{RECOVERY_TERMINAL_TEMP_MARKER}{secrets.token_hex(16)}"
    )
    temporary_path = result_path.with_name(temporary_name)
    fd, snapshot = _write_exclusive_bound(
        temporary_path,
        payload,
        directory_fd=evidence.parent.fd,
        name=temporary_name,
    )
    binding = BoundFile(
        path=temporary_path,
        name=temporary_name,
        fd=fd,
        snapshot=snapshot,
    )
    published = False
    try:
        validate_bound_regular_file(
            binding,
            evidence.parent,
            label="recovery_terminal_result_pending",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        RecoveryTerminalEvidence._require_private_single_link(
            snapshot,
            label="recovery_terminal_result_pending",
        )
        evidence.validate()
        try:
            atomic_rename_no_replace(
                evidence.parent.fd,
                temporary_name,
                evidence.parent.fd,
                result_path.name,
            )
        except (OSError, TransactionError) as error:
            result_observation = observe_directory_entry(
                evidence.parent.fd,
                result_path.name,
                expected=snapshot,
            )
            pending_observation = observe_directory_entry(
                evidence.parent.fd,
                temporary_name,
                expected=snapshot,
            )
            if not observation_matches(result_observation):
                raise TransactionError(
                    "recovery_required",
                    "recovery terminal result publication did not reach a "
                    "provable terminal namespace state",
                    exit_code=EXIT_POST_REPLACE_FAILED,
                    details={
                        "reason": (
                            error.status
                            if isinstance(error, TransactionError)
                            else "terminal_result_publish_failed"
                        ),
                        "result_observation": result_observation,
                        "pending_observation": pending_observation,
                        "pending_locator": (
                            str(temporary_path)
                            if observation_matches(pending_observation)
                            else None
                        ),
                    },
                ) from error
        binding.path = result_path
        binding.name = result_path.name
        evidence.result = binding
        published = True
        validate_bound_regular_file(
            binding,
            evidence.parent,
            label="recovery_terminal_result",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        os.fsync(evidence.parent.fd)
        evidence.validate()
        return binding
    except BaseException as error:
        if not published:
            attach_failures_to_exception(
                error,
                "cleanup_failures",
                close_descriptors_best_effort(
                    [("recovery_terminal_result_pending", binding.fd)]
                ),
            )
        raise


def record_recovery_terminal(
    path: Path,
    *,
    transaction_id: str,
    original: Snapshot,
    restored: Snapshot,
    binding: BoundFile | None = None,
    parent: BoundDirectory | None = None,
    evidence: RecoveryTerminalEvidence | None = None,
    result_binding_sink: list[BoundFile] | None = None,
    allow_unreserved_legacy: bool = False,
    expected_reservation: Snapshot | None = None,
) -> dict[str, object]:
    if property_mismatches(original, restored) == []:
        evidence_kind = "original-identity"
    elif content_access_and_object_policy_match(original, restored):
        evidence_kind = "recorded-restored-identity"
    else:
        raise TransactionError(
            "recovery_terminal_invalid",
            "restored terminal state does not match the original protected content "
            "and policy",
        )
    payload: dict[str, object] = {
        "schema_version": RECOVERY_TERMINAL_SCHEMA_VERSION,
        "transaction_id": transaction_id,
        "created_unix_ns": time.time_ns(),
        "state": RECOVERY_TERMINAL_RESTORED,
        "evidence_kind": evidence_kind,
        "restored": restored.to_json(),
    }
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise TransactionError(
            "recovery_terminal_invalid",
            "recovery terminal evidence is too large",
        )
    if evidence is not None:
        if (
            evidence.path != path
            or evidence.transaction_id != transaction_id
            or evidence.parent.path != path.parent
        ):
            raise TransactionError(
                "recovery_terminal_conflict",
                "bound recovery terminal evidence does not match this publication",
            )
        existing = evidence.validate()
        if existing.get("state") == RECOVERY_TERMINAL_RESTORED:
            existing_restored = Snapshot.from_json(
                existing.get("restored"),
                label="recovery_terminal.restored",
                require_object_policy=True,
            )
            if property_mismatches(restored, existing_restored):
                raise TransactionError(
                    "recovery_terminal_conflict",
                    "existing recovery terminal evidence does not match this recovery",
                )
            return existing
        published = publish_recovery_terminal_result(evidence, encoded)
        persisted = evidence.validate()
        persisted_restored = Snapshot.from_json(
            persisted.get("restored"),
            label="recovery_terminal.restored",
            require_object_policy=True,
        )
        if property_mismatches(restored, persisted_restored):
            raise TransactionError(
                "recovery_terminal_conflict",
                "recovery terminal result changed after publication",
            )
        if result_binding_sink is not None and published not in result_binding_sink:
            result_binding_sink.append(published)
        return persisted

    owns_parent = parent is None
    owns_binding = binding is None
    created_legacy_terminal = False
    local_evidence: RecoveryTerminalEvidence | None = None
    outcome: dict[str, object] | None = None
    primary_error: BaseException | None = None
    try:
        if parent is None:
            parent = bind_directory(
                path.parent,
                label="recovery_terminal",
                require_owner_private=True,
            )
        if binding is None:
            try:
                binding = bind_regular_file(
                    path,
                    parent,
                    label="recovery_terminal",
                    max_bytes=MAX_RECEIPT_BYTES,
                )
            except TransactionError as error:
                if (
                    not allow_unreserved_legacy
                    or error.status != "recovery_terminal_missing"
                ):
                    raise
                fd, snapshot = _write_exclusive_bound(
                    path,
                    encoded,
                    directory_fd=parent.fd,
                    name=path.name,
                )
                binding = BoundFile(
                    path=path,
                    name=path.name,
                    fd=fd,
                    snapshot=snapshot,
                )
                created_legacy_terminal = True
        existing_payload, snapshot = validate_bound_regular_file(
            binding,
            parent,
            label="recovery_terminal",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if (
            snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
            or snapshot.nlink != 1
        ):
            raise TransactionError(
                "recovery_terminal_invalid",
                "recovery terminal evidence is not owner-only and single-link",
            )
        existing = decode_recovery_terminal(existing_payload)
        if created_legacy_terminal:
            os.fsync(parent.fd)
            if (
                existing.get("transaction_id") != transaction_id
                or existing.get("state") != RECOVERY_TERMINAL_RESTORED
            ):
                raise TransactionError(
                    "recovery_terminal_conflict",
                    "legacy recovery terminal publication changed",
                )
            outcome = existing
            return outcome
        local_evidence = RecoveryTerminalEvidence(
            path=path,
            parent=parent,
            reservation=binding,
            expected_reservation=expected_reservation or snapshot,
            transaction_id=transaction_id,
        )
        result_path = local_evidence.result_path
        if (
            observe_directory_entry(parent.fd, result_path.name).get("state")
            != "missing"
        ):
            local_evidence.result = bind_regular_file(
                result_path,
                parent,
                label="recovery_terminal_result",
                max_bytes=MAX_RECEIPT_BYTES,
            )
        existing = local_evidence.validate()
        if existing.get("state") == RECOVERY_TERMINAL_RESTORED:
            existing_restored = Snapshot.from_json(
                existing.get("restored"),
                label="recovery_terminal.restored",
                require_object_policy=True,
            )
            if property_mismatches(restored, existing_restored):
                raise TransactionError(
                    "recovery_terminal_conflict",
                    "existing recovery terminal evidence does not match this recovery",
                )
            outcome = existing
            return outcome
        published = publish_recovery_terminal_result(local_evidence, encoded)
        persisted = local_evidence.validate()
        persisted_restored = Snapshot.from_json(
            persisted.get("restored"),
            label="recovery_terminal.restored",
            require_object_policy=True,
        )
        if (
            persisted.get("transaction_id") != transaction_id
            or persisted.get("state") != RECOVERY_TERMINAL_RESTORED
            or property_mismatches(restored, persisted_restored)
        ):
            raise TransactionError(
                "recovery_terminal_conflict",
                "recovery terminal evidence changed after publication",
            )
        if result_binding_sink is not None and published not in result_binding_sink:
            result_binding_sink.append(published)
        outcome = persisted
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        descriptors: list[tuple[str, int]] = []
        if (
            local_evidence is not None
            and local_evidence.result is not None
            and (
                result_binding_sink is None
                or local_evidence.result not in result_binding_sink
            )
        ):
            descriptors.append(
                (
                    "recovery_terminal_result",
                    local_evidence.result.fd,
                )
            )
        if owns_binding and binding is not None:
            descriptors.append(("recovery_terminal_reservation", binding.fd))
        if owns_parent and parent is not None:
            descriptors.append(("recovery_terminal_parent", parent.fd))
        failures = close_descriptors_best_effort(descriptors)
        if failures:
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            elif outcome is not None:
                attach_cleanup_failures_to_payload(outcome, failures)
            else:
                raise descriptor_cleanup_error(failures)


def verify_restored_terminal(rules: Path, expected: Snapshot) -> Snapshot:
    _payload, actual = read_stable(
        rules,
        label="live_rules",
        require_modeled_metadata=True,
    )
    mismatches = property_mismatches(expected, actual)
    if mismatches:
        raise TransactionError(
            "recovery_terminal_live_changed",
            "live rules changed before restored terminal evidence was finalized",
            details={
                "mismatched_properties": mismatches,
                "actual_live": actual.to_json(),
            },
        )
    return actual


@dataclass
class ApplyEvidenceBindings:
    lock: BoundFile
    rules_parent: BoundDirectory
    receipt_parent: BoundDirectory
    recovery_terminal: BoundFile
    prepared_candidate: BoundFile
    stage: PrivateStage | None = None
    backup: BoundFile | None = None
    receipt: BoundFile | None = None
    recovery_terminal_result: BoundFile | None = None
    candidate_in_stage: bool = False
    restored: bool = False
    closed: bool = False

    def stage_owns_prepared_candidate(self) -> bool:
        if self.candidate_in_stage:
            return True
        if self.stage is None:
            return False
        if any(
            binding is self.prepared_candidate for binding in self.stage.files.values()
        ):
            return True
        return self.prepared_candidate.fd in self.stage.extra_fds

    def validate_controls(self) -> None:
        validate_bound_directory(self.rules_parent)
        revalidate_lock(self.lock, self.rules_parent)
        validate_bound_directory(self.receipt_parent)
        validate_bound_regular_file(
            self.recovery_terminal,
            self.receipt_parent,
            label="recovery_terminal",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        if self.recovery_terminal_result is not None:
            validate_bound_regular_file(
                self.recovery_terminal_result,
                self.receipt_parent,
                label="recovery_terminal_result",
                max_bytes=MAX_RECEIPT_BYTES,
            )
        if self.receipt is not None:
            validate_bound_regular_file(
                self.receipt,
                self.receipt_parent,
                label="receipt",
                max_bytes=MAX_RECEIPT_BYTES,
            )
        if self.stage is not None:
            self.stage._validate_rules_parent()
            self.stage._validate_stage_root()
        validate_bound_directory(self.rules_parent)
        revalidate_lock(self.lock, self.rules_parent)
        validate_bound_directory(self.receipt_parent)

    def validate(self) -> None:
        self.validate_controls()
        if self.restored:
            return
        if self.backup is None:
            if self.stage_owns_prepared_candidate():
                if self.stage is None:
                    raise TransactionError(
                        "private_candidate_unbound",
                        "prepared candidate moved without a bound private stage",
                    )
                staged_binding = self.stage._binding(self.prepared_candidate.path)
                self.stage.validate(
                    self.prepared_candidate.path,
                    staged_binding.snapshot,
                    label="private_candidate",
                )
            else:
                validate_bound_regular_file(
                    self.prepared_candidate,
                    self.receipt_parent,
                    label="prepared_candidate",
                )
        if self.backup is not None:
            if self.stage is None:
                raise TransactionError(
                    "backup_unbound",
                    "backup binding has no private stage",
                )
            validate_bound_regular_file(
                self.backup,
                self.stage.rules_parent_binding,
                label="backup",
            )
        self.validate_controls()

    def close(self) -> list[dict[str, object]]:
        if self.closed:
            return []
        self.closed = True
        descriptors: list[tuple[str, int]] = [
            *(
                [
                    (
                        "recovery_terminal_result",
                        self.recovery_terminal_result.fd,
                    )
                ]
                if self.recovery_terminal_result is not None
                else []
            ),
            (
                "recovery_terminal_reservation",
                self.recovery_terminal.fd,
            ),
            *(
                [("recovery_receipt", self.receipt.fd)]
                if self.receipt is not None
                else []
            ),
        ]
        if not self.stage_owns_prepared_candidate():
            descriptors.append(("prepared_candidate", self.prepared_candidate.fd))
        descriptors.extend(
            [
                ("receipt_parent", self.receipt_parent.fd),
                ("rules_parent", self.rules_parent.fd),
            ]
        )
        return close_descriptors_best_effort(descriptors)


def rollback(
    *,
    stage: PrivateStage,
    rules: Path,
    lock_binding: BoundFile,
    backup: Path,
    original: Snapshot,
    installed: Snapshot,
    backup_expected: Snapshot,
    pre_exchange_revalidate: Callable[[], None] | None = None,
    mutation_attempt: Callable[[], None] | None = None,
    mutation_complete: Callable[[], None] | None = None,
) -> tuple[bool, dict[str, object]]:
    backup_binding: BoundFile | None = None
    live_binding: BoundFile | None = None
    exchange_completed = False
    outcome: tuple[bool, dict[str, object]] | None = None
    primary_error: BaseException | None = None
    try:
        stage._validate_rules_parent()
        backup_binding = bind_regular_file(
            backup,
            stage.rules_parent_binding,
            label="backup",
        )
        _backup_bytes, backup_actual = validate_bound_regular_file(
            backup_binding,
            stage.rules_parent_binding,
            label="backup",
        )
        backup_mismatches = property_mismatches(
            backup_expected,
            backup_actual,
        )
        if backup_mismatches:
            outcome = (
                False,
                {
                    "rollback_status": "backup_changed",
                    "mismatched_properties": backup_mismatches,
                },
            )
            return outcome
        live_binding = bind_regular_file(
            rules,
            stage.rules_parent_binding,
            label="live_rules",
        )
        _live_bytes, live = validate_bound_regular_file(
            live_binding,
            stage.rules_parent_binding,
            label="live_rules",
        )
        live_mismatches = property_mismatches(installed, live)
        if live_mismatches:
            outcome = (
                False,
                {
                    "rollback_status": "live_no_longer_installed",
                    "mismatched_properties": live_mismatches,
                    "actual_live": live.to_json(),
                },
            )
            return outcome
        revalidate_lock(lock_binding, stage.rules_parent_binding)
        validate_bound_regular_file(
            backup_binding,
            stage.rules_parent_binding,
            label="backup",
        )
        validate_bound_regular_file(
            live_binding,
            stage.rules_parent_binding,
            label="live_rules",
        )
        stage._validate_rules_parent()
        if pre_exchange_revalidate is not None:
            pre_exchange_revalidate()

        atomic_error: OSError | None = None
        if mutation_attempt is not None:
            mutation_attempt()
        stage.mutation_uncertain = True
        try:
            atomic_rename_exchange(
                stage.rules_parent_fd,
                backup_binding.name,
                stage.rules_parent_fd,
                live_binding.name,
            )
        except TransactionError:
            stage.mutation_uncertain = False
            raise
        except OSError as error:
            atomic_error = error

        backup_observation = observe_directory_entry(
            stage.rules_parent_fd,
            backup_binding.name,
            expected=installed,
        )
        live_observation = observe_directory_entry(
            stage.rules_parent_fd,
            live_binding.name,
            expected=original,
        )
        if atomic_error is not None:
            unchanged_backup = observe_directory_entry(
                stage.rules_parent_fd,
                backup_binding.name,
                expected=backup_expected,
            )
            unchanged_live = observe_directory_entry(
                stage.rules_parent_fd,
                live_binding.name,
                expected=installed,
            )
            if observation_matches(unchanged_backup) and observation_matches(
                unchanged_live
            ):
                stage.mutation_uncertain = False
                outcome = (
                    False,
                    {
                        "rollback_status": "atomic_exchange_failed",
                        "rollback_message": str(atomic_error),
                        "backup_observation": unchanged_backup,
                        "live_observation": unchanged_live,
                    },
                )
                return outcome
            raise stage._uncertain_mutation(
                operation="rollback_exchange",
                source=backup_binding,
                destination_binding=live_binding,
                destination=rules,
                source_observation=backup_observation,
                destination_observation=live_observation,
                destination_expected=installed,
                error=atomic_error,
            ) from atomic_error

        try:
            _original_bytes, original_after = read_bound_fd(
                backup_binding.fd,
                label="rollback_original",
            )
            _installed_bytes, installed_after = read_bound_fd(
                live_binding.fd,
                label="rollback_displaced_installed",
            )
            reject_unmodeled_metadata_fd(
                backup_binding.fd,
                label="rollback_original",
            )
            reject_unmodeled_metadata_fd(
                live_binding.fd,
                label="rollback_displaced_installed",
            )
        except TransactionError as error:
            raise stage._uncertain_mutation(
                operation="rollback_exchange",
                source=backup_binding,
                destination_binding=live_binding,
                destination=rules,
                source_observation=backup_observation,
                destination_observation=live_observation,
                destination_expected=installed,
            ) from error
        if (
            property_mismatches(backup_expected, original_after)
            or property_mismatches(installed, installed_after)
            or not observation_matches(backup_observation)
            or not observation_matches(live_observation)
        ):
            raise stage._uncertain_mutation(
                operation="rollback_exchange",
                source=backup_binding,
                destination_binding=live_binding,
                destination=rules,
                source_observation=backup_observation,
                destination_observation=live_observation,
                destination_expected=installed,
            )
        stage.mutation_uncertain = False
        exchange_completed = True
        if mutation_complete is not None:
            mutation_complete()
        os.fsync(stage.rules_parent_fd)
        if pre_exchange_revalidate is not None:
            pre_exchange_revalidate()
        _restored_bytes, restored = read_bound_regular_child(
            rules,
            stage.rules_parent_binding,
            label="live_rules",
        )
        restored_mismatches = property_mismatches(
            backup_expected,
            restored,
        )
        if restored_mismatches or not content_access_and_object_policy_match(
            original,
            restored,
        ):
            outcome = (
                False,
                {
                    "rollback_status": "recovery_required",
                    "recovery_reason": "rollback_verification_failed",
                    "mismatched_properties": restored_mismatches,
                    "actual_live": restored.to_json(),
                },
            )
            return outcome
        outcome = (
            True,
            {
                "rollback_status": "rolled_back",
                "restored": restored.to_json(),
            },
        )
        return outcome
    except (OSError, TransactionError) as error:
        error_status = (
            error.status if isinstance(error, TransactionError) else "rollback_failed"
        )
        result: dict[str, object] = {
            "rollback_status": (
                "recovery_required" if exchange_completed else error_status
            ),
            "rollback_message": str(error),
        }
        if exchange_completed:
            result["recovery_reason"] = error_status
        if isinstance(error, TransactionError):
            result.update(error.details)
        outcome = (False, result)
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        finalize_descriptor_cleanup(
            [
                *(
                    [("rollback_live_rules", live_binding.fd)]
                    if live_binding is not None
                    else []
                ),
                *(
                    [("rollback_backup", backup_binding.fd)]
                    if backup_binding is not None
                    else []
                ),
            ],
            primary_error=primary_error,
            payload=outcome[1] if outcome is not None else None,
        )


def _apply_transaction_inner(
    args: argparse.Namespace,
    cleanup_callbacks: list[Callable[[], list[dict[str, object]]]],
) -> tuple[int, dict[str, object]]:
    expected_sha256 = args.expected_sha256.lower()
    if not valid_sha256(expected_sha256):
        raise TransactionError(
            "expected_digest_invalid",
            "--expected-sha256 must be 64 lowercase hexadecimal characters",
        )
    candidate_sha256 = args.candidate_sha256.lower()
    if not valid_sha256(candidate_sha256):
        raise TransactionError(
            "candidate_digest_invalid",
            "--candidate-sha256 must be 64 lowercase hexadecimal characters",
        )
    rules = codex_rules_path()
    candidate_source = resolved_leaf(args.candidate, label="candidate")
    receipt = resolved_leaf(args.receipt, label="receipt")
    recovery_terminal = recovery_terminal_path(receipt)
    recovery_terminal_result = recovery_terminal_result_path(recovery_terminal)
    prepared_recovery_candidate = prepared_candidate_path(receipt)
    if Path(
        args.backup_name
    ).name != args.backup_name or not args.backup_name.startswith("default.rules.bak-"):
        raise TransactionError(
            "path_invalid",
            "--backup-name must be one default.rules.bak-* basename",
        )
    backup = rules.parent / args.backup_name
    lock = rules.parent / ".default.rules.apply.lock"
    reject_fixed_stage_namespace_overlap(
        rules.parent,
        [
            ("receipt", receipt),
            ("recovery_terminal", recovery_terminal),
            ("recovery_terminal_result", recovery_terminal_result),
            ("prepared_candidate", prepared_recovery_candidate),
            ("lock", lock),
        ],
    )
    if (
        candidate_source == rules
        or receipt in (rules, backup, lock, candidate_source)
        or recovery_terminal in (rules, backup, lock, candidate_source, receipt)
        or recovery_terminal_result
        in (rules, backup, lock, candidate_source, receipt, recovery_terminal)
        or prepared_recovery_candidate
        in (
            rules,
            backup,
            lock,
            candidate_source,
            receipt,
            recovery_terminal,
            recovery_terminal_result,
        )
    ):
        raise TransactionError("path_invalid", "transaction paths must be distinct")

    candidate_bytes, source_snapshot = read_stable(
        candidate_source,
        label="candidate_source",
        require_modeled_metadata=True,
    )
    if not hmac.compare_digest(source_snapshot.sha256, candidate_sha256):
        raise TransactionError(
            "candidate_digest_mismatch",
            "candidate source does not match the audited candidate SHA-256",
            exit_code=EXIT_VALIDATION_FAILED,
            details={
                "expected_candidate_sha256": candidate_sha256,
                "actual_candidate_sha256": source_snapshot.sha256,
            },
        )

    stage: PrivateStage | None = None
    evidence: ApplyEvidenceBindings | None = None
    lock_acquired = False
    retain_stage = False
    pending_success_status: str | None = None
    replacement_started = False
    finalized = False
    rules_parent_binding: BoundDirectory | None = None
    stage_cleanup_failures: list[dict[str, object]] = []

    def finalize_apply_state() -> None:
        nonlocal finalized, retain_stage
        if finalized:
            return
        finalized = True
        evidence_error: TransactionError | None = None
        try:
            if evidence is not None:
                try:
                    (
                        evidence.validate_controls()
                        if retain_stage or evidence.restored
                        else evidence.validate()
                    )
                except TransactionError as error:
                    retain_stage = True
                    evidence_error = error
        finally:
            effective_retain_stage = retain_stage or (
                stage is not None and stage.mutation_uncertain
            )
            warnings = (
                stage.cleanup(retain=effective_retain_stage)
                if stage is not None
                else []
            )
        if warnings:
            print(
                json.dumps(
                    {
                        "status": "cleanup_warning",
                        "lock_acquired": lock_acquired,
                        "warnings": warnings,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        cleanup_refusals = [
            warning
            for warning in warnings
            if warning.get("status") == "stage_cleanup_refused"
        ]
        descriptor_failures = private_stage_descriptor_cleanup_failures(warnings)
        stage_cleanup_failures.extend(descriptor_failures)
        if pending_success_status is not None and descriptor_failures:
            raise TransactionError(
                "recovery_required",
                "cannot report success while private-stage descriptor cleanup is uncertain",
                exit_code=EXIT_POST_REPLACE_FAILED,
                details={
                    "operation_status": pending_success_status,
                    "reason": PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
                    "cleanup_reason": PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
                },
            )
        if (
            pending_success_status is not None or replacement_started
        ) and cleanup_refusals:
            raise TransactionError(
                "recovery_required",
                "cannot finalize a replaced transaction while fixed stage cleanup is unverified",
                exit_code=EXIT_POST_REPLACE_FAILED,
                details={
                    "operation_status": pending_success_status,
                    "cleanup_refusals": cleanup_refusals,
                },
            )
        if evidence_error is not None and pending_success_status is not None:
            raise TransactionError(
                "recovery_required",
                "bound transaction evidence changed before lock release",
                exit_code=EXIT_POST_REPLACE_FAILED,
                details={
                    "reason": evidence_error.status,
                    "message": str(evidence_error),
                    **evidence_error.details,
                },
            ) from evidence_error

    def close_apply_state() -> list[dict[str, object]]:
        failures = list(stage_cleanup_failures)
        try:
            if evidence is not None:
                failures.extend(evidence.close())
                return failures
            if rules_parent_binding is not None:
                failures.extend(
                    close_descriptors_best_effort(
                        [("rules_parent", rules_parent_binding.fd)]
                    )
                )
                return failures
        except BaseException as error:
            failures.append(
                structured_operation_failure(
                    "close",
                    "apply_evidence_group",
                    error,
                )
            )
        return failures

    cleanup_callbacks.append(close_apply_state)

    try:
        # A no-op needs neither a validator process nor a staging directory.
        # The unlocked read is only a hint; every protected live property and
        # the candidate source are revalidated under the shared writer lock.
        live_hint, _live_hint_snapshot = read_stable(
            rules,
            label="live_rules",
        )
        if live_hint == candidate_bytes:
            with shared_lock(
                lock,
                timeout_seconds=args.lock_timeout_seconds,
            ) as lock_binding:
                lock_acquired = True
                no_change_parent_binding = bind_directory(
                    rules.parent,
                    label="rules",
                )
                no_change_outcome: tuple[int, dict[str, object]] | None = None
                no_change_error: BaseException | None = None
                try:
                    revalidate_lock(lock_binding, no_change_parent_binding)
                    current_bytes, current = read_bound_regular_child(
                        rules,
                        no_change_parent_binding,
                        label="live_rules",
                    )
                    if current.nlink != 1:
                        no_change_outcome = (
                            EXIT_LIVE_CONFLICT,
                            {
                                "status": "live_rules_object_policy_unsupported",
                                "rules_path": str(rules),
                                "object_policy": {"nlink": current.nlink},
                            },
                        )
                        return no_change_outcome
                    if not hmac.compare_digest(current.sha256, expected_sha256):
                        no_change_outcome = (
                            EXIT_LIVE_CONFLICT,
                            {
                                "status": "expected_digest_mismatch",
                                "rules_path": str(rules),
                                "expected_sha256": expected_sha256,
                                "actual_sha256": current.sha256,
                            },
                        )
                        return no_change_outcome
                    revalidate_candidate_source(
                        candidate_source,
                        source_snapshot,
                        candidate_sha256=candidate_sha256,
                    )
                    if current_bytes == candidate_bytes:
                        validate_existing_fixed_stage_is_empty(
                            rules.parent,
                            rules_parent_expected=no_change_parent_binding.snapshot,
                        )
                        revalidate_lock(lock_binding, no_change_parent_binding)
                        no_change_outcome = (
                            0,
                            {
                                "status": "no_change_after_lock",
                                "rules_path": str(rules),
                                "sha256": current.sha256,
                            },
                        )
                        return no_change_outcome
                    revalidate_lock(lock_binding, no_change_parent_binding)
                except BaseException as error:
                    no_change_error = error
                    raise
                finally:
                    finalize_descriptor_cleanup(
                        [("rules_parent", no_change_parent_binding.fd)],
                        primary_error=no_change_error,
                        payload=(
                            no_change_outcome[1]
                            if no_change_outcome is not None
                            else None
                        ),
                    )
            lock_acquired = False

        # The first validator sees only an unlinked descriptor-backed copy.  No
        # rules-parent stage exists until the copy and the caller-owned audited
        # source have both survived full protected-property revalidation.
        with AnonymousValidatorInput(candidate_bytes) as validation_input:
            pre_validation = run_validator(
                args.validator_command,
                validation_input.path,
                timeout_seconds=args.validator_timeout_seconds,
                pass_fds=(validation_input.fd,),
            )
            validation_input.validate()
            revalidate_candidate_source(
                candidate_source,
                source_snapshot,
                candidate_sha256=candidate_sha256,
            )
        if not pre_validation.valid:
            return EXIT_VALIDATION_FAILED, {
                "status": "candidate_validation_failed",
                "validator": pre_validation.to_json(),
                "rules_path": str(rules),
            }

        with shared_lock(
            lock,
            timeout_seconds=args.lock_timeout_seconds,
            before_release=finalize_apply_state,
        ) as lock_binding:
            lock_acquired = True
            rules_parent_binding = bind_directory(
                rules.parent,
                label="rules",
            )
            revalidate_lock(lock_binding, rules_parent_binding)
            current_bytes, current = read_bound_regular_child(
                rules,
                rules_parent_binding,
                label="live_rules",
            )
            if current.nlink != 1:
                return EXIT_LIVE_CONFLICT, {
                    "status": "live_rules_object_policy_unsupported",
                    "rules_path": str(rules),
                    "object_policy": {"nlink": current.nlink},
                }
            if not hmac.compare_digest(current.sha256, expected_sha256):
                return EXIT_LIVE_CONFLICT, {
                    "status": "expected_digest_mismatch",
                    "rules_path": str(rules),
                    "expected_sha256": expected_sha256,
                    "actual_sha256": current.sha256,
                }
            if current_bytes == candidate_bytes:
                revalidate_candidate_source(
                    candidate_source,
                    source_snapshot,
                    candidate_sha256=candidate_sha256,
                )
                validate_existing_fixed_stage_is_empty(
                    rules.parent,
                    rules_parent_expected=rules_parent_binding.snapshot,
                )
                revalidate_lock(lock_binding, rules_parent_binding)
                pending_success_status = "no_change_after_lock"
                return 0, {
                    "status": "no_change_after_lock",
                    "rules_path": str(rules),
                    "sha256": current.sha256,
                }

            transaction_id = secrets.token_hex(16)
            receipt_parent = bind_directory(
                receipt.parent,
                label="receipt",
                require_owner_private=True,
            )
            try:
                if receipt_parent.path == rules.parent / PRIVATE_STAGE_NAME:
                    raise TransactionError(
                        "path_invalid",
                        "receipt parent cannot be the fixed transaction stage",
                    )
                if (
                    receipt_parent.snapshot.device
                    != rules_parent_binding.snapshot.device
                ):
                    raise TransactionError(
                        "prepared_candidate_cross_device",
                        (
                            "receipt and rules parents must share one filesystem "
                            "for atomic prepared-candidate publication"
                        ),
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                if (
                    observe_directory_entry(
                        receipt_parent.fd,
                        receipt.name,
                    ).get("state")
                    != "missing"
                ):
                    raise TransactionError(
                        "receipt_exists",
                        f"recovery receipt already exists: {receipt}",
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                if (
                    observe_directory_entry(
                        receipt_parent.fd,
                        prepared_recovery_candidate.name,
                    ).get("state")
                    != "missing"
                ):
                    raise TransactionError(
                        "prepared_candidate_exists",
                        (
                            "prepared recovery candidate already exists: "
                            f"{prepared_recovery_candidate}"
                        ),
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                if (
                    observe_directory_entry(
                        receipt_parent.fd,
                        recovery_terminal.name,
                    ).get("state")
                    != "missing"
                ):
                    raise TransactionError(
                        "recovery_terminal_exists",
                        (
                            "recovery terminal path already exists before this "
                            "transaction"
                        ),
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                if (
                    observe_directory_entry(
                        receipt_parent.fd,
                        recovery_terminal_result.name,
                    ).get("state")
                    != "missing"
                ):
                    raise TransactionError(
                        "recovery_terminal_result_exists",
                        (
                            "recovery terminal result path already exists before "
                            "this transaction"
                        ),
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                if (
                    observe_directory_entry(
                        rules_parent_binding.fd,
                        backup.name,
                    ).get("state")
                    != "missing"
                ):
                    raise TransactionError(
                        "backup_exists",
                        f"backup already exists: {backup}",
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                revalidate_candidate_source(
                    candidate_source,
                    source_snapshot,
                    candidate_sha256=candidate_sha256,
                )
                validate_existing_fixed_stage_is_empty(
                    rules.parent,
                    rules_parent_expected=rules_parent_binding.snapshot,
                )
                revalidate_lock(lock_binding, rules_parent_binding)
                validate_bound_directory(receipt_parent)
                revalidate_candidate_source(
                    candidate_source,
                    source_snapshot,
                    candidate_sha256=candidate_sha256,
                )
                prepared_binding = write_prepared_candidate(
                    prepared_recovery_candidate,
                    candidate_bytes,
                    parent=receipt_parent,
                    policy=current,
                )
                terminal_binding: BoundFile | None = None
                try:
                    terminal_binding = reserve_recovery_terminal(
                        recovery_terminal,
                        transaction_id=transaction_id,
                        parent=receipt_parent,
                    )
                except BaseException as error:
                    finalize_descriptor_cleanup(
                        [("prepared_candidate", prepared_binding.fd)],
                        primary_error=error,
                    )
                    raise
            except BaseException as error:
                finalize_descriptor_cleanup(
                    [("receipt_parent", receipt_parent.fd)],
                    primary_error=error,
                )
                raise
            evidence = ApplyEvidenceBindings(
                lock=lock_binding,
                rules_parent=rules_parent_binding,
                receipt_parent=receipt_parent,
                recovery_terminal=terminal_binding,
                prepared_candidate=prepared_binding,
            )
            evidence.validate()

            parent_expected = rules_parent_binding.snapshot
            installed_snapshot = prepared_binding.snapshot
            candidate = rules.parent / PRIVATE_STAGE_NAME / "candidate"
            transaction_receipt = receipt_payload(
                transaction_id=transaction_id,
                rules=rules,
                lock=lock,
                backup=backup,
                expected_sha256=expected_sha256,
                candidate_sha256=candidate_sha256,
                parent=parent_expected,
                original=current,
                installed=installed_snapshot,
                backup_snapshot=current,
                staged_backup=candidate,
                staged_backup_parent=None,
                prepared_candidate=prepared_recovery_candidate,
                prepared_candidate_parent=receipt_parent.snapshot,
                recovery_terminal=recovery_terminal,
                recovery_terminal_snapshot=evidence.recovery_terminal.snapshot,
            )
            evidence.receipt = write_receipt(
                receipt,
                transaction_receipt,
                evidence.receipt_parent,
            )
            evidence.validate()

            stage = PrivateStage(
                rules.parent,
                rules_parent_expected=rules_parent_binding.snapshot,
            )
            evidence.stage = stage
            candidate, installed_snapshot = move_prepared_candidate_to_stage(
                stage=stage,
                prepared=evidence.prepared_candidate,
                prepared_parent=evidence.receipt_parent,
            )
            evidence.candidate_in_stage = True
            try:
                os.fsync(stage.stage_fd)
                os.fsync(stage.rules_parent_fd)
                os.fsync(evidence.receipt_parent.fd)
            except OSError as error:
                retain_stage = True
                raise TransactionError(
                    "recovery_required",
                    "prepared candidate move could not be made durable",
                    exit_code=EXIT_POST_REPLACE_FAILED,
                    details={
                        "reason": "prepared_candidate_move_fsync_failed",
                        "message": str(error),
                        "receipt_path": str(receipt),
                        "staged_backup_path": str(candidate),
                    },
                ) from error
            evidence.validate()

            revalidate_lock(lock_binding, rules_parent_binding)
            _final_bytes, final_live = read_bound_regular_child(
                rules,
                rules_parent_binding,
                label="live_rules",
            )
            final_mismatches = property_mismatches(current, final_live)
            if final_mismatches:
                return EXIT_LIVE_CONFLICT, {
                    "status": "live_changed_before_replace",
                    "mismatched_properties": final_mismatches,
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }

            try:
                installed_expected = stage.move_to(
                    candidate,
                    rules,
                    final_live,
                    pre_exchange_revalidate=evidence.validate,
                )
                replacement_started = True
                evidence.validate()
            except TransactionError as error:
                error.details.setdefault("receipt_path", str(receipt))
                error.details.setdefault("backup_path", str(backup))
                if replacement_started:
                    retain_stage = True
                    return EXIT_POST_REPLACE_FAILED, {
                        "status": "recovery_required",
                        "post_replace_failure": {
                            "status": error.status,
                            "message": str(error),
                            **error.details,
                        },
                        "receipt_path": str(receipt),
                        "backup_path": str(backup),
                        "staged_backup_path": str(candidate),
                    }
                raise
            # The exchange leaves the exact original live inode bound at the
            # staged candidate path.  Publish that object itself as the formal
            # no-clobber backup so a successful transaction leaves no child
            # inode in its private stage.
            try:
                backup_binding = stage.publish_backup(candidate, backup)
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                    "staged_backup_path": str(candidate),
                }
            backup_snapshot = backup_binding.snapshot
            if property_mismatches(current, backup_snapshot):
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": "backup_identity_mismatch",
                        "mismatched_properties": property_mismatches(
                            current,
                            backup_snapshot,
                        ),
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                    "staged_backup_path": str(candidate),
                }
            evidence.backup = backup_binding
            try:
                os.fsync(stage.stage_fd)
                os.fsync(stage.rules_parent_fd)
            except OSError as error:
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": "backup_publication_fsync_failed",
                        "message": str(error),
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            post_failure: dict[str, object] | None = None
            try:
                evidence.validate()
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            try:
                fsync_file_and_parent(rules)
            except (OSError, TransactionError) as error:
                post_failure = {
                    "status": (
                        error.status
                        if isinstance(error, TransactionError)
                        else "post_replace_fsync_failed"
                    ),
                    "message": str(error),
                }

            try:
                _installed_bytes, installed_live = read_bound_regular_child(
                    rules,
                    rules_parent_binding,
                    label="live_rules",
                )
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            try:
                evidence.validate()
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            installed_mismatches = property_mismatches(
                installed_expected,
                installed_live,
            )
            if installed_mismatches:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": "installed_identity_mismatch",
                        "mismatched_properties": installed_mismatches,
                    },
                    "actual_live": installed_live.to_json(),
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }

            post_validation: ValidatorResult | None = None
            if post_failure is None:
                post_validation = run_validator(
                    args.validator_command,
                    rules,
                    timeout_seconds=args.validator_timeout_seconds,
                )
                if not post_validation.valid:
                    post_failure = {
                        "status": "post_replace_validation_failed",
                        "validator": post_validation.to_json(),
                    }

            try:
                evidence.validate()
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            try:
                _post_bytes, post_live = read_bound_regular_child(
                    rules,
                    rules_parent_binding,
                    label="live_rules",
                )
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            try:
                evidence.validate()
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            post_mismatches = property_mismatches(installed_expected, post_live)
            if post_mismatches:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": "live_changed_after_replace",
                        "mismatched_properties": post_mismatches,
                    },
                    "actual_live": post_live.to_json(),
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }

            if post_failure is not None:
                try:
                    evidence.validate()
                except TransactionError as error:
                    retain_stage = True
                    return EXIT_POST_REPLACE_FAILED, {
                        "status": "recovery_required",
                        "post_replace_failure": post_failure,
                        "recovery_evidence_failure": {
                            "status": error.status,
                            "message": str(error),
                            **error.details,
                        },
                        "receipt_path": str(receipt),
                        "backup_path": str(backup),
                    }
                rolled_back, rollback_result = rollback(
                    stage=stage,
                    rules=rules,
                    lock_binding=lock_binding,
                    backup=backup,
                    original=current,
                    installed=installed_expected,
                    backup_expected=backup_snapshot,
                )
                recovery_terminal_result: dict[str, object] | None = None
                if rolled_back:
                    try:
                        restored = Snapshot.from_json(
                            rollback_result.get("restored"),
                            label="rollback.restored",
                            require_object_policy=True,
                        )
                        terminal_result_bindings: list[BoundFile] = []
                        recovery_terminal_result = record_recovery_terminal(
                            recovery_terminal,
                            transaction_id=str(transaction_receipt["transaction_id"]),
                            original=current,
                            restored=restored,
                            binding=evidence.recovery_terminal,
                            parent=evidence.receipt_parent,
                            expected_reservation=Snapshot.from_json(
                                transaction_receipt.get("recovery_terminal"),
                                label="recovery_terminal",
                                require_object_policy=True,
                            ),
                            result_binding_sink=terminal_result_bindings,
                        )
                        if terminal_result_bindings:
                            evidence.recovery_terminal_result = (
                                terminal_result_bindings[0]
                            )
                        verify_restored_terminal(rules, restored)
                        evidence.restored = True
                    except TransactionError as error:
                        retain_stage = True
                        return EXIT_POST_REPLACE_FAILED, {
                            "status": "recovery_required",
                            "post_replace_failure": post_failure,
                            "rollback": rollback_result,
                            "recovery_terminal_failure": {
                                "status": error.status,
                                "message": str(error),
                                **error.details,
                            },
                            "receipt_path": str(receipt),
                            "backup_path": str(backup),
                        }
                retain_stage = not rolled_back
                return EXIT_POST_REPLACE_FAILED, {
                    "status": (
                        "post_replace_failed_rolled_back"
                        if rolled_back
                        else "recovery_required"
                    ),
                    "post_replace_failure": post_failure,
                    "rollback": rollback_result,
                    "recovery_terminal": recovery_terminal_result,
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }

            try:
                evidence.validate()
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            pending_success_status = "applied"
            return 0, {
                "status": "applied",
                "transaction_id": transaction_receipt["transaction_id"],
                "rules_path": str(rules),
                "candidate_sha256": installed_expected.sha256,
                "backup_path": str(backup),
                "receipt_path": str(receipt),
                "validator": (
                    post_validation.to_json() if post_validation is not None else None
                ),
            }
    except BaseException as error:
        if (
            isinstance(error, TransactionError) and error.status == "recovery_required"
        ) or (stage is not None and stage.mutation_uncertain):
            retain_stage = True
        if (
            evidence is not None
            and evidence.receipt is not None
            and isinstance(error, (OSError, TransactionError))
            and not (
                isinstance(error, TransactionError)
                and error.status == "recovery_required"
            )
        ):
            raise TransactionError(
                "recovery_required",
                "durable prepared transaction evidence requires explicit recovery",
                exit_code=EXIT_POST_REPLACE_FAILED,
                details={
                    "reason": (
                        error.status
                        if isinstance(error, TransactionError)
                        else "apply_io_failed"
                    ),
                    "message": str(error),
                    **(error.details if isinstance(error, TransactionError) else {}),
                    "receipt_path": str(receipt),
                    "prepared_candidate_path": str(prepared_recovery_candidate),
                },
            ) from error
        raise
    finally:
        finalize_apply_state()


def apply_transaction(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    cleanup_callbacks: list[Callable[[], list[dict[str, object]]]] = []
    outcome: tuple[int, dict[str, object]] | None = None
    primary_error: BaseException | None = None
    try:
        outcome = _apply_transaction_inner(args, cleanup_callbacks)
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        failures: list[dict[str, object]] = []
        for callback in cleanup_callbacks:
            try:
                failures.extend(callback())
            except BaseException as error:
                failures.append(
                    structured_operation_failure(
                        "close",
                        "apply_evidence_group",
                        error,
                    )
                )
        if failures:
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            elif outcome is not None:
                attach_cleanup_failures_to_payload(outcome[1], failures)
            else:
                raise descriptor_cleanup_error(failures)


def publish_staged_backup_for_recovery(
    *,
    stage: PrivateStage,
    backup: Path,
    staged_backup: Path,
    original: Snapshot,
) -> Snapshot:
    backup_binding = stage.publish_backup(staged_backup, backup)
    persisted = backup_binding.snapshot
    mismatches = property_mismatches(original, persisted)
    if mismatches:
        raise stage._uncertain_mutation(
            operation="recovery_no_replace",
            source=backup_binding,
            destination_binding=None,
            destination=backup,
            source_observation=observe_directory_entry(
                stage.stage_fd,
                staged_backup.name,
            ),
            destination_observation=observe_directory_entry(
                stage.rules_parent_fd,
                backup.name,
                expected=original,
            ),
        )
    return persisted


def recovery_entry_snapshot(path: Path, *, label: str) -> Snapshot | None:
    try:
        _payload, snapshot = read_stable(
            path,
            label=label,
            require_modeled_metadata=True,
        )
    except TransactionError as error:
        if error.status == f"{label}_missing":
            return None
        raise
    return snapshot


def recovery_entry_snapshot_bound(
    path: Path,
    parent: BoundDirectory,
    *,
    label: str,
) -> Snapshot | None:
    try:
        _payload, snapshot = read_bound_regular_child(
            path,
            parent,
            label=label,
        )
    except TransactionError as error:
        if error.status == f"{label}_missing":
            return None
        raise
    return snapshot


def probe_fixed_stage_for_recovery(
    rules_parent: BoundDirectory,
) -> tuple[Snapshot | None, Snapshot | None]:
    validate_bound_directory(rules_parent)
    try:
        stage_stat = os.stat(
            PRIVATE_STAGE_NAME,
            dir_fd=rules_parent.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        validate_bound_directory(rules_parent)
        return None, None
    except OSError as error:
        raise TransactionError(
            "private_stage_unreadable",
            f"cannot inspect the fixed private stage: {error}",
        ) from error
    stage_snapshot = Snapshot.from_stat(stage_stat, b"")
    if (
        not stat.S_ISDIR(stage_stat.st_mode)
        or stage_snapshot.uid != os.geteuid()
        or stage_snapshot.mode != 0o700
    ):
        raise TransactionError(
            "private_stage_invalid",
            "fixed private stage is not an owner-only directory",
        )
    stage_parent = bind_directory(
        rules_parent.path / PRIVATE_STAGE_NAME,
        label="private_stage",
        require_owner_private=True,
        expected=stage_snapshot,
    )
    primary_error: BaseException | None = None
    try:
        entries, entries_exceeded = bounded_directory_entries(stage_parent.fd)
        if entries_exceeded:
            raise TransactionError(
                "private_stage_retained",
                "fixed private stage exceeds the recovery inspection bound",
                details={"entry_count_lower_bound": len(entries)},
            )
        if sorted(entries) not in ([], ["candidate"]):
            raise TransactionError(
                "private_stage_retained",
                "fixed private stage contains unrecognized recovery evidence",
                details={"retained_entries": sorted(entries)},
            )
        candidate = (
            recovery_entry_snapshot_bound(
                stage_parent.path / "candidate",
                stage_parent,
                label="staged_backup",
            )
            if entries
            else None
        )
        validate_bound_directory(stage_parent)
        validate_bound_directory(rules_parent)
        return stage_parent.snapshot, candidate
    except BaseException as error:
        primary_error = error
        raise
    finally:
        failures = close_descriptors_best_effort(
            [("private_stage_parent", stage_parent.fd)]
        )
        if failures:
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            else:
                raise descriptor_cleanup_error(failures)


def recovery_snapshot_role(
    actual: Snapshot | None,
    *,
    original: Snapshot,
    installed: Snapshot,
) -> str:
    if actual is None:
        return "M"
    if not property_mismatches(original, actual):
        return "O"
    if not property_mismatches(installed, actual):
        return "I"
    return "?"


def observe_recovery_primary_state(
    *,
    receipt_schema_version: int,
    rules: Path,
    lock_binding: BoundFile,
    backup: Path,
    prepared_candidate: Path | None,
    rules_parent_expected: Snapshot,
    prepared_parent_expected: Snapshot | None,
    original: Snapshot,
    installed: Snapshot,
    mutation_tracker: RecoveryMutationTracker,
) -> None:
    """Record transaction roles before strict terminal evidence can fail."""

    rules_parent: BoundDirectory | None = None
    prepared_parent: BoundDirectory | None = None
    prepared_binding: BoundFile | None = None
    try:
        rules_parent = bind_directory(
            rules.parent,
            label="rules",
            expected=rules_parent_expected,
        )
        revalidate_lock(lock_binding, rules_parent)
        live_actual = recovery_entry_snapshot_bound(
            rules,
            rules_parent,
            label="live_rules",
        )
        backup_actual = recovery_entry_snapshot_bound(
            backup,
            rules_parent,
            label="backup",
        )
        live_role = recovery_snapshot_role(
            live_actual,
            original=original,
            installed=installed,
        )
        backup_role = recovery_snapshot_role(
            backup_actual,
            original=original,
            installed=installed,
        )
        primary_state_hint = {
            ("O", "M"): "P" if receipt_schema_version == 3 else "Q_or_P",
            ("I", "M"): "X",
            ("I", "O"): "C",
            ("O", "I"): "R",
        }.get((live_role, backup_role))
        primary_observation: dict[str, object] = {
            "transaction_state_hint": primary_state_hint,
            "roles": {
                "live": live_role,
                "backup": backup_role,
                "staged_backup": "unprobed",
                **(
                    {"prepared_candidate": "unprobed"}
                    if receipt_schema_version >= 4
                    else {}
                ),
            },
            "snapshots": {
                "live": live_actual.to_json() if live_actual is not None else None,
                "backup": (
                    backup_actual.to_json() if backup_actual is not None else None
                ),
                "staged_backup": "unprobed",
                **(
                    {"prepared_candidate": "unprobed"}
                    if receipt_schema_version >= 4
                    else {}
                ),
            },
            "terminal_state": "unvalidated",
        }
        mutation_tracker.observe(primary_observation)

        if receipt_schema_version == 3:
            mutation_tracker.observe_prior_mutation(
                (
                    "prior_transaction_state"
                    if primary_state_hint is not None
                    else "possible_prior_transaction_state"
                ),
                state=primary_state_hint or "unknown",
            )
            return

        assert receipt_schema_version >= 4
        assert prepared_candidate is not None
        assert prepared_parent_expected is not None
        if primary_state_hint in ("X", "C", "R"):
            mutation_tracker.observe_prior_mutation(
                "prior_transaction_state",
                state=primary_state_hint,
            )
        try:
            prepared_parent = bind_directory(
                prepared_candidate.parent,
                label="prepared_candidate",
                require_owner_private=True,
                expected=prepared_parent_expected,
            )
            _stage_parent, staged_actual = probe_fixed_stage_for_recovery(rules_parent)
            try:
                prepared_binding = bind_regular_file(
                    prepared_candidate,
                    prepared_parent,
                    label="prepared_candidate",
                )
            except TransactionError as error:
                if error.status != "prepared_candidate_missing":
                    raise
                prepared_actual = None
            else:
                _prepared_payload, prepared_actual = validate_bound_regular_file(
                    prepared_binding,
                    prepared_parent,
                    label="prepared_candidate",
                )
        except BaseException:
            if not mutation_tracker.mutation_started:
                mutation_tracker.defer_possible_prior_mutation(
                    "possible_prior_transaction_state",
                    state=primary_state_hint or "unknown",
                )
            raise

        roles = (
            live_role,
            backup_role,
            recovery_snapshot_role(
                staged_actual,
                original=original,
                installed=installed,
            ),
            recovery_snapshot_role(
                prepared_actual,
                original=original,
                installed=installed,
            ),
        )
        state = {
            ("O", "M", "M", "I"): "Q",
            ("O", "M", "I", "M"): "P",
            ("I", "M", "O", "M"): "X",
            ("I", "O", "M", "M"): "C",
            ("O", "I", "M", "M"): "R",
        }.get(roles)
        observed_state: dict[str, object] = {
            "transaction_state": state,
            "transaction_state_hint": primary_state_hint,
            "roles": {
                "live": roles[0],
                "backup": roles[1],
                "staged_backup": roles[2],
                "prepared_candidate": roles[3],
            },
            "snapshots": {
                "live": live_actual.to_json() if live_actual is not None else None,
                "backup": (
                    backup_actual.to_json() if backup_actual is not None else None
                ),
                "staged_backup": (
                    staged_actual.to_json() if staged_actual is not None else None
                ),
                "prepared_candidate": (
                    prepared_actual.to_json() if prepared_actual is not None else None
                ),
            },
            "terminal_state": "unvalidated",
        }
        mutation_tracker.observe(observed_state)
        if state in ("P", "X", "C", "R"):
            mutation_tracker.observe_prior_mutation(
                "prior_transaction_state",
                state=state,
            )
        elif state != "Q":
            mutation_tracker.defer_possible_prior_mutation(
                "possible_prior_transaction_state",
                state=primary_state_hint or "unknown",
            )
    finally:
        mutation_tracker.record_cleanup_failures(
            close_descriptors_best_effort(
                [
                    *(
                        [("prepared_candidate", prepared_binding.fd)]
                        if prepared_binding is not None
                        else []
                    ),
                    *(
                        [("prepared_candidate_parent", prepared_parent.fd)]
                        if prepared_parent is not None
                        else []
                    ),
                    *(
                        [("rules_parent_probe", rules_parent.fd)]
                        if rules_parent is not None
                        else []
                    ),
                ]
            )
        )


def recover_schema_v3_transaction(
    *,
    rules: Path,
    lock_binding: BoundFile,
    backup: Path,
    staged_backup: Path,
    rules_parent_expected: Snapshot,
    staged_parent_expected: Snapshot,
    original: Snapshot,
    installed: Snapshot,
    terminal_path: Path,
    terminal_expected: Snapshot,
    transaction_id: str,
    terminal_evidence: RecoveryTerminalEvidence,
    validate_controls: Callable[[], None],
    mutation_tracker: RecoveryMutationTracker,
) -> tuple[int, dict[str, object]]:
    rules_parent_binding: BoundDirectory | None = None
    staged_parent_binding: BoundDirectory | None = None
    live_actual: Snapshot | None = None
    backup_actual: Snapshot | None = None
    staged_actual: Snapshot | None = None
    terminal: dict[str, object] | None = None
    primary_state_hint: str | None = None
    try:
        rules_parent_binding = bind_directory(
            rules.parent,
            label="rules",
            expected=rules_parent_expected,
        )
        revalidate_lock(lock_binding, rules_parent_binding)
        live_actual = recovery_entry_snapshot_bound(
            rules,
            rules_parent_binding,
            label="live_rules",
        )
        backup_actual = recovery_entry_snapshot_bound(
            backup,
            rules_parent_binding,
            label="backup",
        )
        live_role = recovery_snapshot_role(
            live_actual,
            original=original,
            installed=installed,
        )
        backup_role = recovery_snapshot_role(
            backup_actual,
            original=original,
            installed=installed,
        )
        primary_state_hint = {
            ("O", "M"): "P",
            ("I", "M"): "X",
            ("I", "O"): "C",
            ("O", "I"): "R",
        }.get((live_role, backup_role))
        terminal = terminal_evidence.validate()
        primary_observation: dict[str, object] = {
            "transaction_state_hint": primary_state_hint,
            "roles": {
                "live": live_role,
                "backup": backup_role,
                "staged_backup": "unprobed",
            },
            "snapshots": {
                "live": live_actual.to_json() if live_actual is not None else None,
                "backup": (
                    backup_actual.to_json() if backup_actual is not None else None
                ),
                "staged_backup": "unprobed",
            },
            "terminal_state": terminal.get("state"),
        }
        mutation_tracker.observe(primary_observation)
        if terminal.get("state") == RECOVERY_TERMINAL_RESTORED:
            mutation_tracker.observe_prior_mutation(
                "terminal_publish",
                state=primary_state_hint or "unknown",
            )
        elif primary_state_hint is not None:
            mutation_tracker.observe_prior_mutation(
                "prior_transaction_state",
                state=primary_state_hint,
            )
        validate_controls()
        staged_parent_binding = bind_directory(
            staged_backup.parent,
            label="private_stage",
            require_owner_private=True,
            expected=staged_parent_expected,
        )
        staged_actual = recovery_entry_snapshot_bound(
            staged_backup,
            staged_parent_binding,
            label="staged_backup",
        )
        validate_bound_directory(rules_parent_binding)
        revalidate_lock(lock_binding, rules_parent_binding)
        validate_controls()
    except TransactionError as error:
        if mutation_tracker.mutation_started:
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "reason": error.status,
                "message": str(error),
                **mutation_tracker.details(state=primary_state_hint),
                **error.details,
            }
        return EXIT_RECOVERY_REFUSED, {
            "status": "recovery_refused",
            "reason": error.status,
            "message": str(error),
            **error.details,
        }
    finally:
        mutation_tracker.record_cleanup_failures(
            close_descriptors_best_effort(
                [
                    *(
                        [("private_stage_parent", staged_parent_binding.fd)]
                        if staged_parent_binding is not None
                        else []
                    ),
                    *(
                        [("rules_parent", rules_parent_binding.fd)]
                        if rules_parent_binding is not None
                        else []
                    ),
                ]
            )
        )
    roles = (
        recovery_snapshot_role(
            live_actual,
            original=original,
            installed=installed,
        ),
        recovery_snapshot_role(
            backup_actual,
            original=original,
            installed=installed,
        ),
        recovery_snapshot_role(
            staged_actual,
            original=original,
            installed=installed,
        ),
    )
    states = {
        ("O", "M", "I"): "P",
        ("I", "M", "O"): "X",
        ("I", "O", "M"): "C",
        ("O", "I", "M"): "R",
    }
    state = states.get(roles)
    observed_state: dict[str, object] = {
        "transaction_state": state,
        "transaction_state_hint": primary_state_hint,
        "roles": {
            "live": roles[0],
            "backup": roles[1],
            "staged_backup": roles[2],
        },
        "snapshots": {
            "live": live_actual.to_json() if live_actual is not None else None,
            "backup": backup_actual.to_json() if backup_actual is not None else None,
            "staged_backup": (
                staged_actual.to_json() if staged_actual is not None else None
            ),
        },
        "terminal_state": terminal.get("state") if terminal is not None else None,
    }
    mutation_tracker.observe(observed_state)
    if state is not None:
        mutation_tracker.observe_prior_mutation(
            "prior_transaction_state",
            state=state,
        )
    if state is None:
        if (
            live_actual is not None
            and content_access_and_object_policy_match(original, live_actual)
            and property_mismatches(original, live_actual)
            and not mutation_tracker.mutation_started
        ):
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": "original_identity_untrusted",
                "mismatched_properties": ["object_identity"],
                "actual_live": live_actual.to_json(),
            }
        classification_code = (
            EXIT_POST_REPLACE_FAILED
            if mutation_tracker.mutation_started
            else EXIT_RECOVERY_REFUSED
        )
        return classification_code, {
            "status": (
                "recovery_required"
                if mutation_tracker.mutation_started
                else "recovery_refused"
            ),
            "reason": "schema_v3_state_unrecognized",
            "observed_roles": {
                "live": roles[0],
                "backup": roles[1],
                "staged_backup": roles[2],
            },
            "actual": {
                "live": live_actual.to_json() if live_actual is not None else None,
                "backup": (
                    backup_actual.to_json() if backup_actual is not None else None
                ),
                "staged_backup": (
                    staged_actual.to_json() if staged_actual is not None else None
                ),
            },
            **(
                mutation_tracker.details(
                    state=primary_state_hint,
                    observed=observed_state,
                )
                if mutation_tracker.mutation_started
                else {}
            ),
        }
    assert terminal is not None
    if terminal.get("state") == RECOVERY_TERMINAL_RESTORED:
        if state != "R" or live_actual is None:
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "reason": "recovery_terminal_state_mismatch",
                "transaction_state": state,
                **mutation_tracker.details(state=state),
            }
        terminal_restored = Snapshot.from_json(
            terminal.get("restored"),
            label="recovery_terminal.restored",
            require_object_policy=True,
        )
        terminal_mismatches = property_mismatches(
            terminal_restored,
            live_actual,
        )
        if terminal_mismatches or property_mismatches(original, live_actual):
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "reason": "recovery_terminal_live_mismatch",
                "mismatched_properties": terminal_mismatches,
                "actual_live": live_actual.to_json(),
                **mutation_tracker.details(state=state),
            }
        try:
            terminal_stage = PrivateStage(
                rules.parent,
                rules_parent_expected=rules_parent_expected,
                recovery_stage_expected=staged_parent_expected,
            )
        except (OSError, TransactionError) as error:
            error_status = (
                error.status
                if isinstance(error, TransactionError)
                else "recovery_io_failed"
            )
            error_details = error.details if isinstance(error, TransactionError) else {}
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "transaction_state": state,
                "reason": error_status,
                "message": str(error),
                **mutation_tracker.details(state=state),
                **error_details,
            }
        terminal_cleanup_warnings = terminal_stage.cleanup(retain=False)
        terminal_descriptor_failures = private_stage_descriptor_cleanup_failures(
            terminal_cleanup_warnings
        )
        mutation_tracker.record_cleanup_failures(terminal_descriptor_failures)
        if terminal_cleanup_warnings:
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "transaction_state": state,
                "operation_status": "already_original",
                "reason": (
                    PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON
                    if terminal_descriptor_failures
                    else "stage_cleanup_refused"
                ),
                **(
                    {"cleanup_reason": (PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON)}
                    if terminal_descriptor_failures
                    else {}
                ),
                "cleanup_refusals": terminal_cleanup_warnings,
                **mutation_tracker.details(state=state),
            }
        return 0, {
            "status": "already_original",
            "rules_path": str(rules),
            "live": live_actual.to_json(),
            "identity_evidence": "recovery_terminal",
        }
    if terminal.get("state") != RECOVERY_TERMINAL_RESERVED:
        return EXIT_POST_REPLACE_FAILED, {
            "status": "recovery_required",
            "reason": "recovery_terminal_state_invalid",
            **mutation_tracker.details(state=state),
        }

    stage_candidate_expected = (
        installed if state == "P" else original if state == "X" else None
    )
    stage: PrivateStage | None = None
    retain_stage = False
    pending_success = False
    rollback_result: dict[str, object] | None = None
    try:
        stage = PrivateStage(
            rules.parent,
            rules_parent_expected=rules_parent_expected,
            recovery_stage_expected=staged_parent_expected,
            recovery_candidate_expected=stage_candidate_expected,
        )
        revalidate_lock(lock_binding, stage.rules_parent_binding)
        validate_controls()
        if state == "P":
            assert staged_actual is not None
            mutation_tracker.enter("P_to_X", state="P")
            stage.move_to(
                staged_backup,
                rules,
                original,
                pre_exchange_revalidate=lambda: (
                    revalidate_lock(lock_binding, stage.rules_parent_binding),
                    validate_controls(),
                ),
            )
            state = "X"
            os.fsync(stage.stage_fd)
            os.fsync(stage.rules_parent_fd)
            mutation_tracker.complete("P_to_X", state=state)
            validate_controls()
        if state == "X":
            validate_controls()
            mutation_tracker.enter("X_to_C", state="X")
            publish_staged_backup_for_recovery(
                stage=stage,
                backup=backup,
                staged_backup=staged_backup,
                original=original,
            )
            state = "C"
            os.fsync(stage.stage_fd)
            os.fsync(stage.rules_parent_fd)
            mutation_tracker.complete("X_to_C", state=state)
            validate_controls()
        if state == "C":
            validate_controls()
            mutation_tracker.enter("C_to_R", state="C")
            rolled_back, rollback_result = rollback(
                stage=stage,
                rules=rules,
                lock_binding=lock_binding,
                backup=backup,
                original=original,
                installed=installed,
                backup_expected=original,
                pre_exchange_revalidate=validate_controls,
            )
            if not rolled_back:
                recovery_required = (
                    mutation_tracker.mutation_started
                    or rollback_result.get("rollback_status") == "recovery_required"
                    or stage.mutation_uncertain
                )
                retain_stage = recovery_required
                return (
                    EXIT_POST_REPLACE_FAILED
                    if recovery_required
                    else EXIT_RECOVERY_REFUSED
                ), {
                    "status": (
                        "recovery_required" if recovery_required else "recovery_refused"
                    ),
                    "transaction_state": "C",
                    "rollback": rollback_result,
                    **mutation_tracker.details(state="C"),
                }
            os.fsync(stage.stage_fd)
            os.fsync(stage.rules_parent_fd)
            state = "R"
            mutation_tracker.complete("C_to_R", state=state)
            validate_controls()

        _restored_bytes, restored = read_stable(
            rules,
            label="live_rules",
            require_modeled_metadata=True,
        )
        _displaced_bytes, displaced = read_stable(
            backup,
            label="backup",
            require_modeled_metadata=True,
        )
        if property_mismatches(original, restored) or property_mismatches(
            installed,
            displaced,
        ):
            retain_stage = True
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "reason": "schema_v3_restored_state_unverified",
                "actual_live": restored.to_json(),
                "actual_backup": displaced.to_json(),
            }
        validate_controls()
        mutation_tracker.enter("terminal_publish", state="R")
        terminal_result = record_recovery_terminal(
            terminal_path,
            transaction_id=transaction_id,
            original=original,
            restored=restored,
            expected_reservation=terminal_expected,
            evidence=terminal_evidence,
        )
        mutation_tracker.complete("terminal_publish", state="R")
        validate_controls()
        verify_restored_terminal(rules, restored)
        pending_success = True
        return 0, {
            "status": "recovered",
            "rules_path": str(rules),
            "rollback": rollback_result,
            "recovery_terminal": terminal_result,
        }
    except (OSError, TransactionError) as error:
        error_status = (
            error.status
            if isinstance(error, TransactionError)
            else "recovery_io_failed"
        )
        error_details = error.details if isinstance(error, TransactionError) else {}
        retain_stage = error_status == "recovery_required" or (
            stage is not None and stage.mutation_uncertain
        )
        if (
            mutation_tracker.mutation_started
            or state in ("X", "C", "R")
            or retain_stage
        ):
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "transaction_state": state,
                "reason": error_status,
                "message": str(error),
                **mutation_tracker.details(state=state),
                **error_details,
            }
        return EXIT_RECOVERY_REFUSED, {
            "status": "recovery_refused",
            "transaction_state": state,
            "reason": error_status,
            "message": str(error),
            **error_details,
        }
    finally:
        if stage is not None:
            warnings = stage.cleanup(retain=retain_stage)
            if warnings:
                print(
                    json.dumps(
                        {"status": "cleanup_warning", "warnings": warnings},
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )
            cleanup_refusals = [
                warning
                for warning in warnings
                if warning.get("status") == "stage_cleanup_refused"
            ]
            descriptor_failures = private_stage_descriptor_cleanup_failures(warnings)
            mutation_tracker.record_cleanup_failures(descriptor_failures)
            if pending_success and descriptor_failures:
                raise TransactionError(
                    "recovery_required",
                    (
                        "cannot report recovered while private-stage "
                        "descriptor cleanup is uncertain"
                    ),
                    exit_code=EXIT_POST_REPLACE_FAILED,
                    details={
                        "operation_status": "recovered",
                        "reason": PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
                        "cleanup_reason": (PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON),
                    },
                )
            if pending_success and cleanup_refusals:
                raise TransactionError(
                    "recovery_required",
                    "cannot report recovered while fixed stage cleanup is unverified",
                    exit_code=EXIT_POST_REPLACE_FAILED,
                    details={"cleanup_refusals": cleanup_refusals},
                )


def recover_schema_v4_transaction(
    *,
    rules: Path,
    lock_binding: BoundFile,
    backup: Path,
    staged_backup: Path,
    prepared_candidate: Path,
    rules_parent_expected: Snapshot,
    prepared_parent_expected: Snapshot,
    original: Snapshot,
    installed: Snapshot,
    terminal_path: Path,
    terminal_expected: Snapshot,
    transaction_id: str,
    terminal_evidence: RecoveryTerminalEvidence,
    validate_controls: Callable[[], None],
    mutation_tracker: RecoveryMutationTracker,
) -> tuple[int, dict[str, object]]:
    rules_parent: BoundDirectory | None = None
    prepared_parent: BoundDirectory | None = None
    prepared_binding: BoundFile | None = None
    live_actual: Snapshot | None = None
    backup_actual: Snapshot | None = None
    staged_actual: Snapshot | None = None
    prepared_actual: Snapshot | None = None
    terminal: dict[str, object] | None = None
    primary_state_hint: str | None = None
    try:
        rules_parent = bind_directory(
            rules.parent,
            label="rules",
            expected=rules_parent_expected,
        )
        revalidate_lock(lock_binding, rules_parent)
        live_actual = recovery_entry_snapshot_bound(
            rules,
            rules_parent,
            label="live_rules",
        )
        backup_actual = recovery_entry_snapshot_bound(
            backup,
            rules_parent,
            label="backup",
        )
        live_role = recovery_snapshot_role(
            live_actual,
            original=original,
            installed=installed,
        )
        backup_role = recovery_snapshot_role(
            backup_actual,
            original=original,
            installed=installed,
        )
        primary_state_hint = {
            ("O", "M"): "Q_or_P",
            ("I", "M"): "X",
            ("I", "O"): "C",
            ("O", "I"): "R",
        }.get((live_role, backup_role))
        terminal = terminal_evidence.validate()
        primary_observation: dict[str, object] = {
            "transaction_state_hint": primary_state_hint,
            "roles": {
                "live": live_role,
                "backup": backup_role,
                "staged_backup": "unprobed",
                "prepared_candidate": "unprobed",
            },
            "snapshots": {
                "live": live_actual.to_json() if live_actual is not None else None,
                "backup": (
                    backup_actual.to_json() if backup_actual is not None else None
                ),
                "staged_backup": "unprobed",
                "prepared_candidate": "unprobed",
            },
            "terminal_state": terminal.get("state"),
        }
        mutation_tracker.observe(primary_observation)
        if terminal.get("state") == RECOVERY_TERMINAL_RESTORED:
            mutation_tracker.observe_prior_mutation(
                "terminal_publish",
                state=primary_state_hint or "unknown",
            )
        elif primary_state_hint in ("X", "C", "R"):
            mutation_tracker.observe_prior_mutation(
                "prior_transaction_state",
                state=primary_state_hint,
            )
        validate_controls()
        prepared_parent = bind_directory(
            prepared_candidate.parent,
            label="prepared_candidate",
            require_owner_private=True,
            expected=prepared_parent_expected,
        )
        stage_parent_actual, staged_actual = probe_fixed_stage_for_recovery(
            rules_parent
        )
        try:
            prepared_binding = bind_regular_file(
                prepared_candidate,
                prepared_parent,
                label="prepared_candidate",
            )
        except TransactionError as error:
            if error.status == "prepared_candidate_missing":
                prepared_actual = None
            else:
                raise
        else:
            _prepared_bytes, prepared_actual = validate_bound_regular_file(
                prepared_binding,
                prepared_parent,
                label="prepared_candidate",
            )

        roles = (
            recovery_snapshot_role(
                live_actual,
                original=original,
                installed=installed,
            ),
            recovery_snapshot_role(
                backup_actual,
                original=original,
                installed=installed,
            ),
            recovery_snapshot_role(
                staged_actual,
                original=original,
                installed=installed,
            ),
            recovery_snapshot_role(
                prepared_actual,
                original=original,
                installed=installed,
            ),
        )
        states = {
            ("O", "M", "M", "I"): "Q",
            ("O", "M", "I", "M"): "P",
            ("I", "M", "O", "M"): "X",
            ("I", "O", "M", "M"): "C",
            ("O", "I", "M", "M"): "R",
        }
        state = states.get(roles)
        observed_state: dict[str, object] = {
            "transaction_state": state,
            "transaction_state_hint": primary_state_hint,
            "roles": {
                "live": roles[0],
                "backup": roles[1],
                "staged_backup": roles[2],
                "prepared_candidate": roles[3],
            },
            "snapshots": {
                "live": live_actual.to_json() if live_actual is not None else None,
                "backup": (
                    backup_actual.to_json() if backup_actual is not None else None
                ),
                "staged_backup": (
                    staged_actual.to_json() if staged_actual is not None else None
                ),
                "prepared_candidate": (
                    prepared_actual.to_json() if prepared_actual is not None else None
                ),
            },
            "terminal_state": terminal.get("state") if terminal is not None else None,
        }
        mutation_tracker.observe(observed_state)
        if state in ("P", "X", "C", "R"):
            mutation_tracker.observe_prior_mutation(
                "prior_transaction_state",
                state=state,
            )
        elif state is None and primary_state_hint == "Q_or_P" and roles[2] != "M":
            # With original live, no backup, and a non-missing/unknown stage
            # candidate, the observation is ambiguous between a damaged P
            # retry and unrelated drift. It is not proof of untouched Q.
            mutation_tracker.observe_prior_mutation(
                "possible_prior_transaction_state",
                state="P",
            )
        if state is None:
            if (
                live_actual is not None
                and content_access_and_object_policy_match(
                    original,
                    live_actual,
                )
                and property_mismatches(original, live_actual)
                and not mutation_tracker.mutation_started
            ):
                return EXIT_RECOVERY_REFUSED, {
                    "status": "recovery_refused",
                    "reason": "original_identity_untrusted",
                    "mismatched_properties": ["object_identity"],
                    "actual_live": live_actual.to_json(),
                }
            return (
                EXIT_POST_REPLACE_FAILED
                if mutation_tracker.mutation_started
                else EXIT_RECOVERY_REFUSED
            ), {
                "status": (
                    "recovery_required"
                    if mutation_tracker.mutation_started
                    else "recovery_refused"
                ),
                "reason": "schema_v4_state_unrecognized",
                "observed_roles": {
                    "live": roles[0],
                    "backup": roles[1],
                    "staged_backup": roles[2],
                    "prepared_candidate": roles[3],
                },
                "actual": {
                    "live": (
                        live_actual.to_json() if live_actual is not None else None
                    ),
                    "backup": (
                        backup_actual.to_json() if backup_actual is not None else None
                    ),
                    "staged_backup": (
                        staged_actual.to_json() if staged_actual is not None else None
                    ),
                    "prepared_candidate": (
                        prepared_actual.to_json()
                        if prepared_actual is not None
                        else None
                    ),
                },
                **(
                    mutation_tracker.details(
                        state=primary_state_hint,
                        observed=observed_state,
                    )
                    if mutation_tracker.mutation_started
                    else {}
                ),
            }

        if state != "Q":
            if stage_parent_actual is None:
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "reason": "schema_v4_stage_missing",
                    "transaction_state": state,
                    **mutation_tracker.details(state=state),
                }
            revalidate_lock(lock_binding, rules_parent)
            validate_controls()
            result = recover_schema_v3_transaction(
                rules=rules,
                lock_binding=lock_binding,
                backup=backup,
                staged_backup=staged_backup,
                rules_parent_expected=rules_parent_expected,
                staged_parent_expected=stage_parent_actual,
                original=original,
                installed=installed,
                terminal_path=terminal_path,
                terminal_expected=terminal_expected,
                transaction_id=transaction_id,
                terminal_evidence=terminal_evidence,
                validate_controls=validate_controls,
                mutation_tracker=mutation_tracker,
            )
            revalidate_lock(lock_binding, rules_parent)
            validate_bound_directory(prepared_parent)
            validate_controls()
            return result

        assert live_actual is not None
        assert prepared_binding is not None
        assert terminal is not None
        terminal_result: dict[str, object]
        if terminal.get("state") == RECOVERY_TERMINAL_RESTORED:
            terminal_restored = Snapshot.from_json(
                terminal.get("restored"),
                label="recovery_terminal.restored",
                require_object_policy=True,
            )
            terminal_live_mismatches = property_mismatches(
                terminal_restored,
                live_actual,
            )
            if terminal_live_mismatches or property_mismatches(
                original,
                live_actual,
            ):
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "reason": "recovery_terminal_live_mismatch",
                    "mismatched_properties": terminal_live_mismatches,
                    "actual_live": live_actual.to_json(),
                    **mutation_tracker.details(state="Q"),
                }
            terminal_result = terminal
            result_status = "already_original"
        elif terminal.get("state") == RECOVERY_TERMINAL_RESERVED:
            validate_controls()
            mutation_tracker.enter("terminal_publish", state="Q")
            terminal_result = record_recovery_terminal(
                terminal_path,
                transaction_id=transaction_id,
                original=original,
                restored=live_actual,
                expected_reservation=terminal_expected,
                evidence=terminal_evidence,
            )
            mutation_tracker.complete("terminal_publish", state="Q")
            validate_controls()
            result_status = "recovered"
        else:
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "reason": "recovery_terminal_state_invalid",
                **mutation_tracker.details(state="Q"),
            }

        final_live = recovery_entry_snapshot_bound(
            rules,
            rules_parent,
            label="live_rules",
        )
        final_prepared_payload, final_prepared = validate_bound_regular_file(
            prepared_binding,
            prepared_parent,
            label="prepared_candidate",
        )
        final_stage_parent, final_staged = probe_fixed_stage_for_recovery(rules_parent)
        if (
            final_live is None
            or property_mismatches(original, final_live)
            or property_mismatches(installed, final_prepared)
            or final_staged is not None
            or (
                stage_parent_actual is not None
                and (
                    final_stage_parent is None
                    or directory_property_mismatches(
                        stage_parent_actual,
                        os.stat(
                            PRIVATE_STAGE_NAME,
                            dir_fd=rules_parent.fd,
                            follow_symlinks=False,
                        ),
                    )
                )
            )
            or len(final_prepared_payload) != installed.size
        ):
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "transaction_state": "Q",
                "reason": "schema_v4_prepared_state_changed",
                **mutation_tracker.details(state="Q"),
            }
        revalidate_lock(lock_binding, rules_parent)
        validate_bound_directory(prepared_parent)
        validate_controls()
        return 0, {
            "status": result_status,
            "transaction_state": "Q",
            "rules_path": str(rules),
            "live": final_live.to_json(),
            "recovery_terminal": terminal_result,
            "prepared_candidate_path": str(prepared_candidate),
        }
    except (OSError, TransactionError) as error:
        error_status = (
            error.status
            if isinstance(error, TransactionError)
            else "recovery_io_failed"
        )
        error_details = error.details if isinstance(error, TransactionError) else {}
        stage_recovery_statuses = {
            "private_stage_retained",
            "private_stage_invalid",
            "private_stage_unreadable",
            "private_stage_changed",
            "stage_cleanup_refused",
        }
        if (
            mutation_tracker.mutation_started
            or error_status == "recovery_required"
            or error_status in stage_recovery_statuses
        ):
            live_role = (
                recovery_snapshot_role(
                    live_actual,
                    original=original,
                    installed=installed,
                )
                if "live_actual" in locals()
                else "?"
            )
            backup_role = (
                recovery_snapshot_role(
                    backup_actual,
                    original=original,
                    installed=installed,
                )
                if "backup_actual" in locals()
                else "?"
            )
            state_hint = {
                ("O", "I"): "R",
                ("I", "O"): "C",
                ("I", "M"): "X",
                ("O", "M"): "Q",
            }.get((live_role, backup_role), "Q")
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "transaction_state": state_hint,
                "reason": error_status,
                "message": str(error),
                **mutation_tracker.details(state=state_hint),
                **error_details,
            }
        return EXIT_RECOVERY_REFUSED, {
            "status": "recovery_refused",
            "reason": error_status,
            "message": str(error),
            **error_details,
        }
    finally:
        mutation_tracker.record_cleanup_failures(
            close_descriptors_best_effort(
                [
                    *(
                        [("prepared_candidate", prepared_binding.fd)]
                        if prepared_binding is not None
                        else []
                    ),
                    *(
                        [("prepared_candidate_parent", prepared_parent.fd)]
                        if prepared_parent is not None
                        else []
                    ),
                    *(
                        [("rules_parent", rules_parent.fd)]
                        if rules_parent is not None
                        else []
                    ),
                ]
            )
        )


def recover_legacy_transaction(
    *,
    rules: Path,
    lock_binding: BoundFile,
    backup: Path,
    receipt_parent_path: Path,
    receipt_parent_expected: Snapshot,
    rules_parent_expected: Snapshot,
    original: Snapshot,
    installed: Snapshot,
    backup_expected: Snapshot,
    terminal_path: Path | None,
    terminal_expected: Snapshot | None,
    transaction_id: object,
    mutation_tracker: RecoveryMutationTracker,
) -> tuple[int, dict[str, object]]:
    rules_parent: BoundDirectory | None = None
    receipt_parent: BoundDirectory | None = None
    terminal_binding: BoundFile | None = None
    stage: PrivateStage | None = None
    try:
        rules_parent = bind_directory(
            rules.parent,
            label="rules",
            expected=rules_parent_expected,
        )
        receipt_parent = bind_directory(
            receipt_parent_path,
            label="receipt",
            require_owner_private=True,
            expected=receipt_parent_expected,
        )
        revalidate_lock(lock_binding, rules_parent)
        try:
            _live_bytes, live = read_bound_regular_child(
                rules,
                rules_parent,
                label="live_rules",
            )
        except TransactionError as error:
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": error.status,
                "message": str(error),
            }
        if property_mismatches(original, live) == []:
            validate_existing_fixed_stage_is_empty(
                rules.parent,
                rules_parent_expected=rules_parent_expected,
            )
            revalidate_lock(lock_binding, rules_parent)
            return 0, {
                "status": "already_original",
                "rules_path": str(rules),
                "live": live.to_json(),
                "identity_evidence": "receipt_original_identity",
            }

        terminal_was_missing = False
        terminal: dict[str, object] | None = None
        if terminal_path is not None:
            try:
                terminal_binding = bind_regular_file(
                    terminal_path,
                    receipt_parent,
                    label="recovery_terminal",
                    max_bytes=MAX_RECEIPT_BYTES,
                    writable=True,
                )
                terminal_bytes, terminal_actual = validate_bound_regular_file(
                    terminal_binding,
                    receipt_parent,
                    label="recovery_terminal",
                    max_bytes=MAX_RECEIPT_BYTES,
                )
                terminal = decode_recovery_terminal(terminal_bytes)
            except TransactionError as error:
                if error.status == "recovery_terminal_missing":
                    if terminal_expected is not None:
                        return EXIT_RECOVERY_REFUSED, {
                            "status": "recovery_refused",
                            "reason": "recovery_terminal_missing",
                        }
                    terminal_was_missing = True
                else:
                    return EXIT_RECOVERY_REFUSED, {
                        "status": "recovery_refused",
                        "reason": error.status,
                        "message": str(error),
                        **error.details,
                    }
            if terminal is not None:
                if terminal_expected is not None:
                    if terminal.get("state") == RECOVERY_TERMINAL_RESERVED:
                        terminal_binding_mismatches = property_mismatches(
                            terminal_expected,
                            terminal_actual,
                        )
                    else:
                        terminal_binding_mismatches = (
                            identity_access_and_object_policy_mismatches(
                                terminal_expected,
                                terminal_actual,
                            )
                        )
                    if terminal_binding_mismatches:
                        return EXIT_RECOVERY_REFUSED, {
                            "status": "recovery_refused",
                            "reason": "recovery_terminal_binding_changed",
                            "mismatched_properties": terminal_binding_mismatches,
                        }
                if terminal.get("transaction_id") != transaction_id:
                    return EXIT_RECOVERY_REFUSED, {
                        "status": "recovery_refused",
                        "reason": "recovery_terminal_transaction_mismatch",
                    }
                if terminal.get("state") == RECOVERY_TERMINAL_RESTORED:
                    terminal_restored = Snapshot.from_json(
                        terminal.get("restored"),
                        label="recovery_terminal.restored",
                        require_object_policy=True,
                    )
                    terminal_mismatches = property_mismatches(
                        terminal_restored,
                        live,
                    )
                    if (
                        isinstance(transaction_id, str)
                        and not terminal_mismatches
                        and content_access_and_object_policy_match(
                            original,
                            live,
                        )
                    ):
                        validate_existing_fixed_stage_is_empty(
                            rules.parent,
                            rules_parent_expected=rules_parent_expected,
                        )
                        revalidate_lock(lock_binding, rules_parent)
                        return 0, {
                            "status": "already_original",
                            "rules_path": str(rules),
                            "live": live.to_json(),
                            "identity_evidence": "recovery_terminal",
                        }
                    return EXIT_RECOVERY_REFUSED, {
                        "status": "recovery_refused",
                        "reason": "recovery_terminal_live_mismatch",
                        "mismatched_properties": terminal_mismatches,
                        "actual_live": live.to_json(),
                    }

        if content_access_and_object_policy_match(original, live):
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": "original_identity_untrusted",
                "mismatched_properties": ["object_identity"],
                "actual_live": live.to_json(),
            }
        live_mismatches = property_mismatches(installed, live)
        if live_mismatches:
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": "live_no_longer_installed",
                "mismatched_properties": live_mismatches,
                "actual_live": live.to_json(),
            }
        backup_actual = recovery_entry_snapshot_bound(
            backup,
            rules_parent,
            label="backup",
        )
        if backup_actual is None:
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": "backup_missing",
            }
        backup_mismatches = property_mismatches(
            backup_expected,
            backup_actual,
        )
        if backup_mismatches:
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": "backup_changed",
                "mismatched_properties": backup_mismatches,
            }

        stage = PrivateStage(
            rules.parent,
            rules_parent_expected=rules_parent_expected,
        )
        retain_stage = False
        pending_success_status: str | None = None
        try:
            rolled_back, rollback_result = rollback(
                stage=stage,
                rules=rules,
                lock_binding=lock_binding,
                backup=backup,
                original=original,
                installed=installed,
                backup_expected=backup_expected,
                mutation_attempt=lambda: mutation_tracker.enter(
                    "legacy_rollback_exchange",
                    state="legacy_installed",
                ),
                mutation_complete=lambda: mutation_tracker.complete(
                    "legacy_rollback_exchange",
                    state="legacy_original",
                ),
            )
            if not rolled_back:
                if rollback_result.get("rollback_status") == "recovery_required":
                    retain_stage = True
                    return EXIT_POST_REPLACE_FAILED, {
                        "status": "recovery_required",
                        "rollback": rollback_result,
                        **mutation_tracker.details(state="legacy_unknown"),
                    }
                return EXIT_RECOVERY_REFUSED, {
                    "status": "recovery_refused",
                    "rollback": rollback_result,
                }
            restored = Snapshot.from_json(
                rollback_result.get("restored"),
                label="rollback.restored",
                require_object_policy=True,
            )
            if terminal_path is None:
                pending_success_status = "recovered"
                revalidate_lock(lock_binding, rules_parent)
                return 0, {
                    "status": "recovered",
                    "rules_path": str(rules),
                    "rollback": rollback_result,
                    "identity_evidence": "current-run-only-legacy-receipt",
                }
            try:
                terminal_result = record_recovery_terminal(
                    terminal_path,
                    transaction_id=str(transaction_id),
                    original=original,
                    restored=restored,
                    binding=terminal_binding,
                    parent=receipt_parent,
                    allow_unreserved_legacy=terminal_was_missing,
                    expected_reservation=terminal_expected,
                )
                _restored_bytes, restored_live = read_bound_regular_child(
                    rules,
                    rules_parent,
                    label="live_rules",
                )
                if property_mismatches(restored, restored_live):
                    raise TransactionError(
                        "recovery_terminal_live_mismatch",
                        "restored live rules changed after terminal publication",
                    )
            except TransactionError as error:
                retain_stage = True
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "rollback": rollback_result,
                    **mutation_tracker.details(state="legacy_original"),
                    "recovery_terminal_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                }
            pending_success_status = "recovered"
            revalidate_lock(lock_binding, rules_parent)
            return 0, {
                "status": "recovered",
                "rules_path": str(rules),
                "rollback": rollback_result,
                "recovery_terminal": terminal_result,
            }
        except BaseException as error:
            if (
                isinstance(error, TransactionError)
                and error.status == "recovery_required"
            ) or stage.mutation_uncertain:
                retain_stage = True
            raise
        finally:
            warnings = stage.cleanup(retain=retain_stage)
            if warnings:
                print(
                    json.dumps(
                        {"status": "cleanup_warning", "warnings": warnings},
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )
            cleanup_refusals = [
                warning
                for warning in warnings
                if warning.get("status") == "stage_cleanup_refused"
            ]
            descriptor_failures = private_stage_descriptor_cleanup_failures(warnings)
            mutation_tracker.record_cleanup_failures(descriptor_failures)
            if pending_success_status is not None and descriptor_failures:
                raise TransactionError(
                    "recovery_required",
                    (
                        "cannot report success while private-stage descriptor "
                        "cleanup is uncertain"
                    ),
                    exit_code=EXIT_POST_REPLACE_FAILED,
                    details={
                        "operation_status": pending_success_status,
                        "reason": PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
                        "cleanup_reason": (PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON),
                    },
                )
            if pending_success_status is not None and cleanup_refusals:
                raise TransactionError(
                    "recovery_required",
                    ("cannot report success because fixed stage cleanup was refused"),
                    exit_code=EXIT_POST_REPLACE_FAILED,
                    details={
                        "operation_status": pending_success_status,
                        "cleanup_refusals": cleanup_refusals,
                    },
                )
            try:
                revalidate_lock(lock_binding, rules_parent)
                validate_bound_directory(receipt_parent)
            except TransactionError as error:
                if pending_success_status is not None:
                    raise TransactionError(
                        "recovery_required",
                        "bound recovery evidence changed before lock release",
                        exit_code=EXIT_POST_REPLACE_FAILED,
                        details={
                            "reason": error.status,
                            "message": str(error),
                            **error.details,
                        },
                    ) from error
                raise
    except TransactionError as error:
        if error.status == "recovery_required":
            cleanup_refusals = error.details.get("cleanup_refusals")
            cleanup_reason = (
                cleanup_refusals[0].get("reason")
                if isinstance(cleanup_refusals, list)
                and cleanup_refusals
                and isinstance(cleanup_refusals[0], dict)
                else None
            )
            return EXIT_POST_REPLACE_FAILED, {
                "status": "recovery_required",
                "reason": (
                    error.details.get("stage_status")
                    or error.details.get("reason")
                    or cleanup_reason
                    or error.status
                ),
                "message": str(error),
                **(
                    mutation_tracker.details()
                    if mutation_tracker.mutation_started
                    else {}
                ),
                **error.details,
            }
        return EXIT_RECOVERY_REFUSED, {
            "status": "recovery_refused",
            "reason": error.status,
            "message": str(error),
            **error.details,
        }
    finally:
        final_error: BaseException | None = None
        if rules_parent is not None and receipt_parent is not None:
            try:
                revalidate_lock(lock_binding, rules_parent)
                validate_bound_directory(receipt_parent)
            except BaseException as error:
                final_error = error
        mutation_tracker.record_cleanup_failures(
            close_descriptors_best_effort(
                [
                    *(
                        [("recovery_terminal_reservation", terminal_binding.fd)]
                        if terminal_binding is not None
                        else []
                    ),
                    *(
                        [("receipt_parent", receipt_parent.fd)]
                        if receipt_parent is not None
                        else []
                    ),
                    *(
                        [("rules_parent", rules_parent.fd)]
                        if rules_parent is not None
                        else []
                    ),
                ]
            )
        )
        if final_error is not None:
            raise final_error


def _recover_transaction_bound(
    args: argparse.Namespace,
    *,
    receipt_path: Path,
    receipt_evidence: RecoveryReceiptEvidence,
) -> tuple[int, dict[str, object]]:
    receipt = receipt_evidence.value
    receipt_parent_expected = receipt_evidence.parent.snapshot
    receipt_schema_version = receipt["schema_version"]
    assert isinstance(receipt_schema_version, int)
    require_object_policy = receipt_schema_version >= 2
    required_paths = ("rules_path", "lock_path", "backup_path")
    if any(not isinstance(receipt.get(name), str) for name in required_paths):
        raise TransactionError(
            "receipt_invalid",
            "receipt is missing a transaction path",
        )
    rules = codex_rules_path()
    recorded_rules = resolved_leaf(str(receipt["rules_path"]), label="rules")
    lock = resolved_leaf(str(receipt["lock_path"]), label="lock")
    backup = resolved_leaf(str(receipt["backup_path"]), label="backup")
    terminal_raw = receipt.get("recovery_terminal_path")
    transaction_id = receipt.get("transaction_id")
    if terminal_raw is not None and (
        not isinstance(transaction_id, str) or len(transaction_id) != 32
    ):
        raise TransactionError(
            "receipt_invalid",
            "receipt transaction_id is invalid",
        )
    terminal_path: Path | None = None
    if terminal_raw is not None:
        if not isinstance(terminal_raw, str):
            raise TransactionError(
                "receipt_invalid",
                "receipt recovery_terminal_path is invalid",
            )
        terminal_path = resolved_leaf(
            terminal_raw,
            label="recovery_terminal",
        )
        if terminal_path != recovery_terminal_path(receipt_path):
            raise TransactionError(
                "receipt_invalid",
                "receipt recovery terminal path is not the bound sibling path",
            )
    expected_lock = rules.parent / ".default.rules.apply.lock"
    if (
        recorded_rules != rules
        or lock != expected_lock
        or backup.parent != rules.parent
        or not backup.name.startswith("default.rules.bak-")
    ):
        raise TransactionError(
            "receipt_invalid",
            "receipt paths do not match the current CODEX_HOME rules target",
        )
    parent_expected = Snapshot.from_json(
        receipt.get("rules_parent"),
        label="rules_parent",
        require_object_policy=require_object_policy,
        legacy_historical_object_policy=receipt_schema_version == 1,
    )
    original = Snapshot.from_json(
        receipt.get("original"),
        label="original",
        require_object_policy=require_object_policy,
        legacy_historical_object_policy=receipt_schema_version == 1,
    )
    installed = Snapshot.from_json(
        receipt.get("installed"),
        label="installed",
        require_object_policy=require_object_policy,
        legacy_historical_object_policy=receipt_schema_version == 1,
    )
    backup_expected = Snapshot.from_json(
        receipt.get("backup"),
        label="backup",
        require_object_policy=require_object_policy,
        legacy_historical_object_policy=receipt_schema_version == 1,
    )
    staged_backup: Path | None = None
    staged_parent_expected: Snapshot | None = None
    prepared_candidate: Path | None = None
    prepared_parent_expected: Snapshot | None = None
    if receipt_schema_version >= 3:
        backup_receipt_mismatches = property_mismatches(
            original,
            backup_expected,
        )
        if backup_receipt_mismatches:
            raise TransactionError(
                "receipt_invalid",
                "schema-v3+ backup snapshot must exactly match original",
                details={
                    "mismatched_properties": backup_receipt_mismatches,
                },
            )
        staged_backup_raw = receipt.get("staged_backup_path")
        if not isinstance(staged_backup_raw, str):
            raise TransactionError(
                "receipt_invalid",
                "schema-v3+ receipt is missing staged_backup_path",
            )
        staged_backup = Path(staged_backup_raw)
        expected_staged_backup = rules.parent / PRIVATE_STAGE_NAME / "candidate"
        if not staged_backup.is_absolute() or staged_backup != expected_staged_backup:
            raise TransactionError(
                "receipt_invalid",
                "staged backup path is not the fixed transaction-stage candidate",
            )
        if receipt_schema_version == 3:
            staged_parent_expected = Snapshot.from_json(
                receipt.get("staged_backup_parent"),
                label="staged_backup_parent",
                require_object_policy=True,
            )
        elif receipt.get("staged_backup_parent") is not None:
            raise TransactionError(
                "receipt_invalid",
                "schema-v4 staged_backup_parent must be null before stage creation",
            )
    if receipt_schema_version >= 4:
        prepared_candidate_raw = receipt.get("prepared_candidate_path")
        if not isinstance(prepared_candidate_raw, str):
            raise TransactionError(
                "receipt_invalid",
                "schema-v4 receipt is missing prepared_candidate_path",
            )
        prepared_candidate = Path(prepared_candidate_raw)
        expected_prepared_candidate = prepared_candidate_path(receipt_path)
        if (
            not prepared_candidate.is_absolute()
            or prepared_candidate != expected_prepared_candidate
        ):
            raise TransactionError(
                "receipt_invalid",
                "prepared candidate path is not the receipt-bound recovery locator",
            )
        prepared_parent_expected = Snapshot.from_json(
            receipt.get("prepared_candidate_parent"),
            label="prepared_candidate_parent",
            require_object_policy=True,
        )
    derived_terminal = recovery_terminal_path(receipt_path)
    derived_terminal_result = recovery_terminal_result_path(derived_terminal)
    derived_prepared_candidate = prepared_candidate_path(receipt_path)
    reject_fixed_stage_namespace_overlap(
        rules.parent,
        [
            ("receipt", receipt_path),
            ("recovery_terminal", derived_terminal),
            ("recovery_terminal_result", derived_terminal_result),
            ("prepared_candidate", derived_prepared_candidate),
            ("lock", lock),
            *(
                [("recorded_recovery_terminal", terminal_path)]
                if terminal_path is not None
                else []
            ),
            *(
                [("recorded_prepared_candidate", prepared_candidate)]
                if prepared_candidate is not None
                else []
            ),
        ],
    )
    terminal_expected: Snapshot | None = None
    if receipt.get("recovery_terminal") is not None:
        if terminal_path is None:
            raise TransactionError(
                "receipt_invalid",
                "receipt binds recovery terminal properties without a path",
            )
        terminal_expected = Snapshot.from_json(
            receipt.get("recovery_terminal"),
            label="recovery_terminal",
            require_object_policy=True,
        )
        if terminal_expected.nlink != 1:
            raise TransactionError(
                "receipt_invalid",
                "recovery_terminal.object_policy.nlink must be 1",
            )
    if receipt_schema_version >= 3 and (
        terminal_path is None
        or terminal_expected is None
        or not isinstance(transaction_id, str)
    ):
        raise TransactionError(
            "receipt_invalid",
            "schema-v3+ receipt requires a bound recovery terminal",
        )
    if require_object_policy:
        for label, snapshot in (
            ("original", original),
            ("installed", installed),
            ("backup", backup_expected),
        ):
            if snapshot.nlink != 1:
                raise TransactionError(
                    "receipt_invalid",
                    f"{label}.object_policy.nlink must be 1",
                )
    mutation_tracker = RecoveryMutationTracker(
        locators={
            "receipt": str(receipt_path),
            "live": str(rules),
            "backup": str(backup),
            "staged_backup": str(staged_backup) if staged_backup is not None else "",
            "prepared_candidate": (
                str(prepared_candidate) if prepared_candidate is not None else ""
            ),
            "recovery_terminal": (
                str(terminal_path) if terminal_path is not None else ""
            ),
            "recovery_terminal_result": (
                str(recovery_terminal_result_path(terminal_path))
                if terminal_path is not None
                else ""
            ),
        }
    )
    terminal_evidence: RecoveryTerminalEvidence | None = None
    lock_acquired = False
    outcome: tuple[int, dict[str, object]] | None = None
    primary_error: BaseException | None = None

    def record_outcome(
        value: tuple[int, dict[str, object]],
    ) -> tuple[int, dict[str, object]]:
        nonlocal outcome
        outcome = value
        return value

    def validate_controls() -> None:
        receipt_evidence.validate()
        if terminal_evidence is not None:
            terminal_evidence.validate()

    def before_lock_release() -> None:
        try:
            validate_controls()
        except TransactionError as error:
            if mutation_tracker.mutation_started:
                raise TransactionError(
                    "recovery_required",
                    "receipt-bound recovery evidence changed before lock release",
                    exit_code=EXIT_POST_REPLACE_FAILED,
                    details={
                        "reason": error.status,
                        "message": str(error),
                        **mutation_tracker.details(),
                        **error.details,
                    },
                ) from error
            raise

    try:
        try:
            with shared_lock(
                lock,
                timeout_seconds=args.lock_timeout_seconds,
                before_release=before_lock_release,
            ) as lock_binding:
                lock_acquired = True
                receipt_evidence.validate()
                if receipt_schema_version >= 3:
                    assert terminal_path is not None
                    assert terminal_expected is not None
                    assert isinstance(transaction_id, str)
                    observe_recovery_primary_state(
                        receipt_schema_version=receipt_schema_version,
                        rules=rules,
                        lock_binding=lock_binding,
                        backup=backup,
                        prepared_candidate=prepared_candidate,
                        rules_parent_expected=parent_expected,
                        prepared_parent_expected=prepared_parent_expected,
                        original=original,
                        installed=installed,
                        mutation_tracker=mutation_tracker,
                    )
                    terminal_evidence = bind_recovery_terminal_evidence(
                        terminal_path,
                        parent=receipt_evidence.parent,
                        expected_reservation=terminal_expected,
                        transaction_id=transaction_id,
                    )
                    preflight_terminal = terminal_evidence.validate()
                    if preflight_terminal.get("state") == RECOVERY_TERMINAL_RESERVED:
                        mutation_tracker.clear_deferred_mutation()
                    else:
                        mutation_tracker.promote_deferred_mutation()
                    validate_controls()
                if receipt_schema_version >= 4:
                    assert staged_backup is not None
                    assert prepared_candidate is not None
                    assert prepared_parent_expected is not None
                    assert terminal_path is not None
                    assert terminal_expected is not None
                    assert isinstance(transaction_id, str)
                    return record_outcome(
                        recover_schema_v4_transaction(
                            rules=rules,
                            lock_binding=lock_binding,
                            backup=backup,
                            staged_backup=staged_backup,
                            prepared_candidate=prepared_candidate,
                            rules_parent_expected=parent_expected,
                            prepared_parent_expected=prepared_parent_expected,
                            original=original,
                            installed=installed,
                            terminal_path=terminal_path,
                            terminal_expected=terminal_expected,
                            transaction_id=transaction_id,
                            terminal_evidence=terminal_evidence,
                            validate_controls=validate_controls,
                            mutation_tracker=mutation_tracker,
                        )
                    )
                if receipt_schema_version == 3:
                    assert staged_backup is not None
                    assert staged_parent_expected is not None
                    assert terminal_path is not None
                    assert terminal_expected is not None
                    assert isinstance(transaction_id, str)
                    return record_outcome(
                        recover_schema_v3_transaction(
                            rules=rules,
                            lock_binding=lock_binding,
                            backup=backup,
                            staged_backup=staged_backup,
                            rules_parent_expected=parent_expected,
                            staged_parent_expected=staged_parent_expected,
                            original=original,
                            installed=installed,
                            terminal_path=terminal_path,
                            terminal_expected=terminal_expected,
                            transaction_id=transaction_id,
                            terminal_evidence=terminal_evidence,
                            validate_controls=validate_controls,
                            mutation_tracker=mutation_tracker,
                        )
                    )
                return record_outcome(
                    recover_legacy_transaction(
                        rules=rules,
                        lock_binding=lock_binding,
                        backup=backup,
                        receipt_parent_path=receipt_path.parent,
                        receipt_parent_expected=receipt_parent_expected,
                        rules_parent_expected=parent_expected,
                        original=original,
                        installed=installed,
                        backup_expected=backup_expected,
                        terminal_path=terminal_path,
                        terminal_expected=terminal_expected,
                        transaction_id=transaction_id,
                        mutation_tracker=mutation_tracker,
                    )
                )
        except TransactionError as error:
            if not lock_acquired:
                raise
            mutation_tracker.promote_deferred_mutation()
            if mutation_tracker.mutation_started or error.status == "recovery_required":
                return record_outcome(
                    (
                        EXIT_POST_REPLACE_FAILED,
                        {
                            "status": "recovery_required",
                            "reason": error.details.get("reason") or error.status,
                            "message": str(error),
                            **mutation_tracker.details(),
                            **error.details,
                        },
                    )
                )
            return record_outcome(
                (
                    EXIT_RECOVERY_REFUSED,
                    {
                        "status": "recovery_refused",
                        "reason": error.status,
                        "message": str(error),
                        **(
                            {
                                "transaction_state": (
                                    mutation_tracker.last_observed.get(
                                        "transaction_state"
                                    )
                                    or mutation_tracker.last_observed.get(
                                        "transaction_state_hint"
                                    )
                                ),
                                "observed_state": mutation_tracker.last_observed,
                            }
                            if mutation_tracker.last_observed is not None
                            else {}
                        ),
                        **error.details,
                    },
                )
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if terminal_evidence is not None:
            mutation_tracker.record_cleanup_failures(terminal_evidence.close())
        failures = mutation_tracker.take_cleanup_failures()
        if failures:
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            elif outcome is not None:
                attach_cleanup_failures_to_payload(outcome[1], failures)
            else:
                raise descriptor_cleanup_error(failures)


def recover_transaction(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    receipt_path = resolved_leaf(args.receipt, label="receipt")
    receipt_evidence = bind_recovery_receipt(receipt_path)
    outcome: tuple[int, dict[str, object]] | None = None
    primary_error: BaseException | None = None
    try:
        outcome = _recover_transaction_bound(
            args,
            receipt_path=receipt_path,
            receipt_evidence=receipt_evidence,
        )
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        failures = receipt_evidence.close()
        if failures:
            if primary_error is not None:
                attach_failures_to_exception(
                    primary_error,
                    "cleanup_failures",
                    failures,
                )
            elif outcome is not None:
                attach_cleanup_failures_to_payload(outcome[1], failures)
            else:
                raise descriptor_cleanup_error(failures)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a private rules candidate, compare-and-replace default.rules "
            "under a shared lock, and retain bound recovery evidence."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--candidate", required=True)
    apply_parser.add_argument("--candidate-sha256", required=True)
    apply_parser.add_argument("--expected-sha256", required=True)
    apply_parser.add_argument("--backup-name", required=True)
    apply_parser.add_argument("--receipt", required=True)
    apply_parser.add_argument(
        "--validator-timeout-seconds",
        type=float,
        default=DEFAULT_VALIDATOR_TIMEOUT_SECONDS,
    )
    apply_parser.add_argument(
        "--lock-timeout-seconds",
        type=float,
        default=DEFAULT_LOCK_TIMEOUT_SECONDS,
    )
    apply_parser.add_argument(
        "validator_command",
        nargs=argparse.REMAINDER,
        help=f"Direct validator argv containing one {RULES_PLACEHOLDER!r} argument.",
    )
    recover_parser = subparsers.add_parser("recover")
    recover_parser.add_argument("--receipt", required=True)
    recover_parser.add_argument(
        "--lock-timeout-seconds",
        type=float,
        default=DEFAULT_LOCK_TIMEOUT_SECONDS,
    )
    return parser


def emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True, ensure_ascii=True))


def main(argv: list[str] | None = None) -> int:
    if os.name != "posix":
        emit(
            {
                "status": "unsupported_platform",
                "message": "the shared-lock helper requires POSIX",
            }
        )
        return EXIT_RUNTIME_ERROR
    args = build_parser().parse_args(argv)
    if args.command == "apply" and args.validator_command[:1] == ["--"]:
        args.validator_command = args.validator_command[1:]
    lock_timeout_invalid = (
        not math.isfinite(args.lock_timeout_seconds) or args.lock_timeout_seconds <= 0
    )
    validator_timeout_invalid = args.command == "apply" and (
        not math.isfinite(args.validator_timeout_seconds)
        or args.validator_timeout_seconds <= 0
    )
    if (
        lock_timeout_invalid
        or validator_timeout_invalid
        or (args.command == "apply" and not args.validator_command)
    ):
        emit(
            {
                "status": "arguments_invalid",
                "message": (
                    "timeouts must be finite and positive and apply needs validator argv"
                ),
            }
        )
        return EXIT_RUNTIME_ERROR
    try:
        if args.command == "apply":
            exit_code, payload = apply_transaction(args)
        else:
            exit_code, payload = recover_transaction(args)
    except ForwardedValidatorSignal as event:
        exit_code = min(255, 128 + event.signum)
        payload = {
            "status": "interrupted",
            "signal": event.signum,
            "signal_name": signal.Signals(event.signum).name,
        }
        if event.cleanup_errors:
            payload["validator_cleanup_errors"] = event.cleanup_errors
    except TransactionError as error:
        exit_code = error.exit_code
        payload = {
            "status": error.status,
            "message": str(error),
            **error.details,
        }
    except OSError as error:
        exit_code = EXIT_RUNTIME_ERROR
        payload = {"status": "runtime_error", "message": str(error)}
        cleanup_failures = getattr(error, "cleanup_failures", None)
        if isinstance(cleanup_failures, list):
            payload["cleanup_failures"] = cleanup_failures
    emit(payload)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
