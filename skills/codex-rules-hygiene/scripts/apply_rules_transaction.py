#!/usr/bin/env python3
"""Apply a validated default.rules candidate with bound recovery evidence."""

from __future__ import annotations

import argparse
from array import array
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
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
import time


SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = frozenset((1, SCHEMA_VERSION))
RECOVERY_TERMINAL_SCHEMA_VERSION = 1
RULES_PLACEHOLDER = "{rules}"
MAX_RULES_BYTES = 8 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_DIAGNOSTIC_CHARS = 4_000
DEFAULT_VALIDATOR_TIMEOUT_SECONDS = 60.0
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
MAX_VALIDATOR_OUTPUT_BYTES = 128 * 1024
MAX_XATTR_NAME_BYTES = 64 * 1024
VALIDATOR_TERM_GRACE_SECONDS = 0.25
VALIDATOR_KILL_DRAIN_SECONDS = 1.0

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
        nlink = object_policy.get("nlink") if isinstance(object_policy, dict) else None
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


def valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def compact(value: str) -> str:
    if len(value) <= MAX_DIAGNOSTIC_CHARS:
        return value
    return value[: MAX_DIAGNOSTIC_CHARS - 3] + "..."


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
    if expected.nlink is not None and expected.nlink != actual.nlink:
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
        and (expected.nlink is None or expected.nlink == actual.nlink)
    )


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
    if expected.nlink is not None and expected.nlink != actual.st_nlink:
        mismatches.append("object_policy")
    return mismatches


def directory_property_mismatches(
    expected: Snapshot,
    actual: os.stat_result,
) -> list[str]:
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


def read_stable(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_RULES_BYTES,
    require_modeled_metadata: bool = False,
) -> tuple[bytes, Snapshot]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
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
        return payload, snapshot
    finally:
        os.close(fd)


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
) -> None:
    try:
        file_stat = os.fstat(fd)
    except OSError as error:
        raise TransactionError(
            f"{label}_metadata_unreadable",
            f"{label} bound metadata is unreadable: {error}",
        ) from error
    if not stat.S_ISREG(file_stat.st_mode):
        raise TransactionError(
            f"{label}_not_regular",
            f"{label} is not a regular file while metadata is inspected",
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
    os.close(fd)
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
        os.close(fd)
        if isinstance(error, TransactionError):
            error.details.setdefault("retained_created_object", retained)
            raise
        if isinstance(error, Exception):
            retained_status = retained.get("retention_status")
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
                details={"retained_created_object": retained},
            ) from error
        raise


class PrivateStage:
    def __init__(self, rules_parent: Path) -> None:
        directory_flags = (
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        self.rules_parent = rules_parent
        self.rules_parent_fd = os.open(rules_parent, directory_flags)
        parent_stat = os.fstat(self.rules_parent_fd)
        parent_path_stat = os.stat(rules_parent, follow_symlinks=False)
        parent_mismatches = directory_property_mismatches(
            Snapshot.from_stat(parent_stat, b""),
            parent_path_stat,
        )
        if parent_mismatches:
            os.close(self.rules_parent_fd)
            raise TransactionError(
                "rules_directory_changed",
                "rules directory path no longer names the bound directory",
                details={"mismatched_properties": parent_mismatches},
            )
        self.rules_parent_snapshot = Snapshot.from_stat(parent_stat, b"")
        self.stage_name = ""
        for _attempt in range(128):
            candidate = f".rules-apply-{secrets.token_hex(8)}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=self.rules_parent_fd)
            except FileExistsError:
                continue
            self.stage_name = candidate
            break
        if not self.stage_name:
            os.close(self.rules_parent_fd)
            raise TransactionError(
                "private_stage_unavailable",
                "cannot allocate a unique private staging directory",
            )
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
            if (
                not stat.S_ISDIR(stage_stat.st_mode)
                or stage_stat.st_uid != os.geteuid()
                or stat.S_IMODE(stage_stat.st_mode) != 0o700
                or directory_property_mismatches(
                    Snapshot.from_stat(stage_stat, b""),
                    stage_path_stat,
                )
            ):
                raise TransactionError(
                    "private_stage_invalid",
                    "staging directory is not the bound owner-only directory",
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
            if hasattr(self, "stage_fd"):
                os.close(self.stage_fd)
            os.close(self.rules_parent_fd)
            if isinstance(error, TransactionError):
                error.details.setdefault("retained_stage", stage_identity_details)
            raise
        self.stage_snapshot = Snapshot.from_stat(stage_stat, b"")
        self.files: dict[Path, BoundFile] = {}
        self.extra_fds: list[int] = []
        self.closed = False

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
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target.name, flags, dir_fd=self.rules_parent_fd)
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
        except BaseException:
            os.close(fd)
            raise
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
        atomic_error: OSError | None = None
        try:
            atomic_rename_exchange(
                self.stage_fd,
                source.name,
                self.rules_parent_fd,
                target.name,
            )
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
                self.extra_fds.remove(target_binding.fd)
                os.close(target_binding.fd)
                raise TransactionError(
                    "atomic_exchange_failed",
                    f"atomic exchange failed without changing either side: {atomic_error}",
                    details={
                        "source_observation": initial_source,
                        "destination_observation": initial_destination,
                    },
                ) from atomic_error
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

        os.close(source.fd)
        self.extra_fds.remove(target_binding.fd)
        source.fd = target_binding.fd
        source.snapshot = target_actual
        return expected

    def publish_backup(self, path: Path, backup: Path) -> Snapshot:
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
        try:
            atomic_rename_no_replace(
                self.stage_fd,
                source.name,
                self.rules_parent_fd,
                backup.name,
            )
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
                raise TransactionError(
                    "backup_exists",
                    f"backup already exists: {backup}",
                    details={"backup_observation": destination_observation},
                ) from atomic_error
            if (
                observation_matches(source_observation)
                and destination_observation.get("state") == "missing"
            ):
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
        os.close(source.fd)
        self.files.pop(path, None)
        return actual

    def _find_bound_entry(
        self,
        directory_fd: int,
        expected: Snapshot,
    ) -> str | None:
        try:
            names = os.listdir(directory_fd)
        except OSError:
            return None
        if len(names) > 1024:
            return None
        for name in names:
            try:
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                continue
            if (entry.st_dev, entry.st_ino) == (expected.device, expected.inode):
                return name
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
        root_name = self._find_bound_entry(
            self.rules_parent_fd,
            self.stage_snapshot,
        )
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
        parent_name = self._find_bound_entry(self.rules_parent_fd, expected)
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

    def cleanup(self) -> list[dict[str, object]]:
        if self.closed:
            return []
        warnings: list[dict[str, object]] = []
        root_locator = self._locator_for_snapshot(self.stage_snapshot)
        for binding in self.files.values():
            locator = self._locator_for_snapshot(binding.snapshot)
            current_stat = os.fstat(binding.fd)
            persistently_retained = locator is not None and current_stat.st_nlink > 0
            current_observation = observe_directory_entry(
                self.stage_fd,
                binding.name,
                expected=binding.snapshot,
            )
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
                    "recovery_locator": str(locator) if locator is not None else None,
                    "last_known_path": str(binding.path),
                    "last_known_path_observation": current_observation,
                }
            )
            os.close(binding.fd)
        for fd in self.extra_fds:
            try:
                file_stat = os.fstat(fd)
                locator = self._locator_for_snapshot(
                    Snapshot.from_stat(file_stat, b""),
                )
                persistently_retained = locator is not None and file_stat.st_nlink > 0
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
            finally:
                os.close(fd)
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
        self.files.clear()
        self.extra_fds.clear()
        self.closed = True
        os.close(self.stage_fd)
        os.close(self.rules_parent_fd)
        return warnings


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


@contextmanager
def shared_lock(path: Path, *, timeout_seconds: float):
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise TransactionError(
            "arguments_invalid",
            "lock timeout must be finite and positive",
        )
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = os.open(path, flags)
    try:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TransactionError(
                        "lock_busy",
                        "transaction lock remained busy",
                        exit_code=EXIT_LIVE_CONFLICT,
                    )
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        yield lock_snapshot(path, os.fstat(fd))
    finally:
        os.close(fd)


def revalidate_lock(path: Path, expected: Snapshot) -> None:
    try:
        actual_stat = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as error:
        raise TransactionError(
            "lock_missing", "transaction lock disappeared"
        ) from error
    actual = Snapshot.from_stat(actual_stat, b"")
    mismatches = property_mismatches(expected, actual)
    if mismatches:
        raise TransactionError(
            "lock_changed",
            "transaction lock changed",
            details={"mismatched_properties": mismatches},
        )


def _validator_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Darwin reports EPERM for a process group containing only zombies.
        # Every live member of this newly created group has our effective UID,
        # so an unsignalable group has no live validator process to clean up.
        return False
    return True


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


def _stop_validator_process_group(
    process: subprocess.Popen[bytes],
    exit_observer: _ValidatorExitObserver,
    selector: selectors.BaseSelector,
    buffers: dict[str, bytearray],
    *,
    max_output_bytes: int,
) -> int:
    process_group_id = process.pid
    if not (exit_observer.child_exited() and not selector.get_map()):
        _signal_validator_group(process_group_id, signal.SIGTERM)
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
        if exit_observer.child_exited() and not selector.get_map():
            break
    quiescent = exit_observer.child_exited() and not selector.get_map()
    _signal_validator_group(
        process_group_id,
        signal.SIGKILL,
        allow_zombie_only=quiescent,
    )

    kill_deadline = time.monotonic() + VALIDATOR_KILL_DRAIN_SECONDS
    while selector.get_map() and time.monotonic() < kill_deadline:
        remaining = kill_deadline - time.monotonic()
        _read_validator_events(
            selector,
            buffers,
            max_output_bytes=max_output_bytes,
            timeout_seconds=min(0.02, remaining),
            retain=False,
        )
    try:
        returncode = process.wait(timeout=max(0.0, kill_deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        raise TransactionError(
            "validator_cleanup_failed",
            "validator direct child survived process-group SIGKILL",
        ) from error
    while (
        _validator_group_exists(process_group_id) and time.monotonic() < kill_deadline
    ):
        time.sleep(min(0.01, max(0.0, kill_deadline - time.monotonic())))
    if _validator_group_exists(process_group_id):
        raise TransactionError(
            "validator_cleanup_failed",
            "validator process group remained observable after SIGKILL",
        )
    if selector.get_map():
        raise TransactionError(
            "validator_cleanup_failed",
            "validator output pipes remained open after process-group SIGKILL",
        )
    return returncode


def run_validator(
    command_template: list[str],
    rules_path: Path,
    *,
    timeout_seconds: float,
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
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as error:
        raise TransactionError(
            "validator_launch_failed",
            f"cannot launch validator: {error}",
        ) from error
    try:
        exit_observer = _ValidatorExitObserver(process)
    except TransactionError:
        _signal_validator_group(process.pid, signal.SIGKILL)
        process.wait()
        raise
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    for stream, label in (
        (process.stdout, "stdout"),
        (process.stderr, "stderr"),
    ):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)

    timed_out = False
    output_limit_exceeded = False
    descendants_terminated = False
    try:
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

            # Reap every byte already made readable by the direct child. Any
            # still-open pipe or surviving group member then belongs to a
            # descendant and is not an acceptable validator terminal state.
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
            if selector.get_map():
                descendants_terminated = True
            returncode = _stop_validator_process_group(
                process,
                exit_observer,
                selector,
                buffers,
                max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
            )
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

        _stop_validator_process_group(
            process,
            exit_observer,
            selector,
            buffers,
            max_output_bytes=MAX_VALIDATOR_OUTPUT_BYTES,
        )
        return ValidatorResult(
            124 if timed_out else 125,
            bytes(buffers["stdout"]).decode("utf-8", "replace"),
            bytes(buffers["stderr"]).decode("utf-8", "replace"),
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
            descendants_terminated=descendants_terminated,
        )
    finally:
        exit_observer.close()
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


def fsync_file_and_parent(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(
        path.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def require_owner_private_directory(path: Path, *, label: str) -> None:
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise TransactionError(
            f"{label}_parent_unreadable",
            f"cannot inspect {label} parent directory: {error}",
        ) from error
    if (
        not stat.S_ISDIR(path_stat.st_mode)
        or path_stat.st_uid != os.geteuid()
        or stat.S_IMODE(path_stat.st_mode) & 0o077
    ):
        raise TransactionError(
            f"{label}_parent_not_private",
            f"{label} parent directory must be owner-only",
        )


def receipt_payload(
    *,
    rules: Path,
    lock: Path,
    backup: Path,
    expected_sha256: str,
    parent: Snapshot,
    original: Snapshot,
    installed: Snapshot,
    backup_snapshot: Snapshot,
    recovery_terminal: Path,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "transaction_id": secrets.token_hex(16),
        "created_unix_ns": time.time_ns(),
        "rules_path": str(rules),
        "lock_path": str(lock),
        "backup_path": str(backup),
        "recovery_terminal_path": str(recovery_terminal),
        "expected_sha256": expected_sha256,
        "rules_parent": parent.to_json(),
        "original": original.to_json(),
        "installed": installed.to_json(),
        "backup": backup_snapshot.to_json(),
    }


def recovery_terminal_path(receipt: Path) -> Path:
    return receipt.with_name(f"{receipt.name}.recovered")


def write_receipt(path: Path, payload: dict[str, object]) -> None:
    require_owner_private_directory(path.parent, label="receipt")
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise TransactionError("receipt_too_large", "recovery receipt is too large")
    snapshot = write_exclusive(path, encoded)
    if snapshot.uid != os.geteuid() or snapshot.mode != 0o600:
        raise TransactionError(
            "receipt_invalid",
            "recovery receipt is not owner-only",
        )
    fsync_directory(path.parent)


def read_receipt(path: Path) -> dict[str, object]:
    require_owner_private_directory(path.parent, label="receipt")
    payload, snapshot = read_stable(
        path,
        label="receipt",
        max_bytes=MAX_RECEIPT_BYTES,
    )
    if snapshot.uid != os.geteuid() or snapshot.mode != 0o600:
        raise TransactionError(
            "receipt_invalid",
            "recovery receipt is not owner-only",
        )
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


def read_recovery_terminal(path: Path) -> dict[str, object]:
    require_owner_private_directory(path.parent, label="recovery_terminal")
    payload, snapshot = read_stable(
        path,
        label="recovery_terminal",
        max_bytes=MAX_RECEIPT_BYTES,
        require_modeled_metadata=True,
    )
    if snapshot.uid != os.geteuid() or snapshot.mode != 0o600 or snapshot.nlink != 1:
        raise TransactionError(
            "recovery_terminal_invalid",
            "recovery terminal evidence is not owner-only and single-link",
        )
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
    Snapshot.from_json(
        value.get("restored"),
        label="recovery_terminal.restored",
        require_object_policy=True,
    )
    return value


def record_recovery_terminal(
    path: Path,
    *,
    transaction_id: str,
    original: Snapshot,
    restored: Snapshot,
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
        "evidence_kind": evidence_kind,
        "restored": restored.to_json(),
    }
    require_owner_private_directory(path.parent, label="recovery_terminal")
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise TransactionError(
            "recovery_terminal_invalid",
            "recovery terminal evidence is too large",
        )
    try:
        snapshot = write_exclusive(path, encoded)
    except TransactionError as error:
        if error.status != "path_exists":
            raise
        existing = read_recovery_terminal(path)
        existing_restored = Snapshot.from_json(
            existing.get("restored"),
            label="recovery_terminal.restored",
            require_object_policy=True,
        )
        if existing.get("transaction_id") != transaction_id or property_mismatches(
            restored, existing_restored
        ):
            raise TransactionError(
                "recovery_terminal_conflict",
                "existing recovery terminal evidence does not match this recovery",
            ) from error
        return existing
    if snapshot.uid != os.geteuid() or snapshot.mode != 0o600 or snapshot.nlink != 1:
        raise TransactionError(
            "recovery_terminal_invalid",
            "recovery terminal evidence is not owner-only and single-link",
        )
    fsync_directory(path.parent)
    persisted = read_recovery_terminal(path)
    persisted_restored = Snapshot.from_json(
        persisted.get("restored"),
        label="recovery_terminal.restored",
        require_object_policy=True,
    )
    if persisted.get("transaction_id") != transaction_id or property_mismatches(
        restored, persisted_restored
    ):
        raise TransactionError(
            "recovery_terminal_conflict",
            "recovery terminal evidence changed after publication",
        )
    return persisted


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


def rollback(
    *,
    stage: PrivateStage,
    rules: Path,
    lock: Path,
    lock_expected: Snapshot,
    backup: Path,
    original: Snapshot,
    installed: Snapshot,
    backup_expected: Snapshot,
) -> tuple[bool, dict[str, object]]:
    try:
        reject_unmodeled_metadata(backup, label="backup")
        backup_bytes, backup_actual = read_stable(
            backup,
            label="backup",
            require_modeled_metadata=True,
        )
        backup_mismatches = property_mismatches(backup_expected, backup_actual)
        if backup_mismatches:
            return False, {
                "rollback_status": "backup_changed",
                "mismatched_properties": backup_mismatches,
            }
        reject_unmodeled_metadata(rules)
        _live_bytes, live = read_stable(
            rules,
            label="live_rules",
            require_modeled_metadata=True,
        )
        live_mismatches = property_mismatches(installed, live)
        if live_mismatches:
            return False, {
                "rollback_status": "live_no_longer_installed",
                "mismatched_properties": live_mismatches,
                "actual_live": live.to_json(),
            }
        rollback_path, rollback_snapshot = stage.create("rollback", backup_bytes)
        rollback_snapshot = stage.set_policy(
            rollback_path,
            rollback_snapshot,
            original,
        )
        revalidate_lock(lock, lock_expected)
        reject_unmodeled_metadata(rules)
        _final_bytes, final_live = read_stable(
            rules,
            label="live_rules",
            require_modeled_metadata=True,
        )
        final_mismatches = property_mismatches(installed, final_live)
        if final_mismatches:
            return False, {
                "rollback_status": "live_changed_before_rollback",
                "mismatched_properties": final_mismatches,
                "actual_live": final_live.to_json(),
            }
        restored_expected = stage.move_to(
            rollback_path,
            rules,
            final_live,
        )
        fsync_file_and_parent(rules)
        _restored_bytes, restored = read_stable(
            rules,
            label="live_rules",
            require_modeled_metadata=True,
        )
        if property_mismatches(
            restored_expected, restored
        ) or not content_access_and_object_policy_match(
            original,
            restored,
        ):
            return False, {
                "rollback_status": "rollback_verification_failed",
                "actual_live": restored.to_json(),
            }
        return True, {
            "rollback_status": "rolled_back",
            "restored": restored.to_json(),
        }
    except (OSError, TransactionError) as error:
        result: dict[str, object] = {
            "rollback_status": (
                error.status
                if isinstance(error, TransactionError)
                else "rollback_failed"
            ),
            "rollback_message": str(error),
        }
        if isinstance(error, TransactionError):
            result.update(error.details)
        return False, result


def apply_transaction(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    expected_sha256 = args.expected_sha256.lower()
    if not valid_sha256(expected_sha256):
        raise TransactionError(
            "expected_digest_invalid",
            "--expected-sha256 must be 64 lowercase hexadecimal characters",
        )
    rules = codex_rules_path()
    candidate_source = resolved_leaf(args.candidate, label="candidate")
    receipt = resolved_leaf(args.receipt, label="receipt")
    recovery_terminal = recovery_terminal_path(receipt)
    if Path(
        args.backup_name
    ).name != args.backup_name or not args.backup_name.startswith("default.rules.bak-"):
        raise TransactionError(
            "path_invalid",
            "--backup-name must be one default.rules.bak-* basename",
        )
    backup = rules.parent / args.backup_name
    lock = rules.parent / ".default.rules.apply.lock"
    if (
        candidate_source == rules
        or receipt in (rules, backup, lock, candidate_source)
        or recovery_terminal in (rules, backup, lock, candidate_source, receipt)
    ):
        raise TransactionError("path_invalid", "transaction paths must be distinct")

    candidate_bytes, _source_snapshot = read_stable(
        candidate_source,
        label="candidate_source",
    )
    observed_bytes, observed = read_stable(rules, label="live_rules")
    if (
        hmac.compare_digest(observed.sha256, expected_sha256)
        and observed_bytes == candidate_bytes
    ):
        return 0, {
            "status": "no_change",
            "rules_path": str(rules),
            "sha256": observed.sha256,
        }

    stage = PrivateStage(rules.parent)
    lock_acquired = False
    try:
        candidate, candidate_snapshot = stage.create("candidate", candidate_bytes)
        pre_validation = run_validator(
            args.validator_command,
            candidate,
            timeout_seconds=args.validator_timeout_seconds,
        )
        if not pre_validation.valid:
            return EXIT_VALIDATION_FAILED, {
                "status": "candidate_validation_failed",
                "validator": pre_validation.to_json(),
                "rules_path": str(rules),
            }
        stage.validate(candidate, candidate_snapshot, label="private_candidate")

        with shared_lock(
            lock, timeout_seconds=args.lock_timeout_seconds
        ) as lock_expected:
            lock_acquired = True
            current_bytes, current = read_stable(
                rules,
                label="live_rules",
                require_modeled_metadata=True,
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
                return 0, {
                    "status": "no_change_after_lock",
                    "rules_path": str(rules),
                    "sha256": current.sha256,
                }

            parent_expected = directory_snapshot(rules.parent)
            backup_stage, backup_stage_snapshot = stage.create("backup", current_bytes)
            backup_stage_snapshot = stage.set_policy(
                backup_stage,
                backup_stage_snapshot,
                current,
            )
            backup_snapshot = stage.publish_backup(backup_stage, backup)
            fsync_directory(rules.parent)

            installed_snapshot = stage.set_policy(
                candidate,
                candidate_snapshot,
                current,
            )
            transaction_receipt = receipt_payload(
                rules=rules,
                lock=lock,
                backup=backup,
                expected_sha256=expected_sha256,
                parent=parent_expected,
                original=current,
                installed=installed_snapshot,
                backup_snapshot=backup_snapshot,
                recovery_terminal=recovery_terminal,
            )
            write_receipt(receipt, transaction_receipt)

            revalidate_lock(lock, lock_expected)
            _final_bytes, final_live = read_stable(
                rules,
                label="live_rules",
                require_modeled_metadata=True,
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
                )
            except TransactionError as error:
                error.details.setdefault("receipt_path", str(receipt))
                error.details.setdefault("backup_path", str(backup))
                raise
            post_failure: dict[str, object] | None = None
            try:
                fsync_file_and_parent(rules)
            except OSError as error:
                post_failure = {
                    "status": "post_replace_fsync_failed",
                    "message": str(error),
                }

            try:
                _installed_bytes, installed_live = read_stable(
                    rules,
                    label="live_rules",
                    require_modeled_metadata=True,
                )
            except TransactionError as error:
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            installed_mismatches = property_mismatches(
                installed_expected,
                installed_live,
            )
            if installed_mismatches:
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
                _post_bytes, post_live = read_stable(
                    rules,
                    label="live_rules",
                    require_modeled_metadata=True,
                )
            except TransactionError as error:
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "post_replace_failure": {
                        "status": error.status,
                        "message": str(error),
                    },
                    "receipt_path": str(receipt),
                    "backup_path": str(backup),
                }
            post_mismatches = property_mismatches(installed_expected, post_live)
            if post_mismatches:
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
                rolled_back, rollback_result = rollback(
                    stage=stage,
                    rules=rules,
                    lock=lock,
                    lock_expected=lock_expected,
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
                        recovery_terminal_result = record_recovery_terminal(
                            recovery_terminal,
                            transaction_id=str(transaction_receipt["transaction_id"]),
                            original=current,
                            restored=restored,
                        )
                        verify_restored_terminal(rules, restored)
                    except TransactionError as error:
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
    finally:
        warnings = stage.cleanup()
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


def recover_transaction(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    receipt_path = resolved_leaf(args.receipt, label="receipt")
    receipt = read_receipt(receipt_path)
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
    )
    original = Snapshot.from_json(
        receipt.get("original"),
        label="original",
        require_object_policy=require_object_policy,
    )
    installed = Snapshot.from_json(
        receipt.get("installed"),
        label="installed",
        require_object_policy=require_object_policy,
    )
    backup_expected = Snapshot.from_json(
        receipt.get("backup"),
        label="backup",
        require_object_policy=require_object_policy,
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
    parent_mismatches = directory_property_mismatches(
        parent_expected,
        os.stat(rules.parent, follow_symlinks=False),
    )
    if parent_mismatches:
        return EXIT_RECOVERY_REFUSED, {
            "status": "recovery_refused",
            "reason": "rules_parent_changed",
            "mismatched_properties": parent_mismatches,
        }

    stage: PrivateStage | None = None
    with shared_lock(lock, timeout_seconds=args.lock_timeout_seconds) as lock_expected:
        try:
            _live_bytes, live = read_stable(
                rules,
                label="live_rules",
                require_modeled_metadata=True,
            )
        except TransactionError as error:
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": error.status,
                "message": str(error),
            }
        if property_mismatches(original, live) == []:
            return 0, {
                "status": "already_original",
                "rules_path": str(rules),
                "live": live.to_json(),
                "identity_evidence": "receipt_original_identity",
            }
        if terminal_path is not None:
            try:
                terminal = read_recovery_terminal(terminal_path)
            except TransactionError as error:
                if error.status != "recovery_terminal_missing":
                    return EXIT_RECOVERY_REFUSED, {
                        "status": "recovery_refused",
                        "reason": error.status,
                        "message": str(error),
                        **error.details,
                    }
            else:
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
                    and terminal.get("transaction_id") == transaction_id
                    and not terminal_mismatches
                    and content_access_and_object_policy_match(original, live)
                ):
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
        stage = PrivateStage(rules.parent)
        try:
            rolled_back, rollback_result = rollback(
                stage=stage,
                rules=rules,
                lock=lock,
                lock_expected=lock_expected,
                backup=backup,
                original=original,
                installed=installed,
                backup_expected=backup_expected,
            )
            if not rolled_back:
                if rollback_result.get("rollback_status") == "recovery_required":
                    return EXIT_POST_REPLACE_FAILED, {
                        "status": "recovery_required",
                        "rollback": rollback_result,
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
                return 0, {
                    "status": "recovered",
                    "rules_path": str(rules),
                    "rollback": rollback_result,
                    "identity_evidence": "current-run-only-legacy-receipt",
                }
            try:
                terminal = record_recovery_terminal(
                    terminal_path,
                    transaction_id=str(transaction_id),
                    original=original,
                    restored=restored,
                )
                verify_restored_terminal(rules, restored)
            except TransactionError as error:
                return EXIT_POST_REPLACE_FAILED, {
                    "status": "recovery_required",
                    "rollback": rollback_result,
                    "recovery_terminal_failure": {
                        "status": error.status,
                        "message": str(error),
                        **error.details,
                    },
                }
            return 0, {
                "status": "recovered",
                "rules_path": str(rules),
                "rollback": rollback_result,
                "recovery_terminal": terminal,
            }
        finally:
            warnings = stage.cleanup()
            if warnings:
                print(
                    json.dumps(
                        {"status": "cleanup_warning", "warnings": warnings},
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )


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
    emit(payload)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
