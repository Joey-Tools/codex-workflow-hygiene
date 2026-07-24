#!/usr/bin/env python3
"""Apply a validated default.rules candidate with bound recovery evidence."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time


SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = frozenset((1, SCHEMA_VERSION))
RULES_PLACEHOLDER = "{rules}"
MAX_RULES_BYTES = 8 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_DIAGNOSTIC_CHARS = 4_000
DEFAULT_VALIDATOR_TIMEOUT_SECONDS = 60.0
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0

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

    @property
    def valid(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_json(self) -> dict[str, object]:
        return {
            "returncode": self.returncode,
            "timed_out": self.timed_out,
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


def reject_unmodeled_metadata(path: Path, *, label: str = "live_rules") -> None:
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as error:
        raise TransactionError(
            f"{label}_missing",
            f"{label} is missing while metadata is inspected",
        ) from error
    except PermissionError as error:
        raise TransactionError(
            f"{label}_unreadable",
            f"{label} metadata is unreadable: {error}",
        ) from error
    file_flags = int(getattr(path_stat, "st_flags", 0))
    if file_flags:
        raise TransactionError(
            "unsupported_file_flags",
            f"{label} uses file flags that this helper does not preserve",
            details={"st_flags": file_flags},
        )
    if hasattr(os, "listxattr"):
        try:
            extended_attributes = os.listxattr(path, follow_symlinks=False)
        except OSError as error:
            raise TransactionError(
                f"{label}_unreadable",
                f"{label} extended attributes are unreadable: {error}",
            ) from error
        if extended_attributes:
            raise TransactionError(
                "unsupported_extended_attributes",
                f"{label} uses extended attributes that this helper does not preserve",
                details={"extended_attributes": sorted(extended_attributes)},
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
            payload, origin_actual = read_bound_fd(
                binding.fd,
                label=f"{role}_bound_object",
            )
            result["origin_actual"] = origin_actual.to_json()
            result["origin_mismatched_properties"] = property_mismatches(
                binding.snapshot,
                origin_actual,
            )
            recovery_name = f".recovery-{role}-{secrets.token_hex(8)}"
            recovery_path, recovery_snapshot = self.create(recovery_name, payload)
            recovery_snapshot = self.set_policy(
                recovery_path,
                recovery_snapshot,
                origin_actual,
            )
            os.fsync(self.stage_fd)
            os.fsync(self.rules_parent_fd)
            locator = self._locator_for_snapshot(recovery_snapshot)
            result.update(
                {
                    "recovery_copy": recovery_snapshot.to_json(),
                    "recovery_locator": (str(locator) if locator is not None else None),
                    "retention_status": (
                        "verified_recovery_copy"
                        if locator is not None and recovery_snapshot.nlink == 1
                        else "recovery_copy_unlocatable"
                    ),
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


def run_validator(
    command_template: list[str],
    rules_path: Path,
    *,
    timeout_seconds: float,
) -> ValidatorResult:
    if command_template.count(RULES_PLACEHOLDER) != 1:
        raise TransactionError(
            "validator_command_invalid",
            f"validator argv must contain exactly one {RULES_PLACEHOLDER!r} argument",
        )
    command = [
        str(rules_path) if argument == RULES_PLACEHOLDER else argument
        for argument in command_template
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        stdout = (
            error.stdout.decode() if isinstance(error.stdout, bytes) else error.stdout
        )
        stderr = (
            error.stderr.decode() if isinstance(error.stderr, bytes) else error.stderr
        )
        return ValidatorResult(124, stdout or "", stderr or "", timed_out=True)
    except OSError as error:
        raise TransactionError(
            "validator_launch_failed",
            f"cannot launch validator: {error}",
        ) from error
    return ValidatorResult(result.returncode, result.stdout, result.stderr)


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
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "transaction_id": secrets.token_hex(16),
        "created_unix_ns": time.time_ns(),
        "rules_path": str(rules),
        "lock_path": str(lock),
        "backup_path": str(backup),
        "expected_sha256": expected_sha256,
        "rules_parent": parent.to_json(),
        "original": original.to_json(),
        "installed": installed.to_json(),
        "backup": backup_snapshot.to_json(),
    }


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
        backup_bytes, backup_actual = read_stable(backup, label="backup")
        backup_mismatches = property_mismatches(backup_expected, backup_actual)
        if backup_mismatches:
            return False, {
                "rollback_status": "backup_changed",
                "mismatched_properties": backup_mismatches,
            }
        reject_unmodeled_metadata(rules)
        _live_bytes, live = read_stable(rules, label="live_rules")
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
        _final_bytes, final_live = read_stable(rules, label="live_rules")
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
        _restored_bytes, restored = read_stable(rules, label="live_rules")
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
    if Path(
        args.backup_name
    ).name != args.backup_name or not args.backup_name.startswith("default.rules.bak-"):
        raise TransactionError(
            "path_invalid",
            "--backup-name must be one default.rules.bak-* basename",
        )
    backup = rules.parent / args.backup_name
    lock = rules.parent / ".default.rules.apply.lock"
    if candidate_source == rules or receipt in (
        rules,
        backup,
        lock,
        candidate_source,
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
            current_bytes, current = read_stable(rules, label="live_rules")
            reject_unmodeled_metadata(rules)
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
            )
            write_receipt(receipt, transaction_receipt)

            revalidate_lock(lock, lock_expected)
            _final_bytes, final_live = read_stable(rules, label="live_rules")
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
                _post_bytes, post_live = read_stable(rules, label="live_rules")
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
                return EXIT_POST_REPLACE_FAILED, {
                    "status": (
                        "post_replace_failed_rolled_back"
                        if rolled_back
                        else "recovery_required"
                    ),
                    "post_replace_failure": post_failure,
                    "rollback": rollback_result,
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
            _live_bytes, live = read_stable(rules, label="live_rules")
        except TransactionError as error:
            return EXIT_RECOVERY_REFUSED, {
                "status": "recovery_refused",
                "reason": error.status,
                "message": str(error),
            }
        if content_access_and_object_policy_match(original, live):
            return 0, {
                "status": "already_original",
                "rules_path": str(rules),
                "live": live.to_json(),
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
            return 0, {
                "status": "recovered",
                "rules_path": str(rules),
                "rollback": rollback_result,
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
    if args.lock_timeout_seconds <= 0 or (
        args.command == "apply"
        and (args.validator_timeout_seconds <= 0 or not args.validator_command)
    ):
        emit(
            {
                "status": "arguments_invalid",
                "message": "timeouts must be positive and apply needs validator argv",
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
