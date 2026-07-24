#!/usr/bin/env python3
"""Apply a validated default.rules candidate with bound recovery evidence."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
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
import tempfile
import time


SCHEMA_VERSION = 1
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
        )

    @classmethod
    def from_json(cls, value: object, *, label: str) -> Snapshot:
        if not isinstance(value, dict):
            raise TransactionError("receipt_invalid", f"{label} is not an object")
        identity = value.get("identity")
        content = value.get("content")
        access = value.get("access_policy")
        if not all(isinstance(item, dict) for item in (identity, content, access)):
            raise TransactionError(
                "receipt_invalid",
                f"{label} is missing a protected-property group",
            )
        assert isinstance(identity, dict)
        assert isinstance(content, dict)
        assert isinstance(access, dict)
        fields = {
            "device": identity.get("device"),
            "inode": identity.get("inode"),
            "size": content.get("size"),
            "sha256": content.get("sha256"),
            "mode": access.get("mode"),
            "uid": access.get("uid"),
            "gid": access.get("gid"),
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
    return mismatches


def content_and_access_match(expected: Snapshot, actual: Snapshot) -> bool:
    return (
        expected.size == actual.size
        and hmac.compare_digest(expected.sha256, actual.sha256)
        and (expected.mode, expected.uid, expected.gid)
        == (actual.mode, actual.uid, actual.gid)
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
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise TransactionError(
                f"{label}_not_regular",
                f"{label} is not a regular file",
            )
        first = read_fd(fd, label=label, max_bytes=max_bytes)
        second = read_fd(fd, label=label, max_bytes=max_bytes)
        after = os.fstat(fd)
    finally:
        os.close(fd)

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
    if (path_stat.st_dev, path_stat.st_ino) != (after.st_dev, after.st_ino):
        raise TransactionError(
            f"{label}_identity_changed",
            f"{label} path was replaced after it was read",
        )
    path_access = (
        stat.S_IMODE(path_stat.st_mode),
        path_stat.st_uid,
        path_stat.st_gid,
    )
    if path_access != after_access:
        raise TransactionError(
            f"{label}_access_policy_changed",
            f"{label} access policy changed after it was read",
        )
    return second, Snapshot.from_stat(after, second)


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
    flags = (
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags, 0o600)
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
    except BaseException:
        os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    os.close(fd)
    _written, snapshot = read_stable(path, label="staged_file")
    return snapshot


def set_policy(path: Path, expected: Snapshot, policy: Snapshot) -> Snapshot:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before_payload = read_fd(fd, label="staged_file", max_bytes=MAX_RULES_BYTES)
        before = Snapshot.from_stat(os.fstat(fd), before_payload)
        mismatches = property_mismatches(expected, before)
        if mismatches:
            raise TransactionError(
                "private_candidate_changed",
                "staged file changed before access-policy update",
                details={"mismatched_properties": mismatches},
            )
        if policy.uid != os.geteuid():
            raise TransactionError(
                "unsupported_rules_owner",
                "live rules are not owned by the current user",
            )
        os.fchown(fd, policy.uid, policy.gid)
        os.fchmod(fd, policy.mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    _payload, snapshot = read_stable(path, label="staged_file")
    if (
        (snapshot.device, snapshot.inode) != (expected.device, expected.inode)
        or snapshot.size != expected.size
        or not hmac.compare_digest(snapshot.sha256, expected.sha256)
    ):
        raise TransactionError(
            "private_candidate_changed",
            "staged identity or content changed while applying access policy",
            details={"mismatched_properties": ["object_identity", "content"]},
        )
    return snapshot


class PrivateStage:
    def __init__(self, rules_parent: Path) -> None:
        self.path = Path(tempfile.mkdtemp(prefix=".rules-apply-", dir=rules_parent))
        self.path.chmod(0o700)
        stage_stat = self.path.stat()
        if (
            not stat.S_ISDIR(stage_stat.st_mode)
            or stage_stat.st_uid != os.geteuid()
            or stat.S_IMODE(stage_stat.st_mode) != 0o700
        ):
            raise TransactionError(
                "private_stage_invalid",
                "staging directory is not owner-only",
            )
        self.files: dict[Path, Snapshot] = {}

    def create(self, name: str, payload: bytes) -> tuple[Path, Snapshot]:
        path = self.path / name
        snapshot = write_exclusive(path, payload)
        file_stat = path.stat()
        if (
            file_stat.st_nlink != 1
            or snapshot.uid != os.geteuid()
            or snapshot.mode != 0o600
        ):
            raise TransactionError(
                "private_candidate_invalid",
                "staged file is not an owner-only, single-link regular file",
            )
        self.files[path] = snapshot
        return path, snapshot

    def update_snapshot(self, path: Path, snapshot: Snapshot) -> None:
        self.files[path] = snapshot

    def validate(self, path: Path, expected: Snapshot, *, label: str) -> Snapshot:
        _payload, actual = read_stable(path, label=label)
        mismatches = property_mismatches(expected, actual)
        if mismatches:
            raise TransactionError(
                f"{label}_changed",
                f"{label} changed after staging",
                details={"mismatched_properties": mismatches},
            )
        return actual

    def move_to(self, path: Path, target: Path) -> Snapshot:
        expected = self.files[path]
        self.validate(path, expected, label="private_candidate")
        os.replace(path, target)
        self.files.pop(path, None)
        return expected

    def publish_backup(self, path: Path, backup: Path) -> Snapshot:
        expected = self.files[path]
        try:
            os.link(path, backup, follow_symlinks=False)
        except FileExistsError as error:
            raise TransactionError(
                "backup_exists",
                f"backup already exists: {backup}",
            ) from error
        path.unlink()
        self.files.pop(path, None)
        _payload, actual = read_stable(backup, label="backup")
        mismatches = property_mismatches(expected, actual)
        if mismatches:
            raise TransactionError(
                "backup_changed",
                "published backup does not match the bound original",
                details={"mismatched_properties": mismatches},
            )
        return actual

    def cleanup(self) -> list[str]:
        warnings: list[str] = []
        for path, expected in list(self.files.items()):
            try:
                _payload, actual = read_stable(path, label="private_cleanup")
                if property_mismatches(expected, actual):
                    warnings.append(f"left changed staged file: {path}")
                    continue
                path.unlink()
                self.files.pop(path, None)
            except TransactionError as error:
                warnings.append(str(error))
            except OSError as error:
                warnings.append(f"private cleanup failed for {path}: {error}")
        try:
            self.path.rmdir()
        except OSError as error:
            warnings.append(f"retained staging directory {self.path}: {error}")
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
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
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
        rollback_snapshot = set_policy(rollback_path, rollback_snapshot, original)
        stage.update_snapshot(rollback_path, rollback_snapshot)
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
        restored_expected = stage.move_to(rollback_path, rules)
        fsync_file_and_parent(rules)
        _restored_bytes, restored = read_stable(rules, label="live_rules")
        if property_mismatches(
            restored_expected, restored
        ) or not content_and_access_match(
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
        return False, {
            "rollback_status": (
                error.status
                if isinstance(error, TransactionError)
                else "rollback_failed"
            ),
            "rollback_message": str(error),
        }


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
            backup_stage_snapshot = set_policy(
                backup_stage,
                backup_stage_snapshot,
                current,
            )
            stage.update_snapshot(backup_stage, backup_stage_snapshot)
            backup_snapshot = stage.publish_backup(backup_stage, backup)
            fsync_directory(rules.parent)

            installed_snapshot = set_policy(candidate, candidate_snapshot, current)
            stage.update_snapshot(candidate, installed_snapshot)
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

            installed_expected = stage.move_to(candidate, rules)
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
    )
    original = Snapshot.from_json(receipt.get("original"), label="original")
    installed = Snapshot.from_json(receipt.get("installed"), label="installed")
    backup_expected = Snapshot.from_json(receipt.get("backup"), label="backup")
    parent_actual = directory_snapshot(rules.parent)
    parent_mismatches = property_mismatches(parent_expected, parent_actual)
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
        if content_and_access_match(original, live):
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
