"""Owner-only, idempotent retained staging for Session Retrospective v2."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time
from typing import Any

from . import safe_io
from .reporting import (
    RETAINED_ARTIFACT_NAMES,
    RetainedInventoryError,
    assemble_retained_artifacts,
    validate_retained_artifacts,
)


_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_IGNORED_ROOT_NAME = ".codex-local"
MAX_RETAINED_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_RETENTION_STATE_BYTES = 1024 * 1024
DEFAULT_EXPORT_RETENTION = dt.timedelta(hours=24)
MAX_EXPORT_RETENTION = dt.timedelta(hours=72)
MAX_PUBLICATION_BOUND_RETENTION = dt.timedelta(days=7)
_RETENTION_SUFFIX = ".retention-v2.json"
_RETENTION_LOCK_SUFFIX = ".retention-v2.lock"
_ATTEMPT_REF_RE = re.compile(r"attempt_ref_v2:[0-9a-f]{64}\Z")
_TEMPORARY_STAGING_RE = re.compile(
    r"\.(?P<output>.+)\.staging-(?:0|[1-9][0-9]*)-[0-9a-f]{24}\Z"
)
_GC_MAX_ENTRIES = 50_000
_GC_MAX_DEPTH = 64
_GC_MAX_PATH_BYTES = 16 * 1024 * 1024
_GC_MAX_SECONDS = 60.0
_GC_MAX_RESULT_SAMPLES = 256


class RetainedExportError(RuntimeError):
    """Base error for retained staging failures."""


class ExportLocationError(RetainedExportError):
    """Raised when staging is outside the ignored owner-only run area."""


class ExportConflictError(RetainedExportError):
    """Raised when an immutable staging path already has different content."""


class _GcBudgetExhausted(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _GcBudget:
    def __init__(self) -> None:
        self.deadline = time.monotonic() + _GC_MAX_SECONDS
        self.entries = 0
        self.path_bytes = 0
        self.max_depth = 0

    def checkpoint(self) -> None:
        if time.monotonic() >= self.deadline:
            raise _GcBudgetExhausted("deadline_exhausted")

    def observe(self, path: Path, *, depth: int) -> None:
        self.require_depth(depth)
        self.entries += 1
        self.path_bytes += len(os.fsencode(path))
        self.max_depth = max(self.max_depth, depth)
        if self.entries > _GC_MAX_ENTRIES:
            raise _GcBudgetExhausted("entry_budget_exhausted")
        if self.path_bytes > _GC_MAX_PATH_BYTES:
            raise _GcBudgetExhausted("path_byte_budget_exhausted")

    def require_depth(self, depth: int) -> None:
        self.checkpoint()
        if depth > _GC_MAX_DEPTH:
            raise _GcBudgetExhausted("depth_budget_exhausted")
        self.max_depth = max(self.max_depth, depth)


class _GcPathSamples:
    def __init__(self) -> None:
        self.count = 0
        self.values: list[str] = []

    def append(self, value: str) -> None:
        self.count += 1
        if len(self.values) < _GC_MAX_RESULT_SAMPLES:
            self.values.append(value)


def _absolute(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.realpath(os.path.abspath(os.fspath(path))))


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _ignored_root(path: Path) -> Path:
    parts = path.parts
    indices = [index for index, part in enumerate(parts) if part == _IGNORED_ROOT_NAME]
    if not indices:
        raise ExportLocationError(
            f"retained staging must be below an ignored {_IGNORED_ROOT_NAME}/ run area: {path}"
        )
    index = indices[-1]
    root = Path(*parts[: index + 1])
    if path == root:
        raise ExportLocationError(
            "retained staging cannot replace the ignored run-area root"
        )
    return root


def _assert_no_symlink_below(root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ExportLocationError(
            f"staging path escapes ignored root {root}: {path}"
        ) from exc
    current = root
    candidates = (
        root,
        *(
            root / Path(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        ),
    )
    for current in candidates:
        if not _lexists(current):
            continue
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ExportLocationError(
                f"cannot inspect staging path component {current}: {exc}"
            ) from exc
        if stat.S_ISLNK(mode):
            raise ExportLocationError(
                f"refusing symlinked staging path component: {current}"
            )


def _normalized_staging_path(
    path: str | os.PathLike[str],
    *,
    require_ignored: bool,
) -> Path:
    lexical = Path(os.path.abspath(os.fspath(path)))
    if require_ignored:
        lexical_root = _ignored_root(lexical)
        _assert_no_symlink_below(lexical_root, lexical)
    elif _lexists(lexical) and stat.S_ISLNK(lexical.lstat().st_mode):
        raise ExportLocationError(
            f"refusing symlinked retained staging path: {lexical}"
        )
    resolved = _absolute(lexical)
    if require_ignored:
        _ignored_root(resolved)
    return resolved


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    relative_parts = path.parts[1:] if path.anchor else path.parts
    for part in relative_parts:
        current = current / part
        if not _lexists(current):
            continue
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ExportLocationError(
                f"cannot inspect staging path component {current}: {exc}"
            ) from exc
        if stat.S_ISLNK(mode):
            raise ExportLocationError(
                f"refusing symlinked staging path component: {current}"
            )


def _require_owner(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RetainedInventoryError(f"cannot inspect {label} {path}: {exc}") from exc
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise RetainedInventoryError(
            f"{label} is not owned by the current user: {path}"
        )
    return metadata


def _require_directory_mode(path: Path) -> None:
    try:
        safe_io.check_owner_only_directory(path)
    except (OSError, safe_io.UnsafePathError) as exc:
        raise RetainedInventoryError(
            f"retained staging directory must be owner-only: {path}"
        ) from exc


def _require_file_mode(path: Path) -> os.stat_result:
    try:
        _normalized, parent_fd = safe_io.open_owner_only_directory(path.parent)
        try:
            descriptor = safe_io.open_checked_file_at(
                parent_fd,
                path.name,
                display_path=path,
                require_owner_only=True,
            )
            try:
                return os.fstat(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_fd)
    except (OSError, safe_io.UnsafePathError) as exc:
        raise RetainedInventoryError(
            f"retained artifact must be an owner-only regular file: {path}"
        ) from exc


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


def _normalize_instant(value: dt.datetime | str, *, label: str) -> dt.datetime:
    if isinstance(value, str):
        text = value
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = dt.datetime.fromisoformat(text)
        except ValueError as exc:
            raise RetainedExportError(
                f"{label} must be an ISO-8601 UTC instant"
            ) from exc
    elif isinstance(value, dt.datetime):
        parsed = value
    else:
        raise RetainedExportError(f"{label} must be a datetime or ISO-8601 string")
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise RetainedExportError(f"{label} must be timezone-aware UTC")
    return parsed.astimezone(dt.UTC).replace(microsecond=0)


def _format_instant(value: dt.datetime) -> str:
    return (
        value.astimezone(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _retention_path(output: Path) -> Path:
    return output.parent / f".{output.name}{_RETENTION_SUFFIX}"


def _retention_lock_path(output: Path) -> Path:
    return output.parent / f".{output.name}{_RETENTION_LOCK_SUFFIX}"


class _AnchoredExport:
    def __init__(self, output: Path, parent_fd: int) -> None:
        self.output = output
        self.parent = output.parent
        self.name = output.name
        self.parent_fd = parent_fd
        self.parent_stat = os.fstat(parent_fd)

    @classmethod
    def open(
        cls,
        output_dir: str | os.PathLike[str],
        *,
        create_parent: bool,
        require_ignored: bool = True,
    ) -> _AnchoredExport:
        output = _normalized_staging_path(
            output_dir,
            require_ignored=require_ignored,
        )
        if not output.name or output.name in {".", ".."}:
            raise ExportLocationError("retained export name is invalid")
        try:
            normalized_parent, parent_fd = safe_io.open_owner_only_directory(
                output.parent,
                create=create_parent,
            )
        except (OSError, safe_io.UnsafePathError) as exc:
            raise ExportLocationError(
                f"cannot anchor retained export parent {output.parent}: {exc}"
            ) from exc
        anchored = cls(normalized_parent / output.name, parent_fd)
        try:
            anchored.assert_current()
            return anchored
        except Exception:
            anchored.close()
            raise

    def close(self) -> None:
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def assert_current(self) -> None:
        try:
            current = os.stat(self.parent, follow_symlinks=False)
        except OSError as exc:
            raise ExportLocationError(
                "retained export parent disappeared during the operation"
            ) from exc
        if (current.st_dev, current.st_ino) != (
            self.parent_stat.st_dev,
            self.parent_stat.st_ino,
        ):
            raise ExportLocationError(
                "retained export parent changed during the operation"
            )

    def exists(self, name: str | None = None) -> bool:
        target = self.name if name is None else name
        try:
            os.stat(target, dir_fd=self.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    @contextmanager
    def lock(self) -> Any:
        lock_name = f".{self.name}{_RETENTION_LOCK_SUFFIX}"
        descriptor = safe_io.open_lock_file_at(
            self.parent_fd,
            lock_name,
            display_path=self.parent / lock_name,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self.assert_current()
            yield
            self.assert_current()
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def child_fd(self, name: str | None = None) -> int:
        target = self.name if name is None else name
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            observed = os.stat(
                target,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
            descriptor = os.open(target, flags, dir_fd=self.parent_fd)
        except OSError as exc:
            raise RetainedInventoryError(
                f"cannot anchor retained staging directory {self.parent / target}"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            safe_io.validate_owner_only_directory_descriptor(
                descriptor,
                self.parent / target,
            )
            if (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino):
                raise RetainedInventoryError(
                    "retained staging directory is not owner-only and stable"
                )
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @property
    def retention_name(self) -> str:
        return f".{self.name}{_RETENTION_SUFFIX}"


@contextmanager
def _bundle_lock(output: Path) -> Any:
    lock_path = _retention_lock_path(output)
    parent_fd: int | None = None
    descriptor: int | None = None
    try:
        _normalized, parent_fd = safe_io.open_owner_only_directory(lock_path.parent)
        descriptor = safe_io.open_lock_file_at(
            parent_fd,
            lock_path.name,
            display_path=lock_path,
        )
    except (OSError, safe_io.UnsafePathError) as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        raise RetainedExportError(
            f"cannot open retained export lock {lock_path}: {exc}"
        ) from exc
    try:
        assert descriptor is not None
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            assert parent_fd is not None
            os.close(parent_fd)


def _read_owner_only_json(path: Path) -> dict[str, Any]:
    try:
        payload = safe_io.read_bounded_bytes(
            path,
            max_bytes=MAX_RETENTION_STATE_BYTES,
            require_owner_only=True,
        )
        value = json.loads(payload.decode("ascii"))
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        safe_io.ReadLimitExceeded,
        safe_io.UnsafePathError,
    ) as exc:
        raise RetainedExportError(
            f"cannot read retained export state {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise RetainedExportError(
            f"retained export state must be a JSON object: {path}"
        )
    _validate_retention_state(value)
    return value


def _write_owner_only_json(path: Path, value: Mapping[str, Any]) -> None:
    _validate_retention_state(value)
    payload = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        safe_io.harden_created_owner_only_file_descriptor(descriptor, temporary)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, _FILE_MODE)
        safe_io.check_owner_only_file(path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _validate_retention_state(value: Mapping[str, Any]) -> None:
    expected_fields = {
        "bundle_digest",
        "exported_at",
        "publication_attempt_ref",
        "publication_heartbeat_at",
        "retention_deadline",
        "schema_version",
        "staging_dir",
        "status",
        "terminal_at",
        "terminal_disposition",
    }
    if set(value) != expected_fields or value.get("schema_version") != 2:
        raise RetainedExportError("retained export state has an unexpected shape")
    digest = value["bundle_digest"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RetainedExportError("retained export state has an invalid bundle digest")
    if (
        not isinstance(value["staging_dir"], str)
        or not Path(value["staging_dir"]).is_absolute()
    ):
        raise RetainedExportError("retained export state staging_dir must be absolute")
    exported_at = _normalize_instant(value["exported_at"], label="exported_at")
    deadline = _normalize_instant(
        value["retention_deadline"], label="retention_deadline"
    )
    if deadline <= exported_at or deadline - exported_at > MAX_EXPORT_RETENTION:
        raise RetainedExportError(
            "retained export deadline is outside the immutable policy bound"
        )
    status_value = value["status"]
    attempt_ref = value["publication_attempt_ref"]
    heartbeat_at = value["publication_heartbeat_at"]
    terminal_at = value["terminal_at"]
    terminal_disposition = value["terminal_disposition"]
    if status_value == "exported":
        if (
            attempt_ref is not None
            or heartbeat_at is not None
            or terminal_at is not None
            or terminal_disposition is not None
        ):
            raise RetainedExportError(
                "ordinary exported state cannot carry publication disposition"
            )
    elif status_value == "publication_bound":
        if (
            not isinstance(attempt_ref, str)
            or _ATTEMPT_REF_RE.fullmatch(attempt_ref) is None
            or heartbeat_at is None
            or terminal_at is not None
            or terminal_disposition is not None
        ):
            raise RetainedExportError(
                "publication-bound export has an invalid attempt reference"
            )
        heartbeat = _normalize_instant(heartbeat_at, label="publication_heartbeat_at")
        if heartbeat < exported_at:
            raise RetainedExportError("publication heartbeat predates export")
    elif status_value == "publication_terminal":
        if (
            not isinstance(attempt_ref, str)
            or _ATTEMPT_REF_RE.fullmatch(attempt_ref) is None
            or heartbeat_at is None
            or terminal_disposition not in {"aborted", "committed"}
            or terminal_at is None
        ):
            raise RetainedExportError(
                "terminal publication export has an invalid disposition"
            )
        terminal_instant = _normalize_instant(terminal_at, label="terminal_at")
        heartbeat = _normalize_instant(heartbeat_at, label="publication_heartbeat_at")
        if terminal_instant < heartbeat or heartbeat < exported_at:
            raise RetainedExportError(
                "terminal publication disposition predates its binding"
            )
    else:
        raise RetainedExportError("retained export state has an unsupported status")


def _ensure_retention_state(
    output: Path,
    *,
    bundle_digest: str,
    retention_deadline: dt.datetime | str | None,
    now: dt.datetime | None,
) -> dict[str, Any]:
    clock = _normalize_instant(now or _utc_now(), label="now")
    state_path = _retention_path(output)
    with _bundle_lock(output):
        if state_path.exists() or state_path.is_symlink():
            state = _read_owner_only_json(state_path)
            if (
                state["staging_dir"] != str(output)
                or state["bundle_digest"] != bundle_digest
            ):
                raise ExportConflictError(
                    "retained export state is bound to different staged bytes"
                )
            if retention_deadline is not None:
                requested = _format_instant(
                    _normalize_instant(retention_deadline, label="retention_deadline")
                )
                if requested != state["retention_deadline"]:
                    raise ExportConflictError(
                        "retained export deadline is immutable across retries"
                    )
            return state
        deadline = (
            _normalize_instant(retention_deadline, label="retention_deadline")
            if retention_deadline is not None
            else clock + DEFAULT_EXPORT_RETENTION
        )
        if deadline <= clock or deadline - clock > MAX_EXPORT_RETENTION:
            raise RetainedExportError(
                "retention_deadline must be within the next 72 hours"
            )
        state = {
            "bundle_digest": bundle_digest,
            "exported_at": _format_instant(clock),
            "publication_attempt_ref": None,
            "publication_heartbeat_at": None,
            "retention_deadline": _format_instant(deadline),
            "schema_version": 2,
            "staging_dir": str(output),
            "status": "exported",
            "terminal_at": None,
            "terminal_disposition": None,
        }
        _write_owner_only_json(state_path, state)
        return state


def _ensure_retention_state_at(
    anchor: _AnchoredExport,
    *,
    bundle_digest: str,
    retention_deadline: dt.datetime | str | None,
    now: dt.datetime | None,
) -> dict[str, Any]:
    clock = _normalize_instant(now or _utc_now(), label="now")
    if anchor.exists(anchor.retention_name):
        state = _read_retention_at(anchor)
        if (
            state["staging_dir"] != str(anchor.output)
            or state["bundle_digest"] != bundle_digest
        ):
            raise ExportConflictError(
                "retained export state is bound to different staged bytes"
            )
        if retention_deadline is not None:
            requested = _format_instant(
                _normalize_instant(retention_deadline, label="retention_deadline")
            )
            if requested != state["retention_deadline"]:
                raise ExportConflictError(
                    "retained export deadline is immutable across retries"
                )
        return state
    deadline = (
        _normalize_instant(retention_deadline, label="retention_deadline")
        if retention_deadline is not None
        else clock + DEFAULT_EXPORT_RETENTION
    )
    if deadline <= clock or deadline - clock > MAX_EXPORT_RETENTION:
        raise RetainedExportError("retention_deadline must be within the next 72 hours")
    state = {
        "bundle_digest": bundle_digest,
        "exported_at": _format_instant(clock),
        "publication_attempt_ref": None,
        "publication_heartbeat_at": None,
        "retention_deadline": _format_instant(deadline),
        "schema_version": 2,
        "staging_dir": str(anchor.output),
        "status": "exported",
        "terminal_at": None,
        "terminal_disposition": None,
    }
    _write_retention_at(anchor, state)
    return state


def _receipt_at(
    anchor: _AnchoredExport,
    *,
    idempotent: bool,
) -> dict[str, Any]:
    validation = _validate_at(anchor)
    retention = _read_retention_at(anchor)
    if retention["bundle_digest"] != validation["bundle_digest"]:
        raise ExportConflictError(
            "retained export state differs from the staged bundle"
        )
    return _retention_receipt_at(anchor, retention, idempotent=idempotent)


def _retention_receipt_at(
    anchor: _AnchoredExport,
    retention: Mapping[str, Any],
    *,
    idempotent: bool,
) -> dict[str, Any]:
    return {
        "artifact_names": list(RETAINED_ARTIFACT_NAMES),
        "bundle_digest": retention["bundle_digest"],
        "exported_at": retention["exported_at"],
        "git_commit_created": False,
        "idempotent": idempotent,
        "publication_attempt_ref": retention["publication_attempt_ref"],
        "publication_heartbeat_at": retention["publication_heartbeat_at"],
        "retention_deadline": retention["retention_deadline"],
        "schema_version": 2,
        "staging_dir": str(anchor.output),
        "state_advanced": False,
        "status": retention["status"],
        "terminal_at": retention["terminal_at"],
        "terminal_disposition": retention["terminal_disposition"],
    }


def _write_artifact(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, _FILE_MODE)
    try:
        os.fchmod(descriptor, _FILE_MODE)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RetainedExportError(f"short write while staging {path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_artifact_at(
    directory_fd: int,
    name: str,
    content: bytes,
    *,
    display_path: Path,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, _FILE_MODE, dir_fd=directory_fd)
    try:
        try:
            safe_io.harden_created_owner_only_file_descriptor(
                descriptor,
                display_path,
            )
        except (OSError, safe_io.UnsafePathError) as exc:
            raise RetainedExportError(
                f"cannot harden retained artifact {display_path}"
            ) from exc
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RetainedExportError(
                    f"short write while staging {display_path.name}"
                )
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_artifact_at(
    directory_fd: int,
    name: str,
    *,
    display_path: Path,
) -> bytes:
    try:
        expected = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise RetainedInventoryError(
            f"cannot inspect retained artifact {display_path}"
        ) from exc
    current_uid = getattr(os, "geteuid", lambda: expected.st_uid)()
    if (
        not stat.S_ISREG(expected.st_mode)
        or expected.st_uid != current_uid
        or stat.S_IMODE(expected.st_mode) != _FILE_MODE
        or expected.st_nlink != 1
        or expected.st_size > MAX_RETAINED_BUNDLE_BYTES
    ):
        raise RetainedInventoryError(
            f"retained artifact is not owner-only and bounded: {display_path}"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        try:
            safe_io.validate_owner_only_file_descriptor(
                descriptor,
                display_path,
                directory_fd=directory_fd,
                name=name,
            )
        except (OSError, safe_io.UnsafePathError) as exc:
            raise RetainedInventoryError(
                f"retained artifact access policy is invalid: {display_path}"
            ) from exc
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            expected.st_dev,
            expected.st_ino,
            expected.st_size,
        ):
            raise RetainedInventoryError(
                f"retained artifact changed while opened: {display_path}"
            )
        chunks: list[bytes] = []
        remaining = expected.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RetainedInventoryError(
                    f"retained artifact ended early: {display_path}"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RetainedInventoryError(
                f"retained artifact grew while read: {display_path}"
            )
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            expected.st_dev,
            expected.st_ino,
            expected.st_size,
        ):
            raise RetainedInventoryError(
                f"retained artifact changed while read: {display_path}"
            )
        try:
            safe_io.validate_owner_only_file_descriptor(
                descriptor,
                display_path,
                directory_fd=directory_fd,
                name=name,
            )
        except (OSError, safe_io.UnsafePathError) as exc:
            raise RetainedInventoryError(
                f"retained artifact access policy changed while read: {display_path}"
            ) from exc
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_exact_artifacts_at(
    anchor: _AnchoredExport,
    *,
    child_name: str | None = None,
) -> dict[str, bytes]:
    directory_fd = anchor.child_fd(child_name)
    display = anchor.output if child_name is None else anchor.parent / child_name
    try:
        names = os.listdir(directory_fd)
        if set(names) != set(RETAINED_ARTIFACT_NAMES) or len(names) != len(
            RETAINED_ARTIFACT_NAMES
        ):
            missing = sorted(set(RETAINED_ARTIFACT_NAMES) - set(names))
            extra = sorted(set(names) - set(RETAINED_ARTIFACT_NAMES))
            raise RetainedInventoryError(
                f"staged retained inventory mismatch: missing={missing}, extra={extra}"
            )
        artifacts = {
            name: _read_artifact_at(
                directory_fd,
                name,
                display_path=display / name,
            )
            for name in RETAINED_ARTIFACT_NAMES
        }
        if sum(len(value) for value in artifacts.values()) > MAX_RETAINED_BUNDLE_BYTES:
            raise RetainedInventoryError(
                "staged retained bundle exceeds the 256 MiB preparation limit"
            )
        return artifacts
    finally:
        os.close(directory_fd)


def _read_retention_at(anchor: _AnchoredExport) -> dict[str, Any]:
    payload = safe_io.read_bounded_bytes_at(
        anchor.parent_fd,
        anchor.retention_name,
        display_path=anchor.parent / anchor.retention_name,
        max_bytes=64 * 1024,
        require_owner_only=True,
    )
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetainedExportError("retained export state is invalid JSON") from exc
    if not isinstance(value, dict):
        raise RetainedExportError("retained export state must be a JSON object")
    _validate_retention_state(value)
    return value


def _write_retention_at(
    anchor: _AnchoredExport,
    value: Mapping[str, Any],
) -> None:
    _validate_retention_state(value)
    payload = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    safe_io.atomic_write_bytes_at(
        anchor.parent_fd,
        anchor.retention_name,
        payload,
        display_path=anchor.parent / anchor.retention_name,
    )


def _validate_at(anchor: _AnchoredExport) -> dict[str, Any]:
    artifacts = _read_exact_artifacts_at(anchor)
    parsed = validate_retained_artifacts(artifacts)
    return {
        "artifact_names": list(RETAINED_ARTIFACT_NAMES),
        "bundle_digest": parsed["manifest"]["retained_bundle_digest_v2"]["value"],
        "manifest": parsed["manifest"],
        "schema_version": 2,
        "staging_dir": str(anchor.output),
    }


def _validate_in_memory_inventory(
    artifacts: Mapping[str, bytes],
) -> dict[str, bytes]:
    if not isinstance(artifacts, Mapping):
        raise RetainedInventoryError("retained artifacts must be a mapping")
    if set(artifacts) != set(RETAINED_ARTIFACT_NAMES):
        missing = sorted(set(RETAINED_ARTIFACT_NAMES) - set(artifacts))
        extra = sorted(set(artifacts) - set(RETAINED_ARTIFACT_NAMES))
        raise RetainedInventoryError(
            f"retained inventory mismatch: missing={missing}, extra={extra}"
        )
    expected: dict[str, bytes] = {}
    total_bytes = 0
    for name in RETAINED_ARTIFACT_NAMES:
        content = artifacts[name]
        if not isinstance(content, bytes):
            raise RetainedInventoryError(f"{name} must be immutable bytes")
        if len(content) > MAX_RETAINED_BUNDLE_BYTES:
            raise RetainedInventoryError(
                f"{name} exceeds the 256 MiB per-artifact preparation limit"
            )
        total_bytes += len(content)
        if total_bytes > MAX_RETAINED_BUNDLE_BYTES:
            raise RetainedInventoryError(
                "retained bundle exceeds the 256 MiB preparation limit: "
                f"{total_bytes} bytes"
            )
        expected[name] = content
    return expected


def _read_bounded_artifact(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RetainedInventoryError(
            f"cannot open retained artifact {path}: {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            expected.st_dev,
            expected.st_ino,
            expected.st_size,
        ):
            raise RetainedInventoryError(
                f"retained artifact changed before it was read: {path}"
            )
        content = bytearray()
        remaining = expected.st_size + 1
        while remaining:
            try:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
            except OSError as exc:
                raise RetainedInventoryError(
                    f"cannot read retained artifact {path}: {exc}"
                ) from exc
            if not chunk:
                break
            content.extend(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            expected.st_dev,
            expected.st_ino,
            expected.st_size,
        ) or len(content) != expected.st_size:
            raise RetainedInventoryError(
                f"retained artifact changed while it was read: {path}"
            )
        return bytes(content)
    finally:
        os.close(descriptor)


def _read_exact_artifacts(path: Path) -> dict[str, bytes]:
    _require_directory_mode(path)
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        raise RetainedInventoryError(
            f"cannot enumerate retained staging directory {path}: {exc}"
        ) from exc
    actual_names = [entry.name for entry in entries]
    if set(actual_names) != set(RETAINED_ARTIFACT_NAMES) or len(actual_names) != len(
        RETAINED_ARTIFACT_NAMES
    ):
        missing = sorted(set(RETAINED_ARTIFACT_NAMES) - set(actual_names))
        extra = sorted(set(actual_names) - set(RETAINED_ARTIFACT_NAMES))
        raise RetainedInventoryError(
            f"staged retained inventory mismatch: missing={missing}, extra={extra}"
        )

    entries_by_name = {entry.name: entry for entry in entries}
    metadata = {
        name: _require_file_mode(entries_by_name[name])
        for name in RETAINED_ARTIFACT_NAMES
    }
    oversized = sorted(
        name
        for name, item in metadata.items()
        if item.st_size > MAX_RETAINED_BUNDLE_BYTES
    )
    if oversized:
        raise RetainedInventoryError(
            f"staged retained artifacts exceed the per-file limit: {oversized}"
        )
    if sum(item.st_size for item in metadata.values()) > MAX_RETAINED_BUNDLE_BYTES:
        raise RetainedInventoryError(
            "staged retained bundle exceeds the 256 MiB preparation limit"
        )

    artifacts: dict[str, bytes] = {}
    for name in RETAINED_ARTIFACT_NAMES:
        entry = entries_by_name[name]
        before = metadata[name]
        content = _read_bounded_artifact(entry, before)
        after = _require_file_mode(entry)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise RetainedInventoryError(
                f"retained artifact changed while it was read: {entry}"
            )
        if len(content) != before.st_size:
            raise RetainedInventoryError(
                f"retained artifact size changed while it was read: {entry}"
            )
        artifacts[name] = content
    return artifacts


def validate_staged_export(
    output_dir: str | os.PathLike[str],
    *,
    require_ignored: bool = True,
) -> dict[str, Any]:
    """Validate filesystem ownership/inventory and all retained bundle bytes."""

    anchor = _AnchoredExport.open(
        output_dir,
        create_parent=False,
        require_ignored=require_ignored,
    )
    try:
        result = _validate_at(anchor)
        retention = _read_retention_at(anchor)
        if (
            retention["bundle_digest"] != result["bundle_digest"]
            or retention["staging_dir"] != result["staging_dir"]
        ):
            raise ExportConflictError(
                "retained export state differs from the staged bundle"
            )
        result.update(
            {
                "exported_at": retention["exported_at"],
                "retention_deadline": retention["retention_deadline"],
                "status": retention["status"],
            }
        )
        anchor.assert_current()
        return result
    finally:
        anchor.close()


def _same_artifacts(output: Path, expected: Mapping[str, bytes]) -> bool:
    actual = _read_exact_artifacts(output)
    validate_retained_artifacts(actual)
    return all(actual[name] == expected[name] for name in RETAINED_ARTIFACT_NAMES)


def _receipt(output: Path, *, idempotent: bool) -> dict[str, Any]:
    validation = validate_staged_export(output)
    retention = _read_owner_only_json(_retention_path(output))
    return {
        "artifact_names": validation["artifact_names"],
        "bundle_digest": validation["bundle_digest"],
        "exported_at": retention["exported_at"],
        "git_commit_created": False,
        "idempotent": idempotent,
        "publication_attempt_ref": retention["publication_attempt_ref"],
        "publication_heartbeat_at": retention["publication_heartbeat_at"],
        "retention_deadline": retention["retention_deadline"],
        "schema_version": 2,
        "staging_dir": str(output),
        "state_advanced": False,
        "status": retention["status"],
        "terminal_at": retention["terminal_at"],
        "terminal_disposition": retention["terminal_disposition"],
    }


def stage_retained_artifacts(
    output_dir: str | os.PathLike[str],
    artifacts: Mapping[str, bytes],
    *,
    retention_deadline: dt.datetime | str | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Atomically stage one immutable eight-artifact bundle.

    Identical retries return without rewriting any file.  A different bundle at
    the same destination is an explicit conflict, never an in-place update.
    """

    expected = _validate_in_memory_inventory(artifacts)
    validate_retained_artifacts(artifacts)
    anchor = _AnchoredExport.open(output_dir, create_parent=True)
    temporary_name: str | None = None
    try:
        with anchor.lock():
            if anchor.exists():
                actual = _read_exact_artifacts_at(anchor)
                validate_retained_artifacts(actual)
                if actual != expected:
                    raise ExportConflictError(
                        "retained staging path already contains a different bundle: "
                        f"{anchor.output}"
                    )
                validation = _validate_at(anchor)
                _ensure_retention_state_at(
                    anchor,
                    bundle_digest=validation["bundle_digest"],
                    retention_deadline=retention_deadline,
                    now=now,
                )
                return _receipt_at(anchor, idempotent=True)
            temporary_name = (
                f".{anchor.name}.staging-{os.getpid()}-{secrets.token_hex(12)}"
            )
            os.mkdir(
                temporary_name,
                _DIRECTORY_MODE,
                dir_fd=anchor.parent_fd,
            )
            temporary_fd = anchor.child_fd(temporary_name)
            try:
                for name in RETAINED_ARTIFACT_NAMES:
                    _write_artifact_at(
                        temporary_fd,
                        name,
                        expected[name],
                        display_path=anchor.parent / temporary_name / name,
                    )
                os.fsync(temporary_fd)
            finally:
                os.close(temporary_fd)
            staged = _read_exact_artifacts_at(anchor, child_name=temporary_name)
            validate_retained_artifacts(staged)
            if staged != expected:
                raise ExportConflictError(
                    "temporary retained export bytes changed before installation"
                )
            os.rename(
                temporary_name,
                anchor.name,
                src_dir_fd=anchor.parent_fd,
                dst_dir_fd=anchor.parent_fd,
            )
            temporary_name = None
            os.fsync(anchor.parent_fd)
            validation = _validate_at(anchor)
            _ensure_retention_state_at(
                anchor,
                bundle_digest=validation["bundle_digest"],
                retention_deadline=retention_deadline,
                now=now,
            )
            return _receipt_at(anchor, idempotent=False)
    except (OSError, safe_io.UnsafePathError) as exc:
        raise RetainedExportError(
            f"failed to stage retained bundle at {anchor.output}: {exc}"
        ) from exc
    finally:
        if temporary_name is not None:
            try:
                safe_io.secure_remove_tree_at(
                    anchor.parent_fd,
                    temporary_name,
                    display_path=anchor.parent / temporary_name,
                )
            except (OSError, safe_io.UnsafePathError):
                pass
        anchor.close()


def export_retained_bundle(
    output_dir: str | os.PathLike[str],
    run_state: Mapping[str, Any],
    review_data: Mapping[str, Any],
    *,
    prior_period: Mapping[str, Any] | None = None,
    retention_deadline: dt.datetime | str | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Assemble and stage retained output without committing or advancing state."""

    output = _normalized_staging_path(output_dir, require_ignored=True)
    artifacts = assemble_retained_artifacts(
        run_state, review_data, prior_period=prior_period
    )
    return stage_retained_artifacts(
        output,
        artifacts,
        retention_deadline=retention_deadline,
        now=now,
    )


def export_run_staging(
    run_dir: str | os.PathLike[str],
    run_state: Mapping[str, Any],
    review_data: Mapping[str, Any],
    *,
    prior_period: Mapping[str, Any] | None = None,
    staging_name: str = "retained-v2",
    retention_deadline: dt.datetime | str | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Use the conventional owner-only publication-staging child of a run."""

    if not staging_name or Path(staging_name).name != staging_name:
        raise ExportLocationError("staging_name must be one safe path component")
    output = (
        Path(os.path.abspath(os.fspath(run_dir))) / "publication-staging" / staging_name
    )
    return export_retained_bundle(
        output,
        run_state,
        review_data,
        prior_period=prior_period,
        retention_deadline=retention_deadline,
        now=now,
    )


def bind_staged_export(
    output_dir: str | os.PathLike[str],
    attempt_ref: str,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Bind ordinary export retention to one durable publication attempt."""

    if _ATTEMPT_REF_RE.fullmatch(attempt_ref) is None:
        raise RetainedExportError(
            "attempt_ref must be an opaque v2 publication attempt reference"
        )
    anchor = _AnchoredExport.open(output_dir, create_parent=False)
    try:
        with anchor.lock():
            state = _read_retention_at(anchor)
            if state["staging_dir"] != str(anchor.output):
                raise ExportConflictError(
                    "retained export state names another staging directory"
                )
            validation = _validate_at(anchor)
            if state["bundle_digest"] != validation["bundle_digest"] or state[
                "staging_dir"
            ] != str(anchor.output):
                raise ExportConflictError(
                    "retained export state no longer matches staged bytes"
                )
            clock = _normalize_instant(now or _utc_now(), label="now")
            if state["status"] == "publication_terminal":
                if state["publication_attempt_ref"] != attempt_ref:
                    raise ExportConflictError(
                        "retained export is already bound to another attempt"
                    )
                return _receipt_at(anchor, idempotent=True)
            if state["status"] == "publication_bound":
                if state["publication_attempt_ref"] != attempt_ref:
                    raise ExportConflictError(
                        "retained export is already bound to another attempt"
                    )
                heartbeat = _normalize_instant(
                    state["publication_heartbeat_at"],
                    label="publication_heartbeat_at",
                )
                if clock < heartbeat:
                    raise RetainedExportError(
                        "publication resume clock predates its heartbeat"
                    )
                if clock >= heartbeat + MAX_PUBLICATION_BOUND_RETENTION:
                    raise RetainedExportError(
                        "expired publication-bound export cannot be resumed"
                    )
                if clock != heartbeat:
                    updated = dict(state)
                    updated["publication_heartbeat_at"] = _format_instant(clock)
                    _write_retention_at(anchor, updated)
                return _receipt_at(anchor, idempotent=True)
            deadline = _normalize_instant(
                state["retention_deadline"], label="retention_deadline"
            )
            if clock >= deadline:
                raise RetainedExportError(
                    "expired retained export cannot enter publication"
                )
            updated = dict(state)
            updated["publication_attempt_ref"] = attempt_ref
            updated["publication_heartbeat_at"] = _format_instant(clock)
            updated["status"] = "publication_bound"
            _write_retention_at(anchor, updated)
            return _receipt_at(anchor, idempotent=False)
    finally:
        anchor.close()


def _release_staged_export(
    output_dir: str | os.PathLike[str],
    attempt_ref: str,
    disposition: str,
    *,
    now: dt.datetime | None = None,
    require_bound: bool,
    allow_collected: bool = False,
) -> dict[str, Any]:
    if _ATTEMPT_REF_RE.fullmatch(attempt_ref) is None:
        raise RetainedExportError(
            "attempt_ref must be an opaque v2 publication attempt reference"
        )
    if disposition not in {"aborted", "committed"}:
        raise RetainedExportError(
            "terminal retained export disposition must be aborted or committed"
        )
    anchor = _AnchoredExport.open(output_dir, create_parent=False)
    try:
        with anchor.lock():
            bundle_present = anchor.exists()
            retention_present = anchor.exists(anchor.retention_name)
            if allow_collected and not bundle_present and not retention_present:
                return {
                    "idempotent": True,
                    "publication_attempt_ref": attempt_ref,
                    "schema_version": 2,
                    "staging_dir": str(anchor.output),
                    "status": "collected",
                    "terminal_disposition": disposition,
                }
            if bundle_present != retention_present:
                raise ExportConflictError(
                    "retained export bundle and retention state presence differ"
                )
            state = _read_retention_at(anchor)
            if state["staging_dir"] != str(anchor.output):
                raise ExportConflictError(
                    "retained export state names another staging directory"
                )
            if state["status"] == "exported" and not require_bound:
                return _retention_receipt_at(anchor, state, idempotent=True)
            validation = _validate_at(anchor)
            if state["bundle_digest"] != validation["bundle_digest"] or state[
                "staging_dir"
            ] != str(anchor.output):
                raise ExportConflictError(
                    "retained export state no longer matches staged bytes"
                )
            if state["publication_attempt_ref"] != attempt_ref:
                raise ExportConflictError(
                    "retained export terminal disposition names another attempt"
                )
            if state["status"] == "publication_terminal":
                if state["terminal_disposition"] != disposition:
                    raise ExportConflictError(
                        "retained export already has another terminal disposition"
                    )
                return _receipt_at(anchor, idempotent=True)
            if state["status"] != "publication_bound":
                raise RetainedExportError(
                    "only a publication-bound export can become terminal"
                )
            clock = _normalize_instant(now or _utc_now(), label="now")
            heartbeat = _normalize_instant(
                state["publication_heartbeat_at"],
                label="publication_heartbeat_at",
            )
            if clock < heartbeat:
                raise RetainedExportError(
                    "publication terminal disposition predates its heartbeat"
                )
            updated = dict(state)
            updated["status"] = "publication_terminal"
            updated["terminal_at"] = _format_instant(clock)
            updated["terminal_disposition"] = disposition
            _write_retention_at(anchor, updated)
            return _receipt_at(anchor, idempotent=False)
    finally:
        anchor.close()


def release_staged_export(
    output_dir: str | os.PathLike[str],
    attempt_ref: str,
    disposition: str,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Record an attempt-bound terminal disposition so local bytes can be reaped."""

    return _release_staged_export(
        output_dir,
        attempt_ref,
        disposition,
        now=now,
        require_bound=True,
    )


def release_staged_export_if_bound(
    output_dir: str | os.PathLike[str],
    attempt_ref: str,
    disposition: str,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Release this attempt's binding, or leave an ordinary export unchanged."""

    return _release_staged_export(
        output_dir,
        attempt_ref,
        disposition,
        now=now,
        require_bound=False,
    )


def release_committed_staged_export(
    output_dir: str | os.PathLike[str],
    attempt_ref: str,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Release committed bytes after the run checkpoint, tolerating completed GC."""

    return _release_staged_export(
        output_dir,
        attempt_ref,
        "committed",
        now=now,
        require_bound=True,
        allow_collected=True,
    )


def _orphan_expired(metadata: os.stat_result, clock: dt.datetime) -> bool:
    modified = dt.datetime.fromtimestamp(metadata.st_mtime, tz=dt.UTC)
    return clock >= modified + MAX_EXPORT_RETENTION


def _bounded_artifact_names(directory_fd: int) -> list[str] | None:
    names: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if len(names) >= len(RETAINED_ARTIFACT_NAMES):
                return None
            names.append(entry.name)
    return names


def _temporary_staging_metadata(
    anchor: _AnchoredExport,
    temporary_name: str,
) -> os.stat_result | None:
    try:
        descriptor = anchor.child_fd(temporary_name)
    except RetainedInventoryError:
        return None
    try:
        before = os.fstat(descriptor)
        names = _bounded_artifact_names(descriptor)
        if (
            names is None
            or len(names) != len(set(names))
            or not set(names).issubset(RETAINED_ARTIFACT_NAMES)
        ):
            return None
        total_bytes = 0
        current_uid = getattr(os, "geteuid", lambda: before.st_uid)()
        for name in names:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != current_uid
                or stat.S_IMODE(metadata.st_mode) != _FILE_MODE
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_RETAINED_BUNDLE_BYTES
            ):
                return None
            total_bytes += metadata.st_size
            if total_bytes > MAX_RETAINED_BUNDLE_BYTES:
                return None
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
        ):
            raise ExportConflictError(
                "temporary retained export changed during orphan inspection"
            )
        return after
    finally:
        os.close(descriptor)


def _collect_temporary_orphan(
    directory_fd: int,
    current: Path,
    name: str,
    *,
    budget: _GcBudget,
    clock: dt.datetime,
    deleted: _GcPathSamples,
    retained: _GcPathSamples,
) -> bool:
    budget.checkpoint()
    match = _TEMPORARY_STAGING_RE.fullmatch(name)
    if match is None:
        return False
    output_name = match.group("output")
    if not output_name or Path(output_name).name != output_name:
        return False
    anchor = _AnchoredExport(current / output_name, os.dup(directory_fd))
    temporary_path = current / name
    try:
        with anchor.lock():
            if not anchor.exists(name):
                return True
            metadata = _temporary_staging_metadata(anchor, name)
            if metadata is None:
                return False
            if not _orphan_expired(metadata, clock):
                retained.append(str(temporary_path))
                return True
            budget.checkpoint()
            safe_io.secure_remove_tree_at(
                anchor.parent_fd,
                name,
                display_path=temporary_path,
            )
            os.fsync(anchor.parent_fd)
            deleted.append(str(temporary_path))
            return True
    finally:
        anchor.close()


def _collect_installed_orphan(
    directory_fd: int,
    current: Path,
    name: str,
    *,
    budget: _GcBudget,
    clock: dt.datetime,
    deleted: _GcPathSamples,
    retained: _GcPathSamples,
) -> bool:
    budget.checkpoint()
    anchor = _AnchoredExport(current / name, os.dup(directory_fd))
    try:
        descriptor = anchor.child_fd()
        try:
            initial_names = _bounded_artifact_names(descriptor)
        finally:
            os.close(descriptor)
        if (
            initial_names is None
            or set(initial_names) != set(RETAINED_ARTIFACT_NAMES)
            or len(initial_names) != len(RETAINED_ARTIFACT_NAMES)
        ):
            return False
        with anchor.lock():
            if anchor.exists(anchor.retention_name):
                retained.append(str(anchor.output))
                return True
            if not anchor.exists():
                return True
            descriptor = anchor.child_fd()
            try:
                directory_names = _bounded_artifact_names(descriptor)
                metadata = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (
                directory_names is None
                or set(directory_names) != set(RETAINED_ARTIFACT_NAMES)
                or len(directory_names) != len(RETAINED_ARTIFACT_NAMES)
            ):
                raise ExportConflictError(
                    "installed retained orphan inventory changed during GC inspection"
                )
            _validate_at(anchor)
            budget.checkpoint()
            current_metadata = os.stat(
                anchor.name,
                dir_fd=anchor.parent_fd,
                follow_symlinks=False,
            )
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mtime_ns,
            ) != (
                current_metadata.st_dev,
                current_metadata.st_ino,
                current_metadata.st_mtime_ns,
            ):
                raise ExportConflictError(
                    "installed retained orphan changed during GC inspection"
                )
            if not _orphan_expired(metadata, clock):
                retained.append(str(anchor.output))
                return True
            if anchor.exists(anchor.retention_name):
                retained.append(str(anchor.output))
                return True
            budget.checkpoint()
            safe_io.secure_remove_tree_at(
                anchor.parent_fd,
                anchor.name,
                display_path=anchor.output,
            )
            os.fsync(anchor.parent_fd)
            deleted.append(str(anchor.output))
            return True
    finally:
        anchor.close()


def _bounded_gc_names(
    directory_fd: int,
    current: Path,
    *,
    budget: _GcBudget,
    depth: int,
) -> list[str]:
    budget.require_depth(depth)
    names: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            budget.observe(current / entry.name, depth=depth + 1)
            names.append(entry.name)
    budget.checkpoint()
    return sorted(names, key=os.fsencode)


def _garbage_collect_directory(
    directory_fd: int,
    current: Path,
    *,
    budget: _GcBudget,
    clock: dt.datetime,
    deleted: _GcPathSamples,
    retained: _GcPathSamples,
    depth: int,
) -> list[str]:
    names = _bounded_gc_names(
        directory_fd,
        current,
        budget=budget,
        depth=depth,
    )
    retention_names = [name for name in names if name.endswith(_RETENTION_SUFFIX)]
    bundle_names: set[str] = set()
    for state_name in retention_names:
        budget.checkpoint()
        if not state_name.startswith("."):
            raise RetainedExportError(
                "retained export state filename is not bundle-bound"
            )
        output_name = state_name[1 : -len(_RETENTION_SUFFIX)]
        if not output_name or Path(output_name).name != output_name:
            raise RetainedExportError(
                "retained export state filename has an invalid bundle name"
            )
        bundle_names.add(output_name)
        anchor = _AnchoredExport(current / output_name, os.dup(directory_fd))
        try:
            with anchor.lock():
                state = _read_retention_at(anchor)
                if state["staging_dir"] != str(anchor.output):
                    raise RetainedExportError(
                        "retained export state filename/path binding is invalid"
                    )
                deadline = _normalize_instant(
                    state["retention_deadline"], label="retention_deadline"
                )
                terminal_at = (
                    None
                    if state["terminal_at"] is None
                    else _normalize_instant(state["terminal_at"], label="terminal_at")
                )
                if state["status"] == "publication_bound":
                    # Only the attempt owner can recover or terminate a bound
                    # publication. GC has no transaction authority and must
                    # retain the exact bundle until an authenticated terminal
                    # disposition is persisted.
                    retained.append(str(anchor.output))
                    continue
                eligible = (state["status"] == "exported" and clock >= deadline) or (
                    state["status"] == "publication_terminal"
                    and terminal_at is not None
                    and clock >= terminal_at
                )
                if not eligible:
                    retained.append(str(anchor.output))
                    continue
                if anchor.exists():
                    validation = _validate_at(anchor)
                    budget.checkpoint()
                    if validation["bundle_digest"] != state["bundle_digest"]:
                        raise ExportConflictError(
                            "expired retained export bytes changed before GC"
                        )
                if _read_retention_at(anchor) != state:
                    raise ExportConflictError(
                        "retained export state changed before GC deletion"
                    )
                if anchor.exists():
                    budget.checkpoint()
                    safe_io.secure_remove_tree_at(
                        anchor.parent_fd,
                        anchor.name,
                        display_path=anchor.output,
                    )
                safe_io.read_bounded_bytes_at(
                    anchor.parent_fd,
                    anchor.retention_name,
                    display_path=anchor.parent / anchor.retention_name,
                    max_bytes=64 * 1024,
                    require_owner_only=True,
                )
                os.unlink(anchor.retention_name, dir_fd=anchor.parent_fd)
                os.fsync(anchor.parent_fd)
                deleted.append(str(anchor.output))
        finally:
            anchor.close()
    child_names: list[str] = []
    for name in names:
        budget.checkpoint()
        if name in bundle_names:
            continue
        if name.startswith("."):
            _collect_temporary_orphan(
                directory_fd,
                current,
                name,
                budget=budget,
                clock=clock,
                deleted=deleted,
                retained=retained,
            )
            continue
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        if _collect_installed_orphan(
            directory_fd,
            current,
            name,
            budget=budget,
            clock=clock,
            deleted=deleted,
            retained=retained,
        ):
            continue
        child_names.append(name)
    return child_names


def _garbage_collect_iterative(
    directory_fd: int,
    current: Path,
    *,
    budget: _GcBudget,
    clock: dt.datetime,
    deleted: _GcPathSamples,
    retained: _GcPathSamples,
) -> None:
    stack: list[dict[str, Any]] = []

    def push(parent_fd: int, path: Path, depth: int, name: str | None) -> None:
        budget.require_depth(depth)
        if name is None:
            child_fd = os.dup(parent_fd)
        else:
            anchor = _AnchoredExport(path / ".gc-anchor", os.dup(parent_fd))
            try:
                child_fd = anchor.child_fd(name)
            finally:
                anchor.close()
        try:
            children = _garbage_collect_directory(
                child_fd,
                path,
                budget=budget,
                clock=clock,
                deleted=deleted,
                retained=retained,
                depth=depth,
            )
        except BaseException:
            os.close(child_fd)
            raise
        stack.append(
            {
                "children": children,
                "depth": depth,
                "directory_fd": child_fd,
                "index": 0,
                "path": path,
            }
        )

    push(directory_fd, current, 0, None)
    try:
        while stack:
            budget.checkpoint()
            frame = stack[-1]
            index = frame["index"]
            if index >= len(frame["children"]):
                os.close(frame["directory_fd"])
                stack.pop()
                continue
            name = frame["children"][index]
            frame["index"] = index + 1
            push(
                frame["directory_fd"],
                frame["path"] / name,
                frame["depth"] + 1,
                name,
            )
    finally:
        for frame in stack:
            os.close(frame["directory_fd"])


def _gc_receipt(
    *,
    budget: _GcBudget,
    deleted: _GcPathSamples,
    retained: _GcPathSamples,
    incomplete_reason: str | None,
) -> dict[str, Any]:
    return {
        "budget": {
            "deadline_seconds": _GC_MAX_SECONDS,
            "entries_limit": _GC_MAX_ENTRIES,
            "entries_observed": budget.entries,
            "max_depth_limit": _GC_MAX_DEPTH,
            "max_depth_observed": budget.max_depth,
            "path_bytes_limit": _GC_MAX_PATH_BYTES,
            "path_bytes_observed": budget.path_bytes,
            "result_sample_limit": _GC_MAX_RESULT_SAMPLES,
        },
        "deleted": sorted(deleted.values),
        "deleted_count": deleted.count,
        "deleted_truncated": deleted.count > len(deleted.values),
        "incomplete_reason": incomplete_reason,
        "retained": sorted(retained.values),
        "retained_count": retained.count,
        "retained_truncated": retained.count > len(retained.values),
        "schema_version": 3,
        "status": "incomplete" if incomplete_reason else "complete",
    }


def garbage_collect_expired_exports(
    root_dir: str | os.PathLike[str],
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Delete eligible exports under one bounded descriptor-anchored traversal."""

    budget = _GcBudget()
    deleted = _GcPathSamples()
    retained = _GcPathSamples()
    root = Path(os.path.abspath(os.fspath(root_dir)))
    if not os.path.lexists(root):
        return _gc_receipt(
            budget=budget,
            deleted=deleted,
            retained=retained,
            incomplete_reason=None,
        )
    root = _normalized_staging_path(root, require_ignored=True)
    clock = _normalize_instant(now or _utc_now(), label="now")
    normalized_root, root_fd = safe_io.open_owner_only_directory(root)
    root_stat = os.fstat(root_fd)
    incomplete_reason: str | None = None
    try:
        try:
            _garbage_collect_iterative(
                root_fd,
                normalized_root,
                budget=budget,
                clock=clock,
                deleted=deleted,
                retained=retained,
            )
        except _GcBudgetExhausted as exc:
            incomplete_reason = exc.reason
        current = os.stat(normalized_root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (root_stat.st_dev, root_stat.st_ino):
            raise ExportLocationError("retained export GC root changed during GC")
    finally:
        os.close(root_fd)
    return _gc_receipt(
        budget=budget,
        deleted=deleted,
        retained=retained,
        incomplete_reason=incomplete_reason,
    )
