from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
from functools import lru_cache
import hashlib
import hmac
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

from .contracts import (
    JsonValue,
    StrictJsonError,
    canonical_json_bytes,
    strict_json_loads,
)


OWNER_DIRECTORY_MODE = 0o700
OWNER_FILE_MODE = 0o600
DEFAULT_MAX_JSON_BYTES = 1024 * 1024
DEFAULT_MAX_JSONL_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_JSONL_LINES = 100_000
DEFAULT_MAX_JSONL_LINE_BYTES = 1024 * 1024

_DIRECTORY_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_MAX_TRUSTED_SYMLINKS = 16
_ATOMIC_CREATE_PREFIX = ".atomic-create-"
_ATOMIC_CREATE_RE = re.compile(
    r"\.atomic-create-(?P<target>[0-9a-f]{32})-"
    r"(?P<size>[0-9a-f]+)-(?P<digest>[0-9a-f]{64})\.tmp\Z"
)


class UnsafePathError(PermissionError):
    pass


class ReadLimitExceeded(ValueError):
    pass


class TreeInventoryLimitExceeded(UnsafePathError):
    pass


class InvalidJsonError(ValueError):
    pass


PathSecurityError = UnsafePathError
BoundedReadError = ReadLimitExceeded


@dataclass(slots=True)
class TreeInventoryBudget:
    max_entries: int
    max_path_bytes: int
    max_depth: int
    deadline: float
    clock: Callable[[], float] = time.monotonic
    entry_count: int = 0
    path_byte_count: int = 0

    @classmethod
    def from_timeout(
        cls,
        *,
        max_entries: int,
        max_path_bytes: int,
        max_depth: int,
        timeout_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> TreeInventoryBudget:
        if timeout_seconds <= 0:
            raise ValueError("tree inventory timeout must be positive")
        return cls(
            max_entries=max_entries,
            max_path_bytes=max_path_bytes,
            max_depth=max_depth,
            deadline=clock() + timeout_seconds,
            clock=clock,
        )

    def __post_init__(self) -> None:
        if min(self.max_entries, self.max_path_bytes) < 1 or self.max_depth < 0:
            raise ValueError("tree inventory bounds are invalid")

    def checkpoint(self) -> None:
        if self.clock() >= self.deadline:
            raise TreeInventoryLimitExceeded("tree inventory exceeded its deadline")

    def reserve(self, relative_path: str, *, depth: int) -> None:
        self.checkpoint()
        if depth > self.max_depth:
            raise TreeInventoryLimitExceeded("tree inventory exceeds its depth bound")
        try:
            path_bytes = len(os.fsencode(relative_path))
        except (TypeError, UnicodeEncodeError) as error:
            raise UnsafePathError("tree inventory path cannot be encoded") from error
        if self.entry_count >= self.max_entries:
            raise TreeInventoryLimitExceeded("tree inventory exceeds its entry bound")
        if self.path_byte_count + path_bytes > self.max_path_bytes:
            raise TreeInventoryLimitExceeded(
                "tree inventory exceeds its path-byte bound"
            )
        self.entry_count += 1
        self.path_byte_count += path_bytes
        self.checkpoint()


_DARWIN_ACL_TYPE_EXTENDED = 0x100
_DARWIN_FILESEC_ACL = 5
_DARWIN_FILESEC_REMOVE_ACL = ctypes.c_void_p(1)


class _DarwinAclApi:
    def __init__(self) -> None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            self.acl_get_fd_np = libc.acl_get_fd_np
            self.acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
            self.acl_get_fd_np.restype = ctypes.c_void_p
            self.acl_free = libc.acl_free
            self.acl_free.argtypes = (ctypes.c_void_p,)
            self.acl_free.restype = ctypes.c_int
            self.filesec_init = libc.filesec_init
            self.filesec_init.argtypes = ()
            self.filesec_init.restype = ctypes.c_void_p
            self.filesec_set_property = libc.filesec_set_property
            self.filesec_set_property.argtypes = (
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_void_p,
            )
            self.filesec_set_property.restype = ctypes.c_int
            self.filesec_free = libc.filesec_free
            self.filesec_free.argtypes = (ctypes.c_void_p,)
            self.filesec_free.restype = None
            self.fchmodx_np = libc.fchmodx_np
            self.fchmodx_np.argtypes = (ctypes.c_int, ctypes.c_void_p)
            self.fchmodx_np.restype = ctypes.c_int
        except (AttributeError, OSError) as exc:
            raise UnsafePathError(
                "required Darwin descriptor ACL operations are unavailable"
            ) from exc


@lru_cache(maxsize=1)
def _darwin_acl_api() -> _DarwinAclApi | None:
    if sys.platform != "darwin":
        return None
    return _DarwinAclApi()


def _darwin_descriptor_has_extended_acl(descriptor: int) -> bool:
    api = _darwin_acl_api()
    if api is None:
        return False
    ctypes.set_errno(0)
    acl = api.acl_get_fd_np(descriptor, _DARWIN_ACL_TYPE_EXTENDED)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return False
        raise UnsafePathError(
            "could not verify the Darwin extended ACL on an owner-only object: "
            f"errno={error_number}"
        )

    ctypes.set_errno(0)
    if api.acl_free(acl) != 0:
        raise UnsafePathError(
            "could not release a Darwin ACL inspection object: "
            f"errno={ctypes.get_errno()}"
        )
    return True


def _validate_owner_only_acl(descriptor: int, display_path: Path) -> None:
    if _darwin_descriptor_has_extended_acl(descriptor):
        raise UnsafePathError(
            f"owner-only object has a Darwin extended ACL: {display_path}"
        )


def _clear_darwin_extended_acl(descriptor: int, display_path: Path) -> None:
    api = _darwin_acl_api()
    if api is None:
        return
    ctypes.set_errno(0)
    filesec = api.filesec_init()
    if not filesec:
        raise UnsafePathError(
            "could not allocate Darwin ACL removal state for "
            f"{display_path}: errno={ctypes.get_errno()}"
        )
    try:
        ctypes.set_errno(0)
        if (
            api.filesec_set_property(
                filesec,
                _DARWIN_FILESEC_ACL,
                _DARWIN_FILESEC_REMOVE_ACL,
            )
            != 0
        ):
            raise UnsafePathError(
                "could not configure Darwin ACL removal for "
                f"{display_path}: errno={ctypes.get_errno()}"
            )
        ctypes.set_errno(0)
        if api.fchmodx_np(descriptor, filesec) != 0:
            raise UnsafePathError(
                f"could not remove inherited Darwin ACL from {display_path}: "
                f"errno={ctypes.get_errno()}"
            )
    finally:
        api.filesec_free(filesec)
    _validate_owner_only_acl(descriptor, display_path)


def _owner_uid() -> int:
    getter = getattr(os, "geteuid", os.getuid)
    return getter()


def _run_dir_fd_smoke_probe() -> tuple[str, ...]:
    required_constants = ("O_DIRECTORY", "O_NOFOLLOW")
    missing = tuple(
        f"missing_{name.lower()}"
        for name in required_constants
        if not hasattr(os, name)
    )
    if missing:
        return missing

    try:
        with tempfile.TemporaryDirectory(prefix="retrospective-safe-io-probe-") as root:
            root_fd = os.open(root, _DIRECTORY_FLAGS)
            try:
                os.mkdir("child", OWNER_DIRECTORY_MODE, dir_fd=root_fd)
                child_fd = os.open("child", _DIRECTORY_FLAGS, dir_fd=root_fd)
                try:
                    _clear_darwin_extended_acl(child_fd, Path(root) / "child")
                    _validate_owner_only_acl(child_fd, Path(root) / "child")
                    source_fd = os.open(
                        "source",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
                        OWNER_FILE_MODE,
                        dir_fd=child_fd,
                    )
                    try:
                        _clear_darwin_extended_acl(
                            source_fd,
                            Path(root) / "child" / "source",
                        )
                        _validate_owner_only_acl(
                            source_fd,
                            Path(root) / "child" / "source",
                        )
                    finally:
                        os.close(source_fd)
                    os.replace(
                        "source",
                        "renamed",
                        src_dir_fd=child_fd,
                        dst_dir_fd=child_fd,
                    )
                    os.link(
                        "renamed",
                        "linked",
                        src_dir_fd=child_fd,
                        dst_dir_fd=child_fd,
                        follow_symlinks=False,
                    )
                    os.stat("linked", dir_fd=child_fd, follow_symlinks=False)
                    os.unlink("linked", dir_fd=child_fd)
                    os.symlink("renamed", "probe-link", dir_fd=child_fd)
                    if os.readlink("probe-link", dir_fd=child_fd) != "renamed":
                        return ("dir_fd_smoke_probe_readlink_mismatch",)
                    os.unlink("probe-link", dir_fd=child_fd)
                    if "renamed" not in os.listdir(child_fd):
                        return ("dir_fd_smoke_probe_listdir_mismatch",)
                    os.unlink("renamed", dir_fd=child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir("child", dir_fd=root_fd)
            finally:
                os.close(root_fd)
    except (NotImplementedError, OSError, TypeError, ValueError) as exc:
        code = getattr(exc, "errno", None)
        detail = str(code) if code is not None else type(exc).__name__.lower()
        return (f"dir_fd_smoke_probe_failed_{detail}",)
    return ()


@lru_cache(maxsize=1)
def _cached_dir_fd_capability_issues() -> tuple[str, ...]:
    return _run_dir_fd_smoke_probe()


def secure_io_capability_issues() -> tuple[str, ...]:
    """Return actual no-follow dir-fd capability failures.

    CPython 3.13 on macOS does not list ``os.replace`` in
    ``os.supports_dir_fd`` even though both dir-fd arguments work. A real probe
    avoids that false negative and still fails closed on a partial platform.
    """

    return _cached_dir_fd_capability_issues()


def require_secure_io_capabilities() -> None:
    issues = secure_io_capability_issues()
    if issues:
        raise UnsafePathError(
            "required no-follow directory capabilities are unavailable: "
            + ",".join(issues)
        )


def _normalized_path(path: str | os.PathLike[str]) -> Path:
    require_secure_io_capabilities()
    normalized = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    if normalized == Path(normalized.anchor):
        raise UnsafePathError("a filesystem root cannot be an owner-only data path")
    if "\x00" in os.fspath(normalized):
        raise UnsafePathError("filesystem paths cannot contain NUL bytes")
    return normalized


def _describe_mode(mode: int) -> str:
    return f"0o{stat.S_IMODE(mode):03o}"


def _validate_owner(st: os.stat_result, path: Path) -> None:
    if st.st_uid != _owner_uid():
        raise UnsafePathError(f"path is not owned by the current user: {path}")


def _validate_ancestor_directory(st: os.stat_result, path: Path) -> None:
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(f"path ancestor is not a directory: {path}")
    if st.st_uid not in {0, _owner_uid()}:
        raise UnsafePathError(f"path ancestor has an untrusted owner: {path}")
    mode = stat.S_IMODE(st.st_mode)
    root_owned_sticky = st.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if mode & 0o022 and not root_owned_sticky:
        raise UnsafePathError(f"path ancestor is writable by another user: {path}")


def _validate_directory_stat(
    st: os.stat_result,
    path: Path,
    *,
    exact_mode: bool,
) -> None:
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(f"expected a real directory, not a symlink: {path}")
    _validate_owner(st, path)
    mode = stat.S_IMODE(st.st_mode)
    if exact_mode and mode != OWNER_DIRECTORY_MODE:
        raise UnsafePathError(
            f"directory mode must be 0o700, found {_describe_mode(st.st_mode)}: {path}"
        )
    if not exact_mode and mode & 0o022:
        raise UnsafePathError(f"directory is writable by another user: {path}")


def _validate_regular_file_stat(
    st: os.stat_result,
    path: Path,
    *,
    exact_mode: bool,
    single_link: bool,
) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise UnsafePathError(f"expected a real regular file, not a symlink: {path}")
    _validate_owner(st, path)
    if single_link and st.st_nlink != 1:
        raise UnsafePathError(
            f"owner-only files must have exactly one hard link: {path}"
        )
    if exact_mode and stat.S_IMODE(st.st_mode) != OWNER_FILE_MODE:
        raise UnsafePathError(
            f"file mode must be 0o600, found {_describe_mode(st.st_mode)}: {path}"
        )


def _validate_file_stat(st: os.stat_result, path: Path) -> None:
    _validate_regular_file_stat(st, path, exact_mode=True, single_link=True)


def validate_owner_only_directory_descriptor(
    descriptor: int,
    display_path: Path,
    *,
    exact_mode: bool = True,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    _validate_directory_stat(metadata, display_path, exact_mode=exact_mode)
    _validate_owner_only_acl(descriptor, display_path)
    return metadata


def harden_created_owner_only_directory_descriptor(
    descriptor: int,
    display_path: Path,
) -> os.stat_result:
    os.fchmod(descriptor, OWNER_DIRECTORY_MODE)
    _clear_darwin_extended_acl(descriptor, display_path)
    return validate_owner_only_directory_descriptor(descriptor, display_path)


def _normalize_component_sequence(parts: list[str]) -> list[str]:
    normalized: list[str] = []
    for part in parts:
        if part in {"", ".", os.sep}:
            continue
        if part == "..":
            if normalized:
                normalized.pop()
            continue
        normalized.append(part)
    return normalized


def _trusted_symlink_target(
    directory_fd: int,
    name: str,
    traversed: list[str],
    remaining: list[str],
    display_path: Path,
) -> list[str] | None:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(before.st_mode):
        return None

    parent = os.fstat(directory_fd)
    if before.st_uid != 0 or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022:
        raise UnsafePathError(
            f"user-controlled symlink ancestor is not allowed: {display_path}"
        )
    target = os.readlink(name, dir_fd=directory_fd)
    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise UnsafePathError(
            f"symlink ancestor changed while inspected: {display_path}"
        )

    target_parts = list(Path(target).parts)
    base = [] if os.path.isabs(target) else list(traversed)
    return _normalize_component_sequence(base + target_parts + remaining)


def _open_directory_chain(
    path: Path,
    *,
    exact_mode: bool,
    create: bool,
    reject_symlink_ancestors: bool,
) -> int:
    components = _normalize_component_sequence(list(path.parts[1:]))
    if not components:
        raise UnsafePathError("a filesystem root cannot be an owner-only data path")

    directory_fd = os.open(path.anchor, _DIRECTORY_FLAGS)
    traversed: list[str] = []
    symlink_count = 0
    index = 0
    try:
        while index < len(components):
            name = components[index]
            is_final = index == len(components) - 1
            created = False
            try:
                child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, OWNER_DIRECTORY_MODE, dir_fd=directory_fd)
                    created = True
                except FileExistsError:
                    pass
                child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            except OSError as exc:
                if reject_symlink_ancestors:
                    raise UnsafePathError(
                        "symlink ancestor is not allowed: "
                        f"{Path(path.anchor, *traversed, name)}"
                    ) from exc
                replacement = _trusted_symlink_target(
                    directory_fd,
                    name,
                    traversed,
                    components[index + 1 :],
                    Path(path.anchor, *traversed, name),
                )
                if replacement is None:
                    raise exc
                symlink_count += 1
                if symlink_count > _MAX_TRUSTED_SYMLINKS:
                    raise UnsafePathError(
                        f"too many trusted symlink ancestors while opening: {path}"
                    ) from exc
                os.close(directory_fd)
                directory_fd = os.open(path.anchor, _DIRECTORY_FLAGS)
                components = replacement
                traversed = []
                index = 0
                continue

            try:
                metadata = os.fstat(child_fd)
                component_path = Path(path.anchor, *traversed, name)
                if created:
                    _validate_directory_stat(metadata, component_path, exact_mode=False)
                    metadata = harden_created_owner_only_directory_descriptor(
                        child_fd,
                        component_path,
                    )
                    os.fsync(directory_fd)
                elif is_final:
                    metadata = validate_owner_only_directory_descriptor(
                        child_fd,
                        path,
                        exact_mode=exact_mode,
                    )
                else:
                    _validate_ancestor_directory(metadata, component_path)
            except BaseException:
                os.close(child_fd)
                raise

            os.close(directory_fd)
            directory_fd = child_fd
            traversed.append(name)
            index += 1
        return directory_fd
    except BaseException:
        os.close(directory_fd)
        raise


def open_owner_only_directory(
    path: str | os.PathLike[str],
    *,
    create: bool = False,
    reject_symlink_ancestors: bool = False,
) -> tuple[Path, int]:
    normalized = _normalized_path(path)
    descriptor = _open_directory_chain(
        normalized,
        exact_mode=True,
        create=create,
        reject_symlink_ancestors=reject_symlink_ancestors,
    )
    return normalized, descriptor


def owner_controlled_directory_identity(
    path: str | os.PathLike[str],
) -> tuple[int, int, int, int]:
    descriptor = _open_directory_chain(
        _normalized_path(path),
        exact_mode=False,
        create=False,
        reject_symlink_ancestors=True,
    )
    try:
        metadata = os.fstat(descriptor)
        return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid
    finally:
        os.close(descriptor)


_CLEANUP_ENTRY_FIELDS = frozenset(
    {
        "access_policy",
        "content_commitment",
        "device",
        "group",
        "inode",
        "link_count",
        "mode",
        "object_type",
        "owner",
        "relative_path",
        "size",
    }
)


def _expected_cleanup_entries(
    inventory: Sequence[Mapping[str, Any]] | None,
) -> dict[str, dict[str, Any]] | None:
    if inventory is None:
        return None
    if isinstance(inventory, (str, bytes)):
        raise UnsafePathError("expected cleanup inventory must be a sequence")
    entries: dict[str, dict[str, Any]] = {}
    for raw_entry in inventory:
        if (
            not isinstance(raw_entry, Mapping)
            or set(raw_entry) != _CLEANUP_ENTRY_FIELDS
        ):
            raise UnsafePathError("expected cleanup inventory entry is invalid")
        entry = dict(raw_entry)
        relative_path = entry.get("relative_path")
        object_type = entry.get("object_type")
        commitment = entry.get("content_commitment")
        if (
            not isinstance(relative_path, str)
            or relative_path in entries
            or relative_path != str(PurePosixPath(relative_path))
            or PurePosixPath(relative_path).is_absolute()
            or any(part in {"", ".."} for part in PurePosixPath(relative_path).parts)
            or object_type not in {"directory", "file"}
            or entry.get("access_policy") != "owner-only-no-acl"
            or commitment is not None
            and (
                object_type != "file"
                or not isinstance(commitment, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", commitment) is None
            )
        ):
            raise UnsafePathError("expected cleanup inventory entry is invalid")
        entries[relative_path] = entry
    if not entries or entries.get(".", {}).get("object_type") != "directory":
        raise UnsafePathError("expected cleanup inventory lacks its root")
    return entries


def _cleanup_entry_path(relative_path: str, child_name: str) -> str:
    return child_name if relative_path == "." else f"{relative_path}/{child_name}"


def _expected_direct_children(
    entries: Mapping[str, Mapping[str, Any]],
    relative_path: str,
) -> list[str]:
    prefix = "" if relative_path == "." else f"{relative_path}/"
    names: set[str] = set()
    for candidate in entries:
        if candidate == relative_path or not candidate.startswith(prefix):
            continue
        tail = candidate[len(prefix) :]
        if tail and "/" not in tail:
            names.add(tail)
    return sorted(names, key=os.fsencode)


def _require_expected_cleanup_stat(
    metadata: os.stat_result,
    expected: Mapping[str, Any],
    *,
    display_path: Path,
    relaxed_directory_metadata: bool,
) -> None:
    is_directory = stat.S_ISDIR(metadata.st_mode)
    if is_directory != (expected.get("object_type") == "directory"):
        raise UnsafePathError(f"cleanup object type changed: {display_path}")
    fields = (
        (metadata.st_dev, expected.get("device")),
        (metadata.st_ino, expected.get("inode")),
        (metadata.st_uid, expected.get("owner")),
        (metadata.st_gid, expected.get("group")),
        (stat.S_IMODE(metadata.st_mode), expected.get("mode")),
    )
    if not is_directory or not relaxed_directory_metadata:
        fields += (
            (metadata.st_nlink, expected.get("link_count")),
            (metadata.st_size, expected.get("size")),
        )
    if any(observed != planned for observed, planned in fields):
        raise UnsafePathError(
            f"cleanup object identity or policy changed: {display_path}"
        )


def _secure_remove_tree_at(
    parent_fd: int,
    name: str,
    *,
    display_path: Path,
    expected_entries: Mapping[str, Mapping[str, Any]] | None,
    relative_path: str,
) -> dict[str, int]:
    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if expected_entries is not None:
            raise UnsafePathError(f"expected cleanup tree disappeared: {display_path}")
        return {"byte_count": 0, "directory_count": 0, "file_count": 0}
    _validate_directory_stat(observed, display_path, exact_mode=True)
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafePathError(f"cannot anchor cleanup tree: {display_path}") from exc
    try:
        anchored = validate_owner_only_directory_descriptor(
            descriptor,
            display_path,
        )
        if (observed.st_dev, observed.st_ino) != (anchored.st_dev, anchored.st_ino):
            raise UnsafePathError(f"cleanup tree changed while opened: {display_path}")
        expected = (
            None if expected_entries is None else expected_entries.get(relative_path)
        )
        if expected_entries is not None and expected is None:
            raise UnsafePathError(
                f"cleanup tree is absent from inventory: {display_path}"
            )
        if expected is not None:
            _require_expected_cleanup_stat(
                anchored,
                expected,
                display_path=display_path,
                relaxed_directory_metadata=False,
            )
        counts = {"byte_count": 0, "directory_count": 1, "file_count": 0}
        child_names = sorted(os.listdir(descriptor), key=os.fsencode)
        if expected_entries is not None and child_names != _expected_direct_children(
            expected_entries,
            relative_path,
        ):
            raise UnsafePathError(f"cleanup tree contents changed: {display_path}")
        for child_name in child_names:
            child_path = display_path / child_name
            child_relative = _cleanup_entry_path(relative_path, child_name)
            child = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                nested = _secure_remove_tree_at(
                    descriptor,
                    child_name,
                    display_path=child_path,
                    expected_entries=expected_entries,
                    relative_path=child_relative,
                )
                for key, value in nested.items():
                    counts[key] += value
                continue
            child_fd = open_checked_file_at(
                descriptor,
                child_name,
                display_path=child_path,
                require_owner_only=True,
            )
            try:
                anchored_child = os.fstat(child_fd)
                expected_child = (
                    None
                    if expected_entries is None
                    else expected_entries.get(child_relative)
                )
                if expected_entries is not None and expected_child is None:
                    raise UnsafePathError(
                        f"cleanup file is absent from inventory: {child_path}"
                    )
                if expected_child is not None:
                    _require_expected_cleanup_stat(
                        anchored_child,
                        expected_child,
                        display_path=child_path,
                        relaxed_directory_metadata=False,
                    )
                    commitment = expected_child.get("content_commitment")
                    if commitment is not None and not hmac.compare_digest(
                        commitment,
                        "sha256:" + _hash_file_descriptor(child_fd),
                    ):
                        raise UnsafePathError(
                            f"cleanup file content changed: {child_path}"
                        )
                    final_child = os.fstat(child_fd)
                    _require_expected_cleanup_stat(
                        final_child,
                        expected_child,
                        display_path=child_path,
                        relaxed_directory_metadata=False,
                    )
                current = os.stat(
                    child_name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (anchored_child.st_dev, anchored_child.st_ino) != (
                    current.st_dev,
                    current.st_ino,
                ):
                    raise UnsafePathError(
                        f"cleanup file changed before unlink: {child_path}"
                    )
                _validate_owner_only_acl(child_fd, child_path)
                os.unlink(child_name, dir_fd=descriptor)
                counts["byte_count"] += anchored_child.st_size
                counts["file_count"] += 1
            finally:
                os.close(child_fd)
        os.fsync(descriptor)
        validate_owner_only_directory_descriptor(descriptor, display_path)
        current_root = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (anchored.st_dev, anchored.st_ino) != (
            current_root.st_dev,
            current_root.st_ino,
        ):
            raise UnsafePathError(
                f"cleanup tree name changed before removal: {display_path}"
            )
        if expected is not None:
            _require_expected_cleanup_stat(
                current_root,
                expected,
                display_path=display_path,
                relaxed_directory_metadata=True,
            )
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)
    return counts


def secure_remove_tree_at(
    parent_fd: int,
    name: str,
    *,
    display_path: Path,
    expected_inventory: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, int]:
    """Remove one owner-only tree through an already anchored parent fd."""

    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise UnsafePathError("remove-tree name must be one safe component")
    return _secure_remove_tree_at(
        parent_fd,
        name,
        display_path=display_path,
        expected_entries=_expected_cleanup_entries(expected_inventory),
        relative_path=".",
    )


def _cleanup_inventory_entry(
    metadata: os.stat_result,
    *,
    content_commitment: str | None = None,
    object_type: str,
    relative_path: str,
) -> dict[str, Any]:
    return {
        "access_policy": "owner-only-no-acl",
        "content_commitment": content_commitment,
        "device": metadata.st_dev,
        "group": metadata.st_gid,
        "inode": metadata.st_ino,
        "link_count": metadata.st_nlink,
        "mode": stat.S_IMODE(metadata.st_mode),
        "object_type": object_type,
        "owner": metadata.st_uid,
        "relative_path": relative_path,
        "size": metadata.st_size,
    }


def _inspect_file_inventory_entry(
    parent_fd: int,
    name: str,
    *,
    budget: TreeInventoryBudget,
    display_path: Path,
    relative_path: str,
) -> dict[str, Any]:
    descriptor = open_checked_file_at(
        parent_fd,
        name,
        display_path=display_path,
        require_owner_only=True,
    )
    try:
        anchored = os.fstat(descriptor)
        initial = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            initial.st_dev,
            initial.st_ino,
            initial.st_uid,
            initial.st_gid,
            stat.S_IMODE(initial.st_mode),
            initial.st_nlink,
            initial.st_size,
        ) != (
            anchored.st_dev,
            anchored.st_ino,
            anchored.st_uid,
            anchored.st_gid,
            stat.S_IMODE(anchored.st_mode),
            anchored.st_nlink,
            anchored.st_size,
        ):
            raise UnsafePathError(
                f"inspected file changed while inventoried: {display_path}"
            )
        _validate_owner_only_acl(descriptor, display_path)
        commitment = "sha256:" + _hash_file_descriptor(
            descriptor,
            checkpoint=budget.checkpoint,
        )
        final = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            final.st_dev,
            final.st_ino,
            final.st_uid,
            final.st_gid,
            stat.S_IMODE(final.st_mode),
            final.st_nlink,
            final.st_size,
            current.st_dev,
            current.st_ino,
            current.st_uid,
            current.st_gid,
            stat.S_IMODE(current.st_mode),
            current.st_nlink,
            current.st_size,
        ) != (
            anchored.st_dev,
            anchored.st_ino,
            anchored.st_uid,
            anchored.st_gid,
            stat.S_IMODE(anchored.st_mode),
            anchored.st_nlink,
            anchored.st_size,
            anchored.st_dev,
            anchored.st_ino,
            anchored.st_uid,
            anchored.st_gid,
            stat.S_IMODE(anchored.st_mode),
            anchored.st_nlink,
            anchored.st_size,
        ):
            raise UnsafePathError(
                f"inspected file changed while hashed: {display_path}"
            )
        _validate_owner_only_acl(descriptor, display_path)
        return _cleanup_inventory_entry(
            anchored,
            content_commitment=commitment,
            object_type="file",
            relative_path=relative_path,
        )
    finally:
        os.close(descriptor)


def _inspect_tree_descriptor(
    descriptor: int,
    *,
    budget: TreeInventoryBudget,
    depth: int,
    display_path: Path,
    relative_path: str,
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    budget.checkpoint()
    anchored = validate_owner_only_directory_descriptor(descriptor, display_path)
    counts = {"byte_count": 0, "directory_count": 1, "file_count": 0}
    entries = [
        _cleanup_inventory_entry(
            anchored,
            object_type="directory",
            relative_path=relative_path,
        )
    ]
    child_names: list[str] = []
    with os.scandir(descriptor) as children:
        for child in children:
            budget.checkpoint()
            child_name = child.name
            child_relative = (
                child_name if relative_path == "." else f"{relative_path}/{child_name}"
            )
            budget.reserve(child_relative, depth=depth + 1)
            child_names.append(child_name)
    for child_name in sorted(child_names, key=os.fsencode):
        budget.checkpoint()
        child_path = display_path / child_name
        child_relative = (
            child_name if relative_path == "." else f"{relative_path}/{child_name}"
        )
        observed = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            try:
                child_fd = os.open(child_name, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise UnsafePathError(
                    f"cannot anchor inspected tree: {child_path}"
                ) from exc
            try:
                child_anchored = validate_owner_only_directory_descriptor(
                    child_fd,
                    child_path,
                )
                if (observed.st_dev, observed.st_ino) != (
                    child_anchored.st_dev,
                    child_anchored.st_ino,
                ):
                    raise UnsafePathError(
                        f"inspected tree changed while opened: {child_path}"
                    )
                nested_counts, nested_entries = _inspect_tree_descriptor(
                    child_fd,
                    budget=budget,
                    depth=depth + 1,
                    display_path=child_path,
                    relative_path=child_relative,
                )
                current = os.stat(
                    child_name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    current.st_dev,
                    current.st_ino,
                    current.st_uid,
                    current.st_gid,
                    stat.S_IMODE(current.st_mode),
                    current.st_nlink,
                    current.st_size,
                ) != (
                    child_anchored.st_dev,
                    child_anchored.st_ino,
                    child_anchored.st_uid,
                    child_anchored.st_gid,
                    stat.S_IMODE(child_anchored.st_mode),
                    child_anchored.st_nlink,
                    child_anchored.st_size,
                ):
                    raise UnsafePathError(
                        f"inspected tree changed while inventoried: {child_path}"
                    )
            finally:
                os.close(child_fd)
            for key, value in nested_counts.items():
                counts[key] += value
            entries.extend(nested_entries)
            continue

        file_entry = _inspect_file_inventory_entry(
            descriptor,
            child_name,
            budget=budget,
            display_path=child_path,
            relative_path=child_relative,
        )
        entries.append(file_entry)
        counts["byte_count"] += file_entry["size"]
        counts["file_count"] += 1

    budget.checkpoint()
    final = validate_owner_only_directory_descriptor(descriptor, display_path)
    if (
        final.st_dev,
        final.st_ino,
        final.st_uid,
        final.st_gid,
        stat.S_IMODE(final.st_mode),
        final.st_nlink,
        final.st_size,
    ) != (
        anchored.st_dev,
        anchored.st_ino,
        anchored.st_uid,
        anchored.st_gid,
        stat.S_IMODE(anchored.st_mode),
        anchored.st_nlink,
        anchored.st_size,
    ):
        raise UnsafePathError(
            f"inspected tree changed while inventoried: {display_path}"
        )
    return counts, entries


def inspect_tree_inventory_at(
    parent_fd: int,
    name: str,
    *,
    budget: TreeInventoryBudget,
    display_path: Path,
) -> dict[str, Any]:
    """Inventory one owner-only tree without following caller-controlled links."""

    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise UnsafePathError("inspect-tree name must be one safe component")
    budget.checkpoint()
    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return {
            "counters": {
                "byte_count": 0,
                "directory_count": 0,
                "file_count": 0,
            },
            "entries": [],
        }
    budget.reserve(".", depth=0)
    _validate_directory_stat(observed, display_path, exact_mode=True)
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafePathError(f"cannot anchor inspected tree: {display_path}") from exc
    try:
        anchored = validate_owner_only_directory_descriptor(
            descriptor,
            display_path,
        )
        if (observed.st_dev, observed.st_ino) != (anchored.st_dev, anchored.st_ino):
            raise UnsafePathError(
                f"inspected tree changed while opened: {display_path}"
            )
        counts, entries = _inspect_tree_descriptor(
            descriptor,
            budget=budget,
            depth=0,
            display_path=display_path,
            relative_path=".",
        )
        entries.sort(key=lambda item: os.fsencode(item["relative_path"]))
        current_root = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            current_root.st_dev,
            current_root.st_ino,
            current_root.st_uid,
            current_root.st_gid,
            stat.S_IMODE(current_root.st_mode),
            current_root.st_nlink,
            current_root.st_size,
        ) != (
            anchored.st_dev,
            anchored.st_ino,
            anchored.st_uid,
            anchored.st_gid,
            stat.S_IMODE(anchored.st_mode),
            anchored.st_nlink,
            anchored.st_size,
        ):
            raise UnsafePathError(
                f"inspected tree name changed while inventoried: {display_path}"
            )
        return {"counters": counts, "entries": entries}
    finally:
        os.close(descriptor)


def inspect_tree_at(
    parent_fd: int,
    name: str,
    *,
    budget: TreeInventoryBudget,
    display_path: Path,
) -> dict[str, int]:
    """Count one owner-only tree without following caller-controlled links."""

    return inspect_tree_inventory_at(
        parent_fd,
        name,
        budget=budget,
        display_path=display_path,
    )["counters"]


def _open_parent_directory(
    path: str | os.PathLike[str],
    *,
    create_parents: bool,
) -> tuple[Path, int]:
    normalized = _normalized_path(path)
    descriptor = _open_directory_chain(
        normalized.parent,
        exact_mode=True,
        create=create_parents,
        reject_symlink_ancestors=False,
    )
    return normalized, descriptor


def check_owner_only_directory(path: str | os.PathLike[str]) -> Path:
    normalized, descriptor = open_owner_only_directory(path)
    os.close(descriptor)
    return normalized


def check_owner_only_file(path: str | os.PathLike[str]) -> Path:
    normalized, directory_fd = _open_parent_directory(path, create_parents=False)
    try:
        descriptor = open_checked_file_at(
            directory_fd,
            normalized.name,
            display_path=normalized,
            require_owner_only=True,
        )
        os.close(descriptor)
        return normalized
    finally:
        os.close(directory_fd)


check_secure_directory = check_owner_only_directory
check_secure_file = check_owner_only_file


def ensure_owner_only_directory(path: str | os.PathLike[str]) -> Path:
    normalized, descriptor = open_owner_only_directory(path, create=True)
    os.close(descriptor)
    return normalized


ensure_owner_only_dir = ensure_owner_only_directory
ensure_secure_directory = ensure_owner_only_directory


def open_checked_file_at(
    directory_fd: int,
    name: str,
    *,
    display_path: Path,
    require_owner_only: bool,
) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _FILE_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise UnsafePathError(
                f"refusing to follow file symlink: {display_path}"
            ) from exc
        raise
    try:
        metadata = os.fstat(descriptor)
        if require_owner_only:
            _validate_file_stat(metadata, display_path)
            _validate_owner_only_acl(descriptor, display_path)
        elif not stat.S_ISREG(metadata.st_mode):
            raise UnsafePathError(f"expected a regular file: {display_path}")
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise UnsafePathError(f"file changed while it was opened: {display_path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_owner_only_file_descriptor(
    descriptor: int,
    display_path: Path,
    *,
    directory_fd: int | None = None,
    name: str | None = None,
    single_link: bool = True,
) -> None:
    metadata = os.fstat(descriptor)
    _validate_regular_file_stat(
        metadata,
        display_path,
        exact_mode=True,
        single_link=single_link,
    )
    _validate_owner_only_acl(descriptor, display_path)
    if directory_fd is None and name is None:
        return
    if directory_fd is None or name is None:
        raise ValueError("directory_fd and name must be supplied together")
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise UnsafePathError(f"locked file name disappeared: {display_path}") from exc
    if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
        raise UnsafePathError(f"locked file name changed: {display_path}")


def harden_created_owner_only_file_descriptor(
    descriptor: int,
    display_path: Path,
    *,
    single_link: bool = True,
) -> None:
    os.fchmod(descriptor, OWNER_FILE_MODE)
    _clear_darwin_extended_acl(descriptor, display_path)
    validate_owner_only_file_descriptor(
        descriptor,
        display_path,
        single_link=single_link,
    )


def open_lock_file_at(directory_fd: int, name: str, *, display_path: Path) -> int:
    flags = os.O_RDWR | _FILE_NOFOLLOW
    created = False
    try:
        descriptor = os.open(
            name,
            flags | os.O_CREAT | os.O_EXCL,
            OWNER_FILE_MODE,
            dir_fd=directory_fd,
        )
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise UnsafePathError(
                    f"refusing to follow lock-file symlink: {display_path}"
                ) from exc
            raise

    try:
        metadata = os.fstat(descriptor)
        _validate_regular_file_stat(
            metadata,
            display_path,
            exact_mode=False,
            single_link=True,
        )
        mode = stat.S_IMODE(metadata.st_mode)
        repairable_mode = mode & ~OWNER_FILE_MODE == 0
        if mode != OWNER_FILE_MODE and not repairable_mode:
            raise UnsafePathError(
                f"lock file mode must be 0o600, found {_describe_mode(mode)}: "
                f"{display_path}"
            )
        if not created:
            _validate_owner_only_acl(descriptor, display_path)
        if created or mode != OWNER_FILE_MODE:
            os.fchmod(descriptor, OWNER_FILE_MODE)
        if created:
            _clear_darwin_extended_acl(descriptor, display_path)
        if created or mode != OWNER_FILE_MODE:
            os.fsync(directory_fd)
        validate_owner_only_file_descriptor(
            descriptor,
            display_path,
            directory_fd=directory_fd,
            name=name,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_existing_target_at(
    directory_fd: int,
    target_name: str,
    display_path: Path,
) -> bool:
    try:
        descriptor = open_checked_file_at(
            directory_fd,
            target_name,
            display_path=display_path,
            require_owner_only=True,
        )
    except FileNotFoundError:
        return False
    os.close(descriptor)
    return True


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(fd, view[written:])
        if count <= 0:
            raise OSError("short write while persisting owner-only file")
        written += count


def _write_temporary_at(directory_fd: int, target_name: str, data: bytes) -> str:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW
    target_token = hashlib.sha256(os.fsencode(target_name)).hexdigest()[:16]
    for _ in range(32):
        temporary_name = f".atomic-write-{target_token}-{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                OWNER_FILE_MODE,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            continue
        succeeded = False
        try:
            _validate_regular_file_stat(
                os.fstat(descriptor),
                Path(temporary_name),
                exact_mode=False,
                single_link=True,
            )
            harden_created_owner_only_file_descriptor(
                descriptor,
                Path(temporary_name),
            )
            _write_all(descriptor, data)
            os.fsync(descriptor)
            succeeded = True
        finally:
            os.close(descriptor)
            if not succeeded:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        return temporary_name
    raise FileExistsError("could not allocate a unique atomic-write temporary file")


ReplaceAt = Callable[[int, str, str], None]


def _default_replace_at(directory_fd: int, source_name: str, target_name: str) -> None:
    os.replace(
        source_name,
        target_name,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )


def atomic_write_bytes_at(
    directory_fd: int,
    target_name: str,
    data: bytes | bytearray | memoryview,
    *,
    display_path: Path,
    replace_at: ReplaceAt = _default_replace_at,
) -> None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("atomic write data must be bytes-like")
    payload = bytes(data)
    temporary_name: str | None = None
    try:
        _validate_existing_target_at(directory_fd, target_name, display_path)
        temporary_name = _write_temporary_at(directory_fd, target_name, payload)
        replace_at(directory_fd, temporary_name, target_name)
        temporary_name = None
        os.fsync(directory_fd)
        descriptor = open_checked_file_at(
            directory_fd,
            target_name,
            display_path=display_path,
            require_owner_only=True,
        )
        os.close(descriptor)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes | bytearray | memoryview,
    *,
    create_parents: bool = True,
) -> Path:
    target, directory_fd = _open_parent_directory(
        path,
        create_parents=create_parents,
    )
    try:
        atomic_write_bytes_at(
            directory_fd,
            target.name,
            data,
            display_path=target,
        )
        return target
    finally:
        os.close(directory_fd)


def _atomic_create_target_token(target_name: str) -> str:
    return hashlib.sha256(os.fsencode(target_name)).hexdigest()[:32]


def _atomic_create_pending_name(target_name: str, data: bytes) -> str:
    token = _atomic_create_target_token(target_name)
    digest = hashlib.sha256(data).hexdigest()
    return f"{_ATOMIC_CREATE_PREFIX}{token}-{len(data):x}-{digest}.tmp"


def _atomic_create_lock_name(target_name: str) -> str:
    if not target_name or target_name in {".", ".."} or "/" in target_name:
        raise UnsafePathError("atomic-create target name is invalid")
    return f"{_ATOMIC_CREATE_PREFIX}directory.lock"


def _atomic_create_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(stat.S_IMODE(metadata.st_mode)),
        int(metadata.st_nlink),
    )


def _atomic_create_parent_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return _atomic_create_identity(metadata)[:-1]


@dataclass(frozen=True, slots=True)
class AtomicCreateReceipt:
    """Identity-bound ownership proof for one newly created file."""

    path: Path
    parent_identity: tuple[int, ...]
    file_identity: tuple[int, ...]
    byte_count: int
    digest: str


def _hash_file_descriptor(
    descriptor: int,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        if checkpoint is not None:
            checkpoint()
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    if checkpoint is not None:
        checkpoint()
    return digest.hexdigest()


def _pending_candidates_at(
    directory_fd: int,
    target_name: str,
) -> list[tuple[str, os.stat_result]]:
    token = _atomic_create_target_token(target_name)
    prefix = f"{_ATOMIC_CREATE_PREFIX}{token}-"
    candidates: list[tuple[str, os.stat_result]] = []
    for name in os.listdir(directory_fd):
        if not name.startswith(prefix) or not name.endswith(".tmp"):
            continue
        match = _ATOMIC_CREATE_RE.fullmatch(name)
        if match is None or match.group("target") != token:
            raise UnsafePathError(f"invalid atomic-create recovery file name: {name}")
        try:
            descriptor = os.open(
                name, os.O_RDONLY | _FILE_NOFOLLOW, dir_fd=directory_fd
            )
        except FileNotFoundError:
            continue
        try:
            metadata = os.fstat(descriptor)
            _validate_regular_file_stat(
                metadata,
                Path(name),
                exact_mode=False,
                single_link=False,
            )
            _validate_owner_only_acl(descriptor, Path(name))
            if stat.S_IMODE(metadata.st_mode) != OWNER_FILE_MODE:
                if metadata.st_nlink != 1:
                    raise UnsafePathError(
                        f"invalid hard-linked atomic-create recovery file: {name}"
                    )
                os.close(descriptor)
                descriptor = -1
                os.unlink(name, dir_fd=directory_fd)
                continue
            expected_size = int(match.group("size"), 16)
            if metadata.st_size != expected_size:
                if metadata.st_nlink != 1:
                    raise UnsafePathError(
                        f"invalid hard-linked atomic-create recovery file: {name}"
                    )
                os.close(descriptor)
                descriptor = -1
                os.unlink(name, dir_fd=directory_fd)
                continue
            if _hash_file_descriptor(descriptor) != match.group("digest"):
                if metadata.st_nlink != 1:
                    raise UnsafePathError(
                        f"invalid hard-linked atomic-create recovery file: {name}"
                    )
                os.close(descriptor)
                descriptor = -1
                os.unlink(name, dir_fd=directory_fd)
                continue
            candidates.append((name, metadata))
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return candidates


def _recover_atomic_create_at(
    directory_fd: int,
    target_name: str,
    display_path: Path,
) -> bool:
    candidates = _pending_candidates_at(directory_fd, target_name)
    try:
        target_stat = os.stat(
            target_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        target_stat = None

    if target_stat is not None:
        target_descriptor = os.open(
            target_name,
            os.O_RDONLY | _FILE_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            anchored_target = os.fstat(target_descriptor)
            _validate_regular_file_stat(
                anchored_target,
                display_path,
                exact_mode=True,
                single_link=False,
            )
            _validate_owner_only_acl(target_descriptor, display_path)
            if (target_stat.st_dev, target_stat.st_ino) != (
                anchored_target.st_dev,
                anchored_target.st_ino,
            ):
                raise UnsafePathError(
                    f"atomic-create target changed while opened: {display_path}"
                )
            target_stat = anchored_target
        finally:
            os.close(target_descriptor)
        matching = [
            name
            for name, metadata in candidates
            if (metadata.st_dev, metadata.st_ino)
            == (target_stat.st_dev, target_stat.st_ino)
        ]
        if target_stat.st_nlink == 2 and len(matching) == 1:
            os.unlink(matching[0], dir_fd=directory_fd)
            os.fsync(directory_fd)
            target_stat = os.stat(
                target_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        if not _validate_existing_target_at(directory_fd, target_name, display_path):
            raise UnsafePathError(
                f"atomic-create target disappeared during recovery: {display_path}"
            )
        for name, metadata in candidates:
            if name in matching:
                continue
            if metadata.st_nlink != 1:
                raise UnsafePathError(
                    f"unexpected hard-linked atomic-create recovery file: {name}"
                )
            os.unlink(name, dir_fd=directory_fd)
        if candidates:
            os.fsync(directory_fd)
        return True

    if not candidates:
        return False
    if len(candidates) != 1:
        raise UnsafePathError(
            f"multiple recoverable atomic-create files exist for: {display_path}"
        )
    pending_name, pending_stat = candidates[0]
    if pending_stat.st_nlink != 1:
        raise UnsafePathError(
            f"unexpected hard-linked atomic-create recovery file: {pending_name}"
        )
    os.link(
        pending_name,
        target_name,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    os.fsync(directory_fd)
    os.unlink(pending_name, dir_fd=directory_fd)
    os.fsync(directory_fd)
    if not _validate_existing_target_at(directory_fd, target_name, display_path):
        raise UnsafePathError(
            f"atomic-create target disappeared during recovery: {display_path}"
        )
    return True


def recover_atomic_create(path: str | os.PathLike[str]) -> bool:
    """Finish a durable exclusive-create transaction after a process crash.

    Prepared content is named by its target token, byte length, and SHA-256.
    Recovery can therefore distinguish a complete pending file from a partial
    write and can collapse the brief hard-link commit window back to one link.
    """

    target, directory_fd = _open_parent_directory(path, create_parents=False)
    lock_name = _atomic_create_lock_name(target.name)
    lock_path = target.parent / lock_name
    lock_fd: int | None = None
    try:
        lock_fd = open_lock_file_at(
            directory_fd,
            lock_name,
            display_path=lock_path,
        )
        import fcntl

        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        return _recover_atomic_create_at(directory_fd, target.name, target)
    finally:
        if lock_fd is not None:
            try:
                import fcntl

                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(directory_fd)


def read_recoverable_atomic_json(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> Any:
    """Recover and read an atomic-create JSON file through one parent dir fd."""

    target, directory_fd = _open_parent_directory(path, create_parents=False)
    lock_name = _atomic_create_lock_name(target.name)
    lock_path = target.parent / lock_name
    lock_fd: int | None = None
    try:
        lock_fd = open_lock_file_at(
            directory_fd,
            lock_name,
            display_path=lock_path,
        )
        import fcntl

        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        _recover_atomic_create_at(directory_fd, target.name, target)
        return read_bounded_json_at(
            directory_fd,
            target.name,
            display_path=target,
            max_bytes=max_bytes,
            require_owner_only=True,
        )
    finally:
        if lock_fd is not None:
            try:
                import fcntl

                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(directory_fd)


def atomic_create_bytes_with_receipt(
    path: str | os.PathLike[str],
    data: bytes | bytearray | memoryview,
    *,
    create_parents: bool = True,
) -> AtomicCreateReceipt:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("atomic create data must be bytes-like")
    payload = bytes(data)
    target, directory_fd = _open_parent_directory(
        path,
        create_parents=create_parents,
    )
    lock_name = _atomic_create_lock_name(target.name)
    lock_path = target.parent / lock_name
    lock_fd: int | None = None
    pending_name: str | None = None
    prepared = False
    try:
        lock_fd = open_lock_file_at(
            directory_fd,
            lock_name,
            display_path=lock_path,
        )
        import fcntl

        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        if _recover_atomic_create_at(directory_fd, target.name, target):
            raise FileExistsError(target)

        pending_name = _atomic_create_pending_name(target.name, payload)
        descriptor = os.open(
            pending_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
            OWNER_FILE_MODE,
            dir_fd=directory_fd,
        )
        try:
            _validate_regular_file_stat(
                os.fstat(descriptor),
                target.parent / pending_name,
                exact_mode=False,
                single_link=True,
            )
            harden_created_owner_only_file_descriptor(
                descriptor,
                target.parent / pending_name,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            prepared = True
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
        os.link(
            pending_name,
            target.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.fsync(directory_fd)
        os.unlink(pending_name, dir_fd=directory_fd)
        pending_name = None
        os.fsync(directory_fd)
        _validate_existing_target_at(directory_fd, target.name, target)
        target_fd = open_checked_file_at(
            directory_fd,
            target.name,
            display_path=target,
            require_owner_only=True,
        )
        try:
            target_metadata = os.fstat(target_fd)
            validate_owner_only_file_descriptor(
                target_fd,
                target,
                directory_fd=directory_fd,
                name=target.name,
            )
            if (
                target_metadata.st_size != len(payload)
                or _hash_file_descriptor(target_fd)
                != hashlib.sha256(payload).hexdigest()
            ):
                raise UnsafePathError(f"atomic-create target content changed: {target}")
            parent_metadata = os.fstat(directory_fd)
            return AtomicCreateReceipt(
                path=target,
                parent_identity=_atomic_create_parent_identity(parent_metadata),
                file_identity=_atomic_create_identity(target_metadata),
                byte_count=len(payload),
                digest=hashlib.sha256(payload).hexdigest(),
            )
        finally:
            os.close(target_fd)
    finally:
        if pending_name is not None and not prepared:
            try:
                os.unlink(pending_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        if lock_fd is not None:
            try:
                import fcntl

                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(directory_fd)


def atomic_create_bytes(
    path: str | os.PathLike[str],
    data: bytes | bytearray | memoryview,
    *,
    create_parents: bool = True,
) -> Path:
    return atomic_create_bytes_with_receipt(
        path,
        data,
        create_parents=create_parents,
    ).path


def remove_atomic_created_bytes(receipt: AtomicCreateReceipt) -> None:
    """Remove only the cooperating object bound by an atomic-create receipt.

    The directory lock excludes other users of this API through the final unlink.
    A non-cooperating same-UID writer remains outside this point-in-time
    ownership proof and can only cause a detected mismatch before that boundary.
    """

    if not isinstance(receipt, AtomicCreateReceipt):
        raise TypeError("atomic-create rollback requires an ownership receipt")
    target, directory_fd = _open_parent_directory(
        receipt.path,
        create_parents=False,
    )
    lock_name = _atomic_create_lock_name(target.name)
    lock_path = target.parent / lock_name
    lock_fd: int | None = None
    descriptor = -1
    try:
        if (
            _atomic_create_parent_identity(os.fstat(directory_fd))
            != receipt.parent_identity
        ):
            raise UnsafePathError(
                f"atomic-create rollback parent changed: {receipt.path.parent}"
            )
        lock_fd = open_lock_file_at(
            directory_fd,
            lock_name,
            display_path=lock_path,
        )
        import fcntl

        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        validate_owner_only_file_descriptor(
            lock_fd,
            lock_path,
            directory_fd=directory_fd,
            name=lock_name,
        )
        if (
            _atomic_create_parent_identity(os.fstat(directory_fd))
            != receipt.parent_identity
        ):
            raise UnsafePathError(
                f"atomic-create rollback parent changed: {receipt.path.parent}"
            )
        try:
            descriptor = open_checked_file_at(
                directory_fd,
                target.name,
                display_path=target,
                require_owner_only=True,
            )
        except FileNotFoundError:
            return
        validate_owner_only_file_descriptor(
            descriptor,
            target,
            directory_fd=directory_fd,
            name=target.name,
        )
        before = os.fstat(descriptor)
        if (
            _atomic_create_identity(before) != receipt.file_identity
            or before.st_size != receipt.byte_count
            or _hash_file_descriptor(descriptor) != receipt.digest
        ):
            raise UnsafePathError(f"atomic-create rollback target changed: {target}")
        validate_owner_only_file_descriptor(
            descriptor,
            target,
            directory_fd=directory_fd,
            name=target.name,
        )
        after = os.fstat(descriptor)
        if (
            _atomic_create_identity(after) != receipt.file_identity
            or after.st_size != receipt.byte_count
            or _hash_file_descriptor(descriptor) != receipt.digest
        ):
            raise UnsafePathError(f"atomic-create rollback target changed: {target}")
        validate_owner_only_file_descriptor(
            descriptor,
            target,
            directory_fd=directory_fd,
            name=target.name,
        )
        os.unlink(target.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        primary = sys.exception()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as close_error:
                if primary is not None and hasattr(primary, "add_note"):
                    primary.add_note(
                        "atomic-create rollback target descriptor close failed: "
                        f"{type(close_error).__name__}"
                    )
        if lock_fd is not None:
            try:
                import fcntl

                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError as unlock_error:
                    if primary is not None and hasattr(primary, "add_note"):
                        primary.add_note(
                            "atomic-create rollback lock release failed: "
                            f"{type(unlock_error).__name__}"
                        )
            finally:
                try:
                    os.close(lock_fd)
                except OSError as close_error:
                    if primary is not None and hasattr(primary, "add_note"):
                        primary.add_note(
                            "atomic-create rollback lock descriptor close failed: "
                            f"{type(close_error).__name__}"
                        )
        try:
            os.close(directory_fd)
        except OSError as close_error:
            if primary is not None and hasattr(primary, "add_note"):
                primary.add_note(
                    "atomic-create rollback parent descriptor close failed: "
                    f"{type(close_error).__name__}"
                )


def atomic_write_json(
    path: str | os.PathLike[str],
    value: JsonValue,
    *,
    create_parents: bool = True,
) -> Path:
    return atomic_write_bytes(
        path,
        canonical_json_bytes(value) + b"\n",
        create_parents=create_parents,
    )


def atomic_create_json(
    path: str | os.PathLike[str],
    value: JsonValue,
    *,
    create_parents: bool = True,
) -> Path:
    return atomic_create_bytes(
        path,
        canonical_json_bytes(value) + b"\n",
        create_parents=create_parents,
    )


def fsync_directory(path: str | os.PathLike[str]) -> None:
    _, descriptor = open_owner_only_directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bounded_read_identity(st: os.stat_result) -> tuple[int, ...]:
    return (
        int(st.st_dev),
        int(st.st_ino),
        int(stat.S_IFMT(st.st_mode)),
    )


def _validate_bounded_read_policy(
    st: os.stat_result,
    display_path: Path,
    *,
    require_owner_only: bool,
) -> None:
    if require_owner_only:
        _validate_file_stat(st, display_path)
    elif not stat.S_ISREG(st.st_mode):
        raise UnsafePathError(f"expected a regular file: {display_path}")


def _read_bounded_descriptor_pass(
    descriptor: int,
    *,
    max_bytes: int,
    display_path: Path,
    consume: Callable[[bytes], None],
) -> tuple[int, bytes]:
    total = 0
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, min(64 * 1024, max_bytes - total + 1))
        if not chunk:
            break
        consume(chunk)
        digest.update(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise ReadLimitExceeded(
                f"file grew beyond byte limit ({max_bytes}): {display_path}"
            )
    return total, digest.digest()


def read_bounded_bytes_at(
    directory_fd: int,
    name: str,
    *,
    display_path: Path,
    max_bytes: int,
    require_owner_only: bool = True,
) -> bytes:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    descriptor = open_checked_file_at(
        directory_fd,
        name,
        display_path=display_path,
        require_owner_only=require_owner_only,
    )
    try:
        before = os.fstat(descriptor)
        _validate_bounded_read_policy(
            before,
            display_path,
            require_owner_only=require_owner_only,
        )
        if require_owner_only:
            _validate_owner_only_acl(descriptor, display_path)
        if before.st_size > max_bytes:
            raise ReadLimitExceeded(
                "file exceeds byte limit "
                f"({before.st_size} > {max_bytes}): {display_path}"
            )
        chunks: list[bytes] = []
        total, first_digest = _read_bounded_descriptor_pass(
            descriptor,
            max_bytes=max_bytes,
            display_path=display_path,
            consume=chunks.append,
        )
        after_first_read = os.fstat(descriptor)
        _validate_bounded_read_policy(
            after_first_read,
            display_path,
            require_owner_only=require_owner_only,
        )
        if require_owner_only:
            _validate_owner_only_acl(descriptor, display_path)
        if (
            _bounded_read_identity(before) != _bounded_read_identity(after_first_read)
            or total != before.st_size
            or after_first_read.st_size != before.st_size
        ):
            raise UnsafePathError(f"file changed while reading: {display_path}")

        os.lseek(descriptor, 0, os.SEEK_SET)
        verified_total, verification_digest = _read_bounded_descriptor_pass(
            descriptor,
            max_bytes=max_bytes,
            display_path=display_path,
            consume=lambda _chunk: None,
        )
        after_verification = os.fstat(descriptor)
        _validate_bounded_read_policy(
            after_verification,
            display_path,
            require_owner_only=require_owner_only,
        )
        if require_owner_only:
            _validate_owner_only_acl(descriptor, display_path)
        try:
            path_after_verification = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise UnsafePathError(
                f"file identity changed while reading: {display_path}"
            ) from exc
        _validate_bounded_read_policy(
            path_after_verification,
            display_path,
            require_owner_only=require_owner_only,
        )
        if require_owner_only:
            _validate_owner_only_acl(descriptor, display_path)
        if (
            _bounded_read_identity(before) != _bounded_read_identity(after_verification)
            or _bounded_read_identity(before)
            != _bounded_read_identity(path_after_verification)
            or verified_total != before.st_size
            or after_verification.st_size != before.st_size
            or path_after_verification.st_size != before.st_size
            or not hmac.compare_digest(first_digest, verification_digest)
        ):
            raise UnsafePathError(f"file content changed while reading: {display_path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_bounded_bytes(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    require_owner_only: bool = True,
) -> bytes:
    normalized, directory_fd = _open_parent_directory(path, create_parents=False)
    try:
        return read_bounded_bytes_at(
            directory_fd,
            normalized.name,
            display_path=normalized,
            max_bytes=max_bytes,
            require_owner_only=require_owner_only,
        )
    finally:
        os.close(directory_fd)


def fingerprint_file_bounded(
    path: str | os.PathLike[str],
    *,
    sample_bytes: int = 64 * 1024,
    require_owner_only: bool = True,
) -> str:
    """Return a stable content-free fingerprint with bounded memory and I/O."""

    if (
        not isinstance(sample_bytes, int)
        or isinstance(sample_bytes, bool)
        or sample_bytes < 1
    ):
        raise ValueError("sample_bytes must be a positive integer")
    normalized, directory_fd = _open_parent_directory(path, create_parents=False)
    try:
        descriptor = open_checked_file_at(
            directory_fd,
            normalized.name,
            display_path=normalized,
            require_owner_only=require_owner_only,
        )
        try:
            before = os.fstat(descriptor)
            if require_owner_only:
                _validate_owner_only_acl(descriptor, normalized)
            prefix = os.pread(descriptor, min(sample_bytes, before.st_size), 0)
            suffix_offset = max(0, before.st_size - sample_bytes)
            suffix = os.pread(
                descriptor,
                min(sample_bytes, before.st_size),
                suffix_offset,
            )
            after = os.fstat(descriptor)
            if require_owner_only:
                _validate_owner_only_acl(descriptor, normalized)
            before_identity = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            if before_identity != after_identity:
                raise UnsafePathError(
                    f"file changed while fingerprinting: {normalized}"
                )
            digest = hashlib.sha256()
            digest.update(b"bounded-file-fingerprint-v2\0")
            digest.update(str(before.st_size).encode("ascii"))
            digest.update(b"\0")
            digest.update(prefix)
            digest.update(b"\0")
            digest.update(suffix)
            return digest.hexdigest()
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def decode_json_bytes(data: bytes, *, label: str) -> Any:
    """Decode strict JSON using the checkpoint numeric model.

    Integers remain exact Python integers. Decimal and exponent forms become
    finite IEEE-754 binary64 values, including signed zero. Canonical writers
    use ``canonical_json_bytes``; consequently canonical byte equality keeps
    integers distinct from floats (for example, ``1`` versus ``1.0``).
    """

    try:
        return strict_json_loads(data)
    except StrictJsonError as exc:
        raise InvalidJsonError(f"invalid strict UTF-8 JSON in {label}") from exc


def read_bounded_json_at(
    directory_fd: int,
    name: str,
    *,
    display_path: Path,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    require_owner_only: bool = True,
) -> Any:
    data = read_bounded_bytes_at(
        directory_fd,
        name,
        display_path=display_path,
        max_bytes=max_bytes,
        require_owner_only=require_owner_only,
    )
    return decode_json_bytes(data, label=str(display_path))


def read_bounded_json(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    require_owner_only: bool = True,
) -> Any:
    normalized, directory_fd = _open_parent_directory(path, create_parents=False)
    try:
        return read_bounded_json_at(
            directory_fd,
            normalized.name,
            display_path=normalized,
            max_bytes=max_bytes,
            require_owner_only=require_owner_only,
        )
    finally:
        os.close(directory_fd)


def read_bounded_jsonl(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_JSONL_BYTES,
    max_lines: int = DEFAULT_MAX_JSONL_LINES,
    max_line_bytes: int = DEFAULT_MAX_JSONL_LINE_BYTES,
    require_owner_only: bool = True,
) -> list[Any]:
    if not isinstance(max_lines, int) or isinstance(max_lines, bool) or max_lines < 0:
        raise ValueError("max_lines must be a non-negative integer")
    if (
        not isinstance(max_line_bytes, int)
        or isinstance(max_line_bytes, bool)
        or max_line_bytes < 1
    ):
        raise ValueError("max_line_bytes must be a positive integer")

    normalized = _normalized_path(path)
    data = read_bounded_bytes(
        normalized,
        max_bytes=max_bytes,
        require_owner_only=require_owner_only,
    )
    raw_lines = data.split(b"\n")
    if raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()
    if len(raw_lines) > max_lines:
        raise ReadLimitExceeded(
            f"JSONL exceeds line limit ({len(raw_lines)} > {max_lines})"
        )

    rows: list[Any] = []
    for line_number, raw_line in enumerate(raw_lines, 1):
        if raw_line.endswith(b"\r"):
            raw_line = raw_line[:-1]
        if not raw_line:
            raise InvalidJsonError(f"blank JSONL line at {line_number}")
        if len(raw_line) > max_line_bytes:
            raise ReadLimitExceeded(
                f"JSONL line {line_number} exceeds byte limit "
                f"({len(raw_line)} > {max_line_bytes})"
            )
        rows.append(decode_json_bytes(raw_line, label=f"JSONL line {line_number}"))
    return rows


read_json = read_bounded_json
read_jsonl = read_bounded_jsonl
