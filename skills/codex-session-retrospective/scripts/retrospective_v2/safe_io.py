from __future__ import annotations

import ctypes
import errno
from functools import lru_cache
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
from typing import Any, Callable

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


class InvalidJsonError(ValueError):
    pass


PathSecurityError = UnsafePathError
BoundedReadError = ReadLimitExceeded


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


def secure_remove_tree_at(
    parent_fd: int,
    name: str,
    *,
    display_path: Path,
) -> dict[str, int]:
    """Remove one owner-only tree through an already anchored parent fd."""

    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise UnsafePathError("remove-tree name must be one safe component")
    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
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
        counts = {"byte_count": 0, "directory_count": 1, "file_count": 0}
        for child_name in sorted(os.listdir(descriptor), key=os.fsencode):
            child_path = display_path / child_name
            child = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                nested = secure_remove_tree_at(
                    descriptor,
                    child_name,
                    display_path=child_path,
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
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)
    return counts


def inspect_tree_at(
    parent_fd: int,
    name: str,
    *,
    display_path: Path,
) -> dict[str, int]:
    """Count one owner-only tree without following caller-controlled links."""

    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise UnsafePathError("inspect-tree name must be one safe component")
    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return {"byte_count": 0, "directory_count": 0, "file_count": 0}
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
        counts = {"byte_count": 0, "directory_count": 1, "file_count": 0}
        for child_name in sorted(os.listdir(descriptor), key=os.fsencode):
            child_path = display_path / child_name
            child = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                nested = inspect_tree_at(
                    descriptor,
                    child_name,
                    display_path=child_path,
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
                current = os.stat(
                    child_name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    anchored_child.st_dev,
                    anchored_child.st_ino,
                    anchored_child.st_size,
                ) != (current.st_dev, current.st_ino, current.st_size):
                    raise UnsafePathError(
                        f"inspected file changed while counted: {child_path}"
                    )
                _validate_owner_only_acl(child_fd, child_path)
                counts["byte_count"] += anchored_child.st_size
                counts["file_count"] += 1
            finally:
                os.close(child_fd)
        validate_owner_only_directory_descriptor(descriptor, display_path)
        current_root = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (anchored.st_dev, anchored.st_ino) != (
            current_root.st_dev,
            current_root.st_ino,
        ):
            raise UnsafePathError(
                f"inspected tree name changed while counted: {display_path}"
            )
        return counts
    finally:
        os.close(descriptor)


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
    return f"{_ATOMIC_CREATE_PREFIX}{_atomic_create_target_token(target_name)}.lock"


def _hash_file_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
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


def atomic_create_bytes(
    path: str | os.PathLike[str],
    data: bytes | bytearray | memoryview,
    *,
    create_parents: bool = True,
) -> Path:
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
        return target
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
