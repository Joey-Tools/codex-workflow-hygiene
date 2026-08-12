"""Closed local-repository completeness checks for retained-history Git reads."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Iterator, Mapping, Sequence

from . import executable_authority, safe_io
from .authority_errors import HistoryValidationError


GitRunner = Callable[[tuple[str, ...]], subprocess.CompletedProcess[bytes]]
DirectoryIdentity = Callable[[Path], tuple[int, ...]]


class LocalRepositorySafetyError(ValueError):
    """A closed local-repository admission property was not proved."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class LocalRepositoryAdmission:
    """Filesystem binding shared by history readers and publishers."""

    repository: Path
    git_dir: Path
    common_dir: Path
    object_store: Path
    directory_identities: tuple[tuple[Path, tuple[int, ...]], ...]
    forbidden_metadata: tuple[tuple[Path, str], ...]
    config_path: Path
    config_sha256: str


@dataclass
class LocalRepositoryCommandBinding:
    """Held directory objects used by one admitted Git subprocess."""

    admission: LocalRepositoryAdmission
    repository_fd: int
    git_dir_fd: int
    common_dir_fd: int
    object_store_fd: int

    @property
    def descriptors(self) -> tuple[int, ...]:
        return (
            self.repository_fd,
            self.git_dir_fd,
            self.common_dir_fd,
            self.object_store_fd,
        )

    def command(
        self,
        python_executable: str,
        executable: str,
        arguments: Sequence[str],
    ) -> tuple[str, ...]:
        return (
            python_executable,
            "-I",
            "-B",
            "-S",
            "-c",
            _DESCRIPTOR_CWD_EXEC_SOURCE,
            str(self.repository_fd),
            executable,
            "-C",
            ".",
            *arguments,
        )


_CONFIG_LIMIT_BYTES = 1024 * 1024
_DESCRIPTOR_CWD_EXEC_SOURCE = (
    "import os,sys\n"
    "descriptor=int(sys.argv[1])\n"
    "os.fchdir(descriptor)\n"
    "os.execve(sys.argv[2],sys.argv[2:],os.environ)\n"
)


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid


def _config_stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
    )


def _close_descriptors(descriptors: Sequence[int], label: str) -> None:
    failures: list[OSError] = []
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError as error:
            failures.append(error)
    if not failures:
        return
    message = f"{label} descriptor close failed"
    if (active_error := sys.exception()) is not None:
        active_error.add_note(message)
        return
    raise LocalRepositorySafetyError("descriptor-close-failed", message) from failures[
        0
    ]


def _config_commitment(common_dir_fd: int, display_path: Path) -> str:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open("config", flags, dir_fd=common_dir_fd)
    except OSError as exc:
        raise LocalRepositorySafetyError(
            "config-unreadable", "local Git configuration cannot be authenticated"
        ) from exc
    try:
        before = os.fstat(descriptor)
        named_before = os.stat("config", dir_fd=common_dir_fd, follow_symlinks=False)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or mode & 0o022
            or before.st_nlink != 1
            or before.st_size > _CONFIG_LIMIT_BYTES
            or _config_stat_identity(named_before) != _config_stat_identity(before)
        ):
            raise LocalRepositorySafetyError(
                "config-unsafe", "local Git configuration is not owner-controlled"
            )
        remaining = _CONFIG_LIMIT_BYTES + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        named_after = os.stat("config", dir_fd=common_dir_fd, follow_symlinks=False)
        if (
            _config_stat_identity(after) != _config_stat_identity(before)
            or _config_stat_identity(named_after) != _config_stat_identity(before)
            or len(payload) != after.st_size
            or len(payload) > _CONFIG_LIMIT_BYTES
        ):
            raise LocalRepositorySafetyError(
                "config-changed", "local Git configuration changed while read"
            )
        return hashlib.sha256(payload).hexdigest()
    except LocalRepositorySafetyError:
        raise
    except OSError as exc:
        raise LocalRepositorySafetyError(
            "config-unreadable", "local Git configuration cannot be authenticated"
        ) from exc
    finally:
        _close_descriptors((descriptor,), "Git config")


def _open_bound_directory(
    path: Path,
    expected: tuple[int, ...],
) -> int:
    descriptor: int | None = None
    try:
        _normalized, descriptor = safe_io.open_owner_controlled_directory(path)
        metadata = safe_io.validate_owner_only_directory_descriptor(
            descriptor, path, exact_mode=False
        )
        if _stat_identity(metadata) != expected:
            raise safe_io.UnsafePathError("Git metadata identity changed")
    except (OSError, safe_io.UnsafePathError) as exc:
        if descriptor is not None:
            _close_descriptors((descriptor,), "Git metadata")
        raise LocalRepositorySafetyError(
            "metadata-changed", "Git metadata changed after validation"
        ) from exc
    assert descriptor is not None
    return descriptor


def _revalidate_command_binding(binding: LocalRepositoryCommandBinding) -> None:
    identities = dict(binding.admission.directory_identities)
    for path, descriptor in (
        (binding.admission.repository, binding.repository_fd),
        (binding.admission.git_dir, binding.git_dir_fd),
        (binding.admission.common_dir, binding.common_dir_fd),
        (binding.admission.object_store, binding.object_store_fd),
    ):
        try:
            metadata = safe_io.validate_owner_only_directory_descriptor(
                descriptor, path, exact_mode=False
            )
        except (OSError, safe_io.UnsafePathError) as exc:
            raise LocalRepositorySafetyError(
                "metadata-changed", "Git metadata changed after validation"
            ) from exc
        if _stat_identity(metadata) != identities[path]:
            raise LocalRepositorySafetyError(
                "metadata-changed", "Git metadata changed after validation"
            )
    if (
        _config_commitment(binding.common_dir_fd, binding.admission.config_path)
        != binding.admission.config_sha256
    ):
        raise LocalRepositorySafetyError(
            "config-changed", "local Git configuration changed after validation"
        )


@contextmanager
def bind_local_repository_command(
    admission: LocalRepositoryAdmission,
    directory_identity: DirectoryIdentity,
) -> Iterator[LocalRepositoryCommandBinding]:
    """Hold every admitted directory across one Git subprocess."""

    revalidate_local_repository(admission, directory_identity)
    expected = dict(admission.directory_identities)
    descriptors: list[int] = []
    try:
        for path in (
            admission.repository,
            admission.git_dir,
            admission.common_dir,
            admission.object_store,
        ):
            descriptors.append(_open_bound_directory(path, expected[path]))
        binding = LocalRepositoryCommandBinding(admission, *descriptors)
        _revalidate_command_binding(binding)
        try:
            yield binding
        except BaseException as operation_error:
            try:
                _revalidate_command_binding(binding)
                revalidate_local_repository(admission, directory_identity)
            except BaseException as validation_error:
                raise validation_error from operation_error
            raise
        _revalidate_command_binding(binding)
        revalidate_local_repository(admission, directory_identity)
    finally:
        _close_descriptors(descriptors, "Git metadata")


@contextmanager
def repository_git_invocation(
    admission: LocalRepositoryAdmission | None,
    repository: Path,
    executable: str,
    arguments: Sequence[str],
    environment: Mapping[str, str],
    directory_identity: DirectoryIdentity,
) -> Iterator[tuple[tuple[str, ...], dict[str, str], tuple[int, ...]]]:
    """Build one bootstrap or descriptor-bound Git invocation."""

    if admission is None:
        yield (
            (executable, "-C", str(repository), *arguments),
            dict(environment),
            (),
        )
        return
    python_authority = executable_authority.resolve_executable(
        sys.executable, label="Python"
    )
    with executable_authority.executable_invocation(python_authority):
        with bind_local_repository_command(admission, directory_identity) as binding:
            yield (
                binding.command(python_authority.path, executable, arguments),
                dict(environment),
                binding.descriptors,
            )


@contextmanager
def history_repository_git_invocation(
    admission: LocalRepositoryAdmission | None,
    repository: Path,
    executable: str,
    arguments: Sequence[str],
    environment: Mapping[str, str],
    directory_identity: DirectoryIdentity,
) -> Iterator[tuple[tuple[str, ...], dict[str, str], tuple[int, ...]]]:
    """Map descriptor-bound launch failures to the history API."""

    try:
        with repository_git_invocation(
            admission,
            repository,
            executable,
            arguments,
            environment,
            directory_identity,
        ) as invocation:
            yield invocation
    except (OSError, LocalRepositorySafetyError, safe_io.UnsafePathError) as error:
        raise HistoryValidationError(
            "history repository safety binding changed"
        ) from error


def local_only_git_environment() -> dict[str, str]:
    """Return process controls shared by all retained-history Git callers."""

    return {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "PAGER": "cat",
        "SSH_ASKPASS": "/usr/bin/false",
    }


def history_git_environment(*, home: str, gnupg_home: str) -> dict[str, str]:
    """Return the complete environment for authenticated history reads."""

    return {
        **local_only_git_environment(),
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TZ": "UTC",
        "GNUPGHOME": gnupg_home,
    }


def validate_complete_local_repository_commands(run: GitRunner) -> None:
    """Probe completeness without reading repository objects."""

    shallow = run(("rev-parse", "--is-shallow-repository"))
    config = run(("config", "--local", "--no-includes", "--name-only", "--list"))
    if shallow.returncode != 0 or config.returncode != 0:
        raise ValueError("repository completeness cannot be verified")
    validate_complete_local_repository(shallow.stdout, config.stdout)


def validate_complete_local_repository(
    shallow_output: bytes,
    local_config_keys_output: bytes,
) -> None:
    """Reject repository modes that may lazily obtain missing objects."""

    if shallow_output.strip() != b"false":
        raise ValueError("repository is shallow")
    try:
        keys = local_config_keys_output.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("local Git configuration keys are not ASCII") from error
    if any(not key or "\x00" in key for key in keys):
        raise ValueError("local Git configuration keys are malformed")
    normalized = [key.casefold() for key in keys]
    if any(
        key == "include.path"
        or (key.startswith("includeif.") and key.endswith(".path"))
        or key == "extensions.worktreeconfig"
        for key in normalized
    ):
        raise ValueError("repository has unclosed local configuration sources")
    if any(
        key == "extensions.partialclone"
        or (
            key.startswith("remote.")
            and key.endswith((".promisor", ".partialclonefilter"))
        )
        for key in normalized
    ):
        raise ValueError("repository has promisor or partial-clone configuration")


def _absolute_git_path(run: GitRunner, option: str, *values: str) -> Path:
    result = run(("rev-parse", "--path-format=absolute", option, *values))
    path = Path(os.fsdecode(result.stdout).strip())
    if not all((result.returncode == 0, path.is_absolute())):
        raise LocalRepositorySafetyError(
            "metadata-path-invalid", "Git metadata path is invalid"
        )
    return path


def _reject_forbidden_metadata(entries: tuple[tuple[Path, str], ...]) -> None:
    for path, label in entries:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise LocalRepositorySafetyError(
                "metadata-unreadable", f"{label} cannot be authenticated"
            ) from exc
        raise LocalRepositorySafetyError(
            "forbidden-metadata", f"{label} are not allowed"
        )


def admit_local_repository(
    repository: Path,
    run: GitRunner,
    directory_identity: DirectoryIdentity,
) -> LocalRepositoryAdmission:
    """Authenticate one complete local worktree and its closed object store."""

    repository = repository.absolute()
    identities = [(repository, directory_identity(repository))]
    probe = run(("rev-parse", "--is-inside-work-tree"))
    if not all((probe.returncode == 0, probe.stdout.strip() == b"true")):
        raise LocalRepositorySafetyError(
            "not-worktree", "repository is not a Git work tree"
        )
    git_dir = _absolute_git_path(run, "--git-dir")
    common_dir = _absolute_git_path(run, "--git-common-dir")
    object_store = common_dir / "objects"
    if _absolute_git_path(run, "--git-path", "objects") != object_store:
        raise LocalRepositorySafetyError(
            "object-store-not-closed", "Git object store path is not closed"
        )
    identities.extend(
        map(
            lambda path: (path, directory_identity(path)),
            (git_dir, common_dir, object_store),
        )
    )
    forbidden_by_path = {
        object_store / "info" / "alternates": "Git object alternates",
        common_dir / "info" / "grafts": "Git grafts",
        common_dir / "config.worktree": "Git worktree configurations",
        git_dir / "config.worktree": "Git worktree configurations",
    }
    forbidden = tuple(forbidden_by_path.items())
    _reject_forbidden_metadata(forbidden)
    try:
        validate_complete_local_repository_commands(run)
    except ValueError as exc:
        raise LocalRepositorySafetyError(
            "incomplete", "repository must be complete and non-promisor"
        ) from exc
    _normalized, common_dir_fd = safe_io.open_owner_controlled_directory(common_dir)
    try:
        config_path = common_dir / "config"
        config_sha256 = _config_commitment(common_dir_fd, config_path)
    finally:
        _close_descriptors((common_dir_fd,), "Git common directory")
    admission = LocalRepositoryAdmission(
        repository=repository,
        git_dir=git_dir,
        common_dir=common_dir,
        object_store=object_store,
        directory_identities=tuple(identities),
        forbidden_metadata=forbidden,
        config_path=config_path,
        config_sha256=config_sha256,
    )
    revalidate_local_repository(admission, directory_identity)
    return admission


def revalidate_local_repository(
    admission: LocalRepositoryAdmission,
    directory_identity: DirectoryIdentity,
) -> None:
    """Recheck the admitted filesystem objects before each history Git call."""

    for path, expected in admission.directory_identities:
        if directory_identity(path) != expected:
            raise LocalRepositorySafetyError(
                "metadata-changed", "Git metadata changed after validation"
            )
    _reject_forbidden_metadata(admission.forbidden_metadata)
    _normalized, common_dir_fd = safe_io.open_owner_controlled_directory(
        admission.common_dir
    )
    try:
        if (
            _config_commitment(common_dir_fd, admission.config_path)
            != admission.config_sha256
        ):
            raise LocalRepositorySafetyError(
                "config-changed", "local Git configuration changed after validation"
            )
    finally:
        _close_descriptors((common_dir_fd,), "Git common directory")


def admit_history_repository(
    repository: Path,
    run: GitRunner,
    directory_identity: DirectoryIdentity,
) -> LocalRepositoryAdmission:
    """Map shared admission failures to the durable-history API."""

    try:
        return admit_local_repository(repository, run, directory_identity)
    except (OSError, ValueError) as error:
        message = {
            "incomplete": "history repository must be complete and non-promisor"
        }.get(
            getattr(error, "reason", None),
            "history repository failed local safety admission",
        )
        raise HistoryValidationError(message) from error


def revalidate_history_repository(
    admission: LocalRepositoryAdmission | None,
    directory_identity: DirectoryIdentity,
) -> None:
    """Map shared revalidation failures to the durable-history API."""

    if admission is None:
        return
    try:
        revalidate_local_repository(admission, directory_identity)
    except (OSError, ValueError) as error:
        raise HistoryValidationError(
            "history repository safety binding changed"
        ) from error
