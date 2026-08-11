"""Closed local-repository completeness checks for retained-history Git reads."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess

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
    forbidden = (
        (object_store / "info" / "alternates", "Git object alternates"),
        (common_dir / "info" / "grafts", "Git grafts"),
    )
    _reject_forbidden_metadata(forbidden)
    try:
        validate_complete_local_repository_commands(run)
    except ValueError as exc:
        raise LocalRepositorySafetyError(
            "incomplete", "repository must be complete and non-promisor"
        ) from exc
    return LocalRepositoryAdmission(
        repository=repository,
        git_dir=git_dir,
        common_dir=common_dir,
        object_store=object_store,
        directory_identities=tuple(identities),
        forbidden_metadata=forbidden,
    )


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
