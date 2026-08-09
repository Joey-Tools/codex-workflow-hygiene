"""Closed local-repository completeness checks for retained-history Git reads."""

from __future__ import annotations

from collections.abc import Callable
import os
import subprocess


GitRunner = Callable[[tuple[str, ...]], subprocess.CompletedProcess[bytes]]


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
