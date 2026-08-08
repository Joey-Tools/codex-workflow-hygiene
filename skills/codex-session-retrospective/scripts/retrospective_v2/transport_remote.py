"""Bounded delegation through the canonical remote-host-context helper."""

from __future__ import annotations

import argparse
import codecs
import os
import pathlib
import pwd
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

try:
    from .transport_contracts import TransportValidationError, _canonical_commitment
    from .transport_program import _program_component
    from .transport_snapshot import (
        REMOTE_HOST_CONTEXT_SNAPSHOT_BOOTSTRAP,
        REMOTE_HOST_CONTEXT_SNAPSHOT_SCHEMA,
    )
except (ImportError, ModuleNotFoundError):
    from transport_contracts import (  # type: ignore[no-redef]
        TransportValidationError,
        _canonical_commitment,
    )
    from transport_program import _program_component  # type: ignore[no-redef]
    from transport_snapshot import (  # type: ignore[no-redef]
        REMOTE_HOST_CONTEXT_SNAPSHOT_BOOTSTRAP,
        REMOTE_HOST_CONTEXT_SNAPSHOT_SCHEMA,
    )

REMOTE_HOST_CONTEXT_HELPER_RELATIVE_PATH = pathlib.PurePosixPath(
    ".codex/skills/remote-host-context/scripts/remote_codex_probe.py"
)
REMOTE_HOST_CONTEXT_COMMAND_TIMEOUT_SECONDS = 60
REMOTE_HOST_CONTEXT_FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
REMOTE_HOST_CONTEXT_AUTH_ENVIRONMENT_KEYS = ("SSH_AUTH_SOCK",)


def remote_host_context_helper_path() -> pathlib.Path:
    return pathlib.Path.home().joinpath(*REMOTE_HOST_CONTEXT_HELPER_RELATIVE_PATH.parts)


def remote_host_context_helper_commitment(
    path: str | os.PathLike[str] | None = None,
) -> str:
    helper = remote_host_context_helper_path() if path is None else pathlib.Path(path)
    return remote_host_context_helper_component_commitment(
        _program_component(
            helper,
            role="remote_host_context_helper",
            allow_missing=False,
        )
    )


def remote_host_context_helper_component_commitment(
    component: Mapping[str, Any],
) -> str:
    committed_component = dict(component)
    committed_component.pop("content_b64", None)
    return _canonical_commitment(
        {
            "component": committed_component,
            "relative_contract": REMOTE_HOST_CONTEXT_HELPER_RELATIVE_PATH.as_posix(),
            "schema": "remote_host_context_helper_commitment_v2",
        }
    )


def _remote_host_context_command(
    args: argparse.Namespace,
    command: str,
    command_arguments: Sequence[str],
) -> tuple[str, ...]:
    configured_helper = getattr(args, "remote_helper", None)
    helper_commitment = getattr(args, "remote_helper_commitment", None)
    helper = pathlib.Path(configured_helper or "")
    if (
        not configured_helper
        or not helper.is_absolute()
        or not isinstance(helper_commitment, str)
        or len(helper_commitment) != 71
        or not helper_commitment.startswith("sha256:")
        or any(
            character not in "0123456789abcdef" for character in helper_commitment[7:]
        )
    ):
        raise ValueError("remote-host-context helper snapshot binding is invalid")
    return (
        sys.executable,
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={os.devnull}",
        "-c",
        REMOTE_HOST_CONTEXT_SNAPSHOT_BOOTSTRAP,
        REMOTE_HOST_CONTEXT_SNAPSHOT_SCHEMA,
        helper_commitment,
        str(helper),
        command,
        "--host",
        str(args.host),
        *command_arguments,
    )


def _remote_host_context_environment() -> dict[str, str]:
    try:
        account = pwd.getpwuid(os.getuid())
    except (KeyError, OSError) as exc:
        raise RuntimeError("remote-host-context account identity unavailable") from exc
    if not account.pw_name or not account.pw_dir:
        raise RuntimeError("remote-host-context account identity unavailable")
    account_home = pathlib.PurePath(account.pw_dir)
    if not account_home.is_absolute() or "\x00" in account.pw_dir:
        raise RuntimeError("remote-host-context account home is invalid")

    environment = {
        "HOME": account.pw_dir,
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": account.pw_name,
        "PATH": REMOTE_HOST_CONTEXT_FIXED_PATH,
        "USER": account.pw_name,
    }
    for key in REMOTE_HOST_CONTEXT_AUTH_ENVIRONMENT_KEYS:
        value = os.environ.get(key)
        if value is None:
            continue
        if (
            not value
            or "\x00" in value
            or "\n" in value
            or "\r" in value
            or not pathlib.PurePath(value).is_absolute()
        ):
            raise RuntimeError(
                "remote-host-context authentication environment is invalid"
            )
        environment[key] = value
    return environment


def _relay_valid_utf8(output: Any) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    output.seek(0)
    while chunk := output.read(64 * 1024):
        decoder.decode(chunk, final=False)
    decoder.decode(b"", final=True)
    output.seek(0)
    binary_stdout = getattr(sys.stdout, "buffer", None)
    if binary_stdout is not None:
        while chunk := output.read(64 * 1024):
            binary_stdout.write(chunk)
        binary_stdout.flush()
        return
    text_decoder = codecs.getincrementaldecoder("utf-8")("strict")
    while chunk := output.read(64 * 1024):
        sys.stdout.write(text_decoder.decode(chunk, final=False))
    sys.stdout.write(text_decoder.decode(b"", final=True))
    sys.stdout.flush()


def _terminate_remote_process_group(process: subprocess.Popen[bytes]) -> None:
    terminations = {
        False: (process.kill,),
        True: (lambda: os.killpg(process.pid, signal.SIGKILL), process.kill),
    }[os.name == "posix"]
    for terminate in terminations:
        try:
            terminate()
        except OSError:
            pass


def _close_remote_process_group(process: subprocess.Popen[bytes]) -> int:
    _terminate_remote_process_group(process)
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "remote-host-context transport did not terminate"
            ) from exc


def _filter_remote_output(stream_filter: Any, chunk: bytes | None = None) -> bytes:
    try:
        if chunk is None:
            return stream_filter.finish()
        return chunk if stream_filter is None else stream_filter.feed(chunk)
    except (TransportValidationError, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(
            "remote-host-context transport emitted an invalid protocol stream"
        ) from exc


def _relay_remote_host_context_command(
    argv: Sequence[str],
    *,
    max_output_bytes: int,
    validator: Callable[[Any], None] | None = None,
    stream_filter: Any | None = None,
) -> None:
    """Run the canonical helper with bounded, content-free failure handling."""

    if max_output_bytes < 1:
        raise RuntimeError("remote-host-context output envelope is invalid")
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_remote_host_context_environment(),
            close_fds=True,
            start_new_session=os.name == "posix",
        )
    except OSError as exc:
        raise RuntimeError("remote-host-context transport unavailable") from exc

    leader_reaped = False

    selector = selectors.DefaultSelector()
    active_error: BaseException | None = None
    try:
        if process.stdout is None:
            raise RuntimeError("remote-host-context transport unavailable")
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + REMOTE_HOST_CONTEXT_COMMAND_TIMEOUT_SECONDS
        with tempfile.TemporaryFile(mode="w+b") as output:
            input_bytes = 0
            output_bytes = 0
            timed_out = False
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if not selector.select(remaining):
                    timed_out = True
                    break
                try:
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                input_bytes += len(chunk)
                if input_bytes > max_output_bytes:
                    raise RuntimeError(
                        "remote-host-context transport exceeded its output envelope"
                    )
                filtered = _filter_remote_output(stream_filter, chunk)
                output_bytes += len(filtered)
                if output_bytes > max_output_bytes:
                    raise RuntimeError(
                        "remote-host-context transport exceeded its output envelope"
                    )
                output.write(filtered)
            if timed_out:
                raise RuntimeError("remote-host-context transport unavailable")
            if stream_filter is not None:
                filtered = _filter_remote_output(stream_filter)
                output_bytes += len(filtered)
                if output_bytes > max_output_bytes:
                    raise RuntimeError(
                        "remote-host-context transport exceeded its output envelope"
                    )
                output.write(filtered)
            # Close the task-owned group while the unreaped leader still pins
            # its PID/PGID. Reaping first would open a reuse race.
            return_code = _close_remote_process_group(process)
            leader_reaped = True
            if return_code != 0:
                raise RuntimeError("remote-host-context transport unavailable")
            if validator is not None:
                try:
                    validator(output)
                except (OSError, TransportValidationError, ValueError) as exc:
                    raise RuntimeError(
                        "remote-host-context transport emitted an invalid protocol stream"
                    ) from exc
            try:
                _relay_valid_utf8(output)
            except UnicodeDecodeError as exc:
                raise RuntimeError(
                    "remote-host-context transport emitted invalid UTF-8"
                ) from exc
    except BaseException as exc:
        active_error = exc
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if not leader_reaped:
            try:
                _close_remote_process_group(process)
            except RuntimeError as cleanup_error:
                if active_error is None:
                    raise
                active_error.add_note(str(cleanup_error))
