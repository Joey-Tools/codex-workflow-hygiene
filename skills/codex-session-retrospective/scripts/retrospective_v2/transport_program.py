"""Closed executable commitment for the private source transport worker."""

from __future__ import annotations

import base64
import hashlib
import os
import pathlib
import stat
import sys
import tempfile
from typing import Callable, Mapping, Sequence

try:
    from .contracts import JsonValue
    from .transport_contracts import SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST
    from .transport_contracts import TransportValidationError, _canonical_commitment
    from .transport_paths import (
        _program_named_identity,
        _require_program_component_policy,
        _program_stat_identity,
        _read_program_component,
    )
except (ImportError, ModuleNotFoundError):
    from contracts import JsonValue  # type: ignore[no-redef]
    from transport_contracts import (  # type: ignore[no-redef]
        SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST,
        TransportValidationError,
        _canonical_commitment,
    )
    from transport_paths import (  # type: ignore[no-redef]
        _program_named_identity,
        _require_program_component_policy,
        _program_stat_identity,
        _read_program_component,
    )

SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES = 4 * 1024 * 1024
SOURCE_TRANSPORT_MAX_INTERPRETER_BYTES = 64 * 1024 * 1024
SOURCE_TRANSPORT_BASE_PYTHON_FLAGS = (
    "-I",
    "-B",
    "-S",
    "-X",
    f"pycache_prefix={os.devnull}",
)
SOURCE_TRANSPORT_SNAPSHOT_SCHEMA = "source_transport_worker_snapshot_v1"
SOURCE_TRANSPORT_MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
SOURCE_TRANSPORT_SNAPSHOT_CACHE = pathlib.Path(tempfile.gettempdir()) / (
    f"codex-session-retrospective-v2-program-{os.getuid()}"
)


def _program_component(
    path: pathlib.Path,
    *,
    role: str,
    allow_missing: bool,
    maximum_bytes: int = SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES,
    include_content: bool = False,
) -> dict[str, JsonValue]:
    path = pathlib.Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(path.parent, flags)
    except FileNotFoundError as exc:
        if allow_missing:
            return {"path": str(path), "role": role, "state": "absent"}
        raise TransportValidationError(
            f"source transport {role} is unavailable"
        ) from exc
    except OSError as exc:
        raise TransportValidationError(
            f"source transport {role} cannot be authenticated"
        ) from exc
    try:
        return _program_component_at(
            parent_fd,
            path.name,
            display_path=path,
            role=role,
            allow_missing=allow_missing,
            maximum_bytes=maximum_bytes,
            include_content=include_content,
        )
    finally:
        os.close(parent_fd)


def _program_component_at(
    parent_fd: int,
    name: str,
    *,
    display_path: pathlib.Path,
    role: str,
    allow_missing: bool,
    maximum_bytes: int = SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES,
    include_content: bool = False,
) -> dict[str, JsonValue]:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise TransportValidationError(
            f"source transport {role} has an invalid component name"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        if allow_missing:
            return {"path": str(display_path), "role": role, "state": "absent"}
        raise TransportValidationError(
            f"source transport {role} is unavailable"
        ) from exc
    except OSError as exc:
        raise TransportValidationError(
            f"source transport {role} cannot be authenticated"
        ) from exc
    try:
        before = os.fstat(descriptor)
        _require_program_component_policy(before, role)
        if before.st_size > maximum_bytes:
            raise TransportValidationError(
                f"source transport {role} exceeds the program component bound"
            )
        expected_identity = _program_stat_identity(before)
        if (
            _program_named_identity(parent_fd, name, role=role, phase="opened")
            != expected_identity
        ):
            raise TransportValidationError(
                f"source transport {role} changed while opened"
            )
        retained = _read_program_component(descriptor, maximum_bytes, role)
        changed_message = f"source transport {role} changed while read"
        if len(retained) != before.st_size:
            raise TransportValidationError(changed_message)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if _read_program_component(descriptor, maximum_bytes, role) != retained:
            raise TransportValidationError(changed_message)
        after = os.fstat(descriptor)
        if (
            _program_stat_identity(after) != expected_identity
            or after.st_size != before.st_size
            or _program_named_identity(parent_fd, name, role=role, phase="read")
            != expected_identity
        ):
            raise TransportValidationError(changed_message)
        _require_program_component_policy(after, role)
        component: dict[str, JsonValue] = {
            "content_commitment": "sha256:" + hashlib.sha256(retained).hexdigest(),
            "path": str(display_path),
            "role": role,
            "state": "present",
        }
        if include_content:
            component["content_b64"] = base64.b64encode(retained).decode("ascii")
        return component
    finally:
        os.close(descriptor)


def _package_program_components(
    package_dir: pathlib.Path,
    *,
    include_content: bool = False,
) -> list[dict[str, JsonValue]]:
    package_dir = pathlib.Path(os.path.abspath(os.fspath(package_dir)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(package_dir, flags)
    except OSError as exc:
        raise TransportValidationError(
            "source transport package tree cannot be authenticated"
        ) from exc
    try:
        before = os.fstat(directory_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise TransportValidationError(
                "source transport package tree must be a real directory"
            )
        manifest = SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST
        if len(manifest) != len(set(manifest)) or any(
            not name.endswith(".py")
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\x00" in name
            for name in manifest
        ):
            raise TransportValidationError(
                "source transport worker dependency manifest is invalid"
            )
        components = [
            _program_component_at(
                directory_fd,
                module_name,
                display_path=package_dir / module_name,
                role=f"package_module:{module_name}",
                allow_missing=False,
                include_content=include_content,
            )
            for module_name in manifest
        ]
        after = os.fstat(directory_fd)
        try:
            named_after = os.stat(package_dir, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise TransportValidationError(
                "source transport package tree changed while hashed"
            ) from exc
        if _program_stat_identity(after) != _program_stat_identity(before) or (
            named_after.st_dev,
            named_after.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise TransportValidationError(
                "source transport package tree changed while hashed"
            )
        return components
    finally:
        os.close(directory_fd)


def _python_runtime_authority(
    executable: str | os.PathLike[str] | None = None,
) -> dict[str, JsonValue]:
    selected = pathlib.Path(sys.executable if executable is None else executable)
    resolved = pathlib.Path(os.path.realpath(selected))
    return {
        "component": _program_component(
            resolved,
            role="python_interpreter",
            allow_missing=False,
            maximum_bytes=SOURCE_TRANSPORT_MAX_INTERPRETER_BYTES,
        ),
        "executable": str(resolved),
        "implementation": sys.implementation.name,
        "schema": "source_transport_python_runtime_v1",
        "version": list(sys.version_info),
    }


def _program_snapshot_protocol():
    try:
        from . import transport_snapshot
    except ImportError:
        import transport_snapshot  # type: ignore[no-redef]
    return transport_snapshot


def source_transport_python_command(
    snapshot_cache: pathlib.Path | None = None,
    *,
    stage_file: Callable[[pathlib.Path, bytes], None] | None = None,
    executable: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    python_runtime = _python_runtime_authority(executable)
    package_dir = pathlib.Path(
        os.path.abspath(os.fspath(pathlib.Path(__file__).parent))
    )
    return (
        str(python_runtime["executable"]),
        *_program_snapshot_protocol()._source_transport_snapshot_flags(
            package_dir=package_dir,
            components=_package_program_components(package_dir, include_content=True),
            module_manifest=SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST,
            python_runtime=python_runtime,
            base_flags=SOURCE_TRANSPORT_BASE_PYTHON_FLAGS,
            schema=SOURCE_TRANSPORT_SNAPSHOT_SCHEMA,
            cache=pathlib.Path(snapshot_cache or SOURCE_TRANSPORT_SNAPSHOT_CACHE),
            maximum_bytes=SOURCE_TRANSPORT_MAX_SNAPSHOT_BYTES,
            stage_file=stage_file,
        ),
    )


def _decode_program_snapshot(
    argv: tuple[str, ...],
    *,
    snapshot_cache: pathlib.Path,
    prepared_files: Mapping[pathlib.Path, bytes] | None = None,
    recover: bool = True,
) -> tuple[dict[str, JsonValue], int, str]:
    if not argv:
        raise TransportValidationError("source transport command is incomplete")
    executable = pathlib.Path(argv[0])
    canonical = pathlib.Path(os.path.realpath(executable))
    if not executable.is_absolute() or executable != canonical:
        raise TransportValidationError("source transport Python path is not canonical")
    protocol = _program_snapshot_protocol()
    prefix = (
        str(executable),
        *SOURCE_TRANSPORT_BASE_PYTHON_FLAGS,
        "-c",
        protocol.SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP,
        SOURCE_TRANSPORT_SNAPSHOT_SCHEMA,
    )
    return protocol._source_transport_decode_snapshot(
        argv,
        prefix=prefix,
        cache=snapshot_cache,
        maximum_bytes=SOURCE_TRANSPORT_MAX_SNAPSHOT_BYTES,
        component_reader=_program_component,
        prepared_files=prepared_files,
        recover=recover,
    )


def transport_program_commitment(
    command_argv: Sequence[str],
    *,
    snapshot_cache: pathlib.Path | None = None,
    prepared_files: Mapping[pathlib.Path, bytes] | None = None,
    recover: bool = True,
) -> str:
    """Commit every executable component used by one source transport lease."""
    argv = tuple(command_argv)
    snapshot, worker_index, snapshot_commitment = _decode_program_snapshot(
        argv,
        snapshot_cache=pathlib.Path(snapshot_cache or SOURCE_TRANSPORT_SNAPSHOT_CACHE),
        prepared_files=prepared_files,
        recover=recover,
    )
    worker = pathlib.Path(argv[worker_index])
    if not worker.is_absolute():
        raise TransportValidationError("source transport worker path must be absolute")
    package_dir = pathlib.Path(
        os.path.abspath(os.fspath(pathlib.Path(__file__).parent))
    )
    expected_worker = package_dir / "transport_worker.py"
    if worker != expected_worker:
        raise TransportValidationError(
            "source transport worker is outside the closed package dependency manifest"
        )
    modules = snapshot.get("modules")
    snapshot_authority = (
        set(snapshot),
        snapshot.get("schema"),
        snapshot.get("package_dir"),
        snapshot.get("python_runtime"),
        type(modules),
        tuple(getattr(modules, "keys", lambda: ())()),
    )
    expected_authority = (
        {"modules", "package_dir", "python_runtime", "schema"},
        SOURCE_TRANSPORT_SNAPSHOT_SCHEMA,
        str(package_dir),
        _python_runtime_authority(argv[0]),
        dict,
        SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST,
    )
    if snapshot_authority != expected_authority:
        raise TransportValidationError("source transport snapshot authority changed")
    components: list[dict[str, JsonValue]] = []
    for module_name, content in modules.items():
        if not isinstance(content, str):
            raise TransportValidationError(
                "source transport snapshot component is invalid"
            )
        try:
            decoded = base64.b64decode(content, validate=True)
        except ValueError as exc:
            raise TransportValidationError(
                "source transport snapshot component is invalid"
            ) from exc
        if len(decoded) > SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES:
            raise TransportValidationError(
                "source transport snapshot component is too large"
            )
        components.append(
            {
                "content_commitment": "sha256:" + hashlib.sha256(decoded).hexdigest(),
                "path": str(package_dir / module_name),
                "role": f"package_module:{module_name}",
                "state": "present",
            }
        )
    helper_count = argv.count("--remote-helper")
    commitment_count = argv.count("--remote-helper-commitment")
    if helper_count or commitment_count:
        if helper_count != 1 or commitment_count != 1:
            raise TransportValidationError(
                "source transport remote helper binding is invalid"
            )
        helper_index = argv.index("--remote-helper")
        commitment_index = argv.index("--remote-helper-commitment")
        if helper_index + 1 >= len(argv) or commitment_index + 1 >= len(argv):
            raise TransportValidationError(
                "source transport remote helper binding is invalid"
            )
        helper = pathlib.Path(argv[helper_index + 1])
        helper_commitment = argv[commitment_index + 1]
        expected_helper = (
            _program_snapshot_protocol()._source_transport_external_snapshot_path(
                pathlib.Path(snapshot_cache or SOURCE_TRANSPORT_SNAPSHOT_CACHE),
                helper_commitment,
            )
        )
        if not helper.is_absolute() or helper != expected_helper:
            raise TransportValidationError(
                "source transport remote helper snapshot path is invalid"
            )
        prepared_helper = None if prepared_files is None else prepared_files.get(helper)
        if prepared_helper is None:
            helper_component = _program_component(
                helper,
                role="remote_host_context_helper",
                allow_missing=False,
            )
        else:
            if (
                not isinstance(prepared_helper, bytes)
                or len(prepared_helper) > SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES
            ):
                raise TransportValidationError(
                    "source transport remote helper snapshot is invalid"
                )
            helper_component = {
                "content_commitment": "sha256:"
                + hashlib.sha256(prepared_helper).hexdigest(),
                "path": str(helper),
                "role": "remote_host_context_helper",
                "state": "present",
            }
        if helper_component["content_commitment"] != helper_commitment:
            raise TransportValidationError(
                "source transport remote helper snapshot changed"
            )
        components.append(helper_component)
    protocol = _program_snapshot_protocol()
    bootstrap = protocol.SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP.encode("utf-8")
    return _canonical_commitment(
        {
            "components": components,
            "module_manifest": list(SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST),
            "python_flags": list(SOURCE_TRANSPORT_BASE_PYTHON_FLAGS),
            "python_runtime": snapshot["python_runtime"],
            "snapshot_bootstrap_commitment": "sha256:"
            + hashlib.sha256(bootstrap).hexdigest(),
            "remote_helper_bootstrap_commitment": "sha256:"
            + hashlib.sha256(
                protocol.REMOTE_HOST_CONTEXT_SNAPSHOT_BOOTSTRAP.encode("utf-8")
            ).hexdigest(),
            "snapshot_commitment": snapshot_commitment,
            "schema": "source_transport_worker_program_v8",
        }
    )
