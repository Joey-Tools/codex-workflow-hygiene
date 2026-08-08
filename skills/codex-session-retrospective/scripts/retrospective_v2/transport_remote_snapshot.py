"""Parent-owned snapshots of the canonical remote transport helper."""

from __future__ import annotations

import base64
import hashlib
import hmac
import pathlib

try:
    from . import safe_io
    from .transport_contracts import TransportValidationError
    from .transport_program import (
        SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES,
        _program_component,
    )
    from .transport_snapshot import _source_transport_external_snapshot_path
    from .transport_remote import remote_host_context_helper_component_commitment
except (ImportError, ModuleNotFoundError):
    import safe_io  # type: ignore[no-redef]
    from transport_contracts import (  # type: ignore[no-redef]
        TransportValidationError,
    )
    from transport_program import (  # type: ignore[no-redef]
        SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES,
        _program_component,
    )
    from transport_snapshot import (  # type: ignore[no-redef]
        _source_transport_external_snapshot_path,
    )
    from transport_remote import (  # type: ignore[no-redef]
        remote_host_context_helper_component_commitment,
    )


def snapshot_remote_host_context_helper(
    path: pathlib.Path,
    snapshot_cache: pathlib.Path,
    *,
    expected_source_commitment: str | None = None,
) -> tuple[pathlib.Path, str]:
    component = _program_component(
        pathlib.Path(path),
        role="remote_host_context_helper",
        allow_missing=False,
        maximum_bytes=SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES,
        include_content=True,
    )
    observed_source_commitment = remote_host_context_helper_component_commitment(
        component
    )
    if expected_source_commitment is not None and (
        not isinstance(expected_source_commitment, str)
        or not hmac.compare_digest(
            observed_source_commitment,
            expected_source_commitment,
        )
    ):
        raise TransportValidationError(
            "remote-host-context helper differs from the run provenance"
        )
    payload = base64.b64decode(str(component["content_b64"]), validate=True)
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    snapshot_path = _source_transport_external_snapshot_path(
        pathlib.Path(snapshot_cache), digest
    )
    safe_io.ensure_owner_only_directory(snapshot_path.parent)
    safe_io.recover_atomic_create(snapshot_path)
    try:
        safe_io.atomic_create_bytes(snapshot_path, payload, create_parents=False)
    except FileExistsError:
        existing = safe_io.read_bounded_bytes(
            snapshot_path,
            max_bytes=SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES,
            require_owner_only=True,
        )
        if not hmac.compare_digest(existing, payload):
            raise TransportValidationError("source transport external snapshot changed")
    return snapshot_path, digest
