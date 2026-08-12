"""Projection and authenticated loading of sealed raw agent artifacts."""

from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping

from . import safe_io, sharding
from .orchestrator_support import (
    InvalidTransitionError,
    RAW_SHARD_DIRECTORY,
)


def _binding(
    immutable: Mapping[str, Any],
    restore_manifest: Callable[[object], sharding.ShardManifest],
) -> tuple[Path, Mapping[str, Any], sharding.ShardManifest] | None:
    manifest_value = immutable.get("raw_manifest")
    relative_path = immutable.get("raw_artifact")
    if manifest_value is None and relative_path is None:
        return None
    if not isinstance(manifest_value, Mapping) or not isinstance(relative_path, str):
        raise InvalidTransitionError(
            "raw agent artifact requires one sealed path and manifest"
        )
    relative = Path(relative_path)
    if (
        relative.is_absolute()
        or relative.parts[:1] != (RAW_SHARD_DIRECTORY,)
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise InvalidTransitionError("raw agent artifact path is invalid")
    manifest = restore_manifest(manifest_value)
    if relative.name != manifest.file_name:
        raise InvalidTransitionError(
            "raw agent artifact path does not match its manifest"
        )
    return relative, manifest_value, manifest


def projected(
    immutable: Mapping[str, Any],
    *,
    restore_manifest: Callable[[object], sharding.ShardManifest],
) -> dict[str, Any] | None:
    binding = _binding(immutable, restore_manifest)
    if binding is None:
        return None
    _relative, manifest_value, manifest = binding
    return {
        "encoding": "base64",
        "manifest": copy.deepcopy(dict(manifest_value)),
        "payload_b64": "A" * (4 * ((manifest.byte_count + 2) // 3)),
    }


def sealed(
    run_dir: Path,
    immutable: Mapping[str, Any],
    *,
    restore_manifest: Callable[[object], sharding.ShardManifest],
) -> dict[str, Any] | None:
    binding = _binding(immutable, restore_manifest)
    if binding is None:
        return None
    relative, manifest_value, manifest = binding
    try:
        data = safe_io.read_bounded_bytes(
            run_dir / relative,
            max_bytes=manifest.byte_count,
            require_owner_only=True,
        )
    except (OSError, ValueError) as error:
        raise InvalidTransitionError(
            "raw agent artifact cannot be read within its sealed bound"
        ) from error
    if (
        len(data) != manifest.byte_count
        or hashlib.sha256(data).hexdigest() != manifest.content_sha256
    ):
        raise InvalidTransitionError(
            "raw agent artifact does not match its sealed manifest"
        )
    return {
        "encoding": "base64",
        "manifest": copy.deepcopy(dict(manifest_value)),
        "payload_b64": base64.b64encode(data).decode("ascii"),
    }
