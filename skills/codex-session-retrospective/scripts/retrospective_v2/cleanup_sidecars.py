"""Bounded owner-only sidecars for exact cleanup inventories."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import safe_io
from .checkpoints import canonical_json_bytes
from .contracts import (
    MAX_CLEANUP_INVENTORY_BYTES,
    MAX_CLEANUP_INVENTORY_DEPTH as MAX_CLEANUP_INVENTORY_DEPTH,
    MAX_CLEANUP_INVENTORY_ENTRIES,
    MAX_CLEANUP_INVENTORY_PATH_BYTES,
    MAX_CLEANUP_INVENTORY_SECONDS as MAX_CLEANUP_INVENTORY_SECONDS,
    strict_json_loads,
)
from .orchestrator_support import InvalidTransitionError


CLEANUP_INVENTORY_SCHEMA = "cleanup_inventory_v1"
CLEANUP_INVENTORY_DESCRIPTOR_SCHEMA = "cleanup_inventory_descriptor_v1"
CLEANUP_INVENTORY_DIRECTORY = "cleanup-inventories"


def _fail(message: str, error: BaseException | None = None) -> InvalidTransitionError:
    result = InvalidTransitionError(message)
    if error is not None:
        result.__cause__ = error
    return result


def _inventory_statistics(
    entries_by_root: Mapping[str, Any],
    roots: Sequence[str],
) -> tuple[int, int]:
    entry_count = 0
    path_byte_count = 0
    for name in roots:
        entries = entries_by_root.get(name)
        if not isinstance(entries, list):
            raise _fail("cleanup inventory sidecar entries are invalid")
        entry_count += len(entries)
        for entry in entries:
            if not isinstance(entry, Mapping) or not isinstance(
                entry.get("relative_path"), str
            ):
                raise _fail("cleanup inventory sidecar entries are invalid")
            try:
                path_byte_count += len(os.fsencode(entry["relative_path"]))
            except (TypeError, UnicodeEncodeError) as error:
                raise _fail(
                    "cleanup inventory sidecar path encoding is invalid",
                    error,
                ) from error
    if entry_count > MAX_CLEANUP_INVENTORY_ENTRIES:
        raise _fail("cleanup inventory sidecar exceeds its entry bound")
    if path_byte_count > MAX_CLEANUP_INVENTORY_PATH_BYTES:
        raise _fail("cleanup inventory sidecar exceeds its path-byte bound")
    return entry_count, path_byte_count


def persist(
    run_dir: Path,
    roots: Sequence[str],
    inventory: Mapping[str, Any],
) -> dict[str, Any]:
    entries_by_root = inventory.get("root_entries")
    if not isinstance(entries_by_root, Mapping) or set(entries_by_root) != set(roots):
        raise _fail("cleanup inventory sidecar entries are invalid")
    entry_count, path_byte_count = _inventory_statistics(entries_by_root, roots)
    try:
        payload = canonical_json_bytes(
            {
                "root_entries": dict(entries_by_root),
                "roots": list(roots),
                "schema": CLEANUP_INVENTORY_SCHEMA,
            }
        )
    except (TypeError, ValueError) as error:
        raise _fail("cleanup inventory sidecar is not canonical JSON", error) from error
    if len(payload) > MAX_CLEANUP_INVENTORY_BYTES:
        raise _fail("cleanup inventory sidecar exceeds its byte bound")
    digest = hashlib.sha256(payload).hexdigest()
    name = f"cleanup-inventory-v1-{digest}.json"
    root = run_dir / CLEANUP_INVENTORY_DIRECTORY
    path = root / name
    try:
        safe_io.ensure_owner_only_directory(root)
        safe_io.atomic_create_bytes(path, payload, create_parents=False)
    except FileExistsError:
        try:
            existing = safe_io.read_bounded_bytes(
                path,
                max_bytes=len(payload),
                require_owner_only=True,
            )
        except (OSError, safe_io.UnsafePathError) as error:
            raise _fail(
                "cleanup inventory sidecar cannot be authenticated",
                error,
            ) from error
        if existing != payload:
            raise _fail("cleanup inventory sidecar conflicts with this run")
    except (OSError, safe_io.UnsafePathError) as error:
        raise _fail("cleanup inventory sidecar cannot be persisted", error) from error
    return {
        "byte_count": len(payload),
        "content_commitment": f"sha256:{digest}",
        "entry_count": entry_count,
        "path_byte_count": path_byte_count,
        "relative_path": f"{CLEANUP_INVENTORY_DIRECTORY}/{name}",
        "schema": CLEANUP_INVENTORY_DESCRIPTOR_SCHEMA,
    }


def load(
    run_dir: Path,
    roots: Sequence[str],
    descriptor: object,
) -> dict[str, list[dict[str, Any]]]:
    fields = {
        "byte_count",
        "content_commitment",
        "entry_count",
        "path_byte_count",
        "relative_path",
        "schema",
    }
    if not isinstance(descriptor, Mapping) or set(descriptor) != fields:
        raise _fail("cleanup inventory descriptor is invalid")
    byte_count = descriptor.get("byte_count")
    entry_count = descriptor.get("entry_count")
    path_byte_count = descriptor.get("path_byte_count")
    commitment = descriptor.get("content_commitment")
    relative_path = descriptor.get("relative_path")
    if (
        descriptor.get("schema") != CLEANUP_INVENTORY_DESCRIPTOR_SCHEMA
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count < 1
        or byte_count > MAX_CLEANUP_INVENTORY_BYTES
        or not isinstance(entry_count, int)
        or isinstance(entry_count, bool)
        or entry_count < 0
        or entry_count > MAX_CLEANUP_INVENTORY_ENTRIES
        or not isinstance(path_byte_count, int)
        or isinstance(path_byte_count, bool)
        or path_byte_count < 0
        or path_byte_count > MAX_CLEANUP_INVENTORY_PATH_BYTES
        or not isinstance(commitment, str)
        or not commitment.startswith("sha256:")
        or len(commitment) != 71
        or not isinstance(relative_path, str)
    ):
        raise _fail("cleanup inventory descriptor is invalid")
    digest = commitment.removeprefix("sha256:")
    if any(character not in "0123456789abcdef" for character in digest):
        raise _fail("cleanup inventory descriptor is invalid")
    expected_relative = (
        f"{CLEANUP_INVENTORY_DIRECTORY}/cleanup-inventory-v1-{digest}.json"
    )
    if relative_path != expected_relative:
        raise _fail("cleanup inventory descriptor path is invalid")
    try:
        payload = safe_io.read_bounded_bytes(
            run_dir / expected_relative,
            max_bytes=byte_count,
            require_owner_only=True,
        )
    except (OSError, safe_io.UnsafePathError) as error:
        raise _fail(
            "cleanup inventory sidecar cannot be authenticated",
            error,
        ) from error
    if len(payload) != byte_count or hashlib.sha256(payload).hexdigest() != digest:
        raise _fail("cleanup inventory sidecar changed")
    try:
        decoded = strict_json_loads(payload)
    except (TypeError, ValueError) as error:
        raise _fail("cleanup inventory sidecar is invalid", error) from error
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"root_entries", "roots", "schema"}
        or decoded.get("schema") != CLEANUP_INVENTORY_SCHEMA
        or decoded.get("roots") != list(roots)
        or not isinstance(decoded.get("root_entries"), dict)
        or set(decoded["root_entries"]) != set(roots)
        or canonical_json_bytes(decoded) != payload
    ):
        raise _fail("cleanup inventory sidecar is invalid")
    observed_entry_count, observed_path_bytes = _inventory_statistics(
        decoded["root_entries"],
        roots,
    )
    if observed_entry_count != entry_count or observed_path_bytes != path_byte_count:
        raise _fail("cleanup inventory descriptor counters are invalid")
    return {
        name: [dict(entry) for entry in decoded["root_entries"][name]] for name in roots
    }
