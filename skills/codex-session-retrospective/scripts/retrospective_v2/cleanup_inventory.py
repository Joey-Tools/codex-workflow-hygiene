"""Authenticated cleanup inventories and descriptor-relative deletion."""

from __future__ import annotations

import copy
import os
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from . import safe_io
from .orchestrator_support import (
    InvalidTransitionError,
    LEGACY_SHADOW_CLEANUP_ROOTS,
    SHADOW_CLEANUP_ROOTS,
)


COUNTER_FIELDS = ("byte_count", "directory_count", "file_count")
ENTRY_FIELDS = {
    "access_policy",
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
INTEGER_ENTRY_FIELDS = (
    "device",
    "group",
    "inode",
    "link_count",
    "mode",
    "owner",
    "size",
)
EXACT_CLAIM_SCHEMAS = {"raw_cleanup_claim_v4", "shadow_cleanup_claim_v4"}


def _cleanup_contract(kind: str, version: int, roots: Sequence[str]):
    return (
        f"{kind}_cleanup_claim_v{version}:",
        f"{kind}-cleanup-claim-v{version}",
        roots,
        f"raw_cleanup_receipt_v{version}",
        f"raw_cleanup_auth_v{version}",
    )


RAW_CLEANUP_CONTRACTS = {
    "raw_cleanup_claim_v2": _cleanup_contract("raw", 2, LEGACY_SHADOW_CLEANUP_ROOTS),
    "raw_cleanup_claim_v3": _cleanup_contract("raw", 3, SHADOW_CLEANUP_ROOTS),
    "raw_cleanup_claim_v4": _cleanup_contract("raw", 4, SHADOW_CLEANUP_ROOTS),
}
SHADOW_CLEANUP_CONTRACTS = {
    "shadow_cleanup_claim_v2": _cleanup_contract(
        "shadow", 2, LEGACY_SHADOW_CLEANUP_ROOTS
    ),
    "shadow_cleanup_claim_v3": _cleanup_contract("shadow", 3, SHADOW_CLEANUP_ROOTS),
    "shadow_cleanup_claim_v4": _cleanup_contract("shadow", 4, SHADOW_CLEANUP_ROOTS),
}


def _require(condition: object, label: str) -> None:
    if not condition:
        raise InvalidTransitionError(f"{label} cleanup inventory is invalid")


def _is_nonnegative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_mode(value: object) -> bool:
    return _is_nonnegative_integer(value) and value <= 0o7777


def _valid_root_object(value: object) -> bool:
    if value is None:
        return True
    return all(
        (
            isinstance(value, Mapping),
            isinstance(value, Mapping) and set(value) == {"device", "inode"},
            isinstance(value, Mapping)
            and all(map(_is_nonnegative_integer, value.values())),
        )
    )


def _validate_entries(
    value: object,
    *,
    root_object: object,
    counts: Mapping[str, Any],
    label: str,
) -> None:
    _require(isinstance(value, list), label)
    assert isinstance(value, list)
    paths: list[str] = []
    directories = 0
    files = 0
    byte_count = 0
    for index, raw_entry in enumerate(value):
        _require(
            isinstance(raw_entry, Mapping) and set(raw_entry) == ENTRY_FIELDS,
            label,
        )
        assert isinstance(raw_entry, Mapping)
        entry = dict(raw_entry)
        relative_path = entry["relative_path"]
        object_type = entry["object_type"]
        _require(
            isinstance(relative_path, str) and "\x00" not in relative_path,
            label,
        )
        assert isinstance(relative_path, str)
        path = PurePosixPath(relative_path)
        if relative_path == ".":
            _require(index == 0, label)
        else:
            _require(
                all(
                    (
                        not path.is_absolute(),
                        str(path) == relative_path,
                        all(part not in {"", ".", ".."} for part in path.parts),
                    )
                ),
                label,
            )
        _require(object_type in {"directory", "file"}, label)
        _require(
            all(
                (
                    entry["access_policy"] == "owner-only-no-acl",
                    all(
                        map(
                            _is_nonnegative_integer,
                            (entry[name] for name in INTEGER_ENTRY_FIELDS),
                        )
                    ),
                    _is_mode(entry["mode"]),
                )
            ),
            label,
        )
        paths.append(relative_path)
        if object_type == "directory":
            directories += 1
        else:
            files += 1
            byte_count += entry["size"]
    _require(
        all((paths == sorted(paths, key=os.fsencode), len(paths) == len(set(paths)))),
        label,
    )
    _require(
        dict(counts)
        == {
            "byte_count": byte_count,
            "directory_count": directories,
            "file_count": files,
        },
        label,
    )
    if not value:
        _require(root_object is None, label)
        return
    root = value[0]
    _require(
        all(
            (
                root["relative_path"] == ".",
                root["object_type"] == "directory",
                isinstance(root_object, Mapping),
                isinstance(root_object, Mapping)
                and set(root_object) == {"device", "inode"},
                isinstance(root_object, Mapping)
                and root["device"] == root_object["device"],
                isinstance(root_object, Mapping)
                and root["inode"] == root_object["inode"],
            )
        ),
        label,
    )


def validate_claim_inventory(
    claim: Mapping[str, Any],
    *,
    label: str,
    roots: Sequence[str],
    require_exact_entries: bool = False,
) -> dict[str, Any]:
    counters = claim.get("root_counters")
    objects = claim.get("root_objects")
    entries_by_root = claim.get("root_entries")
    totals = dict.fromkeys(COUNTER_FIELDS, 0)
    _require(
        all(
            (
                claim.get("raw_path_inventory") == list(roots),
                isinstance(counters, Mapping),
                isinstance(counters, Mapping) and set(counters) == set(roots),
                isinstance(objects, Mapping),
                isinstance(objects, Mapping) and set(objects) == set(roots),
            )
        ),
        label,
    )
    if require_exact_entries:
        _require(
            isinstance(entries_by_root, Mapping) and set(entries_by_root) == set(roots),
            label,
        )
    else:
        _require(entries_by_root is None, label)
    assert isinstance(counters, Mapping) and isinstance(objects, Mapping)
    for name in roots:
        counts = counters[name]
        root_object = objects[name]
        _require(
            all(
                (
                    isinstance(counts, Mapping),
                    isinstance(counts, Mapping) and set(counts) == set(COUNTER_FIELDS),
                    isinstance(counts, Mapping)
                    and all(map(_is_nonnegative_integer, counts.values())),
                    _valid_root_object(root_object),
                )
            ),
            label,
        )
        assert isinstance(counts, Mapping)
        if require_exact_entries:
            assert isinstance(entries_by_root, Mapping)
            _validate_entries(
                entries_by_root[name],
                root_object=root_object,
                counts=counts,
                label=label,
            )
        for key in COUNTER_FIELDS:
            totals[key] += counts[key]
    if not all(claim.get(f"removed_{key}") == value for key, value in totals.items()):
        raise InvalidTransitionError(f"{label} cleanup totals are invalid")
    inventory = {
        "root_counters": copy.deepcopy(dict(counters)),
        "root_objects": copy.deepcopy(dict(objects)),
        **totals,
    }
    if require_exact_entries:
        assert isinstance(entries_by_root, Mapping)
        inventory["root_entries"] = copy.deepcopy(dict(entries_by_root))
    return inventory


def inspect_run_paths(
    run_dir: Path,
    roots: Sequence[str],
) -> dict[str, Any]:
    normalized, run_fd = safe_io.open_owner_only_directory(run_dir)
    root_counters: dict[str, dict[str, int]] = {}
    root_entries: dict[str, list[dict[str, Any]]] = {}
    root_objects: dict[str, dict[str, int] | None] = {}
    totals = dict.fromkeys(COUNTER_FIELDS, 0)
    try:
        for name in roots:
            snapshot = safe_io.inspect_tree_inventory_at(
                run_fd,
                name,
                display_path=normalized / name,
            )
            counts = snapshot["counters"]
            entries = snapshot["entries"]
            root_counters[name] = counts
            root_entries[name] = entries
            root_objects[name] = None
            if entries:
                root_objects[name] = {
                    "device": entries[0]["device"],
                    "inode": entries[0]["inode"],
                }
            for key in COUNTER_FIELDS:
                totals[key] += counts[key]
        return {
            "root_counters": root_counters,
            "root_entries": root_entries,
            "root_objects": root_objects,
            **totals,
        }
    finally:
        os.close(run_fd)


def _exact_prevalidation(
    run_fd: int,
    normalized: Path,
    claim: Mapping[str, Any],
) -> dict[str, dict[str, Any]] | None:
    prevalidated: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    claimed_present = {
        name
        for name in claim["raw_path_inventory"]
        if claim["root_objects"][name] is not None
    }
    for name in claim["raw_path_inventory"]:
        snapshot = safe_io.inspect_tree_inventory_at(
            run_fd,
            name,
            display_path=normalized / name,
        )
        planned_object = claim["root_objects"][name]
        if planned_object is None:
            if snapshot["entries"]:
                raise safe_io.UnsafePathError(
                    f"raw cleanup root appeared after claim: {normalized / name}"
                )
            continue
        if not snapshot["entries"]:
            missing.append(name)
            continue
        root = snapshot["entries"][0]
        if not all(
            (
                root["device"] == planned_object["device"],
                root["inode"] == planned_object["inode"],
                snapshot["counters"] == claim["root_counters"][name],
                snapshot["entries"] == claim["root_entries"][name],
            )
        ):
            raise safe_io.UnsafePathError(
                f"raw cleanup inventory changed after claim: {normalized / name}"
            )
        prevalidated[name] = snapshot
    if not missing:
        return prevalidated
    if set(missing) == claimed_present:
        os.fsync(run_fd)
        return None
    raise safe_io.UnsafePathError(
        "raw cleanup inventory became partially absent after claim"
    )


def delete_claimed_paths(run_dir: Path, claim: Mapping[str, Any]) -> None:
    normalized, run_fd = safe_io.open_owner_only_directory(run_dir)
    try:
        exact = claim.get("schema") in EXACT_CLAIM_SCHEMAS
        prevalidated = _exact_prevalidation(run_fd, normalized, claim) if exact else {}
        if prevalidated is None:
            return
        if exact:
            revalidated = _exact_prevalidation(run_fd, normalized, claim)
            if revalidated is None or revalidated != prevalidated:
                raise safe_io.UnsafePathError(
                    "raw cleanup inventory changed during complete revalidation"
                )
            prevalidated = revalidated
        for name in claim["raw_path_inventory"]:
            planned_object = claim["root_objects"][name]
            if planned_object is None:
                continue
            try:
                metadata = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
            except FileNotFoundError:
                if exact:
                    raise safe_io.UnsafePathError(
                        f"raw cleanup root disappeared before deletion: "
                        f"{normalized / name}"
                    )
                continue
            if (metadata.st_dev, metadata.st_ino) != (
                planned_object["device"],
                planned_object["inode"],
            ):
                raise safe_io.UnsafePathError(
                    f"raw cleanup root changed after claim: {normalized / name}"
                )
            if exact:
                current_snapshot = safe_io.inspect_tree_inventory_at(
                    run_fd,
                    name,
                    display_path=normalized / name,
                )
                if current_snapshot != prevalidated[name]:
                    raise safe_io.UnsafePathError(
                        "raw cleanup inventory changed during revalidation: "
                        f"{normalized / name}"
                    )
                current = current_snapshot["counters"]
            else:
                current = safe_io.inspect_tree_at(
                    run_fd,
                    name,
                    display_path=normalized / name,
                )
            planned = claim["root_counters"][name]
            if exact and current != planned:
                raise safe_io.UnsafePathError(
                    f"raw cleanup root changed after claim: {normalized / name}"
                )
            if not exact and any(current[key] > planned[key] for key in current):
                raise safe_io.UnsafePathError(
                    f"raw cleanup root grew after claim: {normalized / name}"
                )
            removed = safe_io.secure_remove_tree_at(
                run_fd,
                name,
                display_path=normalized / name,
            )
            if removed != current:
                raise safe_io.UnsafePathError(
                    f"raw cleanup count changed during deletion: {normalized / name}"
                )
        for name in claim["raw_path_inventory"]:
            try:
                os.stat(name, dir_fd=run_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise safe_io.UnsafePathError(
                f"raw working path survived cleanup: {normalized / name}"
            )
        os.fsync(run_fd)
    finally:
        os.close(run_fd)
