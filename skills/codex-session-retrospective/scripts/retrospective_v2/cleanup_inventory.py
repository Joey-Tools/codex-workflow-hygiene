"""Authenticated cleanup inventories and descriptor-relative deletion."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence

from . import cleanup_sidecars, safe_io
from .checkpoints import canonical_json_bytes
from .orchestrator_support import (
    InvalidTransitionError,
    LEGACY_SHADOW_CLEANUP_ROOTS,
    SHADOW_CLEANUP_ROOTS,
)


COUNTER_FIELDS = ("byte_count", "directory_count", "file_count")
ENTRY_FIELDS = {
    "access_policy",
    "content_commitment",
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
LEGACY_ENTRY_FIELDS = ENTRY_FIELDS - {"content_commitment"}
CONTENT_COMMITMENT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
INTEGER_ENTRY_FIELDS = (
    "device",
    "group",
    "inode",
    "link_count",
    "mode",
    "owner",
    "size",
)
INLINE_EXACT_CLAIM_SCHEMAS = {
    "raw_cleanup_claim_v4",
    "shadow_cleanup_claim_v4",
}
SIDECAR_EXACT_CLAIM_SCHEMAS = {
    "raw_cleanup_claim_v5",
    "shadow_cleanup_claim_v5",
}
EXACT_CLAIM_SCHEMAS = INLINE_EXACT_CLAIM_SCHEMAS | SIDECAR_EXACT_CLAIM_SCHEMAS
CLEANUP_QUARANTINE_DIRECTORY = "cleanup-quarantine-v1"
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


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
    "raw_cleanup_claim_v5": _cleanup_contract("raw", 5, SHADOW_CLEANUP_ROOTS),
}
SHADOW_CLEANUP_CONTRACTS = {
    "shadow_cleanup_claim_v2": _cleanup_contract(
        "shadow", 2, LEGACY_SHADOW_CLEANUP_ROOTS
    ),
    "shadow_cleanup_claim_v3": _cleanup_contract("shadow", 3, SHADOW_CLEANUP_ROOTS),
    "shadow_cleanup_claim_v4": _cleanup_contract("shadow", 4, SHADOW_CLEANUP_ROOTS),
    "shadow_cleanup_claim_v5": _cleanup_contract("shadow", 5, SHADOW_CLEANUP_ROOTS),
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
        content_commitment = entry["content_commitment"]
        _require(
            (
                object_type == "directory"
                and content_commitment is None
                or object_type == "file"
                and (
                    content_commitment is None
                    or isinstance(content_commitment, str)
                    and CONTENT_COMMITMENT_RE.fullmatch(content_commitment) is not None
                )
            ),
            label,
        )
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
    run_dir: Path,
    label: str,
    roots: Sequence[str],
) -> dict[str, Any]:
    schema = claim.get("schema")
    counters = claim.get("root_counters")
    objects = claim.get("root_objects")
    entries_by_root = claim.get("root_entries")
    descriptor = claim.get("inventory_descriptor")
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
    if schema in INLINE_EXACT_CLAIM_SCHEMAS:
        _require(
            isinstance(entries_by_root, Mapping) and set(entries_by_root) == set(roots),
            label,
        )
        _require(descriptor is None, label)
        assert isinstance(entries_by_root, Mapping)
        normalized_inline: dict[str, list[dict[str, Any]]] = {}
        for name in roots:
            raw_entries = entries_by_root[name]
            _require(isinstance(raw_entries, list), label)
            normalized_inline[name] = []
            for raw_entry in raw_entries:
                _require(
                    isinstance(raw_entry, Mapping)
                    and (
                        set(raw_entry) == ENTRY_FIELDS
                        or set(raw_entry) == LEGACY_ENTRY_FIELDS
                    ),
                    label,
                )
                entry = dict(raw_entry)
                entry.setdefault("content_commitment", None)
                normalized_inline[name].append(entry)
        entries_by_root = normalized_inline
    elif schema in SIDECAR_EXACT_CLAIM_SCHEMAS:
        _require(entries_by_root is None, label)
        entries_by_root = cleanup_sidecars.load(run_dir, roots, descriptor)
    else:
        _require(entries_by_root is None and descriptor is None, label)
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
        if schema in EXACT_CLAIM_SCHEMAS:
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
    if schema in EXACT_CLAIM_SCHEMAS:
        assert isinstance(entries_by_root, Mapping)
        inventory["root_entries"] = copy.deepcopy(dict(entries_by_root))
    if schema in SIDECAR_EXACT_CLAIM_SCHEMAS:
        inventory["inventory_descriptor"] = copy.deepcopy(descriptor)
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
    budget = _new_inventory_budget()
    try:
        for name in roots:
            snapshot = safe_io.inspect_tree_inventory_at(
                run_fd,
                name,
                budget=budget,
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


def _inventory_budget(*, deadline: float) -> safe_io.TreeInventoryBudget:
    return safe_io.TreeInventoryBudget(
        max_entries=cleanup_sidecars.MAX_CLEANUP_INVENTORY_ENTRIES,
        max_path_bytes=cleanup_sidecars.MAX_CLEANUP_INVENTORY_PATH_BYTES,
        max_depth=cleanup_sidecars.MAX_CLEANUP_INVENTORY_DEPTH,
        deadline=deadline,
    )


def _new_inventory_budget() -> safe_io.TreeInventoryBudget:
    return safe_io.TreeInventoryBudget.from_timeout(
        max_entries=cleanup_sidecars.MAX_CLEANUP_INVENTORY_ENTRIES,
        max_path_bytes=cleanup_sidecars.MAX_CLEANUP_INVENTORY_PATH_BYTES,
        max_depth=cleanup_sidecars.MAX_CLEANUP_INVENTORY_DEPTH,
        timeout_seconds=cleanup_sidecars.MAX_CLEANUP_INVENTORY_SECONDS,
    )


def _contract_roots(claim: Mapping[str, Any]) -> Sequence[str]:
    schema = str(claim.get("schema"))
    contract = RAW_CLEANUP_CONTRACTS.get(schema)
    if contract is None:
        contract = SHADOW_CLEANUP_CONTRACTS.get(schema)
    if contract is None or claim.get("raw_path_inventory") != list(contract[2]):
        raise safe_io.UnsafePathError("raw cleanup claim has unsupported roots")
    return contract[2]


def _open_owner_only_child_directory(
    parent_fd: int,
    name: str,
    *,
    display_path: Path,
) -> int:
    created = False
    try:
        os.mkdir(name, safe_io.OWNER_DIRECTORY_MODE, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise safe_io.UnsafePathError(
            f"cannot anchor cleanup quarantine: {display_path}"
        ) from error
    try:
        if created:
            anchored = safe_io.harden_created_owner_only_directory_descriptor(
                descriptor,
                display_path,
            )
            os.fsync(parent_fd)
        else:
            anchored = safe_io.validate_owner_only_directory_descriptor(
                descriptor,
                display_path,
            )
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (anchored.st_dev, anchored.st_ino) != (current.st_dev, current.st_ino):
            raise safe_io.UnsafePathError(
                f"cleanup quarantine changed while opened: {display_path}"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_claim_quarantine(
    run_fd: int,
    normalized: Path,
    claim: Mapping[str, Any],
) -> tuple[Path, int]:
    root_path = normalized / CLEANUP_QUARANTINE_DIRECTORY
    root_fd = _open_owner_only_child_directory(
        run_fd,
        CLEANUP_QUARANTINE_DIRECTORY,
        display_path=root_path,
    )
    token = hashlib.sha256(os.fsencode(str(claim["claim_ref"]))).hexdigest()
    claim_path = root_path / token
    try:
        claim_fd = _open_owner_only_child_directory(
            root_fd,
            token,
            display_path=claim_path,
        )
    finally:
        os.close(root_fd)
    return claim_path, claim_fd


def _quarantine_names(name: str) -> tuple[str, str]:
    token = hashlib.sha256(os.fsencode(name)).hexdigest()
    return f"root-{token}", f"started-{token}.json"


def _marker_bytes(claim: Mapping[str, Any], name: str) -> bytes:
    return canonical_json_bytes(
        {
            "claim_ref": claim["claim_ref"],
            "root": name,
            "root_object": claim["root_objects"][name],
            "schema": "cleanup_quarantine_progress_v1",
            "state": "started",
        }
    )


def _read_marker(
    quarantine_fd: int,
    quarantine_path: Path,
    marker_name: str,
    expected: bytes,
) -> bool:
    try:
        observed = safe_io.read_bounded_bytes_at(
            quarantine_fd,
            marker_name,
            display_path=quarantine_path / marker_name,
            max_bytes=len(expected),
            require_owner_only=True,
        )
    except FileNotFoundError:
        return False
    if observed != expected:
        raise safe_io.UnsafePathError(
            f"cleanup progress marker changed: {quarantine_path / marker_name}"
        )
    return True


def _create_marker(
    quarantine_fd: int,
    quarantine_path: Path,
    marker_name: str,
    payload: bytes,
) -> None:
    marker_path = quarantine_path / marker_name
    try:
        descriptor = os.open(
            marker_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            safe_io.OWNER_FILE_MODE,
            dir_fd=quarantine_fd,
        )
    except FileExistsError:
        if not _read_marker(quarantine_fd, quarantine_path, marker_name, payload):
            raise safe_io.UnsafePathError(
                f"cleanup progress marker disappeared: {marker_path}"
            )
        return
    succeeded = False
    try:
        safe_io.harden_created_owner_only_file_descriptor(descriptor, marker_path)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short write while persisting cleanup progress")
            written += count
        os.fsync(descriptor)
        succeeded = True
    finally:
        os.close(descriptor)
        if not succeeded:
            try:
                os.unlink(marker_name, dir_fd=quarantine_fd)
            except FileNotFoundError:
                pass
    os.fsync(quarantine_fd)
    if not _read_marker(quarantine_fd, quarantine_path, marker_name, payload):
        raise safe_io.UnsafePathError(
            f"cleanup progress marker was not persisted: {marker_path}"
        )


def _entry_matches(
    entry: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    relaxed_directory_metadata: bool,
) -> bool:
    if entry["object_type"] != expected["object_type"]:
        return False
    if entry["object_type"] == "file":
        stable_fields = ENTRY_FIELDS - {"content_commitment"}
        if any(entry[field] != expected[field] for field in stable_fields):
            return False
        expected_commitment = expected["content_commitment"]
        return (
            expected_commitment is None
            or entry["content_commitment"] == expected_commitment
        )
    stable_fields = (
        ENTRY_FIELDS - {"link_count", "size"}
        if relaxed_directory_metadata
        else ENTRY_FIELDS
    )
    return all(entry[field] == expected[field] for field in stable_fields)


def _remaining_entries_match(
    observed: Sequence[Mapping[str, Any]],
    planned: Sequence[Mapping[str, Any]],
) -> bool:
    planned_by_path = {entry["relative_path"]: entry for entry in planned}
    if not observed or observed[0]["relative_path"] != ".":
        return False
    return all(
        (expected := planned_by_path.get(entry["relative_path"])) is not None
        and _entry_matches(
            entry,
            expected,
            relaxed_directory_metadata=True,
        )
        for entry in observed
    )


def _complete_entries_match(
    observed: Sequence[Mapping[str, Any]],
    planned: Sequence[Mapping[str, Any]],
) -> bool:
    if len(observed) != len(planned):
        return False
    for entry, expected in zip(observed, planned, strict=True):
        if not _entry_matches(
            entry,
            expected,
            relaxed_directory_metadata=False,
        ):
            return False
    return True


def _exact_progress_snapshot(
    run_fd: int,
    quarantine_fd: int,
    normalized: Path,
    quarantine_path: Path,
    claim: Mapping[str, Any],
    *,
    allow_legacy_all_absent: bool,
    budget: safe_io.TreeInventoryBudget,
) -> dict[str, dict[str, Any]]:
    roots = claim["raw_path_inventory"]
    expected_names = {item for name in roots for item in _quarantine_names(name)}
    observed_names: set[str] = set()
    with os.scandir(quarantine_fd) as entries:
        for entry in entries:
            budget.checkpoint()
            if len(observed_names) >= len(expected_names):
                raise safe_io.UnsafePathError(
                    f"cleanup quarantine has unexpected entries: {quarantine_path}"
                )
            observed_names.add(entry.name)
    if not observed_names <= expected_names:
        raise safe_io.UnsafePathError(
            f"cleanup quarantine has unexpected entries: {quarantine_path}"
        )
    states: dict[str, dict[str, Any]] = {}
    unproved_missing: list[str] = []
    claimed_present = {
        name for name in roots if claim["root_objects"][name] is not None
    }
    for name in roots:
        quarantine_name, marker_name = _quarantine_names(name)
        original = safe_io.inspect_tree_inventory_at(
            run_fd,
            name,
            budget=budget,
            display_path=normalized / name,
        )
        quarantined = safe_io.inspect_tree_inventory_at(
            quarantine_fd,
            quarantine_name,
            budget=budget,
            display_path=quarantine_path / quarantine_name,
        )
        marker = _read_marker(
            quarantine_fd,
            quarantine_path,
            marker_name,
            _marker_bytes(claim, name),
        )
        planned_object = claim["root_objects"][name]
        if planned_object is None:
            if original["entries"] or quarantined["entries"] or marker:
                raise safe_io.UnsafePathError(
                    f"raw cleanup root appeared after claim: {normalized / name}"
                )
            states[name] = {"phase": "absent"}
            continue
        if original["entries"] and quarantined["entries"]:
            raise safe_io.UnsafePathError(
                f"raw cleanup root exists both live and quarantined: {normalized / name}"
            )
        if original["entries"]:
            root = original["entries"][0]
            if marker or not all(
                (
                    root["device"] == planned_object["device"],
                    root["inode"] == planned_object["inode"],
                    original["counters"] == claim["root_counters"][name],
                    _complete_entries_match(
                        original["entries"], claim["root_entries"][name]
                    ),
                )
            ):
                raise safe_io.UnsafePathError(
                    f"raw cleanup inventory changed after claim: {normalized / name}"
                )
            states[name] = {"inventory": original, "phase": "original"}
            continue
        if quarantined["entries"]:
            root = quarantined["entries"][0]
            if not all(
                (
                    root["device"] == planned_object["device"],
                    root["inode"] == planned_object["inode"],
                    _remaining_entries_match(
                        quarantined["entries"],
                        claim["root_entries"][name],
                    ),
                    any(
                        (
                            marker,
                            len(quarantined["entries"])
                            == len(claim["root_entries"][name]),
                        )
                    ),
                )
            ):
                raise safe_io.UnsafePathError(
                    f"quarantined cleanup inventory changed: {normalized / name}"
                )
            states[name] = {
                "inventory": quarantined,
                "marker": marker,
                "phase": "quarantined",
            }
            continue
        if marker:
            states[name] = {"phase": "complete"}
            continue
        unproved_missing.append(name)
    if unproved_missing:
        if allow_legacy_all_absent and set(unproved_missing) == claimed_present:
            for name in unproved_missing:
                states[name] = {"phase": "legacy-complete"}
        else:
            raise safe_io.UnsafePathError(
                "raw cleanup inventory became absent without durable progress"
            )
    return states


def _delete_exact_claimed_paths(
    run_fd: int,
    normalized: Path,
    claim: Mapping[str, Any],
) -> None:
    quarantine_path, quarantine_fd = _open_claim_quarantine(
        run_fd,
        normalized,
        claim,
    )
    try:
        allow_legacy_all_absent = claim["schema"] in INLINE_EXACT_CLAIM_SCHEMAS
        initial_budget = _new_inventory_budget()
        deadline = initial_budget.deadline
        states = _exact_progress_snapshot(
            run_fd,
            quarantine_fd,
            normalized,
            quarantine_path,
            claim,
            allow_legacy_all_absent=allow_legacy_all_absent,
            budget=initial_budget,
        )
        revalidated = _exact_progress_snapshot(
            run_fd,
            quarantine_fd,
            normalized,
            quarantine_path,
            claim,
            allow_legacy_all_absent=allow_legacy_all_absent,
            budget=_inventory_budget(deadline=deadline),
        )
        if revalidated != states:
            raise safe_io.UnsafePathError(
                "raw cleanup inventory changed during complete revalidation"
            )
        states = revalidated
        for name in claim["raw_path_inventory"]:
            phase = states[name]["phase"]
            if phase in {"absent", "complete", "legacy-complete"}:
                continue
            quarantine_name, marker_name = _quarantine_names(name)
            if phase == "original":
                os.rename(
                    name,
                    quarantine_name,
                    src_dir_fd=run_fd,
                    dst_dir_fd=quarantine_fd,
                )
                os.fsync(run_fd)
                os.fsync(quarantine_fd)
                quarantined = safe_io.inspect_tree_inventory_at(
                    quarantine_fd,
                    quarantine_name,
                    budget=_inventory_budget(deadline=deadline),
                    display_path=quarantine_path / quarantine_name,
                )
                if quarantined != states[name]["inventory"]:
                    raise safe_io.UnsafePathError(
                        f"raw cleanup root changed during quarantine: {normalized / name}"
                    )
                expected_entries = quarantined["entries"]
            else:
                expected_entries = states[name]["inventory"]["entries"]
            _create_marker(
                quarantine_fd,
                quarantine_path,
                marker_name,
                _marker_bytes(claim, name),
            )
            safe_io.secure_remove_tree_at(
                quarantine_fd,
                quarantine_name,
                display_path=quarantine_path / quarantine_name,
                expected_inventory=expected_entries,
                budget=_inventory_budget(deadline=deadline),
            )
            states[name] = {"phase": "complete"}
        final = _exact_progress_snapshot(
            run_fd,
            quarantine_fd,
            normalized,
            quarantine_path,
            claim,
            allow_legacy_all_absent=allow_legacy_all_absent,
            budget=_inventory_budget(deadline=deadline),
        )
        if any(
            value["phase"] not in {"absent", "complete", "legacy-complete"}
            for value in final.values()
        ):
            raise safe_io.UnsafePathError("raw working paths survived cleanup")
        os.fsync(quarantine_fd)
        os.fsync(run_fd)
    finally:
        os.close(quarantine_fd)


def _delete_legacy_claimed_paths(
    run_fd: int,
    normalized: Path,
    claim: Mapping[str, Any],
) -> None:
    budget = _new_inventory_budget()
    for name in claim["raw_path_inventory"]:
        planned_object = claim["root_objects"][name]
        if planned_object is None:
            continue
        try:
            metadata = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (metadata.st_dev, metadata.st_ino) != (
            planned_object["device"],
            planned_object["inode"],
        ):
            raise safe_io.UnsafePathError(
                f"raw cleanup root changed after claim: {normalized / name}"
            )
        current = safe_io.inspect_tree_at(
            run_fd,
            name,
            budget=budget,
            display_path=normalized / name,
        )
        planned = claim["root_counters"][name]
        if any(current[key] > planned[key] for key in current):
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


def delete_claimed_paths(run_dir: Path, claim: Mapping[str, Any]) -> None:
    roots = _contract_roots(claim)
    inventory = validate_claim_inventory(
        claim,
        run_dir=run_dir,
        label="raw",
        roots=roots,
    )
    effective_claim = copy.deepcopy(dict(claim))
    if claim.get("schema") in EXACT_CLAIM_SCHEMAS:
        effective_claim["root_entries"] = inventory["root_entries"]
    normalized, run_fd = safe_io.open_owner_only_directory(run_dir)
    try:
        if claim.get("schema") in EXACT_CLAIM_SCHEMAS:
            _delete_exact_claimed_paths(run_fd, normalized, effective_claim)
        else:
            _delete_legacy_claimed_paths(run_fd, normalized, effective_claim)
        for name in roots:
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
