"""Durable retained-export destination binding for the v2 CLI."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import os
from typing import Any
import unicodedata

from retrospective_v2 import export as export_api, safe_io
from retrospective_v2.orchestrator_core import SHADOW_CLEANUP_ROOTS
import session_retrospective_v2_export_records as records


EXPORT_DESTINATION_CLAIM_SCHEMA = records.EXPORT_DESTINATION_CLAIM_SCHEMA
EXPORT_DESTINATION_CLAIM_NAME = records.EXPORT_DESTINATION_CLAIM_NAME
EXPORT_DESCRIPTOR_SCHEMA = records.EXPORT_DESCRIPTOR_SCHEMA
EXPORT_DESCRIPTOR_NAME = records.EXPORT_DESCRIPTOR_NAME
EXPORT_RESERVATION_SCHEMA = records.EXPORT_RESERVATION_SCHEMA
LEGACY_EXPORT_DESCRIPTOR_NAME = records.LEGACY_EXPORT_DESCRIPTOR_NAME
ExportCliContractError = records.ExportCliContractError
JsonReader = records.JsonReader


def _folded_path_component(component: str) -> str:
    decomposed = unicodedata.normalize("NFD", component)
    return unicodedata.normalize("NFD", decomposed.casefold())


def _folded_path_parts(path: Path) -> tuple[str, ...]:
    return tuple(_folded_path_component(part) for part in path.parts)


def _reject_cleanup_destination(run_dir: Path, output: Path) -> None:
    canonical_run = Path(os.path.realpath(run_dir))
    output_parts = _folded_path_parts(output)
    for relative_root in SHADOW_CLEANUP_ROOTS:
        cleanup_root = Path(os.path.realpath(canonical_run / relative_root))
        cleanup_parts = _folded_path_parts(cleanup_root)
        if output_parts[: len(cleanup_parts)] != cleanup_parts:
            continue
        records.raise_cli_error(
            "INVALID_INPUT",
            "export_location_invalid",
            "the retained export destination is inside a run cleanup root",
        )


def load_export_descriptor(
    run_dir: Path,
    *,
    read_json: JsonReader,
) -> dict[str, Any]:
    result_path = run_dir / EXPORT_DESCRIPTOR_NAME
    legacy_path = run_dir / LEGACY_EXPORT_DESCRIPTOR_NAME
    claim_path = run_dir / EXPORT_DESTINATION_CLAIM_NAME
    for path in (legacy_path, claim_path, result_path):
        safe_io.recover_atomic_create(path)
    if not os.path.lexists(legacy_path):
        records.invalid_descriptor("the retained export reservation is missing")
    legacy_claim, legacy_descriptor = records.load_legacy_binding(
        run_dir, read_json=read_json
    )
    claim = (
        records.load_destination_claim(run_dir, read_json=read_json)
        if os.path.lexists(claim_path)
        else legacy_claim
    )
    if legacy_descriptor is not None and not records.same(claim, legacy_claim):
        records.invalid_descriptor("the retained export destination binding conflicts")
    if os.path.lexists(result_path):
        result = records.load_descriptor_at(result_path, read_json=read_json)
        if not records.same(records.normalized_descriptor_claim(result), claim):
            records.invalid_descriptor("the retained export result binding conflicts")
        if legacy_descriptor is not None and not records.same(
            result, legacy_descriptor
        ):
            records.invalid_descriptor("the retained export results conflict")
        return result
    if legacy_descriptor is not None:
        return legacy_descriptor
    records.invalid_descriptor("the retained export result is not complete")


def require_export_destination_claim(
    run_dir: Path,
    output: Path,
    publication_role: str,
    *,
    read_json: JsonReader,
) -> None:
    output = export_api.normalize_retained_export_destination(output)
    expected = records.destination_claim(output, publication_role)
    legacy_claim, _legacy_descriptor = records.load_legacy_binding(
        run_dir, read_json=read_json
    )
    claim = records.load_destination_claim(run_dir, read_json=read_json)
    if not records.same(claim, expected) or (
        _legacy_descriptor is not None and not records.same(legacy_claim, expected)
    ):
        records.conflict()


def claim_export_destination(
    run_dir: Path,
    output: Path,
    publication_role: str,
    *,
    read_json: JsonReader,
) -> Path:
    output = export_api.normalize_retained_export_destination(output)
    _reject_cleanup_destination(run_dir, output)
    requested = records.destination_claim(output, publication_role)
    legacy_path = run_dir / LEGACY_EXPORT_DESCRIPTOR_NAME
    claim_path = run_dir / EXPORT_DESTINATION_CLAIM_NAME
    result_path = run_dir / EXPORT_DESCRIPTOR_NAME
    for path in (legacy_path, claim_path, result_path):
        safe_io.recover_atomic_create(path)
    claimed = (
        records.load_destination_claim(run_dir, read_json=read_json)
        if os.path.lexists(claim_path)
        else requested
    )
    if not os.path.lexists(legacy_path):
        try:
            safe_io.atomic_create_json(
                legacy_path,
                records.reservation(
                    export_api.normalize_retained_export_destination(claimed["output"]),
                    claimed["publication_role"],
                ),
            )
        except FileExistsError:
            pass
    legacy_claim, _legacy_descriptor = records.load_legacy_binding(
        run_dir, read_json=read_json
    )
    if os.path.lexists(claim_path):
        claimed = records.load_destination_claim(run_dir, read_json=read_json)
    else:
        try:
            safe_io.atomic_create_json(claim_path, legacy_claim)
        except FileExistsError:
            claimed = records.load_destination_claim(run_dir, read_json=read_json)
        else:
            claimed = legacy_claim
    if _legacy_descriptor is not None and not records.same(claimed, legacy_claim):
        records.conflict()
    if not records.same(claimed, requested):
        records.conflict()
    if os.path.lexists(result_path) and not records.same(
        records.normalized_descriptor_claim(
            load_export_descriptor(run_dir, read_json=read_json)
        ),
        requested,
    ):
        records.conflict()
    return output


def persist_export_descriptor(
    run_dir: Path,
    output: Path,
    receipt: Mapping[str, Any],
    publication_role: str,
    *,
    read_json: JsonReader,
) -> None:
    output = export_api.normalize_retained_export_destination(output)
    require_export_destination_claim(
        run_dir, output, publication_role, read_json=read_json
    )
    bundle_digest = receipt.get("bundle_digest")
    retention_deadline = receipt.get("retention_deadline")
    if (
        not isinstance(bundle_digest, str)
        or records.SHA256_RE.fullmatch(bundle_digest) is None
        or not isinstance(retention_deadline, str)
    ):
        records.raise_cli_error(
            "INVALID_STATE",
            "invalid_export_receipt",
            "the retained export receipt is invalid",
        )
    descriptor = {
        "bundle_digest": bundle_digest,
        "output": str(output),
        "publication_role": publication_role,
        "retention_deadline": retention_deadline,
        "schema": EXPORT_DESCRIPTOR_SCHEMA,
    }
    _legacy_claim, legacy_descriptor = records.load_legacy_binding(
        run_dir, read_json=read_json
    )
    if legacy_descriptor is not None and not records.same(
        legacy_descriptor, descriptor
    ):
        records.conflict()
    try:
        safe_io.atomic_create_json(run_dir / EXPORT_DESCRIPTOR_NAME, descriptor)
    except FileExistsError:
        existing = records.load_descriptor_at(
            run_dir / EXPORT_DESCRIPTOR_NAME, read_json=read_json
        )
        if not records.same(existing, descriptor):
            records.conflict()
