"""Durable retained-export destination binding for the v2 CLI."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
import os
import re
from typing import Any, NoReturn

from retrospective_v2 import contracts, export as export_api, safe_io


EXPORT_DESTINATION_CLAIM_SCHEMA = "cli_export_destination_claim_v2"
EXPORT_DESTINATION_CLAIM_NAME = "cli-export-destination-v2.json"
EXPORT_DESCRIPTOR_SCHEMA = "cli_export_descriptor_v2"
EXPORT_DESCRIPTOR_NAME = "cli-export-v2.json"
MAX_DESCRIPTOR_BYTES = 64 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

JsonReader = Callable[..., dict[str, Any]]


class ExportCliContractError(RuntimeError):
    def __init__(self, exit_code: str, code: str, message: str) -> None:
        super().__init__(code)
        self.exit_code = exit_code
        self.code = code
        self.safe_message = message


def _raise_cli_error(exit_code: str, code: str, message: str) -> NoReturn:
    raise ExportCliContractError(exit_code, code, message)


def _conflict() -> NoReturn:
    _raise_cli_error(
        "CONFLICT",
        "export_descriptor_conflict",
        "the immutable export destination conflicts with this request",
    )


def _invalid_descriptor(message: str) -> NoReturn:
    _raise_cli_error("INVALID_STATE", "invalid_export_descriptor", message)


def _same(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return contracts.canonical_json(left) == contracts.canonical_json(right)


def _destination_claim(output: Path, publication_role: str) -> dict[str, str]:
    return {
        "output": str(output),
        "publication_role": publication_role,
        "schema": EXPORT_DESTINATION_CLAIM_SCHEMA,
    }


def _load_destination_claim(
    run_dir: Path,
    *,
    read_json: JsonReader,
) -> dict[str, Any]:
    claim = read_json(
        run_dir / EXPORT_DESTINATION_CLAIM_NAME,
        max_bytes=MAX_DESCRIPTOR_BYTES,
    )
    if (
        set(claim) != {"output", "publication_role", "schema"}
        or claim.get("schema") != EXPORT_DESTINATION_CLAIM_SCHEMA
        or not isinstance(claim.get("output"), str)
        or claim.get("publication_role") != "standalone"
    ):
        _invalid_descriptor("the retained export destination claim is invalid")
    return claim


def load_export_descriptor(
    run_dir: Path,
    *,
    read_json: JsonReader,
) -> dict[str, Any]:
    descriptor = read_json(
        run_dir / EXPORT_DESCRIPTOR_NAME,
        max_bytes=MAX_DESCRIPTOR_BYTES,
    )
    bundle_digest = descriptor.get("bundle_digest")
    if (
        set(descriptor)
        != {
            "bundle_digest",
            "output",
            "publication_role",
            "retention_deadline",
            "schema",
        }
        or descriptor.get("schema") != EXPORT_DESCRIPTOR_SCHEMA
        or not isinstance(descriptor.get("output"), str)
        or not isinstance(bundle_digest, str)
        or SHA256_RE.fullmatch(bundle_digest) is None
        or descriptor.get("publication_role") != "standalone"
        or not isinstance(descriptor.get("retention_deadline"), str)
    ):
        _invalid_descriptor("the retained export descriptor is invalid")
    return descriptor


def _normalized_descriptor_claim(
    descriptor: Mapping[str, Any],
) -> dict[str, str]:
    output = export_api.normalize_retained_export_destination(descriptor["output"])
    return _destination_claim(output, str(descriptor["publication_role"]))


def require_export_destination_claim(
    run_dir: Path,
    output: Path,
    publication_role: str,
    *,
    read_json: JsonReader,
) -> None:
    output = export_api.normalize_retained_export_destination(output)
    expected = _destination_claim(output, publication_role)
    if not _same(_load_destination_claim(run_dir, read_json=read_json), expected):
        _conflict()


def claim_export_destination(
    run_dir: Path,
    output: Path,
    publication_role: str,
    *,
    read_json: JsonReader,
) -> Path:
    output = export_api.normalize_retained_export_destination(output)
    requested = _destination_claim(output, publication_role)
    descriptor_path = run_dir / EXPORT_DESCRIPTOR_NAME
    safe_io.recover_atomic_create(descriptor_path)
    claimed = requested
    if os.path.lexists(descriptor_path):
        claimed = _normalized_descriptor_claim(
            load_export_descriptor(run_dir, read_json=read_json)
        )
    try:
        safe_io.atomic_create_json(
            run_dir / EXPORT_DESTINATION_CLAIM_NAME,
            claimed,
        )
    except FileExistsError:
        claimed = _load_destination_claim(run_dir, read_json=read_json)
    if not _same(claimed, requested):
        _conflict()
    if os.path.lexists(descriptor_path) and not _same(
        _normalized_descriptor_claim(
            load_export_descriptor(run_dir, read_json=read_json)
        ),
        requested,
    ):
        _conflict()
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
        run_dir,
        output,
        publication_role,
        read_json=read_json,
    )
    bundle_digest = receipt.get("bundle_digest")
    retention_deadline = receipt.get("retention_deadline")
    if (
        not isinstance(bundle_digest, str)
        or SHA256_RE.fullmatch(bundle_digest) is None
        or not isinstance(retention_deadline, str)
    ):
        _raise_cli_error(
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
    try:
        safe_io.atomic_create_json(run_dir / EXPORT_DESCRIPTOR_NAME, descriptor)
    except FileExistsError:
        existing = load_export_descriptor(run_dir, read_json=read_json)
        existing["output"] = _normalized_descriptor_claim(existing)["output"]
        if not _same(existing, descriptor):
            _conflict()
