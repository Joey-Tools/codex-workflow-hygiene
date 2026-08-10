"""Closed retained-export reservation and result record schemas."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
import re
from typing import Any, NoReturn

from retrospective_v2 import contracts, export as export_api


EXPORT_DESTINATION_CLAIM_SCHEMA = "cli_export_destination_claim_v2"
EXPORT_DESTINATION_CLAIM_NAME = "cli-export-destination-v2.json"
EXPORT_DESCRIPTOR_SCHEMA = "cli_export_descriptor_v2"
EXPORT_DESCRIPTOR_NAME = "cli-export-result-v3.json"
EXPORT_RESERVATION_SCHEMA = "cli_export_reservation_v3"
LEGACY_EXPORT_DESCRIPTOR_NAME = "cli-export-v2.json"
MAX_DESCRIPTOR_BYTES = 64 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

JsonReader = Callable[..., dict[str, Any]]


class ExportCliContractError(RuntimeError):
    def __init__(self, exit_code: str, code: str, message: str) -> None:
        super().__init__(code)
        self.exit_code = exit_code
        self.code = code
        self.safe_message = message


def raise_cli_error(exit_code: str, code: str, message: str) -> NoReturn:
    raise ExportCliContractError(exit_code, code, message)


def conflict() -> NoReturn:
    raise_cli_error(
        "CONFLICT",
        "export_descriptor_conflict",
        "the immutable export destination conflicts with this request",
    )


def invalid_descriptor(message: str) -> NoReturn:
    raise_cli_error("INVALID_STATE", "invalid_export_descriptor", message)


def same(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return contracts.canonical_json(left) == contracts.canonical_json(right)


def destination_claim(output: Path, publication_role: str) -> dict[str, str]:
    return {
        "output": str(output),
        "publication_role": publication_role,
        "schema": EXPORT_DESTINATION_CLAIM_SCHEMA,
    }


def reservation(output: Path, publication_role: str) -> dict[str, str]:
    return {
        "output": str(output),
        "publication_role": publication_role,
        "schema": EXPORT_RESERVATION_SCHEMA,
    }


def load_destination_claim(
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
        invalid_descriptor("the retained export destination claim is invalid")
    claim["output"] = str(
        export_api.normalize_retained_export_destination(claim["output"])
    )
    return claim


def validated_descriptor(descriptor: dict[str, Any]) -> dict[str, Any]:
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
        invalid_descriptor("the retained export descriptor is invalid")
    descriptor["output"] = str(
        export_api.normalize_retained_export_destination(descriptor["output"])
    )
    return descriptor


def load_descriptor_at(
    path: Path,
    *,
    read_json: JsonReader,
) -> dict[str, Any]:
    return validated_descriptor(read_json(path, max_bytes=MAX_DESCRIPTOR_BYTES))


def normalized_descriptor_claim(
    descriptor: Mapping[str, Any],
) -> dict[str, str]:
    output = export_api.normalize_retained_export_destination(descriptor["output"])
    return destination_claim(output, str(descriptor["publication_role"]))


def load_legacy_binding(
    run_dir: Path,
    *,
    read_json: JsonReader,
) -> tuple[dict[str, str], dict[str, Any] | None]:
    record = read_json(
        run_dir / LEGACY_EXPORT_DESCRIPTOR_NAME,
        max_bytes=MAX_DESCRIPTOR_BYTES,
    )
    if record.get("schema") == EXPORT_DESCRIPTOR_SCHEMA:
        descriptor = validated_descriptor(record)
        return normalized_descriptor_claim(descriptor), descriptor
    if (
        set(record) != {"output", "publication_role", "schema"}
        or record.get("schema") != EXPORT_RESERVATION_SCHEMA
        or not isinstance(record.get("output"), str)
        or record.get("publication_role") != "standalone"
    ):
        invalid_descriptor("the retained export reservation is invalid")
    output = export_api.normalize_retained_export_destination(record["output"])
    return destination_claim(output, "standalone"), None
