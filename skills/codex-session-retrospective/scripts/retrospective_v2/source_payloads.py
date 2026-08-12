"""Closed validation and conflict-safe merging for source payload indexes."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .contracts import RefType, parse_typed_ref
from .orchestrator_core import InvalidTransitionError, _SAFE_REASON_RE


_COMMITMENT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RAW_PATH_RE = re.compile(r"raw-inputs/[0-9a-f]{64}\.bin\Z")


def _validated_payload_state(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidTransitionError("source payload state is invalid")
    status = value.get("status")
    if status == "gap":
        if set(value) != {"reason", "status"}:
            raise InvalidTransitionError("source payload gap is invalid")
        reason = value.get("reason")
        if not isinstance(reason, str) or not _SAFE_REASON_RE.fullmatch(reason):
            raise InvalidTransitionError("source payload gap is invalid")
        return {"reason": reason, "status": "gap"}
    if status != "available" or set(value) != {
        "byte_count",
        "content_commitment",
        "relative_path",
        "status",
    }:
        raise InvalidTransitionError("source payload state is invalid")
    byte_count = value.get("byte_count")
    commitment = value.get("content_commitment")
    relative_path = value.get("relative_path")
    if (
        not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count <= 0
        or not isinstance(commitment, str)
        or _COMMITMENT_RE.fullmatch(commitment) is None
        or not isinstance(relative_path, str)
        or _RAW_PATH_RE.fullmatch(relative_path) is None
    ):
        raise InvalidTransitionError("source payload state is invalid")
    return {
        "byte_count": byte_count,
        "content_commitment": commitment,
        "relative_path": relative_path,
        "status": "available",
    }


def merge_payload_index_into(merged: dict[str, dict[str, Any]], value: object) -> None:
    """Validate one index and merge it in place without allowing overrides."""

    if not isinstance(value, Mapping):
        raise InvalidTransitionError("source payload index is invalid")
    for unit_ref, payload_state in value.items():
        if not isinstance(unit_ref, str):
            raise InvalidTransitionError("source payload index is invalid")
        try:
            parse_typed_ref(unit_ref, expected=RefType.SOURCE_UNIT)
        except (TypeError, ValueError) as error:
            raise InvalidTransitionError(
                "source payload index contains an invalid source unit"
            ) from error
        normalized = _validated_payload_state(payload_state)
        existing = merged.get(unit_ref)
        if existing is not None and existing != normalized:
            raise InvalidTransitionError("source payload index changed")
        merged[unit_ref] = normalized


def merge_payload_indexes(*values: object) -> dict[str, dict[str, Any]]:
    """Validate and merge indexes without allowing later values to override."""

    merged: dict[str, dict[str, Any]] = {}
    for value in values:
        merge_payload_index_into(merged, value)
    return dict(sorted(merged.items()))
