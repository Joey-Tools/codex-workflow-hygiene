"""Owner-only retained-export input sidecars."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping

from . import safe_io
from .checkpoints import canonical_json_bytes
from .contracts import strict_json_loads
from .orchestrator_core import RETAINED_EXPORT_INPUT_DIRECTORY
from .orchestrator_support import InvalidTransitionError, RunConflictError, _json_copy


RETAINED_EXPORT_INPUT_SCHEMA = "retained_export_input_v2"
RETAINED_EXPORT_DESCRIPTOR_SCHEMA = "retained_export_input_descriptor_v2"
MAX_RETAINED_EXPORT_INPUT_BYTES = 256 * 1024 * 1024


def clear_legacy_terminal_payload(
    store: Any,
    snapshot: Any,
    *,
    phase: str,
    validate_terminal: Callable[[Mapping[str, Any]], object],
) -> Any:
    validate_terminal(snapshot.state)
    if snapshot.state.get("retained_export") is None:
        return snapshot

    def clear(current: dict[str, Any]) -> tuple[dict[str, Any], None]:
        if current["publication"].get("phase") != phase:
            raise RunConflictError("terminal cleanup phase changed")
        validate_terminal(current)
        current["retained_export"] = None
        return current, None

    return store.transaction(clear).snapshot


def _validated_inputs(
    current: Mapping[str, Any],
    run_state: object,
    review_data: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(run_state, Mapping) or not isinstance(review_data, Mapping):
        raise InvalidTransitionError("retained export inputs are invalid")
    normalized_run_state = _json_copy(run_state, label="run_state")
    normalized_review_data = _json_copy(review_data, label="review_data")
    if (
        normalized_run_state.get("run_ref") != current.get("run_ref")
        or normalized_run_state.get("mode") != current.get("mode")
        or normalized_run_state.get("window") != current.get("window")
    ):
        raise InvalidTransitionError("retained export inputs differ from the run")
    return normalized_run_state, normalized_review_data


def persist(
    run_dir: Path,
    run_state: Mapping[str, Any],
    review_data: Mapping[str, Any],
) -> dict[str, Any]:
    payload = canonical_json_bytes(
        {
            "review_data": _json_copy(review_data, label="review_data"),
            "run_state": _json_copy(run_state, label="run_state"),
            "schema": RETAINED_EXPORT_INPUT_SCHEMA,
        }
    )
    if len(payload) > MAX_RETAINED_EXPORT_INPUT_BYTES:
        raise InvalidTransitionError("retained export inputs exceed their byte bound")
    digest = hashlib.sha256(payload).hexdigest()
    name = f"retained-export-input-v2-{digest}.json"
    root = run_dir / RETAINED_EXPORT_INPUT_DIRECTORY
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
            raise InvalidTransitionError(
                "retained export input sidecar cannot be authenticated"
            ) from error
        if existing != payload:
            raise InvalidTransitionError(
                "retained export input sidecar conflicts with this run"
            )
    except (OSError, safe_io.UnsafePathError) as error:
        raise InvalidTransitionError(
            "retained export input sidecar cannot be persisted"
        ) from error
    return {
        "byte_count": len(payload),
        "content_commitment": f"sha256:{digest}",
        "relative_path": f"{RETAINED_EXPORT_INPUT_DIRECTORY}/{name}",
        "schema": RETAINED_EXPORT_DESCRIPTOR_SCHEMA,
    }


def load(
    run_dir: Path,
    current: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    descriptor = current.get("retained_export")
    if isinstance(descriptor, Mapping) and set(descriptor) == {
        "review_data",
        "run_state",
    }:
        try:
            payload = canonical_json_bytes(descriptor)
        except (TypeError, ValueError) as error:
            raise InvalidTransitionError(
                "legacy retained export inputs are invalid"
            ) from error
        if len(payload) > MAX_RETAINED_EXPORT_INPUT_BYTES:
            raise InvalidTransitionError(
                "legacy retained export inputs exceed their byte bound"
            )
        return _validated_inputs(
            current,
            descriptor["run_state"],
            descriptor["review_data"],
        )
    expected_fields = {
        "byte_count",
        "content_commitment",
        "relative_path",
        "schema",
    }
    if not isinstance(descriptor, Mapping) or set(descriptor) != expected_fields:
        raise InvalidTransitionError("retained export descriptor is invalid")
    byte_count = descriptor.get("byte_count")
    commitment = descriptor.get("content_commitment")
    relative_path = descriptor.get("relative_path")
    if (
        descriptor.get("schema") != RETAINED_EXPORT_DESCRIPTOR_SCHEMA
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count < 1
        or byte_count > MAX_RETAINED_EXPORT_INPUT_BYTES
        or not isinstance(commitment, str)
        or not commitment.startswith("sha256:")
        or len(commitment) != 71
        or not isinstance(relative_path, str)
    ):
        raise InvalidTransitionError("retained export descriptor is invalid")
    digest = commitment.removeprefix("sha256:")
    if any(character not in "0123456789abcdef" for character in digest):
        raise InvalidTransitionError("retained export descriptor is invalid")
    expected_relative = (
        f"{RETAINED_EXPORT_INPUT_DIRECTORY}/retained-export-input-v2-{digest}.json"
    )
    if relative_path != expected_relative:
        raise InvalidTransitionError("retained export descriptor path is invalid")
    try:
        payload = safe_io.read_bounded_bytes(
            run_dir / expected_relative,
            max_bytes=byte_count,
            require_owner_only=True,
        )
    except (OSError, safe_io.UnsafePathError) as error:
        raise InvalidTransitionError(
            "retained export input sidecar cannot be authenticated"
        ) from error
    if len(payload) != byte_count or hashlib.sha256(payload).hexdigest() != digest:
        raise InvalidTransitionError("retained export input sidecar changed")
    try:
        decoded = strict_json_loads(payload)
    except (TypeError, ValueError) as error:
        raise InvalidTransitionError(
            "retained export input sidecar is invalid"
        ) from error
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"review_data", "run_state", "schema"}
        or decoded.get("schema") != RETAINED_EXPORT_INPUT_SCHEMA
        or not isinstance(decoded.get("run_state"), dict)
        or not isinstance(decoded.get("review_data"), dict)
        or canonical_json_bytes(decoded) != payload
    ):
        raise InvalidTransitionError("retained export input sidecar is invalid")
    try:
        return _validated_inputs(
            current,
            decoded["run_state"],
            decoded["review_data"],
        )
    except InvalidTransitionError as error:
        raise InvalidTransitionError(
            "retained export input sidecar differs from the run"
        ) from error
