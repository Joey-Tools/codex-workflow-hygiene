"""Authenticated transient sidecars for reassembled extractor turns."""

from __future__ import annotations

import copy
import hashlib
import hmac
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence

from . import safe_io, source_inputs
from .checkpoints import canonical_json_bytes
from .contracts import RefType, strict_json_loads
from .orchestrator_support import InvalidTransitionError


EXTRACTED_TURNS_ARTIFACT_SCHEMA = "extracted_turns_artifact_v2"
EXTRACTED_TURNS_DESCRIPTOR_SCHEMA = "extracted_turns_descriptor_v2"
EXTRACTED_TURNS_DIRECTORY = "agent-sinks/derived"
MAX_EXTRACTED_TURNS_ARTIFACT_BYTES = 96 * 1024 * 1024
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_TURN_REF_RE = re.compile(rf"{re.escape(RefType.TURN.value)}:[0-9a-f]{{64}}\Z")
_DESCRIPTOR_FIELDS = frozenset(
    {"byte_count", "content_commitment", "relative_path", "schema", "turn_count"}
)


def _validated_turns(value: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    turns: dict[str, dict[str, Any]] = {}
    for turn_ref, raw_turn in value.items():
        if (
            not isinstance(turn_ref, str)
            or _TURN_REF_RE.fullmatch(turn_ref) is None
            or not isinstance(raw_turn, Mapping)
            or raw_turn.get("turn_ref") != turn_ref
        ):
            raise InvalidTransitionError("extracted turn material is invalid")
        turns[turn_ref] = copy.deepcopy(dict(raw_turn))
    return turns


def prepare(
    run_dir: Path,
    turns: Mapping[str, Any],
) -> tuple[dict[str, Any], source_inputs.PreparedFile]:
    normalized = _validated_turns(turns)
    payload = canonical_json_bytes(
        {
            "schema": EXTRACTED_TURNS_ARTIFACT_SCHEMA,
            "turns": normalized,
        }
    )
    if len(payload) > MAX_EXTRACTED_TURNS_ARTIFACT_BYTES:
        raise InvalidTransitionError("extracted turn sidecar exceeds its byte bound")
    digest = hashlib.sha256(payload).hexdigest()
    relative_path = f"{EXTRACTED_TURNS_DIRECTORY}/extracted-turns-v2-{digest}.json"
    return (
        {
            "byte_count": len(payload),
            "content_commitment": f"sha256:{digest}",
            "relative_path": relative_path,
            "schema": EXTRACTED_TURNS_DESCRIPTOR_SCHEMA,
            "turn_count": len(normalized),
        },
        source_inputs.prepare_file(run_dir / relative_path, payload),
    )


def _validated_descriptor(value: Mapping[str, Any]) -> tuple[int, str, str, int]:
    if set(value) != _DESCRIPTOR_FIELDS:
        raise InvalidTransitionError("extracted turn descriptor is invalid")
    byte_count = value.get("byte_count")
    commitment = value.get("content_commitment")
    relative_path = value.get("relative_path")
    turn_count = value.get("turn_count")
    if (
        value.get("schema") != EXTRACTED_TURNS_DESCRIPTOR_SCHEMA
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or not 0 < byte_count <= MAX_EXTRACTED_TURNS_ARTIFACT_BYTES
        or not isinstance(commitment, str)
        or not commitment.startswith("sha256:")
        or not isinstance(relative_path, str)
        or not isinstance(turn_count, int)
        or isinstance(turn_count, bool)
        or turn_count < 0
    ):
        raise InvalidTransitionError("extracted turn descriptor is invalid")
    digest = commitment.removeprefix("sha256:")
    expected = f"{EXTRACTED_TURNS_DIRECTORY}/extracted-turns-v2-{digest}.json"
    relative = PurePosixPath(relative_path)
    if (
        _HASH_RE.fullmatch(digest) is None
        or relative.is_absolute()
        or str(relative) != expected
    ):
        raise InvalidTransitionError("extracted turn descriptor path is invalid")
    return byte_count, digest, relative_path, turn_count


def _staged_payload(
    expected_path: Path,
    staged_files: Sequence[source_inputs.PreparedFile] | None,
) -> bytes | None:
    if staged_files is None:
        return None
    matches = [item.payload for item in staged_files if item.path == expected_path]
    if len(matches) > 1:
        raise InvalidTransitionError("extracted turn staging is ambiguous")
    return None if not matches else matches[0]


def load(
    run_dir: Path,
    value: Mapping[str, Any],
    *,
    staged_files: Sequence[source_inputs.PreparedFile] | None = None,
) -> dict[str, dict[str, Any]]:
    if value.get("schema") != EXTRACTED_TURNS_DESCRIPTOR_SCHEMA:
        return _validated_turns(value)
    byte_count, digest, relative_path, turn_count = _validated_descriptor(value)
    expected_path = (run_dir / relative_path).absolute()
    payload = _staged_payload(expected_path, staged_files)
    if payload is None:
        try:
            payload = safe_io.read_bounded_bytes(
                expected_path,
                max_bytes=byte_count,
                require_owner_only=True,
            )
        except (OSError, safe_io.UnsafePathError) as error:
            raise InvalidTransitionError(
                "extracted turn sidecar cannot be authenticated"
            ) from error
    if len(payload) != byte_count or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(), digest
    ):
        raise InvalidTransitionError("extracted turn sidecar changed")
    try:
        decoded = strict_json_loads(payload)
    except (TypeError, ValueError) as error:
        raise InvalidTransitionError("extracted turn sidecar is invalid") from error
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"schema", "turns"}
        or decoded.get("schema") != EXTRACTED_TURNS_ARTIFACT_SCHEMA
        or not isinstance(decoded.get("turns"), dict)
    ):
        raise InvalidTransitionError("extracted turn sidecar is invalid")
    turns = _validated_turns(decoded["turns"])
    if len(turns) != turn_count:
        raise InvalidTransitionError("extracted turn sidecar count changed")
    return turns
