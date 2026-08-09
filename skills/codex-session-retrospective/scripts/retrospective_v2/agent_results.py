"""Authenticated owner-only sidecars for accepted agent results."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import hmac
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence

from . import result_validation, safe_io, source_inputs
from .checkpoints import canonical_json_bytes
from .contracts import RefType, strict_json_loads
from .orchestrator_support import InvalidTransitionError


AGENT_RESULT_ARTIFACT_SCHEMA = "agent_result_artifact_v2"
AGENT_RESULT_DESCRIPTOR_SCHEMA = "agent_result_descriptor_v2"
AGENT_RESULT_REFERENCE_SCHEMA = "agent_result_reference_v2"
AGENT_RESULT_DIRECTORY = "agent-sinks/results"
MAX_AGENT_RESULT_ARTIFACT_BYTES = result_validation.MAX_RESULT_BYTES + 4 * 1024
_TASK_REF_RE = re.compile(rf"{re.escape(RefType.RUN_INPUT.value)}:[0-9a-f]{{64}}\Z")
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_DESCRIPTOR_FIELDS = frozenset(
    {
        "byte_count",
        "content_commitment",
        "relative_path",
        "result_hash",
        "schema",
        "task_ref",
    }
)


@dataclass(frozen=True, slots=True)
class PreparedAgentResult:
    descriptor: dict[str, Any]
    file: source_inputs.PreparedFile


@dataclass(slots=True)
class Staging:
    files: list[source_inputs.PreparedFile] = field(default_factory=list)

    def prepare(
        self,
        run_dir: Path,
        task: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> tuple[dict[str, Any], str]:
        task_ref = task.get("task_ref")
        if not isinstance(task_ref, str):
            raise InvalidTransitionError("agent result task_ref is invalid")
        result_hash = result_validation.canonical_result_hash(result)
        prepared = prepare(
            run_dir,
            task_ref=task_ref,
            result=result,
            result_hash=result_hash,
        )
        self.files.append(prepared.file)
        return prepared.descriptor, result_hash

    def commit(self, store: Any, mutator: Any) -> Any:
        return store.staged_transaction(
            mutator,
            stage=lambda: source_inputs.materialize(self.files),
            rollback=source_inputs.rollback,
        )


def prepare(
    run_dir: Path,
    *,
    task_ref: str,
    result: Mapping[str, Any],
    result_hash: str,
) -> PreparedAgentResult:
    if _TASK_REF_RE.fullmatch(task_ref) is None:
        raise InvalidTransitionError("agent result task_ref is invalid")
    if _HASH_RE.fullmatch(result_hash) is None:
        raise InvalidTransitionError("agent result hash is invalid")
    normalized = dict(result)
    if result_validation.canonical_result_hash(normalized) != result_hash:
        raise InvalidTransitionError("agent result hash does not match its payload")
    payload = canonical_json_bytes(
        {
            "result": normalized,
            "result_hash": result_hash,
            "schema": AGENT_RESULT_ARTIFACT_SCHEMA,
            "task_ref": task_ref,
        }
    )
    if len(payload) > MAX_AGENT_RESULT_ARTIFACT_BYTES:
        raise InvalidTransitionError("agent result sidecar exceeds its byte bound")
    digest = hashlib.sha256(payload).hexdigest()
    relative_path = f"{AGENT_RESULT_DIRECTORY}/agent-result-v2-{digest}.json"
    descriptor = {
        "byte_count": len(payload),
        "content_commitment": f"sha256:{digest}",
        "relative_path": relative_path,
        "result_hash": result_hash,
        "schema": AGENT_RESULT_DESCRIPTOR_SCHEMA,
        "task_ref": task_ref,
    }
    return PreparedAgentResult(
        descriptor=descriptor,
        file=source_inputs.prepare_file(run_dir / relative_path, payload),
    )


def _validated_descriptor(
    value: Mapping[str, Any],
    *,
    expected_task_ref: str,
) -> tuple[int, str, str, str]:
    if not isinstance(value, Mapping) or set(value) != _DESCRIPTOR_FIELDS:
        raise InvalidTransitionError("agent result descriptor is invalid")
    byte_count = value.get("byte_count")
    commitment = value.get("content_commitment")
    relative_path = value.get("relative_path")
    result_hash = value.get("result_hash")
    task_ref = value.get("task_ref")
    if (
        value.get("schema") != AGENT_RESULT_DESCRIPTOR_SCHEMA
        or task_ref != expected_task_ref
        or _TASK_REF_RE.fullmatch(expected_task_ref) is None
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or not 0 < byte_count <= MAX_AGENT_RESULT_ARTIFACT_BYTES
        or not isinstance(commitment, str)
        or not commitment.startswith("sha256:")
        or not isinstance(relative_path, str)
        or not isinstance(result_hash, str)
        or _HASH_RE.fullmatch(result_hash) is None
    ):
        raise InvalidTransitionError("agent result descriptor is invalid")
    digest = commitment.removeprefix("sha256:")
    if _HASH_RE.fullmatch(digest) is None:
        raise InvalidTransitionError("agent result descriptor is invalid")
    relative = PurePosixPath(relative_path)
    expected = f"{AGENT_RESULT_DIRECTORY}/agent-result-v2-{digest}.json"
    if relative.is_absolute() or str(relative) != expected:
        raise InvalidTransitionError("agent result descriptor path is invalid")
    return byte_count, digest, relative_path, result_hash


def load(
    run_dir: Path,
    descriptor: Mapping[str, Any],
    *,
    expected_task_ref: str,
) -> dict[str, Any]:
    byte_count, digest, relative_path, expected_result_hash = _validated_descriptor(
        descriptor,
        expected_task_ref=expected_task_ref,
    )
    try:
        payload = safe_io.read_bounded_bytes(
            run_dir / relative_path,
            max_bytes=byte_count,
            require_owner_only=True,
        )
    except (OSError, safe_io.UnsafePathError) as error:
        raise InvalidTransitionError(
            "agent result sidecar cannot be authenticated"
        ) from error
    if len(payload) != byte_count or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(), digest
    ):
        raise InvalidTransitionError("agent result sidecar changed")
    try:
        decoded = strict_json_loads(payload)
    except (TypeError, ValueError) as error:
        raise InvalidTransitionError("agent result sidecar is invalid") from error
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"result", "result_hash", "schema", "task_ref"}
        or decoded.get("schema") != AGENT_RESULT_ARTIFACT_SCHEMA
        or decoded.get("task_ref") != expected_task_ref
        or decoded.get("result_hash") != expected_result_hash
        or not isinstance(decoded.get("result"), dict)
        or canonical_json_bytes(decoded) != payload
    ):
        raise InvalidTransitionError("agent result sidecar is invalid")
    result = decoded["result"]
    if result_validation.canonical_result_hash(result) != expected_result_hash:
        raise InvalidTransitionError("agent result sidecar hash changed")
    return result


def for_task(run_dir: Path, task: Mapping[str, Any]) -> dict[str, Any] | None:
    """Load one accepted result, retaining read-only inline compatibility."""

    has_inline = "result" in task
    has_descriptor = "result_artifact" in task
    if has_inline and has_descriptor:
        raise InvalidTransitionError("agent result has multiple representations")
    task_result_hash = task.get("result_hash")
    if has_inline:
        inline = task.get("result")
        if not isinstance(inline, Mapping):
            raise InvalidTransitionError("inline agent result is invalid")
        normalized = dict(inline)
        if (
            not isinstance(task_result_hash, str)
            or _HASH_RE.fullmatch(task_result_hash) is None
            or result_validation.canonical_result_hash(normalized) != task_result_hash
        ):
            raise InvalidTransitionError("inline agent result hash changed")
        return normalized
    if not has_descriptor:
        if task.get("status") == "accepted":
            raise InvalidTransitionError("accepted agent result is missing")
        return None
    descriptor = task.get("result_artifact")
    if not isinstance(descriptor, Mapping):
        raise InvalidTransitionError("agent result descriptor is invalid")
    task_ref = task.get("task_ref")
    if not isinstance(task_ref, str):
        raise InvalidTransitionError("agent result task_ref is invalid")
    if (
        not isinstance(task_result_hash, str)
        or descriptor.get("result_hash") != task_result_hash
    ):
        raise InvalidTransitionError("agent result task hash binding changed")
    return load(run_dir, descriptor, expected_task_ref=task_ref)


def reference_for_task(task: Mapping[str, Any]) -> dict[str, str]:
    if task.get("status") != "accepted":
        raise InvalidTransitionError("agent result reference requires an accepted task")
    task_ref = task.get("task_ref")
    result_hash = task.get("result_hash")
    if (
        not isinstance(task_ref, str)
        or _TASK_REF_RE.fullmatch(task_ref) is None
        or not isinstance(result_hash, str)
        or _HASH_RE.fullmatch(result_hash) is None
    ):
        raise InvalidTransitionError("agent result reference binding is invalid")
    return {
        "result_hash": result_hash,
        "schema": AGENT_RESULT_REFERENCE_SCHEMA,
        "task_ref": task_ref,
    }


def from_reference(
    run_dir: Path,
    jobs: Mapping[str, Mapping[str, Any]],
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve a compact task binding or a legacy inline derived result."""

    if value.get("schema") != AGENT_RESULT_REFERENCE_SCHEMA:
        return copy.deepcopy(dict(value))
    if set(value) != {"result_hash", "schema", "task_ref"}:
        raise InvalidTransitionError("agent result reference is invalid")
    task_ref = value.get("task_ref")
    result_hash = value.get("result_hash")
    if (
        not isinstance(task_ref, str)
        or _TASK_REF_RE.fullmatch(task_ref) is None
        or not isinstance(result_hash, str)
        or _HASH_RE.fullmatch(result_hash) is None
    ):
        raise InvalidTransitionError("agent result reference is invalid")
    task = jobs.get(task_ref)
    if (
        not isinstance(task, Mapping)
        or task.get("status") != "accepted"
        or task.get("result_hash") != result_hash
    ):
        raise InvalidTransitionError("agent result reference task binding changed")
    result = require(run_dir, task)
    if result_validation.canonical_result_hash(result) != result_hash:
        raise InvalidTransitionError("agent result reference hash changed")
    return result


def require(
    run_dir: Path,
    task: Mapping[str, Any],
    *,
    label: str = "accepted agent",
) -> dict[str, Any]:
    result = for_task(run_dir, task)
    if result is None:
        raise InvalidTransitionError(f"{label} result is missing")
    return result


def copies_for_tasks(
    run_dir: Path,
    tasks: Sequence[Mapping[str, Any]],
    *,
    label: str,
) -> list[dict[str, Any]]:
    return [copy.deepcopy(require(run_dir, task, label=label)) for task in tasks]
