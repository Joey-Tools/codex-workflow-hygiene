"""Authenticated sidecars for immutable agent-task inputs."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import hmac
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from . import safe_io, source_inputs
from .checkpoints import canonical_json_bytes, content_digest
from .contracts import RefType, strict_json_loads
from .orchestrator_support import InvalidTransitionError


AGENT_TASK_INPUT_ARTIFACT_SCHEMA = "agent_task_input_artifact_v2"
AGENT_TASK_INPUT_DESCRIPTOR_SCHEMA = "agent_task_input_descriptor_v2"
AGENT_TASK_INPUT_DIRECTORY = "agent-sinks/task-inputs"
MAX_AGENT_TASK_INPUT_ARTIFACT_BYTES = 640 * 1024
IMMUTABLE_FIELDS = frozenset(
    {
        "allowed_refs",
        "allowed_turn_refs",
        "execution_contract",
        "framing",
        "host_refs",
        "input_payload",
        "input_refs",
        "job_kind",
        "metadata",
        "partition_ref",
        "raw_artifact",
        "raw_manifest",
        "stage",
    }
)
SUMMARY_FIELDS = frozenset(
    {"host_refs", "job_kind", "metadata", "partition_ref", "stage"}
)
SIDECAR_ONLY_METADATA_FIELDS = frozenset(
    {
        "adjudication_candidate_results",
        "candidate_results",
        "turn_metadata",
        "underlying_episode_refs",
        "underlying_turn_refs",
        "validation_child_topic_results",
        "validation_topic_input",
    }
)
_BULK_FIELDS = IMMUTABLE_FIELDS - SUMMARY_FIELDS
_TASK_REF_RE = re.compile(rf"{re.escape(RefType.RUN_INPUT.value)}:[0-9a-f]{{64}}\Z")
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_DESCRIPTOR_FIELDS = frozenset(
    {
        "byte_count",
        "content_commitment",
        "immutable_digest",
        "relative_path",
        "schema",
        "task_ref",
    }
)


@dataclass(slots=True)
class Staging:
    files: list[source_inputs.PreparedFile] = field(default_factory=list)

    def prepare(
        self,
        run_dir: Path,
        *,
        task_ref: str,
        immutable: Mapping[str, Any],
        immutable_digest: str,
    ) -> dict[str, Any]:
        descriptor, prepared = prepare(
            run_dir,
            task_ref=task_ref,
            immutable=immutable,
            immutable_digest=immutable_digest,
        )
        self.files.append(prepared)
        return descriptor

    def materialize(self) -> tuple[source_inputs.MaterializedFile, ...]:
        return source_inputs.materialize(self.files)

    def add_file(self, path: Path, payload: bytes) -> None:
        self.files.append(source_inputs.prepare_file(path, payload))

    def for_task(self, run_dir: Path, task: Mapping[str, Any]) -> dict[str, Any]:
        binding = _task_binding(task)
        if binding is None:
            return for_task(run_dir, task)
        task_ref, immutable_digest, descriptor = binding
        byte_count, digest, relative_path = _validated_descriptor(
            descriptor,
            task_ref=task_ref,
            immutable_digest=immutable_digest,
        )
        expected_path = (run_dir / relative_path).absolute()
        matches = [
            prepared for prepared in self.files if prepared.path == expected_path
        ]
        if not matches:
            return for_task(run_dir, task)
        if len(matches) != 1:
            raise InvalidTransitionError("agent task input staging is ambiguous")
        immutable = _decode_payload(
            matches[0].payload,
            byte_count=byte_count,
            digest=digest,
            task_ref=task_ref,
            immutable_digest=immutable_digest,
        )
        _validate_summaries(task, immutable)
        return immutable

    @staticmethod
    def rollback(files: tuple[source_inputs.MaterializedFile, ...]) -> None:
        source_inputs.rollback(files)

    def clear(self) -> None:
        self.files.clear()


def prepare(
    run_dir: Path,
    *,
    task_ref: str,
    immutable: Mapping[str, Any],
    immutable_digest: str,
) -> tuple[dict[str, Any], source_inputs.PreparedFile]:
    normalized = dict(immutable)
    if (
        _TASK_REF_RE.fullmatch(task_ref) is None
        or set(normalized) != IMMUTABLE_FIELDS
        or _HASH_RE.fullmatch(immutable_digest) is None
        or content_digest(normalized) != immutable_digest
    ):
        raise InvalidTransitionError("agent task input binding is invalid")
    payload = canonical_json_bytes(
        {
            "immutable": normalized,
            "immutable_digest": immutable_digest,
            "schema": AGENT_TASK_INPUT_ARTIFACT_SCHEMA,
            "task_ref": task_ref,
        }
    )
    if len(payload) > MAX_AGENT_TASK_INPUT_ARTIFACT_BYTES:
        raise InvalidTransitionError("agent task input sidecar exceeds its byte bound")
    digest = hashlib.sha256(payload).hexdigest()
    relative_path = f"{AGENT_TASK_INPUT_DIRECTORY}/agent-task-input-v2-{digest}.json"
    descriptor = {
        "byte_count": len(payload),
        "content_commitment": f"sha256:{digest}",
        "immutable_digest": immutable_digest,
        "relative_path": relative_path,
        "schema": AGENT_TASK_INPUT_DESCRIPTOR_SCHEMA,
        "task_ref": task_ref,
    }
    return descriptor, source_inputs.prepare_file(run_dir / relative_path, payload)


def _validated_descriptor(
    value: Mapping[str, Any],
    *,
    task_ref: str,
    immutable_digest: str,
) -> tuple[int, str, str]:
    if set(value) != _DESCRIPTOR_FIELDS:
        raise InvalidTransitionError("agent task input descriptor is invalid")
    byte_count = value.get("byte_count")
    commitment = value.get("content_commitment")
    relative_path = value.get("relative_path")
    if (
        value.get("schema") != AGENT_TASK_INPUT_DESCRIPTOR_SCHEMA
        or value.get("task_ref") != task_ref
        or value.get("immutable_digest") != immutable_digest
        or _TASK_REF_RE.fullmatch(task_ref) is None
        or _HASH_RE.fullmatch(immutable_digest) is None
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or not 0 < byte_count <= MAX_AGENT_TASK_INPUT_ARTIFACT_BYTES
        or not isinstance(commitment, str)
        or not commitment.startswith("sha256:")
        or not isinstance(relative_path, str)
    ):
        raise InvalidTransitionError("agent task input descriptor is invalid")
    digest = commitment.removeprefix("sha256:")
    expected = f"{AGENT_TASK_INPUT_DIRECTORY}/agent-task-input-v2-{digest}.json"
    relative = PurePosixPath(relative_path)
    if (
        _HASH_RE.fullmatch(digest) is None
        or relative.is_absolute()
        or str(relative) != expected
    ):
        raise InvalidTransitionError("agent task input descriptor path is invalid")
    return byte_count, digest, relative_path


def load(
    run_dir: Path,
    descriptor: Mapping[str, Any],
    *,
    task_ref: str,
    immutable_digest: str,
) -> dict[str, Any]:
    byte_count, digest, relative_path = _validated_descriptor(
        descriptor,
        task_ref=task_ref,
        immutable_digest=immutable_digest,
    )
    try:
        payload = safe_io.read_bounded_bytes(
            run_dir / relative_path,
            max_bytes=byte_count,
            require_owner_only=True,
        )
    except (OSError, safe_io.UnsafePathError) as error:
        raise InvalidTransitionError(
            "agent task input sidecar cannot be authenticated"
        ) from error
    return _decode_payload(
        payload,
        byte_count=byte_count,
        digest=digest,
        task_ref=task_ref,
        immutable_digest=immutable_digest,
    )


def _decode_payload(
    payload: bytes,
    *,
    byte_count: int,
    digest: str,
    task_ref: str,
    immutable_digest: str,
) -> dict[str, Any]:
    if len(payload) != byte_count or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(), digest
    ):
        raise InvalidTransitionError("agent task input sidecar changed")
    try:
        decoded = strict_json_loads(payload)
    except (TypeError, ValueError) as error:
        raise InvalidTransitionError("agent task input sidecar is invalid") from error
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"immutable", "immutable_digest", "schema", "task_ref"}
        or decoded.get("schema") != AGENT_TASK_INPUT_ARTIFACT_SCHEMA
        or decoded.get("task_ref") != task_ref
        or decoded.get("immutable_digest") != immutable_digest
        or not isinstance(decoded.get("immutable"), dict)
        or set(decoded["immutable"]) != IMMUTABLE_FIELDS
        or content_digest(decoded["immutable"]) != immutable_digest
        or canonical_json_bytes(decoded) != payload
    ):
        raise InvalidTransitionError("agent task input sidecar is invalid")
    return decoded["immutable"]


def _task_binding(
    task: Mapping[str, Any],
) -> tuple[str, str, Mapping[str, Any]] | None:
    descriptor = task.get("task_input_artifact")
    if descriptor is None:
        return None
    if not isinstance(descriptor, Mapping) or any(key in task for key in _BULK_FIELDS):
        raise InvalidTransitionError("agent task input has multiple representations")
    task_ref = task.get("task_ref")
    immutable_digest = task.get("immutable_digest")
    if not isinstance(task_ref, str) or not isinstance(immutable_digest, str):
        raise InvalidTransitionError("agent task input binding is invalid")
    return task_ref, immutable_digest, descriptor


def _validate_summaries(task: Mapping[str, Any], immutable: Mapping[str, Any]) -> None:
    for key in SUMMARY_FIELDS:
        expected = (
            checkpoint_metadata(immutable[key]) if key == "metadata" else immutable[key]
        )
        if task.get(key) != expected:
            raise InvalidTransitionError("agent task input summary changed")


def checkpoint_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidTransitionError("agent task metadata is invalid")
    return {
        key: copy.deepcopy(value[key])
        for key in sorted(value)
        if key not in SIDECAR_ONLY_METADATA_FIELDS
    }


def for_task(run_dir: Path, task: Mapping[str, Any]) -> dict[str, Any]:
    binding = _task_binding(task)
    if binding is None:
        if not IMMUTABLE_FIELDS.issubset(task):
            raise InvalidTransitionError("legacy agent task input is incomplete")
        return {key: task[key] for key in IMMUTABLE_FIELDS}
    task_ref, immutable_digest, descriptor = binding
    immutable = load(
        run_dir,
        descriptor,
        task_ref=task_ref,
        immutable_digest=immutable_digest,
    )
    _validate_summaries(task, immutable)
    return immutable
