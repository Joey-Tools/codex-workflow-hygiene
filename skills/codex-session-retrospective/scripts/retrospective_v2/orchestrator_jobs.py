"""Bounded agent job and execution-envelope construction."""

from __future__ import annotations
import base64
import copy
import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from . import result_validation, safe_io, sharding, transport as source_transport
from .checkpoints import canonical_json_bytes, content_digest
from .contracts import JobKind, RefType, RunStage
from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_protocols import JobsProjectionPort

from .orchestrator_support import (
    EXECUTION_CONTRACT_SCHEMA,
    EXECUTION_VERSION_CONTRACT,
    InvalidInputError,
    InvalidTransitionError,
    PROMPT_DIGEST,
    PROMPT_VERSION,
    RAW_SHARD_DIRECTORY,
    RunConflictError,
    _AGENT_INSTRUCTIONS,
    _RESULT_SCHEMA_BY_KIND,
    _json_copy,
)


class AgentJobOperations(OrchestratorComponent):
    def __init__(
        self,
        context: RuntimeContext,
        *,
        projection: JobsProjectionPort,
    ) -> None:
        super().__init__(context)
        self._projection = projection

    def _agent_envelope(
        self,
        task: Mapping[str, Any],
        attempt: Mapping[str, Any],
    ) -> dict[str, Any]:
        sink_name = str(attempt["job_ref"]).replace(":", "-") + ".json"
        output_sink = attempt.get("output_sink")
        if not isinstance(output_sink, str):
            output_sink = str(self.run_dir / "agent-sinks" / sink_name)
        public_metadata = {
            "allowed_output_refs": copy.deepcopy(task["allowed_refs"]),
            "attempt_ref": attempt["attempt_ref"],
            "input_digest": task["input_digest"],
            "job_ref": attempt["job_ref"],
            "output_sink": output_sink,
            "retry_ordinal": attempt["ordinal"],
            "stage": task["stage"],
            "task_ref": task["task_ref"],
        }
        if attempt.get("claim_ref") is not None:
            public_metadata.update(
                {
                    "claim_ref": attempt["claim_ref"],
                    "dispatcher_ref": attempt["dispatcher_ref"],
                    "result_ref": attempt["result_ref"],
                }
            )
        if attempt.get("reviewer_ref") is not None:
            public_metadata.update(
                {
                    "reviewer_ref": attempt["reviewer_ref"],
                    "reviewer_slot": task["metadata"]["reviewer_slot"],
                }
            )
        raw_artifact = self._sealed_raw_agent_artifact(task)
        return {
            "execution_contract": copy.deepcopy(task["execution_contract"]),
            "framing": copy.deepcopy(task["framing"]),
            "instruction": _AGENT_INSTRUCTIONS[task["job_kind"]],
            "job_manifest": copy.deepcopy(attempt["job_manifest"]),
            "payload": {
                "input_payload": copy.deepcopy(task.get("input_payload")),
                "input_refs": copy.deepcopy(task["input_refs"]),
                "raw_artifact": raw_artifact,
            },
            "public_metadata": public_metadata,
            "result_schema": _RESULT_SCHEMA_BY_KIND[task["job_kind"]],
            "schema": "coordinator_agent_envelope_v2",
        }

    def _materialize_agent_result_sink(self, attempt: Mapping[str, Any]) -> None:
        output_relative = attempt.get("output_sink_relative")
        output_sink = attempt.get("output_sink")
        if (
            not isinstance(output_relative, str)
            or Path(output_relative).parts[:1] != ("agent-sinks",)
            or len(Path(output_relative).parts) != 2
            or not isinstance(output_sink, str)
            or output_sink != str(self.run_dir / output_relative)
        ):
            raise InvalidTransitionError("agent result sink binding is invalid")
        output_path = self.run_dir / output_relative
        try:
            safe_io.ensure_owner_only_directory(output_path.parent)
            safe_io.atomic_create_bytes(
                output_path,
                b"",
                create_parents=False,
            )
        except FileExistsError:
            try:
                safe_io.check_owner_only_file(output_path)
            except (OSError, safe_io.UnsafePathError) as error:
                raise InvalidTransitionError(
                    "agent result sink cannot be authenticated"
                ) from error
        except (OSError, safe_io.UnsafePathError) as error:
            raise InvalidTransitionError(
                "agent result sink cannot be materialized"
            ) from error

    def _agent_input_fits(
        self,
        *,
        kind: str,
        input_payload: Mapping[str, Any] | None,
        input_refs: Iterable[str],
        allowed_refs: Iterable[str],
        raw_artifact: str | None = None,
        reviewer_slot: Any = None,
    ) -> bool:
        if raw_artifact is not None:
            raise InvalidInputError(
                "raw artifact fit checks require a fully constructed agent task"
            )
        normalized_refs = sorted(set(input_refs))
        normalized_allowed = sorted(set(allowed_refs))
        task_ref = "run_input_ref_v2:" + "0" * 64
        job_ref = "job_ref_v2:" + "0" * 64
        attempt_ref = "attempt_ref_v2:" + "0" * 64
        input_digest = content_digest(
            {
                "input_payload": input_payload,
                "input_refs": normalized_refs,
                "raw_manifest": None,
            }
        )
        metadata = {"reviewer_slot": reviewer_slot} if reviewer_slot else {}
        task = {
            "allowed_refs": normalized_allowed,
            "execution_contract": {
                "model": {
                    "model": "size-probe",
                    "parameters": {
                        "reasoning_effort": "xhigh",
                        "service_tier": "priority",
                    },
                    "provider": "size-probe",
                },
                "prompt": {"digest": PROMPT_DIGEST, "version": PROMPT_VERSION},
                "schema": EXECUTION_CONTRACT_SCHEMA,
                "transport": {
                    "remote_host_context_helper_commitment": "sha256:" + "0" * 64,
                    "source_transport_schema": (
                        source_transport.SOURCE_TRANSPORT_STREAM_SCHEMA
                    ),
                },
                "versions": dict(EXECUTION_VERSION_CONTRACT),
            },
            "framing": {},
            "input_digest": input_digest,
            "input_payload": (
                None if input_payload is None else copy.deepcopy(dict(input_payload))
            ),
            "input_refs": normalized_refs,
            "job_kind": kind,
            "metadata": metadata,
            "raw_artifact": None,
            "raw_manifest": None,
            "stage": RunStage.GLOBAL_SYNTHESIS.value,
            "task_ref": task_ref,
        }
        job_manifest = {
            "allowed_output_refs": normalized_allowed,
            "candidate_result_hashes": [],
            "execution_contract": copy.deepcopy(task["execution_contract"]),
            "input_digest": input_digest,
            "input_refs": normalized_refs,
            "job_kind": kind,
            "job_ref": job_ref,
            "result_schema": _RESULT_SCHEMA_BY_KIND[kind],
            "retry_ordinal": 1,
            "safety_review_hashes": [],
            "schema": "coordinator_agent_job_v2",
            "task_ref": task_ref,
        }
        attempt = {
            "attempt_ref": attempt_ref,
            "job_manifest": job_manifest,
            "job_ref": job_ref,
            "ordinal": 1,
            "reviewer_ref": (
                "reviewer_ref_v2:" + "0" * 64 if reviewer_slot is not None else None
            ),
        }
        return (
            len(canonical_json_bytes(self._agent_envelope(task, attempt)))
            <= self._agent_envelope_limit()
        )

    def _create_agent_task(
        self,
        state: dict[str, Any],
        *,
        stage: str,
        kind: str,
        partition_ref: str,
        input_refs: Sequence[str],
        input_payload: Mapping[str, Any] | None,
        allowed_refs: Iterable[str],
        allowed_turn_refs: Iterable[str] = (),
        host_refs: Iterable[str] = (),
        metadata: Mapping[str, Any] | None = None,
        raw_manifest: Mapping[str, Any] | None = None,
        raw_artifact: str | None = None,
        framing: Mapping[str, Any] | None = None,
    ) -> str:
        normalized_allowed_refs = sorted(set(allowed_refs))
        normalized_allowed_turn_refs = sorted(set(allowed_turn_refs))
        normalized_host_refs = sorted(set(host_refs))
        immutable = {
            "allowed_refs": normalized_allowed_refs,
            "allowed_turn_refs": normalized_allowed_turn_refs,
            "execution_contract": self._projection._execution_contract(state),
            "framing": _json_copy(dict(framing or {}), label="task framing"),
            "host_refs": normalized_host_refs,
            "input_payload": (
                None
                if input_payload is None
                else _json_copy(dict(input_payload), label="task input payload")
            ),
            "input_refs": sorted(set(input_refs)),
            "job_kind": kind,
            "metadata": _json_copy(dict(metadata or {}), label="task metadata"),
            "partition_ref": partition_ref,
            "raw_artifact": raw_artifact,
            "raw_manifest": (
                None
                if raw_manifest is None
                else _json_copy(dict(raw_manifest), label="raw shard manifest")
            ),
            "stage": stage,
        }
        immutable_digest = content_digest(immutable)
        task_ref = self._ref(
            RefType.RUN_INPUT,
            state["run_ref"],
            "agent_task",
            immutable_digest,
        )
        existing = state["jobs"].get(task_ref)
        if existing is not None:
            if existing.get("immutable_digest") != immutable_digest:
                raise RunConflictError("deterministic task reference collision")
            reuse_count = existing.get("cache_reuse_count", 0)
            if (
                not isinstance(reuse_count, int)
                or isinstance(reuse_count, bool)
                or reuse_count < 0
            ):
                raise RunConflictError("agent task cache reuse count is invalid")
            metrics = state.setdefault("metrics", {})
            metrics["agent_task_cache_hits"] = (
                metrics.get("agent_task_cache_hits", 0) + 1
            )
            metrics["agent_task_reuses"] = metrics.get("agent_task_reuses", 0) + 1
            existing["cache_reuse_count"] = reuse_count + 1
            return task_ref
        task = {
            "active_attempt_ref": None,
            "active_job_ref": None,
            "attempts": [],
            "cache_reuse_count": 0,
            "category": "agent",
            "immutable_digest": immutable_digest,
            "input_digest": content_digest(
                {
                    "input_payload": immutable["input_payload"],
                    "input_refs": immutable["input_refs"],
                    "raw_manifest": immutable["raw_manifest"],
                }
            ),
            "status": "pending",
            "task_ref": task_ref,
            **immutable,
        }
        projected_envelope = self._project_agent_envelope(state, task, ordinal=1)
        if len(canonical_json_bytes(projected_envelope)) > self._agent_envelope_limit():
            raise InvalidInputError("agent task exceeds the complete 512 KiB envelope")
        state["jobs"][task_ref] = task
        metrics = state.setdefault("metrics", {})
        metrics["agent_task_cache_misses"] = (
            metrics.get("agent_task_cache_misses", 0) + 1
        )
        return task_ref

    def _execution_manifest(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
        retry_ordinal: int,
    ) -> dict[str, Any]:
        kind = task["job_kind"]
        execution_contract = copy.deepcopy(task["execution_contract"])
        if kind == JobKind.EXTRACTOR_REDACTOR.value:
            shard_manifest = self._projection._restore_shard_manifest(
                task["raw_manifest"]
            )
            framing = canonical_json_bytes(task["framing"])
            generated = sharding.build_job_manifest(
                shard_manifest,
                job_kind=JobKind.EXTRACTOR_REDACTOR,
                prompt_version=self._projection._version_token(
                    state, "prompt", "extractor_v2"
                ),
                result_schema_version=result_validation.EXTRACTOR_RESULT_SCHEMA,
                policy_version=self._projection._policy_token(
                    state, "policy", "source_policy_v2"
                ),
                framing=framing,
                job_key=self.identity,
                retry_ordinal=retry_ordinal,
            ).to_dict()
            body = {key: value for key, value in generated.items() if key != "job_ref"}
            body.update(
                {
                    "execution_contract": execution_contract,
                    "allowed_output_refs": copy.deepcopy(task["allowed_refs"]),
                    "result_schema": result_validation.EXTRACTOR_RESULT_SCHEMA,
                    "task_ref": task["task_ref"],
                }
            )
            return {
                "job_ref": self._ref(RefType.JOB, state["run_ref"], body),
                **body,
            }
        body = {
            "allowed_output_refs": copy.deepcopy(task["allowed_refs"]),
            "candidate_result_hashes": copy.deepcopy(
                task["metadata"].get("candidate_result_hashes", [])
            ),
            "input_digest": task["input_digest"],
            "input_refs": copy.deepcopy(task["input_refs"]),
            "execution_contract": execution_contract,
            "job_kind": kind,
            "result_schema": _RESULT_SCHEMA_BY_KIND[kind],
            "retry_ordinal": retry_ordinal,
            "schema": "coordinator_agent_job_v2",
            "safety_review_hashes": copy.deepcopy(
                task["metadata"].get("safety_review_hashes", [])
            ),
            "task_ref": task["task_ref"],
        }
        job_ref = self._ref(RefType.JOB, state["run_ref"], body)
        return {"job_ref": job_ref, **body}

    def _project_agent_envelope(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
        *,
        ordinal: int,
    ) -> dict[str, Any]:
        job_manifest = self._execution_manifest(state, task, ordinal)
        job_ref = job_manifest["job_ref"]
        attempt_ref = self._ref(
            RefType.ATTEMPT,
            state["run_ref"],
            job_ref,
            ordinal,
        )
        reviewer_ref = None
        reviewer_slot = task["metadata"].get("reviewer_slot")
        if reviewer_slot is not None:
            reviewer_ref = self._ref(
                RefType.REVIEWER,
                task["partition_ref"],
                reviewer_slot,
                ordinal,
            )
        return self._agent_envelope(
            task,
            {
                "attempt_ref": attempt_ref,
                "job_manifest": job_manifest,
                "job_ref": job_ref,
                "ordinal": ordinal,
                "reviewer_ref": reviewer_ref,
            },
        )

    def _sealed_raw_agent_artifact(
        self,
        task: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        relative_path = task.get("raw_artifact")
        manifest_value = task.get("raw_manifest")
        if relative_path is None and manifest_value is None:
            return None
        if not isinstance(relative_path, str) or not isinstance(
            manifest_value, Mapping
        ):
            raise InvalidTransitionError(
                "raw agent artifact requires one sealed path and manifest"
            )
        relative = Path(relative_path)
        if (
            relative.is_absolute()
            or relative.parts[:1] != (RAW_SHARD_DIRECTORY,)
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise InvalidTransitionError("raw agent artifact path is invalid")
        manifest = self._projection._restore_shard_manifest(manifest_value)
        if relative.name != manifest.file_name:
            raise InvalidTransitionError(
                "raw agent artifact path does not match its manifest"
            )
        try:
            data = safe_io.read_bounded_bytes(
                self.run_dir / relative,
                max_bytes=manifest.byte_count,
                require_owner_only=True,
            )
        except (OSError, ValueError) as error:
            raise InvalidTransitionError(
                "raw agent artifact cannot be read within its sealed bound"
            ) from error
        if (
            len(data) != manifest.byte_count
            or hashlib.sha256(data).hexdigest() != manifest.content_sha256
        ):
            raise InvalidTransitionError(
                "raw agent artifact does not match its sealed manifest"
            )
        return {
            "encoding": "base64",
            "manifest": copy.deepcopy(dict(manifest_value)),
            "payload_b64": base64.b64encode(data).decode("ascii"),
        }
