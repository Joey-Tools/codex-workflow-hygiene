"""Agent result validation and retained history projection."""

from __future__ import annotations
import codecs
from collections import Counter
from collections.abc import Iterator
import copy
import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence
from . import (
    agent_results,
    agent_task_inputs,
    authority,
    catalog,
    result_validation,
    retained_inputs,
    safe_io,
    sharding,
    source_overlap,
)
from .checkpoints import canonical_json_bytes
from .contracts import JobKind, RefType, RunStage
from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_protocols import HistoryProjectionPort, HistoryReductionPort

from .orchestrator_support import (
    ENGINE_VERSION,
    InvalidTransitionError,
    RAW_SHARD_DIRECTORY,
    RunConflictError,
    _json_copy,
)


class ResultHistoryOperations(OrchestratorComponent):
    def __init__(
        self,
        context: RuntimeContext,
        *,
        projection: HistoryProjectionPort,
        reduction: HistoryReductionPort,
    ) -> None:
        super().__init__(context)
        self._projection = projection
        self._reduction = reduction

    def _adjudication_candidates(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        metadata = task.get("metadata")
        jobs = state.get("jobs")
        if not isinstance(metadata, Mapping) or not isinstance(jobs, Mapping):
            raise InvalidTransitionError("adjudication candidate binding is invalid")
        task_refs = metadata.get("candidate_task_refs")
        result_hashes = metadata.get("candidate_result_hashes")
        if (
            not isinstance(task_refs, list)
            or not isinstance(result_hashes, list)
            or len(task_refs) != 2
            or len(result_hashes) != 2
            or len(set(task_refs)) != 2
        ):
            raise InvalidTransitionError("adjudication candidate binding is invalid")
        candidates: list[dict[str, Any]] = []
        for task_ref, result_hash in zip(task_refs, result_hashes, strict=True):
            candidate_task = jobs.get(task_ref)
            if (
                not isinstance(task_ref, str)
                or not isinstance(result_hash, str)
                or not isinstance(candidate_task, Mapping)
                or candidate_task.get("status") != "accepted"
                or candidate_task.get("result_hash") != result_hash
            ):
                raise InvalidTransitionError(
                    "adjudication candidate task binding changed"
                )
            candidate = agent_results.require(
                self.run_dir,
                candidate_task,
                label="adjudication candidate",
            )
            if result_validation.canonical_result_hash(candidate) != result_hash:
                raise InvalidTransitionError("adjudication candidate result changed")
            candidates.append(candidate)
        return candidates

    def _validate_agent_result(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
        result: Mapping[str, Any],
        *,
        attempt_ref: str,
    ) -> dict[str, Any]:
        kind = task["job_kind"]
        immutable = agent_task_inputs.for_task(self.run_dir, task)
        allowed_refs = immutable["allowed_refs"]
        allowed_turn_refs = immutable["allowed_turn_refs"]
        metadata = immutable["metadata"]
        if kind == JobKind.EXTRACTOR_REDACTOR.value:
            turn_metadata = metadata["turn_metadata"]
            result_validation.validate_result_envelope(result)
            sanitized = result_validation.post_redact(result)
            overlap_views = (
                result_validation.extractor_overlap_text_view(result),
                result_validation.extractor_overlap_text_view(sanitized),
            )
            query_chars = result_validation.source_overlap_query_chars(
                *overlap_views,
            )
            for source_batch in self._extractor_overlap_batches(
                state,
                task,
                query_chars=query_chars,
            ):
                for candidate in overlap_views:
                    overlap_findings = result_validation.scan_for_leaks(
                        candidate,
                        original_prompts=source_batch,
                    )
                    if any(
                        finding.category == "original_prompt"
                        for finding in overlap_findings
                    ):
                        raise result_validation.ResultValidationError(
                            "extractor result overlaps sealed raw source text"
                        )
            validated = result_validation.validate_extractor_result(
                result,
                allowed_refs,
                turn_bindings=turn_metadata,
            )
            return validated
        if kind in {
            JobKind.EPISODE_REVIEWER.value,
            JobKind.INDEPENDENT_RISK_REVIEWER.value,
        }:
            slot = metadata["reviewer_slot"]
            input_payload = immutable.get("input_payload")
            child_results = (
                input_payload.get("child_results")
                if isinstance(input_payload, Mapping)
                and input_payload.get("schema")
                == "episode_review_hierarchical_input_v2"
                else None
            )
            if child_results is None:
                validated = result_validation.validate_episode_review_result(
                    result,
                    allowed_refs,
                    allowed_turn_refs=allowed_turn_refs,
                    expected_reviewer_slot=slot,
                )
            else:
                validated = (
                    result_validation.validate_hierarchical_episode_review_result(
                        result,
                        child_results,
                        allowed_refs,
                        allowed_turn_refs=allowed_turn_refs,
                        expected_child_result_hashes=input_payload[
                            "child_result_hashes"
                        ],
                        expected_reviewer_slot=slot,
                    )
                )
            attempt = self._projection._active_attempt(task, attempt_ref)
            if validated["attempt_ref"] != attempt_ref:
                raise result_validation.ResultValidationError(
                    "review result is not bound to the active attempt"
                )
            if validated["reviewer_ref"] != attempt["reviewer_ref"]:
                raise result_validation.ResultValidationError(
                    "review result is not bound to the assigned reviewer"
                )
            for field in ("episode_ref", "episode_revision_ref"):
                if validated[field] != metadata[field]:
                    raise result_validation.ResultValidationError(
                        f"review result {field} does not match its job"
                    )
            return validated
        if kind == JobKind.ADJUDICATOR.value:
            return result_validation.validate_adjudication_result(
                result,
                allowed_refs,
                allowed_turn_refs=allowed_turn_refs,
                candidate_results=self._adjudication_candidates(state, task),
            )
        if kind == JobKind.TOPIC_REDUCER.value:
            child_results = metadata.get("validation_child_topic_results")
            if child_results is not None:
                return result_validation.validate_hierarchical_topic_result(
                    result,
                    child_results,
                    allowed_refs,
                    expected_topic_candidate_ref=metadata["topic_candidate_ref"],
                    expected_topic_ref=metadata["topic_ref"],
                    expected_workstream_ref=metadata["workstream_ref"],
                )
            return result_validation.validate_topic_result(
                result,
                metadata["validation_topic_input"],
                allowed_refs,
                expected_topic_ref=metadata["topic_ref"],
                allowed_turn_refs=allowed_turn_refs,
                adjudication_candidate_results=metadata.get(
                    "adjudication_candidate_results", {}
                ),
            )
        if kind == JobKind.GLOBAL_SYNTHESIS.value:
            topic_results, independent_review_results = (
                self._reduction._synthesis_validation_results(state, task)
            )
            validated = result_validation.validate_synthesis_result(
                result,
                allowed_refs,
                allowed_turn_refs=allowed_turn_refs,
                independent_review_results=independent_review_results,
                source_allowed_refs=self._projection._collect_refs(
                    {
                        "independent_review_results": independent_review_results,
                        "topic_results": topic_results,
                    }
                ),
                topic_results=topic_results,
            )
            return validated
        raise result_validation.ResultValidationError(f"unsupported JobKind: {kind}")

    def _extractor_overlap_batches(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
        *,
        query_chars: int,
    ) -> Iterator[tuple[str, ...]]:
        immutable = agent_task_inputs.for_task(self.run_dir, task)
        task_manifest = self._projection._restore_shard_manifest(
            immutable["raw_manifest"]
        )
        task_relative_path = immutable.get("raw_artifact")
        shard_state = state.get("source", {}).get("shards", {})
        reassembly = state.get("source", {}).get("reassembly", {})
        if (
            not isinstance(task_relative_path, str)
            or not isinstance(shard_state, Mapping)
            or not isinstance(reassembly, Mapping)
        ):
            raise result_validation.ResultValidationError(
                "extractor task is missing its sealed raw shard state"
            )
        task_shard = shard_state.get(task["partition_ref"])
        if not isinstance(task_shard, Mapping):
            raise result_validation.ResultValidationError(
                "extractor task shard is absent from sealed source state"
            )
        if (
            task_shard.get("manifest") != task_manifest.to_dict()
            or task_shard.get("relative_path") != task_relative_path
        ):
            raise result_validation.ResultValidationError(
                "extractor task shard differs from sealed source state"
            )

        def load_shard(shard_ref: str) -> tuple[sharding.ShardManifest, bytes]:
            raw_entry = shard_state.get(shard_ref)
            if not isinstance(raw_entry, Mapping):
                raise result_validation.ResultValidationError(
                    "extractor reassembly shard is missing"
                )
            manifest = self._projection._restore_shard_manifest(
                raw_entry.get("manifest")
            )
            relative_path = raw_entry.get("relative_path")
            if (
                manifest.shard_ref != shard_ref
                or not isinstance(relative_path, str)
                or Path(relative_path).parts
                != (RAW_SHARD_DIRECTORY, manifest.file_name)
            ):
                raise result_validation.ResultValidationError(
                    "extractor reassembly shard binding is invalid"
                )
            try:
                data = safe_io.read_bounded_bytes(
                    self.run_dir / relative_path,
                    max_bytes=manifest.byte_count,
                    require_owner_only=True,
                )
            except (OSError, ValueError) as error:
                raise result_validation.ResultValidationError(
                    "extractor raw shard could not be read within its bound"
                ) from error
            if (
                len(data) != manifest.byte_count
                or hashlib.sha256(data).hexdigest() != manifest.content_sha256
            ):
                raise result_validation.ResultValidationError(
                    "extractor raw shard does not match its sealed manifest"
                )
            serialized_header, separator, payload = data.partition(b"\n")
            expected_header = canonical_json_bytes(
                {
                    "format": "session_retrospective_raw_shard_v2",
                    "ranges": [item.to_dict() for item in manifest.ranges],
                    "schema_version": sharding.RAW_SHARD_SCHEMA_VERSION,
                }
            )
            if not separator or serialized_header != expected_header:
                raise result_validation.ResultValidationError(
                    "extractor raw shard header is not sealed by its manifest"
                )
            if len(payload) != manifest.raw_byte_count:
                raise result_validation.ResultValidationError(
                    "extractor raw shard payload length is inconsistent"
                )
            return manifest, payload

        turn_metadata = immutable["metadata"].get("turn_metadata", {})
        if not isinstance(turn_metadata, Mapping):
            raise result_validation.ResultValidationError(
                "extractor task turn metadata is invalid"
            )
        for turn_ref in sorted(turn_metadata):
            plan = reassembly.get(turn_ref)
            if not isinstance(plan, Mapping):
                raise result_validation.ResultValidationError(
                    "extractor logical record reassembly plan is missing"
                )
            contributors = plan.get("contributors")
            if (
                not isinstance(contributors, list)
                or not contributors
                or len(contributors) != plan.get("fragment_count")
            ):
                raise result_validation.ResultValidationError(
                    "extractor logical record contributor set is invalid"
                )

            def fragments() -> Iterator[bytes]:
                for contributor in contributors:
                    if not isinstance(contributor, Mapping):
                        raise result_validation.ResultValidationError(
                            "extractor logical record contributor is invalid"
                        )
                    shard_ref = contributor.get("shard_ref")
                    if not isinstance(shard_ref, str):
                        raise result_validation.ResultValidationError(
                            "extractor logical record shard reference is invalid"
                        )
                    manifest, payload = load_shard(shard_ref)
                    descriptors = [
                        descriptor
                        for descriptor in manifest.ranges
                        if descriptor.fragment_index
                        == contributor.get("fragment_index")
                        and descriptor.fragment_commitment
                        == contributor.get("fragment_commitment")
                        and descriptor.record_commitment
                        == plan.get("record_commitment")
                        and descriptor.coordinate.to_dict() == plan.get("coordinate")
                    ]
                    if len(descriptors) != 1:
                        raise result_validation.ResultValidationError(
                            "extractor logical record contributor is ambiguous"
                        )
                    descriptor = descriptors[0]
                    fragment = payload[
                        descriptor.payload_offset : descriptor.payload_offset
                        + descriptor.payload_length
                    ]
                    if (
                        len(fragment) != descriptor.payload_length
                        or catalog.content_commitment(fragment)
                        != descriptor.fragment_commitment
                    ):
                        raise result_validation.ResultValidationError(
                            "extractor raw shard fragment commitment changed"
                        )
                    yield fragment

            digest = hashlib.sha256()
            decoder = codecs.getincrementaldecoder("utf-8")("strict")
            try:
                for fragment in fragments():
                    digest.update(fragment)
                    decoder.decode(fragment, final=False)
                decoder.decode(b"", final=True)
            except UnicodeDecodeError as error:
                raise result_validation.ResultValidationError(
                    "extractor logical record is not UTF-8"
                ) from error
            if f"sha256:{digest.hexdigest()}" != plan.get("record_commitment"):
                raise result_validation.ResultValidationError(
                    "extractor logical record commitment changed"
                )

            try:
                yield from source_overlap.json_string_value_batches(
                    source_overlap.decoded_utf8_chunks(fragments()),
                    query_chars=query_chars,
                    maximum_batch_chars=result_validation.MAX_SOURCE_OVERLAP_CHARS,
                    maximum_batch_items=result_validation.MAX_SOURCE_OVERLAP_ITEMS,
                )
            except ValueError as error:
                raise result_validation.ResultValidationError(
                    "extractor logical record is not valid bounded JSON"
                ) from error

    @staticmethod
    def _typed_agent_gap(
        task: Mapping[str, Any],
        validated: Mapping[str, Any],
        *,
        attempt_ref: str,
    ) -> dict[str, str] | None:
        if task["job_kind"] in {
            JobKind.EPISODE_REVIEWER.value,
            JobKind.INDEPENDENT_RISK_REVIEWER.value,
        }:
            if validated["disposition"] == "reviewed":
                return None
            return {
                "attempt_ref": attempt_ref,
                "gap_reason": validated["gap_reason"],
                "kind": "episode_review_gap",
                "reviewer_slot": validated["reviewer_slot"],
            }
        if (
            task["job_kind"] == JobKind.ADJUDICATOR.value
            and validated["resolution"] == "review_gap"
        ):
            return {
                "attempt_ref": attempt_ref,
                "gap_reason": validated["gap_reason"],
                "kind": "adjudication_gap",
            }
        return None

    @staticmethod
    def _retained_agent_execution(state: Mapping[str, Any]) -> dict[str, Any]:
        jobs: list[dict[str, Any]] = []
        result_count = 0
        retry_count = 0
        agent_tasks = [
            task
            for task in state.get("jobs", {}).values()
            if task.get("category") == "agent"
        ]
        for task in sorted(agent_tasks, key=lambda item: item["task_ref"]):
            attempts: list[dict[str, Any]] = []
            for attempt in task["attempts"]:
                completed_at = attempt.get("completed_at")
                if completed_at is not None:
                    result_count += 1
                attempts.append(
                    {
                        "attempt_ref": attempt["attempt_ref"],
                        "claimed_at": attempt.get("claimed_at"),
                        "completed_at": completed_at,
                        "issued_at": attempt["issued_at"],
                        "job_ref": attempt["job_ref"],
                        "ordinal": attempt["ordinal"],
                        "reason": attempt.get("reason"),
                        "result_ref": attempt.get("result_ref"),
                        "reviewer_ref": attempt.get("reviewer_ref"),
                        "status": attempt["status"],
                    }
                )
            retry_count += max(0, len(attempts) - 1)
            jobs.append(
                {
                    "attempts": attempts,
                    "job_kind": task["job_kind"],
                    "partition_commitment": task["partition_ref"],
                    "result_hash": task.get("result_hash"),
                    "reuse_count": task.get("cache_reuse_count", 0),
                    "stage": task["stage"],
                    "status": task["status"],
                    "task_ref": task["task_ref"],
                }
            )
        return {
            "jobs": jobs,
            "result_count": result_count,
            "retry_count": retry_count,
            "schema": "agent_execution_provenance_v2",
            "task_cache": {
                "hits": state["metrics"].get("agent_task_cache_hits", 0),
                "misses": state["metrics"].get("agent_task_cache_misses", 0),
                "reuses": state["metrics"].get("agent_task_reuses", 0),
            },
        }

    def _retained_review_provenance(
        self,
        state: Mapping[str, Any],
        revision_ref: str,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for task in state.get("jobs", {}).values():
            metadata = task.get("metadata", {})
            if (
                task.get("stage") != RunStage.EPISODE_REVIEW.value
                or task.get("status") != "accepted"
                or metadata.get("episode_revision_ref") != revision_ref
                or metadata.get("hierarchy_final") is not True
            ):
                continue
            result = agent_results.for_task(self.run_dir, task)
            result_hash = task.get("result_hash")
            attempt_ref = task.get("accepted_attempt_ref")
            if (
                not isinstance(result, Mapping)
                or not isinstance(result_hash, str)
                or result_hash != result_validation.canonical_result_hash(result)
                or not isinstance(attempt_ref, str)
            ):
                raise InvalidTransitionError(
                    "accepted episode review provenance is incomplete"
                )
            attempt = next(
                (
                    item
                    for item in task["attempts"]
                    if item["attempt_ref"] == attempt_ref
                ),
                None,
            )
            reviewer_ref = (
                result.get("reviewer_ref")
                if isinstance(result.get("reviewer_ref"), str)
                else None
                if attempt is None
                else attempt.get("reviewer_ref")
            )
            reviewer_slot = metadata.get("reviewer_slot")
            if (
                attempt is None
                or not isinstance(reviewer_ref, str)
                or not isinstance(reviewer_slot, str)
            ):
                raise InvalidTransitionError(
                    "accepted episode review lacks reviewer attempt provenance"
                )
            rows.append(
                {
                    "attempt_ref": attempt_ref,
                    "job_kind": task["job_kind"],
                    "result_hash": result_hash,
                    "result_schema": result["schema"],
                    "reviewer_ref": reviewer_ref,
                    "reviewer_slot": reviewer_slot,
                }
            )
        rows.sort(key=lambda item: (item["job_kind"], item["attempt_ref"]))
        return rows

    def _persist_retained_export_inputs(
        self,
        run_state: Mapping[str, Any],
        review_data: Mapping[str, Any],
    ) -> dict[str, Any]:
        return retained_inputs.persist(self.run_dir, run_state, review_data)

    def retained_export_inputs(
        self,
        state: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        current = self.store.load() if state is None else state
        return retained_inputs.load(self.run_dir, current)

    def _build_retained_export(
        self,
        state: dict[str, Any],
        synthesis: Mapping[str, Any],
    ) -> None:
        execution_model_era = self._projection._model_era(state)
        policy_era = self._projection._policy_token(state, "policy", "source_policy_v2")
        revision_by_ref = {
            item["episode_revision_ref"]: item for item in state["episodes"]
        }
        episode_rows: list[dict[str, Any]] = []
        turn_findings: list[dict[str, Any]] = []
        meaningful_turn_refs: list[str] = []
        episode_model_eras: dict[str, str] = {}
        context_only_count = 0
        meaningfulness_gap_count = 0
        for revision_ref, revision in sorted(revision_by_ref.items()):
            meaningfulness = revision["meaningfulness"]
            context_only_count += len(meaningfulness["context_only_turn_refs"])
            meaningfulness_gap_count += len(meaningfulness["gap_turn_refs"])
            resolved_binding = state["resolved_reviews"].get(revision_ref)
            if not meaningfulness["review_required"]:
                disposition = "review_not_required"
                decision: Mapping[str, Any] = {}
            elif resolved_binding is None:
                disposition = "review_gap"
                decision = {}
            else:
                disposition = "reviewed"
                decision = agent_results.from_reference(
                    self.run_dir,
                    state["jobs"],
                    resolved_binding,
                )
            review_result_hash = (
                None
                if disposition != "reviewed"
                else result_validation.canonical_result_hash(decision)
            )
            review_provenance = self._retained_review_provenance(
                state,
                revision_ref,
            )
            episode_model_era = self._projection._retained_model_era_for_turns(
                state,
                revision["turn_refs"],
            )
            episode_model_eras[revision["episode_ref"]] = episode_model_era
            episode_rows.append(
                {
                    "episode_ref": revision["episode_ref"],
                    "episode_revision_ref": revision_ref,
                    "event_counts": self._projection._signal_counts(
                        decision.get("events", [])
                    ),
                    "finding_counts": self._projection._signal_counts(
                        decision.get("findings", [])
                    ),
                    "findings": copy.deepcopy(decision.get("findings", [])),
                    "meaningful_turn_count": len(
                        meaningfulness["meaningful_turn_refs"]
                    ),
                    "lineage_kind": revision["lineage_kind"],
                    "model_era": episode_model_era,
                    "policy_era": policy_era,
                    "review_provenance": review_provenance,
                    "review_disposition": disposition,
                    "review_result_hash": review_result_hash,
                    "revision_ordinal": revision["revision_ordinal"],
                    "risk_counts": dict(Counter(decision.get("risk_flags", []))),
                    "session_ref": revision["session_ref"],
                    "strength_counts": self._projection._signal_counts(
                        decision.get("strengths", [])
                    ),
                    "supersedes_episode_revision_ref": revision[
                        "supersedes_episode_revision_ref"
                    ],
                }
            )
            high_impact = {
                item["turn_ref"]: item for item in decision.get("high_impact_turns", [])
            }
            for turn_ref in meaningfulness["meaningful_turn_refs"]:
                meaningful_turn_refs.append(turn_ref)
                turn_model_era = self._projection._retained_model_era_for_turn(
                    state, turn_ref
                )
                if turn_ref in high_impact:
                    high_impact_turn = high_impact[turn_ref]
                    turn_findings.append(
                        {
                            "cause": high_impact_turn["cause"],
                            "confidence": high_impact_turn["confidence"],
                            "disposition": "high_impact",
                            "episode_ref": revision["episode_ref"],
                            "evidence_refs": copy.deepcopy(
                                high_impact_turn["evidence_refs"]
                            ),
                            "expected_effect": high_impact_turn["expected_effect"],
                            "model_era": turn_model_era,
                            "policy_era": policy_era,
                            "problem_statement": high_impact_turn["problem_statement"],
                            "rewritten_prompt": high_impact_turn["rewritten_prompt"],
                            "turn_ref": turn_ref,
                        }
                    )
                else:
                    turn_findings.append(
                        {
                            "disposition": (
                                "turn_review_gap"
                                if disposition == "review_gap"
                                else "not_high_impact"
                            ),
                            "episode_ref": revision["episode_ref"],
                            "model_era": turn_model_era,
                            "policy_era": policy_era,
                            "turn_ref": turn_ref,
                        }
                    )
        topic_rows = []
        for task in self._projection._tasks_for_stage(
            state, RunStage.TOPIC_REDUCTION.value
        ):
            if (
                task.get("status") != "accepted"
                or task.get("metadata", {}).get("hierarchy_final") is not True
            ):
                continue
            topic_result = agent_results.for_task(self.run_dir, task)
            if topic_result is None:
                raise InvalidTransitionError("accepted topic result is missing")
            topic_model_eras = {
                episode_model_eras.get(episode_ref, self._projection.UNKNOWN_MODEL_ERA)
                for episode_ref in topic_result["episode_refs"]
            }
            if (
                not topic_model_eras
                or self._projection.UNKNOWN_MODEL_ERA in topic_model_eras
            ):
                topic_model_era = self._projection.UNKNOWN_MODEL_ERA
            elif (
                len(topic_model_eras) != 1
                or self._projection.MIXED_MODEL_ERA in topic_model_eras
            ):
                topic_model_era = self._projection.MIXED_MODEL_ERA
            else:
                topic_model_era = next(iter(topic_model_eras))
            topic_rows.append(
                {
                    "episode_lineage": copy.deepcopy(topic_result["episode_lineage"]),
                    "episode_refs": copy.deepcopy(topic_result["episode_refs"]),
                    "findings": copy.deepcopy(topic_result["findings"]),
                    "model_era": topic_model_era,
                    "policy_era": policy_era,
                    "topic_ref": topic_result["topic_ref"],
                }
            )
        accounting = state["metrics"].get(
            "accounting",
            {item.value: 0 for item in catalog.AccountingClass},
        )
        source_expected = sum(accounting.values())
        coverage_complete = not state["gaps"] and accounting["explicit_gap"] == 0
        configuration_ref = self._ref(
            RefType.CONFIGURATION,
            state["provenance"]["configuration_root"],
        )
        retained_provenance = copy.deepcopy(state["provenance"])
        retained_provenance.update(
            {
                "agent_execution": self._retained_agent_execution(state),
                "engine_version": ENGINE_VERSION,
                "production_configuration_ref": configuration_ref,
            }
        )
        retained_model_eras = sorted(
            {row["model_era"] for row in [*episode_rows, *turn_findings, *topic_rows]}
            or {self._projection.UNKNOWN_MODEL_ERA}
        )
        run_state = {
            "coverage": {
                "context_only_turn_count": context_only_count,
                "coverage_complete": coverage_complete,
                "extraction_accepted_turn_count": (
                    len(meaningful_turn_refs)
                    + context_only_count
                    + meaningfulness_gap_count
                ),
                "extraction_gap_count": sum(
                    gap["stage"] == RunStage.EXTRACTION.value for gap in state["gaps"]
                ),
                "gaps": copy.deepcopy(state["gaps"]),
                "meaningful_episode_count": sum(
                    row["review_disposition"] != "review_not_required"
                    for row in episode_rows
                ),
                "meaningful_turn_count": len(meaningful_turn_refs),
                "meaningful_turn_refs": sorted(meaningful_turn_refs),
                "meaningfulness_gap_count": meaningfulness_gap_count,
                "source_units": {
                    "consumed_candidate": accounting["consumed_candidate"],
                    "expected": source_expected,
                    "explicit_gap": accounting["explicit_gap"],
                    "structurally_excluded": accounting["structurally_excluded"],
                },
            },
            "default_model_era": execution_model_era,
            "default_policy_era": policy_era,
            "durable_state": self._publication_durable_state(state),
            "model_eras": retained_model_eras,
            "mode": state["mode"],
            "policy_eras": [policy_era],
            "production_configuration_ref": configuration_ref,
            "provenance": retained_provenance,
            "publication_role": "standalone",
            "run_ref": state["run_ref"],
            "window": copy.deepcopy(state["window"]),
        }
        review_data = {
            "episodes": episode_rows,
            "synthesis": _json_copy(dict(synthesis), label="synthesis"),
            "topics": topic_rows,
            "turn_findings": turn_findings,
        }
        state["retained_export"] = self._persist_retained_export_inputs(
            run_state,
            review_data,
        )

    def _publication_durable_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        try:
            expected = authority.history_state_from_projection(
                state["authority"]["history_snapshot"],
                identity=self.identity,
            )
        except (KeyError, TypeError, authority.AuthorityError) as error:
            raise InvalidTransitionError(
                "persisted durable history is invalid"
            ) from error

        cursor_by_host = {
            row["host_ref"]: copy.deepcopy(row) for row in expected.cursor_rows
        }
        for host, cursor in sorted(state["cursors"].items()):
            if cursor["publication_state"] == "not_applicable":
                continue
            host_ref = state["host_refs"][host]
            expected_cursor, expected_backlog, expected_boundary = (
                self._projection._cursor_before(cursor["before"])
            )
            if cursor["publication_state"] == "complete":
                proposed = cursor.get("proposed")
                if not isinstance(proposed, Mapping) or not isinstance(
                    proposed.get("source_snapshot_ref"), str
                ):
                    raise InvalidTransitionError(
                        "complete host cursor lacks a source snapshot"
                    )
                cursor_ref = proposed["source_snapshot_ref"]
                backlog_ref = None
                logical_boundary = proposed["logical_boundary"]
            elif cursor["publication_state"] == "backfill_required":
                cursor_ref = expected_cursor
                backlog_ref = self._ref(
                    RefType.RUN_INPUT,
                    state["run_ref"],
                    host_ref,
                    "publication_backlog",
                )
                logical_boundary = expected_boundary
            else:
                raise InvalidTransitionError("host cursor is not publication-ready")
            existing = cursor_by_host.get(host_ref)
            if existing is not None and (
                existing["cursor_ref"] != expected_cursor
                or existing["backlog_ref"] != expected_backlog
                or existing["logical_boundary"] != expected_boundary
            ):
                raise RunConflictError("run cursor base differs from durable history")
            cursor_by_host[host_ref] = {
                "backlog_ref": backlog_ref,
                "cursor_ref": cursor_ref,
                "host_ref": host_ref,
                "logical_boundary": logical_boundary,
            }

        proposed_heads = self._episode_head_projection(
            state,
            expected.episode_heads,
        )
        snapshots = sorted(
            {
                cell["snapshot_ref"]
                for cells in state["source"]["cells"].values()
                for cell in cells.values()
                if isinstance(cell.get("snapshot_ref"), str)
            }
        )
        return authority.durable_state_manifest(
            expected=expected,
            proposed_cursor_rows=sorted(
                cursor_by_host.values(), key=lambda item: item["host_ref"]
            ),
            proposed_episode_heads=proposed_heads,
            identity=self.identity,
            source_snapshot_refs=snapshots,
            backfill_of=state["lineage"]["backfill_of"],
        )

    def _episode_head_projection(
        self,
        state: Mapping[str, Any],
        current_heads: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        raw_projection = state["lineage"].get("proposed_episode_heads")
        if not isinstance(raw_projection, list):
            raise InvalidTransitionError(
                "run lacks its full proposed episode-head projection"
            )
        projection = [copy.deepcopy(item) for item in raw_projection]
        if projection != sorted(projection, key=lambda item: item["episode_ref"]):
            raise InvalidTransitionError(
                "proposed episode-head projection is not ordered"
            )
        projected_by_ref = {item["episode_ref"]: item for item in projection}
        if len(projected_by_ref) != len(projection):
            raise InvalidTransitionError(
                "proposed episode-head projection contains duplicate anchors"
            )
        current_by_ref = {
            item["episode_ref"]: copy.deepcopy(item) for item in current_heads
        }
        workset_by_ref = {
            item["episode_ref"]: copy.deepcopy(item) for item in state["episodes"]
        }
        if len(workset_by_ref) != len(state["episodes"]):
            raise InvalidTransitionError(
                "episode revision workset contains duplicate anchors"
            )
        for episode_ref, previous in current_by_ref.items():
            proposed = projected_by_ref.get(episode_ref)
            if proposed is None:
                raise RunConflictError(
                    "proposed episode-head projection removes a durable head"
                )
            if proposed["episode_revision_ref"] == previous["episode_revision_ref"]:
                if episode_ref in workset_by_ref:
                    raise InvalidTransitionError(
                        "unchanged durable head leaked into the revision workset"
                    )
                continue
            if (
                proposed["revision_ordinal"] != previous["revision_ordinal"] + 1
                or proposed["supersedes_episode_revision_ref"]
                != previous["episode_revision_ref"]
                or workset_by_ref.get(episode_ref) != proposed
            ):
                raise RunConflictError(
                    "proposed episode does not append its durable predecessor"
                )
        for episode_ref, proposed in projected_by_ref.items():
            if (
                episode_ref not in current_by_ref
                and workset_by_ref.get(episode_ref) != proposed
            ):
                raise RunConflictError(
                    "new proposed episode is absent from the revision workset"
                )
        if set(workset_by_ref) != {
            episode_ref
            for episode_ref, proposed in projected_by_ref.items()
            if episode_ref not in current_by_ref
            or proposed["episode_revision_ref"]
            != current_by_ref[episode_ref]["episode_revision_ref"]
        }:
            raise InvalidTransitionError(
                "episode revision workset differs from the durable projection delta"
            )
        proposed_ref = authority.derive_episode_head_root(
            projection,
            identity=self.identity,
        )
        if proposed_ref != state["lineage"].get("proposed_episode_head_set_ref"):
            raise InvalidTransitionError(
                "proposed episode-head root does not match its full projection"
            )
        return projection
