"""Read-only state queries, metrics, references, and public status views."""

from __future__ import annotations
from collections import Counter
import copy
import datetime as dt
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence
from . import (
    catalog,
    controlled_gaps,
    result_validation,
    sharding,
    transport as source_transport,
)
from .checkpoints import CheckpointSnapshot, content_digest
from .contracts import (
    MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
    RunMode,
    RunStage,
    SourceCellStatus,
    SourceKind,
)
from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_protocols import ProjectionStatePort

from .orchestrator_support import (
    InvalidInputError,
    InvalidTransitionError,
    PUBLISHER_FINGERPRINT,
    RAW_INPUT_DIRECTORY,
    RunConflictError,
    _NON_GAP_SOURCE_TERMINAL,
    _OPAQUE_REF_RE,
    _SAFE_ERA_RE,
    _SOURCE_TERMINAL,
    _normalize_timestamp,
    _parse_timestamp,
    publisher_readiness,
)


class StateProjectionOperations(OrchestratorComponent):
    UNKNOWN_MODEL_ERA = "unknown_model_era"
    MIXED_MODEL_ERA = "mixed_model_era"

    def __init__(
        self,
        context: RuntimeContext,
        *,
        state: ProjectionStatePort,
    ) -> None:
        super().__init__(context)
        self._state = state

    def _empty_synthesis_result(self, state: Mapping[str, Any]) -> dict[str, Any]:
        allowed_refs = self._collect_refs(state.get("episodes", []))
        del allowed_refs
        result = {
            "confidence": {
                "comparability": "high",
                "coverage": "high" if not state["gaps"] else "low",
                "extraction": "high",
                "review": "high",
            },
            "era_comparison": {"change": "unavailable", "status": "unavailable"},
            "events": [],
            "evidence_refs": [],
            "findings": [],
            "follow_up_actions": [],
            "guidance_candidates": [],
            "prompt_rewrites": [],
            "question_answers": [
                {
                    "confidence": "high",
                    "disposition": "not_observed",
                    "event_kinds": [],
                    "evidence_refs": [],
                    "finding_kinds": [],
                    "question_id": question_id,
                    "strength_kinds": [],
                }
                for question_id in result_validation.QUESTION_IDS
            ],
            "schema": result_validation.SYNTHESIS_RESULT_SCHEMA,
            "signal_commitments": result_validation.build_synthesis_signal_commitments(
                ()
            ),
            "skill_candidates": [],
            "strengths": [],
            "topic_result_hashes": [],
        }
        return result_validation.validate_synthesis_result(
            result,
            set(),
            topic_results=(),
        )

    @staticmethod
    def _signal_counts(values: Iterable[Mapping[str, Any]]) -> dict[str, int]:
        return dict(Counter(item["kind"] for item in values))

    def _episode_turn_payloads(
        self,
        state: dict[str, Any],
        turn_refs: Sequence[str],
        *,
        episode_revision_ref: str,
    ) -> list[dict[str, Any]] | None:
        wanted = set(turn_refs)
        extracted = state.get("extracted_turns", {})
        result = [
            copy.deepcopy(turn)
            for turn_ref, turn in extracted.items()
            if turn_ref in wanted
        ]
        available = {turn["turn_ref"] for turn in result}
        missing = sorted(wanted - available)
        if missing:
            self._state._append_gap(
                state,
                dependency_ref=episode_revision_ref,
                reason="episode_turn_material_missing",
                stage=RunStage.EPISODE_REVIEW.value,
                repairable=True,
                typed_gap={
                    "episode_revision_ref": episode_revision_ref,
                    "kind": "episode_turn_material_gap",
                    "missing_turn_count": str(len(missing)),
                    "missing_turn_refs_commitment": content_digest(missing),
                },
            )
            self._state._block(state, "episode_turn_material_missing")
            return None
        return sorted(result, key=lambda item: item["turn_ref"])

    def _review_task(
        self,
        state: Mapping[str, Any],
        revision_ref: str,
        kind: str,
    ) -> dict[str, Any] | None:
        matches = [
            task
            for task in self._tasks_for_stage(state, RunStage.EPISODE_REVIEW.value)
            if task["job_kind"] == kind and task["partition_ref"] == revision_ref
        ]
        if len(matches) > 1:
            raise RunConflictError("duplicate review task")
        return matches[0] if matches else None

    @staticmethod
    def _review_plan_result(
        task: Mapping[str, Any] | None,
    ) -> dict[str, Any] | None:
        if task is None:
            return None
        if task.get("status") == "accepted":
            result = task.get("result")
            return result if isinstance(result, dict) else None
        gaps = task.get("validated_gap_results", [])
        if isinstance(gaps, list) and gaps and isinstance(gaps[-1], dict):
            return gaps[-1]
        return None

    @staticmethod
    def _is_completed_episode_review(result: Any) -> bool:
        return (
            isinstance(result, Mapping)
            and result.get("schema") == result_validation.EPISODE_REVIEW_RESULT_SCHEMA
            and result.get("disposition") == "reviewed"
        )

    @classmethod
    def _is_resolved_review(cls, result: Any) -> bool:
        if cls._is_completed_episode_review(result):
            return True
        return (
            isinstance(result, Mapping)
            and result.get("schema") == result_validation.ADJUDICATION_RESULT_SCHEMA
            and result.get("resolution")
            in {
                "merged_supported",
                "primary_supported",
                "secondary_supported",
            }
        )

    @staticmethod
    def _tasks_for_stage(state: Mapping[str, Any], stage: str) -> list[dict[str, Any]]:
        return sorted(
            [
                job
                for job in state["jobs"].values()
                if job.get("category") == "agent" and job.get("stage") == stage
            ],
            key=lambda task: task["task_ref"],
        )

    def _task_for_active_job(
        self,
        state: Mapping[str, Any],
        job_ref: str,
    ) -> dict[str, Any]:
        matches = [
            task
            for task in state["jobs"].values()
            if task.get("category") == "agent" and task.get("active_job_ref") == job_ref
        ]
        if len(matches) != 1:
            raise InvalidInputError("unknown or inactive agent job_ref")
        return matches[0]

    @staticmethod
    def _active_attempt(
        task: Mapping[str, Any],
        attempt_ref: str,
    ) -> dict[str, Any]:
        matches = [
            item for item in task["attempts"] if item.get("attempt_ref") == attempt_ref
        ]
        if len(matches) != 1 or matches[0].get("status") != "runnable":
            raise InvalidTransitionError("agent attempt is not runnable")
        return matches[0]

    @staticmethod
    def _restore_shard_manifest(value: Mapping[str, Any]) -> sharding.ShardManifest:
        ranges: list[sharding.RawRangeDescriptor] = []
        for item in value["ranges"]:
            coordinate = catalog.StableSourceCoordinate.from_dict(item["coordinate"])
            range_value = item["range"]
            ranges.append(
                sharding.RawRangeDescriptor(
                    unit_ref=item["unit_ref"],
                    source_kind=item["source_kind"],
                    coordinate=coordinate,
                    range_start=range_value["start"],
                    range_end=range_value["end"],
                    fragment_index=item["fragment_index"],
                    fragment_count=item["fragment_count"],
                    payload_offset=item["payload_offset"],
                    payload_length=item["payload_length"],
                    fragment_commitment=item["fragment_commitment"],
                    record_commitment=item["record_commitment"],
                    event_time=item["event_time"],
                    turn_count=item["turn_count"],
                )
            )
        return sharding.ShardManifest(
            schema_version=value["schema_version"],
            ordinal=value["ordinal"],
            shard_ref=value["shard_ref"],
            file_name=value["file_name"],
            content_sha256=value["content_sha256"],
            byte_count=value["byte_count"],
            raw_byte_count=value["raw_byte_count"],
            turn_count=value["turn_count"],
            ranges=tuple(ranges),
        )

    @staticmethod
    def _shard_limits_from_state(
        state: Mapping[str, Any],
    ) -> sharding.ShardLimits:
        value = state.get("shard_limits")
        if not isinstance(value, Mapping) or set(value) != {
            "max_bytes",
            "max_turns",
            "record_processing_budget",
        }:
            raise InvalidTransitionError("checkpoint shard limits are invalid")
        try:
            limits = sharding.ShardLimits(
                max_bytes=value["max_bytes"],
                max_turns=value["max_turns"],
                record_processing_budget=value["record_processing_budget"],
            )
        except (TypeError, ValueError, sharding.ShardingValidationError) as error:
            raise InvalidTransitionError(
                "checkpoint shard limits are invalid"
            ) from error
        if limits.record_processing_budget < MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES:
            raise InvalidTransitionError("checkpoint shard limits are below protocol")
        return limits

    def _partial_can_continue(self, state: Mapping[str, Any]) -> bool:
        if (
            state["mode"] != RunMode.DAILY.value
            or not state["partial_policy"]["allow_partial"]
        ):
            return False
        complete_host_exists = any(
            all(cell["status"] in _NON_GAP_SOURCE_TERMINAL for cell in cells.values())
            for cells in state["source"]["cells"].values()
        )
        if not complete_host_exists:
            return False
        controlled_by_host_ref: dict[str, controlled_gaps.ControlledGapReceipt] = {}
        for host, cells in state["source"]["cells"].items():
            if not any(
                cell["status"] == SourceCellStatus.GAP.value for cell in cells.values()
            ):
                continue
            if not all(
                cell["status"] == SourceCellStatus.GAP.value for cell in cells.values()
            ):
                return False
            raw_receipt = state.get("controlled_holdouts", {}).get(host)
            if not isinstance(raw_receipt, Mapping):
                return False
            try:
                receipt = controlled_gaps.verify_controlled_gap_receipt(
                    self.identity,
                    raw_receipt,
                )
            except controlled_gaps.ControlledGapError:
                return False
            source_receipts = tuple(
                sorted(cell["transport_receipt_ref"] for cell in cells.values())
            )
            reasons = {
                cell["manifest"]["enumeration_gap"]["reason"]
                for cell in cells.values()
                if isinstance(cell.get("manifest"), Mapping)
                and isinstance(cell["manifest"].get("enumeration_gap"), Mapping)
            }
            if (
                receipt.run_ref != state["run_ref"]
                or receipt.host != host
                or receipt.host_ref != state["host_refs"][host]
                or receipt.window_start != state["window"]["start"]
                or receipt.window_end != state["window"]["end"]
                or receipt.source_receipt_refs != source_receipts
                or reasons != {receipt.reason.value}
            ):
                return False
            controlled_by_host_ref[receipt.host_ref] = receipt
        for gap in state["gaps"]:
            receipt = controlled_by_host_ref.get(gap.get("host_ref"))
            if (
                receipt is None
                or gap.get("reason") != receipt.reason.value
                or gap.get("stage") != RunStage.SHARDING.value
                or gap.get("source_kind")
                not in {source_kind.value for source_kind in receipt.source_kinds}
            ):
                return False
        return True

    @staticmethod
    def _source_has_gaps(state: Mapping[str, Any]) -> bool:
        return any(
            cell["status"] == SourceCellStatus.GAP.value
            for cells in state["source"]["cells"].values()
            for cell in cells.values()
        )

    def _is_verified_no_activity(self, state: Mapping[str, Any]) -> bool:
        cells = self._all_cells(state)
        return (
            bool(cells)
            and all(
                cell["status"]
                in {
                    SourceCellStatus.NO_ACTIVITY.value,
                    SourceCellStatus.VERIFIED_ABSENT.value,
                }
                for cell in cells
            )
            and state["metrics"].get("discovered_source_units", 0) == 0
            and not state["source"]["shards"]
            and not state["gaps"]
        )

    @staticmethod
    def _all_cells(state: Mapping[str, Any]) -> list[dict[str, Any]]:
        return [
            cell
            for cells in state["source"]["cells"].values()
            for cell in cells.values()
        ]

    @staticmethod
    def _stage_has_gaps(state: Mapping[str, Any], stage: str) -> bool:
        return any(gap.get("stage") == stage for gap in state.get("gaps", [])) or any(
            task["status"] == "gap"
            for task in StateProjectionOperations._tasks_for_stage(state, stage)
        )

    @staticmethod
    def _stage_has_runnable_task(state: Mapping[str, Any], stage: str) -> bool:
        if stage == RunStage.SOURCE_CATALOG.value:
            return any(
                job.get("category") == "source" and job.get("status") == "runnable"
                for job in state["jobs"].values()
            )
        return any(
            task["status"] == "runnable"
            for task in StateProjectionOperations._tasks_for_stage(state, stage)
        )

    @staticmethod
    def _validate_external_ref(value: Any, prefix: str) -> str:
        if (
            not isinstance(value, str)
            or re.fullmatch(
                rf"{re.escape(prefix)}_ref_v2:[0-9a-f]{{64}}",
                value,
            )
            is None
        ):
            raise InvalidInputError(f"expected a {prefix}_ref_v2 reference")
        return value

    @staticmethod
    def _is_external_ref(value: Any, prefix: str) -> bool:
        return (
            isinstance(value, str)
            and re.fullmatch(
                rf"{re.escape(prefix)}_ref_v2:[0-9a-f]{{64}}",
                value,
            )
            is not None
        )

    @staticmethod
    def _collect_refs(value: Any) -> set[str]:
        refs: set[str] = set()
        if isinstance(value, str):
            if _OPAQUE_REF_RE.fullmatch(value):
                refs.add(value)
        elif isinstance(value, Mapping):
            for item in value.values():
                refs.update(StateProjectionOperations._collect_refs(item))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for item in value:
                refs.update(StateProjectionOperations._collect_refs(item))
        return refs

    @staticmethod
    def _policy_token(
        state: Mapping[str, Any],
        name: str,
        fallback: str,
    ) -> str:
        versions = state["provenance"].get("versions", {})
        value = versions.get(name) if isinstance(versions, Mapping) else None
        return StateProjectionOperations._era_token(value, fallback)

    @staticmethod
    def _version_token(
        state: Mapping[str, Any],
        name: str,
        fallback: str,
    ) -> str:
        if name == "prompt":
            prompt = state["provenance"].get("prompt", {})
            value = prompt.get("version") if isinstance(prompt, Mapping) else None
        else:
            versions = state["provenance"].get("versions", {})
            value = versions.get(name) if isinstance(versions, Mapping) else None
        return StateProjectionOperations._era_token(value, fallback)

    @staticmethod
    def _era_token(value: Any, fallback: str) -> str:
        if isinstance(value, str):
            normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
            if _SAFE_ERA_RE.fullmatch(normalized):
                return normalized
        return fallback

    @staticmethod
    def _model_era(state: Mapping[str, Any]) -> str:
        model = state["provenance"].get("model", {})
        if isinstance(model, Mapping):
            selected = model.get("model")
        else:
            selected = model
        return StateProjectionOperations._era_token(selected, "unspecified")

    @staticmethod
    def _source_model_era(record: Mapping[str, Any]) -> str | None:
        candidates: set[str] = set()
        nodes: list[tuple[Mapping[str, Any], int]] = [(record, 0)]
        visited = 0
        while nodes:
            node, depth = nodes.pop()
            visited += 1
            if visited > 4096 or depth > 16:
                raise ValueError("source model evidence structure exceeds bounds")
            for key in ("model", "model_name", "model_slug"):
                value = node.get(key)
                if isinstance(value, str):
                    era = StateProjectionOperations._era_token(value, "")
                    if era:
                        candidates.add(era)
            for child in node.values():
                if isinstance(child, Mapping):
                    nodes.append((child, depth + 1))
        if not candidates:
            return None
        if len(candidates) > 1:
            return StateProjectionOperations.MIXED_MODEL_ERA
        return next(iter(candidates))

    @classmethod
    def _retained_model_era_for_turn(
        cls,
        state: Mapping[str, Any],
        turn_ref: str,
    ) -> str:
        source = state.get("source", {})
        reassembly = source.get("reassembly", {}) if isinstance(source, Mapping) else {}
        metadata = reassembly.get(turn_ref) if isinstance(reassembly, Mapping) else None
        value = metadata.get("model_era") if isinstance(metadata, Mapping) else None
        if isinstance(value, str) and _SAFE_ERA_RE.fullmatch(value):
            return value
        return cls.UNKNOWN_MODEL_ERA

    @classmethod
    def _retained_model_era_for_turns(
        cls,
        state: Mapping[str, Any],
        turn_refs: Sequence[str],
    ) -> str:
        eras = {cls._retained_model_era_for_turn(state, ref) for ref in turn_refs}
        if not eras or cls.UNKNOWN_MODEL_ERA in eras:
            return cls.UNKNOWN_MODEL_ERA
        if len(eras) != 1 or cls.MIXED_MODEL_ERA in eras:
            return cls.MIXED_MODEL_ERA
        return next(iter(eras))

    @staticmethod
    def _execution_contract(state: Mapping[str, Any]) -> dict[str, Any]:
        provenance = state.get("provenance")
        if not isinstance(provenance, Mapping):
            raise InvalidTransitionError("run execution provenance is missing")
        configuration_root = provenance.get("configuration_root")
        contract = {
            key: copy.deepcopy(value)
            for key, value in provenance.items()
            if key != "configuration_root"
        }
        if (
            not isinstance(configuration_root, str)
            or content_digest(contract) != configuration_root
        ):
            raise InvalidTransitionError("run execution provenance changed")
        return contract

    def _safe_coverage_payload(self, state: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "accounting": copy.deepcopy(state["metrics"].get("accounting", {})),
            "coverage_status": state["coverage"]["status"],
            "gap_refs": [gap["gap_ref"] for gap in state["gaps"]],
            "host_states": {
                state["host_refs"][host]: state["cursors"][host]["publication_state"]
                for host in state["host_refs"]
            },
        }

    def _status_view(self, snapshot: CheckpointSnapshot) -> dict[str, Any]:
        state = snapshot.state
        self._state._assert_state_identity(state)
        publisher = publisher_readiness()
        now = _parse_timestamp(self._state._now(), label="clock")
        runnable_jobs: list[dict[str, Any]] = []
        retryable_jobs: list[dict[str, Any]] = []
        blocked_jobs: list[dict[str, Any]] = []
        source_manifests: list[dict[str, Any]] = []
        for job in sorted(
            state["jobs"].values(),
            key=lambda item: item.get("task_ref", item.get("job_ref", "")),
        ):
            if job["category"] == "source":
                if job["status"] == "runnable":
                    runnable_jobs.append(self._public_source_job(job))
                continue
            public = self._public_agent_task(job, now=now)
            if job["status"] == "runnable":
                runnable_jobs.append(public)
            elif job["status"] == "retryable":
                retryable_jobs.append(public)
            elif job["status"] == "gap":
                blocked_jobs.append(public)
        for host, cells in state["source"]["cells"].items():
            for source_kind, cell in cells.items():
                if cell.get("manifest") is None:
                    continue
                source_manifests.append(
                    {
                        "host_ref": state["host_refs"][host],
                        "record_count": cell["metrics"]["record_count"],
                        "snapshot_ref": cell["snapshot_ref"],
                        "source_kind": source_kind,
                        "status": cell["status"],
                    }
                )
        source_coverage = {
            host: {
                "cells": {
                    source_kind: self._public_source_cell(cell)
                    for source_kind, cell in cells.items()
                },
                "host_ref": state["host_refs"][host],
                "publication_state": state["cursors"][host]["publication_state"],
                "status": self._host_coverage_status(cells),
            }
            for host, cells in state["source"]["cells"].items()
        }
        deadlines = copy.deepcopy(state["deadlines"])
        deadlines["raw_expired"] = now >= _parse_timestamp(
            deadlines["raw"], label="raw deadline"
        )
        deadlines["working_expired"] = now >= _parse_timestamp(
            deadlines["working"], label="working deadline"
        )
        return {
            "accepted_source_manifests": sorted(
                source_manifests,
                key=lambda item: (item["host_ref"], item["source_kind"]),
            ),
            "active_source_leases": [
                job for job in runnable_jobs if job["category"] == "source"
            ],
            "blocked_jobs": blocked_jobs,
            "blocked_reason": state["blocked_reason"],
            "catalog": self._public_catalog(state),
            "checkpoint_revision": snapshot.revision,
            "coverage": {
                **copy.deepcopy(state["coverage"]),
                "hosts": source_coverage,
            },
            "cursors": copy.deepcopy(state["cursors"]),
            "deadlines": deadlines,
            "gaps": copy.deepcopy(state["gaps"]),
            "identity_key_id": state["identity_key_id"],
            "lineage": copy.deepcopy(state["lineage"]),
            "metrics": self._metrics_view(state),
            "mode": state["mode"],
            "next_actions": self._next_actions(
                state,
                runnable_jobs,
                retryable_jobs,
            ),
            "partial_policy": copy.deepcopy(state["partial_policy"]),
            "provenance": copy.deepcopy(state["provenance"]),
            "publication": copy.deepcopy(state["publication"]),
            "publisher": {
                "fingerprint": PUBLISHER_FINGERPRINT,
                "ready": publisher.get("ready") is True
                and publisher.get("fingerprint") == PUBLISHER_FINGERPRINT,
            },
            "retryable_jobs": retryable_jobs,
            "run_ref": state["run_ref"],
            "runnable_jobs": runnable_jobs,
            "schema_version": state["schema_version"],
            "session_target": state["session_target"],
            "shadow": state.get("shadow", False),
            "stage": state["stage"],
            "stage_history": copy.deepcopy(state["stage_history"]),
            "window": copy.deepcopy(state["window"]),
        }

    def _public_source_job(self, job: Mapping[str, Any]) -> dict[str, Any]:
        lease = source_transport.TransportLease.from_dict(job["transport_lease"])
        artifact_dir = (
            self.run_dir
            / RAW_INPUT_DIRECTORY
            / "source-preparations"
            / lease.lease_ref.replace(":", "-")
        )
        stream_path = artifact_dir / "source-transport.jsonl"
        cli_path = Path(__file__).resolve().parents[1] / "session_retrospective_v2.py"
        identity_arguments = (
            []
            if self.identity.path is None
            else [
                "--identity-path",
                str(self.identity.path),
                "--require-existing-identity",
            ]
        )
        source_contract = (
            "bounded_metadata_jsonl_v2"
            if lease.source_kind in {SourceKind.SESSION_INDEX, SourceKind.HISTORY}
            else "bounded_rollout_jsonl_v2"
        )
        return {
            "category": "source",
            "host": job["host"],
            "host_ref": job["host_ref"],
            "job_kind": job["job_kind"],
            "job_ref": job["job_ref"],
            "lease_ref": job["lease_ref"],
            "source_kind": job["source_kind"],
            "stage": job["stage"],
            "status": job["status"],
            "source_contract": source_contract,
            "transport_contract": source_transport.TRANSPORT_LEASE_SCHEMA,
            "transport_lease": lease.to_dict(),
            "native_subagent_instruction": (
                "Capture source_transport_command stdout at source_transport_output, "
                "then run the accept-source coordinator action."
            ),
            "native_coordinator_actions": [
                {
                    "action": "capture-source-transport",
                    "command": list(lease.command_argv),
                    "stdout_path": str(stream_path),
                },
                {
                    "action": "accept-source",
                    "command": [
                        sys.executable,
                        str(cli_path),
                        "accept-source",
                        "--run-dir",
                        str(self.run_dir),
                        "--lease-ref",
                        lease.lease_ref,
                        "--transport-stream-file",
                        str(stream_path),
                        *identity_arguments,
                    ],
                },
            ],
            "source_transport_command": list(lease.command_argv),
            "source_transport_output": str(stream_path),
            "coordinator_cwd_contract": "run_directory",
            "window": copy.deepcopy(job["window"]),
        }

    def _public_agent_task(
        self,
        task: Mapping[str, Any],
        *,
        now: dt.datetime | None = None,
    ) -> dict[str, Any]:
        if now is None:
            now = _parse_timestamp(self._state._now(), label="clock")
        active = None
        if task.get("active_attempt_ref") is not None:
            active = next(
                item
                for item in task["attempts"]
                if item["attempt_ref"] == task["active_attempt_ref"]
            )
        result: dict[str, Any] = {
            "active_attempt_ref": task.get("active_attempt_ref"),
            "allowed_output_refs": copy.deepcopy(task["allowed_refs"]),
            "category": "agent",
            "input_payload": copy.deepcopy(task.get("input_payload")),
            "job_kind": task["job_kind"],
            "job_ref": task.get("active_job_ref"),
            "retry_ordinal": max(0, len(task["attempts"]) - 1),
            "stage": task["stage"],
            "status": task["status"],
            "task_ref": task["task_ref"],
        }
        if active is not None:
            result.update(
                {
                    "dispatch_state": active["dispatch_state"],
                    "envelope_digest": active.get(
                        "envelope_digest", active["base_envelope_digest"]
                    ),
                    "envelope_size": active.get(
                        "envelope_size", active["base_envelope_size"]
                    ),
                    "reviewer_ref": active.get("reviewer_ref"),
                }
            )
            if active["dispatch_state"] == "claimed":
                result.update(
                    {
                        "claim_expires_at": active["claim_expires_at"],
                        "claim_expired": self._claim_is_expired(active, now),
                        "claim_generation": active["claim_generation"],
                        "claim_heartbeat_at": active["claim_heartbeat_at"],
                        "claim_ref": active["claim_ref"],
                        "dispatcher_ref": active["dispatcher_ref"],
                        "output_sink": active["output_sink"],
                        "result_ref": active["result_ref"],
                    }
                )
        return result

    @staticmethod
    def _public_source_cell(cell: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: copy.deepcopy(cell[key])
            for key in (
                "lease_ref",
                "metrics",
                "snapshot_ref",
                "status",
                "transport_receipt_ref",
            )
        }

    @staticmethod
    def _host_coverage_status(cells: Mapping[str, Mapping[str, Any]]) -> str:
        statuses = [cell["status"] for cell in cells.values()]
        if any(status == SourceCellStatus.GAP.value for status in statuses):
            return SourceCellStatus.GAP.value
        if any(status not in _SOURCE_TERMINAL for status in statuses):
            return "pending"
        if all(
            status
            in {
                SourceCellStatus.NO_ACTIVITY.value,
                SourceCellStatus.VERIFIED_ABSENT.value,
            }
            for status in statuses
        ):
            return SourceCellStatus.NO_ACTIVITY.value
        return SourceCellStatus.COMPLETE.value

    @staticmethod
    def _public_catalog(state: Mapping[str, Any]) -> dict[str, Any] | None:
        value = state["source"].get("catalog")
        if not isinstance(value, Mapping):
            return None
        return {
            "accounting_counts": copy.deepcopy(value["accounting_counts"]),
            "catalog_digest": content_digest(value),
            "manifest_count": len(value["manifests"]),
            "schema_version": value["schema_version"],
        }

    def _metrics_view(self, state: Mapping[str, Any]) -> dict[str, Any]:
        cells = self._all_cells(state)
        agent_tasks = [
            job for job in state["jobs"].values() if job.get("category") == "agent"
        ]
        non_gap_terminal = sum(
            cell["status"] in _NON_GAP_SOURCE_TERMINAL for cell in cells
        )
        total_cells = len(cells)
        return {
            **copy.deepcopy(state["metrics"]),
            "agent_jobs_accepted": sum(
                task["status"] == "accepted" for task in agent_tasks
            ),
            "agent_jobs_gap": sum(task["status"] == "gap" for task in agent_tasks),
            "agent_jobs_total": len(agent_tasks),
            "coverage_percent": (
                round((non_gap_terminal / total_cells) * 100.0, 2)
                if total_cells
                else 100.0
            ),
            "gaps_total": len(state["gaps"]),
            "source_cells_gap": sum(
                cell["status"] == SourceCellStatus.GAP.value for cell in cells
            ),
            "source_cells_terminal": sum(
                cell["status"] in _SOURCE_TERMINAL for cell in cells
            ),
            "source_cells_total": total_cells,
        }

    @staticmethod
    def _next_actions(
        state: Mapping[str, Any],
        runnable_jobs: Sequence[Mapping[str, Any]],
        retryable_jobs: Sequence[Mapping[str, Any]],
    ) -> list[str]:
        if state["stage"] == RunStage.BLOCKED.value:
            return ["inspect-gaps"]
        if state["stage"] == RunStage.COMPLETE.value:
            return []
        if state["stage"] == RunStage.EXPORT.value:
            return ["finalize"] if state["publication"]["exported_at"] else ["export"]
        actions: list[str] = []
        if any(job["category"] == "source" for job in runnable_jobs):
            actions.extend(("capture-source-transport", "accept-source"))
        if any(job["category"] == "agent" for job in runnable_jobs):
            actions.append("spawn-native-subagents")
            actions.append("accept-agent-result")
        if retryable_jobs or not runnable_jobs:
            actions.append("advance")
        return actions

    @staticmethod
    def _cursor_before(
        value: Any,
    ) -> tuple[str | None, str | None, str | None]:
        if value is None:
            return None, None, None
        if isinstance(value, str):
            raise InvalidTransitionError(
                "starting cursor state lacks its logical boundary"
            )
        if not isinstance(value, Mapping) or set(value) != {
            "backlog_head",
            "cursor",
            "logical_boundary",
        }:
            raise InvalidTransitionError("starting cursor state is invalid")
        cursor = value["cursor"]
        backlog = value["backlog_head"]
        boundary = value["logical_boundary"]
        if (cursor is not None and not isinstance(cursor, str)) or (
            backlog is not None and not isinstance(backlog, str)
        ):
            raise InvalidTransitionError("starting cursor state is invalid")
        if (cursor is None) != (boundary is None):
            raise InvalidTransitionError("starting cursor boundary is invalid")
        if boundary is not None:
            boundary = _normalize_timestamp(boundary, label="starting cursor boundary")
        return cursor, backlog, boundary

    @staticmethod
    def _claim_is_expired(
        attempt: Mapping[str, Any],
        now: dt.datetime,
    ) -> bool:
        expires_at = attempt.get("claim_expires_at")
        if not isinstance(expires_at, str):
            raise InvalidTransitionError("claimed agent attempt lacks lease expiry")
        return now >= _parse_timestamp(expires_at, label="agent claim expiry")
