"""Deterministic stage transitions and bounded job scheduling."""

from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import sys
from typing import Any, Mapping
from . import catalog, controlled_gaps, safe_io, transport as source_transport
from .checkpoints import CheckpointNotFoundError, canonical_json_bytes
from .contracts import (
    ControlledGapReason,
    RefType,
    RunMode,
    RunStage,
    SourceCellStatus,
    SourceKind,
)
from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_protocols import (
    SchedulerHistoryPort,
    SchedulerJobsPort,
    SchedulerLifecyclePort,
    SchedulerProjectionPort,
    SchedulerReductionPort,
    SchedulerSourcePort,
    SchedulerStatePort,
)

from .orchestrator_support import (
    InvalidInputError,
    InvalidTransitionError,
    RAW_INPUT_DIRECTORY,
    REQUIRED_SOURCE_KINDS,
    RunConflictError,
    RunNotStartedError,
    SOURCE_TRANSPORT_MAX_FRAME_BYTES,
    SOURCE_TRANSPORT_MAX_RECORDS,
    _SOURCE_TERMINAL,
    _STAGE_SEQUENCE,
    _TASK_TERMINAL,
    _parse_timestamp,
)


class StageSchedulingOperations(OrchestratorComponent):
    def __init__(
        self,
        context: RuntimeContext,
        *,
        state: SchedulerStatePort,
        projection: SchedulerProjectionPort,
        jobs: SchedulerJobsPort,
        reduction: SchedulerReductionPort,
        history: SchedulerHistoryPort,
        source: SchedulerSourcePort,
        lifecycle: SchedulerLifecyclePort,
    ) -> None:
        super().__init__(context)
        self._state = state
        self._projection = projection
        self._jobs = jobs
        self._reduction = reduction
        self._history = history
        self._source = source
        self._lifecycle = lifecycle

    def advance(self) -> dict[str, Any]:
        self._lifecycle.gc_expired_raw()

        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            if state["stage"] in {RunStage.COMPLETE.value, RunStage.BLOCKED.value}:
                return state, {"advanced": False, "reason": "terminal_stage"}
            if self._state._retention_expired(state):
                self._state._append_gap(
                    state,
                    dependency_ref=state["run_ref"],
                    reason="retention_window_expired",
                    stage=state["stage"],
                    repairable=True,
                )
                self._state._block(state, "retention_window_expired")
                return state, {"advanced": True, "reason": "retention_window_expired"}
            if state["stage"] == RunStage.EXPORT.value:
                return state, {"advanced": False, "reason": "awaiting_publication"}

            scheduled: list[str] = []
            advanced = False
            reason = "stable_checkpoint"
            for _ in range(len(_STAGE_SEQUENCE) + 4):
                stage = state["stage"]
                if stage == RunStage.SOURCE_CATALOG.value:
                    step = self._advance_source_catalog(state)
                elif stage == RunStage.SHARDING.value:
                    step = self._advance_sharding(state)
                elif stage == RunStage.EXTRACTION.value:
                    step = self._advance_extraction(state)
                elif stage == RunStage.EPISODE_REVIEW.value:
                    step = self._advance_episode_review(state)
                elif stage == RunStage.TOPIC_REDUCTION.value:
                    step = self._advance_topic_reduction(state)
                elif stage == RunStage.GLOBAL_SYNTHESIS.value:
                    step = self._advance_synthesis(state)
                else:
                    raise InvalidTransitionError(f"cannot advance stage {stage!r}")
                advanced = advanced or bool(step["advanced"])
                reason = step["reason"]
                scheduled.extend(step.get("scheduled", []))
                if not step["advanced"]:
                    break
                if state["stage"] in {
                    RunStage.EXPORT.value,
                    RunStage.BLOCKED.value,
                    RunStage.COMPLETE.value,
                }:
                    break
                if self._projection._stage_has_runnable_task(state, state["stage"]):
                    break
            else:
                raise InvalidTransitionError(
                    "advance did not reach a stable checkpoint"
                )
            result: dict[str, Any] = {"advanced": advanced, "reason": reason}
            if scheduled:
                result["scheduled"] = sorted(set(scheduled))
            return state, result

        try:
            transaction = self.store.transaction(mutate)
        except CheckpointNotFoundError as error:
            raise RunNotStartedError("run has not been started") from error
        response = self._projection._status_view(transaction.snapshot)
        response.update(
            {"action": "advance", "changed": transaction.changed, **transaction.value}
        )
        return response

    def _advance_source_catalog(self, state: dict[str, Any]) -> dict[str, Any]:
        if any(
            job.get("category") == "source" and job.get("status") == "runnable"
            for job in state["jobs"].values()
        ):
            return {"advanced": False, "reason": "source_results_pending"}
        scheduled = self._schedule_source_wave(state)
        if scheduled:
            return {
                "advanced": True,
                "reason": "source_wave_scheduled",
                "scheduled": scheduled,
            }
        cells = self._projection._all_cells(state)
        if any(cell["status"] not in _SOURCE_TERMINAL for cell in cells):
            raise InvalidTransitionError(
                "source catalog has nonterminal cells without leases"
            )
        self._state._transition(state, RunStage.SHARDING)
        return {"advanced": True, "reason": "source_catalog_complete"}

    def _advance_sharding(self, state: dict[str, Any]) -> dict[str, Any]:
        if self._projection._source_has_gaps(
            state
        ) and not self._projection._partial_can_continue(state):
            self._reduction._record_unmaterialized_catalog_metrics(state)
            self._state._block(state, "source_coverage_incomplete")
            return {"advanced": True, "reason": "source_coverage_incomplete"}
        if state["source"]["catalog"] is None:
            self._reduction._freeze_catalog_and_materialize(state)
        self._prepare_cursor_proposals(state)
        if self._projection._source_has_gaps(state):
            state["coverage"]["status"] = "partial"
            state["partial_policy"]["decision"] = "partial"
        else:
            state["coverage"]["status"] = "complete"
            state["partial_policy"]["decision"] = "complete"
        self._state._transition(state, RunStage.EXTRACTION)
        scheduled = self._issue_agent_tasks(state, RunStage.EXTRACTION.value)
        return {
            "advanced": True,
            "reason": "sharding_complete",
            "scheduled": scheduled,
        }

    def _advance_extraction(self, state: dict[str, Any]) -> dict[str, Any]:
        pending = self._pending_agent_stage(state, RunStage.EXTRACTION.value)
        if pending is not None:
            return pending
        if self._projection._stage_has_gaps(
            state, RunStage.EXTRACTION.value
        ) and not self._projection._partial_can_continue(state):
            self._state._block(state, "extraction_incomplete")
            return {"advanced": True, "reason": "extraction_incomplete"}

        if self._projection._is_verified_no_activity(state):
            if state["lineage"]["proposed_episode_head_set_ref"] is None:
                self._reduction._bind_episode_revisions(state, [])
            self._history._build_retained_export(
                state,
                self._projection._empty_synthesis_result(state),
            )
            for stage in (
                RunStage.EPISODE_REVIEW,
                RunStage.TOPIC_REDUCTION,
                RunStage.GLOBAL_SYNTHESIS,
                RunStage.EXPORT,
            ):
                self._state._transition(state, stage)
            return {"advanced": True, "reason": "verified_no_activity"}

        if not state["episodes"]:
            self._reduction._construct_episode_revisions(state)
        if self._projection._stage_has_gaps(
            state, RunStage.EXTRACTION.value
        ) and not self._projection._partial_can_continue(state):
            self._state._block(state, "extraction_incomplete")
            return {"advanced": True, "reason": "extraction_incomplete"}
        if not self._reduction._refresh_review_plan(state):
            return {"advanced": True, "reason": "episode_turn_material_missing"}
        self._state._transition(state, RunStage.EPISODE_REVIEW)
        scheduled = self._issue_agent_tasks(state, RunStage.EPISODE_REVIEW.value)
        return {
            "advanced": True,
            "reason": "extraction_complete",
            "scheduled": scheduled,
        }

    def _advance_episode_review(self, state: dict[str, Any]) -> dict[str, Any]:
        if not self._reduction._refresh_review_plan(state):
            return {"advanced": True, "reason": "episode_turn_material_missing"}
        pending = self._pending_agent_stage(state, RunStage.EPISODE_REVIEW.value)
        if pending is not None:
            return pending
        if not self._reduction._refresh_review_plan(state):
            return {"advanced": True, "reason": "episode_turn_material_missing"}
        if self._projection._stage_has_gaps(state, RunStage.EPISODE_REVIEW.value):
            plan_reasons = {
                plan["blocked_reason"]
                for plan in state["review_plans"].values()
                if plan["review_gaps"] and plan["blocked_reason"] is not None
            }
            reason = (
                next(iter(plan_reasons))
                if len(plan_reasons) == 1
                else "episode_review_incomplete"
            )
            self._state._block(state, reason)
            return {"advanced": True, "reason": reason}
        self._reduction._build_topic_inputs(state)
        self._state._transition(state, RunStage.TOPIC_REDUCTION)
        scheduled = self._issue_agent_tasks(state, RunStage.TOPIC_REDUCTION.value)
        return {
            "advanced": True,
            "reason": "episode_review_complete",
            "scheduled": scheduled,
        }

    def _advance_topic_reduction(self, state: dict[str, Any]) -> dict[str, Any]:
        self._reduction._refresh_topic_hierarchies(state)
        pending = self._pending_agent_stage(state, RunStage.TOPIC_REDUCTION.value)
        if pending is not None:
            return pending
        if self._projection._stage_has_gaps(
            state, RunStage.TOPIC_REDUCTION.value
        ) and not self._projection._partial_can_continue(state):
            self._state._block(state, "topic_reduction_incomplete")
            return {"advanced": True, "reason": "topic_reduction_incomplete"}
        self._reduction._seed_synthesis_task(state)
        self._state._transition(state, RunStage.GLOBAL_SYNTHESIS)
        scheduled = self._issue_agent_tasks(state, RunStage.GLOBAL_SYNTHESIS.value)
        return {
            "advanced": True,
            "reason": "topic_reduction_complete",
            "scheduled": scheduled,
        }

    def _advance_synthesis(self, state: dict[str, Any]) -> dict[str, Any]:
        self._reduction._refresh_synthesis_hierarchy(state)
        pending = self._pending_agent_stage(state, RunStage.GLOBAL_SYNTHESIS.value)
        if pending is not None:
            return pending
        if self._projection._stage_has_gaps(state, RunStage.GLOBAL_SYNTHESIS.value):
            self._state._block(state, "global_synthesis_incomplete")
            return {"advanced": True, "reason": "global_synthesis_incomplete"}
        synthesis_tasks = self._projection._tasks_for_stage(
            state, RunStage.GLOBAL_SYNTHESIS.value
        )
        final_tasks = [
            task
            for task in synthesis_tasks
            if task["metadata"].get("hierarchy_final") is True
            and task["status"] == "accepted"
        ]
        if len(final_tasks) == 1:
            self._history._build_retained_export(state, final_tasks[0]["result"])
        elif final_tasks:
            raise RunConflictError("global synthesis has duplicate final reducers")
        else:
            self._history._build_retained_export(
                state,
                self._projection._empty_synthesis_result(state),
            )
        self._state._transition(state, RunStage.EXPORT)
        return {"advanced": True, "reason": "run_exportable"}

    def _pending_agent_stage(
        self,
        state: dict[str, Any],
        stage: str,
    ) -> dict[str, Any] | None:
        tasks = self._projection._tasks_for_stage(state, stage)
        if any(task["status"] == "runnable" for task in tasks):
            return {"advanced": False, "reason": "agent_results_pending"}
        scheduled = self._issue_agent_tasks(state, stage)
        if scheduled:
            return {
                "advanced": True,
                "reason": "agent_wave_scheduled",
                "scheduled": scheduled,
            }
        if any(task["status"] not in _TASK_TERMINAL for task in tasks):
            raise InvalidTransitionError(
                "agent stage has nonterminal tasks without active attempts"
            )
        return None

    def _schedule_source_wave(self, state: dict[str, Any]) -> list[str]:
        scheduled: list[str] = []
        for host in state["source"]["cells"]:
            active = any(
                job.get("category") == "source"
                and job.get("host") == host
                and job.get("status") == "runnable"
                for job in state["jobs"].values()
            )
            if active:
                continue
            for source_kind in REQUIRED_SOURCE_KINDS:
                cell = state["source"]["cells"][host][source_kind]
                if cell["status"] != "pending":
                    continue
                job_ref = self._ref(
                    RefType.JOB,
                    state["run_ref"],
                    "source_catalog",
                    state["provenance"]["configuration_root"],
                    cell["host_ref"],
                    source_kind,
                    len(cell.get("continuation_segments", [])),
                )
                lease_ref = self._ref(
                    RefType.LEASE,
                    state["run_ref"],
                    job_ref,
                    len(cell.get("continuation_segments", [])),
                )
                process_nonce = self.identity.derive_digest(
                    "source-transport-process/v2",
                    {
                        "job_ref": job_ref,
                        "lease_ref": lease_ref,
                        "run_ref": state["run_ref"],
                    },
                )
                source_cursor, _backlog, cursor_time = self._projection._cursor_before(
                    state["cursors"][host]["before"]
                )
                command_argv = self._source_transport_command(
                    host=host,
                    source_kind=source_kind,
                    window=state["window"],
                    lease_ref=lease_ref,
                    process_nonce=process_nonce,
                    source_cursor=source_cursor,
                    cursor_time=cursor_time,
                    resume_position=cell.get("continuation_position"),
                    session_selector_commitment=state["session_selector_commitment"],
                    remote_helper_source_commitment=state["provenance"]["transport"][
                        "remote_host_context_helper_commitment"
                    ],
                )
                transport_lease = source_transport.issue_transport_lease(
                    self.identity,
                    lease_ref=lease_ref,
                    run_ref=state["run_ref"],
                    job_ref=job_ref,
                    host=host,
                    host_ref=cell["host_ref"],
                    source_kind=source_kind,
                    window_start=state["window"]["start"],
                    window_end=state["window"]["end"],
                    process_nonce=process_nonce,
                    command_argv=command_argv,
                    transport_program_commitment=(
                        source_transport.transport_program_commitment(
                            command_argv,
                            snapshot_cache=(
                                self.run_dir
                                / RAW_INPUT_DIRECTORY
                                / "source-program-snapshots"
                            ),
                        )
                    ),
                    source_byte_limit=self._source_transport_max_source_bytes(),
                    record_limit=SOURCE_TRANSPORT_MAX_RECORDS,
                    frame_byte_limit=SOURCE_TRANSPORT_MAX_FRAME_BYTES,
                    session_target=state["session_target"],
                    session_selector_commitment=state["session_selector_commitment"],
                    source_cursor=source_cursor,
                    cursor_time=cursor_time,
                    resume_position=cell.get("continuation_position"),
                )
                source_transport_output = (
                    self._projection._source_transport_output_path(lease_ref)
                )
                try:
                    safe_io.ensure_owner_only_directory(source_transport_output.parent)
                except (OSError, safe_io.UnsafePathError) as error:
                    raise InvalidTransitionError(
                        "source transport output directory cannot be authenticated"
                    ) from error
                state["jobs"][job_ref] = {
                    "category": "source",
                    "execution_contract": self._projection._execution_contract(state),
                    "host": host,
                    "host_ref": cell["host_ref"],
                    "job_kind": "source_catalog",
                    "job_ref": job_ref,
                    "lease_ref": lease_ref,
                    "shard_limits": copy.deepcopy(state["shard_limits"]),
                    "source_kind": source_kind,
                    "source_transport_output_relative": (
                        source_transport_output.relative_to(self.run_dir).as_posix()
                    ),
                    "stage": RunStage.SOURCE_CATALOG.value,
                    "status": "runnable",
                    "transport_lease": transport_lease.to_dict(),
                    "window": copy.deepcopy(state["window"]),
                }
                cell["lease_ref"] = lease_ref
                cell["status"] = "leased"
                state["metrics"]["source_leases"] += 1
                scheduled.append(job_ref)
                break
        return scheduled

    def _source_transport_command(
        self,
        *,
        host: str,
        source_kind: str,
        window: Mapping[str, Any],
        lease_ref: str,
        process_nonce: str,
        source_cursor: str | None,
        cursor_time: str | None,
        resume_position: Mapping[str, object] | None,
        session_selector_commitment: str | None,
        remote_helper_source_commitment: str,
    ) -> tuple[str, ...]:
        worker = Path(__file__).resolve().with_name("transport_worker.py")
        command = [
            sys.executable,
            *source_transport.source_transport_python_flags(
                self.run_dir / RAW_INPUT_DIRECTORY / "source-program-snapshots"
            ),
            str(worker),
            "source-transport",
            "--host",
            host,
            "--source-kind",
            source_kind,
            "--window-start",
            str(window["start"]),
            "--window-end",
            str(window["end"]),
            "--lease-ref",
            lease_ref,
            "--process-nonce",
            process_nonce,
            "--max-source-bytes",
            str(self._source_transport_max_source_bytes()),
            "--max-records",
            str(SOURCE_TRANSPORT_MAX_RECORDS),
            "--max-frame-bytes",
            str(SOURCE_TRANSPORT_MAX_FRAME_BYTES),
        ]
        if source_cursor is not None:
            command.extend(("--source-cursor", source_cursor))
        if cursor_time is not None:
            command.extend(("--cursor-time", cursor_time))
        if resume_position is not None:
            command.extend(
                (
                    "--resume-position",
                    source_transport.encode_source_resume_position(resume_position),
                )
            )
        if session_selector_commitment is not None:
            command.extend(
                (
                    "--session-selector-commitment",
                    session_selector_commitment,
                )
            )
        if host != "local":
            helper_snapshot, helper_commitment = (
                source_transport.snapshot_remote_host_context_helper(
                    source_transport.remote_host_context_helper_path(),
                    self.run_dir / RAW_INPUT_DIRECTORY / "source-program-snapshots",
                    expected_source_commitment=remote_helper_source_commitment,
                )
            )
            command.extend(
                (
                    "--remote-helper",
                    str(helper_snapshot),
                    "--remote-helper-commitment",
                    helper_commitment,
                )
            )
        return tuple(command)

    def _issue_agent_tasks(self, state: dict[str, Any], stage: str) -> list[str]:
        scheduled: list[str] = []
        for task in self._projection._tasks_for_stage(state, stage):
            if task["status"] not in {"pending", "retryable"}:
                continue
            ordinal = len(task["attempts"])
            if ordinal >= 2:
                raise InvalidTransitionError("fresh-agent retry budget was exhausted")
            job_manifest = self._jobs._execution_manifest(state, task, ordinal)
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
            attempt = {
                "attempt_ref": attempt_ref,
                "claim_expires_at": None,
                "claim_generation": 0,
                "claim_heartbeat_at": None,
                "claim_ref": None,
                "claimed_at": None,
                "dispatch_state": "unclaimed",
                "dispatcher_ref": None,
                "issued_at": self._state._now(),
                "job_manifest": job_manifest,
                "job_ref": job_ref,
                "ordinal": ordinal,
                "reviewer_ref": reviewer_ref,
                "sink_state": "reserved",
                "status": "runnable",
            }
            task["attempts"].append(attempt)
            task["active_attempt_ref"] = attempt_ref
            task["active_job_ref"] = job_ref
            task["status"] = "runnable"
            envelope = self._jobs._agent_envelope(task, attempt)
            envelope_bytes = canonical_json_bytes(envelope)
            if len(envelope_bytes) > self._agent_envelope_limit():
                raise InvalidTransitionError(
                    "issued agent task exceeds the complete 512 KiB envelope"
                )
            envelope_name = (
                hashlib.sha256(attempt_ref.encode("ascii")).hexdigest() + ".json"
            )
            envelope_relative_path = (
                f"{RAW_INPUT_DIRECTORY}/agent-envelopes/{envelope_name}"
            )
            envelope_path = self.run_dir / envelope_relative_path
            safe_io.ensure_owner_only_directory(envelope_path.parent)
            try:
                safe_io.atomic_create_bytes(envelope_path, envelope_bytes)
            except FileExistsError:
                existing_envelope = safe_io.read_bounded_bytes(
                    envelope_path,
                    max_bytes=self._agent_envelope_limit(),
                    require_owner_only=True,
                )
                if existing_envelope != envelope_bytes:
                    raise RunConflictError("issued agent envelope changed")
            attempt.update(
                {
                    "base_envelope_digest": hashlib.sha256(envelope_bytes).hexdigest(),
                    "base_envelope_path": envelope_relative_path,
                    "base_envelope_size": len(envelope_bytes),
                }
            )
            state["metrics"]["agent_attempts"] += 1
            if ordinal == 1:
                state["metrics"]["agent_retries"] += 1
            scheduled.append(job_ref)
        return scheduled

    def _prepare_cursor_proposals(self, state: dict[str, Any]) -> None:
        for host, cells in state["source"]["cells"].items():
            cursor = state["cursors"][host]
            if state["mode"] in {
                RunMode.BASELINE.value,
                RunMode.SESSION.value,
            }:
                cursor.update(
                    {
                        "decision": "not_applicable",
                        "proposed": None,
                        "publication_state": "not_applicable",
                    }
                )
                continue
            if any(
                cell["status"] == SourceCellStatus.GAP.value for cell in cells.values()
            ):
                cursor.update(
                    {
                        "decision": "held_for_gap",
                        "proposed": None,
                        "publication_state": "backfill_required",
                    }
                )
                continue
            source_vector = {
                source_kind: {
                    "snapshot_ref": cell["snapshot_ref"],
                    "status": cell["status"],
                }
                for source_kind, cell in sorted(cells.items())
            }
            source_cursor, _backlog, prior_boundary = self._projection._cursor_before(
                cursor["before"]
            )
            window_end = state["window"]["end"]
            advances = prior_boundary is None or _parse_timestamp(
                window_end,
                label="window end",
            ) > _parse_timestamp(prior_boundary, label="cursor boundary")
            logical_boundary = window_end if advances else prior_boundary
            snapshot_ref = (
                self._ref(
                    RefType.SOURCE,
                    state["run_ref"],
                    "cursor_proposal",
                    state["host_refs"][host],
                    cursor["before"],
                    source_vector,
                    logical_boundary,
                )
                if advances
                else source_cursor
            )
            if snapshot_ref is None or logical_boundary is None:
                raise InvalidTransitionError(
                    "complete cursor proposal lacks a durable boundary"
                )
            cursor.update(
                {
                    "decision": "proposed",
                    "proposed": {
                        "logical_boundary": logical_boundary,
                        "source_cells": source_vector,
                        "source_snapshot_ref": snapshot_ref,
                    },
                    "publication_state": "complete",
                }
            )

    def holdout_host(
        self,
        host: str,
        *,
        reason: ControlledGapReason | str,
    ) -> dict[str, Any]:
        self._state.ensure_retention_active()
        try:
            normalized_reason = ControlledGapReason(reason)
        except (TypeError, ValueError) as error:
            raise InvalidInputError("controlled gap reason is not closed") from error
        snapshot = self.store.read()
        state = snapshot.state
        expected_reason = (
            ControlledGapReason.SHADOW_MISSING_HOST_HOLDOUT
            if state.get("shadow") is True
            else ControlledGapReason.MISSING_HOST_HOLDOUT
        )
        if normalized_reason is not expected_reason:
            raise InvalidInputError(
                "controlled gap reason does not match the run shadow mode"
            )
        source_receipt_refs: list[str] = []
        source_kinds: list[SourceKind] = []
        for _ in range((2 * len(REQUIRED_SOURCE_KINDS)) + 1):
            snapshot = self.store.read()
            state = snapshot.state
            self._state._assert_state_identity(state)
            self._state._require_stage(state, RunStage.SOURCE_CATALOG)
            if (
                state["mode"] != RunMode.DAILY.value
                or not state["partial_policy"]["allow_partial"]
            ):
                raise InvalidTransitionError(
                    "controlled host holdout requires a partial daily run"
                )
            if host not in state["source"]["cells"]:
                raise InvalidInputError("controlled holdout host is not configured")
            existing_holdout = state.get("controlled_holdouts", {}).get(host)
            if existing_holdout is not None:
                restored = controlled_gaps.verify_controlled_gap_receipt(
                    self.identity,
                    existing_holdout,
                )
                if restored.reason is not normalized_reason:
                    raise RunConflictError(
                        "host already has a different controlled holdout"
                    )
                response = self._projection._status_view(snapshot)
                response.update(
                    {
                        "action": "holdout-host",
                        "changed": False,
                        "controlled_gap_receipt": restored.to_dict(),
                        "idempotent": True,
                    }
                )
                return response

            cells = state["source"]["cells"][host]
            leased = [
                source_kind
                for source_kind, cell in cells.items()
                if cell["status"] == "leased"
            ]
            pending = [
                source_kind
                for source_kind, cell in cells.items()
                if cell["status"] == "pending"
            ]
            if not leased and not pending:
                break
            source_kind = leased[0] if leased else pending[0]
            cell = cells[source_kind]
            if cell["status"] == "pending":
                self.store.transaction(
                    lambda current: (
                        current,
                        self._schedule_source_wave(current),
                    )
                )
                continue
            jobs = [
                job
                for job in state["jobs"].values()
                if job.get("category") == "source"
                and job.get("host") == host
                and job.get("source_kind") == source_kind
                and job.get("status") == "runnable"
            ]
            if len(jobs) != 1:
                raise InvalidTransitionError(
                    "controlled holdout source lease is not uniquely runnable"
                )
            job = jobs[0]
            lease = source_transport.TransportLease.from_dict(job["transport_lease"])
            remote = (
                None
                if host == "local"
                else catalog.RemoteTransportBinding(
                    process_nonce=lease.process_nonce,
                    forced_command_argv=lease.command_argv,
                )
            )
            manifest = catalog.SourceTransportManifest.create(
                host_ref=lease.host_ref,
                transport_kind=(
                    catalog.TransportKind.LOCAL
                    if host == "local"
                    else catalog.TransportKind.REMOTE
                ),
                source_kind=source_kind,
                window_start=lease.window_start,
                window_end=lease.window_end,
                status=SourceCellStatus.GAP,
                records=(),
                enumeration_gap=catalog.ExplicitGap(
                    reason=normalized_reason.value,
                    stage="controlled_holdout",
                    repairable=True,
                ),
                remote=remote,
            )
            transcript = source_transport.transcript_commitment(
                {},
                source_marker=lease.lease_ref,
            )
            terminal_proof = "sha256:" + self.identity.derive_digest(
                "controlled-gap-terminal/v2",
                {
                    "host_ref": lease.host_ref,
                    "lease_ref": lease.lease_ref,
                    "reason": normalized_reason.value,
                    "run_ref": state["run_ref"],
                    "source_kind": source_kind,
                },
            )
            source_snapshot = source_transport.AuthoritativeSourceSnapshot.create(
                host_ref=lease.host_ref,
                source_kind=source_kind,
                window_start=lease.window_start,
                window_end=lease.window_end,
                session_target=lease.session_target,
                source_content_commitment=transcript,
                source_byte_count=0,
                terminal_byte_offset=0,
                catalog_record_count=0,
                catalog_byte_count=0,
                catalog_commitment=None,
                transcript_commitment=transcript,
                terminal_proof_commitment=terminal_proof,
                terminal_status=SourceCellStatus.GAP,
                terminal_reason=normalized_reason.value,
                complete=False,
                resume_position=None,
            )
            receipt = source_transport.issue_transport_receipt(
                self.identity,
                lease=lease,
                manifest=manifest.to_dict(),
                source_snapshot=source_snapshot,
            )
            self._source._authorize_transport_receipt(
                lease.lease_ref, manifest, receipt
            )
            self._source.accept_source(
                lease.lease_ref,
                manifest.to_dict(),
                transport_receipt=receipt.to_dict(),
                raw_records={},
            )
            source_receipt_refs.append(receipt.receipt_ref)
            source_kinds.append(SourceKind(source_kind))
        else:
            raise InvalidTransitionError(
                "controlled holdout did not reach a stable source checkpoint"
            )

        snapshot = self.store.read()
        state = snapshot.state
        cells = state["source"]["cells"][host]
        for source_kind, cell in cells.items():
            manifest = cell.get("manifest")
            if (
                cell["status"] != SourceCellStatus.GAP.value
                or not isinstance(manifest, Mapping)
                or not isinstance(manifest.get("enumeration_gap"), Mapping)
                or manifest["enumeration_gap"].get("reason") != normalized_reason.value
            ):
                raise RunConflictError(
                    "controlled holdout cannot replace existing source evidence"
                )
            if cell["transport_receipt_ref"] not in source_receipt_refs:
                source_receipt_refs.append(cell["transport_receipt_ref"])
                source_kinds.append(SourceKind(source_kind))
        aggregate = controlled_gaps.issue_controlled_gap_receipt(
            self.identity,
            run_ref=state["run_ref"],
            host=host,
            host_ref=state["host_refs"][host],
            source_kinds=source_kinds,
            window_start=state["window"]["start"],
            window_end=state["window"]["end"],
            reason=normalized_reason,
            shadow=state.get("shadow") is True,
            source_receipt_refs=source_receipt_refs,
        )

        def persist(
            current: dict[str, Any],
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(current)
            self._state._require_retention_active_state(current)
            holdouts = current.setdefault("controlled_holdouts", {})
            existing = holdouts.get(host)
            if existing is not None and existing != aggregate.to_dict():
                raise RunConflictError(
                    "host already has a different controlled holdout receipt"
                )
            holdouts[host] = aggregate.to_dict()
            return current, {"idempotent": existing is not None}

        result = self.store.transaction(persist)
        response = self._projection._status_view(result.snapshot)
        response.update(
            {
                "action": "holdout-host",
                "changed": result.changed,
                "controlled_gap_receipt": aggregate.to_dict(),
                **result.value,
            }
        )
        return response
