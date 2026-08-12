"""Source transport admission and leased agent result handling."""

from __future__ import annotations
import copy
import datetime as dt
from functools import partial
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import (
    agent_checkpoint_capacity,
    agent_claim_artifacts,
    agent_results,
    agent_task_inputs,
    catalog,
    result_validation,
    source_capacity,
    source_inputs,
    source_payloads,
    transport as source_transport,
)
from .checkpoints import canonical_json_bytes, content_digest
from .contracts import (
    AGENT_FAILURE_SCHEMA,
    AgentFailure,
    RefType,
    RunMode,
    RunStage,
    SessionShardsRequest,
    SourceCellStatus,
    SourceKind,
)
from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_protocols import (
    SourceHistoryPort,
    SourceJobsPort,
    SourceProjectionPort,
    SourceStatePort,
)
from .orchestrator_source_segments import consume_session_shard_segments

from .orchestrator_support import (
    DEFAULT_AGENT_CLAIM_TTL_SECONDS,
    InvalidInputError,
    InvalidTransitionError,
    MAX_AGENT_CLAIM_TTL_SECONDS,
    MAX_AGENT_CLAIM_GENERATIONS,
    MIN_AGENT_CLAIM_TTL_SECONDS,
    RAW_INPUT_DIRECTORY,
    RunConflictError,
    SourcePreparation,
    _SHA256_RE,
    _format_timestamp,
    _json_copy,
    _parse_timestamp,
    _safe_reason,
    _source_session_identifiers,
    _strict_source_record,
)


class SourceCoordinationOperations(OrchestratorComponent):
    def __init__(
        self,
        context: RuntimeContext,
        *,
        state: SourceStatePort,
        projection: SourceProjectionPort,
        jobs: SourceJobsPort,
        history: SourceHistoryPort,
    ) -> None:
        super().__init__(context)
        self._state = state
        self._projection = projection
        self._jobs = jobs
        self._history = history

    def prepare_source(
        self,
        lease_ref: str,
        lines: Iterable[bytes | str],
    ) -> SourcePreparation:
        self._state.ensure_retention_active()

        def capture_factory(
            lease: source_transport.TransportLease,
        ) -> source_transport.SourceTransportCapture:
            self._verify_source_transport_program(lease)
            try:
                return source_transport.capture_source_transport(lines, lease=lease)
            except source_transport.TransportValidationError as error:
                raise InvalidInputError(
                    "source transport stream did not produce valid terminal evidence"
                ) from error

        return self._prepare_source(lease_ref, capture_factory=capture_factory)

    def _prepare_source(
        self,
        lease_ref: str,
        *,
        capture_factory: Callable[
            [source_transport.TransportLease],
            source_transport.SourceTransportCapture,
        ],
    ) -> SourcePreparation:
        normalized_lease = self._state._validate_ref(
            lease_ref,
            RefType.LEASE,
            label="lease_ref",
        )
        snapshot = self.store.read()
        state = snapshot.state
        self._state._assert_state_identity(state)
        self._state._require_stage(state, RunStage.SOURCE_CATALOG)
        job = self._source_job_for_lease(state, normalized_lease)
        action_key = f"accept_source:{normalized_lease}"
        replayable = job["status"] == "accepted" and action_key in state["actions"]
        if job["status"] != "runnable" and not replayable:
            raise InvalidTransitionError("source lease is not runnable")
        try:
            lease = source_transport.TransportLease.from_dict(job["transport_lease"])
            source_transport.verify_transport_lease(self.identity, lease)
        except (
            KeyError,
            TypeError,
            ValueError,
            source_transport.TransportValidationError,
        ) as error:
            raise InvalidInputError("source transport lease is invalid") from error
        capture = capture_factory(lease)
        manifest, raw_records = self._manifest_from_transport_capture(
            state,
            job,
            lease,
            capture,
        )
        transcript = source_transport.transcript_commitment(
            raw_records,
            source_marker=lease.lease_ref,
        )
        source_bytes = sum(len(payload) for payload in raw_records.values())
        terminal = manifest.status in {
            SourceCellStatus.COMPLETE,
            SourceCellStatus.NO_ACTIVITY,
            SourceCellStatus.VERIFIED_ABSENT,
        }
        authoritative_snapshot = source_transport.AuthoritativeSourceSnapshot.create(
            host_ref=manifest.host_ref,
            source_kind=manifest.source_kind,
            window_start=manifest.window_start,
            window_end=manifest.window_end,
            session_target=lease.session_target,
            source_content_commitment=transcript,
            source_byte_count=source_bytes,
            terminal_byte_offset=source_bytes if terminal else 0,
            catalog_record_count=manifest.total_records,
            catalog_byte_count=manifest.total_bytes,
            catalog_commitment=manifest.snapshot_commitment,
            transcript_commitment=transcript,
            terminal_proof_commitment=capture.terminal_proof_commitment,
            terminal_status=manifest.status,
            terminal_reason=(
                capture.terminal_reason
                if manifest.status is capture.terminal_status
                or (
                    manifest.status is SourceCellStatus.COMPLETE
                    and capture.terminal_status is SourceCellStatus.NO_ACTIVITY
                )
                else "source_record_validation_failed"
            ),
            complete=terminal,
            resume_position=capture.resume_position,
        )
        receipt = source_transport.issue_transport_receipt(
            self.identity,
            lease=lease,
            manifest=manifest.to_dict(),
            source_snapshot=authoritative_snapshot,
        )
        self._authorize_transport_receipt(
            normalized_lease,
            manifest,
            receipt,
        )
        return SourcePreparation(
            lease_ref=normalized_lease,
            host=lease.host,
            manifest=manifest.to_dict(),
            receipt=receipt.to_dict(),
            raw_records=raw_records,
        )

    def _verify_source_transport_program(
        self,
        lease: source_transport.TransportLease,
    ) -> None:
        if len(lease.command_argv) < 2:
            raise InvalidInputError("source transport command is incomplete")
        try:
            current_program_commitment = source_transport.transport_program_commitment(
                lease.command_argv,
                snapshot_cache=(
                    self.run_dir / RAW_INPUT_DIRECTORY / "source-program-snapshots"
                ),
            )
        except (OSError, source_transport.TransportValidationError) as error:
            raise InvalidInputError(
                "source transport program cannot be authenticated"
            ) from error
        if not hmac.compare_digest(
            current_program_commitment,
            lease.transport_program_commitment,
        ):
            raise InvalidInputError(
                "source transport program changed after lease issuance"
            )

    def _manifest_from_transport_capture(
        self,
        state: Mapping[str, Any],
        job: Mapping[str, Any],
        lease: source_transport.TransportLease,
        capture: source_transport.SourceTransportCapture,
    ) -> tuple[catalog.SourceTransportManifest, dict[str, bytes]]:
        source_kind = SourceKind(lease.source_kind)
        captured_by_coordinate = {
            (record.source_locator, record.record_index): record
            for record in capture.records
        }
        record_validation_failed = False
        records: list[catalog.CatalogRecord] = []
        raw_records: dict[str, bytes] = {}
        session_target = state.get("session_target")
        selector_commitment = state.get("session_selector_commitment")
        exclusion_reasons = {
            "empty_structural_unit": (
                catalog.StructuralExclusionReason.EMPTY_STRUCTURAL_UNIT
            ),
            "non_evidence_wrapper": (
                catalog.StructuralExclusionReason.NON_EVIDENCE_WRAPPER
            ),
            "retrospective_coordinator": (
                catalog.StructuralExclusionReason.RETROSPECTIVE_COORDINATOR
            ),
            "retrospective_worker": (
                catalog.StructuralExclusionReason.RETROSPECTIVE_WORKER
            ),
            "before_cursor": (
                catalog.StructuralExclusionReason.OUTSIDE_REQUESTED_WINDOW
            ),
            "before_window": (
                catalog.StructuralExclusionReason.OUTSIDE_REQUESTED_WINDOW
            ),
            "after_window": (
                catalog.StructuralExclusionReason.OUTSIDE_REQUESTED_WINDOW
            ),
            "session_target_mismatch": (
                catalog.StructuralExclusionReason.SOURCE_POLICY_EXCLUDED
            ),
        }
        for inventory in capture.inventory:
            locator = str(inventory["source_locator"])
            record_index = int(inventory["record_index"])
            captured = captured_by_coordinate.get((locator, record_index))
            accounting_class = catalog.AccountingClass(
                str(inventory["accounting_class"])
            )
            content_commitment = inventory["content_commitment"]
            event_time = inventory["event_time"]
            row_session_commitment = inventory["session_commitment"]
            value: Mapping[str, Any] | None = None
            row_validation_failed = False
            if captured is not None:
                try:
                    value = _strict_source_record(captured.payload)
                    identifiers = _source_session_identifiers(
                        value,
                        source_kind=source_kind,
                    )
                    if len(identifiers) == 1 and (
                        source_transport.session_selector_commitment(identifiers[0])
                        != row_session_commitment
                    ):
                        raise ValueError("source session commitment changed")
                    derived_time = catalog.event_time_from_record(
                        value,
                        stable_event_time=catalog.stable_event_time_from_locator(
                            locator
                        ),
                    )
                    if derived_time != event_time:
                        raise ValueError("source event time changed")
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    ValueError,
                    source_transport.TransportValidationError,
                ):
                    value = None
                    row_validation_failed = True
                    record_validation_failed = True
            elif accounting_class is catalog.AccountingClass.CONSUMED_CANDIDATE:
                row_validation_failed = True
                record_validation_failed = True

            is_target_row = (
                state["mode"] == RunMode.SESSION.value
                and isinstance(row_session_commitment, str)
                and row_session_commitment == selector_commitment
            )
            if is_target_row:
                source_ref = str(session_target)
            elif isinstance(row_session_commitment, str):
                source_ref = str(
                    self.identity.derive_ref(
                        RefType.SESSION,
                        {"session_selector_commitment": row_session_commitment},
                    )
                )
            else:
                source_ref = str(
                    self.identity.derive_ref(
                        RefType.SESSION,
                        {
                            "host_ref": lease.host_ref,
                            "unresolved_record_commitment": content_commitment,
                        },
                    )
                )
            is_rollout = source_kind in {
                SourceKind.ACTIVE_ROLLOUT,
                SourceKind.ARCHIVED_ROLLOUT,
            }
            occurrence_source_kind = "rollout" if is_rollout else source_kind.value
            source_occurrence = str(inventory["source_occurrence"])
            physical_occurrence = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "host_ref": lease.host_ref,
                        "source_occurrence": source_occurrence,
                    }
                )
            ).hexdigest()
            canonical_record = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "byte_end": inventory["byte_end"],
                        "byte_start": inventory["byte_start"],
                        "content_commitment": content_commitment,
                        "record_index": record_index,
                        "source_family": occurrence_source_kind,
                        "source_ref": source_ref,
                    }
                )
            ).hexdigest()
            coordinate = catalog.StableSourceCoordinate(
                host_ref=lease.host_ref,
                source_ref=source_ref,
                record_ref=(f"record-v2:{physical_occurrence}:{canonical_record}"),
                byte_start=int(inventory["byte_start"]),
                byte_end=int(inventory["byte_end"]),
            )
            unit_ref = str(
                self.identity.derive_ref(
                    RefType.SOURCE_UNIT,
                    {
                        "content_commitment": content_commitment,
                        "coordinate": coordinate.to_dict(),
                    },
                )
            )
            if row_validation_failed and accounting_class is (
                catalog.AccountingClass.CONSUMED_CANDIDATE
            ):
                accounting_class = catalog.AccountingClass.EXPLICIT_GAP
            if accounting_class is catalog.AccountingClass.EXPLICIT_GAP:
                records.append(
                    catalog.CatalogRecord(
                        unit_ref=unit_ref,
                        source_kind=source_kind,
                        coordinate=coordinate,
                        accounting_class=catalog.AccountingClass.EXPLICIT_GAP,
                        turn_count=0,
                        gap=catalog.ExplicitGap(
                            reason=_safe_reason(
                                inventory["reason"],
                                fallback="source_record_unparseable",
                            ),
                            stage="source_transport",
                        ),
                    )
                )
                continue
            if accounting_class is catalog.AccountingClass.STRUCTURALLY_EXCLUDED:
                records.append(
                    catalog.CatalogRecord(
                        unit_ref=unit_ref,
                        source_kind=source_kind,
                        coordinate=coordinate,
                        accounting_class=(
                            catalog.AccountingClass.STRUCTURALLY_EXCLUDED
                        ),
                        event_time=event_time,
                        content_commitment=content_commitment,
                        turn_count=0,
                        exclusion_reason=exclusion_reasons.get(
                            str(inventory["reason"]),
                            catalog.StructuralExclusionReason.SOURCE_POLICY_EXCLUDED,
                        ),
                    )
                )
                continue
            if captured is None or value is None or event_time is None:
                record_validation_failed = True
                continue
            records.append(
                catalog.CatalogRecord(
                    unit_ref=unit_ref,
                    source_kind=source_kind,
                    coordinate=coordinate,
                    accounting_class=catalog.AccountingClass.CONSUMED_CANDIDATE,
                    event_time=event_time,
                    content_commitment=content_commitment,
                    turn_count=1,
                )
            )
            raw_records[unit_ref] = captured.payload

        records_by_ref: dict[str, catalog.CatalogRecord] = {}
        for record in records:
            existing = records_by_ref.get(record.unit_ref)
            if existing is not None and existing != record:
                raise InvalidInputError(
                    "source occurrence identity has conflicting records"
                )
            records_by_ref[record.unit_ref] = record
        records = sorted(
            records_by_ref.values(),
            key=catalog.catalog_record_sort_key,
        )

        status = capture.terminal_status
        gap_reason: str | None = None
        if record_validation_failed:
            status = SourceCellStatus.GAP
            gap_reason = "source_record_validation_failed"
        elif status is SourceCellStatus.GAP:
            gap_reason = _safe_reason(
                capture.terminal_reason,
                fallback="source_transport_gap",
            )
        elif not records:
            status = (
                SourceCellStatus.VERIFIED_ABSENT
                if capture.terminal_status is SourceCellStatus.VERIFIED_ABSENT
                else SourceCellStatus.NO_ACTIVITY
            )
        else:
            status = SourceCellStatus.COMPLETE
        remote = (
            None
            if lease.host == "local"
            else catalog.RemoteTransportBinding(
                process_nonce=lease.process_nonce,
                forced_command_argv=lease.command_argv,
            )
        )
        snapshot_commitment = (
            catalog.snapshot_commitment_for_records(records)
            if status in {SourceCellStatus.COMPLETE, SourceCellStatus.NO_ACTIVITY}
            else None
        )
        manifest = catalog.SourceTransportManifest.create(
            host_ref=lease.host_ref,
            transport_kind=(
                catalog.TransportKind.LOCAL
                if lease.host == "local"
                else catalog.TransportKind.REMOTE
            ),
            source_kind=source_kind,
            window_start=lease.window_start,
            window_end=lease.window_end,
            status=status,
            records=records,
            snapshot_commitment=snapshot_commitment,
            absence_proof=(
                "transport_terminal:"
                + capture.terminal_proof_commitment.removeprefix("sha256:")
                if status is SourceCellStatus.VERIFIED_ABSENT
                else None
            ),
            enumeration_gap=(
                catalog.ExplicitGap(
                    reason=gap_reason or "source_transport_gap",
                    stage="source_transport",
                )
                if status is SourceCellStatus.GAP
                else None
            ),
            remote=remote,
        )
        return manifest, raw_records

    @staticmethod
    def _transport_authorization(
        lease: source_transport.TransportLease,
        manifest: catalog.SourceTransportManifest,
        receipt: source_transport.TransportReceipt,
    ) -> dict[str, Any]:
        return {
            "lease_binding": lease.binding,
            "manifest_digest": content_digest(manifest.to_dict()),
            "receipt_ref": receipt.receipt_ref,
            "terminal_proof_commitment": (
                receipt.source_snapshot.terminal_proof_commitment
            ),
            "transport_program_commitment": lease.transport_program_commitment,
        }

    def _authorize_transport_receipt(
        self,
        lease_ref: str,
        manifest: catalog.SourceTransportManifest,
        receipt: source_transport.TransportReceipt,
    ) -> None:
        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], None]:
            self._state._assert_state_identity(state)
            self._state._require_retention_active_state(state)
            self._state._require_stage(state, RunStage.SOURCE_CATALOG)
            job = self._source_job_for_lease(state, lease_ref)
            self._validate_source_binding(state, job, manifest)
            lease = source_transport.TransportLease.from_dict(job["transport_lease"])
            source_transport.verify_transport_receipt(
                self.identity,
                lease=lease,
                manifest=manifest.to_dict(),
                receipt=receipt,
            )
            authorization = self._transport_authorization(lease, manifest, receipt)
            existing = job.get("transport_authorization")
            if existing is not None and existing != authorization:
                raise RunConflictError(
                    "source transport lease already authorized different evidence"
                )
            action_key = f"accept_source:{lease_ref}"
            if job["status"] == "accepted" and action_key in state["actions"]:
                if existing != authorization:
                    raise RunConflictError(
                        "source lease replay changed its authorized evidence"
                    )
                return state, None
            if job["status"] != "runnable":
                raise InvalidTransitionError("source lease is not runnable")
            job["transport_authorization"] = authorization
            return state, None

        self.store.transaction(mutate)

    def _aggregate_source_segments(
        self,
        segments: Sequence[Mapping[str, Any]],
    ) -> tuple[catalog.SourceTransportManifest, str, str]:
        return source_inputs.aggregate_segments(self.identity, self.run_dir, segments)

    def accept_source(
        self,
        lease_ref: str,
        manifest: Mapping[str, Any],
        *,
        transport_receipt: Mapping[str, Any],
        raw_records: Mapping[str, bytes] | None = None,
        transport_streams: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
        transport_requests: Mapping[str, SessionShardsRequest | Mapping[str, Any]]
        | None = None,
        transport_segments: Mapping[
            str,
            Iterable[
                tuple[
                    Iterable[Mapping[str, Any]],
                    SessionShardsRequest | Mapping[str, Any],
                ]
            ],
        ]
        | None = None,
    ) -> dict[str, Any]:
        self._state.ensure_retention_active()
        normalized_lease = self._state._validate_ref(
            lease_ref,
            RefType.LEASE,
            label="lease_ref",
        )
        if not isinstance(manifest, Mapping):
            raise InvalidInputError("source manifest must be a mapping")
        try:
            transport = catalog.SourceTransportManifest.from_dict(dict(manifest))
        except (catalog.CatalogValidationError, TypeError, ValueError) as error:
            raise InvalidInputError(
                "source manifest violates the closed contract"
            ) from error
        if not isinstance(transport_receipt, Mapping):
            raise InvalidInputError(
                "source acceptance requires an authenticated transport receipt"
            )
        try:
            receipt = source_transport.TransportReceipt.from_dict(
                dict(transport_receipt)
            )
        except (
            TypeError,
            ValueError,
            source_transport.TransportValidationError,
        ) as error:
            raise InvalidInputError(
                "source transport receipt violates the closed contract"
            ) from error
        raw_values, segments = source_inputs.normalize_transport_inputs(
            raw_records=raw_records,
            transport_streams=transport_streams,
            transport_requests=transport_requests,
            transport_segments=transport_segments,
        )

        snapshot = self.store.read()
        state = snapshot.state
        self._state._assert_state_identity(state)
        self._state._require_stage(state, RunStage.SOURCE_CATALOG)
        source_job = self._source_job_for_lease(state, normalized_lease)
        self._validate_source_binding(state, source_job, transport)
        try:
            transport_lease = source_transport.TransportLease.from_dict(
                source_job["transport_lease"]
            )
            source_snapshot = source_transport.verify_transport_receipt(
                self.identity,
                lease=transport_lease,
                manifest=transport.to_dict(),
                receipt=receipt,
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            source_transport.TransportValidationError,
        ) as error:
            raise InvalidInputError(
                "source transport lease or receipt authentication failed"
            ) from error
        self._validate_authoritative_source_snapshot(transport, source_snapshot)
        expected_authorization = self._transport_authorization(
            transport_lease,
            transport,
            receipt,
        )
        if source_job.get("transport_authorization") != expected_authorization:
            raise InvalidInputError(
                "source transport receipt was not issued by the execution boundary"
            )
        action_key = f"accept_source:{normalized_lease}"
        if source_job["status"] != "runnable":
            previous = state["actions"].get(action_key)
            if previous is None:
                raise InvalidTransitionError("source lease is not runnable")
            if source_job.get("accepted_input_digest") != previous.get("input_digest"):
                raise RunConflictError("accepted source action binding changed")
            response = self._projection._status_view(snapshot)
            response.update(
                {
                    "accepted": True,
                    "action": "accept-source",
                    "changed": False,
                    "idempotent": True,
                    "outcome": previous.get("outcome"),
                }
            )
            return response
        limits = self._projection._shard_limits_from_state(state)
        initial_cell = state["source"]["cells"][source_job["host"]][
            source_job["source_kind"]
        ]
        accepted_requests: dict[str, tuple[SessionShardsRequest, ...]] = {}
        consumed = source_inputs.consumed_records(transport)
        payloads = source_inputs.SourcePayloadCollection(
            self.identity,
            self.run_dir,
            consumed,
            model_era_for_payload=lambda payload: self._projection._source_model_era(
                _strict_source_record(payload)
            ),
            validate_unit_ref=lambda unit_ref: self._projection._validate_external_ref(
                unit_ref,
                "source_unit",
            ),
        )
        if segments is not None:
            if source_job["status"] == "runnable":
                source_inputs.require_new_segment_capacity(initial_cell)
                source_capacity.require_candidate_capacity(
                    state["source"]["cells"],
                    acceptance_bytes=source_inputs.MAX_SOURCE_ACCEPTANCE_BYTES,
                    byte_count=transport.total_bytes,
                    record_count=transport.total_records,
                )
            expected_source_refs = source_inputs.consumed_source_refs(consumed)
            if set(segments) != expected_source_refs:
                raise InvalidInputError(
                    "session-shards streams and requests must cover every source_ref"
                )
            payloads.enable_streaming(
                max_bytes=sum(record.byte_count for record in consumed.values()),
                max_records=len(consumed),
                spool_ref=normalized_lease,
            )

            def consume_record(raw_record) -> None:
                payloads.add(raw_record.unit_ref, raw_record.payload)

            try:
                for source_ref in sorted(segments):
                    accepted_requests[source_ref] = consume_session_shard_segments(
                        transport,
                        source_ref,
                        segments[source_ref],
                        limits=limits,
                        on_record=consume_record,
                    )
            except BaseException as error:
                payloads.discard_streamed(error)
                raise
        else:
            for unit_ref, payload in sorted(raw_values.items()):
                payloads.add(unit_ref, payload)
        payloads.complete_missing()

        try:
            self._validate_received_transport_transcript(
                normalized_lease,
                transport,
                source_snapshot,
                payloads.payload_metadata,
            )
            if transport.status in {
                catalog.SourceCellStatus.COMPLETE,
                catalog.SourceCellStatus.NO_ACTIVITY,
                catalog.SourceCellStatus.VERIFIED_ABSENT,
            } and any(
                item.get("status") != "available" for item in payloads.staged.values()
            ):
                raise InvalidInputError(
                    "terminal source transport is missing authenticated record bytes"
                )
            acceptance_digest = self._source_acceptance_digest(
                transport,
                receipt,
                payloads.payload_metadata,
                accepted_requests,
            )
        except BaseException as error:
            payloads.discard_streamed(error)
            raise
        segment = source_inputs.segment_descriptor(
            normalized_lease, transport, receipt, source_snapshot
        )
        segment_unit_eras, segment_session_eras = source_inputs.model_era_indexes(
            payloads.model_era_evidence
        )
        try:
            initial_legacy_payloads = source_payloads.merge_payload_indexes(
                initial_cell.get("payloads", {})
            )
            acceptance_payloads = source_payloads.merge_payload_indexes(
                initial_legacy_payloads, payloads.staged
            )
            prepared_acceptance = source_inputs.prepare_acceptance(
                self.run_dir,
                segment=segment,
                payloads=acceptance_payloads,
                model_era_by_unit=segment_unit_eras,
                model_eras_by_session=segment_session_eras,
            )
        except BaseException as error:
            payloads.discard_streamed(error)
            raise

        def mutate(current: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(current)
            self._state._require_retention_active_state(current)
            replay = self._check_replay(current, action_key, acceptance_digest)
            if replay:
                return current, {
                    "accepted": True,
                    "idempotent": True,
                    "outcome": current["actions"][action_key]["outcome"],
                }
            self._state._require_stage(current, RunStage.SOURCE_CATALOG)
            job = self._source_job_for_lease(current, normalized_lease)
            if job["status"] != "runnable":
                raise InvalidTransitionError("source lease is not runnable")
            self._validate_source_binding(current, job, transport)
            current_lease = source_transport.TransportLease.from_dict(
                job["transport_lease"]
            )
            current_snapshot = source_transport.verify_transport_receipt(
                self.identity,
                lease=current_lease,
                manifest=transport.to_dict(),
                receipt=receipt,
            )
            self._validate_authoritative_source_snapshot(transport, current_snapshot)
            if job.get("transport_authorization") != self._transport_authorization(
                current_lease,
                transport,
                receipt,
            ):
                raise InvalidInputError(
                    "source transport authorization changed before acceptance"
                )
            host = job["host"]
            source_kind = job["source_kind"]
            cell = current["source"]["cells"][host][source_kind]
            payload_gaps = [
                item for item in payloads.staged.values() if item.get("status") == "gap"
            ]
            if current_lease.resume_position != cell.get("continuation_position"):
                raise RunConflictError(
                    "source continuation lease does not match durable progress"
                )
            current_legacy_payloads = source_payloads.merge_payload_indexes(
                cell.get("payloads", {})
            )
            if current_legacy_payloads != initial_legacy_payloads:
                raise RunConflictError("legacy source payload index changed")
            existing_segments = list(cell.get("continuation_segments", []))
            source_inputs.require_new_segment_capacity(cell)
            source_capacity.require_candidate_capacity(
                current["source"]["cells"],
                acceptance_bytes=prepared_acceptance.file.byte_count,
                byte_count=transport.total_bytes,
                record_count=transport.total_records,
            )
            segments = [*existing_segments, prepared_acceptance.descriptor]
            continuation = current_snapshot.resume_position
            if continuation is not None:
                if payload_gaps:
                    raise InvalidInputError(
                        "source continuation cannot hide payload validation gaps"
                    )
                previous = current_lease.resume_position
                if previous is not None and (
                    int(continuation["candidate_index"]),
                    int(continuation["byte_offset"]),
                    int(continuation["record_index"]),
                ) <= (
                    int(previous["candidate_index"]),
                    int(previous["byte_offset"]),
                    int(previous["record_index"]),
                ):
                    raise InvalidInputError(
                        "source continuation did not make durable forward progress"
                    )
                effective_status = "continued"
                cell.update(
                    {
                        "accepted_input_digest": acceptance_digest,
                        "continuation_position": copy.deepcopy(continuation),
                        "continuation_segments": segments,
                        "lease_ref": normalized_lease,
                        "manifest": None,
                        "metrics": {
                            "byte_count": int(cell["metrics"]["byte_count"])
                            + transport.total_bytes,
                            "record_count": int(cell["metrics"]["record_count"])
                            + transport.total_records,
                        },
                        "payloads": {},
                        "snapshot_ref": None,
                        "status": "pending",
                        "transport_receipt": None,
                        "transport_receipt_ref": None,
                        "transport_status": "continued",
                    }
                )
            else:
                aggregate, snapshot_ref, receipt_ref = self._aggregate_source_segments(
                    [*existing_segments, segment]
                )
                effective_status = (
                    SourceCellStatus.GAP.value
                    if payload_gaps
                    else aggregate.status.value
                )
                cell.update(
                    {
                        "accepted_input_digest": acceptance_digest,
                        "continuation_position": None,
                        "continuation_segments": segments,
                        "lease_ref": normalized_lease,
                        "manifest": source_inputs.manifest_summary(aggregate),
                        "metrics": {
                            "byte_count": aggregate.total_bytes,
                            "record_count": aggregate.total_records,
                        },
                        "payloads": {},
                        "snapshot_ref": snapshot_ref,
                        "status": effective_status,
                        "transport_receipt": receipt.to_dict(),
                        "transport_receipt_ref": receipt_ref,
                        "transport_status": aggregate.status.value,
                    }
                )
            job.update(
                {
                    "accepted_input_digest": acceptance_digest,
                    "completed_at": self._state._now(),
                    "status": "accepted",
                }
            )
            current["actions"][action_key] = {
                "input_digest": acceptance_digest,
                "outcome": effective_status,
            }
            self._recompute_source_metrics(current)
            return current, {
                "accepted": True,
                "idempotent": False,
                "outcome": effective_status,
            }

        try:
            result = self.store.staged_transaction(
                mutate,
                stage=lambda: payloads.materialize_with(prepared_acceptance.file),
                rollback=source_inputs.rollback,
            )
        except BaseException as error:
            payloads.discard_streamed(error)
            raise
        else:
            payloads.discard_streamed()
        response = self._projection._status_view(result.snapshot)
        response.update(
            {"action": "accept-source", "changed": result.changed, **result.value}
        )
        return response

    def _exhaust_agent_claim_budget(
        self,
        state: dict[str, Any],
        task: dict[str, Any],
        attempt: dict[str, Any],
        *,
        action_key: str,
        attempt_ref: str,
        budget_digest: str,
        job_ref: str,
        takeover: bool,
    ) -> dict[str, Any]:
        outcome = self._close_exhausted_agent_claim(
            state,
            task,
            attempt,
            attempt_ref=attempt_ref,
            budget_digest=budget_digest,
        )
        state["actions"][action_key] = {
            "input_digest": budget_digest,
            "outcome": outcome,
            "takeover": takeover,
        }
        return {
            "attempt_ref": attempt_ref,
            "claim_budget_exhausted": True,
            "idempotent": False,
            "job_ref": job_ref,
            "outcome": outcome,
            "takeover": takeover,
        }

    def claim_agent_job(
        self,
        job_ref: str,
        attempt_ref: str,
        dispatcher_ref: str,
        *,
        claim_ref: str | None = None,
        ttl_seconds: int = DEFAULT_AGENT_CLAIM_TTL_SECONDS,
    ) -> dict[str, Any]:
        self._state.ensure_retention_active()
        normalized_job_ref = self._state._validate_ref(
            job_ref, RefType.JOB, label="job_ref"
        )
        normalized_attempt_ref = self._state._validate_ref(
            attempt_ref,
            RefType.ATTEMPT,
            label="attempt_ref",
        )
        normalized_dispatcher_ref = self._state._validate_ref(
            dispatcher_ref,
            RefType.LEASE,
            label="dispatcher_ref",
        )
        normalized_claim_ref = (
            None
            if claim_ref is None
            else self._state._validate_ref(claim_ref, RefType.CLAIM, label="claim_ref")
        )
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not MIN_AGENT_CLAIM_TTL_SECONDS
            <= ttl_seconds
            <= MAX_AGENT_CLAIM_TTL_SECONDS
        ):
            raise InvalidInputError(
                "agent claim TTL is outside the closed lease bounds"
            )
        budget_action_key = f"exhaust_agent_claim_budget:{normalized_attempt_ref}"
        budget_input_digest = content_digest(
            {
                "attempt_ref": normalized_attempt_ref,
                "job_ref": normalized_job_ref,
                "reason": "agent_claim_budget_exhausted",
            }
        )
        prepared_claim_files: list[source_inputs.PreparedFile] = []

        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            self._state._require_retention_active_state(state)
            original_state = copy.deepcopy(state)
            finalize_mutation = partial(
                agent_checkpoint_capacity.finalize_claim,
                self.store,
                self._state,
                state,
                original_state,
                prepared_files=prepared_claim_files,
                attempt_ref=normalized_attempt_ref,
                job_ref=normalized_job_ref,
            )

            previous_budget = state["actions"].get(budget_action_key)
            if previous_budget is not None:
                if previous_budget.get("input_digest") != budget_input_digest:
                    raise RunConflictError("agent claim budget replay binding changed")
                _, task, attempt = self._projection._agent_attempt_binding(
                    state, normalized_job_ref, normalized_attempt_ref
                )
                self._bound_agent_job_manifest(state, task, attempt)
                value = {
                    "attempt_ref": normalized_attempt_ref,
                    "claim_budget_exhausted": True,
                    "idempotent": True,
                    "job_ref": normalized_job_ref,
                    "outcome": previous_budget.get("outcome"),
                    "takeover": bool(previous_budget.get("takeover")),
                }
                return finalize_mutation(
                    task=task,
                    value=value,
                    changed=state != original_state,
                )
            task = self._projection._task_for_active_job(state, normalized_job_ref)
            if task.get("stage") != state["stage"]:
                raise InvalidTransitionError("agent job is not in the current stage")
            if task.get("status") != "runnable":
                raise InvalidTransitionError("agent job is not runnable")
            if task.get("active_attempt_ref") != normalized_attempt_ref:
                raise InvalidInputError("attempt_ref is not the active fresh attempt")
            attempt = self._projection._active_attempt(task, normalized_attempt_ref)
            self._bound_agent_job_manifest(state, task, attempt)
            dispatch_state = attempt.get("dispatch_state")
            now_text = self._state._now()
            now = _parse_timestamp(now_text, label="clock")
            expired = (
                dispatch_state == "claimed"
                and self._projection._claim_is_expired(attempt, now)
            )

            def exhaust_claim_budget(*, takeover: bool) -> dict[str, Any]:
                return self._exhaust_agent_claim_budget(
                    state,
                    task,
                    attempt,
                    action_key=budget_action_key,
                    attempt_ref=normalized_attempt_ref,
                    budget_digest=budget_input_digest,
                    job_ref=normalized_job_ref,
                    takeover=takeover,
                )

            if (
                dispatch_state == "claimed"
                and agent_claim_artifacts.sink_exceeds_budget(
                    self.run_dir,
                    attempt,
                    max_bytes=result_validation.MAX_RESULT_BYTES,
                )
            ):
                return finalize_mutation(
                    task=task,
                    value=exhaust_claim_budget(takeover=expired),
                    changed=True,
                )
            heartbeat = False
            takeover = False
            new_claim = False
            if dispatch_state == "claimed" and not expired:
                if attempt.get("dispatcher_ref") != normalized_dispatcher_ref:
                    raise RunConflictError(
                        "agent attempt is already claimed by another dispatcher"
                    )
                current_claim_ref = attempt.get("claim_ref")
                if normalized_claim_ref is not None:
                    if current_claim_ref != normalized_claim_ref:
                        raise RunConflictError(
                            "agent claim heartbeat does not match the active lease"
                        )
                    current_expiry = _parse_timestamp(
                        attempt["claim_expires_at"],
                        label="agent claim expiry",
                    )
                    claim_expires_at = _format_timestamp(
                        max(
                            current_expiry,
                            now + dt.timedelta(seconds=ttl_seconds),
                        )
                    )
                    attempt.update(
                        {
                            "claim_expires_at": claim_expires_at,
                            "claim_heartbeat_at": now_text,
                        }
                    )
                    heartbeat = True
                    idempotent = False
                else:
                    idempotent = True
            elif dispatch_state == "unclaimed" or expired:
                if normalized_claim_ref is not None:
                    raise InvalidTransitionError(
                        "an expired or unclaimed attempt requires a fresh claim"
                    )
                takeover = expired
                generation = int(attempt.get("claim_generation", 0)) + 1
                if generation > MAX_AGENT_CLAIM_GENERATIONS:
                    return finalize_mutation(
                        task=task,
                        value=exhaust_claim_budget(takeover=expired),
                        changed=True,
                    )
                active_claim_ref = self._ref(
                    RefType.CLAIM,
                    state["run_ref"],
                    normalized_job_ref,
                    normalized_attempt_ref,
                    generation,
                    normalized_dispatcher_ref,
                )
                output_name = agent_claim_artifacts.artifact_name(
                    normalized_attempt_ref,
                    generation,
                    "result",
                )
                output_relative = f"agent-sinks/{output_name}"
                result_ref = self._ref(
                    RefType.RESULT,
                    state["run_ref"],
                    normalized_job_ref,
                    normalized_attempt_ref,
                    active_claim_ref,
                    output_relative,
                )
                attempt.update(
                    {
                        "claim_expires_at": _format_timestamp(
                            now + dt.timedelta(seconds=ttl_seconds)
                        ),
                        "claim_generation": generation,
                        "claim_heartbeat_at": now_text,
                        "claim_ref": active_claim_ref,
                        "claimed_at": now_text,
                        "dispatcher_ref": normalized_dispatcher_ref,
                        "dispatch_state": "claimed",
                        "output_sink": str(self.run_dir / output_relative),
                        "output_sink_relative": output_relative,
                        "result_ref": result_ref,
                        "sink_state": "open",
                    }
                )
                prepared_claim_files.append(
                    self._prepare_claim_envelope(state, task, attempt)
                )
                prepared_claim_files.append(
                    source_inputs.prepare_file(
                        self.run_dir / output_relative,
                        b"",
                    )
                )
                idempotent = False
                new_claim = True
            else:
                raise InvalidTransitionError("agent attempt cannot be claimed")
            if not new_claim:
                self._jobs._materialize_agent_result_sink(attempt)
            return finalize_mutation(
                task=task,
                value={
                    "attempt_ref": normalized_attempt_ref,
                    "claim_expires_at": attempt["claim_expires_at"],
                    "claim_heartbeat_at": attempt["claim_heartbeat_at"],
                    "claim_ref": attempt["claim_ref"],
                    "dispatcher_ref": normalized_dispatcher_ref,
                    "envelope_digest": attempt["envelope_digest"],
                    "envelope_path": str(self.run_dir / attempt["envelope_path"]),
                    "envelope_size": attempt["envelope_size"],
                    "heartbeat": heartbeat,
                    "idempotent": idempotent,
                    "job_ref": normalized_job_ref,
                    "output_sink": attempt["output_sink"],
                    "result_ref": attempt["result_ref"],
                    "takeover": takeover,
                },
                changed=state != original_state,
            )

        transaction = self.store.staged_transaction(
            mutate,
            stage=lambda: source_inputs.materialize(prepared_claim_files),
            rollback=source_inputs.rollback,
        )
        response = self._projection._status_view(transaction.snapshot)
        response.update(
            {
                "action": "status",
                "changed": transaction.changed,
                **transaction.value,
            }
        )
        return response

    def _prepare_claim_envelope(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
        attempt: dict[str, Any],
    ) -> source_inputs.PreparedFile:
        claim_ref = attempt.get("claim_ref")
        attempt_ref = attempt.get("attempt_ref")
        generation = attempt.get("claim_generation")
        if (
            not isinstance(claim_ref, str)
            or not isinstance(attempt_ref, str)
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
        ):
            raise InvalidTransitionError("agent claim identity is missing")
        job_manifest = self._bound_agent_job_manifest(state, task, attempt)
        envelope = self._jobs._agent_envelope(
            task,
            {**attempt, "job_manifest": job_manifest},
        )
        envelope_bytes = canonical_json_bytes(envelope)
        if len(envelope_bytes) > self._agent_envelope_limit():
            raise InvalidTransitionError(
                "claimed agent task exceeds the complete 512 KiB envelope"
            )
        envelope_name = agent_claim_artifacts.artifact_name(
            attempt_ref,
            generation,
            "envelope",
        )
        relative_path = f"{RAW_INPUT_DIRECTORY}/agent-claims/{envelope_name}"
        attempt.update(
            {
                "envelope_digest": hashlib.sha256(envelope_bytes).hexdigest(),
                "envelope_path": relative_path,
                "envelope_size": len(envelope_bytes),
            }
        )
        return source_inputs.prepare_file(
            self.run_dir / relative_path,
            envelope_bytes,
        )

    def _bound_agent_job_manifest(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
        attempt: dict[str, Any],
    ) -> dict[str, Any]:
        ordinal = attempt.get("ordinal")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0:
            raise InvalidTransitionError("agent job manifest ordinal is invalid")
        expected = self._jobs._execution_manifest(state, task, ordinal)
        expected_digest = content_digest(expected)
        has_manifest = "job_manifest" in attempt
        has_digest = "job_manifest_digest" in attempt
        if has_manifest == has_digest:
            raise InvalidTransitionError("agent job manifest binding is ambiguous")
        if has_manifest:
            legacy = attempt.get("job_manifest")
            if not isinstance(legacy, Mapping) or dict(legacy) != expected:
                raise InvalidTransitionError("legacy agent job manifest changed")
            attempt.pop("job_manifest")
            attempt["job_manifest_digest"] = expected_digest
        elif attempt.get("job_manifest_digest") != expected_digest:
            raise InvalidTransitionError("agent job manifest binding changed")
        if expected.get("job_ref") != attempt.get("job_ref"):
            raise InvalidTransitionError("agent job manifest job_ref changed")
        return expected

    def _require_active_agent_claim(
        self,
        attempt: Mapping[str, Any],
        claim_ref: str,
        result_ref: str,
    ) -> None:
        if (
            attempt.get("dispatch_state") != "claimed"
            or attempt.get("sink_state") != "open"
        ):
            raise InvalidTransitionError(
                "agent attempt must have an active claim before result acceptance"
            )
        if attempt.get("claim_ref") != claim_ref:
            raise RunConflictError("agent result is not bound to the active claim")
        if attempt.get("result_ref") != result_ref:
            raise RunConflictError("agent result_ref is not bound to the active claim")
        now = _parse_timestamp(self._state._now(), label="clock")
        if self._projection._claim_is_expired(attempt, now):
            raise InvalidTransitionError("agent claim lease expired before acceptance")

    def accept_agent_result(
        self,
        job_ref: str,
        attempt_ref: str,
        result: Mapping[str, Any],
        *,
        claim_ref: str,
        result_ref: str,
    ) -> dict[str, Any]:
        self._state.ensure_retention_active()
        normalized_job_ref = self._state._validate_ref(
            job_ref, RefType.JOB, label="job_ref"
        )
        normalized_attempt_ref = self._state._validate_ref(
            attempt_ref,
            RefType.ATTEMPT,
            label="attempt_ref",
        )
        normalized_claim_ref = self._state._validate_ref(
            claim_ref,
            RefType.CLAIM,
            label="claim_ref",
        )
        normalized_result_ref = self._state._validate_ref(
            result_ref,
            RefType.RESULT,
            label="result_ref",
        )
        if not isinstance(result, Mapping):
            raise InvalidInputError("agent result must be a mapping")
        result_value = _json_copy(dict(result), label="agent result")
        result_digest = content_digest(result_value)
        action_digest = content_digest(
            {
                "claim_ref": normalized_claim_ref,
                "attempt_ref": normalized_attempt_ref,
                "job_ref": normalized_job_ref,
                "result_digest": result_digest,
                "result_ref": normalized_result_ref,
            }
        )
        action_key = f"accept_agent_result:{normalized_attempt_ref}"
        result_staging = agent_results.Staging()

        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            self._state._require_retention_active_state(state)
            original_state = copy.deepcopy(state)
            replay = self._check_replay(state, action_key, action_digest)
            if replay:
                return self._finalize_agent_result_replay(
                    state,
                    original_state,
                    action_key=action_key,
                    attempt_ref=normalized_attempt_ref,
                    claim_ref=normalized_claim_ref,
                    job_ref=normalized_job_ref,
                    result_digest=result_digest,
                    result_ref=normalized_result_ref,
                    staging=result_staging,
                )
            task = self._projection._task_for_active_job(state, normalized_job_ref)
            if task.get("stage") != state["stage"]:
                raise InvalidTransitionError("agent job is not in the current stage")
            if task.get("status") != "runnable":
                raise InvalidTransitionError("agent job is not runnable")
            if task.get("active_attempt_ref") != normalized_attempt_ref:
                raise InvalidInputError("attempt_ref is not the active fresh attempt")
            attempt = self._projection._active_attempt(task, normalized_attempt_ref)
            self._bound_agent_job_manifest(state, task, attempt)
            self._require_active_agent_claim(
                attempt,
                normalized_claim_ref,
                normalized_result_ref,
            )

            accepted = False
            reason = ""
            validated: dict[str, Any] | None = None
            typed_gap: dict[str, str] | None = None
            if result_value.get("schema") == AGENT_FAILURE_SCHEMA:
                try:
                    failure = AgentFailure.from_dict(result_value)
                except (TypeError, ValueError):
                    reason = "schema_violation"
                else:
                    reason = failure.failure_kind.value
            else:
                try:
                    validated = self._history._validate_agent_result(
                        state,
                        task,
                        result_value,
                        attempt_ref=normalized_attempt_ref,
                    )
                    typed_gap = self._history._typed_agent_gap(
                        task,
                        validated,
                        attempt_ref=normalized_attempt_ref,
                    )
                    if typed_gap is None:
                        accepted = True
                    else:
                        reason = (
                            f"{typed_gap['reviewer_slot']}_review_gap"
                            if typed_gap["kind"] == "episode_review_gap"
                            else "adjudication_gap"
                        )
                except result_validation.ResultValidationError:
                    reason = "schema_violation"

            if accepted and validated is not None:
                attempt.update(
                    {
                        "completed_at": self._state._now(),
                        "dispatch_state": "completed",
                        "input_digest": result_digest,
                        "result_ref": normalized_result_ref,
                        "sink_state": "closed",
                        "status": "accepted",
                    }
                )
                task["active_attempt_ref"] = None
                task["active_job_ref"] = None
                state["metrics"]["agent_results"] += 1
                result_artifact, result_hash = result_staging.prepare(
                    self.run_dir, task, validated
                )
                task.update(
                    {
                        "accepted_attempt_ref": normalized_attempt_ref,
                        "accepted_job_ref": normalized_job_ref,
                        "binding": {
                            "attempt_ref": normalized_attempt_ref,
                            "claim_ref": normalized_claim_ref,
                            "input_digest": task["input_digest"],
                            "input_refs": copy.deepcopy(
                                agent_task_inputs.for_task(self.run_dir, task)[
                                    "input_refs"
                                ]
                            ),
                            "job_ref": normalized_job_ref,
                            "result_digest": result_digest,
                            "result_ref": normalized_result_ref,
                        },
                        "result_artifact": result_artifact,
                        "result_hash": result_hash,
                        "status": "accepted",
                    }
                )
                state["metrics"]["accepted_agent_results"] += 1
                outcome = "accepted"
            else:
                outcome = self._close_failed_agent_attempt(
                    state,
                    task,
                    attempt,
                    attempt_ref=normalized_attempt_ref,
                    result_digest=result_digest,
                    reason=reason,
                    typed_gap=typed_gap,
                    validated_gap=validated,
                )
            state["actions"][action_key] = {
                "binding": {
                    "attempt_ref": normalized_attempt_ref,
                    "claim_ref": normalized_claim_ref,
                    "job_ref": normalized_job_ref,
                    "result_digest": result_digest,
                    "result_ref": normalized_result_ref,
                },
                "input_digest": action_digest,
                "outcome": outcome,
                "reason": None if accepted else reason,
            }
            return agent_checkpoint_capacity.finalize_result(
                self.store,
                self._state,
                state,
                original_state,
                task,
                job_ref=normalized_job_ref,
                outcome=outcome,
                reason=None if accepted else reason,
                staging=result_staging,
            )

        transaction = result_staging.commit(self.store, mutate)
        response = self._projection._status_view(transaction.snapshot)
        response.update(
            {
                "action": "accept-agent-result",
                "changed": transaction.changed,
                **transaction.value,
            }
        )
        return response

    def reject_agent_result_payload(
        self,
        job_ref: str,
        attempt_ref: str,
        *,
        claim_ref: str,
        result_ref: str,
        payload_digest: str,
        reason: str,
    ) -> dict[str, Any]:
        self._state.ensure_retention_active()
        normalized_job_ref = self._state._validate_ref(
            job_ref, RefType.JOB, label="job_ref"
        )
        normalized_attempt_ref = self._state._validate_ref(
            attempt_ref,
            RefType.ATTEMPT,
            label="attempt_ref",
        )
        normalized_claim_ref = self._state._validate_ref(
            claim_ref,
            RefType.CLAIM,
            label="claim_ref",
        )
        normalized_result_ref = self._state._validate_ref(
            result_ref,
            RefType.RESULT,
            label="result_ref",
        )
        if _SHA256_RE.fullmatch(payload_digest) is None:
            raise InvalidInputError("agent payload digest is invalid")
        if reason not in {
            "duplicate_keys",
            "invalid_root_type",
            "malformed_json",
            "malformed_utf8",
            "result_too_large",
        }:
            raise InvalidInputError("agent payload rejection reason is invalid")
        action_key = f"accept_agent_result:{normalized_attempt_ref}"
        action_digest = content_digest(
            {
                "claim_ref": normalized_claim_ref,
                "attempt_ref": normalized_attempt_ref,
                "job_ref": normalized_job_ref,
                "result_digest": payload_digest,
                "result_ref": normalized_result_ref,
            }
        )

        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            self._state._require_retention_active_state(state)
            original_state = copy.deepcopy(state)
            replay = self._check_replay(state, action_key, action_digest)
            if replay:
                return self._finalize_agent_result_replay(
                    state,
                    original_state,
                    action_key=action_key,
                    attempt_ref=normalized_attempt_ref,
                    claim_ref=normalized_claim_ref,
                    job_ref=normalized_job_ref,
                    result_digest=payload_digest,
                    result_ref=normalized_result_ref,
                )
            task = self._projection._task_for_active_job(state, normalized_job_ref)
            if task.get("stage") != state["stage"]:
                raise InvalidTransitionError("agent job is not in the current stage")
            if task.get("status") != "runnable":
                raise InvalidTransitionError("agent job is not runnable")
            if task.get("active_attempt_ref") != normalized_attempt_ref:
                raise InvalidInputError("attempt_ref is not the active fresh attempt")
            attempt = self._projection._active_attempt(task, normalized_attempt_ref)
            self._bound_agent_job_manifest(state, task, attempt)
            self._require_active_agent_claim(
                attempt,
                normalized_claim_ref,
                normalized_result_ref,
            )
            outcome = self._close_failed_agent_attempt(
                state,
                task,
                attempt,
                attempt_ref=normalized_attempt_ref,
                result_digest=payload_digest,
                reason=reason,
            )
            state["actions"][action_key] = {
                "binding": {
                    "attempt_ref": normalized_attempt_ref,
                    "claim_ref": normalized_claim_ref,
                    "job_ref": normalized_job_ref,
                    "result_digest": payload_digest,
                    "result_ref": normalized_result_ref,
                },
                "input_digest": action_digest,
                "outcome": outcome,
                "reason": reason,
            }
            return agent_checkpoint_capacity.finalize_result(
                self.store,
                self._state,
                state,
                original_state,
                task,
                job_ref=normalized_job_ref,
                outcome=outcome,
                reason=reason,
            )

        transaction = self.store.transaction(mutate)
        response = self._projection._status_view(transaction.snapshot)
        response.update(
            {
                "action": "accept-agent-result",
                "changed": transaction.changed,
                **transaction.value,
            }
        )
        return response

    def resolve_agent_result_sink(
        self,
        job_ref: str,
        attempt_ref: str,
        *,
        claim_ref: str,
        result_ref: str,
        requested_path: str | os.PathLike[str],
    ) -> dict[str, str]:
        self._state.ensure_retention_active()
        normalized_job_ref = self._state._validate_ref(
            job_ref, RefType.JOB, label="job_ref"
        )
        normalized_attempt_ref = self._state._validate_ref(
            attempt_ref,
            RefType.ATTEMPT,
            label="attempt_ref",
        )
        normalized_claim_ref = self._state._validate_ref(
            claim_ref,
            RefType.CLAIM,
            label="claim_ref",
        )
        normalized_result_ref = self._state._validate_ref(
            result_ref,
            RefType.RESULT,
            label="result_ref",
        )
        state = self._state.load_state()
        task = self._projection._task_for_active_job(state, normalized_job_ref)
        if task.get("active_attempt_ref") != normalized_attempt_ref:
            raise InvalidInputError("attempt_ref is not the active fresh attempt")
        attempt = self._projection._active_attempt(task, normalized_attempt_ref)
        self._require_active_agent_claim(
            attempt,
            normalized_claim_ref,
            normalized_result_ref,
        )
        relative = attempt.get("output_sink_relative")
        expected_path = attempt.get("output_sink")
        if (
            not isinstance(relative, str)
            or Path(relative).parts[:1] != ("agent-sinks",)
            or len(Path(relative).parts) != 2
            or not isinstance(expected_path, str)
            or Path(expected_path).absolute() != (self.run_dir / relative).absolute()
            or Path(requested_path).expanduser().absolute()
            != Path(expected_path).absolute()
        ):
            raise RunConflictError(
                "agent result path is not the registered active-claim sink"
            )
        return {
            "output_sink": expected_path,
            "result_ref": normalized_result_ref,
        }

    def _close_failed_agent_attempt(
        self,
        state: dict[str, Any],
        task: dict[str, Any],
        attempt: dict[str, Any],
        *,
        attempt_ref: str,
        result_digest: str,
        reason: str,
        typed_gap: Mapping[str, str] | None = None,
        validated_gap: Mapping[str, Any] | None = None,
    ) -> str:
        attempt.update(
            {
                "completed_at": self._state._now(),
                "dispatch_state": "completed",
                "input_digest": result_digest,
                "reason": reason,
                "sink_state": "closed",
                "status": "review_gap" if typed_gap is not None else "failed",
            }
        )
        if typed_gap is not None and validated_gap is not None:
            attempt["typed_gap"] = copy.deepcopy(dict(typed_gap))
            task.setdefault("validated_gap_results", []).append(
                copy.deepcopy(dict(validated_gap))
            )
        task["active_attempt_ref"] = None
        task["active_job_ref"] = None
        state["metrics"]["agent_results"] += 1
        state["metrics"]["rejected_agent_results"] += 1
        if len(task["attempts"]) < 2:
            task["status"] = "retryable"
            return "retryable"
        task["status"] = "gap"
        self._state._append_gap(
            state,
            dependency_ref=task["task_ref"],
            reason=reason,
            stage=task["stage"],
            repairable=True,
            host_refs=task.get("host_refs", []),
            typed_gap=typed_gap,
        )
        return "gap"

    def _close_exhausted_agent_claim(
        self,
        state: dict[str, Any],
        task: dict[str, Any],
        attempt: dict[str, Any],
        *,
        attempt_ref: str,
        budget_digest: str,
    ) -> str:
        reason = "agent_claim_budget_exhausted"
        if attempt.get("attempt_ref") != attempt_ref:
            raise RunConflictError("agent claim budget attempt binding changed")
        attempt.update(
            {
                "claim_budget_digest": budget_digest,
                "completed_at": self._state._now(),
                "dispatch_state": "completed",
                "reason": reason,
                "sink_state": "closed",
                "status": "failed",
            }
        )
        task["active_attempt_ref"] = None
        task["active_job_ref"] = None
        state["metrics"]["agent_claim_budget_exhaustions"] = (
            int(state["metrics"].get("agent_claim_budget_exhaustions", 0)) + 1
        )
        if len(task["attempts"]) < 2:
            task["status"] = "retryable"
            return "retryable"
        task["status"] = "gap"
        self._state._append_gap(
            state,
            dependency_ref=task["task_ref"],
            reason=reason,
            stage=task["stage"],
            repairable=True,
            host_refs=task.get("host_refs", []),
        )
        return "gap"

    @staticmethod
    def _check_replay(
        state: Mapping[str, Any],
        action_key: str,
        input_digest: str,
    ) -> bool:
        previous = state["actions"].get(action_key)
        if previous is None:
            return False
        if previous.get("input_digest") != input_digest:
            raise RunConflictError("idempotency key was reused with different input")
        return True

    def _validate_agent_result_replay_binding(
        self,
        state: Mapping[str, Any],
        *,
        action_key: str,
        attempt_ref: str,
        claim_ref: str,
        job_ref: str,
        result_digest: str,
        result_ref: str,
    ) -> Mapping[str, Any]:
        action = state["actions"].get(action_key)
        expected_binding = {
            "attempt_ref": attempt_ref,
            "claim_ref": claim_ref,
            "job_ref": job_ref,
            "result_digest": result_digest,
            "result_ref": result_ref,
        }
        if not isinstance(action, Mapping) or action.get("binding") != expected_binding:
            raise RunConflictError("agent result replay binding changed")
        task_key, task, attempt = self._projection._agent_attempt_binding(
            state, job_ref, attempt_ref
        )
        ordinal = attempt.get("ordinal")
        generation = attempt.get("claim_generation")
        dispatcher_ref = attempt.get("dispatcher_ref")
        output_relative = attempt.get("output_sink_relative")
        expected_manifest = self._bound_agent_job_manifest(state, task, attempt)
        expected_attempt_ref = (
            None
            if expected_manifest is None
            else self._ref(RefType.ATTEMPT, state["run_ref"], job_ref, ordinal)
        )
        expected_claim_ref = (
            None
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 1
                or not isinstance(dispatcher_ref, str)
            )
            else self._ref(
                RefType.CLAIM,
                state["run_ref"],
                job_ref,
                attempt_ref,
                generation,
                dispatcher_ref,
            )
        )
        expected_result_ref = (
            None
            if expected_claim_ref is None or not isinstance(output_relative, str)
            else self._ref(
                RefType.RESULT,
                state["run_ref"],
                job_ref,
                attempt_ref,
                claim_ref,
                output_relative,
            )
        )
        if (
            task.get("category") != "agent"
            or task.get("task_ref") != task_key
            or attempt.get("job_ref") != job_ref
            or expected_manifest.get("job_ref") != job_ref
            or expected_attempt_ref != attempt_ref
            or attempt.get("claim_ref") != claim_ref
            or expected_claim_ref != claim_ref
            or attempt.get("result_ref") != result_ref
            or expected_result_ref != result_ref
            or attempt.get("output_sink") != str(self.run_dir / str(output_relative))
            or attempt.get("input_digest") != result_digest
            or attempt.get("dispatch_state") != "completed"
            or attempt.get("sink_state") != "closed"
            or attempt.get("status") not in {"accepted", "failed", "review_gap"}
        ):
            raise RunConflictError("agent result replay task binding changed")
        outcome = action.get("outcome")
        if outcome == "accepted":
            accepted_binding = task.get("binding")
            if (
                attempt.get("status") != "accepted"
                or task.get("status") != "accepted"
                or task.get("accepted_attempt_ref") != attempt_ref
                or task.get("accepted_job_ref") != job_ref
                or not isinstance(accepted_binding, Mapping)
                or any(
                    accepted_binding.get(key) != value
                    for key, value in expected_binding.items()
                )
            ):
                raise RunConflictError("accepted agent result replay binding changed")
            agent_results.require(self.run_dir, task)
        elif (
            outcome not in {"retryable", "gap"}
            or task.get("status") != outcome
            or attempt.get("status") not in {"failed", "review_gap"}
        ):
            raise RunConflictError("rejected agent result replay outcome changed")
        return task

    def _finalize_agent_result_replay(
        self,
        state: dict[str, Any],
        original_state: Mapping[str, Any],
        *,
        action_key: str,
        attempt_ref: str,
        claim_ref: str,
        job_ref: str,
        result_digest: str,
        result_ref: str,
        staging: agent_results.Staging | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        task = self._validate_agent_result_replay_binding(
            state,
            action_key=action_key,
            attempt_ref=attempt_ref,
            claim_ref=claim_ref,
            job_ref=job_ref,
            result_digest=result_digest,
            result_ref=result_ref,
        )
        action = state["actions"][action_key]
        return agent_checkpoint_capacity.finalize_result(
            self.store,
            self._state,
            state,
            original_state,
            task,
            job_ref=job_ref,
            outcome=action["outcome"],
            reason=action.get("reason"),
            staging=staging,
            changed=state != original_state,
            idempotent=True,
        )

    def _recompute_source_metrics(self, state: dict[str, Any]) -> None:
        accepted_cells = [
            cell
            for cell in self._projection._all_cells(state)
            if isinstance(cell.get("manifest"), Mapping)
        ]
        state["metrics"]["accepted_source_manifests"] = len(accepted_cells)
        state["metrics"]["source_records"] = sum(
            cell["metrics"]["record_count"] for cell in accepted_cells
        )
        state["metrics"]["source_bytes"] = sum(
            cell["metrics"]["byte_count"] for cell in accepted_cells
        )

    @staticmethod
    def _source_acceptance_digest(
        manifest: catalog.SourceTransportManifest,
        receipt: source_transport.TransportReceipt,
        payloads: Mapping[str, Mapping[str, Any]],
        transport_requests: Mapping[str, Sequence[SessionShardsRequest]] | None = None,
    ) -> str:
        payload_descriptors = {
            unit_ref: {
                "byte_count": descriptor["byte_count"],
                "content_commitment": descriptor["content_commitment"],
            }
            for unit_ref, descriptor in sorted(payloads.items())
        }
        requests = {
            source_ref: [request.to_dict() for request in source_requests]
            for source_ref, source_requests in sorted(
                (transport_requests or {}).items()
            )
        }
        return content_digest(
            {
                "manifest": manifest.to_dict(),
                "payloads": payload_descriptors,
                "transport_receipt": receipt.to_dict(),
                "transport_requests": requests,
            }
        )

    def _source_job_for_lease(
        self,
        state: Mapping[str, Any],
        lease_ref: str,
    ) -> dict[str, Any]:
        matches = [
            job
            for job in state["jobs"].values()
            if job.get("category") == "source" and job.get("lease_ref") == lease_ref
        ]
        if len(matches) != 1:
            raise InvalidInputError("unknown or ambiguous source lease")
        return matches[0]

    @staticmethod
    def _validate_authoritative_source_snapshot(
        manifest: catalog.SourceTransportManifest,
        snapshot: source_transport.AuthoritativeSourceSnapshot,
    ) -> None:
        if snapshot.terminal_status is not manifest.status:
            raise InvalidInputError(
                "source snapshot terminal status does not match manifest"
            )
        if snapshot.catalog_record_count != manifest.total_records:
            raise InvalidInputError(
                "source snapshot record count does not match manifest"
            )
        if snapshot.catalog_byte_count != manifest.total_bytes:
            raise InvalidInputError(
                "source snapshot byte count does not match manifest"
            )
        if snapshot.catalog_commitment != manifest.snapshot_commitment:
            raise InvalidInputError(
                "source snapshot catalog commitment does not match manifest"
            )
        if (
            manifest.status
            in {
                catalog.SourceCellStatus.COMPLETE,
                catalog.SourceCellStatus.NO_ACTIVITY,
                catalog.SourceCellStatus.VERIFIED_ABSENT,
            }
            and not snapshot.complete
        ):
            raise InvalidInputError(
                "terminal source manifest lacks authoritative terminal proof"
            )

    @staticmethod
    def _validate_received_transport_transcript(
        lease_ref: str,
        manifest: catalog.SourceTransportManifest,
        snapshot: source_transport.AuthoritativeSourceSnapshot,
        payloads: Mapping[str, Mapping[str, Any]],
    ) -> None:
        expected_transcript = catalog.transcript_descriptor_commitment(
            payloads,
            source_marker=lease_ref,
        )
        if (
            snapshot.transcript_commitment != expected_transcript
            or snapshot.source_content_commitment != expected_transcript
        ):
            raise InvalidInputError(
                "source transport receipt does not bind the received transcript"
            )
        received_bytes = sum(
            int(descriptor["byte_count"]) for descriptor in payloads.values()
        )
        if snapshot.source_byte_count != received_bytes:
            raise InvalidInputError(
                "source transport receipt byte count does not match the transcript"
            )
        if (
            manifest.status
            in {
                catalog.SourceCellStatus.COMPLETE,
                catalog.SourceCellStatus.NO_ACTIVITY,
                catalog.SourceCellStatus.VERIFIED_ABSENT,
            }
            and snapshot.terminal_byte_offset != received_bytes
        ):
            raise InvalidInputError(
                "source transport terminal offset does not match received bytes"
            )

    def _validate_source_binding(
        self,
        state: Mapping[str, Any],
        job: Mapping[str, Any],
        manifest: catalog.SourceTransportManifest,
    ) -> None:
        if manifest.host_ref != job["host_ref"]:
            raise InvalidInputError("source manifest host_ref does not match lease")
        if manifest.source_kind.value != job["source_kind"]:
            raise InvalidInputError("source manifest source_kind does not match lease")
        if (
            manifest.window_start != state["window"]["start"]
            or manifest.window_end != state["window"]["end"]
        ):
            raise InvalidInputError("source manifest window does not match run window")
        expected_transport = (
            catalog.TransportKind.LOCAL
            if job["host"] == "local"
            else catalog.TransportKind.REMOTE
        )
        if manifest.transport_kind is not expected_transport:
            raise InvalidInputError("source transport kind does not match host")
        lease = source_transport.TransportLease.from_dict(job["transport_lease"])
        if lease.lease_ref != job["lease_ref"]:
            raise InvalidInputError("source transport lease_ref does not match job")
        if manifest.remote is not None and (
            manifest.remote.process_nonce != lease.process_nonce
            or manifest.remote.forced_command_argv != lease.command_argv
        ):
            raise InvalidInputError(
                "remote source manifest is not bound to the forced transport command"
            )
        session_target = state.get("session_target")
        for record in manifest.records:
            self._projection._validate_external_ref(record.unit_ref, "source_unit")
            if (
                state.get("mode") == RunMode.SESSION.value
                and record.coordinate.source_ref != session_target
                and (
                    record.accounting_class
                    is not catalog.AccountingClass.STRUCTURALLY_EXCLUDED
                    or record.exclusion_reason
                    is not catalog.StructuralExclusionReason.SOURCE_POLICY_EXCLUDED
                )
            ):
                raise InvalidInputError(
                    "session-mode source record does not match session_target"
                )
