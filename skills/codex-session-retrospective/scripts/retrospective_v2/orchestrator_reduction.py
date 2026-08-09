"""Catalog materialization and episode, topic, and synthesis reduction."""

from __future__ import annotations
from collections import defaultdict
import copy
from dataclasses import replace
import heapq
from typing import Any, Callable, Iterable, Mapping, Sequence
from . import (
    agent_results,
    agent_task_inputs,
    authority,
    catalog,
    controlled_gaps,
    episode_review,
    extracted_turns,
    raw_shard_staging,
    result_validation,
    sharding,
    source_inputs,
    source_payloads,
)
from .checkpoints import canonical_json_bytes
from .contracts import JobKind, RefType, RunStage, SourceKind
from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_protocols import (
    ReductionJobsPort,
    ReductionProjectionPort,
    ReductionStatePort,
)

from .orchestrator_support import (
    InvalidTransitionError,
    RAW_SHARD_DIRECTORY,
    _safe_reason,
)


class HierarchicalReductionOperations(OrchestratorComponent):
    def __init__(
        self,
        context: RuntimeContext,
        *,
        state: ReductionStatePort,
        projection: ReductionProjectionPort,
        jobs: ReductionJobsPort,
    ) -> None:
        super().__init__(context)
        self._state = state
        self._projection = projection
        self._jobs = jobs

    def _task_metadata(self, task: Mapping[str, Any]) -> Mapping[str, Any]:
        return agent_task_inputs.for_task(self.run_dir, task)["metadata"]

    def _accepted_source_inputs(
        self,
        state: Mapping[str, Any],
    ) -> tuple[
        list[catalog.SourceTransportManifest],
        dict[str, Mapping[str, Any]],
        dict[str, str],
        dict[str, list[str]],
    ]:
        transport_manifests: list[catalog.SourceTransportManifest] = []
        payload_state: dict[str, Mapping[str, Any]] = {}
        model_era_by_unit: dict[str, str] = {}
        model_eras_by_session: dict[str, set[str]] = {}
        for cells in state["source"]["cells"].values():
            for cell in cells.values():
                descriptors = cell.get("continuation_segments")
                if (
                    not isinstance(descriptors, Sequence)
                    or isinstance(descriptors, (str, bytes))
                    or not descriptors
                ):
                    raise InvalidTransitionError(
                        "accepted source cell lacks sidecar descriptors"
                    )
                materialized = source_inputs.materialize_segments(
                    self.run_dir,
                    descriptors,
                )
                manifest, _snapshot_ref, _receipt_ref = (
                    source_inputs.aggregate_segments(
                        self.identity,
                        self.run_dir,
                        descriptors,
                    )
                )
                if not source_inputs.manifest_matches_persisted(
                    cell.get("manifest"), manifest
                ):
                    raise InvalidTransitionError(
                        "accepted source cell differs from its sidecar manifest"
                    )
                transport_manifests.append(manifest)
                payload_state = source_payloads.merge_payload_indexes(
                    payload_state,
                    materialized["payloads"],
                    cell.get("payloads", {}),
                )

                for unit_ref, model_era in materialized["model_era_by_unit"].items():
                    existing = model_era_by_unit.get(unit_ref)
                    if existing is not None and existing != model_era:
                        raise InvalidTransitionError(
                            "accepted source model-era index changed"
                        )
                    model_era_by_unit[unit_ref] = model_era
                for session_ref, model_eras in materialized[
                    "model_eras_by_session"
                ].items():
                    model_eras_by_session.setdefault(session_ref, set()).update(
                        model_eras
                    )

        legacy_unit_eras = state["source"].get("model_era_by_unit", {})
        if isinstance(legacy_unit_eras, Mapping):
            for unit_ref, model_era in legacy_unit_eras.items():
                if isinstance(unit_ref, str) and isinstance(model_era, str):
                    existing = model_era_by_unit.get(unit_ref)
                    if existing is not None and existing != model_era:
                        raise InvalidTransitionError(
                            "accepted source model-era index changed"
                        )
                    model_era_by_unit[unit_ref] = model_era
        legacy_session_eras = state["source"].get("model_eras_by_session", {})
        if isinstance(legacy_session_eras, Mapping):
            for session_ref, model_eras in legacy_session_eras.items():
                if isinstance(session_ref, str) and isinstance(model_eras, Sequence):
                    if isinstance(model_eras, (str, bytes)):
                        continue
                    model_eras_by_session.setdefault(session_ref, set()).update(
                        value for value in model_eras if isinstance(value, str)
                    )
        return (
            transport_manifests,
            payload_state,
            model_era_by_unit,
            {key: sorted(values) for key, values in model_eras_by_session.items()},
        )

    def _freeze_catalog_and_materialize(
        self,
        state: dict[str, Any],
        *,
        raw_stages: list[
            tuple[
                Callable[[], sharding.RawShardStageReceipt],
                Callable[[sharding.RawShardStageReceipt], None],
            ]
        ],
    ) -> None:
        (
            transport_manifests,
            payload_state,
            model_era_by_unit,
            model_eras_by_session,
        ) = self._accepted_source_inputs(state)

        all_records = [
            record for manifest in transport_manifests for record in manifest.records
        ]
        deduplicated = catalog.deduplicate_active_archived(all_records)
        records_by_ref = {record.unit_ref: record for record in deduplicated}
        payload_gap_reasons: dict[str, str] = {}
        for unit_ref, record in list(records_by_ref.items()):
            if (
                record.accounting_class
                is not catalog.AccountingClass.CONSUMED_CANDIDATE
            ):
                continue
            payload = payload_state.get(unit_ref, {})
            if payload.get("status") == "available":
                continue
            fallback = self._payload_for_equivalent_record(
                record,
                all_records,
                payload_state,
            )
            if fallback is not None:
                payload_state[unit_ref] = fallback
                continue
            reason = _safe_reason(payload.get("reason"), fallback="raw_payload_missing")
            payload_gap_reasons[unit_ref] = reason
            records_by_ref[unit_ref] = replace(
                record,
                accounting_class=catalog.AccountingClass.EXPLICIT_GAP,
                exclusion_reason=None,
                duplicate_of=None,
                gap=catalog.ExplicitGap(reason=reason, stage="sharding"),
            )

        normalized_manifests = self._rebuild_manifests(
            transport_manifests,
            records_by_ref,
        )
        source_catalog = catalog.SourceCatalog.create(normalized_manifests)
        source_catalog.validate_required_matrix(state["host_refs"].values())
        source_catalog = catalog.SourceCatalog.from_dict(source_catalog.to_dict())

        candidates = [
            record
            for manifest in source_catalog.manifests
            for record in manifest.records
            if record.accounting_class is catalog.AccountingClass.CONSUMED_CANDIDATE
        ]
        limits = self._projection._shard_limits_from_state(state)
        raw_stage = raw_shard_staging.prepare(
            self.run_dir,
            candidates,
            payload_state,
            limits,
        )
        planned = raw_stage.plan
        raw_stages.append((raw_stage.materialize, raw_stage.rollback))

        if planned.gaps:
            for gap in planned.gaps:
                record = records_by_ref[gap.unit_ref]
                records_by_ref[gap.unit_ref] = gap.as_catalog_gap(record)
            normalized_manifests = self._rebuild_manifests(
                transport_manifests,
                records_by_ref,
            )
            source_catalog = catalog.SourceCatalog.create(normalized_manifests)
            source_catalog.validate_required_matrix(state["host_refs"].values())
            source_catalog = catalog.SourceCatalog.from_dict(source_catalog.to_dict())

        state["source"]["catalog"] = source_catalog.to_dict()
        state["source"]["materialization"] = planned.to_manifest_dict()
        state["source"]["shards"] = {
            manifest.shard_ref: {
                "manifest": manifest.to_dict(),
                "relative_path": f"{RAW_SHARD_DIRECTORY}/{manifest.file_name}",
            }
            for manifest in planned.shards
        }
        state["source"]["reassembly"] = self._build_turn_reassembly(
            state,
            planned,
            source_catalog,
            model_era_by_unit=model_era_by_unit,
            model_eras_by_session=model_eras_by_session,
        )
        self._apply_catalog_cells_and_gaps(state, source_catalog)
        self._recompute_frozen_metrics(state, source_catalog, planned)
        state["metrics"]["sharding_peak_working_bytes"] = (
            planned.peak_working_byte_count
        )
        for manifest in planned.shards:
            self._create_extractor_task(state, manifest)

    @staticmethod
    def _payload_for_equivalent_record(
        record: catalog.CatalogRecord,
        original_records: Sequence[catalog.CatalogRecord],
        payload_state: Mapping[str, Mapping[str, Any]],
    ) -> Mapping[str, Any] | None:
        for candidate in original_records:
            if (
                candidate.coordinate == record.coordinate
                and candidate.content_commitment == record.content_commitment
                and payload_state.get(candidate.unit_ref, {}).get("status")
                == "available"
            ):
                return payload_state[candidate.unit_ref]
        return None

    def _rebuild_manifests(
        self,
        originals: Sequence[catalog.SourceTransportManifest],
        records_by_ref: Mapping[str, catalog.CatalogRecord],
    ) -> list[catalog.SourceTransportManifest]:
        rebuilt: list[catalog.SourceTransportManifest] = []
        for original in originals:
            records = tuple(records_by_ref[item.unit_ref] for item in original.records)
            has_gap = any(
                item.accounting_class is catalog.AccountingClass.EXPLICIT_GAP
                for item in records
            )
            status = (
                catalog.SourceCellStatus.GAP
                if has_gap or original.status is catalog.SourceCellStatus.GAP
                else original.status
            )
            snapshot = original.snapshot_commitment
            if snapshot is not None:
                snapshot = catalog.snapshot_commitment_for_records(records)
            rebuilt.append(
                catalog.SourceTransportManifest.create(
                    absence_proof=original.absence_proof,
                    enumeration_gap=original.enumeration_gap,
                    host_ref=original.host_ref,
                    records=records,
                    remote=original.remote,
                    snapshot_commitment=snapshot,
                    source_kind=original.source_kind,
                    status=status,
                    transport_kind=original.transport_kind,
                    window_end=original.window_end,
                    window_start=original.window_start,
                )
            )
        return rebuilt

    def _apply_catalog_cells_and_gaps(
        self,
        state: dict[str, Any],
        source_catalog: catalog.SourceCatalog,
    ) -> None:
        host_by_ref = {value: key for key, value in state["host_refs"].items()}
        for manifest in source_catalog.manifests:
            host = host_by_ref[manifest.host_ref]
            source_kind = manifest.source_kind.value
            cell = state["source"]["cells"][host][source_kind]
            cell["status"] = manifest.status.value
            if manifest.status is catalog.SourceCellStatus.GAP:
                reason = (
                    manifest.enumeration_gap.reason
                    if manifest.enumeration_gap is not None
                    else "source_unit_gap"
                )
                self._state._append_gap(
                    state,
                    dependency_ref=cell["snapshot_ref"],
                    reason=reason,
                    stage=RunStage.SHARDING.value,
                    repairable=True,
                    host_refs=[manifest.host_ref],
                    source_kind=source_kind,
                )
            for record in manifest.records:
                if (
                    record.accounting_class is catalog.AccountingClass.EXPLICIT_GAP
                    and record.gap is not None
                ):
                    self._state._append_gap(
                        state,
                        dependency_ref=record.unit_ref,
                        reason=record.gap.reason,
                        stage=record.gap.stage,
                        repairable=record.gap.repairable,
                        host_refs=[manifest.host_ref],
                        source_kind=source_kind,
                    )

    def _recompute_frozen_metrics(
        self,
        state: dict[str, Any],
        source_catalog: catalog.SourceCatalog,
        materialized: sharding.ShardPlan,
    ) -> None:
        counts = source_catalog.accounting_counts()
        records = [
            record
            for manifest in source_catalog.manifests
            for record in manifest.records
        ]
        state["metrics"].update(
            {
                "accounting": counts,
                "discovered_source_bytes": sum(item.byte_count for item in records),
                "discovered_source_units": len(records),
                "materialized_raw_bytes": materialized.materialized_raw_bytes,
                "materialized_shards": len(materialized.shards),
                "source_unit_gap_bytes": sum(
                    item.byte_count
                    for item in records
                    if item.accounting_class is catalog.AccountingClass.EXPLICIT_GAP
                ),
            }
        )

    def _record_unmaterialized_catalog_metrics(self, state: dict[str, Any]) -> None:
        manifests, _payloads, _unit_eras, _session_eras = self._accepted_source_inputs(
            state
        )
        records = [record for manifest in manifests for record in manifest.records]
        accounting = {
            accounting_class.value: sum(
                record.accounting_class is accounting_class for record in records
            )
            for accounting_class in catalog.AccountingClass
        }
        state["metrics"].update(
            {
                "accounting": accounting,
                "discovered_source_bytes": sum(record.byte_count for record in records),
                "discovered_source_units": len(records),
                "materialized_raw_bytes": 0,
                "materialized_shards": 0,
                "source_unit_gap_bytes": sum(
                    record.byte_count
                    for record in records
                    if record.accounting_class is catalog.AccountingClass.EXPLICIT_GAP
                ),
            }
        )

    def _build_turn_reassembly(
        self,
        state: Mapping[str, Any],
        materialized: sharding.ShardPlan,
        source_catalog: catalog.SourceCatalog,
        *,
        model_era_by_unit: Mapping[str, str],
        model_eras_by_session: Mapping[str, Sequence[str]],
    ) -> dict[str, dict[str, Any]]:
        source_precedence = {
            SourceKind.ACTIVE_ROLLOUT: 0,
            SourceKind.ARCHIVED_ROLLOUT: 1,
            SourceKind.HISTORY: 2,
            SourceKind.SESSION_INDEX: 3,
        }
        consumed = [
            record
            for manifest in source_catalog.manifests
            for record in manifest.records
            if record.accounting_class is catalog.AccountingClass.CONSUMED_CANDIDATE
        ]
        sequence_by_unit: dict[str, int] = {}
        records_by_session: dict[str, list[catalog.CatalogRecord]] = {}
        for record in consumed:
            records_by_session.setdefault(record.coordinate.source_ref, []).append(
                record
            )
        for records in records_by_session.values():
            physical_groups: dict[tuple[object, ...], list[catalog.CatalogRecord]] = {}
            for record in records:
                identity = catalog.rollout_record_identity(record.coordinate.record_ref)
                physical_occurrence = (
                    record.coordinate.record_ref if identity is None else identity[0]
                )
                physical_key = (
                    record.coordinate.host_ref,
                    SourceKind(record.source_kind).value,
                    physical_occurrence,
                )
                physical_groups.setdefault(physical_key, []).append(record)

            ordered_groups = [
                sorted(
                    group,
                    key=lambda record: (
                        record.coordinate.byte_start,
                        record.coordinate.byte_end,
                        record.coordinate.record_ref,
                        record.unit_ref,
                    ),
                )
                for _key, group in sorted(physical_groups.items())
            ]

            frontier: list[tuple[tuple[object, ...], int, int]] = []

            def push(group_index: int, record_index: int) -> None:
                record = ordered_groups[group_index][record_index]
                heapq.heappush(
                    frontier,
                    (
                        (
                            record.event_time,
                            source_precedence.get(SourceKind(record.source_kind), 99),
                            record.coordinate.host_ref,
                            (
                                catalog.rollout_record_identity(
                                    record.coordinate.record_ref
                                )
                                or (record.coordinate.record_ref, "")
                            )[0],
                            record.coordinate.byte_start,
                            record.coordinate.byte_end,
                            record.coordinate.record_ref,
                            record.unit_ref,
                        ),
                        group_index,
                        record_index,
                    ),
                )

            for group_index in range(len(ordered_groups)):
                push(group_index, 0)

            ordered: list[catalog.CatalogRecord] = []
            while frontier:
                _key, group_index, record_index = heapq.heappop(frontier)
                ordered.append(ordered_groups[group_index][record_index])
                next_index = record_index + 1
                if next_index < len(ordered_groups[group_index]):
                    push(group_index, next_index)
            for sequence, record in enumerate(ordered):
                sequence_by_unit[record.unit_ref] = sequence

        plan: dict[str, dict[str, Any]] = {}
        for manifest in materialized.shards:
            for descriptor in manifest.ranges:
                try:
                    sequence = sequence_by_unit[descriptor.unit_ref]
                except KeyError as exc:
                    raise InvalidTransitionError(
                        "materialized source unit is absent from the frozen catalog"
                    ) from exc
                coordinate = descriptor.coordinate.to_dict()
                turn_ref = self._ref(
                    RefType.TURN,
                    "logical_source_record_v2",
                    coordinate,
                    descriptor.record_commitment,
                )
                session_ref = (
                    descriptor.coordinate.source_ref
                    if self._projection._is_external_ref(
                        descriptor.coordinate.source_ref, "session"
                    )
                    else self._ref(
                        RefType.SESSION,
                        descriptor.coordinate.host_ref,
                        descriptor.coordinate.source_ref,
                    )
                )
                unit_model_era = model_era_by_unit.get(descriptor.unit_ref)
                session_model_eras = model_eras_by_session.get(session_ref, [])
                if isinstance(unit_model_era, str):
                    model_era = unit_model_era
                elif len(session_model_eras) == 1:
                    model_era = session_model_eras[0]
                elif session_model_eras:
                    model_era = self._projection.MIXED_MODEL_ERA
                else:
                    model_era = self._projection.UNKNOWN_MODEL_ERA
                entry = plan.setdefault(
                    turn_ref,
                    {
                        "canonical_time": descriptor.event_time,
                        "contributors": [],
                        "coordinate": coordinate,
                        "fragment_count": descriptor.fragment_count,
                        "goal_ref": self._ref(RefType.GOAL, session_ref, turn_ref),
                        "model_era": model_era,
                        "record_commitment": descriptor.record_commitment,
                        "sequence": sequence,
                        "session_ref": session_ref,
                        "source_unit_ref": descriptor.unit_ref,
                        "turn_ref": turn_ref,
                        "workstream_ref": self._ref(
                            RefType.WORKSTREAM,
                            descriptor.coordinate.host_ref,
                            descriptor.coordinate.source_ref,
                        ),
                    },
                )
                expected = {
                    "coordinate": coordinate,
                    "fragment_count": descriptor.fragment_count,
                    "model_era": model_era,
                    "record_commitment": descriptor.record_commitment,
                    "source_unit_ref": descriptor.unit_ref,
                }
                if any(entry[key] != value for key, value in expected.items()):
                    raise InvalidTransitionError(
                        "logical turn fragments do not share one stable record identity"
                    )
                evidence_ref = self._ref(
                    RefType.EVIDENCE,
                    turn_ref,
                    descriptor.fragment_index,
                    descriptor.fragment_commitment,
                )
                span_ref = self._ref(
                    RefType.SPAN_COMMITMENT,
                    descriptor.fragment_commitment,
                )
                entry["contributors"].append(
                    {
                        "evidence_ref": evidence_ref,
                        "fragment_commitment": descriptor.fragment_commitment,
                        "fragment_index": descriptor.fragment_index,
                        "shard_ref": manifest.shard_ref,
                        "span_ref": span_ref,
                    }
                )
        for turn_ref, entry in plan.items():
            contributors = sorted(
                entry["contributors"],
                key=lambda item: (item["fragment_index"], item["shard_ref"]),
            )
            indexes = [item["fragment_index"] for item in contributors]
            if indexes != list(range(entry["fragment_count"])):
                raise InvalidTransitionError(
                    "logical turn reassembly plan is incomplete or duplicated"
                )
            if len({item["shard_ref"] for item in contributors}) != len(contributors):
                raise InvalidTransitionError(
                    "one shard cannot contribute duplicate logical turn fragments"
                )
            entry["contributors"] = contributors
            plan[turn_ref] = entry
        return dict(sorted(plan.items()))

    def _create_extractor_task(
        self,
        state: dict[str, Any],
        manifest: sharding.ShardManifest,
    ) -> None:
        unit_metadata: dict[str, dict[str, Any]] = {}
        allowed_refs: set[str] = set()
        host_refs: set[str] = set()
        for descriptor in manifest.ranges:
            turn_ref = self._ref(
                RefType.TURN,
                "logical_source_record_v2",
                descriptor.coordinate.to_dict(),
                descriptor.record_commitment,
            )
            global_metadata = state["source"]["reassembly"].get(turn_ref)
            if not isinstance(global_metadata, Mapping):
                raise InvalidTransitionError(
                    "extractor shard is missing its logical turn reassembly plan"
                )
            contributor = next(
                (
                    item
                    for item in global_metadata["contributors"]
                    if item["shard_ref"] == manifest.shard_ref
                    and item["fragment_index"] == descriptor.fragment_index
                ),
                None,
            )
            if contributor is None:
                raise InvalidTransitionError(
                    "extractor shard fragment is not bound to the reassembly plan"
                )
            host_refs.add(descriptor.coordinate.host_ref)
            metadata = unit_metadata.setdefault(
                turn_ref,
                {
                    "canonical_time": global_metadata["canonical_time"],
                    "evidence_refs": [],
                    "fragment_count": global_metadata["fragment_count"],
                    "fragment_indexes": [],
                    "goal_ref": global_metadata["goal_ref"],
                    "record_commitment": global_metadata["record_commitment"],
                    "sequence": global_metadata["sequence"],
                    "session_ref": global_metadata["session_ref"],
                    "source_unit_ref": global_metadata["source_unit_ref"],
                    "span_refs": [],
                    "turn_ref": turn_ref,
                    "workstream_ref": global_metadata["workstream_ref"],
                },
            )
            metadata["evidence_refs"].append(contributor["evidence_ref"])
            metadata["fragment_indexes"].append(contributor["fragment_index"])
            metadata["span_refs"].append(contributor["span_ref"])
        for metadata in unit_metadata.values():
            metadata["evidence_refs"] = sorted(set(metadata["evidence_refs"]))
            metadata["fragment_indexes"] = sorted(set(metadata["fragment_indexes"]))
            metadata["span_refs"] = sorted(set(metadata["span_refs"]))
            allowed_refs.update(
                {
                    metadata["goal_ref"],
                    metadata["session_ref"],
                    metadata["source_unit_ref"],
                    metadata["turn_ref"],
                    metadata["workstream_ref"],
                    *metadata["evidence_refs"],
                    *metadata["span_refs"],
                }
            )
        framing = {
            "allowed_output_refs": sorted(
                value for value in allowed_refs if isinstance(value, str)
            ),
            "result_schema": result_validation.EXTRACTOR_RESULT_SCHEMA,
            "schema": "extractor_control_v2",
            "shard_ref": manifest.shard_ref,
        }
        self._jobs._create_agent_task(
            state,
            stage=RunStage.EXTRACTION.value,
            kind=JobKind.EXTRACTOR_REDACTOR.value,
            partition_ref=manifest.shard_ref,
            input_refs=[manifest.shard_ref],
            input_payload=None,
            allowed_refs=(value for value in allowed_refs if isinstance(value, str)),
            allowed_turn_refs=unit_metadata,
            host_refs=host_refs,
            metadata={"turn_metadata": unit_metadata},
            raw_manifest=manifest.to_dict(),
            raw_artifact=f"{RAW_SHARD_DIRECTORY}/{manifest.file_name}",
            framing=framing,
        )

    def _construct_episode_revisions(self, state: dict[str, Any]) -> None:
        enriched_turns: list[dict[str, Any]] = []
        contributions: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        gapped_shards: set[str] = set()
        for task in self._projection._tasks_for_stage(state, RunStage.EXTRACTION.value):
            if task["status"] != "accepted":
                continue
            result = agent_results.require(self.run_dir, task, label="extractor")
            if "gap_reason" in result:
                self._state._append_gap(
                    state,
                    dependency_ref=task["task_ref"],
                    reason=result["gap_reason"],
                    stage=RunStage.EXTRACTION.value,
                    repairable=True,
                    host_refs=task.get("host_refs", []),
                )
                gapped_shards.add(task["partition_ref"])
                continue
            metadata_by_turn = self._task_metadata(task)["turn_metadata"]
            for turn in result["turns"]:
                turn_ref = turn["turn_ref"]
                if task["partition_ref"] in contributions[turn_ref]:
                    raise InvalidTransitionError(
                        "extractor task duplicated a logical turn contribution"
                    )
                contributions[turn_ref][task["partition_ref"]] = {
                    "metadata": copy.deepcopy(metadata_by_turn[turn_ref]),
                    "turn": copy.deepcopy(turn),
                }
        reassembled: dict[str, dict[str, Any]] = {}
        for turn_ref, plan in sorted(state["source"]["reassembly"].items()):
            expected_shards = {item["shard_ref"] for item in plan["contributors"]}
            actual = contributions.get(turn_ref, {})
            missing_shards = expected_shards - set(actual)
            if set(actual) - expected_shards or missing_shards - gapped_shards:
                raise InvalidTransitionError(
                    "logical turn reassembly is missing an accepted shard contribution"
                )
            if missing_shards:
                continue
            turn = self._reassemble_turn(plan, actual)
            reassembled[turn_ref] = turn
            hint = turn.get("meaningfulness_hint", "meaningful")
            meaningfulness = {
                "context_only": "context_only",
                "meaningful": "meaningful",
                "uncertain": "meaningfulness_gap",
            }[hint]
            enriched_turns.append(
                {
                    "canonical_time": plan["canonical_time"],
                    "confidence": turn["confidence"],
                    "conflicting_signals": turn.get("conflicting_signals", False),
                    "extraction_confidence": turn["confidence"],
                    "goal_change": turn.get("goal_change", "continues"),
                    "goal_ref": turn.get("goal_ref", plan["goal_ref"]),
                    "meaningfulness": meaningfulness,
                    "repository_responsibility_change": False,
                    "risk_flags": copy.deepcopy(turn["risk_flags"]),
                    "segmentation_confidence": turn["confidence"],
                    "sequence": plan["sequence"],
                    "session_ref": plan["session_ref"],
                    "task_completed": turn.get("task_completed", False),
                    "turn_ref": turn_ref,
                    "user_redirect": turn.get("user_redirect", False),
                    "workstream_change": turn.get("workstream_change", False),
                    "workstream_ref": turn.get(
                        "workstream_ref", plan["workstream_ref"]
                    ),
                }
            )
        self._resolve_semantic_turn_refs(enriched_turns)
        if reassembled:
            descriptor, prepared = extracted_turns.prepare(self.run_dir, reassembled)
            self._jobs._stage_run_file(prepared.path, prepared.payload)
            state["extracted_turns"] = descriptor
        else:
            state["extracted_turns"] = {}
        try:
            episodes = episode_review.construct_episodes(enriched_turns)
            self._bind_episode_revisions(state, episodes)
        except result_validation.ResultValidationError as error:
            self._state._append_gap(
                state,
                dependency_ref=state["run_ref"],
                reason="episode_construction_failure",
                stage=RunStage.EXTRACTION.value,
                repairable=True,
            )
            if not self._projection._partial_can_continue(state):
                raise InvalidTransitionError(
                    "episode construction rejected validated extraction"
                ) from error

    def _resolve_semantic_turn_refs(self, turns: Sequence[dict[str, Any]]) -> None:
        by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for turn in turns:
            by_session[turn["session_ref"]].append(turn)
        for session_ref, session_turns in by_session.items():
            session_turns.sort(
                key=lambda item: (
                    item["canonical_time"],
                    item["sequence"],
                    item["turn_ref"],
                )
            )
            current_goal_ref: str | None = None
            current_workstream_ref: str | None = None
            for turn in session_turns:
                if current_goal_ref is None or turn["goal_change"] in {
                    "completed_then_new",
                    "new_goal",
                    "redirected",
                    "unknown",
                }:
                    current_goal_ref = turn["goal_ref"]
                turn["goal_ref"] = current_goal_ref
                if current_workstream_ref is None:
                    current_workstream_ref = turn["workstream_ref"]
                elif turn["workstream_change"]:
                    current_workstream_ref = self._ref(
                        RefType.WORKSTREAM,
                        session_ref,
                        turn["turn_ref"],
                    )
                turn["workstream_ref"] = current_workstream_ref

    def _bind_episode_revisions(
        self,
        state: dict[str, Any],
        episodes: Sequence[Mapping[str, Any]],
    ) -> None:
        backfill_of = state["lineage"]["backfill_of"]
        prior_heads = {
            item["episode_ref"]: copy.deepcopy(item)
            for item in state["lineage"]["prior_episode_heads"]
        }
        proposed_heads = copy.deepcopy(prior_heads)
        matched_prior_refs: set[str] = set()
        revisions: list[dict[str, Any]] = []
        for episode in episodes:
            candidates = self._backfill_predecessor_candidates(
                episode,
                prior_heads.values(),
                state["lineage"]["prior_episode_membership"],
            )
            if len(candidates) > 1:
                raise result_validation.ResultValidationError(
                    "episode must match exactly one authenticated prior head"
                )
            if not candidates:
                if backfill_of is not None:
                    self._validate_new_backfill_episode_host(state, episode)
                revision = episode_review.create_episode_revision(
                    episode,
                    identity_key=self.identity,
                    key_id=self.identity.key_id,
                )
                if revision["episode_ref"] in proposed_heads:
                    raise result_validation.ResultValidationError(
                        "new episode collides with an unmatched durable anchor"
                    )
                revisions.append(revision)
                proposed_heads[revision["episode_ref"]] = copy.deepcopy(revision)
                continue
            previous = candidates[0]
            if previous["episode_ref"] in matched_prior_refs:
                raise result_validation.ResultValidationError(
                    "one durable episode cannot split into multiple ordinary revisions"
                )
            matched_prior_refs.add(previous["episode_ref"])
            merged = self._merge_episode_evidence(state, previous, episode)
            successor = episode_review.create_episode_revision(
                merged,
                identity_key=self.identity,
                key_id=self.identity.key_id,
                previous_revision=previous,
            )
            if successor["episode_revision_ref"] == previous["episode_revision_ref"]:
                continue
            revisions.append(successor)
            proposed_heads[previous["episode_ref"]] = copy.deepcopy(successor)
        revisions.sort(key=lambda item: item["episode_ref"])
        full_projection = sorted(
            proposed_heads.values(),
            key=lambda item: item["episode_ref"],
        )
        state["episodes"] = revisions
        state["lineage"]["proposed_episode_heads"] = full_projection
        state["lineage"]["proposed_episode_head_set_ref"] = (
            authority.derive_episode_head_root(
                full_projection,
                identity=self.identity,
            )
        )
        if backfill_of is not None:
            gap_receipt = state["lineage"].get("controlled_gap_receipt")
            expected_ref = state["lineage"]["expected_episode_head_set_ref"]
            proposed_ref = state["lineage"]["proposed_episode_head_set_ref"]
            if (
                not isinstance(gap_receipt, Mapping)
                or not isinstance(expected_ref, str)
                or not isinstance(proposed_ref, str)
            ):
                raise result_validation.ResultValidationError(
                    "backfill lineage is missing authenticated CAS inputs"
                )
            lineage_receipt = controlled_gaps.issue_backfill_lineage_receipt(
                self.identity,
                controlled_gap_receipt=gap_receipt,
                expected_episode_head_set_ref=expected_ref,
                proposed_episode_head_set_ref=proposed_ref,
                prior_episode_heads=state["lineage"]["prior_episode_heads"],
                proposed_episode_heads=full_projection,
                expected_backlog_ref=state["lineage"].get("expected_backlog_ref"),
            )
            state["lineage"]["backfill_lineage_receipt"] = lineage_receipt.to_dict()

    @staticmethod
    def _validate_new_backfill_episode_host(
        state: Mapping[str, Any],
        episode: Mapping[str, Any],
    ) -> None:
        gap_receipt = state["lineage"].get("controlled_gap_receipt")
        if not isinstance(gap_receipt, Mapping):
            raise result_validation.ResultValidationError(
                "new backfill episode lacks a controlled missing-host receipt"
            )
        host_ref = gap_receipt.get("host_ref")
        reassembly = state.get("source", {}).get("reassembly", {})
        observed_hosts: set[str] = set()
        for turn_ref in episode["turn_refs"]:
            plan = reassembly.get(turn_ref)
            coordinate = (
                None if not isinstance(plan, Mapping) else plan.get("coordinate")
            )
            if not isinstance(coordinate, Mapping) or not isinstance(
                coordinate.get("host_ref"), str
            ):
                raise result_validation.ResultValidationError(
                    "new backfill episode turn lacks authenticated host provenance"
                )
            observed_hosts.add(coordinate["host_ref"])
        if not observed_hosts or observed_hosts != {host_ref}:
            raise result_validation.ResultValidationError(
                "new backfill episode is not confined to the controlled missing host"
            )

    @staticmethod
    def _backfill_predecessor_candidates(
        episode: Mapping[str, Any],
        prior_heads: Iterable[Mapping[str, Any]],
        prior_membership: Sequence[Mapping[str, str]],
    ) -> list[dict[str, Any]]:
        heads_by_ref = {head["episode_ref"]: dict(head) for head in prior_heads}
        semantic_anchors = {
            ref for field in ("turn_refs", "goal_refs") for ref in episode[field]
        }
        matched_refs = {
            row["episode_ref"]
            for row in prior_membership
            if row["anchor_ref"] in semantic_anchors
        }
        return [
            heads_by_ref[ref] for ref in sorted(matched_refs) if ref in heads_by_ref
        ]

    def _merge_episode_evidence(
        self,
        state: Mapping[str, Any],
        previous: Mapping[str, Any],
        episode: Mapping[str, Any],
    ) -> dict[str, Any]:
        turn_refs = self._canonical_merged_turn_refs(state, previous, episode)
        previous_meaningfulness = previous["meaningfulness"]
        current_meaningfulness = episode["meaningfulness"]

        def merged_members(field: str) -> list[str]:
            members = set(current_meaningfulness[field]) | set(
                previous_meaningfulness[field]
            )
            return [turn_ref for turn_ref in turn_refs if turn_ref in members]

        meaningful = merged_members("meaningful_turn_refs")
        context_only = merged_members("context_only_turn_refs")
        gaps = merged_members("gap_turn_refs")
        if meaningful:
            disposition = "meaningful"
            review_required = True
        elif gaps:
            disposition = "meaningfulness_gap"
            review_required = False
        else:
            disposition = "review_not_required"
            review_required = False
        confidence_rank = {"low": 0, "medium": 1, "high": 2}
        return {
            "boundary_before": copy.deepcopy(episode["boundary_before"]),
            "extraction_confidence": min(
                previous["extraction_confidence"],
                episode["extraction_confidence"],
                key=confidence_rank.__getitem__,
            ),
            "goal_refs": sorted(set(previous["goal_refs"]) | set(episode["goal_refs"])),
            "internal_boundary_candidates": copy.deepcopy(
                episode["internal_boundary_candidates"]
            ),
            "meaningfulness": {
                "context_only_turn_refs": context_only,
                "disposition": disposition,
                "gap_turn_refs": gaps,
                "meaningful_turn_refs": meaningful,
                "review_required": review_required,
                "semantic_coverage": "gap" if gaps else "complete",
            },
            "risk_flags": sorted(
                set(previous["risk_flags"]) | set(episode["risk_flags"])
            ),
            "segmentation_confidence": min(
                previous["segmentation_confidence"],
                episode["segmentation_confidence"],
                key=confidence_rank.__getitem__,
            ),
            "session_ref": episode["session_ref"],
            "turn_refs": turn_refs,
            "workstream_refs": sorted(
                set(previous["workstream_refs"]) | set(episode["workstream_refs"])
            ),
        }

    @staticmethod
    def _canonical_merged_turn_refs(
        state: Mapping[str, Any],
        previous: Mapping[str, Any],
        episode: Mapping[str, Any],
    ) -> list[str]:
        previous_refs = list(previous["turn_refs"])
        current_refs = list(episode["turn_refs"])
        all_refs = set(previous_refs) | set(current_refs)
        successors: dict[str, set[str]] = {ref: set() for ref in all_refs}
        indegree = {ref: 0 for ref in all_refs}
        for ordered in (previous_refs, current_refs):
            for left, right in zip(ordered, ordered[1:], strict=False):
                if right not in successors[left]:
                    successors[left].add(right)
                    indegree[right] += 1

        prior_order = {ref: index for index, ref in enumerate(previous_refs)}
        reassembly = state.get("source", {}).get("reassembly", {})

        def canonical_key(turn_ref: str) -> tuple[object, ...]:
            plan = reassembly.get(turn_ref)
            if isinstance(plan, Mapping):
                canonical_time = plan.get("canonical_time")
                sequence = plan.get("sequence")
                if isinstance(canonical_time, str) and isinstance(sequence, int):
                    return (0, canonical_time, sequence, turn_ref)
            return (1, prior_order.get(turn_ref, len(previous_refs)), turn_ref)

        ready = sorted(
            (ref for ref, degree in indegree.items() if degree == 0),
            key=canonical_key,
        )
        merged: list[str] = []
        while ready:
            turn_ref = ready.pop(0)
            merged.append(turn_ref)
            for successor in sorted(successors[turn_ref], key=canonical_key):
                indegree[successor] -= 1
                if indegree[successor] == 0:
                    ready.append(successor)
            ready.sort(key=canonical_key)
        if len(merged) != len(all_refs):
            raise result_validation.ResultValidationError(
                "prior and current episode membership orders conflict"
            )
        return merged

    @staticmethod
    def _reassemble_turn(
        plan: Mapping[str, Any],
        contributions: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        ordered = sorted(
            contributions.values(),
            key=lambda item: (
                min(item["metadata"]["fragment_indexes"]),
                item["metadata"]["source_unit_ref"],
            ),
        )
        turns = [item["turn"] for item in ordered]

        def unique_scalar(field: str, default: Any) -> tuple[Any, bool]:
            values = [turn.get(field, default) for turn in turns]
            first = values[0]
            return first, any(value != first for value in values[1:])

        def merged_records(field: str) -> list[dict[str, Any]]:
            records: dict[bytes, dict[str, Any]] = {}
            for turn in turns:
                for record in turn[field]:
                    records.setdefault(
                        canonical_json_bytes(record), copy.deepcopy(record)
                    )
            return [records[key] for key in sorted(records)]

        texts = list(dict.fromkeys(turn["generalized_working_text"] for turn in turns))
        outcome, outcome_conflict = unique_scalar("outcome", "unknown")
        goal_change, goal_conflict = unique_scalar("goal_change", "continues")
        meaningfulness, meaningfulness_conflict = unique_scalar(
            "meaningfulness_hint", "meaningful"
        )
        goal_ref, goal_ref_conflict = unique_scalar("goal_ref", plan["goal_ref"])
        workstream_ref, workstream_ref_conflict = unique_scalar(
            "workstream_ref", plan["workstream_ref"]
        )
        conflict = (
            len(texts) > 1
            or outcome_conflict
            or goal_conflict
            or meaningfulness_conflict
            or goal_ref_conflict
            or workstream_ref_conflict
            or any(turn.get("conflicting_signals", False) for turn in turns)
        )
        confidence = min(
            (turn["confidence"] for turn in turns),
            key={"low": 0, "medium": 1, "high": 2}.__getitem__,
        )
        evidence_refs = sorted(
            {evidence_ref for turn in turns for evidence_ref in turn["evidence_refs"]}
        )
        span_commitments = sorted(
            {span_ref for turn in turns for span_ref in turn["span_commitments"]}
        )
        expected_evidence = {item["evidence_ref"] for item in plan["contributors"]}
        expected_spans = {item["span_ref"] for item in plan["contributors"]}
        if (
            set(evidence_refs) != expected_evidence
            or set(span_commitments) != expected_spans
        ):
            raise InvalidTransitionError(
                "logical turn contributions do not conserve fragment evidence"
            )
        return {
            "confidence": "low" if conflict else confidence,
            "conflicting_signals": conflict,
            "events": merged_records("events"),
            "evidence_refs": evidence_refs,
            "findings": merged_records("findings"),
            "generalized_working_text": (
                texts[0]
                if len(texts) == 1
                else "Multiple bounded fragments contributed to this logical turn."
            ),
            "goal_change": "unknown" if goal_conflict else goal_change,
            "goal_ref": plan["goal_ref"] if goal_ref_conflict else goal_ref,
            "meaningfulness_hint": (
                "uncertain" if meaningfulness_conflict else meaningfulness
            ),
            "outcome": "partial" if outcome_conflict else outcome,
            "risk_flags": sorted(
                {flag for turn in turns for flag in turn["risk_flags"]}
            ),
            "span_commitments": span_commitments,
            "strengths": merged_records("strengths"),
            "task_completed": all(turn.get("task_completed", False) for turn in turns),
            "turn_ref": plan["turn_ref"],
            "user_redirect": any(turn.get("user_redirect", False) for turn in turns),
            "workstream_change": any(
                turn.get("workstream_change", False) for turn in turns
            ),
            "workstream_ref": (
                plan["workstream_ref"] if workstream_ref_conflict else workstream_ref
            ),
        }

    def _compose_episode_screening_results(
        self,
        state: Mapping[str, Any],
        turn_refs: Sequence[str],
        *,
        extracted: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        state_value = state.get("extracted_turns")
        if not isinstance(state_value, Mapping):
            return []
        extracted_values = (
            self._jobs._load_extracted_turns(state_value)
            if extracted is None
            else extracted
        )
        decisions: list[dict[str, Any]] = []
        for turn_ref in turn_refs:
            turn = extracted_values.get(turn_ref)
            if not isinstance(turn, Mapping):
                continue
            risk_flags = turn.get("risk_flags")
            if not isinstance(risk_flags, list):
                continue
            decisions.append(
                {
                    "decision": (
                        "high_impact"
                        if "high_impact_prompt" in risk_flags
                        else "not_high_impact"
                    ),
                    "risk_flags": copy.deepcopy(risk_flags),
                    "turn_ref": turn_ref,
                }
            )
        return decisions

    def _refresh_review_plan(self, state: dict[str, Any]) -> bool:
        resolved: dict[str, dict[str, Any] | None] = {}
        plans: dict[str, dict[str, Any]] = {}
        extracted_value = state.get("extracted_turns")
        if not isinstance(extracted_value, Mapping):
            raise InvalidTransitionError("extracted turn state is invalid")
        extracted = self._jobs._load_extracted_turns(extracted_value)
        for revision in state["episodes"]:
            revision_ref = revision["episode_revision_ref"]
            primary_task = self._projection._review_task(
                state,
                revision_ref,
                JobKind.EPISODE_REVIEWER.value,
            )
            secondary_task = self._projection._review_task(
                state,
                revision_ref,
                JobKind.INDEPENDENT_RISK_REVIEWER.value,
            )
            primary = self._projection._review_plan_result(primary_task)
            secondary = self._projection._review_plan_result(secondary_task)
            plan = episode_review.plan_episode_review_jobs(
                revision,
                identity_key=self.identity,
                screening_results=self._compose_episode_screening_results(
                    state,
                    revision["turn_refs"],
                    extracted=extracted,
                ),
                primary_review=primary,
                secondary_review=secondary,
            )
            plans[revision_ref] = plan
            review_jobs = [
                job
                for job in plan["jobs"]
                if job["kind"]
                in {
                    JobKind.EPISODE_REVIEWER.value,
                    JobKind.INDEPENDENT_RISK_REVIEWER.value,
                }
            ]
            turn_payloads: list[dict[str, Any]] = []
            if review_jobs:
                restored = self._projection._episode_turn_payloads(
                    state,
                    revision["turn_refs"],
                    episode_revision_ref=revision_ref,
                    extracted=extracted,
                )
                if restored is None:
                    state["review_plans"] = plans
                    state["resolved_reviews"] = resolved
                    return False
                turn_payloads = restored
            for job in plan["jobs"]:
                kind = job["kind"]
                reviewer_slot = job.get("reviewer_slot")
                if kind == JobKind.ADJUDICATOR.value and reviewer_slot is None:
                    reviewer_slot = "adjudicator"
                metadata: dict[str, Any] = {
                    "episode_ref": revision["episode_ref"],
                    "episode_revision_ref": revision_ref,
                    "reason_codes": job["reason_codes"],
                    "reviewer_slot": reviewer_slot,
                }
                input_payload: dict[str, Any] = {
                    "episode_revision": revision,
                    "schema": "episode_review_input_v2",
                    "turns": turn_payloads,
                }
                if kind == JobKind.ADJUDICATOR.value:
                    if not (
                        plan["primary_review_completed"]
                        and plan["secondary_review_completed"]
                        and self._projection._is_completed_episode_review(primary)
                        and self._projection._is_completed_episode_review(secondary)
                    ):
                        continue
                    hashes = [
                        result_validation.canonical_result_hash(primary),
                        result_validation.canonical_result_hash(secondary),
                    ]
                    if primary_task is None or secondary_task is None:
                        raise InvalidTransitionError(
                            "completed episode reviews lack task bindings"
                        )
                    metadata["candidate_result_hashes"] = hashes
                    metadata["candidate_task_refs"] = [
                        primary_task["task_ref"],
                        secondary_task["task_ref"],
                    ]
                    input_payload = {
                        "candidate_result_hashes": hashes,
                        "candidate_results": [primary, secondary],
                        "episode_context": {
                            "episode_ref": revision["episode_ref"],
                            "episode_revision_ref": revision_ref,
                            "session_ref": revision["session_ref"],
                        },
                        "schema": "episode_adjudication_input_v2",
                    }
                    metadata["hierarchy_final"] = True
                    metadata["hierarchy_level"] = 0
                    metadata["hierarchy_root_ref"] = revision_ref
                allowed_refs = self._projection._collect_refs(input_payload)
                if kind in {
                    JobKind.EPISODE_REVIEWER.value,
                    JobKind.INDEPENDENT_RISK_REVIEWER.value,
                }:
                    self._ensure_review_hierarchy(
                        state,
                        revision=revision,
                        kind=kind,
                        metadata=metadata,
                        full_input=input_payload,
                    )
                else:
                    self._jobs._create_agent_task(
                        state,
                        stage=RunStage.EPISODE_REVIEW.value,
                        kind=kind,
                        partition_ref=revision_ref,
                        input_refs=[revision["episode_ref"], revision_ref],
                        input_payload=input_payload,
                        allowed_refs=allowed_refs,
                        allowed_turn_refs=revision["turn_refs"],
                        metadata=metadata,
                    )

            if not plan["review_required"]:
                resolved[revision_ref] = None
                continue
            if plan["review_gaps"] or plan["blocked_reason"] is not None:
                continue
            if not (
                plan["primary_review_completed"]
                and self._projection._is_completed_episode_review(primary)
            ):
                continue
            if plan["second_review_required"] and not (
                plan["secondary_review_completed"]
                and self._projection._is_completed_episode_review(secondary)
            ):
                continue
            adjudicator = self._projection._review_task(
                state,
                revision_ref,
                JobKind.ADJUDICATOR.value,
            )
            if plan["adjudication_required"]:
                adjudication_result = (
                    None
                    if adjudicator is None
                    else agent_results.for_task(self.run_dir, adjudicator)
                )
                if (
                    adjudicator
                    and adjudicator.get("status") == "accepted"
                    and self._projection._is_resolved_review(adjudication_result)
                ):
                    resolved[revision_ref] = agent_results.reference_for_task(
                        adjudicator
                    )
            else:
                if primary_task is None:
                    raise InvalidTransitionError(
                        "completed primary review lacks its task binding"
                    )
                resolved[revision_ref] = agent_results.reference_for_task(primary_task)
        state["review_plans"] = plans
        state["resolved_reviews"] = resolved
        return True

    def _ensure_review_hierarchy(
        self,
        state: dict[str, Any],
        *,
        revision: Mapping[str, Any],
        kind: str,
        metadata: Mapping[str, Any],
        full_input: Mapping[str, Any],
    ) -> None:
        revision_ref = revision["episode_revision_ref"]
        input_refs = [revision["episode_ref"], revision_ref]
        full_allowed = self._projection._collect_refs(full_input)
        existing = [
            task
            for task in self._projection._tasks_for_stage(
                state, RunStage.EPISODE_REVIEW.value
            )
            if task["job_kind"] == kind
            and task["metadata"].get("hierarchy_root_ref") == revision_ref
        ]
        if not existing and self._jobs._agent_input_fits(
            kind=kind,
            input_payload=full_input,
            input_refs=input_refs,
            allowed_refs=full_allowed,
            reviewer_slot=metadata.get("reviewer_slot"),
        ):
            self._jobs._create_agent_task(
                state,
                stage=RunStage.EPISODE_REVIEW.value,
                kind=kind,
                partition_ref=revision_ref,
                input_refs=input_refs,
                input_payload=full_input,
                allowed_refs=full_allowed,
                allowed_turn_refs=revision["turn_refs"],
                metadata={
                    **dict(metadata),
                    "hierarchy_final": True,
                    "hierarchy_level": 0,
                    "hierarchy_root_ref": revision_ref,
                    "underlying_turn_refs": list(revision["turn_refs"]),
                },
            )
            return
        if not existing:
            episode_context = {
                "episode_ref": revision["episode_ref"],
                "episode_revision_ref": revision_ref,
                "risk_flags": revision["risk_flags"],
                "session_ref": revision["session_ref"],
                "workstream_refs": revision["workstream_refs"],
            }
            items: list[dict[str, Any]] = [
                {"kind": "turn", "value": turn} for turn in full_input["turns"]
            ]
            groups: list[list[dict[str, Any]]] = []
            for item in items:
                candidate = [*(groups[-1] if groups else []), item]
                payload = self._review_partition_payload(episode_context, candidate)
                allowed = self._projection._collect_refs(payload)
                if groups and not self._jobs._agent_input_fits(
                    kind=kind,
                    input_payload=payload,
                    input_refs=input_refs,
                    allowed_refs=allowed,
                    reviewer_slot=metadata.get("reviewer_slot"),
                ):
                    groups.append([item])
                elif groups:
                    groups[-1] = candidate
                else:
                    groups.append([item])
            if not groups:
                groups = [[]]
            for index, group in enumerate(groups):
                payload = self._review_partition_payload(episode_context, group)
                allowed = self._projection._collect_refs(payload)
                partition_ref = self._ref(
                    RefType.RUN_INPUT,
                    revision_ref,
                    kind,
                    "review_leaf",
                    index,
                )
                turn_refs = [item["value"]["turn_ref"] for item in group]
                self._jobs._create_agent_task(
                    state,
                    stage=RunStage.EPISODE_REVIEW.value,
                    kind=kind,
                    partition_ref=partition_ref,
                    input_refs=input_refs,
                    input_payload=payload,
                    allowed_refs=allowed,
                    allowed_turn_refs=turn_refs,
                    metadata={
                        **dict(metadata),
                        "hierarchy_final": False,
                        "hierarchy_level": 0,
                        "hierarchy_root_ref": revision_ref,
                        "underlying_turn_refs": turn_refs,
                    },
                )
            return
        if any(task["metadata"].get("hierarchy_final") for task in existing):
            return
        level = max(int(task["metadata"]["hierarchy_level"]) for task in existing)
        current = [
            task for task in existing if task["metadata"]["hierarchy_level"] == level
        ]
        if any(task["status"] != "accepted" for task in current):
            return
        if any(task["metadata"]["hierarchy_level"] == level + 1 for task in existing):
            return
        groups: list[list[dict[str, Any]]] = []
        for task in sorted(current, key=lambda item: item["task_ref"]):
            candidate = [*(groups[-1] if groups else []), task]
            payload = self._review_reduce_payload(revision, candidate)
            allowed = self._projection._collect_refs(payload)
            if groups and not self._jobs._agent_input_fits(
                kind=kind,
                input_payload=payload,
                input_refs=input_refs,
                allowed_refs=allowed,
                reviewer_slot=metadata.get("reviewer_slot"),
            ):
                groups.append([task])
            elif groups:
                groups[-1] = candidate
            else:
                groups.append([task])
        final_level = len(groups) == 1
        for index, group in enumerate(groups):
            payload = self._review_reduce_payload(revision, group)
            turn_refs = sorted(
                {
                    turn_ref
                    for task in group
                    for turn_ref in self._task_metadata(task)["underlying_turn_refs"]
                }
            )
            self._jobs._create_agent_task(
                state,
                stage=RunStage.EPISODE_REVIEW.value,
                kind=kind,
                partition_ref=(
                    revision_ref
                    if final_level
                    else self._ref(
                        RefType.RUN_INPUT,
                        revision_ref,
                        kind,
                        "review_reduce",
                        level + 1,
                        index,
                    )
                ),
                input_refs=input_refs,
                input_payload=payload,
                allowed_refs=self._projection._collect_refs(payload),
                allowed_turn_refs=turn_refs,
                metadata={
                    **dict(metadata),
                    "candidate_result_hashes": payload["child_result_hashes"],
                    "hierarchy_final": final_level,
                    "hierarchy_level": level + 1,
                    "hierarchy_root_ref": revision_ref,
                    "underlying_turn_refs": turn_refs,
                },
            )

    @staticmethod
    def _review_partition_payload(
        episode_context: Mapping[str, Any],
        items: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        return {
            "episode_context": copy.deepcopy(dict(episode_context)),
            "schema": "episode_review_partition_input_v2",
            "turns": [
                copy.deepcopy(item["value"]) for item in items if item["kind"] == "turn"
            ],
        }

    def _review_reduce_payload(
        self,
        revision: Mapping[str, Any],
        tasks: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        results = agent_results.copies_for_tasks(
            self.run_dir, tasks, label="accepted review"
        )
        return {
            "child_result_hashes": [
                result_validation.canonical_result_hash(result) for result in results
            ],
            "child_results": results,
            "episode_context": {
                "episode_ref": revision["episode_ref"],
                "episode_revision_ref": revision["episode_revision_ref"],
                "session_ref": revision["session_ref"],
            },
            "schema": "episode_review_hierarchical_input_v2",
        }

    def _build_topic_inputs(self, state: dict[str, Any]) -> None:
        if state["topic_inputs"]:
            return
        groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(
            list
        )
        revision_by_ref = {
            item["episode_revision_ref"]: item for item in state["episodes"]
        }
        expected_revision_refs = {
            revision_ref
            for revision_ref, revision in revision_by_ref.items()
            if revision.get("meaningfulness", {}).get("review_required") is True
        }
        resolved_revision_refs = {
            revision_ref
            for revision_ref, review in state["resolved_reviews"].items()
            if review is not None
        }
        if resolved_revision_refs != expected_revision_refs:
            raise InvalidTransitionError(
                "resolved episode reviews must exactly cover every review-required "
                "episode revision"
            )
        for revision_ref, review_binding in state["resolved_reviews"].items():
            if review_binding is None:
                continue
            review = agent_results.from_reference(
                self.run_dir,
                state["jobs"],
                review_binding,
            )
            if not self._projection._is_resolved_review(review):
                raise InvalidTransitionError(
                    "non-reviewed disposition cannot enter topic reduction"
                )
            revision = revision_by_ref[revision_ref]
            workstream_ref = (
                revision["workstream_refs"][0]
                if revision["workstream_refs"]
                else self._ref(
                    RefType.WORKSTREAM,
                    revision["session_ref"],
                    "unclassified",
                )
            )
            groups[workstream_ref].append((revision, review))

        for workstream_ref, rows in sorted(groups.items()):
            rows.sort(key=lambda item: item[0]["episode_revision_ref"])
            topic_candidate_ref = self._ref(
                RefType.TOPIC_CANDIDATE,
                workstream_ref,
                [item[0]["episode_revision_ref"] for item in rows],
            )
            candidate_map: dict[str, Sequence[Mapping[str, Any]]] = {}
            for revision, review in rows:
                if review["schema"] != result_validation.ADJUDICATION_RESULT_SCHEMA:
                    continue
                revision_ref = revision["episode_revision_ref"]
                task = self._projection._review_task(
                    state,
                    revision_ref,
                    JobKind.ADJUDICATOR.value,
                )
                if task is None:
                    raise InvalidTransitionError(
                        "resolved adjudication task is missing"
                    )
                candidate_task_refs = task["metadata"].get("candidate_task_refs")
                if candidate_task_refs is None:
                    candidate_map[revision_ref] = self._task_metadata(task)[
                        "candidate_results"
                    ]
                else:
                    if (
                        not isinstance(candidate_task_refs, list)
                        or len(candidate_task_refs) != 2
                    ):
                        raise InvalidTransitionError(
                            "adjudication candidate task bindings are invalid"
                        )
                    candidate_map[revision_ref] = [
                        agent_results.require(
                            self.run_dir,
                            state["jobs"][task_ref],
                            label="adjudication candidate",
                        )
                        for task_ref in candidate_task_refs
                    ]
            topic_ref = self._ref(RefType.TOPIC, topic_candidate_ref)
            partitions = self._partition_topic_rows(
                topic_candidate_ref=topic_candidate_ref,
                topic_ref=topic_ref,
                workstream_ref=workstream_ref,
                rows=rows,
                candidate_map=candidate_map,
            )
            state["topic_inputs"][topic_candidate_ref] = {
                "expected_episode_revision_refs": [
                    revision["episode_revision_ref"] for revision, _review in rows
                ],
                "leaf_input_hashes": [
                    result_validation.canonical_result_hash(partition["topic_input"])
                    for partition in partitions
                ],
                "schema": "topic_partition_index_v2",
                "topic_candidate_ref": topic_candidate_ref,
                "topic_ref": topic_ref,
                "workstream_ref": workstream_ref,
            }
            self._seed_topic_hierarchy(
                state,
                partitions=partitions,
                topic_ref=topic_ref,
                root_ref=topic_candidate_ref,
            )

    def _partition_topic_rows(
        self,
        *,
        topic_candidate_ref: str,
        topic_ref: str,
        workstream_ref: str,
        rows: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
        candidate_map: Mapping[str, Sequence[Mapping[str, Any]]],
    ) -> list[dict[str, Any]]:
        grouped_rows: list[list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = []
        for row in rows:
            candidate = [*(grouped_rows[-1] if grouped_rows else []), row]
            candidate_input = self._topic_input_for_rows(
                candidate_map=candidate_map,
                topic_candidate_ref=topic_candidate_ref,
                workstream_ref=workstream_ref,
                rows=candidate,
            )
            if grouped_rows and len(canonical_json_bytes(candidate_input)) > (
                result_validation.MAX_RESULT_BYTES
            ):
                grouped_rows.append([row])
            elif grouped_rows:
                grouped_rows[-1] = candidate
            else:
                grouped_rows.append([row])

        partitions: list[dict[str, Any]] = []
        for partition_rows in grouped_rows:
            topic_input = self._topic_input_for_rows(
                candidate_map=candidate_map,
                topic_candidate_ref=topic_candidate_ref,
                workstream_ref=workstream_ref,
                rows=partition_rows,
            )
            if (
                len(canonical_json_bytes(topic_input))
                > result_validation.MAX_RESULT_BYTES
            ):
                raise InvalidTransitionError(
                    "one bounded episode review cannot fit a topic reducer input"
                )
            revision_refs = {
                revision["episode_revision_ref"] for revision, _review in partition_rows
            }
            partition_candidates = {
                key: copy.deepcopy(value)
                for key, value in candidate_map.items()
                if key in revision_refs
            }
            allowed_turn_refs = {
                turn_ref
                for revision, _review in partition_rows
                for turn_ref in revision["turn_refs"]
            }
            allowed_refs = self._projection._collect_refs(
                {
                    "candidate_map": partition_candidates,
                    "topic_input": topic_input,
                    "topic_ref": topic_ref,
                }
            )
            validated = result_validation.validate_topic_input(
                topic_input,
                allowed_refs,
                allowed_turn_refs=allowed_turn_refs,
                adjudication_candidate_results=partition_candidates,
            )
            partitions.append(
                {
                    "adjudication_candidate_results": partition_candidates,
                    "allowed_refs": sorted(allowed_refs),
                    "allowed_turn_refs": sorted(allowed_turn_refs),
                    "topic_input": validated,
                }
            )
        return partitions

    @staticmethod
    def _topic_input_for_rows(
        *,
        candidate_map: Mapping[str, Sequence[Mapping[str, Any]]],
        topic_candidate_ref: str,
        workstream_ref: str,
        rows: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    ) -> dict[str, Any]:
        revision_refs = {revision["episode_revision_ref"] for revision, _review in rows}
        return {
            "adjudication_candidate_results": {
                revision_ref: copy.deepcopy(candidates)
                for revision_ref, candidates in sorted(candidate_map.items())
                if revision_ref in revision_refs
            },
            "adjudication_required_episode_revision_refs": [
                revision["episode_revision_ref"]
                for revision, review in rows
                if review["schema"] == result_validation.ADJUDICATION_RESULT_SCHEMA
            ],
            "episode_contexts": [
                {
                    "episode_ref": revision["episode_ref"],
                    "episode_revision_ref": revision["episode_revision_ref"],
                    "session_ref": revision["session_ref"],
                }
                for revision, _review in rows
            ],
            "episode_reviews": [copy.deepcopy(review) for _revision, review in rows],
            "expected_episode_revision_refs": [
                revision["episode_revision_ref"] for revision, _review in rows
            ],
            "schema": result_validation.TOPIC_INPUT_SCHEMA,
            "topic_candidate_ref": topic_candidate_ref,
            "workstream_ref": workstream_ref,
        }

    def _seed_topic_hierarchy(
        self,
        state: dict[str, Any],
        *,
        partitions: Sequence[Mapping[str, Any]],
        topic_ref: str,
        root_ref: str,
    ) -> None:
        if not partitions:
            raise InvalidTransitionError("topic hierarchy has no bounded leaves")
        final_leaf = len(partitions) == 1
        for index, partition in enumerate(partitions):
            topic_input = partition["topic_input"]
            episode_refs = list(topic_input["expected_episode_revision_refs"])
            self._jobs._create_agent_task(
                state,
                stage=RunStage.TOPIC_REDUCTION.value,
                kind=JobKind.TOPIC_REDUCER.value,
                partition_ref=(
                    root_ref
                    if final_leaf
                    else self._ref(RefType.RUN_INPUT, root_ref, "topic_leaf", index)
                ),
                input_refs=[root_ref, *episode_refs],
                input_payload=topic_input,
                allowed_refs=partition["allowed_refs"],
                allowed_turn_refs=partition["allowed_turn_refs"],
                metadata={
                    "adjudication_candidate_results": partition[
                        "adjudication_candidate_results"
                    ],
                    "hierarchy_final": final_leaf,
                    "hierarchy_level": 0,
                    "hierarchy_root_ref": root_ref,
                    "topic_candidate_ref": root_ref,
                    "topic_ref": topic_ref,
                    "underlying_episode_refs": episode_refs,
                    "validation_topic_input": copy.deepcopy(dict(topic_input)),
                    "workstream_ref": topic_input["workstream_ref"],
                },
            )

    @staticmethod
    def _slice_topic_input(
        topic_input: Mapping[str, Any],
        episode_refs: Sequence[str],
    ) -> dict[str, Any]:
        wanted = set(episode_refs)
        contexts_by_ref = {
            item["episode_revision_ref"]: item
            for item in topic_input["episode_contexts"]
        }
        reviews_by_ref = {
            item["episode_revision_ref"]: item
            for item in topic_input["episode_reviews"]
        }
        ordered = [
            ref
            for ref in topic_input["expected_episode_revision_refs"]
            if ref in wanted
        ]
        return {
            "adjudication_candidate_results": {
                ref: copy.deepcopy(candidates)
                for ref, candidates in topic_input[
                    "adjudication_candidate_results"
                ].items()
                if ref in wanted
            },
            "adjudication_required_episode_revision_refs": [
                ref
                for ref in topic_input["adjudication_required_episode_revision_refs"]
                if ref in wanted
            ],
            "episode_contexts": [
                copy.deepcopy(contexts_by_ref[ref]) for ref in ordered
            ],
            "episode_reviews": [copy.deepcopy(reviews_by_ref[ref]) for ref in ordered],
            "expected_episode_revision_refs": ordered,
            "schema": result_validation.TOPIC_INPUT_SCHEMA,
            "topic_candidate_ref": topic_input["topic_candidate_ref"],
            "workstream_ref": topic_input["workstream_ref"],
        }

    def _refresh_topic_hierarchies(self, state: dict[str, Any]) -> None:
        tasks = self._projection._tasks_for_stage(state, RunStage.TOPIC_REDUCTION.value)
        for root_ref, topic_index in sorted(state["topic_inputs"].items()):
            if topic_index.get("schema") != "topic_partition_index_v2":
                raise InvalidTransitionError("topic partition index is invalid")
            root_tasks = [
                task
                for task in tasks
                if task["metadata"].get("hierarchy_root_ref") == root_ref
            ]
            if not root_tasks or any(
                task["metadata"].get("hierarchy_final") for task in root_tasks
            ):
                continue
            level = max(int(task["metadata"]["hierarchy_level"]) for task in root_tasks)
            current = [
                task
                for task in root_tasks
                if task["metadata"]["hierarchy_level"] == level
            ]
            if any(task["status"] != "accepted" for task in current):
                continue
            if any(
                task["metadata"]["hierarchy_level"] == level + 1 for task in root_tasks
            ):
                continue
            groups: list[list[dict[str, Any]]] = []
            for task in sorted(current, key=lambda item: item["task_ref"]):
                candidate = [*(groups[-1] if groups else []), task]
                payload = self._topic_reduce_payload(root_ref, candidate)
                episode_refs = sorted(
                    {
                        ref
                        for child in candidate
                        for ref in self._task_metadata(child)["underlying_episode_refs"]
                    }
                )
                allowed = self._projection._collect_refs(
                    {
                        "payload": payload,
                        "topic_candidate_ref": root_ref,
                        "topic_ref": topic_index["topic_ref"],
                        "workstream_ref": topic_index["workstream_ref"],
                    }
                )
                if groups and not self._jobs._agent_input_fits(
                    kind=JobKind.TOPIC_REDUCER.value,
                    input_payload=payload,
                    input_refs=[root_ref, *episode_refs],
                    allowed_refs=allowed,
                ):
                    groups.append([task])
                elif groups:
                    groups[-1] = candidate
                else:
                    groups.append([task])
            final_level = len(groups) == 1
            for index, group in enumerate(groups):
                episode_refs = sorted(
                    {
                        ref
                        for task in group
                        for ref in self._task_metadata(task)["underlying_episode_refs"]
                    }
                )
                payload = self._topic_reduce_payload(root_ref, group)
                topic_ref = topic_index["topic_ref"]
                self._jobs._create_agent_task(
                    state,
                    stage=RunStage.TOPIC_REDUCTION.value,
                    kind=JobKind.TOPIC_REDUCER.value,
                    partition_ref=(
                        root_ref
                        if final_level
                        else self._ref(
                            RefType.RUN_INPUT,
                            root_ref,
                            "topic_reduce",
                            level + 1,
                            index,
                        )
                    ),
                    input_refs=[root_ref, *episode_refs],
                    input_payload=payload,
                    allowed_refs=self._projection._collect_refs(
                        {
                            "payload": payload,
                            "topic_candidate_ref": root_ref,
                            "topic_ref": topic_ref,
                            "workstream_ref": topic_index["workstream_ref"],
                        }
                    ),
                    allowed_turn_refs={
                        turn_ref
                        for task in group
                        for turn_ref in agent_task_inputs.for_task(self.run_dir, task)[
                            "allowed_turn_refs"
                        ]
                    },
                    metadata={
                        "child_result_hashes": payload["child_result_hashes"],
                        "hierarchy_final": final_level,
                        "hierarchy_level": level + 1,
                        "hierarchy_root_ref": root_ref,
                        "topic_candidate_ref": root_ref,
                        "topic_ref": topic_ref,
                        "underlying_episode_refs": episode_refs,
                        "validation_child_topic_results": copy.deepcopy(
                            payload["child_topic_results"]
                        ),
                        "workstream_ref": topic_index["workstream_ref"],
                    },
                )

    def _topic_reduce_payload(
        self,
        root_ref: str,
        tasks: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        results = agent_results.copies_for_tasks(
            self.run_dir, tasks, label="accepted topic"
        )
        return {
            "child_result_hashes": [
                result_validation.canonical_result_hash(result) for result in results
            ],
            "child_topic_results": results,
            "schema": "topic_hierarchical_input_v2",
            "topic_candidate_ref": root_ref,
        }

    def _seed_synthesis_task(self, state: dict[str, Any]) -> None:
        final_topic_tasks = self._accepted_final_topic_tasks(state)
        if self._projection._tasks_for_stage(state, RunStage.GLOBAL_SYNTHESIS.value):
            return
        topic_results = agent_results.copies_for_tasks(
            self.run_dir, final_topic_tasks, label="accepted topic"
        )
        independent_reviews = []
        for task in self._projection._tasks_for_stage(
            state, RunStage.EPISODE_REVIEW.value
        ):
            if (
                task["job_kind"] != JobKind.INDEPENDENT_RISK_REVIEWER.value
                or task["status"] != "accepted"
                or task["metadata"].get("hierarchy_final") is not True
            ):
                continue
            result = agent_results.for_task(self.run_dir, task)
            if self._projection._is_completed_episode_review(result):
                independent_reviews.append(result)
        root_ref = self._ref(
            RefType.RUN_INPUT,
            state["run_ref"],
            "global_synthesis",
            [task["task_ref"] for task in final_topic_tasks],
        )
        self._seed_synthesis_hierarchy(
            state,
            root_ref=root_ref,
            topic_results=topic_results,
            independent_reviews=independent_reviews,
        )

    def _accepted_final_topic_tasks(
        self,
        state: Mapping[str, Any],
    ) -> list[Mapping[str, Any]]:
        expected_roots = set(state["topic_inputs"])
        accepted = [
            task
            for task in state["jobs"].values()
            if task.get("stage") == RunStage.TOPIC_REDUCTION.value
            and task.get("status") == "accepted"
            and isinstance(task.get("metadata"), Mapping)
            and task["metadata"].get("hierarchy_final") is True
        ]
        roots: list[str] = []
        for task in accepted:
            root_ref = task["metadata"].get("hierarchy_root_ref")
            result = agent_results.for_task(self.run_dir, task)
            if (
                not isinstance(root_ref, str)
                or not isinstance(result, Mapping)
                or result.get("topic_candidate_ref") != root_ref
            ):
                raise InvalidTransitionError(
                    "accepted final topic result has invalid root binding"
                )
            roots.append(root_ref)
        root_counts = {root_ref: roots.count(root_ref) for root_ref in set(roots)}
        if set(root_counts) - expected_roots:
            raise InvalidTransitionError("extra accepted final topic result root")
        if any(count != 1 for count in root_counts.values()):
            raise InvalidTransitionError("duplicate accepted final topic result root")
        if expected_roots - set(root_counts):
            raise InvalidTransitionError("missing accepted final topic result root")
        return sorted(accepted, key=lambda task: task["metadata"]["hierarchy_root_ref"])

    def _seed_synthesis_hierarchy(
        self,
        state: dict[str, Any],
        *,
        root_ref: str,
        topic_results: Sequence[Mapping[str, Any]],
        independent_reviews: Sequence[Mapping[str, Any]],
    ) -> None:
        coverage = self._projection._safe_coverage_payload(state)
        payload = self._synthesis_input_payload(
            coverage,
            topic_results,
            independent_reviews,
        )
        allowed = self._projection._collect_refs(
            {
                "independent_reviews": independent_reviews,
                "topic_results": topic_results,
            }
        )
        input_refs = sorted(allowed)
        all_turn_refs = {
            turn_ref
            for revision in state["episodes"]
            for turn_ref in revision["turn_refs"]
        }
        if self._jobs._agent_input_fits(
            kind=JobKind.GLOBAL_SYNTHESIS.value,
            input_payload=payload,
            input_refs=input_refs,
            allowed_refs=allowed,
        ):
            self._create_synthesis_task(
                state,
                root_ref=root_ref,
                partition_ref=root_ref,
                payload=payload,
                topic_results=topic_results,
                independent_reviews=independent_reviews,
                allowed_turn_refs=all_turn_refs,
                level=0,
                final=True,
            )
            return
        items = [
            ("topic", result_validation.canonical_result_hash(item), item)
            for item in topic_results
        ] + [
            ("review", result_validation.canonical_result_hash(item), item)
            for item in independent_reviews
        ]
        items.sort(key=lambda item: (item[0], item[1]))
        groups: list[list[tuple[str, str, Mapping[str, Any]]]] = []
        for item in items:
            candidate = [*(groups[-1] if groups else []), item]
            topics = [value for kind, _digest, value in candidate if kind == "topic"]
            reviews = [value for kind, _digest, value in candidate if kind == "review"]
            candidate_payload = self._synthesis_input_payload(coverage, topics, reviews)
            candidate_allowed = self._projection._collect_refs(
                {"independent_reviews": reviews, "topic_results": topics}
            )
            if groups and not self._jobs._agent_input_fits(
                kind=JobKind.GLOBAL_SYNTHESIS.value,
                input_payload=candidate_payload,
                input_refs=sorted(candidate_allowed),
                allowed_refs=candidate_allowed,
            ):
                groups.append([item])
            elif groups:
                groups[-1] = candidate
            else:
                groups.append([item])
        if not groups:
            groups = [[]]
        for index, group in enumerate(groups):
            topics = [value for kind, _digest, value in group if kind == "topic"]
            reviews = [value for kind, _digest, value in group if kind == "review"]
            self._create_synthesis_task(
                state,
                root_ref=root_ref,
                partition_ref=self._ref(
                    RefType.RUN_INPUT, root_ref, "synthesis_leaf", index
                ),
                payload=self._synthesis_input_payload(coverage, topics, reviews),
                topic_results=topics,
                independent_reviews=reviews,
                allowed_turn_refs=all_turn_refs,
                level=0,
                final=False,
            )

    def _create_synthesis_task(
        self,
        state: dict[str, Any],
        *,
        root_ref: str,
        partition_ref: str,
        payload: Mapping[str, Any],
        topic_results: Sequence[Mapping[str, Any]],
        independent_reviews: Sequence[Mapping[str, Any]],
        allowed_turn_refs: Iterable[str],
        level: int,
        final: bool,
        validation_child_task_refs: Sequence[str] = (),
    ) -> None:
        allowed = self._projection._collect_refs({"payload": payload})
        review_hashes = sorted(
            result_validation.canonical_result_hash(review)
            for review in independent_reviews
        )
        topic_hashes = sorted(
            result_validation.canonical_result_hash(result) for result in topic_results
        )
        self._jobs._create_agent_task(
            state,
            stage=RunStage.GLOBAL_SYNTHESIS.value,
            kind=JobKind.GLOBAL_SYNTHESIS.value,
            partition_ref=partition_ref,
            input_refs=sorted(allowed),
            input_payload=payload,
            allowed_refs=allowed,
            allowed_turn_refs=allowed_turn_refs,
            metadata={
                "hierarchy_final": final,
                "hierarchy_level": level,
                "hierarchy_root_ref": root_ref,
                "safety_review_hashes": review_hashes,
                "topic_result_hashes": topic_hashes,
                "validation_child_task_refs": sorted(set(validation_child_task_refs)),
                "validation_independent_review_hashes": review_hashes,
                "validation_topic_result_hashes": topic_hashes,
            },
        )

    @staticmethod
    def _synthesis_input_payload(
        coverage: Mapping[str, Any],
        topic_results: Sequence[Mapping[str, Any]],
        independent_reviews: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        return {
            "coverage": copy.deepcopy(dict(coverage)),
            "independent_reviews": copy.deepcopy(list(independent_reviews)),
            "schema": "global_synthesis_input_v2",
            "safety_review_hashes": sorted(
                result_validation.canonical_result_hash(review)
                for review in independent_reviews
            ),
            "signal_commitments": result_validation.build_synthesis_signal_commitments(
                topic_results
            ),
            "topic_result_hashes": sorted(
                result_validation.canonical_result_hash(result)
                for result in topic_results
            ),
            "topic_results": copy.deepcopy(list(topic_results)),
        }

    def _refresh_synthesis_hierarchy(self, state: dict[str, Any]) -> None:
        tasks = self._projection._tasks_for_stage(
            state, RunStage.GLOBAL_SYNTHESIS.value
        )
        if not tasks or any(
            task["metadata"].get("hierarchy_final") is True for task in tasks
        ):
            return
        level = max(int(task["metadata"]["hierarchy_level"]) for task in tasks)
        current = [
            task for task in tasks if task["metadata"]["hierarchy_level"] == level
        ]
        if any(task["status"] != "accepted" for task in current):
            return
        if any(task["metadata"]["hierarchy_level"] == level + 1 for task in tasks):
            return
        root_ref = current[0]["metadata"]["hierarchy_root_ref"]
        groups: list[list[dict[str, Any]]] = []
        for task in sorted(current, key=lambda item: item["task_ref"]):
            candidate = [*(groups[-1] if groups else []), task]
            payload = self._synthesis_reduce_payload(candidate)
            allowed = self._projection._collect_refs({"payload": payload})
            if groups and not self._jobs._agent_input_fits(
                kind=JobKind.GLOBAL_SYNTHESIS.value,
                input_payload=payload,
                input_refs=sorted(allowed),
                allowed_refs=allowed,
            ):
                groups.append([task])
            elif groups:
                groups[-1] = candidate
            else:
                groups.append([task])
        final_level = len(groups) == 1
        all_turn_refs = {
            turn_ref
            for revision in state["episodes"]
            for turn_ref in revision["turn_refs"]
        }
        for index, group in enumerate(groups):
            self._create_synthesis_task(
                state,
                root_ref=root_ref,
                partition_ref=(
                    root_ref
                    if final_level
                    else self._ref(
                        RefType.RUN_INPUT,
                        root_ref,
                        "synthesis_reduce",
                        level + 1,
                        index,
                    )
                ),
                payload=self._synthesis_reduce_payload(group),
                topic_results=(),
                independent_reviews=(),
                allowed_turn_refs=all_turn_refs,
                level=level + 1,
                final=final_level,
                validation_child_task_refs=[task["task_ref"] for task in group],
            )

    def _synthesis_validation_results(
        self,
        state: Mapping[str, Any],
        task: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        metadata = task["metadata"]
        root_ref = metadata["hierarchy_root_ref"]
        topics: list[tuple[str, dict[str, Any]]] = []
        reviews: list[tuple[str, dict[str, Any]]] = []
        topic_hashes: set[str] = set()
        review_hashes: set[str] = set()
        pending = [task]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            current_ref = current.get("task_ref")
            if not isinstance(current_ref, str) or current_ref in visited:
                continue
            visited.add(current_ref)
            current_metadata = current.get("metadata")
            if (
                not isinstance(current_metadata, Mapping)
                or current_metadata.get("hierarchy_root_ref") != root_ref
            ):
                raise result_validation.ResultValidationError(
                    "synthesis validation lineage is invalid"
                )
            child_refs = current_metadata.get("validation_child_task_refs", [])
            if child_refs:
                if current_metadata.get(
                    "validation_topic_result_hashes"
                ) or current_metadata.get("validation_independent_review_hashes"):
                    raise result_validation.ResultValidationError(
                        "synthesis parent duplicates leaf validation results"
                    )
            else:
                payload = agent_task_inputs.for_task(self.run_dir, current).get(
                    "input_payload"
                )
                if (
                    not isinstance(payload, Mapping)
                    or payload.get("schema") != "global_synthesis_input_v2"
                ):
                    raise result_validation.ResultValidationError(
                        "synthesis validation leaf input is invalid"
                    )
                leaf_topics = payload.get("topic_results", [])
                leaf_reviews = payload.get("independent_reviews", [])
                if not isinstance(leaf_topics, list) or any(
                    not isinstance(result, Mapping) for result in leaf_topics
                ):
                    raise result_validation.ResultValidationError(
                        "synthesis validation leaf topic results are invalid"
                    )
                if not isinstance(leaf_reviews, list) or any(
                    not isinstance(result, Mapping) for result in leaf_reviews
                ):
                    raise result_validation.ResultValidationError(
                        "synthesis validation leaf reviews are invalid"
                    )
                leaf_topic_rows = [
                    (
                        result_validation.canonical_result_hash(result),
                        copy.deepcopy(dict(result)),
                    )
                    for result in leaf_topics
                ]
                leaf_review_rows = [
                    (
                        result_validation.canonical_result_hash(result),
                        copy.deepcopy(dict(result)),
                    )
                    for result in leaf_reviews
                ]
                leaf_topic_hashes = [digest for digest, _result in leaf_topic_rows]
                leaf_review_hashes = [digest for digest, _result in leaf_review_rows]
                if len(set(leaf_topic_hashes)) != len(leaf_topic_hashes) or len(
                    set(leaf_review_hashes)
                ) != len(leaf_review_hashes):
                    raise result_validation.ResultValidationError(
                        "synthesis validation leaf contains duplicate results"
                    )
                if sorted(leaf_topic_hashes) != sorted(
                    current_metadata.get("validation_topic_result_hashes", [])
                ) or sorted(leaf_review_hashes) != sorted(
                    current_metadata.get("validation_independent_review_hashes", [])
                ):
                    raise result_validation.ResultValidationError(
                        "synthesis validation leaf commitments changed"
                    )
                if topic_hashes & set(leaf_topic_hashes) or review_hashes & set(
                    leaf_review_hashes
                ):
                    raise result_validation.ResultValidationError(
                        "synthesis validation hierarchy contains duplicate results"
                    )
                topic_hashes.update(leaf_topic_hashes)
                review_hashes.update(leaf_review_hashes)
                topics.extend(leaf_topic_rows)
                reviews.extend(leaf_review_rows)
            for child_ref in child_refs:
                child = state["jobs"].get(child_ref)
                if not isinstance(child, Mapping):
                    raise result_validation.ResultValidationError(
                        "synthesis validation child task is missing"
                    )
                pending.append(child)

        try:
            source_topic_tasks = self._accepted_final_topic_tasks(state)
        except InvalidTransitionError as exc:
            raise result_validation.ResultValidationError(str(exc)) from exc
        source_hashes = sorted(
            result_validation.canonical_result_hash(
                agent_results.for_task(self.run_dir, source_task)
            )
            for source_task in source_topic_tasks
        )
        if sorted(digest for digest, _result in topics) != source_hashes:
            raise result_validation.ResultValidationError(
                "synthesis topic results do not exactly match accepted final roots"
            )
        return (
            [result for _digest, result in sorted(topics)],
            [result for _digest, result in sorted(reviews)],
        )

    def _synthesis_reduce_payload(
        self,
        tasks: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        results = agent_results.copies_for_tasks(
            self.run_dir, tasks, label="accepted synthesis"
        )
        return {
            "child_result_hashes": [
                result_validation.canonical_result_hash(result) for result in results
            ],
            "child_synthesis_results": results,
            "schema": "global_synthesis_hierarchical_input_v2",
        }
