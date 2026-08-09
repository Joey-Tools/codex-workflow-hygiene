"""Bounded two-pass raw-shard planning and staged materialization."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import catalog, safe_io, sharding
from .orchestrator_support import InvalidTransitionError, RAW_SHARD_DIRECTORY


def _raw_records(
    run_dir: Path,
    records: Sequence[catalog.CatalogRecord],
    payload_state: Mapping[str, Mapping[str, Any]],
    limits: sharding.ShardLimits,
) -> Iterable[sharding.RawEvidenceRecord | sharding.DeferredRawGap]:
    for record in records:
        if record.byte_count > limits.record_processing_budget:
            yield sharding.DeferredRawGap(record, "oversized_record_budget_exceeded")
            continue
        if record.turn_count > limits.max_turns:
            yield sharding.DeferredRawGap(record, "record_turn_limit_exceeded")
            continue
        payload = payload_state[record.unit_ref]
        relative_path = payload.get("relative_path")
        if not isinstance(relative_path, str):
            raise InvalidTransitionError("materializable source unit lacks raw input")
        data = safe_io.read_bounded_bytes(
            run_dir / relative_path,
            max_bytes=max(1, record.byte_count),
            require_owner_only=True,
        )
        yield sharding.RawEvidenceRecord(catalog_record=record, payload=data)


@dataclass(frozen=True, slots=True)
class RawShardStage:
    run_dir: Path
    records: tuple[catalog.CatalogRecord, ...]
    payload_state: Mapping[str, Mapping[str, Any]]
    limits: sharding.ShardLimits
    plan: sharding.ShardPlan

    def _raw_records(
        self,
    ) -> Iterable[sharding.RawEvidenceRecord | sharding.DeferredRawGap]:
        return _raw_records(
            self.run_dir,
            self.records,
            self.payload_state,
            self.limits,
        )

    def materialize(self) -> sharding.RawShardStageReceipt:
        return sharding.materialize_ordered_raw_shards(
            self._raw_records(),
            self.run_dir / RAW_SHARD_DIRECTORY,
            plan=self.plan,
            limits=self.limits,
        )

    @staticmethod
    def rollback(receipt: sharding.RawShardStageReceipt) -> None:
        sharding.rollback_ordered_raw_shards(receipt)


def prepare(
    run_dir: Path,
    records: Sequence[catalog.CatalogRecord],
    payload_state: Mapping[str, Mapping[str, Any]],
    limits: sharding.ShardLimits,
) -> RawShardStage:
    ordered = tuple(sorted(records, key=catalog.catalog_record_sort_key))
    plan = sharding.plan_ordered_raw_shards(
        _raw_records(run_dir, ordered, payload_state, limits),
        limits=limits,
    )
    return RawShardStage(
        run_dir=run_dir,
        records=ordered,
        payload_state=payload_state,
        limits=limits,
        plan=plan,
    )
