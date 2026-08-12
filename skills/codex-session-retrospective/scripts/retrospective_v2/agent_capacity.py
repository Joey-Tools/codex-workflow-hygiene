"""Partitioned task reservations for one bounded retrospective run."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import (
    MAX_AGENT_CHECKPOINT_TASK_BYTES,
    MAX_RUN_AGENT_TASKS,
    MAX_RUN_DOWNSTREAM_AGENT_TASKS,
    MAX_RUN_RAW_SHARDS,
    JobKind,
)
from .checkpoints import canonical_json_bytes
from .orchestrator_support import InvalidInputError, RunConflictError


@dataclass(frozen=True, slots=True)
class TaskReservation:
    total_misses: int
    partition_metric: str
    partition_misses: int

    def commit(self, metrics: dict[str, Any]) -> None:
        metrics["agent_task_cache_misses"] = self.total_misses + 1
        metrics[self.partition_metric] = self.partition_misses + 1


def validate_checkpoint_task(task: Mapping[str, Any]) -> None:
    byte_count = len(canonical_json_bytes(dict(task)))
    if byte_count > MAX_AGENT_CHECKPOINT_TASK_BYTES:
        raise InvalidInputError(
            "agent task exceeds its checkpoint byte budget "
            f"({byte_count} > {MAX_AGENT_CHECKPOINT_TASK_BYTES})"
        )


def reserve(state: Mapping[str, Any], kind: str) -> TaskReservation:
    metrics = state.get("metrics")
    jobs = state.get("jobs")
    if not isinstance(metrics, Mapping) or not isinstance(jobs, Mapping):
        raise RunConflictError("agent task capacity state is invalid")
    misses = metrics.get("agent_task_cache_misses", 0)
    if isinstance(misses, bool) or not isinstance(misses, int) or misses < 0:
        raise RunConflictError("agent task cache miss count is invalid")
    if misses >= MAX_RUN_AGENT_TASKS:
        raise InvalidInputError("agent task count exceeds cleanup capacity")

    extractor = kind == JobKind.EXTRACTOR_REDACTOR.value
    partition_metric = (
        "extractor_agent_task_misses" if extractor else "downstream_agent_task_misses"
    )
    partition_limit = (
        MAX_RUN_RAW_SHARDS if extractor else MAX_RUN_DOWNSTREAM_AGENT_TASKS
    )
    partition_label = "extractor agent task" if extractor else "downstream agent task"
    partition_misses = metrics.get(partition_metric)
    if partition_misses is None:
        partition_misses = sum(
            1
            for task in jobs.values()
            if isinstance(task, Mapping)
            and task.get("category") == "agent"
            and (task.get("job_kind") == JobKind.EXTRACTOR_REDACTOR.value) == extractor
        )
    if (
        isinstance(partition_misses, bool)
        or not isinstance(partition_misses, int)
        or partition_misses < 0
    ):
        raise RunConflictError(f"{partition_label} count is invalid")
    if partition_misses >= partition_limit:
        raise InvalidInputError(f"{partition_label} count exceeds its reserved budget")
    return TaskReservation(misses, partition_metric, partition_misses)
