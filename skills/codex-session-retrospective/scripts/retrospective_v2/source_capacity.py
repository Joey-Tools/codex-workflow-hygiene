"""Run-global capacity accounting for retained source evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import (
    MAX_RUN_SOURCE_ACCEPTANCE_BYTES,
    MAX_RUN_SOURCE_BYTES,
    MAX_RUN_SOURCE_RECORDS,
    MAX_RUN_SOURCE_SEGMENTS,
    MAX_SOURCE_ACCEPTANCE_BYTES,
    MAX_SOURCE_ACCEPTANCE_SEGMENTS_PER_CELL,
)
from .orchestrator_core import InvalidTransitionError


@dataclass(slots=True)
class SourceUsage:
    acceptance_bytes: int = 0
    byte_count: int = 0
    record_count: int = 0
    segment_count: int = 0

    def add(
        self,
        *,
        acceptance_bytes: int,
        byte_count: int,
        record_count: int,
        segment_count: int = 1,
    ) -> None:
        values = (acceptance_bytes, byte_count, record_count, segment_count)
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ):
            raise InvalidTransitionError("source capacity counters are invalid")
        candidate = (
            self.acceptance_bytes + acceptance_bytes,
            self.byte_count + byte_count,
            self.record_count + record_count,
            self.segment_count + segment_count,
        )
        limits = (
            MAX_RUN_SOURCE_ACCEPTANCE_BYTES,
            MAX_RUN_SOURCE_BYTES,
            MAX_RUN_SOURCE_RECORDS,
            MAX_RUN_SOURCE_SEGMENTS,
        )
        labels = ("acceptance bytes", "bytes", "records", "segments")
        for value, limit, label in zip(candidate, limits, labels, strict=True):
            if value > limit:
                raise InvalidTransitionError(
                    f"run source {label} exceed cleanup capacity"
                )
        (
            self.acceptance_bytes,
            self.byte_count,
            self.record_count,
            self.segment_count,
        ) = candidate


def _acceptance_bytes(value: Mapping[str, Any]) -> int:
    if value.get("schema") == "source_acceptance_descriptor_v2":
        byte_count = value.get("byte_count")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or not 0 < byte_count <= MAX_SOURCE_ACCEPTANCE_BYTES
        ):
            raise InvalidTransitionError("source acceptance descriptor is invalid")
        return byte_count
    if "manifest" in value:
        return 0
    raise InvalidTransitionError("source continuation descriptor is invalid")


def observe_segment(
    usage: SourceUsage,
    descriptor: Mapping[str, Any],
    segment: Mapping[str, Any],
) -> None:
    metrics = segment.get("metrics")
    if not isinstance(metrics, Mapping):
        raise InvalidTransitionError("source continuation metrics are invalid")
    usage.add(
        acceptance_bytes=_acceptance_bytes(descriptor),
        byte_count=metrics.get("byte_count"),
        record_count=metrics.get("record_count"),
    )


def usage_from_cells(cells: Mapping[str, Any]) -> SourceUsage:
    usage = SourceUsage()
    for host_cells in cells.values():
        if not isinstance(host_cells, Mapping):
            raise InvalidTransitionError("source cell matrix is invalid")
        for cell in host_cells.values():
            if not isinstance(cell, Mapping) or not isinstance(
                cell.get("metrics"), Mapping
            ):
                raise InvalidTransitionError("source cell capacity state is invalid")
            descriptors = cell.get("continuation_segments")
            if not isinstance(descriptors, Sequence) or isinstance(
                descriptors, (str, bytes)
            ):
                raise InvalidTransitionError(
                    "source continuation descriptors are invalid"
                )
            if len(descriptors) > MAX_SOURCE_ACCEPTANCE_SEGMENTS_PER_CELL:
                raise InvalidTransitionError(
                    "source continuation chain exceeds cleanup capacity"
                )
            acceptance_bytes = 0
            for descriptor in descriptors:
                if not isinstance(descriptor, Mapping):
                    raise InvalidTransitionError(
                        "source continuation descriptor is invalid"
                    )
                acceptance_bytes += _acceptance_bytes(descriptor)
            metrics = cell["metrics"]
            usage.add(
                acceptance_bytes=acceptance_bytes,
                byte_count=metrics.get("byte_count"),
                record_count=metrics.get("record_count"),
                segment_count=len(descriptors),
            )
    return usage


def require_candidate_capacity(
    cells: Mapping[str, Any],
    *,
    acceptance_bytes: int,
    byte_count: int,
    record_count: int,
) -> None:
    usage_from_cells(cells).add(
        acceptance_bytes=acceptance_bytes,
        byte_count=byte_count,
        record_count=record_count,
    )
