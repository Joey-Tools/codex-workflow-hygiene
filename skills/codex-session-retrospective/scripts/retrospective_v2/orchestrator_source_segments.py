"""Frozen multi-segment session-shards source consumption."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from . import catalog
from .contracts import (
    SessionShardsRequest,
    session_shards_resume_cursor_value,
)
from .orchestrator_support import (
    InvalidInputError,
    SOURCE_TRANSPORT_MAX_RECORDS,
    consume_session_shard_frames,
)
from .sharding import RawEvidenceRecord


def consume_session_shard_segments(
    manifest: catalog.SourceTransportManifest,
    source_ref: str,
    segments: Iterable[
        tuple[
            Iterable[Mapping[str, Any]],
            SessionShardsRequest | Mapping[str, Any],
        ]
    ],
    *,
    limits: Any,
    on_record: Callable[[RawEvidenceRecord], None],
) -> tuple[SessionShardsRequest, ...]:
    catalog_records = tuple(
        sorted(
            (
                record
                for record in manifest.records
                if record.coordinate.source_ref == source_ref
            ),
            key=lambda record: (
                record.coordinate.byte_start,
                record.coordinate.byte_end,
                record.coordinate.record_ref,
                record.unit_ref,
            ),
        )
    )
    if not catalog_records:
        raise InvalidInputError("session-shards source has no catalog records")
    expected_byte = catalog_records[0].coordinate.byte_start
    final_byte = catalog_records[-1].coordinate.byte_end
    initial_record_index: int | None = None
    expected_record_index: int | None = None
    chain: tuple[str, int, str, str, int, int, int] | None = None
    accepted: list[SessionShardsRequest] = []
    for position, segment in enumerate(segments):
        if position >= SOURCE_TRANSPORT_MAX_RECORDS:
            raise InvalidInputError("session-shards segment count exceeds its bound")
        if not isinstance(segment, tuple) or len(segment) != 2:
            raise InvalidInputError("session-shards segment shape is invalid")
        frames, request_value = segment
        try:
            request = (
                request_value
                if isinstance(request_value, SessionShardsRequest)
                else SessionShardsRequest.from_dict(request_value)
            )
            cursor = session_shards_resume_cursor_value(request.resume_cursor)
        except (TypeError, ValueError) as error:
            raise InvalidInputError(
                "session-shards request violates its closed contract"
            ) from error
        assert request.byte_end is not None
        request_chain = (
            request.source_token or "",
            int(cursor["frozen_byte_end"]),
            str(cursor["prefix_commitment"]),
            request.rollout,
            request.shard_bytes,
            request.max_shards,
            request.record_processing_budget_bytes,
        )
        if expected_record_index is None:
            initial_record_index = request.record_start
            expected_record_index = request.record_start
            chain = request_chain
        if (
            request.mode != "records"
            or request.byte_start != expected_byte
            or request.record_start != expected_record_index
            or request_chain != chain
        ):
            raise InvalidInputError(
                "session-shards segments are not one frozen contiguous chain"
            )
        consumption = consume_session_shard_frames(
            manifest,
            source_ref,
            frames,
            request=request,
            limits=limits,
            on_raw_record=on_record,
        )
        if consumption.source_token != request.source_token:
            raise InvalidInputError("session-shards segment source token changed")
        expected_byte = request.byte_end
        expected_record_index += consumption.record_count
        accepted.append(request)
    if (
        not accepted
        or expected_byte != final_byte
        or initial_record_index is None
        or expected_record_index is None
        or expected_record_index - initial_record_index != len(catalog_records)
    ):
        raise InvalidInputError(
            "session-shards segments do not cover the complete catalog source"
        )
    return tuple(accepted)
