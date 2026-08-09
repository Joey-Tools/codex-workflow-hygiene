"""Bounded source-acceptance input collection."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from . import catalog, safe_io
from .identity import IdentityKey
from .orchestrator_support import InvalidInputError
from .source_spool import StreamingRawPayloadStaging
from .source_staging import (
    MaterializedFiles,
    PreparedFile,
    materialize,
    prepare_raw_payload,
)


TransportSegments = dict[
    str,
    Iterable[tuple[Iterable[Mapping[str, Any]], object]],
]


def normalize_transport_inputs(
    *,
    raw_records: Mapping[str, bytes] | None,
    transport_streams: Mapping[str, Iterable[Mapping[str, Any]]] | None,
    transport_requests: Mapping[str, object] | None,
    transport_segments: Mapping[
        str,
        Iterable[tuple[Iterable[Mapping[str, Any]], object]],
    ]
    | None,
) -> tuple[dict[str, bytes], TransportSegments | None]:
    if raw_records is not None and any(
        value is not None
        for value in (transport_streams, transport_requests, transport_segments)
    ):
        raise InvalidInputError(
            "raw record files and session-shards streams are mutually exclusive"
        )
    if transport_segments is not None and (
        transport_streams is not None or transport_requests is not None
    ):
        raise InvalidInputError(
            "segmented and legacy session-shards inputs are mutually exclusive"
        )
    raw_values = {} if raw_records is None else dict(raw_records)
    if any(
        not isinstance(key, str) or not isinstance(value, bytes)
        for key, value in raw_values.items()
    ):
        raise InvalidInputError("raw_records must map unit_ref strings to bytes")
    if transport_segments is not None:
        segments = dict(transport_segments)
    elif transport_streams is not None:
        streams = dict(transport_streams)
        if transport_requests is None:
            raise InvalidInputError(
                "session-shards streams require exact request manifests"
            )
        request_values = dict(transport_requests)
        if set(streams) != set(request_values):
            raise InvalidInputError(
                "session-shards streams and requests must cover the same sources"
            )
        segments = {
            source_ref: ((streams[source_ref], request_values[source_ref]),)
            for source_ref in streams
        }
    elif transport_requests is not None:
        raise InvalidInputError(
            "session-shards requests require matching transport streams"
        )
    else:
        segments = None
    return raw_values, segments


class SourcePayloadCollection:
    """Collect compact payload metadata while retaining bytes outside the heap."""

    def __init__(
        self,
        identity: IdentityKey,
        run_dir: Path,
        consumed: Mapping[str, catalog.SourceTransportRecord],
        *,
        model_era_for_payload: Callable[[bytes], str | None],
        validate_unit_ref: Callable[[str], None],
    ) -> None:
        self.identity = identity
        self.run_dir = run_dir
        self.consumed = dict(consumed)
        self.model_era_for_payload = model_era_for_payload
        self.validate_unit_ref = validate_unit_ref
        self.model_era_evidence: dict[str, tuple[str, str]] = {}
        self.staged: dict[str, dict[str, Any]] = {}
        self.payload_metadata: dict[str, dict[str, Any]] = {}
        self.prepared_raw_files: list[PreparedFile] = []
        self._streamed: StreamingRawPayloadStaging | None = None

    def enable_streaming(
        self,
        *,
        max_bytes: int,
        max_records: int,
        spool_ref: str,
    ) -> None:
        if self._streamed is not None:
            raise InvalidInputError("source transport streaming is already enabled")
        self._streamed = StreamingRawPayloadStaging(
            self.identity,
            self.run_dir,
            max_bytes=max_bytes,
            max_records=max_records,
            spool_ref=spool_ref,
        )

    def add(
        self, unit_ref: str, payload: bytes
    ) -> catalog.SourceTransportRecord | None:
        if unit_ref in self.payload_metadata:
            raise InvalidInputError("session-shards streams duplicate a source unit")
        record = self.consumed.get(unit_ref)
        if record is None:
            raise InvalidInputError("raw_records contains an undeclared source unit")
        self.validate_unit_ref(unit_ref)
        commitment = catalog.content_commitment(payload)
        self.payload_metadata[unit_ref] = {
            "byte_count": len(payload),
            "content_commitment": commitment,
        }
        if len(payload) != record.byte_count:
            self.staged[unit_ref] = {
                "reason": "raw_payload_size_mismatch",
                "status": "gap",
            }
            return None
        if commitment != record.content_commitment:
            self.staged[unit_ref] = {
                "reason": "raw_payload_commitment_mismatch",
                "status": "gap",
            }
            return None
        if self._streamed is None:
            relative_path, prepared_file = prepare_raw_payload(
                self.identity,
                self.run_dir,
                unit_ref,
                payload,
            )
            self.prepared_raw_files.append(prepared_file)
            payload_state = {
                "byte_count": len(payload),
                "content_commitment": commitment,
                "relative_path": relative_path,
                "status": "available",
            }
        else:
            payload_state = self._streamed.add(unit_ref, payload)
        self.staged[unit_ref] = payload_state
        try:
            model_era = self.model_era_for_payload(payload)
        except (ValueError, safe_io.InvalidJsonError):
            model_era = None
        if model_era is not None:
            self.model_era_evidence[unit_ref] = (
                record.coordinate.source_ref,
                model_era,
            )
        return record

    def complete_missing(self) -> None:
        for unit_ref in self.consumed:
            self.validate_unit_ref(unit_ref)
            if unit_ref not in self.staged:
                self.staged[unit_ref] = {
                    "reason": "raw_payload_missing",
                    "status": "gap",
                }

    def discard_streamed(self, primary: BaseException | None = None) -> None:
        if self._streamed is None:
            return
        try:
            self._streamed.discard()
        except BaseException as cleanup_error:
            if primary is None:
                raise
            if hasattr(primary, "add_note"):
                primary.add_note(
                    "segmented source spool cleanup was incomplete; "
                    f"{type(cleanup_error).__name__}"
                )

    def materialize_with(
        self,
        acceptance_file: PreparedFile,
    ) -> MaterializedFiles:
        if self._streamed is None:
            return materialize((*self.prepared_raw_files, acceptance_file))
        return self._streamed.materialize((acceptance_file,))


def consumed_records(
    manifest: catalog.SourceTransportManifest,
) -> dict[str, catalog.SourceTransportRecord]:
    return {
        record.unit_ref: record
        for record in manifest.records
        if record.accounting_class is catalog.AccountingClass.CONSUMED_CANDIDATE
    }


def consumed_source_refs(
    records: Mapping[str, catalog.SourceTransportRecord],
) -> set[str]:
    return {record.coordinate.source_ref for record in records.values()}


def model_era_indexes(
    evidence: Mapping[str, tuple[str, str]],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    by_unit = {
        unit_ref: model_era for unit_ref, (_session_ref, model_era) in evidence.items()
    }
    by_session: dict[str, list[str]] = {}
    for session_ref, model_era in evidence.values():
        by_session[session_ref] = sorted({*by_session.get(session_ref, []), model_era})
    return by_unit, by_session


def segment_descriptor(
    lease_ref: str,
    manifest: catalog.SourceTransportManifest,
    receipt: Any,
    source_snapshot: Any,
) -> dict[str, Any]:
    return {
        "lease_ref": lease_ref,
        "manifest": manifest.to_dict(),
        "metrics": {
            "byte_count": manifest.total_bytes,
            "record_count": manifest.total_records,
            "scan_byte_count": source_snapshot.terminal_byte_offset,
        },
        "receipt": receipt.to_dict(),
        "receipt_ref": receipt.receipt_ref,
        "snapshot_ref": source_snapshot.snapshot_ref,
        "source_snapshot": source_snapshot.to_dict(),
    }
