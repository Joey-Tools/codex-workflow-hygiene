"""Bounded owner-only sidecars for accepted source segments."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import (
    catalog,
    safe_io,
    source_capacity,
    source_payloads,
    transport as source_transport,
)
from .checkpoints import canonical_json_bytes
from .contracts import (
    MAX_SOURCE_ACCEPTANCE_BYTES,
    MAX_SOURCE_ACCEPTANCE_SEGMENTS_PER_CELL,
    SourceCellStatus,
    strict_json_loads,
)
from .identity import IdentityKey
from .orchestrator_core import RAW_INPUT_DIRECTORY
from .orchestrator_support import InvalidTransitionError
from .source_acceptance import (  # noqa: F401
    SourcePayloadCollection,
    consumed_records,
    consumed_source_refs,
    model_era_indexes,
    normalize_transport_inputs,
    segment_descriptor,
)
from .source_staging import (  # noqa: F401
    MaterializedFile,
    MaterializedFiles,
    PreparedFile,
    materialize,
    prepare_file,
    prepare_raw_payload,
    raw_payload_relative_path,
    rollback,
)
from .source_spool import (  # noqa: F401
    SOURCE_TRANSPORT_SPOOL_DIRECTORY,
    StreamingRawPayloadStaging,
)


SOURCE_ACCEPTANCE_SCHEMA = "source_acceptance_v2"
SOURCE_ACCEPTANCE_DESCRIPTOR_SCHEMA = "source_acceptance_descriptor_v2"
SOURCE_ACCEPTANCE_DIRECTORY = f"{RAW_INPUT_DIRECTORY}/source-acceptances"
MAX_SOURCE_ACCEPTANCE_SEGMENTS = MAX_SOURCE_ACCEPTANCE_SEGMENTS_PER_CELL
_DESCRIPTOR_FIELDS = frozenset(
    {"byte_count", "content_commitment", "relative_path", "schema"}
)


@dataclass(frozen=True, slots=True)
class PreparedAcceptance:
    descriptor: dict[str, Any]
    file: PreparedFile


def require_new_segment_capacity(cell: Mapping[str, Any]) -> None:
    descriptors = cell.get("continuation_segments")
    if not isinstance(descriptors, Sequence) or isinstance(descriptors, (str, bytes)):
        raise InvalidTransitionError("source continuation descriptors are invalid")
    if len(descriptors) >= MAX_SOURCE_ACCEPTANCE_SEGMENTS:
        raise InvalidTransitionError("source continuation chain exceeds bounds")


def prepare_acceptance(
    run_dir: Path,
    *,
    segment: Mapping[str, Any],
    payloads: Mapping[str, Any],
    model_era_by_unit: Mapping[str, str],
    model_eras_by_session: Mapping[str, Sequence[str]],
) -> PreparedAcceptance:
    payload = canonical_json_bytes(
        {
            "model_era_by_unit": dict(sorted(model_era_by_unit.items())),
            "model_eras_by_session": {
                key: list(values)
                for key, values in sorted(model_eras_by_session.items())
            },
            "payloads": dict(sorted(payloads.items())),
            "schema": SOURCE_ACCEPTANCE_SCHEMA,
            "segment": dict(segment),
        }
    )
    if len(payload) > MAX_SOURCE_ACCEPTANCE_BYTES:
        raise InvalidTransitionError("source acceptance sidecar exceeds its byte bound")
    digest = hashlib.sha256(payload).hexdigest()
    name = f"source-acceptance-v2-{digest}.json"
    relative_path = f"{SOURCE_ACCEPTANCE_DIRECTORY}/{name}"
    descriptor = {
        "byte_count": len(payload),
        "content_commitment": f"sha256:{digest}",
        "relative_path": relative_path,
        "schema": SOURCE_ACCEPTANCE_DESCRIPTOR_SCHEMA,
    }
    return PreparedAcceptance(
        descriptor=descriptor,
        file=PreparedFile(run_dir / relative_path, payload),
    )


def _validated_descriptor(value: Mapping[str, Any]) -> tuple[int, str, str]:
    if not isinstance(value, Mapping) or set(value) != _DESCRIPTOR_FIELDS:
        raise InvalidTransitionError("source acceptance descriptor is invalid")
    byte_count = value.get("byte_count")
    commitment = value.get("content_commitment")
    relative_path = value.get("relative_path")
    if (
        value.get("schema") != SOURCE_ACCEPTANCE_DESCRIPTOR_SCHEMA
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or not 0 < byte_count <= MAX_SOURCE_ACCEPTANCE_BYTES
        or not isinstance(commitment, str)
        or len(commitment) != 71
        or not commitment.startswith("sha256:")
        or not isinstance(relative_path, str)
    ):
        raise InvalidTransitionError("source acceptance descriptor is invalid")
    digest = commitment.removeprefix("sha256:")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise InvalidTransitionError("source acceptance descriptor is invalid")
    expected = f"{SOURCE_ACCEPTANCE_DIRECTORY}/source-acceptance-v2-{digest}.json"
    if relative_path != expected:
        raise InvalidTransitionError("source acceptance descriptor path is invalid")
    return byte_count, digest, relative_path


def load(run_dir: Path, descriptor: Mapping[str, Any]) -> dict[str, Any]:
    byte_count, digest, relative_path = _validated_descriptor(descriptor)
    try:
        payload = safe_io.read_bounded_bytes(
            run_dir / relative_path,
            max_bytes=byte_count,
            require_owner_only=True,
        )
    except (OSError, safe_io.UnsafePathError) as error:
        raise InvalidTransitionError(
            "source acceptance sidecar cannot be authenticated"
        ) from error
    if len(payload) != byte_count or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(), digest
    ):
        raise InvalidTransitionError("source acceptance sidecar changed")
    try:
        decoded = strict_json_loads(payload)
    except (TypeError, ValueError) as error:
        raise InvalidTransitionError("source acceptance sidecar is invalid") from error
    if (
        not isinstance(decoded, dict)
        or set(decoded)
        != {
            "model_era_by_unit",
            "model_eras_by_session",
            "payloads",
            "schema",
            "segment",
        }
        or decoded.get("schema") != SOURCE_ACCEPTANCE_SCHEMA
        or not isinstance(decoded.get("segment"), dict)
        or not isinstance(decoded.get("payloads"), dict)
        or not isinstance(decoded.get("model_era_by_unit"), dict)
        or not isinstance(decoded.get("model_eras_by_session"), dict)
        or canonical_json_bytes(decoded) != payload
    ):
        raise InvalidTransitionError("source acceptance sidecar is invalid")
    source_payloads.merge_payload_indexes(decoded["payloads"])
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in decoded["model_era_by_unit"].items()
    ):
        raise InvalidTransitionError("source acceptance model-era index is invalid")
    for key, values in decoded["model_eras_by_session"].items():
        if (
            not isinstance(key, str)
            or not isinstance(values, list)
            or any(not isinstance(value, str) for value in values)
            or values != sorted(set(values))
        ):
            raise InvalidTransitionError(
                "source acceptance session model-era index is invalid"
            )
    return decoded


def materialized_segment(run_dir: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") == SOURCE_ACCEPTANCE_DESCRIPTOR_SCHEMA:
        return load(run_dir, value)
    if "manifest" in value:
        return {
            "model_era_by_unit": {},
            "model_eras_by_session": {},
            "payloads": {},
            "schema": SOURCE_ACCEPTANCE_SCHEMA,
            "segment": dict(value),
        }
    raise InvalidTransitionError("source continuation descriptor is invalid")


def materialize_segments(
    run_dir: Path,
    values: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not values or len(values) > MAX_SOURCE_ACCEPTANCE_SEGMENTS:
        raise InvalidTransitionError("source segment chain exceeds its bound")
    segments: list[dict[str, Any]] = []
    payloads: dict[str, Any] = {}
    model_era_by_unit: dict[str, str] = {}
    model_eras_by_session: dict[str, set[str]] = {}
    usage = source_capacity.SourceUsage()
    for value in values:
        materialized = materialized_segment(run_dir, value)
        segment = materialized["segment"]
        if not isinstance(segment, dict):
            raise InvalidTransitionError("source continuation segment is invalid")
        source_capacity.observe_segment(usage, value, segment)
        segments.append(segment)
        source_payloads.merge_payload_index_into(payloads, materialized["payloads"])
        for unit_ref, model_era in materialized["model_era_by_unit"].items():
            existing = model_era_by_unit.get(unit_ref)
            if existing is not None and existing != model_era:
                raise InvalidTransitionError("source continuation model era changed")
            model_era_by_unit[unit_ref] = model_era
        for session_ref, model_eras in materialized["model_eras_by_session"].items():
            model_eras_by_session.setdefault(session_ref, set()).update(model_eras)
    return {
        "model_era_by_unit": model_era_by_unit,
        "model_eras_by_session": {
            key: sorted(values) for key, values in model_eras_by_session.items()
        },
        "payloads": dict(sorted(payloads.items())),
        "segments": tuple(segments),
    }


def manifest_summary(manifest: catalog.SourceTransportManifest) -> dict[str, Any]:
    return {
        "absence_proof": manifest.absence_proof,
        "enumeration_gap": (
            None
            if manifest.enumeration_gap is None
            else manifest.enumeration_gap.to_dict()
        ),
        "snapshot_commitment": manifest.snapshot_commitment,
        "status": manifest.status.value,
        "total_bytes": manifest.total_bytes,
        "total_records": manifest.total_records,
    }


def manifest_matches_persisted(
    value: object,
    manifest: catalog.SourceTransportManifest,
) -> bool:
    """Accept the exact compact form or the same-schema legacy full manifest."""

    return value == manifest_summary(manifest) or value == manifest.to_dict()


def aggregate_segments(
    identity: IdentityKey,
    run_dir: Path,
    values: Sequence[Mapping[str, Any]],
) -> tuple[catalog.SourceTransportManifest, str, str]:
    materialized = materialize_segments(run_dir, values)
    manifests: list[catalog.SourceTransportManifest] = []
    snapshot_refs: list[str] = []
    receipt_refs: list[str] = []
    segments = materialized["segments"]
    for index, segment in enumerate(segments):
        try:
            manifest = catalog.SourceTransportManifest.from_dict(segment["manifest"])
            snapshot = source_transport.AuthoritativeSourceSnapshot.from_dict(
                segment["source_snapshot"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            catalog.CatalogValidationError,
            source_transport.TransportValidationError,
        ) as error:
            raise InvalidTransitionError(
                "persisted source continuation segment is invalid"
            ) from error
        if snapshot.snapshot_ref != segment.get("snapshot_ref") or not isinstance(
            segment.get("receipt_ref"), str
        ):
            raise InvalidTransitionError(
                "persisted source continuation binding is invalid"
            )
        if index < len(segments) - 1:
            if (
                manifest.status is not SourceCellStatus.GAP
                or snapshot.resume_position is None
            ):
                raise InvalidTransitionError(
                    "non-final source segment lacks continuation authority"
                )
        elif snapshot.resume_position is not None:
            raise InvalidTransitionError("final source segment is still incomplete")
        manifests.append(manifest)
        snapshot_refs.append(snapshot.snapshot_ref)
        receipt_refs.append(str(segment["receipt_ref"]))

    first = manifests[0]
    final = manifests[-1]
    if any(
        manifest.host_ref != first.host_ref
        or manifest.source_kind is not first.source_kind
        or manifest.window_start != first.window_start
        or manifest.window_end != first.window_end
        or manifest.transport_kind is not first.transport_kind
        for manifest in manifests
    ):
        raise InvalidTransitionError("source continuation segment scope changed")
    records_by_ref: dict[str, catalog.CatalogRecord] = {}
    for manifest in manifests:
        for record in manifest.records:
            existing = records_by_ref.get(record.unit_ref)
            if existing is not None and existing != record:
                raise InvalidTransitionError("source continuation records conflict")
            records_by_ref[record.unit_ref] = record
    records = sorted(records_by_ref.values(), key=catalog.catalog_record_sort_key)
    status = final.status
    if status is SourceCellStatus.NO_ACTIVITY and records:
        status = SourceCellStatus.COMPLETE
    if status is SourceCellStatus.VERIFIED_ABSENT and records:
        raise InvalidTransitionError(
            "source continuation cannot end absent after discovering records"
        )
    aggregate = catalog.SourceTransportManifest.create(
        host_ref=first.host_ref,
        transport_kind=first.transport_kind,
        source_kind=first.source_kind,
        window_start=first.window_start,
        window_end=first.window_end,
        status=status,
        records=records,
        snapshot_commitment=(
            catalog.snapshot_commitment_for_records(records)
            if status in {SourceCellStatus.COMPLETE, SourceCellStatus.NO_ACTIVITY}
            else None
        ),
        absence_proof=(
            final.absence_proof if status is SourceCellStatus.VERIFIED_ABSENT else None
        ),
        enumeration_gap=(
            final.enumeration_gap if status is SourceCellStatus.GAP else None
        ),
        remote=final.remote,
    )
    if len(segments) == 1:
        return aggregate, snapshot_refs[0], receipt_refs[0]
    aggregate_snapshot_ref = (
        source_transport.SOURCE_SNAPSHOT_REF_PREFIX
        + identity.derive_digest(
            "source-transport-aggregate-snapshot/v2",
            {
                "manifest": aggregate.to_dict(),
                "segment_snapshot_refs": snapshot_refs,
            },
        )
    )
    aggregate_receipt_ref = (
        source_transport.TRANSPORT_RECEIPT_REF_PREFIX
        + identity.derive_digest(
            "source-transport-aggregate-receipt/v2",
            {
                "aggregate_snapshot_ref": aggregate_snapshot_ref,
                "segment_receipt_refs": receipt_refs,
            },
        )
    )
    return aggregate, aggregate_snapshot_ref, aggregate_receipt_ref
