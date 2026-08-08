"""Bounded validation and capture of source transport streams."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
import hashlib
from typing import Any, Iterable, Mapping

try:
    from . import catalog
    from .contracts import JsonValue, SourceCellStatus
    from .transport_contracts import (
        SOURCE_TRANSPORT_MAX_RECORD_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
        SOURCE_TRANSPORT_STREAM_SCHEMA,
        TRANSPORT_LEASE_AUTH_PREFIX,
        CapturedSourceRecord,
        SourceTransportCapture,
        TransportLease,
        TransportValidationError,
        _LOCATOR_RE,
        _REASON_RE,
        _canonical_commitment,
        _derive_source_resume_position,
        _exact_keys,
        _non_negative_int,
        _normalize_source_resume_position,
        _positive_int,
        _sha256,
        _source_transport_inventory_commitment,
        _source_transport_resume_probe,
        _stream_frame,
    )
except (ImportError, ModuleNotFoundError):
    import catalog  # type: ignore[no-redef]
    from contracts import JsonValue, SourceCellStatus  # type: ignore[no-redef]
    from transport_contracts import (  # type: ignore[no-redef]
        SOURCE_TRANSPORT_MAX_RECORD_BYTES,
        SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
        SOURCE_TRANSPORT_STREAM_SCHEMA,
        TRANSPORT_LEASE_AUTH_PREFIX,
        CapturedSourceRecord,
        SourceTransportCapture,
        TransportLease,
        TransportValidationError,
        _LOCATOR_RE,
        _REASON_RE,
        _canonical_commitment,
        _derive_source_resume_position,
        _exact_keys,
        _non_negative_int,
        _normalize_source_resume_position,
        _positive_int,
        _sha256,
        _source_transport_inventory_commitment,
        _source_transport_resume_probe,
        _stream_frame,
    )


@dataclass(frozen=True, slots=True)
class _TerminalEvidence:
    status: SourceCellStatus
    reason: str
    resume_position: dict[str, JsonValue] | None
    inventory_commitment: str
    inventory_count: int
    scan_byte_count: int
    oversized_record_count: int
    oversized_byte_count: int
    emitted_record_count: int
    emitted_byte_count: int


class _SourceTransportCaptureValidator:
    def __init__(self, lease: TransportLease) -> None:
        self.lease = lease
        self.expected_header: dict[str, JsonValue] = {
            "cursor": {"ref": lease.source_cursor, "time": lease.cursor_time},
            "frame": "header",
            "host": lease.host,
            "lease_ref": lease.lease_ref,
            "limits": {
                "frame_bytes": lease.frame_byte_limit,
                "records": lease.record_limit,
                "source_bytes": lease.source_byte_limit,
            },
            "process_nonce": lease.process_nonce,
            "resume_position": lease.resume_position,
            "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
            "session_selector_commitment": lease.session_selector_commitment,
            "source_kind": lease.source_kind.value,
            "window": {"end": lease.window_end, "start": lease.window_start},
        }
        self.records: list[CapturedSourceRecord] = []
        self.inventory: list[dict[str, JsonValue]] = []
        self.inventory_by_coordinate: dict[tuple[str, int], dict[str, JsonValue]] = {}
        self.proof_rows: list[JsonValue] = []
        self.header_seen = False
        self.terminal: Mapping[str, object] | None = None
        self.pending: dict[str, object] | None = None
        self.resume_probe_pending: dict[str, object] | None = None
        self.resume_probe_payload: bytes | None = None
        self.resume_probe_locator: str | None = None
        self.resume_probe_range: tuple[int, int] | None = None
        self.wire_bytes = 0
        self.payload_bytes = 0
        self.prior_locator = (
            None
            if lease.resume_position is None
            else str(lease.resume_position["source_locator"])
        )
        self.prior_record_index = (
            -1
            if lease.resume_position is None
            else int(lease.resume_position["record_index"]) - 1
        )
        self.prior_byte_end = (
            0
            if lease.resume_position is None
            else int(lease.resume_position["byte_offset"])
        )
        self.prior_candidate_index = (
            -1
            if lease.resume_position is None
            else int(lease.resume_position["candidate_index"])
        )
        self.prior_source_size = (
            None
            if lease.resume_position is None
            else int(lease.resume_position["source_size"])
        )
        self.prior_source_token = (
            None
            if lease.resume_position is None
            else str(lease.resume_position["source_token"])
        )
        self.discovery_commitment = (
            None
            if lease.resume_position is None
            else str(lease.resume_position["discovery_commitment"])
        )
        self.wire_limit = (
            lease.source_byte_limit * 2
            + lease.record_limit * 4096
            + lease.frame_byte_limit * 2
            + SOURCE_TRANSPORT_RESUME_PROBE_BYTES * 2
        )

    def _finish_pending(self) -> None:
        if self.pending is None:
            return
        fragments = self.pending["fragments"]
        assert isinstance(fragments, list)
        fragment_count = int(self.pending["fragment_count"])
        if len(fragments) != fragment_count:
            raise TransportValidationError(
                "source transport record fragments are incomplete"
            )
        payload = b"".join(fragments)
        byte_start = int(self.pending["byte_start"])
        byte_end = int(self.pending["byte_end"])
        if len(payload) != byte_end - byte_start:
            raise TransportValidationError(
                "source transport record byte range does not match its payload"
            )
        self.payload_bytes += len(payload)
        if self.payload_bytes > self.lease.source_byte_limit:
            raise TransportValidationError(
                "source transport exceeded its source-byte lease"
            )
        record = CapturedSourceRecord(
            source_locator=str(self.pending["source_locator"]),
            record_index=int(self.pending["record_index"]),
            byte_start=byte_start,
            byte_end=byte_end,
            payload=payload,
        )
        inventory_row = self.inventory_by_coordinate.get(
            (record.source_locator, record.record_index)
        )
        if (
            inventory_row is None
            or inventory_row["accounting_class"]
            != catalog.AccountingClass.CONSUMED_CANDIDATE.value
            or inventory_row["byte_start"] != record.byte_start
            or inventory_row["byte_end"] != record.byte_end
            or inventory_row["content_commitment"]
            != "sha256:" + hashlib.sha256(payload).hexdigest()
        ):
            raise TransportValidationError(
                "source transport record does not match its inventory item"
            )
        self.records.append(record)
        self.proof_rows.append(
            {
                "byte_end": record.byte_end,
                "byte_start": record.byte_start,
                "content_commitment": "sha256:"
                + hashlib.sha256(record.payload).hexdigest(),
                "record_index": record.record_index,
                "source_locator_commitment": "sha256:"
                + hashlib.sha256(record.source_locator.encode("utf-8")).hexdigest(),
            }
        )
        self.pending = None

    def _accept_inventory(self, frame: Mapping[str, object]) -> None:
        self._finish_pending()
        _exact_keys(
            frame,
            {
                "accounting_class",
                "byte_end",
                "byte_start",
                "candidate_index",
                "content_commitment",
                "discovery_commitment",
                "event_time",
                "frame",
                "reason",
                "record_index",
                "schema",
                "session_commitment",
                "source_occurrence",
                "source_locator",
                "source_size",
                "source_token",
            },
            "source transport inventory item",
        )
        if frame["schema"] != SOURCE_TRANSPORT_STREAM_SCHEMA:
            raise TransportValidationError("source transport inventory schema changed")
        locator = frame["source_locator"]
        if not isinstance(locator, str) or _LOCATOR_RE.fullmatch(locator) is None:
            raise TransportValidationError(
                "source transport inventory locator is invalid"
            )
        record_index = _non_negative_int(
            frame["record_index"],
            "source transport inventory record_index",
        )
        byte_start = _non_negative_int(
            frame["byte_start"],
            "source transport inventory byte_start",
        )
        byte_end = _non_negative_int(
            frame["byte_end"],
            "source transport inventory byte_end",
        )
        if byte_end <= byte_start:
            raise TransportValidationError(
                "source transport inventory coordinates are invalid"
            )
        candidate_index = _non_negative_int(
            frame["candidate_index"],
            "source transport inventory candidate_index",
        )
        discovery_commitment = _sha256(
            frame["discovery_commitment"],
            "source transport inventory discovery_commitment",
        )
        source_size = _non_negative_int(
            frame["source_size"],
            "source transport inventory source_size",
        )
        source_token = _sha256(
            frame["source_token"],
            "source transport inventory source_token",
        )
        if byte_end > source_size:
            raise TransportValidationError(
                "source transport inventory exceeds its frozen source"
            )
        if self.discovery_commitment is None:
            self.discovery_commitment = discovery_commitment
        elif self.discovery_commitment != discovery_commitment:
            raise TransportValidationError(
                "source transport inventory discovery changed"
            )
        try:
            accounting_class = catalog.AccountingClass(frame["accounting_class"])
        except (TypeError, ValueError) as exc:
            raise TransportValidationError(
                "source transport inventory accounting class is invalid"
            ) from exc
        reason = frame["reason"]
        if not isinstance(reason, str) or _REASON_RE.fullmatch(reason) is None:
            raise TransportValidationError(
                "source transport inventory reason is invalid"
            )
        commitment = frame["content_commitment"]
        if commitment is not None:
            _sha256(commitment, "source transport inventory content commitment")
        source_occurrence = _sha256(
            frame["source_occurrence"],
            "source transport inventory occurrence",
        )
        event_time = self._normalized_event_time(frame["event_time"])
        session_commitment = frame["session_commitment"]
        if session_commitment is not None:
            _sha256(
                session_commitment,
                "source transport inventory session commitment",
            )
        self._validate_inventory_coordinate(
            locator,
            candidate_index=candidate_index,
            record_index=record_index,
            byte_start=byte_start,
            source_size=source_size,
            source_token=source_token,
        )
        normalized: dict[str, JsonValue] = {
            "accounting_class": accounting_class.value,
            "byte_end": byte_end,
            "byte_start": byte_start,
            "candidate_index": candidate_index,
            "content_commitment": commitment,  # type: ignore[dict-item]
            "discovery_commitment": discovery_commitment,
            "event_time": event_time,
            "frame": "inventory",
            "reason": reason,
            "record_index": record_index,
            "schema": SOURCE_TRANSPORT_STREAM_SCHEMA,
            "session_commitment": session_commitment,  # type: ignore[dict-item]
            "source_occurrence": source_occurrence,
            "source_locator": locator,
            "source_size": source_size,
            "source_token": source_token,
        }
        coordinate = (locator, record_index)
        if coordinate in self.inventory_by_coordinate:
            raise TransportValidationError(
                "source transport inventory contains a duplicate coordinate"
            )
        self.inventory.append(normalized)
        self.inventory_by_coordinate[coordinate] = normalized
        self.prior_locator = locator
        self.prior_candidate_index = candidate_index
        self.prior_record_index = record_index
        self.prior_byte_end = byte_end
        self.prior_source_size = source_size
        self.prior_source_token = source_token

    @staticmethod
    def _normalized_event_time(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TransportValidationError(
                "source transport inventory event time is invalid"
            )
        try:
            return catalog.canonical_utc_timestamp(
                value,
                "source transport inventory event time",
            )
        except catalog.CatalogValidationError as exc:
            raise TransportValidationError(
                "source transport inventory event time is invalid"
            ) from exc

    def _validate_inventory_coordinate(
        self,
        locator: str,
        *,
        candidate_index: int,
        record_index: int,
        byte_start: int,
        source_size: int,
        source_token: str,
    ) -> None:
        if self.prior_locator is not None:
            if locator.encode("utf-8") < self.prior_locator.encode("utf-8"):
                raise TransportValidationError(
                    "source transport inventory locators are not ordered"
                )
            if locator == self.prior_locator:
                if (
                    candidate_index != self.prior_candidate_index
                    or record_index != self.prior_record_index + 1
                    or byte_start != self.prior_byte_end
                    or source_size != self.prior_source_size
                    or source_token != self.prior_source_token
                ):
                    raise TransportValidationError(
                        "source transport inventory is not contiguous"
                    )
            elif (
                candidate_index <= self.prior_candidate_index
                or record_index != 0
                or byte_start != 0
            ):
                raise TransportValidationError(
                    "source transport inventory locator does not start at zero"
                )
        elif record_index != 0 or byte_start != 0 or candidate_index < 0:
            raise TransportValidationError(
                "source transport first inventory locator does not start at zero"
            )

    def _accept_record_fragment(self, frame: Mapping[str, object]) -> None:
        _exact_keys(
            frame,
            {
                "byte_end",
                "byte_start",
                "fragment_count",
                "fragment_index",
                "frame",
                "payload_b64",
                "record_index",
                "schema",
                "source_locator",
            },
            "source transport record fragment",
        )
        if frame["schema"] != SOURCE_TRANSPORT_STREAM_SCHEMA:
            raise TransportValidationError("source transport record schema changed")
        locator = frame["source_locator"]
        if not isinstance(locator, str) or _LOCATOR_RE.fullmatch(locator) is None:
            raise TransportValidationError("source transport source_locator is invalid")
        record_index = _non_negative_int(
            frame["record_index"], "source transport record_index"
        )
        byte_start = _non_negative_int(
            frame["byte_start"], "source transport byte_start"
        )
        byte_end = _non_negative_int(frame["byte_end"], "source transport byte_end")
        fragment_index = _non_negative_int(
            frame["fragment_index"], "source transport fragment_index"
        )
        fragment_count = _positive_int(
            frame["fragment_count"], "source transport fragment_count"
        )
        if byte_end <= byte_start or fragment_index >= fragment_count:
            raise TransportValidationError(
                "source transport fragment coordinates are invalid"
            )
        identity = (locator, record_index, byte_start, byte_end, fragment_count)
        if self.pending is None or self.pending["identity"] != identity:
            self._finish_pending()
            self._start_pending_fragment(
                identity,
                locator=locator,
                record_index=record_index,
                byte_start=byte_start,
                byte_end=byte_end,
                fragment_count=fragment_count,
            )
        fragments = self.pending["fragments"]
        assert isinstance(fragments, list)
        if fragment_index != len(fragments):
            raise TransportValidationError(
                "source transport fragments are missing or reordered"
            )
        payload_b64 = frame["payload_b64"]
        if not isinstance(payload_b64, str):
            raise TransportValidationError(
                "source transport fragment payload must be base64 text"
            )
        try:
            fragments.append(base64.b64decode(payload_b64, validate=True))
        except (binascii.Error, ValueError) as exc:
            raise TransportValidationError(
                "source transport fragment payload is not canonical base64"
            ) from exc

    def _start_pending_fragment(
        self,
        identity: tuple[str, int, int, int, int],
        *,
        locator: str,
        record_index: int,
        byte_start: int,
        byte_end: int,
        fragment_count: int,
    ) -> None:
        inventory_row = self.inventory_by_coordinate.get((locator, record_index))
        if (
            inventory_row is None
            or inventory_row["accounting_class"]
            != catalog.AccountingClass.CONSUMED_CANDIDATE.value
            or inventory_row["byte_start"] != byte_start
            or inventory_row["byte_end"] != byte_end
        ):
            raise TransportValidationError(
                "source transport fragment lacks a consumed inventory item"
            )
        self.pending = {
            "byte_end": byte_end,
            "byte_start": byte_start,
            "fragment_count": fragment_count,
            "fragments": [],
            "identity": identity,
            "record_index": record_index,
            "source_locator": locator,
        }

    def _accept_resume_probe_fragment(self, frame: Mapping[str, object]) -> None:
        self._finish_pending()
        _exact_keys(
            frame,
            {
                "byte_end",
                "byte_start",
                "fragment_count",
                "fragment_index",
                "frame",
                "payload_b64",
                "schema",
                "source_locator",
            },
            "source transport resume probe fragment",
        )
        if frame["schema"] != SOURCE_TRANSPORT_STREAM_SCHEMA:
            raise TransportValidationError(
                "source transport resume probe schema changed"
            )
        if self.resume_probe_payload is not None:
            raise TransportValidationError(
                "source transport contains more than one resume probe"
            )
        locator = frame["source_locator"]
        if not isinstance(locator, str) or _LOCATOR_RE.fullmatch(locator) is None:
            raise TransportValidationError(
                "source transport resume probe locator is invalid"
            )
        byte_start = _non_negative_int(
            frame["byte_start"],
            "source transport resume probe byte_start",
        )
        byte_end = _non_negative_int(
            frame["byte_end"],
            "source transport resume probe byte_end",
        )
        fragment_index = _non_negative_int(
            frame["fragment_index"],
            "source transport resume probe fragment_index",
        )
        fragment_count = _positive_int(
            frame["fragment_count"],
            "source transport resume probe fragment_count",
        )
        if (
            byte_end <= byte_start
            or byte_end - byte_start > SOURCE_TRANSPORT_RESUME_PROBE_BYTES
            or fragment_index >= fragment_count
        ):
            raise TransportValidationError(
                "source transport resume probe coordinates are invalid"
            )
        identity = (locator, byte_start, byte_end, fragment_count)
        if self.resume_probe_pending is None:
            if fragment_index != 0:
                raise TransportValidationError(
                    "source transport resume probe fragments are missing or reordered"
                )
            self.resume_probe_pending = {
                "byte_end": byte_end,
                "byte_start": byte_start,
                "fragment_count": fragment_count,
                "fragments": [],
                "identity": identity,
                "source_locator": locator,
            }
        elif self.resume_probe_pending["identity"] != identity:
            raise TransportValidationError(
                "source transport resume probe identity changed"
            )
        fragments = self.resume_probe_pending["fragments"]
        assert isinstance(fragments, list)
        if fragment_index != len(fragments):
            raise TransportValidationError(
                "source transport resume probe fragments are missing or reordered"
            )
        payload_b64 = frame["payload_b64"]
        if not isinstance(payload_b64, str):
            raise TransportValidationError(
                "source transport resume probe payload must be base64 text"
            )
        try:
            fragments.append(base64.b64decode(payload_b64, validate=True))
        except (binascii.Error, ValueError) as exc:
            raise TransportValidationError(
                "source transport resume probe payload is not canonical base64"
            ) from exc

    def _finish_resume_probe(self) -> None:
        if self.resume_probe_pending is None:
            return
        fragments = self.resume_probe_pending["fragments"]
        assert isinstance(fragments, list)
        if len(fragments) != int(self.resume_probe_pending["fragment_count"]):
            raise TransportValidationError(
                "source transport resume probe fragments are incomplete"
            )
        payload = b"".join(fragments)
        byte_start = int(self.resume_probe_pending["byte_start"])
        byte_end = int(self.resume_probe_pending["byte_end"])
        if len(payload) != byte_end - byte_start:
            raise TransportValidationError(
                "source transport resume probe payload has the wrong length"
            )
        self.resume_probe_payload = payload
        self.resume_probe_locator = str(self.resume_probe_pending["source_locator"])
        self.resume_probe_range = (byte_start, byte_end)
        self.resume_probe_pending = None

    def accept(self, raw_line: bytes | str) -> None:
        encoded = raw_line.encode("utf-8") if isinstance(raw_line, str) else raw_line
        self.wire_bytes += len(encoded)
        if self.wire_bytes > self.wire_limit:
            raise TransportValidationError(
                "source transport exceeded its bounded wire envelope"
            )
        stripped = encoded.rstrip(b"\r\n")
        if not stripped or len(stripped) > self.lease.frame_byte_limit:
            raise TransportValidationError(
                "source transport contains an empty or oversized frame"
            )
        frame = _stream_frame(stripped)
        if not self.header_seen:
            if dict(frame) != self.expected_header:
                raise TransportValidationError(
                    "source transport header is not bound to its authenticated lease"
                )
            self.header_seen = True
            return
        if self.terminal is not None:
            raise TransportValidationError(
                "source transport contains frames after its terminal proof"
            )
        frame_kind = frame.get("frame")
        if frame_kind == "inventory":
            if (
                self.resume_probe_pending is not None
                or self.resume_probe_payload is not None
            ):
                raise TransportValidationError(
                    "source transport inventory follows its resume probe"
                )
            self._accept_inventory(frame)
            return
        if frame_kind == "record_fragment":
            if (
                self.resume_probe_pending is not None
                or self.resume_probe_payload is not None
            ):
                raise TransportValidationError(
                    "source transport record follows its resume probe"
                )
            self._accept_record_fragment(frame)
            return
        if frame_kind == "resume_probe_fragment":
            self._accept_resume_probe_fragment(frame)
            return
        if frame_kind != "terminal":
            raise TransportValidationError(
                "source transport contains an unknown frame kind"
            )
        self._finish_pending()
        self._finish_resume_probe()
        _exact_keys(
            frame,
            {
                "complete",
                "emitted_byte_count",
                "emitted_record_count",
                "frame",
                "inventory_accounting",
                "inventory_commitment",
                "inventory_count",
                "oversized_byte_count",
                "oversized_record_count",
                "reason",
                "resume_position",
                "scan_byte_count",
                "schema",
                "status",
            },
            "source transport terminal",
        )
        self.terminal = frame

    def finish(self) -> SourceTransportCapture:
        self._finish_pending()
        self._finish_resume_probe()
        if not self.header_seen or self.terminal is None:
            raise TransportValidationError(
                "source transport ended without its header and terminal proof"
            )
        evidence = self._terminal_evidence(self.terminal)
        explicit_gap_count = self._validate_accounting(evidence, self.terminal)
        self._validate_terminal_semantics(evidence, explicit_gap_count, self.terminal)
        validated_resume_position = self._validated_outgoing_resume_position(evidence)
        probe_proof: dict[str, JsonValue] | None = None
        if self.resume_probe_payload is not None:
            assert self.resume_probe_locator is not None
            assert self.resume_probe_range is not None
            probe_proof = {
                "resume_probe": _source_transport_resume_probe(
                    self.resume_probe_payload,
                    byte_offset=self.resume_probe_range[1],
                ),
                "source_locator": self.resume_probe_locator,
            }
        proof = _canonical_commitment(
            {
                "header": self.expected_header,
                "lease_binding": self.lease.binding,
                "inventory": self.inventory,
                "records": self.proof_rows,
                "resume_probe": probe_proof,
                "schema": "source_transport_terminal_proof_v2",
                "terminal": dict(self.terminal),
            }
        )
        return SourceTransportCapture(
            records=tuple(self.records),
            terminal_status=evidence.status,
            terminal_reason=evidence.reason,
            inventory_commitment=evidence.inventory_commitment,
            inventory_count=evidence.inventory_count,
            scan_byte_count=evidence.scan_byte_count,
            oversized_record_count=evidence.oversized_record_count,
            oversized_byte_count=evidence.oversized_byte_count,
            terminal_proof_commitment=proof,
            resume_position=validated_resume_position,
            inventory=tuple(self.inventory),
        )

    def _validated_outgoing_resume_position(
        self,
        evidence: _TerminalEvidence,
    ) -> dict[str, JsonValue] | None:
        if evidence.resume_position is None:
            if self.resume_probe_payload is not None:
                raise TransportValidationError(
                    "source transport emitted an unbound resume probe"
                )
            return None
        if (
            self.resume_probe_payload is None
            or self.resume_probe_locator is None
            or self.resume_probe_range is None
            or not self.inventory
        ):
            raise TransportValidationError(
                "source transport continuation lacks independently captured probe evidence"
            )
        last = self.inventory[-1]
        byte_offset = int(last["byte_end"])
        expected_range = (
            max(0, byte_offset - SOURCE_TRANSPORT_RESUME_PROBE_BYTES),
            byte_offset,
        )
        if (
            self.resume_probe_locator != last["source_locator"]
            or self.resume_probe_range != expected_range
        ):
            raise TransportValidationError(
                "source transport continuation probe does not match accepted inventory"
            )
        expected = _derive_source_resume_position(
            prior_position=self.lease.resume_position,
            inventory=self.inventory,
            resume_probe=_source_transport_resume_probe(
                self.resume_probe_payload,
                byte_offset=byte_offset,
            ),
        )
        if expected != evidence.resume_position:
            raise TransportValidationError(
                "source transport terminal resume position was not independently derived"
            )
        return expected

    @staticmethod
    def _terminal_evidence(terminal: Mapping[str, object]) -> _TerminalEvidence:
        if terminal["schema"] != SOURCE_TRANSPORT_STREAM_SCHEMA:
            raise TransportValidationError("source transport terminal schema changed")
        try:
            terminal_status = SourceCellStatus(terminal["status"])
        except (TypeError, ValueError) as exc:
            raise TransportValidationError(
                "source transport terminal status is invalid"
            ) from exc
        terminal_reason = terminal["reason"]
        if (
            not isinstance(terminal_reason, str)
            or _REASON_RE.fullmatch(terminal_reason) is None
        ):
            raise TransportValidationError(
                "source transport terminal reason is invalid"
            )
        raw_resume = terminal["resume_position"]
        if raw_resume is not None and not isinstance(raw_resume, Mapping):
            raise TransportValidationError(
                "source transport terminal resume position is invalid"
            )
        return _TerminalEvidence(
            status=terminal_status,
            reason=terminal_reason,
            resume_position=_normalize_source_resume_position(raw_resume),
            inventory_commitment=_sha256(
                terminal["inventory_commitment"],
                "source transport inventory_commitment",
            ),
            inventory_count=_non_negative_int(
                terminal["inventory_count"], "source transport inventory_count"
            ),
            scan_byte_count=_non_negative_int(
                terminal["scan_byte_count"], "source transport scan_byte_count"
            ),
            oversized_record_count=_non_negative_int(
                terminal["oversized_record_count"],
                "source transport oversized_record_count",
            ),
            oversized_byte_count=_non_negative_int(
                terminal["oversized_byte_count"],
                "source transport oversized_byte_count",
            ),
            emitted_record_count=_non_negative_int(
                terminal["emitted_record_count"],
                "source transport emitted_record_count",
            ),
            emitted_byte_count=_non_negative_int(
                terminal["emitted_byte_count"],
                "source transport emitted_byte_count",
            ),
        )

    def _validate_accounting(
        self,
        evidence: _TerminalEvidence,
        terminal: Mapping[str, object],
    ) -> int:
        expected = {
            value.value: sum(
                item["accounting_class"] == value.value for item in self.inventory
            )
            for value in catalog.AccountingClass
        }
        raw_accounting = terminal["inventory_accounting"]
        if not isinstance(raw_accounting, Mapping) or set(raw_accounting) != set(
            expected
        ):
            raise TransportValidationError(
                "source transport inventory accounting is malformed"
            )
        supplied = {
            key: _non_negative_int(
                raw_accounting[key],
                f"source transport inventory accounting {key}",
            )
            for key in expected
        }
        consumed_count = expected[catalog.AccountingClass.CONSUMED_CANDIDATE.value]
        scanned_inventory_bytes = sum(
            int(item["byte_end"]) - int(item["byte_start"]) for item in self.inventory
        )
        if (
            evidence.emitted_record_count != len(self.records)
            or evidence.emitted_byte_count != self.payload_bytes
            or evidence.emitted_record_count != consumed_count
            or evidence.inventory_count != len(self.inventory)
            or supplied != expected
            or evidence.inventory_commitment
            != _source_transport_inventory_commitment(self.inventory)
            or len(self.records) > self.lease.record_limit
            or evidence.inventory_count > self.lease.record_limit + 1
            or evidence.scan_byte_count > self.lease.source_byte_limit
            or evidence.scan_byte_count != scanned_inventory_bytes
            or evidence.oversized_record_count > 1
            or evidence.oversized_byte_count > evidence.scan_byte_count
        ):
            raise TransportValidationError(
                "source transport terminal accounting does not match captured records"
            )
        return expected[catalog.AccountingClass.EXPLICIT_GAP.value]

    def _validate_terminal_semantics(
        self,
        evidence: _TerminalEvidence,
        explicit_gap_count: int,
        terminal: Mapping[str, object],
    ) -> None:
        complete = evidence.status in {
            SourceCellStatus.COMPLETE,
            SourceCellStatus.NO_ACTIVITY,
            SourceCellStatus.VERIFIED_ABSENT,
        }
        if terminal["complete"] is not complete:
            raise TransportValidationError(
                "source transport terminal completeness is inconsistent"
            )
        continuation_reason = evidence.reason in {
            "source_byte_limit_reached",
            "source_record_limit_reached",
        }
        if (evidence.resume_position is None) != (not continuation_reason):
            raise TransportValidationError(
                "source transport terminal continuation binding is inconsistent"
            )
        if (
            evidence.resume_position is not None
            and evidence.status is not SourceCellStatus.GAP
        ):
            raise TransportValidationError(
                "source transport continuation must remain incomplete"
            )
        if evidence.status is SourceCellStatus.COMPLETE and not self.records:
            raise TransportValidationError(
                "complete source transport must contain records"
            )
        if (
            evidence.status
            in {
                SourceCellStatus.NO_ACTIVITY,
                SourceCellStatus.VERIFIED_ABSENT,
            }
            and self.records
        ):
            raise TransportValidationError(
                "empty terminal source transport cannot contain records"
            )
        if explicit_gap_count and evidence.status is not SourceCellStatus.GAP:
            raise TransportValidationError(
                "source transport explicit inventory gap requires a terminal gap"
            )
        if evidence.oversized_record_count:
            if (
                evidence.status is not SourceCellStatus.GAP
                or evidence.reason != "source_record_oversized"
                or evidence.oversized_byte_count <= SOURCE_TRANSPORT_MAX_RECORD_BYTES
            ):
                raise TransportValidationError(
                    "oversized source accounting requires its explicit terminal gap"
                )
        elif evidence.oversized_byte_count != 0:
            raise TransportValidationError(
                "source transport oversized byte accounting is inconsistent"
            )


def capture_source_transport(
    lines: Iterable[bytes | str],
    *,
    lease: TransportLease,
) -> SourceTransportCapture:
    """Validate and capture one exact, bounded source-transport process stream."""

    validator = _SourceTransportCaptureValidator(lease)
    for line in lines:
        validator.accept(line)
    return validator.finish()


def _source_transport_validation_lease(args: argparse.Namespace) -> TransportLease:
    zero = "0" * 64
    return TransportLease(
        lease_ref=args.lease_ref,
        run_ref=f"run_ref_v2:{zero}",
        job_ref=f"job_ref_v2:{zero}",
        host=args.host,
        host_ref=f"host_ref_v2:{zero}",
        source_kind=args.source_kind,
        window_start=args.window_start,
        window_end=args.window_end,
        process_nonce=args.process_nonce,
        command_argv=("remote-host-context",),
        transport_program_commitment=f"sha256:{zero}",
        source_byte_limit=args.max_source_bytes,
        record_limit=args.max_records,
        frame_byte_limit=args.max_frame_bytes,
        session_target=None,
        session_selector_commitment=args.session_selector_commitment,
        source_cursor=args.source_cursor,
        cursor_time=args.cursor_time,
        resume_position=args.resume_position,
        authentication_tag=TRANSPORT_LEASE_AUTH_PREFIX + zero,
    )


def _validate_source_transport_relay(
    args: argparse.Namespace,
    output: Any,
) -> None:
    output.seek(0)
    capture_source_transport(
        iter(output.readline, b""),
        lease=_source_transport_validation_lease(args),
    )
    output.seek(0)
