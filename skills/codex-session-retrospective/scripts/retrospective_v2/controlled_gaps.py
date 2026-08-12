from __future__ import annotations

from dataclasses import dataclass, replace
import datetime as dt
import hmac
from operator import attrgetter
import re
from typing import Mapping, Sequence

from .catalog import CatalogValidationError, canonical_utc_timestamp
from .contracts import (
    ControlledGapReason,
    JsonValue,
    RefType,
    SourceCellStatus,
    SourceKind,
    canonical_sha256,
    parse_typed_ref,
)
from .identity import IdentityKey
from .transport_contracts import (
    TRANSPORT_RECEIPT_REF_PREFIX,
    TransportReceipt,
    TransportValidationError,
)


CONTROLLED_GAP_RECEIPT_SCHEMA = "controlled_gap_receipt_v2"
CONTROLLED_GAP_RECEIPT_REF_PREFIX = "controlled_gap_receipt_v2:"
CONTROLLED_GAP_AUTH_PREFIX = "controlled_gap_auth_v2:"
BACKFILL_LINEAGE_RECEIPT_SCHEMA = "backfill_lineage_receipt_v2"
BACKFILL_LINEAGE_RECEIPT_REF_PREFIX = "backfill_lineage_receipt_v2:"
BACKFILL_LINEAGE_AUTH_PREFIX = "backfill_lineage_auth_v2:"
CONTROLLED_GAP_SOURCE_KINDS = (
    SourceKind.ACTIVE_ROLLOUT,
    SourceKind.ARCHIVED_ROLLOUT,
    SourceKind.HISTORY,
    SourceKind.SESSION_INDEX,
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,511}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID_RE = re.compile(r"identity_key_v2:[0-9a-f]{64}\Z")
_RECEIPT_REF_RE = re.compile(
    re.escape(TRANSPORT_RECEIPT_REF_PREFIX) + r"[0-9a-f]{64}\Z"
)
_CONTROLLED_GAP_REF_RE = re.compile(
    re.escape(CONTROLLED_GAP_RECEIPT_REF_PREFIX) + r"[0-9a-f]{64}\Z"
)
_CONTROLLED_GAP_AUTH_RE = re.compile(
    re.escape(CONTROLLED_GAP_AUTH_PREFIX) + r"[0-9a-f]{64}\Z"
)
_BACKFILL_LINEAGE_REF_RE = re.compile(
    re.escape(BACKFILL_LINEAGE_RECEIPT_REF_PREFIX) + r"[0-9a-f]{64}\Z"
)
_BACKFILL_LINEAGE_AUTH_RE = re.compile(
    re.escape(BACKFILL_LINEAGE_AUTH_PREFIX) + r"[0-9a-f]{64}\Z"
)
_SHA256_REF_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ControlledGapError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ControlledGapReceipt:
    receipt_ref: str
    run_ref: str
    identity_key_id: str
    host: str
    host_ref: str
    source_kinds: tuple[SourceKind, ...]
    window_start: str
    window_end: str
    reason: ControlledGapReason
    shadow: bool
    source_receipt_refs: tuple[str, ...]
    backfill_required: bool
    authentication_tag: str
    schema: str = CONTROLLED_GAP_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CONTROLLED_GAP_RECEIPT_SCHEMA:
            raise ControlledGapError("controlled gap receipt schema is invalid")
        try:
            parse_typed_ref(self.run_ref, expected=RefType.RUN)
            parse_typed_ref(self.host_ref, expected=RefType.HOST)
        except (TypeError, ValueError) as exc:
            raise ControlledGapError(
                "controlled gap receipt has an invalid typed reference"
            ) from exc
        if _TOKEN_RE.fullmatch(self.host) is None:
            raise ControlledGapError("controlled gap host is invalid")
        if (
            not isinstance(self.identity_key_id, str)
            or _KEY_ID_RE.fullmatch(self.identity_key_id) is None
        ):
            raise ControlledGapError("controlled gap identity key is invalid")
        try:
            reason = ControlledGapReason(self.reason)
        except (TypeError, ValueError) as exc:
            raise ControlledGapError("controlled gap reason is not closed") from exc
        object.__setattr__(self, "reason", reason)
        if not isinstance(self.shadow, bool):
            raise ControlledGapError("controlled gap shadow mode must be a boolean")
        expected_reason = (
            ControlledGapReason.SHADOW_MISSING_HOST_HOLDOUT
            if self.shadow
            else ControlledGapReason.MISSING_HOST_HOLDOUT
        )
        if reason is not expected_reason:
            raise ControlledGapError("controlled gap reason does not match shadow mode")
        kinds = tuple(SourceKind(value) for value in self.source_kinds)
        if kinds != CONTROLLED_GAP_SOURCE_KINDS:
            raise ControlledGapError(
                "controlled gap must cover every required source kind"
            )
        object.__setattr__(self, "source_kinds", kinds)
        receipts = tuple(self.source_receipt_refs)
        if (
            len(receipts) != len(kinds)
            or len(receipts) != len(set(receipts))
            or receipts != tuple(sorted(receipts))
            or any(_RECEIPT_REF_RE.fullmatch(value) is None for value in receipts)
        ):
            raise ControlledGapError(
                "controlled gap source receipt coverage is invalid"
            )
        object.__setattr__(self, "source_receipt_refs", receipts)
        try:
            window_start = canonical_utc_timestamp(
                self.window_start,
                "controlled gap window start",
            )
            window_end = canonical_utc_timestamp(
                self.window_end,
                "controlled gap window end",
            )
        except CatalogValidationError as exc:
            raise ControlledGapError("controlled gap window is invalid") from exc
        start_value = dt.datetime.fromisoformat(
            window_start.removesuffix("Z") + "+00:00"
        )
        end_value = dt.datetime.fromisoformat(window_end.removesuffix("Z") + "+00:00")
        if start_value >= end_value:
            raise ControlledGapError("controlled gap window is invalid")
        object.__setattr__(self, "window_start", window_start)
        object.__setattr__(self, "window_end", window_end)
        if self.backfill_required is not True:
            raise ControlledGapError("controlled gap must require a later backfill")
        if (
            not isinstance(self.receipt_ref, str)
            or _CONTROLLED_GAP_REF_RE.fullmatch(self.receipt_ref) is None
            or not isinstance(self.authentication_tag, str)
            or _CONTROLLED_GAP_AUTH_RE.fullmatch(self.authentication_tag) is None
        ):
            raise ControlledGapError("controlled gap authentication fields are invalid")

    def unsigned_dict(self) -> dict[str, JsonValue]:
        return {
            "backfill_required": self.backfill_required,
            "host": self.host,
            "host_ref": self.host_ref,
            "identity_key_id": self.identity_key_id,
            "reason": self.reason.value,
            "run_ref": self.run_ref,
            "schema": self.schema,
            "shadow": self.shadow,
            "source_kinds": [kind.value for kind in self.source_kinds],
            "source_receipt_refs": list(self.source_receipt_refs),
            "window": {"end": self.window_end, "start": self.window_start},
        }

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            **self.unsigned_dict(),
            "authentication_tag": self.authentication_tag,
            "receipt_ref": self.receipt_ref,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ControlledGapReceipt:
        expected = {
            "authentication_tag",
            "backfill_required",
            "host",
            "host_ref",
            "identity_key_id",
            "reason",
            "receipt_ref",
            "run_ref",
            "schema",
            "shadow",
            "source_kinds",
            "source_receipt_refs",
            "window",
        }
        if set(value) != expected:
            raise ControlledGapError(
                "controlled gap receipt violates its closed field schema"
            )
        window = value["window"]
        source_kinds = value["source_kinds"]
        source_receipts = value["source_receipt_refs"]
        if (
            not isinstance(window, Mapping)
            or set(window) != {"end", "start"}
            or not isinstance(source_kinds, Sequence)
            or isinstance(source_kinds, (str, bytes))
            or not isinstance(source_receipts, Sequence)
            or isinstance(source_receipts, (str, bytes))
        ):
            raise ControlledGapError("controlled gap receipt fields are invalid")
        return cls(
            schema=value["schema"],  # type: ignore[arg-type]
            receipt_ref=value["receipt_ref"],  # type: ignore[arg-type]
            run_ref=value["run_ref"],  # type: ignore[arg-type]
            identity_key_id=value["identity_key_id"],  # type: ignore[arg-type]
            host=value["host"],  # type: ignore[arg-type]
            host_ref=value["host_ref"],  # type: ignore[arg-type]
            source_kinds=tuple(source_kinds),  # type: ignore[arg-type]
            window_start=window["start"],  # type: ignore[arg-type]
            window_end=window["end"],  # type: ignore[arg-type]
            reason=value["reason"],  # type: ignore[arg-type]
            shadow=value["shadow"],  # type: ignore[arg-type]
            source_receipt_refs=tuple(source_receipts),  # type: ignore[arg-type]
            backfill_required=value["backfill_required"],  # type: ignore[arg-type]
            authentication_tag=value["authentication_tag"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class BackfillLineageReceipt:
    receipt_ref: str
    identity_key_id: str
    controlled_gap_receipt_ref: str
    partial_run_ref: str
    host: str
    host_ref: str
    window_start: str
    window_end: str
    source_receipt_refs: tuple[str, ...]
    expected_backlog_ref: str | None
    proposed_backlog_ref: str | None
    expected_episode_head_set_ref: str
    proposed_episode_head_set_ref: str
    prior_episode_heads_commitment: str
    proposed_episode_heads_commitment: str
    authentication_tag: str
    schema: str = BACKFILL_LINEAGE_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != BACKFILL_LINEAGE_RECEIPT_SCHEMA:
            raise ControlledGapError("backfill lineage receipt schema is invalid")
        try:
            parse_typed_ref(self.partial_run_ref, expected=RefType.RUN)
            parse_typed_ref(self.host_ref, expected=RefType.HOST)
            if self.expected_backlog_ref is not None:
                parse_typed_ref(
                    self.expected_backlog_ref,
                    expected=RefType.RUN_INPUT,
                )
            parse_typed_ref(
                self.expected_episode_head_set_ref,
                expected=RefType.EPISODE_HEAD_SET,
            )
            parse_typed_ref(
                self.proposed_episode_head_set_ref,
                expected=RefType.EPISODE_HEAD_SET,
            )
        except (TypeError, ValueError) as exc:
            raise ControlledGapError(
                "backfill lineage receipt has an invalid typed reference"
            ) from exc
        if self.proposed_backlog_ref is not None:
            raise ControlledGapError("backfill lineage must clear the matched backlog")
        if not isinstance(self.host, str) or _TOKEN_RE.fullmatch(self.host) is None:
            raise ControlledGapError("backfill lineage host is invalid")
        if (
            not isinstance(self.identity_key_id, str)
            or _KEY_ID_RE.fullmatch(self.identity_key_id) is None
        ):
            raise ControlledGapError("backfill lineage identity is invalid")
        if (
            not isinstance(self.controlled_gap_receipt_ref, str)
            or _CONTROLLED_GAP_REF_RE.fullmatch(self.controlled_gap_receipt_ref) is None
        ):
            raise ControlledGapError("backfill lineage controlled gap is invalid")
        receipts = tuple(self.source_receipt_refs)
        if (
            len(receipts) != len(set(receipts))
            or len(receipts) != len(CONTROLLED_GAP_SOURCE_KINDS)
            or receipts != tuple(sorted(receipts))
            or any(_RECEIPT_REF_RE.fullmatch(item) is None for item in receipts)
        ):
            raise ControlledGapError("backfill lineage source receipts are invalid")
        object.__setattr__(self, "source_receipt_refs", receipts)
        try:
            start = canonical_utc_timestamp(self.window_start, "backfill window start")
            end = canonical_utc_timestamp(self.window_end, "backfill window end")
        except CatalogValidationError as exc:
            raise ControlledGapError("backfill lineage window is invalid") from exc
        if dt.datetime.fromisoformat(
            start[:-1] + "+00:00"
        ) >= dt.datetime.fromisoformat(end[:-1] + "+00:00"):
            raise ControlledGapError("backfill lineage window is invalid")
        object.__setattr__(self, "window_start", start)
        object.__setattr__(self, "window_end", end)
        for label, value in (
            ("prior heads commitment", self.prior_episode_heads_commitment),
            ("proposed heads commitment", self.proposed_episode_heads_commitment),
        ):
            if not isinstance(value, str) or _SHA256_REF_RE.fullmatch(value) is None:
                raise ControlledGapError(f"backfill lineage {label} is invalid")
        if (
            not isinstance(self.receipt_ref, str)
            or _BACKFILL_LINEAGE_REF_RE.fullmatch(self.receipt_ref) is None
            or not isinstance(self.authentication_tag, str)
            or _BACKFILL_LINEAGE_AUTH_RE.fullmatch(self.authentication_tag) is None
        ):
            raise ControlledGapError("backfill lineage authentication is invalid")

    def unsigned_dict(self) -> dict[str, JsonValue]:
        return {
            "controlled_gap_receipt_ref": self.controlled_gap_receipt_ref,
            "expected_episode_head_set_ref": self.expected_episode_head_set_ref,
            "expected_backlog_ref": self.expected_backlog_ref,
            "host": self.host,
            "host_ref": self.host_ref,
            "identity_key_id": self.identity_key_id,
            "partial_run_ref": self.partial_run_ref,
            "prior_episode_heads_commitment": self.prior_episode_heads_commitment,
            "proposed_episode_head_set_ref": self.proposed_episode_head_set_ref,
            "proposed_backlog_ref": self.proposed_backlog_ref,
            "proposed_episode_heads_commitment": self.proposed_episode_heads_commitment,
            "schema": self.schema,
            "source_receipt_refs": list(self.source_receipt_refs),
            "window": {"end": self.window_end, "start": self.window_start},
        }

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            **self.unsigned_dict(),
            "authentication_tag": self.authentication_tag,
            "receipt_ref": self.receipt_ref,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> BackfillLineageReceipt:
        expected = {
            "authentication_tag",
            "controlled_gap_receipt_ref",
            "expected_episode_head_set_ref",
            "expected_backlog_ref",
            "host",
            "host_ref",
            "identity_key_id",
            "partial_run_ref",
            "prior_episode_heads_commitment",
            "proposed_episode_head_set_ref",
            "proposed_backlog_ref",
            "proposed_episode_heads_commitment",
            "receipt_ref",
            "schema",
            "source_receipt_refs",
            "window",
        }
        if set(value) != expected:
            raise ControlledGapError(
                "backfill lineage receipt violates its closed field schema"
            )
        window = value["window"]
        receipts = value["source_receipt_refs"]
        if (
            not isinstance(window, Mapping)
            or set(window) != {"end", "start"}
            or not isinstance(receipts, Sequence)
            or isinstance(receipts, (str, bytes))
        ):
            raise ControlledGapError("backfill lineage receipt fields are invalid")
        return cls(
            receipt_ref=value["receipt_ref"],  # type: ignore[arg-type]
            identity_key_id=value["identity_key_id"],  # type: ignore[arg-type]
            controlled_gap_receipt_ref=value["controlled_gap_receipt_ref"],  # type: ignore[arg-type]
            partial_run_ref=value["partial_run_ref"],  # type: ignore[arg-type]
            host=value["host"],  # type: ignore[arg-type]
            host_ref=value["host_ref"],  # type: ignore[arg-type]
            window_start=window["start"],  # type: ignore[arg-type]
            window_end=window["end"],  # type: ignore[arg-type]
            source_receipt_refs=tuple(receipts),  # type: ignore[arg-type]
            expected_backlog_ref=value["expected_backlog_ref"],  # type: ignore[arg-type]
            proposed_backlog_ref=value["proposed_backlog_ref"],  # type: ignore[arg-type]
            expected_episode_head_set_ref=value["expected_episode_head_set_ref"],  # type: ignore[arg-type]
            proposed_episode_head_set_ref=value["proposed_episode_head_set_ref"],  # type: ignore[arg-type]
            prior_episode_heads_commitment=value["prior_episode_heads_commitment"],  # type: ignore[arg-type]
            proposed_episode_heads_commitment=value[
                "proposed_episode_heads_commitment"
            ],  # type: ignore[arg-type]
            authentication_tag=value["authentication_tag"],  # type: ignore[arg-type]
            schema=value["schema"],  # type: ignore[arg-type]
        )


def _receipt_ref(identity: IdentityKey, body: Mapping[str, JsonValue]) -> str:
    return CONTROLLED_GAP_RECEIPT_REF_PREFIX + identity.derive_digest(
        "controlled-gap-receipt-ref/v2",
        dict(body),
    )


def _authentication_tag(identity: IdentityKey, body: Mapping[str, JsonValue]) -> str:
    return CONTROLLED_GAP_AUTH_PREFIX + identity.derive_digest(
        "controlled-gap-receipt-auth/v2",
        dict(body),
    )


def _canonical_source_receipt_refs(
    source_kinds: Sequence[SourceKind | str],
    source_receipt_refs: Sequence[str],
) -> tuple[str, ...]:
    if len(source_kinds) != len(source_receipt_refs):
        raise ControlledGapError("controlled gap source receipt coverage is invalid")
    try:
        kinds = tuple(map(SourceKind, source_kinds))
    except ValueError as exc:
        raise ControlledGapError(
            "controlled gap must cover every required source kind"
        ) from exc
    if set(kinds) != set(CONTROLLED_GAP_SOURCE_KINDS):
        raise ControlledGapError("controlled gap must cover every required source kind")
    return tuple(sorted(source_receipt_refs))


def issue_controlled_gap_receipt(
    identity: IdentityKey,
    *,
    run_ref: str,
    host: str,
    host_ref: str,
    source_kinds: Sequence[SourceKind | str],
    window_start: str,
    window_end: str,
    reason: ControlledGapReason | str,
    shadow: bool,
    source_receipt_refs: Sequence[str],
) -> ControlledGapReceipt:
    placeholder = "0" * 64
    canonical_receipts = _canonical_source_receipt_refs(
        source_kinds,
        source_receipt_refs,
    )
    unsigned = ControlledGapReceipt(
        receipt_ref=CONTROLLED_GAP_RECEIPT_REF_PREFIX + placeholder,
        run_ref=run_ref,
        identity_key_id=identity.key_id,
        host=host,
        host_ref=host_ref,
        source_kinds=CONTROLLED_GAP_SOURCE_KINDS,
        window_start=window_start,
        window_end=window_end,
        reason=ControlledGapReason(reason),
        shadow=shadow,
        source_receipt_refs=canonical_receipts,
        backfill_required=True,
        authentication_tag=CONTROLLED_GAP_AUTH_PREFIX + placeholder,
    )
    body = unsigned.unsigned_dict()
    return replace(
        unsigned,
        receipt_ref=_receipt_ref(identity, body),
        authentication_tag=_authentication_tag(identity, body),
    )


def verify_controlled_gap_receipt(
    identity: IdentityKey,
    receipt: ControlledGapReceipt | Mapping[str, object],
    *,
    source_receipts: Sequence[TransportReceipt | Mapping[str, object]] | None = None,
) -> ControlledGapReceipt:
    restored = (
        receipt
        if isinstance(receipt, ControlledGapReceipt)
        else ControlledGapReceipt.from_dict(receipt)
    )
    if restored.identity_key_id != identity.key_id:
        raise ControlledGapError("controlled gap receipt identity does not match")
    body = restored.unsigned_dict()
    actual_authentication = (restored.receipt_ref, restored.authentication_tag)
    expected_authentication = (
        _receipt_ref(identity, body),
        _authentication_tag(identity, body),
    )
    if not all(
        map(hmac.compare_digest, actual_authentication, expected_authentication)
    ):
        raise ControlledGapError("controlled gap receipt authentication failed")
    if source_receipts is not None:
        _verify_controlled_gap_source_receipts(
            identity,
            restored,
            source_receipts,
        )
    return restored


def _verify_controlled_gap_source_receipts(
    identity: IdentityKey,
    gap: ControlledGapReceipt,
    source_receipts: Sequence[TransportReceipt | Mapping[str, object]],
) -> None:
    receipts_by_ref: dict[str, TransportReceipt] = {}
    try:
        for raw_receipt in source_receipts:
            receipt = (
                raw_receipt
                if isinstance(raw_receipt, TransportReceipt)
                else TransportReceipt.from_dict(raw_receipt)
            )
            expected_ref = TRANSPORT_RECEIPT_REF_PREFIX + identity.derive_digest(
                "source-transport-receipt/v2",
                receipt.unsigned_dict(),
            )
            if not hmac.compare_digest(receipt.receipt_ref, expected_ref):
                raise ControlledGapError(
                    "controlled gap source receipt authentication failed"
                )
            if receipt.receipt_ref in receipts_by_ref:
                raise ControlledGapError(
                    "controlled gap source receipt coverage is invalid"
                )
            receipts_by_ref[receipt.receipt_ref] = receipt
    except TransportValidationError as exc:
        raise ControlledGapError("controlled gap source receipt is invalid") from exc
    if set(receipts_by_ref) != set(gap.source_receipt_refs):
        raise ControlledGapError("controlled gap source receipt coverage is invalid")
    snapshots = tuple(map(attrgetter("source_snapshot"), receipts_by_ref.values()))
    if set(map(attrgetter("source_kind"), snapshots)) != set(gap.source_kinds):
        raise ControlledGapError(
            "controlled gap source receipt kind coverage does not match"
        )
    for snapshot in snapshots:
        observed = (
            snapshot.host_ref,
            snapshot.window_start,
            snapshot.window_end,
            snapshot.terminal_status,
            snapshot.terminal_reason,
            snapshot.complete,
        )
        expected = (
            gap.host_ref,
            gap.window_start,
            gap.window_end,
            SourceCellStatus.GAP,
            gap.reason.value,
            False,
        )
        if observed != expected:
            raise ControlledGapError(
                "controlled gap source receipt does not certify the holdout"
            )


def issue_backfill_lineage_receipt(
    identity: IdentityKey,
    *,
    controlled_gap_receipt: ControlledGapReceipt | Mapping[str, object],
    expected_episode_head_set_ref: str,
    proposed_episode_head_set_ref: str,
    prior_episode_heads: Sequence[Mapping[str, object]],
    proposed_episode_heads: Sequence[Mapping[str, object]],
    expected_backlog_ref: str | None = None,
) -> BackfillLineageReceipt:
    gap = verify_controlled_gap_receipt(identity, controlled_gap_receipt)
    placeholder = "0" * 64
    unsigned = BackfillLineageReceipt(
        receipt_ref=BACKFILL_LINEAGE_RECEIPT_REF_PREFIX + placeholder,
        identity_key_id=identity.key_id,
        controlled_gap_receipt_ref=gap.receipt_ref,
        partial_run_ref=gap.run_ref,
        host=gap.host,
        host_ref=gap.host_ref,
        window_start=gap.window_start,
        window_end=gap.window_end,
        source_receipt_refs=gap.source_receipt_refs,
        expected_backlog_ref=expected_backlog_ref,
        proposed_backlog_ref=None,
        expected_episode_head_set_ref=expected_episode_head_set_ref,
        proposed_episode_head_set_ref=proposed_episode_head_set_ref,
        prior_episode_heads_commitment="sha256:"
        + canonical_sha256(list(prior_episode_heads)),
        proposed_episode_heads_commitment="sha256:"
        + canonical_sha256(list(proposed_episode_heads)),
        authentication_tag=BACKFILL_LINEAGE_AUTH_PREFIX + placeholder,
    )
    body = unsigned.unsigned_dict()
    return replace(
        unsigned,
        receipt_ref=BACKFILL_LINEAGE_RECEIPT_REF_PREFIX
        + identity.derive_digest("backfill-lineage-receipt-ref/v2", body),
        authentication_tag=BACKFILL_LINEAGE_AUTH_PREFIX
        + identity.derive_digest("backfill-lineage-receipt-auth/v2", body),
    )


def verify_backfill_lineage_receipt(
    identity: IdentityKey,
    receipt: BackfillLineageReceipt | Mapping[str, object],
) -> BackfillLineageReceipt:
    restored = (
        receipt
        if isinstance(receipt, BackfillLineageReceipt)
        else BackfillLineageReceipt.from_dict(receipt)
    )
    if restored.identity_key_id != identity.key_id:
        raise ControlledGapError("backfill lineage identity does not match")
    body = restored.unsigned_dict()
    expected_ref = BACKFILL_LINEAGE_RECEIPT_REF_PREFIX + identity.derive_digest(
        "backfill-lineage-receipt-ref/v2", body
    )
    expected_auth = BACKFILL_LINEAGE_AUTH_PREFIX + identity.derive_digest(
        "backfill-lineage-receipt-auth/v2", body
    )
    if not hmac.compare_digest(
        restored.receipt_ref, expected_ref
    ) or not hmac.compare_digest(restored.authentication_tag, expected_auth):
        raise ControlledGapError("backfill lineage authentication failed")
    return restored
