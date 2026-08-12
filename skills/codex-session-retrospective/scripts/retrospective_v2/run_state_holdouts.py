"""Authenticated holdout and shadow-successor authority."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hmac
import re
from typing import Any

from . import controlled_gaps
from .contracts import ControlledGapReason, RunMode, SourceCellStatus
from .identity import IdentityKey
from .run_state_contracts import RunStateAuthorityError, require


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SHADOW_SUCCESSOR_FIELDS = {
    "authentication_tag",
    "backfill_of",
    "cleanup_receipt_ref",
    "controlled_gap_receipt",
    "coverage_receipt_ref",
    "export_bundle_digest",
    "history_repo",
    "history_target_ref",
    "host",
    "partial_checkpoint_revision",
    "provenance",
    "schema",
    "window",
}
_SHADOW_CLEANUP_PREFIXES = (
    "raw_cleanup_receipt_v2:",
    "raw_cleanup_receipt_v3:",
    "raw_cleanup_receipt_v4:",
    "raw_cleanup_receipt_v5:",
)


def _verified_gap(
    identity: IdentityKey,
    value: object,
    *,
    invalid: str,
    source_receipts: list[Mapping[str, Any]],
) -> controlled_gaps.ControlledGapReceipt:
    try:
        return controlled_gaps.verify_controlled_gap_receipt(
            identity,
            value,
            source_receipts=source_receipts,
        )
    except (TypeError, ValueError, controlled_gaps.ControlledGapError) as error:
        raise RunStateAuthorityError(invalid) from error


def validate_formal_controlled_holdouts(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    source_cells: Mapping[str, Mapping[str, Any]],
) -> None:
    """Require every formal source gap to have one exact Daily holdout receipt."""

    invalid = "formal source gaps lack exact controlled holdout authority"
    raw_holdouts = state.get("controlled_holdouts")
    require(isinstance(raw_holdouts, Mapping), invalid)
    gap_hosts = {
        host
        for host, cells in source_cells.items()
        if any(
            cell.get("status") == SourceCellStatus.GAP.value for cell in cells.values()
        )
    }
    if not gap_hosts:
        require(not raw_holdouts, invalid)
        return

    lineage = state.get("lineage")
    partial_policy = state.get("partial_policy")
    coverage = state.get("coverage")
    shadow = state.get("shadow")
    require(isinstance(lineage, Mapping), invalid)
    require(isinstance(partial_policy, Mapping), invalid)
    require(isinstance(coverage, Mapping), invalid)
    require(isinstance(shadow, bool), invalid)
    require(
        (
            state.get("mode"),
            lineage.get("backfill_of"),
            partial_policy.get("allow_partial"),
            partial_policy.get("decision"),
            partial_policy.get("scope"),
            coverage.get("status"),
        )
        == (
            RunMode.DAILY.value,
            None,
            True,
            "partial",
            "per_host",
            "partial",
        ),
        invalid,
    )
    require(set(raw_holdouts) == gap_hosts, invalid)
    require(gap_hosts != set(source_cells), invalid)

    expected_reason = (
        ControlledGapReason.SHADOW_MISSING_HOST_HOLDOUT
        if shadow
        else ControlledGapReason.MISSING_HOST_HOLDOUT
    )
    host_refs = state.get("host_refs")
    window = state.get("window")
    require(isinstance(host_refs, Mapping), invalid)
    require(isinstance(window, Mapping), invalid)
    for host in gap_hosts:
        cells = source_cells[host]
        require(
            all(
                cell.get("status") == SourceCellStatus.GAP.value
                for cell in cells.values()
            ),
            invalid,
        )
        raw_source_receipts = [cell.get("transport_receipt") for cell in cells.values()]
        require(
            all(isinstance(value, Mapping) for value in raw_source_receipts),
            invalid,
        )
        receipt = _verified_gap(
            identity,
            raw_holdouts[host],
            invalid=invalid,
            source_receipts=raw_source_receipts,
        )
        raw_source_receipt_refs = [
            cell.get("transport_receipt_ref") for cell in cells.values()
        ]
        require(
            all(isinstance(value, str) for value in raw_source_receipt_refs),
            invalid,
        )
        source_receipt_refs = tuple(sorted(raw_source_receipt_refs))
        reasons: set[object] = set()
        for cell in cells.values():
            manifest = cell.get("manifest")
            require(isinstance(manifest, Mapping), invalid)
            enumeration_gap = manifest.get("enumeration_gap")
            require(isinstance(enumeration_gap, Mapping), invalid)
            reasons.add(enumeration_gap.get("reason"))
        require(
            (
                receipt.run_ref,
                receipt.host,
                receipt.host_ref,
                receipt.window_start,
                receipt.window_end,
                receipt.shadow,
                receipt.reason,
                receipt.source_receipt_refs,
                reasons,
            )
            == (
                state.get("run_ref"),
                host,
                host_refs.get(host),
                window.get("start"),
                window.get("end"),
                shadow,
                expected_reason,
                source_receipt_refs,
                {expected_reason.value},
            ),
            invalid,
        )


def verify_shadow_daily_successor(
    identity: IdentityKey,
    value: object,
    *,
    backfill_of: str,
    controlled_gap_receipt: Mapping[str, Any],
    history_repo: str,
    history_target_ref: str,
    host: str,
    provenance: Mapping[str, Any],
    window: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a completed shadow partial's exact successor authorization."""

    invalid = "shadow successor authorization is invalid"
    require(isinstance(value, Mapping), invalid)
    require(set(value) == _SHADOW_SUCCESSOR_FIELDS, invalid)
    successor = deepcopy(dict(value))
    body = {key: successor[key] for key in successor if key != "authentication_tag"}
    try:
        expected_tag = "shadow_daily_successor_auth_v2:" + identity.derive_digest(
            "shadow-daily-successor-auth-v2", body
        )
    except (TypeError, ValueError) as error:
        raise RunStateAuthorityError(invalid) from error
    expected_bindings = {
        "backfill_of": backfill_of,
        "controlled_gap_receipt": dict(controlled_gap_receipt),
        "history_repo": history_repo,
        "history_target_ref": history_target_ref,
        "host": host,
        "provenance": dict(provenance),
        "window": dict(window),
    }
    revision = successor.get("partial_checkpoint_revision")
    digest = successor.get("export_bundle_digest")
    coverage_ref = successor.get("coverage_receipt_ref")
    cleanup_ref = successor.get("cleanup_receipt_ref")
    authentication_tag = successor.get("authentication_tag")
    require(
        successor.get("schema") == "shadow_daily_successor_v2"
        and all(successor.get(key) == item for key, item in expected_bindings.items())
        and isinstance(revision, int)
        and not isinstance(revision, bool)
        and revision >= 0
        and isinstance(digest, str)
        and _SHA256_RE.fullmatch(digest) is not None
        and isinstance(coverage_ref, str)
        and coverage_ref.startswith("shadow_coverage_receipt_v2:")
        and isinstance(cleanup_ref, str)
        and cleanup_ref.startswith(_SHADOW_CLEANUP_PREFIXES)
        and isinstance(authentication_tag, str)
        and hmac.compare_digest(authentication_tag, expected_tag),
        invalid,
    )
    return successor
