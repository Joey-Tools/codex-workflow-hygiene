"""Authenticated controlled-gap and backfill lineage validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import controlled_gaps
from .contracts import RefType, RunMode, canonical_sha256
from .identity import IdentityKey
from .run_state_contracts import (
    RunStateAuthorityError,
    derive_ref,
    host_ref,
    require,
)
from .run_state_holdouts import verify_shadow_daily_successor


def _verify_receipt(
    verifier: Any,
    identity: IdentityKey,
    value: object,
    *,
    invalid: str,
) -> Any:
    try:
        return verifier(identity, value)
    except (TypeError, ValueError, controlled_gaps.ControlledGapError) as error:
        raise RunStateAuthorityError(invalid) from error


def verify_backfill(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    canonical_hosts: tuple[str, ...],
    require_lineage: bool,
) -> tuple[
    str | None,
    controlled_gaps.ControlledGapReceipt | None,
    controlled_gaps.BackfillLineageReceipt | None,
]:
    invalid = "run checkpoint backfill authority is invalid"
    lineage = state.get("lineage")
    require(isinstance(lineage, Mapping), invalid)
    backfill_of = lineage.get("backfill_of")
    raw_gap = lineage.get("controlled_gap_receipt")
    gap_ref = lineage.get("controlled_gap_receipt_ref")
    raw_lineage = lineage.get("backfill_lineage_receipt")
    raw_successor = lineage.get("shadow_successor")
    if backfill_of is None:
        require(
            (raw_gap, gap_ref, raw_lineage, raw_successor) == (None, None, None, None),
            invalid,
        )
        return None, None, None
    require(
        (state.get("mode"), isinstance(backfill_of, str))
        == (RunMode.DAILY.value, True),
        invalid,
    )
    gap = _verify_receipt(
        controlled_gaps.verify_controlled_gap_receipt,
        identity,
        raw_gap,
        invalid=invalid,
    )
    window = state.get("window")
    require(isinstance(window, Mapping), invalid)
    require(set(window) == {"end", "start"}, invalid)
    expected_host_refs = dict(
        map(lambda host: (host, host_ref(identity, host)), canonical_hosts)
    )
    shadow = state.get("shadow")
    require(
        (
            gap.run_ref,
            gap.host_ref,
            gap.window_start,
            gap.window_end,
            gap.shadow,
            isinstance(shadow, bool),
            gap_ref,
        )
        == (
            backfill_of,
            expected_host_refs.get(gap.host),
            window["start"],
            window["end"],
            shadow,
            True,
            gap.receipt_ref,
        ),
        invalid,
    )
    require((require_lineage, raw_lineage is None) != (True, True), invalid)
    if shadow:
        authority = state.get("authority")
        provenance = state.get("provenance")
        require(isinstance(authority, Mapping), invalid)
        require(isinstance(provenance, Mapping), invalid)
        history_repo = authority.get("history_repo")
        history_target_ref = authority.get("history_target_ref")
        require(isinstance(history_repo, str), invalid)
        require(isinstance(history_target_ref, str), invalid)
        verify_shadow_daily_successor(
            identity,
            raw_successor,
            backfill_of=backfill_of,
            controlled_gap_receipt=gap.to_dict(),
            history_repo=history_repo,
            history_target_ref=history_target_ref,
            host=gap.host,
            provenance=provenance,
            window=window,
        )
    else:
        require(raw_successor is None, invalid)
    if raw_lineage is None:
        return gap.host, gap, None
    verified = _verify_receipt(
        controlled_gaps.verify_backfill_lineage_receipt,
        identity,
        raw_lineage,
        invalid=invalid,
    )
    require(
        (
            verified.partial_run_ref,
            verified.controlled_gap_receipt_ref,
            verified.host,
            verified.host_ref,
            verified.window_start,
            verified.window_end,
            verified.source_receipt_refs,
        )
        == (
            gap.run_ref,
            gap.receipt_ref,
            gap.host,
            gap.host_ref,
            gap.window_start,
            gap.window_end,
            gap.source_receipt_refs,
        ),
        invalid,
    )
    return gap.host, gap, verified


def _ordinary_cursor(
    _identity: IdentityKey,
    _state: Mapping[str, Any],
    *,
    host_reference: str,
    history_before: Mapping[str, Any],
) -> dict[str, Any]:
    del host_reference
    require(
        history_before.get("backlog_head") is None,
        "ordinary run cannot clear a durable backlog without backfill lineage",
    )
    return dict(history_before)


def _backfill_cursor(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    host_reference: str,
    history_before: Mapping[str, Any],
) -> dict[str, Any]:
    before = dict(history_before)
    expected_backlog = derive_ref(
        identity,
        RefType.RUN_INPUT,
        state["lineage"]["backfill_of"],
        host_reference,
        "publication_backlog",
    )
    require(
        (state.get("shadow") is False, before["backlog_head"] == expected_backlog)
        != (True, False),
        "formal backfill does not match durable backlog history",
    )
    before["backlog_head"] = expected_backlog
    return before


def expected_backfill_cursor(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    host: str,
    host_reference: str,
    backfill_host: str | None,
    history_before: Mapping[str, Any],
) -> dict[str, Any]:
    builder = (_ordinary_cursor, _backfill_cursor)[host == backfill_host]
    return builder(
        identity,
        state,
        host_reference=host_reference,
        history_before=history_before,
    )


def _skip_backfill_lineage(
    _state: Mapping[str, Any],
    *,
    lineage: None,
    before: Mapping[str, Any] | None,
) -> None:
    del lineage, before


def _validate_backfill_lineage(
    state: Mapping[str, Any],
    *,
    lineage: controlled_gaps.BackfillLineageReceipt,
    before: Mapping[str, Any] | None,
) -> None:
    invalid = "formal backfill lineage does not bind durable publication state"
    run_lineage = state["lineage"]
    history = state["authority"]["history_snapshot"]
    prior_heads = history["episode_heads"]
    proposed_heads = run_lineage["proposed_episode_heads"]
    require(isinstance(before, Mapping), invalid)
    expected_backlog = before["backlog_head"]
    require(
        (
            lineage.expected_backlog_ref,
            lineage.expected_episode_head_set_ref,
            lineage.proposed_episode_head_set_ref,
            lineage.prior_episode_heads_commitment,
            lineage.proposed_episode_heads_commitment,
            run_lineage.get("expected_backlog_ref"),
            run_lineage.get("expected_episode_head_set_ref"),
            run_lineage.get("proposed_episode_head_set_ref"),
            run_lineage.get("prior_episode_heads"),
        )
        == (
            expected_backlog,
            history["episode_head_root_ref"],
            run_lineage.get("proposed_episode_head_set_ref"),
            "sha256:" + canonical_sha256(prior_heads),
            "sha256:" + canonical_sha256(proposed_heads),
            expected_backlog,
            history["episode_head_root_ref"],
            lineage.proposed_episode_head_set_ref,
            prior_heads,
        ),
        invalid,
    )


def validate_backfill_lineage(
    state: Mapping[str, Any],
    *,
    lineage: controlled_gaps.BackfillLineageReceipt | None,
    before: Mapping[str, Any] | None,
) -> None:
    validator = (_validate_backfill_lineage, _skip_backfill_lineage)[lineage is None]
    validator(state, lineage=lineage, before=before)
