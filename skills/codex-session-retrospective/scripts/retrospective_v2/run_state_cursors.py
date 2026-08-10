"""History-bound run cursor and terminal source proposal derivation."""

from __future__ import annotations

from collections.abc import Mapping
import datetime as dt
from typing import Any

from .contracts import RefType, RunMode, SourceCellStatus
from .identity import IdentityKey
from .run_state_contracts import (
    RunStateAuthorityError,
    TERMINAL_SOURCE_STATUSES,
    derive_ref,
    require,
)


def history_cursor_rows(state: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    invalid = "run checkpoint durable cursor history is invalid"
    authority = state.get("authority")
    require(isinstance(authority, Mapping), invalid)
    history = authority.get("history_snapshot")
    require(isinstance(history, Mapping), invalid)
    rows = history.get("cursor_rows")
    require(isinstance(rows, list), invalid)
    try:
        by_host = dict(map(lambda row: (row["host_ref"], dict(row)), rows))
    except (KeyError, TypeError, ValueError) as error:
        raise RunStateAuthorityError(invalid) from error
    require(len(by_host) == len(rows), invalid)
    return by_host


def history_cursor_before(
    history_rows: Mapping[str, Mapping[str, Any]],
    host_reference: str,
) -> dict[str, Any]:
    row = history_rows.get(
        host_reference,
        {"backlog_ref": None, "cursor_ref": None, "logical_boundary": None},
    )
    return {
        "backlog_head": row.get("backlog_ref"),
        "cursor": row.get("cursor_ref"),
        "logical_boundary": row.get("logical_boundary"),
    }


def _utc_instant(value: object, *, label: str) -> dt.datetime:
    try:
        require(isinstance(value, str), f"{label} is invalid")
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError) as error:
        raise RunStateAuthorityError(f"{label} is invalid") from error
    require(parsed.tzinfo is not None, f"{label} is invalid")
    return parsed.astimezone(dt.timezone.utc)


def _complete_cursor(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    host_reference: str,
    cells: Mapping[str, Mapping[str, Any]],
    before: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    source_vector = dict(
        map(
            lambda item: (
                item[0],
                {
                    "snapshot_ref": item[1].get("snapshot_ref"),
                    "status": item[1].get("status"),
                },
            ),
            sorted(cells.items()),
        )
    )
    prior_boundary = before["logical_boundary"]
    window_end = state["window"]["end"]
    advance_check = (_cursor_advances_from_boundary, _cursor_always_advances)[
        prior_boundary is None
    ]
    advances = advance_check(window_end, prior_boundary)
    logical_boundary = (prior_boundary, window_end)[advances]
    derived_snapshot_ref = derive_ref(
        identity,
        RefType.SOURCE,
        state["run_ref"],
        "cursor_proposal",
        host_reference,
        before,
        source_vector,
        logical_boundary,
    )
    source_snapshot_ref = (before["cursor"], derived_snapshot_ref)[advances]
    proposal = {
        "logical_boundary": logical_boundary,
        "source_cells": source_vector,
        "source_snapshot_ref": source_snapshot_ref,
    }
    return (
        {
            "before": dict(before),
            "decision": "proposed",
            "proposed": proposal,
            "publication_state": "complete",
        },
        {
            host_reference: {
                "backlog_ref": None,
                "cursor_ref": source_snapshot_ref,
                "host_ref": host_reference,
                "logical_boundary": logical_boundary,
            }
        },
    )


def _cursor_always_advances(_window_end: object, _prior_boundary: object) -> bool:
    return True


def _cursor_advances_from_boundary(
    window_end: object,
    prior_boundary: object,
) -> bool:
    return _utc_instant(
        window_end,
        label="run cursor window end",
    ) > _utc_instant(prior_boundary, label="run cursor prior boundary")


def _gap_cursor(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    host_reference: str,
    cells: Mapping[str, Mapping[str, Any]],
    before: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    del cells
    backlog_ref = derive_ref(
        identity,
        RefType.RUN_INPUT,
        state["run_ref"],
        host_reference,
        "publication_backlog",
    )
    return (
        {
            "before": dict(before),
            "decision": "held_for_gap",
            "proposed": None,
            "publication_state": "backfill_required",
        },
        {
            host_reference: {
                "backlog_ref": backlog_ref,
                "cursor_ref": before["cursor"],
                "host_ref": host_reference,
                "logical_boundary": before["logical_boundary"],
            }
        },
    )


def _not_applicable_cursor(
    _identity: IdentityKey,
    _state: Mapping[str, Any],
    *,
    host_reference: str,
    cells: Mapping[str, Mapping[str, Any]],
    before: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    del host_reference, cells
    return (
        {
            "before": dict(before),
            "decision": "not_applicable",
            "proposed": None,
            "publication_state": "not_applicable",
        },
        {},
    )


def formal_cursor(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    host_reference: str,
    cells: Mapping[str, Mapping[str, Any]],
    before: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    statuses = set(map(lambda cell: cell.get("status"), cells.values()))
    require(
        statuses <= TERMINAL_SOURCE_STATUSES,
        "formal run has nonterminal source cursor evidence",
    )
    mode = state.get("mode")
    has_gap = SourceCellStatus.GAP.value in statuses
    builders = {
        (RunMode.BASELINE.value, False): _not_applicable_cursor,
        (RunMode.SESSION.value, False): _not_applicable_cursor,
        (RunMode.DAILY.value, False): _complete_cursor,
        (RunMode.DAILY.value, True): _gap_cursor,
        (RunMode.WEEKLY.value, False): _complete_cursor,
    }
    builder = builders.get((mode, has_gap))
    require(callable(builder), "formal run mode or source gap state is invalid")
    return builder(
        identity,
        state,
        host_reference=host_reference,
        cells=cells,
        before=before,
    )
