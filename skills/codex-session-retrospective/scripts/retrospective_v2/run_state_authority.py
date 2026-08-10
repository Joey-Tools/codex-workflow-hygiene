"""Shared authenticated run-state and formal-publication authority validation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from itertools import chain
from typing import Any

from .identity import IdentityKey
from .run_state_contracts import (
    FORMAL_STAGES,
    REQUIRED_RUN_SOURCE_KINDS,
    host_ref,
    require,
)
from .run_state_cursors import formal_cursor, history_cursor_before, history_cursor_rows
from .run_state_holdouts import validate_formal_controlled_holdouts
from .run_state_lineage import (
    expected_backfill_cursor,
    validate_backfill_lineage,
    verify_backfill,
)


def _validate_durable_state(
    state: Mapping[str, Any],
    *,
    durable: Mapping[str, Any],
    history_rows: Mapping[str, Mapping[str, Any]],
    cursor_updates: Mapping[str, Mapping[str, Any]],
) -> None:
    expected_rows = dict(
        map(lambda item: (item[0], dict(item[1])), history_rows.items())
    )
    expected_rows.update(
        dict(map(lambda item: (item[0], dict(item[1])), cursor_updates.items()))
    )
    snapshots = sorted(
        map(
            lambda cell: cell["snapshot_ref"],
            chain.from_iterable(
                map(
                    lambda cells: cells.values(),
                    state["source"]["cells"].values(),
                )
            ),
        )
    )
    lineage = state["lineage"]
    require(
        (
            durable.get("backfill_of"),
            durable.get("proposed_cursor_rows"),
            durable.get("proposed_episode_head_root_ref"),
            durable.get("proposed_episode_heads"),
            durable.get("source_snapshot_refs"),
        )
        == (
            lineage.get("backfill_of"),
            sorted(expected_rows.values(), key=lambda row: row["host_ref"]),
            lineage.get("proposed_episode_head_set_ref"),
            lineage.get("proposed_episode_heads"),
            snapshots,
        ),
        "run durable publication state is not derived from checkpoint evidence",
    )


def _skip_durable_state(
    _state: Mapping[str, Any],
    *,
    durable: None,
    history_rows: Mapping[str, Mapping[str, Any]],
    cursor_updates: Mapping[str, Mapping[str, Any]],
) -> None:
    del durable, history_rows, cursor_updates


def _reject_nonformal_durable_state(
    _state: Mapping[str, Any],
    *,
    durable: Mapping[str, Any],
    history_rows: Mapping[str, Mapping[str, Any]],
    cursor_updates: Mapping[str, Mapping[str, Any]],
) -> None:
    del durable, history_rows, cursor_updates
    require(False, "nonformal run retains durable publication state")


def _validate_formal_cursor(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    host: str,
    reference: str,
    cells: Mapping[str, Mapping[str, Any]],
    before: Mapping[str, Any],
    cursor: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    del host
    expected_cursor, updates = formal_cursor(
        identity,
        state,
        host_reference=reference,
        cells=cells,
        before=before,
    )
    require(
        dict(cursor) == expected_cursor,
        "run cursor proposal is not derived from terminal source evidence",
    )
    return updates


def _skip_formal_cursor(
    _identity: IdentityKey,
    _state: Mapping[str, Any],
    *,
    host: str,
    reference: str,
    cells: Mapping[str, Mapping[str, Any]],
    before: Mapping[str, Any],
    cursor: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    del host, reference, cells, before, cursor
    return {}


def validate_run_source_authority(
    identity: IdentityKey,
    state: Mapping[str, Any],
    *,
    canonical_hosts: Sequence[str],
) -> None:
    """Validate source coverage, cursor derivation, and durable run authority."""

    hosts = tuple(canonical_hosts)
    invalid_policy = "canonical host policy is invalid"
    require(bool(hosts), invalid_policy)
    require(len(hosts) == len(set(hosts)), invalid_policy)
    require(set(map(type, hosts)) == {str}, invalid_policy)
    require(all(hosts), invalid_policy)
    formal = state.get("stage") in FORMAL_STAGES
    backfill_host, _gap, backfill_lineage = verify_backfill(
        identity,
        state,
        canonical_hosts=hosts,
        require_lineage=formal,
    )
    expected_hosts = (set(hosts), {backfill_host})[backfill_host is not None]
    expected_source_kinds = set(REQUIRED_RUN_SOURCE_KINDS)
    host_refs = state.get("host_refs")
    source = state.get("source")
    require(isinstance(source, Mapping), "run checkpoint lacks source state")
    source_cells = source.get("cells")
    cursors = state.get("cursors")
    invalid_matrix = "run checkpoint does not cover the canonical source matrix"
    require(isinstance(host_refs, Mapping), invalid_matrix)
    require(isinstance(source_cells, Mapping), invalid_matrix)
    require(isinstance(cursors, Mapping), invalid_matrix)
    require(set(host_refs) == expected_hosts, invalid_matrix)
    require(set(source_cells) == expected_hosts, invalid_matrix)
    require(set(cursors) == expected_hosts, invalid_matrix)
    cells_by_host: dict[str, Mapping[str, Mapping[str, Any]]] = {}
    references: dict[str, str] = {}
    for host in expected_hosts:
        cells = source_cells[host]
        require(isinstance(cells, Mapping), invalid_matrix)
        require(set(cells) == expected_source_kinds, invalid_matrix)
        require(
            all(map(lambda cell: isinstance(cell, Mapping), cells.values())),
            invalid_matrix,
        )
        reference = host_ref(identity, host)
        require(host_refs[host] == reference, invalid_matrix)
        require(
            all(map(lambda cell: cell.get("host_ref") == reference, cells.values())),
            invalid_matrix,
        )
        cells_by_host[host] = cells
        references[host] = reference
    if formal:
        validate_formal_controlled_holdouts(
            identity,
            state,
            source_cells=cells_by_host,
        )
    history_rows = history_cursor_rows(state)
    cursor_updates: dict[str, dict[str, Any]] = {}
    before_by_host: dict[str, dict[str, Any]] = {}
    cursor_validator = (_skip_formal_cursor, _validate_formal_cursor)[formal]
    for host, cells in cells_by_host.items():
        reference = references[host]
        before = expected_backfill_cursor(
            identity,
            state,
            host=host,
            host_reference=reference,
            backfill_host=backfill_host,
            history_before=history_cursor_before(history_rows, reference),
        )
        cursor = cursors[host]
        require(isinstance(cursor, Mapping), "run cursor state is invalid")
        require(
            cursor.get("before") == before,
            "run cursor start does not match durable history",
        )
        before_by_host[host] = before
        cursor_updates.update(
            cursor_validator(
                identity,
                state,
                host=host,
                reference=reference,
                cells=cells,
                before=before,
                cursor=cursor,
            )
        )
    validate_backfill_lineage(
        state,
        lineage=backfill_lineage,
        before=before_by_host.get(backfill_host),
    )
    publication = state.get("publication")
    require(isinstance(publication, Mapping), "run publication state is invalid")
    durable = publication.get("durable_state")
    require(
        (durable is None, isinstance(durable, Mapping)) != (False, False),
        "run durable publication state is invalid",
    )
    durable_validator = {
        (False, False): _skip_durable_state,
        (False, True): _reject_nonformal_durable_state,
        (True, False): _skip_durable_state,
        (True, True): _validate_durable_state,
    }[(formal, durable is not None)]
    durable_validator(
        state,
        durable=durable,
        history_rows=history_rows,
        cursor_updates=cursor_updates,
    )
