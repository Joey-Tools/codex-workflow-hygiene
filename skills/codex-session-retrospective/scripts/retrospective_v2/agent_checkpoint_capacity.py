"""Checkpoint-reserve enforcement for agent claim and result transitions."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Protocol

from . import agent_capacity
from .orchestrator_support import InvalidInputError


class CheckpointStore(Protocol):
    def has_operating_capacity(self, state: Mapping[str, Any]) -> bool: ...


class StatePort(Protocol):
    def _append_gap(self, *args: Any, **kwargs: Any) -> str: ...

    def _block(self, *args: Any, **kwargs: Any) -> None: ...


class Staging(Protocol):
    def clear(self) -> None: ...


def _has_task_capacity(
    store: CheckpointStore,
    state: Mapping[str, Any],
    task: Mapping[str, Any],
) -> bool:
    try:
        agent_capacity.validate_checkpoint_task(task)
    except InvalidInputError:
        return False
    return store.has_operating_capacity(state)


def _restore_blocked(
    state_port: StatePort,
    state: dict[str, Any],
    original_state: Mapping[str, Any],
    *,
    dependency_ref: str,
) -> None:
    state.clear()
    state.update(copy.deepcopy(dict(original_state)))
    state_port._append_gap(
        state,
        dependency_ref=dependency_ref,
        reason="checkpoint_capacity_exhausted",
        stage=state["stage"],
        repairable=True,
    )
    state_port._block(state, "checkpoint_capacity_exhausted")


def finalize_claim(
    store: CheckpointStore,
    state_port: StatePort,
    state: dict[str, Any],
    original_state: Mapping[str, Any],
    task: Mapping[str, Any],
    prepared_files: list[Any],
    value: dict[str, Any],
    *,
    attempt_ref: str,
    changed: bool,
    job_ref: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not changed or _has_task_capacity(store, state, task):
        return state, value
    prepared_files.clear()
    _restore_blocked(
        state_port,
        state,
        original_state,
        dependency_ref=job_ref,
    )
    return state, {
        "attempt_ref": attempt_ref,
        "checkpoint_capacity_exhausted": True,
        "idempotent": False,
        "job_ref": job_ref,
        "outcome": "blocked",
    }


def finalize_result(
    store: CheckpointStore,
    state_port: StatePort,
    state: dict[str, Any],
    original_state: Mapping[str, Any],
    task: Mapping[str, Any],
    *,
    job_ref: str,
    outcome: str,
    reason: str | None,
    staging: Staging | None = None,
    changed: bool = True,
    idempotent: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not changed or _has_task_capacity(store, state, task):
        return state, {
            "accepted": True,
            "idempotent": idempotent,
            "outcome": outcome,
            "reason": reason,
        }
    if staging is not None:
        staging.clear()
    _restore_blocked(
        state_port,
        state,
        original_state,
        dependency_ref=job_ref,
    )
    return state, {
        "accepted": False,
        "checkpoint_capacity_exhausted": True,
        "idempotent": False,
        "outcome": "blocked",
        "reason": "checkpoint_capacity_exhausted",
    }
