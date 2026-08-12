"""Authenticated coordinator state guards and deterministic transitions."""

from __future__ import annotations
import datetime as dt
from typing import Any, Iterable, Mapping
from .checkpoints import CheckpointNotFoundError
from .contracts import (
    RefType,
    RunStage,
    parse_typed_ref,
)
from .identity import IdentityKeyMismatchError
from .run_state_authority import validate_run_source_authority
from .run_state_contracts import RunStateAuthorityError

from .orchestrator_core import (
    InvalidInputError,
    InvalidTransitionError,
    RunNotStartedError,
    _format_timestamp,
    _json_copy,
    _normalize_timestamp,
    _parse_timestamp,
    _safe_reason,
)


class CoordinatorStateOperations:
    def _require_retention_active_state(self, state: Mapping[str, Any]) -> None:
        if state["publication"].get("phase") in {
            "expired_cleanup_claimed",
            "expired_cleanup_complete",
        } or self._retention_expired(state):
            raise InvalidTransitionError(
                "retention deadline expired before publication was finalized"
            )

    def ensure_retention_active(self) -> None:
        state = self.load_state()
        self._require_retention_active_state(state)

    def load_state(self) -> dict[str, Any]:
        try:
            state = self.store.load()
        except CheckpointNotFoundError as error:
            raise RunNotStartedError("run has not been started") from error
        self._assert_state_identity(state)
        return state

    def _append_gap(
        self,
        state: dict[str, Any],
        *,
        dependency_ref: str,
        reason: str,
        stage: str,
        repairable: bool,
        host_refs: Iterable[str] = (),
        source_kind: str | None = None,
        typed_gap: Mapping[str, str] | None = None,
    ) -> str:
        normalized_reason = _safe_reason(reason, fallback="unknown_gap")
        normalized_hosts = sorted(set(host_refs))
        gap_ref = self._ref(
            RefType.RUN_INPUT,
            state["run_ref"],
            "gap",
            dependency_ref,
            normalized_reason,
            stage,
            normalized_hosts,
            source_kind,
        )
        if any(gap["gap_ref"] == gap_ref for gap in state["gaps"]):
            return gap_ref
        gap: dict[str, Any] = {
            "dependency_ref": dependency_ref,
            "gap_ref": gap_ref,
            "reason": normalized_reason,
            "repairable": bool(repairable),
            "stage": stage,
        }
        if normalized_hosts:
            gap["host_ref"] = normalized_hosts[0]
        if source_kind is not None:
            gap["source_kind"] = source_kind
        if typed_gap is not None:
            gap["typed_gap"] = _json_copy(dict(typed_gap), label="typed gap")
        state["gaps"].append(gap)
        state["gaps"].sort(key=lambda item: item["gap_ref"])
        return gap_ref

    def _assert_state_identity(self, state: Mapping[str, Any]) -> None:
        if state.get("identity_key_id") != self.identity.key_id:
            raise IdentityKeyMismatchError(
                "run state identity_key_id does not match the loaded fixed identity"
            )
        try:
            validate_run_source_authority(
                self.identity,
                state,
                canonical_hosts=self._canonical_hosts(),
            )
        except RunStateAuthorityError as error:
            raise InvalidTransitionError(str(error)) from error

    def _block(self, state: dict[str, Any], reason: str) -> None:
        state["blocked_reason"] = reason
        state["coverage"]["status"] = "blocked"
        self._transition(state, RunStage.BLOCKED)

    def _now(self) -> str:
        value = self._clock()
        if isinstance(value, str):
            return _normalize_timestamp(value, label="clock")
        if not isinstance(value, dt.datetime):
            raise InvalidInputError("clock must return datetime or ISO-8601 string")
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidInputError("clock must return a timezone-aware datetime")
        return _format_timestamp(value)

    @staticmethod
    def _require_stage(state: Mapping[str, Any], stage: RunStage) -> None:
        if state.get("stage") != stage.value:
            raise InvalidTransitionError(
                f"action requires stage {stage.value}, found {state.get('stage')}"
            )

    def _retention_expired(self, state: Mapping[str, Any]) -> bool:
        if state["publication"].get("finalized_at") is not None:
            return False
        now = _parse_timestamp(self._now(), label="clock")
        deadlines = [
            _parse_timestamp(state["deadlines"]["raw"], label="raw deadline"),
            _parse_timestamp(state["deadlines"]["working"], label="working deadline"),
        ]
        export_deadline = state["publication"].get("retention_deadline")
        if state["publication"].get("exported_at") is not None:
            if not isinstance(export_deadline, str):
                return True
            deadlines.append(
                _parse_timestamp(export_deadline, label="export retention deadline")
            )
        return now >= min(deadlines)

    def _transition(self, state: dict[str, Any], stage: RunStage) -> None:
        if state["stage"] == stage.value:
            return
        state["stage"] = stage.value
        state["stage_history"].append({"entered_at": self._now(), "stage": stage.value})
        state["metrics"]["stage_transitions"] += 1

    def _validate_ref(
        self,
        value: Any,
        kind: RefType,
        *,
        label: str,
    ) -> str:
        if not isinstance(value, str):
            raise InvalidInputError(f"{label} must be a typed reference string")
        try:
            parse_typed_ref(value, expected=kind)
        except (TypeError, ValueError) as error:
            raise InvalidInputError(
                f"{label} is not a valid {kind.value} reference"
            ) from error
        return value
