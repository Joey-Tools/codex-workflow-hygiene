"""Authenticated run lifecycle, publication claims, and raw cleanup."""

from __future__ import annotations
import copy
import datetime as dt
import hmac
import os
from pathlib import Path
from typing import Any, Mapping, Sequence
from . import (
    authority,
    catalog,
    controlled_gaps,
    export as retained_export_api,
    finalize,
    reporting,
    retained_inputs,
    safe_io,
    source_inputs,
    source_payloads,
    transport as source_transport,
)
from .checkpoints import (
    CheckpointConflictError,
    CheckpointNotFoundError,
    canonical_json_bytes,
    content_digest,
)
from .contracts import RefType, RunMode, RunStage, SourceCellStatus, SourceKind
from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_protocols import (
    LifecycleHistoryPort,
    LifecycleProjectionPort,
    LifecycleSourcePort,
    LifecycleStatePort,
)

from .orchestrator_support import (
    InvalidInputError,
    InvalidTransitionError,
    LEGACY_SHADOW_CLEANUP_ROOTS,
    MAX_BASELINE_WINDOW_DAYS,
    MAX_EXPORT_RETENTION_HOURS,
    MAX_RETENTION_DAYS,
    RAW_INPUT_DIRECTORY,
    RAW_SHARD_DIRECTORY,
    REQUIRED_SOURCE_KINDS,
    RunConflictError,
    RunNotStartedError,
    SHADOW_CLEANUP_ROOTS,
    STATE_SCHEMA_VERSION,
    _NON_GAP_SOURCE_TERMINAL,
    _PUBLICATION_ATTEMPT_RE,
    _SHA256_RE,
    _SOURCE_TERMINAL,
    _TASK_TERMINAL,
    _build_provenance,
    _format_timestamp,
    _json_copy,
    _normalize_hosts,
    _normalize_source_kinds,
    _normalize_timestamp,
    _parse_timestamp,
)


def _cleanup_contract(kind: str, version: int, roots: Sequence[str]):
    return (
        f"{kind}_cleanup_claim_v{version}:",
        f"{kind}-cleanup-claim-v{version}",
        roots,
        f"raw_cleanup_receipt_v{version}",
        f"raw_cleanup_auth_v{version}",
    )


_RAW_CLEANUP_CONTRACTS = {
    "raw_cleanup_claim_v2": _cleanup_contract("raw", 2, LEGACY_SHADOW_CLEANUP_ROOTS),
    "raw_cleanup_claim_v3": _cleanup_contract("raw", 3, SHADOW_CLEANUP_ROOTS),
}
_SHADOW_CLEANUP_CONTRACTS = {
    "shadow_cleanup_claim_v2": _cleanup_contract(
        "shadow", 2, LEGACY_SHADOW_CLEANUP_ROOTS
    ),
    "shadow_cleanup_claim_v3": _cleanup_contract("shadow", 3, SHADOW_CLEANUP_ROOTS),
}


class RunLifecycleOperations(OrchestratorComponent):
    def __init__(
        self,
        context: RuntimeContext,
        *,
        state: LifecycleStatePort,
        projection: LifecycleProjectionPort,
        history: LifecycleHistoryPort,
        source: LifecycleSourcePort,
    ) -> None:
        super().__init__(context)
        self._state = state
        self._projection = projection
        self._history = history
        self._source = source

    def start(
        self,
        *,
        mode: str | RunMode,
        start: str | None = None,
        end: str | None = None,
        window_start: str | None = None,
        window_end: str | None = None,
        hosts: Sequence[str] | None = None,
        source_kinds: Sequence[str | SourceKind] | None = None,
        cursors: Mapping[str, Any] | None = None,
        allow_partial: bool = False,
        session_target: str | None = None,
        session_target_selector: str | None = None,
        backfill_of: str | None = None,
        prior_episode_heads: Sequence[Mapping[str, Any]] | None = None,
        prior_episode_head_set_ref: str | None = None,
        controlled_gap_receipt: Mapping[str, Any] | None = None,
        shadow_successor: Mapping[str, Any] | None = None,
        shadow: bool = False,
        provenance: Mapping[str, Any] | None = None,
        policy_provenance: Mapping[str, Any] | str | None = None,
        model_provenance: Mapping[str, Any] | str | None = None,
        version_provenance: Mapping[str, Any] | None = None,
        history_repo: str | os.PathLike[str] | None = None,
        history_target_ref: str | None = None,
        provider_state: str | os.PathLike[str] | None = None,
        production_marker: str | os.PathLike[str] | None = None,
        publisher_fingerprint: str = authority.DEFAULT_PUBLISHER_FINGERPRINT,
        publisher_gnupg_home: str | os.PathLike[str] = (
            authority.DEFAULT_PUBLISHER_GNUPG_HOME
        ),
        run_ref: str | None = None,
        created_at: str | None = None,
        raw_retention_days: int = MAX_RETENTION_DAYS,
        working_retention_days: int = MAX_RETENTION_DAYS,
    ) -> dict[str, Any]:
        try:
            mode_value = RunMode(mode).value
        except (TypeError, ValueError) as error:
            raise InvalidInputError(f"unknown run mode: {mode!r}") from error
        if not isinstance(allow_partial, bool):
            raise InvalidInputError("allow_partial must be a boolean")
        if not isinstance(shadow, bool):
            raise InvalidInputError("shadow must be a boolean")
        if None in (history_repo, history_target_ref):
            raise InvalidInputError(
                "start requires the configured durable history repository and ref"
            )
        history_path = Path(history_repo).expanduser().absolute()
        if not isinstance(history_target_ref, str) or not history_target_ref:
            raise InvalidInputError("history_target_ref is invalid")
        provider_path = (
            None
            if provider_state is None
            else Path(provider_state).expanduser().absolute()
        )
        marker_path = (
            None
            if production_marker is None
            else Path(production_marker).expanduser().absolute()
        )
        if allow_partial and mode_value != RunMode.DAILY.value:
            raise InvalidInputError("partial state is available only for daily runs")
        canonical_hosts = self._canonical_hosts()
        host_values = _normalize_hosts(canonical_hosts if hosts is None else hosts)
        source_values = _normalize_source_kinds(source_kinds)
        if any(host not in canonical_hosts for host in host_values):
            raise InvalidInputError("runs may target only canonical hosts")
        if mode_value in {
            RunMode.WEEKLY.value,
            RunMode.BASELINE.value,
            RunMode.SESSION.value,
        } and set(host_values) != set(canonical_hosts):
            raise InvalidInputError(
                "weekly, baseline, and session runs require every canonical host"
            )
        if (
            mode_value == RunMode.DAILY.value
            and backfill_of is None
            and set(host_values) != set(canonical_hosts)
        ):
            raise InvalidInputError(
                "ordinary daily runs require the complete canonical host set"
            )
        if (
            mode_value == RunMode.DAILY.value
            and backfill_of is not None
            and (len(host_values) != 1 or host_values[0] not in canonical_hosts)
        ):
            raise InvalidInputError("daily backfill must target one canonical host")

        start_value = window_start if window_start is not None else start
        end_value = window_end if window_end is not None else end
        if None in (start_value, end_value):
            raise InvalidInputError("start and end are required")
        normalized_start = _normalize_timestamp(start_value, label="window start")
        normalized_end = _normalize_timestamp(end_value, label="window end")
        start_time = _parse_timestamp(normalized_start, label="window start")
        end_time = _parse_timestamp(normalized_end, label="window end")
        if start_time >= end_time:
            raise InvalidInputError("run window must be a non-empty half-open interval")
        if mode_value == RunMode.WEEKLY.value and end_time - start_time != dt.timedelta(
            days=7
        ):
            raise InvalidInputError("weekly runs require an exact seven-day window")
        if (
            mode_value == RunMode.BASELINE.value
            and end_time - start_time != dt.timedelta(days=MAX_BASELINE_WINDOW_DAYS)
        ):
            raise InvalidInputError("baseline runs require an exact 90-day window")

        if mode_value == RunMode.SESSION.value:
            normalized_target = self._state._validate_ref(
                session_target,
                RefType.SESSION,
                label="session_target",
            )
            if not isinstance(session_target_selector, str):
                raise InvalidInputError(
                    "session mode requires the raw session selector at start"
                )
            try:
                derived_target = str(
                    self.identity.derive_ref(
                        RefType.SESSION,
                        {"session_id": session_target_selector},
                    )
                )
                session_selector_ref = source_transport.session_selector_commitment(
                    session_target_selector
                )
            except (
                TypeError,
                ValueError,
                source_transport.TransportValidationError,
            ) as error:
                raise InvalidInputError("session target selector is invalid") from error
            if not hmac.compare_digest(derived_target, normalized_target):
                raise InvalidInputError(
                    "session target selector does not match session_target"
                )
        else:
            if session_target is not None or session_target_selector is not None:
                raise InvalidInputError(
                    "session target and selector are valid only in session mode"
                )
            normalized_target = None
            session_selector_ref = None
        if backfill_of is not None:
            if mode_value != RunMode.DAILY.value:
                raise InvalidInputError("backfill_of is valid only for daily runs")
            normalized_backfill = self._state._validate_ref(
                backfill_of,
                RefType.RUN,
                label="backfill_of",
            )
        else:
            normalized_backfill = None
        if prior_episode_heads is not None or prior_episode_head_set_ref is not None:
            raise InvalidInputError(
                "episode heads are derived from durable history and cannot be supplied"
            )

        normalized_provenance = _build_provenance(
            provenance=provenance,
            policy=policy_provenance,
            model=model_provenance,
            versions=version_provenance,
        )
        configuration_ref = self._ref(
            RefType.CONFIGURATION,
            normalized_provenance["configuration_root"],
        )
        era_state = {"provenance": normalized_provenance}
        model_era = self._projection._model_era(era_state)
        policy_era = self._projection._policy_token(
            era_state,
            "policy",
            "source_policy_v2",
        )
        try:
            durable_history = authority.load_durable_history(
                history_path,
                history_target_ref,
                identity=self.identity,
                expected_fingerprint=publisher_fingerprint,
                gnupg_home=publisher_gnupg_home,
            )
            if provider_path is not None:
                authority.assert_provider_cache_matches(
                    provider_path,
                    durable_history,
                    identity=self.identity,
                )
            elif not shadow:
                raise InvalidInputError(
                    "production start requires an initialized provider cache"
                )
            if not shadow:
                if marker_path is None:
                    raise InvalidInputError(
                        "production start requires the completed cutover marker"
                    )
                authority.load_production_marker(
                    marker_path,
                    identity=self.identity,
                    history_repo=history_path,
                    target_ref=history_target_ref,
                    configuration_root=normalized_provenance["configuration_root"],
                    configuration_ref=configuration_ref,
                    model_era=model_era,
                    policy_era=policy_era,
                )
        except authority.AuthorityError as error:
            raise RunConflictError(
                "durable history, provider cache, or production marker validation failed"
            ) from error

        normalized_prior_heads = [
            copy.deepcopy(item) for item in durable_history.episode_heads
        ]
        normalized_prior_head_set_ref = durable_history.episode_head_root_ref
        normalized_prior_membership = [
            copy.deepcopy(item) for item in durable_history.episode_membership
        ]
        if normalized_backfill is not None:
            if controlled_gap_receipt is None:
                raise InvalidInputError(
                    "every backfill requires an authenticated controlled gap receipt"
                )
            try:
                normalized_controlled_gap = (
                    controlled_gaps.verify_controlled_gap_receipt(
                        self.identity,
                        controlled_gap_receipt,
                    )
                )
            except (
                TypeError,
                ValueError,
                controlled_gaps.ControlledGapError,
            ) as error:
                raise InvalidInputError(
                    "controlled gap receipt authentication failed"
                ) from error
            if (
                normalized_controlled_gap.run_ref != normalized_backfill
                or tuple(host_values) != (normalized_controlled_gap.host,)
                or normalized_controlled_gap.window_start != normalized_start
                or normalized_controlled_gap.window_end != normalized_end
                or normalized_controlled_gap.shadow is not shadow
            ):
                raise InvalidInputError(
                    "controlled gap receipt does not bind this backfill"
                )
        else:
            if controlled_gap_receipt is not None:
                raise InvalidInputError(
                    "controlled gap receipt is valid only for a backfill run"
                )
            normalized_controlled_gap = None
        if normalized_backfill is not None and shadow:
            if shadow_successor is None:
                raise InvalidInputError(
                    "shadow backfill requires a completed partial successor authorization"
                )
            normalized_shadow_successor = self._validate_shadow_daily_successor(
                shadow_successor,
                backfill_of=normalized_backfill,
                controlled_gap_receipt=normalized_controlled_gap.to_dict(),
                history_repo=str(history_path),
                history_target_ref=history_target_ref,
                host=host_values[0],
                provenance=normalized_provenance,
                window={"end": normalized_end, "start": normalized_start},
            )
        elif shadow_successor is not None:
            raise InvalidInputError(
                "shadow successor authorization is valid only for a shadow backfill"
            )
        else:
            normalized_shadow_successor = None

        for label, value in (
            ("raw_retention_days", raw_retention_days),
            ("working_retention_days", working_retention_days),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
                or value > MAX_RETENTION_DAYS
            ):
                raise InvalidInputError(f"{label} must be an integer from 1 to 7")

        history_cursors = {
            row["host_ref"]: {
                "backlog_head": row["backlog_ref"],
                "cursor": row["cursor_ref"],
                "logical_boundary": row["logical_boundary"],
            }
            for row in durable_history.cursor_rows
        }
        initial_cursors = {
            host: copy.deepcopy(
                history_cursors.get(
                    self._ref(RefType.HOST, host),
                    {
                        "backlog_head": None,
                        "cursor": None,
                        "logical_boundary": None,
                    },
                )
            )
            for host in host_values
        }
        backlogged_hosts = {
            host: cursor["backlog_head"]
            for host, cursor in initial_cursors.items()
            if cursor["backlog_head"] is not None
        }
        backfill_expected_backlog_ref: str | None = None
        if normalized_backfill is None and backlogged_hosts:
            raise RunConflictError(
                "durable backlog requires a matching authenticated backfill"
            )
        if normalized_backfill is not None:
            assert normalized_controlled_gap is not None
            expected_backlog_ref = self._ref(
                RefType.RUN_INPUT,
                normalized_backfill,
                normalized_controlled_gap.host_ref,
                "publication_backlog",
            )
            backfill_expected_backlog_ref = initial_cursors[
                normalized_controlled_gap.host
            ]["backlog_head"]
            if shadow and backfill_expected_backlog_ref is None:
                initial_cursors[normalized_controlled_gap.host]["backlog_head"] = (
                    expected_backlog_ref
                )
                backfill_expected_backlog_ref = expected_backlog_ref
            if backfill_expected_backlog_ref is None:
                raise RunConflictError(
                    "backfill requires an exact published durable backlog head"
                )
            if backfill_expected_backlog_ref != expected_backlog_ref:
                raise RunConflictError(
                    "durable backlog does not match the controlled partial run"
                )
        if (
            cursors is not None
            and self._normalize_cursors(cursors, host_values) != initial_cursors
        ):
            raise RunConflictError(
                "caller cursor state differs from the latest durable history"
            )
        specification = {
            "allow_partial": allow_partial,
            "backfill_of": normalized_backfill,
            "controlled_gap_receipt": (
                None
                if normalized_controlled_gap is None
                else normalized_controlled_gap.to_dict()
            ),
            "backfill_expected_backlog_ref": backfill_expected_backlog_ref,
            "hosts": list(host_values),
            "identity_key_id": self.identity.key_id,
            "authority": {
                "configuration_root": normalized_provenance["configuration_root"],
                "configuration_ref": configuration_ref,
                "history_repo": str(history_path),
                "history_snapshot": durable_history.provider_projection(),
                "history_target_ref": history_target_ref,
                "model_era": model_era,
                "policy_era": policy_era,
                "production_marker": (
                    None if marker_path is None else str(marker_path)
                ),
                "provider_state": (
                    None if provider_path is None else str(provider_path)
                ),
                "publisher_fingerprint": publisher_fingerprint,
                "publisher_gnupg_home": str(
                    Path(publisher_gnupg_home).expanduser().absolute()
                ),
            },
            "mode": mode_value,
            "provenance": normalized_provenance,
            "prior_episode_head_set_ref": normalized_prior_head_set_ref,
            "prior_episode_heads": normalized_prior_heads,
            "prior_episode_membership": normalized_prior_membership,
            "retention": {
                "raw_days": raw_retention_days,
                "working_days": working_retention_days,
            },
            "shard_limits": {
                "max_bytes": self.shard_limits.max_bytes,
                "max_turns": self.shard_limits.max_turns,
                "record_processing_budget": (
                    self.shard_limits.record_processing_budget
                ),
            },
            "session_target": normalized_target,
            "session_selector_commitment": session_selector_ref,
            "shadow": shadow,
            "shadow_successor": normalized_shadow_successor,
            "source_kinds": list(source_values),
            "starting_cursors": initial_cursors,
            "window": {"end": normalized_end, "start": normalized_start},
        }
        specification_digest = content_digest(specification)
        derived_run_ref = self._ref(RefType.RUN, "run", specification_digest)
        if run_ref is not None:
            supplied_run_ref = self._state._validate_ref(
                run_ref,
                RefType.RUN,
                label="run_ref",
            )
            if supplied_run_ref != derived_run_ref:
                raise InvalidInputError(
                    "run_ref does not match the current specification digest"
                )
        normalized_run_ref = derived_run_ref
        requested_creation_time = (
            _normalize_timestamp(created_at, label="created_at")
            if created_at is not None
            else None
        )

        if self.store.exists():
            snapshot = self.store.read()
            self._state._assert_state_identity(snapshot.state)
            if (
                snapshot.state.get("specification_digest") != specification_digest
                or snapshot.state.get("run_ref") != normalized_run_ref
                or (
                    requested_creation_time is not None
                    and snapshot.state.get("created_at") != requested_creation_time
                )
            ):
                raise RunConflictError("run directory already contains a different run")
            response = self._projection._status_view(snapshot)
            response.update({"action": "start", "created": False, "resumed": True})
            return response

        creation_time = self._state._now()
        if (
            requested_creation_time is not None
            and requested_creation_time != creation_time
        ):
            raise InvalidInputError("created_at does not match the trusted clock")
        creation_datetime = _parse_timestamp(creation_time, label="created_at")
        state = self._initial_state(
            run_ref=normalized_run_ref,
            specification=specification,
            specification_digest=specification_digest,
            created_at=creation_time,
            raw_deadline=_format_timestamp(
                creation_datetime + dt.timedelta(days=raw_retention_days)
            ),
            working_deadline=_format_timestamp(
                creation_datetime + dt.timedelta(days=working_retention_days)
            ),
        )
        try:
            snapshot = self.store.initialize(state)
            created = True
        except CheckpointConflictError:
            snapshot = self.store.read()
            self._state._assert_state_identity(snapshot.state)
            if (
                snapshot.state.get("specification_digest") != specification_digest
                or snapshot.state.get("run_ref") != normalized_run_ref
            ):
                raise RunConflictError(
                    "run directory was concurrently initialized differently"
                )
            created = False
        if snapshot.state["stage"] not in {
            RunStage.COMPLETE.value,
            RunStage.FINALIZE.value,
        }:
            safe_io.ensure_owner_only_directory(
                self.run_dir / RAW_INPUT_DIRECTORY / "source-preparations"
            )
            safe_io.ensure_owner_only_directory(self.run_dir / RAW_SHARD_DIRECTORY)
            safe_io.ensure_owner_only_directory(self.run_dir / "agent-sinks")
        response = self._projection._status_view(snapshot)
        response.update({"action": "start", "created": created, "resumed": not created})
        return response

    def status(self) -> dict[str, Any]:
        self.gc_expired_raw()
        try:
            snapshot = self.store.read()
        except CheckpointNotFoundError as error:
            raise RunNotStartedError("run has not been started") from error
        self._state._assert_state_identity(snapshot.state)
        return self._projection._status_view(snapshot)

    def gc_expired_raw(self) -> dict[str, Any]:
        def claim(
            current: dict[str, Any],
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(current)
            publication = current["publication"]
            phase = publication.get("phase")
            now = _parse_timestamp(self._state._now(), label="clock")
            deadline = _parse_timestamp(
                current["deadlines"]["raw"], label="raw deadline"
            )
            if phase == "expired_cleanup_complete":
                self._validate_completed_raw_cleanup(
                    current,
                    disposition="expired_unpublished",
                )
                current["retained_export"] = None
                return current, {"disposition": "expired_complete"}
            if (
                now < deadline
                or current["stage"] == RunStage.COMPLETE.value
                or phase in {"complete", "shadow_complete"}
            ):
                return current, {"disposition": "ineligible"}
            if phase in {"published_cleanup_pending", "published_cleanup_claimed"}:
                return current, {"disposition": "published"}
            if phase in {"shadow_cleanup_pending", "shadow_cleanup_claimed"}:
                return current, {"disposition": "shadow"}
            publication_claim = publication.get("publication_claim")
            if publication_claim is not None:
                self._validate_publication_claim(current, publication_claim)
                return current, {
                    "claim": copy.deepcopy(dict(publication_claim)),
                    "disposition": "publication_claim",
                }
            existing = publication.get("expired_cleanup_claim")
            if phase == "expired_cleanup_claimed":
                if not isinstance(existing, Mapping):
                    raise RunConflictError("expired cleanup claim is malformed")
                verified = self._validate_raw_cleanup_claim(
                    current,
                    existing,
                    disposition="expired_unpublished",
                    durable_commit=None,
                    phase_before=str(existing.get("phase_before")),
                    publication_claim_ref=None,
                )
                return current, {
                    "claim": verified,
                    "disposition": "claimed",
                }
            inventory = self._raw_cleanup_inventory()
            claim_value = self._raw_cleanup_claim_value(
                current,
                disposition="expired_unpublished",
                durable_commit=None,
                phase_before=str(phase),
                publication_claim_ref=None,
                inventory=inventory,
            )
            publication["expired_cleanup_claim"] = claim_value
            publication["phase"] = "expired_cleanup_claimed"
            return current, {
                "claim": copy.deepcopy(claim_value),
                "disposition": "claimed",
            }

        try:
            claimed = self.store.transaction(claim)
        except CheckpointNotFoundError as error:
            raise RunNotStartedError("run has not been started") from error
        except (OSError, safe_io.UnsafePathError) as error:
            return {
                "cleaned": False,
                "cleanup_error": type(error).__name__,
                "eligible": True,
            }
        disposition = claimed.value["disposition"]
        if disposition == "expired_complete":
            return {"cleaned": True, "eligible": True, "idempotent": True}
        if disposition == "ineligible":
            return {"cleaned": False, "eligible": False}
        if disposition == "published":
            result = self.complete_published_cleanup()
            return {
                "cleaned": result.get("cleanup_pending") is False,
                "eligible": True,
                "published": True,
            }
        if disposition == "shadow":
            result = self.complete_shadow_export()
            return {
                "cleaned": result.get("cleanup_pending") is False,
                "eligible": True,
                "shadow": True,
            }
        if disposition == "publication_claim":
            publication_claim = claimed.value["claim"]
            try:
                result = self.mark_finalized(
                    "committed",
                    attempt_ref=publication_claim["attempt_ref"],
                    claim_revision=publication_claim["checkpoint_revision"],
                    plan_digest=publication_claim["plan_digest"],
                )
            except InvalidTransitionError:
                return {
                    "cleaned": False,
                    "durable": False,
                    "eligible": False,
                    "publication_claimed": True,
                }
            return {
                "cleaned": result.get("cleanup_pending") is False,
                "durable": True,
                "eligible": True,
                "publication_claimed": True,
                "published": True,
            }
        cleanup_claim = claimed.value["claim"]
        try:
            self._delete_claimed_raw_paths(cleanup_claim)
        except (OSError, safe_io.UnsafePathError) as error:
            return {
                "cleaned": False,
                "cleanup_error": type(error).__name__,
                "eligible": True,
            }

        def close(current: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(current)
            publication = current["publication"]
            if (
                publication.get("phase") != "expired_cleanup_claimed"
                or publication.get("expired_cleanup_claim") != cleanup_claim
                or current["stage"] != cleanup_claim["stage"]
            ):
                published = publication.get("phase") in {
                    "complete",
                    "published_cleanup_pending",
                }
                return current, {
                    "cleaned": False,
                    "eligible": False,
                    "published": published,
                    "superseded": True,
                }
            current_deadline = _parse_timestamp(
                current["deadlines"]["raw"], label="raw deadline"
            )
            if (
                current["deadlines"]["raw"] != cleanup_claim["deadline"]
                or _parse_timestamp(self._state._now(), label="clock")
                < current_deadline
            ):
                raise RunConflictError("raw retention deadline changed during cleanup")
            durable_claim = self._validate_raw_cleanup_claim(
                current,
                cleanup_claim,
                disposition="expired_unpublished",
                durable_commit=None,
                phase_before=cleanup_claim["phase_before"],
                publication_claim_ref=None,
            )
            inventory = self._raw_cleanup_inventory(cleanup_claim["raw_path_inventory"])
            if any(
                inventory[key] != 0
                for key in ("byte_count", "directory_count", "file_count")
            ):
                raise RunConflictError(
                    "raw working paths reappeared before expired cleanup commit"
                )
            cleanup = self._raw_cleanup_receipt_value(durable_claim)
            current["jobs"] = {}
            current["extracted_turns"] = {}
            current["episodes"] = []
            current["retained_export"] = None
            current["actions"] = {}
            current["source"].update(
                {
                    "catalog": None,
                    "materialization": None,
                    "model_era_by_unit": {},
                    "model_eras_by_session": {},
                    "reassembly": {},
                    "shards": {},
                }
            )
            for cells in current["source"]["cells"].values():
                for cell in cells.values():
                    cell.pop("accepted_input_digest", None)
                    cell.update(
                        {
                            "lease_ref": None,
                            "manifest": None,
                            "metrics": {"byte_count": 0, "record_count": 0},
                            "payloads": {},
                            "snapshot_ref": None,
                            "status": SourceCellStatus.GAP.value,
                            "transport_receipt": None,
                            "transport_receipt_ref": None,
                            "transport_status": SourceCellStatus.GAP.value,
                        }
                    )
            publication.update(
                {
                    "bundle_digest": None,
                    "cleanup_receipt": cleanup,
                    "durable_state": None,
                    "exported_at": None,
                    "finalized_at": self._state._now(),
                    "phase": "expired_cleanup_complete",
                    "retention_deadline": None,
                }
            )
            self._state._block(current, "raw_retention_expired")
            return current, {"cleaned": True, "eligible": True}

        try:
            return self.store.transaction(
                close,
                expected_revision=claimed.snapshot.revision,
            ).value
        except CheckpointConflictError:
            current = self.store.read().state
            self._state._assert_state_identity(current)
            phase = current["publication"].get("phase")
            return {
                "cleaned": False,
                "eligible": False,
                "published": phase in {"complete", "published_cleanup_pending"},
                "superseded": True,
            }

    def shadow_daily_successor(self) -> dict[str, Any]:
        """Derive the only valid backfill start from a completed shadow partial."""

        state = self._state.load_state()
        publication = state["publication"]
        if (
            state.get("shadow") is not True
            or state.get("mode") != RunMode.DAILY.value
            or state.get("stage") != RunStage.COMPLETE.value
            or publication.get("phase") != "shadow_complete"
            or state.get("partial_policy", {}).get("allow_partial") is not True
            or state.get("lineage", {}).get("backfill_of") is not None
        ):
            raise InvalidTransitionError(
                "shadow successor requires a completed daily partial export"
            )
        cleanup = self._validate_completed_shadow_cleanup(state)
        coverage = self._verified_persisted_shadow_coverage(state)
        holdouts = state.get("controlled_holdouts")
        if (
            not isinstance(holdouts, Mapping)
            or len(holdouts) != 1
            or coverage.get("partial") is not True
            or coverage.get("run_ref") != state["run_ref"]
        ):
            raise InvalidTransitionError(
                "shadow successor requires one authenticated missing-host holdout"
            )
        host, raw_gap = next(iter(holdouts.items()))
        try:
            gap = controlled_gaps.verify_controlled_gap_receipt(
                self.identity,
                raw_gap,
            )
        except (TypeError, ValueError, controlled_gaps.ControlledGapError) as error:
            raise InvalidTransitionError(
                "shadow successor controlled gap is invalid"
            ) from error
        if (
            gap.shadow is not True
            or gap.run_ref != state["run_ref"]
            or gap.host != host
            or gap.window_start != state["window"]["start"]
            or gap.window_end != state["window"]["end"]
            or coverage.get("controlled_gap_receipt_ref") != gap.receipt_ref
        ):
            raise InvalidTransitionError(
                "shadow successor does not match the partial coverage receipt"
            )
        body = {
            "backfill_of": state["run_ref"],
            "cleanup_receipt_ref": cleanup["receipt_ref"],
            "controlled_gap_receipt": gap.to_dict(),
            "coverage_receipt_ref": coverage["receipt_ref"],
            "export_bundle_digest": coverage["export_bundle_digest"],
            "history_repo": state["authority"]["history_repo"],
            "history_target_ref": state["authority"]["history_target_ref"],
            "host": host,
            "partial_checkpoint_revision": coverage["checkpoint_revision"],
            "provenance": copy.deepcopy(state["provenance"]),
            "schema": "shadow_daily_successor_v2",
            "window": copy.deepcopy(state["window"]),
        }
        return {
            **body,
            "authentication_tag": "shadow_daily_successor_auth_v2:"
            + self.identity.derive_digest("shadow-daily-successor-auth-v2", body),
        }

    def _validate_shadow_daily_successor(
        self,
        value: Mapping[str, Any],
        *,
        backfill_of: str,
        controlled_gap_receipt: Mapping[str, Any],
        history_repo: str,
        history_target_ref: str,
        host: str,
        provenance: Mapping[str, Any],
        window: Mapping[str, str],
    ) -> dict[str, Any]:
        fields = {
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
        if not isinstance(value, Mapping) or set(value) != fields:
            raise InvalidInputError("shadow successor authorization is invalid")
        successor = _json_copy(dict(value), label="shadow successor authorization")
        body = {key: successor[key] for key in successor if key != "authentication_tag"}
        expected_tag = "shadow_daily_successor_auth_v2:" + self.identity.derive_digest(
            "shadow-daily-successor-auth-v2",
            body,
        )
        expected_bindings = {
            "backfill_of": backfill_of,
            "controlled_gap_receipt": dict(controlled_gap_receipt),
            "history_repo": history_repo,
            "history_target_ref": history_target_ref,
            "host": host,
            "provenance": dict(provenance),
            "window": dict(window),
        }
        if (
            successor["schema"] != "shadow_daily_successor_v2"
            or any(successor[key] != item for key, item in expected_bindings.items())
            or not isinstance(successor["partial_checkpoint_revision"], int)
            or isinstance(successor["partial_checkpoint_revision"], bool)
            or successor["partial_checkpoint_revision"] < 0
            or not isinstance(successor["export_bundle_digest"], str)
            or _SHA256_RE.fullmatch(successor["export_bundle_digest"]) is None
            or not isinstance(successor["coverage_receipt_ref"], str)
            or not successor["coverage_receipt_ref"].startswith(
                "shadow_coverage_receipt_v2:"
            )
            or not isinstance(successor["cleanup_receipt_ref"], str)
            or not successor["cleanup_receipt_ref"].startswith(
                ("raw_cleanup_receipt_v2:", "raw_cleanup_receipt_v3:")
            )
            or not isinstance(successor["authentication_tag"], str)
            or not hmac.compare_digest(successor["authentication_tag"], expected_tag)
        ):
            raise InvalidInputError("shadow successor authorization is invalid")
        return successor

    def export_retention_deadline(self) -> str:
        state = self._state.load_state()
        existing = state["publication"].get("retention_deadline")
        if existing is not None:
            return _normalize_timestamp(existing, label="export retention deadline")
        now = _parse_timestamp(self._state._now(), label="clock")
        deadline = min(
            _parse_timestamp(state["deadlines"]["raw"], label="raw deadline"),
            _parse_timestamp(state["deadlines"]["working"], label="working deadline"),
            now + dt.timedelta(hours=MAX_EXPORT_RETENTION_HOURS),
        )
        if deadline <= now:
            raise InvalidTransitionError("retention deadline expired")
        return _format_timestamp(deadline)

    def _validate_export_retention_deadline(
        self,
        state: Mapping[str, Any],
        retention_deadline: str,
    ) -> str:
        normalized = _normalize_timestamp(
            retention_deadline,
            label="export retention deadline",
        )
        existing = state["publication"].get("retention_deadline")
        if existing is not None and existing != normalized:
            raise RunConflictError("export retention deadline changed")
        now = _parse_timestamp(self._state._now(), label="clock")
        deadline = _parse_timestamp(normalized, label="export retention deadline")
        maximum = min(
            _parse_timestamp(state["deadlines"]["raw"], label="raw deadline"),
            _parse_timestamp(state["deadlines"]["working"], label="working deadline"),
            now + dt.timedelta(hours=MAX_EXPORT_RETENTION_HOURS),
        )
        if deadline <= now or deadline > maximum:
            raise InvalidInputError("export retention deadline is outside policy")
        return normalized

    def validate_export_retention_deadline(self, retention_deadline: str) -> str:
        """Validate a proposed deadline without mutating export state."""

        state = self._state.load_state()
        self._state._assert_state_identity(state)
        self._state._require_stage(state, RunStage.EXPORT)
        if self._state._retention_expired(state):
            raise InvalidTransitionError("retention deadline expired")
        return self._validate_export_retention_deadline(state, retention_deadline)

    def publication_host_cursor_vector(self) -> dict[str, dict[str, Any]]:
        state = self._state.load_state()
        self._state._require_stage(state, RunStage.EXPORT)
        vector: dict[str, dict[str, Any]] = {}
        for host, cursor in sorted(state["cursors"].items()):
            if cursor["publication_state"] == "not_applicable":
                continue
            expected_cursor, expected_backlog, _expected_boundary = (
                self._projection._cursor_before(cursor["before"])
            )
            if cursor["publication_state"] == "complete":
                proposed = cursor.get("proposed")
                if not isinstance(proposed, Mapping) or not isinstance(
                    proposed.get("source_snapshot_ref"), str
                ):
                    raise InvalidTransitionError(
                        "complete host cursor lacks a source snapshot"
                    )
                update = finalize.HostCursorUpdate(
                    expected_cursor=expected_cursor,
                    proposed_cursor=proposed["source_snapshot_ref"],
                    coverage_complete=True,
                    expected_backlog_head=expected_backlog,
                    proposed_backlog_head=None,
                )
            elif cursor["publication_state"] == "backfill_required":
                backlog_ref = self._ref(
                    RefType.RUN_INPUT,
                    state["run_ref"],
                    state["host_refs"][host],
                    "publication_backlog",
                )
                update = finalize.HostCursorUpdate(
                    expected_cursor=expected_cursor,
                    proposed_cursor=expected_cursor,
                    coverage_complete=False,
                    expected_backlog_head=expected_backlog,
                    proposed_backlog_head=backlog_ref,
                )
            else:
                raise InvalidTransitionError("host cursor is not publication-ready")
            vector[state["host_refs"][host]] = update.to_dict()
        return vector

    def publication_durable_state(self) -> dict[str, Any]:
        state = self._state.load_state()
        self._state._require_stage(state, RunStage.EXPORT)
        return self._history._publication_durable_state(state)

    def publication_episode_head_update(
        self,
        provider_episode_heads_state: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        state = self._state.load_state()
        self._state._require_stage(state, RunStage.EXPORT)
        try:
            expected_history = authority.history_state_from_projection(
                state["authority"]["history_snapshot"],
                identity=self.identity,
            )
        except authority.AuthorityError as error:
            raise InvalidTransitionError(
                "persisted durable history is invalid"
            ) from error
        current_ref = expected_history.episode_head_root_ref
        current_heads = [copy.deepcopy(item) for item in expected_history.episode_heads]
        if provider_episode_heads_state is not None:
            supplied_projection = {
                "episode_head_root_ref": provider_episode_heads_state.get(
                    "episode_head_set_ref"
                ),
                "episode_heads": provider_episode_heads_state.get("episode_heads"),
                "provider_revision": provider_episode_heads_state.get("revision"),
            }
            expected_projection = {
                "episode_head_root_ref": current_ref,
                "episode_heads": current_heads,
                "provider_revision": expected_history.provider_revision,
            }
            if canonical_json_bytes(supplied_projection) != canonical_json_bytes(
                expected_projection
            ):
                raise RunConflictError(
                    "caller provider heads differ from durable history"
                )

        lineage_receipt: dict[str, Any] | None = None
        proposed_heads = self._history._episode_head_projection(
            state,
            current_heads,
        )
        proposed_ref = authority.derive_episode_head_root(
            proposed_heads,
            identity=self.identity,
        )

        if state["lineage"]["backfill_of"] is not None:
            if current_ref != state["lineage"]["expected_episode_head_set_ref"]:
                raise RunConflictError("backfill episode head-set CAS is stale")
            raw_lineage = state["lineage"].get("backfill_lineage_receipt")
            raw_gap = state["lineage"].get("controlled_gap_receipt")
            if (
                not isinstance(proposed_ref, str)
                or not isinstance(raw_lineage, Mapping)
                or not isinstance(raw_gap, Mapping)
            ):
                raise InvalidTransitionError(
                    "backfill lacks its authenticated controlled-gap lineage"
                )
            try:
                verified = controlled_gaps.verify_backfill_lineage_receipt(
                    self.identity,
                    raw_lineage,
                )
                expected = controlled_gaps.issue_backfill_lineage_receipt(
                    self.identity,
                    controlled_gap_receipt=raw_gap,
                    expected_episode_head_set_ref=current_ref,
                    proposed_episode_head_set_ref=proposed_ref,
                    prior_episode_heads=current_heads,
                    proposed_episode_heads=proposed_heads,
                    expected_backlog_ref=state["lineage"].get("expected_backlog_ref"),
                )
            except controlled_gaps.ControlledGapError as error:
                raise InvalidTransitionError(
                    "backfill lineage authentication failed"
                ) from error
            if verified.to_dict() != expected.to_dict():
                raise RunConflictError(
                    "backfill lineage does not bind the provider head set"
                )
            lineage_receipt = verified.to_dict()
        return {
            "backfill_lineage_receipt": lineage_receipt,
            "expected_episode_head_set_ref": current_ref,
            "proposed_episode_head_set_ref": proposed_ref,
            "proposed_episode_heads": proposed_heads,
            "schema": finalize.EPISODE_HEAD_UPDATE_SCHEMA,
        }

    def _validated_shadow_sources(
        self,
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        cells_by_host = state.get("source", {}).get("cells")
        host_refs = state.get("host_refs")
        cursors = state.get("cursors")
        if (
            not isinstance(cells_by_host, Mapping)
            or not isinstance(host_refs, Mapping)
            or not isinstance(cursors, Mapping)
            or set(cells_by_host) != set(host_refs)
            or set(cells_by_host) != set(cursors)
            or not cells_by_host
        ):
            raise InvalidTransitionError("shadow source host matrix is invalid")

        snapshots: list[str] = []
        source_receipts: list[str] = []
        covered_host_refs: list[str] = []
        gap_host_refs: list[str] = []
        accepted_leases: set[str] = set()
        terminal_cells = 0
        for host, cells in sorted(cells_by_host.items()):
            host_ref = host_refs.get(host)
            if (
                not isinstance(host, str)
                or host_ref != self._ref(RefType.HOST, host)
                or not isinstance(cells, Mapping)
                or set(cells) != set(REQUIRED_SOURCE_KINDS)
            ):
                raise InvalidTransitionError("shadow source host binding is invalid")
            statuses: list[str] = []
            for source_kind, cell in sorted(cells.items()):
                if not isinstance(cell, Mapping):
                    raise InvalidTransitionError("shadow source cell is invalid")
                raw_segments = cell.get("continuation_segments")
                if (
                    not isinstance(raw_segments, Sequence)
                    or isinstance(raw_segments, (str, bytes))
                    or not raw_segments
                ):
                    raise InvalidTransitionError(
                        "shadow source cell lacks authenticated transport evidence"
                    )
                try:
                    materialized_segments = source_inputs.materialize_segments(
                        self.run_dir,
                        raw_segments,
                    )
                    aggregate, aggregate_snapshot_ref, aggregate_receipt_ref = (
                        self._source._aggregate_source_segments(raw_segments)
                    )
                except (
                    KeyError,
                    TypeError,
                    ValueError,
                    catalog.CatalogValidationError,
                    source_transport.TransportValidationError,
                ) as error:
                    raise InvalidTransitionError(
                        "shadow source transport evidence is invalid"
                    ) from error
                final_receipt: source_transport.TransportReceipt | None = None
                final_lease_ref: str | None = None
                for segment in materialized_segments["segments"]:
                    if not isinstance(segment, Mapping):
                        raise InvalidTransitionError(
                            "shadow source continuation segment is invalid"
                        )
                    lease_ref = segment.get("lease_ref")
                    if not isinstance(lease_ref, str) or lease_ref in accepted_leases:
                        raise InvalidTransitionError(
                            "shadow source continuation lease is invalid"
                        )
                    try:
                        manifest = catalog.SourceTransportManifest.from_dict(
                            segment["manifest"]
                        )
                        receipt = source_transport.TransportReceipt.from_dict(
                            segment["receipt"]
                        )
                        supplied_snapshot = (
                            source_transport.AuthoritativeSourceSnapshot.from_dict(
                                segment["source_snapshot"]
                            )
                        )
                        job = self._source._source_job_for_lease(state, lease_ref)
                        lease = source_transport.TransportLease.from_dict(
                            job["transport_lease"]
                        )
                        snapshot = source_transport.verify_transport_receipt(
                            self.identity,
                            lease=lease,
                            manifest=manifest.to_dict(),
                            receipt=receipt,
                        )
                        self._source._validate_authoritative_source_snapshot(
                            manifest,
                            snapshot,
                        )
                    except (
                        KeyError,
                        TypeError,
                        ValueError,
                        catalog.CatalogValidationError,
                        source_transport.TransportValidationError,
                    ) as error:
                        raise InvalidTransitionError(
                            "shadow source continuation evidence is invalid"
                        ) from error
                    if (
                        supplied_snapshot != snapshot
                        or segment.get("snapshot_ref") != snapshot.snapshot_ref
                        or segment.get("receipt_ref") != receipt.receipt_ref
                        or job.get("status") != "accepted"
                        or job.get("host") != host
                        or job.get("source_kind") != source_kind
                        or job.get("transport_authorization")
                        != self._source._transport_authorization(
                            lease, manifest, receipt
                        )
                    ):
                        raise InvalidTransitionError(
                            "shadow source continuation binding is invalid"
                        )
                    accepted_leases.add(lease_ref)
                    snapshots.append(snapshot.snapshot_ref)
                    source_receipts.append(receipt.receipt_ref)
                    final_receipt = receipt
                    final_lease_ref = lease_ref
                payloads = source_payloads.merge_payload_indexes(
                    materialized_segments["payloads"], cell.get("payloads", {})
                )
                payload_gap = any(
                    isinstance(item, Mapping) and item.get("status") == "gap"
                    for item in payloads.values()
                )
                expected_status = (
                    SourceCellStatus.GAP.value
                    if payload_gap
                    else aggregate.status.value
                )
                if (
                    final_receipt is None
                    or cell.get("host_ref") != host_ref
                    or cell.get("continuation_position") is not None
                    or cell.get("lease_ref") != final_lease_ref
                    or not source_inputs.manifest_matches_persisted(
                        cell.get("manifest"), aggregate
                    )
                    or cell.get("snapshot_ref") != aggregate_snapshot_ref
                    or cell.get("transport_receipt") != final_receipt.to_dict()
                    or cell.get("transport_receipt_ref") != aggregate_receipt_ref
                    or cell.get("transport_status") != aggregate.status.value
                    or cell.get("metrics")
                    != {
                        "byte_count": aggregate.total_bytes,
                        "record_count": aggregate.total_records,
                    }
                    or cell.get("status") != expected_status
                    or cell.get("status") not in _SOURCE_TERMINAL
                ):
                    raise InvalidTransitionError(
                        "shadow source checkpoint differs from its transport evidence"
                    )
                terminal_cells += 1
                statuses.append(str(cell["status"]))
            if any(status == SourceCellStatus.GAP.value for status in statuses):
                if any(status != SourceCellStatus.GAP.value for status in statuses):
                    raise InvalidTransitionError(
                        "shadow gap classification must cover the complete host"
                    )
                gap_host_refs.append(host_ref)
            elif all(status in _NON_GAP_SOURCE_TERMINAL for status in statuses):
                covered_host_refs.append(host_ref)
            else:
                raise InvalidTransitionError("shadow source host is not terminal")

        source_jobs = {
            job.get("lease_ref")
            for job in state.get("jobs", {}).values()
            if isinstance(job, Mapping) and job.get("category") == "source"
        }
        if (
            accepted_leases != source_jobs
            or len(snapshots) != len(set(snapshots))
            or len(source_receipts) != len(set(source_receipts))
            or state.get("metrics", {}).get("accepted_source_manifests")
            != terminal_cells
        ):
            raise InvalidTransitionError("shadow source inventory is incomplete")

        accounting = state.get("metrics", {}).get("accounting")
        if (
            not isinstance(accounting, Mapping)
            or set(accounting) != {item.value for item in catalog.AccountingClass}
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in accounting.values()
            )
        ):
            raise InvalidTransitionError("shadow source accounting is invalid")
        source_catalog = state.get("source", {}).get("catalog")
        try:
            catalog_counts = catalog.SourceCatalog.from_dict(
                source_catalog
            ).accounting_counts()
        except (TypeError, ValueError, catalog.CatalogValidationError) as error:
            raise InvalidTransitionError("shadow source catalog is invalid") from error
        if dict(accounting) != catalog_counts:
            raise InvalidTransitionError(
                "shadow source accounting differs from the authenticated catalog"
            )
        source_units = {
            "consumed_candidate": accounting["consumed_candidate"],
            "expected": sum(accounting.values()),
            "explicit_gap": accounting["explicit_gap"],
            "structurally_excluded": accounting["structurally_excluded"],
        }
        return {
            "configured_host_refs": sorted(host_refs.values()),
            "covered_host_refs": sorted(covered_host_refs),
            "gap_host_refs": sorted(gap_host_refs),
            "source_receipt_refs": sorted(source_receipts),
            "source_snapshot_refs": sorted(snapshots),
            "source_units": source_units,
        }

    def _shadow_coverage_payload(
        self,
        state: Mapping[str, Any],
        *,
        checkpoint_revision: int,
        staging_dir: Path,
        prior_period: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._state._assert_state_identity(state)
        if state.get("stage") not in {
            RunStage.EXPORT.value,
            RunStage.COMPLETE.value,
        }:
            raise InvalidTransitionError(
                "shadow coverage requires export or completed state"
            )
        if state.get("shadow") is not True:
            raise InvalidTransitionError("shadow coverage requires a shadow run")
        self._assert_no_open_job_leases_or_sinks(state)
        try:
            window_start, window_end = authority._normalize_shadow_window(
                state.get("mode"),
                state.get("window", {}).get("start"),
                state.get("window", {}).get("end"),
            )
        except authority.ProductionMarkerError as error:
            raise InvalidTransitionError("shadow run window is invalid") from error

        provenance = state.get("provenance")
        binding = state.get("authority")
        if not isinstance(provenance, Mapping) or not isinstance(binding, Mapping):
            raise InvalidTransitionError("shadow configuration binding is invalid")
        configuration_root = provenance.get("configuration_root")
        configuration_ref = self._ref(RefType.CONFIGURATION, configuration_root)
        model_era = self._projection._model_era(state)
        policy_era = self._projection._policy_token(state, "policy", "source_policy_v2")
        versions = provenance.get("versions")
        policy = (
            {"policy": versions.get("policy")}
            if isinstance(versions, Mapping)
            else None
        )
        if (
            not isinstance(configuration_root, str)
            or not isinstance(policy, Mapping)
            or not isinstance(versions, Mapping)
            or binding.get("configuration_root") != configuration_root
            or binding.get("configuration_ref") != configuration_ref
            or binding.get("model_era") != model_era
            or binding.get("policy_era") != policy_era
        ):
            raise InvalidTransitionError(
                "shadow configuration changed after the authenticated start"
            )
        policy_commitment = (
            "shadow_policy_commitment_v2:"
            + self.identity.derive_digest(
                "shadow-policy-commitment-v2",
                dict(policy),
            )
        )
        version_commitment = (
            "shadow_version_commitment_v2:"
            + self.identity.derive_digest(
                "shadow-version-commitment-v2",
                dict(versions),
            )
        )

        source = self._validated_shadow_sources(state)
        gap_hosts = source["gap_host_refs"]
        partial = bool(gap_hosts)
        backfill_of = state.get("lineage", {}).get("backfill_of")
        controlled_gap_ref: str | None = None
        if partial:
            if (
                state.get("coverage", {}).get("status") != "partial"
                or state.get("partial_policy", {}).get("decision") != "partial"
                or not self._projection._partial_can_continue(state)
                or len(gap_hosts) != 1
            ):
                raise InvalidTransitionError(
                    "shadow partial coverage lacks controlled gap authority"
                )
            holdouts = state.get("controlled_holdouts")
            if not isinstance(holdouts, Mapping) or len(holdouts) != 1:
                raise InvalidTransitionError(
                    "shadow partial coverage has ambiguous gap authority"
                )
            raw_gap = next(iter(holdouts.values()))
            try:
                gap = controlled_gaps.verify_controlled_gap_receipt(
                    self.identity,
                    raw_gap,
                )
            except (TypeError, controlled_gaps.ControlledGapError) as error:
                raise InvalidTransitionError(
                    "shadow partial controlled gap is invalid"
                ) from error
            if (
                gap.shadow is not True
                or gap.run_ref != state["run_ref"]
                or gap.host_ref != gap_hosts[0]
                or gap.window_start != window_start
                or gap.window_end != window_end
            ):
                raise InvalidTransitionError(
                    "shadow partial controlled gap differs from the run"
                )
            controlled_gap_ref = gap.receipt_ref
        elif backfill_of is not None:
            raw_gap = state.get("lineage", {}).get("controlled_gap_receipt")
            raw_lineage = state.get("lineage", {}).get("backfill_lineage_receipt")
            try:
                gap = controlled_gaps.verify_controlled_gap_receipt(
                    self.identity,
                    raw_gap,
                )
                lineage = controlled_gaps.verify_backfill_lineage_receipt(
                    self.identity,
                    raw_lineage,
                )
            except (TypeError, controlled_gaps.ControlledGapError) as error:
                raise InvalidTransitionError(
                    "shadow backfill lineage is invalid"
                ) from error
            if (
                gap.shadow is not True
                or gap.run_ref != backfill_of
                or lineage.partial_run_ref != backfill_of
                or lineage.controlled_gap_receipt_ref != gap.receipt_ref
                or gap.host_ref not in source["covered_host_refs"]
                or source["configured_host_refs"] != [gap.host_ref]
                or gap.window_start != window_start
                or gap.window_end != window_end
            ):
                raise InvalidTransitionError(
                    "shadow backfill does not reconcile its controlled gap"
                )
            controlled_gap_ref = gap.receipt_ref
        elif (
            state.get("coverage", {}).get("status") != "complete"
            or state.get("partial_policy", {}).get("decision") != "complete"
        ):
            raise InvalidTransitionError(
                "shadow complete coverage is not authoritative"
            )

        try:
            run_state, review_data = self._history.retained_export_inputs(state)
        except InvalidTransitionError as error:
            raise InvalidTransitionError(
                "shadow retained export inputs are invalid"
            ) from error
        if (
            run_state.get("run_ref") != state.get("run_ref")
            or run_state.get("mode") != state.get("mode")
            or run_state.get("window") != state.get("window")
            or run_state.get("production_configuration_ref") != configuration_ref
            or run_state.get("default_model_era") != model_era
            or run_state.get("default_policy_era") != policy_era
            or run_state.get("coverage", {}).get("source_units")
            != source["source_units"]
        ):
            raise InvalidTransitionError(
                "shadow retained export differs from authenticated run state"
            )
        try:
            expected_artifacts = reporting.assemble_retained_artifacts(
                run_state,
                review_data,
                prior_period=prior_period,
            )
            expected = reporting.validate_retained_artifacts(expected_artifacts)
            staged = retained_export_api.validate_staged_export(staging_dir)
        except (
            OSError,
            reporting.RetainedReportingError,
            retained_export_api.RetainedExportError,
        ) as error:
            raise InvalidTransitionError(
                "shadow retained bundle validation failed"
            ) from error
        expected_digest = expected["manifest"]["retained_bundle_digest_v2"]["value"]
        if (
            staged["bundle_digest"] != expected_digest
            or staged["status"] != "exported"
            or staged["staging_dir"] != str(staging_dir)
        ):
            raise InvalidTransitionError(
                "shadow staged bundle differs from reconstructed run output"
            )

        snapshots, source_receipts, source_commitment = (
            authority._shadow_source_evidence(
                self.identity,
                run_ref=state["run_ref"],
                window_start=window_start,
                window_end=window_end,
                configured_host_refs=source["configured_host_refs"],
                covered_host_refs=source["covered_host_refs"],
                gap_host_refs=source["gap_host_refs"],
                source_units=source["source_units"],
                source_snapshot_refs=source["source_snapshot_refs"],
                source_receipt_refs=source["source_receipt_refs"],
            )
        )
        return {
            "backfill_of": backfill_of,
            "checkpoint_revision": checkpoint_revision,
            "configuration_root": configuration_root,
            "controlled_gap_receipt_ref": controlled_gap_ref,
            "configured_host_refs": source["configured_host_refs"],
            "covered_host_refs": source["covered_host_refs"],
            "export_bundle_digest": expected_digest,
            "gap_host_refs": source["gap_host_refs"],
            "mode": state["mode"],
            "model_era": model_era,
            "partial": partial,
            "policy_commitment": policy_commitment,
            "policy_era": policy_era,
            "production_configuration_ref": configuration_ref,
            "run_ref": state["run_ref"],
            "source_evidence_commitment": source_commitment,
            "source_receipt_refs": source_receipts,
            "source_snapshot_refs": snapshots,
            "source_units": source["source_units"],
            "specification_digest": state["specification_digest"],
            "version_commitment": version_commitment,
            "window_end": window_end,
            "window_start": window_start,
            "retention_deadline": staged["retention_deadline"],
        }

    def mark_shadow_exported(
        self,
        staging_dir: str | os.PathLike[str],
        *,
        prior_period: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_prior_period = (
            None
            if prior_period is None
            else _json_copy(dict(prior_period), label="prior retained period")
        )
        locator = Path(
            os.path.realpath(os.path.abspath(os.fspath(Path(staging_dir).expanduser())))
        )
        snapshot = self.store.read()
        existing_coverage = snapshot.state.get("publication", {}).get(
            "coverage_receipt"
        )
        receipt_revision = (
            existing_coverage.get("checkpoint_revision")
            if isinstance(existing_coverage, Mapping)
            else snapshot.revision
        )
        payload = self._shadow_coverage_payload(
            snapshot.state,
            checkpoint_revision=receipt_revision,
            staging_dir=locator,
            prior_period=normalized_prior_period,
        )
        retention_deadline = payload.pop("retention_deadline")
        coverage = self._authenticated_run_receipt(
            schema=authority.SHADOW_COVERAGE_RECEIPT_SCHEMA,
            ref_domain="shadow_coverage_receipt_v2",
            auth_domain="shadow_coverage_auth_v2",
            payload=payload,
        )
        authority.verify_shadow_coverage_receipt(self.identity, coverage)

        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            current_payload = self._shadow_coverage_payload(
                state,
                checkpoint_revision=receipt_revision,
                staging_dir=locator,
                prior_period=normalized_prior_period,
            )
            current_payload.pop("retention_deadline")
            current_coverage = self._authenticated_run_receipt(
                schema=authority.SHADOW_COVERAGE_RECEIPT_SCHEMA,
                ref_domain="shadow_coverage_receipt_v2",
                auth_domain="shadow_coverage_auth_v2",
                payload=current_payload,
            )
            if current_coverage != coverage:
                raise RunConflictError("shadow coverage changed during export binding")
            publication = state["publication"]
            existing = publication.get("coverage_receipt")
            if existing is not None:
                if (
                    existing != coverage
                    or publication.get("shadow_staging_dir") != str(locator)
                    or publication.get("prior_period") != normalized_prior_period
                ):
                    raise RunConflictError("shadow export locator or coverage changed")
                return state, {"recorded": False}
            publication.update(
                {
                    "bundle_digest": coverage["export_bundle_digest"],
                    "coverage_receipt": coverage,
                    "durable_state": self._history._publication_durable_state(state),
                    "exported_at": self._state._now(),
                    "phase": "shadow_cleanup_pending",
                    "prior_period": normalized_prior_period,
                    "retention_deadline": retention_deadline,
                    "shadow_staging_dir": str(locator),
                }
            )
            return state, {"recorded": True}

        result = self.store.transaction(mutate, expected_revision=snapshot.revision)
        response = self._projection._status_view(result.snapshot)
        response.update({"action": "mark-shadow-exported", **result.value})
        return response

    def mark_exported(
        self,
        bundle_digest: str,
        retention_deadline: str | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(bundle_digest, str)
            or _SHA256_RE.fullmatch(bundle_digest) is None
        ):
            raise InvalidInputError("bundle_digest must be a lowercase SHA-256 digest")
        deadline_value = retention_deadline or self.export_retention_deadline()

        def mutate(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            self._state._require_stage(state, RunStage.EXPORT)
            if state.get("shadow") is True:
                raise InvalidTransitionError(
                    "shadow export requires an authenticated staging locator"
                )
            if self._state._retention_expired(state):
                raise InvalidTransitionError("retention deadline expired")
            publication = state["publication"]
            existing = publication.get("bundle_digest")
            if existing is not None and existing != bundle_digest:
                raise RunConflictError("export bundle digest changed")
            normalized_deadline = self._validate_export_retention_deadline(
                state,
                deadline_value,
            )
            if existing is None:
                publication.pop("expired_cleanup_claim", None)
                publication.update(
                    {
                        "bundle_digest": bundle_digest,
                        "durable_state": self._history._publication_durable_state(
                            state
                        ),
                        "exported_at": self._state._now(),
                        "phase": (
                            "shadow_cleanup_pending"
                            if state.get("shadow") is True
                            else publication["phase"]
                        ),
                        "retention_deadline": normalized_deadline,
                    }
                )
            return state, {"recorded": existing is None}

        result = self.store.transaction(mutate)
        response = self._projection._status_view(result.snapshot)
        response.update({"action": "mark-exported", **result.value})
        return response

    def _publication_claim_value(
        self,
        state: Mapping[str, Any],
        *,
        attempt_ref: str,
        checkpoint_revision: int,
        plan_digest: str,
    ) -> dict[str, Any]:
        publication = state["publication"]
        durable_state = publication.get("durable_state")
        if not isinstance(durable_state, Mapping):
            raise InvalidTransitionError(
                "publication claim requires the retained durable candidate"
            )
        history_snapshot = state["authority"].get("history_snapshot")
        if not isinstance(history_snapshot, Mapping) or not isinstance(
            history_snapshot.get("history_commit"), str
        ):
            raise InvalidTransitionError(
                "publication claim requires the durable history base"
            )
        return self._authenticated_run_receipt(
            schema="publication_claim_v2",
            ref_domain="publication_claim_v2",
            auth_domain="publication_claim_auth_v2",
            payload={
                "attempt_ref": attempt_ref,
                "bundle_digest": publication.get("bundle_digest"),
                "checkpoint_revision": checkpoint_revision,
                "durable_state_digest": self.identity.derive_digest(
                    "publication-claim-durable-state/v2",
                    copy.deepcopy(dict(durable_state)),
                ),
                "expected_history_commit": history_snapshot["history_commit"],
                "history_target_ref": state["authority"]["history_target_ref"],
                "plan_digest": plan_digest,
                "run_ref": state["run_ref"],
            },
        )

    def _validate_publication_claim(
        self,
        state: Mapping[str, Any],
        claim: object,
    ) -> dict[str, Any]:
        if not isinstance(claim, Mapping):
            raise RunConflictError("publication claim is malformed")
        attempt_ref = claim.get("attempt_ref")
        checkpoint_revision = claim.get("checkpoint_revision")
        plan_digest = claim.get("plan_digest")
        if (
            not isinstance(attempt_ref, str)
            or _PUBLICATION_ATTEMPT_RE.fullmatch(attempt_ref) is None
            or not isinstance(checkpoint_revision, int)
            or isinstance(checkpoint_revision, bool)
            or checkpoint_revision < 1
            or not isinstance(plan_digest, str)
            or _SHA256_RE.fullmatch(plan_digest) is None
        ):
            raise RunConflictError("publication claim identity is invalid")
        expected = self._publication_claim_value(
            state,
            attempt_ref=attempt_ref,
            checkpoint_revision=checkpoint_revision,
            plan_digest=plan_digest,
        )
        if not hmac.compare_digest(
            canonical_json_bytes(dict(claim)),
            canonical_json_bytes(expected),
        ):
            raise RunConflictError("publication claim authentication failed")
        return expected

    def claim_publication(
        self,
        attempt_ref: str,
        plan_digest: str,
    ) -> dict[str, Any]:
        if (
            not isinstance(attempt_ref, str)
            or _PUBLICATION_ATTEMPT_RE.fullmatch(attempt_ref) is None
        ):
            raise InvalidInputError("publication attempt_ref is invalid")
        if (
            not isinstance(plan_digest, str)
            or _SHA256_RE.fullmatch(plan_digest) is None
        ):
            raise InvalidInputError("publication plan_digest is invalid")

        while True:
            snapshot = self.store.read()
            claim_revision = snapshot.revision + 1

            def mutate(
                state: dict[str, Any],
            ) -> tuple[dict[str, Any], dict[str, Any]]:
                self._state._assert_state_identity(state)
                if state.get("shadow") is True:
                    raise InvalidTransitionError("shadow runs cannot claim publication")
                if state["stage"] not in {
                    RunStage.EXPORT.value,
                    RunStage.FINALIZE.value,
                    RunStage.COMPLETE.value,
                }:
                    raise InvalidTransitionError("run is not in publication")
                publication = state["publication"]
                existing = publication.get("publication_claim")
                if existing is not None:
                    verified = self._validate_publication_claim(state, existing)
                    if (
                        verified["attempt_ref"] != attempt_ref
                        or verified["plan_digest"] != plan_digest
                    ):
                        raise RunConflictError(
                            "run is already claimed by another publication attempt"
                        )
                    return state, {
                        "checkpoint_revision": verified["checkpoint_revision"],
                        "claimed": False,
                        "idempotent": True,
                    }
                if publication.get("phase") in {
                    "expired_cleanup_pending",
                    "expired_cleanup_claimed",
                }:
                    raise InvalidTransitionError(
                        "expired raw cleanup already owns the run"
                    )
                if state["stage"] == RunStage.COMPLETE.value:
                    raise InvalidTransitionError(
                        "completed run cannot start publication"
                    )
                if self._state._retention_expired(state):
                    raise InvalidTransitionError("retention deadline expired")
                publication["publication_claim"] = self._publication_claim_value(
                    state,
                    attempt_ref=attempt_ref,
                    checkpoint_revision=claim_revision,
                    plan_digest=plan_digest,
                )
                return state, {
                    "checkpoint_revision": claim_revision,
                    "claimed": True,
                    "idempotent": False,
                }

            try:
                result = self.store.transaction(
                    mutate,
                    expected_revision=snapshot.revision,
                )
                break
            except CheckpointConflictError:
                continue
        response = self._projection._status_view(result.snapshot)
        response.update({"action": "claim-publication", **result.value})
        return response

    def mark_finalized(
        self,
        phase: str,
        *,
        attempt_ref: str | None = None,
        claim_revision: int | None = None,
        plan_digest: str | None = None,
    ) -> dict[str, Any]:
        if phase not in {
            "prepared",
            "staged",
            "sealed",
            "compliance_closed",
            "promoted",
            "committed",
            "aborted",
        }:
            raise InvalidInputError("publication phase is not closed")
        while True:
            snapshot = self.store.read()
            state = snapshot.state
            self._state._assert_state_identity(state)
            publication_claim = state["publication"].get("publication_claim")
            if publication_claim is not None:
                verified_claim = self._validate_publication_claim(
                    state, publication_claim
                )
                if (
                    attempt_ref != verified_claim["attempt_ref"]
                    or claim_revision != verified_claim["checkpoint_revision"]
                    or plan_digest != verified_claim["plan_digest"]
                ):
                    raise RunConflictError(
                        "finalize acknowledgement does not match publication claim"
                    )
                if phase == "aborted":
                    self._validate_aborted_publication_authority(
                        state,
                        verified_claim,
                    )
            elif any(
                value is not None
                for value in (attempt_ref, claim_revision, plan_digest)
            ):
                raise RunConflictError("finalize acknowledgement has no active claim")
            if phase == "committed" and state["publication"].get("phase") != "complete":
                self._assert_no_open_job_leases_or_sinks(state)
                self._validate_published_authority(state)

            def mutate(
                current: dict[str, Any],
            ) -> tuple[dict[str, Any], dict[str, Any]]:
                self._state._assert_state_identity(current)
                if current["stage"] not in {
                    RunStage.EXPORT.value,
                    RunStage.FINALIZE.value,
                    RunStage.COMPLETE.value,
                }:
                    raise InvalidTransitionError("run is not in publication")
                publication = current["publication"]
                current_claim = publication.get("publication_claim")
                if publication_claim is not None:
                    if current_claim != publication_claim:
                        raise RunConflictError(
                            "publication claim changed during finalize"
                        )
                    self._validate_publication_claim(current, current_claim)
                elif current_claim is not None:
                    raise RunConflictError("publication claim appeared during finalize")
                if (
                    phase not in {"aborted", "committed"}
                    and current_claim is None
                    and self._state._retention_expired(current)
                ):
                    raise InvalidTransitionError("retention deadline expired")
                if phase == "committed" and publication.get("phase") == "complete":
                    return current, {"idempotent": True, "phase": phase}
                publication.pop("expired_cleanup_claim", None)
                if phase == "aborted":
                    publication.pop("publication_claim", None)
                publication["phase"] = (
                    "published_cleanup_pending" if phase == "committed" else phase
                )
                if phase == "committed" and current["stage"] == RunStage.EXPORT.value:
                    self._state._transition(current, RunStage.FINALIZE)
                return current, {"phase": phase}

            try:
                result = self.store.transaction(
                    mutate,
                    expected_revision=snapshot.revision,
                )
                break
            except CheckpointConflictError:
                continue
        if phase != "committed":
            response = self._projection._status_view(result.snapshot)
            response.update({"action": "mark-finalized", **result.value})
            return response
        return self.complete_published_cleanup()

    def _validate_aborted_publication_authority(
        self,
        state: Mapping[str, Any],
        claim: Mapping[str, Any],
    ) -> dict[str, Any]:
        journal = self.run_dir / finalize.PUBLICATION_JOURNAL_NAME
        try:
            transaction = finalize.PublicationTransaction.inspect_local(journal)
            if transaction.get("phase") != finalize.PublicationPhase.ABORTED.value:
                raise RunConflictError(
                    "publication abort journal is not durably complete"
                )
            plan = transaction.get("plan")
            inventory_value = transaction.get("inventory")
            receipts = transaction.get("receipts")
            if (
                not isinstance(plan, Mapping)
                or not isinstance(inventory_value, Mapping)
                or not isinstance(receipts, Mapping)
            ):
                raise RunConflictError(
                    "publication abort journal lacks its durable plan or receipts"
                )
            inventory = finalize.ArtifactInventory.from_dict(inventory_value)
            cleanup = receipts.get("cleanup")
            release = receipts.get("reservation_release")
            abort_commitment = receipts.get("abort_commitment")
            if not all(
                isinstance(value, Mapping)
                for value in (cleanup, release, abort_commitment)
            ):
                raise RunConflictError(
                    "publication abort journal lacks complete cleanup evidence"
                )
            verified_abort = finalize.verify_publication_abort_commitment(
                self.identity,
                abort_commitment,
            )
        except (OSError, ValueError, finalize.PublicationError) as error:
            if isinstance(error, RunConflictError):
                raise
            raise RunConflictError("publication abort authority is invalid") from error

        publication = state["publication"]
        durable_state = publication.get("durable_state")
        publication_authority = plan.get("publication_authority")
        if not isinstance(durable_state, Mapping) or not isinstance(
            publication_authority, Mapping
        ):
            raise RunConflictError(
                "publication abort does not bind the complete durable candidate"
            )
        durable_state_digest = self.identity.derive_digest(
            "publication-claim-durable-state/v2",
            copy.deepcopy(dict(durable_state)),
        )
        if (
            transaction.get("attempt_ref") != claim["attempt_ref"]
            or transaction.get("plan_digest") != claim["plan_digest"]
            or plan.get("attempt_ref") != claim["attempt_ref"]
            or plan.get("expected_target_head") != claim["expected_history_commit"]
            or plan.get("target_ref") != claim["history_target_ref"]
            or plan.get("inventory_digest_v2") != inventory.inventory_digest_v2
            or inventory.retained_bundle_digest_v2 != claim["bundle_digest"]
            or publication.get("bundle_digest") != claim["bundle_digest"]
            or durable_state_digest != claim["durable_state_digest"]
            or publication_authority.get("candidate_digest") != claim["bundle_digest"]
            or canonical_json_bytes(publication_authority.get("proposed_durable_state"))
            != canonical_json_bytes(dict(durable_state))
            or verified_abort["attempt_ref"] != claim["attempt_ref"]
            or verified_abort["plan_digest"] != claim["plan_digest"]
            or verified_abort["inventory_digest"] != inventory.inventory_digest_v2
            or verified_abort["publication_claim_ref"] != claim["receipt_ref"]
            or verified_abort["run_ref"] != state["run_ref"]
            or verified_abort["cleanup_receipt_ref"] != cleanup.get("receipt_ref")
            or verified_abort["reservation_release_receipt_ref"]
            != release.get("receipt_ref")
            or release.get("cleanup_receipt_ref") != cleanup.get("receipt_ref")
            or release.get("cleanup_claim_ref") != cleanup.get("cleanup_claim_ref")
            or release.get("reservations_released") is not True
            or cleanup.get("objects_cleaned") is not True
            or cleanup.get("formal_reachable") is not False
            or cleanup.get("provisional_reachable") is not False
        ):
            raise RunConflictError(
                "publication abort journal does not bind this exact run claim"
            )
        return verified_abort

    def _authenticated_run_receipt(
        self,
        *,
        schema: str,
        ref_domain: str,
        auth_domain: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        body = {
            "identity_key_id": self.identity.key_id,
            **copy.deepcopy(dict(payload)),
            "schema": schema,
        }
        return {
            **body,
            "authentication_tag": auth_domain
            + ":"
            + self.identity.derive_digest(auth_domain, body),
            "receipt_ref": ref_domain
            + ":"
            + self.identity.derive_digest(ref_domain, body),
        }

    @staticmethod
    def _assert_no_open_job_leases_or_sinks(state: Mapping[str, Any]) -> None:
        for job in state["jobs"].values():
            if job.get("status") not in _TASK_TERMINAL:
                raise InvalidTransitionError(
                    "formal completion requires every issued job to be accepted or gapped"
                )
            for attempt in job.get("attempts", []):
                if attempt.get("sink_state") == "open":
                    raise InvalidTransitionError(
                        "formal completion has an open native-agent result sink"
                    )

    def _validate_published_authority(
        self,
        state: Mapping[str, Any],
    ) -> authority.DurableHistoryState:
        binding = state["authority"]
        publication = state["publication"]
        claim = self._validate_publication_claim(
            state,
            publication.get("publication_claim"),
        )
        proposed = publication.get("durable_state")
        if not isinstance(proposed, Mapping):
            raise InvalidTransitionError(
                "published authority lacks the complete retained durable manifest"
            )
        try:
            published = authority.load_durable_history(
                binding["history_repo"],
                binding["history_target_ref"],
                identity=self.identity,
                expected_fingerprint=binding["publisher_fingerprint"],
                gnupg_home=binding["publisher_gnupg_home"],
            )
            if (
                published.publication_commit is None
                or published.head_commit != published.publication_commit
            ):
                raise authority.HistoryValidationError(
                    "durable history head is not this publication commit"
                )
            commitment = authority.load_durable_publication_commitment(
                binding["history_repo"],
                published.head_commit,
                identity=self.identity,
                expected_fingerprint=binding["publisher_fingerprint"],
                gnupg_home=binding["publisher_gnupg_home"],
            )
            authority.load_production_marker(
                binding["production_marker"],
                identity=self.identity,
                history_repo=binding["history_repo"],
                target_ref=binding["history_target_ref"],
                configuration_root=binding["configuration_root"],
                configuration_ref=binding["configuration_ref"],
                model_era=binding["model_era"],
                policy_era=binding["policy_era"],
            )
            authority.assert_provider_cache_matches(
                binding["provider_state"],
                published,
                identity=self.identity,
            )
        except authority.AuthorityError as error:
            raise InvalidTransitionError(
                "published history or derived provider cache is invalid"
            ) from error
        if (
            commitment["attempt_ref"] != claim["attempt_ref"]
            or commitment["plan_digest"] != claim["plan_digest"]
            or commitment["expected_history_commit"] != claim["expected_history_commit"]
            or commitment["history_commit"] != published.head_commit
            or commitment["bundle_digest"] != claim["bundle_digest"]
            or commitment["durable_state_digest"] != claim["durable_state_digest"]
            or canonical_json_bytes(commitment["durable_state"])
            != canonical_json_bytes(dict(proposed))
            or published.provider_revision != proposed["provider_revision_after"]
            or published.cursor_root_ref != proposed["proposed_cursor_root_ref"]
            or published.episode_head_root_ref
            != proposed["proposed_episode_head_root_ref"]
            or canonical_json_bytes(list(published.cursor_rows))
            != canonical_json_bytes(proposed["proposed_cursor_rows"])
            or canonical_json_bytes(list(published.episode_heads))
            != canonical_json_bytes(proposed["proposed_episode_heads"])
            or canonical_json_bytes(list(published.episode_membership))
            != canonical_json_bytes(proposed["proposed_episode_membership"])
        ):
            raise InvalidTransitionError(
                "published history does not match this exact publication attempt"
            )
        return published

    def _raw_cleanup_claim_value(
        self,
        state: Mapping[str, Any],
        *,
        disposition: str,
        durable_commit: str | None,
        phase_before: str,
        publication_claim_ref: str | None,
        inventory: Mapping[str, Any],
        schema: str = "raw_cleanup_claim_v3",
    ) -> dict[str, Any]:
        try:
            ref_prefix, digest_domain, roots, _receipt_schema, _auth_domain = (
                _RAW_CLEANUP_CONTRACTS[schema]
            )
        except KeyError as error:
            raise InvalidTransitionError(
                "raw cleanup claim schema is unsupported"
            ) from error
        body = {
            "bundle_digest": state["publication"].get("bundle_digest"),
            "deadline": state["deadlines"]["raw"],
            "disposition": disposition,
            "durable_commit": durable_commit,
            "phase_before": phase_before,
            "publication_claim_ref": publication_claim_ref,
            "raw_path_inventory": list(roots),
            "removed_byte_count": inventory["byte_count"],
            "removed_directory_count": inventory["directory_count"],
            "removed_file_count": inventory["file_count"],
            "root_counters": copy.deepcopy(inventory["root_counters"]),
            "root_objects": copy.deepcopy(inventory["root_objects"]),
            "run_ref": state["run_ref"],
            "schema": schema,
            "stage": state["stage"],
        }
        return {
            **body,
            "claim_ref": ref_prefix + self.identity.derive_digest(digest_domain, body),
        }

    def _validate_raw_cleanup_claim(
        self,
        state: Mapping[str, Any],
        value: object,
        *,
        disposition: str,
        durable_commit: str | None,
        phase_before: str,
        publication_claim_ref: str | None,
    ) -> dict[str, Any]:
        fields = {
            "bundle_digest",
            "claim_ref",
            "deadline",
            "disposition",
            "durable_commit",
            "phase_before",
            "publication_claim_ref",
            "raw_path_inventory",
            "removed_byte_count",
            "removed_directory_count",
            "removed_file_count",
            "root_counters",
            "root_objects",
            "run_ref",
            "schema",
            "stage",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise InvalidTransitionError("raw cleanup claim has an invalid shape")
        claim = copy.deepcopy(dict(value))
        contract = _RAW_CLEANUP_CONTRACTS.get(str(claim.get("schema")))
        if contract is None:
            raise InvalidTransitionError("raw cleanup claim schema is unsupported")
        inventory = self._validated_cleanup_inventory(
            claim,
            label="raw",
            roots=contract[2],
        )
        expected = self._raw_cleanup_claim_value(
            state,
            disposition=disposition,
            durable_commit=durable_commit,
            phase_before=phase_before,
            publication_claim_ref=publication_claim_ref,
            inventory=inventory,
            schema=str(claim["schema"]),
        )
        if claim != expected:
            raise InvalidTransitionError("raw cleanup claim authentication failed")
        return claim

    def _raw_cleanup_receipt_value(
        self,
        claim: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            _ref_prefix, _digest_domain, roots, schema, auth_domain = (
                _RAW_CLEANUP_CONTRACTS[str(claim["schema"])]
            )
        except KeyError as error:
            raise InvalidTransitionError(
                "raw cleanup claim schema is unsupported"
            ) from error
        return self._authenticated_run_receipt(
            schema=schema,
            ref_domain=schema,
            auth_domain=auth_domain,
            payload={
                "bundle_digest": claim["bundle_digest"],
                "cleanup_claim_ref": claim["claim_ref"],
                "cleanup_complete": True,
                "disposition": claim["disposition"],
                "durable_commit": claim["durable_commit"],
                "raw_path_inventory": list(roots),
                "removed_byte_count": claim["removed_byte_count"],
                "removed_directory_count": claim["removed_directory_count"],
                "removed_file_count": claim["removed_file_count"],
                "run_ref": claim["run_ref"],
                "working_paths_absent": True,
            },
        )

    def _validated_cleanup_inventory(
        self,
        claim: Mapping[str, Any],
        *,
        label: str,
        roots: Sequence[str],
    ) -> dict[str, Any]:
        counters = claim.get("root_counters")
        objects = claim.get("root_objects")
        totals = {"byte_count": 0, "directory_count": 0, "file_count": 0}
        if (
            claim.get("raw_path_inventory") != list(roots)
            or not isinstance(counters, Mapping)
            or set(counters) != set(roots)
            or not isinstance(objects, Mapping)
            or set(objects) != set(roots)
        ):
            raise InvalidTransitionError(f"{label} cleanup inventory is invalid")
        for name in roots:
            counts = counters[name]
            root_object = objects[name]
            if (
                not isinstance(counts, Mapping)
                or set(counts) != set(totals)
                or any(
                    not isinstance(item, int) or isinstance(item, bool) or item < 0
                    for item in counts.values()
                )
                or (
                    root_object is not None
                    and (
                        not isinstance(root_object, Mapping)
                        or set(root_object) != {"device", "inode"}
                        or any(
                            not isinstance(item, int)
                            or isinstance(item, bool)
                            or item < 0
                            for item in root_object.values()
                        )
                    )
                )
            ):
                raise InvalidTransitionError(f"{label} cleanup inventory is invalid")
            for key, item in counts.items():
                totals[key] += item
        if any(claim.get(f"removed_{key}") != value for key, value in totals.items()):
            raise InvalidTransitionError(f"{label} cleanup totals are invalid")
        return {
            "root_counters": copy.deepcopy(dict(counters)),
            "root_objects": copy.deepcopy(dict(objects)),
            **totals,
        }

    def _validate_completed_raw_cleanup(
        self,
        state: Mapping[str, Any],
        *,
        disposition: str = "published",
    ) -> dict[str, Any]:
        self._state._assert_state_identity(state)
        publication = state["publication"]
        claim_name = (
            "raw_cleanup_claim"
            if disposition == "published"
            else "expired_cleanup_claim"
        )
        value = publication.get(claim_name)
        if not isinstance(value, Mapping):
            raise InvalidTransitionError("completed raw cleanup claim is missing")
        claim = copy.deepcopy(dict(value))
        if set(claim) != {
            "bundle_digest",
            "claim_ref",
            "deadline",
            "disposition",
            "durable_commit",
            "phase_before",
            "publication_claim_ref",
            "raw_path_inventory",
            "removed_byte_count",
            "removed_directory_count",
            "removed_file_count",
            "root_counters",
            "root_objects",
            "run_ref",
            "schema",
            "stage",
        }:
            raise InvalidTransitionError(
                "completed raw cleanup claim has an invalid shape"
            )
        contract = _RAW_CLEANUP_CONTRACTS.get(str(claim.get("schema")))
        if contract is None:
            raise InvalidTransitionError("completed raw cleanup schema is unsupported")
        ref_prefix, digest_domain, roots, _receipt_schema, _auth_domain = contract
        self._validated_cleanup_inventory(
            claim,
            label="completed raw",
            roots=roots,
        )
        unsigned = dict(claim)
        claim_ref = unsigned.pop("claim_ref", None)
        expected_ref = ref_prefix + self.identity.derive_digest(
            digest_domain,
            unsigned,
        )
        if claim_ref != expected_ref:
            raise InvalidTransitionError(
                "completed raw cleanup claim authentication failed"
            )
        if (
            claim.get("run_ref") != state["run_ref"]
            or claim.get("deadline") != state["deadlines"]["raw"]
            or claim.get("disposition") != disposition
            or claim.get("raw_path_inventory") != list(roots)
        ):
            raise InvalidTransitionError("completed raw cleanup claim is invalid")
        if disposition == "published":
            if (
                claim.get("bundle_digest") != publication.get("bundle_digest")
                or claim.get("phase_before") != "published_cleanup_pending"
                or claim.get("stage") != RunStage.FINALIZE.value
                or not isinstance(claim.get("durable_commit"), str)
                or not isinstance(claim.get("publication_claim_ref"), str)
            ):
                raise InvalidTransitionError(
                    "published cleanup claim lost publication authority"
                )
        elif (
            claim.get("durable_commit") is not None
            or claim.get("publication_claim_ref") is not None
            or claim.get("phase_before")
            in {
                "expired_cleanup_claimed",
                "expired_cleanup_complete",
                "published_cleanup_claimed",
                "published_cleanup_pending",
            }
        ):
            raise InvalidTransitionError("expired cleanup claim is invalid")
        cleanup = publication.get("cleanup_receipt")
        expected_cleanup = self._raw_cleanup_receipt_value(claim)
        if not isinstance(cleanup, Mapping) or dict(cleanup) != expected_cleanup:
            raise InvalidTransitionError(
                "raw cleanup receipt differs from its durable claim"
            )
        inventory = self._raw_cleanup_inventory(roots)
        if any(
            inventory[key] != 0
            for key in ("byte_count", "directory_count", "file_count")
        ):
            raise InvalidTransitionError("completed raw cleanup paths reappeared")
        return expected_cleanup

    def _raw_cleanup_inventory(
        self,
        roots: Sequence[str] = SHADOW_CLEANUP_ROOTS,
    ) -> dict[str, Any]:
        normalized, run_fd = safe_io.open_owner_only_directory(self.run_dir)
        root_counters: dict[str, dict[str, int]] = {}
        root_objects: dict[str, dict[str, int] | None] = {}
        totals = {"byte_count": 0, "directory_count": 0, "file_count": 0}
        try:
            for name in roots:
                counts = safe_io.inspect_tree_at(
                    run_fd,
                    name,
                    display_path=normalized / name,
                )
                root_counters[name] = counts
                try:
                    metadata = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
                except FileNotFoundError:
                    root_objects[name] = None
                else:
                    root_objects[name] = {
                        "device": metadata.st_dev,
                        "inode": metadata.st_ino,
                    }
                for key, value in counts.items():
                    totals[key] += value
            return {
                "root_counters": root_counters,
                "root_objects": root_objects,
                **totals,
            }
        finally:
            os.close(run_fd)

    def _validated_shadow_coverage(
        self,
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        publication = state.get("publication")
        if not isinstance(publication, Mapping):
            raise InvalidTransitionError("shadow publication state is invalid")
        raw_coverage = publication.get("coverage_receipt")
        staging_dir = publication.get("shadow_staging_dir")
        if not isinstance(raw_coverage, Mapping) or not isinstance(staging_dir, str):
            raise InvalidTransitionError(
                "shadow export lacks its authenticated coverage locator"
            )
        try:
            verified = authority.verify_shadow_coverage_receipt(
                self.identity,
                raw_coverage,
            )
        except authority.ProductionMarkerError as error:
            raise InvalidTransitionError(
                "shadow coverage receipt is invalid"
            ) from error
        payload = self._shadow_coverage_payload(
            state,
            checkpoint_revision=verified["checkpoint_revision"],
            staging_dir=Path(staging_dir),
            prior_period=publication.get("prior_period"),
        )
        retention_deadline = payload.pop("retention_deadline")
        expected = self._authenticated_run_receipt(
            schema=authority.SHADOW_COVERAGE_RECEIPT_SCHEMA,
            ref_domain="shadow_coverage_receipt_v2",
            auth_domain="shadow_coverage_auth_v2",
            payload=payload,
        )
        if (
            verified != expected
            or publication.get("bundle_digest") != verified["export_bundle_digest"]
            or publication.get("retention_deadline") != retention_deadline
        ):
            raise InvalidTransitionError(
                "shadow coverage differs from its checkpoint and staged export"
            )
        return verified

    def _verified_persisted_shadow_coverage(
        self,
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        publication = state.get("publication")
        if not isinstance(publication, Mapping):
            raise InvalidTransitionError("shadow publication state is invalid")
        raw_coverage = publication.get("coverage_receipt")
        if not isinstance(raw_coverage, Mapping):
            raise InvalidTransitionError("shadow coverage receipt is missing")
        try:
            verified = authority.verify_shadow_coverage_receipt(
                self.identity,
                raw_coverage,
            )
            window_start, window_end = authority._normalize_shadow_window(
                state.get("mode"),
                state.get("window", {}).get("start"),
                state.get("window", {}).get("end"),
            )
        except authority.ProductionMarkerError as error:
            raise InvalidTransitionError(
                "shadow coverage receipt is invalid"
            ) from error
        provenance = state.get("provenance")
        binding = state.get("authority")
        if not isinstance(provenance, Mapping) or not isinstance(binding, Mapping):
            raise InvalidTransitionError("shadow configuration binding is invalid")
        configuration_root = provenance.get("configuration_root")
        configuration_ref = self._ref(RefType.CONFIGURATION, configuration_root)
        model_era = self._projection._model_era(state)
        policy_era = self._projection._policy_token(
            state,
            "policy",
            "source_policy_v2",
        )
        if (
            verified["run_ref"] != state.get("run_ref")
            or verified["mode"] != state.get("mode")
            or verified["window_start"] != window_start
            or verified["window_end"] != window_end
            or verified["specification_digest"] != state.get("specification_digest")
            or verified["configuration_root"] != configuration_root
            or verified["production_configuration_ref"] != configuration_ref
            or verified["model_era"] != model_era
            or verified["policy_era"] != policy_era
            or binding.get("configuration_root") != configuration_root
            or binding.get("configuration_ref") != configuration_ref
            or publication.get("bundle_digest") != verified["export_bundle_digest"]
        ):
            raise InvalidTransitionError(
                "shadow coverage receipt differs from durable run state"
            )
        return verified

    def _shadow_cleanup_claim_value(
        self,
        state: Mapping[str, Any],
        coverage: Mapping[str, Any],
        inventory: Mapping[str, Any],
        schema: str = "shadow_cleanup_claim_v3",
    ) -> dict[str, Any]:
        try:
            ref_prefix, digest_domain, roots, _receipt_schema, _auth_domain = (
                _SHADOW_CLEANUP_CONTRACTS[schema]
            )
        except KeyError as error:
            raise InvalidTransitionError(
                "shadow cleanup claim schema is unsupported"
            ) from error
        body = {
            "coverage_receipt_ref": coverage["receipt_ref"],
            "export_bundle_digest": coverage["export_bundle_digest"],
            "raw_path_inventory": list(roots),
            "removed_byte_count": inventory["byte_count"],
            "removed_directory_count": inventory["directory_count"],
            "removed_file_count": inventory["file_count"],
            "root_counters": copy.deepcopy(inventory["root_counters"]),
            "root_objects": copy.deepcopy(inventory["root_objects"]),
            "run_ref": state["run_ref"],
            "schema": schema,
        }
        return {
            **body,
            "claim_ref": ref_prefix + self.identity.derive_digest(digest_domain, body),
        }

    def _validate_shadow_cleanup_claim(
        self,
        state: Mapping[str, Any],
        coverage: Mapping[str, Any],
        value: object,
    ) -> dict[str, Any]:
        fields = {
            "claim_ref",
            "coverage_receipt_ref",
            "export_bundle_digest",
            "raw_path_inventory",
            "removed_byte_count",
            "removed_directory_count",
            "removed_file_count",
            "root_counters",
            "root_objects",
            "run_ref",
            "schema",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise InvalidTransitionError("shadow cleanup claim has an invalid shape")
        claim = copy.deepcopy(dict(value))
        contract = _SHADOW_CLEANUP_CONTRACTS.get(str(claim.get("schema")))
        if contract is None:
            raise InvalidTransitionError("shadow cleanup claim schema is unsupported")
        roots = contract[2]
        counters = claim["root_counters"]
        objects = claim["root_objects"]
        if (
            claim["run_ref"] != state["run_ref"]
            or claim["coverage_receipt_ref"] != coverage["receipt_ref"]
            or claim["export_bundle_digest"] != coverage["export_bundle_digest"]
            or claim["raw_path_inventory"] != list(roots)
            or not isinstance(counters, Mapping)
            or set(counters) != set(roots)
            or not isinstance(objects, Mapping)
            or set(objects) != set(roots)
        ):
            raise InvalidTransitionError("shadow cleanup claim is invalid")
        totals = {"byte_count": 0, "directory_count": 0, "file_count": 0}
        for name in roots:
            counts = counters[name]
            root_object = objects[name]
            if (
                not isinstance(counts, Mapping)
                or set(counts) != set(totals)
                or any(
                    not isinstance(item, int) or isinstance(item, bool) or item < 0
                    for item in counts.values()
                )
                or (
                    root_object is not None
                    and (
                        not isinstance(root_object, Mapping)
                        or set(root_object) != {"device", "inode"}
                        or any(
                            not isinstance(item, int)
                            or isinstance(item, bool)
                            or item < 0
                            for item in root_object.values()
                        )
                    )
                )
            ):
                raise InvalidTransitionError("shadow cleanup inventory is invalid")
            for key, item in counts.items():
                totals[key] += item
        if any(claim[f"removed_{key}"] != value for key, value in totals.items()):
            raise InvalidTransitionError("shadow cleanup totals are invalid")
        expected = self._shadow_cleanup_claim_value(
            state,
            coverage,
            {
                "byte_count": claim["removed_byte_count"],
                "directory_count": claim["removed_directory_count"],
                "file_count": claim["removed_file_count"],
                "root_counters": claim["root_counters"],
                "root_objects": claim["root_objects"],
            },
            schema=str(claim["schema"]),
        )
        if claim != expected:
            raise InvalidTransitionError("shadow cleanup claim authentication failed")
        return claim

    def _prepare_shadow_cleanup_claim(self) -> dict[str, Any]:
        def prepare(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            publication = state["publication"]
            if publication.get("phase") not in {
                "shadow_cleanup_pending",
                "shadow_cleanup_claimed",
            }:
                raise RunConflictError("shadow cleanup phase changed")
            existing = publication.get("cleanup_claim")
            if existing is not None:
                coverage = self._verified_persisted_shadow_coverage(state)
                claim = self._validate_shadow_cleanup_claim(
                    state,
                    coverage,
                    existing,
                )
                publication["phase"] = "shadow_cleanup_claimed"
                return state, claim
            coverage = self._validated_shadow_coverage(state)
            inventory = self._raw_cleanup_inventory()
            if any(
                inventory["root_objects"][name] is None for name in SHADOW_CLEANUP_ROOTS
            ):
                raise InvalidTransitionError(
                    "shadow cleanup cannot claim pre-removed working roots"
                )
            claim = self._shadow_cleanup_claim_value(state, coverage, inventory)
            publication.update(
                {
                    "cleanup_claim": claim,
                    "phase": "shadow_cleanup_claimed",
                }
            )
            return state, claim

        return self.store.transaction(prepare).value

    def _delete_claimed_raw_paths(self, claim: Mapping[str, Any]) -> None:
        normalized, run_fd = safe_io.open_owner_only_directory(self.run_dir)
        try:
            for name in claim["raw_path_inventory"]:
                planned_object = claim["root_objects"][name]
                try:
                    metadata = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if planned_object is None or (
                    metadata.st_dev,
                    metadata.st_ino,
                ) != (
                    planned_object["device"],
                    planned_object["inode"],
                ):
                    raise safe_io.UnsafePathError(
                        f"raw cleanup root changed after claim: {normalized / name}"
                    )
                current = safe_io.inspect_tree_at(
                    run_fd,
                    name,
                    display_path=normalized / name,
                )
                planned = claim["root_counters"][name]
                if any(current[key] > planned[key] for key in current):
                    raise safe_io.UnsafePathError(
                        f"raw cleanup root grew after claim: {normalized / name}"
                    )
                removed = safe_io.secure_remove_tree_at(
                    run_fd,
                    name,
                    display_path=normalized / name,
                )
                if removed != current:
                    raise safe_io.UnsafePathError(
                        f"raw cleanup count changed during deletion: {normalized / name}"
                    )
            for name in claim["raw_path_inventory"]:
                try:
                    os.stat(name, dir_fd=run_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise safe_io.UnsafePathError(
                    f"raw working path survived cleanup: {normalized / name}"
                )
            os.fsync(run_fd)
        finally:
            os.close(run_fd)

    def _validate_completed_shadow_cleanup(
        self,
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._state._assert_state_identity(state)
        coverage = self._verified_persisted_shadow_coverage(state)
        publication = state["publication"]
        claim = self._validate_shadow_cleanup_claim(
            state,
            coverage,
            publication.get("cleanup_claim"),
        )
        raw_cleanup = publication.get("cleanup_receipt")
        if not isinstance(raw_cleanup, Mapping):
            raise InvalidTransitionError("shadow cleanup receipt is missing")
        try:
            cleanup = authority.verify_shadow_cleanup_receipt(
                self.identity,
                raw_cleanup,
            )
        except authority.ProductionMarkerError as error:
            raise InvalidTransitionError("shadow cleanup receipt is invalid") from error
        if (
            cleanup["cleanup_claim_ref"] != claim["claim_ref"]
            or cleanup["coverage_receipt_ref"] != coverage["receipt_ref"]
            or cleanup["bundle_digest"] != coverage["export_bundle_digest"]
            or cleanup["removed_byte_count"] != claim["removed_byte_count"]
            or cleanup["removed_directory_count"] != claim["removed_directory_count"]
            or cleanup["removed_file_count"] != claim["removed_file_count"]
        ):
            raise InvalidTransitionError(
                "shadow cleanup receipt differs from durable cleanup state"
            )
        inventory = self._raw_cleanup_inventory(claim["raw_path_inventory"])
        if any(
            inventory[key] != 0
            for key in ("byte_count", "directory_count", "file_count")
        ):
            raise InvalidTransitionError("shadow cleanup paths are no longer absent")
        return cleanup

    def _prepare_published_cleanup_claim(
        self,
        *,
        durable_commit: str,
    ) -> dict[str, Any]:
        def prepare(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(state)
            publication = state["publication"]
            if publication.get("phase") not in {
                "published_cleanup_pending",
                "published_cleanup_claimed",
            }:
                raise RunConflictError("published cleanup phase changed")
            publication_claim = self._validate_publication_claim(
                state,
                publication.get("publication_claim"),
            )
            existing = publication.get("raw_cleanup_claim")
            if existing is not None:
                claim = self._validate_raw_cleanup_claim(
                    state,
                    existing,
                    disposition="published",
                    durable_commit=durable_commit,
                    phase_before="published_cleanup_pending",
                    publication_claim_ref=publication_claim["receipt_ref"],
                )
                publication["phase"] = "published_cleanup_claimed"
                return state, claim
            inventory = self._raw_cleanup_inventory()
            claim = self._raw_cleanup_claim_value(
                state,
                disposition="published",
                durable_commit=durable_commit,
                phase_before="published_cleanup_pending",
                publication_claim_ref=publication_claim["receipt_ref"],
                inventory=inventory,
            )
            publication.update(
                {
                    "phase": "published_cleanup_claimed",
                    "raw_cleanup_claim": claim,
                }
            )
            return state, claim

        return self.store.transaction(prepare).value

    def complete_published_cleanup(self) -> dict[str, Any]:
        snapshot = self.store.read()
        state = snapshot.state
        self._state._assert_state_identity(state)
        if state["publication"].get("phase") == "complete":
            snapshot = retained_inputs.clear_legacy_terminal_payload(
                self.store,
                snapshot,
                phase="complete",
                validate_terminal=self._validate_completed_raw_cleanup,
            )
            response = self._projection._status_view(snapshot)
            response.update({"action": "postpublication-cleanup", "idempotent": True})
            return response
        if state["publication"].get("phase") not in {
            "published_cleanup_pending",
            "published_cleanup_claimed",
        }:
            raise InvalidTransitionError("durable publication is not awaiting cleanup")
        self._assert_no_open_job_leases_or_sinks(state)
        published = self._validate_published_authority(state)
        try:
            claim = self._prepare_published_cleanup_claim(
                durable_commit=published.head_commit,
            )
        except (OSError, safe_io.UnsafePathError) as error:
            response = self._projection._status_view(self.store.read())
            response.update(
                {
                    "action": "postpublication-cleanup",
                    "cleanup_error": type(error).__name__,
                    "cleanup_pending": True,
                    "idempotent": False,
                }
            )
            return response
        try:
            self._delete_claimed_raw_paths(claim)
        except (OSError, safe_io.UnsafePathError) as error:
            response = self._projection._status_view(self.store.read())
            response.update(
                {
                    "action": "postpublication-cleanup",
                    "cleanup_error": type(error).__name__,
                    "cleanup_pending": True,
                    "idempotent": False,
                }
            )
            return response

        def close(current: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(current)
            publication = current["publication"]
            if (
                publication.get("phase") != "published_cleanup_claimed"
                or publication.get("raw_cleanup_claim") != claim
            ):
                raise RunConflictError("publication cleanup state changed")
            publication_claim = self._validate_publication_claim(
                current,
                publication.get("publication_claim"),
            )
            durable_claim = self._validate_raw_cleanup_claim(
                current,
                claim,
                disposition="published",
                durable_commit=published.head_commit,
                phase_before="published_cleanup_pending",
                publication_claim_ref=publication_claim["receipt_ref"],
            )
            inventory = self._raw_cleanup_inventory(durable_claim["raw_path_inventory"])
            if any(
                inventory[key] != 0
                for key in ("byte_count", "directory_count", "file_count")
            ):
                raise RunConflictError(
                    "raw working paths reappeared before publication cleanup commit"
                )
            cleanup = self._raw_cleanup_receipt_value(durable_claim)
            publication.pop("expired_cleanup_claim", None)
            publication.pop("publication_claim", None)
            current["retained_export"] = None
            publication.update(
                {
                    "cleanup_receipt": cleanup,
                    "finalized_at": self._state._now(),
                    "phase": "complete",
                }
            )
            self._state._transition(current, RunStage.COMPLETE)
            return current, {"cleanup_pending": False, "idempotent": False}

        result = self.store.transaction(close)
        response = self._projection._status_view(result.snapshot)
        response.update({"action": "postpublication-cleanup", **result.value})
        return response

    def complete_shadow_export(self) -> dict[str, Any]:
        snapshot = self.store.read()
        state = snapshot.state
        self._state._assert_state_identity(state)
        phase = state["publication"].get("phase")
        if phase == "shadow_complete":
            snapshot = retained_inputs.clear_legacy_terminal_payload(
                self.store,
                snapshot,
                phase="shadow_complete",
                validate_terminal=self._validate_completed_shadow_cleanup,
            )
            response = self._projection._status_view(snapshot)
            response.update(
                {
                    "action": "shadow-cleanup",
                    "cleanup_pending": False,
                    "idempotent": True,
                }
            )
            return response
        if (
            state.get("shadow") is not True
            or state["stage"] != RunStage.EXPORT.value
            or state["publication"].get("exported_at") is None
            or phase not in {"shadow_cleanup_pending", "shadow_cleanup_claimed"}
        ):
            raise InvalidTransitionError("shadow export is not awaiting cleanup")
        self._assert_no_open_job_leases_or_sinks(state)
        claim = self._prepare_shadow_cleanup_claim()
        try:
            self._delete_claimed_raw_paths(claim)
        except (OSError, safe_io.UnsafePathError) as error:
            current = self.store.read()
            response = self._projection._status_view(current)
            response.update(
                {
                    "action": "shadow-cleanup",
                    "cleanup_error": type(error).__name__,
                    "cleanup_pending": True,
                    "idempotent": False,
                }
            )
            return response

        def close(current: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            self._state._assert_state_identity(current)
            publication = current["publication"]
            if (
                current.get("shadow") is not True
                or publication.get("phase") != "shadow_cleanup_claimed"
            ):
                raise RunConflictError("run disposition changed during shadow cleanup")
            coverage = self._verified_persisted_shadow_coverage(current)
            durable_claim = self._validate_shadow_cleanup_claim(
                current,
                coverage,
                publication.get("cleanup_claim"),
            )
            inventory = self._raw_cleanup_inventory(durable_claim["raw_path_inventory"])
            if any(
                inventory[key] != 0
                for key in ("byte_count", "directory_count", "file_count")
            ):
                raise RunConflictError(
                    "shadow working paths reappeared before cleanup commit"
                )
            _claim_ref, _claim_domain, roots, receipt_schema, auth_domain = (
                _SHADOW_CLEANUP_CONTRACTS[str(durable_claim["schema"])]
            )
            cleanup = self._authenticated_run_receipt(
                schema=receipt_schema,
                ref_domain=receipt_schema,
                auth_domain=auth_domain,
                payload={
                    "bundle_digest": coverage["export_bundle_digest"],
                    "cleanup_claim_ref": durable_claim["claim_ref"],
                    "cleanup_complete": True,
                    "configuration_root": coverage["configuration_root"],
                    "coverage_receipt_ref": coverage["receipt_ref"],
                    "disposition": "shadow",
                    "durable_commit": None,
                    "model_era": coverage["model_era"],
                    "mode": coverage["mode"],
                    "policy_commitment": coverage["policy_commitment"],
                    "policy_era": coverage["policy_era"],
                    "production_configuration_ref": coverage[
                        "production_configuration_ref"
                    ],
                    "raw_path_inventory": list(roots),
                    "removed_byte_count": durable_claim["removed_byte_count"],
                    "removed_directory_count": durable_claim["removed_directory_count"],
                    "removed_file_count": durable_claim["removed_file_count"],
                    "run_ref": coverage["run_ref"],
                    "source_evidence_commitment": coverage[
                        "source_evidence_commitment"
                    ],
                    "version_commitment": coverage["version_commitment"],
                    "window_end": coverage["window_end"],
                    "window_start": coverage["window_start"],
                    "working_paths_absent": True,
                },
            )
            authority.verify_shadow_cleanup_receipt(self.identity, cleanup)
            publication.pop("expired_cleanup_claim", None)
            current["retained_export"] = None
            publication.update(
                {
                    "cleanup_receipt": cleanup,
                    "finalized_at": self._state._now(),
                    "phase": "shadow_complete",
                }
            )
            self._state._transition(current, RunStage.COMPLETE)
            return current, {"cleanup_pending": False, "idempotent": False}

        result = self.store.transaction(close)
        response = self._projection._status_view(result.snapshot)
        response.update({"action": "shadow-cleanup", **result.value})
        return response

    def _initial_state(
        self,
        *,
        run_ref: str,
        specification: dict[str, Any],
        specification_digest: str,
        created_at: str,
        raw_deadline: str,
        working_deadline: str,
    ) -> dict[str, Any]:
        source_cells: dict[str, dict[str, dict[str, Any]]] = {}
        cursor_state: dict[str, dict[str, Any]] = {}
        host_refs: dict[str, str] = {}
        for host in specification["hosts"]:
            host_ref = self._ref(RefType.HOST, host)
            host_refs[host] = host_ref
            source_cells[host] = {
                source_kind: {
                    "host_ref": host_ref,
                    "continuation_position": None,
                    "continuation_segments": [],
                    "lease_ref": None,
                    "manifest": None,
                    "metrics": {"byte_count": 0, "record_count": 0},
                    "payloads": {},
                    "snapshot_ref": None,
                    "status": "pending",
                    "transport_receipt": None,
                    "transport_receipt_ref": None,
                    "transport_status": None,
                }
                for source_kind in specification["source_kinds"]
            }
            cursor_state[host] = {
                "before": copy.deepcopy(specification["starting_cursors"].get(host)),
                "decision": (
                    "not_applicable"
                    if specification["mode"] == RunMode.SESSION.value
                    else "pending"
                ),
                "proposed": None,
                "publication_state": "pending",
            }
        return {
            "actions": {},
            "authority": copy.deepcopy(specification["authority"]),
            "blocked_reason": None,
            "coverage": {"status": "pending"},
            "controlled_holdouts": {},
            "created_at": created_at,
            "cursors": cursor_state,
            "deadlines": {"raw": raw_deadline, "working": working_deadline},
            "episodes": [],
            "extracted_turns": {},
            "gaps": [],
            "host_refs": host_refs,
            "identity_key_id": self.identity.key_id,
            "jobs": {},
            "lineage": {
                "backfill_of": specification["backfill_of"],
                "controlled_gap_receipt_ref": (
                    None
                    if specification["controlled_gap_receipt"] is None
                    else specification["controlled_gap_receipt"]["receipt_ref"]
                ),
                "controlled_gap_receipt": copy.deepcopy(
                    specification["controlled_gap_receipt"]
                ),
                "shadow_successor": copy.deepcopy(specification["shadow_successor"]),
                "backfill_lineage_receipt": None,
                "expected_backlog_ref": specification["backfill_expected_backlog_ref"],
                "expected_episode_head_set_ref": specification[
                    "prior_episode_head_set_ref"
                ],
                "prior_episode_heads": copy.deepcopy(
                    specification["prior_episode_heads"]
                ),
                "prior_episode_membership": copy.deepcopy(
                    specification["prior_episode_membership"]
                ),
                "proposed_episode_heads": copy.deepcopy(
                    specification["prior_episode_heads"]
                ),
                "proposed_episode_head_set_ref": None,
            },
            "metrics": {
                "accepted_agent_results": 0,
                "accepted_source_manifests": 0,
                "agent_attempts": 0,
                "agent_claim_budget_exhaustions": 0,
                "agent_results": 0,
                "agent_retries": 0,
                "agent_task_cache_hits": 0,
                "agent_task_cache_misses": 0,
                "agent_task_reuses": 0,
                "rejected_agent_results": 0,
                "source_bytes": 0,
                "source_leases": 0,
                "source_records": 0,
                "stage_transitions": 0,
            },
            "mode": specification["mode"],
            "shadow": specification["shadow"],
            "partial_policy": {
                "allow_partial": specification["allow_partial"],
                "decision": "pending",
                "scope": "per_host"
                if specification["mode"] == "daily"
                else "all_hosts",
            },
            "provenance": copy.deepcopy(specification["provenance"]),
            "publication": {
                "bundle_digest": None,
                "cleanup_claim": None,
                "cleanup_receipt": None,
                "coverage_receipt": None,
                "durable_state": None,
                "exported_at": None,
                "finalized_at": None,
                "phase": "created",
                "retention_deadline": None,
                "shadow_staging_dir": None,
            },
            "resolved_reviews": {},
            "retained_export": None,
            "review_plans": {},
            "run_ref": run_ref,
            "schema_version": STATE_SCHEMA_VERSION,
            "session_target": specification["session_target"],
            "session_selector_commitment": specification["session_selector_commitment"],
            "shard_limits": copy.deepcopy(specification["shard_limits"]),
            "source": {
                "catalog": None,
                "cells": source_cells,
                "materialization": None,
                "model_era_by_unit": {},
                "model_eras_by_session": {},
                "reassembly": {},
                "shards": {},
            },
            "specification_digest": specification_digest,
            "stage": RunStage.SOURCE_CATALOG.value,
            "stage_history": [
                {"entered_at": created_at, "stage": RunStage.SOURCE_CATALOG.value}
            ],
            "topic_inputs": {},
            "window": copy.deepcopy(specification["window"]),
        }

    @staticmethod
    def _normalize_cursors(
        cursors: Mapping[str, Any] | None,
        hosts: Sequence[str],
    ) -> dict[str, Any]:
        values = {} if cursors is None else dict(cursors)
        unknown = sorted(set(values) - set(hosts))
        if unknown:
            raise InvalidInputError(
                f"cursor state contains unknown hosts: {', '.join(unknown)}"
            )
        return {
            host: _json_copy(values.get(host), label=f"cursor for {host}")
            for host in hosts
        }
