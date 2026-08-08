"""Deterministic coordinator facade for Session Retrospective v2."""

# ruff: noqa: F401

from __future__ import annotations
import datetime as dt
import os
from pathlib import Path
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence
from . import authority, finalize, safe_io, sharding, transport as source_transport
from .checkpoints import AtomicCheckpointStore, canonical_json_bytes
from .contracts import (
    MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
    SESSION_SHARDS_SCHEMA,
    ControlledGapReason,
    RefType,
    SessionShardsRequest,
    SourceKind,
)
from .identity import IdentityKey, IdentityKeyMismatchError

from .orchestrator_support import (
    DEFAULT_AGENT_CLAIM_TTL_SECONDS,
    DEFAULT_HOSTS,
    ENGINE_VERSION,
    EXECUTION_CONTRACT_SCHEMA,
    EXECUTION_VERSION_CONTRACT,
    EXTRACTOR_SHARD_MAX_BYTES,
    InvalidInputError,
    InvalidTransitionError,
    MAX_SESSION_SHARDS_RECORD_DATA_FRAMES,
    MAX_AGENT_ENVELOPE_BYTES,
    MIN_AGENT_CLAIM_TTL_SECONDS,
    OrchestratorError,
    PROMPT_DIGEST,
    PROMPT_VERSION,
    PUBLISHER_FINGERPRINT,
    PUBLISHER_UID,
    RAW_INPUT_DIRECTORY,
    REQUIRED_SOURCE_KINDS,
    RunConflictError,
    RunNotStartedError,
    SESSION_SHARDS_FIXED_MEMORY_ENVELOPE_BYTES,
    SESSION_SHARDS_MAX_FRAME_CHARS,
    SESSION_SHARDS_MAX_JSON_NESTING_DEPTH,
    SESSION_SHARDS_PROTOCOL_FEATURES,
    SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
    SHADOW_CLEANUP_ROOTS,
    SOURCE_TRANSPORT_MAX_FRAME_BYTES,
    SOURCE_TRANSPORT_MAX_SOURCE_BYTES,
    STATE_SCHEMA_VERSION,
    SessionShardConsumption,
    SourcePreparation,
    _build_provenance,
    _checkpoint_key_id,
    _normalize_hosts,
    _normalize_source_kinds,
    _transport_accounting_bytes,
    consume_session_shard_frames,
    publisher_readiness,
    publisher_sign_verify_canary,
)

from .orchestrator_components import (
    build_orchestrator_components,
    install_orchestrator_delegates,
)
from .orchestrator_context import Clock, OrchestratorContext
from .orchestrator_projection import StateProjectionOperations


def doctor(
    *,
    hosts: Sequence[str] | None = None,
    source_kinds: Sequence[str | SourceKind] | None = None,
    provenance: Mapping[str, Any] | None = None,
    checks: Mapping[str, bool] | None = None,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
    identity: IdentityKey | None = None,
    publisher_probe: Callable[[], Mapping[str, Any]] | None = None,
    publisher_canary: Callable[[], bool] | None = None,
    shadow: bool = False,
    history_repo: str | os.PathLike[str] | None = None,
    history_target_ref: str | None = None,
    provider_state: str | os.PathLike[str] | None = None,
    production_marker: str | os.PathLike[str] | None = None,
    publisher_fingerprint: str = authority.DEFAULT_PUBLISHER_FINGERPRINT,
    publisher_gnupg_home: str
    | os.PathLike[str] = authority.DEFAULT_PUBLISHER_GNUPG_HOME,
) -> dict[str, Any]:
    """Run actual capability probes and return a safe readiness report."""

    results: dict[str, dict[str, Any]] = {}

    def record(name: str, ok: bool, detail: str) -> None:
        results[name] = {"detail": detail, "ok": bool(ok)}

    record(
        "python_runtime",
        sys.version_info >= (3, 11),
        f"python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    io_issues = safe_io.secure_io_capability_issues()
    record(
        "safe_io_capabilities",
        not io_issues,
        "available" if not io_issues else ",".join(io_issues),
    )
    resolved_identity = identity
    try:
        if resolved_identity is None:
            loader = (
                IdentityKey.load
                if require_existing_identity
                else IdentityKey.load_or_create
            )
            resolved_identity = loader(identity_path)
        record("fixed_identity", True, resolved_identity.key_id)
    except (IdentityKeyMismatchError, OSError, ValueError) as error:
        record("fixed_identity", False, type(error).__name__)
    try:
        publisher = dict(
            publisher_readiness(
                gnupg_home=publisher_gnupg_home,
                fingerprint=publisher_fingerprint,
            )
            if publisher_probe is None
            else publisher_probe()
        )
        canary_ready = (
            publisher_sign_verify_canary(
                gnupg_home=publisher_gnupg_home,
                fingerprint=publisher_fingerprint,
            )
            if publisher_canary is None and publisher_probe is None
            else publisher.get("ready") is True
            if publisher_canary is None
            else publisher_canary()
        )
    except (OSError, TypeError, ValueError):
        publisher = {"fingerprint": None, "ready": False}
        canary_ready = False
    publisher_safe = {
        "fingerprint": publisher_fingerprint,
        "ready": publisher.get("ready") is True
        and publisher.get("fingerprint") == publisher_fingerprint,
    }
    publisher_safe["ready"] = publisher_safe["ready"] and canary_ready
    record(
        "publisher_identity",
        publisher_safe["ready"],
        publisher_fingerprint,
    )
    normalized_hosts: tuple[str, ...] | None = None
    try:
        normalized_hosts = _normalize_hosts(hosts)
        host_policy_ok = set(normalized_hosts) == set(DEFAULT_HOSTS)
        record(
            "canonical_host_policy",
            host_policy_ok,
            (
                f"{len(normalized_hosts)} canonical hosts"
                if host_policy_ok
                else "configured hosts differ from the canonical role set"
            ),
        )
    except InvalidInputError as error:
        record("canonical_host_policy", False, str(error))
    try:
        normalized_kinds = _normalize_source_kinds(source_kinds)
        record("source_matrix", True, f"{len(normalized_kinds)} required source kinds")
    except InvalidInputError as error:
        record("source_matrix", False, str(error))
    normalized_provenance: dict[str, Any] | None = None
    try:
        normalized_provenance = _build_provenance(
            provenance=provenance,
            policy=None,
            model=None,
            versions=None,
        )
        record(
            "execution_contract",
            True,
            f"configuration root {normalized_provenance['configuration_root']}",
        )
    except InvalidInputError as error:
        record("execution_contract", False, str(error))
    helper_ok = False
    try:
        helper_commitment = source_transport.remote_host_context_helper_commitment()
        expected_helper = (
            normalized_provenance.get("transport", {}).get(
                "remote_host_context_helper_commitment"
            )
            if normalized_provenance is not None
            else None
        )
        helper_ok = helper_commitment == expected_helper
        record(
            "remote_host_context_transport",
            helper_ok,
            helper_commitment if helper_ok else "helper commitment mismatch",
        )
    except (OSError, source_transport.TransportValidationError) as error:
        record("remote_host_context_transport", False, type(error).__name__)

    durable_history: authority.DurableHistoryState | None = None
    history_binding: str | None = None
    if (
        resolved_identity is None
        or history_repo is None
        or not isinstance(history_target_ref, str)
        or not history_target_ref
    ):
        record(
            "durable_history_contract",
            False,
            "history repository, ref, and bound identity are required",
        )
    else:
        try:
            durable_history = authority.load_durable_history(
                Path(history_repo).expanduser().absolute(),
                history_target_ref,
                identity=resolved_identity,
                expected_fingerprint=publisher_fingerprint,
                gnupg_home=publisher_gnupg_home,
            )
            history_binding = authority.history_repository_binding(
                Path(history_repo).expanduser().absolute(),
                history_target_ref,
                identity=resolved_identity,
            )
            record("durable_history_contract", True, history_binding)
        except (OSError, authority.AuthorityError) as error:
            record("durable_history_contract", False, type(error).__name__)

    if shadow:
        record("provider_binding", True, "not_applicable_for_shadow")
        record("production_marker_binding", True, "not_applicable_for_shadow")
    elif durable_history is None or resolved_identity is None or provider_state is None:
        record("provider_binding", False, "production provider state is required")
    else:
        try:
            authority.assert_provider_cache_matches(
                provider_state,
                durable_history,
                identity=resolved_identity,
            )
            record("provider_binding", True, "matches durable history")
        except (OSError, authority.AuthorityError) as error:
            record("provider_binding", False, type(error).__name__)

    if not shadow:
        if (
            resolved_identity is None
            or normalized_provenance is None
            or history_repo is None
            or not isinstance(history_target_ref, str)
            or production_marker is None
        ):
            record(
                "production_marker_binding",
                False,
                "production marker and complete configuration are required",
            )
        else:
            marker_state = {"provenance": normalized_provenance}
            configuration_ref = str(
                resolved_identity.derive_ref(
                    RefType.CONFIGURATION,
                    {"parts": [normalized_provenance["configuration_root"]]},
                )
            )
            try:
                authority.load_production_marker(
                    production_marker,
                    identity=resolved_identity,
                    history_repo=history_repo,
                    target_ref=history_target_ref,
                    configuration_root=normalized_provenance["configuration_root"],
                    configuration_ref=configuration_ref,
                    model_era=StateProjectionOperations._model_era(marker_state),
                    policy_era=StateProjectionOperations._policy_token(
                        marker_state,
                        "policy",
                        "source_policy_v2",
                    ),
                )
                record("production_marker_binding", True, "matches configuration")
            except (OSError, authority.AuthorityError) as error:
                record("production_marker_binding", False, type(error).__name__)
    record("checkpoint_contract", True, f"checkpoint format {STATE_SCHEMA_VERSION}")
    if checks:
        raise InvalidInputError(
            "doctor does not accept caller-asserted readiness checks"
        )
    errors = [name for name, result in results.items() if not result["ok"]]
    return {
        "checks": results,
        "errors": errors,
        "ok": not errors,
        "publisher": publisher_safe,
        "required_source_kinds": list(REQUIRED_SOURCE_KINDS),
        "runtime_coverage_gaps": [
            "remote_host_authentication",
            "remote_host_reachability",
        ],
        "schema_version": STATE_SCHEMA_VERSION,
    }


@install_orchestrator_delegates
class RetrospectiveOrchestrator:
    """Identity-bound, checkpointed coordinator for Session Retrospective v2."""

    UNKNOWN_MODEL_ERA = StateProjectionOperations.UNKNOWN_MODEL_ERA
    MIXED_MODEL_ERA = StateProjectionOperations.MIXED_MODEL_ERA

    def __init__(
        self,
        run_dir: str | os.PathLike[str],
        *,
        clock: Callable[[], dt.datetime | str] | None = None,
        store: AtomicCheckpointStore | None = None,
        identity_path: str | os.PathLike[str] | None = None,
        identity: IdentityKey | None = None,
        require_existing_identity: bool = False,
        shard_limits: sharding.ShardLimits | None = None,
    ) -> None:
        resolved_run_dir = Path(run_dir).expanduser().absolute()
        expected_key_id = (
            store.key_id if store is not None else _checkpoint_key_id(resolved_run_dir)
        )
        if identity is None:
            loader = (
                IdentityKey.load
                if require_existing_identity
                else IdentityKey.load_or_create
            )
            resolved_identity = loader(
                identity_path,
                expected_key_id=expected_key_id,
            )
        else:
            if expected_key_id is not None and identity.key_id != expected_key_id:
                raise IdentityKeyMismatchError(
                    "supplied identity does not match the checkpoint store"
                )
            resolved_identity = identity
        if store is not None:
            if store.run_dir != resolved_run_dir:
                raise InvalidInputError("checkpoint store run_dir does not match")
            if store.key_id != resolved_identity.key_id:
                raise IdentityKeyMismatchError(
                    "checkpoint store is not bound to the loaded identity"
                )
            resolved_store = store
        else:
            resolved_store = AtomicCheckpointStore(
                resolved_run_dir,
                identity=resolved_identity,
            )
        resolved_shard_limits = shard_limits or sharding.ShardLimits(
            max_bytes=EXTRACTOR_SHARD_MAX_BYTES
        )
        if resolved_shard_limits.max_bytes > EXTRACTOR_SHARD_MAX_BYTES:
            raise InvalidInputError(
                "raw shard byte limit exceeds the complete agent envelope budget"
            )
        if (
            resolved_shard_limits.record_processing_budget
            < MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
        ):
            raise InvalidInputError("record processing budget must be at least 4 MiB")
        self._context = OrchestratorContext(
            run_dir=resolved_run_dir,
            identity=resolved_identity,
            store=resolved_store,
            shard_limits=resolved_shard_limits,
            clock=clock or (lambda: dt.datetime.now(dt.timezone.utc)),
            canonical_hosts_provider=lambda: DEFAULT_HOSTS,
            agent_envelope_limit_provider=lambda: MAX_AGENT_ENVELOPE_BYTES,
            source_transport_max_source_bytes_provider=(
                lambda: SOURCE_TRANSPORT_MAX_SOURCE_BYTES
            ),
        )
        self._components = build_orchestrator_components(self._context)

    @property
    def run_dir(self) -> Path:
        return self._context.run_dir

    @property
    def identity(self) -> IdentityKey:
        return self._context.identity

    @property
    def store(self) -> AtomicCheckpointStore:
        return self._context.store

    @property
    def shard_limits(self) -> sharding.ShardLimits:
        return self._context.shard_limits

    @property
    def _clock(self) -> Clock:
        return self._context.clock

    def doctor(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("identity", self.identity)
        kwargs.setdefault("require_existing_identity", True)
        return doctor(**kwargs)

    def _ref(self, kind: RefType, *parts: Any) -> str:
        return self._context.ref(kind, *parts)

    def _agent_envelope_limit(self) -> int:
        return self._context.agent_envelope_limit()

    def _canonical_hosts(self) -> tuple[str, ...]:
        return self._context.canonical_hosts()

    def _source_transport_max_source_bytes(self) -> int:
        return self._context.source_transport_max_source_bytes()


Orchestrator = RetrospectiveOrchestrator
RunOrchestrator = RetrospectiveOrchestrator


def start_run(
    run_dir: str | os.PathLike[str],
    *,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).start(**kwargs)


start = start_run


def status(
    run_dir: str | os.PathLike[str],
    *,
    claim_job_ref: str | None = None,
    claim_attempt_ref: str | None = None,
    dispatcher_ref: str | None = None,
    claim_ref: str | None = None,
    claim_ttl_seconds: int = DEFAULT_AGENT_CLAIM_TTL_SECONDS,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> dict[str, Any]:
    coordinator = RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    )
    claim_values = (claim_job_ref, claim_attempt_ref, dispatcher_ref)
    if any(value is not None for value in (*claim_values, claim_ref)):
        if any(value is None for value in claim_values):
            raise InvalidInputError(
                "status claim requires job, attempt, and dispatcher references"
            )
        return coordinator.claim_agent_job(
            claim_job_ref,
            claim_attempt_ref,
            dispatcher_ref,
            claim_ref=claim_ref,
            ttl_seconds=claim_ttl_seconds,
        )
    if claim_ttl_seconds != DEFAULT_AGENT_CLAIM_TTL_SECONDS:
        raise InvalidInputError("claim TTL is valid only for a status claim")
    return coordinator.status()


def accept_source(
    run_dir: str | os.PathLike[str],
    lease_ref: str,
    manifest: Mapping[str, Any],
    *,
    transport_receipt: Mapping[str, Any],
    raw_records: Mapping[str, bytes] | None = None,
    transport_streams: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    transport_requests: Mapping[str, SessionShardsRequest | Mapping[str, Any]]
    | None = None,
    transport_segments: Mapping[
        str,
        Iterable[
            tuple[
                Iterable[Mapping[str, Any]],
                SessionShardsRequest | Mapping[str, Any],
            ]
        ],
    ]
    | None = None,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> dict[str, Any]:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).accept_source(
        lease_ref,
        manifest,
        transport_receipt=transport_receipt,
        raw_records=raw_records,
        transport_streams=transport_streams,
        transport_requests=transport_requests,
        transport_segments=transport_segments,
    )


def prepare_source(
    run_dir: str | os.PathLike[str],
    lease_ref: str,
    lines: Iterable[bytes | str],
    *,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> SourcePreparation:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).prepare_source(lease_ref, lines)


def holdout_host(
    run_dir: str | os.PathLike[str],
    host: str,
    *,
    reason: ControlledGapReason | str,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> dict[str, Any]:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).holdout_host(host, reason=reason)


def accept_agent_result(
    run_dir: str | os.PathLike[str],
    job_ref: str,
    attempt_ref: str,
    result: Mapping[str, Any],
    *,
    claim_ref: str,
    result_ref: str,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> dict[str, Any]:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).accept_agent_result(
        job_ref,
        attempt_ref,
        result,
        claim_ref=claim_ref,
        result_ref=result_ref,
    )


def claim_agent_job(
    run_dir: str | os.PathLike[str],
    job_ref: str,
    attempt_ref: str,
    dispatcher_ref: str,
    *,
    claim_ref: str | None = None,
    ttl_seconds: int = DEFAULT_AGENT_CLAIM_TTL_SECONDS,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> dict[str, Any]:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).claim_agent_job(
        job_ref,
        attempt_ref,
        dispatcher_ref,
        claim_ref=claim_ref,
        ttl_seconds=ttl_seconds,
    )


def reject_agent_result_payload(
    run_dir: str | os.PathLike[str],
    job_ref: str,
    attempt_ref: str,
    *,
    claim_ref: str,
    result_ref: str,
    payload_digest: str,
    reason: str,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> dict[str, Any]:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).reject_agent_result_payload(
        job_ref,
        attempt_ref,
        claim_ref=claim_ref,
        result_ref=result_ref,
        payload_digest=payload_digest,
        reason=reason,
    )


def resolve_agent_result_sink(
    run_dir: str | os.PathLike[str],
    job_ref: str,
    attempt_ref: str,
    *,
    claim_ref: str,
    result_ref: str,
    requested_path: str | os.PathLike[str],
    **kwargs: Any,
) -> dict[str, str]:
    return RetrospectiveOrchestrator(run_dir, **kwargs).resolve_agent_result_sink(
        job_ref,
        attempt_ref,
        claim_ref=claim_ref,
        result_ref=result_ref,
        requested_path=requested_path,
    )


def advance(
    run_dir: str | os.PathLike[str],
    *,
    identity_path: str | os.PathLike[str] | None = None,
    require_existing_identity: bool = False,
) -> dict[str, Any]:
    return RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=require_existing_identity,
    ).advance()


__all__ = [
    "DEFAULT_HOSTS",
    "ENGINE_VERSION",
    "InvalidInputError",
    "InvalidTransitionError",
    "Orchestrator",
    "OrchestratorError",
    "REQUIRED_SOURCE_KINDS",
    "RetrospectiveOrchestrator",
    "RunConflictError",
    "RunNotStartedError",
    "RunOrchestrator",
    "SessionShardConsumption",
    "SourcePreparation",
    "accept_agent_result",
    "accept_source",
    "advance",
    "claim_agent_job",
    "consume_session_shard_frames",
    "doctor",
    "holdout_host",
    "publisher_readiness",
    "prepare_source",
    "reject_agent_result_payload",
    "resolve_agent_result_sink",
    "start",
    "start_run",
    "status",
]
