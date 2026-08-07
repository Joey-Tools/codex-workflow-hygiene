"""Durable state machine for one immutable publication attempt."""

from __future__ import annotations
from collections.abc import Callable, Mapping
from copy import deepcopy
import hashlib
import os
from pathlib import Path
from typing import Any
from . import authority
from .checkpoints import canonical_json_bytes
from .identity import IdentityKey

from .publication_support import (
    AppendOnlyViolation,
    ArtifactInventory,
    ArtifactValidationError,
    AttemptMismatchError,
    FailureInjector,
    GenerationConflict,
    InvalidTransitionError,
    LOCAL_GIT_CLEANUP_CLAIM_PREFIX,
    MAX_BUNDLE_BYTES,
    OperationRequest,
    PUBLICATION_ABORT_COMMITMENT_AUTH_PREFIX,
    PUBLICATION_ABORT_COMMITMENT_REF_PREFIX,
    PUBLICATION_ABORT_COMMITMENT_SCHEMA,
    PublicationAdapter,
    PublicationError,
    PublicationPhase,
    PublicationRejected,
    ReceiptValidationError,
    SHADOW_RECEIPT_REF_PREFIX,
    SHADOW_TRANSACTION_REF_PREFIX,
    STATE_SCHEMA_VERSION,
    StateCorruptionError,
    TargetHeadConflict,
    TransactionKind,
    _AnchoredStateDirectory,
    _NORMAL_PHASE_INDEX,
    _SAFE_REASON_RE,
    _anchored_lock,
    _canonical_json_bytes,
    _json_clone,
    _load_run_publication_authority,
    _new_event,
    _normalize_episode_head_update,
    _normalize_host_cursor_vector,
    _normalize_publication_authority,
    _normalize_receipt,
    _require_mapping,
    _sha256_json,
    _state_digest,
    _validate_attempt_ref,
    _validate_destination,
    _validate_destination_state,
    _validate_event_chain,
    _validate_optional_ref,
    _validate_optional_ref_state,
    _validate_persistent_publication_claim,
    _validate_phase_receipts,
    _validate_ref,
    _validate_ref_state,
    _validate_ref_value,
    build_artifact_inventory,
    new_attempt_ref,
    verify_publication_abort_commitment,
)


class PublicationTransaction:
    """Durable local coordinator for one immutable publication attempt."""

    def __init__(
        self,
        journal_path: Path,
        state: dict[str, Any],
        *,
        state_directory: _AnchoredStateDirectory,
        adapter: PublicationAdapter | None,
        failure_injector: FailureInjector | None,
    ) -> None:
        self._journal_path = journal_path
        self._journal_name = state_directory._name(journal_path.name)
        self._state_directory = state_directory
        self._state = state
        self._adapter = adapter
        self._failure_injector = failure_injector

    @classmethod
    def create(
        cls,
        journal_path: str | os.PathLike[str],
        *,
        bundle_dir: str | os.PathLike[str],
        destination: str,
        target_ref: str,
        expected_target_head: str | None,
        run_dir: str | os.PathLike[str] | None = None,
        identity_path: str | os.PathLike[str] | None = None,
        attempt_ref: str | None = None,
        shadow: bool = False,
        adapter: PublicationAdapter | None = None,
        failure_injector: FailureInjector | None = None,
        max_bundle_bytes: int = MAX_BUNDLE_BYTES,
    ) -> PublicationTransaction:
        journal = Path(journal_path).absolute()
        if shadow:
            raise PublicationRejected(
                "shadow runs cannot create publication transactions"
            )
        attempt = attempt_ref or new_attempt_ref()
        _validate_attempt_ref(attempt)

        bundle = Path(bundle_dir).absolute()
        inventory = build_artifact_inventory(bundle, max_bundle_bytes=max_bundle_bytes)
        authoritative_run_dir = (
            journal.parent if run_dir is None else Path(run_dir).absolute()
        )
        authoritative_identity_path = (
            authority.DEFAULT_PRODUCTION_MARKER.parent / "identity-v2.key"
            if identity_path is None
            else Path(identity_path).expanduser().absolute()
        )
        publication_authority, normalized_cursor_vector, normalized_episode_update = (
            _load_run_publication_authority(
                run_dir=authoritative_run_dir,
                identity_path=authoritative_identity_path,
                bundle_dir=bundle,
                inventory=inventory,
            )
        )
        if destination != publication_authority["destination"]:
            raise PublicationRejected(
                "caller destination differs from the persisted run identity"
            )
        if target_ref != publication_authority["target_ref"]:
            raise PublicationRejected(
                "caller target ref differs from persisted authority"
            )
        authoritative_head = publication_authority["expected_history"]["history_commit"]
        if expected_target_head != authoritative_head:
            raise PublicationRejected(
                "caller expected head differs from the latest durable history"
            )
        _validate_destination(destination)
        _validate_ref(target_ref, "target_ref")
        _validate_optional_ref(expected_target_head, "expected_target_head")
        kind = TransactionKind.PUBLISH
        plan = {
            "attempt_ref": attempt,
            "kind": kind.value,
            "bundle_dir": str(bundle),
            "destination": destination,
            "target_ref": target_ref,
            "expected_target_head": expected_target_head,
            "inventory_digest_v2": inventory.inventory_digest_v2,
            "host_cursor_vector": normalized_cursor_vector,
            "episode_head_update": normalized_episode_update,
            "publication_authority": publication_authority,
        }
        plan_digest = _sha256_json(plan)
        state: dict[str, Any] = {
            "schema_version": STATE_SCHEMA_VERSION,
            "attempt_ref": attempt,
            "kind": kind.value,
            "phase": PublicationPhase.CREATED.value,
            "plan": plan,
            "plan_digest": plan_digest,
            "inventory": inventory.to_dict(),
            "receipts": {},
            "abort": None,
            "reservations_held": True,
            "state_advanced": False,
            "revision": 0,
            "events": [],
        }
        state["events"].append(
            _new_event(
                state["events"],
                attempt_ref=attempt,
                action="create",
                from_phase=None,
                to_phase=PublicationPhase.CREATED.value,
                details={"plan_digest": plan_digest},
            )
        )
        state["state_digest"] = _state_digest(state)
        cls._validate_state(state)

        state_directory = _AnchoredStateDirectory.open(journal.parent, create=True)
        with _anchored_lock(state_directory, f".{journal.name}.lock"):
            if state_directory.exists(journal.name):
                raise StateCorruptionError(
                    f"publication journal already exists: {journal}"
                )
            state_directory.create_json(journal.name, state)
        transaction = cls(
            journal,
            state,
            state_directory=state_directory,
            adapter=adapter,
            failure_injector=failure_injector,
        )
        transaction._inject("create.after_persist")
        return transaction

    @classmethod
    def open(
        cls,
        journal_path: str | os.PathLike[str],
        *,
        adapter: PublicationAdapter | None = None,
        failure_injector: FailureInjector | None = None,
        expected_attempt_ref: str | None = None,
    ) -> PublicationTransaction:
        journal = Path(journal_path).absolute()
        state_directory = _AnchoredStateDirectory.open(journal.parent)
        with _anchored_lock(state_directory, f".{journal.name}.lock"):
            state = state_directory.read_json(journal.name)
            cls._validate_state(state)
        if (
            expected_attempt_ref is not None
            and state["attempt_ref"] != expected_attempt_ref
        ):
            raise AttemptMismatchError(
                f"journal belongs to {state['attempt_ref']!r}, not {expected_attempt_ref!r}"
            )
        transaction = cls(
            journal,
            state,
            state_directory=state_directory,
            adapter=adapter,
            failure_injector=failure_injector,
        )
        if transaction.phase in {
            PublicationPhase.ABORT_PENDING,
            PublicationPhase.ABORTED,
        }:
            transaction.recover_abort()
            return transaction
        transaction._assert_publication_claim()
        transaction._recover_durable_adapter_progress()
        transaction._refresh_publication_authority()
        return transaction

    resume = open

    @classmethod
    def inspect_local(
        cls,
        journal_path: str | os.PathLike[str],
    ) -> dict[str, Any]:
        """Read and validate a journal without invoking a publication adapter."""

        journal = Path(journal_path).absolute()
        state_directory = _AnchoredStateDirectory.open(journal.parent)
        try:
            with _anchored_lock(state_directory, f".{journal.name}.lock"):
                state = state_directory.read_json(journal.name)
                cls._validate_state(state)
            return deepcopy(state)
        finally:
            state_directory.close()

    @property
    def journal_path(self) -> Path:
        return self._journal_path

    @property
    def attempt_ref(self) -> str:
        return self._state["attempt_ref"]

    @property
    def kind(self) -> TransactionKind:
        return TransactionKind(self._state["kind"])

    @property
    def phase(self) -> PublicationPhase:
        return PublicationPhase(self._state["phase"])

    @property
    def inventory(self) -> ArtifactInventory:
        return ArtifactInventory.from_dict(
            _require_mapping(self._state["inventory"], "inventory")
        )

    @property
    def reservations_held(self) -> bool:
        return self._state["reservations_held"]

    @property
    def state_advanced(self) -> bool:
        return self._state["state_advanced"]

    def status(self) -> dict[str, Any]:
        return deepcopy(self._state)

    def operation_request(self, phase: str | PublicationPhase) -> OperationRequest:
        phase_value = phase.value if isinstance(phase, PublicationPhase) else phase
        receipts = {
            name: deepcopy(_require_mapping(receipt, f"receipt {name}"))
            for name, receipt in self._state["receipts"].items()
        }
        plan = self._state["plan"]
        return OperationRequest(
            phase=phase_value,
            attempt_ref=self.attempt_ref,
            kind=self.kind.value,
            target_ref=plan["target_ref"],
            expected_target_head=plan["expected_target_head"],
            destination=plan["destination"],
            plan_digest=self._state["plan_digest"],
            inventory=self.inventory,
            receipts=receipts,
            bundle_dir=plan["bundle_dir"],
            host_cursor_vector=deepcopy(plan.get("host_cursor_vector", {})),
            episode_head_update=deepcopy(plan.get("episode_head_update", {})),
            publication_authority=deepcopy(plan.get("publication_authority", {})),
        )

    def bound_receipt(
        self, *, status: str, receipt_ref: str, **fields: Any
    ) -> dict[str, Any]:
        """Return the non-secret binding fields an external receipt must include."""

        _validate_ref(receipt_ref, "receipt_ref")
        receipt = self.operation_request(status).binding()
        receipt.update({"status": status, "receipt_ref": receipt_ref})
        receipt.update(fields)
        return _normalize_receipt(receipt, status)

    def expected_added_artifacts(self) -> dict[str, dict[str, Any]]:
        destination = self._state["plan"]["destination"]
        return {
            f"{destination}/{artifact.name}": {
                "sha256": artifact.sha256,
                "size": artifact.size,
            }
            for artifact in self.inventory.artifacts
        }

    def expected_shadow_artifacts(self) -> dict[str, dict[str, Any]]:
        return {
            artifact.name: {"sha256": artifact.sha256, "size": artifact.size}
            for artifact in self.inventory.artifacts
        }

    def prepare(self) -> Mapping[str, Any]:
        self._refresh_publication_authority()
        existing = self._receipt_after_or_at(PublicationPhase.PREPARED, "reservation")
        if existing is not None:
            return existing
        self._require_phase(PublicationPhase.CREATED)
        self._revalidate_inventory()
        self._inject("prepare.after_inventory")

        if self.kind is TransactionKind.SHADOW:
            receipt = self._shadow_receipt(
                "reserved",
                reservation_kind="shadow_local",
                reservations_held=True,
                published=False,
            )
            self._validate_reservation_receipt(receipt, shadow=True)
            self._transition(
                action="prepare",
                to_phase=PublicationPhase.PREPARED,
                receipts={"reservation": receipt},
            )
            return receipt

        adapter = self._require_adapter()
        request = self.operation_request("prepare")
        preflight_prepare = getattr(adapter, "preflight_prepare", None)
        if preflight_prepare is not None:
            self._invoke_adapter("prepare.preflight", preflight_prepare, request)
        lock_receipt = self._invoke_adapter(
            "prepare.acquire_lock",
            adapter.acquire_publication_lock,
            request,
        )
        lock_receipt = self._validate_bound_receipt(lock_receipt, "locked")
        conflict: PublicationError | None = None
        observation: dict[str, Any] | None = None
        reservation: dict[str, Any] | None = None
        try:
            observation_value = self._invoke_adapter(
                "prepare.inspect_target",
                adapter.inspect_target,
                request,
            )
            observation = self._validate_target_observation(observation_value)
            expected_head = self._state["plan"]["expected_target_head"]
            actual_head = observation["target_head"]
            if actual_head != expected_head:
                conflict = TargetHeadConflict(expected_head, actual_head)
                self._mark_abort_pending(
                    "target_head_conflict",
                    details={
                        "expected_target_head": expected_head,
                        "actual_target_head": actual_head,
                    },
                    receipts={"target_observation": observation},
                    action="prepare_target_conflict",
                )
            elif observation["destination_exists"] is not False:
                conflict = AppendOnlyViolation(
                    f"append-only destination already exists: {self._state['plan']['destination']}"
                )
                self._mark_abort_pending(
                    "target_path_exists",
                    details={"destination": self._state["plan"]["destination"]},
                    receipts={"target_observation": observation},
                    action="prepare_append_only_conflict",
                )
            else:
                reservation_value = self._invoke_adapter(
                    "prepare.reserve",
                    adapter.reserve,
                    request,
                )
                reservation = self._validate_reservation_receipt(
                    reservation_value,
                    shadow=False,
                    observation=observation,
                )
        finally:
            self._inject("prepare.release_lock.before_callback")
            adapter.release_publication_lock(request, lock_receipt)
            self._inject("prepare.release_lock.after_callback")

        if conflict is not None:
            raise conflict
        assert observation is not None
        assert reservation is not None
        self._transition(
            action="prepare",
            to_phase=PublicationPhase.PREPARED,
            receipts={"target_observation": observation, "reservation": reservation},
        )
        return reservation

    def stage(self, receipt: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        self._refresh_publication_authority()
        existing = self._receipt_after_or_at(PublicationPhase.STAGED, "stage")
        if existing is not None:
            return existing
        self._require_phase(PublicationPhase.PREPARED)
        self._revalidate_inventory()
        if self.kind is TransactionKind.SHADOW:
            value = receipt or self._shadow_receipt(
                "staged",
                pack_root=self._shadow_ref("pack"),
                reservation_receipt_ref=self._stored_receipt("reservation")[
                    "receipt_ref"
                ],
                expected_target_head=self._state["plan"]["expected_target_head"],
                published=False,
            )
        else:
            value = self._external_receipt("stage", receipt)
        normalized = self._validate_stage_receipt(
            value, shadow=self.kind is TransactionKind.SHADOW
        )
        self._transition(
            action="stage",
            to_phase=PublicationPhase.STAGED,
            receipts={"stage": normalized},
        )
        return normalized

    def seal(self, receipt: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        self._refresh_publication_authority()
        existing = self._receipt_after_or_at(PublicationPhase.SEALED, "seal")
        if existing is not None:
            return existing
        self._require_phase(PublicationPhase.STAGED)
        self._revalidate_inventory()
        stage_receipt = self._stored_receipt("stage")
        if self.kind is TransactionKind.SHADOW:
            value = receipt or self._shadow_receipt(
                "sealed",
                transaction_ref=self._shadow_ref(
                    "transaction", SHADOW_TRANSACTION_REF_PREFIX
                ),
                stage_receipt_ref=stage_receipt["receipt_ref"],
                expected_target_head=self._state["plan"]["expected_target_head"],
                published=False,
            )
        else:
            value = self._external_receipt("seal", receipt)
        normalized = self._validate_seal_receipt(
            value, shadow=self.kind is TransactionKind.SHADOW
        )
        self._transition(
            action="seal",
            to_phase=PublicationPhase.SEALED,
            receipts={"seal": normalized},
        )
        return normalized

    def close_compliance(
        self, receipt: Mapping[str, Any] | None = None
    ) -> Mapping[str, Any]:
        self._refresh_publication_authority()
        existing = self._receipt_after_or_at(
            PublicationPhase.COMPLIANCE_CLOSED, "compliance"
        )
        if existing is not None:
            return existing
        self._require_phase(PublicationPhase.SEALED)
        value = self._external_receipt("close_compliance", receipt)
        normalized = self._validate_compliance_receipt(
            value,
        )
        self._transition(
            action="close_compliance",
            to_phase=PublicationPhase.COMPLIANCE_CLOSED,
            receipts={"compliance": normalized},
        )
        return normalized

    def promote(self, receipt: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        self._refresh_publication_authority()
        existing = self._receipt_after_or_at(PublicationPhase.PROMOTED, "promotion")
        if existing is not None:
            return existing
        self._require_phase(PublicationPhase.COMPLIANCE_CLOSED)
        if self.kind is TransactionKind.SHADOW:
            if receipt is None:
                raise ReceiptValidationError(
                    "shadow promotion requires an external simulation receipt"
                )
            value = self._accept_supplied_receipt("promote", receipt)
            normalized = self._validate_promotion_receipt(value, shadow=True)
        else:
            value = self._external_receipt("promote", receipt)
            normalized_value = _normalize_receipt(value, "promotion")
            if normalized_value.get("status") == "target_head_conflict":
                normalized_value = self._validate_bound_receipt(
                    normalized_value,
                    "target_head_conflict",
                )
                actual_head = normalized_value.get("actual_target_head")
                _validate_optional_ref(actual_head, "actual_target_head")
                expected_head = self._state["plan"]["expected_target_head"]
                self._mark_abort_pending(
                    "target_head_conflict",
                    details={
                        "expected_target_head": expected_head,
                        "actual_target_head": actual_head,
                    },
                    receipts={"promotion_rejection": normalized_value},
                    action="promote_target_conflict",
                )
                raise TargetHeadConflict(expected_head, actual_head)
            if normalized_value.get("status") == "rejected":
                normalized_value = self._validate_bound_receipt(
                    normalized_value, "rejected"
                )
                reason = normalized_value.get("reason")
                if (
                    not isinstance(reason, str)
                    or _SAFE_REASON_RE.fullmatch(reason) is None
                ):
                    raise ReceiptValidationError(
                        "promotion rejection reason is invalid"
                    )
                self._mark_abort_pending(
                    reason,
                    details={},
                    receipts={"promotion_rejection": normalized_value},
                    action="promote_rejected",
                )
                raise PublicationRejected(f"promotion rejected: {reason}")
            normalized = self._validate_promotion_receipt(
                normalized_value, shadow=False
            )
        self._transition(
            action="promote",
            to_phase=PublicationPhase.PROMOTED,
            receipts={"promotion": normalized},
        )
        return normalized

    def commit(
        self,
        history_validation_receipt: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        self._refresh_publication_authority()
        if self.phase is PublicationPhase.COMMITTED:
            return self._stored_receipt(
                "state_advance"
                if self.kind is TransactionKind.PUBLISH
                else "shadow_completion"
            )
        self._require_phase(PublicationPhase.PROMOTED)

        stored_history = self._state["receipts"].get("history_validation")
        if stored_history is None:
            if history_validation_receipt is None:
                if self.kind is TransactionKind.SHADOW:
                    raise ReceiptValidationError(
                        "shadow commit requires an external history validation receipt"
                    )
                adapter = self._require_adapter()
                validate_history = getattr(adapter, "validate_history", None)
                if validate_history is None:
                    raise ReceiptValidationError(
                        "commit requires an external history validation receipt"
                    )
                supplied = self._invoke_adapter(
                    "validate_history",
                    validate_history,
                    self.operation_request("validate_history"),
                )
            else:
                supplied = self._accept_supplied_receipt(
                    "commit.history_validation", history_validation_receipt
                )
            history_receipt = self._validate_history_receipt(
                supplied,
                shadow=self.kind is TransactionKind.SHADOW,
            )
            self._transition(
                action="commit_history_validation",
                to_phase=PublicationPhase.PROMOTED,
                receipts={"history_validation": history_receipt},
            )
        else:
            history_receipt = deepcopy(
                _require_mapping(stored_history, "history validation receipt")
            )
            if history_validation_receipt is not None:
                supplied = self._validate_history_receipt(
                    history_validation_receipt,
                    shadow=self.kind is TransactionKind.SHADOW,
                )
                if _canonical_json_bytes(supplied) != _canonical_json_bytes(
                    history_receipt
                ):
                    raise ReceiptValidationError(
                        "history validation receipt changed during recovery"
                    )

        if self.kind is TransactionKind.SHADOW:
            completion = self._shadow_receipt(
                "shadow_completed",
                history_validation_receipt_ref=history_receipt["receipt_ref"],
                promotion_receipt_ref=self._stored_receipt("promotion")["receipt_ref"],
                published=False,
                state_advanced=False,
                reservations_released=True,
            )
            self._transition(
                action="commit",
                to_phase=PublicationPhase.COMMITTED,
                receipts={"shadow_completion": completion},
                reservations_held=False,
                state_advanced=False,
            )
            return completion

        advance_value = self._external_receipt("advance_state", None)
        advance_receipt = self._validate_state_advance_receipt(advance_value)
        self._transition(
            action="commit",
            to_phase=PublicationPhase.COMMITTED,
            receipts={"state_advance": advance_receipt},
            reservations_held=False,
            state_advanced=True,
        )
        return advance_receipt

    def _refresh_publication_authority(self) -> None:
        if self.kind is not TransactionKind.PUBLISH:
            raise PublicationRejected("shadow publication transactions are unsupported")
        self._assert_publication_claim()
        binding, identity, expected, current = self._load_publication_authority_state()
        published = self.phase in {
            PublicationPhase.PROMOTED,
            PublicationPhase.COMMITTED,
        }
        if not published:
            if canonical_json_bytes(
                current.provider_projection()
            ) != canonical_json_bytes(expected.provider_projection()):
                raise TargetHeadConflict(expected.head_commit, current.head_commit)
            authority.assert_provider_cache_matches(
                binding["provider_state"],
                expected,
                identity=identity,
            )
            return

        promotion = self._state["receipts"].get("promotion")
        if not isinstance(promotion, Mapping):
            raise StateCorruptionError(
                "promoted transaction lacks its publication receipt"
            )
        target_head = promotion.get("target_head")
        if not isinstance(target_head, str) or not self._history_matches_proposed(
            current,
            binding,
            publication_commit=target_head,
        ):
            raise PublicationRejected(
                "reachable publication does not derive the proposed durable state"
            )
        if self.phase is PublicationPhase.COMMITTED:
            authority.assert_provider_cache_matches(
                binding["provider_state"],
                current,
                identity=identity,
            )
        else:
            authority.assert_provider_cache_matches(
                binding["provider_state"],
                expected,
                identity=identity,
            )

    def _assert_publication_claim(self) -> dict[str, Any]:
        if self.kind is not TransactionKind.PUBLISH:
            raise PublicationRejected("shadow publication transactions are unsupported")
        binding = _normalize_publication_authority(
            _require_mapping(
                self._state["plan"]["publication_authority"],
                "publication authority",
            )
        )
        return _validate_persistent_publication_claim(
            run_dir=Path(binding["run_dir"]),
            identity_path=Path(binding["identity_path"]),
            attempt_ref=self.attempt_ref,
            plan_digest=self._state["plan_digest"],
        )

    def _load_publication_authority_state(
        self,
    ) -> tuple[
        dict[str, Any],
        IdentityKey,
        authority.DurableHistoryState,
        authority.DurableHistoryState,
    ]:
        binding = _normalize_publication_authority(
            _require_mapping(
                self._state["plan"]["publication_authority"],
                "publication authority",
            )
        )
        identity = IdentityKey.load(
            binding["identity_path"],
            expected_key_id=binding["identity_key_id"],
        )
        expected = authority.history_state_from_projection(
            binding["expected_history"],
            identity=identity,
        )
        current = authority.load_durable_history(
            binding["history_repo"],
            binding["target_ref"],
            identity=identity,
            expected_fingerprint=binding["publisher_fingerprint"],
            gnupg_home=binding["publisher_gnupg_home"],
        )
        marker = authority.load_production_marker(
            binding["production_marker"],
            identity=identity,
            history_repo=binding["history_repo"],
            target_ref=binding["target_ref"],
            configuration_root=binding["configuration_root"],
            configuration_ref=binding["configuration_ref"],
            model_era=binding["model_era"],
            policy_era=binding["policy_era"],
        )
        if marker["authentication_tag"] != binding["marker_authentication_tag"]:
            raise PublicationRejected(
                "production marker changed after transaction creation"
            )
        return binding, identity, expected, current

    @staticmethod
    def _history_matches_proposed(
        current: authority.DurableHistoryState,
        binding: Mapping[str, Any],
        *,
        publication_commit: str,
    ) -> bool:
        proposed = binding["proposed_durable_state"]
        return bool(
            current.publication_commit == publication_commit
            and current.provider_revision == proposed["provider_revision_after"]
            and current.cursor_root_ref == proposed["proposed_cursor_root_ref"]
            and current.episode_head_root_ref
            == proposed["proposed_episode_head_root_ref"]
            and canonical_json_bytes(list(current.cursor_rows))
            == canonical_json_bytes(proposed["proposed_cursor_rows"])
            and canonical_json_bytes(list(current.episode_heads))
            == canonical_json_bytes(proposed["proposed_episode_heads"])
            and canonical_json_bytes(list(current.episode_membership))
            == canonical_json_bytes(proposed["proposed_episode_membership"])
        )

    def _recover_durable_adapter_progress(self) -> None:
        if self.kind is not TransactionKind.PUBLISH or self._adapter is None:
            return
        if self.phase not in {
            PublicationPhase.COMPLIANCE_CLOSED,
            PublicationPhase.PROMOTED,
        }:
            return
        inspect_attempt = getattr(self._adapter, "inspect_attempt", None)
        if not callable(inspect_attempt):
            return
        raw_attempt = inspect_attempt(self.attempt_ref)
        if raw_attempt is None:
            return
        attempt = _require_mapping(raw_attempt, "durable adapter attempt")
        expected_binding = self.operation_request("recover").binding()
        if attempt.get("attempt_ref") != self.attempt_ref or canonical_json_bytes(
            attempt.get("binding")
        ) != canonical_json_bytes(expected_binding):
            raise AttemptMismatchError(
                "durable adapter attempt does not match the publication journal"
            )
        if self.phase is PublicationPhase.COMPLIANCE_CLOSED:
            prefixes = attempt.get("prefixes")
            if not isinstance(prefixes, list) or not prefixes:
                raise StateCorruptionError(
                    "reachable adapter attempt lacks its publication prefix"
                )
            tip = prefixes[-1].get("commit")
        else:
            promotion = self._state["receipts"].get("promotion")
            if not isinstance(promotion, Mapping):
                raise StateCorruptionError(
                    "promoted transaction lacks its publication receipt"
                )
            tip = promotion.get("target_head")
        if not isinstance(tip, str):
            raise StateCorruptionError(
                "durable adapter attempt lacks its publication tip"
            )
        binding, identity, _expected, current = self._load_publication_authority_state()
        if not self._history_matches_proposed(
            current,
            binding,
            publication_commit=tip,
        ):
            return

        if self.phase is PublicationPhase.COMPLIANCE_CLOSED:
            if current.publication_commit != tip:
                raise PublicationRejected(
                    "durable history does not match this attempt's reachable tip"
                )
            supplied = self._invoke_adapter(
                "recover.promote",
                self._adapter.promote,
                self.operation_request("promote"),
            )
            normalized = self._validate_promotion_receipt(supplied, shadow=False)
            if normalized["target_head"] != tip:
                raise ReceiptValidationError(
                    "recovered promotion receipt changed the reachable tip"
                )
            self._transition(
                action="recover_promote",
                to_phase=PublicationPhase.PROMOTED,
                receipts={"promotion": normalized},
            )

        if self.phase is not PublicationPhase.PROMOTED:
            return
        try:
            authority.assert_provider_cache_matches(
                binding["provider_state"],
                current,
                identity=identity,
            )
        except authority.ProviderCacheError:
            return
        if not isinstance(self._state["receipts"].get("history_validation"), Mapping):
            raise StateCorruptionError(
                "advanced provider state lacks outer history validation"
            )
        supplied = self._invoke_adapter(
            "recover.advance_state",
            self._adapter.advance_state,
            self.operation_request("advance_state"),
        )
        normalized = self._validate_state_advance_receipt(supplied)
        self._transition(
            action="recover_commit",
            to_phase=PublicationPhase.COMMITTED,
            receipts={"state_advance": normalized},
            reservations_held=False,
            state_advanced=True,
        )

    def abort(
        self,
        reason: str = "operator_abort",
        *,
        cleanup_receipt: Mapping[str, Any] | None = None,
        release_receipt: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        if self.phase is PublicationPhase.ABORTED:
            return self.recover_abort()
        if (
            self.kind is TransactionKind.PUBLISH
            and self.phase is not PublicationPhase.ABORT_PENDING
        ):
            self._assert_publication_claim()
        if self.phase in {PublicationPhase.PROMOTED, PublicationPhase.COMMITTED}:
            raise InvalidTransitionError(
                "a formally promoted attempt cannot be aborted locally"
            )
        if _SAFE_REASON_RE.fullmatch(reason) is None:
            raise ValueError("abort reason must be a lowercase typed reason")
        if self.phase is not PublicationPhase.ABORT_PENDING:
            self._mark_abort_pending(
                reason, details={}, receipts={}, action="abort_pending"
            )
        else:
            existing_reason = self._state["abort"]["reason"]
            if reason != "operator_abort" and reason != existing_reason:
                raise InvalidTransitionError(
                    f"abort reason is already immutable as {existing_reason!r}"
                )

        return self.recover_abort(
            cleanup_receipt=cleanup_receipt,
            release_receipt=release_receipt,
        )

    def recover_abort(
        self,
        *,
        cleanup_receipt: Mapping[str, Any] | None = None,
        release_receipt: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Idempotently finish only an already durable abort disposition."""

        if self.phase not in {
            PublicationPhase.ABORT_PENDING,
            PublicationPhase.ABORTED,
        }:
            raise InvalidTransitionError(
                "abort recovery requires an abort_pending or aborted transaction"
            )
        if self.kind is TransactionKind.PUBLISH and (
            cleanup_receipt is not None or release_receipt is not None
        ):
            raise ReceiptValidationError(
                "formal publication abort recovery requires provider-issued durable receipts"
            )
        if self.phase is PublicationPhase.ABORTED:
            stored_cleanup = self._stored_receipt("cleanup")
            stored_release = self._stored_receipt("reservation_release")
            self._validate_cleanup_receipt(stored_cleanup)
            self._validate_reservation_release_receipt(
                stored_release,
                cleanup_receipt=stored_cleanup,
            )
            self._validate_abort_commitment(
                self._stored_receipt("abort_commitment"),
                cleanup_receipt=stored_cleanup,
                release_receipt=stored_release,
            )
            if self.kind is TransactionKind.PUBLISH and self._adapter is not None:
                durable_cleanup = self._external_receipt("cleanup", None)
                normalized_cleanup = self._validate_cleanup_receipt(durable_cleanup)
                if _canonical_json_bytes(normalized_cleanup) != _canonical_json_bytes(
                    stored_cleanup
                ):
                    raise ReceiptValidationError(
                        "durable cleanup receipt changed during abort replay"
                    )
                durable_release = self._external_receipt("release_reservations", None)
                normalized_release = self._validate_reservation_release_receipt(
                    durable_release,
                    cleanup_receipt=stored_cleanup,
                )
                if _canonical_json_bytes(normalized_release) != _canonical_json_bytes(
                    stored_release
                ):
                    raise ReceiptValidationError(
                        "durable reservation release changed during abort replay"
                    )
            return stored_release

        stored_cleanup = self._state["receipts"].get("cleanup")
        if stored_cleanup is None:
            if self.kind is TransactionKind.SHADOW:
                cleanup_value = cleanup_receipt or self._shadow_receipt(
                    "remote_object_cleanup_complete",
                    terminal_disposition=self._expected_abort_disposition(),
                    transaction_ref=self._abort_transaction_ref(),
                    formal_reachable=False,
                    provisional_reachable=False,
                    objects_cleaned=True,
                    capacity_reconciled=True,
                    published=False,
                )
            elif cleanup_receipt is not None:
                cleanup_value = self._accept_supplied_receipt(
                    "abort.cleanup", cleanup_receipt
                )
            else:
                cleanup_value = self._external_receipt("cleanup", None)
            normalized_cleanup = self._validate_cleanup_receipt(cleanup_value)
            self._transition(
                action="abort_cleanup",
                to_phase=PublicationPhase.ABORT_PENDING,
                receipts={"cleanup": normalized_cleanup},
            )
        else:
            normalized_cleanup = deepcopy(
                _require_mapping(stored_cleanup, "cleanup receipt")
            )
            if cleanup_receipt is not None:
                supplied_cleanup = self._validate_cleanup_receipt(cleanup_receipt)
                if _canonical_json_bytes(supplied_cleanup) != _canonical_json_bytes(
                    normalized_cleanup
                ):
                    raise ReceiptValidationError(
                        "cleanup receipt changed during recovery"
                    )

        if self.kind is TransactionKind.SHADOW:
            release_value = release_receipt or self._shadow_receipt(
                "reservations_released",
                cleanup_receipt_ref=normalized_cleanup["receipt_ref"],
                reservations_released=True,
                published=False,
            )
        elif release_receipt is not None:
            release_value = self._accept_supplied_receipt(
                "abort.release_reservations", release_receipt
            )
        else:
            release_value = self._external_receipt("release_reservations", None)
        normalized_release = self._validate_reservation_release_receipt(
            release_value,
            cleanup_receipt=normalized_cleanup,
        )
        abort_commitment = self._issue_abort_commitment(
            cleanup_receipt=normalized_cleanup,
            release_receipt=normalized_release,
        )
        self._transition(
            action="abort",
            to_phase=PublicationPhase.ABORTED,
            receipts={
                "abort_commitment": abort_commitment,
                "reservation_release": normalized_release,
            },
            reservations_held=False,
            state_advanced=False,
        )
        return normalized_release

    def _issue_abort_commitment(
        self,
        *,
        cleanup_receipt: Mapping[str, Any],
        release_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        binding = _normalize_publication_authority(
            _require_mapping(
                self._state["plan"]["publication_authority"],
                "publication authority",
            )
        )
        identity = IdentityKey.load(
            binding["identity_path"],
            expected_key_id=binding["identity_key_id"],
        )
        claim = self._assert_publication_claim()
        body = {
            **self.operation_request("abort_commitment").binding(),
            "cleanup_receipt_ref": cleanup_receipt["receipt_ref"],
            "identity_key_id": identity.key_id,
            "publication_claim_ref": claim["receipt_ref"],
            "reservation_release_receipt_ref": release_receipt["receipt_ref"],
            "run_ref": claim["run_ref"],
            "schema": PUBLICATION_ABORT_COMMITMENT_SCHEMA,
            "status": "publication_abort_complete",
        }
        body["receipt_ref"] = PUBLICATION_ABORT_COMMITMENT_REF_PREFIX + (
            identity.derive_digest(PUBLICATION_ABORT_COMMITMENT_REF_PREFIX, body)
        )
        body["authentication_tag"] = PUBLICATION_ABORT_COMMITMENT_AUTH_PREFIX + (
            identity.derive_digest(PUBLICATION_ABORT_COMMITMENT_AUTH_PREFIX, body)
        )
        return _normalize_receipt(body, "abort commitment")

    def _validate_abort_commitment(
        self,
        value: Mapping[str, Any],
        *,
        cleanup_receipt: Mapping[str, Any],
        release_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        binding = _normalize_publication_authority(
            _require_mapping(
                self._state["plan"]["publication_authority"],
                "publication authority",
            )
        )
        identity = IdentityKey.load(
            binding["identity_path"],
            expected_key_id=binding["identity_key_id"],
        )
        commitment = verify_publication_abort_commitment(identity, value)
        if (
            commitment["attempt_ref"] != self.attempt_ref
            or commitment["plan_digest"] != self._state["plan_digest"]
            or commitment["inventory_digest"] != self.inventory.inventory_digest_v2
            or commitment["cleanup_receipt_ref"] != cleanup_receipt["receipt_ref"]
            or commitment["reservation_release_receipt_ref"]
            != release_receipt["receipt_ref"]
        ):
            raise ReceiptValidationError(
                "abort commitment does not bind this durable transaction"
            )
        return commitment

    def _external_receipt(
        self,
        operation: str,
        supplied: Mapping[str, Any] | None,
    ) -> Mapping[str, Any]:
        if supplied is not None:
            return self._accept_supplied_receipt(operation, supplied)
        adapter = self._require_adapter()
        callback = getattr(adapter, operation)
        return self._invoke_adapter(
            operation, callback, self.operation_request(operation)
        )

    def _accept_supplied_receipt(
        self,
        operation: str,
        receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._inject(f"{operation}.before_callback")
        normalized = _normalize_receipt(receipt, operation)
        self._inject(f"{operation}.after_callback")
        return normalized

    def _invoke_adapter(
        self,
        operation: str,
        callback: Callable[[OperationRequest], Mapping[str, Any]],
        request: OperationRequest,
    ) -> Mapping[str, Any]:
        self._inject(f"{operation}.before_callback")
        receipt = callback(request)
        self._inject(f"{operation}.after_callback")
        return receipt

    def _validate_bound_receipt(
        self,
        value: Mapping[str, Any],
        expected_status: str,
    ) -> dict[str, Any]:
        receipt = _normalize_receipt(value, expected_status)
        expected = self.operation_request(expected_status).binding()
        for key, expected_value in expected.items():
            if receipt.get(key) != expected_value:
                raise ReceiptValidationError(
                    f"{expected_status} receipt has a mismatched {key}"
                )
        if receipt.get("status") != expected_status:
            raise ReceiptValidationError(
                f"expected {expected_status!r} receipt status, got {receipt.get('status')!r}"
            )
        receipt_ref = receipt.get("receipt_ref")
        if not isinstance(receipt_ref, str):
            raise ReceiptValidationError(
                f"{expected_status} receipt has no receipt_ref"
            )
        _validate_ref(receipt_ref, "receipt_ref")
        return receipt

    def _validate_target_observation(self, value: Mapping[str, Any]) -> dict[str, Any]:
        receipt = self._validate_bound_receipt(value, "target_observed")
        _validate_optional_ref(receipt.get("target_head"), "target_head")
        if receipt.get("target_ref") != self._state["plan"]["target_ref"]:
            raise ReceiptValidationError(
                "target observation names a different target ref"
            )
        if receipt.get("destination") != self._state["plan"]["destination"]:
            raise ReceiptValidationError(
                "target observation names a different destination"
            )
        if not isinstance(receipt.get("destination_exists"), bool):
            raise ReceiptValidationError(
                "target observation destination_exists must be boolean"
            )
        return receipt

    def _validate_reservation_receipt(
        self,
        value: Mapping[str, Any],
        *,
        shadow: bool,
        observation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        receipt = self._validate_bound_receipt(value, "reserved")
        if receipt.get("reservations_held") is not True:
            raise ReceiptValidationError(
                "reservation receipt does not hold all reservations"
            )
        if shadow:
            if receipt.get("published") is not False:
                raise ReceiptValidationError(
                    "shadow reservation must be non-publishing"
                )
            if receipt.get("reservation_kind") != "shadow_local":
                raise ReceiptValidationError("shadow reservation kind is invalid")
        else:
            if observation is None:
                raise ReceiptValidationError(
                    "publication reservation lacks a target observation"
                )
            if (
                receipt.get("target_observation_receipt_ref")
                != observation["receipt_ref"]
            ):
                raise ReceiptValidationError(
                    "reservation does not bind the locked target observation"
                )
            if receipt.get("target_ref") != self._state["plan"]["target_ref"]:
                raise ReceiptValidationError("reservation has a mismatched target ref")
            if receipt.get("destination") != self._state["plan"]["destination"]:
                raise ReceiptValidationError("reservation has a mismatched destination")
            if (
                receipt.get("expected_target_head")
                != self._state["plan"]["expected_target_head"]
            ):
                raise ReceiptValidationError("reservation has a mismatched target head")
        return receipt

    def _validate_stage_receipt(
        self,
        value: Mapping[str, Any],
        *,
        shadow: bool,
    ) -> dict[str, Any]:
        receipt = self._validate_bound_receipt(value, "staged")
        if (
            receipt.get("reservation_receipt_ref")
            != self._stored_receipt("reservation")["receipt_ref"]
        ):
            raise ReceiptValidationError(
                "stage receipt does not bind the reservation receipt"
            )
        if (
            receipt.get("expected_target_head")
            != self._state["plan"]["expected_target_head"]
        ):
            raise ReceiptValidationError("stage receipt has a mismatched target head")
        _validate_ref_value(receipt.get("pack_root"), "pack_root")
        if shadow and receipt.get("published") is not False:
            raise ReceiptValidationError("shadow stage must be non-publishing")
        return receipt

    def _validate_seal_receipt(
        self,
        value: Mapping[str, Any],
        *,
        shadow: bool,
    ) -> dict[str, Any]:
        receipt = self._validate_bound_receipt(value, "sealed")
        if (
            receipt.get("stage_receipt_ref")
            != self._stored_receipt("stage")["receipt_ref"]
        ):
            raise ReceiptValidationError(
                "seal receipt does not bind the staged receipt"
            )
        if (
            receipt.get("expected_target_head")
            != self._state["plan"]["expected_target_head"]
        ):
            raise ReceiptValidationError("seal receipt has a mismatched target head")
        _validate_ref_value(receipt.get("transaction_ref"), "transaction_ref")
        if shadow and receipt.get("published") is not False:
            raise ReceiptValidationError("shadow seal must be non-publishing")
        return receipt

    def _validate_compliance_receipt(
        self,
        value: Mapping[str, Any],
    ) -> dict[str, Any]:
        receipt = self._validate_bound_receipt(value, "prepublication_validated")
        seal = self._stored_receipt("seal")
        if receipt.get("transaction_ref") != seal["transaction_ref"]:
            raise ReceiptValidationError(
                "compliance receipt has a mismatched transaction"
            )
        if receipt.get("seal_receipt_ref") != seal["receipt_ref"]:
            raise ReceiptValidationError(
                "compliance receipt does not bind the seal receipt"
            )
        if receipt.get("candidate_validated") is not True:
            raise ReceiptValidationError(
                "prepublication receipt does not validate the candidate"
            )
        if receipt.get("provider_cache_matches_history") is not True:
            raise ReceiptValidationError(
                "prepublication receipt does not validate provider derivation"
            )
        if receipt.get("published") is not False:
            raise ReceiptValidationError(
                "prepublication validation cannot claim publish"
            )
        return receipt

    def _validate_promotion_receipt(
        self,
        value: Mapping[str, Any],
        *,
        shadow: bool,
    ) -> dict[str, Any]:
        status = "shadow_promoted" if shadow else "promoted"
        receipt = self._validate_bound_receipt(value, status)
        seal = self._stored_receipt("seal")
        compliance = self._stored_receipt("compliance")
        if receipt.get("transaction_ref") != seal["transaction_ref"]:
            raise ReceiptValidationError(
                "promotion receipt has a mismatched transaction"
            )
        if receipt.get("compliance_receipt_ref") != compliance["receipt_ref"]:
            raise ReceiptValidationError(
                "promotion receipt does not bind compliance closure"
            )
        expected_head = self._state["plan"]["expected_target_head"]
        if receipt.get("previous_target_head") != expected_head:
            raise ReceiptValidationError(
                "promotion receipt has a mismatched previous target head"
            )
        if shadow:
            if receipt.get("published") is not False:
                raise ReceiptValidationError("shadow promotion must be non-publishing")
            if receipt.get("target_head") != expected_head:
                raise ReceiptValidationError("shadow promotion changed the target head")
            if receipt.get("append_only_simulation") is not True:
                raise ReceiptValidationError(
                    "shadow promotion did not validate append-only simulation"
                )
        else:
            if receipt.get("published") is not True:
                raise ReceiptValidationError(
                    "promotion receipt does not prove formal publication"
                )
            if receipt.get("append_only") is not True:
                raise ReceiptValidationError(
                    "promotion receipt does not prove append-only promotion"
                )
            target_head = receipt.get("target_head")
            _validate_ref_value(target_head, "target_head")
            if target_head == expected_head:
                raise ReceiptValidationError(
                    "promotion did not advance the target head"
                )
        return receipt

    def _validate_history_receipt(
        self,
        value: Mapping[str, Any],
        *,
        shadow: bool,
    ) -> dict[str, Any]:
        status = "shadow_history_validated" if shadow else "history_validated"
        receipt = self._validate_bound_receipt(value, status)
        promotion = self._stored_receipt("promotion")
        seal = self._stored_receipt("seal")
        if receipt.get("promotion_receipt_ref") != promotion["receipt_ref"]:
            raise ReceiptValidationError(
                "history receipt does not bind the promotion receipt"
            )
        if receipt.get("transaction_ref") != seal["transaction_ref"]:
            raise ReceiptValidationError("history receipt has a mismatched transaction")
        if receipt.get("target_ref") != self._state["plan"]["target_ref"]:
            raise ReceiptValidationError("history receipt has a mismatched target ref")
        if receipt.get("destination") != self._state["plan"]["destination"]:
            raise ReceiptValidationError("history receipt has a mismatched destination")

        expected_head = self._state["plan"]["expected_target_head"]
        if shadow:
            if receipt.get("published") is not False:
                raise ReceiptValidationError(
                    "shadow history validation must be non-publishing"
                )
            if receipt.get("target_head_before") != expected_head:
                raise ReceiptValidationError(
                    "shadow validation has a mismatched base target head"
                )
            if receipt.get("target_head_after") != expected_head:
                raise ReceiptValidationError(
                    "shadow validation changed the target head"
                )
            if receipt.get("append_only_simulation") is not True:
                raise ReceiptValidationError(
                    "shadow validation lacks append-only simulation proof"
                )
            if receipt.get("candidate_artifacts") != self.expected_shadow_artifacts():
                raise ReceiptValidationError(
                    "shadow validation candidate inventory is not exact"
                )
        else:
            if receipt.get("base_target_head") != expected_head:
                raise ReceiptValidationError(
                    "history validation has a mismatched base target head"
                )
            if receipt.get("target_head") != promotion["target_head"]:
                raise ReceiptValidationError(
                    "history validation has a mismatched promoted head"
                )
            if (
                receipt.get("append_only") is not True
                or receipt.get("reachable") is not True
            ):
                raise ReceiptValidationError(
                    "history validation lacks append-only reachability proof"
                )
            if receipt.get("added_artifacts") != self.expected_added_artifacts():
                raise ReceiptValidationError(
                    "history validation added artifact inventory is not exact"
                )
            if (
                receipt.get("modified_paths") != []
                or receipt.get("removed_paths") != []
            ):
                raise ReceiptValidationError(
                    "history validation reports modified or removed paths"
                )
        return receipt

    def _validate_state_advance_receipt(
        self, value: Mapping[str, Any]
    ) -> dict[str, Any]:
        receipt = self._validate_bound_receipt(value, "state_advanced")
        promotion = self._stored_receipt("promotion")
        history = self._stored_receipt("history_validation")
        seal = self._stored_receipt("seal")
        if receipt.get("transaction_ref") != seal["transaction_ref"]:
            raise ReceiptValidationError(
                "state advancement has a mismatched transaction"
            )
        if receipt.get("target_head") != promotion["target_head"]:
            raise ReceiptValidationError(
                "state advancement has a mismatched target head"
            )
        if receipt.get("promotion_receipt_ref") != promotion["receipt_ref"]:
            raise ReceiptValidationError("state advancement does not bind promotion")
        if receipt.get("history_validation_receipt_ref") != history["receipt_ref"]:
            raise ReceiptValidationError(
                "state advancement does not bind history validation"
            )
        if receipt.get("reservations_released") is not True:
            raise ReceiptValidationError(
                "state advancement did not consume and release reservations"
            )
        expected_vector = self._state["plan"].get("host_cursor_vector", {})
        if receipt.get("host_cursor_vector") != expected_vector:
            raise ReceiptValidationError(
                "state advancement has a mismatched per-host cursor vector"
            )
        expected_heads = self._state["plan"]["episode_head_update"]
        if (
            receipt.get("expected_episode_head_set_ref")
            != expected_heads["expected_episode_head_set_ref"]
            or receipt.get("proposed_episode_head_set_ref")
            != expected_heads["proposed_episode_head_set_ref"]
            or receipt.get("backfill_lineage_receipt_ref")
            != (
                None
                if expected_heads["backfill_lineage_receipt"] is None
                else expected_heads["backfill_lineage_receipt"]["receipt_ref"]
            )
        ):
            raise ReceiptValidationError(
                "state advancement has a mismatched episode head-set CAS"
            )
        revision_before = receipt.get("state_revision_before")
        revision_after = receipt.get("state_revision_after")
        if (
            not isinstance(revision_before, int)
            or isinstance(revision_before, bool)
            or not isinstance(revision_after, int)
            or isinstance(revision_after, bool)
            or revision_after != revision_before + 1
        ):
            raise ReceiptValidationError(
                "state advancement has invalid provider-state revisions"
            )
        return receipt

    def _validate_cleanup_receipt(self, value: Mapping[str, Any]) -> dict[str, Any]:
        receipt = self._validate_bound_receipt(value, "remote_object_cleanup_complete")
        if receipt.get("terminal_disposition") != self._expected_abort_disposition():
            raise ReceiptValidationError(
                "cleanup receipt has the wrong terminal disposition"
            )
        if receipt.get("transaction_ref") != self._abort_transaction_ref():
            raise ReceiptValidationError(
                "cleanup receipt has a mismatched sealed transaction"
            )
        for field in ("formal_reachable", "provisional_reachable"):
            if receipt.get(field) is not False:
                raise ReceiptValidationError(
                    f"cleanup receipt does not prove {field}=false"
                )
        for field in ("objects_cleaned", "capacity_reconciled"):
            if receipt.get(field) is not True:
                raise ReceiptValidationError(
                    f"cleanup receipt does not prove {field}=true"
                )
        if self.kind is TransactionKind.PUBLISH:
            claim_ref = receipt.get("cleanup_claim_ref")
            if not isinstance(claim_ref, str) or not claim_ref.startswith(
                LOCAL_GIT_CLEANUP_CLAIM_PREFIX
            ):
                raise ReceiptValidationError(
                    "formal cleanup receipt lacks a provider cleanup claim"
                )
            reserved = receipt.get("provider_attempt_reserved")
            capacity = receipt.get("capacity_bytes_observed")
            if not isinstance(reserved, bool) or (
                not isinstance(capacity, int)
                or isinstance(capacity, bool)
                or capacity < 0
            ):
                raise ReceiptValidationError(
                    "formal cleanup receipt has invalid reservation accounting"
                )
            if (reserved and capacity <= 0) or (not reserved and capacity != 0):
                raise ReceiptValidationError(
                    "formal cleanup reservation accounting is inconsistent"
                )
        return receipt

    def _validate_reservation_release_receipt(
        self,
        value: Mapping[str, Any],
        *,
        cleanup_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        if "cleanup" not in self._state["receipts"]:
            raise InvalidTransitionError(
                "reservations cannot release before cleanup is durable"
            )
        receipt = self._validate_bound_receipt(value, "reservations_released")
        if receipt.get("cleanup_receipt_ref") != cleanup_receipt["receipt_ref"]:
            raise ReceiptValidationError("reservation release does not bind cleanup")
        if self.kind is TransactionKind.PUBLISH and receipt.get(
            "cleanup_claim_ref"
        ) != cleanup_receipt.get("cleanup_claim_ref"):
            raise ReceiptValidationError(
                "reservation release does not bind the provider cleanup claim"
            )
        if receipt.get("reservations_released") is not True:
            raise ReceiptValidationError("reservation release receipt is incomplete")
        return receipt

    def _expected_abort_disposition(self) -> str:
        return (
            "sealed_rejected"
            if "seal" in self._state["receipts"]
            else "no_seal_abandoned"
        )

    def _abort_transaction_ref(self) -> str | None:
        seal = self._state["receipts"].get("seal")
        return seal.get("transaction_ref") if isinstance(seal, Mapping) else None

    def _shadow_receipt(self, status: str, **fields: Any) -> dict[str, Any]:
        receipt = self.operation_request(status).binding()
        receipt.update(
            {
                "status": status,
                "receipt_ref": self._shadow_ref(f"receipt:{status}"),
            }
        )
        receipt.update(fields)
        return _normalize_receipt(receipt, status)

    def _shadow_ref(self, label: str, prefix: str = SHADOW_RECEIPT_REF_PREFIX) -> str:
        payload = (
            f"{self.attempt_ref}\x00{self._state['plan_digest']}\x00{label}".encode(
                "utf-8"
            )
        )
        return f"{prefix}{hashlib.sha256(payload).hexdigest()}"

    def _mark_abort_pending(
        self,
        reason: str,
        *,
        details: Mapping[str, Any],
        receipts: Mapping[str, Mapping[str, Any]],
        action: str,
    ) -> None:
        if _SAFE_REASON_RE.fullmatch(reason) is None:
            raise ValueError("abort reason must be a lowercase typed reason")
        abort = {"reason": reason, "details": _json_clone(details)}
        self._transition(
            action=action,
            to_phase=PublicationPhase.ABORT_PENDING,
            receipts=receipts,
            abort=abort,
        )

    def _transition(
        self,
        *,
        action: str,
        to_phase: PublicationPhase,
        receipts: Mapping[str, Mapping[str, Any]] | None = None,
        abort: Mapping[str, Any] | None = None,
        reservations_held: bool | None = None,
        state_advanced: bool | None = None,
    ) -> None:
        expected_revision = self._state["revision"]
        expected_state_digest = self._state["state_digest"]
        new_state = deepcopy(self._state)
        old_phase = new_state["phase"]
        if receipts:
            for name, receipt in receipts.items():
                normalized = _normalize_receipt(receipt, name)
                existing = new_state["receipts"].get(name)
                if existing is not None and _canonical_json_bytes(
                    existing
                ) != _canonical_json_bytes(normalized):
                    raise StateCorruptionError(f"receipt {name!r} is immutable")
                new_state["receipts"][name] = normalized
        if abort is not None:
            if new_state["abort"] is not None and new_state["abort"] != abort:
                raise StateCorruptionError("abort metadata is immutable")
            new_state["abort"] = _json_clone(abort)
        if reservations_held is not None:
            new_state["reservations_held"] = reservations_held
        if state_advanced is not None:
            new_state["state_advanced"] = state_advanced
        new_state["phase"] = to_phase.value
        details = {
            "receipt_refs": {
                name: receipt["receipt_ref"]
                for name, receipt in (receipts or {}).items()
            },
            "reservations_held": new_state["reservations_held"],
            "state_advanced": new_state["state_advanced"],
        }
        if abort is not None:
            details["abort_reason"] = abort["reason"]
        event = _new_event(
            new_state["events"],
            attempt_ref=self.attempt_ref,
            action=action,
            from_phase=old_phase,
            to_phase=to_phase.value,
            details=details,
        )
        new_state["events"].append(event)
        new_state["revision"] = event["sequence"]
        new_state["state_digest"] = _state_digest(new_state)
        self._validate_state(new_state)
        with _anchored_lock(self._state_directory, f".{self._journal_name}.lock"):
            current = self._state_directory.read_json(self._journal_name)
            self._validate_state(current)
            if (
                current["attempt_ref"] != self.attempt_ref
                or current["revision"] != expected_revision
                or current["state_digest"] != expected_state_digest
            ):
                self._state = current
                raise GenerationConflict(
                    "publication journal revision changed; reopen and recover"
                )
            self._state_directory.write_json(self._journal_name, new_state)
        self._state = new_state
        self._inject(f"{action}.after_persist")

    def _receipt_after_or_at(
        self,
        phase: PublicationPhase,
        receipt_name: str,
    ) -> Mapping[str, Any] | None:
        current = self.phase
        if current in {PublicationPhase.ABORT_PENDING, PublicationPhase.ABORTED}:
            return None
        if _NORMAL_PHASE_INDEX[current] >= _NORMAL_PHASE_INDEX[phase]:
            return self._stored_receipt(receipt_name)
        return None

    def _stored_receipt(self, name: str) -> dict[str, Any]:
        receipt = self._state["receipts"].get(name)
        if receipt is None:
            raise StateCorruptionError(f"missing durable {name} receipt")
        return deepcopy(_require_mapping(receipt, f"receipt {name}"))

    def _require_phase(self, expected: PublicationPhase) -> None:
        if self.phase is not expected:
            raise InvalidTransitionError(
                f"{expected.value} operation requires {expected.value!r} predecessor state; "
                f"current state is {self.phase.value!r}"
            )

    def _require_adapter(self) -> PublicationAdapter:
        if self._adapter is None:
            raise PublicationError(
                "publishing transaction requires an injected adapter"
            )
        return self._adapter

    def _revalidate_inventory(self) -> None:
        current = build_artifact_inventory(Path(self._state["plan"]["bundle_dir"]))
        if current.to_dict() != self.inventory.to_dict():
            raise ArtifactValidationError(
                "publication bundle changed after attempt creation"
            )

    def _inject(self, point: str) -> None:
        if self._failure_injector is not None:
            self._failure_injector(point, deepcopy(self._state))

    @staticmethod
    def _validate_state(state: Mapping[str, Any]) -> None:
        required_keys = {
            "schema_version",
            "attempt_ref",
            "kind",
            "phase",
            "plan",
            "plan_digest",
            "inventory",
            "receipts",
            "abort",
            "reservations_held",
            "state_advanced",
            "revision",
            "events",
            "state_digest",
        }
        if set(state) != required_keys:
            raise StateCorruptionError("publication state has an unexpected shape")
        if state["schema_version"] != STATE_SCHEMA_VERSION:
            raise StateCorruptionError("unsupported publication state schema")
        try:
            _validate_attempt_ref(state["attempt_ref"])
        except ValueError as exc:
            raise StateCorruptionError(str(exc)) from exc
        try:
            kind = TransactionKind(state["kind"])
            phase = PublicationPhase(state["phase"])
        except (TypeError, ValueError) as exc:
            raise StateCorruptionError("publication kind or phase is invalid") from exc
        plan = _require_mapping(state["plan"], "plan")
        base_plan_keys = {
            "attempt_ref",
            "kind",
            "bundle_dir",
            "destination",
            "target_ref",
            "expected_target_head",
            "inventory_digest_v2",
        }
        required_plan_keys = base_plan_keys | {
            "episode_head_update",
            "host_cursor_vector",
            "publication_authority",
        }
        if set(plan) != required_plan_keys:
            raise StateCorruptionError("publication plan has an unexpected shape")
        if plan["attempt_ref"] != state["attempt_ref"] or plan["kind"] != kind.value:
            raise StateCorruptionError("publication plan identity does not match state")
        if (
            not isinstance(plan["bundle_dir"], str)
            or not Path(plan["bundle_dir"]).is_absolute()
        ):
            raise StateCorruptionError("publication bundle path must be absolute")
        _validate_destination_state(plan["destination"])
        _validate_ref_state(plan["target_ref"], "target_ref")
        _validate_optional_ref_state(
            plan["expected_target_head"], "expected_target_head"
        )
        inventory = ArtifactInventory.from_dict(
            _require_mapping(state["inventory"], "inventory")
        )
        if plan["inventory_digest_v2"] != inventory.inventory_digest_v2:
            raise StateCorruptionError(
                "publication plan inventory digest is inconsistent"
            )
        try:
            normalized_cursor_vector = _normalize_host_cursor_vector(
                _require_mapping(
                    plan.get("host_cursor_vector", {}), "host_cursor_vector"
                )
            )
        except (StateCorruptionError, ValueError) as exc:
            raise StateCorruptionError(
                f"publication host cursor vector is invalid: {exc}"
            ) from exc
        if plan.get("host_cursor_vector", {}) != normalized_cursor_vector:
            raise StateCorruptionError(
                "publication host cursor vector is not canonical"
            )
        try:
            normalized_episode_update = _normalize_episode_head_update(
                _require_mapping(plan["episode_head_update"], "episode_head_update"),
                required=kind is TransactionKind.PUBLISH,
            )
            normalized_authorization = _normalize_publication_authority(
                _require_mapping(plan["publication_authority"], "publication_authority")
            )
        except (StateCorruptionError, ValueError) as exc:
            raise StateCorruptionError(
                f"publication formal authorization is invalid: {exc}"
            ) from exc
        if (
            plan["episode_head_update"] != normalized_episode_update
            or plan["publication_authority"] != normalized_authorization
        ):
            raise StateCorruptionError(
                "publication formal authorization is not canonical"
            )
        if kind is TransactionKind.SHADOW:
            raise StateCorruptionError(
                "shadow publication transactions are unsupported"
            )
        if state["plan_digest"] != _sha256_json(plan):
            raise StateCorruptionError("publication plan digest is inconsistent")
        receipts = _require_mapping(state["receipts"], "receipts")
        allowed_receipts = {
            "abort_commitment",
            "cleanup",
            "compliance",
            "history_validation",
            "promotion",
            "promotion_rejection",
            "reservation",
            "reservation_release",
            "seal",
            "shadow_completion",
            "stage",
            "state_advance",
            "target_observation",
        }
        if not set(receipts).issubset(allowed_receipts):
            raise StateCorruptionError(
                "publication state contains an unknown receipt kind"
            )
        for name, receipt in receipts.items():
            if not isinstance(name, str):
                raise StateCorruptionError("receipt names must be strings")
            receipt_value = _require_mapping(receipt, f"receipt {name}")
            if receipt_value.get("attempt_ref") != state["attempt_ref"]:
                raise StateCorruptionError(
                    f"receipt {name!r} belongs to another attempt"
                )
            if receipt_value.get("plan_digest") != state["plan_digest"]:
                raise StateCorruptionError(f"receipt {name!r} belongs to another plan")
            if receipt_value.get("inventory_digest") != inventory.inventory_digest_v2:
                raise StateCorruptionError(
                    f"receipt {name!r} belongs to another inventory"
                )
        if not isinstance(state["reservations_held"], bool) or not isinstance(
            state["state_advanced"], bool
        ):
            raise StateCorruptionError("publication state booleans are invalid")
        if state["state_advanced"] and phase is not PublicationPhase.COMMITTED:
            raise StateCorruptionError("state advancement is only legal after commit")
        if phase is PublicationPhase.COMMITTED and state["reservations_held"]:
            raise StateCorruptionError("committed publication still holds reservations")
        if phase is PublicationPhase.ABORTED and state["reservations_held"]:
            raise StateCorruptionError("aborted publication still holds reservations")
        if phase in {PublicationPhase.ABORT_PENDING, PublicationPhase.ABORTED}:
            abort = _require_mapping(state["abort"], "abort")
            reason = abort.get("reason")
            if not isinstance(reason, str) or _SAFE_REASON_RE.fullmatch(reason) is None:
                raise StateCorruptionError("abort reason is invalid")
        elif state["abort"] is not None:
            raise StateCorruptionError(
                "non-aborting publication contains abort metadata"
            )
        if kind is TransactionKind.SHADOW and state["state_advanced"]:
            raise StateCorruptionError(
                "shadow transaction cannot advance canonical state"
            )
        _validate_phase_receipts(
            phase=phase,
            kind=kind,
            receipts=receipts,
            reservations_held=state["reservations_held"],
            state_advanced=state["state_advanced"],
        )
        _validate_event_chain(state)
        if state["state_digest"] != _state_digest(state):
            raise StateCorruptionError("publication state digest is inconsistent")
