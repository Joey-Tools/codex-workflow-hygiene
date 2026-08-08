"""Constrained local Git provider for retained history publication."""

from __future__ import annotations
from collections.abc import Callable, Mapping
from copy import deepcopy
import fcntl
import os
from pathlib import Path
from typing import Any
from . import export as retained_export

from .publication_support import (
    AppendOnlyViolation,
    DEFAULT_PUBLICATION_CAPACITY_BYTES,
    DEFAULT_PUBLISHER_FINGERPRINT,
    DEFAULT_PUBLISHER_GNUPG_HOME,
    DEFAULT_PUBLISHER_UID,
    DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
    FailureInjector,
    InvalidTransitionError,
    LOCAL_GIT_CHAIN_PREFIX,
    LocalGitPublicationError,
    MAX_SUBPROCESS_OUTPUT_BYTES,
    OperationRequest,
    PUBLICATION_CAPACITY_OVERHEAD_BYTES,
    PublicationRejected,
    ReceiptValidationError,
    RetainedExportLifecycle,
    STATE_SCHEMA_VERSION,
    StateCorruptionError,
    TargetHeadConflict,
    _AnchoredStateDirectory,
    _canonical_json_bytes,
    _normalize_cursor_store_hosts,
    _publication_chain_root,
    _resolve_executable,
    _validate_cursor_state,
    _validate_destination,
    _validate_episode_heads_state,
    _validate_generation_state,
    _validate_local_cleanup_claim,
    _validate_ref,
)


from .publication_git_commits import LocalGitCommitOperations
from .publication_git_capacity import LocalGitCapacityOperations
from .publication_git_storage import LocalGitStorageOperations


class LocalGitPublicationAdapter(
    LocalGitCapacityOperations,
    LocalGitStorageOperations,
    LocalGitCommitOperations,
):
    """Owner-only, resumable local-Git implementation of ``PublicationAdapter``.

    The adapter writes Git objects through a temporary index and keeps every
    prepared prefix reachable from an attempt-scoped ref.  The formal target is
    moved only by one exact-old-value ``git update-ref`` operation in
    :meth:`promote`.  All provider receipts are durable and keyed by the
    publication attempt, so the first prepare can discover a reservation made
    before the coordinator persisted its own receipt.
    """

    def __init__(
        self,
        repo_path: str | os.PathLike[str],
        state_dir: str | os.PathLike[str],
        *,
        signing_key: str | os.PathLike[str] | None = DEFAULT_PUBLISHER_FINGERPRINT,
        signing_format: str = "openpgp",
        gnupg_home: str | os.PathLike[str] | None = DEFAULT_PUBLISHER_GNUPG_HOME,
        expected_signer_uid: str = DEFAULT_PUBLISHER_UID,
        allowed_signers_file: str | os.PathLike[str] | None = None,
        signing_program: str | os.PathLike[str] | None = None,
        policy_generation: str = "policy_generation_v2:initial",
        key_generation: str = "key_generation_v2:initial",
        capacity_limit_bytes: int = DEFAULT_PUBLICATION_CAPACITY_BYTES,
        compliance_checker: Callable[[OperationRequest], bool] | None = None,
        failure_injector: FailureInjector | None = None,
        git_binary: str | os.PathLike[str] = "git",
        subprocess_timeout_seconds: float = DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        subprocess_output_limit_bytes: int = MAX_SUBPROCESS_OUTPUT_BYTES,
        retained_export_lifecycle: RetainedExportLifecycle = retained_export,
    ) -> None:
        self._repo = Path(repo_path).absolute()
        self._state_dir = Path(state_dir).absolute()
        self._attempts_dir = self._state_dir / "attempts"
        self._publication_lock_path = self._state_dir / "publication.lock"
        self._generation_path = self._state_dir / "generations.json"
        self._capacity_path = self._state_dir / "capacity.json"
        self._cursor_state_path = self._state_dir / "cursor-state.json"
        self._episode_heads_path = self._state_dir / "episode-heads.json"
        self._provider_cas_journal_path = self._state_dir / "provider-cas-v2.json"
        self._git_binary = _resolve_executable(git_binary, label="Git")
        self._signing_key = None if signing_key is None else os.fspath(signing_key)
        self._signing_format = signing_format
        self._gnupg_home = None if gnupg_home is None else Path(gnupg_home).absolute()
        self._expected_signer_uid = expected_signer_uid
        self._allowed_signers_file = (
            None
            if allowed_signers_file is None
            else Path(allowed_signers_file).absolute()
        )
        self._signing_program = _resolve_executable(
            signing_program or "gpg", label="GPG"
        )
        self._subprocess_timeout_seconds = float(subprocess_timeout_seconds)
        self._subprocess_output_limit_bytes = subprocess_output_limit_bytes
        self._capacity_limit_bytes = capacity_limit_bytes
        self._compliance_checker = compliance_checker
        self._failure_injector = failure_injector
        self._retained_export_lifecycle = retained_export_lifecycle
        self._held_publication_locks: dict[str, int] = {}
        self._held_attempt_directories: dict[str, _AnchoredStateDirectory] = {}

        if signing_format != "openpgp" or self._allowed_signers_file is not None:
            raise LocalGitPublicationError(
                "formal publication requires the dedicated OpenPGP publisher key"
            )
        if (
            not isinstance(capacity_limit_bytes, int)
            or isinstance(capacity_limit_bytes, bool)
            or capacity_limit_bytes <= 0
        ):
            raise ValueError("capacity_limit_bytes must be a positive integer")
        if (
            not isinstance(subprocess_timeout_seconds, (int, float))
            or isinstance(subprocess_timeout_seconds, bool)
            or not 0 < float(subprocess_timeout_seconds) < float("inf")
        ):
            raise ValueError(
                "subprocess_timeout_seconds must be a positive finite number"
            )
        if (
            not isinstance(subprocess_output_limit_bytes, int)
            or isinstance(subprocess_output_limit_bytes, bool)
            or subprocess_output_limit_bytes <= 0
        ):
            raise ValueError("subprocess_output_limit_bytes must be a positive integer")
        _validate_ref(policy_generation, "policy_generation")
        _validate_ref(key_generation, "key_generation")

        self._validate_repo()
        self._validate_signing_identity()
        self._initialize_owner_only_state(
            policy_generation=policy_generation,
            key_generation=key_generation,
        )

    @property
    def repo_path(self) -> Path:
        return self._repo

    @property
    def state_dir(self) -> Path:
        return self._state_dir

    def inspect_attempt(self, attempt_ref: str) -> dict[str, Any] | None:
        """Return the durable provider journal for recovery/status inspection."""

        state = self._read_attempt(attempt_ref, missing_ok=True)
        return None if state is None else deepcopy(state)

    def read_generations(self) -> dict[str, Any]:
        value = self._state_directory.read_json(self._generation_path.name)
        _validate_generation_state(value)
        return value

    def set_generations(
        self,
        *,
        policy_generation: str | None = None,
        key_generation: str | None = None,
    ) -> dict[str, Any]:
        """Advance the policy/key generation under the short publication lock."""

        if policy_generation is not None:
            _validate_ref(policy_generation, "policy_generation")
        if key_generation is not None:
            _validate_ref(key_generation, "key_generation")
        with self._short_publication_lock():
            current = self.read_generations()
            updated = dict(current)
            if policy_generation is not None:
                updated["policy_generation"] = policy_generation
            if key_generation is not None:
                updated["key_generation"] = key_generation
            if updated != current:
                updated["revision"] = int(current["revision"]) + 1
                self._state_directory.write_json(self._generation_path.name, updated)
            return deepcopy(updated)

    def read_cursor_state(self) -> dict[str, Any]:
        value = self._state_directory.read_json(self._cursor_state_path.name)
        _validate_cursor_state(value)
        return value

    def read_episode_heads_state(self) -> dict[str, Any]:
        value = self._state_directory.read_json(self._episode_heads_path.name)
        _validate_episode_heads_state(value)
        return value

    def inspect(self, request: OperationRequest) -> dict[str, Any]:
        """Inspect formal target facts and any durable attempt journal."""

        return {
            "attempt": self.inspect_attempt(request.attempt_ref),
            "target": deepcopy(dict(self.inspect_target(request))),
        }

    def inspect_target_state(
        self,
        target_ref: str,
        *,
        destination: str | None = None,
    ) -> dict[str, Any]:
        """Inspect a formal ref before a transaction or caller receipt exists."""

        _validate_ref(target_ref, "target_ref")
        if destination is not None:
            _validate_destination(destination)
        with self._short_publication_lock():
            target_head = self._read_ref(target_ref)
            destination_exists = (
                None
                if destination is None
                else self._path_exists_at(target_head, destination)
            )
        return {
            "destination": destination,
            "destination_exists": destination_exists,
            "target_head": target_head,
            "target_ref": target_ref,
        }

    def initialize_cursor_state(
        self, hosts: Mapping[str, Mapping[str, Any]]
    ) -> dict[str, Any]:
        """Seed an empty local cursor store for migration/bootstrap tests and setup."""

        normalized_hosts = _normalize_cursor_store_hosts(hosts)
        with self._short_publication_lock():
            current = self.read_cursor_state()
            if current["hosts"]:
                if current["hosts"] != normalized_hosts:
                    raise StateCorruptionError(
                        "cursor state is already initialized differently"
                    )
                return current
            if (
                current["revision"] != 0
                or current["last_publication"] is not None
                or current["applied_publications"]
            ):
                raise StateCorruptionError(
                    "cursor state cannot be initialized after publication"
                )
            updated = {
                "applied_publications": {},
                "hosts": normalized_hosts,
                "last_publication": None,
                "revision": 0,
                "schema_version": STATE_SCHEMA_VERSION,
            }
            self._state_directory.write_json(self._cursor_state_path.name, updated)
            return deepcopy(updated)

    def acquire_publication_lock(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        if request.attempt_ref in self._held_publication_locks:
            raise LocalGitPublicationError(
                "publication lock is already held by this adapter"
            )
        descriptor = self._state_directory.open_lock(self._publication_lock_path.name)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self._held_publication_locks[request.attempt_ref] = descriptor
        return self._receipt(request, "locked", lock_scope="prepare_cas")

    def preflight_prepare(self, request: OperationRequest) -> Mapping[str, Any]:
        """Fail closed on signing identity before taking the prepare lock."""

        self._require_publish_request(request)
        self._validate_signing_identity()
        return self._receipt(
            request, "prepare_preflight_complete", signing_identity_checked=True
        )

    def release_publication_lock(
        self,
        request: OperationRequest,
        lock_receipt: Mapping[str, Any],
    ) -> None:
        descriptor = self._held_publication_locks.pop(request.attempt_ref, None)
        if descriptor is None:
            raise LocalGitPublicationError("publication lock is not held")
        expected = self._receipt(request, "locked", lock_scope="prepare_cas")
        if _canonical_json_bytes(lock_receipt) != _canonical_json_bytes(expected):
            self._held_publication_locks[request.attempt_ref] = descriptor
            raise ReceiptValidationError(
                "publication lock receipt is not bound to this attempt"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        with self._attempt_lock(request.attempt_ref, create=True):
            state = self._read_attempt(request.attempt_ref, missing_ok=True)
            if state is None:
                return
            self._assert_attempt_binding(state, request)
            if state["cleanup_claim"] is not None or state["aborted"]:
                return
            bound_units = self._bind_export_retention_sidecars(
                request,
                state["unit_plan"],
            )
            if bound_units != len(state["unit_plan"]):
                raise StateCorruptionError(
                    "retained export binding did not cover every publication unit"
                )
            self._inject("release_publication_lock.after_retention_bind", state)
            if not state["retention_bound"]:
                state["retention_bound"] = True
                self._write_attempt(state)

    def inspect_target(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        actual_head = self._read_ref(request.target_ref)
        destination_exists = self._path_exists_at(actual_head, request.destination)
        return self._target_observation(
            request,
            target_head=actual_head,
            destination_exists=destination_exists,
        )

    def reserve(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        if request.attempt_ref not in self._held_publication_locks:
            raise LocalGitPublicationError(
                "reserve requires the short publication lock"
            )

        existing = self._read_attempt(request.attempt_ref, missing_ok=True)
        if existing is not None:
            self._assert_attempt_binding(existing, request)
            reservation = existing["receipts"].get("reservation")
            if reservation is None:
                raise StateCorruptionError(
                    "reserved local attempt has no reservation receipt"
                )
            if self._capacity_reservation_locked(request) != existing["capacity_bytes"]:
                raise StateCorruptionError(
                    "reserved local attempt differs from provider capacity"
                )
            return deepcopy(reservation)

        actual_head = self._read_ref(request.target_ref)
        if actual_head != request.expected_target_head:
            raise TargetHeadConflict(request.expected_target_head, actual_head)
        if self._path_exists_at(actual_head, request.destination):
            raise AppendOnlyViolation(
                f"append-only destination already exists: {request.destination}"
            )

        provider_state_snapshot = self._provider_state_snapshot(request)
        generations = self.read_generations()
        units = self._unit_plan_for_request(request)
        capacity_bytes = max(
            1,
            sum(int(unit["inventory"]["total_bytes"]) for unit in units)
            + PUBLICATION_CAPACITY_OVERHEAD_BYTES,
        )
        self._reserve_capacity(request, capacity_bytes)
        self._inject(
            "reserve.after_capacity_persist",
            {
                "attempt_ref": request.attempt_ref,
                "capacity_bytes": capacity_bytes,
            },
        )
        observation = self._target_observation(
            request,
            target_head=actual_head,
            destination_exists=False,
        )
        reservation = self._receipt(
            request,
            "reserved",
            capacity_bytes=capacity_bytes,
            destination=request.destination,
            expected_target_head=request.expected_target_head,
            key_generation=generations["key_generation"],
            policy_generation=generations["policy_generation"],
            reservations_held=True,
            target_observation_receipt_ref=observation["receipt_ref"],
            target_ref=request.target_ref,
        )
        state = {
            "aborted": False,
            "attempt_ref": request.attempt_ref,
            "binding": request.binding(),
            "capacity_bytes": capacity_bytes,
            "capacity_held": True,
            "cleanup_claim": None,
            "expected_target_head": request.expected_target_head,
            "episode_head_update": deepcopy(dict(request.episode_head_update)),
            "formal_promoted": False,
            "generation_snapshot": {
                "key_generation": generations["key_generation"],
                "policy_generation": generations["policy_generation"],
                "revision": generations["revision"],
            },
            "host_cursor_vector": deepcopy(dict(request.host_cursor_vector)),
            "publication_authority": deepcopy(dict(request.publication_authority)),
            "provider_state_snapshot": provider_state_snapshot,
            "prefixes": [],
            "receipts": {
                "reservation": reservation,
                "target_observation": observation,
            },
            "retention_bound": False,
            "schema_version": STATE_SCHEMA_VERSION,
            "staging_ref": self._staging_ref(request.attempt_ref),
            "state_advanced": False,
            "target_ref": request.target_ref,
            "unit_plan": units,
        }
        self._write_attempt(state)
        self._inject("reserve.after_persist", state)
        return reservation

    def stage(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref):
            state = self._required_attempt(request)
            self._require_forward_attempt(state, "stage")
            existing = state["receipts"].get("stage")
            if existing is not None:
                self._validate_local_chain(state, request)
                return deepcopy(existing)
            reservation = state["receipts"]["reservation"]
            request_reservation = request.receipts.get("reservation")
            if request_reservation is None or _canonical_json_bytes(
                request_reservation
            ) != _canonical_json_bytes(reservation):
                raise ReceiptValidationError(
                    "stage request does not carry the durable reservation"
                )

            validated_units = self._validate_publication_units(state, request)
            parent = request.expected_target_head
            if parent is None:
                raise LocalGitPublicationError(
                    "local Git publication currently requires an existing formal target"
                )
            for ordinal, unit in enumerate(validated_units):
                prefixes = state["prefixes"]
                if ordinal < len(prefixes):
                    prefix = prefixes[ordinal]
                    if prefix["parent"] != parent:
                        raise StateCorruptionError(
                            "stored publication prefix has a broken parent chain"
                        )
                    self._validate_publication_commit(
                        commit=prefix["commit"],
                        parent=parent,
                        unit=unit,
                        ordinal=ordinal,
                        attempt_ref=request.attempt_ref,
                        plan_digest=request.plan_digest,
                    )
                    parent = prefix["commit"]
                    continue
                if ordinal != len(prefixes):
                    raise StateCorruptionError(
                        "publication prefix ordinals are not contiguous"
                    )

                observed_ref = self._read_ref(state["staging_ref"])
                if observed_ref not in {None, parent}:
                    recovered = self._recover_uncheckpointed_prefix(
                        state=state,
                        request=request,
                        parent=parent,
                        unit=unit,
                        ordinal=ordinal,
                        observed_ref=observed_ref,
                    )
                    if recovered is None:
                        raise TargetHeadConflict(parent, observed_ref)
                    commit = recovered
                else:
                    if observed_ref is None and ordinal > 0:
                        raise StateCorruptionError(
                            "attempt staging ref disappeared during publication stage"
                        )
                    commit = self._create_signed_publication_commit(
                        parent=parent,
                        unit=unit,
                        ordinal=ordinal,
                        attempt_ref=request.attempt_ref,
                        plan_digest=request.plan_digest,
                    )
                    self._advance_attempt_ref(
                        state["staging_ref"],
                        commit,
                        expected=observed_ref,
                    )
                    # Crash injection begins only after the signed object is reachable.
                    self._inject(f"stage.after_commit_object.{ordinal}", state)
                    self._inject(f"stage.after_ref_update.{ordinal}", state)

                prefix = {
                    "bundle_digest": unit["inventory"].retained_bundle_digest_v2,
                    "commit": commit,
                    "destination": unit["destination"],
                    "inventory_digest": unit["inventory"].inventory_digest_v2,
                    "ordinal": ordinal,
                    "parent": parent,
                    "publication_role": unit["publication_role"],
                }
                state["prefixes"].append(prefix)
                self._write_attempt(state)
                self._inject(f"stage.after_prefix_persist.{ordinal}", state)
                parent = commit

            chain_root = _publication_chain_root(state["prefixes"])
            receipt = self._receipt(
                request,
                "staged",
                campaign=False,
                expected_target_head=request.expected_target_head,
                pack_root=f"{LOCAL_GIT_CHAIN_PREFIX}{chain_root}",
                prefix_count=len(state["prefixes"]),
                reservation_receipt_ref=reservation["receipt_ref"],
                staging_ref=state["staging_ref"],
                tip=parent,
            )
            state["receipts"]["stage"] = receipt
            self._write_attempt(state)
            self._inject("stage.after_persist", state)
            return deepcopy(receipt)

    def seal(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref):
            state = self._required_attempt(request)
            self._require_forward_attempt(state, "seal")
            existing = state["receipts"].get("seal")
            if existing is not None:
                self._validate_local_chain(state, request)
                return deepcopy(existing)
            stage_receipt = state["receipts"].get("stage")
            if stage_receipt is None or request.receipts.get("stage") != stage_receipt:
                raise ReceiptValidationError(
                    "seal request does not bind the durable stage receipt"
                )
            self._validate_local_chain(state, request)
            tip = state["prefixes"][-1]["commit"]
            transaction_ref = self._transaction_ref(request, tip)
            receipt = self._receipt(
                request,
                "sealed",
                chain_root=stage_receipt["pack_root"],
                expected_target_head=request.expected_target_head,
                stage_receipt_ref=stage_receipt["receipt_ref"],
                tip=tip,
                transaction_ref=transaction_ref,
            )
            state["receipts"]["seal"] = receipt
            self._write_attempt(state)
            self._inject("seal.after_persist", state)
            return deepcopy(receipt)

    def close_compliance(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref):
            state = self._required_attempt(request)
            self._require_forward_attempt(state, "close compliance")
            existing = state["receipts"].get("compliance")
            if existing is not None:
                return deepcopy(existing)
            seal = state["receipts"].get("seal")
            if seal is None or request.receipts.get("seal") != seal:
                raise ReceiptValidationError(
                    "compliance closure does not bind the durable seal receipt"
                )
            self._validate_local_chain(state, request)
            if self._compliance_checker is not None and not self._compliance_checker(
                request
            ):
                raise PublicationRejected(
                    "local compliance checker rejected publication"
                )
            generations = self.read_generations()
            receipt = self._receipt(
                request,
                "prepublication_validated",
                candidate_validated=True,
                key_generation=generations["key_generation"],
                policy_generation=generations["policy_generation"],
                provider_cache_matches_history=True,
                published=False,
                seal_receipt_ref=seal["receipt_ref"],
                transaction_ref=seal["transaction_ref"],
            )
            state["receipts"]["compliance"] = receipt
            self._write_attempt(state)
            self._inject("close_compliance.after_persist", state)
            return deepcopy(receipt)

    def promote(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref):
            state = self._required_attempt(request)
            self._require_forward_attempt(state, "promote")
            existing = state["receipts"].get("promotion")
            if existing is not None:
                self._validate_formal_reachability(state, existing["target_head"])
                return deepcopy(existing)
            compliance = state["receipts"].get("compliance")
            if compliance is None or request.receipts.get("compliance") != compliance:
                raise ReceiptValidationError(
                    "promotion does not bind compliance closure"
                )
            self._validate_local_chain(state, request)

            self._validate_signing_identity()

            tip = state["prefixes"][-1]["commit"]
            observed_head = self._read_ref(request.target_ref)
            observed_already_formal = observed_head == tip or self._is_ancestor(
                tip, observed_head
            )
            generation_rejection: dict[str, Any] | None = None
            with self._short_publication_lock():
                actual_head = self._read_ref(request.target_ref)
                already_formal = actual_head == tip or (
                    actual_head == observed_head and observed_already_formal
                )
                if not already_formal and actual_head != request.expected_target_head:
                    return self._receipt(
                        request,
                        "target_head_conflict",
                        actual_target_head=actual_head,
                    )
                if not already_formal:
                    generation_rejection = self._promotion_generation_rejection(
                        state, request
                    )
                    if generation_rejection is None:
                        generation_rejection = self._promotion_provider_rejection(
                            state,
                            request,
                        )
                    if generation_rejection is None:
                        self._inject("promote.before_target_cas", state)
                        try:
                            self._update_ref(
                                request.target_ref,
                                tip,
                                expected=request.expected_target_head,
                            )
                        except TargetHeadConflict:
                            return self._receipt(
                                request,
                                "target_head_conflict",
                                actual_target_head=self._read_ref(request.target_ref),
                            )
                        self._inject("promote.after_target_cas", state)

            if generation_rejection is not None:
                state["receipts"]["promotion_rejection"] = generation_rejection
                self._write_attempt(state)
                return generation_rejection

            self._validate_formal_reachability(state, tip)
            receipt = self._receipt(
                request,
                "promoted",
                append_only=True,
                compliance_receipt_ref=compliance["receipt_ref"],
                previous_target_head=request.expected_target_head,
                published=True,
                target_head=tip,
                transaction_ref=state["receipts"]["seal"]["transaction_ref"],
            )
            state["formal_promoted"] = True
            state["receipts"]["promotion"] = receipt
            self._write_attempt(state)
            self._inject("promote.after_persist", state)
            return deepcopy(receipt)

    def validate_history(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref):
            state = self._required_attempt(request)
            existing = state["receipts"].get("history_validation")
            if existing is not None:
                return deepcopy(existing)
            promotion = state["receipts"].get("promotion")
            if promotion is None or request.receipts.get("promotion") != promotion:
                raise ReceiptValidationError(
                    "history validation does not bind the durable promotion receipt"
                )
            self._validate_local_chain(state, request)
            self._validate_formal_reachability(state, promotion["target_head"])
            added_artifacts = {
                f"{request.destination}/{artifact.name}": {
                    "sha256": artifact.sha256,
                    "size": artifact.size,
                }
                for artifact in request.inventory.artifacts
            }
            publication_artifacts = self._all_publication_artifacts(state)
            receipt = self._receipt(
                request,
                "history_validated",
                added_artifacts=added_artifacts,
                append_only=True,
                base_target_head=request.expected_target_head,
                destination=request.destination,
                modified_paths=[],
                promotion_receipt_ref=promotion["receipt_ref"],
                publication_artifacts=publication_artifacts,
                reachable=True,
                removed_paths=[],
                target_head=promotion["target_head"],
                target_ref=request.target_ref,
                transaction_ref=state["receipts"]["seal"]["transaction_ref"],
            )
            state["receipts"]["history_validation"] = receipt
            self._write_attempt(state)
            self._inject("validate_history.after_persist", state)
            return deepcopy(receipt)

    def advance_state(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref):
            state = self._required_attempt(request)
            existing = state["receipts"].get("state_advance")
            if existing is not None:
                self._release_export_retention_sidecars(
                    request,
                    state["unit_plan"],
                    disposition="committed",
                )
                return deepcopy(existing)
            history = state["receipts"].get("history_validation")
            promotion = state["receipts"].get("promotion")
            if history is None or promotion is None:
                raise InvalidTransitionError(
                    "state cannot advance before history validation"
                )
            if request.receipts.get("history_validation") != history:
                raise ReceiptValidationError(
                    "state advancement does not bind history validation"
                )

            revision_before, revision_after = self._advance_provider_state(
                state, request
            )
            self._inject("advance_state.after_provider_cas", state)
            tip = promotion["target_head"]
            self._delete_attempt_ref_if_exact(state["staging_ref"], tip)
            self._release_capacity(request, int(state["capacity_bytes"]))
            receipt = self._receipt(
                request,
                "state_advanced",
                history_validation_receipt_ref=history["receipt_ref"],
                host_cursor_vector=deepcopy(dict(request.host_cursor_vector)),
                expected_episode_head_set_ref=request.episode_head_update[
                    "expected_episode_head_set_ref"
                ],
                proposed_episode_head_set_ref=request.episode_head_update[
                    "proposed_episode_head_set_ref"
                ],
                backfill_lineage_receipt_ref=(
                    None
                    if request.episode_head_update["backfill_lineage_receipt"] is None
                    else request.episode_head_update["backfill_lineage_receipt"][
                        "receipt_ref"
                    ]
                ),
                promotion_receipt_ref=promotion["receipt_ref"],
                reservations_released=True,
                state_revision_after=revision_after,
                state_revision_before=revision_before,
                target_head=tip,
                transaction_ref=state["receipts"]["seal"]["transaction_ref"],
            )
            state["capacity_held"] = False
            state["state_advanced"] = True
            state["receipts"]["state_advance"] = receipt
            self._write_attempt(state)
            self._inject("advance_state.after_persist", state)
            self._release_export_retention_sidecars(
                request,
                state["unit_plan"],
                disposition="committed",
            )
            return deepcopy(receipt)

    def cleanup(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref, create=True):
            state = self._read_attempt(request.attempt_ref, missing_ok=True)
            if state is None:
                capacity = self._capacity_reservation(request)
                state = self._read_attempt(request.attempt_ref, missing_ok=True)
                if state is None:
                    state = (
                        self._unreserved_abort_state(request)
                        if capacity is None
                        else self._orphaned_reservation_abort_state(
                            request,
                            capacity_bytes=capacity,
                        )
                    )
                else:
                    self._assert_attempt_binding(state, request)
            else:
                self._assert_attempt_binding(state, request)

            raw_claim = state["cleanup_claim"]
            if raw_claim is None:
                claim = self._local_cleanup_claim(state, request)
                state["cleanup_claim"] = claim
                self._write_attempt(state)
                self._inject("cleanup.after_claim_persist", state)
            else:
                claim = _validate_local_cleanup_claim(raw_claim, state)

            existing = state["receipts"].get("cleanup")
            if existing is not None:
                self._validate_durable_local_cleanup(state, request)
                self._release_export_retention_sidecars(
                    request,
                    state["unit_plan"],
                    disposition="aborted",
                )
                return deepcopy(existing)

            target_head = self._delete_claimed_local_staging(claim, request)
            disposition = (
                "sealed_rejected"
                if "seal" in state["receipts"]
                else "no_seal_abandoned"
            )
            receipt = self._receipt(
                request,
                "remote_object_cleanup_complete",
                capacity_bytes_observed=claim["capacity_bytes_observed"],
                capacity_reconciled=True,
                cleanup_claim_ref=claim["claim_ref"],
                formal_reachable=False,
                formal_target_head_after_cleanup=target_head,
                objects_cleaned=True,
                provider_attempt_reserved=claim["provider_attempt_reserved"],
                provisional_reachable=False,
                retention_bound=claim["retention_bound"],
                staging_ref=claim["staging_ref"],
                staging_tip=claim["staging_tip"],
                terminal_disposition=disposition,
                transaction_ref=claim["transaction_ref"],
            )
            state["aborted"] = True
            state["receipts"]["cleanup"] = receipt
            self._write_attempt(state)
            self._inject("cleanup.after_persist", state)
            self._release_export_retention_sidecars(
                request,
                state["unit_plan"],
                disposition="aborted",
            )
            return deepcopy(receipt)

    def release_reservations(self, request: OperationRequest) -> Mapping[str, Any]:
        self._require_publish_request(request)
        with self._attempt_lock(request.attempt_ref):
            state = self._required_attempt(request)
            existing = state["receipts"].get("reservation_release")
            if existing is not None:
                self._validate_durable_local_cleanup(state, request)
                if self._capacity_reservation(request) is not None:
                    raise StateCorruptionError(
                        "released publication still holds provider capacity"
                    )
                return deepcopy(existing)
            cleanup = state["receipts"].get("cleanup")
            if cleanup is None or request.receipts.get("cleanup") != cleanup:
                raise ReceiptValidationError(
                    "reservation release does not bind durable cleanup"
                )
            self._validate_durable_local_cleanup(state, request)
            claim = _validate_local_cleanup_claim(state["cleanup_claim"], state)
            self._release_capacity(
                request,
                claim["capacity_reservation_observed"],
            )
            if self._capacity_reservation(request) is not None:
                raise StateCorruptionError(
                    "publication capacity remains held after release"
                )
            receipt = self._receipt(
                request,
                "reservations_released",
                capacity_bytes_released=claim["capacity_bytes_observed"],
                cleanup_claim_ref=claim["claim_ref"],
                cleanup_receipt_ref=cleanup["receipt_ref"],
                reservations_released=True,
            )
            state["capacity_held"] = False
            state["receipts"]["reservation_release"] = receipt
            self._write_attempt(state)
            self._inject("release_reservations.after_persist", state)
            return deepcopy(receipt)

    def compliance_close(self, request: OperationRequest) -> Mapping[str, Any]:
        return self.close_compliance(request)

    def validate(self, request: OperationRequest) -> Mapping[str, Any]:
        return self.validate_history(request)

    def advance(self, request: OperationRequest) -> Mapping[str, Any]:
        return self.advance_state(request)

    def abort(self, request: OperationRequest) -> Mapping[str, Any]:
        cleanup = self.cleanup(request)
        receipts = {
            name: deepcopy(dict(value)) for name, value in request.receipts.items()
        }
        receipts["cleanup"] = deepcopy(dict(cleanup))
        release_request = OperationRequest(
            phase="abort",
            attempt_ref=request.attempt_ref,
            kind=request.kind,
            target_ref=request.target_ref,
            expected_target_head=request.expected_target_head,
            destination=request.destination,
            plan_digest=request.plan_digest,
            inventory=request.inventory,
            receipts=receipts,
            bundle_dir=request.bundle_dir,
            host_cursor_vector=request.host_cursor_vector,
            episode_head_update=request.episode_head_update,
            publication_authority=request.publication_authority,
        )
        return self.release_reservations(release_request)
