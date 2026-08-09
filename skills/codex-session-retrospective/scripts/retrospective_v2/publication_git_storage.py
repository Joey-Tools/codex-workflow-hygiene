"""Constrained local Git provider for retained history publication."""

from __future__ import annotations
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import os
from pathlib import Path
import stat
from typing import Any
from . import git_safety, safe_io

from .publication_support import (
    ARTIFACT_NAMES_BYTEWISE,
    ATTEMPT_REF_PREFIX,
    ArtifactInventory,
    ArtifactValidationError,
    AttemptMismatchError,
    InvalidTransitionError,
    LOCAL_GIT_CLEANUP_CLAIM_PREFIX,
    LOCAL_GIT_CLEANUP_CLAIM_SCHEMA,
    LOCAL_GIT_RECEIPT_PREFIX,
    LOCAL_GIT_TRANSACTION_PREFIX,
    LocalGitPublicationError,
    MAX_RECEIPT_BYTES,
    OperationRequest,
    PublicationRejected,
    RETAINED_BUNDLE_DOMAIN_V2,
    STATE_SCHEMA_VERSION,
    StateCorruptionError,
    TransactionKind,
    _AnchoredStateDirectory,
    _canonical_json_bytes,
    _local_cleanup_state_binding_digest,
    _normalize_publication_authority,
    _normalize_receipt,
    _parse_declared_bundle_digest,
    _parse_json_object,
    _require_mapping,
    _sha256_json,
    _validate_attempt_ref,
    _validate_capacity_ledger,
    _validate_cursor_state,
    _validate_destination,
    _validate_episode_heads_state,
    _validate_generation_state,
    _validate_local_attempt_state,
    _validate_local_cleanup_claim,
    _validate_local_receipt_integrity,
    validate_publisher_keyring,
)


class LocalGitStorageOperations:
    """Anchored provider state, reservations, and cleanup operations."""

    def _git_publication_unit(
        self,
        *,
        commit: str,
        destination: str,
        inventory: ArtifactInventory,
    ) -> dict[str, Any]:
        artifacts: dict[str, bytes] = {}
        for record in inventory.artifacts:
            path = f"{destination}/{record.name}"
            content = self._git(
                ("show", f"{commit}:{path}"),
                max_output_bytes=record.size + MAX_RECEIPT_BYTES,
            ).stdout
            if len(content) != record.size or hashlib.sha256(content).hexdigest() != (
                record.sha256
            ):
                raise ArtifactValidationError(
                    f"formally reachable Git object differs for {path}"
                )
            artifacts[record.name] = content

        manifest = _parse_json_object(artifacts["manifest.json"], "manifest.json")
        declared_digest = _parse_declared_bundle_digest(
            manifest.get("retained_bundle_digest_v2")
        )
        projection = dict(manifest)
        projection.pop("retained_bundle_digest_v2", None)
        projection_bytes = _canonical_json_bytes(projection) + b"\n"
        bundle_hasher = hashlib.sha256()
        bundle_hasher.update(RETAINED_BUNDLE_DOMAIN_V2)
        for name in ARTIFACT_NAMES_BYTEWISE:
            name_bytes = name.encode("ascii")
            bundle_hasher.update(len(name_bytes).to_bytes(2, "big"))
            bundle_hasher.update(name_bytes)
            content = projection_bytes if name == "manifest.json" else artifacts[name]
            bundle_hasher.update(len(content).to_bytes(8, "big"))
            bundle_hasher.update(content)
        if (
            declared_digest != inventory.retained_bundle_digest_v2
            or bundle_hasher.hexdigest() != inventory.retained_bundle_digest_v2
            or manifest.get("publication_role") != "standalone"
        ):
            raise ArtifactValidationError(
                "formally reachable retained bundle does not match its inventory"
            )
        return {
            "artifacts": artifacts,
            "destination": destination,
            "inventory": inventory,
            "manifest": manifest,
            "publication_role": "standalone",
        }

    def _initialize_owner_only_state(
        self,
        *,
        policy_generation: str,
        key_generation: str,
    ) -> None:
        self._state_directory = _AnchoredStateDirectory.open(
            self._state_dir, create=True
        )
        self._attempts_directory = self._state_directory.child(
            self._attempts_dir.name, create=True
        )
        descriptor = self._state_directory.open_lock(self._publication_lock_path.name)
        os.close(descriptor)
        with self._short_publication_lock():
            if not self._state_directory.exists(self._generation_path.name):
                self._state_directory.create_json(
                    self._generation_path.name,
                    {
                        "key_generation": key_generation,
                        "policy_generation": policy_generation,
                        "revision": 0,
                        "schema_version": STATE_SCHEMA_VERSION,
                    },
                )
            else:
                _validate_generation_state(self.read_generations())
            if not self._state_directory.exists(self._capacity_path.name):
                self._state_directory.create_json(
                    self._capacity_path.name,
                    {
                        "limit_bytes": self._capacity_limit_bytes,
                        "reservations": {},
                        "schema_version": STATE_SCHEMA_VERSION,
                    },
                )
            else:
                ledger = self._state_directory.read_json(self._capacity_path.name)
                _validate_capacity_ledger(ledger)
                if ledger["limit_bytes"] != self._capacity_limit_bytes:
                    raise StateCorruptionError(
                        "configured publication capacity differs from durable ledger"
                    )
            if not self._state_directory.exists(self._cursor_state_path.name):
                self._state_directory.create_json(
                    self._cursor_state_path.name,
                    {
                        "applied_publications": {},
                        "hosts": {},
                        "last_publication": None,
                        "revision": 0,
                        "schema_version": STATE_SCHEMA_VERSION,
                    },
                )
            else:
                _validate_cursor_state(self.read_cursor_state())
            if self._state_directory.exists(self._episode_heads_path.name):
                _validate_episode_heads_state(self.read_episode_heads_state())
            self._recover_provider_cas()

    def _validate_repo(self) -> None:
        self._git_directory_identity(self._repo)
        result = self._git(("rev-parse", "--is-inside-work-tree"), check=False)
        if result.returncode != 0 or result.stdout.strip() != b"true":
            raise LocalGitPublicationError(f"not a Git repository: {self._repo}")
        git_dir = self._git_path("--git-dir")
        common_dir = self._git_path("--git-common-dir")
        object_store = common_dir / "objects"
        if self._git_path("--git-path", "objects") != object_store:
            raise LocalGitPublicationError("Git object store path is not closed")
        paths = (git_dir, common_dir, object_store)
        self._git_metadata_anchors = {
            path: self._git_directory_identity(path) for path in paths
        }
        self._forbidden_git_metadata = {
            object_store / "info" / "alternates": "Git object alternates",
            common_dir / "info" / "grafts": "Git grafts",
        }
        self._reject_forbidden_git_metadata()
        try:
            git_safety.validate_complete_local_repository_commands(
                lambda args: self._git(args, check=False)
            )
        except ValueError as error:
            raise LocalGitPublicationError(
                "Git repository must be complete and non-promisor"
            ) from error
        self._git_dir = git_dir

    def _git_path(self, option: str, *values: str) -> Path:
        result = self._git(
            ("rev-parse", "--path-format=absolute", option, *values),
            check=False,
        )
        path = Path(os.fsdecode(result.stdout).strip())
        if result.returncode != 0 or not path.is_absolute():
            raise LocalGitPublicationError("Git metadata path is invalid")
        return path

    @staticmethod
    def _git_directory_identity(path: Path) -> tuple[int, ...]:
        try:
            return safe_io.owner_controlled_directory_identity(path)
        except (OSError, safe_io.UnsafePathError) as exc:
            raise LocalGitPublicationError(
                "Git metadata requires a current-user-controlled real directory"
            ) from exc

    def _revalidate_git_metadata(self) -> None:
        for path, expected in getattr(self, "_git_metadata_anchors", {}).items():
            if self._git_directory_identity(path) != expected:
                raise LocalGitPublicationError("Git metadata changed after validation")
        self._reject_forbidden_git_metadata()

    def _reject_forbidden_git_metadata(self) -> None:
        for path, label in getattr(self, "_forbidden_git_metadata", {}).items():
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise LocalGitPublicationError(
                    f"{label} cannot be authenticated"
                ) from exc
            raise LocalGitPublicationError(f"{label} are not allowed")

    def _validate_signing_identity(self) -> None:
        if self._signing_format != "openpgp":
            raise LocalGitPublicationError(
                "formal publication requires the dedicated OpenPGP publisher key"
            )
        if self._signing_key is None or self._gnupg_home is None:
            raise LocalGitPublicationError(
                "OpenPGP publication requires an explicit key and GNUPGHOME"
            )
        identity = validate_publisher_keyring(
            gnupg_home=self._gnupg_home,
            fingerprint=self._signing_key,
            expected_uid=self._expected_signer_uid,
            gpg_program=self._signing_program,
            timeout_seconds=self._subprocess_timeout_seconds,
        )
        self._signing_key = identity["fingerprint"]

    @contextmanager
    def _short_publication_lock(self):
        descriptor = self._state_directory.open_lock(self._publication_lock_path.name)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @contextmanager
    def _attempt_lock(self, attempt_ref: str, *, create: bool = False):
        attempt_name = self._attempt_name(attempt_ref)
        try:
            attempt_directory = self._attempts_directory.child(
                attempt_name,
                create=create,
            )
        except FileNotFoundError:
            raise StateCorruptionError(
                f"local publication attempt is not reserved: {attempt_ref}"
            ) from None
        descriptor = attempt_directory.open_lock("attempt.lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._held_attempt_directories[attempt_ref] = attempt_directory
            yield
        finally:
            self._held_attempt_directories.pop(attempt_ref, None)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
                attempt_directory.close()

    def _attempt_name(self, attempt_ref: str) -> str:
        _validate_attempt_ref(attempt_ref)
        return attempt_ref.removeprefix(ATTEMPT_REF_PREFIX)

    def _attempt_dir(self, attempt_ref: str) -> Path:
        return self._attempts_dir / self._attempt_name(attempt_ref)

    def _attempt_state_path(self, attempt_ref: str) -> Path:
        return self._attempt_dir(attempt_ref) / "provider-state.json"

    def _read_attempt(
        self,
        attempt_ref: str,
        *,
        missing_ok: bool = False,
    ) -> dict[str, Any] | None:
        attempt_directory = self._held_attempt_directories.get(attempt_ref)
        close_directory = False
        if attempt_directory is None:
            try:
                attempt_directory = self._attempts_directory.child(
                    self._attempt_name(attempt_ref)
                )
                close_directory = True
            except FileNotFoundError:
                attempt_directory = None
        if attempt_directory is None or not attempt_directory.exists(
            "provider-state.json"
        ):
            if close_directory and attempt_directory is not None:
                attempt_directory.close()
            if missing_ok:
                return None
            raise StateCorruptionError(
                f"local publication attempt is missing: {attempt_ref}"
            )
        try:
            state = attempt_directory.read_json("provider-state.json")
        finally:
            if close_directory:
                attempt_directory.close()
        _validate_local_attempt_state(state)
        return state

    def _write_attempt(self, state: Mapping[str, Any]) -> None:
        _validate_local_attempt_state(state)
        attempt_ref = str(state["attempt_ref"])
        attempt_directory = self._held_attempt_directories.get(attempt_ref)
        close_directory = False
        if attempt_directory is None:
            attempt_directory = self._attempts_directory.child(
                self._attempt_name(attempt_ref), create=True
            )
            close_directory = True
        try:
            attempt_directory.write_json("provider-state.json", state)
        finally:
            if close_directory:
                attempt_directory.close()

    def _required_attempt(self, request: OperationRequest) -> dict[str, Any]:
        state = self._read_attempt(request.attempt_ref)
        assert state is not None
        self._assert_attempt_binding(state, request)
        return state

    @staticmethod
    def _require_forward_attempt(
        state: Mapping[str, Any],
        operation: str,
    ) -> None:
        if state.get("cleanup_claim") is not None:
            raise InvalidTransitionError(
                f"cleanup-owned local publication cannot {operation}"
            )

    def _assert_attempt_binding(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> None:
        if state.get("binding") != request.binding():
            raise AttemptMismatchError("local Git provider attempt binding changed")
        if state.get("target_ref") != request.target_ref:
            raise AttemptMismatchError("local Git provider target ref changed")
        if state.get("expected_target_head") != request.expected_target_head:
            raise AttemptMismatchError(
                "local Git provider expected target head changed"
            )
        if state.get("host_cursor_vector") != dict(request.host_cursor_vector):
            raise AttemptMismatchError("local Git provider host cursor vector changed")
        if state.get("episode_head_update") != dict(request.episode_head_update):
            raise AttemptMismatchError("local Git provider episode head update changed")
        if state.get("publication_authority") != dict(request.publication_authority):
            raise AttemptMismatchError(
                "local Git provider publication authority changed"
            )

    def _require_publish_request(self, request: OperationRequest) -> None:
        if request.kind != TransactionKind.PUBLISH.value:
            raise InvalidTransitionError(
                "shadow mode cannot call the formal local Git adapter"
            )
        _validate_attempt_ref(request.attempt_ref)
        if not request.target_ref.startswith("refs/heads/"):
            raise LocalGitPublicationError(
                "formal target must be a fully qualified heads ref"
            )
        result = self._git(("check-ref-format", request.target_ref), check=False)
        if result.returncode != 0:
            raise LocalGitPublicationError(
                f"invalid Git target ref: {request.target_ref}"
            )
        _validate_destination(request.destination)
        binding = _normalize_publication_authority(request.publication_authority)
        if (
            Path(binding["history_repo"]).absolute() != self._repo
            or Path(binding["provider_state"]).absolute() != self._state_dir
            or binding["target_ref"] != request.target_ref
            or binding["destination"] != request.destination
            or binding["candidate_digest"]
            != request.inventory.retained_bundle_digest_v2
        ):
            raise LocalGitPublicationError(
                "provider configuration differs from persisted publication authority"
            )

    def _receipt(
        self, request: OperationRequest, status: str, **fields: Any
    ) -> dict[str, Any]:
        body = request.binding()
        body.update({"status": status})
        body.update(fields)
        digest = _sha256_json(body)
        body["receipt_ref"] = f"{LOCAL_GIT_RECEIPT_PREFIX}{digest}"
        return _normalize_receipt(body, status)

    def _target_observation(
        self,
        request: OperationRequest,
        *,
        target_head: str | None,
        destination_exists: bool,
    ) -> dict[str, Any]:
        return self._receipt(
            request,
            "target_observed",
            destination=request.destination,
            destination_exists=destination_exists,
            target_head=target_head,
            target_ref=request.target_ref,
        )

    def _transaction_ref(self, request: OperationRequest, tip: str) -> str:
        digest = hashlib.sha256(
            f"{request.attempt_ref}\x00{request.plan_digest}\x00{tip}".encode("ascii")
        ).hexdigest()
        return f"{LOCAL_GIT_TRANSACTION_PREFIX}{digest}"

    def _staging_ref(self, attempt_ref: str) -> str:
        return (
            "refs/retrospective-v2/attempts/"
            f"{attempt_ref.removeprefix(ATTEMPT_REF_PREFIX)}"
        )

    def _unit_plan_for_request(self, request: OperationRequest) -> list[dict[str, Any]]:
        return [
            {
                "bundle_dir": request.bundle_dir,
                "destination": request.destination,
                "inventory": request.inventory.to_dict(),
            }
        ]

    def _unreserved_abort_state(self, request: OperationRequest) -> dict[str, Any]:
        generations = self.read_generations()
        return {
            "aborted": False,
            "attempt_ref": request.attempt_ref,
            "binding": request.binding(),
            "capacity_bytes": 0,
            "capacity_held": False,
            "cleanup_claim": None,
            "episode_head_update": deepcopy(dict(request.episode_head_update)),
            "expected_target_head": request.expected_target_head,
            "formal_promoted": False,
            "generation_snapshot": {
                "key_generation": generations["key_generation"],
                "policy_generation": generations["policy_generation"],
                "revision": generations["revision"],
            },
            "host_cursor_vector": deepcopy(dict(request.host_cursor_vector)),
            "prefixes": [],
            "provider_state_snapshot": self._expected_provider_state_snapshot(request),
            "publication_authority": deepcopy(dict(request.publication_authority)),
            "receipts": {},
            "retention_bound": False,
            "schema_version": STATE_SCHEMA_VERSION,
            "staging_ref": self._staging_ref(request.attempt_ref),
            "state_advanced": False,
            "target_ref": request.target_ref,
            "unit_plan": self._unit_plan_for_request(request),
        }

    def _orphaned_reservation_abort_state(
        self,
        request: OperationRequest,
        *,
        capacity_bytes: int,
    ) -> dict[str, Any]:
        if capacity_bytes <= 0:
            raise StateCorruptionError(
                "orphaned publication capacity reservation is invalid"
            )
        state = self._unreserved_abort_state(request)
        state["capacity_bytes"] = capacity_bytes
        state["capacity_held"] = True
        state["receipts"]["reservation"] = self._receipt(
            request,
            "orphaned_reservation_recovered",
            capacity_bytes=capacity_bytes,
            recovery_only=True,
            reservations_held=True,
        )
        return state

    def _local_cleanup_claim(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> dict[str, Any]:
        tip = state["prefixes"][-1]["commit"] if state["prefixes"] else None
        staging_tip = self._read_ref(str(state["staging_ref"]))
        if staging_tip != tip:
            raise StateCorruptionError(
                "local cleanup staging ref differs from the durable attempt tip"
            )
        target_head = self._read_ref(request.target_ref)
        if tip is not None and self._is_ancestor(tip, target_head):
            raise PublicationRejected(
                "formally reachable publication must recover commit instead of aborting"
            )

        capacity = self._capacity_reservation(request)
        expected_capacity = int(state["capacity_bytes"])
        if state["capacity_held"]:
            if capacity != expected_capacity:
                raise StateCorruptionError(
                    "local cleanup capacity differs from the durable reservation"
                )
        elif capacity is not None:
            raise StateCorruptionError(
                "unreserved local cleanup unexpectedly holds provider capacity"
            )
        reserved = state["receipts"].get("reservation") is not None
        if not reserved and (
            state["capacity_held"] or expected_capacity != 0 or state["prefixes"]
        ):
            raise StateCorruptionError(
                "unreserved local cleanup contains reserved provider resources"
            )

        seal = state["receipts"].get("seal")
        body = {
            "attempt_ref": request.attempt_ref,
            "capacity_bytes_observed": expected_capacity,
            "capacity_reservation_observed": capacity,
            "expected_target_head": request.expected_target_head,
            "formal_target_head_at_claim": target_head,
            "provider_attempt_reserved": reserved,
            "retention_bound": state["retention_bound"],
            "schema": LOCAL_GIT_CLEANUP_CLAIM_SCHEMA,
            "staging_ref": state["staging_ref"],
            "staging_tip": tip,
            "state_binding_digest": self._local_cleanup_binding_digest(state),
            "terminal_disposition": (
                "sealed_rejected" if seal is not None else "no_seal_abandoned"
            ),
            "transaction_ref": (
                seal.get("transaction_ref") if isinstance(seal, Mapping) else None
            ),
        }
        body["claim_ref"] = LOCAL_GIT_CLEANUP_CLAIM_PREFIX + _sha256_json(body)
        return body

    def _local_cleanup_binding_digest(self, state: Mapping[str, Any]) -> str:
        return _local_cleanup_state_binding_digest(state)

    def _delete_claimed_local_staging(
        self,
        claim: Mapping[str, Any],
        request: OperationRequest,
    ) -> str | None:
        staging_ref = str(claim["staging_ref"])
        claimed_tip = claim["staging_tip"]
        observed_tip = self._read_ref(staging_ref)
        if claimed_tip is None:
            if observed_tip is not None:
                raise StateCorruptionError(
                    "unreserved cleanup found an unexpected staging ref"
                )
        elif observed_tip == claimed_tip:
            self._delete_attempt_ref_if_exact(staging_ref, claimed_tip)
        elif observed_tip is not None:
            raise StateCorruptionError(
                "local cleanup refuses to delete a replaced staging ref"
            )
        if self._read_ref(staging_ref) is not None:
            raise StateCorruptionError("local cleanup did not remove the staging ref")

        self._inject("cleanup.after_delete", claim)
        target_head = self._read_ref(request.target_ref)
        if claimed_tip is not None and self._is_ancestor(claimed_tip, target_head):
            raise PublicationRejected(
                "cleaned publication became formally reachable during abort"
            )
        return target_head

    def _validate_durable_local_cleanup(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> None:
        self._assert_attempt_binding(state, request)
        claim = _validate_local_cleanup_claim(state["cleanup_claim"], state)
        cleanup = _require_mapping(
            state["receipts"].get("cleanup"),
            "local cleanup receipt",
        )
        _validate_local_receipt_integrity(cleanup)
        expected_fields = {
            "capacity_bytes_observed": claim["capacity_bytes_observed"],
            "capacity_reconciled": True,
            "cleanup_claim_ref": claim["claim_ref"],
            "formal_reachable": False,
            "objects_cleaned": True,
            "provider_attempt_reserved": claim["provider_attempt_reserved"],
            "provisional_reachable": False,
            "retention_bound": claim["retention_bound"],
            "staging_ref": claim["staging_ref"],
            "staging_tip": claim["staging_tip"],
            "terminal_disposition": claim["terminal_disposition"],
            "transaction_ref": claim["transaction_ref"],
        }
        for name, expected in expected_fields.items():
            if cleanup.get(name) != expected:
                raise StateCorruptionError(
                    f"local cleanup receipt has a mismatched {name}"
                )
        if cleanup.get("status") != "remote_object_cleanup_complete":
            raise StateCorruptionError("local cleanup receipt has the wrong status")
        if state["aborted"] is not True:
            raise StateCorruptionError(
                "local cleanup receipt did not abort the attempt"
            )
        if self._read_ref(str(claim["staging_ref"])) is not None:
            raise StateCorruptionError("durable cleanup staging ref is still present")
        target_head = self._read_ref(request.target_ref)
        if claim["staging_tip"] is not None and self._is_ancestor(
            claim["staging_tip"], target_head
        ):
            raise PublicationRejected("aborted publication is now formally reachable")

    def _bind_export_retention_sidecars(
        self,
        request: OperationRequest,
        units: Sequence[Mapping[str, Any]],
    ) -> int:
        if not units:
            raise StateCorruptionError("publication retention has no export units")
        bundles: list[Path] = []
        for unit in units:
            bundle_dir = Path(str(unit["bundle_dir"]))
            sidecar = bundle_dir.parent / f".{bundle_dir.name}.retention-v2.json"
            try:
                metadata = sidecar.lstat()
            except FileNotFoundError as exc:
                raise StateCorruptionError(
                    "retained export sidecar is missing before publication binding"
                ) from exc
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise StateCorruptionError(
                    "retained export sidecar is not a regular file"
                )
            bundles.append(bundle_dir)
        for bundle_dir in bundles:
            self._retained_export_lifecycle.bind_staged_export(
                bundle_dir,
                request.attempt_ref,
            )
        return len(bundles)

    def _release_export_retention_sidecars(
        self,
        request: OperationRequest,
        units: Sequence[Mapping[str, Any]],
        *,
        disposition: str,
    ) -> None:
        for unit in units:
            bundle_dir = Path(str(unit["bundle_dir"]))
            sidecar = bundle_dir.parent / f".{bundle_dir.name}.retention-v2.json"
            bundle_present = bundle_dir.exists() or bundle_dir.is_symlink()
            if bundle_present and (sidecar.exists() or sidecar.is_symlink()):
                self._retained_export_lifecycle.release_staged_export_if_bound(
                    bundle_dir,
                    request.attempt_ref,
                    disposition,
                )

    def _inject(self, point: str, state: Mapping[str, Any]) -> None:
        if self._failure_injector is not None:
            self._failure_injector(point, deepcopy(dict(state)))
