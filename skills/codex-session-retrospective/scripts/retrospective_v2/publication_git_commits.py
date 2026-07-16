"""Constrained local Git provider for retained history publication."""

from __future__ import annotations
from collections.abc import Mapping, Sequence
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any
from . import authority
from .checkpoints import canonical_json_bytes
from .identity import IdentityKey

from .publication_support import (
    ARTIFACT_NAMES_BYTEWISE,
    AppendOnlyViolation,
    ArtifactInventory,
    ArtifactValidationError,
    HostCursorUpdate,
    LocalGitPublicationError,
    MAX_RECEIPT_BYTES,
    OperationRequest,
    PROVIDER_CAS_JOURNAL_SCHEMA,
    PROVIDER_EPISODE_HEADS_SCHEMA,
    PublicationError,
    STATE_SCHEMA_VERSION,
    StateCorruptionError,
    TargetHeadConflict,
    _HELPER_GIT_ENV_KEYS,
    _SHA1_OR_SHA256_OBJECT_RE,
    _bounded_git_error,
    _normalize_episode_head_update,
    _normalize_host_cursor_vector,
    _normalize_publication_authority,
    _parse_commit_object,
    _privacy_validate_bundle,
    _publication_commit_message,
    _publication_timestamp,
    _require_mapping,
    _run_bounded_subprocess,
    _sha256_json,
    _split_signer_uid,
    _strict_subprocess_environment,
    _validate_append_only_episode_heads,
    build_artifact_inventory,
)


class LocalGitCommitOperations:
    """Signed commit validation and provider-CAS operations."""

    def _validate_publication_units(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> list[dict[str, Any]]:
        validated: list[dict[str, Any]] = []
        for raw_unit in state["unit_plan"]:
            bundle_dir = Path(raw_unit["bundle_dir"])
            inventory = build_artifact_inventory(bundle_dir)
            if inventory.to_dict() != raw_unit["inventory"]:
                raise ArtifactValidationError(
                    "publication unit changed after reservation"
                )
            artifacts, parsed = _privacy_validate_bundle(
                bundle_dir,
                expected_inventory=inventory,
            )
            manifest = parsed["manifest"]
            role = manifest.get("publication_role")
            if role != "standalone":
                raise ArtifactValidationError(
                    "publication unit has an invalid publication role"
                )
            validated.append(
                {
                    "artifacts": artifacts,
                    "bundle_dir": bundle_dir,
                    "destination": raw_unit["destination"],
                    "inventory": inventory,
                    "manifest": manifest,
                    "publication_role": role,
                }
            )
        if len(validated) != 1:
            raise ArtifactValidationError(
                "publication must contain one standalone retained bundle"
            )
        root = validated[-1]
        if root["destination"] != request.destination:
            raise ArtifactValidationError(
                "publication root destination differs from transaction plan"
            )
        if root["inventory"].to_dict() != request.inventory.to_dict():
            raise ArtifactValidationError(
                "publication root inventory differs from transaction plan"
            )
        destinations = [unit["destination"] for unit in validated]
        if len(destinations) != len(set(destinations)):
            raise AppendOnlyViolation(
                "publication units contain duplicate destination paths"
            )
        for unit in validated:
            if self._path_exists_at(request.expected_target_head, unit["destination"]):
                raise AppendOnlyViolation(
                    f"append-only destination already exists: {unit['destination']}"
                )
        return validated

    def _validate_local_chain(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> None:
        prefixes = state["prefixes"]
        if prefixes:
            tip = prefixes[-1].get("commit")
            target_head = self._read_ref(request.target_ref)
            if isinstance(tip, str) and self._is_ancestor(tip, target_head):
                self._validate_formally_reachable_chain(
                    state,
                    request,
                    target_head=target_head,
                )
                return
        units = self._validate_publication_units(state, request)
        if len(prefixes) != len(units):
            raise StateCorruptionError("local publication chain is incomplete")
        parent = request.expected_target_head
        if parent is None:
            raise StateCorruptionError("local publication chain has no first parent")
        for ordinal, (prefix, unit) in enumerate(zip(prefixes, units, strict=True)):
            if (
                prefix["ordinal"] != ordinal
                or prefix["parent"] != parent
                or prefix["destination"] != unit["destination"]
                or prefix["publication_role"] != unit["publication_role"]
                or prefix["bundle_digest"]
                != unit["inventory"].retained_bundle_digest_v2
                or prefix["inventory_digest"] != unit["inventory"].inventory_digest_v2
            ):
                raise StateCorruptionError(
                    "local publication prefix no longer matches its unit"
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
        if self._read_ref(state["staging_ref"]) != parent:
            raise TargetHeadConflict(parent, self._read_ref(state["staging_ref"]))

    def _validate_formally_reachable_chain(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
        *,
        target_head: str | None,
    ) -> None:
        raw_units = state["unit_plan"]
        prefixes = state["prefixes"]
        if len(raw_units) != 1 or len(prefixes) != len(raw_units):
            raise StateCorruptionError("reachable publication chain is incomplete")
        parent = request.expected_target_head
        if parent is None:
            raise StateCorruptionError(
                "reachable publication chain has no first parent"
            )
        for ordinal, (prefix, raw_unit) in enumerate(
            zip(prefixes, raw_units, strict=True)
        ):
            inventory = ArtifactInventory.from_dict(raw_unit["inventory"])
            destination = str(raw_unit["destination"])
            if (
                prefix["ordinal"] != ordinal
                or prefix["parent"] != parent
                or prefix["destination"] != destination
                or prefix["publication_role"] != "standalone"
                or prefix["bundle_digest"] != inventory.retained_bundle_digest_v2
                or prefix["inventory_digest"] != inventory.inventory_digest_v2
                or destination != request.destination
                or inventory.to_dict() != request.inventory.to_dict()
            ):
                raise StateCorruptionError(
                    "reachable publication prefix no longer matches its durable unit"
                )
            unit = self._git_publication_unit(
                commit=prefix["commit"],
                destination=destination,
                inventory=inventory,
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
        if not self._is_ancestor(parent, target_head):
            raise LocalGitPublicationError(
                "prepared publication tip is not formally reachable"
            )

    def _recover_uncheckpointed_prefix(
        self,
        *,
        state: Mapping[str, Any],
        request: OperationRequest,
        parent: str,
        unit: Mapping[str, Any],
        ordinal: int,
        observed_ref: str,
    ) -> str | None:
        try:
            self._validate_publication_commit(
                commit=observed_ref,
                parent=parent,
                unit=unit,
                ordinal=ordinal,
                attempt_ref=request.attempt_ref,
                plan_digest=request.plan_digest,
            )
        except PublicationError:
            return None
        self._inject(f"stage.recovered_uncheckpointed_prefix.{ordinal}", state)
        return observed_ref

    def _create_signed_publication_commit(
        self,
        *,
        parent: str,
        unit: Mapping[str, Any],
        ordinal: int,
        attempt_ref: str,
        plan_digest: str,
    ) -> str:
        if self._signing_key is None:
            raise LocalGitPublicationError(
                "signed publication requires an explicit signing key"
            )
        self._validate_signing_identity()
        with tempfile.TemporaryDirectory(
            prefix="retrospective-v2-git-index-"
        ) as temp_dir:
            os.chmod(temp_dir, 0o700)
            index_path = Path(temp_dir) / "index"
            index_env = {"GIT_INDEX_FILE": str(index_path)}
            self._git(("read-tree", parent), extra_env=index_env)
            for name in ARTIFACT_NAMES_BYTEWISE:
                content = unit["artifacts"][name]
                blob = (
                    self._git(
                        ("hash-object", "-w", "--stdin"),
                        input_bytes=content,
                    )
                    .stdout.decode("ascii")
                    .strip()
                )
                path = f"{unit['destination']}/{name}"
                self._git(
                    ("update-index", "--add", "--cacheinfo", f"100644,{blob},{path}"),
                    extra_env=index_env,
                )
            tree = (
                self._git(("write-tree",), extra_env=index_env)
                .stdout.decode("ascii")
                .strip()
            )

        timestamp = _publication_timestamp(attempt_ref, ordinal)
        message = _publication_commit_message(
            attempt_ref,
            plan_digest,
            unit,
            ordinal,
        )
        signer_identity = _split_signer_uid(self._expected_signer_uid)
        if signer_identity is None:
            raise LocalGitPublicationError("publisher UID is not canonical")
        signer_name, signer_email = signer_identity
        identity = self._expected_signer_uid
        commit_env = {
            "GIT_AUTHOR_DATE": f"@{timestamp} +0000",
            "GIT_AUTHOR_EMAIL": signer_email,
            "GIT_AUTHOR_NAME": signer_name,
            "GIT_COMMITTER_DATE": f"@{timestamp} +0000",
            "GIT_COMMITTER_EMAIL": signer_email,
            "GIT_COMMITTER_NAME": signer_name,
        }
        result = self._git(
            ("commit-tree", tree, "-p", parent, "-S"),
            input_bytes=message,
            extra_env=commit_env,
            signing=True,
        )
        commit = result.stdout.decode("ascii").strip()
        if _SHA1_OR_SHA256_OBJECT_RE.fullmatch(commit) is None:
            raise LocalGitPublicationError(
                "git commit-tree returned an invalid object ID"
            )
        self._validate_publication_commit(
            commit=commit,
            parent=parent,
            unit=unit,
            ordinal=ordinal,
            attempt_ref=attempt_ref,
            plan_digest=plan_digest,
            expected_identity=identity,
            expected_timestamp=timestamp,
            expected_tree=tree,
        )
        return commit

    def _validate_publication_commit(
        self,
        *,
        commit: str,
        parent: str,
        unit: Mapping[str, Any],
        ordinal: int,
        attempt_ref: str,
        plan_digest: str,
        expected_identity: str | None = None,
        expected_timestamp: int | None = None,
        expected_tree: str | None = None,
    ) -> None:
        raw = self._git(("cat-file", "commit", commit)).stdout
        headers, body = _parse_commit_object(raw)
        header_names = [name for name, _value in headers]
        if sorted(header_names) != sorted(
            ("tree", "parent", "author", "committer", "gpgsig")
        ):
            raise LocalGitPublicationError(
                "publication commit has unexpected or duplicate headers"
            )
        values = {name: value for name, value in headers}
        if values["parent"] != parent:
            raise AppendOnlyViolation("publication commit has the wrong sole parent")
        if expected_tree is not None and values["tree"] != expected_tree:
            raise LocalGitPublicationError(
                "publication commit tree changed after signing"
            )
        timestamp = expected_timestamp or _publication_timestamp(attempt_ref, ordinal)
        identity = expected_identity or self._expected_signer_uid
        expected_identity_line = f"{identity} {timestamp} +0000"
        if (
            values["author"] != expected_identity_line
            or values["committer"] != expected_identity_line
        ):
            raise LocalGitPublicationError(
                "publication commit identity or timestamp is not canonical"
            )
        if body != _publication_commit_message(
            attempt_ref,
            plan_digest,
            unit,
            ordinal,
        ):
            raise LocalGitPublicationError(
                "publication commit message is not canonical"
            )
        verification = self._git(
            ("verify-commit", "--raw", commit), check=False, signing=True
        )
        if verification.returncode != 0:
            details = _bounded_git_error(verification)
            raise LocalGitPublicationError(
                f"publication commit signature is invalid: {details}"
            )
        if self._signing_format == "openpgp":
            try:
                valid_fingerprints = authority.validsig_primary_fingerprints(
                    verification.stdout + b"\n" + verification.stderr
                )
            except ValueError as exc:
                raise LocalGitPublicationError(
                    "publication signature status is invalid"
                ) from exc
            if valid_fingerprints != [self._signing_key]:
                raise LocalGitPublicationError(
                    "publication signature does not bind the configured sole fingerprint"
                )

        expected_paths = {
            f"{unit['destination']}/{name}" for name in ARTIFACT_NAMES_BYTEWISE
        }
        diff = self._git(
            (
                "diff-tree",
                "--no-commit-id",
                "--name-status",
                "--no-renames",
                "-r",
                parent,
                commit,
            )
        ).stdout.decode("utf-8")
        observed_paths: set[str] = set()
        for line in diff.splitlines():
            status_value, separator, path = line.partition("\t")
            if separator != "\t" or status_value != "A":
                raise AppendOnlyViolation(
                    "publication commit modifies or removes an existing path"
                )
            observed_paths.add(path)
        if observed_paths != expected_paths:
            raise AppendOnlyViolation(
                "publication commit does not add exactly one eight-artifact unit"
            )
        for name in ARTIFACT_NAMES_BYTEWISE:
            path = f"{unit['destination']}/{name}"
            expected = unit["artifacts"][name]
            content = self._git(
                ("show", f"{commit}:{path}"),
                max_output_bytes=len(expected) + MAX_RECEIPT_BYTES,
            ).stdout
            if content != expected:
                raise ArtifactValidationError(f"Git object bytes differ for {path}")

    def _git(
        self,
        args: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        extra_env: Mapping[str, str] | None = None,
        check: bool = True,
        signing: bool = False,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        self._revalidate_git_metadata()
        command = [self._git_binary, "-C", str(self._repo)]
        if hasattr(self, "_git_dir"):
            command.extend((f"--git-dir={self._git_dir}", f"--work-tree={self._repo}"))
        command.extend(("-c", "core.hooksPath=/dev/null"))
        if signing:
            command.extend(("-c", f"gpg.format={self._signing_format}"))
            if self._signing_key is not None:
                command.extend(("-c", f"user.signingkey={self._signing_key}"))
            command.extend(("-c", f"gpg.program={self._signing_program}"))
        command.extend(args)
        environment = _strict_subprocess_environment(
            home=self._gnupg_home or self._repo
        )
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_LITERAL_PATHSPECS": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        if signing and self._gnupg_home is not None:
            environment["GNUPGHOME"] = str(self._gnupg_home)
        if extra_env:
            unsupported = set(extra_env) - _HELPER_GIT_ENV_KEYS
            if unsupported:
                raise LocalGitPublicationError(
                    "Git helper environment contains unsupported variables: "
                    f"{sorted(unsupported)}"
                )
            if any(not isinstance(value, str) for value in extra_env.values()):
                raise LocalGitPublicationError(
                    "Git helper environment values must be strings"
                )
            environment.update(extra_env)
        result = _run_bounded_subprocess(
            command,
            input_bytes=input_bytes,
            environment=environment,
            timeout_seconds=(
                self._subprocess_timeout_seconds
                if timeout_seconds is None
                else timeout_seconds
            ),
            max_output_bytes=(
                self._subprocess_output_limit_bytes
                if max_output_bytes is None
                else max_output_bytes
            ),
        )
        if check and result.returncode != 0:
            raise LocalGitPublicationError(
                f"Git command failed ({' '.join(args)}): {_bounded_git_error(result)}"
            )
        return result

    def _read_ref(self, ref: str) -> str | None:
        if self._git(("check-ref-format", ref), check=False).returncode != 0:
            raise LocalGitPublicationError(f"cannot inspect invalid Git ref: {ref}")
        result = self._git(("rev-parse", "--verify", "--quiet", ref), check=False)
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise LocalGitPublicationError(
                f"cannot inspect Git ref {ref}: {_bounded_git_error(result)}"
            )
        value = result.stdout.decode("ascii").strip()
        if _SHA1_OR_SHA256_OBJECT_RE.fullmatch(value) is None:
            raise LocalGitPublicationError(
                f"Git ref {ref} resolved to an invalid object ID"
            )
        return value

    def _path_exists_at(self, commit: str | None, destination: str) -> bool:
        if commit is None:
            return False
        result = self._git(
            ("rev-parse", "--verify", "--quiet", f"{commit}:{destination}"),
            check=False,
            max_output_bytes=1024,
        )
        if result.returncode == 1:
            return False
        if result.returncode != 0:
            raise LocalGitPublicationError(
                f"cannot inspect append-only destination: {_bounded_git_error(result)}"
            )
        object_id = result.stdout.decode("ascii").strip()
        if _SHA1_OR_SHA256_OBJECT_RE.fullmatch(object_id) is None:
            raise LocalGitPublicationError(
                "append-only destination resolved to an invalid object ID"
            )
        return True

    def _advance_attempt_ref(
        self,
        ref: str,
        value: str,
        *,
        expected: str | None,
    ) -> None:
        actual = self._read_ref(ref)
        if actual == value:
            return
        if actual != expected:
            raise TargetHeadConflict(expected, actual)
        self._update_ref(ref, value, expected=expected)

    def _update_ref(self, ref: str, value: str, *, expected: str | None) -> None:
        if _SHA1_OR_SHA256_OBJECT_RE.fullmatch(value) is None:
            raise LocalGitPublicationError("Git ref update value is invalid")
        old_value = "0" * len(value) if expected is None else expected
        result = self._git(("update-ref", ref, value, old_value), check=False)
        if result.returncode != 0:
            raise TargetHeadConflict(expected, self._read_ref(ref))

    def _delete_attempt_ref_if_exact(self, ref: str, expected: str) -> None:
        actual = self._read_ref(ref)
        if actual is None:
            return
        if actual != expected:
            raise TargetHeadConflict(expected, actual)
        result = self._git(("update-ref", "-d", ref, expected), check=False)
        if result.returncode != 0 or self._read_ref(ref) is not None:
            raise TargetHeadConflict(expected, self._read_ref(ref))

    def _is_ancestor(self, ancestor: str, descendant: str | None) -> bool:
        if descendant is None:
            return False
        result = self._git(
            ("merge-base", "--is-ancestor", ancestor, descendant), check=False
        )
        if result.returncode not in {0, 1}:
            raise LocalGitPublicationError(
                f"cannot determine Git reachability: {_bounded_git_error(result)}"
            )
        return result.returncode == 0

    def _validate_formal_reachability(
        self,
        state: Mapping[str, Any],
        tip: str,
    ) -> None:
        actual = self._read_ref(str(state["target_ref"]))
        if not self._is_ancestor(tip, actual):
            raise LocalGitPublicationError(
                "prepared publication tip is not formally reachable"
            )

    def _promotion_generation_rejection(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> dict[str, Any] | None:
        current = self.read_generations()
        snapshot = state["generation_snapshot"]
        if current["revision"] != snapshot["revision"]:
            return self._receipt(
                request,
                "rejected",
                actual_generation=str(current["revision"]),
                expected_generation=str(snapshot["revision"]),
                reason="generation_revision_changed",
            )
        if current["policy_generation"] != snapshot["policy_generation"]:
            return self._receipt(
                request,
                "rejected",
                actual_generation=current["policy_generation"],
                expected_generation=snapshot["policy_generation"],
                reason="policy_generation_changed",
            )
        if current["key_generation"] != snapshot["key_generation"]:
            return self._receipt(
                request,
                "rejected",
                actual_generation=current["key_generation"],
                expected_generation=snapshot["key_generation"],
                reason="key_generation_changed",
            )
        return None

    def _provider_state_snapshot(
        self,
        request: OperationRequest,
    ) -> dict[str, Any]:
        binding = _normalize_publication_authority(request.publication_authority)
        identity = IdentityKey.load(
            binding["identity_path"], expected_key_id=binding["identity_key_id"]
        )
        expected_history = authority.history_state_from_projection(
            binding["expected_history"], identity=identity
        )
        current_history = authority.load_durable_history(
            binding["history_repo"],
            binding["target_ref"],
            identity=identity,
            expected_fingerprint=binding["publisher_fingerprint"],
            gnupg_home=binding["publisher_gnupg_home"],
        )
        if canonical_json_bytes(current_history.provider_projection()) != (
            canonical_json_bytes(expected_history.provider_projection())
        ):
            raise TargetHeadConflict(
                expected_history.head_commit, current_history.head_commit
            )
        authority.assert_provider_cache_matches(
            binding["provider_state"],
            expected_history,
            identity=identity,
        )
        return self._expected_provider_state_snapshot(request)

    def _expected_provider_state_snapshot(
        self,
        request: OperationRequest,
    ) -> dict[str, Any]:
        binding = _normalize_publication_authority(request.publication_authority)
        identity = IdentityKey.load(
            binding["identity_path"], expected_key_id=binding["identity_key_id"]
        )
        expected_history = authority.history_state_from_projection(
            binding["expected_history"], identity=identity
        )
        update = _normalize_episode_head_update(
            request.episode_head_update,
            required=True,
        )
        expected_ref = update["expected_episode_head_set_ref"]
        if expected_history.episode_head_root_ref != expected_ref:
            raise TargetHeadConflict(
                expected_ref,
                expected_history.episode_head_root_ref,
            )
        _validate_append_only_episode_heads(
            expected_history.episode_heads,
            update["proposed_episode_heads"],
        )
        cursors = {row["host_ref"]: row for row in expected_history.cursor_rows}
        for host_ref, raw_update in _normalize_host_cursor_vector(
            request.host_cursor_vector
        ).items():
            cursor_update = HostCursorUpdate.from_dict(raw_update, host_ref=host_ref)
            current = cursors.get(
                host_ref,
                {"backlog_ref": None, "cursor_ref": None},
            )
            if (
                current.get("cursor_ref") != cursor_update.expected_cursor
                or current.get("backlog_ref") != cursor_update.expected_backlog_head
            ):
                raise TargetHeadConflict(
                    (
                        f"{cursor_update.expected_cursor}|"
                        f"{cursor_update.expected_backlog_head}"
                    ),
                    f"{current.get('cursor_ref')}|{current.get('backlog_ref')}",
                )
        return {
            "episode_head_set_ref": expected_history.episode_head_root_ref,
            "history_commit": expected_history.head_commit,
            "revision": expected_history.provider_revision,
        }

    def _promotion_provider_rejection(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> dict[str, Any] | None:
        snapshot = state["provider_state_snapshot"]
        current = self._provider_state_snapshot(request)
        if current != snapshot:
            return self._receipt(
                request,
                "rejected",
                actual_generation=str(current["revision"]),
                expected_generation=str(snapshot["revision"]),
                reason="provider_state_revision_changed",
            )
        return None

    def _all_publication_artifacts(self, state: Mapping[str, Any]) -> dict[str, Any]:
        artifacts: dict[str, Any] = {}
        for raw_unit in state["unit_plan"]:
            inventory = ArtifactInventory.from_dict(raw_unit["inventory"])
            for artifact in inventory.artifacts:
                artifacts[f"{raw_unit['destination']}/{artifact.name}"] = {
                    "sha256": artifact.sha256,
                    "size": artifact.size,
                }
        return dict(sorted(artifacts.items()))

    def _advance_provider_state(
        self,
        state: Mapping[str, Any],
        request: OperationRequest,
    ) -> tuple[int, int]:
        binding = _normalize_publication_authority(request.publication_authority)
        identity = IdentityKey.load(
            binding["identity_path"], expected_key_id=binding["identity_key_id"]
        )
        previous = authority.history_state_from_projection(
            binding["expected_history"], identity=identity
        )
        published = authority.load_durable_history(
            binding["history_repo"],
            binding["target_ref"],
            identity=identity,
            expected_fingerprint=binding["publisher_fingerprint"],
            gnupg_home=binding["publisher_gnupg_home"],
        )
        target_head = state["receipts"]["promotion"]["target_head"]
        if published.publication_commit != target_head or not self._is_ancestor(
            target_head, published.head_commit
        ):
            raise TargetHeadConflict(target_head, published.head_commit)
        proposed = binding["proposed_durable_state"]
        if (
            published.provider_revision != proposed["provider_revision_after"]
            or published.cursor_root_ref != proposed["proposed_cursor_root_ref"]
            or published.episode_head_root_ref
            != proposed["proposed_episode_head_root_ref"]
        ):
            raise StateCorruptionError(
                "published history does not derive the proposed provider state"
            )
        authority.derive_provider_cache(
            binding["provider_state"],
            previous=previous,
            published=published,
            identity=identity,
        )
        return previous.provider_revision, published.provider_revision

    def _recover_provider_cas(self) -> None:
        if not self._state_directory.exists(self._provider_cas_journal_path.name):
            return
        journal = self._state_directory.read_json(self._provider_cas_journal_path.name)
        expected_fields = {
            "attempt_ref",
            "expected_episode_head_set_ref",
            "plan_digest",
            "proposed_episode_head_set_ref",
            "revision_after",
            "revision_before",
            "schema",
            "target_head",
            "vector_digest",
        }
        if set(journal) != expected_fields or journal.get("schema") != (
            PROVIDER_CAS_JOURNAL_SCHEMA
        ):
            raise StateCorruptionError("provider CAS journal has an invalid shape")
        attempt = self._read_attempt(journal["attempt_ref"])
        assert attempt is not None
        update = _normalize_episode_head_update(
            _require_mapping(attempt["episode_head_update"], "episode head update"),
            required=True,
        )
        if (
            attempt["binding"]["plan_digest"] != journal["plan_digest"]
            or update["expected_episode_head_set_ref"]
            != journal["expected_episode_head_set_ref"]
            or update["proposed_episode_head_set_ref"]
            != journal["proposed_episode_head_set_ref"]
            or _sha256_json(attempt["host_cursor_vector"]) != journal["vector_digest"]
        ):
            raise StateCorruptionError(
                "provider CAS journal is not bound to its publication attempt"
            )
        cursor_state = self.read_cursor_state()
        heads_state = self.read_episode_heads_state()
        before = journal["revision_before"]
        after = journal["revision_after"]
        if cursor_state["revision"] == after:
            application = cursor_state["applied_publications"].get(
                journal["attempt_ref"]
            )
            if (
                application is None
                or heads_state["revision"] != after
                or heads_state["episode_head_set_ref"]
                != journal["proposed_episode_head_set_ref"]
            ):
                raise StateCorruptionError(
                    "provider CAS recovery observed a torn completed state"
                )
            self._state_directory.unlink(self._provider_cas_journal_path.name)
            return
        if cursor_state["revision"] != before:
            raise StateCorruptionError(
                "provider CAS recovery observed an unexpected cursor revision"
            )
        if heads_state["revision"] == before:
            if (
                heads_state["episode_head_set_ref"]
                != journal["expected_episode_head_set_ref"]
            ):
                raise StateCorruptionError(
                    "provider CAS recovery observed a different prior head set"
                )
            _validate_append_only_episode_heads(
                heads_state["episode_heads"], update["proposed_episode_heads"]
            )
            self._state_directory.write_json(
                self._episode_heads_path.name,
                {
                    "episode_head_set_ref": update["proposed_episode_head_set_ref"],
                    "episode_heads": deepcopy(update["proposed_episode_heads"]),
                    "revision": after,
                    "schema": PROVIDER_EPISODE_HEADS_SCHEMA,
                },
            )
        elif (
            heads_state["revision"] != after
            or heads_state["episode_head_set_ref"]
            != journal["proposed_episode_head_set_ref"]
        ):
            raise StateCorruptionError(
                "provider CAS recovery observed an unexpected head-set revision"
            )
        recovered_cursor = self._apply_cursor_vector(
            cursor_state,
            attempt_ref=journal["attempt_ref"],
            plan_digest=journal["plan_digest"],
            target_head=journal["target_head"],
            vector=attempt["host_cursor_vector"],
            expected_episode_head_set_ref=journal["expected_episode_head_set_ref"],
            proposed_episode_head_set_ref=journal["proposed_episode_head_set_ref"],
        )
        self._state_directory.write_json(self._cursor_state_path.name, recovered_cursor)
        self._state_directory.unlink(self._provider_cas_journal_path.name)

    @staticmethod
    def _apply_cursor_vector(
        cursor_state: Mapping[str, Any],
        *,
        attempt_ref: str,
        plan_digest: str,
        target_head: str,
        vector: Mapping[str, Mapping[str, Any]],
        expected_episode_head_set_ref: str,
        proposed_episode_head_set_ref: str,
    ) -> dict[str, Any]:
        normalized = _normalize_host_cursor_vector(vector)
        hosts = deepcopy(cursor_state["hosts"])
        for host_ref, update_value in normalized.items():
            update = HostCursorUpdate.from_dict(update_value, host_ref=host_ref)
            current = hosts.get(host_ref, {"backlog_head": None, "cursor": None})
            if (
                current.get("cursor") != update.expected_cursor
                or current.get("backlog_head") != update.expected_backlog_head
            ):
                raise TargetHeadConflict(
                    f"{update.expected_cursor}|{update.expected_backlog_head}",
                    f"{current.get('cursor')}|{current.get('backlog_head')}",
                )
            hosts[host_ref] = {
                "backlog_head": update.proposed_backlog_head,
                "cursor": update.proposed_cursor,
            }
        revision_before = int(cursor_state["revision"])
        application = {
            "attempt_ref": attempt_ref,
            "expected_episode_head_set_ref": expected_episode_head_set_ref,
            "plan_digest": plan_digest,
            "proposed_episode_head_set_ref": proposed_episode_head_set_ref,
            "revision_after": revision_before + 1,
            "revision_before": revision_before,
            "target_head": target_head,
            "vector_digest": _sha256_json(normalized),
        }
        applied = dict(cursor_state["applied_publications"])
        applied[attempt_ref] = application
        return {
            "applied_publications": dict(sorted(applied.items())),
            "hosts": dict(sorted(hosts.items())),
            "last_publication": application,
            "revision": revision_before + 1,
            "schema_version": STATE_SCHEMA_VERSION,
        }
