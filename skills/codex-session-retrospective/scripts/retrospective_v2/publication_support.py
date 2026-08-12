"""Immutable publication contracts, validation, and anchored I/O helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

from . import authority, executable_authority, reporting, safe_io
from .checkpoints import AtomicCheckpointStore, canonical_json_bytes
from .contracts import CANONICAL_HOSTS
from .identity import IdentityKey
from .run_state_authority import validate_run_source_authority
from .run_state_contracts import RunStateAuthorityError
from .publication_contracts import (  # noqa: F401
    _ATTEMPT_REF_RE,
    _CREDENTIAL_KEYS,
    _HELPER_GIT_ENV_KEYS,
    _NORMAL_PHASE_INDEX,
    _NORMAL_PHASES,
    _PUBLICATION_CLAIM_AUTH_RE,
    _PUBLICATION_CLAIM_REF_RE,
    _SAFE_DESTINATION_RE,
    _SAFE_REASON_RE,
    _SAFE_REF_RE,
    _SHA1_OR_SHA256_OBJECT_RE,
    _SHA256_RE,
    ARTIFACT_INVENTORY_DOMAIN_V2,
    ARTIFACT_NAMES,
    ARTIFACT_NAMES_BYTEWISE,
    ATTEMPT_REF_PREFIX,
    DEFAULT_PUBLICATION_CAPACITY_BYTES,
    DEFAULT_PUBLISHER_FINGERPRINT,
    DEFAULT_PUBLISHER_GNUPG_HOME,
    DEFAULT_PUBLISHER_UID,
    DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
    EPISODE_HEAD_UPDATE_SCHEMA,
    FORMAL_AUTHORIZATION_SCHEMA,
    LOCAL_GIT_CHAIN_PREFIX,
    LOCAL_GIT_CAPACITY_RESERVATION_SCHEMA,
    LOCAL_GIT_CLEANUP_CLAIM_PREFIX,
    LOCAL_GIT_CLEANUP_CLAIM_SCHEMA,
    LOCAL_GIT_RECEIPT_PREFIX,
    LOCAL_GIT_SIGNER_EMAIL,
    LOCAL_GIT_SIGNER_NAME,
    LOCAL_GIT_TRANSACTION_PREFIX,
    MAX_BUNDLE_BYTES,
    MAX_RECEIPT_BYTES,
    MAX_STATE_BYTES,
    MAX_SUBPROCESS_OUTPUT_BYTES,
    PROVIDER_CAS_JOURNAL_SCHEMA,
    PROVIDER_EPISODE_HEADS_SCHEMA,
    PUBLICATION_ABORT_COMMITMENT_AUTH_PREFIX,
    PUBLICATION_ABORT_COMMITMENT_REF_PREFIX,
    PUBLICATION_ABORT_COMMITMENT_SCHEMA,
    PUBLICATION_CAPACITY_OVERHEAD_BYTES,
    PUBLICATION_CLAIM_SCHEMA,
    PUBLICATION_JOURNAL_NAME,
    READ_CHUNK_BYTES,
    RETAINED_BUNDLE_DOMAIN_V2,
    SHADOW_RECEIPT_REF_PREFIX,
    SHADOW_TRANSACTION_REF_PREFIX,
    STATE_SCHEMA_VERSION,
    AppendOnlyViolation,
    ArtifactInventory,
    ArtifactRecord,
    ArtifactValidationError,
    AttemptMismatchError,
    CapacityReservationError,
    FailureInjector,
    GenerationConflict,
    HostCursorUpdate,
    InvalidTransitionError,
    LocalGitPublicationError,
    OperationRequest,
    PublicationAdapter,
    PublicationError,
    PublicationPhase,
    PublicationRejected,
    ReceiptValidationError,
    RetainedExportLifecycle,
    StateCorruptionError,
    TargetHeadConflict,
    TransactionKind,
    _bounded_git_error,
    _canonical_json_bytes,
    _decode_gpg_colon_field,
    _inventory_digest,
    _json_clone,
    _new_event,
    _normalize_episode_head_update,
    _normalize_host_cursor_vector,
    _normalize_publication_authority,
    _normalize_receipt,
    _parse_commit_object,
    _parse_json_object,
    _publication_chain_root,
    _publication_commit_message,
    _publication_timestamp,
    _reject_artifact_json_constant,
    _reject_credential_fields,
    _reject_duplicate_keys,
    _reject_state_json_constant,
    _require_mapping,
    _sha256_json,
    _split_signer_uid,
    _state_digest,
    _state_duplicate_keys,
    _validate_attempt_ref,
    _validate_destination,
    _validate_destination_state,
    _validate_event_chain,
    _validate_event_transition,
    _validate_optional_ref,
    _validate_optional_ref_state,
    _validate_owner_only_state_directory,
    _validate_phase_receipts,
    _validate_ref,
    _validate_ref_state,
    _validate_ref_value,
    new_attempt_ref,
    verify_publication_abort_commitment,
)
from .publication_state import (  # noqa: F401
    _anchored_lock,
    _AnchoredStateDirectory,
    _local_cleanup_state_binding_digest,
    _normalize_cursor_store_hosts,
    _validate_append_only_episode_heads,
    _validate_capacity_ledger,
    _validate_cursor_state,
    _validate_episode_heads_state,
    _validate_generation_state,
    _validate_local_attempt_state,
    _validate_local_cleanup_claim,
    _validate_local_receipt_integrity,
    read_provider_episode_heads_state,
)


_DESCRIPTOR_CWD_EXEC_SOURCE = (
    "import os,sys\n"
    "descriptor=int(sys.argv[1])\n"
    "os.fchdir(descriptor)\n"
    "os.execve(sys.argv[2],sys.argv[2:],os.environ)\n"
)


def _strict_subprocess_environment(*, home: Path) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TZ": "UTC",
    }
    for name in ("TEMP", "TMP", "TMPDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _revalidate_publisher_home_binding(
    descriptor: int,
    home: Path,
    identity: os.stat_result,
) -> None:
    try:
        safe_io.validate_owner_only_directory_descriptor(descriptor, home)
        with ExitStack() as reopened_custody:
            _reopened_home, reopened_descriptor = safe_io.open_owner_only_directory(
                home,
                reject_symlink_ancestors=True,
            )
            reopened_custody.callback(os.close, reopened_descriptor)
            reopened_identity = os.fstat(reopened_descriptor)
            if (reopened_identity.st_dev, reopened_identity.st_ino) != (
                identity.st_dev,
                identity.st_ino,
            ):
                raise safe_io.UnsafePathError(
                    "publisher GNUPGHOME path no longer names the anchored directory"
                )
    except (OSError, safe_io.UnsafePathError) as exc:
        raise LocalGitPublicationError(
            "publisher GNUPGHOME changed after validation"
        ) from exc


@contextmanager
def _publisher_home_subprocess_binding(
    gnupg_home: str | os.PathLike[str],
):
    home = Path(gnupg_home).expanduser().absolute()
    try:
        home, descriptor = safe_io.open_owner_only_directory(
            home,
            reject_symlink_ancestors=True,
        )
    except (OSError, safe_io.UnsafePathError) as exc:
        raise LocalGitPublicationError(
            f"publisher GNUPGHOME is unavailable: {home}"
        ) from exc
    identity = os.fstat(descriptor)

    try:
        _revalidate_publisher_home_binding(descriptor, home, identity)
        try:
            yield home, Path("."), descriptor
        except BaseException as operation_error:
            try:
                _revalidate_publisher_home_binding(descriptor, home, identity)
            except BaseException as validation_error:
                raise validation_error from operation_error
            raise
        _revalidate_publisher_home_binding(descriptor, home, identity)
    finally:
        os.close(descriptor)


def _descriptor_bound_launch(
    command: Sequence[str],
    descriptor: int | None,
    python_executable: str | None,
) -> tuple[list[str], tuple[int, ...]]:
    if descriptor is None:
        return list(command), ()
    if os.name != "posix":
        raise LocalGitPublicationError(
            "descriptor-bound subprocess launch is unavailable on this platform"
        )
    assert python_executable is not None
    return (
        [
            python_executable,
            "-I",
            "-B",
            "-S",
            "-c",
            _DESCRIPTOR_CWD_EXEC_SOURCE,
            str(descriptor),
            *command,
        ],
        (descriptor,),
    )


def _run_bounded_subprocess(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd_descriptor: int | None = None,
    inherited_descriptors: tuple[int, ...] = (),
    input_bytes: bytes | None = None,
    timeout_seconds: float,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[bytes]:
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < float(timeout_seconds) < float("inf")
    ):
        raise ValueError("subprocess timeout must be a positive finite number")
    if (
        not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or max_output_bytes <= 0
    ):
        raise ValueError("subprocess output limit must be a positive integer")
    python_authority = (
        executable_authority.resolve_executable(sys.executable, label="Python")
        if cwd_descriptor is not None
        else None
    )
    launch_command, cwd_descriptors = _descriptor_bound_launch(
        command,
        cwd_descriptor,
        None if python_authority is None else python_authority.path,
    )
    inherited_descriptors = tuple(
        dict.fromkeys((*cwd_descriptors, *inherited_descriptors))
    )
    if python_authority is not None:
        executable_authority.revalidate_executable(python_authority)
    try:
        process = subprocess.Popen(
            launch_command,
            stdin=(subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment),
            close_fds=True,
            pass_fds=inherited_descriptors,
            start_new_session=os.name == "posix",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        if python_authority is not None:
            executable_authority.revalidate_executable(python_authority)
        raise LocalGitPublicationError("cannot start bounded subprocess") from exc

    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    input_view = memoryview(input_bytes or b"")
    input_offset = 0
    deadline = time.monotonic() + float(timeout_seconds)
    process_group_id = process.pid if os.name == "posix" else None
    process_group_cleanup_attempted = False

    def close_stream(stream: Any) -> None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
        try:
            stream.close()
        except OSError:
            pass

    def kill_process() -> None:
        nonlocal process_group_cleanup_attempted
        if process_group_cleanup_attempted:
            return
        process_group_cleanup_attempted = True
        if process_group_id is not None:
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                pass
        elif process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        if process_group_id is not None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass

    try:
        for stream, target in (
            (process.stdout, stdout),
            (process.stderr, stderr),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, ("read", target))
        if process.stdin is not None:
            if input_view:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, ("write", None))
            else:
                process.stdin.close()

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                kill_process()
                raise LocalGitPublicationError("subprocess exceeded its deadline")
            try:
                events = selector.select(min(remaining, 0.1))
            except InterruptedError:
                continue
            for key, _mask in events:
                stream = key.fileobj
                operation, target = key.data
                if operation == "write":
                    try:
                        written = os.write(
                            stream.fileno(),
                            input_view[input_offset : input_offset + READ_CHUNK_BYTES],
                        )
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        close_stream(stream)
                        continue
                    input_offset += written
                    if input_offset == len(input_view):
                        close_stream(stream)
                    continue
                try:
                    chunk = os.read(stream.fileno(), READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    close_stream(stream)
                    continue
                assert isinstance(target, bytearray)
                if len(stdout) + len(stderr) + len(chunk) > max_output_bytes:
                    kill_process()
                    raise LocalGitPublicationError(
                        "subprocess exceeded its output limit"
                    )
                target.extend(chunk)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            kill_process()
            raise LocalGitPublicationError("subprocess exceeded its deadline")
        # Close the task-owned group while the unreaped leader still pins its
        # PID/PGID. Reaping first would open a process-group reuse race.
        kill_process()
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            kill_process()
            raise LocalGitPublicationError("subprocess exceeded its deadline") from exc
        return subprocess.CompletedProcess(
            args=list(command),
            returncode=return_code,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
        )
    finally:
        try:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    close_stream(stream)
            selector.close()
            kill_process()
        finally:
            if python_authority is not None:
                executable_authority.revalidate_executable(python_authority)


def _run_publisher_listing(
    *,
    argument: str,
    descriptor: int,
    gpg_authority: executable_authority.ExecutableAuthority,
    home: Path,
    subprocess_home: Path,
    timeout_seconds: float,
) -> bytes:
    environment = _strict_subprocess_environment(home=subprocess_home)
    environment["GNUPGHOME"] = str(subprocess_home)
    try:
        with executable_authority.executable_invocation(gpg_authority):
            result = _run_bounded_subprocess(
                [
                    gpg_authority.path,
                    "--homedir",
                    str(subprocess_home),
                    "--batch",
                    "--with-colons",
                    argument,
                ],
                environment=environment,
                cwd_descriptor=descriptor,
                timeout_seconds=timeout_seconds,
                max_output_bytes=MAX_RECEIPT_BYTES,
            )
    except executable_authority.ExecutableAuthorityError as exc:
        raise LocalGitPublicationError(str(exc)) from exc
    _revalidate_publisher_home_binding(descriptor, home, os.fstat(descriptor))
    if result.returncode != 0:
        raise LocalGitPublicationError(
            f"cannot inspect dedicated publisher keyring: {_bounded_git_error(result)}"
        )
    return result.stdout


def validate_publisher_keyring(
    *,
    gnupg_home: str | os.PathLike[str] = DEFAULT_PUBLISHER_GNUPG_HOME,
    fingerprint: str = DEFAULT_PUBLISHER_FINGERPRINT,
    expected_uid: str = DEFAULT_PUBLISHER_UID,
    gpg_program: str | os.PathLike[str] = executable_authority.DEFAULT_GPG_EXECUTABLE,
    timeout_seconds: float = 10.0,
) -> dict[str, str]:
    """Validate only the dedicated owner-only OpenPGP publisher keyring."""

    if re.fullmatch(r"[0-9A-Fa-f]{40}", fingerprint) is None:
        raise LocalGitPublicationError(
            "OpenPGP publication requires one explicit 40-hex signing fingerprint"
        )
    normalized_fingerprint = fingerprint.upper()
    if _split_signer_uid(expected_uid) is None:
        raise LocalGitPublicationError(
            "publisher UID has an invalid canonical name/email shape"
        )
    try:
        gpg_authority = executable_authority.resolve_executable(
            gpg_program, label="GPG"
        )
    except executable_authority.ExecutableAuthorityError as exc:
        raise LocalGitPublicationError("GPG executable is not trusted") from exc

    def inventory(
        payload: bytes,
        *,
        primary_record: str,
    ) -> tuple[list[str], list[str]]:
        fingerprints: list[str] = []
        uids: list[str] = []
        awaiting_primary_fingerprint = False
        try:
            lines = payload.decode("utf-8", errors="strict").splitlines()
            for raw_line in lines:
                fields = raw_line.split(":")
                record_type = fields[0]
                if record_type in {primary_record, "fpr", "uid"} and len(fields) < 10:
                    raise ValueError("truncated GPG colon record")
                if record_type == primary_record:
                    awaiting_primary_fingerprint = True
                elif record_type == "fpr" and awaiting_primary_fingerprint:
                    fingerprints.append(fields[9].upper())
                    awaiting_primary_fingerprint = False
                elif record_type == "uid":
                    uids.append(_decode_gpg_colon_field(fields[9]))
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as exc:
            raise LocalGitPublicationError(
                "dedicated publisher keyring metadata is malformed"
            ) from exc
        return fingerprints, uids

    with _publisher_home_subprocess_binding(gnupg_home) as (
        home,
        subprocess_home,
        home_descriptor,
    ):
        secret_payload = _run_publisher_listing(
            argument="--list-secret-keys",
            descriptor=home_descriptor,
            gpg_authority=gpg_authority,
            home=home,
            subprocess_home=subprocess_home,
            timeout_seconds=timeout_seconds,
        )
        secret_fingerprints, secret_uids = inventory(
            secret_payload,
            primary_record="sec",
        )
        if secret_fingerprints != [normalized_fingerprint]:
            raise LocalGitPublicationError(
                "publisher GNUPGHOME must contain exactly the configured secret primary key"
            )
        if secret_uids != [expected_uid]:
            raise LocalGitPublicationError(
                "publisher key must contain exactly the configured sole UID"
            )
        public_payload = _run_publisher_listing(
            argument="--list-keys",
            descriptor=home_descriptor,
            gpg_authority=gpg_authority,
            home=home,
            subprocess_home=subprocess_home,
            timeout_seconds=timeout_seconds,
        )
    public_fingerprints, public_uids = inventory(public_payload, primary_record="pub")
    if public_fingerprints != [normalized_fingerprint] or public_uids != [expected_uid]:
        raise LocalGitPublicationError(
            "publisher GNUPGHOME must contain only the configured public primary key and UID"
        )
    return {
        "fingerprint": normalized_fingerprint,
        "gnupg_home": str(home),
        "uid": expected_uid,
    }


def compute_retained_bundle_digest(bundle_dir: str | os.PathLike[str]) -> str:
    """Compute the v2 non-self-referential retained bundle digest."""

    _, digest, _ = _scan_artifacts(Path(bundle_dir), require_declared_digest=False)
    return digest


def build_artifact_inventory(
    bundle_dir: str | os.PathLike[str],
    *,
    max_bundle_bytes: int = MAX_BUNDLE_BYTES,
) -> ArtifactInventory:
    if (
        not isinstance(max_bundle_bytes, int)
        or isinstance(max_bundle_bytes, bool)
        or max_bundle_bytes <= 0
        or max_bundle_bytes > MAX_BUNDLE_BYTES
    ):
        raise ValueError("max_bundle_bytes must be between 1 and 256 MiB")
    artifacts, retained_digest, declared_digest = _scan_artifacts(
        Path(bundle_dir),
        require_declared_digest=True,
        max_bundle_bytes=max_bundle_bytes,
    )
    assert declared_digest is not None
    if declared_digest != retained_digest:
        raise ArtifactValidationError(
            "manifest retained_bundle_digest_v2 does not match the exact eight-artifact bundle"
        )
    total_bytes = sum(artifact.size for artifact in artifacts)
    return ArtifactInventory(
        artifacts=artifacts,
        total_bytes=total_bytes,
        retained_bundle_digest_v2=retained_digest,
        inventory_digest_v2=_inventory_digest(artifacts),
    )


def _publication_destination_from_run(state: Mapping[str, Any]) -> str:
    mode = state.get("mode")
    window = state.get("window")
    run_ref = state.get("run_ref")
    if mode not in {"daily", "weekly", "baseline", "session"} or not isinstance(
        window, Mapping
    ):
        raise PublicationRejected("run has no canonical publication destination")
    start = window.get("start")
    end = window.get("end")
    if (
        not isinstance(start, str)
        or not isinstance(end, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}", start[:10]) is None
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}", end[:10]) is None
        or not isinstance(run_ref, str)
        or ":" not in run_ref
        or _SHA256_RE.fullmatch(run_ref.rsplit(":", 1)[-1]) is None
    ):
        raise PublicationRejected("run has no canonical publication destination")
    window_name = start[:10] if mode == "daily" else f"{start[:10]}_to_{end[:10]}"
    return f"runs/{mode}/{window_name}/{run_ref.rsplit(':', 1)[-1]}"


def _host_cursor_vector_from_durable_state(
    durable_state: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    expected_rows = {
        row["host_ref"]: row for row in durable_state.get("expected_cursor_rows", [])
    }
    proposed_rows = {
        row["host_ref"]: row for row in durable_state["proposed_cursor_rows"]
    }
    vector: dict[str, dict[str, Any]] = {}
    for host_ref in sorted(set(expected_rows) | set(proposed_rows)):
        before = expected_rows.get(
            host_ref,
            {
                "backlog_ref": None,
                "cursor_ref": None,
                "host_ref": host_ref,
                "logical_boundary": None,
            },
        )
        after = proposed_rows.get(
            host_ref,
            {
                "backlog_ref": None,
                "cursor_ref": None,
                "host_ref": host_ref,
                "logical_boundary": None,
            },
        )
        if before == after:
            continue
        vector[host_ref] = HostCursorUpdate(
            expected_cursor=before["cursor_ref"],
            proposed_cursor=after["cursor_ref"],
            coverage_complete=(after["backlog_ref"] is None),
            expected_backlog_head=before["backlog_ref"],
            proposed_backlog_head=after["backlog_ref"],
        ).to_dict()
    return vector


def _load_run_publication_authority(
    *,
    run_dir: Path,
    identity_path: Path,
    bundle_dir: Path,
    inventory: ArtifactInventory,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    identity = IdentityKey.load(identity_path)
    snapshot = AtomicCheckpointStore(run_dir, identity=identity).read()
    run_state = snapshot.state
    if run_state.get("identity_key_id") != identity.key_id:
        raise PublicationRejected("run checkpoint identity does not match")
    try:
        validate_run_source_authority(
            identity,
            run_state,
            canonical_hosts=CANONICAL_HOSTS,
        )
    except RunStateAuthorityError as exc:
        raise PublicationRejected(str(exc)) from exc
    if run_state.get("shadow") is not False:
        raise PublicationRejected("shadow runs cannot create formal publication")
    if run_state.get("stage") not in {"export", "finalize", "complete"}:
        raise PublicationRejected("run is not in formal publication")
    publication = run_state.get("publication")
    run_authority = run_state.get("authority")
    if not isinstance(publication, Mapping) or not isinstance(run_authority, Mapping):
        raise PublicationRejected("run lacks persisted publication authority")
    if publication.get("bundle_digest") != inventory.retained_bundle_digest_v2:
        raise PublicationRejected("candidate digest differs from the run checkpoint")
    raw_durable = publication.get("durable_state")
    if not isinstance(raw_durable, Mapping):
        raise PublicationRejected("run lacks proposed durable provider state")
    required_authority_fields = {
        "configuration_root",
        "configuration_ref",
        "history_repo",
        "history_snapshot",
        "history_target_ref",
        "model_era",
        "policy_era",
        "production_marker",
        "provider_state",
        "publisher_fingerprint",
        "publisher_gnupg_home",
    }
    if set(run_authority) != required_authority_fields:
        raise PublicationRejected("run publication authority has an unexpected shape")
    for field in ("history_repo", "provider_state", "production_marker"):
        if not isinstance(run_authority[field], str) or not run_authority[field]:
            raise PublicationRejected(f"run publication authority lacks {field}")
    try:
        expected_history = authority.history_state_from_projection(
            run_authority["history_snapshot"],
            identity=identity,
        )
        current_history = authority.load_durable_history(
            run_authority["history_repo"],
            run_authority["history_target_ref"],
            identity=identity,
            expected_fingerprint=run_authority["publisher_fingerprint"],
            gnupg_home=run_authority["publisher_gnupg_home"],
        )
        if canonical_json_bytes(current_history.provider_projection()) != (
            canonical_json_bytes(expected_history.provider_projection())
        ):
            raise PublicationRejected("durable history advanced after run start")
        authority.assert_provider_cache_matches(
            run_authority["provider_state"],
            current_history,
            identity=identity,
        )
        marker = authority.load_production_marker(
            run_authority["production_marker"],
            identity=identity,
            history_repo=run_authority["history_repo"],
            target_ref=run_authority["history_target_ref"],
            configuration_root=run_authority["configuration_root"],
            configuration_ref=run_authority["configuration_ref"],
            model_era=run_authority["model_era"],
            policy_era=run_authority["policy_era"],
        )
        expected_durable = authority.durable_state_manifest(
            expected=expected_history,
            proposed_cursor_rows=raw_durable["proposed_cursor_rows"],
            proposed_episode_heads=raw_durable["proposed_episode_heads"],
            identity=identity,
            source_snapshot_refs=raw_durable["source_snapshot_refs"],
            backfill_of=raw_durable["backfill_of"],
        )
    except (KeyError, TypeError, authority.AuthorityError) as exc:
        raise PublicationRejected("publication authority validation failed") from exc
    if canonical_json_bytes(raw_durable) != canonical_json_bytes(expected_durable):
        raise PublicationRejected("proposed durable state is not derived")

    artifacts = {
        name: safe_io.read_bounded_bytes(
            bundle_dir / name,
            max_bytes=MAX_BUNDLE_BYTES,
            require_owner_only=True,
        )
        for name in ARTIFACT_NAMES
    }
    try:
        parsed = reporting.validate_retained_artifacts(artifacts)
    except reporting.RetainedReportingError as exc:
        raise PublicationRejected("candidate retained bundle is invalid") from exc
    manifest_durable = parsed["manifest"].get("durable_state")
    if canonical_json_bytes(manifest_durable) != canonical_json_bytes(raw_durable):
        raise PublicationRejected("candidate manifest durable state changed")

    for job in run_state.get("jobs", {}).values():
        if job.get("status") not in {"accepted", "gap"}:
            raise PublicationRejected("publication has an open source or agent lease")
        for attempt in job.get("attempts", []):
            if attempt.get("sink_state") == "open":
                raise PublicationRejected("publication has an open agent result sink")

    expected_cursor_rows = [dict(row) for row in expected_history.cursor_rows]
    durable_with_expected_rows = dict(raw_durable)
    durable_with_expected_rows["expected_cursor_rows"] = expected_cursor_rows
    host_cursor_vector = _host_cursor_vector_from_durable_state(
        durable_with_expected_rows
    )
    episode_update = {
        "backfill_lineage_receipt": run_state.get("lineage", {}).get(
            "backfill_lineage_receipt"
        ),
        "expected_episode_head_set_ref": expected_history.episode_head_root_ref,
        "proposed_episode_head_set_ref": raw_durable["proposed_episode_head_root_ref"],
        "proposed_episode_heads": deepcopy(raw_durable["proposed_episode_heads"]),
        "schema": EPISODE_HEAD_UPDATE_SCHEMA,
    }
    binding = {
        "candidate_digest": inventory.retained_bundle_digest_v2,
        "configuration_root": run_authority["configuration_root"],
        "configuration_ref": run_authority["configuration_ref"],
        "destination": _publication_destination_from_run(run_state),
        "expected_history": expected_history.provider_projection(),
        "history_repo": run_authority["history_repo"],
        "identity_key_id": identity.key_id,
        "identity_path": str(identity_path),
        "production_marker": run_authority["production_marker"],
        "proposed_durable_state": deepcopy(raw_durable),
        "provider_state": run_authority["provider_state"],
        "publisher_fingerprint": run_authority["publisher_fingerprint"],
        "publisher_gnupg_home": run_authority["publisher_gnupg_home"],
        "run_dir": str(run_dir),
        "schema": FORMAL_AUTHORIZATION_SCHEMA,
        "target_ref": run_authority["history_target_ref"],
        "marker_authentication_tag": marker["authentication_tag"],
        "model_era": run_authority["model_era"],
        "policy_era": run_authority["policy_era"],
    }
    return binding, host_cursor_vector, episode_update


def _validate_persistent_publication_claim(
    *,
    run_dir: Path,
    identity_path: Path,
    attempt_ref: str,
    plan_digest: str,
) -> dict[str, Any]:
    identity = IdentityKey.load(identity_path)
    snapshot = AtomicCheckpointStore(run_dir, identity=identity).read()
    run_state = snapshot.state
    publication = run_state.get("publication")
    authority_binding = run_state.get("authority")
    if not isinstance(publication, Mapping) or not isinstance(
        authority_binding, Mapping
    ):
        raise PublicationRejected("run lacks a persistent publication claim")
    try:
        validate_run_source_authority(
            identity,
            run_state,
            canonical_hosts=CANONICAL_HOSTS,
        )
    except RunStateAuthorityError as exc:
        raise PublicationRejected(str(exc)) from exc
    claim = publication.get("publication_claim")
    fields = {
        "attempt_ref",
        "authentication_tag",
        "bundle_digest",
        "checkpoint_revision",
        "durable_state_digest",
        "expected_history_commit",
        "history_target_ref",
        "identity_key_id",
        "plan_digest",
        "receipt_ref",
        "run_ref",
        "schema",
    }
    if not isinstance(claim, Mapping) or set(claim) != fields:
        raise PublicationRejected("run lacks a valid persistent publication claim")
    checkpoint_revision = claim.get("checkpoint_revision")
    durable_state = publication.get("durable_state")
    history_snapshot = authority_binding.get("history_snapshot")
    if (
        not isinstance(checkpoint_revision, int)
        or isinstance(checkpoint_revision, bool)
        or checkpoint_revision < 1
        or checkpoint_revision > snapshot.revision
        or not isinstance(durable_state, Mapping)
        or not isinstance(history_snapshot, Mapping)
        or not isinstance(history_snapshot.get("history_commit"), str)
    ):
        raise PublicationRejected("publication claim checkpoint fence is invalid")
    body = {
        "attempt_ref": attempt_ref,
        "bundle_digest": publication.get("bundle_digest"),
        "checkpoint_revision": checkpoint_revision,
        "durable_state_digest": identity.derive_digest(
            "publication-claim-durable-state/v2",
            dict(durable_state),
        ),
        "expected_history_commit": history_snapshot["history_commit"],
        "history_target_ref": authority_binding.get("history_target_ref"),
        "identity_key_id": identity.key_id,
        "plan_digest": plan_digest,
        "run_ref": run_state.get("run_ref"),
        "schema": PUBLICATION_CLAIM_SCHEMA,
    }
    expected_ref = "publication_claim_v2:" + identity.derive_digest(
        "publication_claim_v2", body
    )
    expected_auth = "publication_claim_auth_v2:" + identity.derive_digest(
        "publication_claim_auth_v2", body
    )
    expected = {
        **body,
        "authentication_tag": expected_auth,
        "receipt_ref": expected_ref,
    }
    if (
        claim.get("attempt_ref") != attempt_ref
        or claim.get("plan_digest") != plan_digest
        or not isinstance(claim.get("receipt_ref"), str)
        or _PUBLICATION_CLAIM_REF_RE.fullmatch(claim["receipt_ref"]) is None
        or not isinstance(claim.get("authentication_tag"), str)
        or _PUBLICATION_CLAIM_AUTH_RE.fullmatch(claim["authentication_tag"]) is None
        or not hmac.compare_digest(
            canonical_json_bytes(dict(claim)),
            canonical_json_bytes(expected),
        )
    ):
        raise PublicationRejected(
            "publication claim does not match this checkpoint revision and transaction"
        )
    return deepcopy(expected)


def _privacy_validate_bundle(
    bundle_dir: Path,
    *,
    expected_inventory: ArtifactInventory,
) -> tuple[dict[str, bytes], Mapping[str, Any]]:
    """Re-read and strictly privacy-validate a bundle immediately before Git use."""

    artifacts = _read_inventory_artifacts_anchored(
        bundle_dir,
        expected_inventory=expected_inventory,
    )
    try:
        parsed = reporting.validate_retained_artifacts(artifacts)
    except Exception as exc:
        raise ArtifactValidationError(
            f"retained privacy validation failed: {exc}"
        ) from exc
    if (
        parsed["manifest"]["retained_bundle_digest_v2"]["value"]
        != expected_inventory.retained_bundle_digest_v2
    ):
        raise ArtifactValidationError(
            "privacy validator and publication inventory disagree"
        )
    return artifacts, parsed


def _read_inventory_artifacts_anchored(
    bundle_dir: Path,
    *,
    expected_inventory: ArtifactInventory,
) -> dict[str, bytes]:
    try:
        normalized, directory_fd = safe_io.open_owner_only_directory(
            bundle_dir,
            reject_symlink_ancestors=True,
        )
    except (OSError, ValueError, safe_io.UnsafePathError) as exc:
        raise ArtifactValidationError(
            f"cannot anchor retained bundle: {bundle_dir}"
        ) from exc
    expected = {artifact.name: artifact for artifact in expected_inventory.artifacts}
    if set(expected) != set(ARTIFACT_NAMES):
        os.close(directory_fd)
        raise ArtifactValidationError("publication inventory is not the exact bundle")
    artifacts: dict[str, bytes] = {}
    try:
        if set(os.listdir(directory_fd)) != set(ARTIFACT_NAMES):
            raise ArtifactValidationError(
                "publication bundle inventory changed before privacy validation"
            )
        for name in ARTIFACT_NAMES_BYTEWISE:
            record = expected[name]
            try:
                observed = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise ArtifactValidationError(
                    f"cannot open retained artifact: {name}"
                ) from exc
            try:
                opened = os.fstat(descriptor)
                _require_same_file(observed, opened, name)
                _validate_artifact_access_policy(
                    descriptor,
                    normalized / name,
                    directory_fd=directory_fd,
                    name=name,
                )
                _require_owner_mode(
                    normalized / name,
                    opened,
                    expected_mode=0o600,
                    label=f"retained artifact {name}",
                )
                if opened.st_size != record.size:
                    raise ArtifactValidationError(
                        f"retained artifact size changed: {name}"
                    )
                chunks: list[bytes] = []
                remaining = record.size + 1
                while remaining > 0:
                    chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                payload = b"".join(chunks)
                if len(payload) != record.size or os.read(descriptor, 1):
                    raise ArtifactValidationError(
                        f"retained artifact changed or exceeded inventory: {name}"
                    )
                closed = os.fstat(descriptor)
                _require_same_file(observed, closed, name)
                _validate_artifact_access_policy(
                    descriptor,
                    normalized / name,
                    directory_fd=directory_fd,
                    name=name,
                    changed=True,
                )
            finally:
                os.close(descriptor)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            _require_same_file(observed, current, name)
            if hashlib.sha256(payload).hexdigest() != record.sha256:
                raise ArtifactValidationError(
                    f"retained artifact digest changed: {name}"
                )
            artifacts[name] = payload
        if set(os.listdir(directory_fd)) != set(ARTIFACT_NAMES):
            raise ArtifactValidationError(
                "publication bundle inventory changed during privacy validation"
            )
    finally:
        os.close(directory_fd)
    return artifacts


def _scan_artifacts(
    bundle_dir: Path,
    *,
    require_declared_digest: bool,
    max_bundle_bytes: int = MAX_BUNDLE_BYTES,
) -> tuple[tuple[ArtifactRecord, ...], str, str | None]:
    try:
        root_stat = bundle_dir.lstat()
    except OSError as exc:
        raise ArtifactValidationError(
            f"cannot inspect retained bundle: {bundle_dir}"
        ) from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise ArtifactValidationError("retained bundle root must be a real directory")
    _require_owner_mode(
        bundle_dir, root_stat, expected_mode=0o700, label="retained bundle root"
    )
    try:
        entries = {entry.name: entry for entry in os.scandir(bundle_dir)}
    except OSError as exc:
        raise ArtifactValidationError(
            f"cannot enumerate retained bundle: {bundle_dir}"
        ) from exc
    expected_names = set(ARTIFACT_NAMES)
    actual_names = set(entries)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise ArtifactValidationError(
            f"retained bundle must contain exactly eight artifacts; missing={missing}, extra={extra}"
        )

    entry_stats: dict[str, os.stat_result] = {}
    total_bytes = 0
    for name in ARTIFACT_NAMES_BYTEWISE:
        try:
            entry_stat = entries[name].stat(follow_symlinks=False)
        except OSError as exc:
            raise ArtifactValidationError(
                f"cannot inspect retained artifact: {name}"
            ) from exc
        if not stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
            raise ArtifactValidationError(
                f"retained artifact must be a regular non-symlink file: {name}"
            )
        _require_owner_mode(
            bundle_dir / name,
            entry_stat,
            expected_mode=0o600,
            label=f"retained artifact {name}",
        )
        total_bytes += entry_stat.st_size
        if total_bytes > max_bundle_bytes:
            raise ArtifactValidationError(
                "retained bundle exceeds the configured preparation limit"
            )
        entry_stats[name] = entry_stat

    manifest_bytes = _read_regular_bytes(
        bundle_dir / "manifest.json", entry_stats["manifest.json"]
    )
    manifest = _parse_json_object(manifest_bytes, "manifest.json")
    declared_value = manifest.get("retained_bundle_digest_v2")
    if require_declared_digest and declared_value is None:
        raise ArtifactValidationError(
            "manifest.json is missing retained_bundle_digest_v2"
        )
    declared_digest = (
        _parse_declared_bundle_digest(declared_value)
        if declared_value is not None
        else None
    )
    projection = dict(manifest)
    projection.pop("retained_bundle_digest_v2", None)
    projection_bytes = _canonical_json_bytes(projection) + b"\n"

    bundle_hasher = hashlib.sha256()
    bundle_hasher.update(RETAINED_BUNDLE_DOMAIN_V2)
    artifacts: list[ArtifactRecord] = []
    for name in ARTIFACT_NAMES_BYTEWISE:
        name_bytes = name.encode("ascii")
        bundle_hasher.update(len(name_bytes).to_bytes(2, "big"))
        bundle_hasher.update(name_bytes)
        if name == "manifest.json":
            bundle_hasher.update(len(projection_bytes).to_bytes(8, "big"))
            bundle_hasher.update(projection_bytes)
            digest = hashlib.sha256(manifest_bytes).hexdigest()
        else:
            bundle_hasher.update(entry_stats[name].st_size.to_bytes(8, "big"))
            digest = _hash_regular_file(
                bundle_dir / name,
                entry_stats[name],
                secondary_hasher=bundle_hasher,
            )
        artifacts.append(
            ArtifactRecord(name=name, size=entry_stats[name].st_size, sha256=digest)
        )
    return tuple(artifacts), bundle_hasher.hexdigest(), declared_digest


def _parse_declared_bundle_digest(value: Any) -> str:
    if not isinstance(value, Mapping) or set(value) != {
        "algorithm",
        "version",
        "value",
    }:
        raise ArtifactValidationError(
            "retained_bundle_digest_v2 object has an invalid shape"
        )
    if value.get("algorithm") != "sha256" or value.get("version") != 2:
        raise ArtifactValidationError(
            "retained_bundle_digest_v2 algorithm or version is invalid"
        )
    digest = value.get("value")
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise ArtifactValidationError(
            "retained_bundle_digest_v2 must be lowercase SHA-256"
        )
    return digest


@contextmanager
def _checked_open(path: Path, expected: os.stat_result):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactValidationError(
            f"cannot open retained artifact: {path.name}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        _require_same_file(expected, opened, path.name)
        _validate_artifact_access_policy(descriptor, path)
        yield descriptor
        closed = os.fstat(descriptor)
        _require_same_file(expected, closed, path.name)
        _validate_artifact_access_policy(descriptor, path, changed=True)
    finally:
        os.close(descriptor)


def _read_regular_bytes(path: Path, expected: os.stat_result) -> bytes:
    chunks: list[bytes] = []
    total = 0
    with _checked_open(path, expected) as descriptor:
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    if total != expected.st_size:
        raise ArtifactValidationError(
            f"retained artifact changed while reading: {path.name}"
        )
    return b"".join(chunks)


def _hash_regular_file(
    path: Path,
    expected: os.stat_result,
    *,
    secondary_hasher: Any,
) -> str:
    hasher = hashlib.sha256()
    total = 0
    with _checked_open(path, expected) as descriptor:
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            hasher.update(chunk)
            secondary_hasher.update(chunk)
            total += len(chunk)
    if total != expected.st_size:
        raise ArtifactValidationError(
            f"retained artifact changed while reading: {path.name}"
        )
    return hasher.hexdigest()


def _require_same_file(
    expected: os.stat_result, actual: os.stat_result, name: str
) -> None:
    expected_tuple = (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_size,
        expected.st_uid,
        expected.st_nlink,
    )
    actual_tuple = (
        actual.st_dev,
        actual.st_ino,
        actual.st_mode,
        actual.st_size,
        actual.st_uid,
        actual.st_nlink,
    )
    if expected_tuple != actual_tuple or not stat.S_ISREG(actual.st_mode):
        raise ArtifactValidationError(
            f"retained artifact changed while reading: {name}"
        )


def _validate_artifact_access_policy(
    descriptor: int,
    path: Path,
    *,
    directory_fd: int | None = None,
    name: str | None = None,
    changed: bool = False,
) -> None:
    try:
        safe_io.validate_owner_only_file_descriptor(
            descriptor,
            path,
            directory_fd=directory_fd,
            name=name,
        )
    except (OSError, safe_io.UnsafePathError) as exc:
        state = "changed while reading" if changed else "is invalid"
        raise ArtifactValidationError(
            f"retained artifact access policy {state}: {path.name}"
        ) from exc


def _require_owner_mode(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_mode: int,
    label: str,
) -> None:
    current_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
    if metadata.st_uid != current_uid:
        raise ArtifactValidationError(
            f"{label} is not owned by the current user: {path}"
        )
    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
        raise ArtifactValidationError(
            f"{label} must have exactly one hard link: {path}"
        )
    actual_mode = stat.S_IMODE(metadata.st_mode)
    if actual_mode != expected_mode:
        raise ArtifactValidationError(
            f"{label} must have mode {expected_mode:04o}, found {actual_mode:04o}: {path}"
        )
