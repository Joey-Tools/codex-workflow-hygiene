"""Anchored owner-only publication state storage and provider-state validation."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

from . import safe_io
from .publication_contracts import (
    _SHA1_OR_SHA256_OBJECT_RE,
    _SHA256_RE,
    EPISODE_HEAD_UPDATE_SCHEMA,
    LOCAL_GIT_CAPACITY_RESERVATION_SCHEMA,
    LOCAL_GIT_CLEANUP_CLAIM_PREFIX,
    LOCAL_GIT_CLEANUP_CLAIM_SCHEMA,
    LOCAL_GIT_RECEIPT_PREFIX,
    MAX_STATE_BYTES,
    PROVIDER_EPISODE_HEADS_SCHEMA,
    READ_CHUNK_BYTES,
    STATE_SCHEMA_VERSION,
    AppendOnlyViolation,
    ArtifactInventory,
    StateCorruptionError,
    _canonical_json_bytes,
    _normalize_episode_head_update,
    _normalize_host_cursor_vector,
    _normalize_publication_authority,
    _reject_credential_fields,
    _reject_state_json_constant,
    _require_mapping,
    _sha256_json,
    _state_duplicate_keys,
    _validate_attempt_ref,
    _validate_destination_state,
    _validate_optional_ref,
    _validate_optional_ref_state,
    _validate_ref,
    _validate_ref_state,
)


def read_provider_episode_heads_state(
    state_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Read the provider head set under its anchored publication lock."""

    directory = _AnchoredStateDirectory.open(Path(state_dir).absolute())
    try:
        with _anchored_lock(directory, "publication.lock"):
            if directory.exists("provider-cas-v2.json"):
                raise StateCorruptionError(
                    "provider state has an unfinished cursor/head-set CAS"
                )
            value = directory.read_json("episode-heads.json")
            _validate_episode_heads_state(value)
            return deepcopy(value)
    finally:
        directory.close()


class _AnchoredStateDirectory:
    """Owner-only state directory held by descriptor across path replacement."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self.descriptor = descriptor

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        create: bool = False,
    ) -> _AnchoredStateDirectory:
        try:
            normalized, descriptor = safe_io.open_owner_only_directory(
                path,
                create=create,
                reject_symlink_ancestors=True,
            )
        except (OSError, ValueError, safe_io.UnsafePathError) as exc:
            raise StateCorruptionError(
                f"cannot anchor publication state directory: {path.absolute()}"
            ) from exc
        return cls(normalized, descriptor)

    @staticmethod
    def _validate_directory_descriptor(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        current_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != current_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise StateCorruptionError(
                "publication state directory descriptor is not owner-only"
            )

    @staticmethod
    def _name(value: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or value in {".", ".."}
            or "/" in value
            or "\x00" in value
        ):
            raise StateCorruptionError("publication state name is invalid")
        return value

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def exists(self, name: str) -> bool:
        normalized = self._name(name)
        try:
            os.stat(normalized, dir_fd=self.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    def unlink(self, name: str) -> None:
        normalized = self._name(name)
        try:
            metadata = os.stat(
                normalized,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StateCorruptionError(
                "publication state unlink target is not a regular file"
            )
        os.unlink(normalized, dir_fd=self.descriptor)
        os.fsync(self.descriptor)

    def child(
        self,
        name: str,
        *,
        create: bool = False,
    ) -> _AnchoredStateDirectory:
        normalized = self._name(name)
        if create:
            try:
                os.mkdir(normalized, 0o700, dir_fd=self.descriptor)
                os.fsync(self.descriptor)
            except FileExistsError:
                pass
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            observed = os.stat(
                normalized,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            descriptor = os.open(normalized, flags, dir_fd=self.descriptor)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise StateCorruptionError(
                "cannot anchor publication state child directory"
            ) from exc
        try:
            self._validate_directory_descriptor(descriptor)
            anchored = os.fstat(descriptor)
            if (observed.st_dev, observed.st_ino) != (
                anchored.st_dev,
                anchored.st_ino,
            ):
                raise StateCorruptionError(
                    "publication state child changed while being anchored"
                )
            return _AnchoredStateDirectory(self.path / normalized, descriptor)
        except Exception:
            os.close(descriptor)
            raise

    def open_lock(self, name: str) -> int:
        normalized = self._name(name)
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        created = False
        descriptor: int | None = None
        try:
            descriptor = os.open(
                normalized,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self.descriptor,
            )
            created = True
        except FileExistsError:
            try:
                observed = os.stat(
                    normalized,
                    dir_fd=self.descriptor,
                    follow_symlinks=False,
                )
                descriptor = os.open(normalized, flags, dir_fd=self.descriptor)
            except OSError as exc:
                raise StateCorruptionError("cannot anchor publication lock") from exc
        try:
            assert descriptor is not None
            if created:
                os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if created:
                observed = os.stat(
                    normalized,
                    dir_fd=self.descriptor,
                    follow_symlinks=False,
                )
            current = os.stat(
                normalized,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            current_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != current_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or (observed.st_dev, observed.st_ino)
                != (metadata.st_dev, metadata.st_ino)
                or (current.st_dev, current.st_ino)
                != (metadata.st_dev, metadata.st_ino)
            ):
                raise StateCorruptionError(
                    "publication lock is not an owner-only anchored file"
                )
            return descriptor
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise

    @staticmethod
    def _encoded(value: Mapping[str, Any]) -> bytes:
        data = _canonical_json_bytes(value) + b"\n"
        if len(data) > MAX_STATE_BYTES:
            raise StateCorruptionError("publication state exceeds the 8 MiB limit")
        return data

    @staticmethod
    def _write_descriptor(descriptor: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise StateCorruptionError("short publication state write")
            offset += written
        os.fsync(descriptor)

    def create_json(self, name: str, value: Mapping[str, Any]) -> None:
        normalized = self._name(name)
        data = self._encoded(value)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        created = False
        try:
            descriptor = os.open(
                normalized,
                flags,
                0o600,
                dir_fd=self.descriptor,
            )
            created = True
            os.fchmod(descriptor, 0o600)
            self._write_descriptor(descriptor, data)
            os.close(descriptor)
            descriptor = None
            os.fsync(self.descriptor)
        except FileExistsError as exc:
            raise StateCorruptionError(
                f"publication state already exists: {self.path / normalized}"
            ) from exc
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                try:
                    os.unlink(normalized, dir_fd=self.descriptor)
                except FileNotFoundError:
                    pass
            raise

    def write_json(self, name: str, value: Mapping[str, Any]) -> None:
        normalized = self._name(name)
        if not self.exists(normalized):
            self.create_json(normalized, value)
            return
        self.read_json(normalized)
        data = self._encoded(value)
        temporary = f".{normalized}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                temporary,
                flags,
                0o600,
                dir_fd=self.descriptor,
            )
            os.fchmod(descriptor, 0o600)
            self._write_descriptor(descriptor, data)
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary,
                normalized,
                src_dir_fd=self.descriptor,
                dst_dir_fd=self.descriptor,
            )
            os.chmod(
                normalized,
                0o600,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            os.fsync(self.descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self.descriptor)
            except FileNotFoundError:
                pass

    def read_json(self, name: str) -> dict[str, Any]:
        normalized = self._name(name)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(normalized, flags, dir_fd=self.descriptor)
        except OSError as exc:
            raise StateCorruptionError(
                f"cannot inspect publication state: {self.path / normalized}"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            current_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != current_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_STATE_BYTES
            ):
                raise StateCorruptionError(
                    "publication state file is not owner-only and bounded"
                )
            chunks: list[bytes] = []
            remaining = MAX_STATE_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_STATE_BYTES:
                raise StateCorruptionError("publication state exceeds the 8 MiB limit")
        finally:
            os.close(descriptor)
        try:
            value = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_state_duplicate_keys,
                parse_constant=_reject_state_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, StateCorruptionError) as exc:
            raise StateCorruptionError(
                "publication state is not valid duplicate-free JSON"
            ) from exc
        if not isinstance(value, dict):
            raise StateCorruptionError("publication state root must be an object")
        return value


@contextmanager
def _anchored_lock(directory: _AnchoredStateDirectory, name: str):
    descriptor = directory.open_lock(name)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _validate_generation_state(value: Mapping[str, Any]) -> None:
    if set(value) != {
        "key_generation",
        "policy_generation",
        "revision",
        "schema_version",
    }:
        raise StateCorruptionError(
            "publication generation state has an unexpected shape"
        )
    if value["schema_version"] != STATE_SCHEMA_VERSION:
        raise StateCorruptionError("publication generation state has the wrong schema")
    if (
        not isinstance(value["revision"], int)
        or isinstance(value["revision"], bool)
        or value["revision"] < 0
    ):
        raise StateCorruptionError("publication generation revision is invalid")
    _validate_ref_state(value["policy_generation"], "policy_generation")
    _validate_ref_state(value["key_generation"], "key_generation")


def _validate_capacity_ledger(value: Mapping[str, Any]) -> None:
    if set(value) != {"limit_bytes", "reservations", "schema_version"}:
        raise StateCorruptionError(
            "publication capacity ledger has an unexpected shape"
        )
    if value["schema_version"] != STATE_SCHEMA_VERSION:
        raise StateCorruptionError("publication capacity ledger has the wrong schema")
    limit = value["limit_bytes"]
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise StateCorruptionError("publication capacity limit is invalid")
    reservations = _require_mapping(value["reservations"], "capacity reservations")
    total = 0
    for attempt_ref, raw_reservation in reservations.items():
        try:
            _validate_attempt_ref(attempt_ref)
        except ValueError as exc:
            raise StateCorruptionError(str(exc)) from exc
        if isinstance(raw_reservation, int) and not isinstance(raw_reservation, bool):
            if raw_reservation <= 0:
                raise StateCorruptionError(
                    "publication capacity reservation is invalid"
                )
            total += raw_reservation
            continue
        reservation = _require_mapping(raw_reservation, "capacity reservation")
        if set(reservation) != {
            "binding_digest",
            "capacity_bytes",
            "schema",
        }:
            raise StateCorruptionError(
                "publication capacity reservation has an unexpected shape"
            )
        if reservation["schema"] != LOCAL_GIT_CAPACITY_RESERVATION_SCHEMA:
            raise StateCorruptionError(
                "publication capacity reservation has the wrong schema"
            )
        amount = reservation["capacity_bytes"]
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise StateCorruptionError("publication capacity reservation is invalid")
        if (
            not isinstance(reservation["binding_digest"], str)
            or _SHA256_RE.fullmatch(reservation["binding_digest"]) is None
        ):
            raise StateCorruptionError(
                "publication capacity reservation binding is invalid"
            )
        total += amount
    if total > limit:
        raise StateCorruptionError(
            "publication capacity ledger exceeds its durable limit"
        )


def _normalize_cursor_store_hosts(
    hosts: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, str | None]]:
    if not isinstance(hosts, Mapping):
        raise ValueError("cursor-state hosts must be a mapping")
    normalized: dict[str, dict[str, str | None]] = {}
    for host_ref, raw in sorted(hosts.items()):
        _validate_ref(host_ref, "host_ref")
        if not isinstance(raw, Mapping) or set(raw) != {"backlog_head", "cursor"}:
            raise ValueError(f"cursor-state host {host_ref!r} has an unexpected shape")
        _validate_optional_ref(raw["cursor"], f"{host_ref}.cursor")
        _validate_optional_ref(raw["backlog_head"], f"{host_ref}.backlog_head")
        normalized[host_ref] = {
            "backlog_head": raw["backlog_head"],
            "cursor": raw["cursor"],
        }
    return normalized


def _validate_cursor_state(value: Mapping[str, Any]) -> None:
    if set(value) != {
        "applied_publications",
        "hosts",
        "last_publication",
        "revision",
        "schema_version",
    }:
        raise StateCorruptionError("cursor state has an unexpected shape")
    if value["schema_version"] != STATE_SCHEMA_VERSION:
        raise StateCorruptionError("cursor state has the wrong schema")
    revision = value["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise StateCorruptionError("cursor state revision is invalid")
    try:
        normalized_hosts = _normalize_cursor_store_hosts(
            _require_mapping(value["hosts"], "cursor hosts")
        )
    except (StateCorruptionError, ValueError) as exc:
        raise StateCorruptionError(f"cursor state hosts are invalid: {exc}") from exc
    if value["hosts"] != normalized_hosts:
        raise StateCorruptionError("cursor state hosts are not canonical")
    applied = _require_mapping(
        value["applied_publications"], "cursor applied publications"
    )
    revision_records: dict[int, Mapping[str, Any]] = {}
    expected_application_fields = {
        "attempt_ref",
        "expected_episode_head_set_ref",
        "plan_digest",
        "proposed_episode_head_set_ref",
        "revision_after",
        "revision_before",
        "target_head",
        "vector_digest",
    }
    for attempt_ref, raw_record in applied.items():
        try:
            _validate_attempt_ref(attempt_ref)
        except ValueError as exc:
            raise StateCorruptionError(str(exc)) from exc
        record = _require_mapping(raw_record, "cursor applied publication")
        if set(record) != expected_application_fields:
            raise StateCorruptionError(
                "cursor applied publication has an unexpected shape"
            )
        if record["attempt_ref"] != attempt_ref:
            raise StateCorruptionError("cursor applied publication attempt differs")
        for digest_field in ("plan_digest", "vector_digest"):
            if (
                not isinstance(record[digest_field], str)
                or _SHA256_RE.fullmatch(record[digest_field]) is None
            ):
                raise StateCorruptionError(
                    "cursor applied publication has an invalid digest"
                )
        _validate_ref_state(
            record["expected_episode_head_set_ref"],
            "cursor expected episode head-set ref",
        )
        _validate_ref_state(
            record["proposed_episode_head_set_ref"],
            "cursor proposed episode head-set ref",
        )
        _validate_ref_state(record["target_head"], "cursor target head")
        revision_before = record["revision_before"]
        revision_after = record["revision_after"]
        if (
            not isinstance(revision_before, int)
            or isinstance(revision_before, bool)
            or revision_before < 0
            or not isinstance(revision_after, int)
            or isinstance(revision_after, bool)
            or revision_after != revision_before + 1
        ):
            raise StateCorruptionError(
                "cursor applied publication revision lineage is invalid"
            )
        if revision_after in revision_records:
            raise StateCorruptionError(
                "cursor applied publication revisions are not unique"
            )
        revision_records[revision_after] = record
    if sorted(revision_records) != list(range(1, revision + 1)):
        raise StateCorruptionError(
            "cursor applied publication ledger does not cover every revision"
        )
    last = value["last_publication"]
    if last is None:
        if revision != 0 or applied:
            raise StateCorruptionError("cursor state is missing its latest publication")
        return
    if not isinstance(last, Mapping) or set(last) != expected_application_fields:
        raise StateCorruptionError(
            "cursor state last publication has an unexpected shape"
        )
    if revision == 0 or revision_records.get(revision) != last:
        raise StateCorruptionError("cursor state revision lineage is inconsistent")


def _validate_episode_heads_state(value: Mapping[str, Any]) -> None:
    if (
        set(value)
        != {
            "episode_head_set_ref",
            "episode_heads",
            "revision",
            "schema",
        }
        or value.get("schema") != PROVIDER_EPISODE_HEADS_SCHEMA
    ):
        raise StateCorruptionError("episode heads state has an unexpected shape")
    _validate_ref_state(value["episode_head_set_ref"], "episode head-set ref")
    revision = value["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise StateCorruptionError("episode heads state revision is invalid")
    try:
        normalized = _normalize_episode_head_update(
            {
                "backfill_lineage_receipt": None,
                "expected_episode_head_set_ref": value["episode_head_set_ref"],
                "proposed_episode_head_set_ref": value["episode_head_set_ref"],
                "proposed_episode_heads": value["episode_heads"],
                "schema": EPISODE_HEAD_UPDATE_SCHEMA,
            },
            required=True,
        )
    except ValueError as exc:
        raise StateCorruptionError(f"episode heads state is invalid: {exc}") from exc
    if value["episode_heads"] != normalized["proposed_episode_heads"]:
        raise StateCorruptionError("episode heads state is not canonical")


def _validate_append_only_episode_heads(
    current: Sequence[Mapping[str, Any]],
    proposed: Sequence[Mapping[str, Any]],
) -> None:
    current_by_ref = {item["episode_ref"]: item for item in current}
    proposed_by_ref = {item["episode_ref"]: item for item in proposed}
    missing = set(current_by_ref) - set(proposed_by_ref)
    if missing:
        raise AppendOnlyViolation("episode head update removes existing episodes")
    for episode_ref, previous in current_by_ref.items():
        successor = proposed_by_ref[episode_ref]
        if successor == previous:
            continue
        if (
            successor.get("revision_ordinal") != int(previous["revision_ordinal"]) + 1
            or successor.get("supersedes_episode_revision_ref")
            != previous["episode_revision_ref"]
            or successor.get("session_ref") != previous.get("session_ref")
        ):
            raise AppendOnlyViolation(
                "existing episode head must advance by one authenticated successor"
            )
    for episode_ref in set(proposed_by_ref) - set(current_by_ref):
        initial = proposed_by_ref[episode_ref]
        if (
            initial.get("revision_ordinal") != 1
            or initial.get("supersedes_episode_revision_ref") is not None
        ):
            raise AppendOnlyViolation(
                "new episode head must begin with an initial revision"
            )


def _local_cleanup_state_binding_digest(state: Mapping[str, Any]) -> str:
    durable_receipts = {
        name: receipt
        for name, receipt in state["receipts"].items()
        if name not in {"cleanup", "reservation_release"}
    }
    return _sha256_json(
        {
            "attempt_ref": state["attempt_ref"],
            "binding": state["binding"],
            "episode_head_update": state["episode_head_update"],
            "expected_target_head": state["expected_target_head"],
            "generation_snapshot": state["generation_snapshot"],
            "host_cursor_vector": state["host_cursor_vector"],
            "prefixes": state["prefixes"],
            "provider_state_snapshot": state["provider_state_snapshot"],
            "publication_authority": state["publication_authority"],
            "receipts": durable_receipts,
            "retention_bound": state["retention_bound"],
            "staging_ref": state["staging_ref"],
            "target_ref": state["target_ref"],
            "unit_plan": state["unit_plan"],
        }
    )


def _validate_local_receipt_integrity(value: Mapping[str, Any]) -> None:
    receipt = dict(value)
    receipt_ref = receipt.pop("receipt_ref", None)
    expected_ref = LOCAL_GIT_RECEIPT_PREFIX + _sha256_json(receipt)
    if receipt_ref != expected_ref:
        raise StateCorruptionError("local Git receipt integrity check failed")


def _validate_local_cleanup_claim(
    value: Any,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    claim = _require_mapping(value, "local cleanup claim")
    expected_fields = {
        "attempt_ref",
        "capacity_bytes_observed",
        "capacity_reservation_observed",
        "claim_ref",
        "expected_target_head",
        "formal_target_head_at_claim",
        "provider_attempt_reserved",
        "retention_bound",
        "schema",
        "staging_ref",
        "staging_tip",
        "state_binding_digest",
        "terminal_disposition",
        "transaction_ref",
    }
    if set(claim) != expected_fields:
        raise StateCorruptionError("local cleanup claim has an unexpected shape")
    if claim["schema"] != LOCAL_GIT_CLEANUP_CLAIM_SCHEMA:
        raise StateCorruptionError("local cleanup claim has the wrong schema")
    if claim["attempt_ref"] != state["attempt_ref"]:
        raise StateCorruptionError("local cleanup claim has the wrong attempt")
    capacity = claim["capacity_bytes_observed"]
    if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 0:
        raise StateCorruptionError("local cleanup capacity is invalid")
    reserved_capacity = claim["capacity_reservation_observed"]
    if reserved_capacity is not None and (
        not isinstance(reserved_capacity, int)
        or isinstance(reserved_capacity, bool)
        or reserved_capacity <= 0
    ):
        raise StateCorruptionError("local cleanup reservation is invalid")
    reserved = claim["provider_attempt_reserved"]
    if not isinstance(reserved, bool) or not isinstance(claim["retention_bound"], bool):
        raise StateCorruptionError("local cleanup reservation flag is invalid")
    if reserved:
        if capacity <= 0 or reserved_capacity != capacity:
            raise StateCorruptionError(
                "local cleanup claim does not bind the reserved capacity"
            )
    elif capacity != 0 or reserved_capacity is not None:
        raise StateCorruptionError(
            "unreserved local cleanup claim contains provider capacity"
        )
    for field_name in (
        "expected_target_head",
        "formal_target_head_at_claim",
        "staging_tip",
        "transaction_ref",
    ):
        _validate_optional_ref_state(claim[field_name], field_name)
    _validate_ref_state(claim["staging_ref"], "local cleanup staging ref")
    if _SHA256_RE.fullmatch(str(claim["state_binding_digest"])) is None:
        raise StateCorruptionError("local cleanup state digest is invalid")
    if claim["terminal_disposition"] not in {
        "no_seal_abandoned",
        "sealed_rejected",
    }:
        raise StateCorruptionError("local cleanup disposition is invalid")

    seal = state["receipts"].get("seal")
    expected_tip = state["prefixes"][-1]["commit"] if state["prefixes"] else None
    expected = {
        "capacity_bytes_observed": state["capacity_bytes"],
        "expected_target_head": state["expected_target_head"],
        "provider_attempt_reserved": state["receipts"].get("reservation") is not None,
        "retention_bound": state["retention_bound"],
        "staging_ref": state["staging_ref"],
        "staging_tip": expected_tip,
        "state_binding_digest": _local_cleanup_state_binding_digest(state),
        "terminal_disposition": (
            "sealed_rejected" if seal is not None else "no_seal_abandoned"
        ),
        "transaction_ref": (
            seal.get("transaction_ref") if isinstance(seal, Mapping) else None
        ),
    }
    for name, expected_value in expected.items():
        if claim[name] != expected_value:
            raise StateCorruptionError(f"local cleanup claim has a mismatched {name}")
    unsigned = dict(claim)
    claim_ref = unsigned.pop("claim_ref")
    expected_ref = LOCAL_GIT_CLEANUP_CLAIM_PREFIX + _sha256_json(unsigned)
    if claim_ref != expected_ref:
        raise StateCorruptionError("local cleanup claim integrity check failed")
    return dict(claim)


def _validate_local_attempt_state(value: Mapping[str, Any]) -> None:
    expected_fields = {
        "aborted",
        "attempt_ref",
        "binding",
        "capacity_bytes",
        "capacity_held",
        "cleanup_claim",
        "publication_authority",
        "episode_head_update",
        "expected_target_head",
        "formal_promoted",
        "generation_snapshot",
        "host_cursor_vector",
        "prefixes",
        "provider_state_snapshot",
        "receipts",
        "retention_bound",
        "schema_version",
        "staging_ref",
        "state_advanced",
        "target_ref",
        "unit_plan",
    }
    if set(value) != expected_fields:
        raise StateCorruptionError(
            "local Git publication state has an unexpected shape"
        )
    if value["schema_version"] != STATE_SCHEMA_VERSION:
        raise StateCorruptionError("local Git publication state has the wrong schema")
    try:
        _validate_attempt_ref(value["attempt_ref"])
    except ValueError as exc:
        raise StateCorruptionError(str(exc)) from exc
    for field_name in (
        "aborted",
        "capacity_held",
        "formal_promoted",
        "retention_bound",
        "state_advanced",
    ):
        if not isinstance(value[field_name], bool):
            raise StateCorruptionError(
                f"local Git publication {field_name} must be boolean"
            )
    if (
        not isinstance(value["capacity_bytes"], int)
        or isinstance(value["capacity_bytes"], bool)
        or value["capacity_bytes"] < 0
    ):
        raise StateCorruptionError("local Git publication capacity is invalid")
    _validate_ref_state(value["target_ref"], "local Git target ref")
    _validate_optional_ref_state(value["expected_target_head"], "expected target head")
    _validate_ref_state(value["staging_ref"], "local Git staging ref")
    binding = _require_mapping(value["binding"], "local Git binding")
    if set(binding) != {"attempt_ref", "inventory_digest", "plan_digest"}:
        raise StateCorruptionError("local Git attempt binding has an unexpected shape")
    if binding["attempt_ref"] != value["attempt_ref"]:
        raise StateCorruptionError("local Git attempt binding has the wrong attempt")
    generations = _require_mapping(value["generation_snapshot"], "generation snapshot")
    if set(generations) != {"key_generation", "policy_generation", "revision"}:
        raise StateCorruptionError(
            "local Git generation snapshot has an unexpected shape"
        )
    _validate_ref_state(generations["key_generation"], "key generation")
    _validate_ref_state(generations["policy_generation"], "policy generation")
    if (
        not isinstance(generations["revision"], int)
        or isinstance(generations["revision"], bool)
        or generations["revision"] < 0
    ):
        raise StateCorruptionError("local Git generation snapshot revision is invalid")
    provider_snapshot = _require_mapping(
        value["provider_state_snapshot"],
        "provider state snapshot",
    )
    if set(provider_snapshot) != {
        "episode_head_set_ref",
        "history_commit",
        "revision",
    }:
        raise StateCorruptionError(
            "local Git provider state snapshot has an unexpected shape"
        )
    _validate_ref_state(
        provider_snapshot["episode_head_set_ref"],
        "provider episode head-set ref",
    )
    _validate_ref_state(provider_snapshot["history_commit"], "provider history commit")
    if (
        not isinstance(provider_snapshot["revision"], int)
        or isinstance(provider_snapshot["revision"], bool)
        or provider_snapshot["revision"] < 0
    ):
        raise StateCorruptionError(
            "local Git provider state snapshot revision is invalid"
        )
    try:
        normalized_vector = _normalize_host_cursor_vector(
            _require_mapping(value["host_cursor_vector"], "host cursor vector")
        )
    except (StateCorruptionError, ValueError) as exc:
        raise StateCorruptionError(
            f"local Git host cursor vector is invalid: {exc}"
        ) from exc
    if value["host_cursor_vector"] != normalized_vector:
        raise StateCorruptionError("local Git host cursor vector is not canonical")
    try:
        normalized_episode_update = _normalize_episode_head_update(
            _require_mapping(value["episode_head_update"], "episode head update"),
            required=True,
        )
        normalized_authorization = _normalize_publication_authority(
            _require_mapping(value["publication_authority"], "publication authority")
        )
    except (StateCorruptionError, ValueError) as exc:
        raise StateCorruptionError(
            f"local Git formal authorization is invalid: {exc}"
        ) from exc
    if (
        value["episode_head_update"] != normalized_episode_update
        or value["publication_authority"] != normalized_authorization
    ):
        raise StateCorruptionError("local Git formal authorization is not canonical")
    receipts = _require_mapping(value["receipts"], "local Git receipts")
    for receipt in receipts.values():
        _reject_credential_fields(receipt)
    prefixes = value["prefixes"]
    if not isinstance(prefixes, list):
        raise StateCorruptionError("local Git publication prefixes must be a list")
    for ordinal, prefix in enumerate(prefixes):
        if not isinstance(prefix, Mapping) or set(prefix) != {
            "bundle_digest",
            "commit",
            "destination",
            "inventory_digest",
            "ordinal",
            "parent",
            "publication_role",
        }:
            raise StateCorruptionError(
                "local Git publication prefix has an unexpected shape"
            )
        if prefix["ordinal"] != ordinal:
            raise StateCorruptionError(
                "local Git publication prefix order is not canonical"
            )
        for object_field in ("commit", "parent"):
            if _SHA1_OR_SHA256_OBJECT_RE.fullmatch(str(prefix[object_field])) is None:
                raise StateCorruptionError(
                    "local Git publication prefix object ID is invalid"
                )
        _validate_destination_state(prefix["destination"])
        if prefix["publication_role"] != "standalone":
            raise StateCorruptionError("local Git publication prefix role is invalid")
        for digest_field in ("bundle_digest", "inventory_digest"):
            if _SHA256_RE.fullmatch(str(prefix[digest_field])) is None:
                raise StateCorruptionError(
                    "local Git publication prefix digest is invalid"
                )
    units = value["unit_plan"]
    if not isinstance(units, list) or not units:
        raise StateCorruptionError("local Git publication unit plan is empty")
    for unit in units:
        if not isinstance(unit, Mapping) or set(unit) != {
            "bundle_dir",
            "destination",
            "inventory",
        }:
            raise StateCorruptionError(
                "local Git publication unit has an unexpected shape"
            )
        if (
            not isinstance(unit["bundle_dir"], str)
            or not Path(unit["bundle_dir"]).is_absolute()
        ):
            raise StateCorruptionError(
                "local Git publication bundle path must be absolute"
            )
        _validate_destination_state(unit["destination"])
        ArtifactInventory.from_dict(
            _require_mapping(unit["inventory"], "unit inventory")
        )

    reservation = receipts.get("reservation")
    cleanup = receipts.get("cleanup")
    release = receipts.get("reservation_release")
    cleanup_claim = value["cleanup_claim"]
    if value["capacity_bytes"] == 0:
        if (
            cleanup_claim is None
            or reservation is not None
            or value["capacity_held"]
            or prefixes
        ):
            raise StateCorruptionError(
                "zero-capacity publication is not an unreserved cleanup attempt"
            )
    elif reservation is None:
        raise StateCorruptionError(
            "reserved local publication lacks its reservation receipt"
        )
    if cleanup_claim is not None:
        claim = _validate_local_cleanup_claim(cleanup_claim, value)
    else:
        claim = None
    if cleanup is not None:
        if claim is None or value["aborted"] is not True:
            raise StateCorruptionError(
                "local cleanup receipt lacks its durable cleanup claim"
            )
        cleanup_mapping = _require_mapping(cleanup, "local cleanup receipt")
        _validate_local_receipt_integrity(cleanup_mapping)
        if cleanup_mapping.get("cleanup_claim_ref") != claim["claim_ref"]:
            raise StateCorruptionError(
                "local cleanup receipt does not bind its cleanup claim"
            )
    elif value["aborted"]:
        raise StateCorruptionError("aborted local publication lacks cleanup proof")
    if release is not None:
        if cleanup is None or value["capacity_held"]:
            raise StateCorruptionError(
                "local reservation release precedes durable cleanup"
            )
        release_mapping = _require_mapping(
            release,
            "local reservation release receipt",
        )
        _validate_local_receipt_integrity(release_mapping)
        if (
            release_mapping.get("cleanup_receipt_ref") != cleanup_mapping["receipt_ref"]
            or release_mapping.get("cleanup_claim_ref") != claim["claim_ref"]
        ):
            raise StateCorruptionError(
                "local reservation release has a mismatched cleanup proof"
            )
