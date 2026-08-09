"""Bounded descriptor-held spool for segmented source transport."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
from typing import Any, Sequence

from . import safe_io, source_staging
from .identity import IdentityKey
from .orchestrator_core import RAW_INPUT_DIRECTORY
from .orchestrator_support import InvalidTransitionError


SOURCE_TRANSPORT_SPOOL_DIRECTORY = f"{RAW_INPUT_DIRECTORY}/source-spool-v1"


@dataclass(frozen=True, slots=True)
class SpooledRawPayload:
    byte_count: int
    content_commitment: str
    offset: int
    relative_path: str
    unit_ref: str


class StreamingRawPayloadStaging:
    """Retain one bounded source batch outside the heap until checkpoint stage."""

    def __init__(
        self,
        identity: IdentityKey,
        run_dir: Path,
        *,
        max_bytes: int,
        max_records: int,
        spool_ref: str,
    ) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (max_bytes, max_records)
        ) or not isinstance(spool_ref, str):
            raise TypeError("source transport spool bounds are invalid")
        self.identity = identity
        self.run_dir = run_dir.expanduser().absolute()
        self.max_bytes = max_bytes
        self.max_records = max_records
        self.spool_root = safe_io.ensure_owner_only_directory(
            self.run_dir / SOURCE_TRANSPORT_SPOOL_DIRECTORY
        )
        token = identity.derive_digest(
            "source-transport-spool/v1",
            {"spool_ref": spool_ref},
        )
        self._name = f"source-spool-{token}.bin"
        self._lock_name = f"source-spool-{token}.lock"
        self._path = self.spool_root / self._name
        self._lock_path = self.spool_root / self._lock_name
        self._parent_fd = -1
        self._lock_fd = -1
        self._descriptor = -1
        self._identity: tuple[int, int] | None = None
        self._byte_count = 0
        self._records: list[SpooledRawPayload] = []
        self._closed = False
        try:
            _, self._parent_fd = safe_io.open_owner_only_directory(self.spool_root)
            self._acquire_lock()
            self._remove_orphan()
            self._create_spool()
        except BaseException as error:
            self._close_after_failure(error)
            raise

    def _acquire_lock(self) -> None:
        self._lock_fd = safe_io.open_lock_file_at(
            self._parent_fd,
            self._lock_name,
            display_path=self._lock_path,
        )
        safe_io.validate_owner_only_file_descriptor(
            self._lock_fd,
            self._lock_path,
            directory_fd=self._parent_fd,
            name=self._lock_name,
        )
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InvalidTransitionError(
                "source transport spool is already active"
            ) from error
        safe_io.validate_owner_only_file_descriptor(
            self._lock_fd,
            self._lock_path,
            directory_fd=self._parent_fd,
            name=self._lock_name,
        )

    def _remove_orphan(self) -> None:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self._name, flags, dir_fd=self._parent_fd)
        except FileNotFoundError:
            return
        try:
            safe_io.validate_owner_only_file_descriptor(
                descriptor,
                self._path,
                directory_fd=self._parent_fd,
                name=self._name,
            )
            os.unlink(self._name, dir_fd=self._parent_fd)
            os.fsync(self._parent_fd)
        finally:
            os.close(descriptor)

    def _create_spool(self) -> None:
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        self._descriptor = os.open(
            self._name,
            flags,
            safe_io.OWNER_FILE_MODE,
            dir_fd=self._parent_fd,
        )
        safe_io.harden_created_owner_only_file_descriptor(
            self._descriptor,
            self._path,
        )
        os.fsync(self._parent_fd)
        metadata = os.fstat(self._descriptor)
        self._identity = (metadata.st_dev, metadata.st_ino)

    def add(self, unit_ref: str, payload: bytes) -> dict[str, Any]:
        if self._closed:
            raise InvalidTransitionError("source transport spool is already closed")
        if not isinstance(payload, bytes):
            raise TypeError("segmented source payload must be bytes")
        if len(self._records) >= self.max_records:
            raise InvalidTransitionError(
                "source transport spool exceeds its record bound"
            )
        if len(payload) > self.max_bytes - self._byte_count:
            raise InvalidTransitionError(
                "source transport spool exceeds its byte bound"
            )
        offset = self._byte_count
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(self._descriptor, view[written:])
            if count <= 0:
                raise OSError("short write while staging source transport payload")
            written += count
        self._byte_count += len(payload)
        commitment = "sha256:" + hashlib.sha256(payload).hexdigest()
        relative_path = source_staging.raw_payload_relative_path(
            self.identity,
            unit_ref,
            len(payload),
        )
        self._records.append(
            SpooledRawPayload(
                byte_count=len(payload),
                content_commitment=commitment,
                offset=offset,
                relative_path=relative_path,
                unit_ref=unit_ref,
            )
        )
        return {
            "byte_count": len(payload),
            "content_commitment": commitment,
            "relative_path": relative_path,
            "status": "available",
        }

    def materialize(
        self,
        extra_files: Sequence[source_staging.PreparedFile] = (),
    ) -> source_staging.MaterializedFiles:
        if self._closed:
            raise InvalidTransitionError("source transport spool is already closed")
        materialized = source_staging.allocate_materializations(
            len(self._records) + len(extra_files)
        )
        try:
            os.fsync(self._descriptor)
            self._revalidate()
            if os.fstat(self._descriptor).st_size != self._byte_count:
                raise InvalidTransitionError("source transport spool size changed")
            for index, record in enumerate(self._records):
                payload = self._read_record(record)
                source_staging.materialize_file(
                    source_staging.prepare_file(
                        self.run_dir / record.relative_path,
                        payload,
                    ),
                    materialized,
                    index,
                )
            offset = len(self._records)
            for index, prepared in enumerate(extra_files, start=offset):
                source_staging.materialize_file(prepared, materialized, index)
            self.discard()
        except BaseException as error:
            try:
                source_staging.rollback(materialized)
            except BaseException as rollback_error:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "streamed source payload rollback was incomplete; "
                        f"{type(rollback_error).__name__}"
                    )
            try:
                self.discard()
            except BaseException as discard_error:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "source transport spool cleanup was incomplete; "
                        f"{type(discard_error).__name__}"
                    )
            raise
        return materialized

    def discard(self) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        try:
            self._revalidate()
            os.unlink(self._name, dir_fd=self._parent_fd)
            os.fsync(self._parent_fd)
        except BaseException as cleanup_error:
            error = cleanup_error
        error = self._close_all(error)
        self._closed = True
        if error is not None:
            raise InvalidTransitionError(
                "source transport spool cleanup could not prove exact removal"
            ) from error

    def _read_record(self, record: SpooledRawPayload) -> bytes:
        chunks: list[bytes] = []
        remaining = record.byte_count
        offset = record.offset
        while remaining:
            chunk = os.pread(self._descriptor, min(64 * 1024, remaining), offset)
            if not chunk:
                raise InvalidTransitionError("source transport spool is truncated")
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if "sha256:" + hashlib.sha256(payload).hexdigest() != record.content_commitment:
            raise InvalidTransitionError("source transport spool content changed")
        self._revalidate()
        return payload

    def _revalidate(self) -> None:
        safe_io.validate_owner_only_file_descriptor(
            self._descriptor,
            self._path,
            directory_fd=self._parent_fd,
            name=self._name,
        )
        metadata = os.fstat(self._descriptor)
        if (metadata.st_dev, metadata.st_ino) != self._identity:
            raise InvalidTransitionError("source transport spool identity changed")

    def _close_after_failure(self, primary: BaseException) -> None:
        if self._descriptor >= 0:
            try:
                os.unlink(self._name, dir_fd=self._parent_fd)
                os.fsync(self._parent_fd)
            except FileNotFoundError:
                pass
            except OSError as error:
                if hasattr(primary, "add_note"):
                    primary.add_note(
                        "source transport spool cleanup failed during creation: "
                        f"{type(error).__name__}"
                    )
        self._close_all(primary)
        self._closed = True

    def _close_all(self, primary: BaseException | None) -> BaseException | None:
        error = primary
        if self._descriptor >= 0:
            error = _close_descriptor(self._descriptor, error, "spool")
            self._descriptor = -1
        if self._lock_fd >= 0:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except OSError as unlock_error:
                error = _record_error(error, unlock_error, "spool lock release")
            error = _close_descriptor(self._lock_fd, error, "spool lock")
            self._lock_fd = -1
        if self._parent_fd >= 0:
            error = _close_descriptor(self._parent_fd, error, "spool parent")
            self._parent_fd = -1
        return error


def _record_error(
    primary: BaseException | None,
    secondary: BaseException,
    label: str,
) -> BaseException:
    if primary is None:
        return secondary
    if hasattr(primary, "add_note"):
        primary.add_note(f"additional {label} failure: {type(secondary).__name__}")
    return primary


def _close_descriptor(
    descriptor: int,
    primary: BaseException | None,
    label: str,
) -> BaseException | None:
    try:
        os.close(descriptor)
    except OSError as error:
        return _record_error(primary, error, f"{label} close")
    return primary
