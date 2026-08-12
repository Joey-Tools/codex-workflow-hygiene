"""Receipt-bound staging for accepted source payloads."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Sequence

from . import safe_io
from .identity import IdentityKey
from .orchestrator_core import RAW_INPUT_DIRECTORY
from .orchestrator_support import InvalidTransitionError


@dataclass(frozen=True, slots=True)
class PreparedFile:
    path: Path
    payload: bytes

    @property
    def byte_count(self) -> int:
        return len(self.payload)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


MaterializedFile = safe_io.AtomicCreateReceipt


@dataclass(slots=True)
class MaterializedFiles:
    """Preallocated rollback authority for one staged transaction."""

    slots: list[safe_io.AtomicCreateReceiptSlot]

    @property
    def receipts(self) -> list[MaterializedFile | None]:
        return list(map(lambda slot: slot.receipt, self.slots))

    def __len__(self) -> int:
        return sum(slot.receipt is not None for slot in self.slots)


def prepare_file(path: Path, payload: bytes) -> PreparedFile:
    if not isinstance(payload, bytes):
        raise TypeError("prepared source payload must be bytes")
    return PreparedFile(path=path.expanduser().absolute(), payload=payload)


def prepare_raw_payload(
    identity: IdentityKey,
    run_dir: Path,
    unit_ref: str,
    payload: bytes,
) -> tuple[str, PreparedFile]:
    relative_path = raw_payload_relative_path(identity, unit_ref, len(payload))
    return relative_path, prepare_file(run_dir / relative_path, payload)


def raw_payload_relative_path(
    identity: IdentityKey,
    unit_ref: str,
    byte_count: int,
) -> str:
    digest = identity.derive_digest(
        "raw-input-file/v2",
        {"byte_count": byte_count, "unit_ref": unit_ref},
    )
    return f"{RAW_INPUT_DIRECTORY}/{digest}.bin"


def allocate_materializations(file_count: int) -> MaterializedFiles:
    if (
        isinstance(file_count, bool)
        or not isinstance(file_count, int)
        or file_count < 0
    ):
        raise TypeError("materialization file count must be a nonnegative integer")
    return MaterializedFiles(
        slots=list(map(lambda _: safe_io.AtomicCreateReceiptSlot(), range(file_count)))
    )


def materialize_file(
    prepared: PreparedFile,
    materialized: MaterializedFiles,
    index: int,
) -> None:
    if not isinstance(prepared, PreparedFile):
        raise TypeError("source materialization requires a prepared file")
    if (
        not isinstance(materialized, MaterializedFiles)
        or isinstance(index, bool)
        or not isinstance(index, int)
        or index < 0
        or index >= len(materialized.slots)
        or materialized.slots[index].receipt is not None
    ):
        raise TypeError("source materialization receipt slot is invalid")
    safe_io.ensure_owner_only_directory(prepared.path.parent)
    try:
        safe_io.atomic_create_bytes_with_receipt(
            prepared.path,
            prepared.payload,
            create_parents=False,
            receipt_slot=materialized.slots[index],
        )
    except FileExistsError:
        existing = safe_io.read_bounded_bytes(
            prepared.path,
            max_bytes=max(1, prepared.byte_count),
            require_owner_only=True,
        )
        if existing != prepared.payload:
            raise InvalidTransitionError("staged source file changed")


def materialize(files: Sequence[PreparedFile]) -> MaterializedFiles:
    materialized = allocate_materializations(len(files))
    try:
        for index, prepared in enumerate(files):
            materialize_file(prepared, materialized, index)
    except BaseException as error:
        try:
            rollback(materialized)
        except BaseException as rollback_error:
            if hasattr(error, "add_note"):
                error.add_note(
                    "staged source rollback was incomplete; "
                    f"{type(rollback_error).__name__}"
                )
        raise
    return materialized


def rollback(files: MaterializedFiles) -> None:
    if not isinstance(files, MaterializedFiles):
        raise InvalidTransitionError(
            "staged source rollback lacks a creation identity ledger"
        )
    primary: BaseException | None = None
    index = len(files.slots) - 1
    while index >= 0:
        receipt = files.slots[index].receipt
        index -= 1
        if receipt is None:
            continue
        try:
            safe_io.remove_atomic_created_bytes(receipt)
        except (OSError, safe_io.UnsafePathError) as error:
            failure = InvalidTransitionError("staged source rollback target changed")
            failure.__cause__ = error
            if primary is None:
                primary = failure
            elif hasattr(primary, "add_note"):
                primary.add_note(
                    "additional staged source rollback failure: "
                    f"{type(failure).__name__}: {failure}"
                )
    if primary is not None:
        raise primary
