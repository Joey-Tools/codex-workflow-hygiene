"""Closed contracts shared by run-state authority validators."""

from __future__ import annotations

from .contracts import RefType, RunStage, SourceCellStatus, SourceKind
from .identity import IdentityKey


REQUIRED_RUN_SOURCE_KINDS = (
    SourceKind.SESSION_INDEX.value,
    SourceKind.HISTORY.value,
    SourceKind.ACTIVE_ROLLOUT.value,
    SourceKind.ARCHIVED_ROLLOUT.value,
)
FORMAL_STAGES = {
    RunStage.EXPORT.value,
    RunStage.FINALIZE.value,
    RunStage.COMPLETE.value,
}
TERMINAL_SOURCE_STATUSES = {item.value for item in SourceCellStatus}


class RunStateAuthorityError(ValueError):
    """Raised when authenticated checkpoint content lacks run authority."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunStateAuthorityError(message)


def derive_ref(identity: IdentityKey, kind: RefType, *parts: object) -> str:
    return str(identity.derive_ref(kind, {"parts": list(parts)}))


def host_ref(identity: IdentityKey, host: str) -> str:
    return derive_ref(identity, RefType.HOST, host)
