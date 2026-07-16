"""Low-level coordinator constants, errors, and deterministic value helpers."""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any, Mapping, Sequence

from .checkpoints import canonical_json_bytes
from .contracts import RunStage, SourceCellStatus, SourceKind

ENGINE_VERSION = "2.0"
STATE_SCHEMA_VERSION = 2
DEFAULT_HOSTS = ("local", "miku-bot-dev", "hoteng-srv-01")
REQUIRED_SOURCE_KINDS = (
    SourceKind.SESSION_INDEX.value,
    SourceKind.HISTORY.value,
    SourceKind.ACTIVE_ROLLOUT.value,
    SourceKind.ARCHIVED_ROLLOUT.value,
)
MAX_RETENTION_DAYS = 7
MAX_EXPORT_RETENTION_HOURS = 72
MAX_BASELINE_WINDOW_DAYS = 90
RAW_INPUT_DIRECTORY = "raw-inputs"
RAW_SHARD_DIRECTORY = "raw-shards"
SHADOW_CLEANUP_ROOTS = (RAW_INPUT_DIRECTORY, RAW_SHARD_DIRECTORY, "agent-sinks")
EXTRACTOR_SHARD_MAX_BYTES = 320 * 1024
MAX_AGENT_ENVELOPE_BYTES = 512 * 1024
DEFAULT_AGENT_CLAIM_TTL_SECONDS = 300
MIN_AGENT_CLAIM_TTL_SECONDS = 30
MAX_AGENT_CLAIM_TTL_SECONDS = 3600

_SOURCE_TERMINAL = frozenset(status.value for status in SourceCellStatus)
_NON_GAP_SOURCE_TERMINAL = frozenset(
    {
        SourceCellStatus.COMPLETE.value,
        SourceCellStatus.NO_ACTIVITY.value,
        SourceCellStatus.VERIFIED_ABSENT.value,
    }
)
_TASK_TERMINAL = frozenset({"accepted", "gap"})
_SAFE_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_SAFE_ERA_RE = re.compile(r"[a-z0-9][a-z0-9_]{0,127}\Z")
_OPAQUE_REF_RE = re.compile(r"[a-z_]+_ref_v2:[0-9a-f]{64}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_PUBLICATION_ATTEMPT_RE = re.compile(r"attempt_ref_v2:[0-9a-f]{64}\Z")
_KEY_ID_RE = re.compile(r"identity_key_v2:[0-9a-f]{64}\Z")

_STAGE_SEQUENCE = (
    RunStage.SOURCE_CATALOG.value,
    RunStage.SHARDING.value,
    RunStage.EXTRACTION.value,
    RunStage.EPISODE_REVIEW.value,
    RunStage.TOPIC_REDUCTION.value,
    RunStage.GLOBAL_SYNTHESIS.value,
    RunStage.EXPORT.value,
)


class OrchestratorError(RuntimeError):
    """Base error for deterministic orchestration failures."""


class RunNotStartedError(OrchestratorError):
    """Raised when an action is requested before start."""


class RunConflictError(OrchestratorError):
    """Raised when an immutable action is replayed with different input."""


class InvalidTransitionError(OrchestratorError):
    """Raised when an action is not legal in the current run stage."""


class InvalidInputError(OrchestratorError, ValueError):
    """Raised when deterministic input validation fails."""


def _json_copy(value: Any, *, label: str = "value") -> Any:
    try:
        return json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise InvalidInputError(f"{label} must be finite canonical JSON") from error


def _as_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        if not value:
            raise InvalidInputError(f"{label} cannot be empty")
        return {"id": value}
    if not isinstance(value, Mapping):
        raise InvalidInputError(f"{label} must be a mapping or string")
    copied = _json_copy(dict(value), label=label)
    if not isinstance(copied, dict):
        raise InvalidInputError(f"{label} must be a JSON object")
    return copied


def _parse_timestamp(value: str, *, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise InvalidInputError(f"{label} must be a non-empty timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as error:
        raise InvalidInputError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidInputError(f"{label} must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def _format_timestamp(value: dt.datetime) -> str:
    normalized = value.astimezone(dt.timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _normalize_timestamp(value: str, *, label: str) -> str:
    return _format_timestamp(_parse_timestamp(value, label=label))


def _safe_reason(value: Any, *, fallback: str) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower().replace("-", "_")
        if _SAFE_REASON_RE.fullmatch(normalized):
            return normalized
    return fallback


def _normalize_hosts(hosts: Sequence[str] | None) -> tuple[str, ...]:
    selected = DEFAULT_HOSTS if hosts is None else tuple(hosts)
    if not selected:
        raise InvalidInputError("at least one host is required")
    normalized: list[str] = []
    seen: set[str] = set()
    for host in selected:
        if (
            not isinstance(host, str)
            or not host
            or len(host.encode("utf-8")) > 128
            or any(ord(character) < 0x20 for character in host)
        ):
            raise InvalidInputError("host names must be bounded non-empty strings")
        if host in seen:
            raise InvalidInputError(f"duplicate host: {host}")
        seen.add(host)
        normalized.append(host)
    if set(normalized) == set(DEFAULT_HOSTS):
        return DEFAULT_HOSTS
    return tuple(normalized)


def _normalize_source_kinds(
    source_kinds: Sequence[str | SourceKind] | None,
) -> tuple[str, ...]:
    if source_kinds is None:
        return REQUIRED_SOURCE_KINDS
    try:
        selected = tuple(SourceKind(value).value for value in source_kinds)
    except (TypeError, ValueError) as error:
        raise InvalidInputError("unknown source kind") from error
    if len(set(selected)) != len(selected):
        raise InvalidInputError("source kinds must be unique")
    if set(selected) != set(REQUIRED_SOURCE_KINDS):
        raise InvalidInputError("ordinary runs require the complete source-kind matrix")
    return REQUIRED_SOURCE_KINDS
