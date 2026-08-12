"""Durable-history authority and owner-local production/cache bindings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
import tomllib
from typing import Any, Mapping, Sequence

from . import (
    calibration,
    controlled_gaps,
    episode_review,
    executable_authority,
    git_safety,
    history_graph,
    reporting,
    safe_io,
)
from .authority_errors import AuthorityError as AuthorityError, AutomationCutoverBlocked
from .authority_errors import HistoryValidationError, ProductionMarkerError
from .authority_errors import ProviderCacheConflict, ProviderCacheError
from .contracts import CANONICAL_HOSTS, RefType, canonical_json_bytes
from .identity import IdentityKey
from .orchestrator_core import LEGACY_SHADOW_CLEANUP_ROOTS, SHADOW_CLEANUP_ROOTS


DURABLE_STATE_SCHEMA = "durable_history_state_v2"
PRODUCTION_MARKER_SCHEMA = "production_marker_v2"
AUTOMATION_CUTOVER_RECORD_SCHEMA = "automation_cutover_record_v2"
AUTOMATION_CUTOVER_SNAPSHOT_SCHEMA = "automation_cutover_snapshot_v2"
AUTOMATION_UPDATE_RESULT_SCHEMA = "automation_update_result_v2"
PROVIDER_CACHE_SCHEMA = "provider_cache_v2"
PROVIDER_INITIALIZATION_SCHEMA = "provider_cache_initialization_v2"
DEFAULT_PRODUCTION_MARKER = (
    Path.home() / ".codex/session-retrospective/production-marker-v2.json"
)
DEFAULT_PUBLISHER_GNUPG_HOME = (
    Path.home() / ".codex/session-retrospective/publisher-gnupg-v2"
)
DEFAULT_PUBLISHER_FINGERPRINT = "40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"
PROVIDER_CACHE_FILE = "provider-cache-v2.json"
PROVIDER_CACHE_LOCK = "provider-cache-v2.lock"
AUTOMATION_CUTOVER_RECORD_FILE = "automation-cutover-v2.json"
AUTOMATION_CUTOVER_SNAPSHOT_FILE = "automation-cutover-pre-update-v2.json"
STABLE_AUTOMATION_MODES = {
    "daily-session-retrospective": "daily",
    "weekly-session-retrospective": "weekly",
}
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_PROVIDER_CACHE_BYTES = 64 * 1024 * 1024
MAX_AUTOMATION_RECORD_BYTES = 1024 * 1024
_OBJECT_ID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_OPAQUE_REF_RE = re.compile(r"[a-z_]+_ref_v2:[0-9a-f]{64}\Z")
_EPISODE_REF_RE = re.compile(r"episode_ref_v2:[0-9a-f]{64}\Z")
_EPISODE_CORRECTION_REF_RE = re.compile(r"episode_correction_ref_v2:[0-9a-f]{64}\Z")
_SOURCE_SNAPSHOT_REF_RE = re.compile(r"source_snapshot_v2:[0-9a-f]{64}\Z")
_SOURCE_TRANSPORT_RECEIPT_REF_RE = re.compile(
    r"source_transport_receipt_v2:[0-9a-f]{64}\Z"
)
_SHADOW_SOURCE_COMMITMENT_RE = re.compile(r"shadow_source_evidence_v2:[0-9a-f]{64}\Z")
_SHADOW_POLICY_COMMITMENT_RE = re.compile(r"shadow_policy_commitment_v2:[0-9a-f]{64}\Z")
_SHADOW_VERSION_COMMITMENT_RE = re.compile(
    r"shadow_version_commitment_v2:[0-9a-f]{64}\Z"
)
_SHADOW_CLEANUP_CLAIM_RE = re.compile(r"shadow_cleanup_claim_v[2345]:[0-9a-f]{64}\Z")
_KEY_ID_RE = re.compile(r"identity_key_v2:[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT_REF_RE = re.compile(r"attempt_ref_v2:[0-9a-f]{64}\Z")
_RUN_REF_RE = re.compile(r"run_ref_v2:[0-9a-f]{64}\Z")
_SHADOW_RECEIPT_REF_RE = re.compile(r"shadow_receipt_v2:[0-9a-f]{64}\Z")
_SHADOW_RECEIPT_AUTH_RE = re.compile(r"shadow_receipt_auth_v2:[0-9a-f]{64}\Z")
_SHADOW_COVERAGE_REF_RE = re.compile(r"shadow_coverage_receipt_v2:[0-9a-f]{64}\Z")
_SHADOW_COVERAGE_AUTH_RE = re.compile(r"shadow_coverage_auth_v2:[0-9a-f]{64}\Z")
_RAW_CLEANUP_REF_RE = re.compile(r"raw_cleanup_receipt_v[2345]:[0-9a-f]{64}\Z")
_RAW_CLEANUP_AUTH_RE = re.compile(r"raw_cleanup_auth_v[2345]:[0-9a-f]{64}\Z")
_CONTROLLED_GAP_REF_RE = re.compile(r"controlled_gap_receipt_v2:[0-9a-f]{64}\Z")
_BACKFILL_LINEAGE_REF_RE = re.compile(r"backfill_lineage_receipt_v2:[0-9a-f]{64}\Z")
_AUTOMATION_RESULT_REF_RE = re.compile(r"automation_update_result_v2:[0-9a-f]{64}\Z")
_AUTOMATION_RECORD_REF_RE = re.compile(r"automation_record_v2:[0-9a-f]{64}\Z")
_AUTOMATION_CUTOVER_AUTH_RE = re.compile(r"automation_cutover_auth_v2:[0-9a-f]{64}\Z")
_AUTOMATION_SNAPSHOT_REF_RE = re.compile(
    r"automation_cutover_snapshot_v2:[0-9a-f]{64}\Z"
)
_AUTOMATION_SNAPSHOT_AUTH_RE = re.compile(
    r"automation_cutover_snapshot_auth_v2:[0-9a-f]{64}\Z"
)
_HOST_REF_RE = re.compile(r"host_ref_v2:[0-9a-f]{64}\Z")
_ERA_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z")
_FINGERPRINT_RE = re.compile(r"[0-9A-F]{40}\Z")
_MANIFEST_PATH_RE = re.compile(
    r"runs/(?:daily|weekly|baseline|session)/[^/]{1,128}/[^/]{1,256}/manifest\.json\Z"
)
_PUBLICATION_MESSAGE_RE = re.compile(
    rb"Publish Session Retrospective v2\n\n"
    rb"Attempt: (attempt_ref_v2:[0-9a-f]{64})\n"
    rb"Plan-Digest: ([0-9a-f]{64})\n"
    rb"Ordinal: ([0-9]+)\n"
    rb"Role: (standalone)\n\Z"
)


def _sha256_ref(prefix: str, domain: bytes, value: Any) -> str:
    digest = hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()
    return f"{prefix}:{digest}"


def _normalize_cursor_boundary(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise HistoryValidationError("cursor row logical_boundary is invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise HistoryValidationError("cursor row logical_boundary is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HistoryValidationError("cursor row logical_boundary is invalid")
    normalized = parsed.astimezone(dt.timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    canonical = normalized.isoformat(timespec=timespec).replace("+00:00", "Z")
    if value != canonical:
        raise HistoryValidationError("cursor row logical_boundary is not canonical")
    return canonical


def _normalize_cursor_rows(
    value: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)):
        raise HistoryValidationError("cursor rows must be an array")
    rows: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {
            "backlog_ref",
            "cursor_ref",
            "host_ref",
            "logical_boundary",
        }:
            raise HistoryValidationError("cursor row has an unexpected shape")
        host_ref = raw["host_ref"]
        if not isinstance(host_ref, str) or _OPAQUE_REF_RE.fullmatch(host_ref) is None:
            raise HistoryValidationError("cursor row host_ref is invalid")
        row = {
            "backlog_ref": raw["backlog_ref"],
            "cursor_ref": raw["cursor_ref"],
            "host_ref": host_ref,
            "logical_boundary": _normalize_cursor_boundary(raw["logical_boundary"]),
        }
        for name in ("backlog_ref", "cursor_ref"):
            item = row[name]
            if item is not None and (
                not isinstance(item, str) or _OPAQUE_REF_RE.fullmatch(item) is None
            ):
                raise HistoryValidationError(f"cursor row {name} is invalid")
        if (row["cursor_ref"] is None) != (row["logical_boundary"] is None):
            raise HistoryValidationError(
                "cursor row ref and logical_boundary must be paired"
            )
        rows.append(row)
    rows.sort(key=lambda item: item["host_ref"])
    if list(value) != rows or len({row["host_ref"] for row in rows}) != len(rows):
        raise HistoryValidationError("cursor rows must be canonical and unique")
    return tuple(rows)


def derive_cursor_root(cursor_rows: Sequence[Mapping[str, Any]]) -> str:
    rows = _normalize_cursor_rows(cursor_rows)
    return _sha256_ref(
        "cursor_root_ref_v2",
        b"session-retrospective-v2/cursor-root\x00",
        list(rows),
    )


def _normalize_episode_heads(
    value: Sequence[Mapping[str, Any]],
    *,
    identity: IdentityKey,
) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)):
        raise HistoryValidationError("episode heads must be an array")
    try:
        rows = [
            episode_review.validate_episode_revision(item, identity_key=identity)
            for item in value
        ]
    except (TypeError, ValueError) as exc:
        raise HistoryValidationError(
            "episode heads violate their revision contract"
        ) from exc
    rows.sort(key=lambda item: item["episode_ref"])
    if list(value) != rows or len({row["episode_ref"] for row in rows}) != len(rows):
        raise HistoryValidationError("episode heads must be canonical and unique")
    return tuple(rows)


def _normalize_episode_corrections(
    value: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)):
        raise HistoryValidationError("episode corrections must be an array")
    rows: list[dict[str, Any]] = []
    required = {
        "correction_ordinal",
        "correction_ref",
        "predecessor_episode_refs",
        "segmentation_major_version",
        "successor_episode_refs",
    }
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise HistoryValidationError("episode correction has an unexpected shape")
        ordinal = raw["correction_ordinal"]
        correction_ref = raw["correction_ref"]
        segmentation_version = raw["segmentation_major_version"]
        if (
            not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal < 1
            or not isinstance(correction_ref, str)
            or _EPISODE_CORRECTION_REF_RE.fullmatch(correction_ref) is None
            or not isinstance(segmentation_version, str)
            or not segmentation_version
        ):
            raise HistoryValidationError("episode correction identity is invalid")
        normalized_refs: dict[str, list[str]] = {}
        for field in ("predecessor_episode_refs", "successor_episode_refs"):
            refs = raw[field]
            if (
                not isinstance(refs, list)
                or not refs
                or refs != sorted(set(refs))
                or any(
                    not isinstance(item, str) or _EPISODE_REF_RE.fullmatch(item) is None
                    for item in refs
                )
            ):
                raise HistoryValidationError(f"episode correction {field} is invalid")
            normalized_refs[field] = list(refs)
        rows.append(
            {
                "correction_ordinal": ordinal,
                "correction_ref": correction_ref,
                "predecessor_episode_refs": normalized_refs["predecessor_episode_refs"],
                "segmentation_major_version": segmentation_version,
                "successor_episode_refs": normalized_refs["successor_episode_refs"],
            }
        )
    rows.sort(key=lambda item: (item["correction_ordinal"], item["correction_ref"]))
    if list(value) != rows or len({row["correction_ref"] for row in rows}) != len(rows):
        raise HistoryValidationError("episode corrections must be canonical and unique")
    return tuple(rows)


def derive_episode_head_root(
    episode_heads: Sequence[Mapping[str, Any]],
    *,
    identity: IdentityKey,
) -> str:
    rows = _normalize_episode_heads(episode_heads, identity=identity)
    return _sha256_ref(
        "episode_head_set_ref_v2",
        b"session-retrospective-v2/episode-head-root\x00",
        list(rows),
    )


def derive_episode_membership(
    episode_heads: Sequence[Mapping[str, Any]],
    *,
    identity: IdentityKey,
) -> tuple[dict[str, str], ...]:
    """Return only stable anchors that identify exactly one persisted episode."""

    heads = _normalize_episode_heads(episode_heads, identity=identity)
    candidates: dict[str, set[str]] = defaultdict(set)
    for head in heads:
        episode_ref = head["episode_ref"]
        for field in ("turn_refs", "goal_refs", "workstream_refs"):
            for anchor_ref in head[field]:
                candidates[anchor_ref].add(episode_ref)
    rows = [
        {"anchor_ref": anchor_ref, "episode_ref": next(iter(episode_refs))}
        for anchor_ref, episode_refs in candidates.items()
        if len(episode_refs) == 1
    ]
    rows.sort(key=lambda item: (item["anchor_ref"], item["episode_ref"]))
    return tuple(rows)


def _normalize_episode_membership(
    value: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, str], ...]:
    if isinstance(value, (str, bytes)):
        raise HistoryValidationError("episode membership must be an array")
    rows: list[dict[str, str]] = []
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {"anchor_ref", "episode_ref"}:
            raise HistoryValidationError(
                "episode membership row has an unexpected shape"
            )
        anchor_ref = raw["anchor_ref"]
        episode_ref = raw["episode_ref"]
        if any(
            not isinstance(item, str) or _OPAQUE_REF_RE.fullmatch(item) is None
            for item in (anchor_ref, episode_ref)
        ):
            raise HistoryValidationError(
                "episode membership row contains an invalid ref"
            )
        rows.append({"anchor_ref": anchor_ref, "episode_ref": episode_ref})
    rows.sort(key=lambda item: (item["anchor_ref"], item["episode_ref"]))
    if list(value) != rows or len({row["anchor_ref"] for row in rows}) != len(rows):
        raise HistoryValidationError("episode membership must be canonical and unique")
    return tuple(rows)


EMPTY_CURSOR_ROOT_REF = derive_cursor_root(())


@dataclass(frozen=True, slots=True)
class DurableHistoryState:
    head_commit: str
    publication_commit: str | None
    identity_key_id: str
    provider_revision: int
    cursor_root_ref: str
    episode_head_root_ref: str
    cursor_rows: tuple[dict[str, Any], ...]
    episode_heads: tuple[dict[str, Any], ...]
    episode_membership: tuple[dict[str, str], ...]

    def provider_projection(self) -> dict[str, Any]:
        return {
            "cursor_root_ref": self.cursor_root_ref,
            "cursor_rows": [dict(row) for row in self.cursor_rows],
            "episode_head_root_ref": self.episode_head_root_ref,
            "episode_heads": [dict(row) for row in self.episode_heads],
            "episode_membership": [dict(row) for row in self.episode_membership],
            "history_commit": self.head_commit,
            "identity_key_id": self.identity_key_id,
            "publication_commit": self.publication_commit,
            "provider_revision": self.provider_revision,
        }


def empty_episode_head_root(identity: IdentityKey) -> str:
    return derive_episode_head_root((), identity=identity)


def history_state_from_projection(
    value: Mapping[str, Any],
    *,
    identity: IdentityKey,
) -> DurableHistoryState:
    expected_fields = {
        "cursor_root_ref",
        "cursor_rows",
        "episode_head_root_ref",
        "episode_heads",
        "episode_membership",
        "history_commit",
        "identity_key_id",
        "provider_revision",
        "publication_commit",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise HistoryValidationError(
            "durable history projection has an unexpected shape"
        )
    if value["identity_key_id"] != identity.key_id:
        raise HistoryValidationError("durable history projection identity changed")
    history_commit = value["history_commit"]
    publication_commit = value["publication_commit"]
    if (
        not isinstance(history_commit, str)
        or _OBJECT_ID_RE.fullmatch(history_commit) is None
    ):
        raise HistoryValidationError("durable history projection head is invalid")
    if publication_commit is not None and (
        not isinstance(publication_commit, str)
        or _OBJECT_ID_RE.fullmatch(publication_commit) is None
    ):
        raise HistoryValidationError("durable history publication commit is invalid")
    revision = value["provider_revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise HistoryValidationError("durable history provider revision is invalid")
    cursors = _normalize_cursor_rows(value["cursor_rows"])
    heads = _normalize_episode_heads(value["episode_heads"], identity=identity)
    membership = _normalize_episode_membership(value["episode_membership"])
    if value["cursor_root_ref"] != derive_cursor_root(cursors):
        raise HistoryValidationError(
            "durable history cursor projection is inconsistent"
        )
    if value["episode_head_root_ref"] != derive_episode_head_root(
        heads, identity=identity
    ):
        raise HistoryValidationError("durable history head projection is inconsistent")
    if list(membership) != list(derive_episode_membership(heads, identity=identity)):
        raise HistoryValidationError(
            "durable history membership projection is inconsistent"
        )
    return DurableHistoryState(
        head_commit=history_commit,
        publication_commit=publication_commit,
        identity_key_id=identity.key_id,
        provider_revision=revision,
        cursor_root_ref=value["cursor_root_ref"],
        episode_head_root_ref=value["episode_head_root_ref"],
        cursor_rows=cursors,
        episode_heads=heads,
        episode_membership=membership,
    )


def durable_state_manifest(
    *,
    expected: DurableHistoryState,
    proposed_cursor_rows: Sequence[Mapping[str, Any]],
    proposed_episode_heads: Sequence[Mapping[str, Any]],
    identity: IdentityKey,
    source_snapshot_refs: Sequence[str],
    backfill_of: str | None,
    episode_corrections: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    cursors = _normalize_cursor_rows(proposed_cursor_rows)
    heads = _normalize_episode_heads(proposed_episode_heads, identity=identity)
    corrections = _normalize_episode_corrections(episode_corrections)
    membership = derive_episode_membership(heads, identity=identity)
    snapshots = sorted(set(source_snapshot_refs))
    if any(_SOURCE_SNAPSHOT_REF_RE.fullmatch(item) is None for item in snapshots):
        raise HistoryValidationError("source snapshot refs are invalid")
    if backfill_of is not None and _OPAQUE_REF_RE.fullmatch(backfill_of) is None:
        raise HistoryValidationError("backfill_of is invalid")
    manifest = {
        "backfill_of": backfill_of,
        "expected_cursor_root_ref": expected.cursor_root_ref,
        "expected_episode_head_root_ref": expected.episode_head_root_ref,
        "expected_history_commit": expected.head_commit,
        "identity_key_id": identity.key_id,
        "provider_revision_after": expected.provider_revision + 1,
        "provider_revision_before": expected.provider_revision,
        "proposed_cursor_root_ref": derive_cursor_root(cursors),
        "proposed_cursor_rows": [dict(row) for row in cursors],
        "proposed_episode_head_root_ref": derive_episode_head_root(
            heads, identity=identity
        ),
        "proposed_episode_heads": [dict(row) for row in heads],
        "proposed_episode_membership": [dict(row) for row in membership],
        "schema": DURABLE_STATE_SCHEMA,
        "source_snapshot_refs": snapshots,
    }
    if corrections:
        manifest["episode_corrections"] = [dict(row) for row in corrections]
    validate_durable_state_transition(expected, manifest, identity=identity)
    return manifest


def _validate_manifest_state(
    value: Mapping[str, Any],
    *,
    identity: IdentityKey,
) -> dict[str, Any]:
    expected_fields = {
        "backfill_of",
        "expected_cursor_root_ref",
        "expected_episode_head_root_ref",
        "expected_history_commit",
        "identity_key_id",
        "provider_revision_after",
        "provider_revision_before",
        "proposed_cursor_root_ref",
        "proposed_cursor_rows",
        "proposed_episode_head_root_ref",
        "proposed_episode_heads",
        "proposed_episode_membership",
        "schema",
        "source_snapshot_refs",
    }
    optional_fields = {"episode_corrections"}
    if (
        not expected_fields <= set(value)
        or set(value) - expected_fields - optional_fields
        or value.get("schema") != DURABLE_STATE_SCHEMA
    ):
        raise HistoryValidationError("durable history state has an unexpected shape")
    if value["identity_key_id"] != identity.key_id:
        raise HistoryValidationError("durable history identity does not match")
    if not isinstance(value["expected_history_commit"], str) or (
        _OBJECT_ID_RE.fullmatch(value["expected_history_commit"]) is None
    ):
        raise HistoryValidationError("durable history parent commit is invalid")
    before = value["provider_revision_before"]
    after = value["provider_revision_after"]
    if (
        not isinstance(before, int)
        or isinstance(before, bool)
        or before < 0
        or after != before + 1
    ):
        raise HistoryValidationError("durable history provider revision is invalid")
    cursor_rows = _normalize_cursor_rows(value["proposed_cursor_rows"])
    heads = _normalize_episode_heads(value["proposed_episode_heads"], identity=identity)
    if "episode_corrections" in value:
        _normalize_episode_corrections(value["episode_corrections"])
    membership = _normalize_episode_membership(value["proposed_episode_membership"])
    if list(membership) != list(derive_episode_membership(heads, identity=identity)):
        raise HistoryValidationError("durable episode membership is not derived")
    if value["proposed_cursor_root_ref"] != derive_cursor_root(cursor_rows):
        raise HistoryValidationError("durable cursor root is inconsistent")
    if value["proposed_episode_head_root_ref"] != derive_episode_head_root(
        heads, identity=identity
    ):
        raise HistoryValidationError("durable episode-head root is inconsistent")
    for name in (
        "expected_cursor_root_ref",
        "expected_episode_head_root_ref",
        "proposed_cursor_root_ref",
        "proposed_episode_head_root_ref",
    ):
        if (
            not isinstance(value[name], str)
            or _OPAQUE_REF_RE.fullmatch(value[name]) is None
        ):
            raise HistoryValidationError(f"durable history {name} is invalid")
    snapshots = value["source_snapshot_refs"]
    if (
        not isinstance(snapshots, list)
        or snapshots != sorted(set(snapshots))
        or any(
            not isinstance(item, str) or _SOURCE_SNAPSHOT_REF_RE.fullmatch(item) is None
            for item in snapshots
        )
    ):
        raise HistoryValidationError("durable source snapshot refs are invalid")
    backfill_of = value["backfill_of"]
    if backfill_of is not None and (
        not isinstance(backfill_of, str)
        or _OPAQUE_REF_RE.fullmatch(backfill_of) is None
    ):
        raise HistoryValidationError("durable backfill ref is invalid")
    return json.loads(json.dumps(value, sort_keys=True))


def _cursor_boundary_instant(value: str) -> dt.datetime:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    return dt.datetime.fromisoformat(candidate).astimezone(dt.timezone.utc)


def _validate_cursor_transition(
    previous_rows: Sequence[Mapping[str, Any]],
    proposed_rows: Sequence[Mapping[str, Any]],
) -> None:
    previous_by_host = {row["host_ref"]: row for row in previous_rows}
    proposed_by_host = {row["host_ref"]: row for row in proposed_rows}
    missing_hosts = sorted(set(previous_by_host) - set(proposed_by_host))
    if missing_hosts:
        raise HistoryValidationError(
            "durable cursor transition removes existing host state"
        )
    for host_ref, previous in previous_by_host.items():
        proposed = proposed_by_host[host_ref]
        previous_boundary = previous["logical_boundary"]
        proposed_boundary = proposed["logical_boundary"]
        if previous_boundary is not None and proposed_boundary is None:
            raise HistoryValidationError(
                f"durable cursor transition rolls back host {host_ref}"
            )
        if previous_boundary is None:
            advanced = proposed_boundary is not None
        else:
            assert proposed_boundary is not None
            previous_instant = _cursor_boundary_instant(previous_boundary)
            proposed_instant = _cursor_boundary_instant(proposed_boundary)
            if proposed_instant < previous_instant:
                raise HistoryValidationError(
                    f"durable cursor transition rolls back host {host_ref}"
                )
            advanced = proposed_instant > previous_instant
        if advanced == (previous["cursor_ref"] == proposed["cursor_ref"]):
            raise HistoryValidationError(
                f"durable cursor transition has inconsistent cursor identity for {host_ref}"
            )


def validate_durable_state_transition(
    previous: DurableHistoryState,
    proposed: Mapping[str, Any],
    *,
    identity: IdentityKey,
) -> None:
    """Validate one complete durable state transition against persisted history."""

    try:
        previous = history_state_from_projection(
            previous.provider_projection(), identity=identity
        )
        manifest = _validate_manifest_state(proposed, identity=identity)
    except (TypeError, ValueError, HistoryValidationError) as exc:
        if isinstance(exc, HistoryValidationError):
            raise
        raise HistoryValidationError("durable history transition is invalid") from exc
    expected_bindings = {
        "expected_cursor_root_ref": previous.cursor_root_ref,
        "expected_episode_head_root_ref": previous.episode_head_root_ref,
        "expected_history_commit": previous.head_commit,
        "provider_revision_before": previous.provider_revision,
        "provider_revision_after": previous.provider_revision + 1,
    }
    for field, expected in expected_bindings.items():
        if manifest[field] != expected:
            raise HistoryValidationError(
                f"durable history transition has stale {field}"
            )

    proposed_cursor_rows = _normalize_cursor_rows(manifest["proposed_cursor_rows"])
    proposed_heads = _normalize_episode_heads(
        manifest["proposed_episode_heads"], identity=identity
    )
    corrections = _normalize_episode_corrections(
        manifest.get("episode_corrections", [])
    )
    _validate_cursor_transition(previous.cursor_rows, proposed_cursor_rows)
    try:
        episode_review.validate_episode_head_transition(
            previous.episode_heads,
            proposed_heads,
            corrections,
            correction_ordinal=manifest["provider_revision_after"],
            identity_key=identity,
        )
    except (TypeError, ValueError) as exc:
        raise HistoryValidationError(str(exc)) from exc


def _run_bounded(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    pass_fds: tuple[int, ...] = (),
    input_bytes: bytes | None = None,
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
    timeout_seconds: float = 30.0,
) -> subprocess.CompletedProcess[bytes]:
    if input_bytes is not None and len(input_bytes) > MAX_GIT_OUTPUT_BYTES:
        raise HistoryValidationError("history command input exceeds its byte bound")
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
        )
    except OSError as exc:
        raise HistoryValidationError("cannot start bounded history command") from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    output = bytearray()
    errors = bytearray()
    input_offset = 0
    deadline = time.monotonic() + timeout_seconds
    process_group_id = process.pid
    process_group_cleanup_attempted = False

    def terminate_process_group() -> None:
        nonlocal process_group_cleanup_attempted
        if process_group_cleanup_attempted:
            return
        process_group_cleanup_attempted = True
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass

    try:
        for stream, target in ((process.stdout, output), (process.stderr, errors)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, ("read", target))
        if process.stdin is not None:
            if input_bytes:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, ("write", None))
            else:
                process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            for key, _mask in selector.select(min(remaining, 0.1)):
                stream = key.fileobj
                operation, target = key.data
                if operation == "write":
                    assert input_bytes is not None
                    try:
                        written = os.write(
                            stream.fileno(),
                            input_bytes[input_offset : input_offset + 64 * 1024],
                        )
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                    if written > 0:
                        input_offset += written
                    if written <= 0 or input_offset == len(input_bytes):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 1024 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if len(output) + len(errors) + len(chunk) > max_output_bytes:
                    raise BufferError
                target.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        # Close the group while the unreaped leader still pins its PID/PGID.
        terminate_process_group()
        return subprocess.CompletedProcess(
            argv, process.wait(timeout=remaining), bytes(output), bytes(errors)
        )
    except (BufferError, TimeoutError, subprocess.TimeoutExpired) as exc:
        terminate_process_group()
        reason = "output limit" if isinstance(exc, BufferError) else "deadline"
        raise HistoryValidationError(f"history command exceeded its {reason}") from exc
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except OSError:
                pass
        terminate_process_group()


class _GitRepository:
    def __init__(
        self,
        path: Path,
        *,
        gnupg_home: Path,
        git_binary: str,
        gpg_program: str = executable_authority.DEFAULT_GPG_EXECUTABLE,
    ) -> None:
        self.path = path.absolute()
        try:
            self._git_executable_authority = executable_authority.resolve_executable(
                git_binary, label="Git"
            )
            self._gpg_executable_authority = executable_authority.resolve_executable(
                gpg_program, label="GPG"
            )
        except executable_authority.ExecutableAuthorityError as exc:
            raise HistoryValidationError(
                "history executable authority is not trusted"
            ) from exc
        self.git = self._git_executable_authority.path
        self.gpg = self._gpg_executable_authority.path
        self.gnupg_home = gnupg_home.expanduser().absolute()
        self.env = git_safety.history_git_environment(
            home=str(Path.home()), gnupg_home=str(self.gnupg_home)
        )
        self._repository_admission = git_safety.admit_history_repository(
            self.path,
            lambda args: self.run(*args, check=False),
            safe_io.owner_controlled_directory_identity,
        )

    def run(
        self,
        *args: str,
        check: bool = True,
        input_bytes: bytes | None = None,
        max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
    ) -> subprocess.CompletedProcess[bytes]:
        arguments = (
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.askPass=/usr/bin/false",
            "-c",
            "credential.helper=",
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={self.gpg}",
            "-c",
            f"gpg.openpgp.program={self.gpg}",
            *args,
        )
        executable_authorities = [self._git_executable_authority]
        if args and args[0] in {"verify-commit", "verify-tag"}:
            executable_authorities.append(self._gpg_executable_authority)
        try:
            with executable_authority.executable_invocation(*executable_authorities):
                with git_safety.history_repository_git_invocation(
                    getattr(self, "_repository_admission", None),
                    self.path,
                    self.git,
                    arguments,
                    self.env,
                    safe_io.owner_controlled_directory_identity,
                ) as (command, environment, descriptors):
                    result = _run_bounded(
                        command,
                        env=environment,
                        pass_fds=descriptors,
                        input_bytes=input_bytes,
                        max_output_bytes=max_output_bytes,
                    )
        except executable_authority.ExecutableAuthorityError as exc:
            raise HistoryValidationError(
                "history executable authority changed after validation"
            ) from exc
        if check and result.returncode != 0:
            raise HistoryValidationError("history Git command failed")
        return result

    def text(self, *args: str) -> str:
        try:
            return self.run(*args).stdout.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise HistoryValidationError("history Git output is not ASCII") from exc

    def object_bytes(self, commit: str, path: str) -> bytes:
        spec = f"{commit}:{path}"
        size_text = self.text("cat-file", "-s", spec)
        try:
            size = int(size_text)
        except ValueError as exc:
            raise HistoryValidationError("history object size is invalid") from exc
        if size < 0 or size > reporting.MAX_RETAINED_ARTIFACT_BYTES:
            raise HistoryValidationError("history artifact exceeds its byte bound")
        payload = self.run(
            "cat-file", "blob", spec, max_output_bytes=max(1, size + 1)
        ).stdout
        if len(payload) != size:
            raise HistoryValidationError("history artifact byte count changed")
        return payload


def validsig_primary_fingerprints(status: bytes) -> list[str]:
    """Return the primary-key fingerprint from each complete GPG VALIDSIG row."""

    fingerprints: list[str] = []
    marker = b"[GNUPG:] VALIDSIG "
    for line in status.splitlines():
        index = line.find(marker)
        if index < 0:
            continue
        fields = line[index + len(marker) :].split()
        if len(fields) not in {9, 10}:
            raise ValueError("GPG VALIDSIG row has an unexpected shape")
        try:
            signing_fingerprint = fields[0].decode("ascii", errors="strict").upper()
            primary_fingerprint = (
                fields[9].decode("ascii", errors="strict").upper()
                if len(fields) == 10
                else signing_fingerprint
            )
        except UnicodeDecodeError as exc:
            raise ValueError("GPG VALIDSIG fingerprint is not ASCII") from exc
        if (
            _FINGERPRINT_RE.fullmatch(signing_fingerprint) is None
            or _FINGERPRINT_RE.fullmatch(primary_fingerprint) is None
        ):
            raise ValueError("GPG VALIDSIG fingerprint is invalid")
        fingerprints.append(primary_fingerprint)
    return fingerprints


def _verify_publication_signature(
    repo: _GitRepository,
    commit: str,
    *,
    expected_fingerprint: str,
) -> None:
    fingerprint = expected_fingerprint.upper()
    if _FINGERPRINT_RE.fullmatch(fingerprint) is None:
        raise HistoryValidationError("publisher fingerprint is invalid")
    result = repo.run("verify-commit", "--raw", commit, check=False)
    if result.returncode != 0:
        raise HistoryValidationError("publication commit signature is invalid")
    status = result.stdout + b"\n" + result.stderr
    try:
        valid = validsig_primary_fingerprints(status)
    except ValueError as exc:
        raise HistoryValidationError("publication signature status is invalid") from exc
    if valid != [fingerprint]:
        raise HistoryValidationError("publication signature has the wrong signer")


def _retained_publication_bundle(
    repo: _GitRepository,
    commit: str,
    *,
    parent: str,
) -> dict[str, Any]:
    changes_text = repo.text(
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "--no-renames",
        "-r",
        parent,
        commit,
        "--",
        history_graph.HISTORY_PATHSPEC,
    )
    paths: list[str] = []
    for line in [] if not changes_text else changes_text.splitlines():
        status_value, separator, path = line.partition("\t")
        if separator != "\t" or status_value != "A" or not path:
            raise HistoryValidationError(
                "publication commit modifies or removes retained history"
            )
        paths.append(path)
    manifests = [path for path in paths if _MANIFEST_PATH_RE.fullmatch(path)]
    if len(manifests) != 1:
        raise HistoryValidationError(
            "publication commit must add one retained manifest"
        )
    directory = manifests[0].removesuffix("/manifest.json")
    expected_paths = {
        f"{directory}/{name}" for name in reporting.RETAINED_ARTIFACT_NAMES
    }
    if len(paths) != len(expected_paths) or set(paths) != expected_paths:
        raise HistoryValidationError(
            "publication commit must add exactly one eight-artifact bundle"
        )
    artifacts = {
        name: repo.object_bytes(commit, f"{directory}/{name}")
        for name in reporting.RETAINED_ARTIFACT_NAMES
    }
    return {
        "artifacts": artifacts,
        "directory": directory,
        "parsed": reporting.validate_retained_artifacts(artifacts),
    }


def _publication_commitment(
    repo: _GitRepository,
    commit: str,
    *,
    identity: IdentityKey,
) -> dict[str, Any]:
    raw_commit = repo.run("cat-file", "commit", commit).stdout
    _headers, separator, body = raw_commit.partition(b"\n\n")
    match = _PUBLICATION_MESSAGE_RE.fullmatch(body) if separator else None
    if match is None:
        raise HistoryValidationError(
            "publication commit lacks its exact attempt and plan commitment"
        )
    attempt_ref = match.group(1).decode("ascii")
    plan_digest = match.group(2).decode("ascii")
    try:
        ordinal = int(match.group(3))
    except ValueError as exc:
        raise HistoryValidationError("publication commit ordinal is invalid") from exc
    if (
        _ATTEMPT_REF_RE.fullmatch(attempt_ref) is None
        or _DIGEST_RE.fullmatch(plan_digest) is None
        or ordinal != 0
    ):
        raise HistoryValidationError("publication commit metadata is invalid")

    parent = repo.text("rev-parse", f"{commit}^")
    bundle = _retained_publication_bundle(repo, commit, parent=parent)
    parsed = bundle["parsed"]
    manifest = parsed["manifest"]
    if manifest.get("publication_role") != "standalone":
        raise HistoryValidationError(
            "publication commit role does not match its bundle"
        )
    raw_state = manifest.get("durable_state")
    if not isinstance(raw_state, Mapping):
        raise HistoryValidationError("publication manifest lacks durable state")
    durable = _validate_manifest_state(raw_state, identity=identity)
    if durable["expected_history_commit"] != parent:
        raise HistoryValidationError("publication manifest names the wrong parent")
    digest_record = manifest.get("retained_bundle_digest_v2")
    if not isinstance(digest_record, Mapping):
        raise HistoryValidationError("publication manifest lacks its bundle digest")
    bundle_digest = digest_record.get("value")
    if (
        not isinstance(bundle_digest, str)
        or _DIGEST_RE.fullmatch(bundle_digest) is None
    ):
        raise HistoryValidationError("publication bundle digest is invalid")
    return {
        "attempt_ref": attempt_ref,
        "bundle_digest": bundle_digest,
        "durable_state": durable,
        "durable_state_digest": identity.derive_digest(
            "publication-claim-durable-state/v2",
            durable,
        ),
        "expected_history_commit": parent,
        "history_commit": commit,
        "ordinal": ordinal,
        "plan_digest": plan_digest,
        "publication_role": "standalone",
    }


def load_durable_publication_commitment(
    repo_path: str | os.PathLike[str],
    commit: str,
    *,
    identity: IdentityKey,
    expected_fingerprint: str = DEFAULT_PUBLISHER_FINGERPRINT,
    gnupg_home: str | os.PathLike[str] = DEFAULT_PUBLISHER_GNUPG_HOME,
    git_binary: str = executable_authority.DEFAULT_GIT_EXECUTABLE,
    gpg_program: str = executable_authority.DEFAULT_GPG_EXECUTABLE,
) -> dict[str, Any]:
    """Load the exact signed attempt, plan, parent, bundle, and durable manifest."""

    if not isinstance(commit, str) or _OBJECT_ID_RE.fullmatch(commit) is None:
        raise HistoryValidationError("publication commitment commit is invalid")
    repo = _GitRepository(
        Path(repo_path),
        gnupg_home=Path(gnupg_home),
        git_binary=git_binary,
        gpg_program=gpg_program,
    )
    resolved = repo.text("rev-parse", "--verify", commit)
    if resolved != commit:
        raise HistoryValidationError("publication commitment commit changed")
    _verify_publication_signature(
        repo,
        commit,
        expected_fingerprint=expected_fingerprint,
    )
    return _publication_commitment(repo, commit, identity=identity)


def load_durable_history(
    repo_path: str | os.PathLike[str],
    target_ref: str,
    *,
    identity: IdentityKey,
    expected_fingerprint: str = DEFAULT_PUBLISHER_FINGERPRINT,
    gnupg_home: str | os.PathLike[str] = DEFAULT_PUBLISHER_GNUPG_HOME,
    git_binary: str = executable_authority.DEFAULT_GIT_EXECUTABLE,
    gpg_program: str = executable_authority.DEFAULT_GPG_EXECUTABLE,
) -> DurableHistoryState:
    """Validate every publication state transition reachable from ``target_ref``."""

    repo = _GitRepository(
        Path(repo_path),
        gnupg_home=Path(gnupg_home),
        git_binary=git_binary,
        gpg_program=gpg_program,
    )
    head = repo.text("rev-parse", "--verify", target_ref)
    if _OBJECT_ID_RE.fullmatch(head) is None:
        raise HistoryValidationError("durable history head is invalid")
    commits = history_graph.retained_publication_commits(
        repo,
        target_ref,
        expected_head=head,
        pathspec=history_graph.HISTORY_PATHSPEC,
    )

    cursor_root = EMPTY_CURSOR_ROOT_REF
    episode_root = empty_episode_head_root(identity)
    revision = 0
    cursor_rows: tuple[dict[str, Any], ...] = ()
    episode_heads: tuple[dict[str, Any], ...] = ()
    membership: tuple[dict[str, str], ...] = ()
    publication_commit: str | None = None
    for commit in commits:
        if _OBJECT_ID_RE.fullmatch(commit) is None:
            raise HistoryValidationError("history log contains an invalid commit id")
        _verify_publication_signature(
            repo,
            commit,
            expected_fingerprint=expected_fingerprint,
        )
        commitment = _publication_commitment(repo, commit, identity=identity)
        durable = commitment["durable_state"]
        if durable["expected_cursor_root_ref"] != cursor_root:
            raise HistoryValidationError(
                "publication cursor history is not append-only"
            )
        if durable["expected_episode_head_root_ref"] != episode_root:
            raise HistoryValidationError(
                "publication episode history is not append-only"
            )
        if durable["provider_revision_before"] != revision:
            raise HistoryValidationError("publication provider revision is stale")
        previous_state = DurableHistoryState(
            head_commit=durable["expected_history_commit"],
            publication_commit=publication_commit,
            identity_key_id=identity.key_id,
            provider_revision=revision,
            cursor_root_ref=cursor_root,
            episode_head_root_ref=episode_root,
            cursor_rows=cursor_rows,
            episode_heads=episode_heads,
            episode_membership=membership,
        )
        validate_durable_state_transition(
            previous_state,
            durable,
            identity=identity,
        )
        cursor_root = durable["proposed_cursor_root_ref"]
        episode_root = durable["proposed_episode_head_root_ref"]
        revision = durable["provider_revision_after"]
        cursor_rows = _normalize_cursor_rows(durable["proposed_cursor_rows"])
        episode_heads = _normalize_episode_heads(
            durable["proposed_episode_heads"], identity=identity
        )
        membership = _normalize_episode_membership(
            durable["proposed_episode_membership"]
        )
        publication_commit = commit

    return DurableHistoryState(
        head_commit=head,
        publication_commit=publication_commit,
        identity_key_id=identity.key_id,
        provider_revision=revision,
        cursor_root_ref=cursor_root,
        episode_head_root_ref=episode_root,
        cursor_rows=cursor_rows,
        episode_heads=episode_heads,
        episode_membership=membership,
    )


def load_prior_period_from_history(
    repo_path: str | os.PathLike[str],
    target_ref: str,
    *,
    identity: IdentityKey,
    expected_fingerprint: str = DEFAULT_PUBLISHER_FINGERPRINT,
    gnupg_home: str | os.PathLike[str] = DEFAULT_PUBLISHER_GNUPG_HOME,
    git_binary: str = executable_authority.DEFAULT_GIT_EXECUTABLE,
    gpg_program: str = executable_authority.DEFAULT_GPG_EXECUTABLE,
) -> dict[str, Any]:
    """Load the latest trend from the fully verified signed history chain."""

    history = load_durable_history(
        repo_path,
        target_ref,
        identity=identity,
        expected_fingerprint=expected_fingerprint,
        gnupg_home=gnupg_home,
        git_binary=git_binary,
        gpg_program=gpg_program,
    )
    commit = history.publication_commit
    if commit is None:
        raise HistoryValidationError(
            "durable history does not contain a prior retained publication"
        )
    repo = _GitRepository(
        Path(repo_path),
        gnupg_home=Path(gnupg_home),
        git_binary=git_binary,
        gpg_program=gpg_program,
    )
    if repo.text("rev-parse", "--verify", target_ref) != history.head_commit:
        raise HistoryValidationError("durable history changed during prior-period load")
    _verify_publication_signature(
        repo,
        commit,
        expected_fingerprint=expected_fingerprint,
    )
    parent = repo.text("rev-parse", f"{commit}^")
    bundle = _retained_publication_bundle(repo, commit, parent=parent)
    parsed = bundle["parsed"]
    manifest = parsed["manifest"]
    return {
        "authenticated_history": {
            "bundle_digest": manifest["retained_bundle_digest_v2"]["value"],
            "history_commit": commit,
            "history_head": history.head_commit,
            "schema": "authenticated_prior_history_v2",
        },
        "trend_report": parsed["trend_report"],
    }


def history_repository_binding(
    repo_path: str | os.PathLike[str],
    target_ref: str,
    *,
    identity: IdentityKey,
    git_binary: str = executable_authority.DEFAULT_GIT_EXECUTABLE,
) -> str:
    repo = _GitRepository(
        Path(repo_path),
        gnupg_home=DEFAULT_PUBLISHER_GNUPG_HOME,
        git_binary=git_binary,
    )
    common_dir = repo.text("rev-parse", "--path-format=absolute", "--git-common-dir")
    remote = repo.run("remote", "get-url", "origin", check=False)
    remote_value = (
        "no_origin"
        if remote.returncode != 0
        else hashlib.sha256(remote.stdout.strip()).hexdigest()
    )
    payload = {
        "common_dir_ref": hashlib.sha256(os.fsencode(common_dir)).hexdigest(),
        "remote_ref": remote_value,
        "target_ref": target_ref,
    }
    return "history_repository_ref_v2:" + identity.derive_digest(
        "production-history-repository-v2", payload
    )


SHADOW_COVERAGE_RECEIPT_SCHEMA = "shadow_coverage_receipt_v2"
SHADOW_GATE_RECEIPT_SCHEMA = "shadow_gate_receipt_v2"
SHADOW_CLEANUP_RECEIPT_SCHEMA = "raw_cleanup_receipt_v5"
_RAW_CLEANUP_RECEIPT_CONTRACTS = {
    "raw_cleanup_receipt_v2": (
        LEGACY_SHADOW_CLEANUP_ROOTS,
        "raw_cleanup_auth_v2",
        "shadow_cleanup_claim_v2:",
    ),
    **{
        f"raw_cleanup_receipt_v{version}": (
            SHADOW_CLEANUP_ROOTS,
            f"raw_cleanup_auth_v{version}",
            f"shadow_cleanup_claim_v{version}:",
        )
        for version in (3, 4, 5)
    },
}
_SOURCE_UNIT_FIELDS = {
    "consumed_candidate",
    "expected",
    "explicit_gap",
    "structurally_excluded",
}


def _production_host_refs(identity: IdentityKey) -> list[str]:
    return sorted(
        str(identity.derive_ref(RefType.HOST, {"parts": [host]}))
        for host in CANONICAL_HOSTS
    )


def _owner_receipt(
    identity: IdentityKey,
    *,
    schema: str,
    ref_domain: str,
    auth_domain: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "identity_key_id": identity.key_id,
        **json.loads(json.dumps(dict(payload), sort_keys=True)),
        "schema": schema,
    }
    return {
        **body,
        "authentication_tag": auth_domain
        + ":"
        + identity.derive_digest(auth_domain, body),
        "receipt_ref": ref_domain + ":" + identity.derive_digest(ref_domain, body),
    }


def _normalize_shadow_window(
    mode: object,
    window_start: object,
    window_end: object,
) -> tuple[str, str]:
    if mode not in {"weekly", "daily"}:
        raise ProductionMarkerError("shadow evidence mode is invalid")

    def parse(value: object, *, label: str) -> tuple[str, dt.datetime]:
        if not isinstance(value, str):
            raise ProductionMarkerError(f"shadow {label} is invalid")
        try:
            parsed = dt.datetime.fromisoformat(
                value[:-1] + "+00:00" if value.endswith("Z") else value
            )
        except ValueError as exc:
            raise ProductionMarkerError(f"shadow {label} is invalid") from exc
        if parsed.tzinfo is None:
            raise ProductionMarkerError(f"shadow {label} must include a timezone")
        utc = parsed.astimezone(dt.timezone.utc)
        normalized = utc.isoformat(timespec="seconds").replace("+00:00", "Z")
        if value != normalized:
            raise ProductionMarkerError(f"shadow {label} is not canonical UTC")
        return normalized, utc

    start, start_time = parse(window_start, label="window_start")
    end, end_time = parse(window_end, label="window_end")
    if start_time >= end_time:
        raise ProductionMarkerError("shadow window must be non-empty")
    if mode == "weekly" and end_time - start_time != dt.timedelta(days=7):
        raise ProductionMarkerError("weekly shadow requires an exact seven-day window")
    return start, end


def _shadow_source_evidence(
    identity: IdentityKey,
    *,
    run_ref: str,
    window_start: str,
    window_end: str,
    configured_host_refs: Sequence[str],
    covered_host_refs: Sequence[str],
    gap_host_refs: Sequence[str],
    source_units: Mapping[str, int],
    source_snapshot_refs: Sequence[str],
    source_receipt_refs: Sequence[str],
) -> tuple[list[str], list[str], str]:
    if isinstance(source_snapshot_refs, (str, bytes)) or isinstance(
        source_receipt_refs, (str, bytes)
    ):
        raise ProductionMarkerError("shadow source evidence inventory is invalid")
    raw_snapshots = list(source_snapshot_refs)
    raw_receipts = list(source_receipt_refs)
    if (
        not raw_snapshots
        or not raw_receipts
        or any(
            not isinstance(item, str) or _SOURCE_SNAPSHOT_REF_RE.fullmatch(item) is None
            for item in raw_snapshots
        )
        or any(
            not isinstance(item, str)
            or _SOURCE_TRANSPORT_RECEIPT_REF_RE.fullmatch(item) is None
            for item in raw_receipts
        )
    ):
        raise ProductionMarkerError("shadow source evidence inventory is invalid")
    snapshots = sorted(set(raw_snapshots))
    receipts = sorted(set(raw_receipts))
    if len(snapshots) != len(raw_snapshots) or len(receipts) != len(raw_receipts):
        raise ProductionMarkerError("shadow source evidence inventory is invalid")
    body = {
        "configured_host_refs": list(configured_host_refs),
        "covered_host_refs": list(covered_host_refs),
        "gap_host_refs": list(gap_host_refs),
        "run_ref": run_ref,
        "source_receipt_refs": receipts,
        "source_snapshot_refs": snapshots,
        "source_units": dict(source_units),
        "window_end": window_end,
        "window_start": window_start,
    }
    commitment = "shadow_source_evidence_v2:" + identity.derive_digest(
        "shadow-source-evidence-v2",
        body,
    )
    return snapshots, receipts, commitment


def _verify_shadow_coverage_receipt(
    identity: IdentityKey,
    value: Mapping[str, object],
    *,
    calibration_receipt: calibration.CalibrationReceipt | None = None,
) -> dict[str, Any]:
    fields = {
        "authentication_tag",
        "backfill_of",
        "checkpoint_revision",
        "configuration_root",
        "controlled_gap_receipt_ref",
        "configured_host_refs",
        "covered_host_refs",
        "export_bundle_digest",
        "gap_host_refs",
        "identity_key_id",
        "mode",
        "model_era",
        "partial",
        "policy_commitment",
        "policy_era",
        "production_configuration_ref",
        "receipt_ref",
        "run_ref",
        "schema",
        "source_evidence_commitment",
        "source_receipt_refs",
        "source_snapshot_refs",
        "source_units",
        "specification_digest",
        "version_commitment",
        "window_end",
        "window_start",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProductionMarkerError("shadow coverage receipt has an unexpected shape")
    receipt = dict(value)
    body = {
        key: receipt[key]
        for key in receipt
        if key not in {"authentication_tag", "receipt_ref"}
    }
    expected_ref = "shadow_coverage_receipt_v2:" + identity.derive_digest(
        "shadow_coverage_receipt_v2", body
    )
    expected_auth = "shadow_coverage_auth_v2:" + identity.derive_digest(
        "shadow_coverage_auth_v2", body
    )
    configured = receipt["configured_host_refs"]
    covered = receipt["covered_host_refs"]
    gap_hosts = receipt["gap_host_refs"]
    units = receipt["source_units"]
    try:
        window_start, window_end = _normalize_shadow_window(
            receipt["mode"],
            receipt["window_start"],
            receipt["window_end"],
        )
        snapshots, source_receipts, source_commitment = _shadow_source_evidence(
            identity,
            run_ref=str(receipt["run_ref"]),
            window_start=window_start,
            window_end=window_end,
            configured_host_refs=configured,
            covered_host_refs=covered,
            gap_host_refs=gap_hosts,
            source_units=units,
            source_snapshot_refs=receipt["source_snapshot_refs"],
            source_receipt_refs=receipt["source_receipt_refs"],
        )
    except (TypeError, ValueError, ProductionMarkerError) as exc:
        raise ProductionMarkerError(
            "shadow coverage source binding is invalid"
        ) from exc
    if (
        receipt["schema"] != SHADOW_COVERAGE_RECEIPT_SCHEMA
        or receipt["identity_key_id"] != identity.key_id
        or not isinstance(receipt["checkpoint_revision"], int)
        or isinstance(receipt["checkpoint_revision"], bool)
        or receipt["checkpoint_revision"] < 1
        or not isinstance(receipt["configuration_root"], str)
        or _DIGEST_RE.fullmatch(receipt["configuration_root"]) is None
        or not isinstance(receipt["production_configuration_ref"], str)
        or _OPAQUE_REF_RE.fullmatch(receipt["production_configuration_ref"]) is None
        or not isinstance(receipt["model_era"], str)
        or _ERA_RE.fullmatch(receipt["model_era"]) is None
        or not isinstance(receipt["policy_era"], str)
        or _ERA_RE.fullmatch(receipt["policy_era"]) is None
        or not isinstance(receipt["policy_commitment"], str)
        or _SHADOW_POLICY_COMMITMENT_RE.fullmatch(receipt["policy_commitment"]) is None
        or not isinstance(receipt["version_commitment"], str)
        or _SHADOW_VERSION_COMMITMENT_RE.fullmatch(receipt["version_commitment"])
        is None
        or not isinstance(receipt["specification_digest"], str)
        or _DIGEST_RE.fullmatch(receipt["specification_digest"]) is None
        or not isinstance(receipt["receipt_ref"], str)
        or _SHADOW_COVERAGE_REF_RE.fullmatch(receipt["receipt_ref"]) is None
        or not isinstance(receipt["authentication_tag"], str)
        or _SHADOW_COVERAGE_AUTH_RE.fullmatch(receipt["authentication_tag"]) is None
        or not hmac.compare_digest(receipt["receipt_ref"], expected_ref)
        or not hmac.compare_digest(receipt["authentication_tag"], expected_auth)
        or not isinstance(receipt["run_ref"], str)
        or _RUN_REF_RE.fullmatch(receipt["run_ref"]) is None
        or receipt["mode"] not in {"weekly", "daily"}
        or receipt["window_start"] != window_start
        or receipt["window_end"] != window_end
        or receipt["source_snapshot_refs"] != snapshots
        or receipt["source_receipt_refs"] != source_receipts
        or receipt["source_evidence_commitment"] != source_commitment
        or not isinstance(receipt["source_evidence_commitment"], str)
        or _SHADOW_SOURCE_COMMITMENT_RE.fullmatch(receipt["source_evidence_commitment"])
        is None
        or not isinstance(receipt["export_bundle_digest"], str)
        or _DIGEST_RE.fullmatch(receipt["export_bundle_digest"]) is None
        or not isinstance(receipt["partial"], bool)
        or not isinstance(configured, list)
        or not configured
        or configured != sorted(set(configured))
        or any(
            not isinstance(item, str) or _HOST_REF_RE.fullmatch(item) is None
            for item in configured
        )
        or not isinstance(covered, list)
        or covered != sorted(set(covered))
        or any(item not in configured for item in covered)
        or not isinstance(gap_hosts, list)
        or gap_hosts != sorted(set(gap_hosts))
        or any(item not in configured for item in gap_hosts)
        or set(covered) & set(gap_hosts)
        or set(covered) | set(gap_hosts) != set(configured)
        or not isinstance(units, Mapping)
        or set(units) != _SOURCE_UNIT_FIELDS
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in units.values()
        )
        or units["expected"]
        != units["consumed_candidate"]
        + units["explicit_gap"]
        + units["structurally_excluded"]
    ):
        raise ProductionMarkerError("shadow coverage receipt is invalid")
    if calibration_receipt is not None and (
        receipt["configuration_root"]
        != calibration_receipt.production_configuration_root
        or receipt["production_configuration_ref"]
        != calibration_receipt.production_configuration_ref
        or receipt["model_era"] != calibration_receipt.model_era
        or receipt["policy_era"] != calibration_receipt.policy_era
    ):
        raise ProductionMarkerError(
            "shadow coverage differs from the calibrated configuration"
        )
    gap_ref = receipt["controlled_gap_receipt_ref"]
    backfill_of = receipt["backfill_of"]
    if backfill_of is not None and (
        not isinstance(backfill_of, str) or _RUN_REF_RE.fullmatch(backfill_of) is None
    ):
        raise ProductionMarkerError("shadow backfill reference is invalid")
    if receipt["mode"] == "weekly":
        if (
            receipt["partial"] is not False
            or backfill_of is not None
            or gap_ref is not None
            or configured != _production_host_refs(identity)
            or covered != configured
            or gap_hosts
            or units["explicit_gap"] != 0
        ):
            raise ProductionMarkerError("weekly shadow coverage is incomplete")
    elif receipt["partial"]:
        if (
            backfill_of is not None
            or not isinstance(gap_ref, str)
            or _CONTROLLED_GAP_REF_RE.fullmatch(gap_ref) is None
            or configured != _production_host_refs(identity)
            or len(gap_hosts) != 1
        ):
            raise ProductionMarkerError("daily partial shadow coverage is invalid")
    elif backfill_of is not None:
        if (
            not isinstance(gap_ref, str)
            or _CONTROLLED_GAP_REF_RE.fullmatch(gap_ref) is None
            or gap_hosts
            or configured != covered
            or len(covered) != 1
            or any(item not in _production_host_refs(identity) for item in covered)
            or units["explicit_gap"] != 0
        ):
            raise ProductionMarkerError("daily backfill shadow coverage is invalid")
    elif (
        gap_ref is not None
        or gap_hosts
        or configured != _production_host_refs(identity)
        or configured != covered
        or units["explicit_gap"] != 0
    ):
        raise ProductionMarkerError("daily complete shadow coverage is invalid")
    return json.loads(json.dumps(receipt, sort_keys=True))


def _verify_shadow_cleanup_receipt(
    identity: IdentityKey,
    value: Mapping[str, object],
    *,
    calibration_receipt: calibration.CalibrationReceipt | None = None,
) -> dict[str, Any]:
    fields = {
        "authentication_tag",
        "bundle_digest",
        "cleanup_claim_ref",
        "cleanup_complete",
        "configuration_root",
        "coverage_receipt_ref",
        "disposition",
        "durable_commit",
        "identity_key_id",
        "model_era",
        "mode",
        "policy_commitment",
        "policy_era",
        "production_configuration_ref",
        "raw_path_inventory",
        "receipt_ref",
        "removed_byte_count",
        "removed_directory_count",
        "removed_file_count",
        "run_ref",
        "schema",
        "source_evidence_commitment",
        "version_commitment",
        "window_end",
        "window_start",
        "working_paths_absent",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProductionMarkerError("shadow cleanup receipt has an unexpected shape")
    receipt = dict(value)
    contract = _RAW_CLEANUP_RECEIPT_CONTRACTS.get(str(receipt.get("schema")))
    if contract is None:
        raise ProductionMarkerError("shadow cleanup receipt schema is unsupported")
    roots, auth_domain, claim_prefix = contract
    body = {
        key: receipt[key]
        for key in receipt
        if key not in {"authentication_tag", "receipt_ref"}
    }
    expected_ref = (
        str(receipt["schema"])
        + ":"
        + identity.derive_digest(str(receipt["schema"]), body)
    )
    expected_auth = auth_domain + ":" + identity.derive_digest(auth_domain, body)
    counts = (
        receipt["removed_byte_count"],
        receipt["removed_directory_count"],
        receipt["removed_file_count"],
    )
    try:
        window_start, window_end = _normalize_shadow_window(
            receipt["mode"],
            receipt["window_start"],
            receipt["window_end"],
        )
    except ProductionMarkerError as exc:
        raise ProductionMarkerError("shadow cleanup window is invalid") from exc
    if (
        receipt["identity_key_id"] != identity.key_id
        or not isinstance(receipt["configuration_root"], str)
        or _DIGEST_RE.fullmatch(receipt["configuration_root"]) is None
        or not isinstance(receipt["production_configuration_ref"], str)
        or _OPAQUE_REF_RE.fullmatch(receipt["production_configuration_ref"]) is None
        or not isinstance(receipt["model_era"], str)
        or _ERA_RE.fullmatch(receipt["model_era"]) is None
        or not isinstance(receipt["policy_era"], str)
        or _ERA_RE.fullmatch(receipt["policy_era"]) is None
        or not isinstance(receipt["policy_commitment"], str)
        or _SHADOW_POLICY_COMMITMENT_RE.fullmatch(receipt["policy_commitment"]) is None
        or not isinstance(receipt["version_commitment"], str)
        or _SHADOW_VERSION_COMMITMENT_RE.fullmatch(receipt["version_commitment"])
        is None
        or not isinstance(receipt["cleanup_claim_ref"], str)
        or _SHADOW_CLEANUP_CLAIM_RE.fullmatch(receipt["cleanup_claim_ref"]) is None
        or not receipt["cleanup_claim_ref"].startswith(claim_prefix)
        or receipt["window_start"] != window_start
        or receipt["window_end"] != window_end
        or not isinstance(receipt["coverage_receipt_ref"], str)
        or _SHADOW_COVERAGE_REF_RE.fullmatch(receipt["coverage_receipt_ref"]) is None
        or not isinstance(receipt["source_evidence_commitment"], str)
        or _SHADOW_SOURCE_COMMITMENT_RE.fullmatch(receipt["source_evidence_commitment"])
        is None
        or not isinstance(receipt["run_ref"], str)
        or _RUN_REF_RE.fullmatch(receipt["run_ref"]) is None
        or not isinstance(receipt["bundle_digest"], str)
        or _DIGEST_RE.fullmatch(receipt["bundle_digest"]) is None
        or receipt["cleanup_complete"] is not True
        or receipt["working_paths_absent"] is not True
        or receipt["disposition"] != "shadow"
        or receipt["durable_commit"] is not None
        or receipt["raw_path_inventory"] != list(roots)
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in counts
        )
        or not isinstance(receipt["receipt_ref"], str)
        or _RAW_CLEANUP_REF_RE.fullmatch(receipt["receipt_ref"]) is None
        or not isinstance(receipt["authentication_tag"], str)
        or _RAW_CLEANUP_AUTH_RE.fullmatch(receipt["authentication_tag"]) is None
        or not hmac.compare_digest(receipt["receipt_ref"], expected_ref)
        or not hmac.compare_digest(receipt["authentication_tag"], expected_auth)
    ):
        raise ProductionMarkerError("shadow cleanup receipt is invalid")
    if calibration_receipt is not None and (
        receipt["configuration_root"]
        != calibration_receipt.production_configuration_root
        or receipt["production_configuration_ref"]
        != calibration_receipt.production_configuration_ref
        or receipt["model_era"] != calibration_receipt.model_era
        or receipt["policy_era"] != calibration_receipt.policy_era
    ):
        raise ProductionMarkerError(
            "shadow cleanup differs from the calibrated configuration"
        )
    return json.loads(json.dumps(receipt, sort_keys=True))


def verify_shadow_coverage_receipt(
    identity: IdentityKey,
    value: Mapping[str, object],
) -> dict[str, Any]:
    """Verify an orchestrator-derived shadow coverage receipt."""

    return _verify_shadow_coverage_receipt(identity, value)


def verify_shadow_cleanup_receipt(
    identity: IdentityKey,
    value: Mapping[str, object],
) -> dict[str, Any]:
    """Verify a durable shadow cleanup transaction receipt."""

    return _verify_shadow_cleanup_receipt(identity, value)


def issue_shadow_gate_receipt(
    identity: IdentityKey,
    *,
    calibration_receipt: calibration.CalibrationReceipt | Mapping[str, object],
    mode: str,
    coverage_receipts: Sequence[Mapping[str, object]],
    cleanup_receipts: Sequence[Mapping[str, object]],
    controlled_gap_receipt: Mapping[str, object] | None = None,
    backfill_lineage_receipt: Mapping[str, object] | None = None,
    backfill_run_ref: str | None = None,
) -> dict[str, Any]:
    verified = calibration.verify_calibration_receipt(identity, calibration_receipt)
    coverages = [
        _verify_shadow_coverage_receipt(
            identity,
            item,
            calibration_receipt=verified,
        )
        for item in coverage_receipts
    ]
    cleanups = [
        _verify_shadow_cleanup_receipt(
            identity,
            item,
            calibration_receipt=verified,
        )
        for item in cleanup_receipts
    ]
    coverages.sort(key=lambda item: item["run_ref"])
    cleanups.sort(key=lambda item: item["run_ref"])
    partial_rows = [item for item in coverages if item["partial"] is True]
    partial_run_ref = partial_rows[0]["run_ref"] if len(partial_rows) == 1 else None
    run_refs = sorted(item["run_ref"] for item in coverages)
    receipt = _owner_receipt(
        identity,
        schema=SHADOW_GATE_RECEIPT_SCHEMA,
        ref_domain="shadow_receipt_v2",
        auth_domain="shadow_receipt_auth_v2",
        payload={
            "backfill_lineage_receipt": (
                None
                if backfill_lineage_receipt is None
                else dict(backfill_lineage_receipt)
            ),
            "backfill_run_ref": backfill_run_ref,
            "cleanup_receipts": cleanups,
            "configuration_root": verified.production_configuration_root,
            "controlled_gap_receipt": (
                None if controlled_gap_receipt is None else dict(controlled_gap_receipt)
            ),
            "coverage_receipts": coverages,
            "mode": mode,
            "model_era": verified.model_era,
            "partial_run_ref": partial_run_ref,
            "policy_era": verified.policy_era,
            "production_configuration_ref": verified.production_configuration_ref,
            "published": False,
            "run_refs": run_refs,
            "shadow": True,
        },
    )
    return _verify_shadow_gate_receipt(
        identity,
        receipt,
        calibration_receipt=verified,
    )


def _verify_shadow_gate_receipt(
    identity: IdentityKey,
    value: Mapping[str, object],
    *,
    calibration_receipt: calibration.CalibrationReceipt,
) -> dict[str, Any]:
    fields = {
        "authentication_tag",
        "backfill_lineage_receipt",
        "backfill_run_ref",
        "cleanup_receipts",
        "configuration_root",
        "controlled_gap_receipt",
        "coverage_receipts",
        "identity_key_id",
        "mode",
        "model_era",
        "partial_run_ref",
        "policy_era",
        "production_configuration_ref",
        "published",
        "receipt_ref",
        "run_refs",
        "schema",
        "shadow",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProductionMarkerError("shadow gate receipt has an unexpected shape")
    receipt = dict(value)
    body = {
        key: receipt[key]
        for key in receipt
        if key not in {"authentication_tag", "receipt_ref"}
    }
    expected_ref = "shadow_receipt_v2:" + identity.derive_digest(
        "shadow_receipt_v2", body
    )
    expected_auth = "shadow_receipt_auth_v2:" + identity.derive_digest(
        "shadow_receipt_auth_v2", body
    )
    raw_coverages = receipt["coverage_receipts"]
    raw_cleanups = receipt["cleanup_receipts"]
    run_refs = receipt["run_refs"]
    if (
        receipt["schema"] != SHADOW_GATE_RECEIPT_SCHEMA
        or receipt["identity_key_id"] != identity.key_id
        or receipt["configuration_root"]
        != calibration_receipt.production_configuration_root
        or receipt["production_configuration_ref"]
        != calibration_receipt.production_configuration_ref
        or receipt["model_era"] != calibration_receipt.model_era
        or receipt["policy_era"] != calibration_receipt.policy_era
        or receipt["shadow"] is not True
        or receipt["published"] is not False
        or receipt["mode"] not in {"weekly", "daily"}
        or not isinstance(receipt["receipt_ref"], str)
        or _SHADOW_RECEIPT_REF_RE.fullmatch(receipt["receipt_ref"]) is None
        or not isinstance(receipt["authentication_tag"], str)
        or _SHADOW_RECEIPT_AUTH_RE.fullmatch(receipt["authentication_tag"]) is None
        or not hmac.compare_digest(receipt["receipt_ref"], expected_ref)
        or not hmac.compare_digest(receipt["authentication_tag"], expected_auth)
        or not isinstance(raw_coverages, list)
        or not isinstance(raw_cleanups, list)
        or not isinstance(run_refs, list)
        or run_refs != sorted(set(run_refs))
        or any(
            not isinstance(item, str) or _RUN_REF_RE.fullmatch(item) is None
            for item in run_refs
        )
    ):
        raise ProductionMarkerError("shadow gate receipt is invalid")
    try:
        coverages = [
            _verify_shadow_coverage_receipt(
                identity,
                item,
                calibration_receipt=calibration_receipt,
            )
            for item in raw_coverages
            if isinstance(item, Mapping)
        ]
        cleanups = [
            _verify_shadow_cleanup_receipt(
                identity,
                item,
                calibration_receipt=calibration_receipt,
            )
            for item in raw_cleanups
            if isinstance(item, Mapping)
        ]
    except (TypeError, ValueError, ProductionMarkerError) as exc:
        raise ProductionMarkerError("shadow gate nested receipt is invalid") from exc
    coverages.sort(key=lambda item: item["run_ref"])
    cleanups.sort(key=lambda item: item["run_ref"])
    if (
        len(coverages) != len(raw_coverages)
        or len(cleanups) != len(raw_cleanups)
        or raw_coverages != coverages
        or raw_cleanups != cleanups
        or run_refs != [item["run_ref"] for item in coverages]
        or run_refs != [item["run_ref"] for item in cleanups]
        or any(item["mode"] != receipt["mode"] for item in coverages)
        or any(
            cleanup["coverage_receipt_ref"] != coverage["receipt_ref"]
            or cleanup["bundle_digest"] != coverage["export_bundle_digest"]
            or cleanup["mode"] != coverage["mode"]
            or cleanup["window_start"] != coverage["window_start"]
            or cleanup["window_end"] != coverage["window_end"]
            or cleanup["source_evidence_commitment"]
            != coverage["source_evidence_commitment"]
            or cleanup["configuration_root"] != coverage["configuration_root"]
            or cleanup["production_configuration_ref"]
            != coverage["production_configuration_ref"]
            or cleanup["model_era"] != coverage["model_era"]
            or cleanup["policy_era"] != coverage["policy_era"]
            or cleanup["policy_commitment"] != coverage["policy_commitment"]
            or cleanup["version_commitment"] != coverage["version_commitment"]
            for coverage, cleanup in zip(coverages, cleanups, strict=True)
        )
    ):
        raise ProductionMarkerError(
            "shadow gate does not bind exact coverage and cleanup receipts"
        )

    if receipt["mode"] == "weekly":
        if (
            len(run_refs) != 1
            or coverages[0]["partial"] is not False
            or receipt["partial_run_ref"] is not None
            or receipt["backfill_run_ref"] is not None
            or receipt["controlled_gap_receipt"] is not None
            or receipt["backfill_lineage_receipt"] is not None
        ):
            raise ProductionMarkerError(
                "weekly shadow receipt has partial or backfill semantics"
            )
    else:
        partial_rows = [item for item in coverages if item["partial"] is True]
        backfill_rows = [
            item
            for item in coverages
            if item["partial"] is False and item["backfill_of"] is not None
        ]
        partial_run_ref = receipt["partial_run_ref"]
        backfill_run_ref = receipt["backfill_run_ref"]
        raw_gap = receipt["controlled_gap_receipt"]
        raw_lineage = receipt["backfill_lineage_receipt"]
        if (
            len(run_refs) != 2
            or len(partial_rows) != 1
            or len(backfill_rows) != 1
            or partial_run_ref != partial_rows[0]["run_ref"]
            or backfill_run_ref != backfill_rows[0]["run_ref"]
            or partial_run_ref == backfill_run_ref
            or not isinstance(raw_gap, Mapping)
            or not isinstance(raw_lineage, Mapping)
        ):
            raise ProductionMarkerError(
                "daily shadow receipt lacks an exact partial/backfill cycle"
            )
        try:
            gap = controlled_gaps.verify_controlled_gap_receipt(identity, raw_gap)
            lineage = controlled_gaps.verify_backfill_lineage_receipt(
                identity, raw_lineage
            )
        except (TypeError, ValueError, controlled_gaps.ControlledGapError) as exc:
            raise ProductionMarkerError(
                "daily shadow controlled-gap evidence is invalid"
            ) from exc
        configured = set(partial_rows[0]["configured_host_refs"])
        partial_covered = set(partial_rows[0]["covered_host_refs"])
        backfill_covered = set(backfill_rows[0]["covered_host_refs"])
        if (
            raw_gap != gap.to_dict()
            or raw_lineage != lineage.to_dict()
            or gap.shadow is not True
            or gap.run_ref != partial_run_ref
            or lineage.partial_run_ref != partial_run_ref
            or lineage.controlled_gap_receipt_ref != gap.receipt_ref
            or partial_rows[0]["controlled_gap_receipt_ref"] != gap.receipt_ref
            or backfill_rows[0]["controlled_gap_receipt_ref"] != gap.receipt_ref
            or backfill_rows[0]["backfill_of"] != partial_run_ref
            or partial_rows[0]["window_start"] != gap.window_start
            or partial_rows[0]["window_end"] != gap.window_end
            or backfill_rows[0]["window_start"] != gap.window_start
            or backfill_rows[0]["window_end"] != gap.window_end
            or configured - partial_covered != {gap.host_ref}
            or set(backfill_rows[0]["configured_host_refs"]) != {gap.host_ref}
            or backfill_covered != {gap.host_ref}
            or partial_covered & backfill_covered
            or partial_covered | backfill_covered != configured
            or partial_rows[0]["source_evidence_commitment"]
            == backfill_rows[0]["source_evidence_commitment"]
            or partial_rows[0]["export_bundle_digest"]
            == backfill_rows[0]["export_bundle_digest"]
        ):
            raise ProductionMarkerError(
                "daily shadow receipt does not reconcile partial/backfill coverage"
            )
    return json.loads(json.dumps(receipt, sort_keys=True))


def _normalize_shadow_gate_evidence(
    values: Sequence[Mapping[str, object]],
    *,
    identity: IdentityKey,
    calibration_receipt: calibration.CalibrationReceipt,
) -> list[dict[str, Any]]:
    if isinstance(values, (str, bytes)) or len(values) != 3:
        raise ProductionMarkerError(
            "production marker requires exactly three shadow gate results"
        )
    normalized = [
        _verify_shadow_gate_receipt(
            identity,
            value,
            calibration_receipt=calibration_receipt,
        )
        for value in values
    ]
    normalized.sort(key=lambda item: item["receipt_ref"])
    weekly = [item for item in normalized if item["mode"] == "weekly"]
    run_coverages = [
        coverage for item in normalized for coverage in item["coverage_receipts"]
    ]
    if (
        len(weekly) != 2
        or [item["mode"] for item in normalized].count("daily") != 1
        or len({item["receipt_ref"] for item in normalized}) != 3
        or len({run_ref for item in normalized for run_ref in item["run_refs"]}) != 4
        or len(
            {
                (
                    item["coverage_receipts"][0]["window_start"],
                    item["coverage_receipts"][0]["window_end"],
                )
                for item in weekly
            }
        )
        != 2
        or len({item["source_evidence_commitment"] for item in run_coverages}) != 4
        or len({tuple(item["source_snapshot_refs"]) for item in run_coverages}) != 4
        or len({tuple(item["source_receipt_refs"]) for item in run_coverages}) != 4
        or len({item["export_bundle_digest"] for item in run_coverages}) != 4
        or len({item["policy_commitment"] for item in run_coverages}) != 1
        or len({item["version_commitment"] for item in run_coverages}) != 1
    ):
        raise ProductionMarkerError(
            "production marker requires two Weekly shadows and one Daily partial/backfill cycle"
        )
    return normalized


def installed_v2_cli_path() -> Path:
    """Return the sole supported installed v2 coordinator path."""

    return (
        Path.home()
        / ".codex"
        / "skills"
        / "codex-session-retrospective"
        / "scripts"
        / "session_retrospective_v2.py"
    ).absolute()


def automation_cutover_record_path() -> Path:
    return (
        Path.home()
        / ".codex"
        / "session-retrospective"
        / AUTOMATION_CUTOVER_RECORD_FILE
    ).absolute()


def automation_cutover_snapshot_path() -> Path:
    return (
        Path.home()
        / ".codex"
        / "session-retrospective"
        / AUTOMATION_CUTOVER_SNAPSHOT_FILE
    ).absolute()


def _automation_root() -> Path:
    return (Path.home() / ".codex" / "automations").absolute()


def _validated_automation_root(automation_root: Path) -> Path:
    try:
        candidate = automation_root.expanduser().absolute()
        candidate_metadata = candidate.stat(follow_symlinks=False)
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise AutomationCutoverBlocked("automation root uses a symlink")
        normalized = candidate.resolve(strict=True)
        metadata = normalized.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise AutomationCutoverBlocked(
            "automation root is unavailable or invalid"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AutomationCutoverBlocked("automation root ownership is invalid")
    return normalized


def _read_installed_automation_bytes(
    record_path: Path,
    *,
    automation_root: Path,
) -> bytes:
    try:
        _validated_automation_root(automation_root)
        for directory in (record_path.parent,):
            metadata = directory.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise AutomationCutoverBlocked(
                    "automation directory ownership is invalid"
                )
        descriptor = os.open(
            record_path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except (OSError, RuntimeError) as exc:
        raise AutomationCutoverBlocked(
            "required automation record is unavailable or invalid"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > MAX_AUTOMATION_RECORD_BYTES
        ):
            raise AutomationCutoverBlocked("automation record ownership is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_AUTOMATION_RECORD_BYTES - total + 1),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_AUTOMATION_RECORD_BYTES:
                raise AutomationCutoverBlocked("automation record exceeds byte limit")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _automation_pre_update_row(
    automation_id: str,
    *,
    automation_root: Path,
) -> dict[str, object]:
    record_path = automation_root / automation_id / "automation.toml"
    directory = record_path.parent
    try:
        metadata = directory.stat(follow_symlinks=False)
    except FileNotFoundError:
        return {
            "automation_id": automation_id,
            "mode": STABLE_AUTOMATION_MODES[automation_id],
            "record_path": str(record_path),
            "record_sha256": None,
            "state": "absent",
        }
    except OSError as exc:
        raise AutomationCutoverBlocked(
            "pre-update automation state is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AutomationCutoverBlocked(
            "pre-update automation directory ownership is invalid"
        )
    raw = _read_installed_automation_bytes(
        record_path,
        automation_root=automation_root,
    )
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise AutomationCutoverBlocked(
            "pre-update automation record is invalid"
        ) from exc
    if (
        document.get("version") != 1
        or document.get("id") != automation_id
        or document.get("kind") != "cron"
    ):
        raise AutomationCutoverBlocked(
            "pre-update automation record does not own the stable ID"
        )
    return {
        "automation_id": automation_id,
        "mode": STABLE_AUTOMATION_MODES[automation_id],
        "record_path": str(record_path),
        "record_sha256": hashlib.sha256(raw).hexdigest(),
        "state": "present",
    }


def verify_automation_cutover_snapshot(
    identity: IdentityKey,
    value: Mapping[str, object],
    *,
    automation_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    fields = {
        "authentication_tag",
        "automation_records",
        "automation_root",
        "identity_key_id",
        "schema",
        "snapshot_ref",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AutomationCutoverBlocked("automation cutover snapshot is invalid")
    snapshot = dict(value)
    body = {
        key: snapshot[key]
        for key in snapshot
        if key not in {"authentication_tag", "snapshot_ref"}
    }
    expected_ref = "automation_cutover_snapshot_v2:" + identity.derive_digest(
        "automation-cutover-snapshot-ref-v2", body
    )
    expected_tag = "automation_cutover_snapshot_auth_v2:" + identity.derive_digest(
        "automation-cutover-snapshot-auth-v2",
        {**body, "snapshot_ref": expected_ref},
    )
    expected_root = _validated_automation_root(
        _automation_root()
        if automation_root is None
        else Path(automation_root).expanduser().absolute()
    )
    rows = snapshot["automation_records"]
    if (
        snapshot["schema"] != AUTOMATION_CUTOVER_SNAPSHOT_SCHEMA
        or snapshot["identity_key_id"] != identity.key_id
        or snapshot["automation_root"] != str(expected_root)
        or snapshot["snapshot_ref"] != expected_ref
        or not isinstance(snapshot["snapshot_ref"], str)
        or _AUTOMATION_SNAPSHOT_REF_RE.fullmatch(snapshot["snapshot_ref"]) is None
        or snapshot["authentication_tag"] != expected_tag
        or not isinstance(snapshot["authentication_tag"], str)
        or _AUTOMATION_SNAPSHOT_AUTH_RE.fullmatch(snapshot["authentication_tag"])
        is None
        or not isinstance(rows, list)
        or len(rows) != len(STABLE_AUTOMATION_MODES)
    ):
        raise AutomationCutoverBlocked("automation cutover snapshot is invalid")
    normalized: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "automation_id",
            "mode",
            "record_path",
            "record_sha256",
            "state",
        }:
            raise AutomationCutoverBlocked(
                "automation cutover snapshot inventory is invalid"
            )
        automation_id = row["automation_id"]
        state = row["state"]
        digest = row["record_sha256"]
        if (
            not isinstance(automation_id, str)
            or automation_id not in STABLE_AUTOMATION_MODES
            or row["mode"] != STABLE_AUTOMATION_MODES.get(automation_id)
            or row["record_path"]
            != str(expected_root / automation_id / "automation.toml")
            or state not in {"absent", "present"}
            or (state == "absent" and digest is not None)
            or (
                state == "present"
                and (
                    not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None
                )
            )
        ):
            raise AutomationCutoverBlocked(
                "automation cutover snapshot inventory is invalid"
            )
        normalized.append(dict(row))
    normalized.sort(key=lambda item: str(item["automation_id"]))
    if rows != normalized or [item["automation_id"] for item in rows] != sorted(
        STABLE_AUTOMATION_MODES
    ):
        raise AutomationCutoverBlocked(
            "automation cutover snapshot includes unrelated automations"
        )
    return json.loads(json.dumps(snapshot, sort_keys=True))


def capture_automation_cutover_snapshot(
    path: str | os.PathLike[str],
    *,
    identity: IdentityKey,
    automation_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    root = _validated_automation_root(
        _automation_root()
        if automation_root is None
        else Path(automation_root).expanduser().absolute()
    )
    body = {
        "automation_records": [
            _automation_pre_update_row(
                automation_id,
                automation_root=root,
            )
            for automation_id in sorted(STABLE_AUTOMATION_MODES)
        ],
        "automation_root": str(root),
        "identity_key_id": identity.key_id,
        "schema": AUTOMATION_CUTOVER_SNAPSHOT_SCHEMA,
    }
    snapshot_ref = "automation_cutover_snapshot_v2:" + identity.derive_digest(
        "automation-cutover-snapshot-ref-v2", body
    )
    snapshot = {
        **body,
        "authentication_tag": "automation_cutover_snapshot_auth_v2:"
        + identity.derive_digest(
            "automation-cutover-snapshot-auth-v2",
            {**body, "snapshot_ref": snapshot_ref},
        ),
        "snapshot_ref": snapshot_ref,
    }
    verified = verify_automation_cutover_snapshot(
        identity,
        snapshot,
        automation_root=root,
    )
    safe_io.atomic_write_json(path, verified)
    return verified


def load_automation_cutover_snapshot(
    path: str | os.PathLike[str],
    *,
    identity: IdentityKey,
    automation_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    try:
        value = safe_io.read_bounded_json(
            path,
            max_bytes=MAX_AUTOMATION_RECORD_BYTES,
            require_owner_only=True,
        )
    except (OSError, ValueError) as exc:
        raise AutomationCutoverBlocked(
            "automation cutover snapshot is unavailable or invalid"
        ) from exc
    return verify_automation_cutover_snapshot(
        identity,
        value,
        automation_root=automation_root,
    )


def _validate_installed_automation(
    automation_id: str,
    *,
    automation_root: Path,
    cli_path: Path,
) -> tuple[str, str]:
    expected_mode = STABLE_AUTOMATION_MODES[automation_id]
    record_path = automation_root / automation_id / "automation.toml"
    try:
        raw = _read_installed_automation_bytes(
            record_path,
            automation_root=automation_root,
        )
        document = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise AutomationCutoverBlocked(
            "required automation record is unavailable or invalid"
        ) from exc
    prompt = document.get("prompt")
    schedule = document.get("rrule")
    expected_frequency = "FREQ=DAILY" if expected_mode == "daily" else "FREQ=WEEKLY"
    forbidden_prompt_tokens = (
        "--allow-partial",
        "--backfill-of",
        "--controlled-gap-receipt",
        "--holdout-host",
        "--host",
        "--shadow",
        "reference_only",
        "session_retrospective.py",
    )
    if (
        document.get("version") != 1
        or document.get("id") != automation_id
        or document.get("kind") != "cron"
        or document.get("status") != "ACTIVE"
        or document.get("reference_only") is not None
        or not isinstance(prompt, str)
        or prompt.count(str(cli_path)) != 1
        or f"--mode {expected_mode}" not in prompt
        or any(token in prompt for token in forbidden_prompt_tokens)
        or not isinstance(schedule, str)
        or not schedule.startswith(expected_frequency)
    ):
        raise AutomationCutoverBlocked(
            "automation record is not an active v2 production coordinator"
        )
    return str(record_path), hashlib.sha256(raw).hexdigest()


def _normalize_automation_update_result(
    value: Mapping[str, object],
    *,
    identity: IdentityKey,
    pre_update_snapshot: Mapping[str, object],
    installed_records: Mapping[str, tuple[str, str]],
) -> tuple[str, list[dict[str, object]]]:
    fields = {
        "available",
        "capability",
        "operations",
        "pre_update_snapshot_ref",
        "schema",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AutomationCutoverBlocked(
            "automation_update result is unavailable or invalid"
        )
    operations = value["operations"]
    if (
        value["schema"] != AUTOMATION_UPDATE_RESULT_SCHEMA
        or value["capability"] != "automation_update"
        or value["available"] is not True
        or value["pre_update_snapshot_ref"] != pre_update_snapshot["snapshot_ref"]
        or not isinstance(operations, list)
        or len(operations) != len(STABLE_AUTOMATION_MODES)
    ):
        raise AutomationCutoverBlocked(
            "automation_update capability did not admit cutover"
        )
    normalized: list[dict[str, object]] = []
    for item in operations:
        if not isinstance(item, Mapping) or set(item) != {
            "automation_id",
            "operation",
            "previous_record_sha256",
            "record_sha256",
            "status",
        }:
            raise AutomationCutoverBlocked(
                "automation_update operation inventory is invalid"
            )
        automation_id = item["automation_id"]
        operation = item["operation"]
        previous = item["previous_record_sha256"]
        record_sha256 = item["record_sha256"]
        snapshot_rows = {
            str(row["automation_id"]): row
            for row in pre_update_snapshot["automation_records"]
        }
        before = snapshot_rows.get(str(automation_id))
        installed = installed_records.get(str(automation_id))
        expected_operation = (
            "register"
            if isinstance(before, Mapping) and before.get("state") == "absent"
            else "update"
        )
        expected_previous = (
            None if not isinstance(before, Mapping) else before.get("record_sha256")
        )
        if (
            not isinstance(automation_id, str)
            or automation_id not in STABLE_AUTOMATION_MODES
            or not isinstance(before, Mapping)
            or installed is None
            or item["status"] != "success"
            or operation != expected_operation
            or previous != expected_previous
            or record_sha256 != installed[1]
            or not isinstance(record_sha256, str)
            or _DIGEST_RE.fullmatch(record_sha256) is None
            or (operation == "register" and previous is not None)
            or (operation == "update" and previous == record_sha256)
        ):
            raise AutomationCutoverBlocked(
                "automation_update operation is not an exact stable-ID admission"
            )
        normalized.append(
            {
                "automation_id": automation_id,
                "operation": operation,
                "previous_record_sha256": previous,
                "record_sha256": record_sha256,
                "status": "success",
            }
        )
    normalized.sort(key=lambda item: str(item["automation_id"]))
    if operations != normalized or [
        item["automation_id"] for item in normalized
    ] != sorted(STABLE_AUTOMATION_MODES):
        raise AutomationCutoverBlocked(
            "automation_update result includes unrelated automations"
        )
    normalized_result = {
        "available": True,
        "capability": "automation_update",
        "operations": normalized,
        "pre_update_snapshot_ref": pre_update_snapshot["snapshot_ref"],
        "schema": AUTOMATION_UPDATE_RESULT_SCHEMA,
    }
    result_ref = "automation_update_result_v2:" + identity.derive_digest(
        "automation-update-result-v2",
        normalized_result,
    )
    return result_ref, normalized


def verify_automation_cutover_record(
    identity: IdentityKey,
    value: Mapping[str, object],
) -> dict[str, Any]:
    fields = {
        "authentication_tag",
        "automation_pre_update_snapshot_ref",
        "automation_records",
        "automation_update_capability",
        "automation_update_result_ref",
        "cutover_ready",
        "identity_key_id",
        "installed_cli_path",
        "installed_commit",
        "schema",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AutomationCutoverBlocked(
            "automation cutover record has an unexpected shape"
        )
    record = dict(value)
    body = {key: record[key] for key in record if key != "authentication_tag"}
    expected_tag = "automation_cutover_auth_v2:" + identity.derive_digest(
        "automation-cutover-v2", body
    )
    cli_path = record["installed_cli_path"]
    cli_suffix = (
        "/.codex/skills/codex-session-retrospective/scripts/session_retrospective_v2.py"
    )
    rows = record["automation_records"]
    if (
        record["schema"] != AUTOMATION_CUTOVER_RECORD_SCHEMA
        or record["identity_key_id"] != identity.key_id
        or record["automation_update_capability"] != "automation_update"
        or not isinstance(record["automation_pre_update_snapshot_ref"], str)
        or _AUTOMATION_SNAPSHOT_REF_RE.fullmatch(
            record["automation_pre_update_snapshot_ref"]
        )
        is None
        or record["cutover_ready"] is not True
        or not isinstance(record["automation_update_result_ref"], str)
        or _AUTOMATION_RESULT_REF_RE.fullmatch(record["automation_update_result_ref"])
        is None
        or not isinstance(record["installed_commit"], str)
        or _OBJECT_ID_RE.fullmatch(record["installed_commit"]) is None
        or not isinstance(cli_path, str)
        or not Path(cli_path).is_absolute()
        or not cli_path.endswith(cli_suffix)
        or not isinstance(record["authentication_tag"], str)
        or _AUTOMATION_CUTOVER_AUTH_RE.fullmatch(record["authentication_tag"]) is None
        or not hmac.compare_digest(record["authentication_tag"], expected_tag)
        or not isinstance(rows, list)
        or len(rows) != len(STABLE_AUTOMATION_MODES)
    ):
        raise AutomationCutoverBlocked("automation cutover record is invalid")
    normalized_rows: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "automation_id",
            "mode",
            "operation",
            "previous_record_sha256",
            "record_path",
            "record_ref",
            "record_sha256",
        }:
            raise AutomationCutoverBlocked(
                "automation cutover record inventory is invalid"
            )
        automation_id = row["automation_id"]
        operation = row["operation"]
        previous = row["previous_record_sha256"]
        record_path = row["record_path"]
        record_sha256 = row["record_sha256"]
        ref_body = {
            "automation_id": automation_id,
            "automation_pre_update_snapshot_ref": record[
                "automation_pre_update_snapshot_ref"
            ],
            "automation_update_result_ref": record["automation_update_result_ref"],
            "installed_cli_path": cli_path,
            "mode": row["mode"],
            "operation": operation,
            "previous_record_sha256": previous,
            "record_path": record_path,
            "record_sha256": record_sha256,
        }
        expected_ref = "automation_record_v2:" + identity.derive_digest(
            "automation-record-v2", ref_body
        )
        if (
            not isinstance(automation_id, str)
            or automation_id not in STABLE_AUTOMATION_MODES
            or row["mode"] != STABLE_AUTOMATION_MODES.get(automation_id)
            or operation not in {"register", "update"}
            or (operation == "register" and previous is not None)
            or (
                operation == "update"
                and (
                    not isinstance(previous, str)
                    or _DIGEST_RE.fullmatch(previous) is None
                )
            )
            or not isinstance(record_path, str)
            or not Path(record_path).is_absolute()
            or not record_path.endswith(
                f"/.codex/automations/{automation_id}/automation.toml"
            )
            or not isinstance(record_sha256, str)
            or _DIGEST_RE.fullmatch(record_sha256) is None
            or previous == record_sha256
            or not isinstance(row["record_ref"], str)
            or _AUTOMATION_RECORD_REF_RE.fullmatch(row["record_ref"]) is None
            or not hmac.compare_digest(row["record_ref"], expected_ref)
        ):
            raise AutomationCutoverBlocked(
                "automation cutover record inventory is invalid"
            )
        normalized_rows.append(dict(row))
    normalized_rows.sort(key=lambda item: str(item["automation_id"]))
    if rows != normalized_rows or [
        item["automation_id"] for item in normalized_rows
    ] != sorted(STABLE_AUTOMATION_MODES):
        raise AutomationCutoverBlocked("automation cutover record inventory is invalid")
    return json.loads(json.dumps(record, sort_keys=True))


def issue_automation_cutover_record(
    path: str | os.PathLike[str],
    *,
    identity: IdentityKey,
    capability_result: Mapping[str, object],
    pre_update_snapshot: Mapping[str, object],
    installed_commit: str,
    automation_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(installed_commit, str)
        or _OBJECT_ID_RE.fullmatch(installed_commit) is None
    ):
        raise AutomationCutoverBlocked("installed release commit is invalid")
    root = _validated_automation_root(
        _automation_root()
        if automation_root is None
        else Path(automation_root).expanduser().absolute()
    )
    snapshot = verify_automation_cutover_snapshot(
        identity,
        pre_update_snapshot,
        automation_root=root,
    )
    cli_path = installed_v2_cli_path()
    installed_records = {
        automation_id: _validate_installed_automation(
            automation_id,
            automation_root=root,
            cli_path=cli_path,
        )
        for automation_id in sorted(STABLE_AUTOMATION_MODES)
    }
    tool_result_ref, operations = _normalize_automation_update_result(
        capability_result,
        identity=identity,
        pre_update_snapshot=snapshot,
        installed_records=installed_records,
    )
    rows: list[dict[str, object]] = []
    for operation in operations:
        automation_id = str(operation["automation_id"])
        record_path, record_sha256 = installed_records[automation_id]
        previous = operation["previous_record_sha256"]
        ref_body = {
            "automation_id": automation_id,
            "automation_pre_update_snapshot_ref": snapshot["snapshot_ref"],
            "automation_update_result_ref": tool_result_ref,
            "installed_cli_path": str(cli_path),
            "mode": STABLE_AUTOMATION_MODES[automation_id],
            "operation": operation["operation"],
            "previous_record_sha256": previous,
            "record_path": record_path,
            "record_sha256": record_sha256,
        }
        rows.append(
            {
                "automation_id": automation_id,
                "mode": STABLE_AUTOMATION_MODES[automation_id],
                "operation": operation["operation"],
                "previous_record_sha256": previous,
                "record_path": record_path,
                "record_ref": "automation_record_v2:"
                + identity.derive_digest("automation-record-v2", ref_body),
                "record_sha256": record_sha256,
            }
        )
    body = {
        "automation_pre_update_snapshot_ref": snapshot["snapshot_ref"],
        "automation_records": rows,
        "automation_update_capability": "automation_update",
        "automation_update_result_ref": tool_result_ref,
        "cutover_ready": True,
        "identity_key_id": identity.key_id,
        "installed_cli_path": str(cli_path),
        "installed_commit": installed_commit,
        "schema": AUTOMATION_CUTOVER_RECORD_SCHEMA,
    }
    record = {
        **body,
        "authentication_tag": "automation_cutover_auth_v2:"
        + identity.derive_digest("automation-cutover-v2", body),
    }
    verified = verify_automation_cutover_record(identity, record)
    safe_io.atomic_write_json(path, verified)
    return verified


def load_automation_cutover_record(
    path: str | os.PathLike[str],
    *,
    identity: IdentityKey,
) -> dict[str, Any]:
    try:
        value = safe_io.read_bounded_json(
            path,
            max_bytes=MAX_AUTOMATION_RECORD_BYTES,
            require_owner_only=True,
        )
    except (OSError, ValueError) as exc:
        raise AutomationCutoverBlocked(
            "automation cutover record is unavailable or invalid"
        ) from exc
    return verify_automation_cutover_record(identity, value)


def issue_production_marker(
    path: str | os.PathLike[str],
    *,
    identity: IdentityKey,
    history_repo: str | os.PathLike[str],
    target_ref: str,
    configuration_root: str,
    configuration_ref: str,
    model_era: str,
    policy_era: str,
    calibration_receipt: calibration.CalibrationReceipt | Mapping[str, object],
    accepted_shadow_evidence: Sequence[Mapping[str, object]],
    automation_cutover_record: Mapping[str, object],
    installed_commits: Sequence[str],
) -> dict[str, Any]:
    try:
        verified_calibration = calibration.verify_calibration_receipt(
            identity,
            calibration_receipt,
        )
    except (TypeError, ValueError, calibration.CalibrationError) as exc:
        raise ProductionMarkerError(
            "production marker calibration evidence is invalid"
        ) from exc
    if (
        configuration_root != verified_calibration.production_configuration_root
        or configuration_ref != verified_calibration.production_configuration_ref
        or model_era != verified_calibration.model_era
        or policy_era != verified_calibration.policy_era
    ):
        raise ProductionMarkerError(
            "production marker configuration and eras are not bound by calibration evidence"
        )
    evidence = _normalize_shadow_gate_evidence(
        accepted_shadow_evidence,
        identity=identity,
        calibration_receipt=verified_calibration,
    )
    shadows = [item["receipt_ref"] for item in evidence]
    commits = sorted(set(installed_commits))
    if not commits or any(_OBJECT_ID_RE.fullmatch(item) is None for item in commits):
        raise ProductionMarkerError("production marker installed commits are invalid")
    try:
        cutover_record = verify_automation_cutover_record(
            identity,
            automation_cutover_record,
        )
    except AutomationCutoverBlocked as exc:
        raise ProductionMarkerError(
            "production marker automation cutover evidence is invalid"
        ) from exc
    if cutover_record["installed_commit"] not in commits:
        raise ProductionMarkerError(
            "production marker does not install the automation cutover commit"
        )
    if (
        not isinstance(configuration_ref, str)
        or _OPAQUE_REF_RE.fullmatch(configuration_ref) is None
    ):
        raise ProductionMarkerError("production marker configuration ref is invalid")
    body = {
        "accepted_shadow_evidence": evidence,
        "accepted_shadow_refs": shadows,
        "automation_cutover_record": cutover_record,
        "calibration_receipt": verified_calibration.to_dict(),
        "configuration_root": verified_calibration.production_configuration_root,
        "configuration_ref": verified_calibration.production_configuration_ref,
        "cutover_complete": True,
        "history_repository_ref": history_repository_binding(
            history_repo, target_ref, identity=identity
        ),
        "identity_key_id": identity.key_id,
        "installed_commits": commits,
        "model_era": verified_calibration.model_era,
        "policy_era": verified_calibration.policy_era,
        "schema": PRODUCTION_MARKER_SCHEMA,
        "target_ref": target_ref,
    }
    marker = {
        **body,
        "authentication_tag": "production_marker_auth_v2:"
        + identity.derive_digest("production-marker-v2", body),
    }
    safe_io.atomic_write_json(path, marker)
    return marker


def load_production_marker(
    path: str | os.PathLike[str],
    *,
    identity: IdentityKey,
    history_repo: str | os.PathLike[str],
    target_ref: str,
    configuration_root: str,
    configuration_ref: str,
    model_era: str,
    policy_era: str,
) -> dict[str, Any]:
    try:
        marker = safe_io.read_bounded_json(
            path,
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
    except (OSError, ValueError) as exc:
        raise ProductionMarkerError(
            "production marker is unavailable or invalid"
        ) from exc
    fields = {
        "accepted_shadow_evidence",
        "accepted_shadow_refs",
        "authentication_tag",
        "automation_cutover_record",
        "calibration_receipt",
        "configuration_root",
        "configuration_ref",
        "cutover_complete",
        "history_repository_ref",
        "identity_key_id",
        "installed_commits",
        "model_era",
        "policy_era",
        "schema",
        "target_ref",
    }
    if not isinstance(marker, Mapping) or set(marker) != fields:
        raise ProductionMarkerError("production marker has an unexpected shape")
    body = {key: marker[key] for key in marker if key != "authentication_tag"}
    expected_tag = "production_marker_auth_v2:" + identity.derive_digest(
        "production-marker-v2", body
    )
    if not isinstance(marker["authentication_tag"], str) or not hmac.compare_digest(
        marker["authentication_tag"], expected_tag
    ):
        raise ProductionMarkerError("production marker authentication failed")
    if (
        marker["schema"] != PRODUCTION_MARKER_SCHEMA
        or marker["cutover_complete"] is not True
        or marker["identity_key_id"] != identity.key_id
        or marker["target_ref"] != target_ref
        or marker["configuration_root"] != configuration_root
        or marker["configuration_ref"] != configuration_ref
        or marker["model_era"] != model_era
        or marker["policy_era"] != policy_era
        or marker["history_repository_ref"]
        != history_repository_binding(history_repo, target_ref, identity=identity)
    ):
        raise ProductionMarkerError(
            "production marker does not authorize this configuration"
        )
    try:
        verified_calibration = calibration.verify_calibration_receipt(
            identity,
            marker["calibration_receipt"],
        )
    except (TypeError, ValueError, calibration.CalibrationError) as exc:
        raise ProductionMarkerError(
            "production marker calibration evidence is invalid"
        ) from exc
    if (
        marker["configuration_root"]
        != verified_calibration.production_configuration_root
        or marker["configuration_ref"]
        != verified_calibration.production_configuration_ref
        or marker["model_era"] != verified_calibration.model_era
        or marker["policy_era"] != verified_calibration.policy_era
    ):
        raise ProductionMarkerError(
            "production marker configuration and eras are not bound by calibration evidence"
        )
    try:
        evidence = _normalize_shadow_gate_evidence(
            marker["accepted_shadow_evidence"],
            identity=identity,
            calibration_receipt=verified_calibration,
        )
    except (TypeError, ValueError, ProductionMarkerError) as exc:
        raise ProductionMarkerError(
            "production marker shadow evidence is invalid"
        ) from exc
    expected_shadow_refs = [item["receipt_ref"] for item in evidence]
    try:
        cutover_record = verify_automation_cutover_record(
            identity,
            marker["automation_cutover_record"],
        )
    except AutomationCutoverBlocked as exc:
        raise ProductionMarkerError(
            "production marker automation cutover evidence is invalid"
        ) from exc
    if (
        marker["accepted_shadow_evidence"] != evidence
        or not isinstance(marker["accepted_shadow_refs"], list)
        or marker["accepted_shadow_refs"] != expected_shadow_refs
        or marker["accepted_shadow_refs"] != sorted(set(marker["accepted_shadow_refs"]))
        or any(
            _SHADOW_RECEIPT_REF_RE.fullmatch(item) is None
            for item in marker["accepted_shadow_refs"]
        )
        or not isinstance(marker["installed_commits"], list)
        or not marker["installed_commits"]
        or marker["installed_commits"] != sorted(set(marker["installed_commits"]))
        or any(
            _OBJECT_ID_RE.fullmatch(item) is None
            for item in marker["installed_commits"]
        )
        or marker["automation_cutover_record"] != cutover_record
        or cutover_record["installed_commit"] not in marker["installed_commits"]
    ):
        raise ProductionMarkerError("production marker inventory is invalid")
    return json.loads(json.dumps(marker, sort_keys=True))


def _provider_cache_record(
    history: DurableHistoryState,
    *,
    initialization_request: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        **history.provider_projection(),
        "initialization_request": json.loads(
            json.dumps(initialization_request, sort_keys=True)
        ),
        "schema": PROVIDER_CACHE_SCHEMA,
    }


def _require_provider_history_identity(
    history: DurableHistoryState,
    *,
    identity: IdentityKey,
    label: str,
) -> None:
    key_id = getattr(history, "identity_key_id", None)
    if not isinstance(key_id, str) or not hmac.compare_digest(key_id, identity.key_id):
        raise ProviderCacheError(f"{label} uses a foreign identity_key_id")


def _read_provider_cache_at(
    directory_fd: int,
    directory: Path,
    *,
    identity: IdentityKey,
) -> dict[str, Any] | None:
    try:
        value = safe_io.read_bounded_json_at(
            directory_fd,
            PROVIDER_CACHE_FILE,
            display_path=directory / PROVIDER_CACHE_FILE,
            max_bytes=MAX_PROVIDER_CACHE_BYTES,
            require_owner_only=True,
        )
    except FileNotFoundError:
        return None
    expected_fields = {
        "cursor_root_ref",
        "cursor_rows",
        "episode_head_root_ref",
        "episode_heads",
        "episode_membership",
        "history_commit",
        "identity_key_id",
        "initialization_request",
        "provider_revision",
        "publication_commit",
        "schema",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value.get("schema") != PROVIDER_CACHE_SCHEMA
    ):
        raise ProviderCacheError("provider cache is malformed")
    request = value["initialization_request"]
    if not isinstance(request, Mapping) or set(request) != {
        "expected_revision",
        "history_commit",
        "history_projection",
        "schema",
    }:
        raise ProviderCacheError("provider initialization request is malformed")
    if request.get("schema") != PROVIDER_INITIALIZATION_SCHEMA:
        raise ProviderCacheError("provider initialization schema is invalid")
    expected_revision = request.get("expected_revision")
    if (
        not isinstance(expected_revision, int)
        or isinstance(expected_revision, bool)
        or expected_revision != 0
    ):
        raise ProviderCacheError(
            "provider initialization revision must prove an empty cache"
        )
    try:
        current_projection = {
            key: value[key]
            for key in expected_fields
            if key not in {"initialization_request", "schema"}
        }
        current_history = history_state_from_projection(
            current_projection,
            identity=identity,
        )
        initialized = history_state_from_projection(
            request["history_projection"],
            identity=identity,
        )
    except (KeyError, TypeError, HistoryValidationError) as exc:
        raise ProviderCacheError("provider cache projection is malformed") from exc
    if (
        request["history_commit"] != initialized.head_commit
        or current_history.identity_key_id != initialized.identity_key_id
    ):
        raise ProviderCacheError("provider initialization request is inconsistent")
    return value


def initialize_provider_cache(
    state_dir: str | os.PathLike[str],
    *,
    history: DurableHistoryState,
    expected_revision: int,
    identity: IdentityKey,
) -> dict[str, Any]:
    if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
        raise ProviderCacheError("expected_revision must be an integer")
    if expected_revision != 0:
        raise ProviderCacheConflict("expected_revision must be exactly zero")
    _require_provider_history_identity(
        history,
        identity=identity,
        label="provider initialization history",
    )
    directory, directory_fd = safe_io.open_owner_only_directory(
        state_dir,
        create=True,
        reject_symlink_ancestors=True,
    )
    lock_fd = safe_io.open_lock_file_at(
        directory_fd,
        PROVIDER_CACHE_LOCK,
        display_path=directory / PROVIDER_CACHE_LOCK,
    )
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    request = {
        "expected_revision": expected_revision,
        "history_commit": history.head_commit,
        "history_projection": history.provider_projection(),
        "schema": PROVIDER_INITIALIZATION_SCHEMA,
    }
    try:
        current = _read_provider_cache_at(
            directory_fd,
            directory,
            identity=identity,
        )
        if current is not None:
            recorded = current.get("initialization_request")
            if (
                not isinstance(recorded, Mapping)
                or recorded.get("expected_revision") != expected_revision
            ):
                raise ProviderCacheConflict(
                    "provider initialization expected_revision changed"
                )
            if canonical_json_bytes(recorded) != canonical_json_bytes(request):
                raise ProviderCacheConflict("provider initialization request changed")
            expected = _provider_cache_record(history, initialization_request=request)
            if canonical_json_bytes(current) != canonical_json_bytes(expected):
                raise ProviderCacheConflict(
                    "provider cache no longer matches its initialization"
                )
            return {"idempotent": True, "state": current}
        record = _provider_cache_record(history, initialization_request=request)
        safe_io.atomic_write_bytes_at(
            directory_fd,
            PROVIDER_CACHE_FILE,
            canonical_json_bytes(record) + b"\n",
            display_path=directory / PROVIDER_CACHE_FILE,
        )
        return {"idempotent": False, "state": record}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        os.close(directory_fd)


def assert_provider_cache_matches(
    state_dir: str | os.PathLike[str],
    history: DurableHistoryState,
    *,
    identity: IdentityKey,
) -> dict[str, Any]:
    directory, directory_fd = safe_io.open_owner_only_directory(
        state_dir,
        reject_symlink_ancestors=True,
    )
    try:
        current = _read_provider_cache_at(
            directory_fd,
            directory,
            identity=identity,
        )
    finally:
        os.close(directory_fd)
    if current is None:
        raise ProviderCacheError("provider cache is not initialized")
    projection = history.provider_projection()
    for key, expected in projection.items():
        if canonical_json_bytes(current.get(key)) != canonical_json_bytes(expected):
            raise ProviderCacheConflict(
                "provider cache differs from the latest durable history"
            )
    return current


def derive_provider_cache(
    state_dir: str | os.PathLike[str],
    *,
    previous: DurableHistoryState,
    published: DurableHistoryState,
    identity: IdentityKey,
) -> dict[str, Any]:
    _require_provider_history_identity(
        previous,
        identity=identity,
        label="previous provider history",
    )
    _require_provider_history_identity(
        published,
        identity=identity,
        label="published provider history",
    )
    if published.provider_revision != previous.provider_revision + 1:
        raise ProviderCacheError(
            "published history does not advance one provider revision"
        )
    directory, directory_fd = safe_io.open_owner_only_directory(
        state_dir,
        reject_symlink_ancestors=True,
    )
    lock_fd = safe_io.open_lock_file_at(
        directory_fd,
        PROVIDER_CACHE_LOCK,
        display_path=directory / PROVIDER_CACHE_LOCK,
    )
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        current = _read_provider_cache_at(
            directory_fd,
            directory,
            identity=identity,
        )
        if current is None:
            raise ProviderCacheError("provider cache is not initialized")
        if current.get("history_commit") == published.head_commit:
            assert_provider_cache_matches(
                state_dir,
                published,
                identity=identity,
            )
            return {"idempotent": True, "state": current}
        for key, expected in previous.provider_projection().items():
            if canonical_json_bytes(current.get(key)) != canonical_json_bytes(expected):
                raise ProviderCacheConflict(
                    "provider cache was rolled back or modified"
                )
        record = _provider_cache_record(
            published,
            initialization_request=current["initialization_request"],
        )
        safe_io.atomic_write_bytes_at(
            directory_fd,
            PROVIDER_CACHE_FILE,
            canonical_json_bytes(record) + b"\n",
            display_path=directory / PROVIDER_CACHE_FILE,
        )
        return {"idempotent": False, "state": record}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        os.close(directory_fd)
