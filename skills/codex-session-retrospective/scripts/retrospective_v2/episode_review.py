"""Deterministic episode construction, lineage, and review job planning."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any

from .contracts import JobKind
from .identity import IdentityKey
from .result_validation import (
    CONFIDENCE_LEVELS,
    RISK_FLAGS,
    ResultValidationError,
    validate_episode_review_result,
)


EPISODE_REVISION_SCHEMA = "episode_revision_v2"
SEGMENTATION_GAP = timedelta(hours=72)

MEANINGFULNESS_DISPOSITIONS = frozenset(
    {"meaningful", "context_only", "meaningfulness_gap"}
)
BOUNDARY_REASONS = frozenset(
    {
        "completed_then_new_goal",
        "elapsed_72h_candidate",
        "goal_change",
        "repository_responsibility_change",
        "user_redirect",
        "workstream_change",
    }
)
SECOND_REVIEW_REASONS = frozenset(
    {
        "conflicting_signals",
        "credential_risk",
        "destructive_action_risk",
        "high_impact_screen",
        "high_impact_screen_gap",
        "low_extraction_confidence",
        "low_segmentation_confidence",
        "primary_reviewer_request",
        "privacy_risk",
        "production_risk",
        "reviewer_escalation",
        "safety_risk",
    }
)

_OPAQUE_REF_RE = re.compile(r"^[a-z][a-z0-9_]*_ref_v2:[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^identity_key_v2:[0-9a-f]{64}$")
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
_HIGH_RISK_TO_REASON = {
    "safety": "safety_risk",
    "privacy": "privacy_risk",
    "production": "production_risk",
    "destructive_action": "destructive_action_risk",
    "credential": "credential_risk",
    "low_extraction_confidence": "low_extraction_confidence",
    "low_segmentation_confidence": "low_segmentation_confidence",
    "conflicting_signals": "conflicting_signals",
    "high_impact_prompt": "high_impact_screen",
}


def _error(path: str, message: str) -> ResultValidationError:
    return ResultValidationError(f"{path}: {message}")


def _require_mapping(value: Any, *, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(path, "must be an object")
    return value


def _require_ref(value: Any, *, path: str, expected_prefix: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_REF_RE.fullmatch(value):
        raise _error(path, "must be an opaque v2 reference")
    prefix = f"{expected_prefix}_ref_v2:"
    if not value.startswith(prefix):
        raise _error(path, f"must use the {prefix} prefix")
    return value


def _thread_ref(turn: Mapping[str, Any], *, path: str) -> str:
    session_ref = turn.get("session_ref")
    thread_ref = turn.get("thread_ref")
    if session_ref is None and thread_ref is None:
        raise _error(path, "session_ref or thread_ref is required")
    if session_ref is not None:
        session_ref = _require_ref(
            session_ref,
            path=f"{path}.session_ref",
            expected_prefix="session",
        )
    if thread_ref is not None:
        thread_ref = _require_ref(
            thread_ref,
            path=f"{path}.thread_ref",
            expected_prefix="session",
        )
    if session_ref is not None and thread_ref is not None and session_ref != thread_ref:
        raise _error(
            path, "session_ref and thread_ref must identify the same stable thread"
        )
    return session_ref or thread_ref


def _parse_time(value: Any, *, path: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _error(path, "must be an ISO-8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise _error(path, "must be a valid ISO-8601 string") from exc
    if parsed.tzinfo is None:
        raise _error(path, "must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _turn_time(turn: Mapping[str, Any], *, path: str) -> datetime | None:
    present = [
        field
        for field in ("canonical_time", "event_time", "timestamp")
        if field in turn
    ]
    if not present:
        return None
    values = [_parse_time(turn[field], path=f"{path}.{field}") for field in present]
    if any(value != values[0] for value in values[1:]):
        raise _error(path, "canonical time aliases disagree")
    return values[0]


def _turn_sequence(turn: Mapping[str, Any], *, path: str) -> int | None:
    present = [
        field for field in ("sequence", "turn_index", "ordinal") if field in turn
    ]
    if not present:
        return None
    values = [turn[field] for field in present]
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in values
    ):
        raise _error(path, "turn order must be a non-negative integer")
    if any(value != values[0] for value in values[1:]):
        raise _error(path, "turn order aliases disagree")
    return values[0]


def _ordered_thread_turns(
    rows: Sequence[tuple[int, Mapping[str, Any]]], *, thread_ref: str
) -> list[Mapping[str, Any]]:
    enriched: list[tuple[int, str, int | None, datetime | None, Mapping[str, Any]]] = []
    for input_index, turn in rows:
        path = f"turns[{input_index}]"
        turn_ref = _require_ref(
            turn.get("turn_ref"), path=f"{path}.turn_ref", expected_prefix="turn"
        )
        sequence = _turn_sequence(turn, path=path)
        event_time = _turn_time(turn, path=path)
        enriched.append((input_index, turn_ref, sequence, event_time, turn))
    sequence_presence = {
        sequence is not None for _index, _ref, sequence, _time, _turn in enriched
    }
    if len(sequence_presence) > 1:
        raise _error(thread_ref, "mixed canonical turn ordering is not allowed")
    if sequence_presence == {True}:
        ordered = sorted(enriched, key=lambda item: item[2])
        sequences = [item[2] for item in ordered]
        if len(sequences) != len(set(sequences)):
            raise _error(thread_ref, "duplicate canonical turn order")
    elif all(
        event_time is not None
        for _index, _ref, _sequence, event_time, _turn in enriched
    ):
        ordered = sorted(enriched, key=lambda item: (item[3], item[1]))
    elif len(enriched) == 1:
        ordered = enriched
    else:
        raise _error(
            thread_ref, "multiple turns require complete canonical ordering metadata"
        )
    return [turn for _index, _ref, _sequence, _time, turn in ordered]


def _turn_disposition(turn: Mapping[str, Any], *, path: str) -> str:
    values = [
        turn[field]
        for field in ("meaningfulness", "semantic_disposition")
        if field in turn
    ]
    if not values:
        raise _error(path, "meaningfulness disposition is required")
    if any(value != values[0] for value in values[1:]):
        raise _error(path, "meaningfulness aliases disagree")
    value = values[0]
    if value not in MEANINGFULNESS_DISPOSITIONS:
        raise _error(path, "unsupported meaningfulness disposition")
    return value


def derive_episode_meaningfulness(turns: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Derive review eligibility without letting gaps shrink the denominator."""

    if not turns:
        raise _error("turns", "an episode must contain at least one turn")
    meaningful: list[str] = []
    context_only: list[str] = []
    gaps: list[str] = []
    for index, turn in enumerate(turns):
        path = f"turns[{index}]"
        row = _require_mapping(turn, path=path)
        turn_ref = _require_ref(
            row.get("turn_ref"),
            path=f"{path}.turn_ref",
            expected_prefix="turn",
        )
        disposition = _turn_disposition(row, path=path)
        if disposition == "meaningful":
            meaningful.append(turn_ref)
        elif disposition == "context_only":
            context_only.append(turn_ref)
        else:
            gaps.append(turn_ref)
    if meaningful:
        disposition = "meaningful"
        review_required = True
    elif gaps:
        disposition = "meaningfulness_gap"
        review_required = False
    else:
        disposition = "review_not_required"
        review_required = False
    return {
        "disposition": disposition,
        "semantic_coverage": "gap" if gaps else "complete",
        "review_required": review_required,
        "meaningful_turn_refs": meaningful,
        "context_only_turn_refs": context_only,
        "gap_turn_refs": gaps,
    }


def _optional_ref(turn: Mapping[str, Any], field: str, *, path: str) -> str | None:
    value = turn.get(field)
    if value is None:
        return None
    prefixes = {"goal_ref": "goal", "workstream_ref": "workstream"}
    try:
        expected_prefix = prefixes[field]
    except KeyError as exc:
        raise _error(f"{path}.{field}", "has no declared reference type") from exc
    return _require_ref(value, path=f"{path}.{field}", expected_prefix=expected_prefix)


def _truthy_flag(turn: Mapping[str, Any], field: str, *, path: str) -> bool:
    value = turn.get(field, False)
    if not isinstance(value, bool):
        raise _error(f"{path}.{field}", "must be a boolean")
    return value


def _goal_change(turn: Mapping[str, Any], *, path: str) -> str | None:
    value = turn.get("goal_change")
    if value is None:
        return None
    allowed = {"completed_then_new", "continues", "new_goal", "redirected", "unknown"}
    if value not in allowed:
        raise _error(f"{path}.goal_change", "unsupported goal_change")
    return value


def boundary_candidate(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    previous_path: str = "previous",
    current_path: str = "current",
) -> dict[str, Any]:
    """Classify one adjacent boundary using only semantic continuity evidence."""

    previous_ref = _require_ref(
        previous.get("turn_ref"),
        path=f"{previous_path}.turn_ref",
        expected_prefix="turn",
    )
    current_ref = _require_ref(
        current.get("turn_ref"),
        path=f"{current_path}.turn_ref",
        expected_prefix="turn",
    )
    previous_thread = _thread_ref(previous, path=previous_path)
    current_thread = _thread_ref(current, path=current_path)
    if previous_thread != current_thread:
        raise _error(
            current_path, "episode boundaries may only be classified inside one thread"
        )

    candidate_reasons: set[str] = set()
    accepted_reasons: set[str] = set()
    previous_goal = _optional_ref(previous, "goal_ref", path=previous_path)
    current_goal = _optional_ref(current, "goal_ref", path=current_path)
    previous_workstream = _optional_ref(previous, "workstream_ref", path=previous_path)
    current_workstream = _optional_ref(current, "workstream_ref", path=current_path)
    goal_change = _goal_change(current, path=current_path)
    goals_differ = (
        previous_goal is not None
        and current_goal is not None
        and previous_goal != current_goal
    )
    workstreams_differ = (
        previous_workstream is not None
        and current_workstream is not None
        and previous_workstream != current_workstream
    )

    if goal_change == "continues" and goals_differ:
        raise _error(
            current_path,
            "goal continuity evidence conflicts with stable goal references",
        )
    if goal_change in {"new_goal", "completed_then_new"} and (
        previous_goal is not None
        and current_goal is not None
        and previous_goal == current_goal
    ):
        raise _error(
            current_path, "new-goal evidence conflicts with stable goal references"
        )
    if current.get("workstream_change") is False and workstreams_differ:
        raise _error(
            current_path,
            "workstream continuity evidence conflicts with stable workstream references",
        )
    if goal_change == "redirected" and current.get("user_redirect") is False:
        raise _error(current_path, "redirect evidence is contradictory")

    if goal_change in {"new_goal", "completed_then_new"} or goals_differ:
        accepted_reasons.add("goal_change")
    if goal_change == "completed_then_new" or (
        _truthy_flag(previous, "task_completed", path=previous_path)
        and (goal_change in {"new_goal", "completed_then_new"} or goals_differ)
    ):
        accepted_reasons.add("completed_then_new_goal")
    if goal_change == "redirected" or _truthy_flag(
        current, "user_redirect", path=current_path
    ):
        accepted_reasons.add("user_redirect")
    if (
        _truthy_flag(current, "workstream_change", path=current_path)
        or workstreams_differ
    ):
        accepted_reasons.add("workstream_change")
    if _truthy_flag(current, "repository_responsibility_change", path=current_path):
        accepted_reasons.add("repository_responsibility_change")

    previous_time = _turn_time(previous, path=previous_path)
    current_time = _turn_time(current, path=current_path)
    if previous_time is not None and current_time is not None:
        if current_time < previous_time:
            raise _error(current_path, "canonical turn time moves backwards")
        if current_time - previous_time >= SEGMENTATION_GAP:
            candidate_reasons.add("elapsed_72h_candidate")
    candidate_reasons.update(accepted_reasons)
    return {
        "left_turn_ref": previous_ref,
        "right_turn_ref": current_ref,
        "candidate_reasons": sorted(candidate_reasons),
        "accepted_boundary": bool(accepted_reasons),
        "accepted_reasons": sorted(accepted_reasons),
    }


def _minimum_confidence(values: Iterable[str]) -> str:
    normalized = list(values)
    if not normalized:
        return "high"
    if any(value not in CONFIDENCE_LEVELS for value in normalized):
        raise _error("confidence", "unsupported confidence level")
    return min(normalized, key=_CONFIDENCE_ORDER.__getitem__)


def _turn_confidence(turn: Mapping[str, Any], field: str) -> str:
    value = turn.get(field, turn.get("confidence", "high"))
    if value not in CONFIDENCE_LEVELS:
        raise _error(field, "unsupported confidence level")
    return value


def _episode_record(
    thread_ref: str,
    turns: Sequence[Mapping[str, Any]],
    *,
    boundary_before: Mapping[str, Any] | None,
    internal_candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    turn_refs = [
        _require_ref(turn.get("turn_ref"), path="turn.turn_ref", expected_prefix="turn")
        for turn in turns
    ]
    goal_refs = sorted(
        {
            value
            for turn in turns
            if (value := _optional_ref(turn, "goal_ref", path="turn")) is not None
        }
    )
    workstream_refs = sorted(
        {
            value
            for turn in turns
            if (value := _optional_ref(turn, "workstream_ref", path="turn")) is not None
        }
    )
    risk_flags: set[str] = set()
    for turn in turns:
        flags = turn.get("risk_flags", [])
        if not isinstance(flags, list) or any(flag not in RISK_FLAGS for flag in flags):
            raise _error("turn.risk_flags", "contains an unsupported risk flag")
        risk_flags.update(flags)
        if _truthy_flag(turn, "conflicting_signals", path="turn"):
            risk_flags.add("conflicting_signals")
    return {
        "session_ref": thread_ref,
        "turn_refs": turn_refs,
        "goal_refs": goal_refs,
        "workstream_refs": workstream_refs,
        "boundary_before": copy.deepcopy(boundary_before),
        "internal_boundary_candidates": copy.deepcopy(list(internal_candidates)),
        "meaningfulness": derive_episode_meaningfulness(turns),
        "risk_flags": sorted(risk_flags),
        "extraction_confidence": _minimum_confidence(
            _turn_confidence(turn, "extraction_confidence") for turn in turns
        ),
        "segmentation_confidence": _minimum_confidence(
            _turn_confidence(turn, "segmentation_confidence") for turn in turns
        ),
    }


def construct_episodes(turns: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Construct goal-continuous episodes without crossing stable threads.

    Input archive state, archive timestamps, filesystem mtimes, and paths are
    intentionally never read. A 72-hour gap is recorded as a candidate reason
    but cannot make ``accepted_boundary`` true by itself.
    """

    grouped: dict[str, list[tuple[int, Mapping[str, Any]]]] = defaultdict(list)
    seen_turns: set[str] = set()
    for index, item in enumerate(turns):
        path = f"turns[{index}]"
        turn = _require_mapping(item, path=path)
        turn_ref = _require_ref(
            turn.get("turn_ref"),
            path=f"{path}.turn_ref",
            expected_prefix="turn",
        )
        if turn_ref in seen_turns:
            raise _error(path, "duplicates a turn_ref")
        seen_turns.add(turn_ref)
        grouped[_thread_ref(turn, path=path)].append((index, turn))

    episodes: list[dict[str, Any]] = []
    for thread_ref in sorted(grouped):
        ordered = _ordered_thread_turns(grouped[thread_ref], thread_ref=thread_ref)
        if not ordered:
            continue
        current_turns: list[Mapping[str, Any]] = [ordered[0]]
        boundary_before: Mapping[str, Any] | None = None
        internal_candidates: list[Mapping[str, Any]] = []
        for position, turn in enumerate(ordered[1:], start=1):
            decision = boundary_candidate(
                ordered[position - 1],
                turn,
                previous_path=f"{thread_ref}[{position - 1}]",
                current_path=f"{thread_ref}[{position}]",
            )
            if decision["accepted_boundary"]:
                episodes.append(
                    _episode_record(
                        thread_ref,
                        current_turns,
                        boundary_before=boundary_before,
                        internal_candidates=internal_candidates,
                    )
                )
                current_turns = [turn]
                boundary_before = decision
                internal_candidates = []
            else:
                current_turns.append(turn)
                if decision["candidate_reasons"]:
                    internal_candidates.append(decision)
        episodes.append(
            _episode_record(
                thread_ref,
                current_turns,
                boundary_before=boundary_before,
                internal_candidates=internal_candidates,
            )
        )
    return episodes


def _identity_key(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        secret = bytes(value)
    else:
        secret = getattr(value, "key_bytes", None)
        if not isinstance(secret, bytes):
            raise _error("identity_key", "must expose 32 bytes of key material")
    if len(secret) != 32:
        raise _error("identity_key", "must contain exactly 32 bytes")
    return secret


def _identity_key_id(value: object, explicit_key_id: str | None) -> str:
    material_key_id = getattr(value, "key_id", None)
    derived_key_id = IdentityKey(_identity_key(value)).key_id
    if material_key_id is not None and not hmac.compare_digest(
        material_key_id, derived_key_id
    ):
        raise _error(
            "key_id", "the identity object key_id does not match its key material"
        )
    key_id = (
        explicit_key_id
        if explicit_key_id is not None
        else material_key_id or derived_key_id
    )
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise _error("key_id", "must be an identity_key_v2 reference")
    if not hmac.compare_digest(derived_key_id, key_id):
        raise _error("key_id", "does not match the supplied identity key")
    return key_id


def _framed_payload(domain: str, values: Sequence[str]) -> bytes:
    payload = bytearray(domain.encode("ascii"))
    for value in values:
        encoded = value.encode("utf-8")
        payload.extend(len(encoded).to_bytes(8, "big"))
        payload.extend(encoded)
    return bytes(payload)


def _hmac_ref(
    identity_key: object, prefix: str, domain: str, values: Sequence[str]
) -> str:
    digest = hmac.new(
        _identity_key(identity_key), _framed_payload(domain, values), hashlib.sha256
    ).hexdigest()
    return f"{prefix}:{digest}"


def derive_episode_ref(
    identity_key: object,
    earliest_turn_ref: str,
    *,
    segmentation_major_version: str | int = 2,
) -> str:
    """Derive the first-publication anchor from the then-earliest stable turn."""

    turn_ref = _require_ref(
        earliest_turn_ref,
        path="earliest_turn_ref",
        expected_prefix="turn",
    )
    return _hmac_ref(
        identity_key,
        "episode_ref_v2",
        "session-retrospective-v2/episode/initial",
        [turn_ref, str(segmentation_major_version), "initial"],
    )


def derive_episode_revision_ref(
    identity_key: object,
    episode_ref: str,
    turn_refs: Sequence[str],
    *,
    revision_metadata: Mapping[str, Any],
    revision_ordinal: int,
    lineage_kind: str,
    segmentation_major_version: str | int = 2,
    supersedes_revision_ref: str | None = None,
) -> str:
    """Derive a deterministic revision reference over all mutable metadata."""

    anchor = _require_ref(episode_ref, path="episode_ref", expected_prefix="episode")
    if not turn_refs:
        raise _error("turn_refs", "must not be empty")
    members = [
        _require_ref(ref, path="turn_refs", expected_prefix="turn") for ref in turn_refs
    ]
    if len(set(members)) != len(members):
        raise _error("turn_refs", "must not contain duplicates")
    metadata = _normalize_episode_metadata(revision_metadata, path="revision_metadata")
    if metadata["turn_refs"] != members:
        raise _error("revision_metadata.turn_refs", "must exactly match turn_refs")
    ordinal, lineage, predecessor_ref = _normalize_revision_lineage(
        revision_ordinal,
        lineage_kind,
        supersedes_revision_ref,
        path="",
    )
    predecessor = predecessor_ref or "none"
    return _hmac_ref(
        identity_key,
        "episode_revision_ref_v2",
        "session-retrospective-v2/episode/revision",
        [
            anchor,
            str(segmentation_major_version),
            str(ordinal),
            lineage,
            predecessor,
            _canonical_projection(metadata),
        ],
    )


def _canonical_projection(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as exc:
        raise _error(
            "revision_metadata", "must contain only canonical JSON values"
        ) from exc


def _is_ordered_subsequence(previous: Sequence[str], current: Sequence[str]) -> bool:
    cursor = iter(current)
    return all(
        any(candidate == expected for candidate in cursor) for expected in previous
    )


def _normalize_revision_lineage(
    revision_ordinal: Any,
    lineage_kind: Any,
    supersedes_revision_ref: Any,
    *,
    path: str,
) -> tuple[int, str, str | None]:
    prefix = f"{path}." if path else ""
    if (
        isinstance(revision_ordinal, bool)
        or not isinstance(revision_ordinal, int)
        or revision_ordinal < 1
    ):
        raise _error(f"{prefix}revision_ordinal", "must be a positive integer")
    expected_lineage = "initial" if revision_ordinal == 1 else "extension"
    if lineage_kind != expected_lineage:
        raise _error(
            f"{prefix}lineage_kind",
            "does not match revision_ordinal",
        )
    predecessor: str | None = None
    if supersedes_revision_ref is not None:
        predecessor = _require_ref(
            supersedes_revision_ref,
            path=f"{prefix}supersedes_episode_revision_ref",
            expected_prefix="episode_revision",
        )
    if (revision_ordinal == 1) != (predecessor is None):
        raise _error(
            f"{prefix}supersedes_episode_revision_ref",
            "does not match revision_ordinal",
        )
    return revision_ordinal, expected_lineage, predecessor


_EPISODE_METADATA_FIELDS = frozenset(
    {
        "session_ref",
        "turn_refs",
        "goal_refs",
        "workstream_refs",
        "boundary_before",
        "internal_boundary_candidates",
        "meaningfulness",
        "risk_flags",
        "extraction_confidence",
        "segmentation_confidence",
    }
)
_EPISODE_REVISION_FIELDS = _EPISODE_METADATA_FIELDS | {
    "schema",
    "episode_ref",
    "episode_revision_ref",
    "segmentation_major_version",
    "key_id",
    "revision_ordinal",
    "lineage_kind",
    "supersedes_episode_revision_ref",
}


def _require_exact_fields(
    value: Mapping[str, Any], *, required: set[str] | frozenset[str], path: str
) -> None:
    missing = set(required) - set(value)
    unknown = set(value) - set(required)
    if missing:
        raise _error(path, f"missing required fields: {', '.join(sorted(missing))}")
    if unknown:
        raise _error(path, f"contains unknown fields: {', '.join(sorted(unknown))}")


def _normalize_ref_list(
    value: Any,
    *,
    path: str,
    expected_prefix: str,
    minimum: int = 0,
    sort_values: bool = False,
) -> list[str]:
    if not isinstance(value, list):
        raise _error(path, "must be an array")
    refs = [
        _require_ref(item, path=f"{path}[{index}]", expected_prefix=expected_prefix)
        for index, item in enumerate(value)
    ]
    if len(refs) < minimum:
        raise _error(path, f"must contain at least {minimum} reference(s)")
    if len(refs) != len(set(refs)):
        raise _error(path, "must not contain duplicates")
    return sorted(refs) if sort_values else refs


def _normalize_boundary_candidate(
    value: Any,
    *,
    path: str,
    expected_accepted: bool,
) -> dict[str, Any]:
    row = _require_mapping(value, path=path)
    required = {
        "left_turn_ref",
        "right_turn_ref",
        "candidate_reasons",
        "accepted_boundary",
        "accepted_reasons",
    }
    _require_exact_fields(row, required=required, path=path)
    left_turn_ref = _require_ref(
        row["left_turn_ref"],
        path=f"{path}.left_turn_ref",
        expected_prefix="turn",
    )
    right_turn_ref = _require_ref(
        row["right_turn_ref"],
        path=f"{path}.right_turn_ref",
        expected_prefix="turn",
    )
    candidate_reasons = row["candidate_reasons"]
    accepted_reasons = row["accepted_reasons"]
    if not isinstance(candidate_reasons, list) or not isinstance(
        accepted_reasons, list
    ):
        raise _error(path, "boundary reasons must be arrays")
    if any(
        reason not in BOUNDARY_REASONS
        for reason in candidate_reasons + accepted_reasons
    ):
        raise _error(path, "contains an unsupported boundary reason")
    if len(candidate_reasons) != len(set(candidate_reasons)) or len(
        accepted_reasons
    ) != len(set(accepted_reasons)):
        raise _error(path, "boundary reasons must not contain duplicates")
    if not candidate_reasons:
        raise _error(path, "must contain at least one candidate reason")
    if not set(accepted_reasons) <= set(candidate_reasons):
        raise _error(path, "accepted reasons must be candidate reasons")
    accepted_boundary = row["accepted_boundary"]
    if (
        not isinstance(accepted_boundary, bool)
        or accepted_boundary != expected_accepted
    ):
        raise _error(f"{path}.accepted_boundary", f"must be {expected_accepted}")
    if accepted_boundary != bool(accepted_reasons):
        raise _error(path, "accepted_boundary must exactly match accepted_reasons")
    return {
        "left_turn_ref": left_turn_ref,
        "right_turn_ref": right_turn_ref,
        "candidate_reasons": sorted(candidate_reasons),
        "accepted_boundary": accepted_boundary,
        "accepted_reasons": sorted(accepted_reasons),
    }


def _normalize_meaningfulness(
    value: Any,
    *,
    turn_refs: Sequence[str],
    path: str,
) -> dict[str, Any]:
    row = _require_mapping(value, path=path)
    required = {
        "disposition",
        "semantic_coverage",
        "review_required",
        "meaningful_turn_refs",
        "context_only_turn_refs",
        "gap_turn_refs",
    }
    _require_exact_fields(row, required=required, path=path)
    disposition = row["disposition"]
    if disposition not in {"meaningful", "meaningfulness_gap", "review_not_required"}:
        raise _error(f"{path}.disposition", "is unsupported")
    coverage = row["semantic_coverage"]
    if coverage not in {"complete", "gap"}:
        raise _error(f"{path}.semantic_coverage", "is unsupported")
    review_required = row["review_required"]
    if not isinstance(review_required, bool):
        raise _error(f"{path}.review_required", "must be a boolean")
    categories = {
        field: _normalize_ref_list(
            row[field],
            path=f"{path}.{field}",
            expected_prefix="turn",
        )
        for field in ("meaningful_turn_refs", "context_only_turn_refs", "gap_turn_refs")
    }
    categorized = [ref for refs in categories.values() for ref in refs]
    if len(categorized) != len(set(categorized)) or set(categorized) != set(turn_refs):
        raise _error(path, "meaningfulness categories must partition episode turn_refs")
    meaningful = set(categories["meaningful_turn_refs"])
    gaps = set(categories["gap_turn_refs"])
    expected_disposition = (
        "meaningful"
        if meaningful
        else "meaningfulness_gap"
        if gaps
        else "review_not_required"
    )
    if disposition != expected_disposition:
        raise _error(f"{path}.disposition", "does not match the categorized turns")
    if review_required != bool(meaningful):
        raise _error(f"{path}.review_required", "does not match meaningful turns")
    if coverage != ("gap" if gaps else "complete"):
        raise _error(f"{path}.semantic_coverage", "does not match gap turns")
    order = {ref: index for index, ref in enumerate(turn_refs)}
    return {
        "disposition": disposition,
        "semantic_coverage": coverage,
        "review_required": review_required,
        **{
            field: sorted(refs, key=order.__getitem__)
            for field, refs in categories.items()
        },
    }


def _normalize_episode_metadata(
    value: Mapping[str, Any], *, path: str
) -> dict[str, Any]:
    source = _require_mapping(value, path=path)
    _require_exact_fields(source, required=_EPISODE_METADATA_FIELDS, path=path)
    session_ref = _require_ref(
        source["session_ref"],
        path=f"{path}.session_ref",
        expected_prefix="session",
    )
    turn_refs = _normalize_ref_list(
        source["turn_refs"],
        path=f"{path}.turn_refs",
        expected_prefix="turn",
        minimum=1,
    )
    goal_refs = _normalize_ref_list(
        source["goal_refs"],
        path=f"{path}.goal_refs",
        expected_prefix="goal",
        sort_values=True,
    )
    workstream_refs = _normalize_ref_list(
        source["workstream_refs"],
        path=f"{path}.workstream_refs",
        expected_prefix="workstream",
        sort_values=True,
    )
    boundary_before = source["boundary_before"]
    if boundary_before is not None:
        boundary_before = _normalize_boundary_candidate(
            boundary_before,
            path=f"{path}.boundary_before",
            expected_accepted=True,
        )
        if boundary_before["right_turn_ref"] != turn_refs[0]:
            raise _error(
                f"{path}.boundary_before", "must terminate at the first episode turn"
            )
    internal_value = source["internal_boundary_candidates"]
    if not isinstance(internal_value, list):
        raise _error(f"{path}.internal_boundary_candidates", "must be an array")
    internal = [
        _normalize_boundary_candidate(
            item,
            path=f"{path}.internal_boundary_candidates[{index}]",
            expected_accepted=False,
        )
        for index, item in enumerate(internal_value)
    ]
    for candidate in internal:
        if (
            candidate["left_turn_ref"] not in turn_refs
            or candidate["right_turn_ref"] not in turn_refs
        ):
            raise _error(
                f"{path}.internal_boundary_candidates",
                "must stay within episode membership",
            )
    internal.sort(
        key=lambda item: (
            turn_refs.index(item["left_turn_ref"]),
            turn_refs.index(item["right_turn_ref"]),
        )
    )
    risk_flags = source["risk_flags"]
    if not isinstance(risk_flags, list) or any(
        flag not in RISK_FLAGS for flag in risk_flags
    ):
        raise _error(f"{path}.risk_flags", "contains an unsupported risk flag")
    if len(risk_flags) != len(set(risk_flags)):
        raise _error(f"{path}.risk_flags", "must not contain duplicates")
    extraction_confidence = source["extraction_confidence"]
    segmentation_confidence = source["segmentation_confidence"]
    if (
        extraction_confidence not in CONFIDENCE_LEVELS
        or segmentation_confidence not in CONFIDENCE_LEVELS
    ):
        raise _error(path, "contains an unsupported confidence level")
    return {
        "session_ref": session_ref,
        "turn_refs": turn_refs,
        "goal_refs": goal_refs,
        "workstream_refs": workstream_refs,
        "boundary_before": boundary_before,
        "internal_boundary_candidates": internal,
        "meaningfulness": _normalize_meaningfulness(
            source["meaningfulness"],
            turn_refs=turn_refs,
            path=f"{path}.meaningfulness",
        ),
        "risk_flags": sorted(risk_flags),
        "extraction_confidence": extraction_confidence,
        "segmentation_confidence": segmentation_confidence,
    }


def _validate_episode_revision(
    value: Mapping[str, Any],
    *,
    identity_key: object,
    path: str,
) -> dict[str, Any]:
    source = _require_mapping(value, path=path)
    _require_exact_fields(source, required=_EPISODE_REVISION_FIELDS, path=path)
    if source["schema"] != EPISODE_REVISION_SCHEMA:
        raise _error(f"{path}.schema", f"must equal {EPISODE_REVISION_SCHEMA}")
    metadata = _normalize_episode_metadata(
        {field: source[field] for field in _EPISODE_METADATA_FIELDS},
        path=path,
    )
    episode_ref = _require_ref(
        source["episode_ref"],
        path=f"{path}.episode_ref",
        expected_prefix="episode",
    )
    revision_ref = _require_ref(
        source["episode_revision_ref"],
        path=f"{path}.episode_revision_ref",
        expected_prefix="episode_revision",
    )
    segmentation_version = source["segmentation_major_version"]
    if not isinstance(segmentation_version, str) or not segmentation_version:
        raise _error(
            f"{path}.segmentation_major_version",
            "must be a non-empty string",
        )
    key_id = _identity_key_id(identity_key, source["key_id"])
    revision_ordinal, lineage_kind, predecessor_ref = _normalize_revision_lineage(
        source["revision_ordinal"],
        source["lineage_kind"],
        source["supersedes_episode_revision_ref"],
        path=path,
    )
    expected_revision_ref = derive_episode_revision_ref(
        identity_key,
        episode_ref,
        metadata["turn_refs"],
        revision_metadata=metadata,
        revision_ordinal=revision_ordinal,
        lineage_kind=lineage_kind,
        segmentation_major_version=segmentation_version,
        supersedes_revision_ref=predecessor_ref,
    )
    if not hmac.compare_digest(revision_ref, expected_revision_ref):
        raise _error(
            f"{path}.episode_revision_ref",
            "does not commit the supplied revision identity and metadata",
        )
    return {
        "schema": EPISODE_REVISION_SCHEMA,
        "episode_ref": episode_ref,
        "episode_revision_ref": revision_ref,
        **metadata,
        "segmentation_major_version": segmentation_version,
        "key_id": key_id,
        "revision_ordinal": revision_ordinal,
        "lineage_kind": lineage_kind,
        "supersedes_episode_revision_ref": predecessor_ref,
    }


def create_episode_revision(
    episode: Mapping[str, Any],
    *,
    identity_key: object,
    key_id: str | None = None,
    segmentation_major_version: str | int = 2,
    previous_revision: Mapping[str, Any] | None = None,
    episode_ref: str | None = None,
) -> dict[str, Any]:
    """Create an append-only ordinary episode revision.

    Earlier backfill extends the persisted anchor. Removing a previously
    published turn requires the explicit correction protocol and is rejected.
    """

    source = _require_mapping(episode, path="episode")
    metadata = _normalize_episode_metadata(source, path="episode")
    key_id = _identity_key_id(identity_key, key_id)
    turn_refs = metadata["turn_refs"]
    segmentation_version = str(segmentation_major_version)

    predecessor_ref: str | None = None
    if previous_revision is not None:
        previous = _validate_episode_revision(
            previous_revision,
            identity_key=identity_key,
            path="previous_revision",
        )
        anchor = previous["episode_ref"]
        if episode_ref is not None and episode_ref != anchor:
            raise _error("episode_ref", "cannot replace a persisted episode anchor")
        if previous["segmentation_major_version"] != segmentation_version:
            raise _error(
                "segmentation_major_version",
                "ordinary revisions cannot change segmentation version",
            )
        previous_metadata = {
            field: previous[field] for field in _EPISODE_METADATA_FIELDS
        }
        if previous_metadata["session_ref"] != metadata["session_ref"]:
            raise _error(
                "episode.session_ref", "cannot move an ordinary revision across threads"
            )
        if previous["key_id"] != key_id:
            raise _error(
                "key_id",
                "ordinary revisions must use the persisted anchor key generation",
            )
        previous_turn_refs = previous_metadata["turn_refs"]
        if not set(previous_turn_refs) <= set(turn_refs):
            raise _error(
                "episode.turn_refs",
                "ordinary revisions cannot remove published membership",
            )
        if not _is_ordered_subsequence(previous_turn_refs, turn_refs):
            raise _error(
                "episode.turn_refs",
                "ordinary revisions cannot reorder published membership",
            )
        previous_revision_ref = previous["episode_revision_ref"]
        revision_ordinal = previous["revision_ordinal"]
        if _canonical_projection(previous_metadata) == _canonical_projection(metadata):
            return copy.deepcopy(dict(previous))
        predecessor_ref = previous_revision_ref
        revision_ordinal += 1
        lineage_kind = "extension"
    else:
        anchor = episode_ref or derive_episode_ref(
            identity_key,
            turn_refs[0],
            segmentation_major_version=segmentation_version,
        )
        _require_ref(anchor, path="episode_ref", expected_prefix="episode")
        revision_ordinal = 1
        lineage_kind = "initial"

    revision_ref = derive_episode_revision_ref(
        identity_key,
        anchor,
        turn_refs,
        revision_metadata=metadata,
        revision_ordinal=revision_ordinal,
        lineage_kind=lineage_kind,
        segmentation_major_version=segmentation_version,
        supersedes_revision_ref=predecessor_ref,
    )
    return {
        "schema": EPISODE_REVISION_SCHEMA,
        "episode_ref": anchor,
        "episode_revision_ref": revision_ref,
        **copy.deepcopy(metadata),
        "segmentation_major_version": segmentation_version,
        "key_id": key_id,
        "revision_ordinal": revision_ordinal,
        "lineage_kind": lineage_kind,
        "supersedes_episode_revision_ref": predecessor_ref,
    }


def validate_episode_revision(
    value: Mapping[str, Any],
    *,
    identity_key: object,
) -> dict[str, Any]:
    """Validate one authenticated append-only episode revision head."""

    return _validate_episode_revision(
        value,
        identity_key=identity_key,
        path="episode_revision",
    )


def derive_episode_head_set_ref(
    identity_key: object,
    source_run_ref: str,
    episode_heads: Sequence[Mapping[str, Any]],
) -> str:
    """Commit a source run and its complete unique set of episode heads."""

    run_ref = _require_ref(
        source_run_ref,
        path="source_run_ref",
        expected_prefix="run",
    )
    heads = [
        validate_episode_revision(head, identity_key=identity_key)
        for head in episode_heads
    ]
    episode_refs = [head["episode_ref"] for head in heads]
    revision_refs = [head["episode_revision_ref"] for head in heads]
    if len(episode_refs) != len(set(episode_refs)):
        raise _error("episode_heads", "contains duplicate episode anchors")
    if len(revision_refs) != len(set(revision_refs)):
        raise _error("episode_heads", "contains duplicate revision heads")
    rows = sorted(zip(episode_refs, revision_refs))
    return _hmac_ref(
        identity_key,
        "episode_head_set_ref_v2",
        "session-retrospective-v2/episode/head-set",
        [run_ref, *(item for row in rows for item in row)],
    )


def derive_episode_correction_generation(
    identity_key: object,
    predecessor_episode_refs: Sequence[str],
    successor_turn_memberships: Sequence[Sequence[str]],
    *,
    correction_ordinal: int,
    segmentation_major_version: str | int = 2,
) -> str:
    """Derive stable split/merge lineage without reusing a predecessor anchor."""

    if (
        isinstance(correction_ordinal, bool)
        or not isinstance(correction_ordinal, int)
        or correction_ordinal < 1
    ):
        raise _error("correction_ordinal", "must be a positive integer")
    predecessor_values = [
        _require_ref(ref, path="predecessor_episode_refs", expected_prefix="episode")
        for ref in predecessor_episode_refs
    ]
    if len(predecessor_values) != len(set(predecessor_values)):
        raise _error("predecessor_episode_refs", "must not contain duplicates")
    predecessors = sorted(predecessor_values)
    if not predecessors:
        raise _error("predecessor_episode_refs", "must not be empty")
    memberships: list[str] = []
    seen_members: set[str] = set()
    for membership in successor_turn_memberships:
        member_values = [
            _require_ref(ref, path="successor_turn_memberships", expected_prefix="turn")
            for ref in membership
        ]
        if len(member_values) != len(set(member_values)):
            raise _error(
                "successor_turn_memberships",
                "a successor membership contains duplicates",
            )
        refs = sorted(member_values)
        if not refs:
            raise _error(
                "successor_turn_memberships", "successor membership must not be empty"
            )
        if seen_members & set(refs):
            raise _error(
                "successor_turn_memberships", "successor memberships must not overlap"
            )
        seen_members.update(refs)
        memberships.append(",".join(refs))
    if not memberships:
        raise _error("successor_turn_memberships", "must not be empty")
    return _hmac_ref(
        identity_key,
        "episode_correction_ref_v2",
        "session-retrospective-v2/episode/correction",
        [
            str(segmentation_major_version),
            str(correction_ordinal),
            *predecessors,
            *sorted(memberships),
        ],
    )


def derive_corrected_episode_ref(
    identity_key: object,
    correction_generation_ref: str,
    successor_turn_refs: Sequence[str],
    *,
    segmentation_major_version: str | int = 2,
) -> str:
    generation = _require_ref(
        correction_generation_ref,
        path="correction_generation_ref",
        expected_prefix="episode_correction",
    )
    member_values = [
        _require_ref(ref, path="successor_turn_refs", expected_prefix="turn")
        for ref in successor_turn_refs
    ]
    if len(member_values) != len(set(member_values)):
        raise _error("successor_turn_refs", "must not contain duplicates")
    members = sorted(member_values)
    if not members:
        raise _error("successor_turn_refs", "must not be empty")
    return _hmac_ref(
        identity_key,
        "episode_ref_v2",
        "session-retrospective-v2/episode/correction-successor",
        [generation, str(segmentation_major_version), *members],
    )


def _episode_payload(head: Mapping[str, Any]) -> dict[str, Any]:
    return {field: head[field] for field in _EPISODE_METADATA_FIELDS}


def _validate_ordinary_episode_successor(
    previous: Mapping[str, Any],
    proposed: Mapping[str, Any],
    *,
    identity_key: object,
) -> None:
    expected = create_episode_revision(
        _episode_payload(proposed),
        identity_key=identity_key,
        key_id=proposed["key_id"],
        segmentation_major_version=proposed["segmentation_major_version"],
        previous_revision=previous,
        episode_ref=previous["episode_ref"],
    )
    if proposed != expected:
        raise _error(
            "episode_transition",
            "durable episode head is not a direct append-only successor",
        )


def _validate_episode_correction(
    correction: Mapping[str, Any],
    *,
    previous_by_ref: Mapping[str, Mapping[str, Any]],
    proposed_by_ref: Mapping[str, Mapping[str, Any]],
    correction_ordinal: int,
    identity_key: object,
) -> None:
    predecessor_refs = correction["predecessor_episode_refs"]
    successor_refs = correction["successor_episode_refs"]
    predecessors = [previous_by_ref[item] for item in predecessor_refs]
    successors = [proposed_by_ref[item] for item in successor_refs]
    segmentation_version = correction["segmentation_major_version"]
    predecessor_turns = {
        turn_ref for head in predecessors for turn_ref in head["turn_refs"]
    }
    successor_turns = {
        turn_ref for head in successors for turn_ref in head["turn_refs"]
    }
    if (
        any(
            head["segmentation_major_version"] != segmentation_version
            for head in (*predecessors, *successors)
        )
        or correction["correction_ordinal"] != correction_ordinal
        or len({head["session_ref"] for head in (*predecessors, *successors)}) != 1
        or predecessor_turns != successor_turns
    ):
        raise _error(
            "episode_transition",
            "episode correction conflicts with its durable predecessor state",
        )
    expected_correction_ref = derive_episode_correction_generation(
        identity_key,
        predecessor_refs,
        [head["turn_refs"] for head in successors],
        correction_ordinal=correction_ordinal,
        segmentation_major_version=segmentation_version,
    )
    if not hmac.compare_digest(correction["correction_ref"], expected_correction_ref):
        raise _error(
            "episode_transition",
            "episode correction ref does not commit its durable lineage",
        )
    for successor in successors:
        expected_episode_ref = derive_corrected_episode_ref(
            identity_key,
            expected_correction_ref,
            successor["turn_refs"],
            segmentation_major_version=segmentation_version,
        )
        if not hmac.compare_digest(successor["episode_ref"], expected_episode_ref):
            raise _error(
                "episode_transition",
                "episode correction successor does not use its derived anchor",
            )
        expected_head = create_episode_revision(
            _episode_payload(successor),
            identity_key=identity_key,
            key_id=successor["key_id"],
            segmentation_major_version=segmentation_version,
            episode_ref=expected_episode_ref,
        )
        if successor != expected_head:
            raise _error(
                "episode_transition",
                "episode correction successor must begin a new revision lineage",
            )


def validate_episode_head_transition(
    previous_heads: Sequence[Mapping[str, Any]],
    proposed_heads: Sequence[Mapping[str, Any]],
    corrections: Sequence[Mapping[str, Any]],
    *,
    correction_ordinal: int,
    identity_key: object,
) -> None:
    """Validate ordinary and explicit correction lineage for durable heads."""

    previous_by_ref = {head["episode_ref"]: head for head in previous_heads}
    proposed_by_ref = {head["episode_ref"]: head for head in proposed_heads}
    removed_refs = set(previous_by_ref) - set(proposed_by_ref)
    correction_predecessors: set[str] = set()
    correction_successors: set[str] = set()
    for correction in corrections:
        predecessors = set(correction["predecessor_episode_refs"])
        successors = set(correction["successor_episode_refs"])
        if correction_predecessors & predecessors or correction_successors & successors:
            raise _error(
                "episode_transition",
                "episode correction reuses a predecessor or successor",
            )
        if (
            predecessors - removed_refs
            or successors & set(previous_by_ref)
            or successors - set(proposed_by_ref)
        ):
            raise _error(
                "episode_transition",
                "episode correction must replace historical anchors with new anchors",
            )
        _validate_episode_correction(
            correction,
            previous_by_ref=previous_by_ref,
            proposed_by_ref=proposed_by_ref,
            correction_ordinal=correction_ordinal,
            identity_key=identity_key,
        )
        correction_predecessors.update(predecessors)
        correction_successors.update(successors)
    if correction_predecessors != removed_refs:
        raise _error(
            "episode_transition",
            "durable episode transition removes a head without correction lineage",
        )
    for episode_ref in set(previous_by_ref) & set(proposed_by_ref):
        _validate_ordinary_episode_successor(
            previous_by_ref[episode_ref],
            proposed_by_ref[episode_ref],
            identity_key=identity_key,
        )


def _iter_screen_rows(screening_results: Any) -> Iterable[Mapping[str, Any]]:
    if screening_results is None:
        return
    if isinstance(screening_results, Mapping):
        if "decisions" in screening_results:
            decisions = screening_results["decisions"]
            if not isinstance(decisions, list):
                raise _error("screening_results.decisions", "must be an array")
            for decision in decisions:
                yield _require_mapping(decision, path="screening_results.decisions")
            return
        for value in screening_results.values():
            if isinstance(value, Mapping):
                yield value
            elif isinstance(value, list):
                for item in value:
                    yield _require_mapping(item, path="screening_results")
            else:
                raise _error("screening_results", "contains an unsupported row")
        return
    if isinstance(screening_results, Sequence) and not isinstance(
        screening_results, (str, bytes)
    ):
        for item in screening_results:
            yield _require_mapping(item, path="screening_results")
        return
    raise _error("screening_results", "must be an object or array")


def _screen_state(
    screening_results: Any,
    *,
    allowed_turn_refs: set[str],
) -> tuple[set[str], dict[str, set[str]], list[dict[str, str]]]:
    reasons: set[str] = set()
    decisions_by_turn: dict[str, set[str]] = defaultdict(set)
    failed_screen = (
        isinstance(screening_results, Mapping)
        and screening_results.get("schema") == "agent_failure_v2"
        and isinstance(screening_results.get("failure_kind"), str)
    )
    rows = () if failed_screen else _iter_screen_rows(screening_results)
    for row in rows:
        turn_ref = _require_ref(
            row.get("turn_ref"),
            path="screening_result.turn_ref",
            expected_prefix="turn",
        )
        if turn_ref not in allowed_turn_refs:
            raise _error(
                "screening_result.turn_ref", "does not belong to the episode revision"
            )
        decision = row.get("decision", row.get("disposition"))
        allowed = {"high_impact", "high_impact_screen_gap", "not_high_impact"}
        if decision not in allowed:
            raise _error("screening_result.decision", "unsupported screening decision")
        decisions_by_turn[turn_ref].add(decision)
        if decision == "high_impact":
            reasons.add("high_impact_screen")
        elif decision == "high_impact_screen_gap":
            reasons.add("high_impact_screen_gap")
        risk_flags = row.get("risk_flags", [])
        if not isinstance(risk_flags, list) or any(
            flag not in RISK_FLAGS for flag in risk_flags
        ):
            raise _error(
                "screening_result.risk_flags", "contains an unsupported risk flag"
            )
        reasons.update(
            _HIGH_RISK_TO_REASON[flag]
            for flag in risk_flags
            if flag in _HIGH_RISK_TO_REASON
        )
    gaps: list[dict[str, str]] = []
    for turn_ref in sorted(allowed_turn_refs):
        decisions = decisions_by_turn[turn_ref]
        if failed_screen:
            decisions.add("high_impact_screen_gap")
            gap_reason = "screening_failure"
        elif not decisions:
            decisions.add("high_impact_screen_gap")
            gap_reason = "missing_decision"
        elif "high_impact_screen_gap" in decisions:
            gap_reason = "reported_gap"
        elif len(decisions) > 1:
            decisions.add("high_impact_screen_gap")
            gap_reason = "conflicting_decisions"
        else:
            continue
        reasons.add("high_impact_screen_gap")
        gaps.append(
            {
                "kind": "high_impact_screen_gap",
                "turn_ref": turn_ref,
                "gap_reason": gap_reason,
            }
        )
    return reasons, decisions_by_turn, gaps


def _review_high_impact_turns(review: Mapping[str, Any] | None) -> set[str]:
    if review is None:
        return set()
    records = review.get("high_impact_turns", [])
    if not isinstance(records, list):
        raise _error("review.high_impact_turns", "must be an array")
    return {
        _require_ref(
            item.get("turn_ref"),
            path="review.high_impact_turns.turn_ref",
            expected_prefix="turn",
        )
        for item in records
    }


def _review_risk_reasons(review: Mapping[str, Any] | None) -> set[str]:
    if review is None:
        return set()
    reasons: set[str] = set()
    flags = review.get("risk_flags", [])
    if not isinstance(flags, list) or any(flag not in RISK_FLAGS for flag in flags):
        raise _error("review.risk_flags", "contains an unsupported risk flag")
    reasons.update(
        _HIGH_RISK_TO_REASON[flag] for flag in flags if flag in _HIGH_RISK_TO_REASON
    )
    if review.get("second_review_recommended") is True:
        reasons.add("primary_reviewer_request")
    if review.get("conflicting_signals") is True:
        reasons.add("conflicting_signals")
    return reasons


def _review_decision_vector(review: Mapping[str, Any]) -> str:
    fields = (
        "confidence",
        "conflicting_signals",
        "disposition",
        "events",
        "evidence_refs",
        "findings",
        "high_impact_turns",
        "risk_flags",
        "second_review_recommended",
        "strengths",
    )
    return _canonical_projection({field: review[field] for field in fields})


def material_review_conflict(
    primary_review: Mapping[str, Any],
    secondary_review: Mapping[str, Any],
) -> bool:
    """Return whether two independent reviews differ on a material decision."""

    primary = validate_episode_review_result(
        _require_mapping(primary_review, path="primary_review"),
        expected_reviewer_slot="primary",
    )
    secondary = validate_episode_review_result(
        _require_mapping(secondary_review, path="secondary_review"),
        expected_reviewer_slot="secondary",
    )
    _validate_distinct_review_identity(primary, secondary)
    if primary["disposition"] != "reviewed" or secondary["disposition"] != "reviewed":
        raise _error("reviews", "material conflict requires two completed reviews")
    return _review_decision_vector(primary) != _review_decision_vector(secondary)


def _validate_distinct_review_identity(
    primary_review: Mapping[str, Any],
    secondary_review: Mapping[str, Any],
) -> None:
    for field in ("episode_ref", "episode_revision_ref"):
        if primary_review[field] != secondary_review[field]:
            raise _error(
                "secondary_review", f"{field} does not match the primary review"
            )
    if primary_review["attempt_ref"] == secondary_review["attempt_ref"]:
        raise _error(
            "secondary_review.attempt_ref", "must be distinct from the primary attempt"
        )
    if primary_review["reviewer_ref"] == secondary_review["reviewer_ref"]:
        raise _error(
            "secondary_review.reviewer_ref", "must identify an independent reviewer"
        )


def _validate_review_binding(
    review: Mapping[str, Any] | None,
    *,
    episode_ref: str,
    episode_revision_ref: str,
    turn_refs: set[str],
    expected_slot: str,
) -> dict[str, Any] | None:
    if review is None:
        return None
    row = validate_episode_review_result(
        _require_mapping(review, path=f"{expected_slot}_review"),
        allowed_turn_refs=turn_refs,
        expected_reviewer_slot=expected_slot,
    )
    if (
        row.get("episode_ref") != episode_ref
        or row.get("episode_revision_ref") != episode_revision_ref
    ):
        raise _error(
            f"{expected_slot}_review", "is not bound to the planned episode revision"
        )
    if not _review_high_impact_turns(row) <= turn_refs:
        raise _error(
            f"{expected_slot}_review.high_impact_turns",
            "contains a turn outside the episode",
        )
    return row


def _typed_review_gap(
    review: Mapping[str, Any] | None,
    *,
    reviewer_slot: str,
) -> dict[str, str] | None:
    if review is None or review["disposition"] == "reviewed":
        return None
    return {
        "kind": "episode_review_gap",
        "reviewer_slot": reviewer_slot,
        "gap_reason": review["gap_reason"],
        "attempt_ref": review["attempt_ref"],
    }


def _job(
    kind: str,
    episode_ref: str,
    episode_revision_ref: str,
    *,
    reviewer_slot: str | None,
    reasons: Iterable[str],
) -> dict[str, Any]:
    result = {
        "kind": kind,
        "episode_ref": episode_ref,
        "episode_revision_ref": episode_revision_ref,
        "reason_codes": sorted(set(reasons)),
    }
    if reviewer_slot is not None:
        result["reviewer_slot"] = reviewer_slot
    return result


def plan_episode_review_jobs(
    episode_revision: Mapping[str, Any],
    *,
    identity_key: object,
    screening_results: Any = None,
    primary_review: Mapping[str, Any] | None = None,
    secondary_review: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic risk-driven primary/secondary/adjudication plan."""

    episode = _validate_episode_revision(
        episode_revision,
        identity_key=identity_key,
        path="episode_revision",
    )
    episode_ref = episode["episode_ref"]
    revision_ref = episode["episode_revision_ref"]
    turn_refs = set(episode["turn_refs"])
    primary_review = _validate_review_binding(
        primary_review,
        episode_ref=episode_ref,
        episode_revision_ref=revision_ref,
        turn_refs=turn_refs,
        expected_slot="primary",
    )
    secondary_review = _validate_review_binding(
        secondary_review,
        episode_ref=episode_ref,
        episode_revision_ref=revision_ref,
        turn_refs=turn_refs,
        expected_slot="secondary",
    )
    if primary_review is not None and secondary_review is not None:
        _validate_distinct_review_identity(primary_review, secondary_review)
    meaningfulness = episode["meaningfulness"]
    disposition = meaningfulness["disposition"]
    primary_completed = (
        primary_review is not None and primary_review["disposition"] == "reviewed"
    )
    secondary_completed = (
        secondary_review is not None and secondary_review["disposition"] == "reviewed"
    )
    review_gaps = [
        gap
        for gap in (
            _typed_review_gap(primary_review, reviewer_slot="primary"),
            _typed_review_gap(secondary_review, reviewer_slot="secondary"),
        )
        if gap is not None
    ]

    screen_reasons, screen_decisions, screening_gaps = _screen_state(
        screening_results, allowed_turn_refs=turn_refs
    )
    episode_risks = episode["risk_flags"]
    second_reasons = set(screen_reasons)
    second_reasons.update(
        _HIGH_RISK_TO_REASON[flag]
        for flag in episode_risks
        if flag in _HIGH_RISK_TO_REASON
    )
    if episode.get("extraction_confidence") == "low":
        second_reasons.add("low_extraction_confidence")
    if episode.get("segmentation_confidence") == "low":
        second_reasons.add("low_segmentation_confidence")
    second_reasons.update(
        _review_risk_reasons(primary_review if primary_completed else None)
    )

    review_high_impact_turns = _review_high_impact_turns(
        primary_review if primary_completed else None
    ) | _review_high_impact_turns(secondary_review if secondary_completed else None)
    if review_high_impact_turns:
        second_reasons.add("high_impact_screen")
    escalation_turns = {
        turn_ref
        for turn_ref in review_high_impact_turns
        if screen_decisions.get(turn_ref) == {"not_high_impact"}
    }
    if escalation_turns:
        second_reasons.add("reviewer_escalation")

    if not second_reasons <= SECOND_REVIEW_REASONS:
        raise _error("review_plan", "contains an unsupported second-review reason")
    review_required = disposition == "meaningful"
    blocked_reason: str | None = None
    if disposition == "meaningfulness_gap":
        blocked_reason = "meaningfulness_gap"
    elif disposition == "review_not_required":
        blocked_reason = "review_not_required"
    elif screening_gaps:
        blocked_reason = "high_impact_screen_gap"
    elif len(review_gaps) > 1:
        blocked_reason = "multiple_review_gaps"
    elif review_gaps:
        blocked_reason = f"{review_gaps[0]['reviewer_slot']}_review_gap"

    adjudication_reasons: set[str] = set()
    if escalation_turns and primary_completed and secondary_completed:
        adjudication_reasons.add("reviewer_escalation")
    if (
        primary_completed
        and secondary_completed
        and material_review_conflict(primary_review, secondary_review)
    ):
        adjudication_reasons.add("material_review_conflict")
        second_reasons.add("conflicting_signals")
    second_required = review_required and bool(
        second_reasons or secondary_review is not None
    )
    adjudication_required = review_required and bool(adjudication_reasons)

    jobs: list[dict[str, Any]] = []
    review_gap_blocked = bool(review_gaps)
    if review_required and not review_gap_blocked and not primary_completed:
        jobs.append(
            _job(
                JobKind.EPISODE_REVIEWER.value,
                episode_ref,
                revision_ref,
                reviewer_slot="primary",
                reasons={"meaningful_episode"},
            )
        )
    if second_required and not review_gap_blocked and not secondary_completed:
        jobs.append(
            _job(
                JobKind.INDEPENDENT_RISK_REVIEWER.value,
                episode_ref,
                revision_ref,
                reviewer_slot="secondary",
                reasons=second_reasons,
            )
        )
    if adjudication_required and not review_gap_blocked:
        jobs.append(
            _job(
                JobKind.ADJUDICATOR.value,
                episode_ref,
                revision_ref,
                reviewer_slot=None,
                reasons=adjudication_reasons,
            )
        )

    return {
        "episode_ref": episode_ref,
        "episode_revision_ref": revision_ref,
        "review_required": review_required,
        "primary_review_completed": primary_completed,
        "secondary_review_completed": secondary_completed,
        "second_review_required": second_required,
        "adjudication_required": adjudication_required,
        "second_review_reason_codes": sorted(second_reasons),
        "adjudication_reason_codes": sorted(adjudication_reasons),
        "reviewer_escalation_turn_refs": sorted(escalation_turns),
        "high_impact_screen_gap_turn_refs": [gap["turn_ref"] for gap in screening_gaps],
        "screening_gaps": screening_gaps,
        "review_gaps": review_gaps,
        "blocked_reason": blocked_reason,
        "jobs": jobs,
    }
