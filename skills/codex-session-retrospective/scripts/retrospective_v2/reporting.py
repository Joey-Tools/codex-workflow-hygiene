"""Deterministic retained-artifact assembly for Session Retrospective v2.

This module deliberately accepts plain mappings.  The coordinator may evolve its
internal run-state types without making retained reporting depend on them.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
import copy
import datetime as dt
import hashlib
import io
import json
import math
import re
import struct
from typing import Any

if __package__:
    from .result_validation import (
        EVENT_KINDS,
        FINDING_KINDS,
        FOLLOW_UP_KINDS,
        GUIDANCE_KINDS,
        RISK_FLAGS,
        SKILL_CANDIDATE_KINDS,
        STRENGTH_KINDS,
    )
else:
    # Finalization also loads this module directly by path. Keep that existing
    # contract usable while normal package imports share the working taxonomy.
    EVENT_KINDS = frozenset(
        {
            "approval_request",
            "assumption_challenged",
            "auth_denial",
            "build_failure",
            "context_handoff",
            "explicit_blocker",
            "failed_command",
            "goal_redirect",
            "incomplete_test",
            "lint_failure",
            "retry",
            "task_completion",
            "tool_failure",
            "user_correction",
            "verification_completed",
            "verification_skipped",
        }
    )
    FINDING_KINDS = frozenset(
        {
            "approval_friction",
            "assumption_risk",
            "auth_friction",
            "conflicting_signals",
            "context_loss",
            "credential_risk",
            "destructive_action_risk",
            "incomplete_delivery",
            "instruction_injection",
            "over_exploration",
            "privacy_risk",
            "production_risk",
            "prompt_ambiguity",
            "retry_loop",
            "scope_drift",
            "under_asking",
            "unclear_handoff",
            "unsupported_claim",
            "verification_gap",
        }
    )
    FOLLOW_UP_KINDS = frozenset(
        {
            "create_skill",
            "investigate_risk",
            "repair_gap",
            "rerun_verification",
            "update_guidance",
        }
    )
    GUIDANCE_KINDS = frozenset(
        {
            "approval_handling",
            "context_management",
            "privacy_guardrail",
            "review_rigor",
            "scope_control",
            "tooling_hygiene",
            "verification",
        }
    )
    RISK_FLAGS = frozenset(
        {
            "conflicting_signals",
            "credential",
            "destructive_action",
            "high_impact_prompt",
            "low_extraction_confidence",
            "low_segmentation_confidence",
            "privacy",
            "production",
            "safety",
        }
    )
    SKILL_CANDIDATE_KINDS = frozenset(
        {
            "automation",
            "privacy_validation",
            "recovery",
            "review_orchestration",
            "source_collection",
            "workflow_hygiene",
        }
    )
    STRENGTH_KINDS = frozenset(
        {
            "bounded_exploration",
            "clear_communication",
            "complete_verification",
            "effective_clarification",
            "evidence_grounding",
            "explicit_assumptions",
            "focused_execution",
            "good_scope_control",
            "precise_handoff",
            "privacy_protection",
            "reliable_recovery",
            "safe_tool_use",
        }
    )


RETAINED_ARTIFACT_NAMES = (
    "manifest.json",
    "coverage.json",
    "episodes.jsonl",
    "turn_findings.jsonl",
    "topics.jsonl",
    "trend_report.json",
    "report.md",
    "summary.json",
)
JSON_ARTIFACT_NAMES = (
    "manifest.json",
    "coverage.json",
    "trend_report.json",
    "summary.json",
)
JSONL_ARTIFACT_NAMES = (
    "episodes.jsonl",
    "turn_findings.jsonl",
    "topics.jsonl",
)
REPORT_SECTIONS = (
    ("what_happened", "What happened"),
    ("what_worked_well", "What worked well"),
    ("noise_and_confusion", "What got noisy, slow, or confusing"),
    (
        "errors_and_verification",
        "Errors, retries, failed commands, or incomplete verification",
    ),
    (
        "collaboration_failure_modes",
        "Over-exploration, under-asking, context loss, or assumptions",
    ),
    ("safety_and_privacy", "Safety and privacy risks"),
    ("prompt_improvements", "Prompt improvements"),
    ("agents_guidance", "Durable `AGENTS.md` guidance"),
    ("skill_candidates", "Reusable Skill candidates"),
    ("follow_up_actions", "Follow-up actions"),
)
SYNTHESIS_QUESTION_IDS = (
    "what_happened",
    "what_worked_well",
    "noise_delay_confusion",
    "errors_retries_verification",
    "exploration_asking_context_assumptions",
    "safety_privacy",
    "prompt_improvements",
    "durable_guidance",
    "reusable_skills",
    "follow_up_actions",
)
_QUESTION_TO_SECTION = dict(
    zip(SYNTHESIS_QUESTION_IDS, (section_id for section_id, _title in REPORT_SECTIONS))
)
CONFIDENCE_DIMENSIONS = ("coverage", "extraction", "review", "comparability")
TURN_DISPOSITIONS = frozenset(("high_impact", "not_high_impact", "turn_review_gap"))
EPISODE_REVIEW_DISPOSITIONS = frozenset(
    ("reviewed", "review_gap", "review_not_required")
)
PUBLICATION_ROLES = frozenset(("standalone",))
RUN_MODES = frozenset(("daily", "weekly", "baseline", "session"))
FINDING_CONFIDENCE_LEVELS = frozenset(("low", "medium", "high"))
FINDING_SEVERITY_LEVELS = frozenset(("low", "medium", "high", "critical"))

_SCHEMA_VERSION = 2
_BUNDLE_DIGEST_DOMAIN = b"session-retrospective-retained-bundle-v2\x00"
MAX_RETAINED_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_RETAINED_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_JSONL_ROWS = 250_000
MAX_JSONL_ROW_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 1_000_000
MAX_SYNTHESIS_SIGNAL_EXEMPLARS = 64
_SAFE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,255}\Z")
_SAFE_KEY_RE = re.compile(r"[a-z][a-z0-9_.]{0,95}\Z")
_OPAQUE_REF_RE = re.compile(
    r"(?:[a-z][a-z0-9_]*_ref_v2|source_snapshot_v2):[0-9a-f]{64}\Z"
)
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_URL_RE = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]{0,31}://|git@)")
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_LOCAL_PATH_RE = re.compile(
    r"(?:(?<![A-Za-z0-9_])/(?!/)"
    r"[A-Za-z0-9._~+@%=-]+(?:/[A-Za-z0-9._~+@%=-]+)*|"
    r"(?:^|[\s'\"`])(?:~[/\\]|[A-Za-z]:\\)|"
    r"(?<![-A-Za-z0-9_.~+@%=/\\])"
    r"(?:\.{1,2}[/\\])?"
    r"(?:[A-Za-z0-9_.~+@%=-]+[/\\])+"
    r"[A-Za-z0-9_.~+@%=-]+"
    r"(?![A-Za-z0-9_.~+@%=-]))"
)
_SECRET_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b|"
    r"\b(?:gh[opsu]_|github_pat_|sk-)[A-Za-z0-9_-]{12,}\b|"
    r"\b(?:authorization|bearer|password|passwd|api[_-]?key)\s*[:=])"
)
_SOURCE_TEXT_MARKER_RE = re.compile(
    r"(?i)(?:\b(?:raw|original|verbatim)[ _-]+(?:prompt|request|message|input|text)\b|"
    r"\b(?:tool|command)[ _-]+(?:output|result)\b|\b(?:stdout|stderr|transcript)\b|"
    r"(?:^|\s)(?:user|assistant|system|tool)\s*:|\b(?:please|can you|could you|"
    r"would you|i need|i want|my request|your response)\b)"
)
_SOURCE_PAYLOAD_SHAPE_RE = re.compile(
    r"(?:^\s*(?:\{|\[|```|>>>|\$\s)|\b[A-Za-z_][A-Za-z0-9_]*=[^\s]+)"
)
_INTERNAL_ID_TEXT_RE = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9_]*_ref_v2:[0-9a-f]{64}\b|"
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|"
    r"\b[0-9a-f]{32,64}\b|\b(?:session|thread|conversation|run|job|attempt)"
    r"[ _-]?(?:id|ref)\s*[:=#])"
)
_FORBIDDEN_TEXT_FIELD_RE = re.compile(
    r"(?:^|_)(?:excerpt|quote|transcript|source_text|tool_output|tool_result|"
    r"stdout|stderr|original_prompt|raw_prompt|raw_text|generalized_working_text)(?:_|$)"
)
_FORBIDDEN_LOCATOR_FIELD_RE = re.compile(
    r"(?:^|_)(?:path|cwd|url|uri|email|secret|credential|password|api_key|"
    r"private_key|customer_name|person_name|repository_name|repo_name)(?:_|$)"
)
_FORBIDDEN_PROSE_FIELDS = frozenset(
    {
        "description",
        "detail",
        "label",
        "message",
        "name",
        "problem",
        "prompt",
        "prompt_rewrite",
        "recommendation",
        "rewrite",
        "summary",
        "text",
        "title",
    }
)
_ALLOWED_DIGEST_FIELDS = frozenset(
    {
        "independent_review_hash",
        "result_hash",
        "review_result_hash",
        "retained_bundle_digest_v2",
    }
)
_REVIEWED_PROSE_FIELDS = frozenset(
    {"cause", "expected_effect", "problem_statement", "rewritten_prompt"}
)
_ALLOWED_STRING_FIELDS = frozenset(
    {
        "algorithm",
        "backfill_of",
        "category_presence",
        "cause",
        "claimed_at",
        "completed_at",
        "confidence",
        "configuration_root",
        "denominator_kind",
        "detector",
        "digest",
        "disposition",
        "end",
        "expected_effect",
        "exception",
        "identity_key_id",
        "issued_at",
        "key_id",
        "kind",
        "level",
        "logical_boundary",
        "mode",
        "model",
        "outcome",
        "partition_commitment",
        "policy",
        "problem_statement",
        "publication_role",
        "provider",
        "question_id",
        "reason",
        "reasoning_effort",
        "redaction",
        "remote_host_context_helper_commitment",
        "result_hash",
        "result_schema",
        "review_disposition",
        "review_result_hash",
        "reviewer_slot",
        "rewritten_prompt",
        "schema",
        "section_id",
        "segmentation",
        "service_tier",
        "severity",
        "source_transport_schema",
        "start",
        "stage",
        "status",
        "unavailable_reason",
        "value",
        "version",
    }
)
_ALLOWED_STRING_FIELD_SUFFIXES = (
    "_algorithm",
    "_category",
    "_class",
    "_commit",
    "_confidence",
    "_coverage",
    "_disposition",
    "_era",
    "_kind",
    "_level",
    "_reason",
    "_ref",
    "_role",
    "_state",
    "_status",
    "_version",
)
_ALLOWED_STRING_LIST_FIELDS = frozenset({"artifact_inventory", "taxonomy"})
_MANIFEST_FIELDS = frozenset(
    {
        "artifact_inventory",
        "compatibility_key",
        "durable_state",
        "mode",
        "provenance",
        "publication_role",
        "retained_bundle_digest_v2",
        "retained_privacy_policy_version",
        "row_counts",
        "run_ref",
        "schema_version",
        "window",
    }
)
_COVERAGE_FIELDS = frozenset(
    {
        "coverage_complete",
        "episode_dispositions",
        "gaps",
        "meaningful_turn_refs",
        "schema_version",
        "source_units",
        "turn_dispositions",
        "turns",
    }
)
_TREND_FIELDS = frozenset(
    {
        "aggregate_counts",
        "compatibility_key",
        "confidence",
        "metrics",
        "model_eras",
        "normalized_changes",
        "policy_eras",
        "schema_version",
        "window",
    }
)
_SUMMARY_FIELDS = frozenset(
    {
        "confidence",
        "counts",
        "coverage_complete",
        "findings",
        "guidance_candidates",
        "mode",
        "model_eras",
        "normalized_change_status",
        "policy_eras",
        "report_section_count",
        "report_sections",
        "run_ref",
        "schema_version",
        "skill_candidates",
        "window",
    }
)
_AGGREGATE_COUNT_FIELDS = {
    "events": EVENT_KINDS,
    "findings": FINDING_KINDS,
    "risks": RISK_FLAGS,
    "strengths": STRENGTH_KINDS,
}
_AGGREGATE_SCALAR_FIELDS = frozenset(
    {
        "agents_guidance_candidates",
        "follow_up_actions",
        "prompt_improvements",
        "skill_candidates",
    }
)
_UNLINEAGED_SCALAR_METRIC_IDS = frozenset(
    {
        "agents_guidance_candidates",
        "follow_up_actions",
        "skill_candidates",
    }
)
_EPISODE_ROW_FIELDS = frozenset(
    {
        "episode_ref",
        "episode_revision_ref",
        "event_counts",
        "finding_counts",
        "findings",
        "lineage_kind",
        "meaningful_turn_count",
        "model_era",
        "policy_era",
        "review_provenance",
        "review_disposition",
        "review_result_hash",
        "revision_ordinal",
        "risk_counts",
        "schema_version",
        "session_ref",
        "strength_counts",
        "supersedes_episode_revision_ref",
    }
)
_TOPIC_ROW_FIELDS = frozenset(
    {
        "episode_lineage",
        "episode_refs",
        "findings",
        "model_era",
        "policy_era",
        "schema_version",
        "topic_ref",
    }
)
_TURN_ROW_BASE_FIELDS = frozenset(
    {
        "disposition",
        "episode_ref",
        "model_era",
        "policy_era",
        "schema_version",
        "turn_ref",
    }
)
_TURN_REWRITE_FIELDS = frozenset(
    {
        "cause",
        "confidence",
        "evidence_refs",
        "expected_effect",
        "problem_statement",
        "rewritten_prompt",
    }
)


class RetainedReportingError(ValueError):
    """Base error for retained assembly and validation failures."""


class RetainedPrivacyError(RetainedReportingError):
    """Raised when retained data crosses the language/privacy firewall."""


class RetainedInventoryError(RetainedReportingError):
    """Raised when the eight-artifact inventory is incomplete or inconsistent."""


def canonical_json_bytes(value: Any) -> bytes:
    """Encode one JSON value with the canonical v2 representation."""

    normalized = _normalize_value(value, path="$")
    try:
        encoded = json.dumps(
            normalized,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise RetainedReportingError(
            f"value is not canonically JSON encodable: {exc}"
        ) from exc
    return (encoded + "\n").encode("ascii")


def canonical_jsonl_bytes(rows: Iterable[Mapping[str, Any]]) -> bytes:
    """Encode canonical JSONL without a blank sentinel row."""

    return b"".join(canonical_json_bytes(row) for row in rows)


def _normalize_value(value: Any, *, path: str) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RetainedReportingError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise RetainedReportingError(
                    f"{path} contains a non-string mapping key"
                )
            if key in result:
                raise RetainedReportingError(f"{path} contains duplicate key {key!r}")
            result[key] = _normalize_value(item, path=f"{path}.{key}")
        return dict(sorted(result.items()))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _normalize_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    raise RetainedReportingError(
        f"{path} contains unsupported value type {type(value).__name__}"
    )


def _ordered_set(values: Iterable[Any], *, path: str) -> list[Any]:
    keyed: dict[bytes, Any] = {}
    for value in values:
        normalized = _normalize_value(value, path=path)
        key = canonical_json_bytes(normalized)
        if key in keyed:
            raise RetainedReportingError(f"{path} contains a duplicate value")
        keyed[key] = normalized
    return [keyed[key] for key in sorted(keyed)]


def _sort_unordered_fields(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return {
            child_key: _sort_unordered_fields(child_value, key=child_key)
            for child_key, child_value in sorted(value.items())
        }
    if isinstance(value, list):
        items = [_sort_unordered_fields(item) for item in value]
        if key and key.endswith(("_refs", "_codes", "_eras")):
            return _ordered_set(items, path=key)
        return items
    return value


def _validate_safe_key(key: str, *, path: str, value: Any) -> None:
    if not _SAFE_KEY_RE.fullmatch(key):
        raise RetainedPrivacyError(
            f"{path} has a noncanonical retained field name: {key!r}"
        )
    lowered = key.lower()
    policy_key = lowered.replace(".", "_")
    if _FORBIDDEN_TEXT_FIELD_RE.search(policy_key):
        raise RetainedPrivacyError(f"{path}.{key} is a forbidden source-text field")
    if _FORBIDDEN_LOCATOR_FIELD_RE.search(policy_key):
        raise RetainedPrivacyError(
            f"{path}.{key} is a forbidden locator or identity field"
        )
    if lowered in _FORBIDDEN_PROSE_FIELDS and not (
        lowered == "prompt" and isinstance(value, Mapping)
    ):
        raise RetainedPrivacyError(
            f"{path}.{key} is arbitrary prose; use a reviewed template_id"
        )
    if policy_key.startswith("raw_") and not isinstance(
        value, (int, float, bool, type(None))
    ):
        raise RetainedPrivacyError(
            f"{path}.{key} may retain only an aggregate raw measurement"
        )
    if (
        lowered.endswith(("_hash", "_digest", "_merkle_root"))
        and lowered not in _ALLOWED_DIGEST_FIELDS
    ):
        raise RetainedPrivacyError(
            f"{path}.{key} must be an opaque field-scoped reference, not a plain digest"
        )
    if isinstance(value, str):
        in_typed_slots = path.endswith(".slots") or ".slots." in path
        if (
            not in_typed_slots
            and lowered not in _ALLOWED_STRING_FIELDS
            and not lowered.endswith(_ALLOWED_STRING_FIELD_SUFFIXES)
        ):
            raise RetainedPrivacyError(
                f"{path}.{key} is not a reviewed string field; use a typed template slot or closed taxonomy field"
            )
        if lowered.endswith("_ref") and value != "configuration_ref_unavailable":
            if not _OPAQUE_REF_RE.fullmatch(value):
                raise RetainedPrivacyError(
                    f"{path}.{key} must contain an opaque v2 reference"
                )
        if lowered == "backfill_of" and not _OPAQUE_REF_RE.fullmatch(value):
            raise RetainedPrivacyError(
                f"{path}.{key} must contain an opaque v2 reference"
            )
    if isinstance(value, list) and any(isinstance(item, str) for item in value):
        if lowered not in _ALLOWED_STRING_LIST_FIELDS and not lowered.endswith(
            ("_codes", "_eras", "_flags", "_kinds", "_refs")
        ):
            raise RetainedPrivacyError(
                f"{path}.{key} is not an allowed closed string-vector field"
            )
        if lowered.endswith("_refs"):
            for item in value:
                if not isinstance(item, str) or not _OPAQUE_REF_RE.fullmatch(item):
                    raise RetainedPrivacyError(
                        f"{path}.{key} must contain only opaque v2 references"
                    )


def _validate_safe_string(value: str, *, path: str) -> None:
    if not value:
        raise RetainedPrivacyError(f"{path} contains an empty retained string")
    if not value.isascii():
        raise RetainedPrivacyError(f"{path} contains non-ASCII retained text")
    if len(value) > 256:
        raise RetainedPrivacyError(f"{path} exceeds the retained scalar length limit")
    if "\n" in value or "\r" in value or "\t" in value:
        raise RetainedPrivacyError(f"{path} contains multiline or tab-delimited text")
    if any(
        (_URL_RE.search(value), _EMAIL_RE.search(value), _LOCAL_PATH_RE.search(value))
    ):
        raise RetainedPrivacyError(
            f"{path} contains a URL, email address, or local path"
        )
    if _SECRET_RE.search(value):
        raise RetainedPrivacyError(f"{path} contains credential-shaped material")
    if not _SAFE_TOKEN_RE.fullmatch(value):
        raise RetainedPrivacyError(
            f"{path} is arbitrary retained prose; use a reviewed template token"
        )


def _validate_reviewed_prose(value: Any, *, path: str) -> None:
    if not isinstance(value, str) or not value:
        raise RetainedPrivacyError(f"{path} must contain reviewed retained text")
    if not value.isascii():
        raise RetainedPrivacyError(f"{path} contains non-ASCII retained text")
    if len(value) > 2048:
        raise RetainedPrivacyError(f"{path} exceeds the reviewed text limit")
    if any(character in value for character in "\r\n\t"):
        raise RetainedPrivacyError(f"{path} contains multiline reviewed text")
    if any(
        (_URL_RE.search(value), _EMAIL_RE.search(value), _LOCAL_PATH_RE.search(value))
    ):
        raise RetainedPrivacyError(
            f"{path} contains a URL, email address, or local path"
        )
    if _SECRET_RE.search(value):
        raise RetainedPrivacyError(f"{path} contains credential-shaped material")
    if (
        _SOURCE_TEXT_MARKER_RE.search(value)
        or _SOURCE_PAYLOAD_SHAPE_RE.search(value)
        or _INTERNAL_ID_TEXT_RE.search(value)
    ):
        raise RetainedPrivacyError(
            f"{path} violates the derived-summary retained content policy"
        )


def validate_retained_value(value: Any, *, path: str = "$") -> None:
    """Validate the strict structured retained-language subset."""

    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RetainedPrivacyError(f"{path} contains a non-finite number")
        return
    if isinstance(value, str):
        _validate_safe_string(value, path=path)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RetainedPrivacyError(f"{path} contains a non-string field name")
            _validate_safe_key(key, path=path, value=item)
            child_path = f"{path}.{key}"
            if key in _REVIEWED_PROSE_FIELDS:
                _validate_reviewed_prose(item, path=child_path)
            else:
                validate_retained_value(item, path=child_path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_retained_value(item, path=f"{path}[{index}]")
        return
    raise RetainedPrivacyError(
        f"{path} contains unsupported retained type {type(value).__name__}"
    )


def _require_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RetainedReportingError(f"{label} must be a mapping")
    return value


def _require_rows(value: Any, *, label: str) -> Sequence[Any]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise RetainedReportingError(f"{label} must be a sequence of mappings")
    return value


def _nonnegative_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RetainedReportingError(f"{label} must be a non-negative integer")
    return value


def _optional_count(
    mapping: Mapping[str, Any], keys: Sequence[str], *, default: int, label: str
) -> int:
    for key in keys:
        if key in mapping:
            return _nonnegative_int(mapping[key], label=f"{label}.{key}")
    return default


def _normalize_window(value: Any, *, label: str = "run_state.window") -> dict[str, str]:
    mapping = _require_mapping(value, label=label)
    try:
        start = _normalize_timestamp(mapping["start"], label=f"{label}.start")
        end = _normalize_timestamp(mapping["end"], label=f"{label}.end")
    except KeyError as exc:
        raise RetainedReportingError(f"{label} is missing {exc.args[0]!r}") from exc
    if _parse_timestamp(start) >= _parse_timestamp(end):
        raise RetainedReportingError(f"{label} must be a non-empty half-open interval")
    return {"end": end, "start": start}


def _validate_prior_window(
    prior_window: Mapping[str, Any], current_window: Mapping[str, str]
) -> None:
    if _parse_timestamp(str(prior_window["end"])) > _parse_timestamp(
        current_window["start"]
    ):
        raise RetainedInventoryError(
            "prior period window must be strictly earlier and non-overlapping with "
            "the current window"
        )


def _parse_timestamp(value: str) -> dt.datetime:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _normalize_timestamp(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise RetainedReportingError(f"{label} must be an ISO-8601 string")
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            parsed = dt.datetime.fromisoformat(value).replace(tzinfo=dt.timezone.utc)
        else:
            parsed = _parse_timestamp(value)
    except ValueError as exc:
        raise RetainedReportingError(f"{label} must be an ISO-8601 timestamp") from exc
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _record_rows(
    value: Any,
    *,
    label: str,
    ref_key: str,
    disposition_key: str | None = None,
    dispositions: frozenset[str] | None = None,
    row_kind: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw_row in enumerate(_require_rows(value, label=label)):
        mapping = _require_mapping(raw_row, label=f"{label}[{index}]")
        row = _sort_unordered_fields(
            _normalize_value(mapping, path=f"{label}[{index}]")
        )
        if row_kind in {"episode", "topic"}:
            if "findings" not in row:
                raise RetainedInventoryError(
                    f"{label}[{index}] is missing exact finding evidence"
                )
            row["findings"] = _finding_records(
                row.get("findings"),
                label=f"{label}[{index}].findings",
            )
        row.setdefault("schema_version", _SCHEMA_VERSION)
        if row["schema_version"] != _SCHEMA_VERSION:
            raise RetainedReportingError(
                f"{label}[{index}].schema_version must be {_SCHEMA_VERSION}"
            )
        ref = row.get(ref_key)
        if not isinstance(ref, str):
            raise RetainedReportingError(
                f"{label}[{index}] is missing string {ref_key}"
            )
        _validate_safe_string(ref, path=f"{label}[{index}].{ref_key}")
        if ref in seen:
            raise RetainedInventoryError(
                f"{label} contains duplicate {ref_key} {ref!r}"
            )
        seen.add(ref)
        if disposition_key is not None:
            disposition = row.get(disposition_key)
            if disposition not in (dispositions or frozenset()):
                raise RetainedReportingError(
                    f"{label}[{index}].{disposition_key} has unsupported value {disposition!r}"
                )
        validate_retained_value(row, path=f"{label}[{index}]")
        _validate_retained_row_schema(
            row,
            row_kind=row_kind,
            label=f"{label}[{index}]",
        )
        if row_kind == "episode" and row["finding_counts"] != dict(
            sorted(Counter(item["kind"] for item in row["findings"]).items())
        ):
            raise RetainedInventoryError(
                f"{label}[{index}].finding_counts does not match exact findings"
            )
        rows.append(row)
    rows.sort(key=lambda row: str(row[ref_key]))
    return rows


def _validate_retained_row_schema(
    row: Mapping[str, Any],
    *,
    row_kind: str,
    label: str,
) -> None:
    if row_kind == "episode":
        expected = _EPISODE_ROW_FIELDS
    elif row_kind == "topic":
        expected = _TOPIC_ROW_FIELDS
    elif row_kind == "turn":
        expected = _TURN_ROW_BASE_FIELDS
        if row.get("disposition") == "high_impact":
            expected |= _TURN_REWRITE_FIELDS
    else:
        raise RetainedReportingError(f"unknown retained row kind {row_kind!r}")
    if set(row) != expected:
        missing = sorted(expected - set(row))
        unknown = sorted(set(row) - expected)
        raise RetainedInventoryError(
            f"{label} has an unexpected closed field set; missing={missing}, unknown={unknown}"
        )
    if row_kind in {"episode", "topic"}:
        normalized = _finding_records(row["findings"], label=f"{label}.findings")
        if row["findings"] != normalized:
            raise RetainedInventoryError(f"{label}.findings is not canonically ordered")
    if row_kind == "episode" and (
        not isinstance(row["session_ref"], str)
        or not row["session_ref"].startswith("session_ref_v2:")
        or _OPAQUE_REF_RE.fullmatch(row["session_ref"]) is None
    ):
        raise RetainedInventoryError(f"{label}.session_ref is not an opaque session")
    if row_kind == "episode":
        revision_ref = row["episode_revision_ref"]
        predecessor_ref = row["supersedes_episode_revision_ref"]
        ordinal = row["revision_ordinal"]
        lineage_kind = row["lineage_kind"]
        if (
            not isinstance(revision_ref, str)
            or not revision_ref.startswith("episode_revision_ref_v2:")
            or _OPAQUE_REF_RE.fullmatch(revision_ref) is None
        ):
            raise RetainedInventoryError(
                f"{label}.episode_revision_ref is not an opaque revision"
            )
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
            raise RetainedInventoryError(
                f"{label}.revision_ordinal must be a positive integer"
            )
        if lineage_kind == "initial":
            if ordinal != 1 or predecessor_ref is not None:
                raise RetainedInventoryError(
                    f"{label} has invalid initial revision lineage"
                )
        elif lineage_kind == "extension":
            if (
                ordinal < 2
                or not isinstance(predecessor_ref, str)
                or not predecessor_ref.startswith("episode_revision_ref_v2:")
                or _OPAQUE_REF_RE.fullmatch(predecessor_ref) is None
            ):
                raise RetainedInventoryError(
                    f"{label} has invalid supersession lineage"
                )
        else:
            raise RetainedInventoryError(f"{label}.lineage_kind is unsupported")
        provenance = _review_provenance_records(
            row["review_provenance"],
            label=f"{label}.review_provenance",
        )
        if row["review_provenance"] != provenance:
            raise RetainedInventoryError(
                f"{label}.review_provenance is not canonically ordered"
            )
        review_hash = row["review_result_hash"]
        if row["review_disposition"] == "reviewed":
            if (
                not isinstance(review_hash, str)
                or _HEX_64_RE.fullmatch(review_hash) is None
                or review_hash not in {item["result_hash"] for item in provenance}
            ):
                raise RetainedInventoryError(
                    f"{label}.review_result_hash lacks reviewer provenance"
                )
        elif review_hash is not None or provenance:
            raise RetainedInventoryError(
                f"{label} cannot retain review provenance without a reviewed result"
            )
    if row_kind == "turn" and row.get("disposition") == "high_impact":
        evidence_refs = row["evidence_refs"]
        if (
            not isinstance(evidence_refs, list)
            or not evidence_refs
            or evidence_refs != sorted(set(evidence_refs))
            or any(
                not isinstance(value, str)
                or not value.startswith("evidence_ref_v2:")
                or _OPAQUE_REF_RE.fullmatch(value) is None
                for value in evidence_refs
            )
        ):
            raise RetainedInventoryError(
                f"{label}.evidence_refs must contain canonical opaque evidence"
            )
        if row["confidence"] not in FINDING_CONFIDENCE_LEVELS:
            raise RetainedInventoryError(
                f"{label}.confidence is not a closed confidence level"
            )
    if row_kind == "topic":
        lineage = _episode_lineage_records(
            row["episode_lineage"],
            label=f"{label}.episode_lineage",
        )
        if row["episode_lineage"] != lineage or {
            item["episode_ref"] for item in lineage
        } != set(row["episode_refs"]):
            raise RetainedInventoryError(
                f"{label}.episode_lineage must canonically cover episode_refs"
            )


def _review_provenance_records(value: Any, *, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    expected_fields = {
        "attempt_ref",
        "job_kind",
        "result_hash",
        "result_schema",
        "reviewer_ref",
        "reviewer_slot",
    }
    schemas = {
        "adjudicator": "episode_review_adjudication_result_v2",
        "episode_reviewer": "episode_review_result_v2",
        "independent_risk_reviewer": "episode_review_result_v2",
    }
    slots = {
        "adjudicator": "adjudicator",
        "episode_reviewer": "primary",
        "independent_risk_reviewer": "secondary",
    }
    for index, raw in enumerate(_require_rows(value, label=label)):
        row = dict(_require_mapping(raw, label=f"{label}[{index}]"))
        if set(row) != expected_fields:
            raise RetainedInventoryError(
                f"{label}[{index}] has an unexpected closed field set"
            )
        kind = row["job_kind"]
        if (
            kind not in schemas
            or row["result_schema"] != schemas[kind]
            or row["reviewer_slot"] != slots[kind]
        ):
            raise RetainedInventoryError(
                f"{label}[{index}] has inconsistent reviewer provenance"
            )
        for field, prefix in (
            ("attempt_ref", "attempt_ref_v2:"),
            ("reviewer_ref", "reviewer_ref_v2:"),
        ):
            item = row[field]
            if (
                not isinstance(item, str)
                or not item.startswith(prefix)
                or _OPAQUE_REF_RE.fullmatch(item) is None
            ):
                raise RetainedInventoryError(
                    f"{label}[{index}].{field} is not an opaque reference"
                )
        if (
            not isinstance(row["result_hash"], str)
            or _HEX_64_RE.fullmatch(row["result_hash"]) is None
        ):
            raise RetainedInventoryError(
                f"{label}[{index}].result_hash is not lowercase SHA-256"
            )
        rows.append(row)
    rows.sort(key=lambda item: (item["job_kind"], item["attempt_ref"]))
    if len({item["attempt_ref"] for item in rows}) != len(rows):
        raise RetainedInventoryError(f"{label} duplicates a review attempt")
    return rows


def _finding_records(value: Any, *, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(_require_rows(value, label=label)):
        row = _require_mapping(raw, label=f"{label}[{index}]")
        allowed_fields = {"confidence", "evidence_refs", "kind", "severity"}
        if set(row) not in (
            {"confidence", "evidence_refs", "kind"},
            allowed_fields,
        ):
            raise RetainedInventoryError(
                f"{label}[{index}] has an unexpected closed field set"
            )
        kind = row.get("kind")
        confidence = row.get("confidence")
        severity = row.get("severity")
        if kind not in FINDING_KINDS:
            raise RetainedInventoryError(
                f"{label}[{index}].kind is not in the closed finding taxonomy"
            )
        if confidence not in FINDING_CONFIDENCE_LEVELS:
            raise RetainedInventoryError(f"{label}[{index}].confidence is not closed")
        if severity is not None and severity not in FINDING_SEVERITY_LEVELS:
            raise RetainedInventoryError(f"{label}[{index}].severity is not closed")
        evidence_refs = row.get("evidence_refs")
        if (
            not isinstance(evidence_refs, list)
            or not evidence_refs
            or evidence_refs != sorted(set(evidence_refs))
            or any(
                not isinstance(item, str) or _OPAQUE_REF_RE.fullmatch(item) is None
                for item in evidence_refs
            )
        ):
            raise RetainedInventoryError(
                f"{label}[{index}].evidence_refs must be exact opaque references"
            )
        normalized = {
            "confidence": confidence,
            "evidence_refs": list(evidence_refs),
            "kind": kind,
        }
        if severity is not None:
            normalized["severity"] = severity
        validate_retained_value(normalized, path=f"{label}[{index}]")
        rows.append(normalized)
    rows.sort(key=canonical_json_bytes)
    return rows


def _unique_finding_records(
    values: Iterable[Mapping[str, Any]],
    *,
    label: str,
) -> list[dict[str, Any]]:
    normalized = _finding_records(list(values), label=label)
    by_value = {canonical_json_bytes(item): item for item in normalized}
    return [by_value[key] for key in sorted(by_value)]


def _validated_synthesis_signal_commitments(
    value: Any,
) -> dict[str, dict[str, Any]] | None:
    if value is None:
        return None
    commitments = _require_mapping(
        value,
        label="review_data.synthesis.signal_commitments",
    )
    if set(commitments) != {"events", "findings", "strengths"}:
        raise RetainedInventoryError(
            "synthesis signal commitments have an unexpected closed field set"
        )
    validated: dict[str, dict[str, Any]] = {}
    for field in ("events", "findings", "strengths"):
        row = _require_mapping(
            commitments[field],
            label=f"review_data.synthesis.signal_commitments.{field}",
        )
        if set(row) != {"canonical_count", "canonical_hash"}:
            raise RetainedInventoryError(
                f"synthesis {field} commitment has an unexpected closed field set"
            )
        count = _nonnegative_int(
            row["canonical_count"],
            label=f"synthesis.signal_commitments.{field}.canonical_count",
        )
        digest = row["canonical_hash"]
        if not isinstance(digest, str) or _HEX_64_RE.fullmatch(digest) is None:
            raise RetainedInventoryError(
                f"synthesis {field} commitment has an invalid canonical hash"
            )
        validated[field] = {
            "canonical_count": count,
            "canonical_hash": digest,
        }
    return validated


def _finding_signal_commitment(
    findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    canonical_values = sorted(
        {
            json.dumps(
                finding,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            for finding in findings
        }
    )
    encoded = json.dumps(
        canonical_values,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "canonical_count": len(canonical_values),
        "canonical_hash": hashlib.sha256(encoded).hexdigest(),
    }


def _bounded_finding_exemplars(
    findings: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    values = {
        json.dumps(
            finding,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ): copy.deepcopy(dict(finding))
        for finding in findings
    }
    selected = [
        value
        for _canonical, value in sorted(
            values.items(),
            key=lambda item: (
                0 if item[1].get("severity") in {"high", "critical"} else 1,
                item[0],
            ),
        )[:MAX_SYNTHESIS_SIGNAL_EXEMPLARS]
    ]
    return _finding_records(selected, label="global.expected_finding_exemplars")


def _episode_lineage_records(value: Any, *, label: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen_episodes: set[str] = set()
    for index, raw in enumerate(_require_rows(value, label=label)):
        row = _require_mapping(raw, label=f"{label}[{index}]")
        if set(row) != {"episode_ref", "session_ref"}:
            raise RetainedInventoryError(
                f"{label}[{index}] has an unexpected closed field set"
            )
        episode_ref = row.get("episode_ref")
        session_ref = row.get("session_ref")
        if (
            not isinstance(episode_ref, str)
            or not episode_ref.startswith("episode_ref_v2:")
            or _OPAQUE_REF_RE.fullmatch(episode_ref) is None
            or not isinstance(session_ref, str)
            or not session_ref.startswith("session_ref_v2:")
            or _OPAQUE_REF_RE.fullmatch(session_ref) is None
        ):
            raise RetainedInventoryError(
                f"{label}[{index}] must contain opaque episode/session refs"
            )
        if episode_ref in seen_episodes:
            raise RetainedInventoryError(f"{label}[{index}] duplicates an episode")
        seen_episodes.add(episode_ref)
        rows.append({"episode_ref": episode_ref, "session_ref": session_ref})
    rows.sort(key=lambda item: (item["episode_ref"], item["session_ref"]))
    return rows


def _durable_candidate_records(
    value: Any,
    *,
    label: str,
    allowed_kinds: frozenset[str],
    episodes_by_ref: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if value is None or isinstance(value, Mapping):
        return []
    candidates: list[dict[str, Any]] = []
    for index, raw in enumerate(_require_rows(value, label=label)):
        item_label = f"{label}[{index}]"
        candidate = _require_mapping(raw, label=item_label)
        required = {"confidence", "episode_lineage", "exception", "kind"}
        optional = {"independent_review_hash"}
        if not required <= set(candidate) or set(candidate) - required - optional:
            raise RetainedInventoryError(
                f"{item_label} has an unexpected closed field set"
            )
        kind = candidate.get("kind")
        confidence = candidate.get("confidence")
        exception = candidate.get("exception")
        if kind not in allowed_kinds:
            raise RetainedInventoryError(f"{item_label}.kind is not closed")
        if confidence not in {"low", "medium", "high"}:
            raise RetainedInventoryError(f"{item_label}.confidence is not closed")
        if exception not in {"high_severity_safety", "none"}:
            raise RetainedInventoryError(f"{item_label}.exception is not closed")
        lineage = _episode_lineage_records(
            candidate["episode_lineage"],
            label=f"{item_label}.episode_lineage",
        )
        sessions: set[str] = set()
        for row in lineage:
            episode = episodes_by_ref.get(row["episode_ref"])
            if episode is None or episode.get("session_ref") != row["session_ref"]:
                raise RetainedInventoryError(
                    f"{item_label}.episode_lineage is not in retained episodes"
                )
            sessions.add(row["session_ref"])
        if exception == "none" and (len(lineage) < 3 or len(sessions) < 2):
            raise RetainedInventoryError(
                f"{item_label} lacks three episodes across two sessions"
            )
        review_hash = candidate.get("independent_review_hash")
        if exception == "high_severity_safety":
            if (
                not isinstance(review_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", review_hash) is None
            ):
                raise RetainedInventoryError(
                    f"{item_label} lacks its independent review hash"
                )
        elif review_hash is not None:
            raise RetainedInventoryError(
                f"{item_label} has an inapplicable independent review hash"
            )
        normalized = {
            "confidence": confidence,
            "episode_lineage": lineage,
            "exception": exception,
            "kind": kind,
        }
        if review_hash is not None:
            normalized["independent_review_hash"] = review_hash
        validate_retained_value(normalized, path=item_label)
        candidates.append(normalized)
    candidates.sort(key=canonical_json_bytes)
    return candidates


def _expected_topic_findings(
    topic: Mapping[str, Any],
    episodes_by_ref: Mapping[str, Mapping[str, Any]],
    *,
    label: str,
) -> list[dict[str, Any]]:
    episode_refs = topic.get("episode_refs")
    if not isinstance(episode_refs, list):
        raise RetainedInventoryError(f"{label}.episode_refs must be an array")
    try:
        findings = [
            finding
            for episode_ref in episode_refs
            for finding in episodes_by_ref[episode_ref]["findings"]
        ]
    except (KeyError, TypeError) as exc:
        raise RetainedInventoryError(
            f"{label} cannot resolve exact episode finding evidence"
        ) from exc
    return _finding_records(findings, label=f"{label}.expected_findings")


def _expected_global_findings(
    episodes: Sequence[Mapping[str, Any]],
    topics: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    source_rows = topics if topics else episodes
    return _unique_finding_records(
        (finding for row in source_rows for finding in row["findings"]),
        label="global.expected_findings",
    )


def _count_map(
    value: Any,
    *,
    label: str,
    allowed: frozenset[str] | None = None,
) -> dict[str, int]:
    if value is None:
        return {}
    mapping = _require_mapping(value, label=label)
    counts: dict[str, int] = {}
    for key, raw_count in mapping.items():
        if not isinstance(key, str):
            raise RetainedReportingError(f"{label} contains a non-string category")
        _validate_safe_string(key, path=f"{label}.{key}")
        if allowed is not None and key not in allowed:
            raise RetainedInventoryError(
                f"{label} contains unsupported category {key!r}"
            )
        counts[key] = _nonnegative_int(raw_count, label=f"{label}.{key}")
    return dict(sorted(counts.items()))


def _aggregate_row_counts(
    rows: Sequence[Mapping[str, Any]],
    field: str,
    *,
    allowed: frozenset[str],
) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for index, row in enumerate(rows):
        for key, count in _count_map(
            row.get(field),
            label=f"rows[{index}].{field}",
            allowed=allowed,
        ).items():
            counter[key] += count
    return dict(sorted(counter.items()))


def _meaningful_episode_rows(
    episodes: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    return [
        row
        for row in episodes
        if row.get("review_disposition") != "review_not_required"
    ]


def _canonical_row_aggregates(
    episodes: Sequence[Mapping[str, Any]],
    turn_findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    meaningful_episodes = _meaningful_episode_rows(episodes)
    return {
        "events": _aggregate_row_counts(
            meaningful_episodes,
            "event_counts",
            allowed=EVENT_KINDS,
        ),
        "findings": _aggregate_row_counts(
            meaningful_episodes,
            "finding_counts",
            allowed=FINDING_KINDS,
        ),
        "prompt_improvements": sum(
            row.get("disposition") == "high_impact" for row in turn_findings
        ),
        "risks": _aggregate_row_counts(
            meaningful_episodes,
            "risk_counts",
            allowed=RISK_FLAGS,
        ),
        "strengths": _aggregate_row_counts(
            meaningful_episodes,
            "strength_counts",
            allowed=STRENGTH_KINDS,
        ),
    }


def _category_counts(
    value: Any,
    *,
    label: str,
    allowed: frozenset[str],
) -> dict[str, int]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return _count_map(value, label=label, allowed=allowed)
    counter: Counter[str] = Counter()
    for index, item in enumerate(_require_rows(value, label=label)):
        if isinstance(item, str):
            category = item
        else:
            mapping = _require_mapping(item, label=f"{label}[{index}]")
            category = mapping.get("category", mapping.get("kind"))
        if not isinstance(category, str):
            raise RetainedReportingError(
                f"{label}[{index}] needs a string category or kind"
            )
        _validate_safe_string(category, path=f"{label}[{index}].category")
        if category not in allowed:
            raise RetainedInventoryError(
                f"{label}[{index}] has unsupported category {category!r}"
            )
        counter[category] += 1
    return dict(sorted(counter.items()))


def _synthesis_mapping(review_data: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidate = review_data.get("synthesis")
    if candidate is None and "question_answers" in review_data:
        candidate = review_data
    if candidate is None:
        return None
    return _require_mapping(candidate, label="review_data.synthesis")


def _review_value(
    review_data: Mapping[str, Any],
    synthesis: Mapping[str, Any] | None,
    *keys: str,
) -> Any:
    for key in keys:
        if key in review_data:
            return review_data[key]
    if synthesis is not None:
        for key in keys:
            if key in synthesis:
                return synthesis[key]
    return None


def _review_category_counts(
    review_data: Mapping[str, Any],
    synthesis: Mapping[str, Any] | None,
    episodes: Sequence[Mapping[str, Any]],
    *,
    singular: str,
    row_field: str,
    allowed: frozenset[str],
) -> dict[str, int]:
    row_counts = _aggregate_row_counts(episodes, row_field, allowed=allowed)
    declarations: list[tuple[str, Any]] = []
    if singular in review_data:
        declarations.append((f"review_data.{singular}", review_data[singular]))
    if synthesis is not None and synthesis is not review_data and singular in synthesis:
        declarations.append((f"review_data.synthesis.{singular}", synthesis[singular]))
    for label, value in declarations:
        if (
            label.startswith("review_data.synthesis.")
            and singular in {"events", "findings", "strengths"}
            and _validated_synthesis_signal_commitments(
                synthesis.get("signal_commitments") if synthesis is not None else None
            )
            is not None
        ):
            continue
        declared_counts = _category_counts(
            value,
            label=label,
            allowed=allowed,
        )
        if declared_counts != row_counts:
            raise RetainedInventoryError(
                f"{label} does not reconcile with episode rows"
            )
    return row_counts


def _safe_string_vector(
    value: Any,
    *,
    label: str,
    allowed: frozenset[str] | None = None,
) -> list[str]:
    values = _ordered_set(_require_rows(value, label=label), path=label)
    result: list[str] = []
    for index, item in enumerate(values):
        if not isinstance(item, str):
            raise RetainedReportingError(f"{label}[{index}] must be a string")
        _validate_safe_string(item, path=f"{label}[{index}]")
        if allowed is not None and item not in allowed:
            raise RetainedInventoryError(
                f"{label}[{index}] has unsupported category {item!r}"
            )
        result.append(item)
    return result


def _compile_synthesis_sections(synthesis: Mapping[str, Any]) -> list[dict[str, Any]]:
    answers = _require_rows(
        synthesis.get("question_answers"),
        label="review_data.synthesis.question_answers",
    )
    if len(answers) != len(SYNTHESIS_QUESTION_IDS):
        raise RetainedInventoryError(
            "synthesis question_answers must contain the fixed ten questions"
        )
    by_question: dict[str, dict[str, Any]] = {}
    required_fields = {
        "confidence",
        "disposition",
        "event_kinds",
        "evidence_refs",
        "finding_kinds",
        "question_id",
        "strength_kinds",
    }
    for index, raw_answer in enumerate(answers):
        answer = _require_mapping(
            raw_answer, label=f"review_data.synthesis.question_answers[{index}]"
        )
        if set(answer) != required_fields:
            raise RetainedInventoryError(
                "synthesis question answer has an unexpected field inventory"
            )
        question_id = answer.get("question_id")
        if question_id not in _QUESTION_TO_SECTION or question_id in by_question:
            raise RetainedInventoryError(
                "synthesis question answer has an unknown or duplicate question_id"
            )
        disposition = answer.get("disposition")
        confidence = answer.get("confidence")
        if disposition not in {"not_observed", "observed", "unavailable"}:
            raise RetainedReportingError("synthesis question disposition is not closed")
        if confidence not in {"low", "medium", "high"}:
            raise RetainedReportingError("synthesis question confidence is not closed")
        event_kinds = _safe_string_vector(
            answer["event_kinds"],
            label=f"synthesis.question_answers[{index}].event_kinds",
            allowed=EVENT_KINDS,
        )
        finding_kinds = _safe_string_vector(
            answer["finding_kinds"],
            label=f"synthesis.question_answers[{index}].finding_kinds",
            allowed=FINDING_KINDS,
        )
        strength_kinds = _safe_string_vector(
            answer["strength_kinds"],
            label=f"synthesis.question_answers[{index}].strength_kinds",
            allowed=STRENGTH_KINDS,
        )
        evidence_refs = _safe_string_vector(
            answer["evidence_refs"],
            label=f"synthesis.question_answers[{index}].evidence_refs",
        )
        signal_count = len(event_kinds) + len(finding_kinds) + len(strength_kinds)
        if disposition == "observed" and (signal_count == 0 or not evidence_refs):
            raise RetainedInventoryError(
                "observed synthesis question requires a closed signal and evidence"
            )
        if disposition == "not_observed" and (signal_count or evidence_refs):
            raise RetainedInventoryError(
                "not_observed synthesis question cannot retain signals or evidence"
            )
        by_question[str(question_id)] = {
            "confidence": confidence,
            "disposition": disposition,
            "event_kinds": event_kinds,
            "evidence_refs": evidence_refs,
            "finding_kinds": finding_kinds,
            "observation_count": signal_count,
            "question_id": question_id,
            "schema_version": _SCHEMA_VERSION,
            "section_id": _QUESTION_TO_SECTION[str(question_id)],
            "strength_kinds": strength_kinds,
        }
    if set(by_question) != set(SYNTHESIS_QUESTION_IDS):
        raise RetainedInventoryError(
            "synthesis question_answers do not cover the fixed ten questions"
        )
    rows = [by_question[question_id] for question_id in SYNTHESIS_QUESTION_IDS]
    validate_retained_value(rows, path="summary.report_sections")
    return rows


def _fallback_report_sections(
    episodes: Sequence[Mapping[str, Any]],
    aggregate_counts: Mapping[str, Any],
) -> list[dict[str, Any]]:
    evidence_refs = sorted(str(row["episode_ref"]) for row in episodes)
    section_signals = {
        "what_happened": (aggregate_counts["events"], {}, {}),
        "what_worked_well": ({}, {}, aggregate_counts["strengths"]),
        "noise_and_confusion": ({}, aggregate_counts["findings"], {}),
        "errors_and_verification": (aggregate_counts["events"], {}, {}),
        "collaboration_failure_modes": ({}, aggregate_counts["findings"], {}),
        "safety_and_privacy": ({}, aggregate_counts["risks"], {}),
        "prompt_improvements": ({}, {}, {}),
        "agents_guidance": ({}, {}, {}),
        "skill_candidates": ({}, {}, {}),
        "follow_up_actions": ({}, {}, {}),
    }
    scalar_counts = {
        "prompt_improvements": int(aggregate_counts["prompt_improvements"]),
        "agents_guidance": int(aggregate_counts["agents_guidance_candidates"]),
        "skill_candidates": int(aggregate_counts["skill_candidates"]),
        "follow_up_actions": int(aggregate_counts["follow_up_actions"]),
    }
    rows: list[dict[str, Any]] = []
    for question_id, (section_id, _title) in zip(
        SYNTHESIS_QUESTION_IDS, REPORT_SECTIONS
    ):
        events, findings, strengths = section_signals[section_id]
        observation_count = (
            sum(events.values()) + sum(findings.values()) + sum(strengths.values())
        )
        observation_count += scalar_counts.get(section_id, 0)
        has_evidence = bool(evidence_refs)
        if observation_count and has_evidence:
            disposition = "observed"
        elif observation_count:
            disposition = "unavailable"
        else:
            disposition = "not_observed"
        rows.append(
            {
                "confidence": "high" if disposition != "unavailable" else "low",
                "disposition": disposition,
                "event_kinds": sorted(
                    key for key, count in events.items() if count > 0
                ),
                "evidence_refs": evidence_refs if disposition == "observed" else [],
                "finding_kinds": sorted(
                    key for key, count in findings.items() if count > 0
                ),
                "observation_count": observation_count,
                "question_id": question_id,
                "schema_version": _SCHEMA_VERSION,
                "section_id": section_id,
                "strength_kinds": sorted(
                    key for key, count in strengths.items() if count > 0
                ),
            }
        )
    validate_retained_value(rows, path="summary.report_sections")
    return rows


def _prompt_rewrite_refs(value: Any) -> list[str]:
    refs: list[str] = []
    for index, raw_row in enumerate(
        _require_rows(value, label="review_data.synthesis.prompt_rewrites")
    ):
        row = _require_mapping(
            raw_row, label=f"review_data.synthesis.prompt_rewrites[{index}]"
        )
        turn_ref = row.get("turn_ref")
        if not isinstance(turn_ref, str):
            raise RetainedReportingError("synthesis prompt rewrite is missing turn_ref")
        _validate_safe_string(
            turn_ref, path=f"synthesis.prompt_rewrites[{index}].turn_ref"
        )
        refs.append(turn_ref)
    return [
        str(ref)
        for ref in _ordered_set(refs, path="synthesis.prompt_rewrites.turn_refs")
    ]


def _gap_rows(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    allowed_fields = {
        "acknowledged",
        "dependency_ref",
        "gap_ref",
        "host_ref",
        "reason",
        "repairable",
        "source_kind",
        "stage",
        "terminal",
    }
    for index, raw_row in enumerate(
        _require_rows(value, label="run_state.coverage.gaps")
    ):
        source = _require_mapping(raw_row, label=f"run_state.coverage.gaps[{index}]")
        unknown = set(source) - allowed_fields - {"host"}
        if unknown:
            raise RetainedInventoryError(
                f"coverage gap has unknown fields: {sorted(unknown)}"
            )
        row = _sort_unordered_fields(
            _normalize_value(
                {key: value for key, value in source.items() if key in allowed_fields},
                path="coverage.gaps",
            )
        )
        validate_retained_value(row, path=f"run_state.coverage.gaps[{index}]")
        rows.append(row)
    rows.sort(key=canonical_json_bytes)
    return rows


def _build_coverage(
    run_state: Mapping[str, Any],
    episodes: Sequence[Mapping[str, Any]],
    turn_findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    raw_coverage = _require_mapping(
        run_state.get("coverage", {}), label="run_state.coverage"
    )
    gaps = _gap_rows(raw_coverage.get("gaps", run_state.get("gaps", ())))
    source_input = _require_mapping(
        raw_coverage.get("source_units", {}), label="run_state.coverage.source_units"
    )
    consumed = _optional_count(
        source_input,
        ("consumed_candidate", "consumed"),
        default=0,
        label="run_state.coverage.source_units",
    )
    excluded = _optional_count(
        source_input,
        ("structurally_excluded", "excluded"),
        default=0,
        label="run_state.coverage.source_units",
    )
    explicit_gap = _optional_count(
        source_input,
        ("explicit_gap", "gaps"),
        default=len(gaps),
        label="run_state.coverage.source_units",
    )
    expected = _optional_count(
        source_input,
        ("expected", "total"),
        default=consumed + excluded + explicit_gap,
        label="run_state.coverage.source_units",
    )
    if expected != consumed + excluded + explicit_gap:
        raise RetainedInventoryError(
            "source-unit accounting must reconcile expected to consumed_candidate, "
            "structurally_excluded, and explicit_gap"
        )

    finding_refs = [str(row["turn_ref"]) for row in turn_findings]
    declared_refs_raw = raw_coverage.get("meaningful_turn_refs")
    if declared_refs_raw is None:
        meaningful_refs = finding_refs
    else:
        meaningful_refs = [
            str(value)
            for value in _ordered_set(
                _require_rows(
                    declared_refs_raw, label="run_state.coverage.meaningful_turn_refs"
                ),
                path="run_state.coverage.meaningful_turn_refs",
            )
        ]
        for index, ref in enumerate(meaningful_refs):
            _validate_safe_string(
                ref, path=f"run_state.coverage.meaningful_turn_refs[{index}]"
            )
    if meaningful_refs != finding_refs:
        raise RetainedInventoryError(
            "turn_findings.jsonl must contain exactly one canonical disposition for every meaningful turn"
        )

    meaningful_turns = len(meaningful_refs)
    declared_turn_count = raw_coverage.get("meaningful_turn_count")
    if (
        declared_turn_count is not None
        and _nonnegative_int(
            declared_turn_count, label="run_state.coverage.meaningful_turn_count"
        )
        != meaningful_turns
    ):
        raise RetainedInventoryError(
            "meaningful_turn_count does not match meaningful_turn_refs"
        )

    context_only = _optional_count(
        raw_coverage,
        ("context_only_turn_count", "context_only"),
        default=0,
        label="run_state.coverage",
    )
    meaningfulness_gap = _optional_count(
        raw_coverage,
        ("meaningfulness_gap_count", "meaningfulness_gaps"),
        default=0,
        label="run_state.coverage",
    )
    extraction_gap = _optional_count(
        raw_coverage,
        ("extraction_gap_count", "extraction_gaps"),
        default=0,
        label="run_state.coverage",
    )
    structurally_excluded_turns = _optional_count(
        raw_coverage,
        ("structurally_excluded_turn_count", "structurally_excluded_turns"),
        default=0,
        label="run_state.coverage",
    )
    extraction_accepted = _optional_count(
        raw_coverage,
        ("extraction_accepted_turn_count", "extraction_accepted"),
        default=meaningful_turns + context_only + meaningfulness_gap,
        label="run_state.coverage",
    )
    if extraction_accepted != meaningful_turns + context_only + meaningfulness_gap:
        raise RetainedInventoryError(
            "extraction-accepted turns must reconcile to meaningful, context_only, and meaningfulness_gap"
        )

    turn_dispositions = Counter(str(row["disposition"]) for row in turn_findings)
    meaningful_episode_rows = [
        row
        for row in episodes
        if row.get("review_disposition") != "review_not_required"
    ]
    meaningful_episodes = len(meaningful_episode_rows)
    declared_episode_count = raw_coverage.get("meaningful_episode_count")
    if (
        declared_episode_count is not None
        and _nonnegative_int(
            declared_episode_count, label="run_state.coverage.meaningful_episode_count"
        )
        != meaningful_episodes
    ):
        raise RetainedInventoryError(
            "meaningful_episode_count does not match episode dispositions"
        )
    episode_dispositions = Counter(
        str(row.get("review_disposition", "review_gap")) for row in episodes
    )

    coverage_complete = (
        explicit_gap == 0
        and not gaps
        and extraction_gap == 0
        and meaningfulness_gap == 0
        and turn_dispositions["turn_review_gap"] == 0
        and episode_dispositions["review_gap"] == 0
    )
    if "coverage_complete" in raw_coverage:
        declared_complete = raw_coverage["coverage_complete"]
        if not isinstance(declared_complete, bool):
            raise RetainedReportingError(
                "run_state.coverage.coverage_complete must be a boolean"
            )
        if declared_complete != coverage_complete:
            raise RetainedInventoryError(
                "declared coverage_complete disagrees with terminal coverage dispositions"
            )

    coverage = {
        "coverage_complete": coverage_complete,
        "episode_dispositions": {
            "meaningful": meaningful_episodes,
            "review_gap": episode_dispositions["review_gap"],
            "review_not_required": episode_dispositions["review_not_required"],
            "reviewed": episode_dispositions["reviewed"],
            "total": len(episodes),
        },
        "gaps": gaps,
        "schema_version": _SCHEMA_VERSION,
        "source_units": {
            "consumed_candidate": consumed,
            "expected": expected,
            "explicit_gap": explicit_gap,
            "structurally_excluded": excluded,
        },
        "turn_dispositions": {
            "high_impact": turn_dispositions["high_impact"],
            "not_high_impact": turn_dispositions["not_high_impact"],
            "turn_review_gap": turn_dispositions["turn_review_gap"],
        },
        "turns": {
            "context_only": context_only,
            "extraction_accepted": extraction_accepted,
            "extraction_gap": extraction_gap,
            "meaningful": meaningful_turns,
            "meaningfulness_gap": meaningfulness_gap,
            "structurally_excluded": structurally_excluded_turns,
        },
        "meaningful_turn_refs": meaningful_refs,
    }
    validate_retained_value(coverage, path="coverage")
    return coverage


def _rate_entry(
    count: int,
    denominator: int,
    *,
    denominator_kind: str,
    available: bool,
    unavailable_reason: str,
) -> dict[str, Any]:
    if not available:
        rate: float | None = None
        reason: str | None = unavailable_reason
    elif denominator == 0:
        rate = None
        reason = "empty_denominator"
    else:
        rate = round(count * 100.0 / denominator, 2)
        reason = None
    return {
        "available": available and denominator > 0,
        "count": count,
        "denominator": denominator,
        "denominator_kind": denominator_kind,
        "rate_per_100": rate,
        "unavailable_reason": reason,
    }


def _build_metrics(
    coverage: Mapping[str, Any],
    aggregate_counts: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    turns = int(coverage["turns"]["meaningful"])
    episodes = int(coverage["episode_dispositions"]["meaningful"])
    source_complete = (
        int(coverage["source_units"]["explicit_gap"]) == 0
        and not coverage["gaps"]
        and int(coverage["turns"]["extraction_gap"]) == 0
        and int(coverage["turns"]["meaningfulness_gap"]) == 0
    )
    turn_review_complete = (
        source_complete and int(coverage["turn_dispositions"]["turn_review_gap"]) == 0
    )
    episode_review_complete = (
        source_complete and int(coverage["episode_dispositions"]["review_gap"]) == 0
    )
    metrics: dict[str, dict[str, Any]] = {}

    for disposition, count in sorted(coverage["turn_dispositions"].items()):
        metrics[f"turn_disposition.{disposition}"] = _rate_entry(
            int(count),
            turns,
            denominator_kind="meaningful_turns",
            available=turn_review_complete,
            unavailable_reason="turn_review_coverage_gap",
        )
    for disposition in ("reviewed", "review_gap"):
        metrics[f"episode_disposition.{disposition}"] = _rate_entry(
            int(coverage["episode_dispositions"][disposition]),
            episodes,
            denominator_kind="meaningful_episodes",
            available=episode_review_complete,
            unavailable_reason="episode_review_coverage_gap",
        )
    for family in ("events", "findings", "strengths", "risks"):
        denominator = turns if family == "events" else episodes
        denominator_kind = (
            "meaningful_turns" if family == "events" else "meaningful_episodes"
        )
        family_available = episode_review_complete
        reason = "episode_review_coverage_gap"
        for category, count in sorted(aggregate_counts[family].items()):
            metrics[f"{family[:-1]}.{category}"] = _rate_entry(
                int(count),
                denominator,
                denominator_kind=denominator_kind,
                available=family_available,
                unavailable_reason=reason,
            )
    for metric_id in (
        "prompt_improvements",
        "agents_guidance_candidates",
        "skill_candidates",
        "follow_up_actions",
    ):
        metrics[metric_id] = _rate_entry(
            int(aggregate_counts[metric_id]),
            episodes,
            denominator_kind="meaningful_episodes",
            available=episode_review_complete,
            unavailable_reason="episode_review_coverage_gap",
        )
    return dict(sorted(metrics.items()))


def _declared_eras(
    run_state: Mapping[str, Any], plural_key: str, default_key: str
) -> list[str]:
    value = run_state.get(plural_key)
    if value is None:
        default = run_state.get(default_key, "unknown")
        values = [default]
    elif isinstance(value, Mapping):
        values = list(value.keys())
    elif isinstance(value, str):
        values = [value]
    else:
        values = list(_require_rows(value, label=f"run_state.{plural_key}"))
    eras = _ordered_set(values, path=f"run_state.{plural_key}")
    for index, era in enumerate(eras):
        if not isinstance(era, str):
            raise RetainedReportingError(
                f"run_state.{plural_key}[{index}] must be a string"
            )
        _validate_safe_string(era, path=f"run_state.{plural_key}[{index}]")
    return [str(era) for era in eras]


def _stratify(
    *,
    era_field: str,
    declared_eras: Sequence[str],
    episodes: Sequence[Mapping[str, Any]],
    turn_findings: Sequence[Mapping[str, Any]],
    coverage: Mapping[str, Any],
    aggregate_counts: Mapping[str, Any],
) -> dict[str, Any]:
    if not declared_eras or len(set(declared_eras)) != len(declared_eras):
        raise RetainedInventoryError(
            f"{era_field} declarations must be non-empty and unique"
        )
    declared = set(declared_eras)

    def row_era(row: Mapping[str, Any], *, label: str) -> str:
        value = row.get(era_field)
        if not isinstance(value, str) or value not in declared:
            raise RetainedInventoryError(f"{label}.{era_field} is not a declared era")
        return value

    turns_by_era: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    episodes_by_era: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for index, row in enumerate(turn_findings):
        turns_by_era[row_era(row, label=f"turn_findings[{index}]")].append(row)
    for index, row in enumerate(episodes):
        episodes_by_era[row_era(row, label=f"episodes[{index}]")].append(row)
    result: dict[str, Any] = {}
    source_complete = (
        int(coverage["source_units"]["explicit_gap"]) == 0
        and not coverage["gaps"]
        and int(coverage["turns"]["extraction_gap"]) == 0
        and int(coverage["turns"]["meaningfulness_gap"]) == 0
    )
    family_inventory = {
        "event": tuple(sorted(aggregate_counts["events"])),
        "finding": tuple(sorted(aggregate_counts["findings"])),
        "risk": tuple(sorted(aggregate_counts["risks"])),
        "strength": tuple(sorted(aggregate_counts["strengths"])),
    }
    for era in sorted(declared_eras):
        _validate_safe_string(era, path=f"stratification.{era}")
        turn_rows = turns_by_era[era]
        episode_rows = _meaningful_episode_rows(episodes_by_era[era])
        turn_counts = Counter(str(row["disposition"]) for row in turn_rows)
        episode_counts = Counter(
            str(row.get("review_disposition", "review_gap")) for row in episode_rows
        )
        strength_counts = _aggregate_row_counts(
            episode_rows,
            "strength_counts",
            allowed=STRENGTH_KINDS,
        )
        finding_counts = _aggregate_row_counts(
            episode_rows,
            "finding_counts",
            allowed=FINDING_KINDS,
        )
        risk_counts = _aggregate_row_counts(
            episode_rows,
            "risk_counts",
            allowed=RISK_FLAGS,
        )
        event_counts = _aggregate_row_counts(
            episode_rows,
            "event_counts",
            allowed=EVENT_KINDS,
        )
        turn_review_complete = source_complete and turn_counts["turn_review_gap"] == 0
        episode_review_complete = source_complete and episode_counts["review_gap"] == 0
        metrics: dict[str, Any] = {}
        for disposition in sorted(TURN_DISPOSITIONS):
            metrics[f"turn_disposition.{disposition}"] = _rate_entry(
                turn_counts[disposition],
                len(turn_rows),
                denominator_kind="meaningful_turns",
                available=turn_review_complete,
                unavailable_reason="turn_review_coverage_gap",
            )
        for disposition in ("reviewed", "review_gap"):
            metrics[f"episode_disposition.{disposition}"] = _rate_entry(
                episode_counts[disposition],
                len(episode_rows),
                denominator_kind="meaningful_episodes",
                available=episode_review_complete,
                unavailable_reason="episode_review_coverage_gap",
            )
        for family, counts in (
            ("event", event_counts),
            ("finding", finding_counts),
            ("strength", strength_counts),
            ("risk", risk_counts),
        ):
            denominator = len(turn_rows) if family == "event" else len(episode_rows)
            denominator_kind = (
                "meaningful_turns" if family == "event" else "meaningful_episodes"
            )
            available = episode_review_complete
            reason = "episode_review_coverage_gap"
            for category in family_inventory[family]:
                metrics[f"{family}.{category}"] = _rate_entry(
                    counts.get(category, 0),
                    denominator,
                    denominator_kind=denominator_kind,
                    available=available,
                    unavailable_reason=reason,
                )
        metrics["prompt_improvements"] = _rate_entry(
            sum(row.get("disposition") == "high_impact" for row in turn_rows),
            len(episode_rows),
            denominator_kind="meaningful_episodes",
            available=episode_review_complete,
            unavailable_reason="episode_review_coverage_gap",
        )
        for metric_id in (
            "agents_guidance_candidates",
            "follow_up_actions",
            "skill_candidates",
        ):
            missing_lineage = (
                len(declared_eras) > 1 and int(aggregate_counts[metric_id]) > 0
            )
            metrics[metric_id] = _rate_entry(
                int(aggregate_counts[metric_id]) if len(declared_eras) == 1 else 0,
                len(episode_rows),
                denominator_kind="meaningful_episodes",
                available=episode_review_complete and not missing_lineage,
                unavailable_reason=(
                    "missing_era_lineage"
                    if missing_lineage
                    else "episode_review_coverage_gap"
                ),
            )
        result[era] = {
            "meaningful_episode_count": len(episode_rows),
            "meaningful_turn_count": len(turn_rows),
            "metrics": dict(sorted(metrics.items())),
        }
    return result


def _validate_turn_episode_era_lineage(
    episodes: Sequence[Mapping[str, Any]],
    turn_findings: Sequence[Mapping[str, Any]],
) -> None:
    episodes_by_ref = {row.get("episode_ref"): row for row in episodes}
    for index, turn in enumerate(turn_findings):
        episode = episodes_by_ref.get(turn.get("episode_ref"))
        if episode is None:
            raise RetainedInventoryError(
                f"turn_findings[{index}] references an absent episode"
            )
        for era_field in ("model_era", "policy_era"):
            turn_era = turn.get(era_field)
            episode_era = episode.get(era_field)
            if (
                not isinstance(turn_era, str)
                or not isinstance(episode_era, str)
                or turn_era != episode_era
            ):
                raise RetainedInventoryError(
                    f"turn_findings[{index}].{era_field} does not match its "
                    "episode era lineage"
                )


def _model_policy_strata(
    episodes: Sequence[Mapping[str, Any]],
    turn_findings: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows = [*_meaningful_episode_rows(episodes), *turn_findings]
    pairs = sorted({(str(row["model_era"]), str(row["policy_era"])) for row in rows})
    return [
        {"model_era": model_era, "policy_era": policy_era}
        for model_era, policy_era in pairs
    ]


def _compatibility_key(
    provenance: Mapping[str, Any],
    model_eras: Sequence[str],
    policy_eras: Sequence[str],
    model_policy_strata: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    validate_retained_value(provenance, path="run_state.provenance")
    _validate_retained_provenance(provenance)
    configuration_ref = provenance["production_configuration_ref"]
    result = {
        "configuration_ref": configuration_ref,
        "model_eras": list(model_eras),
        "model_policy_strata": [dict(row) for row in model_policy_strata],
        "policy_eras": list(policy_eras),
    }
    validate_retained_value(result, path="compatibility_key")
    return result


def _prior_trend(value: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if value is None:
        return None
    candidate: Any = value
    if "trend_report" in value:
        candidate = value["trend_report"]
    elif "trend_report.json" in value:
        candidate = value["trend_report.json"]
    if isinstance(candidate, (bytes, bytearray)):
        candidate = _json_loads_no_duplicates(
            bytes(candidate), label="prior_period.trend_report.json"
        )
    if not isinstance(candidate, Mapping):
        raise RetainedReportingError(
            "prior_period must contain a trend report mapping or canonical JSON bytes"
        )
    return validate_prior_trend_report(candidate)


def _normalized_changes(
    compatibility_key: Mapping[str, Any],
    metrics: Mapping[str, Mapping[str, Any]],
    prior_period: Mapping[str, Any] | None,
    *,
    current_observed_metric_ids: Collection[str] | None = None,
) -> dict[str, Any]:
    prior = _prior_trend(prior_period)
    if prior is None:
        return {"changes": {}, "reason": "no_prior_period", "status": "unavailable"}
    prior_key = prior.get("compatibility_key")
    assert isinstance(prior_key, Mapping)

    def comparison_pair(
        key: Mapping[str, Any],
    ) -> tuple[tuple[str, str] | None, str | None]:
        eras = [*key["model_eras"], *key["policy_eras"]]
        if any(
            token in era.casefold()
            for era in eras
            for token in ("mixed", "unknown", "unspecified")
        ):
            return None, "unknown_model_or_policy_era"
        strata = key["model_policy_strata"]
        if not strata:
            return None, "missing_model_or_policy_era"
        if len(strata) != 1:
            return None, "mixed_model_policy_strata"
        row = strata[0]
        return (row["model_era"], row["policy_era"]), None

    current_pair, current_issue = comparison_pair(compatibility_key)
    prior_pair, prior_issue = comparison_pair(prior_key)
    issue = current_issue or prior_issue
    if issue is not None:
        return {"changes": {}, "reason": issue, "status": "incompatible"}
    if (
        prior_key.get("configuration_ref") != compatibility_key.get("configuration_ref")
        or prior_pair != current_pair
    ):
        return {
            "changes": {},
            "reason": "incompatible_model_or_policy_era",
            "status": "incompatible",
        }
    prior_metrics = _require_mapping(
        prior.get("metrics", {}), label="prior_period.metrics"
    )
    observed = set(
        metrics if current_observed_metric_ids is None else current_observed_metric_ids
    )
    changes: dict[str, Any] = {}
    for metric_id, current in sorted(metrics.items()):
        previous = prior_metrics.get(metric_id)
        prior_present = isinstance(previous, Mapping)
        prior_rate = previous.get("rate_per_100") if prior_present else 0.0
        if not prior_present and not any(
            isinstance(row, Mapping)
            and row.get("denominator_kind") == current.get("denominator_kind")
            and row.get("available") is True
            for row in prior_metrics.values()
        ):
            continue
        current_rate = current.get("rate_per_100")
        if any(
            not isinstance(rate, (int, float)) or isinstance(rate, bool)
            for rate in (current_rate, prior_rate)
        ):
            continue
        delta = round(float(current_rate) - float(prior_rate), 2)
        relative = (
            None
            if float(prior_rate) == 0.0
            else round(delta * 100.0 / abs(float(prior_rate)), 2)
        )
        changes[metric_id] = {
            "category_presence": (
                "both"
                if metric_id in observed and prior_present
                else "current_only"
                if metric_id in observed
                else "prior_only"
            ),
            "current_rate_per_100": float(current_rate),
            "normalized_change_per_100": delta,
            "prior_rate_per_100": float(prior_rate),
            "relative_change_percent": relative,
        }
    return {"changes": changes, "reason": None, "status": "compatible"}


def _confidence_dimension(
    numerator: int, denominator: int, *, available: bool = True
) -> dict[str, Any]:
    if not available or denominator == 0:
        return {
            "denominator": denominator,
            "level": "unavailable",
            "numerator": numerator,
            "score": None,
        }
    score = round(numerator / denominator, 4)
    level = "high" if score >= 0.9 else "medium" if score >= 0.6 else "low"
    return {
        "denominator": denominator,
        "level": level,
        "numerator": numerator,
        "score": score,
    }


def _build_confidence(
    coverage: Mapping[str, Any], normalized_changes: Mapping[str, Any]
) -> dict[str, Any]:
    source = coverage["source_units"]
    source_complete = int(source["consumed_candidate"]) + int(
        source["structurally_excluded"]
    )
    unrepresented_gaps = max(0, len(coverage["gaps"]) - int(source["explicit_gap"]))
    source_total = int(source["expected"]) + unrepresented_gaps
    extraction_accepted = int(coverage["turns"]["extraction_accepted"])
    extraction_total = extraction_accepted + int(coverage["turns"]["extraction_gap"])
    extraction_resolved = max(
        0,
        extraction_accepted - int(coverage["turns"]["meaningfulness_gap"]),
    )
    meaningful_episodes = int(coverage["episode_dispositions"]["meaningful"])
    reviewed_episodes = int(coverage["episode_dispositions"]["reviewed"])
    meaningful_turns = int(coverage["turns"]["meaningful"])
    resolved_turns = meaningful_turns - int(
        coverage["turn_dispositions"]["turn_review_gap"]
    )
    completion_rates = [
        (reviewed_episodes, meaningful_episodes),
        (resolved_turns, meaningful_turns),
    ]
    available_rates = [rate for rate in completion_rates if rate[1] > 0]
    review_numerator, review_denominator = (0, 0)
    for numerator, denominator in available_rates:
        if review_denominator == 0 or (
            numerator * review_denominator < review_numerator * denominator
        ):
            review_numerator, review_denominator = numerator, denominator
    comparability_available = normalized_changes["status"] == "compatible"
    return {
        "comparability": _confidence_dimension(
            1 if comparability_available else 0,
            1,
            available=comparability_available,
        ),
        "coverage": _confidence_dimension(
            source_complete,
            source_total,
            available=source_total > 0,
        ),
        "extraction": _confidence_dimension(
            extraction_resolved,
            extraction_total,
            available=extraction_total > 0,
        ),
        "review": _confidence_dimension(
            review_numerator,
            review_denominator,
            available=review_denominator > 0,
        ),
    }


def _format_kind_list(values: Sequence[str]) -> str:
    if not values:
        return "none_observed"
    return ", ".join(f"`{value}`" for value in values)


def _format_rate(metric: Mapping[str, Any]) -> str:
    rate = metric.get("rate_per_100")
    if isinstance(rate, (int, float)) and not isinstance(rate, bool):
        return f"{float(rate):.2f} per 100 {str(metric['denominator_kind']).replace('_', ' ')}"
    return f"unavailable ({metric.get('unavailable_reason')})"


def _render_report(
    coverage: Mapping[str, Any],
    trend: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> bytes:
    aggregates = trend["aggregate_counts"]
    lines = ["# Session Retrospective v2", ""]
    section_records = {row["section_id"]: row for row in summary["report_sections"]}
    for index, (section_id, title) in enumerate(REPORT_SECTIONS, 1):
        record = section_records[section_id]
        lines.extend(
            (
                f"## {index}. {title}",
                f"- Disposition: {record['disposition']}",
                f"- Events: {_format_kind_list(record['event_kinds'])}",
                f"- Findings: {_format_kind_list(record['finding_kinds'])}",
                f"- Strengths: {_format_kind_list(record['strength_kinds'])}",
                f"- Evidence references: {len(record['evidence_refs'])}",
                f"- Confidence: {record['confidence']}",
            )
        )
        if section_id == "what_happened":
            lines.extend(
                (
                    f"- Meaningful turns: {coverage['turns']['meaningful']}",
                    f"- Meaningful episodes: {coverage['episode_dispositions']['meaningful']}",
                    f"- Topics: {summary['counts']['topics']}",
                )
            )
        elif section_id == "prompt_improvements":
            lines.append(
                f"- Retained prompt improvements: {aggregates['prompt_improvements']}"
            )
        elif section_id == "agents_guidance":
            lines.append(
                f"- Qualified candidates: {aggregates['agents_guidance_candidates']}"
            )
        elif section_id == "skill_candidates":
            lines.append(f"- Qualified candidates: {aggregates['skill_candidates']}")
        elif section_id == "follow_up_actions":
            lines.append(f"- Retained actions: {aggregates['follow_up_actions']}")
        lines.append("")

    lines.append("## Strengths")
    if aggregates["strengths"]:
        for category, count in sorted(aggregates["strengths"].items()):
            metric = trend["metrics"][f"strength.{category}"]
            lines.append(f"- `{category}`: count={count}, rate={_format_rate(metric)}")
    else:
        lines.append("- none_observed")
    lines.append("")
    lines.append("## Four-Dimensional Confidence")
    for dimension in CONFIDENCE_DIMENSIONS:
        value = trend["confidence"][dimension]
        score = (
            "unavailable" if value["score"] is None else f"{float(value['score']):.4f}"
        )
        lines.append(f"- {dimension}: {score} ({value['level']})")
    lines.extend(("", "## Compatible-Period Normalized Changes"))
    changes = trend["normalized_changes"]
    if changes["status"] != "compatible":
        lines.append(f"- Status: {changes['status']} ({changes['reason']})")
    elif not changes["changes"]:
        lines.append("- Status: compatible (no_comparable_metrics)")
    else:
        for metric_id, value in sorted(changes["changes"].items()):
            lines.append(
                f"- `{metric_id}` ({value['category_presence']}): "
                f"prior={float(value['prior_rate_per_100']):.2f}, "
                f"current={float(value['current_rate_per_100']):.2f}, "
                f"delta={float(value['normalized_change_per_100']):+.2f} per 100"
            )

    for heading, field in (
        ("Model Era Stratification", "model_eras"),
        ("Policy Era Stratification", "policy_eras"),
    ):
        lines.extend(("", f"## {heading}"))
        for era, values in sorted(trend[field].items()):
            high_impact = values["metrics"].get("turn_disposition.high_impact")
            rate_text = (
                "not_observed" if high_impact is None else _format_rate(high_impact)
            )
            lines.append(
                f"- `{era}`: turns={values['meaningful_turn_count']}, "
                f"episodes={values['meaningful_episode_count']}, high_impact={rate_text}"
            )
    lines.extend(
        (
            "",
            "## Coverage Gaps",
            f"- Recorded gap records: {len(coverage['gaps'])}",
            f"- Explicit source-unit gaps: {coverage['source_units']['explicit_gap']}",
            f"- Extraction gaps: {coverage['turns']['extraction_gap']}",
            f"- Meaningfulness gaps: {coverage['turns']['meaningfulness_gap']}",
            f"- Turn review gaps: {coverage['turn_dispositions']['turn_review_gap']}",
            f"- Episode review gaps: {coverage['episode_dispositions']['review_gap']}",
            "",
            "## Follow-up Summary",
            f"- Retained follow-up actions: {aggregates['follow_up_actions']}",
        )
    )
    lines.append("")
    return "\n".join(lines).encode("ascii")


def _artifact_row_counts(
    episodes: Sequence[Mapping[str, Any]],
    turn_findings: Sequence[Mapping[str, Any]],
    topics: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    return {
        "episodes.jsonl": len(episodes),
        "topics.jsonl": len(topics),
        "turn_findings.jsonl": len(turn_findings),
    }


def _bundle_digest_input(artifacts: Mapping[str, bytes]) -> dict[str, bytes]:
    if set(artifacts) != set(RETAINED_ARTIFACT_NAMES):
        raise RetainedInventoryError(
            "retained bundle must contain exactly the fixed eight artifacts"
        )
    manifest = _json_loads_no_duplicates(
        artifacts["manifest.json"], label="manifest.json"
    )
    if not isinstance(manifest, dict):
        raise RetainedInventoryError("manifest.json must contain a JSON object")
    if "retained_bundle_digest_v2" not in manifest:
        raise RetainedInventoryError(
            "manifest.json is missing retained_bundle_digest_v2"
        )
    projection = dict(manifest)
    del projection["retained_bundle_digest_v2"]
    result = dict(artifacts)
    result["manifest.json"] = canonical_json_bytes(projection)
    return result


def retained_bundle_digest(artifacts: Mapping[str, bytes]) -> str:
    """Compute the non-self-referential retained bundle digest."""

    framed = _bundle_digest_input(artifacts)
    digest = hashlib.sha256()
    digest.update(_BUNDLE_DIGEST_DOMAIN)
    for name in sorted(RETAINED_ARTIFACT_NAMES, key=lambda item: item.encode("ascii")):
        name_bytes = name.encode("ascii")
        content = framed[name]
        digest.update(struct.pack(">H", len(name_bytes)))
        digest.update(name_bytes)
        digest.update(struct.pack(">Q", len(content)))
        digest.update(content)
    return digest.hexdigest()


def _validate_agent_execution_provenance(value: Any) -> None:
    execution = _require_mapping(value, label="manifest.provenance.agent_execution")
    if set(execution) != {
        "jobs",
        "result_count",
        "retry_count",
        "schema",
        "task_cache",
    } or (execution.get("schema") != "agent_execution_provenance_v2"):
        raise RetainedInventoryError(
            "manifest agent execution provenance has an unexpected shape"
        )
    jobs = _require_rows(
        execution["jobs"], label="manifest.provenance.agent_execution.jobs"
    )
    normalized_jobs: list[Mapping[str, Any]] = []
    result_count = 0
    retry_count = 0
    reuse_count = 0
    for job_index, raw_job in enumerate(jobs):
        label = f"manifest.provenance.agent_execution.jobs[{job_index}]"
        job = _require_mapping(raw_job, label=label)
        if set(job) != {
            "attempts",
            "job_kind",
            "partition_commitment",
            "result_hash",
            "reuse_count",
            "stage",
            "status",
            "task_ref",
        }:
            raise RetainedInventoryError(f"{label} has an unexpected field inventory")
        attempts = _require_rows(job["attempts"], label=f"{label}.attempts")
        ordinals: list[int] = []
        for attempt_index, raw_attempt in enumerate(attempts):
            attempt_label = f"{label}.attempts[{attempt_index}]"
            attempt = _require_mapping(raw_attempt, label=attempt_label)
            if set(attempt) != {
                "attempt_ref",
                "claimed_at",
                "completed_at",
                "issued_at",
                "job_ref",
                "ordinal",
                "reason",
                "result_ref",
                "reviewer_ref",
                "status",
            }:
                raise RetainedInventoryError(
                    f"{attempt_label} has an unexpected field inventory"
                )
            ordinal = attempt["ordinal"]
            if isinstance(ordinal, bool) or not isinstance(ordinal, int):
                raise RetainedInventoryError(
                    f"{attempt_label}.ordinal must be an integer"
                )
            ordinals.append(ordinal)
            issued = _parse_timestamp(str(attempt["issued_at"]))
            claimed = (
                None
                if attempt["claimed_at"] is None
                else _parse_timestamp(str(attempt["claimed_at"]))
            )
            completed = (
                None
                if attempt["completed_at"] is None
                else _parse_timestamp(str(attempt["completed_at"]))
            )
            if claimed is not None and claimed < issued:
                raise RetainedInventoryError(
                    f"{attempt_label}.claimed_at precedes issuance"
                )
            if completed is not None and completed < (claimed or issued):
                raise RetainedInventoryError(
                    f"{attempt_label}.completed_at precedes dispatch"
                )
            if completed is not None:
                result_count += 1
        if ordinals != list(range(len(attempts))):
            raise RetainedInventoryError(f"{label}.attempts are not ordinally complete")
        retry_count += max(0, len(attempts) - 1)
        job_reuse_count = job["reuse_count"]
        if (
            isinstance(job_reuse_count, bool)
            or not isinstance(job_reuse_count, int)
            or job_reuse_count < 0
        ):
            raise RetainedInventoryError(
                f"{label}.reuse_count must be a non-negative integer"
            )
        reuse_count += job_reuse_count
        result_hash = job["result_hash"]
        if result_hash is not None and (
            not isinstance(result_hash, str)
            or _HEX_64_RE.fullmatch(result_hash) is None
        ):
            raise RetainedInventoryError(
                f"{label}.result_hash is not lowercase SHA-256"
            )
        normalized_jobs.append(job)
    task_refs = [str(job["task_ref"]) for job in normalized_jobs]
    if task_refs != sorted(task_refs) or len(task_refs) != len(set(task_refs)):
        raise RetainedInventoryError(
            "manifest agent jobs are not uniquely ordered by task_ref"
        )
    if (
        execution["result_count"] != result_count
        or execution["retry_count"] != retry_count
    ):
        raise RetainedInventoryError(
            "manifest agent result/retry counts do not conserve attempts"
        )
    cache = _require_mapping(
        execution["task_cache"],
        label="manifest.provenance.agent_execution.task_cache",
    )
    if set(cache) != {"hits", "misses", "reuses"} or any(
        isinstance(cache[name], bool)
        or not isinstance(cache[name], int)
        or cache[name] < 0
        for name in ("hits", "misses", "reuses")
    ):
        raise RetainedInventoryError(
            "manifest agent task-cache metrics have an unexpected shape"
        )
    if (
        cache["hits"] != cache["reuses"]
        or cache["misses"] != len(jobs)
        or cache["reuses"] != reuse_count
    ):
        raise RetainedInventoryError(
            "manifest agent task-cache metrics do not conserve task creation and reuse"
        )


def _validate_retained_provenance(value: Any) -> None:
    provenance = _require_mapping(value, label="manifest.provenance")
    if set(provenance) != {
        "agent_execution",
        "configuration_root",
        "engine_version",
        "model",
        "production_configuration_ref",
        "prompt",
        "schema",
        "transport",
        "versions",
    }:
        raise RetainedInventoryError(
            "manifest provenance does not contain the complete execution contract"
        )
    if provenance["schema"] != "retrospective_execution_contract_v2":
        raise RetainedInventoryError("manifest provenance schema is incompatible")
    if (
        not isinstance(provenance["configuration_root"], str)
        or _HEX_64_RE.fullmatch(provenance["configuration_root"]) is None
    ):
        raise RetainedInventoryError("manifest configuration_root is invalid")
    production_configuration_ref = provenance["production_configuration_ref"]
    if (
        not isinstance(production_configuration_ref, str)
        or production_configuration_ref == "configuration_ref_unavailable"
        or not production_configuration_ref.startswith("configuration_ref_v2:")
        or _OPAQUE_REF_RE.fullmatch(production_configuration_ref) is None
    ):
        raise RetainedInventoryError(
            "manifest production_configuration_ref is unavailable or invalid"
        )
    model = _require_mapping(provenance["model"], label="manifest.provenance.model")
    if set(model) != {"model", "parameters", "provider"}:
        raise RetainedInventoryError("manifest model provenance is incomplete")
    parameters = _require_mapping(
        model["parameters"], label="manifest.provenance.model.parameters"
    )
    if set(parameters) != {"reasoning_effort", "service_tier"}:
        raise RetainedInventoryError("manifest model parameters are incomplete")
    prompt = _require_mapping(provenance["prompt"], label="manifest.provenance.prompt")
    if set(prompt) != {"digest", "version"} or (
        not isinstance(prompt["digest"], str)
        or _HEX_64_RE.fullmatch(prompt["digest"]) is None
    ):
        raise RetainedInventoryError("manifest prompt provenance is incomplete")
    transport = _require_mapping(
        provenance["transport"], label="manifest.provenance.transport"
    )
    if set(transport) != {
        "remote_host_context_helper_commitment",
        "source_transport_schema",
    }:
        raise RetainedInventoryError("manifest transport provenance is incomplete")
    versions = _require_mapping(
        provenance["versions"], label="manifest.provenance.versions"
    )
    if set(versions) != {"detector", "policy", "redaction", "schema", "segmentation"}:
        raise RetainedInventoryError("manifest version provenance is incomplete")
    _validate_agent_execution_provenance(provenance["agent_execution"])


def _build_manifest(
    *,
    run_state: Mapping[str, Any],
    window: Mapping[str, str],
    row_counts: Mapping[str, int],
    compatibility_key: Mapping[str, Any],
) -> dict[str, Any]:
    mode = run_state.get("mode")
    if mode not in RUN_MODES:
        raise RetainedReportingError(
            f"run_state.mode must be one of {sorted(RUN_MODES)}"
        )
    run_ref = run_state.get("run_ref")
    if not isinstance(run_ref, str):
        raise RetainedReportingError(
            "run_state.run_ref must be an opaque string reference"
        )
    _validate_safe_string(run_ref, path="run_state.run_ref")
    publication_role = run_state.get("publication_role", "standalone")
    if publication_role not in PUBLICATION_ROLES:
        raise RetainedReportingError(
            f"unsupported publication_role {publication_role!r}"
        )
    provenance = _sort_unordered_fields(
        _normalize_value(
            _require_mapping(
                run_state.get("provenance", {}), label="run_state.provenance"
            ),
            path="provenance",
        )
    )
    validate_retained_value(provenance, path="manifest.provenance")
    _validate_retained_provenance(provenance)
    durable_state = _sort_unordered_fields(
        _normalize_value(
            _require_mapping(
                run_state.get("durable_state"), label="run_state.durable_state"
            ),
            path="durable_state",
        )
    )
    if durable_state.get("schema") != "durable_history_state_v2":
        raise RetainedReportingError("run_state.durable_state has an invalid schema")
    validate_retained_value(durable_state, path="manifest.durable_state")
    manifest = {
        "artifact_inventory": list(RETAINED_ARTIFACT_NAMES),
        "compatibility_key": copy.deepcopy(compatibility_key),
        "durable_state": durable_state,
        "mode": mode,
        "provenance": provenance,
        "publication_role": publication_role,
        "retained_bundle_digest_v2": {
            "algorithm": "sha256",
            "value": "0" * 64,
            "version": _SCHEMA_VERSION,
        },
        "retained_privacy_policy_version": _SCHEMA_VERSION,
        "row_counts": dict(row_counts),
        "run_ref": run_ref,
        "schema_version": _SCHEMA_VERSION,
        "window": dict(window),
    }
    validate_retained_value(manifest, path="manifest")
    return manifest


def assemble_retained_artifacts(
    run_state: Mapping[str, Any],
    review_data: Mapping[str, Any],
    *,
    prior_period: Mapping[str, Any] | None = None,
) -> dict[str, bytes]:
    """Assemble and validate the fixed Session Retrospective v2 bundle.

    No input mapping is mutated.  Arbitrary prose and raw/source locator fields
    are rejected instead of copied or silently redacted.
    """

    run_state = _require_mapping(run_state, label="run_state")
    review_data = _require_mapping(review_data, label="review_data")
    window = _normalize_window(run_state.get("window"))
    episodes = _record_rows(
        review_data.get("episodes"),
        label="review_data.episodes",
        ref_key="episode_ref",
        disposition_key="review_disposition",
        dispositions=EPISODE_REVIEW_DISPOSITIONS,
        row_kind="episode",
    )
    turn_findings = _record_rows(
        review_data.get("turn_findings"),
        label="review_data.turn_findings",
        ref_key="turn_ref",
        disposition_key="disposition",
        dispositions=TURN_DISPOSITIONS,
        row_kind="turn",
    )
    topics = _record_rows(
        review_data.get("topics"),
        label="review_data.topics",
        ref_key="topic_ref",
        row_kind="topic",
    )
    _validate_turn_episode_era_lineage(episodes, turn_findings)
    episodes_by_ref = {row["episode_ref"]: row for row in episodes}
    for index, topic in enumerate(topics):
        expected_findings = _expected_topic_findings(
            topic,
            episodes_by_ref,
            label=f"review_data.topics[{index}]",
        )
        if topic["findings"] != expected_findings:
            raise RetainedInventoryError(
                "topic findings do not preserve exact episode evidence references"
            )
    coverage = _build_coverage(run_state, episodes, turn_findings)

    synthesis = _synthesis_mapping(review_data)
    meaningful_episode_rows = _meaningful_episode_rows(episodes)
    row_aggregates = _canonical_row_aggregates(episodes, turn_findings)
    strengths = _review_category_counts(
        review_data,
        synthesis,
        meaningful_episode_rows,
        singular="strengths",
        row_field="strength_counts",
        allowed=STRENGTH_KINDS,
    )
    findings = _review_category_counts(
        review_data,
        synthesis,
        meaningful_episode_rows,
        singular="findings",
        row_field="finding_counts",
        allowed=FINDING_KINDS,
    )
    events = _review_category_counts(
        review_data,
        synthesis,
        meaningful_episode_rows,
        singular="events",
        row_field="event_counts",
        allowed=EVENT_KINDS,
    )
    risks = _review_category_counts(
        review_data,
        synthesis,
        meaningful_episode_rows,
        singular="risks",
        row_field="risk_counts",
        allowed=RISK_FLAGS,
    )
    high_impact_refs = sorted(
        str(row["turn_ref"])
        for row in turn_findings
        if row["disposition"] == "high_impact"
    )
    rewrite_declarations: list[tuple[str, Any]] = []
    if "prompt_rewrites" in review_data:
        rewrite_declarations.append(
            ("review_data.prompt_rewrites", review_data["prompt_rewrites"])
        )
    if (
        synthesis is not None
        and synthesis is not review_data
        and "prompt_rewrites" in synthesis
    ):
        rewrite_declarations.append(
            (
                "review_data.synthesis.prompt_rewrites",
                synthesis["prompt_rewrites"],
            )
        )
    for rewrite_label, rewrite_value in rewrite_declarations:
        rewrite_refs = _prompt_rewrite_refs(rewrite_value)
        if rewrite_refs != high_impact_refs:
            raise RetainedInventoryError(
                f"{rewrite_label} and high-impact turn findings do not reconcile"
            )
    prompt_improvements = row_aggregates["prompt_improvements"]
    guidance_candidates = _review_value(
        review_data, synthesis, "agents_guidance_candidates", "guidance_candidates"
    )
    follow_up_actions = _review_value(review_data, synthesis, "follow_up_actions")
    skill_candidates = _review_value(review_data, synthesis, "skill_candidates")
    episodes_by_ref = {row["episode_ref"]: row for row in episodes}
    retained_guidance_candidates = _durable_candidate_records(
        guidance_candidates,
        label="review_data.guidance_candidates",
        allowed_kinds=GUIDANCE_KINDS,
        episodes_by_ref=episodes_by_ref,
    )
    retained_skill_candidates = _durable_candidate_records(
        skill_candidates,
        label="review_data.skill_candidates",
        allowed_kinds=SKILL_CANDIDATE_KINDS,
        episodes_by_ref=episodes_by_ref,
    )
    aggregate_counts = {
        "agents_guidance_candidates": sum(
            _category_counts(
                guidance_candidates,
                label="review_data.agents_guidance_candidates",
                allowed=GUIDANCE_KINDS,
            ).values()
        ),
        "events": events,
        "findings": findings,
        "follow_up_actions": sum(
            _category_counts(
                follow_up_actions,
                label="review_data.follow_up_actions",
                allowed=FOLLOW_UP_KINDS,
            ).values()
        ),
        "prompt_improvements": prompt_improvements,
        "risks": risks,
        "skill_candidates": sum(
            _category_counts(
                skill_candidates,
                label="review_data.skill_candidates",
                allowed=SKILL_CANDIDATE_KINDS,
            ).values()
        ),
        "strengths": strengths,
    }
    current_observed_metric_ids = set(_build_metrics(coverage, aggregate_counts))
    validated_prior = _prior_trend(prior_period)
    if validated_prior is not None:
        _validate_prior_window(validated_prior["window"], window)
        prior_aggregates = _require_mapping(
            validated_prior["aggregate_counts"],
            label="prior_period.aggregate_counts",
        )
        for family in _AGGREGATE_COUNT_FIELDS:
            prior_counts = _require_mapping(
                prior_aggregates[family],
                label=f"prior_period.aggregate_counts.{family}",
            )
            current_counts = aggregate_counts[family]
            aggregate_counts[family] = {
                category: current_counts.get(category, 0)
                for category in sorted(set(prior_counts) | set(current_counts))
            }
    report_sections = (
        _compile_synthesis_sections(synthesis)
        if synthesis is not None and "question_answers" in synthesis
        else _fallback_report_sections(episodes, aggregate_counts)
    )
    expected_global_findings = _expected_global_findings(episodes, topics)
    signal_commitments = _validated_synthesis_signal_commitments(
        synthesis.get("signal_commitments") if synthesis is not None else None
    )
    declared_global_findings = (
        synthesis.get("findings") if synthesis is not None else None
    )
    if declared_global_findings is None and "findings" in review_data:
        declared_global_findings = review_data["findings"]
    declared_finding_records = (
        None
        if declared_global_findings is None
        else _finding_records(
            declared_global_findings,
            label="review_data.synthesis.findings",
        )
    )
    if signal_commitments is None:
        global_findings = (
            expected_global_findings
            if declared_finding_records is None
            else declared_finding_records
        )
        if global_findings != expected_global_findings:
            raise RetainedInventoryError(
                "global findings do not preserve exact topic evidence references"
            )
    else:
        if signal_commitments["findings"] != _finding_signal_commitment(
            expected_global_findings
        ):
            raise RetainedInventoryError(
                "global finding commitment does not bind exact topic evidence"
            )
        if declared_finding_records != _bounded_finding_exemplars(
            expected_global_findings
        ):
            raise RetainedInventoryError(
                "global finding exemplars are not the deterministic bounded union"
            )
        global_findings = expected_global_findings
    metrics = _build_metrics(coverage, aggregate_counts)

    model_eras = _declared_eras(run_state, "model_eras", "default_model_era")
    policy_eras = _declared_eras(run_state, "policy_eras", "default_policy_era")
    model_strata = _stratify(
        era_field="model_era",
        declared_eras=model_eras,
        episodes=episodes,
        turn_findings=turn_findings,
        coverage=coverage,
        aggregate_counts=aggregate_counts,
    )
    policy_strata = _stratify(
        era_field="policy_era",
        declared_eras=policy_eras,
        episodes=episodes,
        turn_findings=turn_findings,
        coverage=coverage,
        aggregate_counts=aggregate_counts,
    )
    joint_strata = _model_policy_strata(episodes, turn_findings)
    compatibility_key = _compatibility_key(
        _require_mapping(run_state.get("provenance"), label="run_state.provenance"),
        sorted(model_strata),
        sorted(policy_strata),
        joint_strata,
    )
    normalized_changes = _normalized_changes(
        compatibility_key,
        metrics,
        validated_prior,
        current_observed_metric_ids=current_observed_metric_ids,
    )
    confidence = _build_confidence(coverage, normalized_changes)
    trend = {
        "aggregate_counts": aggregate_counts,
        "compatibility_key": compatibility_key,
        "confidence": confidence,
        "metrics": metrics,
        "model_eras": model_strata,
        "normalized_changes": normalized_changes,
        "policy_eras": policy_strata,
        "schema_version": _SCHEMA_VERSION,
        "window": window,
    }
    validate_retained_value(trend, path="trend_report")

    summary = {
        "confidence": confidence,
        "counts": {
            "episodes": len(episodes),
            "meaningful_episodes": coverage["episode_dispositions"]["meaningful"],
            "meaningful_turns": coverage["turns"]["meaningful"],
            "strengths": sum(strengths.values()),
            "topics": len(topics),
            "turn_findings": len(turn_findings),
        },
        "coverage_complete": coverage["coverage_complete"],
        "findings": global_findings,
        "guidance_candidates": retained_guidance_candidates,
        "mode": run_state["mode"],
        "model_eras": sorted(model_strata),
        "normalized_change_status": normalized_changes["status"],
        "policy_eras": sorted(policy_strata),
        "report_section_count": len(REPORT_SECTIONS),
        "report_sections": report_sections,
        "run_ref": run_state["run_ref"],
        "schema_version": _SCHEMA_VERSION,
        "skill_candidates": retained_skill_candidates,
        "window": window,
    }
    validate_retained_value(summary, path="summary")
    report = _render_report(coverage, trend, summary)

    row_counts = _artifact_row_counts(episodes, turn_findings, topics)
    manifest = _build_manifest(
        run_state=run_state,
        window=window,
        row_counts=row_counts,
        compatibility_key=compatibility_key,
    )
    artifacts = {
        "coverage.json": canonical_json_bytes(coverage),
        "episodes.jsonl": canonical_jsonl_bytes(episodes),
        "manifest.json": canonical_json_bytes(manifest),
        "report.md": report,
        "summary.json": canonical_json_bytes(summary),
        "topics.jsonl": canonical_jsonl_bytes(topics),
        "trend_report.json": canonical_json_bytes(trend),
        "turn_findings.jsonl": canonical_jsonl_bytes(turn_findings),
    }
    digest = retained_bundle_digest(artifacts)
    manifest["retained_bundle_digest_v2"]["value"] = digest
    artifacts["manifest.json"] = canonical_json_bytes(manifest)
    artifacts = {name: artifacts[name] for name in RETAINED_ARTIFACT_NAMES}
    validate_retained_artifacts(artifacts)
    return artifacts


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RetainedInventoryError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _precheck_json_structure(data: bytes, *, label: str) -> None:
    depth = 0
    structural_tokens = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in {ord("{"), ord("[")}:
            depth += 1
            structural_tokens += 1
            if depth > MAX_JSON_DEPTH:
                raise RetainedInventoryError(
                    f"{label} exceeds the maximum JSON nesting depth"
                )
        elif byte in {ord("}"), ord("]")}:
            depth -= 1
            if depth < 0:
                break
        elif byte in {ord(","), ord(":")}:
            structural_tokens += 1
        if structural_tokens > MAX_JSON_NODES * 2:
            raise RetainedInventoryError(
                f"{label} exceeds the maximum JSON structural complexity"
            )


def _validate_json_structure(value: Any, *, label: str) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise RetainedInventoryError(
                f"{label} exceeds the maximum decoded JSON node count"
            )
        if depth > MAX_JSON_DEPTH:
            raise RetainedInventoryError(
                f"{label} exceeds the maximum decoded JSON nesting depth"
            )
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _json_loads_no_duplicates(data: bytes, *, label: str) -> Any:
    if len(data) > MAX_RETAINED_ARTIFACT_BYTES:
        raise RetainedInventoryError(f"{label} exceeds the JSON byte limit")
    _precheck_json_structure(data, label=label)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RetainedPrivacyError(f"{label} must be canonical ASCII JSON") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_json_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise RetainedInventoryError(
            f"{label} is not valid strict JSON: {exc}"
        ) from exc
    _validate_json_structure(value, label=label)
    return value


def _parse_jsonl(data: bytes, *, label: str) -> list[dict[str, Any]]:
    if data and not data.endswith(b"\n"):
        raise RetainedInventoryError(f"{label} must end with one canonical newline")
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(io.BytesIO(data), 1):
        if line_number > MAX_JSONL_ROWS:
            raise RetainedInventoryError(f"{label} exceeds the JSONL row limit")
        if len(raw_line) > MAX_JSONL_ROW_BYTES:
            raise RetainedInventoryError(
                f"{label}:{line_number} exceeds the JSONL row byte limit"
            )
        if not raw_line.endswith(b"\n"):
            raise RetainedInventoryError(
                f"{label}:{line_number} is not newline terminated"
            )
        line = raw_line[:-1]
        if not line:
            raise RetainedInventoryError(f"{label}:{line_number} is a blank JSONL row")
        row = _json_loads_no_duplicates(raw_line, label=f"{label}:{line_number}")
        if not isinstance(row, dict):
            raise RetainedInventoryError(
                f"{label}:{line_number} must contain a JSON object"
            )
        if canonical_json_bytes(row) != raw_line:
            raise RetainedInventoryError(
                f"{label}:{line_number} is not canonically encoded"
            )
        validate_retained_value(row, path=f"{label}[{line_number - 1}]")
        rows.append(row)
    return rows


def _validate_metric(metric_id: str, metric: Any) -> None:
    mapping = _require_mapping(metric, label=f"trend_report.metrics.{metric_id}")
    expected_keys = {
        "available",
        "count",
        "denominator",
        "denominator_kind",
        "rate_per_100",
        "unavailable_reason",
    }
    if set(mapping) != expected_keys:
        raise RetainedInventoryError(
            f"metric {metric_id!r} has an unexpected field inventory"
        )
    if not isinstance(mapping["available"], bool):
        raise RetainedInventoryError(
            f"metric {metric_id!r}.available must be a boolean"
        )
    count = _nonnegative_int(mapping["count"], label=f"metric {metric_id}.count")
    denominator = _nonnegative_int(
        mapping["denominator"], label=f"metric {metric_id}.denominator"
    )
    expected_rate = (
        None
        if denominator == 0 or not mapping["available"]
        else round(count * 100.0 / denominator, 2)
    )
    unavailable_reason = mapping["unavailable_reason"]
    if (
        mapping["denominator_kind"] not in {"meaningful_episodes", "meaningful_turns"}
        or (
            mapping["available"]
            and (denominator == 0 or unavailable_reason is not None)
        )
        or (
            not mapping["available"]
            and unavailable_reason
            not in {
                "empty_denominator",
                "episode_review_coverage_gap",
                "missing_era_lineage",
                "source_or_extraction_coverage_gap",
                "turn_review_coverage_gap",
            }
        )
        or mapping["rate_per_100"] != expected_rate
    ):
        raise RetainedInventoryError(
            f"metric {metric_id!r} has an invalid availability or rate"
        )


def _validate_normalized_changes(value: Any, metrics: Mapping[str, Any]) -> None:
    comparison = _require_mapping(value, label="trend_report.normalized_changes")
    if set(comparison) != {"changes", "reason", "status"}:
        raise RetainedInventoryError("normalized_changes has unexpected fields")
    status = comparison["status"]
    changes = _require_mapping(
        comparison["changes"], label="trend_report.normalized_changes.changes"
    )
    if status not in {"compatible", "incompatible", "unavailable"}:
        raise RetainedInventoryError("normalized_changes has an unsupported status")
    if status != "compatible":
        allowed_reasons = {
            "incompatible_model_or_policy_era",
            "missing_model_or_policy_era",
            "mixed_model_policy_strata",
            "no_prior_period",
            "unknown_model_or_policy_era",
        }
        if changes or comparison["reason"] not in allowed_reasons:
            raise RetainedInventoryError("invalid unavailable normalized_changes")
        return
    if comparison["reason"] is not None:
        raise RetainedInventoryError("compatible normalized_changes has a reason")
    expected_fields = {
        "category_presence",
        "current_rate_per_100",
        "normalized_change_per_100",
        "prior_rate_per_100",
        "relative_change_percent",
    }
    for metric_id, raw_change in changes.items():
        change = _require_mapping(
            raw_change, label=f"normalized_changes.changes.{metric_id}"
        )
        if set(change) != expected_fields or metric_id not in metrics:
            raise RetainedInventoryError("normalized change has invalid fields")
        current = change["current_rate_per_100"]
        prior = change["prior_rate_per_100"]
        delta = change["normalized_change_per_100"]
        presence = change["category_presence"]
        if presence not in {"both", "current_only", "prior_only"}:
            raise RetainedInventoryError(
                "normalized change category presence is invalid"
            )
        rates = (current, prior, delta)
        if any(
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            for item in rates
        ):
            raise RetainedInventoryError(
                "normalized change rates must be finite numeric"
            )
        if metrics[metric_id].get("rate_per_100") != current:
            raise RetainedInventoryError("normalized change metric rate mismatch")
        if (presence == "current_only" and float(prior) != 0.0) or (
            presence == "prior_only" and float(current) != 0.0
        ):
            raise RetainedInventoryError("one-sided category lacks explicit zero rate")
        expected_delta = round(float(current) - float(prior), 2)
        if float(delta) != expected_delta:
            raise RetainedInventoryError("normalized change delta is not reproducible")
        expected_relative = (
            None
            if float(prior) == 0.0
            else round(expected_delta * 100.0 / abs(float(prior)), 2)
        )
        if change["relative_change_percent"] != expected_relative:
            raise RetainedInventoryError("normalized relative change is invalid")


def _validate_era_strata(
    value: Any,
    *,
    label: str,
    meaningful_turns: int,
    meaningful_episodes: int,
    global_metrics: Mapping[str, Any],
) -> None:
    strata = _require_mapping(value, label=label)
    if not strata:
        raise RetainedInventoryError(f"{label} must contain at least one era")
    expected_metric_ids = set(global_metrics)
    turn_total = 0
    episode_total = 0
    count_totals: Counter[str] = Counter()
    denominator_totals: Counter[str] = Counter()
    for era, raw_stratum in strata.items():
        stratum = _require_mapping(raw_stratum, label=f"{label}.{era}")
        if set(stratum) != {
            "meaningful_episode_count",
            "meaningful_turn_count",
            "metrics",
        }:
            raise RetainedInventoryError(
                f"{label}.{era} has an unexpected field inventory"
            )
        turn_total += _nonnegative_int(
            stratum["meaningful_turn_count"],
            label=f"{label}.{era}.meaningful_turn_count",
        )
        episode_total += _nonnegative_int(
            stratum["meaningful_episode_count"],
            label=f"{label}.{era}.meaningful_episode_count",
        )
        stratum_metrics = _require_mapping(
            stratum["metrics"], label=f"{label}.{era}.metrics"
        )
        if set(stratum_metrics) != expected_metric_ids:
            raise RetainedInventoryError(
                f"{label}.{era} does not contain the canonical metric inventory"
            )
        for metric_id, metric in stratum_metrics.items():
            _validate_metric(metric_id, metric)
            metric_mapping = _require_mapping(
                metric, label=f"{label}.{era}.metrics.{metric_id}"
            )
            count_totals[metric_id] += int(metric_mapping["count"])
            denominator_totals[metric_id] += int(metric_mapping["denominator"])
    if turn_total != meaningful_turns or episode_total != meaningful_episodes:
        raise RetainedInventoryError(
            f"{label} does not conserve meaningful turn and episode counts"
        )
    for metric_id in expected_metric_ids:
        global_metric = _require_mapping(
            global_metrics[metric_id], label=f"trend_report.metrics.{metric_id}"
        )
        missing_scalar_lineage = (
            len(strata) > 1
            and metric_id in _UNLINEAGED_SCALAR_METRIC_IDS
            and global_metric["count"] > 0
        )
        if missing_scalar_lineage:
            for era, raw_stratum in strata.items():
                metric = _require_mapping(
                    _require_mapping(raw_stratum, label=f"{label}.{era}")["metrics"],
                    label=f"{label}.{era}.metrics",
                )[metric_id]
                metric_mapping = _require_mapping(
                    metric, label=f"{label}.{era}.metrics.{metric_id}"
                )
                if (
                    metric_mapping["available"]
                    or metric_mapping["count"] != 0
                    or metric_mapping["unavailable_reason"] != "missing_era_lineage"
                ):
                    raise RetainedInventoryError(
                        f"{label} fabricates era lineage for {metric_id}"
                    )
        elif count_totals[metric_id] != global_metric["count"]:
            raise RetainedInventoryError(
                f"{label} does not conserve count for {metric_id}"
            )
        if denominator_totals[metric_id] != global_metric["denominator"]:
            raise RetainedInventoryError(
                f"{label} does not conserve denominator for {metric_id}"
            )


def _validate_compatibility_key(
    value: Any,
    *,
    model_strata: Mapping[str, Any],
    policy_strata: Mapping[str, Any],
) -> Mapping[str, Any]:
    key = _require_mapping(value, label="trend_report.compatibility_key")
    expected_fields = {
        "configuration_ref",
        "model_eras",
        "model_policy_strata",
        "policy_eras",
    }
    if set(key) != expected_fields:
        raise RetainedInventoryError(
            "compatibility_key has an unexpected field inventory"
        )
    configuration_ref = key["configuration_ref"]
    if (
        not isinstance(configuration_ref, str)
        or configuration_ref == "configuration_ref_unavailable"
        or not configuration_ref.startswith("configuration_ref_v2:")
        or _OPAQUE_REF_RE.fullmatch(configuration_ref) is None
    ):
        raise RetainedInventoryError(
            "compatibility_key.configuration_ref is unavailable or invalid"
        )
    for field, strata in (("model_eras", model_strata), ("policy_eras", policy_strata)):
        declared = key[field]
        if (
            not isinstance(declared, list)
            or any(not isinstance(era, str) for era in declared)
            or declared != sorted(set(declared))
            or declared != sorted(strata)
        ):
            raise RetainedInventoryError(
                f"compatibility_key.{field} does not exactly match actual strata"
            )
    raw_joint = key["model_policy_strata"]
    if not isinstance(raw_joint, list):
        raise RetainedInventoryError("model-policy strata must be an array")
    pairs: list[tuple[str, str]] = []
    for raw_row in raw_joint:
        row = _require_mapping(raw_row, label="model-policy stratum")
        pair = (row.get("model_era"), row.get("policy_era"))
        if (
            set(row) != {"model_era", "policy_era"}
            or not all(isinstance(era, str) for era in pair)
            or pair[0] not in model_strata
            or pair[1] not in policy_strata
        ):
            raise RetainedInventoryError("model-policy stratum is invalid")
        pairs.append((pair[0], pair[1]))
    if pairs != sorted(set(pairs)) or (
        pairs
        and (
            {model for model, _policy in pairs} != set(model_strata)
            or {policy for _model, policy in pairs} != set(policy_strata)
        )
    ):
        raise RetainedInventoryError("model-policy strata are not canonical")
    return key


def _validate_report_bytes(
    data: bytes,
    *,
    coverage: Mapping[str, Any],
    trend: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RetainedPrivacyError("report.md must be deterministic ASCII") from exc
    if any(
        (
            _URL_RE.search(text),
            _EMAIL_RE.search(text),
            _LOCAL_PATH_RE.search(text),
            _SECRET_RE.search(text),
        )
    ):
        raise RetainedPrivacyError(
            "report.md contains a forbidden locator or credential-shaped value"
        )
    expected_headings = [
        f"## {index}. {title}"
        for index, (_section_id, title) in enumerate(REPORT_SECTIONS, 1)
    ]
    positions = [text.find(heading) for heading in expected_headings]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise RetainedInventoryError(
            "report.md is missing or reordering one of the fixed ten retrospective sections"
        )
    if data != _render_report(coverage, trend, summary):
        raise RetainedInventoryError(
            "report.md does not match the deterministic retained renderer"
        )


def _validate_closed_category_vector(
    value: Any,
    *,
    label: str,
    allowed: frozenset[str],
) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RetainedInventoryError(f"{label} must be a string vector")
    if value != sorted(set(value)):
        raise RetainedInventoryError(f"{label} must be uniquely ordered")
    unsupported = sorted(set(value) - allowed)
    if unsupported:
        raise RetainedInventoryError(
            f"{label} contains unsupported categories: {unsupported}"
        )
    return value


def _validate_aggregate_counts(value: Any) -> Mapping[str, Any]:
    aggregates = _require_mapping(value, label="trend_report.aggregate_counts")
    expected_fields = set(_AGGREGATE_COUNT_FIELDS) | set(_AGGREGATE_SCALAR_FIELDS)
    if set(aggregates) != expected_fields:
        raise RetainedInventoryError(
            "trend_report.aggregate_counts has an unexpected field inventory"
        )
    for field, allowed in _AGGREGATE_COUNT_FIELDS.items():
        _count_map(
            aggregates[field],
            label=f"trend_report.aggregate_counts.{field}",
            allowed=allowed,
        )
    for field in _AGGREGATE_SCALAR_FIELDS:
        _nonnegative_int(
            aggregates[field], label=f"trend_report.aggregate_counts.{field}"
        )
    return aggregates


def validate_prior_trend_report(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a standalone prior trend before it can affect comparisons."""

    trend = _require_mapping(value, label="prior_period.trend_report")
    if set(trend) != _TREND_FIELDS or trend.get("schema_version") != _SCHEMA_VERSION:
        raise RetainedInventoryError(
            "prior trend has an unexpected top-level field inventory"
        )
    validate_retained_value(trend, path="prior_period.trend_report")
    try:
        normalized_window = _normalize_window(
            trend.get("window"), label="prior_period.window"
        )
    except RetainedReportingError as exc:
        raise RetainedInventoryError("prior trend window is invalid") from exc
    if trend.get("window") != normalized_window:
        raise RetainedInventoryError("prior trend window is invalid")

    model_strata = _require_mapping(
        trend.get("model_eras"), label="prior_period.model_eras"
    )
    policy_strata = _require_mapping(
        trend.get("policy_eras"), label="prior_period.policy_eras"
    )
    _validate_compatibility_key(
        trend.get("compatibility_key"),
        model_strata=model_strata,
        policy_strata=policy_strata,
    )
    aggregates = _validate_aggregate_counts(trend.get("aggregate_counts"))
    metrics = _require_mapping(trend.get("metrics"), label="prior_period.metrics")
    expected_metrics = {
        *(f"turn_disposition.{item}" for item in TURN_DISPOSITIONS),
        "episode_disposition.review_gap",
        "episode_disposition.reviewed",
        "agents_guidance_candidates",
        "follow_up_actions",
        "prompt_improvements",
        "skill_candidates",
    }
    for family in ("events", "findings", "risks", "strengths"):
        expected_metrics.update(f"{family[:-1]}.{item}" for item in aggregates[family])
    if set(metrics) != expected_metrics:
        raise RetainedInventoryError("prior trend metric inventory is invalid")
    for metric_id, metric in metrics.items():
        _validate_metric(metric_id, metric)
    _validate_normalized_changes(trend.get("normalized_changes"), metrics)

    confidence = _require_mapping(
        trend.get("confidence"), label="prior_period.confidence"
    )
    if set(confidence) != {"comparability", "coverage", "extraction", "review"}:
        raise RetainedInventoryError("prior trend confidence inventory is invalid")
    for label, raw_dimension in confidence.items():
        dimension = _require_mapping(
            raw_dimension, label=f"prior_period.confidence.{label}"
        )
        if set(dimension) != {"denominator", "level", "numerator", "score"}:
            raise RetainedInventoryError("prior trend confidence dimension is invalid")
        numerator = _nonnegative_int(
            dimension["numerator"], label=f"prior_period.confidence.{label}.numerator"
        )
        denominator = _nonnegative_int(
            dimension["denominator"],
            label=f"prior_period.confidence.{label}.denominator",
        )
        if numerator > denominator:
            raise RetainedInventoryError("prior trend confidence ratio is invalid")
        if dimension["level"] == "unavailable":
            if dimension["score"] is not None or (
                label != "comparability" and denominator != 0
            ):
                raise RetainedInventoryError("unavailable confidence has a score")
            continue
        if denominator == 0:
            raise RetainedInventoryError("zero-evidence confidence must be unavailable")
        expected_score = round(numerator / denominator, 4)
        expected_level = (
            "high"
            if expected_score >= 0.9
            else "medium"
            if expected_score >= 0.6
            else "low"
        )
        if dimension["score"] != expected_score or dimension["level"] != expected_level:
            raise RetainedInventoryError("prior trend confidence is not reproducible")
    comparability_available = trend["normalized_changes"]["status"] == "compatible"
    if confidence["comparability"] != _confidence_dimension(
        1 if comparability_available else 0,
        1,
        available=comparability_available,
    ):
        raise RetainedInventoryError(
            "prior trend comparability confidence is inconsistent"
        )
    model_turns = sum(
        _nonnegative_int(
            _require_mapping(row, label=f"prior_period.model_eras.{era}")[
                "meaningful_turn_count"
            ],
            label=f"prior_period.model_eras.{era}.meaningful_turn_count",
        )
        for era, row in model_strata.items()
    )
    model_episodes = sum(
        _nonnegative_int(
            _require_mapping(row, label=f"prior_period.model_eras.{era}")[
                "meaningful_episode_count"
            ],
            label=f"prior_period.model_eras.{era}.meaningful_episode_count",
        )
        for era, row in model_strata.items()
    )
    _validate_era_strata(
        model_strata,
        label="prior_period.model_eras",
        meaningful_turns=model_turns,
        meaningful_episodes=model_episodes,
        global_metrics=metrics,
    )
    _validate_era_strata(
        policy_strata,
        label="prior_period.policy_eras",
        meaningful_turns=model_turns,
        meaningful_episodes=model_episodes,
        global_metrics=metrics,
    )
    return json.loads(canonical_json_bytes(trend))


def _validate_report_sections(value: Any) -> None:
    rows = _require_rows(value, label="summary.report_sections")
    if len(rows) != len(REPORT_SECTIONS):
        raise RetainedInventoryError(
            "summary.report_sections must contain the fixed ten sections"
        )
    expected_fields = {
        "confidence",
        "disposition",
        "event_kinds",
        "evidence_refs",
        "finding_kinds",
        "observation_count",
        "question_id",
        "schema_version",
        "section_id",
        "strength_kinds",
    }
    for index, (raw_row, question_id, (section_id, _title)) in enumerate(
        zip(rows, SYNTHESIS_QUESTION_IDS, REPORT_SECTIONS)
    ):
        row = _require_mapping(raw_row, label=f"summary.report_sections[{index}]")
        if set(row) != expected_fields:
            raise RetainedInventoryError(
                "summary report section has an unexpected field inventory"
            )
        if row["question_id"] != question_id or row["section_id"] != section_id:
            raise RetainedInventoryError(
                "summary report sections are not in canonical question order"
            )
        if row["schema_version"] != _SCHEMA_VERSION:
            raise RetainedInventoryError(
                "summary report section schema_version is not v2"
            )
        if row["disposition"] not in {"not_observed", "observed", "unavailable"}:
            raise RetainedInventoryError(
                "summary report section has an unsupported disposition"
            )
        if row["confidence"] not in {"low", "medium", "high"}:
            raise RetainedInventoryError(
                "summary report section has an unsupported confidence"
            )
        _validate_closed_category_vector(
            row["event_kinds"],
            label=f"summary.report_sections[{index}].event_kinds",
            allowed=EVENT_KINDS,
        )
        finding_kinds = (
            FINDING_KINDS | RISK_FLAGS
            if section_id == "safety_and_privacy"
            else FINDING_KINDS
        )
        _validate_closed_category_vector(
            row["finding_kinds"],
            label=f"summary.report_sections[{index}].finding_kinds",
            allowed=finding_kinds,
        )
        _validate_closed_category_vector(
            row["strength_kinds"],
            label=f"summary.report_sections[{index}].strength_kinds",
            allowed=STRENGTH_KINDS,
        )
        evidence_refs = row["evidence_refs"]
        if not isinstance(evidence_refs, list) or evidence_refs != sorted(
            set(evidence_refs)
        ):
            raise RetainedInventoryError(
                "summary report section evidence_refs must be uniquely ordered"
            )
        observation_count = _nonnegative_int(
            row["observation_count"],
            label=f"summary.report_sections[{index}].observation_count",
        )
        signal_count = sum(
            len(row[field])
            for field in ("event_kinds", "finding_kinds", "strength_kinds")
        )
        if observation_count < signal_count:
            raise RetainedInventoryError(
                "summary report section observation count is below its signal count"
            )
        if row["disposition"] == "observed" and (
            observation_count == 0 or not row["evidence_refs"]
        ):
            raise RetainedInventoryError(
                "observed summary report section requires evidence"
            )
        if row["disposition"] == "not_observed" and (
            observation_count or signal_count or row["evidence_refs"]
        ):
            raise RetainedInventoryError(
                "not_observed summary report section cannot carry observations"
            )


def validate_retained_artifacts(artifacts: Mapping[str, bytes]) -> dict[str, Any]:
    """Validate exact inventory, canonical bytes, privacy, and cross-file totals."""

    if not isinstance(artifacts, Mapping):
        raise RetainedInventoryError("retained artifacts must be a mapping")
    if set(artifacts) != set(RETAINED_ARTIFACT_NAMES):
        missing = sorted(set(RETAINED_ARTIFACT_NAMES) - set(artifacts))
        extra = sorted(set(artifacts) - set(RETAINED_ARTIFACT_NAMES))
        raise RetainedInventoryError(
            f"retained inventory mismatch: missing={missing}, extra={extra}"
        )
    total_bytes = 0
    for name in RETAINED_ARTIFACT_NAMES:
        data = artifacts[name]
        if not isinstance(data, bytes):
            raise RetainedInventoryError(f"{name} must be immutable bytes")
        if len(data) > MAX_RETAINED_ARTIFACT_BYTES:
            raise RetainedInventoryError(
                f"{name} exceeds the 256 MiB per-artifact limit"
            )
        total_bytes += len(data)
        if total_bytes > MAX_RETAINED_BUNDLE_BYTES:
            raise RetainedInventoryError(
                "retained bundle exceeds the 256 MiB aggregate limit"
            )

    parsed: dict[str, Any] = {}
    for name in JSON_ARTIFACT_NAMES:
        value = _json_loads_no_duplicates(artifacts[name], label=name)
        if not isinstance(value, dict):
            raise RetainedInventoryError(f"{name} must contain a JSON object")
        if canonical_json_bytes(value) != artifacts[name]:
            raise RetainedInventoryError(f"{name} is not canonically encoded")
        validate_retained_value(value, path=name)
        parsed[name.removesuffix(".json")] = value
    for name in JSONL_ARTIFACT_NAMES:
        parsed[name.removesuffix(".jsonl")] = _parse_jsonl(artifacts[name], label=name)

    manifest = parsed["manifest"]
    coverage = parsed["coverage"]
    trend = parsed["trend_report"]
    summary = parsed["summary"]
    episodes = parsed["episodes"]
    turn_findings = parsed["turn_findings"]
    topics = parsed["topics"]

    for label, rows, row_kind in (
        ("episodes.jsonl", episodes, "episode"),
        ("turn_findings.jsonl", turn_findings, "turn"),
        ("topics.jsonl", topics, "topic"),
    ):
        for index, row in enumerate(rows):
            _validate_retained_row_schema(
                row,
                row_kind=row_kind,
                label=f"{label}[{index}]",
            )

    for label, value, expected_fields in (
        ("manifest.json", manifest, _MANIFEST_FIELDS),
        ("coverage.json", coverage, _COVERAGE_FIELDS),
        ("trend_report.json", trend, _TREND_FIELDS),
        ("summary.json", summary, _SUMMARY_FIELDS),
    ):
        if set(value) != expected_fields:
            raise RetainedInventoryError(
                f"{label} has an unexpected top-level field inventory"
            )
    if manifest.get("artifact_inventory") != list(RETAINED_ARTIFACT_NAMES):
        raise RetainedInventoryError(
            "manifest artifact_inventory is not the fixed eight-artifact inventory"
        )
    if manifest.get("schema_version") != _SCHEMA_VERSION:
        raise RetainedInventoryError("manifest schema_version is not v2")
    if not isinstance(manifest.get("durable_state"), Mapping) or (
        manifest["durable_state"].get("schema") != "durable_history_state_v2"
    ):
        raise RetainedInventoryError("manifest durable_state is invalid")
    _validate_retained_provenance(manifest.get("provenance"))
    expected_row_counts = _artifact_row_counts(episodes, turn_findings, topics)
    if manifest.get("row_counts") != expected_row_counts:
        raise RetainedInventoryError("manifest row_counts do not match JSONL artifacts")
    digest_record = manifest.get("retained_bundle_digest_v2")
    if not isinstance(digest_record, Mapping) or set(digest_record) != {
        "algorithm",
        "value",
        "version",
    }:
        raise RetainedInventoryError(
            "manifest retained_bundle_digest_v2 has an invalid grammar"
        )
    if (
        digest_record.get("algorithm") != "sha256"
        or digest_record.get("version") != _SCHEMA_VERSION
    ):
        raise RetainedInventoryError(
            "manifest retained_bundle_digest_v2 algorithm/version mismatch"
        )
    if not isinstance(digest_record.get("value"), str) or not _HEX_64_RE.fullmatch(
        digest_record["value"]
    ):
        raise RetainedInventoryError(
            "manifest retained_bundle_digest_v2 value is not lowercase SHA-256"
        )
    if digest_record["value"] != retained_bundle_digest(artifacts):
        raise RetainedInventoryError(
            "manifest retained_bundle_digest_v2 does not match bundle bytes"
        )

    finding_refs = [row.get("turn_ref") for row in turn_findings]
    if finding_refs != sorted(finding_refs) or len(finding_refs) != len(
        set(finding_refs)
    ):
        raise RetainedInventoryError(
            "turn_findings.jsonl is not uniquely ordered by turn_ref"
        )
    if coverage.get("meaningful_turn_refs") != finding_refs:
        raise RetainedInventoryError(
            "coverage meaningful turns and turn findings do not reconcile"
        )
    if coverage.get("schema_version") != _SCHEMA_VERSION:
        raise RetainedInventoryError("coverage schema_version is not v2")
    if coverage["turns"].get("meaningful") != len(turn_findings):
        raise RetainedInventoryError(
            "coverage meaningful turn count does not match turn findings"
        )
    actual_turn_dispositions = Counter(row.get("disposition") for row in turn_findings)
    for disposition in TURN_DISPOSITIONS:
        if (
            coverage["turn_dispositions"].get(disposition)
            != actual_turn_dispositions[disposition]
        ):
            raise RetainedInventoryError(
                "coverage turn disposition counts do not reconcile"
            )
    actual_episode_dispositions = Counter(
        row.get("review_disposition") for row in episodes
    )
    meaningful_episode_count = sum(
        1 for row in episodes if row.get("review_disposition") != "review_not_required"
    )
    for disposition in EPISODE_REVIEW_DISPOSITIONS:
        if (
            coverage["episode_dispositions"].get(disposition)
            != actual_episode_dispositions[disposition]
        ):
            raise RetainedInventoryError(
                "coverage episode disposition counts do not reconcile"
            )
    if coverage["episode_dispositions"].get("meaningful") != meaningful_episode_count:
        raise RetainedInventoryError(
            "coverage meaningful episode count does not reconcile"
        )
    if coverage["episode_dispositions"].get("total") != len(episodes):
        raise RetainedInventoryError("coverage total episode count does not reconcile")
    source_units = coverage["source_units"]
    if source_units["expected"] != (
        source_units["consumed_candidate"]
        + source_units["structurally_excluded"]
        + source_units["explicit_gap"]
    ):
        raise RetainedInventoryError(
            "coverage source-unit accounting does not reconcile"
        )
    if coverage["turns"]["extraction_accepted"] != (
        coverage["turns"]["meaningful"]
        + coverage["turns"]["context_only"]
        + coverage["turns"]["meaningfulness_gap"]
    ):
        raise RetainedInventoryError(
            "coverage extraction-accepted turn accounting does not reconcile"
        )
    expected_coverage_complete = (
        source_units["explicit_gap"] == 0
        and not coverage["gaps"]
        and coverage["turns"]["extraction_gap"] == 0
        and coverage["turns"]["meaningfulness_gap"] == 0
        and coverage["turn_dispositions"]["turn_review_gap"] == 0
        and coverage["episode_dispositions"]["review_gap"] == 0
    )
    if coverage["coverage_complete"] != expected_coverage_complete:
        raise RetainedInventoryError(
            "coverage_complete does not match terminal dispositions"
        )
    episode_refs = [row.get("episode_ref") for row in episodes]
    topic_refs = [row.get("topic_ref") for row in topics]
    if episode_refs != sorted(episode_refs) or len(episode_refs) != len(
        set(episode_refs)
    ):
        raise RetainedInventoryError(
            "episodes.jsonl is not uniquely ordered by episode_ref"
        )
    if any(
        row.get("schema_version") != _SCHEMA_VERSION
        or row.get("review_disposition") not in EPISODE_REVIEW_DISPOSITIONS
        for row in episodes
    ):
        raise RetainedInventoryError(
            "episode has an invalid schema or review disposition"
        )
    if topic_refs != sorted(topic_refs) or len(topic_refs) != len(set(topic_refs)):
        raise RetainedInventoryError(
            "topics.jsonl is not uniquely ordered by topic_ref"
        )
    if any(row.get("schema_version") != _SCHEMA_VERSION for row in topics):
        raise RetainedInventoryError("topic schema_version is not v2")
    episodes_by_ref = {row["episode_ref"]: row for row in episodes}
    _validate_turn_episode_era_lineage(episodes, turn_findings)
    for index, row in enumerate(episodes):
        exact_counts = dict(
            sorted(Counter(item["kind"] for item in row["findings"]).items())
        )
        if row["finding_counts"] != exact_counts:
            raise RetainedInventoryError(
                f"episodes.jsonl[{index}] finding counts lose exact evidence"
            )
    for index, row in enumerate(topics):
        if row["findings"] != _expected_topic_findings(
            row,
            episodes_by_ref,
            label=f"topics.jsonl[{index}]",
        ):
            raise RetainedInventoryError(
                "topic findings do not preserve exact episode evidence references"
            )
        for lineage in row["episode_lineage"]:
            episode = episodes_by_ref.get(lineage["episode_ref"])
            if episode is None or episode.get("session_ref") != lineage["session_ref"]:
                raise RetainedInventoryError(
                    "topic episode lineage does not match retained episodes"
                )
    if manifest.get("publication_role") == "standalone":
        episode_ref_set = set(episode_refs)
        for row in turn_findings:
            if row.get("episode_ref") not in episode_ref_set:
                raise RetainedInventoryError(
                    "standalone turn finding references an absent episode"
                )
        for row in topics:
            referenced = row.get("episode_refs", [])
            if (
                not isinstance(referenced, list)
                or not set(referenced) <= episode_ref_set
            ):
                raise RetainedInventoryError(
                    "standalone topic references an absent episode"
                )
    if summary.get("report_section_count") != len(REPORT_SECTIONS):
        raise RetainedInventoryError("summary report_section_count must be ten")
    if (
        trend.get("schema_version") != _SCHEMA_VERSION
        or summary.get("schema_version") != _SCHEMA_VERSION
    ):
        raise RetainedInventoryError("trend or summary schema_version is not v2")
    _validate_report_sections(summary.get("report_sections"))
    summary_findings = _finding_records(
        summary.get("findings"),
        label="summary.findings",
    )
    if summary.get("findings") != summary_findings or summary_findings != (
        _expected_global_findings(episodes, topics)
    ):
        raise RetainedInventoryError(
            "summary findings do not preserve exact topic evidence references"
        )
    for field, allowed in (
        ("guidance_candidates", GUIDANCE_KINDS),
        ("skill_candidates", SKILL_CANDIDATE_KINDS),
    ):
        candidates = _durable_candidate_records(
            summary.get(field),
            label=f"summary.{field}",
            allowed_kinds=allowed,
            episodes_by_ref=episodes_by_ref,
        )
        if summary.get(field) != candidates:
            raise RetainedInventoryError(
                f"summary.{field} is not canonically lineage-bound"
            )
    if summary.get("counts", {}).get("episodes") != len(episodes):
        raise RetainedInventoryError("summary episode count does not reconcile")
    if summary.get("counts", {}).get("turn_findings") != len(turn_findings):
        raise RetainedInventoryError("summary turn-finding count does not reconcile")
    if summary.get("counts", {}).get("topics") != len(topics):
        raise RetainedInventoryError("summary topic count does not reconcile")
    if (
        summary.get("counts", {}).get("meaningful_turns")
        != coverage["turns"]["meaningful"]
    ):
        raise RetainedInventoryError("summary meaningful turn count does not reconcile")
    if (
        summary.get("counts", {}).get("meaningful_episodes")
        != coverage["episode_dispositions"]["meaningful"]
    ):
        raise RetainedInventoryError(
            "summary meaningful episode count does not reconcile"
        )
    if summary.get("counts", {}).get("strengths") != sum(
        trend["aggregate_counts"]["strengths"].values()
    ):
        raise RetainedInventoryError("summary strength count does not reconcile")
    if summary.get("confidence") != trend.get("confidence"):
        raise RetainedInventoryError("summary and trend confidence values differ")
    if summary.get("coverage_complete") != coverage.get("coverage_complete"):
        raise RetainedInventoryError("summary and coverage completeness values differ")
    if summary.get("window") != trend.get("window") or summary.get(
        "window"
    ) != manifest.get("window"):
        raise RetainedInventoryError("manifest, trend, and summary windows differ")
    if summary.get("mode") != manifest.get("mode") or summary.get(
        "run_ref"
    ) != manifest.get("run_ref"):
        raise RetainedInventoryError("manifest and summary run identity differ")
    if summary.get("normalized_change_status") != trend.get(
        "normalized_changes", {}
    ).get("status"):
        raise RetainedInventoryError(
            "summary normalized-change status does not match trend data"
        )
    if summary.get("model_eras") != sorted(trend.get("model_eras", {})):
        raise RetainedInventoryError(
            "summary model-era inventory does not match trend data"
        )
    if summary.get("policy_eras") != sorted(trend.get("policy_eras", {})):
        raise RetainedInventoryError(
            "summary policy-era inventory does not match trend data"
        )
    if manifest.get("compatibility_key") != trend.get("compatibility_key"):
        raise RetainedInventoryError("manifest and trend compatibility keys differ")
    model_strata = _require_mapping(
        trend.get("model_eras"), label="trend_report.model_eras"
    )
    policy_strata = _require_mapping(
        trend.get("policy_eras"), label="trend_report.policy_eras"
    )
    compatibility_key = _validate_compatibility_key(
        trend.get("compatibility_key"),
        model_strata=model_strata,
        policy_strata=policy_strata,
    )
    if (
        compatibility_key["configuration_ref"]
        != manifest["provenance"]["production_configuration_ref"]
    ):
        raise RetainedInventoryError(
            "compatibility configuration is not bound to validated provenance"
        )
    if compatibility_key["model_policy_strata"] != _model_policy_strata(
        episodes, turn_findings
    ):
        raise RetainedInventoryError(
            "model-policy strata are not reproducible from retained rows"
        )
    aggregate_counts = _validate_aggregate_counts(trend.get("aggregate_counts"))
    summary_finding_counts = Counter(item["kind"] for item in summary_findings)
    if aggregate_counts["findings"] != {
        key: summary_finding_counts[key] for key in aggregate_counts["findings"]
    }:
        raise RetainedInventoryError(
            "global finding counts do not match exact retained evidence"
        )
    row_aggregates = _canonical_row_aggregates(episodes, turn_findings)
    for field in ("events", "findings", "risks", "strengths"):
        if set(row_aggregates[field]) - set(aggregate_counts[field]) or (
            aggregate_counts[field]
            != {
                key: row_aggregates[field].get(key, 0)
                for key in aggregate_counts[field]
            }
        ):
            raise RetainedInventoryError(
                f"trend aggregate {field} do not reconcile with episode rows"
            )
    if aggregate_counts["prompt_improvements"] != row_aggregates["prompt_improvements"]:
        raise RetainedInventoryError(
            "trend prompt improvements do not reconcile with turn rows"
        )
    metrics = _require_mapping(trend.get("metrics"), label="trend_report.metrics")
    for metric_id, metric in metrics.items():
        _validate_metric(metric_id, metric)
    if metrics != _build_metrics(coverage, aggregate_counts):
        raise RetainedInventoryError(
            "trend metrics are not reproducible from coverage and aggregate counts"
        )
    _validate_normalized_changes(trend.get("normalized_changes"), metrics)
    if trend.get("confidence") != _build_confidence(
        coverage, trend["normalized_changes"]
    ):
        raise RetainedInventoryError(
            "trend confidence is not reproducible from coverage and comparability"
        )
    for label, field, era_field in (
        ("trend_report.model_eras", "model_eras", "model_era"),
        ("trend_report.policy_eras", "policy_eras", "policy_era"),
    ):
        declared_eras = compatibility_key[field]
        expected_strata = _stratify(
            era_field=era_field,
            declared_eras=declared_eras,
            episodes=episodes,
            turn_findings=turn_findings,
            coverage=coverage,
            aggregate_counts=aggregate_counts,
        )
        if trend[field] != expected_strata:
            raise RetainedInventoryError(
                f"{label} is not reproducible from retained rows"
            )
        _validate_era_strata(
            trend.get(field),
            label=label,
            meaningful_turns=coverage["turns"]["meaningful"],
            meaningful_episodes=coverage["episode_dispositions"]["meaningful"],
            global_metrics=metrics,
        )
    _validate_report_bytes(
        artifacts["report.md"], coverage=coverage, trend=trend, summary=summary
    )
    parsed["report"] = artifacts["report.md"].decode("ascii")
    return parsed
