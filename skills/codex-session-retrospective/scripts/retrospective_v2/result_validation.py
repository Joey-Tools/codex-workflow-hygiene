"""Validation and deterministic privacy filtering for v2 agent results.

This module validates run-local working-zone records. It deliberately accepts
only closed taxonomies and explicitly named generalized-text fields. Retained
artifacts still need the separate retained-language compiler and validator.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
import copy
import hashlib
import ipaddress
import json
import re
from typing import Any

from . import privacy_locators, source_overlap


EXTRACTOR_RESULT_SCHEMA = "extractor_result_v2"
EPISODE_REVIEW_RESULT_SCHEMA = "episode_review_result_v2"
ADJUDICATION_RESULT_SCHEMA = "episode_review_adjudication_result_v2"
TOPIC_INPUT_SCHEMA = "topic_input_v2"
TOPIC_RESULT_SCHEMA = "topic_reduction_result_v2"
SYNTHESIS_RESULT_SCHEMA = "global_synthesis_result_v2"

MAX_RESULT_BYTES = 64 * 1024
MAX_RESULT_DEPTH = 24
MAX_RESULT_NODES = 4_096
MAX_RESULT_CONTAINER_ITEMS = 256
MAX_RESULT_KEY_CHARS = 128
MAX_RESULT_STRING_CHARS = 4_096
MAX_RESULT_TOTAL_STRING_CHARS = 64 * 1024
MAX_SOURCE_OVERLAP_ITEMS = 256
MAX_SOURCE_OVERLAP_CHARS = 512 * 1024
MAX_GENERALIZED_TEXT_CHARS = 1_200
MAX_REWRITE_TEXT_CHARS = 2_000
MAX_TURNS_PER_RESULT = 20
MAX_SIGNALS_PER_KIND = 64
MAX_REFS_PER_FIELD = 128

CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})
SEVERITY_LEVELS = frozenset({"low", "medium", "high", "critical"})
OUTCOMES = frozenset({"completed", "partial", "blocked", "failed", "unknown"})

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

_SAFETY_EXCEPTION_EVENT_KINDS = frozenset(
    {
        "assumption_challenged",
        "auth_denial",
        "build_failure",
        "explicit_blocker",
        "failed_command",
        "incomplete_test",
        "lint_failure",
        "retry",
        "tool_failure",
        "user_correction",
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

QUESTION_IDS = (
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
FOLLOW_UP_KINDS = frozenset(
    {
        "create_skill",
        "investigate_risk",
        "repair_gap",
        "rerun_verification",
        "update_guidance",
    }
)

EXTRACTOR_GAP_REASONS = frozenset(
    {
        "evidence_conflict",
        "insufficient_evidence",
        "privacy_rejection",
        "unsupported_claim",
    }
)
REVIEW_GAP_REASONS = frozenset({"insufficient_support", "review_failure"})
ADJUDICATION_GAP_REASONS = frozenset({"conflicting_evidence", "insufficient_support"})
ADJUDICATION_ITEM_FIELDS = (
    "events",
    "findings",
    "strengths",
    "risk_flags",
    "high_impact_turns",
    "evidence_refs",
)
ADJUDICATION_ITEM_DISPOSITIONS = frozenset({"merged", "rejected", "selected"})
ADJUDICATION_ITEM_REASONS = frozenset(
    {
        "conflicting_evidence",
        "duplicate_supported",
        "insufficient_support",
        "lower_confidence",
        "retained_supported",
    }
)

_OPAQUE_REF_RE = re.compile(r"^[a-z][a-z0-9_]*_ref_v2:[0-9a-f]{64}$")
_SCHEMA_RE = re.compile(r"^[a-z][a-z0-9_]*_v2$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REDACTION_PLACEHOLDER_RE = re.compile(r"^\[REDACTED_[A-Z_]+\]$")

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "secret",
        re.compile(
            r"-----BEGIN (?P<private_key_label>(?:(?:RSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
            r"[\s\S]*?-----END (?P=private_key_label)-----"
        ),
        "[REDACTED_SECRET]",
    ),
    (
        "credential",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        "credential",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{30,})\b"),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        "credential",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        "credential",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{16,}\b"),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        "credential",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        "credential",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        "credential",
        re.compile(
            r"(?i)\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|token|password|passwd|secret)"
            r"\s*(?:=|:)\s*(?!\[?REDACTED)[\"']?[A-Za-z0-9._~+/=-]{8,}"
        ),
        "[REDACTED_CREDENTIAL]",
    ),
)

_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s<>\"']+")
_INTERNAL_HOST_RE = re.compile(
    r"(?i)(?:localhost|(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"[^/:]+\.(?:corp|home|internal|intranet|lan|local)(?::\d+)?)"
)
_LABELED_INTERNAL_HOST_RE = re.compile(
    r"(?i)\b(?:host|hostname|node|server)\s*(?:=|:)\s*"
    r"(?!\[REDACTED)[a-z0-9][a-z0-9._-]*(?::\d{1,5})?"
)
_EMAIL_RE = re.compile(
    r"(?i)(?<![a-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    r"(?![a-z0-9-])"
)
_PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})"
    r"[ .-]?\d{3}[ .-]?\d{4}(?![A-Za-z0-9])"
)
_LABELED_PERSONAL_ID_RE = re.compile(
    r"(?i)\b(?:account|customer|employee|person|user)[_ -]?(?:id|name)"
    r"\s*(?:=|:)\s*(?!\[REDACTED)[\"']?[A-Za-z0-9._@+-]{3,}"
)
_IPV4_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z.])"
    r"(?P<address>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    r"(?::(?P<port>[0-9]{1,5}))?"
    r"(?![0-9A-Za-z.])"
)
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:\[[0-9A-Za-z:.%_-]+\]|"
    r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Za-z:.%_-]*)(?![0-9A-Za-z])"
)
_PRIVATE_KEY_BOUNDARY_RE = re.compile(
    r"(?i)-----\s*(?:BEGIN|END)\s+(?:(?:RSA|EC|OPENSSH|ENCRYPTED)\s+)?"
    r"PRIVATE KEY\s*-----"
)
_UNIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?!/)"
    r"[A-Za-z0-9._~+@%=-]+(?:/[A-Za-z0-9._~+@%=-]+)*"
)
_RELATIVE_PATH_RE = re.compile(
    r"(?<![-A-Za-z0-9_.~+@%=/\\])(?:\.{1,2}[/\\])?"
    r"(?:[A-Za-z0-9_.~+@%=-]+[/\\])+[A-Za-z0-9_.~+@%=-]+"
    r"(?![A-Za-z0-9_.~+@%=-])"
)
_WINDOWS_PATH_RE = re.compile(
    r"(?i)\b[A-Z]:\\(?:[^\\\s\"'<>:|?*]+\\)*[^\\\s\"'<>:|?*]+"
)
_UNC_PATH_RE = re.compile(r"\\\\[^\\\s]+\\[^\s\"'<>:|?*]+")
_UUID_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"(?![A-Za-z0-9])"
)
_LONG_HEX_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:[0-9a-f]{24,})(?![A-Za-z0-9])")
_RAW_ID_LABEL_RE = re.compile(
    r"(?i)\b(?:session|thread|turn|message|tool[_ -]?call|request)[_ -]?id\s*(?:=|:)\s*"
    r"(?![a-z][a-z0-9_]*_ref_v2:)[A-Za-z0-9._:-]{6,}"
)
_CODE_FENCE_RE = re.compile(r"```[\s\S]*?```")

_FORBIDDEN_KEYS = frozenset(
    {
        "command_output",
        "content",
        "excerpt",
        "local_path",
        "original_prompt",
        "path",
        "prompt",
        "quote",
        "raw",
        "raw_content",
        "raw_id",
        "raw_payload",
        "raw_prompt",
        "raw_text",
        "source_path",
        "source_text",
        "stderr",
        "stdout",
        "tool_output",
        "tool_result",
        "transcript",
        "url",
        "user_prompt",
        "verbatim",
    }
)


class ResultValidationError(ValueError):
    """Raised when a v2 result violates its schema or privacy contract."""


@dataclass(frozen=True, order=True)
class LeakFinding:
    """Privacy-safe location of a deterministic leak detector match."""

    category: str
    path: str
    start: int
    end: int


def _error(path: str, message: str) -> ResultValidationError:
    return ResultValidationError(f"{path}: {message}")


def _path(parent: str, child: str | int) -> str:
    if isinstance(child, int):
        return f"{parent}[{child}]"
    return f"{parent}.{child}" if parent else child


def _normalized_key(key: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return value.replace("-", "_").casefold()


def _reject_forbidden_keys(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise _error(path, "object keys must be strings")
            normalized = _normalized_key(key)
            tokens = set(normalized.split("_"))
            if (
                normalized in _FORBIDDEN_KEYS
                or "excerpt" in tokens
                or "verbatim" in tokens
            ):
                raise _error(
                    path,
                    "contains a forbidden raw, excerpt, prompt, tool-output, path, or URL field",
                )
            if "raw" in tokens:
                raise _error(path, "contains a forbidden raw field")
            if "path" in tokens or "url" in tokens:
                raise _error(path, "contains a forbidden path or URL field")
            if "prompt" in tokens and normalized not in {
                "rewritten_prompt",
                "prompt_rewrites",
            }:
                raise _error(
                    path, "contains a prompt field other than rewritten_prompt"
                )
            if "tool" in tokens and ({"output", "result", "stdout", "stderr"} & tokens):
                raise _error(path, "contains a forbidden tool-output field")
            _reject_forbidden_keys(child, path=_path(path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_keys(child, path=_path(path, index))


def _reference_path_kind(path: tuple[str | int, ...]) -> str | None:
    for component in reversed(path):
        if not isinstance(component, str):
            continue
        normalized = _normalized_key(component)
        if normalized.endswith(("_hash", "_hashes")):
            return "hash"
        if normalized.endswith(("_ref", "_refs", "_commitment", "_commitments")):
            return "reference"
        return None
    return None


def _is_valid_reference_value(
    path: tuple[str | int, ...],
    value: str,
) -> bool:
    kind = _reference_path_kind(path)
    if kind == "hash":
        return _SHA256_RE.fullmatch(value) is not None
    if kind == "reference":
        return _OPAQUE_REF_RE.fullmatch(value) is not None
    return False


def _privacy_reference_values(
    *groups: Collection[str] | None,
) -> frozenset[str]:
    values: set[str] = set()
    for group in groups:
        if group is None:
            continue
        if isinstance(group, (str, bytes)) or any(
            not isinstance(value, str) for value in group
        ):
            raise _error("allowed_reference_values", "must contain only strings")
        values.update(group)
    return frozenset(values)


def _walk_strings(
    value: Any, path: tuple[str | int, ...] = ()
) -> Iterable[tuple[tuple[str | int, ...], str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key in sorted(value):
            yield from _walk_strings(value[key], path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_strings(child, path + (index,))


def _display_path(parts: tuple[str | int, ...]) -> str:
    path = "$"
    for part in parts:
        path = _path(path, part)
    return path


def _normalized_overlap_text(value: str) -> str:
    return " ".join(value.split()).casefold()


def source_overlap_query_chars(*values: Any) -> int:
    """Return the longest normalized result string needed for source windows."""

    maximum = 1
    for value in values:
        for _path_parts, text in _walk_strings(value):
            maximum = max(maximum, len(_normalized_overlap_text(text)))
    return maximum


def extractor_overlap_text_view(value: Any) -> dict[str, list[dict[str, str]]]:
    """Project only schema-authorized extractor prose for source-overlap scans."""

    if not isinstance(value, Mapping):
        return {"turns": []}
    turns = value.get("turns")
    if not isinstance(turns, list):
        return {"turns": []}
    projected: list[dict[str, str]] = []
    for turn in turns:
        if not isinstance(turn, Mapping):
            continue
        text = turn.get("generalized_working_text")
        if isinstance(text, str):
            projected.append({"generalized_working_text": text})
    return {"turns": projected}


_ROLLING_HASH_BASE = 257
_ROLLING_HASH_MASK = (1 << 64) - 1


def _rolling_window_hashes(value: str, width: int) -> Iterable[int]:
    if len(value) < width:
        return
    factor = pow(_ROLLING_HASH_BASE, width - 1, 1 << 64)
    digest = 0
    for character in value[:width]:
        digest = (digest * _ROLLING_HASH_BASE + ord(character)) & _ROLLING_HASH_MASK
    yield digest
    for index in range(width, len(value)):
        digest = (
            (digest - ord(value[index - width]) * factor) * _ROLLING_HASH_BASE
            + ord(value[index])
        ) & _ROLLING_HASH_MASK
        yield digest


@dataclass(frozen=True, slots=True)
class _SourceOverlapIndex:
    candidates: tuple[str, ...]
    six_word_excerpts: frozenset[str]
    window_hashes: frozenset[int]


def _build_source_overlap_index(candidates: Sequence[str]) -> _SourceOverlapIndex:
    normalized: list[str] = []
    six_word_excerpts: set[str] = set()
    window_hashes: set[int] = set()
    for candidate in candidates:
        normalized_candidate = _normalized_overlap_text(candidate)
        if not normalized_candidate or _REDACTION_PLACEHOLDER_RE.fullmatch(
            candidate.strip()
        ):
            continue
        normalized.append(normalized_candidate)
        words = normalized_candidate.split()
        for start in range(max(0, len(words) - 5)):
            excerpt = " ".join(words[start : start + 6])
            if len(excerpt) >= 24:
                six_word_excerpts.add(excerpt)
        window_hashes.update(_rolling_window_hashes(normalized_candidate, 32))
    return _SourceOverlapIndex(
        candidates=tuple(normalized),
        six_word_excerpts=frozenset(six_word_excerpts),
        window_hashes=frozenset(window_hashes),
    )


def _source_overlap(
    text: str,
    index: _SourceOverlapIndex,
) -> tuple[int, int] | None:
    normalized_text = _normalized_overlap_text(text)
    if source_overlap.contains_short_token(index.candidates, normalized_text):
        return (0, len(text))
    for normalized_candidate in index.candidates:
        if normalized_candidate == normalized_text:
            return (0, len(text))
        if (
            12 <= len(normalized_candidate) <= len(normalized_text)
            and normalized_candidate in normalized_text
        ):
            return (0, len(text))
        if (
            12 <= len(normalized_text) <= len(normalized_candidate)
            and normalized_text in normalized_candidate
        ):
            return (0, len(text))
    words = normalized_text.split()
    for start in range(max(0, len(words) - 5)):
        if " ".join(words[start : start + 6]) in index.six_word_excerpts:
            return (0, len(text))
    if any(
        digest in index.window_hashes
        for digest in _rolling_window_hashes(normalized_text, 32)
    ):
        return (0, len(text))
    return None


def _validate_source_texts(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or any(
        not isinstance(value, str) for value in values
    ):
        raise _error(label, "must be an array of strings")
    normalized = tuple(values)
    if len(normalized) > MAX_SOURCE_OVERLAP_ITEMS:
        raise _error(
            label,
            f"must contain at most {MAX_SOURCE_OVERLAP_ITEMS} source strings",
        )
    if sum(len(value) for value in normalized) > MAX_SOURCE_OVERLAP_CHARS:
        raise _error(
            label,
            f"must contain at most {MAX_SOURCE_OVERLAP_CHARS} source characters",
        )
    return normalized


def _validate_source_text_groups(
    original_prompts: Sequence[str],
    tool_outputs: Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    prompts = _validate_source_texts(original_prompts, label="original_prompts")
    outputs = _validate_source_texts(tool_outputs, label="tool_outputs")
    if sum(map(len, prompts)) + sum(map(len, outputs)) > MAX_SOURCE_OVERLAP_CHARS:
        raise _error(
            "source_overlap",
            f"must contain at most {MAX_SOURCE_OVERLAP_CHARS} source characters",
        )
    return prompts, outputs


def _is_ipv6_token(value: str) -> bool:
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    address = candidate.split("%", 1)[0]
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
    except ValueError:
        return False


def _is_ipv4_token(value: str) -> bool:
    address = value.split(":", 1)[0]
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address)
    except ValueError:
        return False


def _ipv4_matches(value: str) -> Iterable[re.Match[str]]:
    for match in _IPV4_CANDIDATE_RE.finditer(value):
        if _is_ipv4_token(match.group(0)):
            yield match


def _ipv6_matches(value: str) -> Iterable[re.Match[str]]:
    for match in _IPV6_CANDIDATE_RE.finditer(value):
        if _is_ipv6_token(match.group(0)):
            yield match


def scan_for_leaks(
    value: Any,
    *,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
    allowed_reference_values: Collection[str] = (),
) -> tuple[LeakFinding, ...]:
    """Return deterministic, privacy-safe leak locations without matched text."""

    original_prompts, tool_outputs = _validate_source_text_groups(
        original_prompts,
        tool_outputs,
    )
    prompt_index = _build_source_overlap_index(original_prompts)
    tool_index = _build_source_overlap_index(tool_outputs)
    allowed_values = _privacy_reference_values(allowed_reference_values)
    findings: set[LeakFinding] = set()
    for parts, text in _walk_strings(value):
        if not text or _REDACTION_PLACEHOLDER_RE.fullmatch(text.strip()):
            continue
        path = _display_path(parts)
        reference_field = _is_valid_reference_value(parts, text)
        overlap_exempt = reference_field and text in allowed_values
        for category, pattern, _replacement in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                findings.add(LeakFinding(category, path, match.start(), match.end()))
        for match in _URL_RE.finditer(text):
            category = (
                "internal_url" if _INTERNAL_HOST_RE.search(match.group(0)) else "url"
            )
            findings.add(LeakFinding(category, path, match.start(), match.end()))
        for match in privacy_locators.BARE_PRIVATE_LOCATOR_RE.finditer(text):
            findings.add(LeakFinding("internal_url", path, match.start(), match.end()))
        for match in privacy_locators.BARE_FQDN_RE.finditer(text):
            category = (
                "internal_url" if _INTERNAL_HOST_RE.search(match.group(0)) else "url"
            )
            findings.add(LeakFinding(category, path, match.start(), match.end()))
        for match in _LABELED_INTERNAL_HOST_RE.finditer(text):
            findings.add(LeakFinding("internal_host", path, match.start(), match.end()))
        for match in _ipv4_matches(text):
            findings.add(LeakFinding("ip_address", path, match.start(), match.end()))
        for match in _ipv6_matches(text):
            findings.add(LeakFinding("ip_address", path, match.start(), match.end()))
        for pattern in (_EMAIL_RE, _PHONE_RE, _LABELED_PERSONAL_ID_RE):
            for match in pattern.finditer(text):
                findings.add(
                    LeakFinding("personal_identifier", path, match.start(), match.end())
                )
        for pattern in (
            _RELATIVE_PATH_RE,
            _UNIX_PATH_RE,
            _WINDOWS_PATH_RE,
            _UNC_PATH_RE,
        ):
            for match in pattern.finditer(text):
                findings.add(LeakFinding("path", path, match.start(), match.end()))
        if not reference_field:
            for pattern in (_UUID_RE, _LONG_HEX_RE, _RAW_ID_LABEL_RE):
                for match in pattern.finditer(text):
                    findings.add(
                        LeakFinding("raw_id", path, match.start(), match.end())
                    )
        for match in _CODE_FENCE_RE.finditer(text):
            findings.add(LeakFinding("code", path, match.start(), match.end()))
        for match in _PRIVATE_KEY_BOUNDARY_RE.finditer(text):
            findings.add(
                LeakFinding("unredactable_secret", path, match.start(), match.end())
            )
        if not overlap_exempt:
            prompt_overlap = _source_overlap(text, prompt_index)
            if prompt_overlap is not None:
                findings.add(LeakFinding("original_prompt", path, *prompt_overlap))
            tool_overlap = _source_overlap(text, tool_index)
            if tool_overlap is not None:
                findings.add(LeakFinding("tool_output", path, *tool_overlap))
    return tuple(sorted(findings))


def _literal_redaction_pattern(value: str) -> re.Pattern[str] | None:
    normalized = " ".join(value.split())
    if not normalized:
        return None
    pieces = [re.escape(piece) for piece in normalized.split(" ")]
    return re.compile(r"\s+".join(pieces), re.IGNORECASE)


def _post_redact_text(
    text: str,
    *,
    original_prompt_patterns: Sequence[re.Pattern[str]],
    tool_output_patterns: Sequence[re.Pattern[str]],
    reference_field: bool,
    source_overlap_exempt: bool,
) -> str:
    redacted = text
    if not source_overlap_exempt:
        for pattern in original_prompt_patterns:
            redacted = pattern.sub("[REDACTED_ORIGINAL_PROMPT]", redacted)
        for pattern in tool_output_patterns:
            redacted = pattern.sub("[REDACTED_TOOL_OUTPUT]", redacted)
    for _category, pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    for pattern in (_EMAIL_RE, _PHONE_RE, _LABELED_PERSONAL_ID_RE):
        redacted = pattern.sub("[REDACTED_PERSONAL_IDENTIFIER]", redacted)
    redacted = _URL_RE.sub("[REDACTED_URL]", redacted)
    redacted = privacy_locators.BARE_PRIVATE_LOCATOR_RE.sub("[REDACTED_URL]", redacted)
    redacted = _LABELED_INTERNAL_HOST_RE.sub("[REDACTED_INTERNAL_HOST]", redacted)
    redacted = _IPV4_CANDIDATE_RE.sub(
        lambda match: (
            "[REDACTED_IP_ADDRESS]"
            if _is_ipv4_token(match.group(0))
            else match.group(0)
        ),
        redacted,
    )
    redacted = _IPV6_CANDIDATE_RE.sub(
        lambda match: (
            "[REDACTED_IP_ADDRESS]"
            if _is_ipv6_token(match.group(0))
            else match.group(0)
        ),
        redacted,
    )
    for pattern in (
        _RELATIVE_PATH_RE,
        _UNIX_PATH_RE,
        _WINDOWS_PATH_RE,
        _UNC_PATH_RE,
    ):
        redacted = pattern.sub("[REDACTED_PATH]", redacted)
    redacted = privacy_locators.BARE_FQDN_RE.sub("[REDACTED_URL]", redacted)
    if not reference_field:
        for pattern in (_UUID_RE, _LONG_HEX_RE, _RAW_ID_LABEL_RE):
            redacted = pattern.sub("[REDACTED_RAW_ID]", redacted)
    redacted = _CODE_FENCE_RE.sub("[REDACTED_CODE]", redacted)
    return redacted


def post_redact(
    value: Any,
    *,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
    allowed_reference_values: Collection[str] = (),
) -> Any:
    """Return a deep redacted copy while preserving opaque reference fields."""

    original_prompts, tool_outputs = _validate_source_text_groups(
        original_prompts,
        tool_outputs,
    )
    original_prompt_patterns = tuple(
        pattern
        for value in original_prompts
        if (pattern := _literal_redaction_pattern(value)) is not None
    )
    tool_output_patterns = tuple(
        pattern
        for value in tool_outputs
        if (pattern := _literal_redaction_pattern(value)) is not None
    )
    allowed_values = _privacy_reference_values(allowed_reference_values)

    def redact(child: Any, path: tuple[str | int, ...]) -> Any:
        if isinstance(child, str):
            reference_field = _is_valid_reference_value(path, child)
            return _post_redact_text(
                child,
                original_prompt_patterns=original_prompt_patterns,
                tool_output_patterns=tool_output_patterns,
                reference_field=reference_field,
                source_overlap_exempt=reference_field and child in allowed_values,
            )
        if isinstance(child, Mapping):
            return {key: redact(item, path + (key,)) for key, item in child.items()}
        if isinstance(child, list):
            return [redact(item, path + (index,)) for index, item in enumerate(child)]
        return copy.deepcopy(child)

    return redact(value, ())


def _require_mapping(value: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(path, "must be an object")
    return dict(value)


def _require_exact_keys(
    value: Mapping[str, Any],
    *,
    required: Collection[str],
    optional: Collection[str] = (),
    path: str,
) -> None:
    keys = set(value)
    missing = set(required) - keys
    unknown = keys - set(required) - set(optional)
    if missing:
        raise _error(path, f"missing required fields: {', '.join(sorted(missing))}")
    if unknown:
        raise _error(path, f"contains {len(unknown)} unknown field(s)")


def _require_string(
    value: Any, *, path: str, max_chars: int, allow_empty: bool = False
) -> str:
    if not isinstance(value, str):
        raise _error(path, "must be a string")
    normalized = " ".join(value.split())
    if not normalized and not allow_empty:
        raise _error(path, "must not be empty")
    if len(normalized) > max_chars:
        raise _error(path, f"must be at most {max_chars} characters")
    return normalized


def _require_bool(value: Any, *, path: str) -> bool:
    if not isinstance(value, bool):
        raise _error(path, "must be a boolean")
    return value


def _require_enum(value: Any, allowed: Collection[str], *, path: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise _error(path, f"must be one of: {', '.join(sorted(allowed))}")
    return value


def _require_list(value: Any, *, path: str, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise _error(path, "must be an array")
    if len(value) > maximum:
        raise _error(path, f"must contain at most {maximum} items")
    return value


def _require_unique_strings(
    value: Any,
    *,
    path: str,
    maximum: int,
    allowed: Collection[str] | None = None,
) -> list[str]:
    items = _require_list(value, path=path, maximum=maximum)
    if any(not isinstance(item, str) for item in items):
        raise _error(path, "must contain only strings")
    if len(set(items)) != len(items):
        raise _error(path, "must not contain duplicates")
    if allowed is not None:
        invalid = sorted(set(items) - set(allowed))
        if invalid:
            raise _error(path, "contains unsupported value(s)")
    return list(items)


def _merge_allowed_refs(
    allowed_refs: Collection[str] | None,
    allowed_references: Collection[str] | None,
    allowed_evidence_refs: Collection[str] | None,
) -> frozenset[str] | None:
    supplied = [
        value
        for value in (allowed_refs, allowed_references, allowed_evidence_refs)
        if value is not None
    ]
    if not supplied:
        return None
    merged: set[str] = set()
    for values in supplied:
        merged.update(values)
    return frozenset(merged)


def _require_ref(
    value: Any,
    *,
    path: str,
    allowed_refs: Collection[str] | None,
    expected_prefix: str,
) -> str:
    if not isinstance(value, str) or not _OPAQUE_REF_RE.fullmatch(value):
        raise _error(path, "must be an opaque v2 reference")
    prefix = f"{expected_prefix}_ref_v2:"
    if not value.startswith(prefix):
        raise _error(path, f"must use the {prefix} prefix")
    if allowed_refs is not None and value not in allowed_refs:
        raise _error(path, "reference is not in the job allow-list")
    return value


def _require_refs(
    value: Any,
    *,
    path: str,
    allowed_refs: Collection[str] | None,
    expected_prefix: str,
    minimum: int = 0,
) -> list[str]:
    refs = _require_unique_strings(value, path=path, maximum=MAX_REFS_PER_FIELD)
    if len(refs) < minimum:
        raise _error(path, f"must contain at least {minimum} reference(s)")
    for index, ref in enumerate(refs):
        _require_ref(
            ref,
            path=_path(path, index),
            allowed_refs=allowed_refs,
            expected_prefix=expected_prefix,
        )
    return refs


def _require_sha256(value: Any, *, path: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise _error(path, "must be a 64-character lowercase SHA-256 digest")
    return value


def _require_schema(value: Mapping[str, Any], expected: str, *, path: str) -> None:
    schema = value.get("schema")
    if (
        not isinstance(schema, str)
        or not _SCHEMA_RE.fullmatch(schema)
        or schema != expected
    ):
        raise _error(_path(path, "schema"), f"must equal {expected}")


def _require_json_size(
    value: Any, *, path: str, maximum: int = MAX_RESULT_BYTES
) -> None:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error(path, "must contain only JSON values") from exc
    if len(encoded) > maximum:
        raise _error(path, f"canonical JSON exceeds {maximum} bytes")


def validate_result_envelope(value: Any) -> None:
    """Reject structurally expensive result trees before privacy processing."""

    stack: list[tuple[Any, int, str]] = [(value, 0, "$")]
    nodes = 0
    total_string_chars = 0
    while stack:
        child, depth, path = stack.pop()
        nodes += 1
        if nodes > MAX_RESULT_NODES:
            raise _error("$", f"must contain at most {MAX_RESULT_NODES} JSON nodes")
        if depth > MAX_RESULT_DEPTH:
            raise _error(path, f"must be at most {MAX_RESULT_DEPTH} levels deep")
        if isinstance(child, Mapping):
            if len(child) > MAX_RESULT_CONTAINER_ITEMS:
                raise _error(
                    path,
                    f"must contain at most {MAX_RESULT_CONTAINER_ITEMS} fields",
                )
            for key, item in child.items():
                if not isinstance(key, str) or len(key) > MAX_RESULT_KEY_CHARS:
                    raise _error(path, "contains an invalid field name")
                total_string_chars += len(key)
                stack.append((item, depth + 1, _path(path, key)))
        elif isinstance(child, list):
            if len(child) > MAX_RESULT_CONTAINER_ITEMS:
                raise _error(
                    path,
                    f"must contain at most {MAX_RESULT_CONTAINER_ITEMS} items",
                )
            for index, item in enumerate(child):
                stack.append((item, depth + 1, _path(path, index)))
        elif isinstance(child, str):
            if len(child) > MAX_RESULT_STRING_CHARS:
                raise _error(
                    path,
                    f"must be at most {MAX_RESULT_STRING_CHARS} characters",
                )
            total_string_chars += len(child)
        elif child is None or isinstance(child, (bool, int)):
            pass
        elif isinstance(child, float):
            if child != child or child in {float("inf"), float("-inf")}:
                raise _error(path, "must be a finite JSON number")
        else:
            raise _error(path, "must contain only JSON values")
        if total_string_chars > MAX_RESULT_TOTAL_STRING_CHARS:
            raise _error(
                "$",
                f"must contain at most {MAX_RESULT_TOTAL_STRING_CHARS} string characters",
            )
    _require_json_size(value, path="$")


def canonical_result_hash(value: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 commitment for one validated result."""

    result = _require_mapping(value, path="result")
    try:
        encoded = json.dumps(
            result,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error("result", "must contain only JSON values") from exc
    return hashlib.sha256(encoded).hexdigest()


def _validate_signal_list(
    value: Any,
    *,
    path: str,
    kinds: Collection[str],
    allowed_refs: Collection[str] | None,
    evidence_prefix: str,
) -> None:
    signals = _require_list(value, path=path, maximum=MAX_SIGNALS_PER_KIND)
    identities: set[tuple[str, tuple[str, ...]]] = set()
    for index, item in enumerate(signals):
        item_path = _path(path, index)
        signal = _require_mapping(item, path=item_path)
        _require_exact_keys(
            signal,
            required={"kind", "evidence_refs", "confidence"},
            optional={"severity"},
            path=item_path,
        )
        kind = _require_enum(signal["kind"], kinds, path=_path(item_path, "kind"))
        refs = _require_refs(
            signal["evidence_refs"],
            path=_path(item_path, "evidence_refs"),
            allowed_refs=allowed_refs,
            expected_prefix=evidence_prefix,
            minimum=1,
        )
        _require_enum(
            signal["confidence"], CONFIDENCE_LEVELS, path=_path(item_path, "confidence")
        )
        if "severity" in signal:
            _require_enum(
                signal["severity"], SEVERITY_LEVELS, path=_path(item_path, "severity")
            )
        identity = (kind, tuple(refs))
        if identity in identities:
            raise _error(item_path, "duplicates a structured signal")
        identities.add(identity)


def _validate_high_impact_turns(
    value: Any,
    *,
    path: str,
    allowed_refs: Collection[str] | None,
    allowed_turn_refs: Collection[str] | None,
    evidence_prefix: str,
) -> None:
    records = _require_list(value, path=path, maximum=MAX_TURNS_PER_RESULT)
    seen_turns: set[str] = set()
    for index, item in enumerate(records):
        item_path = _path(path, index)
        record = _require_mapping(item, path=item_path)
        _require_exact_keys(
            record,
            required={
                "turn_ref",
                "problem_statement",
                "cause",
                "rewritten_prompt",
                "expected_effect",
                "evidence_refs",
                "confidence",
            },
            optional={"severity"},
            path=item_path,
        )
        turn_ref = _require_ref(
            record["turn_ref"],
            path=_path(item_path, "turn_ref"),
            allowed_refs=allowed_turn_refs
            if allowed_turn_refs is not None
            else allowed_refs,
            expected_prefix="turn",
        )
        if turn_ref in seen_turns:
            raise _error(item_path, "duplicates a high-impact turn")
        seen_turns.add(turn_ref)
        for field in (
            "problem_statement",
            "cause",
            "rewritten_prompt",
            "expected_effect",
        ):
            _require_string(
                record[field],
                path=_path(item_path, field),
                max_chars=MAX_REWRITE_TEXT_CHARS,
            )
        _require_refs(
            record["evidence_refs"],
            path=_path(item_path, "evidence_refs"),
            allowed_refs=allowed_refs,
            expected_prefix=evidence_prefix,
            minimum=1,
        )
        _require_enum(
            record["confidence"], CONFIDENCE_LEVELS, path=_path(item_path, "confidence")
        )
        if "severity" in record:
            _require_enum(
                record["severity"], SEVERITY_LEVELS, path=_path(item_path, "severity")
            )


def _privacy_prepare(
    result: Mapping[str, Any],
    *allowed_reference_groups: Collection[str] | None,
    original_prompts: Sequence[str],
    tool_outputs: Sequence[str],
) -> dict[str, Any]:
    validate_result_envelope(result)
    source = _require_mapping(result, path="$")
    _reject_forbidden_keys(source)
    allowed_reference_values = _privacy_reference_values(*allowed_reference_groups)
    sanitized = post_redact(
        source,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
        allowed_reference_values=allowed_reference_values,
    )
    leaks = scan_for_leaks(
        sanitized,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
        allowed_reference_values=allowed_reference_values,
    )
    if leaks:
        first = leaks[0]
        categories = ", ".join(sorted({finding.category for finding in leaks}))
        raise _error(first.path, f"post-redaction leak scan failed ({categories})")
    return sanitized


def validate_extractor_result(
    result: Mapping[str, Any],
    allowed_refs: Collection[str] | None = None,
    *,
    allowed_references: Collection[str] | None = None,
    allowed_evidence_refs: Collection[str] | None = None,
    turn_bindings: Mapping[str, Mapping[str, Any]] | None = None,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate and post-redact one ``extractor_result_v2`` object."""

    refs = _merge_allowed_refs(allowed_refs, allowed_references, allowed_evidence_refs)
    value = _privacy_prepare(
        result,
        refs,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    _require_exact_keys(
        value,
        required={"schema", "turns"},
        optional={"source_unit_ref", "gap_reason"},
        path="$",
    )
    _require_schema(value, EXTRACTOR_RESULT_SCHEMA, path="$")
    if "source_unit_ref" in value:
        _require_ref(
            value["source_unit_ref"],
            path="$.source_unit_ref",
            allowed_refs=refs,
            expected_prefix="source_unit",
        )
    if "gap_reason" in value:
        _require_enum(value["gap_reason"], EXTRACTOR_GAP_REASONS, path="$.gap_reason")
    turns = _require_list(value["turns"], path="$.turns", maximum=MAX_TURNS_PER_RESULT)
    if turns and "gap_reason" in value:
        raise _error("$.gap_reason", "is only allowed when turns is empty")
    if not turns and "gap_reason" not in value:
        raise _error("$", "an empty extractor result requires an explicit gap_reason")
    seen_turns: set[str] = set()
    for index, item in enumerate(turns):
        item_path = _path("$.turns", index)
        turn = _require_mapping(item, path=item_path)
        _require_exact_keys(
            turn,
            required={
                "turn_ref",
                "generalized_working_text",
                "events",
                "findings",
                "strengths",
                "risk_flags",
                "outcome",
                "confidence",
                "evidence_refs",
                "span_commitments",
            },
            optional={
                "goal_ref",
                "workstream_ref",
                "goal_change",
                "workstream_change",
                "task_completed",
                "user_redirect",
                "meaningfulness_hint",
                "conflicting_signals",
            },
            path=item_path,
        )
        turn_ref = _require_ref(
            turn["turn_ref"],
            path=_path(item_path, "turn_ref"),
            allowed_refs=refs,
            expected_prefix="turn",
        )
        if turn_ref in seen_turns:
            raise _error(item_path, "duplicates a turn_ref")
        seen_turns.add(turn_ref)
        binding: Mapping[str, Any] | None = None
        turn_refs = refs
        if turn_bindings is not None:
            binding = turn_bindings.get(turn_ref)
            if not isinstance(binding, Mapping):
                raise _error(
                    _path(item_path, "turn_ref"),
                    "is not bound to the extractor turn control manifest",
                )
            expected_evidence = binding.get("evidence_refs")
            expected_spans = binding.get("span_refs")
            if not isinstance(expected_evidence, list) or not isinstance(
                expected_spans, list
            ):
                raise _error(
                    _path(item_path, "turn_ref"),
                    "has an invalid extractor turn control binding",
                )
            bound_refs = {
                turn_ref,
                *expected_evidence,
                *expected_spans,
                binding.get("goal_ref"),
                binding.get("workstream_ref"),
            }
            if any(not isinstance(value, str) for value in bound_refs):
                raise _error(
                    _path(item_path, "turn_ref"),
                    "has an invalid extractor turn control reference",
                )
            turn_refs = bound_refs
        _require_string(
            turn["generalized_working_text"],
            path=_path(item_path, "generalized_working_text"),
            max_chars=MAX_GENERALIZED_TEXT_CHARS,
        )
        _validate_signal_list(
            turn["events"],
            path=_path(item_path, "events"),
            kinds=EVENT_KINDS,
            allowed_refs=turn_refs,
            evidence_prefix="evidence",
        )
        _validate_signal_list(
            turn["findings"],
            path=_path(item_path, "findings"),
            kinds=FINDING_KINDS,
            allowed_refs=turn_refs,
            evidence_prefix="evidence",
        )
        _validate_signal_list(
            turn["strengths"],
            path=_path(item_path, "strengths"),
            kinds=STRENGTH_KINDS,
            allowed_refs=turn_refs,
            evidence_prefix="evidence",
        )
        _require_unique_strings(
            turn["risk_flags"],
            path=_path(item_path, "risk_flags"),
            maximum=len(RISK_FLAGS),
            allowed=RISK_FLAGS,
        )
        _require_enum(turn["outcome"], OUTCOMES, path=_path(item_path, "outcome"))
        _require_enum(
            turn["confidence"], CONFIDENCE_LEVELS, path=_path(item_path, "confidence")
        )
        _require_refs(
            turn["evidence_refs"],
            path=_path(item_path, "evidence_refs"),
            allowed_refs=turn_refs,
            expected_prefix="evidence",
            minimum=1,
        )
        _require_refs(
            turn["span_commitments"],
            path=_path(item_path, "span_commitments"),
            allowed_refs=turn_refs,
            expected_prefix="span_commitment",
            minimum=1,
        )
        if binding is not None:
            if set(turn["evidence_refs"]) != set(binding["evidence_refs"]):
                raise _error(
                    _path(item_path, "evidence_refs"),
                    "must cover the exact turn fragment evidence",
                )
            if set(turn["span_commitments"]) != set(binding["span_refs"]):
                raise _error(
                    _path(item_path, "span_commitments"),
                    "must cover the exact turn fragment commitments",
                )
        if "goal_ref" in turn:
            goal_ref = _require_ref(
                turn["goal_ref"],
                path=_path(item_path, "goal_ref"),
                allowed_refs=turn_refs,
                expected_prefix="goal",
            )
            if binding is not None and goal_ref != binding["goal_ref"]:
                raise _error(
                    _path(item_path, "goal_ref"),
                    "must match the bound turn goal_ref",
                )
        if "workstream_ref" in turn:
            workstream_ref = _require_ref(
                turn["workstream_ref"],
                path=_path(item_path, "workstream_ref"),
                allowed_refs=turn_refs,
                expected_prefix="workstream",
            )
            if binding is not None and workstream_ref != binding["workstream_ref"]:
                raise _error(
                    _path(item_path, "workstream_ref"),
                    "must match the bound turn workstream_ref",
                )
        if "goal_change" in turn:
            _require_enum(
                turn["goal_change"],
                {
                    "completed_then_new",
                    "continues",
                    "new_goal",
                    "redirected",
                    "unknown",
                },
                path=_path(item_path, "goal_change"),
            )
        for field in (
            "workstream_change",
            "task_completed",
            "user_redirect",
            "conflicting_signals",
        ):
            if field in turn:
                _require_bool(turn[field], path=_path(item_path, field))
        if "meaningfulness_hint" in turn:
            _require_enum(
                turn["meaningfulness_hint"],
                {"context_only", "meaningful", "uncertain"},
                path=_path(item_path, "meaningfulness_hint"),
            )
    if turn_bindings is not None and "gap_reason" not in value:
        if seen_turns != set(turn_bindings):
            raise _error(
                "$.turns",
                "must cover every turn in the extractor control manifest",
            )
    return value


def _validate_review_common(
    value: Mapping[str, Any],
    *,
    schema: str,
    allowed_refs: Collection[str] | None,
    allowed_turn_refs: Collection[str] | None,
    adjudication: bool,
    expected_reviewer_slot: str | None = None,
) -> None:
    resolution_field = "resolution" if adjudication else "disposition"
    optional = {"gap_reason"}
    identity_fields = (
        set() if adjudication else {"attempt_ref", "reviewer_ref", "reviewer_slot"}
    )
    review_decision_fields = (
        set() if adjudication else {"second_review_recommended", "conflicting_signals"}
    )
    adjudication_fields = (
        {"candidate_item_decisions", "candidate_result_hashes"}
        if adjudication
        else set()
    )
    _require_exact_keys(
        value,
        required={
            "schema",
            "episode_ref",
            "episode_revision_ref",
            resolution_field,
            "events",
            "findings",
            "strengths",
            "risk_flags",
            "high_impact_turns",
            "evidence_refs",
            "confidence",
        }
        | identity_fields
        | review_decision_fields
        | adjudication_fields,
        optional=optional,
        path="$",
    )
    _require_schema(value, schema, path="$")
    _require_ref(
        value["episode_ref"],
        path="$.episode_ref",
        allowed_refs=allowed_refs,
        expected_prefix="episode",
    )
    _require_ref(
        value["episode_revision_ref"],
        path="$.episode_revision_ref",
        allowed_refs=allowed_refs,
        expected_prefix="episode_revision",
    )
    if adjudication:
        _require_enum(
            value[resolution_field],
            {
                "merged_supported",
                "primary_supported",
                "review_gap",
                "secondary_supported",
            },
            path=f"$.{resolution_field}",
        )
    else:
        _require_enum(
            value[resolution_field],
            {"review_gap", "reviewed"},
            path=f"$.{resolution_field}",
        )
    _validate_signal_list(
        value["events"],
        path="$.events",
        kinds=EVENT_KINDS,
        allowed_refs=allowed_refs,
        evidence_prefix="evidence",
    )
    _validate_signal_list(
        value["findings"],
        path="$.findings",
        kinds=FINDING_KINDS,
        allowed_refs=allowed_refs,
        evidence_prefix="evidence",
    )
    _validate_signal_list(
        value["strengths"],
        path="$.strengths",
        kinds=STRENGTH_KINDS,
        allowed_refs=allowed_refs,
        evidence_prefix="evidence",
    )
    _require_unique_strings(
        value["risk_flags"],
        path="$.risk_flags",
        maximum=len(RISK_FLAGS),
        allowed=RISK_FLAGS,
    )
    _validate_high_impact_turns(
        value["high_impact_turns"],
        path="$.high_impact_turns",
        allowed_refs=allowed_refs,
        allowed_turn_refs=allowed_turn_refs,
        evidence_prefix="evidence",
    )
    _require_refs(
        value["evidence_refs"],
        path="$.evidence_refs",
        allowed_refs=allowed_refs,
        expected_prefix="evidence",
    )
    confidence = _require_enum(
        value["confidence"], CONFIDENCE_LEVELS, path="$.confidence"
    )
    output_empty = not any(
        value[field]
        for field in (
            "events",
            "findings",
            "strengths",
            "risk_flags",
            "high_impact_turns",
            "evidence_refs",
        )
    )
    is_gap = value[resolution_field] == "review_gap"
    if "gap_reason" in value:
        reasons = ADJUDICATION_GAP_REASONS if adjudication else REVIEW_GAP_REASONS
        _require_enum(value["gap_reason"], reasons, path="$.gap_reason")
    if is_gap:
        if "gap_reason" not in value:
            raise _error(
                "$", f"{resolution_field}=review_gap requires an explicit gap_reason"
            )
        if not output_empty:
            raise _error(
                "$", "review_gap cannot carry structured decisions or evidence"
            )
        if confidence != "low":
            raise _error("$.confidence", "review_gap confidence must be low")
    else:
        if "gap_reason" in value:
            raise _error(
                "$.gap_reason", f"is only allowed when {resolution_field}=review_gap"
            )
        if output_empty:
            raise _error(
                "$", f"an empty {resolution_field} requires an explicit review_gap"
            )
    if not adjudication:
        reviewer_slot = _require_enum(
            value["reviewer_slot"], {"primary", "secondary"}, path="$.reviewer_slot"
        )
        if (
            expected_reviewer_slot is not None
            and reviewer_slot != expected_reviewer_slot
        ):
            raise _error("$.reviewer_slot", f"must equal {expected_reviewer_slot}")
        _require_ref(
            value["attempt_ref"],
            path="$.attempt_ref",
            allowed_refs=None,
            expected_prefix="attempt",
        )
        _require_ref(
            value["reviewer_ref"],
            path="$.reviewer_ref",
            allowed_refs=None,
            expected_prefix="reviewer",
        )
        for field in ("second_review_recommended", "conflicting_signals"):
            _require_bool(value[field], path=f"$.{field}")
        if is_gap and (
            value["second_review_recommended"] or value["conflicting_signals"]
        ):
            raise _error(
                "$", "review_gap cannot recommend or assert a structured conflict"
            )
    else:
        hashes = _require_unique_strings(
            value["candidate_result_hashes"],
            path="$.candidate_result_hashes",
            maximum=2,
        )
        if len(hashes) != 2:
            raise _error(
                "$.candidate_result_hashes", "must contain exactly two candidate hashes"
            )
        for index, digest in enumerate(hashes):
            _require_sha256(digest, path=_path("$.candidate_result_hashes", index))
        _require_list(
            value["candidate_item_decisions"],
            path="$.candidate_item_decisions",
            maximum=1_024,
        )


def validate_episode_review_result(
    result: Mapping[str, Any],
    allowed_refs: Collection[str] | None = None,
    *,
    allowed_references: Collection[str] | None = None,
    allowed_evidence_refs: Collection[str] | None = None,
    allowed_turn_refs: Collection[str] | None = None,
    expected_reviewer_slot: str | None = None,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate and post-redact one independent episode review."""

    refs = _merge_allowed_refs(allowed_refs, allowed_references, allowed_evidence_refs)
    value = _privacy_prepare(
        result,
        refs,
        allowed_turn_refs,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    _validate_review_common(
        value,
        schema=EPISODE_REVIEW_RESULT_SCHEMA,
        allowed_refs=refs,
        allowed_turn_refs=allowed_turn_refs,
        adjudication=False,
        expected_reviewer_slot=expected_reviewer_slot,
    )
    return value


def validate_hierarchical_episode_review_result(
    result: Mapping[str, Any],
    child_results: Sequence[Mapping[str, Any]],
    allowed_refs: Collection[str] | None = None,
    *,
    allowed_turn_refs: Collection[str] | None = None,
    expected_child_result_hashes: Sequence[str] = (),
    expected_reviewer_slot: str | None = None,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate a parent review without dropping material child risk evidence."""

    if not child_results:
        raise _error("child_results", "must not be empty")
    children = [
        validate_episode_review_result(
            child,
            allowed_refs,
            allowed_turn_refs=allowed_turn_refs,
            expected_reviewer_slot=expected_reviewer_slot,
            original_prompts=original_prompts,
            tool_outputs=tool_outputs,
        )
        for child in child_results
    ]
    child_hashes = [canonical_result_hash(child) for child in children]
    if expected_child_result_hashes and child_hashes != list(
        expected_child_result_hashes
    ):
        raise _error(
            "expected_child_result_hashes",
            "does not match the validated child review results",
        )
    output = validate_episode_review_result(
        result,
        allowed_refs,
        allowed_turn_refs=allowed_turn_refs,
        expected_reviewer_slot=expected_reviewer_slot,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    for field in ("episode_ref", "episode_revision_ref"):
        if any(child[field] != output[field] for child in children):
            raise _error(f"$.{field}", "must match every child review")

    required_evidence: set[str] = set()
    for field in ("events", "findings"):
        required = {
            _canonical_value(item): item
            for child in children
            for item in child[field]
            if item.get("severity") in {"high", "critical"}
        }
        retained = {_canonical_value(item) for item in output[field]}
        if not set(required) <= retained:
            raise _error(
                f"$.{field}",
                "hierarchical review dropped a high-severity child decision",
            )
        required_evidence.update(
            evidence_ref
            for item in required.values()
            for evidence_ref in item["evidence_refs"]
        )

    required_rewrites = {
        _canonical_value(item): item
        for child in children
        for item in child["high_impact_turns"]
    }
    retained_rewrites = {_canonical_value(item) for item in output["high_impact_turns"]}
    if not set(required_rewrites) <= retained_rewrites:
        raise _error(
            "$.high_impact_turns",
            "hierarchical review dropped a child high-impact adjudication",
        )
    required_evidence.update(
        evidence_ref
        for item in required_rewrites.values()
        for evidence_ref in item["evidence_refs"]
    )

    required_risk_flags = {flag for child in children for flag in child["risk_flags"]}
    if not required_risk_flags <= set(output["risk_flags"]):
        raise _error("$.risk_flags", "hierarchical review dropped a child risk flag")
    for child in children:
        if child["risk_flags"]:
            required_evidence.update(child["evidence_refs"])
    if not required_evidence <= set(output["evidence_refs"]):
        raise _error(
            "$.evidence_refs",
            "hierarchical review dropped child risk evidence",
        )
    if (
        any(child["second_review_recommended"] for child in children)
        and not output["second_review_recommended"]
    ):
        raise _error(
            "$.second_review_recommended",
            "hierarchical review dropped a child escalation decision",
        )
    if (
        any(child["conflicting_signals"] for child in children)
        and not output["conflicting_signals"]
    ):
        raise _error(
            "$.conflicting_signals",
            "hierarchical review dropped a child conflict decision",
        )
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    child_floor = min(
        (child["confidence"] for child in children),
        key=confidence_rank.__getitem__,
    )
    if confidence_rank[output["confidence"]] > confidence_rank[child_floor]:
        raise _error(
            "$.confidence",
            "hierarchical review cannot increase child review confidence",
        )
    return output


_REVIEW_DECISION_FIELDS = (
    "events",
    "findings",
    "strengths",
    "risk_flags",
    "high_impact_turns",
    "evidence_refs",
    "confidence",
)


def _canonical_value(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise _error("candidate_results", "must contain only JSON values") from exc


def _validated_candidate_pair(
    candidate_results: Sequence[Mapping[str, Any]],
    *,
    allowed_refs: Collection[str] | None,
    allowed_turn_refs: Collection[str] | None,
    original_prompts: Sequence[str],
    tool_outputs: Sequence[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if isinstance(candidate_results, (str, bytes)) or len(candidate_results) != 2:
        raise _error("candidate_results", "must contain exactly two review candidates")
    by_slot: dict[str, dict[str, Any]] = {}
    for index, candidate in enumerate(candidate_results):
        try:
            validated = validate_episode_review_result(
                candidate,
                allowed_refs,
                allowed_turn_refs=allowed_turn_refs,
                original_prompts=original_prompts,
                tool_outputs=tool_outputs,
            )
        except ResultValidationError as exc:
            raise _error(_path("candidate_results", index), str(exc)) from exc
        if validated["disposition"] != "reviewed":
            raise _error(
                _path("candidate_results", index),
                "adjudication candidates must be reviewed results",
            )
        slot = validated["reviewer_slot"]
        if slot in by_slot:
            raise _error(
                "candidate_results", "must contain one primary and one secondary review"
            )
        by_slot[slot] = validated
    if set(by_slot) != {"primary", "secondary"}:
        raise _error(
            "candidate_results", "must contain one primary and one secondary review"
        )
    primary = by_slot["primary"]
    secondary = by_slot["secondary"]
    for field in ("episode_ref", "episode_revision_ref"):
        if primary[field] != secondary[field]:
            raise _error("candidate_results", f"candidate {field} values do not match")
    if primary["attempt_ref"] == secondary["attempt_ref"]:
        raise _error(
            "candidate_results",
            "primary and secondary reviews must use distinct attempts",
        )
    if primary["reviewer_ref"] == secondary["reviewer_ref"]:
        raise _error(
            "candidate_results",
            "primary and secondary reviews must use distinct reviewers",
        )
    return primary, secondary


def _canonical_value_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_value(value).encode("utf-8")).hexdigest()


def _validate_candidate_item_decisions(
    adjudication: Mapping[str, Any],
    primary: Mapping[str, Any],
    secondary: Mapping[str, Any],
) -> None:
    candidates = (primary, secondary)
    candidate_hashes = tuple(
        canonical_result_hash(candidate) for candidate in candidates
    )
    retained = {
        field: {_canonical_value(item) for item in adjudication[field]}
        for field in ADJUDICATION_ITEM_FIELDS
    }
    support_counts = {
        (field, _canonical_value(item)): sum(
            _canonical_value(item)
            in {_canonical_value(other) for other in candidate[field]}
            for candidate in candidates
        )
        for field in ADJUDICATION_ITEM_FIELDS
        for candidate in candidates
        for item in candidate[field]
    }
    expected: list[tuple[str, Mapping[str, Any], str, Any]] = []
    for candidate_hash, candidate in zip(candidate_hashes, candidates, strict=True):
        for field in ADJUDICATION_ITEM_FIELDS:
            for item in candidate[field]:
                expected.append((candidate_hash, candidate, field, item))

    decisions = adjudication["candidate_item_decisions"]
    if len(decisions) != len(expected):
        raise _error(
            "$.candidate_item_decisions",
            "must account for every primary and secondary candidate item exactly once",
        )
    for index, (decision, expected_item) in enumerate(
        zip(decisions, expected, strict=True)
    ):
        item_path = _path("$.candidate_item_decisions", index)
        row = _require_mapping(decision, path=item_path)
        _require_exact_keys(
            row,
            required={
                "attempt_ref",
                "candidate_result_hash",
                "disposition",
                "field",
                "item_hash",
                "reason",
                "reviewer_ref",
                "reviewer_slot",
            },
            path=item_path,
        )
        candidate_hash, candidate, field, item = expected_item
        expected_identity = {
            "attempt_ref": candidate["attempt_ref"],
            "candidate_result_hash": candidate_hash,
            "field": field,
            "item_hash": _canonical_value_hash(item),
            "reviewer_ref": candidate["reviewer_ref"],
            "reviewer_slot": candidate["reviewer_slot"],
        }
        for key, expected_value in expected_identity.items():
            if row.get(key) != expected_value:
                raise _error(
                    _path(item_path, key),
                    "does not preserve the candidate item identity and provenance",
                )
        disposition = _require_enum(
            row["disposition"],
            ADJUDICATION_ITEM_DISPOSITIONS,
            path=_path(item_path, "disposition"),
        )
        reason = _require_enum(
            row["reason"],
            ADJUDICATION_ITEM_REASONS,
            path=_path(item_path, "reason"),
        )
        item_key = (field, _canonical_value(item))
        is_retained = item_key[1] in retained[field]
        if is_retained:
            if disposition == "selected" and reason != "retained_supported":
                raise _error(
                    item_path,
                    "selected candidate items require retained_supported",
                )
            if disposition == "merged" and (
                reason != "duplicate_supported" or support_counts[item_key] < 2
            ):
                raise _error(
                    item_path,
                    "merged candidate items require duplicate_supported provenance",
                )
            if disposition == "rejected":
                raise _error(item_path, "a retained candidate item cannot be rejected")
        else:
            if disposition != "rejected" or reason not in {
                "conflicting_evidence",
                "insufficient_support",
                "lower_confidence",
            }:
                raise _error(
                    item_path,
                    "an omitted candidate item requires an explicit rejection reason",
                )


def _validate_merged_decisions(
    adjudication: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
) -> None:
    for field in ADJUDICATION_ITEM_FIELDS:
        supported = {
            _canonical_value(item)
            for candidate in candidates
            for item in candidate[field]
        }
        for index, item in enumerate(adjudication[field]):
            if _canonical_value(item) not in supported:
                raise _error(
                    _path(f"$.{field}", index),
                    "adjudication invented or altered candidate data",
                )
    if adjudication["confidence"] not in {
        candidate["confidence"] for candidate in candidates
    }:
        raise _error("$.confidence", "adjudication altered candidate confidence")


def _validate_secondary_risk_preservation(
    adjudication: Mapping[str, Any],
    primary: Mapping[str, Any],
    secondary: Mapping[str, Any],
) -> None:
    def must_preserve(field: str, item: Mapping[str, Any]) -> bool:
        severity = item.get("severity")
        return severity == "critical" or (
            field in {"events", "findings"} and severity == "high"
        )

    if adjudication["resolution"] == "review_gap":
        has_high_severity_decision = any(
            must_preserve(field, item)
            for field in ("events", "findings", "strengths", "high_impact_turns")
            for item in secondary[field]
        )
        if has_high_severity_decision or secondary["risk_flags"]:
            raise _error(
                "$.resolution",
                "review gap cannot drop high-severity independent-review risk",
            )
        return
    for field in ("events", "findings", "strengths", "high_impact_turns"):
        retained = {_canonical_value(item) for item in adjudication[field]}
        required = {
            _canonical_value(item)
            for item in secondary[field]
            if must_preserve(field, item)
        }
        if not required <= retained:
            raise _error(
                f"$.{field}",
                "adjudication dropped a high-severity independent-review decision",
            )
    if not set(secondary["risk_flags"]) <= set(adjudication["risk_flags"]):
        raise _error(
            "$.risk_flags",
            "adjudication dropped an independent-review risk flag",
        )
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    expected_confidence = min(
        (primary["confidence"], secondary["confidence"]),
        key=confidence_rank.__getitem__,
    )
    if adjudication["confidence"] != expected_confidence:
        raise _error(
            "$.confidence",
            "adjudication cannot increase independent-review confidence",
        )


def validate_adjudication_result(
    result: Mapping[str, Any],
    allowed_refs: Collection[str] | None = None,
    *,
    allowed_references: Collection[str] | None = None,
    allowed_evidence_refs: Collection[str] | None = None,
    allowed_turn_refs: Collection[str] | None = None,
    candidate_results: Sequence[Mapping[str, Any]] = (),
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate a closed adjudication result and reject invented decisions."""

    refs = _merge_allowed_refs(allowed_refs, allowed_references, allowed_evidence_refs)
    primary, secondary = _validated_candidate_pair(
        candidate_results,
        allowed_refs=refs,
        allowed_turn_refs=allowed_turn_refs,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    expected_hashes = [canonical_result_hash(primary), canonical_result_hash(secondary)]
    value = _privacy_prepare(
        result,
        refs,
        allowed_turn_refs,
        expected_hashes,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    _validate_review_common(
        value,
        schema=ADJUDICATION_RESULT_SCHEMA,
        allowed_refs=refs,
        allowed_turn_refs=allowed_turn_refs,
        adjudication=True,
    )
    if (
        value["episode_ref"] != primary["episode_ref"]
        or value["episode_revision_ref"] != primary["episode_revision_ref"]
    ):
        raise _error("$", "adjudication is not bound to the candidate episode revision")
    if value["candidate_result_hashes"] != expected_hashes:
        raise _error(
            "$.candidate_result_hashes",
            "must bind the canonical primary and secondary candidate hashes in slot order",
        )
    resolution = value["resolution"]
    if resolution == "primary_supported":
        selected = primary
    elif resolution == "secondary_supported":
        selected = secondary
    else:
        selected = None
    if selected is not None:
        for field in _REVIEW_DECISION_FIELDS:
            if _canonical_value(value[field]) != _canonical_value(selected[field]):
                raise _error(
                    f"$.{field}",
                    f"{resolution} must preserve the selected candidate exactly",
                )
    elif resolution == "merged_supported":
        _validate_merged_decisions(value, (primary, secondary))
    _validate_candidate_item_decisions(value, primary, secondary)
    _validate_secondary_risk_preservation(value, primary, secondary)
    return value


def validate_topic_input(
    result: Mapping[str, Any],
    allowed_refs: Collection[str] | None = None,
    *,
    allowed_references: Collection[str] | None = None,
    allowed_evidence_refs: Collection[str] | None = None,
    allowed_turn_refs: Collection[str] | None = None,
    adjudication_candidate_results: Mapping[str, Sequence[Mapping[str, Any]]]
    | None = None,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate the complete bounded input for one topic reducer job."""

    refs = _merge_allowed_refs(allowed_refs, allowed_references, allowed_evidence_refs)
    value = _privacy_prepare(
        result,
        refs,
        allowed_turn_refs,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    _require_exact_keys(
        value,
        required={
            "adjudication_candidate_results",
            "schema",
            "workstream_ref",
            "episode_reviews",
            "episode_contexts",
            "expected_episode_revision_refs",
            "adjudication_required_episode_revision_refs",
        },
        optional={
            "topic_ref",
            "topic_candidate_ref",
            "model_configuration_ref",
            "evidence_refs",
        },
        path="$",
    )
    _require_schema(value, TOPIC_INPUT_SCHEMA, path="$")
    _require_ref(
        value["workstream_ref"],
        path="$.workstream_ref",
        allowed_refs=refs,
        expected_prefix="workstream",
    )
    topic_fields = {"topic_ref", "topic_candidate_ref"} & set(value)
    if len(topic_fields) != 1:
        raise _error("$", "exactly one of topic_ref or topic_candidate_ref is required")
    if "topic_ref" in value:
        _require_ref(
            value["topic_ref"],
            path="$.topic_ref",
            allowed_refs=refs,
            expected_prefix="topic",
        )
    if "topic_candidate_ref" in value:
        _require_ref(
            value["topic_candidate_ref"],
            path="$.topic_candidate_ref",
            allowed_refs=refs,
            expected_prefix="topic_candidate",
        )
    if "model_configuration_ref" in value:
        _require_ref(
            value["model_configuration_ref"],
            path="$.model_configuration_ref",
            allowed_refs=refs,
            expected_prefix="model_configuration",
        )
    if "evidence_refs" in value:
        _require_refs(
            value["evidence_refs"],
            path="$.evidence_refs",
            allowed_refs=refs,
            expected_prefix="evidence",
        )
    expected = _require_refs(
        value["expected_episode_revision_refs"],
        path="$.expected_episode_revision_refs",
        allowed_refs=refs,
        expected_prefix="episode_revision",
    )
    adjudication_required = _require_refs(
        value["adjudication_required_episode_revision_refs"],
        path="$.adjudication_required_episode_revision_refs",
        allowed_refs=refs,
        expected_prefix="episode_revision",
    )
    if not set(adjudication_required) <= set(expected):
        raise _error(
            "$.adjudication_required_episode_revision_refs",
            "must be a subset of expected_episode_revision_refs",
        )
    contexts = _require_list(
        value["episode_contexts"], path="$.episode_contexts", maximum=128
    )
    context_revision_refs: list[str] = []
    for index, context in enumerate(contexts):
        item_path = _path("$.episode_contexts", index)
        row = _require_mapping(context, path=item_path)
        _require_exact_keys(
            row,
            required={"episode_ref", "episode_revision_ref", "session_ref"},
            path=item_path,
        )
        _require_ref(
            row["episode_ref"],
            path=_path(item_path, "episode_ref"),
            allowed_refs=refs,
            expected_prefix="episode",
        )
        revision_ref = _require_ref(
            row["episode_revision_ref"],
            path=_path(item_path, "episode_revision_ref"),
            allowed_refs=refs,
            expected_prefix="episode_revision",
        )
        _require_ref(
            row["session_ref"],
            path=_path(item_path, "session_ref"),
            allowed_refs=refs,
            expected_prefix="session",
        )
        context_revision_refs.append(revision_ref)
    if len(context_revision_refs) != len(set(context_revision_refs)) or set(
        context_revision_refs
    ) != set(expected):
        raise _error(
            "$.episode_contexts",
            "must exactly cover expected_episode_revision_refs",
        )
    embedded_candidates = _require_mapping(
        value["adjudication_candidate_results"],
        path="$.adjudication_candidate_results",
    )
    candidate_map: dict[str, Sequence[Mapping[str, Any]]] = {}
    for revision_ref, candidates in embedded_candidates.items():
        _require_ref(
            revision_ref,
            path="$.adjudication_candidate_results",
            allowed_refs=refs,
            expected_prefix="episode_revision",
        )
        if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Sequence):
            raise _error(
                f"$.adjudication_candidate_results.{revision_ref}",
                "must contain exactly two candidate review results",
            )
        candidate_map[revision_ref] = candidates
    if adjudication_candidate_results is not None and _canonical_value(
        candidate_map
    ) != _canonical_value(adjudication_candidate_results):
        raise _error(
            "adjudication_candidate_results",
            "must exactly match the candidates embedded in topic_input_v2",
        )
    extra_candidate_refs = set(candidate_map) - set(adjudication_required)
    if extra_candidate_refs:
        raise _error(
            "adjudication_candidate_results", "contains an unexpected episode revision"
        )
    missing_candidate_refs = set(adjudication_required) - set(candidate_map)
    if missing_candidate_refs:
        raise _error(
            "adjudication_candidate_results",
            "is missing an adjudication-required episode revision",
        )
    reviews = _require_list(
        value["episode_reviews"], path="$.episode_reviews", maximum=128
    )
    if not reviews:
        raise _error("$.episode_reviews", "must not be empty")
    revision_refs: list[str] = []
    for index, review in enumerate(reviews):
        item_path = _path("$.episode_reviews", index)
        review_row = _require_mapping(review, path=item_path)
        revision_ref = _require_ref(
            review_row.get("episode_revision_ref"),
            path=_path(item_path, "episode_revision_ref"),
            allowed_refs=refs,
            expected_prefix="episode_revision",
        )
        try:
            if revision_ref in adjudication_required:
                if review_row.get("schema") != ADJUDICATION_RESULT_SCHEMA:
                    raise _error(item_path, "requires a resolved adjudication result")
                candidates = candidate_map.get(revision_ref)
                if candidates is None:
                    raise _error(
                        "adjudication_candidate_results",
                        f"is missing candidates for {revision_ref}",
                    )
                validated = validate_adjudication_result(
                    review_row,
                    refs,
                    allowed_turn_refs=allowed_turn_refs,
                    candidate_results=candidates,
                    original_prompts=original_prompts,
                    tool_outputs=tool_outputs,
                )
                if validated["resolution"] == "review_gap":
                    raise _error(
                        item_path, "topic input requires resolved adjudication"
                    )
            else:
                if review_row.get("schema") != EPISODE_REVIEW_RESULT_SCHEMA:
                    raise _error(
                        item_path, "adjudication is not declared for this revision"
                    )
                validated = validate_episode_review_result(
                    review_row,
                    refs,
                    allowed_turn_refs=allowed_turn_refs,
                    expected_reviewer_slot="primary",
                    original_prompts=original_prompts,
                    tool_outputs=tool_outputs,
                )
                if validated["disposition"] != "reviewed":
                    raise _error(
                        item_path, "topic input cannot consume an unresolved review gap"
                    )
        except ResultValidationError as exc:
            raise _error(item_path, str(exc)) from exc
        value["episode_reviews"][index] = validated
        revision_refs.append(validated["episode_revision_ref"])
    if len(set(revision_refs)) != len(revision_refs):
        raise _error("$.episode_reviews", "contains duplicate episode revisions")
    if set(expected) != set(revision_refs) or len(expected) != len(revision_refs):
        raise _error(
            "$.expected_episode_revision_refs", "must exactly cover episode_reviews"
        )
    return value


def build_topic_result(
    topic_input: Mapping[str, Any],
    *,
    topic_ref: str,
) -> dict[str, Any]:
    """Build the deterministic cross-episode aggregation for one topic input."""

    contexts = {
        row["episode_revision_ref"]: row for row in topic_input["episode_contexts"]
    }
    reviews = {
        row["episode_revision_ref"]: row for row in topic_input["episode_reviews"]
    }
    _require_enum(
        topic_ref,
        {topic_input.get("topic_ref", topic_ref)},
        path="topic_ref",
    )
    revision_refs = sorted(topic_input["expected_episode_revision_refs"])
    ordered_contexts = [contexts[revision_ref] for revision_ref in revision_refs]
    ordered_reviews = [reviews[revision_ref] for revision_ref in revision_refs]
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    result = {
        "confidence": min(
            (review["confidence"] for review in ordered_reviews),
            key=confidence_rank.__getitem__,
        ),
        "cross_session": len({context["session_ref"] for context in ordered_contexts})
        > 1,
        "episode_refs": sorted(
            {context["episode_ref"] for context in ordered_contexts}
        ),
        "episode_lineage": sorted(
            [
                {
                    "episode_ref": context["episode_ref"],
                    "session_ref": context["session_ref"],
                }
                for context in ordered_contexts
            ],
            key=lambda item: (item["episode_ref"], item["session_ref"]),
        ),
        "episode_revision_refs": revision_refs,
        "events": [
            copy.deepcopy(item)
            for review in ordered_reviews
            for item in review["events"]
        ],
        "evidence_refs": sorted(
            {
                evidence_ref
                for review in ordered_reviews
                for evidence_ref in review["evidence_refs"]
            }
        ),
        "findings": [
            copy.deepcopy(item)
            for review in ordered_reviews
            for item in review["findings"]
        ],
        "review_result_hashes": [
            canonical_result_hash(review) for review in ordered_reviews
        ],
        "risk_flags": sorted(
            {flag for review in ordered_reviews for flag in review["risk_flags"]}
        ),
        "schema": TOPIC_RESULT_SCHEMA,
        "session_refs": sorted(
            {context["session_ref"] for context in ordered_contexts}
        ),
        "strengths": [
            copy.deepcopy(item)
            for review in ordered_reviews
            for item in review["strengths"]
        ],
        "topic_ref": topic_ref,
        "workstream_ref": topic_input["workstream_ref"],
    }
    if "topic_candidate_ref" in topic_input:
        result["topic_candidate_ref"] = topic_input["topic_candidate_ref"]
    return result


def build_hierarchical_topic_result(
    child_topic_results: Sequence[Mapping[str, Any]],
    *,
    topic_candidate_ref: str,
    topic_ref: str,
    workstream_ref: str,
) -> dict[str, Any]:
    """Merge validated child topics without reconstructing oversized leaf input."""

    if not child_topic_results:
        raise _error("child_topic_results", "must not be empty")
    confidence_rank = {"low": 0, "medium": 1, "high": 2}

    def unique_values(field: str) -> list[Any]:
        values: dict[str, Any] = {}
        for child in child_topic_results:
            for item in child[field]:
                values.setdefault(_canonical_value(item), copy.deepcopy(item))
        return [values[key] for key in sorted(values)]

    for index, child in enumerate(child_topic_results):
        path = _path("child_topic_results", index)
        if not isinstance(child, Mapping) or child.get("schema") != TOPIC_RESULT_SCHEMA:
            raise _error(path, "must be a validated topic result")
        if (
            child.get("topic_candidate_ref") != topic_candidate_ref
            or child.get("topic_ref") != topic_ref
            or child.get("workstream_ref") != workstream_ref
        ):
            raise _error(path, "does not belong to the same topic hierarchy")

    episode_lineage = unique_values("episode_lineage")
    return {
        "confidence": min(
            (str(child["confidence"]) for child in child_topic_results),
            key=confidence_rank.__getitem__,
        ),
        "cross_session": len(
            {
                item["session_ref"]
                for item in episode_lineage
                if isinstance(item, Mapping)
            }
        )
        > 1,
        "episode_lineage": episode_lineage,
        "episode_refs": sorted(
            {
                str(value)
                for child in child_topic_results
                for value in child["episode_refs"]
            }
        ),
        "episode_revision_refs": sorted(
            {
                str(value)
                for child in child_topic_results
                for value in child["episode_revision_refs"]
            }
        ),
        "events": unique_values("events"),
        "evidence_refs": sorted(
            {
                str(value)
                for child in child_topic_results
                for value in child["evidence_refs"]
            }
        ),
        "findings": unique_values("findings"),
        "review_result_hashes": sorted(
            {
                str(value)
                for child in child_topic_results
                for value in child["review_result_hashes"]
            }
        ),
        "risk_flags": sorted(
            {
                str(value)
                for child in child_topic_results
                for value in child["risk_flags"]
            }
        ),
        "schema": TOPIC_RESULT_SCHEMA,
        "session_refs": sorted(
            {
                str(value)
                for child in child_topic_results
                for value in child["session_refs"]
            }
        ),
        "strengths": unique_values("strengths"),
        "topic_candidate_ref": topic_candidate_ref,
        "topic_ref": topic_ref,
        "workstream_ref": workstream_ref,
    }


def validate_hierarchical_topic_result(
    result: Mapping[str, Any],
    child_topic_results: Sequence[Mapping[str, Any]],
    allowed_refs: Collection[str] | None = None,
    *,
    expected_topic_candidate_ref: str,
    expected_topic_ref: str,
    expected_workstream_ref: str,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate one bounded parent topic against exact child result commitments."""

    refs = _merge_allowed_refs(allowed_refs, None, None)
    for value, path, prefix in (
        (
            expected_topic_candidate_ref,
            "expected_topic_candidate_ref",
            "topic_candidate",
        ),
        (expected_topic_ref, "expected_topic_ref", "topic"),
        (expected_workstream_ref, "expected_workstream_ref", "workstream"),
    ):
        _require_ref(value, path=path, allowed_refs=refs, expected_prefix=prefix)
    output = _privacy_prepare(
        result,
        refs,
        (
            expected_topic_candidate_ref,
            expected_topic_ref,
            expected_workstream_ref,
        ),
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    expected = build_hierarchical_topic_result(
        child_topic_results,
        topic_candidate_ref=expected_topic_candidate_ref,
        topic_ref=expected_topic_ref,
        workstream_ref=expected_workstream_ref,
    )
    if _canonical_value(output) != _canonical_value(expected):
        raise _error("$", "must exactly preserve the validated child topic results")
    return output


def validate_topic_result(
    result: Mapping[str, Any],
    topic_input: Mapping[str, Any],
    allowed_refs: Collection[str] | None = None,
    *,
    expected_topic_ref: str,
    allowed_turn_refs: Collection[str] | None = None,
    adjudication_candidate_results: Mapping[str, Sequence[Mapping[str, Any]]]
    | None = None,
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate an exact, non-no-op topic aggregation against its closed input."""

    refs = _merge_allowed_refs(allowed_refs, None, None)
    validated_input = validate_topic_input(
        topic_input,
        refs,
        allowed_turn_refs=allowed_turn_refs,
        adjudication_candidate_results=adjudication_candidate_results,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    topic_ref = _require_ref(
        expected_topic_ref,
        path="expected_topic_ref",
        allowed_refs=refs,
        expected_prefix="topic",
    )
    value = _privacy_prepare(
        result,
        refs,
        allowed_turn_refs,
        (topic_ref,),
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    expected = build_topic_result(validated_input, topic_ref=topic_ref)
    if _canonical_value(value) != _canonical_value(expected):
        raise _error("$", "must exactly preserve the validated topic aggregation")
    return value


def _validate_question_answers(
    value: Any, *, allowed_refs: Collection[str] | None
) -> None:
    answers = _require_list(value, path="$.question_answers", maximum=len(QUESTION_IDS))
    seen: set[str] = set()
    for index, item in enumerate(answers):
        item_path = _path("$.question_answers", index)
        answer = _require_mapping(item, path=item_path)
        _require_exact_keys(
            answer,
            required={
                "question_id",
                "disposition",
                "event_kinds",
                "finding_kinds",
                "strength_kinds",
                "evidence_refs",
                "confidence",
            },
            path=item_path,
        )
        question_id = _require_enum(
            answer["question_id"], QUESTION_IDS, path=_path(item_path, "question_id")
        )
        if question_id in seen:
            raise _error(item_path, "duplicates a retrospective question")
        seen.add(question_id)
        _require_enum(
            answer["disposition"],
            {"not_observed", "observed", "unavailable"},
            path=_path(item_path, "disposition"),
        )
        _require_unique_strings(
            answer["event_kinds"],
            path=_path(item_path, "event_kinds"),
            maximum=len(EVENT_KINDS),
            allowed=EVENT_KINDS,
        )
        _require_unique_strings(
            answer["finding_kinds"],
            path=_path(item_path, "finding_kinds"),
            maximum=len(FINDING_KINDS),
            allowed=FINDING_KINDS,
        )
        _require_unique_strings(
            answer["strength_kinds"],
            path=_path(item_path, "strength_kinds"),
            maximum=len(STRENGTH_KINDS),
            allowed=STRENGTH_KINDS,
        )
        evidence_refs = _require_refs(
            answer["evidence_refs"],
            path=_path(item_path, "evidence_refs"),
            allowed_refs=allowed_refs,
            expected_prefix="episode",
        )
        _require_enum(
            answer["confidence"], CONFIDENCE_LEVELS, path=_path(item_path, "confidence")
        )
        signal_count = (
            len(answer["event_kinds"])
            + len(answer["finding_kinds"])
            + len(answer["strength_kinds"])
        )
        if answer["disposition"] == "observed" and (
            not evidence_refs or signal_count == 0
        ):
            raise _error(
                item_path,
                "observed answers require a closed signal and evidence reference",
            )
        if answer["disposition"] == "not_observed" and (evidence_refs or signal_count):
            raise _error(
                item_path, "not_observed answers cannot carry signals or evidence"
            )
    if seen != set(QUESTION_IDS):
        raise _error(
            "$.question_answers",
            "must contain each of the ten retrospective questions exactly once",
        )


def _validate_durable_candidates(
    value: Any,
    *,
    path: str,
    kinds: Collection[str],
    allowed_refs: Collection[str] | None,
    independent_reviews_by_hash: Mapping[str, Mapping[str, Any]],
    episode_sessions: Mapping[str, str],
) -> None:
    candidates = _require_list(value, path=path, maximum=64)
    for index, item in enumerate(candidates):
        item_path = _path(path, index)
        candidate = _require_mapping(item, path=item_path)
        _require_exact_keys(
            candidate,
            required={
                "kind",
                "episode_lineage",
                "confidence",
                "exception",
            },
            optional={"independent_review_hash"},
            path=item_path,
        )
        _require_enum(candidate["kind"], kinds, path=_path(item_path, "kind"))
        lineage = _require_list(
            candidate["episode_lineage"],
            path=_path(item_path, "episode_lineage"),
            maximum=128,
        )
        if not lineage:
            raise _error(item_path, "durable candidate lineage must not be empty")
        episode_refs: list[str] = []
        session_refs: list[str] = []
        for lineage_index, raw_lineage in enumerate(lineage):
            lineage_path = _path(_path(item_path, "episode_lineage"), lineage_index)
            row = _require_mapping(raw_lineage, path=lineage_path)
            _require_exact_keys(
                row,
                required={"episode_ref", "session_ref"},
                path=lineage_path,
            )
            episode_ref = _require_ref(
                row["episode_ref"],
                path=_path(lineage_path, "episode_ref"),
                allowed_refs=allowed_refs,
                expected_prefix="episode",
            )
            session_ref = _require_ref(
                row["session_ref"],
                path=_path(lineage_path, "session_ref"),
                allowed_refs=allowed_refs,
                expected_prefix="session",
            )
            if episode_ref in episode_refs:
                raise _error(lineage_path, "duplicates an episode lineage")
            if episode_sessions.get(episode_ref) != session_ref:
                raise _error(
                    lineage_path,
                    "does not match the validated topic episode/session lineage",
                )
            episode_refs.append(episode_ref)
            session_refs.append(session_ref)
        _require_enum(
            candidate["confidence"],
            CONFIDENCE_LEVELS,
            path=_path(item_path, "confidence"),
        )
        exception = _require_enum(
            candidate["exception"],
            {"high_severity_safety", "none"},
            path=_path(item_path, "exception"),
        )
        if exception == "none" and (
            len(set(episode_refs)) < 3 or len(set(session_refs)) < 2
        ):
            raise _error(
                item_path,
                "durable candidates require three episode lineages across two sessions",
            )
        if exception == "none" and "independent_review_hash" in candidate:
            raise _error(
                _path(item_path, "independent_review_hash"),
                "is only allowed for the high_severity_safety exception",
            )
        if exception == "high_severity_safety":
            if "independent_review_hash" not in candidate:
                raise _error(
                    item_path,
                    "the safety exception requires a bound independent review hash",
                )
            review_hash = _require_sha256(
                candidate["independent_review_hash"],
                path=_path(item_path, "independent_review_hash"),
            )
            review = independent_reviews_by_hash.get(review_hash)
            if review is None:
                raise _error(
                    _path(item_path, "independent_review_hash"),
                    "does not bind a supplied validated independent review",
                )
            if review["episode_ref"] not in episode_refs:
                raise _error(
                    item_path,
                    "the independent review episode is not in episode_lineage",
                )
            severe = any(
                item.get("severity") in {"high", "critical"}
                and (
                    field in {"findings", "high_impact_turns"}
                    or (
                        field == "events"
                        and item.get("kind") in _SAFETY_EXCEPTION_EVENT_KINDS
                    )
                )
                for field in ("events", "findings", "high_impact_turns")
                for item in review[field]
            )
            if "safety" not in review["risk_flags"] or not severe:
                raise _error(
                    item_path,
                    "the bound independent review is not a high-severity safety review",
                )


def _validated_topic_episode_sessions(
    topic_results: Sequence[Mapping[str, Any]],
    *,
    allowed_refs: Collection[str] | None,
) -> dict[str, str]:
    episode_sessions: dict[str, str] = {}
    for topic_index, topic in enumerate(topic_results):
        topic_path = _path("topic_results", topic_index)
        if not isinstance(topic, Mapping):
            raise _error(topic_path, "must be a topic result object")
        episode_refs = _require_refs(
            topic.get("episode_refs"),
            path=_path(topic_path, "episode_refs"),
            allowed_refs=allowed_refs,
            expected_prefix="episode",
            minimum=1,
        )
        lineage = _require_list(
            topic.get("episode_lineage"),
            path=_path(topic_path, "episode_lineage"),
            maximum=128,
        )
        lineage_episodes: list[str] = []
        lineage_sessions: list[str] = []
        for lineage_index, raw_lineage in enumerate(lineage):
            lineage_path = _path(_path(topic_path, "episode_lineage"), lineage_index)
            row = _require_mapping(raw_lineage, path=lineage_path)
            _require_exact_keys(
                row,
                required={"episode_ref", "session_ref"},
                path=lineage_path,
            )
            episode_ref = _require_ref(
                row["episode_ref"],
                path=_path(lineage_path, "episode_ref"),
                allowed_refs=allowed_refs,
                expected_prefix="episode",
            )
            session_ref = _require_ref(
                row["session_ref"],
                path=_path(lineage_path, "session_ref"),
                allowed_refs=allowed_refs,
                expected_prefix="session",
            )
            previous = episode_sessions.setdefault(episode_ref, session_ref)
            if previous != session_ref:
                raise _error(
                    lineage_path,
                    "assigns one episode lineage to multiple sessions",
                )
            lineage_episodes.append(episode_ref)
            lineage_sessions.append(session_ref)
        if len(lineage_episodes) != len(set(lineage_episodes)) or set(
            lineage_episodes
        ) != set(episode_refs):
            raise _error(
                _path(topic_path, "episode_lineage"),
                "must exactly cover the topic episode_refs",
            )
        if "session_refs" in topic and set(topic["session_refs"]) != set(
            lineage_sessions
        ):
            raise _error(
                _path(topic_path, "session_refs"),
                "does not match the exact episode lineage sessions",
            )
    return episode_sessions


def _validate_synthesis_signal_preservation(
    synthesis: Mapping[str, Any],
    *,
    topic_results: Sequence[Mapping[str, Any]],
    independent_reviews_by_hash: Mapping[str, Mapping[str, Any]],
    allowed_refs: Collection[str] | None,
) -> None:
    projected: dict[str, dict[str, Mapping[str, Any]]] = {
        "events": {},
        "findings": {},
        "strengths": {},
    }
    topic_signal_values: dict[str, set[str]] = {
        "events": set(),
        "findings": set(),
    }
    for topic_index, topic in enumerate(topic_results):
        topic_path = _path("topic_results", topic_index)
        if not isinstance(topic, Mapping) or topic.get("schema") != TOPIC_RESULT_SCHEMA:
            raise _error(topic_path, "is not a validated topic result")
        episode_refs = _require_refs(
            topic.get("episode_refs"),
            path=_path(topic_path, "episode_refs"),
            allowed_refs=allowed_refs,
            expected_prefix="episode",
        )
        if not episode_refs:
            raise _error(topic_path, "must bind at least one episode lineage")
        for field in projected:
            values = topic.get(field)
            if not isinstance(values, list):
                raise _error(_path(topic_path, field), "must be a signal array")
            for item_index, item in enumerate(values):
                if not isinstance(item, Mapping):
                    raise _error(
                        _path(_path(topic_path, field), item_index),
                        "must be a signal object",
                    )
                projected_item = copy.deepcopy(dict(item))
                projected_value = _canonical_value(projected_item)
                projected[field].setdefault(projected_value, projected_item)
                if field in topic_signal_values:
                    topic_signal_values[field].add(_canonical_value(item))

    expected_commitments = build_synthesis_signal_commitments(topic_results)
    if synthesis["signal_commitments"] != expected_commitments:
        raise _error(
            "$.signal_commitments",
            "must exactly bind every canonical topic signal",
        )
    exemplars = build_synthesis_signal_exemplars(topic_results)
    for field in projected:
        expected_exemplars = [_canonical_value(item) for item in exemplars[field]]
        actual = [_canonical_value(item) for item in synthesis[field]]
        if actual != expected_exemplars:
            raise _error(
                f"$.{field}",
                "must contain the deterministic bounded topic-signal exemplars",
            )

    for review in independent_reviews_by_hash.values():
        for field in ("events", "findings"):
            for item in review[field]:
                if item.get("severity") not in {"high", "critical"}:
                    continue
                if _canonical_value(item) not in topic_signal_values[field]:
                    raise _error(
                        f"$.{field}",
                        "validated topics dropped a high-severity independent-review decision",
                    )


def build_synthesis_signal_commitments(
    topic_results: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Commit the exact canonical union while keeping synthesis output bounded."""

    commitments: dict[str, dict[str, Any]] = {}
    for field in ("events", "findings", "strengths"):
        canonical_values = sorted(
            {
                _canonical_value(item)
                for topic in topic_results
                for item in topic.get(field, [])
            }
        )
        encoded = json.dumps(
            canonical_values,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        commitments[field] = {
            "canonical_count": len(canonical_values),
            "canonical_hash": hashlib.sha256(encoded).hexdigest(),
        }
    return commitments


def build_synthesis_signal_exemplars(
    topic_results: Sequence[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Select deterministic high-severity-first exemplars from exact topic signals."""

    exemplars: dict[str, list[dict[str, Any]]] = {}
    for field in ("events", "findings", "strengths"):
        values: dict[str, dict[str, Any]] = {}
        for topic in topic_results:
            for item in topic.get(field, []):
                canonical = _canonical_value(item)
                values.setdefault(canonical, copy.deepcopy(dict(item)))
        ordered = sorted(
            values.items(),
            key=lambda item: (
                0 if item[1].get("severity") in {"high", "critical"} else 1,
                item[0],
            ),
        )
        exemplars[field] = [item for _canonical, item in ordered[:MAX_SIGNALS_PER_KIND]]
    return exemplars


def validate_synthesis_result(
    result: Mapping[str, Any],
    allowed_refs: Collection[str] | None = None,
    *,
    allowed_references: Collection[str] | None = None,
    allowed_evidence_refs: Collection[str] | None = None,
    allowed_turn_refs: Collection[str] | None = None,
    independent_review_results: Sequence[Mapping[str, Any]] = (),
    source_allowed_refs: Collection[str] | None = None,
    topic_results: Sequence[Mapping[str, Any]] = (),
    original_prompts: Sequence[str] = (),
    tool_outputs: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate a closed global synthesis result for deterministic compilation."""

    refs = _merge_allowed_refs(allowed_refs, allowed_references, allowed_evidence_refs)
    source_refs = (
        refs if source_allowed_refs is None else frozenset(source_allowed_refs)
    )
    independent_reviews_by_hash: dict[str, Mapping[str, Any]] = {}
    for index, review in enumerate(independent_review_results):
        try:
            validated_review = validate_episode_review_result(
                review,
                source_refs,
                allowed_turn_refs=allowed_turn_refs,
                expected_reviewer_slot="secondary",
                original_prompts=original_prompts,
                tool_outputs=tool_outputs,
            )
        except ResultValidationError as exc:
            raise _error(_path("independent_review_results", index), str(exc)) from exc
        if validated_review["disposition"] != "reviewed":
            raise _error(
                _path("independent_review_results", index), "must be a reviewed result"
            )
        review_hash = canonical_result_hash(validated_review)
        if review_hash in independent_reviews_by_hash:
            raise _error(
                "independent_review_results", "contains duplicate review results"
            )
        independent_reviews_by_hash[review_hash] = validated_review
    expected_topic_hashes = sorted(
        canonical_result_hash(topic_result) for topic_result in topic_results
    )
    value = _privacy_prepare(
        result,
        refs,
        allowed_turn_refs,
        expected_topic_hashes,
        original_prompts=original_prompts,
        tool_outputs=tool_outputs,
    )
    _require_exact_keys(
        value,
        required={
            "schema",
            "question_answers",
            "events",
            "findings",
            "strengths",
            "prompt_rewrites",
            "guidance_candidates",
            "signal_commitments",
            "skill_candidates",
            "follow_up_actions",
            "confidence",
            "evidence_refs",
            "era_comparison",
            "topic_result_hashes",
        },
        path="$",
    )
    _require_schema(value, SYNTHESIS_RESULT_SCHEMA, path="$")
    topic_hashes = _require_list(
        value["topic_result_hashes"],
        path="$.topic_result_hashes",
        maximum=128,
    )
    for index, digest in enumerate(topic_hashes):
        _require_sha256(digest, path=_path("$.topic_result_hashes", index))
    if topic_hashes != expected_topic_hashes:
        raise _error(
            "$.topic_result_hashes",
            "must exactly bind every validated topic result",
        )
    _validate_question_answers(value["question_answers"], allowed_refs=refs)
    _validate_signal_list(
        value["events"],
        path="$.events",
        kinds=EVENT_KINDS,
        allowed_refs=refs,
        evidence_prefix="evidence",
    )
    _validate_signal_list(
        value["findings"],
        path="$.findings",
        kinds=FINDING_KINDS,
        allowed_refs=refs,
        evidence_prefix="evidence",
    )
    _validate_signal_list(
        value["strengths"],
        path="$.strengths",
        kinds=STRENGTH_KINDS,
        allowed_refs=refs,
        evidence_prefix="evidence",
    )
    _validate_high_impact_turns(
        value["prompt_rewrites"],
        path="$.prompt_rewrites",
        allowed_refs=refs,
        allowed_turn_refs=allowed_turn_refs,
        evidence_prefix="episode",
    )
    episode_sessions = _validated_topic_episode_sessions(
        topic_results,
        allowed_refs=source_refs,
    )
    _validate_durable_candidates(
        value["guidance_candidates"],
        path="$.guidance_candidates",
        kinds=GUIDANCE_KINDS,
        allowed_refs=refs,
        independent_reviews_by_hash=independent_reviews_by_hash,
        episode_sessions=episode_sessions,
    )
    _validate_durable_candidates(
        value["skill_candidates"],
        path="$.skill_candidates",
        kinds=SKILL_CANDIDATE_KINDS,
        allowed_refs=refs,
        independent_reviews_by_hash=independent_reviews_by_hash,
        episode_sessions=episode_sessions,
    )
    follow_ups = _require_list(
        value["follow_up_actions"], path="$.follow_up_actions", maximum=64
    )
    for index, item in enumerate(follow_ups):
        item_path = _path("$.follow_up_actions", index)
        follow_up = _require_mapping(item, path=item_path)
        _require_exact_keys(
            follow_up, required={"kind", "evidence_refs", "confidence"}, path=item_path
        )
        _require_enum(follow_up["kind"], FOLLOW_UP_KINDS, path=_path(item_path, "kind"))
        _require_refs(
            follow_up["evidence_refs"],
            path=_path(item_path, "evidence_refs"),
            allowed_refs=refs,
            expected_prefix="episode",
        )
        _require_enum(
            follow_up["confidence"],
            CONFIDENCE_LEVELS,
            path=_path(item_path, "confidence"),
        )
    confidence = _require_mapping(value["confidence"], path="$.confidence")
    _require_exact_keys(
        confidence,
        required={"coverage", "extraction", "review", "comparability"},
        path="$.confidence",
    )
    for field in ("coverage", "extraction", "review", "comparability"):
        _require_enum(
            confidence[field], CONFIDENCE_LEVELS, path=f"$.confidence.{field}"
        )
    _require_refs(
        value["evidence_refs"],
        path="$.evidence_refs",
        allowed_refs=refs,
        expected_prefix="episode",
    )
    era = _require_mapping(value["era_comparison"], path="$.era_comparison")
    _require_exact_keys(era, required={"status", "change"}, path="$.era_comparison")
    _require_enum(
        era["status"],
        {"compatible", "incompatible", "unavailable"},
        path="$.era_comparison.status",
    )
    _require_enum(
        era["change"],
        {"improved", "regressed", "unchanged", "unavailable"},
        path="$.era_comparison.change",
    )
    if era["status"] != "compatible" and era["change"] != "unavailable":
        raise _error(
            "$.era_comparison.change", "must be unavailable outside a compatible era"
        )
    _validate_synthesis_signal_preservation(
        value,
        topic_results=topic_results,
        independent_reviews_by_hash=independent_reviews_by_hash,
        allowed_refs=source_refs,
    )
    return value


def validate_result(
    kind: str,
    result: Mapping[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """Dispatch a declared v2 result kind to its strict validator."""

    validators = {
        EXTRACTOR_RESULT_SCHEMA: validate_extractor_result,
        EPISODE_REVIEW_RESULT_SCHEMA: validate_episode_review_result,
        ADJUDICATION_RESULT_SCHEMA: validate_adjudication_result,
        TOPIC_INPUT_SCHEMA: validate_topic_input,
        TOPIC_RESULT_SCHEMA: validate_topic_result,
        SYNTHESIS_RESULT_SCHEMA: validate_synthesis_result,
    }
    try:
        validator = validators[kind]
    except KeyError as exc:
        raise ResultValidationError(f"unsupported result kind: {kind}") from exc
    return validator(result, **kwargs)
