#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable


WRAPPER_PREFIXES = (
    "# AGENTS.md instructions",
    "<skill>",
    "<environment_context>",
    "<subagent_notification>",
    "# Review findings:",
    "<turn_aborted>",
    "Persistent internal Codex readonly review contract:",
    "Review discipline:",
    "Review the code changes against the base branch",
)

AUTOMATION_PROMPT_PATTERNS = (
    re.compile(r"^Run the (?:daily|weekly) Codex session retrospective\b", re.I),
    re.compile(r"^Run a read-only (?:daily|weekly) retrospective over Joey's Codex session activity\b", re.I),
    re.compile(r"^Use \$codex-session-retrospective to run\b", re.I),
    re.compile(r"^Use the installed codex-session-retrospective workflow\b", re.I),
    re.compile(r"\bWrite task-local artifacts under \.codex-local/session-retrospective\b", re.I),
)

AUTOMATION_PROMPT_MARKERS = (
    "Run a read-only daily retrospective over Joey's Codex session activity.",
    "Run a read-only weekly retrospective over Joey's Codex session activity.",
    "Evidence scope must match $remote-host-context's default host policy",
    "Write task-local artifacts under .codex-local/session-retrospective/runs/",
)

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b(?:(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b"),
        "[REDACTED_SECRET]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/\-]+=*", re.I), "[REDACTED_CREDENTIAL]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_CREDENTIAL]"),
    (re.compile(r"\b(?:ssh://[^\s)>\]\"']+|git@[A-Za-z0-9_.-]+:[^\s)>\]\"']+)"), "[REDACTED_URL]"),
    (
        re.compile(
            r"\b(?:password|passwd|pwd|credential|secret|token|api[_-]?key|authorization)\s*[:=]\s*['\"]?[^'\"\s,;]+",
            re.I,
        ),
        "[REDACTED_CREDENTIAL]",
    ),
    (re.compile(r"https?://[^\s)>\]\"']+"), "[REDACTED_URL]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (
        re.compile(r"(?<!\w)(?:~|/(?:Users|home|root|private|tmp|var|etc|opt|Volumes|workspace|workspaces))/[^\s,;:)>\]\"']+"),
        "[REDACTED_PATH]",
    ),
    (
        re.compile(r"\b(?:customer|client|account|tenant|org|repo|repository)[_-]?(?:id|name)?\s*[:=]\s*['\"]?[A-Za-z0-9_.-]+", re.I),
        "[REDACTED_IDENTIFIER]",
    ),
)

FLAG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("failed_command", re.compile(r"(?:exit(?:ed)?(?: with)? code [1-9]\d*|failed|traceback|error:|permission denied)", re.I)),
    ("approval_auth_friction", re.compile(r"(?:approval|require_escalated|sandbox|\bauth(?:entication|orization|[-_ ]?gated)?\b|credential|permission denied|TCC)", re.I)),
    ("verification_gap", re.compile(r"(?:not run|did not run|unable to run|could not run|untested|未运行|无法运行)", re.I)),
    ("user_correction", re.compile(r"(?:you missed|you forgot|wrong|incorrect|not what I asked|漏了|忘了|不对|错了)", re.I)),
    ("context_loss", re.compile(r"(?:lost context|misunderstood|I misunderstood|assumption|assumed|上下文|误解)", re.I)),
)

SAFETY_PATTERN = re.compile(
    r"(?:\b(secret|token|credential|password|private key|production|destructive|rm -rf|reset --hard)\b|"
    r"客户|客户数据|凭据|凭证|密钥|生产|破坏性)",
    re.I,
)

DEFAULT_REMOTE_HOSTS = ("miku-bot-dev", "hoteng-srv-01")
DEFAULT_REMOTE_SOURCE_ROOT = Path(".codex-local/session-retrospective/remote-sources")
REMOTE_SOURCE_METADATA_FILE = "source_metadata.json"
LOCAL_EVIDENCE_FILES = ("session_index.jsonl", "history.jsonl")
SAFE_OUTPUT_PARTS = (".codex-local", "session-retrospective")
PATH_REF_PREFIX = "path_ref_v1"
PATH_REF_PATTERN = re.compile(r"^path_ref_v1:[0-9a-f]{16}$")
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PATH_REF_KEY = secrets.token_bytes(32)
ROLLOUT_TIMESTAMP_SCAN_BYTES = 1024 * 1024
RETAINED_OUTPUT_FILES = ("episodes.jsonl", "turn_flags.jsonl", "trend_report.json", "retained_manifest.json")
TRANSIENT_OUTPUT_FILES = ("turn_summaries.jsonl", "shard_manifest.json", "shards.jsonl")
EPISODE_FIELDS = {
    "episode_id",
    "host",
    "session_id",
    "start",
    "end",
    "cwd",
    "model_era",
    "topic",
    "turn_count",
    "friction_flags",
    "outcome",
    "work_report_hint",
}
TURN_FLAG_FIELDS = {
    "turn_id",
    "episode_id",
    "host",
    "session_id",
    "source_path",
    "source_hash",
    "timestamp",
    "cwd",
    "model",
    "model_era",
    "redacted_user_prompt_summary",
    "assistant_action_summary",
    "issue_flags",
    "prompt_improvement",
}
TREND_FIELDS = {
    "schema_version",
    "window",
    "turn_count",
    "flagged_turn_count",
    "episode_count",
    "flags",
    "hosts",
    "model_eras",
    "coverage_gaps",
}
MANIFEST_FIELDS = {
    "schema_version",
    "mode",
    "window",
    "sources",
    "coverage_gaps",
    "redaction_policy_version",
    "retention_safe",
    "retention_note",
}
MANIFEST_SOURCE_FIELDS = {"host", "root_ref", "status", "rollout_count", "summary_count"}
MANIFEST_GAP_FIELDS = {"host", "root_ref", "reason", "bytes"}
ALLOWED_REMOTE_GAP_REASONS = {
    "auth_gated",
    "codex_missing",
    "host_unreachable",
    "missing_codex",
    "remote_source_not_materialized",
    "source_root_missing",
    "stale_host",
    "unreachable",
}


@dataclasses.dataclass(frozen=True)
class Source:
    host: str
    root: Path
    missing_reason: str | None = None


@dataclasses.dataclass
class TurnSummary:
    turn_id: str
    episode_id: str
    host: str
    session_id: str
    source_path: str
    source_hash: str
    timestamp: str | None
    cwd: str | None
    model: str | None
    model_era: str
    redacted_user_prompt_summary: str
    assistant_action_summary: str
    issue_flags: list[str]
    prompt_improvement: str | None


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def compact(text: str, limit: int = 600) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "..."


def redact(text: str) -> tuple[str, bool]:
    redacted = text
    changed = False
    for pattern, label in SECRET_PATTERNS:
        redacted, count = pattern.subn(label, redacted)
        changed = changed or count > 0
    if len(redacted) > 1200:
        redacted = redacted[:1200].rstrip() + " [TRUNCATED]"
        changed = True
    return redacted, changed


def has_pr_intent(text: str) -> bool:
    return bool(re.search(r"\b(?:review|pr|pull request)\b", text.lower()))


def prompt_category(text: str) -> str:
    categories: list[str] = []
    lowered = text.lower()
    if has_pr_intent(lowered):
        categories.append("review")
    if any(word in lowered for word in ("fix", "bug", "error", "failed", "failure")):
        categories.append("debug_or_fix")
    if any(word in lowered for word in ("implement", "add", "create", "build", "update")):
        categories.append("implementation")
    if any(word in lowered for word in ("plan", "design", "怎么", "设计")):
        categories.append("planning")
    if any(word in lowered for word in ("test", "verify", "validate")):
        categories.append("verification")
    if not categories:
        categories.append("general")
    return "+".join(sorted(set(categories)))


TOPIC_STOPWORDS = {
    "also",
    "and",
    "build",
    "create",
    "fix",
    "for",
    "implement",
    "please",
    "the",
    "this",
    "update",
    "using",
    "with",
}


def prompt_topic_key(redacted_text: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", redacted_text.casefold())
    meaningful = [
        token
        for token in tokens
        if len(token) > 2 and token not in TOPIC_STOPWORDS and not token.startswith("redacted")
    ]
    if meaningful:
        return "topic_ref:" + stable_hash("+".join(sorted(dict.fromkeys(meaningful))[:6]), 12)
    compacted = re.sub(r"\s+", "", redacted_text)
    return "topic_ref:" + stable_hash(compacted, 12) if compacted else "unknown"


def safe_prompt_summary(
    text: str,
    issue_flags: set[str],
    redacted_changed: bool,
    redacted_text: str | None = None,
) -> str:
    parts = [
        f"category={prompt_category(text)}",
        f"prompt_chars={len(text)}",
    ]
    if redacted_text:
        parts.append("topic_ref=" + prompt_topic_key(redacted_text))
    if issue_flags:
        parts.append("flags=" + ",".join(sorted(issue_flags)))
    if redacted_changed:
        parts.append("redactions=applied")
    return "; ".join(parts)


def safe_assistant_summary(texts: list[str]) -> str:
    if not texts:
        return ""
    categories: list[str] = []
    joined = "\n".join(texts).lower()
    if any(word in joined for word in ("test", "pytest", "unittest", "validated", "verification")):
        categories.append("verification")
    if any(word in joined for word in ("implement", "add", "create", "update", "patch", "edit")):
        categories.append("implementation")
    if any(word in joined for word in ("commit", "push")) or has_pr_intent(joined):
        categories.append("git_or_pr")
    if any(word in joined for word in ("blocked", "cannot", "unable", "failed", "error")):
        categories.append("blocked_or_failed")
    if any(word in joined for word in ("read", "search", "inspect", "rg ", "grep")):
        categories.append("inspection")
    if not categories:
        categories.append("response")
    return f"assistant_messages={len(texts)}; action_categories={','.join(sorted(set(categories)))}"


def stable_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def path_ref(value: str | os.PathLike[str] | None, length: int = 16) -> str | None:
    if not value:
        return None
    digest = hmac.new(PATH_REF_KEY, os.fspath(value).encode("utf-8", errors="surrogatepass"), hashlib.sha256)
    return f"{PATH_REF_PREFIX}:{digest.hexdigest()[:length]}"


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_safe_output_dir(path: Path) -> None:
    parts = path.expanduser().resolve(strict=False).parts
    for index in range(len(parts) - len(SAFE_OUTPUT_PARTS) + 1):
        if parts[index : index + len(SAFE_OUTPUT_PARTS)] == SAFE_OUTPUT_PARTS:
            return
    raise SystemExit("output directory for transient artifacts must be under .codex-local/session-retrospective")


def session_id_from_path(path: Path) -> str:
    match = re.search(r"^rollout-\d{4}-\d{2}-\d{2}(?:T\d{2}-\d{2}-\d{2})?-(.+)\.jsonl$", path.name)
    if match:
        return match.group(1)
    return stable_hash(path.as_posix())


def rollout_date_from_path(path: Path) -> dt.datetime | None:
    match = re.search(r"^rollout-(\d{4}-\d{2}-\d{2})(?:T(\d{2})-(\d{2})-(\d{2}))?-", path.name)
    if not match:
        return None
    if match.group(2):
        return parse_time(f"{match.group(1)}T{match.group(2)}:{match.group(3)}:{match.group(4)}Z")
    return parse_time(f"{match.group(1)}T00:00:00Z")


def dated_path_from_parts(path: Path) -> dt.datetime | None:
    parts = path.parts
    for index in range(len(parts) - 2):
        year, month, day = parts[index : index + 3]
        if re.fullmatch(r"\d{4}", year) and re.fullmatch(r"\d{2}", month) and re.fullmatch(r"\d{2}", day):
            parsed = parse_time(f"{year}-{month}-{day}T00:00:00Z")
            if parsed:
                return parsed
    return None


def summary_date_from_path(path: Path) -> dt.datetime | None:
    return dated_path_from_parts(path)


def first_jsonl_error(path: Path) -> int | None:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError:
                return line_no
    return None


def iter_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                yield line_no, json.loads(line)
            except json.JSONDecodeError:
                continue


def iter_jsonl_strict(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                yield line_no, json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON") from exc


def text_from_message_payload(payload: dict[str, Any]) -> str:
    texts: list[str] = []
    for part in payload.get("content") or []:
        if isinstance(part, dict) and part.get("type") in {"input_text", "output_text", "text"}:
            texts.append(str(part.get("text") or ""))
    return "\n".join(texts).strip()


def user_text_from_payload(payload: dict[str, Any]) -> str:
    if payload.get("type") == "message" and payload.get("role") == "user":
        return text_from_message_payload(payload)
    if payload.get("type") == "user_message":
        return str(payload.get("message") or "").strip()
    return ""


def assistant_text_from_payload(payload: dict[str, Any]) -> str:
    if payload.get("type") == "message" and payload.get("role") == "assistant":
        return text_from_message_payload(payload)
    return ""


def record_timestamp(record: dict[str, Any]) -> str | None:
    payload = record.get("payload") or {}
    for key in ("timestamp", "time", "created_at", "ts"):
        value = record.get(key) or payload.get(key)
        if isinstance(value, str) and parse_time(value):
            return iso(parse_time(value) or utc_now())
    return None


def record_timestamp_or_fallback(record: dict[str, Any], path: Path) -> str | None:
    fallback = rollout_date_from_path(path) or dated_path_from_parts(path)
    return record_timestamp(record) or (iso(fallback) if fallback else None)


def record_text(record: dict[str, Any]) -> str:
    payload = record.get("payload") or {}
    if isinstance(payload, dict) and payload.get("type") in {"message", "user_message"}:
        if payload.get("type") == "user_message":
            return str(payload.get("message") or "")
        return text_from_message_payload(payload)
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(payload)


def meaningful_user_text(text: str) -> bool:
    stripped = meaningful_prompt_text(text)
    if not stripped:
        return False
    if any(pattern.search(stripped) for pattern in AUTOMATION_PROMPT_PATTERNS):
        return False
    marker_count = sum(1 for marker in AUTOMATION_PROMPT_MARKERS if marker in stripped)
    return marker_count < 2


def meaningful_prompt_text(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    if any(stripped.startswith(prefix) for prefix in WRAPPER_PREFIXES):
        for marker in ("</INSTRUCTIONS>", "</environment_context>", "</skill>", "</subagent_notification>", "</turn_aborted>"):
            index = stripped.rfind(marker)
            if index >= 0:
                candidate = stripped[index + len(marker) :].strip()
                if candidate and not any(candidate.startswith(prefix) for prefix in WRAPPER_PREFIXES):
                    return candidate
        return ""
    return stripped


def dedupe_text_key(text: str) -> str:
    return re.sub(r"\W+", " ", text.casefold()).strip()


def duplicate_user_turn(current_text: str, current_time: str, previous: tuple[str, str] | None) -> bool:
    if previous is None or current_time != previous[1]:
        return False
    current_key = dedupe_text_key(current_text)
    previous_key = dedupe_text_key(previous[0])
    if not current_key or not previous_key:
        return False
    if current_key == previous_key or current_key in previous_key or previous_key in current_key:
        return True
    return SequenceMatcher(None, current_key, previous_key).ratio() >= 0.88


def flags_for_text(text: str, *, redacted_changed: bool = False) -> set[str]:
    flags = {name for name, pattern in FLAG_PATTERNS if pattern.search(text)}
    if redacted_changed or SAFETY_PATTERN.search(text):
        flags.add("safety_privacy_flag")
    return flags


def safe_source_file(path: Path, root: Path) -> bool:
    if path.is_symlink():
        return False
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, ValueError):
        return False
    return path.is_file()


def source_rollouts(source: Source) -> list[Path]:
    sessions = source.root / "sessions"
    search_root = sessions if sessions.exists() else source.root
    return sorted(
        path
        for path in search_root.rglob("rollout-*.jsonl")
        if safe_source_file(path, source.root) and not path.name.startswith("rollout-summary")
    )


def source_summary_files(source: Source) -> list[Path]:
    if not source.root.exists():
        return []
    return sorted(path for path in source.root.rglob("rollout-summary*.jsonl") if safe_source_file(path, source.root))


def rollout_has_record_in_window(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    if start is None and end is None:
        return True
    fallback = rollout_date_from_path(path)
    for _line_no, record in iter_jsonl(path):
        timestamp = parse_time(record_timestamp(record))
        if timestamp is None:
            timestamp = fallback
        if timestamp is None:
            continue
        if start and timestamp < start:
            continue
        if end and timestamp >= end:
            continue
        return True
    return False


def rollout_filename_in_window(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    rollout_date = rollout_date_from_path(path)
    if rollout_date is None:
        return True
    if start and rollout_date < start:
        return False
    if end and rollout_date >= end:
        return False
    return True


TIMESTAMP_BYTES_PATTERN = re.compile(rb'"(?:timestamp|time|created_at|ts)"\s*:\s*"([^"]+)"')


def oversized_rollout_has_timestamp_in_window(
    path: Path,
    start: dt.datetime | None,
    end: dt.datetime | None,
    *,
    chunk_bytes: int | None = None,
    max_scan_bytes: int | None = None,
) -> tuple[bool, bool]:
    if chunk_bytes is None:
        chunk_bytes = ROLLOUT_TIMESTAMP_SCAN_BYTES
    if max_scan_bytes is None:
        max_scan_bytes = ROLLOUT_TIMESTAMP_SCAN_BYTES
    size = path.stat().st_size
    scan_bytes = min(size, max_scan_bytes)
    with path.open("rb") as handle:
        if size > max_scan_bytes:
            handle.seek(size - max_scan_bytes)
        carry = b""
        remaining = scan_bytes
        while remaining > 0:
            data = handle.read(min(chunk_bytes, remaining))
            if not data:
                break
            remaining -= len(data)
            window = carry + data
            for match in TIMESTAMP_BYTES_PATTERN.finditer(window):
                timestamp = parse_time(match.group(1).decode("utf-8", errors="replace"))
                if timestamp is None:
                    continue
                if start and timestamp < start:
                    continue
                if end and timestamp >= end:
                    continue
                return True, size <= max_scan_bytes
            carry = window[-256:]
    return False, size <= max_scan_bytes


def oversized_rollout_relevance(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> str:
    if start is None and end is None:
        return "relevant"
    rollout_date = rollout_date_from_path(path)
    if rollout_date and end and rollout_date >= end:
        return "irrelevant"
    if rollout_date and start and rollout_date < start:
        found, complete = oversized_rollout_has_timestamp_in_window(path, start, end)
        if found:
            return "relevant"
        if not complete:
            return "unknown"
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        except OSError:
            mtime = None
        if mtime and mtime < start:
            return "irrelevant"
        return "irrelevant"
    return "relevant"


def oversized_rollout_relevant(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    return oversized_rollout_relevance(path, start, end) == "relevant"


def raw_timestamp_in_window(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    found, _complete = oversized_rollout_has_timestamp_in_window(
        path,
        start,
        end,
        max_scan_bytes=path.stat().st_size,
    )
    return found


def summary_file_relevant(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    if start is None and end is None:
        return True
    summary_date = summary_date_from_path(path)
    if summary_date and end and summary_date >= end:
        return False
    if summary_date and start and summary_date < start:
        return raw_timestamp_in_window(path, start, end)
    return True


def infer_model_era(model: str | None, timestamp: str | None) -> str:
    if model:
        if "gpt-5.5" in model:
            return "gpt-5.5"
        if "gpt-5.4" in model:
            return "gpt-5.4"
        if "gpt-5.3" in model:
            return "gpt-5.3-codex"
        return model
    parsed = parse_time(timestamp)
    if parsed and parsed.date() < dt.date(2026, 1, 1):
        return "pre-gpt-5.3-codex"
    return "unknown"


def extract_rollout(
    source: Source,
    path: Path,
    start: dt.datetime | None,
    end: dt.datetime | None,
    *,
    emit_start: dt.datetime | None = None,
) -> list[TurnSummary]:
    session_id = session_id_from_path(path)
    source_hash = file_hash(path)
    cwd: str | None = None
    model: str | None = None
    current: TurnSummary | None = None
    turns: list[TurnSummary] = []
    assistant_bits: list[str] = []
    last_user_fingerprint: tuple[str, str] | None = None
    current_emitted = False

    def flush_assistant() -> None:
        nonlocal assistant_bits
        if current and assistant_bits:
            current.assistant_action_summary = safe_assistant_summary(assistant_bits)
            assistant_bits = []

    def is_emit_record(timestamp: dt.datetime | None) -> bool:
        return emit_start is None or timestamp is None or timestamp >= emit_start

    def emit_current() -> None:
        nonlocal current_emitted
        if current and not current_emitted:
            turns.append(current)
            current_emitted = True

    for line_no, record in iter_jsonl(path):
        payload = record.get("payload") or {}
        if isinstance(payload, dict):
            cwd = payload.get("cwd") or cwd
            model = payload.get("model") or payload.get("model_id") or model
        timestamp = record_timestamp_or_fallback(record, path)
        parsed_timestamp = parse_time(timestamp)
        if parsed_timestamp and start and parsed_timestamp < start:
            continue
        if parsed_timestamp and end and parsed_timestamp >= end:
            continue

        if isinstance(payload, dict):
            user_text = user_text_from_payload(payload)
            assistant_text = assistant_text_from_payload(payload)
            prompt_text = meaningful_prompt_text(user_text) if user_text else ""
            if user_text and not meaningful_user_text(user_text):
                flush_assistant()
                current = None
                current_emitted = False
                assistant_bits = []
                continue
            if prompt_text and meaningful_user_text(user_text):
                fingerprint_time = iso(parsed_timestamp.replace(microsecond=0)) if parsed_timestamp else ""
                fingerprint = (prompt_text, fingerprint_time)
                if duplicate_user_turn(prompt_text, fingerprint_time, last_user_fingerprint):
                    continue
                last_user_fingerprint = fingerprint
                flush_assistant()
                redacted_prompt, prompt_changed = redact(prompt_text)
                prompt_flags = flags_for_text(prompt_text, redacted_changed=prompt_changed)
                prompt_summary = safe_prompt_summary(prompt_text, prompt_flags, prompt_changed, redacted_prompt)
                date_bucket = (parse_time(timestamp) or rollout_date_from_path(path) or utc_now()).date().isoformat()
                episode_seed = "|".join(
                    [
                        source.host,
                        session_id,
                        (cwd or ""),
                        date_bucket,
                        prompt_category(prompt_text),
                        prompt_topic_key(redacted_prompt),
                    ]
                )
                episode_id = stable_hash(episode_seed, 20)
                turn = TurnSummary(
                    turn_id=stable_hash(f"{source.host}|{path}|{line_no}|{timestamp}", 20),
                    episode_id=episode_id,
                    host=source.host,
                    session_id=session_id,
                    source_path=path_ref(path) or "",
                    source_hash=source_hash,
                    timestamp=timestamp,
                    cwd=path_ref(cwd),
                    model=model,
                    model_era=infer_model_era(model, timestamp),
                    redacted_user_prompt_summary=prompt_summary,
                    assistant_action_summary="",
                    issue_flags=sorted(prompt_flags),
                    prompt_improvement=None,
                )
                if "user_correction" in prompt_flags or "context_loss" in prompt_flags:
                    turn.prompt_improvement = "Clarify the expected outcome, scope boundary, and any prior correction before asking Codex to continue."
                current = turn
                current_emitted = False
                if is_emit_record(parsed_timestamp):
                    emit_current()
                continue
            if assistant_text and current and is_emit_record(parsed_timestamp):
                emit_current()
                assistant_bits.append(assistant_text)

        text = record_text(record)
        _redacted_text, changed = redact(text)
        record_flags = flags_for_text(text, redacted_changed=changed)
        if current and record_flags and is_emit_record(parsed_timestamp):
            emit_current()
            merged = set(current.issue_flags)
            merged.update(record_flags)
            current.issue_flags = sorted(merged)
            if not current.prompt_improvement and ("verification_gap" in merged or "failed_command" in merged):
                current.prompt_improvement = "Ask Codex to report the exact verification run and stop if it cannot complete the requested check."

    flush_assistant()
    return turns


def extract_summary_file(
    source: Source,
    path: Path,
    start: dt.datetime | None,
    end: dt.datetime | None,
    *,
    emit_start: dt.datetime | None = None,
) -> list[TurnSummary]:
    turns: list[TurnSummary] = []
    source_hash = file_hash(path)
    session_id = stable_hash(path.as_posix(), 20)
    fallback = summary_date_from_path(path)
    for line_no, record in iter_jsonl(path):
        timestamp = str(record.get("timestamp") or "") or None
        parsed_timestamp = parse_time(timestamp) or fallback
        if parsed_timestamp is None and (start or end):
            continue
        if parsed_timestamp and start and parsed_timestamp < start:
            continue
        if parsed_timestamp and end and parsed_timestamp >= end:
            continue
        if emit_start and parsed_timestamp and parsed_timestamp < emit_start:
            continue
        text = str(record.get("text") or "")
        kind = str(record.get("kind") or "summary")
        if kind == "session_meta" and text:
            match = re.search(r"session_id=([^\s]+)", text)
            if match:
                session_id = match.group(1)
            continue
        _redacted_text, changed = redact(text)
        flags = flags_for_text(text, redacted_changed=changed)
        if not flags:
            continue
        timestamp_value = timestamp if parse_time(timestamp) else (iso(parsed_timestamp) if parsed_timestamp else None)
        date_bucket = (parsed_timestamp or utc_now()).date().isoformat()
        episode_id = stable_hash("|".join([source.host, session_id, "rollout-summary", date_bucket, kind]), 20)
        turns.append(
            TurnSummary(
                turn_id=stable_hash(f"{source.host}|{path}|{line_no}|{timestamp}", 20),
                episode_id=episode_id,
                host=source.host,
                session_id=session_id,
                source_path=path_ref(path) or "",
                source_hash=source_hash,
                timestamp=timestamp_value,
                cwd=None,
                model=None,
                model_era=infer_model_era(None, timestamp),
                redacted_user_prompt_summary=f"category=remote_rollout_summary; summary_kind={kind}",
                assistant_action_summary="summary_source=remote_rollout_summary",
                issue_flags=sorted(flags),
                prompt_improvement=None,
            )
        )
    return turns


def episode_records(turns: list[TurnSummary]) -> list[dict[str, Any]]:
    grouped: dict[str, list[TurnSummary]] = defaultdict(list)
    for turn in turns:
        grouped[turn.episode_id].append(turn)
    episodes: list[dict[str, Any]] = []
    for episode_id, items in sorted(grouped.items()):
        flags = sorted({flag for item in items for flag in item.issue_flags})
        timestamps = [item.timestamp for item in items if item.timestamp]
        first = min(timestamps) if timestamps else None
        last = max(timestamps) if timestamps else None
        first_turn = items[0]
        episodes.append(
            {
                "episode_id": episode_id,
                "host": first_turn.host,
                "session_id": first_turn.session_id,
                "start": first,
                "end": last,
                "cwd": first_turn.cwd,
                "model_era": first_turn.model_era,
                "topic": compact(first_turn.redacted_user_prompt_summary, 160),
                "turn_count": len(items),
                "friction_flags": flags,
                "outcome": "needs_review" if flags else "no_issue_observed",
                "work_report_hint": None,
            }
        )
    return episodes


def trend_report(
    turns: list[TurnSummary],
    episodes: list[dict[str, Any]],
    window: dict[str, Any],
    coverage_gaps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    flags = Counter(flag for turn in turns for flag in turn.issue_flags)
    hosts = Counter(turn.host for turn in turns)
    eras = Counter(turn.model_era for turn in turns)
    return {
        "schema_version": 1,
        "window": window,
        "turn_count": len(turns),
        "flagged_turn_count": sum(1 for turn in turns if turn.issue_flags),
        "episode_count": len(episodes),
        "flags": dict(sorted(flags.items())),
        "hosts": dict(sorted(hosts.items())),
        "model_eras": dict(sorted(eras.items())),
        "coverage_gaps": retention_safe_coverage_gaps(coverage_gaps or []),
    }


def asdict_turn(turn: TurnSummary) -> dict[str, Any]:
    return dataclasses.asdict(turn)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def jsonl_bytes(rows: Iterable[dict[str, Any]]) -> bytes:
    text = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    return text.encode("utf-8")


def json_bytes(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def redacted_path_entry(key: str, value: Any) -> tuple[str, Any]:
    ref_key = f"{key}_ref"
    if isinstance(value, str) and PATH_REF_PATTERN.fullmatch(value):
        return ref_key, value
    return ref_key, path_ref(str(value)) if value else None


def retention_safe_coverage_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    coverage_gaps: list[dict[str, Any]] = []
    for gap in gaps:
        retained_gap: dict[str, Any] = {}
        for key, value in gap.items():
            if key == "path" or key == "path_ref":
                continue
            if key == "root":
                ref_key, ref_value = redacted_path_entry(key, value)
                retained_gap[ref_key] = ref_value
                continue
            retained_gap[key] = value
        coverage_gaps.append(retained_gap)
    return coverage_gaps


def retained_manifest_from_transient(manifest: dict[str, Any]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for source in manifest.get("sources", []):
        retained_source: dict[str, Any] = {}
        for key, value in source.items():
            if key in {"root", "path"}:
                ref_key, ref_value = redacted_path_entry(key, value)
                retained_source.setdefault(ref_key, ref_value)
                continue
            retained_source[key] = value
        sources.append(retained_source)

    return {
        "schema_version": manifest.get("schema_version", 1),
        "mode": manifest.get("mode", "unknown"),
        "window": manifest.get("window") or {},
        "sources": sources,
        "coverage_gaps": retention_safe_coverage_gaps(manifest.get("coverage_gaps", [])),
        "redaction_policy_version": manifest.get("redaction_policy_version", 1),
        "retention_safe": True,
        "retention_note": "Derived retained manifest; raw location fields removed and opaque refs preserved.",
    }


def contains_raw_path_fields(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"root", "path"}:
                return True
            if contains_raw_path_fields(child):
                return True
    elif isinstance(value, list):
        return any(contains_raw_path_fields(child) for child in value)
    return False


def contains_path_like_text(value: Any) -> bool:
    if isinstance(value, str):
        return "/" in value or "\\" in value or "://" in value
    if isinstance(value, dict):
        return any(contains_path_like_text(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_path_like_text(child) for child in value)
    return False


def contains_invalid_ref(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.endswith("_ref"):
                if not isinstance(child, str) or not PATH_REF_PATTERN.fullmatch(child):
                    return True
                continue
            if contains_invalid_ref(child):
                return True
    if isinstance(value, list):
        return any(contains_invalid_ref(child) for child in value)
    return False


def contains_unredacted_sensitive_text(value: Any) -> bool:
    if isinstance(value, str):
        return any(pattern.search(value) for pattern, _label in SECRET_PATTERNS)
    if isinstance(value, dict):
        return any(contains_unredacted_sensitive_text(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_unredacted_sensitive_text(child) for child in value)
    return False


def safe_token(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))


def ensure_retained_safe_value(label: str, value: Any) -> None:
    if contains_unredacted_sensitive_text(value) or contains_path_like_text(value):
        raise SystemExit(f"{label}: unredacted sensitive or path-like text in retained output")
    if contains_raw_path_fields(value):
        raise SystemExit(f"{label}: raw root/path fields are not retention-safe")
    if contains_invalid_ref(value):
        raise SystemExit(f"{label}: retained refs must use opaque {PATH_REF_PREFIX} values")


def sanitize_mapping(
    obj: Any,
    *,
    allowed: set[str],
    required: set[str],
    label: str,
    strict: bool,
) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise SystemExit(f"{label}: retained entry must be an object")
    keys = set(obj)
    missing = required - keys
    if missing:
        raise SystemExit(f"{label}: missing keys {sorted(missing)}")
    extra = keys - allowed
    if strict and extra:
        raise SystemExit(f"{label}: unexpected keys {sorted(extra)}")
    sanitized = {key: obj[key] for key in sorted(allowed) if key in obj}
    ensure_retained_safe_value(label, sanitized)
    return sanitized


def require_string(value: Any, *, label: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise SystemExit(f"{label}: expected non-empty string")
    return value


def require_optional_string(value: Any, *, label: str) -> str | None:
    if value is None:
        return None
    return require_string(value, label=label)


def require_timestamp_or_none(value: Any, *, label: str) -> str | None:
    if value is None:
        return None
    text = require_string(value, label=label)
    if parse_time(text) is None:
        raise SystemExit(f"{label}: expected timestamp")
    return text


def require_safe_token_string(value: Any, *, label: str) -> str:
    text = require_string(value, label=label)
    if not safe_token(text):
        raise SystemExit(f"{label}: expected safe token")
    return text


def require_path_ref_or_none(value: Any, *, label: str) -> str | None:
    if value is None:
        return None
    text = require_string(value, label=label)
    if not PATH_REF_PATTERN.fullmatch(text):
        raise SystemExit(f"{label}: retained refs must use opaque {PATH_REF_PREFIX} values")
    return text


def require_token_list(value: Any, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise SystemExit(f"{label}: expected list")
    tokens: list[str] = []
    for index, item in enumerate(value):
        tokens.append(require_safe_token_string(item, label=f"{label}[{index}]"))
    return tokens


def require_non_negative_int(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise SystemExit(f"{label}: expected non-negative integer")
    return value


def validate_episode_row(row: dict[str, Any], *, label: str) -> None:
    require_safe_token_string(row["episode_id"], label=f"{label}.episode_id")
    require_safe_token_string(row["host"], label=f"{label}.host")
    require_safe_token_string(row["session_id"], label=f"{label}.session_id")
    require_timestamp_or_none(row["start"], label=f"{label}.start")
    require_timestamp_or_none(row["end"], label=f"{label}.end")
    require_path_ref_or_none(row["cwd"], label=f"{label}.cwd")
    require_safe_token_string(row["model_era"], label=f"{label}.model_era")
    require_string(row["topic"], label=f"{label}.topic")
    turn_count = require_non_negative_int(row["turn_count"], label=f"{label}.turn_count")
    if turn_count == 0:
        raise SystemExit(f"{label}.turn_count: expected positive integer")
    require_token_list(row["friction_flags"], label=f"{label}.friction_flags")
    require_safe_token_string(row["outcome"], label=f"{label}.outcome")
    require_optional_string(row["work_report_hint"], label=f"{label}.work_report_hint")


def validate_turn_flag_row(row: dict[str, Any], *, label: str) -> None:
    require_safe_token_string(row["turn_id"], label=f"{label}.turn_id")
    require_safe_token_string(row["episode_id"], label=f"{label}.episode_id")
    require_safe_token_string(row["host"], label=f"{label}.host")
    require_safe_token_string(row["session_id"], label=f"{label}.session_id")
    require_string(row["source_path"], label=f"{label}.source_path")
    if not PATH_REF_PATTERN.fullmatch(row["source_path"]):
        raise SystemExit(f"{label}.source_path: retained refs must use opaque {PATH_REF_PREFIX} values")
    source_hash = require_string(row["source_hash"], label=f"{label}.source_hash")
    if not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise SystemExit(f"{label}.source_hash: expected sha256 hex digest")
    require_timestamp_or_none(row["timestamp"], label=f"{label}.timestamp")
    require_path_ref_or_none(row["cwd"], label=f"{label}.cwd")
    require_optional_string(row["model"], label=f"{label}.model")
    require_safe_token_string(row["model_era"], label=f"{label}.model_era")
    require_string(row["redacted_user_prompt_summary"], label=f"{label}.redacted_user_prompt_summary")
    require_string(row["assistant_action_summary"], label=f"{label}.assistant_action_summary", allow_empty=True)
    issue_flags = require_token_list(row["issue_flags"], label=f"{label}.issue_flags")
    if not issue_flags:
        raise SystemExit(f"{label}.issue_flags: expected non-empty list")
    require_optional_string(row["prompt_improvement"], label=f"{label}.prompt_improvement")


def sanitize_retained_jsonl(
    path: Path,
    *,
    allowed: set[str],
    strict: bool,
    validator: Any | None = None,
) -> list[dict[str, Any]]:
    try:
        rows = list(iter_jsonl_strict(path))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    sanitized_rows: list[dict[str, Any]] = []
    for line_no, obj in rows:
        label = f"{path}:{line_no}"
        sanitized = sanitize_mapping(obj, allowed=allowed, required=allowed, label=label, strict=strict)
        if validator is not None:
            validator(sanitized, label=label)
        sanitized_rows.append(sanitized)
    return sanitized_rows


def sanitize_count_map(value: Any, *, label: str, strict: bool) -> dict[str, int]:
    if not isinstance(value, dict):
        raise SystemExit(f"{label}: expected count map")
    counts: dict[str, int] = {}
    for key, count in value.items():
        if not safe_token(key):
            raise SystemExit(f"{label}: retained count map key is not safe")
        if not isinstance(count, int) or count < 0:
            raise SystemExit(f"{label}: retained count map value must be a non-negative integer")
        counts[key] = count
    return counts


def sanitize_window(value: Any, *, label: str) -> dict[str, Any]:
    sanitized = sanitize_mapping(value, allowed={"mode", "start", "end"}, required={"mode", "start", "end"}, label=label, strict=True)
    if not safe_token(sanitized["mode"]) or not parse_time(str(sanitized["start"])) or not parse_time(str(sanitized["end"])):
        raise SystemExit(f"{label}: invalid retained window")
    return sanitized


def sanitize_coverage_gap(value: Any, *, label: str, strict: bool) -> dict[str, Any]:
    sanitized = sanitize_mapping(value, allowed=MANIFEST_GAP_FIELDS, required={"host", "reason"}, label=label, strict=strict)
    if not safe_token(sanitized.get("host")) or not safe_token(sanitized.get("reason")):
        raise SystemExit(f"{label}: unsafe retained coverage gap token")
    if "bytes" in sanitized and (not isinstance(sanitized["bytes"], int) or sanitized["bytes"] < 0):
        raise SystemExit(f"{label}: coverage gap bytes must be a non-negative integer")
    if "root_ref" in sanitized and not PATH_REF_PATTERN.fullmatch(str(sanitized["root_ref"])):
        raise SystemExit(f"{label}: retained refs must use opaque {PATH_REF_PREFIX} values")
    return sanitized


def sanitize_trend_report(data: Any, *, label: str, strict: bool) -> dict[str, Any]:
    sanitized = sanitize_mapping(data, allowed=TREND_FIELDS, required=TREND_FIELDS, label=label, strict=strict)
    sanitized["window"] = sanitize_window(sanitized["window"], label=f"{label}.window")
    for count_key in ("flags", "hosts", "model_eras"):
        sanitized[count_key] = sanitize_count_map(sanitized[count_key], label=f"{label}.{count_key}", strict=strict)
    gaps = sanitized.get("coverage_gaps")
    if not isinstance(gaps, list):
        raise SystemExit(f"{label}.coverage_gaps: expected list")
    sanitized["coverage_gaps"] = [
        sanitize_coverage_gap(gap, label=f"{label}.coverage_gaps[{index}]", strict=strict)
        for index, gap in enumerate(gaps)
    ]
    for key in ("schema_version", "turn_count", "flagged_turn_count", "episode_count"):
        if not isinstance(sanitized[key], int) or sanitized[key] < 0:
            raise SystemExit(f"{label}.{key}: expected non-negative integer")
    return sanitized


def sanitize_retained_manifest_obj(data: Any, *, label: str, strict: bool) -> dict[str, Any]:
    sanitized = sanitize_mapping(data, allowed=MANIFEST_FIELDS, required=MANIFEST_FIELDS, label=label, strict=strict)
    sanitized["window"] = sanitize_window(sanitized["window"], label=f"{label}.window")
    sources = sanitized.get("sources")
    if not isinstance(sources, list) or not (1 <= len(sources) <= 16):
        raise SystemExit(f"{label}.sources: retained sources must be a bounded non-empty list")
    clean_sources: list[dict[str, Any]] = []
    for index, source in enumerate(sources):
        clean_source = sanitize_mapping(
            source,
            allowed=MANIFEST_SOURCE_FIELDS,
            required=MANIFEST_SOURCE_FIELDS,
            label=f"{label}.sources[{index}]",
            strict=strict,
        )
        if not safe_token(clean_source.get("host")) or not safe_token(clean_source.get("status")):
            raise SystemExit(f"{label}.sources[{index}]: unsafe retained source token")
        for key in ("rollout_count", "summary_count"):
            if not isinstance(clean_source[key], int) or clean_source[key] < 0:
                raise SystemExit(f"{label}.sources[{index}].{key}: expected non-negative integer")
        clean_sources.append(clean_source)
    gaps = sanitized.get("coverage_gaps")
    if not isinstance(gaps, list):
        raise SystemExit(f"{label}.coverage_gaps: expected list")
    sanitized["sources"] = clean_sources
    sanitized["coverage_gaps"] = [
        sanitize_coverage_gap(gap, label=f"{label}.coverage_gaps[{index}]", strict=strict)
        for index, gap in enumerate(gaps)
    ]
    return sanitized


def validate_retained_manifest(path: Path) -> None:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if contains_raw_path_fields(manifest):
        raise SystemExit(f"{path}: raw root/path fields are not retention-safe")
    if contains_invalid_ref(manifest):
        raise SystemExit(f"{path}: retained refs must use opaque {PATH_REF_PREFIX} values")
    manifest = sanitize_retained_manifest_obj(manifest, label=str(path), strict=True)
    if manifest.get("retention_safe") is not True:
        raise SystemExit(f"{path}: retention_safe must be true")
    if contains_raw_path_fields(manifest):
        raise SystemExit(f"{path}: raw root/path fields are not retention-safe")
    if contains_path_like_text(manifest):
        raise SystemExit(f"{path}: path-like free text is not retention-safe")
    if contains_invalid_ref(manifest):
        raise SystemExit(f"{path}: retained refs must use opaque {PATH_REF_PREFIX} values")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not (1 <= len(sources) <= 16):
        raise SystemExit(f"{path}: retained sources must be a bounded non-empty list")
    for source in sources:
        if not isinstance(source, dict):
            raise SystemExit(f"{path}: retained source entries must be objects")
        for key in ("rollout_count", "summary_count"):
            count = source.get(key)
            if not isinstance(count, int) or count < 0:
                raise SystemExit(f"{path}: retained source {key} must be a non-negative integer")
    for gap in manifest.get("coverage_gaps", []):
        if isinstance(gap, dict) and "path_ref" in gap:
            raise SystemExit(f"{path}: per-shard path refs are not retention-safe")


def parse_sources(values: list[str] | None, *, require_default_hosts: bool = True) -> list[Source]:
    if not values:
        return [
            Source("local", Path("~/.codex").expanduser()),
            *(
                Source(
                    host,
                    DEFAULT_REMOTE_SOURCE_ROOT / host,
                    "remote_source_not_materialized",
                )
                for host in DEFAULT_REMOTE_HOSTS
            ),
        ]
    sources: list[Source] = []
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--source must be HOST=PATH, got {value!r}")
        host, raw_path = value.split("=", 1)
        sources.append(Source(host.strip(), Path(raw_path).expanduser()))
    if require_default_hosts:
        present = {source.host for source in sources}
        if "local" not in present:
            sources.insert(0, Source("local", Path("~/.codex").expanduser()))
            present.add("local")
        for host in DEFAULT_REMOTE_HOSTS:
            if host not in present:
                sources.append(Source(host, DEFAULT_REMOTE_SOURCE_ROOT / host, "remote_source_not_materialized"))
    return sources


def load_state(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path: Path | None, data: dict[str, Any]) -> None:
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_state_path(raw: str | None) -> Path | None:
    if not raw:
        return None
    path = Path(raw)
    ensure_safe_output_dir(path)
    return path


def earliest_rollout_date(sources: list[Source]) -> dt.datetime | None:
    earliest: dt.datetime | None = None
    for source in sources:
        for rollout in source_rollouts(source):
            parsed = dated_path_from_parts(rollout) or rollout_date_from_path(rollout)
            if parsed and (earliest is None or parsed < earliest):
                earliest = parsed
    return earliest


def local_evidence_gaps(source: Source) -> list[dict[str, Any]]:
    if source.host != "local":
        return []
    gaps: list[dict[str, Any]] = []
    for name in LOCAL_EVIDENCE_FILES:
        evidence = source.root / name
        stem = name.removesuffix(".jsonl")
        if not evidence.exists():
            gaps.append({"host": source.host, "root_ref": path_ref(source.root), "reason": f"{stem}_missing"})
        elif not evidence.is_file() or not os.access(evidence, os.R_OK):
            gaps.append({"host": source.host, "root_ref": path_ref(source.root), "reason": f"{stem}_unreadable"})
    return gaps


def remote_metadata_gap(source: Source, reason: str = "stale_host") -> dict[str, Any]:
    if reason not in ALLOWED_REMOTE_GAP_REASONS:
        reason = "stale_host"
    return {"host": source.host, "root_ref": path_ref(source.root), "reason": reason}


def remote_evidence_gaps(
    source: Source,
    *,
    start: dt.datetime | None,
    end: dt.datetime | None,
) -> list[dict[str, Any]]:
    if source.host not in DEFAULT_REMOTE_HOSTS:
        return []
    metadata_path = source.root / REMOTE_SOURCE_METADATA_FILE
    if not metadata_path.exists() or metadata_path.is_symlink() or not metadata_path.is_file():
        return [remote_metadata_gap(source)]
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [remote_metadata_gap(source)]
    if not isinstance(metadata, dict):
        return [remote_metadata_gap(source)]
    if metadata.get("host") != source.host:
        return [remote_metadata_gap(source)]
    if metadata.get("status") != "ready":
        reason = metadata.get("reason") or metadata.get("status") or "stale_host"
        return [remote_metadata_gap(source, str(reason))]
    materialized_at = parse_time(str(metadata.get("materialized_at") or ""))
    window_start = parse_time(str(metadata.get("window_start") or ""))
    window_end = parse_time(str(metadata.get("window_end") or ""))
    if materialized_at is None or window_start is None or window_end is None:
        return [remote_metadata_gap(source)]
    if start and window_start > start:
        return [remote_metadata_gap(source)]
    if end and window_end != end:
        return [remote_metadata_gap(source)]
    if materialized_at < window_end:
        return [remote_metadata_gap(source)]
    return []


def run_scan(
    args: argparse.Namespace,
    *,
    mode: str,
    start: dt.datetime | None,
    end: dt.datetime,
    emit_start: dt.datetime | None = None,
) -> int:
    output = Path(args.output)
    ensure_safe_output_dir(output)
    safe_state_path(args.state)
    sources = parse_sources(args.source, require_default_hosts=not getattr(args, "allow_partial_hosts", False))
    all_turns: list[TurnSummary] = []
    manifest_sources: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    max_raw_bytes = getattr(args, "max_raw_bytes", 512_000)
    for source in sources:
        if not source.root.exists():
            coverage_gaps.append(
                {
                    "host": source.host,
                    "root_ref": path_ref(source.root),
                    "reason": source.missing_reason or "source_root_missing",
                }
            )
            manifest_sources.append(
                {
                    "host": source.host,
                    "root": source.root.as_posix(),
                    "root_ref": path_ref(source.root),
                    "rollout_count": 0,
                    "summary_count": 0,
                    "status": "missing",
                }
            )
            continue
        coverage_gaps.extend(local_evidence_gaps(source))
        coverage_gaps.extend(
            remote_evidence_gaps(
                source,
                start=start,
                end=end,
            )
        )
        rollouts = source_rollouts(source)
        summaries = source_summary_files(source)
        if not rollouts and not summaries:
            coverage_gaps.append({"host": source.host, "root_ref": path_ref(source.root), "reason": "no_rollout_or_summary_files"})
        manifest_sources.append(
            {
                "host": source.host,
                "root": source.root.as_posix(),
                "root_ref": path_ref(source.root),
                "rollout_count": len(rollouts),
                "summary_count": len(summaries),
                "status": "ready" if rollouts or summaries else "empty",
            }
        )
        for rollout in rollouts:
            size = rollout.stat().st_size
            if size <= max_raw_bytes:
                error_line = first_jsonl_error(rollout)
                if error_line is not None:
                    if rollout_filename_in_window(rollout, start, end) or raw_timestamp_in_window(rollout, start, end):
                        coverage_gaps.append(
                            {
                                "host": source.host,
                                "path_ref": path_ref(rollout),
                                "reason": "invalid_jsonl",
                            }
                        )
                    continue
                if not rollout_has_record_in_window(rollout, start, end):
                    continue
                all_turns.extend(extract_rollout(source, rollout, start, end, emit_start=emit_start))
                continue
            relevance = oversized_rollout_relevance(rollout, start, end)
            if relevance == "irrelevant":
                continue
            if relevance == "unknown":
                coverage_gaps.append(
                    {
                        "host": source.host,
                        "path_ref": path_ref(rollout),
                        "bytes": size,
                        "reason": "oversized_rollout_skipped",
                    }
                )
                continue
            if size > max_raw_bytes:
                coverage_gaps.append(
                    {
                        "host": source.host,
                        "path_ref": path_ref(rollout),
                        "bytes": size,
                        "reason": "oversized_rollout_skipped",
                    }
                )
                continue
        for summary in summaries:
            if not summary_file_relevant(summary, start, end):
                continue
            if first_jsonl_error(summary) is not None:
                coverage_gaps.append(
                    {
                        "host": source.host,
                        "path_ref": path_ref(summary),
                        "reason": "invalid_jsonl",
                    }
                )
                continue
            all_turns.extend(extract_summary_file(source, summary, start, end, emit_start=emit_start))
    if getattr(args, "allow_partial_hosts", False):
        coverage_gaps.append({"host": "scope", "reason": "partial_host_scope"})

    episodes = episode_records(all_turns)
    window = {
        "mode": mode,
        "start": iso(emit_start or start) if (emit_start or start) else None,
        "end": iso(end),
    }
    write_jsonl(output / "turn_summaries.jsonl", (asdict_turn(turn) for turn in all_turns))
    write_jsonl(output / "turn_flags.jsonl", (asdict_turn(turn) for turn in all_turns if turn.issue_flags))
    write_jsonl(output / "episodes.jsonl", episodes)
    write_json(output / "trend_report.json", trend_report(all_turns, episodes, window, coverage_gaps))
    transient_manifest = {
        "schema_version": 1,
        "mode": mode,
        "window": window,
        "sources": manifest_sources,
        "coverage_gaps": coverage_gaps,
        "redaction_policy_version": 1,
        "retention_safe": False,
        "retention_note": "Transient execution manifest may contain raw local paths; promote redacted refs only.",
    }
    write_json(output / "shard_manifest.json", transient_manifest)
    write_json(output / "retained_manifest.json", retained_manifest_from_transient(transient_manifest))
    print(output)
    return 0


def run_discover(args: argparse.Namespace, *, mode: str, start: dt.datetime | None, end: dt.datetime) -> int:
    output = Path(args.output)
    ensure_safe_output_dir(output)
    sources = parse_sources(args.source, require_default_hosts=not getattr(args, "allow_partial_hosts", False))
    manifest_sources: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    for source in sources:
        if not source.root.exists():
            coverage_gaps.append(
                {
                    "host": source.host,
                    "root_ref": path_ref(source.root),
                    "reason": source.missing_reason or "source_root_missing",
                }
            )
            manifest_sources.append(
                {
                    "host": source.host,
                    "root": source.root.as_posix(),
                    "root_ref": path_ref(source.root),
                    "rollout_count": 0,
                    "summary_count": 0,
                    "status": "missing",
                }
            )
            continue
        coverage_gaps.extend(local_evidence_gaps(source))
        coverage_gaps.extend(
            remote_evidence_gaps(
                source,
                start=start,
                end=end,
            )
        )
        rollouts = source_rollouts(source)
        summaries = source_summary_files(source)
        if not rollouts and not summaries:
            coverage_gaps.append({"host": source.host, "root_ref": path_ref(source.root), "reason": "no_rollout_or_summary_files"})
        manifest_sources.append(
            {
                "host": source.host,
                "root": source.root.as_posix(),
                "root_ref": path_ref(source.root),
                "rollout_count": len(rollouts),
                "summary_count": len(summaries),
                "status": "ready" if rollouts or summaries else "empty",
            }
        )
    if getattr(args, "allow_partial_hosts", False):
        coverage_gaps.append({"host": "scope", "reason": "partial_host_scope"})

    window = {
        "mode": mode,
        "start": iso(start) if start else None,
        "end": iso(end),
    }
    transient_manifest = {
        "schema_version": 1,
        "mode": mode,
        "window": window,
        "sources": manifest_sources,
        "coverage_gaps": coverage_gaps,
        "redaction_policy_version": 1,
        "retention_safe": False,
        "retention_note": "Transient execution manifest may contain raw local paths; promote redacted refs only.",
    }
    write_json(output / "shard_manifest.json", transient_manifest)
    write_json(output / "retained_manifest.json", retained_manifest_from_transient(transient_manifest))
    print(output / "shard_manifest.json")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    end = parse_time(args.end) if args.end else utc_now()
    if end is None:
        raise SystemExit(f"invalid --end timestamp: {args.end}")
    start = parse_time(args.start) if args.start else None
    if not args.start:
        raise SystemExit("--start is required for discover")
    if start is None:
        raise SystemExit(f"invalid --start timestamp: {args.start}")
    return run_discover(args, mode=args.mode, start=start, end=end)


def scan_end(args: argparse.Namespace) -> dt.datetime:
    end_value = getattr(args, "end", None)
    end = parse_time(end_value) if end_value else utc_now()
    if end is None:
        raise SystemExit(f"invalid --end timestamp: {end_value}")
    return end


def cmd_scan_daily(args: argparse.Namespace) -> int:
    end = scan_end(args)
    state_path = safe_state_path(args.state)
    state = load_state(state_path) if state_path else {}
    last = parse_time(state.get("last_scan_at"))
    lookback_start = end - dt.timedelta(days=args.active_lookback_days)
    if last and last <= end:
        start = min(last, lookback_start)
        emit_start = last
    else:
        start = lookback_start
        emit_start = None
    return run_scan(args, mode="daily", start=start, end=end, emit_start=emit_start)


def cmd_scan_weekly(args: argparse.Namespace) -> int:
    end = scan_end(args)
    start = end - dt.timedelta(days=args.days)
    return run_scan(args, mode="weekly", start=start, end=end)


def bounded_baseline_end(start: dt.datetime, window_days: int, now: dt.datetime) -> dt.datetime:
    return min(now, start + dt.timedelta(days=window_days))


def cmd_baseline(args: argparse.Namespace) -> int:
    now = scan_end(args)
    sources = parse_sources(args.source, require_default_hosts=not args.allow_partial_hosts)
    if args.from_value == "first":
        start = earliest_rollout_date(sources) or (now - dt.timedelta(days=args.window_days))
    else:
        start = parse_time(args.from_value)
        if start is None:
            raise SystemExit(f"invalid --from timestamp: {args.from_value}")
    mode = f"baseline-{args.window_days}d"
    return run_scan(args, mode=mode, start=start, end=bounded_baseline_end(start, args.window_days, now))


def parse_manifest_window_time(window: dict[str, Any], key: str) -> dt.datetime | None:
    value = window.get(key)
    if value is None or value == "":
        return None
    parsed = parse_time(str(value))
    if parsed is None:
        raise SystemExit(f"invalid manifest window {key}: {value}")
    return parsed


def cmd_make_shards(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if manifest.get("retention_safe") is True:
        raise SystemExit("make-shards requires transient shard_manifest.json, not retained_manifest.json")
    output = Path(args.output)
    ensure_safe_output_dir(output)
    sources = manifest.get("sources", [])
    window = manifest.get("window") or {}
    start = parse_manifest_window_time(window, "start")
    end = parse_manifest_window_time(window, "end")
    rows: list[dict[str, Any]] = []
    for source in sources:
        host = source.get("host")
        if not source.get("root"):
            raise SystemExit("make-shards requires transient manifest sources with raw root fields")
        root = Path(source["root"]).expanduser()
        if not root.exists():
            rows.append({"host": host, "path": root.as_posix(), "path_ref": path_ref(root), "status": "missing", "coverage_gap": "source root missing"})
            continue
        for rollout in source_rollouts(Source(str(host), root)):
            size = rollout.stat().st_size
            row = {"host": host, "path": rollout.as_posix(), "path_ref": path_ref(rollout), "bytes": size}
            if size <= args.max_raw_bytes:
                error_line = first_jsonl_error(rollout)
                if error_line is not None:
                    if rollout_filename_in_window(rollout, start, end) or raw_timestamp_in_window(rollout, start, end):
                        row["status"] = "invalid"
                        row["coverage_gap"] = "invalid JSONL; cannot safely hand to extractor shard"
                        rows.append(row)
                    continue
                if rollout_has_record_in_window(rollout, start, end):
                    row["status"] = "ready"
                    rows.append(row)
                continue
            relevance = oversized_rollout_relevance(rollout, start, end)
            if relevance == "irrelevant":
                continue
            if relevance == "unknown":
                row["status"] = "oversized"
                row["coverage_gap"] = "rollout exceeds timestamp relevance scan; use bounded rollout-summary before extractor handoff"
                rows.append(row)
                continue
            if size > args.max_raw_bytes:
                row["status"] = "oversized"
                row["coverage_gap"] = "rollout exceeds max raw shard bytes; use bounded rollout-summary before extractor handoff"
                rows.append(row)
                continue
    write_jsonl(output / "shards.jsonl", rows)
    print(output / "shards.jsonl")
    return 0


def cmd_validate_manifest(args: argparse.Namespace) -> int:
    validate_retained_manifest(Path(args.manifest))
    print(f"validated: {args.manifest}")
    return 0


def validate_output_run(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if run_dir.is_symlink():
        raise SystemExit(f"refusing symlinked output directory: {run_dir}")
    required = {
        "turn_summaries.jsonl": {"turn_id", "episode_id", "host", "redacted_user_prompt_summary", "issue_flags"},
        "episodes.jsonl": {"episode_id", "host", "topic", "friction_flags"},
        "turn_flags.jsonl": {"turn_id", "episode_id", "issue_flags"},
    }
    for name, keys in required.items():
        path = run_dir / name
        if not path.exists():
            raise SystemExit(f"missing output: {path}")
        try:
            rows = list(iter_jsonl_strict(path))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        for line_no, obj in rows:
            missing = keys - set(obj)
            if missing:
                raise SystemExit(f"{path}:{line_no}: missing keys {sorted(missing)}")
            if contains_unredacted_sensitive_text(obj):
                raise SystemExit(f"{path}:{line_no}: unredacted sensitive text in retained output")
    sanitize_retained_jsonl(run_dir / "episodes.jsonl", allowed=EPISODE_FIELDS, strict=False, validator=validate_episode_row)
    sanitize_retained_jsonl(run_dir / "turn_flags.jsonl", allowed=TURN_FLAG_FIELDS, strict=False, validator=validate_turn_flag_row)
    trend_path = run_dir / "trend_report.json"
    trend = sanitize_trend_report(json.loads(trend_path.read_text(encoding="utf-8")), label=str(trend_path), strict=True)
    validate_retained_manifest(run_dir / "retained_manifest.json")
    retained_manifest = json.loads((run_dir / "retained_manifest.json").read_text(encoding="utf-8"))
    return trend, retained_manifest


def retained_export_files_from_run(run_dir: Path) -> dict[str, bytes]:
    validate_output_run(run_dir)
    episodes = sanitize_retained_jsonl(
        run_dir / "episodes.jsonl",
        allowed=EPISODE_FIELDS,
        strict=False,
        validator=validate_episode_row,
    )
    turn_flags = sanitize_retained_jsonl(
        run_dir / "turn_flags.jsonl",
        allowed=TURN_FLAG_FIELDS,
        strict=False,
        validator=validate_turn_flag_row,
    )
    trend = sanitize_trend_report(
        json.loads((run_dir / "trend_report.json").read_text(encoding="utf-8")),
        label=str(run_dir / "trend_report.json"),
        strict=False,
    )
    manifest = sanitize_retained_manifest_obj(
        json.loads((run_dir / "retained_manifest.json").read_text(encoding="utf-8")),
        label=str(run_dir / "retained_manifest.json"),
        strict=False,
    )
    return {
        "episodes.jsonl": jsonl_bytes(episodes),
        "turn_flags.jsonl": jsonl_bytes(turn_flags),
        "trend_report.json": json_bytes(trend),
        "retained_manifest.json": json_bytes(manifest),
    }


def retained_export_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[name])
        digest.update(b"\0")
    return digest.hexdigest()


def retained_export_files_from_dir(run_dir: Path) -> dict[str, bytes]:
    return {name: (run_dir / name).read_bytes() for name in RETAINED_OUTPUT_FILES}


def validate_retained_output_dir(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if run_dir.is_symlink():
        raise SystemExit(f"refusing symlinked retained output directory: {run_dir}")
    if not run_dir.is_dir():
        raise SystemExit(f"retained output directory not found: {run_dir}")
    allowed = set(RETAINED_OUTPUT_FILES)
    for path in run_dir.iterdir():
        if path.name not in allowed or path.is_symlink() or not path.is_file():
            raise SystemExit(f"unexpected retained output: {path}")
    episodes_path = run_dir / "episodes.jsonl"
    turn_flags_path = run_dir / "turn_flags.jsonl"
    for path in (episodes_path, turn_flags_path):
        if not path.exists():
            raise SystemExit(f"missing retained output: {path}")
    sanitize_retained_jsonl(episodes_path, allowed=EPISODE_FIELDS, strict=True, validator=validate_episode_row)
    sanitize_retained_jsonl(turn_flags_path, allowed=TURN_FLAG_FIELDS, strict=True, validator=validate_turn_flag_row)
    trend_path = run_dir / "trend_report.json"
    if not trend_path.exists():
        raise SystemExit(f"missing retained output: {trend_path}")
    trend = sanitize_trend_report(json.loads(trend_path.read_text(encoding="utf-8")), label=str(trend_path), strict=True)
    manifest_path = run_dir / "retained_manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing retained output: {manifest_path}")
    validate_retained_manifest(manifest_path)
    retained_manifest = sanitize_retained_manifest_obj(json.loads(manifest_path.read_text(encoding="utf-8")), label=str(manifest_path), strict=True)
    return trend, retained_manifest


def cmd_validate_output(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    validate_output_run(run_dir)
    print(f"validated: {run_dir}")
    return 0


def cmd_export_retained(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    files = retained_export_files_from_run(run_dir)
    output = Path(args.output)
    if output.is_symlink():
        raise SystemExit(f"refusing symlinked retained output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    allowed = set(RETAINED_OUTPUT_FILES)
    for path in output.iterdir():
        if path.name not in allowed or path.is_symlink() or not path.is_file():
            raise SystemExit(f"refusing to export into directory with unexpected retained output: {path}")
    for name, content in files.items():
        target = output / name
        if target.exists() and (target.is_symlink() or not target.is_file()):
            raise SystemExit(f"refusing to overwrite unexpected retained output: {target}")
        temp = output / f".{name}.tmp"
        target.parent.mkdir(parents=True, exist_ok=True)
        temp.write_bytes(content)
        os.replace(temp, target)
    validate_retained_output_dir(output)
    print(output)
    return 0


def cmd_validate_retained(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    validate_retained_output_dir(run_dir)
    print(f"validated: {run_dir}")
    return 0


def cmd_advance_state(args: argparse.Namespace) -> int:
    state_path = safe_state_path(args.state)
    if state_path is None:
        raise SystemExit("--state is required")
    history_commit = str(args.history_commit or "")
    if not COMMIT_SHA_PATTERN.fullmatch(history_commit):
        raise SystemExit("--history-commit must be a full 40-character hex commit SHA")
    run_dir = Path(args.run_dir)
    expected_files = retained_export_files_from_run(run_dir)
    trend, retained_manifest = validate_output_run(run_dir)
    retained_trend, retained_export_manifest = validate_retained_output_dir(Path(args.retained_run_dir))
    actual_files = retained_export_files_from_dir(Path(args.retained_run_dir))
    if actual_files != expected_files:
        raise SystemExit("retained export does not match scan output")
    if trend.get("window") != retained_trend.get("window"):
        raise SystemExit("retained export window does not match scan output window")
    if retained_manifest.get("window") != retained_export_manifest.get("window"):
        raise SystemExit("retained export manifest window does not match scan output manifest")
    window = trend.get("window") or {}
    last_scan_at = window.get("end")
    last_mode = window.get("mode")
    if not isinstance(last_scan_at, str) or not isinstance(last_mode, str):
        raise SystemExit("trend_report.json window must include mode and end")
    if last_mode != "daily":
        raise SystemExit("advance-state only supports daily runs")
    coverage_gaps = list(trend.get("coverage_gaps") or []) + list(retained_manifest.get("coverage_gaps") or [])
    if coverage_gaps:
        raise SystemExit("refusing to advance state while coverage gaps are present")
    state = load_state(state_path)
    new_scan_at = parse_time(last_scan_at)
    previous_scan_at = parse_time(state.get("last_scan_at"))
    if new_scan_at is None:
        raise SystemExit("trend_report.json window end must be a valid timestamp")
    if previous_scan_at and new_scan_at < previous_scan_at:
        raise SystemExit("refusing to move retrospective state backwards")
    if previous_scan_at:
        window_start_at = parse_time(str(window.get("start") or ""))
        if window_start_at is None:
            raise SystemExit("trend_report.json window start must be valid when advancing existing state")
        if window_start_at > previous_scan_at:
            raise SystemExit("refusing to advance state with a scan window that does not cover previous state")
    state["last_scan_at"] = last_scan_at
    state["last_retained_export_sha256"] = retained_export_digest(actual_files)
    state["last_history_commit"] = history_commit
    state["last_mode"] = last_mode
    save_state(state_path, state)
    print(f"advanced: {state_path}")
    return 0


def add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--source",
        action="append",
        help="Source in HOST=PATH form. Defaults to local=~/.codex plus materialized miku-bot-dev and hoteng-srv-01 sources.",
    )
    parser.add_argument("--state", help="State JSON path for incremental runs.")
    parser.add_argument("--output", required=True, help="Output directory for retrospective artifacts.")
    parser.add_argument("--max-raw-bytes", type=int, default=512_000, help="Skip raw extraction for larger rollout files and report a coverage gap.")
    parser.add_argument(
        "--allow-partial-hosts",
        action="store_true",
        help="Allow intentionally narrowed scans without default remote-host coverage gaps. Partial scans cannot advance shared state.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build redacted Codex session retrospective artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover")
    add_common_scan_args(discover)
    discover.add_argument("--mode", required=True)
    discover.add_argument("--start", required=True)
    discover.add_argument("--end")
    discover.set_defaults(func=cmd_discover)

    daily = subparsers.add_parser("scan-daily")
    add_common_scan_args(daily)
    daily.add_argument("--active-lookback-days", type=int, default=14)
    daily.add_argument("--end", help="Fixed exclusive window end timestamp. Use the same timestamp used to materialize remote sources.")
    daily.set_defaults(func=cmd_scan_daily)

    weekly = subparsers.add_parser("scan-weekly")
    add_common_scan_args(weekly)
    weekly.add_argument("--days", type=int, default=7)
    weekly.add_argument("--end", help="Fixed exclusive window end timestamp. Use the same timestamp used to materialize remote sources.")
    weekly.set_defaults(func=cmd_scan_weekly)

    baseline = subparsers.add_parser("baseline")
    add_common_scan_args(baseline)
    baseline.add_argument("--window-days", type=int, default=90)
    baseline.add_argument("--from", dest="from_value", default="first")
    baseline.add_argument("--end", help="Fixed upper bound timestamp for the baseline window.")
    baseline.set_defaults(func=cmd_baseline)

    shards = subparsers.add_parser("make-shards")
    shards.add_argument("--manifest", required=True)
    shards.add_argument("--output", required=True)
    shards.add_argument("--max-raw-bytes", type=int, default=512_000)
    shards.set_defaults(func=cmd_make_shards)

    validate = subparsers.add_parser("validate-output")
    validate.add_argument("--run-dir", required=True)
    validate.set_defaults(func=cmd_validate_output)

    export_retained = subparsers.add_parser("export-retained")
    export_retained.add_argument("--run-dir", required=True)
    export_retained.add_argument("--output", required=True)
    export_retained.set_defaults(func=cmd_export_retained)

    validate_retained = subparsers.add_parser("validate-retained")
    validate_retained.add_argument("--run-dir", required=True)
    validate_retained.set_defaults(func=cmd_validate_retained)

    advance = subparsers.add_parser("advance-state")
    advance.add_argument("--run-dir", required=True)
    advance.add_argument("--retained-run-dir", required=True)
    advance.add_argument("--state", required=True)
    advance.add_argument("--history-commit", required=True)
    advance.set_defaults(func=cmd_advance_state)

    validate_manifest = subparsers.add_parser("validate-manifest")
    validate_manifest.add_argument("--manifest", required=True)
    validate_manifest.set_defaults(func=cmd_validate_manifest)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
