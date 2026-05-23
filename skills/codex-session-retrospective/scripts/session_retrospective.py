#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
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
    re.compile(r"^Run inside the dedicated worktree provisioned for this automation\b", re.I),
    re.compile(r"^Use \$codex-session-retrospective to run\b", re.I),
    re.compile(r"^Use the installed codex-session-retrospective workflow\b", re.I),
)

AUTOMATION_PROMPT_MARKERS = (
    "Run a read-only daily retrospective over Joey's Codex session activity.",
    "Run a read-only weekly retrospective over Joey's Codex session activity.",
    "Evidence scope must match $remote-host-context's default host policy",
    "Use the automation's configured model and reasoning effort",
    "When reconstructing the real user task from rollouts, ignore injected wrapper content",
    "Write task-local artifacts under .codex-local/session-retrospective/runs/",
)

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.I), "[REDACTED_PRIVATE_KEY]"),
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
    r"(?:\b(secret|token|credential|password|private key|production|destructive|rm -rf|reset --hard|customer data|privacy|pii)\b|"
    r"客户|客户数据|凭据|凭证|密钥|生产|破坏性)",
    re.I,
)

DEFAULT_REMOTE_HOSTS = ("miku-bot-dev", "hoteng-srv-01")
RETAINED_CUSTOM_SOURCE_HOST = "custom_source"
RETAINED_DIRECT_SOURCE_HOSTS = frozenset(("local", *DEFAULT_REMOTE_HOSTS))
RETAINED_EVIDENCE_HOSTS = frozenset((*RETAINED_DIRECT_SOURCE_HOSTS, RETAINED_CUSTOM_SOURCE_HOST))
RETAINED_HOSTS = frozenset((*RETAINED_EVIDENCE_HOSTS, "scope"))
EXPECTED_HISTORY_REPO = "Joey-Tools/codex-session-retrospective-history"
DEFAULT_REMOTE_SOURCE_ROOT = Path(".codex-local/session-retrospective/remote-sources")
REMOTE_SOURCE_METADATA_FILE = "source_metadata.json"
LOCAL_EVIDENCE_FILES = ("session_index.jsonl", "history.jsonl")
SAFE_OUTPUT_PARTS = (".codex-local", "session-retrospective")
PATH_REF_PREFIX = "path_ref_v1"
PATH_REF_PATTERN = re.compile(r"^path_ref_v1:[0-9a-f]{16}$")
SESSION_REF_PREFIX = "session_ref_v1"
EPISODE_REF_PREFIX = "episode_ref_v1"
TURN_REF_PREFIX = "turn_ref_v1"
OPAQUE_ID_PATTERN = re.compile(r"^(?:session_ref_v1|episode_ref_v1|turn_ref_v1):[0-9a-f]{20}$")
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
BARE_64_HEX_PATTERN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
INTERNAL_HOSTNAME_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|lan|example|invalid|test)\b",
    re.I,
)
OPAQUE_REF_KEY_FILE = Path(".codex-local/session-retrospective/opaque_ref_key")
PATH_REF_KEY: bytes | None = None
ROLLOUT_TIMESTAMP_SCAN_BYTES = 1024 * 1024
RETAINED_SUMMARY_KINDS = frozenset(("summary", "function_call_output"))
RETAINED_OUTPUT_FILES = ("episodes.jsonl", "turn_flags.jsonl", "trend_report.json", "retained_manifest.json")
TRANSIENT_OUTPUT_FILES = ("turn_summaries.jsonl", "shard_manifest.json", "shards.jsonl")
HISTORY_FORBIDDEN_FILENAMES = frozenset((*TRANSIENT_OUTPUT_FILES, *LOCAL_EVIDENCE_FILES, REMOTE_SOURCE_METADATA_FILE))
HISTORY_FORBIDDEN_COMPONENTS = frozenset((".codex", ".codex-local", ".codex-tmp", "raw", "scratch", "transient"))
HISTORY_FORBIDDEN_NAME_STEMS = frozenset(
    (
        "history",
        "session_index",
        "shard_manifest",
        "shards",
        "source_metadata",
        "turn_summaries",
    )
)
HISTORY_FORBIDDEN_NAME_TOKENS = frozenset(
    (
        "credential",
        "credentials",
        "key",
        "keys",
        "raw",
        "rollout",
        "scratch",
        "secret",
        "secrets",
        "token",
        "tokens",
        "transcript",
        "transcripts",
        "transient",
    )
)
HISTORY_FORBIDDEN_TOKEN_PHRASES = (
    ("conversation", "log"),
    ("full", "prompt"),
    ("message", "log"),
    ("prompt", "log"),
    ("tool", "output"),
    ("turn", "summaries"),
    ("user", "prompt"),
)
HISTORY_FORBIDDEN_COMPACT_NAME_PARTS = frozenset(
    (
        "conversationlog",
        "fullprompt",
        "messagelog",
        "promptlog",
        "rawtranscript",
        "tooloutput",
        "turnsummaries",
        "userprompt",
    )
)
HISTORY_FORBIDDEN_COMPACT_NAME_PREFIXES = frozenset(("raw",))
HISTORY_TEXT_EXTENSIONS = (".md", ".txt")
HISTORY_JSON_EXTENSIONS = (".json",)
HISTORY_STRIPPABLE_NAME_SUFFIXES = frozenset((*HISTORY_TEXT_EXTENSIONS, *HISTORY_JSON_EXTENSIONS, ".jsonl"))
HISTORY_ROOT_FILES = frozenset((".gitignore", "AGENTS.md", "README.md"))
HISTORY_FLAT_RETAINED_EXPORT_PARENTS = frozenset(("retained/daily", "retained/weekly", "retained/baseline"))
HISTORY_SCHEMA_FILES = frozenset(("retained-manifest-v1.schema.json", "session-retrospective-v1.schema.json"))
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


def default_window_end() -> dt.datetime:
    return utc_now().replace(microsecond=0)


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def compact(text: str, limit: int = 600) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "..."


def redact(text: str) -> tuple[str, bool]:
    redacted = text
    sensitive_redacted = False
    for pattern, label in SECRET_PATTERNS:
        redacted, count = pattern.subn(label, redacted)
        sensitive_redacted = sensitive_redacted or count > 0
    if len(redacted) > 1200:
        redacted = redacted[:1200].rstrip() + " [TRUNCATED]"
    return redacted, sensitive_redacted


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
    def topic_ref(value: str) -> str:
        digest = hmac.new(path_ref_key(), f"topic\0{value}".encode("utf-8", errors="surrogatepass"), hashlib.sha256)
        return "topic_ref:" + digest.hexdigest()[:12]

    if meaningful:
        return topic_ref("+".join(sorted(dict.fromkeys(meaningful))[:6]))
    compacted = re.sub(r"\s+", "", redacted_text)
    return topic_ref(compacted) if compacted else "unknown"


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


def parse_opaque_ref_key(raw: str, *, label: str) -> bytes:
    value = raw.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise SystemExit(f"{label}: opaque ref key must be 64 hex characters")
    return bytes.fromhex(value)


def read_opaque_ref_key_file(path: Path) -> bytes:
    if path.is_symlink():
        raise SystemExit(f"refusing symlinked opaque ref key file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SystemExit(f"refusing symlinked opaque ref key file: {path}") from exc
        raise
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return parse_opaque_ref_key(handle.read(), label=str(path))


def create_or_read_opaque_ref_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    key_hex = secrets.token_hex(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return read_opaque_ref_key_file(path)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SystemExit(f"refusing symlinked opaque ref key file: {path}") from exc
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(key_hex + "\n")
    return bytes.fromhex(key_hex)


def path_ref_key() -> bytes:
    global PATH_REF_KEY
    if PATH_REF_KEY is not None:
        return PATH_REF_KEY
    env_key = os.environ.get("CODEX_SESSION_RETROSPECTIVE_KEY")
    if env_key:
        PATH_REF_KEY = parse_opaque_ref_key(env_key, label="CODEX_SESSION_RETROSPECTIVE_KEY")
        return PATH_REF_KEY
    key_path = Path(os.environ.get("CODEX_SESSION_RETROSPECTIVE_KEY_FILE", OPAQUE_REF_KEY_FILE.as_posix())).expanduser()
    if key_path.exists():
        PATH_REF_KEY = read_opaque_ref_key_file(key_path)
    else:
        PATH_REF_KEY = create_or_read_opaque_ref_key(key_path)
    return PATH_REF_KEY


def path_ref(value: str | os.PathLike[str] | None, length: int = 16) -> str | None:
    if not value:
        return None
    digest = hmac.new(path_ref_key(), os.fspath(value).encode("utf-8", errors="surrogatepass"), hashlib.sha256)
    return f"{PATH_REF_PREFIX}:{digest.hexdigest()[:length]}"


def opaque_digest(value: str | os.PathLike[str], length: int = 20) -> str:
    digest = hmac.new(path_ref_key(), os.fspath(value).encode("utf-8", errors="surrogatepass"), hashlib.sha256)
    return digest.hexdigest()[:length]


def opaque_id(prefix: str, value: str | os.PathLike[str]) -> str:
    return f"{prefix}:{opaque_digest(value, 20)}"


def opaque_session_id(value: str | os.PathLike[str]) -> str:
    return opaque_id(SESSION_REF_PREFIX, f"session_id_v1|{os.fspath(value)}")


def opaque_episode_id(value: str | os.PathLike[str]) -> str:
    return opaque_id(EPISODE_REF_PREFIX, f"episode_id_v1|{os.fspath(value)}")


def opaque_turn_id(value: str | os.PathLike[str]) -> str:
    return opaque_id(TURN_REF_PREFIX, f"turn_id_v1|{os.fspath(value)}")


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_source_hash(path: Path) -> str:
    digest = hmac.new(path_ref_key(), b"source_hash_v1\0", hashlib.sha256)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_safe_output_dir(path: Path) -> Path:
    expanded = path.expanduser()
    parts = expanded.resolve(strict=False).parts
    for index in range(len(parts) - len(SAFE_OUTPUT_PARTS) + 1):
        if parts[index : index + len(SAFE_OUTPUT_PARTS)] == SAFE_OUTPUT_PARTS:
            return expanded
    raise SystemExit("output directory for transient artifacts must be under .codex-local/session-retrospective")


def session_id_from_path(path: Path) -> str:
    match = re.search(r"^rollout-\d{4}-\d{2}-\d{2}(?:T\d{2}-\d{2}-\d{2})?-(.+)\.jsonl$", path.name)
    if match:
        return opaque_session_id(match.group(1))
    return opaque_session_id(path.as_posix())


def rollout_date_from_path(path: Path) -> dt.datetime | None:
    match = re.search(r"^rollout-(\d{4}-\d{2}-\d{2})(?:T(\d{2})-(\d{2})-(\d{2}))?-", path.name)
    if not match:
        return None
    if match.group(2):
        return parse_time(f"{match.group(1)}T{match.group(2)}:{match.group(3)}:{match.group(4)}Z")
    return parse_time(f"{match.group(1)}T00:00:00Z")


def dated_path_from_parts(path: Path) -> dt.datetime | None:
    parts = path.parts
    for index in range(len(parts) - 3, -1, -1):
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
                record = json.loads(line)
            except json.JSONDecodeError:
                return line_no
            if not isinstance(record, dict):
                return line_no
    return None


def iter_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    yield from iter_jsonl_strict(path)


def iter_jsonl_strict(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_no}: JSONL record must be an object")
            yield line_no, record


def iter_jsonl_strict_bytes(data: bytes, label: str) -> Iterable[tuple[int, dict[str, Any]]]:
    for line_no, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label}:{line_no}: invalid JSON") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{label}:{line_no}: JSONL record must be an object")
        yield line_no, record


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
    if payload.get("type") == "task_complete":
        return str(payload.get("last_agent_message") or "").strip()
    return ""


def record_timestamp(record: dict[str, Any]) -> str | None:
    payload = record.get("payload") or {}
    for key in ("timestamp", "time", "created_at", "ts"):
        value = record.get(key)
        if value is None and isinstance(payload, dict):
            value = payload.get(key)
        if isinstance(value, str) and parse_time(value):
            return iso(parse_time(value) or utc_now())
    return None


def record_timestamp_or_fallback(record: dict[str, Any], path: Path) -> str | None:
    fallback = rollout_date_from_path(path) or dated_path_from_parts(path)
    return record_timestamp(record) or (iso(fallback) if fallback else None)


def record_timestamp_with_origin(record: dict[str, Any], path: Path) -> tuple[str | None, bool]:
    timestamp = record_timestamp(record)
    if timestamp:
        return timestamp, False
    fallback = rollout_date_from_path(path) or dated_path_from_parts(path)
    return (iso(fallback) if fallback else None), True


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
    key = re.sub(r"\W+", " ", text.casefold()).strip()
    for prefix in ("user says ", "user said "):
        if key.startswith(prefix):
            return key[len(prefix) :].strip()
    return key


def duplicate_user_turn(current_text: str, current_time: str, previous: tuple[str, str] | None) -> bool:
    if previous is None or not current_time or current_time != previous[1]:
        return False
    current_key = dedupe_text_key(current_text)
    previous_key = dedupe_text_key(previous[0])
    if not current_key or not previous_key:
        return False
    return current_key == previous_key


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
    search_roots = [sessions] if sessions.exists() else [source.root]
    archived = source.root / "archived_sessions"
    if archived.exists() and sessions.exists():
        search_roots.append(archived)
    return sorted(
        path
        for search_root in search_roots
        for path in search_root.rglob("rollout-*.jsonl")
        if safe_source_file(path, source.root) and not path.name.startswith("rollout-summary")
    )


def source_summary_files(source: Source) -> list[Path]:
    if not source.root.exists():
        return []
    return sorted(path for path in source.root.rglob("rollout-summary*.jsonl") if safe_source_file(path, source.root))


def rollout_window_date(path: Path) -> dt.datetime | None:
    return rollout_date_from_path(path) or dated_path_from_parts(path)


def rollout_has_record_in_window(
    path: Path,
    start: dt.datetime | None,
    end: dt.datetime | None,
    *,
    allow_mtime_fallback: bool = False,
) -> bool:
    if start is None and end is None:
        return True
    fallback = rollout_window_date(path)
    saw_record = False
    saw_record_without_timestamp = False
    for _line_no, record in iter_jsonl(path):
        saw_record = True
        timestamp = parse_time(record_timestamp(record))
        if timestamp is not None:
            pass
        else:
            saw_record_without_timestamp = True
            timestamp = fallback
        if timestamp is None:
            continue
        if start and timestamp < start:
            continue
        if end and timestamp >= end:
            continue
        return True
    if saw_record and saw_record_without_timestamp and allow_mtime_fallback and rollout_mtime_active(path, start, end):
        return True
    return False


def rollout_filename_in_window(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    rollout_date = rollout_window_date(path)
    if rollout_date is None:
        return True
    rollout_end = rollout_date + dt.timedelta(days=1)
    if start and rollout_end <= start:
        return False
    if end and rollout_date >= end:
        return False
    return True


def rollout_candidate_relevant(
    path: Path,
    start: dt.datetime | None,
    end: dt.datetime | None,
    *,
    max_raw_bytes: int | None = None,
    allow_mtime_fallback: bool = False,
) -> bool:
    if start is None and end is None:
        return True
    rollout_date = rollout_window_date(path)
    if rollout_date and end and rollout_date >= end:
        return False
    if rollout_date and start and rollout_date < start:
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        except OSError:
            return True
        if allow_mtime_fallback and (not start or mtime >= start) and (not end or mtime < end):
            return True
        if max_raw_bytes is not None and path.stat().st_size > max_raw_bytes:
            return True
        return raw_timestamp_in_window(path, start, end)
    return True


def rollout_mtime_active(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    return rollout_active_mtime(path, start, end) is not None


def rollout_active_mtime(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> dt.datetime | None:
    if start is None and end is None:
        return None
    try:
        mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
    except OSError:
        return start
    if start and mtime < start:
        return None
    if end and mtime >= end:
        return None
    return mtime


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
    size = path.stat().st_size
    scan_bytes = size if max_scan_bytes is None else min(size, max_scan_bytes)
    complete = scan_bytes == size
    with path.open("rb") as handle:
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
                return True, complete
            carry = window[-256:]
    return False, complete


def oversized_rollout_relevance(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> str:
    if start is None and end is None:
        return "relevant"
    rollout_date = rollout_window_date(path)
    if rollout_date and end and rollout_date >= end:
        return "irrelevant"
    if rollout_date and start and rollout_date < start:
        found, complete = oversized_rollout_has_timestamp_in_window(
            path,
            start,
            end,
            max_scan_bytes=ROLLOUT_TIMESTAMP_SCAN_BYTES,
        )
        if found:
            return "relevant"
        if not complete:
            return "unknown"
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        except OSError:
            mtime = None
        if mtime and ((start and mtime < start) or (end and mtime >= end)):
            return "irrelevant"
        return "unknown"
    return "relevant"


def oversized_rollout_relevant(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    return oversized_rollout_relevance(path, start, end) == "relevant"


def raw_timestamp_in_window(path: Path, start: dt.datetime | None, end: dt.datetime | None, *, max_scan_bytes: int | None = None) -> bool:
    if max_scan_bytes is None:
        max_scan_bytes = path.stat().st_size
    found, _complete = oversized_rollout_has_timestamp_in_window(
        path,
        start,
        end,
        max_scan_bytes=max_scan_bytes,
    )
    return found


def summary_file_relevant(path: Path, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    if start is None and end is None:
        return True
    summary_date = summary_date_from_path(path)
    if summary_date and start and summary_date < start:
        if summary_date + dt.timedelta(days=1) > start:
            return True
        return raw_timestamp_in_window(path, start, end)
    if summary_date and end and summary_date >= end:
        return False
    return True


def summary_timestamp_with_fallback(record: dict[str, Any], path: Path) -> dt.datetime | None:
    return parse_time(str(record.get("timestamp") or "")) or summary_date_from_path(path)


def infer_model_era(model: str | None, timestamp: str | None) -> str:
    if model:
        if "gpt-5.5" in model:
            return "gpt-5.5"
        if "gpt-5.4" in model:
            return "gpt-5.4"
        if "gpt-5.3" in model:
            return "gpt-5.3-codex"
        return "other-model"
    parsed = parse_time(timestamp)
    if parsed and parsed.date() < dt.date(2026, 1, 1):
        return "pre-gpt-5.3-codex"
    return "unknown"


def retained_model_id(model: str | None) -> str | None:
    if not model:
        return None
    era = infer_model_era(model, None)
    if era != "other-model":
        return era
    return None


def retained_summary_kind(kind: str) -> str:
    if kind in RETAINED_SUMMARY_KINDS:
        return kind
    return "other_summary"


def extract_rollout(
    source: Source,
    path: Path,
    start: dt.datetime | None,
    end: dt.datetime | None,
    *,
    emit_start: dt.datetime | None = None,
    allow_mtime_fallback: bool = False,
) -> list[TurnSummary]:
    session_id = session_id_from_path(path)
    source_hash = file_source_hash(path)
    cwd: str | None = None
    model: str | None = None
    current: TurnSummary | None = None
    turns: list[TurnSummary] = []
    assistant_bits: list[str] = []
    last_user_fingerprint: tuple[str, str] | None = None
    current_emitted = False
    current_has_post_prompt_evidence = False
    emit_threshold = emit_start or start

    def flush_assistant() -> None:
        nonlocal assistant_bits
        if current and assistant_bits:
            current.assistant_action_summary = safe_assistant_summary(assistant_bits)
            assistant_bits = []

    def is_emit_record(timestamp: dt.datetime | None, *, timestamp_is_fallback: bool) -> bool:
        if emit_threshold is None or timestamp is None or timestamp >= emit_threshold:
            return True
        return timestamp_is_fallback and allow_mtime_fallback and rollout_mtime_active(path, emit_threshold, end)

    def effective_record_time(
        raw_timestamp: str | None,
        parsed: dt.datetime | None,
        *,
        timestamp_is_fallback: bool,
    ) -> tuple[str | None, dt.datetime | None]:
        if allow_mtime_fallback and timestamp_is_fallback and emit_threshold is not None and (parsed is None or parsed < emit_threshold):
            active_mtime = rollout_active_mtime(path, emit_threshold, end)
            if active_mtime is not None:
                return iso(active_mtime), active_mtime
        return raw_timestamp, parsed

    def emit_current(trigger_line_no: int | None = None, trigger_timestamp: str | None = None) -> None:
        nonlocal current, current_emitted
        if current and not current_emitted:
            current_timestamp = parse_time(current.timestamp)
            event_timestamp = parse_time(trigger_timestamp) if trigger_timestamp else None
            if (
                emit_threshold is not None
                and current_timestamp is not None
                and current_timestamp < emit_threshold
                and event_timestamp is not None
                and event_timestamp >= emit_threshold
                and trigger_line_no is not None
            ):
                current = dataclasses.replace(
                    current,
                    turn_id=opaque_turn_id(f"{source.host}|{path_ref(path)}|{trigger_line_no}|{trigger_timestamp}|continuation"),
                    timestamp=trigger_timestamp or current.timestamp,
                )
            turns.append(current)
            current_emitted = True

    for line_no, record in iter_jsonl(path):
        payload = record.get("payload") or {}
        if isinstance(payload, dict):
            cwd = payload.get("cwd") or cwd
            model = payload.get("model") or payload.get("model_id") or model
        timestamp, timestamp_is_fallback = record_timestamp_with_origin(record, path)
        parsed_timestamp = parse_time(timestamp)
        timestamp, parsed_timestamp = effective_record_time(
            timestamp,
            parsed_timestamp,
            timestamp_is_fallback=timestamp_is_fallback,
        )
        if parsed_timestamp and end and parsed_timestamp >= end:
            continue

        if isinstance(payload, dict):
            user_text = user_text_from_payload(payload)
            assistant_text = assistant_text_from_payload(payload)
            prompt_text = meaningful_prompt_text(user_text) if user_text else ""
            if user_text and not meaningful_user_text(user_text):
                if current and (assistant_bits or current_has_post_prompt_evidence):
                    flush_assistant()
                    current = None
                    current_emitted = False
                    current_has_post_prompt_evidence = False
                    assistant_bits = []
                continue
            if prompt_text and meaningful_user_text(user_text):
                fingerprint_time = iso(parsed_timestamp.replace(microsecond=0)) if parsed_timestamp and not timestamp_is_fallback else ""
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
                        (path_ref(cwd) or ""),
                        date_bucket,
                        prompt_category(prompt_text),
                        prompt_topic_key(redacted_prompt),
                    ]
                )
                episode_id = opaque_episode_id(episode_seed)
                turn = TurnSummary(
                    turn_id=opaque_turn_id(f"{source.host}|{path_ref(path)}|{line_no}|{timestamp}"),
                    episode_id=episode_id,
                    host=source.host,
                    session_id=session_id,
                    source_path=path_ref(path) or "",
                    source_hash=source_hash,
                    timestamp=timestamp,
                    cwd=path_ref(cwd),
                    model=retained_model_id(model),
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
                current_has_post_prompt_evidence = False
                if is_emit_record(parsed_timestamp, timestamp_is_fallback=timestamp_is_fallback):
                    emit_current()
                continue
            if assistant_text and current and is_emit_record(parsed_timestamp, timestamp_is_fallback=timestamp_is_fallback):
                emit_current(line_no, timestamp)
                assistant_bits.append(assistant_text)
                current_has_post_prompt_evidence = True
            if (
                current
                and not user_text
                and is_emit_record(parsed_timestamp, timestamp_is_fallback=timestamp_is_fallback)
            ):
                current_has_post_prompt_evidence = True

        text = record_text(record)
        _redacted_text, changed = redact(text)
        record_flags = flags_for_text(text, redacted_changed=changed)
        if current and record_flags and is_emit_record(parsed_timestamp, timestamp_is_fallback=timestamp_is_fallback):
            emit_current(line_no, timestamp)
            current_has_post_prompt_evidence = True
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
    source_hash = file_source_hash(path)
    session_id = opaque_session_id(path.as_posix())
    records = list(iter_jsonl(path))
    for _line_no, record in records:
        if str(record.get("kind") or "summary") != "session_meta":
            continue
        match = re.search(r"session_id=([^\s]+)", str(record.get("text") or ""))
        if match:
            session_id = opaque_session_id(match.group(1))
            break
    for line_no, record in records:
        timestamp = str(record.get("timestamp") or "") or None
        parsed_timestamp = summary_timestamp_with_fallback(record, path)
        text = str(record.get("text") or "")
        kind = str(record.get("kind") or "summary")
        retained_kind = retained_summary_kind(kind)
        if kind == "session_meta" and text:
            match = re.search(r"session_id=([^\s]+)", text)
            if match:
                session_id = opaque_session_id(match.group(1))
            continue
        if parsed_timestamp is None:
            continue
        if start and parsed_timestamp < start:
            continue
        if end and parsed_timestamp >= end:
            continue
        if emit_start and parsed_timestamp < emit_start:
            continue
        _redacted_text, changed = redact(text)
        flags = flags_for_text(text, redacted_changed=changed)
        if not flags:
            continue
        timestamp_value = timestamp if parse_time(timestamp) else (iso(parsed_timestamp) if parsed_timestamp else None)
        date_bucket = parsed_timestamp.date().isoformat()
        episode_id = opaque_episode_id("|".join([source.host, session_id, "rollout-summary", date_bucket, retained_kind]))
        turns.append(
            TurnSummary(
                turn_id=opaque_turn_id(f"{source.host}|{path_ref(path)}|{line_no}|{timestamp}"),
                episode_id=episode_id,
                host=source.host,
                session_id=session_id,
                source_path=path_ref(path) or "",
                source_hash=source_hash,
                timestamp=timestamp_value,
                cwd=None,
                model=None,
                model_era=infer_model_era(None, timestamp_value),
                redacted_user_prompt_summary=f"category=remote_rollout_summary; summary_kind={retained_kind}",
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


def write_bytes_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SystemExit(f"refusing to write unsafe output path: {path}")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except Exception:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    write_bytes_atomic(path, jsonl_bytes(rows))


def write_json(path: Path, data: dict[str, Any]) -> None:
    write_bytes_atomic(path, json_bytes(data))


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
        return any(pattern.search(value) for pattern, _label in SECRET_PATTERNS) or bool(INTERNAL_HOSTNAME_PATTERN.search(value))
    if isinstance(value, dict):
        return any(contains_unredacted_sensitive_text(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_unredacted_sensitive_text(child) for child in value)
    return False


def safe_token(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))


def retained_source_host(host: str) -> str:
    label = host.strip()
    if not label:
        raise SystemExit("--source HOST must be non-empty")
    if label in RETAINED_DIRECT_SOURCE_HOSTS:
        return label
    return RETAINED_CUSTOM_SOURCE_HOST


def retained_host_token(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_EVIDENCE_HOSTS


def retained_coverage_host_token(value: Any) -> bool:
    return isinstance(value, str) and value in RETAINED_HOSTS


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


def require_retained_host_string(value: Any, *, label: str) -> str:
    text = require_safe_token_string(value, label=label)
    if not retained_host_token(text):
        raise SystemExit(f"{label}: retained host label is not allowed")
    return text


def require_opaque_digest_string(value: Any, *, label: str, prefix: str | None = None) -> str:
    text = require_string(value, label=label)
    if prefix is None:
        pattern = OPAQUE_ID_PATTERN
    else:
        pattern = re.compile(rf"^{re.escape(prefix)}:[0-9a-f]{{20}}$")
    if not pattern.fullmatch(text):
        raise SystemExit(f"{label}: expected opaque keyed digest")
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
    require_opaque_digest_string(row["episode_id"], label=f"{label}.episode_id", prefix=EPISODE_REF_PREFIX)
    require_retained_host_string(row["host"], label=f"{label}.host")
    require_opaque_digest_string(row["session_id"], label=f"{label}.session_id", prefix=SESSION_REF_PREFIX)
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
    require_opaque_digest_string(row["turn_id"], label=f"{label}.turn_id", prefix=TURN_REF_PREFIX)
    require_opaque_digest_string(row["episode_id"], label=f"{label}.episode_id", prefix=EPISODE_REF_PREFIX)
    require_retained_host_string(row["host"], label=f"{label}.host")
    require_opaque_digest_string(row["session_id"], label=f"{label}.session_id", prefix=SESSION_REF_PREFIX)
    require_string(row["source_path"], label=f"{label}.source_path")
    if not PATH_REF_PATTERN.fullmatch(row["source_path"]):
        raise SystemExit(f"{label}.source_path: retained refs must use opaque {PATH_REF_PREFIX} values")
    source_hash = require_string(row["source_hash"], label=f"{label}.source_hash")
    if not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise SystemExit(f"{label}.source_hash: expected keyed hex digest")
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


def sanitize_retained_jsonl_bytes(
    data: bytes,
    *,
    label: str,
    allowed: set[str],
    strict: bool,
    validator: Any | None = None,
) -> list[dict[str, Any]]:
    try:
        rows = list(iter_jsonl_strict_bytes(data, label))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    sanitized_rows: list[dict[str, Any]] = []
    for line_no, obj in rows:
        row_label = f"{label}:{line_no}"
        sanitized = sanitize_mapping(obj, allowed=allowed, required=allowed, label=row_label, strict=strict)
        if validator is not None:
            validator(sanitized, label=row_label)
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


def require_retained_host_count_map(value: dict[str, int], *, label: str) -> None:
    for key in value:
        if not retained_host_token(key):
            raise SystemExit(f"{label}: retained host label is not allowed")


def sanitize_window(value: Any, *, label: str) -> dict[str, Any]:
    sanitized = sanitize_mapping(value, allowed={"mode", "start", "end"}, required={"mode", "start", "end"}, label=label, strict=True)
    if not safe_token(sanitized["mode"]) or not parse_time(str(sanitized["start"])) or not parse_time(str(sanitized["end"])):
        raise SystemExit(f"{label}: invalid retained window")
    return sanitized


def sanitize_coverage_gap(value: Any, *, label: str, strict: bool) -> dict[str, Any]:
    sanitized = sanitize_mapping(value, allowed=MANIFEST_GAP_FIELDS, required={"host", "reason"}, label=label, strict=strict)
    if not retained_coverage_host_token(sanitized.get("host")) or not safe_token(sanitized.get("reason")):
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
    require_retained_host_count_map(sanitized["hosts"], label=f"{label}.hosts")
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
        if not retained_host_token(clean_source.get("host")) or not safe_token(clean_source.get("status")):
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
    manifest = history_json(path.read_bytes(), str(path))
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
        sources = [Source("local", Path("~/.codex").expanduser())]
        if require_default_hosts:
            sources.extend(
                Source(
                    host,
                    DEFAULT_REMOTE_SOURCE_ROOT / host,
                    "remote_source_not_materialized",
                )
                for host in DEFAULT_REMOTE_HOSTS
            )
        return sources
    sources: list[Source] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--source must be HOST=PATH, got {value!r}")
        host, raw_path = value.split("=", 1)
        source = Source(retained_source_host(host), Path(raw_path).expanduser())
        key = (source.host, source.root.resolve(strict=False).as_posix())
        if key in seen:
            continue
        seen.add(key)
        sources.append(source)
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
    if not path:
        return {}
    if path.is_symlink():
        raise SystemExit(f"refusing to read unsafe state file: {path}")
    if not path.exists():
        return {}
    if not path.is_file():
        raise SystemExit(f"refusing to read unsafe state file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("state file must contain an object")
    return data


def save_state(path: Path | None, data: dict[str, Any]) -> None:
    if not path:
        return
    write_bytes_atomic(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def safe_state_path(raw: str | None) -> Path | None:
    if not raw:
        return None
    return ensure_safe_output_dir(Path(raw))


def history_artifact_name_tokens(name: str) -> list[str]:
    stem = name
    while True:
        next_stem, suffix = os.path.splitext(stem)
        if suffix.lower() not in HISTORY_STRIPPABLE_NAME_SUFFIXES:
            break
        stem = next_stem
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", stem)
    return [token for token in re.split(r"[^a-z0-9]+", separated.lower()) if token]


def history_artifact_token_variants(tokens: list[str]) -> set[str]:
    variants = set(tokens)
    for token in tokens:
        if token.endswith("ies") and len(token) > 4:
            variants.add(token[:-3] + "y")
        elif token.endswith("s") and len(token) > 3:
            variants.add(token[:-1])
    return variants


def forbidden_history_artifact_name(name: str) -> bool:
    tokens = history_artifact_name_tokens(name)
    if not tokens:
        return False
    normalized = "_".join(tokens)
    if normalized in HISTORY_FORBIDDEN_NAME_STEMS:
        return True
    compacted = "".join(tokens)
    if any(compacted.startswith(prefix) for prefix in HISTORY_FORBIDDEN_COMPACT_NAME_PREFIXES):
        return True
    if any(part in compacted for part in HISTORY_FORBIDDEN_COMPACT_NAME_PARTS):
        return True
    token_set = history_artifact_token_variants(tokens)
    if token_set & HISTORY_FORBIDDEN_NAME_TOKENS:
        return True
    return any(all(token in token_set for token in phrase) for phrase in HISTORY_FORBIDDEN_TOKEN_PHRASES)


def forbidden_history_artifact(file_path: str) -> bool:
    parts = file_path.split("/")
    name = parts[-1]
    if name in HISTORY_FORBIDDEN_FILENAMES:
        return True
    if forbidden_history_artifact_name(name):
        return True
    if any(part in HISTORY_FORBIDDEN_COMPONENTS or forbidden_history_artifact_name(part) for part in parts[:-1]):
        return True
    return name.startswith("rollout") and name.endswith(".jsonl")


def history_text_contains_sensitive(data: bytes, file_path: str) -> bool:
    text = data.decode("utf-8", errors="replace")
    if file_path.startswith("schemas/"):
        text = text.replace("https://json-schema.org/draft/2020-12/schema", "")
    return contains_unredacted_sensitive_text(text) or bool(BARE_64_HEX_PATTERN.search(text))


def history_text_contains_retention_risk(data: bytes, file_path: str) -> bool:
    text = data.decode("utf-8", errors="replace")
    if file_path.startswith("schemas/"):
        text = text.replace("https://json-schema.org/draft/2020-12/schema", "")
    if contains_unredacted_sensitive_text(text) or BARE_64_HEX_PATTERN.search(text):
        return True
    if file_path in HISTORY_ROOT_FILES or file_path in {"data/README.md", "reports/README.md"}:
        return False
    generated_follow_on = history_path_kind(file_path) in {"text", "json_text"}
    return generated_follow_on and contains_path_like_text(text)


def history_safe_year_month(parts: tuple[str, ...], start: int) -> bool:
    return len(parts) > start + 1 and bool(re.fullmatch(r"\d{4}", parts[start]) and re.fullmatch(r"\d{2}", parts[start + 1]))


def history_report_path_allowed(parts: tuple[str, ...]) -> bool:
    if len(parts) == 5 and parts[0] == "reports" and parts[1] in {"daily", "weekly"}:
        return bool(
            history_safe_year_month(parts, 2)
            and parts[4].endswith(".md")
            and re.fullmatch(r"\d{2}", Path(parts[4]).stem)
        )
    return bool(
        len(parts) == 4
        and parts[:3] == ("reports", "baseline", "90-day-windows")
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}_to_\d{4}-\d{2}-\d{2}\.md", parts[3])
    )


def history_flat_retained_export_parent_allowed(parent: str) -> bool:
    return parent in HISTORY_FLAT_RETAINED_EXPORT_PARENTS


def history_flat_retained_export_kind(parent: str, name: str) -> str | None:
    if not history_flat_retained_export_parent_allowed(parent):
        return None
    if name == "episodes.jsonl":
        return "episodes"
    if name == "turn_flags.jsonl":
        return "turn_flags"
    if name == "trend_report.json":
        return "trend"
    if name == "retained_manifest.json":
        return "manifest"
    return None


def retained_export_parent_for_mode(mode: Any) -> str:
    if mode == "daily":
        return "retained/daily"
    if mode == "weekly":
        return "retained/weekly"
    if isinstance(mode, str) and mode.startswith("baseline-"):
        return "retained/baseline"
    raise SystemExit("retained export mode is not supported")


def retained_export_expected_parent(retained_files: dict[str, bytes]) -> str:
    trend = sanitize_trend_report(history_json(retained_files["trend_report.json"], "trend_report.json"), label="trend_report.json", strict=True)
    manifest = sanitize_retained_manifest_obj(
        history_json(retained_files["retained_manifest.json"], "retained_manifest.json"),
        label="retained_manifest.json",
        strict=True,
    )
    return retained_export_parent_for_records(trend, manifest)


def retained_export_parent_for_records(trend: dict[str, Any], manifest: dict[str, Any]) -> str:
    trend_window = trend.get("window") or {}
    manifest_window = manifest.get("window") or {}
    mode = trend_window.get("mode")
    if manifest.get("mode") != mode or manifest_window.get("mode") != mode:
        raise SystemExit("retained export mode does not match retained manifest")
    if manifest_window != trend_window:
        raise SystemExit("retained export window does not match retained manifest")
    return retained_export_parent_for_mode(mode)


def validate_retained_export_parent(retained_files: dict[str, bytes], parent: str | None = None) -> str:
    expected_parent = retained_export_expected_parent(retained_files)
    if parent is not None and parent != expected_parent:
        raise SystemExit("retained export directory does not match export mode")
    return expected_parent


def history_path_kind(file_path: str) -> str:
    parts = tuple(file_path.split("/"))
    name = file_path.rsplit("/", 1)[-1]
    parent = file_path.rpartition("/")[0]
    flat_kind = history_flat_retained_export_kind(parent, name)
    if flat_kind:
        return flat_kind
    if len(parts) == 5 and parts[:2] == ("data", "episodes") and history_safe_year_month(parts, 2) and name == "episodes.jsonl":
        return "episodes"
    if len(parts) == 5 and parts[:2] == ("data", "turn_flags") and history_safe_year_month(parts, 2) and name == "turn_flags.jsonl":
        return "turn_flags"
    if len(parts) == 5 and parts[:2] == ("data", "trends") and history_safe_year_month(parts, 2) and name == "trend_report.json":
        return "trend"
    if len(parts) == 5 and parts[:2] == ("data", "manifests") and history_safe_year_month(parts, 2) and name == "retained_manifest.json":
        return "manifest"
    if file_path in HISTORY_ROOT_FILES or file_path in {"data/README.md", "reports/README.md"}:
        return "text"
    if history_report_path_allowed(parts):
        return "text"
    if len(parts) == 2 and parts[0] == "schemas" and parts[1] in HISTORY_SCHEMA_FILES:
        return "json_text"
    raise SystemExit(f"history tree contains unexpected artifact: {file_path}")


def history_commit_changed_files(repo: Path, commit: str) -> set[str]:
    changed = subprocess.run(
        ["git", "-C", str(repo), "diff-tree", "--no-commit-id", "--root", "-r", "-m", "-z", "--name-only", commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if changed.returncode != 0:
        raise SystemExit("failed to inspect --history-commit changed files")
    return {raw_name.decode("utf-8", errors="surrogateescape") for raw_name in changed.stdout.split(b"\0") if raw_name}


def require_history_repo(history_repo: str | None) -> Path:
    if not history_repo:
        raise SystemExit("--history-repo is required")
    repo = Path(history_repo).expanduser()
    if not repo.exists() or not repo.is_dir():
        raise SystemExit("--history-repo must be an existing git repository")
    require_history_repo_identity(repo)
    return repo


def require_history_repo_identity(repo: Path) -> None:
    fetch_urls = history_remote_urls(repo, push=False)
    push_urls = history_remote_urls(repo, push=True)
    if not fetch_urls or not push_urls:
        raise SystemExit(f"--history-repo origin must be {EXPECTED_HISTORY_REPO}")
    if any(not history_remote_matches_expected(remote_url) for remote_url in (*fetch_urls, *push_urls)):
        raise SystemExit(f"--history-repo origin must be {EXPECTED_HISTORY_REPO}")


def history_remote_urls(repo: Path, *, push: bool) -> list[str]:
    args = ["git", "-C", str(repo), "remote", "get-url"]
    if push:
        args.append("--push")
    args.extend(["--all", "origin"])
    remote = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if remote.returncode != 0:
        return []
    return [line.strip() for line in remote.stdout.splitlines() if line.strip()]


def history_remote_matches_expected(remote_url: str) -> bool:
    value = remote_url.strip().removesuffix(".git").removesuffix("/")
    if value == f"git@github.com:{EXPECTED_HISTORY_REPO}":
        return True
    for prefix in ("https://github.com/", "ssh://git@github.com/"):
        if value.startswith(prefix):
            return value.removeprefix(prefix) == EXPECTED_HISTORY_REPO
    return False


def require_history_commit(repo: Path, commit: str) -> None:
    completed = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit("history ref must exist in --history-repo")


def require_history_ancestor(repo: Path, ancestor: str, ref: str) -> None:
    require_history_commit(repo, ancestor)
    require_history_commit(repo, ref)
    completed = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, ref],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit("--history-ref must include --history-commit")


def history_commit_oid(repo: Path, ref: str) -> str:
    require_history_commit(repo, ref)
    completed = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{ref}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit("failed to resolve history ref")
    return completed.stdout.strip()


def require_history_ref_current_head(repo: Path, ref: str) -> None:
    ref_oid = history_commit_oid(repo, ref)
    head_oid = history_commit_oid(repo, "HEAD")
    if ref_oid != head_oid:
        raise SystemExit("--history-ref must resolve to the current history worktree HEAD")


def require_history_worktree_clean(repo: Path) -> None:
    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if status.returncode != 0:
        raise SystemExit("failed to inspect history worktree status")
    if status.stdout:
        raise SystemExit("--history-repo worktree must be clean before advancing state")


@dataclasses.dataclass(frozen=True)
class HistoryTreeEntry:
    mode: str
    object_type: str
    path: str


def history_tree_entries(repo: Path, ref: str) -> dict[str, HistoryTreeEntry]:
    require_history_commit(repo, ref)
    tree = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "-z", ref],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if tree.returncode != 0:
        raise SystemExit("failed to inspect history tree")
    entries: dict[str, HistoryTreeEntry] = {}
    for raw_entry in tree.stdout.split(b"\0"):
        if not raw_entry:
            continue
        raw_meta, separator, raw_path = raw_entry.partition(b"\t")
        if not separator:
            raise SystemExit("failed to parse history tree")
        meta = raw_meta.decode("utf-8", errors="replace").split()
        if len(meta) < 3:
            raise SystemExit("failed to parse history tree")
        file_path = raw_path.decode("utf-8", errors="surrogateescape")
        entries[file_path] = HistoryTreeEntry(mode=meta[0], object_type=meta[1], path=file_path)
    return entries


def require_regular_history_blob(entries: dict[str, HistoryTreeEntry], file_path: str) -> None:
    entry = entries.get(file_path)
    if entry is None:
        raise SystemExit(f"missing history artifact: {file_path}")
    if entry.object_type != "blob" or entry.mode not in {"100644", "100755"}:
        raise SystemExit(f"history artifact is not a regular file: {file_path}")


def history_tree_files(repo: Path, ref: str) -> list[str]:
    return list(history_tree_entries(repo, ref))


def history_blob(repo: Path, ref: str, file_path: str) -> bytes:
    blob = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{file_path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if blob.returncode != 0:
        raise SystemExit(f"failed to inspect history artifact: {file_path}")
    return blob.stdout


def history_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label}: invalid JSON") from exc


def retained_export_paths(parent: str) -> dict[str, str]:
    return {name: f"{parent}/{name}" if parent else name for name in RETAINED_OUTPUT_FILES}


def require_retained_export_in_history_ref(repo: Path, ref: str, parent: str, retained_files: dict[str, bytes]) -> None:
    entries = history_tree_entries(repo, ref)
    tree_files = set(entries)
    expected_paths = retained_export_paths(parent)
    missing = [path for path in expected_paths.values() if path not in tree_files]
    if missing:
        raise SystemExit("--history-ref does not contain the retained export from --history-commit")
    if parent:
        descendant_paths = {file_path for file_path in tree_files if file_path.startswith(f"{parent}/")}
    else:
        descendant_paths = {file_path for file_path in tree_files if "/" not in file_path}
    if descendant_paths != set(expected_paths.values()):
        raise SystemExit("--history-ref retained export directory changed after --history-commit")
    for file_path in expected_paths.values():
        require_regular_history_blob(entries, file_path)
    actual = {name: history_blob(repo, ref, file_path) for name, file_path in expected_paths.items()}
    if actual != retained_files:
        raise SystemExit("--history-ref retained export content changed after --history-commit")


def validate_history_tree(history_repo: str | None, history_ref: str) -> None:
    repo = require_history_repo(history_repo)
    entries = history_tree_entries(repo, history_ref)
    files = list(entries)
    parent_files: dict[str, set[str]] = defaultdict(set)
    for file_path in files:
        parent, _, name = file_path.rpartition("/")
        parent_files[parent].add(name)
    for parent, names in parent_files.items():
        retained_names = names & set(RETAINED_OUTPUT_FILES)
        if not retained_names:
            continue
        if history_flat_retained_export_parent_allowed(parent):
            if names != set(RETAINED_OUTPUT_FILES):
                label = parent or "."
                raise SystemExit(f"history retained export directory is incomplete or has extra files: {label}")
            retained_files = {name: history_blob(repo, history_ref, f"{parent}/{name}") for name in RETAINED_OUTPUT_FILES}
            validate_retained_export_parent(retained_files, parent)
        elif parent.startswith("retained/"):
            raise SystemExit(f"history retained export directory is not allowed: {parent}")
    for file_path in files:
        require_regular_history_blob(entries, file_path)
        if forbidden_history_artifact(file_path):
            raise SystemExit(f"history tree contains forbidden transient/raw artifact: {file_path}")
        kind = history_path_kind(file_path)
        data = history_blob(repo, history_ref, file_path)
        if kind == "episodes":
            sanitize_retained_jsonl_bytes(
                data,
                label=file_path,
                allowed=EPISODE_FIELDS,
                strict=True,
                validator=validate_episode_row,
            )
        elif kind == "turn_flags":
            sanitize_retained_jsonl_bytes(
                data,
                label=file_path,
                allowed=TURN_FLAG_FIELDS,
                strict=True,
                validator=validate_turn_flag_row,
            )
        elif kind == "trend":
            sanitize_trend_report(history_json(data, file_path), label=file_path, strict=True)
        elif kind == "manifest":
            manifest = sanitize_retained_manifest_obj(history_json(data, file_path), label=file_path, strict=True)
            if manifest.get("retention_safe") is not True:
                raise SystemExit(f"{file_path}: retention_safe must be true")
            if contains_raw_path_fields(manifest) or contains_path_like_text(manifest) or contains_invalid_ref(manifest):
                raise SystemExit(f"{file_path}: retained manifest is not retention-safe")
        elif kind in {"text", "json_text"}:
            if kind == "json_text":
                history_json(data, file_path)
            if history_text_contains_retention_risk(data, file_path):
                raise SystemExit(f"history artifact contains unredacted sensitive text or path-like text: {file_path}")


def validate_history_commit(history_repo: str | None, history_commit: str, retained_files: dict[str, bytes]) -> str:
    repo = require_history_repo(history_repo)
    require_history_commit(repo, history_commit)
    entries = history_tree_entries(repo, history_commit)
    tree_files = set(entries)
    changed_files = history_commit_changed_files(repo, history_commit)
    expected_parent = validate_retained_export_parent(retained_files)
    grouped: dict[str, dict[str, str]] = defaultdict(dict)
    parent_files: dict[str, set[str]] = defaultdict(set)
    for file_path in tree_files:
        require_regular_history_blob(entries, file_path)
        if forbidden_history_artifact(file_path):
            raise SystemExit(f"--history-commit contains forbidden transient/raw artifact: {file_path}")
        parent, _, name = file_path.rpartition("/")
        parent_files[parent].add(name)
        if name in RETAINED_OUTPUT_FILES and history_flat_retained_export_parent_allowed(parent):
            grouped[parent][name] = file_path
    expected_digest = retained_export_digest(retained_files)
    for parent, paths in grouped.items():
        if set(paths) != set(RETAINED_OUTPUT_FILES):
            continue
        if parent_files[parent] != set(RETAINED_OUTPUT_FILES):
            continue
        allowed_paths = set(retained_export_paths(parent).values())
        if parent:
            descendant_paths = {file_path for file_path in tree_files if file_path.startswith(f"{parent}/")}
        else:
            descendant_paths = {file_path for file_path in tree_files if "/" not in file_path}
        if descendant_paths != allowed_paths:
            continue
        candidate: dict[str, bytes] = {}
        for name, file_path in paths.items():
            candidate[name] = history_blob(repo, history_commit, file_path)
        changed_retained_paths = set(paths.values())
        if (
            candidate
            and retained_export_digest(candidate) == expected_digest
            and changed_files
            and changed_files <= changed_retained_paths
        ):
            if parent != expected_parent:
                raise SystemExit("--history-commit retained export directory does not match export mode")
            return parent
    raise SystemExit("--history-commit does not contain exactly one retained export and no other changed files")


def require_positive_window(value: int, name: str) -> int:
    if value <= 0:
        raise SystemExit(f"{name} must be positive")
    return value


def validate_window_bounds(start: dt.datetime | None, end: dt.datetime | None, label: str) -> None:
    if start is not None and end is not None and start >= end:
        raise SystemExit(f"{label} start must be before end")


def earliest_rollout_date(sources: list[Source]) -> dt.datetime | None:
    earliest: dt.datetime | None = None
    for source in sources:
        for rollout in source_rollouts(source):
            parsed = dated_path_from_parts(rollout) or rollout_date_from_path(rollout)
            if parsed and (earliest is None or parsed < earliest):
                earliest = parsed
        for summary in source_summary_files(source):
            parsed = summary_date_from_path(summary)
            try:
                for _line_no, record in iter_jsonl(summary):
                    timestamp = parse_time(record_timestamp(record))
                    if timestamp and (parsed is None or timestamp < parsed):
                        parsed = timestamp
            except ValueError:
                pass
            if parsed and (earliest is None or parsed < earliest):
                earliest = parsed
    return earliest


def state_last_scan_at(state: dict[str, Any]) -> dt.datetime | None:
    if "last_scan_at" not in state:
        return None
    value = state.get("last_scan_at")
    if not isinstance(value, str):
        raise SystemExit("state last_scan_at must be a valid timestamp")
    parsed = parse_time(value)
    if parsed is None:
        raise SystemExit("state last_scan_at must be a valid timestamp")
    return parsed


def local_evidence_gaps(source: Source) -> list[dict[str, Any]]:
    if not local_source_requires_index_files(source):
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


def local_source_requires_index_files(source: Source) -> bool:
    if source.host != "local":
        return False
    canonical_codex = Path("~/.codex").expanduser().resolve(strict=False)
    return source.root.expanduser().resolve(strict=False) == canonical_codex


def source_allows_mtime_fallback(source: Source) -> bool:
    if source.host != "local":
        return False
    canonical_codex = Path("~/.codex").expanduser().resolve(strict=False)
    return source.root.expanduser().resolve(strict=False) == canonical_codex


def remote_metadata_gap(source: Source, reason: str = "stale_host") -> dict[str, Any]:
    if reason not in ALLOWED_REMOTE_GAP_REASONS:
        reason = "stale_host"
    return {"host": source.host, "root_ref": path_ref(source.root), "reason": reason}


def same_second(left: dt.datetime | None, right: dt.datetime | None) -> bool:
    return left is not None and right is not None and left.replace(microsecond=0) == right.replace(microsecond=0)


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
    if end and not same_second(window_end, end):
        return [remote_metadata_gap(source)]
    if materialized_at.replace(microsecond=0) < window_end.replace(microsecond=0):
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
    validate_window_bounds(start, end, "scan")
    output = ensure_safe_output_dir(Path(args.output))
    safe_state_path(args.state)
    sources = parse_sources(args.source, require_default_hosts=not getattr(args, "allow_partial_hosts", False))
    gap_start = emit_start or start
    all_turns: list[TurnSummary] = []
    manifest_sources: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    max_raw_bytes = require_positive_window(getattr(args, "max_raw_bytes", 512_000), "--max-raw-bytes")

    def append_oversized_rollout_gap(path: Path, size: int) -> None:
        coverage_gaps.append(
            {
                "host": source.host,
                "path_ref": path_ref(path),
                "bytes": size,
                "reason": "oversized_rollout_skipped",
            }
        )

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
        source_remote_gaps = remote_evidence_gaps(
            source,
            start=start,
            end=end,
        )
        coverage_gaps.extend(source_remote_gaps)
        if source_remote_gaps:
            manifest_sources.append(
                {
                    "host": source.host,
                    "root": source.root.as_posix(),
                    "root_ref": path_ref(source.root),
                    "rollout_count": 0,
                    "summary_count": 0,
                    "status": "stale",
                }
            )
            continue
        rollouts = source_rollouts(source)
        summaries = source_summary_files(source)
        allow_mtime_fallback = source_allows_mtime_fallback(source)
        if not rollouts and not summaries and source.host not in DEFAULT_REMOTE_HOSTS:
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
            if not rollout_candidate_relevant(
                rollout,
                start,
                end,
                max_raw_bytes=max_raw_bytes,
                allow_mtime_fallback=allow_mtime_fallback,
            ):
                continue
            size = rollout.stat().st_size
            if size <= max_raw_bytes:
                error_line = first_jsonl_error(rollout)
                if error_line is not None:
                    if (
                        rollout_filename_in_window(rollout, gap_start, end)
                        or raw_timestamp_in_window(rollout, gap_start, end)
                        or (allow_mtime_fallback and rollout_mtime_active(rollout, gap_start, end))
                    ):
                        coverage_gaps.append(
                            {
                                "host": source.host,
                                "path_ref": path_ref(rollout),
                                "reason": "invalid_jsonl",
                            }
                        )
                    continue
                if not rollout_has_record_in_window(rollout, start, end, allow_mtime_fallback=allow_mtime_fallback):
                    continue
                all_turns.extend(
                    extract_rollout(
                        source,
                        rollout,
                        start,
                        end,
                        emit_start=emit_start,
                        allow_mtime_fallback=allow_mtime_fallback,
                    )
                )
                continue
            relevance = oversized_rollout_relevance(rollout, gap_start, end)
            if relevance == "irrelevant":
                continue
            append_oversized_rollout_gap(rollout, size)
            continue
        for summary in summaries:
            if not summary_file_relevant(summary, start, end):
                continue
            if first_jsonl_error(summary) is not None:
                if summary_file_relevant(summary, gap_start, end):
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
    validate_window_bounds(start, end, "discover")
    output = ensure_safe_output_dir(Path(args.output))
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
        source_remote_gaps = remote_evidence_gaps(
            source,
            start=start,
            end=end,
        )
        coverage_gaps.extend(source_remote_gaps)
        if source_remote_gaps:
            manifest_sources.append(
                {
                    "host": source.host,
                    "root": source.root.as_posix(),
                    "root_ref": path_ref(source.root),
                    "rollout_count": 0,
                    "summary_count": 0,
                    "status": "stale",
                }
            )
            continue
        rollouts = source_rollouts(source)
        summaries = source_summary_files(source)
        if not rollouts and not summaries and source.host not in DEFAULT_REMOTE_HOSTS:
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
    end = parse_time(args.end) if args.end else default_window_end()
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
    end = parse_time(end_value) if end_value else default_window_end()
    if end is None:
        raise SystemExit(f"invalid --end timestamp: {end_value}")
    return end


def cmd_scan_daily(args: argparse.Namespace) -> int:
    active_lookback_days = require_positive_window(args.active_lookback_days, "--active-lookback-days")
    end = scan_end(args)
    state_path = safe_state_path(args.state)
    state = load_state(state_path) if state_path else {}
    last = state_last_scan_at(state)
    lookback_start = end - dt.timedelta(days=active_lookback_days)
    if last and last <= end:
        start = min(last, lookback_start)
        emit_start = last
    else:
        start = lookback_start
        emit_start = None
    return run_scan(args, mode="daily", start=start, end=end, emit_start=emit_start)


def cmd_scan_weekly(args: argparse.Namespace) -> int:
    days = require_positive_window(args.days, "--days")
    end = scan_end(args)
    start = end - dt.timedelta(days=days)
    return run_scan(args, mode="weekly", start=start, end=end)


def bounded_baseline_end(start: dt.datetime, window_days: int, now: dt.datetime) -> dt.datetime:
    return min(now, start + dt.timedelta(days=window_days))


def cmd_baseline(args: argparse.Namespace) -> int:
    window_days = require_positive_window(args.window_days, "--window-days")
    now = scan_end(args)
    sources = parse_sources(args.source, require_default_hosts=not args.allow_partial_hosts)
    if args.from_value == "first":
        start = earliest_rollout_date(sources) or (now - dt.timedelta(days=window_days))
    else:
        start = parse_time(args.from_value)
        if start is None:
            raise SystemExit(f"invalid --from timestamp: {args.from_value}")
    mode = f"baseline-{window_days}d"
    end = bounded_baseline_end(start, window_days, now)
    validate_window_bounds(start, end, "baseline")
    return run_scan(args, mode=mode, start=start, end=end)


def parse_manifest_window_time(window: dict[str, Any], key: str) -> dt.datetime | None:
    value = window.get(key)
    if value is None or value == "":
        return None
    parsed = parse_time(str(value))
    if parsed is None:
        raise SystemExit(f"invalid manifest window {key}: {value}")
    return parsed


def require_manifest_window_bounds(window: dict[str, Any], label: str) -> tuple[dt.datetime, dt.datetime]:
    start = parse_manifest_window_time(window, "start")
    end = parse_manifest_window_time(window, "end")
    if start is None or end is None:
        raise SystemExit(f"{label} requires bounded start and end")
    validate_window_bounds(start, end, label)
    return start, end


def cmd_make_shards(args: argparse.Namespace) -> int:
    max_raw_bytes = require_positive_window(args.max_raw_bytes, "--max-raw-bytes")
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if manifest.get("retention_safe") is True:
        raise SystemExit("make-shards requires transient shard_manifest.json, not retained_manifest.json")
    output = ensure_safe_output_dir(Path(args.output))
    sources = manifest.get("sources", [])
    window = manifest.get("window") or {}
    start, end = require_manifest_window_bounds(window, "manifest window")
    rows: list[dict[str, Any]] = []

    def shard_row(path: Path, **values: Any) -> dict[str, Any]:
        row = {"host": host, "path_ref": path_ref(path), **values}
        if getattr(args, "include_raw_paths", False):
            row["path"] = path.as_posix()
        return row

    def append_summary_shard(summary: Path) -> None:
        if not summary_file_relevant(summary, start, end):
            return
        row = shard_row(summary, bytes=summary.stat().st_size, kind="summary")
        if first_jsonl_error(summary) is not None:
            row["status"] = "invalid"
            row["coverage_gap"] = "invalid summary JSONL; cannot safely hand to extractor shard"
            rows.append(row)
            return
        row["status"] = "ready"
        rows.append(row)

    for source in sources:
        host = source.get("host")
        if not source.get("root"):
            raise SystemExit("make-shards requires transient manifest sources with raw root fields")
        root = Path(source["root"]).expanduser()
        status = source.get("status")
        if status is None:
            raise SystemExit("make-shards requires transient manifest sources with status=ready")
        if status != "ready":
            continue
        source = Source(str(host), root)
        allow_mtime_fallback = source_allows_mtime_fallback(source)
        if not root.exists():
            rows.append(shard_row(root, status="missing", coverage_gap="source root missing"))
            continue
        for rollout in source_rollouts(source):
            if not rollout_candidate_relevant(
                rollout,
                start,
                end,
                max_raw_bytes=max_raw_bytes,
                allow_mtime_fallback=allow_mtime_fallback,
            ):
                continue
            size = rollout.stat().st_size
            row = shard_row(rollout, bytes=size)
            if size <= max_raw_bytes:
                error_line = first_jsonl_error(rollout)
                if error_line is not None:
                    if (
                        rollout_filename_in_window(rollout, start, end)
                        or raw_timestamp_in_window(rollout, start, end)
                        or (allow_mtime_fallback and rollout_mtime_active(rollout, start, end))
                    ):
                        row["status"] = "invalid"
                        row["coverage_gap"] = "invalid JSONL; cannot safely hand to extractor shard"
                        rows.append(row)
                    continue
                if rollout_has_record_in_window(rollout, start, end, allow_mtime_fallback=allow_mtime_fallback):
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
            if size > max_raw_bytes:
                row["status"] = "oversized"
                row["coverage_gap"] = "rollout exceeds max raw shard bytes; use bounded rollout-summary before extractor handoff"
                rows.append(row)
                continue
        for summary in source_summary_files(Source(str(host), root)):
            append_summary_shard(summary)
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
    if not run_dir.is_dir():
        raise SystemExit(f"output directory not found: {run_dir}")
    required_files = ("turn_summaries.jsonl", *RETAINED_OUTPUT_FILES)
    allowed = set(TRANSIENT_OUTPUT_FILES) | set(RETAINED_OUTPUT_FILES) | {"state.json"}
    for path in run_dir.iterdir():
        if path.name not in allowed or path.is_symlink() or not path.is_file():
            raise SystemExit(f"unexpected output file: {path}")
    for name in required_files:
        path = run_dir / name
        if not path.exists():
            raise SystemExit(f"missing output: {path}")
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise SystemExit(f"unexpected output file: {path}")
    required = {
        "turn_summaries.jsonl": {"turn_id", "episode_id", "host", "redacted_user_prompt_summary", "issue_flags"},
        "episodes.jsonl": {"episode_id", "host", "topic", "friction_flags"},
        "turn_flags.jsonl": {"turn_id", "episode_id", "issue_flags"},
    }
    for name, keys in required.items():
        path = run_dir / name
        try:
            rows = list(iter_jsonl_strict(path))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        for line_no, obj in rows:
            if not isinstance(obj, dict):
                raise SystemExit(f"{path}:{line_no}: JSONL record must be an object")
            missing = keys - set(obj)
            if missing:
                raise SystemExit(f"{path}:{line_no}: missing keys {sorted(missing)}")
            if contains_unredacted_sensitive_text(obj):
                raise SystemExit(f"{path}:{line_no}: unredacted sensitive text in retained output")
    sanitize_retained_jsonl(run_dir / "episodes.jsonl", allowed=EPISODE_FIELDS, strict=False, validator=validate_episode_row)
    sanitize_retained_jsonl(run_dir / "turn_flags.jsonl", allowed=TURN_FLAG_FIELDS, strict=False, validator=validate_turn_flag_row)
    trend_path = run_dir / "trend_report.json"
    trend = sanitize_trend_report(history_json(trend_path.read_bytes(), str(trend_path)), label=str(trend_path), strict=True)
    validate_retained_manifest(run_dir / "retained_manifest.json")
    manifest_path = run_dir / "retained_manifest.json"
    retained_manifest = sanitize_retained_manifest_obj(history_json(manifest_path.read_bytes(), str(manifest_path)), label=str(manifest_path), strict=True)
    retained_export_parent_for_records(trend, retained_manifest)
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
    retained_export_parent_for_records(trend, retained_manifest)
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
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=output)
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, target)
        except Exception:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
            raise
    validate_retained_output_dir(output)
    print(output)
    return 0


def cmd_validate_retained(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    validate_retained_output_dir(run_dir)
    print(f"validated: {run_dir}")
    return 0


def cmd_validate_history_commit(args: argparse.Namespace) -> int:
    history_commit = str(args.history_commit or "")
    if not COMMIT_SHA_PATTERN.fullmatch(history_commit):
        raise SystemExit("--history-commit must be a full 40-character hex commit SHA")
    retained_run_dir = Path(args.retained_run_dir)
    validate_retained_output_dir(retained_run_dir)
    validate_history_commit(args.history_repo, history_commit, retained_export_files_from_dir(retained_run_dir))
    print(f"validated history commit: {history_commit}")
    return 0


def cmd_validate_history_tree(args: argparse.Namespace) -> int:
    validate_history_tree(args.history_repo, str(args.history_ref or "HEAD"))
    print(f"validated history tree: {args.history_ref or 'HEAD'}")
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
    history_ref = str(args.history_ref or "HEAD")
    retained_parent = validate_history_commit(args.history_repo, history_commit, actual_files)
    history_repo = require_history_repo(args.history_repo)
    require_history_ancestor(history_repo, history_commit, history_ref)
    require_history_ref_current_head(history_repo, history_ref)
    require_history_worktree_clean(history_repo)
    validate_history_tree(args.history_repo, history_ref)
    require_retained_export_in_history_ref(history_repo, history_ref, retained_parent, actual_files)
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
    previous_scan_at = state_last_scan_at(state)
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
    shards.add_argument(
        "--include-raw-paths",
        action="store_true",
        help="Include local raw paths for extractor dispatch. Only use under ignored .codex-local outputs; never retain or commit shards.jsonl.",
    )
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

    validate_history = subparsers.add_parser("validate-history-commit")
    validate_history.add_argument("--retained-run-dir", required=True)
    validate_history.add_argument("--history-repo", required=True)
    validate_history.add_argument("--history-commit", required=True)
    validate_history.set_defaults(func=cmd_validate_history_commit)

    validate_history_tree_parser = subparsers.add_parser("validate-history-tree")
    validate_history_tree_parser.add_argument("--history-repo", required=True)
    validate_history_tree_parser.add_argument("--history-ref", default="HEAD")
    validate_history_tree_parser.set_defaults(func=cmd_validate_history_tree)

    advance = subparsers.add_parser("advance-state")
    advance.add_argument("--run-dir", required=True)
    advance.add_argument("--retained-run-dir", required=True)
    advance.add_argument("--state", required=True)
    advance.add_argument("--history-repo", required=True)
    advance.add_argument("--history-commit", required=True)
    advance.add_argument("--history-ref", default="HEAD")
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
