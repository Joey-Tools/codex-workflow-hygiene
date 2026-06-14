#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import socket
import subprocess
import stat
import sys
from collections.abc import Iterable
from typing import Any

DATE_FORMAT = "%Y/%m/%d"
MAX_SESSION_META_LIMIT = 500
MAX_SESSION_META_DATE_COUNT = 31
MAX_FETCH_ROLLOUT_BYTES = 16 * 1024 * 1024
MAX_ROLLOUT_SUMMARY_LIMIT = 200
MAX_ROLLOUT_SUMMARY_SCAN_BYTES = MAX_FETCH_ROLLOUT_BYTES
MAX_ROLLOUT_SUMMARY_LINE_BYTES = 1024 * 1024
MAX_ROLLOUT_SUMMARY_TAIL_RECORDS = 50
MAX_ROLLOUT_SUMMARY_TEXT_CHARS = 1200
REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF = "remote_generated_rollout_summary_v1"
REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF = "remote_generated_rollout_source_identity_v1"
SOURCE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BARE_64_HEX_SIGNAL_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
SAFE_CREDENTIAL_VALUE_PATTERN_TEXT = (
    r"(?:bearer|basic|digest|negotiate|token|api[-_]?key|hmac|aws4-hmac-sha256|signature|oauth|mac|"
    r"redacted(?:[_-][a-z0-9]+)*|masked(?:[_-][a-z0-9]+)*|missing|omitted|present|unknown|null|none|empty|"
    r"in|not|required|denied|expired|invalid|unavailable|absent|needed|necessary|revoked|rotated|budget|count|limit)"
)
SAFE_CREDENTIAL_VALUE_BOUNDARY_PATTERN_TEXT = r"(?=$|[\s,;&#，。；)\]\}>\"']|\.(?:$|\s))"
SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT = (
    r"(?![\[<({]?" + SAFE_CREDENTIAL_VALUE_PATTERN_TEXT + SAFE_CREDENTIAL_VALUE_BOUNDARY_PATTERN_TEXT + r")"
)
COMPACT_TOKEN_KEY_PATTERN_TEXT = r"(?:access|api|auth|authorization|client|refresh|id|session|csrf|xsrf)Token"
COMPACT_TOKEN_FIELD_PATTERN_TEXT = (
    r"(?:(?<![\w-])|(?<=[._-]))['\"]?(?:[A-Za-z0-9]+[._-])*"
    + COMPACT_TOKEN_KEY_PATTERN_TEXT
    + r"['\"]?"
)
AUTH_SCHEME_NAME_PATTERN_TEXT = r"(?:Bearer|Basic|Digest|Negotiate|Token|Api[-_]?Key|HMAC|AWS4-HMAC-SHA256|Signature|OAuth|MAC)"
AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT = (
    r"\b(?:Proxy-)?Authorization\s*[:=]\s*"
    + AUTH_SCHEME_NAME_PATTERN_TEXT
    + r"\s+"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\r\n;]+"
)
AUTHORIZATION_FIELD_SCHEME_CREDENTIAL_PATTERN_TEXT = (
    r"(?:(?<![\w-])|(?<=[._-]))['\"]?(?:[A-Za-z0-9]+[._-])*authorization['\"]?\s*[:=]\s*['\"]?"
    + AUTH_SCHEME_NAME_PATTERN_TEXT
    + r"\s+"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\r\n,;]+"
)
CREDENTIAL_FIELD_KEY_PATTERN_TEXT = (
    r"(?:(?<![\w-])|(?<=[._-]))['\"]?(?:[A-Za-z0-9]+[._-])*(?:authorization|aws[\s_-]?secret[\s_-]?access[\s_-]?key|secret[\s_-]?access[\s_-]?key|access[\s_-]?token|client[\s_-]?secret|api[\s_-]?key|private[\s_-]?key|secret(?:[\s_-]?key)?|password|passwd|pwd|credential|token)['\"]?"
)
CREDENTIAL_FIELD_AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT = (
    r"(?:" + CREDENTIAL_FIELD_KEY_PATTERN_TEXT + r"|" + COMPACT_TOKEN_FIELD_PATTERN_TEXT + r")"
    r"\s*[:=]\s*['\"]?"
    + AUTH_SCHEME_NAME_PATTERN_TEXT
    + r"\s+"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\r\n,;]+"
)
MAX_SESSION_META_SCAN_BYTES = 256 * 1024
SESSION_META_FLAT_UNDATED_ALIAS_PREFIX = "flat_archived_undated_v1"
REMOTE_PREFLIGHT_TIMEOUT_SECONDS = 15
REMOTE_COMMAND_TIMEOUT_SECONDS = 60
TASK_OUTPUT_RELATIVE_DIR = pathlib.Path(".codex-tmp/remote-host-context")
ACTIVE_ROLLOUT_RELATIVE_RE = re.compile(
    r"^sessions/\d{4}/\d{2}/\d{2}/rollout-(?!summary)[^/]+\.jsonl$"
)
ARCHIVED_ROLLOUT_RELATIVE_RE = re.compile(
    r"^archived_sessions/(?:\d{4}/\d{2}/\d{2}/)?rollout-(?!summary)[^/]+\.jsonl$"
)
ROOT_ROLLOUT_RELATIVE_RE = re.compile(r"^rollout-(?!summary)[^/]+\.jsonl$")
ROLLOUT_FILENAME_TIME_RE = re.compile(
    r"^rollout-(\d{4}-\d{2}-\d{2})(?:T(\d{2})-(\d{2})-(\d{2}))?(?:-|\.jsonl$)"
)
PRIVATE_IPV4_SIGNAL_RE = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|100\.(?:6[4-9]|[78]\d|9\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3}|169\.254(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})(?![\d.])"
)
PRIVATE_IPV6_SIGNAL_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:::1|f[cd][0-9A-Fa-f]{0,2}(?::[0-9A-Fa-f]{0,4}){1,7}|fe[89abAB][0-9A-Fa-f]?(?::[0-9A-Fa-f]{0,4}){1,7})(?![0-9A-Fa-f:])",
    re.I,
)
INTERNAL_HOSTNAME_SIGNAL_RE = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|localhost|lan|example|invalid|test)(?=$|[:/?#\s,;)>\]\"']|\.(?:$|\s))",
    re.I,
)
SECRET_TOKEN_SIGNAL_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|"
    r"\b(?:(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    + AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT
    + r"|"
    r"\bBearer\s+"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[A-Za-z0-9._~+/\-]+=*|"
    + CREDENTIAL_FIELD_AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT
    + r"|"
    + AUTHORIZATION_FIELD_SCHEME_CREDENTIAL_PATTERN_TEXT
    + r"|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    r")",
    re.I,
)
COMPACT_TOKEN_ASSIGNMENT_SIGNAL_RE = re.compile(
    r"(?:"
    + COMPACT_TOKEN_FIELD_PATTERN_TEXT
    + r"\s*[:=]\s*['\"]?"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\s,;]+|"
    r"(?<![\w-])--" + COMPACT_TOKEN_KEY_PATTERN_TEXT
    + r"\s+"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\s,;]+|"
    r"\b" + COMPACT_TOKEN_KEY_PATTERN_TEXT
    + r"\s*(?:\bis\b|\bwas\b|\bset\s+to\b)\s*['\"]?"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\s,;]{3,}|"
    r"\b(?:https?|ssh|sftp|git\+ssh)://[^\s)>\]\"']*[?&#]"
    + COMPACT_TOKEN_KEY_PATTERN_TEXT
    + r"="
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^&#\s)>\]\"']+"
    r")",
    re.I,
)
CREDENTIAL_ASSIGNMENT_SIGNAL_RE = re.compile(
    r"(?:"
    r"(?:(?<![\w-])|(?<=[._-]))['\"]?(?:[A-Za-z0-9]+[._-])*(?:authorization|aws[\s_-]?secret[\s_-]?access[\s_-]?key|secret[\s_-]?access[\s_-]?key|access[\s_-]?token|client[\s_-]?secret|api[\s_-]?key|private[\s_-]?key|secret(?:[\s_-]?key)?|password|passwd|pwd|credential|token)['\"]?\s*[:=]\s*['\"]?"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\s,;]+|"
    r"(?<![\w-])--(?:authorization|aws[\s_-]?secret[\s_-]?access[\s_-]?key|secret[\s_-]?access[\s_-]?key|access[\s_-]?token|client[\s_-]?secret|api[\s_-]?key|private[\s_-]?key|secret(?:[\s_-]?key)?|password|passwd|pwd|credential|token)\s+"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\s,;]+|"
    r"\b(?:aws[\s_-]?secret[\s_-]?access[\s_-]?key|secret[\s_-]?access[\s_-]?key|access[\s_-]?token|client[\s_-]?secret|api[\s_-]?key|private[\s_-]?key|secret(?:[\s_-]?key)?|password|passwd|pwd|credential|token)\s*(?:\bis\b|\bwas\b|\bset\s+to\b)\s*['\"]?"
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^'\"\s,;]{3,}"
    r")",
    re.I,
)
CHINESE_CREDENTIAL_ASSIGNMENT_SIGNAL_RE = re.compile(
    r"(?:密码|口令|凭据|凭证|密钥|令牌|授权)\s*(?:[:=：]|是|为|设置为)\s*['\"]?"
    r"(?!(?:[\[<({]?(?:(?i:redacted(?:[_-][a-z0-9]+)*|masked(?:[_-][a-z0-9]+)*|missing|omitted|unknown|null|none|empty)|已脱敏|缺失|不存在|未知|为空|空|未设置|无|没有|必须|必需|需要|被拒绝|拒绝|过期|已过期|失效|已失效|不可用|无效|错误|失败|未授权)(?:[\]\)>}]|(?:的|了)?(?:[\s,;，。；]|$))))"
    r"[^'\"\s,;，。；]+"
)
SENSITIVE_IDENTIFIER_SIGNAL_RE = re.compile(
    r"\b(?:customer|client|account|tenant|org|organi[sz]ation)[_-]?(?:id|name)?\s*[:=]\s*['\"]?"
    r"(?!(?:[\[<({]?(?:(?i:redacted(?:[_-][a-z0-9]+)*|masked(?:[_-][a-z0-9]+)*|missing|omitted|unknown|null|none|empty)|已脱敏|缺失|不存在|未知|为空|空|未设置|无|没有)(?:[\]\)>}]|(?:的|了)?(?:[\s,;，。；]|$))))"
    r"[^'\"\s,;，。；]+",
    re.I,
)
CHINESE_IDENTIFIER_SIGNAL_RE = re.compile(
    r"(?:客户|客户端|租户|账户|账号|组织|机构)(?:ID|Id|id|编号|名称|名)?\s*[:=：]\s*['\"]?"
    r"(?!(?:[\[<({]?(?:(?i:redacted(?:[_-][a-z0-9]+)*|masked(?:[_-][a-z0-9]+)*|missing|omitted|unknown|null|none|empty)|已脱敏|缺失|不存在|未知|为空|空|未设置|无|没有)(?:[\]\)>}]|(?:的|了)?(?:[\s,;，。；]|$))))"
    r"[^'\"\s,;，。；]+"
)
URL_CREDENTIAL_SIGNAL_RE = re.compile(
    r"\b(?:https?|ssh|sftp|git\+ssh)://(?:"
    r"[^/\s:@]+:[^@\s/]+@[^\s)>\]\"']+|"
    r"[^\s)>\]\"']*(?:[?&#](?:[A-Za-z0-9]+[_-])*(?:token|key|secret|credential|authorization|password|passwd)="
    + SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT
    + r"[^&#\s)>\]\"']+)"
    r")",
    re.I,
)
EMAIL_SIGNAL_RE = re.compile(
    r"(?<![\w.+-])(?!(?:git|ssh)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::[^\s]|/[^\s]))[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
PRIVATE_URL_SIGNAL_RE = re.compile(
    rf"(?:"
    rf"\b(?:https?://|ssh://|sftp://|git\+ssh://)(?:[^@\s/]+@)?(?:localhost|{PRIVATE_IPV4_SIGNAL_RE.pattern}|(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|localhost|lan|example|invalid|test))(?=$|[:/?#\s,;)>\]\"']|\.(?:$|\s))(?::\d+)?(?:[/?#][^\s)>\]\"']*)?|"
    rf"\b(?:https?://|ssh://|sftp://|git\+ssh://)(?:[^@\s/]+@)?[A-Za-z][A-Za-z0-9-]*(?::\d+)?(?:[/?#][^\s)>\]\"']*|(?=$|[\s,;)>\]\"']|\.(?:$|\s)))|"
    rf"\bgit@(?:localhost|{PRIVATE_IPV4_SIGNAL_RE.pattern}|(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|lan|example|invalid|test)):[^\s)>\]\"']+|"
    rf"\bgit@[A-Za-z][A-Za-z0-9-]*:[^\s)>\]\"']+"
    rf")",
    re.I,
)
PRIVACY_RISK_SIGNAL_RE = re.compile(
    r"(?:"
    r"\b(?:customer|client|tenant|account|personal)\s+data\b|"
    r"\b(?:pii|personally identifiable information)\b|"
    r"\bprivacy\s+(?:risk|issue|concern|leak|exposure|breach)\b|"
    r"\b(?:credential|secret|data|api[\s_-]?key|private[\s_-]?key|token|password|passwd|key)\s+(?:leaks?|leaked|expos(?:ure|ed|e|es)|breach(?:ed|es)?)\b|"
    r"\b(?:leaks?|leaked|expos(?:ure|ed|e|es)|breach(?:ed|es)?)\s+(?:credential|secret|data|api[\s_-]?key|private[\s_-]?key|token|password|passwd|key)\b|"
    r"客户数据|客户隐私|个人信息|隐私风险|隐私泄露|凭据泄露|凭证泄露|密钥泄露|敏感数据"
    r")",
    re.I,
)
DESTRUCTIVE_COMMAND_SIGNAL_RE = re.compile(
    r"(?:\brm\s+(?=(?:[^\n\r]|\\\r?\n)*(?:-[A-Za-z]*r[A-Za-z]*\b|--recursive\b))(?=(?:[^\n\r]|\\\r?\n)*(?:-[A-Za-z]*f[A-Za-z]*\b|--force\b))(?:[^\n\r]|\\\r?\n)*|\bgit\s+reset\s+--hard\b|\breset\s+--hard\b|\bdrop\s+(?:database|table|schema)\b|\btruncate\s+table\b|\bdelete\s+from\s+[`\"\[]?[A-Za-z_][A-Za-z0-9_.$`\"\]]*(?=\s*(?:where\b|;|$)))",
    re.I,
)
PRODUCTION_RISK_SIGNAL_RE = re.compile(
    r"(?:"
    r"\b(?:production|prod)\s+(?:database|db|system|server|host|cluster|environment|tenant|customer|(?:(?:api|private|secret|access|auth)\s+)?(?:credentials?|secrets?|tokens?|keys?|passwords?|passwds?|pwds?)|traffic|data)\b|"
    r"\b(?:prod|production)[-_](?:db|database|server|host|cluster|environment|tenant|customer|data|traffic|credentials?|secrets?|tokens?|keys?|passwords?|passwds?|pwds?|(?:(?:api|private|secret|access|auth)[-_])(?:credentials?|secrets?|tokens?|keys?|passwords?|passwds?|pwds?))[-_]?[A-Za-z0-9.-]*\b|"
    r"\b(?:deploy|write|delete|migrate|run|execute|operate)\b[\s\S]{0,80}\bproduction\b[\s\S]{0,40}\b(?:database|db|data|system|server|cluster|environment)\b|"
    r"\b(?:deploy|deploying|deployed|migrate|migration|rollback|restart|apply|write|delete|execute|operate)\b[\s\S]{0,40}\b(?:to|in|on|against)?\s*(?:prod|production)\b|"
    r"\brun\b[\s\S]{0,20}\b(?:migration|migrate|schema\s+change|destructive\s+command)\b[\s\S]{0,40}\b(?:in|on|against)?\s*(?:prod|production)\b|"
    r"\b(?:prod|production)\s+(?:deploy(?:ment)?|migration|rollback|write|delete|operation|change)\b|"
    r"(?:生产(?:数据库|系统|服务器|主机|集群|环境|租户|客户|凭据|凭证|密钥|令牌|密码|口令|流量|数据)|(?:部署|写入|删除|迁移|运行|执行|操作)[\s\S]{0,80}生产[\s\S]{0,40}(?:数据库|数据|系统|服务器|集群|环境)|破坏性(?:命令|操作|删除|重置|清空|销毁))"
    r")",
    re.I,
)
WRAPPER_PREFIXES = (
    "# AGENTS.md instructions",
    "<skill>",
    "<environment_context>",
    "<subagent_notification>",
    "# Review findings:",
    "<turn_aborted>",
    "Persistent internal Codex readonly review contract:",
    "Review discipline:",
)
WRAPPER_END_MARKERS = ("</INSTRUCTIONS>", "</environment_context>", "</skill>", "</subagent_notification>", "</turn_aborted>")
AUTOMATION_PROMPT_PATTERN_TEXTS = (
    r"^Run the (?:daily|weekly) Codex session retrospective\b",
    r"^Run a read-only (?:daily|weekly) retrospective over Joey's Codex session activity\b",
    r"^Run inside the dedicated worktree provisioned for this automation\b",
    r"^Use \$codex-session-retrospective to run\b",
    r"^Use the installed codex-session-retrospective workflow\b",
)
AUTOMATION_PROMPT_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in AUTOMATION_PROMPT_PATTERN_TEXTS)
AUTOMATION_PROMPT_MARKERS = (
    "Run a read-only daily retrospective over Joey's Codex session activity.",
    "Run a read-only weekly retrospective over Joey's Codex session activity.",
    "Evidence scope must match $remote-host-context's default host policy",
    "Use the automation's configured model and reasoning effort",
    "When reconstructing the real user task from rollouts, ignore injected wrapper content",
    "Write task-local artifacts under .codex-local/session-retrospective/runs/",
)
SUMMARY_SIGNAL_MARKERS = (
    "error:",
    "approval",
    "could not run",
    "you missed",
    "assumed",
    "over exploration",
    "under asking",
    "secret",
)
SUMMARY_SIGNAL_CHUNK_CHARS = 8192
SUMMARY_SIGNAL_CHUNK_OVERLAP = 256
REMOTE_SESSION_META_BEGIN = "__REMOTE_CODEX_PROBE_SESSION_META_BEGIN__"
REMOTE_SESSION_META_END = "__REMOTE_CODEX_PROBE_SESSION_META_END__"
SESSION_META_LIMIT_TRUNCATED_REASON = "session_meta_limit_truncated"
REMOTE_FETCH_ROLLOUT_BEGIN = "__REMOTE_CODEX_PROBE_FETCH_ROLLOUT_BEGIN__"
REMOTE_FETCH_ROLLOUT_END = "__REMOTE_CODEX_PROBE_FETCH_ROLLOUT_END__"
REMOTE_ROLLOUT_SUMMARY_BEGIN = "__REMOTE_CODEX_PROBE_ROLLOUT_SUMMARY_BEGIN__"
REMOTE_ROLLOUT_SUMMARY_END = "__REMOTE_CODEX_PROBE_ROLLOUT_SUMMARY_END__"

HOSTS: dict[str, dict[str, str]] = {
    "local": {"kind": "local", "label": "local", "codex_root": "~/.codex"},
    "miku-bot-dev": {
        "kind": "ssh",
        "label": "miku-bot-dev",
        "ssh_target": "miku-bot-dev",
        "codex_root": "/home/hoteng/.codex",
    },
    "miku-server-dev": {
        "kind": "ssh",
        "label": "miku-bot-dev",
        "ssh_target": "miku-bot-dev",
        "codex_root": "/home/hoteng/.codex",
    },
    "hoteng-srv-01": {
        "kind": "ssh",
        "label": "hoteng-srv-01",
        "ssh_target": "hoteng-srv-01",
        "codex_root": "/home/hoteng/.codex",
    },
}


@dataclasses.dataclass(frozen=True)
class SessionMetaScan:
    rows: list[dict[str, str]]
    truncated: bool


class SessionMetaRolloutError(ValueError):
    def __init__(self, error: str, *, rollout: str | None = None) -> None:
        super().__init__(error)
        self.error = error
        self.rollout = rollout


REMOTE_PREFLIGHT_SCRIPT = r"""
hostname_value="$(hostname 2>/dev/null || printf unknown)"
user_value="$(id -un 2>/dev/null || printf unknown)"
printf 'hostname=%s\n' "$hostname_value"
printf 'user=%s\n' "$user_value"
printf 'home=%s\n' "$HOME"
codex_root="${CODEX_REMOTE_ROOT:-$HOME/.codex}"
printf 'codex_root=%s\n' "$codex_root"
if [ -d "$codex_root" ]; then
  echo 'codex=present'
else
  echo 'codex=missing'
fi
if command -v rg >/dev/null 2>&1; then
  echo 'rg=present'
else
  echo 'rg=missing'
fi
if command -v python3 >/dev/null 2>&1; then
  echo 'python3=present'
else
  echo 'python3=missing'
fi
"""


def _error(message: str) -> int:
    print(f"error={message}", file=sys.stderr)
    return 2


def _parse_date(value: str) -> dt.date:
    try:
        return dt.datetime.strptime(value, DATE_FORMAT).date()
    except ValueError as exc:
        raise ValueError(f"invalid date: {value}; expected YYYY/MM/DD") from exc


def _iter_dates(start: dt.date, end: dt.date) -> list[dt.date]:
    if end < start:
        raise ValueError("--to must be on or after --from")
    current = start
    dates: list[dt.date] = []
    while current <= end:
        dates.append(current)
        current += dt.timedelta(days=1)
    if len(dates) > MAX_SESSION_META_DATE_COUNT:
        raise ValueError(
            f"date range must stay within {MAX_SESSION_META_DATE_COUNT} days"
        )
    return dates


def _resolve_dates(args: argparse.Namespace) -> list[dt.date]:
    explicit_dates = [_parse_date(value) for value in args.date]
    if explicit_dates and (args.from_date or args.to_date):
        raise ValueError("--date cannot be combined with --from/--to")
    if explicit_dates:
        unique_dates = sorted(dict.fromkeys(explicit_dates))
        if len(unique_dates) > MAX_SESSION_META_DATE_COUNT:
            raise ValueError(
                f"date selection must stay within {MAX_SESSION_META_DATE_COUNT} days"
            )
        return unique_dates
    if args.from_date or args.to_date:
        if not args.from_date or not args.to_date:
            raise ValueError("--from and --to must be provided together")
        return _iter_dates(_parse_date(args.from_date), _parse_date(args.to_date))
    raise ValueError("at least one --date or a --from/--to range is required")


def _parse_rollout_bound(value: str | None, option: str) -> dt.datetime | None:
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        raise ValueError(f"{option} must not be empty")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(
            f"invalid {option}: {value}; expected ISO timestamp such as 2026-05-21T10:00:00Z"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0)


def _resolve_rollout_bounds(args: argparse.Namespace) -> tuple[dt.datetime | None, dt.datetime | None]:
    rollout_start = _parse_rollout_bound(getattr(args, "rollout_start", None), "--rollout-start")
    rollout_end = _parse_rollout_bound(getattr(args, "rollout_end", None), "--rollout-end")
    if rollout_start and rollout_end and rollout_end <= rollout_start:
        raise ValueError("--rollout-end must be after --rollout-start")
    return rollout_start, rollout_end


def _iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _rollout_filename_window(path: pathlib.Path) -> tuple[dt.datetime, dt.datetime, bool] | None:
    match = ROLLOUT_FILENAME_TIME_RE.search(path.name)
    if not match:
        return None
    try:
        if match.group(2):
            timestamp = dt.datetime(
                int(match.group(1)[0:4]),
                int(match.group(1)[5:7]),
                int(match.group(1)[8:10]),
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
                tzinfo=dt.timezone.utc,
            )
            return timestamp, timestamp + dt.timedelta(seconds=1), True
        day_start = dt.datetime(
            int(match.group(1)[0:4]),
            int(match.group(1)[5:7]),
            int(match.group(1)[8:10]),
            tzinfo=dt.timezone.utc,
        )
        return day_start, day_start + dt.timedelta(days=1), False
    except ValueError:
        return None


def _rollout_matches_bounds(
    path: pathlib.Path,
    rollout_start: dt.datetime | None,
    rollout_end: dt.datetime | None,
    *,
    filename_mode: str = "all",
) -> bool:
    window = _rollout_filename_window(path)
    if filename_mode == "unknown":
        return window is None or not window[2]
    if filename_mode == "known" and (window is None or not window[2]):
        return False
    if rollout_start is None and rollout_end is None:
        return True
    if window is None:
        return False
    window_start, window_end, _has_exact_time = window
    if rollout_start and window_end <= rollout_start:
        return False
    if rollout_end and window_start >= rollout_end:
        return False
    return True


def _resolve_hosts(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    hosts: list[str] = []
    for value in values:
        if value not in HOSTS:
            raise ValueError(f"host not allowed: {value}")
        canonical = str(HOSTS[value]["label"])
        if canonical not in HOSTS:
            raise ValueError(
                f"host table misconfigured: canonical host missing for {value}: {canonical}"
            )
        if canonical in seen:
            continue
        seen.add(canonical)
        hosts.append(canonical)
    if not hosts:
        raise ValueError("at least one --host is required")
    return hosts


def _local_codex_root() -> pathlib.Path:
    return pathlib.Path.home() / ".codex"


def _task_output_root(workspace_root: pathlib.Path | None = None) -> pathlib.Path:
    root = workspace_root.resolve() if workspace_root is not None else pathlib.Path.cwd().resolve()
    return root / TASK_OUTPUT_RELATIVE_DIR


def _reject_symlink_components(path: pathlib.Path) -> None:
    if not path.is_absolute():
        raise ValueError("output path must be absolute after normalization")
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(current_stat.st_mode):
            raise ValueError("output path uses a symlink component")
        if current != path and not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError("output path ancestor is not a directory")


def _validate_output_path(candidate: pathlib.Path, root: pathlib.Path) -> pathlib.Path:
    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    if not _path_is_relative_to(resolved_candidate, resolved_root):
        raise ValueError(f"output path must stay under {resolved_root}")
    _reject_symlink_components(candidate)
    return resolved_candidate


def _resolve_output_path(
    output: str, *, workspace_root: pathlib.Path | None = None
) -> pathlib.Path:
    raw_path = pathlib.Path(output).expanduser()
    if any(part == ".." for part in raw_path.parts):
        raise ValueError("output path must not contain ..")
    workspace = workspace_root.resolve() if workspace_root is not None else pathlib.Path.cwd().resolve()
    task_output_root = _task_output_root(workspace_root)
    tmp_alias_root = pathlib.Path("/tmp")
    tmp_root = pathlib.Path("/tmp").resolve()
    if not raw_path.is_absolute():
        task_output_parts = TASK_OUTPUT_RELATIVE_DIR.parts
        if raw_path.parts[: len(task_output_parts)] == task_output_parts:
            return _validate_output_path(workspace / raw_path, task_output_root)
        return _validate_output_path(task_output_root / raw_path, task_output_root)
    if _path_is_relative_to(raw_path, tmp_alias_root):
        raw_path = tmp_root / raw_path.relative_to(tmp_alias_root)
    for root in (task_output_root, tmp_root):
        if _path_is_relative_to(raw_path.resolve(strict=False), root.resolve(strict=False)):
            return _validate_output_path(raw_path, root)
    raise ValueError(
        f"output path must stay under {task_output_root.resolve(strict=False)} or {tmp_root}"
    )


def _resolve_rollout_relative_path(value: str) -> pathlib.PurePosixPath:
    candidate = pathlib.PurePosixPath(value)
    normalized = candidate.as_posix()
    if not (
        ACTIVE_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ARCHIVED_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ROOT_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
    ):
        raise ValueError(
            "rollout path must match sessions/YYYY/MM/DD/rollout-*.jsonl, archived_sessions/rollout-*.jsonl, or rollout-*.jsonl"
        )
    return candidate


def _path_is_relative_to(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_safe_codex_root(codex_root: pathlib.Path) -> pathlib.Path:
    expanded_root = codex_root.expanduser()
    root_stat = expanded_root.lstat()
    if stat.S_ISLNK(root_stat.st_mode):
        raise ValueError("Codex root is a symlink")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("Codex root is not a directory")
    return expanded_root.resolve(strict=True)


def _safe_relative_path(
    codex_root: pathlib.Path,
    relative_path: pathlib.PurePosixPath,
    *,
    expect_directory: bool = False,
    expect_regular_file: bool = False,
) -> pathlib.Path:
    root = _resolve_safe_codex_root(codex_root)
    target = root
    parts = relative_path.parts
    for index, part in enumerate(parts):
        if part in ("", ".", ".."):
            raise ValueError("path must stay under Codex root")
        target = target / part
        target_stat = target.lstat()
        if stat.S_ISLNK(target_stat.st_mode):
            raise ValueError("path uses a symlink ancestor")
        is_last = index == len(parts) - 1
        if not is_last:
            if not stat.S_ISDIR(target_stat.st_mode):
                raise ValueError("path ancestor is not a directory")
        elif expect_directory and not stat.S_ISDIR(target_stat.st_mode):
            raise ValueError("path is not a directory")
        elif expect_regular_file and not stat.S_ISREG(target_stat.st_mode):
            raise ValueError("rollout path is not a regular file")
    target_resolved = target.resolve(strict=True)
    if not _path_is_relative_to(target_resolved, root):
        raise ValueError("path escapes Codex root")
    return target_resolved


def _safe_rollout_path(
    codex_root: pathlib.Path, rollout_relative_path: pathlib.PurePosixPath
) -> pathlib.Path:
    return _safe_relative_path(codex_root, rollout_relative_path, expect_regular_file=True)


def _safe_directory_path(
    codex_root: pathlib.Path, relative_path: pathlib.PurePosixPath
) -> pathlib.Path:
    return _safe_relative_path(codex_root, relative_path, expect_directory=True)


def _open_local_rollout_text(
    codex_root: pathlib.Path, rollout_relative_path: pathlib.PurePosixPath
):
    target = _safe_rollout_path(codex_root, rollout_relative_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("rollout path is not a regular file")
        handle = os.fdopen(fd, "rb")
        fd = -1
        return handle
    finally:
        if fd != -1:
            os.close(fd)


def _file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("rollout path is not a regular file")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if fd != -1:
            os.close(fd)
    return digest.hexdigest()


def _read_local_rollout_bytes(
    codex_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
    *,
    max_bytes: int,
) -> bytes:
    target = _safe_rollout_path(codex_root, rollout_relative_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), flags)
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise ValueError("rollout path is not a regular file")
        size = stat_result.st_size
        if max_bytes and size > max_bytes:
            raise ValueError(f"rollout too large: {size} bytes > {max_bytes}")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd != -1:
            os.close(fd)


def _write_private_bytes(output: pathlib.Path, data: bytes) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        target_stat = output.lstat()
    except FileNotFoundError:
        target_stat = None
    if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
        raise ValueError("output path exists and is not a regular file")

    last_error: FileExistsError | None = None
    for attempt in range(100):
        temp_path = output.with_name(f".{output.name}.tmp-{os.getpid()}-{attempt}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(temp_path), flags, 0o600)
        except FileExistsError as error:
            last_error = error
            continue
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, output)
            os.chmod(output, 0o600)
            return
        except Exception:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
            raise
    raise FileExistsError(f"could not create private temporary output for {output}") from last_error


def _flat_archived_rollout_matches_date(
    rollout_path: pathlib.Path, date_value: dt.date
) -> bool:
    return rollout_path.name.startswith(f"rollout-{date_value.strftime('%Y-%m-%d')}")


def _flat_archived_rollout_matches_date_or_unknown(
    rollout_path: pathlib.Path, date_value: dt.date
) -> bool:
    return _flat_archived_rollout_matches_date(
        rollout_path,
        date_value,
    ) or _session_meta_rollout_filename_date(rollout_path.name) is None


def _flat_archived_rollout_matches_bounds_or_unknown(
    rollout_path: pathlib.Path,
    rollout_start: dt.datetime | None,
    rollout_end: dt.datetime | None,
    *,
    filename_mode: str,
) -> bool:
    if _session_meta_rollout_filename_date(rollout_path.name) is None:
        return filename_mode != "known"
    return _rollout_matches_bounds(
        rollout_path,
        rollout_start,
        rollout_end,
        filename_mode=filename_mode,
    )


def _is_raw_rollout_file(path: pathlib.Path) -> bool:
    return path.name.startswith("rollout-") and not path.name.startswith("rollout-summary")


def _session_meta_rollout_filename_date(name: str) -> dt.date | None:
    window = _rollout_filename_window(pathlib.PurePosixPath(name))
    if window is None:
        return None
    return window[0].date()


def _session_meta_rollout_dedupe_key(relative_path: pathlib.PurePosixPath) -> str:
    parts = relative_path.parts
    if not parts:
        return relative_path.as_posix()
    if parts[0] == "sessions" and len(parts) > 1:
        return pathlib.PurePosixPath(*parts[1:]).as_posix()
    if parts[0] == "archived_sessions" and len(parts) > 1:
        remainder = parts[1:]
        if len(remainder) == 1:
            rollout_date = _session_meta_rollout_filename_date(remainder[0])
            if rollout_date is None:
                return relative_path.as_posix()
            return f"{rollout_date:%Y/%m/%d}/{remainder[0]}"
        return pathlib.PurePosixPath(*remainder).as_posix()
    if len(parts) == 1:
        rollout_date = _session_meta_rollout_filename_date(parts[0])
        if rollout_date is not None:
            return f"{rollout_date:%Y/%m/%d}/{parts[0]}"
    return relative_path.as_posix()


def _session_meta_flat_undated_alias(relative_path: pathlib.PurePosixPath) -> str | None:
    parts = relative_path.parts
    if not parts:
        return None
    name = parts[-1]
    if not (name.startswith("rollout-") and name.endswith(".jsonl")):
        return None
    if _session_meta_rollout_filename_date(name) is not None:
        return None
    if len(parts) == 1 or parts[0] == "sessions" or (len(parts) == 2 and parts[0] == "archived_sessions"):
        return f"{SESSION_META_FLAT_UNDATED_ALIAS_PREFIX}:{name}"
    return None


def _session_meta_is_flat_archived_undated(relative_path: pathlib.PurePosixPath) -> bool:
    return relative_path.parts[:1] == ("archived_sessions",) and _session_meta_flat_undated_alias(relative_path) is not None


def _rollout_paths_have_same_bounded_source(path: pathlib.Path, other: pathlib.Path) -> bool:
    try:
        path_size = path.stat().st_size
        other_size = other.stat().st_size
    except OSError:
        return False
    if path_size != other_size or path_size > MAX_SESSION_META_SCAN_BYTES:
        return False
    try:
        return _file_sha256(path) == _file_sha256(other)
    except OSError:
        return False


def _session_meta_record_timestamp(row: dict[str, Any]) -> dt.datetime | None:
    timestamp = row.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        return None
    try:
        return _parse_rollout_bound(timestamp, "session_meta.timestamp")
    except ValueError:
        return None


def _session_meta_record_matches_window(
    row: dict[str, Any],
    date_value: dt.date,
    rollout_start: dt.datetime | None,
    rollout_end: dt.datetime | None,
) -> bool:
    timestamp = _session_meta_record_timestamp(row)
    if timestamp is None:
        return False
    if timestamp.date() != date_value:
        return False
    if rollout_start is not None and timestamp < rollout_start:
        return False
    if rollout_end is not None and timestamp >= rollout_end:
        return False
    return True


def _session_meta_date_overlaps_window(
    date_value: dt.date,
    rollout_start: dt.datetime | None,
    rollout_end: dt.datetime | None,
) -> bool:
    day_start = dt.datetime.combine(date_value, dt.time.min, tzinfo=dt.timezone.utc)
    day_end = day_start + dt.timedelta(days=1)
    if rollout_start is not None and day_end <= rollout_start:
        return False
    if rollout_end is not None and day_start >= rollout_end:
        return False
    return True


def _session_meta_from_rollout(
    resolved_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
    *,
    date_value: dt.date | None = None,
    require_record_date_match: bool = False,
    rollout_start: dt.datetime | None = None,
    rollout_end: dt.datetime | None = None,
) -> tuple[dt.date | None, str, str, dt.datetime | None] | None:
    try:
        handle = _open_local_rollout_text(resolved_root, rollout_relative_path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SessionMetaRolloutError(
            "rollout unreadable",
            rollout=rollout_relative_path.as_posix(),
        ) from exc
    with handle:
        for line in _bounded_text_lines(handle, MAX_SESSION_META_SCAN_BYTES):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "session_meta":
                continue
            timestamp = _session_meta_record_timestamp(obj)
            if require_record_date_match:
                if date_value is None or not _session_meta_record_matches_window(
                    obj,
                    date_value,
                    rollout_start,
                    rollout_end,
                ):
                    continue
            elif timestamp is None:
                if date_value is None or not _session_meta_date_overlaps_window(
                    date_value,
                    rollout_start,
                    rollout_end,
                ):
                    continue
            else:
                if rollout_start is not None and timestamp < rollout_start:
                    continue
                if rollout_end is not None and timestamp >= rollout_end:
                    continue
            payload = obj.get("payload", {})
            session_id = str(payload.get("id", ""))
            if not session_id:
                return None
            cwd = str(payload.get("cwd", ""))
            return (timestamp.date() if timestamp is not None else date_value), session_id, cwd, timestamp
    return None


def _session_meta_rollout_preference(relative_path: pathlib.PurePosixPath) -> tuple[int, str]:
    parts = relative_path.parts
    if parts and parts[0] == "sessions":
        tier = 0
    elif parts and parts[0] == "archived_sessions":
        tier = 2
    else:
        tier = 1
    return (tier, relative_path.as_posix())


def _session_meta_rollout_sort_key(
    relative_path: pathlib.PurePosixPath,
    cached_timestamp: dt.datetime | None = None,
) -> tuple[dt.datetime, str]:
    window = _rollout_filename_window(relative_path)
    timestamp = cached_timestamp or (window[0] if window is not None else dt.datetime.min.replace(tzinfo=dt.timezone.utc))
    return (timestamp, relative_path.as_posix())


def _filter_session_meta_flat_archived_rollouts(
    selected_rollout_paths: dict[str, pathlib.Path],
    resolved_root: pathlib.Path,
) -> dict[str, pathlib.Path]:
    filtered: dict[str, pathlib.Path] = {}
    alias_owner: dict[str, list[pathlib.Path]] = {}
    for rollout_relative_key, rollout_path in sorted(
        selected_rollout_paths.items(),
        key=lambda item: _session_meta_rollout_preference(
            pathlib.PurePosixPath(item[1].relative_to(resolved_root).as_posix())
        ),
    ):
        rollout_relative_path = pathlib.PurePosixPath(rollout_path.relative_to(resolved_root).as_posix())
        alias = _session_meta_flat_undated_alias(rollout_relative_path)
        if alias is not None:
            is_session_rollout = rollout_relative_path.parts[:1] == ("sessions",)
            if (
                not is_session_rollout
                and alias in alias_owner
                and any(
                    _rollout_paths_have_same_bounded_source(rollout_path, owner)
                    for owner in alias_owner[alias]
                )
            ):
                continue
            alias_owner.setdefault(alias, []).append(rollout_path)
        filtered[rollout_relative_key] = rollout_path
    return filtered


def _parse_kv_lines(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


def _run_subprocess_text(
    argv: list[str], *, input_text: str | None = None, timeout_seconds: int | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"command not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        if timeout_seconds is None:
            raise RuntimeError("command timed out") from exc
        raise RuntimeError(
            f"command timed out after {timeout_seconds}s"
        ) from exc


def _local_preflight_row(alias: str) -> dict[str, str]:
    codex_root = _local_codex_root()
    return {
        "host": alias,
        "hostname": socket.gethostname(),
        "user": os.getenv("USER", ""),
        "home": str(pathlib.Path.home()),
        "codex": "present" if codex_root.is_dir() else "missing",
        "rg": "present" if _which("rg") else "missing",
        "python3": "present" if _which("python3") else "missing",
    }


def _which(binary: str) -> str | None:
    for directory in os.getenv("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = pathlib.Path(directory) / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _remote_preflight_row(alias: str) -> dict[str, str]:
    ssh_target = HOSTS[alias]["ssh_target"]
    result = _run_subprocess_text(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            ssh_target,
            f"CODEX_REMOTE_ROOT={shlex.quote(HOSTS[alias]['codex_root'])} {REMOTE_PREFLIGHT_SCRIPT}",
        ],
        timeout_seconds=REMOTE_PREFLIGHT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "ssh preflight failed"
        raise RuntimeError(message)
    row = _parse_kv_lines(result.stdout)
    row["host"] = alias
    return row


def _remote_python_script(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return f"""
import base64
import collections
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

CONFIG = json.loads({encoded!r})
DATE_STRINGS = CONFIG.get("dates", [])
LIMIT = int(CONFIG.get("limit", 0))
ROOT = pathlib.Path(CONFIG["codex_root"]).expanduser()
MAX_FETCH_ROLLOUT_BYTES = int(CONFIG.get("max_fetch_rollout_bytes", 0))
SESSION_META_SCAN_BYTES = int(CONFIG.get("session_meta_scan_bytes", 0))
SUMMARY_LIMIT = int(CONFIG.get("summary_limit", 0))
SUMMARY_SCAN_BYTES = int(CONFIG.get("summary_scan_bytes", 0))
SUMMARY_LINE_BYTES = int(CONFIG.get("summary_line_bytes", 0)) or {MAX_ROLLOUT_SUMMARY_LINE_BYTES}
SUMMARY_TAIL_RECORDS = int(CONFIG.get("summary_tail_records", 0))
SUMMARY_MAX_TEXT_CHARS = int(CONFIG.get("summary_max_text_chars", 0))
SUMMARY_MAX_TEXT_CHARS_LIMIT = {MAX_ROLLOUT_SUMMARY_TEXT_CHARS}
SUMMARY_KEYWORDS = [str(value) for value in CONFIG.get("summary_keywords", [])]
ROLLOUT_START = CONFIG.get("rollout_start")
ROLLOUT_END = CONFIG.get("rollout_end")
ROLLOUT_FILENAME_MODE = str(CONFIG.get("rollout_filename_mode", "all"))
ACTIVE_ROLLOUT_RELATIVE_RE = re.compile({ACTIVE_ROLLOUT_RELATIVE_RE.pattern!r})
ARCHIVED_ROLLOUT_RELATIVE_RE = re.compile({ARCHIVED_ROLLOUT_RELATIVE_RE.pattern!r})
ROOT_ROLLOUT_RELATIVE_RE = re.compile({ROOT_ROLLOUT_RELATIVE_RE.pattern!r})
ROLLOUT_FILENAME_TIME_RE = re.compile({ROLLOUT_FILENAME_TIME_RE.pattern!r})
BARE_64_HEX_SIGNAL_RE = re.compile({BARE_64_HEX_SIGNAL_RE.pattern!r})
SAFE_CREDENTIAL_VALUE_PATTERN_TEXT = {SAFE_CREDENTIAL_VALUE_PATTERN_TEXT!r}
SAFE_CREDENTIAL_VALUE_BOUNDARY_PATTERN_TEXT = {SAFE_CREDENTIAL_VALUE_BOUNDARY_PATTERN_TEXT!r}
SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT = {SAFE_CREDENTIAL_VALUE_LOOKAHEAD_PATTERN_TEXT!r}
COMPACT_TOKEN_KEY_PATTERN_TEXT = {COMPACT_TOKEN_KEY_PATTERN_TEXT!r}
COMPACT_TOKEN_FIELD_PATTERN_TEXT = {COMPACT_TOKEN_FIELD_PATTERN_TEXT!r}
AUTH_SCHEME_NAME_PATTERN_TEXT = {AUTH_SCHEME_NAME_PATTERN_TEXT!r}
AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT = {AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT!r}
AUTHORIZATION_FIELD_SCHEME_CREDENTIAL_PATTERN_TEXT = {AUTHORIZATION_FIELD_SCHEME_CREDENTIAL_PATTERN_TEXT!r}
CREDENTIAL_FIELD_KEY_PATTERN_TEXT = {CREDENTIAL_FIELD_KEY_PATTERN_TEXT!r}
CREDENTIAL_FIELD_AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT = {CREDENTIAL_FIELD_AUTH_SCHEME_CREDENTIAL_PATTERN_TEXT!r}
PRIVATE_IPV4_SIGNAL_RE = re.compile({PRIVATE_IPV4_SIGNAL_RE.pattern!r})
PRIVATE_IPV6_SIGNAL_RE = re.compile({PRIVATE_IPV6_SIGNAL_RE.pattern!r}, re.I)
INTERNAL_HOSTNAME_SIGNAL_RE = re.compile({INTERNAL_HOSTNAME_SIGNAL_RE.pattern!r}, re.I)
SECRET_TOKEN_SIGNAL_RE = re.compile({SECRET_TOKEN_SIGNAL_RE.pattern!r}, re.I)
COMPACT_TOKEN_ASSIGNMENT_SIGNAL_RE = re.compile({COMPACT_TOKEN_ASSIGNMENT_SIGNAL_RE.pattern!r}, re.I)
CREDENTIAL_ASSIGNMENT_SIGNAL_RE = re.compile({CREDENTIAL_ASSIGNMENT_SIGNAL_RE.pattern!r}, re.I)
CHINESE_CREDENTIAL_ASSIGNMENT_SIGNAL_RE = re.compile({CHINESE_CREDENTIAL_ASSIGNMENT_SIGNAL_RE.pattern!r})
SENSITIVE_IDENTIFIER_SIGNAL_RE = re.compile({SENSITIVE_IDENTIFIER_SIGNAL_RE.pattern!r}, re.I)
CHINESE_IDENTIFIER_SIGNAL_RE = re.compile({CHINESE_IDENTIFIER_SIGNAL_RE.pattern!r})
URL_CREDENTIAL_SIGNAL_RE = re.compile({URL_CREDENTIAL_SIGNAL_RE.pattern!r}, re.I)
EMAIL_SIGNAL_RE = re.compile({EMAIL_SIGNAL_RE.pattern!r})
PRIVATE_URL_SIGNAL_RE = re.compile({PRIVATE_URL_SIGNAL_RE.pattern!r}, re.I)
PRIVACY_RISK_SIGNAL_RE = re.compile({PRIVACY_RISK_SIGNAL_RE.pattern!r}, re.I)
DESTRUCTIVE_COMMAND_SIGNAL_RE = re.compile({DESTRUCTIVE_COMMAND_SIGNAL_RE.pattern!r}, re.I)
PRODUCTION_RISK_SIGNAL_RE = re.compile({PRODUCTION_RISK_SIGNAL_RE.pattern!r}, re.I)
WRAPPER_PREFIXES = {WRAPPER_PREFIXES!r}
WRAPPER_END_MARKERS = {WRAPPER_END_MARKERS!r}
AUTOMATION_PROMPT_PATTERN_TEXTS = {AUTOMATION_PROMPT_PATTERN_TEXTS!r}
AUTOMATION_PROMPT_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in AUTOMATION_PROMPT_PATTERN_TEXTS)
AUTOMATION_PROMPT_MARKERS = {AUTOMATION_PROMPT_MARKERS!r}
SUMMARY_SIGNAL_MARKERS = {SUMMARY_SIGNAL_MARKERS!r}
SUMMARY_SIGNAL_CHUNK_CHARS = {SUMMARY_SIGNAL_CHUNK_CHARS}
SUMMARY_SIGNAL_CHUNK_OVERLAP = {SUMMARY_SIGNAL_CHUNK_OVERLAP}
REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF = {REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF!r}
REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF = {REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF!r}
SESSION_META_BEGIN = {REMOTE_SESSION_META_BEGIN!r}
SESSION_META_END = {REMOTE_SESSION_META_END!r}
SESSION_META_LIMIT_TRUNCATED_REASON = {SESSION_META_LIMIT_TRUNCATED_REASON!r}
SESSION_META_FLAT_UNDATED_ALIAS_PREFIX = {SESSION_META_FLAT_UNDATED_ALIAS_PREFIX!r}
FETCH_ROLLOUT_BEGIN = {REMOTE_FETCH_ROLLOUT_BEGIN!r}
FETCH_ROLLOUT_END = {REMOTE_FETCH_ROLLOUT_END!r}
ROLLOUT_SUMMARY_BEGIN = {REMOTE_ROLLOUT_SUMMARY_BEGIN!r}
ROLLOUT_SUMMARY_END = {REMOTE_ROLLOUT_SUMMARY_END!r}


def path_is_relative_to(path, root):
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def safe_codex_root():
    root_stat = ROOT.lstat()
    if stat.S_ISLNK(root_stat.st_mode):
        raise ValueError("Codex root is a symlink")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("Codex root is not a directory")
    return ROOT.resolve(strict=True)


def safe_relative_path(rel, *, expect_directory=False, expect_regular_file=False):
    root = safe_codex_root()
    target = root
    parts = rel.parts
    for index, part in enumerate(parts):
        if part in ("", ".", ".."):
            raise ValueError("path must stay under Codex root")
        target = target / part
        target_stat = target.lstat()
        if stat.S_ISLNK(target_stat.st_mode):
            raise ValueError("path uses a symlink ancestor")
        is_last = index == len(parts) - 1
        if not is_last:
            if not stat.S_ISDIR(target_stat.st_mode):
                raise ValueError("path ancestor is not a directory")
        elif expect_directory and not stat.S_ISDIR(target_stat.st_mode):
            raise ValueError("path is not a directory")
        elif expect_regular_file and not stat.S_ISREG(target_stat.st_mode):
            raise ValueError("rollout path is not a regular file")
    target_resolved = target.resolve(strict=True)
    if not path_is_relative_to(target_resolved, root):
        raise ValueError("path escapes Codex root")
    return target_resolved


def safe_rollout_path(rel):
    return safe_relative_path(rel, expect_regular_file=True)


def safe_directory_path(rel):
    return safe_relative_path(rel, expect_directory=True)


def parse_config_time(value):
    if value in (None, ""):
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc).replace(microsecond=0)


ROLLOUT_START_TIME = parse_config_time(ROLLOUT_START)
ROLLOUT_END_TIME = parse_config_time(ROLLOUT_END)


def rollout_filename_window(path):
    match = ROLLOUT_FILENAME_TIME_RE.search(path.name)
    if not match:
        return None
    try:
        if match.group(2):
            timestamp = datetime.datetime(
                int(match.group(1)[0:4]),
                int(match.group(1)[5:7]),
                int(match.group(1)[8:10]),
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
                tzinfo=datetime.timezone.utc,
            )
            return timestamp, timestamp + datetime.timedelta(seconds=1), True
        day_start = datetime.datetime(
            int(match.group(1)[0:4]),
            int(match.group(1)[5:7]),
            int(match.group(1)[8:10]),
            tzinfo=datetime.timezone.utc,
        )
        return day_start, day_start + datetime.timedelta(days=1), False
    except ValueError:
        return None


def rollout_matches_bounds(path):
    window = rollout_filename_window(path)
    if ROLLOUT_FILENAME_MODE == "unknown":
        return window is None or not window[2]
    if ROLLOUT_FILENAME_MODE == "known" and (window is None or not window[2]):
        return False
    if ROLLOUT_START_TIME is None and ROLLOUT_END_TIME is None:
        return True
    if window is None:
        return False
    window_start, window_end, _has_exact_time = window
    if ROLLOUT_START_TIME is not None and window_end <= ROLLOUT_START_TIME:
        return False
    if ROLLOUT_END_TIME is not None and window_start >= ROLLOUT_END_TIME:
        return False
    return True


def open_rollout_text(target):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("rollout path is not a regular file")
        handle = os.fdopen(fd, "rb")
        fd = -1
        return handle
    finally:
        if fd != -1:
            os.close(fd)


def file_sha256(path):
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("rollout path is not a regular file")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if fd != -1:
            os.close(fd)
    return digest.hexdigest()


def read_rollout_bytes(target, max_bytes):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), flags)
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise ValueError("rollout path is not a regular file")
        size = stat_result.st_size
        if max_bytes and size > max_bytes:
            raise ValueError("rollout too large: " + str(size) + " bytes > " + str(max_bytes))
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return size, handle.read()
    finally:
        if fd != -1:
            os.close(fd)


def flat_archived_rollout_matches_date(rollout, date_text):
    return rollout.name.startswith("rollout-" + date_text.replace("/", "-"))


def flat_archived_rollout_matches_date_or_unknown(rollout, date_text):
    return flat_archived_rollout_matches_date(rollout, date_text) or session_meta_rollout_filename_date(rollout.name) is None


def flat_archived_rollout_matches_bounds_or_unknown(rollout):
    if session_meta_rollout_filename_date(rollout.name) is None:
        return ROLLOUT_FILENAME_MODE != "known"
    return rollout_matches_bounds(rollout)


def is_raw_rollout_file(path):
    return path.name.startswith("rollout-") and not path.name.startswith("rollout-summary")


def session_meta_rollout_filename_date(name):
    window = rollout_filename_window(pathlib.PurePosixPath(name))
    if window is None:
        return None
    return window[0].date()


def session_meta_rollout_dedupe_key(rel):
    parts = rel.parts
    if not parts:
        return rel.as_posix()
    if parts[0] == "sessions" and len(parts) > 1:
        return pathlib.PurePosixPath(*parts[1:]).as_posix()
    if parts[0] == "archived_sessions" and len(parts) > 1:
        remainder = parts[1:]
        if len(remainder) == 1:
            rollout_date = session_meta_rollout_filename_date(remainder[0])
            if rollout_date is None:
                return rel.as_posix()
            return rollout_date.strftime("%Y/%m/%d") + "/" + remainder[0]
        return pathlib.PurePosixPath(*remainder).as_posix()
    if len(parts) == 1:
        rollout_date = session_meta_rollout_filename_date(parts[0])
        if rollout_date is not None:
            return rollout_date.strftime("%Y/%m/%d") + "/" + parts[0]
    return rel.as_posix()


def session_meta_flat_undated_alias(rel):
    parts = rel.parts
    if not parts:
        return None
    name = parts[-1]
    if not (name.startswith("rollout-") and name.endswith(".jsonl")):
        return None
    if session_meta_rollout_filename_date(name) is not None:
        return None
    if len(parts) == 1 or parts[0] == "sessions" or (len(parts) == 2 and parts[0] == "archived_sessions"):
        return SESSION_META_FLAT_UNDATED_ALIAS_PREFIX + ":" + name
    return None


def session_meta_is_flat_archived_undated(rel):
    return rel.parts[:1] == ("archived_sessions",) and session_meta_flat_undated_alias(rel) is not None


def rollout_paths_have_same_bounded_source(path, other):
    try:
        path_size = path.stat().st_size
        other_size = other.stat().st_size
    except OSError:
        return False
    if path_size != other_size or path_size > SESSION_META_SCAN_BYTES:
        return False
    try:
        return file_sha256(path) == file_sha256(other)
    except OSError:
        return False


def session_meta_record_timestamp(row):
    timestamp = row.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        return None
    try:
        return parse_config_time(timestamp)
    except Exception:
        return None


def session_meta_record_matches_window(row, date_text):
    timestamp = session_meta_record_timestamp(row)
    if timestamp is None:
        return False
    if timestamp.date() != datetime.datetime.strptime(date_text, "%Y/%m/%d").date():
        return False
    if ROLLOUT_START_TIME is not None and timestamp < ROLLOUT_START_TIME:
        return False
    if ROLLOUT_END_TIME is not None and timestamp >= ROLLOUT_END_TIME:
        return False
    return True


def session_meta_date_overlaps_window(date_text):
    try:
        date_value = datetime.datetime.strptime(date_text, "%Y/%m/%d").date()
    except ValueError:
        return False
    day_start = datetime.datetime.combine(date_value, datetime.time.min, tzinfo=datetime.timezone.utc)
    day_end = day_start + datetime.timedelta(days=1)
    if ROLLOUT_START_TIME is not None and day_end <= ROLLOUT_START_TIME:
        return False
    if ROLLOUT_END_TIME is not None and day_start >= ROLLOUT_END_TIME:
        return False
    return True


def session_meta_from_rollout(rel, date_text=None, require_record_date_match=False):
    try:
        target = safe_rollout_path(rel)
    except FileNotFoundError:
        return None
    try:
        handle = open_rollout_text(target)
    except OSError:
        print(json.dumps({{"kind": "error", "error": "rollout unreadable", "rollout": rel.as_posix()}}, separators=(",", ":"), sort_keys=True))
        print(SESSION_META_END)
        raise SystemExit(0)
    with handle:
        for line in bounded_text_lines(handle, SESSION_META_SCAN_BYTES):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "session_meta":
                continue
            timestamp = session_meta_record_timestamp(obj)
            if require_record_date_match:
                if date_text is None or not session_meta_record_matches_window(obj, date_text):
                    continue
            elif timestamp is None:
                if date_text is None or not session_meta_date_overlaps_window(date_text):
                    continue
            else:
                if ROLLOUT_START_TIME is not None and timestamp < ROLLOUT_START_TIME:
                    continue
                if ROLLOUT_END_TIME is not None and timestamp >= ROLLOUT_END_TIME:
                    continue
            payload = obj.get("payload", {{}})
            session_id = str(payload.get("id", ""))
            if not session_id:
                return None
            cwd = str(payload.get("cwd", ""))
            if timestamp is None:
                meta_date = date_text
            else:
                meta_date = timestamp.strftime("%Y/%m/%d")
            return meta_date, session_id, cwd, timestamp
    return None


def session_meta_rollout_preference(rel):
    parts = rel.parts
    if parts and parts[0] == "sessions":
        tier = 0
    elif parts and parts[0] == "archived_sessions":
        tier = 2
    else:
        tier = 1
    return (tier, rel.as_posix())


def session_meta_rollout_sort_key(rel, cached_timestamp=None):
    window = rollout_filename_window(rel)
    timestamp = cached_timestamp or (window[0] if window is not None else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
    return (timestamp, rel.as_posix())


def filter_session_meta_flat_archived_rollouts(selected_rollout_paths, root):
    filtered = {{}}
    alias_owner = {{}}
    for rel_key, rollout in sorted(
        selected_rollout_paths.items(),
        key=lambda item: session_meta_rollout_preference(
            pathlib.PurePosixPath(item[1].relative_to(root).as_posix())
        ),
    ):
        rel = pathlib.PurePosixPath(rollout.relative_to(root).as_posix())
        alias = session_meta_flat_undated_alias(rel)
        if alias is not None:
            is_session_rollout = rel.parts[:1] == ("sessions",)
            if (
                not is_session_rollout
                and alias in alias_owner
                and any(rollout_paths_have_same_bounded_source(rollout, owner) for owner in alias_owner[alias])
            ):
                continue
            alias_owner.setdefault(alias, []).append(rollout)
        filtered[rel_key] = rollout
    return filtered


def normalize_text(text, max_chars):
    collapsed = " ".join(str(text).replace("\\r", "\\n").split())
    if max_chars and max_chars > 3 and len(collapsed) > max_chars:
        return collapsed[: max_chars - 3] + "..."
    return collapsed


def message_summary_from_payload(payload):
    role = str(payload.get("role", ""))
    if role not in ("assistant", "user"):
        return None, None
    parts = []
    for item in payload.get("content", []):
        if not isinstance(item, dict):
            continue
        if item.get("type") not in ("input_text", "output_text", "text"):
            continue
        text = item.get("text")
        if text:
            parts.append(str(text))
    if not parts:
        return None, None
    kind = "user_message" if role == "user" else "assistant_message"
    return kind, "\\n".join(parts)


def meaningful_prompt_text(text):
    stripped = str(text).strip()
    if not stripped:
        return ""
    if any(stripped.startswith(prefix) for prefix in WRAPPER_PREFIXES):
        for marker in WRAPPER_END_MARKERS:
            index = stripped.rfind(marker)
            if index >= 0:
                candidate = stripped[index + len(marker):].strip()
                if candidate and not any(candidate.startswith(prefix) for prefix in WRAPPER_PREFIXES):
                    return candidate
        return ""
    return stripped


def meaningful_user_message_text(text):
    stripped = meaningful_prompt_text(text)
    if not stripped:
        return ""
    if any(pattern.search(stripped) for pattern in AUTOMATION_PROMPT_PATTERNS):
        return ""
    marker_count = sum(1 for marker in AUTOMATION_PROMPT_MARKERS if marker in stripped)
    if marker_count >= 2:
        return ""
    return stripped


def summary_signal_chunks(text):
    value = str(text)
    if len(value) <= SUMMARY_SIGNAL_CHUNK_CHARS:
        yield value
        return
    step = max(1, SUMMARY_SIGNAL_CHUNK_CHARS - SUMMARY_SIGNAL_CHUNK_OVERLAP)
    offset = 0
    while offset < len(value):
        yield value[offset : offset + SUMMARY_SIGNAL_CHUNK_CHARS]
        if offset + SUMMARY_SIGNAL_CHUNK_CHARS >= len(value):
            break
        offset += step


def summary_regex_search(pattern, text, flags=re.I):
    return any(re.search(pattern, chunk, flags) for chunk in summary_signal_chunks(text))


def summary_pattern_search(pattern, text):
    return any(pattern.search(chunk) for chunk in summary_signal_chunks(text))


def summary_has_sensitive_signal(text):
    if (
        summary_pattern_search(PRIVATE_IPV4_SIGNAL_RE, text)
        or summary_pattern_search(PRIVATE_IPV6_SIGNAL_RE, text)
        or summary_pattern_search(INTERNAL_HOSTNAME_SIGNAL_RE, text)
    ):
        return True
    return any(
        summary_pattern_search(pattern, text)
        for pattern in (
            SECRET_TOKEN_SIGNAL_RE,
            COMPACT_TOKEN_ASSIGNMENT_SIGNAL_RE,
            CREDENTIAL_ASSIGNMENT_SIGNAL_RE,
            CHINESE_CREDENTIAL_ASSIGNMENT_SIGNAL_RE,
            SENSITIVE_IDENTIFIER_SIGNAL_RE,
            CHINESE_IDENTIFIER_SIGNAL_RE,
            URL_CREDENTIAL_SIGNAL_RE,
            EMAIL_SIGNAL_RE,
            PRIVATE_URL_SIGNAL_RE,
            PRIVACY_RISK_SIGNAL_RE,
            DESTRUCTIVE_COMMAND_SIGNAL_RE,
            PRODUCTION_RISK_SIGNAL_RE,
            BARE_64_HEX_SIGNAL_RE,
        )
    )


def summary_signal_text(kind, text):
    signals = []
    if summary_regex_search(r"(?:exit(?:ed)?(?: with)? code [1-9]\\d*|failed|traceback|error:|permission denied)", text):
        signals.append("error:")
    if summary_regex_search(r"(?:approval|require_escalated|sandbox|\\bauth(?:entication|orization|[-_ ]?gated)?\\b|(?<![\\w-])(?!(?:redacted|masked)(?:[_-][a-z0-9]+)*\\b)[\\w-]*credential|permission denied|TCC)", text):
        signals.append("approval")
    if summary_regex_search(r"(?:not run|did not run|unable to run|could not run|untested|未运行|无法运行)", text):
        signals.append("could not run")
    if summary_regex_search(r"(?:you missed|you forgot|wrong|incorrect|not what I asked|漏了|忘了|不对|错了)", text):
        signals.append("you missed")
    if summary_regex_search(r"(?:lost context|misunderstood|I misunderstood|assumption|assumed|上下文|误解)", text):
        signals.append("assumed")
    if summary_regex_search(r"(?:over[-_ ]?explor|over[-_ ]?investigat|over[-_ ]?search|explored too much|too much exploration|unrelated files|unrelated paths)", text):
        signals.append("over exploration")
    if summary_regex_search(r"(?:under[-_ ]?ask|did not ask|didn't ask|should have asked|without asking|missing clarification|needed clarification)", text):
        signals.append("under asking")
    if summary_has_sensitive_signal(text):
        signals.append("secret")
    return " ".join(signals) if signals else kind.replace("_", " ") + " present"


def safe_summary_text(kind, text):
    return summary_signal_text(kind, str(text))


def event_user_message_text(payload):
    message = payload.get("message")
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, dict):
        kind, text = message_summary_from_payload(message)
        if kind == "user_message" and text:
            return text.strip()
    text = payload.get("text")
    if isinstance(text, str):
        return text.strip()
    return ""


def summary_record(kind, text, *, line_no, timestamp, session_id=""):
    signal_text = text
    if kind == "user_message":
        signal_text = meaningful_user_message_text(text)
        if not signal_text:
            return None
    value = normalize_text(safe_summary_text(kind, signal_text), SUMMARY_MAX_TEXT_CHARS)
    if not value:
        return None
    record = {{"kind": kind, "line": line_no, "text": value, "timestamp": timestamp or ""}}
    if session_id:
        record["session_id"] = str(session_id)
    match_text = normalize_text(signal_text, SUMMARY_MAX_TEXT_CHARS)
    if match_text and match_text != value:
        record["_match_text"] = match_text
    return record


def summary_record_has_signal(record):
    if record is None or str(record.get("kind", "")) in ("session_meta", "scan_meta"):
        return False
    text = str(record.get("text", ""))
    return any(marker in text for marker in SUMMARY_SIGNAL_MARKERS)


def bounded_text_lines(handle, max_scan_bytes):
    scanned = 0
    buffer = bytearray()
    dropping_oversized_line = False
    chunk_bytes = 64 * 1024

    def line_ended(part):
        return part.endswith(b"\\n") or part.endswith(b"\\r")

    while True:
        if max_scan_bytes and scanned >= max_scan_bytes:
            if dropping_oversized_line:
                yield "\\n"
            elif buffer:
                yield bytes(buffer).decode("utf-8", "replace")
            return
        remaining = max_scan_bytes - scanned if max_scan_bytes else 0
        read_size = min(chunk_bytes, remaining) if remaining else chunk_bytes
        chunk = handle.read(read_size)
        if not chunk:
            if dropping_oversized_line:
                yield "\\n"
            elif buffer:
                yield bytes(buffer).decode("utf-8", "replace")
            return
        if isinstance(chunk, str):
            raw_bytes = chunk.encode("utf-8", "surrogatepass")
        else:
            raw_bytes = bytes(chunk)
        scanned += len(raw_bytes)
        for part in raw_bytes.splitlines(keepends=True):
            if dropping_oversized_line:
                if line_ended(part):
                    yield "\\n"
                    dropping_oversized_line = False
                continue
            if len(buffer) + len(part) > SUMMARY_LINE_BYTES:
                buffer.clear()
                dropping_oversized_line = True
                if line_ended(part):
                    yield "\\n"
                    dropping_oversized_line = False
                continue
            buffer.extend(part)
            if line_ended(part):
                yield bytes(buffer).decode("utf-8", "replace")
                buffer.clear()


def summarize_rollout():
    rel = pathlib.PurePosixPath(str(CONFIG["rollout"]))
    normalized = rel.as_posix()
    print(ROLLOUT_SUMMARY_BEGIN)
    if SUMMARY_MAX_TEXT_CHARS < 40 or SUMMARY_MAX_TEXT_CHARS > SUMMARY_MAX_TEXT_CHARS_LIMIT:
        print(json.dumps({{"ok": False, "error": "summary max text chars out of range"}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    if not (
        ACTIVE_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ARCHIVED_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ROOT_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
    ):
        print(json.dumps({{"ok": False, "error": "invalid rollout path"}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    try:
        target = safe_rollout_path(rel)
    except FileNotFoundError:
        print(json.dumps({{"ok": False, "error": "rollout not found"}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    except ValueError as error:
        print(json.dumps({{"ok": False, "error": str(error)}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return

    keywords = [value.casefold() for value in SUMMARY_KEYWORDS if value]
    matched = []
    matched_seen = set()
    signal_records = []
    signal_seen = set()
    signal_record_limit_reached = False
    matched_record_limit_reached = False
    json_error_count = 0
    summary_record_count = 0
    tail = collections.deque(maxlen=SUMMARY_TAIL_RECORDS)
    session_meta_record = None
    last_assistant_record = None
    last_user_record = None
    last_task_complete_record = None

    try:
        target_size = target.stat().st_size
        effective_summary_scan_bytes = SUMMARY_SCAN_BYTES or target_size
        target_sha256 = file_sha256(target) if target_size <= effective_summary_scan_bytes else None
        handle = open_rollout_text(target)
    except OSError:
        print(json.dumps({{"ok": False, "error": "rollout unreadable"}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    with handle:
        for line_no, line in enumerate(bounded_text_lines(handle, effective_summary_scan_bytes), 1):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                json_error_count += 1
                continue
            timestamp = str(obj.get("timestamp", ""))
            record = None
            record_type = str(obj.get("type", ""))
            if record_type == "session_meta" and session_meta_record is None:
                payload = obj.get("payload", {{}})
                record = summary_record(
                    "session_meta",
                    "session_id=" + str(payload.get("id", ""))
                    + " cwd_present="
                    + str(bool(payload.get("cwd", ""))).lower(),
                    line_no=line_no,
                    timestamp=timestamp,
                    session_id=str(payload.get("id", "")),
                )
                session_meta_record = record
            elif record_type == "response_item":
                payload = obj.get("payload", {{}})
                payload_type = str(payload.get("type", ""))
                if payload_type == "message":
                    kind, text = message_summary_from_payload(payload)
                    if text:
                        record = summary_record(kind, text, line_no=line_no, timestamp=timestamp)
                        if kind == "assistant_message":
                            last_assistant_record = record
                        elif kind == "user_message" and record is not None:
                            last_user_record = record
                elif payload_type == "function_call_output":
                    output = payload.get("output")
                    if isinstance(output, str) and output.strip():
                        record = summary_record("function_call_output", output, line_no=line_no, timestamp=timestamp)
            elif record_type == "event_msg":
                payload = obj.get("payload", {{}})
                payload_type = str(payload.get("type", ""))
                if payload_type == "task_complete":
                    text = payload.get("last_agent_message")
                    if text:
                        record = summary_record("task_complete", text, line_no=line_no, timestamp=timestamp)
                        last_task_complete_record = record
                elif payload_type == "user_message":
                    text = event_user_message_text(payload)
                    if text:
                        record = summary_record("user_message", text, line_no=line_no, timestamp=timestamp)
                        if record is not None:
                            last_user_record = record

            if not record or record.get("kind") == "session_meta":
                continue

            summary_record_count += 1
            if summary_record_has_signal(record):
                key = (str(record.get("kind", "")), int(record.get("line", 0)))
                if key not in signal_seen:
                    if not SUMMARY_LIMIT or len(signal_records) < SUMMARY_LIMIT:
                        signal_records.append(record)
                        signal_seen.add(key)
                    else:
                        signal_record_limit_reached = True

            text_value = str(record.get("_match_text") or record.get("text", ""))
            if keywords and any(keyword in text_value.casefold() for keyword in keywords):
                key = (str(record.get("kind", "")), int(record.get("line", 0)))
                if key not in matched_seen:
                    if not SUMMARY_LIMIT or len(matched) < SUMMARY_LIMIT:
                        matched.append(record)
                        matched_seen.add(key)
                    else:
                        matched_record_limit_reached = True
            if SUMMARY_TAIL_RECORDS:
                tail.append(record)

    print(json.dumps({{"ok": True}}, separators=(",", ":"), sort_keys=True))
    keyword_filter_applied = bool(keywords)
    record_limit_reached = bool(signal_record_limit_reached or matched_record_limit_reached)
    planned_emitted = set()

    def mark_planned(record):
        if not record:
            return
        planned_emitted.add((str(record.get("kind", "")), int(record.get("line", 0))))

    mark_planned(session_meta_record)
    for record in signal_records:
        mark_planned(record)
    for record in matched:
        mark_planned(record)
    if not keywords:
        for record in tail:
            mark_planned(record)
    mark_planned(last_user_record)
    mark_planned(last_assistant_record)
    if last_assistant_record is None:
        mark_planned(last_task_complete_record)
    emitted_summary_record_count = sum(1 for kind, _line in planned_emitted if kind != "session_meta")
    tail_record_limit_reached = bool(
        not keyword_filter_applied and summary_record_count > emitted_summary_record_count
    )
    scan_meta = {{
        "keyword_filter_applied": keyword_filter_applied,
        "kind": "scan_meta",
        "json_error_count": json_error_count,
        "line": 0,
        "matched_record_limit_reached": matched_record_limit_reached,
        "record_limit_reached": record_limit_reached,
        "rollout": normalized,
        "scan_bytes": effective_summary_scan_bytes,
        "scan_truncated": bool(effective_summary_scan_bytes and target_size > effective_summary_scan_bytes),
        "signal_record_limit_reached": signal_record_limit_reached,
        "source_bytes": target_size,
        "summary_limit": SUMMARY_LIMIT,
        "summary_record_count": summary_record_count,
        "tail_record_limit_reached": tail_record_limit_reached,
        "tail_records": SUMMARY_TAIL_RECORDS,
        "text": "scan_truncated=" + str(bool(effective_summary_scan_bytes and target_size > effective_summary_scan_bytes)).lower()
            + " keyword_filter_applied=" + str(keyword_filter_applied).lower()
            + " record_limit_reached=" + str(record_limit_reached).lower()
            + " signal_record_limit_reached=" + str(signal_record_limit_reached).lower()
            + " matched_record_limit_reached=" + str(matched_record_limit_reached).lower()
            + " tail_record_limit_reached=" + str(tail_record_limit_reached).lower()
            + " scan_bytes=" + str(effective_summary_scan_bytes)
            + " json_error_count=" + str(json_error_count)
            + " summary_limit=" + str(SUMMARY_LIMIT)
            + " tail_records=" + str(SUMMARY_TAIL_RECORDS)
            + " summary_record_count=" + str(summary_record_count)
            + " source_bytes=" + str(target_size),
        "timestamp": "",
    }}
    if target_sha256 is not None:
        scan_meta["source_sha256"] = target_sha256
    source_identity_proven = (
        scan_meta.get("scan_truncated") is False
        and type(scan_meta.get("summary_limit")) is int
        and scan_meta["summary_limit"] >= 0
        and type(scan_meta.get("json_error_count")) is int
        and scan_meta["json_error_count"] == 0
        and scan_meta.get("keyword_filter_applied") is False
        and scan_meta.get("record_limit_reached") is False
        and scan_meta.get("signal_record_limit_reached") is False
        and scan_meta.get("matched_record_limit_reached") is False
        and type(scan_meta.get("source_bytes")) is int
        and scan_meta["source_bytes"] >= 0
        and type(scan_meta.get("scan_bytes")) is int
        and scan_meta["scan_bytes"] >= scan_meta["source_bytes"]
        and isinstance(scan_meta.get("source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{{64}}", scan_meta["source_sha256"]) is not None
    )
    if source_identity_proven:
        scan_meta["source_identity_proof"] = REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF
    if source_identity_proven and scan_meta.get("tail_record_limit_reached") is False:
        scan_meta["coverage_proof"] = REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF
    print(json.dumps(scan_meta, separators=(",", ":"), sort_keys=True))
    emitted = set()

    def emit(record):
        if not record:
            return
        key = (str(record.get("kind", "")), int(record.get("line", 0)))
        if key in emitted:
            return
        payload = dict(record)
        payload.pop("_match_text", None)
        payload["rollout"] = normalized
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        emitted.add(key)

    emit(session_meta_record)
    for record in signal_records:
        emit(record)
    for record in matched:
        emit(record)
    if not keywords:
        for record in tail:
            emit(record)
    emit(last_user_record)
    emit(last_assistant_record)
    if last_assistant_record is None:
        emit(last_task_complete_record)
    print(ROLLOUT_SUMMARY_END)


def iter_session_meta():
    try:
        root = safe_codex_root()
    except FileNotFoundError:
        print(SESSION_META_BEGIN)
        print(SESSION_META_END)
        return
    print(SESSION_META_BEGIN)

    def session_directory_unreadable():
        print(json.dumps({{"kind": "error", "error": "session directory unreadable"}}, separators=(",", ":"), sort_keys=True))
        print(SESSION_META_END)
        raise SystemExit(0)

    def sorted_rollout_paths(directory):
        try:
            return sorted(directory.glob("rollout-*.jsonl"), reverse=True)
        except OSError:
            session_directory_unreadable()

    count = 0
    seen_session_ids = set()
    flat_archived_unknown_by_date = {{}}
    if ROLLOUT_FILENAME_MODE != "known":
        try:
            flat_archived_dir = safe_directory_path(pathlib.PurePosixPath("archived_sessions"))
            date_set = set(DATE_STRINGS)
            for rollout in sorted_rollout_paths(flat_archived_dir):
                if not is_raw_rollout_file(rollout):
                    continue
                if session_meta_rollout_filename_date(rollout.name) is not None:
                    continue
                rel = pathlib.PurePosixPath(rollout.relative_to(root).as_posix())
                meta = session_meta_from_rollout(rel)
                if meta is None:
                    continue
                meta_date, session_id, cwd, timestamp = meta
                if meta_date in date_set:
                    flat_archived_unknown_by_date.setdefault(meta_date, {{}})[rollout] = (session_id, cwd, timestamp)
        except FileNotFoundError:
            pass
        except OSError:
            session_directory_unreadable()
    for date_text in reversed(DATE_STRINGS):
        rollout_paths = []
        for rel_dir in (pathlib.PurePosixPath("sessions") / date_text, pathlib.PurePosixPath("archived_sessions") / date_text):
            try:
                date_dir = safe_directory_path(rel_dir)
            except FileNotFoundError:
                continue
            except OSError:
                session_directory_unreadable()
            rollout_paths.extend(
                rollout
                for rollout in sorted_rollout_paths(date_dir)
                if is_raw_rollout_file(rollout) and rollout_matches_bounds(rollout)
            )
        try:
            flat_archived_dir = safe_directory_path(pathlib.PurePosixPath("archived_sessions"))
            rollout_paths.extend(
                rollout
                for rollout in sorted_rollout_paths(flat_archived_dir)
                if is_raw_rollout_file(rollout)
                and flat_archived_rollout_matches_date(rollout, date_text)
                and flat_archived_rollout_matches_bounds_or_unknown(rollout)
            )
        except FileNotFoundError:
            pass
        except OSError:
            session_directory_unreadable()
        rollout_paths.extend(flat_archived_unknown_by_date.get(date_text, {{}}))
        rollout_paths.extend(
            rollout
            for rollout in sorted_rollout_paths(root)
            if is_raw_rollout_file(rollout)
            and flat_archived_rollout_matches_date(rollout, date_text)
            and rollout_matches_bounds(rollout)
        )
        selected_rollout_paths = {{}}
        for rollout in rollout_paths:
            rel = pathlib.PurePosixPath(rollout.relative_to(root).as_posix())
            rel_key = session_meta_rollout_dedupe_key(rel)
            selected_rollout = selected_rollout_paths.get(rel_key)
            if selected_rollout is None:
                selected_rollout_paths[rel_key] = rollout
                continue
            selected_rel = pathlib.PurePosixPath(selected_rollout.relative_to(root).as_posix())
            if session_meta_rollout_preference(rel) < session_meta_rollout_preference(selected_rel):
                selected_rollout_paths[rel_key] = rollout
        selected_rollout_paths = filter_session_meta_flat_archived_rollouts(selected_rollout_paths, root)
        cached_rollout_meta = flat_archived_unknown_by_date.get(date_text, {{}})
        selected_rollouts = sorted(
            selected_rollout_paths.values(),
            key=lambda rollout: session_meta_rollout_sort_key(
                pathlib.PurePosixPath(rollout.relative_to(root).as_posix()),
                cached_rollout_meta.get(rollout, ("", "", None))[2],
            ),
            reverse=True,
        )
        for rollout in selected_rollouts:
            rel = pathlib.PurePosixPath(rollout.relative_to(root).as_posix())
            require_record_date_match = session_meta_is_flat_archived_undated(rel)
            cached_meta = cached_rollout_meta.get(rollout)
            if cached_meta is not None:
                session_id, cwd, _timestamp = cached_meta
            else:
                meta = session_meta_from_rollout(
                    rel,
                    date_text,
                    require_record_date_match=require_record_date_match,
                )
                if meta is None:
                    continue
                _meta_date, session_id, cwd, _timestamp = meta
            if session_id:
                if session_id in seen_session_ids:
                    continue
                seen_session_ids.add(session_id)
                count += 1
                if LIMIT and count > LIMIT:
                    print(json.dumps({{"kind": "truncation", "reason": SESSION_META_LIMIT_TRUNCATED_REASON, "date": date_text, "limit": LIMIT}}, separators=(",", ":"), sort_keys=True))
                    print(SESSION_META_END)
                    return
                print(json.dumps({{"date": date_text, "session_id": session_id, "cwd": cwd, "rollout": rollout.relative_to(root).as_posix()}}, separators=(",", ":"), sort_keys=True))
    print(SESSION_META_END)


def fetch_rollout():
    rel = pathlib.PurePosixPath(str(CONFIG["rollout"]))
    normalized = rel.as_posix()
    print(FETCH_ROLLOUT_BEGIN)
    if not (
        ACTIVE_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ARCHIVED_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ROOT_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
    ):
        print(json.dumps({{"ok": False, "error": "invalid rollout path"}}, separators=(",", ":"), sort_keys=True))
        print(FETCH_ROLLOUT_END)
        return
    try:
        target = safe_rollout_path(rel)
        size, data = read_rollout_bytes(target, MAX_FETCH_ROLLOUT_BYTES)
    except FileNotFoundError:
        print(json.dumps({{"ok": False, "error": "rollout not found"}}, separators=(",", ":"), sort_keys=True))
        print(FETCH_ROLLOUT_END)
        return
    except OSError:
        print(json.dumps({{"ok": False, "error": "rollout unreadable"}}, separators=(",", ":"), sort_keys=True))
        print(FETCH_ROLLOUT_END)
        return
    except ValueError as error:
        print(json.dumps({{"ok": False, "error": str(error)}}, separators=(",", ":"), sort_keys=True))
        print(FETCH_ROLLOUT_END)
        return
    payload = base64.b64encode(data).decode("ascii")
    print(json.dumps({{"ok": True, "bytes": size}}, separators=(",", ":"), sort_keys=True))
    print(payload)
    print(FETCH_ROLLOUT_END)


if CONFIG["mode"] == "session-meta":
    try:
        iter_session_meta()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
elif CONFIG["mode"] == "fetch-rollout":
    fetch_rollout()
elif CONFIG["mode"] == "rollout-summary":
    summarize_rollout()
else:
    raise SystemExit("unknown mode: " + str(CONFIG["mode"]))
""".lstrip()


def _run_remote_python(alias: str, payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
    ssh_target = HOSTS[alias]["ssh_target"]
    return _run_subprocess_text(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            ssh_target,
            "python3",
            "-",
        ],
        input_text=_remote_python_script(payload),
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
    )


def _scan_session_meta_records(
    *,
    codex_root: pathlib.Path,
    dates: list[dt.date],
    limit: int,
    host: str,
    rollout_start: dt.datetime | None = None,
    rollout_end: dt.datetime | None = None,
    rollout_filename_mode: str = "all",
) -> SessionMetaScan:
    try:
        resolved_root = _resolve_safe_codex_root(codex_root)
    except OSError:
        return SessionMetaScan(rows=[], truncated=False)
    rows: list[dict[str, str]] = []
    seen_session_ids: set[str] = set()

    def sorted_rollout_paths(directory: pathlib.Path) -> list[pathlib.Path]:
        try:
            return sorted(directory.glob("rollout-*.jsonl"), reverse=True)
        except OSError as exc:
            raise SessionMetaRolloutError("session directory unreadable") from exc

    flat_archived_unknown_by_date: dict[dt.date, dict[pathlib.Path, tuple[str, str, dt.datetime | None]]] = {}
    if rollout_filename_mode != "known":
        try:
            flat_archived_dir = _safe_directory_path(resolved_root, pathlib.PurePosixPath("archived_sessions"))
            date_set = set(dates)
            for rollout_path in sorted_rollout_paths(flat_archived_dir):
                if not _is_raw_rollout_file(rollout_path):
                    continue
                if _session_meta_rollout_filename_date(rollout_path.name) is not None:
                    continue
                rollout_relative_path = pathlib.PurePosixPath(
                    rollout_path.relative_to(resolved_root).as_posix()
                )
                meta = _session_meta_from_rollout(
                    resolved_root,
                    rollout_relative_path,
                    rollout_start=rollout_start,
                    rollout_end=rollout_end,
                )
                if meta is None:
                    continue
                meta_date, session_id, cwd, timestamp = meta
                if meta_date in date_set:
                    flat_archived_unknown_by_date.setdefault(meta_date, {})[rollout_path] = (session_id, cwd, timestamp)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SessionMetaRolloutError("session directory unreadable") from exc

    for date_value in reversed(dates):
        date_text = date_value.strftime(DATE_FORMAT)
        rollout_paths: list[pathlib.Path] = []
        for relative_dir in (
            pathlib.PurePosixPath("sessions") / date_text,
            pathlib.PurePosixPath("archived_sessions") / date_text,
        ):
            try:
                date_dir = _safe_directory_path(resolved_root, relative_dir)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise SessionMetaRolloutError("session directory unreadable") from exc
            rollout_paths.extend(
                rollout_path
                for rollout_path in sorted_rollout_paths(date_dir)
                if _is_raw_rollout_file(rollout_path)
                and _rollout_matches_bounds(
                    rollout_path,
                    rollout_start,
                    rollout_end,
                    filename_mode=rollout_filename_mode,
                )
            )
        try:
            flat_archived_dir = _safe_directory_path(resolved_root, pathlib.PurePosixPath("archived_sessions"))
            rollout_paths.extend(
                rollout_path
                for rollout_path in sorted_rollout_paths(flat_archived_dir)
                if _is_raw_rollout_file(rollout_path)
                and _flat_archived_rollout_matches_date(rollout_path, date_value)
                and _flat_archived_rollout_matches_bounds_or_unknown(
                    rollout_path,
                    rollout_start,
                    rollout_end,
                    filename_mode=rollout_filename_mode,
                )
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SessionMetaRolloutError("session directory unreadable") from exc
        rollout_paths.extend(flat_archived_unknown_by_date.get(date_value, {}))
        rollout_paths.extend(
            rollout_path
            for rollout_path in sorted_rollout_paths(resolved_root)
            if _is_raw_rollout_file(rollout_path)
            and _flat_archived_rollout_matches_date(rollout_path, date_value)
            and _rollout_matches_bounds(
                rollout_path,
                rollout_start,
                rollout_end,
                filename_mode=rollout_filename_mode,
            )
        )
        selected_rollout_paths: dict[str, pathlib.Path] = {}
        for rollout_path in rollout_paths:
            rollout_relative_path = pathlib.PurePosixPath(
                rollout_path.relative_to(resolved_root).as_posix()
            )
            rollout_relative_key = _session_meta_rollout_dedupe_key(rollout_relative_path)
            selected_rollout_path = selected_rollout_paths.get(rollout_relative_key)
            if selected_rollout_path is None:
                selected_rollout_paths[rollout_relative_key] = rollout_path
                continue
            selected_relative_path = pathlib.PurePosixPath(
                selected_rollout_path.relative_to(resolved_root).as_posix()
            )
            if _session_meta_rollout_preference(rollout_relative_path) < _session_meta_rollout_preference(selected_relative_path):
                selected_rollout_paths[rollout_relative_key] = rollout_path
        selected_rollout_paths = _filter_session_meta_flat_archived_rollouts(selected_rollout_paths, resolved_root)
        cached_rollout_meta = flat_archived_unknown_by_date.get(date_value, {})
        selected_rollout_values = sorted(
            selected_rollout_paths.values(),
            key=lambda candidate: _session_meta_rollout_sort_key(
                pathlib.PurePosixPath(candidate.relative_to(resolved_root).as_posix()),
                cached_rollout_meta.get(candidate, ("", "", None))[2],
            ),
            reverse=True,
        )
        for rollout_path in selected_rollout_values:
            rollout_relative_path = pathlib.PurePosixPath(
                rollout_path.relative_to(resolved_root).as_posix()
            )
            require_record_date_match = _session_meta_is_flat_archived_undated(rollout_relative_path)
            cached_meta = cached_rollout_meta.get(rollout_path)
            if cached_meta is not None:
                session_id, cwd, _timestamp = cached_meta
            else:
                meta = _session_meta_from_rollout(
                    resolved_root,
                    rollout_relative_path,
                    date_value=date_value,
                    require_record_date_match=require_record_date_match,
                    rollout_start=rollout_start,
                    rollout_end=rollout_end,
                )
                if meta is None:
                    continue
                _meta_date, session_id, cwd, _timestamp = meta
            if not session_id:
                continue
            if session_id in seen_session_ids:
                continue
            seen_session_ids.add(session_id)
            rows.append(
                {
                    "host": host,
                    "date": date_value.strftime(DATE_FORMAT),
                    "session_id": session_id,
                    "cwd": cwd,
                    "rollout": rollout_path.relative_to(resolved_root).as_posix(),
                }
            )
            if limit and len(rows) > limit:
                return SessionMetaScan(rows=rows[:limit], truncated=True)
    return SessionMetaScan(rows=rows, truncated=False)


def _iter_session_meta_records(
    *,
    codex_root: pathlib.Path,
    dates: list[dt.date],
    limit: int,
    host: str,
    rollout_start: dt.datetime | None = None,
    rollout_end: dt.datetime | None = None,
    rollout_filename_mode: str = "all",
) -> list[dict[str, str]]:
    return _scan_session_meta_records(
        codex_root=codex_root,
        dates=dates,
        limit=limit,
        host=host,
        rollout_start=rollout_start,
        rollout_end=rollout_end,
        rollout_filename_mode=rollout_filename_mode,
    ).rows


def _fetch_local_rollout(codex_root: pathlib.Path, rollout_relative_path: pathlib.PurePosixPath) -> bytes:
    return _read_local_rollout_bytes(
        codex_root,
        rollout_relative_path,
        max_bytes=MAX_FETCH_ROLLOUT_BYTES,
    )


def _print_tsv(rows: list[dict[str, str]], columns: list[str]) -> None:
    print("\t".join(columns))
    for row in rows:
        print("\t".join(row.get(column, "") for column in columns))


def _sort_session_meta_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        rows,
        key=lambda row: (
            row.get("date", ""),
            row.get("rollout", ""),
            row.get("session_id", ""),
            row.get("host", ""),
        ),
        reverse=True,
    )


def _json_line_to_dict(line: str, *, host: str) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"remote helper returned a non-JSON line for host {host}: {line!r}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(
            f"remote helper returned a non-object JSON value for host {host}"
        )
    return value


def _extract_framed_lines(
    text: str,
    *,
    begin_marker: str,
    end_marker: str,
    host: str,
    command: str,
) -> list[str]:
    started = False
    payload_lines: list[str] = []
    for line in text.splitlines():
        if not started:
            if line == begin_marker:
                started = True
            continue
        if line == end_marker:
            return payload_lines
        payload_lines.append(line)
    raise ValueError(
        f"remote {command} output on host {host} was missing framed payload markers"
    )


def _extract_framed_fetch_rollout_payload(
    text: str,
    *,
    begin_marker: str,
    end_marker: str,
    host: str,
    command: str,
) -> bytes:
    payload_lines = _extract_framed_lines(
        text,
        begin_marker=begin_marker,
        end_marker=end_marker,
        host=host,
        command=command,
    )
    if not payload_lines:
        raise ValueError(
            f"remote {command} output on host {host} was missing payload header"
        )
    try:
        header = _json_line_to_dict(payload_lines[0], host=host)
    except ValueError as exc:
        raise ValueError(
            f"remote {command} output on host {host} had an invalid payload header"
        ) from exc
    if not bool(header.get("ok")):
        error = str(header.get("error", "")).strip() or "remote fetch failed"
        if error == "rollout not found":
            raise FileNotFoundError(error)
        raise ValueError(error)
    try:
        expected_bytes = int(header["bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            f"remote {command} output on host {host} had an invalid payload size"
        ) from exc
    if expected_bytes < 0:
        raise ValueError(
            f"remote {command} output on host {host} had a negative payload size"
        )
    payload = "".join(line.strip() for line in payload_lines[1:] if line.strip())
    if not payload:
        if expected_bytes != 0:
            raise ValueError(
                f"remote {command} output on host {host} was truncated or mismatched its payload size"
            )
        return b""
    try:
        data = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"remote {command} output on host {host} contained invalid base64 payload"
        ) from exc
    if len(data) != expected_bytes:
        raise ValueError(
            f"remote {command} output on host {host} was truncated or mismatched its payload size"
        )
    if len(data) > MAX_FETCH_ROLLOUT_BYTES:
        raise ValueError(
            f"rollout too large: {len(data)} bytes > {MAX_FETCH_ROLLOUT_BYTES}"
        )
    return data


def _extract_framed_rollout_summary_records(
    text: str,
    *,
    begin_marker: str,
    end_marker: str,
    host: str,
    command: str,
) -> list[dict[str, Any]]:
    payload_lines = _extract_framed_lines(
        text,
        begin_marker=begin_marker,
        end_marker=end_marker,
        host=host,
        command=command,
    )
    if not payload_lines:
        raise ValueError(
            f"remote {command} output on host {host} was missing payload header"
        )
    try:
        header = _json_line_to_dict(payload_lines[0], host=host)
    except ValueError as exc:
        raise ValueError(
            f"remote {command} output on host {host} had an invalid payload header"
        ) from exc
    if not bool(header.get("ok")):
        error = str(header.get("error", "")).strip() or "remote rollout summary failed"
        if error == "rollout not found":
            raise FileNotFoundError(error)
        raise ValueError(error)

    records: list[dict[str, Any]] = []
    for line in payload_lines[1:]:
        if not line.strip():
            continue
        item = _json_line_to_dict(line, host=host)
        records.append(item)
    return records


def _session_meta_row_from_item(item: dict[str, Any], *, host: str) -> dict[str, str]:
    required_keys = ("date", "session_id", "cwd", "rollout")
    missing = [key for key in required_keys if key not in item]
    if missing:
        raise ValueError(
            f"remote helper returned incomplete session-meta payload for host {host}: missing {', '.join(missing)}"
        )
    return {
        "host": host,
        "date": str(item["date"]),
        "session_id": str(item["session_id"]),
        "cwd": str(item["cwd"]),
        "rollout": str(item["rollout"]),
    }


def _is_session_meta_truncation_item(item: dict[str, Any]) -> bool:
    return (
        item.get("kind") == "truncation"
        and item.get("reason") == SESSION_META_LIMIT_TRUNCATED_REASON
    )


def _session_meta_error_from_item(item: dict[str, Any]) -> SessionMetaRolloutError | None:
    if item.get("kind") != "error":
        return None
    error = str(item.get("error", "")).strip() or "remote session-meta failed"
    rollout = item.get("rollout")
    rollout_text = str(rollout) if isinstance(rollout, str) and rollout else None
    return SessionMetaRolloutError(error, rollout=rollout_text)


def _session_meta_limit_error(host: str, limit: int) -> int:
    print(f"host={host}", file=sys.stderr)
    print(
        f"error=session-meta result exceeded --limit={limit}; narrow the date/host scope, use --auto-split, or raise --limit up to {MAX_SESSION_META_LIMIT}",
        file=sys.stderr,
    )
    return 1


def _scan_host_session_meta(
    alias: str,
    *,
    dates: list[dt.date],
    limit: int,
    rollout_start: dt.datetime | None,
    rollout_end: dt.datetime | None,
    rollout_filename_mode: str = "all",
) -> SessionMetaScan:
    if HOSTS[alias]["kind"] == "local":
        return _scan_session_meta_records(
            codex_root=_local_codex_root(),
            dates=dates,
            limit=limit,
            host=alias,
            rollout_start=rollout_start,
            rollout_end=rollout_end,
            rollout_filename_mode=rollout_filename_mode,
        )

    payload: dict[str, object] = {
        "mode": "session-meta",
        "dates": [date_value.strftime(DATE_FORMAT) for date_value in dates],
        "limit": limit,
        "codex_root": HOSTS[alias]["codex_root"],
        "session_meta_scan_bytes": MAX_SESSION_META_SCAN_BYTES,
    }
    if rollout_start is not None:
        payload["rollout_start"] = _iso_utc(rollout_start)
    if rollout_end is not None:
        payload["rollout_end"] = _iso_utc(rollout_end)
    if rollout_filename_mode != "all":
        payload["rollout_filename_mode"] = rollout_filename_mode
    result = _run_remote_python(alias, payload)
    if result.returncode != 0:
        raise RuntimeError("remote session-meta failed")
    rows: list[dict[str, str]] = []
    truncated = False
    payload_lines = _extract_framed_lines(
        result.stdout,
        begin_marker=REMOTE_SESSION_META_BEGIN,
        end_marker=REMOTE_SESSION_META_END,
        host=alias,
        command="session-meta",
    )
    for line in payload_lines:
        if not line.strip():
            continue
        item = _json_line_to_dict(line, host=alias)
        if _is_session_meta_truncation_item(item):
            truncated = True
            continue
        session_meta_error = _session_meta_error_from_item(item)
        if session_meta_error is not None:
            raise session_meta_error
        rows.append(_session_meta_row_from_item(item, host=alias))
    return SessionMetaScan(rows=rows, truncated=truncated)


def _session_meta_split_windows(
    windows: list[tuple[dt.date, dt.datetime, dt.datetime]],
    step: dt.timedelta,
) -> list[tuple[dt.date, dt.datetime, dt.datetime]]:
    split: list[tuple[dt.date, dt.datetime, dt.datetime]] = []
    for date_value, window_start, window_end in windows:
        current = window_start
        while current < window_end:
            next_value = min(current + step, window_end)
            split.append((date_value, current, next_value))
            current = next_value
    return split


def _dedupe_session_meta_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in _sort_session_meta_rows(rows):
        key = (row.get("host", ""), row.get("session_id", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _auto_split_host_session_meta(
    alias: str,
    *,
    dates: list[dt.date],
    limit: int,
    rollout_start: dt.datetime | None = None,
    rollout_end: dt.datetime | None = None,
) -> SessionMetaScan:
    rows: list[dict[str, str]] = []
    for date_value in reversed(dates):
        unknown_scan = _scan_host_session_meta(
            alias,
            dates=[date_value],
            limit=limit,
            rollout_start=rollout_start,
            rollout_end=rollout_end,
            rollout_filename_mode="unknown",
        )
        rows.extend(unknown_scan.rows)
        if unknown_scan.truncated:
            return SessionMetaScan(rows=_dedupe_session_meta_rows(rows), truncated=True)

    pending: list[tuple[dt.date, dt.datetime, dt.datetime]] = []
    for date_value in reversed(dates):
        day_start = dt.datetime.combine(date_value, dt.time.min, tzinfo=dt.timezone.utc)
        day_end = day_start + dt.timedelta(days=1)
        window_start = max(day_start, rollout_start) if rollout_start is not None else day_start
        window_end = min(day_end, rollout_end) if rollout_end is not None else day_end
        if window_end <= window_start:
            continue
        pending.append((date_value, window_start, window_end))

    for step in (dt.timedelta(hours=1), dt.timedelta(minutes=15), dt.timedelta(minutes=1)):
        next_pending: list[tuple[dt.date, dt.datetime, dt.datetime]] = []
        for date_value, rollout_start, rollout_end in _session_meta_split_windows(pending, step):
            scan = _scan_host_session_meta(
                alias,
                dates=[date_value],
                limit=limit,
                rollout_start=rollout_start,
                rollout_end=rollout_end,
                rollout_filename_mode="known",
            )
            if scan.truncated:
                next_pending.append((date_value, rollout_start, rollout_end))
                continue
            rows.extend(scan.rows)
        if not next_pending:
            return SessionMetaScan(rows=_dedupe_session_meta_rows(rows), truncated=False)
        pending = next_pending
    return SessionMetaScan(rows=_dedupe_session_meta_rows(rows), truncated=True)


def _scan_host_session_meta_with_auto_split(
    alias: str,
    *,
    dates: list[dt.date],
    limit: int,
    rollout_start: dt.datetime | None = None,
    rollout_end: dt.datetime | None = None,
) -> SessionMetaScan:
    rows: list[dict[str, str]] = []
    truncated = False
    for date_value in dates:
        scan = _scan_host_session_meta(
            alias,
            dates=[date_value],
            limit=limit,
            rollout_start=rollout_start,
            rollout_end=rollout_end,
        )
        if scan.truncated:
            scan = _auto_split_host_session_meta(
                alias,
                dates=[date_value],
                limit=limit,
                rollout_start=rollout_start,
                rollout_end=rollout_end,
            )
        rows.extend(scan.rows)
        truncated = truncated or scan.truncated
    return SessionMetaScan(rows=_dedupe_session_meta_rows(rows), truncated=truncated)


def cmd_preflight(args: argparse.Namespace) -> int:
    try:
        hosts = _resolve_hosts(args.host)
    except ValueError as error:
        return _error(str(error))

    rows: list[dict[str, str]] = []
    for alias in hosts:
        try:
            row = (
                _local_preflight_row(alias)
                if HOSTS[alias]["kind"] == "local"
                else _remote_preflight_row(alias)
            )
        except RuntimeError as error:
            print(f"host={alias}", file=sys.stderr)
            print(f"error={error}", file=sys.stderr)
            return 1
        row.setdefault("hostname", "")
        row.setdefault("user", "")
        row.setdefault("home", "")
        row.setdefault("codex", "missing")
        row.setdefault("rg", "missing")
        row.setdefault("python3", "missing")
        rows.append(row)

    _print_tsv(
        rows,
        ["host", "hostname", "user", "home", "codex", "rg", "python3"],
    )
    return 0


def cmd_session_meta(args: argparse.Namespace) -> int:
    try:
        hosts = _resolve_hosts(args.host)
        dates = _resolve_dates(args)
        rollout_start, rollout_end = _resolve_rollout_bounds(args)
        if args.limit < 1 or args.limit > MAX_SESSION_META_LIMIT:
            raise ValueError(
                f"--limit must stay between 1 and {MAX_SESSION_META_LIMIT}"
            )
    except ValueError as error:
        return _error(str(error))

    rows: list[dict[str, str]] = []
    auto_split = bool(getattr(args, "auto_split", False))
    for alias in hosts:
        try:
            if auto_split:
                scan = _scan_host_session_meta_with_auto_split(
                    alias,
                    dates=dates,
                    limit=args.limit,
                    rollout_start=rollout_start,
                    rollout_end=rollout_end,
                )
            else:
                scan = _scan_host_session_meta(
                    alias,
                    dates=dates,
                    limit=args.limit,
                    rollout_start=rollout_start,
                    rollout_end=rollout_end,
                )
        except SessionMetaRolloutError as error:
            print(f"host={alias}", file=sys.stderr)
            if error.rollout:
                print(f"rollout={error.rollout}", file=sys.stderr)
            print(f"error={error.error}", file=sys.stderr)
            return 1
        except (RuntimeError, ValueError) as error:
            print(f"host={alias}", file=sys.stderr)
            print(f"error={error}", file=sys.stderr)
            return 1
        if scan.truncated:
            return _session_meta_limit_error(alias, args.limit)
        host_rows = scan.rows
        rows.extend(host_rows)
        if not auto_split and len(rows) > args.limit:
            return _session_meta_limit_error("all", args.limit)
    rows = _sort_session_meta_rows(rows)

    _print_tsv(rows, ["host", "date", "session_id", "cwd", "rollout"])
    return 0


def cmd_fetch_rollout(args: argparse.Namespace) -> int:
    try:
        hosts = _resolve_hosts([args.host])
        alias = hosts[0]
        rollout_relative_path = _resolve_rollout_relative_path(args.rollout)
        output = _resolve_output_path(args.output)
    except ValueError as error:
        return _error(str(error))

    try:
        if HOSTS[alias]["kind"] == "local":
            data = _fetch_local_rollout(_local_codex_root(), rollout_relative_path)
        else:
            payload = {
                "mode": "fetch-rollout",
                "rollout": rollout_relative_path.as_posix(),
                "codex_root": HOSTS[alias]["codex_root"],
                "max_fetch_rollout_bytes": MAX_FETCH_ROLLOUT_BYTES,
            }
            try:
                result = _run_remote_python(alias, payload)
            except RuntimeError as error:
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
                print(f"error={error}", file=sys.stderr)
                return 1
            if result.returncode != 0:
                message = result.stderr.strip() or result.stdout.strip() or "remote fetch-rollout failed"
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
                print(f"error={message}", file=sys.stderr)
                return 1
            try:
                data = _extract_framed_fetch_rollout_payload(
                    result.stdout,
                    begin_marker=REMOTE_FETCH_ROLLOUT_BEGIN,
                    end_marker=REMOTE_FETCH_ROLLOUT_END,
                    host=alias,
                    command="fetch-rollout",
                )
            except FileNotFoundError:
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
                print("error=rollout not found", file=sys.stderr)
                return 1
            except ValueError as error:
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
                print(f"error={error}", file=sys.stderr)
                return 1
    except FileNotFoundError:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
        print("error=rollout not found", file=sys.stderr)
        return 1
    except OSError:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
        print("error=rollout unreadable", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
        print(f"error={error}", file=sys.stderr)
        return 1

    try:
        _write_private_bytes(output, data)
    except (OSError, ValueError) as error:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
        print(f"error={error}", file=sys.stderr)
        return 1
    print(f"host={alias}")
    print(f"rollout={rollout_relative_path.as_posix()}")
    print(f"output={output}")
    print(f"bytes={len(data)}")
    return 0


def _normalize_summary_text(value: str, *, max_text_chars: int) -> str:
    collapsed = " ".join(str(value).replace("\r", "\n").split())
    if max_text_chars > 3 and len(collapsed) > max_text_chars:
        return collapsed[: max_text_chars - 3] + "..."
    return collapsed


def _message_summary(payload: dict[str, Any]) -> tuple[str, str]:
    role = str(payload.get("role", ""))
    if role not in {"assistant", "user"}:
        return "", ""
    parts: list[str] = []
    for item in payload.get("content", []):
        if not isinstance(item, dict):
            continue
        if item.get("type") not in {"input_text", "output_text", "text"}:
            continue
        text = item.get("text")
        if text:
            parts.append(str(text))
    kind = "user_message" if role == "user" else "assistant_message"
    return kind, "\n".join(parts).strip()


def _meaningful_prompt_text(text: str) -> str:
    stripped = str(text).strip()
    if not stripped:
        return ""
    if any(stripped.startswith(prefix) for prefix in WRAPPER_PREFIXES):
        for marker in WRAPPER_END_MARKERS:
            index = stripped.rfind(marker)
            if index >= 0:
                candidate = stripped[index + len(marker) :].strip()
                if candidate and not any(candidate.startswith(prefix) for prefix in WRAPPER_PREFIXES):
                    return candidate
        return ""
    return stripped


def _meaningful_user_message_text(text: str) -> str:
    stripped = _meaningful_prompt_text(text)
    if not stripped:
        return ""
    if any(pattern.search(stripped) for pattern in AUTOMATION_PROMPT_PATTERNS):
        return ""
    marker_count = sum(1 for marker in AUTOMATION_PROMPT_MARKERS if marker in stripped)
    if marker_count >= 2:
        return ""
    return stripped


def _summary_signal_chunks(text: str) -> Iterable[str]:
    value = str(text)
    if len(value) <= SUMMARY_SIGNAL_CHUNK_CHARS:
        yield value
        return
    step = max(1, SUMMARY_SIGNAL_CHUNK_CHARS - SUMMARY_SIGNAL_CHUNK_OVERLAP)
    offset = 0
    while offset < len(value):
        yield value[offset : offset + SUMMARY_SIGNAL_CHUNK_CHARS]
        if offset + SUMMARY_SIGNAL_CHUNK_CHARS >= len(value):
            break
        offset += step


def _summary_regex_search(pattern: str, text: str, flags: int = re.I) -> bool:
    return any(re.search(pattern, chunk, flags) for chunk in _summary_signal_chunks(text))


def _summary_pattern_search(pattern: re.Pattern[str], text: str) -> bool:
    return any(pattern.search(chunk) for chunk in _summary_signal_chunks(text))


def _summary_has_sensitive_signal(text: str) -> bool:
    if (
        _summary_pattern_search(PRIVATE_IPV4_SIGNAL_RE, text)
        or _summary_pattern_search(PRIVATE_IPV6_SIGNAL_RE, text)
        or _summary_pattern_search(INTERNAL_HOSTNAME_SIGNAL_RE, text)
    ):
        return True
    return any(
        _summary_pattern_search(pattern, text)
        for pattern in (
            SECRET_TOKEN_SIGNAL_RE,
            COMPACT_TOKEN_ASSIGNMENT_SIGNAL_RE,
            CREDENTIAL_ASSIGNMENT_SIGNAL_RE,
            CHINESE_CREDENTIAL_ASSIGNMENT_SIGNAL_RE,
            SENSITIVE_IDENTIFIER_SIGNAL_RE,
            CHINESE_IDENTIFIER_SIGNAL_RE,
            URL_CREDENTIAL_SIGNAL_RE,
            EMAIL_SIGNAL_RE,
            PRIVATE_URL_SIGNAL_RE,
            PRIVACY_RISK_SIGNAL_RE,
            DESTRUCTIVE_COMMAND_SIGNAL_RE,
            PRODUCTION_RISK_SIGNAL_RE,
            BARE_64_HEX_SIGNAL_RE,
        )
    )


def _summary_signal_text(kind: str, text: str) -> str:
    signals: list[str] = []
    if _summary_regex_search(r"(?:exit(?:ed)?(?: with)? code [1-9]\d*|failed|traceback|error:|permission denied)", text):
        signals.append("error:")
    if _summary_regex_search(r"(?:approval|require_escalated|sandbox|\bauth(?:entication|orization|[-_ ]?gated)?\b|(?<![\w-])(?!(?:redacted|masked)(?:[_-][a-z0-9]+)*\b)[\w-]*credential|permission denied|TCC)", text):
        signals.append("approval")
    if _summary_regex_search(r"(?:not run|did not run|unable to run|could not run|untested|未运行|无法运行)", text):
        signals.append("could not run")
    if _summary_regex_search(r"(?:you missed|you forgot|wrong|incorrect|not what I asked|漏了|忘了|不对|错了)", text):
        signals.append("you missed")
    if _summary_regex_search(r"(?:lost context|misunderstood|I misunderstood|assumption|assumed|上下文|误解)", text):
        signals.append("assumed")
    if _summary_regex_search(r"(?:over[-_ ]?explor|over[-_ ]?investigat|over[-_ ]?search|explored too much|too much exploration|unrelated files|unrelated paths)", text):
        signals.append("over exploration")
    if _summary_regex_search(r"(?:under[-_ ]?ask|did not ask|didn't ask|should have asked|without asking|missing clarification|needed clarification)", text):
        signals.append("under asking")
    if _summary_has_sensitive_signal(text):
        signals.append("secret")
    return " ".join(signals) if signals else f"{kind.replace('_', ' ')} present"


def _safe_summary_text(kind: str, text: str) -> str:
    return _summary_signal_text(kind, text)


def _summary_record_has_signal(record: dict[str, Any] | None) -> bool:
    if record is None or str(record.get("kind", "")) in {"session_meta", "scan_meta"}:
        return False
    text = str(record.get("text", ""))
    return any(marker in text for marker in SUMMARY_SIGNAL_MARKERS)


def _event_user_message_text(payload: dict[str, Any]) -> str:
    message = payload.get("message")
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, dict):
        kind, text = _message_summary(message)
        if kind == "user_message" and text:
            return text.strip()
    text = payload.get("text")
    if isinstance(text, str):
        return text.strip()
    return ""


def _build_summary_record(
    *,
    kind: str,
    text: str,
    line_no: int,
    timestamp: str,
    max_text_chars: int,
    session_id: str = "",
) -> dict[str, Any] | None:
    signal_text = text
    if kind == "user_message":
        signal_text = _meaningful_user_message_text(text)
        if not signal_text:
            return None
    normalized = _normalize_summary_text(
        _safe_summary_text(kind, signal_text),
        max_text_chars=max_text_chars,
    )
    if not normalized:
        return None
    record = {
        "kind": kind,
        "line": line_no,
        "text": normalized,
        "timestamp": timestamp,
    }
    if session_id:
        record["session_id"] = session_id
    match_text = _normalize_summary_text(signal_text, max_text_chars=max_text_chars)
    if match_text and match_text != normalized:
        record["_match_text"] = match_text
    return record


def _bounded_text_lines(handle: Any, max_scan_bytes: int) -> Iterable[str]:
    scanned = 0
    buffer = bytearray()
    dropping_oversized_line = False
    chunk_bytes = 64 * 1024

    def line_ended(part: bytes) -> bool:
        return part.endswith(b"\n") or part.endswith(b"\r")

    while True:
        if max_scan_bytes and scanned >= max_scan_bytes:
            if dropping_oversized_line:
                yield "\n"
            elif buffer:
                yield bytes(buffer).decode("utf-8", "replace")
            return
        remaining = max_scan_bytes - scanned if max_scan_bytes else 0
        read_size = min(chunk_bytes, remaining) if remaining else chunk_bytes
        chunk = handle.read(read_size)
        if not chunk:
            if dropping_oversized_line:
                yield "\n"
            elif buffer:
                yield bytes(buffer).decode("utf-8", "replace")
            return
        if isinstance(chunk, str):
            raw_bytes = chunk.encode("utf-8", "surrogatepass")
        else:
            raw_bytes = bytes(chunk)
        scanned += len(raw_bytes)
        for part in raw_bytes.splitlines(keepends=True):
            if dropping_oversized_line:
                if line_ended(part):
                    yield "\n"
                    dropping_oversized_line = False
                continue
            if len(buffer) + len(part) > MAX_ROLLOUT_SUMMARY_LINE_BYTES:
                buffer.clear()
                dropping_oversized_line = True
                if line_ended(part):
                    yield "\n"
                    dropping_oversized_line = False
                continue
            buffer.extend(part)
            if line_ended(part):
                yield bytes(buffer).decode("utf-8", "replace")
                buffer.clear()


def _summarize_rollout_records(
    *,
    lines: Iterable[str],
    keywords: list[str],
    limit: int,
    tail_records: int,
    max_text_chars: int,
) -> list[dict[str, Any]]:
    records, _meta = _summarize_rollout_records_with_meta(
        lines=lines,
        keywords=keywords,
        limit=limit,
        tail_records=tail_records,
        max_text_chars=max_text_chars,
    )
    return records


def _summarize_rollout_records_with_meta(
    *,
    lines: Iterable[str],
    keywords: list[str],
    limit: int,
    tail_records: int,
    max_text_chars: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    search_keywords = [value.casefold() for value in keywords if value]
    matched: list[dict[str, Any]] = []
    matched_seen: set[tuple[str, int]] = set()
    signal_records: list[dict[str, Any]] = []
    signal_seen: set[tuple[str, int]] = set()
    signal_record_limit_reached = False
    matched_record_limit_reached = False
    json_error_count = 0
    summary_record_count = 0
    tail: collections.deque[dict[str, Any]] = collections.deque(maxlen=tail_records)
    session_meta_record: dict[str, Any] | None = None
    last_assistant_record: dict[str, Any] | None = None
    last_user_record: dict[str, Any] | None = None
    last_task_complete_record: dict[str, Any] | None = None

    for line_no, line in enumerate(lines, 1):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            json_error_count += 1
            continue
        timestamp = str(obj.get("timestamp", ""))
        record: dict[str, Any] | None = None
        record_type = str(obj.get("type", ""))

        if record_type == "session_meta" and session_meta_record is None:
            payload = obj.get("payload", {})
            session_meta_record = _build_summary_record(
                kind="session_meta",
                text=f"session_id={payload.get('id', '')} cwd_present={str(bool(payload.get('cwd', ''))).lower()}",
                line_no=line_no,
                timestamp=timestamp,
                max_text_chars=max_text_chars,
                session_id=str(payload.get("id", "")),
            )
            continue

        if record_type == "response_item":
            payload = obj.get("payload", {})
            payload_type = str(payload.get("type", ""))
            if payload_type == "message":
                kind, text = _message_summary(payload)
                if text:
                    record = _build_summary_record(
                        kind=kind,
                        text=text,
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                    )
                    if kind == "assistant_message":
                        last_assistant_record = record
                    elif kind == "user_message" and record is not None:
                        last_user_record = record
            elif payload_type == "function_call_output":
                output = payload.get("output")
                if isinstance(output, str) and output.strip():
                    record = _build_summary_record(
                        kind="function_call_output",
                        text=output,
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                    )
        elif record_type == "event_msg":
            payload = obj.get("payload", {})
            payload_type = str(payload.get("type", ""))
            if payload_type == "task_complete":
                text = payload.get("last_agent_message")
                if text:
                    record = _build_summary_record(
                        kind="task_complete",
                        text=str(text),
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                    )
                    last_task_complete_record = record
            elif payload_type == "user_message":
                text = _event_user_message_text(payload)
                if text:
                    record = _build_summary_record(
                        kind="user_message",
                        text=text,
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                    )
                    if record is not None:
                        last_user_record = record

        if record is None:
            continue

        summary_record_count += 1
        if _summary_record_has_signal(record):
            key = (str(record.get("kind", "")), int(record.get("line", 0)))
            if key not in signal_seen:
                if limit <= 0 or len(signal_records) < limit:
                    signal_records.append(record)
                    signal_seen.add(key)
                else:
                    signal_record_limit_reached = True

        if search_keywords:
            text_value = str(record.get("_match_text") or record.get("text", "")).casefold()
            if any(keyword in text_value for keyword in search_keywords):
                key = (str(record.get("kind", "")), int(record.get("line", 0)))
                if key not in matched_seen:
                    if limit <= 0 or len(matched) < limit:
                        matched.append(record)
                        matched_seen.add(key)
                    else:
                        matched_record_limit_reached = True

        if tail_records > 0:
            tail.append(record)

    emitted: set[tuple[str, int]] = set()
    result: list[dict[str, Any]] = []

    def append(record: dict[str, Any] | None) -> None:
        if record is None:
            return
        key = (str(record.get("kind", "")), int(record.get("line", 0)))
        if key in emitted:
            return
        emitted.add(key)
        safe_record = dict(record)
        safe_record.pop("_match_text", None)
        result.append(safe_record)

    append(session_meta_record)
    for record in signal_records:
        append(record)
    for record in matched:
        append(record)
    if not search_keywords:
        for record in tail:
            append(record)
    append(last_user_record)
    append(last_assistant_record)
    if last_assistant_record is None:
        append(last_task_complete_record)
    keyword_filter_applied = bool(search_keywords)
    emitted_summary_record_count = sum(1 for record in result if record.get("kind") != "session_meta")
    return result, {
        "keyword_filter_applied": keyword_filter_applied,
        "json_error_count": json_error_count,
        "matched_record_limit_reached": matched_record_limit_reached,
        "record_limit_reached": signal_record_limit_reached or matched_record_limit_reached,
        "signal_record_limit_reached": signal_record_limit_reached,
        "summary_record_count": summary_record_count,
        "summary_limit": limit,
        "tail_record_limit_reached": not keyword_filter_applied
        and summary_record_count > emitted_summary_record_count,
        "tail_records": tail_records,
    }


def _rollout_summary_scan_meta(
    *,
    source_bytes: int,
    source_sha256: str | None = None,
    scan_bytes: int,
    summary_limit: int,
    record_limit_reached: bool = False,
    signal_record_limit_reached: bool = False,
    matched_record_limit_reached: bool = False,
    tail_record_limit_reached: bool = False,
    keyword_filter_applied: bool = False,
    json_error_count: int = 0,
    tail_records: int = 0,
    summary_record_count: int = 0,
) -> dict[str, Any]:
    scan_truncated = bool(scan_bytes and source_bytes > scan_bytes)
    record_limit_reached = bool(record_limit_reached or signal_record_limit_reached or matched_record_limit_reached)
    row = {
        "kind": "scan_meta",
        "json_error_count": json_error_count,
        "keyword_filter_applied": keyword_filter_applied,
        "line": 0,
        "matched_record_limit_reached": matched_record_limit_reached,
        "record_limit_reached": record_limit_reached,
        "scan_bytes": scan_bytes,
        "scan_truncated": scan_truncated,
        "signal_record_limit_reached": signal_record_limit_reached,
        "source_bytes": source_bytes,
        "summary_record_count": summary_record_count,
        "summary_limit": summary_limit,
        "tail_record_limit_reached": tail_record_limit_reached,
        "tail_records": tail_records,
        "text": (
            f"scan_truncated={str(scan_truncated).lower()} "
            f"keyword_filter_applied={str(keyword_filter_applied).lower()} "
            f"record_limit_reached={str(record_limit_reached).lower()} "
            f"signal_record_limit_reached={str(signal_record_limit_reached).lower()} "
            f"matched_record_limit_reached={str(matched_record_limit_reached).lower()} "
            f"tail_record_limit_reached={str(tail_record_limit_reached).lower()} "
            f"scan_bytes={scan_bytes} json_error_count={json_error_count} "
            f"summary_limit={summary_limit} tail_records={tail_records} "
            f"summary_record_count={summary_record_count} source_bytes={source_bytes}"
        ),
        "timestamp": "",
    }
    if source_sha256 is not None:
        row["source_sha256"] = source_sha256
    return row


def _scan_meta_allows_remote_generated_source_identity_proof(row: dict[str, Any]) -> bool:
    source_bytes = row.get("source_bytes")
    scan_bytes = row.get("scan_bytes")
    summary_limit = row.get("summary_limit")
    source_sha256 = row.get("source_sha256")
    return (
        row.get("scan_truncated") is False
        and type(summary_limit) is int
        and summary_limit >= 0
        and type(row.get("json_error_count")) is int
        and row["json_error_count"] == 0
        and row.get("keyword_filter_applied") is False
        and row.get("record_limit_reached") is False
        and row.get("signal_record_limit_reached") is False
        and row.get("matched_record_limit_reached") is False
        and type(source_bytes) is int
        and source_bytes >= 0
        and type(scan_bytes) is int
        and scan_bytes >= source_bytes
        and isinstance(source_sha256, str)
        and SOURCE_SHA256_RE.fullmatch(source_sha256) is not None
    )


def _scan_meta_allows_remote_generated_coverage_proof(row: dict[str, Any]) -> bool:
    return (
        _scan_meta_allows_remote_generated_source_identity_proof(row)
        and row.get("tail_record_limit_reached") is False
    )


def cmd_rollout_summary(args: argparse.Namespace) -> int:
    try:
        hosts = _resolve_hosts([args.host])
        alias = hosts[0]
        rollout_relative_path = _resolve_rollout_relative_path(args.rollout)
        if args.limit < 1 or args.limit > MAX_ROLLOUT_SUMMARY_LIMIT:
            raise ValueError(
                f"--limit must stay between 1 and {MAX_ROLLOUT_SUMMARY_LIMIT}"
            )
        if args.tail_records < 0 or args.tail_records > MAX_ROLLOUT_SUMMARY_TAIL_RECORDS:
            raise ValueError(
                f"--tail-records must stay between 0 and {MAX_ROLLOUT_SUMMARY_TAIL_RECORDS}"
            )
        if args.max_text_chars < 40:
            raise ValueError("--max-text-chars must be at least 40")
        if args.max_text_chars > MAX_ROLLOUT_SUMMARY_TEXT_CHARS:
            raise ValueError(
                f"--max-text-chars must stay at or below {MAX_ROLLOUT_SUMMARY_TEXT_CHARS}"
            )
    except ValueError as error:
        return _error(str(error))

    rollout_ref = rollout_relative_path.as_posix()
    try:
        if HOSTS[alias]["kind"] == "local":
            codex_root = _local_codex_root()
            rollout_path = _safe_rollout_path(codex_root, rollout_relative_path)
            source_bytes = rollout_path.stat().st_size
            effective_summary_scan_bytes = MAX_ROLLOUT_SUMMARY_SCAN_BYTES or source_bytes
            source_sha256 = _file_sha256(rollout_path) if source_bytes <= effective_summary_scan_bytes else None
            with _open_local_rollout_text(codex_root, rollout_relative_path) as handle:
                records, summary_meta = _summarize_rollout_records_with_meta(
                    lines=_bounded_text_lines(handle, effective_summary_scan_bytes),
                    keywords=args.keyword,
                    limit=args.limit,
                    tail_records=args.tail_records,
                    max_text_chars=args.max_text_chars,
                )
            records.insert(
                0,
                _rollout_summary_scan_meta(
                    source_bytes=source_bytes,
                    source_sha256=source_sha256,
                    scan_bytes=effective_summary_scan_bytes,
                    summary_limit=args.limit,
                    record_limit_reached=bool(summary_meta["record_limit_reached"]),
                    signal_record_limit_reached=bool(summary_meta["signal_record_limit_reached"]),
                    matched_record_limit_reached=bool(summary_meta["matched_record_limit_reached"]),
                    tail_record_limit_reached=bool(summary_meta["tail_record_limit_reached"]),
                    keyword_filter_applied=bool(summary_meta["keyword_filter_applied"]),
                    json_error_count=int(summary_meta["json_error_count"]),
                    tail_records=int(summary_meta["tail_records"]),
                    summary_record_count=int(summary_meta["summary_record_count"]),
                ),
            )
            if _scan_meta_allows_remote_generated_source_identity_proof(records[0]):
                records[0]["source_identity_proof"] = REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF
            if _scan_meta_allows_remote_generated_coverage_proof(records[0]):
                records[0]["coverage_proof"] = REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF
            records = [dict(record, rollout=rollout_ref) for record in records]
        else:
            payload = {
                "mode": "rollout-summary",
                "rollout": rollout_ref,
                "codex_root": HOSTS[alias]["codex_root"],
                "session_meta_scan_bytes": MAX_SESSION_META_SCAN_BYTES,
                "summary_keywords": list(args.keyword),
                "summary_limit": args.limit,
                "summary_line_bytes": MAX_ROLLOUT_SUMMARY_LINE_BYTES,
                "summary_scan_bytes": MAX_ROLLOUT_SUMMARY_SCAN_BYTES,
                "summary_tail_records": args.tail_records,
                "summary_max_text_chars": args.max_text_chars,
            }
            try:
                result = _run_remote_python(alias, payload)
            except RuntimeError as error:
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_ref}", file=sys.stderr)
                print(f"error={error}", file=sys.stderr)
                return 1
            if result.returncode != 0:
                message = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "remote rollout-summary failed"
                )
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_ref}", file=sys.stderr)
                print(f"error={message}", file=sys.stderr)
                return 1
            try:
                records = _extract_framed_rollout_summary_records(
                    result.stdout,
                    begin_marker=REMOTE_ROLLOUT_SUMMARY_BEGIN,
                    end_marker=REMOTE_ROLLOUT_SUMMARY_END,
                    host=alias,
                    command="rollout-summary",
                )
            except FileNotFoundError:
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_ref}", file=sys.stderr)
                print("error=rollout not found", file=sys.stderr)
                return 1
            except ValueError as error:
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_ref}", file=sys.stderr)
                print(f"error={error}", file=sys.stderr)
                return 1
    except FileNotFoundError:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_ref}", file=sys.stderr)
        print("error=rollout not found", file=sys.stderr)
        return 1
    except OSError:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_ref}", file=sys.stderr)
        print("error=rollout unreadable", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_ref}", file=sys.stderr)
        print(f"error={error}", file=sys.stderr)
        return 1

    # Normalize the host and backing ref after both local and remote paths.
    for record in records:
        item = dict(record)
        item["host"] = alias
        item["rollout"] = rollout_ref
        print(json.dumps(item, separators=(",", ":"), sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read bounded Codex session evidence from Joey's default hosts without ad hoc SSH literals."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser(
        "preflight",
        help="Check reachability and bounded prerequisites on the allowed hosts.",
    )
    preflight.add_argument("--host", action="append", required=True)
    preflight.set_defaults(func=cmd_preflight)

    session_meta = subparsers.add_parser(
        "session-meta",
        help="List session ids, cwd, and rollout paths from bounded date trees.",
    )
    session_meta.add_argument("--host", action="append", required=True)
    session_meta.add_argument("--date", action="append", default=[])
    session_meta.add_argument("--from", dest="from_date")
    session_meta.add_argument("--to", dest="to_date")
    session_meta.add_argument("--limit", type=int, default=200)
    session_meta.add_argument(
        "--rollout-start",
        help="Inclusive UTC filename timestamp lower bound, e.g. 2026-05-21T10:00:00Z.",
    )
    session_meta.add_argument(
        "--rollout-end",
        help="Exclusive UTC filename timestamp upper bound, e.g. 2026-05-21T11:00:00Z.",
    )
    session_meta.add_argument(
        "--auto-split",
        action="store_true",
        help="When a date overflows --limit, retry by hour, then 15-minute, then 1-minute rollout filename windows and merge rows.",
    )
    session_meta.set_defaults(func=cmd_session_meta)

    fetch_rollout = subparsers.add_parser(
        "fetch-rollout",
        help="Copy one validated rollout file from an allowed host to a local path.",
    )
    fetch_rollout.add_argument("--host", required=True)
    fetch_rollout.add_argument(
        "--rollout",
        required=True,
        help="Relative rollout path under the remote Codex root (sessions/..., archived_sessions/..., or root rollout-*.jsonl).",
    )
    fetch_rollout.add_argument(
        "--output",
        required=True,
        help="Output path must resolve under .codex-tmp/remote-host-context/ or /tmp.",
    )
    fetch_rollout.set_defaults(func=cmd_fetch_rollout)

    rollout_summary = subparsers.add_parser(
        "rollout-summary",
        help="Read a bounded redacted prefix summary from one rollout without copying the full file.",
    )
    rollout_summary.add_argument("--host", required=True)
    rollout_summary.add_argument(
        "--rollout",
        required=True,
        help="Relative rollout path under the remote Codex root (sessions/..., archived_sessions/..., or root rollout-*.jsonl).",
    )
    rollout_summary.add_argument("--keyword", action="append", default=[])
    rollout_summary.add_argument("--limit", type=int, default=40)
    rollout_summary.add_argument("--tail-records", type=int, default=8)
    rollout_summary.add_argument("--max-text-chars", type=int, default=400)
    rollout_summary.set_defaults(func=cmd_rollout_summary)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
