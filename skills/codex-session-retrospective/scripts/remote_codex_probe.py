#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import dataclasses
import datetime as dt
import errno
import hashlib
import io
import json
import os
import pathlib
import re
import selectors
import shlex
import socket
import subprocess
import stat
import sys
import time
from collections.abc import Iterable
from typing import Any, BinaryIO

DATE_FORMAT = "%Y/%m/%d"
MAX_SESSION_META_LIMIT = 500
MAX_SESSION_META_CANDIDATE_LIMIT = MAX_SESSION_META_LIMIT + 1
MAX_SESSION_META_DATE_COUNT = 31
MAX_FETCH_ROLLOUT_BYTES = 16 * 1024 * 1024
MAX_REMOTE_SESSION_META_SERIALIZED_ROW_BYTES = 64 * 1024
REMOTE_SESSION_META_FRAME_OVERHEAD_BYTES = 64 * 1024
MAX_REMOTE_SESSION_META_STDOUT_BYTES = (
    (MAX_SESSION_META_LIMIT + 1) * MAX_REMOTE_SESSION_META_SERIALIZED_ROW_BYTES
    + REMOTE_SESSION_META_FRAME_OVERHEAD_BYTES
)
MAX_ROLLOUT_SUMMARY_LIMIT = 200
MAX_ROLLOUT_SUMMARY_SCAN_BYTES = MAX_FETCH_ROLLOUT_BYTES
MAX_ROLLOUT_SUMMARY_LINE_BYTES = 1024 * 1024
MAX_ROLLOUT_SUMMARY_TAIL_RECORDS = 50
MAX_ROLLOUT_SUMMARY_TEXT_CHARS = 1200
MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_RECORD_BYTES = 64 * 1024
MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_BYTES = (
    (2 * MAX_ROLLOUT_SUMMARY_LIMIT + 4)
    * MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_RECORD_BYTES
)
REMOTE_ROLLOUT_SUMMARY_FRAME_OVERHEAD_BYTES = 64 * 1024
MAX_REMOTE_ROLLOUT_SUMMARY_STDOUT_BYTES = (
    MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_BYTES
    + REMOTE_ROLLOUT_SUMMARY_FRAME_OVERHEAD_BYTES
)
MAX_REMOTE_STDERR_BYTES = 64 * 1024
REMOTE_FETCH_FRAME_OVERHEAD_BYTES = 64 * 1024
SESSION_META_READ_CHUNK_BYTES = 64 * 1024
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
RAW_ROLLOUT_BASENAME_RE = re.compile(r"^rollout-(?!summary)[^/]+\.jsonl$")
SECURE_ROLLOUT_DIR_FD_SUPPORTED = (
    getattr(os, "O_DIRECTORY", None) is not None
    and getattr(os, "O_NOFOLLOW", None) is not None
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)
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
SUMMARY_SIGNAL_CATEGORY_PATTERNS = (
    ("error:", r"(?:exit(?:ed)?(?: with)? code [1-9]\d*|failed|traceback|error:|permission denied)"),
    (
        "approval",
        r"(?:approval|require_escalated|sandbox|\bauth(?:entication|orization|[-_ ]?gated)?\b|(?<![\w-])(?!(?:redacted|masked)(?:[_-][a-z0-9]+)*\b)[\w-]*credential|permission denied|TCC)",
    ),
    ("could not run", r"(?:not run|did not run|unable to run|could not run|untested|未运行|无法运行)"),
    ("you missed", r"(?:you missed|you forgot|wrong|incorrect|not what I asked|漏了|忘了|不对|错了)"),
    ("assumed", r"(?:lost context|misunderstood|I misunderstood|assumption|assumed|上下文|误解)"),
    (
        "over exploration",
        r"(?:over[-_ ]?explor|over[-_ ]?investigat|over[-_ ]?search|explored too much|too much exploration|unrelated files|unrelated paths)",
    ),
    (
        "under asking",
        r"(?:under[-_ ]?ask|did not ask|didn't ask|should have asked|without asking|missing clarification|needed clarification)",
    ),
)
SUMMARY_SIGNAL_CATEGORY_LABELS = tuple(label for label, _pattern in SUMMARY_SIGNAL_CATEGORY_PATTERNS)
SUMMARY_SIGNAL_CATEGORY_RES = tuple((label, re.compile(pattern, re.I)) for label, pattern in SUMMARY_SIGNAL_CATEGORY_PATTERNS)
SUMMARY_SENSITIVE_SIGNAL_PATTERN_TEXT = "|".join(
    f"(?:{pattern})"
    for pattern in (
        PRIVATE_IPV4_SIGNAL_RE.pattern,
        PRIVATE_IPV6_SIGNAL_RE.pattern,
        INTERNAL_HOSTNAME_SIGNAL_RE.pattern,
        SECRET_TOKEN_SIGNAL_RE.pattern,
        COMPACT_TOKEN_ASSIGNMENT_SIGNAL_RE.pattern,
        CREDENTIAL_ASSIGNMENT_SIGNAL_RE.pattern,
        CHINESE_CREDENTIAL_ASSIGNMENT_SIGNAL_RE.pattern,
        SENSITIVE_IDENTIFIER_SIGNAL_RE.pattern,
        CHINESE_IDENTIFIER_SIGNAL_RE.pattern,
        URL_CREDENTIAL_SIGNAL_RE.pattern,
        EMAIL_SIGNAL_RE.pattern,
        PRIVATE_URL_SIGNAL_RE.pattern,
        PRIVACY_RISK_SIGNAL_RE.pattern,
        DESTRUCTIVE_COMMAND_SIGNAL_RE.pattern,
        PRODUCTION_RISK_SIGNAL_RE.pattern,
        BARE_64_HEX_SIGNAL_RE.pattern,
    )
)
SUMMARY_SENSITIVE_SIGNAL_RE = re.compile(SUMMARY_SENSITIVE_SIGNAL_PATTERN_TEXT, re.I)
REMOTE_SESSION_META_BEGIN = "__REMOTE_CODEX_PROBE_SESSION_META_BEGIN__"
REMOTE_SESSION_META_END = "__REMOTE_CODEX_PROBE_SESSION_META_END__"
SESSION_META_LIMIT_TRUNCATED_REASON = "session_meta_limit_truncated"
SESSION_META_CANDIDATE_LIMIT_TRUNCATED_REASON = (
    "session_meta_candidate_limit_truncated"
)
SESSION_META_OUTPUT_ROW_TOO_LARGE_ERROR = "session-meta output row too large"
REMOTE_FETCH_ROLLOUT_BEGIN = "__REMOTE_CODEX_PROBE_FETCH_ROLLOUT_BEGIN__"
REMOTE_FETCH_ROLLOUT_END = "__REMOTE_CODEX_PROBE_FETCH_ROLLOUT_END__"
REMOTE_ROLLOUT_SUMMARY_BEGIN = "__REMOTE_CODEX_PROBE_ROLLOUT_SUMMARY_BEGIN__"
REMOTE_ROLLOUT_SUMMARY_END = "__REMOTE_CODEX_PROBE_ROLLOUT_SUMMARY_END__"
ROLLOUT_SUMMARY_OUTPUT_TOO_LARGE_ERROR = "rollout summary output too large"

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


@dataclasses.dataclass(frozen=True)
class RolloutIdentity:
    size: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


@dataclasses.dataclass(frozen=True)
class RolloutInventoryIdentity:
    mode: int
    size: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


@dataclasses.dataclass(frozen=True)
class RolloutStableIdentity:
    device: int
    inode: int


@dataclasses.dataclass(frozen=True)
class RolloutPrefixProof:
    length: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class RolloutCandidateIdentity:
    snapshot: RolloutIdentity
    stable: RolloutStableIdentity
    prefix_proof: RolloutPrefixProof | None = None


@dataclasses.dataclass(frozen=True)
class EnumeratedRolloutParent:
    fd: int
    expected_identity: RolloutCandidateIdentity
    allow_append: bool


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


def _directory_open_flags() -> int:
    if not SECURE_ROLLOUT_DIR_FD_SUPPORTED:
        raise OSError(
            "secure rollout reads require O_DIRECTORY, O_NOFOLLOW, and descriptor-relative open/stat"
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _regular_file_open_flags() -> int:
    _directory_open_flags()
    nonblocking_flag = getattr(os, "O_NONBLOCK", None)
    if nonblocking_flag is None:
        raise OSError("secure rollout reads require O_NONBLOCK")
    return os.O_RDONLY | os.O_NOFOLLOW | nonblocking_flag | getattr(os, "O_CLOEXEC", 0)


def _validate_relative_path_parts(
    relative_path: pathlib.PurePosixPath,
) -> tuple[str, ...]:
    if relative_path.is_absolute():
        raise ValueError("path must stay under Codex root")
    parts = relative_path.parts
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("path must stay under Codex root")
    return parts


def _inspect_safe_codex_root(
    codex_root: pathlib.Path,
) -> tuple[pathlib.Path, os.stat_result]:
    expanded_root = codex_root.expanduser()
    root_entry = expanded_root.lstat()
    if stat.S_ISLNK(root_entry.st_mode):
        raise ValueError("Codex root is a symlink")
    if not stat.S_ISDIR(root_entry.st_mode):
        raise ValueError("Codex root is not a directory")
    return expanded_root, root_entry


def _open_pinned_codex_root(codex_root: pathlib.Path) -> int:
    expanded_root, observed = _inspect_safe_codex_root(codex_root)
    try:
        fd = os.open(str(expanded_root), _directory_open_flags())
    except FileNotFoundError as error:
        raise ValueError("Codex root changed after initial inspection") from error
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError("Codex root is not a directory")
        if (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino):
            raise ValueError("Codex root changed during open")
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_pinned_directory_from_fd(
    root_fd: int,
    relative_path: pathlib.PurePosixPath,
) -> int:
    directory_fd = os.dup(root_fd)
    try:
        for part in _validate_relative_path_parts(relative_path):
            observed = os.stat(part, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(observed.st_mode):
                raise ValueError("path uses a symlink ancestor")
            if not stat.S_ISDIR(observed.st_mode):
                raise ValueError("path ancestor is not a directory")
            try:
                next_fd = os.open(part, _directory_open_flags(), dir_fd=directory_fd)
            except FileNotFoundError as error:
                raise ValueError("path ancestor changed during open") from error
            try:
                opened = os.fstat(next_fd)
                if not stat.S_ISDIR(opened.st_mode):
                    raise ValueError("path ancestor is not a directory")
                if (opened.st_dev, opened.st_ino) != (
                    observed.st_dev,
                    observed.st_ino,
                ):
                    raise ValueError("path ancestor changed during open")
            except Exception:
                os.close(next_fd)
                raise
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _rollout_identity_from_stat(stat_result: os.stat_result) -> RolloutIdentity:
    if not stat.S_ISREG(stat_result.st_mode):
        raise ValueError("rollout path is not a regular file")
    return RolloutIdentity(
        size=stat_result.st_size,
        device=stat_result.st_dev,
        inode=stat_result.st_ino,
        mtime_ns=stat_result.st_mtime_ns,
        ctime_ns=stat_result.st_ctime_ns,
    )


def _stable_rollout_identity_from_stat(
    stat_result: os.stat_result,
) -> RolloutStableIdentity:
    if stat.S_ISLNK(stat_result.st_mode):
        raise ValueError("rollout path is a symlink")
    if not stat.S_ISREG(stat_result.st_mode):
        raise ValueError("rollout path is not a regular file")
    return RolloutStableIdentity(
        device=stat_result.st_dev,
        inode=stat_result.st_ino,
    )


def _rollout_inventory_identity_from_stat(
    stat_result: os.stat_result,
) -> RolloutInventoryIdentity:
    return RolloutInventoryIdentity(
        mode=stat_result.st_mode,
        size=stat_result.st_size,
        device=stat_result.st_dev,
        inode=stat_result.st_ino,
        mtime_ns=stat_result.st_mtime_ns,
        ctime_ns=stat_result.st_ctime_ns,
    )


def _capture_rollout_inventory_identity_from_parent_fd(
    parent_fd: int,
    name: str,
) -> RolloutInventoryIdentity:
    try:
        stat_result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError("rollout identity changed during enumeration") from error
    return _rollout_inventory_identity_from_stat(stat_result)


def _assert_rollout_inventory_identity(
    actual: RolloutInventoryIdentity,
    expected: RolloutInventoryIdentity,
    *,
    allow_append: bool,
    phase: str,
) -> None:
    if allow_append:
        same_file = (
            actual.device == expected.device
            and actual.inode == expected.inode
        )
        unchanged_snapshot = actual.size != expected.size or actual == expected
        matches = (
            same_file
            and actual.size >= expected.size
            and unchanged_snapshot
        )
    else:
        matches = actual == expected
    if not matches:
        raise ValueError(f"rollout identity changed {phase}")


def _validated_rollout_inventory_identity_from_parent_fd(
    parent_fd: int,
    name: str,
    expected: RolloutInventoryIdentity,
    *,
    allow_append: bool,
    phase: str,
) -> RolloutInventoryIdentity:
    try:
        stat_result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError(f"rollout identity changed {phase}") from error
    actual = _rollout_inventory_identity_from_stat(stat_result)
    _assert_rollout_inventory_identity(
        actual,
        expected,
        allow_append=allow_append,
        phase=phase,
    )
    if stat.S_ISLNK(actual.mode):
        raise ValueError("rollout path is a symlink")
    if not stat.S_ISREG(actual.mode):
        raise ValueError("rollout path is not a regular file")
    return actual


def _rollout_candidate_identity_from_stat(
    stat_result: os.stat_result,
) -> RolloutCandidateIdentity:
    stable = _stable_rollout_identity_from_stat(stat_result)
    return RolloutCandidateIdentity(
        snapshot=_rollout_identity_from_stat(stat_result),
        stable=stable,
    )


def _capture_rollout_candidate_identity_from_parent_fd(
    parent_fd: int,
    name: str,
    inventory_identity: RolloutInventoryIdentity,
) -> RolloutCandidateIdentity:
    phase = "after enumeration"
    _validated_rollout_inventory_identity_from_parent_fd(
        parent_fd,
        name,
        inventory_identity,
        allow_append=False,
        phase=phase,
    )
    try:
        fd = os.open(name, _regular_file_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ValueError("rollout identity changed during open") from error
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("rollout identity changed during open") from error
        raise
    try:
        descriptor_stat = os.fstat(fd)
        descriptor_inventory_identity = _rollout_inventory_identity_from_stat(
            descriptor_stat
        )
        _assert_rollout_inventory_identity(
            descriptor_inventory_identity,
            inventory_identity,
            allow_append=False,
            phase="during open",
        )
        descriptor_identity = _rollout_candidate_identity_from_stat(descriptor_stat)
        for _ in range(2):
            try:
                path_stat = os.stat(
                    name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as error:
                raise ValueError("rollout identity changed during open") from error
            path_inventory_identity = _rollout_inventory_identity_from_stat(
                path_stat
            )
            _assert_rollout_inventory_identity(
                path_inventory_identity,
                inventory_identity,
                allow_append=False,
                phase="during open",
            )
            path_identity = _rollout_candidate_identity_from_stat(path_stat)
            _assert_rollout_identity(
                path_identity.snapshot,
                descriptor_identity.snapshot,
                phase="during open",
            )
        return descriptor_identity
    finally:
        os.close(fd)


def _assert_rollout_identity(
    actual: RolloutIdentity,
    expected: RolloutIdentity,
    *,
    phase: str,
) -> None:
    if actual != expected:
        raise ValueError(f"rollout identity changed {phase}")


def _assert_append_only_rollout_identity(
    actual: RolloutIdentity,
    expected: RolloutIdentity,
    *,
    phase: str,
) -> None:
    same_file = (
        actual.device == expected.device
        and actual.inode == expected.inode
    )
    unchanged_snapshot = actual.size != expected.size or actual == expected
    if not same_file or actual.size < expected.size or not unchanged_snapshot:
        raise ValueError(f"rollout identity changed {phase}")


def _read_rollout_prefix_proof(
    fd: int,
    length: int,
    *,
    expected_prefix: RolloutPrefixProof | None = None,
    phase: str,
) -> tuple[RolloutPrefixProof, bytes]:
    if length < 0 or length > MAX_SESSION_META_SCAN_BYTES:
        raise ValueError(f"rollout identity changed {phase}")
    if expected_prefix is not None and (
        expected_prefix.length < 0
        or expected_prefix.length > length
        or expected_prefix.length > MAX_SESSION_META_SCAN_BYTES
    ):
        raise ValueError(f"rollout identity changed {phase}")
    digest = hashlib.sha256()
    snapshot = bytearray()
    offset = 0
    verified_length = expected_prefix.length if expected_prefix is not None else 0

    def read_through(target: int) -> None:
        nonlocal offset
        while offset < target:
            requested = min(SESSION_META_READ_CHUNK_BYTES, target - offset)
            chunk = os.pread(fd, requested, offset)
            if not chunk or len(chunk) > requested:
                raise ValueError(f"rollout identity changed {phase}")
            digest.update(chunk)
            snapshot.extend(chunk)
            offset += len(chunk)

    read_through(verified_length)
    if (
        expected_prefix is not None
        and digest.hexdigest() != expected_prefix.sha256
    ):
        raise ValueError(f"rollout identity changed {phase}")
    read_through(length)
    return (
        RolloutPrefixProof(length=length, sha256=digest.hexdigest()),
        bytes(snapshot),
    )


def _capture_active_rollout_candidate_identity_from_parent_fd(
    parent_fd: int,
    name: str,
    inventory_identity: RolloutInventoryIdentity,
) -> RolloutCandidateIdentity:
    phase = "during prefix proof capture"
    observed_inventory_identity = (
        _validated_rollout_inventory_identity_from_parent_fd(
            parent_fd,
            name,
            inventory_identity,
            allow_append=False,
            phase="after enumeration",
        )
    )
    try:
        fd = os.open(name, _regular_file_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ValueError(f"rollout identity changed {phase}") from error
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError(f"rollout identity changed {phase}") from error
        raise
    try:
        initial_stat = os.fstat(fd)
        initial_inventory_identity = _rollout_inventory_identity_from_stat(
            initial_stat
        )
        _assert_rollout_inventory_identity(
            initial_inventory_identity,
            observed_inventory_identity,
            allow_append=False,
            phase=phase,
        )
        initial = _rollout_candidate_identity_from_stat(initial_stat)
        initial_proof, _snapshot = _read_rollout_prefix_proof(
            fd,
            min(initial.snapshot.size, MAX_SESSION_META_SCAN_BYTES),
            phase=phase,
        )
        descriptor_after_proof = _rollout_inventory_identity_from_stat(
            os.fstat(fd)
        )
        _assert_rollout_inventory_identity(
            descriptor_after_proof,
            inventory_identity,
            allow_append=False,
            phase=phase,
        )
        _validated_rollout_inventory_identity_from_parent_fd(
            parent_fd,
            name,
            inventory_identity,
            allow_append=False,
            phase=phase,
        )
        current, _snapshot_identity, proof, _verified_snapshot = (
            _assert_append_only_rollout_checkpoint(
                fd,
                parent_fd,
                name,
                initial.snapshot,
                initial_proof,
                phase=phase,
            )
        )
        return RolloutCandidateIdentity(
            snapshot=current,
            stable=RolloutStableIdentity(
                device=current.device,
                inode=current.inode,
            ),
            prefix_proof=proof,
        )
    finally:
        os.close(fd)


def _assert_append_only_rollout_checkpoint(
    fd: int,
    parent_fd: int,
    name: str,
    expected: RolloutIdentity,
    prefix_proof: RolloutPrefixProof | None,
    *,
    phase: str,
) -> tuple[RolloutIdentity, RolloutIdentity, RolloutPrefixProof, bytes]:
    if prefix_proof is None:
        raise ValueError(f"rollout identity changed {phase}")
    descriptor_identity = _rollout_identity_from_stat(os.fstat(fd))
    _assert_append_only_rollout_identity(
        descriptor_identity,
        expected,
        phase=phase,
    )
    try:
        current = _rollout_identity_from_stat(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
    except (FileNotFoundError, ValueError) as error:
        raise ValueError(f"rollout identity changed {phase}") from error
    _assert_append_only_rollout_identity(current, descriptor_identity, phase=phase)
    advanced_proof, _snapshot = _read_rollout_prefix_proof(
        fd,
        min(current.size, MAX_SESSION_META_SCAN_BYTES),
        expected_prefix=prefix_proof,
        phase=phase,
    )
    descriptor_after = _rollout_identity_from_stat(os.fstat(fd))
    _assert_append_only_rollout_identity(descriptor_after, current, phase=phase)
    try:
        current_after = _rollout_identity_from_stat(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
    except (FileNotFoundError, ValueError) as error:
        raise ValueError(f"rollout identity changed {phase}") from error
    _assert_append_only_rollout_identity(
        current_after,
        descriptor_after,
        phase=phase,
    )
    _verified_proof, verified_snapshot = _read_rollout_prefix_proof(
        fd,
        advanced_proof.length,
        expected_prefix=advanced_proof,
        phase=phase,
    )
    descriptor_final = _rollout_identity_from_stat(os.fstat(fd))
    _assert_append_only_rollout_identity(
        descriptor_final,
        current_after,
        phase=phase,
    )
    try:
        current_final = _rollout_identity_from_stat(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
    except (FileNotFoundError, ValueError) as error:
        raise ValueError(f"rollout identity changed {phase}") from error
    _assert_append_only_rollout_identity(
        current_final,
        descriptor_final,
        phase=phase,
    )
    if current_final != current_after:
        _reverified_proof, verified_snapshot = _read_rollout_prefix_proof(
            fd,
            advanced_proof.length,
            expected_prefix=advanced_proof,
            phase=phase,
        )
        descriptor_reverified = _rollout_identity_from_stat(os.fstat(fd))
        _assert_rollout_identity(
            descriptor_reverified,
            current_final,
            phase=phase,
        )
        try:
            current_reverified = _rollout_identity_from_stat(
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            )
        except (FileNotFoundError, ValueError) as error:
            raise ValueError(f"rollout identity changed {phase}") from error
        _assert_rollout_identity(
            current_reverified,
            current_final,
            phase=phase,
        )
    return current_final, current, advanced_proof, verified_snapshot


def _open_pinned_regular_file_from_fd(
    parent_fd: int,
    name: str,
    *,
    expected_identity: RolloutCandidateIdentity | None = None,
    allow_append: bool = False,
) -> tuple[
    int,
    RolloutIdentity,
    RolloutIdentity | None,
    RolloutPrefixProof | None,
    bytes | None,
]:
    if name in ("", ".", "..") or "/" in name:
        raise ValueError("rollout path has an invalid file name")
    try:
        observed_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        if expected_identity is not None:
            raise ValueError("rollout identity changed after enumeration") from error
        raise
    if stat.S_ISLNK(observed_stat.st_mode):
        raise ValueError("rollout path is a symlink")
    observed = _rollout_identity_from_stat(observed_stat)
    if expected_identity is not None:
        if allow_append:
            _assert_append_only_rollout_identity(
                observed,
                expected_identity.snapshot,
                phase="after enumeration",
            )
        else:
            _assert_rollout_identity(
                observed,
                expected_identity.snapshot,
                phase="after enumeration",
            )
    try:
        fd = os.open(name, _regular_file_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ValueError("rollout changed during open") from error
    try:
        opened_stat = os.fstat(fd)
        opened = _rollout_identity_from_stat(opened_stat)
        if expected_identity is None:
            _assert_rollout_identity(opened, observed, phase="during open")
        elif allow_append:
            current, snapshot_identity, prefix_proof, verified_snapshot = (
                _assert_append_only_rollout_checkpoint(
                    fd,
                    parent_fd,
                    name,
                    observed,
                    expected_identity.prefix_proof,
                    phase="during open",
                )
            )
            return fd, current, snapshot_identity, prefix_proof, verified_snapshot
        else:
            _assert_rollout_identity(
                opened,
                expected_identity.snapshot,
                phase="during open",
            )
        try:
            current_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as error:
            raise ValueError("rollout changed during open") from error
        current = _rollout_identity_from_stat(current_stat)
        if expected_identity is None:
            _assert_rollout_identity(current, opened, phase="during open")
        elif allow_append:
            _assert_append_only_rollout_identity(
                current,
                opened,
                phase="during open",
            )
        else:
            _assert_rollout_identity(
                current,
                expected_identity.snapshot,
                phase="during open",
            )
        return fd, current, None, None, None
    except Exception:
        os.close(fd)
        raise


class _PinnedRolloutHandle:
    def __init__(
        self,
        fd: int,
        parent_fd: int,
        name: str,
        open_identity: RolloutIdentity,
        verified_snapshot_identity: RolloutIdentity | None,
        prefix_proof: RolloutPrefixProof | None,
        verified_snapshot: bytes | None,
    ) -> None:
        try:
            self._handle = os.fdopen(fd, "rb")
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            os.close(parent_fd)
            raise
        self._parent_fd = parent_fd
        self._name = name
        self._open_identity = open_identity
        self._verified_snapshot_identity = verified_snapshot_identity
        self._prefix_proof = prefix_proof
        self._verified_snapshot = verified_snapshot

    def __enter__(self) -> _PinnedRolloutHandle:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)

    def close(self) -> None:
        try:
            close = getattr(self._handle, "close", None)
            if close is not None:
                close()
            else:
                self._handle.__exit__(None, None, None)
        finally:
            if self._parent_fd != -1:
                os.close(self._parent_fd)
                self._parent_fd = -1

    def assert_identity(self, expected: RolloutIdentity, *, phase: str) -> None:
        _assert_rollout_identity(
            _rollout_identity_from_stat(os.fstat(self.fileno())),
            expected,
            phase=phase,
        )
        try:
            current = _rollout_identity_from_stat(
                os.stat(
                    self._name,
                    dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
            )
        except (FileNotFoundError, ValueError) as error:
            raise ValueError(f"rollout identity changed {phase}") from error
        _assert_rollout_identity(current, expected, phase=phase)

    def assert_append_only_identity(
        self,
        expected: RolloutIdentity,
        *,
        phase: str,
    ) -> RolloutIdentity:
        current, snapshot_identity, prefix_proof, verified_snapshot = (
            _assert_append_only_rollout_checkpoint(
                self.fileno(),
                self._parent_fd,
                self._name,
                expected,
                self._prefix_proof,
                phase=phase,
            )
        )
        self._verified_snapshot_identity = snapshot_identity
        self._prefix_proof = prefix_proof
        self._verified_snapshot = verified_snapshot
        return current

    @property
    def open_identity(self) -> RolloutIdentity:
        return self._open_identity

    @property
    def verified_snapshot(self) -> bytes | None:
        return self._verified_snapshot

    @property
    def verified_snapshot_identity(self) -> RolloutIdentity | None:
        return self._verified_snapshot_identity


def _open_pinned_rollout_text_from_parent_fd(
    parent_fd: int,
    name: str,
    *,
    expected_identity: RolloutCandidateIdentity | None = None,
    allow_append: bool = False,
) -> _PinnedRolloutHandle:
    fd, open_identity, snapshot_identity, prefix_proof, verified_snapshot = (
        _open_pinned_regular_file_from_fd(
            parent_fd,
            name,
            expected_identity=expected_identity,
            allow_append=allow_append,
        )
    )
    try:
        pinned_parent_fd = os.dup(parent_fd)
    except Exception:
        os.close(fd)
        raise
    return _PinnedRolloutHandle(
        fd,
        pinned_parent_fd,
        name,
        open_identity,
        snapshot_identity,
        prefix_proof,
        verified_snapshot,
    )


def _open_pinned_rollout_text(
    codex_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
) -> _PinnedRolloutHandle:
    parts = _validate_relative_path_parts(rollout_relative_path)
    if not parts:
        raise ValueError("rollout path must name a file")
    root_fd = _open_pinned_codex_root(codex_root)
    try:
        parent_fd = _open_pinned_directory_from_fd(
            root_fd,
            pathlib.PurePosixPath(*parts[:-1]),
        )
        try:
            return _open_pinned_rollout_text_from_parent_fd(parent_fd, parts[-1])
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


class _HashingReader:
    def __init__(self, handle: BinaryIO) -> None:
        self.handle = handle
        self.hasher = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        data = self.handle.read(size)
        if not isinstance(data, bytes):
            raise TypeError("rollout hashing reader requires binary input")
        self.hasher.update(data)
        self.bytes_read += len(data)
        return data

    def tell(self) -> int:
        return self.handle.tell()

    def hexdigest(self) -> str:
        return self.hasher.hexdigest()


def _open_local_rollout_text(
    codex_root: pathlib.Path | int | EnumeratedRolloutParent,
    rollout_relative_path: pathlib.PurePosixPath,
):
    if isinstance(codex_root, EnumeratedRolloutParent):
        return _open_pinned_rollout_text_from_parent_fd(
            codex_root.fd,
            rollout_relative_path.name,
            expected_identity=codex_root.expected_identity,
            allow_append=codex_root.allow_append,
        )
    if isinstance(codex_root, int):
        return _open_pinned_rollout_text_from_parent_fd(
            codex_root,
            rollout_relative_path.name,
        )
    return _open_pinned_rollout_text(codex_root, rollout_relative_path)


def _file_sha256(path: pathlib.Path) -> str:
    parent_fd = _open_pinned_codex_root(path.parent)
    try:
        try:
            handle = _open_pinned_rollout_text_from_parent_fd(parent_fd, path.name)
        except ValueError as error:
            raise OSError(str(error)) from error
    finally:
        os.close(parent_fd)
    digest = hashlib.sha256()
    with handle:
        identity = _rollout_identity_from_stat(os.fstat(handle.fileno()))
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        handle.assert_identity(identity, phase="after hash")
    return digest.hexdigest()


def _read_local_rollout_bytes(
    codex_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
    *,
    max_bytes: int,
) -> bytes:
    with _open_pinned_rollout_text(codex_root, rollout_relative_path) as handle:
        identity = _rollout_identity_from_stat(os.fstat(handle.fileno()))
        if max_bytes and identity.size > max_bytes:
            raise ValueError(f"rollout too large: {identity.size} bytes > {max_bytes}")
        data = handle.read(identity.size + 1)
        handle.assert_identity(identity, phase="after read")
        if len(data) != identity.size:
            raise ValueError(
                "rollout read did not match snapshot size: "
                f"{len(data)} bytes != {identity.size}"
            )
        return data


def _open_output_parent(output: pathlib.Path) -> int:
    if not output.is_absolute() or output.name in ("", ".", ".."):
        raise ValueError("output path must name an absolute file")
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if directory_flag is None or nofollow_flag is None:
        raise OSError("secure output writes require O_DIRECTORY and O_NOFOLLOW")
    flags = os.O_RDONLY | directory_flag | nofollow_flag | getattr(os, "O_CLOEXEC", 0)
    anchor = pathlib.Path(output.anchor)
    directory_fd = os.open(str(anchor), flags)
    try:
        for part in output.parent.relative_to(anchor).parts:
            if part in ("", ".", ".."):
                raise ValueError("output path has an invalid directory component")
            try:
                next_fd = os.open(part, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _write_private_bytes(output: pathlib.Path, data: bytes) -> None:
    parent_fd = _open_output_parent(output)
    try:
        try:
            target_stat = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target_stat = None
        if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
            raise ValueError("output path exists and is not a regular file")

        last_error: FileExistsError | None = None
        for attempt in range(100):
            temp_name = f".{output.name}.tmp-{os.getpid()}-{attempt}"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            except FileExistsError as error:
                last_error = error
                continue
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    os.fchmod(handle.fileno(), 0o600)
                os.replace(
                    temp_name,
                    output.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                return
            except Exception:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                raise
        raise FileExistsError(
            f"could not create private temporary output for {output}"
        ) from last_error
    finally:
        os.close(parent_fd)


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


def _session_meta_allows_append(
    relative_path: pathlib.PurePosixPath,
) -> bool:
    return len(relative_path.parts) == 1 or relative_path.parts[0] == "sessions"


def _session_meta_record_timestamp(row: dict[str, Any]) -> dt.datetime | None:
    timestamp = row.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        return None
    try:
        return _parse_rollout_bound(timestamp, "session_meta.timestamp")
    except (ValueError, OverflowError):
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


def _session_meta_snapshot_reader(
    identity: RolloutIdentity,
    verified_snapshot: bytes | None,
) -> io.BytesIO:
    phase = "before session-meta scan"
    if (
        verified_snapshot is None
        or len(verified_snapshot) > MAX_SESSION_META_SCAN_BYTES
        or identity.size < len(verified_snapshot)
    ):
        raise ValueError(f"rollout identity changed {phase}")
    source_has_unread_bytes = identity.size > len(verified_snapshot)
    if source_has_unread_bytes and len(verified_snapshot) < MAX_SESSION_META_SCAN_BYTES:
        raise ValueError(f"rollout identity changed {phase}")
    unread_sentinel = b"\0" if source_has_unread_bytes else b""
    return io.BytesIO(verified_snapshot + unread_sentinel)


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


def _decode_session_meta_line(raw_bytes: bytes) -> str:
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("session-meta record is not valid UTF-8") from error


def _parse_session_meta_snapshot(
    scan_handle: Any,
    *,
    date_value: dt.date | None,
    require_record_date_match: bool,
    rollout_start: dt.datetime | None,
    rollout_end: dt.datetime | None,
) -> tuple[dt.date | None, str, str, dt.datetime | None] | None:
    for line in _bounded_session_meta_lines(
        scan_handle,
        MAX_SESSION_META_SCAN_BYTES,
    ):
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(obj, dict):
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
        if not isinstance(payload, dict):
            continue
        session_id_value = payload.get("id")
        if not isinstance(session_id_value, str) or not session_id_value:
            continue
        session_id = session_id_value
        cwd = str(payload.get("cwd", ""))
        return (
            timestamp.date() if timestamp is not None else date_value,
            session_id,
            cwd,
            timestamp,
        )
    return None


def _session_meta_from_rollout(
    codex_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
    *,
    parent_fd: int | None = None,
    expected_identity: RolloutCandidateIdentity | None = None,
    date_value: dt.date | None = None,
    require_record_date_match: bool = False,
    rollout_start: dt.datetime | None = None,
    rollout_end: dt.datetime | None = None,
) -> tuple[dt.date | None, str, str, dt.datetime | None] | None:
    allow_append = _session_meta_allows_append(
        rollout_relative_path
    )
    rollout_source: pathlib.Path | int | EnumeratedRolloutParent
    if parent_fd is not None and expected_identity is not None:
        rollout_source = EnumeratedRolloutParent(
            parent_fd,
            expected_identity,
            allow_append,
        )
    else:
        rollout_source = parent_fd if parent_fd is not None else codex_root
    try:
        handle = _open_local_rollout_text(
            rollout_source,
            rollout_relative_path,
        )
    except FileNotFoundError as error:
        if expected_identity is not None:
            raise SessionMetaRolloutError(
                "rollout identity changed after enumeration",
                rollout=rollout_relative_path.as_posix(),
            ) from error
        return None
    except OSError as exc:
        raise SessionMetaRolloutError(
            "rollout unreadable",
            rollout=rollout_relative_path.as_posix(),
        ) from exc
    except ValueError as exc:
        raise SessionMetaRolloutError(
            str(exc),
            rollout=rollout_relative_path.as_posix(),
        ) from exc
    try:
        with handle:
            if expected_identity is not None and allow_append:
                identity = handle.assert_append_only_identity(
                    handle.open_identity,
                    phase="before session-meta scan",
                )
                snapshot_identity = handle.verified_snapshot_identity
                if snapshot_identity is None:
                    raise ValueError("rollout identity changed before session-meta scan")
                scan_handle = _session_meta_snapshot_reader(
                    snapshot_identity,
                    handle.verified_snapshot,
                )
            else:
                identity = _rollout_identity_from_stat(os.fstat(handle.fileno()))
                scan_handle = handle
            result = _parse_session_meta_snapshot(
                scan_handle,
                date_value=date_value,
                require_record_date_match=require_record_date_match,
                rollout_start=rollout_start,
                rollout_end=rollout_end,
            )
            if expected_identity is None:
                handle.assert_identity(identity, phase="after session-meta scan")
            elif allow_append:
                refreshed_identity = handle.assert_append_only_identity(
                    identity,
                    phase="after session-meta scan",
                )
                refreshed_snapshot_identity = handle.verified_snapshot_identity
                if refreshed_snapshot_identity is None:
                    raise ValueError(
                        "rollout identity changed after session-meta scan"
                    )
                if (
                    result is None
                    and refreshed_snapshot_identity == snapshot_identity
                    and refreshed_identity != refreshed_snapshot_identity
                ):
                    raise ValueError(
                        "rollout identity changed after session-meta scan"
                    )
                if (
                    result is None
                    and refreshed_snapshot_identity != snapshot_identity
                ):
                    result = _parse_session_meta_snapshot(
                        _session_meta_snapshot_reader(
                            refreshed_snapshot_identity,
                            handle.verified_snapshot,
                        ),
                        date_value=date_value,
                        require_record_date_match=require_record_date_match,
                        rollout_start=rollout_start,
                        rollout_end=rollout_end,
                    )
                    final_identity = handle.assert_append_only_identity(
                        refreshed_identity,
                        phase="after refreshed session-meta scan",
                    )
                    final_snapshot_identity = handle.verified_snapshot_identity
                    if final_snapshot_identity is None:
                        raise ValueError(
                            "rollout identity changed after session-meta scan"
                        )
                    if (
                        result is None
                        and (
                            final_snapshot_identity != refreshed_snapshot_identity
                            or final_identity != final_snapshot_identity
                        )
                    ):
                        raise ValueError(
                            "rollout identity changed after session-meta scan"
                        )
            else:
                handle.assert_identity(
                    expected_identity.snapshot,
                    phase="after session-meta scan",
                )
            return result
    except OSError as error:
        raise SessionMetaRolloutError(
            "rollout unreadable",
            rollout=rollout_relative_path.as_posix(),
        ) from error
    except ValueError as error:
        raise SessionMetaRolloutError(
            str(error),
            rollout=rollout_relative_path.as_posix(),
        ) from error


def _session_meta_rollout_sort_key(
    relative_path: pathlib.PurePosixPath,
    cached_timestamp: dt.datetime | None = None,
) -> tuple[dt.datetime, str]:
    window = _rollout_filename_window(relative_path)
    timestamp = cached_timestamp or (window[0] if window is not None else dt.datetime.min.replace(tzinfo=dt.timezone.utc))
    return (timestamp, relative_path.as_posix())


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


def _run_subprocess_text_bounded(
    argv: list[str],
    *,
    input_text: str | None = None,
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> subprocess.CompletedProcess[str]:
    if max_stdout_bytes < 1 or max_stderr_bytes < 1:
        raise ValueError("bounded subprocess output limits must be positive")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"command not found: {argv[0]}") from exc

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    input_bytes = (input_text or "").encode("utf-8")
    input_offset = 0
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    for stream, events, label in (
        (process.stdout, selectors.EVENT_READ, "stdout"),
        (process.stderr, selectors.EVENT_READ, "stderr"),
    ):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, events, label)
    if input_bytes:
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    else:
        process.stdin.close()

    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"command timed out after {timeout_seconds}s")
            for key, _ in selector.select(min(0.25, remaining)):
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(),
                            input_bytes[input_offset : input_offset + 65536],
                        )
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(input_bytes)
                    else:
                        input_offset += written
                    if input_offset >= len(input_bytes):
                        selector.unregister(stream)
                        stream.close()
                    continue

                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer = stdout if key.data == "stdout" else stderr
                limit = max_stdout_bytes if key.data == "stdout" else max_stderr_bytes
                if len(buffer) + len(chunk) > limit:
                    raise RuntimeError(
                        f"command {key.data} exceeded {limit}-byte capture limit"
                    )
                buffer.extend(chunk)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"command timed out after {timeout_seconds}s")
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise RuntimeError(f"command timed out after {timeout_seconds}s") from exc
    except Exception:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()

    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )


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
import errno
import hashlib
import io
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
SESSION_META_READ_CHUNK_BYTES = {SESSION_META_READ_CHUNK_BYTES}
SESSION_META_PREFIX_PROOF_BYTES = {MAX_SESSION_META_SCAN_BYTES}
SESSION_META_CANDIDATE_LIMIT = {MAX_SESSION_META_CANDIDATE_LIMIT}
SESSION_META_SERIALIZED_ROW_BYTES = {MAX_REMOTE_SESSION_META_SERIALIZED_ROW_BYTES}
SESSION_META_OUTPUT_ROW_TOO_LARGE_ERROR = {SESSION_META_OUTPUT_ROW_TOO_LARGE_ERROR!r}
SUMMARY_LIMIT = int(CONFIG.get("summary_limit", 0))
SUMMARY_SCAN_BYTES = int(CONFIG.get("summary_scan_bytes", 0))
SUMMARY_LINE_BYTES = int(CONFIG.get("summary_line_bytes", 0)) or {MAX_ROLLOUT_SUMMARY_LINE_BYTES}
SUMMARY_TAIL_RECORDS = int(CONFIG.get("summary_tail_records", 0))
SUMMARY_MAX_TEXT_CHARS = int(CONFIG.get("summary_max_text_chars", 0))
SUMMARY_MAX_TEXT_CHARS_LIMIT = {MAX_ROLLOUT_SUMMARY_TEXT_CHARS}
ROLLOUT_SUMMARY_SERIALIZED_BYTES = {MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_BYTES}
ROLLOUT_SUMMARY_SERIALIZED_RECORD_BYTES = {MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_RECORD_BYTES}
ROLLOUT_SUMMARY_OUTPUT_TOO_LARGE_ERROR = {ROLLOUT_SUMMARY_OUTPUT_TOO_LARGE_ERROR!r}
SUMMARY_KEYWORDS = [str(value) for value in CONFIG.get("summary_keywords", [])]
ROLLOUT_START = CONFIG.get("rollout_start")
ROLLOUT_END = CONFIG.get("rollout_end")
ROLLOUT_FILENAME_MODE = str(CONFIG.get("rollout_filename_mode", "all"))
ACTIVE_ROLLOUT_RELATIVE_RE = re.compile({ACTIVE_ROLLOUT_RELATIVE_RE.pattern!r})
ARCHIVED_ROLLOUT_RELATIVE_RE = re.compile({ARCHIVED_ROLLOUT_RELATIVE_RE.pattern!r})
ROOT_ROLLOUT_RELATIVE_RE = re.compile({ROOT_ROLLOUT_RELATIVE_RE.pattern!r})
RAW_ROLLOUT_BASENAME_RE = re.compile({RAW_ROLLOUT_BASENAME_RE.pattern!r})
SECURE_ROLLOUT_DIR_FD_SUPPORTED = (
    getattr(os, "O_DIRECTORY", None) is not None
    and getattr(os, "O_NOFOLLOW", None) is not None
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)
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
SUMMARY_SIGNAL_CATEGORY_PATTERNS = {SUMMARY_SIGNAL_CATEGORY_PATTERNS!r}
SUMMARY_SIGNAL_CATEGORY_LABELS = tuple(label for label, _pattern in SUMMARY_SIGNAL_CATEGORY_PATTERNS)
SUMMARY_SIGNAL_CATEGORY_RES = tuple((label, re.compile(pattern, re.I)) for label, pattern in SUMMARY_SIGNAL_CATEGORY_PATTERNS)
SUMMARY_SENSITIVE_SIGNAL_PATTERN_TEXT = {SUMMARY_SENSITIVE_SIGNAL_PATTERN_TEXT!r}
SUMMARY_SENSITIVE_SIGNAL_RE = re.compile(SUMMARY_SENSITIVE_SIGNAL_PATTERN_TEXT, re.I)
REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF = {REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF!r}
REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF = {REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF!r}
SESSION_META_BEGIN = {REMOTE_SESSION_META_BEGIN!r}
SESSION_META_END = {REMOTE_SESSION_META_END!r}
SESSION_META_LIMIT_TRUNCATED_REASON = {SESSION_META_LIMIT_TRUNCATED_REASON!r}
SESSION_META_CANDIDATE_LIMIT_TRUNCATED_REASON = {SESSION_META_CANDIDATE_LIMIT_TRUNCATED_REASON!r}
SESSION_META_FLAT_UNDATED_ALIAS_PREFIX = {SESSION_META_FLAT_UNDATED_ALIAS_PREFIX!r}
FETCH_ROLLOUT_BEGIN = {REMOTE_FETCH_ROLLOUT_BEGIN!r}
FETCH_ROLLOUT_END = {REMOTE_FETCH_ROLLOUT_END!r}
ROLLOUT_SUMMARY_BEGIN = {REMOTE_ROLLOUT_SUMMARY_BEGIN!r}
ROLLOUT_SUMMARY_END = {REMOTE_ROLLOUT_SUMMARY_END!r}


def directory_open_flags():
    if not SECURE_ROLLOUT_DIR_FD_SUPPORTED:
        raise OSError(
            "secure rollout reads require O_DIRECTORY, O_NOFOLLOW, and descriptor-relative open/stat"
        )
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def regular_file_open_flags():
    directory_open_flags()
    nonblocking_flag = getattr(os, "O_NONBLOCK", None)
    if nonblocking_flag is None:
        raise OSError("secure rollout reads require O_NONBLOCK")
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | nonblocking_flag
        | getattr(os, "O_CLOEXEC", 0)
    )


def validate_relative_path_parts(rel):
    if rel.is_absolute():
        raise ValueError("path must stay under Codex root")
    parts = rel.parts
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("path must stay under Codex root")
    return parts


def open_pinned_codex_root():
    root_entry = ROOT.lstat()
    if stat.S_ISLNK(root_entry.st_mode):
        raise ValueError("Codex root is a symlink")
    if not stat.S_ISDIR(root_entry.st_mode):
        raise ValueError("Codex root is not a directory")
    try:
        fd = os.open(str(ROOT), directory_open_flags())
    except FileNotFoundError as error:
        raise ValueError("Codex root changed after initial inspection") from error
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError("Codex root is not a directory")
        if (opened.st_dev, opened.st_ino) != (root_entry.st_dev, root_entry.st_ino):
            raise ValueError("Codex root changed during open")
        return fd
    except Exception:
        os.close(fd)
        raise


def open_pinned_directory_from_fd(root_fd, rel):
    directory_fd = os.dup(root_fd)
    try:
        for part in validate_relative_path_parts(rel):
            observed = os.stat(part, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(observed.st_mode):
                raise ValueError("path uses a symlink ancestor")
            if not stat.S_ISDIR(observed.st_mode):
                raise ValueError("path ancestor is not a directory")
            try:
                next_fd = os.open(part, directory_open_flags(), dir_fd=directory_fd)
            except FileNotFoundError as error:
                raise ValueError("path ancestor changed during open") from error
            try:
                opened = os.fstat(next_fd)
                if not stat.S_ISDIR(opened.st_mode):
                    raise ValueError("path ancestor is not a directory")
                if (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino):
                    raise ValueError("path ancestor changed during open")
            except Exception:
                os.close(next_fd)
                raise
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def rollout_identity_from_stat(stat_result):
    if not stat.S_ISREG(stat_result.st_mode):
        raise ValueError("rollout path is not a regular file")
    return {{
        "size": stat_result.st_size,
        "device": stat_result.st_dev,
        "inode": stat_result.st_ino,
        "mtime_ns": stat_result.st_mtime_ns,
        "ctime_ns": stat_result.st_ctime_ns,
    }}


def stable_rollout_identity_from_stat(stat_result):
    if stat.S_ISLNK(stat_result.st_mode):
        raise ValueError("rollout path is a symlink")
    if not stat.S_ISREG(stat_result.st_mode):
        raise ValueError("rollout path is not a regular file")
    return {{
        "device": stat_result.st_dev,
        "inode": stat_result.st_ino,
    }}


def rollout_inventory_identity_from_stat(stat_result):
    return {{
        "mode": stat_result.st_mode,
        "size": stat_result.st_size,
        "device": stat_result.st_dev,
        "inode": stat_result.st_ino,
        "mtime_ns": stat_result.st_mtime_ns,
        "ctime_ns": stat_result.st_ctime_ns,
    }}


def capture_rollout_inventory_identity_from_parent_fd(parent_fd, name):
    try:
        stat_result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError("rollout identity changed during enumeration") from error
    return rollout_inventory_identity_from_stat(stat_result)


def assert_rollout_inventory_identity(
    actual,
    expected,
    allow_append,
    phase,
):
    if allow_append:
        same_file = (
            actual["device"] == expected["device"]
            and actual["inode"] == expected["inode"]
        )
        unchanged_snapshot = actual["size"] != expected["size"] or actual == expected
        matches = (
            same_file
            and actual["size"] >= expected["size"]
            and unchanged_snapshot
        )
    else:
        matches = actual == expected
    if not matches:
        raise ValueError("rollout identity changed " + phase)


def validated_rollout_inventory_identity_from_parent_fd(
    parent_fd,
    name,
    expected,
    allow_append,
    phase,
):
    try:
        stat_result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError("rollout identity changed " + phase) from error
    actual = rollout_inventory_identity_from_stat(stat_result)
    assert_rollout_inventory_identity(
        actual,
        expected,
        allow_append,
        phase,
    )
    if stat.S_ISLNK(actual["mode"]):
        raise ValueError("rollout path is a symlink")
    if not stat.S_ISREG(actual["mode"]):
        raise ValueError("rollout path is not a regular file")
    return actual


def rollout_candidate_identity_from_stat(stat_result, prefix_proof=None):
    stable = stable_rollout_identity_from_stat(stat_result)
    return {{
        "snapshot": rollout_identity_from_stat(stat_result),
        "stable": stable,
        "prefix_proof": prefix_proof,
    }}


def capture_rollout_candidate_identity_from_parent_fd(
    parent_fd,
    name,
    inventory_identity,
):
    phase = "after enumeration"
    validated_rollout_inventory_identity_from_parent_fd(
        parent_fd,
        name,
        inventory_identity,
        False,
        phase,
    )
    try:
        fd = os.open(name, regular_file_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ValueError("rollout identity changed during open") from error
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("rollout identity changed during open") from error
        raise
    try:
        descriptor_stat = os.fstat(fd)
        descriptor_inventory_identity = rollout_inventory_identity_from_stat(
            descriptor_stat
        )
        assert_rollout_inventory_identity(
            descriptor_inventory_identity,
            inventory_identity,
            False,
            "during open",
        )
        descriptor_identity = rollout_candidate_identity_from_stat(descriptor_stat)
        for _ in range(2):
            try:
                path_stat = os.stat(
                    name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as error:
                raise ValueError("rollout identity changed during open") from error
            path_inventory_identity = rollout_inventory_identity_from_stat(path_stat)
            assert_rollout_inventory_identity(
                path_inventory_identity,
                inventory_identity,
                False,
                "during open",
            )
            path_identity = rollout_candidate_identity_from_stat(path_stat)
            assert_rollout_identity(
                path_identity["snapshot"],
                descriptor_identity["snapshot"],
                "during open",
            )
        return descriptor_identity
    finally:
        os.close(fd)


def assert_rollout_identity(actual, expected, phase):
    if actual != expected:
        raise ValueError("rollout identity changed " + phase)


def assert_append_only_rollout_identity(actual, expected, phase):
    same_file = (
        actual["device"] == expected["device"]
        and actual["inode"] == expected["inode"]
    )
    unchanged_snapshot = actual["size"] != expected["size"] or actual == expected
    if not same_file or actual["size"] < expected["size"] or not unchanged_snapshot:
        raise ValueError("rollout identity changed " + phase)


def read_rollout_prefix_proof(
    fd,
    length,
    expected_prefix=None,
    phase="during prefix proof capture",
):
    if length < 0 or length > SESSION_META_PREFIX_PROOF_BYTES:
        raise ValueError("rollout identity changed " + phase)
    if expected_prefix is not None and (
        expected_prefix["length"] < 0
        or expected_prefix["length"] > length
        or expected_prefix["length"] > SESSION_META_PREFIX_PROOF_BYTES
    ):
        raise ValueError("rollout identity changed " + phase)
    digest = hashlib.sha256()
    snapshot = bytearray()
    offset = 0
    verified_length = expected_prefix["length"] if expected_prefix is not None else 0

    def read_through(target):
        nonlocal offset
        while offset < target:
            requested = min(SESSION_META_READ_CHUNK_BYTES, target - offset)
            chunk = os.pread(fd, requested, offset)
            if not chunk or len(chunk) > requested:
                raise ValueError("rollout identity changed " + phase)
            digest.update(chunk)
            snapshot.extend(chunk)
            offset += len(chunk)

    read_through(verified_length)
    if (
        expected_prefix is not None
        and digest.hexdigest() != expected_prefix["sha256"]
    ):
        raise ValueError("rollout identity changed " + phase)
    read_through(length)
    return (
        {{"length": length, "sha256": digest.hexdigest()}},
        bytes(snapshot),
    )


def capture_active_rollout_candidate_identity_from_parent_fd(
    parent_fd,
    name,
    inventory_identity,
):
    phase = "during prefix proof capture"
    observed_inventory_identity = (
        validated_rollout_inventory_identity_from_parent_fd(
            parent_fd,
            name,
            inventory_identity,
            False,
            "after enumeration",
        )
    )
    try:
        fd = os.open(name, regular_file_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ValueError("rollout identity changed " + phase) from error
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("rollout identity changed " + phase) from error
        raise
    try:
        initial_stat = os.fstat(fd)
        initial_inventory_identity = rollout_inventory_identity_from_stat(
            initial_stat
        )
        assert_rollout_inventory_identity(
            initial_inventory_identity,
            observed_inventory_identity,
            False,
            phase,
        )
        initial = rollout_candidate_identity_from_stat(initial_stat)
        initial_proof, _snapshot = read_rollout_prefix_proof(
            fd,
            min(initial["snapshot"]["size"], SESSION_META_PREFIX_PROOF_BYTES),
            phase=phase,
        )
        descriptor_after_proof = rollout_inventory_identity_from_stat(os.fstat(fd))
        assert_rollout_inventory_identity(
            descriptor_after_proof,
            inventory_identity,
            False,
            phase,
        )
        validated_rollout_inventory_identity_from_parent_fd(
            parent_fd,
            name,
            inventory_identity,
            False,
            phase,
        )
        current, _snapshot_identity, proof, _verified_snapshot = (
            assert_append_only_rollout_checkpoint(
                fd,
                parent_fd,
                name,
                initial["snapshot"],
                initial_proof,
                phase,
            )
        )
        return {{
            "snapshot": current,
            "stable": {{
                "device": current["device"],
                "inode": current["inode"],
            }},
            "prefix_proof": proof,
        }}
    finally:
        os.close(fd)


def assert_append_only_rollout_checkpoint(
    fd,
    parent_fd,
    name,
    expected,
    prefix_proof,
    phase,
):
    if prefix_proof is None:
        raise ValueError("rollout identity changed " + phase)
    descriptor_identity = rollout_identity_from_stat(os.fstat(fd))
    assert_append_only_rollout_identity(descriptor_identity, expected, phase)
    try:
        current = rollout_identity_from_stat(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
    except (FileNotFoundError, ValueError) as error:
        raise ValueError("rollout identity changed " + phase) from error
    assert_append_only_rollout_identity(current, descriptor_identity, phase)
    advanced_proof, _snapshot = read_rollout_prefix_proof(
        fd,
        min(current["size"], SESSION_META_PREFIX_PROOF_BYTES),
        expected_prefix=prefix_proof,
        phase=phase,
    )
    descriptor_after = rollout_identity_from_stat(os.fstat(fd))
    assert_append_only_rollout_identity(descriptor_after, current, phase)
    try:
        current_after = rollout_identity_from_stat(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
    except (FileNotFoundError, ValueError) as error:
        raise ValueError("rollout identity changed " + phase) from error
    assert_append_only_rollout_identity(current_after, descriptor_after, phase)
    _verified_proof, verified_snapshot = read_rollout_prefix_proof(
        fd,
        advanced_proof["length"],
        expected_prefix=advanced_proof,
        phase=phase,
    )
    descriptor_final = rollout_identity_from_stat(os.fstat(fd))
    assert_append_only_rollout_identity(descriptor_final, current_after, phase)
    try:
        current_final = rollout_identity_from_stat(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
    except (FileNotFoundError, ValueError) as error:
        raise ValueError("rollout identity changed " + phase) from error
    assert_append_only_rollout_identity(current_final, descriptor_final, phase)
    if current_final != current_after:
        _reverified_proof, verified_snapshot = read_rollout_prefix_proof(
            fd,
            advanced_proof["length"],
            expected_prefix=advanced_proof,
            phase=phase,
        )
        descriptor_reverified = rollout_identity_from_stat(os.fstat(fd))
        assert_rollout_identity(descriptor_reverified, current_final, phase)
        try:
            current_reverified = rollout_identity_from_stat(
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            )
        except (FileNotFoundError, ValueError) as error:
            raise ValueError("rollout identity changed " + phase) from error
        assert_rollout_identity(current_reverified, current_final, phase)
    return current_final, current, advanced_proof, verified_snapshot


def open_pinned_regular_file_from_fd(
    parent_fd,
    name,
    expected_identity=None,
    allow_append=False,
):
    if name in ("", ".", "..") or "/" in name:
        raise ValueError("rollout path has an invalid file name")
    try:
        observed_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as error:
        if expected_identity is not None:
            raise ValueError("rollout identity changed after enumeration") from error
        raise
    if stat.S_ISLNK(observed_stat.st_mode):
        raise ValueError("rollout path is a symlink")
    observed = rollout_identity_from_stat(observed_stat)
    if expected_identity is not None:
        if allow_append:
            assert_append_only_rollout_identity(
                observed,
                expected_identity["snapshot"],
                "after enumeration",
            )
        else:
            assert_rollout_identity(
                observed,
                expected_identity["snapshot"],
                "after enumeration",
            )
    try:
        fd = os.open(name, regular_file_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ValueError("rollout changed during open") from error
    try:
        opened_stat = os.fstat(fd)
        opened = rollout_identity_from_stat(opened_stat)
        if expected_identity is None:
            assert_rollout_identity(opened, observed, "during open")
        elif allow_append:
            current, snapshot_identity, prefix_proof, verified_snapshot = (
                assert_append_only_rollout_checkpoint(
                    fd,
                    parent_fd,
                    name,
                    observed,
                    expected_identity["prefix_proof"],
                    "during open",
                )
            )
            return fd, current, snapshot_identity, prefix_proof, verified_snapshot
        else:
            assert_rollout_identity(
                opened,
                expected_identity["snapshot"],
                "during open",
            )
        try:
            current_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as error:
            raise ValueError("rollout changed during open") from error
        current = rollout_identity_from_stat(current_stat)
        if expected_identity is None:
            assert_rollout_identity(current, opened, "during open")
        elif allow_append:
            assert_append_only_rollout_identity(
                current,
                opened,
                "during open",
            )
        else:
            assert_rollout_identity(
                current,
                expected_identity["snapshot"],
                "during open",
            )
        return fd, current, None, None, None
    except Exception:
        os.close(fd)
        raise


class PinnedRolloutHandle:
    def __init__(
        self,
        fd,
        parent_fd,
        name,
        open_identity,
        verified_snapshot_identity,
        prefix_proof,
        verified_snapshot,
    ):
        try:
            self.handle = os.fdopen(fd, "rb")
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            os.close(parent_fd)
            raise
        self.parent_fd = parent_fd
        self.name = name
        self.open_identity = open_identity
        self.verified_snapshot_identity = verified_snapshot_identity
        self.prefix_proof = prefix_proof
        self.verified_snapshot = verified_snapshot

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getattr__(self, name):
        return getattr(self.handle, name)

    def close(self):
        try:
            close = getattr(self.handle, "close", None)
            if close is not None:
                close()
            else:
                self.handle.__exit__(None, None, None)
        finally:
            if self.parent_fd != -1:
                os.close(self.parent_fd)
                self.parent_fd = -1

    def assert_identity(self, expected, phase):
        assert_rollout_identity(
            rollout_identity_from_stat(os.fstat(self.fileno())),
            expected,
            phase,
        )
        try:
            current = rollout_identity_from_stat(
                os.stat(
                    self.name,
                    dir_fd=self.parent_fd,
                    follow_symlinks=False,
                )
            )
        except (FileNotFoundError, ValueError) as error:
            raise ValueError("rollout identity changed " + phase) from error
        assert_rollout_identity(current, expected, phase)

    def assert_append_only_identity(self, expected, phase):
        current, snapshot_identity, prefix_proof, verified_snapshot = (
            assert_append_only_rollout_checkpoint(
                self.fileno(),
                self.parent_fd,
                self.name,
                expected,
                self.prefix_proof,
                phase,
            )
        )
        self.verified_snapshot_identity = snapshot_identity
        self.prefix_proof = prefix_proof
        self.verified_snapshot = verified_snapshot
        return current


def open_pinned_rollout_text_from_parent_fd(
    parent_fd,
    name,
    expected_identity=None,
    allow_append=False,
):
    fd, open_identity, snapshot_identity, prefix_proof, verified_snapshot = (
        open_pinned_regular_file_from_fd(
            parent_fd,
            name,
            expected_identity=expected_identity,
            allow_append=allow_append,
        )
    )
    try:
        pinned_parent_fd = os.dup(parent_fd)
    except Exception:
        os.close(fd)
        raise
    return PinnedRolloutHandle(
        fd,
        pinned_parent_fd,
        name,
        open_identity,
        snapshot_identity,
        prefix_proof,
        verified_snapshot,
    )


def open_pinned_rollout_text(rel):
    parts = validate_relative_path_parts(rel)
    if not parts:
        raise ValueError("rollout path must name a file")
    root_fd = open_pinned_codex_root()
    try:
        parent_fd = open_pinned_directory_from_fd(
            root_fd,
            pathlib.PurePosixPath(*parts[:-1]),
        )
        try:
            return open_pinned_rollout_text_from_parent_fd(parent_fd, parts[-1])
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


class HashingReader:
    def __init__(self, handle):
        self.handle = handle
        self.hasher = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size=-1):
        data = self.handle.read(size)
        if not isinstance(data, bytes):
            raise TypeError("rollout hashing reader requires binary input")
        self.hasher.update(data)
        self.bytes_read += len(data)
        return data

    def tell(self):
        return self.handle.tell()

    def hexdigest(self):
        return self.hasher.hexdigest()


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


def open_rollout_text(
    rel,
    parent_fd=None,
    expected_identity=None,
    allow_append=False,
):
    if parent_fd is not None:
        return open_pinned_rollout_text_from_parent_fd(
            parent_fd,
            rel.name,
            expected_identity=expected_identity,
            allow_append=allow_append,
        )
    return open_pinned_rollout_text(rel)


def read_rollout_bytes(rel, max_bytes):
    with open_pinned_rollout_text(rel) as handle:
        identity = rollout_identity_from_stat(os.fstat(handle.fileno()))
        if max_bytes and identity["size"] > max_bytes:
            raise ValueError("rollout too large: " + str(identity["size"]) + " bytes > " + str(max_bytes))
        data = handle.read(identity["size"] + 1)
        handle.assert_identity(identity, "after read")
        if len(data) != identity["size"]:
            raise ValueError("rollout read did not match snapshot size")
        return identity["size"], data


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


def session_meta_allows_append(rel):
    return len(rel.parts) == 1 or rel.parts[0] == "sessions"


def session_meta_record_timestamp(row):
    timestamp = row.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        return None
    try:
        return parse_config_time(timestamp)
    except (ValueError, OverflowError):
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


def session_meta_snapshot_reader(identity, verified_snapshot):
    phase = "before session-meta scan"
    if (
        verified_snapshot is None
        or len(verified_snapshot) > SESSION_META_PREFIX_PROOF_BYTES
        or identity["size"] < len(verified_snapshot)
    ):
        raise ValueError("rollout identity changed " + phase)
    source_has_unread_bytes = identity["size"] > len(verified_snapshot)
    if (
        source_has_unread_bytes
        and len(verified_snapshot) < SESSION_META_PREFIX_PROOF_BYTES
    ):
        raise ValueError("rollout identity changed " + phase)
    unread_sentinel = b"\\0" if source_has_unread_bytes else b""
    return io.BytesIO(verified_snapshot + unread_sentinel)


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


def decode_session_meta_line(raw_bytes):
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("session-meta record is not valid UTF-8") from error


def parse_session_meta_snapshot(
    scan_handle,
    date_text,
    require_record_date_match,
):
    for line in bounded_session_meta_lines(
        scan_handle,
        SESSION_META_SCAN_BYTES,
    ):
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(obj, dict):
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
        if not isinstance(payload, dict):
            continue
        session_id_value = payload.get("id")
        if not isinstance(session_id_value, str) or not session_id_value:
            continue
        session_id = session_id_value
        cwd = str(payload.get("cwd", ""))
        if timestamp is None:
            meta_date = date_text
        else:
            meta_date = timestamp.strftime("%Y/%m/%d")
        return (meta_date, session_id, cwd, timestamp)
    return None


def emit_session_meta_item(item):
    serialized = json.dumps(item, separators=(",", ":"), sort_keys=True)
    if len(serialized.encode("utf-8")) > SESSION_META_SERIALIZED_ROW_BYTES:
        print(json.dumps({{"kind": "error", "error": SESSION_META_OUTPUT_ROW_TOO_LARGE_ERROR}}, separators=(",", ":"), sort_keys=True))
        return False
    print(serialized)
    return True


def session_meta_from_rollout(
    parent_fd,
    rel,
    expected_identity=None,
    date_text=None,
    require_record_date_match=False,
):
    allow_append = session_meta_allows_append(rel)
    try:
        handle = open_rollout_text(
            rel,
            parent_fd=parent_fd,
            expected_identity=expected_identity,
            allow_append=allow_append,
        )
    except FileNotFoundError:
        if expected_identity is not None:
            emit_session_meta_item({{"kind": "error", "error": "rollout identity changed after enumeration", "rollout": rel.as_posix()}})
            print(SESSION_META_END)
            raise SystemExit(0)
        return None
    except OSError:
        emit_session_meta_item({{"kind": "error", "error": "rollout unreadable", "rollout": rel.as_posix()}})
        print(SESSION_META_END)
        raise SystemExit(0)
    except ValueError as error:
        emit_session_meta_item({{"kind": "error", "error": str(error), "rollout": rel.as_posix()}})
        print(SESSION_META_END)
        raise SystemExit(0)
    try:
        with handle:
            if expected_identity is not None and allow_append:
                identity = handle.assert_append_only_identity(
                    handle.open_identity,
                    "before session-meta scan",
                )
                snapshot_identity = handle.verified_snapshot_identity
                if snapshot_identity is None:
                    raise ValueError("rollout identity changed before session-meta scan")
                scan_handle = session_meta_snapshot_reader(
                    snapshot_identity,
                    handle.verified_snapshot,
                )
            else:
                identity = rollout_identity_from_stat(os.fstat(handle.fileno()))
                scan_handle = handle
            result = parse_session_meta_snapshot(
                scan_handle,
                date_text,
                require_record_date_match,
            )
            if expected_identity is None:
                handle.assert_identity(identity, "after session-meta scan")
            elif allow_append:
                refreshed_identity = handle.assert_append_only_identity(
                    identity,
                    "after session-meta scan",
                )
                refreshed_snapshot_identity = handle.verified_snapshot_identity
                if refreshed_snapshot_identity is None:
                    raise ValueError(
                        "rollout identity changed after session-meta scan"
                    )
                if (
                    result is None
                    and refreshed_snapshot_identity == snapshot_identity
                    and refreshed_identity != refreshed_snapshot_identity
                ):
                    raise ValueError(
                        "rollout identity changed after session-meta scan"
                    )
                if (
                    result is None
                    and refreshed_snapshot_identity != snapshot_identity
                ):
                    result = parse_session_meta_snapshot(
                        session_meta_snapshot_reader(
                            refreshed_snapshot_identity,
                            handle.verified_snapshot,
                        ),
                        date_text,
                        require_record_date_match,
                    )
                    final_identity = handle.assert_append_only_identity(
                        refreshed_identity,
                        "after refreshed session-meta scan",
                    )
                    final_snapshot_identity = handle.verified_snapshot_identity
                    if final_snapshot_identity is None:
                        raise ValueError(
                            "rollout identity changed after session-meta scan"
                        )
                    if (
                        result is None
                        and (
                            final_snapshot_identity != refreshed_snapshot_identity
                            or final_identity != final_snapshot_identity
                        )
                    ):
                        raise ValueError(
                            "rollout identity changed after session-meta scan"
                        )
            else:
                handle.assert_identity(
                    expected_identity["snapshot"],
                    "after session-meta scan",
                )
            return result
    except OSError:
        emit_session_meta_item({{"kind": "error", "error": "rollout unreadable", "rollout": rel.as_posix()}})
        print(SESSION_META_END)
        raise SystemExit(0)
    except ValueError as error:
        emit_session_meta_item({{"kind": "error", "error": str(error), "rollout": rel.as_posix()}})
        print(SESSION_META_END)
        raise SystemExit(0)


def session_meta_rollout_sort_key(rel, cached_timestamp=None):
    window = rollout_filename_window(rel)
    timestamp = cached_timestamp or (window[0] if window is not None else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
    return (timestamp, rel.as_posix())


def normalize_text(text, max_chars):
    collapsed = " ".join(str(text).replace("\\r", "\\n").split())
    if max_chars and max_chars > 3 and len(collapsed) > max_chars:
        return collapsed[: max_chars - 3] + "..."
    return collapsed


def message_content_is_valid(content):
    if not isinstance(content, list):
        return False
    for item in content:
        if not isinstance(item, dict):
            return False
        item_type = item.get("type")
        if not isinstance(item_type, str):
            return False
        if item_type in ("input_text", "output_text", "text") and not isinstance(item.get("text"), str):
            return False
    return True


def message_payload_is_valid(payload):
    role = payload.get("role")
    return (
        isinstance(role, str)
        and role in ("assistant", "developer", "system", "user")
        and message_content_is_valid(payload.get("content"))
    )


def message_summary_from_payload(payload):
    role = str(payload.get("role", ""))
    if role not in ("assistant", "user"):
        return None, None
    parts = []
    for item in payload.get("content", []):
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if not isinstance(item_type, str):
            continue
        if item_type not in ("input_text", "output_text", "text"):
            continue
        text = item.get("text")
        if isinstance(text, str) and text:
            parts.append(text)
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
    return summary_pattern_search(re.compile(pattern, flags), text)


def summary_pattern_search(pattern, text):
    return any(pattern.search(chunk) for chunk in summary_signal_chunks(text))


def summary_category_signals(chunks):
    matched = set()
    for label, pattern in SUMMARY_SIGNAL_CATEGORY_RES:
        for chunk in chunks:
            if pattern.search(chunk):
                matched.add(label)
                break
        if len(matched) == len(SUMMARY_SIGNAL_CATEGORY_LABELS):
            break
    return [label for label in SUMMARY_SIGNAL_CATEGORY_LABELS if label in matched]


def summary_has_sensitive_signal_chunks(chunks):
    return any(SUMMARY_SENSITIVE_SIGNAL_RE.search(chunk) for chunk in chunks)


def summary_has_sensitive_signal(text):
    return summary_has_sensitive_signal_chunks(tuple(summary_signal_chunks(text)))


def summary_signal_text(kind, text):
    chunks = tuple(summary_signal_chunks(text))
    signals = summary_category_signals(chunks)
    if summary_has_sensitive_signal_chunks(chunks):
        signals.append("secret")
    return " ".join(signals) if signals else kind.replace("_", " ") + " present"


def safe_summary_text(kind, text):
    return summary_signal_text(kind, str(text))


def summary_matches_keywords(text, search_keywords):
    if not search_keywords:
        return False
    normalized = normalize_text(text, 0).casefold()
    return any(keyword in normalized for keyword in search_keywords)


def event_user_message_text(payload):
    message_present = "message" in payload
    message = payload.get("message")
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, dict):
        kind, text = message_summary_from_payload(message)
        if kind == "user_message" and text:
            return text.strip()
    if not message_present:
        text = payload.get("text")
        if isinstance(text, str):
            return text.strip()
    return ""


def summary_record(kind, text, *, line_no, timestamp, session_id="", search_keywords=()):
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
    if summary_matches_keywords(signal_text, search_keywords):
        record["_keyword_matched"] = True
    return record


def summary_record_has_signal(record):
    if record is None or str(record.get("kind", "")) in ("session_meta", "scan_meta"):
        return False
    text = str(record.get("text", ""))
    return any(marker in text for marker in SUMMARY_SIGNAL_MARKERS)


def bounded_session_meta_lines(handle, max_scan_bytes):
    if max_scan_bytes < 1:
        raise ValueError("session metadata scan budget must be positive")
    try:
        file_descriptor = handle.fileno()
    except (AttributeError, OSError, ValueError):
        file_descriptor = None
    scanned = 0
    buffer = bytearray()
    buffer_offset = 0
    while True:
        remaining = max_scan_bytes - scanned
        if remaining <= 0:
            return
        read_size = min(SESSION_META_READ_CHUNK_BYTES, remaining)
        chunk = os.read(file_descriptor, read_size) if file_descriptor is not None else handle.read(read_size)
        if not chunk:
            if buffer:
                yield decode_session_meta_line(bytes(buffer))
            return
        raw_bytes = chunk.encode("utf-8", "surrogatepass") if isinstance(chunk, str) else bytes(chunk)
        if len(raw_bytes) > read_size:
            raise ValueError("session metadata reader exceeded requested byte count")
        scanned += len(raw_bytes)
        buffer.extend(raw_bytes)
        cap_has_unread_bytes = False
        if scanned == max_scan_bytes:
            try:
                if file_descriptor is not None:
                    position = os.lseek(file_descriptor, 0, os.SEEK_CUR)
                    cap_has_unread_bytes = os.fstat(file_descriptor).st_size > position
                else:
                    cap_has_unread_bytes = len(handle.getbuffer()) > handle.tell()
            except (AttributeError, OSError, TypeError, ValueError):
                cap_has_unread_bytes = True
        while True:
            line_end = buffer.find(b"\\n")
            if line_end < 0:
                break
            line_size = line_end + 1
            absolute_line_end = buffer_offset + line_size
            if cap_has_unread_bytes and absolute_line_end == max_scan_bytes:
                raise ValueError("session metadata scan truncated at " + str(max_scan_bytes) + " bytes")
            line = bytes(buffer[:line_size])
            del buffer[:line_size]
            buffer_offset = absolute_line_end
            yield decode_session_meta_line(line)
        if scanned == max_scan_bytes:
            if cap_has_unread_bytes:
                raise ValueError("session metadata scan truncated at " + str(max_scan_bytes) + " bytes")
            if buffer:
                yield decode_session_meta_line(bytes(buffer))
            return


def decode_summary_line(raw_bytes):
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return "\\n"


def bounded_text_lines(handle, max_scan_bytes, source_size):
    try:
        start_offset = handle.tell()
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise ValueError("rollout summary reader offset is unavailable") from error
    if (
        isinstance(start_offset, bool)
        or not isinstance(start_offset, int)
        or start_offset < 0
        or start_offset > source_size
    ):
        raise ValueError("rollout summary reader offset is invalid")
    if start_offset != 0:
        raise ValueError("rollout summary reader must start at byte 0")
    scanned = 0
    buffer = bytearray()
    dropping_oversized_line = False
    chunk_bytes = 64 * 1024
    scan_limit = min(max_scan_bytes, source_size) if max_scan_bytes else source_size

    while scanned < scan_limit:
        read_size = min(chunk_bytes, scan_limit - scanned)
        chunk = handle.read(read_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            raw_bytes = chunk.encode("utf-8", "surrogatepass")
        else:
            raw_bytes = bytes(chunk)
        scanned += len(raw_bytes)
        offset = 0
        while offset < len(raw_bytes):
            line_end = raw_bytes.find(b"\\n", offset)
            part_end = len(raw_bytes) if line_end < 0 else line_end + 1
            part = raw_bytes[offset:part_end]
            if dropping_oversized_line:
                if line_end >= 0:
                    yield "\\n"
                    dropping_oversized_line = False
            elif len(buffer) + len(part) > SUMMARY_LINE_BYTES:
                buffer.clear()
                dropping_oversized_line = True
                if line_end >= 0:
                    yield "\\n"
                    dropping_oversized_line = False
            else:
                buffer.extend(part)
                if line_end >= 0:
                    yield decode_summary_line(bytes(buffer))
                    buffer.clear()
            offset = part_end

    if scanned == source_size:
        if dropping_oversized_line:
            yield "\\n"
        elif buffer:
            yield decode_summary_line(bytes(buffer))


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
        handle = open_rollout_text(rel)
        try:
            identity = rollout_identity_from_stat(os.fstat(handle.fileno()))
            handle.assert_identity(identity, "before summary scan")
        except Exception:
            handle.close()
            raise
    except FileNotFoundError:
        print(json.dumps({{"ok": False, "error": "rollout not found"}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    except OSError:
        print(json.dumps({{"ok": False, "error": "rollout unreadable"}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    except ValueError as error:
        print(json.dumps({{"ok": False, "error": str(error)}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    target_size = identity["size"]
    effective_summary_scan_bytes = SUMMARY_SCAN_BYTES or target_size
    hashing_reader = HashingReader(handle)
    with handle:
        for line_no, line in enumerate(
            bounded_text_lines(hashing_reader, effective_summary_scan_bytes, target_size),
            1,
        ):
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError):
                json_error_count += 1
                continue
            if not isinstance(obj, dict):
                json_error_count += 1
                continue
            timestamp_value = obj.get("timestamp")
            if "timestamp" in obj and not isinstance(timestamp_value, str):
                json_error_count += 1
                continue
            timestamp = timestamp_value if isinstance(timestamp_value, str) else ""
            record = None
            record_type = obj.get("type")
            if not isinstance(record_type, str):
                json_error_count += 1
                continue
            payload = obj.get("payload")
            if record_type in ("session_meta", "response_item", "event_msg") and not isinstance(payload, dict):
                json_error_count += 1
                continue
            if record_type == "session_meta":
                session_id_value = payload.get("id")
                if not isinstance(session_id_value, str) or not session_id_value:
                    json_error_count += 1
                    continue
                cwd_value = payload.get("cwd")
                if "cwd" in payload and not isinstance(cwd_value, str):
                    json_error_count += 1
                    continue
                cwd_present = isinstance(cwd_value, str) and bool(cwd_value)
                if session_meta_record is None:
                    record = summary_record(
                        "session_meta",
                        "session_id=" + session_id_value
                        + " cwd_present="
                        + str(cwd_present).lower(),
                        line_no=line_no,
                        timestamp=timestamp,
                        session_id=session_id_value,
                        search_keywords=keywords,
                    )
                    session_meta_record = record
                continue
            elif record_type == "response_item":
                payload_type = payload.get("type")
                if not isinstance(payload_type, str):
                    json_error_count += 1
                    continue
                if payload_type == "message":
                    if not message_payload_is_valid(payload):
                        json_error_count += 1
                        continue
                    kind, text = message_summary_from_payload(payload)
                    if text:
                        record = summary_record(
                            kind,
                            text,
                            line_no=line_no,
                            timestamp=timestamp,
                            search_keywords=keywords,
                        )
                        if kind == "assistant_message":
                            last_assistant_record = record
                        elif kind == "user_message" and record is not None:
                            last_user_record = record
                elif payload_type == "function_call_output":
                    output = payload.get("output")
                    if not isinstance(output, str):
                        json_error_count += 1
                        continue
                    if output.strip():
                        record = summary_record(
                            "function_call_output",
                            output,
                            line_no=line_no,
                            timestamp=timestamp,
                            search_keywords=keywords,
                        )
            elif record_type == "event_msg":
                payload_type = payload.get("type")
                if not isinstance(payload_type, str):
                    json_error_count += 1
                    continue
                if payload_type == "task_complete":
                    text = payload.get("last_agent_message")
                    if not isinstance(text, str):
                        json_error_count += 1
                        continue
                    if text.strip():
                        record = summary_record(
                            "task_complete",
                            text,
                            line_no=line_no,
                            timestamp=timestamp,
                            search_keywords=keywords,
                        )
                        last_task_complete_record = record
                elif payload_type == "user_message":
                    message = payload.get("message")
                    if "message" in payload:
                        if isinstance(message, dict):
                            if message.get("role") != "user" or not message_content_is_valid(
                                message.get("content")
                            ):
                                json_error_count += 1
                                continue
                        elif not isinstance(message, str):
                            json_error_count += 1
                            continue
                    elif not isinstance(payload.get("text"), str):
                        json_error_count += 1
                        continue
                    text = event_user_message_text(payload)
                    if text:
                        record = summary_record(
                            "user_message",
                            text,
                            line_no=line_no,
                            timestamp=timestamp,
                            search_keywords=keywords,
                        )
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

            if keywords and record.get("_keyword_matched") is True:
                key = (str(record.get("kind", "")), int(record.get("line", 0)))
                if key not in matched_seen:
                    if not SUMMARY_LIMIT or len(matched) < SUMMARY_LIMIT:
                        matched.append(record)
                        matched_seen.add(key)
                    else:
                        matched_record_limit_reached = True
            if SUMMARY_TAIL_RECORDS:
                tail.append(record)

        try:
            handle.assert_identity(identity, "after summary scan")
        except (OSError, ValueError) as error:
            print(json.dumps({{"ok": False, "error": str(error)}}, separators=(",", ":"), sort_keys=True))
            print(ROLLOUT_SUMMARY_END)
            return

    target_sha256 = hashing_reader.hexdigest() if hashing_reader.bytes_read == target_size else None

    serialized_lines = []
    serialized_bytes = 0
    output_too_large = False

    def append_serialized(item):
        nonlocal serialized_bytes, output_too_large
        if output_too_large:
            return
        line = json.dumps(item, separators=(",", ":"), sort_keys=True)
        line_bytes = len(line.encode("utf-8")) + 1
        if (
            line_bytes > ROLLOUT_SUMMARY_SERIALIZED_RECORD_BYTES
            or serialized_bytes + line_bytes > ROLLOUT_SUMMARY_SERIALIZED_BYTES
        ):
            output_too_large = True
            return
        serialized_lines.append(line)
        serialized_bytes += line_bytes

    append_serialized({{"ok": True}})
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
    append_serialized(scan_meta)
    emitted = set()

    def emit(record):
        if not record:
            return
        key = (str(record.get("kind", "")), int(record.get("line", 0)))
        if key in emitted:
            return
        payload = dict(record)
        payload.pop("_keyword_matched", None)
        payload["rollout"] = normalized
        append_serialized(payload)
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
    if output_too_large:
        print(json.dumps({{"ok": False, "error": ROLLOUT_SUMMARY_OUTPUT_TOO_LARGE_ERROR}}, separators=(",", ":"), sort_keys=True))
        print(ROLLOUT_SUMMARY_END)
        return
    for line in serialized_lines:
        print(line)
    print(ROLLOUT_SUMMARY_END)


def iter_session_meta():
    print(SESSION_META_BEGIN)

    def session_directory_unreadable():
        emit_session_meta_item({{"kind": "error", "error": "session directory unreadable"}})
        print(SESSION_META_END)
        raise SystemExit(0)

    def session_rollout_error(rel, error):
        emit_session_meta_item({{"kind": "error", "error": error, "rollout": rel.as_posix()}})
        print(SESSION_META_END)
        raise SystemExit(0)

    try:
        root_fd = open_pinned_codex_root()
    except FileNotFoundError:
        print(SESSION_META_END)
        return
    except (OSError, ValueError):
        session_directory_unreadable()

    opened_directories = {{}}
    prefix_proof_candidate_limit = SESSION_META_CANDIDATE_LIMIT
    prefix_proof_candidate_captures = 0

    def open_directory(rel_dir):
        key = rel_dir.as_posix()
        if key in opened_directories:
            return opened_directories[key]
        try:
            directory_fd = open_pinned_directory_from_fd(root_fd, rel_dir)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            session_directory_unreadable()
        opened_directories[key] = directory_fd
        return directory_fd

    def close_directory(rel_dir):
        key = rel_dir.as_posix()
        directory_fd = opened_directories.pop(key, None)
        if directory_fd is not None:
            os.close(directory_fd)

    def prepare_candidate_for_consumption(parent_fd, rel, inventory_identity):
        nonlocal prefix_proof_candidate_captures
        try:
            if session_meta_allows_append(rel):
                if prefix_proof_candidate_captures >= prefix_proof_candidate_limit:
                    return None
                prefix_proof_candidate_captures += 1
                return capture_active_rollout_candidate_identity_from_parent_fd(
                    parent_fd,
                    rel.name,
                    inventory_identity,
                )
            return capture_rollout_candidate_identity_from_parent_fd(
                parent_fd,
                rel.name,
                inventory_identity,
            )
        except ValueError as error:
            session_rollout_error(rel, str(error))
        except OSError:
            session_rollout_error(rel, "rollout unreadable")

    def sorted_rollout_candidates(rel_dir, predicate):
        directory_fd = open_directory(rel_dir)
        if directory_fd is None:
            return None, []
        try:
            candidates = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    name = entry.name
                    if not RAW_ROLLOUT_BASENAME_RE.fullmatch(name):
                        continue
                    rel = rel_dir / name
                    if not predicate(rel):
                        continue
                    try:
                        inventory_identity = (
                            capture_rollout_inventory_identity_from_parent_fd(
                                directory_fd,
                                name,
                            )
                        )
                    except ValueError as error:
                        session_rollout_error(rel, str(error))
                    except OSError:
                        session_rollout_error(rel, "rollout unreadable")
                    candidates.append((name, inventory_identity))
        except OSError:
            session_directory_unreadable()
        candidates.sort(key=lambda candidate: candidate[0], reverse=True)
        return directory_fd, candidates

    def add_directory_candidates(selected, rel_dir, predicate):
        directory_fd, candidates = sorted_rollout_candidates(rel_dir, predicate)
        if directory_fd is None:
            return
        for name, inventory_identity in candidates:
            rel = rel_dir / name
            key = session_meta_rollout_dedupe_key(rel)
            selected.setdefault(key, (rel, directory_fd, inventory_identity))

    count = 0
    seen_rollout_paths = set()
    flat_archived_unknown_by_date = {{}}
    flat_archived_inventory_identities = {{}}
    try:
        if ROLLOUT_FILENAME_MODE != "known":
            flat_archived_rel_dir = pathlib.PurePosixPath("archived_sessions")
            flat_archived_fd, flat_archived_candidates = sorted_rollout_candidates(
                flat_archived_rel_dir,
                lambda rel: session_meta_rollout_filename_date(rel.name) is None,
            )
            date_set = set(DATE_STRINGS)
            if flat_archived_fd is not None:
                for name, inventory_identity in flat_archived_candidates:
                    rel = flat_archived_rel_dir / name
                    consumed_identity = prepare_candidate_for_consumption(
                        flat_archived_fd,
                        rel,
                        inventory_identity,
                    )
                    meta = session_meta_from_rollout(
                        flat_archived_fd,
                        rel,
                        consumed_identity,
                    )
                    if meta is None:
                        continue
                    meta_date, session_id, cwd, timestamp = meta
                    if meta_date in date_set:
                        flat_archived_unknown_by_date.setdefault(meta_date, {{}})[
                            rel.as_posix()
                        ] = (session_id, cwd, timestamp)
                        flat_archived_inventory_identities[
                            rel.as_posix()
                        ] = inventory_identity

        for date_text in reversed(DATE_STRINGS):
            date_rel_dirs = (
                pathlib.PurePosixPath("sessions") / date_text,
                pathlib.PurePosixPath("archived_sessions") / date_text,
            )
            selected_rollout_paths = {{}}
            for rel_dir in date_rel_dirs:
                add_directory_candidates(
                    selected_rollout_paths,
                    rel_dir,
                    lambda rel: rollout_matches_bounds(rel),
                )
            flat_archived_rel_dir = pathlib.PurePosixPath("archived_sessions")
            add_directory_candidates(
                selected_rollout_paths,
                flat_archived_rel_dir,
                lambda rel: flat_archived_rollout_matches_date(rel, date_text)
                and flat_archived_rollout_matches_bounds_or_unknown(rel),
            )
            flat_archived_fd = open_directory(flat_archived_rel_dir)
            if flat_archived_fd is not None:
                for rel_key in flat_archived_unknown_by_date.get(date_text, {{}}):
                    rel = pathlib.PurePosixPath(rel_key)
                    selected_rollout_paths.setdefault(
                        rel_key,
                        (
                            rel,
                            flat_archived_fd,
                            flat_archived_inventory_identities[rel_key],
                        ),
                    )
            root_rel_dir = pathlib.PurePosixPath()
            add_directory_candidates(
                selected_rollout_paths,
                root_rel_dir,
                lambda rel: flat_archived_rollout_matches_date(rel, date_text)
                and rollout_matches_bounds(rel),
            )
            cached_rollout_meta = flat_archived_unknown_by_date.get(date_text, {{}})
            selected_rollouts = sorted(
                selected_rollout_paths.values(),
                key=lambda candidate: session_meta_rollout_sort_key(
                    candidate[0],
                    cached_rollout_meta.get(
                        candidate[0].as_posix(),
                        ("", "", None),
                    )[2],
                ),
                reverse=True,
            )
            for rel, parent_fd, inventory_identity in selected_rollouts:
                rel_key = rel.as_posix()
                if rel_key in seen_rollout_paths:
                    continue
                seen_rollout_paths.add(rel_key)
                require_record_date_match = session_meta_is_flat_archived_undated(rel)
                cached_meta = cached_rollout_meta.get(rel_key)
                if cached_meta is not None:
                    session_id, cwd, _timestamp = cached_meta
                else:
                    consumed_identity = prepare_candidate_for_consumption(
                        parent_fd,
                        rel,
                        inventory_identity,
                    )
                    if consumed_identity is None:
                        emit_session_meta_item({{"kind": "truncation", "reason": SESSION_META_CANDIDATE_LIMIT_TRUNCATED_REASON, "date": date_text, "candidate_limit": SESSION_META_CANDIDATE_LIMIT}})
                        print(SESSION_META_END)
                        return
                    meta = session_meta_from_rollout(
                        parent_fd,
                        rel,
                        consumed_identity,
                        date_text=date_text,
                        require_record_date_match=require_record_date_match,
                    )
                    if meta is None:
                        continue
                    _meta_date, session_id, cwd, _timestamp = meta
                if session_id:
                    count += 1
                    if LIMIT and count > LIMIT:
                        emit_session_meta_item({{"kind": "truncation", "reason": SESSION_META_LIMIT_TRUNCATED_REASON, "date": date_text, "limit": LIMIT}})
                        print(SESSION_META_END)
                        return
                    if not emit_session_meta_item({{"date": date_text, "session_id": session_id, "cwd": cwd, "rollout": rel_key}}):
                        print(SESSION_META_END)
                        return
            for rel_dir in date_rel_dirs:
                close_directory(rel_dir)
    finally:
        for directory_fd in opened_directories.values():
            os.close(directory_fd)
        os.close(root_fd)
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
        size, data = read_rollout_bytes(rel, MAX_FETCH_ROLLOUT_BYTES)
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


def _remote_python_argv(alias: str) -> list[str]:
    ssh_target = HOSTS[alias]["ssh_target"]
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        ssh_target,
        "python3",
        "-",
    ]


def _run_remote_python_bounded(
    alias: str,
    payload: dict[str, object],
    *,
    max_stdout_bytes: int,
) -> subprocess.CompletedProcess[str]:
    return _run_subprocess_text_bounded(
        _remote_python_argv(alias),
        input_text=_remote_python_script(payload),
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=MAX_REMOTE_STDERR_BYTES,
    )


def _validated_session_meta_output_item(
    *,
    date: str,
    session_id: str,
    cwd: str,
    rollout: str,
) -> dict[str, str]:
    item = {"date": date, "session_id": session_id, "cwd": cwd, "rollout": rollout}
    serialized = json.dumps(item, separators=(",", ":"), sort_keys=True)
    if len(serialized.encode("utf-8")) > MAX_REMOTE_SESSION_META_SERIALIZED_ROW_BYTES:
        raise ValueError(SESSION_META_OUTPUT_ROW_TOO_LARGE_ERROR)
    return item


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
        root_fd = _open_pinned_codex_root(codex_root)
    except FileNotFoundError:
        return SessionMetaScan(rows=[], truncated=False)
    except OSError as exc:
        raise SessionMetaRolloutError("session directory unreadable") from exc
    rows: list[dict[str, str]] = []
    seen_rollout_paths: set[str] = set()
    opened_directories: dict[str, int] = {}
    prefix_proof_candidate_limit = MAX_SESSION_META_CANDIDATE_LIMIT
    prefix_proof_candidate_captures = 0

    def open_directory(relative_dir: pathlib.PurePosixPath) -> int | None:
        key = relative_dir.as_posix()
        if key in opened_directories:
            return opened_directories[key]
        try:
            directory_fd = _open_pinned_directory_from_fd(root_fd, relative_dir)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SessionMetaRolloutError("session directory unreadable") from exc
        opened_directories[key] = directory_fd
        return directory_fd

    def close_directory(relative_dir: pathlib.PurePosixPath) -> None:
        key = relative_dir.as_posix()
        directory_fd = opened_directories.pop(key, None)
        if directory_fd is not None:
            os.close(directory_fd)

    def prepare_candidate_for_consumption(
        parent_fd: int,
        relative_path: pathlib.PurePosixPath,
        inventory_identity: RolloutInventoryIdentity,
    ) -> RolloutCandidateIdentity | None:
        nonlocal prefix_proof_candidate_captures
        try:
            if _session_meta_allows_append(relative_path):
                if prefix_proof_candidate_captures >= prefix_proof_candidate_limit:
                    return None
                prefix_proof_candidate_captures += 1
                return _capture_active_rollout_candidate_identity_from_parent_fd(
                    parent_fd,
                    relative_path.name,
                    inventory_identity,
                )
            return _capture_rollout_candidate_identity_from_parent_fd(
                parent_fd,
                relative_path.name,
                inventory_identity,
            )
        except ValueError as exc:
            raise SessionMetaRolloutError(
                str(exc),
                rollout=relative_path.as_posix(),
            ) from exc
        except OSError as exc:
            raise SessionMetaRolloutError(
                "rollout unreadable",
                rollout=relative_path.as_posix(),
            ) from exc

    def sorted_rollout_candidates(
        relative_dir: pathlib.PurePosixPath,
        predicate: Any,
    ) -> tuple[
        int | None,
        list[tuple[str, RolloutInventoryIdentity]],
    ]:
        directory_fd = open_directory(relative_dir)
        if directory_fd is None:
            return None, []
        try:
            candidates: list[tuple[str, RolloutInventoryIdentity]] = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    name = entry.name
                    if not RAW_ROLLOUT_BASENAME_RE.fullmatch(name):
                        continue
                    relative_path = relative_dir / name
                    if not predicate(relative_path):
                        continue
                    try:
                        inventory_identity = (
                            _capture_rollout_inventory_identity_from_parent_fd(
                                directory_fd,
                                name,
                            )
                        )
                    except ValueError as exc:
                        raise SessionMetaRolloutError(
                            str(exc),
                            rollout=relative_path.as_posix(),
                        ) from exc
                    except OSError as exc:
                        raise SessionMetaRolloutError(
                            "rollout unreadable",
                            rollout=relative_path.as_posix(),
                        ) from exc
                    candidates.append((name, inventory_identity))
        except OSError as exc:
            raise SessionMetaRolloutError("session directory unreadable") from exc
        candidates.sort(key=lambda candidate: candidate[0], reverse=True)
        return directory_fd, candidates

    def add_directory_candidates(
        selected: dict[
            str,
            tuple[
                pathlib.PurePosixPath,
                int,
                RolloutInventoryIdentity,
            ],
        ],
        relative_dir: pathlib.PurePosixPath,
        predicate: Any,
    ) -> None:
        directory_fd, candidates = sorted_rollout_candidates(
            relative_dir,
            predicate,
        )
        if directory_fd is None:
            return
        for name, inventory_identity in candidates:
            relative_path = relative_dir / name
            key = _session_meta_rollout_dedupe_key(relative_path)
            selected.setdefault(
                key,
                (relative_path, directory_fd, inventory_identity),
            )

    flat_archived_unknown_by_date: dict[
        dt.date,
        dict[str, tuple[str, str, dt.datetime | None]],
    ] = {}
    flat_archived_inventory_identities: dict[
        str,
        RolloutInventoryIdentity,
    ] = {}
    try:
        if rollout_filename_mode != "known":
            flat_archived_relative_dir = pathlib.PurePosixPath("archived_sessions")
            flat_archived_fd, flat_archived_candidates = sorted_rollout_candidates(
                flat_archived_relative_dir,
                lambda relative_path: _session_meta_rollout_filename_date(
                    relative_path.name
                )
                is None,
            )
            date_set = set(dates)
            if flat_archived_fd is not None:
                for name, inventory_identity in flat_archived_candidates:
                    rollout_relative_path = flat_archived_relative_dir / name
                    consumed_identity = prepare_candidate_for_consumption(
                        flat_archived_fd,
                        rollout_relative_path,
                        inventory_identity,
                    )
                    meta = _session_meta_from_rollout(
                        codex_root,
                        rollout_relative_path,
                        parent_fd=flat_archived_fd,
                        expected_identity=consumed_identity,
                        rollout_start=rollout_start,
                        rollout_end=rollout_end,
                    )
                    if meta is None:
                        continue
                    meta_date, session_id, cwd, timestamp = meta
                    if meta_date in date_set:
                        flat_archived_unknown_by_date.setdefault(meta_date, {})[
                            rollout_relative_path.as_posix()
                        ] = (session_id, cwd, timestamp)
                        flat_archived_inventory_identities[
                            rollout_relative_path.as_posix()
                        ] = inventory_identity

        for date_value in reversed(dates):
            date_text = date_value.strftime(DATE_FORMAT)
            date_relative_dirs = (
                pathlib.PurePosixPath("sessions") / date_text,
                pathlib.PurePosixPath("archived_sessions") / date_text,
            )
            selected_rollout_paths: dict[
                str,
                tuple[
                    pathlib.PurePosixPath,
                    int,
                    RolloutInventoryIdentity,
                ],
            ] = {}
            for relative_dir in date_relative_dirs:
                add_directory_candidates(
                    selected_rollout_paths,
                    relative_dir,
                    lambda relative_path: _rollout_matches_bounds(
                        relative_path,
                        rollout_start,
                        rollout_end,
                        filename_mode=rollout_filename_mode,
                    ),
                )
            flat_archived_relative_dir = pathlib.PurePosixPath("archived_sessions")
            add_directory_candidates(
                selected_rollout_paths,
                flat_archived_relative_dir,
                lambda relative_path: _flat_archived_rollout_matches_date(
                    pathlib.Path(relative_path.name),
                    date_value,
                )
                and _flat_archived_rollout_matches_bounds_or_unknown(
                    pathlib.Path(relative_path.name),
                    rollout_start,
                    rollout_end,
                    filename_mode=rollout_filename_mode,
                ),
            )
            flat_archived_fd = open_directory(flat_archived_relative_dir)
            if flat_archived_fd is not None:
                for relative_key in flat_archived_unknown_by_date.get(
                    date_value,
                    {},
                ):
                    relative_path = pathlib.PurePosixPath(relative_key)
                    selected_rollout_paths.setdefault(
                        relative_key,
                        (
                            relative_path,
                            flat_archived_fd,
                            flat_archived_inventory_identities[relative_key],
                        ),
                    )
            root_relative_dir = pathlib.PurePosixPath()
            add_directory_candidates(
                selected_rollout_paths,
                root_relative_dir,
                lambda relative_path: _flat_archived_rollout_matches_date(
                    pathlib.Path(relative_path.name),
                    date_value,
                )
                and _rollout_matches_bounds(
                    relative_path,
                    rollout_start,
                    rollout_end,
                    filename_mode=rollout_filename_mode,
                ),
            )
            cached_rollout_meta = flat_archived_unknown_by_date.get(date_value, {})
            selected_rollouts = sorted(
                selected_rollout_paths.values(),
                key=lambda candidate: _session_meta_rollout_sort_key(
                    candidate[0],
                    cached_rollout_meta.get(
                        candidate[0].as_posix(),
                        ("", "", None),
                    )[2],
                ),
                reverse=True,
            )
            for (
                rollout_relative_path,
                parent_fd,
                inventory_identity,
            ) in selected_rollouts:
                rollout_relative_key = rollout_relative_path.as_posix()
                if rollout_relative_key in seen_rollout_paths:
                    continue
                seen_rollout_paths.add(rollout_relative_key)
                require_record_date_match = _session_meta_is_flat_archived_undated(
                    rollout_relative_path
                )
                cached_meta = cached_rollout_meta.get(rollout_relative_key)
                if cached_meta is not None:
                    session_id, cwd, _timestamp = cached_meta
                else:
                    consumed_identity = prepare_candidate_for_consumption(
                        parent_fd,
                        rollout_relative_path,
                        inventory_identity,
                    )
                    if consumed_identity is None:
                        return SessionMetaScan(rows=rows, truncated=True)
                    meta = _session_meta_from_rollout(
                        codex_root,
                        rollout_relative_path,
                        parent_fd=parent_fd,
                        expected_identity=consumed_identity,
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
                if limit and len(rows) >= limit:
                    return SessionMetaScan(rows=rows, truncated=True)
                try:
                    item = _validated_session_meta_output_item(
                        date=date_value.strftime(DATE_FORMAT),
                        session_id=session_id,
                        cwd=cwd,
                        rollout=rollout_relative_key,
                    )
                except ValueError as exc:
                    raise SessionMetaRolloutError(
                        str(exc),
                        rollout=rollout_relative_key,
                    ) from exc
                rows.append({"host": host, **item})
            for relative_dir in date_relative_dirs:
                close_directory(relative_dir)
        return SessionMetaScan(rows=rows, truncated=False)
    finally:
        for directory_fd in opened_directories.values():
            os.close(directory_fd)
        os.close(root_fd)


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
    except (ValueError, RecursionError) as exc:
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
    validated = _validated_session_meta_output_item(
        date=str(item["date"]),
        session_id=str(item["session_id"]),
        cwd=str(item["cwd"]),
        rollout=str(item["rollout"]),
    )
    return {"host": host, **validated}


def _is_session_meta_truncation_item(item: dict[str, Any]) -> bool:
    return (
        item.get("kind") == "truncation"
        and item.get("reason")
        in {
            SESSION_META_LIMIT_TRUNCATED_REASON,
            SESSION_META_CANDIDATE_LIMIT_TRUNCATED_REASON,
        }
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
    result = _run_remote_python_bounded(
        alias,
        payload,
        max_stdout_bytes=MAX_REMOTE_SESSION_META_STDOUT_BYTES,
    )
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
        key = (row.get("host", ""), row.get("rollout", ""))
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
                result = _run_remote_python_bounded(
                    alias,
                    payload,
                    max_stdout_bytes=(
                        4 * ((MAX_FETCH_ROLLOUT_BYTES + 2) // 3)
                        + REMOTE_FETCH_FRAME_OVERHEAD_BYTES
                    ),
                )
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


def _message_content_is_valid(content: Any) -> bool:
    if not isinstance(content, list):
        return False
    for item in content:
        if not isinstance(item, dict):
            return False
        item_type = item.get("type")
        if not isinstance(item_type, str):
            return False
        if item_type in ("input_text", "output_text", "text") and not isinstance(
            item.get("text"), str
        ):
            return False
    return True


def _message_payload_is_valid(payload: dict[str, Any]) -> bool:
    role = payload.get("role")
    return (
        isinstance(role, str)
        and role in ("assistant", "developer", "system", "user")
        and _message_content_is_valid(payload.get("content"))
    )


def _message_summary(payload: dict[str, Any]) -> tuple[str, str]:
    role = str(payload.get("role", ""))
    if role not in {"assistant", "user"}:
        return "", ""
    parts: list[str] = []
    for item in payload.get("content", []):
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if not isinstance(item_type, str):
            continue
        if item_type not in ("input_text", "output_text", "text"):
            continue
        text = item.get("text")
        if isinstance(text, str) and text:
            parts.append(text)
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
    return _summary_pattern_search(re.compile(pattern, flags), text)


def _summary_pattern_search(pattern: re.Pattern[str], text: str) -> bool:
    return any(pattern.search(chunk) for chunk in _summary_signal_chunks(text))


def _summary_category_signals(chunks: tuple[str, ...]) -> list[str]:
    matched: set[str] = set()
    for label, pattern in SUMMARY_SIGNAL_CATEGORY_RES:
        for chunk in chunks:
            if pattern.search(chunk):
                matched.add(label)
                break
        if len(matched) == len(SUMMARY_SIGNAL_CATEGORY_LABELS):
            break
    return [label for label in SUMMARY_SIGNAL_CATEGORY_LABELS if label in matched]


def _summary_has_sensitive_signal_chunks(chunks: tuple[str, ...]) -> bool:
    return any(SUMMARY_SENSITIVE_SIGNAL_RE.search(chunk) for chunk in chunks)


def _summary_has_sensitive_signal(text: str) -> bool:
    return _summary_has_sensitive_signal_chunks(tuple(_summary_signal_chunks(text)))


def _summary_signal_text(kind: str, text: str) -> str:
    chunks = tuple(_summary_signal_chunks(text))
    signals = _summary_category_signals(chunks)
    if _summary_has_sensitive_signal_chunks(chunks):
        signals.append("secret")
    return " ".join(signals) if signals else f"{kind.replace('_', ' ')} present"


def _safe_summary_text(kind: str, text: str) -> str:
    return _summary_signal_text(kind, text)


def _summary_matches_keywords(text: str, search_keywords: list[str]) -> bool:
    if not search_keywords:
        return False
    normalized = _normalize_summary_text(text, max_text_chars=0).casefold()
    return any(keyword in normalized for keyword in search_keywords)


def _summary_record_has_signal(record: dict[str, Any] | None) -> bool:
    if record is None or str(record.get("kind", "")) in {"session_meta", "scan_meta"}:
        return False
    text = str(record.get("text", ""))
    return any(marker in text for marker in SUMMARY_SIGNAL_MARKERS)


def _event_user_message_text(payload: dict[str, Any]) -> str:
    message_present = "message" in payload
    message = payload.get("message")
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, dict):
        kind, text = _message_summary(message)
        if kind == "user_message" and text:
            return text.strip()
    if not message_present:
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
    search_keywords: list[str] | None = None,
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
    if _summary_matches_keywords(signal_text, search_keywords or []):
        record["_keyword_matched"] = True
    return record


def _bounded_session_meta_lines(handle: Any, max_scan_bytes: int) -> Iterable[str]:
    if max_scan_bytes < 1:
        raise ValueError("session metadata scan budget must be positive")
    try:
        file_descriptor = handle.fileno()
    except (AttributeError, OSError, ValueError):
        file_descriptor = None
    scanned = 0
    buffer = bytearray()
    buffer_offset = 0
    while True:
        remaining = max_scan_bytes - scanned
        if remaining <= 0:
            return
        read_size = min(SESSION_META_READ_CHUNK_BYTES, remaining)
        chunk = os.read(file_descriptor, read_size) if file_descriptor is not None else handle.read(read_size)
        if not chunk:
            if buffer:
                yield _decode_session_meta_line(bytes(buffer))
            return
        raw_bytes = (
            chunk.encode("utf-8", "surrogatepass")
            if isinstance(chunk, str)
            else bytes(chunk)
        )
        if len(raw_bytes) > read_size:
            raise ValueError("session metadata reader exceeded requested byte count")
        scanned += len(raw_bytes)
        buffer.extend(raw_bytes)
        cap_has_unread_bytes = False
        if scanned == max_scan_bytes:
            try:
                if file_descriptor is not None:
                    position = os.lseek(file_descriptor, 0, os.SEEK_CUR)
                    cap_has_unread_bytes = os.fstat(file_descriptor).st_size > position
                else:
                    cap_has_unread_bytes = len(handle.getbuffer()) > handle.tell()
            except (AttributeError, OSError, TypeError, ValueError):
                cap_has_unread_bytes = True
        while True:
            line_end = buffer.find(b"\n")
            if line_end < 0:
                break
            line_size = line_end + 1
            absolute_line_end = buffer_offset + line_size
            if cap_has_unread_bytes and absolute_line_end == max_scan_bytes:
                raise ValueError(f"session metadata scan truncated at {max_scan_bytes} bytes")
            line = bytes(buffer[:line_size])
            del buffer[:line_size]
            buffer_offset = absolute_line_end
            yield _decode_session_meta_line(line)
        if scanned == max_scan_bytes:
            if cap_has_unread_bytes:
                raise ValueError(f"session metadata scan truncated at {max_scan_bytes} bytes")
            if buffer:
                yield _decode_session_meta_line(bytes(buffer))
            return


def _decode_summary_line(raw_bytes: bytes) -> str:
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return "\n"


def _bounded_text_lines(
    handle: Any,
    max_scan_bytes: int,
    source_size: int,
) -> Iterable[str]:
    try:
        start_offset = handle.tell()
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise ValueError("rollout summary reader offset is unavailable") from error
    if (
        isinstance(start_offset, bool)
        or not isinstance(start_offset, int)
        or start_offset < 0
        or start_offset > source_size
    ):
        raise ValueError("rollout summary reader offset is invalid")
    if start_offset != 0:
        raise ValueError("rollout summary reader must start at byte 0")
    scanned = 0
    buffer = bytearray()
    dropping_oversized_line = False
    chunk_bytes = 64 * 1024
    scan_limit = min(max_scan_bytes, source_size) if max_scan_bytes else source_size

    while scanned < scan_limit:
        read_size = min(chunk_bytes, scan_limit - scanned)
        chunk = handle.read(read_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            raw_bytes = chunk.encode("utf-8", "surrogatepass")
        else:
            raw_bytes = bytes(chunk)
        scanned += len(raw_bytes)
        offset = 0
        while offset < len(raw_bytes):
            line_end = raw_bytes.find(b"\n", offset)
            part_end = len(raw_bytes) if line_end < 0 else line_end + 1
            part = raw_bytes[offset:part_end]
            if dropping_oversized_line:
                if line_end >= 0:
                    yield "\n"
                    dropping_oversized_line = False
            elif len(buffer) + len(part) > MAX_ROLLOUT_SUMMARY_LINE_BYTES:
                buffer.clear()
                dropping_oversized_line = True
                if line_end >= 0:
                    yield "\n"
                    dropping_oversized_line = False
            else:
                buffer.extend(part)
                if line_end >= 0:
                    yield _decode_summary_line(bytes(buffer))
                    buffer.clear()
            offset = part_end

    if scanned == source_size:
        if dropping_oversized_line:
            yield "\n"
        elif buffer:
            yield _decode_summary_line(bytes(buffer))


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
        except (ValueError, RecursionError):
            json_error_count += 1
            continue
        if not isinstance(obj, dict):
            json_error_count += 1
            continue
        timestamp_value = obj.get("timestamp")
        if "timestamp" in obj and not isinstance(timestamp_value, str):
            json_error_count += 1
            continue
        timestamp = timestamp_value if isinstance(timestamp_value, str) else ""
        record: dict[str, Any] | None = None
        record_type = obj.get("type")
        if not isinstance(record_type, str):
            json_error_count += 1
            continue
        payload = obj.get("payload")
        if record_type in ("session_meta", "response_item", "event_msg") and not isinstance(payload, dict):
            json_error_count += 1
            continue

        if record_type == "session_meta":
            session_id_value = payload.get("id")
            if not isinstance(session_id_value, str) or not session_id_value:
                json_error_count += 1
                continue
            cwd_value = payload.get("cwd")
            if "cwd" in payload and not isinstance(cwd_value, str):
                json_error_count += 1
                continue
            cwd_present = isinstance(cwd_value, str) and bool(cwd_value)
            if session_meta_record is None:
                session_meta_record = _build_summary_record(
                    kind="session_meta",
                    text=f"session_id={session_id_value} cwd_present={str(cwd_present).lower()}",
                    line_no=line_no,
                    timestamp=timestamp,
                    max_text_chars=max_text_chars,
                    session_id=session_id_value,
                    search_keywords=search_keywords,
                )
            continue

        if record_type == "response_item":
            payload_type = payload.get("type")
            if not isinstance(payload_type, str):
                json_error_count += 1
                continue
            if payload_type == "message":
                if not _message_payload_is_valid(payload):
                    json_error_count += 1
                    continue
                kind, text = _message_summary(payload)
                if text:
                    record = _build_summary_record(
                        kind=kind,
                        text=text,
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                        search_keywords=search_keywords,
                    )
                    if kind == "assistant_message":
                        last_assistant_record = record
                    elif kind == "user_message" and record is not None:
                        last_user_record = record
            elif payload_type == "function_call_output":
                output = payload.get("output")
                if not isinstance(output, str):
                    json_error_count += 1
                    continue
                if output.strip():
                    record = _build_summary_record(
                        kind="function_call_output",
                        text=output,
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                        search_keywords=search_keywords,
                    )
        elif record_type == "event_msg":
            payload_type = payload.get("type")
            if not isinstance(payload_type, str):
                json_error_count += 1
                continue
            if payload_type == "task_complete":
                text = payload.get("last_agent_message")
                if not isinstance(text, str):
                    json_error_count += 1
                    continue
                if text.strip():
                    record = _build_summary_record(
                        kind="task_complete",
                        text=text,
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                        search_keywords=search_keywords,
                    )
                    last_task_complete_record = record
            elif payload_type == "user_message":
                message = payload.get("message")
                if "message" in payload:
                    if isinstance(message, dict):
                        if message.get("role") != "user" or not _message_content_is_valid(
                            message.get("content")
                        ):
                            json_error_count += 1
                            continue
                    elif not isinstance(message, str):
                        json_error_count += 1
                        continue
                elif not isinstance(payload.get("text"), str):
                    json_error_count += 1
                    continue
                text = _event_user_message_text(payload)
                if text:
                    record = _build_summary_record(
                        kind="user_message",
                        text=text,
                        line_no=line_no,
                        timestamp=timestamp,
                        max_text_chars=max_text_chars,
                        search_keywords=search_keywords,
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
            if record.get("_keyword_matched") is True:
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
        safe_record.pop("_keyword_matched", None)
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
            with _open_local_rollout_text(codex_root, rollout_relative_path) as handle:
                identity = _rollout_identity_from_stat(os.fstat(handle.fileno()))
                handle.assert_identity(identity, phase="before summary scan")
                effective_summary_scan_bytes = (
                    MAX_ROLLOUT_SUMMARY_SCAN_BYTES or identity.size
                )
                hashing_reader = _HashingReader(handle)
                records, summary_meta = _summarize_rollout_records_with_meta(
                    lines=_bounded_text_lines(
                        hashing_reader,
                        effective_summary_scan_bytes,
                        identity.size,
                    ),
                    keywords=args.keyword,
                    limit=args.limit,
                    tail_records=args.tail_records,
                    max_text_chars=args.max_text_chars,
                )
                handle.assert_identity(identity, phase="after summary scan")
            source_sha256 = (
                hashing_reader.hexdigest()
                if hashing_reader.bytes_read == identity.size
                else None
            )
            records.insert(
                0,
                _rollout_summary_scan_meta(
                    source_bytes=identity.size,
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
                result = _run_remote_python_bounded(
                    alias,
                    payload,
                    max_stdout_bytes=MAX_REMOTE_ROLLOUT_SUMMARY_STDOUT_BYTES,
                )
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
