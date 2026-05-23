#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import datetime as dt
import json
import os
import pathlib
import re
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
MAX_ROLLOUT_SUMMARY_SCAN_BYTES = 2 * 1024 * 1024
MAX_ROLLOUT_SUMMARY_TAIL_RECORDS = 50
MAX_ROLLOUT_SUMMARY_TEXT_CHARS = 1200
MAX_SESSION_META_SCAN_BYTES = 256 * 1024
REMOTE_PREFLIGHT_TIMEOUT_SECONDS = 15
REMOTE_COMMAND_TIMEOUT_SECONDS = 60
TASK_OUTPUT_RELATIVE_DIR = pathlib.Path(".codex-tmp/remote-host-context")
ACTIVE_ROLLOUT_RELATIVE_RE = re.compile(
    r"^sessions/\d{4}/\d{2}/\d{2}/rollout-[^/]+\.jsonl$"
)
ARCHIVED_ROLLOUT_RELATIVE_RE = re.compile(
    r"^archived_sessions/(?:\d{4}/\d{2}/\d{2}/)?rollout-[^/]+\.jsonl$"
)
REMOTE_SESSION_META_BEGIN = "__REMOTE_CODEX_PROBE_SESSION_META_BEGIN__"
REMOTE_SESSION_META_END = "__REMOTE_CODEX_PROBE_SESSION_META_END__"
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

REMOTE_PREFLIGHT_SCRIPT = r"""
hostname_value="$(hostname 2>/dev/null || printf unknown)"
user_value="$(id -un 2>/dev/null || printf unknown)"
printf 'hostname=%s\n' "$hostname_value"
printf 'user=%s\n' "$user_value"
printf 'home=%s\n' "$HOME"
if [ -d "$HOME/.codex" ]; then
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


def _resolve_output_path(
    output: str, *, workspace_root: pathlib.Path | None = None
) -> pathlib.Path:
    raw_path = pathlib.Path(output).expanduser()
    task_output_root = _task_output_root(workspace_root).resolve()
    candidate = (task_output_root / raw_path) if not raw_path.is_absolute() else raw_path
    resolved = candidate.resolve()
    tmp_root = pathlib.Path("/tmp").resolve()
    if resolved.is_relative_to(task_output_root) or resolved.is_relative_to(tmp_root):
        return resolved
    raise ValueError(
        f"output path must stay under {task_output_root} or {tmp_root}"
    )


def _resolve_rollout_relative_path(value: str) -> pathlib.PurePosixPath:
    candidate = pathlib.PurePosixPath(value)
    normalized = candidate.as_posix()
    if not (
        ACTIVE_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ARCHIVED_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
    ):
        raise ValueError(
            "rollout path must match sessions/YYYY/MM/DD/rollout-*.jsonl or archived_sessions/rollout-*.jsonl"
        )
    return candidate


def _path_is_relative_to(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_rollout_path(
    codex_root: pathlib.Path, rollout_relative_path: pathlib.PurePosixPath
) -> pathlib.Path:
    root = codex_root.expanduser().resolve(strict=True)
    target = root.joinpath(*rollout_relative_path.parts)
    target_stat = target.lstat()
    if stat.S_ISLNK(target_stat.st_mode):
        raise ValueError("rollout path is a symlink")
    if not stat.S_ISREG(target_stat.st_mode):
        raise ValueError("rollout path is not a regular file")
    target_resolved = target.resolve(strict=True)
    if not _path_is_relative_to(target_resolved, root):
        raise ValueError("rollout path escapes Codex root")
    return target_resolved


def _open_local_rollout_text(
    codex_root: pathlib.Path, rollout_relative_path: pathlib.PurePosixPath
):
    target = _safe_rollout_path(codex_root, rollout_relative_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("rollout path is not a regular file")
        handle = os.fdopen(fd, "r", encoding="utf-8", errors="replace")
        fd = -1
        return handle
    finally:
        if fd != -1:
            os.close(fd)


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
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
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
            REMOTE_PREFLIGHT_SCRIPT,
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
SUMMARY_TAIL_RECORDS = int(CONFIG.get("summary_tail_records", 0))
SUMMARY_MAX_TEXT_CHARS = int(CONFIG.get("summary_max_text_chars", 0))
SUMMARY_MAX_TEXT_CHARS_LIMIT = {MAX_ROLLOUT_SUMMARY_TEXT_CHARS}
SUMMARY_KEYWORDS = [str(value) for value in CONFIG.get("summary_keywords", [])]
ACTIVE_ROLLOUT_RELATIVE_RE = re.compile({ACTIVE_ROLLOUT_RELATIVE_RE.pattern!r})
ARCHIVED_ROLLOUT_RELATIVE_RE = re.compile({ARCHIVED_ROLLOUT_RELATIVE_RE.pattern!r})
SESSION_META_BEGIN = {REMOTE_SESSION_META_BEGIN!r}
SESSION_META_END = {REMOTE_SESSION_META_END!r}
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


def safe_rollout_path(rel):
    root = ROOT.resolve(strict=True)
    target = root.joinpath(*rel.parts)
    target_stat = target.lstat()
    if stat.S_ISLNK(target_stat.st_mode):
        raise ValueError("rollout path is a symlink")
    if not stat.S_ISREG(target_stat.st_mode):
        raise ValueError("rollout path is not a regular file")
    target_resolved = target.resolve(strict=True)
    if not path_is_relative_to(target_resolved, root):
        raise ValueError("rollout path escapes Codex root")
    return target_resolved


def open_rollout_text(target):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("rollout path is not a regular file")
        handle = os.fdopen(fd, "r", encoding="utf-8", errors="replace")
        fd = -1
        return handle
    finally:
        if fd != -1:
            os.close(fd)


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


def user_prompt_signal_text(text):
    signals = []
    if re.search(r"(?:exit(?:ed)?(?: with)? code [1-9]\\d*|failed|traceback|error:|permission denied)", text, re.I):
        signals.append("error:")
    if re.search(r"(?:approval|require_escalated|sandbox|\\bauth(?:entication|orization|[-_ ]?gated)?\\b|credential|permission denied|TCC)", text, re.I):
        signals.append("approval")
    if re.search(r"(?:not run|did not run|unable to run|could not run|untested|未运行|无法运行)", text, re.I):
        signals.append("could not run")
    if re.search(r"(?:you missed|you forgot|wrong|incorrect|not what I asked|漏了|忘了|不对|错了)", text, re.I):
        signals.append("you missed")
    if re.search(r"(?:lost context|misunderstood|I misunderstood|assumption|assumed|上下文|误解)", text, re.I):
        signals.append("assumed")
    if re.search(r"(?:\\b(secret|token|credential|password|private key|production|destructive|rm -rf|reset --hard|customer data|privacy|pii)\\b|客户|客户数据|凭据|凭证|密钥|生产|破坏性)", text, re.I):
        signals.append("secret")
    return " ".join(signals) if signals else "user prompt present"


def safe_summary_text(kind, text):
    if kind == "user_message":
        return user_prompt_signal_text(str(text))
    return str(text)


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


def summary_record(kind, text, *, line_no, timestamp):
    value = normalize_text(safe_summary_text(kind, text), SUMMARY_MAX_TEXT_CHARS)
    if not value:
        return None
    record = {{"kind": kind, "line": line_no, "text": value, "timestamp": timestamp or ""}}
    match_text = normalize_text(text, SUMMARY_MAX_TEXT_CHARS)
    if kind == "user_message" and match_text and match_text != value:
        record["_match_text"] = match_text
    return record


def bounded_text_lines(handle, max_scan_bytes):
    scanned = 0
    while True:
        if max_scan_bytes and scanned >= max_scan_bytes:
            return
        remaining = max_scan_bytes - scanned if max_scan_bytes else 0
        line = handle.readline(remaining + 1 if remaining else -1)
        if not line:
            return
        encoded_len = len(line.encode("utf-8", "surrogatepass"))
        if max_scan_bytes and encoded_len > remaining:
            return
        scanned += encoded_len
        yield line


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
    tail = collections.deque(maxlen=SUMMARY_TAIL_RECORDS)
    session_meta_record = None
    last_assistant_record = None
    last_user_record = None
    last_task_complete_record = None

    target_size = target.stat().st_size
    with open_rollout_text(target) as handle:
        for line_no, line in enumerate(bounded_text_lines(handle, SUMMARY_SCAN_BYTES), 1):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
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
                        elif kind == "user_message":
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
                        last_user_record = record

            if not record or record.get("kind") == "session_meta":
                continue

            text_value = str(record.get("_match_text") or record.get("text", ""))
            if keywords and any(keyword in text_value.casefold() for keyword in keywords):
                key = (str(record.get("kind", "")), int(record.get("line", 0)))
                if key not in matched_seen and (not SUMMARY_LIMIT or len(matched) < SUMMARY_LIMIT):
                    matched.append(record)
                    matched_seen.add(key)
            if SUMMARY_TAIL_RECORDS:
                tail.append(record)

    print(json.dumps({{"ok": True}}, separators=(",", ":"), sort_keys=True))
    print(json.dumps(
        {{
            "kind": "scan_meta",
            "line": 0,
            "scan_bytes": SUMMARY_SCAN_BYTES,
            "scan_truncated": bool(SUMMARY_SCAN_BYTES and target_size > SUMMARY_SCAN_BYTES),
            "source_bytes": target_size,
            "text": "scan_truncated=" + str(bool(SUMMARY_SCAN_BYTES and target_size > SUMMARY_SCAN_BYTES)).lower()
                + " scan_bytes=" + str(SUMMARY_SCAN_BYTES)
                + " source_bytes=" + str(target_size),
            "timestamp": "",
        }},
        separators=(",", ":"),
        sort_keys=True,
    ))
    emitted = set()

    def emit(record):
        if not record:
            return
        key = (str(record.get("kind", "")), int(record.get("line", 0)))
        if key in emitted:
            return
        payload = dict(record)
        payload.pop("_match_text", None)
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        emitted.add(key)

    emit(session_meta_record)
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
    print(SESSION_META_BEGIN)
    count = 0
    for date_text in reversed(DATE_STRINGS):
        rollout_paths = []
        for date_dir in (ROOT / "sessions" / date_text, ROOT / "archived_sessions" / date_text):
            if not date_dir.is_dir():
                continue
            rollout_paths.extend(sorted(date_dir.glob("rollout-*.jsonl"), reverse=True))
        flat_archived_dir = ROOT / "archived_sessions"
        if flat_archived_dir.is_dir():
            rollout_paths.extend(
                rollout
                for rollout in sorted(flat_archived_dir.glob("rollout-*.jsonl"), reverse=True)
                if flat_archived_rollout_matches_date(rollout, date_text)
            )
        for rollout in rollout_paths:
            rel = pathlib.PurePosixPath(rollout.relative_to(ROOT).as_posix())
            session_id = ""
            cwd = ""
            try:
                target = safe_rollout_path(rel)
            except (FileNotFoundError, ValueError):
                continue
            with open_rollout_text(target) as handle:
                for line in bounded_text_lines(handle, SESSION_META_SCAN_BYTES):
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("type") != "session_meta":
                        continue
                    payload = obj.get("payload", {{}})
                    session_id = str(payload.get("id", ""))
                    cwd = str(payload.get("cwd", ""))
                    break
            if session_id:
                print(json.dumps({{"date": date_text, "session_id": session_id, "cwd": cwd, "rollout": rollout.relative_to(ROOT).as_posix()}}, separators=(",", ":"), sort_keys=True))
                count += 1
                if LIMIT and count >= LIMIT:
                    print(SESSION_META_END)
                    return
    print(SESSION_META_END)


def fetch_rollout():
    rel = pathlib.PurePosixPath(str(CONFIG["rollout"]))
    normalized = rel.as_posix()
    print(FETCH_ROLLOUT_BEGIN)
    if not (
        ACTIVE_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
        or ARCHIVED_ROLLOUT_RELATIVE_RE.fullmatch(normalized)
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
    except ValueError as error:
        print(json.dumps({{"ok": False, "error": str(error)}}, separators=(",", ":"), sort_keys=True))
        print(FETCH_ROLLOUT_END)
        return
    payload = base64.b64encode(data).decode("ascii")
    print(json.dumps({{"ok": True, "bytes": size}}, separators=(",", ":"), sort_keys=True))
    print(payload)
    print(FETCH_ROLLOUT_END)


if CONFIG["mode"] == "session-meta":
    iter_session_meta()
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


def _iter_session_meta_records(
    *,
    codex_root: pathlib.Path,
    dates: list[dt.date],
    limit: int,
    host: str,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for date_value in reversed(dates):
        date_text = date_value.strftime(DATE_FORMAT)
        rollout_paths: list[pathlib.Path] = []
        for date_dir in (codex_root / "sessions" / date_text, codex_root / "archived_sessions" / date_text):
            if not date_dir.is_dir():
                continue
            rollout_paths.extend(sorted(date_dir.glob("rollout-*.jsonl"), reverse=True))
        flat_archived_dir = codex_root / "archived_sessions"
        if flat_archived_dir.is_dir():
            rollout_paths.extend(
                rollout_path
                for rollout_path in sorted(flat_archived_dir.glob("rollout-*.jsonl"), reverse=True)
                if _flat_archived_rollout_matches_date(rollout_path, date_value)
            )
        for rollout_path in rollout_paths:
            rollout_relative_path = pathlib.PurePosixPath(
                rollout_path.relative_to(codex_root).as_posix()
            )
            session_id = ""
            cwd = ""
            try:
                handle = _open_local_rollout_text(codex_root, rollout_relative_path)
            except (FileNotFoundError, ValueError):
                continue
            with handle:
                for line in _bounded_text_lines(handle, MAX_SESSION_META_SCAN_BYTES):
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("type") != "session_meta":
                        continue
                    payload = obj.get("payload", {})
                    session_id = str(payload.get("id", ""))
                    cwd = str(payload.get("cwd", ""))
                    break
            if not session_id:
                continue
            rows.append(
                {
                    "host": host,
                    "date": date_value.strftime(DATE_FORMAT),
                    "session_id": session_id,
                    "cwd": cwd,
                    "rollout": rollout_path.relative_to(codex_root).as_posix(),
                }
            )
            if limit and len(rows) >= limit:
                return rows
    return rows


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
        if args.limit < 1 or args.limit > MAX_SESSION_META_LIMIT:
            raise ValueError(
                f"--limit must stay between 1 and {MAX_SESSION_META_LIMIT}"
            )
    except ValueError as error:
        return _error(str(error))

    rows: list[dict[str, str]] = []
    for alias in hosts:
        if HOSTS[alias]["kind"] == "local":
            host_rows = _iter_session_meta_records(
                codex_root=_local_codex_root(),
                dates=dates,
                limit=args.limit,
                host=alias,
            )
        else:
            payload = {
                "mode": "session-meta",
                "dates": [date_value.strftime(DATE_FORMAT) for date_value in dates],
                "limit": args.limit,
                "codex_root": HOSTS[alias]["codex_root"],
                "session_meta_scan_bytes": MAX_SESSION_META_SCAN_BYTES,
            }
            try:
                result = _run_remote_python(alias, payload)
            except RuntimeError as error:
                print(f"host={alias}", file=sys.stderr)
                print(f"error={error}", file=sys.stderr)
                return 1
            if result.returncode != 0:
                message = result.stderr.strip() or result.stdout.strip() or "remote session-meta failed"
                print(f"host={alias}", file=sys.stderr)
                print(f"error={message}", file=sys.stderr)
                return 1
            host_rows = []
            try:
                payload_lines = _extract_framed_lines(
                    result.stdout,
                    begin_marker=REMOTE_SESSION_META_BEGIN,
                    end_marker=REMOTE_SESSION_META_END,
                    host=alias,
                    command="session-meta",
                )
            except ValueError as error:
                print(f"host={alias}", file=sys.stderr)
                print(f"error={error}", file=sys.stderr)
                return 1
            for line in payload_lines:
                if not line.strip():
                    continue
                try:
                    item = _json_line_to_dict(line, host=alias)
                except ValueError as error:
                    print(f"host={alias}", file=sys.stderr)
                    print(f"error={error}", file=sys.stderr)
                    return 1
                try:
                    host_rows.append(_session_meta_row_from_item(item, host=alias))
                except ValueError as error:
                    print(f"host={alias}", file=sys.stderr)
                    print(f"error={error}", file=sys.stderr)
                    return 1
        rows.extend(host_rows)
    rows = _sort_session_meta_rows(rows)[: args.limit]

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


def _user_prompt_signal_text(text: str) -> str:
    signals: list[str] = []
    if re.search(r"(?:exit(?:ed)?(?: with)? code [1-9]\d*|failed|traceback|error:|permission denied)", text, re.I):
        signals.append("error:")
    if re.search(r"(?:approval|require_escalated|sandbox|\bauth(?:entication|orization|[-_ ]?gated)?\b|credential|permission denied|TCC)", text, re.I):
        signals.append("approval")
    if re.search(r"(?:not run|did not run|unable to run|could not run|untested|未运行|无法运行)", text, re.I):
        signals.append("could not run")
    if re.search(r"(?:you missed|you forgot|wrong|incorrect|not what I asked|漏了|忘了|不对|错了)", text, re.I):
        signals.append("you missed")
    if re.search(r"(?:lost context|misunderstood|I misunderstood|assumption|assumed|上下文|误解)", text, re.I):
        signals.append("assumed")
    if re.search(
        r"(?:\b(secret|token|credential|password|private key|production|destructive|rm -rf|reset --hard|customer data|privacy|pii)\b|客户|客户数据|凭据|凭证|密钥|生产|破坏性)",
        text,
        re.I,
    ):
        signals.append("secret")
    return " ".join(signals) if signals else "user prompt present"


def _safe_summary_text(kind: str, text: str) -> str:
    if kind == "user_message":
        return _user_prompt_signal_text(text)
    return text


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
) -> dict[str, Any] | None:
    normalized = _normalize_summary_text(_safe_summary_text(kind, text), max_text_chars=max_text_chars)
    if not normalized:
        return None
    record = {
        "kind": kind,
        "line": line_no,
        "text": normalized,
        "timestamp": timestamp,
    }
    match_text = _normalize_summary_text(text, max_text_chars=max_text_chars)
    if kind == "user_message" and match_text and match_text != normalized:
        record["_match_text"] = match_text
    return record


def _bounded_text_lines(handle: Any, max_scan_bytes: int) -> Iterable[str]:
    scanned = 0
    while True:
        if max_scan_bytes and scanned >= max_scan_bytes:
            return
        remaining = max_scan_bytes - scanned if max_scan_bytes else 0
        line = handle.readline(remaining + 1 if remaining else -1)
        if not line:
            return
        encoded_len = len(line.encode("utf-8", "surrogatepass"))
        if max_scan_bytes and encoded_len > remaining:
            return
        scanned += encoded_len
        yield line


def _summarize_rollout_records(
    *,
    lines: Iterable[str],
    keywords: list[str],
    limit: int,
    tail_records: int,
    max_text_chars: int,
) -> list[dict[str, Any]]:
    search_keywords = [value.casefold() for value in keywords if value]
    matched: list[dict[str, Any]] = []
    matched_seen: set[tuple[str, int]] = set()
    tail: collections.deque[dict[str, Any]] = collections.deque(maxlen=tail_records)
    session_meta_record: dict[str, Any] | None = None
    last_assistant_record: dict[str, Any] | None = None
    last_user_record: dict[str, Any] | None = None
    last_task_complete_record: dict[str, Any] | None = None

    for line_no, line in enumerate(lines, 1):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
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
                    elif kind == "user_message":
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
                    last_user_record = record

        if record is None:
            continue

        if search_keywords:
            text_value = str(record.get("_match_text") or record.get("text", "")).casefold()
            if any(keyword in text_value for keyword in search_keywords):
                key = (str(record.get("kind", "")), int(record.get("line", 0)))
                if key not in matched_seen and (limit <= 0 or len(matched) < limit):
                    matched.append(record)
                    matched_seen.add(key)

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
    for record in matched:
        append(record)
    if not search_keywords:
        for record in tail:
            append(record)
    append(last_user_record)
    append(last_assistant_record)
    if last_assistant_record is None:
        append(last_task_complete_record)
    return result


def _rollout_summary_scan_meta(*, source_bytes: int, scan_bytes: int) -> dict[str, Any]:
    scan_truncated = bool(scan_bytes and source_bytes > scan_bytes)
    return {
        "kind": "scan_meta",
        "line": 0,
        "scan_bytes": scan_bytes,
        "scan_truncated": scan_truncated,
        "source_bytes": source_bytes,
        "text": f"scan_truncated={str(scan_truncated).lower()} scan_bytes={scan_bytes} source_bytes={source_bytes}",
        "timestamp": "",
    }


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

    try:
        if HOSTS[alias]["kind"] == "local":
            codex_root = _local_codex_root()
            source_bytes = _safe_rollout_path(codex_root, rollout_relative_path).stat().st_size
            with _open_local_rollout_text(codex_root, rollout_relative_path) as handle:
                records = _summarize_rollout_records(
                    lines=_bounded_text_lines(handle, MAX_ROLLOUT_SUMMARY_SCAN_BYTES),
                    keywords=args.keyword,
                    limit=args.limit,
                    tail_records=args.tail_records,
                    max_text_chars=args.max_text_chars,
                )
            records.insert(
                0,
                _rollout_summary_scan_meta(
                    source_bytes=source_bytes,
                    scan_bytes=MAX_ROLLOUT_SUMMARY_SCAN_BYTES,
                ),
            )
        else:
            payload = {
                "mode": "rollout-summary",
                "rollout": rollout_relative_path.as_posix(),
                "codex_root": HOSTS[alias]["codex_root"],
                "session_meta_scan_bytes": MAX_SESSION_META_SCAN_BYTES,
                "summary_keywords": list(args.keyword),
                "summary_limit": args.limit,
                "summary_scan_bytes": MAX_ROLLOUT_SUMMARY_SCAN_BYTES,
                "summary_tail_records": args.tail_records,
                "summary_max_text_chars": args.max_text_chars,
            }
            try:
                result = _run_remote_python(alias, payload)
            except RuntimeError as error:
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
                print(f"error={error}", file=sys.stderr)
                return 1
            if result.returncode != 0:
                message = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "remote rollout-summary failed"
                )
                print(f"host={alias}", file=sys.stderr)
                print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
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
    except ValueError as error:
        print(f"host={alias}", file=sys.stderr)
        print(f"rollout={rollout_relative_path.as_posix()}", file=sys.stderr)
        print(f"error={error}", file=sys.stderr)
        return 1

    for record in records:
        item = dict(record)
        item["host"] = alias
        item["rollout"] = rollout_relative_path.as_posix()
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
    session_meta.set_defaults(func=cmd_session_meta)

    fetch_rollout = subparsers.add_parser(
        "fetch-rollout",
        help="Copy one validated rollout file from an allowed host to a local path.",
    )
    fetch_rollout.add_argument("--host", required=True)
    fetch_rollout.add_argument(
        "--rollout",
        required=True,
        help="Relative rollout path under the remote Codex root (sessions/... or archived_sessions/...).",
    )
    fetch_rollout.add_argument(
        "--output",
        required=True,
        help="Output path must resolve under .codex-tmp/remote-host-context/ or /tmp.",
    )
    fetch_rollout.set_defaults(func=cmd_fetch_rollout)

    rollout_summary = subparsers.add_parser(
        "rollout-summary",
        help="Read a bounded structured summary from one rollout without copying the full file.",
    )
    rollout_summary.add_argument("--host", required=True)
    rollout_summary.add_argument(
        "--rollout",
        required=True,
        help="Relative rollout path under the remote Codex root (sessions/... or archived_sessions/...).",
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
