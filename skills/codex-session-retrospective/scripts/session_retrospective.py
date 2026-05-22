#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
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
)

SECRET_PATTERNS = (
    re.compile(r"\b(?:(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"https?://[^\s)>\]\"']+"),
)

FLAG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("failed_command", re.compile(r"(?:exit(?:ed)?(?: with)? code [1-9]\d*|failed|traceback|error:|permission denied)", re.I)),
    ("approval_auth_friction", re.compile(r"(?:approval|require_escalated|sandbox|auth|credential|permission denied|TCC)", re.I)),
    ("verification_gap", re.compile(r"(?:not run|did not run|unable to run|could not run|untested|未运行|无法运行)", re.I)),
    ("user_correction", re.compile(r"(?:you missed|you forgot|wrong|incorrect|not what I asked|漏了|忘了|不对|错了)", re.I)),
    ("context_loss", re.compile(r"(?:lost context|misunderstood|I misunderstood|assumption|assumed|上下文|误解)", re.I)),
)

SAFETY_PATTERN = re.compile(
    r"\b(secret|token|credential|password|private key|production|destructive|rm -rf|reset --hard|客户|凭据|密钥)\b",
    re.I,
)


@dataclasses.dataclass(frozen=True)
class Source:
    host: str
    root: Path


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
    labels = ("[REDACTED_SECRET]", "[REDACTED_SECRET]", "[REDACTED_EMAIL]", "[REDACTED_URL]")
    for pattern, label in zip(SECRET_PATTERNS, labels, strict=True):
        redacted, count = pattern.subn(label, redacted)
        changed = changed or count > 0
    if len(redacted) > 1200:
        redacted = redacted[:1200].rstrip() + " [TRUNCATED]"
        changed = True
    return redacted, changed


def prompt_category(text: str) -> str:
    categories: list[str] = []
    lowered = text.lower()
    if any(word in lowered for word in ("review", "pr", "pull request")):
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


def safe_prompt_summary(text: str, issue_flags: set[str], redacted_changed: bool) -> str:
    parts = [
        f"category={prompt_category(text)}",
        f"prompt_chars={len(text)}",
    ]
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
    if any(word in joined for word in ("commit", "push", "pr", "pull request")):
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


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def session_id_from_path(path: Path) -> str:
    match = re.search(r"rollout-[^-]+-[^-]+-(.+)\.jsonl$", path.name)
    if match:
        return match.group(1)
    return stable_hash(path.as_posix())


def rollout_date_from_path(path: Path) -> dt.datetime | None:
    match = re.search(r"rollout-(\d{4}-\d{2}-\d{2})T", path.name)
    if not match:
        return None
    return parse_time(match.group(1) + "T00:00:00Z")


def iter_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                yield line_no, json.loads(line)
            except json.JSONDecodeError:
                continue


def text_from_message_payload(payload: dict[str, Any]) -> str:
    texts: list[str] = []
    for part in payload.get("content") or []:
        if isinstance(part, dict) and part.get("type") in {"input_text", "output_text", "text"}:
            texts.append(str(part.get("text") or ""))
    return "\n".join(texts).strip()


def record_timestamp(record: dict[str, Any]) -> str | None:
    payload = record.get("payload") or {}
    for key in ("timestamp", "time", "created_at", "ts"):
        value = record.get(key) or payload.get(key)
        if isinstance(value, str) and parse_time(value):
            return iso(parse_time(value) or utc_now())
    return None


def record_text(record: dict[str, Any]) -> str:
    payload = record.get("payload") or {}
    if isinstance(payload, dict) and payload.get("type") == "message":
        return text_from_message_payload(payload)
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(payload)


def meaningful_user_text(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and not any(stripped.startswith(prefix) for prefix in WRAPPER_PREFIXES)


def flags_for_text(text: str, *, redacted_changed: bool = False) -> set[str]:
    flags = {name for name, pattern in FLAG_PATTERNS if pattern.search(text)}
    if redacted_changed or SAFETY_PATTERN.search(text):
        flags.add("safety_privacy_flag")
    return flags


def source_rollouts(source: Source) -> list[Path]:
    sessions = source.root / "sessions"
    search_root = sessions if sessions.exists() else source.root
    return sorted(path for path in search_root.rglob("rollout-*.jsonl") if path.is_file())


def source_summary_files(source: Source) -> list[Path]:
    if not source.root.exists():
        return []
    return sorted(path for path in source.root.rglob("rollout-summary*.jsonl") if path.is_file())


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


def extract_rollout(source: Source, path: Path, start: dt.datetime | None, end: dt.datetime | None) -> list[TurnSummary]:
    session_id = session_id_from_path(path)
    source_hash = file_hash(path)
    cwd: str | None = None
    model: str | None = None
    current: TurnSummary | None = None
    turns: list[TurnSummary] = []
    assistant_bits: list[str] = []

    def flush_assistant() -> None:
        nonlocal assistant_bits
        if current and assistant_bits:
            current.assistant_action_summary = safe_assistant_summary(assistant_bits)
            assistant_bits = []

    for line_no, record in iter_jsonl(path):
        payload = record.get("payload") or {}
        if isinstance(payload, dict):
            cwd = payload.get("cwd") or cwd
            model = payload.get("model") or payload.get("model_id") or model
        timestamp = record_timestamp(record) or (iso(rollout_date_from_path(path)) if rollout_date_from_path(path) else None)
        parsed_timestamp = parse_time(timestamp)
        if parsed_timestamp and start and parsed_timestamp < start:
            continue
        if parsed_timestamp and end and parsed_timestamp >= end:
            continue

        if isinstance(payload, dict) and payload.get("type") == "message":
            role = payload.get("role")
            message_text = text_from_message_payload(payload)
            if role == "user" and not meaningful_user_text(message_text):
                continue
            if role == "user" and meaningful_user_text(message_text):
                flush_assistant()
                _redacted_prompt, prompt_changed = redact(message_text)
                prompt_flags = flags_for_text(message_text, redacted_changed=prompt_changed)
                prompt_summary = safe_prompt_summary(message_text, prompt_flags, prompt_changed)
                date_bucket = (parse_time(timestamp) or rollout_date_from_path(path) or utc_now()).date().isoformat()
                episode_seed = "|".join([source.host, session_id, (cwd or ""), date_bucket, prompt_category(message_text)])
                episode_id = stable_hash(episode_seed, 20)
                turn = TurnSummary(
                    turn_id=stable_hash(f"{source.host}|{path}|{line_no}|{timestamp}", 20),
                    episode_id=episode_id,
                    host=source.host,
                    session_id=session_id,
                    source_path=path.as_posix(),
                    source_hash=source_hash,
                    timestamp=timestamp,
                    cwd=cwd,
                    model=model,
                    model_era=infer_model_era(model, timestamp),
                    redacted_user_prompt_summary=prompt_summary,
                    assistant_action_summary="",
                    issue_flags=sorted(prompt_flags),
                    prompt_improvement=None,
                )
                if "user_correction" in prompt_flags or "context_loss" in prompt_flags:
                    turn.prompt_improvement = "Clarify the expected outcome, scope boundary, and any prior correction before asking Codex to continue."
                turns.append(turn)
                current = turn
                continue
            if role == "assistant" and current and message_text:
                assistant_bits.append(message_text)

        text = record_text(record)
        _redacted_text, changed = redact(text)
        record_flags = flags_for_text(text, redacted_changed=changed)
        if current and record_flags:
            merged = set(current.issue_flags)
            merged.update(record_flags)
            current.issue_flags = sorted(merged)
            if not current.prompt_improvement and ("verification_gap" in merged or "failed_command" in merged):
                current.prompt_improvement = "Ask Codex to report the exact verification run and stop if it cannot complete the requested check."

    flush_assistant()
    return turns


def extract_summary_file(source: Source, path: Path, start: dt.datetime | None, end: dt.datetime | None) -> list[TurnSummary]:
    turns: list[TurnSummary] = []
    source_hash = file_hash(path)
    session_id = stable_hash(path.as_posix(), 20)
    for line_no, record in iter_jsonl(path):
        timestamp = str(record.get("timestamp") or "") or None
        parsed_timestamp = parse_time(timestamp)
        if parsed_timestamp and start and parsed_timestamp < start:
            continue
        if parsed_timestamp and end and parsed_timestamp >= end:
            continue
        text = str(record.get("text") or "")
        kind = str(record.get("kind") or "summary")
        if kind == "session_meta" and text:
            match = re.search(r"session_id=([^\s]+)", text)
            if match:
                session_id = match.group(1)
            continue
        flags = flags_for_text(text, redacted_changed=False)
        if not flags:
            continue
        date_bucket = (parsed_timestamp or utc_now()).date().isoformat()
        episode_id = stable_hash("|".join([source.host, session_id, "rollout-summary", date_bucket, kind]), 20)
        turns.append(
            TurnSummary(
                turn_id=stable_hash(f"{source.host}|{path}|{line_no}|{timestamp}", 20),
                episode_id=episode_id,
                host=source.host,
                session_id=session_id,
                source_path=path.as_posix(),
                source_hash=source_hash,
                timestamp=timestamp,
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
        "coverage_gaps": coverage_gaps or [],
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


def parse_sources(values: list[str] | None) -> list[Source]:
    if not values:
        return [Source("local", Path("~/.codex").expanduser())]
    sources: list[Source] = []
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--source must be HOST=PATH, got {value!r}")
        host, raw_path = value.split("=", 1)
        sources.append(Source(host.strip(), Path(raw_path).expanduser()))
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


def earliest_rollout_date(sources: list[Source]) -> dt.datetime | None:
    earliest: dt.datetime | None = None
    for source in sources:
        for rollout in source_rollouts(source):
            parsed = rollout_date_from_path(rollout)
            if parsed and (earliest is None or parsed < earliest):
                earliest = parsed
    return earliest


def run_scan(args: argparse.Namespace, *, mode: str, start: dt.datetime | None, end: dt.datetime) -> int:
    output = Path(args.output)
    sources = parse_sources(args.source)
    all_turns: list[TurnSummary] = []
    manifest_sources: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    max_raw_bytes = getattr(args, "max_raw_bytes", 512_000)
    for source in sources:
        if not source.root.exists():
            coverage_gaps.append({"host": source.host, "root": source.root.as_posix(), "reason": "source_root_missing"})
            manifest_sources.append({"host": source.host, "root": source.root.as_posix(), "rollout_count": 0, "status": "missing"})
            continue
        rollouts = source_rollouts(source)
        summaries = source_summary_files(source)
        if not rollouts and not summaries:
            coverage_gaps.append({"host": source.host, "root": source.root.as_posix(), "reason": "no_rollout_or_summary_files"})
        manifest_sources.append(
            {
                "host": source.host,
                "root": source.root.as_posix(),
                "rollout_count": len(rollouts),
                "summary_count": len(summaries),
                "status": "ready" if rollouts or summaries else "empty",
            }
        )
        for rollout in rollouts:
            size = rollout.stat().st_size
            if size > max_raw_bytes:
                coverage_gaps.append(
                    {
                        "host": source.host,
                        "path": rollout.as_posix(),
                        "bytes": size,
                        "reason": "oversized_rollout_skipped",
                    }
                )
                continue
            all_turns.extend(extract_rollout(source, rollout, start, end))
        for summary in summaries:
            all_turns.extend(extract_summary_file(source, summary, start, end))

    episodes = episode_records(all_turns)
    window = {
        "mode": mode,
        "start": iso(start) if start else None,
        "end": iso(end),
    }
    write_jsonl(output / "turn_summaries.jsonl", (asdict_turn(turn) for turn in all_turns))
    write_jsonl(output / "turn_flags.jsonl", (asdict_turn(turn) for turn in all_turns if turn.issue_flags))
    write_jsonl(output / "episodes.jsonl", episodes)
    write_json(output / "trend_report.json", trend_report(all_turns, episodes, window, coverage_gaps))
    write_json(
        output / "shard_manifest.json",
        {
            "schema_version": 1,
            "mode": mode,
            "window": window,
            "sources": manifest_sources,
            "coverage_gaps": coverage_gaps,
            "redaction_policy_version": 1,
        },
    )
    if args.state and not coverage_gaps:
        state = load_state(Path(args.state))
        state["last_scan_at"] = iso(end)
        state["last_mode"] = mode
        save_state(Path(args.state), state)
    print(output)
    return 0


def cmd_scan_daily(args: argparse.Namespace) -> int:
    end = utc_now()
    state = load_state(Path(args.state)) if args.state else {}
    last = parse_time(state.get("last_scan_at"))
    lookback_start = end - dt.timedelta(days=args.active_lookback_days)
    start = min(last, lookback_start) if last else end - dt.timedelta(days=1)
    return run_scan(args, mode="daily", start=start, end=end)


def cmd_scan_weekly(args: argparse.Namespace) -> int:
    end = utc_now()
    start = end - dt.timedelta(days=args.days)
    return run_scan(args, mode="weekly", start=start, end=end)


def cmd_baseline(args: argparse.Namespace) -> int:
    now = utc_now()
    sources = parse_sources(args.source)
    if args.from_value == "first":
        start = earliest_rollout_date(sources) or (now - dt.timedelta(days=args.window_days))
    else:
        start = parse_time(args.from_value)
        if start is None:
            raise SystemExit(f"invalid --from timestamp: {args.from_value}")
    end = min(now, start + dt.timedelta(days=args.window_days))
    return run_scan(args, mode=f"baseline-{args.window_days}d", start=start, end=end)


def cmd_make_shards(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    output = Path(args.output)
    sources = manifest.get("sources", [])
    window = manifest.get("window") or {}
    start = parse_time(window.get("start"))
    end = parse_time(window.get("end"))
    rows: list[dict[str, Any]] = []
    for source in sources:
        host = source.get("host")
        root = Path(source.get("root", "")).expanduser()
        if not root.exists():
            rows.append({"host": host, "path": root.as_posix(), "status": "missing", "coverage_gap": "source root missing"})
            continue
        for rollout in source_rollouts(Source(str(host), root)):
            size = rollout.stat().st_size
            row = {"host": host, "path": rollout.as_posix(), "bytes": size}
            if size > args.max_raw_bytes:
                rollout_date = rollout_date_from_path(rollout)
                if rollout_date and end and rollout_date >= end:
                    continue
                row["status"] = "oversized"
                row["coverage_gap"] = "rollout exceeds max raw shard bytes; use bounded rollout-summary before extractor handoff"
                rows.append(row)
                continue
            if rollout_has_record_in_window(rollout, start, end):
                row["status"] = "ready"
                rows.append(row)
    write_jsonl(output / "shards.jsonl", rows)
    print(output / "shards.jsonl")
    return 0


def cmd_validate_output(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    required = {
        "turn_summaries.jsonl": {"turn_id", "episode_id", "host", "redacted_user_prompt_summary", "issue_flags"},
        "episodes.jsonl": {"episode_id", "host", "topic", "friction_flags"},
        "turn_flags.jsonl": {"turn_id", "episode_id", "issue_flags"},
    }
    for name, keys in required.items():
        path = run_dir / name
        if not path.exists():
            raise SystemExit(f"missing output: {path}")
        for line_no, obj in iter_jsonl(path):
            missing = keys - set(obj)
            if missing:
                raise SystemExit(f"{path}:{line_no}: missing keys {sorted(missing)}")
    json.loads((run_dir / "trend_report.json").read_text(encoding="utf-8"))
    json.loads((run_dir / "shard_manifest.json").read_text(encoding="utf-8"))
    print(f"validated: {run_dir}")
    return 0


def add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", action="append", help="Source in HOST=PATH form. Defaults to local=~/.codex.")
    parser.add_argument("--state", help="State JSON path for incremental runs.")
    parser.add_argument("--output", required=True, help="Output directory for retrospective artifacts.")
    parser.add_argument("--max-raw-bytes", type=int, default=512_000, help="Skip raw extraction for larger rollout files and report a coverage gap.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build redacted Codex session retrospective artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    daily = subparsers.add_parser("scan-daily")
    add_common_scan_args(daily)
    daily.add_argument("--active-lookback-days", type=int, default=14)
    daily.set_defaults(func=cmd_scan_daily)

    weekly = subparsers.add_parser("scan-weekly")
    add_common_scan_args(weekly)
    weekly.add_argument("--days", type=int, default=7)
    weekly.set_defaults(func=cmd_scan_weekly)

    baseline = subparsers.add_parser("baseline")
    add_common_scan_args(baseline)
    baseline.add_argument("--window-days", type=int, default=90)
    baseline.add_argument("--from", dest="from_value", default="first")
    baseline.set_defaults(func=cmd_baseline)

    shards = subparsers.add_parser("make-shards")
    shards.add_argument("--manifest", required=True)
    shards.add_argument("--output", required=True)
    shards.add_argument("--max-raw-bytes", type=int, default=512_000)
    shards.set_defaults(func=cmd_make_shards)

    validate = subparsers.add_parser("validate-output")
    validate.add_argument("--run-dir", required=True)
    validate.set_defaults(func=cmd_validate_output)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
