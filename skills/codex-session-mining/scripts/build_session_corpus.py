#!/usr/bin/env python3
"""Build a bounded, cross-root Codex rollout corpus without losing suffixes."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable


UTC = dt.timezone.utc
SESSION_ID_RE = re.compile(
    r"(?P<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)
ROLLOUT_DATE_RE = re.compile(r"rollout-(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})")
VOLATILE_KEYS = frozenset({"timestamp", "ts", "created_at", "updated_at"})
REPLAY_EVIDENCE_TYPES = frozenset(
    {
        "agent_message",
        "computer_call",
        "computer_tool_call",
        "custom_tool_call",
        "custom_tool_call_output",
        "function_call",
        "function_call_output",
        "reasoning",
        "task_complete",
        "web_search_call",
    }
)


class CorpusError(RuntimeError):
    """A corpus cannot be trusted because an input or inventory step failed."""


@dataclass(frozen=True, slots=True)
class Record:
    line_no: int
    fingerprint: str
    timestamp: dt.datetime | None
    replay_evidence: bool


@dataclass(frozen=True, slots=True)
class RolloutMetadata:
    path: Path
    source: str
    lifecycle_id: str | None
    filename_session_id: str | None
    content_sha256: str
    source_bytes: int
    fallback_timestamp: dt.datetime | None
    first_timestamp: dt.datetime | None
    has_record_timestamp: bool
    has_in_window_record: bool
    fallback_accepted: bool
    record_count: int

    @property
    def accepted(self) -> bool:
        return self.has_in_window_record or self.fallback_accepted


@dataclass(frozen=True, slots=True)
class Rollout:
    path: Path
    source: str
    records: tuple[Record, ...]
    lifecycle_id: str | None
    filename_session_id: str | None
    content_sha256: str
    fallback_timestamp: dt.datetime | None
    first_timestamp: dt.datetime | None


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parents = list(range(size))

    def find(self, item: int) -> int:
        parent = self.parents[item]
        if parent != item:
            self.parents[item] = self.find(parent)
        return self.parents[item]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parents[right_root] = left_root


def parse_instant(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def maybe_instant(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return parse_instant(value)
    except argparse.ArgumentTypeError:
        return None


def normalized_fingerprint_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): normalized_fingerprint_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [normalized_fingerprint_value(item) for item in value]
    return value


def record_fingerprint(row: dict[str, Any]) -> str:
    stable = normalized_fingerprint_value(row)
    if not isinstance(stable, dict):
        raise TypeError("normalized rollout record must remain an object")
    for key in VOLATILE_KEYS:
        stable.pop(key, None)
    payload = stable.get("payload")
    if isinstance(payload, dict):
        for key in VOLATILE_KEYS:
            payload.pop(key, None)
    encoded = json.dumps(
        stable,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def record_timestamp(row: dict[str, Any]) -> dt.datetime | None:
    payload = row.get("payload")
    sources = [row]
    if isinstance(payload, dict):
        sources.append(payload)
    for source in sources:
        for key in ("timestamp", "ts", "created_at", "updated_at"):
            parsed = maybe_instant(source.get(key))
            if parsed is not None:
                return parsed
    return None


def record_lifecycle_id(row: dict[str, Any]) -> str | None:
    payload = row.get("payload")
    payload_type = payload.get("type") if isinstance(payload, dict) else None
    if row.get("type") != "session_meta" and payload_type != "session_meta":
        return None
    sources = [payload, row]
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("id", "session_id", "thread_id"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def record_replay_evidence(row: dict[str, Any]) -> bool:
    payload = row.get("payload")
    sources = [payload, row]
    for source in sources:
        if not isinstance(source, dict):
            continue
        role = source.get("role")
        if role == "assistant":
            return True
        record_type = source.get("type")
        if isinstance(record_type, str) and record_type in REPLAY_EVIDENCE_TYPES:
            return True
    return False


def filename_session_id(path: Path) -> str | None:
    match = SESSION_ID_RE.search(path.name)
    return match.group("id").lower() if match else None


def fallback_path_timestamp(path: Path, root: Path) -> dt.datetime | None:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return None
    for index in range(max(0, len(relative_parts) - 3)):
        year, month, day = relative_parts[index : index + 3]
        if not (year.isdigit() and month.isdigit() and day.isdigit()):
            continue
        try:
            return dt.datetime(int(year), int(month), int(day), tzinfo=UTC)
        except ValueError:
            continue
    match = ROLLOUT_DATE_RE.search(path.name)
    if match is None:
        return None
    try:
        return dt.datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            tzinfo=UTC,
        )
    except ValueError:
        return None


def inventory_root(root: Path) -> list[Path]:
    try:
        root_mode = root.lstat().st_mode
    except FileNotFoundError:
        return []
    except OSError as error:
        raise CorpusError(f"unable to inspect rollout root {root}: {error}") from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise CorpusError(f"unsafe rollout root: {root}")
    resolved_root = root.resolve(strict=True)
    paths: list[Path] = []

    def traversal_error(error: OSError) -> None:
        raise CorpusError(f"unable to inventory rollout root {root}: {error}") from error

    try:
        for current, directories, filenames in os.walk(
            root,
            topdown=True,
            onerror=traversal_error,
            followlinks=False,
        ):
            directories.sort()
            filenames.sort()
            current_path = Path(current)
            for directory in directories:
                path = current_path / directory
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    raise CorpusError(f"unsafe rollout directory: {path}")
            for filename in filenames:
                if not filename.startswith("rollout-") or not filename.endswith(".jsonl"):
                    continue
                if filename.startswith("rollout-summary"):
                    continue
                path = current_path / filename
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                    raise CorpusError(f"unsafe rollout candidate: {path}")
                try:
                    path.resolve(strict=True).relative_to(resolved_root)
                except (OSError, ValueError) as error:
                    raise CorpusError(f"rollout candidate escapes root: {path}") from error
                paths.append(path)
    except OSError as error:
        raise CorpusError(f"unable to inventory rollout root {root}: {error}") from error
    return sorted(paths)


def scan_rollout_metadata(
    path: Path,
    source: str,
    root: Path,
    start: dt.datetime,
    end: dt.datetime,
) -> RolloutMetadata:
    lifecycle_id: str | None = None
    digest = hashlib.sha256()
    source_bytes = 0
    first_timestamp: dt.datetime | None = None
    has_record_timestamp = False
    has_in_window_record = False
    record_count = 0
    try:
        with path.open("rb") as handle:
            for line_no, raw_line in enumerate(handle, 1):
                digest.update(raw_line)
                source_bytes += len(raw_line)
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise CorpusError(f"invalid rollout JSON at {path}:{line_no}") from error
                if not isinstance(row, dict):
                    raise CorpusError(f"non-object rollout record at {path}:{line_no}")
                lifecycle_id = lifecycle_id or record_lifecycle_id(row)
                timestamp = record_timestamp(row)
                record_count += 1
                if timestamp is not None:
                    has_record_timestamp = True
                    first_timestamp = (
                        timestamp
                        if first_timestamp is None
                        else min(first_timestamp, timestamp)
                    )
                    has_in_window_record = has_in_window_record or in_window(
                        timestamp,
                        start,
                        end,
                    )
    except OSError as error:
        raise CorpusError(f"unable to read rollout {path}: {error}") from error
    fallback_timestamp = fallback_path_timestamp(path, root)
    return RolloutMetadata(
        path=path,
        source=source,
        lifecycle_id=lifecycle_id,
        filename_session_id=filename_session_id(path),
        content_sha256=digest.hexdigest(),
        source_bytes=source_bytes,
        fallback_timestamp=fallback_timestamp,
        first_timestamp=first_timestamp or fallback_timestamp,
        has_record_timestamp=has_record_timestamp,
        has_in_window_record=has_in_window_record,
        fallback_accepted=(
            not has_record_timestamp and in_window(fallback_timestamp, start, end)
        ),
        record_count=record_count,
    )


def load_rollout_records(metadata: RolloutMetadata) -> Rollout:
    records: list[Record] = []
    digest = hashlib.sha256()
    try:
        with metadata.path.open("rb") as handle:
            remaining = metadata.source_bytes
            line_no = 0
            while remaining:
                raw_line = handle.readline(remaining)
                if not raw_line:
                    raise CorpusError(
                        f"rollout was truncated during corpus construction: {metadata.path}"
                    )
                remaining -= len(raw_line)
                line_no += 1
                digest.update(raw_line)
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise CorpusError(
                        f"rollout changed or became invalid at {metadata.path}:{line_no}"
                    ) from error
                if not isinstance(row, dict):
                    raise CorpusError(
                        f"rollout changed or became non-object at {metadata.path}:{line_no}"
                    )
                records.append(
                    Record(
                        line_no=line_no,
                        fingerprint=record_fingerprint(row),
                        timestamp=record_timestamp(row),
                        replay_evidence=record_replay_evidence(row),
                    )
                )
    except OSError as error:
        raise CorpusError(f"unable to reread rollout {metadata.path}: {error}") from error
    if digest.hexdigest() != metadata.content_sha256 or len(records) != metadata.record_count:
        raise CorpusError(
            f"rollout prefix changed during corpus construction: {metadata.path}"
        )
    return Rollout(
        path=metadata.path,
        source=metadata.source,
        records=tuple(records),
        lifecycle_id=metadata.lifecycle_id,
        filename_session_id=metadata.filename_session_id,
        content_sha256=metadata.content_sha256,
        fallback_timestamp=metadata.fallback_timestamp,
        first_timestamp=metadata.first_timestamp,
    )


def common_prefix_length(left: Rollout, right: Rollout) -> int:
    count = 0
    for left_record, right_record in zip(left.records, right.records):
        if left_record.fingerprint != right_record.fingerprint:
            break
        count += 1
    return count


def confirmed_replay_prefix_length(left: Rollout, right: Rollout) -> int:
    prefix = common_prefix_length(left, right)
    if prefix == 0:
        return 0
    if left.content_sha256 == right.content_sha256:
        return prefix
    if any(record.replay_evidence for record in left.records[:prefix]):
        return prefix
    return 0


def group_metadata(metadata: list[RolloutMetadata]) -> list[list[RolloutMetadata]]:
    """Build broad groups before loading fingerprint sequences.

    Filename IDs are candidate keys at this stage. The second pass splits candidates
    whose ordered fingerprints do not actually match.
    """

    union_find = UnionFind(len(metadata))
    lifecycle_owner: dict[str, int] = {}
    content_owner: dict[tuple[str, str], int] = {}
    filename_owner: dict[str, int] = {}
    for index, rollout in enumerate(metadata):
        if rollout.lifecycle_id is not None:
            owner = lifecycle_owner.setdefault(rollout.lifecycle_id, index)
            union_find.union(owner, index)
        content_identity = rollout.lifecycle_id or rollout.filename_session_id
        if content_identity is not None:
            owner = content_owner.setdefault(
                (content_identity, rollout.content_sha256),
                index,
            )
            union_find.union(owner, index)
        if rollout.filename_session_id is not None:
            owner = filename_owner.setdefault(rollout.filename_session_id, index)
            union_find.union(owner, index)
    groups: dict[int, list[RolloutMetadata]] = {}
    for index, rollout in enumerate(metadata):
        groups.setdefault(union_find.find(index), []).append(rollout)
    return list(groups.values())


def group_rollouts(rollouts: list[Rollout]) -> list[list[Rollout]]:
    union_find = UnionFind(len(rollouts))
    lifecycle_owner: dict[str, int] = {}
    content_owner: dict[tuple[str, str], int] = {}
    filename_members: dict[str, list[int]] = {}
    for index, rollout in enumerate(rollouts):
        if rollout.lifecycle_id is not None:
            owner = lifecycle_owner.setdefault(rollout.lifecycle_id, index)
            union_find.union(owner, index)
        content_identity = rollout.lifecycle_id or rollout.filename_session_id
        if content_identity is not None:
            owner = content_owner.setdefault(
                (content_identity, rollout.content_sha256),
                index,
            )
            union_find.union(owner, index)
        if rollout.filename_session_id is not None:
            filename_members.setdefault(rollout.filename_session_id, []).append(index)
    for members in filename_members.values():
        for offset, left_index in enumerate(members):
            for right_index in members[offset + 1 :]:
                if common_prefix_length(rollouts[left_index], rollouts[right_index]) > 0:
                    union_find.union(left_index, right_index)
    groups: dict[int, list[Rollout]] = {}
    for index, rollout in enumerate(rollouts):
        groups.setdefault(union_find.find(index), []).append(rollout)
    return list(groups.values())


def in_window(value: dt.datetime | None, start: dt.datetime, end: dt.datetime) -> bool:
    return value is not None and start <= value < end


def line_ranges(lines: list[int]) -> list[list[int]]:
    ranges: list[list[int]] = []
    for line in lines:
        if not ranges or line != ranges[-1][1] + 1:
            ranges.append([line, line])
        else:
            ranges[-1][1] = line
    return ranges


def rollout_sort_key(rollout: Rollout) -> tuple[dt.datetime, int, int, str]:
    first = rollout.first_timestamp or dt.datetime.max.replace(tzinfo=UTC)
    source_rank = 0 if rollout.source == "active" else 1
    return (first, len(rollout.records), source_rank, rollout.path.as_posix())


def union_entries(
    groups: list[list[Rollout]],
    start: dt.datetime,
    end: dt.datetime,
    group_start: int,
) -> tuple[list[dict[str, object]], int, int, int]:
    entries: list[dict[str, object]] = []
    replayed_record_count = 0
    collapsed_rollout_count = 0
    accepted_group_count = 0
    ordered_groups = sorted(groups, key=lambda item: min(map(rollout_sort_key, item)))
    for group_index, group in enumerate(ordered_groups, group_start):
        histories: list[Rollout] = []
        group_accepted = False
        for rollout in sorted(group, key=rollout_sort_key):
            prefix = max(
                (
                    confirmed_replay_prefix_length(rollout, previous)
                    for previous in histories
                ),
                default=0,
            )
            replayed_record_count += prefix
            unique_records = rollout.records[prefix:]
            relevant_lines = [
                record.line_no
                for record in unique_records
                if in_window(record.timestamp, start, end)
            ]
            fallback_accepted = (
                not any(record.timestamp is not None for record in rollout.records)
                and in_window(rollout.fallback_timestamp, start, end)
                and (bool(unique_records) or not rollout.records)
                and not (histories and prefix == len(rollout.records))
            )
            if fallback_accepted:
                relevant_lines = [record.line_no for record in unique_records]
            if prefix == len(rollout.records) and histories:
                collapsed_rollout_count += 1
            if relevant_lines or fallback_accepted:
                group_accepted = True
                entries.append(
                    {
                        "accepted_line_ranges": line_ranges(relevant_lines),
                        "accepted_record_count": len(relevant_lines),
                        "fallback_date_used": fallback_accepted,
                        "group": group_index,
                        "lifecycle_id": rollout.lifecycle_id,
                        "path": rollout.path.as_posix(),
                        "replayed_prefix_records": prefix,
                        "root": rollout.source,
                        "unique_suffix_records": len(unique_records),
                    }
                )
            histories.append(rollout)
        if group_accepted:
            accepted_group_count += 1
    return entries, replayed_record_count, collapsed_rollout_count, accepted_group_count


def write_lines(path: Path, values: Iterable[str]) -> None:
    content = "".join(f"{value}\n" for value in values)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_text(
        f"{json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)}\n",
        encoding="utf-8",
    )


def build_corpus(
    codex_home: Path,
    start: dt.datetime,
    end: dt.datetime,
    output: Path,
    sample_limit: int,
) -> dict[str, object]:
    if start >= end:
        raise CorpusError("window start must be earlier than window end")
    active_root = codex_home / "sessions"
    archived_root = codex_home / "archived_sessions"
    active_paths = inventory_root(active_root)
    archived_paths = inventory_root(archived_root)
    active_metadata = [
        scan_rollout_metadata(path, "active", active_root, start, end)
        for path in active_paths
    ]
    archived_metadata = [
        scan_rollout_metadata(path, "archived", archived_root, start, end)
        for path in archived_paths
    ]
    metadata = active_metadata + archived_metadata
    active_accepted = [rollout for rollout in active_metadata if rollout.accepted]
    archived_accepted = [rollout for rollout in archived_metadata if rollout.accepted]
    entries: list[dict[str, object]] = []
    replayed_count = 0
    collapsed_count = 0
    accepted_group_count = 0
    cross_root_duplicate_groups = 0
    next_group = 1
    broad_groups = sorted(
        group_metadata(metadata),
        key=lambda group: min(rollout.path.as_posix() for rollout in group),
    )
    for broad_group in broad_groups:
        sources = {rollout.source for rollout in broad_group}
        if not any(rollout.accepted for rollout in broad_group) and sources != {
            "active",
            "archived",
        }:
            continue
        refined_groups = group_rollouts(
            [load_rollout_records(rollout) for rollout in broad_group]
        )
        cross_root_duplicate_groups += sum(
            1
            for group in refined_groups
            if {rollout.source for rollout in group} == {"active", "archived"}
        )
        new_entries, new_replayed, new_collapsed, new_accepted_groups = union_entries(
            refined_groups,
            start,
            end,
            next_group,
        )
        entries.extend(new_entries)
        replayed_count += new_replayed
        collapsed_count += new_collapsed
        accepted_group_count += new_accepted_groups
        next_group += len(refined_groups)
    counts = {
        "active_accepted": len(active_accepted),
        "active_candidate": len(active_paths),
        "active_parsed": len(active_metadata),
        "archived_accepted": len(archived_accepted),
        "archived_candidate": len(archived_paths),
        "archived_parsed": len(archived_metadata),
        "cross_root_duplicate_groups": cross_root_duplicate_groups,
        "duplicate_rollouts_collapsed": collapsed_count,
        "replayed_prefix_records": replayed_count,
        "union_accepted": len(entries),
        "union_accepted_groups": accepted_group_count,
        "union_candidate": len(metadata),
        "union_parsed": len(metadata),
    }
    manifest: dict[str, object] = {
        "counts": counts,
        "window": {
            "end_exclusive": end.isoformat().replace("+00:00", "Z"),
            "start_inclusive": start.isoformat().replace("+00:00", "Z"),
        },
    }
    try:
        output.mkdir(parents=True, exist_ok=True)
        write_lines(output / "active-paths.txt", (path.as_posix() for path in active_paths))
        write_lines(output / "archived-paths.txt", (path.as_posix() for path in archived_paths))
        write_lines(
            output / "active-accepted-paths.txt",
            (rollout.path.as_posix() for rollout in active_accepted),
        )
        write_lines(
            output / "archived-accepted-paths.txt",
            (rollout.path.as_posix() for rollout in archived_accepted),
        )
        write_lines(output / "corpus-paths.txt", (str(entry["path"]) for entry in entries))
        write_lines(
            output / "corpus.jsonl",
            (json.dumps(entry, ensure_ascii=False, sort_keys=True) for entry in entries),
        )
        write_json(output / "manifest.json", manifest)
    except OSError as error:
        raise CorpusError(f"unable to write corpus artifacts under {output}: {error}") from error
    for key in (
        "active_candidate",
        "archived_candidate",
        "union_candidate",
        "active_parsed",
        "archived_parsed",
        "union_parsed",
        "active_accepted",
        "archived_accepted",
        "union_accepted",
        "cross_root_duplicate_groups",
        "duplicate_rollouts_collapsed",
        "replayed_prefix_records",
    ):
        print(f"{key.replace('_', ' ')} count: {counts[key]}")
    for entry in entries[:sample_limit]:
        ranges = entry["accepted_line_ranges"]
        range_sample = ranges[:3] if isinstance(ranges, list) else []
        print(
            "sample: "
            f"{entry['root']}:{entry['path']}:"
            f"accepted_records={entry['accepted_record_count']}:"
            f"line_ranges={range_sample}:"
            f"replayed_prefix={entry['replayed_prefix_records']}"
        )
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--codex-home", type=Path, required=True)
    result.add_argument("--start", type=parse_instant, required=True)
    result.add_argument("--end", type=parse_instant, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--sample-limit", type=int, default=20)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.sample_limit < 0:
        parser().error("--sample-limit must be non-negative")
    try:
        build_corpus(
            args.codex_home.expanduser(),
            args.start,
            args.end,
            args.output.expanduser(),
            args.sample_limit,
        )
    except CorpusError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
