from __future__ import annotations

from collections.abc import Iterator
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/codex-session-mining/scripts/build_session_corpus.py"
SPEC = importlib.util.spec_from_file_location("codex_session_corpus", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {SCRIPT}")
CORPUS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORPUS
SPEC.loader.exec_module(CORPUS)


def record(timestamp: str, payload_type: str, **payload: object) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "type": payload_type,
        "payload": {"type": payload_type, **payload},
    }


def write_rollout(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{json.dumps(row, sort_keys=True)}\n" for row in rows),
        encoding="utf-8",
    )


class SessionCorpusTests(unittest.TestCase):
    def run_corpus(
        self,
        codex_home: Path,
        output: Path,
        *,
        start: str = "2026-07-16T00:00:00Z",
        end: str = "2026-07-17T00:00:00Z",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--codex-home",
                str(codex_home),
                "--start",
                start,
                "--end",
                end,
                "--output",
                str(output),
                "--sample-limit",
                "2",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_cross_root_prefix_dedup_preserves_human_suffix_and_old_path_followup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            first_id = "019f6935-43ab-7702-a9f1-3b3c42c3b88f"
            second_id = "019f693c-9a29-7e01-a22b-503d9c9c7f76"
            active_original = (
                codex_home
                / "sessions/2026/01/01"
                / f"rollout-2026-01-01T01-00-00-{first_id}.jsonl"
            )
            archived_continuation = (
                codex_home
                / "archived_sessions/2026/01/01"
                / f"rollout-2026-01-01T01-00-00-{first_id}.jsonl"
            )
            old_path_followup = (
                codex_home
                / "sessions/2026/02/02"
                / f"rollout-2026-02-02T02-00-00-{second_id}.jsonl"
            )
            flat_archived_copy = (
                codex_home
                / "archived_sessions"
                / f"rollout-2026-02-02T02-00-00-{second_id}.jsonl"
            )
            original_rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=first_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            continuation_rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=first_id),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
                record(
                    "2026-07-16T02:00:00Z",
                    "response_item",
                    role="user",
                    text="genuine human follow-up",
                ),
            ]
            followup_rows = [
                record("2026-07-16T03:00:00Z", "session_meta", id=second_id),
                record(
                    "2026-07-16T03:01:00Z",
                    "response_item",
                    role="user",
                    text="continued from an old dated path",
                ),
            ]
            write_rollout(active_original, original_rows)
            write_rollout(archived_continuation, continuation_rows)
            write_rollout(old_path_followup, followup_rows)
            write_rollout(flat_archived_copy, followup_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["counts"],
                {
                    "active_accepted": 1,
                    "active_candidate": 2,
                    "active_parsed": 2,
                    "archived_accepted": 2,
                    "archived_candidate": 2,
                    "archived_parsed": 2,
                    "cross_root_duplicate_groups": 2,
                    "duplicate_rollouts_collapsed": 1,
                    "replayed_prefix_records": 5,
                    "union_accepted": 2,
                    "union_accepted_groups": 2,
                    "union_candidate": 4,
                    "union_parsed": 4,
                },
            )
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(
                set(by_path), {str(archived_continuation), str(old_path_followup)}
            )
            self.assertEqual(
                by_path[str(archived_continuation)]["accepted_line_ranges"], [[4, 4]]
            )
            self.assertEqual(
                by_path[str(archived_continuation)]["accepted_record_count"], 1
            )
            self.assertEqual(
                by_path[str(archived_continuation)]["replayed_prefix_records"], 3
            )
            self.assertEqual(
                by_path[str(old_path_followup)]["accepted_line_ranges"], [[1, 2]]
            )
            self.assertEqual(
                by_path[str(old_path_followup)]["accepted_record_count"], 2
            )
            self.assertNotIn(
                str(active_original), (output / "corpus-paths.txt").read_text()
            )
            self.assertRegex(completed.stdout, r"active candidate count: 2")
            self.assertRegex(completed.stdout, r"archived accepted count: 2")
            self.assertRegex(completed.stdout, r"union accepted count: 2")
            self.assertIn("accepted_records=1:line_ranges=[[4, 4]]", completed.stdout)

    def test_short_archived_prefix_owns_replay_before_long_active_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b7e-a3dd-7193-acaf-18ef0a912d1b"
            archived = (
                codex_home / "archived_sessions" / f"rollout-old-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-continued-{session_id}.jsonl"
            )
            archived_rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            active_rows = [
                archived_rows[0],
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
                record(
                    "2026-07-16T02:00:00Z",
                    "response_item",
                    role="user",
                    text="genuine suffix",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], str(active))
            self.assertEqual(entries[0]["accepted_line_ranges"], [[4, 4]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 3)

    def test_uppercase_lifecycle_uuid_matches_lowercase_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b7e-a3dd-7193-acaf-18ef0a912d1c"
            archived = (
                codex_home / "archived_sessions" / f"rollout-old-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-continued-{session_id}.jsonl"
            )
            archived_rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            active_rows = [
                record(
                    "2026-07-16T01:00:00Z",
                    "session_meta",
                    id=session_id.upper(),
                ),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
                record(
                    "2026-07-16T02:00:00Z",
                    "response_item",
                    role="user",
                    text="genuine suffix",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], str(active))
            self.assertEqual(entries[0]["owner_id"], session_id)
            self.assertEqual(entries[0]["accepted_line_ranges"], [[4, 4]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 3)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 1)

    def test_opaque_lifecycle_ids_preserve_case(self) -> None:
        upper = record("2026-07-16T01:00:00Z", "session_meta", id="Opaque-ID")
        lower = record("2026-07-16T01:00:00Z", "session_meta", id="opaque-id")

        self.assertEqual(CORPUS.record_lifecycle_ids(upper), ("Opaque-ID",))
        self.assertEqual(CORPUS.record_lifecycle_ids(lower), ("opaque-id",))

    def test_older_long_source_owns_short_restamped_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b90-f29c-7b92-8479-ec64017caeca"
            archived = (
                codex_home / "archived_sessions" / f"rollout-source-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-restamped-{session_id}.jsonl"
            )
            archived_rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
                record(
                    "2026-01-01T01:03:00Z",
                    "function_call_output",
                    output="old tool result",
                ),
            ]
            active_rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((output / "corpus.jsonl").read_text(encoding="utf-8"), "")
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 3)

    def test_complete_timestamp_source_owns_partial_restamped_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b90-f29c-7b92-8479-ec64017caecb"
            archived = (
                codex_home / "archived_sessions" / f"rollout-source-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-restamped-{session_id}.jsonl"
            )
            archived_rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
                record(
                    "2026-01-01T01:03:00Z",
                    "function_call_output",
                    output="old tool result",
                ),
            ]
            active_rows = [
                archived_rows[0],
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((output / "corpus.jsonl").read_text(encoding="utf-8"), "")
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 3)

    def test_complete_timestamp_coverage_owns_sparse_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b90-f29c-7b92-8479-ec64017caecc"
            sparse = (
                codex_home / "archived_sessions" / f"rollout-sparse-{session_id}.jsonl"
            )
            complete = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-complete-{session_id}.jsonl"
            )
            complete_rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="current task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="current result",
                ),
            ]
            sparse_rows = [dict(row) for row in complete_rows]
            sparse_rows[1].pop("timestamp")
            sparse_rows[2].pop("timestamp")
            write_rollout(sparse, sparse_rows)
            write_rollout(complete, complete_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], str(complete))
            self.assertEqual(entries[0]["accepted_line_ranges"], [[1, 3]])
            self.assertEqual(entries[0]["accepted_record_count"], 3)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 3)

    def test_fallback_provenance_orders_timestamp_less_restamp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b90-f29c-7b92-8479-ec64017caecd"
            archived = (
                codex_home
                / "archived_sessions"
                / f"rollout-2026-01-01T01-00-00-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-2026-07-16T01-00-00-{session_id}.jsonl"
            )
            rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            timestamp_less_rows = [dict(row) for row in rows]
            for row in timestamp_less_rows:
                row.pop("timestamp")
            write_rollout(archived, timestamp_less_rows)
            write_rollout(active, timestamp_less_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((output / "corpus.jsonl").read_text(encoding="utf-8"), "")
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 3)

    def test_missing_fallback_does_not_hide_sparse_window_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b90-f29c-7b92-8479-ec64017caece"
            unknown = (
                codex_home
                / "archived_sessions"
                / f"rollout-unknown-{session_id}.jsonl"
            )
            sparse = (
                codex_home
                / "sessions"
                / f"rollout-sparse-{session_id}.jsonl"
            )
            rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="current task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="current result",
                ),
            ]
            unknown_rows = [dict(row) for row in rows]
            for row in unknown_rows:
                row.pop("timestamp")
            sparse_rows = [dict(row) for row in unknown_rows]
            sparse_rows[2]["timestamp"] = "2026-07-16T01:02:00Z"
            write_rollout(unknown, unknown_rows)
            write_rollout(sparse, sparse_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], str(sparse))
            self.assertEqual(entries[0]["accepted_line_ranges"], [[3, 3]])
            self.assertEqual(entries[0]["accepted_record_count"], 1)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 3)

    def test_later_old_timestamp_anchors_sparse_source_before_restamp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b90-f29c-7b92-8479-ec64017caecf"
            archived = (
                codex_home
                / "archived_sessions"
                / f"rollout-source-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions"
                / f"rollout-restamped-{session_id}.jsonl"
            )
            archived_rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            archived_rows[0].pop("timestamp")
            active_rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((output / "corpus.jsonl").read_text(encoding="utf-8"), "")
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 3)

    def test_replay_prefix_ignores_session_meta_environment_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6c4c-4f35-7139-a601-54d91db64c34"
            archived = (
                codex_home / "archived_sessions" / f"rollout-old-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-restamped-{session_id}.jsonl"
            )
            archived_rows = [
                record(
                    "2026-01-01T01:00:00Z",
                    "session_meta",
                    id=session_id,
                    cli_version="0.143.0",
                    cwd="/old/worktree",
                    model="gpt-old",
                    model_id="model-old",
                    model_provider="old-provider",
                    originator="codex_cli_rs",
                    source="cli",
                    thread_source="old-terminal",
                    context_window=100_000,
                    history_mode="legacy",
                    base_instructions="old instructions",
                    git={"branch": "old", "commit_hash": "old-commit"},
                ),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-01-01T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            active_rows = [
                record(
                    "2026-07-16T01:00:00Z",
                    "session_meta",
                    id=session_id,
                    cli_version="0.144.3",
                    cwd="/new/worktree",
                    model="gpt-new",
                    model_id="model-new",
                    model_provider="new-provider",
                    originator="codex_exec",
                    source="exec",
                    thread_source="new-subagent",
                    context_window=200_000,
                    history_mode="forked",
                    base_instructions="new instructions",
                    git={"branch": "new", "commit_hash": "new-commit"},
                ),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="old task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
                record(
                    "2026-07-16T02:00:00Z",
                    "response_item",
                    role="user",
                    text="genuine suffix",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], str(active))
            self.assertEqual(entries[0]["accepted_line_ranges"], [[4, 4]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 3)

    def test_replay_prefix_ignores_turn_context_runtime_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6c4c-4f35-7139-a601-54d91db64c39"
            archived = (
                codex_home / "archived_sessions" / f"rollout-old-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-restamped-{session_id}.jsonl"
            )

            def replayed_rows(day: str, cwd: str, model: str) -> list[dict[str, object]]:
                return [
                    record(f"{day}T01:00:00Z", "session_meta", id=session_id),
                    record(
                        f"{day}T01:01:00Z",
                        "turn_context",
                        cwd=cwd,
                        model=model,
                        sandbox_policy="read-only" if day < "2026-07-16" else "workspace-write",
                        base_instructions=f"instructions for {cwd}",
                    ),
                    record(
                        f"{day}T01:02:00Z",
                        "response_item",
                        role="assistant",
                        text="old result",
                    ),
                ]

            write_rollout(
                archived,
                replayed_rows("2026-01-01", "/old/worktree", "gpt-old"),
            )
            active_rows = replayed_rows(
                "2026-07-16", "/new/worktree", "gpt-new"
            )
            active_rows.append(
                record(
                    "2026-07-16T02:00:00Z",
                    "response_item",
                    role="user",
                    text="genuine suffix",
                )
            )
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["accepted_line_ranges"], [[4, 4]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 3)

    def test_replay_prefix_ignores_incidental_response_and_call_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6c4c-4f35-7139-a601-54d91db64c35"
            archived = (
                codex_home / "archived_sessions" / f"rollout-old-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-restamped-{session_id}.jsonl"
            )

            def execution_rows(
                prefix: str, timestamp_prefix: str
            ) -> list[dict[str, object]]:
                return [
                    record(
                        f"{timestamp_prefix}T01:00:00Z",
                        "session_meta",
                        id=session_id,
                    ),
                    record(
                        f"{timestamp_prefix}T01:01:00Z",
                        "function_call",
                        id=f"fc-{prefix}",
                        call_id=f"call-{prefix}",
                        name="exec_command",
                        arguments='{"cmd":"git status --short"}',
                    ),
                    record(
                        f"{timestamp_prefix}T01:02:00Z",
                        "function_call_output",
                        call_id=f"call-{prefix}",
                        output="clean",
                    ),
                    record(
                        f"{timestamp_prefix}T01:03:00Z",
                        "response_item",
                        id=f"message-{prefix}",
                        role="assistant",
                        text="working tree is clean",
                    ),
                ]

            write_rollout(archived, execution_rows("old", "2026-01-01"))
            active_rows = execution_rows("new", "2026-07-16")
            active_rows.append(
                record(
                    "2026-07-16T02:00:00Z",
                    "response_item",
                    role="user",
                    text="genuine suffix",
                )
            )
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["accepted_line_ranges"], [[5, 5]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 4)

    def test_computer_call_outputs_normalize_call_ids_and_are_replay_evidence(
        self,
    ) -> None:
        for call_type, output_type in (
            ("computer_call", "computer_call_output"),
            ("computer_tool_call", "computer_tool_call_output"),
        ):
            with self.subTest(output_type=output_type):
                def fingerprints(prefix: str) -> tuple[list[str], dict[str, object]]:
                    rows = [
                        record(
                            "2026-07-16T01:00:00Z",
                            call_type,
                            id=f"item-{prefix}",
                            call_id=f"call-{prefix}",
                            action={"type": "screenshot"},
                        ),
                        record(
                            "2026-07-16T01:01:00Z",
                            output_type,
                            call_id=f"call-{prefix}",
                            output="same screenshot",
                        ),
                    ]
                    state = CORPUS.GeneratedIdCanonicalizer()
                    return (
                        [CORPUS.record_fingerprint(row, state) for row in rows],
                        rows[1],
                    )

                old_fingerprints, old_output = fingerprints("old")
                new_fingerprints, new_output = fingerprints("new")
                self.assertEqual(old_fingerprints, new_fingerprints)
                self.assertTrue(CORPUS.record_replay_evidence(old_output))
                self.assertTrue(CORPUS.record_replay_evidence(new_output))

    def test_nested_domain_ids_remain_in_replay_fingerprints(self) -> None:
        first = record(
            "2026-07-16T01:00:00Z",
            "function_call_output",
            output={"id": "ISSUE-1", "status": "open"},
        )
        second = record(
            "2026-07-16T02:00:00Z",
            "function_call_output",
            output={"id": "ISSUE-2", "status": "open"},
        )
        self.assertNotEqual(
            CORPUS.record_fingerprint(first),
            CORPUS.record_fingerprint(second),
        )

    def test_generated_id_canonicalization_preserves_linkage_and_unknown_ids(
        self,
    ) -> None:
        def fingerprints(rows: list[dict[str, object]]) -> list[str]:
            state = CORPUS.GeneratedIdCanonicalizer()
            return [CORPUS.record_fingerprint(row, state) for row in rows]

        source = [
            record(
                "2026-01-01T01:00:00Z",
                "function_call",
                id="item-old",
                call_id="call-old",
                name="exec_command",
                arguments='{"cmd":"git status --short"}',
            ),
            record(
                "2026-01-01T01:01:00Z",
                "function_call_output",
                call_id="call-old",
                output="clean",
            ),
        ]
        broken_copy = [
            record(
                "2026-07-16T01:00:00Z",
                "function_call",
                id="item-new",
                call_id="call-new",
                name="exec_command",
                arguments='{"cmd":"git status --short"}',
            ),
            record(
                "2026-07-16T01:01:00Z",
                "function_call_output",
                call_id="orphan-output",
                output="clean",
            ),
        ]
        source_fingerprints = fingerprints(source)
        copy_fingerprints = fingerprints(broken_copy)
        self.assertEqual(source_fingerprints[0], copy_fingerprints[0])
        self.assertNotEqual(source_fingerprints[1], copy_fingerprints[1])

        def turn_rows(first_turn: str, second_turn: str) -> list[dict[str, object]]:
            return [
                record(
                    "2026-07-16T01:00:00Z",
                    "response_item",
                    id="message-one",
                    role="assistant",
                    text="one",
                    internal_chat_message_metadata_passthrough={"turn_id": first_turn},
                ),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    id="message-two",
                    role="assistant",
                    text="two",
                    internal_chat_message_metadata_passthrough={"turn_id": second_turn},
                ),
            ]

        one_turn = fingerprints(turn_rows("turn-old", "turn-old"))
        replayed_one_turn = fingerprints(turn_rows("turn-new", "turn-new"))
        split_turns = fingerprints(turn_rows("turn-new-one", "turn-new-two"))
        self.assertEqual(one_turn, replayed_one_turn)
        self.assertEqual(one_turn[0], split_turns[0])
        self.assertNotEqual(one_turn[1], split_turns[1])

        orphan_old = record(
            "2026-01-01T01:00:00Z",
            "function_call_output",
            call_id="orphan-old",
            output="same",
        )
        orphan_new = record(
            "2026-07-16T01:00:00Z",
            "function_call_output",
            call_id="orphan-new",
            output="same",
        )
        self.assertNotEqual(
            CORPUS.record_fingerprint(orphan_old),
            CORPUS.record_fingerprint(orphan_new),
        )

        unknown_old = record(
            "2026-01-01T01:00:00Z",
            "future_record",
            id="domain-old",
            value="same",
        )
        unknown_new = record(
            "2026-07-16T01:00:00Z",
            "future_record",
            id="domain-new",
            value="same",
        )
        self.assertNotEqual(
            CORPUS.record_fingerprint(unknown_old),
            CORPUS.record_fingerprint(unknown_new),
        )

        lifecycle_old = record(
            "2026-01-01T01:00:00Z",
            "session_meta",
            id="019f6c4c-4f35-7139-a601-54d91db64c37",
            cwd="/old",
        )
        lifecycle_new = record(
            "2026-07-16T01:00:00Z",
            "session_meta",
            id="019f6c4c-4f35-7139-a601-54d91db64c38",
            cwd="/new",
        )
        self.assertNotEqual(
            CORPUS.record_fingerprint(lifecycle_old),
            CORPUS.record_fingerprint(lifecycle_new),
        )

    def test_prompt_only_repeat_under_one_lifecycle_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6ba6-6b81-7cb1-bb7e-4b8ab4dc66cd"
            archived = (
                codex_home / "archived_sessions" / f"rollout-old-{session_id}.jsonl"
            )
            active = (
                codex_home / "sessions/2026/07/16" / f"rollout-new-{session_id}.jsonl"
            )
            write_rollout(
                archived,
                [
                    record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                    record(
                        "2026-01-01T01:01:00Z",
                        "response_item",
                        role="user",
                        text="retry task",
                    ),
                ],
            )
            write_rollout(
                active,
                [
                    record("2026-07-16T01:00:00Z", "session_meta", id=session_id),
                    record(
                        "2026-07-16T01:01:00Z",
                        "response_item",
                        role="user",
                        text="retry task",
                    ),
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], str(active))
            self.assertEqual(entries[0]["accepted_line_ranges"], [[1, 2]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 0)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)

    def test_cross_root_metric_requires_replay_or_collapsed_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6ba6-6b81-7cb1-bb7e-4b8ab4dc66cf"
            active = (
                codex_home / "sessions/2026/07/16" / f"rollout-a-{session_id}.jsonl"
            )
            archived = (
                codex_home / "archived_sessions" / f"rollout-b-{session_id}.jsonl"
            )
            write_rollout(
                active,
                [
                    record("2026-07-16T01:00:00Z", "session_meta", id=session_id),
                    record(
                        "2026-07-16T01:01:00Z",
                        "response_item",
                        role="user",
                        text="active task",
                    ),
                ],
            )
            write_rollout(
                archived,
                [
                    record("2026-07-16T02:00:00Z", "session_meta", id=session_id),
                    record(
                        "2026-07-16T02:01:00Z",
                        "response_item",
                        role="user",
                        text="different archived task",
                    ),
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["union_accepted"], 2)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 0)
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 0)

    def test_cross_root_metric_ignores_same_root_duplicate_in_mixed_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6ba6-6b81-7cb1-bb7e-4b8ab4dc66d0"
            active_original = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-a-{session_id}.jsonl"
            )
            active_copy = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-b-{session_id}.jsonl"
            )
            archived_branch = (
                codex_home / "archived_sessions" / f"rollout-c-{session_id}.jsonl"
            )
            write_rollout(
                active_original,
                [
                    record("2026-07-16T01:00:00Z", "session_meta", id=session_id),
                    record(
                        "2026-07-16T01:01:00Z",
                        "response_item",
                        role="assistant",
                        text="same-root result",
                    ),
                ],
            )
            write_rollout(
                active_copy,
                [
                    record("2026-07-16T02:00:00Z", "session_meta", id=session_id),
                    record(
                        "2026-07-16T02:01:00Z",
                        "response_item",
                        role="assistant",
                        text="same-root result",
                    ),
                ],
            )
            write_rollout(
                archived_branch,
                [
                    record("2026-07-16T03:00:00Z", "session_meta", id=session_id),
                    record(
                        "2026-07-16T03:01:00Z",
                        "response_item",
                        role="user",
                        text="different archived branch",
                    ),
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["union_accepted"], 2)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 2)
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)

    def test_replay_prefix_stops_before_repeated_human_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6ba6-6b81-7cb1-bb7e-4b8ab4dc66ce"
            archived = (
                codex_home / "archived_sessions" / f"rollout-old-{session_id}.jsonl"
            )
            active = (
                codex_home / "sessions/2026/07/16" / f"rollout-new-{session_id}.jsonl"
            )

            def branch_rows(day: str) -> list[dict[str, object]]:
                return [
                    record(f"{day}T01:00:00Z", "session_meta", id=session_id),
                    record(
                        f"{day}T01:01:00Z",
                        "response_item",
                        role="user",
                        text="original task",
                    ),
                    record(
                        f"{day}T01:02:00Z",
                        "response_item",
                        role="assistant",
                        text="shared answer",
                    ),
                    record(
                        f"{day}T01:03:00Z",
                        "response_item",
                        role="user",
                        text="repeat request after the fork",
                    ),
                ]

            write_rollout(archived, branch_rows("2026-01-01"))
            write_rollout(active, branch_rows("2026-07-16"))

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["path"], str(active))
            self.assertEqual(entries[0]["accepted_line_ranges"], [[4, 4]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 3)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 0)

    def test_filename_id_is_only_a_candidate_key_without_matching_fingerprints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f620a-f4e2-7b80-8d9d-1c4b8e9b70b0"
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-active-{session_id}.jsonl"
            )
            archived = (
                codex_home
                / "archived_sessions"
                / f"rollout-archived-{session_id}.jsonl"
            )
            write_rollout(
                active,
                [
                    record(
                        "2026-07-16T04:00:00Z",
                        "response_item",
                        role="user",
                        text="alpha",
                    )
                ],
            )
            write_rollout(
                archived,
                [
                    record(
                        "2026-07-16T05:00:00Z",
                        "response_item",
                        role="user",
                        text="beta",
                    )
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["union_accepted"], 2)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)
            corpus_paths = set((output / "corpus-paths.txt").read_text().splitlines())
            self.assertEqual(corpus_paths, {str(active), str(archived)})

    def test_filename_id_does_not_merge_different_lifecycle_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            filename_id = "019f6bb9-315a-7e33-a0ee-039b7b24540c"
            first_lifecycle = "019f6bb9-315a-7e33-a0ee-039b7b24540d"
            second_lifecycle = "019f6bb9-315a-7e33-a0ee-039b7b24540e"
            active = (
                codex_home / "sessions/2026/07/16" / f"rollout-a-{filename_id}.jsonl"
            )
            archived = (
                codex_home / "archived_sessions" / f"rollout-b-{filename_id}.jsonl"
            )
            shared_execution = record(
                "2026-07-16T01:00:00Z",
                "function_call_output",
                output="shared tool result",
            )
            write_rollout(
                active,
                [
                    shared_execution,
                    record(
                        "2026-07-16T01:01:00Z",
                        "session_meta",
                        id=first_lifecycle,
                    ),
                    record(
                        "2026-07-16T01:02:00Z",
                        "response_item",
                        role="user",
                        text="first task",
                    ),
                ],
            )
            write_rollout(
                archived,
                [
                    shared_execution,
                    record(
                        "2026-07-16T01:01:00Z",
                        "session_meta",
                        id=second_lifecycle,
                    ),
                    record(
                        "2026-07-16T01:02:00Z",
                        "response_item",
                        role="user",
                        text="second task",
                    ),
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 2)
            self.assertEqual(
                {tuple(map(tuple, entry["accepted_line_ranges"])) for entry in entries},
                {((1, 3),)},
            )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 0)

    def test_missing_lifecycle_does_not_bridge_different_lifecycle_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            filename_id = "019f6bb9-315a-7e33-a0ee-039b7b245410"
            lifecycle_ids = (
                "019f6bb9-315a-7e33-a0ee-039b7b245411",
                None,
                "019f6bb9-315a-7e33-a0ee-039b7b245412",
            )
            roots = (
                codex_home / "sessions/2026/07/16",
                codex_home / "archived_sessions/2026/07/16",
                codex_home / "archived_sessions",
            )
            shared_execution = record(
                "2026-07-16T01:00:00Z",
                "function_call_output",
                output="shared tool result",
            )
            for index, (root, lifecycle_id) in enumerate(zip(roots, lifecycle_ids)):
                rows = [shared_execution]
                if lifecycle_id is not None:
                    rows.append(
                        record(
                            "2026-07-16T01:01:00Z",
                            "session_meta",
                            id=lifecycle_id,
                        )
                    )
                rows.append(
                    record(
                        "2026-07-16T01:02:00Z",
                        "response_item",
                        role="user",
                        text=f"task {index}",
                    )
                )
                write_rollout(root / f"rollout-{index}-{filename_id}.jsonl", rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 3)
            groups_by_lifecycle = {
                entry["lifecycle_id"]: entry["group"]
                for entry in entries
                if entry["lifecycle_id"] is not None
            }
            self.assertNotEqual(
                groups_by_lifecycle[lifecycle_ids[0]],
                groups_by_lifecycle[lifecycle_ids[2]],
            )

    def test_conflicting_lifecycle_ids_isolate_restored_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            first_id = "019f6c4c-4f35-7139-a601-54d91db64c3a"
            second_id = "019f6c4c-4f35-7139-a601-54d91db64c3b"
            first = (
                codex_home / "sessions/2026/07/16" / f"rollout-first-{first_id}.jsonl"
            )
            restored = (
                codex_home / "archived_sessions" / f"rollout-restored-{second_id}.jsonl"
            )
            second = (
                codex_home / "sessions/2026/07/16" / f"rollout-second-{second_id}.jsonl"
            )
            first_rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=first_id),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="user",
                    text="first task",
                ),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="first result",
                ),
            ]
            restored_rows = [
                *first_rows,
                record("2026-07-16T02:00:00Z", "session_meta", id=second_id),
                record(
                    "2026-07-16T02:01:00Z",
                    "response_item",
                    role="user",
                    text="restored task",
                ),
            ]
            second_rows = [
                record("2026-07-16T03:00:00Z", "session_meta", id=second_id),
                record(
                    "2026-07-16T03:01:00Z",
                    "response_item",
                    role="assistant",
                    text="second result",
                ),
            ]
            write_rollout(first, first_rows)
            write_rollout(restored, restored_rows)
            write_rollout(second, second_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 3)
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(by_path[str(first)]["lifecycle_ids"], [first_id])
            self.assertEqual(by_path[str(second)]["lifecycle_ids"], [second_id])
            self.assertIsNone(by_path[str(restored)]["lifecycle_id"])
            self.assertEqual(
                by_path[str(restored)]["lifecycle_ids"],
                [first_id, second_id],
            )
            self.assertEqual(
                by_path[str(restored)]["accepted_line_ranges"],
                [[1, 5]],
            )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 0)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)

    def test_matching_multi_lifecycle_sets_remain_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            first_id = "019f6c4c-4f35-7139-a601-54d91db64c3a"
            second_id = "019f6c4c-4f35-7139-a601-54d91db64c3b"
            active = codex_home / "sessions/2026/07/16" / f"rollout-a-{first_id}.jsonl"
            archived = codex_home / "archived_sessions" / f"rollout-b-{second_id}.jsonl"
            shared = record(
                "2026-07-16T01:00:00Z",
                "response_item",
                role="assistant",
                text="shared execution evidence",
            )
            write_rollout(
                active,
                [
                    shared,
                    record("2026-07-16T01:01:00Z", "session_meta", id=first_id),
                    record("2026-07-16T01:02:00Z", "session_meta", id=second_id),
                ],
            )
            write_rollout(
                archived,
                [
                    shared,
                    record("2026-07-16T01:01:00Z", "session_meta", id=second_id),
                    record("2026-07-16T01:02:00Z", "session_meta", id=first_id),
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 2)
            self.assertEqual(
                {tuple(entry["lifecycle_ids"]) for entry in entries},
                {(first_id, second_id)},
            )
            self.assertEqual(
                {entry["accepted_record_count"] for entry in entries},
                {3},
            )
            self.assertEqual(len({entry["group"] for entry in entries}), 2)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 0)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)

    def test_identical_ambiguous_multi_lifecycle_copies_are_collapsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            first_id = "019f6c4c-4f35-7139-a601-54d91db64c3a"
            filename_id = "019f6c4c-4f35-7139-a601-54d91db64c3b"
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-active-{filename_id}.jsonl"
            )
            archived = (
                codex_home
                / "archived_sessions"
                / f"rollout-archived-{filename_id}.jsonl"
            )
            rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=first_id),
                record("2026-07-16T01:01:00Z", "session_meta", id=filename_id),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="restored suffix",
                ),
            ]
            write_rollout(active, rows)
            write_rollout(archived, rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertIsNone(entries[0]["owner_id"])
            self.assertEqual(entries[0]["lifecycle_ids"], [first_id, filename_id])
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 1)
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)

    def test_identical_mixed_owner_and_ambiguous_copies_are_collapsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            owner_id = "019f6c4c-4f35-7139-a601-54d91db64c3a"
            foreign_id = "019f6c4c-4f35-7139-a601-54d91db64c3b"
            active = (
                codex_home / "sessions/2026/07/16" / f"rollout-owner-{owner_id}.jsonl"
            )
            archived = (
                codex_home
                / "archived_sessions"
                / f"rollout-ambiguous-{foreign_id}.jsonl"
            )
            rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=owner_id),
                record("2026-07-16T01:01:00Z", "session_meta", id=foreign_id),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="identical restored history",
                ),
            ]
            write_rollout(active, rows)
            write_rollout(archived, rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["lifecycle_ids"], [owner_id, foreign_id])
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 1)
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)

    def test_multi_lifecycle_copies_with_same_owner_are_collapsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            owner_id = "019f6c4c-4f35-7139-a601-54d91db64c3a"
            foreign_id = "019f6c4c-4f35-7139-a601-54d91db64c3b"
            active = (
                codex_home / "sessions/2026/07/16" / f"rollout-active-{owner_id}.jsonl"
            )
            archived = (
                codex_home / "archived_sessions" / f"rollout-archived-{owner_id}.jsonl"
            )
            rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=owner_id),
                record("2026-07-16T01:01:00Z", "session_meta", id=foreign_id),
                record(
                    "2026-07-16T01:02:00Z",
                    "response_item",
                    role="assistant",
                    text="same owner suffix",
                ),
            ]
            write_rollout(active, rows)
            write_rollout(archived, rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["owner_id"], owner_id)
            self.assertEqual(entries[0]["lifecycle_ids"], [owner_id, foreign_id])
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 1)
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)

    def test_first_lifecycle_record_owns_rollout_without_filename_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            owner_id = "019f6c4c-4f35-7139-a601-54d91db64c3c"
            alias_id = "019f6c4c-4f35-7139-a601-54d91db64c3d"
            archived = codex_home / "archived_sessions/rollout-original.jsonl"
            active = codex_home / "sessions/2026/07/16/rollout-continued.jsonl"
            archived_rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=owner_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            active_rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=owner_id),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
                record("2026-07-16T01:02:00Z", "session_meta", id=alias_id),
                record(
                    "2026-07-16T01:03:00Z",
                    "response_item",
                    role="user",
                    text="genuine suffix",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["owner_id"], owner_id)
            self.assertEqual(entries[0]["lifecycle_ids"], [owner_id, alias_id])
            self.assertEqual(entries[0]["accepted_line_ranges"], [[3, 4]])
            self.assertEqual(entries[0]["replayed_prefix_records"], 2)

    def test_session_meta_collects_conflicting_identity_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            owner_id = "019f6c4c-4f35-7139-a601-54d91db64c3a"
            alias_id = "019f6c4c-4f35-7139-a601-54d91db64c3b"
            pure = codex_home / "sessions/2026/07/16" / f"rollout-pure-{owner_id}.jsonl"
            ambiguous = (
                codex_home / "archived_sessions" / f"rollout-aliases-{owner_id}.jsonl"
            )
            shared = record(
                "2026-07-16T00:59:00Z",
                "response_item",
                role="assistant",
                text="shared execution evidence",
            )
            write_rollout(
                pure,
                [
                    shared,
                    record(
                        "2026-07-16T01:00:00Z",
                        "session_meta",
                        id=owner_id,
                    ),
                ],
            )
            write_rollout(
                ambiguous,
                [
                    shared,
                    record(
                        "2026-07-16T01:00:00Z",
                        "session_meta",
                        id=owner_id,
                        session_id=alias_id,
                    ),
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 2)
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(by_path[str(pure)]["owner_id"], owner_id)
            self.assertIsNone(by_path[str(ambiguous)]["owner_id"])
            self.assertEqual(
                by_path[str(ambiguous)]["lifecycle_ids"],
                [owner_id, alias_id],
            )
            self.assertEqual(len({entry["group"] for entry in entries}), 2)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 0)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)

    def test_wrapped_session_meta_ignores_outer_envelope_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6c4c-4f35-7139-a601-54d91db64c3c"
            archived = (
                codex_home
                / "archived_sessions"
                / f"rollout-source-{session_id}.jsonl"
            )
            active = (
                codex_home
                / "sessions"
                / f"rollout-restamped-{session_id}.jsonl"
            )

            def wrapped_meta(timestamp: str, envelope_id: str) -> dict[str, object]:
                return {
                    "timestamp": timestamp,
                    "type": "event_msg",
                    "id": envelope_id,
                    "payload": {"type": "session_meta", "id": session_id},
                }

            archived_rows = [
                wrapped_meta("2026-01-01T01:00:00Z", "old-envelope"),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="assistant",
                    text="shared result",
                ),
            ]
            active_rows = [
                wrapped_meta("2026-07-16T01:00:00Z", "new-envelope"),
                record(
                    "2026-07-16T01:01:00Z",
                    "response_item",
                    role="assistant",
                    text="shared result",
                ),
            ]
            write_rollout(archived, archived_rows)
            write_rollout(active, active_rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((output / "corpus.jsonl").read_text(encoding="utf-8"), "")
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["duplicate_rollouts_collapsed"], 1)
            self.assertEqual(manifest["counts"]["replayed_prefix_records"], 2)

    def test_surrogate_lifecycle_id_is_stably_escaped_in_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            rollout = codex_home / "sessions" / "rollout-surrogate.jsonl"
            surrogate_id = "\ud800"
            write_rollout(
                rollout,
                [
                    record(
                        "2026-07-16T01:00:00Z",
                        "session_meta",
                        id=surrogate_id,
                    )
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            corpus_text = (output / "corpus.jsonl").read_text(encoding="utf-8")
            self.assertIn("\\ud800", corpus_text)
            entry = json.loads(corpus_text)
            self.assertEqual(entry["lifecycle_ids"], [surrogate_id])

    def test_identical_content_without_shared_identity_is_not_collapsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            active = codex_home / "sessions/2026/07/16/rollout-unrelated.jsonl"
            archived = (
                codex_home / "archived_sessions/2026/07/16/rollout-unrelated.jsonl"
            )
            rows = [
                record(
                    "2026-07-16T05:00:00Z", "response_item", role="user", text="same"
                )
            ]
            write_rollout(active, rows)
            write_rollout(archived, rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["union_accepted"], 2)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)

    def test_nested_timestamp_content_is_not_treated_as_volatile_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b4b-8471-7b71-987b-3e08fbe75c63"
            active = (
                codex_home / "sessions/2026/07/16" / f"rollout-a-{session_id}.jsonl"
            )
            archived = (
                codex_home / "archived_sessions" / f"rollout-b-{session_id}.jsonl"
            )
            shared_meta = record(
                "2026-07-16T04:00:00Z",
                "session_meta",
                id=session_id,
            )
            active_tool = record(
                "2026-07-16T04:01:00Z",
                "function_call_output",
                result={"created_at": "2026-07-15T23:59:00Z"},
            )
            archived_tool = record(
                "2026-07-16T04:01:00Z",
                "function_call_output",
                result={"created_at": "2026-07-16T00:01:00Z"},
            )
            write_rollout(active, [shared_meta, active_tool])
            write_rollout(archived, [shared_meta, archived_tool])

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 2)
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(by_path[str(active)]["accepted_line_ranges"], [[1, 2]])
            self.assertEqual(by_path[str(archived)]["accepted_line_ranges"], [[1, 2]])
            self.assertEqual(by_path[str(archived)]["replayed_prefix_records"], 0)

    def test_date_path_fallback_locates_every_unique_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            path = codex_home / "sessions/2026/07/16/rollout-no-timestamps.jsonl"
            write_rollout(
                path,
                [
                    {
                        "type": "response_item",
                        "payload": {"role": "user", "text": "one"},
                    },
                    {
                        "type": "response_item",
                        "payload": {"role": "assistant", "text": "two"},
                    },
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0]["fallback_date_used"])
            self.assertEqual(entries[0]["accepted_record_count"], 2)
            self.assertEqual(entries[0]["accepted_line_ranges"], [[1, 2]])

    def test_filename_time_fallback_preserves_subday_windows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6c4c-4f35-7139-a601-54d91db64c36"
            path = (
                codex_home
                / "archived_sessions"
                / f"rollout-2026-07-16T21-30-45-{session_id}.jsonl"
            )
            write_rollout(
                path,
                [
                    {
                        "type": "response_item",
                        "payload": {"role": "user", "text": "subday task"},
                    }
                ],
            )

            output = temp / "out"
            completed = self.run_corpus(
                codex_home,
                output,
                start="2026-07-16T21:00:00Z",
                end="2026-07-16T22:00:00Z",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0]["fallback_date_used"])

    def test_time_field_is_a_timestamp_and_volatile_fingerprint_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            path = codex_home / "archived_sessions/rollout-time.jsonl"
            row = {
                "time": "2026-07-16T15:00:00Z",
                "type": "user_message",
                "payload": {
                    "type": "user_message",
                    "role": "user",
                    "text": "in-window task",
                },
            }
            write_rollout(path, [row])

            output = temp / "out"
            completed = self.run_corpus(
                codex_home,
                output,
                start="2026-07-16T14:00:00Z",
                end="2026-07-16T16:00:00Z",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["accepted_line_ranges"], [[1, 1]])
            self.assertFalse(entries[0]["fallback_date_used"])

            restamped = dict(row)
            restamped["time"] = "2026-07-16T15:30:00Z"
            self.assertEqual(
                CORPUS.record_fingerprint(row),
                CORPUS.record_fingerprint(restamped),
            )
            self.assertEqual(entries[0]["accepted_line_ranges"], [[1, 1]])

    def test_filename_fallback_validation_and_priority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "sessions"
            full = root / "2026/01/01/rollout-2026-07-16T21-30-45-id.jsonl"
            date_only = root / "rollout-2026-07-16-id.jsonl"
            invalid_flat = root / "rollout-2026-07-16T25-00-00-id.jsonl"
            invalid_with_dated_path = (
                root / "2026/07/15/rollout-2026-07-16T25-00-00-id.jsonl"
            )

            self.assertEqual(
                CORPUS.fallback_path_timestamp(full, root),
                CORPUS.parse_instant("2026-07-16T21:30:45Z"),
            )
            self.assertEqual(
                CORPUS.fallback_path_timestamp(date_only, root),
                CORPUS.parse_instant("2026-07-16T00:00:00Z"),
            )
            self.assertIsNone(CORPUS.fallback_path_timestamp(invalid_flat, root))
            self.assertEqual(
                CORPUS.fallback_path_timestamp(invalid_with_dated_path, root),
                CORPUS.parse_instant("2026-07-15T00:00:00Z"),
            )
            self.assertIsNone(
                CORPUS.fallback_path_timestamp(
                    Path(temp_dir) / "outside/rollout-2026-07-16-id.jsonl",
                    root,
                )
            )

    def test_empty_timestamp_less_rollouts_are_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6c4c-4f35-7139-a601-54d91db64c39"
            active = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-2026-07-16T01-00-00-{session_id}.jsonl"
            )
            archived = (
                codex_home
                / "archived_sessions"
                / f"rollout-2026-07-16T01-00-00-{session_id}.jsonl"
            )
            write_rollout(active, [])
            write_rollout(archived, [])

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((output / "corpus.jsonl").read_text(encoding="utf-8"), "")
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["counts"]["active_accepted"], 0)
            self.assertEqual(manifest["counts"]["archived_accepted"], 0)
            self.assertEqual(manifest["counts"]["union_accepted"], 0)
            self.assertEqual(manifest["counts"]["union_accepted_groups"], 0)

            write_rollout(
                archived,
                [
                    {
                        "type": "response_item",
                        "payload": {"role": "user", "text": "real task"},
                    }
                ],
            )
            mixed_output = temp / "mixed-out"
            mixed = self.run_corpus(codex_home, mixed_output)
            self.assertEqual(mixed.returncode, 0, mixed.stderr)
            mixed_manifest = json.loads(
                (mixed_output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(mixed_manifest["counts"]["active_accepted"], 0)
            self.assertEqual(mixed_manifest["counts"]["archived_accepted"], 1)
            self.assertEqual(mixed_manifest["counts"]["union_accepted"], 1)
            self.assertEqual(mixed_manifest["counts"]["union_accepted_groups"], 1)
            mixed_entries = [
                json.loads(line)
                for line in (mixed_output / "corpus.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(mixed_entries), 1)
            self.assertEqual(mixed_entries[0]["path"], str(archived))
            self.assertEqual(mixed_entries[0]["accepted_record_count"], 1)

            write_rollout(archived, [])
            accepted = (
                codex_home
                / "sessions/2026/07/16"
                / f"rollout-2026-07-16T02-00-00-copy-{session_id}.jsonl"
            )
            write_rollout(
                accepted,
                [
                    {
                        "type": "response_item",
                        "payload": {"role": "user", "text": "real task"},
                    }
                ],
            )
            metrics_output = temp / "metrics-out"
            metrics = self.run_corpus(codex_home, metrics_output)
            self.assertEqual(metrics.returncode, 0, metrics.stderr)
            metrics_manifest = json.loads(
                (metrics_output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metrics_manifest["counts"]["union_accepted"], 1)
            self.assertEqual(
                metrics_manifest["counts"]["union_accepted_groups"],
                1,
            )
            self.assertEqual(
                metrics_manifest["counts"]["cross_root_duplicate_groups"],
                0,
            )
            self.assertEqual(
                metrics_manifest["counts"]["duplicate_rollouts_collapsed"],
                0,
            )

    def test_invalid_json_and_invalid_window_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            bad = codex_home / "sessions/2026/07/16/rollout-bad.jsonl"
            bad.parent.mkdir(parents=True)
            bad.write_text("not-json\n", encoding="utf-8")

            invalid_json = self.run_corpus(codex_home, temp / "bad-json")
            self.assertEqual(invalid_json.returncode, 2)
            self.assertIn("invalid rollout JSON", invalid_json.stderr)

            bad.unlink()
            invalid_window = self.run_corpus(
                codex_home,
                temp / "bad-window",
                start="2026-07-17T00:00:00Z",
                end="2026-07-16T00:00:00Z",
            )
            self.assertEqual(invalid_window.returncode, 2)
            self.assertIn("window start must be earlier", invalid_window.stderr)

    def test_inventory_propagates_walk_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "sessions"
            root.mkdir()

            def failing_walk(
                *_args: object,
                onerror: object,
                **_kwargs: object,
            ) -> list[object]:
                if not callable(onerror):
                    raise AssertionError("os.walk must receive an error callback")
                onerror(PermissionError("blocked subtree"))
                return []

            with mock.patch.object(CORPUS.os, "walk", side_effect=failing_walk):
                with self.assertRaisesRegex(
                    CORPUS.CorpusError,
                    "unable to inventory rollout root.*blocked subtree",
                ):
                    CORPUS.inventory_root(root)

    def test_inventory_rejects_dangling_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            root = temp / "archived_sessions"
            root.symlink_to(temp / "missing", target_is_directory=True)

            with self.assertRaisesRegex(CORPUS.CorpusError, "unsafe rollout root"):
                CORPUS.inventory_root(root)

    def test_inventory_rejects_non_printable_rollout_path_components(self) -> None:
        unsafe_paths = (
            Path("2026/07/16/rollout-bad\nspoof.jsonl"),
            Path("2026/07\x1bspoof/rollout-safe.jsonl"),
        )
        for relative_path in unsafe_paths:
            with self.subTest(relative_path=repr(relative_path)):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp = Path(temp_dir)
                    codex_home = temp / ".codex"
                    write_rollout(
                        codex_home / "sessions" / relative_path,
                        [
                            record(
                                "2026-07-16T01:00:00Z",
                                "user_message",
                                text="task",
                            )
                        ],
                    )

                    output = temp / "out"
                    completed = self.run_corpus(codex_home, output)

                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(
                        completed.stderr,
                        "error: rollout candidate path contains "
                        "non-printable characters\n",
                    )
                    self.assertFalse(output.exists())

    def test_inventory_rejects_directory_replacement_during_walk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            root = temp / "sessions"
            path = root / "2026/07/16/rollout-swap.jsonl"
            write_rollout(
                path,
                [record("2026-07-16T01:00:00Z", "user_message", text="old")],
            )
            original_walk = CORPUS.os.walk

            def swapping_walk(
                *args: object,
                **kwargs: object,
            ) -> Iterator[tuple[str, list[str], list[str]]]:
                for index, entry in enumerate(original_walk(*args, **kwargs)):
                    yield entry
                    if index == 0:
                        (root / "2026").rename(temp / "inventoried-2026")
                        (root / "2026").mkdir()

            with mock.patch.object(CORPUS.os, "walk", swapping_walk):
                with self.assertRaisesRegex(
                    CORPUS.CorpusError,
                    "rollout inventory changed during traversal",
                ):
                    CORPUS.inventory_root(root)

    def test_inventory_rejects_file_to_directory_swap_during_walk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            root = temp / "sessions"
            root.mkdir()
            original_entry = root / "2026"
            original_entry.write_text("not a directory\n", encoding="utf-8")
            original_walk = CORPUS.os.walk

            def swapping_walk(
                *args: object,
                **kwargs: object,
            ) -> Iterator[tuple[str, list[str], list[str]]]:
                for index, entry in enumerate(original_walk(*args, **kwargs)):
                    yield entry
                    if index == 0:
                        original_entry.rename(temp / "inventoried-2026-file")
                        write_rollout(
                            root / "2026/07/16/rollout-hidden.jsonl",
                            [
                                record(
                                    "2026-07-16T01:00:00Z",
                                    "user_message",
                                    text="hidden",
                                )
                            ],
                        )

            with mock.patch.object(CORPUS.os, "walk", swapping_walk):
                with self.assertRaisesRegex(
                    CORPUS.CorpusError,
                    "rollout inventory changed during traversal",
                ):
                    CORPUS.inventory_root(root)

    def test_inventory_identity_rejects_root_and_candidate_swaps(self) -> None:
        start = CORPUS.parse_instant("2026-07-16T00:00:00Z")
        end = CORPUS.parse_instant("2026-07-17T00:00:00Z")

        with self.subTest("candidate inode replacement"):
            with tempfile.TemporaryDirectory() as temp_dir:
                temp = Path(temp_dir)
                root = temp / "sessions"
                path = root / "2026/07/16/rollout-swap.jsonl"
                write_rollout(
                    path,
                    [record("2026-07-16T01:00:00Z", "user_message", text="old")],
                )
                candidate = CORPUS.inventory_root(root)[0]
                replacement = temp / "replacement.jsonl"
                write_rollout(
                    replacement,
                    [record("2026-07-16T01:00:00Z", "user_message", text="new")],
                )
                replacement.replace(path)

                with self.assertRaisesRegex(
                    CORPUS.CorpusError,
                    "rollout candidate changed after inventory",
                ):
                    CORPUS.scan_rollout_metadata(
                        candidate,
                        "active",
                        root,
                        start,
                        end,
                    )

        with self.subTest("candidate symlink replacement"):
            with tempfile.TemporaryDirectory() as temp_dir:
                temp = Path(temp_dir)
                root = temp / "sessions"
                path = root / "2026/07/16/rollout-swap.jsonl"
                outside = temp / "outside.jsonl"
                write_rollout(
                    path,
                    [record("2026-07-16T01:00:00Z", "user_message", text="old")],
                )
                write_rollout(
                    outside,
                    [record("2026-07-16T01:00:00Z", "user_message", text="secret")],
                )
                candidate = CORPUS.inventory_root(root)[0]
                path.unlink()
                path.symlink_to(outside)

                with self.assertRaisesRegex(
                    CORPUS.CorpusError,
                    "rollout candidate changed after inventory",
                ):
                    CORPUS.scan_rollout_metadata(
                        candidate,
                        "active",
                        root,
                        start,
                        end,
                    )

        with self.subTest("intermediate directory symlink replacement"):
            with tempfile.TemporaryDirectory() as temp_dir:
                temp = Path(temp_dir)
                root = temp / "sessions"
                relative = Path("2026/07/16/rollout-swap.jsonl")
                path = root / relative
                write_rollout(
                    path,
                    [record("2026-07-16T01:00:00Z", "user_message", text="old")],
                )
                candidate = CORPUS.inventory_root(root)[0]
                (root / "2026").rename(temp / "inventoried-2026")
                outside_year = temp / "outside-2026"
                write_rollout(
                    outside_year / "07/16/rollout-swap.jsonl",
                    [
                        record(
                            "2026-07-16T01:00:00Z",
                            "user_message",
                            text="secret",
                        )
                    ],
                )
                (root / "2026").symlink_to(
                    outside_year,
                    target_is_directory=True,
                )

                with self.assertRaisesRegex(
                    CORPUS.CorpusError,
                    "rollout candidate changed after inventory",
                ):
                    CORPUS.scan_rollout_metadata(
                        candidate,
                        "active",
                        root,
                        start,
                        end,
                    )

        with self.subTest("root replacement"):
            with tempfile.TemporaryDirectory() as temp_dir:
                temp = Path(temp_dir)
                root = temp / "sessions"
                relative = Path("2026/07/16/rollout-swap.jsonl")
                path = root / relative
                write_rollout(
                    path,
                    [record("2026-07-16T01:00:00Z", "user_message", text="old")],
                )
                candidate = CORPUS.inventory_root(root)[0]
                root.rename(temp / "inventoried-sessions")
                write_rollout(
                    root / relative,
                    [record("2026-07-16T01:00:00Z", "user_message", text="new")],
                )

                with self.assertRaisesRegex(
                    CORPUS.CorpusError,
                    "rollout root changed after inventory",
                ):
                    CORPUS.scan_rollout_metadata(
                        candidate,
                        "active",
                        root,
                        start,
                        end,
                    )

    def test_second_pass_rejects_candidate_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            root = temp / "sessions"
            path = root / "2026/07/16/rollout-swap.jsonl"
            outside = temp / "outside.jsonl"
            rows = [record("2026-07-16T01:00:00Z", "user_message", text="original")]
            write_rollout(path, rows)
            write_rollout(outside, rows)
            start = CORPUS.parse_instant("2026-07-16T00:00:00Z")
            end = CORPUS.parse_instant("2026-07-17T00:00:00Z")
            metadata = CORPUS.scan_rollout_metadata(
                path,
                "active",
                root,
                start,
                end,
            )
            path.unlink()
            path.symlink_to(outside)

            with self.assertRaisesRegex(
                CORPUS.CorpusError,
                "rollout candidate changed after inventory",
            ):
                CORPUS.load_rollout_records(metadata)

    def test_output_rejects_symlink_and_existing_artifact_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            outside = temp / "outside"
            outside.mkdir()
            output_link = temp / "output-link"
            output_link.symlink_to(outside, target_is_directory=True)

            linked = self.run_corpus(codex_home, output_link)
            self.assertEqual(linked.returncode, 2)
            self.assertIn("unsafe output path uses a symlink", linked.stderr)
            self.assertFalse((outside / "manifest.json").exists())

            ancestor_link = temp / "ancestor-link"
            ancestor_link.symlink_to(outside, target_is_directory=True)
            nested = self.run_corpus(codex_home, ancestor_link / "nested")
            self.assertEqual(nested.returncode, 2)
            self.assertIn("unsafe output path uses a symlink", nested.stderr)
            self.assertFalse((outside / "nested").exists())

            existing = temp / "existing"
            existing.mkdir()
            sentinel = temp / "sentinel"
            sentinel.write_text("unchanged", encoding="utf-8")
            (existing / "manifest.json").symlink_to(sentinel)

            prepopulated = self.run_corpus(codex_home, existing)
            self.assertEqual(prepopulated.returncode, 2)
            self.assertIn("output directory must be fresh", prepopulated.stderr)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

            artifact_output = temp / "artifact-output"
            directory_fd = CORPUS.create_output_directory(artifact_output)
            try:
                (artifact_output / "manifest.json").symlink_to(sentinel)
                with self.assertRaises(FileExistsError):
                    CORPUS.write_artifact(
                        directory_fd,
                        "manifest.json",
                        "replacement",
                    )
            finally:
                CORPUS.os.close(directory_fd)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

            normalized_output = temp / "canceled" / ".." / "normalized-output"
            normalized = self.run_corpus(codex_home, normalized_output)
            self.assertEqual(normalized.returncode, 0, normalized.stderr)
            self.assertTrue((temp / "normalized-output" / "manifest.json").is_file())
            self.assertFalse((temp / "canceled").exists())

    def test_out_of_window_cross_root_group_skips_fingerprint_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6bb9-315a-7e33-a0ee-039b7b24540f"
            rows = [
                record("2026-01-01T01:00:00Z", "session_meta", id=session_id),
                record(
                    "2026-01-01T01:01:00Z",
                    "response_item",
                    role="assistant",
                    text="old result",
                ),
            ]
            write_rollout(
                codex_home / "sessions/2026/01/01" / f"rollout-a-{session_id}.jsonl",
                rows,
            )
            write_rollout(
                codex_home / "archived_sessions" / f"rollout-b-{session_id}.jsonl",
                rows,
            )
            start = CORPUS.parse_instant("2026-07-16T00:00:00Z")
            end = CORPUS.parse_instant("2026-07-17T00:00:00Z")
            output = temp / "out"

            with mock.patch.object(
                CORPUS,
                "load_rollout_records",
                side_effect=AssertionError("second pass must be skipped"),
            ):
                manifest = CORPUS.build_corpus(codex_home, start, end, output, 0)
            self.assertEqual(manifest["counts"]["union_accepted"], 0)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)

    def test_second_pass_accepts_append_only_growth_but_rejects_prefix_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            active_root = temp / ".codex/sessions"
            path = active_root / "2026/07/16/rollout-growing.jsonl"
            original = [
                record("2026-07-16T06:00:00Z", "response_item", role="user", text="old")
            ]
            appended = record(
                "2026-07-16T06:01:00Z",
                "response_item",
                role="user",
                text="new",
            )
            write_rollout(path, original)
            start = CORPUS.parse_instant("2026-07-16T00:00:00Z")
            end = CORPUS.parse_instant("2026-07-17T00:00:00Z")
            metadata = CORPUS.scan_rollout_metadata(
                path, "active", active_root, start, end
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"{json.dumps(appended, sort_keys=True)}\n")

            rollout = CORPUS.load_rollout_records(metadata)
            self.assertEqual(len(rollout.records), 1)

            changed = [
                record("2026-07-16T06:00:00Z", "response_item", role="user", text="bad")
            ]
            write_rollout(path, changed + [appended])
            with self.assertRaisesRegex(CORPUS.CorpusError, "rollout prefix changed"):
                CORPUS.load_rollout_records(metadata)

    def test_first_pass_pins_growth_after_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            root = temp / "sessions"
            path = root / "2026/07/16/rollout-growing.jsonl"
            first = record(
                "2026-07-16T06:00:00Z",
                "response_item",
                role="user",
                text="first",
            )
            second = record(
                "2026-07-16T06:01:00Z",
                "response_item",
                role="assistant",
                text="second",
            )
            third = record(
                "2026-07-16T06:02:00Z",
                "response_item",
                role="user",
                text="third",
            )
            write_rollout(path, [first])
            candidate = CORPUS.inventory_root(root)[0]
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"{json.dumps(second, sort_keys=True)}\n")
            start = CORPUS.parse_instant("2026-07-16T00:00:00Z")
            end = CORPUS.parse_instant("2026-07-17T00:00:00Z")

            metadata = CORPUS.scan_rollout_metadata(
                candidate,
                "active",
                root,
                start,
                end,
            )
            self.assertEqual(metadata.record_count, 2)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"{json.dumps(third, sort_keys=True)}\n")

            rollout = CORPUS.load_rollout_records(metadata)
            self.assertEqual(len(rollout.records), 2)

    def test_first_pass_defers_active_unterminated_fragment_at_record_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            root = temp / "sessions"
            path = root / "2026/07/16/rollout-growing.jsonl"
            first = record(
                "2026-07-16T06:00:00Z",
                "response_item",
                role="user",
                text="first",
            )
            second = record(
                "2026-07-16T06:01:00Z",
                "response_item",
                role="assistant",
                text="second",
            )
            first_line = f"{json.dumps(first, sort_keys=True)}\n".encode()
            second_line = f"{json.dumps(second, sort_keys=True)}\n".encode()
            split_at = len(second_line) // 2
            path.parent.mkdir(parents=True)
            path.write_bytes(first_line + second_line[:split_at])
            start = CORPUS.parse_instant("2026-07-16T00:00:00Z")
            end = CORPUS.parse_instant("2026-07-17T00:00:00Z")

            metadata = CORPUS.scan_rollout_metadata(
                path,
                "active",
                root,
                start,
                end,
            )
            self.assertEqual(metadata.record_count, 1)
            self.assertEqual(metadata.source_bytes, len(first_line))
            self.assertEqual(metadata.candidate.file_size, len(first_line))
            self.assertEqual(
                metadata.content_sha256, hashlib.sha256(first_line).hexdigest()
            )
            self.assertEqual(len(CORPUS.load_rollout_records(metadata).records), 1)

            with path.open("ab") as handle:
                handle.write(second_line[split_at:])
            self.assertEqual(len(CORPUS.load_rollout_records(metadata).records), 1)
            refreshed = CORPUS.scan_rollout_metadata(
                path,
                "active",
                root,
                start,
                end,
            )
            self.assertEqual(refreshed.record_count, 2)

    def test_unterminated_fragment_deferral_is_active_and_json_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            start = CORPUS.parse_instant("2026-07-16T00:00:00Z")
            end = CORPUS.parse_instant("2026-07-17T00:00:00Z")
            first = record(
                "2026-07-16T06:00:00Z",
                "response_item",
                role="user",
                text="first",
            )
            first_line = f"{json.dumps(first, sort_keys=True)}\n".encode()

            active_root = temp / "sessions"
            committed_bad = active_root / "rollout-committed-bad.jsonl"
            committed_bad.parent.mkdir(parents=True)
            committed_bad.write_bytes(first_line + b"not-json\n")
            with self.assertRaisesRegex(CORPUS.CorpusError, "invalid rollout JSON"):
                CORPUS.scan_rollout_metadata(
                    committed_bad,
                    "active",
                    active_root,
                    start,
                    end,
                )

            non_object = active_root / "rollout-non-object.jsonl"
            non_object.write_bytes(first_line + b"[]")
            with self.assertRaisesRegex(CORPUS.CorpusError, "non-object rollout"):
                CORPUS.scan_rollout_metadata(
                    non_object,
                    "active",
                    active_root,
                    start,
                    end,
                )

            archived_root = temp / "archived_sessions"
            archived_partial = archived_root / "rollout-partial.jsonl"
            archived_partial.parent.mkdir(parents=True)
            archived_partial.write_bytes(first_line + b'{"timestamp":')
            with self.assertRaisesRegex(CORPUS.CorpusError, "invalid rollout JSON"):
                CORPUS.scan_rollout_metadata(
                    archived_partial,
                    "archived",
                    archived_root,
                    start,
                    end,
                )


if __name__ == "__main__":
    unittest.main()
