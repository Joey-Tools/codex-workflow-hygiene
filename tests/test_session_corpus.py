from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


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

    def test_cross_root_prefix_dedup_preserves_human_suffix_and_old_path_followup(self) -> None:
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
                record("2026-01-01T01:01:00Z", "response_item", role="user", text="old task"),
            ]
            continuation_rows = [
                record("2026-07-16T01:00:00Z", "session_meta", id=first_id),
                record("2026-07-16T01:01:00Z", "response_item", role="user", text="old task"),
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
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
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
                    "replayed_prefix_records": 4,
                    "union_accepted": 2,
                    "union_accepted_groups": 2,
                    "union_candidate": 4,
                    "union_parsed": 4,
                },
            )
            entries = [
                json.loads(line)
                for line in (output / "corpus.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(set(by_path), {str(archived_continuation), str(old_path_followup)})
            self.assertEqual(by_path[str(archived_continuation)]["accepted_line_ranges"], [[3, 3]])
            self.assertEqual(by_path[str(archived_continuation)]["accepted_record_count"], 1)
            self.assertEqual(by_path[str(archived_continuation)]["replayed_prefix_records"], 2)
            self.assertEqual(by_path[str(old_path_followup)]["accepted_line_ranges"], [[1, 2]])
            self.assertEqual(by_path[str(old_path_followup)]["accepted_record_count"], 2)
            self.assertNotIn(str(active_original), (output / "corpus-paths.txt").read_text())
            self.assertRegex(completed.stdout, r"active candidate count: 2")
            self.assertRegex(completed.stdout, r"archived accepted count: 2")
            self.assertRegex(completed.stdout, r"union accepted count: 2")
            self.assertIn("accepted_records=1:line_ranges=[[3, 3]]", completed.stdout)

    def test_filename_id_is_only_a_candidate_key_without_matching_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f620a-f4e2-7b80-8d9d-1c4b8e9b70b0"
            active = codex_home / "sessions/2026/07/16" / f"rollout-active-{session_id}.jsonl"
            archived = codex_home / "archived_sessions" / f"rollout-archived-{session_id}.jsonl"
            write_rollout(
                active,
                [record("2026-07-16T04:00:00Z", "response_item", role="user", text="alpha")],
            )
            write_rollout(
                archived,
                [record("2026-07-16T05:00:00Z", "response_item", role="user", text="beta")],
            )

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["counts"]["union_accepted"], 2)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)
            corpus_paths = set((output / "corpus-paths.txt").read_text().splitlines())
            self.assertEqual(corpus_paths, {str(active), str(archived)})

    def test_identical_content_without_shared_identity_is_not_collapsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            active = codex_home / "sessions/2026/07/16/rollout-unrelated-active.jsonl"
            archived = (
                codex_home
                / "archived_sessions/2026/07/16/rollout-unrelated-archived.jsonl"
            )
            rows = [record("2026-07-16T05:00:00Z", "response_item", role="user", text="same")]
            write_rollout(active, rows)
            write_rollout(archived, rows)

            output = temp / "out"
            completed = self.run_corpus(codex_home, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["counts"]["union_accepted"], 2)
            self.assertEqual(manifest["counts"]["cross_root_duplicate_groups"], 0)

    def test_nested_timestamp_content_is_not_treated_as_volatile_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            session_id = "019f6b4b-8471-7b71-987b-3e08fbe75c63"
            active = codex_home / "sessions/2026/07/16" / f"rollout-a-{session_id}.jsonl"
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
                for line in (output / "corpus.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(entries), 2)
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(by_path[str(active)]["accepted_line_ranges"], [[1, 2]])
            self.assertEqual(by_path[str(archived)]["accepted_line_ranges"], [[2, 2]])
            self.assertEqual(by_path[str(archived)]["replayed_prefix_records"], 1)

    def test_date_path_fallback_locates_every_unique_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            codex_home = temp / ".codex"
            path = codex_home / "sessions/2026/07/16/rollout-no-timestamps.jsonl"
            write_rollout(
                path,
                [
                    {"type": "response_item", "payload": {"role": "user", "text": "one"}},
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
                for line in (output / "corpus.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0]["fallback_date_used"])
            self.assertEqual(entries[0]["accepted_record_count"], 2)
            self.assertEqual(entries[0]["accepted_line_ranges"], [[1, 2]])

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

    def test_second_pass_accepts_append_only_growth_but_rejects_prefix_changes(self) -> None:
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
            metadata = CORPUS.scan_rollout_metadata(path, "active", active_root, start, end)
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


if __name__ == "__main__":
    unittest.main()
