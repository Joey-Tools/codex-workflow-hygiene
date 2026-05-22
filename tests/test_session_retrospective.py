from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "codex-session-retrospective"
    / "scripts"
    / "session_retrospective.py"
)
SPEC = importlib.util.spec_from_file_location("session_retrospective", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def message(role: str, text: str, timestamp: str) -> dict:
    return {
        "type": "response_item",
        "timestamp": timestamp,
        "payload": {
            "type": "message",
            "role": role,
            "content": [{"type": "input_text" if role == "user" else "output_text", "text": text}],
        },
    }


def message_with_cwd(role: str, text: str, timestamp: str, cwd: str) -> dict:
    row = message(role, text, timestamp)
    row["payload"]["cwd"] = cwd
    return row


def event_user_message(text: str, timestamp: str) -> dict:
    return {
        "type": "event_msg",
        "timestamp": timestamp,
        "payload": {
            "type": "user_message",
            "message": text,
            "images": [],
            "local_images": [],
            "text_elements": [],
        },
    }


class SessionRetrospectiveTests(unittest.TestCase):
    def test_filename_parsers_support_current_and_legacy_rollouts(self) -> None:
        current = Path("rollout-2026-05-07T13-24-44-019d-uuid.jsonl")
        legacy = Path("rollout-2025-05-26-legacy-uuid.jsonl")

        self.assertEqual(MODULE.session_id_from_path(current), "019d-uuid")
        self.assertEqual(MODULE.session_id_from_path(legacy), "legacy-uuid")
        self.assertEqual(MODULE.iso(MODULE.rollout_date_from_path(current)), "2026-05-07T00:00:00Z")
        self.assertEqual(MODULE.iso(MODULE.rollout_date_from_path(legacy)), "2025-05-26T00:00:00Z")

    def test_prompt_category_does_not_treat_prompt_as_pr_review(self) -> None:
        self.assertEqual(MODULE.prompt_category("Improve this prompt for the project."), "general")
        self.assertEqual(MODULE.prompt_category("Review this PR."), "review")
        self.assertNotIn("git_or_pr", MODULE.safe_assistant_summary(["Improved the prompt."]))

    def test_ignores_wrapper_and_redacts_flagged_turns(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "# AGENTS.md instructions\nsecret wrapper", "2026-05-22T10:00:00Z"),
                    message("user", "Please fix this using https://internal.example/case and token sk-proj-abcdefghijklmnop123456.", "2026-05-22T10:01:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:02:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            source = MODULE.Source("local", root)
            turns = MODULE.extract_rollout(source, rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("category=debug_or_fix", turns[0].redacted_user_prompt_summary)
        self.assertIn("redactions=applied", turns[0].redacted_user_prompt_summary)
        self.assertNotIn("internal.example", turns[0].redacted_user_prompt_summary)
        self.assertNotIn("sk-proj", turns[0].redacted_user_prompt_summary)
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("approval_auth_friction", turns[0].issue_flags)
        self.assertIn("safety_privacy_flag", turns[0].issue_flags)

    def test_extract_rollout_groups_multiple_turns_into_one_episode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-22T10:01:00Z"),
                    message("assistant", "Implemented the helper.", "2026-05-22T10:02:00Z"),
                    message("user", "Also update helper.", "2026-05-22T10:03:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            episodes = MODULE.episode_records(turns)

        self.assertEqual(len(turns), 2)
        self.assertEqual(turns[0].episode_id, turns[1].episode_id)
        self.assertEqual(len(episodes), 1)
        self.assertEqual(episodes[0]["turn_count"], 2)

    def test_extract_rollout_reads_event_msg_user_messages_once(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-event.jsonl"
            write_jsonl(
                rollout,
                [
                    event_user_message("Review the PR.", "2026-05-22T10:01:00.001Z"),
                    event_user_message("Review the PR.", "2026-05-22T10:01:00.002Z"),
                    message("assistant", "Reviewed it.", "2026-05-22T10:02:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("category=review", turns[0].redacted_user_prompt_summary)
        self.assertIn("assistant_messages=1", turns[0].assistant_action_summary)

    def test_extract_rollout_deduplicates_near_duplicate_user_message_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-event.jsonl"
            write_jsonl(
                rollout,
                [
                    event_user_message("Review the PR.", "2026-05-22T10:01:00.001Z"),
                    message("user", "User says: Review the PR.", "2026-05-22T10:01:00.002Z"),
                    message("assistant", "Reviewed it.", "2026-05-22T10:02:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("assistant_messages=1", turns[0].assistant_action_summary)

    def test_automation_prompt_is_not_treated_as_user_episode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-auto.jsonl"
            write_jsonl(
                rollout,
                [
                    message(
                        "user",
                        "Run the daily Codex session retrospective. Check auth, secrets, customer data, and write task-local artifacts.",
                        "2026-05-22T10:01:00Z",
                    ),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(turns, [])

    def test_synthetic_internal_review_prompt_is_not_treated_as_user_episode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-review.jsonl"
            write_jsonl(
                rollout,
                [
                    message(
                        "user",
                        "Persistent internal Codex readonly review contract:\nReview discipline:\nReport findings only.",
                        "2026-05-22T10:01:00Z",
                    ),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(turns, [])

    def test_episode_splits_by_day_and_prompt_category(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-22T10:01:00Z"),
                    message("user", "Please plan the rollout.", "2026-05-22T10:03:00Z"),
                    message("user", "Please implement the helper.", "2026-05-23T10:01:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            episodes = MODULE.episode_records(turns)

        self.assertEqual(len(turns), 3)
        self.assertEqual(len(episodes), 3)

    def test_assistant_summary_does_not_persist_response_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-22T10:01:00Z"),
                    message("assistant", "Implemented secret project path /internal/customer/code.py and ran unittest.", "2026-05-22T10:02:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertIn("assistant_messages=1", turns[0].assistant_action_summary)
        self.assertIn("implementation", turns[0].assistant_action_summary)
        self.assertIn("verification", turns[0].assistant_action_summary)
        self.assertNotIn("customer", turns[0].assistant_action_summary)
        self.assertNotIn("code.py", turns[0].assistant_action_summary)

    def test_paths_are_redacted_in_turn_and_episode_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-secret.jsonl"
            write_jsonl(
                rollout,
                [
                    message_with_cwd(
                        "user",
                        "Please implement the helper.",
                        "2026-05-22T10:01:00Z",
                        "/Users/hoteng/Program/GitHub/customer-secret/repo",
                    ),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            episodes = MODULE.episode_records(turns)
            serialized = json.dumps({"turns": [MODULE.asdict_turn(turns[0])], "episodes": episodes})

        self.assertIn("path_hash:", turns[0].source_path)
        self.assertIn("path_hash:", turns[0].cwd)
        self.assertNotIn("customer-secret", serialized)
        self.assertNotIn(str(root), serialized)

    def test_wrapper_user_message_does_not_flag_previous_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-22T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\napproval sandbox error", "2026-05-22T10:02:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].issue_flags, [])

    def test_scan_does_not_skip_old_rollout_with_new_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-old.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Old task.", "2026-01-01T10:00:00Z"),
                    message("user", "New continuation.", "2026-05-22T10:00:00Z"),
                ],
            )
            output = Path(raw) / "out"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None),
                mode="weekly",
                start=MODULE.parse_time("2026-05-15T00:00:00Z"),
                end=MODULE.parse_time("2026-05-23T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertIn("category=general", rows[0]["redacted_user_prompt_summary"])

    def test_baseline_honors_window_days(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            first = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-first.jsonl"
            later = root / "sessions" / "2026" / "04" / "15" / "rollout-2026-04-15T10-00-00-later.jsonl"
            write_jsonl(first, [message("user", "First window task.", "2026-01-01T10:00:00Z")])
            write_jsonl(later, [message("user", "Later window task.", "2026-04-15T10:00:00Z")])
            output = Path(raw) / "out"

            MODULE.main(
                [
                    "baseline",
                    "--window-days",
                    "90",
                    "--from",
                    "first",
                    "--source",
                    f"local={root}",
                    "--output",
                    str(output),
                ]
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["turn_count"], 1)
        self.assertEqual(trend["window"]["start"], "2026-01-01T00:00:00Z")
        self.assertEqual(trend["window"]["end"], "2026-04-01T00:00:00Z")

    def test_daily_first_run_uses_active_lookback_days(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-active.jsonl"
            write_jsonl(rollout, [message("user", "Continue active work.", "2026-05-12T10:00:00Z")])
            output = Path(raw) / "out"
            state = Path(raw) / "state.json"

            with mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-22T10:00:00Z")):
                MODULE.main(
                    [
                        "scan-daily",
                        "--active-lookback-days",
                        "14",
                        "--state",
                        str(state),
                        "--source",
                        f"local={root}",
                        "--output",
                        str(output),
                    ]
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["turn_count"], 1)
        self.assertEqual(trend["window"]["start"], "2026-05-08T10:00:00Z")

    def test_make_shards_respects_window_and_reports_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-old.jsonl"
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            summary = root / "sessions" / "2026" / "05" / "22" / "rollout-summary-large.jsonl"
            large = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-large.jsonl"
            write_jsonl(old, [message("user", "Old task.", "2026-01-01T10:00:00Z")])
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-old-oversized " + ("x" * 2000), encoding="utf-8")
            large.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("summary " + ("x" * 2000), encoding="utf-8")
            large.write_text("not-json-but-oversized " + ("x" * 2000), encoding="utf-8")
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root)}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = Path(raw) / "out"
            MODULE.main(
                [
                    "make-shards",
                    "--manifest",
                    str(manifest),
                    "--output",
                    str(output),
                    "--max-raw-bytes",
                    "1000",
                ]
            )
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "oversized")
        self.assertIn("coverage_gap", rows[0])
        self.assertNotIn(str(root), json.dumps(rows))

    def test_window_outside_oversized_rollout_does_not_block_daily_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-old-oversized " + ("x" * 2000), encoding="utf-8")
            output = Path(raw) / "out"
            state = Path(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

            self.assertTrue(state.exists())
            self.assertEqual(trend["coverage_gaps"], [])

    def test_missing_source_reports_gap_and_does_not_update_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = Path(raw) / "missing"
            output = Path(raw) / "out"
            state = Path(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={missing}"], output=str(output), state=str(state), max_raw_bytes=100),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "source_root_missing")
        self.assertNotIn(str(missing), json.dumps(trend))

    def test_validate_output_rejects_invalid_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            (run_dir / "turn_summaries.jsonl").write_text("{bad json\n", encoding="utf-8")
            write_jsonl(run_dir / "episodes.jsonl", [])
            write_jsonl(run_dir / "turn_flags.jsonl", [])
            (run_dir / "trend_report.json").write_text("{}\n", encoding="utf-8")
            (run_dir / "shard_manifest.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "invalid JSON"):
                MODULE.main(["validate-output", "--run-dir", str(run_dir)])

    def test_rollout_summary_file_contributes_flags_without_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=s1 cwd=/secret/repo"},
                    {"kind": "function_call_output", "timestamp": "2026-05-22T10:01:00Z", "text": "permission denied in /customer/code.py"},
                ],
            )
            output = Path(raw) / "out"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=100),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-06-01T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["redacted_user_prompt_summary"], "category=remote_rollout_summary; summary_kind=function_call_output")
        self.assertIn("approval_auth_friction", rows[0]["issue_flags"])
        self.assertNotIn("customer", json.dumps(rows[0]))

    def test_rollout_summary_privacy_marker_contributes_flag_without_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=s1"},
                    {"kind": "summary", "timestamp": "2026-05-22T10:01:00Z", "text": "Contact joey@example.com"},
                ],
            )
            output = Path(raw) / "out"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=100),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-06-01T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertIn("safety_privacy_flag", rows[0]["issue_flags"])
        self.assertNotIn("joey@example.com", json.dumps(rows[0]))

    def test_episode_and_trend_outputs_are_schema_shaped(self) -> None:
        turn = MODULE.TurnSummary(
            turn_id="t1",
            episode_id="e1",
            host="miku-bot-dev",
            session_id="s1",
            source_path="/tmp/rollout.jsonl",
            source_hash="hash",
            timestamp="2026-05-22T10:00:00Z",
            cwd="/repo",
            model="gpt-5.5",
            model_era="gpt-5.5",
            redacted_user_prompt_summary="Fix the review issue",
            assistant_action_summary="Ran tests",
            issue_flags=["verification_gap"],
            prompt_improvement="Ask for exact verification.",
        )

        episodes = MODULE.episode_records([turn])
        trend = MODULE.trend_report([turn], episodes, {"mode": "weekly"})

        self.assertEqual(episodes[0]["host"], "miku-bot-dev")
        self.assertEqual(episodes[0]["friction_flags"], ["verification_gap"])
        self.assertEqual(trend["flagged_turn_count"], 1)
        self.assertEqual(trend["model_eras"]["gpt-5.5"], 1)


if __name__ == "__main__":
    unittest.main()
