from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


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


class SessionRetrospectiveTests(unittest.TestCase):
    def test_ignores_wrapper_and_redacts_flagged_turns(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "# AGENTS.md instructions\nsecret wrapper", "2026-05-22T10:00:00Z"),
                    message("user", "Please fix this using https://internal.example/case and token ghp_abcdefghijklmnop123456.", "2026-05-22T10:01:00Z"),
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
        self.assertIn("[REDACTED_URL]", turns[0].redacted_user_prompt_summary)
        self.assertIn("[REDACTED_SECRET]", turns[0].redacted_user_prompt_summary)
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("approval_auth_friction", turns[0].issue_flags)
        self.assertIn("safety_privacy_flag", turns[0].issue_flags)

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
