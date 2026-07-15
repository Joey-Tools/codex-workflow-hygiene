from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest


def json_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def extract_python_block_after(workflow: str, heading: str, marker: str = "```bash\npython3 - <<'PY'\n") -> str:
    section_start = workflow.index(heading)
    code_start = workflow.index(marker, section_start) + len(marker)
    return workflow[code_start : workflow.index("\nPY\n```", code_start)]


class SkillStructureTests(unittest.TestCase):
    def test_skills_have_frontmatter(self) -> None:
        root = Path(__file__).resolve().parents[1] / "skills"
        skill_files = sorted(root.glob("*/SKILL.md"))
        self.assertGreaterEqual(len(skill_files), 3)
        for path in skill_files:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"), path)
            frontmatter = text.split("---", 2)[1]
            self.assertIn("\nname:", frontmatter, path)
            self.assertIn("\ndescription:", frontmatter, path)

    def test_bounded_command_output_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill_root = root / "skills/bounded-command-output"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        patterns = (skill_root / "references/command-patterns.md").read_text(encoding="utf-8")
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        for trigger in (
            "broad searches or inventories",
            "large Jenkins, GitHub Actions, artifact, manual, diff, or review-range reads",
            "broad or noisy process diagnostics",
            "verbose xcodebuild or other tests and builds",
            "spinner-heavy container builds",
        ):
            self.assertIn(trigger, skill)
        self.assertIn("Apply alongside the domain skill", skill)
        self.assertIn("controls command shape and output handling only", skill)
        self.assertIn("display backstops, not as execution-time bounds", skill)
        self.assertIn("pollable TTY or PTY shape", skill)
        self.assertIn("plain-pipe session after stdin closes", skill)
        self.assertIn("## Searches And Inventories", patterns)
        self.assertIn("## Logs, Artifacts, And Manuals", patterns)
        self.assertIn("## Process And System Diagnostics", patterns)
        self.assertIn("## Builds, Tests, And Polling", patterns)
        self.assertIn("/usr/local/bin/container build", patterns)
        self.assertIn("tail -c 8192 <task-log>", patterns)
        self.assertIn("tr '\\r' '\\n'", patterns)
        self.assertIn("$bounded-command-output", interface)
        self.assertIn("allow_implicit_invocation: true", interface)
        self.assertNotIn("TODO", skill)

    def test_session_mining_avoids_per_record_jsonl_key_dumps(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(encoding="utf-8")
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        self.assertIn("do not run a per-line key dump", skill)
        self.assertIn("jq -R 'fromjson | keys'", skill)
        self.assertIn("aggregate unique keys once", workflow)

    def test_session_mining_avoids_whole_record_tostring_searches(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(encoding="utf-8")
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        self.assertIn("select(tostring | contains", skill)
        self.assertIn("function_call_output", skill)
        self.assertIn("filter by record type and field first", skill)
        self.assertIn("Do not use `jq 'select(tostring | contains", workflow)
        self.assertIn("filter on record shape and specific fields", workflow)
        self.assertIn("function_call_output", workflow)
        self.assertIn("def hit_window", workflow)
        self.assertIn("hit_window(text, needle)", workflow)
        self.assertIn("def add_top_level_fields", workflow)
        self.assertIn("thread_name", workflow)
        self.assertIn("session_id", workflow)
        self.assertIn("current_date", workflow)
        self.assertIn("sandbox_policy", workflow)
        self.assertIn("model_provider", workflow)
        self.assertIn("'output'", workflow)
        self.assertIn("'arguments'", workflow)
        self.assertIn("add_top_level_fields(payload, text_parts)", workflow)
        self.assertIn("elif isinstance(value, dict)", workflow)
        self.assertIn("for item in value.values()", workflow)
        self.assertIn("elif item_type == 'user_message'", workflow)
        self.assertIn("elif item_type == 'task_complete'", workflow)
        self.assertIn("payload.get('message')", workflow)
        self.assertIn("last_agent_message", workflow)
        self.assertIn("record_kind = item_type or obj.get('type') or 'history'", workflow)
        self.assertNotIn("text = json.dumps(payload", workflow)
        self.assertNotIn("snippet = ' '.join(text.split())[:", workflow)

    def test_session_mining_avoids_whole_codex_home_searches(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(encoding="utf-8")
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        self.assertIn("read your rollout", skill)
        self.assertIn("Do not start with keyword `rg -n` over all of `$CODEX_HOME` / `~/.codex`", skill)
        self.assertIn("Do not point raw `rg -n` at the whole `$CODEX_HOME` / `~/.codex` tree", skill)
        self.assertIn('Recent prior turn or "read your rollout":', workflow)
        self.assertIn("Do not run keyword `rg -n ... ~/.codex`", workflow)
        self.assertIn("installed skills, overlays, caches, and package payloads", workflow)

    def test_session_mining_requires_replay_boundary_detection(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(encoding="utf-8")
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")

        self.assertIn("copied and restamped earlier history", skill)
        self.assertIn("A strict record-timestamp filter is not sufficient", skill)
        self.assertIn("latest genuine resume boundary", skill)
        self.assertIn("Detect resumed or forked replay", workflow)
        self.assertIn("stable fingerprint", workflow)
        self.assertIn("Do not deduplicate a real repeated short prompt", workflow)
        self.assertIn("replayed and genuinely new record counts separately", workflow)

    def test_session_retrospective_bounds_operator_output(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-retrospective/SKILL.md").read_text(encoding="utf-8")

        self.assertIn("task-scoped ignored log", skill)
        self.assertIn("progress markers", skill)
        self.assertIn("do not poll with 30k+ visible output caps", skill)
        self.assertIn("`pgrep -af`", skill)
        self.assertIn("`ps -p`", skill)
        self.assertIn("`ps -eo` / `ps -axo`", skill)
        self.assertIn("full `sample` output", skill)

    def test_session_mining_recent_turn_recipe_reads_both_indexes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        code = extract_python_block_after(workflow, 'Recent prior turn or "read your rollout":')

        with tempfile.TemporaryDirectory() as home:
            codex_home = Path(home) / ".codex"
            codex_home.mkdir()
            history_rows = [
                {"session_id": f"history-{index}", "ts": f"2026-06-04T00:{index:02d}:00Z", "text": f"history row {index}"}
                for index in range(20)
            ]
            (codex_home / "history.jsonl").write_text(
                "\n".join(json_dumps(row) for row in history_rows) + "\n",
                encoding="utf-8",
            )
            (codex_home / "session_index.jsonl").write_text(
                json_dumps({
                    "session_id": "index-session",
                    "updated_at": "2026-06-03T00:00:00Z",
                    "cwd": "/tmp/index-repo",
                    "thread_name": "session index row",
                }) + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys.executable, "-c", code],
                check=True,
                capture_output=True,
                env=dict(os.environ, HOME=home),
                text=True,
            )

        lines = result.stdout.splitlines()
        self.assertEqual(13, len(lines))
        self.assertIn("history-19", result.stdout)
        self.assertIn("index-session", result.stdout)
        self.assertIn("session_index.jsonl", result.stdout)

    def test_session_mining_exact_probe_handles_real_record_shapes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n```", start)]

        needle = "needle-structured-probe"
        jsonl = root / "tests/fixtures/codex_session_mining_exact_probe.jsonl"
        result = subprocess.run(
            [sys.executable, "-c", code, str(jsonl), needle],
            check=True,
            capture_output=True,
            text=True,
        )

        output = result.stdout
        for kind in ("history", "session_meta", "turn_context", "user_message", "function_call_output", "task_complete", "thread/start"):
            self.assertIn(f":{kind}:", output)
        self.assertIn("top-level output", output)

        metadata_result = subprocess.run(
            [sys.executable, "-c", code, str(jsonl), "approval_policy"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn(":turn_context:", metadata_result.stdout)

    def test_session_mining_failure_probe_handles_event_message_fields(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        code = extract_python_block_after(workflow, "Focus on tool failures or approval friction:")
        jsonl = root / "tests/fixtures/codex_session_mining_exact_probe.jsonl"
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        self.assertIn(":event_msg:task_complete:", result.stdout)
        self.assertIn("permission denied", result.stdout)
        self.assertIn(":turn_context:None:", result.stdout)
        self.assertIn("approval_policy", result.stdout)

    def test_session_mining_bounded_rollout_probe_handles_structured_user_messages(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        code = extract_python_block_after(workflow, "Search a bounded rollout set without dumping full JSONL records:")
        jsonl = root / "tests/fixtures/codex_session_mining_exact_probe.jsonl"
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        self.assertIn(":event_msg:user_message:", result.stdout)
        self.assertIn("thread/start", result.stdout)

    def test_session_mining_bounded_rollout_probe_caps_output(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        code = extract_python_block_after(workflow, "Search a bounded rollout set without dumping full JSONL records:")
        jsonl = root / "tests/fixtures/codex_session_mining_many_thread_start.jsonl"
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        lines = result.stdout.splitlines()
        self.assertEqual(20, len(lines))
        self.assertIn("sample 20", lines[-1])
        self.assertNotIn("sample 21", result.stdout)

    def test_session_mining_bounded_rollout_probe_skips_tool_output(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        code = extract_python_block_after(workflow, "Search a bounded rollout set without dumping full JSONL records:")
        jsonl = root / "tests/fixtures/codex_session_mining_tool_output_then_thread_start.jsonl"
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        self.assertEqual(1, len(result.stdout.splitlines()))
        self.assertIn(":event_msg:thread/start:", result.stdout)
        self.assertIn("real event", result.stdout)
        self.assertNotIn("tool output", result.stdout)


if __name__ == "__main__":
    unittest.main()
