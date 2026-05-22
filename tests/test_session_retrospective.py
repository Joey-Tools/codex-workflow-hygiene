from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
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


def write_local_evidence(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "session_index.jsonl").write_text("{}\n", encoding="utf-8")
    (root / "history.jsonl").write_text("{}\n", encoding="utf-8")


def write_remote_metadata(
    root: Path,
    host: str,
    *,
    window_start: str = "2026-05-01T00:00:00Z",
    window_end: str = "2026-05-02T00:00:00Z",
    materialized_at: str = "2026-05-02T00:00:00Z",
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / MODULE.REMOTE_SOURCE_METADATA_FILE).write_text(
        json.dumps(
            {
                "host": host,
                "status": "ready",
                "window_start": window_start,
                "window_end": window_end,
                "materialized_at": materialized_at,
            }
        ),
        encoding="utf-8",
    )


def write_default_remote_sources(base: str | Path, *, timestamp: str = "2026-05-01T10:00:00Z") -> list[str]:
    base_path = Path(base)
    source_args: list[str] = []
    date_part, time_part = timestamp.removesuffix("Z").split("T", 1)
    rollout_time = time_part.replace(":", "-")
    for host in MODULE.DEFAULT_REMOTE_HOSTS:
        root = base_path / host
        write_remote_metadata(root, host)
        rollout = root / "sessions" / date_part[:4] / date_part[5:7] / date_part[8:10] / f"rollout-{date_part}T{rollout_time}-{host}.jsonl"
        write_jsonl(rollout, [message("user", f"{host} task.", timestamp)])
        source_args.append(f"{host}={root}")
    return source_args


def manifest_fixture(**overrides: object) -> dict:
    manifest = {
        "schema_version": 1,
        "mode": "daily",
        "window": {"mode": "daily", "start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
        "sources": [
            {
                "host": "local",
                "root_ref": "path_ref_v1:0123456789abcdef",
                "rollout_count": 1,
                "summary_count": 0,
                "status": "ready",
            }
        ],
        "coverage_gaps": [],
        "redaction_policy_version": 1,
        "retention_safe": True,
        "retention_note": "Derived retained manifest; raw location fields removed and opaque refs preserved.",
    }
    manifest.update(overrides)
    return manifest


def safe_output_dir(root: str, name: str = "out") -> Path:
    return Path(root) / ".codex-local" / "session-retrospective" / name


def export_retained(run_dir: Path, root: str, name: str = "history-retained") -> Path:
    retained_output = Path(root) / name
    MODULE.main(["export-retained", "--run-dir", str(run_dir), "--output", str(retained_output)])
    return retained_output


def write_history_repo(root: str | Path, retained_dir: Path | None = None) -> tuple[Path, str]:
    repo = Path(root) / "history-repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=repo, check=True)
    if retained_dir is None:
        (repo / "retained.json").write_text("{}\n", encoding="utf-8")
        subprocess.run(["git", "add", "retained.json"], cwd=repo, check=True)
    else:
        target = repo / "retained" / "daily"
        target.mkdir(parents=True, exist_ok=True)
        for name in MODULE.RETAINED_OUTPUT_FILES:
            (target / name).write_bytes((retained_dir / name).read_bytes())
        subprocess.run(["git", "add", "retained"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=repo, check=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    return repo, commit


def history_commit_args(root: str | Path, retained_dir: Path) -> list[str]:
    repo, commit = write_history_repo(root, retained_dir)
    return ["--history-repo", str(repo), "--history-commit", commit]


def advance_state(run_dir: Path, state: Path, root: str) -> Path:
    retained_output = export_retained(run_dir, root)
    MODULE.main(
        [
            "advance-state",
            "--run-dir",
            str(run_dir),
            "--retained-run-dir",
            str(retained_output),
            "--state",
            str(state),
            *history_commit_args(root, retained_output),
        ]
    )
    return retained_output


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


def untimestamped_message(role: str, text: str) -> dict:
    return {
        "type": "response_item",
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
    def setUp(self) -> None:
        self._key_tmp = tempfile.TemporaryDirectory()
        self._old_key_file = os.environ.get("CODEX_SESSION_RETROSPECTIVE_KEY_FILE")
        self._old_key = os.environ.get("CODEX_SESSION_RETROSPECTIVE_KEY")
        os.environ["CODEX_SESSION_RETROSPECTIVE_KEY_FILE"] = str(Path(self._key_tmp.name) / "opaque_ref_key")
        os.environ.pop("CODEX_SESSION_RETROSPECTIVE_KEY", None)
        MODULE.PATH_REF_KEY = None

    def tearDown(self) -> None:
        if self._old_key_file is None:
            os.environ.pop("CODEX_SESSION_RETROSPECTIVE_KEY_FILE", None)
        else:
            os.environ["CODEX_SESSION_RETROSPECTIVE_KEY_FILE"] = self._old_key_file
        if self._old_key is None:
            os.environ.pop("CODEX_SESSION_RETROSPECTIVE_KEY", None)
        else:
            os.environ["CODEX_SESSION_RETROSPECTIVE_KEY"] = self._old_key
        MODULE.PATH_REF_KEY = None
        self._key_tmp.cleanup()

    def test_filename_parsers_support_current_and_legacy_rollouts(self) -> None:
        current = Path("rollout-2026-05-07T13-24-44-019d-uuid.jsonl")
        legacy = Path("rollout-2025-05-26-legacy-uuid.jsonl")

        self.assertEqual(MODULE.session_id_from_path(current), MODULE.opaque_session_id("019d-uuid"))
        self.assertEqual(MODULE.session_id_from_path(legacy), MODULE.opaque_session_id("legacy-uuid"))
        self.assertRegex(MODULE.session_id_from_path(current), r"^[0-9a-f]{20}$")
        self.assertNotEqual(MODULE.session_id_from_path(current), "019d-uuid")
        self.assertNotEqual(MODULE.session_id_from_path(legacy), "legacy-uuid")
        self.assertEqual(MODULE.iso(MODULE.rollout_date_from_path(current)), "2026-05-07T13:24:44Z")
        self.assertEqual(MODULE.iso(MODULE.rollout_date_from_path(legacy)), "2025-05-26T00:00:00Z")

    def test_prompt_category_does_not_treat_prompt_as_pr_review(self) -> None:
        self.assertEqual(MODULE.prompt_category("Improve this prompt for the project."), "general")
        self.assertEqual(MODULE.prompt_category("Review this PR."), "review")
        self.assertNotIn("git_or_pr", MODULE.safe_assistant_summary(["Improved the prompt."]))

    def test_auth_friction_flag_does_not_match_authoring(self) -> None:
        self.assertNotIn("approval_auth_friction", MODULE.flags_for_text("Improve skill authoring guidance."))
        self.assertIn("approval_auth_friction", MODULE.flags_for_text("Remote host is auth gated."))

    def test_meaningful_prompt_text_keeps_real_prompt_after_leading_wrappers(self) -> None:
        wrapped = (
            "# AGENTS.md instructions for /tmp/repo\n"
            "<INSTRUCTIONS>Repository policy.</INSTRUCTIONS>"
            "<environment_context>Runtime metadata.</environment_context>\n"
            "Please implement the session retrospective workflow."
        )

        self.assertEqual(
            MODULE.meaningful_prompt_text(wrapped),
            "Please implement the session retrospective workflow.",
        )
        self.assertTrue(MODULE.meaningful_user_text(wrapped))
        self.assertFalse(MODULE.meaningful_user_text("# AGENTS.md instructions\nRepository policy only."))
        self.assertFalse(
            MODULE.meaningful_user_text("Run a read-only daily retrospective over Joey's Codex session activity.")
        )

    def test_default_sources_include_remote_hosts_as_missing_until_materialized(self) -> None:
        sources = MODULE.parse_sources(None)

        self.assertEqual([source.host for source in sources], ["local", "miku-bot-dev", "hoteng-srv-01"])
        self.assertIsNone(sources[0].missing_reason)
        self.assertEqual(sources[1].missing_reason, "remote_source_not_materialized")
        self.assertEqual(sources[2].missing_reason, "remote_source_not_materialized")

    def test_explicit_sources_still_require_default_host_coverage(self) -> None:
        sources = MODULE.parse_sources(["local=/tmp/local", "miku-bot-dev=/tmp/miku"])

        self.assertEqual([source.host for source in sources], ["local", "miku-bot-dev", "hoteng-srv-01"])
        self.assertEqual(sources[2].missing_reason, "remote_source_not_materialized")
        self.assertEqual(
            [source.host for source in MODULE.parse_sources(["local=/tmp/local"], require_default_hosts=False)],
            ["local"],
        )

    def test_partial_host_default_sources_use_local_only(self) -> None:
        sources = MODULE.parse_sources(None, require_default_hosts=False)

        self.assertEqual([source.host for source in sources], ["local"])

    def test_parse_sources_deduplicates_repeated_host_path(self) -> None:
        sources = MODULE.parse_sources(["local=/tmp/local", "local=/tmp/local"], require_default_hosts=False)

        self.assertEqual(len(sources), 1)

    def test_source_file_discovery_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            outside = Path(raw) / "outside-rollout.jsonl"
            outside.write_text(json.dumps(message("user", "Outside task.", "2026-05-01T10:00:00Z")) + "\n", encoding="utf-8")
            link = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-link.jsonl"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(outside)

            source = MODULE.Source("local", root)
            self.assertEqual(MODULE.source_rollouts(source), [])

    def test_source_rollouts_includes_archived_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            active = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-active.jsonl"
            archived = root / "archived_sessions" / "2026" / "04" / "01" / "rollout-2026-04-01T10-00-00-archived.jsonl"
            summary = root / "archived_sessions" / "2026" / "04" / "01" / "rollout-summary-2026-04-01.jsonl"
            write_jsonl(active, [message("user", "Active task.", "2026-05-01T10:00:00Z")])
            write_jsonl(archived, [message("user", "Archived task.", "2026-04-01T10:00:00Z")])
            write_jsonl(summary, [message("user", "Summary.", "2026-04-01T10:00:00Z")])

            paths = MODULE.source_rollouts(MODULE.Source("local", root))

        self.assertEqual({path.name for path in paths}, {active.name, archived.name})

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
        self.assertNotIn("redacted_excerpt=", turns[0].redacted_user_prompt_summary)
        self.assertNotIn("internal.example", turns[0].redacted_user_prompt_summary)
        self.assertNotIn("sk-proj", turns[0].redacted_user_prompt_summary)
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("approval_auth_friction", turns[0].issue_flags)
        self.assertIn("safety_privacy_flag", turns[0].issue_flags)

    def test_sensitive_prompt_excerpt_and_topic_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-sensitive.jsonl"
            write_jsonl(
                rollout,
                [
                    message(
                        "user",
                        "Fix failed deploy password=hunter2 Bearer abc.def.ghi /Users/hoteng/customer/repo /root/workspace/customer/repo customer_id=AcmeCorp",
                        "2026-05-22T10:01:00Z",
                    )
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            summary = turns[0].redacted_user_prompt_summary

        self.assertIn("safety_privacy_flag", turns[0].issue_flags)
        self.assertNotIn("redacted_excerpt=", summary)
        self.assertNotIn("hunter2", summary)
        self.assertNotIn("Bearer", summary)
        self.assertNotIn("/Users/hoteng", summary)
        self.assertNotIn("/root/workspace", summary)
        self.assertNotIn("AcmeCorp", summary)

    def test_non_sensitive_flagged_prompt_keeps_opaque_topic_ref(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-failed.jsonl"
            write_jsonl(rollout, [message("user", "Fix the failed calendar sync verification.", "2026-05-22T10:01:00Z")])

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("topic_ref=topic_ref:", turns[0].redacted_user_prompt_summary)
        self.assertNotIn("redacted_excerpt=", turns[0].redacted_user_prompt_summary)

    def test_topic_ref_is_not_unsalted_dictionary_hash(self) -> None:
        redacted_text = "Fix the failed calendar sync verification."
        old_dictionary_ref = "topic_ref:" + hashlib.sha256(
            "calendar+failed+sync+verification".encode("utf-8")
        ).hexdigest()[:12]

        topic_ref = MODULE.prompt_topic_key(redacted_text)

        self.assertTrue(topic_ref.startswith("topic_ref:"))
        self.assertEqual(topic_ref, MODULE.prompt_topic_key(redacted_text))
        self.assertNotEqual(topic_ref, old_dictionary_ref)

    def test_path_refs_are_stable_across_processes_with_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            key_file = Path(raw) / ".codex-local" / "session-retrospective" / "opaque_ref_key"
            probe = (
                "import importlib.util, sys\n"
                f"spec = importlib.util.spec_from_file_location('session_retrospective', {str(SCRIPT)!r})\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "sys.modules[spec.name] = module\n"
                "spec.loader.exec_module(module)\n"
                "print(module.path_ref('/tmp/customer/repo'))\n"
            )
            env = os.environ.copy()
            env["CODEX_SESSION_RETROSPECTIVE_KEY_FILE"] = str(key_file)

            first = subprocess.check_output([sys.executable, "-c", probe], env=env, text=True).strip()
            second = subprocess.check_output([sys.executable, "-c", probe], env=env, text=True).strip()

        self.assertEqual(first, second)
        self.assertTrue(first.startswith("path_ref_v1:"))

    def test_human_prompt_mentioning_retrospective_workflow_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-human.jsonl"
            write_jsonl(
                rollout,
                [
                    message(
                        "user",
                        "You missed remote hosts in the codex-session-retrospective workflow; please fix the coverage.",
                        "2026-05-22T10:01:00Z",
                    )
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("user_correction", turns[0].issue_flags)

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

    def test_extract_rollout_splits_unrelated_same_category_topics(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the billing helper.", "2026-05-22T10:01:00Z"),
                    message("user", "Please implement the calendar sync.", "2026-05-22T10:03:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            episodes = MODULE.episode_records(turns)

        self.assertEqual(len(turns), 2)
        self.assertNotEqual(turns[0].episode_id, turns[1].episode_id)
        self.assertEqual(len(episodes), 2)

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

    def test_extract_rollout_preserves_distinct_same_second_user_prompts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-fast.jsonl"
            write_jsonl(
                rollout,
                [
                    event_user_message("Review PR 123.", "2026-05-22T10:01:00.001Z"),
                    event_user_message("Review PR 124.", "2026-05-22T10:01:00.002Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 2)

    def test_extract_rollout_does_not_dedupe_fallback_timestamp_turns(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-undated.jsonl"
            write_jsonl(
                rollout,
                [
                    untimestamped_message("user", "Review the PR."),
                    untimestamped_message("user", "Review the PR."),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 2)

    def test_wrapper_only_user_message_keeps_active_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-wrapper.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Fix the failing deployment.", "2026-05-22T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "Ran the verification and it failed.", "2026-05-22T10:02:00Z"),
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

    def test_existing_daily_skill_friction_wrapper_is_not_user_episode(self) -> None:
        prompt = (
            "Run inside the dedicated worktree provisioned for this automation. "
            "Use the automation's configured model and reasoning effort unless the runtime refuses them. "
            "When reconstructing the real user task from rollouts, ignore injected wrapper content. "
            "Check approval/auth friction, secrets, customer data, and destructive commands."
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-dsf.jsonl"
            write_jsonl(rollout, [message("user", prompt, "2026-05-22T10:01:00Z")])

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(turns, [])

    def test_agent_default_prompt_is_not_treated_as_user_episode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-agent.jsonl"
            write_jsonl(
                rollout,
                [
                    message(
                        "user",
                        "Use $codex-session-retrospective to run a read-only retrospective over Codex session history and produce redacted episode, turn, and trend artifacts.",
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

        self.assertIn("path_ref_v1:", turns[0].source_path)
        self.assertIn("path_ref_v1:", turns[0].cwd)
        self.assertNotIn("customer-secret", serialized)
        self.assertNotIn(str(root), serialized)

    def test_retained_ids_do_not_use_unsalted_raw_path_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-undated.jsonl"
            write_jsonl(
                rollout,
                [
                    message_with_cwd(
                        "user",
                        "Please fix this permission denied failure.",
                        "2026-05-22T10:01:00Z",
                        "/Users/hoteng/Program/GitHub/customer-secret/repo",
                    ),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            episodes = MODULE.episode_records(turns)

        raw_path_hash = MODULE.stable_hash(rollout.as_posix(), 20)
        raw_turn_hash = MODULE.stable_hash(f"local|{rollout}|1|2026-05-22T10:01:00Z", 20)
        raw_episode_hash = MODULE.stable_hash(
            "|".join(
                [
                    "local",
                    MODULE.session_id_from_path(rollout),
                    "/Users/hoteng/Program/GitHub/customer-secret/repo",
                    "2026-05-22",
                    "debug_or_fix",
                    MODULE.prompt_topic_key("Please fix this permission denied failure."),
                ]
            ),
            20,
        )

        self.assertNotEqual(turns[0].session_id, raw_path_hash)
        self.assertNotEqual(turns[0].turn_id, raw_turn_hash)
        self.assertNotEqual(episodes[0]["episode_id"], raw_episode_hash)

    def test_retained_source_hash_does_not_use_plain_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Please summarize this session.", "2026-05-22T10:00:00Z")])

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            plain_hash = MODULE.file_hash(rollout)

        self.assertRegex(turns[0].source_hash, r"^[0-9a-f]{64}$")
        self.assertNotEqual(turns[0].source_hash, plain_hash)

    def test_summary_session_id_is_opaque(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=customer-incident-123 cwd=/secret/repo"},
                    {"kind": "summary", "timestamp": "2026-05-22T10:01:00Z", "text": "permission denied"},
                ],
            )

            turns = MODULE.extract_summary_file(MODULE.Source("remote", root), summary, None, None)

        self.assertRegex(turns[0].session_id, r"^[0-9a-f]{20}$")
        self.assertNotEqual(turns[0].session_id, "customer-incident-123")

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

    def test_wrapper_followup_output_does_not_pollute_previous_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-22T10:01:00Z"),
                    message("assistant", "Implemented the helper.", "2026-05-22T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    message("assistant", "Failed with permission denied.", "2026-05-22T10:04:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:05:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                    message("user", "Now continue the real task.", "2026-05-22T10:06:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 2)
        self.assertEqual(turns[0].issue_flags, [])
        self.assertNotIn("blocked_or_failed", turns[0].assistant_action_summary)
        self.assertEqual(turns[1].issue_flags, [])

    def test_task_complete_last_agent_message_updates_assistant_summary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-22T10:01:00Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {
                            "type": "task_complete",
                            "last_agent_message": "Implemented the helper and ran tests.",
                        },
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("implementation", turns[0].assistant_action_summary)
        self.assertIn("verification", turns[0].assistant_action_summary)

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
            old_mtime = MODULE.parse_time("2026-01-02T00:00:00Z").timestamp()
            os.utime(rollout, (old_mtime, old_mtime))
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, allow_partial_hosts=True),
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

    def test_scan_uses_dated_path_for_untimestamped_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-undated.jsonl"
            write_jsonl(rollout, [untimestamped_message("user", "Directory dated task.")])
            old_mtime = MODULE.parse_time("2026-01-01T00:00:00Z").timestamp()
            os.utime(rollout, (old_mtime, old_mtime))
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-01T00:00:00Z")
        self.assertIn("category=general", rows[0]["redacted_user_prompt_summary"])

    def test_explicit_local_rollout_only_source_does_not_require_index_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "copied-local"
            rollout = root / "rollout-2026-05-01T10-00-00-copied.jsonl"
            write_jsonl(rollout, [message("user", "Copied rollout task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual([gap["reason"] for gap in trend["coverage_gaps"]], ["partial_host_scope"])

    def test_baseline_honors_window_days(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            first = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-first.jsonl"
            later = root / "sessions" / "2026" / "04" / "15" / "rollout-2026-04-15T10-00-00-later.jsonl"
            write_jsonl(first, [message("user", "First window task.", "2026-01-01T10:00:00Z")])
            write_jsonl(later, [message("user", "Later window task.", "2026-04-15T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.main(
                [
                    "baseline",
                    "--window-days",
                    "90",
                    "--from",
                    "first",
                    "--source",
                    f"local={root}",
                    "--allow-partial-hosts",
                    "--output",
                    str(output),
                ]
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["turn_count"], 1)
        self.assertEqual(trend["window"]["start"], "2026-01-01T00:00:00Z")
        self.assertEqual(trend["window"]["end"], "2026-04-01T00:00:00Z")

    def test_baseline_from_first_includes_rollout_summary_dates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            later = root / "sessions" / "2026" / "04" / "15" / "rollout-2026-04-15T10-00-00-later.jsonl"
            write_jsonl(summary, [{"timestamp": "2026-01-01T10:00:00Z", "kind": "summary", "text": "failed verification"}])
            write_jsonl(later, [message("user", "Later window task.", "2026-04-15T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.main(
                [
                    "baseline",
                    "--window-days",
                    "90",
                    "--from",
                    "first",
                    "--end",
                    "2026-05-22T00:00:00Z",
                    "--source",
                    f"local={root}",
                    "--allow-partial-hosts",
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
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

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
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                    ]
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["turn_count"], 1)
        self.assertEqual(trend["window"]["start"], "2026-05-08T10:00:00Z")

    def test_default_scan_end_truncates_microseconds(self) -> None:
        with mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-22T10:00:00.987654Z")):
            end = MODULE.scan_end(types.SimpleNamespace(end=None))

        self.assertEqual(end, MODULE.parse_time("2026-05-22T10:00:00Z"))
        self.assertEqual(MODULE.iso(end), "2026-05-22T10:00:00Z")

    def test_scan_commands_reject_non_positive_windows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            output = safe_output_dir(raw)

            with self.assertRaisesRegex(SystemExit, "active-lookback-days.*positive"):
                MODULE.main(
                    [
                        "scan-daily",
                        "--active-lookback-days",
                        "0",
                        "--source",
                        f"local={root}",
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                        "--end",
                        "2026-05-22T10:00:00Z",
                    ]
                )
            with self.assertRaisesRegex(SystemExit, "--days.*positive"):
                MODULE.main(
                    [
                        "scan-weekly",
                        "--days",
                        "0",
                        "--source",
                        f"local={root}",
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                        "--end",
                        "2026-05-22T10:00:00Z",
                    ]
                )
            with self.assertRaisesRegex(SystemExit, "--window-days.*positive"):
                MODULE.main(
                    [
                        "baseline",
                        "--window-days",
                        "0",
                        "--source",
                        f"local={root}",
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                        "--end",
                        "2026-05-22T10:00:00Z",
                    ]
                )

    def test_daily_scan_uses_explicit_end_for_materialized_remote_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            remote = Path(raw) / "miku-bot-dev"
            write_local_evidence(local)
            write_remote_metadata(remote, "miku-bot-dev")
            local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            remote_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(local_rollout, [message("user", "Local task.", "2026-05-01T10:00:00Z")])
            write_jsonl(remote_rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(
                MODULE,
                "parse_sources",
                return_value=[
                    MODULE.Source("local", local),
                    MODULE.Source("miku-bot-dev", remote),
                ],
            ), mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-02T00:05:00Z")):
                MODULE.main(
                    [
                        "scan-daily",
                        "--active-lookback-days",
                        "1",
                        "--end",
                        "2026-05-02T00:00:00Z",
                        "--state",
                        str(state),
                        "--source",
                        f"local={local}",
                        "--output",
                        str(output),
                    ]
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["window"]["end"], "2026-05-02T00:00:00Z")
        self.assertEqual(trend["coverage_gaps"], [])

    def test_daily_existing_state_uses_last_scan_for_output_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            old_rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-active.jsonl"
            new_rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T09-00-00-active.jsonl"
            write_jsonl(old_rollout, [message("user", "Already reported active work.", "2026-05-12T10:00:00Z")])
            write_jsonl(new_rollout, [message("user", "New daily work.", "2026-05-22T09:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-21T10:00:00Z"}), encoding="utf-8")

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
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                    ]
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            state_after_scan = json.loads(state.read_text(encoding="utf-8"))

        self.assertEqual(trend["turn_count"], 1)
        self.assertEqual(trend["window"]["start"], "2026-05-21T10:00:00Z")
        self.assertEqual(state_after_scan["last_scan_at"], "2026-05-21T10:00:00Z")

    def test_daily_existing_state_rejects_invalid_last_scan_at(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "not-a-date"}), encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "state last_scan_at"):
                MODULE.main(
                    [
                        "scan-daily",
                        "--state",
                        str(state),
                        "--source",
                        f"local={root}",
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                        "--end",
                        "2026-05-22T10:00:00Z",
                    ]
                )

    def test_daily_existing_state_revisits_active_thread_context_without_duplicate_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-active.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the active deployment.", "2026-05-12T10:00:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T09:00:00Z",
                        "payload": {"output": "Process exited with code 1"},
                    },
                ],
            )
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-21T10:00:00Z"}), encoding="utf-8")

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
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                    ]
                )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            state_after_scan = json.loads(state.read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertIn("failed_command", rows[0]["issue_flags"])
        self.assertEqual(trend["window"]["start"], "2026-05-21T10:00:00Z")
        self.assertEqual(state_after_scan["last_scan_at"], "2026-05-21T10:00:00Z")

    def test_active_thread_continuation_uses_window_event_turn_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-active.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the active deployment.", "2026-05-12T10:00:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T09:00:00Z",
                        "payload": {"output": "Process exited with code 1"},
                    },
                ],
            )

            first = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-08T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
            )
            continuation = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-08T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T10:00:00Z"),
            )

        self.assertEqual(len(first), 1)
        self.assertEqual(len(continuation), 1)
        self.assertNotEqual(first[0].turn_id, continuation[0].turn_id)
        self.assertEqual(continuation[0].timestamp, "2026-05-22T09:00:00Z")
        self.assertIn("failed_command", continuation[0].issue_flags)

    def test_active_thread_with_fallback_timestamp_emits_when_mtime_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-undated-active.jsonl"
            write_jsonl(
                rollout,
                [
                    untimestamped_message("user", "Debug the active undated deployment."),
                    {
                        "type": "function_call_output",
                        "payload": {"output": "Process exited with code 1"},
                    },
                ],
            )
            active_mtime = MODULE.parse_time("2026-05-22T09:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-08T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T10:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertIn("failed_command", turns[0].issue_flags)

    def test_pre_window_user_with_in_window_failure_is_not_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-active.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the long-running deployment.", "2026-01-01T10:00:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T09:00:00Z",
                        "payload": {"output": "Process exited with code 1"},
                    },
                ],
            )
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-21T10:00:00Z"}), encoding="utf-8")

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
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                    ]
                )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-22T09:00:00Z")
        self.assertIn("failed_command", rows[0]["issue_flags"])

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
            old_mtime = MODULE.parse_time("2026-01-02T10:00:00Z").timestamp()
            os.utime(old, (old_mtime, old_mtime))
            os.utime(old_large, (old_mtime, old_mtime))
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)
            MODULE.main(
                [
                    "make-shards",
                    "--manifest",
                    str(manifest),
                    "--output",
                    str(output),
                    "--max-raw-bytes",
                    "1000",
                    "--include-raw-paths",
                ]
            )
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "oversized")
        self.assertIn("coverage_gap", rows[0])
        self.assertEqual(rows[0]["path"], str(large))
        self.assertIn("path_ref_v1:", rows[0]["path_ref"])

    def test_make_shards_omits_raw_paths_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-ready.jsonl"
            write_jsonl(rollout, [message("user", "Shard task.", "2026-05-22T10:00:00Z")])
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertNotIn("path", rows[0])
        self.assertIn("path_ref_v1:", rows[0]["path_ref"])

    def test_make_shards_reports_in_window_invalid_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            bad = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-bad.jsonl"
            bad.parent.mkdir(parents=True, exist_ok=True)
            bad.write_text("{bad json\n", encoding="utf-8")
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(rows[0]["status"], "invalid")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_reports_non_object_jsonl_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            bad = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-array.jsonl"
            bad.parent.mkdir(parents=True, exist_ok=True)
            bad.write_text("[]\n", encoding="utf-8")
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(rows[0]["status"], "invalid")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_skips_non_ready_manifest_sources(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-stale.jsonl"
            write_jsonl(rollout, [message("user", "Stale remote task.", "2026-05-22T10:00:00Z")])
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "stale"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = list((output / "shards.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

    def test_make_shards_rejects_missing_manifest_source_status(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
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
            output = safe_output_dir(raw)

            with self.assertRaisesRegex(SystemExit, "status=ready"):
                MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])

    def test_make_shards_rejects_invalid_manifest_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "not-a-date", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            with self.assertRaisesRegex(SystemExit, "invalid manifest window start"):
                MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])

    def test_make_shards_ignores_window_external_invalid_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_bad = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            old_bad.parent.mkdir(parents=True, exist_ok=True)
            old_bad.write_text("{bad json\n", encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-01-01T10:00:00Z").timestamp()
            os.utime(old_bad, (old_mtime, old_mtime))
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = list((output / "shards.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

    def test_make_shards_uses_dated_path_to_ignore_old_invalid_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_bad = root / "sessions" / "2026" / "01" / "01" / "rollout-undated-bad.jsonl"
            old_bad.parent.mkdir(parents=True, exist_ok=True)
            old_bad.write_text("{bad json\n", encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-01-01T10:00:00Z").timestamp()
            os.utime(old_bad, (old_mtime, old_mtime))
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = list((output / "shards.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

    def test_make_shards_reports_old_invalid_jsonl_with_in_window_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_bad = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            old_bad.parent.mkdir(parents=True, exist_ok=True)
            old_bad.write_text('{"timestamp":"2026-05-22T10:00:00Z", bad json\n', encoding="utf-8")
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(rows[0]["status"], "invalid")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_reports_old_invalid_jsonl_with_active_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_bad = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            old_bad.parent.mkdir(parents=True, exist_ok=True)
            old_bad.write_text("{bad json\n", encoding="utf-8")
            active_mtime = MODULE.parse_time("2026-05-22T10:00:00Z").timestamp()
            os.utime(old_bad, (active_mtime, active_mtime))
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(rows[0]["status"], "invalid")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_ignores_old_invalid_jsonl_with_future_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_bad = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            old_bad.parent.mkdir(parents=True, exist_ok=True)
            old_bad.write_text("{bad json\n", encoding="utf-8")
            future_mtime = MODULE.parse_time("2026-06-15T10:00:00Z").timestamp()
            os.utime(old_bad, (future_mtime, future_mtime))
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = list((output / "shards.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

    def test_make_shards_rejects_retained_or_rootless_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = safe_output_dir(raw)
            retained = Path(raw) / "retained_manifest.json"
            retained.write_text(
                json.dumps(
                    {
                        "retention_safe": True,
                        "sources": [{"host": "local", "root_ref": "path_ref_v1:0123456789abcdef", "rollout_count": 1, "status": "ready"}],
                    }
                ),
                encoding="utf-8",
            )
            rootless = Path(raw) / "rootless_manifest.json"
            rootless.write_text(json.dumps({"sources": [{"host": "local"}]}), encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "requires transient"):
                MODULE.main(["make-shards", "--manifest", str(retained), "--output", str(output)])
            with self.assertRaisesRegex(SystemExit, "raw root fields"):
                MODULE.main(["make-shards", "--manifest", str(rootless), "--output", str(output)])

    def test_transient_output_rejects_tracked_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            unsafe = Path(raw) / "reports"

            with self.assertRaisesRegex(SystemExit, "must be under .codex-local/session-retrospective"):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(unsafe), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            traversal = safe_output_dir(raw) / ".." / ".." / "reports"
            with self.assertRaisesRegex(SystemExit, "must be under .codex-local/session-retrospective"):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(traversal), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            unsafe_state = Path(raw) / "state.json"
            with self.assertRaisesRegex(SystemExit, "must be under .codex-local/session-retrospective"):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(safe_output_dir(raw)), state=str(unsafe_state), max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )

    def test_transient_output_rejects_child_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            output.mkdir(parents=True)
            outside = Path(raw) / "outside.jsonl"
            outside.write_text("do not overwrite\n", encoding="utf-8")
            (output / "turn_summaries.jsonl").symlink_to(outside)

            with self.assertRaisesRegex(SystemExit, "unsafe output path"):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )

            self.assertEqual(outside.read_text(encoding="utf-8"), "do not overwrite\n")

    def test_scan_daily_rejects_unsafe_state_before_loading(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            unsafe_state = Path(raw) / "state.json"
            unsafe_state.write_text("{bad json\n", encoding="utf-8")
            output = safe_output_dir(raw)

            with mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-22T10:00:00Z")):
                with self.assertRaisesRegex(SystemExit, "must be under .codex-local/session-retrospective"):
                    MODULE.main(
                        [
                            "scan-daily",
                            "--state",
                            str(unsafe_state),
                            "--source",
                            f"local={root}",
                            "--allow-partial-hosts",
                            "--output",
                            str(output),
                        ]
                    )

    def test_scan_daily_rejects_symlink_state_before_loading(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            linked_state = safe_output_dir(raw) / "linked-state.json"
            linked_state.write_text(json.dumps({"last_scan_at": "2026-05-21T10:00:00Z"}), encoding="utf-8")
            state.symlink_to(linked_state)
            output = safe_output_dir(raw, "out")

            with self.assertRaisesRegex(SystemExit, "unsafe state file"):
                MODULE.main(
                    [
                        "scan-daily",
                        "--state",
                        str(state),
                        "--source",
                        f"local={root}",
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                        "--end",
                        "2026-05-22T10:00:00Z",
                    ]
                )

    def test_advance_state_after_valid_scan_ignores_window_external_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-old-oversized " + ("x" * 2000), encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-01-02T10:00:00Z").timestamp()
            os.utime(old_large, (old_mtime, old_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

            self.assertFalse(state.exists())
            advance_state(output, state, raw)

            self.assertTrue(state.exists())
            state_data = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(state_data["last_scan_at"], "2026-05-02T00:00:00Z")
            self.assertRegex(state_data["last_history_commit"], r"^[0-9a-f]{40}$")
            self.assertEqual(trend["coverage_gaps"], [])

    def test_old_oversized_rollout_with_in_window_tail_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text(
                ("x" * 2000)
                + "\n"
                + json.dumps(message("user", "Fresh continuation.", "2026-05-01T12:00:00Z"))
                + "\n",
                encoding="utf-8",
            )
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            retained_output = export_retained(output, raw)
            with self.assertRaisesRegex(SystemExit, "coverage gaps"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained_output),
                        "--state",
                        str(state),
                        *history_commit_args(raw, retained_output),
                    ]
                )

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "oversized_rollout_skipped")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_old_oversized_rollout_checks_timestamps_before_mtime_skip(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text(
                json.dumps(message("user", "Fresh continuation.", "2026-05-01T12:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            old_mtime = MODULE.parse_time("2026-01-02T10:00:00Z").timestamp()
            os.utime(old_large, (old_mtime, old_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "oversized_rollout_skipped")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_old_oversized_rollout_with_active_mtime_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-active-oversized " + ("x" * 2000), encoding="utf-8")
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(old_large, (active_mtime, active_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "oversized_rollout_skipped")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_old_oversized_rollout_prefilter_does_not_use_full_raw_timestamp_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-old-oversized " + ("x" * 2000), encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-01-02T10:00:00Z").timestamp()
            os.utime(old_large, (old_mtime, old_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(MODULE, "raw_timestamp_in_window", side_effect=AssertionError("unbounded raw scan")):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["coverage_gaps"][0]["reason"], "partial_host_scope")

    def test_old_oversized_rollout_with_large_in_window_record_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            large_payload = "x" * (300 * 1024)
            old_large.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-05-01T12:00:00Z",
                        "type": "function_call_output",
                        "payload": {"output": large_payload},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "oversized_rollout_skipped")

    def test_old_oversized_rollout_with_uncertain_middle_timestamp_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text(
                json.dumps(message("user", "Middle continuation.", "2026-05-01T12:00:00Z"))
                + "\n"
                + ("x" * 1000),
                encoding="utf-8",
            )
            old_mtime = MODULE.parse_time("2026-01-02T10:00:00Z").timestamp()
            os.utime(old_large, (old_mtime, old_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(MODULE, "ROLLOUT_TIMESTAMP_SCAN_BYTES", 128):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "oversized_rollout_skipped")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_scan_manifest_keeps_execution_path_and_redacted_ref(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=10000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))
            retained = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))
            MODULE.main(["validate-output", "--run-dir", str(output)])

        self.assertEqual(manifest["sources"][0]["root"], str(root))
        self.assertIn("path_ref_v1:", manifest["sources"][0]["root_ref"])
        self.assertFalse(manifest["retention_safe"])
        self.assertNotIn("root", retained["sources"][0])
        self.assertIn("path_ref_v1:", retained["sources"][0]["root_ref"])
        self.assertTrue(retained["retention_safe"])

    def test_export_retained_writes_history_safe_subset(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fix failed verification.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            retained_output = Path(raw) / "history-retained"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            export_retained(output, raw)
            MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

            self.assertTrue((retained_output / "episodes.jsonl").exists())
            self.assertTrue((retained_output / "turn_flags.jsonl").exists())
            self.assertTrue((retained_output / "trend_report.json").exists())
            self.assertTrue((retained_output / "retained_manifest.json").exists())
            self.assertFalse((retained_output / "turn_summaries.jsonl").exists())
            self.assertFalse((retained_output / "shard_manifest.json").exists())
            self.assertFalse((retained_output / "shards.jsonl").exists())

    def test_validate_retained_rejects_unexpected_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            retained_output = Path(raw) / "history-retained"
            retained_output.mkdir()
            (retained_output / "debug.txt").write_text("/workspace/customer/raw-rollout.jsonl", encoding="utf-8")
            write_jsonl(retained_output / "episodes.jsonl", [])
            write_jsonl(retained_output / "turn_flags.jsonl", [])
            (retained_output / "trend_report.json").write_text("{}\n", encoding="utf-8")
            (retained_output / "retained_manifest.json").write_text(
                json.dumps(
                    {
                        "retention_safe": True,
                        "sources": [
                            {
                                "host": "local",
                                "root_ref": "path_ref_v1:0123456789abcdef",
                                "rollout_count": 1,
                                "summary_count": 0,
                                "status": "ready",
                            }
                        ],
                        "coverage_gaps": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(SystemExit, "unexpected retained output"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

    def test_export_retained_rejects_dirty_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            retained_output = Path(raw) / "history-retained"
            retained_output.mkdir()
            (retained_output / "debug.txt").write_text("raw debug", encoding="utf-8")

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )

            with self.assertRaisesRegex(SystemExit, "unexpected retained output"):
                MODULE.main(["export-retained", "--run-dir", str(output), "--output", str(retained_output)])

    def test_export_retained_rejects_symlink_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            real_output = Path(raw) / "real-retained"
            real_output.mkdir()
            retained_output = Path(raw) / "history-retained"
            retained_output.symlink_to(real_output, target_is_directory=True)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )

            with self.assertRaisesRegex(SystemExit, "symlinked retained output directory"):
                MODULE.main(["export-retained", "--run-dir", str(output), "--output", str(retained_output)])
            with self.assertRaisesRegex(SystemExit, "symlinked retained output directory"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])
            self.assertEqual(list(real_output.iterdir()), [])

    def test_validate_retained_rejects_extra_jsonl_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fix failed verification.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained_output = export_retained(output, raw)
            rows = [json.loads(line) for line in (retained_output / "turn_flags.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["raw_prompt"] = "proprietary snippet"
            write_jsonl(retained_output / "turn_flags.jsonl", rows)

            with self.assertRaisesRegex(SystemExit, "unexpected keys"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

    def test_validate_retained_rejects_malformed_jsonl_types(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fix failed verification.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            malformed_episode = export_retained(output, raw, "bad-episode")
            episodes = [json.loads(line) for line in (malformed_episode / "episodes.jsonl").read_text(encoding="utf-8").splitlines()]
            episodes[0]["turn_count"] = "bad"
            write_jsonl(malformed_episode / "episodes.jsonl", episodes)

            with self.assertRaisesRegex(SystemExit, "turn_count"):
                MODULE.main(["validate-retained", "--run-dir", str(malformed_episode)])

            malformed_turn = export_retained(output, raw, "bad-turn")
            rows = [json.loads(line) for line in (malformed_turn / "turn_flags.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["issue_flags"] = "failed_command"
            write_jsonl(malformed_turn / "turn_flags.jsonl", rows)

            with self.assertRaisesRegex(SystemExit, "issue_flags"):
                MODULE.main(["validate-retained", "--run-dir", str(malformed_turn)])

    def test_validate_retained_rejects_path_like_allowed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained_output = export_retained(output, raw)
            rows = [json.loads(line) for line in (retained_output / "episodes.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["topic"] = "src/private.py"
            write_jsonl(retained_output / "episodes.jsonl", rows)

            with self.assertRaisesRegex(SystemExit, "path-like"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

    def test_validate_retained_rejects_symlink_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained_output = export_retained(output, raw)
            symlink_target = Path(raw) / "episodes-copy.jsonl"
            symlink_target.write_text((retained_output / "episodes.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
            (retained_output / "episodes.jsonl").unlink()
            (retained_output / "episodes.jsonl").symlink_to(symlink_target)

            with self.assertRaisesRegex(SystemExit, "unexpected retained output"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

    def test_advance_state_rejects_retained_export_from_different_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            first = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-first.jsonl"
            second = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T11-00-00-second.jsonl"
            write_jsonl(first, [message("user", "First task.", "2026-05-01T10:00:00Z")])
            output_one = safe_output_dir(raw, "out-one")
            output_two = safe_output_dir(raw, "out-two")
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output_one), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            first.unlink()
            write_jsonl(second, [message("user", "Second task.", "2026-05-01T11:00:00Z")])
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output_two), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained_two = export_retained(output_two, raw, "history-retained-two")

            with self.assertRaisesRegex(SystemExit, "does not match"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output_one),
                        "--retained-run-dir",
                        str(retained_two),
                        "--state",
                        str(state),
                        *history_commit_args(raw, retained_two),
                    ]
                )

    def test_advance_state_rejects_unknown_history_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw)

            with self.assertRaisesRegex(SystemExit, "must exist"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        "0" * 40,
                    ]
                )

    def test_validate_history_commit_accepts_dedicated_retained_export_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-08T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, commit = write_history_repo(raw, retained)

            MODULE.main(
                [
                    "validate-history-commit",
                    "--retained-run-dir",
                    str(retained),
                    "--history-repo",
                    str(history_repo),
                    "--history-commit",
                    commit,
                ]
            )

    def test_validate_history_commit_accepts_retained_export_merge_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-08T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo = Path(raw) / "history-merge"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            (history_repo / "README.md").write_text("# History\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Initial history"], cwd=history_repo, check=True)
            default_branch = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=history_repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(["git", "checkout", "-q", "-b", "retained-export"], cwd=history_repo, check=True)
            target = history_repo / "retained" / "daily"
            target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            subprocess.run(["git", "checkout", "-q", default_branch], cwd=history_repo, check=True)
            subprocess.run(["git", "merge", "--no-ff", "-m", "Merge retained export", "retained-export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            MODULE.main(
                [
                    "validate-history-commit",
                    "--retained-run-dir",
                    str(retained),
                    "--history-repo",
                    str(history_repo),
                    "--history-commit",
                    commit,
                ]
            )

    def test_validate_history_tree_accepts_clean_follow_on_report_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-08T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            report = history_repo / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("# Weekly retrospective\n\nNo raw transcript excerpts retained.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/weekly/2026/05/08.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add redacted report"], cwd=history_repo, check=True)

            MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_follow_on_transient_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-08T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            raw_artifact = history_repo / "reports" / "weekly" / "turn_summaries.jsonl"
            raw_artifact.parent.mkdir(parents=True, exist_ok=True)
            raw_artifact.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/weekly/turn_summaries.jsonl"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add bad follow-on artifact"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_unredacted_report_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "daily" / "2026" / "05" / "01.md"
            report.parent.mkdir(parents=True)
            report.write_text("Debug log from /Users/hoteng/customer/project\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/daily/2026/05/01.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add bad report"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "unredacted sensitive text"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_raw_follow_on_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            raw_log = history_repo / "raw" / "tool-output.log"
            raw_log.parent.mkdir(parents=True)
            raw_log.write_text("raw output\n", encoding="utf-8")
            subprocess.run(["git", "add", "raw/tool-output.log"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add raw artifact"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_requires_retention_safe_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-08T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            manifest_path = history_repo / "retained" / "daily" / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["retention_safe"] = False
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "retained/daily/retained_manifest.json"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Break retained manifest"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "retention_safe"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_incomplete_retained_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-08T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            subprocess.run(["git", "rm", "-q", "retained/daily/turn_flags.jsonl"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Remove retained file"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "incomplete"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_advance_state_validates_final_history_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, retained_commit = write_history_repo(raw, retained)
            raw_log = history_repo / "raw" / "tool-output.log"
            raw_log.parent.mkdir(parents=True)
            raw_log.write_text("raw output\n", encoding="utf-8")
            subprocess.run(["git", "add", "raw/tool-output.log"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add raw follow-on"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        retained_commit,
                    ]
                )

    def test_advance_state_rejects_history_commit_without_retained_export(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, commit = write_history_repo(raw)

            with self.assertRaisesRegex(SystemExit, "does not contain|forbidden transient/raw artifact"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        commit,
                    ]
                )

    def test_advance_state_rejects_history_commit_with_extra_retained_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            extra = history_repo / "retained" / "daily" / "raw-copy.jsonl"
            extra.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "retained/daily/raw-copy.jsonl"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add extra retained file"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "does not contain|forbidden transient/raw artifact"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        commit,
                    ]
                )

    def test_advance_state_rejects_history_commit_with_existing_nested_retained_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo = Path(raw) / "history-with-nested-retained"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            nested = history_repo / "retained" / "daily" / "raw" / "debug.txt"
            nested.parent.mkdir(parents=True)
            nested.write_text("debug artifact\n", encoding="utf-8")
            subprocess.run(["git", "add", "retained/daily/raw/debug.txt"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add nested retained artifact"], cwd=history_repo, check=True)
            retained_target = history_repo / "retained" / "daily"
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (retained_target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", *[f"retained/daily/{name}" for name in MODULE.RETAINED_OUTPUT_FILES]], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "does not contain|forbidden transient/raw artifact"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        commit,
                    ]
                )

    def test_advance_state_rejects_history_commit_with_transient_file_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            transient = history_repo / "raw" / "turn_summaries.jsonl"
            transient.parent.mkdir(parents=True)
            transient.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "raw/turn_summaries.jsonl"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add transient artifact"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        commit,
                    ]
                )

    def test_advance_state_rejects_history_commit_with_raw_evidence_file_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            raw_evidence = history_repo / "raw" / "history.jsonl"
            raw_evidence.parent.mkdir(parents=True)
            raw_evidence.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "raw/history.jsonl"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add raw evidence"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        commit,
                    ]
                )

    def test_advance_state_rejects_history_commit_with_existing_codex_tmp_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo = Path(raw) / "history-with-tmp"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            tmp_artifact = history_repo / ".codex-tmp" / "raw-tool-output.txt"
            tmp_artifact.parent.mkdir(parents=True)
            tmp_artifact.write_text("raw output\n", encoding="utf-8")
            subprocess.run(["git", "add", ".codex-tmp/raw-tool-output.txt"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add bad artifact"], cwd=history_repo, check=True)
            retained_target = history_repo / "retained" / "daily"
            retained_target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (retained_target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        commit,
                    ]
                )

    def test_advance_state_rejects_backward_last_scan_at(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Daily task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-03T00:00:00Z"}), encoding="utf-8")

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)

            with self.assertRaisesRegex(SystemExit, "backwards"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        *history_commit_args(raw, retained),
                    ]
                )

            state_data = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(state_data["last_scan_at"], "2026-05-03T00:00:00Z")

    def test_advance_state_rejects_invalid_previous_last_scan_at(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Daily task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "not-a-date"}), encoding="utf-8")

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)

            with self.assertRaisesRegex(SystemExit, "state last_scan_at"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        *history_commit_args(raw, retained),
                    ]
                )

            state_data = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(state_data["last_scan_at"], "not-a-date")

    def test_advance_state_rejects_run_that_does_not_cover_previous_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw, timestamp="2026-05-15T10:00:00Z")
            for source_arg in remote_sources:
                host, path = source_arg.split("=", 1)
                write_remote_metadata(
                    Path(path),
                    host,
                    window_start="2026-05-15T00:00:00Z",
                    window_end="2026-05-16T00:00:00Z",
                    materialized_at="2026-05-16T00:00:00Z",
                )
            rollout = root / "sessions" / "2026" / "05" / "15" / "rollout-2026-05-15T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Late daily task.", "2026-05-15T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-10T00:00:00Z"}), encoding="utf-8")

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-15T00:00:00Z"),
                end=MODULE.parse_time("2026-05-16T00:00:00Z"),
            )
            retained = export_retained(output, raw)

            with self.assertRaisesRegex(SystemExit, "does not cover previous state"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        *history_commit_args(raw, retained),
                    ]
                )

            state_data = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(state_data["last_scan_at"], "2026-05-10T00:00:00Z")

    def test_advance_state_rejects_non_daily_runs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Weekly task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)

            with self.assertRaisesRegex(SystemExit, "only supports daily"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        *history_commit_args(raw, retained),
                    ]
                )

            self.assertFalse(state.exists())

    def test_advance_state_rejects_partial_host_scope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Partial task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

            with self.assertRaisesRegex(SystemExit, "coverage gaps"):
                MODULE.main(
                    [
                        "advance-state",
                        "--run-dir",
                        str(output),
                        "--retained-run-dir",
                        str(retained),
                        "--state",
                        str(state),
                        *history_commit_args(raw, retained),
                    ]
                )

        self.assertIn("partial_host_scope", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertFalse(state.exists())

    def test_discover_writes_manifest_without_turn_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.main(
                [
                    "discover",
                    "--mode",
                    "daily",
                    "--start",
                    "2026-05-01T00:00:00Z",
                    "--end",
                    "2026-05-02T00:00:00Z",
                    "--source",
                    f"local={root}",
                    "--allow-partial-hosts",
                    "--output",
                    str(output),
                ]
            )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(manifest["sources"][0]["rollout_count"], 1)
            self.assertFalse((output / "turn_summaries.jsonl").exists())
            self.assertTrue((output / "retained_manifest.json").exists())

    def test_discover_requires_bounded_start_for_retained_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = safe_output_dir(raw)

            with self.assertRaisesRegex(SystemExit, "--start is required"):
                MODULE.cmd_discover(
                    types.SimpleNamespace(
                        mode="daily",
                        start=None,
                        end="2026-05-02T00:00:00Z",
                        source=None,
                        output=str(output),
                        max_raw_bytes=1000,
                        allow_partial_hosts=True,
                    )
                )

    def test_retained_manifest_converts_coverage_gap_paths(self) -> None:
        transient = {
            "schema_version": 1,
            "mode": "daily",
            "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "sources": [{"host": "local", "root": "/secret/.codex", "status": "ready"}],
            "coverage_gaps": [{"host": "local", "path": "/secret/.codex/rollout.jsonl", "reason": "oversized"}],
            "retention_safe": False,
        }

        retained = MODULE.retained_manifest_from_transient(transient)

        self.assertTrue(retained["retention_safe"])
        self.assertNotIn("root", retained["sources"][0])
        self.assertIn("path_ref_v1:", retained["sources"][0]["root_ref"])
        self.assertNotIn("path", retained["coverage_gaps"][0])
        self.assertNotIn("path_ref", retained["coverage_gaps"][0])

    def test_missing_source_reports_gap_and_does_not_update_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = Path(raw) / "missing"
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={missing}"], output=str(output), state=str(state), max_raw_bytes=100, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "source_root_missing")
        self.assertNotIn(str(missing), json.dumps(trend))

    def test_missing_local_index_files_report_gaps_and_block_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual([gap["reason"] for gap in trend["coverage_gaps"][:2]], ["session_index_missing", "history_missing"])
        self.assertIn("partial_host_scope", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_missing_gap_blocks_state_update(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            missing = Path(raw) / "remote"
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(
                MODULE,
                "parse_sources",
                return_value=[
                    MODULE.Source("local", root),
                    MODULE.Source("miku-bot-dev", missing, "remote_source_not_materialized"),
                ],
            ):
                MODULE.run_scan(
                    types.SimpleNamespace(source=None, output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["host"], "miku-bot-dev")
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "remote_source_not_materialized")
        self.assertIn("path_ref_v1:", trend["coverage_gaps"][0]["root_ref"])

    def test_default_remote_without_fresh_metadata_blocks_state_update(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            remote = Path(raw) / "miku-bot-dev"
            write_local_evidence(local)
            local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            remote_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(local_rollout, [message("user", "Local task.", "2026-05-01T10:00:00Z")])
            write_jsonl(remote_rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(
                MODULE,
                "parse_sources",
                return_value=[
                    MODULE.Source("local", local),
                    MODULE.Source("miku-bot-dev", remote),
                ],
            ):
                MODULE.run_scan(
                    types.SimpleNamespace(source=None, output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["host"], "miku-bot-dev")
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "stale_host")
        self.assertEqual(trend["hosts"], {"local": 1})
        self.assertEqual([row["host"] for row in rows], ["local"])
        remote_source = next(source for source in manifest["sources"] if source["host"] == "miku-bot-dev")
        self.assertEqual(remote_source["status"], "stale")
        self.assertEqual(remote_source["rollout_count"], 0)

    def test_discover_skips_default_remote_with_stale_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            remote = Path(raw) / "miku-bot-dev"
            write_local_evidence(local)
            local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            remote_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(local_rollout, [message("user", "Local task.", "2026-05-01T10:00:00Z")])
            write_jsonl(remote_rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            with mock.patch.object(
                MODULE,
                "parse_sources",
                return_value=[
                    MODULE.Source("local", local),
                    MODULE.Source("miku-bot-dev", remote),
                ],
            ):
                MODULE.run_discover(
                    types.SimpleNamespace(source=None, output=str(output), allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))

        remote_source = next(source for source in manifest["sources"] if source["host"] == "miku-bot-dev")
        self.assertEqual(remote_source["status"], "stale")
        self.assertEqual(remote_source["rollout_count"], 0)
        self.assertEqual(manifest["coverage_gaps"][0]["reason"], "stale_host")

    def test_default_remote_non_ready_metadata_uses_status_as_gap_reason(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            metadata_path = remote / MODULE.REMOTE_SOURCE_METADATA_FILE
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["status"] = "auth_gated"
            metadata.pop("reason", None)
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

            gaps = MODULE.remote_evidence_gaps(
                MODULE.Source("miku-bot-dev", remote),
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )

        self.assertEqual(gaps[0]["reason"], "auth_gated")

    def test_default_remote_non_ready_metadata_preserves_common_gap_reasons(self) -> None:
        for reason in ("missing_codex", "codex_missing", "unreachable", "host_unreachable"):
            with self.subTest(reason=reason):
                with tempfile.TemporaryDirectory() as raw:
                    remote = Path(raw) / "miku-bot-dev"
                    write_remote_metadata(remote, "miku-bot-dev")
                    metadata_path = remote / MODULE.REMOTE_SOURCE_METADATA_FILE
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    metadata["status"] = reason
                    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

                    gaps = MODULE.remote_evidence_gaps(
                        MODULE.Source("miku-bot-dev", remote),
                        start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                        end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                    )

                self.assertEqual(gaps[0]["reason"], reason)

    def test_default_remote_metadata_end_matches_at_second_precision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")

            gaps = MODULE.remote_evidence_gaps(
                MODULE.Source("miku-bot-dev", remote),
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00.500000Z"),
            )

        self.assertEqual(gaps, [])

    def test_explicit_default_remote_requires_metadata_even_when_partial_hosts_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            remote_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(remote_rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["host"], "miku-bot-dev")
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "stale_host")

    def test_default_remote_metadata_must_cover_window_tail(self) -> None:
        for metadata_overrides in (
            {"window_end": "2026-05-01T22:30:00Z", "materialized_at": "2026-05-02T00:00:00Z"},
            {"window_end": "2026-05-03T00:00:00Z", "materialized_at": "2026-05-03T00:00:00Z"},
            {"window_end": "2026-05-02T00:00:00Z", "materialized_at": "2026-05-01T22:30:00Z"},
        ):
            with self.subTest(metadata_overrides=metadata_overrides):
                with tempfile.TemporaryDirectory() as raw:
                    local = Path(raw) / ".codex"
                    remote = Path(raw) / "miku-bot-dev"
                    write_local_evidence(local)
                    write_remote_metadata(remote, "miku-bot-dev", **metadata_overrides)
                    local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
                    remote_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
                    write_jsonl(local_rollout, [message("user", "Local task.", "2026-05-01T10:00:00Z")])
                    write_jsonl(remote_rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
                    output = safe_output_dir(raw)
                    state = safe_output_dir(raw) / "state.json"

                    with mock.patch.object(
                        MODULE,
                        "parse_sources",
                        return_value=[
                            MODULE.Source("local", local),
                            MODULE.Source("miku-bot-dev", remote),
                        ],
                    ):
                        MODULE.run_scan(
                            types.SimpleNamespace(source=None, output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                            mode="daily",
                            start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                            end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                        )
                    trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

                self.assertFalse(state.exists())
                self.assertEqual(trend["coverage_gaps"][0]["host"], "miku-bot-dev")
                self.assertEqual(trend["coverage_gaps"][0]["reason"], "stale_host")

    def test_default_remote_with_fresh_metadata_can_advance_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            remote = Path(raw) / "miku-bot-dev"
            write_local_evidence(local)
            write_remote_metadata(remote, "miku-bot-dev")
            local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            remote_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(local_rollout, [message("user", "Local task.", "2026-05-01T10:00:00Z")])
            write_jsonl(remote_rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(
                MODULE,
                "parse_sources",
                return_value=[
                    MODULE.Source("local", local),
                    MODULE.Source("miku-bot-dev", remote),
                ],
            ):
                MODULE.run_scan(
                    types.SimpleNamespace(source=None, output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            advance_state(output, state, raw)
            state_exists = state.exists()

        self.assertEqual(trend["coverage_gaps"], [])
        self.assertTrue(state_exists)

    def test_default_remote_with_fresh_metadata_and_no_activity_is_not_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            remote = Path(raw) / "miku-bot-dev"
            write_local_evidence(local)
            write_remote_metadata(remote, "miku-bot-dev")
            local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            write_jsonl(local_rollout, [message("user", "Local task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(
                MODULE,
                "parse_sources",
                return_value=[
                    MODULE.Source("local", local),
                    MODULE.Source("miku-bot-dev", remote),
                ],
            ):
                MODULE.run_scan(
                    types.SimpleNamespace(source=None, output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
                discover_output = safe_output_dir(raw, "discover")
                MODULE.run_discover(
                    types.SimpleNamespace(source=None, output=str(discover_output), allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((discover_output / "shard_manifest.json").read_text(encoding="utf-8"))
            advance_state(output, state, raw)
            state_exists = state.exists()

        self.assertEqual(trend["coverage_gaps"], [])
        remote_source = next(source for source in manifest["sources"] if source["host"] == "miku-bot-dev")
        self.assertEqual(remote_source["status"], "empty")
        self.assertEqual(manifest["coverage_gaps"], [])
        self.assertTrue(state_exists)

    def test_invalid_rollout_jsonl_reports_gap_and_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("{bad json\n", encoding="utf-8")
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "invalid_jsonl")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_non_object_rollout_jsonl_reports_gap_and_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-array.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("[]\n", encoding="utf-8")
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "invalid_jsonl")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_invalid_rollout_jsonl_on_start_date_after_start_time_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T18-00-00-abc.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("{bad json\n", encoding="utf-8")
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T10:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "invalid_jsonl")

    def test_old_invalid_rollout_with_active_mtime_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("{bad json\n", encoding="utf-8")
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "invalid_jsonl")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_old_invalid_rollout_with_future_mtime_does_not_block_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("{bad json\n", encoding="utf-8")
            future_mtime = MODULE.parse_time("2026-05-03T12:00:00Z").timestamp()
            os.utime(rollout, (future_mtime, future_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["coverage_gaps"], [])

    def test_window_external_invalid_rollout_does_not_block_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            old_bad = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            old_bad.parent.mkdir(parents=True, exist_ok=True)
            old_bad.write_text("{bad json\n", encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-01-01T10:00:00Z").timestamp()
            os.utime(old_bad, (old_mtime, old_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

            self.assertFalse(state.exists())
            advance_state(output, state, raw)

            self.assertTrue(state.exists())
            self.assertEqual(trend["coverage_gaps"], [])

    def test_validate_output_rejects_invalid_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            (run_dir / "turn_summaries.jsonl").write_text("{bad json\n", encoding="utf-8")
            write_jsonl(run_dir / "episodes.jsonl", [])
            write_jsonl(run_dir / "turn_flags.jsonl", [])
            (run_dir / "trend_report.json").write_text("{}\n", encoding="utf-8")
            (run_dir / "retained_manifest.json").write_text('{"retention_safe": true}\n', encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "invalid JSON"):
                MODULE.main(["validate-output", "--run-dir", str(run_dir)])

    def test_validate_output_rejects_symlink_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            symlink_target = Path(raw) / "turn-copy.jsonl"
            symlink_target.write_text((output / "turn_summaries.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
            (output / "turn_summaries.jsonl").unlink()
            (output / "turn_summaries.jsonl").symlink_to(symlink_target)

            with self.assertRaisesRegex(SystemExit, "unexpected output file"):
                MODULE.main(["validate-output", "--run-dir", str(output)])

    def test_validate_output_rejects_raw_retained_manifest_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            (run_dir / "turn_summaries.jsonl").write_text("", encoding="utf-8")
            (run_dir / "episodes.jsonl").write_text("", encoding="utf-8")
            (run_dir / "turn_flags.jsonl").write_text("", encoding="utf-8")
            (run_dir / "trend_report.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "window": {"mode": "daily", "start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                        "turn_count": 0,
                        "flagged_turn_count": 0,
                        "episode_count": 0,
                        "flags": {},
                        "hosts": {},
                        "model_eras": {},
                        "coverage_gaps": [],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "retained_manifest.json").write_text(
                json.dumps(
                    manifest_fixture(
                        sources=[
                            {
                                "host": "local",
                                "root": "/secret/.codex",
                                "root_ref": "path_ref_v1:0123456789abcdef",
                                "rollout_count": 1,
                                "summary_count": 0,
                                "status": "ready",
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(SystemExit, "raw root/path fields"):
                MODULE.main(["validate-output", "--run-dir", str(run_dir)])

    def test_validate_output_rejects_unexpected_trend_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            (run_dir / "turn_summaries.jsonl").write_text("", encoding="utf-8")
            (run_dir / "episodes.jsonl").write_text("", encoding="utf-8")
            (run_dir / "turn_flags.jsonl").write_text("", encoding="utf-8")
            trend = {
                "schema_version": 1,
                "window": {"mode": "daily", "start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                "turn_count": 0,
                "flagged_turn_count": 0,
                "episode_count": 0,
                "flags": {},
                "hosts": {},
                "model_eras": {},
                "coverage_gaps": [],
                "raw_path": "/Users/example/.codex",
            }
            (run_dir / "trend_report.json").write_text(json.dumps(trend), encoding="utf-8")
            (run_dir / "retained_manifest.json").write_text(json.dumps(manifest_fixture()), encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "unexpected keys"):
                MODULE.main(["validate-output", "--run-dir", str(run_dir)])

    def test_validate_manifest_rejects_non_opaque_refs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            retained = Path(raw) / "retained_manifest.json"
            retained.write_text(
                json.dumps(
                    manifest_fixture(
                        sources=[
                            {
                                "host": "local",
                                "root_ref": "path_hash:0123456789abcdef",
                                "rollout_count": 1,
                                "summary_count": 0,
                                "status": "ready",
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(SystemExit, "opaque path_ref_v1"):
                MODULE.main(["validate-manifest", "--manifest", str(retained)])

    def test_validate_manifest_requires_bounded_source_counts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            retained = Path(raw) / "retained_manifest.json"
            retained.write_text(
                json.dumps(
                    manifest_fixture(
                        sources=[
                            {
                                "host": "local",
                                "root_ref": "path_ref_v1:0123456789abcdef",
                                "rollout_count": 1,
                                "status": "ready",
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(SystemExit, "summary_count"):
                MODULE.main(["validate-manifest", "--manifest", str(retained)])

    def test_validate_output_rejects_unredacted_sensitive_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            row = {
                "turn_id": "t1",
                "episode_id": "e1",
                "host": "local",
                "session_id": "a" * 20,
                "source_path": "path_ref_v1:0123456789abcdef",
                "source_hash": "0" * 64,
                "timestamp": "2026-05-22T10:00:00Z",
                "cwd": None,
                "model": None,
                "model_era": "unknown",
                "redacted_user_prompt_summary": "category=debug; redacted_excerpt=/workspace/customer/Foo.java",
                "assistant_action_summary": "",
                "issue_flags": ["failed_command"],
                "prompt_improvement": None,
            }
            write_jsonl(run_dir / "turn_summaries.jsonl", [row])
            write_jsonl(run_dir / "turn_flags.jsonl", [row])
            write_jsonl(run_dir / "episodes.jsonl", [])
            (run_dir / "trend_report.json").write_text("{}\n", encoding="utf-8")
            (run_dir / "retained_manifest.json").write_text(
                json.dumps(
                    {
                        "retention_safe": True,
                        "sources": [
                            {
                                "host": "local",
                                "root_ref": "path_ref_v1:0123456789abcdef",
                                "rollout_count": 1,
                                "summary_count": 0,
                                "status": "ready",
                            }
                        ],
                        "coverage_gaps": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(SystemExit, "unredacted sensitive text"):
                MODULE.main(["validate-output", "--run-dir", str(run_dir)])

    def test_retained_validators_reject_raw_session_id(self) -> None:
        turn = {
            "turn_id": "a" * 20,
            "episode_id": "b" * 20,
            "host": "local",
            "session_id": "customer-incident-123",
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": "0" * 64,
            "timestamp": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model": None,
            "model_era": "unknown",
            "redacted_user_prompt_summary": "category=debug",
            "assistant_action_summary": "",
            "issue_flags": ["failed_command"],
            "prompt_improvement": None,
        }
        episode = {
            "episode_id": "b" * 20,
            "host": "local",
            "session_id": "customer-incident-123",
            "start": "2026-05-22T10:00:00Z",
            "end": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model_era": "unknown",
            "topic": "category=debug",
            "turn_count": 1,
            "friction_flags": ["failed_command"],
            "outcome": "needs_review",
            "work_report_hint": None,
        }

        with self.assertRaisesRegex(SystemExit, "opaque keyed digest"):
            MODULE.validate_turn_flag_row(turn, label="turn")
        with self.assertRaisesRegex(SystemExit, "opaque keyed digest"):
            MODULE.validate_episode_row(episode, label="episode")

    def test_retained_validators_reject_raw_turn_and_episode_ids(self) -> None:
        turn = {
            "turn_id": "customer-turn-123",
            "episode_id": "b" * 20,
            "host": "local",
            "session_id": "c" * 20,
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": "0" * 64,
            "timestamp": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model": None,
            "model_era": "unknown",
            "redacted_user_prompt_summary": "category=debug",
            "assistant_action_summary": "",
            "issue_flags": ["failed_command"],
            "prompt_improvement": None,
        }
        episode = {
            "episode_id": "customer-episode-123",
            "host": "local",
            "session_id": "c" * 20,
            "start": "2026-05-22T10:00:00Z",
            "end": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model_era": "unknown",
            "topic": "category=debug",
            "turn_count": 1,
            "friction_flags": ["failed_command"],
            "outcome": "needs_review",
            "work_report_hint": None,
        }

        with self.assertRaisesRegex(SystemExit, "turn.turn_id: expected opaque keyed digest"):
            MODULE.validate_turn_flag_row(turn, label="turn")
        with self.assertRaisesRegex(SystemExit, "episode.episode_id: expected opaque keyed digest"):
            MODULE.validate_episode_row(episode, label="episode")

    def test_rollout_summary_file_contributes_flags_without_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=customer-incident-123 cwd=/secret/repo"},
                    {"kind": "function_call_output", "timestamp": "2026-05-22T10:01:00Z", "text": "permission denied in /customer/code.py"},
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=100, allow_partial_hosts=True),
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
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=100, allow_partial_hosts=True),
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

    def test_old_invalid_summary_outside_window_does_not_block_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("{bad json\n", encoding="utf-8")
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            state_exists_after_scan = state.exists()
            advance_state(output, state, raw)
            state_exists_after_advance = state.exists()

        self.assertFalse(state_exists_after_scan)
        self.assertTrue(state_exists_after_advance)
        self.assertEqual(trend["coverage_gaps"], [])

    def test_old_summary_without_timestamp_outside_window_is_not_current_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            write_jsonl(summary, [{"kind": "summary", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=100, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

    def test_chinese_privacy_marker_contributes_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "请检查客户数据和凭据泄露风险。", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=10000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertIn("safety_privacy_flag", rows[0]["issue_flags"])

    def test_long_prompt_truncation_does_not_create_privacy_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            long_prompt = "Please summarize this ordinary planning note. " + ("alpha beta " * 160)
            write_jsonl(rollout, [message("user", long_prompt, "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=10000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertNotIn("safety_privacy_flag", rows[0]["issue_flags"])
        self.assertNotIn("redactions=applied", rows[0]["redacted_user_prompt_summary"])

    def test_unsafe_model_id_is_bucketed_for_retained_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            row = message("user", "Permission denied while running helper.", "2026-05-01T10:00:00Z")
            row["payload"]["model"] = "openai/gpt-6 preview"
            write_jsonl(rollout, [row])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            MODULE.main(["validate-output", "--run-dir", str(output)])
            retained = export_retained(output, raw)
            turns = [
                json.loads(line)
                for line in (retained / "turn_flags.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            episodes = [
                json.loads(line)
                for line in (retained / "episodes.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(turns[0]["model"], None)
        self.assertEqual(turns[0]["model_era"], "other-model")
        self.assertEqual(episodes[0]["model_era"], "other-model")

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
