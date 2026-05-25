from __future__ import annotations

import datetime as dt
import importlib.util
import hashlib
import io
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
REMOTE_PROBE_SCRIPT = SCRIPT.parent / "remote_codex_probe.py"
SPEC = importlib.util.spec_from_file_location("session_retrospective", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
REMOTE_PROBE_SPEC = importlib.util.spec_from_file_location("remote_codex_probe", REMOTE_PROBE_SCRIPT)
REMOTE_PROBE = importlib.util.module_from_spec(REMOTE_PROBE_SPEC)
assert REMOTE_PROBE_SPEC is not None
assert REMOTE_PROBE_SPEC.loader is not None
sys.modules[REMOTE_PROBE_SPEC.name] = REMOTE_PROBE
REMOTE_PROBE_SPEC.loader.exec_module(REMOTE_PROBE)

VALID_TURN_ID = f"{MODULE.TURN_REF_PREFIX}:{'a' * 20}"
VALID_EPISODE_ID = f"{MODULE.EPISODE_REF_PREFIX}:{'b' * 20}"
VALID_SESSION_ID = f"{MODULE.SESSION_REF_PREFIX}:{'c' * 20}"
VALID_SOURCE_HASH = f"{MODULE.SOURCE_HASH_PREFIX}:{'d' * 20}"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def complete_rollout_summary_scan_meta(**overrides: object) -> dict:
    row = {
        "kind": "scan_meta",
        "json_error_count": 0,
        "keyword_filter_applied": False,
        "line": 0,
        "matched_record_limit_reached": False,
        "record_limit_reached": False,
        "scan_bytes": 2097152,
        "scan_truncated": False,
        "signal_record_limit_reached": False,
        "source_bytes": 1200,
        "summary_record_count": 1,
        "summary_limit": 40,
        "tail_record_limit_reached": False,
        "tail_records": 8,
        "timestamp": "",
        "text": (
            "scan_truncated=false keyword_filter_applied=false record_limit_reached=false "
            "signal_record_limit_reached=false matched_record_limit_reached=false "
            "tail_record_limit_reached=false scan_bytes=2097152 json_error_count=0 summary_limit=40 "
            "tail_records=8 summary_record_count=1 source_bytes=1200"
        ),
    }
    row.update(overrides)
    return row


def blocked_path_open(target: Path):
    real_open = Path.open

    def open_or_raise(self: Path, *args, **kwargs):
        if self == target:
            raise PermissionError("blocked test path")
        return real_open(self, *args, **kwargs)

    return mock.patch.object(Path, "open", open_or_raise)


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


def add_expected_history_origin(repo: Path) -> None:
    subprocess.run(
        ["git", "remote", "add", "origin", f"git@github.com:{MODULE.EXPECTED_HISTORY_REPO}.git"],
        cwd=repo,
        check=True,
    )


def write_history_repo(root: str | Path, retained_dir: Path | None = None) -> tuple[Path, str]:
    repo = Path(root) / "history-repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=repo, check=True)
    add_expected_history_origin(repo)
    if retained_dir is None:
        (repo / "README.md").write_text("Session retrospective history fixture.\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    else:
        target = repo / retained_parent_for_dir(retained_dir)
        target.mkdir(parents=True, exist_ok=True)
        for name in MODULE.RETAINED_OUTPUT_FILES:
            (target / name).write_bytes((retained_dir / name).read_bytes())
        subprocess.run(["git", "add", "retained"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=repo, check=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    return repo, commit


def retained_parent_for_dir(retained_dir: Path) -> str:
    manifest = json.loads((retained_dir / "retained_manifest.json").read_text(encoding="utf-8"))
    return MODULE.retained_export_parent_for_mode(manifest["mode"])


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
        current_without_suffix = Path("rollout-2026-05-07T13-24-44.jsonl")
        legacy = Path("rollout-2025-05-26-legacy-uuid.jsonl")

        self.assertEqual(MODULE.session_id_from_path(current), MODULE.opaque_session_id("019d-uuid"))
        self.assertEqual(MODULE.session_id_from_path(legacy), MODULE.opaque_session_id("legacy-uuid"))
        self.assertRegex(MODULE.session_id_from_path(current), r"^session_ref_v1:[0-9a-f]{20}$")
        self.assertNotEqual(MODULE.session_id_from_path(current), "019d-uuid")
        self.assertNotEqual(MODULE.session_id_from_path(legacy), "legacy-uuid")
        self.assertEqual(MODULE.iso(MODULE.rollout_date_from_path(current)), "2026-05-07T13:24:44Z")
        self.assertEqual(MODULE.iso(MODULE.rollout_date_from_path(current_without_suffix)), "2026-05-07T13:24:44Z")
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
        self.assertFalse(
            MODULE.meaningful_user_text(
                "Run inside the dedicated worktree provisioned for this automation.\n"
                "Check approval/auth, secrets, customer data, and verification gaps."
            )
        )
        self.assertTrue(
            MODULE.meaningful_user_text(
                "The retrospective failed after writing to .codex-local/session-retrospective/runs/latest."
            )
        )

    def test_meaningful_prompt_text_keeps_normal_review_request(self) -> None:
        prompt = "Review the code changes against the base branch and report only actionable findings."

        self.assertEqual(MODULE.meaningful_prompt_text(prompt), prompt)
        self.assertTrue(MODULE.meaningful_user_text(prompt))

    def test_default_sources_include_remote_hosts_as_missing_until_materialized(self) -> None:
        sources = MODULE.parse_sources(None)

        self.assertEqual([source.host for source in sources], ["local", "miku-bot-dev", "hoteng-srv-01"])
        self.assertIsNone(sources[0].missing_reason)
        self.assertEqual(sources[1].missing_reason, "remote_source_not_materialized")
        self.assertEqual(sources[2].missing_reason, "remote_source_not_materialized")

    def test_remote_probe_helper_is_bundled_with_skill(self) -> None:
        helper = SCRIPT.parent / "remote_codex_probe.py"
        skill = SCRIPT.parents[1] / "SKILL.md"

        self.assertTrue(helper.is_file())
        self.assertIn("scripts/remote_codex_probe.py", skill.read_text(encoding="utf-8"))

    def test_remote_probe_fetch_rejects_symlink_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            outside = Path(raw) / "outside-secret.txt"
            outside.write_text("SECRET\n", encoding="utf-8")
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-link.jsonl"
            rollout.parent.mkdir(parents=True)
            rollout.symlink_to(outside)

            with self.assertRaisesRegex(ValueError, "symlink"):
                REMOTE_PROBE._fetch_local_rollout(
                    root,
                    REMOTE_PROBE.pathlib.PurePosixPath(
                        "sessions/2026/05/01/rollout-2026-05-01T10-00-00-link.jsonl"
                    ),
                )

    def test_remote_probe_fetch_rejects_symlink_rollout_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            target_dir = root / "other-date"
            rollout_name = "rollout-2026-05-01T10-00-00-link.jsonl"
            write_jsonl(target_dir / rollout_name, [message("user", "Wrong window.", "2026-05-01T10:00:00Z")])
            link_dir = root / "sessions" / "2026" / "05" / "01"
            link_dir.parent.mkdir(parents=True)
            link_dir.symlink_to(target_dir, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symlink"):
                REMOTE_PROBE._fetch_local_rollout(
                    root,
                    REMOTE_PROBE.pathlib.PurePosixPath(f"sessions/2026/05/01/{rollout_name}"),
                )

    def test_remote_probe_fetch_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            real_root = Path(raw) / "real-codex"
            rollout = real_root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(rollout, [message("user", "Hidden task.", "2026-05-01T10:00:00Z")])
            link_root = Path(raw) / ".codex"
            link_root.symlink_to(real_root, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "Codex root is a symlink"):
                REMOTE_PROBE._fetch_local_rollout(
                    link_root,
                    REMOTE_PROBE.pathlib.PurePosixPath(
                        "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl"
                    ),
                )

    def test_remote_probe_session_meta_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            real_root = Path(raw) / "real-codex"
            rollout = real_root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "hidden-session", "cwd": "/secret/repo"},
                    }
                ],
            )
            link_root = Path(raw) / ".codex"
            link_root.symlink_to(real_root, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "Codex root is a symlink"):
                REMOTE_PROBE._iter_session_meta_records(
                    codex_root=link_root,
                    dates=[dt.date(2026, 5, 1)],
                    limit=10,
                    host="local",
                )

    def test_remote_probe_summary_rejects_symlink_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            outside = Path(raw) / "outside-rollout.jsonl"
            write_jsonl(outside, [message("user", "Leaked task.", "2026-05-01T10:00:00Z")])
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-link.jsonl"
            rollout.parent.mkdir(parents=True)
            rollout.symlink_to(outside)

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root):
                result = REMOTE_PROBE.cmd_rollout_summary(
                    types.SimpleNamespace(
                        host="local",
                        rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00-link.jsonl",
                        keyword=[],
                        limit=40,
                        tail_records=8,
                        max_text_chars=400,
                    )
                )

            self.assertEqual(result, 1)

    def test_remote_probe_rollout_summary_reports_unreadable_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(rollout, [message("user", "Unreadable task.", "2026-05-01T10:00:00Z")])
            stderr = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE, "_open_local_rollout_text", side_effect=PermissionError("blocked")
            ), mock.patch.object(sys, "stderr", stderr):
                result = REMOTE_PROBE.cmd_rollout_summary(
                    types.SimpleNamespace(
                        host="local",
                        rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                        keyword=[],
                        limit=40,
                        tail_records=8,
                        max_text_chars=400,
                    )
                )

        self.assertEqual(result, 1)
        self.assertIn("error=rollout unreadable", stderr.getvalue())

    def test_remote_probe_rollout_summary_rejects_unbounded_text_limit(self) -> None:
        result = REMOTE_PROBE.cmd_rollout_summary(
            types.SimpleNamespace(
                host="local",
                rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                keyword=[],
                limit=40,
                tail_records=8,
                max_text_chars=10_000,
            )
        )

        self.assertEqual(result, 2)

    def test_remote_probe_session_meta_rejects_symlink_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            outside = Path(raw) / "outside-rollout.jsonl"
            write_jsonl(
                outside,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "leaked-session", "cwd": "/secret/repo"},
                    }
                ],
            )
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-link.jsonl"
            rollout.parent.mkdir(parents=True)
            rollout.symlink_to(outside)

            with self.assertRaisesRegex(ValueError, "symlink"):
                REMOTE_PROBE._iter_session_meta_records(
                    codex_root=root,
                    dates=[dt.date(2026, 5, 1)],
                    limit=10,
                    host="local",
                )

    def test_remote_probe_session_meta_missing_codex_root_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=Path(raw) / "missing-codex",
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
            )

        self.assertEqual(rows, [])

    def test_remote_probe_session_meta_reports_unreadable_local_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "blocked-session", "cwd": "/secret/repo"},
                    }
                ],
            )
            stderr = io.StringIO()
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE, "_open_local_rollout_text", side_effect=PermissionError("blocked path")
            ), mock.patch.object(sys, "stderr", stderr), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_session_meta(
                    types.SimpleNamespace(host=["local"], date=["2026/05/01"], from_date=None, to_date=None, limit=10)
                )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("host=local", stderr.getvalue())
        self.assertIn("rollout=sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl", stderr.getvalue())
        self.assertIn("error=rollout unreadable", stderr.getvalue())
        self.assertNotIn("blocked path", stderr.getvalue())

    def test_remote_probe_session_meta_reports_unreadable_local_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            date_dir = root / "sessions" / "2026" / "05" / "01"
            date_dir.mkdir(parents=True)
            resolved_date_dir = date_dir.resolve()
            real_glob = Path.glob

            def glob_or_raise(self: Path, pattern: str):
                if self == resolved_date_dir:
                    raise PermissionError("blocked /home/hoteng/.codex/sessions/2026/05/01")
                return real_glob(self, pattern)

            stderr = io.StringIO()
            stdout = io.StringIO()
            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                Path, "glob", glob_or_raise
            ), mock.patch.object(sys, "stderr", stderr), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_session_meta(
                    types.SimpleNamespace(host=["local"], date=["2026/05/01"], from_date=None, to_date=None, limit=10)
                )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("host=local", stderr.getvalue())
        self.assertIn("error=session directory unreadable", stderr.getvalue())
        self.assertNotIn("/home/hoteng/.codex", stderr.getvalue())
        self.assertNotIn("blocked", stderr.getvalue())

    def test_remote_probe_session_meta_reports_unreadable_remote_rollout_without_remote_path(self) -> None:
        marker = json.dumps(
            {
                "kind": "error",
                "error": "rollout unreadable",
                "rollout": "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
            }
        )
        remote_output = f"{REMOTE_PROBE.REMOTE_SESSION_META_BEGIN}\n{marker}\n{REMOTE_PROBE.REMOTE_SESSION_META_END}\n"
        stderr = io.StringIO()
        stdout = io.StringIO()

        with mock.patch.object(
            REMOTE_PROBE,
            "_run_remote_python",
            return_value=subprocess.CompletedProcess(
                args=["ssh"],
                returncode=0,
                stdout=remote_output,
                stderr="Traceback: /home/hoteng/.codex/private-rollout.jsonl",
            ),
        ), mock.patch.object(sys, "stderr", stderr), mock.patch.object(sys, "stdout", stdout):
            result = REMOTE_PROBE.cmd_session_meta(
                types.SimpleNamespace(host=["miku-bot-dev"], date=["2026/05/01"], from_date=None, to_date=None, limit=10)
            )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("host=miku-bot-dev", stderr.getvalue())
        self.assertIn("rollout=sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl", stderr.getvalue())
        self.assertIn("error=rollout unreadable", stderr.getvalue())
        self.assertNotIn("/home/hoteng/.codex", stderr.getvalue())

    def test_remote_probe_session_meta_hides_unframed_remote_failure_stderr(self) -> None:
        stderr = io.StringIO()
        stdout = io.StringIO()

        with mock.patch.object(
            REMOTE_PROBE,
            "_run_remote_python",
            return_value=subprocess.CompletedProcess(
                args=["ssh"],
                returncode=1,
                stdout="",
                stderr="Traceback: /home/hoteng/.codex/sessions/2026/05/01",
            ),
        ), mock.patch.object(sys, "stderr", stderr), mock.patch.object(sys, "stdout", stdout):
            result = REMOTE_PROBE.cmd_session_meta(
                types.SimpleNamespace(host=["miku-bot-dev"], date=["2026/05/01"], from_date=None, to_date=None, limit=10)
            )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("host=miku-bot-dev", stderr.getvalue())
        self.assertIn("error=remote session-meta failed", stderr.getvalue())
        self.assertNotIn("/home/hoteng/.codex", stderr.getvalue())

    def test_remote_probe_session_meta_rejects_symlink_date_dir(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            target_dir = root / "other-date"
            write_jsonl(
                target_dir / "rollout-2026-05-01T10-00-00-link.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "wrong-session", "cwd": "/secret/repo"},
                    }
                ],
            )
            link_dir = root / "sessions" / "2026" / "05" / "01"
            link_dir.parent.mkdir(parents=True)
            link_dir.symlink_to(target_dir, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symlink"):
                REMOTE_PROBE._iter_session_meta_records(
                    codex_root=root,
                    dates=[dt.date(2026, 5, 1)],
                    limit=10,
                    host="local",
                )

    def test_remote_probe_supports_dated_archived_rollout_paths(self) -> None:
        path = REMOTE_PROBE._resolve_rollout_relative_path(
            "archived_sessions/2026/05/01/rollout-2026-05-01T10-00-00-archived.jsonl"
        )

        self.assertEqual(
            path.as_posix(),
            "archived_sessions/2026/05/01/rollout-2026-05-01T10-00-00-archived.jsonl",
        )

    def test_remote_probe_supports_root_rollout_paths(self) -> None:
        path = REMOTE_PROBE._resolve_rollout_relative_path("rollout-2026-05-01T10-00-00-root.jsonl")

        self.assertEqual(path.as_posix(), "rollout-2026-05-01T10-00-00-root.jsonl")

    def test_remote_probe_session_meta_includes_root_rollouts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_jsonl(
                root / "rollout-2026-05-01T10-00-00-root.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "root-session", "cwd": "/redacted/repo"},
                    }
                ],
            )

            rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["session_id"], "root-session")
        self.assertEqual(rows[0]["rollout"], "rollout-2026-05-01T10-00-00-root.jsonl")

    def test_remote_probe_session_meta_includes_dated_archived_rollouts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            archived = root / "archived_sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-archived.jsonl"
            write_jsonl(
                archived,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "archived-session", "cwd": "/redacted/repo"},
                    }
                ],
            )

            rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
            )

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["session_id"], "archived-session")
            self.assertEqual(
                rows[0]["rollout"],
                "archived_sessions/2026/05/01/rollout-2026-05-01T10-00-00-archived.jsonl",
            )

    def test_remote_probe_session_meta_includes_flat_archived_rollouts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            archived = root / "archived_sessions" / "rollout-2026-05-01T10-00-00-flat.jsonl"
            write_jsonl(
                archived,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "flat-archived-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                root / "archived_sessions" / "rollout-2026-05-02T10-00-00-flat.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-02T10:00:00Z",
                        "payload": {"id": "other-date-session", "cwd": "/redacted/repo"},
                    }
                ],
            )

            rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
            )

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["session_id"], "flat-archived-session")
        self.assertEqual(
            rows[0]["rollout"],
            "archived_sessions/rollout-2026-05-01T10-00-00-flat.jsonl",
        )

    def test_remote_probe_session_meta_filters_by_rollout_filename_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            for hour in (10, 11):
                rollout = root / "sessions" / "2026" / "05" / "01" / f"rollout-2026-05-01T{hour:02d}-00-00.jsonl"
                write_jsonl(
                    rollout,
                    [
                        {
                            "type": "session_meta",
                            "timestamp": f"2026-05-01T{hour:02d}:00:00Z",
                            "payload": {"id": f"session-{hour}", "cwd": "/redacted/repo"},
                        }
                    ],
                )

            rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
                rollout_start=dt.datetime(2026, 5, 1, 11, 0, 0, tzinfo=dt.timezone.utc),
                rollout_end=dt.datetime(2026, 5, 1, 12, 0, 0, tzinfo=dt.timezone.utc),
            )

        self.assertEqual([row["session_id"] for row in rows], ["session-11"])

    def test_remote_probe_session_meta_treats_date_only_rollout_name_as_day_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01-date-only.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:00:00Z",
                        "payload": {"id": "session-date-only", "cwd": "/redacted/repo"},
                    }
                ],
            )

            midday_rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
                rollout_start=dt.datetime(2026, 5, 1, 12, 0, 0, tzinfo=dt.timezone.utc),
                rollout_end=dt.datetime(2026, 5, 1, 13, 0, 0, tzinfo=dt.timezone.utc),
            )
            next_day_rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
                rollout_start=dt.datetime(2026, 5, 2, 0, 0, 0, tzinfo=dt.timezone.utc),
                rollout_end=dt.datetime(2026, 5, 2, 1, 0, 0, tzinfo=dt.timezone.utc),
            )

        self.assertEqual([row["session_id"] for row in midday_rows], ["session-date-only"])
        self.assertEqual(next_day_rows, [])

    def test_remote_probe_session_meta_classifies_date_only_rollout_name_as_unknown_for_split(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01-date-only.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:00:00Z",
                        "payload": {"id": "session-date-only", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T12-00-00-known.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:00:00Z",
                        "payload": {"id": "session-known", "cwd": "/redacted/repo"},
                    }
                ],
            )

            unknown_rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
                rollout_filename_mode="unknown",
            )
            known_rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
                rollout_filename_mode="known",
            )

        self.assertEqual([row["session_id"] for row in unknown_rows], ["session-date-only"])
        self.assertEqual([row["session_id"] for row in known_rows], ["session-known"])

    def test_remote_probe_session_meta_treats_bad_filename_timestamp_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "session-known", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T99-00-00-bad.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T11:00:00Z",
                        "payload": {"id": "session-bad-name", "cwd": "/redacted/repo"},
                    }
                ],
            )

            unknown_rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
                rollout_filename_mode="unknown",
            )
            known_rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
                rollout_filename_mode="known",
            )

        self.assertEqual([row["session_id"] for row in unknown_rows], ["session-bad-name"])
        self.assertEqual([row["session_id"] for row in known_rows], ["session-known"])

    def test_remote_probe_session_meta_ignores_rollout_summary_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            raw_rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-raw.jsonl"
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-2026-05-01.jsonl"
            write_jsonl(
                raw_rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "shared-session", "cwd": "/raw/repo"},
                    }
                ],
            )
            write_jsonl(
                summary,
                [
                    {
                        "kind": "session_meta",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "session_id": "shared-session",
                        "cwd": "/summary/repo",
                    }
                ],
            )

            rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=10,
                host="local",
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cwd"], "/raw/repo")
        self.assertEqual(
            rows[0]["rollout"],
            "sessions/2026/05/01/rollout-2026-05-01T10-00-00-raw.jsonl",
        )

    def test_remote_probe_session_meta_deduplicates_archived_rollout_names_before_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            dated_duplicate = root / "archived_sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T12-00-00-dup.jsonl"
            flat_duplicate = root / "archived_sessions" / "rollout-2026-05-01T12-00-00-dup.jsonl"
            flat_unique = root / "archived_sessions" / "rollout-2026-05-01T11-00-00-unique.jsonl"
            write_jsonl(
                dated_duplicate,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:00:00Z",
                        "payload": {"id": "duplicate-dated-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                flat_duplicate,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:00:00Z",
                        "payload": {"id": "duplicate-flat-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                flat_unique,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T11:00:00Z",
                        "payload": {"id": "unique-session", "cwd": "/redacted/repo"},
                    }
                ],
            )

            rows = REMOTE_PROBE._iter_session_meta_records(
                codex_root=root,
                dates=[dt.date(2026, 5, 1)],
                limit=2,
                host="local",
            )

        self.assertEqual([row["session_id"] for row in rows], ["duplicate-dated-session", "unique-session"])

    def test_remote_probe_session_meta_rejects_local_limit_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            for index in range(3):
                rollout = root / "sessions" / "2026" / "05" / "01" / f"rollout-2026-05-01T10-0{index}-00-{index}.jsonl"
                write_jsonl(
                    rollout,
                    [
                        {
                            "type": "session_meta",
                            "timestamp": f"2026-05-01T10:0{index}:00Z",
                            "payload": {"id": f"session-{index}", "cwd": "/redacted/repo"},
                        }
                    ],
                )
            stderr = io.StringIO()
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                sys, "stderr", stderr
            ), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_session_meta(
                    types.SimpleNamespace(host=["local"], date=["2026/05/01"], from_date=None, to_date=None, limit=2)
                )

        self.assertEqual(result, 1)
        self.assertIn("session-meta result exceeded --limit=2", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_remote_probe_session_meta_auto_split_merges_over_limit_day(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            for hour in range(3):
                rollout = root / "sessions" / "2026" / "05" / "01" / f"rollout-2026-05-01T{hour:02d}-00-00-{hour}.jsonl"
                write_jsonl(
                    rollout,
                    [
                        {
                            "type": "session_meta",
                            "timestamp": f"2026-05-01T{hour:02d}:00:00Z",
                            "payload": {"id": f"session-{hour}", "cwd": "/redacted/repo"},
                        }
                    ],
                )
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-undated.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:00:00Z",
                        "payload": {"id": "session-undated", "cwd": "/redacted/repo"},
                    }
                ],
            )
            stderr = io.StringIO()
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                sys, "stderr", stderr
            ), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_session_meta(
                    types.SimpleNamespace(
                        host=["local"],
                        date=["2026/05/01"],
                        from_date=None,
                        to_date=None,
                        limit=1,
                        rollout_start=None,
                        rollout_end=None,
                        auto_split=True,
                    )
                )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        rows = stdout.getvalue().strip().splitlines()
        self.assertEqual(rows[0], "host\tdate\tsession_id\tcwd\trollout")
        self.assertEqual(
            {row.split("\t")[2] for row in rows[1:]},
            {"session-0", "session-1", "session-2", "session-undated"},
        )

    def test_remote_probe_session_meta_auto_split_scans_unknown_names_per_date(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            for day in (1, 2):
                rollout = root / "sessions" / "2026" / "05" / f"{day:02d}" / f"rollout-undated-{day}.jsonl"
                write_jsonl(
                    rollout,
                    [
                        {
                            "type": "session_meta",
                            "timestamp": f"2026-05-{day:02d}T10:00:00Z",
                            "payload": {"id": f"session-{day}", "cwd": "/redacted/repo"},
                        }
                    ],
                )
            stderr = io.StringIO()
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                sys, "stderr", stderr
            ), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_session_meta(
                    types.SimpleNamespace(
                        host=["local"],
                        date=["2026/05/01", "2026/05/02"],
                        from_date=None,
                        to_date=None,
                        limit=1,
                        rollout_start=None,
                        rollout_end=None,
                        auto_split=True,
                    )
                )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        rows = stdout.getvalue().strip().splitlines()
        self.assertEqual(rows[0], "host\tdate\tsession_id\tcwd\trollout")
        self.assertEqual({row.split("\t")[2] for row in rows[1:]}, {"session-1", "session-2"})

    def test_remote_probe_session_meta_auto_split_only_splits_truncated_dates(self) -> None:
        calls = []

        def fake_scan_host_session_meta(
            alias: str,
            *,
            dates: list[dt.date],
            limit: int,
            rollout_start: dt.datetime | None,
            rollout_end: dt.datetime | None,
            rollout_filename_mode: str = "all",
        ) -> REMOTE_PROBE.SessionMetaScan:
            date_value = dates[0]
            calls.append((date_value, rollout_filename_mode, rollout_start, rollout_end))
            if rollout_filename_mode == "all" and date_value == dt.date(2026, 5, 1):
                return REMOTE_PROBE.SessionMetaScan(
                    rows=[
                        {
                            "host": alias,
                            "date": "2026/05/01",
                            "session_id": "session-1",
                            "cwd": "/redacted/repo",
                            "rollout": "sessions/2026/05/01/rollout-2026-05-01T10-00-00-1.jsonl",
                        }
                    ],
                    truncated=False,
                )
            if rollout_filename_mode == "all":
                return REMOTE_PROBE.SessionMetaScan(rows=[], truncated=True)
            if rollout_filename_mode == "unknown":
                return REMOTE_PROBE.SessionMetaScan(rows=[], truncated=False)
            return REMOTE_PROBE.SessionMetaScan(
                rows=[
                    {
                        "host": alias,
                        "date": "2026/05/02",
                        "session_id": "session-2",
                        "cwd": "/redacted/repo",
                        "rollout": "sessions/2026/05/02/rollout-2026-05-02T00-00-00-2.jsonl",
                    }
                ],
                truncated=False,
            )

        stderr = io.StringIO()
        stdout = io.StringIO()

        with mock.patch.object(REMOTE_PROBE, "_scan_host_session_meta", side_effect=fake_scan_host_session_meta), mock.patch.object(
            sys, "stderr", stderr
        ), mock.patch.object(sys, "stdout", stdout):
            result = REMOTE_PROBE.cmd_session_meta(
                types.SimpleNamespace(
                    host=["local"],
                    date=["2026/05/01", "2026/05/02"],
                    from_date=None,
                    to_date=None,
                    limit=1,
                    rollout_start=None,
                    rollout_end=None,
                    auto_split=True,
                )
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(any(call[0] == dt.date(2026, 5, 2) and call[1] == "known" for call in calls))
        self.assertFalse(any(call[0] == dt.date(2026, 5, 1) and call[1] == "known" for call in calls))
        self.assertEqual({row.split("\t")[2] for row in stdout.getvalue().strip().splitlines()[1:]}, {"session-1", "session-2"})

    def test_remote_probe_session_meta_auto_split_keeps_latest_rollout_for_duplicate_session(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            for hour in (1, 2):
                rollout = root / "sessions" / "2026" / "05" / "01" / f"rollout-2026-05-01T{hour:02d}-00-00-same.jsonl"
                write_jsonl(
                    rollout,
                    [
                        {
                            "type": "session_meta",
                            "timestamp": f"2026-05-01T{hour:02d}:00:00Z",
                            "payload": {"id": "session-same", "cwd": "/redacted/repo"},
                        }
                    ],
                )
            stderr = io.StringIO()
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                sys, "stderr", stderr
            ), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_session_meta(
                    types.SimpleNamespace(
                        host=["local"],
                        date=["2026/05/01"],
                        from_date=None,
                        to_date=None,
                        limit=1,
                        rollout_start=None,
                        rollout_end=None,
                        auto_split=True,
                    )
                )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        rows = stdout.getvalue().strip().splitlines()
        self.assertEqual(rows[0], "host\tdate\tsession_id\tcwd\trollout")
        self.assertEqual(len(rows), 2)
        fields = rows[1].split("\t")
        self.assertEqual(fields[2], "session-same")
        self.assertEqual(fields[4], "sessions/2026/05/01/rollout-2026-05-01T02-00-00-same.jsonl")

    def test_remote_probe_session_meta_rejects_remote_limit_marker(self) -> None:
        row = json.dumps(
            {"date": "2026/05/01", "session_id": "session-1", "cwd": "/redacted/repo", "rollout": "sessions/2026/05/01/rollout-1.jsonl"}
        )
        marker = json.dumps({"kind": "truncation", "reason": REMOTE_PROBE.SESSION_META_LIMIT_TRUNCATED_REASON, "date": "2026/05/01", "limit": 1})
        remote_output = f"{REMOTE_PROBE.REMOTE_SESSION_META_BEGIN}\n{row}\n{marker}\n{REMOTE_PROBE.REMOTE_SESSION_META_END}\n"
        stderr = io.StringIO()
        stdout = io.StringIO()

        with mock.patch.object(
            REMOTE_PROBE,
            "_run_remote_python",
            return_value=subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout=remote_output, stderr=""),
        ), mock.patch.object(sys, "stderr", stderr), mock.patch.object(sys, "stdout", stdout):
            result = REMOTE_PROBE.cmd_session_meta(
                types.SimpleNamespace(host=["miku-bot-dev"], date=["2026/05/01"], from_date=None, to_date=None, limit=1)
            )

        self.assertEqual(result, 1)
        self.assertIn("host=miku-bot-dev", stderr.getvalue())
        self.assertIn("session-meta result exceeded --limit=1", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_remote_probe_session_meta_rejects_global_limit_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "local-session", "cwd": "/redacted/local"},
                    }
                ],
            )
            remote_row = json.dumps(
                {
                    "date": "2026/05/01",
                    "session_id": "remote-session",
                    "cwd": "/redacted/remote",
                    "rollout": "sessions/2026/05/01/rollout-remote.jsonl",
                }
            )
            remote_output = f"{REMOTE_PROBE.REMOTE_SESSION_META_BEGIN}\n{remote_row}\n{REMOTE_PROBE.REMOTE_SESSION_META_END}\n"
            stderr = io.StringIO()
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE,
                "_run_remote_python",
                return_value=subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout=remote_output, stderr=""),
            ), mock.patch.object(sys, "stderr", stderr), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_session_meta(
                    types.SimpleNamespace(
                        host=["local", "miku-bot-dev"],
                        date=["2026/05/01"],
                        from_date=None,
                        to_date=None,
                        limit=1,
                    )
                )

        self.assertEqual(result, 1)
        self.assertIn("host=all", stderr.getvalue())
        self.assertIn("session-meta result exceeded --limit=1", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_remote_probe_script_is_executable(self) -> None:
        self.assertTrue(os.access(REMOTE_PROBE_SCRIPT, os.X_OK))

    def test_remote_probe_preflight_uses_configured_remote_codex_root(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ssh"],
            returncode=0,
            stdout="hostname=remote\nuser=hoteng\nhome=/home/other\ncodex_root=/home/hoteng/.codex\ncodex=present\nrg=present\npython3=present\n",
            stderr="",
        )
        with mock.patch.object(REMOTE_PROBE, "_run_subprocess_text", return_value=completed) as run:
            row = REMOTE_PROBE._remote_preflight_row("miku-bot-dev")

        command = run.call_args.args[0]
        self.assertIn("CODEX_REMOTE_ROOT=/home/hoteng/.codex", command[-1])
        self.assertIn('[ -d "$codex_root" ]', command[-1])
        self.assertEqual(row["codex_root"], "/home/hoteng/.codex")
        self.assertEqual(row["codex"], "present")

    def test_remote_probe_fetch_rollout_writes_private_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "private-output-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            task_output_root = Path(raw) / "task-output"
            output = task_output_root / "rollout.jsonl"
            output.parent.mkdir(parents=True)
            output.write_text("old\n", encoding="utf-8")
            os.chmod(output, 0o644)

            def fake_task_output_root(workspace_root: Path | None = None) -> Path:
                return task_output_root.resolve()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE, "_task_output_root", fake_task_output_root
            ):
                result = REMOTE_PROBE.cmd_fetch_rollout(
                    types.SimpleNamespace(
                        host="local",
                        rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                        output="rollout.jsonl",
                    )
                )

            self.assertEqual(result, 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn("private-output-session", output.read_text(encoding="utf-8"))

    def test_remote_probe_fetch_rollout_accepts_root_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "rollout-2026-05-01T10-00-00-root.jsonl"
            write_jsonl(
                root / rollout_ref,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "root-rollout-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            task_output_root = Path(raw) / "task-output"
            output = task_output_root / "rollout.jsonl"

            def fake_task_output_root(workspace_root: Path | None = None) -> Path:
                return task_output_root.resolve()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE, "_task_output_root", fake_task_output_root
            ):
                result = REMOTE_PROBE.cmd_fetch_rollout(
                    types.SimpleNamespace(host="local", rollout=rollout_ref, output="rollout.jsonl")
                )

            self.assertEqual(result, 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn("root-rollout-session", output.read_text(encoding="utf-8"))

    def test_remote_probe_fetch_rollout_accepts_task_output_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "task-output-relative-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            workspace = Path(raw) / "workspace"
            task_output_root = workspace / REMOTE_PROBE.TASK_OUTPUT_RELATIVE_DIR
            output = task_output_root / "rollout.jsonl"
            workspace.mkdir(parents=True)

            def fake_task_output_root(workspace_root: Path | None = None) -> Path:
                return task_output_root.resolve()

            previous_cwd = Path.cwd()
            try:
                os.chdir(workspace)
                with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                    REMOTE_PROBE, "_task_output_root", fake_task_output_root
                ):
                    result = REMOTE_PROBE.cmd_fetch_rollout(
                        types.SimpleNamespace(
                            host="local",
                            rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                            output=(REMOTE_PROBE.TASK_OUTPUT_RELATIVE_DIR / "rollout.jsonl").as_posix(),
                        )
                    )
            finally:
                os.chdir(previous_cwd)

            nested = task_output_root / REMOTE_PROBE.TASK_OUTPUT_RELATIVE_DIR / "rollout.jsonl"
            self.assertEqual(result, 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn("task-output-relative-session", output.read_text(encoding="utf-8"))
            self.assertFalse(nested.exists())

    def test_remote_probe_fetch_rollout_reports_unreadable_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            task_output_root = Path(raw) / "task-output"
            task_output_root.mkdir(parents=True)
            stderr = io.StringIO()

            def fake_task_output_root(workspace_root: Path | None = None) -> Path:
                return task_output_root.resolve()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE, "_fetch_local_rollout", side_effect=PermissionError("blocked")
            ), mock.patch.object(REMOTE_PROBE, "_task_output_root", fake_task_output_root), mock.patch.object(
                sys, "stderr", stderr
            ):
                result = REMOTE_PROBE.cmd_fetch_rollout(
                    types.SimpleNamespace(
                        host="local",
                        rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                        output="rollout.jsonl",
                    )
                )

        self.assertEqual(result, 1)
        self.assertIn("error=rollout unreadable", stderr.getvalue())

    def test_remote_probe_fetch_rollout_rejects_symlink_output_parent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "symlink-parent-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            task_output_root = Path(raw) / "task-output"
            outside = Path(raw) / "outside"
            task_output_root.mkdir(parents=True)
            outside.mkdir()
            os.symlink(outside, task_output_root / "link")

            def fake_task_output_root(workspace_root: Path | None = None) -> Path:
                return task_output_root

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE, "_task_output_root", fake_task_output_root
            ):
                result = REMOTE_PROBE.cmd_fetch_rollout(
                    types.SimpleNamespace(
                        host="local",
                        rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                        output="link/rollout.jsonl",
                    )
                )

            self.assertNotEqual(result, 0)
            self.assertFalse((outside / "rollout.jsonl").exists())

    def test_remote_probe_fetch_rollout_rejects_symlink_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "symlink-output-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            task_output_root = Path(raw) / "task-output"
            outside = Path(raw) / "outside"
            task_output_root.mkdir(parents=True)
            outside.mkdir()
            os.symlink(outside / "rollout.jsonl", task_output_root / "rollout.jsonl")

            def fake_task_output_root(workspace_root: Path | None = None) -> Path:
                return task_output_root

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                REMOTE_PROBE, "_task_output_root", fake_task_output_root
            ):
                result = REMOTE_PROBE.cmd_fetch_rollout(
                    types.SimpleNamespace(
                        host="local",
                        rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                        output="rollout.jsonl",
                    )
                )

            self.assertNotEqual(result, 0)
            self.assertFalse((outside / "rollout.jsonl").exists())

    def test_remote_probe_rollout_summary_preserves_bounded_user_signal(self) -> None:
        records = REMOTE_PROBE._summarize_rollout_records(
            lines=[
                json.dumps(message("user", "You forgot the verification step and assumed success.", "2026-05-01T10:00:00Z")),
                json.dumps(message("assistant", "I will check it.", "2026-05-01T10:01:00Z")),
            ],
            keywords=[],
            limit=10,
            tail_records=0,
            max_text_chars=80,
        )

        self.assertEqual([record["kind"] for record in records], ["user_message", "assistant_message"])
        self.assertIn("you missed", records[0]["text"])
        self.assertIn("assumed", records[0]["text"])
        self.assertNotIn("verification step", records[0]["text"])

    def test_remote_probe_rollout_summary_preserves_real_user_before_wrapper(self) -> None:
        records = REMOTE_PROBE._summarize_rollout_records(
            lines=[
                json.dumps(message("user", "Review the deployment.", "2026-05-01T10:00:00Z")),
                json.dumps(
                    message(
                        "user",
                        "Persistent internal Codex readonly review contract:\nCheck approval, secrets, privacy, and verification.",
                        "2026-05-01T10:01:00Z",
                    )
                ),
            ],
            keywords=[],
            limit=10,
            tail_records=0,
            max_text_chars=80,
        )

        self.assertEqual([record["kind"] for record in records], ["user_message"])
        self.assertEqual(records[0]["text"], "user message present")

    def test_remote_probe_generated_rollout_summary_preserves_real_user_before_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the deployment.", "2026-05-01T10:00:00Z"),
                    message(
                        "user",
                        "Persistent internal Codex readonly review contract:\nCheck approval, secrets, privacy, and verification.",
                        "2026-05-01T10:01:00Z",
                    ),
                ],
            )
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "rollout-summary",
                    "codex_root": str(root),
                    "rollout": "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                    "summary_limit": 10,
                    "summary_scan_bytes": 4096,
                    "summary_tail_records": 0,
                    "summary_max_text_chars": 80,
                    "summary_keywords": [],
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [
            row
            for line in result.stdout.splitlines()
            if line.startswith("{")
            for row in [json.loads(line)]
            if "kind" in row
            if row["kind"] != "scan_meta"
        ]
        self.assertEqual([row["kind"] for row in rows], ["user_message"])
        self.assertEqual(rows[0]["text"], "user message present")
        self.assertEqual(rows[0]["rollout"], "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl")

    def test_remote_probe_generated_rollout_summary_accepts_root_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "rollout-2026-05-01T10-00-00-root.jsonl"
            write_jsonl(root / rollout_ref, [message("user", "Review the deployment.", "2026-05-01T10:00:00Z")])
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "rollout-summary",
                    "codex_root": str(root),
                    "rollout": rollout_ref,
                    "summary_limit": 10,
                    "summary_scan_bytes": 4096,
                    "summary_tail_records": 0,
                    "summary_max_text_chars": 80,
                    "summary_keywords": [],
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.startswith("{") and json.loads(line).get("kind")
        ]
        self.assertTrue(rows)
        self.assertTrue(all(row.get("rollout") == rollout_ref for row in rows))

    def test_remote_probe_local_rollout_summary_emits_backing_rollout_refs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(root / rollout_ref, [message("user", "Review the deployment.", "2026-05-01T10:00:00Z")])
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                sys, "stdout", stdout
            ):
                result = REMOTE_PROBE.cmd_rollout_summary(
                    types.SimpleNamespace(
                        host="local",
                        rollout=rollout_ref,
                        keyword=[],
                        limit=10,
                        tail_records=0,
                        max_text_chars=80,
                    )
                )

        self.assertEqual(result, 0)
        rows = [json.loads(line) for line in stdout.getvalue().splitlines() if line.startswith("{")]
        self.assertTrue(rows)
        self.assertTrue(all(row.get("rollout") == rollout_ref for row in rows))

    def test_remote_probe_root_rollout_summary_emits_backing_rollout_refs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "rollout-2026-05-01T10-00-00-root.jsonl"
            write_jsonl(root / rollout_ref, [message("user", "Review the deployment.", "2026-05-01T10:00:00Z")])
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(
                sys, "stdout", stdout
            ):
                result = REMOTE_PROBE.cmd_rollout_summary(
                    types.SimpleNamespace(
                        host="local",
                        rollout=rollout_ref,
                        keyword=[],
                        limit=10,
                        tail_records=0,
                        max_text_chars=80,
                    )
                )

        self.assertEqual(result, 0)
        rows = [json.loads(line) for line in stdout.getvalue().splitlines() if line.startswith("{")]
        self.assertTrue(rows)
        self.assertTrue(all(row.get("rollout") == rollout_ref for row in rows))

    def test_remote_probe_rollout_summary_reports_record_limit_metadata(self) -> None:
        records, meta = REMOTE_PROBE._summarize_rollout_records_with_meta(
            lines=[
                json.dumps(message("user", "You forgot verification.", "2026-05-01T10:00:00Z")),
                json.dumps(message("user", "You missed tests.", "2026-05-01T10:01:00Z")),
            ],
            keywords=["you"],
            limit=1,
            tail_records=0,
            max_text_chars=80,
        )

        self.assertGreaterEqual(len(records), 1)
        self.assertTrue(meta["record_limit_reached"])
        self.assertTrue(meta["signal_record_limit_reached"])
        self.assertTrue(meta["matched_record_limit_reached"])
        self.assertTrue(meta["keyword_filter_applied"])
        self.assertFalse(meta["tail_record_limit_reached"])

    def test_remote_probe_rollout_summary_reports_tail_limit_metadata(self) -> None:
        records, meta = REMOTE_PROBE._summarize_rollout_records_with_meta(
            lines=[
                json.dumps(message("assistant", "Ordinary update 1.", "2026-05-01T10:00:00Z")),
                json.dumps(message("assistant", "Ordinary update 2.", "2026-05-01T10:01:00Z")),
            ],
            keywords=[],
            limit=10,
            tail_records=1,
            max_text_chars=80,
        )

        self.assertEqual(len(records), 1)
        self.assertFalse(meta["record_limit_reached"])
        self.assertFalse(meta["keyword_filter_applied"])
        self.assertTrue(meta["tail_record_limit_reached"])
        self.assertEqual(meta["json_error_count"], 0)

    def test_remote_probe_rollout_summary_tail_flag_ignores_signal_records_already_emitted(self) -> None:
        records, meta = REMOTE_PROBE._summarize_rollout_records_with_meta(
            lines=[
                json.dumps(message("user", f"You forgot verification {index}.", f"2026-05-01T10:0{index}:00Z"))
                for index in range(9)
            ],
            keywords=[],
            limit=40,
            tail_records=8,
            max_text_chars=80,
        )

        self.assertEqual(len(records), 9)
        self.assertFalse(meta["record_limit_reached"])
        self.assertFalse(meta["tail_record_limit_reached"])

    def test_remote_probe_rollout_summary_reports_json_error_metadata(self) -> None:
        records, meta = REMOTE_PROBE._summarize_rollout_records_with_meta(
            lines=[
                json.dumps(message("user", "You forgot verification.", "2026-05-01T10:00:00Z")),
                "{not json",
                json.dumps(message("assistant", "Done.", "2026-05-01T10:01:00Z")),
            ],
            keywords=[],
            limit=10,
            tail_records=8,
            max_text_chars=80,
        )

        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(meta["json_error_count"], 1)
        self.assertFalse(meta["record_limit_reached"])

    def test_remote_probe_cmd_rollout_summary_emits_record_limit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "You forgot verification.", "2026-05-01T10:00:00Z"),
                    message("user", "You missed tests.", "2026-05-01T10:01:00Z"),
                ],
            )
            stdout = io.StringIO()

            with mock.patch.object(REMOTE_PROBE, "_local_codex_root", return_value=root), mock.patch.object(sys, "stdout", stdout):
                result = REMOTE_PROBE.cmd_rollout_summary(
                    types.SimpleNamespace(
                        host="local",
                        rollout="sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                        keyword=["you"],
                        limit=1,
                        tail_records=0,
                        max_text_chars=80,
                    )
                )

        self.assertEqual(result, 0)
        rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
        scan_meta = rows[0]
        self.assertEqual(scan_meta["kind"], "scan_meta")
        self.assertTrue(scan_meta["record_limit_reached"])
        self.assertTrue(scan_meta["signal_record_limit_reached"])
        self.assertTrue(scan_meta["matched_record_limit_reached"])
        self.assertTrue(scan_meta["keyword_filter_applied"])
        self.assertFalse(scan_meta["tail_record_limit_reached"])
        self.assertEqual(scan_meta["summary_limit"], 1)
        self.assertEqual(scan_meta["json_error_count"], 0)
        self.assertTrue(all(row["rollout"] == "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl" for row in rows))

    def test_remote_probe_generated_rollout_summary_emits_record_limit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "You forgot verification.", "2026-05-01T10:00:00Z"),
                    message("user", "You missed tests.", "2026-05-01T10:01:00Z"),
                ],
            )
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "rollout-summary",
                    "codex_root": str(root),
                    "rollout": "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                    "summary_limit": 1,
                    "summary_scan_bytes": 4096,
                    "summary_tail_records": 0,
                    "summary_max_text_chars": 80,
                    "summary_keywords": ["you"],
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        scan_meta = next(
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.startswith("{") and json.loads(line).get("kind") == "scan_meta"
        )
        self.assertTrue(scan_meta["record_limit_reached"])
        self.assertTrue(scan_meta["signal_record_limit_reached"])
        self.assertTrue(scan_meta["matched_record_limit_reached"])
        self.assertTrue(scan_meta["keyword_filter_applied"])
        self.assertFalse(scan_meta["tail_record_limit_reached"])
        self.assertEqual(scan_meta["summary_limit"], 1)
        self.assertEqual(scan_meta["json_error_count"], 0)

    def test_remote_probe_generated_rollout_summary_tail_flag_ignores_signal_records_already_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", f"You forgot verification {index}.", f"2026-05-01T10:0{index}:00Z")
                    for index in range(9)
                ],
            )
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "rollout-summary",
                    "codex_root": str(root),
                    "rollout": "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                    "summary_limit": 40,
                    "summary_scan_bytes": 4096,
                    "summary_tail_records": 8,
                    "summary_max_text_chars": 80,
                    "summary_keywords": [],
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        scan_meta = next(
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.startswith("{") and json.loads(line).get("kind") == "scan_meta"
        )
        self.assertFalse(scan_meta["record_limit_reached"])
        self.assertFalse(scan_meta["tail_record_limit_reached"])
        self.assertEqual(scan_meta["summary_record_count"], 9)

    def test_remote_probe_generated_rollout_summary_reports_json_error_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "You forgot verification.", "2026-05-01T10:00:00Z"))
                + "\n"
                + "{not json"
                + "\n",
                encoding="utf-8",
            )
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "rollout-summary",
                    "codex_root": str(root),
                    "rollout": "sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl",
                    "summary_limit": 10,
                    "summary_scan_bytes": 4096,
                    "summary_tail_records": 8,
                    "summary_max_text_chars": 80,
                    "summary_keywords": [],
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        scan_meta = next(
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.startswith("{") and json.loads(line).get("kind") == "scan_meta"
        )
        self.assertEqual(scan_meta["json_error_count"], 1)

    def test_remote_probe_rollout_summary_preserves_early_signal_outside_tail(self) -> None:
        lines = [json.dumps(message("user", "permission denied while fetching remote logs", "2026-05-01T10:00:00Z"))]
        for index in range(10):
            lines.append(json.dumps(message("assistant", f"Ordinary update {index}", "2026-05-01T10:01:00Z")))

        records = REMOTE_PROBE._summarize_rollout_records(
            lines=lines,
            keywords=[],
            limit=10,
            tail_records=2,
            max_text_chars=80,
        )

        self.assertIn("error:", records[0]["text"])
        self.assertIn("approval", records[0]["text"])
        self.assertNotIn("permission denied", json.dumps(records))

    def test_remote_probe_rollout_summary_preserves_event_user_message_signal(self) -> None:
        records = REMOTE_PROBE._summarize_rollout_records(
            lines=[
                json.dumps(
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"type": "user_message", "message": "You missed the context-loss follow-up."},
                    }
                )
            ],
            keywords=[],
            limit=10,
            tail_records=0,
            max_text_chars=80,
        )

        self.assertEqual([record["kind"] for record in records], ["user_message"])
        self.assertIn("you missed", records[0]["text"])
        self.assertNotIn("context-loss", records[0]["text"])

    def test_remote_probe_rollout_summary_uses_bounded_input_scan(self) -> None:
        first = json.dumps(message("user", "First bounded signal.", "2026-05-01T10:00:00Z")) + "\n"
        second = json.dumps(message("user", "You missed the late unbounded signal.", "2026-05-01T10:01:00Z")) + "\n"

        records = REMOTE_PROBE._summarize_rollout_records(
            lines=REMOTE_PROBE._bounded_text_lines(io.BytesIO((first + second).encode("utf-8")), len(first.encode("utf-8"))),
            keywords=["missed"],
            limit=10,
            tail_records=0,
            max_text_chars=80,
        )

        self.assertEqual([record["text"] for record in records], ["user message present"])

    def test_remote_probe_bounded_text_lines_counts_multibyte_bytes(self) -> None:
        first = json.dumps(message("user", "多字节任务 needle", "2026-05-01T10:00:00Z"), ensure_ascii=False) + "\n"
        second = json.dumps(message("user", "Second bounded signal.", "2026-05-01T10:01:00Z")) + "\n"
        payload = (first + second).encode("utf-8")

        self.assertEqual(list(REMOTE_PROBE._bounded_text_lines(io.BytesIO(payload), len(first))), [])
        self.assertEqual(
            list(REMOTE_PROBE._bounded_text_lines(io.BytesIO(payload), len(first.encode("utf-8")))),
            [first],
        )

    def test_remote_probe_rollout_summary_redacts_non_user_text(self) -> None:
        records = REMOTE_PROBE._summarize_rollout_records(
            lines=[
                json.dumps(message("assistant", "Use Bearer abc.def.ghi in /Users/hoteng/customer/repo", "2026-05-01T10:00:00Z")),
                json.dumps(
                    {
                        "type": "response_item",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "payload": {
                            "type": "function_call_output",
                            "output": "Traceback with token=secret123 in /customer/code.py",
                        },
                    }
                ),
            ],
            keywords=["Bearer", "token"],
            limit=10,
            tail_records=0,
            max_text_chars=80,
        )

        serialized = json.dumps(records)
        self.assertIn("secret", serialized)
        self.assertIn("error:", serialized)
        self.assertNotIn("Bearer", serialized)
        self.assertNotIn("secret123", serialized)
        self.assertNotIn("/customer", serialized)

    def test_remote_probe_rollout_summary_keeps_structured_session_id(self) -> None:
        raw_session = "session-raw-abc123456"
        records = REMOTE_PROBE._summarize_rollout_records(
            lines=[
                json.dumps(
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T09:59:00Z",
                        "payload": {"id": raw_session, "cwd": "/Users/hoteng/secret/repo"},
                    }
                ),
                json.dumps(
                    {
                        "type": "response_item",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"type": "function_call_output", "output": "permission denied"},
                    }
                ),
            ],
            keywords=["permission"],
            limit=10,
            tail_records=0,
            max_text_chars=80,
        )

        self.assertEqual(records[0]["kind"], "session_meta")
        self.assertEqual(records[0]["session_id"], raw_session)
        self.assertEqual(records[0]["text"], "session meta present")
        self.assertNotIn(raw_session, records[0]["text"])
        self.assertNotIn("/Users", json.dumps(records))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-structured-session.jsonl"
            write_jsonl(summary, records)

            turns = MODULE.extract_summary_file(MODULE.Source("remote", root), summary, None, None)

        self.assertEqual(turns[0].session_id, MODULE.opaque_session_id(raw_session))

    def test_remote_probe_session_meta_uses_bounded_input_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-large.jsonl"
            rollout.parent.mkdir(parents=True)
            first = json.dumps({"type": "response_item", "payload": {"type": "function_call_output", "output": "x" * 256}}) + "\n"
            rollout.write_text(
                first
                + json.dumps(
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "late-session", "cwd": "/redacted/repo"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with mock.patch.object(REMOTE_PROBE, "MAX_SESSION_META_SCAN_BYTES", len(first) - 1):
                rows = REMOTE_PROBE._iter_session_meta_records(
                    codex_root=root,
                    dates=[dt.date(2026, 5, 1)],
                    limit=10,
                    host="local",
                )

        self.assertEqual(rows, [])

    def test_explicit_sources_still_require_default_host_coverage(self) -> None:
        sources = MODULE.parse_sources(["local=/tmp/local", "miku-bot-dev=/tmp/miku"])

        self.assertEqual([source.host for source in sources], ["local", "miku-bot-dev", "hoteng-srv-01"])
        self.assertEqual(sources[2].missing_reason, "remote_source_not_materialized")
        self.assertEqual(
            [source.host for source in MODULE.parse_sources(["local=/tmp/local"], require_default_hosts=False)],
            ["local"],
        )

    def test_parse_sources_canonicalizes_default_remote_aliases(self) -> None:
        sources = MODULE.parse_sources(["miku-server-dev=/tmp/miku"])

        self.assertEqual([source.host for source in sources], ["local", "miku-bot-dev", "hoteng-srv-01"])
        self.assertTrue(sources[1].explicit)
        self.assertIsNone(sources[1].missing_reason)
        self.assertEqual(sources[2].missing_reason, "remote_source_not_materialized")

    def test_partial_host_default_sources_use_local_only(self) -> None:
        sources = MODULE.parse_sources(None, require_default_hosts=False)

        self.assertEqual([source.host for source in sources], ["local"])

    def test_parse_sources_deduplicates_repeated_host_path(self) -> None:
        sources = MODULE.parse_sources(["local=/tmp/local", "local=/tmp/local"], require_default_hosts=False)

        self.assertEqual(len(sources), 1)

    def test_parse_sources_rejects_multiple_default_roots_for_same_host(self) -> None:
        with self.assertRaisesRegex(SystemExit, "multiple roots for miku-bot-dev"):
            MODULE.parse_sources(
                ["miku-bot-dev=/tmp/miku-one", "miku-server-dev=/tmp/miku-two"],
                require_default_hosts=False,
            )

    def test_parse_sources_rejects_empty_path(self) -> None:
        with self.assertRaisesRegex(SystemExit, "PATH must be non-empty"):
            MODULE.parse_sources(["local="], require_default_hosts=False)
        with self.assertRaisesRegex(SystemExit, "PATH must be non-empty"):
            MODULE.parse_sources(["local=   "], require_default_hosts=False)

    def test_explicit_noncanonical_local_source_blocks_shared_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "local-copy"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            write_jsonl(rollout, [message("user", "Local copied task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(
                    source=[f"local={root}"],
                    output=str(output),
                    state=str(state),
                    max_raw_bytes=1000,
                    allow_partial_hosts=False,
                ),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertIn("partial_host_scope", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_parse_sources_buckets_custom_host_labels(self) -> None:
        sources = MODULE.parse_sources(["customer-acme=/tmp/acme"], require_default_hosts=False)

        self.assertEqual([source.host for source in sources], [MODULE.RETAINED_CUSTOM_SOURCE_HOST])

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

    def test_source_rollouts_does_not_duplicate_archived_sessions_during_root_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            archived = root / "archived_sessions" / "2026" / "04" / "01" / "rollout-2026-04-01T10-00-00-archived.jsonl"
            write_jsonl(archived, [message("user", "Archived task.", "2026-04-01T10:00:00Z")])

            paths = MODULE.source_rollouts(MODULE.Source("local", root))

        self.assertEqual(paths, [archived])

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

    def test_local_rollout_internal_hostname_is_redacted_and_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-internal.jsonl"
            write_jsonl(rollout, [message("user", "Investigate db01.internal routing.", "2026-05-22T10:01:00Z")])

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            serialized = json.dumps(MODULE.asdict_turn(turns[0]))

        self.assertEqual(len(turns), 1)
        self.assertIn("safety_privacy_flag", turns[0].issue_flags)
        self.assertIn("redactions=applied", turns[0].redacted_user_prompt_summary)
        self.assertNotIn("db01.internal", serialized)

    def test_local_rollout_bare_64_hex_is_redacted_and_flagged(self) -> None:
        token = "a" * 64
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-token.jsonl"
            write_jsonl(rollout, [message("user", "Investigate opaque token " + token, "2026-05-22T10:01:00Z")])

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            serialized = json.dumps(MODULE.asdict_turn(turns[0]))

        self.assertEqual(len(turns), 1)
        self.assertIn("safety_privacy_flag", turns[0].issue_flags)
        self.assertIn("redactions=applied", turns[0].redacted_user_prompt_summary)
        self.assertNotIn(token, serialized)
        self.assertIn("safety_privacy_flag", MODULE.flags_for_text(token))

    def test_flags_for_text_detects_collaboration_friction_categories(self) -> None:
        over_flags = MODULE.flags_for_text("Codex over-explored unrelated files and searched too broadly.")
        under_flags = MODULE.flags_for_text("Codex should have asked for clarification before proceeding.")

        self.assertIn("over_exploration", over_flags)
        self.assertIn("under_asking", under_flags)

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

    def test_opaque_ref_key_file_rejects_symlink_parent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            outside = Path(raw) / "outside-cache"
            outside.mkdir()
            symlink_parent = Path(raw) / ".codex-local"
            symlink_parent.symlink_to(outside, target_is_directory=True)
            key_file = symlink_parent / "session-retrospective" / "opaque_ref_key"

            with self.assertRaisesRegex(SystemExit, "opaque ref key file must not use symlink ancestors"):
                MODULE.create_or_read_opaque_ref_key(key_file)

        self.assertFalse((outside / "session-retrospective" / "opaque_ref_key").exists())

    def test_opaque_ref_key_file_rejects_group_readable_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            key_file = Path(raw) / ".codex-local" / "session-retrospective" / "opaque_ref_key"
            key_file.parent.mkdir(parents=True)
            key_file.write_text("a" * 64 + "\n", encoding="utf-8")
            os.chmod(key_file, 0o644)

            with self.assertRaisesRegex(SystemExit, "owner-only"):
                MODULE.create_or_read_opaque_ref_key(key_file)

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

    def test_extract_rollout_splits_same_topic_across_model_eras(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            first = message("user", "Permission denied while updating helper.", "2026-05-22T10:01:00Z")
            first["payload"]["model"] = "openai/gpt-5.5"
            second = message("user", "Permission denied while updating helper.", "2026-05-22T10:03:00Z")
            second["payload"]["model"] = "openai/gpt-5.4"
            write_jsonl(rollout, [first, second])

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)
            episodes = MODULE.episode_records(turns)
            trend = MODULE.trend_report(turns, episodes, {"mode": "daily"})

        self.assertEqual(len(turns), 2)
        self.assertNotEqual(turns[0].episode_id, turns[1].episode_id)
        self.assertEqual(len(episodes), 2)
        self.assertEqual(trend["model_eras"], {"gpt-5.4": 1, "gpt-5.5": 1})
        MODULE.validate_retained_export_consistency(episodes, [MODULE.asdict_turn(turn) for turn in turns], trend, label="test")

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

    def test_extract_rollout_reads_structured_event_msg_user_messages(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-structured.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:01:00Z",
                        "payload": {
                            "type": "user_message",
                            "message": {
                                "role": "user",
                                "content": [
                                    {
                                        "type": "input_text",
                                        "text": "You forgot the verification step and assumed success.",
                                    }
                                ],
                            },
                        },
                    }
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("user_correction", turns[0].issue_flags)
        self.assertIn("context_loss", turns[0].issue_flags)
        self.assertNotIn("role", turns[0].redacted_user_prompt_summary)

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

    def test_wrapper_only_user_message_preserves_initial_followup_output(self) -> None:
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
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("blocked_or_failed", turns[0].assistant_action_summary)
        self.assertIn("verification", turns[0].assistant_action_summary)

    def test_wrapper_only_user_message_keeps_prompt_flags_without_followup_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-wrapper.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Fix the failed deployment.", "2026-05-22T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "Ran the verification and it failed.", "2026-05-22T10:02:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("blocked_or_failed", turns[0].assistant_action_summary)
        self.assertIn("verification", turns[0].assistant_action_summary)

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
            same_key_hash = MODULE.file_source_hash(rollout)
            MODULE.PATH_REF_KEY = b"\x02" * 32
            different_key_hash = MODULE.file_source_hash(rollout)

        self.assertRegex(turns[0].source_hash, r"^source_hash_v1:[0-9a-f]{20}$")
        self.assertNotEqual(turns[0].source_hash, plain_hash)
        self.assertNotEqual(turns[0].source_hash, f"{MODULE.SOURCE_HASH_PREFIX}:{plain_hash[:20]}")
        self.assertEqual(turns[0].source_hash, same_key_hash)
        self.assertNotEqual(turns[0].source_hash, different_key_hash)

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

        self.assertRegex(turns[0].session_id, r"^session_ref_v1:[0-9a-f]{20}$")
        self.assertNotEqual(turns[0].session_id, "customer-incident-123")

    def test_late_summary_session_meta_backfills_prior_rows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "summary", "timestamp": "2026-05-22T10:01:00Z", "text": "permission denied"},
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:02:00Z", "text": "session_id=late-session cwd=/secret/repo"},
                    {"kind": "summary", "timestamp": "2026-05-22T10:03:00Z", "text": "failed command"},
                ],
            )

            turns = MODULE.extract_summary_file(MODULE.Source("remote", root), summary, None, None)

        expected_session = MODULE.opaque_session_id("late-session")
        self.assertEqual([turn.session_id for turn in turns], [expected_session, expected_session])
        self.assertEqual(len({turn.episode_id for turn in turns}), 1)

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

    def test_wrapper_after_tool_output_does_not_pollute_previous_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-22T10:01:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:02:00Z",
                        "payload": {"output": "Process exited with code 0"},
                    },
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                    message("user", "Now continue the real task.", "2026-05-22T10:05:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 2)
        self.assertEqual(turns[0].issue_flags, [])
        self.assertEqual(turns[1].issue_flags, [])

    def test_wrapper_after_lookback_assistant_does_not_emit_old_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-20T10:01:00Z"),
                    message("assistant", "Implemented the helper.", "2026-05-20T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    message("assistant", "Failed with permission denied.", "2026-05-22T10:04:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(turns, [])

    def test_wrapper_after_lookback_prompt_without_evidence_does_not_emit_old_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please implement the helper.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    message("assistant", "Failed with permission denied.", "2026-05-22T10:04:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(turns, [])

    def test_wrapper_after_lookback_prompt_preserves_tool_failure_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-active.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the long-running deployment.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    message("assistant", "Verification failed with permission denied.", "2026-05-22T10:04:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:05:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:05:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("blocked_or_failed", turns[0].assistant_action_summary)
        self.assertIn("verification", turns[0].assistant_action_summary)

    def test_wrapper_after_assistant_preamble_preserves_active_turn_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-preamble.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the long-running deployment.", "2026-05-20T10:01:00Z"),
                    message("assistant", "I'll implement the update and check the failed test.", "2026-05-20T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:05:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:05:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)

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

    def test_wrapper_before_task_complete_preserves_active_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please fix the deployment.", "2026-05-22T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {
                            "type": "task_complete",
                            "last_agent_message": "The command failed with exit code 1.",
                        },
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("blocked_or_failed", turns[0].assistant_action_summary)

    def test_wrapper_after_lookback_prompt_preserves_task_complete_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-lookback.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please fix the deployment.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {
                            "type": "task_complete",
                            "last_agent_message": "The command failed with exit code 1.",
                        },
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:04:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("blocked_or_failed", turns[0].assistant_action_summary)

    def test_wrapper_after_lookback_prompt_preserves_neutral_task_complete(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-neutral.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the proposed change.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {
                            "type": "task_complete",
                            "last_agent_message": "All set.",
                        },
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:04:00Z")
        self.assertIn("response", turns[0].assistant_action_summary)

    def test_neutral_task_complete_detaches_before_runtime_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-neutral.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the proposed change.", "2026-05-22T10:01:00Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:02:00Z",
                        "payload": {
                            "type": "task_complete",
                            "last_agent_message": "All set.",
                        },
                    },
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("response", turns[0].assistant_action_summary)

    def test_runtime_wrapper_followup_function_call_does_not_merge_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-wrapper-call.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the proposed change.", "2026-05-22T10:01:00Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:02:00Z",
                        "payload": {
                            "type": "task_complete",
                            "last_agent_message": "All set.",
                        },
                    },
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:03:00Z"),
                    {
                        "type": "response_item",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "arguments": "{\"cmd\":\"cat secret.txt\",\"sandbox_permissions\":\"require_escalated\"}",
                        },
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertNotIn("approval_auth_friction", turns[0].issue_flags)
        self.assertNotIn("safety_privacy_flag", turns[0].issue_flags)
        self.assertIn("response", turns[0].assistant_action_summary)

    def test_neutral_assistant_final_detaches_before_runtime_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-neutral-assistant.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the proposed change.", "2026-05-22T10:01:00Z"),
                    message("assistant", "LGTM / no actionable findings.", "2026-05-22T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("response", turns[0].assistant_action_summary)

    def test_past_tense_then_assistant_final_detaches_before_runtime_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-then-final.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review and verify the proposed change.", "2026-05-22T10:01:00Z"),
                    message("assistant", "Ran tests, then updated docs.", "2026-05-22T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("implementation", turns[0].assistant_action_summary)
        self.assertIn("verification", turns[0].assistant_action_summary)

    def test_verification_gap_assistant_final_detaches_before_runtime_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-gap-assistant.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Verify the deployment.", "2026-05-22T10:01:00Z"),
                    message("assistant", "Could not run tests.", "2026-05-22T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("verification_gap", turns[0].issue_flags)
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("verification", turns[0].assistant_action_summary)

    def test_wrapper_pending_assistant_flags_survive_neutral_tool_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-pending-flags.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Verify the deployment.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "Could not run tests.", "2026-05-22T10:02:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {"output": "Process exited with code 0\nOK"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:04:00Z")
        self.assertIn("verification_gap", turns[0].issue_flags)
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("verification", turns[0].assistant_action_summary)

    def test_wrapper_pending_assistant_final_emits_at_eof(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-pending-eof.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the proposed change.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "LGTM / no actionable findings.", "2026-05-22T10:03:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:03:00Z")
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("response", turns[0].assistant_action_summary)

    def test_wrapper_pending_review_findings_final_emits_at_eof(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-pending-findings.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the proposed change.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message(
                        "assistant",
                        "Findings:\n- [P1] session_retrospective.py:10 drops actionable review output.",
                        "2026-05-22T10:03:00Z",
                    ),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:03:00Z")
        self.assertIn("git_or_pr", turns[0].assistant_action_summary)

    def test_wrapper_pending_path_bullet_findings_final_emits_at_eof(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-pending-path-bullet.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Review the proposed change.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "- session_retrospective.py:10 drops actionable review output.", "2026-05-22T10:03:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:03:00Z")

    def test_wrapper_pending_implementation_final_emits_at_eof(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-pending-implementation.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Implement the helper.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "Implemented the change.", "2026-05-22T10:03:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:03:00Z")
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("implementation", turns[0].assistant_action_summary)

    def test_wrapper_pending_verification_gap_final_emits_at_eof(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-gap-pending-eof.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Verify the deployment.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "Could not run tests.", "2026-05-22T10:03:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:03:00Z")
        self.assertIn("verification_gap", turns[0].issue_flags)
        self.assertNotIn("failed_command", turns[0].issue_flags)
        self.assertIn("verification", turns[0].assistant_action_summary)

    def test_wrapper_pending_assistant_final_emits_before_next_user(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-pending-next-user.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Verify the deployment.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "Verification failed during smoke test.", "2026-05-22T10:03:00Z"),
                    message("user", "Now inspect the logs.", "2026-05-22T10:04:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 2)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:03:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("verification", turns[0].assistant_action_summary)
        self.assertEqual(turns[1].timestamp, "2026-05-22T10:04:00Z")

    def test_wrapper_pending_verification_gap_final_emits_before_next_user(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-gap-pending-next-user.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Verify the deployment.", "2026-05-20T10:01:00Z"),
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:01Z"),
                    message("assistant", "Could not run tests.", "2026-05-22T10:03:00Z"),
                    message("user", "Now inspect the logs.", "2026-05-22T10:04:00Z"),
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 2)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:03:00Z")
        self.assertIn("verification_gap", turns[0].issue_flags)
        self.assertIn("verification", turns[0].assistant_action_summary)
        self.assertEqual(turns[1].timestamp, "2026-05-22T10:04:00Z")

    def test_future_intent_preamble_does_not_detach_active_turn_on_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-preamble.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the long-running deployment.", "2026-05-20T10:01:00Z"),
                    message("assistant", "I'll get this fixed and verified.", "2026-05-20T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:05:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:05:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)

    def test_future_intent_after_progress_does_not_detach_active_turn_on_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-progress-preamble.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the long-running deployment.", "2026-05-20T10:01:00Z"),
                    message("assistant", "I updated the helper and will run the tests next.", "2026-05-20T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:05:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:05:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)

    def test_prefixed_future_intent_preamble_does_not_detach_active_turn_on_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-prefixed-preamble.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the long-running deployment.", "2026-05-20T10:01:00Z"),
                    message("assistant", "Got it. I'll get this fixed and verified.", "2026-05-20T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:05:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:05:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)

    def test_future_intent_failure_preamble_does_not_detach_active_turn_on_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "20" / "rollout-2026-05-20T10-00-00-failure-preamble.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Debug the long-running deployment.", "2026-05-20T10:01:00Z"),
                    message("assistant", "I'll investigate why the test failed.", "2026-05-20T10:02:00Z"),
                    message("user", "# AGENTS.md instructions\nwrapper", "2026-05-22T10:03:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:05:00Z",
                        "payload": {"output": "Process exited with code 1\npermission denied"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-05-20T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T00:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T10:05:00Z")
        self.assertIn("failed_command", turns[0].issue_flags)

    def test_harmless_event_before_wrapper_preserves_active_turn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-abc.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Please fix the deployment.", "2026-05-22T10:01:00Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:01:01Z",
                        "payload": {"type": "token_count", "input_tokens": 100},
                    },
                    message("user", "# AGENTS.md instructions\nRepository policy only.", "2026-05-22T10:01:02Z"),
                    {
                        "type": "event_msg",
                        "timestamp": "2026-05-22T10:04:00Z",
                        "payload": {
                            "type": "task_complete",
                            "last_agent_message": "The command failed with exit code 1.",
                        },
                    },
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("blocked_or_failed", turns[0].assistant_action_summary)

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

    def test_copied_dot_codex_source_does_not_require_index_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-copied.jsonl"
            write_jsonl(rollout, [message("user", "Copied rollout task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
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

    def test_baseline_dry_run_writes_scan_shards_and_report_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-dry.jsonl"
            write_jsonl(rollout, [message("user", "Dry-run task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw, "baseline-dry-run")

            MODULE.main(
                [
                    "baseline-dry-run",
                    "--window-days",
                    "90",
                    "--from",
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
            report = json.loads((output / "dry_run_report.json").read_text(encoding="utf-8"))
            scan_exists = (output / "scan" / "trend_report.json").is_file()
            shards_exist = (output / "shards" / "shards.jsonl").is_file()

        self.assertTrue(scan_exists)
        self.assertTrue(shards_exist)
        self.assertEqual(report["kind"], "baseline_dry_run")
        self.assertFalse(report["retained_export_created"])
        self.assertFalse(report["history_commit_created"])
        self.assertFalse(report["state_advanced"])

    def test_baseline_dry_run_stores_absolute_source_roots_for_repair(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw) / "workspace"
            workspace.mkdir()
            root = workspace / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-relative.jsonl"
            write_jsonl(rollout, [message("user", "Relative dry-run task.", "2026-05-01T10:00:00Z")])
            dry_run = workspace / ".codex-local" / "session-retrospective" / "baseline-dry-run"
            repair = workspace / ".codex-local" / "session-retrospective" / "coverage-repair"
            previous_cwd = Path.cwd()
            try:
                os.chdir(workspace)
                MODULE.main(
                    [
                        "baseline-dry-run",
                        "--window-days",
                        "90",
                        "--from",
                        "2026-05-01T00:00:00Z",
                        "--end",
                        "2026-05-02T00:00:00Z",
                        "--source",
                        "local=.codex",
                        "--allow-partial-hosts",
                        "--output",
                        ".codex-local/session-retrospective/baseline-dry-run",
                    ]
                )
                elsewhere = Path(raw) / "elsewhere"
                elsewhere.mkdir()
                os.chdir(elsewhere)
                MODULE.main(
                    [
                        "repair-coverage",
                        "--run-dir",
                        str(dry_run),
                        "--output",
                        str(repair),
                        "--skip-remote-materialization",
                        "--allow-partial-hosts",
                    ]
                )
            finally:
                os.chdir(previous_cwd)
            manifest = json.loads((dry_run / "scan" / "shard_manifest.json").read_text(encoding="utf-8"))
            trend = json.loads((repair / "scan" / "trend_report.json").read_text(encoding="utf-8"))

        self.assertTrue(Path(manifest["sources"][0]["root"]).is_absolute())
        self.assertEqual(Path(manifest["sources"][0]["root"]).resolve(), root.resolve())
        self.assertEqual(trend["turn_count"], 1)

    def test_baseline_dry_run_stores_absolute_default_roots_for_skip_remote_repair(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw) / "workspace"
            home = Path(raw) / "home"
            workspace.mkdir()
            root = home / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-default.jsonl"
            write_jsonl(rollout, [message("user", "Default dry-run task.", "2026-05-01T10:00:00Z")])
            dry_run = workspace / ".codex-local" / "session-retrospective" / "baseline-dry-run"
            repair = workspace / ".codex-local" / "session-retrospective" / "coverage-repair"
            previous_cwd = Path.cwd()
            try:
                os.chdir(workspace)
                with mock.patch.dict(os.environ, {"HOME": str(home)}):
                    MODULE.main(
                        [
                            "baseline-dry-run",
                            "--window-days",
                            "90",
                            "--from",
                            "2026-05-01T00:00:00Z",
                            "--end",
                            "2026-05-02T00:00:00Z",
                            "--output",
                            ".codex-local/session-retrospective/baseline-dry-run",
                        ]
                    )
                    MODULE.main(
                        [
                            "repair-coverage",
                            "--run-dir",
                            str(dry_run),
                            "--output",
                            str(repair),
                            "--skip-remote-materialization",
                        ]
                    )
            finally:
                os.chdir(previous_cwd)
            manifest = json.loads((dry_run / "scan" / "shard_manifest.json").read_text(encoding="utf-8"))
            trend = json.loads((repair / "scan" / "trend_report.json").read_text(encoding="utf-8"))

        self.assertTrue(all(Path(source["root"]).is_absolute() for source in manifest["sources"]))
        self.assertEqual(trend["turn_count"], 1)

    def test_repair_coverage_reruns_with_larger_raw_limit_for_local_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-large.jsonl"
            write_jsonl(
                rollout,
                [message("user", f"Oversized local task {index}.", "2026-05-01T10:00:00Z") for index in range(40)],
            )
            dry_run = safe_output_dir(raw, "baseline-dry-run")
            repair = safe_output_dir(raw, "coverage-repair")

            MODULE.main(
                [
                    "baseline-dry-run",
                    "--window-days",
                    "90",
                    "--from",
                    "2026-05-01T00:00:00Z",
                    "--end",
                    "2026-05-02T00:00:00Z",
                    "--source",
                    f"local={root}",
                    "--allow-partial-hosts",
                    "--max-raw-bytes",
                    "200",
                    "--output",
                    str(dry_run),
                ]
            )
            before = json.loads((dry_run / "scan" / "trend_report.json").read_text(encoding="utf-8"))

            MODULE.main(
                [
                    "repair-coverage",
                    "--run-dir",
                    str(dry_run),
                    "--output",
                    str(repair),
                    "--skip-remote-materialization",
                    "--allow-partial-hosts",
                    "--max-raw-bytes",
                    "20000",
                ]
            )
            after = json.loads((repair / "scan" / "trend_report.json").read_text(encoding="utf-8"))
            report = json.loads((repair / "repair_report.json").read_text(encoding="utf-8"))

        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in before["coverage_gaps"]])
        self.assertNotIn("oversized_rollout_skipped", [gap["reason"] for gap in after["coverage_gaps"]])
        self.assertEqual(report["kind"], "coverage_repair")
        self.assertFalse(report["retained_export_created"])
        self.assertFalse(report["state_advanced"])

    def test_repair_coverage_default_output_does_not_nest_under_direct_scan_run_dir(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-direct-scan.jsonl"
            write_jsonl(rollout, [message("user", "Direct scan repair task.", "2026-05-01T10:00:00Z")])
            dry_run = safe_output_dir(raw, "baseline-dry-run")

            MODULE.main(
                [
                    "baseline-dry-run",
                    "--window-days",
                    "90",
                    "--from",
                    "2026-05-01T00:00:00Z",
                    "--end",
                    "2026-05-02T00:00:00Z",
                    "--source",
                    f"local={root}",
                    "--allow-partial-hosts",
                    "--output",
                    str(dry_run),
                ]
            )
            MODULE.main(
                [
                    "repair-coverage",
                    "--run-dir",
                    str(dry_run / "scan"),
                    "--skip-remote-materialization",
                    "--allow-partial-hosts",
                ]
            )
            MODULE.main(["validate-output", "--run-dir", str(dry_run / "scan")])
            sibling_report_exists = (dry_run / "coverage-repair" / "repair_report.json").is_file()
            nested_output_exists = (dry_run / "scan" / "coverage-repair").exists()

        self.assertTrue(sibling_report_exists)
        self.assertFalse(nested_output_exists)

    def test_repair_coverage_materializes_remote_with_auto_split_probe(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dry_run = safe_output_dir(raw, "baseline-dry-run")
            scan = dry_run / "scan"
            scan.mkdir(parents=True)
            manifest = {
                "schema_version": 1,
                "mode": "baseline-90d",
                "window": {
                    "mode": "baseline-90d",
                    "start": "2026-05-01T00:00:00Z",
                    "end": "2026-05-02T00:00:00Z",
                },
                "sources": [
                    {
                        "host": "miku-bot-dev",
                        "root": str(Path(raw) / "stale-miku"),
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "rollout_count": 0,
                        "summary_count": 0,
                        "status": "stale",
                    }
                ],
                "coverage_gaps": [
                    {
                        "host": "miku-bot-dev",
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "reason": "remote_source_not_materialized",
                    }
                ],
                "redaction_policy_version": 1,
                "retention_safe": False,
            }
            (scan / "shard_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            fake_probe = Path(raw) / "fake_remote_probe.py"
            fake_probe.write_text(
                "\n".join(
                    [
                        "import json, pathlib, sys",
                        "args = sys.argv[1:]",
                        "cmd = args[0]",
                        "def arg(name):",
                        "    return args[args.index(name) + 1]",
                        "if cmd == 'preflight':",
                        "    print('host\\thostname\\tuser\\thome\\tcodex\\trg\\tpython3')",
                        "    print(arg('--host') + '\\tfake\\thoteng\\t/home/hoteng\\tpresent\\tpresent\\tpresent')",
                        "elif cmd == 'session-meta':",
                        "    host = arg('--host')",
                        "    print('host\\tdate\\tsession_id\\tcwd\\trollout')",
                        "    print(host + '\\t2026/05/01\\ts1\\t/work\\tsessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl')",
                        "elif cmd == 'fetch-rollout':",
                        "    output = pathlib.Path(arg('--output'))",
                        "    output.parent.mkdir(parents=True, exist_ok=True)",
                        "    row = {'type': 'event_msg', 'timestamp': '2026-05-01T10:00:00Z', 'payload': {'type': 'user_message', 'message': 'Remote repaired task.'}}",
                        "    output.write_text(json.dumps(row) + '\\n', encoding='utf-8')",
                        "    print('ok=true')",
                        "else:",
                        "    raise SystemExit(2)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            repair = safe_output_dir(raw, "coverage-repair")

            MODULE.main(
                [
                    "repair-coverage",
                    "--run-dir",
                    str(dry_run),
                    "--output",
                    str(repair),
                    "--allow-partial-hosts",
                    "--remote-probe",
                    str(fake_probe),
                ]
            )
            trend = json.loads((repair / "scan" / "trend_report.json").read_text(encoding="utf-8"))
            report = json.loads((repair / "repair_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["hosts"]["miku-bot-dev"], 1)
        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(report["repair"]["materialized_hosts"][0]["rollout_count"], 1)

    def test_repair_coverage_keeps_remote_gap_when_rollout_materialization_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dry_run = safe_output_dir(raw, "baseline-dry-run")
            scan = dry_run / "scan"
            scan.mkdir(parents=True)
            manifest = {
                "schema_version": 1,
                "mode": "baseline-90d",
                "window": {
                    "mode": "baseline-90d",
                    "start": "2026-05-01T00:00:00Z",
                    "end": "2026-05-02T00:00:00Z",
                },
                "sources": [
                    {
                        "host": "miku-bot-dev",
                        "root": str(Path(raw) / "stale-miku"),
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "rollout_count": 0,
                        "summary_count": 0,
                        "status": "stale",
                    }
                ],
                "coverage_gaps": [
                    {
                        "host": "miku-bot-dev",
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "reason": "remote_source_not_materialized",
                    }
                ],
                "redaction_policy_version": 1,
                "retention_safe": False,
            }
            (scan / "shard_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            fake_probe = Path(raw) / "fake_remote_probe.py"
            fake_probe.write_text(
                "\n".join(
                    [
                        "import sys",
                        "args = sys.argv[1:]",
                        "cmd = args[0]",
                        "def arg(name):",
                        "    return args[args.index(name) + 1]",
                        "if cmd == 'preflight':",
                        "    print('host\\thostname\\tuser\\thome\\tcodex\\trg\\tpython3')",
                        "    print(arg('--host') + '\\tfake\\thoteng\\t/home/hoteng\\tpresent\\tpresent\\tpresent')",
                        "elif cmd == 'session-meta':",
                        "    host = arg('--host')",
                        "    print('host\\tdate\\tsession_id\\tcwd\\trollout')",
                        "    print(host + '\\t2026/05/01\\ts1\\t/work\\tsessions/2026/05/01/rollout-2026-05-01T10-00-00-missing.jsonl')",
                        "elif cmd in {'fetch-rollout', 'rollout-summary'}:",
                        "    print('error=blocked', file=sys.stderr)",
                        "    raise SystemExit(1)",
                        "else:",
                        "    raise SystemExit(2)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            repair = safe_output_dir(raw, "coverage-repair")

            MODULE.main(
                [
                    "repair-coverage",
                    "--run-dir",
                    str(dry_run),
                    "--output",
                    str(repair),
                    "--allow-partial-hosts",
                    "--remote-probe",
                    str(fake_probe),
                ]
            )
            trend = json.loads((repair / "scan" / "trend_report.json").read_text(encoding="utf-8"))
            report = json.loads((repair / "repair_report.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        host_report = report["repair"]["materialized_hosts"][0]
        self.assertEqual(host_report["status"], "remote_source_not_materialized")
        self.assertEqual(host_report["failed_rollout_count"], 1)

    def test_repair_coverage_keeps_remote_gap_when_only_summary_fallback_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dry_run = safe_output_dir(raw, "baseline-dry-run")
            scan = dry_run / "scan"
            scan.mkdir(parents=True)
            manifest = {
                "schema_version": 1,
                "mode": "baseline-90d",
                "window": {
                    "mode": "baseline-90d",
                    "start": "2026-05-01T00:00:00Z",
                    "end": "2026-05-02T00:00:00Z",
                },
                "sources": [
                    {
                        "host": "miku-bot-dev",
                        "root": str(Path(raw) / "stale-miku"),
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "rollout_count": 0,
                        "summary_count": 0,
                        "status": "stale",
                    }
                ],
                "coverage_gaps": [
                    {
                        "host": "miku-bot-dev",
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "reason": "remote_source_not_materialized",
                    }
                ],
                "redaction_policy_version": 1,
                "retention_safe": False,
            }
            (scan / "shard_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            fake_probe = Path(raw) / "fake_remote_probe.py"
            fake_probe.write_text(
                "\n".join(
                    [
                        "import json, sys",
                        "args = sys.argv[1:]",
                        "cmd = args[0]",
                        "def arg(name):",
                        "    return args[args.index(name) + 1]",
                        "if cmd == 'preflight':",
                        "    print('host\\thostname\\tuser\\thome\\tcodex\\trg\\tpython3')",
                        "    print(arg('--host') + '\\tfake\\thoteng\\t/home/hoteng\\tpresent\\tpresent\\tpresent')",
                        "elif cmd == 'session-meta':",
                        "    host = arg('--host')",
                        "    print('host\\tdate\\tsession_id\\tcwd\\trollout')",
                        "    print(host + '\\t2026/05/01\\ts1\\t/work\\tsessions/2026/05/01/rollout-2026-05-01T10-00-00-summary-only.jsonl')",
                        "elif cmd == 'fetch-rollout':",
                        "    print('error=blocked', file=sys.stderr)",
                        "    raise SystemExit(1)",
                        "elif cmd == 'rollout-summary':",
                        "    rollout = arg('--rollout')",
                        "    print(json.dumps({'kind': 'scan_meta', 'timestamp': '', 'rollout': rollout, 'scan_bytes': 1000, 'scan_truncated': False, 'json_error_count': 0, 'keyword_filter_applied': False, 'record_limit_reached': False, 'signal_record_limit_reached': False, 'matched_record_limit_reached': False, 'tail_record_limit_reached': False, 'summary_limit': 200, 'source_bytes': 1000}))",
                        "    print(json.dumps({'kind': 'user_message', 'timestamp': '2026-05-01T10:00:00Z', 'rollout': rollout, 'text': 'permission denied while reading remote rollout'}))",
                        "else:",
                        "    raise SystemExit(2)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            repair = safe_output_dir(raw, "coverage-repair")

            MODULE.main(
                [
                    "repair-coverage",
                    "--run-dir",
                    str(dry_run),
                    "--output",
                    str(repair),
                    "--allow-partial-hosts",
                    "--remote-probe",
                    str(fake_probe),
                ]
            )
            trend = json.loads((repair / "scan" / "trend_report.json").read_text(encoding="utf-8"))
            report = json.loads((repair / "repair_report.json").read_text(encoding="utf-8"))
            metadata = json.loads(
                (
                    repair
                    / "remote-sources"
                    / "miku-bot-dev"
                    / MODULE.REMOTE_SOURCE_METADATA_FILE
                ).read_text(encoding="utf-8")
            )

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(trend["turn_count"], 1)
        host_report = report["repair"]["materialized_hosts"][0]
        self.assertEqual(host_report["status"], "ready")
        self.assertEqual(host_report["summary_count"], 1)
        self.assertEqual(host_report["failed_rollout_count"], 0)
        self.assertEqual(metadata["status"], "ready")

    def test_repair_coverage_rejects_relative_manifest_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dry_run = safe_output_dir(raw, "baseline-dry-run")
            scan = dry_run / "scan"
            scan.mkdir(parents=True)
            manifest = {
                "schema_version": 1,
                "mode": "baseline-90d",
                "window": {
                    "mode": "baseline-90d",
                    "start": "2026-05-01T00:00:00Z",
                    "end": "2026-05-02T00:00:00Z",
                },
                "sources": [
                    {
                        "host": "local",
                        "root": ".codex",
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "rollout_count": 1,
                        "summary_count": 0,
                        "status": "ready",
                    }
                ],
                "coverage_gaps": [],
                "redaction_policy_version": 1,
                "retention_safe": False,
            }
            (scan / "shard_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            repair = safe_output_dir(raw, "coverage-repair")

            with self.assertRaisesRegex(SystemExit, "absolute source roots"):
                MODULE.main(
                    [
                        "repair-coverage",
                        "--run-dir",
                        str(dry_run),
                        "--output",
                        str(repair),
                        "--skip-remote-materialization",
                        "--allow-partial-hosts",
                    ]
                )

    def test_repair_coverage_rejects_symlinked_remote_sources_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dry_run = safe_output_dir(raw, "baseline-dry-run")
            scan = dry_run / "scan"
            scan.mkdir(parents=True)
            manifest = {
                "schema_version": 1,
                "mode": "baseline-90d",
                "window": {
                    "mode": "baseline-90d",
                    "start": "2026-05-01T00:00:00Z",
                    "end": "2026-05-02T00:00:00Z",
                },
                "sources": [
                    {
                        "host": "miku-bot-dev",
                        "root": str(Path(raw) / "stale-miku"),
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "rollout_count": 0,
                        "summary_count": 0,
                        "status": "stale",
                    }
                ],
                "coverage_gaps": [
                    {
                        "host": "miku-bot-dev",
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "reason": "remote_source_not_materialized",
                    }
                ],
                "redaction_policy_version": 1,
                "retention_safe": False,
            }
            (scan / "shard_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            fake_probe = Path(raw) / "fake_remote_probe.py"
            fake_probe.write_text("raise SystemExit(2)\n", encoding="utf-8")
            repair = safe_output_dir(raw, "coverage-repair")
            repair.mkdir(parents=True)
            outside = Path(raw) / "outside"
            outside.mkdir()
            (repair / "remote-sources").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(SystemExit, "materialized remote metadata must not use symlink"):
                MODULE.main(
                    [
                        "repair-coverage",
                        "--run-dir",
                        str(dry_run),
                        "--output",
                        str(repair),
                        "--allow-partial-hosts",
                        "--remote-probe",
                        str(fake_probe),
                    ]
                )

    def test_repair_coverage_rejects_non_empty_remote_materialization_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dry_run = safe_output_dir(raw, "baseline-dry-run")
            scan = dry_run / "scan"
            scan.mkdir(parents=True)
            manifest = {
                "schema_version": 1,
                "mode": "baseline-90d",
                "window": {
                    "mode": "baseline-90d",
                    "start": "2026-05-01T00:00:00Z",
                    "end": "2026-05-02T00:00:00Z",
                },
                "sources": [
                    {
                        "host": "miku-bot-dev",
                        "root": str(Path(raw) / "stale-miku"),
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "rollout_count": 0,
                        "summary_count": 0,
                        "status": "stale",
                    }
                ],
                "coverage_gaps": [
                    {
                        "host": "miku-bot-dev",
                        "root_ref": "path_ref_v1:0123456789abcdef",
                        "reason": "remote_source_not_materialized",
                    }
                ],
                "redaction_policy_version": 1,
                "retention_safe": False,
            }
            (scan / "shard_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            fake_probe = Path(raw) / "fake_remote_probe.py"
            fake_probe.write_text("raise SystemExit(2)\n", encoding="utf-8")
            repair = safe_output_dir(raw, "coverage-repair")
            stale = repair / "remote-sources" / "miku-bot-dev" / "sessions" / "2026" / "05" / "01"
            write_jsonl(
                stale / "rollout-2026-05-01T10-00-00-stale.jsonl",
                [message("user", "Stale remote task.", "2026-05-01T10:00:00Z")],
            )

            with self.assertRaisesRegex(SystemExit, "remote materialization root must be empty"):
                MODULE.main(
                    [
                        "repair-coverage",
                        "--run-dir",
                        str(dry_run),
                        "--output",
                        str(repair),
                        "--allow-partial-hosts",
                        "--remote-probe",
                        str(fake_probe),
                    ]
                )

    def test_baseline_from_first_includes_rollout_summary_dates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
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

    def test_earliest_rollout_date_scans_summaries_with_bounded_timestamp_probe(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            write_jsonl(summary, [{"timestamp": "2025-12-31T23:00:00Z", "kind": "summary", "text": "earlier"}])

            with mock.patch.object(MODULE, "iter_jsonl", side_effect=AssertionError("unbounded scan")):
                earliest = MODULE.earliest_rollout_date([MODULE.Source("local", root)])

        self.assertEqual(MODULE.iso(earliest), "2025-12-31T23:00:00Z")

    def test_baseline_from_first_ignores_malformed_summary_when_deriving_start(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            summary.parent.mkdir(parents=True)
            summary.write_text("{bad json\n", encoding="utf-8")
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-fresh.jsonl"
            write_jsonl(rollout, [message("user", "Fresh baseline task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.main(
                [
                    "baseline",
                    "--window-days",
                    "90",
                    "--from",
                    "first",
                    "--end",
                    "2026-06-01T00:00:00Z",
                    "--source",
                    f"local={root}",
                    "--allow-partial-hosts",
                    "--output",
                    str(output),
                ]
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["window"]["start"], "2026-01-01T00:00:00Z")
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "invalid_jsonl")

    def test_baseline_from_first_skips_stale_default_remote_cache_when_deriving_start(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            write_local_evidence(local)
            local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            write_jsonl(local_rollout, [message("user", "Fresh local baseline task.", "2026-05-01T10:00:00Z")])
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            metadata_path = remote / MODULE.REMOTE_SOURCE_METADATA_FILE
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["status"] = "stale"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            old_remote = remote / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-remote.jsonl"
            write_jsonl(old_remote, [message("user", "Stale remote baseline task.", "2026-01-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.main(
                [
                    "baseline",
                    "--window-days",
                    "90",
                    "--from",
                    "first",
                    "--end",
                    "2026-06-01T00:00:00Z",
                    "--source",
                    f"local={local}",
                    "--source",
                    f"miku-bot-dev={remote}",
                    "--allow-partial-hosts",
                    "--output",
                    str(output),
                ]
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["window"]["start"], "2026-05-01T00:00:00Z")
        self.assertIn("stale_host", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_baseline_from_first_ignores_remote_rollouts_outside_metadata_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            write_local_evidence(local)
            local_rollout = local / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-local.jsonl"
            write_jsonl(local_rollout, [message("user", "Fresh local baseline task.", "2026-05-01T10:00:00Z")])
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            old_remote = remote / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-remote.jsonl"
            write_jsonl(old_remote, [message("user", "Old remote baseline task.", "2026-01-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.main(
                [
                    "baseline",
                    "--window-days",
                    "90",
                    "--from",
                    "first",
                    "--end",
                    "2026-06-01T00:00:00Z",
                    "--source",
                    f"local={local}",
                    "--source",
                    f"miku-bot-dev={remote}",
                    "--allow-partial-hosts",
                    "--output",
                    str(output),
                ]
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["window"]["start"], "2026-05-01T00:00:00Z")

    def test_daily_first_run_uses_active_lookback_days(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-active.jsonl"
            write_jsonl(rollout, [message("user", "Continue active work.", "2026-05-12T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-22T10:00:00Z")), mock.patch.object(
                MODULE, "local_source_is_canonical", return_value=True
            ):
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
                        "-7",
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

    def test_baseline_rejects_window_days_above_retained_schema_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            output = safe_output_dir(raw)

            with self.assertRaisesRegex(SystemExit, "--window-days.*9999"):
                MODULE.main(
                    [
                        "baseline",
                        "--window-days",
                        "10000",
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

            with mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-22T10:00:00Z")), mock.patch.object(
                MODULE, "local_source_is_canonical", return_value=True
            ):
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

    def test_daily_existing_state_at_end_rejects_replay(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-active.jsonl"
            write_jsonl(rollout, [message("user", "Active lookback work.", "2026-05-12T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-22T10:00:00Z"}), encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "already at or after scan end"):
                MODULE.main(
                    [
                        "scan-daily",
                        "--active-lookback-days",
                        "14",
                        "--end",
                        "2026-05-22T10:00:00Z",
                        "--state",
                        str(state),
                        "--source",
                        f"local={root}",
                        "--allow-partial-hosts",
                        "--output",
                        str(output),
                    ]
                )
            state_after_scan = json.loads(state.read_text(encoding="utf-8"))

        self.assertFalse(output.exists())
        self.assertEqual(state_after_scan["last_scan_at"], "2026-05-22T10:00:00Z")

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

    def test_daily_existing_state_ignores_old_lookback_invalid_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = []
            for host in MODULE.DEFAULT_REMOTE_HOSTS:
                remote_root = Path(raw) / host
                write_remote_metadata(
                    remote_root,
                    host,
                    window_start="2026-05-08T10:00:00Z",
                    window_end="2026-05-22T10:00:00Z",
                    materialized_at="2026-05-22T10:00:00Z",
                )
                remote_sources.append(f"{host}={remote_root}")
            bad_rollout = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-bad.jsonl"
            new_rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T09-00-00-active.jsonl"
            bad_rollout.parent.mkdir(parents=True, exist_ok=True)
            bad_rollout.write_text("{bad json\n", encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-05-12T10:00:00Z").timestamp()
            os.utime(bad_rollout, (old_mtime, old_mtime))
            write_jsonl(new_rollout, [message("user", "New daily work.", "2026-05-22T09:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-21T10:00:00Z"}), encoding="utf-8")

            with (
                mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-22T10:00:00Z")),
                mock.patch.object(MODULE, "local_source_is_canonical", return_value=True),
            ):
                MODULE.main(
                    [
                        "scan-daily",
                        "--active-lookback-days",
                        "14",
                        "--state",
                        str(state),
                        "--source",
                        f"local={root}",
                        "--source",
                        remote_sources[0],
                        "--source",
                        remote_sources[1],
                        "--output",
                        str(output),
                    ]
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["turn_count"], 1)
        self.assertEqual(trend["coverage_gaps"], [])

    def test_daily_existing_state_ignores_old_lookback_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = []
            for host in MODULE.DEFAULT_REMOTE_HOSTS:
                remote_root = Path(raw) / host
                write_remote_metadata(
                    remote_root,
                    host,
                    window_start="2026-05-08T10:00:00Z",
                    window_end="2026-05-22T10:00:00Z",
                    materialized_at="2026-05-22T10:00:00Z",
                )
                remote_sources.append(f"{host}={remote_root}")
            old_large = root / "sessions" / "2026" / "05" / "12" / "rollout-2026-05-12T10-00-00-large.jsonl"
            new_rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T09-00-00-active.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-old-oversized " + ("x" * 2000), encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-05-12T10:00:00Z").timestamp()
            os.utime(old_large, (old_mtime, old_mtime))
            write_jsonl(new_rollout, [message("user", "New daily work.", "2026-05-22T09:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-21T10:00:00Z"}), encoding="utf-8")

            with (
                mock.patch.object(MODULE, "utc_now", return_value=MODULE.parse_time("2026-05-22T10:00:00Z")),
                mock.patch.object(MODULE, "local_source_is_canonical", return_value=True),
            ):
                MODULE.main(
                    [
                        "scan-daily",
                        "--active-lookback-days",
                        "14",
                        "--max-raw-bytes",
                        "1000",
                        "--state",
                        str(state),
                        "--source",
                        f"local={root}",
                        "--source",
                        remote_sources[0],
                        "--source",
                        remote_sources[1],
                        "--output",
                        str(output),
                    ]
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(trend["turn_count"], 1)
        self.assertEqual(trend["coverage_gaps"], [])

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

    def test_wrapper_only_message_preserves_active_turn_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-wrapper.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Fix the deployment verification.", "2026-05-22T10:00:00Z"),
                    message("assistant", "I will inspect the failing check.", "2026-05-22T10:00:01Z"),
                    message(
                        "user",
                        "# AGENTS.md instructions\n"
                        "<INSTRUCTIONS>Repository policy.</INSTRUCTIONS>\n"
                        "<environment_context>Runtime metadata.</environment_context>",
                        "2026-05-22T10:00:02Z",
                    ),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T10:00:03Z",
                        "payload": {"output": "Process exited with code 1\nverification failed"},
                    },
                    message("assistant", "Verification failed after the command exited.", "2026-05-22T10:00:04Z"),
                ],
            )

            turns = MODULE.extract_rollout(MODULE.Source("local", root), rollout, None, None)

        self.assertEqual(len(turns), 1)
        self.assertIn("failed_command", turns[0].issue_flags)
        self.assertIn("blocked_or_failed", turns[0].assistant_action_summary)
        self.assertIn("verification", turns[0].assistant_action_summary)

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
                allow_mtime_fallback=True,
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

    def test_pre_window_user_with_in_window_successful_tool_output_is_not_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-success.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Continue the long-running migration.", "2026-01-01T10:00:00Z"),
                    {
                        "type": "function_call_output",
                        "timestamp": "2026-05-22T09:00:00Z",
                        "payload": {"output": "Processed 42 records successfully"},
                    },
                ],
            )

            turns = MODULE.extract_rollout(
                MODULE.Source("local", root),
                rollout,
                MODULE.parse_time("2026-01-01T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-21T10:00:00Z"),
            )

        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].timestamp, "2026-05-22T09:00:00Z")
        self.assertEqual(turns[0].issue_flags, [])

    def test_make_shards_respects_window_and_reports_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-old.jsonl"
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            summary = root / "sessions" / "2026" / "01" / "02" / "rollout-summary-large.jsonl"
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

        self.assertEqual(len(rows), 2)
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(by_path[str(summary)]["kind"], "summary")
        self.assertEqual(by_path[str(summary)]["status"], "oversized")
        self.assertIn("coverage_gap", by_path[str(summary)])
        self.assertEqual(by_path[str(large)]["status"], "oversized")
        self.assertIn("coverage_gap", by_path[str(large)])
        self.assertIn("path_ref_v1:", by_path[str(large)]["path_ref"])

    def test_make_shards_marks_oversized_summary_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "05" / "22" / "rollout-summary-large.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("summary " + ("x" * 2000), encoding="utf-8")
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
                ]
            )
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "oversized")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_marks_old_undated_oversized_summary_conservative(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "rollout-summary-undated.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps({"kind": "summary", "timestamp": "2026-04-01T10:00:00Z", "text": "permission denied"})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
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
                ]
            )
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "oversized")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_revalidates_source_materialization_before_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "custom-source"
            safe_rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-safe.jsonl"
            write_jsonl(safe_rollout, [message("user", "Safe custom task.", "2026-05-01T10:00:00Z")])
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "custom_source", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            outside = Path(raw) / "outside.jsonl"
            write_jsonl(outside, [message("user", "Unsafe custom task.", "2026-05-01T11:00:00Z")])
            unsafe_rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T11-00-00-unsafe.jsonl"
            unsafe_rollout.symlink_to(outside)
            output = safe_output_dir(raw)

            MODULE.main(
                [
                    "make-shards",
                    "--manifest",
                    str(manifest),
                    "--output",
                    str(output),
                    "--include-raw-paths",
                ]
            )
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], str(root))
        self.assertEqual(rows[0]["status"], "stale")
        self.assertEqual(rows[0]["coverage_gap"], "unsafe_source_artifact")

    def test_make_shards_revalidates_remote_summary_backing_before_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
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
                    "--include-raw-paths",
                ]
            )
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], str(root))
        self.assertEqual(rows[0]["status"], "stale")
        self.assertEqual(rows[0]["coverage_gap"], "remote_source_not_materialized")

    def test_make_shards_scans_old_dated_summary_for_current_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-22T10:00:00Z", "text": "permission denied"}])
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

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "ready")

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

    def test_make_shards_reports_in_window_unreadable_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            blocked = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-blocked.jsonl"
            write_jsonl(blocked, [message("user", "Blocked shard.", "2026-05-22T10:00:00Z")])
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

            with blocked_path_open(blocked):
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

    def test_make_shards_includes_relevant_rollout_summary_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "05" / "22" / "rollout-summary-large.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-22T10:00:00Z", "text": "permission denied"}])
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

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "ready")
        self.assertIn("path_ref_v1:", rows[0]["path_ref"])

    def test_make_shards_reports_invalid_relevant_rollout_summary_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "05" / "22" / "rollout-summary-large.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("{bad json\n", encoding="utf-8")
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

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "invalid")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_skips_window_external_invalid_rollout_summary_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("{bad json\n", encoding="utf-8")
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

    def test_make_shards_skips_exact_timestamp_invalid_rollout_outside_subday_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-bad.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("{bad json\n", encoding="utf-8")
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T11:00:00Z", "end": "2026-05-01T12:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = list((output / "shards.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

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

    def test_make_shards_requires_bounded_manifest_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "22" / "rollout-2026-05-22T10-00-00-ready.jsonl"
            write_jsonl(rollout, [message("user", "Shard task.", "2026-05-22T10:00:00Z")])
            output = safe_output_dir(raw)
            for window in (
                {},
                {"start": "2026-05-01T00:00:00Z"},
                {"end": "2026-06-01T00:00:00Z"},
            ):
                manifest = Path(raw) / f"manifest-{len(window)}.json"
                manifest.write_text(
                    json.dumps({"sources": [{"host": "local", "root": str(root), "status": "ready"}], "window": window}),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(SystemExit, "requires bounded start and end"):
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
            home = Path(raw) / "home"
            root = home / ".codex"
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

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(rows[0]["status"], "invalid")
        self.assertIn("coverage_gap", rows[0])

    def test_active_mtime_rollout_without_record_timestamps_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            root = home / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "01" / "02" / "rollout-undated-active.jsonl"
            write_jsonl(rollout, [untimestamped_message("user", "Fix the failed deployment.")])
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))
            output = safe_output_dir(raw)

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-01T12:00:00Z")
        self.assertIn("failed_command", rows[0]["issue_flags"])

    def test_make_shards_includes_active_mtime_rollout_without_record_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            root = home / ".codex"
            rollout = root / "sessions" / "2026" / "01" / "02" / "rollout-undated-active.jsonl"
            write_jsonl(rollout, [untimestamped_message("user", "Fix the failed deployment.")])
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ready")

    def test_active_mtime_rollout_with_mixed_record_timestamps_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            root = home / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "01" / "02" / "rollout-mixed-active.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Fix the deployment issue.", "2026-01-02T10:00:00Z"),
                    untimestamped_message("assistant", "The verification command failed with exit code 1."),
                ],
            )
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))
            output = safe_output_dir(raw)

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-01T12:00:00Z")
        self.assertIn("failed_command", rows[0]["issue_flags"])

    def test_make_shards_includes_active_mtime_rollout_with_mixed_record_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            root = home / ".codex"
            rollout = root / "sessions" / "2026" / "01" / "02" / "rollout-mixed-active.jsonl"
            write_jsonl(
                rollout,
                [
                    message("user", "Fix the deployment issue.", "2026-01-02T10:00:00Z"),
                    untimestamped_message("assistant", "The verification command failed with exit code 1."),
                ],
            )
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output)])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ready")

    def test_copied_rollout_source_does_not_use_local_mtime_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "copied-local"
            rollout = root / "sessions" / "2026" / "01" / "02" / "rollout-copied-active.jsonl"
            write_jsonl(rollout, [untimestamped_message("user", "Fix the failed deployment.")])
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(rows, [])

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
            rootless.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-06-01T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )

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

    def test_safe_state_path_expands_tilde_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                state = MODULE.safe_state_path("~/.codex-local/session-retrospective/state.json")

        self.assertEqual(state, home / ".codex-local" / "session-retrospective" / "state.json")

    def test_scan_output_expands_tilde_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            root = Path(raw) / "source"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                MODULE.run_scan(
                    types.SimpleNamespace(
                        source=[f"local={root}"],
                        output="~/.codex-local/session-retrospective/out",
                        state=None,
                        max_raw_bytes=1000,
                        allow_partial_hosts=True,
                    ),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            output_exists = (home / ".codex-local" / "session-retrospective" / "out" / "turn_summaries.jsonl").exists()

        self.assertTrue(output_exists)

    def test_transient_output_rejects_symlink_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            outside = Path(raw) / "outside-cache"
            outside.mkdir()
            symlink_root = Path(raw) / ".codex-local"
            symlink_root.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(SystemExit, "symlink ancestors"):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(symlink_root / "session-retrospective" / "out"), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )

            self.assertFalse((outside / "session-retrospective" / "out").exists())

    def test_transient_output_rejects_symlink_before_safe_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            outside = Path(raw) / "outside-cache"
            outside.mkdir()
            symlink_prefix = Path(raw) / "link"
            symlink_prefix.symlink_to(outside, target_is_directory=True)
            output = symlink_prefix / ".codex-local" / "session-retrospective" / "out"

            with self.assertRaisesRegex(SystemExit, "symlink ancestors"):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )

            self.assertFalse((outside / ".codex-local" / "session-retrospective" / "out").exists())

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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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
            home = Path(raw) / "home"
            root = home / ".codex"
            write_local_evidence(root)
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-active-oversized " + ("x" * 2000), encoding="utf-8")
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(old_large, (active_mtime, active_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
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

    def test_old_file_relevance_prefilters_handle_unreadable_timestamp_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_rollout = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old.jsonl"
            old_summary = root / "sessions" / "2026" / "01" / "02" / "rollout-summary-old.jsonl"
            write_jsonl(old_rollout, [message("user", "Old task.", "2026-01-02T10:00:00Z")])
            write_jsonl(old_summary, [{"kind": "summary", "timestamp": "2026-01-02T10:00:00Z", "text": "Old summary."}])
            start = MODULE.parse_time("2026-05-01T00:00:00Z")
            end = MODULE.parse_time("2026-05-02T00:00:00Z")

            with mock.patch.object(MODULE, "raw_timestamp_in_window", side_effect=PermissionError("blocked")):
                self.assertTrue(
                    MODULE.rollout_candidate_relevant(
                        old_rollout,
                        start,
                        end,
                        max_raw_bytes=1000,
                    )
                )
                self.assertFalse(
                    MODULE.summary_file_relevant_with_scan_cap(
                        old_summary,
                        start,
                        end,
                        max_scan_bytes=1000,
                    )
                )
                self.assertFalse(MODULE.summary_file_relevant(old_summary, start, end))

    def test_old_oversized_rollout_relevance_uses_bounded_timestamp_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            old_large = root / "sessions" / "2026" / "01" / "02" / "rollout-2026-01-02T10-00-00-old-large.jsonl"
            old_large.parent.mkdir(parents=True, exist_ok=True)
            old_large.write_text("not-json-but-old-oversized " + ("x" * 2000), encoding="utf-8")

            with mock.patch.object(MODULE, "oversized_rollout_has_timestamp_in_window", return_value=(False, False)) as scan:
                relevance = MODULE.oversized_rollout_relevance(
                    old_large,
                    MODULE.parse_time("2026-05-01T00:00:00Z"),
                    MODULE.parse_time("2026-05-02T00:00:00Z"),
                )

        self.assertEqual(relevance, "unknown")
        self.assertEqual(scan.call_args.kwargs["max_scan_bytes"], MODULE.ROLLOUT_TIMESTAMP_SCAN_BYTES)

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

    def test_complete_rollout_summary_covers_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size),
                    {"kind": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "text": "session_id=s1"},
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertIn("user_correction", rows[0]["issue_flags"])
        self.assertNotIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_complete_rollout_summary_without_retained_flags_does_not_cover_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size),
                    {"kind": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "text": "session_id=s1"},
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Ordinary assistant update without retained flags.",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_complete_summary_extracts_when_backing_ref_is_relevant_but_summary_path_is_late(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=rollout_ref, source_bytes=rollout.stat().st_size),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertIn("user_correction", rows[0]["issue_flags"])
        self.assertNotIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_complete_summary_extracts_untimestamped_record_when_backing_ref_is_relevant_but_summary_path_is_late(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(untimestamped_message("user", "Fresh oversized task."))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=rollout_ref, source_bytes=rollout.stat().st_size),
                    {
                        "kind": "user_message",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-01T10:00:00Z")
        self.assertIn("user_correction", rows[0]["issue_flags"])
        self.assertNotIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_late_summary_without_scan_meta_uses_record_backing_ref_for_relevance(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "user_message",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-01T10:00:00Z")
        self.assertIn("user_correction", rows[0]["issue_flags"])

    def test_complete_summary_extracts_when_late_path_backs_old_rollout_with_current_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Old oversized task.", "2026-01-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertIn("user_correction", rows[0]["issue_flags"])
        self.assertNotIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_complete_rollout_summary_covers_flat_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "rollout-2026-05-01T10-00-00-flat.jsonl"
            rollout = root / rollout_ref
            rollout.write_text(
                json.dumps(message("user", "Fresh flat oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "rollout-summary-flat.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_scan_meta_only_complete_summary_does_not_cover_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps({"type": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "payload": {"id": "s1"}})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        summary_record_count=0,
                    )
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_scan_meta_only_complete_summary_does_not_cover_old_oversized_rollout_with_current_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps({"type": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "payload": {"id": "s1"}})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        summary_record_count=0,
                    )
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_scan_meta_only_complete_summary_late_path_does_not_cover_without_records(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps({"type": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "payload": {"id": "s1"}})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        summary_record_count=0,
                    )
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_scan_meta_with_short_scan_bytes_does_not_cover_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        scan_bytes=1,
                        scan_truncated=False,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_root_scan_meta_only_complete_summary_does_not_cover_without_records(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps({"type": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "payload": {"id": "s1"}})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        summary_record_count=0,
                    )
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_stale_rollout_summary_source_bytes_does_not_cover_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size - 1),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertIn("oversized_rollout_skipped", reasons)
        self.assertIn("stale_rollout_summary", reasons)
        self.assertEqual(rows, [])

    def test_stale_rollout_summary_does_not_block_direct_raw_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-small.jsonl"
            rollout = root / rollout_ref
            write_jsonl(rollout, [message("user", "Fresh direct task.", "2026-05-01T10:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-small.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size + 1,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Stale summary text",
                    },
                ],
            )
            output = safe_output_dir(raw)
            discover_output = safe_output_dir(raw, "discover")

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            MODULE.run_discover(
                types.SimpleNamespace(source=[f"local={root}"], output=str(discover_output), allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((discover_output / "shard_manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertNotIn("Stale summary text", rows[0]["redacted_user_prompt_summary"])
        self.assertNotIn("stale_rollout_summary", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "ready")
        self.assertNotIn("stale_rollout_summary", [gap["reason"] for gap in manifest["coverage_gaps"]])

    def test_truncated_stale_summary_does_not_block_direct_raw_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-small.jsonl"
            rollout = root / rollout_ref
            write_jsonl(rollout, [message("user", "Fresh direct task.", "2026-05-01T10:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-small.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size + 1,
                        scan_truncated=True,
                        record_limit_reached=True,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Stale summary text",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertEqual(len(rows), 1)
        self.assertNotIn("Stale summary text", rows[0]["redacted_user_prompt_summary"])
        self.assertNotIn("stale_rollout_summary", reasons)
        self.assertNotIn("truncated_rollout_summary", reasons)

    def test_stale_root_rollout_summary_uses_direct_raw_rollout_when_sessions_exists(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            (root / "sessions").mkdir(parents=True, exist_ok=True)
            rollout_ref = "rollout-2026-05-01T10-00-00-small.jsonl"
            rollout = root / rollout_ref
            write_jsonl(rollout, [message("user", "Fresh root direct task.", "2026-05-01T10:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-small.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size + 1,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Stale root summary text",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            expected_source_hash = MODULE.file_source_hash(rollout)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_hash"], expected_source_hash)
        self.assertNotIn("Stale root summary text", rows[0]["redacted_user_prompt_summary"])
        self.assertNotIn("stale_rollout_summary", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_truncated_stale_rollout_summary_does_not_extract_summary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        source_bytes=rollout.stat().st_size - 1,
                        scan_truncated=True,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertIn("oversized_rollout_skipped", reasons)
        self.assertIn("stale_rollout_summary", reasons)
        self.assertIn("truncated_rollout_summary", reasons)
        self.assertEqual(rows, [])

    def test_json_error_rollout_summary_does_not_cover_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + "{not json"
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(json_error_count=1),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_record_limited_rollout_summary_does_not_cover_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        matched_record_limit_reached=True,
                        record_limit_reached=True,
                        summary_limit=1,
                        text=(
                            "scan_truncated=false keyword_filter_applied=false record_limit_reached=true "
                            "signal_record_limit_reached=false matched_record_limit_reached=true "
                            "tail_record_limit_reached=false scan_bytes=2097152 summary_limit=1 "
                            "tail_records=8 summary_record_count=1 source_bytes=1200"
                        ),
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
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

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertIn("oversized_rollout_skipped", reasons)
        self.assertIn("truncated_rollout_summary", reasons)

    def test_truncated_rollout_summary_does_not_cover_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=1000 source_bytes=3000",
                        "scan_truncated": True,
                    },
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
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

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertIn("oversized_rollout_skipped", reasons)
        self.assertIn("truncated_rollout_summary", reasons)

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

    def test_validate_retained_rejects_unknown_schema_versions(self) -> None:
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
            bad_trend = export_retained(output, raw, "bad-trend-schema")
            trend = json.loads((bad_trend / "trend_report.json").read_text(encoding="utf-8"))
            trend["schema_version"] = 2
            (bad_trend / "trend_report.json").write_text(json.dumps(trend) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "schema_version must be 1"):
                MODULE.main(["validate-retained", "--run-dir", str(bad_trend)])

            bad_manifest = export_retained(output, raw, "bad-manifest-schema")
            manifest = json.loads((bad_manifest / "retained_manifest.json").read_text(encoding="utf-8"))
            manifest["schema_version"] = 2
            (bad_manifest / "retained_manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "schema_version must be 1"):
                MODULE.main(["validate-retained", "--run-dir", str(bad_manifest)])

    def test_validate_retained_rejects_non_integer_schema_versions(self) -> None:
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
        }
        manifest = manifest_fixture()
        for bad_value in (True, "1", 2):
            with self.subTest(bad_value=bad_value):
                bad_trend = dict(trend, schema_version=bad_value)
                bad_manifest = dict(manifest, schema_version=bad_value)
                with self.assertRaisesRegex(SystemExit, "schema_version must be 1"):
                    MODULE.sanitize_trend_report(bad_trend, label="trend", strict=True)
                with self.assertRaisesRegex(SystemExit, "schema_version must be 1"):
                    MODULE.sanitize_retained_manifest_obj(bad_manifest, label="manifest", strict=True)
                bad_policy_manifest = dict(manifest, redaction_policy_version=bad_value)
                with self.assertRaisesRegex(SystemExit, "redaction_policy_version must be 1"):
                    MODULE.sanitize_retained_manifest_obj(bad_policy_manifest, label="manifest", strict=True)

    def test_validate_retained_rejects_cross_file_inconsistency(self) -> None:
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
            bad_trend = export_retained(output, raw, "bad-trend-consistency")
            trend = json.loads((bad_trend / "trend_report.json").read_text(encoding="utf-8"))
            trend["flags"] = {}
            (bad_trend / "trend_report.json").write_text(json.dumps(trend) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "flags must match turn_flags"):
                MODULE.main(["validate-retained", "--run-dir", str(bad_trend)])

            bad_episode = export_retained(output, raw, "bad-episode-consistency")
            episodes = [json.loads(line) for line in (bad_episode / "episodes.jsonl").read_text(encoding="utf-8").splitlines()]
            episodes[0]["friction_flags"] = []
            write_jsonl(bad_episode / "episodes.jsonl", episodes)

            with self.assertRaisesRegex(SystemExit, "episode friction_flags must match"):
                MODULE.main(["validate-retained", "--run-dir", str(bad_episode)])

            bad_model_era = export_retained(output, raw, "bad-model-era-consistency")
            rows = [json.loads(line) for line in (bad_model_era / "turn_flags.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["model_era"] = "gpt-5.5"
            write_jsonl(bad_model_era / "turn_flags.jsonl", rows)

            with self.assertRaisesRegex(SystemExit, "model_era must match referenced episode"):
                MODULE.main(["validate-retained", "--run-dir", str(bad_model_era)])

            bad_scan = safe_output_dir(raw, "bad-scan-consistency")
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(bad_scan), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [json.loads(line) for line in (bad_scan / "turn_flags.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["model_era"] = "gpt-5.5"
            write_jsonl(bad_scan / "turn_flags.jsonl", rows)

            with self.assertRaisesRegex(SystemExit, "model_era must match referenced episode"):
                MODULE.main(["validate-output", "--run-dir", str(bad_scan)])

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

    def test_export_retained_rejects_symlink_output_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fix failed verification.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            real_parent = Path(raw) / "real-retained"
            real_parent.mkdir()
            history = Path(raw) / "history"
            history.mkdir()
            symlink_parent = history / "retained"
            symlink_parent.symlink_to(real_parent, target_is_directory=True)
            retained_output = symlink_parent / "daily"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )

            with self.assertRaisesRegex(SystemExit, "symlink ancestors"):
                MODULE.main(["export-retained", "--run-dir", str(output), "--output", str(retained_output)])
            self.assertEqual(list(real_parent.iterdir()), [])

            export_retained(output, real_parent, "daily")
            with self.assertRaisesRegex(SystemExit, "symlink ancestors"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

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

    def test_validate_retained_rejects_raw_identifiers_in_retained_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fix failed deployment.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained_output = export_retained(output, raw)
            originals = {
                name: (retained_output / name).read_text(encoding="utf-8")
                for name in MODULE.RETAINED_OUTPUT_FILES
            }
            cases = [
                ("episodes.jsonl", lambda rows: rows[0].__setitem__("topic", "rollout-2026-05-22T10-00-00-abc123.jsonl")),
                ("turn_flags.jsonl", lambda rows: rows[0].__setitem__("redacted_user_prompt_summary", "session_id=abc123-def456")),
                ("trend_report.json", lambda obj: obj["window"].__setitem__("mode", "session_id=abc123-def456")),
                ("retained_manifest.json", lambda obj: obj["window"].__setitem__("mode", "rollout-2026-05-22T10-00-00-abc123.jsonl")),
            ]

            for file_name, mutate in cases:
                with self.subTest(file_name=file_name):
                    for original_name, original_text in originals.items():
                        (retained_output / original_name).write_text(original_text, encoding="utf-8")
                    target = retained_output / file_name
                    if file_name.endswith(".jsonl"):
                        rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
                        mutate(rows)
                        write_jsonl(target, rows)
                    else:
                        obj = json.loads(target.read_text(encoding="utf-8"))
                        mutate(obj)
                        target.write_text(json.dumps(obj) + "\n", encoding="utf-8")

                    with self.assertRaisesRegex(SystemExit, "raw identifier"):
                        MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

    def test_validate_retained_rejects_mode_or_window_mismatch(self) -> None:
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
            retained_output = export_retained(output, raw)
            manifest = json.loads((retained_output / "retained_manifest.json").read_text(encoding="utf-8"))
            manifest["mode"] = "daily"
            (retained_output / "retained_manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "mode does not match"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

            retained_output = export_retained(output, raw, "history-retained-window-mismatch")
            manifest = json.loads((retained_output / "retained_manifest.json").read_text(encoding="utf-8"))
            manifest["window"]["end"] = "2026-05-09T00:00:00Z"
            (retained_output / "retained_manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "window does not match"):
                MODULE.main(["validate-retained", "--run-dir", str(retained_output)])

    def test_validate_retained_rejects_inverted_window(self) -> None:
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
            trend = json.loads((retained_output / "trend_report.json").read_text(encoding="utf-8"))
            trend["window"]["start"] = "2026-05-02T00:00:00Z"
            trend["window"]["end"] = "2026-05-01T00:00:00Z"
            (retained_output / "trend_report.json").write_text(json.dumps(trend) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "start must be before end"):
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
            history_repo, _commit = write_history_repo(raw, retained)

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

    def test_validate_history_tree_rejects_wrong_origin_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            subprocess.run(["git", "remote", "set-url", "origin", "git@github.com:Joey-Tools/not-session-retrospective-history.git"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "origin must be"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_missing_origin_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            subprocess.run(["git", "remote", "remove", "origin"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "origin must be"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_substring_spoofed_origin_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            subprocess.run(
                ["git", "remote", "set-url", "origin", f"git@github.com:Joey-Tools/codex-session-retrospective-history-fork.git"],
                cwd=history_repo,
                check=True,
            )

            with self.assertRaisesRegex(SystemExit, "origin must be"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_bare_origin_repo_string(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            subprocess.run(["git", "remote", "set-url", "origin", MODULE.EXPECTED_HISTORY_REPO], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "origin must be"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_wrong_push_origin_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            subprocess.run(
                ["git", "remote", "set-url", "--push", "origin", "git@github.com:Joey-Tools/not-session-retrospective-history.git"],
                cwd=history_repo,
                check=True,
            )

            with self.assertRaisesRegex(SystemExit, "origin must be"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_history_remote_accepts_trailing_git_slash(self) -> None:
        self.assertTrue(MODULE.history_remote_matches_expected("https://github.com/Joey-Tools/codex-session-retrospective-history.git/"))
        self.assertTrue(MODULE.history_remote_matches_expected("ssh://git@github.com/Joey-Tools/codex-session-retrospective-history.git/"))

    def test_advance_state_rejects_dirty_history_worktree_before_saving_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            retained = export_retained(output, raw)
            history_repo, commit = write_history_repo(raw, retained)
            raw_artifact = history_repo / "turn_summaries.jsonl"
            raw_artifact.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "worktree must be clean"):
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

        self.assertFalse(state.exists())

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

    def test_validate_history_commit_accepts_retained_export_subset_change(self) -> None:
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
            second_retained = Path(raw) / "history-retained-second"
            second_retained.mkdir()
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (second_retained / name).write_bytes((retained / name).read_bytes())
            trend = json.loads((second_retained / "trend_report.json").read_text(encoding="utf-8"))
            trend["coverage_gaps"] = [{"host": "local", "reason": "history_missing"}]
            (second_retained / "trend_report.json").write_text(json.dumps(trend) + "\n", encoding="utf-8")
            parent = retained_parent_for_dir(second_retained)
            (history_repo / parent / "trend_report.json").write_text((second_retained / "trend_report.json").read_text(encoding="utf-8"), encoding="utf-8")
            subprocess.run(["git", "add", f"{parent}/trend_report.json"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Update retained trend"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            MODULE.main(
                [
                    "validate-history-commit",
                    "--retained-run-dir",
                    str(second_retained),
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
            add_expected_history_origin(history_repo)
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
            target = history_repo / retained_parent_for_dir(retained)
            target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            subprocess.run(["git", "checkout", "-q", default_branch], cwd=history_repo, check=True)
            (history_repo / "README.md").write_text("# History\n\nLocal documentation update.\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Update docs"], cwd=history_repo, check=True)
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

    def test_validate_history_commit_rejects_merge_side_raw_artifact_history(self) -> None:
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
            history_repo = Path(raw) / "history-merge-raw"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            add_expected_history_origin(history_repo)
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
            raw_artifact = history_repo / "sessions" / "prompt.txt"
            raw_artifact.parent.mkdir(parents=True)
            raw_artifact.write_text("raw prompt text\n", encoding="utf-8")
            subprocess.run(["git", "add", "sessions/prompt.txt"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Accidentally add raw prompt"], cwd=history_repo, check=True)
            raw_artifact.unlink()
            subprocess.run(["git", "add", "-u", "sessions/prompt.txt"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Remove raw prompt"], cwd=history_repo, check=True)
            target = history_repo / retained_parent_for_dir(retained)
            target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            subprocess.run(["git", "checkout", "-q", default_branch], cwd=history_repo, check=True)
            subprocess.run(["git", "merge", "--no-ff", "-m", "Merge retained export", "retained-export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "merge side history is not retention-safe"):
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

    def test_validate_history_commit_rejects_merge_side_restored_export_change(self) -> None:
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
            history_repo = Path(raw) / "history-merge-restored-export"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            add_expected_history_origin(history_repo)
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
            target = history_repo / retained_parent_for_dir(retained)
            target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            manifest_path = target / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["sources"][0]["summary_count"] = manifest["sources"][0]["summary_count"] + 1
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add different retained export"], cwd=history_repo, check=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Restore retained export"], cwd=history_repo, check=True)
            subprocess.run(["git", "checkout", "-q", default_branch], cwd=history_repo, check=True)
            subprocess.run(["git", "merge", "--no-ff", "-m", "Merge retained export", "retained-export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "merge side history is not retention-safe"):
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

    def test_validate_history_commit_rejects_reachable_raw_artifact_history(self) -> None:
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
            history_repo = Path(raw) / "history-linear-raw"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            add_expected_history_origin(history_repo)
            raw_artifact = history_repo / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-raw.jsonl"
            raw_artifact.parent.mkdir(parents=True)
            raw_artifact.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "sessions"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Accidentally add raw rollout"], cwd=history_repo, check=True)
            subprocess.run(["git", "rm", "-q", "-r", "sessions"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Remove raw rollout"], cwd=history_repo, check=True)
            target = history_repo / retained_parent_for_dir(retained)
            target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "reachable history is not retention-safe"):
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

    def test_validate_history_commit_rejects_identifier_retained_export_parent(self) -> None:
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
            history_repo = Path(raw) / "history-identifier-parent"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            add_expected_history_origin(history_repo)
            target = history_repo / "customer-acme"
            target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "customer-acme"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "does not contain exactly one retained export"):
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

    def test_validate_history_commit_rejects_mode_mismatched_retained_parent(self) -> None:
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
            history_repo = Path(raw) / "history-mode-mismatch"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            add_expected_history_origin(history_repo)
            target = history_repo / "retained" / "daily"
            target.mkdir(parents=True)
            for name in MODULE.RETAINED_OUTPUT_FILES:
                (target / name).write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add retained export"], cwd=history_repo, check=True)
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=history_repo, check=True, capture_output=True, text=True).stdout.strip()

            with self.assertRaisesRegex(SystemExit, "does not match export mode"):
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

    def test_validate_history_tree_validates_legacy_data_export_consistency(self) -> None:
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
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            legacy_paths = {
                "episodes.jsonl": "data/episodes/2026/05/episodes.jsonl",
                "turn_flags.jsonl": "data/turn_flags/2026/05/turn_flags.jsonl",
                "trend_report.json": "data/trends/2026/05/trend_report.json",
                "retained_manifest.json": "data/manifests/2026/05/retained_manifest.json",
            }
            for name, relative_path in legacy_paths.items():
                target = history_repo / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((retained / name).read_bytes())
            subprocess.run(["git", "add", "data"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add legacy data export"], cwd=history_repo, check=True)

            MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

            trend_path = history_repo / legacy_paths["trend_report.json"]
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["turn_count"] = trend["turn_count"] + 1
            trend_path.write_text(json.dumps(trend) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", str(trend_path.relative_to(history_repo))], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Break legacy data export"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "turn_count must match"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_incomplete_legacy_data_export(self) -> None:
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
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            target = history_repo / "data" / "episodes" / "2026" / "05" / "episodes.jsonl"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((retained / "episodes.jsonl").read_bytes())
            subprocess.run(["git", "add", "data"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add incomplete legacy data export"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "legacy data export is incomplete"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_unexpected_retained_paths(self) -> None:
        for relative_path in (
            "reports/customer-acme/summary.md",
            "reports/baseline/90-day-windows/customer-acme.md",
            "data/episodes/customer-acme/episodes.jsonl",
            "data/episodes/2026/05/customer-acme.jsonl",
            "data/turn_flags/2026/05/session_id-rawabcdef123456.jsonl",
            "data/trends/customer-acme/trend_report.json",
            "data/trends/2026/05/customer-acme.json",
            "data/manifests/2026/05/customer-acme.json",
            "schemas/customer-acme.schema.json",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    history_repo, _commit = write_history_repo(raw)
                    artifact = history_repo / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("\n", encoding="utf-8")
                    subprocess.run(["git", "add", relative_path], cwd=history_repo, check=True)
                    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add unexpected path"], cwd=history_repo, check=True)

                    with self.assertRaisesRegex(SystemExit, "unexpected artifact"):
                        MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_internal_hostname_in_follow_on_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("Investigation mentioned jira.cisco.example but no raw URLs.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/weekly/2026/05/08.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add internal hostname"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "sensitive text"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_accepts_root_gitignore_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo = Path(raw) / "history-gitignore"
            history_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.name", "Codex Test"], cwd=history_repo, check=True)
            subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=history_repo, check=True)
            add_expected_history_origin(history_repo)
            (history_repo / ".gitignore").write_text(".codex-local/\nretained/\n*.jsonl\n", encoding="utf-8")
            subprocess.run(["git", "add", ".gitignore"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add ignore rules"], cwd=history_repo, check=True)

            MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_symlink_report_artifact(self) -> None:
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
            os.symlink("safe-summary.md", report)
            subprocess.run(["git", "add", "reports/weekly/2026/05/08.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add symlink report"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "not a regular file"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_invalid_utf8_report_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_bytes(b"\xff\n")
            subprocess.run(["git", "add", "reports/weekly/2026/05/08.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add invalid utf8 report"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "invalid UTF-8"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_private_key_in_follow_on_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text(
                "Mistaken retained text:\n-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "reports/weekly/2026/05/08.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add private key"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "sensitive text"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_pgp_private_key_in_follow_on_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text(
                "Mistaken retained text:\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nredacted\n-----END PGP PRIVATE KEY BLOCK-----\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "reports/weekly/2026/05/08.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add PGP private key"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "sensitive text"):
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

    def test_validate_history_tree_rejects_renamed_raw_report_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            raw_artifact = history_repo / "reports" / "weekly" / "raw_tool_output.md"
            raw_artifact.parent.mkdir(parents=True)
            raw_artifact.write_text("Tool stdout was copied here.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/weekly/raw_tool_output.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add renamed raw artifact"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_full_prompt_report_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            prompt_artifact = history_repo / "reports" / "weekly" / "full_prompt.md"
            prompt_artifact.parent.mkdir(parents=True)
            prompt_artifact.write_text("Summarized prompt text.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/weekly/full_prompt.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add full prompt artifact"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_plural_raw_report_artifact_names(self) -> None:
        for relative_path in (
            "reports/weekly/full_prompts.md",
            "reports/weekly/user_prompts.md",
            "reports/weekly/prompt_logs.md",
            "reports/weekly/tool_outputs.md",
            "reports/weekly/fullprompt.md",
            "reports/weekly/promptlog.md",
            "reports/weekly/rawTranscript.md",
            "reports/weekly/rawdata.md",
            "reports/weekly/rawdump.md",
            "reports/weekly/rawcopy.md",
            "reports/weekly/raw.transcript.md",
            "reports/weekly/full.prompt.md",
            "reports/weekly/tool.output.md",
            "reports/weekly/turn.summaries.jsonl",
            "reports/raw.transcripts/summary.md",
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    history_repo, _commit = write_history_repo(raw)
                    artifact = history_repo / relative_path
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("Summarized text.\n", encoding="utf-8")
                    subprocess.run(["git", "add", relative_path], cwd=history_repo, check=True)
                    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add plural raw artifact"], cwd=history_repo, check=True)

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

    def test_validate_history_tree_rejects_path_like_follow_on_report_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "daily" / "2026" / "05" / "01.md"
            report.parent.mkdir(parents=True)
            report.write_text("The failed implementation was in src/private_impl.swift.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/daily/2026/05/01.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add path-like report"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "path-like text"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_raw_rollout_filename_follow_on_report_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "daily" / "2026" / "05" / "01.md"
            report.parent.mkdir(parents=True)
            report.write_text("Investigated rollout-2026-05-22T10-00-00-abc123.jsonl.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/daily/2026/05/01.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add raw rollout report"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "raw identifier"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_raw_session_id_follow_on_report_text(self) -> None:
        for text in (
            "Matched session_id=abc123-def456 before redaction.\n",
            "Matched session_id: abc123-def456 before redaction.\n",
            '{"session_id": "abc123-def456"}\n',
        ):
            with self.subTest(text=text):
                with tempfile.TemporaryDirectory() as raw:
                    history_repo, _commit = write_history_repo(raw)
                    report = history_repo / "reports" / "daily" / "2026" / "05" / "01.md"
                    report.parent.mkdir(parents=True)
                    report.write_text(text, encoding="utf-8")
                    subprocess.run(["git", "add", "reports/daily/2026/05/01.md"], cwd=history_repo, check=True)
                    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add raw session report"], cwd=history_repo, check=True)

                    with self.assertRaisesRegex(SystemExit, "raw identifier"):
                        MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_allows_session_id_schema_property(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            schema = history_repo / "schemas" / "session-retrospective-v1.schema.json"
            schema.parent.mkdir(parents=True)
            schema.write_text(
                json.dumps({"type": "object", "properties": {"session_id": {"type": "string"}}}),
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "schemas/session-retrospective-v1.schema.json"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add schema"], cwd=history_repo, check=True)

            MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_raw_identifiers_in_allowed_text_artifacts(self) -> None:
        for relative_path, text in (
            ("README.md", "Investigated rollout-2026-05-22T10-00-00-abc123.jsonl.\n"),
            ("AGENTS.md", "Matched session_id: abc123-def456 before redaction.\n"),
            ("data/README.md", "Matched session_id=abc123-def456 before redaction.\n"),
            ("reports/README.md", "Investigated rollout-2026-05-22T10-00-00-abc123.jsonl.\n"),
        ):
            with self.subTest(relative_path=relative_path):
                with tempfile.TemporaryDirectory() as raw:
                    history_repo, _commit = write_history_repo(raw)
                    report = history_repo / relative_path
                    report.parent.mkdir(parents=True, exist_ok=True)
                    report.write_text(text, encoding="utf-8")
                    subprocess.run(["git", "add", relative_path], cwd=history_repo, check=True)
                    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add raw identifier"], cwd=history_repo, check=True)

                    with self.assertRaisesRegex(SystemExit, "raw identifier"):
                        MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_allows_schema_refs_in_follow_on_report_text(self) -> None:
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
            report = history_repo / "reports" / "daily" / "2026" / "05" / "01.md"
            report.parent.mkdir(parents=True)
            report.write_text("Schema reference `#/$defs/retained_text` stayed aligned.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/daily/2026/05/01.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add schema ref report"], cwd=history_repo, check=True)

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

    def test_validate_history_tree_rejects_sensitive_named_follow_on_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            key_artifact = history_repo / "reports" / "weekly" / "opaque_ref_key.txt"
            key_artifact.parent.mkdir(parents=True)
            key_artifact.write_text("redacted placeholder\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/weekly/opaque_ref_key.txt"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add key artifact"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "forbidden transient/raw artifact"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_bare_retrospective_key_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history_repo, _commit = write_history_repo(raw)
            report = history_repo / "reports" / "weekly" / "2026" / "05" / "08.md"
            report.parent.mkdir(parents=True)
            report.write_text("Opaque key: " + "a" * 64 + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/weekly/2026/05/08.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add key leak"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "unredacted sensitive text"):
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
            retained_parent = retained_parent_for_dir(retained)
            manifest_path = history_repo / retained_parent / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["retention_safe"] = False
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", f"{retained_parent}/retained_manifest.json"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Break retained manifest"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "retention_safe"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo)])

    def test_validate_history_tree_rejects_retained_parent_mode_mismatch(self) -> None:
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
            subprocess.run(["git", "mv", "retained/weekly", "retained/daily"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Move retained export"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "directory does not match export mode"):
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
            retained_parent = retained_parent_for_dir(retained)
            subprocess.run(["git", "rm", "-q", f"{retained_parent}/turn_flags.jsonl"], cwd=history_repo, check=True)
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
            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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

    def test_advance_state_validates_deleted_follow_on_history(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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
            raw_log.unlink()
            subprocess.run(["git", "add", "raw/tool-output.log"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Remove raw follow-on"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "history follow-on commit is not retention-safe"):
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

    def test_advance_state_validates_non_first_parent_follow_on_history(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            retained = export_retained(output, raw)
            history_repo, retained_commit = write_history_repo(raw, retained)
            subprocess.run(["git", "checkout", "-q", "-b", "unsafe-follow-on"], cwd=history_repo, check=True)
            raw_log = history_repo / "raw" / "tool-output.log"
            raw_log.parent.mkdir(parents=True)
            raw_log.write_text("raw output\n", encoding="utf-8")
            subprocess.run(["git", "add", "raw/tool-output.log"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add raw side artifact"], cwd=history_repo, check=True)
            raw_log.unlink()
            subprocess.run(["git", "add", "raw/tool-output.log"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Remove raw side artifact"], cwd=history_repo, check=True)
            subprocess.run(["git", "checkout", "-q", retained_commit], cwd=history_repo, check=True)
            subprocess.run(["git", "merge", "--no-ff", "-m", "Merge side report", "unsafe-follow-on"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "history follow-on commit is not retention-safe"):
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

    def test_advance_state_requires_history_ref_to_be_current_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, retained_commit = write_history_repo(raw, retained)
            report = history_repo / "reports" / "daily" / "2026" / "05" / "02.md"
            report.parent.mkdir(parents=True)
            report.write_text("# Daily retrospective\n\nRedacted follow-on summary.\n", encoding="utf-8")
            subprocess.run(["git", "add", "reports/daily/2026/05/02.md"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Add follow-on report"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "current history worktree HEAD"):
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
                        "--history-ref",
                        retained_commit,
                    ]
                )

    def test_advance_state_requires_retained_export_still_present_in_final_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, retained_commit = write_history_repo(raw, retained)
            subprocess.run(["git", "rm", "-r", "-q", "retained"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Remove retained export"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "does not contain the retained export"):
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

    def test_advance_state_requires_retained_export_unchanged_in_final_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            history_repo, retained_commit = write_history_repo(raw, retained)
            manifest_path = history_repo / "retained" / "daily" / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["retention_note"] = "Different retained export"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "retained/daily/retained_manifest.json"], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Modify retained export"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "content changed"):
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
            add_expected_history_origin(history_repo)
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
            add_expected_history_origin(history_repo)
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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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

    def test_advance_state_rejects_same_last_scan_at(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            remote_sources = write_default_remote_sources(raw)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Daily task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text(json.dumps({"last_scan_at": "2026-05-02T00:00:00Z"}), encoding="utf-8")

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
                MODULE.run_scan(
                    types.SimpleNamespace(source=[f"local={root}", *remote_sources], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            retained = export_retained(output, raw)

            with self.assertRaisesRegex(SystemExit, "newer scan end"):
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
            self.assertEqual(state_data["last_scan_at"], "2026-05-02T00:00:00Z")

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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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
            home = Path(raw) / "home"
            root = home / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
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

    def test_default_remote_symlink_source_root_is_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target_remote = Path(raw) / "target-remote"
            write_remote_metadata(target_remote, "miku-bot-dev")
            rollout = target_remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(rollout, [message("user", "Symlinked root task.", "2026-05-01T10:00:00Z")])
            remote = Path(raw) / "miku-bot-dev"
            remote.symlink_to(target_remote, target_is_directory=True)
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))
            gaps = MODULE.remote_evidence_gaps(
                MODULE.Source("miku-bot-dev", remote),
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )

        self.assertFalse(state.exists())
        self.assertEqual(trend["turn_count"], 0)
        self.assertEqual(gaps[0]["reason"], "source_root_symlink")
        self.assertIn("source_root_symlink", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["rollout_count"], 0)

    def test_default_remote_symlink_source_root_parent_is_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            real_parent = Path(raw) / "real-cache"
            link_parent = Path(raw) / "linked-cache"
            real_parent.mkdir()
            link_parent.symlink_to(real_parent, target_is_directory=True)
            remote = link_parent / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(rollout, [message("user", "Symlinked parent task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(trend["turn_count"], 0)
        self.assertIn("source_root_symlink", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["rollout_count"], 0)

    def test_default_remote_symlink_rollout_reports_materialization_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            target = Path(raw) / "outside.jsonl"
            write_jsonl(target, [message("user", "Symlinked remote task.", "2026-05-01T10:00:00Z")])
            rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            rollout.parent.mkdir(parents=True)
            rollout.symlink_to(target)
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1500, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")

    def test_default_remote_symlink_summary_reports_materialization_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            target = Path(raw) / "outside-summary.jsonl"
            write_jsonl(target, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-remote.jsonl"
            summary.parent.mkdir(parents=True)
            summary.symlink_to(target)
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["summary_count"], 0)

    def test_default_remote_symlink_summary_directory_reports_materialization_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            outside = Path(raw) / "outside-summaries"
            summary = outside / "rollout-summary-remote.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            unsafe_root = remote / "summaries-link"
            unsafe_root.symlink_to(outside, target_is_directory=True)
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["summary_count"], 0)

    def test_default_remote_symlink_search_roots_report_materialization_gap(self) -> None:
        for search_root_name in ("sessions", "archived_sessions"):
            with self.subTest(search_root=search_root_name):
                with tempfile.TemporaryDirectory() as raw:
                    remote = Path(raw) / "miku-bot-dev"
                    write_remote_metadata(remote, "miku-bot-dev")
                    outside = Path(raw) / "outside-sessions"
                    rollout = outside / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
                    write_jsonl(rollout, [message("user", "Unsafe search root task.", "2026-05-01T10:00:00Z")])
                    if search_root_name == "archived_sessions":
                        (remote / "sessions").mkdir(parents=True)
                    unsafe_root = remote / search_root_name
                    unsafe_root.symlink_to(outside, target_is_directory=True)
                    output = safe_output_dir(raw)
                    state = safe_output_dir(raw) / "state.json"

                    MODULE.run_scan(
                        types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                        mode="daily",
                        start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                        end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                    )
                    trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
                    rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())
                    manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))
                    state_exists = state.exists()

                self.assertFalse(state_exists)
                self.assertEqual(rows, [])
                self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
                self.assertEqual(manifest["sources"][0]["status"], "stale")

    def test_default_remote_nested_symlink_directory_reports_materialization_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            outside = Path(raw) / "outside-day"
            rollout = outside / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(rollout, [message("user", "Hidden remote task.", "2026-05-01T10:00:00Z")])
            link = remote / "sessions" / "2026" / "05" / "01"
            link.parent.mkdir(parents=True)
            link.symlink_to(outside, target_is_directory=True)
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(rows, [])
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")

    def test_partial_remote_materialization_skips_direct_scan_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            safe_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-safe.jsonl"
            write_jsonl(safe_rollout, [message("user", "Safe remote task.", "2026-05-01T10:00:00Z")])
            outside = Path(raw) / "outside.jsonl"
            write_jsonl(outside, [message("user", "Unsafe remote task.", "2026-05-01T11:00:00Z")])
            unsafe_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T11-00-00-unsafe.jsonl"
            unsafe_rollout.symlink_to(outside)
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()]
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertEqual(trend["hosts"], {})
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["rollout_count"], 1)

    def test_custom_source_unsafe_artifact_blocks_state_advancement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "custom-source"
            safe_rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-safe.jsonl"
            write_jsonl(safe_rollout, [message("user", "Safe custom task.", "2026-05-01T10:00:00Z")])
            outside = Path(raw) / "outside.jsonl"
            write_jsonl(outside, [message("user", "Unsafe custom task.", "2026-05-01T11:00:00Z")])
            unsafe_rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T11-00-00-unsafe.jsonl"
            unsafe_rollout.symlink_to(outside)
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(MODULE, "parse_sources", return_value=[MODULE.Source("custom_source", root)]):
                MODULE.run_scan(
                    types.SimpleNamespace(source=None, output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()]
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

            with self.assertRaisesRegex(SystemExit, "coverage gaps"):
                advance_state(output, state, raw)

        self.assertEqual(rows, [])
        self.assertEqual(trend["hosts"], {})
        self.assertIn("unsafe_source_artifact", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["host"], "custom_source")
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["rollout_count"], 1)

    def test_custom_source_nested_symlink_directory_blocks_state_advancement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "custom-source"
            outside = Path(raw) / "outside-day"
            rollout = outside / "rollout-2026-05-01T10-00-00-hidden.jsonl"
            write_jsonl(rollout, [message("user", "Hidden custom task.", "2026-05-01T10:00:00Z")])
            link = root / "sessions" / "2026" / "05" / "01"
            link.parent.mkdir(parents=True)
            link.symlink_to(outside, target_is_directory=True)
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.object(MODULE, "parse_sources", return_value=[MODULE.Source("custom_source", root)]):
                MODULE.run_scan(
                    types.SimpleNamespace(source=None, output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(rows, [])
        self.assertIn("unsafe_source_artifact", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["host"], "custom_source")
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["rollout_count"], 0)

    def test_discover_reports_default_remote_materialization_gaps(self) -> None:
        for filename in ("rollout-2026-05-01T10-00-00-remote.jsonl", "rollout-summary-remote.jsonl"):
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as raw:
                    remote = Path(raw) / "miku-bot-dev"
                    write_remote_metadata(remote, "miku-bot-dev")
                    target = Path(raw) / f"outside-{filename}"
                    write_jsonl(target, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
                    unsafe = remote / "sessions" / "2026" / "05" / "01" / filename
                    unsafe.parent.mkdir(parents=True)
                    unsafe.symlink_to(target)
                    output = safe_output_dir(raw)

                    MODULE.run_discover(
                        types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), allow_partial_hosts=True),
                        mode="daily",
                        start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                        end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                    )
                    manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))

                self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in manifest["coverage_gaps"]])
                self.assertEqual(manifest["sources"][0]["status"], "stale")

    def test_partial_remote_materialization_marks_source_stale_and_skips_shards(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            safe_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-safe.jsonl"
            write_jsonl(safe_rollout, [message("user", "Safe remote task.", "2026-05-01T10:00:00Z")])
            outside = Path(raw) / "outside.jsonl"
            write_jsonl(outside, [message("user", "Unsafe remote task.", "2026-05-01T11:00:00Z")])
            unsafe_rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T11-00-00-unsafe.jsonl"
            unsafe_rollout.symlink_to(outside)
            output = safe_output_dir(raw)

            MODULE.run_discover(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))
            shard_output = Path(raw) / ".codex-local" / "session-retrospective" / "shards"
            MODULE.main(["make-shards", "--manifest", str(output / "shard_manifest.json"), "--output", str(shard_output)])
            rows = [json.loads(line) for line in (shard_output / "shards.jsonl").read_text(encoding="utf-8").splitlines()]

        self.assertEqual(manifest["sources"][0]["rollout_count"], 1)
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in manifest["coverage_gaps"]])
        self.assertEqual(rows, [])

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

    def test_default_remote_metadata_may_extend_beyond_requested_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            local = Path(raw) / ".codex"
            remote = Path(raw) / "miku-bot-dev"
            write_local_evidence(local)
            write_remote_metadata(
                remote,
                "miku-bot-dev",
                window_end="2026-05-03T00:00:00Z",
                materialized_at="2026-05-03T00:00:00Z",
            )
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
                MODULE.run_scan(
                    types.SimpleNamespace(source=None, output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=False),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("stale_host", [gap["reason"] for gap in trend["coverage_gaps"]])

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

    def test_default_remote_summary_only_blocks_state_but_keeps_bounded_signal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-remote.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "miku-bot-dev")
        self.assertIn("failed_command", rows[0]["issue_flags"])
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertEqual(manifest["sources"][0]["summary_count"], 1)

    def test_discover_marks_unbacked_remote_summary_stale_before_shards(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-remote.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)
            shard_output = safe_output_dir(raw, "shards")

            MODULE.run_discover(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))
            MODULE.main(["make-shards", "--manifest", str(output / "shard_manifest.json"), "--output", str(shard_output)])
            rows = [json.loads(line) for line in (shard_output / "shards.jsonl").read_text(encoding="utf-8").splitlines()]

        self.assertEqual(manifest["sources"][0]["status"], "stale")
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in manifest["coverage_gaps"]])
        self.assertEqual(rows, [])

    def test_default_remote_ignores_irrelevant_summary_when_rollouts_cover_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            summary = remote / "sessions" / "2026" / "06" / "01" / "rollout-summary-future.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-06-01T10:00:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)
            discover_output = safe_output_dir(raw, "discover")

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            MODULE.run_discover(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(discover_output), allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((discover_output / "shard_manifest.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "ready")

    def test_default_remote_ignores_relevant_summary_when_rollouts_cover_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            rollout = remote / rollout_ref
            write_jsonl(rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied",
                    }
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_scan_meta_summary_does_not_require_backing_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "scan_truncated": False,
                        "text": "scan_truncated=false scan_bytes=1000 source_bytes=200",
                    },
                    {
                        "kind": "session_meta",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "text": "session_id=remote-session cwd_present=true",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_discover(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in manifest["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "ready")

    def test_default_remote_relevant_summary_requires_valid_backing_rollout_ref(self) -> None:
        cases = [
            {"kind": "summary", "timestamp": "2026-05-01T10:01:00Z", "text": "permission denied"},
            {
                "kind": "summary",
                "timestamp": "2026-05-01T10:01:00Z",
                "rollout": "../rollout-2026-05-01T10-00-00-remote.jsonl",
                "text": "permission denied",
            },
        ]
        for record in cases:
            with self.subTest(record=record):
                with tempfile.TemporaryDirectory() as raw:
                    remote = Path(raw) / "miku-bot-dev"
                    write_remote_metadata(remote, "miku-bot-dev")
                    rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
                    rollout = remote / rollout_ref
                    write_jsonl(rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
                    summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
                    write_jsonl(summary, [record])
                    output = safe_output_dir(raw)

                    MODULE.run_scan(
                        types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                        mode="daily",
                        start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                        end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                    )
                    trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

                self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_summary_backing_requires_materialized_window_record(self) -> None:
        cases = [
            ("empty", []),
            ("stale", [message("user", "Old remote task.", "2026-04-01T10:00:00Z")]),
        ]
        for name, rollout_rows in cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as raw:
                    remote = Path(raw) / "miku-bot-dev"
                    write_remote_metadata(remote, "miku-bot-dev")
                    rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
                    rollout = remote / rollout_ref
                    write_jsonl(rollout, rollout_rows)
                    summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
                    write_jsonl(
                        summary,
                        [
                            {
                                "kind": "summary",
                                "timestamp": "2026-05-01T10:01:00Z",
                                "rollout": rollout_ref,
                                "text": "permission denied",
                            }
                        ],
                    )
                    output = safe_output_dir(raw)
                    state = safe_output_dir(raw) / "state.json"

                    MODULE.run_scan(
                        types.SimpleNamespace(
                            source=[f"miku-bot-dev={remote}"],
                            output=str(output),
                            state=str(state),
                            max_raw_bytes=1000,
                            allow_partial_hosts=True,
                        ),
                        mode="daily",
                        start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                        end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                    )
                    trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

                self.assertFalse(state.exists())
                self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_mixed_summary_backing_requires_each_materialized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            missing_rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T11-00-00-missing.jsonl"
            rollout = remote / rollout_ref
            write_jsonl(rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "covered remote summary",
                    },
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T11:01:00Z",
                        "rollout": missing_rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
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
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_mixed_stale_summary_does_not_cover_valid_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            oversized_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-oversized.jsonl"
            stale_covered_ref = "sessions/2026/05/01/rollout-2026-05-01T11-00-00-covered.jsonl"
            oversized = remote / oversized_ref
            oversized.parent.mkdir(parents=True, exist_ok=True)
            oversized.write_text(
                json.dumps(message("user", "Oversized remote task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 5000),
                encoding="utf-8",
            )
            stale_covered = remote / stale_covered_ref
            write_jsonl(stale_covered, [message("user", "Covered remote task.", "2026-05-01T11:00:00Z")])
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=oversized_ref, source_bytes=oversized.stat().st_size),
                    complete_rollout_summary_scan_meta(rollout=stale_covered_ref, source_bytes=1),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": oversized_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T11:01:00Z",
                        "rollout": stale_covered_ref,
                        "text": "You missed verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=4000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertIn("oversized_rollout_skipped", reasons)
        self.assertNotIn("remote_source_not_materialized", reasons)

    def test_default_remote_summary_backing_ignores_out_of_window_rollout_refs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            old_missing_rollout_ref = "sessions/2026/04/01/rollout-2026-04-01T11-00-00-missing.jsonl"
            rollout = remote / rollout_ref
            write_jsonl(rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "covered remote summary",
                    },
                    {
                        "kind": "summary",
                        "timestamp": "2026-04-01T11:01:00Z",
                        "rollout": old_missing_rollout_ref,
                        "text": "old permission denied before raw materialization",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_complete_summary_covers_unknown_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-remote.jsonl"
            rollout = remote / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Old oversized task.", "2026-01-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertNotIn("remote_source_not_materialized", reasons)
        self.assertNotIn("oversized_rollout_skipped", reasons)

    def test_default_remote_complete_summary_with_rollout_scan_meta_covers_old_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-remote.jsonl"
            rollout = remote / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Old oversized task.", "2026-01-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                    ),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertNotIn("remote_source_not_materialized", reasons)
        self.assertNotIn("oversized_rollout_skipped", reasons)

    def test_default_remote_complete_summary_requires_scan_meta_for_each_backing_ref(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_a_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-a.jsonl"
            rollout_b_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-b.jsonl"
            rollout_payload = (
                json.dumps(message("user", "Old oversized task.", "2026-01-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000)
            )
            for rollout_ref in (rollout_a_ref, rollout_b_ref):
                rollout = remote / rollout_ref
                rollout.parent.mkdir(parents=True, exist_ok=True)
                rollout.write_text(rollout_payload, encoding="utf-8")
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_a_ref,
                        source_bytes=(remote / rollout_a_ref).stat().st_size,
                    ),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_b_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_complete_summary_requires_rollout_backing_ref_shape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            non_rollout_ref = "notes/rollout-2026-05-01T10-00-00-note.jsonl"
            non_rollout = remote / non_rollout_ref
            non_rollout.parent.mkdir(parents=True, exist_ok=True)
            non_rollout.write_text("not a rollout\n", encoding="utf-8")
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=non_rollout_ref, source_bytes=non_rollout.stat().st_size),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": non_rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_complete_summary_requires_materialized_backing_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=3000),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_complete_summary_covers_materialized_root_backing_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            (remote / "sessions").mkdir(parents=True)
            rollout_ref = "rollout-2026-05-01T10-00-00-root.jsonl"
            rollout = remote / rollout_ref
            rollout.write_text(
                json.dumps(message("user", "Root materialized remote task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=rollout_ref, source_bytes=rollout.stat().st_size),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "ready")

    def test_default_remote_late_summary_uses_backing_rollout_date_for_untimestamped_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            rollout = remote / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(untimestamped_message("user", "Remote oversized task."))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = remote / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=rollout_ref, source_bytes=rollout.stat().st_size),
                    {
                        "kind": "user_message",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        reasons = [gap["reason"] for gap in trend["coverage_gaps"]]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-01T10:00:00Z")
        self.assertIn("user_correction", rows[0]["issue_flags"])
        self.assertNotIn("remote_source_not_materialized", reasons)
        self.assertNotIn("oversized_rollout_skipped", reasons)

    def test_complete_summary_rejects_nested_backing_rollout_when_source_scans_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout_ref = "copied/rollout-2026-05-01T10-00-00-nested.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Nested oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "rollout-summary-nested.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=rollout_ref, source_bytes=rollout.stat().st_size),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("oversized_rollout_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_scan_meta_backing_ref_uses_exact_filename_timestamp_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-old.jsonl"
            rollout = root / rollout_ref
            write_jsonl(rollout, [message("user", "Old task.", "2026-05-01T10:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        summary_record_count=0,
                    )
                ],
            )

            self.assertFalse(
                MODULE.rollout_ref_in_window(
                    rollout_ref,
                    MODULE.parse_time("2026-05-01T11:00:00Z"),
                    MODULE.parse_time("2026-05-01T12:00:00Z"),
                )
            )
            self.assertFalse(
                MODULE.summary_file_has_relevant_backing_ref(
                    summary,
                    MODULE.parse_time("2026-05-01T11:00:00Z"),
                    MODULE.parse_time("2026-05-01T12:00:00Z"),
                    max_scan_bytes=1000,
                )
            )
            refs = MODULE.complete_summary_backing_rollout_refs(
                [summary],
                MODULE.parse_time("2026-05-01T11:00:00Z"),
                MODULE.parse_time("2026-05-01T12:00:00Z"),
                source_root=root,
                max_scan_bytes=1000,
            )

        self.assertEqual(refs, set())

    def test_default_remote_old_rollout_does_not_cover_current_summary_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            old_rollout = remote / "sessions" / "2026" / "04" / "01" / "rollout-2026-04-01T10-00-00-remote.jsonl"
            write_jsonl(old_rollout, [message("user", "Old remote task.", "2026-04-01T10:00:00Z")])
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:01:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_old_oversized_rollout_does_not_cover_current_summary_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            old_rollout = remote / "sessions" / "2026" / "04" / "01" / "rollout-2026-04-01T10-00-00-remote.jsonl"
            old_rollout.parent.mkdir(parents=True, exist_ok=True)
            old_rollout.write_text(json.dumps(message("user", "Old remote task.", "2026-04-01T10:00:00Z")) + "\n" + ("x" * 1500), encoding="utf-8")
            old_mtime = MODULE.parse_time("2026-04-01T11:00:00Z").timestamp()
            os.utime(old_rollout, (old_mtime, old_mtime))
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:01:00Z", "text": "permission denied"}])
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
        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_incremental_summary_gap_uses_emit_start(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-old.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-03T00:00:00Z"),
                emit_start=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_undated_summary_gap_uses_timestamp_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            summary = remote / "rollout-summary-undated.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-04-01T10:00:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_undated_current_summary_still_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            summary = remote / "rollout-summary-undated.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_default_remote_old_oversized_summary_relevance_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout = remote / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(rollout, [message("user", "Remote task.", "2026-05-01T10:00:00Z")])
            summary = remote / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("summary " + ("x" * 2000), encoding="utf-8")
            output = safe_output_dir(raw)

            with mock.patch.object(MODULE, "raw_timestamp_in_window", side_effect=AssertionError("unbounded scan")):
                MODULE.run_discover(
                    types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), max_raw_bytes=1000, allow_partial_hosts=True),
                    mode="daily",
                    start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                    end=MODULE.parse_time("2026-05-02T00:00:00Z"),
                )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))

        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in manifest["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "ready")

    def test_default_remote_mixed_summary_fallback_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(
                remote / rollout_ref,
                [message("user", "Remote raw task.", "2026-05-01T10:00:00Z")],
            )
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-remote.jsonl"
            write_jsonl(
                summary,
                [{"kind": "summary", "timestamp": "2026-05-01T11:00:00Z", "rollout": rollout_ref, "text": "permission denied"}],
            )
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "retained_manifest.json").read_text(encoding="utf-8"))

        self.assertFalse(state.exists())
        self.assertEqual(len(rows), 2)
        self.assertNotIn("remote_source_not_materialized", [gap["reason"] for gap in trend["coverage_gaps"]])
        self.assertEqual(manifest["sources"][0]["status"], "ready")
        self.assertEqual(manifest["sources"][0]["rollout_count"], 1)
        self.assertEqual(manifest["sources"][0]["summary_count"], 1)

    def test_make_shards_keeps_safe_shards_for_summary_fallback_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            remote = Path(raw) / "miku-bot-dev"
            write_remote_metadata(remote, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            write_jsonl(
                remote / rollout_ref,
                [message("user", "Remote raw task.", "2026-05-01T10:00:00Z")],
            )
            summary = remote / "sessions" / "2026" / "05" / "01" / "rollout-summary-remote.jsonl"
            write_jsonl(
                summary,
                [{"kind": "summary", "timestamp": "2026-05-01T11:00:00Z", "rollout": rollout_ref, "text": "permission denied"}],
            )
            output = safe_output_dir(raw)
            shard_output = safe_output_dir(raw, "shards")

            MODULE.run_discover(
                types.SimpleNamespace(source=[f"miku-bot-dev={remote}"], output=str(output), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            manifest = json.loads((output / "shard_manifest.json").read_text(encoding="utf-8"))
            MODULE.main(["make-shards", "--manifest", str(output / "shard_manifest.json"), "--output", str(shard_output)])
            rows = [json.loads(line) for line in (shard_output / "shards.jsonl").read_text(encoding="utf-8").splitlines()]

        self.assertEqual(manifest["sources"][0]["status"], "ready")
        self.assertEqual([row["status"] for row in rows], ["ready", "ready"])
        self.assertEqual([row.get("kind") for row in rows], [None, "summary"])

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

    def test_unreadable_rollout_jsonl_reports_gap_and_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Unreadable task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with blocked_path_open(rollout):
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

    def test_unreadable_rollout_summary_reports_gap_and_blocks_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "Unreadable summary"}])
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with blocked_path_open(summary):
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

    def test_exact_timestamp_invalid_rollout_before_subday_start_does_not_report_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-bad.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("{bad json\n", encoding="utf-8")
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=str(state), max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T11:00:00Z"),
                end=MODULE.parse_time("2026-05-01T12:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("invalid_jsonl", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_old_invalid_rollout_with_active_mtime_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"
            root = home / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "01" / "01" / "rollout-2026-01-01T10-00-00-bad.jsonl"
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text("{bad json\n", encoding="utf-8")
            active_mtime = MODULE.parse_time("2026-05-01T12:00:00Z").timestamp()
            os.utime(rollout, (active_mtime, active_mtime))
            output = safe_output_dir(raw)
            state = safe_output_dir(raw) / "state.json"

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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

    def test_validate_output_rejects_invalid_utf8_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            (run_dir / "turn_summaries.jsonl").write_bytes(b"\xff\n")
            write_jsonl(run_dir / "episodes.jsonl", [])
            write_jsonl(run_dir / "turn_flags.jsonl", [])
            (run_dir / "trend_report.json").write_text("{}\n", encoding="utf-8")
            (run_dir / "retained_manifest.json").write_text('{"retention_safe": true}\n', encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "invalid UTF-8"):
                MODULE.main(["validate-output", "--run-dir", str(run_dir)])

    def test_validate_output_rejects_non_object_jsonl_rows(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            (run_dir / "turn_summaries.jsonl").write_text("1\n", encoding="utf-8")
            write_jsonl(run_dir / "episodes.jsonl", [])
            write_jsonl(run_dir / "turn_flags.jsonl", [])
            (run_dir / "trend_report.json").write_text("{}\n", encoding="utf-8")
            (run_dir / "retained_manifest.json").write_text('{"retention_safe": true}\n', encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "JSONL record must be an object"):
                MODULE.main(["validate-output", "--run-dir", str(run_dir)])

    def test_validate_output_reports_missing_required_json_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "run"
            run_dir.mkdir()
            write_jsonl(run_dir / "turn_summaries.jsonl", [])
            write_jsonl(run_dir / "episodes.jsonl", [])
            write_jsonl(run_dir / "turn_flags.jsonl", [])
            (run_dir / "retained_manifest.json").write_text('{"retention_safe": true}\n', encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "missing output"):
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

    def test_validate_output_rejects_unexpected_files(self) -> None:
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
            (output / "raw-debug.jsonl").write_text('{"path": "/secret/raw-rollout.jsonl"}\n', encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "unexpected output file"):
                MODULE.main(["validate-output", "--run-dir", str(output)])

    def test_validate_output_rejects_extra_retained_jsonl_fields(self) -> None:
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
            rows = [json.loads(line) for line in (output / "episodes.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["raw_prompt"] = "please include the full original prompt"
            write_jsonl(output / "episodes.jsonl", rows)

            with self.assertRaisesRegex(SystemExit, "unexpected keys"):
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
                "turn_id": VALID_TURN_ID,
                "episode_id": VALID_EPISODE_ID,
                "host": "local",
                "session_id": VALID_SESSION_ID,
                "source_path": "path_ref_v1:0123456789abcdef",
                "source_hash": VALID_SOURCE_HASH,
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
            "turn_id": VALID_TURN_ID,
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": "customer-incident-123",
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": VALID_SOURCE_HASH,
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
            "episode_id": VALID_EPISODE_ID,
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

    def test_retained_validators_require_model_to_match_model_era(self) -> None:
        turn = {
            "turn_id": VALID_TURN_ID,
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": VALID_SESSION_ID,
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": VALID_SOURCE_HASH,
            "timestamp": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model": "gpt-5.4",
            "model_era": "gpt-5.5",
            "redacted_user_prompt_summary": "category=debug",
            "assistant_action_summary": "",
            "issue_flags": ["failed_command"],
            "prompt_improvement": None,
        }

        with self.assertRaisesRegex(SystemExit, "model must match model_era"):
            MODULE.validate_turn_flag_row(turn, label="turn")


    def test_retained_validators_reject_raw_turn_and_episode_ids(self) -> None:
        turn = {
            "turn_id": "customer-turn-123",
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": VALID_SESSION_ID,
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": VALID_SOURCE_HASH,
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
            "session_id": VALID_SESSION_ID,
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

    def test_retained_validators_reject_private_model_identifiers(self) -> None:
        turn = {
            "turn_id": VALID_TURN_ID,
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": VALID_SESSION_ID,
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": VALID_SOURCE_HASH,
            "timestamp": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model": "customer_acme_model",
            "model_era": "unknown",
            "redacted_user_prompt_summary": "category=debug",
            "assistant_action_summary": "",
            "issue_flags": ["failed_command"],
            "prompt_improvement": None,
        }

        with self.assertRaisesRegex(SystemExit, "retained model id"):
            MODULE.validate_turn_flag_row(turn, label="turn")

    def test_retained_validators_reject_private_model_eras(self) -> None:
        turn = {
            "turn_id": VALID_TURN_ID,
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": VALID_SESSION_ID,
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": VALID_SOURCE_HASH,
            "timestamp": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model": None,
            "model_era": "customer_acme_model",
            "redacted_user_prompt_summary": "category=debug",
            "assistant_action_summary": "",
            "issue_flags": ["failed_command"],
            "prompt_improvement": None,
        }
        episode = {
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": VALID_SESSION_ID,
            "start": "2026-05-22T10:00:00Z",
            "end": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model_era": "customer_acme_model",
            "topic": "category=debug",
            "turn_count": 1,
            "friction_flags": ["failed_command"],
            "outcome": "needs_review",
            "work_report_hint": None,
        }
        trend = {
            "schema_version": 1,
            "window": {"mode": "daily", "start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "turn_count": 1,
            "flagged_turn_count": 1,
            "episode_count": 1,
            "flags": {"failed_command": 1},
            "hosts": {"local": 1},
            "model_eras": {"customer_acme_model": 1},
            "coverage_gaps": [],
        }

        with self.assertRaisesRegex(SystemExit, "retained model era"):
            MODULE.validate_turn_flag_row(turn, label="turn")
        with self.assertRaisesRegex(SystemExit, "retained model era"):
            MODULE.validate_episode_row(episode, label="episode")
        with self.assertRaisesRegex(SystemExit, "retained model era"):
            MODULE.sanitize_trend_report(trend, label="trend", strict=True)

    def test_retained_validators_reject_private_flag_tokens(self) -> None:
        turn = {
            "turn_id": VALID_TURN_ID,
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": VALID_SESSION_ID,
            "source_path": "path_ref_v1:0123456789abcdef",
            "source_hash": VALID_SOURCE_HASH,
            "timestamp": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model": None,
            "model_era": "unknown",
            "redacted_user_prompt_summary": "category=debug",
            "assistant_action_summary": "",
            "issue_flags": ["customer_acme"],
            "prompt_improvement": None,
        }
        episode = {
            "episode_id": VALID_EPISODE_ID,
            "host": "local",
            "session_id": VALID_SESSION_ID,
            "start": "2026-05-22T10:00:00Z",
            "end": "2026-05-22T10:00:00Z",
            "cwd": None,
            "model_era": "unknown",
            "topic": "category=debug",
            "turn_count": 1,
            "friction_flags": ["incident_123"],
            "outcome": "customer_state",
            "work_report_hint": None,
        }
        trend = {
            "schema_version": 1,
            "window": {"mode": "daily", "start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "turn_count": 1,
            "flagged_turn_count": 1,
            "episode_count": 1,
            "flags": {"customer_acme": 1},
            "hosts": {"local": 1},
            "model_eras": {"unknown": 1},
            "coverage_gaps": [],
        }

        with self.assertRaisesRegex(SystemExit, "known flag allowlist"):
            MODULE.validate_turn_flag_row(turn, label="turn")
        with self.assertRaisesRegex(SystemExit, "known flag allowlist"):
            MODULE.validate_episode_row(episode, label="episode")
        episode["friction_flags"] = ["failed_command"]
        with self.assertRaisesRegex(SystemExit, "known outcome allowlist"):
            MODULE.validate_episode_row(episode, label="episode")
        with self.assertRaisesRegex(SystemExit, "known flag allowlist"):
            MODULE.sanitize_trend_report(trend, label="trend", strict=True)

    def test_retained_validators_reject_private_window_modes(self) -> None:
        trend = {
            "schema_version": 1,
            "window": {"mode": "baseline-customer_acme", "start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "turn_count": 0,
            "flagged_turn_count": 0,
            "episode_count": 0,
            "flags": {},
            "hosts": {},
            "model_eras": {},
            "coverage_gaps": [],
        }

        with self.assertRaisesRegex(SystemExit, "invalid retained window"):
            MODULE.sanitize_trend_report(trend, label="trend", strict=True)
        with self.assertRaisesRegex(SystemExit, "retained export mode is not supported"):
            MODULE.retained_export_parent_for_mode("baseline-customer_acme")

    def test_private_network_addresses_are_redacted_and_rejected(self) -> None:
        redacted, changed = MODULE.redact("Inspect 169.254.169.254 and fc00::1 before continuing.")

        self.assertTrue(changed)
        self.assertNotIn("169.254.169.254", redacted)
        self.assertNotIn("fc00::1", redacted)
        for text in ("169.254.169.254", "100.64.0.1", "fc00::1", "::1", "fe80::1"):
            with self.subTest(text=text):
                self.assertTrue(MODULE.contains_unredacted_sensitive_text(text))

    def test_retained_validators_reject_safety_privacy_markers(self) -> None:
        for text in ("customer data", "PII", "production", "destructive", "客户数据"):
            with self.subTest(text=text):
                self.assertTrue(MODULE.contains_unredacted_sensitive_text(text))
        with self.assertRaisesRegex(SystemExit, "unredacted sensitive"):
            MODULE.ensure_retained_safe_value("retained", {"prompt_improvement": "Mentions customer data directly."})

    def test_custom_source_host_is_bucketed_in_retained_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fresh task.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(
                    source=[f"customer-acme={root}"],
                    output=str(output),
                    state=None,
                    max_raw_bytes=1000,
                    allow_partial_hosts=True,
                ),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)

            retained_text = "\n".join(path.read_text(encoding="utf-8") for path in retained.iterdir())
            self.assertNotIn("customer-acme", retained_text)
            self.assertIn(MODULE.RETAINED_CUSTOM_SOURCE_HOST, retained_text)
            MODULE.main(["validate-retained", "--run-dir", str(retained)])
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
            MODULE.main(["validate-history-tree", "--history-repo", str(history_repo), "--history-ref", "HEAD"])

    def test_validate_history_commit_with_history_ref_requires_unchanged_export(self) -> None:
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
            retained = export_retained(output, raw)
            history_repo, retained_commit = write_history_repo(raw, retained)
            MODULE.main(
                [
                    "validate-history-commit",
                    "--retained-run-dir",
                    str(retained),
                    "--history-repo",
                    str(history_repo),
                    "--history-commit",
                    retained_commit,
                    "--history-ref",
                    "HEAD",
                ]
            )
            manifest_path = history_repo / retained_parent_for_dir(retained) / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["retention_note"] = "Different retained export"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", str(manifest_path.relative_to(history_repo))], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Modify retained export"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "content changed"):
                MODULE.main(
                    [
                        "validate-history-commit",
                        "--retained-run-dir",
                        str(retained),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        retained_commit,
                        "--history-ref",
                        "HEAD",
                    ]
                )

    def test_validate_history_commit_with_history_ref_rejects_restored_export_change(self) -> None:
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
            retained = export_retained(output, raw)
            history_repo, retained_commit = write_history_repo(raw, retained)
            parent = retained_parent_for_dir(retained)
            manifest_path = history_repo / parent / "retained_manifest.json"
            original_manifest = manifest_path.read_bytes()

            manifest = json.loads(original_manifest.decode("utf-8"))
            manifest["sources"][0]["summary_count"] = manifest["sources"][0]["summary_count"] + 1
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", str(manifest_path.relative_to(history_repo))], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Modify retained export"], cwd=history_repo, check=True)
            manifest_path.write_bytes(original_manifest)
            subprocess.run(["git", "add", str(manifest_path.relative_to(history_repo))], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Restore retained export"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "history follow-on commit is not retention-safe"):
                MODULE.main(
                    [
                        "validate-history-commit",
                        "--retained-run-dir",
                        str(retained),
                        "--history-repo",
                        str(history_repo),
                        "--history-commit",
                        retained_commit,
                        "--history-ref",
                        "HEAD",
                    ]
                )

    def test_validate_retained_rejects_raw_host_label(self) -> None:
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
            retained = export_retained(output, raw)
            episode_path = retained / "episodes.jsonl"
            episode = json.loads(episode_path.read_text(encoding="utf-8").splitlines()[0])
            episode["host"] = "customer-acme"
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "retained host label"):
                MODULE.main(["validate-retained", "--run-dir", str(retained)])

    def test_validate_retained_rejects_bare_64_hex_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Fix failed deployment.", "2026-05-01T10:00:00Z")])
            output = safe_output_dir(raw)
            MODULE.run_scan(
                types.SimpleNamespace(source=[f"local={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            retained = export_retained(output, raw)
            turn_flags_path = retained / "turn_flags.jsonl"
            row = json.loads(turn_flags_path.read_text(encoding="utf-8").splitlines()[0])
            row["prompt_improvement"] = "a" * 64
            turn_flags_path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "unredacted sensitive or path-like text"):
                MODULE.main(["validate-retained", "--run-dir", str(retained)])

    def test_validate_retained_rejects_scope_as_evidence_host(self) -> None:
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
            retained = export_retained(output, raw)
            episode_path = retained / "episodes.jsonl"
            episode = json.loads(episode_path.read_text(encoding="utf-8").splitlines()[0])
            episode["host"] = "scope"
            episode_path.write_text(json.dumps(episode) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "retained host label"):
                MODULE.main(["validate-retained", "--run-dir", str(retained)])

            retained = export_retained(output, raw, "history-retained-scope-trend")
            trend_path = retained / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["hosts"] = {"scope": 1}
            trend_path.write_text(json.dumps(trend) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "retained host label"):
                MODULE.main(["validate-retained", "--run-dir", str(retained)])

            retained = export_retained(output, raw, "history-retained-scope-source")
            manifest_path = retained / "retained_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["sources"][0]["host"] = "scope"
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "unsafe retained source token"):
                MODULE.main(["validate-retained", "--run-dir", str(retained)])

    def test_validate_history_tree_rejects_raw_host_label(self) -> None:
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
            retained = export_retained(output, raw)
            history_repo, _commit = write_history_repo(raw, retained)
            trend_path = history_repo / retained_parent_for_dir(retained) / "trend_report.json"
            trend = json.loads(trend_path.read_text(encoding="utf-8"))
            trend["hosts"] = {"customer-acme": 1}
            trend_path.write_text(json.dumps(trend) + "\n", encoding="utf-8")
            subprocess.run(["git", "add", str(trend_path.relative_to(history_repo))], cwd=history_repo, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Break retained host"], cwd=history_repo, check=True)

            with self.assertRaisesRegex(SystemExit, "retained host label"):
                MODULE.main(["validate-history-tree", "--history-repo", str(history_repo), "--history-ref", "HEAD"])

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
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
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

    def test_rollout_summary_timestamps_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-offset.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T09:00:00Z", "session_id": "s1"},
                    {"kind": "summary", "timestamp": "2026-05-22T09:30:00+01:00", "text": "permission denied"},
                ],
            )

            rows = MODULE.extract_summary_file(
                MODULE.Source("remote", root),
                summary,
                MODULE.parse_time("2026-05-22T00:00:00Z"),
                MODULE.parse_time("2026-05-23T00:00:00Z"),
            )

        self.assertEqual(rows[0].timestamp, "2026-05-22T08:30:00Z")

    def test_rollout_summary_user_message_contributes_prompt_flags_without_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=s1"},
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-22T10:01:00Z",
                        "text": "You forgot the verification step and assumed success in /customer/code.py",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-06-01T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["redacted_user_prompt_summary"], "category=remote_rollout_summary; summary_kind=user_message")
        self.assertIn("user_correction", rows[0]["issue_flags"])
        self.assertNotIn("customer", json.dumps(rows[0]))

    def test_rollout_summary_private_network_address_contributes_safety_flag(self) -> None:
        for sample in ("169.254.169.254", "100.64.0.1", "fc00::1", "::1", "fe80::1", "db01.internal"):
            with self.subTest(sample=sample):
                with tempfile.TemporaryDirectory() as raw:
                    root = Path(raw) / "remote"
                    summary = root / "rollout-summary-large.jsonl"
                    write_jsonl(
                        summary,
                        [
                            {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=s1"},
                            {"kind": "user_message", "timestamp": "2026-05-22T10:01:00Z", "text": "Investigate " + sample},
                        ],
                    )
                    output = safe_output_dir(raw)

                    MODULE.run_scan(
                        types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
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
                self.assertNotIn(sample, json.dumps(rows[0]))

    def test_rollout_summary_user_message_ignores_wrapper_only_text(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=s1"},
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-22T10:01:00Z",
                        "text": "Persistent internal Codex readonly review contract:\nRun approval and verification checks.",
                    },
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-06-01T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertEqual(trend["turn_count"], 0)

    def test_remote_probe_ignores_wrapper_only_user_message_before_signaling(self) -> None:
        record = REMOTE_PROBE._build_summary_record(
            kind="user_message",
            text="Persistent internal Codex readonly review contract:\nCheck approval, secrets, privacy, and verification.",
            line_no=1,
            timestamp="2026-05-22T10:01:00Z",
            max_text_chars=1200,
            session_id="s1",
        )

        self.assertIsNone(record)

    def test_remote_probe_keeps_normal_review_prompt_before_signaling(self) -> None:
        prompt = "Review the code changes against the base branch and report only actionable findings."

        record = REMOTE_PROBE._build_summary_record(
            kind="user_message",
            text=prompt,
            line_no=1,
            timestamp="2026-05-22T10:01:00Z",
            max_text_chars=1200,
            session_id="s1",
        )

        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["_match_text"], prompt)

    def test_remote_probe_ignores_automation_prompt_before_signaling(self) -> None:
        records = REMOTE_PROBE._summarize_rollout_records(
            lines=[
                json.dumps(
                    message(
                        "user",
                        "Run inside the dedicated worktree provisioned for this automation.\n"
                        "Check approval/auth, secrets, customer data, and verification gaps.",
                        "2026-05-22T10:01:00Z",
                    )
                )
            ],
            keywords=[],
            limit=10,
            tail_records=0,
            max_text_chars=1200,
        )

        self.assertEqual(records, [])

    def test_oversized_rollout_summary_file_reports_gap_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "05" / "22" / "rollout-summary-large.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("summary " + ("x" * 2000), encoding="utf-8")
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-06-01T00:00:00Z"),
            )
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "oversized_summary_skipped")
        self.assertNotIn("path_ref", trend["coverage_gaps"][0])

    def test_old_oversized_rollout_summary_reports_gap_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text("summary " + ("x" * 2000), encoding="utf-8")
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertEqual(trend["coverage_gaps"][0]["reason"], "oversized_summary_skipped")

    def test_old_undated_oversized_rollout_summary_reports_conservative_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-undated.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps({"kind": "summary", "timestamp": "2026-04-01T10:00:00Z", "text": "permission denied"})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("oversized_summary_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_undated_oversized_rollout_summary_with_late_current_record_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-undated.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps({"kind": "summary", "timestamp": "2026-04-01T10:00:00Z", "text": "old"})
                + "\n"
                + ("x" * 1500)
                + "\n"
                + json.dumps({"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"})
                + "\n",
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("oversized_summary_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_future_oversized_rollout_summary_with_current_record_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps({"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("oversized_summary_skipped", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_truncated_rollout_summary_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "05" / "22" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    },
                    {"kind": "summary", "timestamp": "2026-05-22T10:00:00Z", "text": "permission denied"},
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-06-01T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertIn("truncated_rollout_summary", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_old_truncated_rollout_summary_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    }
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertEqual(rows, [])
        self.assertIn("truncated_rollout_summary", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_old_undated_truncated_rollout_summary_does_not_report_current_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-undated.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    },
                    {"kind": "summary", "timestamp": "2026-04-01T10:00:00Z", "text": "permission denied"},
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("truncated_rollout_summary", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_old_truncated_rollout_summary_with_later_bad_json_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps(
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    }
                )
                + "\n{bad json\n",
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertIn("truncated_rollout_summary", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_future_truncated_rollout_summary_does_not_report_current_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-future.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    }
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("truncated_rollout_summary", [gap["reason"] for gap in trend["coverage_gaps"]])

    def test_make_shards_marks_truncated_rollout_summary_partial(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    }
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
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

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "partial")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_marks_truncated_summary_with_later_bad_json_partial(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps(
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    }
                )
                + "\n{bad json\n",
                encoding="utf-8",
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
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

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "partial")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_marks_undated_oversized_summary_with_late_current_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "rollout-summary-undated.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps({"kind": "summary", "timestamp": "2026-04-01T10:00:00Z", "text": "old"})
                + "\n"
                + ("x" * 1500)
                + "\n"
                + json.dumps({"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"})
                + "\n",
                encoding="utf-8",
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1500"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "oversized")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_marks_future_oversized_summary_with_current_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps({"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "oversized")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_uses_complete_summary_instead_of_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size),
                    {"kind": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "text": "session_id=s1"},
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "ready")

    def test_make_shards_keeps_oversized_rollout_when_complete_summary_has_no_retained_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size),
                    {"kind": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "text": "session_id=s1"},
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Ordinary assistant update without retained flags.",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertNotIn("kind", rows[0])
        self.assertEqual(rows[0]["status"], "oversized")

    def test_make_shards_complete_summary_covers_only_refs_with_retained_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_a_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-a.jsonl"
            rollout_b_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-b.jsonl"
            for rollout_ref in (rollout_a_ref, rollout_b_ref):
                rollout = root / rollout_ref
                rollout.parent.mkdir(parents=True, exist_ok=True)
                rollout.write_text(
                    json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                    + "\n"
                    + ("x" * 5000),
                    encoding="utf-8",
                )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_a_ref,
                        source_bytes=(root / rollout_a_ref).stat().st_size,
                    ),
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_b_ref,
                        source_bytes=(root / rollout_b_ref).stat().st_size,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_a_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:02:00Z",
                        "rollout": rollout_b_ref,
                        "text": "Ordinary assistant update without retained flags.",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "3000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        summary_rows = [row for row in rows if row.get("kind") == "summary"]
        oversized_rows = [row for row in rows if row.get("status") == "oversized"]
        self.assertEqual(len(summary_rows), 1)
        self.assertEqual(summary_rows[0]["status"], "ready")
        self.assertEqual(len(oversized_rows), 1)

    def test_make_shards_stale_rollout_summary_keeps_oversized_rollout_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-large.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size - 1),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        rollout_rows = [
            row
            for row in rows
            if row.get("status") == "oversized" and "rollout exceeds" in str(row.get("coverage_gap", ""))
        ]
        summary_rows = [row for row in rows if row.get("kind") == "summary"]
        self.assertEqual(len(rollout_rows), 1)
        self.assertIn("coverage_gap", rollout_rows[0])
        self.assertEqual(len(summary_rows), 1)
        self.assertEqual(summary_rows[0]["status"], "partial")
        self.assertIn("source_bytes", summary_rows[0]["coverage_gap"])

    def test_make_shards_skips_stale_summary_when_raw_rollout_ready(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-small.jsonl"
            rollout = root / rollout_ref
            write_jsonl(rollout, [message("user", "Fresh direct task.", "2026-05-01T10:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-small.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size + 1,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Stale summary text",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ready")
        self.assertEqual(rows[0]["path_ref"], MODULE.path_ref(rollout))

    def test_make_shards_skips_truncated_stale_summary_when_raw_rollout_ready(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-small.jsonl"
            rollout = root / rollout_ref
            write_jsonl(rollout, [message("user", "Fresh direct task.", "2026-05-01T10:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-small.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size + 1,
                        scan_truncated=True,
                        record_limit_reached=True,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Stale summary text",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ready")
        self.assertEqual(rows[0]["path_ref"], MODULE.path_ref(rollout))

    def test_make_shards_skips_stale_root_summary_when_raw_rollout_ready(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            (root / "sessions").mkdir(parents=True, exist_ok=True)
            rollout_ref = "rollout-2026-05-01T10-00-00-small.jsonl"
            rollout = root / rollout_ref
            write_jsonl(rollout, [message("user", "Fresh root direct task.", "2026-05-01T10:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-small.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size + 1,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "Stale summary text",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ready")
        self.assertEqual(rows[0]["path_ref"], MODULE.path_ref(rollout))

    def test_make_shards_remote_complete_summary_covers_unknown_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-remote.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Old oversized task.", "2026-01-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=rollout.stat().st_size),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "ready")

    def test_make_shards_remote_late_summary_uses_backing_rollout_date_for_untimestamped_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(untimestamped_message("user", "Remote oversized task."))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=rollout_ref, source_bytes=rollout.stat().st_size),
                    {
                        "kind": "user_message",
                        "rollout": rollout_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "ready")

    def test_make_shards_mixed_stale_summary_does_not_cover_valid_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            oversized_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-oversized.jsonl"
            stale_covered_ref = "sessions/2026/05/01/rollout-2026-05-01T11-00-00-covered.jsonl"
            oversized = root / oversized_ref
            oversized.parent.mkdir(parents=True, exist_ok=True)
            oversized.write_text(
                json.dumps(message("user", "Oversized remote task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 5000),
                encoding="utf-8",
            )
            stale_covered = root / stale_covered_ref
            write_jsonl(stale_covered, [message("user", "Covered remote task.", "2026-05-01T11:00:00Z")])
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=oversized_ref, source_bytes=oversized.stat().st_size),
                    complete_rollout_summary_scan_meta(rollout=stale_covered_ref, source_bytes=1),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": oversized_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T11:01:00Z",
                        "rollout": stale_covered_ref,
                        "text": "You missed verification for /customer/repo",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "4000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertTrue(
            any(
                row.get("status") == "oversized"
                and "rollout exceeds" in str(row.get("coverage_gap", ""))
                for row in rows
            )
        )
        self.assertFalse(any(row.get("kind") == "summary" and row.get("status") == "ready" for row in rows))

    def test_make_shards_remote_complete_summary_with_rollout_scan_meta_covers_old_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-remote.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Old oversized task.", "2026-01-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                    ),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "ready")

    def test_make_shards_late_complete_summary_with_current_record_covers_old_oversized_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-remote.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Old oversized task.", "2026-01-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                    ),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "summary")
        self.assertEqual(rows[0]["status"], "ready")

    def test_make_shards_scan_meta_only_late_summary_does_not_cover_without_records(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-remote.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps({"type": "session_meta", "timestamp": "2026-05-01T10:00:00Z", "payload": {"id": "s1"}})
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-late.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        summary_record_count=0,
                    )
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "oversized")
        self.assertIn("coverage_gap", rows[0])

    def test_make_shards_marks_summary_with_short_scan_bytes_partial(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            rollout_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-remote.jsonl"
            rollout = root / rollout_ref
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(
                json.dumps(message("user", "Oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000),
                encoding="utf-8",
            )
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_ref,
                        source_bytes=rollout.stat().st_size,
                        scan_bytes=rollout.stat().st_size - 1,
                    ),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 2)
        summary_rows = [row for row in rows if row.get("kind") == "summary"]
        oversized_rows = [row for row in rows if row.get("status") == "oversized"]
        self.assertEqual(len(summary_rows), 1)
        self.assertEqual(summary_rows[0]["status"], "partial")
        self.assertEqual(
            summary_rows[0]["coverage_gap"],
            "summary scan incomplete; regenerate complete bounded evidence before extractor handoff",
        )
        self.assertEqual(len(oversized_rows), 1)

    def test_make_shards_complete_summary_requires_scan_meta_for_each_backing_ref(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout_a_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-a.jsonl"
            rollout_b_ref = "sessions/2026/05/01/rollout-2026-05-01T10-00-00-b.jsonl"
            rollout_payload = (
                json.dumps(message("user", "Fresh oversized task.", "2026-05-01T10:00:00Z"))
                + "\n"
                + ("x" * 2000)
            )
            for rollout_ref in (rollout_a_ref, rollout_b_ref):
                rollout = root / rollout_ref
                rollout.parent.mkdir(parents=True, exist_ok=True)
                rollout.write_text(rollout_payload, encoding="utf-8")
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(
                        rollout=rollout_a_ref,
                        source_bytes=(root / rollout_a_ref).stat().st_size,
                    ),
                    {
                        "kind": "user_message",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_b_ref,
                        "text": "You forgot verification for /customer/repo",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        summary_rows = [row for row in rows if row.get("kind") == "summary"]
        oversized_rows = [row for row in rows if row.get("status") == "oversized"]
        self.assertEqual(len(summary_rows), 1)
        self.assertEqual(summary_rows[0]["status"], "partial")
        self.assertIn("source_bytes", summary_rows[0]["coverage_gap"])
        self.assertGreaterEqual(len(oversized_rows), 1)

    def test_make_shards_remote_complete_summary_requires_materialized_backing_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            rollout_ref = "sessions/2026/01/01/rollout-2026-01-01T10-00-00-remote.jsonl"
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(source_bytes=3000),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "stale")
        self.assertEqual(rows[0]["coverage_gap"], "remote_source_not_materialized")

    def test_make_shards_remote_complete_summary_rejects_invalid_backing_ref_shape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "miku-bot-dev"
            write_remote_metadata(root, "miku-bot-dev")
            non_rollout_ref = "notes/rollout-2026-05-01T10-00-00-note.jsonl"
            non_rollout = root / non_rollout_ref
            non_rollout.parent.mkdir(parents=True, exist_ok=True)
            non_rollout.write_text("not a rollout\n", encoding="utf-8")
            summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-current.jsonl"
            write_jsonl(
                summary,
                [
                    complete_rollout_summary_scan_meta(rollout=non_rollout_ref, source_bytes=non_rollout.stat().st_size),
                    {
                        "kind": "summary",
                        "timestamp": "2026-05-01T10:01:00Z",
                        "rollout": non_rollout_ref,
                        "text": "permission denied before raw materialization",
                    },
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "miku-bot-dev", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
                    }
                ),
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.main(["make-shards", "--manifest", str(manifest), "--output", str(output), "--max-raw-bytes", "1000"])
            rows = [
                json.loads(line)
                for line in (output / "shards.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "stale")
        self.assertEqual(rows[0]["coverage_gap"], "remote_source_not_materialized")

    def test_make_shards_skips_future_truncated_rollout_summary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            summary = root / "sessions" / "2026" / "06" / "01" / "rollout-summary-future.jsonl"
            write_jsonl(
                summary,
                [
                    {
                        "kind": "scan_meta",
                        "timestamp": "",
                        "text": "scan_truncated=true scan_bytes=2097152 source_bytes=3000000",
                        "scan_truncated": True,
                    }
                ],
            )
            manifest = Path(raw) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "sources": [{"host": "local", "root": str(root), "status": "ready"}],
                        "window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
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

        self.assertEqual(rows, [])

    def test_unknown_rollout_summary_kind_is_bucketed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-05-22T10:00:00Z", "text": "session_id=s1"},
                    {"kind": "acme_incident_123", "timestamp": "2026-05-22T10:01:00Z", "text": "permission denied"},
                ],
            )

            turns = MODULE.extract_summary_file(MODULE.Source("remote", root), summary, None, None)

        self.assertEqual(turns[0].redacted_user_prompt_summary, "category=remote_rollout_summary; summary_kind=other_summary")
        self.assertNotIn("acme", json.dumps(MODULE.asdict_turn(turns[0])))

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
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
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

    def test_remote_probe_redaction_only_sensitive_text_contributes_signal(self) -> None:
        samples = [
            "Contact joey@example.com",
            "Open https://internal.example/ticket",
            "Inspect /Users/hoteng/customer/repo",
            "customer_id=AcmeCorp",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "Use sk-proj-abcdefghijklmnop123456",
            "github_pat_abcdefghijklmnop1234567890",
            "AKIAABCDEFGHIJKLMNOP",
            "eyJabcdefghijkl.eyJmnopqrstuv.eyJwxyzabcdef",
            "a" * 64,
            "169.254.169.254",
            "100.64.0.1",
            "fc00::1",
            "::1",
            "fe80::1",
            "db01.internal",
            "svc.corp",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                signal = REMOTE_PROBE._safe_summary_text("user_message", sample)
                self.assertIn("secret", signal)
                self.assertNotIn(sample, signal)

    def test_remote_probe_generated_script_preserves_regex_quantifiers(self) -> None:
        script = REMOTE_PROBE._remote_python_script(
            {
                "codex_root": "/tmp/codex",
                "dates": [],
                "limit": 1,
                "max_fetch_rollout_bytes": 1,
                "session_meta_scan_bytes": 1,
                "summary_limit": 1,
                "summary_scan_bytes": 1,
                "summary_tail_records": 1,
                "summary_max_text_chars": 100,
                "summary_keywords": [],
            }
        )

        self.assertIn(r"[A-Za-z]{2,}", script)
        self.assertIn(r"[A-Za-z0-9_-]{16,}", script)
        self.assertIn("169\\\\.254", script)
        self.assertIn("fe[89abAB]", script)
        self.assertIn("internal|corp|local|lan|example|invalid|test", script)
        self.assertIn("meaningful_user_message_text", script)
        self.assertIn("Persistent internal Codex readonly review contract", script)
        self.assertIn("ROOT.lstat()", script)
        self.assertIn("Codex root is a symlink", script)
        self.assertIn('os.fdopen(fd, "rb")', script)
        self.assertIn('raw_bytes.decode("utf-8", "replace")', script)
        self.assertNotIn("(2,)", script)
        self.assertNotIn("(16,)", script)

    def test_remote_probe_generated_session_meta_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            real_root = Path(raw) / "real-codex"
            rollout = real_root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "hidden-session", "cwd": "/secret/repo"},
                    }
                ],
            )
            link_root = Path(raw) / ".codex"
            link_root.symlink_to(real_root, target_is_directory=True)
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "session-meta",
                    "codex_root": str(link_root),
                    "dates": ["2026/05/01"],
                    "limit": 10,
                    "session_meta_scan_bytes": 1024,
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Codex root is a symlink", result.stderr)
        self.assertNotIn("hidden-session", result.stdout)

    def test_remote_probe_generated_session_meta_marks_limit_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            for index in range(2):
                rollout = root / "sessions" / "2026" / "05" / "01" / f"rollout-2026-05-01T10-0{index}-00-{index}.jsonl"
                write_jsonl(
                    rollout,
                    [
                        {
                            "type": "session_meta",
                            "timestamp": f"2026-05-01T10:0{index}:00Z",
                            "payload": {"id": f"session-{index}", "cwd": "/redacted/repo"},
                        }
                    ],
                )
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "session-meta",
                    "codex_root": str(root),
                    "dates": ["2026/05/01"],
                    "limit": 1,
                    "session_meta_scan_bytes": 1024,
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn(REMOTE_PROBE.SESSION_META_LIMIT_TRUNCATED_REASON, result.stdout)
        self.assertIn('"kind":"truncation"', result.stdout)

    def test_remote_probe_generated_session_meta_filters_rollout_window_before_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            for hour in (10, 11):
                rollout = root / "sessions" / "2026" / "05" / "01" / f"rollout-2026-05-01T{hour:02d}-00-00.jsonl"
                write_jsonl(
                    rollout,
                    [
                        {
                            "type": "session_meta",
                            "timestamp": f"2026-05-01T{hour:02d}:00:00Z",
                            "payload": {"id": f"session-{hour}", "cwd": "/redacted/repo"},
                        }
                    ],
                )
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "session-meta",
                    "codex_root": str(root),
                    "dates": ["2026/05/01"],
                    "limit": 1,
                    "session_meta_scan_bytes": 1024,
                    "rollout_start": "2026-05-01T11:00:00Z",
                    "rollout_end": "2026-05-01T12:00:00Z",
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"session_id":"session-11"', result.stdout)
        self.assertNotIn("session-10", result.stdout)
        self.assertNotIn(REMOTE_PROBE.SESSION_META_LIMIT_TRUNCATED_REASON, result.stdout)

    def test_remote_probe_generated_session_meta_includes_root_rollouts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_jsonl(
                root / "rollout-2026-05-01T10-00-00-root.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "root-session", "cwd": "/redacted/repo"},
                    }
                ],
            )
            script = REMOTE_PROBE._remote_python_script(
                {
                    "mode": "session-meta",
                    "codex_root": str(root),
                    "dates": ["2026/05/01"],
                    "limit": 10,
                    "session_meta_scan_bytes": 1024,
                }
            )

            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"session_id":"root-session"', result.stdout)
        self.assertIn('"rollout":"rollout-2026-05-01T10-00-00-root.jsonl"', result.stdout)

    def test_remote_probe_generated_session_meta_filters_rollout_filename_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "session-known", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-undated.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T11:00:00Z",
                        "payload": {"id": "session-unknown", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01-date-only.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:30:00Z",
                        "payload": {"id": "session-date-only", "cwd": "/redacted/repo"},
                    }
                ],
            )
            write_jsonl(
                root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T99-00-00-bad.jsonl",
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T12:00:00Z",
                        "payload": {"id": "session-bad-name", "cwd": "/redacted/repo"},
                    }
                ],
            )
            base_payload = {
                "mode": "session-meta",
                "codex_root": str(root),
                "dates": ["2026/05/01"],
                "limit": 10,
                "session_meta_scan_bytes": 1024,
            }
            unknown_script = REMOTE_PROBE._remote_python_script(
                {**base_payload, "rollout_filename_mode": "unknown"}
            )
            known_script = REMOTE_PROBE._remote_python_script(
                {**base_payload, "rollout_filename_mode": "known"}
            )

            unknown_result = subprocess.run(
                [sys.executable, "-"],
                input=unknown_script,
                text=True,
                capture_output=True,
                check=False,
            )
            known_result = subprocess.run(
                [sys.executable, "-"],
                input=known_script,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(unknown_result.returncode, 0, unknown_result.stderr)
        self.assertIn("session-unknown", unknown_result.stdout)
        self.assertIn("session-date-only", unknown_result.stdout)
        self.assertIn("session-bad-name", unknown_result.stdout)
        self.assertNotIn("session-known", unknown_result.stdout)
        self.assertEqual(known_result.returncode, 0, known_result.stderr)
        self.assertIn("session-known", known_result.stdout)
        self.assertNotIn("session-unknown", known_result.stdout)
        self.assertNotIn("session-date-only", known_result.stdout)
        self.assertNotIn("session-bad-name", known_result.stdout)

    def test_remote_probe_generated_session_meta_marks_unreadable_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00.jsonl"
            write_jsonl(
                rollout,
                [
                    {
                        "type": "session_meta",
                        "timestamp": "2026-05-01T10:00:00Z",
                        "payload": {"id": "hidden-session", "cwd": "/secret/repo"},
                    }
                ],
            )
            os.chmod(rollout, 0)
            try:
                script = REMOTE_PROBE._remote_python_script(
                    {
                        "mode": "session-meta",
                        "codex_root": str(root),
                        "dates": ["2026/05/01"],
                        "limit": 10,
                        "session_meta_scan_bytes": 1024,
                    }
                )

                result = subprocess.run(
                    [sys.executable, "-"],
                    input=script,
                    text=True,
                    capture_output=True,
                    check=False,
                )
            finally:
                os.chmod(rollout, 0o600)

        if '"kind":"error"' not in result.stdout:
            self.skipTest("chmod(0) did not make the rollout unreadable in this environment")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"error":"rollout unreadable"', result.stdout)
        self.assertIn('"rollout":"sessions/2026/05/01/rollout-2026-05-01T10-00-00.jsonl"', result.stdout)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn(str(root), result.stderr)
        self.assertNotIn("hidden-session", result.stdout)

    def test_remote_probe_generated_session_meta_marks_unreadable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            date_dir = root / "sessions" / "2026" / "05" / "01"
            date_dir.mkdir(parents=True)
            os.chmod(date_dir, 0)
            try:
                script = REMOTE_PROBE._remote_python_script(
                    {
                        "mode": "session-meta",
                        "codex_root": str(root),
                        "dates": ["2026/05/01"],
                        "limit": 10,
                        "session_meta_scan_bytes": 1024,
                    }
                )

                result = subprocess.run(
                    [sys.executable, "-"],
                    input=script,
                    text=True,
                    capture_output=True,
                    check=False,
                )
            finally:
                os.chmod(date_dir, 0o700)

        if '"error":"session directory unreadable"' not in result.stdout:
            self.skipTest("chmod(0) did not make the session directory unreadable in this environment")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"kind":"error"', result.stdout)
        self.assertIn('"error":"session directory unreadable"', result.stdout)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn(str(root), result.stderr)

    def test_out_of_window_summary_meta_still_sets_session_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-large.jsonl"
            write_jsonl(
                summary,
                [
                    {"kind": "session_meta", "timestamp": "2026-04-30T23:59:00Z", "text": "session_id=session-from-header"},
                    {"kind": "summary", "timestamp": "2026-05-01T00:01:00Z", "text": "permission denied"},
                ],
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["session_id"], MODULE.opaque_session_id("session-from-header"))

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

            with mock.patch.object(MODULE, "local_source_is_canonical", return_value=True):
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
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

    def test_old_dated_summary_with_current_timestamp_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            write_jsonl(summary, [{"kind": "summary", "timestamp": "2026-05-01T10:00:00Z", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            rows = [
                json.loads(line)
                for line in (output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timestamp"], "2026-05-01T10:00:00Z")
        self.assertIn("failed_command", rows[0]["issue_flags"])

    def test_summary_with_invalid_timestamp_uses_path_date_for_window(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            old_summary = root / "sessions" / "2026" / "01" / "01" / "rollout-summary-old.jsonl"
            fresh_summary = root / "sessions" / "2026" / "05" / "01" / "rollout-summary-fresh.jsonl"
            write_jsonl(old_summary, [{"kind": "summary", "timestamp": "not-a-date", "text": "permission denied"}])
            write_jsonl(fresh_summary, [{"kind": "summary", "timestamp": "not-a-date", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
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

    def test_summary_without_timestamp_or_path_date_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-undated.jsonl"
            write_jsonl(summary, [{"kind": "summary", "text": "permission denied"}])
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="weekly",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-08T00:00:00Z"),
            )
            rows = list((output / "turn_summaries.jsonl").read_text(encoding="utf-8").splitlines())

        self.assertEqual(rows, [])

    def test_old_undated_invalid_rollout_summary_does_not_report_current_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "remote"
            summary = root / "rollout-summary-undated.jsonl"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                '{"kind":"summary","timestamp":"2026-04-01T10:00:00Z","text":"permission denied"\n',
                encoding="utf-8",
            )
            output = safe_output_dir(raw)

            MODULE.run_scan(
                types.SimpleNamespace(source=[f"remote={root}"], output=str(output), state=None, max_raw_bytes=1000, allow_partial_hosts=True),
                mode="daily",
                start=MODULE.parse_time("2026-05-01T00:00:00Z"),
                end=MODULE.parse_time("2026-05-02T00:00:00Z"),
            )
            trend = json.loads((output / "trend_report.json").read_text(encoding="utf-8"))

        self.assertNotIn("invalid_jsonl", [gap["reason"] for gap in trend["coverage_gaps"]])

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

    def test_english_privacy_marker_contributes_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".codex"
            write_local_evidence(root)
            rollout = root / "sessions" / "2026" / "05" / "01" / "rollout-2026-05-01T10-00-00-abc.jsonl"
            write_jsonl(rollout, [message("user", "Please check customer data and PII privacy risk.", "2026-05-01T10:00:00Z")])
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
        self.assertIsNone(MODULE.retained_model_id("customer_acme_model"))
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
            source_hash=VALID_SOURCE_HASH,
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

    def test_episode_records_order_timestamps_by_instant(self) -> None:
        base = dict(
            turn_id="t1",
            episode_id=VALID_EPISODE_ID,
            host="local",
            session_id=VALID_SESSION_ID,
            source_path="path_ref_v1:0123456789abcdef",
            source_hash=VALID_SOURCE_HASH,
            cwd=None,
            model=None,
            model_era="unknown",
            redacted_user_prompt_summary="category=debug",
            assistant_action_summary="",
            issue_flags=["verification_gap"],
            prompt_improvement=None,
        )
        later = MODULE.TurnSummary(timestamp="2026-05-22T08:45:00Z", **base)
        earlier = MODULE.TurnSummary(timestamp="2026-05-22T09:30:00+01:00", **(base | {"turn_id": "t2"}))

        episodes = MODULE.episode_records([later, earlier])

        self.assertEqual(episodes[0]["start"], "2026-05-22T08:30:00Z")
        self.assertEqual(episodes[0]["end"], "2026-05-22T08:45:00Z")


if __name__ == "__main__":
    unittest.main()
