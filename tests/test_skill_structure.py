from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
LOCATOR = SKILLS / "codex-session-mining/scripts/locate_session.py"


class SkillStructureTests(unittest.TestCase):
    def test_skills_have_frontmatter(self) -> None:
        skill_files = sorted(SKILLS.glob("*/SKILL.md"))
        self.assertGreaterEqual(len(skill_files), 3)
        for path in skill_files:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"), path)
            frontmatter = text.split("---", 2)[1]
            self.assertIn("\nname:", frontmatter, path)
            self.assertIn("\ndescription:", frontmatter, path)

    def test_bounded_command_output_is_a_thin_execution_control_layer(self) -> None:
        skill_root = SKILLS / "bounded-command-output"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        contract = (skill_root / "references/command-patterns.md").read_text(
            encoding="utf-8"
        )
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        self.assertLess(len(skill.splitlines()), 90)
        self.assertLess(len(contract.splitlines()), 100)
        self.assertIn("genuinely broad, noisy, or long-running", skill)
        self.assertIn(
            "ordinary exact commands already known to be small and fast", skill
        )
        for boundary in (
            "Producer scope",
            "Runtime",
            "Retained bytes",
            "Visible output",
        ):
            self.assertIn(boundary, skill)
        self.assertIn("hard deadline", skill)
        self.assertIn("process-group cleanup", skill)
        self.assertIn("fixed ceiling across every saved", skill)
        self.assertIn("it does not enforce a byte", skill)
        self.assertIn("one monotonic deadline", contract)
        self.assertIn("returns `124`", contract)
        self.assertIn("returns `125`", contract)
        self.assertIn("prove group quiescence after the leader exits", contract)
        self.assertIn("Retained-Byte Enforcement", contract)
        self.assertIn("Post-exit size checks", contract)
        self.assertTrue(
            (skill_root / "scripts/run_process_group_deadline.py").is_file()
        )
        self.assertIn("allow_implicit_invocation: true", interface)

    def test_skill_authoring_only_adds_local_overlay_policy(self) -> None:
        skill_root = SKILLS / "codex-skill-authoring"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        self.assertLess(len(skill.splitlines()), 90)
        self.assertIn("system `$skill-creator`", skill)
        self.assertIn("Choose Placement", skill)
        self.assertIn("Choose The Instruction Layer", skill)
        self.assertIn("AGENTS.md", skill)
        self.assertIn("SKILL.md", skill)
        self.assertIn("references/", skill)
        self.assertIn("codex_skill_validate.py", skill)
        self.assertIn("approval rules can match a", skill)
        self.assertIn("stable command prefix", skill)
        self.assertIn("direct argv", skill)
        self.assertFalse((skill_root / "references/description-patterns.md").exists())
        self.assertIn("$skill-creator", interface)

    def test_session_mining_routes_locate_and_corpus_profiles(self) -> None:
        skill_root = SKILLS / "codex-session-mining"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        locate = (skill_root / "references/locate.md").read_text(encoding="utf-8")
        corpus = (skill_root / "references/corpus.md").read_text(encoding="utf-8")

        self.assertLess(len(skill.splitlines()), 100)
        self.assertLess(len(locate.splitlines()), 100)
        self.assertLess(len(corpus.splitlines()), 100)
        self.assertIn("`locate`: Exact Or Narrow Lookup", skill)
        self.assertIn("`corpus`: Complete Current-Host Evidence", skill)
        self.assertIn("scripts/locate_session.py", skill)
        self.assertIn("scripts/build_session_corpus.py", skill)
        self.assertIn("references/locate.md", skill)
        self.assertIn("references/corpus.md", skill)
        self.assertIn("checked`, `unavailable`, `partial`, or `blocked`", skill)
        self.assertIn("both existing `sessions/` and", corpus)
        self.assertIn("`archived_sessions/` roots", corpus)
        self.assertIn("replay prefix", corpus)
        self.assertIn("raw `rg -n`", locate)
        self.assertFalse((skill_root / "references/workflow.md").exists())
        self.assertTrue(LOCATOR.is_file())
        self.assertTrue(os.access(LOCATOR, os.X_OK))
        self.assertTrue((skill_root / "scripts/build_session_corpus.py").is_file())

    def test_session_retrospective_bounds_operator_output(self) -> None:
        skill = (SKILLS / "codex-session-retrospective/SKILL.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("task-scoped ignored log", skill)
        self.assertIn("progress markers", skill)
        self.assertIn("do not poll with 30k+ visible output caps", skill)
        self.assertIn("`pgrep -af`", skill)
        self.assertIn("`ps -p`", skill)
        self.assertIn("`ps -eo` / `ps -axo`", skill)
        self.assertIn("full `sample` output", skill)
        self.assertIn("one open descriptor snapshot", skill)
        self.assertIn("session-metadata record crosses its byte budget", skill)
        self.assertIn("complete normalized signal", skill)


class SessionLocatorTests(unittest.TestCase):
    def run_locator(
        self,
        codex_home: Path,
        *arguments: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = subprocess.run(
            [
                sys.executable,
                os.fspath(LOCATOR),
                "--codex-home",
                os.fspath(codex_home),
                *arguments,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        payload = json.loads(completed.stdout) if completed.stdout else {}
        return completed, payload

    def make_roots(self, codex_home: Path) -> None:
        (codex_home / "sessions/2026/07/24").mkdir(parents=True)
        (codex_home / "archived_sessions").mkdir(parents=True)

    def test_exact_id_checks_indexes_and_both_rollout_roots(self) -> None:
        session_id = "019EF067-976B-7E41-928D-80361777330B"
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / ".codex"
            self.make_roots(codex_home)
            (codex_home / "session_index.jsonl").write_text(
                json.dumps(
                    {
                        "id": session_id.lower(),
                        "thread_name": "Range-local materializer",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (codex_home / "history.jsonl").write_text(
                json.dumps({"session_id": session_id, "text": "resume review"}) + "\n",
                encoding="utf-8",
            )
            (
                codex_home
                / "sessions/2026/07/24"
                / f"rollout-2026-07-24T00-00-00-{session_id.lower()}.jsonl"
            ).write_text("{}\n", encoding="utf-8")
            (
                codex_home / "archived_sessions" / f"rollout-copy-{session_id}.jsonl"
            ).write_text("{}\n", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--session-id",
                session_id,
                "--limit",
                "5",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "checked")
        self.assertEqual(payload["total_matches"], 4)
        sources = payload["sources"]
        self.assertEqual(len(sources), 4)
        self.assertTrue(all(source["status"] == "checked" for source in sources))
        self.assertEqual(
            [source["match_count"] for source in sources],
            [1, 1, 1, 1],
        )

    def test_thread_query_scans_only_bounded_public_index_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / ".codex"
            codex_home.mkdir()
            rows = [
                {
                    "id": f"session-{index}",
                    "thread_name": f"Review helper {index}",
                    "text": "ignored",
                }
                for index in range(5)
            ]
            (codex_home / "session_index.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--thread-query",
                "review helper",
                "--limit",
                "2",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "checked")
        self.assertEqual(len(payload["sources"]), 2)
        source = payload["sources"][0]
        self.assertEqual(source["match_count"], 5)
        self.assertEqual(len(source["matches"]), 2)
        self.assertTrue(source["matches_truncated"])

    def test_malformed_and_oversized_index_records_make_coverage_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / ".codex"
            self.make_roots(codex_home)
            with (codex_home / "session_index.jsonl").open("wb") as handle:
                handle.write(b"{not-json}\n")
                handle.write(b"x" * (1024 * 1024 + 1) + b"\n")
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--session-id",
                "opaque-id",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "partial")
        source = payload["sources"][0]
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["malformed_records"], 1)
        self.assertEqual(source["oversized_records"], 1)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlinked_index_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / ".codex"
            codex_home.mkdir()
            target = codex_home / "target.jsonl"
            target.write_text(
                json.dumps({"id": "secret", "thread_name": "do not follow"}) + "\n",
                encoding="utf-8",
            )
            os.symlink(target, codex_home / "session_index.jsonl")
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--thread-query",
                "do not follow",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "partial")
        source = payload["sources"][0]
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["match_count"], 0)


if __name__ == "__main__":
    unittest.main()
