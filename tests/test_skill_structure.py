from __future__ import annotations

from pathlib import Path
import unittest


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


if __name__ == "__main__":
    unittest.main()
