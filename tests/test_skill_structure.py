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

    def test_session_mining_caps_unbounded_candidate_lists(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(encoding="utf-8")
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")

        self.assertIn("unbounded `rg -l`", skill)
        self.assertIn("one matching path or timestamp per rollout", skill)
        self.assertIn("Count by date shard first", workflow)
        self.assertIn("candidate samples, capped", workflow)


if __name__ == "__main__":
    unittest.main()
