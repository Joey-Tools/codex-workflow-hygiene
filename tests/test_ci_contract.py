from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CiContractTests(unittest.TestCase):
    def test_ci_uses_the_authorized_python_minor(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertEqual(1, workflow.count('python-version: "3.13"'))
        self.assertNotIn('python-version: "3.x"', workflow)
        self.assertEqual(1, workflow.count("python3 -m unittest discover -s tests"))


if __name__ == "__main__":
    unittest.main()
