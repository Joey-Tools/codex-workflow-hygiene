from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CiContractTests(unittest.TestCase):
    def test_ci_uses_the_authorized_python_minor(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertEqual(1, workflow.count('python-version: "3.13"'))
        self.assertNotIn('python-version: "3.x"', workflow)
        self.assertIn(
            'python3 -I -B -S -m venv --copies "$RUNNER_TEMP/codex-python"',
            workflow,
        )
        self.assertIn('chmod 0755 "$RUNNER_TEMP/codex-python/bin/python3"', workflow)
        self.assertIn(
            '"$RUNNER_TEMP/codex-python/bin/python3" -B -S -m unittest discover \\\n'
            "            -s tests -p test_ci_contract.py",
            workflow,
        )
        self.assertIn(
            '"$RUNNER_TEMP/codex-python/bin/python3" -B -S -m unittest discover -s tests',
            workflow,
        )
        self.assertNotIn("\n          python3 -m unittest discover -s tests", workflow)

    def test_ci_runtime_is_owner_controlled(self) -> None:
        executable = Path(sys.executable)
        metadata = executable.lstat()

        self.assertEqual((3, 13), sys.version_info[:2])
        self.assertEqual(1, sys.flags.no_site)
        self.assertEqual(1, sys.flags.dont_write_bytecode)
        self.assertTrue(executable.is_absolute())
        self.assertEqual(executable, Path(os.path.realpath(executable)))
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(os.geteuid(), metadata.st_uid)
        self.assertFalse(stat.S_IMODE(metadata.st_mode) & 0o022)
        self.assertEqual(1, metadata.st_nlink)


if __name__ == "__main__":
    unittest.main()
