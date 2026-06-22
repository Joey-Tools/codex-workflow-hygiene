from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
WRAPPER = REPO_ROOT / "skills/codex-skill-authoring/scripts/codex_skill_validate.py"


class SkillValidatorWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory(prefix="skill-validator-wrapper.")
        self.root = Path(self.tmpdir.name)
        self.validator = self.root / "quick_validate.py"
        self.validator.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                from pathlib import Path
                import sys

                if len(sys.argv) != 2:
                    print("Usage: quick_validate.py <skill_directory>")
                    raise SystemExit(2)

                skill = Path(sys.argv[1])
                if skill.name.startswith("valid"):
                    print("Skill is valid!")
                    raise SystemExit(0)
                if skill.name.startswith("verbose"):
                    print("First diagnostic line")
                    print("Second diagnostic line")
                    print("x" * 300)
                    raise SystemExit(1)
                print("Name should be hyphen-case")
                raise SystemExit(1)
                """
            ),
            encoding="utf-8",
        )
        self.validator.chmod(0o755)
        self.valid_skill = self.root / "valid-skill"
        self.invalid_skill = self.root / "invalid-skill"
        self.verbose_skill = self.root / "verbose-skill"
        self.valid_skill.mkdir()
        self.invalid_skill.mkdir()
        self.verbose_skill.mkdir()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def run_wrapper(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(WRAPPER),
                "--no-uv",
                "--validator",
                str(self.validator),
                *args,
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_single_skill_preserves_installed_validator_message(self) -> None:
        result = self.run_wrapper(str(self.valid_skill))

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "Skill is valid!")
        self.assertEqual(result.stderr, "")

    def test_multiple_skills_emit_summary_and_report(self) -> None:
        report = self.root / "report.json"

        result = self.run_wrapper(
            "--report",
            str(report),
            str(self.valid_skill),
            str(self.invalid_skill),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("PASS\t", result.stdout)
        self.assertIn("FAIL\t", result.stdout)
        self.assertIn("Summary: 1/2 skills valid; 1 failed.", result.stdout)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["total"], 2)
        self.assertEqual(payload["summary"]["passed"], 1)
        self.assertEqual(payload["summary"]["failed"], 1)
        self.assertEqual(payload["summary"]["runtime_errors"], 0)

    def test_multiple_skill_stdout_uses_compact_messages(self) -> None:
        report = self.root / "report.json"

        result = self.run_wrapper(
            "--report",
            str(report),
            str(self.valid_skill),
            str(self.verbose_skill),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL\t", result.stdout)
        self.assertIn("First diagnostic line", result.stdout)
        self.assertNotIn("Second diagnostic line", result.stdout)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertIn("Second diagnostic line", payload["results"][1]["stdout"])

    def test_missing_installed_validator_is_runtime_error(self) -> None:
        missing = self.root / "missing.py"
        result = subprocess.run(
            [
                sys.executable,
                str(WRAPPER),
                "--no-uv",
                "--validator",
                str(missing),
                str(self.valid_skill),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Installed skill validator not found", result.stderr)

    def test_uv_uses_task_scoped_cache_by_default(self) -> None:
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        capture = self.root / "uv-cache-path.txt"
        fake_uv = bin_dir / "uv"
        fake_uv.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                import subprocess
                import sys

                Path = __import__("pathlib").Path
                Path(os.environ["CAPTURE_UV_CACHE"]).write_text(
                    os.environ.get("UV_CACHE_DIR", ""), encoding="utf-8"
                )
                raise SystemExit(subprocess.run(sys.argv[5:]).returncode)
                """
            ),
            encoding="utf-8",
        )
        fake_uv.chmod(0o755)
        env = os.environ.copy()
        env["CAPTURE_UV_CACHE"] = str(capture)
        env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")

        result = subprocess.run(
            [
                sys.executable,
                str(WRAPPER),
                "--validator",
                str(self.validator),
                str(self.valid_skill),
            ],
            check=False,
            cwd=self.root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        expected_cache = self.root / ".codex-tmp/skill-validator-wrapper/uv-cache"
        self.assertEqual(result.returncode, 0)
        self.assertEqual(Path(capture.read_text(encoding="utf-8")).resolve(), expected_cache.resolve())
        self.assertTrue(expected_cache.is_dir())


if __name__ == "__main__":
    unittest.main()
