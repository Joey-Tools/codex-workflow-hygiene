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
                if skill.name.startswith("crash"):
                    raise RuntimeError("validator setup failed")
                if skill.name.startswith("syntax-text"):
                    print('description: "SyntaxError: still a validation message"')
                    raise SystemExit(1)
                if skill.name.startswith("uv-text"):
                    print("Failed to fetch: still a validation message")
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
        self.crash_skill = self.root / "crash-skill"
        self.syntax_text_skill = self.root / "syntax-text-skill"
        self.uv_text_skill = self.root / "uv-text-skill"
        self.valid_skill.mkdir()
        self.invalid_skill.mkdir()
        self.verbose_skill.mkdir()
        self.crash_skill.mkdir()
        self.syntax_text_skill.mkdir()
        self.uv_text_skill.mkdir()

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

    def make_symlinked_install(self) -> tuple[Path, Path, Path]:
        source_skills_root = self.root / "source-checkout" / "skills"
        source_skill = source_skills_root / "codex-skill-authoring"
        source_wrapper = source_skill / "scripts" / "codex_skill_validate.py"
        source_wrapper.parent.mkdir(parents=True)
        source_wrapper.write_text(WRAPPER.read_text(encoding="utf-8"), encoding="utf-8")

        loaded_skills_root = self.root / "loaded-install" / "skills"
        loaded_skills_root.mkdir(parents=True)
        loaded_skill = loaded_skills_root / "codex-skill-authoring"
        loaded_skill.symlink_to(source_skill, target_is_directory=True)
        invoked_wrapper = loaded_skill / "scripts" / "codex_skill_validate.py"
        return invoked_wrapper, loaded_skills_root, source_skills_root

    def write_success_validator(self, skills_root: Path, message: str) -> None:
        validator = skills_root / ".system/skill-creator/scripts/quick_validate.py"
        validator.parent.mkdir(parents=True)
        validator.write_text(
            f"print({message!r})\n",
            encoding="utf-8",
        )

    def default_validator_environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("CODEX_HOME", None)
        env.pop("CODEX_SKILL_VALIDATOR", None)
        env["HOME"] = str(self.root / "isolated-home")
        return env

    def run_default_wrapper(
        self,
        wrapper: Path,
        *,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(wrapper),
                "--no-uv",
                str(self.valid_skill),
            ],
            check=False,
            cwd=self.root,
            env=env,
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

    def test_default_validator_respects_codex_home(self) -> None:
        layouts = [
            Path("skills/.system/skill-creator/scripts/quick_validate.py"),
            Path(".system/skill-creator/scripts/quick_validate.py"),
        ]
        for index, relative_path in enumerate(layouts):
            with self.subTest(relative_path=relative_path):
                codex_home = self.root / f"codex-home-{index}"
                validator = codex_home / relative_path
                validator.parent.mkdir(parents=True)
                validator.write_text(
                    self.validator.read_text(encoding="utf-8"), encoding="utf-8"
                )
                validator.chmod(0o755)
                env = os.environ.copy()
                env["CODEX_HOME"] = str(codex_home)
                env.pop("CODEX_SKILL_VALIDATOR", None)

                result = subprocess.run(
                    [
                        sys.executable,
                        str(WRAPPER),
                        "--no-uv",
                        str(self.valid_skill),
                    ],
                    check=False,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "Skill is valid!")

    def test_default_validator_resolves_from_loaded_skill_root(self) -> None:
        skills_root = self.root / "portable-install" / "skills"
        wrapper = (
            skills_root
            / "codex-skill-authoring"
            / "scripts"
            / "codex_skill_validate.py"
        )
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text(WRAPPER.read_text(encoding="utf-8"), encoding="utf-8")
        validator = (
            skills_root / ".system" / "skill-creator" / "scripts" / "quick_validate.py"
        )
        validator.parent.mkdir(parents=True)
        validator.write_text(
            self.validator.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        validator.chmod(0o755)
        env = os.environ.copy()
        env.pop("CODEX_HOME", None)
        env.pop("CODEX_SKILL_VALIDATOR", None)

        result = subprocess.run(
            [
                sys.executable,
                str(wrapper),
                "--no-uv",
                str(self.valid_skill),
            ],
            check=False,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "Skill is valid!")

    def test_symlinked_loaded_skill_root_works_without_codex_home(self) -> None:
        wrapper, loaded_skills_root, _ = self.make_symlinked_install()
        self.write_success_validator(loaded_skills_root, "loaded validator")

        result = self.run_default_wrapper(
            wrapper,
            env=self.default_validator_environment(),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "loaded validator")

    def test_symlinked_loaded_root_precedes_resolved_source_root(self) -> None:
        wrapper, loaded_skills_root, source_skills_root = self.make_symlinked_install()
        self.write_success_validator(loaded_skills_root, "loaded validator")
        self.write_success_validator(source_skills_root, "source validator")

        result = self.run_default_wrapper(
            wrapper,
            env=self.default_validator_environment(),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "loaded validator")

    def test_codex_home_precedes_loaded_and_resolved_source_roots(self) -> None:
        wrapper, loaded_skills_root, source_skills_root = self.make_symlinked_install()
        self.write_success_validator(loaded_skills_root, "loaded validator")
        self.write_success_validator(source_skills_root, "source validator")
        codex_home = self.root / "explicit-codex-home"
        self.write_success_validator(codex_home / "skills", "CODEX_HOME validator")
        env = self.default_validator_environment()
        env["CODEX_HOME"] = str(codex_home)

        result = self.run_default_wrapper(wrapper, env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "CODEX_HOME validator")

    def test_resolved_source_root_remains_symlinked_install_fallback(self) -> None:
        wrapper, _, source_skills_root = self.make_symlinked_install()
        self.write_success_validator(source_skills_root, "source validator")

        result = self.run_default_wrapper(
            wrapper,
            env=self.default_validator_environment(),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "source validator")

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

    def test_validator_traceback_is_runtime_error(self) -> None:
        report = self.root / "report.json"

        result = self.run_wrapper(
            "--report",
            str(report),
            str(self.valid_skill),
            str(self.crash_skill),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("ERROR\t", result.stdout)
        self.assertIn(
            "Summary: 1/2 skills valid; 0 failed; 1 runtime errors.", result.stdout
        )
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["runtime_errors"], 1)
        self.assertTrue(payload["results"][1]["runtime_error"])
        self.assertIn(
            "Traceback (most recent call last):", payload["results"][1]["stderr"]
        )

    def test_validator_syntax_error_is_runtime_error(self) -> None:
        report = self.root / "report.json"
        broken_validator = self.root / "broken_validator.py"
        broken_validator.write_text("def broken(:\n", encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable,
                str(WRAPPER),
                "--no-uv",
                "--validator",
                str(broken_validator),
                "--report",
                str(report),
                str(self.valid_skill),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 2)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["runtime_errors"], 1)
        self.assertTrue(payload["results"][0]["runtime_error"])
        self.assertIn("SyntaxError:", payload["results"][0]["stderr"])

    def test_python_error_token_on_stdout_is_validation_failure(self) -> None:
        report = self.root / "report.json"

        result = self.run_wrapper("--report", str(report), str(self.syntax_text_skill))

        self.assertEqual(result.returncode, 1)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["failed"], 1)
        self.assertEqual(payload["summary"]["runtime_errors"], 0)
        self.assertFalse(payload["results"][0]["runtime_error"])

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
        self.assertEqual(
            Path(capture.read_text(encoding="utf-8")).resolve(),
            expected_cache.resolve(),
        )
        self.assertTrue(expected_cache.is_dir())

    def test_uv_setup_failure_falls_back_to_direct_python(self) -> None:
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake_uv = bin_dir / "uv"
        fake_uv.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import sys

                print("error: Request failed after 3 retries", file=sys.stderr)
                print("  Caused by: Failed to fetch: `https://pypi.org/simple/pyyaml/`", file=sys.stderr)
                raise SystemExit(2)
                """
            ),
            encoding="utf-8",
        )
        fake_uv.chmod(0o755)
        report = self.root / "report.json"
        env = os.environ.copy()
        env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")

        result = subprocess.run(
            [
                sys.executable,
                str(WRAPPER),
                "--validator",
                str(self.validator),
                "--report",
                str(report),
                str(self.valid_skill),
            ],
            check=False,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "Skill is valid!")
        payload = json.loads(report.read_text(encoding="utf-8"))
        attempts = payload["results"][0]["attempts"]
        self.assertEqual([attempt["mode"] for attempt in attempts], ["uv", "python"])
        self.assertEqual([attempt["returncode"] for attempt in attempts], [2, 0])

    def test_uv_setup_detection_ignores_validator_stdout(self) -> None:
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake_uv = bin_dir / "uv"
        fake_uv.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import subprocess
                import sys

                raise SystemExit(subprocess.run(sys.argv[5:]).returncode)
                """
            ),
            encoding="utf-8",
        )
        fake_uv.chmod(0o755)
        report = self.root / "report.json"
        env = os.environ.copy()
        env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")

        result = subprocess.run(
            [
                sys.executable,
                str(WRAPPER),
                "--validator",
                str(self.validator),
                "--report",
                str(report),
                str(self.uv_text_skill),
            ],
            check=False,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["failed"], 1)
        self.assertEqual(
            [attempt["mode"] for attempt in payload["results"][0]["attempts"]], ["uv"]
        )


if __name__ == "__main__":
    unittest.main()
