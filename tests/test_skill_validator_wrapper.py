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
VALIDATOR_RELATIVE_PATH = Path(".system/skill-creator/scripts/quick_validate.py")


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

    def make_portable_install(self, suffix: str) -> tuple[Path, Path]:
        skills_root = self.root / suffix / "skills"
        wrapper = skills_root / "codex-skill-authoring/scripts/codex_skill_validate.py"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text(WRAPPER.read_text(encoding="utf-8"), encoding="utf-8")
        return wrapper, skills_root

    def make_symlinked_install(
        self, suffix: str
    ) -> tuple[Path, Path, Path]:
        source_skills_root = self.root / suffix / "source-checkout" / "skills"
        source_skill = source_skills_root / "codex-skill-authoring"
        source_wrapper = source_skill / "scripts/codex_skill_validate.py"
        source_wrapper.parent.mkdir(parents=True)
        source_wrapper.write_text(WRAPPER.read_text(encoding="utf-8"), encoding="utf-8")

        loaded_skills_root = self.root / suffix / "loaded-install" / "skills"
        loaded_skills_root.mkdir(parents=True)
        loaded_skill = loaded_skills_root / "codex-skill-authoring"
        loaded_skill.symlink_to(source_skill, target_is_directory=True)
        return (
            loaded_skill / "scripts/codex_skill_validate.py",
            loaded_skills_root,
            source_skills_root,
        )

    def write_success_validator(self, validator: Path, message: str) -> None:
        validator.parent.mkdir(parents=True, exist_ok=True)
        validator.write_text(f"print({message!r})\n", encoding="utf-8")

    def default_validator_environment(self, home_name: str) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("CODEX_HOME", None)
        env.pop("CODEX_SKILL_VALIDATOR", None)
        env["HOME"] = str(self.root / home_name)
        return env

    def run_discovery_wrapper(
        self,
        wrapper: Path,
        *,
        env: dict[str, str],
        explicit_validator: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(wrapper), "--no-uv"]
        if explicit_validator is not None:
            command.extend(["--validator", str(explicit_validator)])
        command.append(str(self.valid_skill))
        return subprocess.run(
            command,
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

    def test_validator_override_precedence_and_directory_rejection(self) -> None:
        wrapper, skills_root = self.make_portable_install("override-precedence")
        automatic_validator = skills_root / VALIDATOR_RELATIVE_PATH
        environment_validator = self.root / "environment-validator.py"
        explicit_validator = self.root / "explicit-validator.py"
        self.write_success_validator(automatic_validator, "automatic validator")
        self.write_success_validator(environment_validator, "environment validator")
        self.write_success_validator(explicit_validator, "explicit validator")
        env = self.default_validator_environment("override-home")
        env["CODEX_SKILL_VALIDATOR"] = str(environment_validator)

        result = self.run_discovery_wrapper(
            wrapper,
            env=env,
            explicit_validator=explicit_validator,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "explicit validator")

        result = self.run_discovery_wrapper(wrapper, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "environment validator")

        env.pop("CODEX_SKILL_VALIDATOR")
        result = self.run_discovery_wrapper(wrapper, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "automatic validator")

        explicit_directory = self.root / "explicit-validator-directory"
        explicit_directory.mkdir()
        env["CODEX_SKILL_VALIDATOR"] = str(environment_validator)
        result = self.run_discovery_wrapper(
            wrapper,
            env=env,
            explicit_validator=explicit_directory,
        )
        self.assertEqual(result.returncode, 2)

        environment_directory = self.root / "environment-validator-directory"
        environment_directory.mkdir()
        env["CODEX_SKILL_VALIDATOR"] = str(environment_directory)
        result = self.run_discovery_wrapper(wrapper, env=env)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Checked:", result.stderr)

    def test_default_validator_respects_codex_home(self) -> None:
        layouts = [
            (Path("skills") / VALIDATOR_RELATIVE_PATH, "skills layout validator"),
            (VALIDATOR_RELATIVE_PATH, "legacy layout validator"),
        ]
        for index, (relative_path, message) in enumerate(layouts):
            with self.subTest(layout=relative_path):
                codex_home = self.root / f"codex-home-layout-{index}"
                self.write_success_validator(codex_home / relative_path, message)
                env = self.default_validator_environment(f"layout-home-{index}")
                env["CODEX_HOME"] = str(codex_home)

                result = self.run_discovery_wrapper(WRAPPER, env=env)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), message)

        codex_home = self.root / "codex-home-simultaneous"
        self.write_success_validator(
            codex_home / "skills" / VALIDATOR_RELATIVE_PATH,
            "preferred skills layout validator",
        )
        self.write_success_validator(
            codex_home / VALIDATOR_RELATIVE_PATH,
            "lower priority legacy layout validator",
        )
        env = self.default_validator_environment("simultaneous-layout-home")
        env["CODEX_HOME"] = str(codex_home)

        result = self.run_discovery_wrapper(WRAPPER, env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "preferred skills layout validator")

        codex_home = self.root / "codex-home-directory-skip"
        (codex_home / "skills" / VALIDATOR_RELATIVE_PATH).mkdir(parents=True)
        self.write_success_validator(
            codex_home / VALIDATOR_RELATIVE_PATH,
            "file after directory validator",
        )
        env = self.default_validator_environment("directory-skip-home")
        env["CODEX_HOME"] = str(codex_home)

        result = self.run_discovery_wrapper(WRAPPER, env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "file after directory validator")

        codex_home = self.root / "codex-home-symlink-file"
        symlink_target = self.root / "symlink-target-validator.py"
        preferred_validator = codex_home / "skills" / VALIDATOR_RELATIVE_PATH
        self.write_success_validator(symlink_target, "symlinked regular validator")
        preferred_validator.parent.mkdir(parents=True)
        preferred_validator.symlink_to(symlink_target)
        self.write_success_validator(
            codex_home / VALIDATOR_RELATIVE_PATH,
            "lower priority file validator",
        )
        env = self.default_validator_environment("symlink-file-home")
        env["CODEX_HOME"] = str(codex_home)

        result = self.run_discovery_wrapper(WRAPPER, env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "symlinked regular validator")

    def test_symlinked_install_discovery_order(self) -> None:
        wrapper, loaded_root, _ = self.make_symlinked_install("loaded-only")
        self.write_success_validator(
            loaded_root / VALIDATOR_RELATIVE_PATH,
            "loaded-only validator",
        )
        result = self.run_discovery_wrapper(
            wrapper,
            env=self.default_validator_environment("loaded-only-home"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "loaded-only validator")

        wrapper, loaded_root, source_root = self.make_symlinked_install(
            "loaded-before-source"
        )
        self.write_success_validator(
            loaded_root / VALIDATOR_RELATIVE_PATH,
            "loaded precedence validator",
        )
        self.write_success_validator(
            source_root / VALIDATOR_RELATIVE_PATH,
            "lower priority source validator",
        )
        result = self.run_discovery_wrapper(
            wrapper,
            env=self.default_validator_environment("loaded-source-home"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "loaded precedence validator")

        wrapper, _, source_root = self.make_symlinked_install("source-fallback")
        self.write_success_validator(
            source_root / VALIDATOR_RELATIVE_PATH,
            "resolved source validator",
        )
        result = self.run_discovery_wrapper(
            wrapper,
            env=self.default_validator_environment("source-fallback-home"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "resolved source validator")

        wrapper, loaded_root, source_root = self.make_symlinked_install(
            "codex-home-first"
        )
        self.write_success_validator(
            loaded_root / VALIDATOR_RELATIVE_PATH,
            "lower priority loaded validator",
        )
        self.write_success_validator(
            source_root / VALIDATOR_RELATIVE_PATH,
            "lower priority resolved validator",
        )
        codex_home = self.root / "preferred-codex-home"
        self.write_success_validator(
            codex_home / "skills" / VALIDATOR_RELATIVE_PATH,
            "preferred CODEX_HOME validator",
        )
        env = self.default_validator_environment("codex-home-first-home")
        env["CODEX_HOME"] = str(codex_home)
        result = self.run_discovery_wrapper(wrapper, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "preferred CODEX_HOME validator")

    def test_home_fallback_requires_unset_or_empty_codex_home(self) -> None:
        for index, codex_home in enumerate((None, "")):
            with self.subTest(codex_home=codex_home):
                wrapper, _ = self.make_portable_install(f"home-fallback-{index}")
                env = self.default_validator_environment(f"fallback-home-{index}")
                if codex_home is not None:
                    env["CODEX_HOME"] = codex_home
                home_validator = (
                    Path(env["HOME"])
                    / ".codex"
                    / "skills"
                    / VALIDATOR_RELATIVE_PATH
                )
                message = f"HOME fallback validator {index}"
                self.write_success_validator(home_validator, message)

                result = self.run_discovery_wrapper(wrapper, env=env)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), message)

        wrapper, skills_root = self.make_portable_install("invalid-codex-home")
        env = self.default_validator_environment("disabled-home-fallback")
        home_validator = (
            Path(env["HOME"]) / ".codex" / "skills" / VALIDATOR_RELATIVE_PATH
        )
        self.write_success_validator(home_validator, "disabled HOME validator")
        env["CODEX_HOME"] = str(self.root / "nonempty-invalid-codex-home")

        result = self.run_discovery_wrapper(wrapper, env=env)

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("disabled HOME validator", result.stdout)
        self.assertNotIn(str(home_validator), result.stderr)
        checked_line = next(
            line for line in result.stderr.splitlines() if line.startswith("Checked: ")
        )
        checked_candidates = checked_line.removeprefix("Checked: ").split(", ")
        self.assertEqual(
            checked_candidates.count(str(skills_root / VALIDATOR_RELATIVE_PATH)),
            1,
        )

    def test_all_automatic_directory_candidates_are_rejected(self) -> None:
        wrapper, loaded_root, source_root = self.make_symlinked_install(
            "automatic-directories"
        )
        env = self.default_validator_environment("automatic-directory-home")
        home_validator = (
            Path(env["HOME"]) / ".codex" / "skills" / VALIDATOR_RELATIVE_PATH
        )
        candidates = [
            loaded_root / VALIDATOR_RELATIVE_PATH,
            source_root / VALIDATOR_RELATIVE_PATH,
            home_validator,
        ]
        for candidate in candidates:
            candidate.mkdir(parents=True)
        ancestor_validator = (
            self.root / "automatic-directories" / VALIDATOR_RELATIVE_PATH
        )
        path_validator = self.root / "automatic-directories/path-bin/quick_validate.py"
        self.write_success_validator(ancestor_validator, "ancestor scan validator")
        self.write_success_validator(path_validator, "PATH search validator")
        env["PATH"] = str(path_validator.parent) + os.pathsep + env.get("PATH", "")

        result = self.run_discovery_wrapper(wrapper, env=env)

        self.assertEqual(result.returncode, 2)
        self.assertIn("Installed skill validator not found", result.stderr)
        self.assertNotIn("ancestor scan validator", result.stdout)
        self.assertNotIn("PATH search validator", result.stdout)
        for candidate in candidates:
            self.assertIn(str(candidate), result.stderr)

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
        self.assertIn("Summary: 1/2 skills valid; 0 failed; 1 runtime errors.", result.stdout)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["summary"]["runtime_errors"], 1)
        self.assertTrue(payload["results"][1]["runtime_error"])
        self.assertIn("Traceback (most recent call last):", payload["results"][1]["stderr"])

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
        self.assertEqual(Path(capture.read_text(encoding="utf-8")).resolve(), expected_cache.resolve())
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
        self.assertEqual([attempt["mode"] for attempt in payload["results"][0]["attempts"]], ["uv"])


if __name__ == "__main__":
    unittest.main()
