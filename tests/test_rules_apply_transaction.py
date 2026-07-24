from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = (
    REPO_ROOT
    / "skills"
    / "codex-rules-hygiene"
    / "scripts"
    / "apply_rules_transaction.py"
)
OLD_RULES = b'prefix_rule(pattern=["git", "status"], decision="allow")\n'
NEW_RULES = b'prefix_rule(pattern=["git", "status", "--short"], decision="allow")\n'
LATER_RULES = b'prefix_rule(pattern=["gh", "pr", "view"], decision="allow")\n'


class RulesApplyTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory(prefix="rules-apply-transaction.")
        self.root = Path(self.tmpdir.name)
        self.codex_home = self.root / "codex-home"
        self.rules_dir = self.codex_home / "rules"
        self.rules_dir.mkdir(parents=True)
        self.rules = self.rules_dir / "default.rules"
        self.rules.write_bytes(OLD_RULES)
        self.rules.chmod(0o640)
        self.candidate = self.root / "candidate.rules"
        self.candidate.write_bytes(NEW_RULES)
        self.receipt = self.root / "task" / "recovery.json"
        self.receipt.parent.mkdir(mode=0o700)
        self.backup_name = "default.rules.bak-20260724-120000"
        self.backup = self.rules_dir / self.backup_name
        self.validator = self.root / "validator.py"

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def write_validator(self, source: str) -> None:
        self.validator.write_text(
            textwrap.dedent(source),
            encoding="utf-8",
        )

    def helper_environment(
        self,
        **updates: str,
    ) -> dict[str, str]:
        environment = os.environ.copy()
        environment["CODEX_HOME"] = str(self.codex_home)
        environment.update(updates)
        return environment

    def run_apply(
        self,
        *,
        expected_sha256: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        expected = expected_sha256 or hashlib.sha256(OLD_RULES).hexdigest()
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "apply",
                "--candidate",
                str(self.candidate),
                "--expected-sha256",
                expected,
                "--backup-name",
                self.backup_name,
                "--receipt",
                str(self.receipt),
                "--validator-timeout-seconds",
                "5",
                "--lock-timeout-seconds",
                "2",
                "--",
                sys.executable,
                str(self.validator),
                "{rules}",
            ],
            check=False,
            env=environment or self.helper_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def run_recover(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "recover",
                "--receipt",
                str(self.receipt),
                "--lock-timeout-seconds",
                "2",
            ],
            check=False,
            env=self.helper_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def test_apply_validates_private_stage_before_atomic_replace(self) -> None:
        validator_log = self.root / "validator.jsonl"
        self.write_validator(
            """\
            import json
            import os
            from pathlib import Path
            import stat
            import sys

            path = Path(sys.argv[1])
            file_mode = stat.S_IMODE(path.stat().st_mode)
            parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
            row = {
                "name": path.name,
                "file_mode": file_mode,
                "parent_mode": parent_mode,
                "content": path.read_text(encoding="utf-8"),
            }
            with Path(os.environ["VALIDATOR_LOG"]).open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write(json.dumps(row, sort_keys=True) + "\\n")
            if path.name == "candidate" and (
                file_mode != 0o600 or parent_mode != 0o700
            ):
                raise SystemExit(7)
            """
        )

        result = self.run_apply(
            environment=self.helper_environment(VALIDATOR_LOG=str(validator_log))
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "applied")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o600)
        self.assertEqual(self.rules.stat().st_dev, self.backup.stat().st_dev)
        lock = self.rules_dir / ".default.rules.apply.lock"
        self.assertTrue(lock.is_file())
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

        validator_rows = [
            json.loads(line)
            for line in validator_log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            [row["name"] for row in validator_rows], ["candidate", "default.rules"]
        )
        self.assertEqual(validator_rows[0]["file_mode"], 0o600)
        self.assertEqual(validator_rows[0]["parent_mode"], 0o700)
        self.assertEqual(validator_rows[1]["file_mode"], 0o640)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(
            receipt["rules_parent"]["identity"],
            {
                "device": self.rules_dir.stat().st_dev,
                "inode": self.rules_dir.stat().st_ino,
            },
        )

    def test_candidate_changed_by_validator_is_rejected_before_lock(self) -> None:
        self.write_validator(
            """\
            from pathlib import Path
            import sys

            path = Path(sys.argv[1])
            path.write_bytes(b"validator changed candidate\\n")
            """
        )

        result = self.run_apply()

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "private_candidate_changed")
        self.assertIn("content", payload["mismatched_properties"])
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())

    def test_expected_digest_is_revalidated_under_shared_lock(self) -> None:
        later_path = self.root / "later.rules"
        self.write_validator(
            """\
            import os
            from pathlib import Path
            import sys

            path = Path(sys.argv[1])
            if path.name == "candidate":
                live = Path(os.environ["LIVE_RULES"])
                later = Path(os.environ["LATER_RULES"])
                later.write_bytes(b'prefix_rule(pattern=["gh", "pr", "view"], decision="allow")\\n')
                later.chmod(0o640)
                os.replace(later, live)
            """
        )

        result = self.run_apply(
            environment=self.helper_environment(
                LIVE_RULES=str(self.rules),
                LATER_RULES=str(later_path),
            )
        )

        self.assertEqual(result.returncode, 20, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "expected_digest_mismatch")
        self.assertEqual(self.rules.read_bytes(), LATER_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())

    def test_post_replace_validation_failure_rolls_back_bound_original(self) -> None:
        self.write_validator(
            """\
            from pathlib import Path
            import sys

            if Path(sys.argv[1]).name == "default.rules":
                raise SystemExit(9)
            """
        )

        result = self.run_apply()

        self.assertEqual(result.returncode, 30, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "post_replace_failed_rolled_back")
        self.assertEqual(payload["rollback"]["rollback_status"], "rolled_back")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o640)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertTrue(self.receipt.is_file())

    def test_post_replace_failure_preserves_later_live_state(self) -> None:
        actions = ("replace", "content", "access", "missing")
        for action in actions:
            with (
                self.subTest(action=action),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-later-{action}."
                ) as temp_dir,
            ):
                case_root = Path(temp_dir)
                self.codex_home = case_root / "codex-home"
                self.rules_dir = self.codex_home / "rules"
                self.rules_dir.mkdir(parents=True)
                self.rules = self.rules_dir / "default.rules"
                self.rules.write_bytes(OLD_RULES)
                self.rules.chmod(0o640)
                self.candidate = case_root / "candidate.rules"
                self.candidate.write_bytes(NEW_RULES)
                self.receipt = case_root / "recovery.json"
                self.backup_name = f"default.rules.bak-20260724-{action}"
                self.backup = self.rules_dir / self.backup_name
                self.validator = case_root / "validator.py"
                self.write_validator(
                    """\
                    import os
                    from pathlib import Path
                    import sys

                    path = Path(sys.argv[1])
                    if path.name == "candidate":
                        raise SystemExit(0)
                    action = os.environ["POST_ACTION"]
                    if action == "replace":
                        later = path.with_name(".later.rules")
                        later.write_bytes(
                            b'prefix_rule(pattern=["gh", "pr", "view"], decision="allow")\\n'
                        )
                        later.chmod(0o640)
                        os.replace(later, path)
                    elif action == "content":
                        path.write_bytes(
                            b'prefix_rule(pattern=["gh", "pr", "view"], decision="allow")\\n'
                        )
                    elif action == "access":
                        path.chmod(0o600)
                    elif action == "missing":
                        path.unlink()
                    raise SystemExit(11)
                    """
                )

                result = self.run_apply(
                    environment=self.helper_environment(POST_ACTION=action)
                )

                self.assertEqual(result.returncode, 30, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["status"], "recovery_required")
                if action == "replace":
                    self.assertEqual(self.rules.read_bytes(), LATER_RULES)
                    mismatches = payload["post_replace_failure"][
                        "mismatched_properties"
                    ]
                    self.assertIn("object_identity", mismatches)
                    self.assertIn("content", mismatches)
                elif action == "content":
                    self.assertEqual(self.rules.read_bytes(), LATER_RULES)
                    self.assertEqual(
                        payload["post_replace_failure"]["mismatched_properties"],
                        ["content"],
                    )
                elif action == "access":
                    self.assertEqual(self.rules.read_bytes(), NEW_RULES)
                    self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o600)
                    self.assertEqual(
                        payload["post_replace_failure"]["mismatched_properties"],
                        ["access_policy"],
                    )
                else:
                    self.assertFalse(self.rules.exists())
                    self.assertEqual(
                        payload["post_replace_failure"]["status"],
                        "live_rules_missing",
                    )

                recover = self.run_recover()

                self.assertEqual(recover.returncode, 40, recover.stderr)
                recovery_payload = json.loads(recover.stdout)
                self.assertEqual(recovery_payload["status"], "recovery_refused")
                if action in ("replace", "content"):
                    self.assertEqual(self.rules.read_bytes(), LATER_RULES)
                elif action == "access":
                    self.assertEqual(self.rules.read_bytes(), NEW_RULES)
                    self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o600)
                else:
                    self.assertFalse(self.rules.exists())

    @unittest.skipUnless(os.name == "posix", "helper requires POSIX signals and flock")
    def test_recover_restores_after_process_dies_post_replace(self) -> None:
        self.write_validator(
            """\
            import os
            from pathlib import Path
            import signal
            import sys

            if Path(sys.argv[1]).name == "default.rules":
                os.kill(os.getppid(), signal.SIGKILL)
            """
        )

        interrupted = self.run_apply()

        self.assertLess(interrupted.returncode, 0)
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertTrue(self.receipt.is_file())

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovered")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
