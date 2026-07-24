from __future__ import annotations

from contextlib import redirect_stderr
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest import mock


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


def load_helper_module():
    spec = importlib.util.spec_from_file_location(
        "rules_apply_transaction_helper",
        HELPER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load transaction helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TRANSACTION = load_helper_module()


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

    def xattr_validator_source(self, *, live_only: bool = False) -> str:
        probe = self.root / "xattr-probe"
        probe.write_bytes(b"probe\n")
        if hasattr(os, "setxattr"):
            try:
                os.setxattr(probe, b"user.codex_review", b"value")
            except OSError as error:
                self.skipTest(f"user xattrs unsupported by test filesystem: {error}")
            return f"""\
                import os
                from pathlib import Path
                import sys

                path = Path(sys.argv[1])
                if {live_only!r} and path.name != "default.rules":
                    raise SystemExit(0)
                os.setxattr(path, b"user.codex_review", b"value")
                """
        xattr = shutil.which("xattr")
        if xattr is None:
            self.skipTest(
                "xattr injection unavailable; production descriptor inspection "
                "still fails closed when its platform API is unavailable"
            )
        probe_result = subprocess.run(
            [xattr, "-w", "user.codex-review", "value", str(probe)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if probe_result.returncode != 0:
            self.skipTest(
                "xattr injection unsupported by test filesystem: "
                + probe_result.stderr.decode("utf-8", "replace")
            )
        return f"""\
            from pathlib import Path
            import subprocess
            import sys

            path = Path(sys.argv[1])
            if {live_only!r} and path.name != "default.rules":
                raise SystemExit(0)
            subprocess.run(
                [{xattr!r}, "-w", "user.codex-review", "value", str(path)],
                check=True,
            )
            """

    def acl_validator_source(self) -> str:
        probe = self.root / "acl-probe"
        probe.write_bytes(b"probe\n")
        username = pwd.getpwuid(os.geteuid()).pw_name
        if sys.platform == "darwin":
            command = ["/bin/chmod", "+a", f"user:{username} allow read"]
        else:
            setfacl = shutil.which("setfacl")
            if setfacl is None:
                self.skipTest(
                    "ACL injection tool unavailable; production descriptor "
                    "inspection does not treat an unknown platform as ACL-free"
                )
            command = [setfacl, "-m", f"u:{username}:r--"]
        probe_result = subprocess.run(
            [*command, str(probe)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if probe_result.returncode != 0:
            self.skipTest(
                "ACL injection unsupported by test filesystem: "
                + probe_result.stderr.decode("utf-8", "replace")
            )
        return f"""\
            from pathlib import Path
            import subprocess
            import sys

            path = Path(sys.argv[1])
            subprocess.run({command!r} + [str(path)], check=True)
            """

    def add_test_xattr(self, path: Path) -> None:
        if hasattr(os, "setxattr"):
            try:
                os.setxattr(path, b"user.codex_review", b"value")
            except OSError as error:
                self.skipTest(f"user xattrs unsupported by test filesystem: {error}")
            return
        xattr = shutil.which("xattr")
        if xattr is None:
            self.skipTest("xattr injection unavailable")
        result = subprocess.run(
            [xattr, "-w", "user.codex-review", "value", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            self.skipTest(
                "xattr injection unsupported by test filesystem: "
                + result.stderr.decode("utf-8", "replace")
            )

    def add_test_acl(self, path: Path) -> None:
        username = pwd.getpwuid(os.geteuid()).pw_name
        if sys.platform == "darwin":
            command = ["/bin/chmod", "+a", f"user:{username} allow read"]
        else:
            setfacl = shutil.which("setfacl")
            if setfacl is None:
                self.skipTest("ACL injection tool unavailable")
            command = [setfacl, "-m", f"u:{username}:r--"]
        result = subprocess.run(
            [*command, str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            self.skipTest(
                "ACL injection unsupported by test filesystem: "
                + result.stderr.decode("utf-8", "replace")
            )

    def apply_namespace(self) -> SimpleNamespace:
        return SimpleNamespace(
            expected_sha256=hashlib.sha256(OLD_RULES).hexdigest(),
            candidate=str(self.candidate),
            receipt=str(self.receipt),
            backup_name=self.backup_name,
            validator_timeout_seconds=5.0,
            lock_timeout_seconds=2.0,
            validator_command=[
                sys.executable,
                str(self.validator),
                "{rules}",
            ],
        )

    def create_apply_evidence(
        self,
    ) -> tuple[object, object]:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        receipt_parent = TRANSACTION.bind_directory(
            self.receipt.parent,
            label="receipt",
            require_owner_private=True,
        )
        terminal = TRANSACTION.reserve_recovery_terminal(
            TRANSACTION.recovery_terminal_path(self.receipt),
            transaction_id="0" * 32,
            parent=receipt_parent,
        )
        backup_stage, backup_expected = stage.create("backup", OLD_RULES)
        _live_payload, live = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        backup_expected = stage.set_policy(
            backup_stage,
            backup_expected,
            live,
        )
        backup = stage.publish_backup(backup_stage, self.backup)
        receipt = TRANSACTION.write_receipt(
            self.receipt,
            {"schema_version": 2, "transaction_id": "0" * 32},
            receipt_parent,
        )
        evidence = TRANSACTION.ApplyEvidenceBindings(
            stage=stage,
            receipt_parent=receipt_parent,
            recovery_terminal=terminal,
            backup=backup,
            receipt=receipt,
        )
        evidence.validate()
        return stage, evidence

    def run_apply(
        self,
        *,
        expected_sha256: str | None = None,
        environment: dict[str, str] | None = None,
        validator_timeout: str = "5",
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
                f"--validator-timeout-seconds={validator_timeout}",
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
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(
            receipt["rules_parent"]["identity"],
            {
                "device": self.rules_dir.stat().st_dev,
                "inode": self.rules_dir.stat().st_ino,
            },
        )
        self.assertEqual(receipt["installed"]["object_policy"], {"nlink": 1})
        self.assertEqual(receipt["backup"]["object_policy"], {"nlink": 1})
        self.assertEqual(
            receipt["recovery_terminal"]["object_policy"],
            {"nlink": 1},
        )
        terminal = json.loads(
            Path(receipt["recovery_terminal_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(terminal["state"], "reserved")
        self.assertEqual(terminal["transaction_id"], receipt["transaction_id"])

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

    def test_candidate_hardlinked_by_validator_is_rejected_before_lock(self) -> None:
        self.write_validator(
            """\
            import os
            from pathlib import Path
            import sys

            path = Path(sys.argv[1])
            os.link(path, path.with_name("candidate.alias"))
            """
        )

        result = self.run_apply()

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "private_candidate_changed")
        self.assertEqual(payload["mismatched_properties"], ["object_policy"])
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())

    def test_candidate_xattr_injected_by_validator_is_rejected_before_lock(
        self,
    ) -> None:
        self.write_validator(self.xattr_validator_source())

        result = self.run_apply()

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "unsupported_extended_attributes")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())

    def test_candidate_acl_injected_by_validator_is_rejected_before_lock(
        self,
    ) -> None:
        self.write_validator(self.acl_validator_source())

        result = self.run_apply()

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "unsupported_access_control_list")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())

    def test_live_xattr_injected_by_post_validator_never_reports_success(
        self,
    ) -> None:
        self.write_validator(self.xattr_validator_source(live_only=True))

        result = self.run_apply()

        self.assertEqual(result.returncode, 30, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["post_replace_failure"]["status"],
            "unsupported_extended_attributes",
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertTrue(self.backup.exists())
        self.assertTrue(self.receipt.exists())

    def test_metadata_inspection_capability_failure_is_fail_closed(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        candidate, expected = stage.create("candidate", NEW_RULES)
        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "_list_bound_xattrs",
                    side_effect=TRANSACTION.TransactionError(
                        "metadata_inspection_unsupported",
                        "fault-injected missing descriptor API",
                    ),
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.validate(
                    candidate,
                    expected,
                    label="private_candidate",
                )

            self.assertEqual(
                raised.exception.status,
                "metadata_inspection_unsupported",
            )
        finally:
            stage.cleanup()

    def test_bound_file_flags_are_rejected_from_the_open_descriptor(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        candidate, expected = stage.create("candidate", NEW_RULES)
        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "_bound_file_flags",
                    return_value=0x10,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.validate(
                    candidate,
                    expected,
                    label="private_candidate",
                )

            self.assertEqual(
                raised.exception.status,
                "unsupported_file_flags",
            )
            self.assertEqual(raised.exception.details["st_flags"], 0x10)
        finally:
            stage.cleanup()

    def test_bound_backup_replacement_is_detected(self) -> None:
        stage, evidence = self.create_apply_evidence()
        moved_backup = self.rules_dir / "backup.bound"
        os.rename(self.backup, moved_backup)
        self.backup.write_bytes(LATER_RULES)
        self.backup.chmod(0o640)
        try:
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                evidence.validate()

            self.assertEqual(raised.exception.status, "backup_changed")
            self.assertIn(
                "object_identity",
                raised.exception.details["mismatched_properties"],
            )
        finally:
            evidence.close()
            stage.cleanup()

    def test_bound_receipt_hardlink_is_detected(self) -> None:
        stage, evidence = self.create_apply_evidence()
        os.link(self.receipt, self.receipt.with_name("receipt.alias"))
        try:
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                evidence.validate()

            self.assertEqual(raised.exception.status, "receipt_changed")
            self.assertEqual(
                raised.exception.details["mismatched_properties"],
                ["object_policy"],
            )
        finally:
            evidence.close()
            stage.cleanup()

    def test_bound_backup_xattr_is_detected(self) -> None:
        stage, evidence = self.create_apply_evidence()
        self.add_test_xattr(self.backup)
        try:
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                evidence.validate()

            self.assertEqual(
                raised.exception.status,
                "unsupported_extended_attributes",
            )
        finally:
            evidence.close()
            stage.cleanup()

    def test_bound_receipt_acl_is_detected(self) -> None:
        stage, evidence = self.create_apply_evidence()
        self.add_test_acl(self.receipt)
        try:
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                evidence.validate()

            self.assertEqual(
                raised.exception.status,
                "unsupported_access_control_list",
            )
        finally:
            evidence.close()
            stage.cleanup()

    def test_bound_receipt_file_flags_are_detected(self) -> None:
        stage, evidence = self.create_apply_evidence()
        real_flags = TRANSACTION._bound_file_flags

        def inject_receipt_flags(fd: int, *, label: str) -> int:
            if label == "receipt":
                return 0x10
            return real_flags(fd, label=label)

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "_bound_file_flags",
                    side_effect=inject_receipt_flags,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                evidence.validate()

            self.assertEqual(raised.exception.status, "unsupported_file_flags")
            self.assertEqual(raised.exception.details["st_flags"], 0x10)
        finally:
            evidence.close()
            stage.cleanup()

    def test_bound_receipt_parent_replacement_is_detected(self) -> None:
        stage, evidence = self.create_apply_evidence()
        moved_parent = self.root / "task.bound"
        os.rename(self.receipt.parent, moved_parent)
        self.receipt.parent.mkdir(mode=0o700)
        try:
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                evidence.validate()

            self.assertEqual(
                raised.exception.status,
                "receipt_parent_changed",
            )
        finally:
            evidence.close()
            stage.cleanup()

    def test_bound_receipt_parent_xattr_is_detected(self) -> None:
        stage, evidence = self.create_apply_evidence()
        self.add_test_xattr(self.receipt.parent)
        try:
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                evidence.validate()

            self.assertEqual(
                raised.exception.status,
                "unsupported_extended_attributes",
            )
        finally:
            evidence.close()
            stage.cleanup()

    def test_receipt_read_rejects_hardlink_and_metadata(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)

        alias = self.receipt.with_name("receipt.alias")
        os.link(self.receipt, alias)
        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 50, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["status"], "receipt_invalid")

        alias.unlink()
        self.add_test_xattr(self.receipt)
        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 50, recovered.stderr)
        self.assertEqual(
            json.loads(recovered.stdout)["status"],
            "unsupported_extended_attributes",
        )

    def test_receipt_hardlink_inside_exchange_never_reports_success(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_exchange = TRANSACTION.atomic_rename_exchange
        injected = False

        def hardlink_receipt_then_exchange(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            nonlocal injected
            if not injected:
                injected = True
                os.link(self.receipt, self.receipt.with_name("receipt.alias"))
            real_exchange(
                source_directory_fd,
                source_name,
                destination_directory_fd,
                destination_name,
            )

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
                side_effect=hardlink_receipt_then_exchange,
            ),
            redirect_stderr(io.StringIO()),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["post_replace_failure"]["status"],
            "receipt_changed",
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)

    def test_evidence_is_revalidated_immediately_before_exchange(self) -> None:
        stage, evidence = self.create_apply_evidence()
        candidate, candidate_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        candidate_expected = stage.set_policy(
            candidate,
            candidate_expected,
            live,
        )

        def mutate_then_revalidate() -> None:
            os.link(self.receipt, self.receipt.with_name("receipt.alias"))
            evidence.validate()

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                ) as atomic_exchange,
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(
                    candidate,
                    self.rules,
                    live,
                    pre_exchange_revalidate=mutate_then_revalidate,
                )

            self.assertEqual(raised.exception.status, "receipt_changed")
            atomic_exchange.assert_not_called()
            self.assertEqual(
                candidate_expected.sha256, hashlib.sha256(NEW_RULES).hexdigest()
            )
            self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        finally:
            evidence.close()
            stage.cleanup()

    def test_validator_output_ceiling_terminates_the_process_group(self) -> None:
        self.write_validator(
            f"""\
            import os

            os.write(1, b"x" * {TRANSACTION.MAX_VALIDATOR_OUTPUT_BYTES + 4096})
            """
        )

        result = TRANSACTION.run_validator(
            [sys.executable, str(self.validator), "{rules}"],
            self.candidate,
            timeout_seconds=2,
        )

        self.assertFalse(result.valid)
        self.assertTrue(result.output_limit_exceeded)
        self.assertFalse(result.timed_out)
        self.assertLessEqual(
            len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")),
            TRANSACTION.MAX_VALIDATOR_OUTPUT_BYTES,
        )

    def test_validator_timeout_terminates_the_process_group(self) -> None:
        self.write_validator(
            """\
            import time

            time.sleep(30)
            """
        )
        started = time.monotonic()

        result = TRANSACTION.run_validator(
            [sys.executable, str(self.validator), "{rules}"],
            self.candidate,
            timeout_seconds=0.1,
        )

        self.assertFalse(result.valid)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 124)
        self.assertLess(time.monotonic() - started, 3)

    def test_validator_descendant_is_terminated_after_leader_exit(self) -> None:
        pid_path = self.root / "validator-descendant.pid"
        ready_path = self.root / "validator-descendant.ready"
        stopped_path = self.root / "validator-descendant.stopped"
        child_script = self.root / "validator-descendant.py"
        child_script.write_text(
            textwrap.dedent(
                f"""\
                from pathlib import Path
                import signal
                import sys
                import time

                def stop(_signum, _frame):
                    Path({str(stopped_path)!r}).write_text(
                        "stopped",
                        encoding="ascii",
                    )
                    raise SystemExit(0)

                signal.signal(signal.SIGTERM, stop)
                Path({str(ready_path)!r}).write_text("ready", encoding="ascii")
                while True:
                    time.sleep(1)
                """
            ),
            encoding="utf-8",
        )
        self.write_validator(
            f"""\
            from pathlib import Path
            import subprocess
            import sys
            import time

            child = subprocess.Popen(
                [sys.executable, {str(child_script)!r}]
            )
            Path({str(pid_path)!r}).write_text(
                str(child.pid),
                encoding="ascii",
            )
            deadline = time.monotonic() + 1
            while not Path({str(ready_path)!r}).exists():
                if time.monotonic() >= deadline:
                    raise SystemExit(8)
                time.sleep(0.01)
            """
        )

        result = TRANSACTION.run_validator(
            [sys.executable, str(self.validator), "{rules}"],
            self.candidate,
            timeout_seconds=2,
        )

        self.assertFalse(result.valid)
        self.assertTrue(result.descendants_terminated)
        self.assertTrue(pid_path.is_file())
        self.assertEqual(stopped_path.read_text(encoding="ascii"), "stopped")

    def test_validator_detects_descendant_with_all_stdio_closed(self) -> None:
        ready_path = self.root / "validator-devnull-descendant.ready"
        stopped_path = self.root / "validator-devnull-descendant.stopped"
        child_script = self.root / "validator-devnull-descendant.py"
        child_script.write_text(
            textwrap.dedent(
                f"""\
                from pathlib import Path
                import signal
                import time

                def stop(_signum, _frame):
                    Path({str(stopped_path)!r}).write_text(
                        "stopped",
                        encoding="ascii",
                    )
                    raise SystemExit(0)

                signal.signal(signal.SIGTERM, stop)
                Path({str(ready_path)!r}).write_text("ready", encoding="ascii")
                while True:
                    time.sleep(1)
                """
            ),
            encoding="utf-8",
        )
        self.write_validator(
            f"""\
            from pathlib import Path
            import subprocess
            import sys
            import time

            subprocess.Popen(
                [sys.executable, {str(child_script)!r}],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 1
            while not Path({str(ready_path)!r}).exists():
                if time.monotonic() >= deadline:
                    raise SystemExit(8)
                time.sleep(0.01)
            """
        )

        result = TRANSACTION.run_validator(
            [sys.executable, str(self.validator), "{rules}"],
            self.candidate,
            timeout_seconds=2,
        )

        self.assertFalse(result.valid)
        self.assertTrue(result.descendants_terminated)
        self.assertEqual(stopped_path.read_text(encoding="ascii"), "stopped")

    def test_validator_rejects_nonfinite_timeouts(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        for value in (float("nan"), float("inf"), float("-inf")):
            with (
                self.subTest(value=value),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                TRANSACTION.run_validator(
                    [sys.executable, str(self.validator), "{rules}"],
                    self.candidate,
                    timeout_seconds=value,
                )
            self.assertEqual(
                raised.exception.status,
                "validator_command_invalid",
            )

        for value in ("nan", "inf", "-inf"):
            with self.subTest(cli_value=value):
                result = self.run_apply(validator_timeout=value)
                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertEqual(
                    json.loads(result.stdout)["status"],
                    "arguments_invalid",
                )

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

    def test_no_change_waits_for_shared_writer_and_rechecks_digest(self) -> None:
        self.candidate.write_bytes(OLD_RULES)
        self.write_validator("raise SystemExit(0)\n")
        ready = self.root / "writer.ready"
        writer = subprocess.Popen(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    """\
                    import fcntl
                    import os
                    from pathlib import Path
                    import sys
                    import time

                    lock = Path(sys.argv[1])
                    live = Path(sys.argv[2])
                    ready = Path(sys.argv[3])
                    fd = os.open(
                        lock,
                        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
                        0o600,
                    )
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX)
                        ready.write_text("ready", encoding="ascii")
                        time.sleep(0.3)
                        replacement = live.with_name(".compliant-writer")
                        replacement.write_bytes(
                            b'prefix_rule(pattern=["gh", "pr", "view"], decision="allow")\\n'
                        )
                        replacement.chmod(0o640)
                        os.replace(replacement, live)
                    finally:
                        os.close(fd)
                    """
                ),
                str(self.rules_dir / ".default.rules.apply.lock"),
                str(self.rules),
                str(ready),
            ],
            env=self.helper_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 2
            while not ready.exists():
                if writer.poll() is not None:
                    self.fail(writer.stderr.read())
                if time.monotonic() >= deadline:
                    self.fail("compliant writer did not acquire the shared lock")
                time.sleep(0.01)

            result = self.run_apply()
            writer_stdout, writer_stderr = writer.communicate(timeout=5)
        finally:
            if writer.poll() is None:
                writer.kill()
                writer.wait(timeout=5)

        self.assertEqual(writer.returncode, 0, writer_stderr)
        self.assertEqual(writer_stdout, "")
        self.assertEqual(result.returncode, 20, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "expected_digest_mismatch")
        self.assertEqual(self.rules.read_bytes(), LATER_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())

    def test_no_change_succeeds_only_after_locked_metadata_admission(self) -> None:
        self.candidate.write_bytes(OLD_RULES)
        self.write_validator("raise SystemExit(0)\n")

        result = self.run_apply()

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "no_change_after_lock")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(TRANSACTION.recovery_terminal_path(self.receipt).exists())
        self.assertTrue((self.rules_dir / ".default.rules.apply.lock").is_file())

    def test_no_change_rejects_live_metadata_anomaly_after_lock(self) -> None:
        self.candidate.write_bytes(OLD_RULES)
        self.write_validator("raise SystemExit(0)\n")
        self.add_test_xattr(self.rules)

        result = self.run_apply()

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "unsupported_extended_attributes")
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())

    def test_stale_recovery_terminal_blocks_before_backup(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        terminal.write_text("stale\n", encoding="utf-8")
        terminal.chmod(0o600)

        result = self.run_apply()

        self.assertEqual(result.returncode, 20, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "recovery_terminal_exists")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertEqual(terminal.read_text(encoding="utf-8"), "stale\n")

    def test_hardlinked_live_rules_are_rejected_before_backup(self) -> None:
        live_alias = self.rules_dir / "default.rules.alias"
        os.link(self.rules, live_alias)
        self.write_validator("raise SystemExit(0)\n")

        result = self.run_apply()

        self.assertEqual(result.returncode, 20, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(
            payload["status"],
            "live_rules_object_policy_unsupported",
        )
        self.assertEqual(payload["object_policy"], {"nlink": 2})
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
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

    def test_read_only_live_rules_apply_and_rollback(self) -> None:
        self.rules.chmod(0o444)
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
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o444)

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

    def test_recover_refuses_same_original_bytes_on_untrusted_new_inode(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        replacement = self.rules_dir / ".same-original-new-inode"
        replacement.write_bytes(OLD_RULES)
        replacement.chmod(0o640)
        os.replace(replacement, self.rules)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 40, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "original_identity_untrusted")
        self.assertEqual(payload["mismatched_properties"], ["object_identity"])
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_recover_is_idempotent_with_bound_terminal_identity(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)

        recovered = self.run_recover()
        repeated = self.run_recover()

        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["status"], "recovered")
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        repeated_payload = json.loads(repeated.stdout)
        self.assertEqual(repeated_payload["status"], "already_original")
        self.assertEqual(
            repeated_payload["identity_evidence"],
            "recovery_terminal",
        )
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        terminal = Path(receipt["recovery_terminal_path"])
        self.assertTrue(terminal.is_file())
        self.assertEqual(stat.S_IMODE(terminal.stat().st_mode), 0o600)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_recover_refuses_replaced_terminal_reservation(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        terminal = Path(receipt["recovery_terminal_path"])
        reservation = terminal.read_bytes()
        terminal.rename(terminal.with_name("recovery.bound"))
        terminal.write_bytes(reservation)
        terminal.chmod(0o600)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 40, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "recovery_terminal_binding_changed")
        self.assertEqual(payload["mismatched_properties"], ["object_identity"])
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)

    def test_recover_accepts_legacy_v1_receipt_without_link_policy(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["schema_version"] = 1
        for key in ("rules_parent", "original", "installed", "backup"):
            receipt[key].pop("object_policy")
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovered")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_recover_rejects_v2_receipt_with_non_single_link_policy(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["installed"]["object_policy"]["nlink"] = 2
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 50, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "receipt_invalid")
        self.assertIn("object_policy.nlink must be 1", payload["message"])
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)


class RulesApplyPrimitiveRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory(prefix="rules-primitive-race.")
        self.root = Path(self.tmpdir.name)
        self.rules_dir = self.root / "rules"
        self.rules_dir.mkdir()
        self.rules = self.rules_dir / "default.rules"
        self.rules.write_bytes(OLD_RULES)
        self.rules.chmod(0o640)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    @staticmethod
    def exchange_entries(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        temporary_name = ".fault-exchange-temporary"
        os.rename(
            source_name,
            temporary_name,
            src_dir_fd=source_directory_fd,
            dst_dir_fd=source_directory_fd,
        )
        os.rename(
            destination_name,
            source_name,
            src_dir_fd=destination_directory_fd,
            dst_dir_fd=source_directory_fd,
        )
        os.rename(
            temporary_name,
            destination_name,
            src_dir_fd=source_directory_fd,
            dst_dir_fd=destination_directory_fd,
        )

    def test_write_failure_does_not_unlink_replacement_leaf(self) -> None:
        target = self.root / "exclusive.rules"
        moved_created = self.root / "created-object.rules"
        original_write = os.write
        injected = False

        def replace_then_fail(fd: int, payload: bytes) -> int:
            nonlocal injected
            written = original_write(fd, payload)
            if not injected:
                injected = True
                os.rename(target, moved_created)
                target.write_bytes(b"replacement must survive\n")
                raise OSError(5, "fault after pathname replacement")
            return written

        with (
            mock.patch.object(TRANSACTION.os, "write", replace_then_fail),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.write_exclusive(target, NEW_RULES)

        self.assertEqual(raised.exception.status, "write_failed")
        self.assertEqual(target.read_bytes(), b"replacement must survive\n")
        self.assertEqual(moved_created.read_bytes(), NEW_RULES)
        retained = raised.exception.details["retained_created_object"]
        self.assertIsNone(retained["recovery_locator"])
        self.assertEqual(
            retained["retention_status"],
            "descriptor_only_or_unlocatable",
        )
        self.assertEqual(
            retained["cleanup_policy"],
            "no_false_retention_claim",
        )

    def test_backup_source_swap_retains_created_and_replacement_objects(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("backup", OLD_RULES)
        moved_source = stage.path / "backup.bound"
        victim = b"replacement backup leaf\n"
        backup = self.rules_dir / "default.rules.bak-fault"

        def swap_source_then_publish(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            os.rename(
                source_name,
                moved_source.name,
                src_dir_fd=source_directory_fd,
                dst_dir_fd=source_directory_fd,
            )
            source.write_bytes(victim)
            os.rename(
                source_name,
                destination_name,
                src_dir_fd=source_directory_fd,
                dst_dir_fd=destination_directory_fd,
            )

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_no_replace",
                    swap_source_then_publish,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.publish_backup(source, backup)

            self.assertEqual(raised.exception.status, "recovery_required")
            retention = raised.exception.details["retention"]["source"]
            self.assertEqual(
                retention["retention_status"],
                "verified_recovery_copy",
            )
            recovery_copy = Path(retention["recovery_locator"])
            self.assertEqual(recovery_copy.read_bytes(), OLD_RULES)
            self.assertEqual(backup.read_bytes(), victim)
            self.assertEqual(moved_source.read_bytes(), OLD_RULES)
        finally:
            warnings = stage.cleanup()

        retained = [
            warning
            for warning in warnings
            if warning["status"] == "retained_staged_file"
        ]
        self.assertEqual(len(retained), 2)
        self.assertIn(
            str(moved_source),
            {warning["recovery_locator"] for warning in retained},
        )
        self.assertEqual(backup.read_bytes(), victim)
        self.assertEqual(moved_source.read_bytes(), OLD_RULES)

    def test_exchange_source_swap_retains_every_object(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, source_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        moved_source = stage.path / "candidate.bound"
        victim = b"replacement candidate leaf\n"

        def swap_source_then_exchange(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            os.rename(
                source_name,
                moved_source.name,
                src_dir_fd=source_directory_fd,
                dst_dir_fd=source_directory_fd,
            )
            source.write_bytes(victim)
            self.exchange_entries(
                source_directory_fd,
                source_name,
                destination_directory_fd,
                destination_name,
            )

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                    swap_source_then_exchange,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(source, self.rules, live_expected)

            self.assertEqual(raised.exception.status, "recovery_required")
            self.assertEqual(self.rules.read_bytes(), victim)
            self.assertEqual(source.read_bytes(), OLD_RULES)
            self.assertEqual(moved_source.read_bytes(), NEW_RULES)
            self.assertEqual(
                raised.exception.details["source_expected"],
                source_expected.to_json(),
            )
        finally:
            stage.cleanup()

        self.assertEqual(self.rules.read_bytes(), victim)
        self.assertEqual(source.read_bytes(), OLD_RULES)
        self.assertEqual(moved_source.read_bytes(), NEW_RULES)

    def test_exchange_target_swap_retains_later_target(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        moved_original = self.rules_dir / ".original-live.rules"

        def swap_target_then_exchange(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            os.rename(
                destination_name,
                moved_original.name,
                src_dir_fd=destination_directory_fd,
                dst_dir_fd=destination_directory_fd,
            )
            self.rules.write_bytes(LATER_RULES)
            self.rules.chmod(0o640)
            self.exchange_entries(
                source_directory_fd,
                source_name,
                destination_directory_fd,
                destination_name,
            )

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                    swap_target_then_exchange,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(source, self.rules, live_expected)

            self.assertEqual(raised.exception.status, "recovery_required")
            self.assertEqual(self.rules.read_bytes(), NEW_RULES)
            self.assertEqual(source.read_bytes(), LATER_RULES)
            self.assertEqual(moved_original.read_bytes(), OLD_RULES)
        finally:
            stage.cleanup()

        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(source.read_bytes(), LATER_RULES)
        self.assertEqual(moved_original.read_bytes(), OLD_RULES)

    def test_exchange_unlink_race_copies_both_bound_objects(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )

        def exchange_then_unlink(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            self.exchange_entries(
                source_directory_fd,
                source_name,
                destination_directory_fd,
                destination_name,
            )
            os.unlink(source_name, dir_fd=source_directory_fd)
            os.unlink(destination_name, dir_fd=destination_directory_fd)

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                    exchange_then_unlink,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(source, self.rules, live_expected)

            self.assertEqual(raised.exception.status, "recovery_required")
            self.assertEqual(
                raised.exception.details["retention_status"],
                "bound_objects_copied",
            )
            retention = raised.exception.details["retention"]
            source_copy = Path(retention["source"]["recovery_locator"])
            destination_copy = Path(retention["destination"]["recovery_locator"])
            self.assertEqual(source_copy.read_bytes(), NEW_RULES)
            self.assertEqual(destination_copy.read_bytes(), OLD_RULES)
            self.assertFalse(source.exists())
            self.assertFalse(self.rules.exists())
        finally:
            warnings = stage.cleanup()

        self.assertEqual(source_copy.read_bytes(), NEW_RULES)
        self.assertEqual(destination_copy.read_bytes(), OLD_RULES)
        unretained = [
            warning
            for warning in warnings
            if warning["status"] == "unretained_bound_file"
        ]
        self.assertGreaterEqual(len(unretained), 2)
        self.assertTrue(
            all(warning["recovery_locator"] is None for warning in unretained)
        )

    def test_backup_unlink_race_copies_bound_source(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("backup", OLD_RULES)
        backup = self.rules_dir / "default.rules.bak-unlinked"

        def publish_then_unlink(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            os.rename(
                source_name,
                destination_name,
                src_dir_fd=source_directory_fd,
                dst_dir_fd=destination_directory_fd,
            )
            os.unlink(destination_name, dir_fd=destination_directory_fd)

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_no_replace",
                    publish_then_unlink,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.publish_backup(source, backup)

            self.assertEqual(raised.exception.status, "recovery_required")
            retention = raised.exception.details["retention"]["source"]
            self.assertEqual(
                retention["retention_status"],
                "verified_recovery_copy",
            )
            recovery_copy = Path(retention["recovery_locator"])
            self.assertEqual(recovery_copy.read_bytes(), OLD_RULES)
            self.assertFalse(source.exists())
            self.assertFalse(backup.exists())
        finally:
            stage.cleanup()

        self.assertEqual(recovery_copy.read_bytes(), OLD_RULES)

    def test_recovery_copy_locator_binding_rejects_protected_property_races(
        self,
    ) -> None:
        for action in ("content", "hardlink", "access"):
            with self.subTest(action=action):
                stage = TRANSACTION.PrivateStage(self.rules_dir)
                source, _source_expected = stage.create("candidate", NEW_RULES)
                source_binding = stage._binding(source)
                real_locator = stage._locator_for_snapshot
                injected = False

                def mutate_after_locator(
                    expected: object,
                ) -> Path | None:
                    nonlocal injected
                    locator = real_locator(expected)
                    if injected or locator is None:
                        return locator
                    injected = True
                    recovery_bindings = [
                        binding
                        for binding in stage.files.values()
                        if binding is not source_binding
                        and (
                            binding.snapshot.device,
                            binding.snapshot.inode,
                        )
                        == (expected.device, expected.inode)
                    ]
                    self.assertEqual(len(recovery_bindings), 1)
                    recovery = recovery_bindings[0]
                    if action == "content":
                        os.ftruncate(recovery.fd, 0)
                        os.lseek(recovery.fd, 0, os.SEEK_SET)
                        os.write(recovery.fd, LATER_RULES)
                        os.fsync(recovery.fd)
                    elif action == "hardlink":
                        os.link(
                            recovery.name,
                            f"{recovery.name}.alias",
                            src_dir_fd=stage.stage_fd,
                            dst_dir_fd=stage.stage_fd,
                        )
                    else:
                        os.fchmod(recovery.fd, 0o640)
                    return locator

                try:
                    with mock.patch.object(
                        stage,
                        "_locator_for_snapshot",
                        side_effect=mutate_after_locator,
                    ):
                        retention = stage._preserve_bound_file(
                            source_binding,
                            role="source",
                        )

                    self.assertEqual(
                        retention["retention_status"],
                        "not_persistently_retained",
                    )
                    self.assertNotIn("recovery_locator", retention)
                    self.assertEqual(
                        retention["retention_error"]["status"],
                        "recovery_copy_changed",
                    )
                    mismatches = retention["retention_error"]["details"][
                        "recovery_mismatched_properties"
                    ]
                    expected_mismatch = (
                        "object_policy" if action == "hardlink" else action
                    )
                    if action == "access":
                        expected_mismatch = "access_policy"
                    self.assertIn(expected_mismatch, mismatches)
                finally:
                    stage.cleanup()

    def test_no_replace_eexist_with_unlinked_source_requires_recovery(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("backup", OLD_RULES)
        backup = self.rules_dir / "default.rules.bak-existing"

        def unlink_then_report_eexist(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            destination_fd = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_directory_fd,
            )
            try:
                os.write(destination_fd, LATER_RULES)
            finally:
                os.close(destination_fd)
            os.unlink(source_name, dir_fd=source_directory_fd)
            raise FileExistsError(errno.EEXIST, "fault-injected EEXIST")

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_no_replace",
                    unlink_then_report_eexist,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.publish_backup(source, backup)

            self.assertEqual(raised.exception.status, "recovery_required")
            retention = raised.exception.details["retention"]["source"]
            self.assertEqual(
                retention["retention_status"],
                "verified_recovery_copy",
            )
            recovery_copy = Path(retention["recovery_locator"])
            self.assertEqual(recovery_copy.read_bytes(), OLD_RULES)
            self.assertEqual(backup.read_bytes(), LATER_RULES)
        finally:
            stage.cleanup()

        self.assertEqual(recovery_copy.read_bytes(), OLD_RULES)

    def test_parent_replacement_never_produces_locator_in_new_directory(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("candidate", NEW_RULES)
        moved_rules = self.root / "rules.bound"
        os.rename(self.rules_dir, moved_rules)
        self.rules_dir.mkdir()

        warnings = stage.cleanup()

        retained_file = moved_rules / stage.stage_name / source.name
        self.assertEqual(retained_file.read_bytes(), NEW_RULES)
        file_warnings = [
            warning
            for warning in warnings
            if warning["status"] == "unretained_bound_file"
        ]
        self.assertEqual(len(file_warnings), 1)
        self.assertIsNone(file_warnings[0]["recovery_locator"])
        root_warnings = [
            warning
            for warning in warnings
            if warning["status"] == "unretained_staging_directory"
        ]
        self.assertEqual(len(root_warnings), 1)
        self.assertIsNone(root_warnings[0]["recovery_locator"])

    def test_unlinked_objects_and_replaced_parent_report_incomplete_retention(
        self,
    ) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        moved_rules = self.root / "rules.bound"

        def exchange_unlink_and_replace_parent(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            self.exchange_entries(
                source_directory_fd,
                source_name,
                destination_directory_fd,
                destination_name,
            )
            os.unlink(source_name, dir_fd=source_directory_fd)
            os.unlink(destination_name, dir_fd=destination_directory_fd)
            os.rename(self.rules_dir, moved_rules)
            self.rules_dir.mkdir()

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                    exchange_unlink_and_replace_parent,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(source, self.rules, live_expected)

            self.assertEqual(raised.exception.status, "recovery_required")
            self.assertEqual(
                raised.exception.details["retention_status"],
                "retention_incomplete",
            )
            self.assertEqual(
                raised.exception.details["cleanup_policy"],
                "retention_incomplete_no_false_claim",
            )
            for role in ("source", "destination"):
                retention = raised.exception.details["retention"][role]
                self.assertEqual(
                    retention["retention_status"],
                    "not_persistently_retained",
                )
                self.assertIsNone(retention.get("recovery_locator"))
                self.assertEqual(
                    retention["retention_error"]["status"],
                    "rules_directory_changed",
                )
        finally:
            warnings = stage.cleanup()

        self.assertTrue(
            all(warning.get("recovery_locator") is None for warning in warnings)
        )

    def test_set_policy_rejects_hardlink_added_after_validation(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, source_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        real_fchmod = TRANSACTION.os.fchmod
        injected = False

        def hardlink_then_chmod(fd: int, mode: int) -> None:
            nonlocal injected
            if not injected:
                injected = True
                os.link(
                    source.name,
                    "candidate.alias",
                    src_dir_fd=stage.stage_fd,
                    dst_dir_fd=stage.stage_fd,
                )
            real_fchmod(fd, mode)

        try:
            with (
                mock.patch.object(
                    TRANSACTION.os,
                    "fchmod",
                    hardlink_then_chmod,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.set_policy(source, source_expected, live_expected)

            self.assertEqual(raised.exception.status, "private_candidate_changed")
            self.assertEqual(
                raised.exception.details["mismatched_properties"],
                ["object_policy"],
            )
        finally:
            stage.cleanup()

    def test_exchange_revalidates_single_link_immediately_before_mutation(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        real_validate = stage.validate
        validation_count = 0

        def hardlink_after_first_validation(
            path: Path,
            expected: object,
            *,
            label: str,
        ) -> object:
            nonlocal validation_count
            actual = real_validate(path, expected, label=label)
            validation_count += 1
            if validation_count == 1:
                os.link(
                    source.name,
                    "candidate.alias",
                    src_dir_fd=stage.stage_fd,
                    dst_dir_fd=stage.stage_fd,
                )
            return actual

        try:
            with (
                mock.patch.object(
                    stage,
                    "validate",
                    side_effect=hardlink_after_first_validation,
                ),
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                ) as atomic_exchange,
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(source, self.rules, live_expected)

            self.assertEqual(raised.exception.status, "private_candidate_changed")
            self.assertEqual(
                raised.exception.details["mismatched_properties"],
                ["object_policy"],
            )
            atomic_exchange.assert_not_called()
        finally:
            stage.cleanup()

    def test_backup_publication_revalidates_single_link_before_mutation(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("backup", OLD_RULES)
        backup = self.rules_dir / "default.rules.bak-hardlink"
        real_validate = stage.validate
        validation_count = 0

        def hardlink_after_first_validation(
            path: Path,
            expected: object,
            *,
            label: str,
        ) -> object:
            nonlocal validation_count
            actual = real_validate(path, expected, label=label)
            validation_count += 1
            if validation_count == 1:
                os.link(
                    source.name,
                    "backup.alias",
                    src_dir_fd=stage.stage_fd,
                    dst_dir_fd=stage.stage_fd,
                )
            return actual

        try:
            with (
                mock.patch.object(
                    stage,
                    "validate",
                    side_effect=hardlink_after_first_validation,
                ),
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_no_replace",
                ) as atomic_publish,
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.publish_backup(source, backup)

            self.assertEqual(raised.exception.status, "private_backup_changed")
            self.assertEqual(
                raised.exception.details["mismatched_properties"],
                ["object_policy"],
            )
            atomic_publish.assert_not_called()
        finally:
            stage.cleanup()

    def test_hardlink_added_inside_exchange_is_detected_after_mutation(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )

        def hardlink_then_exchange(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            os.link(
                source_name,
                "candidate.alias",
                src_dir_fd=source_directory_fd,
                dst_dir_fd=source_directory_fd,
            )
            self.exchange_entries(
                source_directory_fd,
                source_name,
                destination_directory_fd,
                destination_name,
            )

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                    hardlink_then_exchange,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(source, self.rules, live_expected)

            self.assertEqual(raised.exception.status, "recovery_required")
            self.assertEqual(
                raised.exception.details["retention_status"],
                "bound_objects_copied",
            )
            self.assertIn(
                "object_policy",
                raised.exception.details["destination_observation"][
                    "mismatched_properties"
                ],
            )
        finally:
            stage.cleanup()

    def test_cleanup_leaf_swap_reports_true_bound_locator(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)
        moved_source = stage.path / "candidate.bound"
        os.rename(source, moved_source)
        source.write_bytes(b"replacement cleanup leaf\n")

        warnings = stage.cleanup()

        self.assertEqual(source.read_bytes(), b"replacement cleanup leaf\n")
        self.assertEqual(moved_source.read_bytes(), NEW_RULES)
        retained = [
            warning
            for warning in warnings
            if warning["status"] == "retained_staged_file"
        ]
        self.assertEqual(retained[0]["recovery_locator"], str(moved_source))

    def test_cleanup_root_swap_preserves_replacement_tree(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)
        moved_root = self.rules_dir / ".moved-stage"
        os.rename(stage.path, moved_root)
        stage.path.mkdir(mode=0o700)
        replacement_leaf = stage.path / "replacement"
        replacement_leaf.write_bytes(b"replacement stage tree\n")

        warnings = stage.cleanup()

        self.assertEqual(replacement_leaf.read_bytes(), b"replacement stage tree\n")
        self.assertEqual((moved_root / source.name).read_bytes(), NEW_RULES)
        retained_roots = [
            warning
            for warning in warnings
            if warning["status"] == "retained_staging_directory"
        ]
        self.assertEqual(retained_roots[0]["recovery_locator"], str(moved_root))

    def test_atomic_exchange_unsupported_fails_without_fallback(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)
        _live_payload, live_expected = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "atomic_rename_exchange",
                    side_effect=TRANSACTION.TransactionError(
                        "atomic_rename_unsupported",
                        "fault-injected unsupported filesystem",
                    ),
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                stage.move_to(source, self.rules, live_expected)

            self.assertEqual(
                raised.exception.status,
                "atomic_rename_unsupported",
            )
            self.assertEqual(self.rules.read_bytes(), OLD_RULES)
            self.assertEqual(source.read_bytes(), NEW_RULES)
        finally:
            stage.cleanup()


if __name__ == "__main__":
    unittest.main()
