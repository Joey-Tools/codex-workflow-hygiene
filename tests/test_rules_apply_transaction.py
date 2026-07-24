from __future__ import annotations

from contextlib import redirect_stderr
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
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

    def assert_no_private_stage(self) -> None:
        self.assertEqual(list(self.rules_dir.glob(".rules-apply-*")), [])
        self.assertEqual(
            list(self.rules_dir.glob(".default.rules.cleanup-retained-*")),
            [],
        )
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        if stage.exists():
            self.assertTrue(stage.is_dir())
            self.assertEqual(list(stage.iterdir()), [])

    def write_sleeping_validator(self, pid_path: Path) -> None:
        self.write_validator(
            f"""\
            from pathlib import Path
            import os
            import time

            Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding="ascii")
            while True:
                time.sleep(1)
            """
        )

    def wait_for_pid_path(self, pid_path: Path) -> int:
        deadline = time.monotonic() + 2
        while not pid_path.exists():
            if time.monotonic() >= deadline:
                self.fail(f"validator did not publish its PID: {pid_path}")
            time.sleep(0.01)
        return int(pid_path.read_text(encoding="ascii"))

    def wait_for_path(self, path: Path, *, label: str) -> None:
        deadline = time.monotonic() + 3
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail(f"{label} did not become ready: {path}")
            time.sleep(0.01)

    def assert_process_exited(self, pid: int) -> None:
        deadline = time.monotonic() + 2
        while True:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            if time.monotonic() >= deadline:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.fail(f"validator process {pid} remained alive")
            time.sleep(0.01)

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
            candidate_sha256=hashlib.sha256(NEW_RULES).hexdigest(),
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
        lock_path = self.rules_dir / ".default.rules.apply.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        lock_fd = os.open(
            lock_path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        lock = TRANSACTION.BoundFile(
            path=lock_path,
            name=lock_path.name,
            fd=lock_fd,
            snapshot=TRANSACTION.lock_snapshot(lock_path, os.fstat(lock_fd)),
        )
        stage.extra_fds.append(lock_fd)
        rules_parent = TRANSACTION.bind_directory(
            self.rules_dir,
            label="rules",
        )
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
            lock=lock,
            rules_parent=rules_parent,
            stage=stage,
            receipt_parent=receipt_parent,
            recovery_terminal=terminal,
            prepared_candidate=backup,
            backup=backup,
            receipt=receipt,
            candidate_in_stage=True,
        )
        evidence.validate()
        return stage, evidence

    def run_apply(
        self,
        *,
        expected_sha256: str | None = None,
        candidate_sha256: str | None = None,
        environment: dict[str, str] | None = None,
        validator_timeout: str = "5",
    ) -> subprocess.CompletedProcess[str]:
        expected = expected_sha256 or hashlib.sha256(OLD_RULES).hexdigest()
        candidate_digest = (
            candidate_sha256 or hashlib.sha256(self.candidate.read_bytes()).hexdigest()
        )
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "apply",
                "--candidate",
                str(self.candidate),
                "--candidate-sha256",
                candidate_digest,
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

    def rewrite_receipt_as_legacy_v1(self) -> dict[str, object]:
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["schema_version"] = 1
        for key in ("rules_parent", "original", "installed", "backup"):
            receipt[key].pop("object_policy")
        for key in (
            "staged_backup_path",
            "staged_backup_parent",
            "prepared_candidate_path",
            "prepared_candidate_parent",
        ):
            receipt.pop(key, None)
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)
        return receipt

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
                "nlink": path.stat().st_nlink,
                "content": path.read_text(encoding="utf-8"),
            }
            with Path(os.environ["VALIDATOR_LOG"]).open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write(json.dumps(row, sort_keys=True) + "\\n")
            if path.name != "default.rules" and (
                file_mode != 0o600 or path.stat().st_nlink != 0
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
        self.assertTrue(validator_rows[0]["name"].isdigit())
        self.assertEqual(validator_rows[1]["name"], "default.rules")
        self.assertEqual(validator_rows[0]["file_mode"], 0o600)
        self.assertEqual(validator_rows[0]["nlink"], 0)
        self.assertEqual(validator_rows[0]["content"].encode(), NEW_RULES)
        self.assertEqual(validator_rows[1]["file_mode"], 0o640)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema_version"], 4)
        self.assertEqual(
            receipt["rules_parent"]["identity"],
            {
                "device": self.rules_dir.stat().st_dev,
                "inode": self.rules_dir.stat().st_ino,
            },
        )
        self.assertEqual(receipt["installed"]["object_policy"], {"nlink": 1})
        self.assertEqual(receipt["backup"]["object_policy"], {"nlink": 1})
        self.assertEqual(receipt["backup"], receipt["original"])
        self.assertIsNone(receipt["staged_backup_parent"])
        self.assertEqual(
            Path(receipt["staged_backup_path"]).resolve(),
            (self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate").resolve(),
        )
        prepared_candidate = self.receipt.with_name(
            f"{self.receipt.name}{TRANSACTION.PREPARED_CANDIDATE_SUFFIX}"
        )
        self.assertEqual(
            Path(receipt["prepared_candidate_path"]).resolve(),
            prepared_candidate.resolve(),
        )
        self.assertEqual(
            receipt["prepared_candidate_parent"]["identity"],
            {
                "device": self.receipt.parent.stat().st_dev,
                "inode": self.receipt.parent.stat().st_ino,
            },
        )
        self.assertFalse(prepared_candidate.exists())
        self.assertEqual(
            receipt["recovery_terminal"]["object_policy"],
            {"nlink": 1},
        )
        terminal = json.loads(
            Path(receipt["recovery_terminal_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(terminal["state"], "reserved")
        self.assertEqual(terminal["transaction_id"], receipt["transaction_id"])
        self.assertEqual(
            receipt["candidate_sha256"],
            hashlib.sha256(NEW_RULES).hexdigest(),
        )
        self.assert_no_private_stage()

    def test_candidate_digest_mismatch_is_rejected_before_staging(self) -> None:
        self.write_validator("raise SystemExit(0)\n")

        result = self.run_apply(candidate_sha256="0" * 64)

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "candidate_digest_mismatch")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assert_no_private_stage()

    def test_candidate_source_replacement_after_validation_is_rejected(
        self,
    ) -> None:
        self.write_validator(
            """\
            import os
            from pathlib import Path
            import sys

            path = Path(sys.argv[1])
            if path.name != "default.rules":
                source = Path(os.environ["CANDIDATE_SOURCE"])
                replacement = source.with_name("candidate.replacement")
                replacement.write_bytes(source.read_bytes())
                os.replace(replacement, source)
            """
        )

        result = self.run_apply(
            environment=self.helper_environment(
                CANDIDATE_SOURCE=str(self.candidate),
            )
        )

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "candidate_source_changed")
        self.assertEqual(
            payload["mismatched_properties"],
            ["object_identity"],
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assert_no_private_stage()

    def test_candidate_changed_by_validator_is_rejected_before_lock(self) -> None:
        self.write_validator(
            """\
            import os
            from pathlib import Path
            import sys

            path = Path(sys.argv[1])
            fd = int(path.name)
            os.ftruncate(fd, 0)
            os.pwrite(fd, b"validator changed candidate\\n", 0)
            """
        )

        result = self.run_apply()

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "validator_input_changed")
        self.assertIn("content", payload["mismatched_properties"])
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())
        self.assert_no_private_stage()

    def test_candidate_access_change_via_inherited_fd_is_rejected(self) -> None:
        self.write_validator(
            """\
            import os
            from pathlib import Path
            import sys

            fd = int(Path(sys.argv[1]).name)
            os.fchmod(fd, 0o640)
            """
        )

        result = self.run_apply()

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "validator_input_changed")
        self.assertEqual(payload["mismatched_properties"], ["access_policy"])
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())
        self.assert_no_private_stage()

    def test_anonymous_validator_input_rejects_object_policy_drift(self) -> None:
        with TRANSACTION.AnonymousValidatorInput(NEW_RULES) as validator_input:
            real_read_bound_fd = TRANSACTION.read_bound_fd

            def report_added_link(
                fd: int,
                *,
                label: str,
                max_bytes: int = TRANSACTION.MAX_RULES_BYTES,
            ) -> tuple[bytes, object]:
                payload, actual = real_read_bound_fd(
                    fd,
                    label=label,
                    max_bytes=max_bytes,
                )
                if fd == validator_input.fd:
                    actual = TRANSACTION.Snapshot(
                        device=actual.device,
                        inode=actual.inode,
                        size=actual.size,
                        sha256=actual.sha256,
                        mode=actual.mode,
                        uid=actual.uid,
                        gid=actual.gid,
                        nlink=(actual.nlink or 0) + 1,
                    )
                return payload, actual

            with (
                mock.patch.object(
                    TRANSACTION,
                    "read_bound_fd",
                    side_effect=report_added_link,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                validator_input.validate()

        self.assertEqual(raised.exception.status, "validator_input_changed")
        self.assertIn(
            "object_policy",
            raised.exception.details["mismatched_properties"],
        )

    def test_rejected_unchanged_candidate_stage_is_removed(self) -> None:
        self.write_validator("raise SystemExit(7)\n")

        result = self.run_apply()

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "candidate_validation_failed")
        self.assertEqual(payload["validator"]["returncode"], 7)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assert_no_private_stage()

    def test_repeated_validation_failures_do_not_consume_stage_capacity(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(7)\n")

        for attempt in range(12):
            with self.subTest(attempt=attempt):
                result = self.run_apply()
                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertEqual(
                    json.loads(result.stdout)["status"],
                    "candidate_validation_failed",
                )
                self.assertFalse(self.receipt.exists())
                self.assert_no_private_stage()

        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(json.loads(applied.stdout)["status"], "applied")
        self.assert_no_private_stage()

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

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "candidate_validation_failed")
        self.assertNotEqual(payload["validator"]["returncode"], 0)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assert_no_private_stage()

    def test_candidate_xattr_injected_by_validator_is_rejected_before_lock(
        self,
    ) -> None:
        self.write_validator(self.xattr_validator_source())

        result = self.run_apply()

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn(
            payload["status"],
            {"candidate_validation_failed", "validator_input_changed"},
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())

    def test_candidate_acl_injected_by_validator_is_rejected_before_lock(
        self,
    ) -> None:
        self.write_validator(self.acl_validator_source())

        result = self.run_apply()

        self.assertEqual(result.returncode, 10, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn(
            payload["status"],
            {"candidate_validation_failed", "validator_input_changed"},
        )
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
        self.assert_no_private_stage()

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

    def test_evidence_close_attempts_every_fd_after_baseexception(self) -> None:
        stage, evidence = self.create_apply_evidence()
        assert evidence.receipt is not None
        receipt_fd = evidence.receipt.fd
        expected_closed = (
            evidence.recovery_terminal.fd,
            evidence.receipt_parent.fd,
            evidence.rules_parent.fd,
        )
        real_close = TRANSACTION.os.close
        interrupted = False

        def interrupt_first_close(fd: int) -> None:
            nonlocal interrupted
            if fd == receipt_fd and not interrupted:
                interrupted = True
                raise KeyboardInterrupt("fault-injected evidence close")
            real_close(fd)

        try:
            with (
                mock.patch.object(
                    TRANSACTION.os,
                    "close",
                    side_effect=interrupt_first_close,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                evidence.close()

            for fd in expected_closed:
                with self.assertRaises(OSError) as closed:
                    os.fstat(fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)
        finally:
            real_close(receipt_fd)
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

    def test_validator_waitid_failure_still_terminates_and_reaps(self) -> None:
        pid_path = self.root / "validator-waitid-failure.pid"
        self.write_sleeping_validator(pid_path)

        def fail_waitid(*_args: object, **_kwargs: object) -> None:
            self.wait_for_pid_path(pid_path)
            raise OSError(errno.EIO, "fault-injected waitid failure")

        with (
            mock.patch.object(
                TRANSACTION.os,
                "waitid",
                side_effect=fail_waitid,
            ),
            self.assertRaises(OSError),
        ):
            TRANSACTION.run_validator(
                [sys.executable, str(self.validator), "{rules}"],
                self.candidate,
                timeout_seconds=2,
            )

        self.assert_process_exited(self.wait_for_pid_path(pid_path))

    def test_validator_inventory_failure_still_terminates_and_reaps(self) -> None:
        pid_path = self.root / "validator-inventory-failure.pid"
        self.write_sleeping_validator(pid_path)

        def fail_inventory(*_args: object, **_kwargs: object) -> tuple[int, ...]:
            self.wait_for_pid_path(pid_path)
            raise TRANSACTION.TransactionError(
                "validator_cleanup_failed",
                "fault-injected process inventory failure",
            )

        with (
            mock.patch.object(
                TRANSACTION,
                "_live_validator_group_member_pids",
                side_effect=fail_inventory,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.run_validator(
                [sys.executable, str(self.validator), "{rules}"],
                self.candidate,
                timeout_seconds=0.1,
            )

        self.assertEqual(raised.exception.status, "validator_cleanup_failed")
        self.assert_process_exited(self.wait_for_pid_path(pid_path))

    def test_validator_signal_failure_still_terminates_and_reaps(self) -> None:
        pid_path = self.root / "validator-signal-failure.pid"
        self.write_sleeping_validator(pid_path)

        def fail_signal(*_args: object, **_kwargs: object) -> None:
            self.wait_for_pid_path(pid_path)
            raise TRANSACTION.TransactionError(
                "validator_cleanup_failed",
                "fault-injected managed signal failure",
            )

        with (
            mock.patch.object(
                TRANSACTION,
                "_signal_validator_group",
                side_effect=fail_signal,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.run_validator(
                [sys.executable, str(self.validator), "{rules}"],
                self.candidate,
                timeout_seconds=0.1,
            )

        self.assertEqual(raised.exception.status, "validator_cleanup_failed")
        self.assert_process_exited(self.wait_for_pid_path(pid_path))

    @unittest.skipUnless(hasattr(signal, "SIGCHLD"), "POSIX SIGCHLD required")
    def test_validator_rejects_external_sigchld_reaping_policy(self) -> None:
        real_getsignal = TRANSACTION.signal.getsignal

        def nondefault_sigchld(signum: int) -> object:
            if signum == signal.SIGCHLD:
                return signal.SIG_IGN
            return real_getsignal(signum)

        with (
            mock.patch.object(
                TRANSACTION.signal,
                "getsignal",
                side_effect=nondefault_sigchld,
            ),
            mock.patch.object(TRANSACTION.subprocess, "Popen") as popen,
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.run_validator(
                [sys.executable, str(self.validator), "{rules}"],
                self.candidate,
                timeout_seconds=2,
            )

        self.assertEqual(
            raised.exception.status,
            "validator_supervision_unsupported",
        )
        self.assertIn("SIGCHLD", str(raised.exception))
        popen.assert_not_called()

    def test_normal_cleanup_never_uses_pgid_after_leader_reap(self) -> None:
        state = {"reaped": False, "inventory_calls": 0}

        class FakeProcess:
            pid = 424_242
            returncode: int | None = None

            def wait(self, timeout: float) -> int:
                self.returncode = 0
                state["reaped"] = True
                return 0

        class FakeObserver:
            @staticmethod
            def child_exited() -> bool:
                return True

        process = FakeProcess()
        selector = mock.Mock()
        selector.get_map.return_value = {}

        def inventory(
            process_group_id: int,
            *,
            leader_pid: int,
        ) -> tuple[int, ...]:
            self.assertFalse(
                state["reaped"],
                "a reused numeric PGID was inspected after leader reap",
            )
            self.assertEqual(process_group_id, process.pid)
            self.assertEqual(leader_pid, process.pid)
            state["inventory_calls"] += 1
            return (515_151,) if state["inventory_calls"] == 1 else ()

        def signal_group(
            process_group_id: int,
            signum: int,
            *,
            allow_zombie_only: bool = False,
        ) -> None:
            self.assertFalse(
                state["reaped"],
                "a reused numeric PGID was signaled after leader reap",
            )
            self.assertEqual(process_group_id, process.pid)
            self.assertIn(signum, (signal.SIGTERM, signal.SIGKILL))
            self.assertTrue(allow_zombie_only)

        with (
            mock.patch.object(
                TRANSACTION,
                "VALIDATOR_TERM_GRACE_SECONDS",
                0,
            ),
            mock.patch.object(
                TRANSACTION,
                "_live_validator_group_member_pids",
                side_effect=inventory,
            ),
            mock.patch.object(
                TRANSACTION,
                "_signal_validator_group",
                side_effect=signal_group,
            ),
        ):
            returncode, descendants_terminated = (
                TRANSACTION._stop_validator_process_group(
                    process,
                    FakeObserver(),
                    selector,
                    {"stdout": bytearray(), "stderr": bytearray()},
                    max_output_bytes=TRANSACTION.MAX_VALIDATOR_OUTPUT_BYTES,
                )
            )

        self.assertEqual(returncode, 0)
        self.assertTrue(descendants_terminated)
        self.assertTrue(state["reaped"])
        self.assertGreaterEqual(state["inventory_calls"], 3)

    def test_normal_cleanup_accepts_verified_zombie_only_eperm_race(self) -> None:
        state = {"exit_probes": 0, "reaped": False}

        class FakeProcess:
            pid = 525_252
            returncode: int | None = None

            def wait(self, timeout: float) -> int:
                self.returncode = 0
                state["reaped"] = True
                return 0

        class FakeObserver:
            @staticmethod
            def child_exited() -> bool:
                state["exit_probes"] += 1
                return state["exit_probes"] > 1

        selector = mock.Mock()
        selector.get_map.return_value = {}
        permission_error = PermissionError(
            errno.EPERM,
            "fault-injected zombie-only process group",
        )

        with (
            mock.patch.object(
                TRANSACTION,
                "VALIDATOR_TERM_GRACE_SECONDS",
                0,
            ),
            mock.patch.object(
                TRANSACTION,
                "VALIDATOR_KILL_DRAIN_SECONDS",
                0,
            ),
            mock.patch.object(
                TRANSACTION,
                "_live_validator_group_member_pids",
                return_value=(),
            ),
            mock.patch.object(
                TRANSACTION.os,
                "killpg",
                side_effect=permission_error,
            ) as killpg,
        ):
            returncode, descendants_terminated = (
                TRANSACTION._stop_validator_process_group(
                    FakeProcess(),
                    FakeObserver(),
                    selector,
                    {"stdout": bytearray(), "stderr": bytearray()},
                    max_output_bytes=TRANSACTION.MAX_VALIDATOR_OUTPUT_BYTES,
                )
            )

        self.assertEqual(returncode, 0)
        self.assertFalse(descendants_terminated)
        self.assertTrue(state["reaped"])
        self.assertGreaterEqual(state["exit_probes"], 2)
        killpg.assert_called_once_with(FakeProcess.pid, signal.SIGTERM)

    def test_emergency_cleanup_never_signals_pgid_after_leader_reap(self) -> None:
        state = {"reaped": False}

        class FakeProcess:
            pid = 626_262
            returncode: int | None = None

            def wait(self, timeout: float) -> int:
                self.returncode = 0
                state["reaped"] = True
                return 0

        def kill_group(process_group_id: int, signum: int) -> None:
            self.assertFalse(
                state["reaped"],
                "a reused numeric PGID was signaled after leader reap",
            )
            self.assertEqual(process_group_id, FakeProcess.pid)
            self.assertIn(signum, (signal.SIGTERM, signal.SIGKILL))

        with (
            mock.patch.object(
                TRANSACTION,
                "VALIDATOR_TERM_GRACE_SECONDS",
                0,
            ),
            mock.patch.object(
                TRANSACTION,
                "VALIDATOR_KILL_DRAIN_SECONDS",
                0,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "killpg",
                side_effect=kill_group,
            ) as killpg,
        ):
            cleanup_errors = TRANSACTION._emergency_stop_validator_process_group(
                FakeProcess(),
                None,
                {"stdout": bytearray(), "stderr": bytearray()},
                max_output_bytes=TRANSACTION.MAX_VALIDATOR_OUTPUT_BYTES,
            )

        self.assertEqual(cleanup_errors, [])
        self.assertTrue(state["reaped"])
        self.assertEqual(killpg.call_count, 3)

    def test_reaped_leader_refuses_late_emergency_pgid_cleanup(self) -> None:
        process = SimpleNamespace(pid=737_373, returncode=0)

        with mock.patch.object(TRANSACTION.os, "killpg") as killpg:
            cleanup_errors = TRANSACTION._emergency_stop_validator_process_group(
                process,
                None,
                {"stdout": bytearray(), "stderr": bytearray()},
                max_output_bytes=TRANSACTION.MAX_VALIDATOR_OUTPUT_BYTES,
            )

        killpg.assert_not_called()
        self.assertEqual(
            cleanup_errors[0]["operation"],
            "process-group-identity-anchor",
        )

    def test_validator_cancellation_still_terminates_and_reaps(self) -> None:
        pid_path = self.root / "validator-cancellation.pid"
        self.write_sleeping_validator(pid_path)

        def interrupt_read(*_args: object, **_kwargs: object) -> tuple[bool, bool]:
            self.wait_for_pid_path(pid_path)
            raise KeyboardInterrupt

        with (
            mock.patch.object(
                TRANSACTION,
                "_read_validator_events",
                side_effect=interrupt_read,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            TRANSACTION.run_validator(
                [sys.executable, str(self.validator), "{rules}"],
                self.candidate,
                timeout_seconds=2,
            )

        self.assert_process_exited(self.wait_for_pid_path(pid_path))

    def test_validator_cancellation_cleans_same_group_descendant(self) -> None:
        leader_pid_path = self.root / "validator-cancel-leader.pid"
        child_pid_path = self.root / "validator-cancel-child.pid"
        child_script = self.root / "validator-cancel-child.py"
        child_script.write_text(
            textwrap.dedent(
                f"""\
                from pathlib import Path
                import os
                import time

                Path({str(child_pid_path)!r}).write_text(
                    str(os.getpid()),
                    encoding="ascii",
                )
                while True:
                    time.sleep(1)
                """
            ),
            encoding="utf-8",
        )
        self.write_validator(
            f"""\
            from pathlib import Path
            import os
            import subprocess
            import sys
            import time

            Path({str(leader_pid_path)!r}).write_text(
                str(os.getpid()),
                encoding="ascii",
            )
            subprocess.Popen([sys.executable, {str(child_script)!r}])
            while True:
                time.sleep(1)
            """
        )

        def interrupt_read(*_args: object, **_kwargs: object) -> tuple[bool, bool]:
            self.wait_for_pid_path(child_pid_path)
            raise KeyboardInterrupt

        with (
            mock.patch.object(
                TRANSACTION,
                "_read_validator_events",
                side_effect=interrupt_read,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            TRANSACTION.run_validator(
                [sys.executable, str(self.validator), "{rules}"],
                self.candidate,
                timeout_seconds=2,
            )

        self.assert_process_exited(self.wait_for_pid_path(leader_pid_path))
        self.assert_process_exited(self.wait_for_pid_path(child_pid_path))

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "validator signal supervision requires POSIX signal masks",
    )
    def test_real_managed_signal_waits_for_validator_group_cleanup(self) -> None:
        leader_pid_path = self.root / "validator-signal-leader.pid"
        child_pid_path = self.root / "validator-signal-child.pid"
        ready_path = self.root / "validator-signal.ready"
        leader_term_path = self.root / "validator-signal-leader.term"
        child_term_path = self.root / "validator-signal-child.term"
        child_script = self.root / "validator-signal-child.py"
        child_script.write_text(
            textwrap.dedent(
                f"""\
                from pathlib import Path
                import os
                import signal
                import time

                term_path = Path({str(child_term_path)!r})

                def record_term(_signum, _frame):
                    term_path.write_text("term", encoding="ascii")

                signal.signal(signal.SIGTERM, record_term)
                Path({str(child_pid_path)!r}).write_text(
                    str(os.getpid()),
                    encoding="ascii",
                )
                while True:
                    time.sleep(1)
                """
            ),
            encoding="utf-8",
        )
        self.write_validator(
            f"""\
            from pathlib import Path
            import os
            import signal
            import subprocess
            import sys
            import time

            term_path = Path({str(leader_term_path)!r})

            def record_term(_signum, _frame):
                term_path.write_text("term", encoding="ascii")

            signal.signal(signal.SIGTERM, record_term)
            Path({str(leader_pid_path)!r}).write_text(
                str(os.getpid()),
                encoding="ascii",
            )
            subprocess.Popen([sys.executable, {str(child_script)!r}])
            child_pid_path = Path({str(child_pid_path)!r})
            while not child_pid_path.exists():
                time.sleep(0.01)
            Path({str(ready_path)!r}).write_text("ready", encoding="ascii")
            while True:
                time.sleep(1)
            """
        )
        command = [
            sys.executable,
            str(HELPER),
            "apply",
            "--candidate",
            str(self.candidate),
            "--candidate-sha256",
            hashlib.sha256(NEW_RULES).hexdigest(),
            "--expected-sha256",
            hashlib.sha256(OLD_RULES).hexdigest(),
            "--backup-name",
            self.backup_name,
            "--receipt",
            str(self.receipt),
            "--validator-timeout-seconds=5",
            "--lock-timeout-seconds",
            "2",
            "--",
            sys.executable,
            str(self.validator),
            "{rules}",
        ]

        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=signal.Signals(signum).name):
                for path in (
                    leader_pid_path,
                    child_pid_path,
                    ready_path,
                    leader_term_path,
                    child_term_path,
                ):
                    path.unlink(missing_ok=True)
                process = subprocess.Popen(
                    command,
                    env=self.helper_environment(),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                leader_pid: int | None = None
                child_pid: int | None = None
                try:
                    self.wait_for_path(ready_path, label="validator process group")
                    leader_pid = self.wait_for_pid_path(leader_pid_path)
                    child_pid = self.wait_for_pid_path(child_pid_path)
                    process.send_signal(signum)
                    stdout, stderr = process.communicate(timeout=8)

                    self.assertEqual(process.returncode, 128 + signum, stderr)
                    payload = json.loads(stdout)
                    self.assertEqual(payload["status"], "interrupted")
                    self.assertEqual(payload["signal"], signum)
                    self.assertEqual(
                        payload["signal_name"],
                        signal.Signals(signum).name,
                    )
                    self.assertNotIn("Traceback", stderr)
                    self.assert_process_exited(leader_pid)
                    self.assert_process_exited(child_pid)
                    self.assertTrue(leader_term_path.is_file())
                    self.assertTrue(child_term_path.is_file())
                    self.assertFalse(self.backup.exists())
                    self.assertFalse(self.receipt.exists())
                    self.assert_no_private_stage()
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=2)
                    if leader_pid is not None:
                        try:
                            os.killpg(leader_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "validator signal supervision requires POSIX signal masks",
    )
    def test_real_signal_in_popen_handoff_is_deferred_until_cleanup(self) -> None:
        leader_pid_path = self.root / "validator-handoff-leader.pid"
        driver = self.root / "validator-handoff-driver.py"
        self.write_validator(
            """\
            import time

            while True:
                time.sleep(1)
            """
        )
        driver.write_text(
            textwrap.dedent(
                f"""\
                import importlib.util
                import json
                import os
                from pathlib import Path
                import signal
                import sys

                spec = importlib.util.spec_from_file_location(
                    "handoff_transaction",
                    {str(HELPER)!r},
                )
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                real_popen = module.subprocess.Popen

                def signal_before_return(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    Path({str(leader_pid_path)!r}).write_text(
                        str(process.pid),
                        encoding="ascii",
                    )
                    os.kill(os.getpid(), signal.SIGTERM)
                    return process

                module.subprocess.Popen = signal_before_return
                try:
                    module.run_validator(
                        [
                            sys.executable,
                            {str(self.validator)!r},
                            "{{rules}}",
                        ],
                        Path({str(self.candidate)!r}),
                        timeout_seconds=5,
                    )
                except module.ForwardedValidatorSignal as event:
                    print(
                        json.dumps(
                            {{
                                "status": "interrupted",
                                "signal": event.signum,
                            }}
                        )
                    )
                    raise SystemExit(128 + event.signum)
                raise SystemExit(99)
                """
            ),
            encoding="utf-8",
        )
        leader_pid: int | None = None
        try:
            result = subprocess.run(
                [sys.executable, str(driver)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            leader_pid = self.wait_for_pid_path(leader_pid_path)

            self.assertEqual(result.returncode, 128 + signal.SIGTERM, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "interrupted")
            self.assertNotIn("Traceback", result.stderr)
            self.assert_process_exited(leader_pid)
        finally:
            if leader_pid is not None:
                try:
                    os.killpg(leader_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "validator signal supervision requires POSIX signal masks",
    )
    def test_validator_restores_signal_handlers_and_mask(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        previous_handlers = {
            signum: signal.getsignal(signum)
            for signum in TRANSACTION.MANAGED_VALIDATOR_SIGNALS
        }
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        result = TRANSACTION.run_validator(
            [sys.executable, str(self.validator), "{rules}"],
            self.candidate,
            timeout_seconds=2,
        )

        self.assertTrue(result.valid)
        self.assertEqual(
            {
                signum: signal.getsignal(signum)
                for signum in TRANSACTION.MANAGED_VALIDATOR_SIGNALS
            },
            previous_handlers,
        )
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "validator signal supervision requires POSIX signal masks",
    )
    def test_validator_launch_failure_restores_signal_handlers_and_mask(
        self,
    ) -> None:
        previous_handlers = {
            signum: signal.getsignal(signum)
            for signum in TRANSACTION.MANAGED_VALIDATOR_SIGNALS
        }
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        with (
            mock.patch.object(
                TRANSACTION.subprocess,
                "Popen",
                side_effect=FileNotFoundError(errno.ENOENT, "fault-injected"),
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.run_validator(
                [sys.executable, str(self.validator), "{rules}"],
                self.candidate,
                timeout_seconds=2,
            )

        self.assertEqual(raised.exception.status, "validator_launch_failed")
        self.assertEqual(
            {
                signum: signal.getsignal(signum)
                for signum in TRANSACTION.MANAGED_VALIDATOR_SIGNALS
            },
            previous_handlers,
        )
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

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
            if path.name != "default.rules":
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
        validator_marker = self.root / "validator-ran"
        self.write_validator(
            f"""\
            from pathlib import Path

            Path({str(validator_marker)!r}).write_text("ran", encoding="ascii")
            raise SystemExit(9)
            """
        )

        result = self.run_apply()

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "no_change_after_lock")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(TRANSACTION.recovery_terminal_path(self.receipt).exists())
        self.assertTrue((self.rules_dir / ".default.rules.apply.lock").is_file())
        self.assertFalse(validator_marker.exists())
        self.assert_no_private_stage()

    def test_no_change_refuses_retained_fixed_stage_evidence(self) -> None:
        self.candidate.write_bytes(OLD_RULES)
        validator_marker = self.root / "validator-ran"
        self.write_validator(
            f"""\
            from pathlib import Path

            Path({str(validator_marker)!r}).write_text("ran", encoding="ascii")
            """
        )
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        retained = stage / "candidate"
        retained.write_bytes(NEW_RULES)
        retained.chmod(0o600)

        result = self.run_apply()

        self.assertEqual(result.returncode, 30, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["stage_status"], "private_stage_retained")
        self.assertFalse(validator_marker.exists())
        self.assertEqual(retained.read_bytes(), NEW_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())

    def test_concurrent_no_change_revalidates_candidate_source(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_revalidate = TRANSACTION.revalidate_candidate_source
        revalidation_count = 0

        def install_expected_live(
            _command: list[str],
            _path: Path,
            *,
            timeout_seconds: float,
            pass_fds: tuple[int, ...] = (),
        ) -> object:
            del timeout_seconds, pass_fds
            replacement = self.rules_dir / ".concurrent-expected-live"
            replacement.write_bytes(NEW_RULES)
            replacement.chmod(0o640)
            os.replace(replacement, self.rules)
            return TRANSACTION.ValidatorResult(0, "", "")

        def replace_source_on_second_revalidation(
            path: Path,
            expected: object,
            *,
            candidate_sha256: str,
        ) -> bytes:
            nonlocal revalidation_count
            revalidation_count += 1
            if revalidation_count == 2:
                replacement = self.root / "candidate.replacement"
                replacement.write_bytes(self.candidate.read_bytes())
                os.replace(replacement, self.candidate)
            return real_revalidate(
                path,
                expected,
                candidate_sha256=candidate_sha256,
            )

        namespace = self.apply_namespace()
        namespace.expected_sha256 = hashlib.sha256(NEW_RULES).hexdigest()
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "run_validator",
                side_effect=install_expected_live,
            ),
            mock.patch.object(
                TRANSACTION,
                "revalidate_candidate_source",
                side_effect=replace_source_on_second_revalidation,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(namespace)

        self.assertEqual(raised.exception.status, "candidate_source_changed")
        self.assertEqual(
            raised.exception.details["mismatched_properties"],
            ["object_identity"],
        )
        self.assertEqual(revalidation_count, 2)
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assert_no_private_stage()

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
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)
        self.assertTrue(self.receipt.is_file())
        self.assert_no_private_stage()

    def test_rollback_post_exchange_fsync_failure_requires_recovery(self) -> None:
        self.write_validator(
            """\
            from pathlib import Path
            import sys

            if Path(sys.argv[1]).name == "default.rules":
                raise SystemExit(9)
            """
        )
        real_exchange = TRANSACTION.atomic_rename_exchange
        real_fsync = TRANSACTION.os.fsync
        rollback_parent_fd: int | None = None
        rollback_exchange_completed = False
        failure_injected = False

        def observe_exchange(
            source_dir_fd: int,
            source_name: str,
            destination_dir_fd: int,
            destination_name: str,
        ) -> None:
            nonlocal rollback_exchange_completed, rollback_parent_fd
            real_exchange(
                source_dir_fd,
                source_name,
                destination_dir_fd,
                destination_name,
            )
            if source_name == self.backup.name and destination_name == self.rules.name:
                rollback_parent_fd = source_dir_fd
                rollback_exchange_completed = True

        def fail_rollback_parent_fsync(fd: int) -> None:
            nonlocal failure_injected
            if (
                rollback_exchange_completed
                and fd == rollback_parent_fd
                and not failure_injected
            ):
                failure_injected = True
                raise OSError(
                    errno.EIO,
                    "fault-injected rollback parent fsync failure",
                )
            real_fsync(fd)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
                side_effect=observe_exchange,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=fail_rollback_parent_fsync,
            ),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(failure_injected)
        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["rollback"]["rollback_status"],
            "recovery_required",
        )
        self.assertEqual(
            payload["rollback"]["recovery_reason"],
            "rollback_failed",
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["status"], "recovered")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)
        self.assert_no_private_stage()

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
                    if path.name != "default.rules":
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

    def test_recover_converges_every_schema_v3_transaction_state(self) -> None:
        for state in ("P", "X", "C", "R"):
            with (
                self.subTest(state=state),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-recovery-state-{state}."
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
                self.receipt = case_root / "task" / "recovery.json"
                self.receipt.parent.mkdir(mode=0o700)
                self.backup_name = f"default.rules.bak-state-{state}"
                self.backup = self.rules_dir / self.backup_name
                self.validator = case_root / "validator.py"
                self.write_validator("raise SystemExit(0)\n")

                applied = self.run_apply()
                self.assertEqual(applied.returncode, 0, applied.stderr)
                receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
                stage_root = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
                receipt["schema_version"] = 3
                receipt["staged_backup_parent"] = TRANSACTION.Snapshot.from_stat(
                    stage_root.stat(follow_symlinks=False),
                    b"",
                ).to_json()
                receipt.pop("prepared_candidate_path", None)
                receipt.pop("prepared_candidate_parent", None)
                self.receipt.write_text(
                    json.dumps(receipt, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                self.receipt.chmod(0o600)
                staged = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
                if state in ("P", "X"):
                    os.rename(self.backup, staged)
                if state == "P":
                    stage_fd = os.open(
                        staged.parent,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )
                    rules_fd = os.open(
                        self.rules_dir,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )
                    try:
                        TRANSACTION.atomic_rename_exchange(
                            stage_fd,
                            staged.name,
                            rules_fd,
                            self.rules.name,
                        )
                    finally:
                        os.close(rules_fd)
                        os.close(stage_fd)
                elif state == "R":
                    rules_fd = os.open(
                        self.rules_dir,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )
                    try:
                        TRANSACTION.atomic_rename_exchange(
                            rules_fd,
                            self.backup.name,
                            rules_fd,
                            self.rules.name,
                        )
                    finally:
                        os.close(rules_fd)

                recovered = self.run_recover()

                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assertEqual(
                    json.loads(recovered.stdout)["status"],
                    "recovered",
                )
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertEqual(self.backup.read_bytes(), NEW_RULES)
                self.assert_no_private_stage()

                repeated = self.run_recover()
                self.assertEqual(repeated.returncode, 0, repeated.stderr)
                self.assertEqual(
                    json.loads(repeated.stdout)["status"],
                    "already_original",
                )

    def test_post_exchange_backup_publication_failure_is_recoverable(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stderr = io.StringIO()

        def refuse_publication(
            _stage: object,
            _path: Path,
            _backup: Path,
        ) -> object:
            raise TRANSACTION.TransactionError(
                "atomic_no_replace_failed",
                "fault-injected publication failure",
            )

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "publish_backup",
                autospec=True,
                side_effect=refuse_publication,
            ),
            redirect_stderr(stderr),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertFalse(self.backup.exists())
        staged = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
        self.assertEqual(staged.read_bytes(), OLD_RULES)
        cleanup = json.loads(stderr.getvalue().strip())
        self.assertTrue(
            any(
                warning["status"] == "retained_staged_file"
                for warning in cleanup["warnings"]
            )
        )

        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["status"], "recovered")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)
        self.assert_no_private_stage()

    def test_recovery_publication_fsync_failure_records_committed_state(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        staged = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
        os.rename(self.backup, staged)

        real_publish = TRANSACTION.PrivateStage.publish_backup
        real_fsync = TRANSACTION.os.fsync
        published_stage: object | None = None
        failure_injected = False

        def observe_publication(
            stage: object,
            path: Path,
            backup: Path,
        ) -> object:
            nonlocal published_stage
            assert isinstance(stage, TRANSACTION.PrivateStage)
            result = real_publish(stage, path, backup)
            published_stage = stage
            return result

        def fail_first_stage_fsync(fd: int) -> None:
            nonlocal failure_injected
            if (
                isinstance(published_stage, TRANSACTION.PrivateStage)
                and fd == published_stage.stage_fd
                and not failure_injected
            ):
                failure_injected = True
                raise OSError(
                    errno.EIO,
                    "fault-injected recovery stage fsync failure",
                )
            real_fsync(fd)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "publish_backup",
                autospec=True,
                side_effect=observe_publication,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=fail_first_stage_fsync,
            ),
        ):
            exit_code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(failure_injected)
        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["transaction_state"], "C")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assert_no_private_stage()

        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["status"], "recovered")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)
        self.assert_no_private_stage()

    def test_post_publication_stage_fsync_failure_requires_recovery(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_publish = TRANSACTION.PrivateStage.publish_backup
        real_fsync = TRANSACTION.os.fsync
        published_stage: object | None = None
        failure_injected = False

        def observe_publication(
            stage: object,
            path: Path,
            backup: Path,
        ) -> object:
            nonlocal published_stage
            assert isinstance(stage, TRANSACTION.PrivateStage)
            result = real_publish(stage, path, backup)
            published_stage = stage
            return result

        def fail_first_stage_fsync(fd: int) -> None:
            nonlocal failure_injected
            if (
                isinstance(published_stage, TRANSACTION.PrivateStage)
                and fd == published_stage.stage_fd
                and not failure_injected
            ):
                failure_injected = True
                raise OSError(errno.EIO, "fault-injected stage fsync failure")
            real_fsync(fd)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "publish_backup",
                autospec=True,
                side_effect=observe_publication,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=fail_first_stage_fsync,
            ),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(failure_injected)
        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["post_replace_failure"]["status"],
            "backup_publication_fsync_failed",
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assert_no_private_stage()

        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_receipt_and_backup_publication_fsync_both_directories(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        events: list[str] = []
        stage_fds: dict[str, int] = {}
        real_stage_init = TRANSACTION.PrivateStage.__init__
        real_prepared_move = TRANSACTION.move_prepared_candidate_to_stage
        real_publish = TRANSACTION.PrivateStage.publish_backup
        real_write_receipt = TRANSACTION.write_receipt
        real_fsync = TRANSACTION.os.fsync
        real_fsync_live = TRANSACTION.fsync_file_and_parent

        def observe_stage_init(
            stage: object,
            *args: object,
            **kwargs: object,
        ) -> None:
            events.append("stage_init_begin")
            real_stage_init(stage, *args, **kwargs)
            assert isinstance(stage, TRANSACTION.PrivateStage)
            stage_fds["stage"] = stage.stage_fd
            stage_fds["rules"] = stage.rules_parent_fd
            events.append("stage_init_end")

        def observe_prepared_move(
            *args: object,
            **kwargs: object,
        ) -> tuple[Path, object]:
            events.append("prepared_move_begin")
            result = real_prepared_move(*args, **kwargs)
            events.append("prepared_move_end")
            return result

        def observe_publish(
            stage: object,
            path: Path,
            backup: Path,
        ) -> object:
            assert isinstance(stage, TRANSACTION.PrivateStage)
            events.append("publish_begin")
            result = real_publish(stage, path, backup)
            events.append("publish_end")
            return result

        def observe_receipt(*args: object, **kwargs: object) -> object:
            events.append("receipt_begin")
            result = real_write_receipt(*args, **kwargs)
            events.append("receipt_end")
            return result

        def observe_fsync(fd: int) -> None:
            for label, expected_fd in stage_fds.items():
                if fd == expected_fd:
                    events.append(f"fsync_{label}")
            real_fsync(fd)

        def observe_live_fsync(path: Path) -> None:
            events.append("live_fsync_begin")
            real_fsync_live(path)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "__init__",
                autospec=True,
                side_effect=observe_stage_init,
            ),
            mock.patch.object(
                TRANSACTION,
                "move_prepared_candidate_to_stage",
                side_effect=observe_prepared_move,
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "publish_backup",
                autospec=True,
                side_effect=observe_publish,
            ),
            mock.patch.object(
                TRANSACTION,
                "write_receipt",
                side_effect=observe_receipt,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=observe_fsync,
            ),
            mock.patch.object(
                TRANSACTION,
                "fsync_file_and_parent",
                side_effect=observe_live_fsync,
            ),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "applied")
        self.assertLess(
            events.index("receipt_end"),
            events.index("stage_init_begin"),
        )
        self.assertLess(
            events.index("stage_init_end"),
            events.index("prepared_move_begin"),
        )
        publication_end = events.index("publish_end")
        live_fsync_begin = events.index("live_fsync_begin")
        publication_durability = events[publication_end + 1 : live_fsync_begin]
        self.assertIn("fsync_stage", publication_durability)
        self.assertIn("fsync_rules", publication_durability)

    def assert_receipt_fault_precedes_private_stage(self, fault: str) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_write_receipt = TRANSACTION.write_receipt
        real_write = TRANSACTION.os.write
        real_fsync = TRANSACTION.os.fsync

        def faulting_receipt(
            path: Path,
            payload: dict[str, object],
            parent: object,
        ) -> object:
            assert isinstance(parent, TRANSACTION.BoundDirectory)
            injected = False

            def fail_write(fd: int, data: bytes) -> int:
                nonlocal injected
                if fault == "write" and not injected:
                    injected = True
                    raise OSError(errno.EIO, "fault-injected receipt write")
                return real_write(fd, data)

            def fail_fsync(fd: int) -> None:
                nonlocal injected
                is_parent = fd == parent.fd
                if not injected and (
                    (fault == "file_fsync" and not is_parent)
                    or (fault == "parent_fsync" and is_parent)
                ):
                    injected = True
                    raise OSError(errno.EIO, f"fault-injected receipt {fault}")
                real_fsync(fd)

            with (
                mock.patch.object(
                    TRANSACTION.os,
                    "write",
                    side_effect=fail_write,
                ),
                mock.patch.object(
                    TRANSACTION.os,
                    "fsync",
                    side_effect=fail_fsync,
                ),
            ):
                return real_write_receipt(path, payload, parent)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "write_receipt",
                side_effect=faulting_receipt,
            ),
            self.assertRaises((OSError, TRANSACTION.TransactionError)),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertTrue(prepared.is_file())
        self.assertEqual(prepared.read_bytes(), NEW_RULES)
        self.assertTrue(terminal.is_file())
        self.assertFalse((self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME).exists())

    def test_receipt_write_failure_precedes_private_stage(self) -> None:
        self.assert_receipt_fault_precedes_private_stage("write")

    def test_receipt_file_fsync_failure_precedes_private_stage(self) -> None:
        self.assert_receipt_fault_precedes_private_stage("file_fsync")

    def test_receipt_parent_fsync_failure_precedes_private_stage(self) -> None:
        self.assert_receipt_fault_precedes_private_stage("parent_fsync")

    def test_schema_v4_q_recovery_is_idempotent_after_stage_creation_failure(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "__init__",
                side_effect=TRANSACTION.TransactionError(
                    "private_stage_unavailable",
                    "fault-injected stage creation failure",
                ),
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.exit_code, 30)
        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(prepared.is_file())
        self.assertFalse((self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME).exists())

        with mock.patch.dict(
            os.environ,
            {"CODEX_HOME": str(self.codex_home)},
        ):
            first_code, first = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )
            second_code, second = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertEqual(first_code, 0)
        self.assertEqual(first["status"], "recovered")
        self.assertEqual(first["transaction_state"], "Q")
        self.assertEqual(second_code, 0)
        self.assertEqual(second["status"], "already_original")
        self.assertEqual(second["transaction_state"], "Q")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(prepared.read_bytes(), NEW_RULES)

    def test_schema_v4_p_recovery_after_move_fsync_failure(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_move = TRANSACTION.move_prepared_candidate_to_stage
        real_fsync = TRANSACTION.os.fsync
        stage_fd: int | None = None
        injected = False

        def observe_move(*args: object, **kwargs: object) -> object:
            nonlocal stage_fd
            result = real_move(*args, **kwargs)
            stage = kwargs["stage"]
            assert isinstance(stage, TRANSACTION.PrivateStage)
            stage_fd = stage.stage_fd
            return result

        def fail_stage_fsync(fd: int) -> None:
            nonlocal injected
            if stage_fd is not None and fd == stage_fd and not injected:
                injected = True
                raise OSError(errno.EIO, "fault-injected stage fsync")
            real_fsync(fd)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "move_prepared_candidate_to_stage",
                side_effect=observe_move,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=fail_stage_fsync,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.exit_code, 30)
        staged = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
        self.assertTrue(staged.is_file())
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())

        with mock.patch.dict(
            os.environ,
            {"CODEX_HOME": str(self.codex_home)},
        ):
            code, recovered = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertEqual(code, 0)
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_apply_rejects_lock_replacement_after_durable_receipt(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_write_receipt = TRANSACTION.write_receipt
        lock = self.rules_dir / ".default.rules.apply.lock"
        moved_lock = self.rules_dir / ".default.rules.apply.lock.bound"

        def replace_lock_after_receipt(
            *args: object,
            **kwargs: object,
        ) -> object:
            result = real_write_receipt(*args, **kwargs)
            os.rename(lock, moved_lock)
            lock.write_bytes(b"")
            lock.chmod(0o600)
            return result

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "write_receipt",
                side_effect=replace_lock_after_receipt,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.exit_code, 30)
        self.assertEqual(raised.exception.details["reason"], "lock_changed")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(TRANSACTION.prepared_candidate_path(self.receipt).is_file())
        self.assertFalse((self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME).exists())

    def test_no_change_rejects_lock_replacement_before_return(self) -> None:
        self.candidate.write_bytes(OLD_RULES)
        real_validate_stage = TRANSACTION.validate_existing_fixed_stage_is_empty
        lock = self.rules_dir / ".default.rules.apply.lock"
        moved_lock = self.rules_dir / ".default.rules.apply.lock.bound"

        def replace_lock_after_stage_check(
            *args: object,
            **kwargs: object,
        ) -> None:
            real_validate_stage(*args, **kwargs)
            os.rename(lock, moved_lock)
            lock.write_bytes(b"")
            lock.chmod(0o600)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "validate_existing_fixed_stage_is_empty",
                side_effect=replace_lock_after_stage_check,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(
                SimpleNamespace(
                    **{
                        **vars(self.apply_namespace()),
                        "candidate_sha256": hashlib.sha256(OLD_RULES).hexdigest(),
                    }
                )
            )

        self.assertEqual(raised.exception.status, "lock_changed")
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_receipt_parent_cannot_be_fixed_private_stage(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        self.receipt = stage / "recovery.json"

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(raised.exception.status, "path_invalid")
        self.assertFalse(self.receipt.exists())
        self.assertEqual(list(stage.iterdir()), [])
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_cross_device_prepared_publication_is_rejected_preflight(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_bind_directory = TRANSACTION.bind_directory

        def report_other_receipt_device(
            path: Path,
            **kwargs: object,
        ) -> object:
            binding = real_bind_directory(path, **kwargs)
            if kwargs.get("label") == "receipt":
                snapshot = binding.snapshot
                binding.snapshot = TRANSACTION.Snapshot(
                    device=snapshot.device + 1,
                    inode=snapshot.inode,
                    size=snapshot.size,
                    sha256=snapshot.sha256,
                    mode=snapshot.mode,
                    uid=snapshot.uid,
                    gid=snapshot.gid,
                    nlink=snapshot.nlink,
                )
            return binding

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "bind_directory",
                side_effect=report_other_receipt_device,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(
            raised.exception.status,
            "prepared_candidate_cross_device",
        )
        self.assertFalse(self.receipt.exists())
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())
        self.assertFalse((self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME).exists())
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_prepared_ownership_transfer_survives_baseexception(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_move = TRANSACTION.move_prepared_candidate_to_stage
        moved_fd: int | None = None

        def interrupt_after_move(*args: object, **kwargs: object) -> object:
            nonlocal moved_fd
            real_move(*args, **kwargs)
            prepared = kwargs["prepared"]
            assert isinstance(prepared, TRANSACTION.BoundFile)
            moved_fd = prepared.fd
            raise KeyboardInterrupt("fault-injected ownership interruption")

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "move_prepared_candidate_to_stage",
                side_effect=interrupt_after_move,
            ),
            redirect_stderr(io.StringIO()),
            self.assertRaises(KeyboardInterrupt),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        assert moved_fd is not None
        with self.assertRaises(OSError) as closed:
            os.fstat(moved_fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        staged = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
        self.assertEqual(staged.read_bytes(), NEW_RULES)
        self.assertTrue(self.receipt.is_file())
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

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
        self.assert_no_private_stage()

    def test_repeated_recover_does_not_hide_retained_fixed_stage_evidence(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        retained = stage / "unexpected"
        retained.write_bytes(b"retained recovery evidence\n")

        repeated = self.run_recover()

        self.assertEqual(repeated.returncode, 30, repeated.stderr)
        payload = json.loads(repeated.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["transaction_state"], "R")
        self.assertEqual(payload["reason"], "private_stage_retained")
        self.assertEqual(
            retained.read_bytes(),
            b"retained recovery evidence\n",
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

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
        self.rewrite_receipt_as_legacy_v1()

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovered")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_legacy_recovery_rejects_rules_parent_replacement(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        real_bind_directory = TRANSACTION.bind_directory
        moved_rules_parent = self.root / "rules.bound"
        replaced = False

        def replace_parent_before_bind(
            path: Path,
            **kwargs: object,
        ) -> object:
            nonlocal replaced
            if (
                not replaced
                and path.resolve() == self.rules_dir.resolve()
                and kwargs.get("label") == "rules"
            ):
                replaced = True
                os.rename(self.rules_dir, moved_rules_parent)
                self.rules_dir.mkdir()
                for child in list(moved_rules_parent.iterdir()):
                    os.rename(child, self.rules_dir / child.name)
            return real_bind_directory(path, **kwargs)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "bind_directory",
                side_effect=replace_parent_before_bind,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(replaced)
        self.assertEqual(code, 40)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "rules_parent_changed")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)

    def test_legacy_already_original_retained_stage_requires_recovery(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        recovered = self.run_recover()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.rewrite_receipt_as_legacy_v1()
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        retained = stage / "unexpected"
        retained.write_bytes(b"retained legacy evidence\n")

        repeated = self.run_recover()

        self.assertEqual(repeated.returncode, 30, repeated.stderr)
        payload = json.loads(repeated.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "private_stage_retained")
        self.assertEqual(retained.read_bytes(), b"retained legacy evidence\n")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_legacy_recovery_cleanup_refusal_is_recovery_required(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        real_cleanup = TRANSACTION.PrivateStage._cleanup_fixed_stage

        def refuse_after_closing(stage: object) -> list[dict[str, object]]:
            assert isinstance(stage, TRANSACTION.PrivateStage)
            real_cleanup(stage)
            return [
                {
                    "status": "stage_cleanup_refused",
                    "reason": "fault_injected",
                }
            ]

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "_cleanup_fixed_stage",
                autospec=True,
                side_effect=refuse_after_closing,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "fault_injected")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

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

    def test_recover_rejects_schema_v3_backup_snapshot_not_equal_original(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["backup"]["identity"]["inode"] += 1
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 50, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "receipt_invalid")
        self.assertIn(
            "backup snapshot must exactly match original",
            payload["message"],
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)

    def test_atomic_exchange_unsupported_retains_receipt_bound_stage(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stderr = io.StringIO()

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
                side_effect=TRANSACTION.TransactionError(
                    "atomic_rename_unsupported",
                    "fault-injected unsupported exchange",
                ),
            ),
            redirect_stderr(stderr),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.exit_code, 30)
        self.assertEqual(
            raised.exception.details["reason"],
            "atomic_rename_unsupported",
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        self.assertEqual((stage / "candidate").read_bytes(), NEW_RULES)
        self.assertTrue(self.receipt.is_file())
        self.assertFalse(self.backup.exists())
        self.assertEqual(list(self.rules_dir.glob(".rules-apply-*")), [])
        self.assertEqual(
            list(self.rules_dir.glob(".default.rules.cleanup-retained-*")),
            [],
        )
        cleanup = json.loads(stderr.getvalue().strip())
        self.assertEqual(cleanup["status"], "cleanup_warning")
        self.assertTrue(
            any(
                warning["status"] == "stage_cleanup_refused"
                for warning in cleanup["warnings"]
            )
        )

    def test_cleanup_refusal_overrides_pending_applied_success(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stderr = io.StringIO()
        real_cleanup = TRANSACTION.PrivateStage._cleanup_fixed_stage

        def inject_unexpected_entry(
            stage: object,
        ) -> list[dict[str, object]]:
            assert isinstance(stage, TRANSACTION.PrivateStage)
            (stage.path / "unexpected").write_bytes(b"retained evidence\n")
            return real_cleanup(stage)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "_cleanup_fixed_stage",
                autospec=True,
                side_effect=inject_unexpected_entry,
            ),
            redirect_stderr(stderr),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.exit_code, 30)
        self.assertEqual(raised.exception.details["operation_status"], "applied")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertTrue(self.backup.is_file())
        self.assertTrue(self.receipt.is_file())
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        self.assertEqual(
            (stage / "unexpected").read_bytes(),
            b"retained evidence\n",
        )
        cleanup = json.loads(stderr.getvalue().strip())
        self.assertTrue(
            any(
                warning["status"] == "stage_cleanup_refused"
                for warning in cleanup["warnings"]
            )
        )

    def test_successful_apply_leaves_fixed_stage_empty_without_warning(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")

        result = self.run_apply()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "applied")
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assert_no_private_stage()

    def test_successful_apply_cleans_fixed_stage_before_releasing_lock(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        lock = self.rules_dir / ".default.rules.apply.lock"
        real_cleanup = TRANSACTION.PrivateStage._cleanup_fixed_stage
        cleanup_observed = False

        def assert_lock_still_held(stage: object) -> list[dict[str, object]]:
            nonlocal cleanup_observed
            assert isinstance(stage, TRANSACTION.PrivateStage)
            probe_fd = os.open(lock, os.O_RDWR | os.O_CLOEXEC)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(
                        probe_fd,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
            finally:
                os.close(probe_fd)
            cleanup_observed = True
            return real_cleanup(stage)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "_cleanup_fixed_stage",
                autospec=True,
                side_effect=assert_lock_still_held,
            ),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(cleanup_observed)
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "applied")
        self.assert_no_private_stage()

    def test_repeated_successful_applies_reuse_one_empty_stage_root(self) -> None:
        self.write_validator("raise SystemExit(0)\n")

        for attempt in range(12):
            with self.subTest(attempt=attempt):
                current = self.rules.read_bytes()
                candidate = NEW_RULES if current == OLD_RULES else OLD_RULES
                self.candidate.write_bytes(candidate)
                self.receipt = self.root / "task" / f"recovery-{attempt:02d}.json"
                self.backup_name = f"default.rules.bak-repeat-{attempt:02d}"
                self.backup = self.rules_dir / self.backup_name
                result = self.run_apply(
                    expected_sha256=hashlib.sha256(current).hexdigest(),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    json.loads(result.stdout)["status"],
                    "applied",
                )
                self.assertEqual(self.rules.read_bytes(), candidate)
                self.assertEqual(self.backup.read_bytes(), current)
                self.assert_no_private_stage()

        stage_roots = list(self.rules_dir.glob(TRANSACTION.PRIVATE_STAGE_NAME))
        self.assertEqual(len(stage_roots), 1)
        self.assertEqual(list(stage_roots[0].iterdir()), [])

    def test_successful_recover_leaves_fixed_stage_empty_without_warning(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["status"], "recovered")
        self.assertEqual(recovered.stderr, "")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)
        self.assert_no_private_stage()


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

    def test_private_stage_init_closes_parent_on_baseexception(self) -> None:
        real_open = TRANSACTION.os.open
        real_fstat = TRANSACTION.os.fstat
        parent_fd: int | None = None
        interrupted = False

        def observe_open(
            path: object,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            nonlocal parent_fd
            fd = real_open(path, flags, *args, **kwargs)
            if os.fspath(path) == os.fspath(self.rules_dir):
                parent_fd = fd
            return fd

        def interrupt_fstat(fd: int) -> os.stat_result:
            nonlocal interrupted
            if parent_fd is not None and fd == parent_fd and not interrupted:
                interrupted = True
                raise KeyboardInterrupt("fault-injected parent fstat")
            return real_fstat(fd)

        with (
            mock.patch.object(
                TRANSACTION.os,
                "open",
                side_effect=observe_open,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fstat",
                side_effect=interrupt_fstat,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            TRANSACTION.PrivateStage(self.rules_dir)

        assert parent_fd is not None
        with self.assertRaises(OSError) as closed:
            os.fstat(parent_fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_move_to_ownership_transfer_closes_all_fds_on_baseexception(
        self,
    ) -> None:
        class InterruptingList(list[int]):
            def remove(self, value: int) -> None:
                raise KeyboardInterrupt("fault-injected fd ownership transfer")

        stage = TRANSACTION.PrivateStage(self.rules_dir)
        candidate, candidate_snapshot = stage.create("candidate", NEW_RULES)
        _live_payload, live = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        stage.set_policy(candidate, candidate_snapshot, live)
        stage.extra_fds = InterruptingList(stage.extra_fds)
        owned_fds: set[int] = set()
        try:
            with self.assertRaises(KeyboardInterrupt):
                stage.move_to(candidate, self.rules, live)
        finally:
            owned_fds.update(binding.fd for binding in stage.files.values())
            owned_fds.update(stage.extra_fds)
            stage.cleanup(retain=True)

        for fd in owned_fds:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_publish_backup_ownership_transfer_closes_duplicate_fd(
        self,
    ) -> None:
        class InterruptingDict(dict[Path, object]):
            def pop(
                self,
                key: Path,
                default: object = None,
            ) -> object:
                raise KeyboardInterrupt("fault-injected backup ownership transfer")

        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _source_snapshot = stage.create("backup", OLD_RULES)
        stage.files = InterruptingDict(stage.files)
        source_fd = stage.files[source].fd
        backup = self.rules_dir / "default.rules.bak-interrupted"
        try:
            with self.assertRaises(KeyboardInterrupt):
                stage.publish_backup(source, backup)
        finally:
            stage.cleanup(retain=True)

        with self.assertRaises(OSError) as closed:
            os.fstat(source_fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        self.assertEqual(backup.read_bytes(), OLD_RULES)

    def test_retain_cleanup_closes_all_fds_on_baseexception(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        candidate, _candidate_snapshot = stage.create(
            "candidate",
            NEW_RULES,
        )
        candidate_fd = stage.files[candidate].fd
        stage_fd = stage.stage_fd
        parent_fd = stage.rules_parent_fd

        with (
            mock.patch.object(
                stage,
                "_locator_for_snapshot",
                side_effect=KeyboardInterrupt("fault-injected retention inspection"),
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            stage.cleanup(retain=True)

        for fd in (candidate_fd, stage_fd, parent_fd):
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

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
                case_rules_dir = self.root / f"rules-{action}"
                case_rules_dir.mkdir()
                stage = TRANSACTION.PrivateStage(case_rules_dir)
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

    def test_stage_root_metadata_is_revalidated_before_candidate_create(
        self,
    ) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        RulesApplyTransactionTests.add_test_xattr(self, stage.path)

        try:
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                stage.create("candidate", NEW_RULES)

            self.assertEqual(
                raised.exception.status,
                "unsupported_extended_attributes",
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

    def test_known_backup_locator_ignores_large_sibling_inventory(self) -> None:
        for index in range(TRANSACTION.MAX_STAGE_DIRECTORY_ENTRIES + 8):
            sibling = self.rules_dir / f"default.rules.bak-sibling-{index:04d}"
            sibling.write_bytes(b"sibling\n")
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)
        backup = self.rules_dir / "default.rules.bak-known"

        published = stage.publish_backup(source, backup)
        try:
            locator = stage._locator_for_snapshot(published.snapshot)
        finally:
            stage.cleanup(retain=False)

        self.assertEqual(locator, backup)
        self.assertEqual(backup.read_bytes(), NEW_RULES)

    def test_fixed_stage_cleanup_never_removes_replacement_leaf(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)
        moved_source = stage.path / "candidate.bound"
        os.rename(source, moved_source)
        source.write_bytes(b"replacement cleanup leaf\n")

        warnings = stage.cleanup(retain=False)

        refused = next(
            warning
            for warning in warnings
            if warning["status"] == "stage_cleanup_refused"
        )
        self.assertEqual(
            source.read_bytes(),
            b"replacement cleanup leaf\n",
        )
        self.assertEqual(moved_source.read_bytes(), NEW_RULES)
        self.assertEqual(refused["recovery_locator"], str(stage.path))
        self.assertTrue(stage.path.exists())

    def test_fixed_stage_cleanup_never_removes_replacement_root(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)
        moved_root = self.rules_dir / ".moved-disposable-stage"
        os.rename(stage.path, moved_root)
        stage.path.mkdir(mode=0o700)
        replacement_leaf = stage.path / "replacement"
        replacement_leaf.write_bytes(b"replacement stage tree\n")

        warnings = stage.cleanup(retain=False)

        self.assertEqual(replacement_leaf.read_bytes(), b"replacement stage tree\n")
        self.assertEqual((moved_root / source.name).read_bytes(), NEW_RULES)
        refused = next(
            warning
            for warning in warnings
            if warning["status"] == "stage_cleanup_refused"
        )
        self.assertEqual(refused["reason"], "private_stage_changed")
        self.assertEqual(refused["recovery_locator"], str(moved_root))

    def test_fixed_stage_cleanup_never_calls_path_delete_primitives(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)

        with (
            mock.patch.object(TRANSACTION.os, "unlink") as unlink,
            mock.patch.object(TRANSACTION.os, "rmdir") as rmdir,
        ):
            warnings = stage.cleanup(retain=False)

        unlink.assert_not_called()
        rmdir.assert_not_called()
        refused = next(
            warning
            for warning in warnings
            if warning["status"] == "stage_cleanup_refused"
        )
        self.assertEqual(refused["recovery_locator"], str(stage.path))
        self.assertEqual(source.read_bytes(), NEW_RULES)

    def test_fixed_stage_cleanup_does_not_move_or_reuse_children(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        source, _expected = stage.create("candidate", NEW_RULES)
        replacement = stage.path / "replacement"
        replacement.write_bytes(b"replacement stage tree\n")

        with mock.patch.object(
            TRANSACTION,
            "atomic_rename_no_replace",
        ) as atomic_move:
            warnings = stage.cleanup(retain=False)

        atomic_move.assert_not_called()
        refused = next(
            warning
            for warning in warnings
            if warning["status"] == "stage_cleanup_refused"
        )
        self.assertEqual(refused["recovery_locator"], str(stage.path))
        self.assertEqual(source.read_bytes(), NEW_RULES)
        self.assertEqual(replacement.read_bytes(), b"replacement stage tree\n")

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
