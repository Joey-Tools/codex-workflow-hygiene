from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager, redirect_stderr, redirect_stdout
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
VALIDATOR_RESOURCE_FINALIZERS = (
    "exit-observer-close",
    "selector-close",
    "stdout-pipe-close",
    "stderr-pipe-close",
    "signal-supervision-restore",
)
DEFERRED_VALIDATOR_RESOURCE_FINALIZERS = (
    *VALIDATOR_RESOURCE_FINALIZERS[:-1],
    "signal-ownership-mask-handoff",
)


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
LINUX_TERMINAL_PROCESS_STATES = frozenset((b"Z", b"X", b"x"))


def process_has_exited(pid: int, *, proc_root: Path = Path("/proc")) -> bool:
    if sys.platform.startswith("linux") and (proc_root / "self/stat").is_file():
        try:
            with (proc_root / str(pid) / "stat").open("rb", buffering=0) as handle:
                raw = handle.read(4097)
        except (FileNotFoundError, ProcessLookupError):
            return True
        except OSError:
            return False
        if len(raw) > 4096:
            return False
        close_paren = raw.rfind(b")")
        fields = raw[close_paren + 2 :].split() if close_paren >= 0 else []
        return bool(fields) and fields[0] in LINUX_TERMINAL_PROCESS_STATES
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


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
        while True:
            try:
                return int(pid_path.read_text(encoding="ascii"))
            except (FileNotFoundError, ValueError):
                pass
            if time.monotonic() >= deadline:
                self.fail(f"validator did not publish its PID: {pid_path}")
            time.sleep(0.01)

    def wait_for_path(self, path: Path, *, label: str) -> None:
        deadline = time.monotonic() + 3
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail(f"{label} did not become ready: {path}")
            time.sleep(0.01)

    def assert_process_exited(self, pid: int) -> None:
        deadline = time.monotonic() + 2
        while True:
            if process_has_exited(pid):
                return
            if time.monotonic() >= deadline:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.fail(f"validator process {pid} remained alive")
            time.sleep(0.01)

    @contextmanager
    def inject_validator_finalizer_signal(
        self,
        target: str,
        *,
        active: Callable[[], bool] = lambda: True,
        signum: int = signal.SIGTERM,
    ):
        real_attempt = TRANSACTION.ValidatorFailureAccumulator.attempt
        state = SimpleNamespace(
            completed=[],
            injected=False,
            observed=[],
        )

        def instrument_attempt(
            accumulator: object,
            descriptor: str,
            operation: Callable[[], object],
        ) -> object | None:
            assert isinstance(
                accumulator,
                TRANSACTION.ValidatorFailureAccumulator,
            )
            if not active():
                return real_attempt(accumulator, descriptor, operation)
            state.observed.append(descriptor)

            def instrument_operation() -> object:
                if descriptor == target and not state.injected:
                    state.injected = True
                    os.kill(os.getpid(), signum)
                result = operation()
                state.completed.append(descriptor)
                if descriptor == target:
                    raise OSError(
                        errno.EIO,
                        f"fault-injected {descriptor} finalizer failure",
                    )
                return result

            return real_attempt(
                accumulator,
                descriptor,
                instrument_operation,
            )

        with mock.patch.object(
            TRANSACTION.ValidatorFailureAccumulator,
            "attempt",
            autospec=True,
            side_effect=instrument_attempt,
        ):
            yield state

    @contextmanager
    def inject_validator_finalizer_failure(
        self,
        target: str,
        *,
        active: Callable[[], bool] = lambda: True,
    ):
        real_attempt = TRANSACTION.ValidatorFailureAccumulator.attempt
        state = SimpleNamespace(injected=False)

        def instrument_attempt(
            accumulator: object,
            descriptor: str,
            operation: Callable[[], object],
        ) -> object | None:
            assert isinstance(
                accumulator,
                TRANSACTION.ValidatorFailureAccumulator,
            )
            if not active() or descriptor != target or state.injected:
                return real_attempt(accumulator, descriptor, operation)

            def fail_after_operation() -> object:
                operation()
                state.injected = True
                raise OSError(
                    errno.EIO,
                    f"fault-injected {descriptor} finalizer failure",
                )

            return real_attempt(
                accumulator,
                descriptor,
                fail_after_operation,
            )

        with mock.patch.object(
            TRANSACTION.ValidatorFailureAccumulator,
            "attempt",
            autospec=True,
            side_effect=instrument_attempt,
        ):
            yield state

    @contextmanager
    def inject_signal_after_validator_final_pending_read(
        self,
        *,
        active: Callable[[], bool],
        signum: int,
    ):
        real_capture = TRANSACTION._capture_pending_managed_validator_signals
        state = SimpleNamespace(injected=False, observed=[])

        def capture_then_signal(
            gate: object,
            failures: list[dict[str, object]],
            *,
            descriptor: str,
        ) -> None:
            assert isinstance(gate, TRANSACTION.ValidatorSignalGate)
            real_capture(
                gate,
                failures,
                descriptor=descriptor,
            )
            if not active():
                return
            state.observed.append(descriptor)
            if (
                descriptor == "signal-handoff:final-pending-before-mask"
                and not state.injected
            ):
                state.injected = True
                os.kill(os.getpid(), signum)

        with mock.patch.object(
            TRANSACTION,
            "_capture_pending_managed_validator_signals",
            side_effect=capture_then_signal,
        ):
            yield state

    def test_process_exit_probe_accepts_linux_terminal_states_only(self) -> None:
        proc_root = self.root / "proc"
        (proc_root / "self").mkdir(parents=True)
        (proc_root / "self/stat").write_bytes(b"1 (test runner) R 0 1 1\n")
        target_stat = proc_root / "123/stat"
        target_stat.parent.mkdir()

        with mock.patch.object(sys, "platform", "linux"):
            for state in (b"Z", b"X", b"x"):
                with self.subTest(state=state.decode("ascii")):
                    target_stat.write_bytes(
                        b"123 (validator child) " + state + b" 1 123 123\n"
                    )
                    self.assertTrue(process_has_exited(123, proc_root=proc_root))

            for state in (b"R", b"S", b"D", b"T", b"I"):
                with self.subTest(state=state.decode("ascii")):
                    target_stat.write_bytes(
                        b"123 (validator child) " + state + b" 1 123 123\n"
                    )
                    self.assertFalse(process_has_exited(123, proc_root=proc_root))

            target_stat.unlink()
            self.assertTrue(process_has_exited(123, proc_root=proc_root))

    def test_linux_process_group_inventory_excludes_all_terminal_states(self) -> None:
        entry = SimpleNamespace(name="123")
        scandir = mock.MagicMock()
        scandir.return_value.__iter__.return_value = [entry]

        for state in TRANSACTION.LINUX_TERMINAL_PROCESS_STATES:
            with self.subTest(state=state.decode("ascii")):
                process_stat = b"123 (validator child) " + state + b" 1 456 456\n"
                with (
                    mock.patch.object(TRANSACTION.os, "scandir", scandir),
                    mock.patch(
                        "builtins.open",
                        mock.mock_open(read_data=process_stat),
                    ),
                ):
                    self.assertEqual(
                        TRANSACTION._linux_live_process_group_members(
                            456,
                            leader_pid=999,
                        ),
                        (),
                    )

    def test_linux_process_group_inventory_retains_live_members(self) -> None:
        entry = SimpleNamespace(name="123")
        scandir = mock.MagicMock()
        scandir.return_value.__iter__.return_value = [entry]

        with (
            mock.patch.object(TRANSACTION.os, "scandir", scandir),
            mock.patch(
                "builtins.open",
                mock.mock_open(
                    read_data=b"123 (validator child) S 1 456 456\n",
                ),
            ),
        ):
            self.assertEqual(
                TRANSACTION._linux_live_process_group_members(
                    456,
                    leader_pid=999,
                ),
                (123,),
            )

    def test_linux_process_group_inventory_rejects_malformed_state(self) -> None:
        entry = SimpleNamespace(name="123")
        scandir = mock.MagicMock()
        scandir.return_value.__iter__.return_value = [entry]

        with (
            mock.patch.object(TRANSACTION.os, "scandir", scandir),
            mock.patch(
                "builtins.open",
                mock.mock_open(read_data=b"123 (validator child) broken\n"),
            ),
            self.assertRaisesRegex(
                TRANSACTION.TransactionError,
                "metadata for 123 is malformed",
            ),
        ):
            TRANSACTION._linux_live_process_group_members(
                456,
                leader_pid=999,
            )

    def test_linux_process_group_inventory_rejects_unreadable_state(self) -> None:
        entry = SimpleNamespace(name="123")
        scandir = mock.MagicMock()
        scandir.return_value.__iter__.return_value = [entry]

        with (
            mock.patch.object(TRANSACTION.os, "scandir", scandir),
            mock.patch(
                "builtins.open",
                side_effect=PermissionError(errno.EACCES, "denied"),
            ),
            self.assertRaisesRegex(
                TRANSACTION.TransactionError,
                "cannot inspect validator process-group candidate 123",
            ),
        ):
            TRANSACTION._linux_live_process_group_members(
                456,
                leader_pid=999,
            )

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

    def apply_argv(self) -> list[str]:
        namespace = self.apply_namespace()
        return [
            "apply",
            "--candidate",
            namespace.candidate,
            "--candidate-sha256",
            namespace.candidate_sha256,
            "--expected-sha256",
            namespace.expected_sha256,
            "--backup-name",
            namespace.backup_name,
            "--receipt",
            namespace.receipt,
            "--validator-timeout-seconds",
            str(namespace.validator_timeout_seconds),
            "--lock-timeout-seconds",
            str(namespace.lock_timeout_seconds),
            "--",
            *namespace.validator_command,
        ]

    def configure_isolated_case(self, root: Path) -> None:
        self.root = root
        self.codex_home = root / "codex-home"
        self.rules_dir = self.codex_home / "rules"
        self.rules_dir.mkdir(parents=True)
        self.rules = self.rules_dir / "default.rules"
        self.rules.write_bytes(OLD_RULES)
        self.rules.chmod(0o640)
        self.candidate = root / "candidate.rules"
        self.candidate.write_bytes(NEW_RULES)
        self.receipt = root / "task" / "recovery.json"
        self.receipt.parent.mkdir(mode=0o700)
        self.backup_name = "default.rules.bak-20260724-120000"
        self.backup = self.rules_dir / self.backup_name
        self.validator = root / "validator.py"

    def inject_final_apply_evidence_drift(
        self,
        drift: str,
    ) -> tuple[str, str]:
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        result = TRANSACTION.recovery_terminal_result_path(terminal)
        if drift == "identity":
            bound = self.receipt.with_name("recovery.bound.json")
            os.rename(self.receipt, bound)
            replacement = self.receipt.with_name("recovery.replacement.json")
            replacement.write_bytes(bound.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, self.receipt)
            return "receipt_changed", "object_identity"
        if drift == "content":
            result.write_bytes(result.read_bytes() + b" ")
            return "recovery_terminal_result_changed", "content"
        if drift == "access":
            terminal.chmod(0o640)
            return "recovery_terminal_changed", "access_policy"
        if drift == "link":
            os.link(self.receipt, self.receipt.with_name("recovery.link.json"))
            return "receipt_changed", "object_policy"
        if drift == "parent":
            moved_parent = self.root / "task.bound"
            os.rename(self.receipt.parent, moved_parent)
            self.receipt.parent.mkdir(mode=0o700)
            return "receipt_parent_changed", "object_identity"
        raise AssertionError(f"unknown final evidence drift: {drift}")

    def inject_final_data_role_drift(
        self,
        data_role: str,
        drift: str,
    ) -> tuple[str, str]:
        if data_role == "staged_backup":
            if drift != "appearance":
                raise AssertionError(f"unknown staged-backup drift: {drift}")
            stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
            stage.mkdir(mode=0o700, exist_ok=True)
            staged = stage / "candidate"
            staged.write_bytes(NEW_RULES)
            staged.chmod(0o600)
            return "transaction_data_role_unexpected", "presence"
        targets = {
            "live": self.rules,
            "backup": self.backup,
            "prepared_candidate": TRANSACTION.prepared_candidate_path(self.receipt),
        }
        target = targets.get(data_role)
        if target is None:
            raise AssertionError(f"unknown data role: {data_role}")
        if drift == "appearance":
            target.write_bytes(NEW_RULES)
            target.chmod(0o600)
            return "transaction_data_role_unexpected", "presence"
        if drift == "missing":
            target.unlink()
            return "transaction_data_role_missing", "missing"
        if drift == "identity":
            bound = target.with_name(f".{target.name}.{data_role}.bound")
            replacement = target.with_name(f".{target.name}.{data_role}.replacement")
            mode = stat.S_IMODE(target.stat().st_mode)
            os.rename(target, bound)
            replacement.write_bytes(bound.read_bytes())
            replacement.chmod(mode)
            os.replace(replacement, target)
            return "transaction_data_role_changed", "object_identity"
        if drift == "content":
            target.write_bytes(LATER_RULES)
            return "transaction_data_role_changed", "content"
        if drift == "access":
            mode = stat.S_IMODE(target.stat().st_mode)
            target.chmod(0o600 if mode != 0o600 else 0o640)
            return "transaction_data_role_changed", "access_policy"
        if drift == "link":
            os.link(
                target,
                target.with_name(f".{target.name}.{data_role}.link"),
            )
            return "transaction_data_role_changed", "object_policy"
        raise AssertionError(f"unknown final data-role drift: {drift}")

    @contextmanager
    def drift_before_transaction_lock_release(
        self,
        data_role: str,
        drift: str,
    ):
        real_shared_lock = TRANSACTION.shared_lock
        injected: dict[str, object] = {"count": 0}

        @contextmanager
        def shared_lock_with_drift(
            path: Path,
            *,
            timeout_seconds: float,
            before_release: object = None,
        ):
            finalizer = before_release

            def drift_then_release() -> None:
                if injected["count"] == 0:
                    status, mismatched_property = self.inject_final_data_role_drift(
                        data_role, drift
                    )
                    injected.update(
                        {
                            "count": 1,
                            "status": status,
                            "mismatched_property": mismatched_property,
                        }
                    )
                if callable(finalizer):
                    finalizer()

            with real_shared_lock(
                path,
                timeout_seconds=timeout_seconds,
                before_release=(drift_then_release if finalizer is not None else None),
            ) as binding:
                yield binding

        with mock.patch.object(
            TRANSACTION,
            "shared_lock",
            new=shared_lock_with_drift,
        ):
            yield injected

    def recover_argv(self) -> list[str]:
        return [
            "recover",
            "--receipt",
            str(self.receipt),
            "--lock-timeout-seconds",
            "2",
        ]

    @contextmanager
    def fault_private_stage_descriptor_closes(self):
        real_close_descriptors = TRANSACTION.close_descriptors_best_effort
        closed: list[tuple[str, int]] = []

        def close_stage_with_faults(
            descriptors: list[tuple[str, int]],
            *,
            release_uncertain: bool = False,
        ) -> list[dict[str, object]]:
            if [descriptor for descriptor, _fd in descriptors] == [
                "private_stage",
                "rules_parent",
            ]:
                failures: list[dict[str, object]] = []
                for index, (descriptor, fd) in enumerate(descriptors):
                    TRANSACTION.os.close(fd)
                    closed.append((descriptor, fd))
                    error_number = errno.EIO if index == 0 else errno.EINTR
                    failures.append(
                        TRANSACTION.structured_operation_failure(
                            "close",
                            descriptor,
                            OSError(
                                error_number,
                                f"fault-injected {descriptor} close",
                            ),
                        )
                    )
                return failures
            return real_close_descriptors(
                descriptors,
                release_uncertain=release_uncertain,
            )

        with mock.patch.object(
            TRANSACTION,
            "close_descriptors_best_effort",
            side_effect=close_stage_with_faults,
        ):
            yield closed

    @contextmanager
    def fault_final_rules_parent_close(self, error_number: int):
        real_bind_directory = TRANSACTION.bind_directory
        real_close_descriptors = TRANSACTION.close_descriptors_best_effort
        state: dict[str, int | None] = {
            "outer_fd": None,
            "fault_calls": 0,
        }

        def capture_outer_rules_parent(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> object:
            binding = real_bind_directory(path, *args, **kwargs)
            assert isinstance(binding, TRANSACTION.BoundDirectory)
            # The no-change branch binds its outer evidence before the
            # short-lived fixed-stage probe binds the same parent again.
            if (
                kwargs.get("label") == "rules"
                and Path(path).resolve() == self.rules_dir.resolve()
                and state["outer_fd"] is None
            ):
                state["outer_fd"] = binding.fd
            return binding

        def fail_outer_rules_parent_close(
            descriptors: list[tuple[str, int]],
            *,
            release_uncertain: bool = False,
        ) -> list[dict[str, object]]:
            if state["outer_fd"] is not None and descriptors == [
                ("rules_parent", state["outer_fd"])
            ]:
                state["fault_calls"] += 1
                TRANSACTION.os.close(descriptors[0][1])
                return [
                    TRANSACTION.structured_operation_failure(
                        "close",
                        "rules_parent",
                        OSError(
                            error_number,
                            "fault-injected final rules-parent close",
                        ),
                    )
                ]
            return real_close_descriptors(
                descriptors,
                release_uncertain=release_uncertain,
            )

        with (
            mock.patch.object(
                TRANSACTION,
                "bind_directory",
                side_effect=capture_outer_rules_parent,
            ),
            mock.patch.object(
                TRANSACTION,
                "close_descriptors_best_effort",
                side_effect=fail_outer_rules_parent_close,
            ),
        ):
            yield state

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
        timeout: float = 15,
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
            timeout=timeout,
        )

    def run_recover(self, *, timeout: float = 15) -> subprocess.CompletedProcess[str]:
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
            timeout=timeout,
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

    def rewrite_receipt_as_legacy_v2(self) -> dict[str, object]:
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["schema_version"] = 2
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

    def assert_stage_namespace_receipt_rejected(self) -> dict[str, object]:
        self.write_validator("raise SystemExit(0)\n")
        lock = self.rules_dir / ".default.rules.apply.lock"

        result = self.run_apply()

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "path_invalid")
        self.assertIn(
            "overlaps the fixed transaction-stage namespace",
            payload["message"],
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(lock.exists())
        return payload

    def test_cleanup_attachment_preserves_primary_without_add_note(self) -> None:
        class LegacyNoteError(Exception):
            def __getattribute__(self, name: str) -> object:
                if name == "add_note":
                    raise AttributeError("add_note is unavailable")
                return super().__getattribute__(name)

        primary = LegacyNoteError("primary failure")
        failure = TRANSACTION.structured_operation_failure(
            "close",
            "private_stage",
            OSError(errno.EIO, "fault-injected close"),
        )

        TRANSACTION.attach_failures_to_exception(
            primary,
            "cleanup_failures",
            [failure],
        )

        self.assertEqual(str(primary), "primary failure")
        self.assertEqual(primary.cleanup_failures, [failure])

    def test_pending_attachment_preserves_primary_without_add_note(self) -> None:
        class LegacyNoteError(Exception):
            def __getattribute__(self, name: str) -> object:
                if name == "add_note":
                    raise AttributeError("add_note is unavailable")
                return super().__getattribute__(name)

        primary = LegacyNoteError("primary pending failure")
        retention = {
            "retention_status": "verified_pending_result",
            "pending_locator": str(self.receipt.with_suffix(".pending")),
        }

        TRANSACTION.attach_pending_recovery_terminal_retention(
            primary,
            retention,
        )

        self.assertEqual(str(primary), "primary pending failure")
        self.assertIs(primary.pending_retention, retention)

    def test_attachment_preserves_primary_when_add_note_fails(self) -> None:
        class BrokenNoteError(Exception):
            def add_note(self, _note: str) -> None:
                raise OSError(errno.EIO, "fault-injected add_note failure")

        primary = BrokenNoteError("primary failure")
        failure = TRANSACTION.structured_operation_failure(
            "lock-finalization",
            "final-release-revalidation",
            OSError(errno.EIO, "fault-injected finalization"),
        )

        TRANSACTION.attach_failures_to_exception(
            primary,
            "lock_finalization_failures",
            [failure],
        )

        self.assertEqual(str(primary), "primary failure")
        self.assertEqual(primary.lock_finalization_failures, [failure])

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

    def test_new_lock_normalizes_restrictive_owner_umask(self) -> None:
        lock = self.rules_dir / ".default.rules.apply.lock"
        previous_umask = os.umask(0o200)
        try:
            with TRANSACTION.shared_lock(
                lock,
                timeout_seconds=2.0,
            ):
                self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        finally:
            os.umask(previous_umask)

        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        self.assert_no_private_stage()

    def test_new_stage_with_owner_permissions_stripped_fails_without_chmod(
        self,
    ) -> None:
        stage_path = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        previous_umask = os.umask(0o700)
        try:
            with (
                mock.patch.object(
                    TRANSACTION.os,
                    "fchmod",
                    side_effect=AssertionError(
                        "an unbound named stage must never be chmodded"
                    ),
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                TRANSACTION.PrivateStage(self.rules_dir)
        finally:
            os.umask(previous_umask)

        self.assertIn(
            raised.exception.status,
            {"private_stage_unavailable", "private_stage_invalid"},
        )
        self.assertTrue(stage_path.is_dir())
        self.assertEqual(stat.S_IMODE(stage_path.stat().st_mode), 0)
        stage_path.rmdir()

    def test_new_stage_replacement_before_open_is_not_chmodded(self) -> None:
        stage_path = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        created_stage = self.root / "stage-created-before-replacement"
        real_open = TRANSACTION.os.open
        replaced = False

        def replace_before_stage_open(
            path: object,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            nonlocal replaced
            if (
                not replaced
                and os.fspath(path) == TRANSACTION.PRIVATE_STAGE_NAME
                and kwargs.get("dir_fd") is not None
            ):
                os.rename(stage_path, created_stage)
                stage_path.mkdir(mode=0o700)
                stage_path.chmod(0o500)
                replaced = True
            return real_open(path, flags, *args, **kwargs)

        with (
            mock.patch.object(
                TRANSACTION.os,
                "open",
                side_effect=replace_before_stage_open,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fchmod",
                side_effect=AssertionError(
                    "a pathname replacement must never be chmodded"
                ),
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.PrivateStage(self.rules_dir)

        self.assertTrue(replaced)
        self.assertEqual(raised.exception.status, "private_stage_invalid")
        self.assertEqual(stat.S_IMODE(created_stage.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(stage_path.stat().st_mode), 0o500)

    def test_new_lock_path_replacement_is_rejected_before_fchmod(self) -> None:
        lock = self.rules_dir / ".default.rules.apply.lock"
        created_lock = self.root / "created-lock"
        real_open = TRANSACTION.os.open
        fchmod_calls: list[tuple[int, int]] = []

        def replace_after_exclusive_open(
            path: object,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            fd = real_open(path, flags, *args, **kwargs)
            if os.fspath(path) == os.fspath(lock) and flags & os.O_EXCL:
                os.rename(lock, created_lock)
                lock.write_bytes(b"replacement\n")
                lock.chmod(0o640)
            return fd

        def record_fchmod(fd: int, mode: int) -> None:
            fchmod_calls.append((fd, mode))

        with (
            mock.patch.object(
                TRANSACTION.os,
                "open",
                side_effect=replace_after_exclusive_open,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fchmod",
                side_effect=record_fchmod,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            with TRANSACTION.shared_lock(lock, timeout_seconds=2.0):
                self.fail("replaced lock must not be acquired")

        self.assertEqual(raised.exception.status, "lock_invalid")
        self.assertEqual(fchmod_calls, [])
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o640)

    def test_new_lock_hardlink_is_rejected_before_fchmod(self) -> None:
        lock = self.rules_dir / ".default.rules.apply.lock"
        alias = self.root / "lock-alias"
        real_open = TRANSACTION.os.open
        fchmod_calls: list[tuple[int, int]] = []

        def link_after_exclusive_open(
            path: object,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            fd = real_open(path, flags, *args, **kwargs)
            if os.fspath(path) == os.fspath(lock) and flags & os.O_EXCL:
                os.link(lock, alias)
            return fd

        def record_fchmod(fd: int, mode: int) -> None:
            fchmod_calls.append((fd, mode))

        with (
            mock.patch.object(
                TRANSACTION.os,
                "open",
                side_effect=link_after_exclusive_open,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "fchmod",
                side_effect=record_fchmod,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            with TRANSACTION.shared_lock(lock, timeout_seconds=2.0):
                self.fail("hard-linked lock must not be acquired")

        self.assertEqual(raised.exception.status, "lock_invalid")
        self.assertEqual(fchmod_calls, [])
        self.assertEqual(lock.stat().st_nlink, 2)

    def test_read_stable_classifies_hardlink_drift_as_object_policy(self) -> None:
        alias = self.root / "candidate.alias"
        real_read_bound_fd = TRANSACTION.read_bound_fd
        linked = False

        def link_after_descriptor_read(
            fd: int,
            *,
            label: str,
            max_bytes: int = TRANSACTION.MAX_RULES_BYTES,
        ) -> tuple[bytes, object]:
            nonlocal linked
            payload, snapshot = real_read_bound_fd(
                fd,
                label=label,
                max_bytes=max_bytes,
            )
            if not linked:
                os.link(self.candidate, alias)
                linked = True
            return payload, snapshot

        with (
            mock.patch.object(
                TRANSACTION,
                "read_bound_fd",
                side_effect=link_after_descriptor_read,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.read_stable(
                self.candidate,
                label="candidate_source",
            )

        self.assertTrue(linked)
        self.assertEqual(
            raised.exception.status,
            "candidate_source_object_policy_changed",
        )
        self.assertEqual(
            raised.exception.details["mismatched_properties"],
            ["object_policy"],
        )

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

    def test_candidate_fifo_is_rejected_without_blocking_before_lock(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        self.write_validator("raise SystemExit(0)\n")
        candidate_digest = hashlib.sha256(NEW_RULES).hexdigest()
        self.candidate.unlink()
        os.mkfifo(self.candidate, 0o600)

        result = self.run_apply(
            candidate_sha256=candidate_digest,
            timeout=5,
        )

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "candidate_source_not_regular")
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assert_no_private_stage()

    def test_existing_lock_fifo_is_rejected_without_blocking_before_flock(
        self,
    ) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        self.write_validator("raise SystemExit(0)\n")
        lock = self.rules_dir / ".default.rules.apply.lock"
        os.mkfifo(lock, 0o600)

        result = self.run_apply(timeout=5)

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "transaction_lock_not_regular")
        self.assertTrue(stat.S_ISFIFO(lock.stat().st_mode))
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

    def test_candidate_fifo_replacement_after_validator_does_not_block(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        self.write_validator(
            """\
            import os
            from pathlib import Path
            import sys

            path = Path(sys.argv[1])
            if path.name != "default.rules":
                source = Path(os.environ["CANDIDATE_SOURCE"])
                source.unlink()
                os.mkfifo(source, 0o600)
            """
        )

        result = self.run_apply(
            environment=self.helper_environment(
                CANDIDATE_SOURCE=str(self.candidate),
            ),
            timeout=5,
        )

        self.assertEqual(result.returncode, 50, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "candidate_source_not_regular")
        self.assertTrue(stat.S_ISFIFO(self.candidate.stat().st_mode))
        self.assertFalse((self.rules_dir / ".default.rules.apply.lock").exists())
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

    def test_linux_directory_index_flag_is_ignored_but_immutable_is_rejected(
        self,
    ) -> None:
        directory_fd = os.open(self.rules_dir, os.O_RDONLY)

        def inspect_flags(
            raw_flags: int,
            *,
            file_mode: int = stat.S_IFDIR | 0o700,
            require_directory: bool = True,
        ) -> None:
            def inject_flags(
                _fd: int,
                request: int,
                buffer: object,
                mutate: bool,
            ) -> int:
                self.assertEqual(request, TRANSACTION.LINUX_FS_IOC_GETFLAGS)
                self.assertTrue(mutate)
                buffer[0] = raw_flags  # type: ignore[index]
                return 0

            with (
                mock.patch.object(
                    TRANSACTION.os,
                    "fstat",
                    return_value=SimpleNamespace(
                        st_flags=None,
                        st_mode=file_mode,
                    ),
                ),
                mock.patch.object(TRANSACTION.sys, "platform", "linux"),
                mock.patch.object(
                    TRANSACTION.fcntl,
                    "ioctl",
                    side_effect=inject_flags,
                ),
                mock.patch.object(
                    TRANSACTION,
                    "_list_bound_xattrs",
                    return_value=(),
                ),
                mock.patch.object(
                    TRANSACTION,
                    "_bound_has_extended_acl",
                    return_value=False,
                ),
            ):
                TRANSACTION.reject_unmodeled_metadata_fd(
                    directory_fd,
                    label="rules_parent",
                    require_directory=require_directory,
                )

        try:
            inspect_flags(0x00001000)  # FS_INDEX_FL
            with self.assertRaises(TRANSACTION.TransactionError) as raised:
                inspect_flags(0x00001000 | 0x00000010)  # FS_IMMUTABLE_FL

            self.assertEqual(raised.exception.status, "unsupported_file_flags")
            self.assertEqual(raised.exception.details["st_flags"], 0x00000010)
            with self.assertRaises(TRANSACTION.TransactionError) as regular_raised:
                inspect_flags(
                    0x00001000,
                    file_mode=stat.S_IFREG | 0o600,
                    require_directory=False,
                )
            self.assertEqual(
                regular_raised.exception.status,
                "unsupported_file_flags",
            )
            self.assertEqual(
                regular_raised.exception.details["st_flags"],
                0x00001000,
            )
        finally:
            os.close(directory_fd)

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
            with mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=interrupt_first_close,
            ):
                failures = evidence.close()

            self.assertEqual(
                failures,
                [
                    {
                        "operation": "close",
                        "descriptor": "recovery_receipt",
                        "error_type": "KeyboardInterrupt",
                        "message": "fault-injected evidence close",
                    }
                ],
            )
            for fd in expected_closed:
                with self.assertRaises(OSError) as closed:
                    os.fstat(fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)
        finally:
            real_close(receipt_fd)
            stage.cleanup()

    def test_bind_regular_file_preserves_primary_over_close_failure(self) -> None:
        path = self.receipt.parent / "bound-evidence"
        path.write_bytes(b"bound\n")
        path.chmod(0o600)
        parent = TRANSACTION.bind_directory(
            self.receipt.parent,
            label="bound_evidence",
        )
        real_close = TRANSACTION.os.close

        def close_then_fail(fd: int) -> None:
            real_close(fd)
            raise OSError(errno.EIO, "fault-injected bind close")

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "validate_bound_regular_file",
                    side_effect=TRANSACTION.TransactionError(
                        "bound_evidence_changed",
                        "fault-injected bind property failure",
                    ),
                ),
                mock.patch.object(
                    TRANSACTION.os,
                    "close",
                    side_effect=close_then_fail,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                TRANSACTION.bind_regular_file(
                    path,
                    parent,
                    label="bound_evidence",
                )
        finally:
            real_close(parent.fd)

        self.assertEqual(raised.exception.status, "bound_evidence_changed")
        self.assertEqual(
            raised.exception.details["cleanup_failures"][0]["errno_name"],
            "EIO",
        )

    def test_read_bound_child_preserves_primary_over_close_failure(self) -> None:
        path = self.receipt.parent / "read-evidence"
        path.write_bytes(b"bound\n")
        path.chmod(0o600)
        parent = TRANSACTION.bind_directory(
            self.receipt.parent,
            label="read_evidence",
        )
        real_validate = TRANSACTION.validate_bound_regular_file
        real_close = TRANSACTION.os.close
        validations = 0

        def fail_second_validation(*args: object, **kwargs: object) -> object:
            nonlocal validations
            validations += 1
            if validations == 2:
                raise TRANSACTION.TransactionError(
                    "read_evidence_changed",
                    "fault-injected read property failure",
                )
            return real_validate(*args, **kwargs)

        def close_then_fail(fd: int) -> None:
            real_close(fd)
            raise OSError(errno.EINTR, "fault-injected read close")

        try:
            with (
                mock.patch.object(
                    TRANSACTION,
                    "validate_bound_regular_file",
                    side_effect=fail_second_validation,
                ),
                mock.patch.object(
                    TRANSACTION.os,
                    "close",
                    side_effect=close_then_fail,
                ),
                self.assertRaises(TRANSACTION.TransactionError) as raised,
            ):
                TRANSACTION.read_bound_regular_child(
                    path,
                    parent,
                    label="read_evidence",
                )
        finally:
            real_close(parent.fd)

        self.assertEqual(raised.exception.status, "read_evidence_changed")
        self.assertEqual(
            raised.exception.details["cleanup_failures"][0]["errno_name"],
            "EINTR",
        )

    def test_terminal_read_attempts_all_closes_without_masking_primary(
        self,
    ) -> None:
        parent = TRANSACTION.bind_directory(
            self.receipt.parent,
            label="recovery_terminal",
            require_owner_private=True,
        )
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        reservation = TRANSACTION.reserve_recovery_terminal(
            terminal,
            transaction_id="0" * 32,
            parent=parent,
        )
        os.close(reservation.fd)
        os.close(parent.fd)
        real_close = TRANSACTION.os.close
        closed_fds: list[int] = []
        close_count = 0

        def close_with_two_faults(fd: int) -> None:
            nonlocal close_count
            real_close(fd)
            closed_fds.append(fd)
            close_count += 1
            if close_count == 1:
                raise OSError(errno.EIO, "fault-injected terminal close")
            if close_count == 2:
                raise OSError(errno.EINTR, "fault-injected parent close")

        with (
            mock.patch.object(
                TRANSACTION,
                "decode_recovery_terminal",
                side_effect=TRANSACTION.TransactionError(
                    "recovery_terminal_changed",
                    "fault-injected terminal parse failure",
                ),
            ),
            mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=close_with_two_faults,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.read_recovery_terminal_with_snapshot(terminal)

        self.assertEqual(raised.exception.status, "recovery_terminal_changed")
        failures = raised.exception.details["cleanup_failures"]
        self.assertEqual(
            [failure["descriptor"] for failure in failures],
            [
                "recovery_terminal_reservation",
                "recovery_terminal_parent",
            ],
        )
        self.assertEqual(
            [failure["errno_name"] for failure in failures],
            ["EIO", "EINTR"],
        )
        self.assertEqual(len(closed_fds), 2)
        for fd in closed_fds:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

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
            redirect_stdout(stdout := io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = TRANSACTION.main(self.apply_argv())

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["operation_status"], "replacement_started")
        self.assertEqual(payload["reason"], "receipt_changed")
        self.assertIn("object_policy", payload["mismatched_properties"])
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

    def test_backup_case_alias_is_reproved_missing_before_exchange(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        backup_alias = self.rules_dir / self.backup_name.swapcase()
        real_move = TRANSACTION.PrivateStage.move_to
        real_observe = TRANSACTION.observe_directory_entry

        def occupy_alias_then_move(
            stage: object,
            path: Path,
            target: Path,
            target_expected: object,
            *,
            pre_exchange_revalidate: object = None,
        ) -> object:
            backup_alias.write_bytes(LATER_RULES)
            backup_alias.chmod(0o640)
            return real_move(
                stage,
                path,
                target,
                target_expected,
                pre_exchange_revalidate=pre_exchange_revalidate,
            )

        def observe_case_insensitive_alias(
            directory_fd: int,
            name: str,
            *,
            expected: object = None,
        ) -> dict[str, object]:
            if name == self.backup.name and backup_alias.exists():
                return real_observe(
                    directory_fd,
                    backup_alias.name,
                    expected=expected,
                )
            return real_observe(directory_fd, name, expected=expected)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "move_to",
                autospec=True,
                side_effect=occupy_alias_then_move,
            ),
            mock.patch.object(
                TRANSACTION,
                "observe_directory_entry",
                side_effect=observe_case_insensitive_alias,
            ),
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
            ) as atomic_exchange,
            redirect_stderr(io.StringIO()),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.details["reason"], "backup_exists")
        atomic_exchange.assert_not_called()
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(backup_alias.read_bytes(), LATER_RULES)
        self.assertTrue(self.receipt.is_file())

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

    def test_validator_failure_accumulator_preserves_raw_primary_failure(
        self,
    ) -> None:
        finalizer_descriptors = [
            "emergency-process-group",
            "exit-observer",
            "selector",
            "stdout",
            "stderr",
        ]

        for primary_label, error_number in (
            ("waitid", errno.EIO),
            ("read", errno.EINTR),
        ):
            with self.subTest(primary=primary_label):
                accumulator = TRANSACTION.ValidatorFailureAccumulator()
                primary = OSError(
                    error_number,
                    f"fault-injected raw {primary_label} failure",
                )
                try:
                    raise primary
                except OSError as caught:
                    accumulator.capture_primary(caught)

                finalizers = [
                    mock.Mock(
                        side_effect=OSError(
                            errno.EIO,
                            f"fault-injected {descriptor} failure",
                        )
                    )
                    for descriptor in finalizer_descriptors
                ]
                for descriptor, finalizer in zip(
                    finalizer_descriptors,
                    finalizers,
                ):
                    accumulator.attempt(descriptor, finalizer)
                accumulator.extend(
                    [
                        TRANSACTION.structured_operation_failure(
                            "validator-finalization",
                            "signal-restore",
                            RuntimeError("fault-injected signal restoration failure"),
                        )
                    ]
                )

                with self.assertRaises(OSError) as raised:
                    accumulator.finish(TRANSACTION.ValidatorResult(0, "", ""))

                self.assertIs(raised.exception, primary)
                for finalizer in finalizers:
                    finalizer.assert_called_once_with()
                failures = getattr(
                    primary,
                    "validator_cleanup_failures",
                )
                self.assertEqual(
                    [failure["descriptor"] for failure in failures],
                    [*finalizer_descriptors, "signal-restore"],
                )
                self.assertTrue(
                    all(
                        failure["operation"] == "validator-finalization"
                        for failure in failures
                    )
                )

    def test_run_validator_preserves_raw_primary_while_finalizing_every_resource(
        self,
    ) -> None:
        for primary_label, error_number in (
            ("waitid", errno.EIO),
            ("read", errno.EINTR),
        ):
            with self.subTest(primary=primary_label):
                primary = OSError(
                    error_number,
                    f"fault-injected raw {primary_label} failure",
                )
                gate = mock.Mock()
                observer = mock.Mock()
                selector = mock.Mock()
                stdout = mock.Mock()
                stderr = mock.Mock()
                stdout.fileno.return_value = 101
                stderr.fileno.return_value = 102
                observer.child_exited.side_effect = (
                    primary if primary_label == "waitid" else None
                )
                observer.close.side_effect = OSError(
                    errno.EIO,
                    "fault-injected observer close failure",
                )
                selector.close.side_effect = OSError(
                    errno.EIO,
                    "fault-injected selector close failure",
                )
                stdout.close.side_effect = OSError(
                    errno.EIO,
                    "fault-injected stdout close failure",
                )
                stderr.close.side_effect = OSError(
                    errno.EIO,
                    "fault-injected stderr close failure",
                )
                process = SimpleNamespace(
                    stdout=stdout,
                    stderr=stderr,
                )
                read_events = mock.Mock(
                    side_effect=(primary if primary_label == "read" else None),
                    return_value=(False, False),
                )
                quiesce_failure = TRANSACTION.structured_operation_failure(
                    "validator-finalization",
                    "signal-quiesce",
                    OSError(
                        errno.EIO,
                        "fault-injected signal quiesce failure",
                    ),
                )
                restore_failure = TRANSACTION.structured_operation_failure(
                    "validator-finalization",
                    "signal-restore",
                    OSError(
                        errno.EIO,
                        "fault-injected signal restore failure",
                    ),
                )
                emergency_failures = [
                    TRANSACTION.structured_operation_failure(
                        "validator-emergency-cleanup",
                        descriptor,
                        OSError(
                            errno.EIO,
                            f"fault-injected {descriptor} failure",
                        ),
                    )
                    for descriptor in (
                        "term",
                        "drain",
                        "kill",
                        "reap",
                    )
                ]

                with (
                    mock.patch.object(
                        TRANSACTION,
                        "_validator_exit_observer_supported",
                        return_value=True,
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "_start_validator_signal_supervision",
                        return_value=(gate, {}, set(), set()),
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "_arm_validator_signal_supervision",
                    ) as arm_supervision,
                    mock.patch.object(
                        TRANSACTION.subprocess,
                        "Popen",
                        return_value=process,
                    ) as popen,
                    mock.patch.object(
                        TRANSACTION,
                        "_ValidatorExitObserver",
                        return_value=observer,
                    ),
                    mock.patch.object(
                        TRANSACTION.selectors,
                        "DefaultSelector",
                        return_value=selector,
                    ),
                    mock.patch.object(
                        TRANSACTION.os,
                        "set_blocking",
                    ) as set_blocking,
                    mock.patch.object(
                        TRANSACTION,
                        "_read_validator_events",
                        read_events,
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "_quiesce_validator_signal_supervision",
                        return_value=[quiesce_failure],
                    ) as quiesce,
                    mock.patch.object(
                        TRANSACTION,
                        "_emergency_stop_validator_process_group",
                        return_value=emergency_failures,
                    ) as emergency_cleanup,
                    mock.patch.object(
                        TRANSACTION,
                        "_restore_validator_signal_supervision",
                        return_value=[restore_failure],
                    ) as restore,
                    self.assertRaises(OSError) as raised,
                ):
                    TRANSACTION.run_validator(
                        [sys.executable, "{rules}"],
                        self.candidate,
                        timeout_seconds=2,
                    )

                self.assertIs(raised.exception, primary)
                popen.assert_called_once()
                arm_supervision.assert_called_once_with(gate, set())
                self.assertEqual(set_blocking.call_count, 2)
                quiesce.assert_called_once_with(gate)
                emergency_cleanup.assert_called_once()
                observer.close.assert_called_once_with()
                selector.close.assert_called_once_with()
                stdout.close.assert_called_once_with()
                stderr.close.assert_called_once_with()
                restore.assert_called_once_with(gate, {}, set())
                cleanup_failures = getattr(
                    primary,
                    "validator_cleanup_failures",
                )
                self.assertEqual(
                    [failure["descriptor"] for failure in cleanup_failures],
                    [
                        "signal-quiesce",
                        "term",
                        "drain",
                        "kill",
                        "reap",
                        "exit-observer-close",
                        "selector-close",
                        "stdout-pipe-close",
                        "stderr-pipe-close",
                        "signal-restore",
                    ],
                )

    def test_validator_failure_accumulator_preserves_forwarded_signal(
        self,
    ) -> None:
        accumulator = TRANSACTION.ValidatorFailureAccumulator()
        forwarded = TRANSACTION.ForwardedValidatorSignal(signal.SIGTERM)
        accumulator.capture_primary(forwarded)
        accumulator.record(
            "selector",
            OSError(errno.EIO, "fault-injected selector close failure"),
        )

        with self.assertRaises(TRANSACTION.ForwardedValidatorSignal) as raised:
            accumulator.finish(TRANSACTION.ValidatorResult(0, "", ""))

        self.assertIs(raised.exception, forwarded)
        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(
            [failure["descriptor"] for failure in forwarded.cleanup_errors],
            ["selector"],
        )

    def test_validator_failure_accumulator_rejects_cleanup_only_failure(
        self,
    ) -> None:
        accumulator = TRANSACTION.ValidatorFailureAccumulator()
        selector_close = mock.Mock(
            side_effect=OSError(
                errno.EIO,
                "fault-injected selector close failure",
            )
        )
        accumulator.attempt("selector", selector_close)

        with self.assertRaises(TRANSACTION.TransactionError) as raised:
            accumulator.finish(TRANSACTION.ValidatorResult(0, "", ""))

        selector_close.assert_called_once_with()
        self.assertEqual(
            raised.exception.status,
            "validator_cleanup_failed",
        )
        self.assertEqual(
            raised.exception.details["validator_cleanup_failures"][0]["descriptor"],
            "selector",
        )

    def test_signal_restore_postcondition_failure_blocks_validator_success(
        self,
    ) -> None:
        previous_handler = signal.SIG_DFL
        inherited_mask = {signal.SIGTERM}

        for failure_kind in ("handler", "mask"):
            with self.subTest(postcondition=failure_kind):
                gate = TRANSACTION.ValidatorSignalGate()
                restored_handler = (
                    signal.SIG_IGN if failure_kind == "handler" else previous_handler
                )
                final_mask = inherited_mask if failure_kind == "handler" else set()
                pthread_sigmask = mock.Mock(
                    side_effect=[
                        set(),
                        set(),
                        inherited_mask,
                        final_mask,
                    ]
                )
                with (
                    mock.patch.object(
                        TRANSACTION.signal,
                        "pthread_sigmask",
                        pthread_sigmask,
                    ),
                    mock.patch.object(
                        TRANSACTION.signal,
                        "signal",
                    ) as install_handler,
                    mock.patch.object(
                        TRANSACTION.signal,
                        "getsignal",
                        side_effect=[
                            gate.handle,
                            restored_handler,
                        ],
                    ) as get_handler,
                    mock.patch.object(
                        TRANSACTION.signal,
                        "sigpending",
                        return_value=set(),
                    ),
                ):
                    failures = TRANSACTION._restore_validator_signal_supervision(
                        gate,
                        {signal.SIGTERM: previous_handler},
                        inherited_mask,
                    )

                accumulator = TRANSACTION.ValidatorFailureAccumulator()
                accumulator.extend(failures)
                with self.assertRaises(TRANSACTION.TransactionError) as raised:
                    accumulator.finish(TRANSACTION.ValidatorResult(0, "", ""))

                expected_descriptor = (
                    "signal-handoff:validate-restored-handler:SIGTERM"
                    if failure_kind == "handler"
                    else "signal-handoff:validate-final-mask"
                )
                self.assertEqual(
                    [failure["descriptor"] for failure in failures],
                    [expected_descriptor],
                )
                self.assertEqual(
                    raised.exception.status,
                    "validator_cleanup_failed",
                )
                self.assertEqual(
                    raised.exception.details["validator_cleanup_failures"][0][
                        "descriptor"
                    ],
                    expected_descriptor,
                )
                install_handler.assert_called_once_with(
                    signal.SIGTERM,
                    previous_handler,
                )
                self.assertEqual(get_handler.call_count, 2)
                self.assertEqual(pthread_sigmask.call_count, 4)

        gate = TRANSACTION.ValidatorSignalGate()
        handoff = TRANSACTION.ValidatorSignalOwnershipHandoff(
            gate,
            {
                signal.SIGINT: signal.SIG_DFL,
                signal.SIGTERM: signal.SIG_DFL,
            },
            inherited_mask,
            mask_released_to_gate=True,
        )
        with (
            mock.patch.object(
                TRANSACTION.signal,
                "pthread_sigmask",
                return_value=set(),
            ) as pthread_sigmask,
            mock.patch.object(
                TRANSACTION.signal,
                "sigpending",
                return_value=set(),
            ),
            mock.patch.object(
                TRANSACTION.signal,
                "signal",
                side_effect=[
                    OSError(errno.EIO, "fault-injected first handler failure"),
                    signal.SIG_DFL,
                ],
            ) as install_handler,
            mock.patch.object(
                TRANSACTION.signal,
                "getsignal",
                side_effect=[
                    signal.SIG_IGN,
                    OSError(errno.EIO, "fault-injected second handler read"),
                ],
            ) as get_handler,
        ):
            failures = TRANSACTION._complete_validator_signal_ownership_handoff(handoff)

        self.assertEqual(install_handler.call_count, 2)
        self.assertEqual(get_handler.call_count, 2)
        self.assertEqual(pthread_sigmask.call_count, 1)
        self.assertEqual(
            [failure["descriptor"] for failure in failures],
            [
                "signal-handoff:restore-handler:SIGINT",
                "signal-handoff:validate-restored-handler:SIGINT",
                "signal-handoff:validate-restored-handler:SIGTERM",
                "signal-handoff:validate-final-mask",
            ],
        )

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

        class FaultingProcess:
            pid = 626_263
            returncode: int | None = None

            def __init__(self) -> None:
                self.wait_calls = 0
                self.kill_calls = 0

            def wait(self, timeout: float) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("validator", timeout)
                raise OSError(errno.ECHILD, "fault-injected final reap failure")

            def kill(self) -> None:
                self.kill_calls += 1
                raise OSError(errno.EPERM, "fault-injected child kill failure")

        faulting_process = FaultingProcess()
        selector = mock.Mock()
        selector.get_map.return_value = {"stdout": object()}
        with (
            mock.patch.object(
                TRANSACTION,
                "VALIDATOR_TERM_GRACE_SECONDS",
                0.1,
            ),
            mock.patch.object(
                TRANSACTION,
                "VALIDATOR_KILL_DRAIN_SECONDS",
                0.1,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "killpg",
                side_effect=OSError(
                    errno.EIO,
                    "fault-injected process-group signal failure",
                ),
            ) as faulting_killpg,
            mock.patch.object(
                TRANSACTION.os,
                "kill",
                side_effect=OSError(
                    errno.EPERM,
                    "fault-injected direct signal failure",
                ),
            ) as direct_signal,
            mock.patch.object(
                TRANSACTION,
                "_read_validator_events",
                side_effect=OSError(
                    errno.EIO,
                    "fault-injected output drain failure",
                ),
            ) as drain,
        ):
            combined_failures = TRANSACTION._emergency_stop_validator_process_group(
                faulting_process,
                selector,
                {"stdout": bytearray(), "stderr": bytearray()},
                max_output_bytes=TRANSACTION.MAX_VALIDATOR_OUTPUT_BYTES,
            )

        self.assertEqual(faulting_killpg.call_count, 3)
        self.assertEqual(direct_signal.call_count, 3)
        self.assertEqual(drain.call_count, 2)
        self.assertEqual(faulting_process.wait_calls, 2)
        self.assertEqual(faulting_process.kill_calls, 1)
        self.assertEqual(
            [failure["descriptor"] for failure in combined_failures],
            [
                f"killpg:{signal.SIGTERM}",
                f"signal-direct-child:{signal.SIGTERM}",
                "drain-validator-output",
                f"killpg:{signal.SIGKILL}",
                f"signal-direct-child:{signal.SIGKILL}",
                "drain-validator-output",
                f"killpg:{signal.SIGKILL}",
                f"signal-direct-child:{signal.SIGKILL}",
                "reap-direct-child",
                "kill-direct-child",
                "final-reap-direct-child",
            ],
        )

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
    def test_post_replace_managed_signal_rolls_back_and_reports_recovery(
        self,
    ) -> None:
        validator_pid_path = self.root / "post-replace-validator.pid"
        ready_path = self.root / "post-replace-validator.ready"
        self.write_validator(
            f"""\
            from pathlib import Path
            import os
            import sys
            import time

            rules = Path(sys.argv[1])
            if rules.name != "default.rules":
                raise SystemExit(0)
            Path({str(validator_pid_path)!r}).write_text(
                str(os.getpid()),
                encoding="ascii",
            )
            Path({str(ready_path)!r}).write_text("ready", encoding="ascii")
            while True:
                time.sleep(1)
            """
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(HELPER),
                *self.apply_argv(),
            ],
            env=self.helper_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        validator_pid: int | None = None
        try:
            self.wait_for_path(ready_path, label="post-replace validator")
            validator_pid = self.wait_for_pid_path(validator_pid_path)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)

            self.assertEqual(
                process.returncode,
                128 + signal.SIGTERM,
                stderr,
            )
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "interrupted")
            self.assertEqual(payload["signal"], signal.SIGTERM)
            self.assertEqual(
                payload["interrupted_phase"],
                "post_replace_validation",
            )
            recovery = payload["post_replace_recovery"]
            self.assertEqual(recovery["exit_code"], 30)
            self.assertEqual(
                recovery["status"],
                "post_replace_failed_rolled_back",
            )
            self.assertEqual(
                recovery["post_replace_failure"]["status"],
                "post_replace_validation_interrupted",
            )
            self.assertEqual(
                recovery["rollback"]["rollback_status"],
                "rolled_back",
            )
            self.assertEqual(
                Path(payload["receipt_path"]).resolve(),
                self.receipt.resolve(),
            )
            self.assertEqual(
                Path(payload["backup_path"]).resolve(),
                self.backup.resolve(),
            )
            self.assertEqual(
                Path(payload["recovery_locators"]["receipt"]).resolve(),
                self.receipt.resolve(),
            )
            self.assertEqual(
                Path(payload["recovery_locators"]["backup"]).resolve(),
                self.backup.resolve(),
            )
            self.assertEqual(
                Path(payload["recovery_locators"]["recovery_terminal"]).resolve(),
                TRANSACTION.recovery_terminal_path(self.receipt).resolve(),
            )
            self.assertNotIn("Traceback", stderr)
            self.assertEqual(self.rules.read_bytes(), OLD_RULES)
            self.assertEqual(self.backup.read_bytes(), NEW_RULES)
            self.assertTrue(self.receipt.is_file())
            self.assertTrue(
                TRANSACTION.recovery_terminal_result_path(
                    TRANSACTION.recovery_terminal_path(self.receipt)
                ).is_file()
            )
            self.assert_no_private_stage()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            if validator_pid is not None:
                self.assert_process_exited(validator_pid)

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

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "validator finalization signal capture requires POSIX signal waits",
    )
    def test_signal_immediately_before_finalization_boundary_is_latched(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_quiesce = TRANSACTION._quiesce_validator_signal_supervision

        for signum in TRANSACTION.MANAGED_VALIDATOR_SIGNALS:
            with self.subTest(signal=signal.Signals(signum).name):
                calls = 0

                def signal_before_quiesce(gate: object) -> list[dict[str, object]]:
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        os.kill(os.getpid(), signum)
                    assert isinstance(gate, TRANSACTION.ValidatorSignalGate)
                    return real_quiesce(gate)

                with (
                    mock.patch.object(
                        TRANSACTION,
                        "_quiesce_validator_signal_supervision",
                        side_effect=signal_before_quiesce,
                    ),
                    self.inject_validator_finalizer_signal(
                        "not-a-finalizer",
                    ) as state,
                    self.assertRaises(TRANSACTION.ForwardedValidatorSignal) as raised,
                ):
                    TRANSACTION.run_validator(
                        [sys.executable, str(self.validator), "{rules}"],
                        self.candidate,
                        timeout_seconds=2,
                    )

                self.assertEqual(calls, 2)
                self.assertEqual(raised.exception.signum, signum)
                self.assertEqual(raised.exception.cleanup_errors, [])
                self.assertEqual(
                    state.observed,
                    list(VALIDATOR_RESOURCE_FINALIZERS),
                )
                self.assertEqual(
                    state.completed,
                    list(VALIDATOR_RESOURCE_FINALIZERS),
                )

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "validator finalization signal capture requires POSIX signal waits",
    )
    def test_signal_at_each_success_finalizer_completes_cleanup_and_wins(
        self,
    ) -> None:
        expected_attempts = VALIDATOR_RESOURCE_FINALIZERS
        self.write_validator("raise SystemExit(0)\n")

        for target_index, target in enumerate(VALIDATOR_RESOURCE_FINALIZERS):
            with self.subTest(finalizer=target):
                signum = TRANSACTION.MANAGED_VALIDATOR_SIGNALS[
                    target_index % len(TRANSACTION.MANAGED_VALIDATOR_SIGNALS)
                ]
                previous_handlers = {
                    signum: signal.getsignal(signum)
                    for signum in TRANSACTION.MANAGED_VALIDATOR_SIGNALS
                }
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

                with (
                    self.inject_validator_finalizer_signal(
                        target,
                        signum=signum,
                    ) as state,
                    self.assertRaises(TRANSACTION.ForwardedValidatorSignal) as raised,
                ):
                    TRANSACTION.run_validator(
                        [sys.executable, str(self.validator), "{rules}"],
                        self.candidate,
                        timeout_seconds=2,
                    )

                self.assertTrue(state.injected)
                self.assertEqual(state.observed, list(expected_attempts))
                self.assertEqual(state.completed, list(expected_attempts))
                self.assertEqual(raised.exception.signum, signum)
                self.assertEqual(
                    [
                        failure["descriptor"]
                        for failure in raised.exception.cleanup_errors
                    ],
                    [target],
                )
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
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "validator finalization signal capture requires POSIX signal waits",
    )
    def test_signal_at_each_failure_finalizer_supersedes_raw_error(
        self,
    ) -> None:
        finalizers = (
            "emergency-process-group-cleanup",
            *VALIDATOR_RESOURCE_FINALIZERS,
        )
        expected_attempts = finalizers

        for target_index, target in enumerate(finalizers):
            with self.subTest(finalizer=target):
                signum = TRANSACTION.MANAGED_VALIDATOR_SIGNALS[
                    target_index % len(TRANSACTION.MANAGED_VALIDATOR_SIGNALS)
                ]
                pid_path = self.root / f"validator-finalizer-{target}.pid"
                self.write_sleeping_validator(pid_path)
                primary = OSError(
                    errno.EIO,
                    "fault-injected validator observation failure",
                )

                def fail_after_validator_start(_observer: object) -> bool:
                    self.wait_for_pid_path(pid_path)
                    raise primary

                with (
                    mock.patch.object(
                        TRANSACTION._ValidatorExitObserver,
                        "child_exited",
                        autospec=True,
                        side_effect=fail_after_validator_start,
                    ),
                    self.inject_validator_finalizer_signal(
                        target,
                        signum=signum,
                    ) as state,
                    self.assertRaises(TRANSACTION.ForwardedValidatorSignal) as raised,
                ):
                    TRANSACTION.run_validator(
                        [sys.executable, str(self.validator), "{rules}"],
                        self.candidate,
                        timeout_seconds=2,
                    )

                self.assert_process_exited(self.wait_for_pid_path(pid_path))
                self.assertTrue(state.injected)
                self.assertEqual(state.observed, list(expected_attempts))
                self.assertEqual(state.completed, list(expected_attempts))
                self.assertEqual(raised.exception.signum, signum)
                cleanup_by_descriptor = {
                    failure["descriptor"]: failure
                    for failure in raised.exception.cleanup_errors
                }
                self.assertTrue(
                    {target, "superseded-primary"}.issubset(cleanup_by_descriptor),
                    cleanup_by_descriptor,
                )
                self.assertEqual(
                    cleanup_by_descriptor[target]["errno"],
                    errno.EIO,
                )
                self.assertEqual(
                    cleanup_by_descriptor["superseded-primary"]["errno"],
                    errno.EIO,
                )
                self.assertEqual(
                    cleanup_by_descriptor["superseded-primary"]["operation"],
                    "validator-execution",
                )

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "validator finalization signal capture requires POSIX signal waits",
    )
    def test_signal_at_each_post_replace_finalizer_keeps_exit_precedence(
        self,
    ) -> None:
        expected_attempts = DEFERRED_VALIDATOR_RESOURCE_FINALIZERS

        for target_index, target in enumerate(DEFERRED_VALIDATOR_RESOURCE_FINALIZERS):
            with (
                self.subTest(finalizer=target),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-post-replace-{target}."
                ) as isolated,
            ):
                signum = TRANSACTION.MANAGED_VALIDATOR_SIGNALS[
                    target_index % len(TRANSACTION.MANAGED_VALIDATOR_SIGNALS)
                ]
                self.configure_isolated_case(Path(isolated))
                self.write_validator("raise SystemExit(0)\n")
                post_replace_phase = False
                real_run_validator = TRANSACTION.run_validator

                def track_validator_phase(
                    command_template: list[str],
                    rules_path: Path,
                    *,
                    timeout_seconds: float,
                    pass_fds: tuple[int, ...] = (),
                    deferred_signal_handoffs: (
                        list[TRANSACTION.ValidatorSignalOwnershipHandoff] | None
                    ) = None,
                ) -> object:
                    nonlocal post_replace_phase
                    post_replace_phase = rules_path.resolve() == self.rules.resolve()
                    try:
                        return real_run_validator(
                            command_template,
                            rules_path,
                            timeout_seconds=timeout_seconds,
                            pass_fds=pass_fds,
                            deferred_signal_handoffs=deferred_signal_handoffs,
                        )
                    finally:
                        post_replace_phase = False

                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "run_validator",
                        side_effect=track_validator_phase,
                    ),
                    self.inject_validator_finalizer_signal(
                        target,
                        active=lambda: post_replace_phase,
                        signum=signum,
                    ) as state,
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    exit_code = TRANSACTION.main(self.apply_argv())

                payload = json.loads(stdout.getvalue())
                self.assertEqual(exit_code, 128 + signum, stderr.getvalue())
                self.assertEqual(payload["status"], "interrupted")
                self.assertEqual(payload["signal"], signum)
                self.assertEqual(
                    payload["interrupted_phase"],
                    "post_replace_validation",
                )
                self.assertEqual(
                    payload["post_replace_recovery"]["status"],
                    "post_replace_failed_rolled_back",
                )
                self.assertEqual(
                    payload["post_replace_recovery"]["rollback"]["rollback_status"],
                    "rolled_back",
                )
                self.assertEqual(
                    [
                        failure["descriptor"]
                        for failure in payload["validator_cleanup_errors"]
                    ],
                    [target],
                )
                self.assertTrue(state.injected)
                self.assertEqual(state.observed, list(expected_attempts))
                self.assertEqual(state.completed, list(expected_attempts))
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertEqual(self.backup.read_bytes(), NEW_RULES)
                self.assertTrue(self.receipt.is_file())
                self.assert_no_private_stage()

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "sigpending")
        and hasattr(signal, "sigwait"),
        "validator signal ownership handoff requires POSIX signal waits",
    )
    def test_signal_after_final_pending_read_preserves_failed_live_result(
        self,
    ) -> None:
        signum = signal.SIGTERM
        failed_marker = self.root / "live-validator-failed"
        self.write_validator(
            f"""\
            from pathlib import Path
            import sys

            if Path(sys.argv[1]).name == "default.rules":
                Path({str(failed_marker)!r}).write_text("failed", encoding="ascii")
                raise SystemExit(9)
            """
        )
        saved_handler = signal.getsignal(signum)
        saved_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        escaped_signals: list[int] = []

        def escaped_handler(observed: int, _frame: object) -> None:
            escaped_signals.append(observed)

        signal.signal(signum, escaped_handler)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signum})
        inherited_test_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        post_replace_phase = False
        deferred_handoff_ids: set[int] = set()
        real_run_validator = TRANSACTION.run_validator
        real_record_terminal = TRANSACTION.record_recovery_terminal
        real_complete_handoff = TRANSACTION._complete_validator_signal_ownership_handoff
        events: list[str] = []
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        terminal_result = TRANSACTION.recovery_terminal_result_path(terminal)

        def track_validator_phase(
            command_template: list[str],
            rules_path: Path,
            *,
            timeout_seconds: float,
            pass_fds: tuple[int, ...] = (),
            deferred_signal_handoffs: (
                list[TRANSACTION.ValidatorSignalOwnershipHandoff] | None
            ) = None,
        ) -> object:
            nonlocal post_replace_phase
            post_replace_phase = rules_path.resolve() == self.rules.resolve()
            handoff_count = (
                len(deferred_signal_handoffs)
                if deferred_signal_handoffs is not None
                else 0
            )
            try:
                return real_run_validator(
                    command_template,
                    rules_path,
                    timeout_seconds=timeout_seconds,
                    pass_fds=pass_fds,
                    deferred_signal_handoffs=deferred_signal_handoffs,
                )
            finally:
                if deferred_signal_handoffs is not None:
                    deferred_handoff_ids.update(
                        id(handoff)
                        for handoff in deferred_signal_handoffs[handoff_count:]
                    )
                post_replace_phase = False

        def record_terminal_then_mark(*args: object, **kwargs: object) -> object:
            result = real_record_terminal(*args, **kwargs)
            events.append("terminal-published")
            return result

        def complete_after_terminal(
            handoff: TRANSACTION.ValidatorSignalOwnershipHandoff,
        ) -> list[dict[str, object]]:
            if id(handoff) not in deferred_handoff_ids:
                return real_complete_handoff(handoff)
            self.assertTrue(terminal_result.is_file())
            self.assertEqual(self.rules.read_bytes(), OLD_RULES)
            events.append("handoff-start")
            failures = real_complete_handoff(handoff)
            events.append("handoff-complete")
            return failures

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with (
                mock.patch.dict(
                    os.environ,
                    {"CODEX_HOME": str(self.codex_home)},
                ),
                mock.patch.object(
                    TRANSACTION,
                    "run_validator",
                    side_effect=track_validator_phase,
                ),
                mock.patch.object(
                    TRANSACTION,
                    "record_recovery_terminal",
                    side_effect=record_terminal_then_mark,
                ),
                mock.patch.object(
                    TRANSACTION,
                    "_complete_validator_signal_ownership_handoff",
                    side_effect=complete_after_terminal,
                ),
                self.inject_signal_after_validator_final_pending_read(
                    active=lambda: post_replace_phase,
                    signum=signum,
                ) as signal_state,
                self.inject_validator_finalizer_failure(
                    "signal-ownership-mask-handoff",
                    active=lambda: post_replace_phase,
                ) as failure_state,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = TRANSACTION.main(self.apply_argv())
            events.append("signal-forwarded")

            payload = json.loads(stdout.getvalue())
            self.assertEqual(
                exit_code,
                128 + signum,
                json.dumps(payload, sort_keys=True),
            )
            self.assertTrue(failed_marker.is_file())
            self.assertTrue(signal_state.injected)
            self.assertEqual(
                signal_state.observed,
                ["signal-handoff:final-pending-before-mask"],
            )
            self.assertTrue(failure_state.injected)
            self.assertEqual(escaped_signals, [])
            self.assertEqual(
                events,
                [
                    "terminal-published",
                    "handoff-start",
                    "handoff-complete",
                    "signal-forwarded",
                ],
            )
            self.assertEqual(payload["status"], "interrupted")
            self.assertEqual(payload["signal"], signum)
            self.assertEqual(
                payload["interrupted_phase"],
                "post_replace_validation",
            )
            recovery = payload["post_replace_recovery"]
            self.assertEqual(
                recovery["status"],
                "post_replace_failed_rolled_back",
            )
            self.assertEqual(
                recovery["rollback"]["rollback_status"],
                "rolled_back",
            )
            self.assertEqual(
                recovery["post_replace_failure"]["validator"]["returncode"],
                9,
            )
            self.assertEqual(
                [
                    failure["descriptor"]
                    for failure in payload["validator_cleanup_errors"]
                ],
                [
                    "superseded-primary",
                    "signal-ownership-mask-handoff",
                ],
            )
            self.assertEqual(
                payload["validator_cleanup_errors"][0]["details"]["validator"][
                    "returncode"
                ],
                9,
            )
            self.assertEqual(self.rules.read_bytes(), OLD_RULES)
            self.assertEqual(self.backup.read_bytes(), NEW_RULES)
            self.assertTrue(self.receipt.is_file())
            self.assertTrue(terminal_result.is_file())
            self.assert_no_private_stage()
            self.assertEqual(signal.getsignal(signum), escaped_handler)
            self.assertEqual(
                signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                inherited_test_mask,
            )
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signum})
            if signum in signal.sigpending():
                signal.sigwait({signum})
            signal.signal(signum, saved_handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, saved_mask)

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

    def test_fast_no_change_finalizer_revalidates_live_data_role(self) -> None:
        for drift in ("identity", "content", "access", "link"):
            with (
                self.subTest(drift=drift),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-fast-no-change-{drift}."
                ) as temp_dir,
            ):
                self.configure_isolated_case(Path(temp_dir))
                self.candidate.write_bytes(OLD_RULES)
                self.write_validator("raise SystemExit(9)\n")
                argv = self.apply_argv()
                digest_index = argv.index("--candidate-sha256") + 1
                argv[digest_index] = hashlib.sha256(OLD_RULES).hexdigest()
                stdout = io.StringIO()

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    self.drift_before_transaction_lock_release(
                        "live",
                        drift,
                    ) as injected,
                    redirect_stdout(stdout),
                    redirect_stderr(io.StringIO()),
                ):
                    code = TRANSACTION.main(argv)

                payload = json.loads(stdout.getvalue())
                self.assertEqual(injected["count"], 1)
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["operation_status"],
                    "no_change_after_lock",
                )
                self.assertEqual(
                    payload["reason"],
                    "transaction_data_role_changed",
                )
                self.assertEqual(payload["data_role"], "live")
                self.assertEqual(payload["transaction_state"], "no_change")
                self.assertIn(
                    injected["mismatched_property"],
                    payload["mismatched_properties"],
                )

    def test_converged_no_change_finalizer_revalidates_live_data_role(
        self,
    ) -> None:
        for drift in ("identity", "content", "access", "link"):
            with (
                self.subTest(drift=drift),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-converged-no-change-{drift}."
                ) as temp_dir,
            ):
                self.configure_isolated_case(Path(temp_dir))
                self.write_validator("raise SystemExit(0)\n")

                def install_candidate_as_live(
                    _command: list[str],
                    _path: Path,
                    *,
                    timeout_seconds: float,
                    pass_fds: tuple[int, ...] = (),
                ) -> object:
                    del timeout_seconds, pass_fds
                    replacement = self.rules_dir / ".converged-candidate-live"
                    replacement.write_bytes(NEW_RULES)
                    replacement.chmod(0o640)
                    os.replace(replacement, self.rules)
                    return TRANSACTION.ValidatorResult(0, "", "")

                argv = self.apply_argv()
                digest_index = argv.index("--expected-sha256") + 1
                argv[digest_index] = hashlib.sha256(NEW_RULES).hexdigest()
                stdout = io.StringIO()

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "run_validator",
                        side_effect=install_candidate_as_live,
                    ) as run_validator,
                    self.drift_before_transaction_lock_release(
                        "live",
                        drift,
                    ) as injected,
                    redirect_stdout(stdout),
                    redirect_stderr(io.StringIO()),
                ):
                    code = TRANSACTION.main(argv)

                payload = json.loads(stdout.getvalue())
                run_validator.assert_called_once()
                self.assertEqual(injected["count"], 1)
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["operation_status"],
                    "no_change_after_lock",
                )
                self.assertEqual(
                    payload["reason"],
                    "transaction_data_role_changed",
                )
                self.assertEqual(payload["data_role"], "live")
                self.assertEqual(payload["transaction_state"], "no_change")
                self.assertIn(
                    injected["mismatched_property"],
                    payload["mismatched_properties"],
                )

    def test_no_change_final_rules_parent_close_failure_requires_recovery(
        self,
    ) -> None:
        self.candidate.write_bytes(OLD_RULES)
        validator_marker = self.root / "validator-ran"
        self.write_validator(
            f"""\
            from pathlib import Path

            Path({str(validator_marker)!r}).write_text("ran", encoding="ascii")
            """
        )
        argv = self.apply_argv()
        digest_index = argv.index("--candidate-sha256") + 1
        argv[digest_index] = hashlib.sha256(OLD_RULES).hexdigest()

        for error_number in (errno.EIO, errno.EINTR):
            with self.subTest(errno=errno.errorcode[error_number]):
                stdout = io.StringIO()
                stderr = io.StringIO()

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    self.fault_final_rules_parent_close(error_number) as close_state,
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    code = TRANSACTION.main(argv)

                self.assertEqual(close_state["fault_calls"], 1)
                self.assertIsNotNone(close_state["outer_fd"])
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(code, 30)
                payload = json.loads(stdout.getvalue())
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["operation_status"],
                    "no_change_after_lock",
                )
                self.assertEqual(
                    payload["reason"],
                    "final_evidence_descriptor_close_failed",
                )
                self.assertEqual(
                    payload["cleanup_reason"],
                    "final_evidence_descriptor_close_failed",
                )
                self.assertEqual(
                    payload["cleanup_failures"][0]["descriptor"],
                    "rules_parent",
                )
                self.assertEqual(
                    payload["cleanup_failures"][0]["errno"],
                    error_number,
                )
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertFalse(self.backup.exists())
                self.assertFalse(self.receipt.exists())
                self.assertFalse(
                    TRANSACTION.prepared_candidate_path(self.receipt).exists()
                )
                terminal = TRANSACTION.recovery_terminal_path(self.receipt)
                self.assertFalse(terminal.exists())
                self.assertFalse(
                    TRANSACTION.recovery_terminal_result_path(terminal).exists()
                )
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

    def assert_no_real_change_transaction_artifacts(self) -> None:
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())
        self.assertFalse(terminal.exists())
        self.assertFalse(TRANSACTION.recovery_terminal_result_path(terminal).exists())

    def test_real_change_preflights_retained_stage_before_any_artifact(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        retained = stage / "unexpected"
        retained.write_bytes(b"retained recovery evidence\n")

        result = self.run_apply()

        self.assertEqual(result.returncode, 30, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["stage_status"], "private_stage_retained")
        self.assertEqual(retained.read_bytes(), b"retained recovery evidence\n")
        self.assert_no_real_change_transaction_artifacts()

    def test_real_change_preflights_invalid_stage_before_any_artifact(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        stage.chmod(0o755)

        result = self.run_apply()

        self.assertEqual(result.returncode, 30, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertIn(
            payload["stage_status"],
            {
                "private_stage_invalid",
                "private_stage_parent_not_private",
                "private_stage_parent_changed",
            },
        )
        self.assert_no_real_change_transaction_artifacts()

    def test_real_change_preflights_stage_replacement_before_any_artifact(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        moved_stage = self.root / "stage.bound"
        real_stage_init = TRANSACTION.PrivateStage.__init__
        replaced = False

        def replace_before_stage_bind(
            stage_object: object,
            rules_parent: Path,
            **kwargs: object,
        ) -> None:
            nonlocal replaced
            if kwargs.get("recovery_stage_expected") is not None and not replaced:
                replaced = True
                os.rename(stage, moved_stage)
                stage.mkdir(mode=0o700)
            real_stage_init(stage_object, rules_parent, **kwargs)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "__init__",
                autospec=True,
                side_effect=replace_before_stage_bind,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(replaced)
        self.assertEqual(raised.exception.status, "recovery_required")
        self.assert_no_real_change_transaction_artifacts()
        self.assertTrue(moved_stage.is_dir())
        self.assertTrue(stage.is_dir())

    def test_concurrent_no_change_final_rules_parent_close_requires_recovery(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")

        def install_candidate_as_live(
            _command: list[str],
            _path: Path,
            *,
            timeout_seconds: float,
            pass_fds: tuple[int, ...] = (),
        ) -> object:
            del timeout_seconds, pass_fds
            replacement = self.rules_dir / ".concurrent-candidate-live"
            replacement.write_bytes(NEW_RULES)
            replacement.chmod(0o640)
            os.replace(replacement, self.rules)
            return TRANSACTION.ValidatorResult(0, "", "")

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
                side_effect=install_candidate_as_live,
            ) as run_validator,
            self.fault_final_rules_parent_close(errno.EIO) as close_state,
        ):
            code, payload = TRANSACTION.apply_transaction(namespace)

        run_validator.assert_called_once()
        self.assertEqual(close_state["fault_calls"], 1)
        self.assertIsNotNone(close_state["outer_fd"])
        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["operation_status"],
            "no_change_after_lock",
        )
        self.assertEqual(
            payload["reason"],
            "final_evidence_descriptor_close_failed",
        )
        self.assertEqual(
            payload["cleanup_reason"],
            "final_evidence_descriptor_close_failed",
        )
        self.assertEqual(
            payload["cleanup_failures"][0]["descriptor"],
            "rules_parent",
        )
        self.assertEqual(payload["cleanup_failures"][0]["errno"], errno.EIO)
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        self.assertFalse(terminal.exists())
        self.assertFalse(TRANSACTION.recovery_terminal_result_path(terminal).exists())
        self.assert_no_private_stage()

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

    def test_stale_recovery_terminal_result_blocks_before_backup(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        result_path = TRANSACTION.recovery_terminal_result_path(terminal)
        result_path.write_text("stale\n", encoding="utf-8")
        result_path.chmod(0o600)

        result = self.run_apply()

        self.assertEqual(result.returncode, 20, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "recovery_terminal_result_exists")
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())
        self.assertFalse(terminal.exists())
        self.assertEqual(result_path.read_text(encoding="utf-8"), "stale\n")

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

    def test_applied_finalizer_revalidates_live_and_backup_data_roles(
        self,
    ) -> None:
        for data_role in ("live", "backup"):
            for drift in ("identity", "content", "access", "link"):
                with (
                    self.subTest(data_role=data_role, drift=drift),
                    tempfile.TemporaryDirectory(
                        prefix=f"rules-applied-role-{data_role}-{drift}."
                    ) as temp_dir,
                ):
                    self.configure_isolated_case(Path(temp_dir))
                    self.write_validator("raise SystemExit(0)\n")
                    stdout = io.StringIO()
                    with (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(self.codex_home)},
                        ),
                        mock.patch.object(
                            TRANSACTION,
                            "run_validator",
                            return_value=TRANSACTION.ValidatorResult(0, "", ""),
                        ),
                        self.drift_before_transaction_lock_release(
                            data_role,
                            drift,
                        ) as injected,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        code = TRANSACTION.main(self.apply_argv())

                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(injected["count"], 1)
                    self.assertEqual(code, 30)
                    self.assertEqual(payload["status"], "recovery_required")
                    self.assertEqual(payload["operation_status"], "applied")
                    self.assertEqual(
                        payload["reason"],
                        "transaction_data_role_changed",
                    )
                    self.assertEqual(payload["data_role"], data_role)
                    self.assertEqual(
                        payload["transaction_state"],
                        "C",
                    )
                    self.assertIn(
                        injected["mismatched_property"],
                        payload["mismatched_properties"],
                    )

    def test_rollback_finalizer_revalidates_live_and_backup_data_roles(
        self,
    ) -> None:
        for data_role in ("live", "backup"):
            for drift in ("identity", "content", "access", "link"):
                with (
                    self.subTest(data_role=data_role, drift=drift),
                    tempfile.TemporaryDirectory(
                        prefix=f"rules-rollback-role-{data_role}-{drift}."
                    ) as temp_dir,
                ):
                    self.configure_isolated_case(Path(temp_dir))
                    self.write_validator("raise SystemExit(0)\n")
                    stdout = io.StringIO()
                    with (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(self.codex_home)},
                        ),
                        mock.patch.object(
                            TRANSACTION,
                            "run_validator",
                            side_effect=[
                                TRANSACTION.ValidatorResult(0, "", ""),
                                TRANSACTION.ValidatorResult(9, "", ""),
                            ],
                        ),
                        self.drift_before_transaction_lock_release(
                            data_role,
                            drift,
                        ) as injected,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        code = TRANSACTION.main(self.apply_argv())

                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(injected["count"], 1)
                    self.assertEqual(code, 30)
                    self.assertEqual(payload["status"], "recovery_required")
                    self.assertEqual(
                        payload["operation_status"],
                        "post_replace_failed_rolled_back",
                    )
                    self.assertEqual(
                        payload["reason"],
                        "transaction_data_role_changed",
                    )
                    self.assertEqual(payload["data_role"], data_role)
                    self.assertEqual(payload["transaction_state"], "R")
                    self.assertIn(
                        injected["mismatched_property"],
                        payload["mismatched_properties"],
                    )

    def test_signal_rollback_finalizer_revalidates_data_roles_without_masking_signal(
        self,
    ) -> None:
        for data_role in ("live", "backup"):
            for drift in ("identity", "content", "access", "link"):
                with (
                    self.subTest(data_role=data_role, drift=drift),
                    tempfile.TemporaryDirectory(
                        prefix=f"rules-signal-role-{data_role}-{drift}."
                    ) as temp_dir,
                ):
                    self.configure_isolated_case(Path(temp_dir))
                    self.write_validator("raise SystemExit(0)\n")
                    forwarded = TRANSACTION.ForwardedValidatorSignal(signal.SIGTERM)
                    stdout = io.StringIO()
                    with (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(self.codex_home)},
                        ),
                        mock.patch.object(
                            TRANSACTION,
                            "run_validator",
                            side_effect=[
                                TRANSACTION.ValidatorResult(0, "", ""),
                                forwarded,
                            ],
                        ),
                        self.drift_before_transaction_lock_release(
                            data_role,
                            drift,
                        ) as injected,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        code = TRANSACTION.main(self.apply_argv())

                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(injected["count"], 1)
                    self.assertEqual(code, 128 + signal.SIGTERM)
                    self.assertEqual(payload["status"], "interrupted")
                    self.assertEqual(payload["signal"], signal.SIGTERM)
                    recovery = payload["post_replace_recovery"]
                    self.assertEqual(recovery["status"], "recovery_required")
                    self.assertEqual(
                        recovery["operation_status"],
                        "post_replace_failed_rolled_back",
                    )
                    final_failure = recovery["final_evidence_failure"]
                    self.assertEqual(
                        final_failure["status"],
                        "transaction_data_role_changed",
                    )
                    self.assertEqual(final_failure["data_role"], data_role)
                    self.assertEqual(final_failure["transaction_state"], "R")
                    self.assertIn(
                        injected["mismatched_property"],
                        final_failure["mismatched_properties"],
                    )
                    finalization = payload["lock_finalization_failures"]
                    self.assertEqual(len(finalization), 1)
                    self.assertEqual(
                        finalization[0]["status"],
                        "recovery_required",
                    )
                    self.assertEqual(
                        finalization[0]["details"]["reason"],
                        "transaction_data_role_changed",
                    )

    def test_recovery_finalizer_revalidates_live_and_backup_data_roles(
        self,
    ) -> None:
        for data_role in ("live", "backup"):
            for drift in ("identity", "content", "access", "link"):
                with (
                    self.subTest(data_role=data_role, drift=drift),
                    tempfile.TemporaryDirectory(
                        prefix=f"rules-recovery-role-{data_role}-{drift}."
                    ) as temp_dir,
                ):
                    self.configure_isolated_case(Path(temp_dir))
                    self.write_validator("raise SystemExit(0)\n")
                    applied = self.run_apply()
                    self.assertEqual(applied.returncode, 0, applied.stderr)

                    stdout = io.StringIO()
                    with (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(self.codex_home)},
                        ),
                        self.drift_before_transaction_lock_release(
                            data_role,
                            drift,
                        ) as injected,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        code = TRANSACTION.main(self.recover_argv())

                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(injected["count"], 1)
                    self.assertEqual(code, 30)
                    self.assertEqual(payload["status"], "recovery_required")
                    self.assertEqual(payload["operation_status"], "recovered")
                    self.assertEqual(
                        payload["reason"],
                        "transaction_data_role_changed",
                    )
                    self.assertEqual(payload["data_role"], data_role)
                    self.assertEqual(payload["transaction_state"], "R")
                    self.assertIn(
                        injected["mismatched_property"],
                        payload["mismatched_properties"],
                    )
                    self.assertTrue(
                        any(
                            event["operation"] == "terminal_publish"
                            for event in payload["mutation_journal"]
                        )
                    )

    def test_applied_finalizer_revalidates_missing_auxiliary_roles(
        self,
    ) -> None:
        for data_role in ("prepared_candidate", "staged_backup"):
            with (
                self.subTest(data_role=data_role),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-applied-missing-role-{data_role}."
                ) as temp_dir,
            ):
                self.configure_isolated_case(Path(temp_dir))
                self.write_validator("raise SystemExit(0)\n")
                stdout = io.StringIO()
                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "run_validator",
                        return_value=TRANSACTION.ValidatorResult(0, "", ""),
                    ),
                    self.drift_before_transaction_lock_release(
                        data_role,
                        "appearance",
                    ) as injected,
                    redirect_stdout(stdout),
                    redirect_stderr(io.StringIO()),
                ):
                    code = TRANSACTION.main(self.apply_argv())

                payload = json.loads(stdout.getvalue())
                self.assertEqual(injected["count"], 1)
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(payload["operation_status"], "applied")
                self.assertEqual(
                    payload["reason"],
                    "transaction_data_role_unexpected",
                )
                self.assertEqual(payload["data_role"], data_role)
                self.assertEqual(payload["transaction_state"], "C")

    def test_rollback_finalizer_revalidates_missing_auxiliary_roles(
        self,
    ) -> None:
        for data_role in ("prepared_candidate", "staged_backup"):
            with (
                self.subTest(data_role=data_role),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-rollback-missing-role-{data_role}."
                ) as temp_dir,
            ):
                self.configure_isolated_case(Path(temp_dir))
                self.write_validator("raise SystemExit(0)\n")
                stdout = io.StringIO()
                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "run_validator",
                        side_effect=[
                            TRANSACTION.ValidatorResult(0, "", ""),
                            TRANSACTION.ValidatorResult(9, "", ""),
                        ],
                    ),
                    self.drift_before_transaction_lock_release(
                        data_role,
                        "appearance",
                    ) as injected,
                    redirect_stdout(stdout),
                    redirect_stderr(io.StringIO()),
                ):
                    code = TRANSACTION.main(self.apply_argv())

                payload = json.loads(stdout.getvalue())
                self.assertEqual(injected["count"], 1)
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["operation_status"],
                    "post_replace_failed_rolled_back",
                )
                self.assertEqual(
                    payload["reason"],
                    "transaction_data_role_unexpected",
                )
                self.assertEqual(payload["data_role"], data_role)
                self.assertEqual(payload["transaction_state"], "R")

    def test_schema_v4_c_to_r_finalizer_revalidates_missing_auxiliary_roles(
        self,
    ) -> None:
        for data_role in ("prepared_candidate", "staged_backup"):
            with (
                self.subTest(data_role=data_role),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-recovery-missing-role-{data_role}."
                ) as temp_dir,
            ):
                self.configure_isolated_case(Path(temp_dir))
                self.write_validator("raise SystemExit(0)\n")
                applied = self.run_apply()
                self.assertEqual(applied.returncode, 0, applied.stderr)
                stdout = io.StringIO()

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    self.drift_before_transaction_lock_release(
                        data_role,
                        "appearance",
                    ) as injected,
                    redirect_stdout(stdout),
                    redirect_stderr(io.StringIO()),
                ):
                    code = TRANSACTION.main(self.recover_argv())

                payload = json.loads(stdout.getvalue())
                self.assertEqual(injected["count"], 1)
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(payload["operation_status"], "recovered")
                self.assertEqual(
                    payload["reason"],
                    "transaction_data_role_unexpected",
                )
                self.assertEqual(payload["data_role"], data_role)
                self.assertEqual(payload["transaction_state"], "R")
                self.assertTrue(
                    any(
                        event["operation"] == "terminal_publish"
                        for event in payload["mutation_journal"]
                    )
                )

    def test_rollback_finalizer_propagates_persistent_evidence_drift(
        self,
    ) -> None:
        for drift in ("identity", "content", "access", "link", "parent"):
            with (
                self.subTest(drift=drift),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-rollback-finalizer-{drift}."
                ) as temp_dir,
            ):
                self.configure_isolated_case(Path(temp_dir))
                self.write_validator(
                    """\
                    from pathlib import Path
                    import sys

                    if Path(sys.argv[1]).name == "default.rules":
                        raise SystemExit(9)
                    """
                )
                real_record_terminal = TRANSACTION.record_recovery_terminal
                drift_status: str | None = None
                drift_property: str | None = None

                def record_then_drift(
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    nonlocal drift_status, drift_property
                    result = real_record_terminal(*args, **kwargs)
                    drift_status, drift_property = (
                        self.inject_final_apply_evidence_drift(drift)
                    )
                    return result

                stdout = io.StringIO()
                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "record_recovery_terminal",
                        side_effect=record_then_drift,
                    ),
                    redirect_stdout(stdout),
                    redirect_stderr(io.StringIO()),
                ):
                    code = TRANSACTION.main(self.apply_argv())

                assert drift_status is not None
                assert drift_property is not None
                payload = json.loads(stdout.getvalue())
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["operation_status"],
                    "post_replace_failed_rolled_back",
                )
                self.assertEqual(payload["reason"], drift_status)
                self.assertIn(
                    drift_property,
                    payload["mismatched_properties"],
                )
                self.assertEqual(
                    Path(payload["recovery_locators"]["receipt"]).resolve(),
                    self.receipt.resolve(),
                )
                self.assertEqual(
                    Path(payload["recovery_locators"]["backup"]).resolve(),
                    self.backup.resolve(),
                )
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_signal_rollback_keeps_signal_primary_on_final_evidence_drift(
        self,
    ) -> None:
        for drift in ("identity", "content", "access", "link", "parent"):
            with (
                self.subTest(drift=drift),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-signal-finalizer-{drift}."
                ) as temp_dir,
            ):
                self.configure_isolated_case(Path(temp_dir))
                self.write_validator("raise SystemExit(0)\n")
                forwarded = TRANSACTION.ForwardedValidatorSignal(signal.SIGTERM)
                real_record_terminal = TRANSACTION.record_recovery_terminal
                drift_status: str | None = None
                drift_property: str | None = None

                def record_then_drift(
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    nonlocal drift_status, drift_property
                    result = real_record_terminal(*args, **kwargs)
                    drift_status, drift_property = (
                        self.inject_final_apply_evidence_drift(drift)
                    )
                    return result

                stdout = io.StringIO()
                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "run_validator",
                        side_effect=[
                            TRANSACTION.ValidatorResult(0, "", ""),
                            forwarded,
                        ],
                    ) as run_validator,
                    mock.patch.object(
                        TRANSACTION,
                        "record_recovery_terminal",
                        side_effect=record_then_drift,
                    ),
                    redirect_stdout(stdout),
                    redirect_stderr(io.StringIO()),
                ):
                    code = TRANSACTION.main(self.apply_argv())

                assert drift_status is not None
                assert drift_property is not None
                self.assertEqual(run_validator.call_count, 2)
                payload = json.loads(stdout.getvalue())
                self.assertEqual(code, 128 + signal.SIGTERM)
                self.assertEqual(payload["status"], "interrupted")
                self.assertEqual(payload["signal"], signal.SIGTERM)
                recovery = payload["post_replace_recovery"]
                self.assertEqual(recovery["status"], "recovery_required")
                self.assertEqual(
                    recovery["operation_status"],
                    "post_replace_failed_rolled_back",
                )
                self.assertEqual(
                    recovery["final_evidence_failure"]["status"],
                    drift_status,
                )
                self.assertIn(
                    drift_property,
                    recovery["final_evidence_failure"]["mismatched_properties"],
                )
                finalization = payload["lock_finalization_failures"]
                self.assertEqual(len(finalization), 1)
                self.assertEqual(
                    finalization[0]["descriptor"],
                    "before-release",
                )
                self.assertEqual(
                    finalization[0]["status"],
                    "recovery_required",
                )
                self.assertEqual(
                    finalization[0]["details"]["reason"],
                    drift_status,
                )
                self.assertIn(
                    drift_property,
                    finalization[0]["details"]["mismatched_properties"],
                )
                self.assertEqual(
                    Path(
                        finalization[0]["details"]["recovery_locators"]["receipt"]
                    ).resolve(),
                    self.receipt.resolve(),
                )
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_post_replace_validator_raw_failure_preserves_cleanup_evidence(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        primary = OSError(
            errno.EIO,
            "fault-injected post-replacement validator read failure",
        )
        primary.validator_cleanup_failures = [
            TRANSACTION.structured_operation_failure(
                "validator-emergency-cleanup",
                descriptor,
                OSError(
                    errno.EIO,
                    f"fault-injected {descriptor} failure",
                ),
            )
            for descriptor in ("term", "drain", "kill", "reap")
        ]

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "run_validator",
                side_effect=[
                    TRANSACTION.ValidatorResult(0, "", ""),
                    primary,
                ],
            ) as run_validator,
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(run_validator.call_count, 2)
        self.assertEqual(
            run_validator.call_args_list[1].args[1].resolve(),
            self.rules.resolve(),
        )
        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.exit_code, 30)
        self.assertEqual(raised.exception.details["reason"], "apply_io_failed")
        self.assertIs(raised.exception.__cause__, primary)
        self.assertEqual(
            [
                failure["descriptor"]
                for failure in raised.exception.details["validator_cleanup_failures"]
            ],
            ["term", "drain", "kill", "reap"],
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertTrue(self.receipt.is_file())
        self.assert_no_private_stage()

    def test_post_replace_primary_preserves_all_lock_finalization_evidence(
        self,
    ) -> None:
        expected_property = {
            "identity": "object_identity",
            "content": "content",
            "access": "access_policy",
        }
        for primary_kind in ("validator_io", "transaction"):
            for drift in ("identity", "content", "access"):
                with (
                    self.subTest(primary_kind=primary_kind, drift=drift),
                    tempfile.TemporaryDirectory(
                        prefix=f"rules-primary-lock-{primary_kind}-{drift}."
                    ) as temp_dir,
                ):
                    self.configure_isolated_case(Path(temp_dir))
                    self.write_validator("raise SystemExit(0)\n")
                    primary: BaseException
                    expected_reason: str
                    if primary_kind == "validator_io":
                        primary = OSError(
                            errno.EIO,
                            "fault-injected post-replacement validator failure",
                        )
                        expected_reason = "apply_io_failed"
                    else:
                        primary = TRANSACTION.TransactionError(
                            "validator_runtime_failed",
                            "fault-injected post-replacement transaction failure",
                            details={"primary_marker": primary_kind},
                        )
                        expected_reason = "validator_runtime_failed"

                    validator_failures = [
                        TRANSACTION.structured_operation_failure(
                            "validator-emergency-cleanup",
                            descriptor,
                            OSError(
                                errno.EIO,
                                f"fault-injected {descriptor} failure",
                            ),
                        )
                        for descriptor in ("term", "reap")
                    ]
                    descriptor_failures = [
                        TRANSACTION.structured_operation_failure(
                            "close",
                            descriptor,
                            OSError(
                                errno.EIO,
                                f"fault-injected {descriptor} failure",
                            ),
                        )
                        for descriptor in ("stdout-pipe", "stderr-pipe")
                    ]
                    TRANSACTION.attach_validator_failures_to_exception(
                        primary,
                        validator_failures,
                    )
                    TRANSACTION.attach_failures_to_exception(
                        primary,
                        "cleanup_failures",
                        descriptor_failures,
                    )

                    # Fail while the applied result is assembled, after its
                    # release-time data roles have been recorded.
                    class FailingValidatorResult:
                        valid = True

                        def to_json(self) -> dict[str, object]:
                            raise primary

                    stdout = io.StringIO()
                    with (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(self.codex_home)},
                        ),
                        mock.patch.object(
                            TRANSACTION,
                            "run_validator",
                            side_effect=[
                                TRANSACTION.ValidatorResult(0, "", ""),
                                FailingValidatorResult(),
                            ],
                        ) as run_validator,
                        self.drift_before_transaction_lock_release(
                            "live",
                            drift,
                        ) as injected,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        code = TRANSACTION.main(self.apply_argv())

                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(run_validator.call_count, 2)
                    self.assertEqual(injected["count"], 1)
                    self.assertEqual(code, 30)
                    self.assertEqual(payload["status"], "recovery_required")
                    self.assertEqual(payload["reason"], expected_reason)
                    self.assertEqual(payload["message"], str(primary))
                    if primary_kind == "transaction":
                        self.assertEqual(
                            payload["primary_marker"],
                            primary_kind,
                        )
                    self.assertEqual(
                        [
                            failure["descriptor"]
                            for failure in payload["validator_cleanup_failures"]
                        ],
                        ["term", "reap"],
                    )
                    self.assertEqual(
                        [
                            failure["descriptor"]
                            for failure in payload["cleanup_failures"]
                        ],
                        ["stdout-pipe", "stderr-pipe"],
                    )
                    self.assertIn(
                        "lock_finalization_failures",
                        payload,
                        json.dumps(
                            {
                                "payload": payload,
                                "primary_attributes": vars(primary),
                            },
                            sort_keys=True,
                            default=str,
                        ),
                    )
                    finalization = payload["lock_finalization_failures"]
                    self.assertEqual(
                        [failure["descriptor"] for failure in finalization],
                        ["before-release"],
                    )
                    self.assertEqual(
                        finalization[0]["status"],
                        "recovery_required",
                    )
                    self.assertEqual(
                        finalization[0]["details"]["reason"],
                        "transaction_data_role_changed",
                    )
                    self.assertEqual(
                        finalization[0]["details"]["data_role"],
                        "live",
                    )
                    self.assertIn(
                        expected_property[drift],
                        finalization[0]["details"]["mismatched_properties"],
                    )
                    self.assertEqual(
                        list(
                            TRANSACTION.structured_secondary_failure_evidence(primary)
                        ),
                        [
                            "validator_cleanup_failures",
                            "lock_finalization_failures",
                            "cleanup_failures",
                        ],
                    )
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

                self.assertEqual(recover.returncode, 30, recover.stderr)
                recovery_payload = json.loads(recover.stdout)
                self.assertEqual(recovery_payload["status"], "recovery_required")
                self.assertEqual(
                    recovery_payload["reason"],
                    "schema_v4_state_unrecognized",
                )
                self.assertIn(
                    {
                        "operation": "possible_prior_transaction_state",
                        "phase": "observed",
                        "state": "unknown",
                    },
                    recovery_payload["mutation_journal"],
                )
                self.assertEqual(
                    Path(recovery_payload["recovery_locators"]["receipt"]).resolve(),
                    self.receipt.resolve(),
                )
                self.assertEqual(
                    Path(recovery_payload["recovery_locators"]["backup"]).resolve(),
                    self.backup.resolve(),
                )
                if action in ("replace", "content"):
                    self.assertEqual(self.rules.read_bytes(), LATER_RULES)
                elif action == "access":
                    self.assertEqual(self.rules.read_bytes(), NEW_RULES)
                    self.assertEqual(stat.S_IMODE(self.rules.stat().st_mode), 0o600)
                else:
                    self.assertFalse(self.rules.exists())

    def test_recovery_backup_fifo_is_rejected_without_blocking_under_lock(
        self,
    ) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.backup.unlink()
        os.mkfifo(self.backup, 0o600)

        recovered = self.run_recover(timeout=5)

        self.assertEqual(recovered.returncode, 40, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "backup_not_regular")
        self.assertTrue(stat.S_ISFIFO(self.backup.stat().st_mode))
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertTrue(self.receipt.exists())
        self.assert_no_private_stage()

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
                    os.stat(stage_root, follow_symlinks=False),
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

    def test_schema_v3_recovery_stage_close_faults_are_structured(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        stage_root = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        receipt["schema_version"] = 3
        receipt["staged_backup_parent"] = TRANSACTION.Snapshot.from_stat(
            os.stat(stage_root, follow_symlinks=False),
            b"",
        ).to_json()
        receipt.pop("prepared_candidate_path", None)
        receipt.pop("prepared_candidate_parent", None)
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)
        stdout = io.StringIO()

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            self.fault_private_stage_descriptor_closes() as closed,
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            code = TRANSACTION.main(self.recover_argv())

        self.assertEqual(code, 30)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["operation_status"], "recovered")
        self.assertEqual(
            payload["cleanup_reason"],
            TRANSACTION.PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
        )
        self.assertEqual(
            [failure["descriptor_class"] for failure in payload["cleanup_failures"]],
            ["private_stage", "rules_parent"],
        )
        self.assertEqual(len(closed), 2)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_schema_v4_recovery_stage_close_faults_are_structured(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        stdout = io.StringIO()

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            self.fault_private_stage_descriptor_closes() as closed,
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            code = TRANSACTION.main(self.recover_argv())

        self.assertEqual(code, 30)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["operation_status"], "recovered")
        self.assertEqual(
            payload["cleanup_reason"],
            TRANSACTION.PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
        )
        self.assertEqual(
            [failure["descriptor_class"] for failure in payload["cleanup_failures"]],
            ["private_stage", "rules_parent"],
        )
        self.assertEqual(len(closed), 2)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

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

    def test_reserved_terminal_does_not_downgrade_unknown_post_exchange_state(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")

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
            redirect_stderr(io.StringIO()),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        staged = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(staged.read_bytes(), OLD_RULES)
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())
        self.backup.write_bytes(LATER_RULES)
        self.backup.chmod(0o640)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 30, recovered.stderr)
        recovered_payload = json.loads(recovered.stdout)
        self.assertEqual(recovered_payload["status"], "recovery_required")
        self.assertEqual(
            recovered_payload["reason"],
            "schema_v4_state_unrecognized",
        )
        self.assertEqual(
            recovered_payload["observed_roles"],
            {
                "live": "I",
                "backup": "?",
                "staged_backup": "O",
                "prepared_candidate": "M",
            },
        )
        self.assertTrue(
            any(
                event["operation"] == "prior_exchange_state"
                and event["phase"] == "observed"
                for event in recovered_payload["mutation_journal"]
            )
        )
        terminal = json.loads(
            TRANSACTION.recovery_terminal_path(self.receipt).read_text(encoding="utf-8")
        )
        self.assertEqual(terminal["state"], "reserved")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), LATER_RULES)
        self.assertEqual(staged.read_bytes(), OLD_RULES)

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

    def test_original_live_fsync_and_revalidation_precede_receipt_and_exchange(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        events: list[str] = []
        real_durability = TRANSACTION.fsync_and_revalidate_original_live
        real_write_receipt = TRANSACTION.write_receipt
        real_exchange = TRANSACTION.atomic_rename_exchange
        real_fsync = TRANSACTION.os.fsync

        def observe_durability(
            binding: object,
            parent: object,
            expected: object,
        ) -> object:
            assert isinstance(binding, TRANSACTION.BoundFile)

            def observe_fsync(fd: int) -> None:
                if fd == binding.fd:
                    events.append("original_live_fsync")
                real_fsync(fd)

            with mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=observe_fsync,
            ):
                result = real_durability(binding, parent, expected)
            events.append("original_live_revalidated")
            return result

        def observe_receipt(*args: object, **kwargs: object) -> object:
            events.append("receipt_begin")
            result = real_write_receipt(*args, **kwargs)
            events.append("receipt_end")
            return result

        def observe_exchange(*args: object, **kwargs: object) -> None:
            events.append("exchange")
            real_exchange(*args, **kwargs)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "fsync_and_revalidate_original_live",
                side_effect=observe_durability,
            ),
            mock.patch.object(
                TRANSACTION,
                "write_receipt",
                side_effect=observe_receipt,
            ),
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
                side_effect=observe_exchange,
            ),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "applied")
        self.assertLess(
            events.index("original_live_fsync"),
            events.index("original_live_revalidated"),
        )
        self.assertLess(
            events.index("original_live_revalidated"),
            events.index("receipt_begin"),
        )
        self.assertLess(events.index("receipt_end"), events.index("exchange"))

    def test_original_live_fsync_error_fails_before_receipt_and_exchange(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_durability = TRANSACTION.fsync_and_revalidate_original_live
        real_fsync = TRANSACTION.os.fsync
        injected = False

        def fail_durability_fsync(
            binding: object,
            parent: object,
            expected: object,
        ) -> object:
            assert isinstance(binding, TRANSACTION.BoundFile)

            def fail_fsync(fd: int) -> None:
                nonlocal injected
                if fd == binding.fd and not injected:
                    injected = True
                    raise OSError(errno.EIO, "fault-injected original live fsync")
                real_fsync(fd)

            with mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=fail_fsync,
            ):
                return real_durability(binding, parent, expected)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "fsync_and_revalidate_original_live",
                side_effect=fail_durability_fsync,
            ),
            mock.patch.object(
                TRANSACTION,
                "write_receipt",
                wraps=TRANSACTION.write_receipt,
            ) as receipt_mock,
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
                wraps=TRANSACTION.atomic_rename_exchange,
            ) as exchange_mock,
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(injected)
        self.assertEqual(raised.exception.status, "original_live_fsync_failed")
        self.assertEqual(raised.exception.exit_code, 20)
        self.assertEqual(raised.exception.details["phase"], "fsync")
        self.assertEqual(
            raised.exception.details["fsync_error"]["errno"],
            errno.EIO,
        )
        self.assertIn("fsync", raised.exception.details["failed_checks"])
        self.assertEqual(
            raised.exception.details["publication_state"],
            {
                "receipt_written": False,
                "exchange_started": False,
            },
        )
        receipt_mock.assert_not_called()
        exchange_mock.assert_not_called()
        self.assert_original_live_durability_failure_left_no_evidence()

    def assert_original_live_post_fsync_drift(
        self,
        mutation: Callable[[], None],
        *,
        expected_mismatch: str | None,
        expected_entry_state: str = "present",
        expected_failed_check: str | None = None,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_durability = TRANSACTION.fsync_and_revalidate_original_live
        real_fsync = TRANSACTION.os.fsync
        injected = False

        def mutate_after_fsync(
            binding: object,
            parent: object,
            expected: object,
        ) -> object:
            assert isinstance(binding, TRANSACTION.BoundFile)

            def fsync_then_mutate(fd: int) -> None:
                nonlocal injected
                real_fsync(fd)
                if fd == binding.fd and not injected:
                    injected = True
                    mutation()

            with mock.patch.object(
                TRANSACTION.os,
                "fsync",
                side_effect=fsync_then_mutate,
            ):
                return real_durability(binding, parent, expected)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "fsync_and_revalidate_original_live",
                side_effect=mutate_after_fsync,
            ),
            mock.patch.object(
                TRANSACTION,
                "write_receipt",
                wraps=TRANSACTION.write_receipt,
            ) as receipt_mock,
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
                wraps=TRANSACTION.atomic_rename_exchange,
            ) as exchange_mock,
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(injected)
        self.assertEqual(
            raised.exception.status,
            "original_live_changed_after_fsync",
        )
        self.assertEqual(raised.exception.exit_code, 20)
        details = raised.exception.details
        self.assertEqual(details["phase"], "post_fsync_revalidation")
        self.assertEqual(
            details["publication_state"],
            {
                "receipt_written": False,
                "exchange_started": False,
            },
        )
        self.assertEqual(
            details["entry_observation"]["state"],
            expected_entry_state,
        )
        if expected_mismatch is not None:
            self.assertIn(expected_mismatch, details["mismatched_properties"])
        if expected_failed_check is not None:
            self.assertIn(expected_failed_check, details["failed_checks"])
        receipt_mock.assert_not_called()
        exchange_mock.assert_not_called()
        self.assert_original_live_durability_failure_left_no_evidence()

    def assert_original_live_durability_failure_left_no_evidence(self) -> None:
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.backup.exists())
        self.assertFalse(TRANSACTION.prepared_candidate_path(self.receipt).exists())
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        self.assertFalse(terminal.exists())
        self.assertFalse(TRANSACTION.recovery_terminal_result_path(terminal).exists())
        self.assert_no_private_stage()

    def test_original_live_replacement_after_fsync_fails_closed(self) -> None:
        replacement = self.rules_dir / "default.rules.replacement"

        def replace_live() -> None:
            replacement.write_bytes(OLD_RULES)
            replacement.chmod(0o640)
            os.replace(replacement, self.rules)

        self.assert_original_live_post_fsync_drift(
            replace_live,
            expected_mismatch="object_identity",
            expected_failed_check="parent_dirent_binding",
        )

    def test_original_live_content_drift_after_fsync_fails_closed(self) -> None:
        self.assert_original_live_post_fsync_drift(
            lambda: self.rules.write_bytes(LATER_RULES),
            expected_mismatch="content",
        )

    def test_original_live_access_drift_after_fsync_fails_closed(self) -> None:
        self.assert_original_live_post_fsync_drift(
            lambda: self.rules.chmod(0o600),
            expected_mismatch="access_policy",
        )

    def test_original_live_link_drift_after_fsync_fails_closed(self) -> None:
        alias = self.rules_dir / "default.rules.alias"
        self.assert_original_live_post_fsync_drift(
            lambda: os.link(self.rules, alias),
            expected_mismatch="object_policy",
        )

    def test_original_live_dirent_drift_after_fsync_fails_closed(self) -> None:
        moved = self.rules_dir / "default.rules.moved"
        self.assert_original_live_post_fsync_drift(
            lambda: os.rename(self.rules, moved),
            expected_mismatch=None,
            expected_entry_state="missing",
            expected_failed_check="parent_dirent_binding",
        )

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

    def test_schema_v4_q_finalizer_revalidates_prepared_and_staged_roles(
        self,
    ) -> None:
        cases = (
            (
                "prepared_candidate",
                "missing",
                "transaction_data_role_missing",
                None,
            ),
            (
                "prepared_candidate",
                "identity",
                "transaction_data_role_changed",
                "object_identity",
            ),
            (
                "prepared_candidate",
                "content",
                "transaction_data_role_changed",
                "content",
            ),
            (
                "prepared_candidate",
                "access",
                "transaction_data_role_changed",
                "access_policy",
            ),
            (
                "prepared_candidate",
                "link",
                "transaction_data_role_changed",
                "object_policy",
            ),
            (
                "staged_backup",
                "appearance",
                "transaction_data_role_unexpected",
                None,
            ),
        )
        for operation_status in ("recovered", "already_original"):
            for data_role, drift, reason, mismatched_property in cases:
                with (
                    self.subTest(
                        operation_status=operation_status,
                        data_role=data_role,
                        drift=drift,
                    ),
                    tempfile.TemporaryDirectory(
                        prefix=(f"rules-q-{operation_status}-{data_role}-{drift}.")
                    ) as temp_dir,
                ):
                    self.configure_isolated_case(Path(temp_dir))
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
                        self.assertRaises(TRANSACTION.TransactionError),
                    ):
                        TRANSACTION.apply_transaction(self.apply_namespace())

                    if operation_status == "already_original":
                        first = self.run_recover()
                        self.assertEqual(first.returncode, 0, first.stderr)
                        self.assertEqual(
                            json.loads(first.stdout)["status"],
                            "recovered",
                        )

                    stdout = io.StringIO()
                    with (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(self.codex_home)},
                        ),
                        self.drift_before_transaction_lock_release(
                            data_role,
                            drift,
                        ) as injected,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        code = TRANSACTION.main(self.recover_argv())

                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(injected["count"], 1)
                    self.assertEqual(code, 30)
                    self.assertEqual(payload["status"], "recovery_required")
                    self.assertEqual(
                        payload["operation_status"],
                        operation_status,
                    )
                    self.assertEqual(payload["reason"], reason)
                    self.assertEqual(payload["data_role"], data_role)
                    self.assertEqual(payload["transaction_state"], "Q")
                    if mismatched_property is not None:
                        self.assertIn(
                            mismatched_property,
                            payload["mismatched_properties"],
                        )
                    self.assertEqual(
                        Path(
                            payload["recovery_locators"]["prepared_candidate"]
                        ).resolve(),
                        TRANSACTION.prepared_candidate_path(self.receipt).resolve(),
                    )

    def test_schema_v4_q_result_with_replaced_prepared_requires_recovery_on_retry(
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
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

        self.assertEqual(first_code, 0)
        self.assertEqual(first["status"], "recovered")
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        self.assertTrue(TRANSACTION.recovery_terminal_result_path(terminal).is_file())
        replacement = prepared.with_name(f"{prepared.name}.replacement")
        replacement.write_bytes(NEW_RULES)
        replacement.chmod(0o600)
        os.replace(replacement, prepared)

        for attempt in range(2):
            with self.subTest(attempt=attempt):
                recovered = self.run_recover()
                self.assertEqual(recovered.returncode, 30, recovered.stderr)
                payload = json.loads(recovered.stdout)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["reason"],
                    "schema_v4_state_unrecognized",
                )
                self.assertEqual(
                    payload["observed_state"]["terminal_state"],
                    TRANSACTION.RECOVERY_TERMINAL_RESTORED,
                )
                self.assertEqual(
                    payload["observed_state"]["roles"]["prepared_candidate"],
                    "?",
                )
                self.assertTrue(
                    any(
                        event["operation"] == "terminal_publish"
                        and event["phase"] == "observed"
                        for event in payload["mutation_journal"]
                    )
                )
                self.assertEqual(
                    Path(payload["recovery_locators"]["prepared_candidate"]).resolve(),
                    prepared.resolve(),
                )

    def test_schema_v4_proven_p_survives_second_auxiliary_probe_failure(
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        staged = stage / "candidate"
        os.rename(prepared, staged)
        real_probe = TRANSACTION.probe_fixed_stage_for_recovery
        probe_count = 0

        def fail_second_probe(
            rules_parent: object,
        ) -> tuple[object, object]:
            nonlocal probe_count
            probe_count += 1
            if probe_count == 2:
                raise TRANSACTION.TransactionError(
                    "private_stage_unreadable",
                    "fault-injected second auxiliary probe failure",
                )
            return real_probe(rules_parent)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "probe_fixed_stage_for_recovery",
                side_effect=fail_second_probe,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertEqual(probe_count, 2)
        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "private_stage_unreadable")
        self.assertEqual(payload["transaction_state"], "P")
        self.assertEqual(
            payload["observed_state"]["transaction_state"],
            "P",
        )
        self.assertEqual(
            payload["observed_state"]["roles"],
            {
                "live": "O",
                "backup": "M",
                "staged_backup": "I",
                "prepared_candidate": "M",
            },
        )

    def test_schema_v4_failed_auxiliary_probe_never_promotes_q_or_p_to_q(
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "probe_fixed_stage_for_recovery",
                side_effect=TRANSACTION.TransactionError(
                    "private_stage_unreadable",
                    "fault-injected first auxiliary probe failure",
                ),
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
        self.assertEqual(payload["reason"], "private_stage_unreadable")
        self.assertEqual(payload["transaction_state"], "Q_or_P")
        self.assertEqual(
            payload["observed_state"]["transaction_state_hint"],
            "Q_or_P",
        )
        self.assertEqual(
            payload["observed_state"]["roles"]["staged_backup"],
            "unprobed",
        )
        self.assertTrue(
            any(
                event["operation"] == "possible_prior_transaction_state"
                and event["state"] == "Q_or_P"
                for event in payload["mutation_journal"]
            )
        )

    def test_schema_v4_p_stage_candidate_loss_requires_recovery(self) -> None:
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        staged = stage / "candidate"
        os.rename(prepared, staged)
        stage_fd = os.open(
            stage,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        prepared_parent_fd = os.open(
            prepared.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(stage_fd)
            os.fsync(prepared_parent_fd)
            staged.unlink()
            os.fsync(stage_fd)
        finally:
            os.close(prepared_parent_fd)
            os.close(stage_fd)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 30, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "schema_v4_state_unrecognized")
        self.assertEqual(payload["transaction_state"], "Q_or_P")
        self.assertEqual(
            payload["observed_roles"],
            {
                "live": "O",
                "backup": "M",
                "staged_backup": "M",
                "prepared_candidate": "M",
            },
        )
        self.assertTrue(
            any(
                event["operation"] == "possible_prior_transaction_state"
                and event["phase"] == "observed"
                and event["state"] == "Q_or_P"
                for event in payload["mutation_journal"]
            )
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["staged_backup"]).resolve(),
            staged.resolve(),
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["prepared_candidate"]).resolve(),
            prepared.resolve(),
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())

    def test_schema_v4_r_backup_loss_requires_recovery(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
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
            os.fsync(rules_fd)
            os.unlink(self.backup.name, dir_fd=rules_fd)
            os.fsync(rules_fd)
        finally:
            os.close(rules_fd)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 30, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "schema_v4_state_unrecognized")
        self.assertEqual(payload["transaction_state"], "Q_or_P")
        self.assertEqual(
            payload["observed_roles"],
            {
                "live": "O",
                "backup": "M",
                "staged_backup": "M",
                "prepared_candidate": "M",
            },
        )
        self.assertTrue(
            any(
                event["operation"] == "possible_prior_transaction_state"
                and event["phase"] == "observed"
                and event["state"] == "Q_or_P"
                for event in payload["mutation_journal"]
            )
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["backup"]).resolve(),
            self.backup.resolve(),
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["receipt"]).resolve(),
            self.receipt.resolve(),
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())

    def test_schema_v4_reserved_prepared_drift_requires_recovery(
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
        replacement = prepared.with_name(f"{prepared.name}.replacement")
        replacement.write_bytes(NEW_RULES)
        replacement.chmod(0o600)
        os.replace(replacement, prepared)

        for attempt in range(2):
            with self.subTest(attempt=attempt):
                recovered = self.run_recover()
                self.assertEqual(recovered.returncode, 30, recovered.stderr)
                payload = json.loads(recovered.stdout)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["reason"],
                    "schema_v4_state_unrecognized",
                )
                self.assertTrue(
                    any(
                        event["operation"] == "possible_prior_transaction_state"
                        and event["state"] == "Q_or_P"
                        for event in payload["mutation_journal"]
                    )
                )
                self.assertEqual(
                    payload["observed_state"]["roles"]["prepared_candidate"],
                    "?",
                )
                self.assertEqual(
                    Path(payload["recovery_locators"]["prepared_candidate"]).resolve(),
                    prepared.resolve(),
                )
                self.assertFalse(
                    TRANSACTION.recovery_terminal_result_path(
                        TRANSACTION.recovery_terminal_path(self.receipt)
                    ).exists()
                )
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertFalse(self.backup.exists())

    def test_schema_v4_proven_q_replaced_terminal_is_pre_mutation_refusal(
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        reservation = terminal.read_bytes()
        terminal.rename(terminal.with_name("recovery.bound"))
        terminal.write_bytes(reservation)
        terminal.chmod(0o600)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 40, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "recovery_terminal_binding_changed")
        self.assertEqual(payload["transaction_state"], "Q")
        self.assertNotIn("mutation_journal", payload)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())

    def test_schema_v4_q_or_p_unknown_stage_is_ambiguous_recovery_required(
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        unknown_candidate = stage / "candidate"
        unknown_candidate.write_bytes(LATER_RULES)
        unknown_candidate.chmod(0o600)

        for attempt in range(2):
            with self.subTest(attempt=attempt):
                recovered = self.run_recover()
                self.assertEqual(recovered.returncode, 30, recovered.stderr)
                payload = json.loads(recovered.stdout)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["reason"],
                    "schema_v4_state_unrecognized",
                )
                self.assertTrue(
                    any(
                        event["operation"] == "possible_prior_transaction_state"
                        and event["phase"] == "observed"
                        and event["state"] == "P"
                        for event in payload["mutation_journal"]
                    )
                )
                self.assertEqual(
                    payload["observed_state"]["roles"]["staged_backup"],
                    "?",
                )
                self.assertEqual(
                    Path(payload["recovery_locators"]["staged_backup"]).resolve(),
                    unknown_candidate.resolve(),
                )

    def test_schema_v4_r_unknown_stage_candidate_delegation_and_retry_require_recovery(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
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

        stage_candidate = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
        real_recover_v3 = TRANSACTION.recover_schema_v3_transaction
        injected = False

        def inject_unknown_candidate(**kwargs: object) -> tuple[int, dict[str, object]]:
            nonlocal injected
            if not injected:
                stage_candidate.write_bytes(LATER_RULES)
                stage_candidate.chmod(0o600)
                injected = True
            return real_recover_v3(**kwargs)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "recover_schema_v3_transaction",
                side_effect=inject_unknown_candidate,
            ),
        ):
            first_code, first = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(injected)
        self.assertEqual(first_code, 30)
        self.assertEqual(first["status"], "recovery_required")
        self.assertEqual(first["reason"], "schema_v3_state_unrecognized")
        self.assertTrue(
            any(
                event["operation"] == "prior_transaction_state"
                and event["phase"] == "observed"
                and event["state"] == "R"
                for event in first["mutation_journal"]
            )
        )
        self.assertEqual(
            Path(first["recovery_locators"]["staged_backup"]).resolve(),
            stage_candidate.resolve(),
        )

        repeated = self.run_recover()
        self.assertEqual(repeated.returncode, 30, repeated.stderr)
        repeated_payload = json.loads(repeated.stdout)
        self.assertEqual(repeated_payload["status"], "recovery_required")
        self.assertEqual(
            repeated_payload["reason"],
            "schema_v4_state_unrecognized",
        )
        self.assertEqual(
            repeated_payload["observed_state"]["roles"]["staged_backup"],
            "?",
        )
        self.assertTrue(repeated_payload["mutation_journal"])
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

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

    def test_live_change_after_staged_publication_requires_recovery(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_validate = TRANSACTION.ApplyEvidenceBindings.validate
        injected = False

        def validate_then_change_live(
            evidence: object,
        ) -> None:
            nonlocal injected
            assert isinstance(evidence, TRANSACTION.ApplyEvidenceBindings)
            real_validate(evidence)
            if evidence.candidate_in_stage and not injected:
                self.rules.write_bytes(LATER_RULES)
                injected = True

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "run_validator",
                return_value=TRANSACTION.ValidatorResult(0, "", ""),
            ),
            mock.patch.object(
                TRANSACTION.ApplyEvidenceBindings,
                "validate",
                autospec=True,
                side_effect=validate_then_change_live,
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = TRANSACTION.main(self.apply_argv())

        payload = json.loads(stdout.getvalue())
        self.assertTrue(injected)
        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["operation_status"],
            "live_changed_before_replace",
        )
        self.assertEqual(payload["reason"], "live_changed_before_replace")
        self.assertEqual(payload["mismatched_properties"], ["content"])
        self.assertEqual(
            payload["pre_replace_failure"]["mismatched_properties"],
            ["content"],
        )
        locators = payload["recovery_locators"]
        self.assertEqual(
            set(locators),
            {
                "receipt",
                "live",
                "backup",
                "staged_backup",
                "prepared_candidate",
                "recovery_terminal",
                "recovery_terminal_result",
            },
        )
        self.assertEqual(Path(locators["receipt"]).resolve(), self.receipt.resolve())
        self.assertEqual(Path(locators["live"]).resolve(), self.rules.resolve())
        self.assertEqual(Path(locators["backup"]).resolve(), self.backup.resolve())
        staged = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME / "candidate"
        self.assertEqual(
            Path(locators["staged_backup"]).resolve(),
            staged.resolve(),
        )
        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
        self.assertEqual(
            Path(locators["prepared_candidate"]).resolve(),
            prepared.resolve(),
        )
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        self.assertEqual(
            Path(locators["recovery_terminal"]).resolve(),
            terminal.resolve(),
        )
        self.assertEqual(
            Path(locators["recovery_terminal_result"]).resolve(),
            TRANSACTION.recovery_terminal_result_path(terminal).resolve(),
        )
        self.assertEqual(self.rules.read_bytes(), LATER_RULES)
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(terminal.is_file())
        self.assertFalse(TRANSACTION.recovery_terminal_result_path(terminal).exists())
        self.assertFalse(self.backup.exists())
        self.assertFalse(prepared.exists())
        self.assertEqual(staged.read_bytes(), NEW_RULES)
        self.assertIn('"status": "cleanup_warning"', stderr.getvalue())

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

    def test_receipt_cannot_equal_fixed_private_stage(self) -> None:
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        self.receipt = stage

        payload = self.assert_stage_namespace_receipt_rejected()

        self.assertEqual(payload["path"], str(stage.resolve()))
        self.assertEqual(list(stage.iterdir()), [])

    def test_receipt_cannot_be_descendant_of_fixed_private_stage(self) -> None:
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        nested = stage / "nested"
        nested.mkdir(parents=True, mode=0o700)
        self.receipt = nested / "recovery.json"

        payload = self.assert_stage_namespace_receipt_rejected()

        self.assertEqual(
            payload["canonical_path"],
            str(self.receipt.resolve(strict=False)),
        )
        self.assertEqual(list(nested.iterdir()), [])

    def test_receipt_cannot_be_ancestor_of_fixed_private_stage(self) -> None:
        self.receipt = self.rules_dir

        payload = self.assert_stage_namespace_receipt_rejected()

        self.assertEqual(payload["path"], str(self.rules_dir.resolve()))
        self.assertFalse((self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME).exists())

    def test_receipt_stage_symlink_alias_is_rejected_before_lock(self) -> None:
        stage = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        stage.mkdir(mode=0o700)
        alias = self.root / "stage-alias"
        alias.symlink_to(stage, target_is_directory=True)
        self.receipt = alias / "recovery.json"

        payload = self.assert_stage_namespace_receipt_rejected()

        self.assertEqual(
            payload["canonical_path"],
            str((stage / "recovery.json").resolve(strict=False)),
        )
        self.assertEqual(list(stage.iterdir()), [])

    def test_stage_casefold_alias_is_rejected_before_any_write(self) -> None:
        self.receipt = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME.swapcase()

        payload = self.assert_stage_namespace_receipt_rejected()

        self.assertIn("case folding", payload["message"])
        self.assertFalse(self.receipt.exists())

    def test_stage_unicode_alias_is_rejected_before_any_write(self) -> None:
        unicode_alias = TRANSACTION.PRIVATE_STAGE_NAME.replace("s", "\u017f", 1)
        self.assertEqual(
            TRANSACTION.normalized_namespace_component(unicode_alias),
            TRANSACTION.normalized_namespace_component(TRANSACTION.PRIVATE_STAGE_NAME),
        )
        self.receipt = self.rules_dir / unicode_alias

        payload = self.assert_stage_namespace_receipt_rejected()

        self.assertIn("Unicode normalization", payload["message"])
        self.assertFalse(self.receipt.exists())

    def test_transaction_leaf_casefold_and_nfkc_aliases_are_rejected_pairwise(
        self,
    ) -> None:
        lock_name = ".default.rules.apply.lock"
        aliases = (
            lock_name.swapcase(),
            lock_name.replace("s", "\u017f", 1),
        )
        self.write_validator("raise SystemExit(0)\n")

        for alias in aliases:
            with self.subTest(alias=alias):
                self.assertEqual(
                    TRANSACTION.normalized_namespace_component(alias),
                    TRANSACTION.normalized_namespace_component(lock_name),
                )
                self.receipt = self.rules_dir / alias

                result = self.run_apply()

                self.assertEqual(result.returncode, 50, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["status"], "path_invalid")
                self.assertIn(
                    "descriptor-bound parent leaf",
                    payload["message"],
                )
                self.assertEqual(payload["left_label"], "lock")
                self.assertEqual(payload["right_label"], "receipt")
                self.assertFalse(
                    (self.rules_dir / ".default.rules.apply.lock").exists()
                )
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)

    def test_stage_name_prefix_sibling_is_not_namespace_overlap(self) -> None:
        receipt_parent = self.rules_dir / (f"{TRANSACTION.PRIVATE_STAGE_NAME}-shadow")
        receipt_parent.mkdir(mode=0o700)
        self.receipt = receipt_parent / "recovery.json"
        self.write_validator("raise SystemExit(0)\n")

        result = self.run_apply()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "applied")
        self.assertTrue(self.receipt.is_file())
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assert_no_private_stage()

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

    def test_recover_requires_operator_for_untrusted_post_apply_inode(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        replacement = self.rules_dir / ".same-original-new-inode"
        replacement.write_bytes(OLD_RULES)
        replacement.chmod(0o640)
        os.replace(replacement, self.rules)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 30, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "schema_v4_state_unrecognized")
        self.assertIn(
            {
                "operation": "possible_prior_transaction_state",
                "phase": "observed",
                "state": "unknown",
            },
            payload["mutation_journal"],
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["receipt"]).resolve(),
            self.receipt.resolve(),
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["backup"]).resolve(),
            self.backup.resolve(),
        )
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

    def test_delegated_v3_receipt_races_after_mutation_require_recovery(
        self,
    ) -> None:
        for action in ("replace", "content", "hardlink", "mode", "parent"):
            with (
                self.subTest(action=action),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-recovery-receipt-{action}."
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
                self.backup_name = f"default.rules.bak-receipt-{action}"
                self.backup = self.rules_dir / self.backup_name
                self.validator = case_root / "validator.py"
                self.write_validator("raise SystemExit(0)\n")
                applied = self.run_apply()
                self.assertEqual(applied.returncode, 0, applied.stderr)
                receipt_bytes = self.receipt.read_bytes()
                real_rollback = TRANSACTION.rollback
                mutated = False

                def mutate_receipt_after_rollback(
                    **kwargs: object,
                ) -> tuple[bool, dict[str, object]]:
                    nonlocal mutated
                    result = real_rollback(**kwargs)
                    if not result[0] or mutated:
                        return result
                    mutated = True
                    if action == "replace":
                        moved = self.receipt.with_name("recovery.bound")
                        os.rename(self.receipt, moved)
                        self.receipt.write_bytes(receipt_bytes)
                        self.receipt.chmod(0o600)
                    elif action == "content":
                        self.receipt.write_bytes(receipt_bytes + b" ")
                    elif action == "hardlink":
                        os.link(
                            self.receipt,
                            self.receipt.with_name("recovery.alias"),
                        )
                    elif action == "mode":
                        self.receipt.chmod(0o640)
                    else:
                        moved_parent = case_root / "task.bound"
                        os.rename(self.receipt.parent, moved_parent)
                        self.receipt.parent.mkdir(mode=0o700)
                    return result

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "rollback",
                        side_effect=mutate_receipt_after_rollback,
                    ),
                ):
                    code, payload = TRANSACTION.recover_transaction(
                        SimpleNamespace(
                            receipt=str(self.receipt),
                            lock_timeout_seconds=2.0,
                        )
                    )

                self.assertTrue(mutated)
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    Path(payload["recovery_locators"]["receipt"]).resolve(),
                    self.receipt.resolve(),
                )
                journal = payload["mutation_journal"]
                self.assertTrue(
                    any(
                        event["operation"] == "C_to_R" and event["phase"] == "entry"
                        for event in journal
                    )
                )
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_receipt_change_between_parse_and_lock_is_recovery_refused(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt_bytes = self.receipt.read_bytes()
        real_shared_lock = TRANSACTION.shared_lock
        mutated = False

        @contextmanager
        def mutate_before_lock(*args: object, **kwargs: object):
            nonlocal mutated
            self.receipt.write_bytes(receipt_bytes + b" ")
            mutated = True
            with real_shared_lock(*args, **kwargs) as binding:
                yield binding

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "shared_lock",
                side_effect=mutate_before_lock,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(mutated)
        self.assertEqual(code, 40)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "receipt_changed")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)

    def test_terminal_result_publication_crash_points_are_retryable(self) -> None:
        for fault in (
            "write",
            "file_fsync",
            "rename_before",
            "rename_after",
            "directory_fsync",
        ):
            with (
                self.subTest(fault=fault),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-terminal-crash-{fault}."
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
                self.backup_name = f"default.rules.bak-terminal-{fault}"
                self.backup = self.rules_dir / self.backup_name
                self.validator = case_root / "validator.py"
                self.write_validator("raise SystemExit(0)\n")
                applied = self.run_apply()
                self.assertEqual(applied.returncode, 0, applied.stderr)
                terminal = TRANSACTION.recovery_terminal_path(self.receipt)
                reservation = terminal.read_bytes()
                real_exclusive = TRANSACTION._write_exclusive_bound
                real_atomic = TRANSACTION.atomic_rename_no_replace
                real_write = TRANSACTION.os.write
                real_fsync = TRANSACTION.os.fsync
                injected = False
                rename_completed = False

                def faulting_exclusive(
                    path: Path,
                    payload: bytes,
                    **kwargs: object,
                ) -> tuple[int, object]:
                    nonlocal injected
                    if TRANSACTION.RECOVERY_TERMINAL_TEMP_MARKER not in path.name:
                        return real_exclusive(path, payload, **kwargs)
                    if fault == "write":

                        def fail_write(fd: int, data: bytes) -> int:
                            nonlocal injected
                            if not injected:
                                injected = True
                                raise OSError(errno.EIO, "fault-injected result write")
                            return real_write(fd, data)

                        with mock.patch.object(
                            TRANSACTION.os,
                            "write",
                            side_effect=fail_write,
                        ):
                            return real_exclusive(path, payload, **kwargs)
                    if fault == "file_fsync":

                        def fail_file_fsync(fd: int) -> None:
                            nonlocal injected
                            if not injected:
                                injected = True
                                raise OSError(
                                    errno.EIO,
                                    "fault-injected result file fsync",
                                )
                            real_fsync(fd)

                        with mock.patch.object(
                            TRANSACTION.os,
                            "fsync",
                            side_effect=fail_file_fsync,
                        ):
                            return real_exclusive(path, payload, **kwargs)
                    return real_exclusive(path, payload, **kwargs)

                def faulting_atomic(*args: object) -> None:
                    nonlocal injected, rename_completed
                    if fault == "rename_before" and not injected:
                        injected = True
                        raise OSError(errno.EIO, "fault-injected pre-rename crash")
                    real_atomic(*args)
                    rename_completed = True
                    if fault == "rename_after" and not injected:
                        injected = True
                        raise OSError(errno.EIO, "fault-injected post-rename crash")

                def faulting_fsync(fd: int) -> None:
                    nonlocal injected
                    if fault == "directory_fsync" and rename_completed and not injected:
                        injected = True
                        raise OSError(errno.EIO, "fault-injected directory fsync")
                    real_fsync(fd)

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "_write_exclusive_bound",
                        side_effect=faulting_exclusive,
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "atomic_rename_no_replace",
                        side_effect=faulting_atomic,
                    ),
                    mock.patch.object(
                        TRANSACTION.os,
                        "fsync",
                        side_effect=faulting_fsync,
                    ),
                ):
                    first_code, first = TRANSACTION.recover_transaction(
                        SimpleNamespace(
                            receipt=str(self.receipt),
                            lock_timeout_seconds=2.0,
                        )
                    )

                self.assertTrue(injected)
                self.assertEqual(terminal.read_bytes(), reservation)
                if fault == "rename_after":
                    self.assertEqual(first_code, 0)
                else:
                    self.assertEqual(first_code, 30)
                    self.assertEqual(first["status"], "recovery_required")
                    self.assertTrue(first["mutation_journal"])
                    if fault in {"file_fsync", "rename_before"}:
                        self.assertEqual(
                            first["retention_status"],
                            "verified_pending_result",
                        )
                        self.assertIsNotNone(first["pending_locator"])
                    elif fault == "write":
                        self.assertEqual(
                            first["retention_status"],
                            "retention_incomplete",
                        )
                        self.assertIsNone(first.get("pending_locator"))

                repeated = self.run_recover()
                repeated_payload = json.loads(repeated.stdout)
                if fault == "write":
                    self.assertEqual(repeated.returncode, 30, repeated.stderr)
                    self.assertEqual(
                        repeated_payload["status"],
                        "recovery_required",
                    )
                    self.assertEqual(
                        repeated_payload["retention_status"],
                        "retention_incomplete",
                    )
                    pending_prefix = (
                        f"{terminal.name}"
                        f"{TRANSACTION.RECOVERY_TERMINAL_RESULT_SUFFIX}"
                        f"{TRANSACTION.RECOVERY_TERMINAL_TEMP_MARKER}"
                    )
                    self.assertEqual(
                        len(
                            [
                                child
                                for child in terminal.parent.iterdir()
                                if child.name.startswith(pending_prefix)
                            ]
                        ),
                        1,
                    )
                else:
                    self.assertEqual(
                        repeated.returncode,
                        0,
                        repeated.stderr + repeated.stdout,
                    )
                    self.assertIn(
                        repeated_payload["status"],
                        {"recovered", "already_original"},
                    )
                self.assertEqual(terminal.read_bytes(), reservation)
                self.assertEqual(self.rules.read_bytes(), OLD_RULES)
                self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_terminal_result_pre_rename_validation_failure_retains_exact_pending(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        real_validate = TRANSACTION.RecoveryTerminalEvidence.validate
        injected = False

        def fail_with_pending(evidence: object) -> dict[str, object]:
            nonlocal injected
            assert isinstance(evidence, TRANSACTION.RecoveryTerminalEvidence)
            pending_prefix = (
                f"{evidence.result_path.name}"
                f"{TRANSACTION.RECOVERY_TERMINAL_TEMP_MARKER}"
            )
            if (
                not injected
                and evidence.result is None
                and any(
                    child.name.startswith(pending_prefix)
                    for child in evidence.parent.path.iterdir()
                )
            ):
                injected = True
                raise TRANSACTION.TransactionError(
                    "fault_injected_control_failure",
                    "fault-injected pre-rename control failure",
                )
            return real_validate(evidence)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.RecoveryTerminalEvidence,
                "validate",
                autospec=True,
                side_effect=fail_with_pending,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(injected)
        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["retention_status"],
            "verified_pending_result",
        )
        pending_locator = Path(payload["pending_locator"])
        self.assertTrue(pending_locator.is_file())

        real_atomic = TRANSACTION.atomic_rename_no_replace
        blocked_reuse_rename = False

        def fail_reused_pending_rename(*args: object) -> None:
            nonlocal blocked_reuse_rename
            if (
                not blocked_reuse_rename
                and len(args) >= 2
                and args[1] == pending_locator.name
            ):
                blocked_reuse_rename = True
                raise OSError(errno.EIO, "fault-injected reused-pending rename")
            real_atomic(*args)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_no_replace",
                side_effect=fail_reused_pending_rename,
            ),
        ):
            repeated_code, repeated_payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(blocked_reuse_rename)
        self.assertEqual(repeated_code, 30)
        self.assertEqual(repeated_payload["status"], "recovery_required")
        self.assertEqual(
            repeated_payload["retention_status"],
            "verified_pending_result",
        )
        self.assertEqual(
            repeated_payload["pending_locator"],
            str(pending_locator),
        )

        repeated = self.run_recover()
        self.assertEqual(
            repeated.returncode,
            0,
            repeated.stderr + repeated.stdout,
        )
        self.assertFalse(pending_locator.exists())

    def test_pending_terminal_locator_rejects_unlink_and_replacement_races(
        self,
    ) -> None:
        for action in ("unlink", "replace"):
            with (
                self.subTest(action=action),
                tempfile.TemporaryDirectory(
                    prefix=f"rules-pending-retention-{action}."
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
                self.backup_name = f"default.rules.bak-pending-{action}"
                self.backup = self.rules_dir / self.backup_name
                self.validator = case_root / "validator.py"
                self.write_validator("raise SystemExit(0)\n")
                applied = self.run_apply()
                self.assertEqual(applied.returncode, 0, applied.stderr)

                real_validate = TRANSACTION.RecoveryTerminalEvidence.validate
                real_observe = TRANSACTION.observe_directory_entry
                validation_failed = False
                entry_mutated = False

                def fail_with_pending(evidence: object) -> dict[str, object]:
                    nonlocal validation_failed
                    assert isinstance(
                        evidence,
                        TRANSACTION.RecoveryTerminalEvidence,
                    )
                    pending_prefix = (
                        f"{evidence.result_path.name}"
                        f"{TRANSACTION.RECOVERY_TERMINAL_TEMP_MARKER}"
                    )
                    if (
                        not validation_failed
                        and evidence.result is None
                        and any(
                            child.name.startswith(pending_prefix)
                            for child in evidence.parent.path.iterdir()
                        )
                    ):
                        validation_failed = True
                        raise TRANSACTION.TransactionError(
                            "fault_injected_control_failure",
                            "fault-injected pre-rename control failure",
                        )
                    return real_validate(evidence)

                def mutate_pending_before_observation(
                    directory_fd: int,
                    name: str,
                    *,
                    expected: object = None,
                ) -> dict[str, object]:
                    nonlocal entry_mutated
                    if (
                        not entry_mutated
                        and expected is not None
                        and TRANSACTION.RECOVERY_TERMINAL_TEMP_MARKER in name
                    ):
                        matched_observation = real_observe(
                            directory_fd,
                            name,
                            expected=expected,
                        )
                        entry_mutated = True
                        if action == "unlink":
                            os.unlink(name, dir_fd=directory_fd)
                        else:
                            os.rename(
                                name,
                                f"{name}.attacker-bound",
                                src_dir_fd=directory_fd,
                                dst_dir_fd=directory_fd,
                            )
                            replacement_fd = os.open(
                                name,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                                0o600,
                                dir_fd=directory_fd,
                            )
                            try:
                                os.write(replacement_fd, b"replacement\n")
                            finally:
                                os.close(replacement_fd)
                        return matched_observation
                    return real_observe(
                        directory_fd,
                        name,
                        expected=expected,
                    )

                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                    ),
                    mock.patch.object(
                        TRANSACTION.RecoveryTerminalEvidence,
                        "validate",
                        autospec=True,
                        side_effect=fail_with_pending,
                    ),
                    mock.patch.object(
                        TRANSACTION,
                        "observe_directory_entry",
                        side_effect=mutate_pending_before_observation,
                    ),
                ):
                    code, payload = TRANSACTION.recover_transaction(
                        SimpleNamespace(
                            receipt=str(self.receipt),
                            lock_timeout_seconds=2.0,
                        )
                    )

                self.assertTrue(validation_failed)
                self.assertTrue(entry_mutated)
                self.assertEqual(code, 30)
                self.assertEqual(payload["status"], "recovery_required")
                self.assertEqual(
                    payload["retention_status"],
                    "retention_incomplete",
                )
                self.assertIsNone(payload.get("pending_locator"))
                self.assertEqual(
                    payload["pending_retention"]["retention_status"],
                    "retention_incomplete",
                )

    def test_terminal_result_publication_never_truncates_reservation(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        terminal = TRANSACTION.recovery_terminal_path(self.receipt)
        reservation = terminal.read_bytes()

        with (
            mock.patch.object(
                TRANSACTION.os,
                "ftruncate",
                side_effect=AssertionError("terminal publication must not truncate"),
            ),
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "recovered")
        self.assertEqual(terminal.read_bytes(), reservation)
        self.assertTrue(TRANSACTION.recovery_terminal_result_path(terminal).is_file())

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

    def test_recover_requires_evidence_for_replaced_terminal_after_state_c(
        self,
    ) -> None:
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

        self.assertEqual(recovered.returncode, 30, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "recovery_terminal_binding_changed")
        self.assertEqual(payload["mismatched_properties"], ["object_identity"])
        self.assertEqual(payload["transaction_state"], "C")
        self.assertTrue(
            any(
                event["operation"] == "prior_transaction_state"
                and event["phase"] == "observed"
                and event["state"] == "C"
                for event in payload["mutation_journal"]
            )
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["recovery_terminal"]).resolve(),
            terminal.resolve(),
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)

    def test_schema_v4_same_inode_terminal_rewrite_is_binding_change(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        terminal = Path(receipt["recovery_terminal_path"])
        reservation = json.loads(terminal.read_text(encoding="utf-8"))
        reservation_inode = terminal.stat().st_ino
        terminal.write_text(
            json.dumps(
                {
                    "schema_version": TRANSACTION.RECOVERY_TERMINAL_SCHEMA_VERSION,
                    "transaction_id": receipt["transaction_id"],
                    "created_unix_ns": reservation["created_unix_ns"],
                    "state": TRANSACTION.RECOVERY_TERMINAL_RESTORED,
                    "evidence_kind": "original-identity",
                    "restored": receipt["original"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        terminal.chmod(0o600)
        self.assertEqual(terminal.stat().st_ino, reservation_inode)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 30, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "recovery_terminal_binding_changed")
        self.assertIn("content", payload["mismatched_properties"])
        self.assertEqual(payload["transaction_state"], "C")
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)

    def test_schema_v3_explicitly_accepts_same_inode_terminal_rewrite(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        stage_root = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        receipt["schema_version"] = 3
        receipt["staged_backup_parent"] = TRANSACTION.Snapshot.from_stat(
            os.stat(stage_root, follow_symlinks=False),
            b"",
        ).to_json()
        receipt.pop("prepared_candidate_path", None)
        receipt.pop("prepared_candidate_parent", None)
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)
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
        terminal = Path(receipt["recovery_terminal_path"])
        reservation = json.loads(terminal.read_text(encoding="utf-8"))
        reservation_inode = terminal.stat().st_ino
        terminal.write_text(
            json.dumps(
                {
                    "schema_version": TRANSACTION.RECOVERY_TERMINAL_SCHEMA_VERSION,
                    "transaction_id": receipt["transaction_id"],
                    "created_unix_ns": reservation["created_unix_ns"],
                    "state": TRANSACTION.RECOVERY_TERMINAL_RESTORED,
                    "evidence_kind": "original-identity",
                    "restored": receipt["original"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        terminal.chmod(0o600)
        self.assertEqual(terminal.stat().st_ino, reservation_inode)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "already_original")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_schema_v3_state_p_replaced_terminal_requires_recovery(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        stage_root = self.rules_dir / TRANSACTION.PRIVATE_STAGE_NAME
        receipt["schema_version"] = 3
        receipt["staged_backup_parent"] = TRANSACTION.Snapshot.from_stat(
            os.stat(stage_root, follow_symlinks=False),
            b"",
        ).to_json()
        receipt.pop("prepared_candidate_path", None)
        receipt.pop("prepared_candidate_parent", None)
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)
        staged = stage_root / "candidate"
        os.rename(self.backup, staged)
        stage_fd = os.open(
            stage_root,
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
        terminal = Path(receipt["recovery_terminal_path"])
        reservation = terminal.read_bytes()
        terminal.rename(terminal.with_name("recovery.bound"))
        terminal.write_bytes(reservation)
        terminal.chmod(0o600)

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 30, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "recovery_terminal_binding_changed")
        self.assertEqual(payload["transaction_state"], "P")
        self.assertTrue(
            any(
                event["operation"] == "prior_transaction_state"
                and event["state"] == "P"
                for event in payload["mutation_journal"]
            )
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertFalse(self.backup.exists())
        self.assertEqual(staged.read_bytes(), NEW_RULES)

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

    def test_legacy_v1_rejects_explicit_non_single_link_policy_downgrade(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = self.rewrite_receipt_as_legacy_v1()
        for key in ("original", "installed", "backup"):
            receipt[key]["object_policy"] = {"nlink": 2}
        self.receipt.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.receipt.chmod(0o600)
        os.link(self.rules, self.root / "downgraded-live-hardlink")
        os.link(self.backup, self.root / "downgraded-backup-hardlink")

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 50, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "receipt_invalid")
        self.assertIn(
            "object_policy.nlink must be 1 when present",
            payload["message"],
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertEqual(self.rules.stat().st_nlink, 2)
        self.assertEqual(self.backup.stat().st_nlink, 2)

    def test_legacy_v1_recovery_rejects_current_live_hardlink(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        os.link(self.rules, self.root / "live-rules-hardlink")

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 40, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "live_no_longer_installed")
        self.assertIn("object_policy", payload["mismatched_properties"])

    def test_legacy_v1_recovery_rejects_current_backup_hardlink(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        os.link(self.backup, self.root / "backup-hardlink")

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 40, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(payload["reason"], "backup_changed")
        self.assertIn("object_policy", payload["mismatched_properties"])

    def test_legacy_v1_recovery_rejects_terminal_reservation_hardlink(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = self.rewrite_receipt_as_legacy_v1()
        terminal = Path(receipt["recovery_terminal_path"])
        os.link(terminal, self.root / "terminal-hardlink")

        recovered = self.run_recover()

        self.assertEqual(recovered.returncode, 40, recovered.stderr)
        payload = json.loads(recovered.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertEqual(
            payload["reason"],
            "recovery_terminal_binding_changed",
        )
        self.assertIn("object_policy", payload["mismatched_properties"])

    def test_legacy_v1_exchange_detects_live_hardlink_before_commit(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        real_exchange = TRANSACTION.atomic_rename_exchange
        hardlink = self.root / "exchange-live-hardlink"
        linked = False

        def exchange_then_hardlink(
            source_directory_fd: int,
            source_name: str,
            destination_directory_fd: int,
            destination_name: str,
        ) -> None:
            nonlocal linked
            real_exchange(
                source_directory_fd,
                source_name,
                destination_directory_fd,
                destination_name,
            )
            if not linked and destination_name == self.rules.name:
                linked = True
                os.link(self.rules, hardlink)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "atomic_rename_exchange",
                side_effect=exchange_then_hardlink,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(linked)
        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(
            payload["rollback"]["rollback_status"],
            "recovery_required",
        )
        self.assertEqual(self.rules.stat().st_nlink, 2)

    def test_legacy_v1_post_recovery_hardlink_blocks_terminal_success(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        real_record_terminal = TRANSACTION.record_recovery_terminal
        hardlink = self.root / "post-recovery-live-hardlink"

        def record_then_hardlink(*args: object, **kwargs: object) -> object:
            result = real_record_terminal(*args, **kwargs)
            os.link(self.rules, hardlink)
            return result

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "record_recovery_terminal",
                side_effect=record_then_hardlink,
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
        self.assertEqual(
            payload["recovery_terminal_failure"]["status"],
            "recovery_terminal_live_mismatch",
        )

    def test_legacy_v1_already_original_rechecks_current_link_policy(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        first = self.run_recover()
        self.assertEqual(first.returncode, 0, first.stderr)
        os.link(self.rules, self.root / "restored-live-hardlink")

        repeated = self.run_recover()

        self.assertEqual(repeated.returncode, 40, repeated.stderr)
        payload = json.loads(repeated.stdout)
        self.assertEqual(payload["status"], "recovery_refused")
        self.assertIn("object_policy", payload["mismatched_properties"])

    def test_legacy_already_original_finalizer_revalidates_live_data_role(
        self,
    ) -> None:
        for schema_version in (1, 2):
            for drift in ("identity", "content", "access", "link"):
                with (
                    self.subTest(schema_version=schema_version, drift=drift),
                    tempfile.TemporaryDirectory(
                        prefix=(
                            f"rules-legacy-v{schema_version}-already-original-{drift}."
                        )
                    ) as temp_dir,
                ):
                    self.configure_isolated_case(Path(temp_dir))
                    self.write_validator("raise SystemExit(0)\n")
                    applied = self.run_apply()
                    self.assertEqual(applied.returncode, 0, applied.stderr)
                    if schema_version == 1:
                        self.rewrite_receipt_as_legacy_v1()
                    else:
                        self.rewrite_receipt_as_legacy_v2()
                    first = self.run_recover()
                    self.assertEqual(first.returncode, 0, first.stderr)
                    stdout = io.StringIO()

                    with (
                        mock.patch.dict(
                            os.environ,
                            {"CODEX_HOME": str(self.codex_home)},
                        ),
                        self.drift_before_transaction_lock_release(
                            "live",
                            drift,
                        ) as injected,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        code = TRANSACTION.main(self.recover_argv())

                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(injected["count"], 1)
                    self.assertEqual(code, 30)
                    self.assertEqual(payload["status"], "recovery_required")
                    self.assertEqual(
                        payload["operation_status"],
                        "already_original",
                    )
                    self.assertEqual(
                        payload["reason"],
                        "transaction_data_role_changed",
                    )
                    self.assertEqual(payload["data_role"], "live")
                    self.assertEqual(
                        payload["transaction_state"],
                        "legacy_original",
                    )
                    self.assertIn(
                        injected["mismatched_property"],
                        payload["mismatched_properties"],
                    )

    def test_legacy_completed_exchange_then_parent_drift_requires_recovery(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        real_rollback = TRANSACTION.rollback
        moved_parent = self.root / "task.bound"
        drifted = False

        def rollback_then_replace_parent(
            **kwargs: object,
        ) -> tuple[bool, dict[str, object]]:
            nonlocal drifted
            result = real_rollback(**kwargs)
            if result[0] and not drifted:
                drifted = True
                os.rename(self.receipt.parent, moved_parent)
                self.receipt.parent.mkdir(mode=0o700)
            return result

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "rollback",
                side_effect=rollback_then_replace_parent,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertTrue(drifted)
        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["reason"], "receipt_parent_changed")
        self.assertEqual(
            Path(payload["recovery_locators"]["receipt"]).resolve(),
            self.receipt.resolve(),
        )
        self.assertTrue(
            any(
                event["operation"] == "legacy_rollback_exchange"
                and event["phase"] == "completion"
                for event in payload["mutation_journal"]
            )
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_legacy_completed_exchange_then_lock_close_fault_requires_recovery(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        real_close_descriptors = TRANSACTION.close_descriptors_best_effort

        def fail_lock_close(
            descriptors: list[tuple[str, int]],
            *,
            release_uncertain: bool = False,
        ) -> list[dict[str, object]]:
            if (
                release_uncertain
                and descriptors
                and descriptors[0][0] == "transaction_lock"
            ):
                TRANSACTION.os.close(descriptors[0][1])
                return [
                    TRANSACTION.structured_operation_failure(
                        "close",
                        "transaction_lock",
                        OSError(errno.EIO, "fault-injected legacy lock close"),
                        release_uncertain=True,
                    )
                ]
            return real_close_descriptors(
                descriptors,
                release_uncertain=release_uncertain,
            )

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "close_descriptors_best_effort",
                side_effect=fail_lock_close,
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
        self.assertEqual(payload["reason"], "lock_close_failed")
        self.assertEqual(
            payload["cleanup_failures"][0]["descriptor"],
            "transaction_lock",
        )
        self.assertTrue(payload["cleanup_failures"][0]["release_uncertain"])
        self.assertTrue(
            any(
                event["operation"] == "legacy_rollback_exchange"
                and event["phase"] == "completion"
                for event in payload["mutation_journal"]
            )
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["backup"]).resolve(),
            self.backup.resolve(),
        )
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

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

    def test_legacy_recovery_stage_close_faults_are_structured_in_stdout(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.rewrite_receipt_as_legacy_v1()
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            self.fault_private_stage_descriptor_closes() as closed,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = TRANSACTION.main(self.recover_argv())

        self.assertEqual(code, 30)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["operation_status"], "recovered")
        self.assertEqual(
            payload["cleanup_reason"],
            TRANSACTION.PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
        )
        self.assertEqual(
            [failure["descriptor_class"] for failure in payload["cleanup_failures"]],
            ["private_stage", "rules_parent"],
        )
        self.assertTrue(
            any(
                event["operation"] == "legacy_rollback_exchange"
                for event in payload["mutation_journal"]
            )
        )
        self.assertEqual(len(closed), 2)
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)
        self.assertIn("descriptor_cleanup_failed", stderr.getvalue())

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

    def test_apply_stage_close_faults_are_structured_in_stdout(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            self.fault_private_stage_descriptor_closes() as closed,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = TRANSACTION.main(self.apply_argv())

        self.assertEqual(code, 30)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["operation_status"], "applied")
        self.assertEqual(
            payload["cleanup_reason"],
            TRANSACTION.PRIVATE_STAGE_DESCRIPTOR_CLEANUP_REASON,
        )
        self.assertEqual(
            [failure["descriptor_class"] for failure in payload["cleanup_failures"]],
            ["private_stage", "rules_parent"],
        )
        self.assertEqual(
            [failure["descriptor"] for failure in payload["cleanup_failures"]],
            ["private_stage", "rules_parent"],
        )
        self.assertEqual(len(closed), 2)
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        cleanup = json.loads(stderr.getvalue().strip())
        self.assertTrue(
            any(
                warning["status"] == "descriptor_cleanup_failed"
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

    def test_apply_closes_terminal_result_evidence_only_after_lock_exit(
        self,
    ) -> None:
        self.write_validator(
            """\
            from pathlib import Path
            import sys

            if Path(sys.argv[1]).name == "default.rules":
                raise SystemExit(9)
            """
        )
        real_close = TRANSACTION.ApplyEvidenceBindings.close
        close_observed = False

        def assert_close_order(bindings: object) -> None:
            nonlocal close_observed
            assert isinstance(bindings, TRANSACTION.ApplyEvidenceBindings)
            assert bindings.receipt is not None
            assert bindings.recovery_terminal_result is not None
            for fd in (
                bindings.receipt.fd,
                bindings.recovery_terminal.fd,
                bindings.recovery_terminal_result.fd,
                bindings.receipt_parent.fd,
                bindings.rules_parent.fd,
            ):
                os.fstat(fd)
            with self.assertRaises(OSError) as lock_closed:
                os.fstat(bindings.lock.fd)
            self.assertEqual(lock_closed.exception.errno, errno.EBADF)
            close_observed = True
            real_close(bindings)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.ApplyEvidenceBindings,
                "close",
                autospec=True,
                side_effect=assert_close_order,
            ),
        ):
            exit_code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(close_observed)
        self.assertEqual(exit_code, 30)
        self.assertEqual(payload["status"], "post_replace_failed_rolled_back")
        self.assertEqual(self.rules.read_bytes(), OLD_RULES)
        self.assertEqual(self.backup.read_bytes(), NEW_RULES)

    def test_applied_final_evidence_close_failure_requires_recovery(self) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_close = TRANSACTION.ApplyEvidenceBindings.close
        close_calls = 0

        def fail_final_evidence_close(
            bindings: object,
        ) -> list[dict[str, object]]:
            nonlocal close_calls
            assert isinstance(bindings, TRANSACTION.ApplyEvidenceBindings)
            close_calls += 1
            failures = real_close(bindings)
            failures.append(
                TRANSACTION.structured_operation_failure(
                    "close",
                    "rules_parent",
                    OSError(
                        errno.EIO,
                        "fault-injected final evidence close",
                    ),
                )
            )
            return failures

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.ApplyEvidenceBindings,
                "close",
                autospec=True,
                side_effect=fail_final_evidence_close,
            ),
        ):
            code, payload = TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertEqual(close_calls, 1)
        self.assertEqual(code, 30)
        self.assertEqual(payload["status"], "recovery_required")
        self.assertEqual(payload["operation_status"], "applied")
        self.assertEqual(
            payload["reason"],
            "final_evidence_descriptor_close_failed",
        )
        self.assertEqual(
            payload["cleanup_reason"],
            "final_evidence_descriptor_close_failed",
        )
        self.assertEqual(
            payload["cleanup_failures"][0]["descriptor"],
            "rules_parent",
        )
        self.assertEqual(payload["cleanup_failures"][0]["errno"], errno.EIO)
        self.assertEqual(
            Path(payload["backup_path"]).resolve(),
            self.backup.resolve(),
        )
        self.assertEqual(
            Path(payload["receipt_path"]).resolve(),
            self.receipt.resolve(),
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertTrue(self.receipt.is_file())
        self.assert_no_private_stage()

    def test_lock_path_replacement_failure_preserves_evidence_until_lock_exit(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        lock = self.rules_dir / ".default.rules.apply.lock"
        moved_lock = self.rules_dir / ".default.rules.apply.lock.bound"
        real_cleanup = TRANSACTION.PrivateStage._cleanup_fixed_stage
        real_close = TRANSACTION.ApplyEvidenceBindings.close
        close_observed = False
        lock_replaced = False

        def replace_lock_after_cleanup(stage: object) -> list[dict[str, object]]:
            nonlocal lock_replaced
            assert isinstance(stage, TRANSACTION.PrivateStage)
            result = real_cleanup(stage)
            os.rename(lock, moved_lock)
            lock.write_bytes(b"")
            lock.chmod(0o600)
            lock_replaced = True
            return result

        def assert_bound_evidence_then_fail_close(bindings: object) -> None:
            nonlocal close_observed
            assert isinstance(bindings, TRANSACTION.ApplyEvidenceBindings)
            assert bindings.receipt is not None
            for fd in (
                bindings.receipt.fd,
                bindings.recovery_terminal.fd,
                bindings.receipt_parent.fd,
                bindings.rules_parent.fd,
            ):
                os.fstat(fd)
            with self.assertRaises(OSError) as lock_closed:
                os.fstat(bindings.lock.fd)
            self.assertEqual(lock_closed.exception.errno, errno.EBADF)
            close_observed = True
            real_close(bindings)
            raise OSError(errno.EIO, "fault-injected evidence close failure")

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.PrivateStage,
                "_cleanup_fixed_stage",
                autospec=True,
                side_effect=replace_lock_after_cleanup,
            ),
            mock.patch.object(
                TRANSACTION.ApplyEvidenceBindings,
                "close",
                autospec=True,
                side_effect=assert_bound_evidence_then_fail_close,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(lock_replaced)
        self.assertTrue(close_observed)
        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.exit_code, 30)
        self.assertEqual(raised.exception.details["reason"], "lock_changed")
        cleanup_failures = raised.exception.details["cleanup_failures"]
        self.assertTrue(
            any(
                failure["descriptor"] == "apply_evidence_group"
                for failure in cleanup_failures
            )
        )
        if callable(getattr(raised.exception, "add_note", None)):
            notes = getattr(raised.exception, "__notes__", [])
            self.assertTrue(
                any("descriptor cleanup also failed" in note for note in notes)
            )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertTrue(self.receipt.is_file())

    def test_shared_lock_final_revalidation_wins_over_close_failure(
        self,
    ) -> None:
        lock = self.rules_dir / ".default.rules.apply.lock"
        real_revalidate = TRANSACTION.revalidate_lock
        real_close = TRANSACTION.os.close
        revalidation_count = 0
        lock_fd: int | None = None

        def fail_final_revalidation(binding: object) -> None:
            nonlocal revalidation_count
            revalidation_count += 1
            if revalidation_count == 3:
                raise TRANSACTION.TransactionError(
                    "lock_changed",
                    "fault-injected final lock replacement",
                    details={"mismatched_properties": ["object_identity"]},
                )
            real_revalidate(binding)

        def fail_lock_close(fd: int) -> None:
            if fd == lock_fd:
                real_close(fd)
                raise OSError(errno.EIO, "fault-injected lock close")
            real_close(fd)

        with (
            mock.patch.object(
                TRANSACTION,
                "revalidate_lock",
                side_effect=fail_final_revalidation,
            ),
            mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=fail_lock_close,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            with TRANSACTION.shared_lock(lock, timeout_seconds=2.0) as binding:
                lock_fd = binding.fd

        self.assertEqual(raised.exception.status, "lock_changed")
        self.assertEqual(
            raised.exception.details["mismatched_properties"],
            ["object_identity"],
        )
        self.assertEqual(
            raised.exception.details["cleanup_failures"],
            [
                {
                    "operation": "close",
                    "descriptor": "transaction_lock",
                    "error_type": "OSError",
                    "message": "[Errno 5] fault-injected lock close",
                    "errno": errno.EIO,
                    "errno_name": "EIO",
                    "release_uncertain": True,
                }
            ],
        )
        assert lock_fd is not None
        with self.assertRaises(OSError) as closed:
            os.fstat(lock_fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_shared_lock_close_only_failure_is_structured(self) -> None:
        lock = self.rules_dir / ".default.rules.apply.lock"
        real_close = TRANSACTION.os.close
        lock_fd: int | None = None

        def interrupt_lock_close(fd: int) -> None:
            if fd == lock_fd:
                real_close(fd)
                raise OSError(errno.EINTR, "fault-injected interrupted close")
            real_close(fd)

        with (
            mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=interrupt_lock_close,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            with TRANSACTION.shared_lock(lock, timeout_seconds=2.0) as binding:
                lock_fd = binding.fd

        self.assertEqual(raised.exception.status, "lock_close_failed")
        self.assertEqual(
            raised.exception.details["cleanup_failures"][0]["descriptor"],
            "transaction_lock",
        )
        self.assertEqual(
            raised.exception.details["cleanup_failures"][0]["errno"],
            errno.EINTR,
        )
        self.assertTrue(
            raised.exception.details["cleanup_failures"][0]["release_uncertain"]
        )

    def test_apply_keeps_evidence_bound_until_lock_close_fault_is_classified(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        real_close_descriptors = TRANSACTION.close_descriptors_best_effort
        real_evidence_close = TRANSACTION.ApplyEvidenceBindings.close
        evidence_close_observed = False

        def fail_lock_descriptor_close(
            descriptors: list[tuple[str, int]],
            *,
            release_uncertain: bool = False,
        ) -> list[dict[str, object]]:
            if (
                release_uncertain
                and descriptors
                and descriptors[0][0] == "transaction_lock"
            ):
                TRANSACTION.os.close(descriptors[0][1])
                return [
                    TRANSACTION.structured_operation_failure(
                        "close",
                        "transaction_lock",
                        OSError(errno.EIO, "fault-injected lock close"),
                        release_uncertain=True,
                    )
                ]
            return real_close_descriptors(
                descriptors,
                release_uncertain=release_uncertain,
            )

        def assert_evidence_bound(bindings: object) -> list[dict[str, object]]:
            nonlocal evidence_close_observed
            assert isinstance(bindings, TRANSACTION.ApplyEvidenceBindings)
            assert bindings.receipt is not None
            for fd in (
                bindings.receipt.fd,
                bindings.recovery_terminal.fd,
                bindings.receipt_parent.fd,
                bindings.rules_parent.fd,
            ):
                os.fstat(fd)
            with self.assertRaises(OSError) as lock_closed:
                os.fstat(bindings.lock.fd)
            self.assertEqual(lock_closed.exception.errno, errno.EBADF)
            evidence_close_observed = True
            return real_evidence_close(bindings)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION,
                "close_descriptors_best_effort",
                side_effect=fail_lock_descriptor_close,
            ),
            mock.patch.object(
                TRANSACTION.ApplyEvidenceBindings,
                "close",
                autospec=True,
                side_effect=assert_evidence_bound,
            ),
            self.assertRaises(TRANSACTION.TransactionError) as raised,
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())

        self.assertTrue(evidence_close_observed)
        self.assertEqual(raised.exception.status, "recovery_required")
        self.assertEqual(raised.exception.details["reason"], "lock_close_failed")
        self.assertEqual(
            raised.exception.details["cleanup_failures"][0]["descriptor"],
            "transaction_lock",
        )
        self.assertTrue(
            raised.exception.details["cleanup_failures"][0]["release_uncertain"]
        )
        self.assertEqual(self.rules.read_bytes(), NEW_RULES)
        self.assertEqual(self.backup.read_bytes(), OLD_RULES)
        self.assertTrue(self.receipt.is_file())

    def test_recovered_terminal_result_preserves_multi_close_failures(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        real_terminal_close = TRANSACTION.RecoveryTerminalEvidence.close
        real_receipt_close = TRANSACTION.RecoveryReceiptEvidence.close
        real_os_close = TRANSACTION.os.close
        closed_fds: list[int] = []

        def faulting_close(
            faults: dict[int, tuple[int, str]],
        ):
            def close(fd: int) -> None:
                real_os_close(fd)
                closed_fds.append(fd)
                if fd in faults:
                    error_number, message = faults[fd]
                    raise OSError(error_number, message)

            return close

        def close_terminal(evidence: object) -> list[dict[str, object]]:
            assert isinstance(evidence, TRANSACTION.RecoveryTerminalEvidence)
            assert evidence.result is not None
            with mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=faulting_close(
                    {
                        evidence.result.fd: (
                            errno.EIO,
                            "fault-injected result close",
                        ),
                        evidence.reservation.fd: (
                            errno.EINTR,
                            "fault-injected reservation close",
                        ),
                    }
                ),
            ):
                return real_terminal_close(evidence)

        def close_receipt(evidence: object) -> list[dict[str, object]]:
            assert isinstance(evidence, TRANSACTION.RecoveryReceiptEvidence)
            with mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=faulting_close(
                    {
                        evidence.binding.fd: (
                            errno.EIO,
                            "fault-injected receipt close",
                        ),
                        evidence.parent.fd: (
                            errno.EINTR,
                            "fault-injected receipt parent close",
                        ),
                    }
                ),
            ):
                return real_receipt_close(evidence)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.RecoveryTerminalEvidence,
                "close",
                autospec=True,
                side_effect=close_terminal,
            ),
            mock.patch.object(
                TRANSACTION.RecoveryReceiptEvidence,
                "close",
                autospec=True,
                side_effect=close_receipt,
            ),
        ):
            code, payload = TRANSACTION.recover_transaction(
                SimpleNamespace(
                    receipt=str(self.receipt),
                    lock_timeout_seconds=2.0,
                )
            )

        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "recovered")
        self.assertEqual(
            [failure["descriptor"] for failure in payload["cleanup_failures"]],
            [
                "recovery_terminal_result",
                "recovery_terminal_reservation",
                "recovery_receipt",
                "receipt_parent",
            ],
        )
        self.assertEqual(
            [failure["errno"] for failure in payload["cleanup_failures"]],
            [errno.EIO, errno.EINTR, errno.EIO, errno.EINTR],
        )
        self.assertEqual(len(closed_fds), 4)
        for fd in closed_fds:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_recovery_required_preserves_primary_with_receipt_close_faults(
        self,
    ) -> None:
        self.write_validator("raise SystemExit(0)\n")
        applied = self.run_apply()
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        terminal = Path(receipt["recovery_terminal_path"])
        reservation = terminal.read_bytes()
        terminal.rename(terminal.with_name("recovery.bound"))
        terminal.write_bytes(reservation)
        terminal.chmod(0o600)
        real_receipt_close = TRANSACTION.RecoveryReceiptEvidence.close
        real_os_close = TRANSACTION.os.close

        def close_receipt(evidence: object) -> list[dict[str, object]]:
            assert isinstance(evidence, TRANSACTION.RecoveryReceiptEvidence)

            def fault_close(fd: int) -> None:
                real_os_close(fd)
                raise OSError(errno.EIO, "fault-injected receipt close")

            with mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=fault_close,
            ):
                return real_receipt_close(evidence)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.RecoveryReceiptEvidence,
                "close",
                autospec=True,
                side_effect=close_receipt,
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
        self.assertEqual(payload["reason"], "recovery_terminal_binding_changed")
        self.assertEqual(
            [failure["descriptor"] for failure in payload["cleanup_failures"]],
            ["recovery_receipt", "receipt_parent"],
        )

    def test_ambiguous_q_or_p_preserves_required_with_receipt_close_faults(
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
            self.assertRaises(TRANSACTION.TransactionError),
        ):
            TRANSACTION.apply_transaction(self.apply_namespace())
        prepared = TRANSACTION.prepared_candidate_path(self.receipt)
        replacement = prepared.with_name(f"{prepared.name}.replacement")
        replacement.write_bytes(NEW_RULES)
        replacement.chmod(0o600)
        os.replace(replacement, prepared)
        real_receipt_close = TRANSACTION.RecoveryReceiptEvidence.close
        real_os_close = TRANSACTION.os.close

        def close_receipt(evidence: object) -> list[dict[str, object]]:
            assert isinstance(evidence, TRANSACTION.RecoveryReceiptEvidence)

            def fault_close(fd: int) -> None:
                real_os_close(fd)
                raise OSError(errno.EINTR, "fault-injected receipt close")

            with mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=fault_close,
            ):
                return real_receipt_close(evidence)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
            ),
            mock.patch.object(
                TRANSACTION.RecoveryReceiptEvidence,
                "close",
                autospec=True,
                side_effect=close_receipt,
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
        self.assertEqual(payload["reason"], "schema_v4_state_unrecognized")
        self.assertIn(
            {
                "operation": "possible_prior_transaction_state",
                "phase": "observed",
                "state": "Q_or_P",
            },
            payload["mutation_journal"],
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["receipt"]).resolve(),
            self.receipt.resolve(),
        )
        self.assertEqual(
            Path(payload["recovery_locators"]["prepared_candidate"]).resolve(),
            prepared.resolve(),
        )
        self.assertEqual(
            [failure["descriptor"] for failure in payload["cleanup_failures"]],
            ["recovery_receipt", "receipt_parent"],
        )

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

    def test_rollback_result_preserves_multiple_close_failures(self) -> None:
        stage = TRANSACTION.PrivateStage(self.rules_dir)
        backup = self.rules_dir / "default.rules.bak-close-fault"
        backup.write_bytes(OLD_RULES)
        backup.chmod(0o640)
        self.rules.write_bytes(NEW_RULES)
        self.rules.chmod(0o640)
        _backup_payload, original = TRANSACTION.read_stable(
            backup,
            label="backup",
        )
        _live_payload, installed = TRANSACTION.read_stable(
            self.rules,
            label="live_rules",
        )
        mismatched_installed = TRANSACTION.Snapshot(
            device=installed.device,
            inode=installed.inode,
            size=installed.size,
            sha256="0" * 64,
            mode=installed.mode,
            uid=installed.uid,
            gid=installed.gid,
            nlink=installed.nlink,
        )
        real_close = TRANSACTION.os.close
        closed_fds: list[int] = []
        close_count = 0

        def close_with_two_faults(fd: int) -> None:
            nonlocal close_count
            real_close(fd)
            closed_fds.append(fd)
            close_count += 1
            if close_count == 1:
                raise OSError(errno.EIO, "fault-injected rollback live close")
            if close_count == 2:
                raise OSError(errno.EINTR, "fault-injected rollback backup close")

        try:
            with mock.patch.object(
                TRANSACTION.os,
                "close",
                side_effect=close_with_two_faults,
            ):
                rolled_back, payload = TRANSACTION.rollback(
                    stage=stage,
                    rules=self.rules,
                    lock_binding=object(),
                    backup=backup,
                    original=original,
                    installed=mismatched_installed,
                    backup_expected=original,
                )
        finally:
            stage.cleanup(retain=False)

        self.assertFalse(rolled_back)
        self.assertEqual(
            payload["rollback_status"],
            "live_no_longer_installed",
        )
        failures = payload["cleanup_failures"]
        self.assertEqual(
            [failure["descriptor"] for failure in failures],
            ["rollback_live_rules", "rollback_backup"],
        )
        self.assertEqual(
            [failure["errno_name"] for failure in failures],
            ["EIO", "EINTR"],
        )
        self.assertEqual(len(closed_fds), 2)
        for fd in closed_fds:
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
