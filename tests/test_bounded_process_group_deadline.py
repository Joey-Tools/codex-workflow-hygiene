from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    REPO_ROOT
    / "skills/bounded-command-output/scripts/run_process_group_deadline.py"
)
POSIX = os.name == "posix"
SAME_SESSION_PROCESS_GROUPS = POSIX


def run_supervisor(
    *arguments: str,
    timeout: float = 8.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def wait_for_file(path: Path, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def load_supervisor_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "bounded_process_group_deadline_under_test",
        SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PlatformRejectionTests(unittest.TestCase):
    def test_non_posix_rejection_precedes_signal_teardown(self) -> None:
        supervisor = load_supervisor_module()
        diagnostics: list[str] = []

        with (
            mock.patch.object(supervisor.os, "name", "nt"),
            mock.patch.object(
                supervisor.signal,
                "pthread_sigmask",
                side_effect=AssertionError("signal teardown should not run"),
                create=True,
            ),
            mock.patch.object(
                supervisor,
                "print_error",
                side_effect=diagnostics.append,
            ),
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "1",
                    "--",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(returncode, 125)
        self.assertEqual(diagnostics, ["POSIX process groups are required"])


@unittest.skipUnless(POSIX, "requires POSIX")
class PosixNewSessionDeadlineTests(unittest.TestCase):
    def test_new_session_mode_is_explicit(self) -> None:
        probe = (
            "import json, os; "
            "print(json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp(), "
            "'sid': os.getsid(0)}))"
        )
        result = run_supervisor(
            "--timeout-seconds",
            "2",
            "--new-session",
            "--",
            sys.executable,
            "-c",
            probe,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = json.loads(result.stdout)
        self.assertEqual(identity["pgid"], identity["pid"])
        self.assertEqual(identity["sid"], identity["pid"])
        self.assertNotEqual(identity["sid"], os.getsid(0))

    def test_cli_and_spawn_failures_are_distinct(self) -> None:
        invalid_durations = (
            ("--timeout-seconds", "inf"),
            ("--timeout-seconds", "1e308"),
            (
                "--timeout-seconds",
                "1",
                "--grace-seconds",
                "1e308",
            ),
        )
        for duration_args in invalid_durations:
            with self.subTest(duration_args=duration_args):
                invalid = run_supervisor(
                    *duration_args,
                    "--new-session",
                    "--",
                    sys.executable,
                    "-c",
                    "pass",
                )
                self.assertEqual(invalid.returncode, 2)

        missing = run_supervisor(
            "--timeout-seconds",
            "1",
            "--new-session",
            "--",
            "/definitely/missing/bounded-command",
        )
        self.assertEqual(missing.returncode, 127)

        with tempfile.TemporaryDirectory() as temp_dir:
            nonexecutable = Path(temp_dir) / "not-executable"
            nonexecutable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            nonexecutable.chmod(0o600)
            denied = run_supervisor(
                "--timeout-seconds",
                "1",
                "--new-session",
                "--",
                str(nonexecutable),
            )
            self.assertEqual(denied.returncode, 126)

            invalid_format = Path(temp_dir) / "invalid-format"
            invalid_format.write_text("not an executable format\n", encoding="utf-8")
            invalid_format.chmod(0o700)
            malformed = run_supervisor(
                "--timeout-seconds",
                "1",
                "--new-session",
                "--",
                str(invalid_format),
            )
            self.assertEqual(malformed.returncode, 126)

            directory = run_supervisor(
                "--timeout-seconds",
                "1",
                "--new-session",
                "--",
                temp_dir,
            )
            self.assertEqual(directory.returncode, 126)

            path_component = Path(temp_dir) / "not-a-directory"
            path_component.write_text("file", encoding="utf-8")
            not_a_directory = run_supervisor(
                "--timeout-seconds",
                "1",
                "--new-session",
                "--",
                str(path_component / "command"),
            )
            self.assertEqual(not_a_directory.returncode, 127)

    def test_missing_posix_signal_masking_is_rejected_before_fork(self) -> None:
        supervisor = load_supervisor_module()
        diagnostics: list[str] = []

        with (
            mock.patch.object(supervisor.signal, "pthread_sigmask", None),
            mock.patch.object(
                supervisor,
                "print_error",
                side_effect=diagnostics.append,
            ),
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "1",
                    "--new-session",
                    "--",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(returncode, 125)
        self.assertEqual(
            diagnostics,
            ["POSIX signal masking is required for safe process startup"],
        )


@unittest.skipUnless(
    SAME_SESSION_PROCESS_GROUPS,
    "requires POSIX",
)
class ProcessGroupDeadlineTests(unittest.TestCase):
    def test_preserves_normal_exit_status(self) -> None:
        for exit_code in (0, 42, 124, 125, 126, 127, 255):
            with self.subTest(exit_code=exit_code):
                result = run_supervisor(
                    "--timeout-seconds",
                    "2",
                    "--",
                    sys.executable,
                    "-c",
                    f"raise SystemExit({exit_code})",
                )
                self.assertEqual(result.returncode, exit_code, result.stderr)

    def test_normalizes_child_signal_status(self) -> None:
        for signum in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signum=signum):
                result = run_supervisor(
                    "--timeout-seconds",
                    "2",
                    "--",
                    sys.executable,
                    "-c",
                    "import os, signal; os.kill(os.getpid(), int(__import__('sys').argv[1]))",
                    str(signum),
                )
                self.assertEqual(result.returncode, 128 + signum, result.stderr)

    def test_preserves_standard_output_and_error_once(self) -> None:
        result = run_supervisor(
            "--timeout-seconds",
            "2",
            "--",
            sys.executable,
            "-c",
            "import os; os.write(1, b'out\\n'); os.write(2, b'err\\n')",
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "out\n")
        self.assertEqual(result.stderr, "err\n")

    def test_same_session_mode_creates_a_new_process_group(self) -> None:
        probe = (
            "import json, os; "
            "print(json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp(), "
            "'sid': os.getsid(0), 'euid': os.geteuid()}))"
        )
        result = run_supervisor(
            "--timeout-seconds",
            "2",
            "--",
            sys.executable,
            "-c",
            probe,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = json.loads(result.stdout)
        self.assertEqual(identity["pgid"], identity["pid"])
        self.assertEqual(identity["sid"], os.getsid(0))
        self.assertEqual(identity["euid"], os.geteuid())

    def test_spawn_refuses_fork_after_fd_enumeration_exhausts_deadline(
        self,
    ) -> None:
        supervisor = load_supervisor_module()
        expired = False

        def monotonic() -> float:
            return 10.0 if expired else 9.0

        def exhaust_deadline() -> list[int]:
            nonlocal expired
            expired = True
            return []

        with (
            mock.patch.object(
                supervisor.signal,
                "pthread_sigmask",
                return_value=set(),
            ) as pthread_sigmask,
            mock.patch.object(
                supervisor.os,
                "pipe",
                side_effect=((101, 102), (103, 104)),
            ),
            mock.patch.object(supervisor.os, "set_inheritable"),
            mock.patch.object(supervisor.os, "set_blocking"),
            mock.patch.object(
                supervisor,
                "inherited_file_descriptors",
                side_effect=exhaust_deadline,
            ),
            mock.patch.object(supervisor.time, "monotonic", side_effect=monotonic),
            mock.patch.object(supervisor, "close_fd") as close_fd,
            mock.patch.object(supervisor.os, "fork") as fork,
        ):
            with self.assertRaises(supervisor.ChildWaitTimeout):
                supervisor.spawn_process(
                    ["/usr/bin/true"],
                    new_session=False,
                    inherited_sigchld_handler=signal.SIG_DFL,
                    deadline=10.0,
                )

        fork.assert_not_called()
        self.assertEqual(
            [call.args[0] for call in close_fd.call_args_list],
            [101, 102, 103, 104],
        )
        self.assertEqual(pthread_sigmask.call_count, 2)

    def test_deadline_before_child_creation_is_a_timeout(self) -> None:
        supervisor = load_supervisor_module()
        diagnostics: list[str] = []

        with (
            mock.patch.object(
                supervisor,
                "spawn_process",
                side_effect=supervisor.ChildWaitTimeout,
            ),
            mock.patch.object(
                supervisor,
                "print_error",
                side_effect=diagnostics.append,
            ),
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "1",
                    "--",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(returncode, 124)
        self.assertEqual(
            diagnostics,
            ["deadline exceeded before child creation; result incomplete"],
        )

    def test_deadline_stops_child_blocked_before_group_handoff(self) -> None:
        supervisor = load_supervisor_module()

        def block_group_setup(*_args: object) -> None:
            time.sleep(30)

        with tempfile.TemporaryDirectory() as temp_dir:
            executed = Path(temp_dir) / "executed"
            started = time.monotonic()
            with (
                mock.patch.object(
                    supervisor.os,
                    "setpgid",
                    side_effect=block_group_setup,
                ),
                mock.patch.object(
                    supervisor.os,
                    "killpg",
                    side_effect=AssertionError(
                        "pre-handoff cleanup must signal only the direct child"
                    ),
                ),
            ):
                returncode = supervisor.main(
                    [
                        "--timeout-seconds",
                        "0.15",
                        "--grace-seconds",
                        "0",
                        "--",
                        sys.executable,
                        "-c",
                        "from pathlib import Path; Path(__import__('sys').argv[1]).touch()",
                        str(executed),
                    ]
                )
            elapsed = time.monotonic() - started
            executed_during_run = executed.exists()

        self.assertEqual(returncode, 124)
        self.assertLess(elapsed, 2.0)
        self.assertFalse(executed_during_run)

    def test_deadline_stops_child_blocked_in_exec_handoff(self) -> None:
        supervisor = load_supervisor_module()
        original_killpg = supervisor.os.killpg
        group_signals: list[int] = []

        def block_exec(*_args: object) -> None:
            time.sleep(30)

        def record_group_signal(process_group_id: int, signum: int) -> None:
            group_signals.append(signum)
            original_killpg(process_group_id, signum)

        with (
            mock.patch.object(supervisor.os, "execvp", side_effect=block_exec),
            mock.patch.object(
                supervisor.os,
                "killpg",
                side_effect=record_group_signal,
            ),
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "0.15",
                    "--grace-seconds",
                    "0.05",
                    "--",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(returncode, 124)
        self.assertIn(signal.SIGTERM, group_signals)

    def test_group_setup_consumes_the_original_deadline_budget(self) -> None:
        supervisor = load_supervisor_module()
        original_setpgid = supervisor.os.setpgid
        original_wait_until = supervisor.ChildProcess.wait_until
        observed_remaining: list[float] = []

        def delayed_setpgid(pid: int, process_group_id: int) -> None:
            time.sleep(0.25)
            original_setpgid(pid, process_group_id)

        def record_deadline(process: object, deadline: float) -> int:
            observed_remaining.append(deadline - time.monotonic())
            return original_wait_until(process, deadline)

        with (
            mock.patch.object(
                supervisor.os,
                "setpgid",
                side_effect=delayed_setpgid,
            ),
            mock.patch.object(
                supervisor.ChildProcess,
                "wait_until",
                side_effect=record_deadline,
                autospec=True,
            ),
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "1",
                    "--",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(len(observed_remaining), 1)
        self.assertGreater(observed_remaining[0], 0)
        self.assertLess(observed_remaining[0], 0.85)

    def test_fork_delay_is_charged_when_fork_returns(self) -> None:
        supervisor = load_supervisor_module()
        original_fork = supervisor.os.fork

        def delayed_fork() -> int:
            time.sleep(0.2)
            return original_fork()

        started = time.monotonic()
        with mock.patch.object(
            supervisor.os,
            "fork",
            side_effect=delayed_fork,
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "0.1",
                    "--grace-seconds",
                    "0",
                    "--",
                    "/usr/bin/true",
                ]
            )
        elapsed = time.monotonic() - started

        self.assertEqual(returncode, 124)
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 2.0)

    def test_reaped_leader_prevents_late_process_group_signal(self) -> None:
        supervisor = load_supervisor_module()
        process = supervisor.ChildProcess(999_999)
        process.returncode = 0

        with (
            mock.patch.object(supervisor.os, "killpg") as killpg,
            mock.patch.object(supervisor.os, "kill") as kill_process,
        ):
            cleanup_unverified = supervisor.stop_process_group(
                process,
                process_group_id=process.pid,
                initial_signal=signal.SIGTERM,
                grace_seconds=0,
                group_handoff_complete=True,
            )

        self.assertTrue(cleanup_unverified)
        killpg.assert_not_called()
        kill_process.assert_not_called()

    def test_deadline_wins_before_a_new_exit_observation(self) -> None:
        supervisor = load_supervisor_module()
        process = supervisor.ChildProcess(999_997)

        with (
            mock.patch.object(supervisor.time, "monotonic", return_value=10.0),
            mock.patch.object(process, "poll") as poll,
        ):
            with self.assertRaises(supervisor.ChildWaitTimeout):
                process.wait_until(10.0)

        poll.assert_not_called()

    def test_exit_observation_started_before_deadline_wins(self) -> None:
        supervisor = load_supervisor_module()
        process = supervisor.ChildProcess(999_996)

        with (
            mock.patch.object(supervisor.time, "monotonic", return_value=9.9),
            mock.patch.object(process, "poll", return_value=0) as poll,
        ):
            self.assertEqual(process.wait_until(10.0), 0)

        poll.assert_called_once_with()

    def test_waitpid_status_is_cached_before_signals_are_unmasked(self) -> None:
        supervisor = load_supervisor_module()
        process = supervisor.ChildProcess(999_995)
        mask_calls = 0

        def mask_then_interrupt(how: int, _signals: object) -> set[object]:
            nonlocal mask_calls
            mask_calls += 1
            if how == signal.SIG_SETMASK:
                self.assertEqual(process.returncode, 0)
                raise supervisor.ForwardedSignal(signal.SIGTERM)
            return set()

        with (
            mock.patch.object(
                supervisor.os,
                "waitpid",
                return_value=(process.pid, 0),
            ),
            mock.patch.object(
                supervisor.signal,
                "pthread_sigmask",
                side_effect=mask_then_interrupt,
            ),
        ):
            with self.assertRaises(supervisor.ForwardedSignal):
                process.poll()

        self.assertEqual(mask_calls, 2)
        self.assertEqual(process.returncode, 0)

    def test_final_group_kill_also_targets_a_pinned_escaped_leader(self) -> None:
        supervisor = load_supervisor_module()
        process = supervisor.ChildProcess(999_998)

        with (
            mock.patch.object(
                supervisor,
                "signal_process_group",
                return_value=supervisor.GroupSignalOutcome.SENT,
            ),
            mock.patch.object(process, "send_signal") as send_signal,
            mock.patch.object(process, "wait", return_value=-signal.SIGKILL),
        ):
            cleanup_unverified = supervisor.stop_process_group(
                process,
                process_group_id=process.pid,
                initial_signal=signal.SIGTERM,
                grace_seconds=0,
                group_handoff_complete=True,
            )

        self.assertFalse(cleanup_unverified)
        send_signal.assert_called_once_with(signal.SIGKILL)

    def test_timeout_signals_group_then_waits_full_grace(self) -> None:
        grandchild = """
import signal
import sys
import time
from pathlib import Path

marker = Path(sys.argv[1])
ready = Path(sys.argv[2])

def record_term(_signum, _frame):
    marker.write_text("term", encoding="utf-8")

signal.signal(signal.SIGTERM, record_term)
ready.write_text("ready", encoding="utf-8")
time.sleep(30)
"""
        leader = """
import signal
import subprocess
import sys
import time
from pathlib import Path

marker = Path(sys.argv[1])
ready = Path(sys.argv[2])
source = sys.argv[3]
subprocess.Popen([sys.executable, "-c", source, str(marker), str(ready)])
deadline = time.monotonic() + 2
while not ready.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "term-marker"
            ready = Path(temp_dir) / "ready"
            started = time.monotonic()
            result = run_supervisor(
                "--timeout-seconds",
                "1.5",
                "--grace-seconds",
                "0.2",
                "--",
                sys.executable,
                "-c",
                leader,
                str(marker),
                str(ready),
                grandchild,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "term")
            self.assertGreaterEqual(elapsed, 1.65)
            self.assertLess(elapsed, 4.0)
            self.assertIn("result incomplete", result.stderr)

    def test_cooperative_single_process_timeout_is_still_a_timeout(self) -> None:
        started = time.monotonic()
        result = run_supervisor(
            "--timeout-seconds",
            "0.2",
            "--grace-seconds",
            "0.1",
            "--",
            "/bin/sleep",
            "30",
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertGreaterEqual(elapsed, 0.25)
        self.assertLess(elapsed, 2.0)
        self.assertIn("result incomplete", result.stderr)

    def test_external_sigterm_is_forwarded_to_the_group(self) -> None:
        child = """
import signal
import sys
import time
from pathlib import Path

marker = Path(sys.argv[1])
ready = Path(sys.argv[2])

def record_term(_signum, _frame):
    marker.write_text("term", encoding="utf-8")

signal.signal(signal.SIGTERM, record_term)
ready.write_text("ready", encoding="utf-8")
time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "term-marker"
            ready = Path(temp_dir) / "ready"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--timeout-seconds",
                    "10",
                    "--grace-seconds",
                    "0.1",
                    "--",
                    sys.executable,
                    "-c",
                    child,
                    str(marker),
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(process.kill)
            wait_for_file(ready)
            process.send_signal(signal.SIGTERM)
            _stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 143, stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "term")

    def test_sigchld_ignore_is_neutralized_for_wait_and_restored(self) -> None:
        supervisor = load_supervisor_module()
        previous_handler = signal.getsignal(signal.SIGCHLD)
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "2",
                    "--",
                    "/usr/bin/true",
                ]
            )
            restored_handler = signal.getsignal(signal.SIGCHLD)
        finally:
            signal.signal(signal.SIGCHLD, previous_handler)

        self.assertEqual(returncode, 0)
        self.assertEqual(restored_handler, signal.SIG_IGN)

    def test_multithreaded_embedding_is_rejected_before_fork(self) -> None:
        supervisor = load_supervisor_module()
        release = threading.Event()
        worker = threading.Thread(target=release.wait)
        worker.start()
        diagnostics: list[str] = []
        try:
            with mock.patch.object(
                supervisor,
                "print_error",
                side_effect=diagnostics.append,
            ):
                returncode = supervisor.main(
                    [
                        "--timeout-seconds",
                        "2",
                        "--",
                        "/usr/bin/true",
                    ]
                )
        finally:
            release.set()
            worker.join(timeout=2)

        self.assertEqual(returncode, 125)
        self.assertEqual(diagnostics, ["run as a standalone single-threaded CLI"])

    def test_exec_target_gets_default_sigpipe_behavior(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "--timeout-seconds",
                "2",
                "--",
                "/usr/bin/yes",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(process.kill)
        if process.stdout is None or process.stderr is None:
            self.fail("expected captured process streams")
        process.stdout.close()
        returncode = process.wait(timeout=3)
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        process.stderr.close()

        self.assertEqual(returncode, 128 + signal.SIGPIPE, stderr)

    def test_exec_target_does_not_inherit_extra_file_descriptors(self) -> None:
        probe = """
import errno
import os
import sys

try:
    os.fstat(int(sys.argv[1]))
except OSError as exc:
    raise SystemExit(0 if exc.errno == errno.EBADF else 2)
raise SystemExit(9)
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            inherited_fd = os.open(
                str(Path(temp_dir) / "inherited"),
                os.O_CREAT | os.O_RDWR,
                0o600,
            )
            try:
                os.set_inheritable(inherited_fd, True)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "--timeout-seconds",
                        "2",
                        "--",
                        sys.executable,
                        "-c",
                        probe,
                        str(inherited_fd),
                    ],
                    pass_fds=(inherited_fd,),
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            finally:
                os.close(inherited_fd)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signal_during_masked_spawn_is_forwarded_after_pid_handoff(self) -> None:
        supervisor = load_supervisor_module()
        original_spawn = supervisor.spawn_process
        started: list[object] = []
        diagnostics: list[str] = []

        def spawn_then_cancel(
            *args: object,
            **kwargs: object,
        ) -> tuple[object, int, int, object]:
            spawned = original_spawn(*args, **kwargs)
            started.append(spawned[0])
            handler = signal.getsignal(signal.SIGTERM)
            if not callable(handler):
                raise AssertionError("SIGTERM handler was not installed before fork")
            handler(signal.SIGTERM, None)
            return spawned

        with (
            mock.patch.object(supervisor, "spawn_process", spawn_then_cancel),
            mock.patch.object(
                supervisor,
                "print_error",
                side_effect=diagnostics.append,
            ),
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "10",
                    "--grace-seconds",
                    "0",
                    "--",
                    "/bin/sleep",
                    "30",
                ]
            )

        self.assertEqual(returncode, 143)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())
        self.assertEqual(diagnostics, [])

    def test_second_signal_during_timeout_transition_cannot_escape_cleanup(
        self,
    ) -> None:
        supervisor = load_supervisor_module()
        original_spawn = supervisor.spawn_process
        original_ignore = supervisor.ignore_managed_signals
        started: list[object] = []
        ignore_calls = 0

        def record_spawn(
            *args: object,
            **kwargs: object,
        ) -> tuple[object, int, int, object]:
            spawned = original_spawn(*args, **kwargs)
            started.append(spawned[0])
            return spawned

        def cleanup_started() -> None:
            for process in started:
                if process.poll() is None:
                    process.send_signal(signal.SIGKILL)
                    process.wait(timeout=2)

        self.addCleanup(cleanup_started)

        def interrupt_then_ignore() -> None:
            nonlocal ignore_calls
            ignore_calls += 1
            handler = signal.getsignal(signal.SIGTERM)
            if not callable(handler):
                raise AssertionError("managed signal handler is not callable")
            handler(signal.SIGTERM, None)
            handler(signal.SIGINT, None)
            original_ignore()

        with (
            mock.patch.object(supervisor, "spawn_process", record_spawn),
            mock.patch.object(
                supervisor,
                "ignore_managed_signals",
                side_effect=interrupt_then_ignore,
            ),
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "0.05",
                    "--grace-seconds",
                    "0",
                    "--",
                    "/bin/sleep",
                    "30",
                ]
            )

        self.assertEqual(returncode, 124)
        self.assertEqual(ignore_calls, 1)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())

    def test_signal_interrupting_timeout_gate_close_still_cleans_child(
        self,
    ) -> None:
        supervisor = load_supervisor_module()
        original_spawn = supervisor.spawn_process
        original_close = supervisor.SignalGate.close
        original_stop = supervisor.stop_process_group
        started: list[object] = []
        close_calls = 0

        def record_spawn(
            *args: object,
            **kwargs: object,
        ) -> tuple[object, int, int, object]:
            spawned = original_spawn(*args, **kwargs)
            started.append(spawned[0])
            return spawned

        def cleanup_started() -> None:
            for process in started:
                if process.poll() is None:
                    process.send_signal(signal.SIGKILL)
                    process.wait(timeout=2)

        self.addCleanup(cleanup_started)

        def interrupt_first_close(gate: object) -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls == 1:
                handler = signal.getsignal(signal.SIGTERM)
                if not callable(handler):
                    raise AssertionError("managed signal handler is not callable")
                handler(signal.SIGTERM, None)
            original_close(gate)

        def assert_sigchld_then_stop(*args: object, **kwargs: object) -> bool:
            self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
            return original_stop(*args, **kwargs)

        previous_sigchld = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            with (
                mock.patch.object(supervisor, "spawn_process", record_spawn),
                mock.patch.object(
                    supervisor.SignalGate,
                    "close",
                    autospec=True,
                    side_effect=interrupt_first_close,
                ),
                mock.patch.object(
                    supervisor,
                    "stop_process_group",
                    side_effect=assert_sigchld_then_stop,
                ),
            ):
                returncode = supervisor.main(
                    [
                        "--timeout-seconds",
                        "0.05",
                        "--grace-seconds",
                        "0",
                        "--",
                        "/bin/sleep",
                        "30",
                    ]
                )
            self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGCHLD, previous_sigchld)

        self.assertEqual(returncode, 143)
        self.assertGreaterEqual(close_calls, 3)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())

    def test_signal_during_handler_restore_cannot_escape_as_traceback(
        self,
    ) -> None:
        supervisor = load_supervisor_module()
        original_restore = supervisor.restore_signal_handlers
        restore_calls = 0

        def signal_then_restore(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            handler = signal.getsignal(signal.SIGTERM)
            if not callable(handler):
                raise AssertionError("managed signal handler is not callable")
            handler(signal.SIGTERM, None)
            original_restore(previous)

        with mock.patch.object(
            supervisor,
            "restore_signal_handlers",
            side_effect=signal_then_restore,
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "2",
                    "--",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(restore_calls, 1)

    def test_signal_before_teardown_mask_is_caught_by_outer_boundary(
        self,
    ) -> None:
        supervisor = load_supervisor_module()
        original_close = supervisor.close_gate_and_restore_signal_handlers
        close_calls = 0

        def signal_then_close(gate: object, previous: object) -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls == 1:
                handler = signal.getsignal(signal.SIGTERM)
                if not callable(handler):
                    raise AssertionError("managed signal handler is not callable")
                handler(signal.SIGTERM, None)
            original_close(gate, previous)

        with mock.patch.object(
            supervisor,
            "close_gate_and_restore_signal_handlers",
            side_effect=signal_then_close,
        ):
            returncode = supervisor.main(
                [
                    "--timeout-seconds",
                    "2",
                    "--",
                    "/usr/bin/true",
                ]
            )

        self.assertEqual(returncode, 143)
        self.assertEqual(close_calls, 2)

    def test_setsid_descendant_is_not_chased(self) -> None:
        escaped = """
import os
import sys
import time
from pathlib import Path

ready = Path(sys.argv[1])
survived = Path(sys.argv[2])
os.setsid()
ready.write_text(str(os.getpid()), encoding="utf-8")
time.sleep(2.0)
survived.write_text("survived", encoding="utf-8")
"""
        leader = """
import subprocess
import sys
import time
from pathlib import Path

ready = Path(sys.argv[1])
survived = Path(sys.argv[2])
source = sys.argv[3]
subprocess.Popen([sys.executable, "-c", source, str(ready), str(survived)])
deadline = time.monotonic() + 2
while not ready.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            ready = Path(temp_dir) / "escaped-ready"
            survived = Path(temp_dir) / "escaped-survived"
            result = run_supervisor(
                "--timeout-seconds",
                "1.0",
                "--grace-seconds",
                "0.1",
                "--",
                sys.executable,
                "-c",
                leader,
                str(ready),
                str(survived),
                escaped,
            )
            self.assertEqual(result.returncode, 124, result.stderr)
            wait_for_file(survived, timeout=3)
            self.assertEqual(survived.read_text(encoding="utf-8"), "survived")

    def test_normal_leader_exit_does_not_clean_up_background_child(self) -> None:
        background = """
import sys
import time
from pathlib import Path

marker = Path(sys.argv[1])
ready = Path(sys.argv[2])
release = Path(sys.argv[3])
ready.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 5
while not release.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if release.exists():
    marker.write_text("finished", encoding="utf-8")
"""
        leader = """
import subprocess
import sys

subprocess.Popen(
    [
        sys.executable,
        "-c",
        sys.argv[4],
        sys.argv[1],
        sys.argv[2],
        sys.argv[3],
    ],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "background-finished"
            ready = Path(temp_dir) / "background-ready"
            release = Path(temp_dir) / "background-release"
            try:
                result = run_supervisor(
                    "--timeout-seconds",
                    "2",
                    "--",
                    sys.executable,
                    "-c",
                    leader,
                    str(marker),
                    str(ready),
                    str(release),
                    background,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                wait_for_file(ready)
                self.assertFalse(marker.exists())
            finally:
                release.write_text("release", encoding="utf-8")
            wait_for_file(marker, timeout=2)
            self.assertEqual(marker.read_text(encoding="utf-8"), "finished")
