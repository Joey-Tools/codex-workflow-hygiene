from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    REPO_ROOT
    / "skills/bounded-command-output/scripts/run_process_group_deadline.py"
)
POSIX = os.name == "posix"
SAME_SESSION_PROCESS_GROUPS = POSIX and sys.version_info >= (3, 11)


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


@unittest.skipUnless(
    SAME_SESSION_PROCESS_GROUPS,
    "requires POSIX and Python 3.11+",
)
class ProcessGroupDeadlineTests(unittest.TestCase):
    def test_preserves_normal_exit_status(self) -> None:
        for exit_code in (0, 42):
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
                "0.3",
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
            self.assertGreaterEqual(elapsed, 0.45)
            self.assertLess(elapsed, 2.0)
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

    def test_signal_during_spawn_is_forwarded_after_process_handoff(self) -> None:
        supervisor = load_supervisor_module()
        original_popen = subprocess.Popen
        started: list[subprocess.Popen[bytes]] = []
        diagnostics: list[str] = []

        def spawn_then_cancel(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            process = original_popen(*args, **kwargs)
            started.append(process)
            handler = signal.getsignal(signal.SIGTERM)
            if not callable(handler):
                process.kill()
                process.wait(timeout=2)
                raise AssertionError("SIGTERM handler was not installed before Popen")
            handler(signal.SIGTERM, None)
            return process

        permission_error = PermissionError(1, "simulated process-group handoff")
        with (
            mock.patch.object(supervisor.subprocess, "Popen", spawn_then_cancel),
            mock.patch.object(
                supervisor.os,
                "killpg",
                side_effect=permission_error,
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
        self.assertEqual(
            diagnostics,
            ["forwarded signal; process-group cleanup unverified"],
        )

    def test_second_signal_during_timeout_transition_cannot_escape_cleanup(
        self,
    ) -> None:
        supervisor = load_supervisor_module()
        original_popen = subprocess.Popen
        original_ignore = supervisor.ignore_managed_signals
        started: list[subprocess.Popen[bytes]] = []
        ignore_calls = 0

        def record_spawn(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            process = original_popen(*args, **kwargs)
            started.append(process)
            return process

        def cleanup_started() -> None:
            for process in started:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)

        self.addCleanup(cleanup_started)

        def interrupt_then_ignore() -> None:
            nonlocal ignore_calls
            ignore_calls += 1
            handler = signal.getsignal(signal.SIGTERM)
            if not callable(handler):
                raise AssertionError("managed signal handler is not callable")
            signum = signal.SIGTERM if ignore_calls == 1 else signal.SIGINT
            handler(signum, None)
            original_ignore()

        with (
            mock.patch.object(supervisor.subprocess, "Popen", record_spawn),
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

        self.assertEqual(returncode, 143)
        self.assertEqual(ignore_calls, 2)
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
        original_sigmask = supervisor.signal.pthread_sigmask
        mask_calls = 0

        def signal_then_mask(how: int, mask: object) -> object:
            nonlocal mask_calls
            mask_calls += 1
            if mask_calls == 1:
                handler = signal.getsignal(signal.SIGTERM)
                if not callable(handler):
                    raise AssertionError("managed signal handler is not callable")
                handler(signal.SIGTERM, None)
            return original_sigmask(how, mask)

        with mock.patch.object(
            supervisor.signal,
            "pthread_sigmask",
            side_effect=signal_then_mask,
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
        self.assertEqual(mask_calls, 1)

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
