#!/usr/bin/env python3

from __future__ import annotations

import argparse
import enum
import errno
import math
import os
import signal
import sys
import threading
import time


TIMEOUT_EXIT = 124
SUPERVISOR_ERROR_EXIT = 125
CANNOT_EXECUTE_EXIT = 126
COMMAND_NOT_FOUND_EXIT = 127
KILL_REAP_TIMEOUT_SECONDS = 5.0
MAX_DURATION_SECONDS = 365 * 24 * 60 * 60
WAIT_POLL_INITIAL_SECONDS = 0.0005
WAIT_POLL_MAX_SECONDS = 0.04
GROUP_READY_MARKER = b"G"
MANAGED_SIGNALS = tuple(
    getattr(signal, name)
    for name in ("SIGINT", "SIGTERM", "SIGHUP")
    if hasattr(signal, name)
)
CHILD_DEFAULT_SIGNALS = tuple(
    dict.fromkeys(
        MANAGED_SIGNALS
        + tuple(
            getattr(signal, name)
            for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ")
            if hasattr(signal, name)
        )
    )
)


class ForwardedSignal(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


class SupervisorError(Exception):
    pass


class ChildWaitTimeout(Exception):
    pass


def require_time_remaining(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ChildWaitTimeout


class ChildProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            MANAGED_SIGNALS,
        )
        try:
            while True:
                try:
                    waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
                    break
                except InterruptedError:
                    continue
                except ChildProcessError as exc:
                    raise SupervisorError(
                        f"cannot reap direct child {self.pid}: {exc}"
                    ) from exc
            if waited_pid == 0:
                return None
            self.returncode = os.waitstatus_to_exitcode(status)
            return self.returncode
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        return self.wait_until(deadline)

    def wait_until(self, deadline: float | None) -> int:
        sleep_seconds = WAIT_POLL_INITIAL_SECONDS
        while True:
            if self.returncode is not None:
                return self.returncode
            if deadline is not None and time.monotonic() >= deadline:
                raise ChildWaitTimeout
            returncode = self.poll()
            if returncode is not None:
                return returncode
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ChildWaitTimeout
                sleep_seconds = min(sleep_seconds, remaining)
            time.sleep(sleep_seconds)
            sleep_seconds = min(sleep_seconds * 2, WAIT_POLL_MAX_SECONDS)

    def send_signal(self, signum: int) -> None:
        os.kill(self.pid, signum)


class GroupSignalOutcome(enum.Enum):
    SENT = "sent"
    DIRECT_CHILD_ONLY = "direct-child-only"
    MISSING = "missing"
    LEADER_EXITED_PERMISSION = "leader-exited-permission"


class SignalGate:
    def __init__(self) -> None:
        self._armed = False
        self._interrupt_raised = False
        self._pending: int | None = None

    def handle(self, signum: int, _frame: object) -> None:
        if self._pending is None:
            self._pending = signum
        self._raise_pending_once()

    def _raise_pending_once(self) -> None:
        if (
            self._armed
            and not self._interrupt_raised
            and self._pending is not None
        ):
            self._interrupt_raised = True
            raise ForwardedSignal(self._pending)

    def arm(self) -> None:
        self._armed = True
        self._raise_pending_once()

    def close(self) -> None:
        self._armed = False


def finite_positive(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if (
        not math.isfinite(parsed)
        or parsed <= 0
        or parsed > MAX_DURATION_SECONDS
    ):
        raise argparse.ArgumentTypeError(
            f"must be greater than zero and at most {MAX_DURATION_SECONDS}"
        )
    return parsed


def finite_nonnegative(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if (
        not math.isfinite(parsed)
        or parsed < 0
        or parsed > MAX_DURATION_SECONDS
    ):
        raise argparse.ArgumentTypeError(
            f"must be nonnegative and at most {MAX_DURATION_SECONDS}"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one non-interactive POSIX command in a lightweight process "
            "group with a task-selected deadline."
        )
    )
    parser.add_argument(
        "--timeout-seconds",
        required=True,
        type=finite_positive,
        help="Task-selected wall-clock deadline in seconds.",
    )
    parser.add_argument(
        "--grace-seconds",
        default=1.0,
        type=finite_nonnegative,
        help="TERM-to-KILL grace period in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--new-session",
        action="store_true",
        help=(
            "Use setsid instead of a same-session process group. This removes "
            "the child's controlling terminal and works on Python 3.10."
        ),
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command argv after --; no implicit shell is used.",
    )
    return parser


def normalized_exit_code(returncode: int) -> int:
    if returncode >= 0:
        return returncode
    return min(255, 128 + (-returncode))


def signal_process_group(
    process_group_id: int,
    signum: int,
    *,
    leader: ChildProcess,
) -> GroupSignalOutcome:
    try:
        os.killpg(process_group_id, signum)
    except ProcessLookupError:
        if leader.poll() is not None:
            return GroupSignalOutcome.MISSING
        try:
            leader.send_signal(signum)
        except ProcessLookupError:
            return GroupSignalOutcome.MISSING
        except OSError as leader_exc:
            raise SupervisorError(
                f"cannot signal missing process group {process_group_id} or its "
                f"leader: {leader_exc}"
            ) from leader_exc
        return GroupSignalOutcome.DIRECT_CHILD_ONLY
    except PermissionError:
        if leader.poll() is not None:
            return GroupSignalOutcome.LEADER_EXITED_PERMISSION
        try:
            leader.send_signal(signum)
        except ProcessLookupError:
            return GroupSignalOutcome.LEADER_EXITED_PERMISSION
        except OSError as leader_exc:
            raise SupervisorError(
                f"cannot signal process group {process_group_id} or its leader: "
                f"{leader_exc}"
            ) from leader_exc
        return GroupSignalOutcome.DIRECT_CHILD_ONLY
    except OSError as exc:
        raise SupervisorError(
            f"cannot signal process group {process_group_id}: {exc}"
        ) from exc
    return GroupSignalOutcome.SENT


def signal_direct_child(
    process: ChildProcess,
    signum: int,
) -> GroupSignalOutcome:
    if process.poll() is not None:
        return GroupSignalOutcome.MISSING
    try:
        process.send_signal(signum)
    except ProcessLookupError:
        return GroupSignalOutcome.MISSING
    except OSError as exc:
        raise SupervisorError(
            f"cannot signal starting child {process.pid}: {exc}"
        ) from exc
    return GroupSignalOutcome.DIRECT_CHILD_ONLY


def signal_pinned_child(
    process: ChildProcess,
    signum: int,
) -> GroupSignalOutcome:
    if process.returncode is not None:
        return GroupSignalOutcome.MISSING
    try:
        process.send_signal(signum)
    except ProcessLookupError:
        return GroupSignalOutcome.MISSING
    except OSError as exc:
        raise SupervisorError(
            f"cannot signal pinned child {process.pid}: {exc}"
        ) from exc
    return GroupSignalOutcome.DIRECT_CHILD_ONLY


def stop_process_group(
    process: ChildProcess,
    *,
    process_group_id: int,
    initial_signal: int,
    grace_seconds: float,
    group_handoff_complete: bool,
) -> bool:
    if process.returncode is not None:
        return group_handoff_complete
    if group_handoff_complete:
        initial_outcome = signal_process_group(
            process_group_id,
            initial_signal,
            leader=process,
        )
    else:
        initial_outcome = signal_direct_child(process, initial_signal)
    signal_delivered = initial_outcome in {
        GroupSignalOutcome.SENT,
        GroupSignalOutcome.DIRECT_CHILD_ONLY,
    }
    cleanup_unverified = group_handoff_complete and initial_outcome in {
        GroupSignalOutcome.DIRECT_CHILD_ONLY,
        GroupSignalOutcome.MISSING,
        GroupSignalOutcome.LEADER_EXITED_PERMISSION,
    }
    if signal_delivered and grace_seconds:
        time.sleep(grace_seconds)
    if signal_delivered:
        if group_handoff_complete:
            kill_outcome = signal_process_group(
                process_group_id,
                signal.SIGKILL,
                leader=process,
            )
        else:
            kill_outcome = signal_direct_child(process, signal.SIGKILL)
        if group_handoff_complete:
            signal_pinned_child(process, signal.SIGKILL)
        cleanup_unverified = cleanup_unverified or (
            group_handoff_complete
            and kill_outcome
            in {
                GroupSignalOutcome.DIRECT_CHILD_ONLY,
                GroupSignalOutcome.MISSING,
                GroupSignalOutcome.LEADER_EXITED_PERMISSION,
            }
        )
    try:
        process.wait(timeout=KILL_REAP_TIMEOUT_SECONDS)
    except ChildWaitTimeout as exc:
        raise SupervisorError(
            "direct child did not exit after process-group SIGKILL"
        ) from exc
    return cleanup_unverified


def write_best_effort_diagnostic(
    diagnostic: bytes,
    *,
    restore_sigpipe: bool,
) -> None:
    previous_sigpipe: signal.Handlers | None = None
    if hasattr(signal, "SIGPIPE"):
        try:
            if restore_sigpipe:
                previous_sigpipe = signal.getsignal(signal.SIGPIPE)
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        except (OSError, ValueError):
            return
    restore_blocking = False
    try:
        try:
            restore_blocking = os.get_blocking(2)
            if restore_blocking:
                os.set_blocking(2, False)
        except (AttributeError, OSError):
            return
        try:
            os.write(2, diagnostic)
        except OSError:
            pass
    finally:
        if restore_blocking:
            try:
                os.set_blocking(2, True)
            except (AttributeError, OSError):
                pass
        if previous_sigpipe is not None:
            try:
                signal.signal(signal.SIGPIPE, previous_sigpipe)
            except (OSError, ValueError):
                pass


def child_error(message: str, returncode: int, *file_descriptors: int) -> None:
    for file_descriptor in file_descriptors:
        try:
            os.close(file_descriptor)
        except OSError:
            pass
    diagnostic = f"run_process_group_deadline: {message[:512]}\n".encode(
        "utf-8",
        errors="replace",
    )
    try:
        write_best_effort_diagnostic(diagnostic, restore_sigpipe=False)
    finally:
        os._exit(returncode)


def close_fd(file_descriptor: int) -> None:
    try:
        os.close(file_descriptor)
    except OSError:
        pass


def inherited_file_descriptors() -> tuple[int, ...]:
    for directory in ("/dev/fd", "/proc/self/fd"):
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        return tuple(
            sorted(
                int(name)
                for name in names
                if name.isdigit() and int(name) > 2
            )
        )
    raise SupervisorError("cannot enumerate inherited file descriptors")


def exec_child(
    command: list[str],
    readiness_fd: int,
    start_fd: int,
    *,
    new_session: bool,
    inherited_signal_mask: set[signal.Signals],
    inherited_sigchld_handler: signal.Handlers,
    inherited_file_descriptors_to_close: tuple[int, ...],
) -> None:
    try:
        if new_session:
            os.setsid()
        else:
            os.setpgid(0, 0)
        for signum in CHILD_DEFAULT_SIGNALS:
            signal.signal(signum, signal.SIG_DFL)
        signal.signal(signal.SIGCHLD, inherited_sigchld_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, inherited_signal_mask)
    except (OSError, ValueError) as exc:
        child_error(
            f"cannot create child process group: {exc}",
            SUPERVISOR_ERROR_EXIT,
            readiness_fd,
            start_fd,
        )

    try:
        os.write(readiness_fd, GROUP_READY_MARKER)
        os.close(readiness_fd)
    except OSError as exc:
        child_error(
            f"cannot report child process group: {exc}",
            SUPERVISOR_ERROR_EXIT,
            readiness_fd,
            start_fd,
        )

    try:
        start_marker = os.read(start_fd, 1)
        os.close(start_fd)
    except OSError as exc:
        child_error(
            f"cannot receive exec release: {exc}",
            SUPERVISOR_ERROR_EXIT,
            start_fd,
        )
    if start_marker != GROUP_READY_MARKER:
        child_error(
            "supervisor exited before exec release",
            SUPERVISOR_ERROR_EXIT,
            start_fd,
        )

    for file_descriptor in inherited_file_descriptors_to_close:
        close_fd(file_descriptor)
    try:
        os.execvp(command[0], command)
    except FileNotFoundError:
        child_error(
            f"command not found: {command[0]}",
            COMMAND_NOT_FOUND_EXIT,
            readiness_fd,
            start_fd,
        )
    except PermissionError:
        child_error(
            f"command is not executable: {command[0]}",
            CANNOT_EXECUTE_EXIT,
            readiness_fd,
            start_fd,
        )
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
            child_error(
                f"command not found: {command[0]}",
                COMMAND_NOT_FOUND_EXIT,
                readiness_fd,
                start_fd,
            )
        if exc.errno in {errno.EACCES, errno.EPERM, errno.ENOEXEC, errno.EISDIR}:
            child_error(
                f"command cannot be executed: {command[0]}: {exc}",
                CANNOT_EXECUTE_EXIT,
                readiness_fd,
                start_fd,
            )
        child_error(
            f"cannot start command: {exc}",
            SUPERVISOR_ERROR_EXIT,
            readiness_fd,
            start_fd,
        )
    child_error(
        "command exec returned unexpectedly",
        SUPERVISOR_ERROR_EXIT,
        readiness_fd,
        start_fd,
    )


def spawn_process(
    command: list[str],
    *,
    new_session: bool,
    inherited_sigchld_handler: signal.Handlers,
    inherited_signal_mask: set[signal.Signals],
    parent_signal_mask: set[signal.Signals],
    deadline: float,
) -> tuple[ChildProcess, int, int]:
    opened_file_descriptors: list[int] = []
    try:
        require_time_remaining(deadline)
        readiness_read_fd, readiness_write_fd = os.pipe()
        opened_file_descriptors.extend((readiness_read_fd, readiness_write_fd))
        require_time_remaining(deadline)
        start_read_fd, start_write_fd = os.pipe()
        opened_file_descriptors.extend((start_read_fd, start_write_fd))
        for file_descriptor in opened_file_descriptors:
            os.set_inheritable(file_descriptor, False)
        os.set_blocking(readiness_read_fd, False)
        require_time_remaining(deadline)
        inherited_file_descriptors_to_close = inherited_file_descriptors()
        require_time_remaining(deadline)
        pid = os.fork()
    except BaseException:
        for file_descriptor in opened_file_descriptors:
            close_fd(file_descriptor)
        signal.pthread_sigmask(signal.SIG_SETMASK, parent_signal_mask)
        raise
    if pid == 0:
        close_fd(readiness_read_fd)
        close_fd(start_write_fd)
        try:
            exec_child(
                command,
                readiness_write_fd,
                start_read_fd,
                new_session=new_session,
                inherited_signal_mask=inherited_signal_mask,
                inherited_sigchld_handler=inherited_sigchld_handler,
                inherited_file_descriptors_to_close=(
                    inherited_file_descriptors_to_close
                ),
            )
        except BaseException as exc:
            child_error(
                f"child bootstrap failed: {type(exc).__name__}",
                SUPERVISOR_ERROR_EXIT,
                readiness_write_fd,
                start_read_fd,
            )
        os._exit(SUPERVISOR_ERROR_EXIT)
    close_fd(readiness_write_fd)
    close_fd(start_read_fd)
    return ChildProcess(pid), readiness_read_fd, start_write_fd


def wait_for_group_handoff(
    process: ChildProcess,
    readiness_fd: int,
    *,
    deadline: float,
) -> bool:
    sleep_seconds = WAIT_POLL_INITIAL_SECONDS
    while True:
        try:
            marker = os.read(readiness_fd, 1)
        except BlockingIOError:
            marker = None
        except InterruptedError:
            continue
        if marker is not None:
            return marker == GROUP_READY_MARKER
        if process.poll() is not None:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChildWaitTimeout
        time.sleep(min(sleep_seconds, remaining))
        sleep_seconds = min(sleep_seconds * 2, WAIT_POLL_MAX_SECONDS)


def release_child_for_exec(start_fd: int) -> None:
    try:
        written = os.write(start_fd, GROUP_READY_MARKER)
    except OSError as exc:
        raise SupervisorError(f"cannot release child exec: {exc}") from exc
    if written != len(GROUP_READY_MARKER):
        raise SupervisorError("cannot release child exec: short control write")


def install_signal_handlers(
    gate: SignalGate,
) -> dict[int, signal.Handlers]:
    previous: dict[int, signal.Handlers] = {}

    for signum in MANAGED_SIGNALS:
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, gate.handle)
    return previous


def ignore_managed_signals() -> None:
    for signum in MANAGED_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def restore_signal_handlers(previous: dict[int, signal.Handlers]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def close_gate_and_restore_signal_handlers(
    gate: SignalGate,
    previous: dict[int, signal.Handlers],
    final_signal_mask: set[signal.Signals],
) -> None:
    pthread_sigmask = getattr(signal, "pthread_sigmask", None)
    if pthread_sigmask is None:
        gate.close()
        restore_signal_handlers(previous)
        return

    pthread_sigmask(
        signal.SIG_BLOCK,
        MANAGED_SIGNALS,
    )
    try:
        gate.close()
        restore_signal_handlers(previous)
    finally:
        pthread_sigmask(signal.SIG_SETMASK, final_signal_mask)


def print_error(message: str) -> None:
    diagnostic = (
        f"run_process_group_deadline: {message[:1024]}\n"
    ).encode("utf-8", errors="replace")
    write_best_effort_diagnostic(diagnostic, restore_sigpipe=True)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a command is required after --")

    if os.name != "posix":
        print_error(
            "process-group deadlines are unsupported on non-POSIX hosts; "
            "command was not started"
        )
        return SUPERVISOR_ERROR_EXIT
    required_posix_functions = ("fork", "killpg", "setpgid", "setsid", "waitpid")
    if any(not hasattr(os, name) for name in required_posix_functions):
        print_error("required POSIX process-group functions are unavailable")
        return SUPERVISOR_ERROR_EXIT
    if not callable(getattr(signal, "pthread_sigmask", None)):
        print_error("POSIX signal masking is required for safe process startup")
        return SUPERVISOR_ERROR_EXIT
    if not hasattr(signal, "SIGCHLD"):
        print_error("SIGCHLD control is required for direct-child supervision")
        return SUPERVISOR_ERROR_EXIT
    if threading.active_count() != 1:
        print_error("run as a standalone single-threaded CLI")
        return SUPERVISOR_ERROR_EXIT
    try:
        for standard_fd in (0, 1, 2):
            os.fstat(standard_fd)
    except OSError:
        print_error("open standard input, output, and error are required")
        return SUPERVISOR_ERROR_EXIT

    previous_sigchld_handler = signal.getsignal(signal.SIGCHLD)
    if previous_sigchld_handler is None:
        previous_sigchld_handler = signal.SIG_DFL
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    inherited_signal_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK,
        MANAGED_SIGNALS,
    )
    supervisor_signal_mask = set(inherited_signal_mask).difference(
        MANAGED_SIGNALS
    )
    gate = SignalGate()
    previous_handlers = install_signal_handlers(gate)
    process: ChildProcess | None = None
    readiness_fd: int | None = None
    start_fd: int | None = None
    group_handoff_complete = False
    deadline = time.monotonic() + args.timeout_seconds

    def run_command() -> int:
        nonlocal process
        nonlocal readiness_fd
        nonlocal start_fd
        nonlocal group_handoff_complete
        try:
            try:
                (
                    process,
                    readiness_fd,
                    start_fd,
                ) = spawn_process(
                    command,
                    new_session=args.new_session,
                    inherited_sigchld_handler=previous_sigchld_handler,
                    inherited_signal_mask=inherited_signal_mask,
                    parent_signal_mask=supervisor_signal_mask,
                    deadline=deadline,
                )
            except ChildWaitTimeout:
                gate.arm()
                raise
            except (OSError, SupervisorError) as exc:
                gate.arm()
                print_error(f"cannot launch command: {exc}")
                return SUPERVISOR_ERROR_EXIT

            try:
                gate.arm()
            finally:
                signal.pthread_sigmask(
                    signal.SIG_SETMASK,
                    supervisor_signal_mask,
                )
            group_handoff_complete = wait_for_group_handoff(
                process,
                readiness_fd,
                deadline=deadline,
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChildWaitTimeout
            if group_handoff_complete:
                try:
                    release_child_for_exec(start_fd)
                finally:
                    close_fd(start_fd)
                    start_fd = None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ChildWaitTimeout
            return normalized_exit_code(process.wait_until(deadline))
        except ChildWaitTimeout:
            gate.close()
            ignore_managed_signals()
            if process is None:
                print_error(
                    "deadline exceeded before child creation; result incomplete"
                )
                return TIMEOUT_EXIT
            try:
                cleanup_unverified = stop_process_group(
                    process,
                    process_group_id=process.pid,
                    initial_signal=signal.SIGTERM,
                    grace_seconds=args.grace_seconds,
                    group_handoff_complete=group_handoff_complete,
                )
            except SupervisorError as exc:
                print_error(str(exc))
                return SUPERVISOR_ERROR_EXIT
            message = "deadline exceeded; result incomplete"
            if cleanup_unverified:
                message += "; post-TERM group cleanup unverified"
            print_error(message)
            return TIMEOUT_EXIT
        except SupervisorError as exc:
            gate.close()
            ignore_managed_signals()
            if process is not None:
                try:
                    stop_process_group(
                        process,
                        process_group_id=process.pid,
                        initial_signal=signal.SIGTERM,
                        grace_seconds=0,
                        group_handoff_complete=group_handoff_complete,
                    )
                except SupervisorError as cleanup_exc:
                    print_error(f"{exc}; cleanup failed: {cleanup_exc}")
                    return SUPERVISOR_ERROR_EXIT
            print_error(str(exc))
            return SUPERVISOR_ERROR_EXIT
        finally:
            if readiness_fd is not None:
                close_fd(readiness_fd)
            if start_fd is not None:
                close_fd(start_fd)

    try:
        try:
            result = run_command()
            close_gate_and_restore_signal_handlers(
                gate,
                previous_handlers,
                inherited_signal_mask,
            )
        except ForwardedSignal as event:
            gate.close()
            ignore_managed_signals()
            if process is not None:
                try:
                    cleanup_unverified = stop_process_group(
                        process,
                        process_group_id=process.pid,
                        initial_signal=event.signum,
                        grace_seconds=args.grace_seconds,
                        group_handoff_complete=group_handoff_complete,
                    )
                except SupervisorError as exc:
                    print_error(str(exc))
                    result = SUPERVISOR_ERROR_EXIT
                else:
                    if cleanup_unverified:
                        print_error(
                            "forwarded signal; process-group cleanup unverified"
                        )
                    result = min(255, 128 + event.signum)
            else:
                result = min(255, 128 + event.signum)
            close_gate_and_restore_signal_handlers(
                gate,
                previous_handlers,
                inherited_signal_mask,
            )
        return result
    finally:
        try:
            signal.signal(signal.SIGCHLD, previous_sigchld_handler)
        finally:
            signal.pthread_sigmask(
                signal.SIG_SETMASK,
                inherited_signal_mask,
            )


if __name__ == "__main__":
    raise SystemExit(main())
