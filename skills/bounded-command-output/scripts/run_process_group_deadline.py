#!/usr/bin/env python3

from __future__ import annotations

import argparse
import enum
import math
import os
import signal
import subprocess
import sys
import time


TIMEOUT_EXIT = 124
SUPERVISOR_ERROR_EXIT = 125
CANNOT_EXECUTE_EXIT = 126
COMMAND_NOT_FOUND_EXIT = 127
KILL_REAP_TIMEOUT_SECONDS = 5.0
MANAGED_SIGNALS = tuple(
    getattr(signal, name)
    for name in ("SIGINT", "SIGTERM", "SIGHUP")
    if hasattr(signal, name)
)


class ForwardedSignal(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


class SupervisorError(Exception):
    pass


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


def finite_positive(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def finite_nonnegative(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("must be finite and nonnegative")
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
    leader: subprocess.Popen[bytes],
) -> GroupSignalOutcome:
    try:
        os.killpg(process_group_id, signum)
    except ProcessLookupError:
        return GroupSignalOutcome.MISSING
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


def stop_process_group(
    process: subprocess.Popen[bytes],
    *,
    process_group_id: int,
    initial_signal: int,
    grace_seconds: float,
) -> bool:
    initial_outcome = signal_process_group(
        process_group_id,
        initial_signal,
        leader=process,
    )
    signal_delivered = initial_outcome in {
        GroupSignalOutcome.SENT,
        GroupSignalOutcome.DIRECT_CHILD_ONLY,
    }
    cleanup_unverified = initial_outcome in {
        GroupSignalOutcome.DIRECT_CHILD_ONLY,
        GroupSignalOutcome.LEADER_EXITED_PERMISSION,
    }
    if signal_delivered and grace_seconds:
        time.sleep(grace_seconds)
    if signal_delivered:
        kill_outcome = signal_process_group(
            process_group_id,
            signal.SIGKILL,
            leader=process,
        )
        cleanup_unverified = cleanup_unverified or kill_outcome in {
            GroupSignalOutcome.DIRECT_CHILD_ONLY,
            GroupSignalOutcome.LEADER_EXITED_PERMISSION,
        }
    try:
        process.wait(timeout=KILL_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise SupervisorError(
            "direct child did not exit after process-group SIGKILL"
        ) from exc
    return cleanup_unverified


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


def print_error(message: str) -> None:
    print(f"run_process_group_deadline: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a command is required after --")

    if os.name != "posix":
        print_error("POSIX process groups are required")
        return SUPERVISOR_ERROR_EXIT
    if not args.new_session and sys.version_info < (3, 11):
        print_error(
            "same-session process groups require Python 3.11 or newer; "
            "use --new-session only when losing the controlling terminal is acceptable"
        )
        return SUPERVISOR_ERROR_EXIT

    popen_options: dict[str, object]
    if args.new_session:
        popen_options = {"start_new_session": True}
    else:
        popen_options = {"process_group": 0}

    gate = SignalGate()
    previous_handlers = install_signal_handlers(gate)
    process: subprocess.Popen[bytes] | None = None
    try:
        try:
            try:
                process = subprocess.Popen(command, **popen_options)
            except FileNotFoundError:
                gate.arm()
                print_error(f"command not found: {command[0]}")
                return COMMAND_NOT_FOUND_EXIT
            except PermissionError:
                gate.arm()
                print_error(f"command is not executable: {command[0]}")
                return CANNOT_EXECUTE_EXIT
            except OSError as exc:
                gate.arm()
                print_error(f"cannot start command: {exc}")
                return SUPERVISOR_ERROR_EXIT

            process_group_id = process.pid
            gate.arm()
            try:
                return normalized_exit_code(
                    process.wait(timeout=args.timeout_seconds)
                )
            except subprocess.TimeoutExpired:
                ignore_managed_signals()
                try:
                    cleanup_unverified = stop_process_group(
                        process,
                        process_group_id=process_group_id,
                        initial_signal=signal.SIGTERM,
                        grace_seconds=args.grace_seconds,
                    )
                except SupervisorError as exc:
                    print_error(str(exc))
                    return SUPERVISOR_ERROR_EXIT
                message = "deadline exceeded; result incomplete"
                if cleanup_unverified:
                    message += "; post-TERM group cleanup unverified"
                print_error(message)
                return TIMEOUT_EXIT
        except ForwardedSignal as event:
            ignore_managed_signals()
            if process is None:
                return min(255, 128 + event.signum)
            try:
                cleanup_unverified = stop_process_group(
                    process,
                    process_group_id=process.pid,
                    initial_signal=event.signum,
                    grace_seconds=args.grace_seconds,
                )
            except SupervisorError as exc:
                print_error(str(exc))
                return SUPERVISOR_ERROR_EXIT
            if cleanup_unverified:
                print_error("forwarded signal; process-group cleanup unverified")
            return min(255, 128 + event.signum)
    finally:
        restore_signal_handlers(previous_handlers)


if __name__ == "__main__":
    raise SystemExit(main())
