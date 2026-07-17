from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator
from contextlib import redirect_stderr, redirect_stdout
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = (
    REPO_ROOT
    / "skills/codex-session-retrospective/scripts/remote_codex_probe.py"
)
SPEC = importlib.util.spec_from_file_location(
    "remote_codex_probe_descriptor_tests",
    SCRIPT_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


ROLLOUT_REF = (
    "sessions/2026/05/26/"
    "rollout-2026-05-26T10-00-00-descriptor.jsonl"
)


def session_meta_row(
    session_id: str,
    *,
    timestamp: str = "2026-05-26T10:00:00Z",
    cwd: str = "/trusted",
) -> dict[str, object]:
    return {
        "type": "session_meta",
        "timestamp": timestamp,
        "payload": {"id": session_id, "cwd": cwd},
    }


def write_rollout(
    codex_root: Path,
    *,
    rollout_ref: str = ROLLOUT_REF,
    session_id: str = "trusted-session",
    timestamp: str = "2026-05-26T10:00:00Z",
) -> Path:
    rollout = codex_root / rollout_ref
    rollout.parent.mkdir(parents=True, exist_ok=True)
    rollout.write_text(
        json.dumps(
            session_meta_row(session_id, timestamp=timestamp),
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return rollout


def embedded_probe_namespace(payload: dict[str, object]) -> dict[str, object]:
    script = MODULE._remote_python_script(payload)
    definitions = script.split('\nif CONFIG["mode"] ==', 1)[0]
    namespace: dict[str, object] = {
        "__name__": "embedded_remote_codex_probe_descriptor_tests"
    }
    exec(
        compile(definitions, "<embedded-remote-codex-probe>", "exec"),
        namespace,
    )
    return namespace


def entry_mutating_scandir(
    real_scandir: Callable[[object], Any],
    target_name: str,
    mutate: Callable[[], None],
    *,
    before_stat: bool = False,
) -> Callable[[object], Any]:
    class EntryProxy:
        def __init__(self, entry: Any) -> None:
            self._entry = entry
            self.name = entry.name

        def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
            if before_stat:
                mutate()
            result = self._entry.stat(follow_symlinks=follow_symlinks)
            if not before_stat:
                mutate()
            return result

        def __getattr__(self, name: str) -> Any:
            return getattr(self._entry, name)

    class ScandirProxy:
        def __init__(self, context: Any) -> None:
            self._context = context

        def __enter__(self) -> Iterator[Any]:
            entries = self._context.__enter__()
            return (
                EntryProxy(entry) if entry.name == target_name else entry
                for entry in entries
            )

        def __exit__(self, *args: object) -> Any:
            return self._context.__exit__(*args)

    def mutating_scandir(path: object) -> Any:
        return ScandirProxy(real_scandir(path))

    return mutating_scandir


class RemoteCodexProbeDescriptorTests(unittest.TestCase):
    def test_session_meta_binds_identity_captured_during_scandir(self) -> None:
        for scope in ("local", "embedded"):
            for mutation in (
                "delete_before_stat",
                "delete_after_stat",
                "replace_after_stat",
            ):
                with self.subTest(
                    scope=scope,
                    mutation=mutation,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    codex_root = Path(temp_dir) / ".codex"
                    rollout = write_rollout(codex_root)
                    replacement = rollout.with_suffix(".replacement")
                    replacement.write_text(
                        json.dumps(session_meta_row("replacement-session")) + "\n",
                        encoding="utf-8",
                    )
                    mutated = False

                    def mutate() -> None:
                        nonlocal mutated
                        if mutated:
                            return
                        mutated = True
                        if mutation.startswith("delete"):
                            rollout.unlink()
                        else:
                            os.replace(replacement, rollout)

                    if scope == "local":
                        target_os = MODULE.os

                        def run_scan() -> object:
                            return MODULE._scan_session_meta_records(
                                codex_root=codex_root,
                                dates=[dt.date(2026, 5, 26)],
                                limit=10,
                                host="local",
                            )
                    else:
                        namespace = embedded_probe_namespace(
                            {
                                "mode": "session-meta",
                                "dates": ["2026/05/26"],
                                "limit": 10,
                                "codex_root": str(codex_root),
                                "session_meta_scan_bytes": MODULE.MAX_SESSION_META_SCAN_BYTES,
                            }
                        )
                        target_os = namespace["os"]

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    mutating_scandir = entry_mutating_scandir(
                        target_os.scandir,
                        rollout.name,
                        mutate,
                        before_stat=mutation == "delete_before_stat",
                    )
                    output = io.StringIO()
                    if scope == "local":
                        with mock.patch.object(
                            target_os,
                            "scandir",
                            side_effect=mutating_scandir,
                        ), self.assertRaises(
                            MODULE.SessionMetaRolloutError
                        ) as raised:
                            run_scan()
                        error = raised.exception.error
                        error_rollout = raised.exception.rollout
                    else:
                        with mock.patch.object(
                            target_os,
                            "scandir",
                            side_effect=mutating_scandir,
                        ), redirect_stdout(output), self.assertRaises(
                            SystemExit
                        ) as raised:
                            run_scan()
                        self.assertEqual(raised.exception.code, 0)
                        lines = output.getvalue().splitlines()
                        self.assertEqual(lines[0], MODULE.REMOTE_SESSION_META_BEGIN)
                        self.assertEqual(lines[-1], MODULE.REMOTE_SESSION_META_END)
                        record = json.loads(lines[1])
                        error = record["error"]
                        error_rollout = record["rollout"]

                    self.assertTrue(mutated)
                    self.assertIn("identity changed", error)
                    self.assertEqual(error_rollout, ROLLOUT_REF)
                    self.assertNotIn("replacement-session", output.getvalue())

    def test_session_meta_allows_same_inode_append_local_and_embedded(self) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root)
                original_stat = rollout.stat()
                appended = False

                def append_after_identity_capture() -> None:
                    nonlocal appended
                    if appended:
                        return
                    appended = True
                    with rollout.open("ab") as output:
                        output.write(
                            b'{"type":"event_msg","payload":{"type":"task_complete"}}\n'
                        )

                if scope == "local":
                    target_os = MODULE.os
                else:
                    namespace = embedded_probe_namespace(
                        {
                            "mode": "session-meta",
                            "dates": ["2026/05/26"],
                            "limit": 10,
                            "codex_root": str(codex_root),
                            "session_meta_scan_bytes": MODULE.MAX_SESSION_META_SCAN_BYTES,
                        }
                    )
                    target_os = namespace["os"]
                mutating_scandir = entry_mutating_scandir(
                    target_os.scandir,
                    rollout.name,
                    append_after_identity_capture,
                )
                output = io.StringIO()
                with mock.patch.object(
                    target_os,
                    "scandir",
                    side_effect=mutating_scandir,
                ), redirect_stdout(output):
                    if scope == "local":
                        scan = MODULE._scan_session_meta_records(
                            codex_root=codex_root,
                            dates=[dt.date(2026, 5, 26)],
                            limit=10,
                            host="local",
                        )
                        session_ids = [row["session_id"] for row in scan.rows]
                    else:
                        namespace["iter_session_meta"]()
                        session_ids = [
                            json.loads(line)["session_id"]
                            for line in output.getvalue().splitlines()[1:-1]
                        ]

                final_stat = rollout.stat()
                self.assertTrue(appended)
                self.assertEqual(
                    (final_stat.st_dev, final_stat.st_ino),
                    (original_stat.st_dev, original_stat.st_ino),
                )
                self.assertGreater(final_stat.st_size, original_stat.st_size)
                self.assertEqual(session_ids, ["trusted-session"])

    def test_session_meta_bounds_directory_fds_across_31_dates(self) -> None:
        dates = [
            dt.date(2026, 1, 1) + dt.timedelta(days=offset)
            for offset in range(31)
        ]
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                for date_value in dates:
                    date_path = date_value.strftime("%Y/%m/%d")
                    (codex_root / "sessions" / date_path).mkdir(parents=True)
                    (codex_root / "archived_sessions" / date_path).mkdir(parents=True)

                if scope == "local":
                    target_os = MODULE.os
                else:
                    namespace = embedded_probe_namespace(
                        {
                            "mode": "session-meta",
                            "dates": [value.strftime("%Y/%m/%d") for value in dates],
                            "limit": 10,
                            "codex_root": str(codex_root),
                            "session_meta_scan_bytes": MODULE.MAX_SESSION_META_SCAN_BYTES,
                        }
                    )
                    target_os = namespace["os"]
                real_open = target_os.open
                real_dup = target_os.dup
                real_close = target_os.close
                directory_fds: set[int] = set()
                peak_directory_fds = 0

                def register_directory_fd(fd: int) -> int:
                    nonlocal peak_directory_fds
                    if len(directory_fds) >= 63:
                        real_close(fd)
                        raise OSError(24, "mock directory descriptor limit")
                    directory_fds.add(fd)
                    peak_directory_fds = max(
                        peak_directory_fds,
                        len(directory_fds),
                    )
                    return fd

                def tracking_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    fd = real_open(path, flags, mode, dir_fd=dir_fd)
                    if flags & os.O_DIRECTORY:
                        return register_directory_fd(fd)
                    return fd

                def tracking_dup(fd: int) -> int:
                    duplicated = real_dup(fd)
                    if fd in directory_fds:
                        return register_directory_fd(duplicated)
                    return duplicated

                def tracking_close(fd: int) -> None:
                    directory_fds.discard(fd)
                    real_close(fd)

                output = io.StringIO()
                with mock.patch.object(
                    target_os,
                    "open",
                    side_effect=tracking_open,
                ), mock.patch.object(
                    target_os,
                    "dup",
                    side_effect=tracking_dup,
                ), mock.patch.object(
                    target_os,
                    "close",
                    side_effect=tracking_close,
                ), redirect_stdout(output):
                    if scope == "local":
                        scan = MODULE._scan_session_meta_records(
                            codex_root=codex_root,
                            dates=dates,
                            limit=10,
                            host="local",
                        )
                        self.assertEqual(scan.rows, [])
                    else:
                        namespace["iter_session_meta"]()
                        self.assertEqual(
                            output.getvalue().splitlines(),
                            [
                                MODULE.REMOTE_SESSION_META_BEGIN,
                                MODULE.REMOTE_SESSION_META_END,
                            ],
                        )

                self.assertLess(peak_directory_fds, 64)
                self.assertEqual(directory_fds, set())

    def test_relative_path_validators_reject_absolute_and_parent_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / ".codex"
            namespace = embedded_probe_namespace(
                {
                    "mode": "session-meta",
                    "dates": [],
                    "limit": 10,
                    "codex_root": str(root),
                    "session_meta_scan_bytes": MODULE.MAX_SESSION_META_SCAN_BYTES,
                }
            )
            for invalid in (
                PurePosixPath("/tmp/rollout.jsonl"),
                PurePosixPath("sessions/../rollout.jsonl"),
            ):
                with self.subTest(scope="local", invalid=invalid), self.assertRaisesRegex(
                    ValueError,
                    "path must stay under Codex root",
                ):
                    MODULE._validate_relative_path_parts(invalid)
                with self.subTest(
                    scope="embedded",
                    invalid=invalid,
                ), self.assertRaisesRegex(
                    ValueError,
                    "path must stay under Codex root",
                ):
                    namespace["validate_relative_path_parts"](invalid)

    def test_root_swap_between_lstat_and_resolve_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            codex_root = base / ".codex"
            external_root = base / "external-codex"
            write_rollout(codex_root)
            write_rollout(external_root, session_id="external-sentinel")
            moved_root = base / ".codex-pinned"
            real_resolve = MODULE.pathlib.Path.resolve
            swapped = False

            def swap_before_resolve(path: Path, *args: object, **kwargs: object) -> Path:
                nonlocal swapped
                if path == codex_root and not swapped:
                    os.replace(codex_root, moved_root)
                    os.replace(external_root, codex_root)
                    swapped = True
                return real_resolve(path, *args, **kwargs)

            with mock.patch.object(
                MODULE.pathlib.Path,
                "resolve",
                swap_before_resolve,
            ), self.assertRaisesRegex(
                ValueError,
                "Codex root changed during resolution",
            ):
                MODULE._read_local_rollout_bytes(
                    codex_root,
                    PurePosixPath(ROLLOUT_REF),
                    max_bytes=MODULE.MAX_FETCH_ROLLOUT_BYTES,
                )

            self.assertTrue(swapped)
            self.assertNotIn(
                b"external-sentinel",
                (moved_root / ROLLOUT_REF).read_bytes(),
            )

    def test_root_swap_between_stat_and_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            codex_root = base / ".codex"
            external_root = base / "external-codex"
            write_rollout(codex_root)
            write_rollout(external_root, session_id="external-sentinel")
            resolved_root = codex_root.resolve()
            moved_root = base / ".codex-pinned"
            real_open = MODULE.os.open
            swapped = False

            def swap_before_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if str(path) == str(resolved_root) and dir_fd is None and not swapped:
                    os.replace(codex_root, moved_root)
                    os.replace(external_root, codex_root)
                    swapped = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(
                MODULE.os,
                "open",
                side_effect=swap_before_open,
            ), self.assertRaisesRegex(
                ValueError,
                "Codex root changed during open",
            ):
                MODULE._read_local_rollout_bytes(
                    codex_root,
                    PurePosixPath(ROLLOUT_REF),
                    max_bytes=MODULE.MAX_FETCH_ROLLOUT_BYTES,
                )

        self.assertTrue(swapped)

    def test_ancestor_swap_between_stat_and_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            codex_root = base / ".codex"
            external_root = base / "external-codex"
            write_rollout(codex_root)
            write_rollout(external_root, session_id="external-sentinel")
            moved_sessions = codex_root / "sessions-pinned"
            real_open = MODULE.os.open
            swapped = False

            def swap_sessions_before_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if path == "sessions" and dir_fd is not None and not swapped:
                    os.replace(codex_root / "sessions", moved_sessions)
                    os.replace(external_root / "sessions", codex_root / "sessions")
                    swapped = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(
                MODULE.os,
                "open",
                side_effect=swap_sessions_before_open,
            ), self.assertRaisesRegex(
                ValueError,
                "path ancestor changed during open",
            ):
                MODULE._read_local_rollout_bytes(
                    codex_root,
                    PurePosixPath(ROLLOUT_REF),
                    max_bytes=MODULE.MAX_FETCH_ROLLOUT_BYTES,
                )

        self.assertTrue(swapped)

    def test_reader_stays_on_pinned_ancestor_after_post_open_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            codex_root = base / ".codex"
            external_root = base / "external-codex"
            trusted_rollout = write_rollout(codex_root)
            write_rollout(external_root, session_id="external-sentinel")
            trusted_data = trusted_rollout.read_bytes()
            moved_sessions = codex_root / "sessions-pinned"
            external_sessions = external_root / "sessions"
            real_open = MODULE.os.open
            swapped = False

            def swap_sessions_after_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
                if path == "sessions" and dir_fd is not None and not swapped:
                    os.replace(codex_root / "sessions", moved_sessions)
                    (codex_root / "sessions").symlink_to(
                        external_sessions,
                        target_is_directory=True,
                    )
                    swapped = True
                return fd

            with mock.patch.object(
                MODULE.os,
                "open",
                side_effect=swap_sessions_after_open,
            ):
                data = MODULE._read_local_rollout_bytes(
                    codex_root,
                    PurePosixPath(ROLLOUT_REF),
                    max_bytes=MODULE.MAX_FETCH_ROLLOUT_BYTES,
                )

        self.assertTrue(swapped)
        self.assertEqual(data, trusted_data)
        self.assertNotIn(b"external-sentinel", data)

    def test_final_swap_between_stat_and_open_fails_closed_local_and_embedded(
        self,
    ) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root)
                replacement = rollout.with_suffix(".replacement")
                replacement.write_text(
                    json.dumps(session_meta_row("external-sentinel")) + "\n",
                    encoding="utf-8",
                )
                if scope == "local":
                    target_os = MODULE.os

                    def reader() -> bytes:
                        return MODULE._read_local_rollout_bytes(
                            codex_root,
                            PurePosixPath(ROLLOUT_REF),
                            max_bytes=MODULE.MAX_FETCH_ROLLOUT_BYTES,
                        )
                else:
                    namespace = embedded_probe_namespace(
                        {
                            "mode": "fetch-rollout",
                            "rollout": ROLLOUT_REF,
                            "codex_root": str(codex_root),
                            "max_fetch_rollout_bytes": MODULE.MAX_FETCH_ROLLOUT_BYTES,
                        }
                    )
                    target_os = namespace["os"]

                    def reader() -> bytes:
                        return namespace["read_rollout_bytes"](
                            namespace["pathlib"].PurePosixPath(ROLLOUT_REF),
                            MODULE.MAX_FETCH_ROLLOUT_BYTES,
                        )
                real_open = target_os.open
                opened_flags: list[int] = []
                swapped = False

                def swap_final_before_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal swapped
                    if path == rollout.name and dir_fd is not None and not swapped:
                        os.replace(replacement, rollout)
                        opened_flags.append(flags)
                        swapped = True
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with mock.patch.object(
                    target_os,
                    "open",
                    side_effect=swap_final_before_open,
                ), self.assertRaisesRegex(ValueError, "identity changed.*during open"):
                    reader()

                self.assertTrue(swapped)
                self.assertTrue(opened_flags[0] & os.O_NOFOLLOW)
                self.assertTrue(opened_flags[0] & os.O_NONBLOCK)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "FIFO nonblocking opens require POSIX mkfifo and O_NONBLOCK",
    )
    def test_fifo_swap_before_final_open_fails_without_blocking(self) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root)
                pinned = rollout.with_suffix(".pinned")
                if scope == "local":
                    target_os = MODULE.os

                    def reader() -> bytes:
                        return MODULE._read_local_rollout_bytes(
                            codex_root,
                            PurePosixPath(ROLLOUT_REF),
                            max_bytes=MODULE.MAX_FETCH_ROLLOUT_BYTES,
                        )
                else:
                    namespace = embedded_probe_namespace(
                        {
                            "mode": "fetch-rollout",
                            "rollout": ROLLOUT_REF,
                            "codex_root": str(codex_root),
                            "max_fetch_rollout_bytes": MODULE.MAX_FETCH_ROLLOUT_BYTES,
                        }
                    )
                    target_os = namespace["os"]

                    def reader() -> bytes:
                        return namespace["read_rollout_bytes"](
                            namespace["pathlib"].PurePosixPath(ROLLOUT_REF),
                            MODULE.MAX_FETCH_ROLLOUT_BYTES,
                        )
                real_open = target_os.open
                opened_flags: list[int] = []

                def swap_for_fifo(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    if path == rollout.name and dir_fd is not None and not opened_flags:
                        os.replace(rollout, pinned)
                        os.mkfifo(rollout, 0o600)
                        self.assertTrue(flags & os.O_NONBLOCK)
                        opened_flags.append(flags)
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with mock.patch.object(
                    target_os,
                    "open",
                    side_effect=swap_for_fifo,
                ), self.assertRaisesRegex(ValueError, "not a regular file"):
                    reader()

                self.assertEqual(len(opened_flags), 1)
                self.assertTrue(opened_flags[0] & os.O_NONBLOCK)

    def test_post_open_scandir_missing_is_path_neutral_local_and_embedded(
        self,
    ) -> None:
        secret = "/sensitive/scandir-target"
        with tempfile.TemporaryDirectory() as temp_dir:
            codex_root = Path(temp_dir) / ".codex"
            write_rollout(codex_root)
            with mock.patch.object(
                MODULE.os,
                "scandir",
                side_effect=FileNotFoundError(secret),
            ), self.assertRaises(MODULE.SessionMetaRolloutError) as raised:
                MODULE._scan_session_meta_records(
                    codex_root=codex_root,
                    dates=[dt.date(2026, 5, 26)],
                    limit=10,
                    host="local",
                )
            self.assertEqual(raised.exception.error, "session directory unreadable")
            self.assertNotIn(secret, str(raised.exception))

            namespace = embedded_probe_namespace(
                {
                    "mode": "session-meta",
                    "dates": ["2026/05/26"],
                    "limit": 10,
                    "codex_root": str(codex_root),
                    "session_meta_scan_bytes": MODULE.MAX_SESSION_META_SCAN_BYTES,
                }
            )
            output = io.StringIO()
            with mock.patch.object(
                namespace["os"],
                "scandir",
                side_effect=FileNotFoundError(secret),
            ), redirect_stdout(output), self.assertRaises(SystemExit) as embedded_exit:
                namespace["iter_session_meta"]()

        self.assertEqual(embedded_exit.exception.code, 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                MODULE.REMOTE_SESSION_META_BEGIN,
                '{"error":"session directory unreadable","kind":"error"}',
                MODULE.REMOTE_SESSION_META_END,
            ],
        )
        self.assertNotIn(secret, output.getvalue())

    def test_parent_dup_failure_closes_final_fd_and_stays_path_neutral(self) -> None:
        secret = "/sensitive/dup-failure"
        with tempfile.TemporaryDirectory() as temp_dir:
            codex_root = Path(temp_dir) / ".codex"
            rollout = write_rollout(codex_root)
            real_open = MODULE.os.open
            real_dup = MODULE.os.dup
            rollout_fds: list[int] = []
            final_opened = False

            def tracking_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal final_opened
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
                if path == rollout.name and dir_fd is not None:
                    rollout_fds.append(fd)
                    final_opened = True
                return fd

            def fail_final_parent_dup(fd: int) -> int:
                if final_opened:
                    raise OSError(24, "Too many open files", secret)
                return real_dup(fd)

            with mock.patch.object(
                MODULE.os,
                "open",
                side_effect=tracking_open,
            ), mock.patch.object(
                MODULE.os,
                "dup",
                side_effect=fail_final_parent_dup,
            ), self.assertRaises(MODULE.SessionMetaRolloutError) as raised:
                MODULE._scan_session_meta_records(
                    codex_root=codex_root,
                    dates=[dt.date(2026, 5, 26)],
                    limit=10,
                    host="local",
                )

        self.assertEqual(raised.exception.error, "rollout unreadable")
        self.assertEqual(raised.exception.rollout, ROLLOUT_REF)
        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(len(rollout_fds), 1)
        with self.assertRaises(OSError):
            os.fstat(rollout_fds[0])

    def test_root_rollout_window_and_auto_split_semantics_remain_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            codex_root = Path(temp_dir) / ".codex"
            root_ref = "rollout-2026-05-26T10-00-00-root.jsonl"
            write_rollout(codex_root, rollout_ref=root_ref, session_id="root-session")
            write_rollout(
                codex_root,
                rollout_ref=(
                    "sessions/2026/05/26/"
                    "rollout-2026-05-26T11-00-00-late.jsonl"
                ),
                session_id="late-session",
                timestamp="2026-05-26T11:00:00Z",
            )
            scan = MODULE._scan_session_meta_records(
                codex_root=codex_root,
                dates=[dt.date(2026, 5, 26)],
                limit=10,
                host="local",
                rollout_start=dt.datetime(2026, 5, 26, 9, 30, tzinfo=dt.timezone.utc),
                rollout_end=dt.datetime(2026, 5, 26, 10, 30, tzinfo=dt.timezone.utc),
            )

        self.assertEqual([row["session_id"] for row in scan.rows], ["root-session"])
        self.assertEqual(scan.rows[0]["rollout"], root_ref)

        calls: list[tuple[str, dt.datetime | None, dt.datetime | None]] = []

        def fake_scan(
            _alias: str,
            *,
            dates: list[dt.date],
            limit: int,
            rollout_start: dt.datetime | None,
            rollout_end: dt.datetime | None,
            rollout_filename_mode: str = "all",
        ) -> MODULE.SessionMetaScan:
            self.assertEqual(limit, 1)
            self.assertEqual(dates, [dt.date(2026, 5, 26)])
            calls.append((rollout_filename_mode, rollout_start, rollout_end))
            return MODULE.SessionMetaScan(rows=[], truncated=False)

        with mock.patch.object(MODULE, "_scan_host_session_meta", side_effect=fake_scan):
            split = MODULE._auto_split_host_session_meta(
                "local",
                dates=[dt.date(2026, 5, 26)],
                limit=1,
            )

        self.assertFalse(split.truncated)
        self.assertEqual(calls[0][0], "unknown")
        known_calls = [call for call in calls if call[0] == "known"]
        self.assertEqual(len(known_calls), 24)
        self.assertTrue(
            all(end - start == dt.timedelta(hours=1) for _mode, start, end in known_calls)
        )

    def test_summary_hash_proof_and_fetch_cap_remain_descriptor_backed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            codex_root = Path(temp_dir) / ".codex"
            root_ref = "rollout-2026-05-26T10-00-00-root.jsonl"
            rollout = write_rollout(
                codex_root,
                rollout_ref=root_ref,
                session_id="proof-session",
            )
            expected_hash = hashlib.sha256(rollout.read_bytes()).hexdigest()
            output = io.StringIO()
            error_output = io.StringIO()
            with mock.patch.object(
                MODULE,
                "_local_codex_root",
                return_value=codex_root,
            ), redirect_stdout(output), redirect_stderr(error_output):
                rc = MODULE.cmd_rollout_summary(
                    argparse.Namespace(
                        host="local",
                        rollout=root_ref,
                        keyword=[],
                        limit=40,
                        tail_records=8,
                        max_text_chars=400,
                    )
                )
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            scan_meta = next(
                record for record in records if record.get("kind") == "scan_meta"
            )

            with mock.patch.object(
                MODULE,
                "MAX_FETCH_ROLLOUT_BYTES",
                rollout.stat().st_size - 1,
            ), self.assertRaisesRegex(ValueError, "rollout too large"):
                MODULE._fetch_local_rollout(codex_root, PurePosixPath(root_ref))

        self.assertEqual(rc, 0, error_output.getvalue())
        self.assertEqual(scan_meta["source_sha256"], expected_hash)
        self.assertEqual(
            scan_meta["source_identity_proof"],
            MODULE.REMOTE_GENERATED_SUMMARY_SOURCE_IDENTITY_PROOF,
        )
        self.assertEqual(
            scan_meta["coverage_proof"],
            MODULE.REMOTE_GENERATED_SUMMARY_COVERAGE_PROOF,
        )
        self.assertEqual(
            scan_meta["scan_bytes"],
            MODULE.MAX_ROLLOUT_SUMMARY_SCAN_BYTES,
        )

    def test_embedded_summary_output_cap_emits_no_partial_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            codex_root = Path(temp_dir) / ".codex"
            write_rollout(codex_root)
            with mock.patch.object(
                MODULE,
                "MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_RECORD_BYTES",
                64,
            ), mock.patch.object(
                MODULE,
                "MAX_REMOTE_ROLLOUT_SUMMARY_SERIALIZED_BYTES",
                128,
            ):
                script = MODULE._remote_python_script(
                    {
                        "mode": "rollout-summary",
                        "rollout": ROLLOUT_REF,
                        "codex_root": str(codex_root),
                        "summary_keywords": [],
                        "summary_limit": 40,
                        "summary_scan_bytes": MODULE.MAX_ROLLOUT_SUMMARY_SCAN_BYTES,
                        "summary_tail_records": 8,
                        "summary_max_text_chars": 400,
                    }
                )
            result = subprocess.run(
                [sys.executable, "-"],
                input=script,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = MODULE._extract_framed_lines(
            result.stdout,
            begin_marker=MODULE.REMOTE_ROLLOUT_SUMMARY_BEGIN,
            end_marker=MODULE.REMOTE_ROLLOUT_SUMMARY_END,
            host="embedded",
            command="rollout-summary",
        )
        self.assertEqual(
            [json.loads(line) for line in payload],
            [{"ok": False, "error": MODULE.ROLLOUT_SUMMARY_OUTPUT_TOO_LARGE_ERROR}],
        )
        self.assertNotIn("proof-session", result.stdout)

    def test_session_meta_serialized_output_cap_rejects_oversized_row(self) -> None:
        oversized = "x" * MODULE.MAX_REMOTE_SESSION_META_SERIALIZED_ROW_BYTES
        with self.assertRaisesRegex(
            ValueError,
            MODULE.SESSION_META_OUTPUT_ROW_TOO_LARGE_ERROR,
        ):
            MODULE._validated_session_meta_output_item(
                date="2026/05/26",
                session_id="session",
                cwd=oversized,
                rollout=ROLLOUT_REF,
            )


if __name__ == "__main__":
    unittest.main()
