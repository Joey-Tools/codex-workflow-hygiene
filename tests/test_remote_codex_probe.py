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
from collections.abc import Callable
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


def candidate_mutating_stat(
    real_stat: Callable[..., os.stat_result],
    target_name: str,
    mutate: Callable[[], None],
    *,
    before_call: int | None = None,
    after_call: int | None = None,
) -> Callable[..., Any]:
    matching_calls = 0

    def mutating_stat(
        path: object,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal matching_calls
        matches_candidate = (
            path == target_name
            and dir_fd is not None
            and follow_symlinks is False
        )
        if matches_candidate:
            matching_calls += 1
            if matching_calls == before_call:
                mutate()
        result = real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if matches_candidate and matching_calls == after_call:
            mutate()
        return result

    return mutating_stat


def metadata_poisoned_scandir(
    real_scandir: Callable[..., Any],
    observed_names: list[str],
) -> Callable[..., Any]:
    class EntryProxy:
        def __init__(self, entry: Any) -> None:
            self.name = entry.name
            observed_names.append(self.name)

        def inode(self) -> int:
            raise AssertionError("session-meta must not read DirEntry.inode()")

        def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
            raise AssertionError("session-meta must not read DirEntry.stat()")

    class ScandirProxy:
        def __init__(self, iterator: Any) -> None:
            self._iterator = iterator

        def __enter__(self) -> Any:
            entries = self._iterator.__enter__()
            return (EntryProxy(entry) for entry in entries)

        def __exit__(self, *args: object) -> object:
            return self._iterator.__exit__(*args)

    def poisoned_scandir(path: object) -> Any:
        return ScandirProxy(real_scandir(path))

    return poisoned_scandir


class RemoteCodexProbeDescriptorTests(unittest.TestCase):
    def test_session_meta_binds_identity_with_descriptor_relative_stats(self) -> None:
        for scope in ("local", "embedded"):
            for mutation in (
                "delete_before_first_stat",
                "replace_before_first_stat",
                "delete_between_stats",
                "replace_between_stats",
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

                    mutating_stat = candidate_mutating_stat(
                        target_os.stat,
                        rollout.name,
                        mutate,
                        before_call=(
                            3 if mutation.endswith("before_first_stat") else None
                        ),
                        after_call=(
                            3 if mutation.endswith("between_stats") else None
                        ),
                    )
                    output = io.StringIO()
                    if scope == "local":
                        with mock.patch.object(
                            target_os,
                            "stat",
                            side_effect=mutating_stat,
                        ), self.assertRaises(
                            MODULE.SessionMetaRolloutError
                        ) as raised:
                            run_scan()
                        error = raised.exception.error
                        error_rollout = raised.exception.rollout
                    else:
                        with mock.patch.object(
                            target_os,
                            "stat",
                            side_effect=mutating_stat,
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

    def test_session_meta_filters_scope_before_abnormal_candidate_metadata(
        self,
    ) -> None:
        for scope in ("local", "embedded"):
            for layout in ("root", "flat_archive"):
                for in_scope in (False, True):
                    with self.subTest(
                        scope=scope,
                        layout=layout,
                        in_scope=in_scope,
                    ), tempfile.TemporaryDirectory() as temp_dir:
                        codex_root = Path(temp_dir) / ".codex"
                        write_rollout(codex_root)
                        date_text = "2026-05-26" if in_scope else "2026-05-25"
                        abnormal_name = (
                            f"rollout-{date_text}T09-00-00-abnormal.jsonl"
                        )
                        abnormal = (
                            codex_root / abnormal_name
                            if layout == "root"
                            else codex_root / "archived_sessions" / abnormal_name
                        )
                        abnormal.parent.mkdir(parents=True, exist_ok=True)
                        outside = Path(temp_dir) / "outside.jsonl"
                        outside.write_text("outside\n", encoding="utf-8")
                        abnormal.symlink_to(outside)

                        output = io.StringIO()
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

                        real_open = target_os.open
                        real_stat = target_os.stat
                        candidate_opened = False
                        candidate_statted = False

                        def tracking_open(
                            path: object,
                            flags: int,
                            mode: int = 0o777,
                            *,
                            dir_fd: int | None = None,
                        ) -> int:
                            nonlocal candidate_opened
                            if path == abnormal.name and dir_fd is not None:
                                candidate_opened = True
                            return real_open(path, flags, mode, dir_fd=dir_fd)

                        def tracking_stat(
                            path: object,
                            *,
                            dir_fd: int | None = None,
                            follow_symlinks: bool = True,
                        ) -> os.stat_result:
                            nonlocal candidate_statted
                            if (
                                path == abnormal.name
                                and dir_fd is not None
                                and follow_symlinks is False
                            ):
                                candidate_statted = True
                            return real_stat(
                                path,
                                dir_fd=dir_fd,
                                follow_symlinks=follow_symlinks,
                            )

                        with mock.patch.object(
                            target_os,
                            "open",
                            side_effect=tracking_open,
                        ), mock.patch.object(
                            target_os,
                            "stat",
                            side_effect=tracking_stat,
                        ), redirect_stdout(output):
                            if in_scope and scope == "local":
                                with self.assertRaises(
                                    MODULE.SessionMetaRolloutError
                                ) as raised:
                                    run_scan()
                                error = raised.exception.error
                            elif in_scope:
                                with self.assertRaises(SystemExit) as raised:
                                    run_scan()
                                self.assertEqual(raised.exception.code, 0)
                                error = next(
                                    json.loads(line)["error"]
                                    for line in output.getvalue().splitlines()[1:-1]
                                    if "error" in json.loads(line)
                                )
                            else:
                                scan = run_scan()

                        self.assertEqual(candidate_statted, in_scope)
                        self.assertFalse(candidate_opened)
                        if in_scope:
                            self.assertEqual(error, "rollout path is a symlink")
                        if scope == "local":
                            if not in_scope:
                                self.assertEqual(
                                    [row["session_id"] for row in scan.rows],
                                    ["trusted-session"],
                                )
                        else:
                            records = [
                                json.loads(line)
                                for line in output.getvalue().splitlines()[1:-1]
                            ]
                            if in_scope:
                                error_record = next(
                                    record for record in records if "error" in record
                                )
                                self.assertEqual(
                                    error_record["rollout"],
                                    abnormal.relative_to(codex_root).as_posix(),
                                )
                                self.assertEqual(
                                    error_record["error"],
                                    "rollout path is a symlink",
                                )
                            else:
                                self.assertEqual(
                                    [record["session_id"] for record in records],
                                    ["trusted-session"],
                                )
                                self.assertNotIn("outside", output.getvalue())

    def test_session_meta_scandir_uses_names_only_local_and_embedded(self) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root)
                observed_names: list[str] = []
                output = io.StringIO()

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
                            "session_meta_scan_bytes": (
                                MODULE.MAX_SESSION_META_SCAN_BYTES
                            ),
                        }
                    )
                    target_os = namespace["os"]

                    def run_scan() -> object:
                        return namespace["iter_session_meta"]()

                poisoned_scandir = metadata_poisoned_scandir(
                    target_os.scandir,
                    observed_names,
                )
                with mock.patch.object(
                    target_os,
                    "scandir",
                    side_effect=poisoned_scandir,
                ), redirect_stdout(output):
                    scan = run_scan()

                self.assertIn(rollout.name, observed_names)
                if scope == "local":
                    self.assertEqual(
                        [row["session_id"] for row in scan.rows],
                        ["trusted-session"],
                    )
                else:
                    records = [
                        json.loads(line)
                        for line in output.getvalue().splitlines()[1:-1]
                    ]
                    self.assertEqual(
                        [record["session_id"] for record in records],
                        ["trusted-session"],
                    )

    def test_active_append_between_inventory_and_consumption_is_accepted(self) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root)
                original_size = rollout.stat().st_size
                appended = False
                output = io.StringIO()

                if scope == "local":
                    real_capture = (
                        MODULE._capture_active_rollout_candidate_identity_from_parent_fd
                    )

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
                            "session_meta_scan_bytes": (
                                MODULE.MAX_SESSION_META_SCAN_BYTES
                            ),
                        }
                    )
                    real_capture = namespace[
                        "capture_active_rollout_candidate_identity_from_parent_fd"
                    ]

                    def run_scan() -> object:
                        return namespace["iter_session_meta"]()

                def append_before_capture(*args: object, **kwargs: object) -> object:
                    nonlocal appended
                    if not appended:
                        with rollout.open("ab") as handle:
                            handle.write(b"{}\n")
                        appended = True
                    return real_capture(*args, **kwargs)

                if scope == "local":
                    patcher = mock.patch.object(
                        MODULE,
                        "_capture_active_rollout_candidate_identity_from_parent_fd",
                        side_effect=append_before_capture,
                    )
                else:
                    patcher = mock.patch.dict(
                        namespace,
                        {
                            "capture_active_rollout_candidate_identity_from_parent_fd": (
                                append_before_capture
                            )
                        },
                    )

                with patcher, redirect_stdout(output):
                    scan = run_scan()

                if scope == "local":
                    session_ids = [row["session_id"] for row in scan.rows]
                else:
                    session_ids = [
                        json.loads(line)["session_id"]
                        for line in output.getvalue().splitlines()[1:-1]
                    ]
                self.assertTrue(appended)
                self.assertGreater(rollout.stat().st_size, original_size)
                self.assertEqual(session_ids, ["trusted-session"])

    def test_active_replacement_between_inventory_and_consumption_is_rejected(
        self,
    ) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root)
                replacement = rollout.with_suffix(".replacement")
                replacement.write_text(
                    json.dumps(session_meta_row("replacement-session")) + "\n",
                    encoding="utf-8",
                )
                replaced = False
                output = io.StringIO()

                if scope == "local":
                    real_capture = (
                        MODULE._capture_active_rollout_candidate_identity_from_parent_fd
                    )

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
                            "session_meta_scan_bytes": (
                                MODULE.MAX_SESSION_META_SCAN_BYTES
                            ),
                        }
                    )
                    real_capture = namespace[
                        "capture_active_rollout_candidate_identity_from_parent_fd"
                    ]

                    def run_scan() -> object:
                        return namespace["iter_session_meta"]()

                def replace_before_capture(
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    nonlocal replaced
                    if not replaced:
                        os.replace(replacement, rollout)
                        replaced = True
                    return real_capture(*args, **kwargs)

                if scope == "local":
                    patcher = mock.patch.object(
                        MODULE,
                        "_capture_active_rollout_candidate_identity_from_parent_fd",
                        side_effect=replace_before_capture,
                    )
                else:
                    patcher = mock.patch.dict(
                        namespace,
                        {
                            "capture_active_rollout_candidate_identity_from_parent_fd": (
                                replace_before_capture
                            )
                        },
                    )

                with patcher, redirect_stdout(output):
                    if scope == "local":
                        with self.assertRaises(
                            MODULE.SessionMetaRolloutError
                        ) as raised:
                            run_scan()
                        error = raised.exception.error
                    else:
                        with self.assertRaises(SystemExit) as raised:
                            run_scan()
                        self.assertEqual(raised.exception.code, 0)
                        error = json.loads(output.getvalue().splitlines()[1])["error"]

                self.assertTrue(replaced)
                self.assertIn("identity changed after enumeration", error)
                self.assertNotIn("replacement-session", output.getvalue())

    def test_archive_replacement_between_inventory_and_consumption_is_rejected(
        self,
    ) -> None:
        rollout_ref = (
            "archived_sessions/2026/05/26/"
            "rollout-2026-05-26T10-00-00-archive.jsonl"
        )
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root, rollout_ref=rollout_ref)
                replacement = rollout.with_suffix(".replacement")
                replacement.write_text(
                    json.dumps(session_meta_row("replacement-session")) + "\n",
                    encoding="utf-8",
                )
                replaced = False
                output = io.StringIO()

                if scope == "local":
                    real_capture = (
                        MODULE._capture_rollout_candidate_identity_from_parent_fd
                    )

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
                            "session_meta_scan_bytes": (
                                MODULE.MAX_SESSION_META_SCAN_BYTES
                            ),
                        }
                    )
                    real_capture = namespace[
                        "capture_rollout_candidate_identity_from_parent_fd"
                    ]

                    def run_scan() -> object:
                        return namespace["iter_session_meta"]()

                def replace_before_capture(
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    nonlocal replaced
                    if not replaced:
                        os.replace(replacement, rollout)
                        replaced = True
                    return real_capture(*args, **kwargs)

                if scope == "local":
                    patcher = mock.patch.object(
                        MODULE,
                        "_capture_rollout_candidate_identity_from_parent_fd",
                        side_effect=replace_before_capture,
                    )
                else:
                    patcher = mock.patch.dict(
                        namespace,
                        {
                            "capture_rollout_candidate_identity_from_parent_fd": (
                                replace_before_capture
                            )
                        },
                    )

                with patcher, redirect_stdout(output):
                    if scope == "local":
                        with self.assertRaises(
                            MODULE.SessionMetaRolloutError
                        ) as raised:
                            run_scan()
                        error = raised.exception.error
                    else:
                        with self.assertRaises(SystemExit) as raised:
                            run_scan()
                        self.assertEqual(raised.exception.code, 0)
                        error = json.loads(output.getvalue().splitlines()[1])["error"]

                self.assertTrue(replaced)
                self.assertIn("identity changed after enumeration", error)
                self.assertNotIn("replacement-session", output.getvalue())

    def test_active_capture_stage_growth_requires_unchanged_prefix(self) -> None:
        for scope in ("local", "embedded"):
            for mutation in ("append", "rewrite_grow"):
                with self.subTest(
                    scope=scope,
                    mutation=mutation,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    codex_root = Path(temp_dir) / ".codex"
                    rollout = write_rollout(codex_root)
                    original = rollout.read_bytes()
                    mutated = False
                    output = io.StringIO()

                    def mutate() -> None:
                        nonlocal mutated
                        if mutated:
                            return
                        mutated = True
                        if mutation == "append":
                            with rollout.open("ab") as handle:
                                handle.write(b"{}\n")
                        else:
                            with rollout.open("r+b") as handle:
                                handle.write(b" " + original[1:] + b"{}\n")

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
                                "session_meta_scan_bytes": (
                                    MODULE.MAX_SESSION_META_SCAN_BYTES
                                ),
                            }
                        )
                        target_os = namespace["os"]

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    mutating_stat = candidate_mutating_stat(
                        target_os.stat,
                        rollout.name,
                        mutate,
                        before_call=3,
                    )
                    with mock.patch.object(
                        target_os,
                        "stat",
                        side_effect=mutating_stat,
                    ), redirect_stdout(output):
                        if mutation == "append":
                            scan = run_scan()
                        elif scope == "local":
                            with self.assertRaises(
                                MODULE.SessionMetaRolloutError
                            ) as raised:
                                run_scan()
                            error = raised.exception.error
                        else:
                            with self.assertRaises(SystemExit) as raised:
                                run_scan()
                            self.assertEqual(raised.exception.code, 0)
                            error = json.loads(
                                output.getvalue().splitlines()[1]
                            )["error"]

                    self.assertTrue(mutated)
                    if mutation == "append":
                        if scope == "local":
                            session_ids = [row["session_id"] for row in scan.rows]
                        else:
                            session_ids = [
                                json.loads(line)["session_id"]
                                for line in output.getvalue().splitlines()[1:-1]
                            ]
                        self.assertEqual(session_ids, ["trusted-session"])
                    else:
                        self.assertIn("identity changed", error)

    def test_active_session_meta_enforces_append_only_policy(self) -> None:
        for scope in ("local", "embedded"):
            for layout in ("sessions", "root"):
                for phase in ("post_initial_checkpoint", "post_read"):
                    for mutation in (
                        "append",
                        "truncate",
                        "rewrite",
                        "rewrite_grow",
                    ):
                        with self.subTest(
                            scope=scope,
                            layout=layout,
                            phase=phase,
                            mutation=mutation,
                        ), tempfile.TemporaryDirectory() as temp_dir:
                            rollout_ref = (
                                ROLLOUT_REF
                                if layout == "sessions"
                                else "rollout-2026-05-26T10-00-00-root.jsonl"
                            )
                            codex_root = Path(temp_dir) / ".codex"
                            rollout = write_rollout(
                                codex_root,
                                rollout_ref=rollout_ref,
                            )
                            original_stat = rollout.stat()
                            mutated = False

                            def mutate() -> None:
                                nonlocal mutated
                                if mutated:
                                    return
                                mutated = True
                                if mutation == "append":
                                    with rollout.open("ab") as handle:
                                        handle.write(b"{}\n")
                                elif mutation == "truncate":
                                    with rollout.open("r+b") as handle:
                                        handle.truncate(
                                            max(1, original_stat.st_size // 2)
                                        )
                                elif mutation == "rewrite":
                                    data = rollout.read_bytes()
                                    with rollout.open("r+b") as handle:
                                        handle.write(b" " + data[1:])
                                    os.utime(
                                        rollout,
                                        ns=(
                                            original_stat.st_atime_ns,
                                            original_stat.st_mtime_ns
                                            + 1_000_000_000,
                                        ),
                                    )
                                else:
                                    data = rollout.read_bytes()
                                    with rollout.open("r+b") as handle:
                                        handle.write(b" " + data[1:] + b"{}\n")

                            if scope == "local":
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
                                def run_scan() -> object:
                                    return namespace["iter_session_meta"]()

                            if phase == "post_initial_checkpoint":
                                if scope == "local":
                                    real_capture = (
                                        MODULE._capture_active_rollout_candidate_identity_from_parent_fd
                                    )

                                    def capture_then_mutate(
                                        *args: object,
                                        **kwargs: object,
                                    ) -> object:
                                        proof = real_capture(*args, **kwargs)
                                        mutate()
                                        return proof

                                    patcher = mock.patch.object(
                                        MODULE,
                                        "_capture_active_rollout_candidate_identity_from_parent_fd",
                                        side_effect=capture_then_mutate,
                                    )
                                else:
                                    real_capture = namespace[
                                        "capture_active_rollout_candidate_identity_from_parent_fd"
                                    ]

                                    def capture_then_mutate(
                                        *args: object,
                                        **kwargs: object,
                                    ) -> object:
                                        proof = real_capture(*args, **kwargs)
                                        mutate()
                                        return proof

                                    patcher = mock.patch.dict(
                                        namespace,
                                        {
                                            "capture_active_rollout_candidate_identity_from_parent_fd": (
                                                capture_then_mutate
                                            )
                                        },
                                    )
                            elif scope == "local":
                                real_lines = MODULE._bounded_session_meta_lines

                                def mutating_lines(handle: object, max_bytes: int):
                                    for line in real_lines(handle, max_bytes):
                                        mutate()
                                        yield line

                                patcher = mock.patch.object(
                                    MODULE,
                                    "_bounded_session_meta_lines",
                                    side_effect=mutating_lines,
                                )
                            else:
                                real_lines = namespace["bounded_session_meta_lines"]

                                def mutating_lines(handle: object, max_bytes: int):
                                    for line in real_lines(handle, max_bytes):
                                        mutate()
                                        yield line

                                patcher = mock.patch.dict(
                                    namespace,
                                    {"bounded_session_meta_lines": mutating_lines},
                                )

                            output = io.StringIO()
                            with patcher, redirect_stdout(output):
                                if mutation == "append":
                                    scan = run_scan()
                                    if scope == "local":
                                        session_ids = [
                                            row["session_id"] for row in scan.rows
                                        ]
                                    else:
                                        session_ids = [
                                            json.loads(line)["session_id"]
                                            for line in output.getvalue().splitlines()[
                                                1:-1
                                            ]
                                        ]
                                elif scope == "local":
                                    with self.assertRaises(
                                        MODULE.SessionMetaRolloutError
                                    ) as raised:
                                        run_scan()
                                    error = raised.exception.error
                                else:
                                    with self.assertRaises(SystemExit) as raised:
                                        run_scan()
                                    self.assertEqual(raised.exception.code, 0)
                                    error = json.loads(
                                        output.getvalue().splitlines()[1]
                                    )["error"]

                            final_stat = rollout.stat()
                            self.assertTrue(mutated)
                            self.assertEqual(
                                (final_stat.st_dev, final_stat.st_ino),
                                (original_stat.st_dev, original_stat.st_ino),
                            )
                            if mutation in ("append", "rewrite_grow"):
                                self.assertGreater(
                                    final_stat.st_size,
                                    original_stat.st_size,
                                )
                            if mutation == "append":
                                self.assertEqual(
                                    session_ids,
                                    ["trusted-session"],
                                )
                            else:
                                self.assertIn("identity changed", error)

    def test_active_append_after_verified_checkpoint_uses_aligned_snapshot(
        self,
    ) -> None:
        for scope in ("local", "embedded"):
            for layout in ("sessions", "root"):
                with self.subTest(
                    scope=scope,
                    layout=layout,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    rollout_ref = (
                        ROLLOUT_REF
                        if layout == "sessions"
                        else "rollout-2026-05-26T10-00-00-root.jsonl"
                    )
                    codex_root = Path(temp_dir) / ".codex"
                    rollout = write_rollout(codex_root, rollout_ref=rollout_ref)
                    original_size = rollout.stat().st_size
                    read_calls = 0
                    mutated = False

                    if scope == "local":
                        real_read = MODULE._read_rollout_prefix_proof

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
                                "session_meta_scan_bytes": (
                                    MODULE.MAX_SESSION_META_SCAN_BYTES
                                ),
                            }
                        )
                        real_read = namespace["read_rollout_prefix_proof"]

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    def append_after_verified_read(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        nonlocal read_calls, mutated
                        result = real_read(*args, **kwargs)
                        read_calls += 1
                        if read_calls == 5:
                            with rollout.open("ab") as handle:
                                handle.write(b"{}\n")
                            mutated = True
                        return result

                    if scope == "local":
                        patcher = mock.patch.object(
                            MODULE,
                            "_read_rollout_prefix_proof",
                            side_effect=append_after_verified_read,
                        )
                    else:
                        patcher = mock.patch.dict(
                            namespace,
                            {
                                "read_rollout_prefix_proof": (
                                    append_after_verified_read
                                )
                            },
                        )

                    output = io.StringIO()
                    with patcher, redirect_stdout(output):
                        scan = run_scan()

                    if scope == "local":
                        session_ids = [row["session_id"] for row in scan.rows]
                    else:
                        session_ids = [
                            json.loads(line)["session_id"]
                            for line in output.getvalue().splitlines()[1:-1]
                        ]
                    self.assertTrue(mutated)
                    self.assertGreaterEqual(read_calls, 7)
                    self.assertGreater(rollout.stat().st_size, original_size)
                    self.assertEqual(session_ids, ["trusted-session"])

    def test_late_append_high_water_rejects_rollback_local_and_embedded(
        self,
    ) -> None:
        for scope in ("local", "embedded"):
            for layout in ("sessions", "root"):
                with self.subTest(
                    scope=scope,
                    layout=layout,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    rollout_ref = (
                        ROLLOUT_REF
                        if layout == "sessions"
                        else "rollout-2026-05-26T10-00-00-root.jsonl"
                    )
                    codex_root = Path(temp_dir) / ".codex"
                    rollout = write_rollout(codex_root, rollout_ref=rollout_ref)
                    original_size = rollout.stat().st_size
                    read_calls = 0
                    appended = False
                    rolled_back = False

                    if scope == "local":
                        real_read = MODULE._read_rollout_prefix_proof
                        real_lines = MODULE._bounded_session_meta_lines

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
                                "session_meta_scan_bytes": (
                                    MODULE.MAX_SESSION_META_SCAN_BYTES
                                ),
                            }
                        )
                        real_read = namespace["read_rollout_prefix_proof"]
                        real_lines = namespace["bounded_session_meta_lines"]

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    def append_after_verified_read(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        nonlocal read_calls, appended
                        result = real_read(*args, **kwargs)
                        read_calls += 1
                        if read_calls == 5:
                            with rollout.open("ab") as handle:
                                handle.write(b"{}\n" * 20)
                            appended = True
                        return result

                    def rollback_after_snapshot_line(
                        handle: object,
                        max_bytes: int,
                    ):
                        nonlocal rolled_back
                        for line in real_lines(handle, max_bytes):
                            if not rolled_back:
                                with rollout.open("r+b") as rollout_handle:
                                    rollout_handle.truncate(original_size + 1)
                                rolled_back = True
                            yield line

                    if scope == "local":
                        read_patcher = mock.patch.object(
                            MODULE,
                            "_read_rollout_prefix_proof",
                            side_effect=append_after_verified_read,
                        )
                        lines_patcher = mock.patch.object(
                            MODULE,
                            "_bounded_session_meta_lines",
                            side_effect=rollback_after_snapshot_line,
                        )
                    else:
                        read_patcher = mock.patch.dict(
                            namespace,
                            {
                                "read_rollout_prefix_proof": (
                                    append_after_verified_read
                                )
                            },
                        )
                        lines_patcher = mock.patch.dict(
                            namespace,
                            {
                                "bounded_session_meta_lines": (
                                    rollback_after_snapshot_line
                                )
                            },
                        )

                    output = io.StringIO()
                    with read_patcher, lines_patcher, redirect_stdout(output):
                        if scope == "local":
                            with self.assertRaises(
                                MODULE.SessionMetaRolloutError
                            ) as raised:
                                run_scan()
                            error = raised.exception.error
                        else:
                            with self.assertRaises(SystemExit) as raised:
                                run_scan()
                            self.assertEqual(raised.exception.code, 0)
                            error = json.loads(
                                output.getvalue().splitlines()[1]
                            )["error"]

                    self.assertTrue(appended)
                    self.assertTrue(rolled_back)
                    self.assertEqual(read_calls, 7)
                    self.assertEqual(rollout.stat().st_size, original_size + 1)
                    self.assertIn(
                        "rollout identity changed after session-meta scan",
                        error,
                    )

    def test_active_prefix_proof_capture_accepts_append_growth(self) -> None:
        for scope in ("local", "embedded"):
            for layout in ("sessions", "root"):
                with self.subTest(
                    scope=scope,
                    layout=layout,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    rollout_ref = (
                        ROLLOUT_REF
                        if layout == "sessions"
                        else "rollout-2026-05-26T10-00-00-root.jsonl"
                    )
                    codex_root = Path(temp_dir) / ".codex"
                    rollout = write_rollout(codex_root, rollout_ref=rollout_ref)
                    original_stat = rollout.stat()
                    mutated = False

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
                                "session_meta_scan_bytes": (
                                    MODULE.MAX_SESSION_META_SCAN_BYTES
                                ),
                            }
                        )
                        target_os = namespace["os"]

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    real_pread = target_os.pread

                    def grow_during_pread(
                        fd: int,
                        length: int,
                        offset: int,
                    ) -> bytes:
                        nonlocal mutated
                        data = real_pread(fd, length, offset)
                        if not mutated:
                            mutated = True
                            with rollout.open("ab") as handle:
                                handle.write(b"{}\n")
                        return data

                    output = io.StringIO()
                    with mock.patch.object(
                        target_os,
                        "pread",
                        side_effect=grow_during_pread,
                    ), redirect_stdout(output):
                        scan = run_scan()

                    if scope == "local":
                        session_ids = [row["session_id"] for row in scan.rows]
                    else:
                        session_ids = [
                            json.loads(line)["session_id"]
                            for line in output.getvalue().splitlines()[1:-1]
                        ]

                    final_stat = rollout.stat()
                    self.assertTrue(mutated)
                    self.assertEqual(
                        (final_stat.st_dev, final_stat.st_ino),
                        (original_stat.st_dev, original_stat.st_ino),
                    )
                    self.assertGreater(final_stat.st_size, original_stat.st_size)
                    self.assertEqual(session_ids, ["trusted-session"])

    def test_active_session_meta_parses_only_verified_snapshot(self) -> None:
        for scope in ("local", "embedded"):
            for layout in ("sessions", "root"):
                with self.subTest(
                    scope=scope,
                    layout=layout,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    rollout_ref = (
                        ROLLOUT_REF
                        if layout == "sessions"
                        else "rollout-2026-05-26T10-00-00-root.jsonl"
                    )
                    codex_root = Path(temp_dir) / ".codex"
                    rollout = write_rollout(codex_root, rollout_ref=rollout_ref)
                    original = rollout.read_bytes()
                    forged = (
                        json.dumps(
                            session_meta_row("forged--session"),
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode()
                    self.assertEqual(len(forged), len(original))
                    mutated = False
                    restored = False

                    if scope == "local":
                        real_lines = MODULE._bounded_session_meta_lines

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
                                "session_meta_scan_bytes": (
                                    MODULE.MAX_SESSION_META_SCAN_BYTES
                                ),
                            }
                        )
                        real_lines = namespace["bounded_session_meta_lines"]

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    def transient_lines(handle: object, max_bytes: int):
                        nonlocal mutated, restored
                        with rollout.open("r+b") as rollout_handle:
                            rollout_handle.write(forged)
                            rollout_handle.truncate(len(forged))
                        mutated = True
                        lines = iter(real_lines(handle, max_bytes))
                        first_line = next(lines)
                        with rollout.open("r+b") as rollout_handle:
                            rollout_handle.write(original)
                            rollout_handle.truncate(len(original))
                        with rollout.open("ab") as rollout_handle:
                            rollout_handle.write(b"{}\n")
                        restored = True
                        yield first_line
                        yield from lines

                    if scope == "local":
                        patcher = mock.patch.object(
                            MODULE,
                            "_bounded_session_meta_lines",
                            side_effect=transient_lines,
                        )
                    else:
                        patcher = mock.patch.dict(
                            namespace,
                            {"bounded_session_meta_lines": transient_lines},
                        )

                    output = io.StringIO()
                    with patcher, redirect_stdout(output):
                        scan = run_scan()
                    if scope == "local":
                        session_ids = [row["session_id"] for row in scan.rows]
                    else:
                        session_ids = [
                            json.loads(line)["session_id"]
                            for line in output.getvalue().splitlines()[1:-1]
                        ]

                    self.assertTrue(mutated)
                    self.assertTrue(restored)
                    self.assertEqual(session_ids, ["trusted-session"])
                    self.assertNotIn("forged--session", output.getvalue())
                    self.assertGreater(rollout.stat().st_size, len(original))

    def test_active_missing_meta_refreshes_once_or_reports_repeated_growth(
        self,
    ) -> None:
        for scope in ("local", "embedded"):
            for layout in ("sessions", "root"):
                for scenario in ("late_meta", "repeated_growth"):
                    with self.subTest(
                        scope=scope,
                        layout=layout,
                        scenario=scenario,
                    ), tempfile.TemporaryDirectory() as temp_dir:
                        rollout_ref = (
                            ROLLOUT_REF
                            if layout == "sessions"
                            else "rollout-2026-05-26T10-00-00-root.jsonl"
                        )
                        codex_root = Path(temp_dir) / ".codex"
                        rollout = write_rollout(
                            codex_root,
                            rollout_ref=rollout_ref,
                        )
                        rollout.write_bytes(b"{}\n")
                        late_meta = (
                            json.dumps(
                                session_meta_row("late-session"),
                                separators=(",", ":"),
                            )
                            + "\n"
                        ).encode()
                        scan_calls = 0
                        append_calls = 0
                        output = io.StringIO()

                        if scope == "local":
                            real_lines = MODULE._bounded_session_meta_lines

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
                                    "session_meta_scan_bytes": (
                                        MODULE.MAX_SESSION_META_SCAN_BYTES
                                    ),
                                }
                            )
                            real_lines = namespace["bounded_session_meta_lines"]

                            def run_scan() -> object:
                                return namespace["iter_session_meta"]()

                        def append_after_snapshot(
                            handle: object,
                            max_bytes: int,
                        ):
                            nonlocal scan_calls, append_calls
                            scan_calls += 1
                            current_scan = scan_calls
                            yield from real_lines(handle, max_bytes)
                            if current_scan == 1:
                                data = (
                                    late_meta
                                    if scenario == "late_meta"
                                    else b"{}\n"
                                )
                            elif (
                                current_scan == 2
                                and scenario == "repeated_growth"
                            ):
                                data = b"{}\n"
                            else:
                                return
                            with rollout.open("ab") as rollout_handle:
                                rollout_handle.write(data)
                            append_calls += 1

                        if scope == "local":
                            patcher = mock.patch.object(
                                MODULE,
                                "_bounded_session_meta_lines",
                                side_effect=append_after_snapshot,
                            )
                        else:
                            patcher = mock.patch.dict(
                                namespace,
                                {
                                    "bounded_session_meta_lines": (
                                        append_after_snapshot
                                    )
                                },
                            )

                        with patcher, redirect_stdout(output):
                            if scenario == "late_meta":
                                scan = run_scan()
                            elif scope == "local":
                                with self.assertRaises(
                                    MODULE.SessionMetaRolloutError
                                ) as raised:
                                    run_scan()
                                error = raised.exception.error
                            else:
                                with self.assertRaises(SystemExit) as raised:
                                    run_scan()
                                self.assertEqual(raised.exception.code, 0)
                                error = next(
                                    json.loads(line)["error"]
                                    for line in output.getvalue().splitlines()[1:-1]
                                    if "error" in json.loads(line)
                                )

                        self.assertEqual(scan_calls, 2)
                        if scenario == "late_meta":
                            self.assertEqual(append_calls, 1)
                            if scope == "local":
                                session_ids = [
                                    row["session_id"] for row in scan.rows
                                ]
                            else:
                                session_ids = [
                                    json.loads(line)["session_id"]
                                    for line in output.getvalue().splitlines()[1:-1]
                                ]
                            self.assertEqual(session_ids, ["late-session"])
                        else:
                            self.assertEqual(append_calls, 2)
                            self.assertEqual(
                                error,
                                "rollout identity changed after session-meta scan",
                            )

    def test_active_missing_meta_rejects_unaligned_checkpoint_high_water(
        self,
    ) -> None:
        for scope in ("local", "embedded"):
            for layout in ("sessions", "root"):
                with self.subTest(
                    scope=scope,
                    layout=layout,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    rollout_ref = (
                        ROLLOUT_REF
                        if layout == "sessions"
                        else "rollout-2026-05-26T10-00-00-root.jsonl"
                    )
                    codex_root = Path(temp_dir) / ".codex"
                    rollout = write_rollout(
                        codex_root,
                        rollout_ref=rollout_ref,
                    )
                    rollout.write_bytes(b"{}\n")
                    late_meta = (
                        json.dumps(
                            session_meta_row("late-unaligned-session"),
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode()
                    appended = False
                    output = io.StringIO()

                    if scope == "local":
                        real_checkpoint = (
                            MODULE._assert_append_only_rollout_checkpoint
                        )

                        def checkpoint_with_unaligned_high_water(
                            fd: int,
                            parent_fd: int,
                            name: str,
                            expected: object,
                            prefix_proof: object,
                            *,
                            phase: str,
                        ) -> object:
                            nonlocal appended
                            result = real_checkpoint(
                                fd,
                                parent_fd,
                                name,
                                expected,
                                prefix_proof,
                                phase=phase,
                            )
                            if phase == "after session-meta scan" and not appended:
                                with rollout.open("ab") as handle:
                                    handle.write(late_meta)
                                appended = True
                                return (
                                    MODULE._rollout_identity_from_stat(
                                        os.fstat(fd)
                                    ),
                                    *result[1:],
                                )
                            return result

                        patcher = mock.patch.object(
                            MODULE,
                            "_assert_append_only_rollout_checkpoint",
                            side_effect=checkpoint_with_unaligned_high_water,
                        )

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
                                "session_meta_scan_bytes": (
                                    MODULE.MAX_SESSION_META_SCAN_BYTES
                                ),
                            }
                        )
                        real_checkpoint = namespace[
                            "assert_append_only_rollout_checkpoint"
                        ]

                        def checkpoint_with_unaligned_high_water(
                            fd: int,
                            parent_fd: int,
                            name: str,
                            expected: object,
                            prefix_proof: object,
                            phase: str,
                        ) -> object:
                            nonlocal appended
                            result = real_checkpoint(
                                fd,
                                parent_fd,
                                name,
                                expected,
                                prefix_proof,
                                phase,
                            )
                            if phase == "after session-meta scan" and not appended:
                                with rollout.open("ab") as handle:
                                    handle.write(late_meta)
                                appended = True
                                return (
                                    namespace["rollout_identity_from_stat"](
                                        os.fstat(fd)
                                    ),
                                    *result[1:],
                                )
                            return result

                        patcher = mock.patch.dict(
                            namespace,
                            {
                                "assert_append_only_rollout_checkpoint": (
                                    checkpoint_with_unaligned_high_water
                                )
                            },
                        )

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    with patcher, redirect_stdout(output):
                        if scope == "local":
                            with self.assertRaises(
                                MODULE.SessionMetaRolloutError
                            ) as raised:
                                run_scan()
                            error = raised.exception.error
                        else:
                            with self.assertRaises(SystemExit) as raised:
                                run_scan()
                            self.assertEqual(raised.exception.code, 0)
                            error = next(
                                json.loads(line)["error"]
                                for line in output.getvalue().splitlines()[1:-1]
                                if "error" in json.loads(line)
                            )

                    self.assertTrue(appended)
                    self.assertEqual(
                        error,
                        "rollout identity changed after session-meta scan",
                    )

    def test_active_prefix_proof_candidate_limit_bounds_capture_io(self) -> None:
        for scope in ("local", "embedded"):
            for scenario in ("valid", "no_meta"):
                with self.subTest(
                    scope=scope,
                    scenario=scenario,
                ), tempfile.TemporaryDirectory() as temp_dir:
                    codex_root = Path(temp_dir) / ".codex"
                    rollout_refs = [
                        (
                            "sessions/2026/05/26/"
                            f"rollout-2026-05-26T10-00-0{index}-candidate.jsonl"
                        )
                        for index in range(2)
                    ]
                    rollout_refs.append(
                        "rollout-2026-05-26T10-00-02-root-candidate.jsonl"
                    )
                    rollouts = [
                        write_rollout(codex_root, rollout_ref=rollout_ref)
                        for rollout_ref in rollout_refs
                    ]
                    if scenario == "no_meta":
                        for rollout in rollouts:
                            rollout.write_bytes(b"{}\n")
                    candidate_size = rollouts[0].stat().st_size
                    capture_names: list[str] = []
                    pread_requests: list[int] = []
                    pread_bytes: list[int] = []

                    if scope == "local":
                        target_os = MODULE.os
                        real_capture = (
                            MODULE._capture_active_rollout_candidate_identity_from_parent_fd
                        )

                        def run_scan() -> object:
                            return MODULE._scan_session_meta_records(
                                codex_root=codex_root,
                                dates=[dt.date(2026, 5, 26)],
                                limit=1,
                                host="local",
                            )

                    else:
                        namespace = embedded_probe_namespace(
                            {
                                "mode": "session-meta",
                                "dates": ["2026/05/26"],
                                "limit": 1,
                                "codex_root": str(codex_root),
                                "session_meta_scan_bytes": (
                                    MODULE.MAX_SESSION_META_SCAN_BYTES
                                ),
                            }
                        )
                        target_os = namespace["os"]
                        real_capture = namespace[
                            "capture_active_rollout_candidate_identity_from_parent_fd"
                        ]

                        def run_scan() -> object:
                            return namespace["iter_session_meta"]()

                    real_pread = target_os.pread

                    def tracking_capture(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        capture_names.append(str(args[1]))
                        return real_capture(*args, **kwargs)

                    def tracking_pread(
                        fd: int,
                        length: int,
                        offset: int,
                    ) -> bytes:
                        data = real_pread(fd, length, offset)
                        pread_requests.append(length)
                        pread_bytes.append(len(data))
                        return data

                    if scope == "local":
                        capture_patcher = mock.patch.object(
                            MODULE,
                            "_capture_active_rollout_candidate_identity_from_parent_fd",
                            side_effect=tracking_capture,
                        )
                    else:
                        capture_patcher = mock.patch.dict(
                            namespace,
                            {
                                "capture_active_rollout_candidate_identity_from_parent_fd": (
                                    tracking_capture
                                )
                            },
                        )

                    output = io.StringIO()
                    with capture_patcher, mock.patch.object(
                        target_os,
                        "pread",
                        side_effect=tracking_pread,
                    ), redirect_stdout(output):
                        scan = run_scan()

                    if scope == "local":
                        self.assertTrue(scan.truncated)
                        if scenario == "valid":
                            self.assertEqual(len(scan.rows), 1)
                        else:
                            self.assertEqual(scan.rows, [])
                    else:
                        records = [
                            json.loads(line)
                            for line in output.getvalue().splitlines()[1:-1]
                        ]
                        self.assertEqual(records[-1]["kind"], "truncation")
                        self.assertEqual(
                            records[-1]["reason"],
                            MODULE.SESSION_META_LIMIT_TRUNCATED_REASON,
                        )
                        if scenario == "valid":
                            self.assertEqual(records[0]["session_id"], "trusted-session")
                        else:
                            self.assertEqual(len(records), 1)
                    if scenario == "no_meta":
                        for rollout_ref in rollout_refs:
                            self.assertNotIn(rollout_ref, output.getvalue())

                    self.assertEqual(len(capture_names), 2)
                    self.assertEqual(len(set(capture_names)), 2)
                    self.assertTrue(
                        all(
                            request <= MODULE.SESSION_META_READ_CHUNK_BYTES
                            for request in pread_requests
                        )
                    )
                    self.assertLessEqual(len(pread_requests), 18)
                    self.assertLessEqual(sum(pread_bytes), 18 * candidate_size)

    def test_mixed_valid_and_no_meta_candidates_auto_split_local_and_embedded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            codex_root = Path(temp_dir) / ".codex"
            newest_ref = (
                "sessions/2026/05/26/"
                "rollout-2026-05-26T10-45-00-newest.jsonl"
            )
            no_meta_ref = (
                "sessions/2026/05/26/"
                "rollout-2026-05-26T10-30-00-no-meta.jsonl"
            )
            oldest_ref = (
                "sessions/2026/05/26/"
                "rollout-2026-05-26T10-15-00-oldest.jsonl"
            )
            write_rollout(
                codex_root,
                rollout_ref=newest_ref,
                session_id="newest-session",
                timestamp="2026-05-26T10:45:00Z",
            )
            no_meta = codex_root / no_meta_ref
            no_meta.parent.mkdir(parents=True, exist_ok=True)
            no_meta.write_text("{}\n", encoding="utf-8")
            write_rollout(
                codex_root,
                rollout_ref=oldest_ref,
                session_id="oldest-session",
                timestamp="2026-05-26T10:15:00Z",
            )

            for scope in ("local", "embedded"):
                with self.subTest(scope=scope):
                    alias = "local" if scope == "local" else "embedded-test"

                    def run_embedded(
                        _alias: str,
                        payload: dict[str, object],
                        *,
                        max_stdout_bytes: int,
                    ) -> subprocess.CompletedProcess[str]:
                        self.assertGreater(max_stdout_bytes, 0)
                        return subprocess.run(
                            [sys.executable, "-"],
                            input=MODULE._remote_python_script(payload),
                            text=True,
                            capture_output=True,
                            check=False,
                        )

                    host_patch = mock.patch.dict(
                        MODULE.HOSTS,
                        {
                            alias: {
                                "kind": scope,
                                "codex_root": str(codex_root),
                                "ssh_target": "unused",
                            }
                        },
                    )
                    local_root_patch = mock.patch.object(
                        MODULE,
                        "_local_codex_root",
                        return_value=codex_root,
                    )
                    runner_patch = mock.patch.object(
                        MODULE,
                        "_run_remote_python_bounded",
                        side_effect=run_embedded,
                    )
                    with host_patch, local_root_patch, runner_patch:
                        initial = MODULE._scan_host_session_meta(
                            alias,
                            dates=[dt.date(2026, 5, 26)],
                            limit=1,
                            rollout_start=None,
                            rollout_end=None,
                        )
                        split = MODULE._scan_host_session_meta_with_auto_split(
                            alias,
                            dates=[dt.date(2026, 5, 26)],
                            limit=1,
                        )

                    self.assertTrue(initial.truncated)
                    self.assertEqual(
                        [row["session_id"] for row in initial.rows],
                        ["newest-session"],
                    )
                    self.assertFalse(split.truncated)
                    self.assertEqual(
                        {row["session_id"] for row in split.rows},
                        {"newest-session", "oldest-session"},
                    )

    def test_append_only_policy_rejects_growth_followed_by_rollback(self) -> None:
        def regular_stat(size: int, timestamp_ns: int) -> argparse.Namespace:
            return argparse.Namespace(
                st_mode=MODULE.stat.S_IFREG | 0o600,
                st_size=size,
                st_dev=11,
                st_ino=22,
                st_mtime_ns=timestamp_ns,
                st_ctime_ns=timestamp_ns,
            )

        initial = regular_stat(100, 1)
        grown = regular_stat(200, 2)
        rolled_back = regular_stat(150, 3)

        for scope in ("local", "embedded"):
            with self.subTest(scope=scope, phase="during_open"):
                if scope == "local":
                    target_os = MODULE.os
                    candidate = MODULE._rollout_candidate_identity_from_stat(initial)
                    open_rollout = MODULE._open_pinned_regular_file_from_fd
                else:
                    namespace = embedded_probe_namespace(
                        {
                            "mode": "session-meta",
                            "dates": [],
                            "limit": 10,
                            "codex_root": "/tmp/unused",
                            "session_meta_scan_bytes": (
                                MODULE.MAX_SESSION_META_SCAN_BYTES
                            ),
                        }
                    )
                    target_os = namespace["os"]
                    candidate = namespace["rollout_candidate_identity_from_stat"](
                        initial
                    )
                    open_rollout = namespace["open_pinned_regular_file_from_fd"]

                with mock.patch.object(
                    target_os,
                    "stat",
                    return_value=grown,
                ), mock.patch.object(
                    target_os,
                    "open",
                    return_value=91,
                ), mock.patch.object(
                    target_os,
                    "fstat",
                    return_value=rolled_back,
                ), mock.patch.object(
                    target_os,
                    "close",
                ) as close_fd, self.assertRaisesRegex(
                    ValueError,
                    "identity changed during open",
                ):
                    open_rollout(
                        7,
                        "rollout.jsonl",
                        expected_identity=candidate,
                        allow_append=True,
                    )
                close_fd.assert_called_once_with(91)

            with self.subTest(scope=scope, phase="after_scan"):
                if scope == "local":
                    handle = MODULE._PinnedRolloutHandle.__new__(
                        MODULE._PinnedRolloutHandle
                    )
                    handle._handle = mock.Mock()
                    handle._handle.fileno.return_value = 92
                    handle._parent_fd = 7
                    handle._name = "rollout.jsonl"
                    expected = MODULE._rollout_identity_from_stat(initial)

                    def assert_append_only() -> None:
                        handle.assert_append_only_identity(
                            expected,
                            phase="after session-meta scan",
                        )

                else:
                    handle_type = namespace["PinnedRolloutHandle"]
                    handle = handle_type.__new__(handle_type)
                    handle.handle = mock.Mock()
                    handle.handle.fileno.return_value = 92
                    handle.parent_fd = 7
                    handle.name = "rollout.jsonl"
                    expected = namespace["rollout_identity_from_stat"](initial)

                    def assert_append_only() -> None:
                        handle.assert_append_only_identity(
                            expected,
                            "after session-meta scan",
                        )

                with mock.patch.object(
                    target_os,
                    "fstat",
                    return_value=grown,
                ), mock.patch.object(
                    target_os,
                    "stat",
                    return_value=rolled_back,
                ), self.assertRaisesRegex(
                    ValueError,
                    "identity changed after session-meta scan",
                ):
                    assert_append_only()

    def test_append_only_policy_preserves_open_to_scan_handoff(self) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                codex_root = Path(temp_dir) / ".codex"
                rollout = write_rollout(codex_root)
                initial_stat = rollout.stat()
                grew = False
                rolled_back = False

                def grow() -> None:
                    nonlocal grew
                    if grew:
                        return
                    grew = True
                    with rollout.open("ab") as handle:
                        handle.write(b"x" * 256)

                def rollback() -> None:
                    nonlocal rolled_back
                    if rolled_back:
                        return
                    rolled_back = True
                    with rollout.open("r+b") as handle:
                        handle.truncate(initial_stat.st_size + 32)

                output = io.StringIO()
                if scope == "local":
                    real_open = MODULE._open_pinned_rollout_text_from_parent_fd
                    real_capture = (
                        MODULE._capture_active_rollout_candidate_identity_from_parent_fd
                    )

                    def capture_then_grow(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        proof = real_capture(*args, **kwargs)
                        grow()
                        return proof

                    def open_then_rollback(*args: object, **kwargs: object) -> object:
                        handle = real_open(*args, **kwargs)
                        rollback()
                        return handle

                    open_patcher = mock.patch.object(
                        MODULE,
                        "_open_pinned_rollout_text_from_parent_fd",
                        side_effect=open_then_rollback,
                    )
                    capture_patcher = mock.patch.object(
                        MODULE,
                        "_capture_active_rollout_candidate_identity_from_parent_fd",
                        side_effect=capture_then_grow,
                    )

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
                            "session_meta_scan_bytes": (
                                MODULE.MAX_SESSION_META_SCAN_BYTES
                            ),
                        }
                    )
                    real_open = namespace["open_pinned_rollout_text_from_parent_fd"]
                    real_capture = namespace[
                        "capture_active_rollout_candidate_identity_from_parent_fd"
                    ]

                    def capture_then_grow(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        proof = real_capture(*args, **kwargs)
                        grow()
                        return proof

                    def open_then_rollback(*args: object, **kwargs: object) -> object:
                        handle = real_open(*args, **kwargs)
                        rollback()
                        return handle

                    open_patcher = mock.patch.dict(
                        namespace,
                        {"open_pinned_rollout_text_from_parent_fd": open_then_rollback},
                    )
                    capture_patcher = mock.patch.dict(
                        namespace,
                        {
                            "capture_active_rollout_candidate_identity_from_parent_fd": (
                                capture_then_grow
                            )
                        },
                    )

                    def run_scan() -> object:
                        return namespace["iter_session_meta"]()

                with capture_patcher, open_patcher, redirect_stdout(output):
                    if scope == "local":
                        with self.assertRaises(
                            MODULE.SessionMetaRolloutError
                        ) as raised:
                            run_scan()
                        error = raised.exception.error
                    else:
                        with self.assertRaises(SystemExit) as raised:
                            run_scan()
                        self.assertEqual(raised.exception.code, 0)
                        error = json.loads(output.getvalue().splitlines()[1])["error"]

                final_stat = rollout.stat()
                self.assertTrue(grew)
                self.assertTrue(rolled_back)
                self.assertGreater(final_stat.st_size, initial_stat.st_size)
                self.assertIn("identity changed before session-meta scan", error)

    def test_archived_session_meta_rejects_same_inode_mutations(self) -> None:
        layouts = {
            "dated": (
                "archived_sessions/2026/05/26/"
                "rollout-2026-05-26T10-00-00-dated.jsonl",
                "append",
            ),
            "flat": (
                "archived_sessions/rollout-2026-05-26T10-00-00-flat.jsonl",
                "truncate",
            ),
            "flat_undated": (
                "archived_sessions/rollout-flat-undated.jsonl",
                "rewrite",
            ),
        }
        for scope in ("local", "embedded"):
            for layout, (rollout_ref, mutation) in layouts.items():
                for phase in ("before_open", "post_read"):
                    with self.subTest(
                        scope=scope,
                        layout=layout,
                        phase=phase,
                        mutation=mutation,
                    ), tempfile.TemporaryDirectory() as temp_dir:
                        codex_root = Path(temp_dir) / ".codex"
                        rollout = write_rollout(
                            codex_root,
                            rollout_ref=rollout_ref,
                            session_id=f"archived-{layout}",
                        )
                        original_stat = rollout.stat()
                        mutated = False

                        def mutate() -> None:
                            nonlocal mutated
                            if mutated:
                                return
                            mutated = True
                            if mutation == "append":
                                with rollout.open("ab") as handle:
                                    handle.write(b"{}\n")
                            elif mutation == "truncate":
                                with rollout.open("r+b") as handle:
                                    handle.truncate(max(1, original_stat.st_size // 2))
                            else:
                                data = rollout.read_bytes()
                                with rollout.open("r+b") as handle:
                                    handle.write(b" " + data[1:])
                                os.utime(
                                    rollout,
                                    ns=(
                                        original_stat.st_atime_ns,
                                        original_stat.st_mtime_ns + 1_000_000_000,
                                    ),
                                )

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

                        if phase == "before_open":
                            mutating_stat = candidate_mutating_stat(
                                target_os.stat,
                                rollout.name,
                                mutate,
                                after_call=2,
                            )
                            patcher = mock.patch.object(
                                target_os,
                                "stat",
                                side_effect=mutating_stat,
                            )
                        elif scope == "local":
                            real_lines = MODULE._bounded_session_meta_lines

                            def mutating_lines(handle: object, max_bytes: int):
                                for line in real_lines(handle, max_bytes):
                                    mutate()
                                    yield line

                            patcher = mock.patch.object(
                                MODULE,
                                "_bounded_session_meta_lines",
                                side_effect=mutating_lines,
                            )
                        else:
                            real_lines = namespace["bounded_session_meta_lines"]

                            def mutating_lines(handle: object, max_bytes: int):
                                for line in real_lines(handle, max_bytes):
                                    mutate()
                                    yield line

                            patcher = mock.patch.dict(
                                namespace,
                                {"bounded_session_meta_lines": mutating_lines},
                            )

                        output = io.StringIO()
                        with patcher, redirect_stdout(output):
                            if scope == "local":
                                with self.assertRaises(
                                    MODULE.SessionMetaRolloutError
                                ) as raised:
                                    run_scan()
                                error = raised.exception.error
                            else:
                                with self.assertRaises(SystemExit) as raised:
                                    run_scan()
                                self.assertEqual(raised.exception.code, 0)
                                error = json.loads(
                                    output.getvalue().splitlines()[1]
                                )["error"]

                        final_stat = rollout.stat()
                        self.assertTrue(mutated)
                        self.assertEqual(
                            (final_stat.st_dev, final_stat.st_ino),
                            (original_stat.st_dev, original_stat.st_ino),
                        )
                        self.assertIn("identity changed", error)

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

    def test_root_swap_to_original_directory_symlink_fails_closed(self) -> None:
        for scope in ("local", "embedded"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                codex_root = base / ".codex"
                moved_root = base / ".codex-pinned"
                write_rollout(codex_root)
                if scope == "local":
                    target_os = MODULE.os

                    def open_root() -> int:
                        return MODULE._open_pinned_codex_root(codex_root)

                else:
                    namespace = embedded_probe_namespace(
                        {
                            "mode": "session-meta",
                            "dates": ["2026/05/26"],
                            "limit": 10,
                            "codex_root": str(codex_root),
                            "session_meta_scan_bytes": (
                                MODULE.MAX_SESSION_META_SCAN_BYTES
                            ),
                        }
                    )
                    target_os = namespace["os"]

                    def open_root() -> int:
                        return namespace["open_pinned_codex_root"]()

                real_open = target_os.open
                swapped = False

                def swap_before_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal swapped
                    if str(path) == str(codex_root) and dir_fd is None and not swapped:
                        os.replace(codex_root, moved_root)
                        codex_root.symlink_to(moved_root, target_is_directory=True)
                        swapped = True
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with mock.patch.object(
                    target_os,
                    "open",
                    side_effect=swap_before_open,
                ), self.assertRaises((OSError, ValueError)):
                    open_root()

                self.assertTrue(swapped)

    def test_root_swap_between_stat_and_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            codex_root = base / ".codex"
            external_root = base / "external-codex"
            write_rollout(codex_root)
            write_rollout(external_root, session_id="external-sentinel")
            expanded_root = codex_root.expanduser()
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
                if str(path) == str(expanded_root) and dir_fd is None and not swapped:
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
            write_rollout(codex_root)
            real_final_open = MODULE._open_pinned_regular_file_from_fd
            real_dup = MODULE.os.dup
            final_fd: int | None = None

            def tracking_final_open(
                *args: object,
                **kwargs: object,
            ) -> tuple[object, ...]:
                nonlocal final_fd
                result = real_final_open(*args, **kwargs)
                if kwargs.get("expected_identity") is not None:
                    final_fd = result[0]
                return result

            def fail_final_parent_dup(fd: int) -> int:
                if final_fd is not None:
                    raise OSError(24, "Too many open files", secret)
                return real_dup(fd)

            with mock.patch.object(
                MODULE,
                "_open_pinned_regular_file_from_fd",
                side_effect=tracking_final_open,
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
        self.assertIsNotNone(final_fd)
        with self.assertRaises(OSError):
            os.fstat(final_fd)

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
