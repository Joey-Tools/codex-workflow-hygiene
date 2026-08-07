from __future__ import annotations

import argparse
import base64
import copy
import io
import json
import os
import stat
import sys
import tempfile
import tracemalloc
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills/codex-session-retrospective/scripts"
sys.path.insert(0, str(SCRIPTS))
SCRIPT_PATH = SCRIPTS / "retrospective_v2/transport.py"
MIGRATION_PROBE_PATH = SCRIPTS / "remote_codex_probe.py"

from retrospective_v2 import transport as MODULE  # noqa: E402
from retrospective_v2.contracts import session_shards_resume_cursor  # noqa: E402


def write_rollout(codex_root: Path, data: bytes) -> str:
    relative = "sessions/2026/07/14/rollout-2026-07-14T10-00-00-shards.jsonl"
    path = codex_root / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    return relative


def command_args(
    rollout: str,
    *,
    host: str = "local",
    emit: str = "descriptors",
    byte_start: int = 0,
    byte_end: int | None = None,
    shard_bytes: int = 512,
    max_shards: int = 64,
    source_token: str | None = None,
    resume_cursor: str | None = None,
    record_processing_budget_bytes: int = (
        MODULE.DEFAULT_SESSION_RECORD_PROCESSING_BUDGET_BYTES
    ),
) -> argparse.Namespace:
    return argparse.Namespace(
        host=host,
        rollout=rollout,
        emit=emit,
        byte_start=byte_start,
        byte_end=byte_end,
        shard_bytes=shard_bytes,
        max_shards=max_shards,
        source_token=source_token,
        resume_cursor=resume_cursor,
        record_processing_budget_bytes=record_processing_budget_bytes,
    )


def run_local(
    codex_root: Path,
    args: argparse.Namespace,
) -> tuple[int, list[dict[str, object]], str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        mock.patch.object(MODULE, "_local_codex_root", return_value=codex_root),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        returncode = MODULE.cmd_session_shards(args)
    frames = [json.loads(line) for line in stdout.getvalue().splitlines()]
    return returncode, frames, stderr.getvalue()


def frame_of_kind(frames: list[dict[str, object]], kind: str) -> dict[str, object]:
    return next(frame for frame in frames if frame["kind"] == kind)


def reassemble_fragments(frames: list[dict[str, object]]) -> bytes:
    fragments = [frame for frame in frames if frame["kind"] == "record_fragment"]
    assert fragments
    fragments.sort(key=lambda frame: int(frame["fragment_index"]))
    return b"".join(
        base64.b64decode(str(frame["fragment_b64"]), validate=True)
        for frame in fragments
    )


class SessionShardsLocalTests(unittest.TestCase):
    def test_utf8_offsets_are_source_bytes_not_characters(self) -> None:
        first = (
            json.dumps(
                {"type": "message", "text": "你好"},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        second = b'{"type":"event","ok":true}\n'
        data = first + second
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(
                codex_root,
                command_args(rollout, shard_bytes=len(first)),
            )
            token = frame_of_kind(descriptors, "stream_meta")["source_token"]
            rc_records, records, records_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    shard_bytes=len(first),
                    source_token=str(token),
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual((rc_records, records_error), (0, ""))
        record_frames = [frame for frame in records if frame["kind"] == "record"]
        self.assertEqual(record_frames[0]["byte_end"], len(first))
        self.assertEqual(record_frames[1]["byte_start"], len(first))
        decoded = base64.b64decode(record_frames[0]["record_b64"])
        self.assertEqual(decoded, first)
        self.assertEqual(json.loads(decoded)["text"], "你好")

    def test_final_record_without_newline_is_complete(self) -> None:
        first = b'{"n":1}\n'
        second = b'{"n":2}'
        data = first + second
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(codex_root, command_args(rollout))
            token = frame_of_kind(descriptors, "stream_meta")["source_token"]
            rc_records, records, records_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    source_token=str(token),
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual((rc_records, records_error), (0, ""))
        terminal = frame_of_kind(records, "stream_end")
        self.assertTrue(terminal["complete"])
        self.assertEqual(terminal["byte_end"], len(data))
        self.assertEqual(terminal["record_end"], 2)

    def test_crlf_delimiter_survives_scan_chunk_boundary(self) -> None:
        prefix = b'{"text":"'
        suffix = b'"}'
        padding = (
            MODULE.SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES
            - len(prefix)
            - len(suffix)
            - 1
        )
        data = prefix + b"x" * padding + suffix + b"\r\n"
        self.assertEqual(
            data[MODULE.SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES - 1 :],
            b"\r\n",
        )
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(
                codex_root, command_args(rollout, shard_bytes=512)
            )
            token = frame_of_kind(descriptors, "stream_meta")["source_token"]
            rc_records, records, records_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    shard_bytes=512,
                    source_token=str(token),
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual((rc_records, records_error), (0, ""))
        fragment = frame_of_kind(records, "record_fragment")
        self.assertEqual(fragment["delimiter_bytes"], 2)
        self.assertEqual(reassemble_fragments(records), data)

    def test_descriptor_pagination_resumes_with_source_token(self) -> None:
        lines = [b'{"n":1}\n', b'{"n":2}\n', b'{"n":3}\n']
        data = b"".join(lines)
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc_first, first_page, first_error = run_local(
                codex_root,
                command_args(rollout, shard_bytes=len(lines[0]), max_shards=2),
            )
            first_terminal = frame_of_kind(first_page, "stream_end")
            token = frame_of_kind(first_page, "stream_meta")["source_token"]
            resume_cursor = first_terminal["next_resume_cursor"]
            rc_second, second_page, second_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    byte_start=int(first_terminal["next_byte_start"]),
                    shard_bytes=len(lines[0]),
                    max_shards=2,
                    source_token=str(token),
                    resume_cursor=str(resume_cursor),
                ),
            )

        self.assertEqual((rc_first, first_error), (0, ""))
        self.assertEqual((rc_second, second_error), (0, ""))
        self.assertFalse(first_terminal["complete"])
        self.assertEqual(first_terminal["reason"], "max_shards")
        self.assertEqual(
            first_terminal["accounted_byte_count"],
            len(lines[0]) + len(lines[1]),
        )
        self.assertEqual(first_terminal["accounted_record_count"], 2)
        self.assertEqual(first_terminal["next_byte_start"], first_terminal["byte_end"])
        self.assertIsInstance(resume_cursor, str)
        self.assertEqual(
            session_shards_resume_cursor(
                str(token),
                byte_offset=int(first_terminal["next_byte_start"]),
                next_record_index=int(first_terminal["next_record_start"]),
            ),
            resume_cursor,
        )
        self.assertEqual(
            first_terminal["next_record_start"], first_terminal["record_end"]
        )
        second_terminal = frame_of_kind(second_page, "stream_end")
        self.assertTrue(second_terminal["complete"])
        self.assertEqual(second_terminal["accounted_byte_count"], len(lines[2]))
        self.assertEqual(second_terminal["accounted_record_count"], 1)
        shards = [
            frame for frame in first_page + second_page if frame["kind"] == "shard"
        ]
        self.assertEqual(
            [(item["byte_start"], item["byte_end"]) for item in shards],
            [
                (0, len(lines[0])),
                (len(lines[0]), len(lines[0]) + len(lines[1])),
                (len(lines[0]) + len(lines[1]), len(data)),
            ],
        )
        self.assertEqual(
            [(item["record_start"], item["record_end"]) for item in shards],
            [(0, 1), (1, 2), (2, 3)],
        )

    def test_max_shards_boundary_does_not_read_the_next_descriptor(self) -> None:
        first = b"not-json\n"
        second = (
            b'{"text":"'
            + b"x" * (2 * MODULE.SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES)
            + b'"}\n'
        )
        bytes_read = 0
        real_open = MODULE._open_session_shard_source

        class CountingHandle:
            def __init__(self, handle: object) -> None:
                self.handle = handle

            def __enter__(self) -> CountingHandle:
                return self

            def __exit__(self, *args: object) -> None:
                del args
                self.handle.close()

            def __getattr__(self, name: str) -> object:
                return getattr(self.handle, name)

            def read(self, size: int = -1) -> bytes:
                nonlocal bytes_read
                value = self.handle.read(size)
                bytes_read += len(value)
                return value

            def readline(self, size: int = -1) -> bytes:
                nonlocal bytes_read
                value = self.handle.readline(size)
                bytes_read += len(value)
                return value

        def counted_open(*args: object, **kwargs: object) -> CountingHandle:
            return CountingHandle(real_open(*args, **kwargs))

        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, first + second)
            with mock.patch.object(
                MODULE,
                "_open_session_shard_source",
                side_effect=counted_open,
            ):
                rc, frames, error = run_local(
                    codex_root,
                    command_args(
                        rollout,
                        shard_bytes=64,
                        max_shards=1,
                    ),
                )

        self.assertEqual((rc, error), (0, ""))
        terminal = frame_of_kind(frames, "stream_end")
        self.assertEqual(terminal["reason"], "max_shards")
        self.assertEqual(terminal["next_byte_start"], len(first))
        self.assertEqual(bytes_read, len(first))

    def test_high_page_resume_cursor_does_not_rescan_the_prefix(self) -> None:
        lines = [f'{{"n":"{index:04d}"}}\n'.encode() for index in range(1_100)]
        self.assertEqual(len({len(line) for line in lines}), 1)
        shard_bytes = len(lines[0])
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, b"".join(lines))
            rc_first, first_page, first_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    shard_bytes=shard_bytes,
                    max_shards=MODULE.MAX_SESSION_SHARDS_PER_PAGE,
                ),
            )
            terminal = frame_of_kind(first_page, "stream_end")
            token = frame_of_kind(first_page, "stream_meta")["source_token"]
            rc_second, second_page, second_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    byte_start=int(terminal["next_byte_start"]),
                    shard_bytes=shard_bytes,
                    max_shards=1,
                    source_token=str(token),
                    resume_cursor=str(terminal["next_resume_cursor"]),
                ),
            )

        self.assertEqual((rc_first, first_error), (0, ""))
        self.assertEqual((rc_second, second_error), (0, ""))
        self.assertEqual(terminal["next_record_start"], 1_024)
        shard = frame_of_kind(second_page, "shard")
        self.assertEqual((shard["record_start"], shard["record_end"]), (1_024, 1_025))

    def test_resume_cursor_rejects_forgery_offset_mismatch_and_stale_source(
        self,
    ) -> None:
        lines = [b'{"n":1}\n', b'{"n":2}\n', b'{"n":3}\n']
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, b"".join(lines))
            rc, first_page, error = run_local(
                codex_root,
                command_args(rollout, shard_bytes=len(lines[0]), max_shards=1),
            )
            terminal = frame_of_kind(first_page, "stream_end")
            token = str(frame_of_kind(first_page, "stream_meta")["source_token"])
            cursor = str(terminal["next_resume_cursor"])
            forged = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
            forged_rc, forged_frames, forged_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    byte_start=int(terminal["next_byte_start"]),
                    shard_bytes=len(lines[0]),
                    source_token=token,
                    resume_cursor=forged,
                ),
            )
            mismatch_rc, mismatch_frames, mismatch_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    byte_start=int(terminal["next_byte_start"]) + len(lines[1]),
                    shard_bytes=len(lines[0]),
                    source_token=token,
                    resume_cursor=cursor,
                ),
            )
            (codex_root / rollout).write_bytes(b"".join(lines) + b'{"n":4}\n')
            stale_rc, stale_frames, stale_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    byte_start=int(terminal["next_byte_start"]),
                    shard_bytes=len(lines[0]),
                    source_token=token,
                    resume_cursor=cursor,
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual((forged_rc, forged_frames), (1, []))
        self.assertIn("invalid session-shards resume cursor", forged_error)
        self.assertEqual((mismatch_rc, mismatch_frames), (1, []))
        self.assertIn("does not match --byte-start", mismatch_error)
        self.assertEqual((stale_rc, stale_frames), (1, []))
        self.assertIn("source token does not match current rollout", stale_error)

    def test_stale_source_token_is_rejected_before_any_frame(self) -> None:
        data = b'{"n":1}\n'
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(codex_root, command_args(rollout))
            token = frame_of_kind(descriptors, "stream_meta")["source_token"]
            (codex_root / rollout).write_bytes(data + b'{"n":2}\n')
            stale_rc, stale_frames, stale_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    source_token=str(token),
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual(stale_rc, 1)
        self.assertEqual(stale_frames, [])
        self.assertIn("source token does not match current rollout", stale_error)

    def test_invalid_json_is_a_content_free_gap(self) -> None:
        valid = b'{"n":1}\n'
        invalid = b"{not-json}\n"
        non_object = b"[]\n"
        nonstandard_constant = b'{"n":NaN}\n'
        data = valid + invalid + non_object + nonstandard_constant
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(codex_root, command_args(rollout))
            token = frame_of_kind(descriptors, "stream_meta")["source_token"]
            rc_records, records, records_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    source_token=str(token),
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual((rc_records, records_error), (0, ""))
        gaps = [frame for frame in records if frame["kind"] == "gap"]
        self.assertEqual([gap["reason"] for gap in gaps], ["invalid_json"] * 3)
        for gap in gaps:
            self.assertTrue(
                {"record", "record_b64", "payload", "raw", "text"}.isdisjoint(gap),
                gap,
            )

    def test_multibyte_record_over_raw_shard_limit_reassembles_exactly(self) -> None:
        data = (
            json.dumps(
                {"type": "message", "text": "\u4f60\u597d\U0001f642" * 70_000},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        self.assertGreater(len(data), MODULE.MAX_SESSION_SHARD_BYTES)
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(
                codex_root,
                command_args(
                    rollout,
                    shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                ),
            )
            token = frame_of_kind(descriptors, "stream_meta")["source_token"]
            rc_records, records, records_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                    source_token=str(token),
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        descriptor = frame_of_kind(descriptors, "shard")
        self.assertEqual(descriptor["status"], "ready")
        self.assertTrue(descriptor["oversized_record"])
        self.assertEqual(descriptor["record_transport"], "base64_fragments")
        self.assertEqual(
            (descriptor["byte_start"], descriptor["byte_end"]),
            (0, len(data)),
        )
        self.assertEqual((rc_records, records_error), (0, ""))
        fragments = [frame for frame in records if frame["kind"] == "record_fragment"]
        self.assertGreater(len(fragments), 2)
        self.assertEqual(
            [int(frame["fragment_index"]) for frame in fragments],
            list(range(len(fragments))),
        )
        self.assertEqual(
            {int(frame["fragment_count"]) for frame in fragments},
            {len(fragments)},
        )
        self.assertEqual(
            [(frame["byte_start"], frame["byte_end"]) for frame in fragments],
            [
                (
                    index * MODULE.SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
                    min(
                        (index + 1) * MODULE.SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
                        len(data),
                    ),
                )
                for index in range(len(fragments))
            ],
        )
        self.assertEqual(
            {
                (
                    frame["record_byte_start"],
                    frame["record_byte_end"],
                    frame["record_start"],
                    frame["record_end"],
                    frame["source_token"],
                )
                for frame in fragments
            },
            {(0, len(data), 0, 1, token)},
        )
        self.assertEqual(reassemble_fragments(records), data)
        terminal = frame_of_kind(records, "stream_end")
        proof = terminal["conservation_proof"]
        self.assertIsInstance(proof, dict)
        self.assertEqual(proof["byte_count"], len(data))
        self.assertEqual(proof["accounted_byte_count"], len(data))
        self.assertEqual(proof["record_count"], 1)
        self.assertEqual(proof["accounted_record_count"], 1)

    def test_large_record_uses_owner_only_spool_with_bounded_peak_memory(self) -> None:
        data = b'{"text":"' + b"x" * (1024 * 1024) + b'"}\n'
        budget = MODULE.MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            with MODULE._open_session_shard_source(
                codex_root,
                MODULE.pathlib.PurePosixPath(rollout),
            ) as handle:
                records = iter(
                    MODULE._iter_session_shard_records(
                        handle,
                        byte_start=0,
                        byte_end=len(data),
                        record_start=0,
                        record_processing_budget_bytes=budget,
                    )
                )
                tracemalloc.start()
                try:
                    record = next(records)
                    _, peak_bytes = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                storage = record.record_storage
                self.assertIsNotNone(storage)
                assert storage is not None
                self.assertTrue(storage._rolled)
                spool_mode = stat.S_IMODE(os.fstat(storage.fileno()).st_mode)
                self.assertEqual(spool_mode & 0o077, 0)
                self.assertLess(peak_bytes, budget)
                self.assertEqual(
                    record.record_commitment,
                    MODULE._session_shards_content_commitment(data),
                )
                records.close()

    def test_fixed_memory_envelope_covers_stream_frame_serialization(self) -> None:
        def measured_peak(data: bytes) -> int:
            with tempfile.TemporaryDirectory() as raw:
                codex_root = Path(raw) / ".codex"
                rollout = write_rollout(codex_root, data)
                with MODULE._open_session_shard_source(
                    codex_root,
                    MODULE.pathlib.PurePosixPath(rollout),
                ) as handle:
                    identity = MODULE._session_shards_source_identity(
                        os.fstat(handle.fileno())
                    )
                token = MODULE._session_shards_source_token(identity)
                tracemalloc.start()
                try:
                    for frame in MODULE._iter_local_session_shard_frames(
                        codex_root=codex_root,
                        rollout_relative_path=MODULE.pathlib.PurePosixPath(rollout),
                        emit="records",
                        byte_start=0,
                        byte_end=len(data),
                        shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                        max_shards=64,
                        source_token=token,
                        record_processing_budget_bytes=(
                            MODULE.MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
                        ),
                    ):
                        encoded = json.dumps(
                            frame,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        self.assertLessEqual(
                            len(encoded), MODULE.MAX_SESSION_SHARDS_FRAME_CHARS
                        )
                        del encoded
                    _, peak_bytes = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
            return peak_bytes

        inline_overhead = len(b'{"text":""}\n')
        normal = (
            b'{"text":"'
            + b"x" * (MODULE.MAX_SESSION_SHARD_BYTES - inline_overhead)
            + b'"}\n'
        )
        fragmented = b'{"text":"' + b"x" * (1024 * 1024) + b'"}\n'
        self.assertEqual(len(normal), MODULE.MAX_SESSION_SHARD_BYTES)
        for name, data in (("normal", normal), ("fragmented", fragmented)):
            with self.subTest(name=name):
                peak_bytes = measured_peak(data)
                self.assertLess(
                    peak_bytes,
                    MODULE.MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
                    f"peak={peak_bytes}",
                )

    def test_processing_budget_gap_is_explicit_content_free_and_conserved(
        self,
    ) -> None:
        budget = MODULE.MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
        over_budget = b'{"text":"' + b"x" * budget + b'"}\n'
        following = b'{"n":2}\n'
        data = over_budget + following
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(
                codex_root,
                command_args(
                    rollout,
                    shard_bytes=32,
                    max_shards=1,
                    record_processing_budget_bytes=budget,
                ),
            )
            descriptor_terminal = frame_of_kind(descriptors, "stream_end")
            token = frame_of_kind(descriptors, "stream_meta")["source_token"]
            rc_records, records, records_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    shard_bytes=32,
                    source_token=str(token),
                    record_processing_budget_bytes=budget,
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        descriptor = frame_of_kind(descriptors, "shard")
        self.assertEqual(descriptor["status"], "gap")
        self.assertEqual(descriptor["gap_reason"], "record_processing_budget_exceeded")
        self.assertEqual(descriptor["byte_count"], len(over_budget))
        self.assertEqual(descriptor["record_processing_budget_bytes"], budget)
        self.assertEqual(descriptor["processing_ceiling_kind"], "record_bytes")
        self.assertEqual(descriptor["processing_ceiling_limit"], budget)
        self.assertEqual(descriptor["processing_ceiling_observed"], len(over_budget))
        self.assertEqual(
            descriptor["hard_record_processing_ceiling_bytes"],
            MODULE.HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES,
        )
        self.assertFalse(descriptor_terminal["complete"])
        self.assertEqual(descriptor_terminal["next_byte_start"], len(over_budget))
        self.assertEqual((rc_records, records_error), (0, ""))
        gap = frame_of_kind(records, "gap")
        self.assertEqual(gap["reason"], "record_processing_budget_exceeded")
        self.assertEqual(gap["byte_count"], len(over_budget))
        self.assertEqual(gap["record_processing_budget_bytes"], budget)
        self.assertEqual(gap["processing_ceiling_kind"], "record_bytes")
        self.assertEqual(gap["processing_ceiling_limit"], budget)
        self.assertEqual(gap["processing_ceiling_observed"], len(over_budget))
        self.assertTrue(
            {
                "record",
                "record_b64",
                "fragment_b64",
                "payload",
                "raw",
                "text",
                "record_commitment",
                "fragment_commitment",
            }.isdisjoint(gap)
        )
        normal = frame_of_kind(records, "record")
        self.assertEqual(base64.b64decode(normal["record_b64"]), following)
        terminal = frame_of_kind(records, "stream_end")
        self.assertEqual(terminal["emitted_gap_bytes"], len(over_budget))
        self.assertEqual(terminal["emitted_record_bytes"], len(following))
        proof = terminal["conservation_proof"]
        self.assertEqual(proof["byte_count"], len(data))
        self.assertEqual(proof["accounted_byte_count"], len(data))

    def test_valid_json_over_nesting_ceiling_is_an_explicit_processing_gap(
        self,
    ) -> None:
        depth = MODULE.SESSION_SHARDS_MAX_JSON_NESTING_DEPTH + 1
        data = b'{"value":' + b"[" * depth + b"0" + b"]" * depth + b"}\n"
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            rc, descriptors, error = run_local(codex_root, command_args(rollout))
            token = str(frame_of_kind(descriptors, "stream_meta")["source_token"])
            rc_records, records, records_error = run_local(
                codex_root,
                command_args(
                    rollout,
                    emit="records",
                    byte_end=len(data),
                    source_token=token,
                ),
            )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual((rc_records, records_error), (0, ""))
        descriptor = frame_of_kind(descriptors, "shard")
        gap = frame_of_kind(records, "gap")
        for frame in (descriptor, gap):
            self.assertEqual(
                frame.get("gap_reason", frame.get("reason")),
                "record_processing_budget_exceeded",
            )
            self.assertEqual(frame["byte_count"], len(data))
            self.assertEqual(frame["processing_ceiling_kind"], "json_nesting_depth")
            self.assertEqual(
                frame["processing_ceiling_limit"],
                MODULE.SESSION_SHARDS_MAX_JSON_NESTING_DEPTH,
            )
            self.assertEqual(
                frame["processing_ceiling_observed"],
                MODULE.SESSION_SHARDS_MAX_JSON_NESTING_DEPTH + 1,
            )
        self.assertTrue(
            {"record_b64", "fragment_b64", "payload", "raw", "text"}.isdisjoint(gap)
        )

    def test_records_range_limit_is_inclusive_and_boundary_aligned(self) -> None:
        range_limit = 2048
        data = b"x" * (range_limit - 1) + b"\n"
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            with mock.patch.object(
                MODULE,
                "MAX_SESSION_SHARDS_RANGE_BYTES",
                range_limit,
            ):
                rc, descriptors, error = run_local(
                    codex_root,
                    command_args(
                        rollout,
                        shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                    ),
                )
                token = frame_of_kind(descriptors, "stream_meta")["source_token"]
                exact_rc, exact_frames, exact_error = run_local(
                    codex_root,
                    command_args(
                        rollout,
                        emit="records",
                        byte_end=len(data),
                        shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                        source_token=str(token),
                    ),
                )
                over_rc, over_frames, over_error = run_local(
                    codex_root,
                    command_args(
                        rollout,
                        emit="records",
                        byte_end=range_limit + 1,
                        source_token=str(token),
                    ),
                )
                unaligned_rc, unaligned_frames, unaligned_error = run_local(
                    codex_root,
                    command_args(
                        rollout,
                        emit="records",
                        byte_start=1,
                        byte_end=len(data),
                        shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                        source_token=str(token),
                    ),
                )

        self.assertEqual((rc, error), (0, ""))
        self.assertEqual((exact_rc, exact_error), (0, ""))
        self.assertTrue(frame_of_kind(exact_frames, "stream_end")["complete"])
        self.assertEqual(frame_of_kind(exact_frames, "gap")["byte_count"], len(data))
        self.assertEqual((over_rc, over_frames), (1, []))
        self.assertIn("record range too large", over_error)
        self.assertEqual((unaligned_rc, unaligned_frames), (1, []))
        self.assertIn("JSONL record boundary", unaligned_error)

    def test_fstat_change_prevents_terminal_completion(self) -> None:
        data = b'{"n":1}\n'
        first_identity = (1, 2, 3, len(data), 4, 5)
        changed_identity = (1, 2, 3, len(data) + 1, 6, 7)
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(MODULE, "_local_codex_root", return_value=codex_root),
                mock.patch.object(
                    MODULE,
                    "_session_shards_source_identity",
                    side_effect=[first_identity, changed_identity],
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                rc = MODULE.cmd_session_shards(command_args(rollout))

        frames = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(rc, 1)
        self.assertNotIn("stream_end", [frame["kind"] for frame in frames])
        self.assertIn("source changed during session-shards read", stderr.getvalue())

    def test_symlink_and_non_regular_rollouts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            codex_root = root / ".codex"
            rollout = "sessions/2026/07/14/rollout-unsafe.jsonl"
            target = codex_root / rollout
            target.parent.mkdir(parents=True)
            outside = root / "outside.jsonl"
            outside.write_bytes(b'{"n":1}\n')
            target.symlink_to(outside)
            symlink_rc, symlink_frames, symlink_error = run_local(
                codex_root, command_args(rollout)
            )
            target.unlink()
            target.mkdir()
            directory_rc, directory_frames, directory_error = run_local(
                codex_root, command_args(rollout)
            )

        self.assertEqual((symlink_rc, symlink_frames), (1, []))
        self.assertIn("symlink", symlink_error)
        self.assertEqual((directory_rc, directory_frames), (1, []))
        self.assertIn("not a regular file", directory_error)

    def test_openat_traversal_survives_ancestor_name_swap(self) -> None:
        safe_data = b'{"source":"safe"}\n'
        unsafe_data = b'{"source":"outside"}\n'
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            codex_root = root / ".codex"
            rollout = write_rollout(codex_root, safe_data)
            sessions = codex_root / "sessions"
            pinned_sessions = codex_root / "sessions-pinned"
            outside_sessions = root / "outside-sessions"
            outside_rollout = outside_sessions / Path(rollout).relative_to("sessions")
            outside_rollout.parent.mkdir(parents=True)
            outside_rollout.write_bytes(unsafe_data)

            def swap_after_sessions_open(index: int, part: str, dirfd: int) -> None:
                del dirfd
                if index == 0 and part == "sessions":
                    sessions.rename(pinned_sessions)
                    sessions.symlink_to(outside_sessions, target_is_directory=True)

            with mock.patch.object(
                MODULE,
                "_SESSION_SHARDS_OPEN_COMPONENT_HOOK",
                side_effect=swap_after_sessions_open,
                create=True,
            ):
                with MODULE._open_session_shard_source(
                    codex_root,
                    MODULE.pathlib.PurePosixPath(rollout),
                ) as handle:
                    opened_data = handle.read()

            self.assertEqual((codex_root / rollout).read_bytes(), unsafe_data)

        self.assertEqual(opened_data, safe_data)

    def test_openat_traversal_fails_closed_without_portable_primitives(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, b'{"n":1}\n')
            with (
                mock.patch.object(MODULE.os, "supports_dir_fd", frozenset()),
                self.assertRaisesRegex(RuntimeError, "secure openat.*unsupported"),
            ):
                MODULE._open_session_shard_source(
                    codex_root,
                    MODULE.pathlib.PurePosixPath(rollout),
                )

    def test_openat_traversal_rejects_a_symlink_codex_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            real_codex_root = root / ".codex-real"
            rollout = write_rollout(real_codex_root, b'{"n":1}\n')
            linked_codex_root = root / ".codex"
            linked_codex_root.symlink_to(real_codex_root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "Codex root.*real directory"):
                MODULE._open_session_shard_source(
                    linked_codex_root,
                    MODULE.pathlib.PurePosixPath(rollout),
                )


class RemoteSessionShardsRelayTests(unittest.TestCase):
    @staticmethod
    def record_stream(
        codex_root: Path,
        data: bytes,
    ) -> tuple[str, argparse.Namespace, list[dict[str, object]]]:
        rollout = write_rollout(codex_root, data)
        descriptors = list(
            MODULE._iter_local_session_shard_frames(
                codex_root=codex_root,
                rollout_relative_path=MODULE.pathlib.PurePosixPath(rollout),
                emit="descriptors",
                byte_start=0,
                byte_end=None,
                shard_bytes=512,
                max_shards=64,
                source_token=None,
                resume_cursor=None,
                record_processing_budget_bytes=(
                    MODULE.DEFAULT_SESSION_RECORD_PROCESSING_BUDGET_BYTES
                ),
            )
        )
        source_token = str(frame_of_kind(descriptors, "stream_meta")["source_token"])
        args = command_args(
            rollout,
            host="remote-a",
            emit="records",
            byte_end=len(data),
            source_token=source_token,
        )
        records = list(
            MODULE._iter_local_session_shard_frames(
                codex_root=codex_root,
                rollout_relative_path=MODULE.pathlib.PurePosixPath(rollout),
                emit="records",
                byte_start=0,
                byte_end=len(data),
                shard_bytes=args.shard_bytes,
                max_shards=args.max_shards,
                source_token=source_token,
                resume_cursor=None,
                record_processing_budget_bytes=(args.record_processing_budget_bytes),
            )
        )
        return rollout, args, records

    @staticmethod
    def relay_filter(
        rollout: str,
        args: argparse.Namespace,
    ) -> object:
        request_binding = MODULE._session_shards_request_binding(
            rollout=rollout,
            mode=args.emit,
            source_token=args.source_token,
            byte_start=args.byte_start,
            byte_end=args.byte_end,
            shard_bytes=args.shard_bytes,
            max_shards=args.max_shards,
            record_processing_budget_bytes=args.record_processing_budget_bytes,
            resume_cursor=args.resume_cursor,
        )
        return MODULE.RemoteSessionShardsFilter(
            host=args.host,
            rollout=rollout,
            mode=args.emit,
            source_token=args.source_token,
            resume_cursor=args.resume_cursor,
            request_binding=request_binding,
            byte_start=args.byte_start,
            byte_end=args.byte_end,
            shard_bytes=args.shard_bytes,
            max_shards=args.max_shards,
            record_processing_budget_bytes=args.record_processing_budget_bytes,
            max_frame_chars=MODULE.MAX_SESSION_SHARDS_FRAME_CHARS,
        )

    @staticmethod
    def wire(frames: list[dict[str, object]]) -> bytes:
        return b"".join(
            json.dumps(
                frame,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
            for frame in frames
        )

    def test_remote_filter_stream_validates_and_binds_host_rollout(self) -> None:
        data = b'{"payload":"' + b"x" * 2_000 + b'"}\n'
        with tempfile.TemporaryDirectory() as raw:
            rollout, args, records = self.record_stream(Path(raw) / ".codex", data)
        stream_filter = self.relay_filter(rollout, args)
        wire = self.wire(records)
        chunks = [wire[index : index + 97] for index in range(0, len(wire), 97)]
        output = b"".join(stream_filter.feed(chunk) for chunk in chunks)
        output += stream_filter.finish()
        relayed = [json.loads(line) for line in output.splitlines()]

        self.assertEqual(len(records), len(relayed))
        self.assertTrue(all(frame["host"] == "remote-a" for frame in relayed))
        self.assertTrue(all(frame["rollout"] == rollout for frame in relayed))
        self.assertEqual(
            frame_of_kind(records, "stream_end")["conservation_proof"],
            frame_of_kind(relayed, "stream_end")["conservation_proof"],
        )

    def test_remote_filter_rejects_cross_host_and_mixed_wrappers(self) -> None:
        data = b'{"n":1}\n'
        with tempfile.TemporaryDirectory() as raw:
            rollout, args, records = self.record_stream(Path(raw) / ".codex", data)
        cross_host = copy.deepcopy(records)
        for frame in cross_host:
            frame.update(host="remote-b", rollout=rollout)
        with self.assertRaisesRegex(ValueError, "cross-host"):
            self.relay_filter(rollout, args).feed(self.wire(cross_host))

        mixed = copy.deepcopy(records)
        mixed[1].update(host="remote-a", rollout=rollout)
        with self.assertRaisesRegex(ValueError, "mixed wrapped"):
            self.relay_filter(rollout, args).feed(self.wire(mixed))

    def test_remote_filter_rejects_terminal_conservation_mismatch(self) -> None:
        data = b'{"n":1}\n'
        with tempfile.TemporaryDirectory() as raw:
            rollout, args, records = self.record_stream(Path(raw) / ".codex", data)
        changed = copy.deepcopy(records)
        terminal = frame_of_kind(changed, "stream_end")
        terminal["emitted_record_bytes"] = int(terminal["emitted_record_bytes"]) + 1

        with self.assertRaisesRegex(ValueError, "does not conserve"):
            self.relay_filter(rollout, args).feed(self.wire(changed))

    def test_remote_record_output_limit_is_derived_from_requested_range(self) -> None:
        rollout = "sessions/2026/07/14/rollout-2026-07-14T10-00-00-small.jsonl"
        args = command_args(
            rollout,
            host="remote-a",
            emit="records",
            byte_end=8,
            source_token="session_shards_source_v1:" + "a" * 64,
        )
        with mock.patch.object(
            MODULE,
            "_relay_remote_host_context_command",
        ) as relay:
            returncode = MODULE.cmd_session_shards(args)

        self.assertEqual(0, returncode)
        self.assertLess(relay.call_args.kwargs["max_output_bytes"], 256 * 1024)
        self.assertIsInstance(
            relay.call_args.kwargs["stream_filter"],
            MODULE.RemoteSessionShardsFilter,
        )

    def test_compact_record_fanout_fits_the_remote_wire_budget(self) -> None:
        data = b"{}\n" * MODULE.MAX_SESSION_SHARDS_RECORD_DATA_FRAMES
        with tempfile.TemporaryDirectory() as raw:
            rollout, args, records = self.record_stream(Path(raw) / ".codex", data)
        wire = self.wire(records)
        output_limit = MODULE._session_shards_remote_output_limit(
            mode="records",
            byte_start=0,
            byte_end=len(data),
            max_shards=args.max_shards,
            frame_metadata_bytes=MODULE.SESSION_SHARDS_FRAME_METADATA_CHARS,
        )
        stream_filter = self.relay_filter(rollout, args)
        output = b"".join(
            stream_filter.feed(wire[index : index + 4096])
            for index in range(0, len(wire), 4096)
        )
        output += stream_filter.finish()

        self.assertLessEqual(len(output), output_limit)
        self.assertEqual(
            MODULE.MAX_SESSION_SHARDS_RECORD_DATA_FRAMES + 2,
            len(output.splitlines()),
        )

    def test_descriptor_and_record_modes_enforce_the_data_frame_limit(self) -> None:
        data = b"{}\n" * (MODULE.MAX_SESSION_SHARDS_RECORD_DATA_FRAMES + 1)
        with tempfile.TemporaryDirectory() as raw:
            codex_root = Path(raw) / ".codex"
            rollout = write_rollout(codex_root, data)
            descriptors = list(
                MODULE._iter_local_session_shard_frames(
                    codex_root=codex_root,
                    rollout_relative_path=MODULE.pathlib.PurePosixPath(rollout),
                    emit="descriptors",
                    byte_start=0,
                    byte_end=None,
                    shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                    max_shards=64,
                    source_token=None,
                    resume_cursor=None,
                )
            )
            source_token = str(
                frame_of_kind(descriptors, "stream_meta")["source_token"]
            )
            shards = [frame for frame in descriptors if frame["kind"] == "shard"]
            records = MODULE._iter_local_session_shard_frames(
                codex_root=codex_root,
                rollout_relative_path=MODULE.pathlib.PurePosixPath(rollout),
                emit="records",
                byte_start=0,
                byte_end=len(data),
                shard_bytes=MODULE.MAX_SESSION_SHARD_BYTES,
                max_shards=64,
                source_token=source_token,
                resume_cursor=None,
            )

            self.assertEqual(
                [MODULE.MAX_SESSION_SHARDS_RECORD_DATA_FRAMES, 1],
                [frame["record_count"] for frame in shards],
            )
            with self.assertRaisesRegex(RuntimeError, "data-frame limit"):
                list(records)


class TransportArchitectureAuditTests(unittest.TestCase):
    def test_v2_transport_delegates_without_owning_ssh_or_remote_programs(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertNotIn('"ssh"', source)
        self.assertNotIn("miku-bot-dev", source)
        self.assertNotIn("hoteng-srv-01", source)
        self.assertEqual(1, source.count("remote_codex_probe.py"))
        self.assertIn(
            '".codex/skills/remote-host-context/scripts/remote_codex_probe.py"',
            source,
        )
        self.assertNotIn("def _remote_session_shards_script", source)
        self.assertNotIn("def _remote_python_script", source)
        self.assertIn("REMOTE_HOST_CONTEXT_HELPER_RELATIVE_PATH", source)
        self.assertIn("_relay_remote_host_context_command", source)

    def test_migration_probe_has_no_v2_engine_or_source_transport_copy(self) -> None:
        source = MIGRATION_PROBE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 6_100)
        self.assertNotIn("retrospective_v2", source)
        self.assertNotIn("source_transport_lease_v2", source)
        self.assertNotIn('"source-transport"', source)
        self.assertNotIn("remote_host_context_helper_path", source)


if __name__ == "__main__":
    unittest.main()
