from __future__ import annotations

import codecs
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/codex-session-mining/scripts/scan_rollout.py"
REALISTIC_FIXTURE = ROOT / "tests/fixtures/codex_session_mining_exact_probe.jsonl"
SCHEMA = "codex.rollout-scan/v1"


def load_scanner_module():
    spec = importlib.util.spec_from_file_location("scan_rollout_contract", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("scanner module is not importable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compact_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def record(
    payload_type: str,
    /,
    *,
    outer_type: str = "event_msg",
    **payload: object,
) -> bytes:
    return compact_json(
        {
            "type": outer_type,
            "payload": {"type": payload_type, **payload},
        }
    ) + b"\n"


def user_record(message: object) -> bytes:
    return record("user_message", message=message)


def assistant_record(content: object) -> bytes:
    return record(
        "message",
        outer_type="response_item",
        role="assistant",
        content=content,
    )


class ScanRolloutTests(unittest.TestCase):
    maxDiff = None

    def run_scan(
        self,
        command: str,
        path: Path,
        *arguments: str,
        timeout: float = 20,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                command,
                "--path",
                str(path),
                *arguments,
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=timeout,
        )

    def run_search(
        self,
        path: Path,
        literal: str = "needle",
        *arguments: str,
        timeout: float = 20,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.run_scan(
            "search",
            path,
            "--literal",
            literal,
            *arguments,
            timeout=timeout,
        )

    def parse_events(
        self,
        completed: subprocess.CompletedProcess[bytes],
        *,
        expected_returncode: int = 0,
    ) -> list[dict[str, object]]:
        self.assertEqual(
            completed.returncode,
            expected_returncode,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        self.assertEqual(completed.stderr, b"")
        self.assertTrue(completed.stdout.endswith(b"\n"), completed.stdout[-200:])
        events = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual(events[0]["event"], "start")
        self.assertEqual(events[-1]["event"], "end")
        run_ids = {event["run_id"] for event in events}
        self.assertEqual(len(run_ids), 1)
        self.assertTrue(next(iter(run_ids)))
        self.assertEqual(
            [event["seq"] for event in events],
            list(range(len(events))),
        )
        for event in events:
            self.assertEqual(event["schema"], SCHEMA)
        return events

    def write_payload(self, directory: Path, payload: bytes) -> Path:
        path = directory / "rollout.jsonl"
        path.write_bytes(payload)
        return path

    @staticmethod
    def result_events(events: list[dict[str, object]]) -> list[dict[str, object]]:
        return [event for event in events if event["event"] == "match"]

    def assert_terminal(
        self,
        events: list[dict[str, object]],
        status: str,
        reason: str | None = None,
    ) -> dict[str, object]:
        end = events[-1]
        self.assertEqual(end["status"], status)
        if reason is not None:
            self.assertEqual(end["stop_reason"], reason)
        self.assertEqual(
            end["continuity"],
            "independent-descriptor-prefix-observation",
        )
        return end

    def test_checked_zero_match_is_terminal_and_typed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), user_record("nothing here"))
            events = self.parse_events(self.run_search(path))

        self.assertEqual(self.result_events(events), [])
        end = self.assert_terminal(events, "checked")
        self.assertEqual(end["next_result_offset"], None)
        self.assertEqual(end["search"]["matched_records"], 0)
        self.assertEqual(end["search"]["emitted_records"], 0)

    def test_result_windows_cover_20_21_and_45_matches_in_record_order(self) -> None:
        for count, page_sizes in ((20, [20]), (21, [20, 1]), (45, [20, 20, 5])):
            with self.subTest(count=count):
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = self.write_payload(
                        Path(temp_dir),
                        b"".join(
                            user_record(f"needle row {index:03d}")
                            for index in range(count)
                        ),
                    )
                    offsets: list[int] = [0]
                    pages: list[list[dict[str, object]]] = []
                    while offsets[-1] < count:
                        offset = offsets[-1]
                        arguments = (
                            ()
                            if offset == 0
                            else ("--result-offset", str(offset))
                        )
                        events = self.parse_events(
                            self.run_search(path, "needle", *arguments)
                        )
                        matches = self.result_events(events)
                        pages.append(matches)
                        end = self.assert_terminal(events, "checked")
                        next_offset = end["next_result_offset"]
                        if next_offset is None:
                            break
                        self.assertIsInstance(next_offset, int)
                        offsets.append(next_offset)

                self.assertEqual([len(page) for page in pages], page_sizes)
                flattened = [match for page in pages for match in page]
                self.assertEqual(
                    [match["result_index"] for match in flattened],
                    list(range(count)),
                )
                self.assertEqual(
                    [match["record"]["number"] for match in flattened],
                    list(range(1, count + 1)),
                )

    def test_result_window_controls_have_hard_caps(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                b"".join(user_record(f"needle {index}") for index in range(260)),
            )
            events = self.parse_events(
                self.run_search(
                    path,
                    "needle",
                    "--max-results",
                    "250",
                    "--max-output-bytes",
                    str(256 * 1024),
                )
            )
            rejected = self.run_search(path, "needle", "--max-results", "251")
            rejected_bytes = self.run_search(
                path,
                "needle",
                "--max-output-bytes",
                str(256 * 1024 + 1),
            )

        self.assertEqual(len(self.result_events(events)), 250)
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, b"")
        self.assertEqual(rejected_bytes.returncode, 2)
        self.assertEqual(rejected_bytes.stdout, b"")

    def test_result_event_bytes_obey_the_configured_detail_budget(self) -> None:
        budget = 4096
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                b"".join(
                    user_record(f"needle {index} " + "x" * 2000)
                    for index in range(40)
                ),
            )
            completed = self.run_search(
                path,
                "needle",
                "--max-results",
                "250",
                "--max-output-bytes",
                str(budget),
            )
            events = self.parse_events(completed)

        match_lines = [
            line
            for line in completed.stdout.splitlines(keepends=True)
            if json.loads(line)["event"] == "match"
        ]
        self.assertLessEqual(sum(map(len, match_lines)), budget)
        end = self.assert_terminal(events, "checked")
        self.assertEqual(end["search"]["matched_records"], 40)
        self.assertGreater(end["search"]["suppressed_records"], 0)
        self.assertEqual(
            end["next_result_offset"],
            end["search"]["emitted_records"],
        )

    def test_output_budget_keeps_a_contiguous_result_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                user_record("needle")
                + user_record("a" * 180 + "needle" + "b" * 220)
                + user_record("needle third"),
            )
            full = self.run_search(path, "needle", "--max-results", "250")
            full_events = self.parse_events(full)
            result_lines = [
                line
                for line in full.stdout.splitlines(keepends=True)
                if json.loads(line)["event"] == "match"
            ]
            self.assertEqual(len(result_lines), 3)
            budget = len(result_lines[0]) + len(result_lines[1]) - 1
            first_page = self.parse_events(
                self.run_search(
                    path,
                    "needle",
                    "--max-results",
                    "250",
                    "--max-output-bytes",
                    str(budget),
                )
            )
            second_page = self.parse_events(
                self.run_search(path, "needle", "--result-offset", "1")
            )

        self.assertEqual(
            [match["result_index"] for match in self.result_events(first_page)],
            [0],
        )
        self.assertEqual(first_page[-1]["next_result_offset"], 1)
        self.assertEqual(
            [match["result_index"] for match in self.result_events(second_page)],
            [1, 2],
        )

    def test_prefix_bound_excludes_a_later_append(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), user_record("needle before"))
            frozen_prefix_bytes = path.stat().st_size
            with path.open("ab") as stream:
                stream.write(user_record("needle after"))
            events = self.parse_events(
                self.run_search(
                    path,
                    "needle",
                    "--prefix-end-bytes",
                    str(frozen_prefix_bytes),
                )
            )

        matches = self.result_events(events)
        self.assertEqual(len(matches), 1)
        end = self.assert_terminal(events, "checked")
        self.assertEqual(end["frozen_prefix_bytes"], frozen_prefix_bytes)
        self.assertEqual(end["coverage"]["bytes_read"], frozen_prefix_bytes)

    def test_prefix_bound_inside_a_record_defers_only_that_bounded_tail(self) -> None:
        first = user_record("needle complete")
        second = user_record("needle outside bounded complete records")
        prefix = len(first) + len(second) // 2
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir), first + second + user_record("needle later")
            )
            events = self.parse_events(
                self.run_search(
                    path,
                    "needle",
                    "--prefix-end-bytes",
                    str(prefix),
                )
            )

        self.assertEqual(len(self.result_events(events)), 1)
        end = self.assert_terminal(events, "checked")
        self.assertEqual(end["frozen_prefix_bytes"], prefix)
        self.assertEqual(end["coverage"]["complete_records"], 1)
        self.assertEqual(
            end["coverage"]["tail_deferred_bytes"],
            prefix - len(first),
        )

    def test_prefix_bound_larger_than_current_size_is_unavailable_not_clamped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), user_record("needle"))
            too_large = self.parse_events(
                self.run_search(
                    path,
                    "needle",
                    "--prefix-end-bytes",
                    str(path.stat().st_size + 1),
                )
            )
            negative = self.run_search(
                path,
                "needle",
                "--prefix-end-bytes",
                "-1",
            )

        self.assertEqual(self.result_events(too_large), [])
        self.assert_terminal(too_large, "unavailable")
        self.assertEqual(negative.returncode, 2)
        self.assertEqual(negative.stdout, b"")

    def test_each_window_declares_independent_non_snapshot_continuity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                b"".join(user_record(f"needle {index}") for index in range(21)),
            )
            first = self.parse_events(self.run_search(path))
            second = self.parse_events(
                self.run_search(path, "needle", "--result-offset", "20")
            )

        self.assertNotEqual(first[0]["run_id"], second[0]["run_id"])
        for events in (first, second):
            self.assert_terminal(events, "checked")
            observation = events[0]["observation"]
            self.assertEqual(observation["content_stability"], "not-proven")
            self.assertEqual(
                observation["basis"], "descriptor-prefix-observation"
            )

    def test_relative_path_is_usage_error(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "search",
                "--path",
                "relative.jsonl",
                "--literal",
                "needle",
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")

    def test_missing_directory_symlink_and_fifo_are_structured_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            regular = self.write_payload(temp, user_record("needle"))
            directory = temp / "directory"
            directory.mkdir()
            symlink = temp / "symlink.jsonl"
            symlink.symlink_to(regular)
            fifo = temp / "rollout.fifo"
            os.mkfifo(fifo)
            paths = (temp / "missing.jsonl", directory, symlink, fifo)
            for path in paths:
                with self.subTest(path=path.name):
                    events = self.parse_events(self.run_search(path, timeout=3))
                    end = self.assert_terminal(events, "unavailable")
                    self.assertEqual(self.result_events(events), [])
                    self.assertIsNotNone(end["stop_reason"])
                    self.assertEqual(
                        end["search"],
                        {
                            "emitted_records": 0,
                            "matched_records": 0,
                            "result_bytes": 0,
                            "result_offset": 0,
                            "suppressed_records": 0,
                        },
                    )

    def test_unavailable_long_source_path_has_a_bounded_protocol_projection(self) -> None:
        module = load_scanner_module()
        secret_suffix = "SECRET_PATH_SUFFIX_MUST_NOT_BE_EMITTED"
        path = "/tmp/" + ("界" * 3000) + secret_suffix
        path_bytes = path.encode("utf-8")
        stream = io.BytesIO()

        with mock.patch.object(module.os, "open", side_effect=OSError) as open_source:
            returncode = module.main(
                ["search", "--path", path, "--literal", "needle"],
                stream=stream,
            )
        output = stream.getvalue()
        events = [json.loads(line) for line in output.splitlines()]

        self.assertEqual(returncode, 0)
        self.assertEqual(open_source.call_args.args[0], path)
        self.assertEqual([event["event"] for event in events], ["start", "end"])
        self.assertEqual(events[-1]["status"], "unavailable")
        self.assertEqual(events[-1]["stop_reason"], "source_open_refused")
        source = events[0]["source"]
        self.assertTrue(source["path_truncated"])
        self.assertEqual(source["path_utf8_bytes"], len(path_bytes))
        self.assertEqual(source["path_sha256"], hashlib.sha256(path_bytes).hexdigest())
        self.assertLessEqual(
            len(source["path"].encode("utf-8")),
            module.MAX_SOURCE_PATH_UTF8_BYTES,
        )
        self.assertNotIn(secret_suffix.encode("ascii"), output)
        self.assertLess(len(output), 32 * 1024)

    def test_single_utf8_bom_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir), codecs.BOM_UTF8 + user_record("needle")
            )
            events = self.parse_events(self.run_search(path))

        self.assertEqual(len(self.result_events(events)), 1)
        self.assert_terminal(events, "checked")

    def test_one_utf8_bom_is_accepted_at_each_physical_record_start(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                user_record("needle before")
                + codecs.BOM_UTF8
                + user_record("needle after bom with \ufeff inside string"),
            )
            events = self.parse_events(self.run_search(path))

        matches = self.result_events(events)
        self.assertEqual(len(matches), 2)
        self.assertEqual(
            [match["record"]["number"] for match in matches],
            [1, 2],
        )
        self.assert_terminal(events, "checked")

    def test_first_bad_record_stops_without_recovery_and_preserves_prior_match(self) -> None:
        valid_json = user_record("needle foreign").rstrip(b"\n").decode("utf-8")
        bad_records = {
            "double-bom": codecs.BOM_UTF8 * 2 + user_record("needle bad"),
            "utf16-le": (valid_json + "\n").encode("utf-16-le"),
            "utf16-be": (valid_json + "\n").encode("utf-16-be"),
            "utf32-le": (valid_json + "\n").encode("utf-32-le"),
            "utf32-be": (valid_json + "\n").encode("utf-32-be"),
            "bad-utf8": b'{"payload":{"type":"user_message","message":"\xff"}}\n',
            "bad-json": b'{"payload":{"type":"user_message",}}\n',
            "nonobject": b"[]\n",
        }
        for name, bad_record in bad_records.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = self.write_payload(
                        Path(temp_dir),
                        user_record("needle before")
                        + bad_record
                        + user_record("needle after"),
                    )
                    events = self.parse_events(self.run_search(path))

                matches = self.result_events(events)
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0]["record"]["number"], 1)
                end = self.assert_terminal(events, "partial")
                self.assertEqual(end["search"]["matched_records"], 1)
                self.assertLess(end["coverage"]["complete_records"], 3)

    def test_partial_positive_results_remain_windowable_before_the_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                b"".join(user_record(f"needle {index}") for index in range(21))
                + b"not-json\n"
                + user_record("needle unreachable"),
            )
            first = self.parse_events(self.run_search(path))
            second = self.parse_events(
                self.run_search(path, "needle", "--result-offset", "20")
            )

        first_end = self.assert_terminal(first, "partial")
        second_end = self.assert_terminal(second, "partial")
        self.assertEqual(len(self.result_events(first)), 20)
        self.assertEqual(len(self.result_events(second)), 1)
        self.assertEqual(first_end["next_result_offset"], 20)
        self.assertEqual(second_end["next_result_offset"], None)
        self.assertEqual(
            [
                match["result_index"]
                for events in (first, second)
                for match in self.result_events(events)
            ],
            list(range(21)),
        )

    def test_unterminated_tail_is_deferred_not_parsed(self) -> None:
        tail = user_record("needle tail").rstrip(b"\n")
        complete = user_record("needle complete")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), complete + tail)
            events = self.parse_events(self.run_search(path))

        self.assertEqual(len(self.result_events(events)), 1)
        end = self.assert_terminal(events, "checked")
        self.assertEqual(end["coverage"]["complete_records"], 1)
        self.assertEqual(end["coverage"]["tail_deferred_bytes"], len(tail))

    def test_record_candidate_over_one_mib_is_terminal_partial(self) -> None:
        oversized = user_record("needle " + "x" * (1024 * 1024))
        for name, candidate in (
            ("terminated", oversized),
            ("unterminated", oversized.rstrip(b"\n")),
        ):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = self.write_payload(
                        Path(temp_dir),
                        user_record("needle before")
                        + candidate
                        + (user_record("needle after") if name == "terminated" else b""),
                    )
                    events = self.parse_events(self.run_search(path))

                self.assertEqual(len(self.result_events(events)), 1)
                end = self.assert_terminal(events, "partial")
                self.assertIn("record", str(end["stop_reason"]))

    def test_physical_record_at_exactly_one_mib_is_accepted(self) -> None:
        empty_record = user_record("")
        message_bytes = 1024 * 1024 - len(empty_record)
        exact_record = user_record("x" * message_bytes)
        self.assertEqual(len(exact_record), 1024 * 1024)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), exact_record)
            events = self.parse_events(self.run_search(path, "x" * 1024))

        self.assertEqual(len(self.result_events(events)), 1)
        self.assert_terminal(events, "checked")

    def test_public_scan_caps_are_exact(self) -> None:
        module = load_scanner_module()

        self.assertEqual(module.MAX_RECORD_BYTES, 1024 * 1024)
        self.assertEqual(module.MAX_READ_BYTES, 192 * 1024 * 1024)
        self.assertEqual(module.MAX_RECORDS, 250_000)
        self.assertEqual(module.DEFAULT_MAX_RESULTS, 20)
        self.assertEqual(module.HARD_MAX_RESULTS, 250)
        self.assertEqual(module.DEFAULT_MAX_OUTPUT_BYTES, 64 * 1024)
        self.assertEqual(module.HARD_MAX_OUTPUT_BYTES, 256 * 1024)
        self.assertEqual(module.MAX_SHAPE_PATH_CHARS, 128)
        self.assertEqual(module.MAX_SHAPE_OUTPUT_BYTES, 64 * 1024)

    def test_record_budget_accepts_exact_boundary_and_rejects_one_more(self) -> None:
        for count, expected_status in ((250_000, "checked"), (250_001, "partial")):
            with self.subTest(count=count):
                deferred_tail = b'{"partial":' if count == 250_000 else b""
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = self.write_payload(
                        Path(temp_dir), b"{}\n" * count + deferred_tail
                    )
                    events = self.parse_events(
                        self.run_search(path, timeout=60)
                    )

                end = self.assert_terminal(events, expected_status)
                self.assertEqual(end["coverage"]["complete_records"], 250_000)
                if count == 250_000:
                    self.assertEqual(
                        end["coverage"]["tail_deferred_bytes"], len(deferred_tail)
                    )
                if count > 250_000:
                    self.assertIn("record", str(end["stop_reason"]))

    def test_record_budget_reads_a_short_tail_after_a_chunk_aligned_boundary(self) -> None:
        module = load_scanner_module()
        original_records = module.MAX_RECORDS
        original_chunk = module.READ_CHUNK_BYTES
        module.MAX_RECORDS = 2
        module.READ_CHUNK_BYTES = 16
        payload = b"{}\n" + b'{"x":"aaaa"}\n' + b'{"tail":'
        self.assertEqual(len(payload) - len(b'{"tail":'), 16)
        stream = io.BytesIO()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = self.write_payload(Path(temp_dir), payload)
                returncode = module.main(
                    ["search", "--path", str(path), "--literal", "absent"],
                    stream=stream,
                )
        finally:
            module.MAX_RECORDS = original_records
            module.READ_CHUNK_BYTES = original_chunk

        self.assertEqual(returncode, 0)
        events = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(events[-1]["status"], "checked")
        self.assertEqual(events[-1]["coverage"]["complete_records"], 2)
        self.assertEqual(
            events[-1]["coverage"]["tail_deferred_bytes"], len(b'{"tail":')
        )

    def test_batch_compaction_preserves_cross_chunk_record_coordinates(self) -> None:
        module = load_scanner_module()
        first = user_record("first")
        second = user_record("界 second")
        tail = b'{"tail":"deferred"}'
        payload = first + second + tail
        original_chunk = module.READ_CHUNK_BYTES
        module.READ_CHUNK_BYTES = 7
        records: list[object] = []
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = self.write_payload(Path(temp_dir), payload)
                source, source_error = module._open_source(str(path), None)
                self.assertIsNone(source_error)
                self.assertIsNotNone(source)
                try:
                    coverage = module._scan_records(source, records.append)
                finally:
                    os.close(source.fd)
        finally:
            module.READ_CHUNK_BYTES = original_chunk

        self.assertEqual(
            [
                (record.number, record.byte_start, record.byte_end)
                for record in records
            ],
            [
                (1, 0, len(first)),
                (2, len(first), len(first) + len(second)),
            ],
        )
        self.assertEqual(coverage.status, "checked")
        self.assertEqual(coverage.bytes_read, len(payload))
        self.assertEqual(coverage.complete_records, 2)
        self.assertEqual(
            coverage.complete_record_prefix_bytes,
            len(first) + len(second),
        )
        self.assertEqual(coverage.tail_deferred_bytes, len(tail))

    def test_short_record_batch_compacts_once_per_read_not_once_per_record(self) -> None:
        module = load_scanner_module()

        class TrackingBytearray(bytearray):
            prefix_deletions = 0
            shifted_suffix_bytes = 0

            def __delitem__(self, key: object) -> None:
                if (
                    isinstance(key, slice)
                    and key.start in (None, 0)
                    and isinstance(key.stop, int)
                ):
                    type(self).prefix_deletions += 1
                    type(self).shifted_suffix_bytes += len(self) - key.stop
                super().__delitem__(key)

        payload = b"{}\n" * 8192
        source = module.Source(
            fd=123,
            path="/synthetic/rollout.jsonl",
            device=1,
            inode=2,
            observed_size_bytes=len(payload),
            prefix_end_bytes=len(payload),
        )
        records: list[object] = []
        with (
            mock.patch.object(module, "bytearray", TrackingBytearray, create=True),
            mock.patch.object(module.os, "read", return_value=payload) as read_source,
        ):
            coverage = module._scan_records(source, records.append)

        self.assertEqual(coverage.status, "checked")
        self.assertEqual(coverage.complete_records, 8192)
        self.assertEqual(len(records), 8192)
        self.assertEqual(read_source.call_count, 1)
        self.assertLessEqual(
            TrackingBytearray.prefix_deletions,
            read_source.call_count + 1,
        )
        self.assertLessEqual(
            TrackingBytearray.shifted_suffix_bytes,
            len(payload),
        )

    def test_small_scale_read_budget_counts_actual_bytes(self) -> None:
        module = load_scanner_module()
        original_read_budget = module.MAX_READ_BYTES
        original_chunk = module.READ_CHUNK_BYTES
        try:
            module.MAX_READ_BYTES = 32
            module.READ_CHUNK_BYTES = 8
            with tempfile.TemporaryDirectory() as temp_dir:
                path = self.write_payload(Path(temp_dir), b"{}\n" * 20)
                output = io.BytesIO()
                returncode = module.main(
                    ["search", "--path", str(path), "--literal", "needle"],
                    stream=output,
                )
            self.assertEqual(returncode, 0)
            events = [json.loads(line) for line in output.getvalue().splitlines()]
            end = events[-1]
            self.assertEqual(end["status"], "partial")
            self.assertEqual(end["stop_reason"], "read_budget_exhausted")
            self.assertEqual(end["coverage"]["bytes_read"], 32)
            self.assertEqual(end["coverage"]["complete_records"], 10)
        finally:
            module.MAX_READ_BYTES = original_read_budget
            module.READ_CHUNK_BYTES = original_chunk

    def test_event_writer_flushes_each_line_and_write_failure_is_nonzero(self) -> None:
        module = load_scanner_module()

        class RecordingStream(io.BytesIO):
            def __init__(self) -> None:
                super().__init__()
                self.flush_count = 0

            def flush(self) -> None:
                self.flush_count += 1
                super().flush()

        recording = RecordingStream()
        writer = module.EventWriter(stream=recording, run_id="test-run")
        writer.emit({"event": "start", "command": "search"})
        writer.emit({"event": "match", "result_index": 0})
        self.assertEqual(recording.flush_count, 2)
        self.assertEqual(
            [json.loads(line)["seq"] for line in recording.getvalue().splitlines()],
            [0, 1],
        )

        class FailingStream:
            def write(self, _data: bytes) -> int:
                raise OSError("synthetic write failure")

            def flush(self) -> None:
                raise AssertionError("flush must not follow a failed write")

        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), user_record("needle"))
            returncode = module.main(
                ["search", "--path", str(path), "--literal", "needle"],
                stream=FailingStream(),
            )
        self.assertEqual(returncode, module.EXIT_IO)

        class WouldBlockStream:
            def write(self, _data: bytes) -> None:
                return None

            def flush(self) -> None:
                return None

        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), user_record("needle"))
            returncode = module.main(
                ["search", "--path", str(path), "--literal", "needle"],
                stream=WouldBlockStream(),
            )
        self.assertEqual(returncode, module.EXIT_IO)

    def test_evidence_categories_cover_calls_outputs_completion_and_metadata(self) -> None:
        payload = b"".join(
            (
                user_record("needle user"),
                assistant_record([{"type": "output_text", "text": "needle assistant"}]),
                record(
                    "function_call",
                    outer_type="response_item",
                    name="needle_tool",
                    arguments='{"query":"needle args"}',
                ),
                record(
                    "custom_tool_call",
                    outer_type="response_item",
                    name="custom",
                    input="needle custom input",
                ),
                record(
                    "function_call_output",
                    outer_type="response_item",
                    output="needle output",
                    content="needle content",
                    result="needle result",
                ),
                record(
                    "custom_tool_call_output",
                    outer_type="response_item",
                    output="needle custom output",
                    content="needle custom content",
                    result="needle custom result",
                ),
                record("task_complete", last_agent_message="needle done"),
                compact_json(
                    {
                        "type": "turn_context",
                        "payload": {"cwd": "/tmp/needle-metadata"},
                    }
                )
                + b"\n",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), payload)
            default_events = self.parse_events(self.run_search(path))
            metadata_events = self.parse_events(
                self.run_search(path, "needle", "--category", "metadata")
            )

        default_categories = {
            hit["category"]
            for match in self.result_events(default_events)
            for hit in match["hits"]
        }
        self.assertEqual(
            default_categories,
            {"assistant", "task_complete", "tool_call", "tool_output", "user"},
        )
        self.assertEqual(len(self.result_events(default_events)), 7)
        default_paths = {
            hit["field_path"]
            for match in self.result_events(default_events)
            for hit in match["hits"]
        }
        self.assertIn("/payload/input", default_paths)
        for alias in ("output", "content", "result"):
            self.assertIn(f"/payload/{alias}", default_paths)
        output_matches = [
            match
            for match in self.result_events(default_events)
            if {hit["category"] for hit in match["hits"]} == {"tool_output"}
        ]
        self.assertEqual(
            [len(match["hits"]) for match in output_matches],
            [3, 3],
        )
        self.assertEqual(
            {
                hit["category"]
                for match in self.result_events(metadata_events)
                for hit in match["hits"]
            },
            {"metadata"},
        )

    def test_documented_event_message_families_are_opt_in_typed_evidence(self) -> None:
        task_started = compact_json(
            {
                "timestamp": "2026-08-16T12:34:56Z",
                "type": "event_msg",
                "payload": {
                    "type": "task_started",
                    "turn_id": "turn-start",
                    "trace_id": "trace-start",
                    "started_at": 1786910012,
                    "model_context_window": 114688,
                    "collaboration_mode_kind": "plan",
                },
            }
        ) + b"\n"
        rows = task_started + b"".join(
            (
                record(
                    "turn_aborted",
                    turn_id="turn-abort",
                    reason="needle-aborted",
                    started_at=1,
                    completed_at=2,
                    duration_ms=1,
                ),
                record(
                    "stream_error",
                    message="needle-retry-message",
                    additional_details="needle-retry-details",
                    codex_error_info={"detail": "not-selected"},
                ),
                record(
                    "error",
                    message="needle-terminal-error",
                    codex_error_info={"detail": "not-selected"},
                ),
                record(
                    "entered_review_mode",
                    target={"type": "custom", "instructions": "needle-review-target"},
                    user_facing_hint="needle-review-hint",
                    turn_id="turn-enter",
                    item_id="item-enter",
                ),
                record(
                    "exited_review_mode",
                    turn_id="turn-exit",
                    item_id="item-exit",
                    review_output={"overall_explanation": "needle-review-output"},
                ),
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), rows)
            default = self.parse_events(self.run_search(path, "task_started"))
            family = self.parse_events(
                self.run_search(path, "task_started", "--category", "event")
            )
            timestamp = self.parse_events(
                self.run_search(
                    path,
                    "2026-08-16T12:34:56Z",
                    "--category",
                    "event",
                )
            )
            cases = {
                "needle-aborted": "/payload/reason",
                "needle-retry-message": "/payload/message",
                "needle-retry-details": "/payload/additional_details",
                "needle-terminal-error": "/payload/message",
                "needle-review-target": "/payload/target/instructions",
                "needle-review-hint": "/payload/user_facing_hint",
                "needle-review-output": "/payload/review_output/overall_explanation",
            }
            observed_paths = {}
            for literal in cases:
                events = self.parse_events(
                    self.run_search(path, literal, "--category", "event")
                )
                matches = self.result_events(events)
                self.assertEqual(len(matches), 1, literal)
                observed_paths[literal] = matches[0]["hits"][0]["field_path"]

        self.assertEqual(self.result_events(default), [])
        self.assert_terminal(default, "checked")
        task_match = self.result_events(family)[0]
        self.assertEqual(task_match["hits"][0]["field_path"], "/payload/type")
        self.assertEqual(task_match["record"]["turn_id"], "turn-start")
        self.assertEqual(task_match["record"]["trace_id"], "trace-start")
        self.assertEqual(
            task_match["record"]["timestamp"],
            "2026-08-16T12:34:56Z",
        )
        self.assertEqual(
            self.result_events(timestamp)[0]["hits"][0]["field_path"],
            "/timestamp",
        )
        self.assertEqual(observed_paths, cases)
        self.assertEqual(
            family[-1]["category_stats"]["event"],
            {"matched_records": 1, "emitted_records": 1, "suppressed_records": 0},
        )

    def test_event_mapping_rejects_unregistered_types_fields_and_outer_decoys(self) -> None:
        rows = b"".join(
            (
                record(
                    "task_started",
                    outer_type="response_item",
                    turn_id="needle-response-decoy",
                ),
                record("thread/start", message="needle-thread-decoy"),
                record(
                    "stream_error",
                    message="ordinary retry",
                    codex_error_info={"detail": "needle-error-info"},
                ),
                record(
                    "task_started",
                    turn_id="ordinary-turn",
                    started_at=1786910012,
                    unknown="needle-unknown-field",
                ),
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), rows)
            for literal in (
                "needle-response-decoy",
                "needle-thread-decoy",
                "needle-error-info",
                "needle-unknown-field",
                "1786910012",
            ):
                events = self.parse_events(
                    self.run_search(path, literal, "--category", "event")
                )
                self.assertEqual(self.result_events(events), [], literal)
                self.assert_terminal(events, "checked")

    def test_computer_call_families_use_typed_action_and_output_fields(self) -> None:
        payload = b"".join(
            (
                record(
                    "computer_call",
                    action={"type": "needle-action"},
                    name="needle-forbidden-name",
                ),
                record(
                    "computer_tool_call",
                    action={"type": "needle-action"},
                    name="needle-forbidden-name",
                ),
                record("computer_call_output", output="needle-output"),
                record("computer_tool_call_output", output="needle-output"),
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), payload)
            calls = self.parse_events(
                self.run_search(
                    path,
                    "needle-action",
                    "--category",
                    "tool_call",
                )
            )
            outputs = self.parse_events(
                self.run_search(
                    path,
                    "needle-output",
                    "--category",
                    "tool_output",
                )
            )
            forbidden = self.parse_events(
                self.run_search(
                    path,
                    "needle-forbidden-name",
                    "--category",
                    "tool_call",
                )
            )

        self.assertEqual(
            [match["record"]["number"] for match in self.result_events(calls)],
            [1, 2],
        )
        self.assertEqual(
            {
                hit["field_path"]
                for match in self.result_events(calls)
                for hit in match["hits"]
            },
            {"/payload/action/type"},
        )
        self.assertEqual(
            [match["record"]["number"] for match in self.result_events(outputs)],
            [3, 4],
        )
        self.assertEqual(self.result_events(forbidden), [])
        self.assert_terminal(forbidden, "checked")

    def test_web_search_calls_use_the_typed_action_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                b"".join(
                    (
                        record(
                            "web_search_call",
                            outer_type="response_item",
                            action={
                                "type": "search",
                                "queries": ["needle-web-query"],
                            },
                            name="needle-web-decoy",
                            arguments="needle-web-decoy",
                            input="needle-web-decoy",
                        ),
                        record(
                            "web_search_call",
                            outer_type="response_item",
                            action={
                                "type": "open_page",
                                "url": "https://needle-open-page.example/",
                            },
                        ),
                        record(
                            "web_search_call",
                            outer_type="response_item",
                            action={
                                "type": "find_in_page",
                                "pattern": "needle-find-pattern",
                                "url": "https://example.invalid/page",
                            },
                        ),
                    )
                ),
            )
            search_action = self.parse_events(
                self.run_search(
                    path,
                    "needle-web-query",
                    "--category",
                    "tool_call",
                )
            )
            open_action = self.parse_events(
                self.run_search(
                    path,
                    "needle-open-page",
                    "--category",
                    "tool_call",
                )
            )
            find_action = self.parse_events(
                self.run_search(
                    path,
                    "needle-find-pattern",
                    "--category",
                    "tool_call",
                )
            )
            decoy = self.parse_events(
                self.run_search(
                    path,
                    "needle-web-decoy",
                    "--category",
                    "tool_call",
                )
            )

        matches = self.result_events(search_action)
        self.assertEqual(
            [hit["field_path"] for hit in matches[0]["hits"]],
            ["/payload/action/queries/0"],
        )
        self.assertEqual(
            [
                match["hits"][0]["field_path"]
                for match in self.result_events(open_action)
            ],
            ["/payload/action/url"],
        )
        self.assertEqual(
            [
                match["hits"][0]["field_path"]
                for match in self.result_events(find_action)
            ],
            ["/payload/action/pattern"],
        )
        self.assertEqual(self.result_events(decoy), [])
        self.assert_terminal(decoy, "checked")

    def test_real_outer_typed_records_use_the_same_curated_mapping(self) -> None:
        evidence = self.parse_events(
            self.run_search(REALISTIC_FIXTURE, "needle-structured-probe")
        )
        metadata = self.parse_events(
            self.run_search(
                REALISTIC_FIXTURE,
                "needle-structured-probe",
                "--category",
                "metadata",
            )
        )

        self.assertEqual(
            [match["record"]["number"] for match in self.result_events(evidence)],
            [4, 5, 6, 7],
        )
        self.assertEqual(
            [match["record"]["number"] for match in self.result_events(metadata)],
            [2, 3],
        )
        date_metadata = self.parse_events(
            self.run_search(
                REALISTIC_FIXTURE,
                "2026-05-29T00:00:01Z",
                "--category",
                "metadata",
            )
        )
        self.assertEqual(
            [match["record"]["number"] for match in self.result_events(date_metadata)],
            [2],
        )

    def test_empty_payload_type_does_not_fall_back_to_an_outer_evidence_type(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                compact_json(
                    {
                        "type": "function_call_output",
                        "payload": {"type": "", "output": "needle"},
                    }
                )
                + b"\n",
            )
            events = self.parse_events(self.run_search(path))

        self.assertEqual(self.result_events(events), [])
        self.assert_terminal(events, "checked")

    def test_non_string_payload_type_does_not_fall_back_to_outer_evidence(self) -> None:
        for payload_type in (None, [], {}, 1):
            with self.subTest(payload_type=payload_type):
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = self.write_payload(
                        Path(temp_dir),
                        compact_json(
                            {
                                "type": "function_call_output",
                                "payload": {
                                    "type": payload_type,
                                    "output": "needle",
                                },
                            }
                        )
                        + b"\n",
                    )
                    events = self.parse_events(self.run_search(path))

                self.assertEqual(self.result_events(events), [])
                self.assert_terminal(events, "checked")

    def test_repeatable_category_filter_is_a_union(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                user_record("needle user")
                + record(
                    "function_call",
                    outer_type="response_item",
                    name="needle_call",
                    arguments="{}",
                )
                + record(
                    "function_call_output",
                    outer_type="response_item",
                    output="needle output",
                ),
            )
            events = self.parse_events(
                self.run_search(
                    path,
                    "needle",
                    "--category",
                    "tool_call",
                    "--category",
                    "tool_output",
                )
            )

        categories = {
            hit["category"]
            for match in self.result_events(events)
            for hit in match["hits"]
        }
        self.assertEqual(categories, {"tool_call", "tool_output"})
        self.assertEqual(len(self.result_events(events)), 2)

    def test_user_text_is_structural_and_preserves_wrapped_user_text(self) -> None:
        wrapper = "<environment_context>needle wrapped</environment_context>"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                user_record(wrapper)
                + assistant_record("needle assistant")
                + record(
                    "function_call_output",
                    outer_type="response_item",
                    output="needle tool",
                ),
            )
            events = self.parse_events(
                self.run_search(path, "needle", "--mode", "user-text")
            )

        matches = self.result_events(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["hits"][0]["category"], "user")
        self.assertIn("environment_context", matches[0]["hits"][0]["snippet"])
        self.assertNotEqual(matches[0]["hits"][0].get("role"), "human")

    def test_response_message_role_user_is_user_not_human(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                record(
                    "message",
                    outer_type="response_item",
                    role="user",
                    content=[{"type": "input_text", "text": "needle"}],
                ),
            )
            evidence = self.parse_events(self.run_search(path))
            user_text = self.parse_events(
                self.run_search(path, "needle", "--mode", "user-text")
            )

        for events in (evidence, user_text):
            hit = self.result_events(events)[0]["hits"][0]
            self.assertEqual(hit["category"], "user")
            self.assertEqual(hit["role"], "user")
            self.assertNotEqual(hit["role"], "human")

    def test_user_matches_preserve_direct_origin_hint_as_record_provenance(self) -> None:
        rows = (
            record(
                "user_message",
                message="needle event user",
                origin_hint="  automation\nwrapper  ",
            )
            + record(
                "message",
                outer_type="response_item",
                role="user",
                content=[{"type": "input_text", "text": "needle response user"}],
                origin_hint="interactive",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), rows)
            evidence = self.parse_events(self.run_search(path, "needle"))
            user_text = self.parse_events(
                self.run_search(path, "needle", "--mode", "user-text")
            )

        for events in (evidence, user_text):
            matches = self.result_events(events)
            self.assertEqual(len(matches), 2)
            self.assertEqual(
                [match["record"]["origin_hint"] for match in matches],
                ["automation wrapper", "interactive"],
            )
            self.assertTrue(
                all("origin_hint" not in hit for match in matches for hit in match["hits"])
            )
            self.assertTrue(
                all(
                    "origin_hint_truncated" not in match["record"]
                    for match in matches
                )
            )

    def test_origin_hint_is_bounded_optional_and_not_searchable(self) -> None:
        long_hint = "x" * 81
        rows = (
            record("user_message", message="needle bounded", origin_hint=long_hint)
            + record("user_message", message="needle invalid", origin_hint=["decoy"])
            + record("user_message", message="ordinary", origin_hint="needle provenance")
            + record(
                "message",
                outer_type="response_item",
                role="assistant",
                content=[{"type": "output_text", "text": "needle assistant"}],
                origin_hint="assistant decoy",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), rows)
            events = self.parse_events(self.run_search(path, "needle"))
            provenance_only = self.parse_events(
                self.run_search(path, "needle provenance", "--mode", "user-text")
            )

        matches = self.result_events(events)
        self.assertEqual(len(matches), 3)
        self.assertEqual(matches[0]["record"]["origin_hint"], "x" * 80)
        self.assertTrue(matches[0]["record"]["origin_hint_truncated"])
        self.assertNotIn("origin_hint", matches[1]["record"])
        self.assertNotIn("origin_hint", matches[2]["record"])
        self.assertEqual(self.result_events(provenance_only), [])
        self.assert_terminal(provenance_only, "checked")

    def test_user_text_ignores_non_text_message_part_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                record(
                    "message",
                    outer_type="response_item",
                    role="user",
                    content=[
                        {
                            "type": "input_image",
                            "image_url": "https://example.invalid/needle.png",
                            "id": "needle-image-id",
                        },
                        {"type": "input_text", "text": "ordinary user text"},
                    ],
                ),
            )
            image_url = self.parse_events(self.run_search(path, "needle.png"))
            image_id = self.parse_events(self.run_search(path, "needle-image-id"))
            text = self.parse_events(self.run_search(path, "ordinary user text"))

        self.assertEqual(self.result_events(image_url), [])
        self.assertEqual(self.result_events(image_id), [])
        self.assertEqual(len(self.result_events(text)), 1)

    def test_non_string_message_part_type_is_an_unknown_shape_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                record(
                    "message",
                    outer_type="response_item",
                    role="user",
                    content=[{"type": [], "text": "needle"}],
                ),
            )
            events = self.parse_events(self.run_search(path))

        self.assertEqual(self.result_events(events), [])
        self.assert_terminal(events, "checked")

    def test_string_leaf_walk_retains_depth_bounded_memory_for_wide_values(self) -> None:
        module = load_scanner_module()
        wide = [None] * 50_000 + ["needle"]

        tracemalloc.start()
        try:
            leaves = list(module._iter_string_leaves(wide, "/payload/output"))
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(leaves, [("/payload/output/50000", "needle")])
        self.assertLess(peak, 2 * 1024 * 1024)

    def test_deep_long_field_paths_use_bounded_state_and_exact_digest(self) -> None:
        module = load_scanner_module()
        keys = [f"segment/{index}~" + ("x" * 980) for index in range(400)]
        nested: object = "needle"
        for key in reversed(keys):
            nested = {key: nested}
        full_path = "/payload/output" + "".join(
            f"/{key.replace('~', '~0').replace('/', '~1')}" for key in keys
        )
        expected = (
            full_path[: module.MAX_FIELD_PATH_CHARS - 20]
            + "...#"
            + hashlib.sha256(full_path.encode("utf-8")).hexdigest()[:16]
        )

        tracemalloc.start()
        try:
            leaves = list(module._iter_string_leaves(nested, "/payload/output"))
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(leaves, [(expected, "needle")])
        self.assertLessEqual(len(leaves[0][0]), module.MAX_FIELD_PATH_CHARS)
        self.assertLess(peak, 4 * 1024 * 1024)

    def test_truncated_field_path_digest_is_escaped_and_branch_local(self) -> None:
        module = load_scanner_module()
        common = "p" * 520
        value = {common: {"a/b~c": "first", "sibling": "second"}}
        full_paths = (
            f"/payload/output/{common}/a~1b~0c",
            f"/payload/output/{common}/sibling",
        )
        expected = [
            path[: module.MAX_FIELD_PATH_CHARS - 20]
            + "...#"
            + hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
            for path in full_paths
        ]

        leaves = list(module._iter_string_leaves(value, "/payload/output"))

        self.assertEqual(leaves, list(zip(expected, ("first", "second"))))

    def test_deep_message_paths_share_the_bounded_state_contract(self) -> None:
        module = load_scanner_module()
        depth = 600
        nested: object = [
            {"type": "text", "text": "first"},
            {"type": "text", "text": "second"},
        ]
        for _ in range(depth):
            nested = {"content": [nested]}
        common = "/payload/content" + ("/content/0" * depth)
        full_paths = (f"{common}/0/text", f"{common}/1/text")
        expected = [
            path[: module.MAX_FIELD_PATH_CHARS - 20]
            + "...#"
            + hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
            for path in full_paths
        ]

        tracemalloc.start()
        try:
            leaves = list(module._iter_message_texts(nested, "/payload/content"))
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(leaves, list(zip(expected, ("first", "second"))))
        self.assertLess(peak, 4 * 1024 * 1024)

    def test_literal_is_case_sensitive_whitespace_normalized_and_field_local(self) -> None:
        split_fields = {"first": "Alpha", "second": "Beta"}
        payload = (
            user_record("Alpha\t \n Beta")
            + user_record(split_fields)
            + user_record("alpha beta")
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), payload)
            events = self.parse_events(self.run_search(path, "Alpha   Beta"))

        matches = self.result_events(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["record"]["number"], 1)

    def test_literal_validation_allows_1024_bytes_and_rejects_larger_or_blank(self) -> None:
        exact = "é" * 512
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), user_record(exact))
            accepted = self.parse_events(self.run_search(path, exact))
            oversized = self.run_search(path, exact + "é")
            blank = self.run_search(path, "\u2003\t\n")
            all_values = self.run_search(path, exact, "--mode", "all-values")

        self.assertEqual(len(self.result_events(accepted)), 1)
        self.assertEqual(oversized.returncode, 2)
        self.assertEqual(oversized.stdout, b"")
        self.assertEqual(blank.returncode, 2)
        self.assertEqual(blank.stdout, b"")
        self.assertEqual(all_values.returncode, 2)
        self.assertEqual(all_values.stdout, b"")

    def test_one_match_event_per_record_has_bounded_hits_and_provenance(self) -> None:
        content = [
            {"type": "output_text", "text": f"needle field {index}"}
            for index in range(10)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), assistant_record(content))
            events = self.parse_events(self.run_search(path))

        matches = self.result_events(events)
        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertGreater(match["hits_observed"], len(match["hits"]))
        self.assertTrue(match["hits_truncated"])
        self.assertLessEqual(len(match["hits"]), 4)
        for hit in match["hits"]:
            self.assertEqual(hit["category"], "assistant")
            self.assertTrue(hit["field_path"].startswith("/payload/content/"))
            self.assertIn("snippet", hit)

    def test_field_paths_use_json_pointer_escaping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                record("function_call_output", output={"a/b~c": "needle"}),
            )
            events = self.parse_events(self.run_search(path))

        hit = self.result_events(events)[0]["hits"][0]
        self.assertEqual(hit["field_path"], "/payload/output/a~1b~0c")

    def test_deep_evidence_traversal_is_iterative_and_deterministic(self) -> None:
        depth = 980
        output_json = (
            '{"first":"needle first","nested":'
            + '{"node":' * depth
            + '"needle deep"'
            + "}" * depth
            + ',"last":"needle last"}'
        )
        raw_record = (
            '{"type":"event_msg","payload":{"type":"function_call_output","output":'
            + output_json
            + "}}\n"
        ).encode("utf-8")
        self.assertIsInstance(json.loads(raw_record), dict)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), raw_record)
            events = self.parse_events(self.run_search(path))

        matches = self.result_events(events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(
            [hit["snippet"] for hit in matches[0]["hits"]],
            ["needle first", "needle deep", "needle last"],
        )

    def test_message_block_structural_type_is_not_searchable_text(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                assistant_record(
                    [{"type": "needle-structural-type", "text": "ordinary text"}]
                ),
            )
            events = self.parse_events(
                self.run_search(path, "needle-structural-type")
            )

        self.assertEqual(self.result_events(events), [])
        self.assert_terminal(events, "checked")

    def test_end_reports_per_category_observed_emitted_and_suppressed_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                user_record("needle user")
                + assistant_record("needle assistant")
                + assistant_record("needle assistant 2"),
            )
            events = self.parse_events(
                self.run_search(path, "needle", "--max-results", "1")
            )

        end = self.assert_terminal(events, "checked")
        self.assertEqual(
            end["category_stats"]["user"],
            {"matched_records": 1, "emitted_records": 1, "suppressed_records": 0},
        )
        self.assertEqual(
            end["category_stats"]["assistant"],
            {"matched_records": 2, "emitted_records": 0, "suppressed_records": 2},
        )

    def test_shapes_retain_first_20_distinct_in_first_seen_order_with_counts(self) -> None:
        rows: list[bytes] = []
        secret_values: list[str] = []
        for index in range(21):
            secret = f"SECRET_VALUE_{index:02d}"
            secret_values.append(secret)
            copies = 2 if index == 0 else 1
            rows.extend(
                record(
                    f"shape_{index:02d}",
                    outer_type="event_msg",
                    text=secret,
                )
                for _ in range(copies)
            )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), b"".join(rows))
            completed = self.run_scan("shapes", path)
            events = self.parse_events(completed)

        shapes = [event for event in events if event["event"] == "shape"]
        self.assertEqual(len(shapes), 20)
        self.assertEqual([shape["shape_index"] for shape in shapes], list(range(20)))
        self.assertEqual(shapes[0]["records_observed"], 2)
        self.assertTrue(
            all(
                shape["shape"]["payload_type"] == f"shape_{index:02d}"
                for index, shape in enumerate(shapes)
            )
        )
        end = self.assert_terminal(events, "checked")
        self.assertEqual(end["shapes"]["retained_distinct_shapes"], 20)
        self.assertEqual(end["shapes"]["emitted_shapes"], 20)
        self.assertEqual(end["shapes"]["suppressed_shapes"], 0)
        self.assertFalse(end["shapes"]["output_truncated"])
        self.assertEqual(end["shapes"]["unretained_records"], 1)
        output_text = completed.stdout.decode("utf-8")
        for secret in secret_values:
            self.assertNotIn(secret, output_text)

    def test_shapes_are_not_result_offset_pageable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), b"{}\n")
            completed = self.run_scan("shapes", path, "--result-offset", "1")

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")

    def test_shapes_bound_depth_and_field_paths(self) -> None:
        nested: dict[str, object] = {"leaf": "SECRET_DEEP_VALUE"}
        for index in range(20):
            nested = {f"level_{index}": nested}
        wide = {f"field_{index}": index for index in range(80)}
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir), record("bounded_shape", nested=nested, wide=wide)
            )
            completed = self.run_scan("shapes", path)
            events = self.parse_events(completed)

        shape = next(event["shape"] for event in events if event["event"] == "shape")
        self.assertTrue(shape["paths_truncated"])
        self.assertLessEqual(len(shape["field_paths"]), 32)
        self.assertNotIn("SECRET_DEEP_VALUE", completed.stdout.decode("utf-8"))

    def test_shapes_bound_retained_memory_before_long_path_projection(self) -> None:
        module = load_scanner_module()
        long_key = "segment/~" + ("x" * 900_000)
        value = {long_key: {f"child_{index:02d}": index for index in range(80)}}
        full_path = f"/{long_key.replace('~', '~0').replace('/', '~1')}"
        expected = (
            full_path[: module.MAX_SHAPE_PATH_CHARS - 20]
            + "...#"
            + hashlib.sha256(full_path.encode("utf-8")).hexdigest()[:16]
        )

        tracemalloc.start()
        try:
            shape = module._shape_of(value)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertIn(
            {"path": expected, "kind": "object"},
            shape["field_paths"],
        )
        self.assertTrue(shape["paths_truncated"])
        self.assertTrue(
            all(
                len(entry["path"]) <= module.MAX_SHAPE_PATH_CHARS
                for entry in shape["field_paths"]
            )
        )
        self.assertLess(peak, 8 * 1024 * 1024)

    def test_shapes_are_stable_across_wide_object_key_order(self) -> None:
        forward = {f"field_{index:03d}": index for index in range(80)}
        reverse = dict(reversed(tuple(forward.items())))
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                compact_json({"type": "wide", "payload": forward})
                + b"\n"
                + compact_json({"payload": reverse, "type": "wide"})
                + b"\n",
            )
            events = self.parse_events(self.run_scan("shapes", path))

        shapes = [event for event in events if event["event"] == "shape"]
        self.assertEqual(len(shapes), 1)
        self.assertEqual(shapes[0]["records_observed"], 2)
        self.assertTrue(shapes[0]["shape"]["paths_truncated"])

    def test_shapes_keep_terminal_end_under_the_fixed_detail_byte_budget(self) -> None:
        rows = []
        for shape_index in range(20):
            wide = {
                f"{'😀' * 40}_{shape_index:02d}_{field_index:02d}": field_index
                for field_index in range(32)
            }
            rows.append(
                compact_json(
                    {
                        "type": f"wide_{shape_index:02d}",
                        "payload": wide,
                    }
                )
                + b"\n"
            )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(Path(temp_dir), b"".join(rows))
            completed = self.run_scan("shapes", path)
            events = self.parse_events(completed)

        end = self.assert_terminal(events, "checked")
        self.assertLessEqual(end["shapes"]["output_bytes"], 64 * 1024)
        self.assertTrue(end["shapes"]["output_truncated"])
        self.assertGreater(end["shapes"]["suppressed_shapes"], 0)
        self.assertEqual(
            end["shapes"]["emitted_shapes"]
            + end["shapes"]["suppressed_shapes"],
            end["shapes"]["retained_distinct_shapes"],
        )
        self.assertLess(len(completed.stdout), 70 * 1024)

    def test_one_worst_case_shape_is_shrunk_to_fit_the_detail_budget(self) -> None:
        wide = {
            f"{'😀' * 500}_{field_index:02d}": field_index
            for field_index in range(32)
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                compact_json(
                    {
                        "type": "😀" * 100,
                        "payload": wide,
                    }
                )
                + b"\n",
            )
            completed = self.run_scan("shapes", path)
            events = self.parse_events(completed)

        shapes = [event for event in events if event["event"] == "shape"]
        self.assertEqual(len(shapes), 1)
        self.assertTrue(shapes[0]["shape"]["paths_truncated"])
        self.assertTrue(
            all(
                len(field["path"]) <= 128
                for field in shapes[0]["shape"]["field_paths"]
            )
        )
        end = self.assert_terminal(events, "checked")
        self.assertEqual(end["shapes"]["emitted_shapes"], 1)
        self.assertEqual(end["shapes"]["suppressed_shapes"], 0)
        self.assertLessEqual(end["shapes"]["output_bytes"], 64 * 1024)

    def test_shapes_partial_summarizes_only_records_before_the_first_bad_record(
        self,
    ) -> None:
        before_secret = "SECRET_BEFORE"
        after_secret = "SECRET_AFTER"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.write_payload(
                Path(temp_dir),
                record("before", text=before_secret)
                + record("before", text=before_secret)
                + b"not-json\n"
                + record("after", text=after_secret),
            )
            completed = self.run_scan("shapes", path)
            events = self.parse_events(completed)

        shapes = [event for event in events if event["event"] == "shape"]
        self.assertEqual(len(shapes), 1)
        self.assertEqual(shapes[0]["records_observed"], 2)
        self.assertEqual(shapes[0]["shape"]["payload_type"], "before")
        self.assert_terminal(events, "partial")
        output = completed.stdout.decode("utf-8")
        self.assertNotIn(before_secret, output)
        self.assertNotIn(after_secret, output)


if __name__ == "__main__":
    unittest.main()
