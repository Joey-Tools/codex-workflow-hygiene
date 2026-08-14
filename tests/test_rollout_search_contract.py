from __future__ import annotations

import codecs
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/codex-session-mining/SKILL.md"
REFERENCE = ROOT / "skills/codex-session-mining/references/rollout-search.md"
WORKFLOW = ROOT / "skills/codex-session-mining/references/workflow.md"

MATCH_PATTERN = "needle"
CONFORMANCE_RG_VERSIONS = frozenset({(15, 2, 0)})
POSITION_SAMPLE_LIMIT = 20
PREVIEW_SAMPLE_LIMIT = 5
PREVIEW_COLUMN_LIMIT = 4096
MAX_PREVIEW_OUTPUT_BYTES = 21 * 1024
MAX_POSITION_OUTPUT_BYTES = 67_108_864
MAX_POSITION_ROW_BYTES = 256

COUNT_HEADING = "Count Before Printing Matches"
POSITION_HEADING = "Show Bounded Matching-Line Positions"
PREVIEW_HEADING = "Optionally Preview A Few Line Prefixes"
EXHAUSTIVE_HEADING = "Exceptional Exhaustive Matching-Line Artifact"
PROTOCOL_HEADINGS = (
    COUNT_HEADING,
    POSITION_HEADING,
    PREVIEW_HEADING,
    EXHAUSTIVE_HEADING,
)

FIXED_RG_ARGV = [
    "$RG_BIN",
    "--no-config",
    "--no-mmap",
    "--text",
    "--encoding",
    "none",
    "--no-heading",
    "--no-filename",
    "--color",
    "never",
    "--fixed-strings",
    "--case-sensitive",
]
EXPECTED_COMMAND_ARGV = {
    COUNT_HEADING: FIXED_RG_ARGV
    + [
        "--count-matches",
        "--include-zero",
        "--",
        "$PATTERN",
        "-",
        "<",
        "$ROLLOUT",
    ],
    POSITION_HEADING: FIXED_RG_ARGV
    + [
        "--line-number",
        "--column",
        "--byte-offset",
        "--max-count",
        "20",
        "--max-columns",
        "1",
        "--",
        "$PATTERN",
        "-",
        "<",
        "$ROLLOUT",
    ],
    PREVIEW_HEADING: FIXED_RG_ARGV
    + [
        "--line-number",
        "--column",
        "--byte-offset",
        "--max-count",
        "5",
        "--max-columns",
        "4096",
        "--max-columns-preview",
        "--",
        "$PATTERN",
        "-",
        "<",
        "$ROLLOUT",
    ],
    EXHAUSTIVE_HEADING: FIXED_RG_ARGV
    + [
        "--line-number",
        "--column",
        "--byte-offset",
        "--max-count",
        "$COUNT",
        "--max-columns",
        "1",
        "--",
        "$PATTERN",
        "-",
        "<",
        "$ROLLOUT",
        ">",
        "$ARTIFACT",
    ],
}


def extract_protocol_template(
    reference_text: str, heading: str
) -> tuple[str, list[str]]:
    section_match = re.search(
        rf"^## {re.escape(heading)}\s*$\n(?P<body>.*?)(?=^##\s|\Z)",
        reference_text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if section_match is None:
        raise AssertionError(f"missing protocol heading: {heading}")

    fenced_blocks = re.finditer(
        r"^```(?:bash|sh)\s*$\n(?P<command>.*?)^```\s*$",
        section_match.group("body"),
        flags=re.MULTILINE | re.DOTALL,
    )
    for fenced_block in fenced_blocks:
        shell_block = fenced_block.group("command")
        logical_block = re.sub(r"\\\r?\n[ \t]*", " ", shell_block)
        try:
            shell_argv = shlex.split(logical_block, posix=True)
        except ValueError as error:
            raise AssertionError(
                f"invalid shell quoting under protocol heading {heading!r}"
            ) from error
        if "$RG_BIN" not in shell_argv:
            continue
        rg_argv = shell_argv[shell_argv.index("$RG_BIN") :]
        if "&&" in rg_argv:
            rg_argv = rg_argv[: rg_argv.index("&&")]
        if rg_argv and rg_argv[-1] == ")":
            rg_argv = rg_argv[:-1]
        if "--" in rg_argv and {"$PATTERN", "$ROLLOUT"} <= set(rg_argv):
            return shell_block, rg_argv

    raise AssertionError(f"missing rollout-search rg command under heading: {heading}")


def load_protocol_templates(
    reference_text: str,
) -> dict[str, tuple[str, list[str]]]:
    return {
        heading: extract_protocol_template(reference_text, heading)
        for heading in PROTOCOL_HEADINGS
    }


def join_shell_continuations(shell_block: str) -> str:
    return re.sub(r"\\\r?\n[ \t]*", " ", shell_block)


def instantiate_protocol_command(
    template: list[str],
    *,
    rg: str,
    path: Path,
    pattern: str = MATCH_PATTERN,
    count: int | None = None,
) -> tuple[list[str], Path]:
    substitutions = {
        "$RG_BIN": rg,
        "$PATTERN": pattern,
        "$ROLLOUT": str(path),
    }
    if count is not None:
        substitutions["$COUNT"] = str(count)
    instantiated = [substitutions.get(argument, argument) for argument in template]
    try:
        stdin_index = instantiated.index("<")
        stdin_path = Path(instantiated[stdin_index + 1])
    except (ValueError, IndexError) as error:
        raise AssertionError("documented command lacks stdin redirection") from error

    output_index = instantiated.index(">") if ">" in instantiated else len(instantiated)
    argv = instantiated[:stdin_index] + instantiated[stdin_index + 2 : output_index]
    unresolved = [argument for argument in argv if argument.startswith("$")]
    if unresolved:
        raise AssertionError(f"unresolved command placeholders: {unresolved!r}")
    return argv, stdin_path


def parse_position_rows(output: bytes) -> list[tuple[int, int, int, bytes]]:
    rows: list[tuple[int, int, int, bytes]] = []
    for row in output.splitlines():
        fields = row.split(b":", 3)
        if len(fields) != 4:
            raise AssertionError(f"position row lacks four fields: {row!r}")
        try:
            line, column, offset = (int(field) for field in fields[:3])
        except ValueError as error:
            raise AssertionError(
                f"position row has a non-numeric prefix: {row!r}"
            ) from error
        rows.append((line, column, offset, fields[3]))
    return rows


def parse_rg_version(output: bytes) -> tuple[int, int, int] | None:
    match = re.match(rb"ripgrep (\d+)\.(\d+)\.(\d+)(?:\s|$)", output)
    if match is None:
        return None
    return tuple(int(component) for component in match.groups())


def extract_field_aware_parser() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
    start = workflow.index(marker) + len(marker)
    return workflow[start : workflow.index("\nPY\n```", start)]


def user_message_json(message: str, *, ensure_ascii: bool = True) -> str:
    return json.dumps(
        {
            "type": "event_msg",
            "payload": {"type": "user_message", "message": message},
        },
        ensure_ascii=ensure_ascii,
        separators=(",", ":"),
    )


def user_message_record(message: str, *, ensure_ascii: bool = True) -> bytes:
    return (user_message_json(message, ensure_ascii=ensure_ascii) + "\n").encode(
        "utf-8"
    )


def run_field_aware_parser_bytes(
    payload: bytes,
    needle: str = MATCH_PATTERN,
    parser_code: str | None = None,
    timeout: float | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    with tempfile.TemporaryDirectory() as temp_dir:
        rollout = Path(temp_dir) / "rollout.jsonl"
        rollout.write_bytes(payload)
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                parser_code or extract_field_aware_parser(),
                str(rollout),
                needle,
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        return completed, str(rollout)


class RolloutSearchReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.skill_text = SKILL.read_text(encoding="utf-8")
        cls.reference_text = REFERENCE.read_text(encoding="utf-8")
        cls.reference_lower = cls.reference_text.lower()
        cls.templates = load_protocol_templates(cls.reference_text)

    def test_skill_links_rollout_search_reference(self) -> None:
        self.assertIn(
            "[references/rollout-search.md](references/rollout-search.md)",
            self.skill_text,
        )

    def test_conformance_set_does_not_pin_host_tooling(self) -> None:
        self.assertEqual(parse_rg_version(b"ripgrep 15.2.0 (rev abc)\n"), (15, 2, 0))
        self.assertEqual(parse_rg_version(b"ripgrep 16.0.1\n"), (16, 0, 1))
        self.assertIn((15, 2, 0), CONFORMANCE_RG_VERSIONS)
        self.assertNotIn((16, 0, 1), CONFORMANCE_RG_VERSIONS)
        self.assertIsNone(parse_rg_version(b"ripgrep development build\n"))

    def test_reference_limits_input_and_qualifies_rg_version(self) -> None:
        self.assertIn("one exact regular rollout file", self.reference_lower)
        self.assertIn("explicit `-` path makes ripgrep read stdin", self.reference_lower)
        self.assertIn("input redirection supplies that one stream", self.reference_lower)
        self.assertIn(
            "case-sensitive literal pattern whose unicode-whitespace-normalized form is non-empty and at most 1024 utf-8 bytes",
            self.reference_lower,
        )
        self.assertIn(
            "reject an empty, whitespace-only, invalid-utf-8, or oversized pattern",
            self.reference_lower,
        )
        self.assertIn("no optional matching flags", self.reference_lower)
        self.assertIn("different ripgrep query may be useful for orientation", self.reference_lower)
        self.assertIn("outside this protocol", self.reference_lower)
        self.assertIn("do not reuse its counts", self.reference_lower)
        self.assertIn("current conformance-qualified version set is exactly ripgrep 15.2.0", self.reference_lower)
        self.assertIn("not a developer-machine pin", self.reference_lower)
        self.assertIn("including a newer version", self.reference_lower)
        self.assertIn("skip every raw ripgrep template", self.reference_lower)
        self.assertIn("future floating compatibility range or stronger executable binding requires a helper", self.reference_lower)
        self.assertIn("execution-time bounded private stdout and stderr sink", self.reference_lower)
        self.assertIn("output release only after validation", self.reference_lower)
        self.assertIn("resolve ripgrep once with `command -v rg`", self.reference_lower)
        self.assertIn("keep the same unchanged `rg_bin` value", self.reference_lower)
        self.assertIn("never re-resolve a bare `rg`", self.reference_lower)
        self.assertIn("do not authenticate an opened executable object", self.reference_lower)
        for flag in ("--fixed-strings", "--case-sensitive"):
            with self.subTest(flag=flag):
                self.assertIn(f"`{flag}`", self.reference_text)

    def test_reference_states_count_exit_semantics(self) -> None:
        for expected in (
            "Exit `0`: stdout is a positive decimal match count",
            "Exit `1`: stdout is exactly `0`",
            "Exit `2` or greater: the search failed",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.reference_text)

    def test_reference_distinguishes_occurrences_from_matching_lines(self) -> None:
        self.assertIn("number of non-overlapping raw literal occurrences", self.reference_lower)
        self.assertIn("not the number of matching lines", self.reference_lower)
        self.assertIn("one line can therefore contribute multiple matches", self.reference_lower)
        self.assertIn("raw count of zero does not prove", self.reference_lower)
        self.assertIn(
            "selected-field result and terminal `scan_meta` are authoritative",
            self.reference_lower,
        )

    def test_reference_marks_output_as_raw_sensitive(self) -> None:
        self.assertIn("not a match-centered excerpt", self.reference_lower)
        self.assertIn("raw source data", self.reference_lower)
        self.assertIn("terminal-unsafe", self.reference_lower)
        self.assertRegex(self.reference_lower, r"expose .*sensitive content")

    def test_reference_states_key_non_guarantees(self) -> None:
        for expected in (
            "does not parse the rollout schema",
            "not a runtime, rss, stderr, input-read, or privacy bound",
            "equal counts still do not freeze",
            "position output is always a bounded sample",
            "continue through point-in-time eof",
            "noclobber is not a general `o_excl`/no-follow primitive",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.reference_lower)

    def test_reference_pins_each_protocol_command_shape(self) -> None:
        for heading, expected_argv in EXPECTED_COMMAND_ARGV.items():
            with self.subTest(heading=heading):
                shell_block, actual_argv = self.templates[heading]
                self.assertEqual(actual_argv, expected_argv)
                logical_block = join_shell_continuations(shell_block)
                self.assertRegex(
                    logical_block,
                    re.compile(r'-- "\$PATTERN"\s+-\s+< "\$ROLLOUT"'),
                )

        exhaustive_block = join_shell_continuations(
            self.templates[EXHAUSTIVE_HEADING][0]
        )
        self.assertRegex(exhaustive_block, re.compile(r'--max-count "\$COUNT"'))
        self.assertRegex(
            exhaustive_block,
            re.compile(r'-\s+< "\$ROLLOUT"\s+> "\$ARTIFACT"'),
        )
        self.assertRegex(
            exhaustive_block,
            re.compile(r'test -f "\$ARTIFACT"'),
        )

    def test_field_aware_parser_scans_past_output_cap_and_reports_coverage(self) -> None:
        code = extract_field_aware_parser()

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout.jsonl"
            records = [b"not-json\n", b"[]\n", b"x" * (1024 * 1024 + 1) + b"\n"]
            records.extend(
                (
                    json.dumps(
                        {
                            "type": "event_msg",
                            "payload": {
                                "type": "user_message",
                                "message": f"needle row {index}",
                            },
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                for index in range(22)
            )
            rollout.write_bytes(b"".join(records))
            completed = subprocess.run(
                [sys.executable, "-c", code, str(rollout), MATCH_PATTERN],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), POSITION_SAMPLE_LIMIT)
        metadata_lines = completed.stderr.splitlines()
        self.assertEqual(len(metadata_lines), 1)
        metadata = json.loads(metadata_lines[0])
        self.assertEqual(
            metadata,
            {
                "emitted_rows": 20,
                "invalid_records": 2,
                "kind": "scan_meta",
                "matched_records": 22,
                "max_rows": 20,
                "output_truncated": True,
                "oversized_records": 1,
                "records_seen": 25,
                "scan_complete": True,
                "stop_reason": None,
                "suppressed_rows": 2,
            },
        )

    def test_field_aware_parser_handles_json_pathologies_after_output_cap(self) -> None:
        code = extract_field_aware_parser()
        nested_depth = 996
        deep_message = (
            '{"first":"deep-first","nested":'
            + '{"node":' * nested_depth
            + '"needle"'
            + '}' * nested_depth
            + ',"last":"deep-last"}'
        )
        deep_record = (
            '{"type":"event_msg","payload":{"type":"user_message","message":'
            + deep_message
            + '}}\n'
        ).encode("utf-8")
        ordinary_records = [
            (
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "user_message",
                            "message": f"needle row {index}",
                        },
                    },
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            for index in range(20)
        ]
        final_record = (
            json.dumps(
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "user_message",
                        "message": "needle after pathologies",
                    },
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        self.assertIsInstance(json.loads(deep_record), dict)

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout.jsonl"
            rollout.write_bytes(
                b"".join(
                    ordinary_records
                    + [b"9" * 5000 + b"\n", deep_record, final_record]
                )
            )
            completed = subprocess.run(
                [sys.executable, "-c", code, str(rollout), MATCH_PATTERN],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), POSITION_SAMPLE_LIMIT)
        metadata = json.loads(completed.stderr)
        self.assertEqual(
            metadata,
            {
                "emitted_rows": 20,
                "invalid_records": 1,
                "kind": "scan_meta",
                "matched_records": 22,
                "max_rows": 20,
                "output_truncated": True,
                "oversized_records": 0,
                "records_seen": 23,
                "scan_complete": True,
                "stop_reason": None,
                "suppressed_rows": 2,
            },
        )

    def test_field_aware_parser_preserves_deep_selected_field_order(self) -> None:
        nested_depth = 996
        deep_message = (
            '{"first":"deep-first","nested":'
            + '{"node":' * nested_depth
            + '"needle"'
            + '}' * nested_depth
            + ',"last":"deep-last"}'
        )
        record = (
            '{"type":"event_msg","payload":{"type":"user_message","message":'
            + deep_message
            + '}}\n'
        )
        needle = "deep-first needle deep-last"

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout.jsonl"
            rollout.write_text(record, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-c", extract_field_aware_parser(), str(rollout), needle],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(needle, completed.stdout)
        metadata = json.loads(completed.stderr)
        self.assertTrue(metadata["scan_complete"])
        self.assertEqual(metadata["matched_records"], 1)
        self.assertEqual(metadata["invalid_records"], 0)
        self.assertFalse(metadata["output_truncated"])

    def test_field_aware_parser_rejects_non_utf8_json_encodings(self) -> None:
        non_utf8_json = user_message_json("needle in a non-UTF-8 record")
        encodings = ("utf-16-be", "utf-32-be")
        encoded_records = [
            (non_utf8_json + "\n").encode(encoding) for encoding in encodings
        ]
        self.assertTrue(
            all(
                isinstance(json.loads(record), dict)
                for record in encoded_records
            )
        )
        completed, _ = run_field_aware_parser_bytes(
            b"".join(encoded_records + [user_message_record("needle in valid UTF-8")])
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertIn("needle in valid UTF-8", completed.stdout)
        self.assertNotIn("non-UTF-8 record", completed.stdout)
        metadata = json.loads(completed.stderr)
        self.assertEqual(
            metadata,
            {
                "emitted_rows": 1,
                "invalid_records": 2,
                "kind": "scan_meta",
                "matched_records": 1,
                "max_rows": 20,
                "output_truncated": False,
                "oversized_records": 0,
                "records_seen": 3,
                "scan_complete": True,
                "stop_reason": None,
                "suppressed_rows": 0,
            },
        )

    def test_field_aware_parser_rejects_little_endian_json_at_eof(self) -> None:
        non_utf8_json = user_message_json("needle in a little-endian record")
        expected_metadata = {
            "emitted_rows": 0,
            "invalid_records": 1,
            "kind": "scan_meta",
            "matched_records": 0,
            "max_rows": 20,
            "output_truncated": False,
            "oversized_records": 0,
            "records_seen": 1,
            "scan_complete": True,
            "stop_reason": None,
            "suppressed_rows": 0,
        }

        for encoding, bom in (
            ("utf-16-le", codecs.BOM_UTF16_LE),
            ("utf-16-le", b""),
            ("utf-32-le", codecs.BOM_UTF32_LE),
            ("utf-32-le", b""),
        ):
            with self.subTest(encoding=encoding, bom=bool(bom)):
                raw_record = bom + non_utf8_json.encode(encoding)
                self.assertIsInstance(json.loads(raw_record), dict)
                completed, _ = run_field_aware_parser_bytes(raw_record)

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(json.loads(completed.stderr), expected_metadata)

    def test_field_aware_parser_recovers_after_little_endian_newline(self) -> None:
        non_utf8_json = user_message_json("needle in a little-endian record")
        valid_record = user_message_record("needle in valid UTF-8")
        expected_metadata = {
            "emitted_rows": 1,
            "invalid_records": 1,
            "kind": "scan_meta",
            "matched_records": 1,
            "max_rows": 20,
            "output_truncated": False,
            "oversized_records": 0,
            "records_seen": 2,
            "scan_complete": True,
            "stop_reason": None,
            "suppressed_rows": 0,
        }

        for encoding, bom in (
            ("utf-16-le", codecs.BOM_UTF16_LE),
            ("utf-16-le", b""),
            ("utf-32-le", codecs.BOM_UTF32_LE),
            ("utf-32-le", b""),
        ):
            with self.subTest(encoding=encoding, bom=bool(bom)):
                foreign_record = bom + (non_utf8_json + "\n").encode(encoding)
                self.assertIsInstance(json.loads(foreign_record), dict)
                completed, rollout = run_field_aware_parser_bytes(
                    foreign_record + valid_record
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(len(completed.stdout.splitlines()), 1)
                self.assertIn(f"{rollout}:2:", completed.stdout)
                self.assertIn("needle in valid UTF-8", completed.stdout)
                self.assertNotIn("little-endian record", completed.stdout)
                self.assertEqual(json.loads(completed.stderr), expected_metadata)

    def test_field_aware_parser_recovers_short_inferred_little_endian_json(
        self,
    ) -> None:
        foreign_record = "0\n".encode("utf-16-le")
        valid_record = user_message_record("needle after short foreign JSON")
        self.assertEqual(foreign_record, b"0\x00\n\x00")
        self.assertEqual(json.loads(foreign_record), 0)

        completed, rollout = run_field_aware_parser_bytes(
            foreign_record + valid_record
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"{rollout}:2:", completed.stdout)
        self.assertIn("needle after short foreign JSON", completed.stdout)
        metadata = json.loads(completed.stderr)
        self.assertEqual(metadata["records_seen"], 2)
        self.assertEqual(metadata["invalid_records"], 1)
        self.assertEqual(metadata["matched_records"], 1)
        self.assertTrue(metadata["scan_complete"])

    def test_field_aware_parser_rolls_back_unproved_little_endian_prefix(
        self,
    ) -> None:
        valid_record = user_message_record("needle after unproved prefix")
        valid_json = user_message_json("foreign unselected value")
        for name, candidate, preserves_following_record in (
            ("utf16-padding-mismatch", b'{\x00"\x00oops\n', True),
            ("utf32-padding-mismatch", b'{\x00\x00\x00"\x00\x00\x00oops\n', True),
            ("utf16-hybrid-lf", valid_json.encode("utf-16-le") + b"\n", True),
            ("utf32-hybrid-lf", valid_json.encode("utf-32-le") + b"\n", True),
            ("utf16-malformed-json", '{"x":,}\n'.encode("utf-16-le"), False),
            ("utf32-malformed-json", '{"x":,}\n'.encode("utf-32-le"), False),
        ):
            with self.subTest(name=name):
                completed, rollout = run_field_aware_parser_bytes(
                    candidate + valid_record
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                metadata = json.loads(completed.stderr)
                self.assertEqual(metadata["records_seen"], 2)
                self.assertTrue(metadata["scan_complete"])
                if preserves_following_record:
                    self.assertIn(f"{rollout}:2:", completed.stdout)
                    self.assertIn(
                        "needle after unproved prefix", completed.stdout
                    )
                    self.assertEqual(metadata["invalid_records"], 1)
                    self.assertEqual(metadata["matched_records"], 1)
                else:
                    self.assertEqual(completed.stdout, "")
                    self.assertEqual(metadata["invalid_records"], 2)
                    self.assertEqual(metadata["matched_records"], 0)

    def test_inferred_little_endian_json_is_fully_validated_once(self) -> None:
        foreign_json = user_message_json(
            "\u010a" * 32,
            ensure_ascii=False,
        ) + "\n"
        self.assertIsInstance(json.loads(foreign_json), dict)
        parser_code = extract_field_aware_parser()
        injection_point = "path = Path(sys.argv[1])"
        validation_guard = """
real_json_loads = json.loads
json_load_calls = 0


def single_json_loads(value, *args, **kwargs):
    global json_load_calls
    if isinstance(value, str) and '\\x00' not in value:
        json_load_calls += 1
        if json_load_calls > 1:
            raise RuntimeError('inferred candidate was fully validated more than once')
    return real_json_loads(value, *args, **kwargs)


json.loads = single_json_loads
"""
        self.assertIn(injection_point, parser_code)
        parser_code = parser_code.replace(
            injection_point,
            validation_guard + "\n" + injection_point,
            1,
        )

        completed, _ = run_field_aware_parser_bytes(
            foreign_json.encode("utf-16-le"),
            parser_code=parser_code,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        metadata = json.loads(completed.stderr)
        self.assertEqual(metadata["records_seen"], 1)
        self.assertEqual(metadata["invalid_records"], 1)
        self.assertEqual(metadata["matched_records"], 0)
        self.assertTrue(metadata["scan_complete"])

    def test_inferred_little_endian_probe_caps_overlapping_failures(self) -> None:
        candidate_lines = 4_000
        valid_record = user_message_record("needle after adversarial prefixes")

        completed, _ = run_field_aware_parser_bytes(
            b"{\x00\n" * candidate_lines + valid_record,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("needle after adversarial prefixes", completed.stdout)
        metadata = json.loads(completed.stderr)
        self.assertEqual(metadata["records_seen"], candidate_lines + 1)
        self.assertEqual(metadata["invalid_records"], candidate_lines)
        self.assertEqual(metadata["matched_records"], 1)
        self.assertTrue(metadata["scan_complete"])

    def test_inferred_little_endian_probe_enforces_fragment_boundary(self) -> None:
        valid_record = user_message_record("needle after fragment boundary")
        for width, internal_fragments, should_commit in (
            (width, internal_fragments, should_commit)
            for width in (2, 4)
            for internal_fragments, should_commit in ((63, True), (64, False))
        ):
            encoding = f"utf-{width * 8}-le"
            foreign_json = user_message_json(
                "\u010a" * internal_fragments,
                ensure_ascii=False,
            ) + "\n"
            self.assertIsInstance(json.loads(foreign_json), dict)

            with self.subTest(width=width, fragments=internal_fragments + 1):
                completed, _ = run_field_aware_parser_bytes(
                    foreign_json.encode(encoding) + valid_record
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                metadata = json.loads(completed.stderr)
                self.assertTrue(metadata["scan_complete"])
                if should_commit:
                    self.assertIn(
                        "needle after fragment boundary", completed.stdout
                    )
                    self.assertEqual(metadata["matched_records"], 1)
                else:
                    self.assertEqual(completed.stdout, "")
                    self.assertEqual(metadata["matched_records"], 0)
                    self.assertGreater(metadata["invalid_records"], 0)

    def test_inferred_little_endian_json_supports_root_shapes(self) -> None:
        valid_record = user_message_record("needle after foreign root")
        root_values = (
            '"escaped \\\" quote"',
            "[1,{\"nested\":true}]",
            "0",
            "-1.2e+3",
            "true",
            "false",
            "null",
        )

        for width, root_value in (
            (width, root_value)
            for width in (2, 4)
            for root_value in root_values
        ):
            encoding = f"utf-{width * 8}-le"
            with self.subTest(width=width, root_value=root_value):
                foreign_record = (root_value + "\n").encode(encoding)
                self.assertEqual(json.loads(foreign_record), json.loads(root_value))
                completed, rollout = run_field_aware_parser_bytes(
                    foreign_record + valid_record
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("needle after foreign root", completed.stdout)
                metadata = json.loads(completed.stderr)
                self.assertEqual(metadata["records_seen"], 2)
                self.assertEqual(metadata["invalid_records"], 1)
                self.assertEqual(metadata["matched_records"], 1)
                self.assertTrue(metadata["scan_complete"])

    def test_field_aware_parser_does_not_strip_extra_nul(self) -> None:
        non_utf8_json = json.dumps(
            {"type": "event_msg", "payload": {"type": "user_message"}},
            separators=(",", ":"),
        )
        valid_record = user_message_record("needle after extra NUL")

        for encoding, bom in (
            ("utf-16-le", codecs.BOM_UTF16_LE),
            ("utf-16-le", b""),
            ("utf-32-le", codecs.BOM_UTF32_LE),
            ("utf-32-le", b""),
        ):
            with self.subTest(encoding=encoding, bom=bool(bom)):
                foreign_record = bom + (non_utf8_json + "\n").encode(encoding)
                completed, _ = run_field_aware_parser_bytes(
                    foreign_record + b"\x00{}\n" + valid_record
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("needle after extra NUL", completed.stdout)
                metadata = json.loads(completed.stderr)
                self.assertEqual(metadata["records_seen"], 3)
                self.assertEqual(metadata["invalid_records"], 2)
                self.assertEqual(metadata["matched_records"], 1)
                self.assertTrue(metadata["scan_complete"])

    def test_field_aware_parser_drains_oversized_little_endian_record(self) -> None:
        max_record_bytes = 1024 * 1024
        valid_record = user_message_record("needle after oversized record")

        for width, bom in (
            (2, codecs.BOM_UTF16_LE),
            (4, codecs.BOM_UTF32_LE),
        ):
            with self.subTest(width=width):
                encoded_a = b"a" + b"\x00" * (width - 1)
                foreign_record = (
                    bom
                    + encoded_a * (max_record_bytes // width + 8)
                    + b"\n"
                    + b"\x00" * (width - 1)
                )
                completed, _ = run_field_aware_parser_bytes(
                    foreign_record + valid_record
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("needle after oversized record", completed.stdout)
                metadata = json.loads(completed.stderr)
                self.assertEqual(metadata["records_seen"], 2)
                self.assertEqual(metadata["invalid_records"], 0)
                self.assertEqual(metadata["oversized_records"], 1)
                self.assertEqual(metadata["matched_records"], 1)
                self.assertTrue(metadata["scan_complete"])

    def test_field_aware_parser_recovers_across_buffer_boundary(self) -> None:
        valid_record = user_message_record("needle after buffer boundary")
        prefix = b" { }\n"
        foreign_text = "{}" + " " * 2043
        foreign_record = codecs.BOM_UTF32_LE + (
            foreign_text + "\n"
        ).encode("utf-32-le")
        self.assertEqual(len(prefix), 5)
        self.assertEqual(len(foreign_record), 8188)

        completed, _ = run_field_aware_parser_bytes(
            prefix + foreign_record + valid_record
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("needle after buffer boundary", completed.stdout)
        metadata = json.loads(completed.stderr)
        self.assertEqual(metadata["records_seen"], 3)
        self.assertEqual(metadata["invalid_records"], 1)
        self.assertEqual(metadata["matched_records"], 1)
        self.assertTrue(metadata["scan_complete"])

    def test_field_aware_parser_skips_raw_lf_bytes_inside_foreign_code_units(
        self,
    ) -> None:
        foreign_json = user_message_json(
            "U+010A \u010a and U+0A00 \u0a00 are not line terminators",
            ensure_ascii=False,
        )
        valid_record = user_message_record("needle after foreign raw LF byte")

        for encoding, bom in (
            ("utf-16-le", codecs.BOM_UTF16_LE),
            ("utf-16-le", b""),
            ("utf-32-le", codecs.BOM_UTF32_LE),
            ("utf-32-le", b""),
        ):
            with self.subTest(encoding=encoding, bom=bool(bom)):
                foreign_record = bom + (foreign_json + "\n").encode(encoding)
                self.assertIsInstance(json.loads(foreign_record), dict)
                completed, rollout = run_field_aware_parser_bytes(
                    foreign_record + valid_record
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(f"{rollout}:4:", completed.stdout)
                self.assertIn("needle after foreign raw LF byte", completed.stdout)
                metadata = json.loads(completed.stderr)
                self.assertEqual(metadata["records_seen"], 2)
                self.assertEqual(metadata["invalid_records"], 1)
                self.assertEqual(metadata["matched_records"], 1)
                self.assertTrue(metadata["scan_complete"])

    def test_field_aware_parser_rejects_whitespace_only_needle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout.jsonl"
            rollout.write_text('{"type":"event_msg"}\n', encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    extract_field_aware_parser(),
                    str(rollout),
                    " \t\u00a0 ",
                ],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            completed.stderr, "NEEDLE must contain non-whitespace text\n"
        )

    def test_field_aware_parser_enforces_utf8_needle_byte_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout.jsonl"
            accepted_needle = "😀" * 256
            rollout.write_text(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "user_message",
                            "message": accepted_needle,
                        },
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            code = extract_field_aware_parser()
            accepted = subprocess.run(
                [sys.executable, "-c", code, str(rollout), accepted_needle],
                capture_output=True,
                check=False,
                text=True,
            )
            rejected = subprocess.run(
                [sys.executable, "-c", code, str(rollout), accepted_needle + "x"],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(len(accepted.stdout.splitlines()), 1)
        accepted_metadata = json.loads(accepted.stderr)
        self.assertEqual(accepted_metadata["matched_records"], 1)
        self.assertTrue(accepted_metadata["scan_complete"])
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, "")
        self.assertEqual(
            rejected.stderr, "NEEDLE must be at most 1024 UTF-8 bytes\n"
        )

    def test_exhaustive_block_pins_complete_shell_structure(self) -> None:
        shell_block = self.templates[EXHAUSTIVE_HEADING][0]
        logical_block = re.sub(r"\\\r?\n[ \t]*", " ", shell_block)
        self.assertEqual(
            shlex.split(logical_block, posix=True),
            ["(", "set", "-C", "umask", "077"]
            + EXPECTED_COMMAND_ARGV[EXHAUSTIVE_HEADING]
            + ["&&", "test", "-f", "$ARTIFACT", ")"],
        )
        for line in (r"^\(\s*$", r"^\s*set -C\s*$", r"^\s*umask 077\s*$", r"^\)\s*$"):
            with self.subTest(line=line):
                self.assertRegex(shell_block, re.compile(line, re.MULTILINE))


class RipgrepConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        reference_text = REFERENCE.read_text(encoding="utf-8")
        cls.templates = load_protocol_templates(reference_text)
        rg = shutil.which("rg")
        failure = "ripgrep is not installed"
        if rg is not None:
            version = subprocess.run(
                [rg, "--version"], capture_output=True, check=False
            )
            parsed_version = parse_rg_version(version.stdout)
            if version.returncode == 0 and parsed_version is not None:
                failure = "dynamic contract requires a conformance-qualified ripgrep version"
                if parsed_version in CONFORMANCE_RG_VERSIONS:
                    cls.rg = rg
                    return
            else:
                failure = "unable to determine ripgrep semantic version"
        if any(
            os.environ.get(variable, "").lower() == "true"
            for variable in ("GITHUB_ACTIONS", "CI")
        ):
            raise AssertionError(failure)
        raise unittest.SkipTest(failure)

    def run_protocol(
        self,
        heading: str,
        path: Path,
        *,
        pattern: str = MATCH_PATTERN,
        count: int | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        argv, stdin_path = instantiate_protocol_command(
            self.templates[heading][1],
            rg=self.rg,
            path=path,
            pattern=pattern,
            count=count,
        )
        with stdin_path.open("rb") as stdin:
            return subprocess.run(
                argv, stdin=stdin, capture_output=True, check=False
            )

    def run_protocol_shell(
        self,
        heading: str,
        *,
        rollout: Path,
        pattern: str,
        search_path: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = {
            "LC_ALL": "C",
            "PATH": search_path or str(Path(self.rg).parent),
            "PATTERN": pattern,
            "RG_BIN": self.rg,
            "ROLLOUT": str(rollout),
        }
        return subprocess.run(
            [
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                self.templates[heading][0],
            ],
            cwd=rollout.parent,
            env=environment,
            capture_output=True,
            check=False,
        )

    def run_exhaustive_shell(
        self, *, rollout: Path, artifact: Path, count: int
    ) -> subprocess.CompletedProcess[bytes]:
        environment = {
            "ARTIFACT": str(artifact),
            "COUNT": str(count),
            "LC_ALL": "C",
            "PATH": str(Path(self.rg).parent),
            "PATTERN": MATCH_PATTERN,
            "RG_BIN": self.rg,
            "ROLLOUT": str(rollout),
        }
        return subprocess.run(
            [
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                self.templates[EXHAUSTIVE_HEADING][0],
            ],
            cwd=rollout.parent,
            env=environment,
            capture_output=True,
            check=False,
        )

    def test_count_statuses_and_literal_occurrence_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rollout-fixture.jsonl"
            path.write_text("needle needle\nno match\nneedle\nlast needle\n", encoding="utf-8")
            matched = self.run_protocol(COUNT_HEADING, path)
            self.assertEqual((matched.returncode, matched.stdout), (0, b"4\n"))

            path.write_text("nothing relevant\n", encoding="utf-8")
            unmatched = self.run_protocol(COUNT_HEADING, path)
            self.assertEqual((unmatched.returncode, unmatched.stdout), (1, b"0\n"))

            path.write_text("literal [ metacharacter\n", encoding="utf-8")
            literal = self.run_protocol(COUNT_HEADING, path, pattern="[")
            self.assertEqual((literal.returncode, literal.stdout), (0, b"1\n"))

    def test_documented_shell_preserves_pattern_and_rollout_as_single_words(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rollout = temp / "rollout fixture [one].jsonl"
            pattern = "alpha.*beta gamma"
            rollout.write_text(
                "alphaZZbeta gamma\nalpha.*beta gamma\n", encoding="utf-8"
            )
            (temp / "alpha.zzbeta").write_text("decoy\n", encoding="utf-8")
            (temp / "gamma").write_text("decoy\n", encoding="utf-8")

            expected_rows = {
                COUNT_HEADING: 1,
                POSITION_HEADING: 1,
                PREVIEW_HEADING: 1,
            }
            for heading, expected_row_count in expected_rows.items():
                with self.subTest(heading=heading):
                    completed = self.run_protocol_shell(
                        heading, rollout=rollout, pattern=pattern
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    if heading == COUNT_HEADING:
                        self.assertEqual(completed.stdout, b"1\n")
                    else:
                        self.assertEqual(
                            len(parse_position_rows(completed.stdout)),
                            expected_row_count,
                        )

    def test_documented_shell_reuses_qualified_rg_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rollout = temp / "rollout-fixture.jsonl"
            rollout.write_text("needle\n", encoding="utf-8")
            fake_bin = temp / "fake-bin"
            fake_bin.mkdir()
            fake_rg = fake_bin / "rg"
            fake_rg.write_text(
                "#!/bin/sh\nprintf 'path-hijack\\n'\n",
                encoding="utf-8",
            )
            fake_rg.chmod(0o700)

            completed = self.run_protocol_shell(
                COUNT_HEADING,
                rollout=rollout,
                pattern=MATCH_PATTERN,
                search_path=str(fake_bin),
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b"1\n")

    def test_raw_zero_does_not_override_selected_field_literal_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rollout-fixture.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "user_message",
                            "message": "needle\u00a0value",
                        },
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )

            raw = self.run_protocol(
                COUNT_HEADING, path, pattern="needle value"
            )
            self.assertEqual((raw.returncode, raw.stdout), (1, b"0\n"))

            parsed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    extract_field_aware_parser(),
                    str(path),
                    "needle value",
                ],
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        self.assertEqual(len(parsed.stdout.splitlines()), 1)
        metadata = json.loads(parsed.stderr)
        self.assertTrue(metadata["scan_complete"])
        self.assertEqual(metadata["matched_records"], 1)
        self.assertEqual(metadata["invalid_records"], 0)
        self.assertEqual(metadata["oversized_records"], 0)
        self.assertFalse(metadata["output_truncated"])

    def test_documented_shell_does_not_fall_back_to_searching_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rollout_directory = temp / "not-a-rollout"
            rollout_directory.mkdir()
            (temp / "decoy.jsonl").write_text("needle\n", encoding="utf-8")

            for heading in (COUNT_HEADING, POSITION_HEADING, PREVIEW_HEADING):
                with self.subTest(heading=heading):
                    completed = self.run_protocol_shell(
                        heading,
                        rollout=rollout_directory,
                        pattern=MATCH_PATTERN,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stdout, b"")

            artifact = temp / "positions.txt"
            exhaustive = self.run_exhaustive_shell(
                rollout=rollout_directory,
                artifact=artifact,
                count=1,
            )
            self.assertNotEqual(exhaustive.returncode, 0)
            self.assertEqual(artifact.read_bytes(), b"")

    def test_live_growth_keeps_position_sample_bounded_and_requires_recount(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rollout-fixture.jsonl"
            path.write_text("needle needle\n", encoding="utf-8")
            initial_count = self.run_protocol(COUNT_HEADING, path)
            self.assertEqual((initial_count.returncode, initial_count.stdout), (0, b"2\n"))

            with path.open("a", encoding="utf-8") as rollout:
                rollout.write(
                    "".join(f"row {index} needle\n" for index in range(2, 31))
                )
            completed = self.run_protocol(POSITION_HEADING, path)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            rows = parse_position_rows(completed.stdout)
            self.assertEqual(len(rows), POSITION_SAMPLE_LIMIT)
            self.assertEqual([row[0] for row in rows], list(range(1, 21)))
            self.assertEqual(sum(row[0] == 1 for row in rows), 1)

            final_count = self.run_protocol(COUNT_HEADING, path)
            self.assertEqual((final_count.returncode, final_count.stdout), (0, b"31\n"))

    def test_preview_caps_rows_and_utf8_boundary_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rollout-fixture.jsonl"
            path.write_text(
                "".join(f"preview {index} needle\n" for index in range(1, 9)),
                encoding="utf-8",
            )
            normal = self.run_protocol(PREVIEW_HEADING, path)
            self.assertEqual(normal.returncode, 0, normal.stderr)
            self.assertEqual(len(normal.stdout.splitlines()), PREVIEW_SAMPLE_LIMIT)

            utf8_boundary = b"x" * (PREVIEW_COLUMN_LIMIT - 1) + "😀".encode()
            path.write_bytes(
                (utf8_boundary + MATCH_PATTERN.encode() + b"\n")
                * PREVIEW_SAMPLE_LIMIT
            )
            boundary = self.run_protocol(PREVIEW_HEADING, path)
            self.assertEqual(boundary.returncode, 0, boundary.stderr)
            rows = boundary.stdout.splitlines(keepends=True)
            self.assertEqual(len(rows), PREVIEW_SAMPLE_LIMIT)
            self.assertTrue(all("😀".encode() in row for row in rows))
            self.assertNotIn(MATCH_PATTERN.encode(), boundary.stdout)
            self.assertLess(len(boundary.stdout), MAX_PREVIEW_OUTPUT_BYTES)

    def test_position_and_preview_exit_one_when_count_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rollout-fixture.jsonl"
            path.write_text("needle\n", encoding="utf-8")
            counted = self.run_protocol(COUNT_HEADING, path)
            self.assertEqual(counted.returncode, 0, counted.stderr)
            path.write_text("changed without the pattern\n", encoding="utf-8")

            for heading in (POSITION_HEADING, PREVIEW_HEADING):
                with self.subTest(heading=heading):
                    completed = self.run_protocol(heading, path)
                    self.assertEqual(completed.returncode, 1, completed.stderr)
                    self.assertEqual(completed.stdout, b"")

    def test_position_and_exhaustive_outputs_bound_omitted_long_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rollout = temp / "rollout-fixture.jsonl"
            artifact = temp / "positions.txt"
            rollout.write_bytes(
                (b"x" * (PREVIEW_COLUMN_LIMIT + 1) + b" needle\n") * 2
            )

            position = self.run_protocol(POSITION_HEADING, rollout)
            self.assertEqual(position.returncode, 0, position.stderr)
            position_lines = position.stdout.splitlines(keepends=True)
            self.assertEqual(len(position_lines), 2)
            self.assertTrue(
                all(len(line) <= MAX_POSITION_ROW_BYTES for line in position_lines)
            )
            self.assertTrue(
                all(b"[Omitted long line with 1 matches]" in line for line in position_lines)
            )
            self.assertNotIn(MATCH_PATTERN.encode(), position.stdout)

            completed = self.run_exhaustive_shell(
                rollout=rollout, artifact=artifact, count=2
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            artifact_bytes = artifact.read_bytes()
            rows = parse_position_rows(artifact_bytes)
            self.assertEqual([row[0] for row in rows], [1, 2])
            artifact_lines = artifact_bytes.splitlines(keepends=True)
            self.assertTrue(
                all(len(line) <= MAX_POSITION_ROW_BYTES for line in artifact_lines)
            )
            self.assertLessEqual(
                len(artifact_bytes), len(artifact_lines) * MAX_POSITION_ROW_BYTES
            )
            self.assertTrue(
                all(b"[Omitted long line with 1 matches]" in line for line in artifact_lines)
            )
            self.assertNotIn(MATCH_PATTERN.encode(), artifact_bytes)

            widest_uint64 = str((1 << 64) - 1).encode()
            worst_width_row = b":".join(
                (widest_uint64, widest_uint64, widest_uint64, rows[0][3])
            ) + b"\n"
            self.assertLessEqual(len(worst_width_row), MAX_POSITION_ROW_BYTES)
            max_rows = MAX_POSITION_OUTPUT_BYTES // MAX_POSITION_ROW_BYTES
            self.assertEqual(max_rows, 262_144)
            self.assertEqual(
                max_rows * MAX_POSITION_ROW_BYTES, MAX_POSITION_OUTPUT_BYTES
            )

    def test_exhaustive_shell_does_not_clobber_existing_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rollout = temp / "rollout-fixture.jsonl"
            artifact = temp / "positions.txt"
            rollout.write_text("needle\n", encoding="utf-8")
            original = b"pre-existing artifact\n"
            artifact.write_bytes(original)
            completed = self.run_exhaustive_shell(
                rollout=rollout, artifact=artifact, count=1
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(artifact.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
