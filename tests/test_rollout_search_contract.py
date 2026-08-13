from __future__ import annotations

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
    "rg",
    "--no-config",
    "--no-mmap",
    "--text",
    "--encoding",
    "none",
    "--no-heading",
    "--no-filename",
    "--color",
    "never",
]
EXPECTED_COMMAND_ARGV = {
    COUNT_HEADING: FIXED_RG_ARGV
    + [
        "--count-matches",
        "--include-zero",
        "--",
        "$PATTERN",
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
        if "rg" not in shell_argv:
            continue
        rg_argv = shell_argv[shell_argv.index("rg") :]
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
        "rg": rg,
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

    def test_reference_limits_input_and_pins_rg_major(self) -> None:
        self.assertIn("one exact regular rollout file", self.reference_lower)
        self.assertIn("input redirection gives ripgrep one input stream", self.reference_lower)
        self.assertIn("only optional search flags allowed", self.reference_lower)
        self.assertIn("require the first line to report ripgrep major version 15", self.reference_lower)
        for flag in ("--fixed-strings", "-i", "-s", "-S", "-w", "-x"):
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
        self.assertIn("number of non-overlapping matches", self.reference_lower)
        self.assertIn("not the number of matching lines", self.reference_lower)
        self.assertIn("one line can therefore contribute multiple matches", self.reference_lower)

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
                    re.compile(r'-- "\$PATTERN"\s+< "\$ROLLOUT"'),
                )

        exhaustive_block = join_shell_continuations(
            self.templates[EXHAUSTIVE_HEADING][0]
        )
        self.assertRegex(exhaustive_block, re.compile(r'--max-count "\$COUNT"'))
        self.assertRegex(
            exhaustive_block,
            re.compile(r'< "\$ROLLOUT"\s+> "\$ARTIFACT"'),
        )
        self.assertRegex(
            exhaustive_block,
            re.compile(r'test -f "\$ARTIFACT"'),
        )

    def test_field_aware_parser_scans_past_output_cap_and_reports_coverage(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n```", start)]

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


class Ripgrep15ConformanceTests(unittest.TestCase):
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
            match = re.search(rb"ripgrep (\d+)\.", version.stdout)
            if version.returncode == 0 and match is not None:
                failure = "dynamic contract is pinned to ripgrep 15.x"
                if int(match.group(1)) == 15:
                    cls.rg = rg
                    return
            else:
                failure = "unable to determine ripgrep major version"
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
        self, heading: str, *, rollout: Path, pattern: str
    ) -> subprocess.CompletedProcess[bytes]:
        environment = {
            "LC_ALL": "C",
            "PATH": str(Path(self.rg).parent),
            "PATTERN": pattern,
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

    def test_count_statuses_and_occurrence_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rollout-fixture.jsonl"
            path.write_text("needle needle\nno match\nneedle\nlast needle\n", encoding="utf-8")
            matched = self.run_protocol(COUNT_HEADING, path)
            self.assertEqual((matched.returncode, matched.stdout), (0, b"4\n"))

            path.write_text("nothing relevant\n", encoding="utf-8")
            unmatched = self.run_protocol(COUNT_HEADING, path)
            self.assertEqual((unmatched.returncode, unmatched.stdout), (1, b"0\n"))

            failed = self.run_protocol(COUNT_HEADING, path, pattern="[")
            self.assertGreaterEqual(failed.returncode, 2)

    def test_documented_shell_preserves_pattern_and_rollout_as_single_words(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rollout = temp / "rollout fixture [one].jsonl"
            pattern = "alpha.*beta gamma"
            rollout.write_text("alphaZZbeta gamma\n", encoding="utf-8")
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

    def test_exhaustive_shell_creates_bounded_owner_private_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            rollout = temp / "rollout-fixture.jsonl"
            artifact = temp / "positions.txt"
            rollout.write_text("first needle\nsecond needle\n", encoding="utf-8")
            completed = self.run_exhaustive_shell(
                rollout=rollout, artifact=artifact, count=2
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            artifact_bytes = artifact.read_bytes()
            rows = parse_position_rows(artifact_bytes)
            self.assertEqual([row[0] for row in rows], [1, 2])

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
