from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
LOCATOR = SKILLS / "codex-session-mining/scripts/locate_session.py"
LOCATOR_SPEC = importlib.util.spec_from_file_location("codex_session_locator", LOCATOR)
if LOCATOR_SPEC is None or LOCATOR_SPEC.loader is None:
    raise RuntimeError(f"unable to load {LOCATOR}")
LOCATE = importlib.util.module_from_spec(LOCATOR_SPEC)
sys.modules[LOCATOR_SPEC.name] = LOCATE
LOCATOR_SPEC.loader.exec_module(LOCATE)


class SkillStructureTests(unittest.TestCase):
    def test_skills_have_frontmatter(self) -> None:
        skill_files = sorted(SKILLS.glob("*/SKILL.md"))
        self.assertGreaterEqual(len(skill_files), 3)
        for path in skill_files:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"), path)
            frontmatter = text.split("---", 2)[1]
            self.assertIn("\nname:", frontmatter, path)
            self.assertIn("\ndescription:", frontmatter, path)

    def test_bounded_command_output_is_a_thin_execution_control_layer(self) -> None:
        skill_root = SKILLS / "bounded-command-output"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        contract = (skill_root / "references/command-patterns.md").read_text(
            encoding="utf-8"
        )
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        self.assertLess(len(skill.splitlines()), 90)
        self.assertLess(len(contract.splitlines()), 100)
        self.assertIn("genuinely broad, noisy, or long-running", skill)
        self.assertIn(
            "ordinary exact commands already known to be small and fast", skill
        )
        for boundary in (
            "Producer scope",
            "Runtime",
            "Retained bytes",
            "Visible output",
        ):
            self.assertIn(boundary, skill)
        self.assertIn("hard deadline", skill)
        self.assertIn("process-group cleanup", skill)
        self.assertIn("fixed ceiling across every saved", skill)
        self.assertIn("it does not enforce a byte", skill)
        self.assertIn("one monotonic deadline", contract)
        self.assertIn("returns `124`", contract)
        self.assertIn("returns `125`", contract)
        self.assertIn("prove group quiescence after the leader exits", contract)
        self.assertIn("Retained-Byte Enforcement", contract)
        self.assertIn("Post-exit size checks", contract)
        self.assertTrue(
            (skill_root / "scripts/run_process_group_deadline.py").is_file()
        )
        self.assertIn("allow_implicit_invocation: true", interface)

    def test_skill_authoring_only_adds_local_overlay_policy(self) -> None:
        skill_root = SKILLS / "codex-skill-authoring"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        self.assertLess(len(skill.splitlines()), 90)
        self.assertIn("system `$skill-creator`", skill)
        self.assertIn("Choose Placement", skill)
        self.assertIn("Choose The Instruction Layer", skill)
        self.assertIn("AGENTS.md", skill)
        self.assertIn("SKILL.md", skill)
        self.assertIn("references/", skill)
        self.assertIn("codex_skill_validate.py", skill)
        self.assertIn("approval rules can match a", skill)
        self.assertIn("stable command prefix", skill)
        self.assertIn("direct argv", skill)
        self.assertFalse((skill_root / "references/description-patterns.md").exists())
        self.assertIn("$skill-creator", interface)

    def test_session_mining_routes_locate_and_corpus_profiles(self) -> None:
        skill_root = SKILLS / "codex-session-mining"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        locate = (skill_root / "references/locate.md").read_text(encoding="utf-8")
        corpus = (skill_root / "references/corpus.md").read_text(encoding="utf-8")

        self.assertLess(len(skill.splitlines()), 100)
        self.assertLess(len(locate.splitlines()), 100)
        self.assertLess(len(corpus.splitlines()), 100)
        self.assertIn("`locate`: Exact Or Narrow Lookup", skill)
        self.assertIn("`corpus`: Complete Current-Host Evidence", skill)
        self.assertIn("scripts/locate_session.py", skill)
        self.assertIn("scripts/build_session_corpus.py", skill)
        self.assertIn("references/locate.md", skill)
        self.assertIn("references/corpus.md", skill)
        self.assertIn("checked`, `unavailable`, `partial`, or `blocked`", skill)
        self.assertIn("both existing `sessions/` and", corpus)
        self.assertIn("`archived_sessions/` roots", corpus)
        self.assertIn("replay prefix", corpus)
        self.assertIn("raw `rg -n`", locate)
        self.assertFalse((skill_root / "references/workflow.md").exists())
        self.assertTrue(LOCATOR.is_file())
        self.assertTrue(os.access(LOCATOR, os.X_OK))
        self.assertTrue((skill_root / "scripts/build_session_corpus.py").is_file())

    def test_session_retrospective_bounds_operator_output(self) -> None:
        skill = (SKILLS / "codex-session-retrospective/SKILL.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("task-scoped ignored log", skill)
        self.assertIn("progress markers", skill)
        self.assertIn("do not poll with 30k+ visible output caps", skill)
        self.assertIn("`pgrep -af`", skill)
        self.assertIn("`ps -p`", skill)
        self.assertIn("`ps -eo` / `ps -axo`", skill)
        self.assertIn("full `sample` output", skill)
        self.assertIn("one open descriptor snapshot", skill)
        self.assertIn("session-metadata record crosses its byte budget", skill)
        self.assertIn("complete normalized signal", skill)


class SessionLocatorTests(unittest.TestCase):
    def run_locator(
        self,
        codex_home: Path,
        *arguments: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = subprocess.run(
            [
                sys.executable,
                os.fspath(LOCATOR),
                "--codex-home",
                os.fspath(codex_home),
                *arguments,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        payload = json.loads(completed.stdout) if completed.stdout else {}
        return completed, payload

    def make_roots(self, codex_home: Path) -> None:
        (codex_home / "sessions/2026/07/24").mkdir(parents=True)
        (codex_home / "archived_sessions").mkdir(parents=True)

    def scan_index(
        self,
        codex_home: Path,
        *,
        query: str = "review helper",
        limit: int = 2,
    ) -> dict[str, object]:
        return LOCATE._scan_index(
            codex_home,
            "session_index.jsonl",
            session_id=None,
            thread_query=query,
            limit=limit,
        )

    def test_exact_id_checks_indexes_and_both_rollout_roots(self) -> None:
        session_id = "019EF067-976B-7E41-928D-80361777330B"
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            self.make_roots(codex_home)
            (codex_home / "session_index.jsonl").write_text(
                json.dumps(
                    {
                        "id": session_id.lower(),
                        "thread_name": "Range-local materializer",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (codex_home / "history.jsonl").write_text(
                json.dumps({"session_id": session_id, "text": "resume review"}) + "\n",
                encoding="utf-8",
            )
            (
                codex_home
                / "sessions/2026/07/24"
                / f"rollout-2026-07-24T00-00-00-{session_id.lower()}.jsonl"
            ).write_text("{}\n", encoding="utf-8")
            (
                codex_home / "archived_sessions" / f"rollout-copy-{session_id}.jsonl"
            ).write_text("{}\n", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--session-id",
                session_id,
                "--limit",
                "5",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "checked")
        self.assertEqual(payload["total_matches"], 4)
        sources = payload["sources"]
        self.assertEqual(len(sources), 4)
        self.assertTrue(all(source["status"] == "checked" for source in sources))
        self.assertEqual(
            [source["match_count"] for source in sources],
            [1, 1, 1, 1],
        )

    def test_thread_query_scans_only_bounded_public_index_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            rows = [
                {
                    "id": f"session-{index}",
                    "thread_name": f"Review helper {index}",
                    "text": "ignored",
                }
                for index in range(5)
            ]
            (codex_home / "session_index.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--thread-query",
                "review helper",
                "--limit",
                "2",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "checked")
        self.assertEqual(len(payload["sources"]), 2)
        source = payload["sources"][0]
        self.assertEqual(source["match_count"], 5)
        self.assertEqual(len(source["matches"]), 2)
        self.assertTrue(source["matches_truncated"])

    def test_recent_mode_reads_both_indexes_without_rollout_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            (codex_home / "session_index.jsonl").write_text(
                "".join(
                    json.dumps(row) + "\n"
                    for row in (
                        {
                            "id": "index-old",
                            "updated_at": "2026-07-24T00:00:00Z",
                        },
                        {
                            "id": "index-new",
                            "updated_at": 2_000_000_000,
                        },
                    )
                ),
                encoding="utf-8",
            )
            (codex_home / "history.jsonl").write_text(
                "".join(
                    json.dumps(row) + "\n"
                    for row in (
                        {"session_id": "history-old", "ts": 1_900_000_000},
                        {"session_id": "history-new", "ts": 2_000_000_000.25},
                    )
                ),
                encoding="utf-8",
            )
            (codex_home / "sessions").write_text("not a directory", encoding="utf-8")
            (codex_home / "archived_sessions").write_text(
                "not a directory",
                encoding="utf-8",
            )

            completed, payload = self.run_locator(
                codex_home,
                "--recent",
                "--limit",
                "1",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["selector"], {"kind": "recent"})
        self.assertEqual(payload["status"], "checked")
        self.assertEqual(payload["total_matches"], 4)
        sources = payload["sources"]
        self.assertEqual(len(sources), 2)
        self.assertTrue(all(source["kind"] == "index" for source in sources))
        self.assertEqual([source["match_count"] for source in sources], [2, 2])
        index_match = sources[0]["matches"][0]
        self.assertEqual(index_match["id"], "index-new")
        self.assertEqual(index_match["updated_at"], 2_000_000_000)
        self.assertEqual(index_match["ordering_timestamp_source"], "updated_at")
        self.assertEqual(
            index_match["ordering_timestamp_utc"],
            "2033-05-18T03:33:20.000000Z",
        )
        history_match = sources[1]["matches"][0]
        self.assertEqual(history_match["session_id"], "history-new")
        self.assertEqual(history_match["ts"], 2_000_000_000.25)
        self.assertEqual(history_match["ordering_timestamp_source"], "ts")
        self.assertEqual(
            history_match["ordering_timestamp_utc"],
            "2033-05-18T03:33:20.250000Z",
        )

    def test_recent_mode_preserves_index_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            with (codex_home / "session_index.jsonl").open("wb") as handle:
                handle.truncate(LOCATE.MAX_INDEX_TOTAL_READ_BYTES // 3 + 1)
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")
            (codex_home / "sessions").write_text("not a directory", encoding="utf-8")
            (codex_home / "archived_sessions").write_text(
                "not a directory",
                encoding="utf-8",
            )

            completed, payload = self.run_locator(codex_home, "--recent")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["selector"], {"kind": "recent"})
        self.assertEqual(payload["status"], "partial")
        self.assertEqual(len(payload["sources"]), 2)
        source = payload["sources"][0]
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["reason"], "index-byte-cap-exceeded")
        self.assertEqual(source["records_scanned"], 0)
        self.assertEqual(source["index_bytes_processed"], 0)

    def test_index_limit_retains_newest_matches_with_stable_ties(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            rows = [
                {
                    "id": "old",
                    "thread_name": "review helper",
                    "updated_at": "2026-07-23T23:59:00Z",
                },
                {
                    "id": "tie-earlier-line",
                    "thread_name": "review helper",
                    "updated_at": "2026-07-24T10:00:00+01:00",
                },
                {
                    "id": "missing-timestamp",
                    "thread_name": "review helper",
                },
                {
                    "id": "tie-later-line",
                    "thread_name": "review helper",
                    "updated_at": "2026-07-24T09:00:00Z",
                },
                {
                    "id": "newest",
                    "thread_name": "review helper",
                    "ts": 2_000_000_000,
                },
            ]
            (codex_home / "session_index.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            source = self.scan_index(codex_home, limit=3)

        self.assertEqual(source["status"], "checked")
        self.assertEqual(source["match_count"], 5)
        self.assertEqual(
            [match["id"] for match in source["matches"]],
            ["newest", "tie-later-line", "tie-earlier-line"],
        )
        self.assertEqual([match["line"] for match in source["matches"]], [5, 4, 2])
        self.assertTrue(source["matches_truncated"])

    def test_numeric_timestamps_respect_representable_utc_range(self) -> None:
        self.assertEqual(
            LOCATE._normalize_index_timestamp(-62_135_596_800),
            -62_135_596_800_000_000,
        )
        self.assertEqual(
            LOCATE._normalize_index_timestamp(253_402_300_799),
            253_402_300_799_000_000,
        )
        for value in (
            -62_135_596_801,
            253_402_300_800,
            -62_135_596_801.0,
            253_402_300_800.0,
        ):
            with self.subTest(value=value):
                self.assertIsNone(LOCATE._normalize_index_timestamp(value))

        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            rows = [
                {
                    "id": "out-of-range-future",
                    "thread_name": "review helper",
                    "ts": 10**31,
                },
                {
                    "id": "real-newest",
                    "thread_name": "review helper",
                    "ts": 2_000_000_000,
                },
                {
                    "id": "out-of-range-past",
                    "thread_name": "review helper",
                    "ts": -(10**31),
                },
            ]
            (codex_home / "session_index.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            source = self.scan_index(codex_home, limit=1)

        self.assertEqual(source["status"], "checked")
        self.assertEqual(source["malformed_records"], 0)
        self.assertEqual(source["match_count"], 3)
        self.assertEqual(
            [match["id"] for match in source["matches"]],
            ["real-newest"],
        )
        match = source["matches"][0]
        self.assertEqual(match["ts"], 2_000_000_000)
        self.assertEqual(match["ordering_timestamp_source"], "ts")
        self.assertEqual(
            match["ordering_timestamp_utc"],
            "2033-05-18T03:33:20.000000Z",
        )
        out_of_range = LOCATE._project_index_match(
            Path("/bounded/session_index.jsonl"),
            1,
            {"id": "future", "ts": 10**31},
        )
        self.assertEqual(out_of_range["ts"], 10**31)
        self.assertNotIn("ordering_timestamp_source", out_of_range)
        self.assertNotIn("ordering_timestamp_utc", out_of_range)

    def test_index_byte_cap_is_schema_v2_partial_without_reading_sparse_body(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            with index.open("wb") as handle:
                handle.truncate(LOCATE.MAX_INDEX_TOTAL_READ_BYTES // 3 + 1)
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--thread-query",
                "review helper",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["status"], "partial")
        source = payload["sources"][0]
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["reason"], "index-byte-cap-exceeded")
        self.assertEqual(source["records_scanned"], 0)
        self.assertEqual(source["index_bytes_processed"], 0)
        self.assertGreater(
            source["planned_index_read_bytes"],
            source["index_total_read_byte_limit"],
        )

    def test_index_record_cap_stops_before_unbounded_tiny_record_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            index.write_text(
                "".join(
                    json.dumps(
                        {
                            "id": f"session-{number}",
                            "thread_name": "review helper",
                            "ts": number,
                        }
                    )
                    + "\n"
                    for number in range(3)
                ),
                encoding="utf-8",
            )

            with mock.patch.object(LOCATE, "MAX_INDEX_RECORDS", 2):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertIn("index-record-cap-exceeded", source["reasons"])
        self.assertEqual(source["records_scanned"], 2)
        self.assertEqual(source["match_count"], 2)
        self.assertEqual(source["content_scope"], "unverified")
        self.assertLess(
            source["index_bytes_processed"],
            source["captured_prefix_bytes"],
        )

    def test_large_json_integer_is_malformed_and_scan_continues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            huge_integer = "9" * 4_301
            rows = [
                json.dumps(
                    {
                        "id": "before",
                        "thread_name": "review helper",
                        "ts": 1,
                    }
                ),
                (
                    '{"id":"malformed","thread_name":"review helper",'
                    f'"ts":{huge_integer}}}'
                ),
                json.dumps(
                    {
                        "id": "after",
                        "thread_name": "review helper",
                        "ts": 2,
                    }
                ),
            ]
            (codex_home / "session_index.jsonl").write_text(
                "\n".join(rows) + "\n",
                encoding="utf-8",
            )

            source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["malformed_records"], 1)
        self.assertEqual(source["records_scanned"], 3)
        self.assertEqual(source["match_count"], 2)
        self.assertEqual(
            [match["id"] for match in source["matches"]],
            ["after", "before"],
        )

    def test_timezone_normalization_overflow_is_a_missing_timestamp(self) -> None:
        boundary_values = (
            "0001-01-01T00:00:00+23:59",
            "9999-12-31T23:59:59-23:59",
        )
        for value in boundary_values:
            with self.subTest(value=value):
                self.assertIsNone(LOCATE._normalize_index_timestamp(value))

        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            rows = [
                {
                    "id": "underflow",
                    "thread_name": "review helper",
                    "updated_at": boundary_values[0],
                },
                {
                    "id": "normal",
                    "thread_name": "review helper",
                    "updated_at": "2026-07-25T00:00:00Z",
                },
                {
                    "id": "overflow",
                    "thread_name": "review helper",
                    "updated_at": boundary_values[1],
                },
            ]
            (codex_home / "session_index.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            source = self.scan_index(codex_home, limit=3)

        self.assertEqual(source["status"], "checked")
        self.assertEqual(
            [match["id"] for match in source["matches"]],
            ["normal", "overflow", "underflow"],
        )

    def test_rollout_filename_requires_exact_terminal_uuid(self) -> None:
        session_id = "019ef067-976b-7e41-928d-80361777330b"
        self.assertTrue(
            LOCATE._rollout_name_matches(
                f"rollout-copy-{session_id}.jsonl",
                session_id.upper(),
            )
        )
        for name in (
            f"rollout-copy-x{session_id}.jsonl",
            f"rollout-copy-{session_id}x.jsonl",
            f"rollout-copy-{session_id}-later.jsonl",
            f"rollout-copy-{session_id}.jsonl.backup",
            f"rollout-copy-{session_id}{session_id}.jsonl",
        ):
            with self.subTest(name=name):
                self.assertFalse(LOCATE._rollout_name_matches(name, session_id))
        self.assertFalse(
            LOCATE._rollout_name_matches(
                "rollout-copy-opaque-id.jsonl",
                "opaque-id",
            )
        )

    def test_opaque_session_id_skips_rollout_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            (codex_home / "session_index.jsonl").write_text(
                json.dumps({"id": "opaque-id", "thread_name": "Opaque thread"}) + "\n",
                encoding="utf-8",
            )
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")
            (codex_home / "sessions").write_text("not a directory", encoding="utf-8")
            (codex_home / "archived_sessions").write_text(
                "not a directory",
                encoding="utf-8",
            )

            completed, payload = self.run_locator(
                codex_home,
                "--session-id",
                "opaque-id",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "checked")
        self.assertEqual(payload["total_matches"], 1)
        self.assertEqual(len(payload["sources"]), 2)
        self.assertTrue(all(source["kind"] == "index" for source in payload["sources"]))

    def test_malformed_and_oversized_index_records_make_coverage_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            self.make_roots(codex_home)
            with (codex_home / "session_index.jsonl").open("wb") as handle:
                handle.write(b"{not-json}\n")
                handle.write(b"x" * (1024 * 1024 + 1) + b"\n")
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--session-id",
                "opaque-id",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "partial")
        source = payload["sources"][0]
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["malformed_records"], 1)
        self.assertEqual(source["oversized_records"], 1)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_broken_symlinked_index_is_partial_not_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            os.symlink(
                codex_home / "missing-target.jsonl",
                codex_home / "session_index.jsonl",
            )
            (codex_home / "history.jsonl").write_text("", encoding="utf-8")

            completed, payload = self.run_locator(
                codex_home,
                "--thread-query",
                "do not follow",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "partial")
        source = payload["sources"][0]
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["match_count"], 0)
        self.assertNotEqual(source["reason"], "missing")

    def test_append_after_captured_index_boundary_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            index.write_text(
                json.dumps({"id": "first", "thread_name": "review helper"}) + "\n",
                encoding="utf-8",
            )
            initial_size = index.stat().st_size
            real_validate = LOCATE._validate_index_completion

            def append_then_validate(*args: object, **kwargs: object) -> int:
                with index.open("ab") as handle:
                    handle.write(
                        (
                            json.dumps(
                                {
                                    "id": "later",
                                    "thread_name": "review helper appended",
                                }
                            )
                            + "\n"
                        ).encode()
                    )
                return real_validate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_validate_index_completion",
                side_effect=append_then_validate,
            ):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "checked")
        self.assertEqual(source["captured_prefix_bytes"], initial_size)
        self.assertEqual(source["match_count"], 1)
        self.assertTrue(source["append_after_boundary"])
        self.assertEqual(
            source["content_scope"],
            "stable-captured-prefix-with-later-append",
        )

    def test_index_prefix_mutation_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            index.write_text(
                json.dumps({"id": "first", "thread_name": "review helper"}) + "\n",
                encoding="utf-8",
            )
            real_validate = LOCATE._validate_index_completion

            def mutate_then_validate(*args: object, **kwargs: object) -> int:
                with index.open("r+b") as handle:
                    handle.write(b" ")
                return real_validate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_validate_index_completion",
                side_effect=mutate_then_validate,
            ):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertIn("source-prefix-mutated", source["reasons"])

    def test_index_truncation_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            index.write_text(
                json.dumps({"id": "first", "thread_name": "review helper"}) + "\n",
                encoding="utf-8",
            )
            real_validate = LOCATE._validate_index_completion

            def truncate_then_validate(*args: object, **kwargs: object) -> int:
                index.write_bytes(b"")
                return real_validate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_validate_index_completion",
                side_effect=truncate_then_validate,
            ):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertIn(
            "source-truncated-during-revalidation",
            source["reasons"],
        )

    def test_index_rotation_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            row = json.dumps({"id": "first", "thread_name": "review helper"}) + "\n"
            index.write_text(row, encoding="utf-8")
            rotated = codex_home / "session_index.rotated"
            real_validate = LOCATE._validate_index_completion

            def rotate_then_validate(*args: object, **kwargs: object) -> int:
                index.rename(rotated)
                index.write_text(row, encoding="utf-8")
                return real_validate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_validate_index_completion",
                side_effect=rotate_then_validate,
            ):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertIn("source-rotated-or-replaced", source["reasons"])

    def test_index_access_policy_change_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            index.write_text(
                json.dumps({"id": "first", "thread_name": "review helper"}) + "\n",
                encoding="utf-8",
            )
            original_mode = stat.S_IMODE(index.stat().st_mode)
            changed_mode = 0o600 if original_mode != 0o600 else 0o640
            real_validate = LOCATE._validate_index_completion

            def chmod_then_validate(*args: object, **kwargs: object) -> int:
                index.chmod(changed_mode)
                return real_validate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_validate_index_completion",
                side_effect=chmod_then_validate,
            ):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertIn(
            "source-identity-or-access-policy-changed",
            source["reasons"],
        )

    def test_unreadable_index_is_partial_not_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            index = codex_home / "session_index.jsonl"
            index.write_text("{}\n", encoding="utf-8")
            real_open = LOCATE.os.open

            def deny_index(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                if path == "session_index.jsonl" and dir_fd is not None:
                    raise PermissionError("blocked test source")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(LOCATE.os, "open", side_effect=deny_index):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["reason"], "open-failed:PermissionError")

    def test_unreadable_index_revalidation_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            codex_home.mkdir()
            (codex_home / "session_index.jsonl").write_text(
                json.dumps({"thread_name": "review helper"}) + "\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                LOCATE,
                "_hash_prefix",
                side_effect=PermissionError("blocked revalidation"),
            ):
                source = self.scan_index(codex_home)

        self.assertEqual(source["status"], "partial")
        self.assertIn(
            "source-revalidation-failed:PermissionError",
            source["reasons"],
        )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_rollout_root_replacement_escape_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            codex_home = base / ".codex"
            root = codex_home / "sessions"
            root.mkdir(parents=True)
            (root / "rollout-target.jsonl").write_text("{}\n", encoding="utf-8")
            outside = base / "outside"
            outside.mkdir()
            original = base / "sessions-original"
            real_revalidate = LOCATE._revalidate_rollout_tree

            def replace_then_validate(*args: object, **kwargs: object) -> None:
                root.rename(original)
                os.symlink(outside, root)
                real_revalidate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_revalidate_rollout_tree",
                side_effect=replace_then_validate,
            ):
                source = LOCATE._scan_rollout_root(
                    codex_home,
                    "sessions",
                    session_id="target",
                    limit=2,
                )

        self.assertEqual(source["status"], "partial")
        self.assertIn("rollout-root-replaced-or-escaped", source["reasons"])

    def test_rollout_inventory_drift_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            root = codex_home / "sessions"
            root.mkdir(parents=True)
            (root / "rollout-target.jsonl").write_text("{}\n", encoding="utf-8")
            real_revalidate = LOCATE._revalidate_rollout_tree

            def drift_then_validate(*args: object, **kwargs: object) -> None:
                (root / "late-entry").write_text("late", encoding="utf-8")
                real_revalidate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_revalidate_rollout_tree",
                side_effect=drift_then_validate,
            ):
                source = LOCATE._scan_rollout_root(
                    codex_home,
                    "sessions",
                    session_id="target",
                    limit=2,
                )

        self.assertEqual(source["status"], "partial")
        self.assertIn("rollout-entry-inventory-changed", source["reasons"])

    def test_rollout_directory_access_policy_change_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            root = codex_home / "sessions"
            root.mkdir(parents=True)
            (root / "rollout-target.jsonl").write_text("{}\n", encoding="utf-8")
            original_mode = stat.S_IMODE(root.stat().st_mode)
            changed_mode = 0o700 if original_mode != 0o700 else 0o750
            real_revalidate = LOCATE._revalidate_rollout_tree

            def chmod_then_validate(*args: object, **kwargs: object) -> None:
                root.chmod(changed_mode)
                real_revalidate(*args, **kwargs)

            with mock.patch.object(
                LOCATE,
                "_revalidate_rollout_tree",
                side_effect=chmod_then_validate,
            ):
                source = LOCATE._scan_rollout_root(
                    codex_home,
                    "sessions",
                    session_id="target",
                    limit=2,
                )

        self.assertEqual(source["status"], "partial")
        self.assertIn(
            "rollout-root-identity-or-access-policy-changed",
            source["reasons"],
        )

    def test_rollout_depth_cap_stops_before_deep_ancestor_reopens(self) -> None:
        session_id = "019ef067-976b-7e41-928d-80361777330b"
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            root = codex_home / "sessions"
            cursor = root
            for depth in range(20):
                cursor /= f"depth-{depth:02d}"
            cursor.mkdir(parents=True)

            with mock.patch.object(LOCATE, "MAX_ROLLOUT_DIRECTORY_DEPTH", 3):
                source = LOCATE._scan_rollout_root(
                    codex_home,
                    "sessions",
                    session_id=session_id,
                    limit=2,
                )

        self.assertEqual(source["status"], "partial")
        self.assertIn(
            "rollout-directory-depth-cap-exceeded",
            source["reasons"],
        )
        self.assertLessEqual(source["directories_scanned"], 4)
        self.assertEqual(source["max_directory_depth_scanned"], 3)

    def test_rollout_aggregate_component_cap_is_partial(self) -> None:
        session_id = "019ef067-976b-7e41-928d-80361777330b"
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            root = codex_home / "sessions"
            for index in range(5):
                (root / f"child-{index}").mkdir(parents=True)

            with mock.patch.object(LOCATE, "MAX_ROLLOUT_PATH_COMPONENTS", 2):
                source = LOCATE._scan_rollout_root(
                    codex_home,
                    "sessions",
                    session_id=session_id,
                    limit=2,
                )

        self.assertEqual(source["status"], "partial")
        self.assertIn(
            "rollout-path-component-cap-exceeded",
            source["reasons"],
        )
        self.assertEqual(source["path_components_reserved"], 2)

    def test_rollout_aggregate_component_byte_cap_is_partial(self) -> None:
        session_id = "019ef067-976b-7e41-928d-80361777330b"
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            root = codex_home / "sessions"
            (root / "first").mkdir(parents=True)
            (root / "second").mkdir()

            with mock.patch.object(
                LOCATE,
                "MAX_ROLLOUT_PATH_COMPONENT_BYTES",
                len("first"),
            ):
                source = LOCATE._scan_rollout_root(
                    codex_home,
                    "sessions",
                    session_id=session_id,
                    limit=2,
                )

        self.assertEqual(source["status"], "partial")
        self.assertIn(
            "rollout-path-component-byte-cap-exceeded",
            source["reasons"],
        )
        self.assertEqual(source["path_component_bytes_reserved"], len("first"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_many_rollout_errors_are_capped_during_collection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory).resolve() / ".codex"
            root = codex_home / "sessions"
            root.mkdir(parents=True)
            for index in range(25):
                os.symlink(
                    root / f"missing-{index:02d}",
                    root / f"broken-{index:02d}",
                )

            source = LOCATE._scan_rollout_root(
                codex_home,
                "sessions",
                session_id="target",
                limit=3,
            )

        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["error_count"], 25)
        self.assertEqual(len(source["errors"]), 3)
        self.assertTrue(source["errors_truncated"])


if __name__ == "__main__":
    unittest.main()
