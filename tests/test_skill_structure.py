from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest


def json_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def extract_python_block_after(
    workflow: str, heading: str, marker: str = "```bash\npython3 - <<'PY'\n"
) -> str:
    section_start = workflow.index(heading)
    code_start = workflow.index(marker, section_start) + len(marker)
    return workflow[code_start : workflow.index("\nPY\n```", code_start)]


def extract_bash_block_after(workflow: str, heading: str) -> str:
    section_start = workflow.index(heading)
    marker = "```bash\n"
    code_start = workflow.index(marker, section_start) + len(marker)
    return workflow[code_start : workflow.index("\n```", code_start)]


class SkillStructureTests(unittest.TestCase):
    def test_skills_have_frontmatter(self) -> None:
        root = Path(__file__).resolve().parents[1] / "skills"
        skill_files = sorted(root.glob("*/SKILL.md"))
        self.assertGreaterEqual(len(skill_files), 3)
        for path in skill_files:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"), path)
            frontmatter = text.split("---", 2)[1]
            self.assertIn("\nname:", frontmatter, path)
            self.assertIn("\ndescription:", frontmatter, path)

    def test_bounded_command_output_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill_root = root / "skills/bounded-command-output"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        patterns = (skill_root / "references/command-patterns.md").read_text(
            encoding="utf-8"
        )
        supervisor = skill_root / "scripts/run_process_group_deadline.py"
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        self.assertIn("genuinely broad, noisy, or long-running", skill)
        self.assertIn("Do not use for routine exact commands", skill)
        self.assertIn("at least one property is real", skill)
        self.assertIn(
            "Do not trigger merely because every command could theoretically hang",
            skill,
        )
        self.assertIn("Small visible output can still qualify", skill)
        self.assertIn("## Keep Three Budgets Separate", skill)
        self.assertIn("Bound the producer", skill)
        self.assertIn("Bound runtime", skill)
        self.assertIn("Bound retained bytes", skill)
        self.assertIn("task-specific finite wall-clock deadline", skill)
        self.assertIn("scripts/run_process_group_deadline.py", skill)
        self.assertIn("process-group cleanup", skill)
        self.assertIn("does not prove quiescence", skill)
        self.assertIn("On non-POSIX runtimes", skill)
        self.assertIn("one enforced aggregate byte ceiling", skill)
        self.assertIn("all per-command caps fit inside that aggregate ceiling", skill)
        self.assertIn(
            "producer volume, runtime, retained bytes, and visible output", skill
        )
        self.assertIn(
            "Start interruptible long-running work in a pollable PTY shape", skill
        )
        self.assertIn("Apply this skill alongside the task's domain skill", skill)
        self.assertIn("genuinely broad, noisy, or long-running command", patterns)
        self.assertIn(
            "producer scope, runtime, retained bytes, and visible output", patterns
        )
        self.assertIn("## Searches And Inventories", patterns)
        self.assertIn("## Logs, Artifacts, And Manuals", patterns)
        self.assertIn("## Process And System Diagnostics", patterns)
        self.assertIn("## Database And Filesystem Scans", patterns)
        self.assertIn("## Builds, Tests, And Polling", patterns)
        self.assertIn("total counter plus an explicit `N`-path sampler", patterns)
        self.assertIn("total count plus an explicit `N`-filename sample", patterns)
        self.assertIn("aggregate counters plus an explicit `N`-path sampler", patterns)
        self.assertIn("not bounded merely because each item is short", patterns)
        self.assertIn("retains at most `N` items", patterns)
        self.assertIn("preserve the producer's exit status", patterns)
        self.assertIn("do not assume `/usr/bin/rg`", patterns)
        self.assertIn("Quoting a value inside a host-language template", patterns)
        self.assertIn("Preserve the pipeline producer's status", patterns)
        self.assertIn("Parallel launch does not create an output budget", patterns)
        self.assertIn(
            "one aggregate visible-output and retained-byte ceiling", patterns
        )
        self.assertNotIn("/usr/bin/sqlite3", patterns)
        self.assertNotIn("/usr/bin/du", patterns)
        self.assertIn("Do not print the complete inventory", patterns)
        self.assertIn("/usr/local/bin/container build", patterns)
        self.assertIn("maximum byte count across the entire retained-log set", patterns)
        self.assertIn("ordinary unbounded rotation", patterns)
        self.assertIn("caps both aggregate bytes and segment count", patterns)
        self.assertIn("Treat any terminated or evicted stream as incomplete", patterns)
        self.assertIn("post-exit size checks", patterns)
        self.assertIn("terminate the producer with a bounded grace period", patterns)
        self.assertIn("tail -c 8192 <task-log>", patterns)
        self.assertIn("tr '\\r' '\\n'", patterns)
        self.assertIn(
            "SQLite `.timeout` controls how long the client waits for a busy lock",
            patterns,
        )
        self.assertIn("it is not a query-execution deadline", patterns)
        self.assertIn("Broad macOS `du` walks", patterns)
        self.assertIn("A PTY and repeated polling", patterns)
        self.assertIn(
            "report every timed-out branch as unknown or incomplete", patterns
        )
        self.assertIn("macOS does not ship GNU `timeout`", patterns)
        self.assertIn("Do not use an in-process Perl `alarm` plus `exec`", patterns)
        self.assertIn("exit status `142` cannot distinguish", patterns)
        self.assertIn("even a single SQLite or `du` producer", patterns)
        self.assertIn("Choose a task-specific deadline before launch", patterns)
        self.assertIn("illustrative rather than defaults", patterns)
        self.assertIn("separate supervisor owns the monotonic deadline", patterns)
        self.assertIn(
            "Launching descendants does not by itself require stronger containment",
            patterns,
        )
        self.assertIn("adds no persistent launcher", patterns)
        self.assertIn("native Windows (non-WSL)", patterns)
        self.assertIn("returns `125` before installing signal handlers", patterns)
        self.assertIn("one absolute monotonic deadline", patterns)
        self.assertIn("checks the deadline before each new exit observation", patterns)
        self.assertIn("reports `READY`, and waits for the parent's `GO`", patterns)
        self.assertIn("later managed signals cannot interrupt it", patterns)
        self.assertIn("unblocks managed `INT`, `TERM`, and `HUP`", patterns)
        self.assertIn("Diagnostics are best effort", patterns)
        self.assertIn("a closed or broken sink, or a full pipe", patterns)
        self.assertIn("shared open-file description", patterns)
        self.assertIn("Python 3.10 baseline", patterns)
        self.assertIn("standalone single-threaded POSIX CLI", patterns)
        self.assertIn("require neither root, a container", patterns)
        self.assertIn("an uninterruptible kernel call cannot be preempted", patterns)
        self.assertIn("capped at one year solely", patterns)
        self.assertIn(
            "retained-output byte ceilings remain a separate caller responsibility",
            patterns,
        )
        self.assertIn("keep an outer pipe reader waiting for EOF", patterns)
        self.assertIn("or prove group quiescence", patterns)
        self.assertIn("not a real-time scheduler", patterns)
        self.assertNotIn("If a tool launches descendants", patterns)
        self.assertNotIn("terminates and reaps the entire unit", patterns)
        self.assertTrue(supervisor.is_file())
        self.assertTrue(os.access(supervisor, os.X_OK))
        self.assertIn("$bounded-command-output", interface)
        self.assertIn("broad, noisy, or long-running", interface)
        self.assertIn("allow_implicit_invocation: true", interface)
        self.assertNotIn("TODO", skill)

    def test_rules_hygiene_separates_audit_and_apply(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill_root = root / "skills/codex-rules-hygiene"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        cadence = (skill_root / "references/audit-cadence.md").read_text(
            encoding="utf-8"
        )
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")
        helper = skill_root / "scripts/apply_rules_transaction.py"
        helper_text = helper.read_text(encoding="utf-8")

        audit = skill.split("### Audit Mode", 1)[1].split("### Apply Mode", 1)[0]
        apply_mode = skill.split("### Apply Mode", 1)[1].split("## Audit Workflow", 1)[
            0
        ]
        audit_workflow = skill.split("## Audit Workflow", 1)[1].split(
            "## Apply Transaction", 1
        )[0]
        cadence_before_apply = cadence.split("## Apply Checklist", 1)[0]
        cold_start = cadence.split("## Cold-Start Bootstrap", 1)[1].split(
            "## Classification Heuristics", 1
        )[0]
        cold_start_audit = cold_start.split("In audit mode:", 1)[1].split(
            "In apply mode:", 1
        )[0]
        transaction = skill.split("## Apply Transaction", 1)[1].split(
            "## Ownership And Guardrails", 1
        )[0]

        self.assertIn("Keep the run read-only", audit)
        self.assertIn("Choose a light audit", audit)
        self.assertIn("choose a full audit", audit)
        self.assertIn(
            "leave `default.rules`, baselines, safety snapshots, and journals unchanged",
            audit,
        )
        self.assertIn("An audit-only request never becomes writable", audit)
        self.assertIn("cleanup/apply", apply_mode)
        self.assertIn("active task already authorizes applying it", apply_mode)
        self.assertIn("report a no-op and create nothing", apply_mode)
        self.assertIn("audited live-rules bytes", apply_mode)
        self.assertIn("exact candidate bytes", apply_mode)
        self.assertIn("do not rewrite live rules directly", apply_mode)
        self.assertIn("Record separate SHA-256 digests", audit_workflow)
        self.assertIn("exact candidate bytes", audit_workflow)
        self.assertIn("Keep the audit read-only", audit_workflow)
        self.assertIn("bootstrap inventory", cold_start_audit)
        self.assertIn("exact full-cleanup plan", cold_start_audit)
        self.assertIn(
            "Do not create the safety backup or clean baseline", cold_start_audit
        )
        for phrase in (
            "shared lock",
            "owner-private staging directory",
            "SHA-256 digest",
            "identity, content, access policy, and link policy",
            "atomic no-replace rename",
            "exchanges the private candidate with live rules",
            "recovery_required",
            "refresh `default.rules.clean-baseline`",
            "necessary adopted-journal",
        ):
            self.assertIn(phrase, transaction)
        self.assertIn(
            "stop before creating a backup or touching live rules", transaction
        )
        self.assertIn("instead of bootstrapping a tracker", transaction)
        self.assertLess(
            transaction.index("For a real change"),
            transaction.index("atomic no-replace rename"),
        )
        self.assertIn("`audit` is read-only", cadence)
        self.assertIn("## Apply Checklist", cadence)
        self.assertIn("Remain read-only until apply mode is authorized", cadence)
        self.assertIn("## Transaction Safety Boundary", cadence)
        self.assertIn("scripts/apply_rules_transaction.py", cadence)
        self.assertIn("owner-only regular file", cadence)
        self.assertIn("`st_nlink == 1`", cadence)
        self.assertIn("object identity (`device`, `inode`)", cadence)
        self.assertIn("object policy (`st_nlink == 1`)", cadence)
        self.assertIn("schema-v2 receipt", cadence)
        self.assertIn("retention_incomplete", cadence)
        self.assertIn("never equates an open FD with durable retention", cadence)
        self.assertIn("rules-parent FD is rebound", cadence)
        self.assertIn("descriptor_only_or_unlocatable", cadence)
        self.assertIn("Modification times are not treated as policy mutation", cadence)
        self.assertIn("not a kernel compare-and-swap", cadence)
        self.assertIn("first-signal gate", cadence)
        self.assertIn("returns `128 + signal`", cadence)
        self.assertIn("no compare-and-unlink or compare-and-rmdir", cadence)
        self.assertIn("stage_cleanup_retained", cadence)
        self.assertIn("stage_cleanup_refused", cadence)
        self.assertIn("not recovery evidence", cadence)
        self.assertIn(
            "requires every legitimate writer to honor the same persistent lock",
            cadence,
        )
        self.assertIn("Missing, unreadable, wrong-type", cadence)
        write_instruction = (
            r"(?im)^\s*(?:[-*]|\d+\.).*"
            r"\b(?:back up|create|delete|remove|rewrite|refresh|update|write)\b"
        )
        read_only_sections = {
            "audit mode": audit,
            "complete audit workflow": audit_workflow,
            "cadence audit sections": cadence_before_apply,
            "cold-start audit branch": cold_start_audit,
        }
        for label, section in read_only_sections.items():
            actionable_lines = "\n".join(
                line
                for line in section.splitlines()
                if not any(
                    marker in line.lower()
                    for marker in (
                        "do not ",
                        "never ",
                        "unchanged",
                        "read-only",
                    )
                )
            )
            with self.subTest(read_only_section=label):
                self.assertNotRegex(actionable_lines, write_instruction)
        self.assertTrue(helper.is_file())
        self.assertTrue(os.access(helper, os.X_OK))
        for phrase in (
            "fcntl.flock",
            "expected_sha256",
            "atomic_rename_no_replace",
            "atomic_rename_exchange",
            "property_mismatches",
            "rollback",
            "recovery_required",
            "MANAGED_VALIDATOR_SIGNALS",
            "stage_cleanup_retained",
            "stage_cleanup_refused",
        ):
            self.assertIn(phrase, helper_text)
        self.assertNotIn("os.replace", helper_text)
        self.assertNotIn("os.unlink", helper_text)
        self.assertNotIn("os.rmdir", helper_text)
        self.assertIn("Audit Codex rules without changing files", interface)
        self.assertIn("run a read-only audit", interface)
        self.assertNotIn("audit or apply", interface.lower())
        self.assertIn("Use $codex-rules-hygiene", interface)

    def test_session_mining_exposes_locate_and_corpus_paths(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill_root = root / "skills/codex-session-mining"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        workflow = (skill_root / "references/workflow.md").read_text(encoding="utf-8")
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        locate = skill.split("### Locate", 1)[1].split("### Corpus", 1)[0]
        corpus = skill.split("### Corpus", 1)[1].split("## Compose Remote Coverage", 1)[
            0
        ]
        self.assertIn("exact session ID, thread ID, recent prior turn", locate)
        self.assertIn("Do not invoke `scripts/build_session_corpus.py`", locate)
        self.assertIn("scripts/build_session_corpus.py", corpus)
        self.assertIn("active and archived roots", corpus)
        self.assertIn("replay prefixes", corpus)
        self.assertIn("$remote-host-context", skill)
        self.assertIn("Do not copy its host list or SSH recipes", skill)
        self.assertNotIn("--host", skill)
        self.assertNotIn("remote_codex_probe.py", skill)
        self.assertIn("## Locate Path: Find The Canonical Rollout File", workflow)
        self.assertIn("## Corpus Path: Build The Current-Host Union", workflow)
        self.assertIn("## Shared Extraction", workflow)
        self.assertIn("## Remote Composition", workflow)
        self.assertIn("choose a locate or corpus path", interface)

    def test_skill_authoring_is_a_thin_skill_creator_overlay(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill_root = root / "skills/codex-skill-authoring"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")
        wrapper = (skill_root / "scripts/codex_skill_validate.py").read_text(
            encoding="utf-8"
        )
        frontmatter = skill.split("---", 2)[1]

        self.assertLess(len(skill.splitlines()), 80)
        self.assertIn("Create or update Codex skills", frontmatter)
        self.assertIn(
            "Use alongside `$skill-creator` whenever a task creates or updates a Codex skill",
            frontmatter,
        )
        self.assertIn("Load `$skill-creator` first", skill)
        self.assertIn("This skill is a thin overlay", skill)
        self.assertIn("`$skill-creator` owns", skill)
        self.assertIn("`init_skill.py` scaffolding", skill)
        self.assertIn("personal versus repo-local placement", skill)
        self.assertIn("`AGENTS.md` / `SKILL.md` / `references/` layering", skill)
        self.assertIn("approval-friendly argv", skill)
        self.assertIn("scripts/codex_skill_validate.py", skill)
        self.assertIn("$skill-creator/scripts/quick_validate.py", skill)
        self.assertIn("SKILL_AUTHORING_DIR", skill)
        self.assertIn("SKILL_CREATOR_DIR", skill)
        self.assertIn('CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"', skill)
        self.assertNotIn('"$HOME/.codex/skills', skill)
        self.assertIn("Path(__file__).resolve().parents[2]", wrapper)
        self.assertIn('os.environ.get("CODEX_HOME")', wrapper)
        self.assertIn(
            'Path(".system/skill-creator/scripts/quick_validate.py")',
            wrapper,
        )
        self.assertIn("Do not duplicate system scaffolding", skill)
        self.assertFalse((skill_root / "references/description-patterns.md").exists())
        self.assertIn(
            "Use $skill-creator for general authoring and scaffolding", interface
        )
        self.assertIn(
            "use $codex-skill-authoring to place, layer, and validate", interface
        )
        self.assertNotIn("concise concise", interface)

    def test_session_mining_avoids_per_record_jsonl_key_dumps(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(
            encoding="utf-8"
        )
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Count record shapes or lines before details", skill)
        self.assertIn(
            "Do not dump full JSONL records or whole per-record inventories", skill
        )
        self.assertIn("inspect one record or aggregate unique keys once", workflow)
        self.assertIn("jq -R 'fromjson | keys'", workflow)
        self.assertIn("aggregate unique keys once", workflow)

    def test_session_mining_schema_recipe_bounds_and_validates_physical_records(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(
            workflow,
            "For JSONL schema checks",
            marker="```bash\npython3 - \"$JSONL_PATH\" <<'PY'\n",
        )

        self.assertIn("path.open('rb')", code)
        self.assertIn("handle.readline(max_record_bytes + 1)", code)
        self.assertIn("handle.readline(drain_chunk_bytes)", code)
        self.assertIn("raw_line.decode('utf-8')", code)
        self.assertIn("except (ValueError, RecursionError):", code)
        self.assertIn("if not isinstance(row, dict):", code)
        self.assertIn("max_unique_keys = 256", code)
        self.assertIn("max_unique_key_utf8_bytes = 32 * 1024", code)
        self.assertIn("unique_keys_truncation_reason = 'count'", code)
        self.assertIn("unique_keys_truncation_reason = 'utf8_bytes'", code)
        self.assertIn("unique_keys_truncation_reason = 'non_utf8_key'", code)
        self.assertNotIn("keys.update(", code)
        self.assertNotIn("sorted(keys)", code)
        self.assertNotIn("errors='replace'", code)

        oversized_decoy = "oversized-schema-decoy"
        valid_first = {"first-safe-key": 1, "shared-safe-key": 2}
        valid_later = {"later-safe-key": 3, "shared-safe-key": 4}
        payload = b'{"malformed-schema-decoy":\n'
        payload += b'["non-object-schema-decoy"]\n'
        payload += b'{"invalid-utf8-schema-decoy-\xff":1}\n'
        payload += b"9" * 5000 + b"\n"
        payload += b"[" * 1100 + b'"deep-schema-decoy"' + b"]" * 1100 + b"\n"
        payload += b"x" * (1024 * 1024) + b"\r"
        payload += (json_dumps({oversized_decoy: 1}) + "\n").encode("utf-8")
        payload += (json_dumps(valid_first) + "\n").encode("utf-8")
        payload += (json_dumps(valid_later) + "\n").encode("utf-8")

        with tempfile.TemporaryDirectory() as temp_dir:
            jsonl = Path(temp_dir) / "schema.jsonl"
            jsonl.write_bytes(payload)
            result = subprocess.run(
                [sys.executable, "-c", code, str(jsonl)],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["line_count"], 8)
        self.assertEqual(summary["first_record_keys"], sorted(valid_first))
        self.assertEqual(summary["first_record_key_count"], len(valid_first))
        self.assertEqual(
            summary["first_record_key_utf8_bytes"],
            sum(len(key.encode("utf-8")) for key in valid_first),
        )
        self.assertFalse(summary["first_record_keys_truncated"])
        self.assertEqual(
            summary["unique_keys"],
            sorted(set(valid_first) | set(valid_later)),
        )
        self.assertEqual(summary["unique_key_count"], 3)
        self.assertEqual(
            summary["unique_key_utf8_bytes"],
            sum(
                len(key.encode("utf-8")) for key in set(valid_first) | set(valid_later)
            ),
        )
        self.assertFalse(summary["unique_keys_truncated"])
        self.assertIsNone(summary["unique_keys_truncation_reason"])
        self.assertNotIn(oversized_decoy, result.stdout)
        self.assertNotIn("schema-decoy", result.stdout)

    def test_session_mining_schema_recipe_bounds_global_unique_key_state(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(
            workflow,
            "For JSONL schema checks",
            marker="```bash\npython3 - \"$JSONL_PATH\" <<'PY'\n",
        )

        def run_recipe(records: list[dict[str, int]]) -> tuple[dict[str, object], int]:
            payload = "".join(
                f"{json.dumps(record, ensure_ascii=True, sort_keys=True)}\n"
                for record in records
            ).encode("utf-8")
            with tempfile.TemporaryDirectory() as temp_dir:
                jsonl = Path(temp_dir) / "schema.jsonl"
                jsonl.write_bytes(payload)
                result = subprocess.run(
                    [sys.executable, "-c", code, str(jsonl)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout), len(result.stdout.encode("utf-8"))

        count_keys = [f"count-key-{index:03d}" for index in range(257)]
        count_summary, count_output_bytes = run_recipe(
            [
                {key: index for index, key in enumerate(count_keys)},
                {"ignored-after-count-truncation": 1},
            ]
        )
        self.assertEqual(count_summary["line_count"], 2)
        self.assertEqual(count_summary["max_unique_keys"], 256)
        self.assertEqual(count_summary["max_unique_key_utf8_bytes"], 32 * 1024)
        self.assertEqual(count_summary["unique_key_count"], 256)
        self.assertEqual(
            count_summary["unique_key_utf8_bytes"],
            sum(len(key.encode("utf-8")) for key in count_keys[:256]),
        )
        self.assertEqual(count_summary["unique_keys"], sorted(count_keys[:256]))
        self.assertTrue(count_summary["unique_keys_truncated"])
        self.assertEqual(count_summary["unique_keys_truncation_reason"], "count")
        self.assertEqual(count_summary["first_record_key_count"], 256)
        self.assertEqual(count_summary["first_record_keys"], sorted(count_keys[:256]))
        self.assertTrue(count_summary["first_record_keys_truncated"])

        byte_keys = ["first", "x" * 16380, "y" * 16383, "z"]
        byte_summary, byte_output_bytes = run_recipe(
            [
                {key: index for index, key in enumerate(byte_keys)},
                {"ignored-after-byte-truncation": 1},
            ]
        )
        self.assertEqual(byte_summary["line_count"], 2)
        self.assertEqual(byte_summary["unique_key_count"], 3)
        self.assertEqual(byte_summary["unique_key_utf8_bytes"], 32 * 1024)
        self.assertEqual(byte_summary["unique_keys"], sorted(byte_keys[:3]))
        self.assertTrue(byte_summary["unique_keys_truncated"])
        self.assertEqual(byte_summary["unique_keys_truncation_reason"], "utf8_bytes")
        self.assertEqual(byte_summary["first_record_key_utf8_bytes"], 32 * 1024)
        self.assertEqual(byte_summary["first_record_keys"], sorted(byte_keys[:3]))
        self.assertTrue(byte_summary["first_record_keys_truncated"])

        invalid_key_summary, invalid_key_output_bytes = run_recipe(
            [{"\ud800": 1}, {"ignored-after-invalid-key": 1}]
        )
        self.assertEqual(invalid_key_summary["line_count"], 2)
        self.assertEqual(invalid_key_summary["unique_key_count"], 0)
        self.assertEqual(invalid_key_summary["unique_key_utf8_bytes"], 0)
        self.assertEqual(invalid_key_summary["unique_keys"], [])
        self.assertTrue(invalid_key_summary["unique_keys_truncated"])
        self.assertEqual(
            invalid_key_summary["unique_keys_truncation_reason"], "non_utf8_key"
        )
        self.assertEqual(invalid_key_summary["first_record_key_count"], 0)
        self.assertTrue(invalid_key_summary["first_record_keys_truncated"])

        max_output_bytes = 2 * 6 * (32 * 1024) + 2 * 4 * 256 + 8192
        self.assertLessEqual(count_output_bytes, max_output_bytes)
        self.assertLessEqual(byte_output_bytes, max_output_bytes)
        self.assertLessEqual(invalid_key_output_bytes, max_output_bytes)

    def test_session_mining_broad_keyword_recipe_uses_bounded_public_index_schemas(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(workflow, "Broad keyword searches across")

        self.assertIn("history.jsonl", code)
        self.assertIn("session_index.jsonl", code)
        self.assertIn("'session_id', 'ts', 'text'", code)
        self.assertIn("'id', 'updated_at', 'thread_name'", code)
        self.assertIn("path.open('rb')", code)
        self.assertIn("handle.readline(max_record_bytes + 1)", code)
        self.assertIn("handle.readline(drain_chunk_bytes)", code)
        self.assertIn("raw_line.decode('utf-8')", code)
        self.assertIn("except (ValueError, RecursionError):", code)
        self.assertIn("if not isinstance(row, dict):", code)
        self.assertIn("isinstance(value, bool)", code)
        self.assertIn("math.isfinite(value)", code)
        self.assertIn("json.dumps(value, allow_nan=False)", code)
        self.assertIn("per_source_match_cap = 20", code)
        self.assertIn("global_match_limit = 20", code)
        self.assertIn("'kind': 'scan_meta'", code)
        self.assertIn("global_output_truncated", code)
        self.assertNotIn("raise SystemExit", code)
        self.assertNotIn("needle.search(line)", code)
        self.assertNotIn("errors='replace'", code)

        history_hit = "history-valid-review-hit"
        index_hit = "index-valid-review-hit"
        bare_cr_decoy = "bare-cr-review-decoy"
        oversized_decoy = "oversized-review-decoy"
        deep_decoy = "deep-review-decoy"
        history_timestamp = 1784304000123
        bool_timestamp_hit = "history-bool-timestamp-hit"
        nonfinite_timestamp_hit = "history-nonfinite-timestamp-hit"
        oversized_timestamp_hit = "history-oversized-timestamp-hit"
        with tempfile.TemporaryDirectory() as temp_dir:
            codex_home = Path(temp_dir) / ".codex"
            codex_home.mkdir()
            history_payload = b"not-json-review-malformed\n"
            history_payload += b'"review-non-object"\n'
            history_payload += b'{"text":"review-invalid-utf8-\xff"}\n'
            history_payload += b"9" * 5000 + b"\n"
            history_payload += (
                b"[" * 1100
                + f'"review {deep_decoy}"'.encode("utf-8")
                + b"]" * 1100
                + b"\n"
            )
            history_payload += b"x" * (1024 * 1024) + b"\r"
            history_payload += (
                json_dumps(
                    {
                        "session_id": oversized_decoy,
                        "ts": "2026-07-18T00:00:00Z",
                        "text": f"review {bare_cr_decoy}",
                    }
                )
                + "\n"
                + json_dumps(
                    {
                        "session_id": history_hit,
                        "ts": history_timestamp,
                        "text": "review valid history evidence",
                    }
                )
                + "\n"
                + json_dumps(
                    {
                        "session_id": bool_timestamp_hit,
                        "ts": True,
                        "text": "review boolean timestamp evidence",
                    }
                )
                + "\n"
                + json_dumps(
                    {
                        "session_id": nonfinite_timestamp_hit,
                        "ts": float("nan"),
                        "text": "review non-finite timestamp evidence",
                    }
                )
                + "\n"
                + json_dumps(
                    {
                        "session_id": oversized_timestamp_hit,
                        "ts": 10**200,
                        "text": "review oversized timestamp evidence",
                    }
                )
                + "\n"
            ).encode("utf-8")
            (codex_home / "history.jsonl").write_bytes(history_payload)
            (codex_home / "session_index.jsonl").write_text(
                json_dumps(
                    {
                        "id": index_hit,
                        "updated_at": "2026-07-18T00:02:00Z",
                        "thread_name": "review valid session index evidence",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-c", code],
                env=dict(os.environ, CODEX_HOME=str(codex_home)),
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertLessEqual(len(rows), 21)
        self.assertEqual(rows[-1]["kind"], "scan_meta")
        match_rows = rows[:-1]
        self.assertLessEqual(len(match_rows), 20)
        rows_by_id = {row["id"]: row for row in match_rows}
        self.assertEqual(
            set(rows_by_id),
            {
                history_hit,
                bool_timestamp_hit,
                nonfinite_timestamp_hit,
                oversized_timestamp_hit,
                index_hit,
            },
        )
        self.assertEqual(rows_by_id[history_hit]["timestamp"], history_timestamp)
        self.assertEqual(rows_by_id[index_hit]["timestamp"], "2026-07-18T00:02:00Z")
        for invalid_timestamp_id in (
            bool_timestamp_hit,
            nonfinite_timestamp_hit,
            oversized_timestamp_hit,
        ):
            self.assertEqual(rows_by_id[invalid_timestamp_id]["timestamp"], "")
        self.assertTrue(
            any(row["path"].endswith("history.jsonl") for row in match_rows)
        )
        self.assertTrue(
            any(row["path"].endswith("session_index.jsonl") for row in match_rows)
        )
        scan_meta = rows[-1]
        self.assertEqual(scan_meta["match_rows_emitted"], 5)
        self.assertFalse(scan_meta["global_output_truncated"])
        self.assertEqual(
            scan_meta["sources"],
            {
                "history": {
                    "available": True,
                    "emitted": 4,
                    "match_cap": 20,
                    "retained": 4,
                    "truncated": False,
                },
                "session_index": {
                    "available": True,
                    "emitted": 1,
                    "match_cap": 20,
                    "retained": 1,
                    "truncated": False,
                },
            },
        )
        self.assertNotIn(bare_cr_decoy, result.stdout)
        self.assertNotIn(oversized_decoy, result.stdout)
        self.assertNotIn(deep_decoy, result.stdout)
        self.assertNotIn("review-malformed", result.stdout)
        self.assertNotIn("review-invalid-utf8", result.stdout)

    def test_session_mining_broad_keyword_recipe_fairly_caps_multiple_sources(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(workflow, "Broad keyword searches across")

        def run_recipe(
            history_records: list[dict[str, object]] | None,
            index_records: list[dict[str, object]] | None,
        ) -> list[dict[str, object]]:
            with tempfile.TemporaryDirectory() as temp_dir:
                codex_home = Path(temp_dir) / ".codex"
                codex_home.mkdir()
                if history_records is not None:
                    (codex_home / "history.jsonl").write_text(
                        "".join(
                            f"{json_dumps(record)}\n" for record in history_records
                        ),
                        encoding="utf-8",
                    )
                if index_records is not None:
                    (codex_home / "session_index.jsonl").write_text(
                        "".join(f"{json_dumps(record)}\n" for record in index_records),
                        encoding="utf-8",
                    )
                result = subprocess.run(
                    [sys.executable, "-c", code],
                    env=dict(os.environ, CODEX_HOME=str(codex_home)),
                    capture_output=True,
                    text=True,
                    check=False,
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            return [json.loads(line) for line in result.stdout.splitlines()]

        history_records = [
            {
                "session_id": f"history-fair-{index:02d}",
                "text": f"review history match {index:02d}",
                "ts": f"2026-07-18T00:{index:02d}:00Z",
            }
            for index in range(21)
        ]
        index_records = [
            {
                "id": "index-fair-00",
                "thread_name": "review session index match",
                "updated_at": "2026-07-18T01:00:00Z",
            }
        ]
        rows = run_recipe(history_records, index_records)

        self.assertEqual(len(rows), 21)
        match_rows = rows[:-1]
        scan_meta = rows[-1]
        self.assertEqual(scan_meta["kind"], "scan_meta")
        self.assertEqual(len(match_rows), 20)
        self.assertEqual(match_rows[0]["id"], "history-fair-00")
        self.assertEqual(match_rows[1]["id"], "index-fair-00")
        self.assertEqual(
            {row["id"] for row in match_rows},
            {"index-fair-00"} | {f"history-fair-{index:02d}" for index in range(19)},
        )
        self.assertEqual(scan_meta["match_rows_emitted"], 20)
        self.assertTrue(scan_meta["global_output_truncated"])
        self.assertEqual(
            scan_meta["sources"],
            {
                "history": {
                    "available": True,
                    "emitted": 19,
                    "match_cap": 20,
                    "retained": 20,
                    "truncated": True,
                },
                "session_index": {
                    "available": True,
                    "emitted": 1,
                    "match_cap": 20,
                    "retained": 1,
                    "truncated": False,
                },
            },
        )
        self.assertLessEqual(
            len(json.dumps(scan_meta, ensure_ascii=True).encode("utf-8")), 1024
        )

        no_match_rows = run_recipe(
            [{"session_id": "no-match", "text": "unrelated", "ts": 0}],
            None,
        )
        self.assertEqual(len(no_match_rows), 1)
        no_match_meta = no_match_rows[0]
        self.assertEqual(no_match_meta["kind"], "scan_meta")
        self.assertEqual(no_match_meta["match_rows_emitted"], 0)
        self.assertFalse(no_match_meta["global_output_truncated"])
        self.assertEqual(
            no_match_meta["sources"],
            {
                "history": {
                    "available": True,
                    "emitted": 0,
                    "match_cap": 20,
                    "retained": 0,
                    "truncated": False,
                },
                "session_index": {
                    "available": False,
                    "emitted": 0,
                    "match_cap": 20,
                    "retained": 0,
                    "truncated": False,
                },
            },
        )

    def test_session_mining_avoids_whole_record_tostring_searches(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(
            encoding="utf-8"
        )
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        recipe_start = workflow.index(marker) + len(marker)
        keyword_recipe = workflow[
            recipe_start : workflow.index("\nPY\n" + (chr(96) * 3), recipe_start)
        ]
        self.assertIn("parse only the fields and nearby records needed", skill)
        self.assertIn(
            "tool outputs only when failures or approval friction matter", skill
        )
        self.assertIn("Do not use `jq 'select(tostring | contains", workflow)
        self.assertIn("filter on record shape and specific fields", workflow)
        self.assertIn("function_call_output", workflow)
        self.assertIn("def hit_window", workflow)
        self.assertIn("hit_window(text, needle)", workflow)
        self.assertIn("def iter_top_level_fields", workflow)
        self.assertIn("thread_name", workflow)
        self.assertIn("session_id", workflow)
        self.assertIn("current_date", workflow)
        self.assertIn("sandbox_policy", workflow)
        self.assertIn("model_provider", workflow)
        self.assertIn("'output'", workflow)
        self.assertIn("'arguments'", workflow)
        self.assertIn("yield from iter_top_level_fields(payload)", workflow)
        self.assertIn("elif isinstance(value, dict)", workflow)
        self.assertIn("for item in value.values()", workflow)
        self.assertIn("elif item_type == 'user_message'", workflow)
        self.assertIn("elif item_type == 'task_complete'", workflow)
        self.assertIn("payload.get('message')", workflow)
        self.assertIn("last_agent_message", workflow)
        self.assertNotIn("text = json.dumps(payload", workflow)
        self.assertNotIn("snippet = ' '.join(text.split())[:", workflow)
        self.assertIn("path.open('rb')", keyword_recipe)
        self.assertIn("handle.readline(max_record_bytes + 1)", keyword_recipe)
        self.assertIn(
            "while raw_line and not raw_line.endswith(b'\\n'):", keyword_recipe
        )
        self.assertIn("def iter_text(value):", keyword_recipe)
        self.assertIn("def normalized_characters(parts):", keyword_recipe)
        self.assertIn("yield from iter_text(item)", keyword_recipe)
        self.assertIn("snippet = hit_window(", keyword_recipe)
        self.assertIn(
            "iter_record_text(obj, payload, item_type)",
            keyword_recipe,
        )
        self.assertIn("yield item_type or ''", keyword_recipe)
        self.assertIn("def bounded_output_field(value, fallback):", keyword_recipe)
        self.assertIn(
            "item_type_value if isinstance(item_type_value, str) else None",
            keyword_recipe,
        )
        self.assertIn(
            "safe_item_type = bounded_output_field(item_type, '')", keyword_recipe
        )
        self.assertIn(
            "record_kind = safe_item_type or bounded_output_field(", keyword_recipe
        )
        self.assertIn(
            "timestamp = bounded_output_field(timestamp_value, '')", keyword_recipe
        )
        self.assertNotIn("text_parts", keyword_recipe)
        self.assertNotIn("' '.join(' '.join(", keyword_recipe)
        self.assertNotIn("collect_text(", keyword_recipe)
        self.assertNotIn("str(item_type", keyword_recipe)
        self.assertNotIn(
            "iter_record_text(obj, payload, item_type, safe_item_type)",
            keyword_recipe,
        )

    def test_session_mining_avoids_whole_codex_home_searches(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(
            encoding="utf-8"
        )
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        self.assertIn("read your rollout", skill)
        self.assertIn(
            "never point raw `rg` at all of `$CODEX_HOME` / `~/.codex`", skill
        )
        self.assertIn('Recent prior turn or "read your rollout":', workflow)
        self.assertIn("Do not run keyword `rg -n ... ~/.codex`", workflow)
        self.assertIn(
            "installed skills, overlays, caches, and package payloads", workflow
        )

    def test_session_mining_requires_replay_boundary_detection(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(
            encoding="utf-8"
        )
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")

        self.assertIn("copied/restamped history", skill)
        self.assertIn("A strict record-timestamp filter is not sufficient", skill)
        self.assertIn("latest genuine resume boundary", skill)
        self.assertIn("Detect resumed or forked replay", workflow)
        self.assertIn("stable fingerprint", workflow)
        self.assertIn("Do not deduplicate a real repeated short prompt", workflow)
        self.assertIn("replayed and genuinely new record counts separately", workflow)

    def test_session_mining_requires_active_and_archived_union_corpus(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(
            encoding="utf-8"
        )
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        corpus_helper = (
            root / "skills/codex-session-mining/scripts/build_session_corpus.py"
        )

        self.assertIn("active-plus-archived", skill)
        self.assertIn("Inventory both existing active and archived roots", skill)
        self.assertIn("an old path can contain a genuine later continuation", skill)
        self.assertIn("Group candidates by lifecycle identity", skill)
        self.assertIn("Do not deduplicate by basename alone", skill)
        self.assertIn(
            'for root in "$CODEX_ROOT/sessions" "$CODEX_ROOT/archived_sessions"',
            workflow,
        )
        self.assertIn("current-host corpus inventory", workflow)
        self.assertIn("set -euo pipefail", workflow)
        self.assertIn("scripts/build_session_corpus.py", skill)
        self.assertTrue(corpus_helper.is_file())
        self.assertTrue(os.access(corpus_helper, os.X_OK))
        self.assertIn(
            'python3 "$SESSION_MINING_SKILL/scripts/build_session_corpus.py"', workflow
        )
        self.assertIn('--codex-home "$CODEX_ROOT"', workflow)
        self.assertIn('--start "$LOWER_BOUND"', workflow)
        self.assertIn('--end "$UPPER_BOUND"', workflow)
        self.assertNotIn('find "$HOME/.codex/sessions/2026/', workflow)
        self.assertNotIn("2>/dev/null", workflow)
        self.assertIn("active candidate count", workflow)
        self.assertIn("archived candidate count", workflow)
        self.assertIn("union candidate count", workflow)
        self.assertIn("active accepted count", workflow)
        self.assertIn("archived accepted count", workflow)
        self.assertIn("union accepted count", workflow)
        self.assertIn("Inventory every rollout under both existing roots", workflow)
        self.assertIn("active and archived roots as one union corpus", workflow)
        self.assertIn("ordered stable record fingerprints", workflow)
        self.assertIn("required candidate boundary", workflow)
        self.assertIn("Do not merge different session identities", workflow)
        self.assertIn(
            "revalidates every traversed directory plus each entry identity", workflow
        )
        self.assertIn("last matching assistant/tool replay-evidence record", workflow)
        self.assertIn(
            "preserve every matching human prompt after that boundary", workflow
        )
        self.assertIn("`session_meta` from explicit lifecycle IDs alone", workflow)
        self.assertIn(
            "synthetic child, subagent, and external-review prompts", workflow
        )
        self.assertIn("first user-shaped record is an automation wrapper", workflow)
        self.assertIn(
            "active, archived, union, and accepted-after-deduplication counts", workflow
        )
        recursive_archive_glob = "archived_sessions/**/rollout-*.jsonl"
        self.assertIn(recursive_archive_glob, skill)
        self.assertIn(recursive_archive_glob, workflow)
        self.assertNotIn("archived_sessions/*.jsonl", skill)
        self.assertNotIn("archived_sessions/*.jsonl", workflow)

    def test_session_mining_corpus_recipe_uses_structured_helper(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(
            encoding="utf-8"
        )
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        recipe = extract_bash_block_after(
            workflow,
            "Bounded date range and current-host corpus inventory:",
        )
        self.assertIn("LOWER_BOUND=2026-03-12T00:00:00Z", recipe)
        self.assertIn("UPPER_BOUND=2026-03-14T00:00:00Z", recipe)
        self.assertIn('CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"', recipe)
        self.assertIn(
            'python3 "$SESSION_MINING_SKILL/scripts/build_session_corpus.py"', recipe
        )
        self.assertIn("--sample-limit 20", recipe)
        self.assertIn("full-root scan, not as a requested-window scan", skill)
        self.assertIn("previous runtime and current corpus scale", skill)
        self.assertIn("incomplete/failed snapshot", skill)
        self.assertIn("Before retrying", skill)
        self.assertIn("original producer and descendants are quiescent", skill)
        self.assertIn("different fresh output directory", skill)
        self.assertIn("identity-bound cleanup contract", skill)
        self.assertIn("leave a failed-run path untouched", skill)
        self.assertIn("quiet stdout is expected", workflow)
        self.assertIn("supplies no reusable checkpoint", workflow)
        self.assertIn("Before any retry", workflow)
        self.assertIn("do not start another full-root scan", workflow)
        self.assertLess(
            workflow.index("Before any retry"),
            workflow.index("After quiescence is proved, retry"),
        )
        self.assertIn("device/inode or platform-equivalent identity", workflow)
        self.assertIn("immediate pre-removal revalidation", workflow)
        self.assertIn("child-entry churn inside the same directory", workflow)
        self.assertIn("Cleanup of the failed-run path is optional", workflow)
        self.assertIn("does not close the check-to-delete replacement window", workflow)
        self.assertIn("trusted descriptor-relative cleanup primitive", workflow)
        self.assertIn(
            "binds both the verified parent directory and target directory identities",
            workflow,
        )
        self.assertIn(
            "If only pathname-based recursive deletion is available", workflow
        )
        self.assertIn("classify that result separately as missing", workflow)
        self.assertIn(
            "do not recreate it or delete anything at that pathname", workflow
        )
        self.assertIn("do not claim this run verified cleanup", workflow)
        self.assertIn("baseline identity is unavailable", workflow)
        self.assertIn("revalidation is unreadable", workflow)
        self.assertIn("current identity mismatches", workflow)
        self.assertIn("leave any present path untouched", workflow)
        self.assertIn("Never interpret missing output as an empty corpus", workflow)

    def test_session_mining_exact_session_recipe_propagates_find_failure(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        recipe = extract_bash_block_after(workflow, "Exact session ID:")
        self.assertIn('CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"', recipe)
        self.assertIn('python3 - "$SESSION_ID" "$CODEX_ROOT"', recipe)
        self.assertIn("matches_file=$(mktemp)", recipe)
        self.assertIn("trap 'rm -f \"$matches_file\"' EXIT", recipe)
        self.assertIn("-print0", recipe)
        self.assertIn("split(b'\\0')", recipe)
        self.assertIn("character.isprintable()", recipe)
        self.assertNotIn('sort -u "$matches_file"', recipe)
        self.assertNotIn("done | sort -u", recipe)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            home = temp / "home"
            codex_home = home / ".codex"
            (codex_home / "sessions").mkdir(parents=True)
            for index_name in ("session_index.jsonl", "history.jsonl"):
                (codex_home / index_name).write_text("", encoding="utf-8")

            fake_bin = temp / "fake-bin"
            fake_bin.mkdir()
            fake_find = fake_bin / "find"
            fake_find.write_text(
                "#!/bin/sh\nprintf 'find-failed\\n' >&2\nexit 23\n",
                encoding="utf-8",
            )
            fake_find.chmod(0o755)
            environment = os.environ.copy()
            environment["HOME"] = str(home)
            environment.pop("CODEX_HOME", None)
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            completed = subprocess.run(
                ["bash", "-c", recipe],
                cwd=temp,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 23)
            self.assertIn("find-failed", completed.stderr)

    def test_session_mining_exact_session_recipe_tolerates_missing_and_malformed_indexes(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        recipe = extract_bash_block_after(workflow, "Exact session ID:")
        self.assertIn("if not path.is_file():", recipe)
        self.assertIn("except OSError:", recipe)
        self.assertIn("path.open('rb')", recipe)
        self.assertIn("handle.readline(max_record_bytes + 1)", recipe)
        self.assertIn("while raw_line and not raw_line.endswith(b'\\n'):", recipe)
        self.assertIn("except (UnicodeDecodeError, json.JSONDecodeError):", recipe)
        self.assertIn("matches_session(row.get(key))", recipe)
        self.assertIn("warning: unable to read optional index", recipe)
        self.assertNotIn("ensure_ascii=False", workflow)
        self.assertGreaterEqual(workflow.count("ensure_ascii=True"), 3)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            home = temp / "home"
            codex_home = temp / "custom-codex"
            session_id = "019ce6e8-a5e3-76e1-91a2-799837c70d1e"
            active = (
                codex_home / f"sessions/2026/03/12/rollout-active-{session_id}.jsonl"
            )
            uppercase = codex_home / (
                f"sessions/2026/03/13/rollout-uppercase-{session_id.upper()}.jsonl"
            )
            archived = (
                codex_home / f"archived_sessions/rollout-archived-{session_id}.jsonl"
            )
            expected = {active, uppercase, archived}
            for path in expected:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")

            environment = os.environ.copy()
            environment["HOME"] = str(home)
            environment["CODEX_HOME"] = str(codex_home)
            missing = subprocess.run(
                ["bash", "-c", recipe],
                cwd=temp,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(missing.returncode, 0, missing.stderr)
            self.assertEqual(
                {Path(line) for line in missing.stdout.splitlines()}, expected
            )

            session_index = codex_home / "session_index.jsonl"
            bare_cr_tail_marker = "bare-cr-tail-index-marker"
            post_oversized_marker = "post-oversized-index-marker"
            decoy_marker = "session-id-text-decoy"
            session_index_payload = f"not-json-{session_id}\n".encode("utf-8")
            session_index_payload += b"x" * (1024 * 1024) + b"\r"
            session_index_payload += (
                json_dumps(
                    {
                        "session_id": session_id,
                        "text": bare_cr_tail_marker,
                    }
                )
                + "\n"
                + json_dumps(
                    {
                        "session_id": session_id,
                        "text": post_oversized_marker,
                    }
                )
                + "\n"
                + json_dumps(
                    {
                        "session_id": "different-session",
                        "text": f"{decoy_marker} mentions {session_id}",
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "session_id": session_id,
                        "text": "matching \ud800 index row",
                    }
                )
                + "\n"
            ).encode("utf-8")
            session_index.write_bytes(session_index_payload)
            (codex_home / "history.jsonl").write_text(
                f"also-not-json-{session_id}\n",
                encoding="utf-8",
            )
            malformed = subprocess.run(
                ["bash", "-c", recipe],
                cwd=temp,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(malformed.returncode, 0, malformed.stderr)
            self.assertIn(str(active), malformed.stdout)
            self.assertIn(str(archived), malformed.stdout)
            self.assertIn(post_oversized_marker, malformed.stdout)
            self.assertNotIn(bare_cr_tail_marker, malformed.stdout)
            self.assertNotIn(decoy_marker, malformed.stdout)
            self.assertIn("\\ud800", malformed.stdout)
            self.assertNotIn("not-json", malformed.stdout)

            opaque_id = "Opaque*?[ID]"
            opaque = codex_home / f"archived_sessions/rollout-opaque-{opaque_id}.jsonl"
            wrong_case = codex_home / (
                f"archived_sessions/rollout-opaque-{opaque_id.lower()}.jsonl"
            )
            glob_decoy = (
                codex_home / "archived_sessions/rollout-opaque-OpaqueXYZI.jsonl"
            )
            opaque.write_text("{}\n", encoding="utf-8")
            wrong_case.write_text("{}\n", encoding="utf-8")
            glob_decoy.write_text("{}\n", encoding="utf-8")
            opaque_recipe = recipe.replace(
                f"SESSION_ID='{session_id}'", f"SESSION_ID='{opaque_id}'", 1
            )
            opaque_result = subprocess.run(
                ["bash", "-c", opaque_recipe],
                cwd=temp,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(opaque_result.returncode, 0, opaque_result.stderr)
            self.assertEqual(
                {Path(line) for line in opaque_result.stdout.splitlines()}, {opaque}
            )

    def test_session_mining_exact_session_recipe_rejects_non_printable_paths(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        recipe = extract_bash_block_after(workflow, "Exact session ID:")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            home = temp / "home"
            codex_home = home / ".codex"
            session_id = "019ce6e8-a5e3-76e1-91a2-799837c70d1e"
            archived = codex_home / "archived_sessions"
            archived.mkdir(parents=True)
            safe = archived / f"rollout-safe-{session_id}.jsonl"
            unsafe = archived / f"rollout-unsafe\nforged-{session_id}.jsonl"
            safe.write_text("{}\n", encoding="utf-8")
            unsafe.write_text("{}\n", encoding="utf-8")

            environment = os.environ.copy()
            environment["HOME"] = str(home)
            environment.pop("CODEX_HOME", None)
            completed = subprocess.run(
                ["bash", "-c", recipe],
                cwd=temp,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(
                completed.stderr,
                "error: rollout path contains non-printable characters\n",
            )
            self.assertNotIn(str(safe), completed.stdout)
            self.assertNotIn("forged", completed.stdout)

    def test_session_retrospective_bounds_operator_output(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-retrospective/SKILL.md").read_text(
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

    def test_session_mining_recent_turn_recipe_reads_both_indexes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(
            workflow, 'Recent prior turn or "read your rollout":'
        )

        self.assertIn("heapq.heapreplace(latest, item)", code)
        self.assertIn("handle.readline(max_record_bytes + 1)", code)
        self.assertNotIn("rows.append(", code)

        with tempfile.TemporaryDirectory() as home:
            codex_home = Path(home) / ".codex"
            codex_home.mkdir()
            history_rows = [
                {
                    "session_id": f"history-{index}",
                    "ts": f"2026-06-04T00:{index:02d}:00Z",
                    "text": f"history row {index}",
                }
                for index in range(20)
            ]
            oversized_marker = "oversized-record-marker"
            bare_cr_tail_marker = "bare-cr-tail-marker"
            post_oversized_marker = "post-oversized-marker"
            oversized_record = json_dumps(
                {
                    "session_id": oversized_marker,
                    "ts": "2026-06-04T00:59:00Z",
                    "text": "x" * (1024 * 1024 + 128),
                }
            )
            history_lines = [json_dumps(row) for row in history_rows]
            history_lines.append(oversized_record)
            history_payload = ("\n".join(history_lines) + "\n").encode("utf-8")
            history_payload += b"x" * (1024 * 1024) + b"\r"
            history_payload += (
                json_dumps(
                    {
                        "session_id": bare_cr_tail_marker,
                        "ts": "2026-06-04T01:00:00Z",
                        "text": "must remain part of the oversized physical line",
                    }
                )
                + "\n"
                + json_dumps(
                    {
                        "session_id": post_oversized_marker,
                        "ts": "2026-06-04T01:01:00Z",
                        "text": "valid record after the oversized physical line",
                    }
                )
                + "\n"
            ).encode("utf-8")
            (codex_home / "history.jsonl").write_bytes(history_payload)
            long_index_value = "z" * 1000
            (codex_home / "session_index.jsonl").write_text(
                json_dumps(
                    {
                        "session_id": "index-session",
                        "updated_at": "2026-06-03T00:00:00Z",
                        "cwd": f"/tmp/{long_index_value}",
                        "thread_name": "session index row",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys.executable, "-c", code],
                check=True,
                capture_output=True,
                env=dict(os.environ, HOME=home),
                text=True,
            )

        lines = result.stdout.splitlines()
        self.assertEqual(13, len(lines))
        self.assertIn("history-19", result.stdout)
        self.assertIn("index-session", result.stdout)
        self.assertIn("session_index.jsonl", result.stdout)
        self.assertNotIn(oversized_marker, result.stdout)
        self.assertNotIn(bare_cr_tail_marker, result.stdout)
        self.assertIn(post_oversized_marker, result.stdout)
        self.assertNotIn(long_index_value, result.stdout)

    def test_session_mining_exact_probe_handles_real_record_shapes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n```", start)]

        needle = "needle-structured-probe"
        jsonl = root / "tests/fixtures/codex_session_mining_exact_probe.jsonl"
        result = subprocess.run(
            [sys.executable, "-c", code, str(jsonl), needle],
            check=True,
            capture_output=True,
            text=True,
        )

        output = result.stdout
        for kind in (
            "history",
            "session_meta",
            "turn_context",
            "user_message",
            "function_call_output",
            "task_complete",
            "thread/start",
        ):
            self.assertIn(f":{kind}:", output)
        self.assertIn("top-level output", output)

        metadata_result = subprocess.run(
            [sys.executable, "-c", code, str(jsonl), "approval_policy"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn(":turn_context:", metadata_result.stdout)

    def test_session_mining_exact_probe_matches_late_nested_signal_without_full_projection(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n" + (chr(96) * 3), start)]
        row = {
            "type": "response_item",
            "timestamp": "2026-07-17T00:00:00Z",
            "payload": {
                "type": "function_call_output",
                "output": {
                    "nested": [
                        {"before": ("x" * 900_000) + "late\n"},
                        {
                            "after": "\tneedle",
                            "tail": "bounded-cross-boundary-tail",
                        },
                    ]
                },
            },
        }
        raw_record = (json_dumps(row) + "\n").encode("utf-8")
        self.assertLessEqual(len(raw_record), 1024 * 1024)

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout-large-accepted.jsonl"
            rollout.write_bytes(raw_record)
            result = subprocess.run(
                [sys.executable, "-c", code, str(rollout), "late needle"],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertIn(f"{rollout}:1:", result.stdout)
        self.assertIn("late needle", result.stdout)
        self.assertIn("bounded-cross-boundary-tail", result.stdout)
        self.assertLess(len(result.stdout), 1200)
        self.assertNotIn("x" * 512, result.stdout)

    def test_session_mining_exact_probe_drains_bare_cr_oversized_decoy_through_lf(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n" + (chr(96) * 3), start)]
        decoy_marker = "bare-cr-decoy-marker"
        normal_marker = "post-oversized-normal-marker"
        decoy = {
            "type": "response_item",
            "timestamp": "2026-07-17T00:00:00Z",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": f"bounded needle {decoy_marker}",
                    }
                ],
            },
        }
        normal = {
            "type": "response_item",
            "timestamp": "2026-07-17T00:01:00Z",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": f"bounded needle {normal_marker}",
                    }
                ],
            },
        }
        payload = b"x" * (1024 * 1024) + b"\r"
        payload += (json_dumps(decoy) + "\n" + json_dumps(normal) + "\n").encode(
            "utf-8"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout-oversized-decoy.jsonl"
            rollout.write_bytes(payload)
            result = subprocess.run(
                [sys.executable, "-c", code, str(rollout), "bounded needle"],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertIn(f"{rollout}:2:", result.stdout)
        self.assertIn(normal_marker, result.stdout)
        self.assertNotIn(decoy_marker, result.stdout)

    def test_session_mining_exact_probe_bounds_and_escapes_untrusted_metadata(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n" + (chr(96) * 3), start)]
        row = {
            "type": "outer\nkind\x00" + ("T" * 220_000),
            "timestamp": {"nested": "timestamp-dict-marker-" + ("Q" * 220_000)},
            "ts": "2026-07-17T00:00:00Z\nforged-ts-line\x1b" + ("Z" * 110_000),
            "payload": {
                "type": {
                    "nested": "payload-type-dict-marker-" + ("P" * 330_000),
                    "control": "\nforged-payload-type-line",
                },
                "content": {
                    "nested": [
                        "metadata safe needle",
                        "bounded metadata tail",
                    ]
                },
            },
        }
        raw_record = (json_dumps(row) + "\n").encode("utf-8")
        self.assertLessEqual(len(raw_record), 1024 * 1024)

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout-untrusted-metadata.jsonl"
            rollout.write_bytes(raw_record)
            result = subprocess.run(
                [sys.executable, "-c", code, str(rollout), "metadata safe needle"],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.stdout.count("\n"), 1)
        self.assertLess(len(result.stdout.encode("utf-8")), 1000)
        self.assertIn("metadata safe needle", result.stdout)
        self.assertIn("bounded metadata tail", result.stdout)
        self.assertIn("\\u0000", result.stdout)
        self.assertIn("\\u001b", result.stdout)
        self.assertNotIn("\x00", result.stdout)
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("forged-ts-line\n", result.stdout)
        self.assertNotIn("timestamp-dict-marker", result.stdout)
        self.assertNotIn("payload-type-dict-marker", result.stdout)
        self.assertNotIn("T" * 256, result.stdout)
        self.assertNotIn("Q" * 256, result.stdout)
        self.assertNotIn("P" * 256, result.stdout)
        self.assertNotIn("Z" * 256, result.stdout)

    def test_session_mining_exact_probe_escapes_selected_content_controls(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n" + (chr(96) * 3), start)]
        needle = "match-csi=\x1b[31m literal Unicode 保留"
        selected_content = (
            "prefix nul=\x00 esc=\x1b "
            "osc=\x1b]0;unsafe-title\x07 bel=\x07 "
            f"{needle} tail=\x1b[0m"
        )
        row = {
            "type": "response_item",
            "timestamp": "2026-07-18T00:00:00Z",
            "payload": {
                "type": "function_call_output",
                "output": selected_content,
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout-control-output.jsonl"
            rollout.write_text(json_dumps(row) + "\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-c", code, str(rollout), needle],
                check=True,
                capture_output=True,
                text=True,
            )

        output_bytes = result.stdout.encode("utf-8")
        self.assertEqual(result.stdout.count("\n"), 1)
        self.assertLess(len(output_bytes), 1000)
        self.assertIn("nul=\\u0000", result.stdout)
        self.assertIn("esc=\\u001b", result.stdout)
        self.assertIn("osc=\\u001b]0;unsafe-title\\u0007", result.stdout)
        self.assertIn("bel=\\u0007", result.stdout)
        self.assertIn("match-csi=\\u001b[31m", result.stdout)
        self.assertIn("tail=\\u001b[0m", result.stdout)
        self.assertIn("literal Unicode 保留", result.stdout)
        self.assertNotIn("\\u4fdd\\u7559", result.stdout)
        for control_byte in (b"\x00", b"\x07", b"\x1b"):
            self.assertNotIn(control_byte, output_bytes)

    def test_session_mining_exact_probe_matches_full_item_type_before_output_projection(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        marker = 'python3 - "$ROLLOUT" "$NEEDLE" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        code = workflow[start : workflow.index("\nPY\n" + (chr(96) * 3), start)]
        needle = "尾部类型针"
        item_type = "分类\n" + ("x" * 400) + needle
        timestamp = "2026-07-17T00:00:00Z"
        row = {
            "type": "response_item",
            "timestamp": timestamp,
            "payload": {"type": item_type},
        }
        raw_record = (json_dumps(row) + "\n").encode("utf-8")
        self.assertLessEqual(len(raw_record), 1024 * 1024)

        with tempfile.TemporaryDirectory() as temp_dir:
            rollout = Path(temp_dir) / "rollout-full-item-type.jsonl"
            rollout.write_bytes(raw_record)
            result = subprocess.run(
                [sys.executable, "-c", code, str(rollout), needle],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.stdout.count("\n"), 1)
        self.assertLess(len(result.stdout.encode("utf-8")), 1000)
        line = result.stdout.rstrip("\n")
        output_prefix = f"{rollout}:1:{timestamp}:"
        self.assertTrue(line.startswith(output_prefix))
        record_kind, snippet = line[len(output_prefix) :].split(":", 1)
        self.assertEqual(len(record_kind), 80)
        self.assertTrue(record_kind.endswith("..."))
        self.assertIn("\\u5206\\u7c7b", record_kind)
        self.assertNotIn("分类", result.stdout)
        self.assertNotIn(needle, record_kind)
        self.assertIn(needle, snippet)

    def test_session_mining_failure_probe_handles_event_message_fields(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(
            workflow, "Focus on tool failures or approval friction:"
        )
        jsonl = root / "tests/fixtures/codex_session_mining_exact_probe.jsonl"
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        self.assertIn(":event_msg:task_complete:", result.stdout)
        self.assertIn("permission denied", result.stdout)
        self.assertIn(":turn_context:None:", result.stdout)
        self.assertIn("approval_policy", result.stdout)

    def test_session_mining_bounded_rollout_probe_handles_structured_user_messages(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(
            workflow, "Search a bounded rollout set without dumping full JSONL records:"
        )
        jsonl = root / "tests/fixtures/codex_session_mining_exact_probe.jsonl"
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        self.assertIn(":event_msg:user_message:", result.stdout)
        self.assertIn("thread/start", result.stdout)

    def test_session_mining_bounded_rollout_probe_caps_output(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(
            workflow, "Search a bounded rollout set without dumping full JSONL records:"
        )
        jsonl = root / "tests/fixtures/codex_session_mining_many_thread_start.jsonl"
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        lines = result.stdout.splitlines()
        self.assertEqual(20, len(lines))
        self.assertIn("sample 20", lines[-1])
        self.assertNotIn("sample 21", result.stdout)

    def test_session_mining_bounded_rollout_probe_skips_tool_output(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / "skills/codex-session-mining/references/workflow.md"
        ).read_text(encoding="utf-8")
        code = extract_python_block_after(
            workflow, "Search a bounded rollout set without dumping full JSONL records:"
        )
        jsonl = (
            root
            / "tests/fixtures/codex_session_mining_tool_output_then_thread_start.jsonl"
        )
        env = dict(os.environ, CODEX_ROLLOUT_SAMPLE=str(jsonl))

        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )

        self.assertEqual(1, len(result.stdout.splitlines()))
        self.assertIn(":event_msg:thread/start:", result.stdout)
        self.assertIn("real event", result.stdout)
        self.assertNotIn("tool output", result.stdout)


if __name__ == "__main__":
    unittest.main()
