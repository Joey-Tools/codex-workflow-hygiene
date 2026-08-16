from __future__ import annotations

import os
from pathlib import Path
import unittest


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

    def test_codex_rules_hygiene_is_archived_and_not_loadable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        active_path = root / "skills/codex-rules-hygiene"
        archive_path = root / "docs/archive/codex-rules-hygiene"
        archived_readme = archive_path / "README.md"
        archived_reference = archive_path / "audit-cadence.md"

        self.assertFalse(active_path.exists())
        self.assertFalse(any(archive_path.rglob("SKILL.md")))
        for path in (archived_readme, archived_reference):
            self.assertTrue(path.is_file(), path)
            self.assertFalse(path.is_symlink(), path)

        archive_text = archived_readme.read_text(encoding="utf-8")
        self.assertFalse(archive_text.startswith("---\n"))
        self.assertIn("This directory is not a loadable Codex skill.", archive_text)
        self.assertIn("## Historical Procedure (Frozen)", archive_text)
        self.assertIn(
            "Frozen historical companion",
            archived_reference.read_text(encoding="utf-8"),
        )

    def test_bounded_command_output_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill_root = root / "skills/bounded-command-output"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        patterns = (skill_root / "references/command-patterns.md").read_text(encoding="utf-8")
        frontmatter = skill.split("---", 2)[1]
        trigger_gate = skill.split("## Trigger Gate\n", 1)[1].split("\n## ", 1)[0]
        supervisor = skill_root / "scripts/run_process_group_deadline.py"
        interface = (skill_root / "agents/openai.yaml").read_text(encoding="utf-8")

        for trigger in (
            "broad searches or inventories",
            "large Jenkins, GitHub Actions, artifact, manual, diff, or review-range reads",
            "broad database aggregates or filesystem walks with uncertain runtime",
            "broad or noisy process diagnostics",
            "verbose xcodebuild or other tests and builds",
            "spinner-heavy container builds",
        ):
            self.assertIn(trigger, skill)
        self.assertIn("Apply alongside the domain skill", skill)
        self.assertIn(
            "Do not use for routine exact commands whose scope, output, and runtime are already predictably small.",
            frontmatter,
        )
        self.assertIn("## Trigger Gate", skill)
        self.assertIn("at least one concern is real", trigger_gate)
        self.assertIn(
            "scope, output, and runtime are all known to be small and fast",
            trigger_gate,
        )
        self.assertIn(
            "Do not trigger it merely because any command could theoretically hang",
            trigger_gate,
        )
        self.assertIn("Small visible output can still qualify", trigger_gate)
        self.assertIn(
            "controls command shape, execution deadlines, and output handling only",
            skill,
        )
        self.assertIn("Small output does not imply bounded runtime", skill)
        self.assertIn("expected result is one line", skill)
        self.assertIn("known to be both small and fast", skill)
        self.assertIn("task-specific deadlines", skill)
        self.assertIn("Do not guess `/usr/bin` or a package-manager prefix", skill)
        self.assertIn("nested host-language and shell quoting", skill)
        self.assertIn("Pass them as positional arguments", skill)
        self.assertIn("one aggregate output and retained-byte budget", skill)
        self.assertIn("native Windows", skill)
        self.assertIn("WSL follows the POSIX path", skill)
        self.assertIn("do not claim process-group or descendant cleanup", skill)
        self.assertIn("expected output is a single value", skill)
        self.assertIn("display backstops, not as execution-time bounds", skill)
        self.assertIn("finite wall-clock deadline", skill)
        self.assertIn("explicitly capped candidate-filename sample", skill)
        self.assertIn("bounded filename samples", skill)
        self.assertIn("enforced ceiling across all retained artifacts", skill)
        self.assertIn("fixed aggregate-byte and segment-count caps", skill)
        self.assertIn("removes or reuses old segments", skill)
        self.assertIn("keep the retained set below its fixed ceiling or terminate the producer", skill)
        self.assertIn("do not by themselves bound disk growth", skill)
        self.assertIn("pollable TTY or PTY shape", skill)
        self.assertIn("plain-pipe session after stdin closes", skill)
        self.assertIn("`ALL_TOOLS` and similar tool registries", skill)
        self.assertIn("scalar `name` and `description` fields", skill)
        self.assertIn("cap the result count", skill)
        self.assertIn("clipped description before calling `text()`", skill)
        self.assertIn("Never emit raw registry entries or a full schema", skill)
        self.assertIn("only after the main skill's trigger gate applies", patterns)
        self.assertIn(
            "producer scope, runtime, retained bytes, and visible output as separate bounds",
            patterns,
        )
        self.assertIn("Tool registry or schema discovery", patterns)
        self.assertIn("Passing raw registry entries or full schema objects to `text()`", patterns)
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
        self.assertIn("one aggregate visible-output and retained-byte ceiling", patterns)
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
        self.assertIn("SQLite `.timeout` controls how long the client waits for a busy lock", patterns)
        self.assertIn("it is not a query-execution deadline", patterns)
        self.assertIn("Broad macOS `du` walks", patterns)
        self.assertIn("A PTY and repeated polling", patterns)
        self.assertIn("report every timed-out branch as unknown or incomplete", patterns)
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
        self.assertIn("retained-output byte ceilings remain a separate caller responsibility", patterns)
        self.assertIn("keep an outer pipe reader waiting for EOF", patterns)
        self.assertIn("or prove group quiescence", patterns)
        self.assertIn("not a real-time scheduler", patterns)
        self.assertNotIn("If a tool launches descendants", patterns)
        self.assertNotIn("terminates and reaps the entire unit", patterns)
        self.assertTrue(supervisor.is_file())
        self.assertTrue(os.access(supervisor, os.X_OK))
        self.assertIn("$bounded-command-output", interface)
        self.assertIn("time-bounded, pollable, and compact", interface)
        self.assertIn("allow_implicit_invocation: true", interface)
        self.assertNotIn("TODO", skill)

    def test_skill_authoring_validator_discovery_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-skill-authoring/SKILL.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("`SKILL_AUTHORING_DIR`", skill)
        self.assertIn("`SKILL_CREATOR_DIR`", skill)
        self.assertIn("`--validator` takes priority", skill)
        self.assertIn("non-empty `CODEX_SKILL_VALIDATOR`", skill)
        self.assertIn("the wrapper checks these fixed locations in order", skill)
        self.assertIn("`$CODEX_HOME/skills/.system/skill-creator", skill)
        self.assertIn("`$CODEX_HOME/.system/skill-creator", skill)
        self.assertIn("lexical loaded skills root", skill)
        self.assertIn("resolved source skills root", skill)
        self.assertIn("only when `CODEX_HOME` is unset or empty", skill)
        self.assertIn("does not scan ancestors or search `PATH`", skill)
        self.assertNotIn(
            '"$HOME/.codex/skills/codex-skill-authoring/scripts/codex_skill_validate.py"',
            skill,
        )

    def test_session_mining_rollout_scanner_documentation_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill_root = root / "skills/codex-session-mining"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        workflow = (skill_root / "references/workflow.md").read_text(
            encoding="utf-8"
        )
        ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        scanner = skill_root / "scripts/scan_rollout.py"
        retired_reference = skill_root / "references/rollout-search.md"

        self.assertTrue(scanner.is_file())
        self.assertIn("scripts/scan_rollout.py", skill)
        self.assertIn("scripts/scan_rollout.py", workflow)
        self.assertFalse(retired_reference.exists())

        combined = f"{skill}\n{workflow}"
        self.assertIn("codex.rollout-scan/v1", workflow)
        for heading in (
            "## 1. Select The Smallest Relevant Rollout Set",
            "## 2. Scan One Exact Rollout",
            "### Typed JSONL Protocol",
            "### Stateless Result Windows",
            "### Input And Completeness Boundaries",
        ):
            self.assertIn(heading, workflow)
        for command in ("search", "shapes"):
            self.assertIn(command, combined)
        for flag in (
            "--mode",
            "--category",
            "--result-offset",
            "--max-results",
            "--max-output-bytes",
            "--prefix-end-bytes",
        ):
            self.assertIn(flag, workflow)
        for protocol_term in (
            "typed JSONL",
            "`start`",
            "`match`",
            "`shape`",
            "`end`",
            "partial",
            "Missing `end`",
            "independent",
            "frozen_prefix_bytes",
        ):
            self.assertIn(protocol_term, combined)
        for ceiling in (
            "1 MiB",
            "192 MiB",
            "250,000",
            "1024 UTF-8 bytes",
            "20 records",
            "64 KiB",
            "256 KiB",
        ):
            self.assertIn(ceiling, combined)
        self.assertIn("model may choose", combined.lower())
        self.assertIn("bounded lookup", combined.lower())
        self.assertIn("no canonical exact-ID", combined)
        self.assertIn("no-match", combined.lower())
        self.assertIn("do not run a per-line key dump", skill)
        self.assertIn("jq -R 'fromjson | keys'", skill)
        self.assertIn("whole-record search", skill)
        self.assertIn("filter by record type and field first", skill)
        self.assertIn("Do not scan all of `~/.codex`", skill)
        self.assertIn("Do not point raw `rg -n` at the whole `$CODEX_HOME`", skill)
        self.assertIn("whole `$CODEX_HOME`", combined)
        self.assertIn("no-follow regular-file descriptor", workflow)
        self.assertNotIn("references/rollout-search.md", combined)
        self.assertNotIn("python3 - \"$ROLLOUT\" \"$NEEDLE\"", workflow)
        self.assertNotIn("def iter_record_text(", workflow)
        self.assertNotIn("def bounded_jsonl(", workflow)
        self.assertNotIn("rg --json", workflow)
        self.assertNotIn("rg 15.2", combined.lower())
        self.assertNotIn("ripgrep-15.2.0", ci)

    def test_session_mining_requires_replay_boundary_detection(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(encoding="utf-8")
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")

        self.assertIn("copied and restamped earlier history", skill)
        self.assertIn("A strict record-timestamp filter is not sufficient", skill)
        self.assertIn("latest genuine resume boundary", skill)
        self.assertIn("Detect resumed or forked replay", workflow)
        self.assertIn("stable fingerprint", workflow)
        self.assertIn("Do not deduplicate a real repeated short prompt", workflow)
        self.assertIn("replayed and genuinely new record counts separately", workflow)

    def test_session_mining_requires_active_and_archived_union_corpus(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(encoding="utf-8")
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(encoding="utf-8")
        corpus_helper = root / "skills/codex-session-mining/scripts/build_session_corpus.py"

        self.assertIn("inventory both `~/.codex/sessions/` and `~/.codex/archived_sessions/`", skill)
        self.assertIn("build one union corpus", skill)
        self.assertIn("flat or date-nested archive layouts", skill)
        self.assertIn("inventory every rollout under both existing active and archived roots first", skill)
        self.assertIn("A rollout in either root may have an old dated path or filename", skill)
        self.assertIn("group candidates by lifecycle session ID", skill)
        self.assertIn("Do not deduplicate by basename alone", skill)
        self.assertIn("current-host corpus inventory", workflow)
        self.assertIn("set -euo pipefail", workflow)
        self.assertIn("scripts/build_session_corpus.py", skill)
        self.assertTrue(corpus_helper.is_file())
        self.assertTrue(os.access(corpus_helper, os.X_OK))
        self.assertIn('python3 "$SESSION_MINING_SKILL/scripts/build_session_corpus.py"', workflow)
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
        self.assertIn("synthetic child, subagent, and external-review prompts", workflow)
        self.assertIn("first user-shaped record is an automation wrapper", workflow)
        self.assertIn("active, archived, union, and accepted-after-deduplication counts", workflow)
        recursive_archive_glob = "archived_sessions/**/rollout-*.jsonl"
        self.assertIn(recursive_archive_glob, skill)
        self.assertNotIn("archived_sessions/*.jsonl", skill)
        self.assertNotIn("archived_sessions/*.jsonl", workflow)

    def test_session_mining_corpus_recipe_uses_structured_helper(self) -> None:
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills/codex-session-mining/SKILL.md").read_text(
            encoding="utf-8"
        )
        workflow = (root / "skills/codex-session-mining/references/workflow.md").read_text(
            encoding="utf-8"
        )
        recipe = extract_bash_block_after(
            workflow,
            "### Bounded Date Range And Current-Host Corpus",
        )
        self.assertIn("LOWER_BOUND=2026-03-12T00:00:00Z", recipe)
        self.assertIn("UPPER_BOUND=2026-03-14T00:00:00Z", recipe)
        self.assertIn('CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"', recipe)
        self.assertIn('python3 "$SESSION_MINING_SKILL/scripts/build_session_corpus.py"', recipe)
        self.assertIn('--sample-limit 20', recipe)
        self.assertIn("full-root cost, not a requested-window cost", skill)
        self.assertIn("previous successful runtime", skill)
        self.assertIn("classify the result as incomplete", skill)
        self.assertIn("Before any retry", skill)
        self.assertIn("without starting another full-root scan", skill)
        self.assertLess(
            skill.index("Before any retry"),
            skill.index("After quiescence is proved, retry"),
        )
        self.assertIn("different fresh nonexistent output directory", skill)
        self.assertIn("original producer and its descendants are quiescent", skill)
        self.assertIn("binds the verified parent and target directory identities", skill)
        self.assertIn("target is missing at revalidation", skill)
        self.assertIn("leave any present path untouched", skill)
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
        self.assertIn("binds both the verified parent directory and target directory identities", workflow)
        self.assertIn("If only pathname-based recursive deletion is available", workflow)
        self.assertIn("classify that result separately as missing", workflow)
        self.assertIn("do not recreate it or delete anything at that pathname", workflow)
        self.assertIn("do not claim this run verified cleanup", workflow)
        self.assertIn("baseline identity is unavailable", workflow)
        self.assertIn("revalidation is unreadable", workflow)
        self.assertIn("current identity mismatches", workflow)
        self.assertIn("leave any present path untouched", workflow)
        self.assertIn("Never interpret missing output as an empty corpus", workflow)


if __name__ == "__main__":
    unittest.main()
