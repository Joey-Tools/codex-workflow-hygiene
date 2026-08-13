---
id: 20260812-cwh003
title: Exact Rollout ripgrep Search Protocol
status: completed
created: 2026-08-12
updated: 2026-08-13
branch: codex/rollout-rg-search
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/71
supersedes: []
superseded_by:
---

# Exact Rollout ripgrep Search Protocol

## Summary

- Added a fixed ripgrep 15.x protocol for keyword discovery in one already-selected rollout without printing an unbounded matching JSONL record.

## Current State

- `codex-session-mining` routes exact-rollout keyword discovery through count, matching-line position, and optional bounded raw-prefix stages.
- The protocol preserves native case-sensitive regex or explicitly allowlisted matching flags and keeps output, framing, transformation, and engine controls fixed.
- Exceptional exhaustive position collection has a 64 MiB retained-output admission bound and remains explicitly live, non-snapshot evidence.
- Dedicated contract tests cover the documentation surface and ripgrep 15.x conformance without changing the shared skill-structure tests owned by the concurrent retrospective workstream.
- CI installs the official ripgrep 15.2.0 Linux release asset after verifying its pinned SHA-256 digest, so the dynamic conformance tests are mandatory on GitHub runners.

## Next Steps

- None.

## Evidence

- `skills/codex-session-mining/references/rollout-search.md`
- `skills/codex-session-mining/SKILL.md`
- `skills/codex-session-mining/references/workflow.md`
- `tests/test_rollout_search_contract.py`
- `python3 -B -m unittest -v tests.test_rollout_search_contract tests.test_skill_structure`: 42 tests passed.
- `CI=true python3 -B -m unittest -q tests.test_rollout_search_contract`: 14 tests passed with the CI-only ripgrep version gate enabled.
- Full repository suite through `run_process_group_deadline.py`, with process-scoped test-fixture commit signing disabled and the CI version gate enabled: 1,147 tests passed in 68.123 seconds.
- `codex_skill_validate.py skills/codex-session-mining`: `Skill is valid!` via the isolated uv/PyYAML path.
- `actionlint 1.7.12`, project-journal validation, and `git diff --check` passed.
- Two read-only pre-commit audits found no remaining P1/P2 in the protocol implementation.
