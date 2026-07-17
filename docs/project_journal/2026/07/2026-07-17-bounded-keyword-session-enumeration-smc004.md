---
id: 20260717-smc004
title: Bounded Keyword Search and Fail-Closed Session Enumeration
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260717-codex-workflow-hygiene-bound-keyword-and-propagate-glob-errors
pr:
supersedes: []
superseded_by:
---

# Bounded Keyword Search and Fail-Closed Session Enumeration

## Summary

- Bounded the exact-rollout keyword recipe to 1 MiB physical JSONL records with LF-only oversized-record draining.
- Replaced full selected-text joins with incremental nested-string traversal, whitespace normalization, matching, and bounded context projection.
- Replaced local and embedded session-meta Path.glob() enumeration with explicit os.scandir() filtering and sorting.

## Current State

- A late keyword can match across nested strings and whitespace boundaries without retaining a second full copy of tool output.
- An oversized bare-CR decoy is discarded through the next LF, while the following normal record remains discoverable.
- Missing session directories remain optional, while permission and I/O failures during directory enumeration produce the redacted session directory unreadable failure.

## Next Steps

- None.

## Evidence

- Focused keyword and session-meta regressions: 6 tests passed.
- Related skill modules: 878 tests passed with process-local fixture commit signing disabled.
- Full test discovery: 945 tests passed with process-local fixture commit signing disabled.
- Both codex-session-mining and codex-session-retrospective passed quick_validate.py.
- Python compilation, project-journal validation, and git diff --check passed.
- Ruff check passed when excluding the repository's existing F541 finding; the same lone finding is present at HEAD.
- Ruff format check remains nonzero for the same three Python files at HEAD and in this branch, so no unrelated whole-file reformat was retained.
