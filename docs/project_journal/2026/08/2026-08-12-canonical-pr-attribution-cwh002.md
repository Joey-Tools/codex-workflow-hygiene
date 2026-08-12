---
id: 20260812-cwh002
title: Canonical PR Attribution
status: completed
created: 2026-08-12
updated: 2026-08-12
branch: wip/canonical-pr-attribution
pr:
supersedes: []
superseded_by:
---

# Canonical PR Attribution

## Summary

- Moved deterministic wholly Codex-authored PR attribution into the canonical public skill owner.

## Current State

- `codex-session-mining` owns the bounded task-family attribution helper, its focused regression suite, and the public skill contract for invocation and fallback behavior.
- Canonical ownership prevents the private overlay scheduled sync from deleting the helper while its downstream regression tests remain.

## Next Steps

- None.

## Evidence

- `skills/codex-session-mining/scripts/pr_attribution.py`
- `skills/codex-session-mining/SKILL.md`
- `tests/test_pr_attribution.py`
- `python3 -B -m unittest tests.test_pr_attribution`: 41 tests passed.
- Full repository suite: 1,100 tests passed with commit signing disabled only for temporary Git fixtures.
- `codex-session-mining` skill validation passed through the isolated PyYAML fallback.
- Project journal validation passed.
