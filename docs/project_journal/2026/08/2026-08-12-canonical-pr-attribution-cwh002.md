---
id: 20260812-cwh002
title: Canonical PR Attribution
status: completed
created: 2026-08-12
updated: 2026-08-12
branch: wip/canonical-pr-attribution
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/68
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
- `python3 -B -m unittest tests.test_pr_attribution`: 66 tests passed.
- Full repository suite: 1,125 tests passed with commit signing disabled only for temporary Git fixtures.
- Fresh-context review identified incomplete legacy multi-lifecycle indexing; the follow-up now indexes every verified lifecycle, rejects incomplete probes, and counts each physical rollout once.
- GitHub Codex identified metadata-only descendants that were invisible from the root rollout. The follow-up now builds one bounded parent-to-child metadata index across physical rollouts, revalidates each reachable binding, and produces the same family result from root, child, or grandchild entry points.
- Final fresh-context review identified that active rollout identity alone did not stabilize content across the metadata and vote passes. The follow-up freezes the first fully read complete-record prefix within the inventory size boundary, verifies its digest on every pass, and ignores later append-only growth until the next invocation.
- A subsequent fresh-context review identified that archived growth and post-inventory rollout candidates could still escape the frozen evidence set. The follow-up now requires archived exact-size/full-content stability, revalidates every frozen candidate, binds every originally traversed directory identity, and compares a bounded, stabilized candidate path/object projection while permitting candidate-neutral file churn.
- `codex-session-mining` skill validation passed through the isolated PyYAML fallback.
- Project journal validation passed.
