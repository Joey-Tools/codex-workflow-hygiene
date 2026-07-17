---
id: 20260717-smc002
title: Session Mining Bare CR Drain
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260717-codex-workflow-hygiene-session-mining-bare-cr-drain
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/47
supersedes: []
superseded_by:
---

# Session Mining Bare CR Drain

## Summary

- Kept oversized binary JSONL records draining until the newline delimiter used by `readline()`.
- Added a regression fixture where the first bounded chunk ends in a bare carriage return.

## Current State

- A bare `\r` cannot make the tail of one oversized physical line appear as a separate JSON record.
- The first valid newline-delimited record after the oversized line remains discoverable.

## Next Steps

- None.

## Evidence

- https://github.com/Joey-Tools/codex-workflow-hygiene/pull/47
- `tests.test_skill_structure.SkillStructureTests.test_session_mining_recent_turn_recipe_reads_both_indexes`
- `python3 -m unittest discover -s tests -p 'test_*.py'` (938 passed, 1 skipped)
- `quick_validate.py skills/codex-session-mining`
- Isolated private-overlay review finding: P2 bare `\r` drain mismatch
