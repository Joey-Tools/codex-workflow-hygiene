---
id: 20260723-smc006
title: Session Corpus Deadline Guardrail
status: completed
created: 2026-07-23
updated: 2026-07-23
branch: codex/daily-skill-friction-20260723-codex-workflow-hygiene-session-corpus-deadline-guardrail
pr:
supersedes: []
superseded_by:
---

# Session Corpus Deadline Guardrail

## Summary

- Added explicit runtime, polling, and retry guidance for complete active-plus-archived session corpus scans.

## Current State

- Corpus-helper deadlines are sized from full-root cost and previous successful runtime rather than the requested timestamp-window width.
- Quiet stdout is treated as expected while a healthy full-root scan is still running.
- Timed-out or interrupted scans are classified as incomplete and rerun only with a fresh nonexistent output directory; missing or partial output cannot be reported as an empty or complete corpus.
- Failed output directories are removed only after producer quiescence and directory-object identity revalidation; child-entry churn within the same directory is not treated as replacement. A missing target is not recreated or claimed as verified cleanup, while unavailable baseline identity, unreadable revalidation, identity mismatch, or unproven quiescence leaves any present path untouched for handoff.

## Next Steps

- Monitor whether full-root session audits still require a user to restart an otherwise healthy scan.

## Evidence

- Session `019f8616-6fbd-7e13-9057-1d703c78fc88` required a user-triggered retry after a healthy 53 GiB cross-root scan was interrupted at roughly three minutes; the fresh rerun completed after several more minutes.
- The 2026-07-23 Daily Skill Friction audit reproduced the short-deadline failure at 300 seconds before the same fixed window completed under a 900-second deadline.
- A fresh-context internal review identified unsafe pathname-only cleanup after interruption; the fix now protects directory object identity and keeps quiescence, unreadable state, missing identity, and replacement outcomes distinct.
- `python3 -m unittest tests.test_skill_structure tests.test_session_corpus`: 83 tests passed.
- Full `python3 -m unittest discover -s tests`: 1,058 tests passed with commit signing disabled only for temporary Git fixture commits.
- `uv run --isolated --with pyyaml ... quick_validate.py skills/codex-session-mining`: passed.
- `skills/codex-session-mining/SKILL.md`
- `skills/codex-session-mining/references/workflow.md`
- `tests/test_skill_structure.py`
