---
id: 20260723-smc006
title: Session Corpus Deadline Guardrail
status: completed
created: 2026-07-23
updated: 2026-07-23
branch: codex/daily-skill-friction-20260723-codex-workflow-hygiene-session-corpus-deadline-guardrail
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/62
supersedes: []
superseded_by:
---

# Session Corpus Deadline Guardrail

## Summary

- Added explicit runtime, polling, and retry guidance for complete active-plus-archived session corpus scans.

## Current State

- Corpus-helper deadlines are sized from full-root cost and previous successful runtime rather than the requested timestamp-window width.
- Quiet stdout is treated as expected while a healthy full-root scan is still running.
- Timed-out or interrupted scans are classified as incomplete; the old producer and its descendants must be proven quiescent before a fresh nonexistent output directory is used for any retry.
- Failed output cleanup is optional. Producer quiescence and directory-object identity revalidation remain necessary evidence, but a pathname `stat` followed by recursive deletion is not treated as race-safe; removal additionally requires a trusted descriptor-relative primitive that binds the verified parent and target identities throughout cleanup, or platform containment that prevents replacement. Otherwise the path is retained for handoff.

## Next Steps

- Monitor whether full-root session audits still require a user to restart an otherwise healthy scan.

## Evidence

- Session `019f8616-6fbd-7e13-9057-1d703c78fc88` required a user-triggered retry after a healthy 53 GiB cross-root scan was interrupted at roughly three minutes; the fresh rerun completed after several more minutes.
- The 2026-07-23 Daily Skill Friction audit reproduced the short-deadline failure at 300 seconds before the same fixed window completed under a 900-second deadline.
- A fresh-context internal review identified unsafe pathname-only cleanup after interruption; the fix now protects directory object identity and keeps quiescence, unreadable state, missing identity, and replacement outcomes distinct.
- PR single review identified retry-before-quiescence resource contention; the fix now blocks every retry until the original producer and its descendants are proven quiescent.
- PR single rereview identified the remaining check-to-delete replacement window; the fix now distinguishes diagnostic identity revalidation from an identity-bound deletion guarantee and retains the path when only pathname recursion is available.
- Final whole-range fresh-context rereview through `5d4d2e8dfa4bfb27821e20b672a380092edfed28` returned `No findings`; exact-secret admission for that range was clean with complete temporary cleanup.
- Closing and reopening PR #62 reconciled GitHub's stale PR head to `2d9e5d6d9f980432a074a181d4314481ffc72a6d`; a fresh whole-range review returned `No findings`, exact-secret admission was clean with complete temporary cleanup, and `chatgpt-codex-connector[bot]` reported no major issues for that reconciled head.
- Follow-up signed evidence head `93fb91251d2ec57aec1214598e0cfa294bc3af19` also passed exact-secret admission and fresh whole-range review with no findings, and GitHub Codex reported no major issues for that head; its `pull_request` CI event nevertheless remained bound to the prior head, documenting a GitHub PR-head propagation delay independent of the correctly bound review-gate event.
- `python3 -m unittest tests.test_skill_structure tests.test_session_corpus`: 83 tests passed.
- Full `python3 -m unittest discover -s tests`: 1,058 tests passed with commit signing disabled only for temporary Git fixture commits.
- `uv run --isolated --with pyyaml ... quick_validate.py skills/codex-session-mining`: passed.
- `skills/codex-session-mining/SKILL.md`
- `skills/codex-session-mining/references/workflow.md`
- `tests/test_skill_structure.py`
