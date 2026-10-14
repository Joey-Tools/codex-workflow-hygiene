---
id: 20261005-cwh010
title: Codex PR Attribution Model Labels
status: completed
created: 2026-10-05
updated: 2026-10-05
branch: codex/remote-first-delivery-routing-20261005
pr:
supersedes: []
superseded_by:
---

# Codex PR Attribution Model Labels

## Summary

- Add GPT-6 model-label support and update the policy fallback for missing evidence; no historical model mappings are changed.

## Current State

- Policy identifies GPT-6.1 Sol as the parent/default model and allows GPT-6 Luna for token-consuming workers and local review up to Max.
- `GPT-6.1 Sol Medium` is the explicit fallback when attribution evidence is missing or unsafe. It records policy intent and is not evidence that a runtime used that model or effort.
- The existing `xhigh` UI label remains `Extra High`.

## Next Steps

- None.

## Evidence

- `skills/codex-session-mining/scripts/pr_attribution.py`
- `skills/codex-session-mining/SKILL.md`
- `tests/test_pr_attribution.py`
- `python3 tests/test_pr_attribution.py`: 75 tests passed.
