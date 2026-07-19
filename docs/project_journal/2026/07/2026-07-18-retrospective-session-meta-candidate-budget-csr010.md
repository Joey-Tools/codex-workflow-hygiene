---
id: 20260718-csr010
title: Retrospective Session Metadata Candidate Budget
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-retrospective-session-meta-limit
pr:
supersedes: []
superseded_by:
---

# Retrospective Session Metadata Candidate Budget

## Summary

- Decoupled the requested session-metadata result-row limit from the fixed active-rollout prefix-proof safety budget.
- Allowed candidates without a usable `session_meta` record to be skipped without consuming the caller's row limit.
- Added a distinct path-neutral truncation reason when the independent active-candidate safety budget is exhausted.

## Current State

- Local and embedded probes can scan past multiple active or legacy-root rollouts without metadata and still return a later usable row when it fits `--limit`.
- Result truncation still occurs before validating or serializing an extra usable row.
- Active prefix-proof work remains bounded to `MAX_SESSION_META_LIMIT + 1` candidates per scan, independently of the requested row limit, and `--auto-split` recognizes both truncation reasons.

## Next Steps

- Complete the pull-request review and merge gates.
- Monitor candidate-budget truncation frequency separately from ordinary result-row truncation.

## Evidence

- Focused local and embedded regressions passed for skipped metadata candidates, remote truncation parsing, and the independent active-candidate proof cap.
- `python3 -B tests/test_remote_codex_probe.py`: 36 of 36 tests passed in 4.058 seconds.
- `python3 -B -m unittest -b tests.test_session_retrospective`: 877 of 877 tests passed in 58.544 seconds with process-scoped Git fixture signing disabled.
- `python3 -B -m unittest discover -s tests -p 'test_*.py' -b`: 1003 of 1003 tests passed in 67.650 seconds with the same fixture-only signing override.
- Ruff 0.13.2 passed the changed Python files with the repository's unchanged single F541 baseline excluded; Python 3.13.0 byte compilation passed.
- Isolated skill validation, project journal validation, and `git diff --check` passed.
- Read-only pre-commit review reported `No findings.`
