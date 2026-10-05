---
id: 20261005-cwh001
title: Completion Report Controller Routing
status: completed
created: 2026-10-05
updated: 2026-10-05
branch:
pr:
supersedes: []
superseded_by:
---

# Completion Report Controller Routing

## Summary

- The consumer controller follows the canonical v2.1.7 routing for verifier-run completion while preserving the existing opt-in failure-triggered review flow.

## Current State

- Only completion events from the canonical verifier workflow are admitted. If GitHub omits the run's pull-request association, the controller passes the runtime's internal `pr_number: 0` sentinel for exact runtime-side binding.
- Completion uses `report-completion`; it does not scan findings, rerun a workflow, or request a fresh review. The diagnostic snapshot is not review evidence or gate authority.
- `begin-review` and `request_review` remain bound to the existing `CODEX_REVIEW_GATE_AUTO_REQUEST=true`, first-attempt failure, and single-PR association conditions. Manual dispatch keeps its explicit inputs.
- The unchanged `codex/github-review-gate` verifier CheckRun remains the required gate authority. The verifier and `.github/CODEOWNERS` are unchanged; repository/org variables and rulesets are outside this controller-only update.

## Evidence

- Canonical controller template: source commit `7e1069c6a6f4c4b319b1c5f33da262ee97460242`.
- Consumer controller matched the canonical template byte-for-byte; `actionlint` passed for the installed verifier and controller.
- The controller contract suite passed (5 tests); source v2 workflow contract tests passed (8 tests).
