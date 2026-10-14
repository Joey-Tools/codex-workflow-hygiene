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

- Completion events are admitted only for the exact verifier workflow path or its `@refs/pull/.../merge` form; lookalike paths are rejected. If GitHub omits the run's pull-request association, the controller passes the runtime's internal `pr_number: 0` sentinel for exact runtime-side binding.
- Concurrency remains keyed by the associated pull request when available and falls back to the workflow-run ID or GitHub run ID when no association exists, preventing unrelated runs from sharing an empty group.
- Completion uses `report-completion`; it does not scan findings, rerun a workflow, or request a fresh review. The diagnostic snapshot is not review evidence or gate authority.
- `begin-review` and `request_review` remain bound to the existing `CODEX_REVIEW_GATE_AUTO_REQUEST=true`, first-attempt failure, and single-PR association conditions. Manual dispatch keeps its explicit inputs.
- The unchanged `codex/github-review-gate` verifier CheckRun remains the required gate authority. The verifier and `.github/CODEOWNERS` are unchanged; repository/org variables and rulesets are outside this controller-only update.

## Evidence

- Canonical controller template: source commit `7e1069c6a6f4c4b319b1c5f33da262ee97460242`.
- Consumer controller matched the canonical template byte-for-byte; `actionlint` passed for the installed verifier and controller.
- The controller contract suite passed (6 tests); canonical source workflow and security contract tests passed (51 tests) after the controller hardening. The bootstrap `--prepare-worktree` dry run reported no changes for this worktree.
