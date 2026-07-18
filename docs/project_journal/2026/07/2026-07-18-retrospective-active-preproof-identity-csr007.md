---
id: 20260718-csr007
title: Retrospective Active Pre-Proof Identity
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-active-preproof-grow-rewrite
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/54
supersedes: [20260717-csr006]
superseded_by:
---

# Retrospective Active Pre-Proof Identity

## Summary

- Made the first active rollout prefix anchor fail closed: the path and opened descriptor must exactly match inventory, including size and timestamps, both before the proof and in a descriptor-plus-fresh-path recheck after the proof read.
- Preserved append-only prefix checkpoints after that anchor, so a safe later append remains accepted while grow-and-rewrite fails.
- Documented the retry tradeoff: portable metadata cannot distinguish an ordinary pre-anchor append from grow-and-rewrite, so either becomes a coverage gap until a stable retry.

## Current State

- Local and embedded probes apply the same boundary without adding rollout opens or proof reads beyond the existing `limit + 1` active-consumption budget.
- Regression coverage rejects append-grow and same-inode rewrite-grow across the inventory handoff, proof read, and post-proof exact recheck; one-shot mutations then succeed on a stable retry.
- Existing post-anchor append acceptance coverage remains in place.

## Next Steps

- Complete review and merge gates for PR #54.

## Evidence

- PR: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/54
- `python3 tests/test_remote_codex_probe.py`: 33 of 33 tests passed in 4.644 seconds, including local and embedded append-grow and same-inode rewrite-grow during the first proof read.
- Ruff 0.13.2 passed on both changed Python files with `--no-cache` because the canonical worktree is read-only to tool caches.
- `codex_skill_validate.py skills/codex-session-retrospective`: valid through the isolated `uv` validator path.
- Project journal validation passed.
- Python 3.13.0 byte compilation and `git diff --check` passed.
- Python 3.13.0 full repository suite: 991 of 991 tests passed in 87.479 seconds (`real 88.85s`).
- Python 3.14.3 full repository suite: 991 of 991 tests passed in 94.082 seconds (`real 94.69s`).
- Read-only reviewer rerun: No findings.
