---
id: 20260718-csr008
title: Retrospective Active Final Checkpoint
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-active-final-checkpoint-proof
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/55
supersedes: [20260718-csr007]
superseded_by:
---

# Retrospective Active Final Checkpoint

## Summary

- Closed the last active-rollout proof window: when an append-only checkpoint observes growth after its final prefix verification, it performs one additional bounded verification of the same proved prefix.
- Requires the open descriptor and a fresh descriptor-relative no-follow path snapshot to remain exactly at that observed growth identity after the extra proof.
- Uses the extra proof's immutable snapshot for parsing without reopening the rollout or retrying the proof in a loop.

## Current State

- A stable late append remains accepted after one extra prefix verification.
- Same-inode rewrite-and-grow after the former final proof fails the extra digest check, while growth during the extra proof fails the exact post-proof identity checks and remains a retryable coverage gap.
- Local and embedded probes retain the same bounded behavior: the checkpoint adds only prefix `pread` and descriptor/path stats, never another rollout open.

## Next Steps

- Complete review and merge gates for PR #55.
- After merge, monitor active-session retry rates for unexpectedly frequent final-checkpoint growth; keep the single re-proof boundary fail closed rather than adding a stabilization loop.

## Evidence

- PR: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/55
- `python3 tests/test_remote_codex_probe.py`: 36 of 36 tests passed in 4.846 seconds.
- Local and embedded regressions force a truthy existing `session_meta` to rewrite-and-grow after the post-parse checkpoint's former final proof, verify the one extra proof rejects it, and confirm a stable retry returns the rewritten session id.
- The same four local/embedded and sessions/root subcases fail against the isolated `d78f50f` base snapshot because no coverage error is raised, proving the regression exercises the repaired silent-return window.
- A second local and embedded regression safely appends after the post-parse checkpoint's second proof, grows again immediately after the one-time third proof, and verifies the exact descriptor/path stability check rejects that later growth before a stable retry returns the trusted session id.
- A descriptor/path gap regression captures the stable post-reproof descriptor `fstat`, grows the pathname before the fresh no-follow path `stat`, and verifies that path check alone rejects the race; all four subcases fail when the fresh path check is removed from an isolated mutation-test copy.
- The late safe-append regression now requires exactly one additional proof and continues to return the original verified session id.
- Ruff 0.13.2, isolated skill validation, project journal validation, Python 3.13.0 and Python 3.14.3 byte compilation, and `git diff --check` passed.
- Python 3.13.0 full repository suite: 994 of 994 tests passed in 81.897 seconds (`real 82.76s`).
- Python 3.14.3 full repository suite: 994 of 994 tests passed in 87.110 seconds (`real 87.72s`).
- Read-only review initially raised two P2 test-coverage gaps around post-extra-reproof descriptor stability and the descriptor-to-fresh-path interval; both regressions were added and the final whole-range review rerun reported `No findings.`
