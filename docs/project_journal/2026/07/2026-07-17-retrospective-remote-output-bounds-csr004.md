---
id: 20260717-csr004
title: Retrospective Remote Output Bounds
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260717-codex-workflow-hygiene-bound-retrospective-remote-output
pr:
supersedes: []
superseded_by:
---

# Retrospective Remote Output Bounds

## Summary

- Bounded parent-side capture for remote session metadata and rollout summaries before frame parsing.
- Added complete-record producer budgets for local and embedded session metadata plus embedded summary output.
- Replaced buffered session-metadata line reads with raw chunk reads that enforce the actual cumulative scan cap.

## Current State

- Remote session metadata has a 32,899,072-byte parent stdout cap derived from 500 rows, one terminal row, and frame overhead.
- Remote rollout summaries retain the public 16 MiB input scan while using a separate 26,542,080-byte parent stdout protocol cap.
- Oversized records and frames fail closed without truncated fields or partial CLI output; complete final JSON at EOF remains valid without a trailing LF.

## Next Steps

- None for this completed output-bounds slice. Descriptor-pinned traversal hardening remains a separate public workstream.

## Evidence

- `skills/codex-session-retrospective/scripts/remote_codex_probe.py`
- `skills/codex-session-retrospective/SKILL.md`
- `tests/test_session_retrospective.py`
- Focused output and raw-read boundary selection: 7 tests passed.
- Post-review limit-order selection: 2 tests passed, covering the new local/embedded truncation parity regression and the existing row boundary.
- Added a real local subprocess regression proving that exactly N stdout bytes are accepted and N+1 bytes fail the parent capture before parsing.
- `python3 -B -m unittest tests.test_session_retrospective`: 868 tests passed in 331.053 seconds after the review fix.
- `python3 -B -m unittest discover -s tests -p 'test_*.py'`: 956 tests passed in 314.646 seconds.
- `python3 -m py_compile` passed for the changed Python source and test files.
- Ruff passed for the changed source and for the test file with its pre-existing `F541` finding excluded.
- The installed skill validator, project-journal validator, and `git diff --check` passed.
- Independent read-only diff reviews reported no findings. Helper-backed fixed-range reviews found a local/embedded limit-order mismatch and a missing real parent-capture boundary test; both are now covered by dedicated regressions. The final whole-range helper-backed rerun reported no findings.
