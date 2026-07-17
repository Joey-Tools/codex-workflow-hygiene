---
id: 20260717-csr006
title: Retrospective Portable Enumeration
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260717-codex-workflow-hygiene-portable-scandir-identity
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/53
supersedes: []
superseded_by:
---

# Retrospective Portable Enumeration

## Summary

- Replaced session-metadata identity checks that compared cached `DirEntry.inode()` data with fresh stat data and assumed a final entry shared its parent directory's device number.
- Treated `scandir` as name-only discovery, then bound every in-scope candidate through its pinned parent using a no-follow, nonblocking descriptor open, authoritative `fstat`, and two fresh descriptor-relative no-follow stats.
- Preserved fail-closed replacement, disappearance, symlink, FIFO, append-proof, proof-budget, and exact archive semantics in both local and embedded probes.

## Current State

- Enumeration no longer depends on filesystem-specific dirent inode or parent/child device behavior, including OverlayFS configurations used by container runners.
- Replacement before the first fresh stat or between the two fresh stats is rejected against the already-open descriptor snapshot.
- `ELOOP` maps to the precise symlink coverage error, while every transient candidate descriptor closes before enumeration continues.

## Next Steps

- Monitor container CI for other filesystem-specific metadata assumptions; keep descriptor identity authoritative when directory inventory metadata differs.

## Evidence

- `python3 -m unittest tests.test_remote_codex_probe`: 27 of 27 tests passed.
- Python 3.13.0 full suite: 985 of 985 tests passed in 78.923 seconds.
- Python 3.14.3 full suite: 985 of 985 tests passed in 86.136 seconds.
- Ruff passed for both changed Python files; Python 3.13 and Python 3.14 byte compilation passed.
- Isolated `quick_validate.py` validation passed for `codex-session-retrospective`; `git diff --check` and signed commit verification passed.
- Private reproduction: `Joey-Tools/codex-private-workflows` run `29600214365`, job `87950238935`, failed with 44 failures and 18 errors rooted in `rollout identity changed during enumeration`.
