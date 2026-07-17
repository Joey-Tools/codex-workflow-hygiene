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
- Treated `scandir` as name-only discovery and delayed all candidate opens until actual consumption. Exact archive candidates bind authoritative `fstat` to two fresh descriptor-relative no-follow stats; active candidates establish a prefix proof before the first path stat and stabilize it through the append-only checkpoint on the same held descriptor.
- Preserved fail-closed replacement, disappearance, symlink, FIFO, append-proof, proof-budget, and exact archive semantics in both local and embedded probes.

## Current State

- Enumeration no longer depends on filesystem-specific dirent inode or parent/child device behavior, including OverlayFS configurations used by container runners.
- The first held-descriptor proof is the active content baseline. Later growth between descriptor and path checks is accepted only when that proved prefix remains unchanged; rewrite-and-grow, replacement, shrink, rollback, and same-size mutation after the baseline fail closed, while archives retain exact snapshots throughout consumption.
- `ELOOP` maps to the precise symlink coverage error, while every transient candidate descriptor closes before enumeration continues.

## Next Steps

- Monitor container CI for other filesystem-specific metadata assumptions; keep descriptor identity authoritative when directory inventory metadata differs.

## Evidence

- `python3 tests/test_remote_codex_probe.py`: 29 of 29 tests passed in 4.401 seconds.
- Python 3.13.0 full suite, final public worktree: 987 of 987 tests passed in 108.809 seconds.
- Python 3.14.2 full suite, final public worktree: 987 of 987 tests passed in 112.400 seconds.
- Ruff passed for both changed Python files; Python 3.13 and Python 3.14 byte compilation passed.
- Isolated `quick_validate.py` validation passed for `codex-session-retrospective`; `git diff --check` and signed commit verification passed.
- Private reproduction: `Joey-Tools/codex-private-workflows` run `29600214365`, job `87950238935`, failed with 44 failures and 18 errors rooted in `rollout identity changed during enumeration`.
