---
id: 20260717-csr006
title: Retrospective Portable Enumeration
status: completed
created: 2026-07-17
updated: 2026-07-18
branch: codex/daily-skill-friction-20260717-codex-workflow-hygiene-portable-scandir-identity
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/53
supersedes: []
superseded_by: 20260718-csr007
---

# Retrospective Portable Enumeration

## Summary

- Replaced session-metadata identity checks that compared cached `DirEntry.inode()` data with fresh stat data and assumed a final entry shared its parent directory's device number.
- Treated `scandir` entries as names only, captured a fresh descriptor-relative no-follow raw metadata identity after scope filtering, and delayed all candidate opens and content proofs until actual consumption. Exact archive candidates carry that inventory snapshot through authoritative `fstat` and fresh path stats; active candidates allow same-inode growth into the first prefix proof while rejecting replacement, shrink, or same-size metadata mutation.
- Preserved fail-closed replacement, disappearance, symlink, FIFO, append-proof, proof-budget, and exact archive semantics in both local and embedded probes.

## Current State

- Enumeration no longer depends on filesystem-specific dirent inode or parent/child device behavior, including OverlayFS configurations used by container runners.
- Scoped inventory snapshots can represent symlinks and non-regular entries without opening them, so replacement or disappearance before first consumption is rejected while precise symlink/FIFO classification remains consumption-time behavior.
- The first held-descriptor proof is the active content baseline. Later growth between descriptor and path checks is accepted only when that proved prefix remains unchanged; rewrite-and-grow, replacement, shrink, rollback, and same-size mutation after the baseline fail closed, while archives retain exact snapshots throughout consumption.
- An active candidate with no metadata in its first immutable snapshot gets one bounded refreshed-snapshot parse after checkpointing. A first metadata record captured in the refreshed aligned snapshot is returned; an append high-water ahead of that verified snapshot, or a second aligned advance with no match, becomes an explicit coverage error instead of a silent miss.
- A no-follow `ELOOP` is reported as a rollout-identity change, while every transient candidate descriptor closes before enumeration continues.

## Next Steps

- Monitor container CI for other filesystem-specific metadata assumptions; keep descriptor identity authoritative when directory inventory metadata differs.

## Evidence

- `python3 tests/test_remote_codex_probe.py`: 33 of 33 tests passed in 4.364 seconds, including local and embedded active/archive pre-consumption replacement regressions and normal active append acceptance.
- Python 3.13.0 full suite, final public worktree: 991 of 991 tests passed in 73.622 seconds.
- Python 3.14.2 full suite, final public worktree: 991 of 991 tests passed in 74.858 seconds.
- Ruff passed for both changed Python files; Python 3.13 and Python 3.14 byte compilation passed.
- Isolated `quick_validate.py` validation passed for `codex-session-retrospective`; `git diff --check` and signed commit verification passed.
- Private reproduction: `Joey-Tools/codex-private-workflows` run `29600214365`, job `87950238935`, failed with 44 failures and 18 errors rooted in `rollout identity changed during enumeration`.
