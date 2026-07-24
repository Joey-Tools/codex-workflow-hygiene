---
id: 20260724-cwh002
title: Skill Surface Thinning
status: completed
created: 2026-07-24
updated: 2026-07-24
branch: wip/thin-bounded-mining-authoring
pr:
supersedes: []
superseded_by:
---

# Skill Surface Thinning

## Summary

- Reduced `bounded-command-output` to hard runtime, process-group cleanup, and
  retained-byte enforcement.
- Split `codex-session-mining` into lightweight `locate` and complete `corpus`
  profiles.
- Hardened the lightweight locator so `checked` means a descriptor-bound,
  revalidated index prefix or rollout inventory rather than a path-level
  best-effort scan.
- Reduced `codex-skill-authoring` to the user's placement, layering,
  validation-wrapper, and approval-friendly argv overlay on system
  `$skill-creator`.

## Current State

- Ordinary exact commands no longer trigger the bounded execution-control
  skill; genuinely broad, noisy, long-running, or retained-byte-sensitive work
  still does.
- `locate_session.py` performs bounded exact-ID or thread-index lookup and
  reports per-source `checked`, `unavailable`, or `partial` coverage.
- Index scans bind one initial byte boundary, rehash that prefix through the
  same regular-file descriptor, and distinguish stable later appends from
  truncation, mutation, rotation, replacement, or unreadable revalidation.
- Rollout lookup binds the complete no-follow directory chain, inventories
  through held descriptors, and revalidates directory identity, uid/gid/mode,
  and a 100,000-entry-bounded name/type/device/inode inventory.
- Match and error retention is capped during collection while total and
  truncation counts remain explicit.
- `build_session_corpus.py` remains the authoritative current-host
  active-plus-archived, replay-aware corpus path.
- Generic skill scaffolding, frontmatter design, `agents/openai.yaml`, and
  forward-testing guidance live in system `$skill-creator`.
- Generated private-overlay mirrors are not edited in this branch.

## Next Steps

- Merge the rules-hygiene PR first, then merge current `master` into this branch
  and preserve its newer regression tests before final review.
- Update the private-overlay sync transformations and source lock after the
  canonical commit is available.

## Evidence

- `python3 -m unittest tests.test_skill_structure -v`: 20 tests passed,
  including append, prefix mutation, truncation, rotation, broken symlink,
  unreadable source/revalidation, directory replacement/escape, inventory
  drift, access-policy drift, and 25-error retention-cap cases.
- Full `python3 -m unittest discover -s tests`: 1,051 tests ran; only four
  sandboxed temporary-Git signing fixtures failed because keyboxd was
  inaccessible.
- The exact four signing fixtures were rerun outside the sandbox and all passed.
- System `$skill-creator` quick validation passed for `codex-session-mining`
  through the documented isolated `uv` + PyYAML fallback.
- Ruff check and format check, Python compilation, and `git diff --check`
  passed.
- Project-journal frontmatter validation passed.
- A real read-only thread-query invocation checked both local indexes, retained
  at most two matches, and reported 27 total matches.
- A real exact-ID invocation checked both indexes plus 176 active rollout
  directories and 9,360 archived entries; every source completed descriptor
  and inventory revalidation.
