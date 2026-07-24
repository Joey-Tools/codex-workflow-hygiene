---
id: 20260724-cwh002
title: Skill Surface Thinning
status: completed
created: 2026-07-24
updated: 2026-07-25
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
- Index match retention now keeps the newest normalized `updated_at` / `ts`
  records in a fixed-size heap, with source path and physical line as stable
  tie-breakers.
- Each index now has a 250,000-record cap and a 192 MiB aggregate content-read
  budget shared by the scan and both prefix-revalidation hashes. A three-pass
  prefix that cannot fit is rejected before body reads, and a record-budget
  stop cannot claim stable-prefix coverage.
- Index JSON parsing rejects integers beyond 32 digits and non-standard
  constants as malformed records while continuing at the next physical record.
  UTC normalization overflow at the supported year boundaries is treated as a
  missing timestamp rather than escaping the schema-v2 response.
- Rollout filename lookup accepts only the exact terminal lifecycle UUID, not
  UUID substrings, adjacent characters, or a non-terminal occurrence.
- Rollout traversal stops with `partial` coverage at depth 32 or before its
  aggregate ancestor state exceeds 250,000 component references or 16 MiB of
  component bytes. These limits bound both retained path state and repeated
  root-to-directory reopening.
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

- `python3 -m unittest tests.test_skill_structure`: 29 tests passed,
  including append, prefix mutation, truncation, rotation, broken symlink,
  unreadable source/revalidation, directory replacement/escape, inventory
  drift, access-policy drift, newest-match retention, exact terminal UUID
  matching, depth/component budgets, index byte/record caps, oversized JSON
  integers, UTC year-boundary overflow, and 25-error retention-cap cases.
- Full `python3 -m unittest discover -s tests -q`: 1,060 tests ran; only four
  unrelated sandboxed temporary-Git merge-signing fixtures failed because
  keyboxd was inaccessible.
- The exact four signing fixtures were rerun outside the sandbox and all passed.
- System `$skill-creator` quick validation passed for `codex-session-mining`
  through the documented isolated `uv` + PyYAML fallback.
- Ruff check and format check for the changed Python files, Python compilation,
  and `git diff --check` passed.
- Project-journal frontmatter validation passed.
- A follow-up real read-only thread-query invocation checked both local
  indexes, reported 12 total matches, and retained the newest two in timestamp
  order.
- A follow-up exact-ID invocation checked both indexes plus 177 active rollout
  directories, 8,667 active entries, and 9,360 archived entries; every source
  completed descriptor and inventory revalidation within the new traversal
  budgets.
