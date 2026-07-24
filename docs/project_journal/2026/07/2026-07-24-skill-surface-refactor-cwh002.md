---
id: 20260724-cwh002
title: Skill Surface Refactor
status: active
created: 2026-07-24
updated: 2026-07-24
branch: codex/skill-surface-refactor
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/63
supersedes: []
superseded_by:
---

# Skill Surface Refactor

## Summary

- Split rules hygiene into read-only audit and explicit transactional apply
  modes.
- Hardened apply publication, exchange, and retained-stage cleanup against
  same-UID pathname replacement without compare-then-delete cleanup.
- Replaced descriptor-only retention claims with fsynced, identity-bound
  recovery copies and explicit incomplete-retention results.
- Added single-link object policy to candidate, live-file, receipt, recovery,
  and pre/post-mutation validation.
- Reduced the Joey authoring overlay to placement and validation policy while
  respecting non-default `CODEX_HOME`.
- Strengthened structural tests for the complete audit and cold-start paths.

## Current State

- Rules apply stages and validates a descriptor-bound private candidate before
  taking a shared lock, then revalidates the expected live digest, object
  identity, content, access policy, and `st_nlink == 1` object policy before a
  Darwin/Linux atomic exchange.
- Backup publication is atomic and no-replace. Unsupported libc/filesystem
  primitives fail closed. Uncertain outcomes copy each still-bound FD into a
  fsynced recovery file; parent replacement or an unlocatable copy reports
  `retention_incomplete` rather than claiming persistence.
- Backup and recovery receipts bind the exact transaction. Rollback refuses to
  overwrite a later legitimate live state and reports retained recovery
  evidence instead; schema-v2 receipts add link policy while schema-v1
  recovery remains supported.
- `codex-skill-authoring` resolves the active skill root from `CODEX_HOME` or
  the loaded skill directory rather than assuming `$HOME/.codex`.
- The active audit workflow remains read-only; apply behavior is isolated in
  the skill-relative transaction helper.

## Next Steps

- Run a fresh whole-range review of the signed checkpoint and address only
  findings bound to the current head.
- Update PR #63 after final validation and review evidence are clean.

## Evidence

- Rules transaction tests: 27 passed on Python 3.13 and system Python 3.9.6,
  including source/destination unlink, parent replacement, validator/set-policy
  hardlink, immediate pre-mutation revalidation, post-mutation link drift,
  `EEXIST` plus source unlink, read-only-live, and schema-v1 recovery cases.
- The focused rules plus structure run passed 28 tests on both Python versions.
- Full repository suite: 1,085 of 1,089 tests passed in the sandbox; the same 4
  sandbox-only GPG merge-fixture failures passed in the exact keybox-enabled
  rerun (4 of 4).
- Ruff check passed for all changed Python files. The helper and transaction
  tests pass Ruff format; the repository's pre-existing structure-test format
  drift remains and was not mechanically expanded.
- `codex-rules-hygiene` passed the official skill validator through the
  existing offline PyYAML environment.
- `git diff --check` passed, and generated Python caches were removed.
