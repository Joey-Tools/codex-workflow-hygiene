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
- Reduced the Joey authoring overlay to placement and validation policy while
  respecting non-default `CODEX_HOME`.
- Strengthened structural tests for the complete audit and cold-start paths.

## Current State

- Rules apply stages and validates a private candidate before taking a shared
  lock, then revalidates the expected live digest, object identity, content,
  and access policy before atomic replacement.
- Backup and recovery receipts bind the exact transaction. Rollback refuses to
  overwrite a later legitimate live state and reports retained recovery
  evidence instead.
- `codex-skill-authoring` resolves the active skill root from `CODEX_HOME` or
  the loaded skill directory rather than assuming `$HOME/.codex`.
- The active audit workflow remains read-only; apply behavior is isolated in
  the skill-relative transaction helper.

## Next Steps

- Run a fresh whole-range review of the signed checkpoint and address only
  findings bound to the current head.
- Update PR #63 after final validation and review evidence are clean.

## Evidence

- Rules transaction tests: 6 passed.
- Structure and validator-wrapper targeted tests: 42 passed; together with the
  transaction suite, the parent focused rerun passed 48 tests.
- Full repository suite: 1,064 tests passed directly; the 4 sandbox-only GPG
  fixture failures passed when rerun with keybox access.
- Ruff check passed for all changed Python files. The repository's pre-existing
  format drift remains and was not mechanically expanded.
- Both modified skills passed the authoring validator through the existing
  offline PyYAML environment.
- `git diff --check` passed.
