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
- Added descriptor-backed file-flag, xattr, and ACL admission plus a bounded
  validator process-group supervisor.
- Kept backup, receipt, recovery-terminal, and parent-directory descriptors
  bound through exchange and installed verification, with repeated protected
  property, metadata, and directory-entry admission.
- Reserved and identity-bound the recovery-terminal leaf before backup
  publication, and made stale terminal evidence a pre-mutation conflict.
- Removed the unlocked no-change fast path; apparent no-change now validates
  under the shared writer lock and returns only `no_change_after_lock`.
- Bound idempotent recovery to exact original or persisted recovery-terminal
  identity, and revalidated recovery copies after locator binding.
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
- Schema-v2 receipts now also bind the reserved recovery-terminal identity.
  Backup, receipt, terminal, rules parent, and receipt parent remain open and
  are revalidated immediately before exchange and throughout installed
  verification.
- Validator execution rejects nonfinite deadlines, caps aggregate captured
  output, and independently enumerates live same-PGID members on Darwin and
  Linux before accepting completion, including descendants whose standard
  streams all point to `/dev/null`.
- A recovery copy is verified only after rereading the held origin and copy
  descriptors and rechecking content, access/link policy, metadata admission,
  and directory-entry binding. Recovery refuses same-content replacement
  inodes unless a transaction-bound recovery-terminal record names them.
- `codex-skill-authoring` resolves the active skill root from `CODEX_HOME` or
  the loaded skill directory rather than assuming `$HOME/.codex`.
- The active audit workflow remains read-only; apply behavior is isolated in
  the skill-relative transaction helper.

## Next Steps

- Run the parent-owned fresh whole-range review against the next signed
  checkpoint.
- Update PR #63 only after that review evidence is clean.

## Evidence

- Rules transaction tests: 55 passed on Python 3.13. New cases cover closed
  validator stdio, compliant concurrent writers, locked no-change metadata
  admission, stale/replaced terminal reservations, and backup/receipt/parent
  replacement, hardlink, file-flag, xattr, and ACL races.
- The focused rules, structure, and validator-wrapper run passed 97 tests.
- Full repository suite covered 1,117 tests. Only the same 4 sandbox-only GPG
  merge-fixture errors remained; their exact keybox-enabled rerun passed 4 of
  4 outside the sandbox.
- Ruff check and Ruff format-check passed for both changed Python files.
- `codex-rules-hygiene` passed the official skill validator through an
  isolated `uv` PyYAML environment after the direct installed wrapper reported
  that local Python lacked `PyYAML`.
- `git diff --check` passed after the last source update; five generated
  `__pycache__` directories were removed and the bounded cache rescan was
  empty.
