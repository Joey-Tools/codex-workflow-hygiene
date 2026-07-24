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
- Kept the receipt and every parent descriptor bound from secure parse through
  the recovery lock, every mutation, terminal publication, final validation,
  and lock release.
- Replaced in-place recovery-terminal rewriting with an immutable reservation
  plus an atomically published, directory-fsynced result slot.
- Moved fixed stage and terminal-result admission under the recovery lock and
  ahead of every candidate, receipt, terminal, or backup artifact.
- Added one mutation tracker shared across schema-v4 recovery and delegated
  schema-v3 recovery so every post-mutation ambiguity reports
  `recovery_required` with retained evidence and locators.
- Deferred persistent apply-evidence descriptor closure until after the shared
  lock has completed its final revalidation and closed its own descriptor.
- Classified recovery from immutable terminal results and live/backup roles
  before auxiliary prepared/stage exactness, so damaged retry evidence cannot
  downgrade a prior or possible mutation to a pre-mutation refusal.
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
- Schema-v4 receipts bind the reserved recovery-terminal identity and prepared
  stage. Recovery holds exact receipt, terminal, result, rules-parent, and
  receipt-parent descriptors through terminal validation and writer-lock
  release; path, identity, content, access, link, and parent bindings are
  revalidated at mutation-aware boundaries.
- Recovery-terminal publication never truncates or rewrites the reservation.
  It fsyncs a unique owner-private pending file, atomically renames it
  no-replace to the fixed `.result` slot, fsyncs the parent, and validates the
  bound result. A crash leaves either the prior valid reservation or a
  recoverable published result.
- Recovery preflights the fixed stage and terminal-result slot under the lock.
  Missing, replaced, retained, or invalid fixed evidence fails before any new
  candidate, receipt, terminal, or backup artifact is created.
- A shared mutation journal records entry and completion for publication,
  exchange, cleanup, and restore operations across schema-v4 and delegated
  schema-v3 paths. Once mutation may have started, later binding or validation
  failures cannot be downgraded to `recovery_refused`.
- Apply final validation and stage cleanup still run under the shared lock, but
  receipt, terminal, result, and parent evidence remains descriptor-bound
  until the lock context completes its own post-callback revalidation. A later
  descriptor-close failure cannot mask an active lock or recovery failure.
- Recovery reads the immutable terminal result and exact live/backup roles
  before prepared/stage probes. A published `Q` result, completed `C` to `R`
  transition, or ambiguous `Q`/`P` stage state records observed prior mutation
  and returns `recovery_required`; only provably pre-mutation drift remains
  `recovery_refused`.
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

- Rules transaction tests: 129 passed on Python 3.13. New cases cover fixed
  stage zero-artifact failures, parse-to-lock receipt races, delegated-v3
  post-mutation receipt and parent changes, every terminal publication crash
  point, successful retry, terminal truncation prohibition, terminal/primary
  evidence taking precedence over auxiliary drift, ambiguous retry states, and
  apply-evidence lifetime through final lock revalidation.
- Full repository suite covered 1,191 tests. Only the same 4 sandbox-only GPG
  merge-fixture errors remained; their exact keybox-enabled rerun passed 4 of
  4 outside the sandbox.
- Ruff check and Ruff format-check passed for both changed Python files.
- `codex-rules-hygiene` passed the official skill validator through an
  isolated `uv` PyYAML environment after the direct installed wrapper reported
  that local Python lacked `PyYAML`.
- `git diff --check` passed after the last source update; five generated
  `__pycache__` directories were removed and the bounded cache rescan was
  empty.
