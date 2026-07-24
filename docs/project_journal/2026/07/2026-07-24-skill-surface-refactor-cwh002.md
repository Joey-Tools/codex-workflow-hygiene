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
- Added a lock-held primary-state probe before strict terminal admission, so
  schema-v3 `P`, v4 `P`, `X/C/R`, and ambiguous post-mutation states retain
  mutation-aware recovery while exact pre-mutation `Q` may still refuse.
- Made evidence and parent descriptor closure best-effort-all with
  deterministic structured failures, preserving the existing terminal result.
- Separated lock-close uncertainty from body, before-release, and final
  revalidation errors so the earlier safety failure remains authoritative.
- Made missing schema-v1 historical link counts enforce current single-link
  policy instead of disabling it for live, backup, recovery, and terminal
  objects.
- Added a zero-write namespace preflight that rejects receipt-derived paths
  overlapping the fixed stage by leaf, ancestry, or canonical alias.
- Extended structured best-effort descriptor cleanup and primary-outcome
  precedence to every remaining bind, read, rollback, and stage helper.
- Normalized every schema-v1 receipt snapshot's historical link policy to
  unknown, rejecting an explicitly supplied non-single link count before it
  can authorize matching current hardlinks.
- Extended the fixed-stage namespace gate to descriptor-bound directory
  identities and conservative NFKC/casefold component comparison.
- Added legacy rollback mutation entry/completion events before exchange, so
  parent or lock finalization failure retains the journal and recovery
  locators.
- Routed private-stage descriptor-close uncertainty into apply and every
  recovery result; a would-be clean success now exits nonzero with its original
  operation status and stable FD classes in stdout JSON.
- Made every untrusted regular-file pathname binding nonblocking and no-follow
  with immediate descriptor file-type proof, so FIFO replacement cannot stall
  pre-lock, post-validator, exchange-target, or recovery execution.
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
  until the lock context completes its own post-callback revalidation and
  attempts lock-FD closure. Lock-close failure is structured release
  uncertainty; persistent evidence remains bound until that failure has been
  classified.
- Result, reservation, receipt, prepared evidence, and every held parent close
  in a deterministic best-effort-all pass. EIO/EINTR on one descriptor cannot
  skip later closes or replace an existing apply/recovery terminal status.
- Legacy schema-v1 receipts treat absent historical `nlink` as unknown history,
  ignore an explicit valid historical `nlink: 1`, and reject any explicit
  non-single value as receipt tampering, while every current regular
  transaction object still has to prove `st_nlink == 1`; hardlinks before
  exchange, during exchange, after restore, or before `already_original` fail
  closed.
- Apply and recovery reject receipt, terminal/result, prepared, and lock
  namespaces that are the fixed stage itself, its ancestor/descendant, or a
  canonical/symlink, case-fold, or Unicode-normalized alias before any new
  persistent transaction write. Existing directory components are anchored by
  descriptor identity; absent leaves compare normalized component sequences
  only under the same bound rules parent.
- Bind/read/rollback helpers now use the same deterministic best-effort close
  primitive as terminal evidence; structured close faults attach to the
  established property, tamper, or rollback result.
- Legacy rollback records mutation entry before the exchange attempt and
  completion immediately after a proved exchange. A later receipt-parent,
  control, or lock-close failure therefore remains `recovery_required` with
  the mutation journal and receipt/live/backup/terminal locators.
- Private-stage cleanup failures join the same structured accumulator for
  apply and schema-v1/v2/v3/v4 recovery. Existing failure results keep their
  terminal status; an otherwise successful apply/recovery reports
  `recovery_required`, records `operation_status`, and exposes stable
  `cleanup_reason` plus `descriptor_class` fields.
- Candidate, live, backup, receipt, prepared, staged, and terminal pathname
  bindings open with nonblocking/no-follow semantics and prove `S_ISREG`
  immediately from the returned descriptor. FIFO substitution is therefore a
  typed fail-closed result rather than an unbounded wait, including before the
  first lock, after validator return, and during lock-held recovery.
- Recovery reads the immutable terminal result and exact live/backup roles
  under the lock before strict terminal validation; an `O/M` v4 primary state
  gets a bounded stage/prepared probe to prove exact `Q` or retain possible
  `P`. A published `Q` result, schema-v3 `P`, completed `C` to `R` transition,
  or ambiguous post-mutation state records observed mutation and returns
  `recovery_required`; only proved pre-mutation `Q` drift remains
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

- Rules transaction tests: 165 passed on Python 3.13. New cases cover fixed
  stage zero-artifact failures, parse-to-lock receipt races, delegated-v3
  post-mutation receipt and parent changes, every terminal publication crash
  point, successful retry, terminal truncation prohibition, terminal/primary
  evidence taking precedence over auxiliary drift, ambiguous retry states, and
  apply-evidence lifetime through final lock revalidation. The newest cases
  cover schema-v3 `P` and schema-v4 `C` terminal replacement, exact `Q`
  refusal, combined final-revalidation/lock-close failure, close-only release
  uncertainty, persistent evidence lifetime, deterministic multi-close
  EIO/EINTR, primary-result preservation for recovered/required/refused,
  schema-v1 current hardlink boundaries, receipt/stage namespace overlap, and
  bind/read/rollback multi-close precedence. The latest 9 cases cover
  schema-v1 explicit-link downgrade attempts, legacy post-exchange
  parent/lock finalization failures, case-folded and Unicode-normalized stage
  aliases, and structured private-stage close failures across apply plus
  schema-v1/v3/v4 recovery. The final 4 cases prove that an initial candidate
  FIFO, an existing lock FIFO, a post-validator candidate FIFO replacement,
  and a lock-held recovery backup FIFO all fail promptly without creating new
  transaction artifacts.
- Full repository suite covered 1,227 tests. Only the same 4 sandbox-only GPG
  merge-fixture errors remained; their exact keybox-enabled rerun passed 4 of
  4 outside the sandbox.
- Ruff check and Ruff format-check passed for both changed Python files.
- `codex-rules-hygiene` passed the official skill validator through an
  isolated `uv` PyYAML environment after the direct installed wrapper reported
  that local Python lacked `PyYAML`.
- `git diff --check` passed after the last source update; five generated
  `__pycache__` directories were removed and the bounded cache rescan was
  empty.
