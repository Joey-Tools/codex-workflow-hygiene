---
id: 20260724-cwh002
title: Skill Surface Refactor
status: active
created: 2026-07-24
updated: 2026-07-29
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
- Converted final persistent-evidence and rules-parent descriptor uncertainty
  after `applied` or either no-change path into nonzero `recovery_required`
  instead of attaching cleanup evidence to an exit-zero result.
- Unified validator finalization around one primary-error accumulator so raw
  wait/read errors and forwarded signals survive TERM/KILL, drain/reap,
  observer, selector, pipe, and signal-restoration failures.
- Moved successful and failed validator exits through one managed-signal
  block/capture boundary before every emergency, observer, selector, pipe,
  handler, and mask finalizer.
- Routed a managed signal from the post-replacement validator through the
  normal rollback/recovery state machine while retaining the signal-derived
  exit code and `interrupted` as the primary outcome.
- Propagated persistent evidence drift discovered during lock finalization
  after any replacement, including a verified ordinary or managed-signal
  rollback, instead of reporting a certain rollback after receipt, terminal,
  result, link, access, or parent evidence became uncertain.
- Re-proved the terminal live/backup data-role tuple through the bound rules
  parent immediately before lock release for applied, ordinary rollback,
  managed-signal rollback, and successful recovery outcomes.
- Added an exact live-only release proof to both apply no-change paths and
  schema-v1/v2 `already_original`, so identity, content, access, or link drift
  cannot escape as a stale success.
- Expanded schema-v4 `Q` release validation from its live/backup projection to
  the complete `(O,M,M,I)` tuple, rebinding prepared exact-installed and
  staged-candidate missing after the inner recovery closes its descriptors.
- Expanded schema-v4 applied `C` and restored `R` release validation to
  `(I,O,M,M)` and `(O,I,M,M)`, proving both prepared and staged candidates
  missing before apply stage cleanup closes its bindings.
- Classified a live-role change after durable receipt and prepared-to-stage
  publication as `recovery_required`, retaining the staged candidate and
  emitting the complete recovery-locator set instead of an ordinary conflict
  plus cleanup warning.
- Preserved the last complete schema-v4 `P` proof or conservative `Q_or_P`
  hint when a later stage/prepared probe fails; `Q` now requires a complete
  four-role observation.
- Promoted deferred schema-v4 possible-prior-state evidence whenever a
  reserved terminal does not accompany exact `Q`, including state-none loss
  of a `P` candidate or `R` backup.
- Bound idempotent recovery to exact original or persisted recovery-terminal
  identity, and revalidated recovery copies after locator binding.
- Scoped ext4's kernel-managed directory-index flag out of unmodeled metadata
  only for descriptor-proved directories, while retaining immutable and other
  user/security-relevant flags as access-policy failures.
- Made Linux process-cleanup assertions accept `/proc` terminal states
  `Z`/`X`/`x` without waiting for PID 1 to reap orphaned descendants, while
  every live state remains a failed quiescence proof.
- Unified the production Linux process-group inventory and test exit probe on
  that terminal-state set, with direct malformed and unreadable fail-closed
  coverage.
- Added an original-live durability boundary before transaction identity or
  persistent publication: apply fsyncs the held `default.rules` descriptor,
  then revalidates identity, exact content, access policy, single-link policy,
  its bound-parent dirent, and parent identity/access policy.
- Classified raw bound-descriptor and parent-dirent I/O failures on both sides
  of that fsync as structured unreadability, preserving exact operation,
  errno, phase, reason, and zero-publication evidence without conflating
  missing entries or proved property drift.
- Extended the original-live durability boundary through the descriptor-bound
  rules parent: file fsync now precedes parent-directory fsync and complete
  file/parent/dirent revalidation, while initial/final parent descriptor/path
  EIO retains unreadable scope, operation, errno, and probe stage.
- Classified the durable prepared-candidate plus terminal-reservation window
  before receipt binding. Receipt write or either fsync failure now returns
  dedicated `recovery_required` evidence with the exact reserved objects,
  receipt observation, transaction ID, publication state, and every recovery
  locator instead of escaping as an arbitrary exception.
- Reduced the Joey authoring overlay to placement and validation policy while
  respecting non-default `CODEX_HOME`.
- Strengthened structural tests for the complete audit and cold-start paths.

## Current State

- A real-change apply keeps the initially admitted live descriptor open,
  fsyncs it, fsyncs the descriptor-bound rules parent, and then completely
  revalidates the file, parent, and exact child dirent before creating
  transaction ID, prepared/terminal evidence, receipt, stage, backup, or
  exchange state. File/parent fsync errors and post-fsync
  replacement/content/access/link/dirent drift report structured
  pre-publication evidence with `receipt_written: false` and
  `exchange_started: false`; directory size/link churn remains benign while
  parent object identity/access policy and the exact child dirent stay
  protected. Raw FD-read, dirent-stat, and initial/final parent probe errors
  are separately reported as `original_live_unreadable_before_fsync` or
  `original_live_unreadable_after_fsync`; missing and mismatch statuses remain
  distinct.
- Once the prepared candidate and recovery-terminal reservation are durable,
  apply records an explicit pre-receipt reserved state until `write_receipt`
  returns a bound descriptor. Receipt write, file-fsync, or parent-fsync
  failure in that window retains both exact objects and reports nonzero
  `recovery_required` with receipt observation/failure, zero-exchange
  publication state, and the complete recovery-locator set.
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
- Cleanup, lock-finalization, and pending-result retention attachments keep
  their structured evidence on Python 3.9 and 3.10. Python 3.11+ exception
  notes are supplemental best-effort diagnostics; missing or faulty
  `add_note` support cannot replace the primary status, exception, or locator.
- Durable-evidence `recovery_required` wrapping now copies every structured
  `*_failures` list from both `TransactionError.details` and raw exception
  attributes. Fixed phase ordering preserves validator cleanup,
  post-replacement recovery, lock-finalization revalidation, and descriptor
  cleanup beside the original reason and message; extra structured fields are
  ordered lexically without changing any field's attempt order.
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
- A fixed stage is never assigned transaction-created identity from
  `mkdir -> stat/open`, because `mkdir` returns no authoritative descriptor.
  The helper only admits the currently bound owner-only empty stage; an
  umask-stripped or replaced pathname fails closed and is neither chmodded nor
  deleted. The `O_EXCL` lock FD is authoritative creation identity, so the
  helper proves FD/path identity, owner, regular type, and one-link policy
  before descriptor-only normalization and proves them again afterward.
- Path revalidation reports link-count drift as `object_policy_changed`
  instead of conflating it with an access-policy change. The structured status
  and `mismatched_properties` now identify the same protected property.
- Recovery-terminal result publication now carries exact pending retention
  evidence through every pre-rename failure. A locator is emitted only after
  descriptor, entry, exact bytes, owner-only access, one-link policy, and both
  fsyncs pass, the entry observation matches, and the bound parent plus
  descriptor are revalidated again; unlink or replacement races say
  `retention_incomplete`. Retry adopts one reservation-time-bound exact
  pending result or blocks without creating another unknown pending file.
- Recovery reads the immutable terminal result and exact live/backup roles
  under the lock before strict terminal validation; an `O/M` v4 primary state
  gets a bounded stage/prepared probe to prove exact `Q` or retain possible
  `P`. A published `Q` result, schema-v3 `P`, completed `C` to `R` transition,
  or ambiguous post-mutation state records observed mutation and returns
  `recovery_required`; only proved pre-mutation `Q` drift remains
  `recovery_refused`.
- A reserved terminal clears deferred mutation evidence only after the full
  v4 role tuple proves `Q`. Every other reserved-terminal or state-none
  observation promotes `possible_prior_transaction_state` when mutation
  cannot be excluded; exact installed live plus exact original staged evidence
  also proves a prior exchange even when backup is unknown and the prepared
  leaf is missing.
- Schema-v4 binds the terminal reservation's exact identity, size/digest,
  access policy, and link policy to the receipt regardless of decoded state.
  Only schema-v3 explicitly accepts the historical same-inode restored
  rewrite.
- Transaction leaves sharing one held parent are rejected pairwise when their
  names collide after NFKC normalization and case folding. Immediately before
  live exchange, apply revalidates controls and proves the backup leaf still
  missing, including case-insensitive alias occupancy.
- Validator execution rejects nonfinite deadlines, caps aggregate captured
  output, and independently enumerates live same-PGID members on Darwin and
  Linux before accepting completion, including descendants whose standard
  streams all point to `/dev/null`.
- Validator failure finalization attempts every remaining process-group,
  observer, selector, and pipe operation, preserves the original exception and
  traceback, and attaches each secondary failure in stable structured order.
  Cleanup-only uncertainty is `validator_cleanup_failed`; restored handler
  identities and the inherited signal mask are reread before success.
- Successful and failed validator execution now share the same first
  finalization step: block managed signals and close the armed gate, then
  synchronously consume any pending `SIGINT`, `SIGTERM`, or `SIGHUP` while
  cleanup remains non-interruptible. The inherited mask is restored only while
  the closed capture gate remains the verified installed handler; caller
  handlers are never restored before an unblock.
- The live-path validator transfers that same gate to the transaction owner.
  It remains effective through rollback or applied-state publication, shared
  lock release, and evidence-descriptor cleanup. Caller handlers are restored
  afterward without a second mask transition, and only then can
  `128 + signal` escape.
- A completed nonzero live-path validator result remains the first ordered
  secondary item when a final-handoff signal wins primary precedence.
  Finalizer failures follow in actual attempt order, while nested recovery
  retains the rejected validator result.
- A managed signal during the second validator completes rollback or records
  operator recovery before it is re-raised. Its JSON result keeps the signal
  primary and includes exact receipt, backup, terminal, prepared, and staged
  recovery locators plus the nested rollback/recovery outcome.
- Final lock-held evidence drift after replacement is always
  `recovery_required`. Ordinary rollback reports its prior
  `post_replace_failed_rolled_back` state as `operation_status`; a managed
  signal remains the primary `interrupted` result while its nested recovery
  and structured `lock_finalization_failures` record the same property
  mismatch and exact recovery locators.
- Terminal `C=(I,O)`, `R=(O,I)`, and `Q=(O,M)` live/backup roles are freshly
  rebound through the held rules parent before lock release. Present objects
  compare identity, content, access, and single-link policy; missing and
  unreadable roles remain distinct from property mismatch.
- Fast and post-validator-converged no-change results retain the full live
  snapshot until a `before_release` proof completes. Legacy schema-v1/v2
  `already_original` selects the same live-only terminal role without
  constraining an unrelated backup path.
- Schema-v4 `Q` now carries all four terminal roles into the outer release
  callback. The callback freshly binds the receipt-owned prepared parent,
  proves prepared exact-installed, and rejects prepared disappearance or
  identity/content/access/link drift plus staged-candidate appearance for
  both `recovered` and retry `already_original`.
- Applied `C`, automatic or managed-signal rollback `R`, and recovery `C→R`
  now carry the missing staged/prepared roles into the same outer proof. That
  proof runs before stage cleanup, so candidate reappearance is reported as
  `transaction_data_role_unexpected` with the exact state and role.
- After receipt durability and prepared-to-stage publication, a live conflict
  no longer permits ordinary exit 20. The transaction retains its exact staged
  candidate, reports the property-scoped live mismatch, and returns every
  receipt, live, backup, staged, prepared, terminal, and result locator for
  operator recovery.
- A managed signal stays primary when that final role proof fails; its nested
  rollback becomes `recovery_required` and carries the exact role, state,
  mismatched property, and recovery locators.
- An apparent apply or no-change result cannot remain successful after final
  evidence or rules-parent close uncertainty. It reports
  `final_evidence_descriptor_close_failed`, retains the original
  `operation_status` and recovery locators, and cannot refresh the rules
  baseline.
- A recovery copy is verified only after rereading the held origin and copy
  descriptors and rechecking content, access/link policy, metadata admission,
  and directory-entry binding. Recovery refuses same-content replacement
  inodes unless a transaction-bound recovery-terminal record names them.
- `codex-skill-authoring` resolves the active skill root from `CODEX_HOME` or
  the loaded skill directory rather than assuming `$HOME/.codex`.
- Linux file-flag admission ignores `FS_INDEX_FL` only for directories because
  it changes ext4's lookup layout rather than object identity, directory-entry
  content, or access policy. The same bit on a regular file and every
  nonautomatic access/security flag remain unmodeled and rejected.
- Linux cleanup assertions read bounded `/proc/<pid>/stat` state while `/proc`
  is available. Missing PIDs and `Z`/`X`/`x` are terminal; malformed,
  unreadable, and live states remain conservative failures. Other platforms
  retain the portable signal-zero probe.
- The active audit workflow remains read-only; apply behavior is isolated in
  the skill-relative transaction helper.
- Lock acquisition now derives an exact supervisor-mask window from the
  launcher's inherited mask: it unblocks only managed signals while polling,
  preserves every other signal bit, then re-blocks, captures the first pending
  managed signal, closes the gate, and restores the exact inherited mask
  before the lock body or capture-only transaction phase can continue.
- Python 3.9 compatibility now preserves slotted frozen session-corpus records
  on Python 3.10+ while omitting the unavailable dataclass option on 3.9,
  serializes `Signals` test arguments as integers, and skips only the
  `waitid`-specific fault injection when that capability is absent; the
  production observer already uses the Darwin `kqueue` fallback.

## Next Steps

- Run the parent-owned fresh whole-range review against the next signed
  checkpoint.
- Update PR #63 only after that review evidence is clean.

## Evidence

- Rules transaction tests: 193 passed on Python 3.13. New cases cover fixed
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
  transaction artifacts. The final identity-boundary cases prove that a
  newly named stage with restrictive owner permissions or a pre-open
  replacement fails without chmod or deletion; a new lock path replacement
  or hardlink fails before fchmod; and terminal-result pending files either
  produce exact durable locators or explicit incomplete-retention evidence
  without accumulating unknown pending files across retries. The final 6
  adversarial cases cover pairwise case-folded and NFKC leaf aliases,
  case-insensitive backup occupancy immediately before exchange, reserved
  terminal handling for ambiguous post-exchange roles, strict schema-v4 and
  explicitly relaxed schema-v3 same-inode terminal rewrites, and pending
  locator unlink/replacement races after an initially matching observation.
  The final 3 compatibility cases prove that missing or failing `add_note`
  support cannot displace structured cleanup, lock-finalization, or pending
  retention evidence. Nine focused stage-close, lock-finalization, and
  pending-publication cases also passed on system Python 3.9.6.
- The final 9 cases cover applied, fast no-change EIO/EINTR, and concurrent
  no-change final-close uncertainty; raw wait/read primary preservation;
  best-effort emergency/observer/selector/pipe/signal finalization; forwarded
  signal preservation; cleanup-only failure; post-replacement handler/mask
  validation; and preservation of every secondary validator cleanup failure
  when a post-replacement raw I/O error becomes `recovery_required`. Ten
  focused compatibility cases passed on system Python 3.9.6.
- The newest focused compatibility run passed 7/7 on system Python 3.9.6,
  including post-replacement signal rollback, `P` candidate loss, `R` backup
  loss, reserved prepared drift, and validator cleanup-primary precedence.
- The three newest transaction cases cover a real managed `SIGTERM` during the
  live-path validator plus durable `P`-candidate and `R`-backup loss. The
  signal case proves rollback, primary exit `128 + signal`, nested recovery
  evidence, exact locators, terminal publication, and validator quiescence;
  the schema-v4 cases prove `recovery_required` with mutation journal and
  locators. Existing later-live-state and untrusted-inode cases now assert the
  same conservative possible-prior-state contract.
- Rules transaction tests: 195 passed on Python 3.13. The two newest methods
  exercise ten post-terminal drift subcases: identity, content, access policy,
  link policy, and parent identity after both ordinary rollback and
  managed-signal rollback. Six targeted scenarios passed on Python 3.9.6
  across the compatibility reruns, including both new methods, hardlink
  finalization, ordinary and managed-signal rollback, and secondary evidence
  attachment without `add_note`.
- Rules transaction tests: 201 passed on Python 3.13. Four new integration
  methods exercise all 32 combinations of applied/rollback/signal/recovery,
  live/backup role, and identity/content/access/link drift. Two schema-v4
  cases prove that a completed first `P` observation survives a failed second
  auxiliary probe and that an incomplete `O/M` probe remains `Q_or_P`.
- Full repository suite covered all 1,263 tests on Python 3.13.
- The six new transaction methods passed on system Python 3.9.6. A broader
  3.9.6 transaction run passed 200 cases and stopped only because the existing
  `test_validator_waitid_failure_still_terminates_and_reaps` mock requires
  `os.waitid`, which that runtime does not expose; the error occurs before the
  transaction helper is entered.
- Final static gates passed Ruff check/format, Python 3.13 and system Python
  3.9.6 byte compilation, the official Rules skill validator, project-journal
  validation, and `git diff --check`.
- Full repository suite covered all 1,257 tests. The sandboxed run passed
  1,253 and failed only four unrelated temporary merge-commit fixtures because
  sandbox GPG could not reach `~/.gnupg/keyboxd`; those exact four tests passed
  in the approved narrow GPG-capable rerun.
- Ruff check and Ruff format-check passed for both changed Python files.
- `codex-rules-hygiene` passed the official skill validator through an
  isolated `uv` PyYAML environment after the direct installed wrapper reported
  that local Python lacked `PyYAML`.
- `git diff --check` passed after the last source update.
- Rules transaction tests: 205 passed on Python 3.13. Four new integration
  methods exercise 28 deterministic lock-release races: fast and converged
  no-change across live identity/content/access/link drift; schema-v1/v2
  `already_original` across the same four properties; and schema-v4 Q
  `recovered` plus retry `already_original` across prepared
  missing/identity/content/access/link and staged-candidate appearance.
- Full repository suite covered all 1,267 tests on Python 3.13.
- The four new transaction methods passed on system Python 3.9.6, and both
  changed Python files byte-compiled on Python 3.13 and system Python 3.9.6
  with task-scoped caches removed afterward.
- A fresh-context whole-range review of
  `212212db3eacf2a9e23a2ce4fa5575a6dd9e930a..bfcb6fb8e3f0d897995315aced26249825cf5726`
  found that the test exit probe treated `Z`/`X`/`x` as terminal while the
  production Linux process-group inventory excluded only `Z`. The production
  parser now uses the same exact terminal-state set.
- Four direct Linux inventory regressions passed on Python 3.13.0 and system
  Python 3.9.6, covering terminal, live, malformed, and unreadable process
  metadata. The full repository suite passed 1,277/1,277 on Python 3.13.0;
  Ruff check/format, byte compilation, and `git diff --check` passed for the
  final files.
- GitHub Actions run `30240557145`, job `89896679716`, and PR #63 all bound the
  failure to head `97f55508418718d8ddbd3547b5cfeb0190a06e33`. Its sole error
  was `unsupported_file_flags` while binding the rules parent after the large
  sibling-inventory test caused ext4 to add `FS_INDEX_FL`.
- The ext4 flag and Linux terminal-state regression methods, the large sibling
  inventory reproduction, and both orphan-descendant cleanup scenarios passed
  5/5 on Python 3.13 and system Python 3.9.6. The full Rules transaction suite
  passed 211/211 and the full repository suite passed 1,273/1,273 on Python
  3.13.
- The newest static gates passed Ruff check/format, the official Rules skill
  validator, project-journal validation, and `git diff --check`.
- Rules transaction tests passed 219/219 and the full repository suite passed
  1,281/1,281 on Python 3.13.0. Four new methods exercise 19 deterministic
  signal injections: immediately before the common finalization boundary,
  across every successful resource finalizer, across emergency plus every
  failed-execution finalizer, and across every post-replacement finalizer.
  The matrix rotates `SIGINT`, `SIGTERM`, and `SIGHUP`, proves every bounded
  cleanup completes, retains displaced execution/finalizer errors as
  secondary evidence, rolls live rules back after replacement, and preserves
  exact `128 + signal` precedence. The same four methods plus five direct
  Linux `Z`/`X`/`x` inventory regressions passed 9/9 on system Python 3.9.6.
- Final repair static gates passed Ruff check/format, Python 3.13.0 and system
  Python 3.9.6 byte compilation, the official Rules skill validator,
  project-journal validation, and `git diff --check`; task-scoped pycache
  directories were removed afterward.
- Final static gates passed Ruff check/format, the official Rules skill
  validator, project-journal validation, and `git diff --check`.
- Rules transaction tests: 209 passed on Python 3.13. Four new integration
  methods cover seven release/publication races: prepared and staged
  reappearance for applied `C`, automatic rollback `R`, and recovery `C→R`,
  plus a live content change after durable prepared-to-stage publication.
- Full repository suite covered all 1,271 tests on Python 3.13.
- The four new transaction methods passed on system Python 3.9.6, and both
  changed Python files byte-compiled on Python 3.13 and system Python 3.9.6
  with task-scoped caches removed afterward.
- Rules transaction tests passed 220/220 and the full repository suite passed
  1,282/1,282 on Python 3.13.0. The newest regression sends a real `SIGTERM`
  after the final pending read and before `SIG_SETMASK`, after the live-path
  validator has already exited 9. It proves the gate still owns the unblock,
  the inherited handler never runs, rollback and recovery-terminal
  publication precede forwarding, and ordered secondary evidence retains the
  rejected validator result before the injected mask-handoff failure.
- Ten focused signal-handoff and Linux `Z`/`X`/`x` regressions passed on
  system Python 3.9.6, including every prior finalizer matrix and the exact
  pending-read/unblock race.
- Final gates passed Ruff check/format, Python 3.13.0 and system Python 3.9.6
  byte compilation, the official Rules skill validator, project-journal
  validation, and `git diff --check`. Task-scoped validation caches and the
  retained validator report were removed afterward.
- The structured-secondary-evidence regression passed its six combinations on
  Python 3.13.0 and system Python 3.9.6. Raw validator `OSError` and
  `TransactionError` primaries each combine with applied-live
  identity/content/access-policy drift at lock release; final JSON retains the
  original reason/message plus validator cleanup, lock-finalization
  revalidation, and descriptor cleanup in deterministic order.
- The final Python 3.13.0 repository suite passed 1,283/1,283 tests. Five
  focused Python 3.9.6 methods covered the new matrix, prior raw-validator
  cleanup propagation, lock-evidence lifetime, exception-note fallback, and
  the exact signal pending-read/unblock race.
- Final static gates passed Ruff check/format, Python 3.13.0 and system Python
  3.9.6 byte compilation, the official Rules skill validator,
  project-journal validation, and `git diff --check`; task-scoped validation
  caches and the skill-validation report were removed afterward.
- The original-live durability boundary passed 7/7 focused cases on both
  Python 3.13.0 and system Python 3.9.6: exact fsync/revalidation ordering,
  fsync error, and post-fsync replacement, content, access, link, and missing
  dirent drift. Every failure proved that receipt, prepared/terminal evidence,
  backup, private stage, and exchange publication had not started.
- The Python 3.13.0 repository run exercised all 1,290 tests. Its only four
  errors were unrelated temporary merge-commit fixtures blocked from
  `~/.gnupg/keyboxd` by the sandbox; those exact four passed 4/4 in the
  approved narrow GPG-capable rerun.
- Final gates passed Ruff check/format, Python 3.13.0 and system Python 3.9.6
  byte compilation, project-journal validation, the official Rules skill
  validator in an isolated `uv --with PyYAML` environment after direct Python
  reported missing `yaml`, and `git diff --check`.
- The complete original-live matrix passed 11/11 on both Python 3.13.0 and
  system Python 3.9.6. Four new syscall-level cases inject raw `EIO` from the
  bound FD read and parent-dirent stat before and after fsync; every result
  retains phase, scope, operation, errno, nested reason, and exact
  `receipt_written: false` / `exchange_started: false` evidence while the
  existing missing-dirent case remains `live_rules_missing`.
- The final Python 3.13.0 repository run exercised all 1,294 tests. Its only
  four errors were the unchanged temporary merge-commit fixtures blocked from
  `~/.gnupg/keyboxd` by the sandbox; those exact four passed 4/4 in the
  approved narrow GPG-capable rerun.
- Final gates passed Ruff check/format, Python 3.13.0 and system Python 3.9.6
  byte compilation, the official Rules skill validator through isolated
  `uv --with pyyaml`, project-journal validation, and `git diff --check`.
- The new original-live parent and pre-receipt matrix passed 10/10 on both
  Python 3.13.0 and system Python 3.9.6. It proves file-fsync →
  parent-fsync → complete revalidation order, structured parent-fsync
  failure, initial/final descriptor/path EIO classification on both sides of
  the boundary, and exact retained `recovery_required` state for receipt
  write, file-fsync, and parent-fsync failures.
- The first validator now hands its managed-signal gate to pre-receipt
  publication. `SIGINT`, `SIGTERM`, and `SIGHUP` remain capture-only across
  prepared-candidate, recovery-terminal, and receipt create/write/fsync/full
  validation/binding boundaries. A signal is forwarded only after the exact
  recovery state is constructed and the transaction-owned descriptors close;
  an ordinary publication failure followed by a late signal inherits the same
  top-level recovery envelope instead of burying locators in cleanup evidence.
- The complete Rules transaction module passed 251/251 on Python 3.13.0. The
  three new integration methods exercise 69 real-signal subcases: 21
  publication boundaries for each managed signal, conflict preservation for
  each signal, and late-signal recovery-envelope inheritance for each signal.
  The Python 3.13.0 repository suite passed 1,313/1,313.
- Final source gates passed Ruff check/format, Python 3.13.0 and system Python
  3.9.6 byte compilation, the official Rules skill validator, and
  project-journal validation. The task-scoped system-Python bytecode cache was
  inspected and removed.
- The first validator's managed-signal gate now becomes interruptible only
  while the post-validation shared lock is being acquired. It returns to
  capture-only before the lock body begins, so `SIGINT`, `SIGTERM`, and
  `SIGHUP` interrupt a contended lock immediately without extending
  asynchronous exceptions into transaction publication. The first signal
  remains authoritative, the lock descriptor closes before handler
  restoration, and no receipt, prepared candidate, recovery terminal, backup,
  or private-stage object is created.
- The final Rules transaction module passed 254/254 on Python 3.13.0, including
  real contended-lock subprocess coverage for all three managed signals,
  deterministic first-signal/duplicate-signal cleanup coverage, and the
  unchanged `lock_busy` timeout outcome. The same three focused methods passed
  on system Python 3.9.6, and the final Python 3.13.0 repository suite passed
  1,316/1,316.
- Final lock-wait gates passed Ruff check/format, Python 3.13.0 and system
  Python 3.9.6 byte compilation, the official Rules skill validator,
  project-journal validation, and `git diff --check`. Repository
  `__pycache__` directories and both task-scoped system-Python bytecode caches
  were inspected and removed.
- The inherited-mask lock-wait matrix passed 5/5 focused cases on Python
  3.13.0 and system Python 3.9.6. Real contended-lock children pre-block each
  of `SIGINT`, `SIGTERM`, and `SIGHUP`, preserve an unrelated blocked signal,
  exit within the interrupt bound, keep the first signal authoritative across
  a distinct second signal, restore the exact inherited mask, close the lock
  descriptor before handler restoration, and create no receipt, backup,
  prepared candidate, terminal, result, or private stage.
- The complete Rules transaction module passed 256/256 on Python 3.13.0 and
  255 passed plus one capability skip across 256 tests on system Python 3.9.6.
  The skip covers only injected `os.waitid` failure because that interpreter
  does not expose `waitid`; production uses the independently tested Darwin
  `kqueue` exit observer and waitid-independent emergency cleanup.
- Session-corpus and bounded-deadline compatibility modules passed 93/93 on
  both Python 3.13.0 and system Python 3.9.6. The final unfiltered repository
  suites passed 1,318/1,318 on Python 3.13.0 and 1,317 passed plus the same
  one capability skip across 1,318 tests on system Python 3.9.6.
- Final source gates passed Ruff check and format-check for all changed Python
  files, Python 3.13.0 and system Python 3.9.6 byte compilation, both affected
  skill validators, project-journal validation, and `git diff --check`.
