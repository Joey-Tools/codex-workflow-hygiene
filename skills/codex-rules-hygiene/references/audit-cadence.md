# Rules Audit Cadence

## Mode Contract

- `audit` is read-only. It may resolve existing anchors, diff, classify, and propose an exact apply plan, but it leaves every host file unchanged.
- Apply-mode authorization and transaction rules begin at the Apply Checklist below.

## Default Rhythm

- Prefer a light audit after one burst of work when `~/.codex/rules/default.rules` clearly gained shell-shaped literals.
- Prefer a fuller audit about once a week, or when roughly `8-12` new rules have accumulated since the clean baseline was last established or another successful full audit.
- If the file grows again immediately after a cleanup, treat that as a workflow-design signal rather than as proof that the deleted literal was actually durable.
- Treat `~/.codex/rules/default.rules.clean-baseline` as the canonical clean anchor after a successful full cleanup.
- If that clean-baseline file does not exist yet, treat the latest timestamped backup as the temporary comparison fallback rather than pretending a clean anchor exists.
- If neither anchor exists yet, treat the current file as a cold-start read-only inventory; host-state mutation belongs exclusively to apply mode.

## Light Audit Checklist

1. Resolve the comparison baseline: prefer `~/.codex/rules/default.rules.clean-baseline`, otherwise fall back to the latest timestamped backup; if neither anchor exists yet, stop the light audit here and switch to the cold-start bootstrap below.
2. Inspect only the added lines.
3. Label each new line:
   - `stable prefix`
   - `wrapper drift`
   - `helper gap`
   - `approval log`
4. Propose removal of obvious approval-log literals without changing the file.
5. If one workflow family drifted because of `env ...` or shell wrappers, name that family and its helper or invocation owner.
6. If a `helper gap` appears, decide the owner before ending the audit:
   - repo-local skill/helper when the drift is tied to one repo's scripts or policy
   - personal skill/helper when the drift is host-level and cross-repo
   - [$codex-skill-authoring](../../codex-skill-authoring/SKILL.md) when the owner or instruction layer is unclear
7. Emit an exact apply plan or a read-only no-change result. Keep every host file unchanged.

## Full Audit Checklist

1. Diff against `~/.codex/rules/default.rules.clean-baseline` when it exists; otherwise use the previous timestamped backup as a first-pass fallback. If neither anchor exists yet, switch to the cold-start bootstrap instead of pretending a comparison baseline exists.
2. Group additions by workflow family rather than by literal string.
3. Propose the narrowest stable prefix that still covers each recurring workflow.
4. Identify obsolete literals already replaced by helpers or skills.
5. State whether the proposed full cleanup would qualify the resulting file as the next `default.rules.clean-baseline`.
6. List any durable observation that apply mode would record in a journal or focused note if adopted.
7. Remain read-only until apply mode is authorized.

## Apply Checklist

1. Enter apply mode only when cleanup is requested or an audit has proved an exact change that the active task authorizes.
2. Carry forward the exact audited `default.rules` SHA-256 digest, an independent SHA-256 digest of the exact candidate bytes, the candidate bytes, selected comparison anchor, and existing policy validator. Stop before backup or replacement if any input is missing.
3. If no content change remains, report a no-op and create nothing.
4. Require all legitimate writers to share the transaction lock. If a rules writer cannot honor that advisory-lock protocol, prove it quiescent for the complete compare/replace/post-validation window or stop.
5. Put the reviewed bytes in a task-scoped candidate source. Derive the active rules parent from `CODEX_HOME`, then create a fresh recovery directory inside that parent with a restrictive umask. This keeps the receipt on the same filesystem as live rules and gives it an owner-private parent; an arbitrary task directory or separately mounted `/tmp` directory does not satisfy the transaction contract. Preserve the recovery directory through every post-replace check and recovery decision. The helper still independently verifies exact owner, `0700` mode, ACL and metadata admission, parent identity, and same-filesystem placement. Before reading the candidate or creating the persistent lock, it rejects the receipt plus every derived terminal, result, prepared-candidate, and lock path when its lexical/canonical namespace, descriptor-bound existing-directory identity, or conservative NFKC/casefold component sequence under the same bound rules parent aliases the fixed stage leaf, an ancestor, or a descendant. It also holds every relevant parent descriptor while pairwise rejecting NFKC-plus-casefold leaf collisions among rules, backup, lock, receipt, terminal, result, and prepared paths:

```bash
set -euo pipefail

RULES_HYGIENE_SKILL="<loaded-codex-rules-hygiene-dir>"
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
RULES_DIR="$CODEX_ROOT/rules"
RECOVERY_DIR="$(umask 077; mktemp -d "$RULES_DIR/.rules-apply-recovery.XXXXXX")"
python3 "$RULES_HYGIENE_SKILL/scripts/apply_rules_transaction.py" apply \
  --candidate "$TASK_DIR/default.rules.candidate" \
  --candidate-sha256 "$CANDIDATE_RULES_SHA256" \
  --expected-sha256 "$EXPECTED_RULES_SHA256" \
  --backup-name "default.rules.bak-$TIMESTAMP" \
  --receipt "$RECOVERY_DIR/rules-apply-recovery.json" \
  -- <validator-argv> '{rules}'
```

6. The helper derives `rules/default.rules` and `.default.rules.apply.lock` from `CODEX_HOME`, with the ordinary Codex home as the fallback. Pass validator arguments directly; the helper replaces the one exact `'{rules}'` argument with an inherited descriptor path for the first pass and the live path for the second pass. The first path is valid only in the synchronous direct child; do not route it through a broker, daemon, container, or grandchild that closes inherited FDs, and do not wrap the validator in `bash -lc`. The timeout must be finite and positive. The supervisor requires a standalone single-threaded main process with default `SIGCHLD` disposition, captures at most 128 KiB across stdout and stderr, and terminates, drains, and reaps the validator process group on timeout, output overflow, surviving descendants, cancellation, or supervisor observation failure. Before validator launch it blocks `SIGINT`, `SIGTERM`, and `SIGHUP`, installs a first-signal gate, lets the child inherit the launcher's original mask, and arms only after `Popen` returns a bound child PID/PGID. A managed signal then closes the gate against later interruption, completes every group inventory and TERM/KILL operation before the final direct-child wait releases the leader PID/PGID, restores the original handlers and mask, and returns `128 + signal`. After the first validator, shared-lock acquisition temporarily re-arms the capture gate inside a supervisor-mask window: it atomically saves the current inherited mask, unblocks only the three managed signals, and preserves every non-managed bit. Before lock success enters the body, or any timeout/exception returns to capture-only mode, it atomically re-blocks the managed set, closes the gate, consumes pending first-signal evidence with synchronous waits, restores and rereads the exact inherited mask, and only then allows lock-FD cleanup and eventual caller-handler restoration. A managed signal preblocked by the launcher therefore interrupts lock contention immediately; later signals cannot displace the first, and no receipt, prepared candidate, terminal, backup, or private-stage object exists at that boundary. During the second validator, signal return is delayed until the helper has attempted the normal rollback/recovery path. The top-level result remains `interrupted` with the signal-derived exit code, while exact receipt/backup/recovery locators, the nested rollback/recovery outcome, and any later cleanup/finalizer failures remain attached evidence.
7. Accept only `applied` or `no_change_after_lock` as successful apply outcomes. Apparent no-change still takes and identity-binds the shared lock, binds the exact rules parent, admits the live file's complete metadata and single-link policy, revalidates the candidate source, and requires any already-existing fixed stage to be the bound metadata-admitted empty root; it creates no stage and launches no validator. A real apply first preflights the fixed stage and its metadata under the lock, before creating a prepared candidate, terminal reservation, receipt, or backup. A retained entry, invalid root, or replacement race therefore leaves zero new transaction artifacts. Only a clean preflight may create and fsync the exact prepared candidate and immutable terminal reservation in the owner-private receipt parent, then make the schema-v4 receipt durable before any fixed-stage creation or candidate publication. Only afterward does it create/open and independently admit the current fixed `.default.rules.transaction-stage`, atomically move that prepared object to `transaction-stage/candidate`, and fsync every affected directory. Because `mkdir` returns no creation FD, the helper never chmods, deletes, or claims creation identity for that named directory; umask-stripped access or a replacement that does not independently satisfy the owner-only empty-stage contract fails closed with retained observation. The lock is normalized only through its authoritative `O_EXCL` FD after pre-chmod and post-chmod FD/path identity, owner, type, and link-policy checks. Immediately before exchange, the helper revalidates all controls and re-proves the formal backup leaf missing, including case-insensitive filesystem alias occupancy. Exchange places the installed object at live and the exact original inode at the staged candidate; atomic no-replace publication moves that original object to the formal backup. Normal apply, rollback, and recovery leave the fixed root empty, without pathname deletion, root quarantine, or child-inode reuse, and verify that terminal state before releasing the same shared lock. Any unexpected entry or replaced root is retained and makes a pending post-replace success `recovery_required`. `post_replace_failed_rolled_back` means the requested cleanup did not apply. `recovery_required` means a prepared publication, atomic publication or exchange outcome, resulting protected properties, lock/parent binding, or required fixed-stage cleanup could not be proved. Preserve the emitted backup, schema-v4 receipt, prepared locator, terminal result or pending-result locator, identity-bound recovery-copy locators, staged-backup locator when present, and object observations for operator-directed recovery. Treat `retention_incomplete` as proof that one or more descriptor-only objects could not be copied durably—not as a retained object.
8. Keep the receipt and bound backup until post-replace checks and any required recovery decision finish. To retry the identity-bound rollback:

```bash
python3 "$RULES_HYGIENE_SKILL/scripts/apply_rules_transaction.py" recover \
  --receipt "$RECOVERY_DIR/rules-apply-recovery.json"
```

9. Refresh `default.rules.clean-baseline` only after a successful full cleanup with no intentionally retained drift debt.
10. Write the necessary adopted-journal or focused-note update only for a durable decision actually applied or a successful full-cleanup baseline refresh. Use an existing owning-repo journal when already adopted; otherwise use a nearby focused note rather than bootstrapping a tracker.
11. Never treat the new safety backup as the comparison anchor for the same apply.

### Transaction Safety Boundary

- Schema-v4 applied `C=(I,O,M,M)` and restored `R=(O,I,M,M)` are complete four-role release states, not only live/backup projections. Apply success, automatic rollback, managed-signal rollback, and `C→R` recovery prove the staged and prepared candidate paths missing before stage cleanup closes its bindings. Reappearance of either path is an unexpected terminal role and preserves recovery evidence instead of returning a successful or certain result.
- A durable receipt plus the atomic prepared-to-stage move establishes operator recovery evidence before live exchange. If the exact original live role then changes, apply retains that staged candidate and returns `recovery_required` with every receipt-bound and derived recovery locator. Identity, content, access-policy, and single-link mismatches remain separately reported; the live conflict is not downgraded to an exit-20 result whose only evidence of the retained stage is a stderr cleanup warning.
- Zero-change is a terminal live-role proof, not only a byte comparison. Both the pre-validator fast path and a live file that converges to the candidate after validation capture identity, exact content, access policy, and single-link policy under the shared lock, then freshly rebind and compare that live role in `before_release`. Legacy schema-v1/v2 `already_original` performs the same outer release proof. Any same-UID identity replacement, content change, access-policy change, or link-count change makes the apparent success nonzero.
- Schema-v4 `Q` remains the complete four-role state `(O,M,M,I)` through lock release. After the inner recovery closes its temporary bindings, the outer callback independently rebinds the rules and prepared parents, proves live exact-original, backup missing, staged candidate missing, and prepared candidate exact-installed, and distinguishes a missing role, an unexpected role, and a protected-property mismatch. This applies to both the first `recovered` result and an idempotent `already_original` retry.
- Candidate validity protects exact authorized bytes and object policy: the helper requires a candidate SHA-256 independent of the audited live digest and first copies those exact bytes to an owner-only regular file that is unlinked and outside the rules directory. Every untrusted regular-file pathname admission uses nonblocking, no-follow open followed immediately by descriptor file-type proof, so a FIFO replacement fails as `*_not_regular` instead of blocking pre-lock, post-validator, exchange-target, or recovery binding. It passes the anonymous FD only to the synchronous validator child, then revalidates the held FD's identity, content, mode/owner, `st_nlink == 0`, flags, xattrs, ACL admission, descriptor path, and the original candidate-source protected properties. Only then does it create an owner-only `st_nlink == 1` prepared candidate at the exact receipt-sibling recovery locator. That object and its binding become part of the durable schema-v4 receipt before the same inode can enter the fixed descriptor-bound `0700` stage. The anonymous copy isolates formal recovery evidence from invalid candidates; it does not claim isolation from a hostile same-UID validator that mutates and restores the inherited FD. Any observable drift fails closed before the rules lock or stage exists.
- Compare-and-replace protects four live property groups under one shared lock: object identity (`device`, `inode`), content (`size`, SHA-256), access policy (`uid`, `gid`, permission bits), and object policy (`st_nlink == 1`). Schema-v1 snapshots always normalize historical `nlink` to unknown; when a downgraded receipt explicitly supplies that field it must be exact integer `1`, but it never becomes current policy. Every current live, backup, staged/recovery source, reservation, result, and restored-terminal observation independently proves exactly one link at every binding and revalidation. Modification times are not treated as policy mutation when those selected properties remain stable.
- The lock, prepared candidate, backup, receipt, immutable recovery-terminal reservation, optional terminal-result slot, rules parent, and receipt parent remain descriptor-bound through every applicable mutation and final live verification. Apply runs final evidence validation and fixed-stage cleanup inside the shared-lock callback but defers receipt, terminal/result, and parent descriptor closure until the lock context has completed its post-callback lock revalidation and attempted the lock-FD close. Immediately before release, apply, rollback, signal rollback, and successful recovery also reopen live and backup through the descriptor-bound rules parent and prove the terminal `C=(I,O)`, `R=(O,I)`, or `Q=(O,M)` role tuple. Each present role compares object identity, exact content, access policy, and single-link policy; missing/unreadable roles stay distinct from a property mismatch. Once live replacement has started, final control or data-role drift always propagates as recovery uncertainty, including after a verified rollback and terminal-result publication. Ordinary rollback becomes `recovery_required` with its prior operation status and exact recovery locators; a forwarded signal remains the primary exit while its nested recovery becomes `recovery_required` and the finalizer failure is attached with transaction status, details, and locators. Body, callback, and final-revalidation failures outrank a lock-close fault; the latter is recorded as structured release uncertainty and is primary only when no prior error exists. Every bind, read, rollback, stage, and persistent-evidence descriptor group closes best-effort-all in deterministic order: later closes are still attempted after EIO, EINTR, or another close failure, and structured diagnostics attach to the existing property/tamper/rollback/apply/recovery outcome instead of replacing it. Private-stage close faults join that accumulator with stable `private_stage_descriptor_close_failed` and `descriptor_class` evidence. An existing failure keeps its terminal status; an otherwise clean apply or recovery becomes nonzero `recovery_required` while retaining the original `operation_status`. A final evidence or rules-parent close fault converts an apparent apply or either no-change success to nonzero `recovery_required` with `final_evidence_descriptor_close_failed`, so it cannot authorize a baseline refresh. Recovery holds the exact receipt file and receipt-parent descriptors from secure parse through lock acquisition, all `Q/P/X/C/R` mutation boundaries, terminal publication, final validation, and lock release. Evidence files repeat identity, exact content, access, single-link, flags, xattr, ACL, and exact directory-entry checks. Directory parents protect identity, access policy, metadata admission, and pathname binding; ordinary child-entry churn is not misclassified as directory content mutation. Missing/unreadable evidence remains distinct from a proved property mismatch. The prepared and fixed-stage parents must be on one filesystem for atomic publication, and no receipt-derived namespace may overlap the fixed stage.
- The recovery-terminal leaf and its derived `.result` sibling must both be absent before apply artifacts are created. The terminal is created with an atomic exclusive open; its owner-only, single-link reservation contains the transaction ID and is never truncated or rewritten. After a verified rollback, recovery writes and fsyncs a fresh owner-private, reservation-time-bound pending result. Before rename, every failure path revalidates its descriptor, exact directory entry, bytes, access policy, one-link policy, and file/parent durability; it emits `pending_locator` only after an exact `observation_matches` result followed by another parent and descriptor/entry/content/policy revalidation. An unlink, replacement, partial, or unreadable state is `retention_incomplete`. A retry performs a bounded pending-name inventory before creation, adopts one exact retry-stable result, and blocks without creating another file when evidence is invalid, incomplete, or ambiguous. It atomically renames the accepted pending object without replacement to the `.result` slot, binds that exact entry, fsyncs the parent directory, and revalidates reservation, result, receipt, and parent before lock release. A crash at write, file-fsync, rename, or directory-fsync therefore leaves the original valid reservation, one bounded pending object with truthful retention evidence, or a complete retry-readable result. Any pre-existing reservation or result blocks a new transaction instead of being interpreted as evidence for it.
- Schema-v4 receipts bind those regular-file properties, the rules-parent object identity, the exact receipt-parent/prepared-candidate recovery locator, the precise staged-backup leaf, and the recovery-terminal reservation identity. Schema-v4 always compares that reservation's exact identity, size/digest, access policy, and link policy with the receipt snapshot, even if same-inode content decodes as restored; only schema-v3 explicitly permits that historical rewrite. The stage-root snapshot is intentionally null because the receipt is durable before stage creation; recovery dynamically admits an owner-private fixed root but still requires the exact receipt-bound candidate identity. The `backup` snapshot must exactly equal `original`, even before the backup pathname exists. Every original, installed, backup, and recorded terminal-reservation snapshot must record `nlink: 1` or recovery refuses it. Recovery remains compatible with schema-v3's stage-bound format and every legacy schema-v1 or schema-v2 receipt that uses copy-backup recovery. Descriptor-backed admission rejects nonzero policy file flags, caller-controlled xattrs, and platform ACLs. Darwin's kernel-managed `com.apple.provenance` record is explicitly outside the protected content/access policy because ordinary file creation adds or recreates it; every other xattr remains rejected. An unavailable flags, xattr, or ACL API is an explicit fail-closed platform error.
- The expected live SHA-256 and independent candidate SHA-256 bind apply to both sides of the audit authorization. Missing, unreadable, wrong-type, digest-mismatched, identity-replaced, content-mutated, and access-policy-changed states remain distinct outcomes.
- After live exchange, backup publication uses Darwin `renameatx_np(RENAME_EXCL)` or Linux `renameat2(RENAME_NOREPLACE)` to move the exact displaced original from the fixed stage to the absent backup pathname; an existing backup is never overwritten. Live installation and restore use `RENAME_SWAP` or `RENAME_EXCHANGE`, then verify the descriptor-bound objects and both directory entries. Missing libc or filesystem support is a fail-closed `atomic_rename_unsupported` outcome; there is no `os.replace` fallback.
- Atomic exchange is not a kernel compare-and-swap against an expected inode. The no-lost-update guarantee therefore still requires every legitimate writer to honor the same persistent lock. On an uncertain outcome, the helper reads every still-bound source/destination FD, creates a fresh single-link recovery copy in the owner-private stage, fsyncs the file and both relevant directories, and reports each origin and copy identity. It never equates an open FD with durable retention.
- A recovery locator is emitted only after the held rules-parent FD is rebound to the configured pathname, then the held origin and recovery-copy FDs are reread and compared for identity, bytes/digest/size, mode/uid/gid, link count, flags/xattrs/ACL admission, and directory-entry binding. The discovered stage/file entries and parent binding are then checked again. If any property drifts, the parent path was replaced, an entry was concurrently unlinked, or a recovery copy could not be completed, the locator is null and the result says `retention_incomplete` or `descriptor_only_or_unlocatable`.
- Fixed-stage cleanup runs only after the validator process group is quiescent. It verifies that the same bound owner-private root is empty, then closes descriptors; there is no compare-and-unlink or compare-and-rmdir, the root is never moved, and a child inode is never reused. The legacy `stage_cleanup_retained` quarantine status is retired: an empty persistent stage is not recovery evidence. A remaining/replacement entry is retained as unfinished or uncertain evidence and yields `stage_cleanup_refused`; after live replacement that becomes `recovery_required`, never success.
- Schema-v4 recovery accepts durable prepared `Q=(live O, backup missing, stage missing, prepared I)`, stage-prepared `P=(live O, backup missing, stage I, prepared missing)`, exchanged `X=(live I, backup missing, stage O, prepared missing)`, committed `C=(live I, backup O, stage missing, prepared missing)`, or restored `R=(live O, backup I, stage missing, prepared missing)`, where `O` and `I` are exact receipt-bound identities. While holding the lock, it records live/backup roles before strict terminal reservation/result binding or validation; when those roles are `O/M`, a bounded stage/prepared probe distinguishes exact pre-mutation `Q` from `P` or ambiguity. `O/M` alone remains `Q_or_P`; only a complete four-role proof may emit `Q`, and a later auxiliary-probe failure preserves the last complete `P` proof or conservative `Q_or_P` hint. A reserved terminal clears deferred mutation evidence only when the complete role tuple proves exact `Q`. Every other reserved-terminal or state-none observation promotes `possible_prior_transaction_state` when a mutation cannot be excluded: a missing `P` candidate, missing `R` backup, drifted prepared object without a prior exact-Q observation, or similarly ambiguous reserved-role tuple is therefore `recovery_required` with its mutation journal and exact locators. Exact installed live plus exact original staged also proves a prior exchange even when backup is unknown and prepared is missing or unreadable. A terminal failure after schema-v3 `P`, v4 `P`, `X/C/R`, or a state that may represent prior apply/recovery mutation is `recovery_required` with the observed journal and locators. Only exact proved `Q` can refuse terminal drift as pre-mutation. After terminal validation, `Q` records the verified original terminal state while retaining the exact prepared locator; repeated recovery is idempotent. Only a prior complete exact-Q observation can keep later prepared drift provably before a recovery mutation; a published Q result, observed `P/X/C/R`, or an auxiliary observation compatible with a damaged post-mutation state makes later drift `recovery_required`, including on retry. Recovery advances `P→X→C→R` through the same atomic primitives and can resume after every later crash boundary. One mutation tracker is shared when v4 delegates `P/X/C/R` work to the v3 engine and records both current-run entry/completion and durable prior-mutation observations; only provably pre-mutation binding drift is `recovery_refused`. Legacy rollback also records mutation entry immediately before its atomic exchange attempt and completion immediately after the exchange is proved, before parent or lock finalization. Once any live, backup, stage, or terminal mutation might have started, every later binding, cleanup, publication, parent-finalization, or lock-close failure remains `recovery_required` and reports the mutation journal, last observed roles/snapshots when available, and all recovery locators. Automatic rollback and legacy recovery still require live rules to match installed protected properties and the backup to match its bound protected properties. Legacy recovery additionally binds the exact receipt/rules parents under the lock and treats any retained fixed-stage evidence or cleanup refusal as `recovery_required`. Successful rollback records and revalidates the immutable reservation plus sibling terminal result. A later `already_original` result requires the receipt's exact original identity or that exact terminal evidence; same-content replacement inodes are refused. Any uncertain exchange requires operator recovery rather than a second destructive guess.
- Validator completion is independent of stdout/stderr EOF. On Darwin the supervisor queries the process group through `libproc`; on Linux it inspects bounded `/proc` process metadata. Any live same-PGID member—including one with all standard streams redirected to `/dev/null`—is terminated and makes the validation result fail closed.

Cleanup, lock-finalization, and pending-result retention attachments are runtime-compatible with Python 3.9 and 3.10: structured fields remain authoritative when `BaseException.add_note` is unavailable. On Python 3.11 and newer, human-readable exception notes are supplemental and best-effort; note lookup or attachment failure cannot displace the established primary exception, status, or recovery locator.

## Cold-Start Bootstrap

Use this branch only when a machine has neither `~/.codex/rules/default.rules.clean-baseline` nor any older `default.rules.bak-*` snapshot.

In audit mode:

1. Treat the current `default.rules` as the bootstrap inventory and classify it directly.
2. Produce an exact full-cleanup plan.
3. Do not create the safety backup or clean baseline.

In apply mode:

1. Revalidate the audited bootstrap inventory through its expected SHA-256 digest.
2. Use the Apply Checklist helper transaction to create the bound timestamped backup, validate the private candidate, and atomically replace live rules.
3. Do not diff against that freshly created backup.
4. Treat rollback or `recovery_required` as a failed bootstrap.
5. Only after the helper reports a successful full cleanup, create `~/.codex/rules/default.rules.clean-baseline`.

## Classification Heuristics

### Stable Prefix

- Direct helper entrypoints such as a fixed `python3 .../jira_issue_probe.py issue`
- Stable diagnostic families such as normalized `ps`, `lsof`, or `gh pr view`
- Repo-owned wrappers whose argv shape is intentionally reusable

### Host Executable Hardening

- Use `host_executable()` only for a small set of trusted basename command families that are already worth keeping in `default.rules`.
- Good candidates are stable toolchain or system commands such as `git`, `gh`, `bash`, `zsh`, or `/usr/bin/log`.
- The main benefit is hardening basename rules against PATH drift while still allowing absolute executable paths to resolve back to the approved basename when execpolicy runs with host-executable resolution enabled.
- Do not use `host_executable()` as a substitute for fixing `env ...`, `/bin/zsh -lc`, prompt-file wrappers, fixed `/tmp` literals, or other `wrapper drift`.
- Do not add `host_executable()` for every command by reflex. Prefer it only when the executable path itself is a meaningful trust boundary.

### Wrapper Drift

- `env FOO=... bash run_automation_e2e_signed.sh ...` when `bash run_automation_e2e_signed.sh` is already the real stable owner
- `/bin/zsh -lc "agent ... $(cat .codex-tmp/...)"` when the repeated workflow should go through a bounded review helper
- Fixed `/tmp/...` prompt-file or bundle-file names surrounding an otherwise stable command family

### Helper Gap

- Repeated Apple Notes reads before `show-work-report-prefix` existed
- Repeated remote `ssh ... jq/rg ...` before `remote_codex_probe.py`
- Repeated tracker issue metadata fetches before a dedicated tracker helper

### Approval Log

- Concrete tracker issue URLs
- Concrete PR numbers or commit SHAs
- Review prompt files under `.codex-tmp/`
- Fixed temp directories or one-off render/debug scenario names

## When To Patch A Skill

- Patch an existing skill/helper when the repeated literal is already clearly owned by that workflow family.
- Prefer repo-local skills/helpers when the drift is tied to one repository's scripts, paths, or policy.
- Create a new personal skill only when the repeated friction is host-level, cross-repo, and not already well owned.
- If ownership or layering is unclear, route that decision through [$codex-skill-authoring](../../codex-skill-authoring/SKILL.md) instead of solving it by widening rules.
- Prefer fixing examples and helper interfaces before inventing broader rules.
