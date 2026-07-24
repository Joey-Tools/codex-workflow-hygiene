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
5. Put the reviewed bytes in a task-scoped candidate source and run the skill-relative helper:

```bash
RULES_HYGIENE_SKILL="<loaded-codex-rules-hygiene-dir>"
python3 "$RULES_HYGIENE_SKILL/scripts/apply_rules_transaction.py" apply \
  --candidate "$TASK_DIR/default.rules.candidate" \
  --candidate-sha256 "$CANDIDATE_RULES_SHA256" \
  --expected-sha256 "$EXPECTED_RULES_SHA256" \
  --backup-name "default.rules.bak-$TIMESTAMP" \
  --receipt "$TASK_DIR/rules-apply-recovery.json" \
  -- <validator-argv> '{rules}'
```

6. The helper derives `rules/default.rules` and `.default.rules.apply.lock` from `CODEX_HOME`, with the ordinary Codex home as the fallback. Pass validator arguments directly; the helper replaces the one exact `'{rules}'` argument with an inherited descriptor path for the first pass and the live path for the second pass. The first path is valid only in the synchronous direct child; do not route it through a broker, daemon, container, or grandchild that closes inherited FDs, and do not wrap the validator in `bash -lc`. The timeout must be finite and positive. The supervisor requires a standalone single-threaded main process with default `SIGCHLD` disposition, captures at most 128 KiB across stdout and stderr, and terminates, drains, and reaps the validator process group on timeout, output overflow, surviving descendants, cancellation, or supervisor observation failure. Before validator launch it blocks `SIGINT`, `SIGTERM`, and `SIGHUP`, installs a first-signal gate, lets the child inherit the launcher's original mask, and arms only after `Popen` returns a bound child PID/PGID. A managed signal then closes the gate against later interruption, completes every group inventory and TERM/KILL operation before the final direct-child wait releases the leader PID/PGID, restores the original handlers and mask, and returns `128 + signal`.
7. Accept only `applied` or `no_change_after_lock` as successful apply outcomes. Apparent no-change still takes the shared lock, admits the live file's complete metadata and single-link policy, revalidates the candidate source, and requires any already-existing fixed stage to be the bound metadata-admitted empty root; it creates no stage and launches no validator. A real apply reuses one fixed owner-private `.default.rules.transaction-stage` root, which must start empty. The schema-v3 receipt becomes durable before live exchange. Exchange places the installed object at live and the exact original inode at `transaction-stage/candidate`; atomic no-replace publication moves that original object to the formal backup, after which both directories are fsynced. Normal apply, rollback, and recovery leave the fixed root empty, without pathname deletion, root quarantine, or child-inode reuse, and verify that terminal state before releasing the same shared lock. Any unexpected entry or replaced root is retained and makes a pending post-replace success `recovery_required`. `post_replace_failed_rolled_back` means the requested cleanup did not apply. `recovery_required` means an atomic publication or exchange outcome, the resulting protected properties, or required fixed-stage cleanup could not be proved. Preserve the emitted backup, schema-v3 receipt, identity-bound recovery-copy locators, staged-backup locator when present, and object observations for operator-directed recovery. Treat `retention_incomplete` as proof that one or more descriptor-only objects could not be copied durably—not as a retained object.
8. Keep the receipt and bound backup until post-replace checks and any required recovery decision finish. To retry the identity-bound rollback:

```bash
python3 "$RULES_HYGIENE_SKILL/scripts/apply_rules_transaction.py" recover \
  --receipt "$TASK_DIR/rules-apply-recovery.json"
```

9. Refresh `default.rules.clean-baseline` only after a successful full cleanup with no intentionally retained drift debt.
10. Write the necessary adopted-journal or focused-note update only for a durable decision actually applied or a successful full-cleanup baseline refresh. Use an existing owning-repo journal when already adopted; otherwise use a nearby focused note rather than bootstrapping a tracker.
11. Never treat the new safety backup as the comparison anchor for the same apply.

### Transaction Safety Boundary

- Candidate validity protects exact authorized bytes and object policy: the helper requires a candidate SHA-256 independent of the audited live digest and first copies those exact bytes to an owner-only regular file that is unlinked and outside the rules directory. It passes that FD only to the synchronous validator child, then revalidates the held FD's identity, content, mode/owner, `st_nlink == 0`, flags, xattrs, ACL admission, descriptor path, and the original candidate-source protected properties. Only then does it create an owner-only `st_nlink == 1` formal candidate inside the fixed descriptor-bound `0700` stage. The anonymous copy isolates the formal stage from invalid candidates; it does not claim isolation from a hostile same-UID validator that mutates and restores the inherited FD. Any observable drift fails closed before the rules lock or stage exists.
- Compare-and-replace protects four live property groups under one shared lock: object identity (`device`, `inode`), content (`size`, SHA-256), access policy (`uid`, `gid`, permission bits), and object policy (`st_nlink == 1`). Modification times are not treated as policy mutation when those selected properties remain stable.
- The backup, receipt, recovery-terminal reservation, rules parent, and receipt parent remain descriptor-bound through the live exchange and installed verification. Evidence files repeat identity, content, access, single-link, flags, xattr, ACL, and exact directory-entry checks. Directory parents protect identity, access policy, metadata admission, and pathname binding; ordinary child-entry churn is not misclassified as directory content mutation.
- The recovery-terminal leaf must be absent and is created with an atomic exclusive open before backup publication. Its owner-only, single-link reservation contains the transaction ID and is finalized in place after a verified rollback. Any pre-existing terminal leaf blocks a new transaction instead of being interpreted as evidence for it.
- Schema-v3 receipts bind those regular-file properties, the rules-parent object identity, the fixed stage-root identity, the precise staged-backup leaf, and the recovery-terminal reservation identity. The v3 `backup` snapshot must exactly equal `original`, even before the backup pathname exists. Every original, installed, backup, and recorded terminal-reservation snapshot must record `nlink: 1` or recovery refuses it. Recovery remains compatible with schema-v1 receipts; schema-v2 receipt compatibility preserves copy-backup semantics and treats a missing terminal or link policy as unknown rather than invented. Descriptor-backed admission rejects nonzero policy file flags, caller-controlled xattrs, and platform ACLs. Darwin's kernel-managed `com.apple.provenance` record is explicitly outside the protected content/access policy because ordinary file creation adds or recreates it; every other xattr remains rejected. An unavailable flags, xattr, or ACL API is an explicit fail-closed platform error.
- The expected live SHA-256 and independent candidate SHA-256 bind apply to both sides of the audit authorization. Missing, unreadable, wrong-type, digest-mismatched, identity-replaced, content-mutated, and access-policy-changed states remain distinct outcomes.
- After live exchange, backup publication uses Darwin `renameatx_np(RENAME_EXCL)` or Linux `renameat2(RENAME_NOREPLACE)` to move the exact displaced original from the fixed stage to the absent backup pathname; an existing backup is never overwritten. Live installation and restore use `RENAME_SWAP` or `RENAME_EXCHANGE`, then verify the descriptor-bound objects and both directory entries. Missing libc or filesystem support is a fail-closed `atomic_rename_unsupported` outcome; there is no `os.replace` fallback.
- Atomic exchange is not a kernel compare-and-swap against an expected inode. The no-lost-update guarantee therefore still requires every legitimate writer to honor the same persistent lock. On an uncertain outcome, the helper reads every still-bound source/destination FD, creates a fresh single-link recovery copy in the owner-private stage, fsyncs the file and both relevant directories, and reports each origin and copy identity. It never equates an open FD with durable retention.
- A recovery locator is emitted only after the held rules-parent FD is rebound to the configured pathname, then the held origin and recovery-copy FDs are reread and compared for identity, bytes/digest/size, mode/uid/gid, link count, flags/xattrs/ACL admission, and directory-entry binding. The discovered stage/file entries and parent binding are then checked again. If any property drifts, the parent path was replaced, an entry was concurrently unlinked, or a recovery copy could not be completed, the locator is null and the result says `retention_incomplete` or `descriptor_only_or_unlocatable`.
- Fixed-stage cleanup runs only after the validator process group is quiescent. It verifies that the same bound owner-private root is empty, then closes descriptors; there is no compare-and-unlink or compare-and-rmdir, the root is never moved, and a child inode is never reused. The legacy `stage_cleanup_retained` quarantine status is retired: an empty persistent stage is not recovery evidence. A remaining/replacement entry is retained as unfinished or uncertain evidence and yields `stage_cleanup_refused`; after live replacement that becomes `recovery_required`, never success.
- Schema-v3 recovery accepts only prepared `P=(live O, backup missing, stage I)`, exchanged `X=(live I, backup missing, stage O)`, committed `C=(live I, backup O, stage missing)`, or restored `R=(live O, backup I, stage missing)`, where `O` and `I` are exact receipt-bound identities. It advances `P→X→C→R` through the same atomic primitives and can resume after any crash boundary. Automatic rollback and legacy recovery still require live rules to match installed protected properties and the backup to match its bound protected properties. Successful rollback records and revalidates a sibling owner-private recovery-terminal identity. A later `already_original` result requires the receipt's exact original identity or that exact terminal evidence; same-content replacement inodes are refused. Any uncertain exchange requires operator recovery rather than a second destructive guess.
- Validator completion is independent of stdout/stderr EOF. On Darwin the supervisor queries the process group through `libproc`; on Linux it inspects bounded `/proc` process metadata. Any live same-PGID member—including one with all standard streams redirected to `/dev/null`—is terminated and makes the validation result fail closed.

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
