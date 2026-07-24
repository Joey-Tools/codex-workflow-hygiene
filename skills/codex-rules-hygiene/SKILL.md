---
name: codex-rules-hygiene
description: Audit or apply cleanup to the user's `~/.codex/rules/default.rules` by separating stable command families from wrapper drift, helper gaps, and disposable approval-log literals. Default to read-only audit after rules growth or recurring one-off approvals; enter apply mode only when cleanup is authorized or an audit has proved an exact change that the active task authorizes.
---

# Codex Rules Hygiene

## Overview

Keep `default.rules` as a compact policy layer rather than an approval log.
Always choose an explicit mode before inspecting or changing host state.

## Choose A Mode

### Audit Mode

- Use for inspect, audit, report, or recommendation requests.
- Choose a light audit for one known recent growth burst; choose a full audit for whole-file, stale-gap, periodic, or cold-start requests.
- Keep the run read-only: leave `default.rules`, baselines, safety snapshots, and journals unchanged.
- Resolve the best existing comparison anchor, classify the delta, and report an exact proposed change.
- If no clean baseline or older backup exists, inspect the current file as a cold-start inventory and report the bootstrap apply plan while leaving host state unchanged.
- An audit-only request never becomes writable merely because it found drift.

### Apply Mode

- Use when the user requested cleanup/apply, or when a prior audit proved an exact change and the active task already authorizes applying it.
- Carry forward independent SHA-256 digests for the audited live-rules bytes and the exact candidate bytes. Stop if either digest or either byte sequence is missing.
- If there is no approved content change, report a no-op and create nothing.
- Otherwise use the skill-relative transaction helper below; do not rewrite live rules directly.

## Audit Workflow

1. Resolve the comparison anchor without writing.
- Prefer `~/.codex/rules/default.rules.clean-baseline`.
- Otherwise use the most recent older `default.rules.bak-*`.
- If neither exists, mark the audit as a cold start and inspect the current file directly.

2. Diff first, then classify each added rule.
- `stable prefix`: a categorical command family likely to recur with the same argv prefix.
- `wrapper drift`: shell, `env`, prompt-file, or fixed-temp plumbing obscures an existing stable owner.
- `helper gap`: a repeated workflow lacks a safe helper interface.
- `approval log`: a one-off URL, PR, SHA, prompt, temp path, or scenario literal.

3. Propose the narrowest owner.
- Keep a stable prefix only when it is intentionally reusable.
- Fix wrapper drift in the invocation or helper instead of preserving the wrapper literal.
- Route repo-specific helper gaps to repo-local owners and host-level cross-repo gaps to personal skills.
- Use [$codex-skill-authoring](../codex-skill-authoring/SKILL.md) when the instruction layer or owner is unclear.
- Use [$codex-session-mining](../codex-session-mining/SKILL.md) only for a targeted origin backtrace when the diff is ambiguous.

4. Bind any proposed apply plan without writing host state.
- Record separate SHA-256 digests for the exact audited `default.rules` bytes and the exact candidate bytes.
- Produce the exact candidate bytes or a deterministic patch that recreates them.
- Name the comparison anchor and validator that apply mode must revalidate.
- Keep the audit read-only: do not create the candidate file, backup, lock, receipt, baseline, or journal update.

## Apply Transaction

1. Identify the existing rules-policy validator. If no trustworthy validation gate can be named and run, stop before creating a backup or touching live rules.
2. Require one writer protocol for the transaction. Every legitimate rules writer must use the helper's shared lock, or the caller must first prove other writers quiescent; POSIX advisory locks cannot protect against a writer that ignores them.
3. Write the reviewed bytes only to a task-scoped candidate source, then invoke `scripts/apply_rules_transaction.py apply` with the audited live SHA-256 digest, the independent audited candidate SHA-256 digest, a fresh timestamped backup basename, an owner-private recovery receipt path, and direct validator argv containing one `'{rules}'` placeholder. The helper derives live `rules/default.rules` and its persistent lock from `CODEX_HOME` (falling back to the default Codex home).
4. Let the helper bind and digest-check the candidate source before copying it. An apparent no-change takes the shared lock, binds that exact lock object and rules parent, admits live metadata and link policy, revalidates the source binding, verifies that any already-existing fixed stage is the bound metadata-admitted empty root, and returns `no_change_after_lock` without creating a stage or starting a validator. For a real change, the first validator receives only an unlinked descriptor-backed copy outside the rules directory; the helper passes that FD directly to the synchronous child, revalidates every protected property and admitted metadata on the held FD, then revalidates the original source. A validator broker, daemon, container, or grandchild that closes inherited FDs cannot consume this first-pass path. After both checks pass and while holding the lock, the helper preflights the fixed stage and its metadata before creating any prepared candidate, terminal reservation, receipt, or backup. Only a clean preflight may create the exact owner-private prepared candidate at the receipt-sibling recovery locator; candidate bytes do not enter the fixed stage until the schema-v4 receipt is durable. Its validator supervisor requires a finite deadline, a standalone single-threaded main process with default `SIGCHLD` disposition, enforces an aggregate output-byte ceiling, and independently enumerates live same-process-group members before accepting completion. Before `Popen`, it masks and installs a first-signal gate for `SIGINT`, `SIGTERM`, and `SIGHUP`; it arms only after the child PID/PGID is parent-bound, performs every group inventory and TERM/KILL operation while the unreaped leader still pins that numeric PGID, and makes the final direct-child wait the last process-group lifecycle operation. Setup, observation, cancellation, process-inventory, and other supervisor failures use the same emergency cleanup. The helper revalidates identity, content, access policy, and link policy on the held candidate and live descriptors, plus file flags, xattrs, and ACL admission, immediately before exchange and after installation.
5. The fixed owner-private staging directory `.default.rules.transaction-stage` is reusable infrastructure: a normal transaction requires it to be owner-only, metadata-admitted, and empty. After the artifact-free preflight, the helper creates and fsyncs the exact prepared candidate and immutable recovery-terminal reservation, writes and fsyncs the schema-v4 receipt that binds both recovery locators and the prepared object's identity, and only then creates or opens the fixed stage and atomically moves that same candidate object into `transaction-stage/candidate`. The receipt and rules parents must be on one filesystem, and the receipt parent cannot itself be the fixed stage. The helper exchanges the private candidate with live rules, so the exact displaced original inode later occupies the staged candidate leaf and is published directly to the absent formal backup with atomic no-replace rename; every affected directory is fsynced. A successful apply, automatic rollback, or recovery leaves the fixed stage empty without unlinking, removing, quarantining, or reusing any exposed child inode, and it completes fixed-stage, lock, and parent revalidation before releasing the same shared lock. Any unexpected remaining entry or replaced stage root is retained and blocks success or a later apply. Treat only `applied` or `no_change_after_lock` as success. The helper re-runs the validator against live rules; a post-exchange failure rolls back by exchanging the bound backup and live objects only while live still matches the exact installed protected properties. If an atomic outcome cannot be proved, it returns `recovery_required` and copies every still-bound source/destination FD into fsynced recovery files. Count an object as retained recovery evidence only after the locator is bound and the held origin and recovery-copy descriptors, complete protected properties, metadata admission, and directory entries are revalidated; `retention_incomplete` explicitly means descriptor cleanup may destroy an unlinked object.
6. Use `scripts/apply_rules_transaction.py recover --receipt <path>` only for that receipt. Schema-v4 adds the durable prepared state `Q=(original live, backup missing, stage missing, installed prepared sibling)` to schema-v3's `P`, `X`, `C`, and `R` identity states. Recovering `Q` records the verified original terminal state without deleting or moving the prepared object; repeated recovery is idempotent. `P→X→C→R` uses the same exchange/no-replace operations. The receipt file and owner-private receipt-parent descriptors stay open from secure parse through lock acquisition, every mutation, terminal publication, final validation, and lock release; exact pathname entry, identity, bytes, access policy, single-link policy, and parent identity/policy are revalidated at every boundary. Pre-mutation drift is `recovery_refused`; once any delegated v3/v4 mutation may have started, later binding failure remains `recovery_required` and includes its mutation journal, observed state, and recovery locators. Terminal publication never truncates the reservation: it fsyncs a fresh owner-private result slot, atomically publishes the sibling `.result` entry without replacement, fsyncs the directory, and keeps both descriptors bound through lock release. A crash therefore leaves either the previous reservation or a complete retry-readable result, possibly plus a reported pending locator. Schema-v3 compatibility retains its four-state recovery. Legacy schema-v1/v2 receipts retain copy-backup recovery semantics but now bind their exact receipt/rules parents under the lock, and retained fixed-stage evidence or refused cleanup returns `recovery_required` rather than success. `already_original` requires either the receipt's exact original identity or a verified recovery-terminal result created for that transaction; matching bytes and policy on a different unrecorded inode are refused.
7. After a successful full cleanup with no intentionally retained drift debt, refresh `default.rules.clean-baseline` from the verified live file. Never refresh it after audit mode, a light cleanup, a rollback, `recovery_required`, or a failed/partial apply.
8. Write only the necessary adopted-journal or focused-note update when apply adopts a durable rule/helper/skill decision or records the successful full-cleanup baseline. Use an owning repo's existing journal when already adopted; otherwise use a nearby focused note instead of bootstrapping a tracker. Do not journal a read-only audit or no-op apply.

## Ownership And Guardrails

- Rules govern reusable approval families; skills decide when to use them; helpers encode repeated fragile mechanics.
- Load [references/audit-cadence.md](references/audit-cadence.md) before apply mode for the helper command, output states, and recovery boundary.
- Use `host_executable()` only to harden a small trusted basename family, not to excuse wrapper drift.
- Do not widen rules because one literal was inconvenient.
- Do not keep fixed issue IDs, PR numbers, prompt files, review bundles, or task-scoped temp paths after their stable owner is known.
- Read [references/audit-cadence.md](references/audit-cadence.md) for light/full audit cadence and classification examples.
