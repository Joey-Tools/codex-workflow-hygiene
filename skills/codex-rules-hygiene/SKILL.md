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
4. Let the helper bind and digest-check the candidate source before copying it. An apparent no-change takes the shared lock, admits live metadata and link policy, revalidates the source binding, and returns `no_change_after_lock` before creating a stage or starting a validator. For a real change, the helper copies and validates the candidate inside an owner-private staging directory, then revalidates the original source identity, content, access policy, and candidate digest after private validation. Its validator supervisor requires a finite deadline, enforces an aggregate output-byte ceiling, and independently enumerates live same-process-group members before accepting completion. Before `Popen`, it masks and installs a first-signal gate for `SIGINT`, `SIGTERM`, and `SIGHUP`; it arms only after the child PID/PGID is parent-bound, then delays the conventional `128 + signal` exit until bounded whole-group TERM/KILL, output drain, and direct-child reap finish. Setup, observation, cancellation, process-inventory, and other supervisor failures use the same emergency cleanup. The helper revalidates identity, content, access policy, and link policy on the held candidate and live descriptors, plus file flags, xattrs, and ACL admission, immediately before exchange and after installation.
5. Before backup publication, the helper atomically reserves an absent owner-only recovery-terminal leaf for the transaction; any stale existing leaf blocks the transaction. Under the lock it publishes the descriptor-bound backup with an atomic no-replace rename, writes a descriptor-bound recovery receipt, keeps both parent directories and every evidence file bound, and exchanges the private candidate with live rules. It repeats those bindings through installed verification. Treat only `applied` or `no_change_after_lock` as success. The helper re-runs the validator against live rules; a post-exchange failure rolls back only while live still matches the exact installed protected properties. If an atomic outcome cannot be proved, it returns `recovery_required` and copies every still-bound source/destination FD into fsynced recovery files. Count an object as retained recovery evidence only after the locator is bound and the held origin and recovery-copy descriptors, complete protected properties, metadata admission, and directory entries are revalidated; `retention_incomplete` explicitly means descriptor cleanup may destroy an unlinked object. Ordinary disposable cleanup never performs path-based unlink or rmdir after a separate identity check: because POSIX has no conditional delete, it atomically moves the complete stage to a fresh no-clobber cleanup quarantine and reports the verified locator. That `stage_cleanup_retained` warning does not change an already verified `applied` or rolled-back outcome, but a `stage_cleanup_refused` result is processed before terminal output and cannot be reported as success.
6. Use `scripts/apply_rules_transaction.py recover --receipt <path>` only for that receipt. Recovery revalidates the same lock, installed object, and bound backup before an atomic exchange restore. `already_original` requires either the receipt's exact original identity or a verified recovery-terminal record created for that transaction; matching bytes and policy on a different unrecorded inode are refused.
7. After a successful full cleanup with no intentionally retained drift debt, refresh `default.rules.clean-baseline` from the verified live file. Never refresh it after audit mode, a light cleanup, a rollback, `recovery_required`, or a failed/partial apply.
8. Write only the necessary adopted-journal or focused-note update when apply adopts a durable rule/helper/skill decision or records the successful full-cleanup baseline. Use an owning repo's existing journal when already adopted; otherwise use a nearby focused note instead of bootstrapping a tracker. Do not journal a read-only audit or no-op apply.

## Ownership And Guardrails

- Rules govern reusable approval families; skills decide when to use them; helpers encode repeated fragile mechanics.
- Load [references/audit-cadence.md](references/audit-cadence.md) before apply mode for the helper command, output states, and recovery boundary.
- Use `host_executable()` only to harden a small trusted basename family, not to excuse wrapper drift.
- Do not widen rules because one literal was inconvenient.
- Do not keep fixed issue IDs, PR numbers, prompt files, review bundles, or task-scoped temp paths after their stable owner is known.
- Read [references/audit-cadence.md](references/audit-cadence.md) for light/full audit cadence and classification examples.
