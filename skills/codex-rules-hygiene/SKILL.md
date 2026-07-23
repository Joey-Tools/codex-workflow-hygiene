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
- Revalidate the current rules and comparison anchor before writing. Stop if they no longer match the audited inputs.
- If there is no approved content change, report a no-op and create nothing.
- Otherwise perform the ordered transaction below: backup, rewrite, validate, baseline refresh when eligible, then any necessary adopted-journal update.

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

## Apply Transaction

1. Re-read and verify the audited inputs, then identify the existing rules-policy validator. If no trustworthy validation gate can be named and run, stop before backup or rewrite and report that missing gate.
2. Create one timestamped safety backup such as `default.rules.bak-YYYYMMDD-HHMMSS`; never use that new backup as the current audit's comparison anchor.
3. Rewrite only the reviewed rule set, preserving unrelated entries.
4. Run the identified policy validator against the rewritten file before treating cleanup as successful.
5. After a successful full cleanup with no intentionally retained drift debt, refresh `default.rules.clean-baseline` from the rewritten file. Never refresh it after audit mode, a light cleanup, or a failed/partial apply.
6. Write only the necessary adopted-journal or focused-note update when apply adopts a durable rule/helper/skill decision or records the successful full-cleanup baseline. Use an owning repo's existing journal when already adopted; otherwise use a nearby focused note instead of bootstrapping a tracker. Do not journal a read-only audit or no-op apply.

## Ownership And Guardrails

- Rules govern reusable approval families; skills decide when to use them; helpers encode repeated fragile mechanics.
- Use `host_executable()` only to harden a small trusted basename family, not to excuse wrapper drift.
- Do not widen rules because one literal was inconvenient.
- Do not keep fixed issue IDs, PR numbers, prompt files, review bundles, or task-scoped temp paths after their stable owner is known.
- Read [references/audit-cadence.md](references/audit-cadence.md) for light/full audit cadence, mode checklists, and classification examples.
