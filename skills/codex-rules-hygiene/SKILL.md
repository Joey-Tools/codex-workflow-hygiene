---
name: codex-rules-hygiene
description: Audit and prune the user's `~/.codex/rules/default.rules` by separating stable command families from wrapper drift, helper gaps, and disposable approval-log literals. Use when `default.rules` grows after recent sessions, when one-off literals keep appearing, or when deciding whether friction belongs in a skill/helper instead of the rules file.
---

# Codex Rules Hygiene

## Overview

Use this skill when the user's `~/.codex/rules/default.rules` starts drifting away from a compact policy layer and back toward an approval log.
The goal is not to preserve every approved command shape. The goal is to keep only stable, reusable command families while pushing repeated friction back into helpers, skills, or cleaner invocation patterns.

## Workflow

1. Start from the rules diff, not from session archaeology.
- Resolve the comparison baseline before touching the file.
- If `~/.codex/rules/default.rules.clean-baseline` exists, use that file as the default clean baseline.
- Otherwise, on a first audit or after a stale gap, fall back to the most recent timestamped backup.
- If neither a clean-baseline file nor an older timestamped backup exists, treat the audit as a cold-start bootstrap.
- Focus on the newly added lines; do not rescan all historical rules unless the diff itself is ambiguous.
- Back up the current file before rewriting it, using a timestamped path such as `~/.codex/rules/default.rules.bak-YYYYMMDD-HHMMSS`.
- Do not treat that pre-rewrite backup as the new clean baseline.
- After a full cleanup, refresh `~/.codex/rules/default.rules.clean-baseline` from the rewritten `default.rules`, then record that refresh in project journals or a focused note.
- Do not refresh `default.rules.clean-baseline` during a light audit or while known wrapper-drift debt is still intentionally left in the file.
- In a cold-start bootstrap, the freshly created pre-rewrite backup is a safety snapshot only; do not use it as the diff baseline for the same audit.
- In that cold-start case, inspect the current file directly as the bootstrap inventory, then create `default.rules.clean-baseline` only after the first successful full cleanup.

2. Classify each new rule into one of four buckets.
- `stable prefix`: a reusable command family whose argv shape should stay allowed over time.
- `wrapper drift`: the underlying workflow is already stable, but the invocation was wrapped in `env ...`, `/bin/zsh -lc`, prompt-file plumbing, fixed `/tmp` paths, or similar shell noise that broke prefix reuse.
- `helper gap`: the literal exists because the current skill/helper cannot yet express the repeated workflow safely.
- `approval log`: one-off review prompts, issue URLs, PR numbers, fixed temp paths, exact scenario names, or similar literals with no long-term reuse value.

3. Apply the matching action for that bucket.
- Keep or add a `stable prefix` only when it is categorical and likely to recur unchanged.
- When a stable prefix is intentionally basename-based (for example `git`, `gh`, `bash`, `zsh`, or `log`), consider `host_executable()` as a hardening tool so absolute executable paths can resolve back to the approved basename without trusting arbitrary PATH resolution.
- For `wrapper drift`, prefer fixing the invocation pattern, helper interface, or skill examples over adding another literal rule.
- For `helper gap`, patch the existing helper/skill first when the workflow family already exists.
- If the drift is tied to one repository's scripts, paths, or policy, prefer the repo-local skill/helper owner.
- If the drift is host-level and cross-repo, prefer a personal skill/helper owner.
- If the owner or the right instruction layer is unclear, hand the decision to [$codex-skill-authoring](../codex-skill-authoring/SKILL.md) instead of widening rules by reflex.
- Delete `approval log` entries once a stable equivalent exists, or when they clearly describe one session's temporary scaffolding rather than a durable policy.

4. Only mine sessions when the root cause is unclear.
- If a rule's origin is not obvious from the diff, then use [$codex-session-mining](../codex-session-mining/SKILL.md) to inspect the smallest useful set of recent sessions.
- Prefer targeted backtraces for a specific literal or workflow family instead of grepping broad rollout archives by default.
- Treat session mining as evidence collection, not as the primary cleanup workflow.

5. Keep the ownership boundary clear.
- Rules govern whether a command family can run without re-approval.
- Skills describe when that family should be used.
- Helpers encode repetitive or fragile mechanics that keep regenerating literal approvals.
- `host_executable()` is a rules-layer hardening tool, not a helper-gap fix. Use it to strengthen a small set of trusted basename command families, not to excuse shell wrappers or broad literal growth.
- Repo-scoped helper gaps should usually flow back to repo-local owners; host-level cross-repo gaps should usually flow back to personal skills.
- Do not solve helper gaps by permanently widening `default.rules` unless the widened argv shape is itself stable and intentionally reusable.

6. Record what changed.
- Update repo journals or a nearby focused note when the audit reveals a durable pattern, such as a new wrapper-drift family or a repeated helper gap.
- Capture the decision in a compact form: what drifted, why it drifted, and whether the fix belongs in rules, a helper, or a skill.

## Audit Cadence

- Run a light audit when `default.rules` grows noticeably after one burst of work, or when new lines clearly show `env ... bash`, `/bin/zsh -lc`, prompt-file wrappers, fixed `/tmp` paths, or other shell-shaped drift.
- Run a fuller audit roughly once a week, or after about `8-12` new rules accumulate since the last clean-baseline refresh or other successful full audit.
- If a cleanup just finished and the next growth immediately recreates a literal family, treat that as evidence of wrapper drift or a missing helper boundary, not as a reason to keep the literal forever.

## Guardrails

- Do not turn `default.rules` into a historical transcript of approvals.
- Do not add a broad stable prefix just because one literal was annoying to approve once.
- Do not jump into session mining first when the diff already explains the growth.
- Do not keep fixed issue ids, PR numbers, prompt files, review bundles, or task-scoped temp paths once their stable owner is known.

## References

- Use [references/audit-cadence.md](references/audit-cadence.md) for the lightweight/full-audit checklist and the classification examples.
