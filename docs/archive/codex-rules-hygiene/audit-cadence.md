# Rules Audit Cadence

> Frozen historical companion to the retired Codex Rules Hygiene workflow. It is not a current supported procedure.

## Default Rhythm

- Prefer a light audit after one burst of work when `~/.codex/rules/default.rules` clearly gained shell-shaped literals.
- Prefer a fuller audit about once a week, or when roughly `8-12` new rules have accumulated since the last clean-baseline refresh or other successful full audit.
- If the file grows again immediately after a cleanup, treat that as a workflow-design signal rather than as proof that the deleted literal was actually durable.
- Treat `~/.codex/rules/default.rules.clean-baseline` as the canonical clean anchor after a successful full cleanup.
- If that clean-baseline file does not exist yet, treat the latest timestamped backup as the temporary comparison fallback rather than pretending a clean anchor exists.
- If neither anchor exists yet, enter a cold-start bootstrap: create one safety backup, do not diff against that freshly created backup, and treat the current file as the initial inventory to clean.

## Light Audit Checklist

1. Resolve the comparison baseline: prefer `~/.codex/rules/default.rules.clean-baseline`, otherwise fall back to the latest timestamped backup; if neither anchor exists yet, stop the light audit here and switch to the cold-start bootstrap below.
2. Back up the current rules file before deleting or rewriting anything.
3. Inspect only the added lines.
4. Label each new line:
   - `stable prefix`
   - `wrapper drift`
   - `helper gap`
   - `approval log`
5. Remove obvious approval-log literals.
6. If one workflow family drifted because of `env ...` or shell wrappers, note that family for helper or invocation cleanup.
7. If a `helper gap` appears, decide the owner before ending the audit:
   - repo-local skill/helper when the drift is tied to one repo's scripts or policy
   - personal skill/helper when the drift is host-level and cross-repo
   - [codex-skill-authoring](../../../skills/codex-skill-authoring/SKILL.md) when the owner or instruction layer is unclear

## Full Audit Checklist

1. Back up the current rules file.
2. Diff against `~/.codex/rules/default.rules.clean-baseline` when it exists; otherwise use the previous timestamped backup as a first-pass fallback. If neither anchor exists yet, switch to the cold-start bootstrap instead of pretending a comparison baseline exists.
3. Group additions by workflow family rather than by literal string.
4. Collapse retained rules back to the narrowest stable prefix that still covers the recurring workflow.
5. Delete obsolete literals that were replaced by helpers or skills.
6. Refresh `~/.codex/rules/default.rules.clean-baseline` from the rewritten `default.rules` only after the cleanup result is good enough to serve as the next clean anchor.
7. Record any durable observation in project journals or a focused note, including when the clean-baseline file was last refreshed.

## Cold-Start Bootstrap

Use this branch only when a machine has neither `~/.codex/rules/default.rules.clean-baseline` nor any older `default.rules.bak-*` snapshot.

1. Create one timestamped backup of the current rules file for safety.
2. Do not diff against that freshly created backup.
3. Treat the current `default.rules` as the bootstrap inventory and classify the file directly.
4. Run a full cleanup pass from that inventory.
5. Only after that full cleanup succeeds, refresh `~/.codex/rules/default.rules.clean-baseline`.

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
- If ownership or layering is unclear, route that decision through [codex-skill-authoring](../../../skills/codex-skill-authoring/SKILL.md) instead of solving it by widening rules.
- Prefer fixing examples and helper interfaces before inventing broader rules.
