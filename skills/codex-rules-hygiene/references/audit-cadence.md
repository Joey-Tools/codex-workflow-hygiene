# Rules Audit Cadence

## Mode Contract

- `audit` is read-only. It may resolve existing anchors, diff, classify, and propose an exact apply plan, but it never creates a backup, rewrites rules, refreshes a baseline, or updates a journal.
- `apply` is writable only when cleanup is requested or an audit has proved an exact change that the active task authorizes. It revalidates the audited inputs before writing.
- If apply has no approved content change, report a no-op and create nothing.

## Default Rhythm

- Prefer a light audit after one burst of work when `~/.codex/rules/default.rules` clearly gained shell-shaped literals.
- Prefer a fuller audit about once a week, or when roughly `8-12` new rules have accumulated since the last clean-baseline refresh or other successful full audit.
- If the file grows again immediately after a cleanup, treat that as a workflow-design signal rather than as proof that the deleted literal was actually durable.
- Treat `~/.codex/rules/default.rules.clean-baseline` as the canonical clean anchor after a successful full cleanup.
- If that clean-baseline file does not exist yet, treat the latest timestamped backup as the temporary comparison fallback rather than pretending a clean anchor exists.
- If neither anchor exists yet, enter a cold-start bootstrap: create one safety backup, do not diff against that freshly created backup, and treat the current file as the initial inventory to clean.

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
7. Emit an exact apply plan or a read-only no-change result. Do not back up, rewrite, refresh the baseline, or journal from audit mode.

## Full Audit Checklist

1. Diff against `~/.codex/rules/default.rules.clean-baseline` when it exists; otherwise use the previous timestamped backup as a first-pass fallback. If neither anchor exists yet, switch to the cold-start bootstrap instead of pretending a comparison baseline exists.
2. Group additions by workflow family rather than by literal string.
3. Propose the narrowest stable prefix that still covers each recurring workflow.
4. Identify obsolete literals already replaced by helpers or skills.
5. State whether the proposed full cleanup would be eligible to refresh `default.rules.clean-baseline`.
6. List any durable observation that would require a journal or focused-note update if adopted.
7. Remain read-only until apply mode is authorized.

## Apply Checklist

1. Re-read `default.rules` and the selected comparison anchor; stop if either differs from the audited inputs. Identify the existing policy validator, and stop before backup or rewrite if no trustworthy validation gate can be named and run.
2. If no content change remains, report a no-op and create nothing.
3. Create one timestamped safety backup before rewriting.
4. Rewrite only the reviewed entries and run the identified validator against the resulting policy.
5. Refresh `default.rules.clean-baseline` only after a successful full cleanup with no intentionally retained drift debt.
6. Write the necessary adopted-journal or focused-note update only for a durable decision actually applied or a successful full-cleanup baseline refresh. Use an existing owning-repo journal when already adopted; otherwise use a nearby focused note rather than bootstrapping a tracker.
7. Never treat the new safety backup as the comparison anchor for the same apply.

## Cold-Start Bootstrap

Use this branch only when a machine has neither `~/.codex/rules/default.rules.clean-baseline` nor any older `default.rules.bak-*` snapshot.

In audit mode:

1. Treat the current `default.rules` as the bootstrap inventory and classify it directly.
2. Produce an exact full-cleanup plan.
3. Do not create the safety backup or clean baseline.

In apply mode:

1. Revalidate the audited bootstrap inventory.
2. Create one timestamped safety backup.
3. Do not diff against that freshly created backup.
4. Apply and validate the reviewed full cleanup.
5. Only after that full cleanup succeeds, create `~/.codex/rules/default.rules.clean-baseline`.

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
