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
2. Carry forward the exact audited `default.rules` SHA-256 digest, candidate bytes, selected comparison anchor, and existing policy validator. Stop before backup or replacement if any input is missing.
3. If no content change remains, report a no-op and create nothing.
4. Require all legitimate writers to share the transaction lock. If a rules writer cannot honor that advisory-lock protocol, prove it quiescent for the complete compare/replace/post-validation window or stop.
5. Put the reviewed bytes in a task-scoped candidate source and run the skill-relative helper:

```bash
RULES_HYGIENE_SKILL="<loaded-codex-rules-hygiene-dir>"
python3 "$RULES_HYGIENE_SKILL/scripts/apply_rules_transaction.py" apply \
  --candidate "$TASK_DIR/default.rules.candidate" \
  --expected-sha256 "$EXPECTED_RULES_SHA256" \
  --backup-name "default.rules.bak-$TIMESTAMP" \
  --receipt "$TASK_DIR/rules-apply-recovery.json" \
  -- <validator-argv> '{rules}'
```

6. The helper derives `rules/default.rules` and `.default.rules.apply.lock` from `CODEX_HOME`, with the ordinary Codex home as the fallback. Pass validator arguments directly; the helper replaces the one exact `'{rules}'` argument with first the private candidate path and then the live path. Do not wrap the validator in `bash -lc`.
7. Accept only `applied`, `no_change`, or `no_change_after_lock` as successful apply outcomes. `post_replace_failed_rolled_back` means the requested cleanup did not apply. `recovery_required` means the helper observed missing, unreadable, or property-mismatched live state and deliberately refused to overwrite it.
8. Keep the receipt and bound backup until post-replace checks and any required recovery decision finish. To retry the identity-bound rollback:

```bash
python3 "$RULES_HYGIENE_SKILL/scripts/apply_rules_transaction.py" recover \
  --receipt "$TASK_DIR/rules-apply-recovery.json"
```

9. Refresh `default.rules.clean-baseline` only after a successful full cleanup with no intentionally retained drift debt.
10. Write the necessary adopted-journal or focused-note update only for a durable decision actually applied or a successful full-cleanup baseline refresh. Use an existing owning-repo journal when already adopted; otherwise use a nearby focused note rather than bootstrapping a tracker.
11. Never treat the new safety backup as the comparison anchor for the same apply.

### Transaction Safety Boundary

- Candidate validity protects exact bytes: the helper copies the source into a `0700` staging directory, creates an owner-only, single-link regular file with mode `0600`, validates it there, and rejects any validator-side identity, content, or access-policy change before publication.
- Compare-and-replace protects three live properties under one shared lock: object identity (`device`, `inode`), content (`size`, SHA-256), and access policy (`uid`, `gid`, permission bits). Modification times are not treated as policy mutation when those selected properties remain stable.
- The receipt also binds the rules-parent object identity. The helper refuses nonzero file flags or extended attributes because it cannot preserve them; callers must separately prove that platform ACLs are absent when ACL state is not exposed through those checks.
- The expected SHA-256 digest binds apply to the audited bytes. Missing, unreadable, wrong-type, digest-mismatched, identity-replaced, content-mutated, and access-policy-changed states remain distinct outcomes.
- `os.replace` provides same-filesystem atomic name replacement, not a kernel compare-and-swap. The no-lost-update guarantee therefore requires every legitimate writer to honor the same persistent lock; a writer that ignores it is outside the helper's enforcement boundary.
- Automatic rollback and `recover` both require live rules to match the receipt's installed identity, content, and access policy and require the backup to match its bound identity, content, and access policy. A later replacement is preserved and reported, never overwritten merely because recovery was requested.

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
