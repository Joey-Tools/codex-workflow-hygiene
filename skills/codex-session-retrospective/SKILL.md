---
name: codex-session-retrospective
description: Run read-only Daily, Weekly, Baseline, or single-session Codex collaboration retrospectives across Joey's canonical local and remote host set, with bounded subagent map-reduce, redaction, episode/topic and turn-level review, coverage proof, and append-only private history publication.
---

# Codex Session Retrospective

## Scope

Use this skill when Joey asks to review one Codex task, a daily or weekly period,
a historical baseline, collaboration trends, difficult prompts, or repeated
workflow friction.

Source scope is the complete canonical role set supplied by
`$remote-host-context`. Codex history and remote hosts are read-only. Archived
sessions are in scope, but archive/unarchive time and filesystem mtime never
redefine event time, session identity, or episode boundaries.

## Main Workflow

The only supported installed coordinator is
`~/.codex/skills/codex-session-retrospective/scripts/session_retrospective_v2.py`.
Do not invoke the migration-only v1 helper for a v2 run.

1. Run the installed v2 coordinator's `doctor` command and require the
   configured identity, policy, history, and transport contracts to match.
2. Start one immutable `daily`, `weekly`, `baseline`, or `session` run.
3. Repeat the machine-readable coordinator loop. Execute rollout leases only
   through `$remote-host-context session-shards`:

```text
status
execute every leased source action through remote-host-context
accept every source result
spawn the maximum available native ephemeral subagent wave
accept every completed agent result
advance
```

4. Stop model work when `status` reports the run exportable, then run `export`.
   Use `--prior-history` for the latest verified signed publication, or supply
   `--prior-period` with one exact retained bundle when an operator-selected
   compatible trend comparison is required.
5. For shadow runs, verify the non-publishable bundle and cleanup receipts. For
   production runs, repeat parameterless `finalize` until the durable history
   transaction, provider derivation, and cleanup are complete.
6. Report explicit source, extraction, review, publication, and verification
   gaps. Never infer completeness from an absent error.

Joey triggers one retrospective task. The automation coordinator owns this loop
and does not ask Joey to invoke individual stages.

Keep verbose command output in a task-scoped ignored log and surface only
progress markers. Use `pgrep -af` and `ps -p` for narrow process checks; do not
use broad `ps -eo` / `ps -axo` or full `sample` output.
For polling, do not poll with 30k+ visible output caps.

## Resource Loading

Read only the reference needed for the current stage:

- [v2-cli.md](references/v2-cli.md): CLI and coordinator loop.
- [v2-agent-prompts.md](references/v2-agent-prompts.md): native subagent jobs.
- [v2-data-contract.md](references/v2-data-contract.md): source, shard, and
  retained contracts.
- [v2-engine-architecture.md](references/v2-engine-architecture.md):
  deterministic module boundaries, complexity inventory, and architecture
  guards.
- [v2-recovery.md](references/v2-recovery.md): retries, expiry, key mismatch, and
  publication recovery.
- [v2-shadow-cutover.md](references/v2-shadow-cutover.md): calibration, shadow
  gate, cutover, and baseline.

The references are normative for agent isolation, retention, publication,
privacy, recovery, and cutover. During migration, v1 is comparison-only; do not
add v1 behavior or use it to publish a v2 run.
