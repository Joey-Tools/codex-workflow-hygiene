---
name: codex-session-retrospective
description: Run read-only retrospective analysis across local and remote Codex session history, using bounded map-reduce extraction, redaction, episode/topic aggregation, turn-level prompt improvement flags, and private history-ready reports.
---

# Codex Session Retrospective

## Overview

Use this skill when Joey wants to review how Codex collaboration went across one session, a daily/weekly window, or historical 90-day windows.
The workflow is read-only against Codex history and remote hosts. It produces redacted retrospective artifacts that can be committed to a private history repository.

## Evidence Scope

- Default host scope follows `$remote-host-context`: local machine, `miku-bot-dev`, and `hoteng-srv-01`.
- Local sources are `~/.codex/session_index.jsonl`, `~/.codex/history.jsonl`, and `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`.
- Remote evidence must be collected through `$remote-host-context` preflight plus `remote_codex_probe.py` bounded reads.
- Once remote rollout data is copied or summarized locally, use this skill's helper for extraction and aggregation.
- Each materialized default remote source root must include `source_metadata.json` with `host`, `status`, `window_start`, `window_end`, and `materialized_at`; missing or stale metadata is a coverage gap and blocks state advancement.
- Choose the scan `--end` timestamp before materializing remote evidence, use that same timestamp as the remote metadata `window_end`, and pass it to `scan-daily`, `scan-weekly`, or `baseline`.
- Never modify `~/.codex`, remote hosts, Apple Notes, or raw rollout files during retrospective collection.

## Workflow

1. Bound the scan first.
- Daily runs scan from the last completed run and also revisit active threads from the last 14 days so cross-day turns are not missed.
- Weekly runs scan the last 7 days across all default hosts.
- Historical baseline runs manually, from first observed Codex use to now, in 90-day windows and by observed model era when metadata is available.

2. Build a bounded map-reduce plan.
- Use `scripts/session_retrospective.py` to discover rollout files, emit host/source metadata, and produce compact JSONL summaries.
- Keep raw transcript access limited to extractor-redactor work. Later aggregation and review stages should consume redacted JSON only.
- Default to maximum practical subagent concurrency for independent shards. If runtime quota or SSH/IO limits block top concurrency, run the remaining shards in waves without changing output schema.

3. Extract and redact.
- Extract meaningful user turns, assistant outcomes, tool failure signals, approval/auth friction, missing verification, user corrections, safety/privacy flags, and prompt-improvement candidates.
- Ignore wrapper-only content such as injected `AGENTS.md`, skill bodies, environment context, synthetic review prompts, and automation boilerplate.
- Redact secrets, credentials, private URLs, emails, customer-like identifiers, and long proprietary-looking snippets before handing data to review agents or writing history artifacts.

4. Aggregate at two levels.
- Episode/topic level: group related turns by host, session/thread, cwd/repo hint, date, and topic.
- Turn level: retain flagged user prompts when a specific prompt likely caused confusion, rework, missing verification, or unsafe/noisy behavior.

5. Write history-ready artifacts.
- Use `export-retained` to create a history-safe retained directory, then commit only that retained export plus schemas or written reports to the private history repository.
- Treat `turn_summaries.jsonl`, `shard_manifest.json`, and `shards.jsonl` as transient execution artifacts. They may contain full retained turn rows or raw local paths and must not be committed.
- Do not commit raw rollout files, full prompts, source snippets, internal URLs, secrets, or unredacted tool output.
- Advance incremental scan state only after retained export validation passes and the private history commit succeeds.
- AGENTS/skill suggestions are recommendations only; this workflow does not directly edit rules, skills, Apple Notes, or Daily Work Report.

## Helper

Use `scripts/session_retrospective.py`:

```bash
python3 scripts/session_retrospective.py discover --mode weekly --start 2026-05-15T00:00:00Z --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/weekly
python3 scripts/session_retrospective.py make-shards --manifest .codex-local/session-retrospective/runs/20260522/weekly/shard_manifest.json --output .codex-local/session-retrospective/runs/20260522/weekly --max-raw-bytes 512000
python3 scripts/session_retrospective.py scan-daily --end 2026-05-22T00:00:00Z --state .codex-local/session-retrospective/state.json --output .codex-local/session-retrospective/runs/20260522/daily
python3 scripts/session_retrospective.py validate-output --run-dir .codex-local/session-retrospective/runs/20260522/daily
python3 scripts/session_retrospective.py export-retained --run-dir .codex-local/session-retrospective/runs/20260522/daily --output .codex-local/session-retrospective/retained/20260522/daily
python3 scripts/session_retrospective.py validate-retained --run-dir .codex-local/session-retrospective/retained/20260522/daily
python3 scripts/session_retrospective.py advance-state --run-dir .codex-local/session-retrospective/runs/20260522/daily --retained-run-dir .codex-local/session-retrospective/retained/20260522/daily --state .codex-local/session-retrospective/state.json --history-commit <40-char-history-commit-sha>
python3 scripts/session_retrospective.py scan-weekly --days 7 --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/weekly
python3 scripts/session_retrospective.py baseline --window-days 90 --from first --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/baseline
python3 scripts/session_retrospective.py validate-output --run-dir .codex-local/session-retrospective/runs/20260522/weekly
python3 scripts/session_retrospective.py export-retained --run-dir .codex-local/session-retrospective/runs/20260522/weekly --output .codex-local/session-retrospective/retained/20260522/weekly
python3 scripts/session_retrospective.py validate-retained --run-dir .codex-local/session-retrospective/retained/20260522/weekly
```

Use `discover` before map-reduce shard work. `scan-*` remains the compact local extraction path for bounded windows and final retained outputs.
Pass repeated `--source HOST=PATH` values when remote evidence has been materialized locally. `PATH` may be a Codex home containing `sessions/` or a task-scoped directory containing copied `rollout-*.jsonl` files.
`scan-daily --state` reads the last completed scan but does not advance it. Run `advance-state` only for the same daily run dir and retained export after `validate-output`, `export-retained`, and `validate-retained` pass and the retained export has been committed to private history; pass the resulting 40-character history commit SHA with `--history-commit`.
Do not run `scan-*`, `discover`, or `make-shards` output directly into a tracked repository path unless that path ignores `.codex-local/`; those commands write transient execution artifacts. `export-retained` is the safe path for materializing files that may be copied into or written inside the private history worktree.

## Output Contract

- `turn_summaries.jsonl`: transient redacted meaningful turns plus flags and source pointers. Do not retain in history.
- `episodes.jsonl`: episode/topic summaries with host, session, cwd/repo hints, outcome, and friction flags.
- `trend_report.json`: aggregate counts by host, model era, issue flag, and scan window.
- `shard_manifest.json`: transient bounded source manifest for map-reduce orchestration. Do not retain it in history.
- `shards.jsonl`: transient shard worklist for extractor-redactor scheduling. Do not retain it in history.
- `retained_manifest.json`: retention-safe manifest with raw path fields removed and opaque refs preserved.
- Retained export directory: contains only `episodes.jsonl`, `turn_flags.jsonl`, `trend_report.json`, and `retained_manifest.json`; `validate-retained` rejects any extra file or directory before commit.

## Guardrails

- Do not let subagents freely scan all of `~/.codex` or remote hosts.
- Do not treat wrapper-only user messages as real user intent.
- Do not silently drop remote hosts; report unreachable, stale, missing `~/.codex`, or oversized rollout gates.
- Do not store unredacted raw text in the private history repository.
- Do not turn one-off friction into AGENTS.md or skill changes without repeated evidence or a single high-signal safety issue.
