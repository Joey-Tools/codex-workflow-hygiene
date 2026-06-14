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
- Archived rollout files under `archived_sessions/` are in scope, but archive or unarchive file mtimes must not define session time; use record timestamps, rollout filenames, or dated paths instead.
- Remote evidence must be collected through `$remote-host-context` preflight plus this skill's bundled `scripts/remote_codex_probe.py` bounded reads.
- Once remote rollout data is copied or summarized locally, use this skill's helper for extraction and aggregation.
- Each materialized default remote source root must include `source_metadata.json` with `host`, `status`, `window_start`, `window_end`, and `materialized_at`; missing or stale metadata is a coverage gap and blocks state advancement.
- Symlinked or root-escaping rollout and summary candidates are coverage gaps for every source type. Treat the whole source as stale for scan state and shard handoff even when other safe files exist in the same source root.
- Choose the scan `--end` timestamp before materializing remote evidence, use that same timestamp as the remote metadata `window_end`, and pass it to `scan-daily`, `scan-weekly`, or `baseline`.
- Opaque retained refs use a stable local HMAC key at `.codex-local/session-retrospective/opaque_ref_key` by default. Keep this key ignored and private; set `CODEX_SESSION_RETROSPECTIVE_KEY_FILE` or `CODEX_SESSION_RETROSPECTIVE_KEY` only when intentionally sharing the same private history root across workspaces.
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
python3 scripts/session_retrospective.py validate-history-commit --retained-run-dir .codex-local/session-retrospective/retained/20260522/daily --history-repo /path/to/codex-session-retrospective-history --history-commit <40-char-retained-export-commit-sha> --history-ref HEAD
python3 scripts/session_retrospective.py validate-history-tree --history-repo /path/to/codex-session-retrospective-history --history-ref HEAD
python3 scripts/session_retrospective.py advance-state --run-dir .codex-local/session-retrospective/runs/20260522/daily --retained-run-dir .codex-local/session-retrospective/retained/20260522/daily --state .codex-local/session-retrospective/state.json --history-repo /path/to/codex-session-retrospective-history --history-commit <40-char-retained-export-commit-sha> --history-ref HEAD
python3 scripts/session_retrospective.py scan-weekly --days 7 --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/weekly
python3 scripts/session_retrospective.py weekly-dry-run --days 7 --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/weekly-dry-run
python3 scripts/session_retrospective.py weekly-repair --run-dir .codex-local/session-retrospective/runs/20260522/weekly-dry-run --output .codex-local/session-retrospective/runs/20260522/weekly-coverage-repair
python3 scripts/session_retrospective.py baseline --window-days 90 --from first --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/baseline
python3 scripts/session_retrospective.py baseline-dry-run --window-days 90 --from first --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/baseline-dry-run
python3 scripts/session_retrospective.py repair-coverage --run-dir .codex-local/session-retrospective/runs/20260522/baseline-dry-run --output .codex-local/session-retrospective/runs/20260522/baseline-coverage-repair
python3 scripts/session_retrospective.py validate-output --run-dir .codex-local/session-retrospective/runs/20260522/weekly
python3 scripts/session_retrospective.py export-retained --run-dir .codex-local/session-retrospective/runs/20260522/weekly --output .codex-local/session-retrospective/retained/20260522/weekly
python3 scripts/session_retrospective.py validate-retained --run-dir .codex-local/session-retrospective/retained/20260522/weekly
```

Use `scripts/remote_codex_probe.py` only for read-only remote materialization after `$remote-host-context` identifies the same default host scope. Keep its output in task-scoped ignored directories and pass the materialized roots back through `--source HOST=PATH`; do not let extractor subagents connect to remote hosts directly.
When `remote_codex_probe.py session-meta` hits the 500-row safety cap for a busy date, rerun it with `--auto-split` so the helper retries bounded rollout filename windows; use explicit `--rollout-start` / `--rollout-end` only when manually materializing a known subwindow. Do not treat that overflow as host unreachable.

Use `weekly-dry-run` for ordinary weekly rehearsal and `baseline-dry-run` for historical baseline rehearsal before retained export. Both commands run the scan, validate the transient output, run `make-shards`, and write `dry_run_report.json` plus `dry_run_report.md`; they deliberately do not run `export-retained`, commit to history, or call `advance-state`. If a weekly dry run reports repairable coverage gaps, use `weekly-repair --run-dir <weekly-dry-run-dir>` or rerun `weekly-dry-run --repair` for a combined transient follow-up. If a baseline dry run reports repairable coverage gaps, use `repair-coverage --run-dir <baseline-dry-run-dir>` to rematerialize the default remote hosts with `remote_codex_probe.py session-meta --auto-split`, rerun the scan with a larger raw limit, rerun shard planning, and write `repair_report.json` plus `repair_report.md`. Direct repair commands use conservative bounded concurrency by default: `--remote-host-jobs 2 --remote-rollout-jobs 2`, capped at `8`; pass `1` to either option for serial behavior. For `weekly-dry-run --repair`, use the matching nested flags `--repair-remote-host-jobs` and `--repair-remote-rollout-jobs`. These repair steps are still transient-only and do not create retained history artifacts.
Use `discover` before map-reduce shard work. `make-shards` only emits sources marked `ready` by the transient manifest; stale, missing, empty, or otherwise non-ready sources stay as coverage gaps and must not be handed to extractor subagents. Add `--include-raw-paths` only for local extractor dispatch inside ignored `.codex-local/session-retrospective` run directories; never retain or commit `shards.jsonl`. `scan-*` remains the compact local extraction path for bounded windows and final retained outputs.
If a relevant raw rollout exceeds `--max-raw-bytes`, generate or use a complete bounded `rollout-summary*.jsonl` that carries safe relative `rollout` backing refs plus `scan_meta` proving `scan_truncated=false`, `json_error_count=0`, no keyword filter, no signal/match/tail record limit, a valid `summary_limit`, and `source_bytes` matching the current backing rollout file size; complete summary-backed oversized rollouts should flow through the summary and not remain as `oversized_rollout_skipped` gaps. Trusted local generated summaries use their own bounded summary cap for scan and shard handoff; for those manifest-listed generated files only, `tail_record_limit_reached=true` may still be accepted when full scanning completed and no keyword/signal/match limits fired, because omitted non-signal tail records are not extractor evidence. Ordinary truncated, stale-source, parse-error, keyword-filtered, record-limited, invalid, oversized, or unbacked summaries still remain coverage gaps.
For local sources, `scan-*` and `discover` may automatically write bounded generated summaries under an ignored `.codex-local/session-retrospective/*-generated-rollout-summaries/` sibling, or under `generated-rollout-summaries/` when the output itself is `.codex-local/session-retrospective`, and reference that root plus the exact per-run generated file list only from the transient manifest. `make-shards` must consume that exact list rather than globbing the whole generated directory, so repeated runs do not hand stale generated summaries to extractor planning. A source-tree `rollout-summary*.jsonl` that carries `coverage_proof=local_generated_rollout_summary_v1` is still an ordinary source summary unless it is in the current transient manifest's generated list. Local generated summaries must preserve canonical local active-mtime fallback semantics, continue using `source_sha256` for stale-source checks even when manifest-listed `tail_record_limit_reached=true` is allowed, and scan full text for retained signal labels using bounded chunks, not head/tail-only sampling. Do not retain that directory or treat it as a source-of-truth copy of the raw rollout.
Pass repeated `--source HOST=PATH` values when remote evidence has been materialized locally. `PATH` may be a Codex home containing `sessions/` or a task-scoped directory containing copied `rollout-*.jsonl` files. Retained host labels are restricted to `local`, the two default remote hosts, and `custom_source`; any other `HOST` label is bucketed as `custom_source` before retained artifacts are written.
`scan-daily --state` reads the last completed scan but does not advance it, and refuses to rescan when the state already covers the requested `--end`. Run `advance-state` only for the same daily run dir and retained export after `validate-output`, `export-retained`, `validate-retained`, `validate-history-commit --history-ref HEAD`, and final `validate-history-tree --history-ref HEAD` pass. Pass the history repository with `--history-repo`, the dedicated retained-export commit SHA with `--history-commit`, and the final audited history ref with `--history-ref HEAD`; `advance-state` verifies the retained export commit, requires the audited ref to resolve to the current history worktree `HEAD`, revalidates the final history tree, and confirms the same retained export still exists unchanged at the same path before moving the scan cursor. Commit reports, schemas, indexes, or annotations separately from the state-advancing retained export commit, then rerun `validate-history-commit --history-ref HEAD` and `validate-history-tree` after those follow-on commits and before `advance-state` or reporting weekly/baseline history success.
Do not run `scan-*`, `discover`, or `make-shards` output directly into a tracked repository path unless that path ignores `.codex-local/`; those commands write transient execution artifacts. `export-retained` is the safe path for materializing files that may be copied into or written inside the private history worktree.

## Output Contract

- `turn_summaries.jsonl`: transient redacted meaningful turns plus flags and source pointers. Do not retain in history.
- `episodes.jsonl`: episode/topic summaries with retained host bucket, session, cwd/repo hints, outcome, and friction flags.
- `trend_report.json`: aggregate counts by retained host bucket, model era, issue flag, and scan window.
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
