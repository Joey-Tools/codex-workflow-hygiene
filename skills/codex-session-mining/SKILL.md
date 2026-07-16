---
name: codex-session-mining
description: Search the user's `~/.codex` active and archived session/history artifacts to recover prior work, audit recent activity, find rollout files by session ID or date, or summarize repeated workflow issues. Use when the task depends on `session_index.jsonl`, `history.jsonl`, `sessions/**/rollout-*.jsonl`, `archived_sessions/**/rollout-*.jsonl`, or a complete current-host session corpus; pair with an environment-specific remote evidence workflow when remote-host evidence may matter.
---

# Codex Session Mining

## Overview

Use this skill when the source of truth is the user's local Codex history rather than the current repository. The goal is to find the smallest relevant transcript set, extract selected evidence, and avoid brittle assumptions about old path layouts.

## When To Use

Use this skill for:

- Recovering prior work, prior commands, or values from a recent Codex turn, including requests such as "read your rollout".
- Mapping a session ID, thread ID, date window, repo/cwd, or user phrasing to canonical rollout files.
- Auditing recent activity, repeated workflow friction, skill trigger misses, review-lane behavior, approval/auth friction, or command-shape problems.
- Building a complete current-host corpus across active and user-archived sessions.

## Canonical Data Sources

- `~/.codex/session_index.jsonl` for fast lookup by session ID, thread name, and sometimes path hints.
- `~/.codex/history.jsonl` for higher-level prompt or thread recovery when the exact rollout file is not known yet.
- `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` for active transcript rollouts on the local machine.
- `~/.codex/archived_sessions/**/rollout-*.jsonl` for user-archived rollouts when that root exists; current hosts may use either flat or date-nested archive layouts.
- Session-derived retained or report JSONL artifacts, such as retrospective `turn_flags.jsonl`, when the user explicitly scopes the task to those artifacts instead of raw rollouts.

## Workflow

1. Scope the lookup.
- Decide whether the request is keyed by exact session ID, date window, repo/cwd, user phrasing, or a workflow pattern such as "skill friction in the last day."
- For "all sessions," recent-activity, date-window, or workflow-friction audits, inventory both `~/.codex/sessions/` and `~/.codex/archived_sessions/` when they exist and build one union corpus before classifying evidence.
- If the task might depend on remote-host evidence, let an environment-specific remote evidence workflow materialize remote rollout candidates locally before concluding that local history is complete.

2. Locate the smallest file set before reading content.
- For an exact session ID or thread ID, start with `session_index.jsonl`, `history.jsonl`, or a filename search under both existing transcript roots for `rollout-*<id>*.jsonl`; do not append either rollout tree to the same raw `rg` command.
- When the user asks to "read your rollout", recover prior commands, or find a value from a recent Codex turn, treat it as a session lookup first. Do not start with keyword `rg -n` over all of `$CODEX_HOME` / `~/.codex`; that tree includes history/session JSONL, retained tool outputs, installed skills, release overlays, caches, and package payloads. First identify a candidate session or date-bounded rollout set, then parse selected fields.
- For a bounded date range, inventory every rollout under both existing active and archived roots first, including flat and date-nested archive layouts, then filter the union by record or lifecycle timestamps. A rollout in either root may have an old dated path or filename but a later genuine continuation inside the requested window.
- Use `scripts/build_session_corpus.py` for a complete current-host date-window audit. It writes per-root candidate, parsed, and accepted path lists plus a deduplicated `corpus.jsonl`; each union entry identifies compact accepted line ranges after replay-prefix removal so a restamped copy cannot turn old history into new evidence.
- Do not trust `find -mtime` as the only date filter when precision matters; copies, indexing, or later metadata updates can give older rollout files a fresh mtime.
- Verify which transcript roots and archive layouts exist on the current host instead of assuming `archived_sessions` is either present or obsolete.

3. Extract only the records and fields needed for the question.
- Before printing details from a large rollout, count record shapes or line count, then add an explicit selector and row cap.
- Treat `corpus.jsonl` as a locator, not transcript output: inspect its accepted line numbers and a small amount of necessary nearby context instead of printing every accepted rollout.
- Use `session_meta` and `turn_context` for `cwd`, date, model, sandbox, and approval context.
- Use `response_item` messages for user intent, assistant decisions, and explicit skill mentions.
- Use `function_call_output` and tool error lines when auditing failures, approval friction, or outdated helper guidance.
- When inferring user intent, filter out wrapper-only user messages that mirror injected context rather than real requests. In the current rollout format, common noise includes leading `# AGENTS.md instructions ...`, pasted `<skill>` blocks, `<environment_context>`, `<subagent_notification>`, and repeated `# Review findings:` payloads.
- Do not treat skill names that appear only inside those wrappers or pasted `SKILL.md` bodies as proof that the skill was actually invoked or even relevant to the user's real request.
- When a session continues another thread, pick the first meaningful user request after that wrapper noise instead of blindly classifying the first user message.
- Exclude automation boilerplate and synthetic child, subagent, or external-review prompts from the reconstructed user task, but do not discard a main rollout solely because it began with an automation wrapper; keep later genuine human follow-ups in that same thread.
- Use `event_msg` only when aborts, retries, or mode changes matter.
- Before counting records as new activity, check whether a resumed, forked, compacted, or restored rollout copied and restamped earlier history into the current file. A strict record-timestamp filter is not sufficient for these rollouts.
- Treat an implausibly dense burst, repeated `session_meta` / `task_started` boundaries, old PR or task references reappearing at nearly identical timestamps, and thousands of historical tool calls emitted within seconds as replay signals.
- Establish the latest genuine resume boundary from bounded `session_meta`, `turn_context`, `task_started`, and nearby `event_msg` user records. Deduplicate only the replayed prefix against earlier source history or stable record fingerprints; keep later human follow-ups in the same rollout.
- Across active and archived roots, group candidates by lifecycle session ID when available and compare ordered stable record fingerprints. Collapse only byte-identical copies or matching replay prefixes; retain every distinct suffix, especially later genuine human follow-ups. Do not deduplicate by basename alone.

4. Classify before proposing a skill or `AGENTS.md` change.
- Separate one-off mistakes from repeated patterns across multiple sessions.
- For skill audits, classify each issue as a trigger miss, outdated path or command example, approval/auth friction, missing guardrail, or repeated workflow that deserves its own personal skill.
- Prefer changing the smallest layer that fixes the pattern: `AGENTS.md` for terse cross-repo policy, `SKILL.md` for workflow/decision logic, `references/` for long command recipes.

5. Report compactly.
- Quote or summarize only the decisive lines.
- Keep the evidence tied to exact session IDs, dates, or file paths so the conclusion is auditable.
- If the evidence is inconclusive, say which narrower search or missing host would resolve it fastest.

## Guardrails

Keep the work read-only unless the user explicitly asks to modify `~/.codex`.

## High-Risk Patterns

- Do not dump full JSONL files into the answer when a few key lines will do.
- Do not dump full per-record inventories of large rollout files; a structured `jq` command can still produce tens of thousands of tokens if it emits every timestamp or tool call.
- Do not use `jq select(tostring | contains(...))` as a shortcut on rollout/history records; it is still a whole-record search and can surface giant nested `function_call_output` payloads. For keyword probes, filter by record type and field first, then emit only an explicit short snippet.
- Do not use JSONL schema probes that print keys for every record. Count lines and inspect one record, or aggregate unique keys once per file; do not run a per-line key dump such as `jq -R 'fromjson | keys' file.jsonl`.
- Do not use `sed`, `head`, or raw `rg -n` as an orientation step on rollout/history JSONL records; the first few records often contain full instructions, and a keyword hit can print a whole nested tool output. Count record shapes or emit selected JSON fields instead.
- Do not scan all of `~/.codex` when the task is already bounded by session ID, repo, or date.
- Do not point raw `rg -n` at the whole `$CODEX_HOME` / `~/.codex` tree. If the exact session is unknown, use `session_index.jsonl`, `history.jsonl`, bounded `sessions/YYYY/MM/DD` directories, `rg -l`, counts, or a JSON extractor before printing snippets.
- Do not combine `session_index.jsonl`, `history.jsonl`, and `~/.codex/sessions` in one raw `rg`; if the ID appears inside a nested tool output, the match can dump an entire rollout JSON record back into context.
- For broad keyword, prompt-shape, or review-lane searches in `history.jsonl`, `session_index.jsonl`, `sessions/**/rollout-*.jsonl`, or `archived_sessions/**/rollout-*.jsonl`, use `rg -l` / counts to find candidate files, then parse JSON and print selected fields plus short snippets.
- Broad raw `rg` across transcript JSONL is a trap: it easily matches injected `AGENTS.md`, `<skills_instructions>`, pasted `SKILL.md` bodies, or huge nested `function_call_output` blobs and can create false skill hits or bury the decisive lines. `--max-count` / `-m` only limits matches per file, not total output.
- Do not count a copied or restamped replay prefix as new friction merely because its outer record timestamps fall inside the audit window. Report replay volume separately from genuinely new records.
- Do not treat `archived_sessions` as a stale export root when the current host contains it, and do not claim an all-session audit is complete until both existing transcript roots were inventoried.
- Do not confuse local transcript evidence with current repo truth; once the session points to a live file, repo, or remote artifact, that source becomes authoritative for the underlying technical question.
- Do not silently mix local-only conclusions into tasks that may need remote-host coverage.
- Do not recreate a second remote-access workflow here; this skill owns local extraction and interpretation after remote evidence is materialized.

## References

- Use [references/workflow.md](references/workflow.md) for concrete lookup patterns and extraction recipes.
