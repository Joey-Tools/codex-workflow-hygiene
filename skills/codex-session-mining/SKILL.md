---
name: codex-session-mining
description: Locate exact Codex sessions or threads and build bounded session corpora from the user's `~/.codex` history. Use the locate path for an exact session ID, thread ID, recent turn, or one canonical rollout; use the corpus path for active-plus-archived, date-window, replay-prefix, repeated-friction, or full current-host analysis. Compose with `$remote-host-context` when remote-host evidence may matter instead of copying host lists or access logic.
---

# Codex Session Mining

## Overview

Treat local Codex history as evidence, not as repository truth.
Choose one path before searching so an exact lookup does not become a corpus scan and a corpus claim does not omit archived or replayed history.

## Choose A Path

### Locate

Use `locate` for an exact session ID, thread ID, recent prior turn, "read your rollout", or one value/command recovered from a known conversation.

1. Start with the optional hints in `~/.codex/session_index.jsonl` and `~/.codex/history.jsonl`.
2. Search exact rollout filenames under both existing roots:
   - `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`
   - `~/.codex/archived_sessions/**/rollout-*.jsonl`
3. Treat missing, unreadable, malformed, or oversized index records as unavailable hints, not as proof that the rollout is absent.
4. Select the smallest candidate set, then parse only the fields and nearby records needed for the question.
5. Do not invoke `scripts/build_session_corpus.py` merely to resolve one exact ID or thread.

Read [the locate recipes](references/workflow.md#locate-path-find-the-canonical-rollout-file) before constructing an exact-ID, recent-turn, or bounded filename lookup.

### Corpus

Use `corpus` for recent activity, a date window, repeated skill friction, active/archive coverage, replay-prefix analysis, or a complete current-host corpus.

1. Use `scripts/build_session_corpus.py` with a fresh nonexistent output directory.
2. Inventory both existing active and archived roots before timestamp filtering; an old path can contain a genuine later continuation.
3. Budget the helper as a full-root scan, not as a requested-window scan. Give it a task-specific deadline based on previous runtime and current corpus scale.
4. Group candidates by lifecycle identity and ordered stable record fingerprints. Collapse only byte-identical copies or proved replay prefixes; retain distinct suffixes and later human follow-ups. Do not deduplicate by basename alone.
5. Treat timeout, cancellation, inventory change, oversized-record, replacement, truncation, or invalid committed JSON as an incomplete/failed snapshot, never as an empty corpus.
6. Before retrying, prove the original producer and descendants are quiescent and use a different fresh output directory. Follow the reference's identity-bound cleanup contract; otherwise leave a failed-run path untouched.
7. Use `corpus.jsonl` as a locator through its accepted line ranges, not as transcript output.

Read [the corpus recipes](references/workflow.md#corpus-path-build-the-current-host-union) before a date-window, replay-prefix, or full-corpus run.

## Compose Remote Coverage

- When the task may include work on remote hosts, load `$remote-host-context` before claiming local evidence is complete.
- Let that skill own the current host scope, reachability/authentication preflight, bounded remote transfer, and canonical host paths. Do not copy its host list or SSH recipes into this skill.
- After it materializes exact rollout evidence locally, use this skill for record selection, wrapper-noise filtering, replay handling, and task/friction classification.
- Preserve host provenance and report unavailable coverage. Do not silently convert a cross-host request into a local-only conclusion.

## Extract Shared Evidence

- Count record shapes or lines before details, then emit selected fields with explicit row and snippet caps.
- Use `session_meta` and `turn_context` for context, `response_item` for genuine user/assistant content, and tool outputs only when failures or approval friction matter.
- Filter injected `AGENTS.md`, pasted skill/environment blocks, automation boilerplate, and synthetic child/reviewer prompts before inferring user intent.
- In corpus work, detect copied/restamped history and the latest genuine resume boundary before counting activity. A strict record-timestamp filter is not sufficient.
- Never orient with raw `sed`, `head`, or `rg -n` output over rollout JSONL, and never point raw `rg` at all of `$CODEX_HOME` / `~/.codex`.
- Treat a live repository, remote artifact, or tracker identified by a session as authoritative for the underlying technical fact.

Read [the shared extraction recipes](references/workflow.md#shared-extraction) only after `locate` or `corpus` has selected bounded input.

## Classify And Report

- Separate one-off mistakes from repeated patterns.
- For skill audits, classify trigger misses, outdated commands/paths, approval/auth friction, missing guardrails, and repeated workflows.
- Prefer the smallest instruction layer: `AGENTS.md` for terse policy, `SKILL.md` for workflow decisions, and `references/` for detailed recipes.
- Report decisive evidence with exact session IDs, dates, paths, and coverage gaps.

## Guardrails

- Keep history work read-only unless the user explicitly authorizes modification.
- Do not dump full JSONL records or whole per-record inventories.
- Do not claim all-session coverage until the selected path and host scope actually support it.
