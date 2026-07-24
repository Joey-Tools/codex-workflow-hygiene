---
name: codex-session-mining
description: Locate exact Codex sessions or build a complete active-plus-archived session corpus from the user's local `~/.codex` history. Use the lightweight `locate` path for a session/thread ID, recent thread, or narrow index lookup; use the `corpus` path for date-window audits, replay-prefix handling, repeated workflow analysis, or claims of complete current-host coverage. Combine with the environment's remote-host evidence workflow when relevant sessions may live on another host.
---

# Codex Session Mining

Treat session history as evidence, not as current repository truth. Select the
lightest profile that can answer the question.

## `locate`: Exact Or Narrow Lookup

Use `locate` for an exact session ID, thread-name fragment, or recent-thread
orientation.

1. Query `session_index.jsonl` and `history.jsonl` through
   `scripts/locate_session.py`.
2. For an exact session ID, also inspect rollout filenames under both existing
   `sessions/` and `archived_sessions/` roots.
3. Open only the selected rollout files. Parse record shapes and selected fields;
   never print raw JSONL matches or whole retained tool outputs.
4. Report source coverage and whether output matches were truncated.

Read [references/locate.md](references/locate.md) for the helper interface and
safe extraction rules.

## `corpus`: Complete Current-Host Evidence

Use `corpus` when the request covers a date range, all sessions, replay/fork
deduplication, or repeated workflow friction.

1. Run `scripts/build_session_corpus.py` against a fresh nonexistent output
   directory.
2. Inventory both active and archived roots before filtering by record or
   lifecycle timestamps.
3. Treat the helper as a full-root scan even for a narrow requested window.
4. Use `corpus.jsonl` as a locator for accepted line ranges, not as transcript
   output.
5. Separate replayed prefixes from genuine later human suffixes before counting
   activity.
6. Treat timeout, interruption, inventory drift, malformed committed records, or
   unsafe paths as incomplete coverage.

Read [references/corpus.md](references/corpus.md) before running or interpreting
the corpus helper.

## Remote Composition

If relevant evidence may be on another host, let the environment's
remote-host evidence workflow select hosts, perform read-only transport, and
report `checked`, `unavailable`, `partial`, or `blocked` coverage. This skill
owns local lookup and interpretation after remote evidence is materialized. Do
not duplicate host lists or transport logic here.

## Shared Guardrails

- Keep the workflow read-only unless the user explicitly asks to modify
  `~/.codex`.
- Filter injected AGENTS/skill/environment wrappers, automation boilerplate,
  child-agent prompts, and review prompts before reconstructing human intent.
- Preserve later genuine human follow-ups even when a rollout begins with
  wrapper noise or a replayed prefix.
- Bound every emitted field and row count. A structured parser can still produce
  unbounded output.
- Tie conclusions to exact session IDs, source paths, timestamps, and coverage.
- Once a session points to a live repository, PR, file, or remote artifact, use
  that source for the underlying technical fact.
