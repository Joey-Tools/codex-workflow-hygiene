# Corpus Profile

Load this profile for complete current-host date-window or repeated-friction
analysis.

## Build

Use a fresh nonexistent task-scoped output directory:

```bash
python3 <loaded-skill-dir>/scripts/build_session_corpus.py \
  --codex-home "${CODEX_HOME:-$HOME/.codex}" \
  --start <inclusive-ISO-8601> \
  --end <exclusive-ISO-8601> \
  --output <fresh-output-directory> \
  --sample-limit 20
```

The helper inventories every rollout under both existing `sessions/` and
`archived_sessions/` roots before applying the time window. A rollout whose path
predates the window may contain a genuine later continuation. Budget runtime for
the complete roots, not the apparent width of the window.

The complete output includes per-root candidate and accepted path lists,
`manifest.json`, `corpus-paths.txt`, and `corpus.jsonl`. Treat `corpus.jsonl` as
a locator: use its owner/lifecycle IDs and accepted line ranges to open a small
amount of necessary transcript context.

## Completeness

Do not use output from a timed-out, interrupted, inventory-changed, malformed,
or unsafe-path run as a complete corpus. Before retrying a full-root producer,
prove the original process and descendants are quiescent and choose another
fresh output directory.

Do not recursively delete an uncertain failed-run path by pathname. Clean it
only with a trusted primitive that keeps parent and target identities bound
through deletion; otherwise retain the path and report it.

## Replay And Deduplication

- Group active and archived candidates by lifecycle identity when available.
- Normalize complete UUID aliases to lowercase; preserve opaque IDs exactly.
- Collapse byte-identical copies.
- For non-identical branches, remove only a proven matching replay prefix
  through the last matching assistant/tool execution record.
- Preserve matching or later human prompts after that boundary as possible
  genuine suffixes.
- Never deduplicate solely by basename, outer timestamp, cwd, model, or prompt
  text.
- Report replayed records separately from genuinely accepted activity.

## Friction Analysis

After replay handling, classify only decisive evidence:

- a clear trigger miss;
- repeated manual reconstruction of an existing helper;
- approval or authentication friction;
- outdated path or command guidance; or
- a repeated fragile workflow that justifies deterministic automation.

Prefer the smallest correction layer: short standing policy in `AGENTS.md`,
workflow and routing in `SKILL.md`, detailed contracts in `references/`, and
deterministic repeated logic in `scripts/`.
