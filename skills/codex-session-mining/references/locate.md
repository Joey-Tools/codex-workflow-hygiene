# Locate Profile

Use this profile for one exact session/thread lookup. It is not evidence that a
date window or host corpus is complete.

## Helper

Exact session ID:

```bash
python3 <loaded-skill-dir>/scripts/locate_session.py \
  --codex-home "${CODEX_HOME:-$HOME/.codex}" \
  --session-id <session-id> \
  --limit 20
```

Thread-name or prompt-index fragment:

```bash
python3 <loaded-skill-dir>/scripts/locate_session.py \
  --codex-home "${CODEX_HOME:-$HOME/.codex}" \
  --thread-query <literal-fragment> \
  --limit 20
```

The helper emits one bounded JSON document. It scans optional
`session_index.jsonl` and `history.jsonl` records with a physical-record byte
cap. Exact-ID mode also inventories filenames under both existing rollout
roots. Each source reports `checked`, `unavailable`, or `partial`, total matches,
retained matches, and truncation.

Missing optional roots are `unavailable`, not empty failures. Malformed,
oversized, unreadable, or changing sources make the corresponding coverage
`partial`; do not call the lookup complete without reporting that status.

## Open A Selected Rollout

Before reading content:

1. Count record shapes.
2. Select only relevant record types and fields.
3. Cap records and every emitted field.
4. Escape control characters before terminal output.

Useful shapes include:

- `session_meta` and `turn_context` for cwd, model, sandbox, and approval
  context;
- `response_item` messages for human intent and assistant decisions;
- `function_call_output` for a specific known failure; and
- `event_msg` only when abort, retry, or mode-transition evidence matters.

Do not use raw `rg -n`, `sed`, `head`, `jq tostring`, or per-record key dumps on
rollout JSONL. Locate candidate files first, then parse selected fields.

## Intent Reconstruction

Ignore wrapper-only messages beginning with injected AGENTS instructions,
`<skill>`, `<environment_context>`, subagent notifications, or copied review
findings. Exclude automation and child/reviewer prompts from the human task, but
keep later genuine human follow-ups in the same rollout.
