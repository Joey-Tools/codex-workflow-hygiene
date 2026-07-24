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

The helper emits one bounded schema-v2 JSON document. It scans optional
`session_index.jsonl` and `history.jsonl` records with a physical-record byte
cap. Exact-ID mode also inventories filenames under both rollout roots. Each
source reports `checked`, `unavailable`, or `partial`, total and retained
matches/errors, and deterministic truncation fields. `--limit` is enforced
during collection; it is not a final slice of an unbounded list.

Only `FileNotFoundError` classifies an optional index or root as
`unavailable`. A broken symlink, permission or I/O error, wrong type, path
escape, or failed revalidation is `partial`.

## Stability Contract

- Open every index with no-follow and nonblocking flags relative to one held
  `codex_home` directory descriptor. Capture its initial byte length and scan
  exactly that prefix.
- Rehash the same prefix from the original descriptor, reopen it relative to a
  freshly validated directory chain, and require byte identity plus stable
  device, inode, file type, owner, group, and permission bits.
- Report `captured_prefix_bytes`, `final_size_bytes`, `content_scope`, and
  `append_after_boundary`. A byte-identical prefix with a later append may stay
  `checked` as `stable-captured-prefix-with-later-append`; the appended records
  were not searched. Truncation, prefix mutation, rotation, replacement, or
  unreadable validation is `partial`.
- Open every component from the filesystem root through `codex_home` and each
  rollout root with descriptor-relative no-follow directory opens. Enumerate
  from held directory descriptors and never traverse symlinks.
- Before `checked`, reopen the full chain and require stable directory identity
  and access policy plus an unchanged bounded inventory of entry names, types,
  devices, and inodes. Inventory is capped at 100,000 entries; exceeding the
  cap is `partial`.

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
