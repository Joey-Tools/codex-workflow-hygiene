# Locate Profile

Use this profile for exact lookup or bounded recent index orientation. It is not
evidence that a date window or host corpus is complete.

## Helper

```bash
python3 <loaded-skill-dir>/scripts/locate_session.py --session-id <session-id>
python3 <loaded-skill-dir>/scripts/locate_session.py --thread-query <fragment>
python3 <loaded-skill-dir>/scripts/locate_session.py --recent
```

Add `--codex-home <path>` or `--limit 1..100` when defaults do not fit.

The bounded schema-v2 selector kind is `session-id`, `thread-query`, or `recent`.
All modes scan both optional indexes with physical-record caps. Recent mode
retains newest records per source and never scans rollouts; UUID exact mode may
inventory both rollout roots, while opaque IDs remain index-only. Each source
reports coverage, total/retained matches and errors, and truncation. `--limit`
is enforced during collection, not applied after an unbounded list.

Index heaps normalize `updated_at` before `ts`, then use source path and physical
line as deterministic ties. Retained matches expose the finite bounded raw
timestamp scalar plus `ordering_timestamp_source` and `ordering_timestamp_utc`.
Out-of-range values remain auditable raw scalars but are absent from ordering.

Each index caps 250,000 records and 192 MiB of aggregate reads across the scan
and both prefix hashes. It rejects a three-pass prefix beyond that budget before
body reads and reports `index-byte-cap-exceeded` or
`index-record-cap-exceeded` as schema-v2 `partial`, never `checked`. Integers
beyond 32 digits, invalid constants, and other parse failures are malformed; later records remain eligible.
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
- Normalize timezone-aware ISO and numeric Unix timestamps to UTC for ordering.
  Invalid or out-of-range values are missing, never process-level failures.
- Open every component from the filesystem root through `codex_home` and each
  rollout root with descriptor-relative no-follow directory opens. Enumerate
  from held directory descriptors and never traverse symlinks.
- A rollout filename match requires the exact UUID in its terminal lifecycle
  position immediately before `.jsonl`; substrings, adjacent characters, and
  non-terminal UUIDs do not match.
- Before `checked`, reopen the full chain and require stable directory identity
  and access policy plus an unchanged bounded inventory of entry names, types,
  devices, and inodes. Inventory is capped at 100,000 entries; exceeding the
  cap is `partial`.
- Rollout traversal is additionally capped at depth 32, 250,000 aggregate
  ancestor-component references, and 16 MiB of aggregate component bytes.
  Exceeding any cap stops descent into that subtree and makes coverage
  `partial`; these aggregate budgets also bound repeated ancestor reopening.

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
