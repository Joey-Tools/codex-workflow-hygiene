---
id: 20260718-cwh001
title: JSONL Schema and Record Safety
status: completed
created: 2026-07-18
updated: 2026-08-16
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-jsonl-schema-record-bound
pr:
supersedes: []
superseded_by: 20260816-cwh007
---

# JSONL Schema and Record Safety

## Summary

- Bounded the broad index-keyword and aggregate schema recipes to 1 MiB binary physical records with fixed 64 KiB LF draining.
- Made broad index-keyword output source-fair with per-source collection caps, deterministic round-robin emission, and explicit scan metadata.
- Bounded aggregate schema discovery to 256 unique keys and 32 KiB under strict UTF-8 encoding, with deterministic truncation metadata and the same limits on the first-record projection.

## Current State

- Oversized records containing a bare CR cannot expose a JSON-like suffix as a separate history, session-index, or schema record.
- Broad index scans retain at most 20 matches per source, always inspect both public index sources, emit at most 20 matches round-robin, and append one fixed-shape record that distinguishes missing sources, per-source truncation, and global output truncation.
- Aggregate schema keys form a deterministic record-order/key-order prefix: exact count and byte boundaries are accepted, the first exceeding or non-UTF-8-encodable key records a stable truncation reason, and later records still contribute to `line_count` without growing retained key state.
- Broad index matches use the public `history.jsonl` and `session_index.jsonl` schemas, preserve bounded finite numeric history timestamps, and keep every emitted match projection bounded before the final scan metadata record.

## Next Steps

- None.

## Evidence

- `python3 -B -m unittest -b tests.test_skill_structure`: 27 tests passed.
- Post-review aggregate schema count/byte boundary and invalid-key selection: 2 focused tests passed.
- Post-review broad index fairness and missing-source behavior: 2 focused tests passed.
- `skills/codex-session-mining/references/workflow.md`
- `tests/test_skill_structure.py`
- `codex-session-mining` passed the Joey skill validator; project-journal validation and `git diff --check` passed.
