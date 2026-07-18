---
id: 20260718-cwh001
title: JSONL Schema and Record Safety
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-jsonl-schema-record-bound
pr:
supersedes: []
superseded_by:
---

# JSONL Schema and Record Safety

## Summary

- Bounded the broad index-keyword and aggregate schema recipes to 1 MiB binary physical records with fixed 64 KiB LF draining.
- Made the retrospective session-metadata readers reject invalid UTF-8 and skip schema-invalid JSON objects without losing later valid metadata.
- Made local and embedded rollout summaries count invalid UTF-8, non-object top-level values, and non-object recognized payloads as JSON errors while preserving later valid evidence.

## Current State

- Oversized records containing a bare CR cannot expose a JSON-like suffix as a separate history, session-index, or schema record.
- Broad index matches use the public `history.jsonl` and `session_index.jsonl` schemas, preserve bounded finite numeric history timestamps, and emit at most 20 bounded JSON projections.
- Invalid UTF-8 session metadata fails closed with a stable path-neutral error; schema-invalid metadata records are skipped.
- Invalid-UTF-8 and schema-invalid summary records, including response or nested event messages with non-array content, increment `json_error_count`, cannot support a complete-source proof, do not emit replacement-decoded evidence, and do not prevent later valid user or assistant evidence from being summarized.

## Next Steps

- None.

## Evidence

- `python3 -B -m unittest -b tests.test_skill_structure`: 25 tests passed.
- Post-review numeric history timestamp regression: 1 test passed.
- Post-review nested message schema regression: 1 test passed.
- Focused local/embedded retrospective selection: 14 tests passed.
- The final full repository suite passed 1,008/1,008 tests after both review follow-ups.
- Python 3.13.0 byte compilation passed for the changed script and test modules.
- Ruff 0.13.2 passed the changed Python files with the repository's unchanged `F541` baseline excluded from `tests/test_session_retrospective.py`.
- Both touched skills passed the Joey skill validator; project-journal validation and `git diff --check` passed.
- `skills/codex-session-mining/references/workflow.md`
- `skills/codex-session-retrospective/scripts/remote_codex_probe.py`
- `tests/test_skill_structure.py`
- `tests/test_session_retrospective.py`
