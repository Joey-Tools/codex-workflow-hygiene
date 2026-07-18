---
id: 20260718-cwh001
title: JSONL Schema and Record Safety
status: completed
created: 2026-07-18
updated: 2026-07-19
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-jsonl-schema-record-bound
pr:
supersedes: []
superseded_by:
---

# JSONL Schema and Record Safety

## Summary

- Bounded the broad index-keyword and aggregate schema recipes to 1 MiB binary physical records with fixed 64 KiB LF draining.
- Made broad index-keyword output source-fair with per-source collection caps, deterministic round-robin emission, and explicit scan metadata.
- Bounded aggregate schema discovery to 256 unique keys and 32 KiB under strict UTF-8 encoding, with deterministic truncation metadata and the same limits on the first-record projection.
- Made the retrospective session-metadata readers reject invalid UTF-8, align overflowing timestamp handling, and skip schema-invalid JSON objects or missing, empty, and non-string session IDs without losing later valid metadata.
- Made local and embedded rollout summaries count invalid UTF-8, non-object top-level values, invalid summary metadata IDs, non-object recognized payloads, unsupported recognized message containers, and content items without a string type or valid supported text as JSON errors while preserving later valid evidence.
- Made the main retained-data scanner enforce exact outer/payload evidence mappings and one shared response-message schema across context metadata, raw flags, and user or assistant extraction; restrict context metadata to recognized carriers after end-window filtering; and apply type-safe task/tool fields and explicit-field precedence instead of crashing, using invalid fallbacks, or stringifying malformed evidence, while preserving later valid turns and compatible generic flags.

## Current State

- Oversized records containing a bare CR cannot expose a JSON-like suffix as a separate history, session-index, or schema record.
- Broad index scans retain at most 20 matches per source, always inspect both public index sources, emit at most 20 matches round-robin, and append one fixed-shape record that distinguishes missing sources, per-source truncation, and global output truncation.
- Aggregate schema keys form a deterministic record-order/key-order prefix: exact count and byte boundaries are accepted, the first exceeding or non-UTF-8-encodable key records a stable truncation reason, and later records still contribute to `line_count` without growing retained key state.
- Broad index matches use the public `history.jsonl` and `session_index.jsonl` schemas, preserve bounded finite numeric history timestamps, and keep every emitted match projection bounded before the final scan metadata record.
- Invalid UTF-8 session metadata fails closed with a stable path-neutral error; schema-invalid metadata records and records without a non-empty string ID are skipped in favor of later valid metadata, while local and embedded timestamp overflow is treated as an unavailable timestamp rather than an uncaught exception.
- Invalid-UTF-8 and schema-invalid summary records, including invalid summary metadata IDs, unsupported recognized event user-message containers, non-object content elements, content items without a string type, and supported content items without string text, increment `json_error_count`, cannot support a complete-source proof, and do not prevent later valid evidence. Explicit message strings and valid user-role message objects never fall back to top-level text; legacy top-level text remains supported only when the message key is absent, and unknown string content types remain ignorable.
- Main rollout extraction accepts non-empty string context metadata only from `session_meta`, `turn_context`, and schema-valid exact `response_item`/`message` carriers after the record passes the end-window gate. Its shared response-message predicate requires a `user` or `assistant` role, list content, object content items with string types, and string text for supported item types; unknown string item types remain schema-valid but contribute no text. The same predicate gates response-message metadata, raw flags, and user or assistant evidence, so invalid or missing roles and malformed content cannot alter context or retained signals. Exact string outer/payload mappings and string task-complete or tool fields remain required. Explicit event messages never fall back to top-level text, invalid preferred fields cannot fall through to tempting alternates, and malformed, wrong-pair, known non-evidence, or out-of-window records contribute no retained evidence or context. Recognized evidence outers with object payloads whose inner type is missing or an unknown string retain compatible generic flag scanning, and malformed records do not stop later valid user or assistant records.

## Next Steps

- None.

## Evidence

- `python3 -B -m unittest -b tests.test_skill_structure`: 27 tests passed.
- Post-review numeric history timestamp regression: 1 test passed.
- Post-review nested message schema regression: 1 test passed.
- Post-review aggregate schema count/byte boundary and invalid-key selection: 2 focused tests passed.
- Post-review broad index fairness and missing-source behavior: 2 focused tests passed.
- Post-review message-container/content, legacy fallback, metadata-ID, and timestamp-overflow selection: 6 focused tests passed.
- Post-review supported-item typing and explicit-message fallback precedence: 3 focused tests passed.
- Post-review content-item type validation and hash-safe summary handling: 3 focused tests passed.
- Post-review main-scanner hash-safety, exact evidence dispatch, context/task/tool typing, explicit-field precedence, recognized metadata-carrier compatibility, end-window context selection, and generic-flag compatibility: 6 focused tests passed.
- Post-review shared response-message schema across metadata, raw flags, and evidence extraction: 2 focused tests and all 10 `extract_rollout` tests passed, including invalid and missing roles, malformed content, unknown string item types, and a later valid turn.
- Focused local/embedded retrospective selection: 14 tests passed.
- `python3 -B -m unittest -b tests.test_session_retrospective`: 884 tests passed after the shared main-scanner response-message schema follow-up.
- The final full repository suite passed 1,014/1,014 tests after the retrospective schema follow-ups.
- Python 3.13.0 byte compilation passed for the changed script and test modules.
- Ruff 0.13.2 passed the changed Python files with the repository's unchanged `F541` baseline excluded from `tests/test_session_retrospective.py`.
- Both touched skills passed the Joey skill validator; project-journal validation and `git diff --check` passed.
- `skills/codex-session-mining/references/workflow.md`
- `skills/codex-session-retrospective/scripts/remote_codex_probe.py`
- `tests/test_skill_structure.py`
- `tests/test_session_retrospective.py`
