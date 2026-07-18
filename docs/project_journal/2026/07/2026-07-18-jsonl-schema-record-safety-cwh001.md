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
- Made local and embedded rollout summaries count invalid UTF-8, non-object top-level values, missing or non-string outer record types, missing or non-string inner types for recognized response and event records, present non-string timestamps, invalid summary metadata IDs or cwd values, non-object recognized payloads, unsupported recognized message containers, response messages with missing, non-string, or unsupported roles, malformed exact tool or task-complete evidence fields, and content items without a string type or valid supported text as JSON errors while preserving later valid evidence.
- Made valid `developer` and `system` response messages schema-checked non-evidence in local and embedded rollout summaries, preserving complete-source proofs and summary counts while continuing to reject malformed content or any other role.
- Made the main retained-data scanner enforce exact outer/payload evidence mappings and one shared response-message schema across context metadata, raw flags, and user or assistant extraction; restrict context metadata to recognized carriers after end-window filtering; and apply type-safe task/tool fields and explicit-field precedence instead of crashing, using invalid fallbacks, or stringifying malformed evidence, while preserving later valid turns and compatible generic flags.
- Scoped the main scanner's tool-output `text` fallback to legacy outer `function_call_output` records; exact response tool output now requires string `output`, so malformed exact records cannot inject flags or detach a later assistant response.

## Current State

- Oversized records containing a bare CR cannot expose a JSON-like suffix as a separate history, session-index, or schema record.
- Broad index scans retain at most 20 matches per source, always inspect both public index sources, emit at most 20 matches round-robin, and append one fixed-shape record that distinguishes missing sources, per-source truncation, and global output truncation.
- Aggregate schema keys form a deterministic record-order/key-order prefix: exact count and byte boundaries are accepted, the first exceeding or non-UTF-8-encodable key records a stable truncation reason, and later records still contribute to `line_count` without growing retained key state.
- Broad index matches use the public `history.jsonl` and `session_index.jsonl` schemas, preserve bounded finite numeric history timestamps, and keep every emitted match projection bounded before the final scan metadata record.
- Invalid UTF-8 session metadata fails closed with a stable path-neutral error; schema-invalid metadata records and records without a non-empty string ID are skipped in favor of later valid metadata, while local and embedded timestamp overflow is treated as an unavailable timestamp rather than an uncaught exception.
- Invalid-UTF-8 and schema-invalid summary records, including records whose outer type is missing or non-string, recognized response or event records whose inner type is missing or non-string, present non-string timestamps, invalid summary metadata IDs or present non-string cwd values, response messages whose role is missing, non-string, or outside `user`, `assistant`, `developer`, and `system`, missing or non-string exact response-tool outputs or task-complete messages, unsupported recognized event user-message containers, non-object content elements, content items without a string type, and supported content items without string text, increment `json_error_count`, cannot support a complete-source proof, and do not prevent later valid evidence. Valid developer and system response messages must satisfy the same content schema but remain non-evidence: they do not increase `summary_record_count` or revoke source and coverage proofs, while user and assistant messages remain summary evidence. Missing timestamps and cwd values remain valid; empty or whitespace-only exact tool and task strings remain valid without evidence; cwd presence derives only from a non-empty string. `session_meta` and legacy outer `function_call_output` records remain valid without an inner type, while unknown real string outer or inner types remain ignorable. Explicit message strings and valid user-role message objects never fall back to top-level text; legacy top-level text remains supported only when the message key is absent, and unknown string content types remain ignorable.
- Main rollout extraction accepts non-empty string context metadata only from `session_meta`, `turn_context`, and schema-valid exact `response_item`/`message` carriers after the record passes the end-window gate. Its shared response-message predicate requires a `user` or `assistant` role, list content, object content items with string types, and string text for supported item types; unknown string item types remain schema-valid but contribute no text. The same predicate gates response-message metadata, raw flags, and user or assistant evidence, so invalid or missing roles and malformed content cannot alter context or retained signals. Exact string outer/payload mappings and string task-complete or tool fields remain required. Explicit event messages never fall back to top-level text, invalid preferred fields cannot fall through to tempting alternates, and malformed, wrong-pair, known non-evidence, or out-of-window records contribute no retained evidence or context. Recognized evidence outers with object payloads whose inner type is missing or an unknown string retain compatible generic flag scanning, and malformed records do not stop later valid user or assistant records.
- Exact `response_item`/`function_call_output` records use only string `output`; missing, non-string, empty, or whitespace-only values produce no evidence and never fall back to sibling `text`. Legacy outer `function_call_output` keeps its compatibility precedence: missing or empty output may fall back to string `text`, while explicit non-string or whitespace-only output blocks fallback.

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
- Post-review local/embedded summary role-schema parity: 2 focused tests passed, including proof revocation and preservation of later valid evidence.
- Post-review local/embedded outer and recognized-inner discriminator typing: 3 focused tests passed, including 12 malformed type records, forward-compatible string types, proof revocation, and preservation of later valid evidence.
- Post-review local/embedded scalar-field typing: 4 focused tests passed, including 22 malformed timestamp, cwd, exact tool-output, and task-complete fields; optional and empty-string compatibility; proof revocation; and preservation of later valid evidence.
- Post-review local/embedded non-evidence response roles: 2 focused tests passed, including valid developer and system content with unchanged summary counts and preserved source/coverage proofs, malformed content with proof revocation, unsupported roles, and exact preservation of later user and assistant evidence.
- Post-review main-scanner exact-versus-legacy tool fallback: 3 focused tests and all 12 `extract_rollout` tests passed, including exact missing-output rejection without flags or detachment, preservation of the later assistant response, legacy text fallback, and legacy preferred-field precedence.
- Focused local/embedded retrospective selection: 14 tests passed.
- `python3 -B -m unittest -b tests.test_session_retrospective`: 891 tests passed after the response-role schema follow-up.
- The final full repository suite passed 1,021/1,021 tests after the retrospective schema follow-ups.
- Python 3.13.0 byte compilation passed for the changed script and test modules.
- Ruff 0.13.2 passed the changed Python files with the repository's unchanged `F541` baseline excluded from `tests/test_session_retrospective.py`.
- Both touched skills passed the Joey skill validator; project-journal validation and `git diff --check` passed.
- `skills/codex-session-mining/references/workflow.md`
- `skills/codex-session-retrospective/scripts/remote_codex_probe.py`
- `tests/test_skill_structure.py`
- `tests/test_session_retrospective.py`
