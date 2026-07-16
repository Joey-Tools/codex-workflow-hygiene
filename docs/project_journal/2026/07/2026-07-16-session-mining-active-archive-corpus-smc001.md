---
id: 20260716-smc001
title: Active And Archived Session Corpus
status: completed
created: 2026-07-16
updated: 2026-07-16
branch: codex/daily-skill-friction-20260716-codex-workflow-hygiene-session-mining-active-archive-corpus
pr:
supersedes: []
superseded_by:
---

# Active And Archived Session Corpus

## Summary

- Updated session-mining guidance so complete current-host audits inventory active and archived rollout roots before classifying evidence.

## Current State

- Exact-session lookup covers both existing transcript roots and both flat and date-nested archive layouts.
- Date-window audits use record and lifecycle timestamps for archived candidates instead of treating filename or mtime as authoritative.
- Cross-root deduplication groups lifecycle session identities and compares ordered stable record fingerprints while retaining later genuine human suffixes.
- The bundled `build_session_corpus.py` helper performs the full-root inventory, inclusive/exclusive timestamp filtering, two-pass fingerprint loading, replay-prefix removal, and per-root/union artifact generation instead of leaving those semantics to an unspecified scanner.
- The helper snapshots each first-pass complete-record prefix so an unterminated active-writer fragment is deferred without invalidating a long scan; truncation, replacement, committed malformed JSON, malformed archived tails, unsafe paths, and prefix rewrites still fail closed.
- Automation wrappers, replay prefixes, and synthetic child or review prompts are excluded narrowly without dropping later human follow-ups in the same main rollout.
- Contract tests pin the active/archive union, deduplication, and intent-reconstruction boundaries.
- The inherited credential-shaped regression fixture is assembled from segments at runtime so the exact legacy preflight can enforce a count-monotonic `1 -> 0` cleanup without changing test semantics.
- Pinned review tightened the recipe to inventory both roots completely before timestamp filtering, preserve shell failures, report per-root candidate and accepted counts, and use recursive archive globs consistently.
- Follow-up review made the exact-session cross-root lookup propagate `find` failures and retain their stderr evidence.
- Exact-session index hints now tolerate missing, unreadable, and malformed inputs without blocking the authoritative rollout-root search or echoing raw records.
- Final PR review found that the original inventory recipe described structured filtering without implementing it. The executable helper and fixture-backed tests now pin old dated paths with new records, flat and nested archives, lifecycle grouping, restamped prefix removal, distinct suffix retention, filename-ID confirmation, and append-only growth.
- Final frozen-range review also made traversal errors fail closed, made shorter source histories own shared prefixes before longer continuations, and aligned exact-session lookup with `CODEX_HOME`. Content-only matches across different session identities remain deliberately separate because repeated wrappers and prompts are not sufficient proof of replay.
- The final ordering rule compares complete record-order timestamp provenance before history length, covering a short original prefix followed by a longer continuation, a fully restamped truncation, and a partially restamped truncation that retains one old opening timestamp. Basenames are never used as identity when lifecycle and filename UUIDs are absent.
- Replay collapse now requires byte identity or assistant/tool execution evidence inside the normalized prefix; prompt-only matches remain visible even under one lifecycle. Root inspection uses `lstat` so a dangling active or archive symlink fails closed instead of reporting an empty root.
- Filename UUIDs no longer bridge components containing two explicit different lifecycle IDs, including through a lifecycle-less intermediate rollout. Corpus output requires a fresh path created through no-follow directory descriptors and uses exclusive no-follow artifact creation, while cross-root groups with no in-window candidate skip the fingerprint-loading pass.
- Final PR review preserved second-level filename timestamps for timestamp-less rollouts and made replay fingerprints stable across narrow `session_meta` runtime-context drift plus regenerated response/call/turn IDs. The canonicalizer preserves lifecycle identity, generated-ID reference relationships, unknown fields, and nested domain IDs from tool results.
- Independent final review made multi-lifecycle rollouts retain every explicit identity and use a filename/first-lifecycle agreement as the owner boundary; owner-later or otherwise ambiguous histories cannot prefix-bridge sessions, while byte-identical copies with the same complete ID set still collapse. Empty timestamp-less files remain counted as candidates but no longer create zero-record accepted entries or duplicate metrics.
- Final GitHub review lexically normalizes `.` and `..` before descriptor-based output traversal, without resolving symlinks, so canceled path components are never created and the no-follow boundary remains intact.
- Final independent review bound every inventoried root and rollout to device/inode/size metadata, reopened both passes through root-relative no-follow descriptors, and rejected root/file replacement or truncation while preserving verified append-only prefix reads.
- The final inventory pass also snapshots and revalidates every traversed directory identity and entry set, so a root or pending subtree replacement cannot silently turn a complete corpus into an empty or partial result.
- Non-byte-identical branch prefixes now stop at the last matching assistant/tool execution record, preserving a repeated human prompt typed after a fork even when its normalized content also appears in another branch.
- Session metadata fingerprints now retain explicit lifecycle IDs while discarding runtime context such as Git state, originator/source, model/provider, thread source, context window, history mode, and base instructions, so restored history still matches across entry points and worktrees.
- Complete UUID-shaped lifecycle aliases are normalized to lowercase like filename UUIDs, while non-UUID opaque IDs retain their original form, so casing alone cannot make one session owner appear ambiguous.
- Non-printable rollout path components now fail closed before line-delimited path artifacts or terminal samples are emitted, preventing a filename from injecting apparent corpus entries.
- `turn_context` runtime drift no longer defeats replay matching, and `time` is now treated as both a record timestamp and a volatile fingerprint field.
- Without a filename UUID, a single first lifecycle identity owns the rollout while later aliases remain provenance; conflicting aliases in the first lifecycle record still fail the owner boundary.
- Cross-root duplicate metrics now require an actual collapsed copy or removed replay prefix between candidates from different roots; same-root overlap in a mixed lifecycle group no longer inflates the count.
- Final exact-range review made exact-session filename discovery NUL-delimited and rejects non-printable paths before printing any rollout match.
- Final independent review made the first pass stop at the last complete active JSONL record while an append is in progress; the old metadata continues to verify only that prefix, and a fresh scan sees the completed record.
- GitHub review added computer-call output records to generated call-ID linkage and replay evidence, so regenerated `call_id` values cannot make a repeated screenshot or output look new.
- Exact-session recipe tests now clear an ambient `CODEX_HOME` when they intentionally exercise a temporary `$HOME/.codex` fixture.
- Final pinned review made byte-identical copies with the same complete lifecycle-ID set collapse even when one filename confirms the owner and the other leaves identity ambiguous; non-identical mixed histories remain isolated.
- Final independent review aligned exact-session filename lookup with UUID lifecycle normalization by matching complete UUIDs case-insensitively while retaining exact case for opaque session IDs.

## Next Steps

- None for this completed slice.

## Evidence

- Archived work-report session `019f6730-5900-7303-85a1-59517b2d8047` required a user correction after archived evidence was omitted.
- Daily Skill Friction session `019f6730-58c3-74e2-aae2-4d4d8c5a0e1d` initially scanned only active sessions; the archived supplement exposed additional repeated review-lane friction.
- `skills/codex-session-mining/SKILL.md`
- `skills/codex-session-mining/references/workflow.md`
- `skills/codex-session-mining/scripts/build_session_corpus.py`
- `tests/test_session_corpus.py`
- `tests/test_skill_structure.py`
- Full repository validation: 915 tests passed with 1 skipped; the session-corpus and skill-structure slice passed 64 tests.
- Real corpus smoke for `2026-07-14T19:25:24Z..2026-07-16T01:11:28Z`: 5,207 active plus 6,305 archived candidates, 891 accepted rollouts, and zero collapsed copies or replay prefixes.
