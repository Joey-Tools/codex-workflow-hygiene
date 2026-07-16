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
- The helper snapshots each first-pass byte prefix so append-only active rollout growth cannot invalidate a long scan; truncation, replacement, malformed JSON, unsafe paths, and prefix rewrites still fail closed.
- Automation wrappers, replay prefixes, and synthetic child or review prompts are excluded narrowly without dropping later human follow-ups in the same main rollout.
- Contract tests pin the active/archive union, deduplication, and intent-reconstruction boundaries.
- The inherited credential-shaped regression fixture is assembled from segments at runtime so the exact legacy preflight can enforce a count-monotonic `1 -> 0` cleanup without changing test semantics.
- Pinned review tightened the recipe to inventory both roots completely before timestamp filtering, preserve shell failures, report per-root candidate and accepted counts, and use recursive archive globs consistently.
- Follow-up review made the exact-session cross-root lookup propagate `find` failures and retain their stderr evidence.
- Exact-session index hints now tolerate missing, unreadable, and malformed inputs without blocking the authoritative rollout-root search or echoing raw records.
- Final PR review found that the original inventory recipe described structured filtering without implementing it. The executable helper and fixture-backed tests now pin old dated paths with new records, flat and nested archives, lifecycle grouping, restamped prefix removal, distinct suffix retention, filename-ID confirmation, and append-only growth.

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
