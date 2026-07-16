---
id: 20260717-csr001
title: Retrospective Remote Probe Safety
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260716-codex-workflow-hygiene-retrospective-output-safety
pr:
supersedes: []
superseded_by:
---

# Retrospective Remote Probe Safety

## Summary

- Adapted the canonical private remote-probe output hardening into the retrospective helper without changing its filename-window or auto-split behavior.
- Pinned local output creation and replacement to one descriptor-opened parent directory.
- Preserved root, active, date-nested archive, and flat archive lifecycle paths even when they share one session id.

## Current State

- A parent pathname replaced by a symlink after output validation cannot redirect fetched bytes outside the approved task or `/tmp` output roots.
- Temporary output creation, cleanup, permission enforcement, and final replacement use descriptor-relative operations against the same pinned parent.
- Local and embedded `session-meta` deduplicate exact relative rollout paths only, including after auto-split window merging; same-session suffix-bearing paths remain independently fetchable.

## Next Steps

- None for this completed slice.

## Evidence

- `skills/codex-session-retrospective/scripts/remote_codex_probe.py`
- `skills/codex-session-retrospective/SKILL.md`
- `tests/test_session_retrospective.py`
- Focused regression selection: 10 tests passed.
- `python3 -m unittest tests.test_session_retrospective`: 843 tests passed, 1 skipped.
- `python3 -m unittest tests.test_skill_structure`: 18 tests passed.
- Full repository suite after fast-forwarding canonical `master`: 928 tests passed, 1 skipped.
- Skill validators, project-journal validation, Python bytecode compilation, and `git diff --check` passed.
