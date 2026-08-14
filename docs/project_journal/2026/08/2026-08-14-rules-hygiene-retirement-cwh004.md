---
id: 20260814-cwh004
title: Codex Rules Hygiene Retirement
status: completed
created: 2026-08-14
updated: 2026-08-14
branch: codex/archive-codex-rules-hygiene
pr:
supersedes: []
superseded_by:
---

# Codex Rules Hygiene Retirement

## Summary

- Retired `codex-rules-hygiene` from the active canonical skill set and preserved its original procedure as a frozen historical archive.

## Current State

- On the target branch, `skills/codex-rules-hygiene/` is absent and the historical files live under `docs/archive/codex-rules-hygiene/` without loadable skill frontmatter or a `SKILL.md` entrypoint.
- The archive is not distributed, installed, or supported, and it has no replacement. Joey's `Approve for me` workflow made continuing rules-hygiene maintenance effectively obsolete.
- Private distribution was removed by [codex-private-workflows PR #170](https://github.com/Joey-Tools/codex-private-workflows/pull/170); Private Overlay release `450fba1` propagated that state, and the installed `codex-rules-hygiene` skill was removed.

## Next Steps

- None.

## Evidence

- `docs/archive/codex-rules-hygiene/README.md`
- `docs/archive/codex-rules-hygiene/audit-cadence.md`
- `README.md`
- `tests/test_skill_structure.py`
- Focused retirement and active-skill frontmatter structure tests: 2 tests passed.
- Full repository suite: 1,172 tests passed.
- The four remaining active skills passed overlay validation.
- Project journal validation passed.
- `git diff --check` passed.
