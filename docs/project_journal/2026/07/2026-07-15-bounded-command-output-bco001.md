---
id: 20260715-bco001
title: Bounded Command Output Skill
status: completed
created: 2026-07-15
updated: 2026-07-15
branch: codex/daily-skill-friction-20260715-codex-workflow-hygiene-bounded-command-output
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/41
supersedes: []
superseded_by:
---

# Bounded Command Output Skill

## Summary

- Added a reusable skill that keeps high-output command producers, retained artifacts, polling, and visible evidence deliberately bounded.

## Current State

- Search, inventory, log, artifact, process, build, test, and spinner-heavy command patterns share one cross-cutting skill.
- Large repository and review-range inventories first use a streaming total counter with an explicit path-sample cap; short per-file lines do not make a complete inventory bounded.
- Domain skills continue to own diagnosis, delivery, and review decisions; stricter domain contracts take precedence.
- Potentially unbounded producers require enforced wall-clock and retained-byte ceilings; rotation qualifies only when the whole retained set has fixed aggregate-byte and segment-count caps with old segments removed or reused. Otherwise the producer must terminate at the ceiling. Task-scoped redirection and byte-count polling alone are only observability.

## Next Steps

- Monitor future session friction for another command family that warrants a focused reference pattern.

## Evidence

- `skills/bounded-command-output/SKILL.md`
- `skills/bounded-command-output/references/command-patterns.md`
- `tests/test_skill_structure.py`
- `tests/test_session_retrospective.py` preserves the fake GitHub token test value through runtime composition so frozen review preflight does not mistake the tracked fixture for a credential.
