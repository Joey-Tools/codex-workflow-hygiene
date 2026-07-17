---
id: 20260718-bco002
title: Bounded Database And Filesystem Scans
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-bound-sqlite-du
pr:
supersedes: []
superseded_by:
---

# Bounded Database And Filesystem Scans

## Summary

- Added concrete hard-deadline guidance for SQLite aggregates and broad macOS filesystem walks after both command shapes caused repeated manual interruption.

## Current State

- SQLite `.timeout` is identified as busy-lock handling rather than a query-execution deadline.
- Large or actively written databases start with metadata, sequence, schema/index, or narrow indexed probes before broad aggregates.
- Broad aggregates require an outer hard wall-clock deadline and produce incomplete evidence when terminated.
- Broad macOS `du` walks require a hard deadline before launch; PTY polling alone is not a runtime bound.
- Timed-out filesystem branches remain explicitly unknown or incomplete.
- macOS single-process scans have a system-Perl direct-`exec` deadline pattern that preserves ordinary exit statuses and maps `SIGALRM` to an explicit incomplete result.
- Producers that detach descendants still require task-scoped supervision or OS containment for the whole process unit.

## Next Steps

- Monitor whether these concrete patterns prevent manual interruption in future database and disk-usage investigations.

## Evidence

- `skills/bounded-command-output/references/command-patterns.md`
- `tests/test_skill_structure.py`
