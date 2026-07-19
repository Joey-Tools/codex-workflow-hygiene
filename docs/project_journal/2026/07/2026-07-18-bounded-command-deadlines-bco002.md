---
id: 20260718-bco002
title: Bounded Database And Filesystem Scans
status: completed
created: 2026-07-18
updated: 2026-07-19
branch: codex/bounded-process-group-supervisor-20260719
pr:
supersedes: []
superseded_by:
---

# Bounded Database And Filesystem Scans

## Summary

- Added task-selected deadline guidance for SQLite aggregates and broad macOS filesystem walks, plus a lightweight process-group wrapper for ordinary child processes.

## Current State

- SQLite `.timeout` is identified as busy-lock handling rather than a query-execution deadline.
- Large or actively written databases start with metadata, sequence, schema/index, or narrow indexed probes before broad aggregates.
- Broad aggregates require an outer hard wall-clock deadline and produce incomplete evidence when terminated.
- Broad macOS `du` walks require a hard deadline before launch; PTY polling alone is not a runtime bound.
- Timed-out filesystem branches remain explicitly unknown or incomplete.
- Numeric deadlines are illustrative rather than default thresholds; long-running scans are not friction by duration alone.
- macOS single-process scans have a system-Perl direct-`exec` deadline pattern that preserves ordinary exit statuses and maps `SIGALRM` to an explicit incomplete result.
- A POSIX/Python 3.11 same-session process-group wrapper adds TERM/grace/KILL handling for ordinary child processes without requiring root or a container.
- Cancellation handlers are installed before process creation; signals received during the startup handoff are forwarded once the new group is available.
- The wrapper preserves the original session, does not allocate a PTY, waits only for its direct child, and intentionally does not chase escaped descendants or prove group quiescence.
- macOS may return `EPERM` during immediate process-group handoff or after the leader exits; the wrapper falls back to signaling a still-live direct child and reports group cleanup as unverified while preserving the timeout or forwarded-signal result.
- Background descendants that intentionally survive a normal leader exit must close or redirect inherited stdout/stderr, or an outer pipe reader can continue waiting for EOF.
- Python 3.10 can use the explicit `--new-session` mode when losing the controlling terminal is acceptable.
- Output-byte enforcement remains separate from the deadline wrapper.

## Next Steps

- Monitor whether the lightweight wrapper covers ordinary non-interactive builds and scans without introducing unacceptable TTY or Python-version constraints.

## Evidence

- `skills/bounded-command-output/references/command-patterns.md`
- `skills/bounded-command-output/scripts/run_process_group_deadline.py`
- `tests/test_bounded_process_group_deadline.py`
- `tests/test_skill_structure.py`
