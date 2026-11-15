---
id: 20261115-bounded-log-capture
title: Bound Command Logs Without Limiting Artifacts
status: completed
created: 2026-11-15
updated: 2026-11-15
branch: wip/bounded-output-stream
pr:
supersedes: []
superseded_by:
---

# Bound Command Logs Without Limiting Artifacts

## Summary

The POSIX deadline runner can capture merged stdout and stderr into a new
task log with an explicit byte ceiling. Capture preserves target resource
limits and ordinary artifact creation.

## Current State

- `--output-log` and `--max-output-bytes` are paired optional arguments.
- Exact-size complete output preserves the child status; excess output returns `123` and incomplete evidence.
- Existing destinations are preserved through exclusive creation of the owner-only log.
- Timeout, cancellation, command-start failures, and the existing process-group boundary retain their distinct outcomes.
- The log sink's protected properties are bounded retained bytes and preservation of existing destinations. It does not claim directory tamper resistance or group quiescence.
- Review-owned evidence contracts retain authority over model-output capture.

## Evidence

- 58 deadline/capture and skill-structure tests passed.
- Regressions cover a 2 MiB artifact under a 4-byte log budget, unchanged caller file-size limits, exact and excess output, binary chunks, descriptor closure, cancellation, and background EOF.
- Ruff, skill validation, and diff checks passed.
- High inherited descriptors retain capture and deadline enforcement through the platform's default selector.
