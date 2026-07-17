---
id: 20260717-csr005
title: Retrospective Descriptor Traversal
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260717-codex-workflow-hygiene-pin-retrospective-input-traversal
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/52
supersedes: []
superseded_by:
---

# Retrospective Descriptor Traversal

## Summary

- Pinned the Codex root and every rollout ancestor through descriptor-relative no-follow directory opens.
- Opened enumerated session-metadata rollout inputs as nonblocking regular files, allowed only same-inode growth whose previously captured bounded prefix remains byte-identical, and retained exact full-snapshot identity for every archive layout and for fetch/summary.
- Applied the same fail-closed traversal contract to local and embedded session metadata, fetches, and summaries without changing public active/archive layouts or output budgets.

## Current State

- A root that is absent at the initial probe remains an empty source, while disappearance or replacement after discovery is a hard coverage error.
- Ancestors that change before pinning and in-scope final entries that change after enumeration are rejected without reopening by pathname; out-of-scope abnormal entries do not abort bounded scans. Final-entry metadata identity is captured in the same scoped `scandir` iteration. Immediately before a selected active/root candidate is consumed, an at-most-256-KiB SHA-256 prefix proof is captured through the pinned parent descriptor. Once pinned, ancestor pathname replacement cannot redirect held descriptors. Active/root session metadata permits only sequential same-inode growth with an unchanged proved prefix and rejects shrink, same-size mutation, rewrite-and-grow, or transient live-read substitution, while archives and fetch/summary continue to require exact snapshots.
- Descriptor cleanup covers partial traversal and duplication failures; remote failures remain framed and path-neutral.
- Session metadata is parsed only from the immutable bytes returned by a verified proof checkpoint. Proof reads use fixed 64-KiB `pread` calls, remain bounded to 256 KiB per pass, and are globally limited to `limit + 1` consumed active/root candidates per scan; unconsumed candidates perform zero proof reads. A valid `limit + 1` result still reports ordinary truncation for auto-split, while a further invalid/no-metadata candidate fails closed with a path-neutral coverage error.

## Next Steps

- None for this completed traversal slice. Continue monitoring new platforms for equivalent no-follow directory and regular-file flag support.

## Evidence

- `skills/codex-session-retrospective/scripts/remote_codex_probe.py`
- `skills/codex-session-retrospective/SKILL.md`
- `tests/test_remote_codex_probe.py`
- `python3 -m unittest -b tests.test_session_retrospective tests.test_remote_codex_probe`: 892 tests passed after pull-request review fixes.
- `python3 -m unittest discover -s tests -p 'test_*.py' -b`: 981 tests passed after pull-request review fixes.
- `python3 tests/test_remote_codex_probe.py`: 23 descriptor and race tests passed.
- Skill validation, project-journal validation, Python compilation, Ruff, and `git diff --check` passed.
- Pre-commit inspections and fixed-range reviews found and closed enumeration, append, descriptor-budget, FIFO-test, scope-order, and archive-snapshot gaps. Pull-request review then found a delayed final-entry stat race and incomplete append-only baselines; follow-up reviews found an open-to-scan handoff gap, rewrite-and-grow bypass, live-read substitution window, and unbounded aggregate proof work. All are covered by local/embedded regressions and the final review result is recorded in the pull request.
