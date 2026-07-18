---
id: 20260718-smc005
title: Session Mining Selected-Output Control Escaping
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-session-mining-control-output-escape
pr:
supersedes: []
superseded_by:
---

# Session Mining Selected-Output Control Escaping

## Summary

- Added a final `escaped_output_text` pass to the exact-keyword recipe after raw matching and bounded context-window selection.
- Escaped each non-printable character with its ASCII JSON representation while leaving printable Unicode unchanged.
- Added a regression covering raw NUL, standalone ESC, OSC terminated by BEL, standalone BEL, and CSI content.

## Current State

- Selected rollout content cannot send raw terminal control characters to stdout.
- Exact matching still evaluates the raw normalized text, including a needle containing CSI, before output escaping.
- The selected output remains one physical line and bounded by the existing context window while printable Unicode remains literal.

## Next Steps

- None.

## Evidence

- Six focused exact-keyword probe regressions passed, including the new selected-content control-character case.
- The full repository suite passed: 995 tests in 84.342 seconds.
- `codex_skill_validate.py skills/codex-session-mining`: valid.
- Ruff 0.13.2: `ruff check --no-cache tests/test_skill_structure.py` passed.
- `python3 -m py_compile tests/test_skill_structure.py`: passed.
- Project journal validation and `git diff --check` passed.
