---
id: 20260722-bco003
title: Portable Command Construction Guardrails
status: completed
created: 2026-07-22
updated: 2026-07-22
branch: codex/daily-skill-friction-20260722-codex-workflow-hygiene-portable-rg-command-guardrail
pr:
supersedes: []
superseded_by:
---

# Portable Command Construction Guardrails

## Summary

- Added bounded-command guidance for portable executable resolution, safe dynamic arguments in unavoidable shell pipelines, and aggregate budgets across parallel producers.

## Current State

- Portable tools use direct argv and the selected runtime's trusted `PATH` instead of guessed `/usr/bin` or package-manager prefixes.
- Shell pipelines receive dynamic values through positional arguments or task-scoped scripts, avoiding nested host-language and shell interpolation failures.
- Parallel producers share one aggregate visible-output and retained-byte budget; independent per-command caps no longer imply that the combined output is bounded.

## Next Steps

- Monitor whether these rules eliminate empty-result false positives and aggregate-output truncation across broad scans.

## Evidence

- `skills/bounded-command-output/SKILL.md`
- `skills/bounded-command-output/references/command-patterns.md`
- `tests/test_skill_structure.py`
- `python3 -m unittest tests.test_skill_structure`: 27 tests passed.
- `python3 -m unittest discover -s tests -q`: 1,058 tests passed with process-local commit signing disabled for temporary fixture merge commits.
- `quick_validate.py skills/bounded-command-output`: valid.
