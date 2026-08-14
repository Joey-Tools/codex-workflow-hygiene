---
id: 20260815-cwh005
title: Bounded Output And Skill Authoring Guardrails
status: completed
created: 2026-08-15
updated: 2026-08-15
branch: codex/bounded-authoring-guardrails
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/74
supersedes: []
superseded_by:
---

# Bounded Output And Skill Authoring Guardrails

## Summary

- Tightened the `bounded-command-output` trigger boundary, bounded tool-registry discovery, and hardened skill-validator discovery across custom `CODEX_HOME` and symlinked installations.

## Current State

- `bounded-command-output` distinguishes genuinely broad, noisy, or runtime-uncertain work from predictable exact commands, and keeps producer scope, runtime, retained bytes, and visible output as separate budgets.
- The bounded-output skill instructs agents to filter scalar tool-registry metadata, cap results, and project clipped summaries before emitting output instead of raw registry entries or full schema objects.
- The skill-validator wrapper honors explicit overrides first, then both `CODEX_HOME` layouts, the lexical loaded skill root, the resolved source root, and finally the default home only when `CODEX_HOME` is unset or empty.
- Validator candidates must resolve through `Path.is_file()`; directories fail as runtime configuration errors instead of being executed as validators.

## Next Steps

- None.

## Evidence

- `skills/bounded-command-output/SKILL.md`
- `skills/bounded-command-output/references/command-patterns.md`
- `skills/codex-skill-authoring/SKILL.md`
- `skills/codex-skill-authoring/scripts/codex_skill_validate.py`
- `tests/test_skill_validator_wrapper.py`
- `tests/test_skill_structure.py`
- `python3 -B -m unittest -q tests.test_skill_validator_wrapper tests.test_skill_structure` (`45` tests passed)
- `python3 -B -m unittest discover -s tests -q` (`1177` tests passed)
- `python3 -m py_compile skills/codex-skill-authoring/scripts/codex_skill_validate.py`
- `python3 skills/codex-skill-authoring/scripts/codex_skill_validate.py --report .codex-tmp/skill-validation/pr-a.json skills/bounded-command-output skills/codex-skill-authoring` (`2/2` skills valid)
- `python3 /Users/hoteng/.codex/skills/project-journal/scripts/project_journal.py validate --repo .`
- `git diff --check`
- Fresh-context local Codex review of the tree-equivalent WIP range `2b270d22d86d6c7cea0c6733a188218387d0d1de..a91fe0ab2085ff69ba75367cb6194882065a3e9c` (`No findings.`)
- Selective donor review: [`codex-workflow-hygiene#63`](https://github.com/Joey-Tools/codex-workflow-hygiene/pull/63) at `5b769d3742d2b48377060373146638a3558d7d5d`; only bounded-output and authoring behavior was retained, not its rules transaction or session-mining scope.
- Local tool-registry guardrail donor: `codex/daily-skill-friction-20260805-codex-workflow-hygiene-all-tools-output-guardrail` at `24c9d1b89eeebf173a6710a6edb88a66a1a2ccd9`; it records two broad tool-metadata projections of roughly 75k tokens that motivated the capped scalar projection.
