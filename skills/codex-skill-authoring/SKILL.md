---
name: codex-skill-authoring
description: Create or update Codex skills for the user's workflows by applying canonical placement, instruction-layering, validation-wrapper, and approval-friendly argv conventions on top of the system `$skill-creator`. Use alongside `$skill-creator` whenever a task creates or updates a Codex skill, especially when choosing personal versus repo-local placement, deciding whether guidance belongs in `AGENTS.md`, `SKILL.md`, or `references/`, or validating skills through the local wrapper.
---

# Codex Skill Authoring

## Overview

Load `$skill-creator` first.
This skill is a thin overlay for local canonical placement and execution conventions; it does not replace the system skill's general authoring workflow.

## Keep The Ownership Boundary

`$skill-creator` owns:

- concrete usage examples, naming, and frontmatter design
- `init_skill.py` scaffolding and standard `agents/openai.yaml` generation
- general resource selection, `quick_validate.py` validation, and forward-testing

This overlay owns:

- personal versus repo-local placement
- `AGENTS.md` / `SKILL.md` / `references/` layering
- the local multi-skill validator wrapper and fallback order
- direct, approval-friendly argv examples and task-scoped temporary artifacts

Do not duplicate system scaffolding or mirror the system validator into this skill.

## Choose Placement

- Put cross-repo habits, host-level state workflows, and reusable local conventions in `~/.codex/skills`.
- Default workflows rooted in `~/.codex`, rules, session history, local archives, or other host state to personal skills.
- Put repository-specific procedures, paths, scripts, fixtures, and policy in `.agents/skills/<skill-name>/`.
- Keep a skill repo-local only when its normal runtime depends on repo-owned material.
- Do not hard-code one repository's paths, secrets, or policy into a personal skill.

## Layer Instructions

- Keep `AGENTS.md` short: stable policy, reminders, and pointers only.
- Keep `SKILL.md` procedural: decisions, workflow, and resource-loading rules.
- Put detailed recipes, examples, schemas, pitfalls, and post-mortems in `references/`.
- Avoid duplicating the same rule across layers.

## Preserve Approval-Friendly Commands

- Prefer the real executable with direct argv so stable approval prefixes can match.
- Use `bash -lc` or `/bin/zsh -lc` only when shell syntax is essential.
- Pass dynamic values as direct arguments; use a task-scoped script for non-trivial multi-line logic.
- Put temporary artifacts in task-scoped directories and state their cleanup or handoff.

## Validate Through The Overlay

After following `$skill-creator`:

1. Prefer `"$HOME/.codex/skills/codex-skill-authoring/scripts/codex_skill_validate.py" --report <task-scoped-report.json> <skill> [...]`.
2. The wrapper must delegate to the installed `$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py`; do not edit or mirror that validator here.
3. If the wrapper exists but is not executable, invoke its Python entrypoint directly.
4. If the wrapper is unavailable, use `uv run --isolated --with pyyaml python3 "$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py" <skill>`.
5. Use direct `python3 .../quick_validate.py` only when its dependencies are already available or `uv` is inappropriate.
6. Smoke-test every newly added helper script with a real invocation.

Treat this wrapper as the canonical local entrypoint, not as a replacement for the system skill's validation contract.
