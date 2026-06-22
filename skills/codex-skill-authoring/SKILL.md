---
name: codex-skill-authoring
description: Create or update Codex skills for the user's workflows. Use when turning repeated work into a repo or personal skill, tightening a skill's frontmatter description, deciding whether guidance belongs in AGENTS.md, SKILL.md, or references, or capturing post-mortem lessons without bloating prompts.
---

# Codex Skill Authoring

## Overview

Create skills that trigger reliably and stay small.
Keep `AGENTS.md` as the short policy/index layer, keep `SKILL.md` procedural, and move detailed notes, examples, and post-mortems into `references/`.

## Place The Skill Correctly

- Put cross-repo habits, local environment practices, and reusable authoring conventions in `~/.codex/skills`.
- When the workflow is driven by host-level state such as `~/.codex/rules`, `~/.cursor/cli-config.json`, downloaded local archives, or Codex session/history mining, default to a personal skill even if the investigation started from a repository checkout.
- Put repo-specific workflows, internal paths, repo-only scripts, and design notes in the repository's `.agents/skills/<skill-name>/` directory.
- Keep it repo-local only when the normal runtime really depends on repo-owned scripts, fixtures, or policy. Do not mirror a host-level workflow into a repo skill just because that repo happened to be open when the friction was discovered.
- Do not create a personal skill that hard-codes one repository's paths, secrets, or policies.

## Follow This Workflow

1. Start from two or three concrete user phrasings that should trigger the skill.
2. Write the frontmatter `description` before writing the body.
3. Keep `SKILL.md` focused on workflow, decisions, and resource loading rules.
4. Move long notes, pitfalls, and examples into `references/`.
5. Add a script only when the work is repetitive or fragile enough to justify deterministic automation.
6. Validate the finished skill before installing or committing it.

## Apply User-Specific Rules

- Keep `AGENTS.md` terse. Store only distilled reminders there and link to the skill or reference file instead of duplicating detailed guidance.
- When a new skill is repo-local and the repo tracks `docs/PROJECT_STATE.md` and `docs/PROJECT_TODO.md`, update those files in the same task.
- If the same workflow keeps reappearing across repositories, prefer a personal skill plus a short `AGENTS.md` pointer over repeating the full procedure in every repo.
- Name important variants in the description when they affect triggering. Do not accidentally narrow a skill to Windows-only if it should also cover macOS or other supported variants.
- Rewrite the description until another Codex instance could decide to load the skill from the frontmatter alone.
- When a skill or reference suggests repeated escalated commands, prefer examples that call the real executable directly so approval prefix rules can match stable argv forms; avoid `bash -lc` / `/bin/zsh -lc` examples unless shell syntax is essential to the workflow.
- When a skill or reference creates temporary artifacts, prefer task-scoped directories plus explicit cleanup guidance over fixed `/tmp/foo` paths that silently accumulate across sessions.

## Use These Creation Defaults

- Prefer `python3 "$HOME/.codex/skills/.system/skill-creator/scripts/init_skill.py" <skill-name> --path ~/.codex/skills` for personal skills, or `python3 "$HOME/.codex/skills/.system/skill-creator/scripts/init_skill.py" <skill-name> --path .agents/skills` for repo-local skills.
- Prefer `"$HOME/.codex/skills/codex-skill-authoring/scripts/codex_skill_validate.py" ...` to validate one or more skills through the local wrapper. The wrapper calls the installed OpenAI validator at `$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py`; do not edit or mirror OpenAI's validator for user-specific workflow changes.
- If the wrapper is unavailable, fall back to `uv run --isolated --with pyyaml python3 "$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py" ...` for direct single-skill validation.
- Fall back to `python3 "$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py" ...` only when the needed dependency is already available locally or when `uv` is not the right tool for the environment.
- Use the Python entrypoint directly if the helper wrapper exists but is not executable in the current environment.

## Check The Description

- State the main job first.
- Include two to four concrete triggers or contexts.
- Mention relevant platforms or variants when they materially change invocation.
- Keep body-only details out of the frontmatter.
- Read `references/description-patterns.md` when naming or description scope is the hard part.

## Validate And Iterate

- Run quick validation before installation or commit. For many skills, use `"$HOME/.codex/skills/codex-skill-authoring/scripts/codex_skill_validate.py" --report .codex-tmp/skill-validation/report.json <skill> [...]` so stdout stays compact and complete results go to a task-scoped file.
- Smoke-test any newly added script with at least one real invocation.
- If `quick_validate.py` cannot run directly because local dependencies such as `PyYAML` are missing, first retry via `uv run --isolated --with pyyaml ...`.
- If the `uv` path is unavailable, inappropriate, or still fails, fall back to explicit checks: parse `agents/openai.yaml`, verify `SKILL.md` frontmatter/body structure, and confirm referenced resources exist.
- If the intended update depends on an external reference that is unreadable in the current environment, stop and ask for a local copy or excerpt instead of shipping a placeholder-only update.
- After real usage, update the skill with the exact friction that appeared instead of adding generic prose.
