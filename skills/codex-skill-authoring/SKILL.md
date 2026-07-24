---
name: codex-skill-authoring
description: Apply the user's placement, instruction-layering, validation-wrapper, and approval-friendly argv conventions while creating or revising a Codex skill. Use together with the system `$skill-creator` when deciding between personal and repo-local placement, moving guidance among AGENTS.md, SKILL.md, and references, validating one or more skills through the local wrapper, or writing examples that should match stable approval prefixes.
---

# Codex Skill Authoring

Use the system `$skill-creator` for scaffolding, frontmatter design, generic
skill structure, `agents/openai.yaml`, validation principles, and forward
testing. This skill adds only the user's local conventions.

## Choose Placement

- Put cross-repo habits and host-level workflows in the personal skill
  collection.
- Put repository-specific procedures, paths, fixtures, and scripts in
  `.agents/skills/<skill-name>/`.
- Do not create a repo-local mirror merely because that repository was open when
  a host-level workflow was discovered.
- Do not put repository secrets, hard-coded private paths, or repo-only policy
  into a personal skill.

## Choose The Instruction Layer

- Keep `AGENTS.md` to short standing policy, authorization boundaries, and
  pointers.
- Keep `SKILL.md` to trigger-relevant workflow, decision rules, and reference
  routing.
- Put detailed contracts, schemas, examples, and post-mortems in
  `references/`.
- Add a script only when repeated work benefits from deterministic behavior.

## Validate Through The Local Wrapper

Use the installed wrapper for one or more skills:

```bash
"$HOME/.codex/skills/codex-skill-authoring/scripts/codex_skill_validate.py" \
  --report <task-scoped-report.json> \
  <skill-path> [...]
```

The wrapper delegates to the installed system `$skill-creator` validator. Do not
fork or edit that validator to add user-specific policy. If the wrapper is not
executable, invoke it with Python; if it is unavailable, use the system
validator directly and report the fallback.

## Keep Examples Approval-Friendly

- Prefer the real executable with direct argv so approval rules can match a
  stable command prefix.
- Use `bash -lc` or another shell wrapper only when a real shell feature is
  required.
- Pass dynamic paths, URLs, and patterns as argv instead of embedding them in
  nested shell text.
- Use task-scoped temporary paths and state the cleanup or retention decision.

After applying these conventions, return to `$skill-creator` for validation and
forward testing.
