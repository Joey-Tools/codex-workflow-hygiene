# Description Patterns

Read this file when the hard part is choosing the skill name, frontmatter description, or placement.

## Use This Formula

Write the description as:

`<main capability>. Use when Codex needs to <trigger 1>, <trigger 2>, or <trigger 3> in <important contexts or variants>.`

The first clause explains what the skill does.
The second clause explains when another Codex instance should load it.

## Prefer These Patterns

- Name the repeated workflow, not the current ticket.
- Mention concrete triggers such as `create`, `update`, `review`, `triage`, `map version to commit`, or `capture repeated refactor lessons`.
- Mention platforms explicitly when they matter, for example `macOS and Windows build provenance`.
- Keep long rationale, edge cases, and examples out of the frontmatter.

## Avoid These Patterns

- Too generic: `General helper for builds and docs.`
- Too narrow by accident: `Check Windows build inclusion.` when the workflow also covers macOS.
- Trigger hidden in body only: frontmatter says what the skill is, but not when to load it.
- AGENTS duplication: copying detailed guidance into both `AGENTS.md` and the skill references.

## Decide Where Content Belongs

- `AGENTS.md`: short rules, reminders, and pointers.
- `SKILL.md`: workflow, decision rules, and resource-loading instructions.
- `references/`: detailed notes, examples, pitfalls, and post-mortems.
- Personal skill: cross-repo habits and local conventions.
- Repo skill: repository-specific procedures, paths, and scripts.

## Quick Review Checklist

- Can the description trigger the skill without reading the body?
- Does the scope cover all real variants that should trigger it?
- Is detailed guidance moved out of `AGENTS.md`?
- Is the skill stored in the right place: personal or repo-local?
