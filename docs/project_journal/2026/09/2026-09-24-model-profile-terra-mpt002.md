---
id: 20260924-mpt002
title: PR Attribution Terra Fallback
status: active
created: 2026-09-24
updated: 2026-09-24
branch: codex/daily-skill-friction-20260924-codex-workflow-hygiene-model-profile-terra
pr:
supersedes: []
superseded_by:
---

# PR Attribution Terra Fallback

## Summary
- Change the PR attribution fallback label from Sol Ultra to GPT-5.6 Terra Ultra.
- Keep historical Sol labels only for interpreting older rollout records.

## Current State
- The session-mining skill, attribution helper, and tests use the Terra Ultra fallback.
- The skill validator and 74 attribution tests pass.

## Next Steps
- Land the validated local change and synchronize the public skill release.

## Evidence
- Worktree: `codex/daily-skill-friction-20260924-codex-workflow-hygiene-model-profile-terra`
- Skill validation: `codex_skill_validate.py` reports `Skill is valid!`.
