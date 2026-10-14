---
id: 20260918-cwh008
title: Codex Review Gate v2 Handoff
status: completed
created: 2026-09-18
updated: 2026-10-01
branch: codex/daily-skill-friction-2026-09-29-codex-workflow-hygiene-remove-v1-bridge
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate v2 Handoff

## Summary

- Complete the v2 review-gate handoff and retire the temporary v1 status producer after the organization cutover.

## Current State

- `codex/github-review-gate` is produced by the canonical pull-request verifier using `JoeyTeng/codex-review-gate-action@v2`.
- The verifier has read access to Actions workflow-run metadata in addition to its existing repository, issue, and pull-request permissions.
- The controller provides bot-comment and manual-dispatch recovery entry points.
- The temporary `codex/review-gate` legacy bridge workflow has been removed.
- CODEOWNERS protects the workflow control plane under `@JoeyTeng` ownership.

## Evidence

- `.github/workflows/codex-review-gate.yml`
- `.github/workflows/codex-review-gate-controller.yml`
- `.github/CODEOWNERS`
- Post-cutover receipt SHA-256: `9a8b38f2188a14168423a07639d6662c87e198fe2dd12041f67fc224f363817e`.
