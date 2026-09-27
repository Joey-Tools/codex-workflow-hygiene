---
id: 20260918-cwh008
title: Codex Review Gate v2 Handoff
status: completed
created: 2026-09-18
updated: 2026-09-27
branch: wip/remove-v1-bridge-workflow-hygiene
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate v2 Handoff

## Summary

- The post-cutover receipt was restored and verified at the exact SHA
  `9a8b38f2188a14168423a07639d6662c87e198fe2dd12041f67fc224f363817e`.
- The verifier and controller now use the canonical v2 action directly; the v1
  status-producer bridge has been removed after the organization-wide cutover.

## Current State

- `codex/github-review-gate` is produced by the canonical pull-request verifier using `JoeyTeng/codex-review-gate-action@v2`.
- The controller provides bot-comment and manual-dispatch recovery entry points using the same canonical v2 action.
- The restored post-cutover receipt was verified before replacing the remaining v1 bridge, so no legacy v1 workflow remains in this repository.
- CODEOWNERS protects the workflow control plane under `@JoeyTeng` ownership.

## Completion

- This handoff is complete. Future changes should treat the canonical v2 verifier and controller as the only review-gate workflow surface.

## Evidence

- `.github/workflows/codex-review-gate.yml`
- `.github/workflows/codex-review-gate-controller.yml`
- Removed: `.github/workflows/codex-review-gate-legacy-bridge.yml`
- `.github/CODEOWNERS`
- Restored post-cutover receipt SHA:
  `9a8b38f2188a14168423a07639d6662c87e198fe2dd12041f67fc224f363817e`
