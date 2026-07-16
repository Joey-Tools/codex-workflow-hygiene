---
id: 20260716-srv2e01
title: Session Retrospective v2 Engine
status: completed
created: 2026-07-16
updated: 2026-07-16
branch: wip/session-retrospective-v2-engine-clean
pr: 43
supersedes: []
superseded_by:
---

# Session Retrospective v2 Engine

## Summary

- Added the modular deterministic coordinator, source adapter, checkpoint and
  identity layer, result validation, episode/topic reducers, reporting, export,
  publication recovery, and closed JSON CLI for Session Retrospective v2.

## Current State

- The engine operates on bounded source streams and native-agent result files;
  it does not invoke models or SSH itself.
- Source, job, publication, and cleanup state use authenticated durable claims
  with explicit retry and gap behavior.
- Source and agent raw-data entrypoints reject work after retention expiry;
  ordinary status and advance paths drive the authenticated cleanup flow.
- Session-shards transcripts close descriptor-pass file descriptors before
  returning lazy, replay-validated record streams.
- Remote helpers run under isolated Python with sanitized injection variables;
  timeout and output-limit cleanup terminates the complete helper process group.
- Extractor gaps omit affected logical turns and reach a stable blocked state,
  while overlap checks reassemble full records before inspecting exact fields.
- Hierarchical synthesis keeps complete validation inputs in bounded leaf
  tasks while parent envelopes carry only child results and necessary refs.
- Durable safety exceptions require a high-severity negative event, finding,
  or high-impact issue; positive strengths cannot trigger the exception.
- Durable-history verification isolates Git configuration, pins the OpenPGP
  verifier, and rejects any retained-history commit that does not add exactly
  one canonical eight-artifact bundle.
- Publication recovery can advance provider state when the exact signed
  publication remains reachable below an unrelated successor commit.
- Retained episode, topic, turn, and global artifacts preserve opaque evidence
  lineage without retaining raw prompts or excerpts.
- Extractor goal/workstream evidence is bound per turn, and backfill matching
  requires a stable turn or goal anchor rather than a session-default workstream.
- Hierarchical episode review conserves every high/critical child risk,
  adjudication, and evidence reference; omission rejects the parent result.
- Retained exports preserve episode supersession, review attempt provenance,
  actual reviewed high-impact rewrites, complete non-sensitive execution
  provenance, and compatible prior-period trend inputs from the official CLI.
- The installed v2 CLI exposes exactly eight public commands and a shadow-only
  Daily direct-successor backfill. A separate cutover controller uses the
  authenticated internal authority API for the two stable production IDs;
  missing `automation_update` capability or reference-only/unrelated automation
  state keeps production cutover blocked.
- The coordinator and publication paths use explicit bounded modules: the
  stable `orchestrator.py` and `finalize.py` facades are 676 and 87 lines, while
  stateless capability, transaction, provider, and validation modules remain
  independently importable and below the enforced 5,000-line ceiling.
- OpenPGP verification accepts a signing subkey only when `VALIDSIG` binds it to
  the configured primary fingerprint; ref creation derives the zero OID width
  from the repository object ID, and GC reclaims authenticated export orphans
  after the maximum 72-hour retention bound.
- Topic reduction rejects missing review-required revisions, requires an exact
  candidate-item adjudication trace, and enforces one final result per expected
  topic root before synthesis.
- Remote session-shard relays require exact host/rollout wrappers, reject mixed
  or replayed streams, and enforce a range-derived streaming output bound.
- Superseding episode review blocks on missing prior turn material; publication
  successors preserve session identity, and retained prose rejects raw prompt,
  tool-output, source-payload, and internal-ID markers.
- Agent task reuse records conserved cache hit/miss/reuse metrics. Public export
  has no sibling-directory GC side effect, and sanitized CLI failures include
  allowlisted reason and recovery fields.
- The v1 helper remains available only for migration-time non-publishing
  comparison until the separate shadow, cutover, and baseline work completes.
- Tests bind a checked-in read-only `remote-host-context` fixture instead of an
  operator-installed helper, so CI validates the adapter contract without
  depending on `/home/runner` machine state.
- Retained path detection now recognizes absolute POSIX paths independently of
  the first directory component, including `/root`, `/usr`, and `/workspace`.
- Run creation derives `run_ref` from the frozen specification and rejects a
  caller-supplied mismatch. The trusted clock owns `created_at`; an optional
  caller value is only an equality assertion and cannot extend raw retention.

## Next Steps

- Integrate the canonical `remote-host-context session-shards` transport and
  private overlay shadow automation.
- Complete the two Weekly plus Daily partial/backfill shadow gate before live
  automation cutover.
- Remove the v1 monolith only after cutover and the first 90-day v2 baseline.

## Evidence

- `skills/codex-session-retrospective/scripts/session_retrospective_v2.py`
- `skills/codex-session-retrospective/scripts/retrospective_v2/`
- `skills/codex-session-retrospective/references/v2-*.md`
- `tests/test_retrospective_v2_*.py`
- `tests/test_session_retrospective_v2_cli.py`
- Final full suite: 1,318 tests in 627.187 seconds, `OK (skipped=1)`.
- Publication transaction suite: 30 tests, `OK`.
- Official v2 CLI suite: 26 tests in 27.279 seconds, `OK`.
- Source-transport suite: 29 tests, `OK`; orchestrator suite: 56 tests, `OK`;
  module-boundary suite: 17 tests, `OK`.
- Architecture inventory: 49 package modules and 48,928 physical lines. The
  principal facades are `orchestrator.py` at 676 lines and `finalize.py` at 87;
  the largest transport units are `transport_source.py` at 1,648,
  `transport_program.py` at 375, and `transport_remote.py` at 237.
- Ruff lint and format checks for 69 v2 runtime/test files, Python bytecode
  compilation, and `git diff --check` passed for the v2 scope.
