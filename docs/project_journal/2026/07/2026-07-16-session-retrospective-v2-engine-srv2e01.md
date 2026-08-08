---
id: 20260716-srv2e01
title: Session Retrospective v2 Engine
status: completed
created: 2026-07-16
updated: 2026-08-08
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
- Retained path detection also rejects relative POSIX and Windows-style paths
  across extractor results, episode reviews, retained artifacts, and reports.
- Session-shards transport limits each record to 1,024 data frames and binds
  that limit through producer metadata, relay validation, adapter output, and
  orchestrator ingestion so compact-frame fanout cannot bypass output budgets.
- Run creation derives `run_ref` from the frozen specification and rejects a
  caller-supplied mismatch. The trusted clock owns `created_at`; an optional
  caller value is only an equality assertion and cannot extend raw retention.
- The delivery branch preserves the signed v2 implementation as the second
  parent of an ordinary merge onto current `master`. It retains the current v1
  safety behavior and the explicit-only retrospective trigger while keeping v1
  comparison-only during shadow validation.
- CLI and source-continuation fixtures now derive one current run timestamp or
  carry the same injected clock across restart. Tests therefore exercise input
  and continuation contracts instead of expiring their own seven-day raw-state
  retention as wall time advances.
- Synthetic history-topology merges disable inherited `commit.gpgsign`; those
  fixtures validate graph semantics and no longer depend on the operator's GPG
  configuration.
- Source continuation uses the closed `source_transport_resume_v4` position,
  independently reconstructs each outgoing cursor from captured evidence, and
  spends one shared bounded probe budget. It detects changes intersecting the
  accepted trailing probe without claiming arbitrary deep-history stability.
- Session-shards descriptor cursors bind stable source identity, frozen byte and
  record coordinates, and a full-prefix commitment. Records mode verifies the
  complete frozen prefix into an owner-only range spool before any frame is
  emitted; later appends remain outside the frozen snapshot.
- Descriptor pages now stop at the 1,024-frame records budget and form one
  contiguous multi-request chain. The adapter binds every continuation response,
  validates all descriptor pages before raw replay, and the coordinator proves
  the complete catalog range across all resulting records segments.
- Source token v2 includes access-policy identity and platform generation or
  birth-time evidence when available. Filesystems without either field retain an
  explicit same-inode, byte-identical replacement non-guarantee; full-prefix
  hashing still rejects content drift. Fragment relays bind every logical record
  coordinate and encoding field across continuation frames.
- Bounded history, publication, and remote-helper subprocesses close their
  task-owned process group while the unreaped leader still pins the PID/PGID,
  including the successful leader-exit path.
- Agent results enforce depth, node, container, key, string, and aggregate
  overlap-input bounds before privacy processing. Extractor output that repeats
  sealed prompt or tool text is rejected before deterministic post-redaction,
  so post-redaction cannot turn a raw-source echo into an accepted result.
- Production automation validation rejects shadow backfill, controlled-gap, and
  host-selection controls. Export validates the run-specific retention deadline
  before staging or descriptor persistence and reuses the immutable staged
  deadline across interrupted retries.
- CLI export anchors its publication timestamp after retention-deadline
  selection. A deadline generated immediately after a UTC second boundary can
  therefore remain at the exact 72-hour policy ceiling without being compared
  against an earlier subsecond timestamp.

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
- Final Python 3.13 full suite: 1,455 tests in 522.599 seconds, `OK`.
- Review-fix Python 3.13 full suite: 1,460 tests in 676.825 seconds, `OK`.
- Privacy, transport, and module-boundary review-fix suite: 148 tests in 9.323
  seconds, `OK`; orchestrator suite: 58 tests in 92.084 seconds, `OK`.
- V2 runtime/test suite: 370 tests in 466.302 seconds, `OK`.
- V1 zero-difference retrospective suite: 891 tests in 40.549 seconds, `OK`.
- Publication transaction suite: 30 tests in 298.021 seconds, `OK`.
- Official v2 CLI suite: 26 tests in 19.731 seconds, `OK`.
- Skill structure suite: 28 tests, `OK`; validator-wrapper suite: 11 tests,
  `OK`; OpenAI quick skill validation: `Skill is valid!`.
- Source-transport suite: 29 tests, `OK`; orchestrator suite: 56 tests, `OK`;
  module-boundary suite: 17 tests, `OK`.
- Continuation and review-fix evidence: source transport 35 tests, session-shards
  transport/adapter 45 tests, result/CLI 83 tests, orchestrator/identity/results
  139 tests, and publication transaction 31 tests, all `OK`. The publication
  suite ran outside the Desktop sandbox because sandboxed `gpg-agent` startup is
  unavailable; its temporary GNUPG home and assertions were otherwise unchanged.
- Independent read-only source-continuation audit: `No findings.`
- Follow-up transport review found four issues: continuation response coordinates,
  descriptor/records frame-budget mismatch, same-inode replacement identity, and
  fragment-coordinate drift. All four were fixed; the focused transport,
  adapter, and orchestrator group passed 108 tests in 75.004 seconds, including a
  1,025-record two-page end-to-end acceptance case.
- Architecture inventory: 52 package modules and 50,726 physical lines. The
  principal facades are `orchestrator.py` at 688 lines and `finalize.py` at 87;
  the largest transport units are `transport_source.py` at 1,641,
  `transport_program.py` at 375, and `transport_remote.py` at 283. The public
  CLI is 1,919 lines; its transcript helper is 176 lines and the source-segment
  coordinator helper is 120 lines.
- Final sandboxed Python 3.13 discovery found 1,463 tests in 180.124 seconds.
  Every runnable test passed; the durable-publication class stopped in
  `setUpClass` because sandboxed `gpg-agent` startup cannot generate its
  temporary signing key. The export deadline boundary regression and its two
  adjacent trend-history cases passed 3 tests in 4.457 seconds.
- Ruff lint/format checks, Actionlint 1.7.12, and `git diff --check` passed for
  the merged v2 scope.
