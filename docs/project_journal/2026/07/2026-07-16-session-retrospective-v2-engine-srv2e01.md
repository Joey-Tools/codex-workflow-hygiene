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
- The public v2 entrypoint requires Python 3.13 or newer and emits a closed
  machine-readable error before importing the engine on an older interpreter.
- Session identifiers use one shared bounded predicate across worker and
  coordinator parsing: nonempty UTF-8, at most 512 bytes, without C0 or DEL
  control characters.
- Source-worker program snapshots are content-addressed beneath the run-owned
  `raw-inputs` tree. Parent-only code also snapshots the installed
  `remote-host-context` helper there before lease creation. The same
  descriptor-bound read must match the run's frozen helper provenance, so a
  mid-run helper replacement cannot mix versions across leases. Missing or
  changed helpers fail before a durable lease is committed; the worker executes
  only that exact owner-only snapshot, and scheduling and acceptance verify the
  same commitment.
- Extractor gaps omit affected logical turns and reach a stable blocked state,
  while source overlap validation verifies sealed fragments incrementally and
  streams every decoded JSON string value into bounded normalized overlap
  windows. Long escaped values and surrogate pairs remain covered. Only
  schema-authorized extractor working text is projected on the result side. A
  fixed-size chunk queue avoids repeated growing-string copies for single-character
  parser emissions, while source keys and metadata cannot collide with fixed
  result enums or references.
- Retained export inputs live in an owner-only, content-addressed sidecar under
  `retained-inputs`; the authenticated checkpoint stores only its descriptor.
  The sidecar is an authenticated cleanup root; shadow finalization persists a
  coverage receipt before deletion and revalidates that receipt, rather than
  reopening deleted export inputs. Exact legacy embedded v2 inputs remain
  readable, while all new writes use the sidecar and descriptor reads are capped
  at the exact committed byte count.
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
- Publication-sidecar binding and cleanup are serialized by the per-attempt
  lock. Capacity reservations persist a request-bound recovery record, migrate
  legacy integer entries only when the durable attempt, exact unit plan,
  inventory, target observation, reservation receipt, and amount all prove
  ownership, and compare-delete only the exact request and byte count under the
  capacity lock. Cleanup v3 binds the added `retained-inputs` root while replaying
  exact legacy v2 three-root claims without cross-schema adoption. A cleanup
  claim permanently fences all forward publication phases; conditional sidecar
  release closes the bind-before-attempt-flag crash window and checks the legal
  unbound no-op before validating an unrelated bundle.

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
- Current review-fix focused evidence: overlap/sidecar 6 tests in 5.050 seconds,
  affected source/result/orchestrator 157 tests in 90.986 seconds, CLI plus
  module boundaries 46 tests in 24.933 seconds, and publication invariants 5
  tests in 0.691 seconds, all `OK` under Python 3.13. The modularity guard
  measured 7,422 branch nodes against a narrowly adjusted 7,450 ceiling;
  `orchestrator_history.py` is 907 lines after extracting deterministic sidecar
  and overlap owners.
- Final audit-fix evidence so far: result/export/orchestrator coverage passed
  171 tests in 79.616 seconds; the remaining non-publication v2 modules passed
  227 tests in 47.310 seconds; module boundaries passed 17 tests in 1.455
  seconds. Focused regressions cover metadata-versus-prose overlap, whitespace-
  dense batch bounds, legacy retained inputs, retained-input expiry, conditional
  sidecar release, cleanup-claim monotonicity, bind-window recovery, and legacy
  capacity ownership. The temporary-GPG publication suite remains a distinct
  host-level gate and is not counted by these sandboxed results.
- Current Python 3.13 sandbox discovery ran 1,474 tests in 175.843 seconds.
  Every runnable test passed; the only error was the durable-publication class
  setup, where sandboxed GPG exited 2 while generating its disposable signing
  key. Skill structure, validator-wrapper, and module-boundary coverage passed
  56 tests in 4.734 seconds. The host-level publication rerun remains pending
  explicit authorization and is not inferred from these results.
- Final-audit Python 3.13 discovery found 1,480 tests in 192.614 seconds. Every
  runnable test passed; the only error was the same sandbox-only disposable GPG
  setup. An initial full run exposed one stale remote output-limit fixture that
  omitted the new helper snapshot binding. The fixture now materializes a real
  content-addressed helper snapshot; its exact regression and the complete
  session-shards transport module passed 1/1 and 40/40 respectively before the
  clean discovery rerun. The affected result/export/source/orchestrator/
  publication group discovered 215 tests in 106.884 seconds with only the same
  GPG class setup error; all 214 runnable tests passed.
- The history repository is now public and history PR #4 has a current-head
  GitHub Codex clean terminal artifact plus a successful ordinary `test` check.
  Organization ruleset 16590367 still requires the absent
  `codex/review-gate` status. Public visibility does not create that status.
  `master` contains no compatibility publisher, while the candidate-only
  `pull_request_target` workflow cannot bootstrap itself, has no dispatch event,
  and names a different head branch. Existing CI or historical-run retries
  therefore cannot unblock the current head. The durable repair is a separately
  reviewed minimal default-branch compatibility-publisher bootstrap followed by
  one authenticated open-PR backfill; no duplicate same-head Codex request is
  needed.
- Three bounded pre-commit audits reached terminal findings after the final
  discovery. The follow-up closes strict primitive parsing and control-value
  projection in `source_overlap.py`, terminal replay removal of legacy retained
  inputs, and post-read helper snapshot access-policy revalidation. New
  regressions cover invalid primitive/string smuggling, role metadata versus
  short source prose, commitment-to-execution snapshot mutation,
  output-to-acceptance snapshot mutation with unchanged cursors, and legacy
  retained payloads attached after published, shadow, and expired terminal
  cleanup. Eight focused tests covering those paths passed under Python 3.13;
  one mistyped test selector was a non-counting invocation and its intended
  test passed on the corrected run. The complete affected result, source
  transport, and orchestrator modules then passed 168 tests in 102.802 seconds.
- The post-audit Python 3.13 discovery found 1,484 tests in 186.773 seconds.
  Every runnable test passed; the sole error was
  `DurablePublicationTests.setUpClass`, where sandboxed GPG exited 2 while
  generating the suite's disposable signing key. This does not count as a
  publication-transaction pass, so the unchanged host-level temporary-GPG gate
  remains required before the signed candidate head is frozen.
- The public history mirror remains clean and current, but the first sandboxed
  `prepare-run` retry could not resolve `github.com`. The corresponding
  host-network retry was cancelled before completion and is non-counting; no
  bootstrap branch or worktree was claimed from that attempt.
- On the same candidate tree, scoped Ruff 0.13.2 lint and format checks passed
  for 65 Python files, `git diff --check` passed, the module-boundary suite
  passed 17 tests in 1.401 seconds, project-journal validation passed, and the
  OpenAI skill validator reported `Skill is valid!`.
- The 16 current-scope GitHub Codex findings on the prior `80d9b0e` head were
  re-enumerated before freezing the follow-up. They cover the explicit Python
  3.13 startup contract, in-repo remote-helper provenance, session-id controls,
  durable helper snapshots, retained-export sidecars and deadlines, source and
  result sink setup, cutover exclusions, and replay idempotency; the current
  implementation and regressions address each category, but only a fresh
  frozen-head review may classify the follow-up as clean.
- Two additional exploratory pre-commit agents were started read-only against
  the complete dirty diff. Neither produced a terminal artifact within the
  15-minute observation bound; both were closed once while still running and
  are recorded as transport-inconclusive and non-counting. No partial output was
  accepted and no replacement exploratory reviewer was started.
- A subsequent parent audit found that two prior-head P2 findings were not yet
  closed: the public source action named a per-lease capture directory without
  creating it, and a claimed agent action named a result sink without creating
  the required 0600 file. Source scheduling now materializes and binds the 0700
  per-lease directory inside its checkpoint transaction, while public status
  projection only authenticates the existing path before exposing it. Agent
  claim, heartbeat, and idempotent replay now materialize or authenticate the
  owner-only regular result sink without truncating existing output. The tests
  no longer perform hidden `mkdir` or `chmod` setup; two exact regressions passed
  in 2.319 seconds, and the complete orchestrator plus v2 CLI modules passed 96
  tests in 112.391 seconds.
- After moving result-sink ownership into the canonical agent-job module, the
  two exact regressions passed again in 2.302 seconds, module boundaries passed
  17 tests in 1.468 seconds, and the complete orchestrator plus v2 CLI modules
  passed 96 tests in 112.799 seconds. One earlier instance of that 96-test run
  exited after its PTY receipt was lost during context compaction; it remains
  explicitly non-counting.
- The final sandboxed Python 3.13 discovery found 1,484 tests in 195.601 seconds.
  Every runnable test passed; the sole error remained
  `DurablePublicationTests.setUpClass`, where sandboxed GPG exited 2 while
  generating the disposable Ed25519 fixture key. The host-level publication
  suite remains required and is not inferred from this result. Ruff 0.13.2
  lint and format checks passed for all 38 changed Python files,
  `git diff --check` passed, project-journal validation passed, and the OpenAI
  skill validator reported `Skill is valid!` through its isolated `uv` runtime.
- After the history repository became public, a new sandboxed `prepare-run`
  attempt still failed only because sandbox DNS could not resolve `github.com`.
  The requested host-network retry was rejected before execution because fetch
  plus branch/worktree creation lacked separately explicit side-effect
  authorization. No history branch, worktree, or repository state was changed.
- A fresh read-only pre-commit reviewer then found four actionable gaps: stale
  status could recreate a per-lease raw directory after expiry cleanup; overlap
  normalization copied a growing string for every ordinary JSON character;
  later remote leases did not compare their live helper to frozen run
  provenance; and Python 3.9 could not parse the CLI far enough to emit its
  closed unsupported-runtime result. The fixes move directory creation into the
  scheduling transaction, use bounded deque-backed normalized chunks, derive and
  compare helper provenance from the snapshot's descriptor read, and replace
  entrypoint-only union syntax with parse-compatible `Optional` annotations.
  Four exact regressions passed in 0.569 seconds. A first affected 218-test run
  exposed one stale facade patch and the deliberately narrow branch-budget
  increase; both exact corrections passed 2/2 in 1.037 seconds, and the complete
  source-transport plus module-boundary modules passed 61/61 in 18.938 seconds.
- The resulting sandboxed Python 3.13 discovery found 1,488 tests in 183.558
  seconds. Every runnable test passed; the sole error was again
  `DurablePublicationTests.setUpClass`, where sandboxed GPG exited 2 while
  generating its disposable Ed25519 key. The host-level publication suite is
  still required and is not inferred from this result. Scoped Ruff lint and
  format checks, `git diff --check`, project-journal validation, and the isolated
  OpenAI skill validator all passed on the same implementation and documentation
  state.
- Joey then authorized the host-level disposable-GPG publication gate. Its first
  run exposed two stale test contracts rather than production failures: three
  retained-input helpers omitted the coordinator now required for authenticated
  sidecar reads, and a same-root ownership test built two distinct source
  snapshots even though current provenance intentionally gives them different
  cursor roots. The tests now pass the coordinator and exercise a byte-identical
  copied run under a distinct publication attempt. The exact repaired case passed
  1/1 in 12.432 seconds; the complete publication module passed 38/38 in 400.348
  seconds with its temporary Ed25519 key and repositories cleaned normally.
- The final host Python 3.13 discovery passed all 1,521 tests in 775.720 seconds.
  This run includes the publication transaction suite and therefore supersedes
  the earlier sandbox-only discovery gaps; no test was skipped or inferred from
  a setup failure.
