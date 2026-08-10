---
id: 20260716-srv2e01
title: Session Retrospective v2 Engine
status: completed
created: 2026-07-16
updated: 2026-08-10
branch: codex/session-retrospective-v2-engine-linear
pr: 67
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
  a nonblocking monotonic relay deadline remains enforceable even when a
  detached descendant inherits stdout, while timeout and output-limit cleanup
  terminates and reaps the task-owned helper process group.
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
- Durable-history verification now walks the complete bounded reachable graph
  and evaluates `runs/` against every parent edge. A root that introduces
  retained history or a merge that changes it relative to any parent fails
  closed; a merge whose retained tree is identical to every parent remains
  valid.
- An existing publication journal is fully re-derived against the current run,
  bundle inventory, durable head, cursor transition, and episode transition
  before the coordinator may persist a publication claim. Abort replay instead
  proves the static plan and authenticated current-run claim before recovering,
  so an intentionally advanced durable head cannot strand cleanup while a
  copied journal still cannot reserve or mutate another run.
- Cleanup v5 authenticates a bounded owner-only sidecar descriptor for the
  globally bytewise-sorted per-object inventory of all four fixed roots. It
  writes inventory-sidecar v2 with a SHA-256 content commitment for every file
  while retaining authenticated contentless v1 sidecars only for legacy replay.
  It revalidates every root twice, then records restart-safe progress in a
  claim-scoped quarantine. Same-size replacement, unproved removal, shrinkage,
  type or access-policy drift fail closed; timestamp-only and verified
  child-deletion directory metadata changes remain benign. Legacy v2/v3/v4
  claims retain schema-scoped replay semantics.
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
- Source token v4 includes access-policy identity and platform generation or
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
- Durable-history Git commands disable environment-selected grafts and reject
  repository-local graft files before use and on revalidation, so forged ancestry
  cannot satisfy publication or authority reachability checks.
- Active-rollout discovery now walks the complete bounded year/month/day tree
  instead of a seven-day date heuristic. It binds descriptor-relative directory
  identity and type-aware entry snapshots, then revalidates every snapshot before
  a successful terminal; replacement, entry churn, or exhausted bounds becomes an
  explicit coverage gap rather than a partial success.
- Active and archived discovery now share a fixed 250,000-entry, 64 MiB path,
  30-second budget. Archived directory dates are not treated as event-time
  authority, and every terminal outcome revalidates the root, each traversed
  directory inventory, and each selected candidate identity/access-policy token.
  Enumeration change, revalidation failure, and individual budget exhaustion
  remain distinct explicit gaps and invalidate any outgoing resume position.
- Every owner-only v2 directory and regular file rejects Darwin extended ACLs.
  Newly created objects clear inherited ACLs through their held descriptors
  before publication; bounded reads, locks, publication state, retained export,
  GPG keyring validation, cleanup, and session-shard spools revalidate the same
  access-policy property without treating timestamp-only changes as mutation.
- JSON source-overlap control keys exempt only exact case-sensitive, per-field
  allowlisted direct scalar values. Unknown classifier values, including
  identifier-shaped model, schema, provider, and status values, remain untrusted
  source-bearing text. Nested objects, arrays, malformed values, arbitrary
  suffix-shaped keys, and Unicode case-fold aliases likewise cannot bypass the
  retained-output overlap gate.
- Retained-export garbage collection has no publication transaction authority.
  It keeps every authenticated `publication_bound` bundle until the exact
  attempt owner persists a terminal disposition; age alone cannot synthesize an
  abort or authorize deletion.
- Retained privacy scanning and deterministic post-redaction recognize every
  bounded hierarchical URI scheme, including one-letter schemes, rather than an
  HTTP/SSH allowlist that could retain another URL form.
- Session-shards transcript segmentation is lazy and constant-space across large
  frame pages. An abandoned records iterator closes its replay immediately even
  while the outer segment iterator remains live; complete pages keep one replay
  open only for the next contiguous records request.
- Source acceptance now places bounded raw payload indexes and complete transport
  segments in owner-only content-addressed sidecars. The checkpoint retains only
  authenticated descriptors and compact terminal summaries; same-schema legacy
  full manifests and inline continuation payloads are conflict-checked and migrated
  on the next acceptance. Segmented input first uses one descriptor-held owner-only
  spool, retains only one bounded record in memory, derives transcript/acceptance
  commitments from compact descriptors, and removes the spool on every terminal
  path. Final raw files and the acceptance sidecar remain checkpoint-coupled.
  Rollback proves identity, exact bytes, single-link state, and owner-only access
  policy before deleting a newly staged file.
- Claim, heartbeat, accepted-result, and rejected-result mutations now validate
  the actual candidate task and checkpoint against the 512 KiB terminal reserve.
  Capacity failure restores the prior active claim, clears only candidate
  envelope/sink/result staging, and records a content-free blocker.
- Session state binds every canonical host key, derived host reference, source-cell
  host reference, and all four required source kinds. Result privacy preserves a
  reference-shaped value against source-overlap redaction only when the parent has
  independently supplied that exact value in the job allow-list.
- Short source values from 4 through 11 normalized characters use token-boundary
  matching, so embedded identifiers such as `Acme` are removed without treating a
  longer token such as `Acmeology` as the same source value.
- Working-zone redaction and retained validation cover generic bare FQDNs in
  addition to protocol URLs, private hosts, and paths. Fixed report taxonomy and
  artifact names remain closed renderer/schema values rather than prose exceptions.
- Durable-history and publication Git commands share one local-only environment,
  reject shallow/promisor/partial-clone repositories before object reads, disable
  lazy fetch and credential helpers, and preserve caller-specific error contracts.
- Durable publication replay uses the static authenticated run binding only after
  a legal durable transaction phase exists; prepublication phases still require
  the original live-history precondition. Finalization loads the commitment from
  the reachable exact publication commit while provider-cache validation remains
  bound to the current durable-history head, so an unrelated successor commit does
  not strand cleanup or weaken current-head integrity.
- A committed export remains publication-bound until both the outer transaction
  journal and the run's cleanup-pending checkpoint are durable. Only then may the
  sidecar become terminal; recovery accepts a fully collected bundle/sidecar pair
  but rejects one-sided disappearance as a conflict.
- The transport boundary is an exact 14-module inventory at 7,214 lines under a
  7,250-line aggregate ceiling. The contract fails on membership drift, individual
  module drift, or aggregate growth instead of relying on an approximate total.
- The public finalize command advances exactly one durable publication phase per
  invocation and releases a publication-bound export only after the transaction
  reaches `committed` and the cleanup-pending checkpoint is durable. Aborted and
  intermediate phases preserve their own disposition without committed release.
- Publication artifact reads protect descriptor identity, owner/mode/link/ACL
  policy, and the expected digest before and after reading. Timestamp-only changes
  trigger the proof but are not mutation evidence.
- Export GC uses a descriptor-anchored iterative walk with global entry, depth,
  path-byte, deadline, and result-sample budgets. Schema-v3 receipts retain full
  counts and typed incomplete reasons without unbounded path arrays.

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
- A fresh whole-range reviewer found five follow-up gaps: repository-local Git
  grafts remained admissible, active discovery could omit an old still-appending
  session, URI detection covered only selected schemes, transcript segmentation
  materialized a complete child stream, and cleanup documentation still described
  three roots after the v3 retained-input addition. The fixes include exact graft
  rejection, complete bounded active-tree discovery plus terminal directory
  snapshot revalidation, generic URI recognition before and after redaction,
  lazy stream iteration, and the four-root/legacy-three-root recovery contract.
- The host-level disposable-GPG publication module passed 39/39 tests in 493.549
  seconds. The current source/adapter/result/export group passed 162/162 in 23.428
  seconds; source transport passed 45/45 in 20.909 seconds; module boundaries
  passed 17/17 in 1.579 seconds; and the added abandoned-replay regression plus
  its complete adapter module passed 11/11 in 1.913 seconds. Ruff and
  `git diff --check` passed on the same current diff.
- The final host Python 3.13 discovery passed all 1,527 tests in 699.543 seconds.
  This run includes the disposable-GPG publication transaction suite and
  supersedes every earlier partial or sandbox-limited discovery result; no test
  was skipped, inferred, or carried forward from another tree.
- The next frozen-range reviewer found five additional gaps: owner-only checks
  omitted Darwin extended ACLs; archived discovery trusted directory dates as a
  prefilter; successful terminal proof did not bind every directory/candidate;
  nested containers under control keys inherited an unsafe overlap exemption;
  and directory enumeration used a derived high memory ceiling. The current
  fixes add descriptor ACL enforcement and inherited-ACL removal, one fixed
  discovery resource contract with terminal revalidation on every outcome,
  event-time filtering after bounded archive discovery, and direct-scalar-only
  control exemptions.
- Current focused Python 3.13 evidence covers 296 distinct affected tests:
  identity/safe I/O 31/31, source transport 52/52, result/episode overlap 60/60,
  checkpoint security 10/10, module boundaries 17/17, export 47/47,
  session-shards transport 40/40, and the host-level disposable-GPG publication
  transaction suite 39/39 in 333.263 seconds. The first host publication attempt
  used macOS's lexical `/var` alias and therefore failed the existing strict
  no-symlink-ancestor contract before the transaction cases; it is non-counting.
  Repeating the unchanged suite with the real `/private/tmp` temporary root
  passed. Scoped Ruff lint, Ruff format, Python compile, and `git diff --check`
  also pass on the current implementation.
- A subsequent host Python 3.13 discovery passed 1,539/1,539 tests in 591.564
  seconds, but two bounded pre-commit audits then found four transport-discovery
  gaps and three ACL/publication gaps. That discovery is therefore retained as
  historical evidence only and is non-counting for the final tree. The transport
  follow-up preserves the 366-day input bound, extends the fixed deadline through
  candidate opens and final sorting, distinguishes post-snapshot disappearance
  from authoritative absence, binds the root source directory as well as every
  candidate, and makes the access-policy mutation regression independent of the
  process umask. The original 7,600 branch-node and 20-large-function ceilings
  remain unchanged after extracting the source-kind traversal.
- The ACL follow-up forces each record spool to create and harden its disk backing
  before the first raw payload byte, applies the same descriptor ACL contract to
  retained-artifact writes and both sides of artifact reads, and keeps the
  dedicated publisher `GNUPGHOME` descriptor anchored while every GPG inventory
  call performs path/object revalidation before and after use. Exact regressions
  cover hardening-before-write, late artifact ACL drift, keyring path replacement,
  root/candidate disappearance, candidate-open deadline expiry, the 366-day bound,
  and deterministic mode drift. The complete affected source, session-shards,
  export, identity/safe-I/O, and result/episode suites passed 237/237 tests in
  23.401 seconds. One prior instance exposed only the now-updated spool-count
  assertion and is non-counting. Module boundaries passed 17/17, and the host
  disposable-GPG publication suite passed 40/40 in 331.326 seconds under
  `/private/tmp`.
- The final host Python 3.13 discovery passed all 1,547 tests in 575.558 seconds
  on the post-audit implementation. It includes the disposable-GPG publication
  transactions and supersedes the earlier 1,539-test run; no test, setup class,
  or cleanup result was inferred from a partial execution. Ruff lint passed,
  all 18 changed Python files passed the scoped Ruff format check, project-journal
  validation passed, the 56-test skill-structure/module/validator-wrapper group
  passed, `git diff --check` passed, and the isolated OpenAI skill validator
  reported `Skill is valid!`. A repository-wide format probe also identified
  three pre-existing unmodified test files outside this change as not Ruff-
  formatted; they were not rewritten as part of this delivery.
- Follow-up transport audits found four remaining proof gaps: duplicated
  `scandir` descriptor ownership leaked one descriptor per directory, the
  discovery deadline started after lexical root traversal, an entirely missing
  configured root could be reported as an unanchored verified absence, and
  source tokens omitted Darwin generation/birth-time evidence. Discovery now
  owns and closes every duplicated scan descriptor, creates one budget before
  root traversal and checkpoints every component open, classifies an unexpected
  missing root as an explicit source-enumeration gap, and binds the shared v4
  generation/birth-time token in both discovery and session-shards transport.
  The source/session/module group passed 118/118 tests in 21.349 seconds and the
  complete affected six-suite group passed 258/258 in 24.651 seconds. The exact
  descriptor, deadline, missing-root, and token regressions passed 7/7; the two
  module size/complexity contracts passed 2/2.
- Publication review then hardened dedicated GPG inventory around a held
  `GNUPGHOME` descriptor. A fixed isolated Python trampoline performs `fchdir`
  before `execve`, avoiding both Darwin's non-directory `/dev/fd` behavior and
  `preexec_fn` deadlock before supervision starts. Secret-key inventory is
  parsed and rejected before public-key enumeration. Every exceptional listing
  exit now revalidates anchored directory identity plus owner/mode/ACL policy;
  a safety failure takes precedence while preserving the operation failure as
  its cause. Exact descriptor/ABA/ordering/exception regressions passed 5/5,
  and the complete publication invariant class passed 10/10. Two additional
  bounded explorer audits produced no terminal artifact and were closed while
  still running; they are transport-inconclusive and non-counting. The formal
  frozen-head review remains independently required.
- The final host-level disposable-GPG publication suite passed 44/44 tests in
  487.038 seconds under `/private/tmp`. The final Python 3.13 host discovery
  passed all 1,555 tests in 920.024 seconds on the same tree, including real
  signing, publication recovery, transport, privacy, export, and CLI coverage.
  It supersedes the earlier 1,547-test evidence and every interrupted or
  pre-audit run. One unquoted shell-pattern invocation was rejected by zsh
  before Python started and is explicitly zero-test/non-counting. Project-journal
  validation passed; the skill-structure, validator-wrapper, and module-boundary
  group passed 56/56 tests in 6.725 seconds; OpenAI quick validation reported
  `Skill is valid!`; scoped Ruff lint/format passed all 18 changed Python files;
  and `git diff --check` passed.
- The first formal fresh-context review of the frozen follow-up found three
  issues: suffix-based overlap exemptions could omit arbitrary source prose,
  garbage collection could synthesize a stale publication abort, and a blocking
  stdout read could outlive the remote-helper timeout when a detached child kept
  the pipe open. The fixes use exact case-sensitive metadata validators, retain
  publication-bound exports until attempt-owner termination, and drive bounded
  relay reads through a monotonic nonblocking selector before group closure.
- A bounded pre-commit export audit returned `No findings.` The overlap audit
  then found two additional validator gaps: Unicode/case-fold key aliases and
  syntactically shaped but invalid timestamps. Both are covered by exact-key and
  Python 3.13 calendar/time/offset regressions. The transport audit did not
  produce a terminal artifact within its bounded observation window and was
  closed while running; it is transport-inconclusive and non-counting.
- The final affected result, export, source-transport, session-shards, and
  module-boundary group passed 228/228 tests in 27.421 seconds. The skill
  structure, validator-wrapper, and module-boundary group passed 56/56 tests in
  7.120 seconds; scoped Ruff lint/format passed and the isolated OpenAI skill
  validator reported `Skill is valid!`. An earlier host publication run was
  interrupted after the overlap audit changed the candidate tree and is
  explicitly non-counting; no recent task-owned `/private/tmp` directory
  remained after shutdown.
- The final host-level disposable-GPG publication transaction suite then passed
  44/44 tests in 461.542 seconds under `/private/tmp` on the post-audit tree.
- The final host Python 3.13 discovery passed all 1,556 tests in 766.713
  seconds on the same post-audit implementation. It includes the real signing
  and publication fixtures and supersedes the interrupted pre-fix publication
  run; no test result was inferred or carried across candidate trees.
- The next two independent audits found legacy full-manifest and inline-payload
  migration gaps, staged-source rollback races, incomplete host/reference
  binding, claim retry exhaustion ambiguity, and an overlap exemption that
  trusted reference-shaped values without an exact parent allow-list entry.
  The fixes move source payloads into conflict-checked content-addressed
  sidecars, retain exact legacy compatibility, revalidate rollback identity,
  single-link state, access policy, and two descriptor reads, bind the complete
  canonical host/source-cell matrix, and cap each claim at two generations.
- On the resulting tree, the affected checkpoint, result/episode,
  source-transport, orchestrator, and module-boundary group passed 226/226 tests
  in 132.349 seconds. The exact disposable-GPG shadow-authority regression
  passed 1/1 in 16.439 seconds. Scoped Ruff lint and format checks, import
  checks, project-journal validation, and `git diff --check` passed. The first
  full-discovery invocation omitted `-s tests`, collected zero tests, and is
  explicitly non-counting.
- The final host Python 3.13 discovery passed all 1,566 tests in 806.139 seconds
  on that same implementation, including the real GPG publication, checkpoint,
  transport, privacy, orchestration, reporting, and legacy-compatibility paths.
  It supersedes the zero-test invocation and all pre-audit discovery evidence.
- The first PR head then exposed a platform-only test-fixture failure: five
  publication invariant cases required macOS `/private/tmp`, which does not
  exist on the Ubuntu runner. The runner completed the other tests before
  reporting those five setup errors. Publication fixtures now prefer the real
  macOS path when present and otherwise use Python's validated system temporary
  root. The focused invariant class passed 11/11 in 0.764 seconds, Ruff lint and
  format checks passed, and the complete host-level disposable-GPG publication
  module passed 45/45 in 438.229 seconds.
- The fresh Codex reviewer for the failed PR head was stopped while still
  running and produced no terminal artifact, so it is explicitly non-counting.
  Its detached workspace passed postvalidation, the trusted manifest, playbook,
  and guard digests remained unchanged, and the task root was removed. A new
  signed head requires new admission, materialization, and review evidence.
- The next valid frozen-head Codex review found three P1s: first-parent history
  simplification could hide a rollback merge, cleanup claims bound only root
  identity plus counters, and an existing journal could be claimed before its
  current-run plan was proved. The follow-up adds complete parent-edge history
  validation, v4 exact child inventories, and pre-claim journal re-derivation.
  Focused regressions passed 7/7, the direct cleanup-order regression and
  module-boundary group passed 21/21, identity/safe-I/O passed 32/32,
  orchestrator passed 74/74 in 106.933 seconds, and the host-level disposable-
  GPG publication suite passed 48/48 in 490.283 seconds. The prior head's review,
  admission, and CI remain historical only; final-head gates must be rerun.
- An initial post-P1 host Python 3.13 discovery passed all 1,573 tests in
  781.751 seconds. A subsequent cleanup audit found that malformed inventory
  modes could escape as `TypeError` and that the second exact inventory pass
  still ran per root immediately before deletion instead of completing across
  every root first. That discovery is retained as historical evidence only.
  The repaired exact-cleanup and module group passed 21/21, the complete
  orchestrator module passed 75/75 in 100.164 seconds, and the short module,
  result-contract, skill-structure, and validator-wrapper group passed 71/71 in
  6.596 seconds.
- The final host Python 3.13 discovery passed all 1,574 tests in 789.683
  seconds, including the disposable-GPG publication transactions. It
  supersedes the earlier 1,573-test run and every affected-module result as the
  complete implementation-tree gate; the only subsequent change was this
  evidence-only journal update.
- The fresh whole-range Codex review of signed head `05a218d` then found three
  actionable recovery gaps: CLI prevalidation could strand `abort_pending`
  after the target advanced, incremental exact deletion had no restart-safe
  child/root progress, and inline `root_entries` could exceed the 32 MiB
  checkpoint at legal scale. The follow-up keeps live-history re-derivation for
  normal publication but authenticates only static run binding before abort
  replay. Cleanup v5 moves exact entries to a bounded content-addressed sidecar
  and uses deterministic quarantine plus durable per-root `started` markers.
  Sidecar tamper, hardlink, oversize, same-size replacement, child deletion
  interruption, root deletion interruption, and global two-pass regressions all
  pass. The complete orchestrator module now passes 78/78 in 103.068 seconds,
  module-boundary tests pass 17/17, and the exact host `/private/tmp` OpenPGP
  conflict-recovery regression passes 1/1 in 13.681 seconds. The complete
  host-level disposable-GPG publication module passes 48/48 in 486.504 seconds.
  An additional v5 regression proves that moving away every claimed root without
  a durable progress marker is rejected rather than treated as completed cleanup.
- The final Python 3.13 host discovery passes all 1,578 tests in 783.319 seconds
  on the same recovery-fix implementation, including the real OpenPGP
  publication transactions. It supersedes every partial or pre-fix result for
  this tree. Exact-secret admission, hosted CI, and final-head review evidence
  remain to be regenerated after the signed append-only commit.
- The next fresh whole-range named-single retry on signed head `345e7c3` returned
  three actionable findings: short source-token overlap, generic bare-FQDN
  retention, and local Git object reads that had not explicitly disabled lazy
  fetch and credential helpers or rejected promisor repositories. The retry
  workspace was postvalidated clean and removed; no partial output from the
  earlier metadata-failed launch was counted.
- The finding fixes pass the complete result/export/module-boundary group at
  126/126 in 4.667 seconds. Before deterministic helper extraction, the complete
  host disposable-GPG publication module passed 51/51 in 540.681 seconds; after
  extraction, the two exact Git-safety regressions passed 2/2 in 18.651 seconds.
- The final Python 3.13 host discovery passes all 1,581 tests in 769.407 seconds
  on the same privacy and Git-safety implementation, including the real
  disposable-GPG publication transactions. It supersedes the affected and
  pre-extraction results as the complete implementation-tree gate. The final
  project-journal validator, scoped Ruff lint/format checks, isolated OpenAI
  skill validator, and `git diff --check` all pass; only this evidence-only
  journal update follows the complete implementation-tree gate.
- A fresh whole-range Codex reviewer of signed head `0f622f5` found three
  actionable recovery and boundary gaps: unrelated durable-history successors
  blocked finalization, committed export sidecars could become collectible before
  the outer run checkpoint was recoverable, and the documented transport total
  did not match the actual module inventory. Its independent workspace was
  postvalidated and removed before these fixes; no partial result was reused.
- The follow-up focused evidence passes the complete export module at 50/50 in
  2.626 seconds and module-boundary tests at 18/18 in 1.800 seconds. All four
  disposable-GPG recovery regressions pass with explicit `TMPDIR=/private/tmp`;
  the earlier default-TMPDIR attempt was setup-blocked by the symlink-ancestor
  security contract before target logic and is non-counting. Scoped Ruff lint and
  format checks over all 69 v2 modules and affected tests pass, as does
  `git diff --check`.
- The final Python 3.13 host discovery passes all 1,586 tests in 1031.874 seconds
  on the same publication-recovery and transport-boundary implementation,
  including the real disposable-GPG publication transactions. It supersedes all
  affected and setup-blocked results for this tree.
- The fresh named-single review of signed head `50f9d50` returned three actionable
  findings: CLI finalize released exports before intermediate transaction phases
  had committed, publication rereads omitted ACL validation and treated timestamps
  as mutation, and recursive GC lacked global traversal and result budgets. The
  workspace postvalidation reproduced the exact materialization receipt and the
  independent task root was removed before fixes; no partial artifact was reused.
- The review fixes pass GC adversarial tests 3/3, publication/CLI/ACL/timestamp
  focused tests 4/4 in 65.481 seconds, the complete export module 53/53 in 2.764
  seconds, module boundaries 18/18 in 1.614 seconds, and the CLI contract 30/30 in
  32.641 seconds. The complete disposable-GPG publication module passes 58/58 in
  823.954 seconds. One sandboxed disposable-key setup attempt ran zero tests and
  is non-counting; the exact host-level rerun supplies the terminal evidence.
- The bounded pre-commit read-only audit did not return a terminal artifact even
  after its hard-stop request and is explicitly transport-inconclusive and
  non-counting. A parent-side review then found one durability gap in the GC
  follow-up: a deadline checkpoint between secure removal and parent-directory
  `fsync` could interrupt the delete commit after mutation but before durable
  receipt accounting. Deadline checks now occur immediately before destructive
  work, and every started delete completes `remove -> fsync -> receipt` without
  an intervening budget checkpoint. The direct deadline and delete-commit
  regressions pass, and the complete export plus module-boundary group passes
  73/73.
- The final Python 3.13 host discovery passes all 1,595 tests in 1092.939 seconds
  on the same review-fix tree, including the real disposable-GPG publication
  transactions. It supersedes every partial, pre-fix, setup-blocked, and
  pre-durability-fix result. Project-journal validation, scoped Ruff lint and
  format checks, and `git diff --check` pass. The direct skill-validator wrapper
  lacked `PyYAML`; its documented isolated `uv` fallback using Python 3.13 and
  `pyyaml` passed the OpenAI quick validator.
- The first Codex review attempt on signed head `d374bce` wrote ignored cache and
  temporary files inside its independent workspace, so the lane is formally
  non-counting. Its diagnostic output nevertheless identified two actionable
  capacity gaps: cleanup inventory traversal accumulated the legal tree before
  enforcing its large terminal sidecar limit, and source continuation repeatedly
  loaded and merged every prior segment. Post-run inspection identified those
  writes, the trusted bundle digests remained unchanged, and the task root was
  removed; no artifact from that lane is accepted as formal review evidence.
- The follow-up shares one early cleanup budget across all fixed roots and rejects
  before 300,000 entries, 64 MiB of encoded relative paths, depth 64, or a
  300-second traversal deadline. Its canonical sidecar is capped at 256 MiB.
  Run acceptance is independently capped at 100,000 source records, 4 GiB of
  source bytes, 768 source segments, 16,384 raw shards, and 15,000 agent tasks.
  The retry and claim constants derive a conservative 288,688-entry maximum,
  including fixed recovery reserve, below the cleanup ceiling.
- Source continuation is limited to 64 segments per host/source cell and 256 MiB
  of acceptance sidecars per run. Each segment is loaded once, payload indexes
  merge in place, and only the final aggregate is sorted; accepting a later
  segment no longer rereads historical sidecars. Exact regressions also prove
  pre-staging run-global rejection, shard/task caps, a shared multi-root cleanup
  budget, path/depth/deadline rejection, and retry/claim capacity derivation.
  One initial focused command named a nonexistent test and is non-counting; the
  intended test passed 1/1 after correction. The complete affected identity,
  sharding, source-transport, orchestrator, and module-boundary run passes all
  223 tests in 142.636 seconds under Python 3.13.
- The final host Python 3.13 discovery passes all 1,602 tests in 1005.247
  seconds on the same capacity-fix implementation, including the disposable-GPG
  publication transactions under `/private/tmp`. An earlier shell invocation
  left the discovery pattern unquoted and exited before Python started; it ran
  zero tests and is explicitly non-counting. The successful discovery is the
  complete implementation-tree gate; only evidence and commit metadata changes
  follow it.
- The fresh whole-range Codex review of signed head `3bf0d01` returned three
  actionable capacity findings. Legal accepted results could still expand the
  authenticated checkpoint beyond 32 MiB; the 16,384-shard contract exceeded
  the complete 15,000-task budget and failed only after raw files were written;
  and the 4 GiB legal source corpus could be copied several times during shard
  planning/materialization. The independent workspace reproduced its exact
  postvalidation receipt, the trusted bundle digests remained unchanged, and
  the task root was removed before fixes.
- New acceptances place canonical result payloads in authenticated owner-only
  `agent-sinks/results` sidecars and retain only task/hash/size/path commitments
  in the checkpoint. Complete immutable task inputs and hierarchy metadata use
  authenticated `agent-sinks/task-inputs` sidecars; attempts retain only a
  deterministic job-manifest digest and reconstruct the manifest at claim/replay.
  Legacy inline results remain read-compatible. The task budget is partitioned
  into 1,000 extractor misses plus 500 downstream misses, with cache hits
  conserved separately. Each checkpoint task is limited to 16 KiB and exact
  candidate checkpoint serialization reserves 512 KiB for terminal blockers
  before any staged file is written.
- Raw sharding now performs a manifest-only first pass and a
  one-record/one-shard-at-a-time second pass. Oversized catalog records become
  explicit gaps before payload I/O, and no more than 1,000 shards may be planned.
  Shard files, task sidecars, envelopes, and the candidate checkpoint form one
  staged transaction. Rollback uses parent/file identity plus exact content and
  access-policy receipts under one persistent directory lock. The conservative
  cleanup proof charges both target and a lock share for every atomic file and is
  259,540/300,000 entries.
- Intermediate review-fix evidence passed scoped Ruff format/lint for all 73 engine
  and affected-test files, module boundaries 18/18 in 1.630 seconds, the
  identity/checkpoint/source/result/history/export group 246/246 in 31.307
  seconds, and catalog/sharding/orchestrator 110/110 in 145.597 seconds. Earlier
  test-first attempts with two incorrect selector names, a stale test constant,
  and an assertion that treated persistent atomic-create lock files as staged
  payloads are non-counting; corrected exact tests are included in the terminal
  groups above.
- After extracting sealed raw-artifact loading into its own bounded module, an
  intermediate quick gate passed Ruff lint/format for 22 directly affected files,
  module boundaries 18/18 in 1.636 seconds, catalog/identity 64/64 in 0.386
  seconds, and orchestrator 87/87 in 125.376 seconds under Python 3.13. The five
  agent-support modules occupy 873/900 lines and the package branch proxy is
  8,151/8,160. A previously started disposable-GPG discovery was interrupted
  before terminal output and is explicitly non-counting; the host publication
  tests must be rerun on the final frozen tree.
- The capacity follow-up now stages each source program snapshot, remote-helper
  snapshot, and bound empty output with the candidate checkpoint only after the
  exact capacity check. Reassembled extracted turns moved to one authenticated
  96 MiB derived sidecar; accepted-result replay reauthenticates its sidecar, gap
  projection remains content-free after task-sidecar cleanup, and legacy attempt
  manifests migrate only after exact reconstruction. Atomic creates share one
  directory lock, independent rollback groups continue after a retained mismatch,
  and close failures cannot reverse a proved file disposition or replace the
  original primary failure.
- Current terminal Python 3.13 evidence for this follow-up includes source
  transport 69/69 in 27.965 seconds, catalog/identity 67/67 in 0.204 seconds,
  orchestrator 93/93 in 134.708 seconds, module boundaries 18/18 in 1.629
  seconds, and the post-suite large-derived-sidecar tamper regression 1/1 in
  0.426 seconds. The six agent-support modules occupy 1,027/1,050 lines, the
  exact transport inventory is 7,229/7,250, and the package branch proxy is
  8,230/8,250. At that checkpoint these focused and affected-suite results did
  not replace the still-pending full discovery or host-level disposable-GPG gate.
- The final host-level Python 3.13 discovery passes all 1,626 tests in 1,105.564
  seconds with `TMPDIR=/private/tmp`. It includes the real disposable-GPG
  publication transactions and reports no skips. This terminal run supersedes
  the interrupted non-counting discovery while preserving the focused and
  affected-suite evidence above for diagnosis.
- Fresh whole-range Codex review of signed head `1e8ae95` found three actionable
  P1 issues: cleanup inventory did not bind same-inode file content, segmented
  source acceptance accumulated the legal 4 GiB corpus in memory, and claim or
  result transitions could consume the checkpoint terminal reserve. The
  independent workspace was postvalidated and removed before repair; its result
  is finding evidence for that superseded head, not final-head review evidence.
- The repair writes cleanup inventory-sidecar v2 file commitments while retaining
  authenticated v1 replay, streams segmented input through one descriptor-held
  private spool with compact descriptor digests, and restores prior claim/result
  state on capacity failure. Cohesive staging and reserve owners keep the source
  coordinator slice at 2,889/3,000 lines, source staging at 593/625, transport at
  7,214/7,250, and the branch proxy at 8,312/8,350. The six exact reviewer
  regressions pass in 7.547 seconds and module boundaries pass 18/18 in 1.690
  seconds under Python 3.13; affected and full host gates remain pending for this
  uncommitted tree.
- The complete affected identity, catalog, source-transport, orchestrator, and
  module-boundary group passes 251/251 in 160.793 seconds. Scoped Ruff lint and
  format checks, `git diff --check`, project-journal validation, and the installed
  OpenAI quick skill validator pass. The skill validator first encountered
  sandbox DNS failure while resolving its isolated `PyYAML` dependency and then
  a documented bare-Python fallback error; the authorized network retry passed
  and supersedes both non-counting runtime attempts.
- A sandboxed full discovery ran 1,584 tests in 241.948 seconds before the
  publication test class failed during disposable Ed25519 key setup; that run is
  non-counting as a complete gate. The exact host-level publication module then
  passed 58/58 in 656.973 seconds. The final host-level Python 3.13 discovery
  passes all 1,630 tests in 978.525 seconds with `TMPDIR=/private/tmp`, including
  the disposable-GPG publication transactions. One malformed `unittest` option
  ordering exited with code 2 before discovery and is also non-counting.
- Three bounded pre-commit audits of the uncommitted repair found additional
  transaction windows. Cleanup rechecked a v2 inventory before deletion but did
  not carry the expected per-file commitment into the unlink walk; segmented
  input still retained each prepared payload and could lose rollback receipts to
  post-create collection allocation; and accepted/rejected replay could migrate
  a legacy inline job manifest before returning idempotently without rechecking
  terminal reserve. The old 1,630-test result predates these findings and is now
  superseded rather than final-tree evidence.
- The follow-up makes recursive cleanup consume the authenticated expected
  inventory and revalidate file identity, access policy, size, and v2 SHA-256
  through the held descriptor immediately before unlink. Authenticated legacy
  null commitments remain identity/policy-only compatibility. Segmented input
  proves run-global capacity before transport iteration, enforces exact byte and
  record caps before spool writes, uses a deterministic lease-derived spool plus
  persistent owner-only lock for crash recovery, and preallocates a payload-free
  receipt ledger before final-file creation. No-change result replay remains
  reserve-neutral; replay-time legacy migration must pass the same checkpoint
  reserve or restore the original representation and persist the blocker.
- Exact regressions for those properties and their compatibility paths pass
  11/11 in 11.448 seconds. A final memory audit then moved the session-shards
  callback to each validated record instead of the end of a segment, preallocated
  scheduler rollback slots before stage calls, and charged all 768 possible
  persistent spool locks to cleanup capacity. The conservative cleanup maximum is
  now 260,308/300,000 entries. Module boundaries pass 18/18 with 8,367/8,375
  branch nodes, 20 functions over 200 lines, a 2,930/3,000-line source
  coordinator/support slice, and 749/775 source-staging lines. The final complete
  affected identity, catalog, source-transport, orchestrator, and module-boundary
  group passes 257/257 in 161.921 seconds under Python 3.13.
- The final host Python 3.13 discovery passes all 1,636 tests in 1,116.000
  seconds with `TMPDIR=/private/tmp`. It includes the disposable-GPG publication
  transactions, reports no skips, and supersedes the older 1,630-test result.
  Scoped Ruff lint passes, all 19 changed Python files pass the Ruff format
  check, `git diff --check` passes, project-journal validation passes, the skill
  structure and validator-wrapper group passes 39/39 in 5.219 seconds, and the
  isolated official OpenAI validator reports `Skill is valid!`. The only
  subsequent change is this evidence-only journal update; exact-head admission,
  review, CI, and PR lifecycle gates remain pending.
- Fresh whole-range Codex review of signed head `4f2764c` found five actionable
  issues. Legacy cleanup v4 authentication normalized the original wire shape
  before checking its claim reference; active inline job manifests could bypass
  binding and migration on claim heartbeat, idempotent recovery, first result
  disposition, and terminal budget replay; markerless quarantine accepted a
  subset of the planned tree; atomic create linked its final name before the
  caller owned durable rollback authority; and cleanup inventory could block on
  an owner-only FIFO before rejecting its type. The independent reviewer
  workspace was postvalidated clean and removed, so its findings apply only to
  the superseded head.
- The repair authenticates legacy cleanup claims against their original
  field-present representation, binds or migrates every active attempt path
  under the checkpoint reserve, and requires either the complete quarantined set
  or a durable progress marker. Atomic create now publishes a descriptor-bound
  receipt into a caller-preallocated slot before linking and can roll back the
  pending-only, two-link, or final-only state after any unwindable
  `BaseException`. Cleanup rejects special files from parent-held metadata and
  uses nonblocking no-follow opens before revalidating regular-file identity,
  content, and access policy. A close-only create failure releases the directory
  lock and parent descriptor before it propagates.
- Exact close/rollback regressions pass 2/2, module boundaries pass 18/18 in
  1.585 seconds, and the complete affected identity, catalog, source-transport,
  orchestrator, and module-boundary group passes 267/267 in 177.443 seconds.
  The package branch proxy is 8,374/8,375 with 20 functions over 200 lines.
  Ruff lint and format checks pass for all 12 changed Python files,
  `git diff --check` passes, skill structure and validator-wrapper tests pass
  39/39 in 5.218 seconds, and the isolated official OpenAI validator reports
  `Skill is valid!`. One initial affected run stopped at 265/266 because an old
  test mock did not accept the new receipt-slot argument; the corrected terminal
  group above supersedes that non-counting run.
- A sandboxed full discovery reached 1,600 tests in 272.019 seconds before the
  disposable-GPG class failed during key generation; it is non-counting because
  the host publication permission gate was absent. Under the explicitly
  authorized host `/private/tmp` shape, the publication module passes 58/58 in
  719.725 seconds and the final Python 3.13 discovery passes all 1,646 tests in
  1,106.765 seconds. The direct Claude lane is skipped under Joey's explicit
  authorization for this Codex task and is not represented as an executed
  double or triple review.
- The first whole-range Codex review attempt on signed head `f032fec` returned
  no findings but wrote an empty ignored validator cache, so it was postvalidated,
  cleaned, and classified non-counting. Its strict read-only retry returned two
  P1 findings: result-side substrings from 12 through 15 normalized characters
  could evade the asymmetric reverse-overlap threshold, and identifier-shaped
  values under classifier keys were exempt without field-specific semantics.
  That workspace postvalidated clean and was removed before repair; `f032fec`
  admission and CI evidence is superseded by the forthcoming signed head.
- The repair makes source/result substring containment symmetric from 12
  normalized characters and replaces the broad classifier regex with exact
  per-field value sets; every unknown classifier value falls back to ordinary
  bounded source-text windows. Regressions cover all former classifier keys,
  every 12--15-character length, and both paths through a real coordinator.
  Focused tests pass 3/3 in 3.579 seconds, result/episode tests 62/62 in 0.800
  seconds, result-contract audit 15/15 in 0.096 seconds, orchestrator tests
  108/108 in 156.045 seconds, and module boundaries 18/18 in 1.636 seconds.
  A sandboxed discovery ran 1,603 tests before the temporary GPG class failed in
  setup and is non-counting as a complete gate. The authorized host Python 3.13
  discovery then passed all 1,649 tests in 1,111.116 seconds with
  `TMPDIR=/private/tmp`, including the disposable-GPG publication transactions.
