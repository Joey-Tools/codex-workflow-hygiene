# Session Retrospective v2 Engine Architecture

## Coordinator model

The v2 engine is a deterministic coordinator. `RetrospectiveOrchestrator` owns
the authenticated checkpoint store, identity, run directory, clock, and shard
limits. Its capability classes are stateless and have no constructors. They
operate on that single coordinator context and do not import one another:

| Module | Responsibility |
| --- | --- |
| `orchestrator.py` | Stable facade, coordinator context, and CLI-compatible exports |
| `orchestrator_support.py` | Source-frame consumption, shared contracts, and runtime readiness |
| `orchestrator_state.py` | Authenticated checkpoint identity and state access primitives |
| `run_state_contracts.py` | Closed run-authority schemas, host references, and common guards |
| `run_state_cursors.py` | History-bound cursor starts and terminal-source cursor derivation |
| `run_state_holdouts.py` | Formal Daily holdout and shadow-successor authorization |
| `run_state_lineage.py` | Controlled-gap, backfill, backlog, and episode-head lineage validation |
| `run_state_authority.py` | Shared formal source-matrix, cursor, lineage, and durable-state composition |
| `orchestrator_projection.py` | Read-only status, metrics, references, and next actions |
| `orchestrator_jobs.py` | Agent attempt, claim, sink, and envelope lifecycle |
| `orchestrator_reduction.py` | Catalog materialization and episode/topic/synthesis hierarchies |
| `orchestrator_history.py` | Result validation and retained history projection |
| `orchestrator_source.py` | Source transport admission and leased agent result handling |
| `orchestrator_lifecycle.py` | Run creation, publication claims, retention, and raw cleanup |
| `source_capacity.py` | Run-global source, sidecar, and cleanup-capacity accounting |
| `source_acceptance.py` | Input normalization and compact accepted-payload accounting |
| `source_spool.py` | Lease-bound spool locking, exact pre-write limits, and crash recovery |
| `agent_capacity.py` | Extractor/downstream task partitions and cache-miss reservations |
| `agent_checkpoint_capacity.py` | Claim/result checkpoint-reserve rollback transactions |
| `agent_task_inputs.py` | Authenticated immutable task-input sidecars and checkpoint summaries |
| `agent_results.py` | Authenticated accepted-result sidecars and checkpoint-coupled staging |
| `agent_raw_artifacts.py` | Sealed raw-artifact projection and envelope loading |
| `extracted_turns.py` | Authenticated derived-turn sidecar preparation and loading |
| `raw_shard_staging.py` | Two-pass source-payload streaming and raw-shard rollback ownership |
| `source_staging.py` | Preallocated receipt ledger and atomic final-file staging |
| `orchestrator_scheduler.py` | Stage transitions, task creation, and bounded envelope scheduling |

Publication uses an explicit side-effect boundary:

| Module | Responsibility |
| --- | --- |
| `finalize.py` | Stable publication facade |
| `publication_transaction.py` | Durable publication state machine and recovery |
| `publication_git.py` | Constrained local Git provider facade and effect ordering |
| `publication_git_capacity.py` | Request-bound capacity ledger and legacy migration |
| `publication_git_storage.py` | Staging, retention-sidecar, and cleanup ownership |
| `publication_git_commits.py` | Signed Git object, reachability, and ref operations |
| `publication_state.py` | Durable publication state and transition validation |
| `publication_contracts.py` | Side-effect protocols and injected adapter contracts |
| `publication_support.py` | Immutable contracts, anchored I/O, and pure validation |
| `executable_authority.py` | Shared executable path, content, and access-policy binding |
| `git_safety.py` | Shared local-only Git environment, repository admission, and revalidation |

`retained_inputs.py` owns authenticated export-input sidecars, while
`source_overlap.py` owns strict streaming JSON token decoding, deterministic
control-field classification, prose normalization, bounded overlap windows, and
short source-token matching. `privacy_locators.py` owns working-zone bare-host
and effective IPv4/IPv6 detection. Working-zone redaction, retained safe
strings, reviewed prose, and final report validation consume that same locator
policy. Protocol locators accept every syntactically legal scheme length and
rely on the result field's existing character ceiling rather than a privacy-only
scheme cap. Their shared left boundary excludes every legal scheme character
instead of relying on a word boundary, so a locator after `_` is detected while
the scanner cannot restart inside a longer scheme. Empty authority remains a
locator and is rejected conservatively. The retained boundary still applies its
stricter field and prose grammar.
Keeping these deterministic policies outside the coordinator capabilities
prevents lifecycle and result-validation modules from growing a second copy of
either state machine.

Remote helper execution has two separate owners. Parent-only
`transport_remote_snapshot.py` materializes the installed
`$remote-host-context` helper into the run-owned content-addressed snapshot
cache. Worker-visible `transport_snapshot.py` contains only deterministic path,
commitment, and isolated bootstrap logic for that external helper; the worker
manifest does not expose the parent materializer.
The bootstrap keeps the helper descriptor open through its bounded read and
revalidates object identity plus owner/mode/link/size policy before executing
the retained exact bytes.
Both source-program bootstraps use no-follow, nonblocking descriptor opens and
compare the opened object with the named object before and after the bounded
read. They require a stable regular-file identity, owner/group/mode, single-link
state, and exact size; the owner-private snapshots additionally require mode
`0600`. FIFO, leaf-symlink, hardlink, access-policy drift, and same-path
replacement therefore fail before compilation or execution. The Python runtime
uses the same bounded reader with a root-or-current-user, non-writable policy.
The scheduler resolves that authenticated runtime to its canonical physical
path and records the complete argv in the lease. Status re-derives the exact
program commitment before projecting any command, and native source acceptance
reuses the same canonical argv0 rather than ambient `sys.executable`. Replacing
an interpreter alias after lease creation therefore cannot redirect execution.
These are point-in-time identity, content, and access-policy checks; they do not
claim to defeat an actively malicious same-UID replacement of the canonical
target after the final validation.
`transport_remote.py` launches the retained snapshot, never the live installed
path. This preserves the worker manifest's no-parent-write boundary while
closing the commitment-to-execution replacement window. The parent derives the
live-helper source commitment from the same descriptor-bound read used to create
the snapshot and requires it to equal the run's frozen transport provenance, so
one run cannot mix helper versions across source leases.

The transport worker imports only modules present in the authenticated program
manifest. Its snapshot finder is the sole authority for the package namespace;
the live worker root is never placed on `sys.path`, and a missing manifest
module cannot fall through to repository or installed-package bytes. Discovered
source locators must satisfy the closed grammar and be UTF-8 encodable. A
filesystem name that cannot be represented becomes an explicit
`source_locator_unrepresentable` gap rather than crashing discovery or being
silently omitted. Source rereads compare the selected protected properties:
object identity, access policy, and the exact scanned byte-range digest.
Timestamp-only churn is benign, while content, identity, or access-policy drift
remains an explicit source-stability gap.

Source scheduling prepares the transport-program snapshot, remote-helper
snapshot, and bound empty output together with the candidate checkpoint. Exact
checkpoint capacity is proved before any file is materialized. A successful
commit records the run-relative output binding; status projection only
authenticates the existing binding and program snapshot with recovery disabled;
it never creates raw state. A stale snapshot therefore cannot recreate a path
after retention cleanup has claimed and removed the raw tree.

Source acceptance has a separate bounded staging boundary. Before transport
iteration, the coordinator proves the candidate batch fits run-global source
capacity and conservatively reserves the full 64 MiB acceptance-sidecar ceiling.
The final checkpoint transaction rechecks the current state with the exact
prepared sidecar bytes. Segmented transport then keeps at most one bounded raw
record in memory
while appending accepted bytes to one deterministic lease-derived, owner-only,
descriptor-held spool. A persistent owner-only lock serializes cooperating
recovery; after the lock is acquired, a retry authenticates and removes only the
same deterministic orphan. Exact record and byte caps are checked before each
write. Compact per-record descriptors drive transcript validation and the
acceptance digest. A preallocated receipt ledger exists before any final file is
created, so rollback authority cannot be lost to a post-create collection
allocation. Replay, failure, rollback, and success all discard the exact spool.

Retained export uses two independently 250-line-bounded CLI support modules: one
owns the transaction and one owns the closed reservation, claim, and result
schemas. The transaction canonicalizes the ignored destination, rejects every
current-run cleanup root, occupies the legacy descriptor path with a no-replace
reservation, and then establishes the immutable destination claim before
artifact assembly or output writes. An exact legacy final descriptor remains
authoritative; a legacy claim that was already in flight may become the effective
destination without allowing two completed results. Final result persistence
reauthenticates the claim and any legacy descriptor before binding the bundle
digest and retention deadline.

Publication cleanup classifies the retained bundle and retention sidecar while
holding the export anchor lock. Two absent objects are an idempotent collected
state; exactly one present object is a conflict. The lifecycle release must
complete before the provider persists its abort and cleanup receipt, so a
one-sided or unreadable retained state cannot authorize reservation release.

The transport program commitment includes every runtime module above. Adding a
module without adding it to the closed allowlist fails source transport.

Runtime source matrices, run-level source capacity, and durable shadow/production
authority derive from one canonical five-host role inventory: `local`,
`BL-mac-mini-m4-hoteng`, `miku-bot-dev`, `hoteng-srv-01`, and
`codex-hoteng-srv-01`. No independent production-host subset may authorize a
complete run or cursor advancement.
The closed five-module run-state authority slice validates the authenticated
checkpoint at both the orchestrator state boundary and the formal publication
boundary. It binds each cursor start to the signed history snapshot, derives
each cursor proposal from terminal source cells, and requires the durable cursor
rows, source snapshot refs, episode-head root/list, and `backfill_of` value to be
the exact checkpoint projection. A single-host Daily backfill is accepted only
when its controlled-gap receipt authenticates and binds the partial run,
canonical host/ref, exact window, backlog, head-set commitments, and shadow mode;
checkpoint HMAC validity or a non-null `backfill_of` field alone is insufficient.
Formal source gaps additionally require an exact authenticated Daily partial
holdout set and reauthenticate each referenced transport receipt body against
the checkpoint source receipts; reference equality alone is not authority.
Weekly gaps, mixed gap cells, cross-host receipts, and ordinary runs that would
clear an existing backlog are rejected. Shadow backfills revalidate the
completed-partial successor authorization and all of its history, provenance,
window, coverage, cleanup, and bundle bindings on every checkpoint read.

Opening a publication journal validates that authenticated checkpoint and its
persistent claim before any adapter recovery. It rebuilds the exact inventory of
every present retained bundle before adapter side effects; only the durable
post-CAS recovery path may continue when that bundle is exactly absent. Direct
abort recovery independently repeats the claim check before adapter release.
Before target CAS, every forward transition additionally re-derives the journal
plan from the current retained bundle, signed history base, provider cache,
cursor vector, and episode update. After an exact target CAS is already
reachable, recovery instead binds the adapter attempt and signed durable
history; it neither mistakes the expected history advance for drift nor requires
an already collected local bundle.

History readiness and formal publication use the same local-repository
admission receipt. It binds owner-controlled real ancestry for the worktree,
Git directory, common directory, and closed object store; rejects alternates,
grafts, shallow repositories, promisor/partial-clone configuration, include
directives, worktree configuration, and an enabled `extensions.worktreeConfig`;
and binds the exact owner-controlled common-config bytes. Each later Git command
holds all four admitted directory descriptors, launches from the held worktree
descriptor with only relative repository discovery, and revalidates directory
identity, access policy, config content, and forbidden metadata before and after
the subprocess. The isolated Python trampoline that performs descriptor-relative
`fchdir` is itself resolved through the shared executable authority, contributes
its physical path, content, and access-policy receipt, and is revalidated around
every Git or GPG child launch. Close failures fail the otherwise-successful
command and remain secondary evidence when another failure is already primary.
These are point-in-time checks: they detect path replacement and stable drift but
do not claim to exclude an actively malicious same-UID ABA after the final
pre-launch check. A repository that finalize would reject is therefore blocked
by doctor/start before an expensive retrospective run begins.

Source-program and remote-helper Python bootstraps run with `-I -B -S`; the
captured bootstrap itself verifies isolated, no-site, no-bytecode flags before
authenticating or compiling retained source. Global or user site initialization
therefore cannot run before the authenticated source-only loader.

Program-component stability protects object identity and access policy without
treating size or timestamps as identity. Every regular component is read twice
through the held descriptor and the exact bytes and final size must agree.
Package-directory child-entry, link-count, and timestamp churn is benign while
directory identity, ownership, type, and mode remain exact; regular components
still require one link. Source rollout
stability similarly compares only BSD immutable, append, nounlink, restricted,
and datavault flags; `UF_HIDDEN` and other presentation flags are not access
policy.

The transport slice remains independently bounded after this hardening: 7,245
physical lines across a 7,250-line aggregate limit. One exact 14-module
inventory and its aggregate are enforced together, so omitting a transport
module cannot create a false budget pass. The newly affected modules are
`transport_paths.py` at 82/100 lines, `transport_program.py` at 450/450,
`transport_remote.py` at 316/320, `transport_snapshot.py` at 219/220, and
`transport_remote_snapshot.py` at 86/100, while `transport_contracts.py` is
990/1,000 and `transport_resume.py` is 168/200,
`transport_source.py` is
1,695/1,700, and `transport_worker.py` is 21/25. The closed run-state
authority inventory is exactly 1,000/1,000 lines: `run_state_authority.py` 243/250,
`run_state_contracts.py` 37/50, `run_state_cursors.py` 219/225,
`run_state_holdouts.py` 236/240, and `run_state_lineage.py` 265/275. Including
this full slice, the orchestrator foundation is 3,297/3,350 lines. The global
branch proxy is 8,500/8,500 nodes after adding executable path, content, and
access-policy authority to the existing descriptor-custody, closed-config,
transport-isolation, canonical-runtime, and locator predicates. The closed
nine-module publication slice is 8,689/8,700 lines; within it,
`publication_support.py` is 1,317/1,320 and `executable_authority.py` is
314/320. The durable `authority.py` integration is 3,259/3,275 lines. The
source coordinator and
its original support slice are 2,930/3,000 lines; the three source-staging modules
are independently capped at 749/775, and the claim/result reserve owner is
123/130. The current increase is confined to run-global source/shard/task
capacity, authenticated task/result/derived sidecars, and checkpoint-coupled
staging; no additional coordinator capability or transport monolith was
introduced. The six agent support modules are independently bounded at
1,030/1,050 aggregate lines; their individual ceilings are 100, 120, 320, 350,
200, and 100 lines. Raw-artifact and derived-turn loading remain separate so
`orchestrator_jobs.py` stays at 507/520 lines, while
`orchestrator_reduction.py`, `orchestrator_scheduler.py`, and
`orchestrator_source.py` stay at 2,465/2,480, 1,092/1,100, and 2,146/2,150 lines.

## Architecture inventory

The inventory snapshot below uses physical lines, Python AST function boundaries (including
nested functions), and a branch proxy that counts `if`, loops, `try`, `match`,
boolean branches, conditional expressions, and comprehensions. Exact duplicate
groups hash normalized AST function bodies of at least eight lines.

| Metric | Before boundary refactor | After boundary refactor |
| --- | ---: | ---: |
| Engine Python modules | 20 | 32 |
| Engine Python lines | 44,954 | 45,469 |
| Nonblank, non-comment lines | 42,234 | 42,808 |
| Functions | 1,206 | 1,191 |
| Functions over 100 lines | 71 | 75 |
| Functions over 200 lines | 18 | 18 |
| Branch proxy total | 6,667 | 6,776 |
| Exact duplicate function-body groups | 0 | 0 |
| `orchestrator.py` lines | 11,819 | 654 |
| Largest orchestrator capability | 11,819 | 3,101 |
| `finalize.py` lines | 7,271 | 87 |
| Largest publication module | 7,271 | 3,186 |

The package inventory includes transport and excludes the 1,892-line public CLI
entrypoint. At that boundary-refactor snapshot, the largest modules were:

| Module | Lines | Functions | Branch proxy | Largest function |
| --- | ---: | ---: | ---: | ---: |
| `transport.py` | 4,839 | 119 | 713 | 542 |
| `reporting.py` | 4,067 | 77 | 704 | 399 |
| `publication_support.py` | 3,186 | 113 | 529 | 236 |
| `orchestrator_lifecycle.py` | 3,101 | 48 | 465 | 474 |
| `authority.py` | 2,985 | 61 | 424 | 200 |
| `result_validation.py` | 2,978 | 62 | 451 | 231 |
| `publication_git.py` | 2,296 | 78 | 282 | 112 |
| `orchestrator_reduction.py` | 2,234 | 40 | 393 | 184 |
| `orchestrator_source.py` | 1,995 | 30 | 292 | 389 |
| `publication_transaction.py` | 1,907 | 58 | 256 | 172 |
| `episode_review.py` | 1,653 | 49 | 291 | 158 |
| `export.py` | 1,652 | 54 | 253 | 128 |

The net lines add explicit bounded task, state, relay, authority, conservation,
and recovery contracts rather than duplicated state machines. The refactor
changes ownership boundaries without deleting fail-closed validation. The audit
finds no exact generated function-body duplication of eight or more lines.
Shared result, hierarchy, row-shape, and privacy validators remain centralized
instead of being mechanically repeated at call sites. Only `__init__.py`,
`orchestrator.py`, and `finalize.py` publish explicit wildcard interfaces;
internal modules are explicit-import-only.

`tests/test_retrospective_v2_module_boundaries.py` enforces total and per-module
line limits, a 600-line function ceiling, aggregate branch and long-function
budgets, zero exact duplicate function bodies of eight or more lines, facade
sizes, stateless capability ownership, dependency direction, publication facade
identity, and transport closure. Import enforcement walks the complete AST and
includes constant-target `importlib.import_module` and `__import__` calls, so
function-, class-, `try`-, and dynamic-import escapes remain covered.
