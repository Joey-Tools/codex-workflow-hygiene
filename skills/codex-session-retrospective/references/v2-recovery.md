# Session Retrospective v2 Recovery

## General Rule

Resume only from an authenticated owner-only checkpoint and the latest validated
private-history head. Never infer success from a timeout, missing response, or
partially written artifact. Exact retries are idempotent; changed input requires
a new attempt or run.

## Source And Agent Work

- An invalid or truncated source stream does not make its source cell terminal.
- `accept-source` is the only source transition; its input remains below the run
  cache and can be retried unchanged.
- Segmented source input proves run-global capacity before transport iteration,
  then uses one deterministic lease-derived owner-only descriptor-held spool and
  retains only one bounded record in memory. A persistent owner-only lock
  serializes retry; after acquiring it, recovery authenticates and removes only
  the same orphan. Byte and record limits are enforced before every write.
  Replay, validation failure, capacity rejection, checkpoint rollback, and
  success all remove that exact spool; inability to prove removal remains an
  explicit failure rather than accepted evidence. A receipt-only rollback ledger
  is preallocated before final raw payloads or the acceptance sidecar are created.
- Source scheduling prepares the transport-program snapshot, remote-helper
  snapshot, and bound empty transport output with the candidate checkpoint.
  Capacity is proved before materialization and the files commit as one staging
  group. Status only authenticates the existing binding. A stale status snapshot
  therefore fails closed after raw expiry cleanup instead of recreating the
  deleted `raw-inputs` tree.
- A job attempt is dispatched only through a bounded claim lease. Repeating the
  matching claim before expiry is an idempotent heartbeat; after expiry, another
  dispatcher may take over the same attempt with a new claim-specific envelope
  and output sink. Attempt count does not change during takeover.
- Native agent completion means the coordinator tool call returned and the
  result was accepted with the exact active, unexpired `claim_ref`. Results from
  expired or replaced claims fail closed. Finalization requires no open claim or
  output sink.
- A newly accepted result is not embedded in the bounded checkpoint. The engine
  stages an owner-only, content-addressed result sidecar and an authenticated
  descriptor in one checkpoint transaction. A write failure before the new
  revision is proved durable removes only sidecars created by that attempt after
  exact identity, access-policy, size, and content revalidation. A committed or
  disposition-unknown revision retains the sidecar for recovery. Existing
  same-schema checkpoints with inline results remain readable but do not cause a
  new sidecar to be inferred retroactively.
- New tasks stage their complete immutable inputs in authenticated owner-only
  sidecars and retain only bounded summaries in the checkpoint. Claim and replay
  rebuild the full job manifest from authenticated task state and require its
  stored digest to match. Missing, ambiguous, oversized, or changed task/result
  sidecars fail closed; they are never replaced by a guessed inline payload. A
  legacy full attempt manifest is accepted only after exact reconstruction, is
  migrated to the digest form, and is rejected when a digest is already present.
  Accepted-result replay reauthenticates the result sidecar before returning it.
- Reassembled extracted turns use one authenticated owner-only derived sidecar
  capped at 96 MiB. New non-empty checkpoints retain only its closed descriptor;
  legacy inline mappings remain readable. A missing, changed, oversized, or
  turn-reference-inconsistent sidecar blocks reduction. Gap status projection
  remains content-free and does not reopen a deleted task-input sidecar.
- Before staging any task sidecar, envelope, or raw shard, `advance` measures the
  exact candidate checkpoint envelope against the 32 MiB limit and its 512 KiB
  terminal reserve. Exhaustion restores the prior checkpoint state, clears the
  staging set, and records `checkpoint_capacity_exhausted` from the reserved
  terminal space. It never publishes a partial task batch.
- Claim creation, claim heartbeat, accepted-result, and rejected-result
  transitions apply the same reserve to their actual mutated checkpoint. On
  exhaustion they restore the prior task and active claim, clear only newly
  staged claim/result artifacts, and persist the content-free blocker; a
  capacity failure cannot consume the claim or masquerade as an accepted result.
  A no-change replay is reserve-neutral, while replay-time migration of a legacy
  inline job manifest must pass the same reserve before the migration commits.
- A bound malformed agent result consumes one attempt. A second failure becomes
  an explicit content-free gap. JSON numeric overflow such as `1e999` is
  malformed at this ingestion boundary; it cannot become a non-finite stored
  value, and each rejected attempt closes its claim and output sink.
- Raw-shard recovery follows the same checkpoint-authoritative disposition. A
  manifest-only first pass proves the complete shard count and downstream task
  reservation before file creation. The second pass stages only exact emitted
  shards and their manifest. If the checkpoint remains at the old revision,
  rollback removes the exact newly created set; byte-identical pre-existing
  files are not part of that receipt. A committed candidate is resumed from its
  descriptors, while an inconsistent or unreadable disposition retains staged
  files and fails closed rather than guessing ownership.
- Staged-file rollback consumes only the creation receipt returned for that
  exact new object. It reacquires the persistent directory lock and revalidates
  parent identity, file identity, owner-only policy, size, and content twice.
  Replacement or unreadability retains the object and preserves the primary
  failure. Benign sibling churn does not alter the protected parent identity.
  This is a cooperating-writer guarantee; cleanup does not claim an atomic
  defense against a malicious same-UID replacement between the final descriptor
  check and the platform's path-based unlink syscall. Rollback continues through
  independent receipts and staging groups after one retained mismatch. A close
  failure after a proved unlink is recorded as secondary evidence and cannot
  reverse that disposition or replace the original primary error.

## Durable Publication

Before every publication phase, `PublicationTransaction` reloads the identity,
run disposition, candidate digest, latest signed history, cursor root,
episode-head root, production marker, and provider cache. Caller arguments cannot
replace these facts. A stale run or rolled-back cache fails closed.

The owner-local production marker is an HMAC-protected completed-cutover record,
not an active lease. The signed private Git chain remains authority after cutover.
History loading traverses the complete bounded parent graph without path
simplification. Every commit-to-parent edge is checked for `runs/` changes; a
merge is accepted only when its retained tree equals every parent, while every
linear retained-tree change must be a valid signed publication transition.

When `finalize` finds an existing journal, it first re-derives the complete
publication plan from the current run, bundle, history snapshot, provider,
target, and identity. The journal must match that plan before the run persists a
publication claim. Copying a valid journal from another run therefore cannot
claim or poison the current run.

Publication recovery is phase-idempotent:

1. prepare and stage the exact retained bundle;
2. seal and close prepublication compliance;
3. promote the signed append-only commit;
4. validate reachability and derive provider cache from that commit;
5. delete the closed raw-path inventory and record the cleanup receipt.

If the adapter target CAS succeeds before the outer `PROMOTED` event, recovery
requires this attempt's durable adapter binding and exact reachable tip before it
repairs that event. If provider CAS succeeds before the outer `COMMITTED` event,
recovery requires the exact provider projection and history-validation receipt
before it repairs commit. The publication-bound export remains non-terminal
until both that outer event and the run's authenticated publication checkpoint
are durable; GC therefore cannot remove the bundle needed by this recovery.
Changed attempts or projections fail closed.

`abort_pending` is an explicit recoverable publication phase. Open/recovery
dispatches its idempotent abort action before checking the now-conflicting live
history authority. CLI journal inspection likewise validates the static plan,
bundle inventory, run/identity paths, and authenticated checkpoint claim before
abort replay; it does not require the superseded history head to remain current.
The provider first persists an authenticated cleanup claim
binding the exact attempt, plan, expected target, staging identity, capacity,
retention sidecar, and immutable provider state. Only verified deletion/absence
may produce cleanup and reservation-release receipts. This also covers a
pre-reservation conflict with no provider attempt or capacity allocation; lost
cleanup/release responses replay the same durable receipts.

An attempt with a cleanup claim or terminal abort can never resume stage, seal,
compliance close, or promotion. Retained-export terminalization is reconciled
from durable attempt identity rather than the cached `retention_bound` flag: a
sidecar bound to this attempt is released, an ordinary unbound export is left
unchanged, and another attempt's binding is a conflict. This closes a crash
between binding the sidecar and persisting the attempt flag. For the legal
ordinary-unbound no-op, the authenticated retention receipt is read before any
bundle validation; a corrupt unrelated bundle therefore cannot turn that no-op
into an unauthorized cleanup or a false failure.

Capacity ledger records bind the complete publication request and byte count.
Recovery from a capacity record written before the attempt state reconstructs
an abort-owned attempt and releases only that reservation. Release happens under
the same short capacity lock and compare-deletes only a record that still matches
the complete request and caller-supplied expected byte count. A legacy integer
entry is migrated only when the durable attempt, reservation receipt, target
observation receipt, unit plan, inventory, and exact capacity all prove the same
ownership; recomputing the amount or matching `attempt_ref` alone is not
authority.

No state claims publication before the durable commit validates. If publication
is durable but raw cleanup fails, the run remains
`published_cleanup_pending`; rerun `finalize` to retry cleanup. The history commit
is never rolled back. Once that pending checkpoint is durable, `finalize` may
terminalize the attempt-bound export sidecar. A later retry accepts a fully
collected bundle/sidecar pair as completed GC, while one-sided local state is a
conflict. Publication rereads validate descriptor identity and owner-only
mode/link/ACL policy before and after content reads, then compare the retained
digest. Timestamp changes trigger that proof but are not mutation evidence.

Export GC uses an iterative descriptor-anchored walk with one global deadline,
entry count, depth, and path-byte budget. Its schema-v3 receipt reports complete
counts but retains only bounded path samples. Exhaustion stops further traversal
and returns `status: incomplete` with a typed reason; it is never represented as
a complete no-activity result. Candidate artifact-directory probes are capped at
the exact retained-artifact cardinality before recursive classification. The
budget can block a new deletion before mutation starts, but a started deletion
always completes secure removal, parent-directory fsync, and receipt accounting
without an intervening deadline checkpoint.

Shadow cleanup recovery is also checkpoint-authoritative. Before deletion, the
engine fsyncs a fixed-root cleanup claim whose authenticated descriptor binds an
owner-only, content-addressed sidecar with the exact per-object inventory:
globally bytewise-sorted relative path, object type, device/inode, size,
owner/group/mode, link count, and the verified owner-only/no-ACL access policy.
New inventory-sidecar schema v2 entries additionally bind the exact SHA-256
content commitment of every regular file; directory commitments are null.
The checkpoint remains below its fixed bound regardless of legal inventory
cardinality. One budget is shared across every fixed root: traversal stops before
300,000 entries, 64 MiB of encoded relative paths, depth 64, or 300 seconds, and
the canonical sidecar may not exceed 256 MiB. Normal source, shard, and agent-task
acceptance limits conservatively reserve fewer entries than that cleanup ceiling,
including fixed directories and recovery artifacts. A limit failure retains the
raw tree without serializing a partial inventory. The engine revalidates every
complete inventory twice before any mutation, then moves each root into a
deterministic claim-scoped quarantine and
fsyncs a per-root `started` marker before recursive deletion. A retry accepts an
exact remaining subset only inside that quarantine. An unmarked missing root,
an original-path replacement, an unexpected quarantine entry, content/type
change, or access-policy drift leaves cleanup pending. Timestamps and directory
size/link-count changes caused by verified child deletion are not mutation
evidence. Recursive deletion consumes the authenticated expected inventory:
each file's identity, access policy, size, and, for v2 entries, SHA-256 content
commitment are revalidated through the held descriptor immediately before its
unlink. A null legacy commitment retains identity/policy compatibility but does
not gain a content-stability claim. The inventory proves the claimed object set
at each observation boundary; it does not claim an atomic defense against an
actively malicious
same-UID process between the final check and a rename or unlink syscall. After
deletion and absence verification, the engine fsyncs the final coverage-bound
cleanup receipt. A lost response after that close is an idempotent read and
revalidation of the same receipt. Durable progress markers distinguish a
legitimate completed root from externally removed data while preserving the
original counters; no caller may replace counters or paths.
The fixed roots are `raw-inputs`, `raw-shards`, `agent-sinks`, and
`retained-inputs`. Post-cleanup shadow validation and Daily successor derivation
use the already authenticated coverage receipt bound to the run, configuration,
model/policy era, and bundle digest; they do not reopen the deleted export-input
sidecar. New cleanup claims and receipts use the v5 claim schema with v2
inventory-sidecar descriptors. Authenticated legacy inventory-sidecar v1
entries remain contentless replay compatibility and never authorize a new
contentless inventory write. Exact
legacy v2 and v3 claims and receipts remain replayable only with their original
counter-only root inventories, while v4 inline exact inventories remain
replayable under their original all-roots-absent response-loss rule. v2, v3,
v4, and v5 claims, authorization references, and receipts cannot adopt one
another. Every published, shadow-complete, or expired terminal
path also clears a legacy embedded retained-input payload from the authenticated
checkpoint.

Formal post-publication cleanup and expired-run cleanup follow the same durable
claim pattern. Before deletion they fsync the authenticated v5 sidecar
descriptor for the fixed raw/source/shard/working roots. Retry uses that exact
inventory and durable quarantine progress, rejects unproved removal,
replacement, shrinkage, type or access-policy drift, verifies final absence,
then checkpoints the receipt. A response lost after deletion therefore
preserves the original byte/file/directory counts instead of recounting an empty
tree.

Lost-finalize recovery and garbage collection never infer publication from
matching retained roots alone. The signed publication commit must bind the exact
`attempt_ref`, immutable plan digest, expected parent history commit, actual
history commit, and bundle digest. Its committed tree must contain the complete
eight-file durable manifest, and the authenticated publication claim must match
that exact commitment byte for byte. A different same-root run or attempt cannot
authorize recovery or raw cleanup.

A publication-bound standalone export carries an authenticated heartbeat. A
live transaction may renew it only while its immutable plan remains resumable.
Once the heartbeat is more than seven days old, internal maintenance first
drives the exact transaction through recovery or a terminal abort and then may
delete its retained export. The public `export` command never performs this
maintenance against the caller's output parent, including when run validation
fails.

History verification and publication disable system and global Git
configuration, credential helpers, interactive prompts, lazy fetching, pagers,
and optional locks. Before object reads, both paths reject shallow repositories
and every repository-local partial-clone or promisor declaration; missing local
objects therefore fail instead of triggering network or credential access. They
pin the resolved OpenPGP verifier and validate every reachable commit that
changes `runs/**`. Each such commit must be a canonical signed publication that
adds exactly one eight-artifact bundle; modification or deletion of retained
history fails closed. An unrelated successor commit may advance the branch
after the publication target CAS. Recovery accepts that state only while the
exact publication commit remains reachable, then derives the provider cache
from the validated current history tip.

## Retention Expiry

At the seven-day raw deadline, a blocked or abandoned unpublished run retries
fd-anchored deletion of `raw-inputs`, `raw-shards`, `agent-sinks`, and
`retained-inputs`. Symlinks or parent replacement fail closed and leave cleanup
retryable. Successful expiry removes source catalogs, payload bindings, jobs,
shards, export inputs, and retained working results, preserving only
authenticated cleanup and content-free gap/run metadata.

Expired retained-export collection is an explicit internal maintenance call
over one operator-selected root. Its bounded receipt reports recovered,
terminal, deleted, and still-live entries; it does not run as an undisclosed
side effect of any public export request.

## Identity Mismatch

Never replace an identity to make an existing checkpoint or history validate.
Restore the matching owner-only key or begin a separately identified history era.
