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
- Source scheduling creates and binds each lease's owner-only capture directory
  inside the checkpoint transaction. Status only authenticates the existing
  binding. A stale status snapshot therefore fails closed after raw expiry
  cleanup instead of recreating the deleted `raw-inputs` tree.
- A job attempt is dispatched only through a bounded claim lease. Repeating the
  matching claim before expiry is an idempotent heartbeat; after expiry, another
  dispatcher may take over the same attempt with a new claim-specific envelope
  and output sink. Attempt count does not change during takeover.
- Native agent completion means the coordinator tool call returned and the
  result was accepted with the exact active, unexpired `claim_ref`. Results from
  expired or replaced claims fail closed. Finalization requires no open claim or
  output sink.
- A bound malformed agent result consumes one attempt. A second failure becomes
  an explicit content-free gap. JSON numeric overflow such as `1e999` is
  malformed at this ingestion boundary; it cannot become a non-finite stored
  value, and each rejected attempt closes its claim and output sink.

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
before it repairs commit. Changed attempts or projections fail closed.

`abort_pending` is an explicit recoverable publication phase. Open/recovery
dispatches its idempotent abort action before checking the now-conflicting live
history authority. The provider first persists an authenticated cleanup claim
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
is never rolled back.

Shadow cleanup recovery is also checkpoint-authoritative. Before deletion, the
engine fsyncs a fixed-root cleanup claim with an exact per-object inventory:
globally bytewise-sorted relative path, object type, device/inode, size,
owner/group/mode, link count, and the verified owner-only/no-ACL access policy.
It revalidates that complete inventory twice before deleting any claimed root;
replacement, removal, size change, type change, or access-policy drift leaves
cleanup pending. Timestamps are not mutation evidence. The inventory proves the
claimed object set at each observation boundary; it does not claim an atomic
defense against an actively malicious same-UID process after the final check.
After deletion and absence verification, it fsyncs the final coverage-bound
cleanup receipt. A lost response after that close is an idempotent read and
revalidation of the same receipt. If deletion completed before the close, the
durable claim supplies the original counters while the retry verifies that all
claimed roots remain absent; no caller may replace counters or paths.
The fixed roots are `raw-inputs`, `raw-shards`, `agent-sinks`, and
`retained-inputs`. Post-cleanup shadow validation and Daily successor derivation
use the already authenticated coverage receipt bound to the run, configuration,
model/policy era, and bundle digest; they do not reopen the deleted export-input
sidecar. New cleanup claims and receipts use the v4 schema that binds the exact
object inventory under all four roots. Exact legacy v2 and v3 claims and
receipts remain replayable only with their original counter-only root
inventories; v2, v3, and v4 claims, authorization references, and receipts
cannot adopt one another. Every published, shadow-complete, or expired terminal
path also clears a legacy embedded retained-input payload from the authenticated
checkpoint.

Formal post-publication cleanup and expired-run cleanup follow the same durable
claim pattern. Before deletion they fsync the authenticated v4 per-object
inventory for the fixed raw/source/shard/working roots. Retry uses that original
inventory, rejects replacement, removal, shrinkage, type or access-policy drift,
verifies final absence, then checkpoints the receipt. A response lost after
deletion therefore preserves the original byte/file/directory counts instead of
recounting an empty tree.

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

History verification disables system and global Git configuration, pins the
resolved OpenPGP verifier, and validates every reachable commit that changes
`runs/**`. Each such commit must be a canonical signed publication that adds
exactly one eight-artifact bundle; modification or deletion of retained history
fails closed. An unrelated successor commit may advance the branch after the
publication target CAS. Recovery accepts that state only while the exact
publication commit remains reachable, then derives the provider cache from the
validated current history tip.

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
