# Session Retrospective v2 CLI

Use exactly the installed
`~/.codex/skills/codex-session-retrospective/scripts/session_retrospective_v2.py`
for the modular v2 engine. The repo-relative script is a source artifact, not an
automation entrypoint. Its command surface is limited to:

```text
doctor
start
status
accept-source
accept-agent-result
advance
export
finalize
```

There are no bootstrap, cutover-lease, campaign, identity-initialization,
source-preparation, or execute-source commands. Durable private Git history is
publication authority. Owner-local marker and provider files are derived state.

All examples use the same installed path:

```bash
V2_CLI="$HOME/.codex/skills/codex-session-retrospective/scripts/session_retrospective_v2.py"
```

## Identity

Production uses the fixed `~/.codex/session-retrospective/identity-v2.key`.
Shadow `doctor` and `start` require both an explicit `--identity-path` and
`--require-existing-identity`; neither command creates an identity.

## Run Loop

```bash
python3 "$V2_CLI" start \
  --shadow \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --mode weekly \
  --start 2026-07-06T00:00:00Z \
  --end 2026-07-13T00:00:00Z \
  --run-dir "$RUN" \
  --run-config "$RUN_CONFIG" \
  --history-repo "$HISTORY" \
  --history-target-ref refs/heads/main

python3 "$V2_CLI" status \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --run-dir "$RUN"
```

For each source job, run the ordered `native_coordinator_actions` returned by
`status`:

1. capture the bounded transport command at its run-owned `stdout_path`;
2. run the provided `accept-source` command.

`accept-source` authenticates the transport lease, terminal proof, authoritative
snapshot, manifest, and receipt before changing coverage. Raw source files must
remain under `<run-dir>/raw-inputs/`; arbitrary output directories are rejected.

For rollout sources, concatenate one complete `$remote-host-context
session-shards` descriptor stream and its exact requested records stream in one
owner-only JSONL file, then bind it to the manifest source:

```bash
python3 "$V2_CLI" accept-source \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --run-dir "$RUN" \
  --lease-ref <lease_ref> \
  --transport-stream-file "$RUN/raw-inputs/source-transport.jsonl" \
  --transport-stream <source_ref> "$RUN/raw-inputs/session-shards.jsonl"
```

The adapter validates descriptor EOF, derives the exact records request,
normalizes only the authenticated wrapper, and conserves fragmented record bytes.
`$remote-host-context` remains the only SSH layer; v2 contains no SSH behavior.

Repeat `status -> native actions -> accept results -> advance` until exportable.
Run `export` once. A shadow export cleans raw state and completes locally. For a
production run, repeat parameterless `finalize --run-dir "$RUN"` until the
durable commit, provider derivation, and cleanup are complete.

`export` validates its identity, run, retained inputs, prior-period source, and
exact destination. It never scans or garbage-collects sibling paths under the
caller's `--output` parent. Expired-export collection is a separate internal
maintenance action with an explicitly selected root and bounded result.

Pass the previous exact retained bundle directory when an operator-selected
period is required:

```bash
python3 "$V2_CLI" export \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --run-dir "$RUN" \
  --output "$OUTPUT" \
  --prior-period "$PREVIOUS_RETAINED_BUNDLE"
```

`--prior-period` requires all eight owner-only retained artifacts and revalidates
their inventory, digest, schema, conservation, and privacy contracts. To select
the latest publication from the run's configured signed Git history instead,
use the mutually exclusive authenticated-history path:

```bash
python3 "$V2_CLI" export \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --run-dir "$RUN" \
  --output "$OUTPUT" \
  --prior-history
```

`--prior-history` verifies the complete signed append-only history chain and
loads the latest exact eight-artifact bundle at the run-bound repository and
target ref. In both paths, the prior trend's closed metric inventory, rates,
era strata, confidence, and compatibility key are validated before normalized
changes can be emitted.

Claim each runnable agent job through the existing `status` command. A fresh
claim atomically returns a claim-specific envelope, output sink, `claim_ref`, and
bounded expiry:

```bash
python3 "$V2_CLI" status \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --run-dir "$RUN" \
  --claim-job-ref <job_ref> \
  --claim-attempt-ref <attempt_ref> \
  --dispatcher-ref <dispatcher_ref>

python3 "$V2_CLI" accept-agent-result \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --run-dir "$RUN" \
  --job-ref <job_ref> \
  --attempt-ref <attempt_ref> \
  --claim-ref <claim_ref> \
  --result-ref <result_ref> \
  --result <output_sink>
```

Heartbeat an unexpired claim by repeating the same `status` claim with its
`--claim-ref`. After expiry, omit the old claim ref to take over the same attempt
with a new dispatcher-bound claim, envelope, and output sink. The old claim can
no longer submit a result.

## Shadow Daily Successor

Start the Daily partial with the complete canonical host set and no production
provider or marker binding:

```bash
python3 "$V2_CLI" start \
  --shadow \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --mode daily \
  --allow-partial \
  --start "$WINDOW_START" \
  --end "$WINDOW_END" \
  --run-dir "$PARTIAL_RUN" \
  --run-config "$RUN_CONFIG" \
  --history-repo "$HISTORY" \
  --history-target-ref refs/heads/main

python3 "$V2_CLI" advance \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --run-dir "$PARTIAL_RUN" \
  --holdout-host miku-bot-dev \
  --holdout-reason shadow_missing_host_holdout
```

Complete the normal loop and shadow export. Only after the partial reaches
`stage=complete` and `publication.phase=shadow_complete`, start its direct
successor:

```bash
python3 "$V2_CLI" start \
  --shadow \
  --identity-path "$IDENTITY" \
  --require-existing-identity \
  --mode daily \
  --start "$WINDOW_START" \
  --end "$WINDOW_END" \
  --run-dir "$BACKFILL_RUN" \
  --run-config "$RUN_CONFIG" \
  --history-repo "$HISTORY" \
  --history-target-ref refs/heads/main \
  --shadow-successor-of "$PARTIAL_RUN"
```

Do not pass `--host`, `--backfill-of`, `--controlled-gap-receipt`,
`--allow-partial`, a provider state, or a production marker. The coordinator
derives the exact missing host, authenticated gap, lineage, window, provenance,
and run-local backlog from the completed partial. This path requires
`--shadow`; production continues to require a matching backlog in durable
history. Shadow export cannot call `finalize` or advance provider/production
coverage state.

## Automation Cutover Authority

The separate cutover controller must call `automation_update` for exactly
`daily-session-retrospective` and `weekly-session-retrospective`. Before the
tool call it captures an identity-authenticated snapshot through the internal
`retrospective_v2.authority` API. After the call it passes the complete result
and snapshot to that API, which verifies the exact stable IDs, operation type,
previous and installed record digests, installed v2 path, production prompts,
and result commitment before writing
`~/.codex/session-retrospective/automation-cutover-v2.json`.

The controller uses this exact internal sequence; it is not an engine command:

```python
snapshot = authority.capture_automation_cutover_snapshot(
    authority.automation_cutover_snapshot_path(),
    identity=identity,
)
capability_result = automation_update_for_stable_ids(snapshot)
record = authority.issue_automation_cutover_record(
    authority.automation_cutover_record_path(),
    identity=identity,
    capability_result=capability_result,
    pre_update_snapshot=snapshot,
    installed_commit=installed_commit,
)
```

`capability_result` must use `automation_update_result_v2` and carry one
successful operation per stable ID, the authenticated pre-update snapshot ref,
the exact previous digest, and the exact installed digest. The result ref is
derived internally from the complete validated result; caller-supplied opaque
result references are rejected.

Cutover is not a public engine CLI verb. A `reference_only` record, v1 path,
`--shadow`, `--allow-partial`, `--holdout-host`, unrelated automation ID,
unavailable capability, forged first registration, or stale update digest is
not admissible. The production marker authority requires the exact internal
record and an `installed_commits` inventory containing its installed commit.

## Modes

- Every mode requires a non-empty half-open `[start, end)` window.
- Weekly windows are exactly seven days.
- Baseline windows are exactly 90 days and carry no campaign identity.
- Session mode requires both `--session-target` and
  `--session-target-selector`; the target must equal the identity-derived
  reference for that selector. These arguments are rejected for all other
  modes. Session runs structurally account discovered non-target records and
  reject any non-target consumed record.
- Daily backfill requires an authenticated controlled-gap receipt; prior episode
  heads and their stable anchor membership are always derived from durable
  history and cannot be supplied by the caller.
- A Daily `--allow-partial` run records an explicit missing-host holdout through
  `advance --holdout-host HOST --holdout-reason REASON`. Complete hosts advance
  their own cursors; held hosts keep their prior cursor and publish a durable
  backlog reference for the required backfill.

Every command emits one canonical JSON object. Raw payloads never appear in CLI
results or diagnostics. Failure objects include an allowlisted `reason_code`,
an allowlisted `recovery_action`, and `retryable`; raw exception text is never
used as automation guidance. Unknown failures collapse to
`unexpected_internal_failure` plus `escalate_internal_failure`.
