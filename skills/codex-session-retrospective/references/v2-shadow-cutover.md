# Session Retrospective v2 Shadow And Cutover

## Calibration Gate

Calibration consumes an ignored owner-only labeled corpus and emits an
identity-authenticated receipt bound to the exact corpus and configuration. The
engine validates precision, recall, episode-boundary F1, minimum denominators,
and privacy holdout results before accepting a passing receipt. Raw prompts and
tool output are never included in the receipt.

## Shadow Gate

Under one unchanged configuration, complete:

1. two distinct Weekly shadow runs, each covering the defined exact seven-day
   window across every configured host;
2. one Daily partial run and exact controlled missing-host backfill over the
   same explicit non-empty Daily window;
3. complete source accounting, retained validation, and raw cleanup.

Shadow runs use an explicit existing owner-only identity under `.codex-local`.
They export the production-shaped eight-file candidate with
`publishable=false`, clean all run-owned raw data, and cannot enter formal
`finalize` or advance production provider state.

The Daily cycle uses the installed v2 coordinator only. Start the partial with
`--shadow --mode daily --allow-partial`, record exactly one
`shadow_missing_host_holdout`, and finish export plus cleanup. Start the
backfill with the same window/configuration and
`--shadow-successor-of <partial-run-dir>`. The engine derives the missing host,
gap receipt, lineage, and a run-local backlog. It also authenticates the partial
checkpoint revision, coverage receipt, export digest, and cleanup receipt in a
successor authorization bound to the window, provenance, history ref, and host.
Every shadow backfill requires that authorization; caller-supplied
host/backfill/gap arguments are forbidden. The run-local backlog exists only for
this shadow successor. Production backfill still requires the exact published
durable backlog, so the shadow mechanism cannot suppress production coverage.

Each signed coverage receipt binds the actual window start and end, mode
semantics, exact source-snapshot inventory, exact source-transport-receipt
inventory, their combined commitment, and the exact export bundle digest. The
signed cleanup receipt binds that coverage receipt and the same bundle digest.
The production gate requires four distinct run references: two Weekly runs with
distinct seven-day windows and distinct source/export commitments, plus distinct
Daily partial and backfill runs with the controlled-gap lineage. Replayed source
evidence, synthetic mode labels, or cleanup for another export fail closed.

Coverage is not a caller-supplied attestation. The shadow export authority accepts
only an owner-only staged-bundle locator, loads the identity-authenticated
checkpoint through an fd-anchored run root, re-verifies every accepted transport
lease/receipt/snapshot, reconciles host and controlled-gap accounting, rebuilds
the expected retained artifacts, and validates the exact eight-file staged
bundle. It derives the digest and binds the checkpoint revision, immutable run
specification, configuration root, policy/model eras, and exact policy/version
commitments itself. There is no public coverage or cleanup issuer that accepts
those values as arguments.

Shadow cleanup first stores an authenticated fixed-root claim containing the
observed inode inventory and counters for `raw-inputs`, `raw-shards`, and
`agent-sinks`. The cleanup transaction then deletes only those anchored roots,
fsyncs their parent, confirms absence, and commits the coverage-bound cleanup
receipt in the authenticated checkpoint. A retry after deletion or a lost close
response uses the durable claim and returns the same receipt; pre-removed,
replaced, symlinked, regrown, or caller-selected paths fail closed.

## Operational Cutover

Cutover is an operator deployment procedure, not a custom PKI, witness, escrow,
or lease protocol:

1. verify the shadow and calibration gates and the installed release commit;
2. pause v1 automation and verify no v1 run is active;
3. preserve the final v1 artifacts for audit without importing their cursors;
4. initialize the owner-local provider cache from the validated private-history
   head using exact `expected_revision=0` request equality, independently of the
   current history projection revision;
5. run and publish one exact 90-day Baseline genesis;
6. use the `automation_update` capability to update verified existing records or
   first-register exactly `daily-session-retrospective` and
   `weekly-session-retrospective` at their stable `~/.codex/automations/**`
   paths, then have the separate cutover controller issue the internal authority
   record and run a bounded Daily canary.

The internal cutover authority verifies the installed TOML records, exact
installed v2 CLI path, active mode-specific production prompts, authenticated
pre-update state, operation lineage, and complete capability-result commitment.
It rejects reference-only templates, v1 paths, shadow/partial coverage controls,
and unrelated IDs. The separate controller writes
`~/.codex/session-retrospective/automation-cutover-v2.json`; production marker
issuance embeds and authenticates that record and the installed commit. Missing
`automation_update` capability leaves cutover blocked, including when an old
record already exists.

After successful cutover, an owner-local HMAC production marker stores the
configuration, installed commits, accepted shadow references, history repository
binding, exact automation cutover record, and `cutover_complete=true`. It is an
accidental-drift gate, not an active lease and not protection against the local
owner. It remains valid for ordinary publication while every operation
revalidates the latest signed durable history chain.

There is no extra Baseline campaign identity. Older 90-day historical windows
are independent runs and cannot alter the forward cursor handoff.
