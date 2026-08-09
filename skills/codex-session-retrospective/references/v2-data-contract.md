# Session Retrospective v2 Data Contract

The coordinator and all local transport workers require Python 3.13 or newer.
The public entrypoint remains parseable under the Python 3.9 grammar solely so
older runtimes can emit the closed unsupported-runtime result before loading the
engine package; that parse path does not add runtime support.

## Source Transport Authority

A source cell is accepted only when all of these independently bound objects
agree:

- an identity-authenticated transport lease issued by the coordinator;
- the exact leased worker/engine program commitment and, for remote work, the
  run-owned `$remote-host-context` helper snapshot commitment;
- a closed source transport stream with an authoritative inventory terminal;
- an authenticated transport receipt binding the lease, manifest, independently
  derived source snapshot, transcript commitment, and terminal proof;
- exact raw bytes from the sealed stream or exact `session-shards` requests and
  streams that reassemble to that same transcript.

Arbitrary `eof_proof`, `terminal_receipt_ref`, path strings, or self-hashed
snapshots are not coverage evidence. Truncation, byte/count mismatch, program
replacement, helper replacement, and terminal mutation fail before the source
cell or cursor changes.

The transport program commitment uses a closed allowlist for every executable
Python module in the local v2 package, including package initialization,
catalog, contracts, identity, transport, and the worker entrypoint. The actual
package-tree `.py` inventory must equal that allowlist; a missing or unexpected
module fails closed. Each component is opened relative to an fd-anchored package
directory with `O_NOFOLLOW`, must be a bounded regular file, and is hashed only
after matching `fstat` and no-follow name identities before and after the read.

Before a remote lease is committed, the parent opens the installed
`$remote-host-context` helper and writes its exact bytes to an owner-only,
content-addressed snapshot below that run's `raw-inputs` tree. The source
commitment derived from that same descriptor-bound read must equal the run's
frozen helper provenance before snapshot publication or lease creation. The
worker receives only the snapshot path and SHA-256 commitment. Its isolated
`-I -B` bootstrap opens the snapshot with no-follow descriptor checks, verifies
regular-file identity, owner, mode, link count, byte count, and digest, then
compiles exactly those retained bytes. Replacing the installed helper after
scheduling cannot change the program that executes, replacing it between leases
cannot mix helper versions within one run, and source acceptance revalidates the
same run-owned commitment.

`session_index` and `history` use bounded metadata JSONL transport. Active and
archived rollouts use bounded rollout JSONL transport. Remote execution is always
delegated to `$remote-host-context`; v2 contains no SSH command, host table, or
generated remote program.

The `session-shards` adapter validates authoritative descriptor EOF, derives the
exact records-mode request, validates request/resume bindings and conservation,
and reassembles fragments before acceptance. One oversized logical JSONL record
retains one stable source/turn identity regardless of transport fragment count or
local shard packing. Transcript bindings cover exactly the `source_ref` values
that contain consumed candidates. Excluded-only source refs stay in catalog
accounting and require no raw transcript.

Descriptor pagination binds one stable source object, frozen byte end, record
coordinates, and domain-separated full-prefix commitment in every closed resume
cursor. Later appends cannot extend that descriptor snapshot. Continuation pages
must repeat the requested source token, frozen byte end, byte offset, and record
index exactly. Each page stops before its derived records stream would exceed
1,024 data frames, using the closed `max_record_data_frames` continuation reason.
A retained transcript stores every descriptor page first, followed by one exact
records stream per page. The adapter validates and closes the complete descriptor
chain before lazily replaying those contiguous records requests into the
coordinator. Abandoning any records iterator closes its replay immediately even
while the outer segment iterator remains live. Descriptor pages alone are
discovery metadata and never authorize retained raw evidence.

The `session_shards_source_v2` token binds device, inode, mode, owner, group, and
the platform generation and birth-time fields when they exist. On a filesystem
that supplies neither generation nor birth time, a same-inode replacement with
byte-identical frozen content cannot be distinguished from the prior object;
this is an explicit platform non-guarantee, not an identity proof. Every
records-mode request separately scans and hashes the complete frozen prefix into
an owner-only temporary spool before emitting its first frame. Content mutation
anywhere in that prefix therefore rejects the stream even on the fallback
platform, while the spool retains only the requested byte range and closes on
every terminal path.

Remote descriptor and record streams are incrementally validated before spool.
Every frame is either consistently wrapped and bound to the exact requested
host and rollout, or consistently legacy-unwrapped and wrapped locally with
those exact values; missing wrappers at the adapter boundary, mixed wrapper
mode, and cross-host or cross-rollout replay fail closed. Record relay output is
bounded from the requested byte range plus compact metadata allowance, with
per-frame size, coordinates, fragments, hashes, counters, and terminal
conservation checked before the complete output can be retained.
Fragment continuation also repeats the logical record byte range, record-index
range, delimiter width, encoding, and complete-record commitment; drift in any
one field rejects the relay before retained output exists.

## Accounting, Shards, And Jobs

Every discovered source unit ends in exactly one accounting class:
`consumed_candidate`, `structurally_excluded`, or `explicit_gap`. Duplicate active
and archived copies retain distinct physical-file occurrence coordinates. An
archived record is excluded only by the closed canonical-equivalence rule when
there is exactly one equivalent active record; multiple active files never
collapse. Source discovery walks the complete active-rollout year/month/day
hierarchy through descriptor-relative no-follow opens under global entry and
candidate ceilings. It therefore includes old still-active sessions; exhausting
either ceiling produces an explicit coverage gap instead of a partial catalog.
Before a complete or no-activity terminal, the worker reopens every traversed
active directory through its anchored identity chain and requires the bounded,
type-aware entry snapshot to remain exact. A replacement or entry-set change is
an explicit enumeration gap rather than an incomplete success.
Archived discovery remains window-bound, and filesystem mtimes never prefilter
candidates. Resume positions use the closed
`source_transport_resume_v4` schema. They carry a public
`accepted_prefix_commitment` transition chain plus the exact trailing probe
range and content commitment; the chain is authoritative only because the
incoming position is carried by the authenticated durable checkpoint, lease,
and exact stream header and the outgoing position is independently reconstructed
by capture before the receipt is issued. `source_token` and public stat fields
never create or replace that authentication.

Each invocation may spend at most three 64 KiB internal reads on resume probes;
budget exhaustion is the explicit `source_resume_probe_budget_exhausted` gap.
The worker rereads the current page separately to prove page stability, freezes
the original source size so later appends are not admitted to that snapshot, and
retains only the bounded trailing bytes needed to construct the next probe. It
never rescans `0..byte_offset` to continue. Without an immutable source snapshot,
this O(page) continuation detects only mutation intersecting the bounded
prior-prefix probe; it does not detect or claim to detect arbitrary mutation deep
in already accepted history. Every enumerated candidate is scanned or represented
by an explicit bound/transport gap, and stable event time, cursor, and window
classification happens only after the bounded read. Logical turn sequencing
preserves each physical file's
`byte_start` order before digest tie-breakers while deterministically merging
different files. Session mode consumes only records matching `session_target`,
records discovered for other sessions remain structurally accounted without
retained raw payload, and a submitted non-target consumed record is rejected.

- Extractor shard: at most 20 turns and 480 KiB.
- Agent input: at most 512 KiB, including its control envelope.
- Job identity: HMAC-derived from immutable inputs, role, schema, prompt, policy,
  and retry ordinal.
- Attempt identity: unique to one fresh launch and never reused as evidence
  identity.
- Task-cache metadata conserves every deterministic task lookup: one miss per
  created task, one hit/reuse per returned existing task, and the sum of
  per-task reuse counts. These counters and agent attempts are retained in run
  provenance.
- Claim identity: a bounded dispatcher lease over one attempt. Heartbeat extends
  only the matching unexpired claim; expiry permits safe takeover on the same
  attempt with a new envelope and output sink. Result acceptance binds the exact
  active, unexpired claim. Each fresh attempt permits exactly two claim
  generations: the initial claim and one expired-lease takeover. Further takeover
  or an over-limit result sink records `agent_claim_budget_exhausted` and closes
  that attempt through the ordinary retry/explicit-gap state machine without
  counting an agent result or accumulating more claim files.
- Accepted source records and raw-payload indexes live in canonical, owner-only,
  content-addressed sidecars under `raw-inputs/source-acceptances`; authenticated
  checkpoint state stores only bounded descriptors and a compact manifest summary.
  Checkpoint capacity is proved before any file is created. New raw files, the
  sidecar, and the exact next checkpoint revision are then staged under one
  checkpoint lock: a proved unchanged old revision rolls back only identity- and
  content-matching files, an exact committed new revision retains them, and an
  unreadable or inconsistent disposition fails closed with explicit retained-file
  evidence. Rollback revalidates the held file's identity, single-link state,
  owner-only access policy, and exact content through two bounded descriptor reads
  before unlink. A same-schema checkpoint that still carries the legacy full
  manifest or inline payload index remains readable; the next accepted continuation
  validates conflicts and migrates that index into the new sidecar before clearing
  the inline copy.
- Raw run directory: mode `0700`; every file: mode `0600`. On Darwin, each
  owner-only directory and file must also have no extended ACL. Newly created
  objects clear inherited ACLs through their held descriptors before use;
  existing objects with an ACL fail closed rather than being repaired.
- Successful publication removes raw shards. Blocked raw state expires within
  seven days and remains an explicit recoverability/coverage outcome.

Extractor validation receives bounded original prompt/tool-output material or
safe fingerprints directly from the sealed raw shard. It rejects ordinary raw
overlap before retained state is written; raw material never leaves working
retention. Each reassembled record is streamed through a strict UTF-8 and JSON
token parser. The parser validates literals and numbers with a closed grammar;
an invalid primitive cannot consume a following string. Object keys,
non-string primitives, and validated low-risk classifiers such as role/type/status
plus semantic timestamps are not source-prose candidates. Instance-bearing IDs,
host and cwd values, typed references, digests, and commitments always remain
source candidates. Every other decoded string value, including long
escaped values and surrogate pairs, is case-folded, whitespace-normalized, and
split into overlapping bounded windows; no long prose value is skipped. The
normalizer accumulates one-character parser emissions in fixed-size chunks and
keeps the active window in a bounded deque rather than repeatedly copying a
growing string. The
result-side projection contains only the extractor's schema-authorized
`turns[].generalized_working_text`, both before and after deterministic
post-redaction. Typed references and hashes are exempt from source-literal
replacement only in result-side schema fields that are independently format- and
allow-list validated; the same bytes in retained prose are rejected. Fixed enum,
status, outcome, and object-key strings are not treated as retained source-derived
prose. Window batches have independent
item and aggregate-character bounds while preserving enough overlap to detect a
query split across windows or transport fragments.

The complete export input is stored as one owner-only, content-addressed
`retained-inputs` sidecar. Authenticated run state retains only its descriptor.
The descriptor binds canonical byte count, SHA-256 commitment, and the one
allowed relative filename; loading reads no more than that exact byte count and
revalidates the canonical payload, digest, run, mode, and window. Existing
same-v2 checkpoints with the exact legacy embedded `{run_state, review_data}`
shape remain readable, but new writes always use the sidecar. The sidecar is a
fixed authenticated cleanup root and is never retained in durable history.
Idempotent replay of each authenticated published, shadow, or expired terminal
cleanup clears any legacy embedded retained input after revalidating the
terminal receipt.

## Partial And Backfill Lineage

Controlled missing-host authority uses the closed reasons
`missing_host_holdout` for production and `shadow_missing_host_holdout` for
shadow runs. Its authenticated aggregate receipt binds the partial run, host,
window, every required source kind, and every accepted source transport receipt.
It requires a later backfill and cannot authorize extraction, review, reduction,
malformed JSON, processing-budget, authentication, or transport gaps.

A backfill binds the controlled-gap receipt, `backfill_of`, the exact durable
backlog reference, prior episode revisions, episode-head root, and stable anchor
membership. A stable match must append one successor revision. An unmatched
episode from the exact controlled missing host may create one new initial
revision; session-only fallback matching is forbidden and every unrelated prior
head remains unchanged. The full proposed head projection is durable state, while
only changed or new revisions enter the review workset.

The sole exception is a direct shadow successor derived from a completed Daily
partial by `--shadow-successor-of`. Its authenticated shadow gap derives an
exact run-local backlog reference without changing durable history. This
exception is unavailable to production, cannot enter `finalize`, and cannot
advance or suppress production host coverage.

Extractor control metadata binds each goal, workstream, evidence, and span
reference to one logical turn. A turn cannot borrow another turn's references
from a shard-wide union. After validation, the coordinator resolves goal and
workstream continuity in canonical session order from the closed
`goal_change`/`workstream_change` decisions. Backfill predecessor matching
requires a stable turn or goal anchor; a session-default workstream alone is
never a semantic predecessor.

A successor review receives payload material for every member turn, including
all turns inherited from its prior durable head. If any prior validated payload
cannot be restored from the current sealed extraction material, the coordinator
records `episode_turn_material_gap` with an exact missing-ref commitment and
blocks before creating a partial review input. A prior turn reference without
its validated material is never treated as coverage.

Oversized episode reviews use validated hierarchical children. Every parent
binds the exact child result hashes and conserves all high/critical events and
findings, high-impact turn adjudications, risk flags, associated evidence,
escalation/conflict decisions, and the minimum child confidence. Omitting any of
those values rejects the parent result.

Episode adjudication additionally carries both validated candidate results and
an ordered `candidate_item_decisions` trace. Every candidate event, finding,
strength, risk flag, high-impact turn, and evidence reference must be selected,
merged with duplicate support, or explicitly rejected with a closed reason and
the exact candidate hash/reviewer/attempt provenance. Downstream topic input
embeds and revalidates that complete candidate context; an adjudicator cannot
silently erase candidate-unique content.

## Automation Cutover Authority

`automation_cutover_snapshot_v2` is captured before the capability call and
identity-authenticates the exact stable-ID inventory, canonical record paths,
and either the absent state or verified existing record digest.
`automation_update_result_v2` then contains exactly the available
`automation_update` capability, that snapshot ref, and one successful
`register` or `update` operation for each stable ID:
`daily-session-retrospective` and `weekly-session-retrospective`. Registration
is admissible only for a snapshot-proven absent ID and requires a null previous
digest. Update is admissible only for a snapshot-proven existing ID and requires
its exact distinct previous digest. The internal authority derives the result
commitment after validating installed bytes. Missing capability, opaque result
refs, stale or forged pre-state, and every extra or unrelated ID fail closed.

`automation_cutover_record_v2` binds the owner identity, installed release
commit, exact installed v2 CLI path, operation lineage, and current SHA-256 plus
identity-derived reference for both fixed `automation.toml` paths. The engine
reads those records with bounded no-follow I/O and requires owner ownership,
non-group-writable paths, active cron state, mode-appropriate schedule and
prompt, and no reference-only, v1, shadow, holdout, or partial-production
controls. The production marker embeds the complete authenticated cutover
record and must include its release commit.

## Retained Bundle

Every published run contains exactly:

```text
manifest.json
coverage.json
episodes.jsonl
turn_findings.jsonl
topics.jsonl
trend_report.json
report.md
summary.json
```

The retained bundle contains summaries, findings, strengths, reviewed prompt
rewrites, typed metrics, confidence, opaque references, and pre-tree provenance
only. Episode rows retain the exact revision ordinal, superseded revision,
review-result hash, reviewer, and attempt lineage. High-impact turn rows retain
the validated `problem_statement`, `cause`, `rewritten_prompt`,
`expected_effect`, `confidence`, and opaque evidence references. These four
reviewed text fields are the only retained prose exception and remain subject to
ASCII, length, locator, and credential scans. The bundle never contains raw or
quoted original prompts, excerpts, tool output, source paths, raw IDs, internal
URLs, secrets, credentials, customer data, personal data, or proprietary code.

Retained prose is also content-validated, not merely field-name validated.
Original/verbatim prompt markers, tool or command output markers, role
transcripts, direct source-request shapes, code/shell/key-value payloads, UUIDs,
opaque internal IDs, and exact source-derived prompt/tool payload overlap are
rejected. A useful generalized `rewritten_prompt` remains admissible when it
does not reproduce those source forms.

`manifest.json` retains the complete non-sensitive execution contract: actual
model/provider/closed parameters, prompt digest/version, schema and transport
bindings, component versions, configuration root, and every agent job's result,
retry, reviewer, and issued/claimed/completed timing provenance. An opaque
configuration commitment cannot replace these fields.
Agent execution provenance includes the exact deterministic task-cache
hit/miss/reuse conservation alongside every job, result, retry, reviewer, and
issued/claimed/completed timestamp.

Trend rates use all meaningful turns or episodes as denominators and are reported
per 100. Incompatible model/policy/configuration eras are rendered separately and
never compared as direct improvement or regression.

Topic-reducer output uses a closed result schema. Validated topic aggregation
contains evidence-bound episode/session membership and cross-session measures;
global synthesis consumes those aggregations rather than byte-equal reducer
input.

Topic inputs are partitioned from bounded episode reviews before the 64 KiB
result-contract validator is called. The durable partition index commits every
expected episode revision and leaf input hash; reducers then combine only
validated bounded children through the hierarchy. The coordinator never first
constructs or validates one oversized topic input.

Global synthesis requires a bijection between durable topic-input roots and
accepted final topic tasks: every expected root appears exactly once, with no
duplicate or extra root, before any dictionary reconstruction. Hash-key
overwrite cannot collapse duplicate results.

Global synthesis represents each exact canonical topic-signal union with a
SHA-256 commitment and count plus at most 64 deterministic exemplars, selected
high-severity-first and then by canonical order. The commitment and exact topic
result hash inventory prevent omitted non-exemplar signals from disappearing.
Retained compilation verifies the finding commitment against topic rows and
writes the complete canonical finding/evidence union to `summary.json`, not just
the bounded exemplars.

Durable episode, topic, and global records use closed per-finding objects. Every
object preserves the exact finding kind, confidence, optional severity, and
non-empty opaque `evidence_refs` that justified that finding. Topic findings are
the exact canonical union of their member episode findings, and global findings
are the exact canonical union of the retained topic findings. Counts cannot
replace these records, and evidence references cannot be dropped or rewritten
during reduction. The existing privacy rules still reject prose, raw content,
paths, identifiers, URLs, secrets, and any non-opaque evidence reference.

## Calibration And Durable Authority

Calibration receipts bind the exact corpus commitment and configuration root.
Precision, recall, and F1 use bounded integer numerator/denominator pairs;
missing denominators fail. The signed private Git publication chain is durable
authority. The owner-local HMAC production marker records completed cutover, and
the provider cache is initialized only by a request that proves
`expected_revision=0` exactly, independently of the current durable-history
projection revision, and then derived from each newly validated history commit.

Production cutover binds exactly `daily-session-retrospective` and
`weekly-session-retrospective` to the installed v2 CLI path. The internal
authority API admits either a verified update of an existing record or an exact
first registration of those stable IDs. Unrelated IDs, unavailable
`automation_update`, a reference-only template, or a different executable path
cannot establish production authority.

Episode heads form an append-only revision chain. A successor advances the
ordinal by exactly one, names the exact predecessor revision, and preserves the
predecessor's `session_ref` byte for byte. Session reassignment requires a new
episode identity and cannot be hidden in a superseding revision.

## Durable Guidance Threshold

AGENTS.md, Skill, and automation candidates require evidence from at least three
episodes across at least two sessions. One independently reviewed high-severity
safety issue may qualify as an exception. Every candidate carries a closed list
of exact `{episode_ref, session_ref}` pairs. Each pair must match validated topic
lineage and retained episode lineage; unrelated episodes or a real episode paired
with the wrong session fail closed.
