# Codex Session Mining Recipes

Use this workflow to recover prior work, select a rollout for inspection, build a complete current-host corpus, or audit repeated workflow friction from the user's local Codex history.

## 1. Select The Smallest Relevant Rollout Set

Use the available `session_index.jsonl`, `history.jsonl`, active and archived rollout filenames, date layouts, cwd hints, and user phrasing to select the smallest useful candidate set. The model may choose whichever bounded lookup fits the evidence; there is no canonical exact-ID, recent-session, or broad-index command recipe.

Do not print raw rollout JSONL during candidate discovery. A locator zero-match proves only that the chosen lookup did not find a candidate. It does not prove that the rollout, session, or requested evidence is absent. Try another relevant locator source, or use the complete current-host corpus when the conclusion requires completeness.

Once one exact rollout is selected, use the scanner in section 2. For all-session, date-window, or repeated-friction work, build the union corpus before classification.

### Bounded Date Range And Current-Host Corpus

Bounded date range and current-host corpus inventory:

```bash
set -euo pipefail

TASK_DIR=.codex-tmp/session-mining-20260312-20260313
LOWER_BOUND=2026-03-12T00:00:00Z
UPPER_BOUND=2026-03-14T00:00:00Z
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
SESSION_MINING_SKILL="$CODEX_ROOT/skills/codex-session-mining"

python3 "$SESSION_MINING_SKILL/scripts/build_session_corpus.py" \
    --codex-home "$CODEX_ROOT" \
    --start "$LOWER_BOUND" \
    --end "$UPPER_BOUND" \
    --output "$TASK_DIR" \
    --sample-limit 20
```

Inventory every rollout under both existing roots before applying the requested lower and upper bounds to record or lifecycle timestamps; the helper above enforces that order. This full-root inventory is required for both active and archived rollouts: a rollout created before the window can resume with a genuine human suffix inside it. Do not exclude a file because its dated path or filename predates the window. When a rollout has no record timestamps, the helper prefers the full second-level timestamp or date encoded in its rollout filename, then falls back to a dated directory; archive moves, copies, or metadata updates make mtime unsuitable as the filter.

Budget this command for the complete active-plus-archived corpus, not for the apparent width of `LOWER_BOUND..UPPER_BOUND`. Prefer a previous successful runtime for the same host plus a conservative margin; otherwise use the current full-root scale rather than a short interactive wait as the deadline basis. The helper publishes its counts and output directory only after the complete snapshot succeeds, so quiet stdout is expected. Poll a healthy process with compact elapsed-time, CPU, and process-state checks; do not cancel it merely because no progress line appeared.

A timeout, cancellation, or interrupted producer is an incomplete scan and supplies no reusable checkpoint. Before any retry, prove the original producer and its descendants are quiescent. If quiescence cannot be proved, do not start another full-root scan; retain the process and output-path evidence for handoff. After quiescence is proved, retry with a different fresh nonexistent output directory.

Cleanup of the failed-run path is optional. The protected property is that output directory's object identity. The device/inode or platform-equivalent identity recorded when the directory first appeared, compared with an immediate pre-removal revalidation, detects a replacement that happened before that check; child-entry churn inside the same directory is not an identity mismatch. That comparison does not close the check-to-delete replacement window: a one-shot pathname revalidation followed by recursive deletion can still remove a different directory substituted by another same-UID process. Permit removal only through a trusted descriptor-relative cleanup primitive that binds both the verified parent directory and target directory identities throughout the operation, or under platform containment that prevents replacement. If only pathname-based recursive deletion is available, leave any present path untouched and retain the recorded identity for handoff rather than claiming safe cleanup. If the target is missing at revalidation, classify that result separately as missing: do not recreate it or delete anything at that pathname, retain the recorded path and identity as unresolved handoff evidence, and do not claim this run verified cleanup. If quiescence becomes uncertain, the baseline identity is unavailable, revalidation is unreadable, or the current identity mismatches, likewise leave any present path untouched. Never interpret missing output as an empty corpus, reuse a partial directory, or claim the requested window was fully scanned.

The helper reports `active candidate count`, `archived candidate count`, `union candidate count`, matching parsed counts, `active accepted count`, `archived accepted count`, `union accepted count`, cross-root duplicate groups among accepted candidate groups, collapsed duplicate rollouts, and replayed-prefix records. It requires a fresh nonexistent output directory, lexically normalizes dot segments before traversal, rejects untrusted symlink ancestors, and creates the complete candidate and accepted path lists, `manifest.json`, `corpus-paths.txt`, and `corpus.jsonl` there without following or replacing existing artifact paths. Inventory snapshots and revalidates every traversed directory plus each entry identity and file type; both read passes reopen candidate files from the root directory descriptor with no-follow components and reject replacement or truncation. Non-printable rollout path components fail closed before line-delimited path artifacts or terminal samples are emitted. The first pass pins the complete-record prefix observed when it opens each same-inode rollout, deferring only an unterminated invalid final fragment from an active rollout; the second pass consumes only that verified unchanged prefix, so normal append-only growth remains safe. It prints only the counts plus a bounded union sample. Each `corpus.jsonl` entry retains a distinct suffix, the inferred `owner_id`, all observed `lifecycle_ids`, its in-window `accepted_record_count`, and compact `accepted_line_ranges`; use those locators plus narrowly selected nearby context when reconstructing the real task. For a multi-ID rollout, the filename UUID is accepted as owner only when every identity alias in its first lifecycle record agrees; later foreign IDs are retained as embedded provenance. Owner-later or otherwise ambiguous histories cannot prefix-bridge sessions, although byte-identical copies with the same complete lifecycle-ID set are still safely collapsed. Timestamp-less empty files stay visible in candidate/parsed counts but are not accepted as zero-record tasks. Committed invalid JSON, any invalid archived tail, unsafe path shapes, and inventory or read failures stop the scan instead of silently shrinking the corpus. Groups with no record or fallback timestamp inside the requested window stay in candidate/parsed counts but do not enter the fingerprint-loading pass.

### Current-Host Union And Deduplication

- Treat the existing active and archived roots as one union corpus. Record per-root candidate and accepted counts so a missing root or unexpected zero cannot disappear into a combined total.
- Do not deduplicate by basename or path precedence alone. Prefer the lifecycle session ID from `session_meta`; when it is unavailable, use the filename session ID only as a candidate key and confirm equivalence with ordered stable record fingerprints. Normalize complete UUID-shaped lifecycle aliases to lowercase before comparing them with filename UUIDs, while preserving non-UUID opaque IDs exactly.
- Treat shared lifecycle or filename identity as a required candidate boundary before fingerprint-prefix collapse. Do not merge different session identities from matching content alone: two intentional runs can have identical wrappers and user prompts. Investigate suspected cross-identity fork replay separately with bounded source-history evidence.
- Collapse a byte-identical second file completely, including mixed owner/ambiguous filename cases when both copies carry the same complete lifecycle-ID set. For a non-byte-identical branch, collapse its normalized prefix only through the last matching assistant/tool replay-evidence record; preserve every matching human prompt after that boundary as an uncertain genuine suffix. Fingerprint `session_meta` from explicit lifecycle IDs alone, taking those identities from the actual payload rather than a generated outer envelope when the record is wrapped, and fingerprint `turn_context` from its wrapper type. Canonicalize known generated item, call, response, and turn IDs by per-rollout order while preserving their reference relationships, including computer-call outputs. Keep provenance IDs, unknown substantive record fields, and nested IDs or timestamps inside content and tool results. Identical wrappers plus a repeated user prompt are not sufficient replay evidence.
- Choose canonical history in two stages: first use the earliest of every known record timestamp, or an available filename/path fallback when every record is timestamp-less, to establish source provenance; then compare the complete record-order timestamp and presence sequence to break ties. A short partially restamped copy must follow the older source even when that source's first timestamp is missing, a sparse-timestamp copy must not outrank a complete source with the same provenance start, and an exact old prefix still precedes its longer genuine continuation. Keep a missing fallback explicitly unknown so later known record timestamps remain visible.
- When a filename UUID is unavailable, use a single identity from the first lifecycle record as the owner and retain later lifecycle aliases as provenance. Keep a rollout ambiguous when that first record itself exposes conflicting aliases.
- Recognize `time` alongside `timestamp`, `ts`, `created_at`, and `updated_at` for window filtering, and remove those volatile fields from replay fingerprints. Report a cross-root duplicate group only when candidates from different roots actually share a collapsed copy or removed replay prefix; same-root overlap in a mixed group is not cross-root duplication.
- Serialize fingerprint inputs and JSON corpus artifacts with ASCII escapes so valid JSON strings containing isolated Unicode surrogates remain deterministic and never fail UTF-8 encoding with an uncaught traceback.
- Apply replay detection after the cross-root grouping. A copied and restamped prefix does not become new activity merely because it moved into `archived_sessions`, while a later direct human turn remains new evidence.
- Filter injected `AGENTS.md`, skill, environment, and automation wrapper records when reconstructing user intent. Exclude synthetic child, subagent, and external-review prompts from main-task counts, but do not drop a main rollout solely because its first user-shaped record is an automation wrapper; inspect and retain its later genuine human suffix.

## 2. Scan One Exact Rollout

Use the standalone scanner instead of raw rollout text, an embedded Markdown parser, or a whole-value JSON search:

```bash
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
SCANNER="$CODEX_ROOT/skills/codex-session-mining/scripts/scan_rollout.py"
ROLLOUT=/absolute/path/to/rollout-example.jsonl

python3 "$SCANNER" shapes --path "$ROLLOUT"
python3 "$SCANNER" search --path "$ROLLOUT" --literal 'case-sensitive text'
python3 "$SCANNER" search \
    --path "$ROLLOUT" \
    --literal 'case-sensitive text' \
    --mode evidence \
    --category tool_output
python3 "$SCANNER" search \
    --path "$ROLLOUT" \
    --literal 'task_started' \
    --category event
```

`search` normalizes Unicode whitespace independently in each selected field, then applies a nonblank case-sensitive literal of at most 1024 UTF-8 bytes. It never concatenates fields. The default `evidence` mode uses an explicit typed whitelist for user, assistant, tool-call, tool-output, and task-complete evidence. Metadata and lifecycle events are searched only when `--category metadata` or `--category event` is requested. `user-text` conservatively includes structurally identified user text without heuristically deleting wrapper text. A direct string `/payload/origin_hint` on a user-message record is record-level provenance, not searchable evidence or a claim that role=`user` is human; it is whitespace-normalized, capped at 80 characters, and marked when truncated. Non-string hints are ignored. Repeat `--category` to select more than one category.

The tool-call whitelist follows each record schema rather than applying one broad alias set: function and custom calls use their documented name/argument or input fields, while computer calls and `web_search_call` use `action`. The listed function, custom, and computer output record types use only the explicit output/content/result aliases. Unknown fields remain structural orientation for `shapes`; they are not silently promoted into searchable evidence.

The opt-in `event` category accepts only outer `event_msg` records with registered payload types. It maps `task_started` identifiers and collaboration mode, `turn_aborted` reason, `stream_error` retry messages, terminal `error` messages, and entered/exited review-mode fields, plus the outer timestamp and exact registered payload type. Numeric timing fields, `codex_error_info`, unknown payload fields, and unregistered event types are not searchable. Match record metadata also preserves bounded `turn_id`, `item_id`, and `trace_id` when present.

Each matching physical record produces at most one `match` event. Its bounded `hits` entries identify category, role, field path, and a short safe snippet. The default result window is 20 records and may be raised to 250 with `--max-results`. The result-event byte budget defaults to 64 KiB and may be raised to 256 KiB with `--max-output-bytes`; fixed small `start`/`end` protocol headroom is separate, so detail pressure cannot suppress the terminal event. The scanner continues reading after presentation limits are reached so terminal coverage and per-category matched/emitted/suppressed record counts remain meaningful.

`shapes` emits value-free structural skeletons: outer and payload type, role, sorted bounded field paths, and container/scalar types. It retains the first 20 distinct shapes in first-seen order and counts those exactly while continuing the scan. Shape detail events use a fixed 64 KiB aggregate budget; the terminal event reports emitted and suppressed retained shapes, so detail pressure cannot hide `end`. Records with unretained shapes increment a separate counter; the output does not claim a complete distinct-shape count.

### Typed JSONL Protocol

Every invocation writes typed JSONL to stdout. Every event carries `schema: codex.rollout-scan/v1`, one `run_id`, and a continuous `seq`:

- `start` is first and binds the invocation's `run_id`, sequence, source observation, command, and limits.
- `match` is emitted and flushed as each retained search result is found.
- `shape` is emitted only when `shapes` reaches normal or semantic-partial termination.
- `end` is last, uses the same `run_id`, and closes a continuous `seq` sequence.

Require `end` before interpreting the run. Missing `end` means `interrupted`; every preceding result is provisional. Terminal statuses are:

- `checked`: the scanner examined the complete eligible records in its descriptor-bound prefix. Zero matches establish no-match only for the scanner's selected fields in that observed prefix; a deferred unterminated tail is outside that claim.
- `partial`: earlier emitted positive matches are valid evidence, but the run cannot establish an exhaustive count or no-match result.
- `unavailable`: the input could not be scanned under the input contract.

These structured terminal statuses exit 0. Invalid CLI usage exits 2. Internal failures, stdout write errors, and crashes exit nonzero.

### Stateless Result Windows

There is no opaque cursor or saved spool. `--result-offset N` skips the first `N` matching-record ordinals and supports sequential continuation or a random jump. Every invocation reopens and independently rescans the file:

```bash
python3 "$SCANNER" search \
    --path "$ROLLOUT" \
    --literal 'case-sensitive text' \
    --result-offset "$NEXT_RESULT_OFFSET" \
    --prefix-end-bytes "$FROZEN_PREFIX_BYTES"
```

Read `next_result_offset` and `frozen_prefix_bytes` from the previous `end` event. The next offset advances by actually emitted result records only. Reusing the prior prefix bound excludes later append, but it does not detect a same-inode in-place rewrite. Each page remains an independent descriptor-prefix observation, not a stable multi-page snapshot. If one more window is needed, prefer a refined category/literal or raise the result count or byte limit once within the hard caps.

### Input And Completeness Boundaries

The scanner accepts one absolute UTF-8 path to a no-follow regular-file descriptor. It opens the exact supplied path, binds the size observed after open, and reads only that initial prefix or the smaller explicit `--prefix-end-bytes` bound. Append after open is excluded. The result describes a descriptor-prefix observation; it does not claim content stability or take a second content snapshot. To keep the protocol bounded, `start.source.path` is capped at 4096 UTF-8 bytes and replaced by a UTF-8-safe prefix plus a digest when longer; `path_truncated`, the original UTF-8 byte count, and the complete path digest make that projection explicit. This display bound does not change which path is opened.

Only complete physical LF-delimited records are parsed. An unterminated tail is deferred and reported only while it stays within the 1 MiB record cap; an unterminated candidate that exceeds the cap stops immediately with `partial`. The scanner caps cumulative actual reads including lookahead at 192 MiB and input records at 250,000. It decodes each physical record with strict `utf-8-sig`, accepting at most one leading UTF-8 BOM per record. The first malformed JSON, oversized record, invalid UTF-8, second consecutive leading BOM, or foreign UTF-16/UTF-32 encoding stops the scan with `partial`; earlier valid positive results remain usable, and later bytes are not recovered. This deliberately excludes the former no-BOM little-endian recovery path.

## 3. Audit Repeated Skill Friction

- First inventory both existing current-host transcript roots and list the sessions in scope. Report active, archived, union, and accepted-after-deduplication counts separately.
- Detect resumed or forked replay before counting new activity:
  - Count records by session and measure the timestamp span before printing details. Hundreds of thousands of records or old user tasks appearing within seconds are replay signals, not evidence that the work happened again.
  - Emit a bounded sequence of `session_meta`, `turn_context`, `task_started`, and user-message summaries around each resume point. Do not orient with the full rollout.
  - Compare the suspicious prefix with earlier source history using a stable fingerprint over record type, role or call name, and normalized selected content. Keep the source path and ordering in the comparison.
  - Choose the latest genuine resume boundary, exclude only the matching replay prefix, and retain later human follow-ups. Do not deduplicate a real repeated short prompt solely because its text matches an earlier prompt.
  - When the same lifecycle session appears under active and archived roots, compare ordered stable record fingerprints across both files and retain any distinct later suffix instead of choosing one path wholesale.
  - Exclude synthetic child/reviewer task prompts from main-task classification, but keep later genuine human follow-ups in a main rollout even when its initial turn was automation boilerplate.
  - Report replayed and genuinely new record counts separately so the audit remains reviewable.
- Then look for the smallest decisive evidence:
  - user asked for a skill explicitly but it was not used
  - a helper or auth preflight was rediscovered manually
  - an outdated path or command shape caused a miss
  - the same bounded workflow appeared multiple times without a reusable skill
- When a problem shows up only once, prefer leaving a note instead of immediately creating a new skill.

## 4. Escalate To Remote Coverage Only When Needed

If the user is asking for a work summary, activity audit, or session recovery that may include remote hosts, use an environment-specific remote evidence workflow before concluding that the local `~/.codex` tree is complete.
