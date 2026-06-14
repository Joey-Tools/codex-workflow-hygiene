# Session Retrospective Improvement TODO

This document tracks the planned follow-up PR sequence for the session retrospective
automation. Keep each item reviewable as its own PR, with tests, the PR readiness
review gates, and merge before starting the next item.

## PR Sequence

1. Archived session time semantics
   - Ensure `archived_sessions` rollouts are covered by local and remote scans.
   - Prevent archive or unarchive file mtimes from defining session time.
   - Deduplicate active and archived copies of the same rollout, preferring the
     active copy.
   - Status: completed in PR #11.

2. Weekly dry-run and repair commands
   - Add first-class `weekly-dry-run` and `weekly-repair` commands instead of
     using `baseline-dry-run --window-days 7`.
   - Support a combined transient `--repair` path when appropriate.
   - Emit a compact human-readable report next to JSON reports.
   - Status: completed.

3. Local oversized rollout summaries
   - Generate bounded local rollout summaries for relevant oversized local
     rollouts instead of only emitting `oversized_rollout_skipped`.
   - Keep raw rollout files read-only and transient.
   - Preserve coverage gaps when summaries are partial, stale, or truncated.
   - Store generated summaries in ignored transient generated-summary
     directories and expose their root plus exact per-run generated file list
     only in the transient `shard_manifest.json`; retained manifests must drop
     both raw generated-summary fields.
   - Use a separate bounded generated-summary cap so trusted local generated
     summaries can feed both compact scan extraction and shard planning even
     when they are larger than the raw rollout cap.
   - Ensure both `scan-*` and `discover -> make-shards` can use the generated
     summaries, so compact extraction and map-reduce planning stay consistent.
   - Ensure repeated runs with the same output path do not let stale generated
     summaries from older runs feed `make-shards`.
   - Ensure stale checks for manifest-listed generated summaries keep using
     `source_sha256` even when `tail_record_limit_reached=true`, so a same-size
     backing rollout content change cannot be treated as ready coverage.
   - Bound generated-summary signal regex input with fixed-size chunk scanning
     for very large single-record payloads while preserving full-text signal
     detection, so middle-record signals cannot be silently hidden by coverage
     proof.
   - Preserve canonical local active-mtime fallback for generated summaries:
     complete coverage proof must receive the same mtime policy as raw rollout
     scanning, and generated records without timestamps should carry the active
     mtime fallback timestamp.
   - Trust `local_generated_rollout_summary_v1` coverage proof only for the
     exact generated summary files listed in the current transient manifest.
     Source-tree `rollout-summary*.jsonl` files must not become trusted local
     generated summaries merely by carrying the same JSON field.
   - Allow `tail_record_limit_reached=true` only for manifest-listed local
     generated summaries whose full scan completed and whose signal/match
     limits did not fire; omitted benign tail records must not keep valid
     oversized rollout coverage gaps open.
   - Store transient raw manifest paths as absolute paths so `discover` and
     `make-shards` can run from different working directories without losing
     generated-summary files.
   - Key retained turn/session/source-path identity for generated local
     summaries from the backing rollout ref, not the transient generated-summary
     artifact path, so repeated runs into different output directories produce
     stable retained identities.
   - Keep generated local summary retained `source_hash` aligned with the same
     backing rollout used for retained `source_path`, not the transient summary
     artifact.
   - Align generated local summary retained identity only when scan metadata
     proves complete bounded backing coverage; incomplete or over-cap backing
     rollouts must retain the summary artifact identity.
   - Resolve generated local summary backing identity and `source_hash` lazily
     only when emitting a retained turn, so no-flag summaries do not read
     backing rollout hashes.
   - Status: implemented in the local oversized rollout summaries PR; review
     and merge pending.

4. Remote oversized rollout summary completeness
   - Improve `rollout-summary` output for remote oversized rollouts so complete
     bounded signal can be distinguished from incomplete coverage.
   - Support chunked or multi-part summary records if needed.
   - Keep retained outputs free of raw remote transcript text.

5. Parallel remote materialization
   - Add bounded concurrency for host-level and rollout-level materialization.
   - Preserve deterministic reports, stable error collection, and read-only
     remote behavior.
   - Keep a conservative default for SSH and IO pressure.

6. Report readability
   - Add a compact report with window, host coverage, before/after gap counts,
     retained-readiness status, top blockers, next command, transient disk usage,
     and confidence.
   - Keep JSON reports as the machine-readable source of truth.

7. Safety and privacy flag calibration
   - Reduce false positives from ordinary paths, approval text, and host labels.
   - Separate true secrets, credentials, customer data, private URLs, and
     destructive/production risk from normal engineering context.
   - Add tests around representative false-positive and true-positive examples.

## Retained Readiness Bar

A weekly or baseline run is not retained-ready until:

- default host coverage is explicit for local, `miku-bot-dev`, and
  `hoteng-srv-01`;
- missing, stale, truncated, invalid, and oversized coverage gaps are either
  repaired or intentionally reported as blockers;
- archive and unarchive file mtimes do not decide the session window;
- retained export validation passes;
- the history commit and state advancement checks pass for retained workflows.
