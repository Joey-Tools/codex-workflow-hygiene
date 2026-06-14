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
     directories and expose their root only in the transient
     `shard_manifest.json`; retained manifests must drop the raw
     generated-summary path.
   - Use a separate bounded generated-summary cap so trusted local generated
     summaries can feed both compact scan extraction and shard planning even
     when they are larger than the raw rollout cap.
   - Ensure both `scan-*` and `discover -> make-shards` can use the generated
     summaries, so compact extraction and map-reduce planning stay consistent.
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
