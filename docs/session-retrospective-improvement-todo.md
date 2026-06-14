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
     rollouts must keep the coverage gap and must not emit retained turns with
     transient generated-summary artifact identity.
   - Resolve generated local summary backing identity and `source_hash` lazily
     only when emitting a retained turn, so no-flag summaries do not read
     backing rollout hashes.
   - Status: completed in PRs #13 through #16.

4. Remote oversized rollout summary completeness
   - Improve `rollout-summary` output for remote oversized rollouts so complete
     bounded signal can be distinguished from incomplete coverage.
   - Support chunked or multi-part summary records if needed.
   - Keep retained outputs free of raw remote transcript text.
   - Generate trusted remote summaries during coverage repair when raw fetch
     fails or when the fetched rollout is still larger than the repaired scan
     limit.
   - Trust remote-generated summary-only coverage only when the current
     materialization metadata and transient manifest list the exact summary
     file and its `scan_meta` carries complete `remote_generated_rollout_summary_v1`
     proof.
   - Emit `remote_generated_rollout_summary_v1` proof only for complete scans
     with a valid `source_sha256`; summaries with parse errors, truncation,
     keyword filters, record limits, or tail limits must remain coverage gaps.
   - Consumer-side proof validation must also reject missing or malformed
     `source_sha256`; do not let invalid proof switch a remote summary into
     generated-summary identity mode.
   - When coverage repair can fetch a remote raw rollout but it still exceeds
     the scan limit, keep only the bounded generated summary after complete
     proof succeeds; otherwise the oversized raw copy would recreate the same
     coverage gap on the repaired scan. If cleanup cannot remove that oversized
     raw copy, keep the source non-ready instead of publishing ready metadata.
   - Do not delete a fetched oversized raw rollout merely because
     `rollout-summary` exited successfully. First revalidate the written summary
     with the same `remote_generated_rollout_summary_v1` proof gate used by
     consumers; if proof is missing, malformed, truncated, filtered,
     tail-limited, parse-error-limited, or missing a valid `source_sha256`, keep
     the raw copy so later scans can report or repair the backing rollout
     directly.
   - Likewise, when raw fetch fails and repair falls back to remote
     `rollout-summary`, do not publish ready materialization metadata unless
     the fallback summary passes the same complete proof gate. A successful
     command without trusted proof is still a `remote_source_not_materialized`
     coverage gap because no raw backing exists.
   - Never hash a materialized remote backing rollout above the configured
     hash cap while validating generated-summary identity; treat that backing
     as untrusted unless bounded summary-only proof is sufficient.
   - Do not let `source_bytes`-only summary identity suppress an oversized raw
     rollout gap when the backing is above the configured hash verification
     cap; without `source_sha256` or trusted generated proof, the later scan
     must still report the oversized backing directly.
   - Keep ordinary source-tree `rollout-summary*.jsonl` files conservative:
     they must still have materialized backing rollouts or they remain coverage
     gaps.
   - Resolve retained `source_path`, `source_hash`, and session identity per
     backing rollout record for trusted remote-generated summaries; mixed
     summary files must not reuse the first `scan_meta` identity for every
     retained turn.
   - Status: completed in PR #18.

5. Parallel remote materialization
   - Add bounded concurrency for host-level and rollout-level materialization.
   - Preserve deterministic reports, stable error collection, and read-only
     remote behavior.
   - Keep a conservative default for SSH and IO pressure.
   - Expose `--remote-host-jobs` and `--remote-rollout-jobs` on repair commands,
     defaulting to `2` and capped at `8`; `1` preserves serial behavior.
   - Status: implemented in the parallel remote materialization PR.

6. Report readability
   - Add a compact report with window, host coverage, before/after gap counts,
     retained-readiness status, top blockers, next command, transient disk usage,
     and confidence.
   - Keep JSON reports as the machine-readable source of truth.
   - Status: implemented in the report readability PR.

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
