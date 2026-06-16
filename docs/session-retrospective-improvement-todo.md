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
   - Status: completed in PR #19.

6. Report readability
   - Add a compact report with window, host coverage, before/after gap counts,
     retained-readiness status, top blockers, next command, transient disk usage,
     and confidence.
   - Keep JSON reports as the machine-readable source of truth.
   - Ensure ready sources with coverage gaps are shown as blocked in the compact
     host coverage summary.
   - Ensure repair reports suggest another follow-up command when repairable
     gaps remain.
   - Preserve the current repair `--max-raw-bytes` in generated repair follow-up
     commands, so repeated repairs do not fall back to the parser default.
   - Do not emit an automatic repair follow-up command when the repaired scan
     still has oversized coverage gaps at the same raw-byte cap; instead report
     that a higher `--max-raw-bytes` is required.
   - Status: completed in PR #20 with follow-up fixes in PR #21, PR #22, and
     the oversized follow-up guard PR.

7. Safety and privacy flag calibration
   - Reduce false positives from ordinary paths, approval text, and host labels.
   - Separate true secrets, credentials, customer data, private URLs, and
     destructive/production risk from normal engineering context.
   - Add tests around representative false-positive and true-positive examples.
   - Keep every sensitive-signal addition paired with local redaction coverage;
     retained prompt summaries must not keep the raw value after a safety flag.
   - Keep local rollout extraction, remote helper extraction, and generated
     remote probe scripts in parity for compact/camelCase credential keys.
   - Cover object-style credentials, prefixed auth headers, multi-word auth
     schemes, and concise production-operation phrases with paired tests.
   - Treat safe credential status words as exact values only; do not let a
     word-boundary match skip real values such as `required-secret-*`.
   - For auth scheme values such as `Authorization: Token ...`, require paired
     safety-signal and redaction tests that prove the full value is removed.
   - For English and Chinese customer, tenant, account, and organization
     identifiers, require both signal tests and retained-output redaction checks.
   - Status: implemented by the safety/privacy calibration change; scope covers
     local rollout flags and remote rollout-summary signal extraction.

8. Weekly dry-run local oversized summary cache
   - Avoid repeated cold-start summary generation for the same local oversized
     rollouts across weekly dry-run output directories.
   - Keep generated summaries per-run and manifest-scoped, but reuse a
     transient `.codex-local/session-retrospective` cache keyed by backing
     rollout SHA-256 when available, bounded scan SHA-256 for scan-capped
     rollouts, source size, rollout ref, host, mtime fallback, and summary
     parameters.
   - Do not let cache files become source evidence unless the current run
     copies a validated cache hit into its generated-summary root and lists it
     in the transient manifest.
   - Preserve conservative window semantics for old archived rollouts: only
     skip when existing bounded timestamp/window checks can prove irrelevance;
     otherwise use the cache to reduce repeated cost without dropping possible
     cross-day or cross-month turns.
   - Status: implemented in the weekly local summary cache change.

9. Weekly coverage diagnostics hardening
   - Preserve `remote_source_not_materialized` for explicit default remote
     source paths, so materialization gaps do not degrade into generic missing
     roots when callers pass default host paths explicitly.
   - Split report output into repairable and non-repairable coverage gap counts,
     and make next-command notes clear when repair only covers a subset of the
     blockers.
   - When repair leaves oversized coverage gaps and backing byte sizes are
     known, suggest a follow-up repair command with a higher rounded
     `--max-raw-bytes` instead of only saying no same-cap command is useful.
   - Treat live rollouts or summaries that disappear during scan or shard
     discovery as volatile coverage gaps instead of crashing a weekly run.
   - Merge shard-only coverage gaps into dry-run and repair reports so
     `make-shards` blockers cannot disappear after the transient scan.
   - Preserve source `root_ref` in shard rows so shard-only path gaps block only
     the matching source root, not sibling sources on the same host.
   - Filter volatile shard-discovery gaps through rollout and summary date
     hints before reporting them, so old or future files that vanish after
     discovery do not block the requested scan window.
   - Treat missing date hints conservatively for disappeared files: only
     suppress a volatile gap when the path hint proves the file is outside the
     requested window.
   - Scan long assistant/tool records for issue flags in bounded overlapping
     chunks rather than head/tail sampling, so middle-record failure and
     safety signals are not lost.
   - Keep old oversized archived rollouts conservative when the bounded
     timestamp scan cannot prove they are outside the window; generate a
     bounded local summary when possible, otherwise preserve the coverage gap.
   - Exclude generated local summary artifacts from transient `summary_refs`,
     so `make-shards` does not mistake an existing generated summary for a
     disappeared source summary when output lives under the source root.
   - Treat disappearing rollouts during generated-summary preprocessing as a
     skip for that preprocessing pass; the later scan loop owns volatile gap
     reporting.
   - Treat disappeared pre-window rollout and summary refs conservatively in
     scan and shard planning; a path date before the window does not prove the
     file lacked in-window records or backing refs.
   - Catch disappearing oversized rollouts inside the bounded prefilter itself
     and treat the relevance as unknown instead of aborting the scan.
   - Read direct `shards.jsonl` files beside a scan `shard_manifest.json` when
     repairing scan-output runs, not only nested or sibling shard directories.
   - Prefer nested dry-run shard outputs over stale top-level shard files when
     repairing a weekly or baseline dry-run directory.
   - Preserve `remote_source_not_materialized` for default remote roots that
     disappear between scan and shard planning, so repair can rematerialize the
     host instead of treating the gap as local `source_root_missing`.
   - Treat legacy shard rows that say `source root missing` for default remote
     hosts as `remote_source_not_materialized` during dry-run report and repair
     planning, so older transient runs remain repairable.
   - Parse dates from root-level `rollout-summary-YYYY-MM-DD...jsonl` filenames
     so future disappeared summaries can be safely suppressed.
   - Store transient scan-time rollout and summary refs in `shard_manifest.json`
     and compare them during `make-shards`, so files that disappear before
     rediscovery still become volatile shard gaps instead of being silently
     treated as retained-ready.
   - Compare scan-time and rediscovered rollout refs by active/archived
     duplicate key so a post-scan archive move of the same rollout does not
     create a false volatile gap.
   - Compare scan-time and rediscovered rollout refs with the full rollout
     match-key set, including flat archived undated aliases.
   - Preserve safe nested root-scan rollout refs in transient manifests so
     copied or materialized root-level rollout files cannot disappear before
     shard planning without a volatile gap.
   - Reuse manifest `root_ref` for shard-only gap rows so source coverage
     grouping stays aligned with the scan manifest even when raw roots were
     normalized between scan and shard planning.
   - Status: implemented in the weekly coverage diagnostics follow-up change.

10. Weekly local summary signal scan performance
   - Avoid long cold-start weekly dry-runs spending excessive CPU in summary
     signal regex scans for cross-window oversized flat archived rollouts.
   - Reuse bounded summary chunks per record instead of rebuilding chunks for
     every signal category.
   - Precompile non-sensitive summary signal category patterns while preserving
     overlapping marker semantics and the existing output order.
   - Combine sensitive summary signal detection into one compiled pattern so
     local summary generation and remote rollout-summary extraction stay in
     parity.
   - Use a cheap sensitive-signal prefilter before the heavy sensitive regex
     on ordinary long tool-output chunks.
   - Use the local-summary scan cap for old oversized rollout relevance before
     generating summaries, and skip partial summaries for larger old rollouts
     when no in-window timestamp is found inside that cap.
   - Keep the behavior conservative for long-lived archived sessions that
     genuinely contain in-window records; optimize signal extraction rather
     than skipping cross-day or cross-month evidence.
   - Status: implemented in the weekly summary signal performance follow-up.

## Retained Readiness Bar

A weekly or baseline run is not retained-ready until:

- default host coverage is explicit for local, `miku-bot-dev`, and
  `hoteng-srv-01`;
- missing, stale, truncated, invalid, and oversized coverage gaps are either
  repaired or intentionally reported as blockers;
- archive and unarchive file mtimes do not decide the session window;
- retained export validation passes;
- the history commit and state advancement checks pass for retained workflows.
