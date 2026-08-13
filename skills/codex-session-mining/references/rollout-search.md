# Searching One Known Rollout With ripgrep 15.x

Use this protocol only for one exact regular rollout file that has already been selected. It is not a file-locator or corpus-search protocol, and it never authorizes a raw scan of an entire rollout tree.

Before using any template, run `rg --version` as a direct command and require the first line to report ripgrep major version 15. If ripgrep is unavailable or another major version is selected, do not improvise with these flags; use the bounded field-aware JSON recipes in [workflow.md](workflow.md) until that version has its own conformance evidence. This version check is a compatibility gate, not an instruction to install or replace host tooling during a search.

## Fixed Command Shape

Quote the exact rollout path in input redirection and put `--` immediately before the pattern. Pass every option and the pattern as separate arguments; never construct a command string or use `eval`.

Every command in this protocol uses:

```bash
rg \
    --no-config --no-mmap --text --encoding none \
    --no-heading --no-filename --color never \
    [PROTOCOL_OPTIONS] \
    -- "$PATTERN" < "$ROLLOUT"
```

Input redirection gives ripgrep one input stream, so an accidental directory path cannot fan out into a recursive, per-file search. Once the shell has opened the stream, replacing the pathname does not redirect that invocation to the replacement. This pure command recipe does not itself provide no-follow opening, regular-file authentication, or a frozen snapshot: resolve one exact rollout path, require it to be a regular file before running the command, and treat any open or read failure as a failed search.

The default is ripgrep's case-sensitive Rust regex engine. The only optional search flags allowed by this protocol are:

- `-F` or `--fixed-strings`.
- At most one of `-i`, `-s`, or `-S` for case handling.
- At most one of `-w` or `-x` for a word or whole-line boundary.

Insert allowed flags as literal, separate arguments before `--`. Any other flag leaves this protocol and loses its bounds and output guarantees. In particular, do not override output, framing, transformation, regex-engine, multiline, preprocessing, JSON, context, or fixed count/column options. Do not use options such as `-o`, `--replace`, `-0`, `--null-data`, `-P`, `--engine`, `-U`, `--multiline-dotall`, `--pre`, `--json`, `-A`, `-B`, or `-C`.

## Count Before Printing Matches

Run the fixed shape with these protocol options:

```bash
rg \
    --no-config --no-mmap --text --encoding none \
    --no-heading --no-filename --color never \
    --count-matches --include-zero \
    -- "$PATTERN" < "$ROLLOUT"
```

Interpret stdout and status together:

- Exit `0`: stdout is a positive decimal match count followed by LF.
- Exit `1`: stdout is exactly `0` followed by LF.
- Exit `2` or greater: the search failed; do not interpret stdout as a count.

For regex searches, the count is the number of non-overlapping matches, not the number of matching lines. One line can therefore contribute multiple matches.

Treat the counted file as an observed live input, not a frozen snapshot. If the path is not a regular file at the time of the search, stop instead of substituting another reader or following a special-file stream.

If the count is greater than 20, refine the pattern and count again by default. Do not print matching lines merely to orient yourself.

## Show Bounded Matching-Line Positions

For an initial count from 1 through 20, print a bounded sample of at most 20 matching-line positions:

```bash
rg \
    --no-config --no-mmap --text --encoding none \
    --no-heading --no-filename --color never \
    --line-number --column --byte-offset \
    --max-count 20 --max-columns 1 \
    -- "$PATTERN" < "$ROLLOUT"
```

The line number is the 1-based physical line number, and the column is a 1-based byte column. The byte offset is the 0-based offset of the matching line's start, not the match's offset. Multiple occurrences on the same line still produce one row. With `--max-columns 1`, ripgrep emits its short omitted-line marker instead of retaining a long source line.

Position output is always a bounded sample, never proof of a complete matching-line set. A live rollout can gain enough matches after the initial count for `--max-count 20` to stop successfully at 20 matching lines. Do not infer completeness from the initial count, the number of position rows, or exit `0`.

Accept position output only when this command exits `0`. Exit `1` after a positive count means the live input no longer matches; discard the output and restart from count. Exit `2` or greater is a search failure; discard stdout rather than treating partial rows as evidence. After an accepted sample, run the count command again; if the count changed, discard the sample and restart. Equal counts still do not freeze the input. In every case, let the subsequent bounded field-aware parser in [workflow.md](workflow.md) continue through point-in-time EOF and inspect its terminal `scan_meta` coverage and truncation counters instead of treating sample coordinates as exhaustive evidence.

Position output is not a sanitizer. A very short matching line without a final LF can still pass through as raw source, including a control byte. Treat stdout as sensitive and terminal-unsafe even though the normal omitted-line marker is small.

## Optionally Preview A Few Line Prefixes

Only when the initial count is from 1 through 5, an optional preview may show bounded prefixes of at most five matching lines:

```bash
rg \
    --no-config --no-mmap --text --encoding none \
    --no-heading --no-filename --color never \
    --line-number --column --byte-offset \
    --max-count 5 --max-columns 4096 --max-columns-preview \
    -- "$PATTERN" < "$ROLLOUT"
```

This is a line-prefix preview, not a match-centered excerpt. The match may occur after byte 4096 and therefore be absent from the preview. The source prefix can reach 4099 bytes when ripgrep finishes a UTF-8 code-point boundary; under this exact template, total successful stdout remains below 21 KiB.

Preview output is raw source data. It can expose secrets, terminal control bytes, or other sensitive content. Prefer the position-only command unless seeing source bytes is necessary.

As with positions, preview output is always a sample. Accept it only on exit `0`, then repeat the count and discard the preview if that count changed. Exit `1` means the earlier positive count is stale and requires a restart; exit `2` or greater is a failure. Discard stdout in either case. Even an unchanged count does not make the preview exhaustive or stable.

## Exceptional Exhaustive Matching-Line Artifact

Use an exhaustive artifact only when refinement is impractical and a local aggregate genuinely needs every matching line. Never print the artifact.

1. Create a fresh owner-private task directory with `mktemp -d` under the repository's `.codex-tmp`, choose a new artifact name inside it, and keep both exact pathnames. Do not reuse, truncate, or follow a pre-existing artifact path. This pure-shell recipe assumes no same-UID or privileged process tampers with that private directory; if that assumption is unavailable, do not create the artifact.
2. Obtain count `N` with the count command above. Require a positive decimal value and prove `N * 256 <= 67108864` (`N <= 262144`) before continuing.
3. Redirect this exact position command to the new artifact, substituting the validated decimal count as one argument. Set `umask 077` and shell noclobber so an existing regular artifact is not overwritten, then require the result to be a regular file:

```bash
(
    set -C
    umask 077
    rg \
        --no-config --no-mmap --text --encoding none \
        --no-heading --no-filename --color never \
        --line-number --column --byte-offset \
        --max-count "$COUNT" --max-columns 1 \
        -- "$PATTERN" \
        < "$ROLLOUT" > "$ARTIFACT" &&
    test -f "$ARTIFACT"
)
```

Require this artifact command to exit `0`. Under ripgrep 15.x on a 64-bit target, the fixed position framing plus `--max-columns 1` is less than 256 bytes per output row. `--max-count "$COUNT"` caps matching lines, so the artifact retains at most `N` rows and 64 MiB even if the input gains matches during the command. This is a retained-stdout bound only; it is not a runtime, RSS, stderr, input-read, or privacy bound.

Shell noclobber is not a general `O_EXCL`/no-follow primitive: special objects such as FIFOs and same-UID replacement races are outside this recipe's protection. The owner-private-directory and no-tamper precondition is therefore part of the artifact contract, not an implementation detail.

Run the count command a second time after artifact creation. If the second count differs from `N`, classify the artifact as incomplete and do not use it as exhaustive evidence. Equal counts still do not freeze the file or prove content stability: matches or surrounding content can change while preserving the same count.

Aggregate the artifact locally without printing its contents. When finished, remove its task-scoped `.codex-tmp` subpath with:

```bash
"$HOME/.codex/bin/codex-clean-tmp" "$TASK_SUBPATH"
```

Here, `TASK_SUBPATH` is the exact task-scoped path relative to `.codex-tmp`, not an arbitrary filesystem path.

## Evidence Limits

ripgrep provides a best-effort live text scan. This protocol does not parse the rollout schema, validate JSON, select fields, create a snapshot, or prove object identity or content stability. Follow candidate line positions with bounded, field-aware JSON parsing before treating a match as evidence.

The documented stdout budgets do not bound stderr. Diagnostics can repeat the pattern or other sensitive details, so keep diagnostic output in a private bounded sink when failure details are needed and never reinterpret stderr as search evidence.

The protocol has no default deadline. When the actual one-file scan is broad or expected to run for a long time, apply the `bounded-command-output` skill and choose a task-specific deadline rather than inventing a universal timeout.
