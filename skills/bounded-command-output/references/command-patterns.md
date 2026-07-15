# Bounded Command Patterns

Use these patterns after the main skill decides that a command needs an output budget. Adapt paths, predicates, and limits to the task instead of copying placeholders literally.

## Searches And Inventories

| Situation | Start with | Open next | Avoid |
| --- | --- | --- | --- |
| Large repository or generated-output-heavy tree | Stream `rg --files <exact-dir>` through a total counter plus an explicit `N`-path sampler, with repo-appropriate exclude globs | One exact file, symbol window, or small explicit file list | Printing the full file inventory or running raw broad `rg -n` |
| High-frequency identifier or large alternation | A total count plus an explicit `N`-filename sample | A bounded match against one exact file | A line-producing multi-file search as the first probe |
| Large review range | Stream `git diff --numstat` or `git diff --name-only` through aggregate counters plus an explicit `N`-path sampler | Selected-file or selected-hunk diffs; save a full stat only to an enforced bounded sink when required | Printing a full stat/name inventory or one wide whole-range diff |
| Potentially large untracked set | `git status --short --untracked-files=no`, then stream `git ls-files --others --exclude-standard` through a total counter plus an explicit `N`-path sampler | Explicit candidate paths | Full untracked or ignored inventory first |
| Sibling repository or reference checkout | Choose one exact repository and bounded file list; exclude generated output and dependency lockfiles unless relevant | Selected files only | Searching a broad parent directory or multiple repository roots |
| Package metadata, cache JSON, lockfile, or binary | Check file type and size; use a structured parser or candidate-key extraction | Selected keys, symbols, or snippets | Raw broad search or unbounded `strings` output |

Common generated-tree excludes include:

```text
!**/node_modules/**
!**/target/**
!**/dist/**
!**/out/**
!**/build/**
!**/vendor/**
```

An inventory command is not bounded merely because each item is short. Consume it with a streaming counter/sampler that retains at most `N` items and emits only the total plus those items; preserve the producer's exit status with the shell's pipeline-status mechanism. Do not print the complete inventory before counting or sampling it.

For embedded payloads, minified bundles, or other very long lines, prefer counts, stream `rg -l` through the total-counter/`N`-filename sampler, or use bounded `rg -o` or structured length/snippet extraction. `rg --max-count` limits matches per file, so it does not replace a bounded candidate file set.

## Logs, Artifacts, And Manuals

- Let the domain skill perform access and authentication preflight before fetching a remote artifact.
- Save large GitHub Actions, Jenkins, crash, or build logs to a task-scoped file. Inspect metadata first, then extract counts, targeted key lines, or a short tail.
- For GitHub Actions, prefer `gh run view --json ...` for metadata. Save `--log` or `--log-failed` output before filtering it.
- For public specs, standards, or manuals fetched with `curl`, use an output file or a bounded range. Extract headings, anchors, or short relevant passages instead of streaming the full document.
- List archive members first. Extract or print only selected members instead of searching the entire expanded tree with a broad line-producing command.
- Quote shell-sensitive URLs when a shell is required. Prefer direct argv forms so `*`, `?`, `[`, `]`, `&`, backticks, and `$` are not rewritten.

Keep the full retained artifact under a task-scoped directory such as `.codex-tmp/<task>/` or a task-specific temporary directory. Do not mix it into a broad source-tree search.

## Process And System Diagnostics

- Start with PID- or name-scoped probes such as `pgrep -af <pattern>`, `ps -p <pid>`, or `lsof -nP -p <pid>`.
- For `log show`, bound the process, predicate, and time window; save a potentially large result before extracting key events.
- Use a count or a small explicit sample before any wider process inventory.
- Avoid full `ps aux`, `ps -ef`, `ps -A`, `ps -e`, `ps axww`, or broad `ps -axo ...` output unless the task specifically requires the complete process table.

## Builds, Tests, And Polling

For verbose `xcodebuild`, Swift, package-manager, or container builds, create the log path first and redirect both stdout and stderr before the process begins. A live PTY does not bound output by itself.

Before launch, set both a finite wall-clock deadline and a maximum byte count across the entire retained-log set. Enforce the byte limit with a quota-bounded sink, a rotation policy that caps both aggregate bytes and segment count and removes or reuses old segments before writing more, or a supervisor that terminates the producer as soon as the limit is reached; ordinary unbounded rotation, post-exit size checks, and periodic `wc -c` observations are not enforcement. The deadline must terminate the producer with a bounded grace period. Byte enforcement must either keep the whole retained set below its fixed ceiling or terminate the producer with the same bounded grace period. Treat any terminated or evicted stream as incomplete when the workflow requires the full log, reject that result, and retain only bounded diagnostic evidence.

For carriage-return or spinner-heavy tools such as `/usr/local/bin/container build`, do not rely on `--progress plain` or a visible-output cap. Keep the spinner stream in the task-scoped log and poll only compact state such as:

- whether the process is still alive
- elapsed time
- log byte count
- configured deadline and remaining retained-byte budget
- a byte-bounded recent tail with carriage returns normalized before limiting lines

For example, bound the byte window before normalizing spinner redraws:

```bash
tail -c 8192 <task-log> | tr '\r' '\n' | tail -n 20
```

Do not repeatedly poll with the entire accumulated log or a large output allowance. When the command finishes, report its exit status and extract only targeted failure lines or a short final tail.

## Evidence Checklist

Before presenting command-derived evidence, confirm:

- the producer input was scoped or the complete output was captured away from the conversation
- potentially unbounded producers had enforced time and retained-byte ceilings plus a defined termination action
- the visible excerpt is compact and directly relevant
- the exit status is known
- an empty result is distinguishable from a failed command
- retained task artifacts have a cleanup or handoff decision
