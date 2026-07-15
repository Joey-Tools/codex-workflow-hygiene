# Bounded Command Patterns

Use these patterns after the main skill decides that a command needs an output budget. Adapt paths, predicates, and limits to the task instead of copying placeholders literally.

## Searches And Inventories

| Situation | Start with | Open next | Avoid |
| --- | --- | --- | --- |
| Large repository or generated-output-heavy tree | `rg --files <exact-dir>` with repo-appropriate exclude globs, then `rg -l` or `rg --count` | One exact file, symbol window, or small explicit file list | Raw broad `rg -n` across the repo |
| High-frequency identifier or large alternation | Candidate filenames or counts | A bounded match against one exact file | A line-producing multi-file search as the first probe |
| Large review range | `git diff --stat`, `git diff --numstat`, and `git diff --name-only` | Selected-file or selected-hunk diffs | One wide whole-range diff |
| Potentially large untracked set | `git status --short --untracked-files=no`, then count or sample `git ls-files --others --exclude-standard` | Explicit candidate paths | Full untracked or ignored inventory first |
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

For embedded payloads, minified bundles, or other very long lines, prefer `rg -l`, bounded `rg -o`, counts, or structured length/snippet extraction. `rg --max-count` limits matches per file, so it does not replace a bounded candidate file set.

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

For carriage-return or spinner-heavy tools such as `/usr/local/bin/container build`, do not rely on `--progress plain` or a visible-output cap. Keep the spinner stream in the task-scoped log and poll only compact state such as:

- whether the process is still alive
- elapsed time
- log byte count
- a byte-bounded recent tail with carriage returns normalized before limiting lines

For example, bound the byte window before normalizing spinner redraws:

```bash
tail -c 8192 <task-log> | tr '\r' '\n' | tail -n 20
```

Do not repeatedly poll with the entire accumulated log or a large output allowance. When the command finishes, report its exit status and extract only targeted failure lines or a short final tail.

## Evidence Checklist

Before presenting command-derived evidence, confirm:

- the producer input was scoped or the complete output was captured away from the conversation
- the visible excerpt is compact and directly relevant
- the exit status is known
- an empty result is distinguishable from a failed command
- retained task artifacts have a cleanup or handoff decision
