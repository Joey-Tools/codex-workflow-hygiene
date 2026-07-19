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

## Database And Filesystem Scans

- SQLite `.timeout` controls how long the client waits for a busy lock; it is not a query-execution deadline. On a large or actively written database, start with metadata, `sqlite_sequence`, schema/index inspection, or a narrow indexed range. Put any broad aggregate behind an outer hard wall-clock deadline, and treat a terminated query as incomplete rather than as an empty result.
- Broad macOS `du` walks under `$HOME`, `/System/Volumes/Data`, Containers, or FileProvider-backed trees require a hard deadline before launch. A PTY and repeated polling make the walk interruptible but do not bound its runtime. Split the scan into explicit top-level directories or narrower branches, and report every timed-out branch as unknown or incomplete instead of inferring a total from the surviving branches.

macOS does not ship GNU `timeout`, but its system Perl can put a direct single-process producer under a real deadline without a shell-inside-a-shell wrapper. Choose a task-specific deadline before launch; the numeric value below is illustrative rather than a default or threshold. This SQLite probe preserves ordinary exit statuses, turns `SIGALRM` into an explicit incomplete result, and terminates the producer itself:

```bash
/usr/bin/perl -e 'alarm shift; exec @ARGV or die qq(exec failed: $!\n)' \
  60 /usr/bin/sqlite3 /exact/path/database.sqlite 'SELECT count(*) FROM events;'
status=$?
if (( status == 142 )); then
  printf '%s\n' 'deadline exceeded; result incomplete' >&2
  exit 124
fi
exit "$status"
```

Use the same prefix with `/usr/bin/du -xhd 1 /exact/path` for a bounded filesystem walk. This direct-`exec` pattern is sufficient when terminating the exec'd producer ends all task-owned work. Launching descendants does not by itself require containing and terminating the whole process unit.

When ordinary same-user child processes should receive the timeout signal too, use the lightweight process-group wrapper without adding a container:

```bash
python3 <loaded-skill-dir>/scripts/run_process_group_deadline.py \
  --timeout-seconds <task-specific-seconds> \
  --grace-seconds 1 \
  -- /usr/bin/du -xhd 1 /exact/path
```

The wrapper runs direct argv without an implicit shell, inherits standard I/O, and normally adds only one process plus process-group setup. On timeout it sends `TERM` to the process group, waits the complete grace period without reaping the leader so the PGID cannot be reused, sends best-effort `KILL`, and waits only for its direct child. A normal child exit is returned unchanged; a deadline returns `124`, and an externally received `INT`, `TERM`, or `HUP` is forwarded to the group before the wrapper returns the conventional `128 + signal` status.

The default same-session mode requires POSIX plus Python 3.11 or newer because it uses `subprocess.Popen(process_group=0)`. It preserves the session and controlling terminal, but the new group is not automatically the terminal's foreground group; use it for non-interactive commands or redirected input. `--new-session` works on the repository's Python 3.10 baseline via `start_new_session=True`, but explicitly removes the controlling terminal. Both modes assume signalable same-effective-UID processes, do not chase descendants that call `setsid()` or `setpgid()` to escape, do not clean up background descendants after a normal leader exit, and do not prove group quiescence. A surviving descendant that inherits stdout or stderr can keep an outer pipe reader waiting for EOF even after the direct child exits; redirect or close those descriptors when background survival is intentional. On macOS, re-signaling a group after its leader exits may return `EPERM`; after confirming the direct child exited, the wrapper preserves the timeout result and reports that post-signal cleanup was unverified. The wrapper enforces time only; retained-output byte ceilings remain a separate caller responsibility. Use stronger supervision or OS containment only when task-owned work can outlive these accepted boundaries and must be stopped.

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
