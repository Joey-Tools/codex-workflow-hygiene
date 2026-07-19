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

macOS does not ship GNU `timeout`. Do not use an in-process Perl `alarm` plus `exec` as a general hard deadline: the target inherits and can ignore, block, replace, or cancel `SIGALRM`, and exit status `142` cannot distinguish a normal `exit(142)` from signal termination. Choose a task-specific deadline before launch; numeric examples are illustrative rather than defaults or slow-command thresholds.

On POSIX, put even a single SQLite or `du` producer behind the lightweight external process-group wrapper. The separate supervisor owns the monotonic deadline and preserves the target's ordinary exit status without adding a container:

Use this wrapper only when Python reports `os.name == "posix"` and the required POSIX process APIs are available. On native Windows (non-WSL) or any other non-POSIX runtime, skip this protection: do not invoke the wrapper and do not claim process-group or descendant cleanup. WSL uses its Linux/POSIX runtime and remains eligible when those APIs are present. The other scope, output, and evidence guardrails still apply; a native-Windows supervisor would be a separate, explicitly validated mechanism rather than an implicit substitute. If this script is invoked accidentally on a non-POSIX host, it returns `125` before installing signal handlers or starting the command.

```bash
python3 <loaded-skill-dir>/scripts/run_process_group_deadline.py \
  --timeout-seconds <task-specific-seconds> \
  --grace-seconds 1 \
  -- /usr/bin/sqlite3 /exact/path/database.sqlite 'SELECT count(*) FROM events;'
```

Use the same wrapper with `/usr/bin/du -xhd 1 /exact/path` for a bounded filesystem walk. Launching descendants does not by itself require stronger containment; the wrapper's documented process-group boundary is sufficient when ordinary same-user descendants should receive the timeout signals too.

The wrapper runs direct argv without an implicit shell, inherits only standard input, output, and error, and adds no persistent launcher between itself and the command. It takes one absolute monotonic deadline before creating the control pipes and forking. The child establishes its process group or session, reports `READY`, and waits for the parent's `GO` before it can execute user code. Before `READY`, timeout or cancellation safely targets only the known child PID; after `GO`, setup, `exec`, and command runtime all consume the same deadline budget and cleanup targets the known PGID. Direct-child waiting uses capped exponential backoff and settles at no more than about 25 nonblocking `waitpid` observations per second for a long-running command. The wrapper checks the deadline before each new exit observation; a direct-child status returned by an observation begun before the deadline wins that boundary race, while no new observation starts once the deadline is reached. The supervisor parent unblocks managed `INT`, `TERM`, and `HUP` signals while it owns cleanup, even if its launcher blocked them; the target child receives the launcher's original signal mask, and the parent restores that mask during teardown. The first timeout or managed signal owns one cleanup transition, so later managed signals cannot interrupt it. On timeout the wrapper sends `TERM`, waits the complete selected grace period without reaping the group leader, sends best-effort `KILL`, and then waits only for its direct child. Diagnostics are best effort and temporarily make standard error nonblocking for one short write: a closed or broken sink, or a full pipe, cannot replace or indefinitely delay the command, timeout, or forwarded-signal status. Because that flag belongs to the shared open-file description, an uncatchable child death in the short toggle window can leave inherited standard error nonblocking; eliminating that edge requires a dedicated diagnostic channel outside this lightweight contract. A normal child exit is returned unchanged; a deadline returns `124`, and an externally received `INT`, `TERM`, or `HUP` is forwarded before the wrapper returns the conventional `128 + signal` status.

Both same-session `setpgid()` and `--new-session` `setsid()` modes work on the repository's Python 3.10 baseline. Same-session mode preserves the session and controlling terminal, but the new group is not automatically the terminal's foreground group; use it for non-interactive commands or redirected input. `--new-session` explicitly removes the controlling terminal. The helper must run as a newly started, standalone single-threaded POSIX CLI with `fork`, `setpgid`, `setsid`, `waitpid`, `killpg`, `pthread_sigmask`, open file descriptors `0` through `2`, and either `/dev/fd` or `/proc/self/fd` available for closing inherited descriptors; its Python thread-count check cannot prove that an embedding host has no native threads, so imported or embedded use is unsupported. These are ordinary same-effective-UID process operations and require neither root, a container, nor a dedicated service manager. Pipe creation, file-descriptor enumeration, and the synchronous `fork()` system call are charged to the deadline when they return, but an uninterruptible kernel call cannot be preempted while it is still inside the kernel. Timeout and grace inputs are capped at one year solely to stay within portable sleep and wait representations; this is not a recommended deadline, default, or slow-command threshold.

Both modes intentionally do not chase descendants that call `setsid()` or `setpgid()` to escape, clean up background descendants after a normal leader exit, or prove group quiescence. A surviving descendant that inherits stdout or stderr can keep an outer pipe reader waiting for EOF even after the direct child exits; redirect or close those descriptors when background survival is intentional. On macOS, signaling the group after `GO` may return `EPERM` during handoff or after its leader exits; the wrapper falls back to signaling a still-live direct child and reports group cleanup as unverified. The wrapper is not a real-time scheduler: CPU starvation or ordinary scheduler delay can postpone deadline recognition and return, even though the monotonic deadline is never reset. It also cannot enforce a deadline while it is stopped, after it receives `SIGKILL`, or while the host is suspended. It enforces time only; retained-output byte ceilings remain a separate caller responsibility. Use stronger supervision or OS containment only when task-owned work can outlive these accepted boundaries and must be stopped.

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
