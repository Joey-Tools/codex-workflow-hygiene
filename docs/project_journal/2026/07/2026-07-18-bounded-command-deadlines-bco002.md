---
id: 20260718-bco002
title: Bounded Database And Filesystem Scans
status: completed
created: 2026-07-18
updated: 2026-07-19
branch: codex/bounded-process-group-supervisor-20260719
pr:
supersedes: []
superseded_by:
---

# Bounded Database And Filesystem Scans

## Summary

- Added task-selected deadline guidance for SQLite aggregates and broad macOS filesystem walks, plus a lightweight process-group wrapper for ordinary child processes.

## Current State

- SQLite `.timeout` is identified as busy-lock handling rather than a query-execution deadline.
- Large or actively written databases start with metadata, sequence, schema/index, or narrow indexed probes before broad aggregates.
- Broad aggregates require an outer hard wall-clock deadline and produce incomplete evidence when terminated.
- Broad macOS `du` walks require a hard deadline before launch; PTY polling alone is not a runtime bound.
- Timed-out filesystem branches remain explicitly unknown or incomplete.
- Numeric deadlines are illustrative rather than default thresholds; long-running scans are not friction by duration alone.
- The main skill now triggers on uncertain runtime as well as uncertain output and routes one-line SQLite aggregates or similar scans to the deadline reference instead of skipping them as small output.
- macOS single-process scans have a system-Perl direct-`exec` deadline pattern that preserves ordinary exit statuses and maps `SIGALRM` to an explicit incomplete result.
- A POSIX/Python 3.10 process-group wrapper adds TERM/grace/KILL handling for ordinary child processes without requiring root, a container, tree scanning, or a persistent launcher process.
- Native Windows and other non-POSIX runtimes explicitly skip this process-group safeguard and must not claim equivalent cleanup; accidental invocation returns `125` before installing signal handlers or starting the command, while WSL follows the POSIX capability path.
- One absolute monotonic deadline starts before pipe creation and `fork`; a masked `READY`/`GO` barrier prevents user code from running until the parent has recorded the child PID and process-group handoff.
- Startup checks the same absolute deadline after pipe setup and descriptor enumeration and immediately before `fork`, closing opened descriptors instead of starting a child once the budget is known to be exhausted.
- The wrapper checks the deadline before each new exit observation; a status returned by an observation begun before the deadline wins that boundary race, and no new observation starts once the deadline is reached.
- Before `READY`, timeout or cancellation signals only the direct child; after `GO`, blocked `exec` and runtime work are stopped through the group, with a final direct `SIGKILL` for a still-pinned leader that moved groups.
- The first managed signal owns the cleanup transition; later managed signals cannot unwind and bypass the in-progress group stop.
- The supervisor parent unblocks managed `INT`, `TERM`, and `HUP` signals during supervision even when the launcher blocked them; the target child and final parent teardown retain the launcher's original mask.
- Diagnostic writes temporarily ignore `SIGPIPE`, make stderr nonblocking for one short best-effort write, and drop output to a closed or broken sink or a full pipe so diagnostics cannot replace or indefinitely delay the selected child, timeout, or forwarded-signal status.
- The nonblocking flag is shared across forked descriptors; an uncatchable child death in the short diagnostic-write window can leave inherited stderr nonblocking, and eliminating that edge would require a dedicated diagnostic channel outside the lightweight design.
- Handler restoration temporarily masks managed signals on the current thread so teardown cannot leak a `ForwardedSignal` traceback.
- An outer signal boundary covers the pre-mask teardown window, while non-POSIX rejection happens before handler setup.
- Timeout and grace inputs are capped at one year for representability rather than as workflow defaults or duration thresholds; malformed executable formats map to exit `126`.
- The child restores default `SIGPIPE`-family behavior, the parent temporarily normalizes and restores `SIGCHLD`, and inherited descriptors above standard I/O are closed from a single-threaded `/dev/fd` or `/proc/self/fd` snapshot.
- The wrapper preserves the original session, does not allocate a PTY, waits only for its direct child, and intentionally does not chase escaped descendants or prove group quiescence.
- macOS may return `EPERM` or report a missing group after `GO` or after the leader exits; the wrapper falls back to signaling a still-live direct child and reports group cleanup as unverified while preserving the timeout or forwarded-signal result.
- Background descendants that intentionally survive a normal leader exit must close or redirect inherited stdout/stderr, or an outer pipe reader can continue waiting for EOF.
- Both same-session `setpgid()` and explicit `--new-session` `setsid()` modes support Python 3.10. The helper must be a standalone single-threaded CLI with open standard descriptors, `pthread_sigmask`, and a process-FD view; synchronous uninterruptible kernel calls, CPU starvation or scheduler delay, `SIGSTOP`, `SIGKILL`, and host suspend remain outside strict real-time enforcement.
- Local interleaved benchmarks observed roughly 39–41 ms added median latency for `/usr/bin/true`; a 10-second supervised sleep consumed 0.04 seconds user and 0.04 seconds system CPU with capped wait polling. One loaded-host sample returned after 14.64 seconds, confirming that scheduler latency rather than CPU overhead can delay observation.
- Output-byte enforcement remains separate from the deadline wrapper.

## Next Steps

- Monitor whether the lightweight wrapper covers ordinary non-interactive builds and scans without introducing unacceptable TTY or Python-version constraints.

## Evidence

- `skills/bounded-command-output/SKILL.md`
- `skills/bounded-command-output/references/command-patterns.md`
- `skills/bounded-command-output/scripts/run_process_group_deadline.py`
- `tests/test_bounded_process_group_deadline.py`
- `tests/test_skill_structure.py`
