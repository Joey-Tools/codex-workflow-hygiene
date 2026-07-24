# Deadline And Byte-Budget Contract

Load this reference only for commands that actually need supervision.

## POSIX Hard Deadline

Run direct argv through the packaged helper:

```bash
python3 <loaded-skill-dir>/scripts/run_process_group_deadline.py \
  --timeout-seconds <task-specific-seconds> \
  --grace-seconds <bounded-grace-seconds> \
  -- <command> <args...>
```

The helper:

- uses one monotonic deadline for setup and command runtime;
- creates a dedicated process group (or a new session with `--new-session`);
- sends `TERM`, waits the configured grace period, then sends best-effort
  `KILL`;
- preserves an ordinary child exit status;
- returns `124` for its deadline and `128 + signal` for a managed external
  signal; and
- returns `125` before launch when required POSIX primitives are unavailable.

It intentionally does not:

- chase descendants that escape with another process group or session;
- prove group quiescence after the leader exits;
- bound retained output;
- preempt an uninterruptible kernel call; or
- provide a native-Windows equivalent.

Treat an unverified group cleanup as a distinct result. Do not infer complete
cleanup from the wrapper's return code alone.

## Retained-Byte Enforcement

Choose one fixed ceiling for the whole retained set, not one independent ceiling
per parallel child. Enforce it during execution with one of:

- a sink that terminates the producer before accepting bytes above the ceiling;
- a quota-bounded filesystem or artifact store; or
- rotation with fixed aggregate-byte and segment-count caps that removes or
  reuses old segments before writing more.

Post-exit size checks, repeated `wc -c`, a UI truncation limit, and unbounded
rotation are observations, not enforcement. If any bytes required for the task
were dropped or evicted, mark the result incomplete.

## Polling

Poll compact state only:

- PID/process state;
- elapsed time and remaining deadline;
- retained bytes and remaining byte budget; and
- a byte-bounded recent tail.

Normalize carriage-return redraws only after bounding the byte window, for
example:

```bash
tail -c 8192 <task-log> | tr '\r' '\n' | tail -n 20
```

At termination, record producer status, supervisor status, byte-limit status,
cleanup status, completeness, and the cleanup or handoff decision for retained
artifacts.
