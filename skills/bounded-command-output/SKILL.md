---
name: bounded-command-output
description: Enforce hard wall-clock and retained-byte bounds for genuinely broad, noisy, or long-running commands while another skill owns the substantive task. Use when producer scope or runtime is uncertain, logs or builds can grow materially, a command needs polling or interruption, or a complete artifact must stay within a fixed byte budget. Do not load for ordinary exact commands already known to be small and fast.
---

# Bounded Command Output

Use this skill as an execution-control layer. The domain skill still owns what to
run, what the evidence means, and whether an incomplete result is usable.

## Set Independent Bounds

Before launch, distinguish four different limits:

- **Producer scope**: files, rows, commits, hosts, or artifacts the command may
  inspect.
- **Runtime**: a finite wall-clock deadline that stops the producer.
- **Retained bytes**: a fixed ceiling across every saved stdout, stderr, log,
  archive, and rotated segment.
- **Visible output**: the compact excerpt returned to the conversation.

A display cap does not bound retained bytes. A small expected answer does not
bound runtime. A task-scoped log path does not bound disk growth.

## Run

1. Narrow the producer when the task permits it.
2. Choose a task-specific hard deadline and retained-byte ceiling before launch.
3. Enforce the byte ceiling while the producer runs: stop the producer at the
   ceiling, or use rotation/quota semantics that keep the complete retained set
   below it.
4. On POSIX, use
   `scripts/run_process_group_deadline.py` when a direct command needs a hard
   deadline and process-group cleanup. Do not use it on non-POSIX runtimes.
5. Start work that may need polling or interruption in a pollable execution
   shape. Poll only process state, elapsed time, retained bytes, and a
   byte-bounded tail.
6. Report the producer exit status, whether the deadline or byte ceiling fired,
   whether cleanup was verified, and whether the evidence is incomplete.

## Guardrails

- Do not call a run bounded when only its displayed output is truncated.
- Preserve the producer's ordinary exit status. Classify deadline, byte-limit,
  launch, and empty-result outcomes separately.
- Treat evicted, truncated, timed-out, or forcibly stopped output as incomplete
  whenever the workflow requires the complete stream.
- The POSIX helper cleans the process group it created; it does not prove that
  descendants which escaped that group are gone, and it does not enforce a byte
  ceiling.
- Prefer direct argv. Use a shell only for an actual shell feature, and keep
  dynamic values out of nested quoting.
- Remove task artifacts when safe, or report the retained path and reason.

Read [references/command-patterns.md](references/command-patterns.md) only when
you need the helper interface or a retained-byte enforcement checklist.
