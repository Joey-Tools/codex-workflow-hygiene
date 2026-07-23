---
name: bounded-command-output
description: Bound genuinely broad, noisy, or long-running commands while another skill owns the substantive task. Use for wide repository, session, filesystem, database, or process inventories; large log, artifact, manual, diff, or review-range reads; verbose or spinner-heavy builds and tests; and commands that require polling or a hard deadline. Do not use for routine exact commands whose scope, output, and runtime are already predictably small.
---

# Bounded Command Output

## Overview

Apply a small execution envelope around commands that are genuinely broad, noisy, or long-running.
This skill controls producer scope, runtime, retained bytes, and visible evidence only.
The domain skill still owns diagnosis, implementation, and review decisions.

## Trigger Gate

- Load this skill when at least one property is real: broad producer scope, noisy or potentially large output, or long/uncertain runtime that needs a deadline or polling.
- Skip it for exact file reads, narrow metadata probes, ordinary status commands, and focused tests that are predictably small and fast.
- Do not trigger merely because every command could theoretically hang or fail.
- Small visible output can still qualify when a broad database aggregate, filesystem walk, or similar producer has genuinely uncertain runtime.

## Keep Three Budgets Separate

1. Bound the producer.
- Narrow roots, dates, predicates, identifiers, or changed paths before launch.
- Prefer counts, metadata, and an explicitly capped filename sample before detailed output.

2. Bound runtime.
- Choose a task-specific finite wall-clock deadline that terminates the producer; a UI timeout is not enough.
- On POSIX, use `scripts/run_process_group_deadline.py` when the producer and ordinary same-user descendants need one monotonic deadline and process-group cleanup.
- Preserve the helper's documented boundary: it does not prove quiescence for descendants that escape the group or survive after a normal leader exit.
- On non-POSIX runtimes, do not invoke that helper or claim process-group cleanup.

3. Bound retained bytes.
- Set one enforced aggregate byte ceiling across every retained log, segment, and child artifact before launch.
- For parallel work, make all per-command caps fit inside that aggregate ceiling or give each producer a separately enforced bounded sink.
- A task-scoped directory, post-exit size check, byte-count poll, or display truncation does not enforce retained-byte growth.
- Keep producer volume, runtime, retained bytes, and visible output as separate properties; one bound never substitutes for another.

## Execute And Report

- Use direct argv when possible. When a shell is necessary, pass dynamic values as positional arguments or use a task-scoped script.
- Redirect only when output may be large or must be retained. Start interruptible long-running work in a pollable PTY shape.
- Poll compact state: process status, elapsed time, retained bytes, and a byte-bounded tail.
- Preserve exit status and enough stderr to distinguish failure from an empty result.
- Remove task artifacts when safe, and report anything intentionally retained.
- Read [references/command-patterns.md](references/command-patterns.md) for concrete search, inventory, database, filesystem, log, build, deadline, and polling patterns.

## Skill Composition

- Apply this skill alongside the task's domain skill, never as a replacement for it.
- A review skill's stricter evidence, byte, time, or process limits take precedence over this general guidance.
