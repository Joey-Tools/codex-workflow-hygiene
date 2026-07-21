---
name: bounded-command-output
description: Keep potentially high-output or long-running commands scoped, time-bounded, pollable, and compact while another skill owns the substantive task. Use for broad searches or inventories; large Jenkins, GitHub Actions, artifact, manual, diff, or review-range reads; broad database aggregates or filesystem walks with uncertain runtime; broad or noisy process diagnostics; verbose xcodebuild or other tests and builds; spinner-heavy container builds; and repeated polling. Apply alongside the domain skill and skip only exact commands known to be both small and fast.
---

# Bounded Command Output

## Overview

Shape commands so the producer, runtime, retained artifact, polling path, and visible evidence all have deliberate bounds.
This skill controls command shape, execution deadlines, and output handling only. It does not own diagnosis, implementation delivery, or review decisions.

## Workflow

1. Decide whether the command needs an output or runtime budget.
- Use this skill when input scope is broad, output size or runtime is unknown, lines may be huge, progress redraws use carriage returns, or a long-running command will be polled.
- Small output does not imply bounded runtime. Apply the database and filesystem deadline patterns to broad SQLite aggregates, `du` walks, and similar scans even when the expected result is one line.
- Skip it only for an exact command known to be both small and fast.

2. Bound the producer scope and runtime before running it.
- Narrow directories, files, time windows, predicates, identifiers, or changed paths.
- Exclude dependency trees, generated output, archives, and lockfiles unless they are the target.
- Start with counts, metadata, an explicitly capped candidate-filename sample, or status summaries before printing matching lines or full records.
- Invoke portable tools by command name when the selected runtime trusts `PATH`. Do not guess `/usr/bin` or a package-manager prefix; when an exact executable path is required, resolve and validate it once before launch.
- When a shell is unavoidable for a pipeline or redirection, keep dynamic paths, patterns, URLs, and other values out of nested host-language and shell quoting. Pass them as positional arguments to the shell entrypoint or move the logic into a task-scoped script.
- Choose task-specific deadlines rather than treating illustrative durations as default thresholds. Route database and filesystem scans to the matching reference patterns before launch.

3. Choose the output sink deliberately.
- Let compact commands return directly.
- Give a parallel batch one aggregate output and retained-byte budget. Per-command caps must fit inside that total, or each producer must write to a separately enforced bounded sink before a compact aggregate is emitted.
- When full output may be large or useful for later inspection, redirect stdout and stderr to a task-scoped file before starting the command.
- Before launch, set a finite wall-clock deadline and an enforced ceiling across all retained artifacts. Use a hard quota or bounded sink, rotation with fixed aggregate-byte and segment-count caps that removes or reuses old segments before writing more, or a supervisor that terminates the producer at the byte ceiling. The deadline must terminate the producer; byte enforcement must either keep the retained set below its fixed ceiling or terminate the producer.
- A task-scoped path and byte-count polling do not by themselves bound disk growth.
- Treat UI or tool output caps as display backstops, not as execution-time bounds.
- Start any long-running command that may need polling, interruption, or final-output harvesting with a pollable TTY or PTY shape while keeping the live stream in the task-scoped file.
- Do not assume a later poll can attach to a plain-pipe session after stdin closes.

4. Surface compact evidence.
- Poll process state, elapsed time, file byte counts, and a byte-bounded short tail instead of replaying the full stream.
- Extract only the decisive counts, bounded filename samples, key lines, or short snippets needed for the task.
- Preserve the command's exit status and enough stderr context to distinguish failure from an empty result.

5. Clean up task artifacts.
- Remove task-scoped logs and extracted artifacts when they are no longer useful and safe to delete.
- Report any retained artifacts explicitly.

## Skill Composition

- Apply this skill alongside the task's domain skill. The domain skill owns the substantive workflow; this skill owns command shape and visible-output handling.
- A debugging skill still owns artifact authority, authentication, hypothesis ranking, and root-cause decisions.
- A delivery skill still owns implementation, validation, documentation, and commits.
- A review skill's stricter evidence, byte, time, or process limits take precedence over this general guidance.

## Guardrails

- Use the process-group deadline wrapper only on POSIX runtimes. On native Windows or any runtime where `os.name != "posix"`, skip this protection and do not claim process-group or descendant cleanup. WSL follows the POSIX path only when its Python runtime exposes the required POSIX APIs.
- Do not run an unbounded producer and assume a small display cap made the work bounded.
- Do not call a redirected log bounded unless its time and retained-byte ceilings are enforced while the producer runs.
- Do not treat per-file match limits such as `rg --max-count` as a total-output cap across many files.
- Do not print a whole long line when a filename, count, bounded match, length, or structured snippet would answer the question.
- Do not redirect a small interactive command when doing so would hide a prompt or other required interaction.
- Do not skip runtime bounding solely because the expected output is a single value or a few lines.
- Use direct commands when possible. Use a shell only when redirection, a pipeline, or another real shell feature is required.

## References

- Use [references/command-patterns.md](references/command-patterns.md) for concrete search, inventory, database, filesystem, log, process, build, deadline, and polling patterns.
