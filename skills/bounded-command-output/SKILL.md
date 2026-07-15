---
name: bounded-command-output
description: Keep potentially high-output commands scoped, pollable, and compact while another skill owns the substantive task. Use for broad searches or inventories; large Jenkins, GitHub Actions, artifact, manual, diff, or review-range reads; broad or noisy process diagnostics; verbose xcodebuild or other tests and builds; spinner-heavy container builds; and repeated polling. Apply alongside the domain skill and skip exact commands known to be small.
---

# Bounded Command Output

## Overview

Shape commands so the producer, retained artifact, polling path, and visible evidence all have deliberate bounds.
This skill controls command shape and output handling only. It does not own diagnosis, implementation delivery, or review decisions.

## Workflow

1. Decide whether the command needs an output budget.
- Use this skill when input scope is broad, output size is unknown, lines may be huge, progress redraws use carriage returns, or a long-running command will be polled.
- Skip it for an exact command whose output is known to be small.

2. Bound the producer before running it.
- Narrow directories, files, time windows, predicates, identifiers, or changed paths.
- Exclude dependency trees, generated output, archives, and lockfiles unless they are the target.
- Start with counts, metadata, candidate filenames, or status summaries before printing matching lines or full records.

3. Choose the output sink deliberately.
- Let compact commands return directly.
- When full output may be large or useful for later inspection, redirect stdout and stderr to a task-scoped file before starting the command.
- Treat UI or tool output caps as display backstops, not as execution-time bounds.
- Start any long-running command that may need polling, interruption, or final-output harvesting with a pollable TTY or PTY shape while keeping the live stream in the task-scoped file.
- Do not assume a later poll can attach to a plain-pipe session after stdin closes.

4. Surface compact evidence.
- Poll process state, elapsed time, file byte counts, and a byte-bounded short tail instead of replaying the full stream.
- Extract only the decisive counts, filenames, key lines, or short snippets needed for the task.
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

- Do not run an unbounded producer and assume a small display cap made the work bounded.
- Do not treat per-file match limits such as `rg --max-count` as a total-output cap across many files.
- Do not print a whole long line when a filename, count, bounded match, length, or structured snippet would answer the question.
- Do not redirect a small interactive command when doing so would hide a prompt or other required interaction.
- Use direct commands when possible. Use a shell only when redirection, a pipeline, or another real shell feature is required.

## References

- Use [references/command-patterns.md](references/command-patterns.md) for concrete search, inventory, log, process, build, and polling patterns.
