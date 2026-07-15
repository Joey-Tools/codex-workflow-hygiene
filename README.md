# Codex Workflow Hygiene

Public skills for bounded command output, skill authoring, session mining,
Codex rules hygiene, and redacted session retrospective artifact generation.

## Test

```bash
python3 -m unittest discover -s tests
```

## Retrospective Baseline Dry Run

```bash
python3 skills/codex-session-retrospective/scripts/session_retrospective.py baseline-dry-run --window-days 90 --from first --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/baseline-dry-run
python3 skills/codex-session-retrospective/scripts/session_retrospective.py repair-coverage --run-dir .codex-local/session-retrospective/runs/20260522/baseline-dry-run --output .codex-local/session-retrospective/runs/20260522/baseline-coverage-repair
```

## Retrospective Weekly Dry Run

```bash
python3 skills/codex-session-retrospective/scripts/session_retrospective.py weekly-dry-run --days 7 --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/weekly-dry-run
python3 skills/codex-session-retrospective/scripts/session_retrospective.py weekly-repair --run-dir .codex-local/session-retrospective/runs/20260522/weekly-dry-run --output .codex-local/session-retrospective/runs/20260522/weekly-coverage-repair
```

These commands only write transient `.codex-local/session-retrospective/**` artifacts.
They do not export retained history, commit, or advance scan state.
Remote repair materialization defaults to conservative bounded concurrency:
`--remote-host-jobs 2 --remote-rollout-jobs 2`. Use `1` for serial behavior.
Read `dry_run_report.md` or `repair_report.md` first for the compact quick read:
window, host coverage, retained-readiness, top blockers, next command, transient
disk usage, and confidence. The adjacent JSON report remains the
machine-readable source of truth.

## Session Retrospective Roadmap

Follow-up retrospective automation improvements are tracked in
[`docs/session-retrospective-improvement-todo.md`](docs/session-retrospective-improvement-todo.md).
