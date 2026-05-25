# Codex Workflow Hygiene

Public skills for skill authoring, session mining, Codex rules hygiene, and
redacted session retrospective artifact generation.

## Test

```bash
python3 -m unittest discover -s tests
```

## Retrospective Baseline Dry Run

```bash
python3 skills/codex-session-retrospective/scripts/session_retrospective.py baseline-dry-run --window-days 90 --from first --end 2026-05-22T00:00:00Z --output .codex-local/session-retrospective/runs/20260522/baseline-dry-run
python3 skills/codex-session-retrospective/scripts/session_retrospective.py repair-coverage --run-dir .codex-local/session-retrospective/runs/20260522/baseline-dry-run --output .codex-local/session-retrospective/runs/20260522/baseline-coverage-repair
```

These commands only write transient `.codex-local/session-retrospective/**` artifacts.
They do not export retained history, commit, or advance scan state.
