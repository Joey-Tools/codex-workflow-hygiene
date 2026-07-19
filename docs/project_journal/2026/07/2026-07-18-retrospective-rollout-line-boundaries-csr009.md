---
id: 20260718-csr009
title: Retrospective Rollout Line Boundaries
status: completed
created: 2026-07-18
updated: 2026-07-18
branch: codex/daily-skill-friction-20260718-codex-workflow-hygiene-retrospective-bare-cr-drain
pr:
supersedes: []
superseded_by:
---

# Retrospective Rollout Line Boundaries

## Summary

- Made LF the only physical JSONL record boundary in local and embedded rollout-summary readers, so a bare CR cannot release a suffix as a separate record.
- Bound each scan to the fixed byte-zero source snapshot range: true EOF without LF remains readable, while a scan cap before the snapshot end drops the incomplete record.
- Forwarded `tell()` through local and embedded hashing readers so production scans prove that they start at byte 0 and fail closed when their offset is unavailable, invalid, or nonzero.

## Current State

- CRLF records retain their CR as legal trailing JSON whitespace and continue to parse normally.
- Oversized records drain through bare CR bytes until the next LF before later records can be emitted.
- Every valid nonzero cursor is rejected before reading, including a JSONL record boundary, a mid-record JSON suffix, and snapshot EOF.
- Descriptor-backed summary scans pass the captured file size explicitly; generated local summaries pass the length of their cap-plus-one in-memory snapshot explicitly.

## Next Steps

- None.

## Evidence

- Focused local, embedded, generated-script, hashing-reader, and fixed-range regressions: 12 of 12 tests passed in 0.098 seconds.
- `python3 -B tests/test_remote_codex_probe.py`: 36 of 36 tests passed in 4.471 seconds.
- `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false python3 -B -m unittest -b -q tests.test_session_retrospective`: 876 of 876 tests passed in 83.974 seconds; the process-only Git override isolates temporary test repositories from the user's global commit-signing setting.
- The same process-only Git override with full repository unittest discovery passed 1002 of 1002 tests in 97.552 seconds.
- Official `quick_validate.py` reported `Skill is valid!` via `uv run --isolated --with pyyaml`; the Joey wrapper's current interpreter lacked the `yaml` dependency.
- Python 3.13.0 byte compilation passed for `remote_codex_probe.py` and `tests/test_session_retrospective.py`.
- Ruff 0.13.2 passed `remote_codex_probe.py`; `tests/test_session_retrospective.py` passed with its unchanged repository-baseline F541 finding excluded.
- `git diff --check` passed.
