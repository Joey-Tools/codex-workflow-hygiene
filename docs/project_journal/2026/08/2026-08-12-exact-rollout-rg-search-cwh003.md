---
id: 20260812-cwh003
title: Exact Rollout ripgrep Search Protocol
status: completed
created: 2026-08-12
updated: 2026-08-13
branch: codex/rollout-rg-search
pr: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/71
supersedes: []
superseded_by:
---

# Exact Rollout ripgrep Search Protocol

## Summary

- Added a fixed ripgrep protocol, conformance-qualified against ripgrep 15.2.0, for keyword discovery in one already-selected rollout without printing an unbounded matching JSONL record.

## Current State

- `codex-session-mining` routes exact-rollout keyword discovery through count, matching-line position, and optional bounded raw-prefix stages.
- The evidence protocol fixes case-sensitive literal matching and keeps output, framing, transformation, and engine controls fixed; regex, case-insensitive, and boundary searches remain available only as non-evidentiary orientation probes.
- Raw ripgrep counts and coordinates are locators only. The selected-field parser uses the same literal as the evidence authority, including after a raw zero caused by JSON escaping or whitespace normalization.
- Empty and whitespace-only patterns fail before scanning so the normalized literal matcher cannot classify every valid record as a hit.
- The selected-field parser caps the normalized needle at 1024 UTF-8 bytes so a repeated match cannot amplify bounded rows into unbounded stdout.
- Every template passes the explicit stdin path `-`, preventing an invalid redirected directory from triggering ripgrep's no-path current-directory fallback.
- Exceptional exhaustive position collection has a 64 MiB retained-output admission bound and remains explicitly live, non-snapshot evidence.
- Dedicated contract tests cover the documentation surface and the conformance-qualified ripgrep 15.2.0 baseline without changing the shared skill-structure tests owned by the concurrent retrospective workstream.
- CI installs the official ripgrep 15.2.0 Linux release asset after verifying its pinned SHA-256 digest as a reproducible reference baseline. Development hosts never need to install, downgrade, or pin ripgrep: an unavailable, unparseable, or unqualified version skips the raw locator and uses the field-aware parser.

## Next Steps

- None.

## Evidence

- `skills/codex-session-mining/references/rollout-search.md`
- `skills/codex-session-mining/SKILL.md`
- `skills/codex-session-mining/references/workflow.md`
- `tests/test_rollout_search_contract.py`
- `CI=true python3 -B -m unittest -q tests.test_rollout_search_contract tests.test_skill_structure`: 49 tests passed.
- `CI=true python3 -B -m unittest -v tests.test_rollout_search_contract`: 21 tests passed with the CI-only ripgrep version gate enabled.
- Full repository suite through `run_process_group_deadline.py`, with process-scoped test-fixture commit signing disabled and the CI version gate enabled: 1,154 tests passed in 66.238 seconds.
- `codex_skill_validate.py skills/codex-session-mining`: `Skill is valid!` via the isolated uv/PyYAML path.
- `actionlint 1.7.12`, project-journal validation, and `git diff --check` passed.
- Formal local review identified and closed two protocol-test gaps: the contract now preserves shell quoting with whitespace- and glob-sensitive inputs, and it treats live position/preview output as bounded samples whose count must be rechecked rather than as complete match sets.
- GitHub Codex review identified and closed the stdin-path fallback gap; dynamic conformance now proves an invalid directory input cannot expose a matching cwd decoy.
- Final local review identified and closed a ripgrep/parser semantic mismatch by fixing the evidence templates to case-sensitive literals and making the parser authoritative for both matches and no-matches.
- Independent semantic audit identified and closed the parser's whitespace-only needle false-positive edge case.
- Final whole-range review identified and closed the unbounded needle amplification path with a UTF-8 byte cap and multibyte boundary tests.
