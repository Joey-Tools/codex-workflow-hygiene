---
id: 20260717-csr003
title: Retrospective Raw Byte Hash Contract
status: completed
created: 2026-07-17
updated: 2026-07-17
branch: codex/daily-skill-friction-20260717-codex-workflow-hygiene-retrospective-byte-hash-invariant
pr:
supersedes: []
superseded_by:
---

# Retrospective Raw Byte Hash Contract

## Summary

- Made the local and embedded rollout hashing readers reject text streams instead of re-encoding decoded text.
- Added local and embedded end-to-end coverage for CRLF JSONL containing an invalid UTF-8 byte.

## Current State

- Production rollout handles already open in binary mode; the reader now enforces that invariant at runtime.
- `source_sha256` and `source_bytes` are proven against the original file bytes before summary decoding.

## Next Steps

- None.

## Evidence

- Three targeted hashing-reader and raw-byte summary tests
- `python3 -m unittest discover -s tests -p 'test_*.py'` (941 passed, 1 skipped)
- `quick_validate.py skills/codex-session-retrospective`
- Independent PR #104 review exposed the previously implicit bytes-only contract
