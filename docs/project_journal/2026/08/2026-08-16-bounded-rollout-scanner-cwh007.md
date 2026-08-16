---
id: 20260816-cwh007
title: Bounded Rollout Scanner
status: completed
created: 2026-08-16
updated: 2026-08-16
branch: codex/rollout-scanner
pr:
supersedes:
  - 20260718-cwh001
  - 20260812-cwh003
superseded_by:
---

# Bounded Rollout Scanner

## Summary

- Replace the embedded one-rollout parser and fixed raw-ripgrep protocol with one deterministic, bounded scanner helper while leaving rollout discovery and interpretation to the model.

## Current State

- The successor is scoped to `codex-session-mining`; it does not revive the stale, conflicting PR #65 locator or add `locate.md` / `corpus.md` routing surfaces.
- The helper has `search` and `shapes` subcommands and emits typed JSONL with `start`, result, and terminal `end` events.
- `search` defaults to a typed `evidence` mapping, offers a conservative structural `user-text` mode, and does not expose an `all-values` mode. Evidence matches retain category, role, field path, and bounded snippets; `custom_tool_call.input` and custom tool output are explicit mappings.
- Computer call families and `web_search_call` use their typed `action` field instead of a shared permissive alias set. The listed function, custom, and computer output records use only their explicit output aliases. Deep evidence and shape paths retain a fixed prefix plus a rolling digest so one valid record cannot amplify path state with nesting depth or width.
- Matching is a case-sensitive literal over Unicode-whitespace-normalized individual fields. It never manufactures a match across field boundaries and groups bounded field hits into one event per physical record.
- Metadata is opt-in through an explicit category. Results retain physical order, support category filters, and use stateless result windows rather than a snapshot cursor.
- The default result window is 20 records and 64 KiB of serialized result-event bytes. Callers may raise it to hard ceilings of 250 records and 256 KiB, or select a later window with a result offset. Every invocation remains an independent descriptor-prefix observation.
- Input is one no-follow regular-file descriptor bounded to its initial-size or explicitly selected prefix and parses only complete LF-delimited records within that extent. The scanner defers an unterminated tail only while it remains within the 1 MiB physical-record cap, caps cumulative reads at 192 MiB, and caps inspected records at 250,000.
- The exact absolute UTF-8 path remains the value passed to the file open operation. Its typed `start` projection is capped at 4096 UTF-8 bytes with explicit truncation, original-length, and digest metadata so unavailable inputs cannot exhaust protocol headroom.
- The first malformed, oversized, or foreign-encoded physical record ends the scan with structured partial evidence. The successor deliberately retires cross-record UTF-16/32 recovery rather than carrying forward the complex framing transaction from PR #72.
- `shapes` retains the first 20 bounded, value-free structural skeletons in physical order, maintains exact counts only for those retained shapes, limits serialized detail to 64 KiB with explicit emitted/suppressed counters, and reports records belonging to unretained shapes without claiming a complete distinct-shape count.

## Plan

- Add a tested `scripts/scan_rollout.py` implementation and replace the duplicated Markdown parsers with concise helper recipes and evidence interpretation rules.
- Retire the conformance-qualified ripgrep 15.2.0 count/position/preview layer, its CI installation, and raw-ripgrep contract tests. Preserve semantic selected-field, strict UTF-8/BOM, bounded-record, terminal-metadata, and no-match evidence contracts in the scanner tests.
- Keep corpus construction, replay handling, PR attribution, and remote-evidence routing unchanged. Leave exact-rollout discovery to the model, and treat candidate-search zero matches as non-authoritative unless a complete corpus workflow supplies the required coverage.
- Validate the complete repository, skill structure, helper CLI, project journal, and delivery range before opening a focused successor PR. Once that PR is established, mark PR #65 as superseded rather than updating its old branch.

## Next Steps

- None.

## Evidence

- Stale donor: https://github.com/Joey-Tools/codex-workflow-hygiene/pull/65 at `e9d4cbc3c0345c7f98b4f4d3dd4f09c9adc60004`.
- Superseded raw locator and semantic parser history: PR #71 (`edc3db2`) and PR #72 (`e93037e`).
- Superseded bounded inline index/schema recipes: journal `20260718-cwh001`; their safe-record properties move into the scanner while candidate discovery becomes model-owned.
- Local current-host usage audit: 21 focused requests across 12 root sessions; 14 required selected evidence beyond user text, none required all string values, and 7 were not applicable wrappers or control turns. Remote-host probes were unavailable, so this evidence is not a cross-host population estimate.
- Follow-through audit found `custom_tool_call.input` absent from the prior selected mapping while corresponding custom tool outputs were retained.
- Focused scanner and structure validation: `python3 -B -m unittest -q tests.test_scan_rollout tests.test_skill_structure` (`61` tests, passed).
- Full repository validation: `python3 -B -m unittest discover -s tests -b -q` (`243` tests, passed).
- Skill validation: `python3 skills/codex-skill-authoring/scripts/codex_skill_validate.py --report .codex-tmp/skill-validation/codex-session-mining.json skills/codex-session-mining` (passed).
- Project-journal validation: `python3 /Users/hoteng/.codex/skills/project-journal/scripts/project_journal.py validate --repo .` (passed).
- Helper interface and syntax validation: `python3 -I -B -S skills/codex-session-mining/scripts/scan_rollout.py --help`, `python3 -m py_compile skills/codex-session-mining/scripts/scan_rollout.py tests/test_scan_rollout.py`, and `git diff --check` (passed).
- Independent implementation, test, contract, and documentation audits found and resolved the outer-type mapping, typed message whitelist, wide-container memory, canonical shape, chunk-aligned record-budget, stdout short-write, and shape-detail byte-budget findings; the final read-only rechecks reported no remaining findings.
- The first formal fresh-context WIP review found deep-path state amplification, missing computer-tool schema variants, and an unbounded source-path projection. The implementation now uses rolling bounded path state, per-type computer call/output mappings, and a fixed-size source projection; the corrected range requires a new formal review before publication.
- The second formal WIP review confirmed those three fixes and found two additional release blockers: `web_search_call.action` was not in the typed mapping, and `shapes` still copied full paths before projection. Both now share the typed action and rolling bounded-path contracts; the updated range requires another fresh formal review.
