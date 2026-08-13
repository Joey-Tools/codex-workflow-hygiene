# Codex Session Mining Recipes

Use these recipes when the task is to recover prior work, map a session ID to a rollout file, or audit repeated workflow friction from the user's local Codex history.

## 1. Find The Canonical Rollout File

Exact session ID:

```bash
set -euo pipefail

SESSION_ID='019ce6e8-a5e3-76e1-91a2-799837c70d1e'
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
python3 - "$SESSION_ID" "$CODEX_ROOT" <<'PY'
from pathlib import Path
import json
import re
import sys

session_id = sys.argv[1]
codex_root = Path(sys.argv[2]).expanduser()
max_record_bytes = 1024 * 1024
uuid_shaped = re.fullmatch(
    r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
    session_id,
) is not None


def bounded_jsonl(handle):
    line_no = 0
    while True:
        raw_line = handle.readline(max_record_bytes + 1)
        if not raw_line:
            return
        line_no += 1
        if len(raw_line) > max_record_bytes:
            while raw_line and not raw_line.endswith(b'\n'):
                raw_line = handle.readline(max_record_bytes + 1)
            continue
        yield line_no, raw_line


def matches_session(value):
    if not isinstance(value, str):
        return False
    if uuid_shaped:
        return value.lower() == session_id.lower()
    return value == session_id


for path in (codex_root / 'session_index.jsonl', codex_root / 'history.jsonl'):
    if not path.is_file():
        continue
    try:
        with path.open('rb') as handle:
            for line_no, raw_line in bounded_jsonl(handle):
                try:
                    row = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(row, dict):
                    continue
                if not any(matches_session(row.get(key)) for key in ('id', 'session_id')):
                    continue
                selected = {key: row.get(key) for key in ('id', 'session_id', 'thread_name', 'updated_at', 'ts', 'cwd')}
                text = ' '.join(str(row.get('text') or '').split())[:300]
                if text:
                    selected['text'] = text
                print(f'{path}:{line_no}:{json.dumps(selected, ensure_ascii=True, sort_keys=True)}')
    except OSError:
        print(f'warning: unable to read optional index {path}', file=sys.stderr)
        continue
PY
matches_file=$(mktemp)
trap 'rm -f "$matches_file"' EXIT
for root in "$CODEX_ROOT/sessions" "$CODEX_ROOT/archived_sessions"; do
    if [ -d "$root" ]; then
        find "$root" -type f -name 'rollout-*.jsonl' -print0 >> "$matches_file"
    fi
done
python3 - "$matches_file" "$SESSION_ID" <<'PY'
from pathlib import Path
import os
import re
import sys

raw_paths = Path(sys.argv[1]).read_bytes().split(b'\0')
session_id = sys.argv[2]
uuid_shaped = re.fullmatch(
    r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
    session_id,
) is not None
needle = session_id.lower() if uuid_shaped else session_id
paths = []
for raw_path in raw_paths:
    if not raw_path:
        continue
    path = os.fsdecode(raw_path)
    basename = os.path.basename(path)
    candidate = basename.lower() if uuid_shaped else basename
    if needle in candidate:
        paths.append(path)
if any(any(not character.isprintable() for character in path) for path in paths):
    print('error: rollout path contains non-printable characters', file=sys.stderr)
    raise SystemExit(2)
for path in sorted(set(paths)):
    print(path)
PY
```

Search both existing roots because an exact session can move from the active date tree to either a flat or date-nested archive layout. Do not append either rollout root to a raw `rg`. A raw rollout match prints the whole JSONL record, and a nested `function_call_output` match can expand into hundreds of thousands of tokens before the useful path is visible.

The recipe keeps `find` output NUL-delimited until Python applies a literal basename substring match and validates every selected path, then rejects non-printable path components before printing any rollout match. It matches complete UUID-shaped session IDs case-insensitively, consistent with lifecycle normalization, while preserving exact characters and case for opaque IDs, including glob metacharacters.

Treat `session_index.jsonl` and `history.jsonl` as optional hints: a missing, unreadable, malformed, or oversized index record must not prevent the rollout-root search, and warnings must never include the raw line. The binary reader limits each candidate record to `max_record_bytes` and drains an oversized physical line through LF in fixed-size chunks; a bare CR never exposes its tail as a separate JSON record.

Recent prior turn or "read your rollout":

```bash
python3 - <<'PY'
from pathlib import Path
import heapq
import json

per_source_limit = 12
max_record_bytes = 1024 * 1024
max_field_chars = 240


def bounded_jsonl(handle):
    line_no = 0
    while True:
        raw_line = handle.readline(max_record_bytes + 1)
        if not raw_line:
            return
        line_no += 1
        if len(raw_line) > max_record_bytes:
            while raw_line and not raw_line.endswith(b'\n'):
                raw_line = handle.readline(max_record_bytes + 1)
            continue
        yield line_no, raw_line


def bounded_scalar(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if not isinstance(value, str):
        return '<non-scalar>'
    output = []
    pending_space = False
    for character in value.replace('\r', '\n'):
        if character.isspace():
            pending_space = bool(output)
            continue
        if pending_space:
            output.append(' ')
            pending_space = False
        output.append(character)
        if len(output) >= max_field_chars:
            break
    return ''.join(output)[:max_field_chars]


for path in (Path('~/.codex/history.jsonl'), Path('~/.codex/session_index.jsonl')):
    path = path.expanduser()
    if not path.exists():
        continue
    latest = []
    with path.open('rb') as handle:
        for line_no, raw_line in bounded_jsonl(handle):
            try:
                row = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(row, dict):
                continue
            selected = {
                key: bounded_scalar(row.get(key))
                for key in ('session_id', 'id', 'ts', 'updated_at', 'cwd')
            }
            text = bounded_scalar(row.get('text') or row.get('thread_name') or '')
            if text:
                selected['text'] = text
            timestamp = str(selected.get('ts') or selected.get('updated_at') or '')
            projection = json.dumps(selected, ensure_ascii=True, sort_keys=True)
            item = (timestamp, line_no, projection)
            if len(latest) < per_source_limit:
                heapq.heappush(latest, item)
            elif item[:2] > latest[0][:2]:
                heapq.heapreplace(latest, item)
    for _, line_no, projection in sorted(latest, reverse=True):
        print(f'{path}:{line_no}:{projection}')
PY
```

The heap retains at most `per_source_limit` bounded projections per source. The reader rejects oversized JSONL records after draining them in fixed-size chunks, so neither one huge record nor a long source file can turn recent-turn orientation into unbounded retained state.

Do not run keyword `rg -n ... ~/.codex` or `rg -n ... "$CODEX_HOME"` to recover a recent command, password hint, or rollout memory. The whole tree includes retained transcript output plus installed skills, overlays, caches, and package payloads; a single match can print irrelevant or enormous records. Use the recent index rows above, a known session ID, or a bounded date directory to select rollout files first.

Bounded date range and current-host corpus inventory:

```bash
set -euo pipefail

TASK_DIR=.codex-tmp/session-mining-20260312-20260313
LOWER_BOUND=2026-03-12T00:00:00Z
UPPER_BOUND=2026-03-14T00:00:00Z
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
SESSION_MINING_SKILL="$CODEX_ROOT/skills/codex-session-mining"

python3 "$SESSION_MINING_SKILL/scripts/build_session_corpus.py" \
    --codex-home "$CODEX_ROOT" \
    --start "$LOWER_BOUND" \
    --end "$UPPER_BOUND" \
    --output "$TASK_DIR" \
    --sample-limit 20
```

Inventory every rollout under both existing roots before applying the requested lower and upper bounds to record or lifecycle timestamps; the helper above enforces that order. This full-root inventory is required for both active and archived rollouts: a rollout created before the window can resume with a genuine human suffix inside it. Do not exclude a file because its dated path or filename predates the window. When a rollout has no record timestamps, the helper prefers the full second-level timestamp or date encoded in its rollout filename, then falls back to a dated directory; archive moves, copies, or metadata updates make mtime unsuitable as the filter.

Budget this command for the complete active-plus-archived corpus, not for the apparent width of `LOWER_BOUND..UPPER_BOUND`. Prefer a previous successful runtime for the same host plus a conservative margin; otherwise use the current full-root scale rather than a short interactive wait as the deadline basis. The helper publishes its counts and output directory only after the complete snapshot succeeds, so quiet stdout is expected. Poll a healthy process with compact elapsed-time, CPU, and process-state checks; do not cancel it merely because no progress line appeared.

A timeout, cancellation, or interrupted producer is an incomplete scan and supplies no reusable checkpoint. Before any retry, prove the original producer and its descendants are quiescent. If quiescence cannot be proved, do not start another full-root scan; retain the process and output-path evidence for handoff. After quiescence is proved, retry with a different fresh nonexistent output directory.

Cleanup of the failed-run path is optional. The protected property is that output directory's object identity. The device/inode or platform-equivalent identity recorded when the directory first appeared, compared with an immediate pre-removal revalidation, detects a replacement that happened before that check; child-entry churn inside the same directory is not an identity mismatch. That comparison does not close the check-to-delete replacement window: a one-shot pathname revalidation followed by recursive deletion can still remove a different directory substituted by another same-UID process. Permit removal only through a trusted descriptor-relative cleanup primitive that binds both the verified parent directory and target directory identities throughout the operation, or under platform containment that prevents replacement. If only pathname-based recursive deletion is available, leave any present path untouched and retain the recorded identity for handoff rather than claiming safe cleanup. If the target is missing at revalidation, classify that result separately as missing: do not recreate it or delete anything at that pathname, retain the recorded path and identity as unresolved handoff evidence, and do not claim this run verified cleanup. If quiescence becomes uncertain, the baseline identity is unavailable, revalidation is unreadable, or the current identity mismatches, likewise leave any present path untouched. Never interpret missing output as an empty corpus, reuse a partial directory, or claim the requested window was fully scanned.

The helper reports `active candidate count`, `archived candidate count`, `union candidate count`, matching parsed counts, `active accepted count`, `archived accepted count`, `union accepted count`, cross-root duplicate groups among accepted candidate groups, collapsed duplicate rollouts, and replayed-prefix records. It requires a fresh nonexistent output directory, lexically normalizes dot segments before traversal, rejects untrusted symlink ancestors, and creates the complete candidate and accepted path lists, `manifest.json`, `corpus-paths.txt`, and `corpus.jsonl` there without following or replacing existing artifact paths. Inventory snapshots and revalidates every traversed directory plus each entry identity and file type; both read passes reopen candidate files from the root directory descriptor with no-follow components and reject replacement or truncation. Non-printable rollout path components fail closed before line-delimited path artifacts or terminal samples are emitted. The first pass pins the complete-record prefix observed when it opens each same-inode rollout, deferring only an unterminated invalid final fragment from an active rollout; the second pass consumes only that verified unchanged prefix, so normal append-only growth remains safe. It prints only the counts plus a bounded union sample. Each `corpus.jsonl` entry retains a distinct suffix, the inferred `owner_id`, all observed `lifecycle_ids`, its in-window `accepted_record_count`, and compact `accepted_line_ranges`; use those locators plus narrowly selected nearby context when reconstructing the real task. For a multi-ID rollout, the filename UUID is accepted as owner only when every identity alias in its first lifecycle record agrees; later foreign IDs are retained as embedded provenance. Owner-later or otherwise ambiguous histories cannot prefix-bridge sessions, although byte-identical copies with the same complete lifecycle-ID set are still safely collapsed. Timestamp-less empty files stay visible in candidate/parsed counts but are not accepted as zero-record tasks. Committed invalid JSON, any invalid archived tail, unsafe path shapes, and inventory or read failures stop the scan instead of silently shrinking the corpus. Groups with no record or fallback timestamp inside the requested window stay in candidate/parsed counts but do not enter the fingerprint-loading pass.

### Current-Host Union And Deduplication

- Treat the existing active and archived roots as one union corpus. Record per-root candidate and accepted counts so a missing root or unexpected zero cannot disappear into a combined total.
- Do not deduplicate by basename or path precedence alone. Prefer the lifecycle session ID from `session_meta`; when it is unavailable, use the filename session ID only as a candidate key and confirm equivalence with ordered stable record fingerprints. Normalize complete UUID-shaped lifecycle aliases to lowercase before comparing them with filename UUIDs, while preserving non-UUID opaque IDs exactly.
- Treat shared lifecycle or filename identity as a required candidate boundary before fingerprint-prefix collapse. Do not merge different session identities from matching content alone: two intentional runs can have identical wrappers and user prompts. Investigate suspected cross-identity fork replay separately with bounded source-history evidence.
- Collapse a byte-identical second file completely, including mixed owner/ambiguous filename cases when both copies carry the same complete lifecycle-ID set. For a non-byte-identical branch, collapse its normalized prefix only through the last matching assistant/tool replay-evidence record; preserve every matching human prompt after that boundary as an uncertain genuine suffix. Fingerprint `session_meta` from explicit lifecycle IDs alone, taking those identities from the actual payload rather than a generated outer envelope when the record is wrapped, and fingerprint `turn_context` from its wrapper type. Canonicalize known generated item, call, response, and turn IDs by per-rollout order while preserving their reference relationships, including computer-call outputs. Keep provenance IDs, unknown substantive record fields, and nested IDs or timestamps inside content and tool results. Identical wrappers plus a repeated user prompt are not sufficient replay evidence.
- Choose canonical history in two stages: first use the earliest of every known record timestamp, or an available filename/path fallback when every record is timestamp-less, to establish source provenance; then compare the complete record-order timestamp and presence sequence to break ties. A short partially restamped copy must follow the older source even when that source's first timestamp is missing, a sparse-timestamp copy must not outrank a complete source with the same provenance start, and an exact old prefix still precedes its longer genuine continuation. Keep a missing fallback explicitly unknown so later known record timestamps remain visible.
- When a filename UUID is unavailable, use a single identity from the first lifecycle record as the owner and retain later lifecycle aliases as provenance. Keep a rollout ambiguous when that first record itself exposes conflicting aliases.
- Recognize `time` alongside `timestamp`, `ts`, `created_at`, and `updated_at` for window filtering, and remove those volatile fields from replay fingerprints. Report a cross-root duplicate group only when candidates from different roots actually share a collapsed copy or removed replay prefix; same-root overlap in a mixed group is not cross-root duplication.
- Serialize fingerprint inputs and JSON corpus artifacts with ASCII escapes so valid JSON strings containing isolated Unicode surrogates remain deterministic and never fail UTF-8 encoding with an uncaught traceback.
- Apply replay detection after the cross-root grouping. A copied and restamped prefix does not become new activity merely because it moved into `archived_sessions`, while a later direct human turn remains new evidence.
- Filter injected `AGENTS.md`, skill, environment, and automation wrapper records when reconstructing user intent. Exclude synthetic child, subagent, and external-review prompts from main-task counts, but do not drop a main rollout solely because its first user-shaped record is an automation wrapper; inspect and retain its later genuine human suffix.

Broad keyword searches across `history.jsonl`, `session_index.jsonl`, `sessions/**/rollout-*.jsonl`, or `archived_sessions/**/rollout-*.jsonl` should not print raw JSONL matches. Use `rg -l` or counts to locate candidate files, then parse records and emit selected fields:

```bash
python3 - <<'PY'
from pathlib import Path
import json
import math
import os
import re

codex_root = Path(os.environ.get('CODEX_HOME', '~/.codex')).expanduser()
sources = (
    ('history', codex_root / 'history.jsonl', 'session_id', 'ts', 'text'),
    ('session_index', codex_root / 'session_index.jsonl', 'id', 'updated_at', 'thread_name'),
)
needle = re.compile(r'review|codex thread|pull/84', re.I)
max_record_bytes = 1024 * 1024
drain_chunk_bytes = 64 * 1024
per_source_match_cap = 20
global_match_limit = 20

def bounded_field(value, limit):
    if not isinstance(value, str):
        return ''
    return ' '.join(value.split())[:limit]

def bounded_timestamp(value, limit):
    if isinstance(value, str):
        return bounded_field(value, limit)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ''
    if isinstance(value, float) and not math.isfinite(value):
        return ''
    encoded = json.dumps(value, allow_nan=False)
    return value if len(encoded) <= limit else ''

source_results = []
for source_name, path, id_key, timestamp_key, text_key in sources:
    matches = []
    source_truncated = False
    try:
        handle = path.open('rb')
    except FileNotFoundError:
        source_results.append({
            'available': False,
            'matches': matches,
            'name': source_name,
            'truncated': source_truncated,
        })
        continue
    with handle:
        line_no = 0
        while True:
            raw_line = handle.readline(max_record_bytes + 1)
            if not raw_line:
                break
            line_no += 1
            if len(raw_line) > max_record_bytes:
                while raw_line and not raw_line.endswith(b'\n'):
                    raw_line = handle.readline(drain_chunk_bytes)
                continue
            try:
                row = json.loads(raw_line.decode('utf-8'))
            except (ValueError, RecursionError):
                continue
            if not isinstance(row, dict):
                continue
            text = row.get(text_key)
            if not isinstance(text, str) or not needle.search(text):
                continue
            if len(matches) >= per_source_match_cap:
                source_truncated = True
                break
            projection = {
                'id': bounded_field(row.get(id_key), 200),
                'line': line_no,
                'path': str(path),
                'text': bounded_field(text, 300),
                'timestamp': bounded_timestamp(row.get(timestamp_key), 200),
            }
            matches.append(projection)
    source_results.append({
        'available': True,
        'matches': matches,
        'name': source_name,
        'truncated': source_truncated,
    })

emitted_counts = [0] * len(source_results)
match_rows_emitted = 0
for match_index in range(per_source_match_cap):
    for source_index, result in enumerate(source_results):
        matches = result['matches']
        if match_index >= len(matches):
            continue
        if match_rows_emitted >= global_match_limit:
            break
        print(json.dumps(matches[match_index], ensure_ascii=True, sort_keys=True))
        emitted_counts[source_index] += 1
        match_rows_emitted += 1
    if match_rows_emitted >= global_match_limit:
        break

source_meta = {}
global_output_truncated = False
for source_index, result in enumerate(source_results):
    retained = len(result['matches'])
    emitted = emitted_counts[source_index]
    truncated = result['truncated']
    source_meta[result['name']] = {
        'available': result['available'],
        'emitted': emitted,
        'match_cap': per_source_match_cap,
        'retained': retained,
        'truncated': truncated,
    }
    if truncated or emitted < retained:
        global_output_truncated = True

print(json.dumps({
    'global_match_limit': global_match_limit,
    'global_output_truncated': global_output_truncated,
    'kind': 'scan_meta',
    'match_rows_emitted': match_rows_emitted,
    'sources': source_meta,
}, ensure_ascii=True, sort_keys=True))
PY
```

This index recipe reads binary physical records up to 1 MiB, drains any oversized record through LF in fixed 64 KiB reads, and treats a bare CR as record data. It strictly decodes UTF-8 and JSON, ignores malformed or non-object records, and searches only the public text field for each index schema. String fields are normalized and length-limited before the outer JSON encoder escapes controls; timestamps additionally preserve bounded JSON integers and finite floats while rejecting booleans, non-finite floats, and oversized numeric projections.

Each source is scanned independently in the fixed order shown above. The recipe retains its first 20 matches in physical-record order, detects a 21st match as source truncation, and then proceeds to the next source. It emits retained matches round-robin in source order, capped at 20 match rows total, so a busy earlier source cannot starve a later one. One fixed-shape `scan_meta` record is always emitted last, making the complete output at most 21 JSON lines. For each source, metadata reports whether the file was available, the 20-match collection cap, retained and emitted counts, and whether a 21st source match was detected. `global_output_truncated` is true when any source detected that extra match or any retained match could not fit in the global output cap. A missing source reports `available: false`; an available source with no matches reports zero retained and emitted rows without truncation.

Use the later bounded rollout probe for `sessions/**/rollout-*.jsonl` and `archived_sessions/**/rollout-*.jsonl`, whose nested record shapes require their own selectors.

## 2. Extract Only The Relevant Parts

For first-pass keyword discovery in one exact rollout, use the fixed case-sensitive literal count, bounded matching-line position sample, and optional bounded raw-prefix sample in [rollout-search.md](rollout-search.md). Those templates prevent an unbounded matching JSONL record from reaching stdout, but they do not parse JSON, select trusted fields, freeze a live rollout, or prove a complete match set. Treat positive and negative counts plus line coordinates as raw-text locator results only. Run the record-shape-aware parser below with the same literal for match or no-match evidence, including when ripgrep counted zero; decoded escapes, normalized whitespace, and field boundaries intentionally give the parser different semantics.

Before printing details from a large rollout, count record shapes and then filter:

```bash
python3 - <<'PY'
from collections import Counter
from pathlib import Path
import json

p = Path('~/.codex/sessions/2026/03/13/rollout-2026-03-13T11-15-32-019ce6e8-a5e3-76e1-91a2-799837c70d1e.jsonl').expanduser()
counts = Counter()

for line in p.open(encoding='utf-8', errors='replace'):
    obj = json.loads(line)
    payload = obj.get('payload') or {}
    counts[(obj.get('type'), payload.get('type'))] += 1

for key, count in counts.most_common():
    print(f'{key[0] or "-"} / {key[1] or "-"}: {count}')
PY
```

Do not use `jq` or Python to print every record timestamp, key list, or tool call from a large rollout just to orient yourself. Once the counts identify the relevant shape, add an explicit selector and row cap before printing snippets.

Do not use `jq 'select(tostring | contains("needle"))'` as a shortcut on rollout or history records. It stringifies the whole record, so a keyword inside retained `function_call_output` can match and print a huge nested payload even when the final projection slices text. Instead, filter on record shape and specific fields before producing an explicitly capped snippet:

```bash
python3 - "$ROLLOUT" "$NEEDLE" <<'PY'
from collections import deque
from pathlib import Path
import json
import sys

path = Path(sys.argv[1]).expanduser()
needle = ' '.join(sys.argv[2].split())
if not needle:
    print('NEEDLE must contain non-whitespace text', file=sys.stderr)
    raise SystemExit(2)
printed = 0
max_rows = 20
max_record_bytes = 1024 * 1024
before_chars = 180
after_chars = 220
max_metadata_chars = 80
scan_meta = {
    'kind': 'scan_meta',
    'scan_complete': False,
    'stop_reason': None,
    'records_seen': 0,
    'invalid_records': 0,
    'oversized_records': 0,
    'matched_records': 0,
    'emitted_rows': 0,
    'suppressed_rows': 0,
    'max_rows': max_rows,
    'output_truncated': False,
}


def bounded_jsonl(handle):
    line_no = 0
    while True:
        raw_line = handle.readline(max_record_bytes + 1)
        if not raw_line:
            return
        line_no += 1
        scan_meta['records_seen'] += 1
        if len(raw_line) > max_record_bytes:
            while raw_line and not raw_line.endswith(b'\n'):
                raw_line = handle.readline(max_record_bytes + 1)
            scan_meta['oversized_records'] += 1
            continue
        yield line_no, raw_line


def iter_text(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_text(item)


def iter_top_level_fields(obj):
    for key in (
        'id',
        'session_id',
        'thread_name',
        'updated_at',
        'ts',
        'timestamp',
        'cwd',
        'model',
        'current_date',
        'timezone',
        'approval_policy',
        'sandbox_policy',
        'permission_profile',
        'originator',
        'cli_version',
        'source',
        'thread_source',
        'model_provider',
        'name',
        'arguments',
        'output',
        'content',
        'result',
        'text',
        'message',
        'last_agent_message',
        'title',
    ):
        value = obj.get(key)
        if value is None or value == '' or value == [] or value == {}:
            continue
        yield key
        yield from iter_text(value)


def bounded_output_field(value, fallback):
    if not isinstance(value, str):
        return fallback
    fragments = []
    length = 0
    pending_space = False
    truncated = False
    for character in value:
        if character.isspace():
            pending_space = bool(fragments)
            continue
        encoded = json.dumps(character, ensure_ascii=True)[1:-1]
        candidates = (' ', encoded) if pending_space else (encoded,)
        for fragment in candidates:
            if length + len(fragment) > max_metadata_chars:
                truncated = True
                break
            fragments.append(fragment)
            length += len(fragment)
        if truncated:
            break
        pending_space = False
    if not fragments:
        return fallback
    if truncated:
        while fragments and length + 3 > max_metadata_chars:
            length -= len(fragments.pop())
        fragments.append('...')
    return ''.join(fragments)


def first_string_value(*values):
    for value in values:
        if isinstance(value, str) and value:
            return value
    return None


def iter_record_text(obj, payload, item_type):
    yield item_type or ''
    if item_type == 'message':
        yield from iter_text(payload.get('content') or [])
    elif item_type == 'function_call':
        yield from iter_text(payload.get('name') or '')
        yield from iter_text(payload.get('arguments') or '')
    elif item_type == 'function_call_output':
        yield from iter_text(payload.get('output') or payload.get('content') or payload.get('result') or '')
    elif item_type == 'user_message':
        yield from iter_text(payload.get('message') or payload.get('text') or payload.get('content') or '')
    elif item_type == 'task_complete':
        yield from iter_text(payload.get('last_agent_message') or payload.get('message') or payload.get('text') or '')
    elif not item_type:
        yield from iter_top_level_fields(obj)
        yield from iter_top_level_fields(payload)
    else:
        yield from iter_top_level_fields(payload)


def normalized_characters(parts):
    emitted = False
    pending_space = False
    for part in parts:
        if emitted:
            pending_space = True
        for character in part:
            if character.isspace():
                if emitted:
                    pending_space = True
                continue
            if pending_space:
                yield ' '
                pending_space = False
            yield character
            emitted = True


def prefix_table(pattern):
    table = [0] * len(pattern)
    matched = 0
    for index in range(1, len(pattern)):
        while matched and pattern[matched] != pattern[index]:
            matched = table[matched - 1]
        if pattern[matched] == pattern[index]:
            matched += 1
            table[index] = matched
    return table


def hit_window(parts, raw_needle):
    normalized_needle = ' '.join(raw_needle.split())
    if not normalized_needle:
        return ''
    table = prefix_table(normalized_needle)
    matched = 0
    consumed = 0
    before = deque(maxlen=before_chars + len(normalized_needle))
    prefix = None
    after = []
    for character in normalized_characters(parts):
        if prefix is not None:
            if len(after) >= after_chars:
                return prefix + ''.join(after) + '...'
            after.append(character)
            continue
        before.append(character)
        consumed += 1
        while matched and normalized_needle[matched] != character:
            matched = table[matched - 1]
        if normalized_needle[matched] == character:
            matched += 1
        if matched == len(normalized_needle):
            prefix = ('...' if consumed > len(before) else '') + ''.join(before)
    if prefix is None:
        return None
    return prefix + ''.join(after)


def escaped_output_text(value):
    return ''.join(
        character
        if character.isprintable()
        else json.dumps(character, ensure_ascii=True)[1:-1]
        for character in value
    )


with path.open('rb') as handle:
    records = bounded_jsonl(handle)
    for line_no, raw_line in records:
        try:
            obj = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            scan_meta['invalid_records'] += 1
            continue
        if not isinstance(obj, dict):
            scan_meta['invalid_records'] += 1
            continue
        payload = obj.get('payload') or {}
        if not isinstance(payload, dict):
            payload = {}
        item_type_value = payload.get('type')
        item_type = item_type_value if isinstance(item_type_value, str) else None
        safe_item_type = bounded_output_field(item_type, '')
        record_kind = safe_item_type or bounded_output_field(obj.get('type'), 'history')
        timestamp_value = first_string_value(obj.get('timestamp'), obj.get('ts'))
        timestamp = bounded_output_field(timestamp_value, '')
        snippet = hit_window(
            iter_record_text(obj, payload, item_type),
            needle,
        )
        if snippet is None:
            continue
        scan_meta['matched_records'] += 1
        if printed < max_rows:
            safe_snippet = escaped_output_text(snippet)
            print(f'{path}:{line_no}:{timestamp}:{record_kind}:{safe_snippet}')
            printed += 1
        else:
            scan_meta['suppressed_rows'] += 1

scan_meta['scan_complete'] = True
scan_meta['emitted_rows'] = printed
scan_meta['output_truncated'] = scan_meta['suppressed_rows'] > 0
print(json.dumps(scan_meta, sort_keys=True, separators=(',', ':')), file=sys.stderr)
PY
```

The parser rejects an empty or whitespace-only needle before opening the rollout. The binary reader accepts only physical JSONL records up to 1 MiB and drains an oversized record through LF in fixed-size chunks; a bare CR inside that record cannot expose its tail as a new record. Matching walks the full selected strings, including the original type string, incrementally, normalizes whitespace across both string and field boundaries, and retains only the needle plus the bounded context window instead of joining a complete tool output in memory. After raw matching and window selection, the snippet JSON-escapes only non-printable characters so terminal control sequences cannot reach stdout while printable Unicode remains unchanged. Printed metadata accepts strings only, normalizes whitespace, JSON-escapes non-ASCII and control characters, and caps each field before it reaches stdout.

The parser continues through point-in-time EOF after its 20 stdout rows are full. Its final stderr line is one compact `scan_meta` JSON object; keep it in a private bounded control sink and require normal process exit plus `scan_complete: true`. `matched_records` counts every matching physical record reached by the selected-field scan, while `emitted_rows`, `suppressed_rows`, and `output_truncated` distinguish complete matching from bounded presentation. `invalid_records` and `oversized_records` identify physical records the parser could not inspect; they must be zero before claiming a complete no-match result. These counters do not freeze a live rollout or prove content stability.

For JSONL schema checks, inspect one record or aggregate unique keys once. Do not run `jq -R 'fromjson | keys' file.jsonl`, because it prints the same key list for every line and can produce massive output on retained artifacts such as `turn_flags.jsonl`.

```bash
python3 - "$JSONL_PATH" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
line_count = 0
unique_keys = set()
unique_key_utf8_bytes = 0
unique_keys_truncated = False
unique_keys_truncation_reason = None
first_record_seen = False
first_record_keys = []
first_record_key_utf8_bytes = 0
first_record_keys_truncated = False
max_record_bytes = 1024 * 1024
drain_chunk_bytes = 64 * 1024
max_unique_keys = 256
max_unique_key_utf8_bytes = 32 * 1024

with path.open('rb') as handle:
    while True:
        raw_line = handle.readline(max_record_bytes + 1)
        if not raw_line:
            break
        line_count += 1
        if len(raw_line) > max_record_bytes:
            while raw_line and not raw_line.endswith(b'\n'):
                raw_line = handle.readline(drain_chunk_bytes)
            continue
        try:
            row = json.loads(raw_line.decode('utf-8'))
        except (ValueError, RecursionError):
            continue
        if not isinstance(row, dict):
            continue
        if not first_record_seen:
            first_record_seen = True
            for key in row:
                try:
                    key_utf8_bytes = len(key.encode('utf-8'))
                except UnicodeEncodeError:
                    first_record_keys_truncated = True
                    break
                if (
                    len(first_record_keys) >= max_unique_keys
                    or first_record_key_utf8_bytes + key_utf8_bytes
                    > max_unique_key_utf8_bytes
                ):
                    first_record_keys_truncated = True
                    break
                first_record_keys.append(key)
                first_record_key_utf8_bytes += key_utf8_bytes
        if unique_keys_truncated:
            continue
        for key in row:
            if key in unique_keys:
                continue
            try:
                key_utf8_bytes = len(key.encode('utf-8'))
            except UnicodeEncodeError:
                unique_keys_truncated = True
                unique_keys_truncation_reason = 'non_utf8_key'
                break
            if len(unique_keys) >= max_unique_keys:
                unique_keys_truncated = True
                unique_keys_truncation_reason = 'count'
                break
            if unique_key_utf8_bytes + key_utf8_bytes > max_unique_key_utf8_bytes:
                unique_keys_truncated = True
                unique_keys_truncation_reason = 'utf8_bytes'
                break
            unique_keys.add(key)
            unique_key_utf8_bytes += key_utf8_bytes

print(json.dumps({
    'path': str(path),
    'line_count': line_count,
    'first_record_key_count': len(first_record_keys),
    'first_record_key_utf8_bytes': first_record_key_utf8_bytes,
    'first_record_keys': sorted(first_record_keys),
    'first_record_keys_truncated': first_record_keys_truncated,
    'max_unique_keys': max_unique_keys,
    'max_unique_key_utf8_bytes': max_unique_key_utf8_bytes,
    'unique_key_count': len(unique_keys),
    'unique_key_utf8_bytes': unique_key_utf8_bytes,
    'unique_keys': sorted(unique_keys),
    'unique_keys_truncated': unique_keys_truncated,
    'unique_keys_truncation_reason': unique_keys_truncation_reason,
}, ensure_ascii=True, sort_keys=True))
PY
```

The schema recipe applies the same 1 MiB binary physical-record cap and fixed-size LF drain. Invalid UTF-8, malformed JSON, non-object top-level values, and oversized records still count as physical input records but do not contribute schema keys.

Schema keys use a deterministic bounded-prefix contract. New keys are considered in physical-record order and then in decoded JSON object order. Duplicate keys do not consume budget. A key is accepted when doing so keeps both the unique-key count at or below 256 and the cumulative size of decoded keys under strict UTF-8 encoding at or below 32 KiB. The first new key that would exceed either boundary is omitted, `unique_keys_truncated` becomes true, `unique_keys_truncation_reason` records `count` or `utf8_bytes`, and no later new keys are accepted. If both limits would be exceeded by the same key, `count` wins because that boundary is checked first. A decoded key that cannot be encoded as strict UTF-8 instead records `non_utf8_key` and stops the prefix at that key. The reported count and byte total describe the retained prefix exactly; sorting happens only after that prefix is bounded. The first valid object remains the source of `first_record_keys`, whose projection uses the same count, byte, and strict-encoding boundaries and reports its own truncation marker.

Beyond a fixed number of per-record parsing objects derived from physical records capped at 1 MiB, the recipe retains at most 256 global keys totaling at most 32 KiB under strict UTF-8 encoding and the equivalently bounded first-record key projection. Its key-list output has the same count and strict-encoding byte bounds before JSON escaping, whose expansion is itself bounded by a constant factor.

Show user and assistant messages for one rollout, while skipping the wrapper noise that otherwise makes every session look like it mentioned every listed skill:

```bash
python3 - <<'PY'
from pathlib import Path
import json
p = Path('~/.codex/sessions/2026/03/13/rollout-2026-03-13T11-15-32-019ce6e8-a5e3-76e1-91a2-799837c70d1e.jsonl').expanduser()
limit = 40
printed = 0

def meaningful(text: str) -> bool:
    prefixes = (
        '# AGENTS.md instructions',
        '<skill>',
        '<environment_context>',
        '<subagent_notification>',
        '# Review findings:',
    )
    return bool(text) and not text.startswith(prefixes)

for line in p.open():
    obj = json.loads(line)
    if obj.get('type') != 'response_item':
        continue
    payload = obj['payload']
    if payload.get('type') != 'message':
        continue
    role = payload.get('role')
    texts = []
    for part in payload.get('content', []):
        if part.get('type') in ('input_text', 'output_text'):
            texts.append(part.get('text', ''))
    text = '\\n'.join(texts).strip()
    if not meaningful(text):
        continue
    print(f'[{role}] {text[:400]}')
    printed += 1
    if printed >= limit:
        print(f'... stopped after {limit} messages; tighten the selector before printing more')
        break
PY
```

If you need the raw wrappers for provenance, keep a second pass for them, but do not use those wrapper-only messages to classify user intent or count skill mentions.

Focus on tool failures or approval friction:

Use this field-aware parser after the fixed rollout-search protocol has identified the exact file or candidate lines.

```bash
python3 - <<'PY'
from pathlib import Path
import json
import os
import re

path = Path(os.environ.get(
    'CODEX_ROLLOUT_SAMPLE',
    '~/.codex/sessions/2026/03/12/rollout-2026-03-12T13-19-05-019ce233-677c-7e73-a77d-a3b7eecab61e.jsonl',
)).expanduser()
needle = re.compile(r'auth|approval|permission|denied|Could not open file|failed|blocked', re.I)
printed = 0

def collect_text(value, parts):
    if isinstance(value, str):
        parts.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            collect_text(item, parts)
    elif isinstance(value, list):
        for item in value:
            collect_text(item, parts)

def hit_window(text, match):
    start = max(0, match.start() - 180)
    end = min(len(text), match.end() + 220)
    prefix = '...' if start else ''
    suffix = '...' if end < len(text) else ''
    return prefix + text[start:end] + suffix

def add_selected_fields(obj, parts):
    for key in (
        'id',
        'session_id',
        'thread_name',
        'updated_at',
        'ts',
        'timestamp',
        'cwd',
        'model',
        'current_date',
        'timezone',
        'approval_policy',
        'sandbox_policy',
        'permission_profile',
        'originator',
        'cli_version',
        'source',
        'thread_source',
        'model_provider',
        'name',
        'arguments',
        'output',
        'content',
        'result',
        'text',
        'message',
        'last_agent_message',
        'title',
    ):
        value = obj.get(key)
        if value is None or value == '' or value == [] or value == {}:
            continue
        parts.append(key)
        collect_text(value, parts)

def add_record_fields(obj, payload, parts):
    item_type = payload.get('type')
    parts.append(str(item_type or ''))
    if item_type == 'message':
        collect_text(payload.get('content') or [], parts)
    elif item_type == 'function_call':
        collect_text(payload.get('name') or '', parts)
        collect_text(payload.get('arguments') or '', parts)
    elif item_type == 'function_call_output':
        collect_text(payload.get('output') or payload.get('content') or payload.get('result') or '', parts)
    elif item_type == 'user_message':
        collect_text(payload.get('message') or payload.get('text') or payload.get('content') or '', parts)
    elif item_type == 'task_complete':
        collect_text(payload.get('last_agent_message') or payload.get('message') or payload.get('text') or '', parts)
    elif not item_type:
        add_selected_fields(obj, parts)
        add_selected_fields(payload, parts)
    else:
        add_selected_fields(payload, parts)

for line_no, line in enumerate(path.open(encoding='utf-8', errors='replace'), 1):
    obj = json.loads(line)
    payload = obj.get('payload') or {}
    parts = []
    add_record_fields(obj, payload, parts)
    text = ' '.join(' '.join(parts).split())
    match = needle.search(text)
    if not match:
        continue
    snippet = hit_window(text, match)
    print(f'{path}:{line_no}:{obj.get("timestamp")}:{obj.get("type")}:{payload.get("type")}:{snippet}')
    printed += 1
    if printed >= 20:
        break
PY
```

Search a bounded rollout set without dumping full JSONL records:

Use this field-aware parser after candidate discovery; it is not a replacement for the fixed one-file ripgrep output protocol.

```bash
python3 - <<'PY'
from pathlib import Path
import json
import os

sample = os.environ.get('CODEX_ROLLOUT_SAMPLE')
paths = [Path(sample).expanduser()] if sample else sorted(Path('~/.codex/sessions/2026/03/12').expanduser().glob('rollout-*.jsonl'))
needle = 'thread/start'
printed = 0

def collect_text(value, parts):
    if isinstance(value, str):
        parts.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            collect_text(item, parts)
    elif isinstance(value, list):
        for item in value:
            collect_text(item, parts)

def hit_window(text, needle):
    idx = text.find(needle)
    if idx < 0:
        return ''
    start = max(0, idx - 160)
    end = min(len(text), idx + len(needle) + 200)
    prefix = '...' if start else ''
    suffix = '...' if end < len(text) else ''
    return prefix + text[start:end] + suffix

def add_selected_fields(obj, parts):
    for key in (
        'id',
        'session_id',
        'thread_name',
        'updated_at',
        'ts',
        'timestamp',
        'cwd',
        'model',
        'current_date',
        'timezone',
        'approval_policy',
        'sandbox_policy',
        'permission_profile',
        'originator',
        'cli_version',
        'source',
        'thread_source',
        'model_provider',
        'name',
        'arguments',
        'output',
        'content',
        'result',
        'text',
        'message',
        'last_agent_message',
        'title',
    ):
        value = obj.get(key)
        if value is None or value == '' or value == [] or value == {}:
            continue
        parts.append(key)
        collect_text(value, parts)

def add_record_fields(obj, payload, parts):
    item_type = payload.get('type')
    parts.append(str(item_type or ''))
    if item_type == 'message':
        collect_text(payload.get('content') or [], parts)
    elif item_type == 'function_call':
        collect_text(payload.get('name') or '', parts)
        collect_text(payload.get('arguments') or '', parts)
    elif item_type == 'function_call_output':
        collect_text(payload.get('output') or payload.get('content') or payload.get('result') or '', parts)
    elif item_type == 'user_message':
        collect_text(payload.get('message') or payload.get('text') or payload.get('content') or '', parts)
    elif item_type == 'task_complete':
        collect_text(payload.get('last_agent_message') or payload.get('message') or payload.get('text') or '', parts)
    elif not item_type:
        add_selected_fields(obj, parts)
        add_selected_fields(payload, parts)
    else:
        add_selected_fields(payload, parts)

for path in paths:
    for line_no, line in enumerate(path.open(encoding='utf-8', errors='replace'), 1):
        obj = json.loads(line)
        payload = obj.get('payload') or {}
        if obj.get('type') == 'function_call_output' or payload.get('type') == 'function_call_output':
            continue
        parts = []
        add_record_fields(obj, payload, parts)
        text = ' '.join(' '.join(parts).split())
        if needle not in text:
            continue
        snippet = hit_window(text, needle)
        print(f'{path}:{line_no}:{obj.get("timestamp")}:{obj.get("type")}:{payload.get("type")}:{snippet}')
        printed += 1
        if printed >= 20:
            raise SystemExit
PY
```

## 3. Audit Repeated Skill Friction

- First inventory both existing current-host transcript roots and list the sessions in scope. Report active, archived, union, and accepted-after-deduplication counts separately.
- Detect resumed or forked replay before counting new activity:
  - Count records by session and measure the timestamp span before printing details. Hundreds of thousands of records or old user tasks appearing within seconds are replay signals, not evidence that the work happened again.
  - Emit a bounded sequence of `session_meta`, `turn_context`, `task_started`, and user-message summaries around each resume point. Do not orient with the full rollout.
  - Compare the suspicious prefix with earlier source history using a stable fingerprint over record type, role or call name, and normalized selected content. Keep the source path and ordering in the comparison.
  - Choose the latest genuine resume boundary, exclude only the matching replay prefix, and retain later human follow-ups. Do not deduplicate a real repeated short prompt solely because its text matches an earlier prompt.
  - When the same lifecycle session appears under active and archived roots, compare ordered stable record fingerprints across both files and retain any distinct later suffix instead of choosing one path wholesale.
  - Exclude synthetic child/reviewer task prompts from main-task classification, but keep later genuine human follow-ups in a main rollout even when its initial turn was automation boilerplate.
  - Report replayed and genuinely new record counts separately so the audit remains reviewable.
- Then look for the smallest decisive evidence:
  - user asked for a skill explicitly but it was not used
  - a helper or auth preflight was rediscovered manually
  - an outdated path or command shape caused a miss
  - the same bounded workflow appeared multiple times without a reusable skill
- When a problem shows up only once, prefer leaving a note instead of immediately creating a new skill.

## 4. Escalate To Remote Coverage Only When Needed

If the user is asking for a work summary, activity audit, or session recovery that may include remote hosts, use an environment-specific remote evidence workflow before concluding that the local `~/.codex` tree is complete.
