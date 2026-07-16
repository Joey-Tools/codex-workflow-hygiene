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
import sys

session_id = sys.argv[1]
codex_root = Path(sys.argv[2]).expanduser()
for path in (codex_root / 'session_index.jsonl', codex_root / 'history.jsonl'):
    if not path.is_file():
        continue
    try:
        with path.open(encoding='utf-8', errors='replace') as handle:
            for line_no, line in enumerate(handle, 1):
                if session_id not in line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                selected = {key: row.get(key) for key in ('id', 'session_id', 'thread_name', 'updated_at', 'ts', 'cwd')}
                text = ' '.join(str(row.get('text') or '').split())[:300]
                if text:
                    selected['text'] = text
                print(f'{path}:{line_no}:{json.dumps(selected, ensure_ascii=False, sort_keys=True)}')
    except OSError:
        print(f'warning: unable to read optional index {path}', file=sys.stderr)
        continue
PY
matches_file=$(mktemp)
trap 'rm -f "$matches_file"' EXIT
find_name_predicate=-name
if [[ "$SESSION_ID" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]; then
    find_name_predicate=-iname
fi
for root in "$CODEX_ROOT/sessions" "$CODEX_ROOT/archived_sessions"; do
    if [ -d "$root" ]; then
        find "$root" -type f "$find_name_predicate" "rollout-*${SESSION_ID}*.jsonl" -print0 >> "$matches_file"
    fi
done
python3 - "$matches_file" <<'PY'
from pathlib import Path
import os
import sys

raw_paths = Path(sys.argv[1]).read_bytes().split(b'\0')
paths = [os.fsdecode(raw_path) for raw_path in raw_paths if raw_path]
if any(any(not character.isprintable() for character in path) for path in paths):
    print('error: rollout path contains non-printable characters', file=sys.stderr)
    raise SystemExit(2)
for path in sorted(set(paths)):
    print(path)
PY
```

Search both existing roots because an exact session can move from the active date tree to either a flat or date-nested archive layout. Do not append either rollout root to a raw `rg`. A raw rollout match prints the whole JSONL record, and a nested `function_call_output` match can expand into hundreds of thousands of tokens before the useful path is visible.

The recipe keeps `find` output NUL-delimited until every candidate path is validated and rejects non-printable path components before printing any rollout match. It matches complete UUID-shaped session IDs case-insensitively, consistent with lifecycle normalization, while preserving exact case for opaque IDs.

Treat `session_index.jsonl` and `history.jsonl` as optional hints: a missing, unreadable, or malformed index record must not prevent the rollout-root search, and warnings must never include the raw line.

Recent prior turn or "read your rollout":

```bash
python3 - <<'PY'
from pathlib import Path
import json

per_source_limit = 12
for path in (Path('~/.codex/history.jsonl'), Path('~/.codex/session_index.jsonl')):
    path = path.expanduser()
    if not path.exists():
        continue
    rows = []
    with path.open(encoding='utf-8', errors='replace') as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append((row.get('ts') or row.get('updated_at') or '', line_no, row))
    for _, line_no, row in sorted(rows, reverse=True)[:per_source_limit]:
        selected = {key: row.get(key) for key in ('session_id', 'id', 'ts', 'updated_at', 'cwd')}
        text = ' '.join(str(row.get('text') or row.get('thread_name') or '').split())[:240]
        if text:
            selected['text'] = text
        print(f'{path}:{line_no}:{json.dumps(selected, ensure_ascii=False, sort_keys=True)}')
PY
```

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

The helper reports `active candidate count`, `archived candidate count`, `union candidate count`, matching parsed counts, `active accepted count`, `archived accepted count`, `union accepted count`, cross-root duplicate groups among accepted candidate groups, collapsed duplicate rollouts, and replayed-prefix records. It requires a fresh nonexistent output directory, lexically normalizes dot segments before traversal, rejects untrusted symlink ancestors, and creates the complete candidate and accepted path lists, `manifest.json`, `corpus-paths.txt`, and `corpus.jsonl` there without following or replacing existing artifact paths. Inventory snapshots and revalidates every traversed directory plus each entry identity and file type; both read passes reopen candidate files from the root directory descriptor with no-follow components and reject replacement or truncation. Non-printable rollout path components fail closed before line-delimited path artifacts or terminal samples are emitted. The first pass pins the complete-record prefix observed when it opens each same-inode rollout, deferring only an unterminated invalid final fragment from an active rollout; the second pass consumes only that verified unchanged prefix, so normal append-only growth remains safe. It prints only the counts plus a bounded union sample. Each `corpus.jsonl` entry retains a distinct suffix, the inferred `owner_id`, all observed `lifecycle_ids`, its in-window `accepted_record_count`, and compact `accepted_line_ranges`; use those locators plus narrowly selected nearby context when reconstructing the real task. For a multi-ID rollout, the filename UUID is accepted as owner only when every identity alias in its first lifecycle record agrees; later foreign IDs are retained as embedded provenance. Owner-later or otherwise ambiguous histories cannot prefix-bridge sessions, although byte-identical copies with the same complete lifecycle-ID set are still safely collapsed. Timestamp-less empty files stay visible in candidate/parsed counts but are not accepted as zero-record tasks. Committed invalid JSON, any invalid archived tail, unsafe path shapes, and inventory or read failures stop the scan instead of silently shrinking the corpus. Groups with no record or fallback timestamp inside the requested window stay in candidate/parsed counts but do not enter the fingerprint-loading pass.

### Current-Host Union And Deduplication

- Treat the existing active and archived roots as one union corpus. Record per-root candidate and accepted counts so a missing root or unexpected zero cannot disappear into a combined total.
- Do not deduplicate by basename or path precedence alone. Prefer the lifecycle session ID from `session_meta`; when it is unavailable, use the filename session ID only as a candidate key and confirm equivalence with ordered stable record fingerprints. Normalize complete UUID-shaped lifecycle aliases to lowercase before comparing them with filename UUIDs, while preserving non-UUID opaque IDs exactly.
- Treat shared lifecycle or filename identity as a required candidate boundary before fingerprint-prefix collapse. Do not merge different session identities from matching content alone: two intentional runs can have identical wrappers and user prompts. Investigate suspected cross-identity fork replay separately with bounded source-history evidence.
- Collapse a byte-identical second file completely, including mixed owner/ambiguous filename cases when both copies carry the same complete lifecycle-ID set. For a non-byte-identical branch, collapse its normalized prefix only through the last matching assistant/tool replay-evidence record; preserve every matching human prompt after that boundary as an uncertain genuine suffix. Fingerprint `session_meta` from explicit lifecycle IDs alone and `turn_context` from its wrapper type, and canonicalize known generated item, call, response, and turn IDs by per-rollout order while preserving their reference relationships, including computer-call outputs. Keep provenance IDs, unknown substantive record fields, and nested IDs or timestamps inside content and tool results. Identical wrappers plus a repeated user prompt are not sufficient replay evidence.
- Choose canonical history by the complete record-order timestamp source, not only the earliest timestamp. A short partially restamped copy that retains one old opening timestamp must follow the older full source, while an exact old prefix still precedes its longer genuine continuation.
- When a filename UUID is unavailable, use a single identity from the first lifecycle record as the owner and retain later lifecycle aliases as provenance. Keep a rollout ambiguous when that first record itself exposes conflicting aliases.
- Recognize `time` alongside `timestamp`, `ts`, `created_at`, and `updated_at` for window filtering, and remove those volatile fields from replay fingerprints. Report a cross-root duplicate group only when candidates from different roots actually share a collapsed copy or removed replay prefix; same-root overlap in a mixed group is not cross-root duplication.
- Apply replay detection after the cross-root grouping. A copied and restamped prefix does not become new activity merely because it moved into `archived_sessions`, while a later direct human turn remains new evidence.
- Filter injected `AGENTS.md`, skill, environment, and automation wrapper records when reconstructing user intent. Exclude synthetic child, subagent, and external-review prompts from main-task counts, but do not drop a main rollout solely because its first user-shaped record is an automation wrapper; inspect and retain its later genuine human suffix.

Broad keyword searches across `history.jsonl`, `session_index.jsonl`, `sessions/**/rollout-*.jsonl`, or `archived_sessions/**/rollout-*.jsonl` should not print raw JSONL matches. Use `rg -l` or counts to locate candidate files, then parse records and emit selected fields:

```bash
python3 - <<'PY'
from pathlib import Path
import json
import re

paths = [Path('~/.codex/history.jsonl').expanduser()]
needle = re.compile(r'review|codex thread|pull/84', re.I)
printed = 0

for path in paths:
    for line_no, line in enumerate(path.open(encoding='utf-8', errors='replace'), 1):
        if not needle.search(line):
            continue
        row = json.loads(line)
        text = ' '.join(str(row.get('text') or '').split())[:300]
        print(f'{path}:{line_no}:{row.get("session_id")}:{row.get("ts")}:{text}')
        printed += 1
        if printed >= 20:
            raise SystemExit
PY
```

## 2. Extract Only The Relevant Parts

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
from pathlib import Path
import json
import sys

path = Path(sys.argv[1]).expanduser()
needle = sys.argv[2]
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
    start = max(0, idx - 180)
    end = min(len(text), idx + len(needle) + 220)
    prefix = '...' if start else ''
    suffix = '...' if end < len(text) else ''
    return prefix + text[start:end] + suffix

def add_top_level_fields(obj, parts):
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

for line_no, line in enumerate(path.open(encoding='utf-8', errors='replace'), 1):
    obj = json.loads(line)
    payload = obj.get('payload') or {}
    item_type = payload.get('type')
    record_kind = item_type or obj.get('type') or 'history'
    text_parts = [str(item_type or '')]
    if item_type == 'message':
        collect_text(payload.get('content') or [], text_parts)
    elif item_type == 'function_call':
        text_parts.append(str(payload.get('name') or ''))
        text_parts.append(str(payload.get('arguments') or ''))
    elif item_type == 'function_call_output':
        collect_text(payload.get('output') or payload.get('content') or payload.get('result') or '', text_parts)
    elif item_type == 'user_message':
        collect_text(payload.get('message') or payload.get('text') or payload.get('content') or '', text_parts)
    elif item_type == 'task_complete':
        collect_text(payload.get('last_agent_message') or payload.get('message') or payload.get('text') or '', text_parts)
    elif not item_type:
        add_top_level_fields(obj, text_parts)
        add_top_level_fields(payload, text_parts)
    else:
        add_top_level_fields(payload, text_parts)
    text = ' '.join(' '.join(text_parts).split())
    if needle not in text:
        continue
    print(f'{path}:{line_no}:{obj.get("timestamp") or obj.get("ts")}:{record_kind}:{hit_window(text, needle)}')
    printed += 1
    if printed >= 20:
        break
PY
```

For JSONL schema checks, inspect one record or aggregate unique keys once. Do not run `jq -R 'fromjson | keys' file.jsonl`, because it prints the same key list for every line and can produce massive output on retained artifacts such as `turn_flags.jsonl`.

```bash
python3 - "$JSONL_PATH" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
line_count = 0
keys = set()
first = None

with path.open(encoding='utf-8', errors='replace') as handle:
    for line in handle:
        line_count += 1
        if not line.strip():
            continue
        row = json.loads(line)
        if first is None:
            first = row
        keys.update(row.keys())

print(json.dumps({
    'path': str(path),
    'line_count': line_count,
    'first_record_keys': sorted(first.keys()) if isinstance(first, dict) else [],
    'unique_keys': sorted(keys),
}, ensure_ascii=False, sort_keys=True))
PY
```

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
