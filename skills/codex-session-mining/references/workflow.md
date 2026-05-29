# Codex Session Mining Recipes

Use these recipes when the task is to recover prior work, map a session ID to a rollout file, or audit repeated workflow friction from the user's local Codex history.

## 1. Find The Canonical Rollout File

Exact session ID:

```bash
SESSION_ID='019ce6e8-a5e3-76e1-91a2-799837c70d1e'
python3 - "$SESSION_ID" <<'PY'
from pathlib import Path
import json
import sys

session_id = sys.argv[1]
for path in (Path('~/.codex/session_index.jsonl'), Path('~/.codex/history.jsonl')):
    path = path.expanduser()
    for line_no, line in enumerate(path.open(encoding='utf-8', errors='replace'), 1):
        if session_id not in line:
            continue
        row = json.loads(line)
        selected = {key: row.get(key) for key in ('id', 'session_id', 'thread_name', 'updated_at', 'ts', 'cwd')}
        text = ' '.join(str(row.get('text') or '').split())[:300]
        if text:
            selected['text'] = text
        print(f'{path}:{line_no}:{json.dumps(selected, ensure_ascii=False, sort_keys=True)}')
PY
find ~/.codex/sessions -type f -name "rollout-*${SESSION_ID}*.jsonl"
```

Do not append `~/.codex/sessions` to a raw `rg`. A raw rollout match prints the whole JSONL record, and a nested `function_call_output` match can expand into hundreds of thousands of tokens before the useful path is visible.

Bounded date range:

```bash
find ~/.codex/sessions/2026/03/12 ~/.codex/sessions/2026/03/13 -type f -name 'rollout-*.jsonl' | sort
```

Prefer filename timestamps or date-tree boundaries over `find -mtime` when the requested window is strict.

Broad keyword searches across `history.jsonl`, `session_index.jsonl`, `sessions/**/rollout-*.jsonl`, or `archived_sessions/*.jsonl` should not print raw JSONL matches. Use `rg -l` or counts to locate candidate files, then parse records and emit selected fields:

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
        collect_text(obj.get(key) or '', parts)

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
        collect_text(obj.get(key) or '', parts)

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
        collect_text(obj.get(key) or '', parts)

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

- First list the sessions in scope.
- Then look for the smallest decisive evidence:
  - user asked for a skill explicitly but it was not used
  - a helper or auth preflight was rediscovered manually
  - an outdated path or command shape caused a miss
  - the same bounded workflow appeared multiple times without a reusable skill
- When a problem shows up only once, prefer leaving a note instead of immediately creating a new skill.

## 4. Escalate To Remote Coverage Only When Needed

If the user is asking for a work summary, activity audit, or session recovery that may include remote hosts, use an environment-specific remote evidence workflow before concluding that the local `~/.codex` tree is complete.
