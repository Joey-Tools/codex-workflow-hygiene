"""Complete retained-history graph and parent-edge validation."""

from __future__ import annotations

import re
from typing import Any, Sequence

from .authority_errors import HistoryValidationError


MAX_HISTORY_COMMITS = 65_536
HISTORY_PATHSPEC = "runs"
_OBJECT_ID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _require(condition: object, message: str) -> None:
    if not condition:
        raise HistoryValidationError(message)


def _complete_graph(
    repo: Any,
    target_ref: str,
    *,
    expected_head: str,
) -> tuple[list[tuple[str, tuple[str, ...]]], bytes]:
    result = repo.run(
        "rev-list",
        "--reverse",
        "--topo-order",
        "--parents",
        f"--max-count={MAX_HISTORY_COMMITS + 1}",
        target_ref,
    )
    rows = result.stdout.splitlines()
    _require(
        len(rows) <= MAX_HISTORY_COMMITS,
        "durable history graph exceeds its bound",
    )

    graph: list[tuple[str, tuple[str, ...]]] = []
    seen: set[str] = set()
    for raw_row in rows:
        try:
            fields = raw_row.decode("ascii", errors="strict").split(" ")
        except UnicodeDecodeError as exc:
            raise HistoryValidationError("durable history graph is not ASCII") from exc
        _require(
            all(
                (
                    bool(fields),
                    all(map(_OBJECT_ID_RE.fullmatch, fields)),
                    fields[0] not in seen,
                    len(set(fields[1:])) == len(fields[1:]),
                    all(map(seen.__contains__, fields[1:])),
                )
            ),
            "durable history graph is invalid",
        )
        commit = fields[0]
        parents = tuple(fields[1:])
        graph.append((commit, parents))
        seen.add(commit)
    _require(bool(graph), "durable history graph does not reach its head")
    _require(
        all(
            (
                graph[-1][0] == expected_head,
                repo.text("rev-parse", "--verify", target_ref) == expected_head,
            )
        ),
        "durable history graph does not reach its head",
    )
    return graph, result.stdout


def _path_change_commits(
    repo: Any,
    graph: Sequence[tuple[str, tuple[str, ...]]],
    graph_input: bytes,
    *,
    pathspec: str,
) -> set[str]:
    result = repo.run(
        "diff-tree",
        "--stdin",
        "-m",
        "--root",
        "--raw",
        "-z",
        "--full-index",
        "--no-renames",
        "-r",
        "--",
        pathspec,
        input_bytes=graph_input,
    )
    known = {commit for commit, _parents in graph}
    changed: set[str] = set()
    current: str | None = None
    tokens = result.stdout.split(b"\0")
    _require(
        bool(tokens) and tokens[-1] == b"",
        "durable history path diff is truncated",
    )
    cursor = 0
    while cursor < len(tokens) - 1:
        token = tokens[cursor]
        if token.startswith(b":"):
            _require(
                current is not None,
                "durable history path diff lacks its commit",
            )
            fields = token.split(b" ")
            _require(
                len(fields) == 5 and fields[0].startswith(b":"),
                "durable history path diff is invalid",
            )
            cursor += 1
            _require(
                cursor < len(tokens) - 1 and bool(tokens[cursor]),
                "durable history path diff is truncated",
            )
            changed.add(current)
            cursor += 1
            continue

        try:
            current = token.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise HistoryValidationError(
                "durable history path diff has a non-ASCII commit"
            ) from exc
        _require(
            current in known,
            "durable history path diff names an unknown commit",
        )
        cursor += 1
    return changed


def retained_publication_commits(
    repo: Any,
    target_ref: str,
    *,
    expected_head: str,
    pathspec: str,
) -> list[str]:
    """Return linear commits that change the retained history path."""

    graph, graph_input = _complete_graph(
        repo,
        target_ref,
        expected_head=expected_head,
    )
    changed = _path_change_commits(
        repo,
        graph,
        graph_input,
        pathspec=pathspec,
    )
    commits: list[str] = []
    for commit, parents in graph:
        if commit not in changed:
            continue
        _require(
            bool(parents),
            "durable retained history cannot be introduced by a root commit",
        )
        _require(
            len(parents) == 1,
            "durable retained history cannot change across a merge",
        )
        commits.append(commit)
    return commits
