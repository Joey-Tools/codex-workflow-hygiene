"""Deterministic bounded files for leased agent claims."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from . import safe_io
from .checkpoints import canonical_json_bytes
from .orchestrator_support import InvalidTransitionError


def artifact_name(
    attempt_ref: str,
    generation: int,
    artifact_kind: str,
) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "artifact_kind": artifact_kind,
                "attempt_ref": attempt_ref,
                "claim_generation": generation,
            }
        )
    ).hexdigest()
    return f"{digest}.json"


def sink_exceeds_budget(
    run_dir: Path,
    attempt: Mapping[str, Any],
    *,
    max_bytes: int,
) -> bool:
    relative = attempt.get("output_sink_relative")
    absolute = attempt.get("output_sink")
    if (
        not isinstance(relative, str)
        or Path(relative).parts[:1] != ("agent-sinks",)
        or len(Path(relative).parts) != 2
        or not isinstance(absolute, str)
        or absolute != str(run_dir / relative)
    ):
        raise InvalidTransitionError("agent result sink binding is invalid")
    try:
        safe_io.read_bounded_bytes(
            run_dir / relative,
            max_bytes=max_bytes,
            require_owner_only=True,
        )
    except FileNotFoundError:
        return False
    except safe_io.ReadLimitExceeded:
        return True
    except (OSError, safe_io.UnsafePathError) as error:
        raise InvalidTransitionError(
            "agent result sink cannot be authenticated"
        ) from error
    return False
