#!/usr/bin/env python3
"""Private executable boundary for authenticated v2 source transport leases."""

from __future__ import annotations

from pathlib import Path
import sys


snapshot = getattr(sys, "_retrospective_v2_transport_snapshot", None)
if __name__ == "__main__" and (
    not isinstance(snapshot, str)
    or not snapshot.startswith("sha256:")
    or len(snapshot) != 71
):
    raise SystemExit("source transport worker requires a committed program snapshot")

WORKER_ROOT = Path(__file__).resolve().parent
if str(WORKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_ROOT))

from transport_source import _run_private_transport_worker  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(_run_private_transport_worker())
