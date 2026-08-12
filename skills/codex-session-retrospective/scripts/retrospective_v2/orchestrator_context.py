"""Runtime context shared by explicitly composed orchestrator components."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from . import sharding
from .checkpoints import AtomicCheckpointStore
from .contracts import RefType
from .identity import IdentityKey


Clock = Callable[[], dt.datetime | str]


class RuntimeContext(Protocol):
    """Data and deterministic helpers available to every component."""

    run_dir: Path
    identity: IdentityKey
    store: AtomicCheckpointStore
    shard_limits: sharding.ShardLimits
    clock: Clock

    def ref(self, kind: RefType, *parts: object) -> str: ...

    def agent_envelope_limit(self) -> int: ...

    def canonical_hosts(self) -> tuple[str, ...]: ...

    def source_transport_max_source_bytes(self) -> int: ...


@dataclass(frozen=True, slots=True)
class OrchestratorContext:
    """Identity-bound state and runtime policy providers for one run."""

    run_dir: Path
    identity: IdentityKey
    store: AtomicCheckpointStore
    shard_limits: sharding.ShardLimits
    clock: Clock
    canonical_hosts_provider: Callable[[], tuple[str, ...]]
    agent_envelope_limit_provider: Callable[[], int]
    source_transport_max_source_bytes_provider: Callable[[], int]

    def ref(self, kind: RefType, *parts: object) -> str:
        return str(self.identity.derive_ref(kind, {"parts": list(parts)}))

    def agent_envelope_limit(self) -> int:
        return self.agent_envelope_limit_provider()

    def canonical_hosts(self) -> tuple[str, ...]:
        return self.canonical_hosts_provider()

    def source_transport_max_source_bytes(self) -> int:
        return self.source_transport_max_source_bytes_provider()


class OrchestratorComponent:
    """Base class exposing only the shared runtime context, not the facade."""

    def __init__(self, context: RuntimeContext) -> None:
        self._context = context

    @property
    def run_dir(self) -> Path:
        return self._context.run_dir

    @property
    def identity(self) -> IdentityKey:
        return self._context.identity

    @property
    def store(self) -> AtomicCheckpointStore:
        return self._context.store

    @property
    def shard_limits(self) -> sharding.ShardLimits:
        return self._context.shard_limits

    @property
    def _clock(self) -> Clock:
        return self._context.clock

    def _ref(self, kind: RefType, *parts: object) -> str:
        return self._context.ref(kind, *parts)

    def _agent_envelope_limit(self) -> int:
        return self._context.agent_envelope_limit()

    def _canonical_hosts(self) -> tuple[str, ...]:
        return self._context.canonical_hosts()

    def _source_transport_max_source_bytes(self) -> int:
        return self._context.source_transport_max_source_bytes()
