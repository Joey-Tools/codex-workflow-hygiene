"""Composition root and facade delegation for orchestrator components."""

from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from types import MappingProxyType
from typing import Any, Mapping, TypeVar

from .orchestrator_context import OrchestratorComponent, RuntimeContext
from .orchestrator_history import ResultHistoryOperations
from .orchestrator_jobs import AgentJobOperations
from .orchestrator_lifecycle import RunLifecycleOperations
from .orchestrator_projection import StateProjectionOperations
from .orchestrator_reduction import HierarchicalReductionOperations
from .orchestrator_scheduler import StageSchedulingOperations
from .orchestrator_source import SourceCoordinationOperations
from .orchestrator_state import CoordinatorStateOperations


class CoordinatorStateComponent(OrchestratorComponent):
    """Context-bound adapter for the stable state operation implementation."""

    _require_retention_active_state = (
        CoordinatorStateOperations._require_retention_active_state
    )
    ensure_retention_active = CoordinatorStateOperations.ensure_retention_active
    load_state = CoordinatorStateOperations.load_state
    _append_gap = CoordinatorStateOperations._append_gap
    _assert_state_identity = CoordinatorStateOperations._assert_state_identity
    _block = CoordinatorStateOperations._block
    _now = CoordinatorStateOperations._now
    _require_stage = staticmethod(CoordinatorStateOperations._require_stage)
    _retention_expired = CoordinatorStateOperations._retention_expired
    _transition = CoordinatorStateOperations._transition
    _validate_ref = CoordinatorStateOperations._validate_ref


@dataclass(frozen=True, slots=True)
class OrchestratorComponents:
    state: CoordinatorStateComponent
    projection: StateProjectionOperations
    jobs: AgentJobOperations
    reduction: HierarchicalReductionOperations
    history: ResultHistoryOperations
    source: SourceCoordinationOperations
    lifecycle: RunLifecycleOperations
    scheduler: StageSchedulingOperations


COMPONENT_METHOD_OWNERS = MappingProxyType(
    {
        "state": CoordinatorStateOperations,
        "projection": StateProjectionOperations,
        "jobs": AgentJobOperations,
        "reduction": HierarchicalReductionOperations,
        "history": ResultHistoryOperations,
        "source": SourceCoordinationOperations,
        "lifecycle": RunLifecycleOperations,
        "scheduler": StageSchedulingOperations,
    }
)


def _declared_methods(component_type: type[Any]) -> tuple[str, ...]:
    return tuple(
        name
        for name, value in vars(component_type).items()
        if name != "__init__"
        and (callable(value) or isinstance(value, (classmethod, staticmethod)))
    )


def _method_component_map() -> Mapping[str, str]:
    result: dict[str, str] = {}
    for component_name, component_type in COMPONENT_METHOD_OWNERS.items():
        for method_name in _declared_methods(component_type):
            prior = result.setdefault(method_name, component_name)
            if prior != component_name:
                raise RuntimeError(
                    f"orchestrator method {method_name!r} has multiple component owners"
                )
    return MappingProxyType(result)


ORCHESTRATOR_METHOD_COMPONENTS = _method_component_map()


def build_orchestrator_components(
    context: RuntimeContext,
) -> OrchestratorComponents:
    """Construct the acyclic component graph from low to high level."""

    state = CoordinatorStateComponent(context)
    projection = StateProjectionOperations(context, state=state)
    jobs = AgentJobOperations(context, projection=projection)
    reduction = HierarchicalReductionOperations(
        context,
        state=state,
        projection=projection,
        jobs=jobs,
    )
    history = ResultHistoryOperations(
        context,
        projection=projection,
        reduction=reduction,
    )
    source = SourceCoordinationOperations(
        context,
        state=state,
        projection=projection,
        jobs=jobs,
        history=history,
    )
    lifecycle = RunLifecycleOperations(
        context,
        state=state,
        projection=projection,
        history=history,
        source=source,
    )
    scheduler = StageSchedulingOperations(
        context,
        state=state,
        projection=projection,
        jobs=jobs,
        reduction=reduction,
        history=history,
        source=source,
        lifecycle=lifecycle,
    )
    return OrchestratorComponents(
        state=state,
        projection=projection,
        jobs=jobs,
        reduction=reduction,
        history=history,
        source=source,
        lifecycle=lifecycle,
        scheduler=scheduler,
    )


class ComponentMethod:
    """Data descriptor preserving the facade API over one explicit component."""

    def __init__(self, component_name: str, method_name: str) -> None:
        self.component_name = component_name
        self.method_name = method_name

    def _component(self, instance: Any) -> Any:
        return getattr(instance._components, self.component_name)

    def __get__(self, instance: Any, owner: type[Any]) -> Any:
        component_type = COMPONENT_METHOD_OWNERS[self.component_name]
        descriptor = vars(component_type)[self.method_name]
        wrapped = getattr(component_type, self.method_name)
        if instance is None:
            if isinstance(descriptor, (classmethod, staticmethod)):
                return wrapped

            @wraps(wrapped)
            def unbound(facade: Any, *args: Any, **kwargs: Any) -> Any:
                return wrapped(self._component(facade), *args, **kwargs)

            return unbound
        return getattr(self._component(instance), self.method_name)

    def __set__(self, instance: Any, value: Any) -> None:
        setattr(self._component(instance), self.method_name, value)

    def __delete__(self, instance: Any) -> None:
        delattr(self._component(instance), self.method_name)


FacadeType = TypeVar("FacadeType", bound=type[Any])


def install_orchestrator_delegates(facade_type: FacadeType) -> FacadeType:
    """Install the complete, fixed method-to-component delegation table."""

    for method_name, component_name in ORCHESTRATOR_METHOD_COMPONENTS.items():
        if method_name in vars(facade_type):
            raise RuntimeError(
                f"facade already defines delegated method {method_name!r}"
            )
        setattr(
            facade_type,
            method_name,
            ComponentMethod(component_name, method_name),
        )
    return facade_type
