from __future__ import annotations

import ast
from collections import defaultdict
import inspect
from pathlib import Path
import sys
import tempfile
from typing import get_type_hints
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "codex-session-retrospective" / "scripts"
PACKAGE = SCRIPTS / "retrospective_v2"
PUBLIC_CLI = SCRIPTS / "session_retrospective_v2.py"
TRANSCRIPT_ADAPTER = SCRIPTS / "session_retrospective_v2_transcript.py"
sys.path.insert(0, str(SCRIPTS))

from retrospective_v2 import (  # noqa: E402
    finalize,
    orchestrator_protocols,
    transport,
    transport_capture,
)
from retrospective_v2.orchestrator import (  # noqa: E402
    RetrospectiveOrchestrator,
)
from retrospective_v2.orchestrator_components import (  # noqa: E402
    COMPONENT_METHOD_OWNERS,
    ORCHESTRATOR_METHOD_COMPONENTS,
    CoordinatorStateComponent,
    OrchestratorComponents,
)
from retrospective_v2.orchestrator_context import (  # noqa: E402
    OrchestratorComponent,
    RuntimeContext,
)
from retrospective_v2.orchestrator_history import (  # noqa: E402
    ResultHistoryOperations,
)
from retrospective_v2.orchestrator_jobs import AgentJobOperations  # noqa: E402
from retrospective_v2.orchestrator_lifecycle import (  # noqa: E402
    RunLifecycleOperations,
)
from retrospective_v2.orchestrator_projection import (  # noqa: E402
    StateProjectionOperations,
)
from retrospective_v2.orchestrator_reduction import (  # noqa: E402
    HierarchicalReductionOperations,
)
from retrospective_v2.orchestrator_scheduler import (  # noqa: E402
    StageSchedulingOperations,
)
from retrospective_v2.orchestrator_source import (  # noqa: E402
    SourceCoordinationOperations,
)
from retrospective_v2.orchestrator_state import (  # noqa: E402
    CoordinatorStateOperations,
)
from retrospective_v2.identity import IdentityKey  # noqa: E402
from retrospective_v2.publication_git import (  # noqa: E402
    LocalGitPublicationAdapter,
)
from retrospective_v2.publication_transaction import (  # noqa: E402
    PublicationTransaction,
)


ORCHESTRATOR_COMPONENTS = (
    RunLifecycleOperations,
    SourceCoordinationOperations,
    StageSchedulingOperations,
    HierarchicalReductionOperations,
    ResultHistoryOperations,
    AgentJobOperations,
    StateProjectionOperations,
    CoordinatorStateOperations,
)

COMPONENT_NAMES = {
    CoordinatorStateOperations: "state",
    StateProjectionOperations: "projection",
    AgentJobOperations: "jobs",
    HierarchicalReductionOperations: "reduction",
    ResultHistoryOperations: "history",
    SourceCoordinationOperations: "source",
    RunLifecycleOperations: "lifecycle",
    StageSchedulingOperations: "scheduler",
}

RUNTIME_COMPONENT_TYPES = {
    "state": CoordinatorStateComponent,
    "projection": StateProjectionOperations,
    "jobs": AgentJobOperations,
    "reduction": HierarchicalReductionOperations,
    "history": ResultHistoryOperations,
    "source": SourceCoordinationOperations,
    "lifecycle": RunLifecycleOperations,
    "scheduler": StageSchedulingOperations,
}

COMPONENT_DEPENDENCIES = {
    "state": {},
    "projection": {"state": "state"},
    "jobs": {"projection": "projection"},
    "reduction": {
        "state": "state",
        "projection": "projection",
        "jobs": "jobs",
    },
    "history": {"projection": "projection", "reduction": "reduction"},
    "source": {
        "state": "state",
        "projection": "projection",
        "jobs": "jobs",
        "history": "history",
    },
    "lifecycle": {
        "state": "state",
        "projection": "projection",
        "history": "history",
        "source": "source",
    },
    "scheduler": {
        "state": "state",
        "projection": "projection",
        "jobs": "jobs",
        "reduction": "reduction",
        "history": "history",
        "source": "source",
        "lifecycle": "lifecycle",
    },
}

COMPONENT_DEPENDENCY_PORTS = {
    StateProjectionOperations: {
        "state": orchestrator_protocols.ProjectionStatePort,
    },
    AgentJobOperations: {
        "projection": orchestrator_protocols.JobsProjectionPort,
    },
    HierarchicalReductionOperations: {
        "state": orchestrator_protocols.ReductionStatePort,
        "projection": orchestrator_protocols.ReductionProjectionPort,
        "jobs": orchestrator_protocols.ReductionJobsPort,
    },
    ResultHistoryOperations: {
        "projection": orchestrator_protocols.HistoryProjectionPort,
        "reduction": orchestrator_protocols.HistoryReductionPort,
    },
    SourceCoordinationOperations: {
        "state": orchestrator_protocols.SourceStatePort,
        "projection": orchestrator_protocols.SourceProjectionPort,
        "jobs": orchestrator_protocols.SourceJobsPort,
        "history": orchestrator_protocols.SourceHistoryPort,
    },
    RunLifecycleOperations: {
        "state": orchestrator_protocols.LifecycleStatePort,
        "projection": orchestrator_protocols.LifecycleProjectionPort,
        "history": orchestrator_protocols.LifecycleHistoryPort,
        "source": orchestrator_protocols.LifecycleSourcePort,
    },
    StageSchedulingOperations: {
        "state": orchestrator_protocols.SchedulerStatePort,
        "projection": orchestrator_protocols.SchedulerProjectionPort,
        "jobs": orchestrator_protocols.SchedulerJobsPort,
        "reduction": orchestrator_protocols.SchedulerReductionPort,
        "history": orchestrator_protocols.SchedulerHistoryPort,
        "source": orchestrator_protocols.SchedulerSourcePort,
        "lifecycle": orchestrator_protocols.SchedulerLifecyclePort,
    },
}

COMPONENT_MODULES = {
    ResultHistoryOperations: "orchestrator_history.py",
    AgentJobOperations: "orchestrator_jobs.py",
    RunLifecycleOperations: "orchestrator_lifecycle.py",
    StateProjectionOperations: "orchestrator_projection.py",
    HierarchicalReductionOperations: "orchestrator_reduction.py",
    StageSchedulingOperations: "orchestrator_scheduler.py",
    SourceCoordinationOperations: "orchestrator_source.py",
    CoordinatorStateOperations: "orchestrator_state.py",
}

COMPONENT_RANK = {
    "orchestrator_state.py": 0,
    "orchestrator_projection.py": 1,
    "orchestrator_jobs.py": 2,
    "orchestrator_reduction.py": 3,
    "orchestrator_history.py": 4,
    "orchestrator_source.py": 5,
    "orchestrator_lifecycle.py": 6,
    "orchestrator_scheduler.py": 7,
}

EXPECTED_CAPABILITY_EDGES = {
    ("orchestrator_history.py", "orchestrator_projection.py"),
    ("orchestrator_history.py", "orchestrator_reduction.py"),
    ("orchestrator_jobs.py", "orchestrator_projection.py"),
    ("orchestrator_lifecycle.py", "orchestrator_history.py"),
    ("orchestrator_lifecycle.py", "orchestrator_projection.py"),
    ("orchestrator_lifecycle.py", "orchestrator_source.py"),
    ("orchestrator_lifecycle.py", "orchestrator_state.py"),
    ("orchestrator_projection.py", "orchestrator_state.py"),
    ("orchestrator_reduction.py", "orchestrator_jobs.py"),
    ("orchestrator_reduction.py", "orchestrator_projection.py"),
    ("orchestrator_reduction.py", "orchestrator_state.py"),
    ("orchestrator_scheduler.py", "orchestrator_history.py"),
    ("orchestrator_scheduler.py", "orchestrator_jobs.py"),
    ("orchestrator_scheduler.py", "orchestrator_lifecycle.py"),
    ("orchestrator_scheduler.py", "orchestrator_projection.py"),
    ("orchestrator_scheduler.py", "orchestrator_reduction.py"),
    ("orchestrator_scheduler.py", "orchestrator_source.py"),
    ("orchestrator_scheduler.py", "orchestrator_state.py"),
    ("orchestrator_source.py", "orchestrator_history.py"),
    ("orchestrator_source.py", "orchestrator_jobs.py"),
    ("orchestrator_source.py", "orchestrator_projection.py"),
    ("orchestrator_source.py", "orchestrator_state.py"),
}

ORCHESTRATOR_OPERATION_MODULES = {
    "orchestrator_history.py",
    "orchestrator_jobs.py",
    "orchestrator_lifecycle.py",
    "orchestrator_projection.py",
    "orchestrator_reduction.py",
    "orchestrator_scheduler.py",
    "orchestrator_source.py",
    "orchestrator_state.py",
}

ORCHESTRATOR_FOUNDATION_MODULES = {
    "orchestrator_components.py",
    "orchestrator_context.py",
    "orchestrator_core.py",
    "orchestrator_protocols.py",
    "orchestrator_support.py",
    "orchestrator_transport.py",
}

ORCHESTRATOR_SOURCE_SUPPORT_MODULES = {
    "agent_claim_artifacts.py",
    "orchestrator_source_segments.py",
    "source_capacity.py",
    "source_inputs.py",
    "source_payloads.py",
}

ORCHESTRATOR_MODULES = (
    ORCHESTRATOR_OPERATION_MODULES
    | ORCHESTRATOR_FOUNDATION_MODULES
    | ORCHESTRATOR_SOURCE_SUPPORT_MODULES
)

PUBLICATION_MODULES = {
    "publication_contracts.py",
    "publication_git.py",
    "publication_git_capacity.py",
    "publication_git_commits.py",
    "publication_git_storage.py",
    "publication_state.py",
    "publication_support.py",
    "publication_transaction.py",
}

TRANSPORT_MODULES = {
    "transport.py",
    "transport_auth.py",
    "transport_capture.py",
    "transport_contracts.py",
    "transport_discovery.py",
    "transport_paths.py",
    "transport_program.py",
    "transport_remote.py",
    "transport_remote_snapshot.py",
    "transport_resume.py",
    "transport_session_shards.py",
    "transport_snapshot.py",
    "transport_source.py",
    "transport_worker.py",
}

TRANSPORT_LINE_INVENTORY = {
    "transport.py": 231,
    "transport_auth.py": 143,
    "transport_capture.py": 999,
    "transport_contracts.py": 999,
    "transport_discovery.py": 240,
    "transport_paths.py": 70,
    "transport_program.py": 408,
    "transport_remote.py": 315,
    "transport_remote_snapshot.py": 79,
    "transport_resume.py": 170,
    "transport_session_shards.py": 1_605,
    "transport_snapshot.py": 196,
    "transport_source.py": 1_700,
    "transport_worker.py": 26,
}
TRANSPORT_AGGREGATE_LINE_LIMIT = 7_200

BOUNDED_MODULE_LINES = {
    "finalize.py": 120,
    "authority.py": 3_250,
    "cleanup_inventory.py": 900,
    "cleanup_sidecars.py": 300,
    "orchestrator.py": 720,
    "orchestrator_components.py": 250,
    "orchestrator_context.py": 180,
    "orchestrator_history.py": 1_000,
    "orchestrator_jobs.py": 500,
    "orchestrator_lifecycle.py": 3_325,
    "orchestrator_projection.py": 1_000,
    "orchestrator_reduction.py": 2_400,
    "orchestrator_scheduler.py": 1_000,
    "orchestrator_source.py": 2_100,
    "orchestrator_source_segments.py": 150,
    "agent_claim_artifacts.py": 100,
    "source_inputs.py": 500,
    "source_payloads.py": 100,
    "source_capacity.py": 150,
    "orchestrator_core.py": 250,
    "orchestrator_protocols.py": 450,
    "orchestrator_support.py": 600,
    "orchestrator_transport.py": 1_100,
    "orchestrator_state.py": 300,
    "publication_contracts.py": 1_350,
    "publication_git.py": 1_100,
    "publication_git_capacity.py": 300,
    "publication_git_commits.py": 1_000,
    "publication_git_storage.py": 800,
    "publication_state.py": 1_250,
    "publication_support.py": 1_300,
    "publication_transaction.py": 2_100,
    "reporting.py": 4_500,
    "result_validation.py": 3_250,
    "transport.py": 250,
    "transport_auth.py": 200,
    "transport_capture.py": 1_000,
    "transport_contracts.py": 1_000,
    "transport_discovery.py": 240,
    "transport_paths.py": 100,
    "transport_program.py": 420,
    "transport_remote.py": 320,
    "transport_remote_snapshot.py": 100,
    "transport_resume.py": 200,
    "transport_session_shards.py": 1_650,
    "transport_snapshot.py": 200,
    "transport_source.py": 1_700,
    "transport_worker.py": 40,
}

TARGETED_FUNCTION_LINES = {
    **{name: 300 for name in PUBLICATION_MODULES},
    **{name: 300 for name in TRANSPORT_MODULES},
    "transport_session_shards.py": 450,
    "transport_source.py": 500,
}

BRANCH_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.BoolOp,
    ast.IfExp,
    ast.comprehension,
)


def module_tree(name: str) -> ast.Module:
    return ast.parse((PACKAGE / name).read_text(encoding="utf-8"), filename=name)


def _normalized_import_name(value: str) -> str:
    return value.lstrip(".").rsplit(".", 1)[-1]


def imports_in_tree(tree: ast.AST) -> set[str]:
    imports: set[str] = set()
    importlib_aliases = {"importlib"}
    builtins_aliases = {"builtins"}
    dynamic_function_aliases = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                if alias.name == "importlib":
                    importlib_aliases.add(bound_name)
                elif alias.name == "builtins":
                    builtins_aliases.add(bound_name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if node.module == "importlib" and alias.name == "import_module":
                    dynamic_function_aliases.add(bound_name)
                elif node.module == "builtins" and alias.name == "__import__":
                    dynamic_function_aliases.add(bound_name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(_normalized_import_name(alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(_normalized_import_name(node.module))
                imports.update(
                    _normalized_import_name(f"{node.module}.{alias.name}")
                    for alias in node.names
                    if alias.name != "*"
                )
            else:
                imports.update(
                    _normalized_import_name(alias.name) for alias in node.names
                )
        elif isinstance(node, ast.Call) and node.args:
            target = node.args[0]
            if not isinstance(target, ast.Constant) or not isinstance(
                target.value, str
            ):
                continue
            dynamic = (
                isinstance(node.func, ast.Name)
                and node.func.id in dynamic_function_aliases
            )
            dynamic = dynamic or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in importlib_aliases
            )
            dynamic = dynamic or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "__import__"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in builtins_aliases
            )
            if dynamic:
                imports.add(_normalized_import_name(target.value))
    return imports


def module_imports(name: str) -> set[str]:
    return imports_in_tree(module_tree(name))


def dynamic_loading_primitives(tree: ast.AST) -> set[str]:
    forbidden_calls = {
        "__import__",
        "exec_module",
        "import_module",
        "module_from_spec",
        "spec_from_file_location",
    }
    function_aliases = {"__import__"}
    findings: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"builtins", "importlib", "importlib.util"}:
                    findings.add(f"import:{alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module in {"builtins", "importlib", "importlib.util"}:
                findings.add(f"from:{node.module}")
                function_aliases.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name in forbidden_calls
                )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in function_aliases:
                findings.add(f"call:{node.func.id}")
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in forbidden_calls
            ):
                findings.add(f"call:{node.func.attr}")
    return findings


class ModuleBoundaryTests(unittest.TestCase):
    def test_orchestrator_facade_uses_explicit_composition(self) -> None:
        self.assertEqual((object,), RetrospectiveOrchestrator.__bases__)
        self.assertNotIn("__getattr__", vars(RetrospectiveOrchestrator))
        self.assertNotIn("__getattribute__", vars(RetrospectiveOrchestrator))
        direct_methods = {
            node.name
            for node in next(
                node
                for node in module_tree("orchestrator.py").body
                if isinstance(node, ast.ClassDef)
                and node.name == "RetrospectiveOrchestrator"
            ).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertEqual(
            direct_methods,
            {
                "__init__",
                "_agent_envelope_limit",
                "_canonical_hosts",
                "_clock",
                "_ref",
                "_source_transport_max_source_bytes",
                "doctor",
                "identity",
                "run_dir",
                "shard_limits",
                "store",
            },
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            identity = IdentityKey.create(root / "identity-v2.key")
            facade = RetrospectiveOrchestrator(root / "run", identity=identity)
            components = facade._components
            self.assertIsInstance(components, OrchestratorComponents)
            for name, expected_type in RUNTIME_COMPONENT_TYPES.items():
                component = getattr(components, name)
                self.assertIsInstance(component, expected_type)
                self.assertIs(component._context, facade._context)
                self.assertNotIn(facade, vars(component).values())
                expected_fields = {
                    "_context",
                    *(f"_{dependency}" for dependency in COMPONENT_DEPENDENCIES[name]),
                }
                self.assertEqual(expected_fields, set(vars(component)))
                for dependency, target in COMPONENT_DEPENDENCIES[name].items():
                    self.assertIs(
                        getattr(component, f"_{dependency}"),
                        getattr(components, target),
                    )

    def test_orchestrator_methods_have_one_component_owner(self) -> None:
        anchors = {
            "start": "lifecycle",
            "accept_source": "source",
            "advance": "scheduler",
            "_construct_episode_revisions": "reduction",
            "_build_retained_export": "history",
            "_status_view": "projection",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            identity = IdentityKey.create(root / "identity-v2.key")
            facade = RetrospectiveOrchestrator(root / "run", identity=identity)
            for method_name, owner in anchors.items():
                with self.subTest(method_name=method_name):
                    self.assertEqual(
                        owner,
                        ORCHESTRATOR_METHOD_COMPONENTS[method_name],
                    )
                    self.assertIs(
                        getattr(facade, method_name).__self__,
                        getattr(facade._components, owner),
                    )

        owned_methods: set[str] = set()
        for component in ORCHESTRATOR_COMPONENTS:
            component_methods = {
                name
                for name, value in component.__dict__.items()
                if name != "__init__"
                and (callable(value) or isinstance(value, (classmethod, staticmethod)))
            }
            self.assertTrue(component_methods)
            self.assertFalse(owned_methods & component_methods)
            owned_methods.update(component_methods)
        self.assertEqual(owned_methods, set(ORCHESTRATOR_METHOD_COMPONENTS))
        self.assertEqual(set(RUNTIME_COMPONENT_TYPES), set(COMPONENT_METHOD_OWNERS))
        for name, owner in COMPONENT_METHOD_OWNERS.items():
            self.assertEqual(name, COMPONENT_NAMES[owner])

    def test_operation_modules_do_not_import_each_other_or_the_facade(self) -> None:
        operation_names = {
            name.removesuffix(".py") for name in ORCHESTRATOR_OPERATION_MODULES
        }
        for name in ORCHESTRATOR_OPERATION_MODULES:
            imports = module_imports(name)
            with self.subTest(module=name):
                self.assertNotIn("orchestrator", imports)
                self.assertNotIn("orchestrator_components", imports)
                self.assertFalse(
                    imports & (operation_names - {name.removesuffix(".py")})
                )
                if name == "orchestrator_state.py":
                    self.assertEqual(
                        {"orchestrator_core"},
                        imports
                        & {
                            "orchestrator_context",
                            "orchestrator_core",
                            "orchestrator_protocols",
                            "orchestrator_support",
                        },
                    )
                else:
                    self.assertEqual(
                        {
                            "orchestrator_context",
                            "orchestrator_protocols",
                            "orchestrator_support",
                        },
                        imports
                        & {
                            "orchestrator_context",
                            "orchestrator_core",
                            "orchestrator_protocols",
                            "orchestrator_support",
                        },
                    )

        composition_imports = module_imports("orchestrator_components.py")
        self.assertEqual(operation_names, composition_imports & operation_names)
        self.assertIn("orchestrator_context", composition_imports)
        for name in ("orchestrator_context.py", "orchestrator_protocols.py"):
            with self.subTest(foundation=name):
                self.assertFalse(module_imports(name) & operation_names)

    def test_low_level_state_dependencies_do_not_reach_high_level_services(
        self,
    ) -> None:
        forbidden = {
            "finalize",
            "orchestrator_support",
            "orchestrator_transport",
            "result_validation",
            "sharding",
            "transport",
        }
        self.assertFalse(module_imports("orchestrator_core.py") & forbidden)
        self.assertFalse(module_imports("orchestrator_state.py") & forbidden)
        self.assertFalse(module_imports("controlled_gaps.py") & forbidden)
        self.assertIn(
            "transport_contracts",
            module_imports("controlled_gaps.py"),
        )

    def test_nested_and_constant_dynamic_imports_cannot_escape_boundaries(self) -> None:
        fixture = ast.parse(
            """
try:
    from . import orchestrator_source
except ImportError:
    pass

from retrospective_v2 import orchestrator_jobs
from retrospective_v2 import orchestrator_state as hidden_state

def load_history():
    import retrospective_v2.orchestrator_history

class Deferred:
    from .orchestrator_scheduler import StageSchedulingOperations

import importlib as importlib_alias
from importlib import import_module
from importlib import import_module as dynamic_import
import builtins
import builtins as builtins_alias
from builtins import __import__ as builtin_import

dynamic_reduction = importlib_alias.import_module(
    ".orchestrator_reduction", "retrospective_v2"
)
dynamic_lifecycle = __import__("retrospective_v2.orchestrator_lifecycle")
dynamic_projection = import_module("retrospective_v2.orchestrator_projection")
dynamic_scheduler = dynamic_import("retrospective_v2.orchestrator_scheduler")
dynamic_source = builtins.__import__("retrospective_v2.orchestrator_source")
dynamic_history = builtins_alias.__import__(
    "retrospective_v2.orchestrator_history"
)
dynamic_state = builtin_import("retrospective_v2.orchestrator_state")
"""
        )
        self.assertTrue(
            {
                "orchestrator_history",
                "orchestrator_jobs",
                "orchestrator_lifecycle",
                "orchestrator_projection",
                "orchestrator_reduction",
                "orchestrator_scheduler",
                "orchestrator_source",
                "orchestrator_state",
            }.issubset(imports_in_tree(fixture))
        )

    def test_publication_boundary_forbids_all_dynamic_loading_primitives(self) -> None:
        fixture = ast.parse(
            """
import importlib as loader
import importlib.util as loader_util
import builtins as runtime
from importlib import import_module as load_module
from builtins import __import__ as load_builtin

loader.import_module("retrospective_v2.export")
load_module("retrospective_v2.reporting")
runtime.__import__("retrospective_v2.export")
load_builtin("retrospective_v2.reporting")
spec = loader_util.spec_from_file_location("export", "export.py")
module = loader_util.module_from_spec(spec)
spec.loader.exec_module(module)
"""
        )
        self.assertTrue(dynamic_loading_primitives(fixture))
        for name in PUBLICATION_MODULES:
            with self.subTest(module=name):
                self.assertEqual(set(), dynamic_loading_primitives(module_tree(name)))

    def test_capability_call_graph_is_explicit_and_acyclic(self) -> None:
        owners: dict[str, str] = {}
        class_nodes: dict[str, ast.ClassDef] = {}
        for component, module in COMPONENT_MODULES.items():
            class_node = next(
                node
                for node in module_tree(module).body
                if isinstance(node, ast.ClassDef) and node.name == component.__name__
            )
            class_nodes[module] = class_node
            for node in class_node.body:
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name != "__init__"
                ):
                    self.assertNotIn(node.name, owners)
                    owners[node.name] = module

        dependency_modules = {
            f"_{name}": COMPONENT_MODULES[component]
            for component, name in COMPONENT_NAMES.items()
        }
        edges: set[tuple[str, str]] = set()
        capabilities: dict[tuple[str, str], set[str]] = defaultdict(set)
        implicit_calls: list[tuple[str, str, str]] = []
        for caller, class_node in class_nodes.items():
            for method in class_node.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(method):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "self"
                    ):
                        callee = owners.get(node.func.attr)
                        if callee is not None and callee != caller:
                            implicit_calls.append((caller, callee, node.func.attr))
                    if (
                        isinstance(node, ast.Attribute)
                        and isinstance(node.value, ast.Attribute)
                        and isinstance(node.value.value, ast.Name)
                        and node.value.value.id == "self"
                        and node.value.attr in dependency_modules
                    ):
                        dependency = node.value.attr
                        callee = dependency_modules[dependency]
                        if callee != caller:
                            edges.add((caller, callee))
                            capabilities[(caller, dependency)].add(node.attr)

        self.assertEqual([], implicit_calls)
        self.assertEqual(EXPECTED_CAPABILITY_EDGES, edges)
        for caller, callee in edges:
            with self.subTest(caller=caller, callee=callee):
                self.assertGreater(COMPONENT_RANK[caller], COMPONENT_RANK[callee])

        expected_ports = {
            (COMPONENT_MODULES[component], f"_{dependency}"): protocol
            for component, dependencies in COMPONENT_DEPENDENCY_PORTS.items()
            for dependency, protocol in dependencies.items()
        }
        self.assertEqual(set(expected_ports), set(capabilities))
        for edge, protocol in expected_ports.items():
            protocol_capabilities = set(getattr(protocol, "__annotations__", {}))
            protocol_capabilities.update(
                name
                for name, value in vars(protocol).items()
                if not name.startswith("__") and callable(value)
            )
            with self.subTest(edge=edge, protocol=protocol.__name__):
                self.assertEqual(protocol_capabilities, capabilities[edge])

    def test_components_require_context_and_narrow_dependency_ports(self) -> None:
        for component, dependencies in COMPONENT_DEPENDENCY_PORTS.items():
            with self.subTest(component=component.__name__):
                self.assertEqual((OrchestratorComponent,), component.__bases__)
                signature = inspect.signature(component.__init__)
                self.assertEqual(
                    {"self", "context", *dependencies},
                    set(signature.parameters),
                )
                self.assertIs(
                    get_type_hints(component.__init__)["context"],
                    RuntimeContext,
                )
                for dependency, protocol in dependencies.items():
                    self.assertEqual(
                        inspect.Parameter.KEYWORD_ONLY,
                        signature.parameters[dependency].kind,
                    )
                    self.assertIs(
                        get_type_hints(component.__init__)[dependency],
                        protocol,
                    )

        self.assertEqual(
            (OrchestratorComponent,),
            CoordinatorStateComponent.__bases__,
        )
        self.assertEqual(
            {"self", "context"},
            set(inspect.signature(CoordinatorStateComponent.__init__).parameters),
        )

    def test_projection_methods_do_not_mutate_coordinator_state(self) -> None:
        projection = next(
            node
            for node in module_tree("orchestrator_projection.py").body
            if isinstance(node, ast.ClassDef)
            and node.name == StateProjectionOperations.__name__
        )

        def root_name(node: ast.AST) -> str | None:
            while isinstance(node, (ast.Attribute, ast.Subscript)):
                node = node.value
            return node.id if isinstance(node, ast.Name) else None

        for method in projection.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(method):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    self.assertFalse(
                        any(
                            isinstance(target, (ast.Attribute, ast.Subscript))
                            and root_name(target) == "state"
                            for target in targets
                        ),
                        f"{method.name} mutates coordinator state",
                    )

    def test_publication_facade_preserves_concrete_interface_identity(self) -> None:
        self.assertIs(finalize.PublicationTransaction, PublicationTransaction)
        self.assertIs(finalize.LocalGitPublicationAdapter, LocalGitPublicationAdapter)
        facade_definitions = {
            type(node).__name__
            for node in module_tree("finalize.py").body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertFalse(facade_definitions)

    def test_transport_relay_validation_helpers_have_capture_owner(self) -> None:
        helper_names = {
            "_source_transport_validation_lease",
            "_validate_source_transport_relay",
        }
        capture_definitions = {
            node.name
            for node in module_tree("transport_capture.py").body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        source_definitions = {
            node.name
            for node in module_tree("transport_source.py").body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertLessEqual(helper_names, capture_definitions)
        self.assertTrue(helper_names.isdisjoint(source_definitions))
        for name in helper_names:
            with self.subTest(helper=name):
                self.assertIs(
                    getattr(transport, name), getattr(transport_capture, name)
                )

    def test_only_stable_facades_publish_wildcard_interfaces(self) -> None:
        declared = {
            path.name
            for path in PACKAGE.glob("*.py")
            if any(
                isinstance(node, (ast.Assign, ast.AnnAssign))
                and any(
                    isinstance(target, ast.Name) and target.id == "__all__"
                    for target in (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                )
                for node in module_tree(path.name).body
            )
        }
        self.assertEqual({"__init__.py", "finalize.py", "orchestrator.py"}, declared)

    def test_publication_layers_do_not_depend_on_each_other(self) -> None:
        self.assertNotIn(
            "publication_git",
            module_imports("publication_transaction.py"),
        )
        self.assertNotIn(
            "publication_transaction",
            module_imports("publication_git.py"),
        )
        support_imports = module_imports("publication_support.py")
        self.assertFalse(
            support_imports
            & {
                "finalize",
                "publication_git",
                "publication_git_commits",
                "publication_git_storage",
                "publication_transaction",
            }
        )
        self.assertFalse(
            module_imports("publication_contracts.py")
            & (PUBLICATION_MODULES - {"publication_contracts.py"})
        )
        self.assertEqual(
            {"publication_contracts"},
            module_imports("publication_state.py")
            & {name.removesuffix(".py") for name in PUBLICATION_MODULES},
        )
        for name in (
            "publication_git_capacity.py",
            "publication_git_commits.py",
            "publication_git_storage.py",
        ):
            with self.subTest(module=name):
                self.assertFalse(
                    module_imports(name)
                    & {"publication_git", "publication_transaction"}
                )

    def test_engine_modules_remain_bounded(self) -> None:
        paths = tuple(PACKAGE.glob("*.py"))
        self.assertLessEqual(
            sum(
                len((PACKAGE / name).read_text(encoding="utf-8").splitlines())
                for name in PUBLICATION_MODULES
            ),
            8_600,
        )
        self.assertLessEqual(
            sum(
                len((PACKAGE / name).read_text(encoding="utf-8").splitlines())
                for name in ORCHESTRATOR_FOUNDATION_MODULES
            ),
            2_300,
        )
        self.assertLessEqual(
            sum(
                len((PACKAGE / name).read_text(encoding="utf-8").splitlines())
                for name in {
                    "orchestrator_source.py",
                    *ORCHESTRATOR_SOURCE_SUPPORT_MODULES,
                }
            ),
            3_000,
        )
        self.assertLessEqual(
            len((SCRIPTS / "session_retrospective_v2.py").read_text().splitlines()),
            1_950,
        )
        self.assertLessEqual(
            len(TRANSCRIPT_ADAPTER.read_text(encoding="utf-8").splitlines()),
            250,
        )
        for path in paths:
            with self.subTest(module=path.name):
                self.assertLessEqual(
                    len(path.read_text(encoding="utf-8").splitlines()),
                    5_000,
                    f"{path.name} must be split before it becomes another monolith",
                )
        for name, limit in BOUNDED_MODULE_LINES.items():
            with self.subTest(module=name):
                self.assertLessEqual(
                    len((PACKAGE / name).read_text(encoding="utf-8").splitlines()),
                    limit,
                )
        for name in TRANSPORT_MODULES:
            with self.subTest(transport_module=name):
                self.assertLessEqual(
                    len((PACKAGE / name).read_text(encoding="utf-8").splitlines()),
                    2_000,
                )

    def test_transport_inventory_and_aggregate_budget_are_exact(self) -> None:
        observed = {
            name: len((PACKAGE / name).read_text(encoding="utf-8").splitlines())
            for name in sorted(TRANSPORT_MODULES)
        }
        self.assertEqual(TRANSPORT_MODULES, set(TRANSPORT_LINE_INVENTORY))
        self.assertEqual(TRANSPORT_LINE_INVENTORY, observed)
        self.assertEqual(7_181, sum(observed.values()))
        self.assertLessEqual(
            sum(observed.values()),
            TRANSPORT_AGGREGATE_LINE_LIMIT,
        )

    def test_engine_function_complexity_and_duplication_remain_bounded(self) -> None:
        duplicate_bodies: dict[str, list[str]] = defaultdict(list)
        branch_total = 0
        functions_over_200 = 0
        sliced_functions_over_200 = 0
        for path in PACKAGE.glob("*.py"):
            tree = module_tree(path.name)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                line_count = node.end_lineno - node.lineno + 1
                self.assertLessEqual(
                    line_count,
                    500,
                    f"{path.name}:{node.lineno} exceeds the function-size gate",
                )
                targeted_limit = TARGETED_FUNCTION_LINES.get(path.name)
                if targeted_limit is not None:
                    self.assertLessEqual(
                        line_count,
                        targeted_limit,
                        f"{path.name}:{node.lineno} exceeds its sliced-module gate",
                    )
                branch_total += sum(
                    isinstance(child, BRANCH_NODES) for child in ast.walk(node)
                )
                functions_over_200 += line_count > 200
                sliced_functions_over_200 += (
                    path.name in TARGETED_FUNCTION_LINES and line_count > 200
                )
                if line_count >= 8:
                    body = ast.dump(
                        ast.Module(body=node.body, type_ignores=[]),
                        annotate_fields=True,
                    )
                    duplicate_bodies[body].append(
                        f"{path.name}:{node.lineno}:{node.name}"
                    )
        duplicates = [owners for owners in duplicate_bodies.values() if len(owners) > 1]
        self.assertEqual([], duplicates)
        self.assertLessEqual(branch_total, 7_955)
        self.assertLessEqual(functions_over_200, 20)
        self.assertLessEqual(sliced_functions_over_200, 3)

    def test_public_cli_exposes_exactly_eight_top_level_verbs(self) -> None:
        tree = ast.parse(PUBLIC_CLI.read_text(encoding="utf-8"))
        build_parser = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "build_parser"
        )
        verbs = {
            node.args[0].value
            for node in ast.walk(build_parser)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_parser"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }
        self.assertEqual(
            {
                "accept-agent-result",
                "accept-source",
                "advance",
                "doctor",
                "export",
                "finalize",
                "start",
                "status",
            },
            verbs,
        )
        self.assertFalse(hasattr(transport, "source_transport_cli"))

    def test_transport_worker_manifest_is_minimal_and_reachability_closed(self) -> None:
        manifest = tuple(transport.SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST)
        self.assertEqual(manifest, transport.SOURCE_TRANSPORT_PROGRAM_MODULE_ALLOWLIST)
        self.assertEqual(len(manifest), len(set(manifest)))
        self.assertLessEqual(len(manifest), 13)
        self.assertNotIn("reporting.py", manifest)
        self.assertFalse(set(manifest) & PUBLICATION_MODULES)
        self.assertFalse(set(manifest) & ORCHESTRATOR_MODULES)

        local_modules = {path.stem for path in PACKAGE.glob("*.py")}
        manifest_modules = {name.removesuffix(".py") for name in manifest}
        reachable = {"transport_worker"}
        pending = ["transport_worker"]
        while pending:
            module = pending.pop()
            dependencies = module_imports(f"{module}.py") & local_modules
            for dependency in dependencies - reachable:
                reachable.add(dependency)
                pending.append(dependency)
        self.assertEqual(manifest_modules, reachable)

        for name in manifest:
            with self.subTest(module=name):
                local_dependencies = module_imports(name) & local_modules
                self.assertLessEqual(local_dependencies, manifest_modules)
                self.assertEqual(set(), dynamic_loading_primitives(module_tree(name)))


if __name__ == "__main__":
    unittest.main()
