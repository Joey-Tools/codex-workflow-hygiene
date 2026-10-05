from __future__ import annotations

import re
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = REPO_ROOT / ".github/workflows/codex-review-gate-controller.yml"
VERIFIER = REPO_ROOT / ".github/workflows/codex-review-gate.yml"


class ReviewGateControllerTests(unittest.TestCase):
    def test_workflow_run_completion_uses_only_the_canonical_verifier(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        guard = workflow.split("    if: >-\n", 1)[1].split("    runs-on:", 1)[0]

        for contract in (
            "  workflow_run:\n    workflows: [Codex Review Gate Verifier]\n    types: [completed]",
            "github.event.action == 'completed'",
            "github.event.workflow_run.path == '.github/workflows/codex-review-gate.yml'",
            "startsWith(github.event.workflow_run.path, '.github/workflows/codex-review-gate.yml@')",
            "github.event.workflow_run.event == 'pull_request'",
            "!github.event.workflow_run.pull_requests[1]",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, workflow if contract.startswith("  workflow_run:") else guard)

        for legacy_review_only_condition in (
            "vars.CODEX_REVIEW_GATE_AUTO_REQUEST",
            "github.event.workflow_run.run_attempt",
            "github.event.workflow_run.conclusion",
            "github.event.workflow_run.pull_requests[0].number",
        ):
            with self.subTest(legacy_review_only_condition=legacy_review_only_condition):
                self.assertNotIn(legacy_review_only_condition, guard)

    def test_lookalike_verifier_workflow_paths_are_not_admitted(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        guard = workflow.split("    if: >-\n", 1)[1].split("    runs-on:", 1)[0]
        exact_paths = re.findall(r"github\.event\.workflow_run\.path == '([^']+)'", guard)
        path_prefixes = re.findall(
            r"startsWith\(github\.event\.workflow_run\.path, '([^']+)'\)", guard
        )

        self.assertEqual(exact_paths, [".github/workflows/codex-review-gate.yml"])
        self.assertEqual(path_prefixes, [".github/workflows/codex-review-gate.yml@"])

        def admitted(path: str) -> bool:
            return path in exact_paths or any(path.startswith(prefix) for prefix in path_prefixes)

        self.assertTrue(admitted(".github/workflows/codex-review-gate.yml"))
        self.assertTrue(admitted(".github/workflows/codex-review-gate.yml@refs/heads/main"))
        self.assertFalse(admitted(".github/workflows/codex-review-gate.yml.backup"))
        self.assertFalse(admitted(".github/workflows/other.yml"))

    def test_completion_without_association_uses_safe_pull_request_fallback(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        pr_number_input = next(
            line.strip()
            for line in workflow.splitlines()
            if line.startswith("          pr_number: ")
        )

        self.assertIn(
            "github.event.workflow_run.pull_requests[0].number || '0'",
            pr_number_input,
        )

    def test_auto_request_remains_opt_in_and_failure_specific(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        operation_input = next(
            line.strip()
            for line in workflow.splitlines()
            if line.startswith("          operation: ")
        )
        request_review_input = next(
            line.strip()
            for line in workflow.splitlines()
            if line.startswith("          request_review: ")
        )

        for legacy_auto_request_condition in (
            "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true'",
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.conclusion == 'failure'",
            "github.event.workflow_run.pull_requests[0].number",
            "!github.event.workflow_run.pull_requests[1]",
        ):
            with self.subTest(legacy_auto_request_condition=legacy_auto_request_condition):
                self.assertIn(legacy_auto_request_condition, operation_input)
                self.assertIn(legacy_auto_request_condition, request_review_input)

        self.assertIn(
            "&& 'begin-review' || github.event_name == 'workflow_run' && 'report-completion'",
            operation_input,
        )
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && inputs.request_review || false",
            request_review_input,
        )


class RequiredGateContractTests(unittest.TestCase):
    """The controller remains a runner, not a replacement gate authority."""

    def test_controller_does_not_change_required_verifier_or_write_permissions(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        verifier = VERIFIER.read_text(encoding="utf-8")
        permissions = workflow.split("permissions:\n", 1)[1].split("\n\nconcurrency:", 1)[0]

        self.assertEqual(
            permissions,
            "  actions: write\n  checks: read\n  contents: read\n  pull-requests: write",
        )
        self.assertIn("workflows: [Codex Review Gate Verifier]", workflow)
        self.assertIn("name: Codex Review Gate Verifier", verifier)
        self.assertIn("    name: codex/github-review-gate", verifier)
        self.assertIn("uses: JoeyTeng/codex-review-gate-action@v2", verifier)
        self.assertIn("operation: reconcile", verifier)
        self.assertIn("request_review: false", verifier)


if __name__ == "__main__":
    unittest.main()
