from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "codex-session-retrospective" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import session_retrospective_v2 as cli  # noqa: E402
from retrospective_v2 import authority  # noqa: E402
from retrospective_v2.contracts import (  # noqa: E402
    RefType,
    RunMode,
    RunStage,
    SourceKind,
)
from retrospective_v2.identity import IdentityKey  # noqa: E402
from retrospective_v2.orchestrator import RetrospectiveOrchestrator  # noqa: E402
from retrospective_v2 import reporting  # noqa: E402
from retrospective_v2 import safe_io  # noqa: E402
from tests.test_retrospective_v2_orchestrator import (  # noqa: E402
    activity_manifest,
    authenticated_receipt,
    execution_provenance,
    no_activity_manifest,
)


WINDOW_START = "2026-07-06T00:00:00Z"
WINDOW_END = "2026-07-07T00:00:00Z"


class CliContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.identity_path = self.root / "identity-v2.key"
        self.identity = IdentityKey.create(self.identity_path)
        self.default_identity = self.root / "default-identity-v2.key"
        self.run_dir = self.root / "run"
        self.history_repo = self.root / "history"
        self.run_config = self.root / "run-config-v2.json"
        self.run_config.write_text(
            json.dumps(
                execution_provenance(),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoding="ascii",
        )
        os.chmod(self.run_config, 0o600)
        self.parser = cli.build_parser()
        self.history_state = authority.DurableHistoryState(
            head_commit="a" * 40,
            publication_commit=None,
            identity_key_id=self.identity.key_id,
            provider_revision=0,
            cursor_root_ref=authority.EMPTY_CURSOR_ROOT_REF,
            episode_head_root_ref=authority.derive_episode_head_root(
                (), identity=self.identity
            ),
            cursor_rows=(),
            episode_heads=(),
            episode_membership=(),
        )
        self.authority_patches = [
            mock.patch(
                "retrospective_v2.orchestrator.authority.load_durable_history",
                return_value=self.history_state,
            ),
            mock.patch(
                "retrospective_v2.orchestrator.authority.assert_provider_cache_matches",
                return_value={},
            ),
            mock.patch(
                "retrospective_v2.orchestrator.authority.load_production_marker",
                return_value={"authentication_tag": "test"},
            ),
        ]
        for patcher in self.authority_patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.authority_patches):
            patcher.stop()
        self.temporary.cleanup()

    def parse_dispatch(self, *arguments: str) -> cli.CommandResult:
        return cli.dispatch(self.parser.parse_args(arguments))

    def shadow_start_arguments(self) -> tuple[str, ...]:
        return (
            "start",
            "--shadow",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--mode",
            "daily",
            "--start",
            "2026-07-06T00:00:00Z",
            "--end",
            "2026-07-07T00:00:00Z",
            "--run-dir",
            str(self.run_dir),
            "--run-config",
            str(self.run_config),
            "--history-repo",
            str(self.history_repo),
            "--history-target-ref",
            "refs/heads/main",
        )

    def write_automation_record(
        self,
        automation_id: str,
        mode: str,
        *,
        prompt_suffix: str = "",
        reference_only: bool = False,
    ) -> Path:
        record_dir = self.root / ".codex" / "automations" / automation_id
        record_dir.mkdir(parents=True, exist_ok=True)
        schedule = "FREQ=DAILY;BYHOUR=3" if mode == "daily" else "FREQ=WEEKLY;BYDAY=MO"
        prompt = (
            f"Run python3 {authority.installed_v2_cli_path()} start --mode {mode} "
            f"for the exact production window.{prompt_suffix}"
        )
        fields = [
            "version = 1",
            f'id = "{automation_id}"',
            'kind = "cron"',
            f'name = "Session Retrospective {mode.title()}"',
            f"prompt = {json.dumps(prompt)}",
            'status = "ACTIVE"',
            f'rrule = "{schedule}"',
        ]
        if reference_only:
            fields.append("reference_only = true")
        record = record_dir / "automation.toml"
        record.write_text("\n".join(fields) + "\n", encoding="utf-8")
        return record

    def automation_root(self) -> Path:
        root = self.root / ".codex" / "automations"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        return root

    def capture_cutover_snapshot(self, name: str) -> dict[str, object]:
        return authority.capture_automation_cutover_snapshot(
            self.root / f"{name}-pre-update.json",
            identity=self.identity,
            automation_root=self.automation_root(),
        )

    def automation_result(
        self,
        snapshot: dict[str, object],
        *,
        available: bool = True,
        operations: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        if operations is None:
            operations = [
                {
                    "automation_id": row["automation_id"],
                    "operation": ("register" if row["state"] == "absent" else "update"),
                    "previous_record_sha256": row["record_sha256"],
                    "record_sha256": hashlib.sha256(
                        Path(str(row["record_path"])).read_bytes()
                    ).hexdigest(),
                    "status": "success",
                }
                for row in snapshot["automation_records"]
            ]
        return {
            "available": available,
            "capability": "automation_update",
            "operations": operations,
            "pre_update_snapshot_ref": snapshot["snapshot_ref"],
            "schema": authority.AUTOMATION_UPDATE_RESULT_SCHEMA,
        }

    def real_coordinator(
        self,
        run_dir: Path,
        *,
        activity: bool,
    ) -> RetrospectiveOrchestrator:
        coordinator = RetrospectiveOrchestrator(
            run_dir,
            identity_path=self.identity_path,
        )
        coordinator.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=WINDOW_END,
            shadow=True,
            provenance=execution_provenance(),
            history_repo=self.history_repo,
            history_target_ref="refs/heads/main",
            created_at="2026-07-14T12:00:00Z",
        )
        payload = b'{"timestamp":"2026-07-06T01:00:00Z","text":"work"}\n'
        for _ in range(32):
            status = coordinator.status()
            if status["stage"] != RunStage.SOURCE_CATALOG.value:
                break
            leases = status["active_source_leases"]
            if not leases:
                coordinator.advance()
                continue
            for lease in leases:
                if activity and lease["source_kind"] == SourceKind.ACTIVE_ROLLOUT.value:
                    manifest, records, _source_ref = activity_manifest(lease, [payload])
                    raw_records = {records[0].unit_ref: payload}
                else:
                    manifest = no_activity_manifest(lease)
                    raw_records = None
                coordinator.accept_source(
                    lease["lease_ref"],
                    manifest.to_dict(),
                    transport_receipt=authenticated_receipt(
                        coordinator,
                        lease,
                        manifest,
                        raw_records=raw_records,
                    ),
                    raw_records=raw_records,
                )
        else:
            self.fail("source catalog did not stabilize")
        coordinator.advance()
        return coordinator

    def test_exact_native_command_surface_excludes_lifecycle_control(self) -> None:
        subparsers = next(
            action
            for action in self.parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
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
            set(subparsers.choices),
        )
        for removed in (
            "bootstrap",
            "campaign-abort",
            "claim-agent-job",
            "cutover-record",
            "cutover-acquire",
            "holdout-host",
            "identity-init",
            "prepare-source",
        ):
            with self.subTest(command=removed):
                with self.assertRaises(cli.CliContractError):
                    self.parser.parse_args([removed])

    def test_cutover_record_accepts_exact_registration_and_verified_update(
        self,
    ) -> None:
        automation_root = self.automation_root()
        registration_snapshot = self.capture_cutover_snapshot("registration")
        for automation_id, mode in authority.STABLE_AUTOMATION_MODES.items():
            self.write_automation_record(automation_id, mode)
        record_path = self.root / "automation-cutover-v2.json"
        registered = authority.issue_automation_cutover_record(
            record_path,
            identity=self.identity,
            capability_result=self.automation_result(registration_snapshot),
            pre_update_snapshot=registration_snapshot,
            installed_commit="a" * 40,
            automation_root=automation_root,
        )
        self.assertTrue(registered["cutover_ready"])
        self.assertEqual(
            sorted(authority.STABLE_AUTOMATION_MODES),
            [item["automation_id"] for item in registered["automation_records"]],
        )
        update_snapshot = self.capture_cutover_snapshot("update")
        for automation_id, mode in authority.STABLE_AUTOMATION_MODES.items():
            self.write_automation_record(
                automation_id,
                mode,
                prompt_suffix=" Updated by the verified cutover coordinator.",
            )
        updated = authority.issue_automation_cutover_record(
            record_path,
            identity=self.identity,
            capability_result=self.automation_result(update_snapshot),
            pre_update_snapshot=update_snapshot,
            installed_commit="a" * 40,
            automation_root=automation_root,
        )
        self.assertTrue(
            all(item["operation"] == "update" for item in updated["automation_records"])
        )
        self.assertEqual(
            updated,
            authority.load_automation_cutover_record(
                record_path,
                identity=self.identity,
            ),
        )

    def test_cutover_record_fails_closed_without_capability_or_for_unrelated_id(
        self,
    ) -> None:
        automation_root = self.automation_root()
        registration_snapshot = self.capture_cutover_snapshot("blocked-registration")
        for automation_id, mode in authority.STABLE_AUTOMATION_MODES.items():
            self.write_automation_record(automation_id, mode)
        output = self.root / "blocked-cutover.json"
        with self.assertRaises(authority.AutomationCutoverBlocked):
            authority.issue_automation_cutover_record(
                output,
                identity=self.identity,
                capability_result=self.automation_result(
                    registration_snapshot,
                    available=False,
                ),
                pre_update_snapshot=registration_snapshot,
                installed_commit="a" * 40,
                automation_root=automation_root,
            )
        unrelated = self.automation_result(registration_snapshot)
        unrelated["operations"][0]["automation_id"] = "daily-skill-friction"
        with self.assertRaises(authority.AutomationCutoverBlocked):
            authority.issue_automation_cutover_record(
                output,
                identity=self.identity,
                capability_result=unrelated,
                pre_update_snapshot=registration_snapshot,
                installed_commit="a" * 40,
                automation_root=automation_root,
            )

        forged_registration = self.automation_result(registration_snapshot)
        forged_registration["operations"][0]["operation"] = "update"
        forged_registration["operations"][0]["previous_record_sha256"] = "c" * 64
        with self.assertRaises(authority.AutomationCutoverBlocked):
            authority.issue_automation_cutover_record(
                output,
                identity=self.identity,
                capability_result=forged_registration,
                pre_update_snapshot=registration_snapshot,
                installed_commit="a" * 40,
                automation_root=automation_root,
            )

        update_snapshot = self.capture_cutover_snapshot("blocked-update")
        for automation_id, mode in authority.STABLE_AUTOMATION_MODES.items():
            self.write_automation_record(
                automation_id,
                mode,
                prompt_suffix=" Verified update.",
            )
        forged_update = self.automation_result(update_snapshot)
        forged_update["operations"][0]["operation"] = "register"
        forged_update["operations"][0]["previous_record_sha256"] = None
        with self.assertRaises(authority.AutomationCutoverBlocked):
            authority.issue_automation_cutover_record(
                output,
                identity=self.identity,
                capability_result=forged_update,
                pre_update_snapshot=update_snapshot,
                installed_commit="a" * 40,
                automation_root=automation_root,
            )
        self.assertFalse(output.exists())

    def test_cutover_record_rejects_reference_only_and_coverage_suppression(
        self,
    ) -> None:
        automation_root = self.automation_root()
        snapshot = self.capture_cutover_snapshot("invalid-production")
        for automation_id, mode in authority.STABLE_AUTOMATION_MODES.items():
            self.write_automation_record(
                automation_id,
                mode,
                reference_only=automation_id == "weekly-session-retrospective",
                prompt_suffix=(
                    " Use --shadow --allow-partial."
                    if automation_id == "daily-session-retrospective"
                    else ""
                ),
            )
        with self.assertRaises(authority.AutomationCutoverBlocked):
            authority.issue_automation_cutover_record(
                self.root / "invalid-cutover.json",
                identity=self.identity,
                capability_result=self.automation_result(snapshot),
                pre_update_snapshot=snapshot,
                installed_commit="a" * 40,
                automation_root=automation_root,
            )

    def test_cutover_authority_rejects_opaque_or_tampered_controller_evidence(
        self,
    ) -> None:
        automation_root = self.automation_root()
        snapshot = self.capture_cutover_snapshot("threat-boundary")
        for automation_id, mode in authority.STABLE_AUTOMATION_MODES.items():
            self.write_automation_record(automation_id, mode)
        output = self.root / "threat-boundary-cutover.json"

        tampered_snapshot = json.loads(json.dumps(snapshot))
        tampered_snapshot["automation_records"][0]["state"] = "present"
        with self.assertRaises(authority.AutomationCutoverBlocked):
            authority.issue_automation_cutover_record(
                output,
                identity=self.identity,
                capability_result=self.automation_result(snapshot),
                pre_update_snapshot=tampered_snapshot,
                installed_commit="a" * 40,
                automation_root=automation_root,
            )

        opaque = self.automation_result(snapshot)
        opaque["tool_result_ref"] = "caller-controlled"
        with self.assertRaises(authority.AutomationCutoverBlocked):
            authority.issue_automation_cutover_record(
                output,
                identity=self.identity,
                capability_result=opaque,
                pre_update_snapshot=snapshot,
                installed_commit="a" * 40,
                automation_root=automation_root,
            )
        self.assertFalse(output.exists())

    def test_start_derives_shadow_backfill_only_from_completed_partial(self) -> None:
        backfill_ref = str(
            self.identity.derive_ref(RefType.RUN, {"parts": ["partial"]})
        )
        normalized_provenance = cli.orchestrator_api._build_provenance(
            provenance=execution_provenance(),
            policy=None,
            model=None,
            versions=None,
        )
        successor = {
            "authentication_tag": "shadow_daily_successor_auth_v2:" + "f" * 64,
            "backfill_of": backfill_ref,
            "cleanup_receipt_ref": "raw_cleanup_receipt_v2:" + "e" * 64,
            "controlled_gap_receipt": {"schema": "controlled_gap_receipt_v2"},
            "coverage_receipt_ref": "shadow_coverage_receipt_v2:" + "d" * 64,
            "export_bundle_digest": "c" * 64,
            "history_repo": str(self.history_repo.absolute()),
            "history_target_ref": "refs/heads/main",
            "host": "miku-bot-dev",
            "partial_checkpoint_revision": 12,
            "provenance": normalized_provenance,
            "schema": "shadow_daily_successor_v2",
            "window": {"end": WINDOW_END, "start": WINDOW_START},
        }
        arguments = (
            *self.shadow_start_arguments(),
            "--shadow-successor-of",
            str(self.root / "partial-run"),
        )
        with (
            mock.patch.object(
                RetrospectiveOrchestrator,
                "shadow_daily_successor",
                return_value=successor,
            ),
            mock.patch.object(
                cli.orchestrator_api,
                "start_run",
                return_value={"stage": "source_catalog"},
            ) as start_run,
        ):
            result = self.parse_dispatch(*arguments)
        self.assertTrue(result.ok)
        self.assertEqual(backfill_ref, result.result["shadow_successor_of"])
        self.assertEqual(("miku-bot-dev",), start_run.call_args.kwargs["hosts"])
        self.assertEqual(backfill_ref, start_run.call_args.kwargs["backfill_of"])
        self.assertEqual(successor, start_run.call_args.kwargs["shadow_successor"])

        bypass = self.parse_dispatch(
            *self.shadow_start_arguments(),
            "--backfill-of",
            backfill_ref,
            "--controlled-gap-receipt",
            str(self.root / "caller-gap.json"),
            "--host",
            "miku-bot-dev",
        )
        self.assertEqual(cli.ExitCode.INVALID_INPUT, bypass.exit_code)
        self.assertEqual("invalid_shadow_successor", bypass.error.code)

        production_arguments = [
            "start",
            "--mode",
            "daily",
            "--start",
            WINDOW_START,
            "--end",
            WINDOW_END,
            "--run-dir",
            str(self.root / "production-run"),
            "--run-config",
            str(self.run_config),
            "--history-repo",
            str(self.history_repo),
            "--history-target-ref",
            "refs/heads/main",
            "--shadow-successor-of",
            str(self.root / "partial-run"),
        ]
        rejected = self.parse_dispatch(*production_arguments)
        self.assertEqual(cli.ExitCode.INVALID_INPUT, rejected.exit_code)
        self.assertEqual("invalid_shadow_successor", rejected.error.code)

    def test_start_and_doctor_require_closed_execution_and_readiness_inputs(
        self,
    ) -> None:
        start_arguments = list(self.shadow_start_arguments())
        config_index = start_arguments.index("--run-config")
        del start_arguments[config_index : config_index + 2]
        with self.assertRaises(cli.CliContractError):
            self.parser.parse_args(start_arguments)
        with self.assertRaises(cli.CliContractError):
            self.parser.parse_args(
                [
                    "doctor",
                    "--shadow",
                    "--identity-path",
                    str(self.identity_path),
                    "--require-existing-identity",
                ]
            )

    def test_start_cli_reaches_all_four_modes_with_exact_bindings(self) -> None:
        selector = "direct-cli-session-selector"
        session_target = str(
            self.identity.derive_ref(RefType.SESSION, {"session_id": selector})
        )
        cases = (
            ("daily", "2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z", ()),
            ("weekly", "2026-07-06T00:00:00Z", "2026-07-13T00:00:00Z", ()),
            ("baseline", "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", ()),
            (
                "session",
                "2026-07-06T00:00:00Z",
                "2026-07-07T00:00:00Z",
                (
                    "--session-target",
                    session_target,
                    "--session-target-selector",
                    selector,
                ),
            ),
        )
        for mode, start, end, extra in cases:
            with self.subTest(mode=mode):
                arguments = list(self.shadow_start_arguments())
                arguments[arguments.index("daily")] = mode
                arguments[arguments.index("2026-07-06T00:00:00Z")] = start
                arguments[arguments.index("2026-07-07T00:00:00Z")] = end
                arguments[arguments.index(str(self.run_dir))] = str(
                    self.root / f"run-{mode}"
                )
                arguments.extend(extra)
                with mock.patch.object(
                    cli.orchestrator_api,
                    "start_run",
                    return_value={"mode": mode, "stage": "source_catalog"},
                ) as start_run:
                    result = self.parse_dispatch(*arguments)

                self.assertTrue(result.ok, result.error)
                self.assertEqual(mode, start_run.call_args.kwargs["mode"])
                self.assertEqual(start, start_run.call_args.kwargs["start"])
                self.assertEqual(end, start_run.call_args.kwargs["end"])
                self.assertEqual(
                    session_target if mode == "session" else None,
                    start_run.call_args.kwargs["session_target"],
                )

    def test_start_cli_rejects_invalid_windows_and_session_bindings(self) -> None:
        selector = "session-binding-selector"
        target = str(
            self.identity.derive_ref(RefType.SESSION, {"session_id": selector})
        )
        wrong_target = str(
            self.identity.derive_ref(
                RefType.SESSION,
                {"session_id": "different-session-selector"},
            )
        )
        cases = (
            (
                "empty-window",
                ("--mode", "daily", "--start", WINDOW_START, "--end", WINDOW_START),
                "invalid_window",
            ),
            (
                "short-week",
                ("--mode", "weekly", "--start", WINDOW_START, "--end", WINDOW_END),
                "invalid_window",
            ),
            (
                "short-baseline",
                (
                    "--mode",
                    "baseline",
                    "--start",
                    "2026-01-01T00:00:00Z",
                    "--end",
                    "2026-03-31T00:00:00Z",
                ),
                "invalid_window",
            ),
            (
                "missing-session-target",
                (
                    "--mode",
                    "session",
                    "--start",
                    WINDOW_START,
                    "--end",
                    WINDOW_END,
                ),
                "invalid_session_target",
            ),
            (
                "mismatched-session-target",
                (
                    "--mode",
                    "session",
                    "--start",
                    WINDOW_START,
                    "--end",
                    WINDOW_END,
                    "--session-target",
                    wrong_target,
                    "--session-target-selector",
                    selector,
                ),
                "invalid_session_target",
            ),
            (
                "daily-session-binding",
                (
                    "--mode",
                    "daily",
                    "--start",
                    WINDOW_START,
                    "--end",
                    WINDOW_END,
                    "--session-target",
                    target,
                    "--session-target-selector",
                    selector,
                ),
                "invalid_session_target",
            ),
        )
        common = (
            "start",
            "--shadow",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--run-dir",
            str(self.run_dir),
            "--run-config",
            str(self.run_config),
            "--history-repo",
            str(self.history_repo),
            "--history-target-ref",
            "refs/heads/main",
        )
        for label, mode_arguments, expected_code in cases:
            with (
                self.subTest(case=label),
                mock.patch.object(cli.orchestrator_api, "start_run") as start_run,
            ):
                result = self.parse_dispatch(*common, *mode_arguments)
                self.assertEqual(cli.ExitCode.INVALID_INPUT, result.exit_code)
                self.assertEqual(expected_code, result.error.code)
                start_run.assert_not_called()

    def test_shadow_start_requires_explicit_existing_identity_without_default_write(
        self,
    ) -> None:
        with (
            mock.patch.object(
                cli.identity_api,
                "identity_key_path",
                return_value=self.default_identity,
            ),
            mock.patch.object(
                cli.orchestrator_api,
                "start_run",
                return_value={"run_ref": "run_ref_v2:" + "a" * 64},
            ) as start_run,
        ):
            missing = self.parse_dispatch(
                "start",
                "--shadow",
                "--mode",
                "daily",
                "--start",
                "2026-07-06T00:00:00Z",
                "--end",
                "2026-07-07T00:00:00Z",
                "--run-dir",
                str(self.run_dir),
                "--run-config",
                str(self.run_config),
                "--history-repo",
                str(self.history_repo),
                "--history-target-ref",
                "refs/heads/main",
            )
            accepted = self.parse_dispatch(*self.shadow_start_arguments())

        self.assertEqual(cli.ExitCode.SECURITY, missing.exit_code)
        self.assertEqual("shadow_identity_required", missing.error.code)
        self.assertTrue(accepted.ok)
        self.assertFalse(self.default_identity.exists())
        self.assertTrue(start_run.call_args.kwargs["shadow"])
        self.assertTrue(start_run.call_args.kwargs["require_existing_identity"])

    def test_production_start_rejects_nondefault_identity_path(self) -> None:
        arguments = list(self.shadow_start_arguments())
        arguments.remove("--shadow")
        with (
            mock.patch.object(
                cli.identity_api,
                "identity_key_path",
                return_value=self.default_identity,
            ),
            mock.patch.object(cli.orchestrator_api, "start_run") as start_run,
        ):
            result = self.parse_dispatch(*arguments)
        self.assertEqual(cli.ExitCode.SECURITY, result.exit_code)
        self.assertEqual("production_identity_path_fixed", result.error.code)
        start_run.assert_not_called()

    def test_doctor_shadow_never_creates_identity(self) -> None:
        with (
            mock.patch.object(
                cli.identity_api,
                "identity_key_path",
                return_value=self.default_identity,
            ),
            mock.patch.object(
                cli.orchestrator_api,
                "doctor",
                return_value={"ok": True},
            ),
        ):
            missing = self.parse_dispatch(
                "doctor",
                "--shadow",
                "--run-config",
                str(self.run_config),
                "--history-repo",
                str(self.history_repo),
                "--history-target-ref",
                "refs/heads/main",
            )
            accepted = self.parse_dispatch(
                "doctor",
                "--shadow",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-config",
                str(self.run_config),
                "--history-repo",
                str(self.history_repo),
                "--history-target-ref",
                "refs/heads/main",
            )
        self.assertEqual(cli.ExitCode.SECURITY, missing.exit_code)
        self.assertTrue(accepted.ok)
        self.assertFalse(self.default_identity.exists())

    def test_accept_source_rejects_raw_path_outside_run_cache(self) -> None:
        outside = self.root / "source-transport.jsonl"
        outside.write_text("{}\n", encoding="ascii")
        os.chmod(outside, 0o600)
        with mock.patch.object(cli.orchestrator_api, "prepare_source") as prepare:
            result = self.parse_dispatch(
                "accept-source",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-dir",
                str(self.run_dir),
                "--lease-ref",
                "source_lease_ref_v2:" + "a" * 64,
                "--transport-stream-file",
                str(outside),
            )
        self.assertEqual(cli.ExitCode.SECURITY, result.exit_code)
        self.assertEqual("raw_path_outside_run_cache", result.error.code)
        prepare.assert_not_called()

    def test_accept_source_exact_command_replays_after_lost_response(self) -> None:
        coordinator = RetrospectiveOrchestrator(
            self.run_dir,
            identity_path=self.identity_path,
        )
        coordinator.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=WINDOW_END,
            shadow=True,
            provenance=execution_provenance(),
            history_repo=self.history_repo,
            history_target_ref="refs/heads/main",
            created_at="2026-07-14T12:00:00Z",
        )
        for _ in range(4):
            leases = coordinator.status()["active_source_leases"]
            if leases:
                lease = next(
                    item
                    for item in leases
                    if item["host"] == "local"
                    and item["source_kind"] == SourceKind.SESSION_INDEX.value
                )
                break
            coordinator.advance()
        else:
            self.fail("source lease was not scheduled")
        stream_path = Path(lease["source_transport_output"])
        stream_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = {**os.environ, "HOME": str(self.root)}
        completed = subprocess.run(
            lease["source_transport_command"],
            check=True,
            capture_output=True,
            env=environment,
        )
        stream_path.write_bytes(completed.stdout)
        os.chmod(stream_path, 0o600)
        arguments = (
            "accept-source",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--run-dir",
            str(self.run_dir),
            "--lease-ref",
            lease["lease_ref"],
            "--transport-stream-file",
            str(stream_path),
        )

        accepted = self.parse_dispatch(*arguments)
        replayed = self.parse_dispatch(*arguments)

        self.assertTrue(accepted.ok, accepted.error)
        self.assertFalse(accepted.result["idempotent"])
        self.assertTrue(replayed.ok, replayed.error)
        self.assertTrue(replayed.result["idempotent"])

        codex_root = self.root / ".codex"
        codex_root.mkdir(mode=0o700)
        codex_root.joinpath("session_index.jsonl").write_text(
            '{"id":"changed","timestamp":"2026-07-06T01:00:00Z"}\n',
            encoding="ascii",
        )
        changed = subprocess.run(
            lease["source_transport_command"],
            check=True,
            capture_output=True,
            env=environment,
        )
        stream_path.write_bytes(changed.stdout)
        os.chmod(stream_path, 0o600)
        mismatch = self.parse_dispatch(*arguments)
        self.assertFalse(mismatch.ok)
        self.assertEqual(cli.ExitCode.CONFLICT, mismatch.exit_code)

    def test_advance_exposes_controlled_holdout_without_a_ninth_command(self) -> None:
        holdout_result = {
            "controlled_gap_receipt": {"receipt_ref": "controlled-gap"},
            "cursors": {
                "local": {"publication_state": "complete"},
                "remote": {"publication_state": "backfill_required"},
            },
        }
        with mock.patch.object(
            cli.orchestrator_api,
            "holdout_host",
            return_value=holdout_result,
        ) as holdout:
            result = self.parse_dispatch(
                "advance",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-dir",
                str(self.run_dir),
                "--holdout-host",
                "remote",
                "--holdout-reason",
                "missing_host_holdout",
            )
        missing_reason = self.parse_dispatch(
            "advance",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--run-dir",
            str(self.run_dir),
            "--holdout-host",
            "remote",
        )

        self.assertTrue(result.ok, result)
        self.assertEqual(
            "backfill_required",
            result.result["cursors"]["remote"]["publication_state"],
        )
        self.assertEqual(cli.ExitCode.INVALID_INPUT, missing_reason.exit_code)
        self.assertEqual("invalid_controlled_holdout", missing_reason.error.code)
        holdout.assert_called_once()
        self.assertEqual("remote", holdout.call_args.args[1])
        self.assertEqual("missing_host_holdout", holdout.call_args.kwargs["reason"])

    def test_duplicate_json_is_rejected_without_echoing_content(self) -> None:
        secret = "SEALED_RAW_CLI_SECRET_4c91"
        path = self.root / "duplicate.json"
        path.write_text(
            '{"schema":"one","schema":"' + secret + '"}\n',
            encoding="ascii",
        )
        os.chmod(path, 0o600)
        with self.assertRaises(cli.CliContractError) as caught:
            cli._read_json_object(path, max_bytes=4096)
        self.assertEqual("invalid_json", caught.exception.code)
        self.assertNotIn(secret, caught.exception.safe_message)

        path.write_bytes(b'{"overflow":1e999}')
        with self.assertRaises(cli.CliContractError) as overflow:
            cli._read_json_object(path, max_bytes=4096)
        self.assertEqual("invalid_json", overflow.exception.code)

        path.write_bytes(b'{"integer":9223372036854775808}')
        with self.assertRaises(cli.CliContractError) as oversized_integer:
            cli._read_json_object(path, max_bytes=4096)
        self.assertEqual("invalid_json", oversized_integer.exception.code)

    def test_export_cli_completes_real_no_activity_bundle(self) -> None:
        coordinator = self.real_coordinator(self.run_dir, activity=False)
        self.assertEqual(RunStage.EXPORT.value, coordinator.status()["stage"])
        output = self.root / ".codex-local" / "exports" / "cli" / "retained-v2"
        result = self.parse_dispatch(
            "export",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--run-dir",
            str(self.run_dir),
            "--output",
            str(output),
        )

        self.assertTrue(result.ok, result)
        self.assertEqual("standalone", result.result["publication_role"])
        self.assertEqual(RunStage.COMPLETE.value, result.result["stage"])
        self.assertTrue((output / "manifest.json").is_file())
        descriptor = json.loads(
            (self.run_dir / cli.EXPORT_DESCRIPTOR_NAME).read_text(encoding="ascii")
        )
        self.assertEqual("standalone", descriptor["publication_role"])
        self.assertEqual(result.result["bundle_digest"], descriptor["bundle_digest"])

    def test_export_does_not_run_implicit_gc_before_run_validation(self) -> None:
        output_parent = self.root / "retained-exports"
        output_parent.mkdir(mode=0o700)
        sentinel = output_parent / "unrelated-retained-state"
        sentinel.write_text("preserve", encoding="ascii")

        with mock.patch.object(
            cli.export_api,
            "garbage_collect_expired_exports",
        ) as garbage_collect:
            result = self.parse_dispatch(
                "export",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-dir",
                str(self.root / "missing-run"),
                "--output",
                str(output_parent / "candidate"),
            )

        self.assertEqual(cli.ExitCode.NOT_FOUND, result.exit_code)
        garbage_collect.assert_not_called()
        self.assertEqual("preserve", sentinel.read_text(encoding="ascii"))

    def test_generic_cli_errors_expose_only_allowlisted_recovery_metadata(
        self,
    ) -> None:
        secret = "raw exception detail must remain private"
        cases = (
            (
                cli.orchestrator_api.RunConflictError(secret),
                "run_state_conflict",
                "refresh_state_and_retry",
            ),
            (
                cli.orchestrator_api.RunNotStartedError(secret),
                "run_not_started",
                "initialize_or_restore_state",
            ),
            (
                cli.orchestrator_api.InvalidTransitionError(secret),
                "run_transition_invalid",
                "inspect_status",
            ),
            (
                cli.orchestrator_api.InvalidInputError(secret),
                "run_input_invalid",
                "correct_request",
            ),
            (OSError(secret), "os_io_failed", "retry_bounded_io"),
            (
                RuntimeError(secret),
                "unexpected_internal_failure",
                "escalate_internal_failure",
            ),
        )
        for error, reason_code, recovery_action in cases:
            with self.subTest(reason_code=reason_code):
                result = cli._failure_from_exception("status", error)
                payload = result.to_json()
                self.assertEqual(reason_code, payload["error"]["reason_code"])
                self.assertEqual(
                    recovery_action,
                    payload["error"]["recovery_action"],
                )
                self.assertIn(reason_code, cli._REASON_CODE_ALLOWLIST)
                self.assertIn(recovery_action, cli._RECOVERY_ACTION_ALLOWLIST)
                self.assertNotIn(secret, json.dumps(payload, sort_keys=True))

    def test_export_cli_uses_prior_period_for_real_trend_comparison(self) -> None:
        coordinator = self.real_coordinator(self.run_dir, activity=False)
        state = coordinator.load_state()
        run_state, review_data = cli._retained_inputs(state)
        run_state["durable_state"] = coordinator.publication_durable_state()
        run_state["window"] = {
            "end": WINDOW_START,
            "start": "2026-07-05T00:00:00Z",
        }
        prior_artifacts = reporting.assemble_retained_artifacts(
            run_state,
            review_data,
        )
        prior_dir = self.root / "prior-period"
        prior_dir.mkdir(mode=0o700)
        for name, payload in prior_artifacts.items():
            artifact = prior_dir / name
            artifact.write_bytes(payload)
            os.chmod(artifact, 0o600)
        output = self.root / ".codex-local" / "exports" / "with-prior"

        result = self.parse_dispatch(
            "export",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--run-dir",
            str(self.run_dir),
            "--output",
            str(output),
            "--prior-period",
            str(prior_dir),
        )

        self.assertTrue(result.ok, result)
        trend = json.loads((output / "trend_report.json").read_text(encoding="ascii"))
        self.assertEqual("incompatible", trend["normalized_changes"]["status"])
        self.assertEqual(
            "unknown_model_or_policy_era",
            trend["normalized_changes"]["reason"],
        )

    def test_export_cli_loads_prior_period_from_authenticated_history(self) -> None:
        coordinator = self.real_coordinator(self.run_dir, activity=False)
        state = coordinator.load_state()
        run_state, review_data = cli._retained_inputs(state)
        run_state["durable_state"] = coordinator.publication_durable_state()
        run_state["window"] = {
            "end": WINDOW_START,
            "start": "2026-07-05T00:00:00Z",
        }
        prior_artifacts = reporting.assemble_retained_artifacts(
            run_state,
            review_data,
        )
        prior_trend = json.loads(prior_artifacts["trend_report.json"])
        authenticated = {
            "authenticated_history": {
                "bundle_digest": "b" * 64,
                "history_commit": "a" * 40,
                "history_head": "a" * 40,
                "schema": "authenticated_prior_history_v2",
            },
            "trend_report": prior_trend,
        }
        output = self.root / ".codex-local" / "exports" / "with-history"

        with mock.patch.object(
            cli.authority_api,
            "load_prior_period_from_history",
            return_value=authenticated,
        ) as load_prior:
            result = self.parse_dispatch(
                "export",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-dir",
                str(self.run_dir),
                "--output",
                str(output),
                "--prior-history",
            )

        self.assertTrue(result.ok, result)
        load_prior.assert_called_once()
        self.assertEqual(
            state["authority"]["history_repo"],
            load_prior.call_args.args[0],
        )
        self.assertEqual(
            state["authority"]["history_target_ref"],
            load_prior.call_args.args[1],
        )
        trend = json.loads((output / "trend_report.json").read_text(encoding="ascii"))
        self.assertEqual("incompatible", trend["normalized_changes"]["status"])
        self.assertEqual(
            "unknown_model_or_policy_era",
            trend["normalized_changes"]["reason"],
        )

    def test_prior_period_rejects_a_standalone_trend_file(self) -> None:
        trend = self.root / "trend_report.json"
        trend.write_text("{}\n", encoding="ascii")
        os.chmod(trend, 0o600)
        with self.assertRaises((NotADirectoryError, safe_io.UnsafePathError)):
            cli._load_prior_period(str(trend))

    def test_malformed_agent_output_consumes_attempt_and_requires_fresh_retry(
        self,
    ) -> None:
        cases = (
            (
                "duplicate_keys",
                "duplicate_keys",
                b'{"schema":"one","schema":"two"}',
            ),
            ("invalid_root_type", "invalid_root_type", b"[]"),
            ("malformed_json", "malformed_json", b"{"),
            ("nonfinite_overflow", "malformed_json", b'{"value":1e999}'),
            (
                "oversized_integer",
                "malformed_json",
                b'{"value":9223372036854775808}',
            ),
            ("malformed_utf8", "malformed_utf8", b"\xff"),
            (
                "malformed_agent_failure",
                "schema_violation",
                b'{"failure_kind":"invalid","schema":"agent_failure_v2"}',
            ),
            (
                "result_too_large",
                "result_too_large",
                b"x" * (cli.MAX_AGENT_RESULT_BYTES + 1),
            ),
        )
        for index, (case, reason, payload) in enumerate(cases):
            with self.subTest(case=case):
                run_dir = self.root / f"agent-{index}"
                coordinator = self.real_coordinator(run_dir, activity=True)
                first = coordinator.status()["runnable_jobs"][0]
                dispatcher_ref = str(
                    self.identity.derive_ref(
                        RefType.LEASE,
                        {"attempt_ref": first["active_attempt_ref"]},
                    )
                )
                claimed = self.parse_dispatch(
                    "status",
                    "--identity-path",
                    str(self.identity_path),
                    "--require-existing-identity",
                    "--run-dir",
                    str(run_dir),
                    "--claim-job-ref",
                    first["job_ref"],
                    "--claim-attempt-ref",
                    first["active_attempt_ref"],
                    "--dispatcher-ref",
                    dispatcher_ref,
                )
                self.assertTrue(claimed.ok, claimed)
                self.assertTrue(Path(claimed.result["envelope_path"]).is_file())
                result_path = Path(claimed.result["output_sink"])
                result_path.write_bytes(payload)
                os.chmod(result_path, 0o600)

                rejected = self.parse_dispatch(
                    "accept-agent-result",
                    "--identity-path",
                    str(self.identity_path),
                    "--require-existing-identity",
                    "--run-dir",
                    str(run_dir),
                    "--job-ref",
                    first["job_ref"],
                    "--attempt-ref",
                    first["active_attempt_ref"],
                    "--claim-ref",
                    claimed.result["claim_ref"],
                    "--result-ref",
                    claimed.result["result_ref"],
                    "--result",
                    str(result_path),
                )
                self.assertTrue(rejected.ok, rejected)
                self.assertEqual("retryable", rejected.result["outcome"])
                self.assertEqual(reason, rejected.result["reason"])

                state = coordinator.load_state()
                task = next(
                    job
                    for job in state["jobs"].values()
                    if job.get("category") == "agent"
                )
                attempt = task["attempts"][0]
                self.assertEqual("failed", attempt["status"])
                self.assertEqual("closed", attempt["sink_state"])
                self.assertIsNone(task["active_attempt_ref"])

                coordinator.advance()
                retry = coordinator.status()["runnable_jobs"][0]
                self.assertEqual(1, retry["retry_ordinal"])
                self.assertNotEqual(first["job_ref"], retry["job_ref"])
                self.assertNotEqual(
                    first["active_attempt_ref"], retry["active_attempt_ref"]
                )

    def test_nonfinite_agent_output_retries_once_then_records_gap(self) -> None:
        coordinator = self.real_coordinator(
            self.root / "agent-nonfinite-gap",
            activity=True,
        )
        attempts = []
        for retry_ordinal in range(2):
            runnable = coordinator.status()["runnable_jobs"][0]
            attempts.append(runnable["active_attempt_ref"])
            dispatcher_ref = str(
                self.identity.derive_ref(
                    RefType.LEASE,
                    {"attempt_ref": runnable["active_attempt_ref"]},
                )
            )
            claimed = self.parse_dispatch(
                "status",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-dir",
                str(coordinator.run_dir),
                "--claim-job-ref",
                runnable["job_ref"],
                "--claim-attempt-ref",
                runnable["active_attempt_ref"],
                "--dispatcher-ref",
                dispatcher_ref,
            )
            self.assertTrue(claimed.ok, claimed)
            result_path = Path(claimed.result["output_sink"])
            result_path.write_bytes(b'{"value":1e999}')
            os.chmod(result_path, 0o600)
            rejected = self.parse_dispatch(
                "accept-agent-result",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-dir",
                str(coordinator.run_dir),
                "--job-ref",
                runnable["job_ref"],
                "--attempt-ref",
                runnable["active_attempt_ref"],
                "--claim-ref",
                claimed.result["claim_ref"],
                "--result-ref",
                claimed.result["result_ref"],
                "--result",
                str(result_path),
            )
            self.assertTrue(rejected.ok, rejected)
            self.assertEqual("malformed_json", rejected.result["reason"])
            self.assertEqual(
                "retryable" if retry_ordinal == 0 else "gap",
                rejected.result["outcome"],
            )
            if retry_ordinal == 0:
                coordinator.advance()

        state = coordinator.load_state()
        task = next(
            job for job in state["jobs"].values() if job.get("category") == "agent"
        )
        self.assertEqual("gap", task["status"])
        self.assertIsNone(task["active_attempt_ref"])
        self.assertIsNone(task["active_job_ref"])
        self.assertEqual(attempts, [row["attempt_ref"] for row in task["attempts"]])
        self.assertTrue(all(row["sink_state"] == "closed" for row in task["attempts"]))
        self.assertTrue(
            all(row["dispatch_state"] == "completed" for row in task["attempts"])
        )
        self.assertTrue(
            any(
                gap["dependency_ref"] == task["task_ref"]
                and gap["reason"] == "malformed_json"
                for gap in state["gaps"]
            )
        )

    def test_finalize_uses_persisted_shadow_disposition(self) -> None:
        orchestrator = mock.Mock()
        orchestrator.load_state.return_value = {
            "publication": {"phase": "not_started"},
            "shadow": True,
            "stage": "export",
        }
        with mock.patch.object(
            cli.orchestrator_api,
            "RetrospectiveOrchestrator",
            return_value=orchestrator,
        ):
            result = self.parse_dispatch(
                "finalize",
                "--identity-path",
                str(self.identity_path),
                "--require-existing-identity",
                "--run-dir",
                str(self.run_dir),
            )
        self.assertEqual(cli.ExitCode.INVALID_STATE, result.exit_code)
        self.assertEqual("shadow_publication_forbidden", result.error.code)

    def test_main_emits_one_bounded_machine_record(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            exit_code = cli.main(["prepare-source"])
        self.assertEqual(cli.ExitCode.USAGE, exit_code)
        self.assertEqual(1, stdout.getvalue().count("\n"))
        payload = json.loads(stdout.getvalue())
        self.assertEqual("usage_error", payload["error"]["code"])
        self.assertLessEqual(len(stderr.getvalue().encode("utf-8")), 256)


if __name__ == "__main__":
    unittest.main()
