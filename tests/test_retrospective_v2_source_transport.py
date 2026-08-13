from __future__ import annotations

from dataclasses import replace
import datetime as dt
import hashlib
import json
import io
import os
from pathlib import Path
import pwd
import py_compile
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock


SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "codex-session-retrospective"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS))

from retrospective_v2 import (  # noqa: E402
    authority,
    catalog,
    safe_io,
    source_capacity,
    source_inputs,
    source_payloads,
    transport,
)
import retrospective_v2.orchestrator as orchestrator_module  # noqa: E402
from retrospective_v2 import (  # noqa: E402
    orchestrator_transport,
    transport_contracts,
    transport_program,
    transport_remote,
    transport_remote_snapshot,
    transport_resume,
    transport_snapshot,
    transport_source,
)
from retrospective_v2.contracts import (  # noqa: E402
    RefType,
    RunMode,
    SourceCellStatus,
    SourceKind,
)
from retrospective_v2.identity import IdentityKey  # noqa: E402
from retrospective_v2.orchestrator import (  # noqa: E402
    InvalidInputError,
    InvalidTransitionError,
    RetrospectiveOrchestrator,
)
from tests.test_retrospective_v2_orchestrator import (  # noqa: E402
    bind_remote_host_context_helper_fixture,
    execution_provenance,
)


WINDOW_START = "2026-07-06T00:00:00Z"
WINDOW_END = "2026-07-07T00:00:00Z"


class SourceTransportProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        bind_remote_host_context_helper_fixture(self)
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        os.chmod(self.root, 0o700)
        self.snapshot_cache_patch = mock.patch.object(
            transport_program,
            "SOURCE_TRANSPORT_SNAPSHOT_CACHE",
            self.root / "program-snapshot-cache",
        )
        self.snapshot_cache_patch.start()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.codex_root = self.home / ".codex"
        self.codex_root.mkdir(mode=0o700)
        self.identity = IdentityKey.create(self.root / "identity-v2.key")
        self.history = authority.DurableHistoryState(
            head_commit="a" * 40,
            publication_commit=None,
            identity_key_id=self.identity.key_id,
            provider_revision=0,
            cursor_root_ref=authority.EMPTY_CURSOR_ROOT_REF,
            episode_head_root_ref=authority.empty_episode_head_root(self.identity),
            cursor_rows=(),
            episode_heads=(),
            episode_membership=(),
        )
        self.history_patch = mock.patch(
            "retrospective_v2.orchestrator.authority.load_durable_history",
            side_effect=lambda *_args, **_kwargs: self.history,
        )
        self.history_patch.start()
        self.host_policy_patch = mock.patch.object(
            orchestrator_module,
            "DEFAULT_HOSTS",
            ("local",),
        )
        self.host_policy_patch.start()

    def tearDown(self) -> None:
        self.host_policy_patch.stop()
        self.history_patch.stop()
        self.snapshot_cache_patch.stop()
        self.temporary_directory.cleanup()

    def test_source_acceptance_sidecar_rejects_hardlinks_and_content_change(
        self,
    ) -> None:
        prepared = source_inputs.prepare_acceptance(
            self.root,
            segment={"lease_ref": "lease-ref"},
            payloads={},
            model_era_by_unit={},
            model_eras_by_session={},
        )
        source_inputs.materialize((prepared.file,))
        alias = prepared.file.path.with_name("sidecar-alias.json")
        os.link(prepared.file.path, alias)
        with self.assertRaisesRegex(InvalidTransitionError, "authenticated"):
            source_inputs.load(self.root, prepared.descriptor)
        alias.unlink()

        original = prepared.file.path.read_bytes()
        prepared.file.path.write_bytes(b"[" + original[1:])
        os.chmod(prepared.file.path, 0o600)
        with self.assertRaisesRegex(InvalidTransitionError, "changed"):
            source_inputs.load(self.root, prepared.descriptor)

    def test_source_rollback_revalidates_single_link_and_exact_content(self) -> None:
        unit_ref = str(
            self.identity.derive_ref(RefType.SOURCE_UNIT, {"case": "rollback"})
        )
        _relative_path, prepared = source_inputs.prepare_raw_payload(
            self.identity,
            self.root,
            unit_ref,
            b"rollback evidence",
        )
        materialized = source_inputs.materialize((prepared,))
        self.assertEqual(1, len(materialized))
        alias = prepared.path.with_name("rollback-alias.bin")
        original_validate = safe_io.validate_owner_only_file_descriptor
        calls = 0

        def add_hardlink_before_revalidation(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                os.link(prepared.path, alias)
            return original_validate(*args, **kwargs)

        with (
            mock.patch.object(
                safe_io,
                "validate_owner_only_file_descriptor",
                side_effect=add_hardlink_before_revalidation,
            ),
            self.assertRaisesRegex(InvalidTransitionError, "target changed"),
        ):
            source_inputs.rollback(materialized)

        self.assertEqual(b"rollback evidence", prepared.path.read_bytes())
        self.assertEqual(b"rollback evidence", alias.read_bytes())

    def test_source_rollback_rejects_same_content_leaf_replacement(self) -> None:
        unit_ref = str(
            self.identity.derive_ref(RefType.SOURCE_UNIT, {"case": "replacement"})
        )
        _relative_path, prepared = source_inputs.prepare_raw_payload(
            self.identity,
            self.root,
            unit_ref,
            b"same content replacement",
        )
        materialized = source_inputs.materialize((prepared,))
        self.assertEqual(1, len(materialized))
        original = prepared.path.with_name("rollback-original.bin")
        prepared.path.rename(original)
        prepared.path.write_bytes(b"same content replacement")
        os.chmod(prepared.path, 0o600)

        with self.assertRaisesRegex(InvalidTransitionError, "target changed"):
            source_inputs.rollback(materialized)

        self.assertEqual(b"same content replacement", original.read_bytes())
        self.assertEqual(b"same content replacement", prepared.path.read_bytes())

    def test_source_rollback_continues_after_one_receipt_mismatch(self) -> None:
        prepared = []
        for label in ("changed", "exact"):
            unit_ref = str(
                self.identity.derive_ref(RefType.SOURCE_UNIT, {"case": label})
            )
            _relative_path, item = source_inputs.prepare_raw_payload(
                self.identity,
                self.root,
                unit_ref,
                label.encode("ascii"),
            )
            prepared.append(item)
        materialized = source_inputs.materialize(tuple(prepared))
        changed = prepared[0].path
        original = changed.with_name("changed-original.bin")
        changed.rename(original)
        changed.write_bytes(b"changed")
        os.chmod(changed, 0o600)

        with self.assertRaisesRegex(InvalidTransitionError, "target changed"):
            source_inputs.rollback(materialized)

        self.assertTrue(changed.is_file())
        self.assertTrue(original.is_file())
        self.assertFalse(prepared[1].path.exists())

    def test_source_materialization_preserves_primary_when_rollback_fails(
        self,
    ) -> None:
        prepared = []
        for label in ("created", "failed"):
            unit_ref = str(
                self.identity.derive_ref(
                    RefType.SOURCE_UNIT,
                    {"case": f"primary-{label}"},
                )
            )
            _relative_path, item = source_inputs.prepare_raw_payload(
                self.identity,
                self.root,
                unit_ref,
                label.encode("ascii"),
            )
            prepared.append(item)
        original_create = safe_io.atomic_create_bytes_with_receipt
        calls = 0

        def create_then_fail(
            path,
            payload,
            *,
            create_parents=True,
            receipt_slot=None,
        ):
            nonlocal calls
            calls += 1
            if calls == 1:
                receipt = original_create(
                    path,
                    payload,
                    create_parents=create_parents,
                    receipt_slot=receipt_slot,
                )
                original = Path(path).with_name("primary-original.bin")
                Path(path).rename(original)
                Path(path).write_bytes(bytes(payload))
                os.chmod(path, 0o600)
                return receipt
            raise RuntimeError("primary materialization failure")

        with (
            mock.patch.object(
                safe_io,
                "atomic_create_bytes_with_receipt",
                side_effect=create_then_fail,
            ),
            self.assertRaisesRegex(
                RuntimeError, "primary materialization failure"
            ) as caught,
        ):
            source_inputs.materialize(tuple(prepared))

        self.assertTrue(
            any(
                "rollback was incomplete" in note for note in caught.exception.__notes__
            )
        )
        self.assertTrue(prepared[0].path.is_file())

    def test_source_payload_indexes_reject_legacy_sidecar_conflicts(self) -> None:
        unit_ref = str(
            self.identity.derive_ref(RefType.SOURCE_UNIT, {"case": "payload"})
        )
        available = {
            "byte_count": 1,
            "content_commitment": "sha256:" + "a" * 64,
            "relative_path": "raw-inputs/" + "b" * 64 + ".bin",
            "status": "available",
        }
        self.assertEqual(
            {unit_ref: available},
            source_payloads.merge_payload_indexes({unit_ref: available}),
        )
        with self.assertRaisesRegex(InvalidTransitionError, "index changed"):
            source_payloads.merge_payload_indexes(
                {unit_ref: available},
                {unit_ref: {"reason": "raw_payload_missing", "status": "gap"}},
            )

    def test_source_capacity_is_run_global_before_new_materialization(self) -> None:
        cells = {
            "local": {
                "history": {
                    "continuation_segments": [],
                    "metrics": {"byte_count": 1, "record_count": 1},
                }
            }
        }
        with (
            mock.patch.object(source_capacity, "MAX_RUN_SOURCE_RECORDS", 1),
            self.assertRaisesRegex(InvalidTransitionError, "records"),
        ):
            source_capacity.require_candidate_capacity(
                cells,
                acceptance_bytes=1,
                byte_count=1,
                record_count=1,
            )

        descriptor = {
            "byte_count": 2,
            "content_commitment": "sha256:" + "0" * 64,
            "relative_path": "raw-inputs/source-acceptances/unused.json",
            "schema": "source_acceptance_descriptor_v2",
        }
        cells["local"]["history"]["continuation_segments"] = [descriptor]
        with (
            mock.patch.object(source_capacity, "MAX_RUN_SOURCE_ACCEPTANCE_BYTES", 2),
            self.assertRaisesRegex(InvalidTransitionError, "acceptance bytes"),
        ):
            source_capacity.require_candidate_capacity(
                cells,
                acceptance_bytes=1,
                byte_count=0,
                record_count=0,
            )

        cells["local"]["history"]["continuation_segments"] = [descriptor] * 65
        with self.assertRaisesRegex(InvalidTransitionError, "continuation chain"):
            source_capacity.require_candidate_capacity(
                cells,
                acceptance_bytes=0,
                byte_count=0,
                record_count=0,
            )

    def test_source_segment_payload_merge_is_in_place_and_linear(self) -> None:
        descriptors = [{"manifest": {}} for _ in range(32)]
        materialized = []
        expected_refs = []
        for index in range(len(descriptors)):
            unit_ref = str(
                self.identity.derive_ref(RefType.SOURCE_UNIT, {"segment": index})
            )
            expected_refs.append(unit_ref)
            materialized.append(
                {
                    "model_era_by_unit": {},
                    "model_eras_by_session": {},
                    "payloads": {
                        unit_ref: {"reason": "raw_payload_missing", "status": "gap"}
                    },
                    "segment": {
                        "metrics": {
                            "byte_count": 0,
                            "record_count": 0,
                            "scan_byte_count": 0,
                        }
                    },
                }
            )
        with (
            mock.patch.object(
                source_inputs,
                "materialized_segment",
                side_effect=materialized,
            ) as loader,
            mock.patch.object(
                source_payloads,
                "merge_payload_index_into",
                wraps=source_payloads.merge_payload_index_into,
            ) as merger,
        ):
            result = source_inputs.materialize_segments(self.root, descriptors)

        self.assertEqual(len(descriptors), loader.call_count)
        self.assertEqual(len(descriptors), merger.call_count)
        self.assertEqual(sorted(expected_refs), list(result["payloads"]))

    @staticmethod
    def _line(session_id: str, *, kind: str = "history") -> bytes:
        if kind == "session_meta":
            value = {
                "payload": {"id": session_id},
                "timestamp": "2026-07-06T01:00:00Z",
                "type": "session_meta",
            }
        elif kind == "session_index":
            value = {
                "id": session_id,
                "timestamp": "2026-07-06T01:00:00Z",
            }
        else:
            value = {
                "session_id": session_id,
                "timestamp": "2026-07-06T01:00:00Z",
            }
        return (
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")
            + b"\n"
        )

    def _write_sources(self, *session_ids: str) -> None:
        self.codex_root.joinpath("session_index.jsonl").write_bytes(
            b"".join(
                self._line(session_id, kind="session_index")
                for session_id in session_ids
            )
        )
        self.codex_root.joinpath("history.jsonl").write_bytes(
            b"".join(self._line(session_id) for session_id in session_ids)
        )
        active = self.codex_root / "sessions/2026/07/06"
        archived = self.codex_root / "archived_sessions/2026/07/06"
        active.mkdir(mode=0o700, parents=True)
        archived.mkdir(mode=0o700, parents=True)
        for index, session_id in enumerate(session_ids):
            active.joinpath(
                f"rollout-2026-07-06T01-0{index}-00-{session_id}.jsonl"
            ).write_bytes(self._line(session_id, kind="session_meta"))
            archived.joinpath(
                f"rollout-2026-07-06T02-0{index}-00-{session_id}.jsonl"
            ).write_bytes(self._line(session_id, kind="session_meta"))

    def _coordinator(
        self,
        name: str,
        *,
        hosts: tuple[str, ...] = ("local",),
        mode: RunMode = RunMode.DAILY,
        provenance: dict[str, object] | None = None,
        session_target: str | None = None,
        session_target_selector: str | None = None,
        window_start: str = WINDOW_START,
        window_end: str = WINDOW_END,
    ) -> RetrospectiveOrchestrator:
        coordinator = RetrospectiveOrchestrator(
            self.root / name,
            clock=lambda: "2026-07-15T00:00:00Z",
            identity_path=self.root / "identity-v2.key",
        )
        coordinator.start(
            mode=mode,
            start=window_start,
            end=window_end,
            hosts=hosts,
            session_target=session_target,
            session_target_selector=session_target_selector,
            created_at="2026-07-15T00:00:00Z",
            history_repo=self.root / "history",
            history_target_ref="refs/heads/main",
            provenance=provenance or execution_provenance(),
            shadow=True,
        )
        return coordinator

    def _first_lease(self, coordinator: RetrospectiveOrchestrator) -> dict[str, object]:
        for _ in range(4):
            leases = coordinator.status()["active_source_leases"]
            if leases:
                return leases[0]
            coordinator.advance()
        self.fail("source lease was not scheduled")

    def _capture_prepare_accept(
        self,
        coordinator: RetrospectiveOrchestrator,
        lease_view: dict[str, object],
        *,
        environment: dict[str, str] | None = None,
    ) -> dict[str, object]:
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        completed = subprocess.run(
            list(lease.command_argv),
            check=False,
            capture_output=True,
            env=environment,
        )
        self.assertEqual(
            0,
            completed.returncode,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        preparation = coordinator.prepare_source(
            lease.lease_ref,
            completed.stdout.splitlines(keepends=True),
        )
        return coordinator.accept_source(
            lease.lease_ref,
            preparation.manifest,
            transport_receipt=preparation.receipt,
            raw_records=preparation.raw_records,
        )

    def _direct_source_frames(
        self,
        name: str,
        *,
        source_kind: str,
        max_records: int,
        max_source_bytes: int = 16 * 1024 * 1024,
        resume_position: dict[str, object] | None = None,
        window_start: str = WINDOW_START,
        window_end: str = WINDOW_END,
    ) -> list[dict[str, object]]:
        output_path = self.root / f"{name}.jsonl"
        lease_ref = str(self.identity.derive_ref(RefType.LEASE, {"case": name}))
        arguments = [
            "source-transport",
            "--host",
            "local",
            "--source-kind",
            source_kind,
            "--window-start",
            window_start,
            "--window-end",
            window_end,
            "--lease-ref",
            lease_ref,
            "--process-nonce",
            name,
            "--max-source-bytes",
            str(max_source_bytes),
            "--max-records",
            str(max_records),
            "--max-frame-bytes",
            "8192",
            "--direct-root",
            str(self.codex_root),
        ]
        if resume_position is not None:
            arguments.extend(
                (
                    "--resume-position",
                    transport.encode_source_resume_position(resume_position),
                )
            )
        with (
            output_path.open("w", encoding="ascii") as output,
            mock.patch.object(sys, "stdout", output),
        ):
            self.assertEqual(
                0,
                transport_source._run_private_transport_worker(arguments),
            )
        return [
            json.loads(line)
            for line in output_path.read_text(encoding="ascii").splitlines()
        ]

    def _direct_source_lease(
        self,
        name: str,
        *,
        source_kind: str,
        max_records: int,
        max_source_bytes: int = 16 * 1024 * 1024,
        resume_position: dict[str, object] | None = None,
    ) -> transport.TransportLease:
        return transport.issue_transport_lease(
            self.identity,
            lease_ref=str(self.identity.derive_ref(RefType.LEASE, {"case": name})),
            run_ref=str(self.identity.derive_ref(RefType.RUN, {"case": name})),
            job_ref=str(self.identity.derive_ref(RefType.JOB, {"case": name})),
            host="local",
            host_ref=str(self.identity.derive_ref(RefType.HOST, {"host": "local"})),
            source_kind=source_kind,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            process_nonce=name,
            command_argv=("python3.13", "transport_worker.py"),
            transport_program_commitment="sha256:" + "0" * 64,
            source_byte_limit=max_source_bytes,
            record_limit=max_records,
            frame_byte_limit=8192,
            session_target=None,
            source_cursor=None,
            cursor_time=None,
            resume_position=resume_position,
        )

    def _complete_native_sources(
        self,
        name: str,
        *,
        window_start: str = WINDOW_START,
        window_end: str = WINDOW_END,
    ) -> dict[str, object]:
        coordinator = self._coordinator(
            name,
            window_start=window_start,
            window_end=window_end,
        )
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            for _ in range(32):
                status = coordinator.status()
                if status["stage"] != "source_catalog":
                    break
                leases = status["active_source_leases"]
                if not leases:
                    coordinator.advance()
                    continue
                environment = dict(os.environ)
                environment["HOME"] = str(self.home)
                for lease in leases:
                    self._capture_prepare_accept(
                        coordinator,
                        lease,
                        environment=environment,
                    )
            else:
                self.fail("native source loop did not terminate")
        if coordinator.status()["stage"] == "source_catalog":
            coordinator.advance()
        return coordinator.store.read().state

    def test_all_source_kinds_execute_and_session_mode_filters_every_record(
        self,
    ) -> None:
        self._write_sources("target-session", "other-session")
        target_payload = (
            b'{"payload":{"content":"TargetEvidence","role":"user"},'
            b'"session_id":"target-session",'
            b'"timestamp":"2026-07-06T03:00:00Z",'
            b'"type":"response_item"}\n'
        )
        other_payload = (
            b'{"payload":{"content":"AcmeNonTargetSecret","role":"user"},'
            b'"session_id":"other-session",'
            b'"timestamp":"2026-07-06T03:00:00Z",'
            b'"type":"response_item"}\n'
        )
        history_path = self.codex_root / "history.jsonl"
        history_path.write_bytes(
            history_path.read_bytes() + target_payload + other_payload
        )
        self.codex_root.joinpath(
            "sessions/2026/07/06/rollout-2026-07-06T03-00-00-target-copy.jsonl"
        ).write_bytes(
            self._line("target-session", kind="session_meta") + target_payload
        )
        other_rollout = self.codex_root.joinpath(
            "sessions/2026/07/06/rollout-2026-07-06T01-01-00-other-session.jsonl"
        )
        other_rollout.write_bytes(other_rollout.read_bytes() + other_payload)
        target = str(
            self.identity.derive_ref(
                RefType.SESSION,
                {"session_id": "target-session"},
            )
        )
        coordinator = self._coordinator(
            "session-run",
            mode=RunMode.SESSION,
            session_target=target,
            session_target_selector="target-session",
        )
        observed_kinds: set[str] = set()
        observed_contracts: dict[str, str] = {}
        inventory_counts: dict[str, int] = {}
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            for _ in range(16):
                state = coordinator.store.read().state
                cells = state["source"]["cells"]["local"]
                if all(
                    cell["status"] in {"complete", "no_activity"}
                    for cell in cells.values()
                ):
                    break
                status = coordinator.status()
                leases = status["active_source_leases"]
                if not leases:
                    coordinator.advance()
                    continue
                lease = leases[0]
                observed_kinds.add(lease["source_kind"])
                observed_contracts[lease["source_kind"]] = lease["source_contract"]
                self.assertEqual("run_directory", lease["coordinator_cwd_contract"])
                actions = lease["native_coordinator_actions"]
                self.assertEqual(
                    [
                        "capture-source-transport",
                        "accept-source",
                    ],
                    [action["action"] for action in actions],
                )
                self.assertNotIn("execute-source", json.dumps(lease))
                environment = dict(os.environ)
                environment["HOME"] = str(self.home)
                transport_lease = transport.TransportLease.from_dict(
                    lease["transport_lease"]
                )
                completed = subprocess.run(
                    list(transport_lease.command_argv),
                    check=True,
                    capture_output=True,
                    env=environment,
                )
                self.assertNotIn(b"AcmeNonTargetSecret", completed.stdout)
                capture = transport.capture_source_transport(
                    completed.stdout.splitlines(keepends=True),
                    lease=transport_lease,
                )
                inventory_counts[lease["source_kind"]] = len(capture.inventory)
                for record in capture.records:
                    self.assertNotIn(b"AcmeNonTargetSecret", record.payload)
                preparation = coordinator.prepare_source(
                    transport_lease.lease_ref,
                    completed.stdout.splitlines(keepends=True),
                )
                coordinator.accept_source(
                    transport_lease.lease_ref,
                    preparation.manifest,
                    transport_receipt=preparation.receipt,
                    raw_records=preparation.raw_records,
                )
            else:
                self.fail("source execution did not terminate")

        self.assertEqual(
            {"session_index", "history", "active_rollout", "archived_rollout"},
            observed_kinds,
        )
        self.assertEqual(
            "bounded_metadata_jsonl_v2", observed_contracts["session_index"]
        )
        self.assertEqual("bounded_metadata_jsonl_v2", observed_contracts["history"])
        self.assertEqual(
            "bounded_rollout_jsonl_v2", observed_contracts["active_rollout"]
        )
        self.assertEqual(
            "bounded_rollout_jsonl_v2", observed_contracts["archived_rollout"]
        )
        state = coordinator.store.read().state
        excluded = 0
        for cell in state["source"]["cells"]["local"].values():
            manifest, _snapshot_ref, _receipt_ref = source_inputs.aggregate_segments(
                coordinator.identity,
                coordinator.run_dir,
                cell["continuation_segments"],
            )
            self.assertGreaterEqual(len(manifest.records), 1)
            self.assertTrue(
                all(
                    record.coordinate.source_ref == target
                    for record in manifest.records
                    if record.accounting_class
                    is catalog.AccountingClass.CONSUMED_CANDIDATE
                )
            )
            excluded += sum(
                record.accounting_class is catalog.AccountingClass.STRUCTURALLY_EXCLUDED
                and record.exclusion_reason
                is catalog.StructuralExclusionReason.SOURCE_POLICY_EXCLUDED
                for record in manifest.records
            )
            self.assertEqual(
                len(manifest.records),
                len({record.unit_ref for record in manifest.records}),
            )
            self.assertEqual(
                inventory_counts[manifest.source_kind.value],
                len(manifest.records),
            )
        self.assertGreater(excluded, 0)
        raw_paths = []
        for cell in state["source"]["cells"]["local"].values():
            materialized = source_inputs.materialize_segments(
                coordinator.run_dir,
                cell["continuation_segments"],
            )
            raw_paths.extend(
                coordinator.run_dir / payload["relative_path"]
                for payload in materialized["payloads"].values()
                if payload.get("status") == "available"
            )
        self.assertTrue(raw_paths)
        self.assertNotIn(
            b"AcmeNonTargetSecret",
            b"".join(path.read_bytes() for path in raw_paths),
        )
        coordinator.advance()
        reassembly = coordinator.store.read().state["source"]["reassembly"]
        self.assertEqual(
            [0, 1], sorted(item["sequence"] for item in reassembly.values())
        )
        self.assertEqual(
            {target},
            {item["session_ref"] for item in reassembly.values()},
        )

    def test_truncated_stream_and_unissued_receipt_cannot_advance_cursor(self) -> None:
        self._write_sources("target-session")
        coordinator = self._coordinator("forgery-run")
        lease_view = self._first_lease(coordinator)
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            completed = subprocess.run(
                list(lease.command_argv),
                check=True,
                capture_output=True,
            )
        lines = completed.stdout.splitlines(keepends=True)
        capture = transport.capture_source_transport(lines, lease=lease)
        self.assertEqual(SourceCellStatus.NO_ACTIVITY, capture.terminal_status)
        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "terminal proof",
        ):
            transport.capture_source_transport(lines[:-1], lease=lease)

        manifest = catalog.SourceTransportManifest.create(
            host_ref=lease.host_ref,
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=lease.source_kind,
            window_start=lease.window_start,
            window_end=lease.window_end,
            status=SourceCellStatus.NO_ACTIVITY,
            records=(),
            snapshot_commitment=catalog.snapshot_commitment_for_records(()),
        )
        transcript = transport.transcript_commitment({}, source_marker=lease.lease_ref)
        snapshot = transport.AuthoritativeSourceSnapshot.create(
            host_ref=lease.host_ref,
            source_kind=lease.source_kind,
            window_start=lease.window_start,
            window_end=lease.window_end,
            session_target=lease.session_target,
            source_content_commitment=transcript,
            source_byte_count=0,
            terminal_byte_offset=0,
            catalog_record_count=0,
            catalog_byte_count=0,
            catalog_commitment=manifest.snapshot_commitment,
            transcript_commitment=transcript,
            terminal_proof_commitment="sha256:" + "1" * 64,
            terminal_status=SourceCellStatus.NO_ACTIVITY,
            terminal_reason="authoritative_empty_snapshot",
            complete=True,
            resume_position=None,
        )
        forged = transport.issue_transport_receipt(
            coordinator.identity,
            lease=lease,
            manifest=manifest.to_dict(),
            source_snapshot=snapshot,
        )
        before = coordinator.store.read().state
        before_cursor = json.loads(json.dumps(before["cursors"]["local"]))
        with self.assertRaisesRegex(InvalidInputError, "execution boundary"):
            coordinator.accept_source(
                lease.lease_ref,
                manifest.to_dict(),
                transport_receipt=forged.to_dict(),
            )
        after = coordinator.store.read().state
        self.assertEqual(before_cursor, after["cursors"]["local"])
        self.assertEqual(
            "leased",
            after["source"]["cells"]["local"][lease.source_kind.value]["status"],
        )

    def test_native_transport_command_uses_isolated_python(self) -> None:
        self._write_sources("target-session")
        poison = self.root / "pythonpath-poison"
        poison.mkdir(mode=0o700)
        poison.joinpath("sitecustomize.py").write_text(
            "raise RuntimeError('transport startup injection executed')\n",
            encoding="utf-8",
        )
        coordinator = self._coordinator("sanitized-environment")
        lease_view = self._first_lease(coordinator)

        with mock.patch.dict(
            os.environ,
            {"HOME": str(self.home), "PYTHONPATH": str(poison)},
        ):
            result = self._capture_prepare_accept(
                coordinator,
                lease_view,
                environment=dict(os.environ),
            )

        self.assertTrue(result["accepted"])
        self.assertEqual("complete", result["outcome"])
        command = lease_view["transport_lease"]["command_argv"]
        self.assertEqual(
            list(transport_program.SOURCE_TRANSPORT_BASE_PYTHON_FLAGS),
            command[1:6],
        )
        self.assertEqual("-c", command[6])
        self.assertEqual(transport_program.SOURCE_TRANSPORT_SNAPSHOT_SCHEMA, command[8])
        self.assertTrue(command[9].startswith("sha256:"))
        self.assertTrue(Path(command[10]).is_file())
        accept_command = lease_view["native_coordinator_actions"][1]["command"]
        self.assertEqual(command[0], accept_command[0])
        self.assertEqual("-B", accept_command[1])
        isolated = subprocess.run(
            [
                sys.executable,
                *transport_program.SOURCE_TRANSPORT_BASE_PYTHON_FLAGS,
                "-c",
                "import sys;print(sys.flags.no_site)",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual("1", isolated.stdout.strip())
        missing_no_site = subprocess.run(
            [component for component in command if component != "-S"],
            check=False,
            capture_output=True,
            env={"HOME": str(self.home), "PATH": os.defpath},
            text=True,
            timeout=30,
        )
        self.assertNotEqual(0, missing_no_site.returncode)
        self.assertIn(
            "source transport Python isolation failed", missing_no_site.stderr
        )

    def test_native_transport_ignores_uncommitted_unchecked_hash_bytecode(
        self,
    ) -> None:
        package = self.root / "pycache-attack"
        package.mkdir(mode=0o700)
        source = package / "victim.py"
        malicious = package / "malicious.py"
        source.write_text("print('source-module')\n", encoding="ascii")
        malicious.write_text("print('unchecked-bytecode')\n", encoding="ascii")
        cache = package / "__pycache__" / f"victim.{sys.implementation.cache_tag}.pyc"
        cache.parent.mkdir(mode=0o700)
        py_compile.compile(
            str(malicious),
            cfile=str(cache),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        script = f"import sys; sys.path.insert(0, {str(package)!r}); import victim"

        unsafe = subprocess.run(
            [sys.executable, "-I", "-B", "-c", script],
            check=True,
            capture_output=True,
            text=True,
        )
        safe = subprocess.run(
            [
                sys.executable,
                *transport_program.SOURCE_TRANSPORT_BASE_PYTHON_FLAGS,
                "-c",
                script,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual("unchecked-bytecode", unsafe.stdout.strip())
        self.assertEqual("source-module", safe.stdout.strip())

    def test_remote_helper_uses_isolated_python_and_sanitized_environment(
        self,
    ) -> None:
        helper = self.root / "remote-helper.py"
        helper.write_text("print('{}')\n", encoding="ascii")
        snapshot, commitment = (
            transport_remote_snapshot.snapshot_remote_host_context_helper(
                helper,
                self.root / "remote-helper-snapshots",
            )
        )
        poison = self.root / "remote-pythonpath-poison"
        poison.mkdir(mode=0o700)
        poison.joinpath("sitecustomize.py").write_text(
            "raise RuntimeError('remote helper injection executed')\n",
            encoding="ascii",
        )
        arguments = mock.Mock(
            remote_helper=str(snapshot),
            remote_helper_commitment=commitment,
            host="remote.example",
        )
        command = transport._remote_host_context_command(arguments, "probe", ())
        account = pwd.getpwuid(os.getuid())
        ssh_auth_sock = str(self.root / "agent.sock")

        self.assertEqual("-I", command[1])
        self.assertEqual("-B", command[2])
        self.assertEqual("-S", command[3])
        self.assertEqual(
            transport_snapshot.REMOTE_HOST_CONTEXT_SNAPSHOT_SCHEMA, command[8]
        )
        self.assertEqual(commitment, command[9])
        self.assertEqual(str(snapshot), command[10])
        self.assertEqual(0o600, snapshot.stat().st_mode & 0o777)
        missing_no_site = subprocess.run(
            [component for component in command if component != "-S"],
            check=False,
            capture_output=True,
            env=transport._remote_host_context_environment(),
            text=True,
            timeout=30,
        )
        self.assertNotEqual(0, missing_no_site.returncode)
        self.assertIn("remote helper Python isolation failed", missing_no_site.stderr)
        with (
            mock.patch.dict(
                os.environ,
                {
                    "BASH_ENV": str(poison / "bash-env"),
                    "DYLD_INSERT_LIBRARIES": str(poison / "inject.dylib"),
                    "GIT_CONFIG_GLOBAL": str(poison / "gitconfig"),
                    "HOME": str(poison),
                    "LD_PRELOAD": str(poison / "inject.so"),
                    "PYTHONHOME": str(poison),
                    "PYTHONPATH": str(poison),
                    "PYTHONSTARTUP": str(poison / "sitecustomize.py"),
                    "SSH_ASKPASS": str(poison / "askpass"),
                    "SSH_AUTH_SOCK": ssh_auth_sock,
                },
                clear=True,
            ),
            mock.patch.object(transport_remote, "_relay_valid_utf8"),
        ):
            environment = transport._remote_host_context_environment()
            transport._relay_remote_host_context_command(
                command,
                max_output_bytes=1024,
            )

        self.assertEqual(
            {
                "HOME": account.pw_dir,
                "LANG": "C",
                "LC_ALL": "C",
                "LOGNAME": account.pw_name,
                "PATH": transport_remote.REMOTE_HOST_CONTEXT_FIXED_PATH,
                "SSH_AUTH_SOCK": ssh_auth_sock,
                "USER": account.pw_name,
            },
            environment,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"SSH_AUTH_SOCK": "relative-agent.sock"},
                clear=True,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "authentication environment is invalid",
            ),
        ):
            transport._remote_host_context_environment()

    def test_remote_helper_launch_uses_run_owned_snapshot_after_live_replacement(
        self,
    ) -> None:
        helper = self.root / "live-remote-helper.py"
        helper.write_text("print('original-helper')\n", encoding="ascii")
        snapshot, commitment = (
            transport_remote_snapshot.snapshot_remote_host_context_helper(
                helper,
                self.root / "remote-helper-snapshots",
            )
        )
        helper.write_text("print('replacement-helper')\n", encoding="ascii")
        arguments = mock.Mock(
            remote_helper=str(snapshot),
            remote_helper_commitment=commitment,
            host="remote.example",
        )

        completed = subprocess.run(
            transport._remote_host_context_command(arguments, "probe", ()),
            check=True,
            capture_output=True,
            env=transport._remote_host_context_environment(),
            text=True,
        )

        self.assertEqual("original-helper", completed.stdout.strip())
        self.assertNotEqual(helper.read_bytes(), snapshot.read_bytes())

    def test_remote_lease_rejects_helper_replaced_after_run_provenance(
        self,
    ) -> None:
        helper = self.root / "run-bound-remote-helper.py"
        helper.write_text("print('original-helper')\n", encoding="ascii")
        provenance = execution_provenance()
        provenance["transport"]["remote_host_context_helper_commitment"] = (
            transport.remote_host_context_helper_commitment(helper)
        )
        with (
            mock.patch.object(orchestrator_module, "DEFAULT_HOSTS", ("remote",)),
            mock.patch.object(
                transport_remote,
                "remote_host_context_helper_path",
                return_value=helper,
            ),
            mock.patch.object(
                transport,
                "remote_host_context_helper_path",
                return_value=helper,
            ),
        ):
            coordinator = self._coordinator(
                "remote-helper-run-provenance",
                hosts=("remote",),
                provenance=provenance,
            )
            helper.write_text("print('replacement-helper')\n", encoding="ascii")

            with self.assertRaisesRegex(
                transport.TransportValidationError,
                "differs from the run provenance",
            ):
                self._first_lease(coordinator)

            state = coordinator.load_state()
            self.assertEqual({}, state["jobs"])
            self.assertTrue(
                all(
                    cell["status"] == "pending"
                    for cell in state["source"]["cells"]["remote"].values()
                )
            )

    def test_remote_helper_launch_rejects_snapshot_changed_after_command_binding(
        self,
    ) -> None:
        helper = self.root / "bound-remote-helper.py"
        helper.write_text("print('original-helper')\n", encoding="ascii")
        snapshot, commitment = (
            transport_remote_snapshot.snapshot_remote_host_context_helper(
                helper,
                self.root / "remote-helper-snapshots",
            )
        )
        arguments = mock.Mock(
            remote_helper=str(snapshot),
            remote_helper_commitment=commitment,
            host="remote.example",
        )
        command = transport._remote_host_context_command(arguments, "probe", ())
        snapshot.write_text("print('replacement-helper')\n", encoding="ascii")
        os.chmod(snapshot, 0o600)

        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=transport._remote_host_context_environment(),
            text=True,
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("snapshot authentication failed", completed.stderr)

    def test_remote_helper_bootstrap_revalidates_access_policy_after_read(
        self,
    ) -> None:
        payload = b"pass\n"
        first = types.SimpleNamespace(
            st_dev=1,
            st_gid=os.getegid(),
            st_ino=2,
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=1,
            st_size=len(payload),
            st_uid=os.geteuid(),
        )
        changed = types.SimpleNamespace(**vars(first))
        changed.st_mode = stat.S_IFREG | 0o644
        fake_os = types.ModuleType("os")
        fake_os.O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
        fake_os.O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
        fake_os.O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
        fake_os.O_RDONLY = os.O_RDONLY
        fake_os.close = mock.Mock()
        fake_os.fstat = mock.Mock(side_effect=(first, changed))
        fake_os.geteuid = os.geteuid
        fake_os.open = mock.Mock(return_value=7)
        fake_os.read = mock.Mock(side_effect=(payload, b""))
        fake_os.stat = mock.Mock(side_effect=(first, changed))
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()

        with (
            mock.patch.dict(sys.modules, {"os": fake_os}),
            mock.patch.object(
                sys,
                "flags",
                types.SimpleNamespace(
                    isolated=1,
                    no_site=1,
                    dont_write_bytecode=1,
                ),
            ),
            mock.patch.object(
                sys,
                "argv",
                [
                    "bootstrap",
                    transport_snapshot.REMOTE_HOST_CONTEXT_SNAPSHOT_SCHEMA,
                    digest,
                    str(self.root / "snapshot.py"),
                ],
            ),
            self.assertRaisesRegex(SystemExit, "snapshot authentication failed"),
        ):
            exec(
                transport_snapshot._REMOTE_HELPER_BOOTSTRAP_SOURCE,
                {"__name__": "__main__"},
            )

        self.assertEqual(2, fake_os.fstat.call_count)
        self.assertEqual(2, fake_os.stat.call_count)

    def test_prepare_source_rejects_remote_snapshot_changed_after_output_capture(
        self,
    ) -> None:
        helper = self.root / "failing-remote-helper.py"
        helper.write_text("raise SystemExit(1)\n", encoding="ascii")
        provenance = execution_provenance()
        provenance["transport"]["remote_host_context_helper_commitment"] = (
            transport.remote_host_context_helper_commitment(helper)
        )
        with (
            mock.patch.object(orchestrator_module, "DEFAULT_HOSTS", ("remote",)),
            mock.patch.object(
                transport_remote,
                "remote_host_context_helper_path",
                return_value=helper,
            ),
            mock.patch.object(
                transport,
                "remote_host_context_helper_path",
                return_value=helper,
            ),
        ):
            coordinator = self._coordinator(
                "remote-snapshot-before-acceptance",
                hosts=("remote",),
                provenance=provenance,
            )
            lease = transport.TransportLease.from_dict(
                self._first_lease(coordinator)["transport_lease"]
            )
            completed = subprocess.run(
                list(lease.command_argv),
                check=True,
                capture_output=True,
                env={**os.environ, "HOME": str(self.home)},
            )
            helper_index = lease.command_argv.index("--remote-helper") + 1
            snapshot = Path(lease.command_argv[helper_index])
            before = json.loads(json.dumps(coordinator.load_state()["cursors"]))
            snapshot.write_text("raise SystemExit(2)\n", encoding="ascii")
            os.chmod(snapshot, 0o600)

            with self.assertRaisesRegex(
                InvalidInputError,
                "program cannot be authenticated",
            ):
                coordinator.prepare_source(
                    lease.lease_ref,
                    completed.stdout.splitlines(keepends=True),
                )

            self.assertEqual(before, coordinator.load_state()["cursors"])

    def test_remote_helper_timeout_terminates_descendant_process_group(self) -> None:
        helper = self.root / "remote-helper-with-child.py"
        helper.write_text(
            "import subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-I', '-c', "
            "'import time; time.sleep(2)'], stdout=sys.stdout)\n",
            encoding="ascii",
        )
        started = time.monotonic()

        with (
            mock.patch.object(
                transport_remote,
                "REMOTE_HOST_CONTEXT_COMMAND_TIMEOUT_SECONDS",
                0.25,
            ),
            self.assertRaisesRegex(RuntimeError, "transport unavailable"),
        ):
            transport._relay_remote_host_context_command(
                (sys.executable, "-I", str(helper)),
                max_output_bytes=1024,
            )

        self.assertLess(time.monotonic() - started, 1.5)

    def test_remote_helper_timeout_closes_detached_inherited_stdout(self) -> None:
        helper = self.root / "remote-helper-with-detached-writer.py"
        helper.write_text(
            "import subprocess, sys\n"
            "subprocess.Popen(\n"
            "    [sys.executable, '-I', '-c', 'import time; time.sleep(1)'],\n"
            "    stdout=sys.stdout,\n"
            "    start_new_session=True,\n"
            ")\n"
            "print('{}')\n",
            encoding="ascii",
        )
        started = time.monotonic()

        with (
            mock.patch.object(
                transport_remote,
                "REMOTE_HOST_CONTEXT_COMMAND_TIMEOUT_SECONDS",
                0.1,
            ),
            self.assertRaisesRegex(RuntimeError, "transport unavailable"),
        ):
            transport._relay_remote_host_context_command(
                (sys.executable, "-I", str(helper)),
                max_output_bytes=1024,
            )

        self.assertLess(time.monotonic() - started, 0.75)

    def test_remote_helper_success_closes_detached_output_descendant(self) -> None:
        helper = self.root / "remote-helper-detached-child.py"
        child_pid_path = self.root / "remote-helper-detached-child.pid"
        helper.write_text(
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            "    [sys.executable, '-I', '-c', 'import time; time.sleep(60)'],\n"
            "    stdin=subprocess.DEVNULL,\n"
            "    stdout=subprocess.DEVNULL,\n"
            "    stderr=subprocess.DEVNULL,\n"
            ")\n"
            "with open(sys.argv[1], 'w', encoding='ascii') as stream:\n"
            "    stream.write(str(child.pid))\n"
            "print('{}')\n",
            encoding="ascii",
        )

        with mock.patch.object(transport_remote, "_relay_valid_utf8"):
            transport._relay_remote_host_context_command(
                (sys.executable, "-I", str(helper), str(child_pid_path)),
                max_output_bytes=1024,
            )

        child_pid = int(child_pid_path.read_text(encoding="ascii"))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail(f"remote helper descendant survived: {child_pid}")

    def test_line_reader_is_bounded_before_allocation(self) -> None:
        class GuardedStream(io.BytesIO):
            maximum_request = 0

            def readline(self, size: int = -1) -> bytes:
                if size < 0 or size > transport.SOURCE_TRANSPORT_SCAN_CHUNK_BYTES:
                    raise AssertionError(
                        "line reader requested an unbounded allocation"
                    )
                self.maximum_request = max(self.maximum_request, size)
                return super().readline(size)

        payload = b"x" * 4097 + b"\n"
        stream = GuardedStream(payload)
        line = transport._read_bounded_line(
            stream,
            max_payload_bytes=1024,
            max_scan_bytes=len(payload),
        )

        self.assertTrue(line.complete)
        self.assertTrue(line.oversized)
        self.assertIsNone(line.payload)
        self.assertEqual(len(payload), line.byte_count)
        self.assertLessEqual(
            stream.maximum_request,
            transport.SOURCE_TRANSPORT_SCAN_CHUNK_BYTES,
        )

    def test_generic_agent_roles_remain_evidence_candidates(self) -> None:
        for role in ("worker", "coordinator"):
            with self.subTest(role=role):
                self.assertIsNone(
                    transport_source._source_structural_exclusion(
                        {
                            "payload": {"content": "ordinary evidence", "role": role},
                            "type": "response_item",
                        },
                        source_kind=SourceKind.ACTIVE_ROLLOUT,
                    )
                )

        for role, expected in (
            ("retrospective_worker", "retrospective_worker"),
            ("session_retrospective_coordinator", "retrospective_coordinator"),
        ):
            with self.subTest(role=role):
                self.assertEqual(
                    expected,
                    transport_source._source_structural_exclusion(
                        {
                            "payload": {"content": "control output", "role": role},
                            "type": "response_item",
                        },
                        source_kind=SourceKind.ACTIVE_ROLLOUT,
                    ),
                )

    def test_metadata_is_filtered_before_copy_and_inventory_is_closed(self) -> None:
        before = self._line("before", kind="session_index").replace(
            b"2026-07-06T01:00:00Z",
            b"2026-07-05T23:59:59Z",
        )
        inside = b'{"id":"inside","updated_at":"2026-07-06T02:00:00Z"}\n'
        after = self._line("after", kind="session_index").replace(
            b"2026-07-06T01:00:00Z",
            b"2026-07-07T00:00:00Z",
        )
        self.codex_root.joinpath("session_index.jsonl").write_bytes(
            before + inside + after
        )
        coordinator = self._coordinator("metadata-window")
        lease_view = self._first_lease(coordinator)
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            completed = subprocess.run(
                list(lease.command_argv),
                check=True,
                capture_output=True,
                env=dict(os.environ),
            )
        lines = completed.stdout.splitlines(keepends=True)
        capture = transport.capture_source_transport(lines, lease=lease)

        self.assertEqual((), tuple(record.payload for record in capture.records))
        self.assertEqual(
            {
                "consumed_candidate": 0,
                "explicit_gap": 0,
                "structurally_excluded": 3,
            },
            {
                key: sum(item["accounting_class"] == key for item in capture.inventory)
                for key in (
                    "consumed_candidate",
                    "explicit_gap",
                    "structurally_excluded",
                )
            },
        )
        without_inventory = [
            line for line in lines if json.loads(line).get("frame") != "inventory"
        ]
        with self.assertRaises(transport.TransportValidationError):
            transport.capture_source_transport(without_inventory, lease=lease)

    def test_cursor_filter_and_bounded_complete_active_rollout_discovery(self) -> None:
        host_ref = str(self.identity.derive_ref(RefType.HOST, {"parts": ["local"]}))
        cursor_rows = (
            {
                "backlog_ref": None,
                "cursor_ref": "source_ref_v2:" + "c" * 64,
                "host_ref": host_ref,
                "logical_boundary": "2026-07-05T12:00:00Z",
            },
        )
        self.history = replace(
            self.history,
            cursor_root_ref=authority.derive_cursor_root(cursor_rows),
            cursor_rows=cursor_rows,
        )
        self.codex_root.joinpath("session_index.jsonl").write_bytes(
            self._line("before-cursor", kind="session_index").replace(
                b"2026-07-06T01:00:00Z",
                b"2026-07-05T11:59:59Z",
            )
            + self._line("after-cursor", kind="session_index")
        )
        coordinator = self._coordinator("cursor-window")
        lease_view = self._first_lease(coordinator)
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        self.assertEqual(cursor_rows[0]["cursor_ref"], lease.source_cursor)
        self.assertEqual("2026-07-05T12:00:00Z", lease.cursor_time)
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            completed = subprocess.run(
                list(lease.command_argv),
                check=True,
                capture_output=True,
                env=dict(os.environ),
            )
        capture = transport.capture_source_transport(
            completed.stdout.splitlines(keepends=True),
            lease=lease,
        )
        self.assertEqual("before_cursor", capture.inventory[0]["reason"])
        self.assertEqual(0, len(capture.records))

        old = self.codex_root / "sessions/2010/01/01"
        current = self.codex_root / "sessions/2026/07/06"
        old.mkdir(parents=True, mode=0o700)
        current.mkdir(parents=True, mode=0o700)
        for index in range(3):
            old_file = old / (f"rollout-2010-01-02T00-00-0{index}-old-{index}.jsonl")
            old_file.write_bytes(b"{}\n")
            old_timestamp = dt.datetime(2010, 1, 2, tzinfo=dt.timezone.utc).timestamp()
            os.utime(old_file, (old_timestamp, old_timestamp))
        continued = old / "rollout-2010-01-02T00-01-00-old-continued.jsonl"
        continued.write_bytes(
            self._line("continued", kind="response_item").replace(
                b'"kind":"response_item"',
                b'"kind":"response_item","role":"user","content":"continued"',
            )
        )
        os.utime(continued, (old_timestamp, old_timestamp))
        previous = self.codex_root / "sessions/2026/07/05"
        previous.mkdir(parents=True, mode=0o700)
        previous_rollout = previous / "rollout-previous-cross-day.jsonl"
        previous_rollout.write_bytes(self._line("previous-cross-day"))
        for index in range(3):
            current.joinpath(f"rollout-current-{index}.jsonl").write_bytes(
                self._line(f"current-{index}", kind="session_meta")
            )
        start = dt.datetime(2026, 7, 6, tzinfo=dt.timezone.utc)
        end = dt.datetime(2026, 7, 7, tzinfo=dt.timezone.utc)
        with mock.patch.object(
            Path,
            "rglob",
            side_effect=AssertionError("unbounded recursive discovery used"),
        ):
            bounded = transport._source_transport_candidate_paths(
                self.codex_root,
                "active_rollout",
                window_start=start,
                window_end=end,
                max_candidates=8,
            )
        self.assertIsNone(bounded.gap_reason)
        self.assertEqual(8, len(bounded.candidates))
        self.assertIn(
            "sessions/2026/07/05/rollout-previous-cross-day.jsonl",
            {relative for _path, relative in bounded.candidates},
        )
        self.assertIn(
            "sessions/2010/01/01/rollout-2010-01-02T00-01-00-old-continued.jsonl",
            {relative for _path, relative in bounded.candidates},
        )
        limited = transport._source_transport_candidate_paths(
            self.codex_root,
            "active_rollout",
            window_start=start,
            window_end=end,
            max_candidates=2,
        )
        self.assertEqual(
            "source_discovery_candidate_limit_reached",
            limited.gap_reason,
        )
        self.assertLessEqual(len(limited.candidates), 2)

        output_path = self.root / "bounded-discovery.jsonl"
        lease_ref = str(
            self.identity.derive_ref(RefType.LEASE, {"case": "bounded-discovery"})
        )
        with (
            output_path.open("w", encoding="ascii") as output,
            mock.patch.object(
                sys,
                "stdout",
                output,
            ),
        ):
            exit_code = transport_source._run_private_transport_worker(
                [
                    "source-transport",
                    "--host",
                    "local",
                    "--source-kind",
                    "active_rollout",
                    "--window-start",
                    WINDOW_START,
                    "--window-end",
                    WINDOW_END,
                    "--lease-ref",
                    lease_ref,
                    "--process-nonce",
                    "bounded-discovery",
                    "--max-source-bytes",
                    str(1024 * 1024),
                    "--max-records",
                    "2",
                    "--max-frame-bytes",
                    "8192",
                    "--direct-root",
                    str(self.codex_root),
                ]
            )
        frames = [
            json.loads(line)
            for line in output_path.read_text(encoding="ascii").splitlines()
        ]
        inventory = [frame for frame in frames if frame.get("frame") == "inventory"]
        terminal = frames[-1]
        self.assertEqual(0, exit_code)
        self.assertEqual(2, len(inventory))
        self.assertEqual("gap", terminal["status"])
        self.assertEqual(
            "source_discovery_candidate_limit_reached",
            terminal["reason"],
        )

    def test_active_rollout_directory_change_before_terminal_is_a_gap(self) -> None:
        day = self.codex_root / "sessions/2026/07/06"
        day.mkdir(parents=True, mode=0o700)
        day.joinpath("rollout-existing.jsonl").write_bytes(
            self._line("existing", kind="session_meta")
        )
        late = day / "rollout-late.jsonl"
        original_revalidate = (
            transport_source.transport_discovery.revalidate_directory_snapshots
        )
        mutated = False

        def mutate_then_revalidate(*args, **kwargs):
            nonlocal mutated
            mutated = True
            late.write_bytes(self._line("late", kind="session_meta"))
            original_revalidate(*args, **kwargs)

        with mock.patch.object(
            transport_source.transport_discovery,
            "revalidate_directory_snapshots",
            side_effect=mutate_then_revalidate,
        ):
            frames = self._direct_source_frames(
                "active-directory-change",
                source_kind="active_rollout",
                max_records=16,
            )

        self.assertTrue(mutated)
        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_enumeration_changed", frames[-1]["reason"])
        self.assertIsNone(frames[-1]["resume_position"])

    def test_non_utf8_rollout_locator_is_an_explicit_gap(self) -> None:
        real_read_entries = transport_source.transport_discovery.read_directory_entries

        def inject_surrogate(descriptor, *, observe_entry):
            rows = real_read_entries(descriptor, observe_entry=observe_entry)
            if not rows:
                name = "rollout-\udcff.jsonl"
                observe_entry(name)
                return ((name, False, False, True),)
            return rows

        with mock.patch.object(
            transport_source.transport_discovery,
            "read_directory_entries",
            side_effect=inject_surrogate,
        ):
            frames = self._direct_source_frames(
                "non-utf8-locator",
                source_kind="archived_rollout",
                max_records=16,
            )

        self.assertEqual(2, len(frames))
        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_locator_unrepresentable", frames[-1]["reason"])
        self.assertIsNone(frames[-1]["resume_position"])

    def test_archived_rollout_directory_date_is_not_event_time_authority(
        self,
    ) -> None:
        old_day = self.codex_root / "archived_sessions/2020/01/02"
        old_day.mkdir(parents=True, mode=0o700)
        rollout = old_day / "rollout-old-directory-current-event.jsonl"
        rollout.write_bytes(
            json.dumps(
                {
                    "content": "current event in an old archive directory",
                    "role": "user",
                    "session_id": "old-directory-current-event",
                    "timestamp": "2026-07-06T01:00:00Z",
                    "type": "response_item",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )

        frames = self._direct_source_frames(
            "archive-directory-date",
            source_kind="archived_rollout",
            max_records=8,
        )
        inventory = [frame for frame in frames if frame.get("frame") == "inventory"]

        self.assertTrue(
            any(
                frame["source_locator"]
                == "archived_sessions/2020/01/02/"
                "rollout-old-directory-current-event.jsonl"
                and frame["accounting_class"] == "consumed_candidate"
                for frame in inventory
            )
        )
        self.assertEqual("complete", frames[-1]["status"])

    def test_candidate_same_name_replacement_before_terminal_is_a_gap(self) -> None:
        day = self.codex_root / "sessions/2026/07/06"
        day.mkdir(parents=True, mode=0o700)
        rollout = day / "rollout-replaced.jsonl"
        rollout.write_bytes(self._line("original", kind="session_meta"))
        replacement = day / "replacement.jsonl"
        replacement.write_bytes(self._line("attacker", kind="session_meta"))
        mutated = False

        original_revalidate = (
            transport_source.transport_discovery.revalidate_directory_snapshots
        )

        def replace_before_terminal(*args, **kwargs) -> None:
            nonlocal mutated
            mutated = True
            os.replace(replacement, rollout)
            original_revalidate(*args, **kwargs)

        with mock.patch.object(
            transport_source.transport_discovery,
            "revalidate_directory_snapshots",
            side_effect=replace_before_terminal,
        ):
            frames = self._direct_source_frames(
                "candidate-same-name-replacement",
                source_kind="active_rollout",
                max_records=8,
            )

        self.assertTrue(mutated)
        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_enumeration_changed", frames[-1]["reason"])

    def test_archived_rollout_membership_change_before_terminal_is_a_gap(
        self,
    ) -> None:
        day = self.codex_root / "archived_sessions/2020/01/02"
        day.mkdir(parents=True, mode=0o700)
        day.joinpath("rollout-existing.jsonl").write_bytes(
            self._line("existing", kind="session_meta")
        )
        late = day / "rollout-late.jsonl"
        original_revalidate = (
            transport_source.transport_discovery.revalidate_directory_snapshots
        )

        def mutate_then_revalidate(*args, **kwargs):
            late.write_bytes(self._line("late", kind="session_meta"))
            return original_revalidate(*args, **kwargs)

        with mock.patch.object(
            transport_source.transport_discovery,
            "revalidate_directory_snapshots",
            side_effect=mutate_then_revalidate,
        ):
            frames = self._direct_source_frames(
                "archived-directory-change",
                source_kind="archived_rollout",
                max_records=16,
            )

        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_enumeration_changed", frames[-1]["reason"])

    def test_non_candidate_directory_fanout_hits_bounded_gap(self) -> None:
        sessions = self.codex_root / "sessions"
        sessions.mkdir(mode=0o700)
        for index in range(5):
            sessions.joinpath(f"ignored-entry-{index}").write_text(
                "noise",
                encoding="ascii",
            )

        budget_cases = (
            (
                transport_source.transport_discovery.SourceDiscoveryBudget(
                    entry_limit=4,
                ),
                "source_discovery_entry_limit_reached",
            ),
            (
                transport_source.transport_discovery.SourceDiscoveryBudget(
                    entry_limit=100,
                    path_byte_limit=8,
                ),
                "source_discovery_path_limit_reached",
            ),
        )
        for budget, expected_reason in budget_cases:
            with self.subTest(expected_reason=expected_reason):
                with mock.patch.object(
                    transport_source.transport_discovery,
                    "SourceDiscoveryBudget",
                    return_value=budget,
                ):
                    discovery = transport._source_transport_candidate_paths(
                        self.codex_root,
                        "active_rollout",
                        window_start=dt.datetime(2026, 7, 6, tzinfo=dt.timezone.utc),
                        window_end=dt.datetime(2026, 7, 7, tzinfo=dt.timezone.utc),
                        max_candidates=100,
                    )
                try:
                    self.assertEqual(
                        expected_reason,
                        discovery.gap_reason,
                    )
                    self.assertEqual((), discovery.candidates)
                finally:
                    discovery.close()

    def test_source_discovery_deadline_is_fixed_and_injectable(self) -> None:
        now = [0.0]
        budget = transport_source.transport_discovery.SourceDiscoveryBudget(
            timeout_seconds=1.0,
            clock=lambda: now[0],
        )
        budget.observe("sessions", "2026")
        now[0] = 1.0

        with self.assertRaisesRegex(
            transport_source.transport_discovery.SourceDiscoveryBudgetExceeded,
            "source_discovery_deadline_reached",
        ):
            budget.checkpoint()

    def test_directory_snapshot_closes_duplicated_scan_descriptor(self) -> None:
        directory = self.root / "descriptor-snapshot"
        directory.mkdir(mode=0o700)
        directory.joinpath("entry").write_text("value", encoding="ascii")
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        duplicated: list[int] = []
        real_dup = os.dup

        def track_dup(value: int) -> int:
            opened = real_dup(value)
            duplicated.append(opened)
            return opened

        try:
            with mock.patch.object(
                transport_source.transport_discovery.os,
                "dup",
                side_effect=track_dup,
            ):
                entries = transport_source.transport_discovery.read_directory_entries(
                    descriptor
                )
        finally:
            os.close(descriptor)

        self.assertEqual((("entry", False, False, True),), entries)
        self.assertEqual(1, len(duplicated))
        with self.assertRaises(OSError):
            os.fstat(duplicated[0])

    def test_root_open_is_inside_the_discovery_deadline(self) -> None:
        now = [0.0]
        budget = transport_source.transport_discovery.SourceDiscoveryBudget(
            timeout_seconds=1.0,
            clock=lambda: now[0],
        )

        def expire_after_component_open(*_args) -> None:
            now[0] = 1.0

        with (
            mock.patch.object(
                transport_source.transport_discovery,
                "SourceDiscoveryBudget",
                return_value=budget,
            ),
            mock.patch.object(
                transport_source,
                "_SOURCE_TRANSPORT_OPEN_COMPONENT_HOOK",
                side_effect=expire_after_component_open,
                create=True,
            ),
        ):
            frames = self._direct_source_frames(
                "root-open-deadline",
                source_kind="history",
                max_records=8,
            )

        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_discovery_deadline_reached", frames[-1]["reason"])

    def test_missing_codex_root_is_an_explicit_gap(self) -> None:
        self.codex_root.rmdir()

        frames = self._direct_source_frames(
            "missing-codex-root",
            source_kind="history",
            max_records=8,
        )

        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_enumeration_failed", frames[-1]["reason"])
        self.assertFalse(frames[-1]["complete"])

    def test_candidate_token_binds_generation_and_birthtime(self) -> None:
        baseline = types.SimpleNamespace(
            st_birthtime=1234.5,
            st_dev=1,
            st_gen=7,
            st_gid=20,
            st_ino=2,
            st_mode=stat.S_IFREG | 0o600,
            st_uid=501,
        )
        replacement = types.SimpleNamespace(**vars(baseline))
        replacement.st_birthtime = 1235.5
        replacement.st_gen = 8

        self.assertNotEqual(
            transport_source._source_transport_candidate_token(baseline),
            transport_source._source_transport_candidate_token(replacement),
        )

    def test_candidate_open_is_inside_the_discovery_deadline(self) -> None:
        history = self.codex_root / "history.jsonl"
        history.write_bytes(self._line("one"))
        now = [0.0]
        budget = transport_source.transport_discovery.SourceDiscoveryBudget(
            timeout_seconds=1.0,
            clock=lambda: now[0],
        )
        real_open = transport_source._open_source_transport_candidate

        def open_then_expire(*args, **kwargs):
            opened = real_open(*args, **kwargs)
            now[0] = 1.0
            return opened

        with (
            mock.patch.object(
                transport_source.transport_discovery,
                "SourceDiscoveryBudget",
                return_value=budget,
            ),
            mock.patch.object(
                transport_source,
                "_open_source_transport_candidate",
                side_effect=open_then_expire,
            ),
        ):
            frames = self._direct_source_frames(
                "candidate-open-deadline",
                source_kind="history",
                max_records=8,
            )

        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual(
            "source_discovery_deadline_reached",
            frames[-1]["reason"],
        )

    def test_candidate_disappearance_after_root_snapshot_is_a_gap(self) -> None:
        self.codex_root.joinpath("history.jsonl").write_bytes(self._line("one"))
        with mock.patch.object(
            transport_source,
            "_open_source_transport_candidate",
            side_effect=FileNotFoundError("simulated candidate disappearance"),
        ):
            frames = self._direct_source_frames(
                "candidate-disappeared",
                source_kind="history",
                max_records=8,
            )

        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_enumeration_changed", frames[-1]["reason"])

    def test_source_directory_disappearance_after_root_snapshot_is_a_gap(self) -> None:
        self.codex_root.joinpath("sessions").mkdir(mode=0o700)
        real_open = transport_source._open_relative_from_codex_root

        def disappear_after_snapshot(anchor, relative_path, **kwargs):
            if relative_path == transport_source.pathlib.PurePosixPath("sessions"):
                raise FileNotFoundError("simulated source directory disappearance")
            return real_open(anchor, relative_path, **kwargs)

        with mock.patch.object(
            transport_source,
            "_open_relative_from_codex_root",
            side_effect=disappear_after_snapshot,
        ):
            frames = self._direct_source_frames(
                "source-directory-disappeared",
                source_kind="active_rollout",
                max_records=8,
            )

        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_enumeration_changed", frames[-1]["reason"])

    def test_source_window_remains_bounded_to_366_days(self) -> None:
        self.codex_root.joinpath("history.jsonl").write_bytes(self._line("one"))
        with self.assertRaisesRegex(
            ValueError,
            "source transport window exceeds the discovery bound",
        ):
            transport._source_transport_candidate_paths(
                self.codex_root,
                "history",
                window_start=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
                window_end=dt.datetime(2026, 1, 3, tzinfo=dt.timezone.utc),
                max_candidates=8,
            )

    def test_resume_terminal_revalidation_clears_stale_resume(self) -> None:
        history = self.codex_root / "history.jsonl"
        history.write_bytes(self._line("first") + self._line("second"))
        os.chmod(history, 0o600)
        first = self._direct_source_frames(
            "resume-terminal-first",
            source_kind="history",
            max_records=1,
        )
        resume_position = first[-1]["resume_position"]
        self.assertIsInstance(resume_position, dict)
        original_revalidate = (
            transport_source.transport_discovery.revalidate_directory_snapshots
        )

        def mutate_then_revalidate(*args, **kwargs) -> None:
            os.chmod(history, 0o640)
            original_revalidate(*args, **kwargs)

        try:
            with mock.patch.object(
                transport_source.transport_discovery,
                "revalidate_directory_snapshots",
                side_effect=mutate_then_revalidate,
            ):
                second = self._direct_source_frames(
                    "resume-terminal-second",
                    source_kind="history",
                    max_records=1,
                    resume_position=resume_position,
                )
        finally:
            os.chmod(history, 0o600)

        self.assertEqual("gap", second[-1]["status"])
        self.assertEqual("source_enumeration_changed", second[-1]["reason"])
        self.assertIsNone(second[-1]["resume_position"])

    def test_terminal_revalidation_io_failure_is_distinct_from_change(self) -> None:
        self.codex_root.joinpath("history.jsonl").write_bytes(self._line("one"))
        with mock.patch.object(
            transport_source.transport_discovery,
            "terminal_revalidate_source_discovery",
            side_effect=PermissionError("simulated unreadable inventory"),
        ):
            frames = self._direct_source_frames(
                "terminal-revalidation-io",
                source_kind="history",
                max_records=8,
            )

        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual(
            "source_enumeration_revalidation_failed",
            frames[-1]["reason"],
        )

    def test_oversized_source_record_yields_exact_gap_accounting(self) -> None:
        self.codex_root.joinpath("session_index.jsonl").write_bytes(
            self._line("oversized-session", kind="session_index")
        )
        oversized = b"x" * (transport.SOURCE_TRANSPORT_MAX_RECORD_BYTES + 257) + b"\n"
        self.codex_root.joinpath("history.jsonl").write_bytes(oversized)
        coordinator = self._coordinator("oversized-record")

        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            first = self._first_lease(coordinator)
            self._capture_prepare_accept(
                coordinator,
                first,
                environment=dict(os.environ),
            )
            history_view = self._first_lease(coordinator)
            self.assertEqual("history", history_view["source_kind"])
            lease = transport.TransportLease.from_dict(history_view["transport_lease"])
            completed = subprocess.run(
                list(lease.command_argv),
                check=True,
                capture_output=True,
                env=dict(os.environ),
            )

        frames = completed.stdout.splitlines(keepends=True)
        capture = transport.capture_source_transport(frames, lease=lease)
        self.assertEqual(SourceCellStatus.GAP, capture.terminal_status)
        self.assertEqual("source_record_oversized", capture.terminal_reason)
        self.assertEqual(1, capture.oversized_record_count)
        self.assertEqual(len(oversized), capture.oversized_byte_count)
        self.assertEqual(len(oversized), capture.scan_byte_count)
        self.assertEqual((), capture.records)

        before = json.loads(
            json.dumps(coordinator.store.read().state["cursors"]["local"])
        )
        preparation = coordinator.prepare_source(lease.lease_ref, frames)
        accepted = coordinator.accept_source(
            lease.lease_ref,
            preparation.manifest,
            transport_receipt=preparation.receipt,
            raw_records=preparation.raw_records,
        )
        self.assertEqual("gap", accepted["outcome"])
        state = coordinator.store.read().state
        self.assertEqual(before, state["cursors"]["local"])
        self.assertEqual(
            "source_record_oversized",
            state["source"]["cells"]["local"]["history"]["manifest"]["enumeration_gap"][
                "reason"
            ],
        )

    def test_strict_numeric_source_failures_become_explicit_gaps(self) -> None:
        malformed_records = (
            b'{"id":"duplicate","id":"again","timestamp":"2026-07-06T01:00:00Z"}\n',
            b'{"id":"large","timestamp":"2026-07-06T01:00:00Z","value":9223372036854775808}\n',
            b'{"id":"nonfinite","timestamp":"2026-07-06T01:00:00Z","value":1e999}\n',
        )
        for index, payload in enumerate(malformed_records):
            with self.subTest(index=index):
                self.codex_root.joinpath("session_index.jsonl").write_bytes(payload)
                coordinator = self._coordinator(f"strict-number-{index}")
                lease_view = self._first_lease(coordinator)
                lease = transport.TransportLease.from_dict(
                    lease_view["transport_lease"]
                )
                environment = {**os.environ, "HOME": str(self.home)}
                completed = subprocess.run(
                    list(lease.command_argv),
                    check=True,
                    capture_output=True,
                    env=environment,
                )
                capture = transport.capture_source_transport(
                    completed.stdout.splitlines(keepends=True),
                    lease=lease,
                )
                self.assertEqual(SourceCellStatus.GAP, capture.terminal_status)
                self.assertEqual("source_record_unparseable", capture.terminal_reason)
                self.assertEqual(
                    "explicit_gap", capture.inventory[0]["accounting_class"]
                )
                self.assertEqual(
                    "source_record_unparseable", capture.inventory[0]["reason"]
                )

    def test_control_character_session_identifiers_become_explicit_gaps(self) -> None:
        malformed_records = (
            (
                SourceKind.SESSION_INDEX,
                {"id": "invalid\x00session", "timestamp": "2026-07-06T01:00:00Z"},
            ),
            (
                SourceKind.ACTIVE_ROLLOUT,
                {
                    "payload": {"id": "invalid\x00session"},
                    "timestamp": "2026-07-06T01:00:00Z",
                    "type": "session_meta",
                },
            ),
            (
                SourceKind.ARCHIVED_ROLLOUT,
                {
                    "payload": {"session_id": "invalid\x00session"},
                    "timestamp": "2026-07-06T01:00:00Z",
                    "type": "session_meta",
                },
            ),
            (
                SourceKind.SESSION_INDEX,
                {"id": "invalid\ud800session", "timestamp": "2026-07-06T01:00:00Z"},
            ),
        )
        for source_kind, record in malformed_records:
            with self.subTest(source_kind=source_kind.value):
                with self.assertRaisesRegex(
                    transport.TransportValidationError,
                    "session identity is invalid",
                ):
                    transport_source._source_record_session_identifiers(
                        record,
                        source_kind=source_kind,
                    )
                with self.assertRaisesRegex(
                    ValueError,
                    "session identity is invalid",
                ):
                    orchestrator_transport._source_session_identifiers(
                        record,
                        source_kind=source_kind,
                    )

        self.codex_root.joinpath("session_index.jsonl").write_text(
            '{"id":"invalid\\u0000session","timestamp":"2026-07-06T01:00:00Z"}\n',
            encoding="ascii",
        )
        coordinator = self._coordinator("control-session-id")
        lease_view = self._first_lease(coordinator)
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        completed = subprocess.run(
            list(lease.command_argv),
            check=True,
            capture_output=True,
            env={**os.environ, "HOME": str(self.home)},
        )
        capture = transport.capture_source_transport(
            completed.stdout.splitlines(keepends=True),
            lease=lease,
        )
        self.assertEqual(SourceCellStatus.GAP, capture.terminal_status)
        self.assertEqual("source_record_unparseable", capture.terminal_reason)
        self.assertEqual("explicit_gap", capture.inventory[0]["accounting_class"])

    def test_source_transport_continues_without_prefix_rescan_after_restart(
        self,
    ) -> None:
        payloads = [
            (
                json.dumps(
                    {
                        "blob": "x" * 500_000,
                        "session_id": f"continued-{index}",
                        "timestamp": "2026-07-06T01:00:00Z",
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                + b"\n"
            )
            for index in range(10)
        ]
        self.codex_root.joinpath("history.jsonl").write_bytes(b"".join(payloads))
        environment = {**os.environ, "HOME": str(self.home)}
        continued_source_kind = ""
        real_materialized_segment = source_inputs.materialized_segment
        materialized_segment_calls = 0
        continued_without_history_reload = False

        def counted_materialized_segment(*args, **kwargs):
            nonlocal materialized_segment_calls
            materialized_segment_calls += 1
            return real_materialized_segment(*args, **kwargs)

        with (
            mock.patch.object(
                orchestrator_module,
                "SOURCE_TRANSPORT_MAX_SOURCE_BYTES",
                2 * 1024 * 1024,
            ),
            mock.patch.object(
                source_inputs,
                "materialized_segment",
                side_effect=counted_materialized_segment,
            ),
        ):
            coordinator = self._coordinator("continued-source")
            restarted = False
            for _ in range(32):
                status = coordinator.status()
                if status["stage"] != "source_catalog":
                    break
                leases = status["active_source_leases"]
                if not leases:
                    coordinator.advance()
                    continue
                lease = transport.TransportLease.from_dict(leases[0]["transport_lease"])
                completed = subprocess.run(
                    list(lease.command_argv),
                    check=True,
                    capture_output=True,
                    env=environment,
                )
                preparation = coordinator.prepare_source(
                    lease.lease_ref,
                    completed.stdout.splitlines(keepends=True),
                )
                existing_segment_count = len(
                    coordinator.load_state()["source"]["cells"]["local"][
                        lease.source_kind.value
                    ]["continuation_segments"]
                )
                calls_before_acceptance = materialized_segment_calls
                accepted = coordinator.accept_source(
                    lease.lease_ref,
                    preparation.manifest,
                    transport_receipt=preparation.receipt,
                    raw_records=preparation.raw_records,
                )
                if accepted["outcome"] == "continued" and existing_segment_count:
                    self.assertEqual(
                        calls_before_acceptance,
                        materialized_segment_calls,
                    )
                    continued_without_history_reload = True
                if accepted["outcome"] == "continued" and not restarted:
                    source_kind = lease.source_kind.value
                    continued_source_kind = source_kind

                    def downgrade_to_legacy_inline_state(current):
                        cell = current["source"]["cells"]["local"][source_kind]
                        accepted_segment = source_inputs.load(
                            coordinator.run_dir,
                            cell["continuation_segments"][0],
                        )
                        cell["continuation_segments"] = [accepted_segment["segment"]]
                        cell["payloads"] = accepted_segment["payloads"]
                        return current, None

                    coordinator.store.transaction(downgrade_to_legacy_inline_state)
                    coordinator = RetrospectiveOrchestrator(
                        coordinator.run_dir,
                        clock=lambda: "2026-07-15T00:00:00Z",
                        identity_path=self.root / "identity-v2.key",
                        require_existing_identity=True,
                    )
                    restarted = True
            else:
                self.fail("source continuation did not terminate")

        state = coordinator.store.read().state
        self.assertEqual("history", continued_source_kind)
        self.assertTrue(continued_without_history_reload)
        cell = state["source"]["cells"]["local"][continued_source_kind]
        descriptors = cell["continuation_segments"]
        segments = [
            source_inputs.materialized_segment(coordinator.run_dir, descriptor)[
                "segment"
            ]
            for descriptor in descriptors
        ]
        self.assertTrue(restarted)
        self.assertGreater(
            len(segments),
            1,
            [
                {
                    "reason": segment["source_snapshot"]["terminal_reason"],
                    "source_byte_count": segment["source_snapshot"][
                        "source_byte_count"
                    ],
                }
                for segment in segments
            ],
        )
        self.assertEqual(10, cell["metrics"]["record_count"])
        self.assertEqual({}, cell["payloads"])
        aggregate, _snapshot_ref, _receipt_ref = source_inputs.aggregate_segments(
            coordinator.identity,
            coordinator.run_dir,
            descriptors,
        )
        self.assertEqual(source_inputs.manifest_summary(aggregate), cell["manifest"])
        self.assertEqual(10, len(aggregate.records))
        materialized = source_inputs.materialize_segments(
            coordinator.run_dir,
            descriptors,
        )
        self.assertEqual(
            10,
            len(materialized["payloads"]),
            [descriptor.get("schema", "legacy") for descriptor in descriptors],
        )
        self.assertTrue(
            source_inputs.manifest_matches_persisted(aggregate.to_dict(), aggregate)
        )

        legacy_state = json.loads(json.dumps(state))
        legacy_cell = legacy_state["source"]["cells"]["local"][continued_source_kind]
        legacy_cell["manifest"] = aggregate.to_dict()
        coordinator._components.reduction._accepted_source_inputs(legacy_state)
        unit_ref = next(iter(materialized["payloads"]))
        legacy_cell["payloads"] = {
            unit_ref: {"reason": "raw_payload_missing", "status": "gap"}
        }
        with self.assertRaisesRegex(InvalidTransitionError, "index changed"):
            coordinator._components.reduction._accepted_source_inputs(legacy_state)
        byte_starts = [record.coordinate.byte_start for record in aggregate.records]
        expected_byte_starts: list[int] = []
        next_byte_start = 0
        for payload in payloads:
            expected_byte_starts.append(next_byte_start)
            next_byte_start += len(payload)
        self.assertEqual(expected_byte_starts, sorted(byte_starts))
        self.assertEqual(len(byte_starts), len(set(byte_starts)))
        for previous, following in zip(segments, segments[1:]):
            resume = previous["source_snapshot"]["resume_position"]
            self.assertIsNotNone(resume)
            following_manifest = catalog.SourceTransportManifest.from_dict(
                following["manifest"]
            )
            self.assertTrue(following_manifest.records)
            self.assertEqual(
                resume["byte_offset"],
                min(
                    record.coordinate.byte_start
                    for record in following_manifest.records
                ),
            )
        self.assertIsNone(segments[-1]["source_snapshot"]["resume_position"])

    def test_source_resume_v4_is_canonical_and_v3_fails_closed(self) -> None:
        source = self.codex_root / "history.jsonl"
        source.write_bytes(
            b"".join(self._line(f"schema-{index}") for index in range(3))
        )
        frames = self._direct_source_frames(
            "resume-v4-schema",
            source_kind="history",
            max_records=1,
        )
        resume = frames[-1]["resume_position"]
        self.assertIsInstance(resume, dict)
        assert isinstance(resume, dict)

        self.assertEqual("source_transport_resume_v4", resume["schema"])
        self.assertEqual(
            {
                "accepted_prefix_commitment",
                "byte_offset",
                "candidate_index",
                "discovery_commitment",
                "record_index",
                "resume_probe",
                "schema",
                "source_locator",
                "source_size",
                "source_token",
            },
            set(resume),
        )
        self.assertEqual(
            {"byte_end", "byte_start", "content_commitment"},
            set(resume["resume_probe"]),
        )
        encoded = transport.encode_source_resume_position(resume)
        self.assertEqual(resume, transport.decode_source_resume_position(encoded))

        wrong_schema = json.loads(json.dumps(resume))
        wrong_schema["schema"] = "source_transport_resume_v3"
        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "resume schema changed",
        ):
            transport.encode_source_resume_position(wrong_schema)

        legacy_fields = json.loads(json.dumps(resume))
        legacy_fields.pop("accepted_prefix_commitment")
        legacy_fields.pop("resume_probe")
        legacy_fields["frozen_prefix_commitment"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "closed field set",
        ):
            transport.encode_source_resume_position(legacy_fields)

    def test_forged_incoming_resume_fails_probe_auth_and_header_chains(self) -> None:
        source = self.codex_root / "history.jsonl"
        source.write_bytes(
            b"".join(self._line(f"incoming-{index}") for index in range(4))
        )
        first = self._direct_source_frames(
            "incoming-resume-original",
            source_kind="history",
            max_records=1,
        )
        resume = first[-1]["resume_position"]
        self.assertIsInstance(resume, dict)
        assert isinstance(resume, dict)

        forged_probe = json.loads(json.dumps(resume))
        forged_probe["resume_probe"]["content_commitment"] = "sha256:" + "0" * 64
        rejected = self._direct_source_frames(
            "incoming-resume-forged-probe",
            source_kind="history",
            max_records=1,
            resume_position=forged_probe,
        )
        self.assertEqual("source_resume_invalid", rejected[-1]["reason"])
        self.assertIsNone(rejected[-1]["resume_position"])

        signed_lease = self._direct_source_lease(
            "incoming-resume-signed",
            source_kind="history",
            max_records=1,
            resume_position=resume,
        )
        transport.verify_transport_lease(self.identity, signed_lease)
        forged_commitment = json.loads(json.dumps(resume))
        forged_commitment["accepted_prefix_commitment"] = "sha256:" + "0" * 64
        forged_lease = replace(signed_lease, resume_position=forged_commitment)
        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "lease authentication failed",
        ):
            transport.verify_transport_lease(self.identity, forged_lease)

        valid_frames = self._direct_source_frames(
            "incoming-resume-signed",
            source_kind="history",
            max_records=1,
            resume_position=resume,
        )
        forged_header = json.loads(json.dumps(valid_frames))
        forged_header[0]["resume_position"] = forged_commitment
        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "header is not bound to its authenticated lease",
        ):
            transport.capture_source_transport(
                (
                    json.dumps(frame, separators=(",", ":"), sort_keys=True) + "\n"
                    for frame in forged_header
                ),
                lease=signed_lease,
            )

    def test_capture_recomputes_and_rejects_forged_outgoing_resume(self) -> None:
        source = self.codex_root / "history.jsonl"
        source.write_bytes(
            b"".join(self._line(f"outgoing-{index}") for index in range(3))
        )
        name = "outgoing-resume-forged"
        frames = self._direct_source_frames(
            name,
            source_kind="history",
            max_records=1,
        )
        lease = self._direct_source_lease(
            name,
            source_kind="history",
            max_records=1,
        )
        lines = [
            json.dumps(frame, separators=(",", ":"), sort_keys=True) + "\n"
            for frame in frames
        ]
        capture = transport.capture_source_transport(lines, lease=lease)
        self.assertIsNotNone(capture.resume_position)

        forged = json.loads(json.dumps(frames))
        forged[-1]["resume_position"]["accepted_prefix_commitment"] = (
            "sha256:" + "0" * 64
        )
        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "was not independently derived",
        ):
            transport.capture_source_transport(
                (
                    json.dumps(frame, separators=(",", ":"), sort_keys=True) + "\n"
                    for frame in forged
                ),
                lease=lease,
            )

    def test_source_resume_freezes_prefix_when_live_file_appends(self) -> None:
        source = self.codex_root / "history.jsonl"
        original = b"".join(self._line(f"resume-{index}") for index in range(3))
        source.write_bytes(original)

        first = self._direct_source_frames(
            "resume-before-append",
            source_kind="history",
            max_records=1,
        )
        first_terminal = first[-1]
        resume = first_terminal["resume_position"]
        self.assertEqual("source_record_limit_reached", first_terminal["reason"])
        self.assertIsInstance(resume, dict)
        assert isinstance(resume, dict)
        self.assertEqual(len(original), resume["source_size"])

        source.write_bytes(
            original
            + self._line("late-append").replace(
                b"2026-07-06T01:00:00Z",
                b"2026-07-07T01:00:00Z",
            )
        )
        second = self._direct_source_frames(
            "resume-after-append",
            source_kind="history",
            max_records=16,
            resume_position=resume,
        )
        second_terminal = second[-1]
        second_inventory = [
            frame for frame in second if frame.get("frame") == "inventory"
        ]

        self.assertTrue(second_terminal["complete"])
        self.assertNotEqual("source_resume_invalid", second_terminal["reason"])
        self.assertEqual(2, len(second_inventory))
        self.assertEqual(
            len(original) - int(resume["byte_offset"]),
            second_terminal["scan_byte_count"],
        )

    def test_source_resume_rejects_changed_frozen_prefix(self) -> None:
        source = self.codex_root / "history.jsonl"
        original = b"".join(self._line(f"prefix-{index}") for index in range(3))
        source.write_bytes(original)
        first = self._direct_source_frames(
            "resume-prefix-original",
            source_kind="history",
            max_records=1,
        )
        resume = first[-1]["resume_position"]
        self.assertIsInstance(resume, dict)
        assert isinstance(resume, dict)

        changed = bytearray(original)
        changed[changed.index(b"prefix-0")] = ord("q")
        with source.open("r+b") as handle:
            handle.write(changed)
        second = self._direct_source_frames(
            "resume-prefix-changed",
            source_kind="history",
            max_records=16,
            resume_position=resume,
        )

        self.assertEqual("gap", second[-1]["status"])
        self.assertEqual("source_resume_invalid", second[-1]["reason"])
        self.assertEqual(0, second[-1]["inventory_count"])

    def test_source_resume_does_not_claim_unprobed_deep_history_detection(self) -> None:
        source = self.codex_root / "history.jsonl"
        rows = [self._line(f"bulk-{index}-" + "x" * 160) for index in range(705)]
        original = b"".join(rows)
        source.write_bytes(original)
        first = self._direct_source_frames(
            "resume-whole-prefix-original",
            source_kind="history",
            max_records=700,
        )
        resume = first[-1]["resume_position"]
        self.assertIsInstance(resume, dict)
        assert isinstance(resume, dict)
        self.assertGreater(int(resume["byte_offset"]), 64 * 1024)

        changed = bytearray(original)
        changed[changed.index(b"bulk-0")] = ord("q")
        source.write_bytes(changed)
        second = self._direct_source_frames(
            "resume-whole-prefix-changed",
            source_kind="history",
            max_records=16,
            resume_position=resume,
        )

        self.assertTrue(second[-1]["complete"])
        self.assertNotEqual("source_resume_invalid", second[-1]["reason"])
        self.assertEqual(5, second[-1]["inventory_count"])

    def test_source_resume_pread_ranges_never_rescan_zero_to_offset(self) -> None:
        source = self.codex_root / "history.jsonl"
        rows = [self._line(f"pread-{index}-" + "x" * 160) for index in range(720)]
        source.write_bytes(b"".join(rows))
        first = self._direct_source_frames(
            "resume-pread-first",
            source_kind="history",
            max_records=700,
        )
        resume = first[-1]["resume_position"]
        self.assertIsInstance(resume, dict)
        assert isinstance(resume, dict)
        byte_offset = int(resume["byte_offset"])
        probe_start = (
            byte_offset - transport_contracts.SOURCE_TRANSPORT_RESUME_PROBE_BYTES
        )
        self.assertGreater(probe_start, 0)

        real_pread = os.pread
        pread_calls: list[tuple[int, int, int]] = []

        def record_pread(descriptor: int, count: int, offset: int) -> bytes:
            payload = real_pread(descriptor, count, offset)
            pread_calls.append((offset, count, len(payload)))
            return payload

        with mock.patch.object(
            transport_source.os,
            "pread",
            side_effect=record_pread,
        ):
            second = self._direct_source_frames(
                "resume-pread-second",
                source_kind="history",
                max_records=3,
                resume_position=resume,
            )

        self.assertEqual("source_record_limit_reached", second[-1]["reason"])
        prior_prefix_reads = [call for call in pread_calls if call[0] < byte_offset]
        self.assertTrue(prior_prefix_reads)
        self.assertEqual(
            {probe_start},
            {offset for offset, _count, _actual in prior_prefix_reads},
        )
        self.assertLessEqual(
            sum(actual for _offset, _count, actual in prior_prefix_reads),
            transport_contracts.SOURCE_TRANSPORT_RESUME_PROBE_BUDGET_BYTES,
        )
        self.assertFalse(any(offset == 0 for offset, _count, _actual in pread_calls))
        self.assertTrue(
            any(offset == byte_offset for offset, _count, _actual in pread_calls)
        )

    def test_source_resume_probe_budget_exhaustion_is_an_explicit_gap(self) -> None:
        source = self.codex_root / "history.jsonl"
        rows = [self._line(f"budget-{index}-" + "x" * 160) for index in range(710)]
        source.write_bytes(b"".join(rows))
        first = self._direct_source_frames(
            "resume-budget-first",
            source_kind="history",
            max_records=700,
        )
        resume = first[-1]["resume_position"]
        self.assertIsInstance(resume, dict)
        assert isinstance(resume, dict)

        with mock.patch.object(
            transport_source,
            "SOURCE_TRANSPORT_RESUME_PROBE_BUDGET_BYTES",
            transport_contracts.SOURCE_TRANSPORT_RESUME_PROBE_BYTES,
        ):
            second = self._direct_source_frames(
                "resume-budget-second",
                source_kind="history",
                max_records=1,
                resume_position=resume,
            )

        self.assertEqual("gap", second[-1]["status"])
        self.assertEqual(
            "source_resume_probe_budget_exhausted",
            second[-1]["reason"],
        )
        self.assertIsNone(second[-1]["resume_position"])

    def test_source_scan_rejects_overwritten_prefix_plus_append(self) -> None:
        source = self.codex_root / "history.jsonl"
        original = b"".join(self._line(f"stable-prefix-{index}") for index in range(3))
        source.write_bytes(original)
        appended = self._line("late-append").replace(
            b"2026-07-06T01:00:00Z",
            b"2026-07-07T01:00:00Z",
        )
        real_read = transport_source._read_bounded_line
        changed = False

        def overwrite_after_read(*args, **kwargs):
            nonlocal changed
            line = real_read(*args, **kwargs)
            if line.byte_count and not changed:
                changed = True
                replacement = bytearray(original)
                replacement[replacement.index(b"stable-prefix-0")] = ord("q")
                source.write_bytes(bytes(replacement) + appended)
            return line

        with mock.patch.object(
            transport_source,
            "_read_bounded_line",
            side_effect=overwrite_after_read,
        ):
            frames = self._direct_source_frames(
                "overwrite-prefix-plus-append",
                source_kind="history",
                max_records=16,
            )

        self.assertTrue(changed)
        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_changed_during_scan", frames[-1]["reason"])
        self.assertIsNone(frames[-1]["resume_position"])

    def test_source_scan_accepts_timestamp_only_change(self) -> None:
        source = self.codex_root / "history.jsonl"
        source.write_bytes(self._line("timestamp-only"))
        real_read = transport_source._read_bounded_line
        changed = False

        def touch_after_read(*args, **kwargs):
            nonlocal changed
            line = real_read(*args, **kwargs)
            if line.byte_count and not changed:
                changed = True
                metadata = source.stat()
                os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1))
            return line

        with mock.patch.object(
            transport_source,
            "_read_bounded_line",
            side_effect=touch_after_read,
        ):
            frames = self._direct_source_frames(
                "timestamp-only-change",
                source_kind="history",
                max_records=16,
            )

        self.assertTrue(changed)
        self.assertEqual("no_activity", frames[-1]["status"])
        self.assertTrue(frames[-1]["complete"])

    def test_source_identity_ignores_non_policy_flags(self) -> None:
        hidden = getattr(stat, "UF_HIDDEN", 0)
        immutable = getattr(stat, "UF_IMMUTABLE", 0)
        if not hidden or not immutable:
            self.skipTest("BSD file flags are unavailable")

        def metadata(flags: int) -> types.SimpleNamespace:
            return types.SimpleNamespace(
                st_dev=1,
                st_ino=2,
                st_mode=stat.S_IFREG | 0o600,
                st_uid=os.getuid(),
                st_gid=os.getgid(),
                st_nlink=1,
                st_flags=flags,
                st_gen=3,
            )

        baseline = transport_source._source_transport_file_identity(metadata(0))
        self.assertEqual(
            baseline,
            transport_source._source_transport_file_identity(metadata(hidden)),
        )
        self.assertNotEqual(
            baseline,
            transport_source._source_transport_file_identity(metadata(immutable)),
        )
        self.assertFalse(transport_resume._SOURCE_ACCESS_POLICY_FLAG_MASK & hidden)
        self.assertTrue(transport_resume._SOURCE_ACCESS_POLICY_FLAG_MASK & immutable)

    def test_source_scan_rejects_access_policy_change(self) -> None:
        source = self.codex_root / "history.jsonl"
        source.write_bytes(self._line("access-policy-change"))
        real_read = transport_source._read_bounded_line
        changed = False

        def chmod_after_read(*args, **kwargs):
            nonlocal changed
            line = real_read(*args, **kwargs)
            if line.byte_count and not changed:
                changed = True
                os.chmod(source, 0o640)
            return line

        with mock.patch.object(
            transport_source,
            "_read_bounded_line",
            side_effect=chmod_after_read,
        ):
            frames = self._direct_source_frames(
                "access-policy-change",
                source_kind="history",
                max_records=16,
            )

        self.assertTrue(changed)
        self.assertEqual("gap", frames[-1]["status"])
        self.assertEqual("source_enumeration_changed", frames[-1]["reason"])

    def test_codex_root_validation_uses_lexical_no_follow_open(self) -> None:
        self.codex_root.joinpath("history.jsonl").write_bytes(
            self._line("lexical-root")
        )

        with mock.patch.object(
            transport.pathlib.Path,
            "resolve",
            side_effect=AssertionError("resolve must not make trust decisions"),
        ):
            discovery = transport._source_transport_candidate_paths(
                self.codex_root,
                "history",
                window_start=dt.datetime.fromisoformat(
                    WINDOW_START.removesuffix("Z") + "+00:00"
                ),
                window_end=dt.datetime.fromisoformat(
                    WINDOW_END.removesuffix("Z") + "+00:00"
                ),
                max_candidates=16,
            )

        self.assertEqual(
            ((self.codex_root / "history.jsonl", "history.jsonl"),),
            discovery.candidates,
        )

    def test_codex_root_name_swap_retains_original_descriptor_identity(
        self,
    ) -> None:
        outside = self.home / "outside-codex"
        outside.mkdir(mode=0o700)
        displaced = self.home / "displaced-codex"
        swapped = False

        def swap_root(_index: int, name: str, _descriptor: int) -> None:
            nonlocal swapped
            if name != ".codex" or swapped:
                return
            swapped = True
            self.codex_root.rename(displaced)
            self.codex_root.symlink_to(outside, target_is_directory=True)

        with mock.patch.object(
            transport_source,
            "_SOURCE_TRANSPORT_OPEN_COMPONENT_HOOK",
            create=True,
            side_effect=swap_root,
        ):
            anchor = transport._open_lexical_codex_root(self.codex_root)

        try:
            displaced_stat = displaced.stat()
            self.assertTrue(swapped)
            self.assertEqual(
                (displaced_stat.st_dev, displaced_stat.st_ino),
                anchor.identity,
            )
        finally:
            anchor.close()

    def test_source_scan_keeps_root_descriptor_after_lexical_name_replacement(
        self,
    ) -> None:
        original_payload = self._line("original-session")
        replacement_payload = self._line("replacement-session")
        self.codex_root.joinpath("history.jsonl").write_bytes(original_payload)
        replacement_root = self.home / "replacement-codex"
        replacement_root.mkdir(mode=0o700)
        replacement_root.joinpath("history.jsonl").write_bytes(replacement_payload)
        displaced_root = self.home / "original-codex"
        component_opens = 0

        def replace_after_discovery(_index: int, name: str, _descriptor: int) -> None:
            nonlocal component_opens
            if name != ".codex":
                return
            component_opens += 1
            if component_opens != 1:
                return
            self.codex_root.rename(displaced_root)
            self.codex_root.symlink_to(replacement_root, target_is_directory=True)

        output_path = self.root / "ancestor-replacement-output.jsonl"
        lease_ref = str(
            self.identity.derive_ref(RefType.LEASE, {"case": "ancestor-replacement"})
        )
        with (
            output_path.open("w", encoding="ascii") as output,
            mock.patch.object(sys, "stdout", output),
            mock.patch.object(
                transport_source,
                "_SOURCE_TRANSPORT_OPEN_COMPONENT_HOOK",
                create=True,
                side_effect=replace_after_discovery,
            ),
        ):
            exit_code = transport_source._run_private_transport_worker(
                [
                    "source-transport",
                    "--host",
                    "local",
                    "--source-kind",
                    "history",
                    "--window-start",
                    WINDOW_START,
                    "--window-end",
                    WINDOW_END,
                    "--lease-ref",
                    lease_ref,
                    "--process-nonce",
                    "ancestor-replacement",
                    "--max-source-bytes",
                    str(1024 * 1024),
                    "--max-records",
                    "16",
                    "--max-frame-bytes",
                    "8192",
                    "--direct-root",
                    str(self.codex_root),
                ]
            )

        frames = [
            json.loads(line)
            for line in output_path.read_text(encoding="ascii").splitlines()
        ]
        self.assertEqual(0, exit_code)
        self.assertEqual(1, component_opens)
        self.assertEqual("no_activity", frames[-1]["status"])
        commitments = [
            frame["content_commitment"]
            for frame in frames
            if frame.get("frame") == "inventory"
        ]
        self.assertEqual([catalog.content_commitment(original_payload)], commitments)
        self.assertNotIn(
            catalog.content_commitment(replacement_payload),
            commitments,
        )

    def test_codex_root_rejects_replacement_before_each_component_open(self) -> None:
        for boundary in ("lexical", "a", "b", ".codex"):
            with self.subTest(boundary=boundary):
                case = self.root / f"boundary-{boundary.replace('.', 'dot')}"
                codex_root = case / "lexical/a/b/.codex"
                codex_root.mkdir(parents=True)
                outside = case / "outside"
                outside.mkdir()
                parts = codex_root.parts
                boundary_index = parts.index(boundary)
                parent_name = parts[boundary_index - 1]
                target = Path(*parts[: boundary_index + 1])
                displaced = target.with_name(target.name + "-opened")
                replaced = False

                def replace_next(_index: int, name: str, _descriptor: int) -> None:
                    nonlocal replaced
                    if replaced or name != parent_name:
                        return
                    replaced = True
                    target.rename(displaced)
                    target.symlink_to(outside, target_is_directory=True)

                with (
                    mock.patch.object(
                        transport_source,
                        "_SOURCE_TRANSPORT_OPEN_COMPONENT_HOOK",
                        create=True,
                        side_effect=replace_next,
                    ),
                    self.assertRaisesRegex(ValueError, "real directory"),
                ):
                    transport._open_lexical_codex_root(codex_root)
                self.assertTrue(replaced)

    def test_archive_move_preserves_physical_identity_and_equivalence(
        self,
    ) -> None:
        session_id = "stable-session"
        self.codex_root.joinpath("session_index.jsonl").write_bytes(
            self._line(session_id, kind="session_index")
        )
        self.codex_root.joinpath("history.jsonl").write_bytes(self._line(session_id))
        payload = (
            json.dumps(
                {
                    "payload": {"content": "stable evidence", "role": "user"},
                    "session_id": session_id,
                    "type": "response_item",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        active = self.codex_root.joinpath(
            "sessions/2026/07/06/rollout-2026-07-06T01-00-00-stable-session.jsonl"
        )
        active.parent.mkdir(mode=0o700, parents=True)
        active.write_bytes(payload)

        active_state = self._complete_native_sources("identity-active")

        archived = self.codex_root.joinpath(
            "archived_sessions/2026/07/06/"
            "rollout-2026-07-06T01-00-00-stable-session.jsonl"
        )
        archived.parent.mkdir(mode=0o700, parents=True)
        os.rename(active, archived)
        os.utime(archived, ns=(1_700_000_000_000_000_000,) * 2)
        archived_state = self._complete_native_sources("identity-archived")
        active_rollout = next(
            record
            for manifest in catalog.SourceCatalog.from_dict(
                active_state["source"]["catalog"]
            ).manifests
            for record in manifest.records
            if manifest.source_kind is catalog.SourceKind.ACTIVE_ROLLOUT
        )
        archived_rollout = next(
            record
            for manifest in catalog.SourceCatalog.from_dict(
                archived_state["source"]["catalog"]
            ).manifests
            for record in manifest.records
            if manifest.source_kind is catalog.SourceKind.ARCHIVED_ROLLOUT
        )
        active_identity = catalog.rollout_record_identity(
            active_rollout.coordinate.record_ref
        )
        archived_identity = catalog.rollout_record_identity(
            archived_rollout.coordinate.record_ref
        )
        self.assertIsNotNone(active_identity)
        self.assertIsNotNone(archived_identity)
        self.assertEqual(active_identity[0], archived_identity[0])
        self.assertEqual(active_identity[1], archived_identity[1])
        self.assertEqual(active_rollout.unit_ref, archived_rollout.unit_ref)
        self.assertEqual(
            active_rollout.coordinate.source_ref,
            archived_rollout.coordinate.source_ref,
        )

        active.write_bytes(payload)
        both_state = self._complete_native_sources("identity-both")
        rollout_records = [
            record
            for manifest in catalog.SourceCatalog.from_dict(
                both_state["source"]["catalog"]
            ).manifests
            for record in manifest.records
            if manifest.source_kind
            in {
                catalog.SourceKind.ACTIVE_ROLLOUT,
                catalog.SourceKind.ARCHIVED_ROLLOUT,
            }
        ]
        self.assertEqual(2, len(rollout_records))
        self.assertEqual(2, len({record.unit_ref for record in rollout_records}))
        self.assertEqual(
            2,
            len(
                {
                    catalog.rollout_record_identity(record.coordinate.record_ref)[0]
                    for record in rollout_records
                }
            ),
        )
        self.assertEqual(
            {
                catalog.AccountingClass.CONSUMED_CANDIDATE,
                catalog.AccountingClass.STRUCTURALLY_EXCLUDED,
            },
            {record.accounting_class for record in rollout_records},
        )
        relocated = self.codex_root / "archived_sessions" / archived.name
        os.rename(archived, relocated)
        os.utime(relocated, ns=(1_800_000_000_000_000_000,) * 2)
        relocated_state = self._complete_native_sources("identity-relocated")

        self.assertEqual(
            set(both_state["source"]["reassembly"]),
            set(relocated_state["source"]["reassembly"]),
        )
        self.assertEqual(
            both_state["metrics"]["accounting"],
            relocated_state["metrics"]["accounting"],
        )
        self.assertEqual(
            3,
            both_state["metrics"]["accounting"]["structurally_excluded"],
        )

    def test_rollout_filename_time_supports_non_midnight_window(self) -> None:
        session_id = "non-midnight"
        timestamp = "2026-07-06T12:34:56Z"
        self.codex_root.joinpath("session_index.jsonl").write_text(
            json.dumps({"id": session_id, "timestamp": timestamp}) + "\n",
            encoding="ascii",
        )
        self.codex_root.joinpath("history.jsonl").write_text(
            json.dumps({"session_id": session_id, "timestamp": timestamp}) + "\n",
            encoding="ascii",
        )
        active = self.codex_root / "sessions/2026/07/06"
        active.mkdir(mode=0o700, parents=True)
        active.joinpath("rollout-2026-07-06T12-34-56-non-midnight.jsonl").write_text(
            json.dumps(
                {
                    "payload": {"content": "window evidence", "role": "user"},
                    "session_id": session_id,
                    "type": "response_item",
                }
            )
            + "\n",
            encoding="ascii",
        )

        state = self._complete_native_sources(
            "non-midnight-window",
            window_start="2026-07-06T12:30:00Z",
            window_end="2026-07-06T12:40:00Z",
        )
        active_manifest = next(
            manifest
            for manifest in catalog.SourceCatalog.from_dict(
                state["source"]["catalog"]
            ).manifests
            if manifest.source_kind is catalog.SourceKind.ACTIVE_ROLLOUT
        )
        self.assertEqual("2026-07-06T12:34:56Z", active_manifest.records[0].event_time)
        self.assertEqual(
            catalog.AccountingClass.CONSUMED_CANDIDATE,
            active_manifest.records[0].accounting_class,
        )

    def test_rollout_without_intrinsic_time_emits_explicit_gap(self) -> None:
        session_id = "missing-time"
        self.codex_root.joinpath("session_index.jsonl").write_bytes(
            self._line(session_id, kind="session_index")
        )
        self.codex_root.joinpath("history.jsonl").write_bytes(self._line(session_id))
        active = self.codex_root / "sessions/2026/07/06"
        active.mkdir(mode=0o700, parents=True)
        active.joinpath("rollout-missing-time.jsonl").write_text(
            json.dumps(
                {
                    "payload": {"content": "missing time", "role": "user"},
                    "session_id": session_id,
                    "type": "response_item",
                }
            )
            + "\n",
            encoding="ascii",
        )

        state = self._complete_native_sources("missing-rollout-time")
        active_cell = state["source"]["cells"]["local"]["active_rollout"]
        self.assertEqual("gap", active_cell["status"])
        self.assertEqual(
            "source_event_time_unavailable",
            active_cell["manifest"]["enumeration_gap"]["reason"],
        )

    def test_session_mode_rejects_a_validly_signed_mismatched_record(self) -> None:
        target = str(
            self.identity.derive_ref(
                RefType.SESSION,
                {"session_id": "target-session"},
            )
        )
        other = str(
            self.identity.derive_ref(
                RefType.SESSION,
                {"session_id": "other-session"},
            )
        )
        coordinator = self._coordinator(
            "session-mismatch",
            mode=RunMode.SESSION,
            session_target=target,
            session_target_selector="target-session",
        )
        lease_view = self._first_lease(coordinator)
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        payload = self._line("other-session", kind="session_index")
        coordinate = catalog.StableSourceCoordinate(
            host_ref=lease.host_ref,
            source_ref=other,
            record_ref="record-0",
            byte_start=0,
            byte_end=len(payload),
        )
        record = catalog.CatalogRecord(
            unit_ref=str(
                self.identity.derive_ref(
                    RefType.SOURCE_UNIT,
                    {"mismatched_session": other},
                )
            ),
            source_kind=lease.source_kind,
            coordinate=coordinate,
            event_time="2026-07-06T01:00:00Z",
            content_commitment=catalog.content_commitment(payload),
        )
        manifest = catalog.SourceTransportManifest.create(
            host_ref=lease.host_ref,
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=lease.source_kind,
            window_start=lease.window_start,
            window_end=lease.window_end,
            status=SourceCellStatus.COMPLETE,
            records=(record,),
            snapshot_commitment=catalog.snapshot_commitment_for_records((record,)),
        )
        transcript = transport.transcript_commitment(
            {record.unit_ref: payload}, source_marker=lease.lease_ref
        )
        snapshot = transport.AuthoritativeSourceSnapshot.create(
            host_ref=lease.host_ref,
            source_kind=lease.source_kind,
            window_start=lease.window_start,
            window_end=lease.window_end,
            session_target=target,
            source_content_commitment=transcript,
            source_byte_count=len(payload),
            terminal_byte_offset=len(payload),
            catalog_record_count=1,
            catalog_byte_count=len(payload),
            catalog_commitment=manifest.snapshot_commitment,
            transcript_commitment=transcript,
            terminal_proof_commitment="sha256:" + "2" * 64,
            terminal_status=SourceCellStatus.COMPLETE,
            terminal_reason="authoritative_eof",
            complete=True,
            resume_position=None,
        )
        receipt = transport.issue_transport_receipt(
            coordinator.identity,
            lease=lease,
            manifest=manifest.to_dict(),
            source_snapshot=snapshot,
        )
        with self.assertRaisesRegex(InvalidInputError, "session_target"):
            coordinator.accept_source(
                lease.lease_ref,
                manifest.to_dict(),
                transport_receipt=receipt.to_dict(),
                raw_records={record.unit_ref: payload},
            )
        self.assertFalse(any((coordinator.run_dir / "raw-inputs").glob("*.bin")))

    def test_transport_program_commitment_isolated_from_unrelated_modules(self) -> None:
        package = self.root / "closed-program"
        package.mkdir(mode=0o700)
        modules = transport_program.SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST
        for index, name in enumerate(modules):
            path = package / name
            path.write_text(f"VALUE = {index}\n", encoding="ascii")
            os.chmod(path, 0o600)
        worker = package / "transport_worker.py"
        with (
            mock.patch.object(
                transport_program,
                "__file__",
                str(package / "transport_program.py"),
            ),
            mock.patch.object(
                transport_program,
                "SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST",
                modules,
            ),
        ):
            argv = (
                *transport_program.source_transport_python_command(),
                str(worker),
                "source-transport",
            )
            original = transport_program.transport_program_commitment(argv)
            (package / "catalog.py").write_text("VALUE = 99\n", encoding="ascii")
            self.assertEqual(
                original,
                transport_program.transport_program_commitment(argv),
            )
            changed_argv = (
                *transport_program.source_transport_python_command(),
                str(worker),
                "source-transport",
            )
            changed = transport_program.transport_program_commitment(changed_argv)
            self.assertNotEqual(original, changed)

            unrelated = package / "reporting.py"
            unrelated.write_text("VALUE = 1\n", encoding="ascii")
            before_unrelated_change = (
                *transport_program.source_transport_python_command(),
                str(worker),
                "source-transport",
            )
            unrelated.write_text("VALUE = 2\n", encoding="ascii")
            self.assertEqual(
                transport_program.transport_program_commitment(before_unrelated_change),
                transport_program.transport_program_commitment(
                    (
                        *transport_program.source_transport_python_command(),
                        str(worker),
                        "source-transport",
                    )
                ),
            )

            (package / "catalog.py").unlink()
            with self.assertRaisesRegex(
                transport.TransportValidationError,
                "package_module:catalog.py is unavailable",
            ):
                transport_program.source_transport_python_command()

    def test_transport_program_rejects_a_missing_remote_helper(self) -> None:
        worker = Path(transport_program.__file__).with_name("transport_worker.py")
        snapshot_cache = self.root / "missing-helper-snapshots"
        missing_commitment = "sha256:" + "a" * 64
        missing_helper = transport_snapshot._source_transport_external_snapshot_path(
            snapshot_cache,
            missing_commitment,
        )
        argv = (
            *transport_program.source_transport_python_command(snapshot_cache),
            str(worker),
            "source-transport",
            "--remote-helper",
            str(missing_helper),
            "--remote-helper-commitment",
            missing_commitment,
        )
        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "remote_host_context_helper is unavailable",
        ):
            transport_program.transport_program_commitment(
                argv,
                snapshot_cache=snapshot_cache,
            )

    def test_transport_program_rejects_same_path_remote_snapshot_mutation(
        self,
    ) -> None:
        worker = Path(transport_program.__file__).with_name("transport_worker.py")
        snapshot_cache = self.root / "mutated-helper-snapshots"
        live_helper = self.root / "live-helper.py"
        live_helper.write_bytes(b"print('{}')\n")
        snapshot, commitment = (
            transport_remote_snapshot.snapshot_remote_host_context_helper(
                live_helper,
                snapshot_cache,
            )
        )
        argv = (
            *transport_program.source_transport_python_command(snapshot_cache),
            str(worker),
            "source-transport",
            "--remote-helper",
            str(snapshot),
            "--remote-helper-commitment",
            commitment,
        )
        original = transport_program.transport_program_commitment(
            argv,
            snapshot_cache=snapshot_cache,
        )
        self.assertRegex(original, r"sha256:[0-9a-f]{64}")
        snapshot.write_bytes(b"print('[]')\n")

        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "remote helper snapshot changed",
        ):
            transport_program.transport_program_commitment(
                argv,
                snapshot_cache=snapshot_cache,
            )

    def test_source_lease_keeps_program_snapshot_with_run_raw_state(self) -> None:
        self._write_sources("durable-program")
        coordinator = self._coordinator("run-owned-program-snapshot")
        lease = transport.TransportLease.from_dict(
            self._first_lease(coordinator)["transport_lease"]
        )
        snapshot_path = Path(lease.command_argv[10])
        self.assertEqual(
            coordinator.run_dir / "raw-inputs" / "source-program-snapshots",
            snapshot_path.parent,
        )
        self.assertEqual(0o700, snapshot_path.parent.stat().st_mode & 0o777)
        self.assertEqual(0o600, snapshot_path.stat().st_mode & 0o777)
        self.assertFalse(transport_program.SOURCE_TRANSPORT_SNAPSHOT_CACHE.exists())

        completed = subprocess.run(
            list(lease.command_argv),
            check=True,
            capture_output=True,
            env={**os.environ, "HOME": str(self.home)},
        )
        resumed = RetrospectiveOrchestrator(
            coordinator.run_dir,
            clock=lambda: "2026-07-15T00:00:00Z",
            identity_path=self.root / "identity-v2.key",
            require_existing_identity=True,
        )
        preparation = resumed.prepare_source(
            lease.lease_ref,
            completed.stdout.splitlines(keepends=True),
        )
        self.assertEqual(lease.lease_ref, preparation.lease_ref)

    def test_source_command_survives_python_alias_replacement(self) -> None:
        self._write_sources("python-alias")
        alias = self.root / "python3.13-alias"
        alias.symlink_to(sys.executable)
        snapshot_cache = self.root / "python-alias-snapshots"
        worker = Path(transport_program.__file__).with_name("transport_worker.py")
        lease_ref = str(
            self.identity.derive_ref(RefType.LEASE, {"case": "python-alias"})
        )
        command = (
            *transport_program.source_transport_python_command(
                snapshot_cache,
                executable=alias,
            ),
            str(worker),
            "source-transport",
            "--host",
            "local",
            "--source-kind",
            "history",
            "--window-start",
            WINDOW_START,
            "--window-end",
            WINDOW_END,
            "--lease-ref",
            lease_ref,
            "--process-nonce",
            "python-alias",
            "--max-source-bytes",
            str(1024 * 1024),
            "--max-records",
            "16",
            "--max-frame-bytes",
            "8192",
            "--direct-root",
            str(self.codex_root),
        )
        commitment = transport_program.transport_program_commitment(
            command,
            snapshot_cache=snapshot_cache,
        )
        self.assertEqual(os.path.realpath(sys.executable), command[0])

        alias.unlink()
        alias.symlink_to("/usr/bin/false")
        self.assertEqual(
            commitment,
            transport_program.transport_program_commitment(
                command,
                snapshot_cache=snapshot_cache,
            ),
        )
        completed = subprocess.run(command, check=True, capture_output=True, timeout=10)

        frames = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertTrue(frames[-1]["complete"])

    def test_status_rejects_authenticated_noncanonical_source_lease(self) -> None:
        self._write_sources("legacy-python-alias")
        coordinator = self._coordinator("legacy-python-alias")
        lease_view = self._first_lease(coordinator)
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        alias = self.root / "legacy-python"
        alias.symlink_to(lease.command_argv[0])
        forged = transport.issue_transport_lease(
            coordinator.identity,
            lease_ref=lease.lease_ref,
            run_ref=lease.run_ref,
            job_ref=lease.job_ref,
            host=lease.host,
            host_ref=lease.host_ref,
            source_kind=lease.source_kind,
            window_start=lease.window_start,
            window_end=lease.window_end,
            process_nonce=lease.process_nonce,
            command_argv=(str(alias), *lease.command_argv[1:]),
            transport_program_commitment=lease.transport_program_commitment,
            source_byte_limit=lease.source_byte_limit,
            record_limit=lease.record_limit,
            frame_byte_limit=lease.frame_byte_limit,
            session_target=lease.session_target,
            session_selector_commitment=lease.session_selector_commitment,
            source_cursor=lease.source_cursor,
            cursor_time=lease.cursor_time,
            resume_position=lease.resume_position,
        )

        def install_forged_lease(state):
            state["jobs"][lease.job_ref]["transport_lease"] = forged.to_dict()
            return state, None

        coordinator.store.transaction(install_forged_lease)
        with self.assertRaisesRegex(
            InvalidTransitionError,
            "cannot be projected safely",
        ):
            coordinator.status()

    def test_status_program_revalidation_does_not_recover_snapshot(self) -> None:
        self._write_sources("read-only-program-revalidation")
        coordinator = self._coordinator("read-only-program-revalidation")
        lease = self._first_lease(coordinator)

        with mock.patch.object(
            safe_io,
            "recover_atomic_create",
            side_effect=AssertionError("status must not recover snapshot state"),
        ):
            status = coordinator.status()

        self.assertEqual(
            lease["lease_ref"], status["active_source_leases"][0]["lease_ref"]
        )

    def test_transport_program_rejects_noncanonical_python_alias(self) -> None:
        alias = self.root / "noncanonical-python"
        alias.symlink_to(sys.executable)
        command = transport_program.source_transport_python_command(
            executable=alias,
        )
        worker = Path(transport_program.__file__).with_name("transport_worker.py")

        with self.assertRaisesRegex(
            transport.TransportValidationError,
            "Python path is not canonical",
        ):
            transport_program.transport_program_commitment(
                (str(alias), *command[1:], str(worker), "source-transport")
            )

    def test_committed_program_snapshot_survives_path_replacement_and_restore(
        self,
    ) -> None:
        self._write_sources("snapshot-target")
        package = self.root / "committed-program"
        package.mkdir(mode=0o700)
        live_package = Path(transport_program.__file__).parent
        originals: dict[str, bytes] = {}
        for name in transport_program.SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST:
            originals[name] = (live_package / name).read_bytes()
            (package / name).write_bytes(originals[name])
        marker = self.root / "replacement-executed"
        worker = package / "transport_worker.py"
        lease_ref = str(self.identity.derive_ref(RefType.LEASE, {"case": "snapshot"}))

        with mock.patch.object(
            transport_program,
            "__file__",
            str(package / "transport_program.py"),
        ):
            argv = (
                *transport_program.source_transport_python_command(),
                str(worker),
                "source-transport",
                "--host",
                "local",
                "--source-kind",
                "history",
                "--window-start",
                WINDOW_START,
                "--window-end",
                WINDOW_END,
                "--lease-ref",
                lease_ref,
                "--process-nonce",
                "committed-snapshot",
                "--max-source-bytes",
                str(1024 * 1024),
                "--max-records",
                "16",
                "--max-frame-bytes",
                "8192",
                "--direct-root",
                str(self.codex_root),
            )
            commitment = transport_program.transport_program_commitment(argv)
            worker.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="ascii",
            )
            (package / "catalog.py").write_text(
                "raise RuntimeError('replacement dependency executed')\n",
                encoding="ascii",
            )
            try:
                completed = subprocess.run(argv, check=True, capture_output=True)
            finally:
                worker.write_bytes(originals["transport_worker.py"])
                (package / "catalog.py").write_bytes(originals["catalog.py"])

            self.assertEqual(
                commitment,
                transport_program.transport_program_commitment(argv),
            )

        frames = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertFalse(marker.exists())
        self.assertTrue(frames[-1]["complete"])

    def test_committed_program_snapshot_does_not_import_uncommitted_module(
        self,
    ) -> None:
        package = self.root / "closed-import-program"
        package.mkdir(mode=0o700)
        live_package = Path(transport_program.__file__).parent
        for name in transport_program.SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST:
            payload = (live_package / name).read_bytes()
            if name == "transport_source.py":
                future = b"from __future__ import annotations\n"
                payload = payload.replace(
                    future,
                    future + b"import uncommitted_dependency\n",
                    1,
                )
            (package / name).write_bytes(payload)
        marker = self.root / "uncommitted-module-executed"
        package.joinpath("uncommitted_dependency.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
            encoding="ascii",
        )
        worker = package / "transport_worker.py"

        with mock.patch.object(
            transport_program,
            "__file__",
            str(package / "transport_program.py"),
        ):
            argv = (
                *transport_program.source_transport_python_command(),
                str(worker),
                "source-transport",
            )
            self.assertRegex(
                transport_program.transport_program_commitment(argv),
                r"sha256:[0-9a-f]{64}",
            )
            completed = subprocess.run(argv, capture_output=True, timeout=10)

        self.assertNotEqual(0, completed.returncode)
        self.assertFalse(marker.exists())
        self.assertIn(b"uncommitted_dependency", completed.stderr)

    def test_content_addressed_program_snapshot_is_created_once_and_recovered(
        self,
    ) -> None:
        first_command = transport_program.source_transport_python_command()
        snapshot_path = Path(first_command[-1])
        payload = snapshot_path.read_bytes()
        first_stat = snapshot_path.stat()

        second_command = transport_program.source_transport_python_command()
        second_stat = snapshot_path.stat()
        self.assertEqual(first_command, second_command)
        self.assertEqual(
            (first_stat.st_dev, first_stat.st_ino),
            (second_stat.st_dev, second_stat.st_ino),
        )

        pending_name = safe_io._atomic_create_pending_name(
            snapshot_path.name,
            payload,
        )
        pending_path = snapshot_path.parent / pending_name
        os.link(snapshot_path, pending_path)
        self.assertEqual(snapshot_path.stat().st_nlink, 2)

        recovered_command = transport_program.source_transport_python_command()
        recovered_stat = snapshot_path.stat()
        self.assertEqual(first_command, recovered_command)
        self.assertEqual(recovered_stat.st_nlink, 1)
        self.assertFalse(pending_path.exists())
        self.assertEqual(
            (first_stat.st_dev, first_stat.st_ino),
            (recovered_stat.st_dev, recovered_stat.st_ino),
        )

    def test_committed_program_snapshot_rejects_replacement_until_restored(
        self,
    ) -> None:
        self._write_sources("snapshot-restore")
        coordinator = self._coordinator("snapshot-replacement")
        lease = transport.TransportLease.from_dict(
            self._first_lease(coordinator)["transport_lease"]
        )
        snapshot_path = Path(lease.command_argv[10])
        original = snapshot_path.read_bytes()
        snapshot_path.write_bytes(b"replaced snapshot")
        try:
            rejected = subprocess.run(
                lease.command_argv,
                capture_output=True,
                env={**os.environ, "HOME": str(self.home)},
            )
        finally:
            snapshot_path.write_bytes(original)

        self.assertNotEqual(0, rejected.returncode)
        self.assertIn(b"snapshot authentication failed", rejected.stderr)
        restored = subprocess.run(
            lease.command_argv,
            check=True,
            capture_output=True,
            env={**os.environ, "HOME": str(self.home)},
        )
        self.assertTrue(restored.stdout)

    def test_program_hash_rejects_path_replacement_after_fd_open(self) -> None:
        component = self.root / "program-component.py"
        replacement = self.root / "program-component-replacement.py"
        component.write_bytes(b"A" * (128 * 1024))
        replacement.write_bytes(b"B" * (128 * 1024))
        os.chmod(component, 0o600)
        os.chmod(replacement, 0o600)
        real_read = os.read
        replaced = False

        def racing_read(descriptor: int, count: int) -> bytes:
            nonlocal replaced
            chunk = real_read(descriptor, count)
            if chunk and not replaced:
                replaced = True
                os.replace(replacement, component)
            return chunk

        with (
            mock.patch.object(transport.os, "read", side_effect=racing_read),
            self.assertRaisesRegex(
                transport.TransportValidationError,
                "changed while read",
            ),
        ):
            transport._program_component(
                component,
                role="adversarial_component",
                allow_missing=False,
            )
        self.assertTrue(replaced)

    def test_program_hash_rejects_hardlinks_and_unsafe_access_policy(self) -> None:
        component = self.root / "single-link-component.py"
        alias = self.root / "single-link-component-alias.py"
        component.write_bytes(b"print('bounded')\n")
        os.chmod(component, 0o600)
        os.link(component, alias)
        with self.assertRaisesRegex(
            transport.TransportValidationError, "exactly one link"
        ):
            transport._program_component(
                component,
                role="hardlinked_component",
                allow_missing=False,
            )
        alias.unlink()
        os.chmod(component, 0o620)
        with self.assertRaisesRegex(
            transport.TransportValidationError, "unsafe access policy"
        ):
            transport._program_component(
                component,
                role="writable_component",
                allow_missing=False,
            )

    def test_program_hash_rejects_permission_drift_after_fd_open(self) -> None:
        component = self.root / "permission-drift-component.py"
        component.write_bytes(b"A" * (128 * 1024))
        os.chmod(component, 0o600)
        real_read = os.read
        changed = False

        def racing_read(descriptor: int, count: int) -> bytes:
            nonlocal changed
            chunk = real_read(descriptor, count)
            if chunk and not changed:
                changed = True
                os.chmod(component, 0o640)
            return chunk

        with (
            mock.patch.object(transport.os, "read", side_effect=racing_read),
            self.assertRaisesRegex(
                transport.TransportValidationError, "changed while read"
            ),
        ):
            transport._program_component(
                component,
                role="permission_drift_component",
                allow_missing=False,
            )
        self.assertTrue(changed)

    def test_program_hash_accepts_timestamp_only_churn(self) -> None:
        component = self.root / "timestamp-churn-component.py"
        component.write_bytes(b"print('bounded')\n")
        os.chmod(component, 0o600)
        real_read = transport_program._read_program_component
        read_count = 0

        def touch_after_first_read(*args, **kwargs):
            nonlocal read_count
            retained = real_read(*args, **kwargs)
            read_count += 1
            if read_count == 1:
                metadata = component.stat()
                os.utime(
                    component,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1),
                )
            return retained

        with mock.patch.object(
            transport_program,
            "_read_program_component",
            side_effect=touch_after_first_read,
        ):
            authenticated = transport._program_component(
                component,
                role="timestamp_churn_component",
                allow_missing=False,
            )

        self.assertEqual("present", authenticated["state"])
        self.assertEqual(2, read_count)

    def test_program_hash_rejects_same_inode_content_mutation(self) -> None:
        component = self.root / "same-inode-mutation-component.py"
        component.write_bytes(b"A" * 4096)
        os.chmod(component, 0o600)
        original_inode = component.stat().st_ino
        real_read = transport_program._read_program_component
        read_count = 0

        def mutate_after_first_read(*args, **kwargs):
            nonlocal read_count
            retained = real_read(*args, **kwargs)
            read_count += 1
            if read_count == 1:
                component.write_bytes(b"B" * 4096)
                self.assertEqual(original_inode, component.stat().st_ino)
            return retained

        with (
            mock.patch.object(
                transport_program,
                "_read_program_component",
                side_effect=mutate_after_first_read,
            ),
            self.assertRaisesRegex(
                transport.TransportValidationError,
                "changed while read",
            ),
        ):
            transport._program_component(
                component,
                role="same_inode_mutation_component",
                allow_missing=False,
            )

    def test_package_program_hash_accepts_unrelated_child_churn(self) -> None:
        package = self.root / "bounded-package"
        package.mkdir(mode=0o700)
        package.joinpath("worker.py").write_bytes(b"VALUE = 1\n")
        os.chmod(package / "worker.py", 0o600)
        real_component = transport_program._program_component_at
        changed = False

        def add_unrelated_child(*args, **kwargs):
            nonlocal changed
            authenticated = real_component(*args, **kwargs)
            if not changed:
                changed = True
                package.joinpath("__pycache__").mkdir(mode=0o700)
            return authenticated

        with (
            mock.patch.object(
                transport_program,
                "SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST",
                ("worker.py",),
            ),
            mock.patch.object(
                transport_program,
                "_program_component_at",
                side_effect=add_unrelated_child,
            ),
        ):
            components = transport._package_program_components(package)

        self.assertTrue(changed)
        self.assertEqual("present", components[0]["state"])

    def test_snapshot_bootstraps_reject_special_file_replacements(self) -> None:
        regular = self.root / "bootstrap-snapshot"
        regular.write_bytes(b"not-a-snapshot")
        os.chmod(regular, 0o600)
        symlink = self.root / "bootstrap-snapshot-symlink"
        symlink.symlink_to(regular)
        hardlink = self.root / "bootstrap-snapshot-hardlink"
        os.link(regular, hardlink)
        fifo = self.root / "bootstrap-snapshot-fifo"
        os.mkfifo(fifo, 0o600)
        unsafe = self.root / "bootstrap-snapshot-unsafe"
        unsafe.write_bytes(b"not-a-snapshot")
        os.chmod(unsafe, 0o620)
        digest = "sha256:" + hashlib.sha256(regular.read_bytes()).hexdigest()

        for name, path in (
            ("symlink", symlink),
            ("hardlink", hardlink),
            ("fifo", fifo),
            ("unsafe", unsafe),
        ):
            with self.subTest(name=name):
                completed = subprocess.run(
                    (
                        sys.executable,
                        "-I",
                        "-B",
                        "-X",
                        f"pycache_prefix={os.devnull}",
                        "-c",
                        transport_snapshot.SOURCE_TRANSPORT_SNAPSHOT_BOOTSTRAP,
                        transport_program.SOURCE_TRANSPORT_SNAPSHOT_SCHEMA,
                        digest,
                        str(path),
                        "transport-worker.py",
                    ),
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                self.assertNotEqual(0, completed.returncode)

        remote = subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                "-X",
                f"pycache_prefix={os.devnull}",
                "-c",
                transport_snapshot.REMOTE_HOST_CONTEXT_SNAPSHOT_BOOTSTRAP,
                transport_snapshot.REMOTE_HOST_CONTEXT_SNAPSHOT_SCHEMA,
                digest,
                str(fifo),
                "session-shards",
            ),
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertNotEqual(0, remote.returncode)


if __name__ == "__main__":
    unittest.main()
