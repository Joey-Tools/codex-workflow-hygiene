from __future__ import annotations

import copy
import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/codex-session-retrospective" / "scripts"
CLI = SCRIPTS / "session_retrospective_v2.py"
sys.path.insert(0, str(SCRIPTS))

import session_retrospective_v2 as cli  # noqa: E402
from retrospective_v2 import (  # noqa: E402
    authority,
    catalog,
    orchestrator as orchestrator_module,
    session_shards_adapter,
    transport,
)
from retrospective_v2.contracts import (  # noqa: E402
    SessionShardsRequest,
    canonical_json,
)
from retrospective_v2.identity import IdentityKey  # noqa: E402
from retrospective_v2.orchestrator import (  # noqa: E402
    RetrospectiveOrchestrator,
)
from tests.test_retrospective_v2_orchestrator import (  # noqa: E402
    bind_remote_host_context_helper_fixture,
    execution_provenance,
)


WINDOW_START = "2026-07-06T00:00:00Z"
WINDOW_END = "2026-07-07T00:00:00Z"


class SessionShardsAdapterCliTests(unittest.TestCase):
    def setUp(self) -> None:
        bind_remote_host_context_helper_fixture(self)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.codex_root = self.home / ".codex"
        self.codex_root.mkdir(mode=0o700)
        self.codex_root.joinpath("session_index.jsonl").write_bytes(b"")
        self.codex_root.joinpath("history.jsonl").write_bytes(b"")
        self.rollout = (
            "sessions/2026/07/06/rollout-2026-07-06T01-00-00-adapter-session.jsonl"
        )
        rollout_path = self.codex_root / self.rollout
        rollout_path.parent.mkdir(mode=0o700, parents=True)
        self.raw_secret = "SEALED_RAW_ADAPTER_SECRET_72a1"
        rollout_path.write_text(
            canonical_json(
                {
                    "payload": {"id": "adapter-session"},
                    "timestamp": "2026-07-06T01:00:00Z",
                    "type": "session_meta",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        with rollout_path.open("a", encoding="utf-8") as stream:
            stream.write(
                canonical_json(
                    {
                        "payload": {
                            "content": [
                                {"text": self.raw_secret, "type": "input_text"}
                            ],
                            "role": "user",
                        },
                        "session_id": "adapter-session",
                        "timestamp": "2026-07-06T01:01:00Z",
                        "type": "response_item",
                    }
                )
                + "\n"
            )
        excluded_rollout = self.codex_root.joinpath(
            "sessions/2026/07/06/rollout-2026-07-06T02-00-00-excluded.jsonl"
        )
        excluded_rollout.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        excluded_rollout.write_text(
            canonical_json(
                {
                    "payload": {"id": "excluded-session"},
                    "timestamp": "2010-01-01T00:00:00Z",
                    "type": "session_meta",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.identity_path = self.root / "identity-v2.key"
        self.identity = IdentityKey.create(self.identity_path)
        self.created_at = (
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        history = authority.DurableHistoryState(
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
            return_value=history,
        )
        self.history_patch.start()
        self.host_policy_patch = mock.patch.object(
            orchestrator_module,
            "DEFAULT_HOSTS",
            ("local",),
        )
        self.host_policy_patch.start()
        self.run_dir = self.root / "run"
        self.coordinator = RetrospectiveOrchestrator(
            self.run_dir,
            clock=lambda: self.created_at,
            identity=self.identity,
        )
        self.coordinator.start(
            mode="daily",
            start=WINDOW_START,
            end=WINDOW_END,
            hosts=("local",),
            created_at=self.created_at,
            history_repo=self.root / "history",
            history_target_ref="refs/heads/main",
            provenance=execution_provenance(),
            shadow=True,
        )
        self.environment = dict(os.environ)
        self.environment["HOME"] = str(self.home)

    def tearDown(self) -> None:
        self.host_policy_patch.stop()
        self.history_patch.stop()
        self.temporary.cleanup()

    def capture(self, lease_view: dict[str, object]) -> bytes:
        lease = transport.TransportLease.from_dict(lease_view["transport_lease"])
        completed = subprocess.run(
            list(lease.command_argv),
            check=True,
            capture_output=True,
            env=self.environment,
        )
        return completed.stdout

    def advance_to_active_rollout(self) -> dict[str, object]:
        for _ in range(20):
            leases = self.coordinator.status()["active_source_leases"]
            if not leases:
                self.coordinator.advance()
                continue
            lease = leases[0]
            if lease["source_kind"] == "active_rollout":
                return lease
            preparation = self.coordinator.prepare_source(
                lease["lease_ref"],
                self.capture(lease).splitlines(keepends=True),
            )
            self.coordinator.accept_source(
                lease["lease_ref"],
                preparation.manifest,
                transport_receipt=preparation.receipt,
                raw_records=preparation.raw_records,
            )
        self.fail("active rollout lease was not scheduled")

    @staticmethod
    def wrapped(
        frames: list[dict[str, object]],
        *,
        rollout: str,
    ) -> list[dict[str, object]]:
        return [{**frame, "host": "local", "rollout": rollout} for frame in frames]

    def shard_streams(
        self,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        descriptors = list(
            transport._iter_local_session_shard_frames(
                codex_root=self.codex_root,
                rollout_relative_path=PurePosixPath(self.rollout),
                emit="descriptors",
                byte_start=0,
                byte_end=None,
                shard_bytes=orchestrator_module.EXTRACTOR_SHARD_MAX_BYTES,
                max_shards=transport.DEFAULT_SESSION_SHARDS_PER_PAGE,
                source_token=None,
                resume_cursor=None,
                record_processing_budget_bytes=(
                    transport.DEFAULT_SESSION_RECORD_PROCESSING_BUDGET_BYTES
                ),
            )
        )
        wrapped_descriptors = self.wrapped(descriptors, rollout=self.rollout)
        plan = session_shards_adapter.descriptor_plan_from_frames(
            wrapped_descriptors,
            expected_host="local",
        )
        assert plan.records_request is not None
        request = plan.records_request
        records = list(
            transport._iter_local_session_shard_frames(
                codex_root=self.codex_root,
                rollout_relative_path=PurePosixPath(self.rollout),
                emit="records",
                byte_start=request.byte_start,
                byte_end=request.byte_end,
                shard_bytes=request.shard_bytes,
                max_shards=request.max_shards,
                source_token=request.source_token,
                resume_cursor=request.resume_cursor,
                record_processing_budget_bytes=(request.record_processing_budget_bytes),
            )
        )
        return wrapped_descriptors, self.wrapped(records, rollout=self.rollout)

    def write_jsonl(self, name: str, frames: list[dict[str, object]]) -> Path:
        directory = self.run_dir / "raw-inputs" / "adapter-cli"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / name
        path.write_text(
            "".join(canonical_json(frame) + "\n" for frame in frames),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        return path

    def invoke(self, *arguments: str) -> tuple[dict[str, object], str]:
        completed = subprocess.run(
            [sys.executable, str(CLI), *arguments],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(1, completed.stdout.count("\n"), completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, result["exit_code"])
        return result, completed.stdout + completed.stderr

    def test_descriptor_record_frames_close_prepare_to_accept_loop(self) -> None:
        lease = self.advance_to_active_rollout()
        self.assertNotIn("execute-source", canonical_json(lease))
        self.assertNotIn("prepare-source", canonical_json(lease))
        transport_path = self.run_dir / "raw-inputs" / "source-transport.jsonl"
        transport_bytes = self.capture(lease)
        transport_path.write_bytes(transport_bytes)
        os.chmod(transport_path, 0o600)
        preparation = self.coordinator.prepare_source(
            lease["lease_ref"],
            transport_bytes.splitlines(keepends=True),
        )
        prepared_manifest = catalog.SourceTransportManifest.from_dict(
            preparation.manifest
        )
        candidate_source_refs = {
            record.coordinate.source_ref
            for record in prepared_manifest.records
            if record.accounting_class is catalog.AccountingClass.CONSUMED_CANDIDATE
        }
        self.assertEqual(1, len(candidate_source_refs))
        excluded_source_refs = {
            record.coordinate.source_ref
            for record in prepared_manifest.records
            if record.accounting_class is catalog.AccountingClass.STRUCTURALLY_EXCLUDED
        }
        excluded_only_source_refs = excluded_source_refs - candidate_source_refs
        self.assertEqual(1, len(excluded_only_source_refs))
        descriptors, records = self.shard_streams()
        transcript_path = self.write_jsonl(
            "session-shards.jsonl", [*descriptors, *records]
        )
        source_ref = next(iter(candidate_source_refs))
        truncated_path = self.write_jsonl(
            "truncated-session-shards.jsonl", [*descriptors[:-1], *records]
        )
        rejected, diagnostic = self.invoke(
            "accept-source",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--run-dir",
            str(self.run_dir),
            "--lease-ref",
            lease["lease_ref"],
            "--transport-stream-file",
            str(transport_path),
            "--transport-stream",
            source_ref,
            str(truncated_path),
        )
        self.assertEqual(3, rejected["exit_code"], rejected)
        self.assertNotIn(self.raw_secret, diagnostic)
        self.assertEqual(
            "leased",
            self.coordinator.store.read().state["source"]["cells"]["local"][
                "active_rollout"
            ]["status"],
        )
        accepted, diagnostic = self.invoke(
            "accept-source",
            "--identity-path",
            str(self.identity_path),
            "--require-existing-identity",
            "--run-dir",
            str(self.run_dir),
            "--lease-ref",
            lease["lease_ref"],
            "--transport-stream-file",
            str(transport_path),
            "--transport-stream",
            source_ref,
            str(transcript_path),
        )
        self.assertEqual(0, accepted["exit_code"], accepted)
        self.assertTrue(accepted["result"]["accepted"])
        self.assertEqual("complete", accepted["result"]["outcome"])
        self.assertNotIn("execute-source", canonical_json(accepted))
        self.assertNotIn(self.raw_secret, diagnostic)

    def test_transcript_closes_descriptor_pass_before_returning_records(self) -> None:
        descriptors, records = self.shard_streams()
        transcript = [*descriptors, *records]
        active_streams = 0
        opened_streams = 0

        def tracked_frames(_path: str):
            nonlocal active_streams, opened_streams
            active_streams += 1
            opened_streams += 1
            try:
                yield from transcript
            finally:
                active_streams -= 1

        with mock.patch.object(
            cli,
            "_iter_transport_frames",
            side_effect=tracked_frames,
        ):
            segments = iter(
                cli._session_shard_transcript(
                    Path("unused-session-shards.jsonl"),
                    expected_host="local",
                )
            )
            normalized, request = next(segments)
            self.assertEqual(0, active_streams)
            self.assertEqual(1, opened_streams)
            self.assertEqual("records", request.mode)
            self.assertEqual(
                [
                    {
                        key: value
                        for key, value in frame.items()
                        if key not in {"host", "rollout"}
                    }
                    for frame in records
                ],
                list(normalized),
            )
            with self.assertRaises(StopIteration):
                next(segments)

        self.assertEqual(0, active_streams)
        self.assertEqual(2, opened_streams)

    def test_abandoned_record_stream_closes_replay_before_outer_generator(self) -> None:
        descriptors, records = self.shard_streams()
        transcript = [*descriptors, *records]
        active_streams = 0
        opened_streams = 0

        def tracked_frames(_path: str):
            nonlocal active_streams, opened_streams
            active_streams += 1
            opened_streams += 1
            try:
                yield from transcript
            finally:
                active_streams -= 1

        with mock.patch.object(
            cli,
            "_iter_transport_frames",
            side_effect=tracked_frames,
        ):
            segments = iter(
                cli._session_shard_transcript(
                    Path("unused-session-shards.jsonl"),
                    expected_host="local",
                )
            )
            normalized, _request = next(segments)
            records_iterator = iter(normalized)
            next(records_iterator)
            self.assertEqual(1, active_streams)

            records_iterator.close()
            self.assertEqual(0, active_streams)
            self.assertEqual(2, opened_streams)
            segments.close()

    def test_stream_segmentation_does_not_materialize_large_frame_pages(self) -> None:
        frame_count = 50_000
        produced = 0

        def frames():
            nonlocal produced
            produced += 1
            yield {"kind": "stream_meta"}
            for index in range(frame_count):
                produced += 1
                yield {"kind": "record", "index": index}
            produced += 1
            yield {"kind": "stream_end"}
            produced += 1
            yield {"kind": "next_stream"}

        source = iter(frames())
        stream = cli.transcript_api._next_stream(source)
        self.assertIsNotNone(stream)
        self.assertEqual(1, produced)

        tracemalloc.start()
        try:
            self.assertEqual(frame_count + 2, sum(1 for _frame in stream))
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertLess(peak, 2 * 1024 * 1024)
        self.assertEqual(frame_count + 2, produced)
        self.assertEqual({"kind": "next_stream"}, next(source))

    def test_adapter_binds_continuation_meta_to_the_request_cursor(self) -> None:
        data = (self.codex_root / self.rollout).read_bytes()
        first_line = data.splitlines(keepends=True)[0]
        first_page = list(
            transport._iter_local_session_shard_frames(
                codex_root=self.codex_root,
                rollout_relative_path=PurePosixPath(self.rollout),
                emit="descriptors",
                byte_start=0,
                byte_end=None,
                shard_bytes=len(first_line),
                max_shards=1,
                source_token=None,
                resume_cursor=None,
            )
        )
        first_plan = session_shards_adapter.descriptor_plan_from_frames(
            self.wrapped(first_page, rollout=self.rollout),
            expected_host="local",
        )
        assert first_plan.next_descriptor_request is not None
        request = first_plan.next_descriptor_request
        second_page = self.wrapped(
            list(
                transport._iter_local_session_shard_frames(
                    codex_root=self.codex_root,
                    rollout_relative_path=PurePosixPath(self.rollout),
                    emit="descriptors",
                    byte_start=request.byte_start,
                    byte_end=None,
                    shard_bytes=request.shard_bytes,
                    max_shards=request.max_shards,
                    source_token=request.source_token,
                    resume_cursor=request.resume_cursor,
                    record_processing_budget_bytes=(
                        request.record_processing_budget_bytes
                    ),
                )
            ),
            rollout=self.rollout,
        )
        meta = second_page[0]
        mutations = {
            "source_token": "session_shards_source_v2:" + "f" * 64,
            "source_bytes": int(meta["source_bytes"]) + 1,
            "record_start": int(meta["record_start"]) + 1,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(second_page)
                changed[0][field] = value
                with self.assertRaisesRegex(
                    session_shards_adapter.SessionShardsAdapterError,
                    "request cursor coordinates",
                ):
                    session_shards_adapter.descriptor_plan_from_frames(
                        changed,
                        expected_host="local",
                    )

    def test_transcript_pages_records_by_the_data_frame_limit(self) -> None:
        data = b"{}\n" * (transport.MAX_SESSION_SHARDS_RECORD_DATA_FRAMES + 1)
        (self.codex_root / self.rollout).write_bytes(data)
        descriptor_pages: list[list[dict[str, object]]] = []
        plans: list[session_shards_adapter.SessionShardsDescriptorPlan] = []
        request: SessionShardsRequest | None = None
        while True:
            descriptors = list(
                transport._iter_local_session_shard_frames(
                    codex_root=self.codex_root,
                    rollout_relative_path=PurePosixPath(self.rollout),
                    emit="descriptors",
                    byte_start=0 if request is None else request.byte_start,
                    byte_end=None,
                    shard_bytes=orchestrator_module.EXTRACTOR_SHARD_MAX_BYTES,
                    max_shards=transport.DEFAULT_SESSION_SHARDS_PER_PAGE,
                    source_token=None if request is None else request.source_token,
                    resume_cursor=None if request is None else request.resume_cursor,
                    record_processing_budget_bytes=(
                        transport.DEFAULT_SESSION_RECORD_PROCESSING_BUDGET_BYTES
                    ),
                )
            )
            wrapped = self.wrapped(descriptors, rollout=self.rollout)
            plan = session_shards_adapter.descriptor_plan_from_frames(
                wrapped,
                expected_host="local",
            )
            descriptor_pages.append(wrapped)
            plans.append(plan)
            if plan.complete:
                break
            assert plan.next_descriptor_request is not None
            request = plan.next_descriptor_request

        record_streams: list[list[dict[str, object]]] = []
        for plan in plans:
            assert plan.records_request is not None
            record_request = plan.records_request
            record_streams.append(
                self.wrapped(
                    list(
                        transport._iter_local_session_shard_frames(
                            codex_root=self.codex_root,
                            rollout_relative_path=PurePosixPath(self.rollout),
                            emit="records",
                            byte_start=record_request.byte_start,
                            byte_end=record_request.byte_end,
                            shard_bytes=record_request.shard_bytes,
                            max_shards=record_request.max_shards,
                            source_token=record_request.source_token,
                            resume_cursor=record_request.resume_cursor,
                            record_processing_budget_bytes=(
                                record_request.record_processing_budget_bytes
                            ),
                        )
                    ),
                    rollout=self.rollout,
                )
            )
        transcript = [
            frame for stream in (*descriptor_pages, *record_streams) for frame in stream
        ]

        with mock.patch.object(
            cli,
            "_iter_transport_frames",
            side_effect=lambda _path: iter(copy.deepcopy(transcript)),
        ):
            segments = iter(
                cli._session_shard_transcript(
                    Path("unused-paged-session-shards.jsonl"),
                    expected_host="local",
                )
            )
            record_counts = []
            for frames, _request in segments:
                record_counts.append(
                    len([frame for frame in frames if frame["kind"] == "record"])
                )

        self.assertEqual(
            [transport.MAX_SESSION_SHARDS_RECORD_DATA_FRAMES, 1],
            record_counts,
        )

    def test_host_bound_adapter_rejects_missing_wrapper(self) -> None:
        descriptors, _records = self.shard_streams()
        unwrapped = [
            {
                key: value
                for key, value in frame.items()
                if key not in {"host", "rollout"}
            }
            for frame in descriptors
        ]

        with self.assertRaisesRegex(
            session_shards_adapter.SessionShardsAdapterError,
            "wrapper is required",
        ):
            session_shards_adapter.descriptor_plan_from_frames(
                unwrapped,
                expected_host="local",
            )

    def test_adapter_rejects_a_different_record_data_frame_limit(self) -> None:
        descriptors, _records = self.shard_streams()
        changed = copy.deepcopy(descriptors)
        changed[0]["max_record_data_frames"] = (
            transport.MAX_SESSION_SHARDS_RECORD_DATA_FRAMES + 1
        )

        with self.assertRaisesRegex(
            session_shards_adapter.SessionShardsAdapterError,
            "unsupported",
        ):
            session_shards_adapter.descriptor_plan_from_frames(
                changed,
                expected_host="local",
            )

    def test_adapter_uses_only_terminal_frozen_cursor_for_records(self) -> None:
        descriptors, _records = self.shard_streams()
        plan = session_shards_adapter.descriptor_plan_from_frames(
            descriptors,
            expected_host="local",
        )
        terminal = next(
            frame for frame in descriptors if frame.get("kind") == "stream_end"
        )
        assert plan.records_request is not None
        self.assertEqual(
            plan.records_request.resume_cursor,
            terminal["records_resume_cursor"],
        )

        changed = copy.deepcopy(descriptors)
        changed_terminal = next(
            frame for frame in changed if frame.get("kind") == "stream_end"
        )
        first_shard = next(frame for frame in changed if frame.get("kind") == "shard")
        changed_terminal["records_resume_cursor"] = first_shard["resume_cursor"]
        with self.assertRaisesRegex(
            session_shards_adapter.SessionShardsAdapterError,
            "records cursor",
        ):
            session_shards_adapter.descriptor_plan_from_frames(
                changed,
                expected_host="local",
            )

    def test_host_bound_adapter_rejects_cross_host_replay(self) -> None:
        descriptors, _records = self.shard_streams()
        replayed = copy.deepcopy(descriptors)
        for frame in replayed:
            frame["host"] = "other-host"

        with self.assertRaisesRegex(
            session_shards_adapter.SessionShardsAdapterError,
            "does not match",
        ):
            session_shards_adapter.descriptor_plan_from_frames(
                replayed,
                expected_host="local",
            )

    def test_adapter_rejects_mixed_wrapped_and_unwrapped_record_stream(self) -> None:
        _descriptors, records = self.shard_streams()
        mixed = copy.deepcopy(records)
        mixed[0].pop("host")
        mixed[0].pop("rollout")

        with self.assertRaisesRegex(
            session_shards_adapter.SessionShardsAdapterError,
            "wrapper presence changed",
        ):
            list(
                session_shards_adapter.normalize_record_frames(
                    mixed,
                    expected_host=None,
                    expected_rollout=self.rollout,
                )
            )


if __name__ == "__main__":
    unittest.main()
