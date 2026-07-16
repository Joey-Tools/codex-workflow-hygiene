from __future__ import annotations

import copy
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
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
from retrospective_v2.contracts import canonical_json  # noqa: E402
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
            clock=lambda: "2026-07-15T00:00:00Z",
            identity=self.identity,
        )
        self.coordinator.start(
            mode="daily",
            start=WINDOW_START,
            end=WINDOW_END,
            hosts=("local",),
            created_at="2026-07-15T00:00:00Z",
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
        self.assertEqual(3, rejected["exit_code"])
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
            normalized, request = cli._session_shard_transcript(
                Path("unused-session-shards.jsonl"),
                expected_host="local",
            )
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

        self.assertEqual(0, active_streams)
        self.assertEqual(2, opened_streams)

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
