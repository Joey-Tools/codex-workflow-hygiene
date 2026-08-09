from __future__ import annotations

import base64
import copy
from dataclasses import replace
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
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
    cleanup_inventory,
    cleanup_sidecars,
    contracts,
    controlled_gaps,
    episode_review,
    orchestrator_jobs,
    reporting,
    retained_inputs,
    result_validation,
    safe_io,
    sharding,
    source_inputs,
    transport,
)
from retrospective_v2.checkpoints import (  # noqa: E402
    AtomicCheckpointStore,
    CheckpointConflictError,
    CheckpointPermissionError,
    DEFAULT_MAX_CHECKPOINT_BYTES,
    canonical_json_bytes,
    content_digest,
)
from retrospective_v2.contracts import (  # noqa: E402
    AgentFailure,
    AgentFailureKind,
    JobKind,
    RefType,
    RunMode,
    RunStage,
    SessionShardsRequest,
    SourceKind,
    format_typed_ref,
)
from retrospective_v2.identity import (  # noqa: E402
    IdentityKey,
    IdentityKeyMismatchError,
)
from retrospective_v2.export import export_retained_bundle  # noqa: E402
import retrospective_v2.orchestrator as orchestrator_module  # noqa: E402
from retrospective_v2.orchestrator import (  # noqa: E402
    DEFAULT_HOSTS,
    MAX_SESSION_SHARDS_RECORD_DATA_FRAMES,
    PUBLISHER_FINGERPRINT,
    PUBLISHER_UID,
    SESSION_SHARDS_FIXED_MEMORY_ENVELOPE_BYTES,
    SESSION_SHARDS_MAX_FRAME_CHARS,
    SESSION_SHARDS_MAX_JSON_NESTING_DEPTH,
    SESSION_SHARDS_PROTOCOL_FEATURES,
    SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
    SESSION_SHARDS_SCHEMA,
    InvalidInputError,
    InvalidTransitionError,
    RetrospectiveOrchestrator,
    RunConflictError,
    _transport_accounting_bytes,
    consume_session_shard_frames,
    doctor,
    publisher_readiness,
)
from retrospective_v2.orchestrator_core import (  # noqa: E402
    LEGACY_SHADOW_CLEANUP_ROOTS,
    REQUIRED_SOURCE_KINDS,
)


WINDOW_START = "2026-07-06T00:00:00Z"
WINDOW_END = "2026-07-13T00:00:00Z"
DAILY_END = "2026-07-07T00:00:00Z"
REMOTE_HOST = "miku-bot-dev"
REMOTE_HOST_CONTEXT_HELPER_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "remote_host_context_helper.py"
)


def bind_remote_host_context_helper_fixture(test_case: unittest.TestCase) -> None:
    for target in (
        "retrospective_v2.transport.remote_host_context_helper_path",
        "retrospective_v2.transport_remote.remote_host_context_helper_path",
    ):
        patcher = mock.patch(
            target,
            return_value=REMOTE_HOST_CONTEXT_HELPER_FIXTURE,
        )
        patcher.start()
        test_case.addCleanup(patcher.stop)


def execution_provenance(
    *,
    model: str = "gpt-5.6-sol",
    reasoning_effort: str = "xhigh",
    service_tier: str = "priority",
) -> dict[str, object]:
    return {
        "model": {
            "model": model,
            "parameters": {
                "reasoning_effort": reasoning_effort,
                "service_tier": service_tier,
            },
            "provider": "openai",
        },
        "prompt": {
            "digest": orchestrator_module.PROMPT_DIGEST,
            "version": orchestrator_module.PROMPT_VERSION,
        },
        "schema": orchestrator_module.EXECUTION_CONTRACT_SCHEMA,
        "transport": {
            "remote_host_context_helper_commitment": (
                transport.remote_host_context_helper_commitment(
                    REMOTE_HOST_CONTEXT_HELPER_FIXTURE
                )
            ),
            "source_transport_schema": transport.SOURCE_TRANSPORT_STREAM_SCHEMA,
        },
        "versions": dict(orchestrator_module.EXECUTION_VERSION_CONTRACT),
    }


def typed_ref(kind: RefType, seed: str) -> str:
    return format_typed_ref(kind, hashlib.sha256(seed.encode("utf-8")).hexdigest())


def adjudication_item_decisions(
    candidates: list[dict[str, object]], adjudication_result: dict[str, object]
) -> list[dict[str, object]]:
    fields = (
        "events",
        "findings",
        "strengths",
        "risk_flags",
        "high_impact_turns",
        "evidence_refs",
    )

    def canonical(value: object) -> str:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    rows: list[dict[str, object]] = []
    for candidate in candidates:
        candidate_hash = result_validation.canonical_result_hash(candidate)
        for field in fields:
            retained = {canonical(item) for item in adjudication_result[field]}
            for item in candidate[field]:
                item_value = canonical(item)
                duplicate = (
                    sum(
                        item_value
                        in {canonical(other) for other in other_candidate[field]}
                        for other_candidate in candidates
                    )
                    > 1
                )
                is_retained = item_value in retained
                rows.append(
                    {
                        "attempt_ref": candidate["attempt_ref"],
                        "candidate_result_hash": candidate_hash,
                        "disposition": (
                            "merged"
                            if is_retained and duplicate
                            else "selected"
                            if is_retained
                            else "rejected"
                        ),
                        "field": field,
                        "item_hash": hashlib.sha256(
                            item_value.encode("utf-8")
                        ).hexdigest(),
                        "reason": (
                            "duplicate_supported"
                            if is_retained and duplicate
                            else "retained_supported"
                            if is_retained
                            else "lower_confidence"
                        ),
                        "reviewer_ref": candidate["reviewer_ref"],
                        "reviewer_slot": candidate["reviewer_slot"],
                    }
                )
    return rows


def source_token(seed: str) -> str:
    return "session_shards_source_v2:" + hashlib.sha256(seed.encode()).hexdigest()


def session_shards_argv(request: SessionShardsRequest) -> tuple[str, ...]:
    assert request.byte_end is not None
    assert request.source_token is not None
    assert request.resume_cursor is not None
    return (
        "python3",
        "remote_codex_probe.py",
        "session-shards",
        "--rollout",
        request.rollout,
        "--emit",
        request.mode,
        "--byte-start",
        str(request.byte_start),
        "--byte-end",
        str(request.byte_end),
        "--shard-bytes",
        str(request.shard_bytes),
        "--max-shards",
        str(request.max_shards),
        "--record-processing-budget-bytes",
        str(request.record_processing_budget_bytes),
        "--source-token",
        request.source_token,
        "--resume-cursor",
        request.resume_cursor,
    )


class FixedClock:
    def __init__(self) -> None:
        self.value = dt.datetime(2026, 7, 14, 12, 0, tzinfo=dt.timezone.utc)

    def __call__(self) -> dt.datetime:
        return self.value


def no_activity_manifest(lease: dict[str, object]) -> catalog.SourceTransportManifest:
    is_local = lease["host"] == "local"
    remote = None
    if not is_local:
        transport_lease = lease["transport_lease"]
        remote = catalog.RemoteTransportBinding(
            process_nonce=transport_lease["process_nonce"],
            forced_command_argv=tuple(transport_lease["command_argv"]),
        )
    return catalog.SourceTransportManifest.create(
        host_ref=lease["host_ref"],
        transport_kind=(
            catalog.TransportKind.LOCAL if is_local else catalog.TransportKind.REMOTE
        ),
        source_kind=lease["source_kind"],
        window_start=lease["window"]["start"],
        window_end=lease["window"]["end"],
        status=catalog.SourceCellStatus.NO_ACTIVITY,
        records=(),
        snapshot_commitment=catalog.snapshot_commitment_for_records(()),
        remote=remote,
    )


def activity_manifest(
    lease: dict[str, object],
    payloads: list[bytes],
    *,
    status: catalog.SourceCellStatus = catalog.SourceCellStatus.COMPLETE,
    gap_reasons: dict[int, str] | None = None,
    source_ref: str | None = None,
) -> tuple[catalog.SourceTransportManifest, list[catalog.CatalogRecord], str]:
    source_ref = source_ref or typed_ref(
        RefType.SESSION, f"source:{lease['host_ref']}:{lease['source_kind']}"
    )
    records: list[catalog.CatalogRecord] = []
    offset = 0
    for index, payload in enumerate(payloads):
        coordinate = catalog.StableSourceCoordinate(
            host_ref=lease["host_ref"],
            source_ref=source_ref,
            record_ref=f"record-{index}",
            byte_start=offset,
            byte_end=offset + len(payload),
        )
        if gap_reasons and index in gap_reasons:
            records.append(
                catalog.CatalogRecord(
                    unit_ref=typed_ref(
                        RefType.SOURCE_UNIT,
                        f"unit:{source_ref}:{lease['source_kind']}:{index}",
                    ),
                    source_kind=lease["source_kind"],
                    coordinate=coordinate,
                    accounting_class=catalog.AccountingClass.EXPLICIT_GAP,
                    content_commitment=None,
                    event_time=None,
                    turn_count=0,
                    gap=catalog.ExplicitGap(
                        reason=gap_reasons[index],
                        stage="source_transport",
                    ),
                )
            )
        else:
            records.append(
                catalog.CatalogRecord(
                    unit_ref=typed_ref(
                        RefType.SOURCE_UNIT,
                        f"unit:{source_ref}:{lease['source_kind']}:{index}",
                    ),
                    source_kind=lease["source_kind"],
                    coordinate=coordinate,
                    accounting_class=catalog.AccountingClass.CONSUMED_CANDIDATE,
                    content_commitment=catalog.content_commitment(payload),
                    event_time="2026-07-06T01:00:00Z",
                    turn_count=1,
                )
            )
        offset += len(payload)
    manifest = catalog.SourceTransportManifest.create(
        host_ref=lease["host_ref"],
        transport_kind=(
            catalog.TransportKind.LOCAL
            if lease["host"] == "local"
            else catalog.TransportKind.REMOTE
        ),
        source_kind=lease["source_kind"],
        window_start=lease["window"]["start"],
        window_end=lease["window"]["end"],
        status=status,
        records=records,
        snapshot_commitment=(
            catalog.snapshot_commitment_for_records(records)
            if status is catalog.SourceCellStatus.COMPLETE
            else None
        ),
        remote=(
            None
            if lease["host"] == "local"
            else catalog.RemoteTransportBinding(
                process_nonce=lease["transport_lease"]["process_nonce"],
                forced_command_argv=tuple(lease["transport_lease"]["command_argv"]),
            )
        ),
    )
    return manifest, records, source_ref


def authenticated_receipt(
    coordinator: RetrospectiveOrchestrator,
    lease: dict[str, object],
    manifest: catalog.SourceTransportManifest,
    raw_records: dict[str, bytes] | None = None,
    authorize: bool = True,
) -> dict[str, object]:
    payloads = raw_records or {}
    transcript = transport.transcript_commitment(
        payloads,
        source_marker=str(lease["lease_ref"]),
    )
    terminal = manifest.status in {
        catalog.SourceCellStatus.COMPLETE,
        catalog.SourceCellStatus.NO_ACTIVITY,
        catalog.SourceCellStatus.VERIFIED_ABSENT,
    }
    source_bytes = sum(len(value) for value in payloads.values())
    snapshot = transport.AuthoritativeSourceSnapshot.create(
        host_ref=manifest.host_ref,
        source_kind=manifest.source_kind,
        window_start=manifest.window_start,
        window_end=manifest.window_end,
        session_target=lease["transport_lease"]["session_target"],
        source_content_commitment=transcript,
        source_byte_count=source_bytes,
        terminal_byte_offset=source_bytes if terminal else 0,
        catalog_record_count=manifest.total_records,
        catalog_byte_count=manifest.total_bytes,
        catalog_commitment=manifest.snapshot_commitment,
        transcript_commitment=transcript,
        terminal_proof_commitment=(
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    {
                        "lease_ref": lease["lease_ref"],
                        "manifest": manifest.to_dict(),
                        "schema": "test_observed_terminal_proof_v2",
                    },
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest()
        ),
        terminal_status=manifest.status,
        terminal_reason=(
            "source_absent"
            if manifest.status is catalog.SourceCellStatus.VERIFIED_ABSENT
            else "source_gap"
            if manifest.status is catalog.SourceCellStatus.GAP
            else "source_enumeration_complete"
        ),
        complete=terminal,
        resume_position=None,
    )
    receipt = transport.issue_transport_receipt(
        coordinator.identity,
        lease=transport.TransportLease.from_dict(lease["transport_lease"]),
        manifest=manifest.to_dict(),
        source_snapshot=snapshot,
    )
    if authorize:
        coordinator._authorize_transport_receipt(
            str(lease["lease_ref"]),
            manifest,
            receipt,
        )
    return receipt.to_dict()


def record_stream_frames(
    records: list[catalog.CatalogRecord],
    payloads: list[bytes],
    limits: sharding.ShardLimits,
    *,
    token_seed: str,
    frozen_payloads: list[bytes] | None = None,
    record_start: int = 0,
) -> tuple[SessionShardsRequest, list[dict[str, object]]]:
    token = source_token(token_seed)
    first = records[0].coordinate.byte_start
    last = records[-1].coordinate.byte_end
    frozen_values = payloads if frozen_payloads is None else frozen_payloads
    frozen_byte_end = sum(len(payload) for payload in frozen_values)
    request = SessionShardsRequest(
        rollout="sessions/2026/07/06/rollout-test.jsonl",
        mode="records",
        source_token=token,
        byte_start=first,
        byte_end=last,
        shard_bytes=limits.max_bytes,
        max_shards=1,
        record_processing_budget_bytes=limits.record_processing_budget,
        resume_cursor=contracts.session_shards_resume_cursor(
            token,
            cursor_kind="records",
            frozen_byte_end=frozen_byte_end,
            byte_offset=first,
            next_record_index=record_start,
            prefix_commitment=(
                "sha256:" + hashlib.sha256(b"".join(frozen_values)).hexdigest()
            ),
        ),
    )
    meta: dict[str, object] = {
        "kind": "stream_meta",
        "schema": SESSION_SHARDS_SCHEMA,
        "mode": "records",
        "source_token": token,
        "request_rollout": request.rollout,
        "request_source_token": token,
        "request_resume_cursor": request.resume_cursor,
        "request_binding": request.request_binding,
        "source_bytes": frozen_byte_end,
        "byte_start": first,
        "byte_end": last,
        "record_start": record_start,
        "shard_bytes": limits.max_bytes,
        "max_shards": request.max_shards,
        "record_processing_budget_bytes": limits.record_processing_budget,
        "fixed_memory_envelope_bytes": (SESSION_SHARDS_FIXED_MEMORY_ENVELOPE_BYTES),
        "hard_record_processing_ceiling_bytes": sharding.HARD_RECORD_PROCESSING_CEILING,
        "record_fragment_bytes": SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
        "json_nesting_depth_limit": SESSION_SHARDS_MAX_JSON_NESTING_DEPTH,
        "max_remote_frame_chars": SESSION_SHARDS_MAX_FRAME_CHARS,
        "max_record_data_frames": MAX_SESSION_SHARDS_RECORD_DATA_FRAMES,
        "protocol_features": list(SESSION_SHARDS_PROTOCOL_FEATURES),
    }
    frames: list[dict[str, object]] = [meta]
    accounting = hashlib.sha256()
    emitted_records = 0
    emitted_gaps = 0
    emitted_fragments = 0
    emitted_record_bytes = 0
    emitted_gap_bytes = 0
    emitted_fragment_bytes = 0
    for index, (record, payload) in enumerate(zip(records, payloads)):
        global_index = record_start + index
        common = {
            "schema": SESSION_SHARDS_SCHEMA,
            "mode": "records",
            "source_token": token,
            "request_binding": request.request_binding,
            "record_start": global_index,
            "record_end": global_index + 1,
            "delimiter_bytes": 1 if payload.endswith(b"\n") else 0,
        }
        if record.accounting_class is catalog.AccountingClass.EXPLICIT_GAP:
            frame = {
                "kind": "gap",
                **common,
                "byte_start": record.coordinate.byte_start,
                "byte_end": record.coordinate.byte_end,
                "byte_count": record.byte_count,
                "reason": record.gap.reason,
            }
            if record.gap.reason == "record_processing_budget_exceeded":
                frame.update(
                    {
                        "record_processing_budget_bytes": (
                            limits.record_processing_budget
                        ),
                        "hard_record_processing_ceiling_bytes": (
                            sharding.HARD_RECORD_PROCESSING_CEILING
                        ),
                        "processing_ceiling_kind": "json_nesting_depth",
                        "processing_ceiling_limit": (
                            SESSION_SHARDS_MAX_JSON_NESTING_DEPTH
                        ),
                        "processing_ceiling_observed": (
                            SESSION_SHARDS_MAX_JSON_NESTING_DEPTH + 1
                        ),
                    }
                )
            frames.append(frame)
            accounting.update(_transport_accounting_bytes(frame))
            emitted_gaps += 1
            emitted_gap_bytes += record.byte_count
            continue
        commitment = catalog.content_commitment(payload)
        if len(payload) <= limits.max_bytes:
            frame = {
                "kind": "record",
                **common,
                "byte_start": record.coordinate.byte_start,
                "byte_end": record.coordinate.byte_end,
                "byte_count": len(payload),
                "record_encoding": "base64",
                "record_b64": base64.b64encode(payload).decode("ascii"),
                "record_commitment": commitment,
            }
            frames.append(frame)
            accounting.update(_transport_accounting_bytes(frame))
        else:
            count = (
                len(payload) + SESSION_SHARDS_RECORD_FRAGMENT_BYTES - 1
            ) // SESSION_SHARDS_RECORD_FRAGMENT_BYTES
            for fragment_index in range(count):
                start = fragment_index * SESSION_SHARDS_RECORD_FRAGMENT_BYTES
                end = min(start + SESSION_SHARDS_RECORD_FRAGMENT_BYTES, len(payload))
                fragment = payload[start:end]
                frame = {
                    "kind": "record_fragment",
                    **common,
                    "byte_start": record.coordinate.byte_start + start,
                    "byte_end": record.coordinate.byte_start + end,
                    "byte_count": len(fragment),
                    "record_byte_start": record.coordinate.byte_start,
                    "record_byte_end": record.coordinate.byte_end,
                    "record_byte_count": len(payload),
                    "fragment_index": fragment_index,
                    "fragment_count": count,
                    "record_encoding": "base64",
                    "fragment_b64": base64.b64encode(fragment).decode("ascii"),
                    "fragment_commitment": catalog.content_commitment(fragment),
                    "record_commitment": commitment,
                }
                frames.append(frame)
                accounting.update(_transport_accounting_bytes(frame))
                emitted_fragments += 1
                emitted_fragment_bytes += len(fragment)
        emitted_records += 1
        emitted_record_bytes += len(payload)
    proof = {
        "schema": "session-shards-conservation-v1",
        "source_token": token,
        "request_binding": request.request_binding,
        "byte_start": first,
        "byte_end": last,
        "byte_count": last - first,
        "accounted_byte_count": emitted_record_bytes + emitted_gap_bytes,
        "record_start": record_start,
        "record_end": record_start + len(records),
        "record_count": len(records),
        "accounted_record_count": emitted_records + emitted_gaps,
        "accounting_commitment": "sha256:" + accounting.hexdigest(),
    }
    frames.append(
        {
            "kind": "stream_end",
            "schema": SESSION_SHARDS_SCHEMA,
            "mode": "records",
            "source_token": token,
            "request_binding": request.request_binding,
            "complete": True,
            "reason": "range_complete",
            "emitted_records": emitted_records,
            "emitted_gaps": emitted_gaps,
            "emitted_fragments": emitted_fragments,
            "emitted_record_bytes": emitted_record_bytes,
            "emitted_gap_bytes": emitted_gap_bytes,
            "emitted_fragment_bytes": emitted_fragment_bytes,
            "byte_start": first,
            "byte_end": last,
            "record_start": record_start,
            "record_end": record_start + len(records),
            "conservation_proof": proof,
        }
    )
    return request, frames


def synthesis_result() -> dict[str, object]:
    return {
        "schema": result_validation.SYNTHESIS_RESULT_SCHEMA,
        "question_answers": [
            {
                "question_id": question_id,
                "disposition": "not_observed",
                "event_kinds": [],
                "finding_kinds": [],
                "strength_kinds": [],
                "evidence_refs": [],
                "confidence": "high",
            }
            for question_id in result_validation.QUESTION_IDS
        ],
        "events": [],
        "findings": [],
        "strengths": [],
        "prompt_rewrites": [],
        "guidance_candidates": [],
        "skill_candidates": [],
        "signal_commitments": result_validation.build_synthesis_signal_commitments(()),
        "follow_up_actions": [],
        "confidence": {
            "coverage": "high",
            "extraction": "high",
            "review": "high",
            "comparability": "high",
        },
        "evidence_refs": [],
        "era_comparison": {"status": "compatible", "change": "unchanged"},
        "topic_result_hashes": [],
    }


class CheckpointStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        os.chmod(self.root, 0o700)
        self.identity = IdentityKey.create(self.root / "identity-v2.key")
        self.store = AtomicCheckpointStore(
            self.root / "run",
            identity=self.identity,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_owner_only_atomic_compare_and_swap_and_key_binding(self) -> None:
        initial = self.store.initialize({"stage": "source_catalog", "value": 1})
        updated = self.store.compare_and_swap(
            initial.revision,
            {"stage": "source_catalog", "value": 2},
        )
        self.assertEqual(2, updated.revision)
        self.assertEqual(0o700, stat.S_IMODE(self.store.run_dir.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.store.path.stat().st_mode))
        with self.assertRaises(CheckpointConflictError):
            self.store.compare_and_swap(initial.revision, {"value": 3})
        wrong = IdentityKey.generate()
        with self.assertRaisesRegex(Exception, "key_id"):
            AtomicCheckpointStore(
                self.store.run_dir,
                identity=wrong,
            ).read()

    def test_failed_replace_and_insecure_mode_fail_closed(self) -> None:
        committed = self.store.initialize({"generation": 1})
        with mock.patch.object(self.store, "_replace", side_effect=OSError("crash")):
            with self.assertRaisesRegex(OSError, "crash"):
                self.store.save({"generation": 2}, expected_revision=committed.revision)
        self.assertEqual(committed, self.store.read())
        os.chmod(self.store.path, 0o644)
        with self.assertRaises(CheckpointPermissionError):
            self.store.read()


class OrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        bind_remote_host_context_helper_fixture(self)
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        os.chmod(self.root, 0o700)
        self.identity_path = self.root / "identity-v2.key"
        self.identity = IdentityKey.create(self.identity_path)
        self.clock = FixedClock()
        self.history_state = self.durable_history()
        self.authority_patches = [
            mock.patch(
                "retrospective_v2.orchestrator.authority.load_durable_history",
                side_effect=lambda *_args, **_kwargs: self.history_state,
            ),
            mock.patch(
                "retrospective_v2.orchestrator.authority.assert_provider_cache_matches",
                return_value={},
            ),
            mock.patch(
                "retrospective_v2.orchestrator.authority.load_production_marker",
                return_value={"authentication_tag": "test"},
            ),
            mock.patch(
                "retrospective_v2.orchestrator.authority.history_repository_binding",
                return_value="sha256:" + "b" * 64,
            ),
        ]
        for patcher in self.authority_patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.authority_patches):
            patcher.stop()
        self.temporary_directory.cleanup()

    def durable_history(
        self,
        episode_heads: list[dict[str, object]] | None = None,
        cursor_rows: list[dict[str, object]] | None = None,
    ) -> authority.DurableHistoryState:
        heads = tuple(
            sorted(
                copy.deepcopy(episode_heads or []),
                key=lambda item: item["episode_ref"],
            )
        )
        rows = tuple(
            sorted(
                copy.deepcopy(cursor_rows or []),
                key=lambda item: item["host_ref"],
            )
        )
        return authority.DurableHistoryState(
            head_commit="a" * 40,
            publication_commit=None,
            identity_key_id=self.identity.key_id,
            provider_revision=0,
            cursor_root_ref=authority.derive_cursor_root(rows),
            episode_head_root_ref=authority.derive_episode_head_root(
                heads,
                identity=self.identity,
            ),
            cursor_rows=rows,
            episode_heads=heads,
            episode_membership=authority.derive_episode_membership(
                heads,
                identity=self.identity,
            ),
        )

    def durable_backlog_history(
        self,
        partial_state: dict[str, object],
        *,
        host: str,
        episode_heads: list[dict[str, object]] | None = None,
    ) -> authority.DurableHistoryState:
        host_ref = str(self.identity.derive_ref(RefType.HOST, {"parts": [host]}))
        backlog_ref = str(
            self.identity.derive_ref(
                RefType.RUN_INPUT,
                {
                    "parts": [
                        partial_state["run_ref"],
                        host_ref,
                        "publication_backlog",
                    ]
                },
            )
        )
        return self.durable_history(
            episode_heads,
            cursor_rows=[
                {
                    "backlog_ref": backlog_ref,
                    "cursor_ref": None,
                    "host_ref": host_ref,
                    "logical_boundary": None,
                }
            ],
        )

    def start_authority(self) -> dict[str, object]:
        return {
            "history_repo": self.root / "history",
            "history_target_ref": "refs/heads/main",
            "production_marker": self.root / "production-marker.json",
            "provenance": execution_provenance(),
            "provider_state": self.root / "provider",
        }

    def published_history(
        self,
        coordinator: RetrospectiveOrchestrator,
    ) -> authority.DurableHistoryState:
        durable = coordinator.store.read().state["publication"]["durable_state"]
        return authority.DurableHistoryState(
            head_commit="b" * 40,
            publication_commit="b" * 40,
            identity_key_id=self.identity.key_id,
            provider_revision=durable["provider_revision_after"],
            cursor_root_ref=durable["proposed_cursor_root_ref"],
            episode_head_root_ref=durable["proposed_episode_head_root_ref"],
            cursor_rows=tuple(durable["proposed_cursor_rows"]),
            episode_heads=tuple(durable["proposed_episode_heads"]),
            episode_membership=tuple(durable["proposed_episode_membership"]),
        )

    def claim_publication_for_test(
        self,
        coordinator: RetrospectiveOrchestrator,
    ) -> dict[str, object]:
        run_ref = coordinator.load_state()["run_ref"]
        attempt_ref = (
            "attempt_ref_v2:"
            + hashlib.sha256(f"test-attempt:{run_ref}".encode("ascii")).hexdigest()
        )
        plan_digest = hashlib.sha256(f"test-plan:{run_ref}".encode("ascii")).hexdigest()
        claimed = coordinator.claim_publication(attempt_ref, plan_digest)
        return {
            "attempt_ref": attempt_ref,
            "claim_revision": claimed["checkpoint_revision"],
            "plan_digest": plan_digest,
        }

    def coordinator(
        self,
        name: str,
        *,
        limits: sharding.ShardLimits | None = None,
    ) -> RetrospectiveOrchestrator:
        coordinator = RetrospectiveOrchestrator(
            self.root / name,
            clock=self.clock,
            identity_path=self.identity_path,
            shard_limits=limits,
        )

        def accept_claimed_result(job_ref, attempt_ref, result):
            state = coordinator.store.read().state
            task = next(
                task
                for task in state["jobs"].values()
                if task.get("active_job_ref") == job_ref
            )
            attempt = next(
                attempt
                for attempt in task["attempts"]
                if attempt["attempt_ref"] == attempt_ref
            )
            if attempt["dispatch_state"] == "unclaimed":
                claimed = coordinator.claim_agent_job(
                    job_ref,
                    attempt_ref,
                    typed_ref(RefType.LEASE, f"test-dispatcher:{attempt_ref}"),
                )
                claim_ref = claimed["claim_ref"]
                result_ref = claimed["result_ref"]
            else:
                claim_ref = attempt["claim_ref"]
                result_ref = attempt["result_ref"]
            return RetrospectiveOrchestrator.accept_agent_result(
                coordinator,
                job_ref,
                attempt_ref,
                result,
                claim_ref=claim_ref,
                result_ref=result_ref,
            )

        coordinator.accept_agent_result = accept_claimed_result  # type: ignore[method-assign]
        return coordinator

    def synthesis_root_state(
        self,
        *,
        expected_roots: list[str],
        accepted_roots: list[str],
    ) -> dict[str, object]:
        jobs = {}
        for index, root_ref in enumerate(accepted_roots):
            task_ref = typed_ref(
                RefType.RUN_INPUT, f"synthesis-source-{index}-{root_ref}"
            )
            jobs[task_ref] = {
                "job_kind": JobKind.TOPIC_REDUCER.value,
                "metadata": {
                    "hierarchy_final": True,
                    "hierarchy_root_ref": root_ref,
                },
                "result": {
                    "schema": result_validation.TOPIC_RESULT_SCHEMA,
                    "topic_candidate_ref": root_ref,
                },
                "stage": RunStage.TOPIC_REDUCTION.value,
                "status": "accepted",
                "task_ref": task_ref,
            }
        return {
            "episodes": [],
            "jobs": jobs,
            "run_ref": typed_ref(RefType.RUN, "synthesis-root-state"),
            "topic_inputs": {root_ref: {} for root_ref in expected_roots},
        }

    def start_daily(
        self,
        name: str,
        *,
        hosts: tuple[str, ...] = DEFAULT_HOSTS,
        allow_partial: bool = False,
        backfill_of: str | None = None,
        prior_episode_heads: list[dict[str, object]] | None = None,
        controlled_gap_receipt: dict[str, object] | None = None,
        shadow_successor: dict[str, object] | None = None,
        shadow: bool = False,
        durable_history: authority.DurableHistoryState | None = None,
        provenance: dict[str, object] | None = None,
    ) -> RetrospectiveOrchestrator:
        coordinator = self.coordinator(name)
        self.history_state = durable_history or self.durable_history(
            prior_episode_heads
        )
        start_authority = self.start_authority()
        if provenance is not None:
            start_authority["provenance"] = provenance
        coordinator.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=DAILY_END,
            hosts=hosts,
            allow_partial=allow_partial,
            backfill_of=backfill_of,
            controlled_gap_receipt=controlled_gap_receipt,
            shadow_successor=shadow_successor,
            shadow=shadow,
            created_at="2026-07-14T12:00:00Z",
            **start_authority,
        )
        return coordinator

    def complete_shadow_partial(
        self,
        coordinator: RetrospectiveOrchestrator,
    ) -> dict[str, object]:
        self.drain_sources(coordinator)
        for _ in range(20):
            status = coordinator.status()
            if status["stage"] == RunStage.EXPORT.value:
                break
            runnable = status["runnable_jobs"]
            if runnable:
                for job in runnable:
                    self.assertEqual(
                        JobKind.GLOBAL_SYNTHESIS.value,
                        job["job_kind"],
                    )
                    result = synthesis_result()
                    result["signal_commitments"] = job["input_payload"][
                        "signal_commitments"
                    ]
                    result["topic_result_hashes"] = job["input_payload"][
                        "topic_result_hashes"
                    ]
                    coordinator.accept_agent_result(
                        job["job_ref"],
                        job["active_attempt_ref"],
                        result,
                    )
                continue
            coordinator.advance()
        else:
            self.fail(
                "shadow partial did not reach export: "
                f"stage={status['stage']} blocked={status['blocked_reason']} "
                f"next={status['next_actions']}"
            )
        run_state, review_data = coordinator.retained_export_inputs()
        bundle = (
            self.root
            / ".codex-local"
            / "shadow-successors"
            / coordinator.run_dir.name
            / "retained-v2"
        )
        export_retained_bundle(
            bundle,
            run_state,
            review_data,
        )
        coordinator.mark_shadow_exported(bundle)
        completed = coordinator.complete_shadow_export()
        self.assertFalse(completed["cleanup_pending"])
        self.assertFalse(
            (
                coordinator.run_dir / retained_inputs.RETAINED_EXPORT_INPUT_DIRECTORY
            ).exists()
        )
        self.assertIsNone(coordinator.load_state()["retained_export"])

        def attach_legacy_terminal_payload(current):
            current["retained_export"] = {
                "review_data": {"legacy": "shadow-terminal"},
                "run_state": {"legacy": "shadow-terminal"},
            }
            return current, None

        coordinator.store.transaction(attach_legacy_terminal_payload)
        replay = coordinator.complete_shadow_export()
        self.assertTrue(replay["idempotent"])
        self.assertIsNone(coordinator.load_state()["retained_export"])
        return coordinator.shadow_daily_successor()

    def drain_sources(
        self,
        coordinator: RetrospectiveOrchestrator,
        handler=None,
    ) -> None:
        for _ in range(80):
            status = coordinator.status()
            if status["stage"] != RunStage.SOURCE_CATALOG.value:
                return
            leases = status["active_source_leases"]
            if not leases:
                coordinator.advance()
                continue
            for lease in leases:
                handled = None if handler is None else handler(lease)
                if handled is None:
                    manifest = no_activity_manifest(lease)
                    coordinator.accept_source(
                        lease["lease_ref"],
                        manifest.to_dict(),
                        transport_receipt=authenticated_receipt(
                            coordinator, lease, manifest
                        ),
                    )
                else:
                    manifest, kwargs = handled
                    kwargs = dict(kwargs)
                    raw_records = kwargs.pop(
                        "_receipt_records", kwargs.get("raw_records")
                    )
                    coordinator.accept_source(
                        lease["lease_ref"],
                        manifest.to_dict(),
                        transport_receipt=authenticated_receipt(
                            coordinator,
                            lease,
                            manifest,
                            raw_records=raw_records,
                        ),
                        **kwargs,
                    )
        self.fail("source catalog did not reach a stable next stage")

    def activity_run(self, name: str) -> RetrospectiveOrchestrator:
        coordinator = self.start_daily(name)
        payload = b'{"timestamp":"2026-07-06T01:00:00Z","text":"work"}\n'

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        self.assertEqual(RunStage.EXTRACTION.value, coordinator.status()["stage"])
        return coordinator

    def extractor_result(self, job: dict[str, object]) -> dict[str, object]:
        refs = job["allowed_output_refs"]

        def one(prefix: str) -> str:
            return next(value for value in refs if value.startswith(prefix))

        evidence = one("evidence_ref_v2:")
        return {
            "schema": result_validation.EXTRACTOR_RESULT_SCHEMA,
            "source_unit_ref": one("source_unit_ref_v2:"),
            "turns": [
                {
                    "turn_ref": one("turn_ref_v2:"),
                    "generalized_working_text": "A bounded production task was verified.",
                    "events": [
                        {
                            "kind": "verification_completed",
                            "evidence_refs": [evidence],
                            "confidence": "high",
                        }
                    ],
                    "findings": [],
                    "strengths": [
                        {
                            "kind": "complete_verification",
                            "evidence_refs": [evidence],
                            "confidence": "high",
                        }
                    ],
                    "risk_flags": ["production"],
                    "outcome": "completed",
                    "confidence": "low",
                    "evidence_refs": [evidence],
                    "span_commitments": [one("span_commitment_ref_v2:")],
                    "goal_ref": one("goal_ref_v2:"),
                    "workstream_ref": one("workstream_ref_v2:"),
                    "goal_change": "continues",
                    "workstream_change": False,
                    "task_completed": True,
                    "user_redirect": False,
                    "meaningfulness_hint": "meaningful",
                    "conflicting_signals": False,
                }
            ],
        }

    def agent_envelope(
        self,
        coordinator: RetrospectiveOrchestrator,
        job: dict[str, object],
    ) -> dict[str, object]:
        claimed = coordinator.claim_agent_job(
            job["job_ref"],
            job["active_attempt_ref"],
            typed_ref(
                RefType.LEASE,
                f"test-dispatcher:{job['active_attempt_ref']}",
            ),
        )
        envelope_bytes = Path(claimed["envelope_path"]).read_bytes()
        self.assertEqual(claimed["envelope_size"], len(envelope_bytes))
        self.assertEqual(
            claimed["envelope_digest"], hashlib.sha256(envelope_bytes).hexdigest()
        )
        return json.loads(envelope_bytes)

    @staticmethod
    def extractor_result_for_task(task: dict[str, object]) -> dict[str, object]:
        turns = []
        for turn_ref, metadata in sorted(task["metadata"]["turn_metadata"].items()):
            evidence_refs = list(metadata["evidence_refs"])
            turns.append(
                {
                    "turn_ref": turn_ref,
                    "generalized_working_text": (
                        "A bounded logical record was summarized."
                    ),
                    "events": [
                        {
                            "kind": "verification_completed",
                            "evidence_refs": evidence_refs,
                            "confidence": "high",
                        }
                    ],
                    "findings": [],
                    "strengths": [
                        {
                            "kind": "complete_verification",
                            "evidence_refs": evidence_refs,
                            "confidence": "high",
                        }
                    ],
                    "risk_flags": ["production"],
                    "outcome": "completed",
                    "confidence": "high",
                    "evidence_refs": evidence_refs,
                    "span_commitments": list(metadata["span_refs"]),
                    "goal_ref": metadata["goal_ref"],
                    "workstream_ref": metadata["workstream_ref"],
                    "goal_change": "new_goal",
                    "workstream_change": False,
                    "task_completed": True,
                    "user_redirect": False,
                    "meaningfulness_hint": "meaningful",
                    "conflicting_signals": False,
                }
            )
        return {
            "schema": result_validation.EXTRACTOR_RESULT_SCHEMA,
            "turns": turns,
        }

    @staticmethod
    def review_result(
        job: dict[str, object],
        *,
        secondary: bool,
    ) -> dict[str, object]:
        episode = job["input_payload"]["episode_revision"]
        turn_ref = episode["turn_refs"][0]
        evidence = next(
            value
            for value in job["allowed_output_refs"]
            if value.startswith("evidence_ref_v2:")
        )
        high_impact = []
        risk_flags = ["production"]
        if secondary:
            risk_flags = ["safety"]
            high_impact = [
                {
                    "turn_ref": turn_ref,
                    "problem_statement": "A high-impact operation needed an explicit boundary.",
                    "cause": "The requested safety condition was underspecified.",
                    "rewritten_prompt": "Require a bounded preflight before the high-impact operation.",
                    "expected_effect": "The operation remains evidence-bound and reversible.",
                    "evidence_refs": [evidence],
                    "confidence": "high",
                    "severity": "high",
                }
            ]
        return {
            "schema": result_validation.EPISODE_REVIEW_RESULT_SCHEMA,
            "episode_ref": episode["episode_ref"],
            "episode_revision_ref": episode["episode_revision_ref"],
            "disposition": "reviewed",
            "events": [
                {
                    "kind": "verification_completed",
                    "evidence_refs": [evidence],
                    "confidence": "high",
                }
            ],
            "findings": [],
            "strengths": [
                {
                    "kind": "complete_verification",
                    "evidence_refs": [evidence],
                    "confidence": "high",
                }
            ],
            "risk_flags": risk_flags,
            "high_impact_turns": high_impact,
            "evidence_refs": [evidence],
            "confidence": "high",
            "reviewer_slot": "secondary" if secondary else "primary",
            "attempt_ref": job["active_attempt_ref"],
            "reviewer_ref": job["reviewer_ref"],
            "second_review_recommended": secondary,
            "conflicting_signals": secondary,
        }

    @staticmethod
    def review_gap_result(job: dict[str, object]) -> dict[str, object]:
        episode = job["input_payload"]["episode_revision"]
        reviewer_slot = (
            "secondary"
            if job["job_kind"] == JobKind.INDEPENDENT_RISK_REVIEWER.value
            else "primary"
        )
        return {
            "schema": result_validation.EPISODE_REVIEW_RESULT_SCHEMA,
            "episode_ref": episode["episode_ref"],
            "episode_revision_ref": episode["episode_revision_ref"],
            "disposition": "review_gap",
            "events": [],
            "findings": [],
            "strengths": [],
            "risk_flags": [],
            "high_impact_turns": [],
            "evidence_refs": [],
            "confidence": "low",
            "reviewer_slot": reviewer_slot,
            "attempt_ref": job["active_attempt_ref"],
            "reviewer_ref": job["reviewer_ref"],
            "second_review_recommended": False,
            "conflicting_signals": False,
            "gap_reason": "insufficient_support",
        }

    def test_doctor_identity_publisher_and_all_host_policy(self) -> None:
        readiness = doctor(
            identity_path=self.identity_path,
            require_existing_identity=True,
            provenance=execution_provenance(),
            shadow=True,
            history_repo=self.root / "history",
            history_target_ref="refs/heads/main",
            publisher_probe=lambda: {
                "fingerprint": PUBLISHER_FINGERPRINT,
                "ready": True,
            },
        )
        self.assertTrue(readiness["ok"])
        self.assertEqual(PUBLISHER_FINGERPRINT, readiness["publisher"]["fingerprint"])
        self.assertNotIn("gnupg", str(readiness).lower())
        self.assertEqual(
            ["remote_host_authentication", "remote_host_reachability"],
            readiness["runtime_coverage_gaps"],
        )
        self.assertTrue(readiness["checks"]["durable_history_contract"]["ok"])
        self.assertTrue(readiness["checks"]["remote_host_context_transport"]["ok"])

        production = doctor(
            identity_path=self.identity_path,
            require_existing_identity=True,
            provenance=execution_provenance(),
            history_repo=self.root / "history",
            history_target_ref="refs/heads/main",
            provider_state=self.root / "provider",
            production_marker=self.root / "production-marker.json",
            publisher_probe=lambda: {
                "fingerprint": PUBLISHER_FINGERPRINT,
                "ready": True,
            },
        )
        self.assertTrue(production["ok"], production)
        missing_provider = doctor(
            identity_path=self.identity_path,
            require_existing_identity=True,
            provenance=execution_provenance(),
            history_repo=self.root / "history",
            history_target_ref="refs/heads/main",
            production_marker=self.root / "production-marker.json",
            publisher_probe=lambda: {
                "fingerprint": PUBLISHER_FINGERPRINT,
                "ready": True,
            },
        )
        self.assertFalse(missing_provider["ok"])
        self.assertFalse(missing_provider["checks"]["provider_binding"]["ok"])

        incompatible = execution_provenance()
        incompatible["transport"]["remote_host_context_helper_commitment"] = (
            "sha256:" + "0" * 64
        )
        mismatched_helper = doctor(
            identity_path=self.identity_path,
            require_existing_identity=True,
            provenance=incompatible,
            shadow=True,
            history_repo=self.root / "history",
            history_target_ref="refs/heads/main",
            publisher_probe=lambda: {
                "fingerprint": PUBLISHER_FINGERPRINT,
                "ready": True,
            },
        )
        self.assertFalse(mismatched_helper["ok"])
        self.assertFalse(mismatched_helper["checks"]["execution_contract"]["ok"])

        gnupg = self.root / "publisher-gnupg-v2"
        gnupg.mkdir(mode=0o700)
        with mock.patch(
            "retrospective_v2.orchestrator.finalize.validate_publisher_keyring",
            return_value={
                "fingerprint": PUBLISHER_FINGERPRINT,
                "gnupg_home": str(gnupg),
                "uid": PUBLISHER_UID,
            },
        ):
            self.assertTrue(
                publisher_readiness(gnupg_home=gnupg, gpg_program="fake-gpg")["ready"]
            )
        with mock.patch(
            "retrospective_v2.orchestrator.finalize.validate_publisher_keyring",
            return_value={
                "fingerprint": "0" * 40,
                "gnupg_home": str(gnupg),
                "uid": PUBLISHER_UID,
            },
        ):
            self.assertFalse(
                publisher_readiness(gnupg_home=gnupg, gpg_program="fake-gpg")["ready"]
            )

        with self.assertRaisesRegex(InvalidInputError, "every canonical host"):
            self.coordinator("weekly-subset").start(
                mode=RunMode.WEEKLY,
                start=WINDOW_START,
                end=WINDOW_END,
                hosts=("local",),
                **self.start_authority(),
            )
        session_selector = "session-host-policy"
        session_target = str(
            self.identity.derive_ref(
                RefType.SESSION,
                {"session_id": session_selector},
            )
        )
        for name, hosts, message in (
            ("session-subset", ("local",), "every canonical host"),
            (
                "session-unknown",
                (*DEFAULT_HOSTS, "unknown-host"),
                "only canonical hosts",
            ),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(InvalidInputError, message):
                    self.coordinator(name).start(
                        mode=RunMode.SESSION,
                        start=WINDOW_START,
                        end=WINDOW_END,
                        hosts=hosts,
                        session_target=session_target,
                        session_target_selector=session_selector,
                        **self.start_authority(),
                    )
        session = self.coordinator("session-checkpoint-host-matrix")
        session.start(
            mode=RunMode.SESSION,
            start=WINDOW_START,
            end=WINDOW_END,
            hosts=DEFAULT_HOSTS,
            session_target=session_target,
            session_target_selector=session_selector,
            **self.start_authority(),
        )

        def swap_host_bindings(current):
            left, right = DEFAULT_HOSTS[:2]
            left_ref, right_ref = (
                current["host_refs"][left],
                current["host_refs"][right],
            )
            current["host_refs"][left], current["host_refs"][right] = (
                right_ref,
                left_ref,
            )
            for cell in current["source"]["cells"][left].values():
                cell["host_ref"] = right_ref
            for cell in current["source"]["cells"][right].values():
                cell["host_ref"] = left_ref

        for label, mutate in (
            (
                "host",
                lambda current: current["host_refs"].pop(DEFAULT_HOSTS[-1]),
            ),
            (
                "source-kind",
                lambda current: current["source"]["cells"][DEFAULT_HOSTS[0]].pop(
                    REQUIRED_SOURCE_KINDS[-1]
                ),
            ),
            ("host-ref-binding", swap_host_bindings),
        ):
            with self.subTest(checkpoint_matrix=label):
                checkpoint = self.coordinator(f"session-checkpoint-{label}")
                checkpoint.start(
                    mode=RunMode.SESSION,
                    start=WINDOW_START,
                    end=WINDOW_END,
                    hosts=DEFAULT_HOSTS,
                    session_target=session_target,
                    session_target_selector=session_selector,
                    **self.start_authority(),
                )

                def tamper(current):
                    mutate(current)
                    return current, None

                checkpoint.store.transaction(tamper)
                with self.assertRaisesRegex(
                    InvalidTransitionError,
                    "canonical source matrix",
                ):
                    checkpoint.status()
        with self.assertRaisesRegex(InvalidInputError, "complete canonical host set"):
            self.coordinator("daily-subset").start(
                mode=RunMode.DAILY,
                start=WINDOW_START,
                end=DAILY_END,
                hosts=("local",),
                allow_partial=True,
                **self.start_authority(),
            )

    def test_execution_configuration_changes_run_job_and_trend_identity(self) -> None:
        first_config = execution_provenance(model="gpt-5.6-sol")
        second_config = execution_provenance(model="gpt-5.6-sol-2026-07-15")
        first = self.start_daily("configuration-first", provenance=first_config)
        second = self.start_daily("configuration-second", provenance=second_config)
        first.advance()
        second.advance()
        first_state = first.load_state()
        second_state = second.load_state()
        first_job = next(iter(first_state["jobs"].values()))
        second_job = next(iter(second_state["jobs"].values()))
        self.assertNotEqual(first_state["run_ref"], second_state["run_ref"])
        self.assertNotEqual(
            first_state["provenance"]["configuration_root"],
            second_state["provenance"]["configuration_root"],
        )
        self.assertNotEqual(first_job["job_ref"], second_job["job_ref"])
        self.assertNotEqual(
            first._model_era(first_state),
            second._model_era(second_state),
        )
        self.assertEqual(
            first_job["execution_contract"],
            {
                key: value
                for key, value in first_state["provenance"].items()
                if key != "configuration_root"
            },
        )

        invalid_prompt = execution_provenance()
        invalid_prompt["prompt"]["digest"] = "0" * 64
        with self.assertRaisesRegex(InvalidInputError, "executable instructions"):
            self.start_daily("configuration-invalid", provenance=invalid_prompt)

    def test_run_ref_is_bound_to_the_specification_digest(self) -> None:
        first = self.coordinator("run-ref-first")
        first_authority = self.start_authority()
        first_result = first.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=DAILY_END,
            hosts=DEFAULT_HOSTS,
            created_at="2026-07-14T12:00:00Z",
            **first_authority,
        )
        run_ref = first_result["run_ref"]

        resumed = first.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=DAILY_END,
            hosts=DEFAULT_HOSTS,
            run_ref=run_ref,
            created_at="2026-07-14T12:00:00Z",
            **first_authority,
        )
        self.assertTrue(resumed["resumed"])

        second_authority = self.start_authority()
        second_authority["provenance"] = execution_provenance(
            model="gpt-5.6-sol-2026-07-15"
        )
        with self.assertRaisesRegex(
            InvalidInputError,
            "current specification digest",
        ):
            self.coordinator("run-ref-second").start(
                mode=RunMode.DAILY,
                start=WINDOW_START,
                end=DAILY_END,
                hosts=DEFAULT_HOSTS,
                run_ref=run_ref,
                created_at="2026-07-14T12:00:00Z",
                **second_authority,
            )

    def test_created_at_cannot_override_the_trusted_clock(self) -> None:
        with self.assertRaisesRegex(InvalidInputError, "trusted clock"):
            self.coordinator("future-created-at").start(
                mode=RunMode.DAILY,
                start=WINDOW_START,
                end=DAILY_END,
                hosts=DEFAULT_HOSTS,
                created_at="2099-01-01T00:00:00Z",
                **self.start_authority(),
            )

    def test_source_session_model_era_is_preserved_without_execution_fallback(
        self,
    ) -> None:
        coordinator = self.start_daily("source-model-era")
        payloads = [
            b'{"timestamp":"2026-07-06T01:00:00Z","type":"turn_context",'
            b'"payload":{"model":"source-model-v1"}}\n',
            b'{"timestamp":"2026-07-06T01:01:00Z","text":"work"}\n',
        ]

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, payloads)
            return manifest, {
                "raw_records": {
                    record.unit_ref: payload
                    for record, payload in zip(records, payloads)
                }
            }

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        state = coordinator.load_state()
        self.assertNotEqual("source_model_v1", coordinator._model_era(state))
        active_cell = state["source"]["cells"]["local"][SourceKind.ACTIVE_ROLLOUT.value]
        materialized_source = source_inputs.materialize_segments(
            coordinator.run_dir,
            active_cell["continuation_segments"],
        )
        self.assertEqual(
            {"source_model_v1"},
            set(materialized_source["model_era_by_unit"].values()),
        )
        self.assertEqual({}, state["source"]["model_era_by_unit"])
        self.assertEqual(
            {"source_model_v1"},
            {row["model_era"] for row in state["source"]["reassembly"].values()},
        )
        turn_refs = sorted(state["source"]["reassembly"])
        self.assertEqual(
            "source_model_v1",
            coordinator._retained_model_era_for_turns(state, turn_refs),
        )
        state["source"]["reassembly"][turn_refs[-1]]["model_era"] = "source_model_v2"
        self.assertEqual(
            coordinator.MIXED_MODEL_ERA,
            coordinator._retained_model_era_for_turns(state, turn_refs),
        )

    def test_source_acceptance_keeps_large_evidence_out_of_checkpoint(self) -> None:
        coordinator = self.start_daily("source-sidecar-checkpoint-bound")
        coordinator.advance()
        lease = next(
            item
            for item in coordinator.status()["active_source_leases"]
            if item["host"] == "local"
        )
        payload = (
            b'{"timestamp":"2026-07-06T01:00:00Z","text":"' + b"x" * 750_000 + b'"}\n'
        )
        manifest, records, _source_ref = activity_manifest(lease, [payload])
        receipt = authenticated_receipt(
            coordinator,
            lease,
            manifest,
            raw_records={records[0].unit_ref: payload},
        )

        coordinator.accept_source(
            lease["lease_ref"],
            manifest.to_dict(),
            transport_receipt=receipt,
            raw_records={records[0].unit_ref: payload},
        )

        state = coordinator.load_state()
        cell = state["source"]["cells"]["local"][lease["source_kind"]]
        self.assertLess(coordinator.store.path.stat().st_size, 1024 * 1024)
        self.assertNotIn("records", cell["manifest"])
        self.assertEqual({}, cell["payloads"])
        self.assertEqual(1, len(cell["continuation_segments"]))
        accepted = source_inputs.load(
            coordinator.run_dir,
            cell["continuation_segments"][0],
        )
        self.assertEqual(1, len(accepted["segment"]["manifest"]["records"]))
        raw_path = (
            coordinator.run_dir
            / accepted["payloads"][records[0].unit_ref]["relative_path"]
        )
        self.assertEqual(payload, raw_path.read_bytes())

    def test_source_acceptance_rolls_back_new_files_on_checkpoint_failure(
        self,
    ) -> None:
        coordinator = self.start_daily("source-sidecar-rollback")
        coordinator.advance()
        lease = next(
            item
            for item in coordinator.status()["active_source_leases"]
            if item["host"] == "local"
        )
        payload = b'{"timestamp":"2026-07-06T01:00:00Z","text":"work"}\n'
        manifest, records, _source_ref = activity_manifest(lease, [payload])
        receipt = authenticated_receipt(
            coordinator,
            lease,
            manifest,
            raw_records={records[0].unit_ref: payload},
        )
        before = coordinator.store.read()

        with mock.patch.object(
            coordinator.store,
            "_replace",
            side_effect=OSError("simulated checkpoint replace failure"),
        ):
            with self.assertRaisesRegex(OSError, "replace failure"):
                coordinator.accept_source(
                    lease["lease_ref"],
                    manifest.to_dict(),
                    transport_receipt=receipt,
                    raw_records={records[0].unit_ref: payload},
                )

        self.assertEqual(before, coordinator.store.read())
        raw_root = coordinator.run_dir / "raw-inputs"
        self.assertEqual([], list(raw_root.glob("*.bin")))
        self.assertEqual(
            [],
            list(raw_root.glob("source-acceptances/source-acceptance-v2-*.json")),
        )

    def test_cursor_boundaries_cover_overlap_disjoint_and_immutable_modes(self) -> None:
        host_ref = str(self.identity.derive_ref(RefType.HOST, {"parts": ["local"]}))
        source_cursor = typed_ref(RefType.SOURCE, "durable-source-cursor")

        def history(boundary: str) -> authority.DurableHistoryState:
            return self.durable_history(
                cursor_rows=[
                    {
                        "backlog_ref": None,
                        "cursor_ref": source_cursor,
                        "host_ref": host_ref,
                        "logical_boundary": boundary,
                    }
                ]
            )

        for label, boundary, expected in (
            ("disjoint", "2026-07-05T12:00:00Z", DAILY_END),
            ("overlap", "2026-07-06T12:00:00Z", DAILY_END),
            ("past", "2026-07-08T00:00:00Z", "2026-07-08T00:00:00Z"),
        ):
            with self.subTest(label=label):
                coordinator = self.start_daily(
                    f"cursor-{label}",
                    durable_history=history(boundary),
                )
                coordinator.advance()
                lease = next(
                    item
                    for item in coordinator.status()["active_source_leases"]
                    if item["host"] == "local"
                )
                self.assertEqual(boundary, lease["transport_lease"]["cursor_time"])
                self.drain_sources(coordinator)
                coordinator.advance()
                proposed = coordinator.load_state()["cursors"]["local"]["proposed"]
                self.assertEqual(expected, proposed["logical_boundary"])
                if label == "past":
                    self.assertEqual(source_cursor, proposed["source_snapshot_ref"])

        baseline_history = history("2026-04-01T00:00:00Z")
        baseline = self.coordinator("cursor-baseline")
        self.history_state = baseline_history
        baseline.start(
            mode=RunMode.BASELINE,
            start="2026-04-08T00:00:00Z",
            end=DAILY_END,
            hosts=DEFAULT_HOSTS,
            **self.start_authority(),
        )
        self.drain_sources(baseline)
        baseline.advance()
        self.assertEqual(
            list(baseline_history.cursor_rows),
            baseline.publication_durable_state()["proposed_cursor_rows"],
        )

        session_history = history("2026-07-06T12:00:00Z")
        session = self.coordinator("cursor-session")
        self.history_state = session_history
        selector = "cursor-session-selector"
        session.start(
            mode=RunMode.SESSION,
            start=WINDOW_START,
            end=DAILY_END,
            hosts=DEFAULT_HOSTS,
            session_target=str(
                self.identity.derive_ref(
                    RefType.SESSION,
                    {"session_id": selector},
                )
            ),
            session_target_selector=selector,
            **self.start_authority(),
        )
        self.drain_sources(session)
        session.advance()
        self.assertEqual(
            list(session_history.cursor_rows),
            session.publication_durable_state()["proposed_cursor_rows"],
        )
        with self.assertRaisesRegex(InvalidInputError, "every canonical host"):
            self.coordinator("baseline-subset").start(
                mode=RunMode.BASELINE,
                start=WINDOW_START,
                end=WINDOW_END,
                hosts=("local",),
                **self.start_authority(),
            )

    def test_verified_no_activity_and_interrupted_resume(self) -> None:
        coordinator = self.coordinator("weekly")
        started = coordinator.start(
            mode=RunMode.WEEKLY,
            start=WINDOW_START,
            end=WINDOW_END,
            hosts=DEFAULT_HOSTS,
            created_at="2026-07-14T12:00:00Z",
            **self.start_authority(),
        )
        coordinator.advance()
        lease = next(
            item
            for item in coordinator.status()["active_source_leases"]
            if item["host"] == "local"
        )
        with self.assertRaises(InvalidInputError):
            coordinator.accept_source(
                lease["lease_ref"],
                {
                    "host": lease["host"],
                    "outcome": "no_activity",
                    "source_kind": lease["source_kind"],
                },
                transport_receipt={},
            )
        manifest = no_activity_manifest(lease)
        coordinator.accept_source(
            lease["lease_ref"],
            manifest.to_dict(),
            transport_receipt=authenticated_receipt(coordinator, lease, manifest),
        )
        resumed = RetrospectiveOrchestrator(
            coordinator.run_dir,
            clock=self.clock,
            identity_path=self.identity_path,
        )
        self.assertGreater(
            resumed.status()["checkpoint_revision"], started["checkpoint_revision"]
        )
        self.drain_sources(resumed)
        resumed.advance()
        status = resumed.status()
        self.assertEqual(RunStage.EXPORT.value, status["stage"])
        self.assertEqual(0, status["metrics"]["discovered_source_units"])
        self.assertEqual([], status["runnable_jobs"])

    def test_fragment_transport_reassembles_and_rejects_corruption(self) -> None:
        limits = sharding.ShardLimits(
            max_bytes=128 * 1024,
            record_processing_budget=4 * 1024 * 1024,
        )
        coordinator = self.start_daily("fragment")
        coordinator.advance()
        lease = coordinator.status()["active_source_leases"][0]
        payload = b'{"text":"' + b"x" * 300_000 + b'"}\n'
        manifest, records, source_ref = activity_manifest(lease, [payload])
        request, frames = record_stream_frames(
            records,
            [payload],
            limits,
            token_seed="fragment",
        )
        consumption = consume_session_shard_frames(
            manifest,
            source_ref,
            frames,
            request=request,
            limits=limits,
        )
        self.assertEqual(payload, consumption.raw_records[0].payload)
        self.assertGreater(
            sum(frame["kind"] == "record_fragment" for frame in frames), 1
        )

        broken = copy.deepcopy(frames)
        fragment = next(frame for frame in broken if frame["kind"] == "record_fragment")
        fragment["fragment_commitment"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(InvalidInputError, "fragment commitment"):
            consume_session_shard_frames(
                manifest,
                source_ref,
                broken,
                request=request,
                limits=limits,
            )

        broken = copy.deepcopy(frames)
        broken[-1]["conservation_proof"]["accounted_byte_count"] -= 1
        with self.assertRaisesRegex(InvalidInputError, "conservation proof"):
            consume_session_shard_frames(
                manifest,
                source_ref,
                broken,
                request=request,
                limits=limits,
            )

    def test_accept_source_consumes_a_frame_limited_segment_chain(self) -> None:
        limits = sharding.ShardLimits(
            max_bytes=orchestrator_module.EXTRACTOR_SHARD_MAX_BYTES
        )
        coordinator = self.start_daily("transport-segments")
        coordinator.advance()
        lease = next(
            item
            for item in coordinator.status()["active_source_leases"]
            if item["host"] == "local"
        )
        payloads = [b"{}\n"] * (MAX_SESSION_SHARDS_RECORD_DATA_FRAMES + 1)
        manifest, records, source_ref = activity_manifest(lease, payloads)
        split = MAX_SESSION_SHARDS_RECORD_DATA_FRAMES
        first_request, first_frames = record_stream_frames(
            records[:split],
            payloads[:split],
            limits,
            token_seed="transport-segments",
            frozen_payloads=payloads,
        )
        second_request, second_frames = record_stream_frames(
            records[split:],
            payloads[split:],
            limits,
            token_seed="transport-segments",
            frozen_payloads=payloads,
            record_start=split,
        )
        raw_records = {
            record.unit_ref: payload
            for record, payload in zip(records, payloads, strict=True)
        }

        result = coordinator.accept_source(
            lease["lease_ref"],
            manifest.to_dict(),
            transport_receipt=authenticated_receipt(
                coordinator,
                lease,
                manifest,
                raw_records,
            ),
            transport_segments={
                source_ref: (
                    (first_frames, first_request),
                    (second_frames, second_request),
                )
            },
        )

        self.assertTrue(result["accepted"])
        self.assertEqual("complete", result["outcome"])
        cell = coordinator.load_state()["source"]["cells"][lease["host"]][
            lease["source_kind"]
        ]
        self.assertEqual(
            len(payloads),
            cell["metrics"]["record_count"],
        )

    def test_transport_replays_physical_offsets_not_record_identity_order(
        self,
    ) -> None:
        limits = sharding.ShardLimits(max_bytes=128 * 1024)
        coordinator = self.start_daily("transport-physical-order")
        coordinator.advance()
        lease = next(
            item
            for item in coordinator.status()["active_source_leases"]
            if item["host"] == "local"
        )
        payloads = [b'{"ordinal":0}\n', b'{"ordinal":1}\n']
        original_manifest, records, source_ref = activity_manifest(lease, payloads)
        reversed_identity_records = [
            replace(
                record,
                coordinate=replace(
                    record.coordinate,
                    record_ref="record-z" if index == 0 else "record-a",
                ),
            )
            for index, record in enumerate(records)
        ]
        manifest = catalog.SourceTransportManifest.create(
            host_ref=original_manifest.host_ref,
            transport_kind=original_manifest.transport_kind,
            source_kind=original_manifest.source_kind,
            window_start=original_manifest.window_start,
            window_end=original_manifest.window_end,
            status=original_manifest.status,
            records=reversed_identity_records,
            snapshot_commitment=catalog.snapshot_commitment_for_records(
                reversed_identity_records
            ),
        )
        request, frames = record_stream_frames(
            reversed_identity_records,
            payloads,
            limits,
            token_seed="transport-physical-order",
        )
        consumption = consume_session_shard_frames(
            manifest,
            source_ref,
            frames,
            request=request,
            limits=limits,
        )
        self.assertEqual(payloads, [item.payload for item in consumption.raw_records])

    def test_transport_request_binding_and_processing_ceiling_are_closed(self) -> None:
        limits = sharding.ShardLimits(
            max_bytes=128 * 1024,
            record_processing_budget=4 * 1024 * 1024,
        )
        coordinator = self.start_daily("transport-binding")
        coordinator.advance()
        lease = coordinator.status()["active_source_leases"][0]
        omitted = b"{" + b"[" * 600 + b"}\n"
        manifest, records, source_ref = activity_manifest(
            lease,
            [omitted],
            status=catalog.SourceCellStatus.GAP,
            gap_reasons={0: "record_processing_budget_exceeded"},
        )
        request, frames = record_stream_frames(
            records,
            [omitted],
            limits,
            token_seed="transport-binding",
        )
        consumption = consume_session_shard_frames(
            manifest,
            source_ref,
            frames,
            request=request,
            limits=limits,
        )
        self.assertEqual((records[0].unit_ref,), consumption.gap_unit_refs)

        changed_request = request.to_dict()
        changed_request["max_shards"] = 2
        with self.assertRaisesRegex(InvalidInputError, "not bound to the run"):
            consume_session_shard_frames(
                manifest,
                source_ref,
                frames,
                request=changed_request,
                limits=limits,
            )

        broken = copy.deepcopy(frames)
        gap = next(frame for frame in broken if frame["kind"] == "gap")
        gap["processing_ceiling_observed"] = 514
        with self.assertRaisesRegex(InvalidInputError, "processing-budget gap"):
            consume_session_shard_frames(
                manifest,
                source_ref,
                broken,
                request=request,
                limits=limits,
            )

        wrong_frame_limit = copy.deepcopy(frames)
        wrong_frame_limit[0]["max_record_data_frames"] = (
            MAX_SESSION_SHARDS_RECORD_DATA_FRAMES + 1
        )
        with self.assertRaisesRegex(InvalidInputError, "not bound to the run"):
            consume_session_shard_frames(
                manifest,
                source_ref,
                wrong_frame_limit,
                request=request,
                limits=limits,
            )

        forged_request = request.to_dict()
        forged_request["resume_cursor"] = contracts.session_shards_resume_cursor(
            source_token("other-source"),
            cursor_kind="records",
            frozen_byte_end=request.byte_end,
            byte_offset=request.byte_start,
            next_record_index=0,
            prefix_commitment=str(
                contracts.session_shards_resume_cursor_value(request.resume_cursor)[
                    "prefix_commitment"
                ]
            ),
        )
        with self.assertRaisesRegex(InvalidInputError, "closed contract"):
            consume_session_shard_frames(
                manifest,
                source_ref,
                frames,
                request=forged_request,
                limits=limits,
            )

    def test_remote_transport_forced_argv_binds_exact_request(self) -> None:
        limits = sharding.ShardLimits(max_bytes=128 * 1024)
        coordinator = self.start_daily("remote-argv")
        coordinator.advance()
        lease = coordinator.status()["active_source_leases"][0]
        payload = b'{"ok":true}\n'
        local_manifest, records, source_ref = activity_manifest(lease, [payload])
        request, frames = record_stream_frames(
            records,
            [payload],
            limits,
            token_seed="remote-argv",
        )
        remote_manifest = catalog.SourceTransportManifest.create(
            host_ref=local_manifest.host_ref,
            transport_kind=catalog.TransportKind.REMOTE,
            source_kind=local_manifest.source_kind,
            window_start=local_manifest.window_start,
            window_end=local_manifest.window_end,
            status=local_manifest.status,
            records=local_manifest.records,
            snapshot_commitment=local_manifest.snapshot_commitment,
            remote=catalog.RemoteTransportBinding(
                process_nonce="remote-argv",
                forced_command_argv=session_shards_argv(request),
            ),
        )
        consumption = consume_session_shard_frames(
            remote_manifest,
            source_ref,
            frames,
            request=request,
            limits=limits,
        )
        self.assertEqual(payload, consumption.raw_records[0].payload)

        incomplete_argv = tuple(
            item
            for item in session_shards_argv(request)
            if item not in {"--max-shards", str(request.max_shards)}
        )
        mismatched = catalog.SourceTransportManifest.create(
            host_ref=local_manifest.host_ref,
            transport_kind=catalog.TransportKind.REMOTE,
            source_kind=local_manifest.source_kind,
            window_start=local_manifest.window_start,
            window_end=local_manifest.window_end,
            status=local_manifest.status,
            records=local_manifest.records,
            snapshot_commitment=local_manifest.snapshot_commitment,
            remote=catalog.RemoteTransportBinding(
                process_nonce="remote-argv-missing-max",
                forced_command_argv=incomplete_argv,
            ),
        )
        with self.assertRaisesRegex(InvalidInputError, "must bind --max-shards"):
            consume_session_shard_frames(
                mismatched,
                source_ref,
                frames,
                request=request,
                limits=limits,
            )

    def test_unauthenticated_partial_gap_blocks_before_materialization(self) -> None:
        coordinator = self.start_daily(
            "mixed",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
        )
        good = b'{"timestamp":"2026-07-06T01:00:00Z","ok":true}\n'
        omitted = b"x" * 11

        def handler(lease):
            if lease["host"] != "local" or lease["source_kind"] != "active_rollout":
                return None
            manifest, records, source_ref = activity_manifest(
                lease,
                [good, omitted],
                status=catalog.SourceCellStatus.GAP,
                gap_reasons={1: "invalid_json"},
            )
            request, frames = record_stream_frames(
                records,
                [good, omitted],
                sharding.ShardLimits(
                    max_bytes=orchestrator_module.EXTRACTOR_SHARD_MAX_BYTES
                ),
                token_seed="mixed",
            )
            return manifest, {
                "_receipt_records": {records[0].unit_ref: good},
                "transport_requests": {source_ref: request},
                "transport_streams": {source_ref: frames},
            }

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        status = coordinator.status()
        self.assertEqual(RunStage.BLOCKED.value, status["stage"])
        self.assertEqual("source_coverage_incomplete", status["blocked_reason"])
        self.assertEqual(0, status["metrics"]["materialized_shards"])
        self.assertEqual(0, status["metrics"]["materialized_raw_bytes"])
        self.assertEqual(
            {"consumed_candidate": 1, "explicit_gap": 1, "structurally_excluded": 0},
            status["metrics"]["accounting"],
        )

    def test_production_and_shadow_partial_require_authenticated_gap_authority(
        self,
    ) -> None:
        for shadow, reason in (
            (False, "missing_host_holdout"),
            (True, "shadow_missing_host_holdout"),
        ):
            with self.subTest(shadow=shadow):
                coordinator = self.start_daily(
                    f"authorized-partial-{shadow}",
                    hosts=DEFAULT_HOSTS,
                    allow_partial=True,
                    shadow=shadow,
                )
                held = coordinator.holdout_host(REMOTE_HOST, reason=reason)
                verified = controlled_gaps.verify_controlled_gap_receipt(
                    coordinator.identity,
                    held["controlled_gap_receipt"],
                )
                self.drain_sources(coordinator)
                coordinator.advance()
                status = coordinator.status()
                self.assertNotEqual(RunStage.BLOCKED.value, status["stage"])
                self.assertEqual("partial", status["coverage"]["status"])
                self.assertEqual(status["run_ref"], verified.run_ref)
                self.assertTrue(verified.backfill_required)

    def test_backlog_clears_only_through_matching_backfill_lineage(self) -> None:
        partial = self.start_daily(
            "production-partial-backlog",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
        )
        held = partial.holdout_host(REMOTE_HOST, reason="missing_host_holdout")
        self.drain_sources(partial)
        partial.advance()
        partial_state = partial.store.read().state
        partial._bind_episode_revisions(partial_state, [])
        durable = partial._publication_durable_state(partial_state)
        published_partial = authority.DurableHistoryState(
            head_commit="b" * 40,
            publication_commit="b" * 40,
            identity_key_id=self.identity.key_id,
            provider_revision=durable["provider_revision_after"],
            cursor_root_ref=durable["proposed_cursor_root_ref"],
            episode_head_root_ref=durable["proposed_episode_head_root_ref"],
            cursor_rows=tuple(durable["proposed_cursor_rows"]),
            episode_heads=tuple(durable["proposed_episode_heads"]),
            episode_membership=tuple(durable["proposed_episode_membership"]),
        )

        with self.assertRaisesRegex(
            RunConflictError, "matching authenticated backfill"
        ):
            self.start_daily(
                "ordinary-full-cannot-clear",
                hosts=DEFAULT_HOSTS,
                durable_history=published_partial,
            )

        with self.assertRaisesRegex(
            RunConflictError, "exact published durable backlog head"
        ):
            self.start_daily(
                "unpublished-backfill-rejected",
                hosts=(REMOTE_HOST,),
                backfill_of=partial_state["run_ref"],
                controlled_gap_receipt=held["controlled_gap_receipt"],
                durable_history=self.durable_history(),
            )
        remote_host_ref = partial_state["host_refs"][REMOTE_HOST]
        wrong_backlog_history = self.durable_history(
            cursor_rows=[
                {
                    "backlog_ref": typed_ref(RefType.RUN_INPUT, "wrong-backlog"),
                    "cursor_ref": None,
                    "host_ref": remote_host_ref,
                    "logical_boundary": None,
                }
            ]
        )
        with self.assertRaisesRegex(
            RunConflictError, "does not match the controlled partial run"
        ):
            self.start_daily(
                "stale-backfill-rejected",
                hosts=(REMOTE_HOST,),
                backfill_of=partial_state["run_ref"],
                controlled_gap_receipt=held["controlled_gap_receipt"],
                durable_history=wrong_backlog_history,
            )

        backfill = self.start_daily(
            "matching-backfill-clears",
            hosts=(REMOTE_HOST,),
            backfill_of=partial_state["run_ref"],
            controlled_gap_receipt=held["controlled_gap_receipt"],
            durable_history=published_partial,
        )
        self.drain_sources(backfill)
        backfill.advance()
        backfill.advance()
        self.assertEqual(RunStage.EXPORT.value, backfill.status()["stage"])
        state = backfill.store.read().state
        host_ref = state["host_refs"][REMOTE_HOST]
        expected_backlog = next(
            row["backlog_ref"]
            for row in published_partial.cursor_rows
            if row["host_ref"] == host_ref
        )
        vector = backfill.publication_host_cursor_vector()[host_ref]
        self.assertEqual(expected_backlog, vector["expected_backlog_head"])
        self.assertIsNone(vector["proposed_backlog_head"])
        update = backfill.publication_episode_head_update()
        lineage = controlled_gaps.verify_backfill_lineage_receipt(
            backfill.identity,
            update["backfill_lineage_receipt"],
        )
        self.assertEqual(expected_backlog, lineage.expected_backlog_ref)
        self.assertIsNone(lineage.proposed_backlog_ref)

    def test_shadow_backfill_derives_run_local_backlog_without_production_state(
        self,
    ) -> None:
        partial = self.start_daily(
            "shadow-partial-successor",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
            shadow=True,
        )
        held = partial.holdout_host(
            REMOTE_HOST,
            reason="shadow_missing_host_holdout",
        )
        successor = self.complete_shadow_partial(partial)
        partial_state = partial.load_state()
        with self.assertRaisesRegex(InvalidInputError, "successor authorization"):
            self.start_daily(
                "shadow-backfill-bypass",
                hosts=(REMOTE_HOST,),
                backfill_of=partial_state["run_ref"],
                controlled_gap_receipt=held["controlled_gap_receipt"],
                shadow=True,
                durable_history=self.durable_history(),
            )
        tampered = copy.deepcopy(successor)
        tampered["coverage_receipt_ref"] = "shadow_coverage_receipt_v2:" + "0" * 64
        with self.assertRaisesRegex(InvalidInputError, "successor authorization"):
            self.start_daily(
                "shadow-backfill-tampered",
                hosts=(REMOTE_HOST,),
                backfill_of=partial_state["run_ref"],
                controlled_gap_receipt=held["controlled_gap_receipt"],
                shadow_successor=tampered,
                shadow=True,
                durable_history=self.durable_history(),
            )
        backfill = self.start_daily(
            "shadow-backfill-successor",
            hosts=(REMOTE_HOST,),
            backfill_of=partial_state["run_ref"],
            controlled_gap_receipt=held["controlled_gap_receipt"],
            shadow_successor=successor,
            shadow=True,
            durable_history=self.durable_history(),
        )
        state = backfill.load_state()
        expected_backlog = str(
            self.identity.derive_ref(
                RefType.RUN_INPUT,
                {
                    "parts": [
                        partial_state["run_ref"],
                        partial_state["host_refs"][REMOTE_HOST],
                        "publication_backlog",
                    ]
                },
            )
        )
        self.assertEqual(
            expected_backlog,
            state["cursors"][REMOTE_HOST]["before"]["backlog_head"],
        )
        self.assertEqual(
            expected_backlog,
            state["lineage"]["expected_backlog_ref"],
        )

    def test_controlled_source_gap_cannot_authorize_agent_gap(self) -> None:
        coordinator = self.start_daily(
            "partial-agent-gap",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
        )
        coordinator.holdout_host(REMOTE_HOST, reason="missing_host_holdout")
        payload = b'{"timestamp":"2026-07-06T01:00:00Z","text":"work"}\n'

        def handler(lease):
            if lease["host"] != "local" or lease["source_kind"] != "active_rollout":
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        first = coordinator.status()["runnable_jobs"][0]
        coordinator.accept_agent_result(
            first["job_ref"],
            first["active_attempt_ref"],
            AgentFailure(AgentFailureKind.TIMEOUT).to_dict(),
        )
        coordinator.advance()
        retry = coordinator.status()["runnable_jobs"][0]
        coordinator.accept_agent_result(
            retry["job_ref"],
            retry["active_attempt_ref"],
            AgentFailure(AgentFailureKind.TIMEOUT).to_dict(),
        )
        coordinator.advance()

        status = coordinator.status()
        self.assertEqual(RunStage.BLOCKED.value, status["stage"])
        self.assertEqual("extraction_incomplete", status["blocked_reason"])

    def test_daily_weekly_overlap_appends_only_changed_workset(self) -> None:
        def episode(turn: str, *, session: str) -> dict[str, object]:
            return {
                "boundary_before": None,
                "extraction_confidence": "high",
                "goal_refs": [typed_ref(RefType.GOAL, f"goal-{session}")],
                "internal_boundary_candidates": [],
                "meaningfulness": {
                    "context_only_turn_refs": [],
                    "disposition": "meaningful",
                    "gap_turn_refs": [],
                    "meaningful_turn_refs": [turn],
                    "review_required": True,
                    "semantic_coverage": "complete",
                },
                "risk_flags": [],
                "segmentation_confidence": "high",
                "session_ref": typed_ref(RefType.SESSION, session),
                "turn_refs": [turn],
                "workstream_refs": [
                    typed_ref(RefType.WORKSTREAM, f"workstream-{session}")
                ],
            }

        overlap_turn = typed_ref(RefType.TURN, "daily-weekly-overlap")
        unchanged_turn = typed_ref(RefType.TURN, "historical-unchanged")
        overlap_head = episode_review.create_episode_revision(
            episode(overlap_turn, session="overlap"),
            identity_key=self.identity,
            key_id=self.identity.key_id,
        )
        unchanged_head = episode_review.create_episode_revision(
            episode(unchanged_turn, session="unchanged"),
            identity_key=self.identity,
            key_id=self.identity.key_id,
        )
        weekly_history = self.durable_history([overlap_head, unchanged_head])
        self.history_state = weekly_history
        weekly = self.coordinator("weekly-overlap")
        weekly.start(
            mode=RunMode.WEEKLY,
            start=WINDOW_START,
            end=WINDOW_END,
            hosts=DEFAULT_HOSTS,
            created_at="2026-07-14T12:00:00Z",
            **self.start_authority(),
        )
        new_turn = typed_ref(RefType.TURN, "weekly-new-turn")
        current = episode(new_turn, session="overlap")
        current["turn_refs"].append(overlap_turn)
        current["meaningfulness"]["meaningful_turn_refs"].append(overlap_turn)
        state = weekly.store.read().state
        state["source"]["reassembly"] = {
            new_turn: {
                "canonical_time": "2026-07-06T00:30:00Z",
                "sequence": 0,
            },
            overlap_turn: {
                "canonical_time": "2026-07-06T01:00:00Z",
                "sequence": 1,
            },
        }
        weekly._bind_episode_revisions(state, [current])

        self.assertEqual(1, len(state["episodes"]))
        successor = state["episodes"][0]
        self.assertEqual(overlap_head["episode_ref"], successor["episode_ref"])
        self.assertEqual(2, successor["revision_ordinal"])
        self.assertEqual([new_turn, overlap_turn], successor["turn_refs"])
        self.assertEqual(
            overlap_head["episode_revision_ref"],
            successor["supersedes_episode_revision_ref"],
        )
        projection = {
            item["episode_ref"]: item
            for item in state["lineage"]["proposed_episode_heads"]
        }
        self.assertEqual(2, len(projection))
        self.assertEqual(unchanged_head, projection[unchanged_head["episode_ref"]])
        self.assertEqual(successor, projection[successor["episode_ref"]])

    def test_retry_uses_fresh_job_then_persists_gap(self) -> None:
        coordinator = self.activity_run("retry")
        first = coordinator.status()["runnable_jobs"][0]
        rejected = coordinator.accept_agent_result(
            first["job_ref"],
            first["active_attempt_ref"],
            AgentFailure(AgentFailureKind.TIMEOUT).to_dict(),
        )
        self.assertEqual("retryable", rejected["outcome"])
        coordinator.advance()
        retry = coordinator.status()["runnable_jobs"][0]
        self.assertNotEqual(first["job_ref"], retry["job_ref"])
        self.assertNotEqual(first["active_attempt_ref"], retry["active_attempt_ref"])
        second = coordinator.accept_agent_result(
            retry["job_ref"],
            retry["active_attempt_ref"],
            {"schema": result_validation.EXTRACTOR_RESULT_SCHEMA, "turns": []},
        )
        self.assertEqual("gap", second["outcome"])
        self.assertEqual("schema_violation", second["reason"])
        coordinator.advance()
        status = coordinator.status()
        self.assertEqual(RunStage.BLOCKED.value, status["stage"])
        self.assertEqual(2, status["metrics"]["agent_attempts"])
        self.assertEqual(1, status["metrics"]["agent_retries"])

    def test_valid_extractor_gap_blocks_without_reassembly_failure(self) -> None:
        coordinator = self.activity_run("typed-extractor-gap")
        job = coordinator.status()["runnable_jobs"][0]
        accepted = coordinator.accept_agent_result(
            job["job_ref"],
            job["active_attempt_ref"],
            {
                "schema": result_validation.EXTRACTOR_RESULT_SCHEMA,
                "turns": [],
                "gap_reason": "insufficient_evidence",
            },
        )

        self.assertEqual("accepted", accepted["outcome"])
        advanced = coordinator.advance()
        state = coordinator.store.read().state

        self.assertEqual("extraction_incomplete", advanced["reason"])
        self.assertEqual(RunStage.BLOCKED.value, state["stage"])
        self.assertEqual("extraction_incomplete", state["blocked_reason"])
        self.assertEqual({}, state["extracted_turns"])
        self.assertIn(
            "insufficient_evidence",
            {gap["reason"] for gap in state["gaps"]},
        )

    def test_extractor_rejects_ordinary_raw_prompt_overlap_without_persisting_it(
        self,
    ) -> None:
        phrase = "Deploy the quartz service only after the bounded approval check."
        payload = (
            json.dumps(
                {
                    "content": phrase,
                    "role": "user",
                    "timestamp": "2026-07-06T01:00:00Z",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        coordinator = self.start_daily("raw-overlap")

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        job = coordinator.status()["runnable_jobs"][0]
        result = self.extractor_result(job)
        result["turns"][0]["generalized_working_text"] = phrase
        rejected = coordinator.accept_agent_result(
            job["job_ref"],
            job["active_attempt_ref"],
            result,
        )

        self.assertEqual("retryable", rejected["outcome"])
        self.assertEqual("schema_violation", rejected["reason"])
        self.assertNotIn(phrase, json.dumps(coordinator.status(), sort_keys=True))
        self.assertNotIn(
            phrase,
            coordinator.store.path.read_text(encoding="utf-8"),
        )

    def test_extractor_rejects_short_prompt_from_fragmented_record(self) -> None:
        phrase = "Acme"
        payload = (
            json.dumps(
                {
                    "content": phrase,
                    "padding": "x" * 200_000,
                    "role": "user",
                    "timestamp": "2026-07-06T01:00:00Z",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        coordinator = self.coordinator(
            "fragmented-short-overlap",
            limits=sharding.ShardLimits(max_bytes=80_000),
        )
        coordinator.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=DAILY_END,
            hosts=DEFAULT_HOSTS,
            created_at="2026-07-14T12:00:00Z",
            **self.start_authority(),
        )

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        state = coordinator.store.read().state
        self.assertGreater(
            next(iter(state["source"]["reassembly"].values()))["fragment_count"],
            1,
        )
        job = coordinator.status()["runnable_jobs"][0]
        task = next(
            task
            for task in state["jobs"].values()
            if task.get("active_job_ref") == job["job_ref"]
        )
        result = self.extractor_result_for_task(task)
        result["turns"][0]["generalized_working_text"] = phrase

        rejected = coordinator.accept_agent_result(
            job["job_ref"],
            job["active_attempt_ref"],
            result,
        )

        self.assertEqual("retryable", rejected["outcome"])
        self.assertEqual("schema_violation", rejected["reason"])

    def test_extractor_rejects_overlap_decoded_from_long_escaped_json_value(
        self,
    ) -> None:
        phrase = "escaped source overlap remains blocked"
        source_text = "x" * 12_000 + phrase + "y" * 12_000
        escaped = "".join(f"\\u{ord(character):04x}" for character in source_text)
        payload = (
            '{"content":"'
            + escaped
            + '","role":"user","timestamp":"2026-07-06T01:00:00Z"}\n'
        ).encode("ascii")
        coordinator = self.start_daily("escaped-long-overlap")

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        state = coordinator.store.read().state
        job = coordinator.status()["runnable_jobs"][0]
        task = next(
            task
            for task in state["jobs"].values()
            if task.get("active_job_ref") == job["job_ref"]
        )
        result = self.extractor_result_for_task(task)
        result["turns"][0]["generalized_working_text"] = phrase

        rejected = coordinator.accept_agent_result(
            job["job_ref"],
            job["active_attempt_ref"],
            result,
        )

        self.assertEqual("retryable", rejected["outcome"])
        self.assertEqual("schema_violation", rejected["reason"])

    def test_extractor_short_overlap_ignores_fixed_metadata_values(self) -> None:
        payload = (
            json.dumps(
                {
                    "content": "Acme",
                    "role": "user",
                    "status": "completed",
                    "timestamp": "2026-07-06T01:00:00Z",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        coordinator = self.start_daily("short-overlap-metadata")

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        state = coordinator.store.read().state
        job = coordinator.status()["runnable_jobs"][0]
        task = next(
            task
            for task in state["jobs"].values()
            if task.get("active_job_ref") == job["job_ref"]
        )
        safe_result = self.extractor_result_for_task(task)
        safe_result["turns"][0]["outcome"] = "completed"
        accepted = coordinator.accept_agent_result(
            job["job_ref"],
            job["active_attempt_ref"],
            safe_result,
        )
        self.assertEqual("accepted", accepted["outcome"])

        second = self.start_daily("short-overlap-content")
        self.drain_sources(second, handler)
        second.advance()
        second_state = second.store.read().state
        second_job = second.status()["runnable_jobs"][0]
        second_task = next(
            task
            for task in second_state["jobs"].values()
            if task.get("active_job_ref") == second_job["job_ref"]
        )
        leaking_result = self.extractor_result_for_task(second_task)
        leaking_result["turns"][0]["generalized_working_text"] = "Acme"
        rejected = second.accept_agent_result(
            second_job["job_ref"],
            second_job["active_attempt_ref"],
            leaking_result,
        )
        self.assertEqual("retryable", rejected["outcome"])
        self.assertEqual("schema_violation", rejected["reason"])

    def test_extractor_accepts_fragmented_source_above_overlap_batch_limit(
        self,
    ) -> None:
        payload = (
            json.dumps(
                {
                    "content": "x"
                    * (result_validation.MAX_SOURCE_OVERLAP_CHARS + 64 * 1024),
                    "role": "user",
                    "timestamp": "2026-07-06T01:00:00Z",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        coordinator = self.coordinator(
            "fragmented-overlap-safe",
            limits=sharding.ShardLimits(max_bytes=80_000),
        )
        coordinator.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=DAILY_END,
            hosts=DEFAULT_HOSTS,
            created_at="2026-07-14T12:00:00Z",
            **self.start_authority(),
        )

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        state = coordinator.store.read().state
        self.assertGreater(
            next(iter(state["source"]["reassembly"].values()))["fragment_count"],
            1,
        )
        job = coordinator.status()["runnable_jobs"][0]
        task = next(
            task
            for task in state["jobs"].values()
            if task.get("active_job_ref") == job["job_ref"]
        )
        accepted = coordinator.accept_agent_result(
            job["job_ref"],
            job["active_attempt_ref"],
            self.extractor_result_for_task(task),
        )

        self.assertEqual("accepted", accepted["outcome"])

    def test_extractor_rejects_overlap_across_source_window_boundary(self) -> None:
        phrase = "cross window source overlap remains blocked"
        marker = "SOURCE_VALUE_MARKER"
        template = json.dumps(
            {
                "content": marker,
                "role": "user",
                "timestamp": "2026-07-06T01:00:00Z",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        marker_offset = template.index(marker.encode("ascii"))
        prefix_length = result_validation.MAX_SOURCE_OVERLAP_CHARS - 16 - marker_offset
        source_value = "x" * prefix_length + phrase + "y" * 80_000
        payload = (
            template.replace(
                marker.encode("ascii"),
                source_value.encode("ascii"),
            )
            + b"\n"
        )
        self.assertEqual(
            result_validation.MAX_SOURCE_OVERLAP_CHARS - 16,
            payload.index(phrase.encode("ascii")),
        )
        coordinator = self.coordinator(
            "fragmented-overlap-boundary",
            limits=sharding.ShardLimits(max_bytes=80_000),
        )
        coordinator.start(
            mode=RunMode.DAILY,
            start=WINDOW_START,
            end=DAILY_END,
            hosts=DEFAULT_HOSTS,
            created_at="2026-07-14T12:00:00Z",
            **self.start_authority(),
        )

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        state = coordinator.store.read().state
        job = coordinator.status()["runnable_jobs"][0]
        task = next(
            task
            for task in state["jobs"].values()
            if task.get("active_job_ref") == job["job_ref"]
        )
        result = self.extractor_result_for_task(task)
        result["turns"][0]["generalized_working_text"] = phrase
        rejected = coordinator.accept_agent_result(
            job["job_ref"],
            job["active_attempt_ref"],
            result,
        )

        self.assertEqual("retryable", rejected["outcome"])
        self.assertEqual("schema_violation", rejected["reason"])
        self.assertNotIn(phrase, coordinator.store.path.read_text(encoding="utf-8"))

    def test_turn_identity_is_stable_across_packing_and_fragments_reassemble_once(
        self,
    ) -> None:
        large_payload = (
            json.dumps(
                {
                    "content": "x" * 200_000,
                    "role": "user",
                    "timestamp": "2026-07-06T01:00:00Z",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        small_payload = b'{"timestamp":"2026-07-06T02:00:00Z","text":"small"}\n'

        def prepare(name: str, max_bytes: int) -> RetrospectiveOrchestrator:
            coordinator = self.coordinator(
                name,
                limits=sharding.ShardLimits(max_bytes=max_bytes),
            )
            coordinator.start(
                mode=RunMode.DAILY,
                start=WINDOW_START,
                end=DAILY_END,
                hosts=DEFAULT_HOSTS,
                created_at="2026-07-14T12:00:00Z",
                **self.start_authority(),
            )

            def handler(lease):
                if (
                    lease["host"] != "local"
                    or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
                ):
                    return None
                manifest, records, _source_ref = activity_manifest(
                    lease,
                    [large_payload, small_payload],
                )
                return manifest, {
                    "raw_records": {
                        records[0].unit_ref: large_payload,
                        records[1].unit_ref: small_payload,
                    }
                }

            self.drain_sources(coordinator, handler)
            coordinator.advance()
            return coordinator

        packed = prepare("turn-packed", 300_000)
        fragmented = prepare("turn-fragmented", 80_000)
        packed_plan = packed.store.read().state["source"]["reassembly"]
        fragmented_plan = fragmented.store.read().state["source"]["reassembly"]

        self.assertEqual(set(packed_plan), set(fragmented_plan))
        large_turn_ref = max(
            fragmented_plan,
            key=lambda ref: fragmented_plan[ref]["fragment_count"],
        )
        self.assertEqual(1, packed_plan[large_turn_ref]["fragment_count"])
        self.assertGreater(fragmented_plan[large_turn_ref]["fragment_count"], 1)

        for job in list(fragmented.status()["runnable_jobs"]):
            state = fragmented.store.read().state
            task = next(
                item
                for item in state["jobs"].values()
                if item.get("active_job_ref") == job["job_ref"]
            )
            accepted = fragmented.accept_agent_result(
                job["job_ref"],
                job["active_attempt_ref"],
                self.extractor_result_for_task(task),
            )
            self.assertEqual("accepted", accepted["outcome"])
        fragmented.advance()
        state = fragmented.store.read().state

        self.assertEqual(set(fragmented_plan), set(state["extracted_turns"]))
        self.assertEqual(2, len(state["extracted_turns"]))
        self.assertEqual(
            fragmented_plan[large_turn_ref]["fragment_count"],
            len(state["extracted_turns"][large_turn_ref]["evidence_refs"]),
        )

    def test_cross_source_offsets_use_one_stable_session_order(self) -> None:
        shared_session = typed_ref(RefType.SESSION, "cross-source-session")
        payloads = {
            SourceKind.ACTIVE_ROLLOUT.value: (
                b'{"timestamp":"2026-07-06T01:00:00Z","text":"rollout"}\n'
            ),
            SourceKind.HISTORY.value: (
                b'{"timestamp":"2026-07-06T01:00:00Z","text":"history"}\n'
            ),
        }

        def prepare(name: str, max_bytes: int) -> dict[str, dict[str, object]]:
            coordinator = self.coordinator(
                name,
                limits=sharding.ShardLimits(max_bytes=max_bytes),
            )
            coordinator.start(
                mode=RunMode.DAILY,
                start=WINDOW_START,
                end=DAILY_END,
                hosts=DEFAULT_HOSTS,
                created_at="2026-07-14T12:00:00Z",
                **self.start_authority(),
            )

            def handler(lease):
                if lease["host"] != "local":
                    return None
                payload = payloads.get(lease["source_kind"])
                if payload is None:
                    return None
                manifest, records, _ = activity_manifest(
                    lease,
                    [payload],
                    source_ref=shared_session,
                )
                return manifest, {"raw_records": {records[0].unit_ref: payload}}

            self.drain_sources(coordinator, handler)
            coordinator.advance()
            return coordinator.store.read().state["source"]["reassembly"]

        packed = prepare("cross-source-packed", 300_000)
        fragmented = prepare("cross-source-fragmented", 4096)

        self.assertEqual(set(packed), set(fragmented))
        self.assertEqual(
            {turn_ref: item["sequence"] for turn_ref, item in packed.items()},
            {turn_ref: item["sequence"] for turn_ref, item in fragmented.items()},
        )
        self.assertEqual([0, 1], sorted(item["sequence"] for item in packed.values()))
        self.assertEqual(
            {shared_session},
            {item["session_ref"] for item in packed.values()},
        )

    def test_logical_turn_sequence_preserves_single_file_byte_order(self) -> None:
        coordinator = self.start_daily("logical-physical-order")
        payloads = [b'{"ordinal":0}\n', b'{"ordinal":1}\n']
        expected_units: list[str] = []

        def handler(lease):
            if (
                lease["host"] != "local"
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            original, records, _source_ref = activity_manifest(lease, payloads)
            physical = "d" * 64
            reordered = [
                replace(
                    record,
                    event_time=(
                        "2026-07-06T02:00:00Z" if index == 0 else "2026-07-06T00:00:00Z"
                    ),
                    coordinate=replace(
                        record.coordinate,
                        record_ref=(
                            f"record-v2:{physical}:"
                            + ("f" * 64 if index == 0 else "a" * 64)
                        ),
                    ),
                )
                for index, record in enumerate(records)
            ]
            expected_units.extend(record.unit_ref for record in reordered)
            manifest = catalog.SourceTransportManifest.create(
                host_ref=original.host_ref,
                transport_kind=original.transport_kind,
                source_kind=original.source_kind,
                window_start=original.window_start,
                window_end=original.window_end,
                status=original.status,
                records=reordered,
                snapshot_commitment=catalog.snapshot_commitment_for_records(reordered),
            )
            return manifest, {
                "raw_records": {
                    record.unit_ref: payload
                    for record, payload in zip(reordered, payloads)
                }
            }

        self.drain_sources(coordinator, handler)
        coordinator.advance()
        reassembly = coordinator.store.read().state["source"]["reassembly"]
        sequence_by_unit = {
            item["source_unit_ref"]: item["sequence"] for item in reassembly.values()
        }

        self.assertEqual([0, 1], [sequence_by_unit[unit] for unit in expected_units])

    def test_agent_claim_lease_heartbeats_and_recovers_same_attempt(self) -> None:
        coordinator = self.activity_run("atomic-agent-claim")
        first = coordinator.status()["runnable_jobs"][0]
        self.assertEqual("unclaimed", first["dispatch_state"])
        self.assertNotIn("envelope_path", first)
        self.assertNotIn("output_sink", first)
        result = self.extractor_result(first)
        with self.assertRaisesRegex(InvalidTransitionError, "active claim"):
            RetrospectiveOrchestrator.accept_agent_result(
                coordinator,
                first["job_ref"],
                first["active_attempt_ref"],
                result,
                claim_ref=typed_ref(RefType.CLAIM, "missing-claim"),
                result_ref=typed_ref(RefType.RESULT, "missing-result"),
            )

        first_dispatcher = typed_ref(RefType.LEASE, "first-dispatcher")
        second_dispatcher = typed_ref(RefType.LEASE, "second-dispatcher")
        claimed = coordinator.claim_agent_job(
            first["job_ref"],
            first["active_attempt_ref"],
            first_dispatcher,
        )
        envelope_path = Path(claimed["envelope_path"])
        envelope_bytes = envelope_path.read_bytes()
        self.assertEqual(claimed["envelope_size"], len(envelope_bytes))
        self.assertEqual(
            claimed["envelope_digest"], hashlib.sha256(envelope_bytes).hexdigest()
        )
        self.assertRegex(claimed["claim_ref"], r"^claim_ref_v2:[0-9a-f]{64}$")
        self.assertFalse(claimed["heartbeat"])
        self.assertFalse(claimed["takeover"])
        self.assertLessEqual(
            len(envelope_bytes), orchestrator_module.MAX_AGENT_ENVELOPE_BYTES
        )
        envelope = json.loads(envelope_bytes)
        self.assertEqual(claimed["claim_ref"], envelope["public_metadata"]["claim_ref"])
        self.assertEqual(
            claimed["output_sink"], envelope["public_metadata"]["output_sink"]
        )
        self.assertEqual(
            claimed["result_ref"], envelope["public_metadata"]["result_ref"]
        )
        self.assertNotIn("input_artifacts", envelope["payload"])
        self.assertNotIn("raw_manifest", envelope["payload"])
        self.assertEqual(1, envelope_bytes.count(b'"payload_b64"'))
        sealed_raw = envelope["payload"]["raw_artifact"]
        self.assertEqual("base64", sealed_raw["encoding"])
        self.assertEqual(
            sealed_raw["manifest"]["content_sha256"],
            hashlib.sha256(base64.b64decode(sealed_raw["payload_b64"])).hexdigest(),
        )
        stale_sink = Path(claimed["output_sink"])
        self.assertEqual(b"", stale_sink.read_bytes())
        self.assertEqual(0o600, stale_sink.stat().st_mode & 0o777)
        stale_sink.unlink()

        recovered = coordinator.claim_agent_job(
            first["job_ref"],
            first["active_attempt_ref"],
            first_dispatcher,
        )
        self.assertTrue(recovered["idempotent"])
        self.assertEqual(b"", stale_sink.read_bytes())
        self.assertEqual(0o600, stale_sink.stat().st_mode & 0o777)
        stale_sink.write_text("{}", encoding="ascii")
        replayed = coordinator.claim_agent_job(
            first["job_ref"],
            first["active_attempt_ref"],
            first_dispatcher,
        )
        self.assertTrue(replayed["idempotent"])
        self.assertEqual("{}", stale_sink.read_text(encoding="ascii"))
        with self.assertRaisesRegex(RunConflictError, "another dispatcher"):
            coordinator.claim_agent_job(
                first["job_ref"],
                first["active_attempt_ref"],
                second_dispatcher,
            )
        public = coordinator.status()["runnable_jobs"][0]
        self.assertEqual("claimed", public["dispatch_state"])
        self.assertNotIn("envelope_path", public)
        self.assertEqual(claimed["output_sink"], public["output_sink"])
        self.assertEqual(claimed["claim_ref"], public["claim_ref"])
        self.assertEqual(claimed["result_ref"], public["result_ref"])
        self.assertFalse(public["claim_expired"])

        self.clock.value += dt.timedelta(
            seconds=orchestrator_module.DEFAULT_AGENT_CLAIM_TTL_SECONDS + 1
        )
        expired = coordinator.status()["runnable_jobs"][0]
        self.assertTrue(expired["claim_expired"])
        takeover = coordinator.claim_agent_job(
            first["job_ref"],
            first["active_attempt_ref"],
            second_dispatcher,
        )
        self.assertTrue(takeover["takeover"])
        self.assertNotEqual(claimed["claim_ref"], takeover["claim_ref"])
        self.assertNotEqual(claimed["output_sink"], takeover["output_sink"])
        self.assertNotEqual(claimed["result_ref"], takeover["result_ref"])
        with self.assertRaisesRegex(RunConflictError, "active claim"):
            coordinator.resolve_agent_result_sink(
                first["job_ref"],
                first["active_attempt_ref"],
                claim_ref=claimed["claim_ref"],
                result_ref=claimed["result_ref"],
                requested_path=stale_sink,
            )
        with self.assertRaisesRegex(RunConflictError, "active claim"):
            RetrospectiveOrchestrator.accept_agent_result(
                coordinator,
                first["job_ref"],
                first["active_attempt_ref"],
                result,
                claim_ref=claimed["claim_ref"],
                result_ref=claimed["result_ref"],
            )
        self.clock.value += dt.timedelta(seconds=10)
        short_heartbeat = coordinator.claim_agent_job(
            first["job_ref"],
            first["active_attempt_ref"],
            second_dispatcher,
            claim_ref=takeover["claim_ref"],
            ttl_seconds=orchestrator_module.MIN_AGENT_CLAIM_TTL_SECONDS,
        )
        self.assertTrue(short_heartbeat["heartbeat"])
        self.assertEqual(
            takeover["claim_expires_at"], short_heartbeat["claim_expires_at"]
        )
        heartbeat = coordinator.claim_agent_job(
            first["job_ref"],
            first["active_attempt_ref"],
            second_dispatcher,
            claim_ref=takeover["claim_ref"],
            ttl_seconds=600,
        )
        self.assertTrue(heartbeat["heartbeat"])
        self.assertEqual(takeover["claim_ref"], heartbeat["claim_ref"])
        self.assertGreater(heartbeat["claim_expires_at"], takeover["claim_expires_at"])
        accepted = RetrospectiveOrchestrator.accept_agent_result(
            coordinator,
            first["job_ref"],
            first["active_attempt_ref"],
            result,
            claim_ref=takeover["claim_ref"],
            result_ref=takeover["result_ref"],
        )
        self.assertEqual("accepted", accepted["outcome"])
        state = coordinator.store.read().state
        task = next(
            task for task in state["jobs"].values() if task["category"] == "agent"
        )
        self.assertEqual(1, len(task["attempts"]))
        self.assertIsNone(task["active_attempt_ref"])
        self.assertEqual(first["active_attempt_ref"], task["accepted_attempt_ref"])
        self.assertEqual(takeover["claim_ref"], task["binding"]["claim_ref"])

        replay = RetrospectiveOrchestrator.accept_agent_result(
            coordinator,
            first["job_ref"],
            first["active_attempt_ref"],
            result,
            claim_ref=takeover["claim_ref"],
            result_ref=takeover["result_ref"],
        )
        self.assertTrue(replay["idempotent"])
        with self.assertRaises(RunConflictError):
            RetrospectiveOrchestrator.accept_agent_result(
                coordinator,
                typed_ref(RefType.JOB, "wrong-successful-result-job"),
                first["active_attempt_ref"],
                result,
                claim_ref=takeover["claim_ref"],
                result_ref=takeover["result_ref"],
            )

    def test_agent_claim_budget_retries_once_then_records_explicit_gap(self) -> None:
        coordinator = self.activity_run("bounded-agent-claim-generations")

        def exhaust_active_attempt(label: str) -> dict[str, object]:
            job = coordinator.status()["runnable_jobs"][0]
            first = coordinator.claim_agent_job(
                job["job_ref"],
                job["active_attempt_ref"],
                typed_ref(RefType.LEASE, f"{label}-dispatcher-1"),
            )
            self.clock.value += dt.timedelta(
                seconds=orchestrator_module.DEFAULT_AGENT_CLAIM_TTL_SECONDS + 1
            )
            second = coordinator.claim_agent_job(
                job["job_ref"],
                job["active_attempt_ref"],
                typed_ref(RefType.LEASE, f"{label}-dispatcher-2"),
            )
            self.assertNotEqual(first["claim_ref"], second["claim_ref"])
            self.clock.value += dt.timedelta(
                seconds=orchestrator_module.DEFAULT_AGENT_CLAIM_TTL_SECONDS + 1
            )
            exhausted = coordinator.claim_agent_job(
                job["job_ref"],
                job["active_attempt_ref"],
                typed_ref(RefType.LEASE, f"{label}-dispatcher-3"),
            )
            replay = coordinator.claim_agent_job(
                job["job_ref"],
                job["active_attempt_ref"],
                typed_ref(RefType.LEASE, f"{label}-dispatcher-replay"),
            )
            self.assertTrue(replay["idempotent"])
            self.assertEqual(exhausted["outcome"], replay["outcome"])
            return exhausted

        first_exhaustion = exhaust_active_attempt("first-attempt")
        self.assertEqual("retryable", first_exhaustion["outcome"])
        self.assertEqual(
            2,
            len(list((coordinator.run_dir / "raw-inputs/agent-claims").glob("*.json"))),
        )
        self.assertEqual(
            2,
            len(list((coordinator.run_dir / "agent-sinks").glob("*.json"))),
        )
        coordinator.advance()
        second_exhaustion = exhaust_active_attempt("second-attempt")
        self.assertEqual("gap", second_exhaustion["outcome"])
        state = coordinator.load_state()
        self.assertEqual(2, state["metrics"]["agent_claim_budget_exhaustions"])
        self.assertEqual(0, state["metrics"]["agent_results"])
        self.assertEqual(0, state["metrics"]["rejected_agent_results"])
        self.assertEqual(
            {"agent_claim_budget_exhausted"},
            {gap["reason"] for gap in state["gaps"]},
        )

    def test_agent_claim_oversized_sink_exhausts_without_takeover(self) -> None:
        coordinator = self.activity_run("bounded-agent-claim-sink")
        job = coordinator.status()["runnable_jobs"][0]
        dispatcher = typed_ref(RefType.LEASE, "oversized-sink-dispatcher")
        claimed = coordinator.claim_agent_job(
            job["job_ref"],
            job["active_attempt_ref"],
            dispatcher,
        )
        Path(claimed["output_sink"]).write_bytes(
            b"x" * (result_validation.MAX_RESULT_BYTES + 1)
        )

        exhausted = coordinator.claim_agent_job(
            job["job_ref"],
            job["active_attempt_ref"],
            dispatcher,
            claim_ref=claimed["claim_ref"],
        )

        self.assertTrue(exhausted["claim_budget_exhausted"])
        self.assertEqual("retryable", exhausted["outcome"])
        self.assertFalse(exhausted["takeover"])

    def test_rejected_agent_result_replay_revalidates_job_binding(self) -> None:
        coordinator = self.activity_run("rejected-agent-result-replay")
        job = coordinator.status()["runnable_jobs"][0]
        claimed = coordinator.claim_agent_job(
            job["job_ref"],
            job["active_attempt_ref"],
            typed_ref(RefType.LEASE, "rejected-result-dispatcher"),
        )
        payload_digest = "a" * 64

        rejected = coordinator.reject_agent_result_payload(
            job["job_ref"],
            job["active_attempt_ref"],
            claim_ref=claimed["claim_ref"],
            result_ref=claimed["result_ref"],
            payload_digest=payload_digest,
            reason="malformed_json",
        )
        replay = coordinator.reject_agent_result_payload(
            job["job_ref"],
            job["active_attempt_ref"],
            claim_ref=claimed["claim_ref"],
            result_ref=claimed["result_ref"],
            payload_digest=payload_digest,
            reason="malformed_json",
        )

        self.assertEqual("retryable", rejected["outcome"])
        self.assertTrue(replay["idempotent"])
        with self.assertRaises(RunConflictError):
            coordinator.reject_agent_result_payload(
                typed_ref(RefType.JOB, "wrong-rejected-result-job"),
                job["active_attempt_ref"],
                claim_ref=claimed["claim_ref"],
                result_ref=claimed["result_ref"],
                payload_digest=payload_digest,
                reason="malformed_json",
            )

    def test_expired_retention_rejects_every_agent_raw_entrypoint(self) -> None:
        scenarios = ("claim", "heartbeat", "resolve", "accept", "reject")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.clock.value = dt.datetime(
                    2026,
                    7,
                    14,
                    12,
                    0,
                    tzinfo=dt.timezone.utc,
                )
                coordinator = self.activity_run(f"expired-agent-{scenario}")
                job = coordinator.status()["runnable_jobs"][0]
                dispatcher_ref = typed_ref(
                    RefType.LEASE,
                    f"expired-agent-dispatcher-{scenario}",
                )
                claimed = None
                if scenario != "claim":
                    claimed = coordinator.claim_agent_job(
                        job["job_ref"],
                        job["active_attempt_ref"],
                        dispatcher_ref,
                    )
                result = self.extractor_result(job)
                self.clock.value += dt.timedelta(days=8)

                with self.assertRaisesRegex(InvalidTransitionError, "retention"):
                    if scenario == "claim":
                        coordinator.claim_agent_job(
                            job["job_ref"],
                            job["active_attempt_ref"],
                            dispatcher_ref,
                        )
                    elif scenario == "heartbeat":
                        assert claimed is not None
                        coordinator.claim_agent_job(
                            job["job_ref"],
                            job["active_attempt_ref"],
                            dispatcher_ref,
                            claim_ref=claimed["claim_ref"],
                        )
                    elif scenario == "resolve":
                        assert claimed is not None
                        coordinator.resolve_agent_result_sink(
                            job["job_ref"],
                            job["active_attempt_ref"],
                            claim_ref=claimed["claim_ref"],
                            result_ref=claimed["result_ref"],
                            requested_path=claimed["output_sink"],
                        )
                    elif scenario == "accept":
                        assert claimed is not None
                        RetrospectiveOrchestrator.accept_agent_result(
                            coordinator,
                            job["job_ref"],
                            job["active_attempt_ref"],
                            result,
                            claim_ref=claimed["claim_ref"],
                            result_ref=claimed["result_ref"],
                        )
                    else:
                        assert claimed is not None
                        coordinator.reject_agent_result_payload(
                            job["job_ref"],
                            job["active_attempt_ref"],
                            claim_ref=claimed["claim_ref"],
                            result_ref=claimed["result_ref"],
                            payload_digest="a" * 64,
                            reason="malformed_json",
                        )

                unchanged = coordinator.load_state()
                self.assertEqual(RunStage.EXTRACTION.value, unchanged["stage"])
                self.assertTrue(unchanged["jobs"])
                cleaned = coordinator.status()
                self.assertEqual(RunStage.BLOCKED.value, cleaned["stage"])
                self.assertEqual("raw_retention_expired", cleaned["blocked_reason"])
                self.assertEqual({}, coordinator.load_state()["jobs"])

    def test_exact_serialized_agent_envelope_enforces_combined_limit(self) -> None:
        coordinator = self.coordinator("exact-envelope-limit")
        base_state = {
            "jobs": {},
            "provenance": orchestrator_module._build_provenance(
                provenance=execution_provenance(),
                policy=None,
                model=None,
                versions=None,
            ),
            "run_ref": typed_ref(RefType.RUN, "exact-envelope-limit"),
        }

        def envelope_size(payload_size: int) -> int | None:
            state = copy.deepcopy(base_state)
            try:
                coordinator._create_agent_task(
                    state,
                    stage=RunStage.GLOBAL_SYNTHESIS.value,
                    kind=JobKind.GLOBAL_SYNTHESIS.value,
                    partition_ref=typed_ref(
                        RefType.RUN_INPUT, "exact-envelope-partition"
                    ),
                    input_refs=(),
                    input_payload={"payload": "x" * payload_size},
                    allowed_refs=(),
                )
            except InvalidInputError:
                return None
            task = next(iter(state["jobs"].values()))
            return len(
                orchestrator_module.canonical_json_bytes(
                    coordinator._project_agent_envelope(state, task, ordinal=1)
                )
            )

        lower = 0
        upper = orchestrator_module.MAX_AGENT_ENVELOPE_BYTES
        while lower < upper:
            candidate = (lower + upper + 1) // 2
            if envelope_size(candidate) is None:
                upper = candidate - 1
            else:
                lower = candidate
        accepted_size = envelope_size(lower)
        self.assertIsNotNone(accepted_size)
        self.assertLessEqual(
            accepted_size,
            orchestrator_module.MAX_AGENT_ENVELOPE_BYTES,
        )
        self.assertIsNone(envelope_size(lower + 1))

    def test_agent_task_cache_metrics_conserve_creation_and_reuse(self) -> None:
        coordinator = self.coordinator("agent-task-cache-metrics")
        state = {
            "jobs": {},
            "metrics": {},
            "provenance": orchestrator_module._build_provenance(
                provenance=execution_provenance(),
                policy=None,
                model=None,
                versions=None,
            ),
            "run_ref": typed_ref(RefType.RUN, "agent-task-cache-metrics"),
        }
        arguments = {
            "stage": RunStage.GLOBAL_SYNTHESIS.value,
            "kind": JobKind.GLOBAL_SYNTHESIS.value,
            "partition_ref": typed_ref(RefType.RUN_INPUT, "cache-partition"),
            "input_refs": (),
            "input_payload": {"schema": "cache-metrics-input-v2"},
            "allowed_refs": (),
        }

        created = coordinator._create_agent_task(state, **arguments)
        reused = coordinator._create_agent_task(state, **arguments)

        self.assertEqual(created, reused)
        self.assertEqual(1, len(state["jobs"]))
        self.assertEqual(
            {
                "agent_task_cache_hits": 1,
                "agent_task_cache_misses": 1,
                "agent_task_reuses": 1,
            },
            state["metrics"],
        )
        self.assertEqual(1, state["jobs"][created]["cache_reuse_count"])
        with mock.patch.object(orchestrator_jobs, "MAX_RUN_AGENT_TASKS", 1):
            self.assertEqual(
                created,
                coordinator._create_agent_task(state, **arguments),
            )
            with self.assertRaisesRegex(InvalidInputError, "cleanup capacity"):
                coordinator._create_agent_task(
                    state,
                    **{
                        **arguments,
                        "partition_ref": typed_ref(
                            RefType.RUN_INPUT,
                            "second-cache-partition",
                        ),
                    },
                )

    def test_all_post_extraction_jobs_partition_under_complete_envelope_cap(
        self,
    ) -> None:
        coordinator = self.coordinator("bounded-agent-hierarchies")
        state = {
            "coverage": {"status": "complete"},
            "cursors": {},
            "episodes": [],
            "gaps": [],
            "host_refs": {},
            "jobs": {},
            "metrics": {
                "accounting": {},
                "agent_attempts": 0,
                "agent_retries": 0,
            },
            "provenance": orchestrator_module._build_provenance(
                provenance=execution_provenance(),
                policy=None,
                model=None,
                versions=None,
            ),
            "run_ref": typed_ref(RefType.RUN, "bounded-agent-hierarchies"),
            "topic_inputs": {},
        }
        envelope_cap = 96 * 1024

        def issue_and_accept(stage: str, payload_size: int = 18_000) -> None:
            coordinator._issue_agent_tasks(state, stage)
            for task in coordinator._tasks_for_stage(state, stage):
                if task["status"] != "runnable":
                    continue
                public = coordinator._public_agent_task(task)
                self.assertLessEqual(
                    len(reporting.canonical_json_bytes(public)),
                    envelope_cap,
                )
                task["status"] = "accepted"
                task["result"] = {
                    "payload": "r" * payload_size,
                    "schema": f"{task['job_kind']}_result_v2",
                    "task_ref": task["task_ref"],
                }

        def issue_final(stage: str) -> list[dict[str, object]]:
            coordinator._issue_agent_tasks(state, stage)
            tasks = coordinator._tasks_for_stage(state, stage)
            for task in tasks:
                if task["status"] == "runnable":
                    self.assertLessEqual(
                        len(
                            reporting.canonical_json_bytes(
                                coordinator._public_agent_task(task)
                            )
                        ),
                        envelope_cap,
                    )
            return tasks

        with mock.patch.object(
            orchestrator_module,
            "MAX_AGENT_ENVELOPE_BYTES",
            envelope_cap,
        ):
            revision = {
                "episode_ref": typed_ref(RefType.EPISODE, "bounded-episode"),
                "episode_revision_ref": typed_ref(
                    RefType.EPISODE_REVISION, "bounded-episode-revision"
                ),
                "risk_flags": ["production"],
                "session_ref": typed_ref(RefType.SESSION, "bounded-session"),
                "turn_refs": [
                    typed_ref(RefType.TURN, f"bounded-turn-{index}")
                    for index in range(12)
                ],
                "workstream_refs": [
                    typed_ref(RefType.WORKSTREAM, "bounded-workstream")
                ],
            }
            turns = [
                {
                    "generalized_working_text": "x" * 28_000,
                    "turn_ref": turn_ref,
                }
                for turn_ref in revision["turn_refs"]
            ]
            full_review_input = {
                "episode_revision": revision,
                "schema": "episode_review_input_v2",
                "turns": turns,
            }
            review_kinds = (
                JobKind.EPISODE_REVIEWER.value,
                JobKind.INDEPENDENT_RISK_REVIEWER.value,
            )
            for kind in review_kinds:
                metadata = {
                    "episode_ref": revision["episode_ref"],
                    "episode_revision_ref": revision["episode_revision_ref"],
                    "reason_codes": ["bounded_hierarchy_test"],
                    "reviewer_slot": (
                        "primary"
                        if kind == JobKind.EPISODE_REVIEWER.value
                        else "secondary"
                    ),
                }
                coordinator._ensure_review_hierarchy(
                    state,
                    revision=revision,
                    kind=kind,
                    metadata=metadata,
                    full_input=full_review_input,
                )
                for _ in range(12):
                    tasks = [
                        task
                        for task in coordinator._tasks_for_stage(
                            state, RunStage.EPISODE_REVIEW.value
                        )
                        if task["job_kind"] == kind
                    ]
                    if any(task["metadata"]["hierarchy_final"] for task in tasks):
                        break
                    issue_and_accept(RunStage.EPISODE_REVIEW.value)
                    coordinator._ensure_review_hierarchy(
                        state,
                        revision=revision,
                        kind=kind,
                        metadata=metadata,
                        full_input=full_review_input,
                    )
                else:  # pragma: no cover - bounded convergence assertion
                    self.fail(f"{kind} hierarchy did not converge")
                tasks = issue_final(RunStage.EPISODE_REVIEW.value)
                kind_tasks = [task for task in tasks if task["job_kind"] == kind]
                self.assertGreater(
                    len(
                        [
                            task
                            for task in kind_tasks
                            if task["metadata"]["hierarchy_level"] == 0
                        ]
                    ),
                    1,
                )
                self.assertEqual(
                    1,
                    sum(
                        task["metadata"]["hierarchy_final"] is True
                        for task in kind_tasks
                    ),
                )

            candidate_results = [
                {
                    "episode_ref": revision["episode_ref"],
                    "episode_revision_ref": revision["episode_revision_ref"],
                    "payload": character * (result_validation.MAX_RESULT_BYTES - 1024),
                    "schema": result_validation.EPISODE_REVIEW_RESULT_SCHEMA,
                }
                for character in ("a", "b")
            ]
            adjudication_payload = {
                "candidate_result_hashes": [
                    result_validation.canonical_result_hash(result)
                    for result in candidate_results
                ],
                "candidate_results": candidate_results,
                "episode_context": {
                    "episode_ref": revision["episode_ref"],
                    "episode_revision_ref": revision["episode_revision_ref"],
                    "session_ref": revision["session_ref"],
                },
                "schema": "episode_adjudication_input_v2",
            }
            with mock.patch.object(
                orchestrator_module,
                "MAX_AGENT_ENVELOPE_BYTES",
                512 * 1024,
            ):
                coordinator._create_agent_task(
                    state,
                    stage=RunStage.EPISODE_REVIEW.value,
                    kind=JobKind.ADJUDICATOR.value,
                    partition_ref=revision["episode_revision_ref"],
                    input_refs=[
                        revision["episode_ref"],
                        revision["episode_revision_ref"],
                    ],
                    input_payload=adjudication_payload,
                    allowed_refs=coordinator._collect_refs(adjudication_payload),
                    allowed_turn_refs=revision["turn_refs"],
                    metadata={"candidate_results": candidate_results},
                )
                coordinator._issue_agent_tasks(state, RunStage.EPISODE_REVIEW.value)
            adjudication_tasks = coordinator._tasks_for_stage(
                state, RunStage.EPISODE_REVIEW.value
            )
            adjudicator = next(
                task
                for task in adjudication_tasks
                if task["job_kind"] == JobKind.ADJUDICATOR.value
            )
            self.assertLessEqual(
                len(
                    reporting.canonical_json_bytes(
                        coordinator._public_agent_task(adjudicator)
                    )
                ),
                512 * 1024,
            )
            self.assertEqual(
                1,
                sum(
                    task["job_kind"] == JobKind.ADJUDICATOR.value
                    for task in adjudication_tasks
                ),
            )

            episode_rows = []
            episode_contexts = []
            episode_reviews = []
            for index in range(12):
                episode_ref = typed_ref(RefType.EPISODE, f"topic-episode-{index}")
                revision_ref = typed_ref(
                    RefType.EPISODE_REVISION, f"topic-revision-{index}"
                )
                turn_ref = typed_ref(RefType.TURN, f"topic-turn-{index}")
                episode = {
                    "episode_ref": episode_ref,
                    "episode_revision_ref": revision_ref,
                    "turn_refs": [turn_ref],
                }
                review = {
                    "episode_ref": episode_ref,
                    "episode_revision_ref": revision_ref,
                    "payload": "t" * 18_000,
                    "schema": result_validation.EPISODE_REVIEW_RESULT_SCHEMA,
                }
                episode_rows.append((episode, review))
                episode_contexts.append(
                    {
                        "episode_ref": episode_ref,
                        "episode_revision_ref": revision_ref,
                        "session_ref": typed_ref(
                            RefType.SESSION, f"topic-session-{index}"
                        ),
                    }
                )
                episode_reviews.append(review)
            root_ref = typed_ref(RefType.TOPIC_CANDIDATE, "bounded-topic-root")
            topic_ref = typed_ref(RefType.TOPIC, "bounded-topic")
            topic_input = {
                "adjudication_candidate_results": {},
                "adjudication_required_episode_revision_refs": [],
                "episode_contexts": episode_contexts,
                "episode_reviews": episode_reviews,
                "expected_episode_revision_refs": [
                    item["episode_revision_ref"] for item in episode_contexts
                ],
                "schema": result_validation.TOPIC_INPUT_SCHEMA,
                "topic_candidate_ref": root_ref,
                "workstream_ref": typed_ref(
                    RefType.WORKSTREAM, "bounded-topic-workstream"
                ),
            }
            state["topic_inputs"][root_ref] = {
                "expected_episode_revision_refs": topic_input[
                    "expected_episode_revision_refs"
                ],
                "leaf_input_hashes": [],
                "schema": "topic_partition_index_v2",
                "topic_candidate_ref": root_ref,
                "topic_ref": topic_ref,
                "workstream_ref": topic_input["workstream_ref"],
            }
            partitions = []
            for start in range(0, len(episode_rows), 3):
                revision_refs = [
                    item[0]["episode_revision_ref"]
                    for item in episode_rows[start : start + 3]
                ]
                sliced = coordinator._slice_topic_input(topic_input, revision_refs)
                partitions.append(
                    {
                        "adjudication_candidate_results": {},
                        "allowed_refs": sorted(
                            coordinator._collect_refs(
                                {
                                    "topic_input": sliced,
                                    "topic_ref": topic_ref,
                                }
                            )
                        ),
                        "allowed_turn_refs": [
                            item[0]["turn_refs"][0]
                            for item in episode_rows[start : start + 3]
                        ],
                        "topic_input": sliced,
                    }
                )
            coordinator._seed_topic_hierarchy(
                state,
                partitions=partitions,
                topic_ref=topic_ref,
                root_ref=root_ref,
            )
            for _ in range(12):
                topic_tasks = coordinator._tasks_for_stage(
                    state, RunStage.TOPIC_REDUCTION.value
                )
                if any(task["metadata"]["hierarchy_final"] for task in topic_tasks):
                    break
                issue_and_accept(RunStage.TOPIC_REDUCTION.value)
                coordinator._refresh_topic_hierarchies(state)
            else:  # pragma: no cover - bounded convergence assertion
                self.fail("topic hierarchy did not converge")
            topic_tasks = issue_final(RunStage.TOPIC_REDUCTION.value)
            final_topic = [
                task for task in topic_tasks if task["metadata"]["hierarchy_final"]
            ]
            self.assertEqual(1, len(final_topic))
            self.assertEqual(
                set(topic_input["expected_episode_revision_refs"]),
                set(final_topic[0]["metadata"]["underlying_episode_refs"]),
            )

            state["jobs"] = {
                task_ref: task
                for task_ref, task in state["jobs"].items()
                if task["stage"] != RunStage.TOPIC_REDUCTION.value
            }
            synthesis_topic_roots = [
                typed_ref(RefType.TOPIC_CANDIDATE, f"synthesis-root-{index}")
                for index in range(12)
            ]
            topic_results = [
                {
                    "evidence_refs": [
                        typed_ref(
                            RefType.EVIDENCE,
                            f"synthesis-evidence-{index}-{ref_index}",
                        )
                        for ref_index in range(180)
                    ],
                    "payload": "s" * 18_000,
                    "schema": result_validation.TOPIC_RESULT_SCHEMA,
                    "topic_candidate_ref": synthesis_topic_roots[index],
                    "topic_ref": typed_ref(RefType.TOPIC, f"synthesis-topic-{index}"),
                }
                for index in range(12)
            ]
            state["topic_inputs"] = {root: {} for root in synthesis_topic_roots}
            for index, result in enumerate(topic_results):
                task_ref = typed_ref(
                    RefType.RUN_INPUT, f"synthesis-topic-source-{index}"
                )
                state["jobs"][task_ref] = {
                    "job_kind": JobKind.TOPIC_REDUCER.value,
                    "metadata": {
                        "hierarchy_final": True,
                        "hierarchy_root_ref": synthesis_topic_roots[index],
                    },
                    "result": copy.deepcopy(result),
                    "stage": RunStage.TOPIC_REDUCTION.value,
                    "status": "accepted",
                    "task_ref": task_ref,
                }
            independent_reviews = [
                {
                    "episode_ref": typed_ref(
                        RefType.EPISODE, f"synthesis-episode-{index}"
                    ),
                    "payload": "v" * 18_000,
                    "schema": result_validation.EPISODE_REVIEW_RESULT_SCHEMA,
                }
                for index in range(12)
            ]
            state["episodes"] = [
                {"turn_refs": [typed_ref(RefType.TURN, f"synthesis-{index}")]}
                for index in range(12)
            ]
            synthesis_root = typed_ref(RefType.RUN_INPUT, "bounded-synthesis-root")
            synthesis_source_refs = coordinator._collect_refs(
                {
                    "independent_reviews": independent_reviews,
                    "topic_results": topic_results,
                }
            )
            self.assertGreater(
                len(reporting.canonical_json_bytes(sorted(synthesis_source_refs))),
                envelope_cap,
            )
            coordinator._seed_synthesis_hierarchy(
                state,
                root_ref=synthesis_root,
                topic_results=topic_results,
                independent_reviews=independent_reviews,
            )
            for _ in range(12):
                synthesis_tasks = coordinator._tasks_for_stage(
                    state, RunStage.GLOBAL_SYNTHESIS.value
                )
                if any(task["metadata"]["hierarchy_final"] for task in synthesis_tasks):
                    break
                issue_and_accept(RunStage.GLOBAL_SYNTHESIS.value)
                coordinator._refresh_synthesis_hierarchy(state)
            else:  # pragma: no cover - bounded convergence assertion
                self.fail("synthesis hierarchy did not converge")
            synthesis_tasks = issue_final(RunStage.GLOBAL_SYNTHESIS.value)
            final_synthesis = [
                task for task in synthesis_tasks if task["metadata"]["hierarchy_final"]
            ]
            self.assertEqual(1, len(final_synthesis))
            self.assertFalse(
                synthesis_source_refs <= set(final_synthesis[0]["allowed_refs"])
            )
            validation_topics, validation_reviews = (
                coordinator._synthesis_validation_results(state, final_synthesis[0])
            )
            self.assertEqual(
                {
                    result_validation.canonical_result_hash(result)
                    for result in topic_results
                },
                {
                    result_validation.canonical_result_hash(result)
                    for result in validation_topics
                },
            )
            self.assertEqual(
                {
                    result_validation.canonical_result_hash(result)
                    for result in independent_reviews
                },
                {
                    result_validation.canonical_result_hash(result)
                    for result in validation_reviews
                },
            )

    def test_global_synthesis_rejects_missing_final_topic_root(self) -> None:
        coordinator = self.coordinator("synthesis-missing-root")
        expected = typed_ref(RefType.TOPIC_CANDIDATE, "synthesis-expected")
        state = self.synthesis_root_state(expected_roots=[expected], accepted_roots=[])

        with self.assertRaisesRegex(
            InvalidTransitionError, "missing accepted final topic result root"
        ):
            coordinator._seed_synthesis_task(state)

    def test_global_synthesis_rejects_duplicate_final_topic_root(self) -> None:
        coordinator = self.coordinator("synthesis-duplicate-root")
        expected = typed_ref(RefType.TOPIC_CANDIDATE, "synthesis-expected")
        state = self.synthesis_root_state(
            expected_roots=[expected], accepted_roots=[expected, expected]
        )

        with self.assertRaisesRegex(
            InvalidTransitionError, "duplicate accepted final topic result root"
        ):
            coordinator._seed_synthesis_task(state)

    def test_global_synthesis_rejects_extra_final_topic_root(self) -> None:
        coordinator = self.coordinator("synthesis-extra-root")
        expected = typed_ref(RefType.TOPIC_CANDIDATE, "synthesis-expected")
        extra = typed_ref(RefType.TOPIC_CANDIDATE, "synthesis-extra")
        state = self.synthesis_root_state(
            expected_roots=[expected], accepted_roots=[expected, extra]
        )

        with self.assertRaisesRegex(
            InvalidTransitionError, "extra accepted final topic result root"
        ):
            coordinator._seed_synthesis_task(state)

    def test_topic_inputs_partition_before_the_64k_validator_boundary(self) -> None:
        coordinator = self.coordinator("topic-partition-before-validation")
        workstream_ref = typed_ref(RefType.WORKSTREAM, "partitioned-workstream")
        episodes = []
        resolved_reviews = {}
        for index in range(10):
            episode_ref = typed_ref(RefType.EPISODE, f"partition-episode-{index}")
            revision_ref = typed_ref(
                RefType.EPISODE_REVISION,
                f"partition-revision-{index}",
            )
            episodes.append(
                {
                    "episode_ref": episode_ref,
                    "episode_revision_ref": revision_ref,
                    "meaningfulness": {"review_required": True},
                    "session_ref": typed_ref(
                        RefType.SESSION,
                        f"partition-session-{index}",
                    ),
                    "turn_refs": [typed_ref(RefType.TURN, f"partition-turn-{index}")],
                    "workstream_refs": [workstream_ref],
                }
            )
            resolved_reviews[revision_ref] = {
                "disposition": "reviewed",
                "payload": "x" * 20_000,
                "schema": result_validation.EPISODE_REVIEW_RESULT_SCHEMA,
            }
        state = {
            "episodes": episodes,
            "jobs": {},
            "resolved_reviews": resolved_reviews,
            "topic_inputs": {},
        }
        validated_sizes = []
        seeded_partitions = []

        def validate_bounded(value, *_args, **_kwargs):
            encoded_size = len(reporting.canonical_json_bytes(value))
            validated_sizes.append(encoded_size)
            self.assertLessEqual(encoded_size, result_validation.MAX_RESULT_BYTES)
            return copy.deepcopy(value)

        def capture_seed(_state, *, partitions, **_kwargs):
            seeded_partitions.extend(copy.deepcopy(partitions))

        with (
            mock.patch.object(
                result_validation,
                "validate_topic_input",
                side_effect=validate_bounded,
            ),
            mock.patch.object(
                coordinator,
                "_seed_topic_hierarchy",
                side_effect=capture_seed,
            ),
        ):
            coordinator._build_topic_inputs(state)

        self.assertGreater(len(validated_sizes), 1)
        self.assertEqual(len(validated_sizes), len(seeded_partitions))
        index = next(iter(state["topic_inputs"].values()))
        self.assertEqual("topic_partition_index_v2", index["schema"])
        self.assertEqual(10, len(index["expected_episode_revision_refs"]))

    def test_topic_inputs_reject_missing_review_required_episode_revision(
        self,
    ) -> None:
        coordinator = self.coordinator("topic-input-review-conservation")
        workstream_ref = typed_ref(RefType.WORKSTREAM, "review-conservation")
        revisions = []
        for index in range(2):
            revisions.append(
                {
                    "episode_ref": typed_ref(
                        RefType.EPISODE, f"review-conservation-episode-{index}"
                    ),
                    "episode_revision_ref": typed_ref(
                        RefType.EPISODE_REVISION,
                        f"review-conservation-revision-{index}",
                    ),
                    "meaningfulness": {
                        "disposition": "meaningful",
                        "review_required": True,
                    },
                    "session_ref": typed_ref(
                        RefType.SESSION, f"review-conservation-session-{index}"
                    ),
                    "turn_refs": [
                        typed_ref(RefType.TURN, f"review-conservation-turn-{index}")
                    ],
                    "workstream_refs": [workstream_ref],
                }
            )
        state = {
            "episodes": revisions,
            "jobs": {},
            "resolved_reviews": {
                revisions[0]["episode_revision_ref"]: {
                    "disposition": "reviewed",
                    "schema": result_validation.EPISODE_REVIEW_RESULT_SCHEMA,
                }
            },
            "topic_inputs": {},
        }

        with self.assertRaisesRegex(
            InvalidTransitionError,
            "exactly cover every review-required episode revision",
        ):
            coordinator._build_topic_inputs(state)

    def test_backfill_requires_head_set_cas_and_emits_successor_revision(self) -> None:
        seed = self.start_daily("backfill-seed", hosts=DEFAULT_HOSTS)
        seed_payload = b'{"timestamp":"2026-07-06T01:00:00Z","text":"work"}\n'

        def seed_handler(lease):
            if (
                lease["host"] != REMOTE_HOST
                or lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value
            ):
                return None
            manifest, records, _source_ref = activity_manifest(
                lease,
                [seed_payload],
            )
            return manifest, {"raw_records": {records[0].unit_ref: seed_payload}}

        self.drain_sources(seed, seed_handler)
        seed.advance()
        extractor = seed.status()["runnable_jobs"][0]
        accepted = seed.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            self.extractor_result(extractor),
        )
        self.assertEqual("accepted", accepted["outcome"])
        seed.advance()
        prior_head = copy.deepcopy(seed.store.read().state["episodes"][0])

        partial = self.start_daily(
            "backfill-partial",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
            shadow=True,
        )
        partial.holdout_host(
            REMOTE_HOST,
            reason="shadow_missing_host_holdout",
        )
        successor = self.complete_shadow_partial(partial)
        gap_receipt = successor["controlled_gap_receipt"]
        original_state = partial.store.read().state
        self.history_state = self.durable_backlog_history(
            original_state,
            host=REMOTE_HOST,
            episode_heads=[prior_head],
        )
        invalid = self.coordinator("backfill-invalid-cas")
        with self.assertRaisesRegex(InvalidInputError, "derived from durable history"):
            invalid.start(
                mode=RunMode.DAILY,
                start=WINDOW_START,
                end=DAILY_END,
                hosts=(REMOTE_HOST,),
                backfill_of=original_state["run_ref"],
                prior_episode_heads=[prior_head],
                controlled_gap_receipt=gap_receipt,
                prior_episode_head_set_ref=authority.empty_episode_head_root(
                    self.identity
                ),
                shadow=True,
                **self.start_authority(),
            )

        backfill = self.start_daily(
            "backfill-successor",
            hosts=(REMOTE_HOST,),
            backfill_of=original_state["run_ref"],
            prior_episode_heads=[prior_head],
            controlled_gap_receipt=gap_receipt,
            shadow_successor=successor,
            shadow=True,
            durable_history=self.durable_backlog_history(
                original_state,
                host=REMOTE_HOST,
                episode_heads=[prior_head],
            ),
        )
        new_payload = b'{"timestamp":"2026-07-06T02:00:00Z","text":"work backfill"}\n'
        payloads = [seed_payload, new_payload]

        def handler(lease):
            if lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value:
                return None
            manifest, records, _source_ref = activity_manifest(lease, payloads)
            return manifest, {
                "raw_records": {
                    record.unit_ref: payload
                    for record, payload in zip(records, payloads, strict=True)
                }
            }

        self.drain_sources(backfill, handler)
        backfill.advance()
        extractor = backfill.status()["runnable_jobs"][0]
        task = next(
            task
            for task in backfill.store.read().state["jobs"].values()
            if task.get("active_job_ref") == extractor["job_ref"]
        )
        result = self.extractor_result_for_task(task)
        for turn in result["turns"]:
            turn["goal_change"] = "continues"
        backfill.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            result,
        )
        backfill.advance()
        state = backfill.store.read().state
        successor = state["episodes"][0]
        expected_head_set = authority.derive_episode_head_root(
            [prior_head], identity=self.identity
        )

        self.assertEqual(prior_head["episode_ref"], successor["episode_ref"])
        self.assertEqual("extension", successor["lineage_kind"])
        self.assertEqual(
            prior_head["episode_revision_ref"],
            successor["supersedes_episode_revision_ref"],
        )
        self.assertEqual(
            prior_head["revision_ordinal"] + 1,
            successor["revision_ordinal"],
        )
        self.assertEqual(
            expected_head_set,
            state["lineage"]["expected_episode_head_set_ref"],
        )
        self.assertEqual(
            authority.derive_episode_head_root([successor], identity=self.identity),
            state["lineage"]["proposed_episode_head_set_ref"],
        )
        lineage_receipt = controlled_gaps.verify_backfill_lineage_receipt(
            backfill.identity,
            state["lineage"]["backfill_lineage_receipt"],
        )
        self.assertEqual(
            gap_receipt["receipt_ref"],
            lineage_receipt.controlled_gap_receipt_ref,
        )
        self.assertEqual(
            expected_head_set, lineage_receipt.expected_episode_head_set_ref
        )

    def test_backfill_review_blocks_when_prior_turn_material_is_missing(self) -> None:
        coordinator = self.coordinator("backfill-missing-prior-turn-material")
        old_turn_ref = typed_ref(RefType.TURN, "missing-prior-turn")
        new_turn_ref = typed_ref(RefType.TURN, "available-backfill-turn")
        revision_ref = typed_ref(
            RefType.EPISODE_REVISION, "missing-prior-turn-successor"
        )
        state = {
            "blocked_reason": None,
            "coverage": {"status": "complete"},
            "extracted_turns": {
                new_turn_ref: {
                    "generalized_working_text": "Newly validated backfill material.",
                    "turn_ref": new_turn_ref,
                }
            },
            "gaps": [],
            "lineage": {
                "backfill_of": typed_ref(RefType.RUN, "missing-prior-run"),
                "prior_episode_heads": [{"turn_refs": [old_turn_ref]}],
            },
            "metrics": {"stage_transitions": 0},
            "run_ref": typed_ref(RefType.RUN, "missing-prior-material-run"),
            "stage": RunStage.EXTRACTION.value,
            "stage_history": [],
        }

        payloads = coordinator._episode_turn_payloads(
            state,
            [old_turn_ref, new_turn_ref],
            episode_revision_ref=revision_ref,
        )

        self.assertIsNone(payloads)
        self.assertEqual(RunStage.BLOCKED.value, state["stage"])
        self.assertEqual("episode_turn_material_missing", state["blocked_reason"])
        self.assertEqual(1, len(state["gaps"]))
        gap = state["gaps"][0]
        self.assertEqual(RunStage.EPISODE_REVIEW.value, gap["stage"])
        self.assertEqual("episode_turn_material_missing", gap["reason"])
        self.assertEqual(
            {
                "episode_revision_ref": revision_ref,
                "kind": "episode_turn_material_gap",
                "missing_turn_count": "1",
                "missing_turn_refs_commitment": content_digest([old_turn_ref]),
            },
            gap["typed_gap"],
        )

    def test_backfill_does_not_match_session_default_workstream_alone(self) -> None:
        episode_ref = typed_ref(RefType.EPISODE, "prior-semantic-anchor")
        shared_workstream = typed_ref(RefType.WORKSTREAM, "session-default")
        prior_goal = typed_ref(RefType.GOAL, "prior-goal")
        current_goal = typed_ref(RefType.GOAL, "current-goal")
        head = {"episode_ref": episode_ref}
        episode = {
            "turn_refs": [typed_ref(RefType.TURN, "current-turn")],
            "goal_refs": [current_goal],
            "workstream_refs": [shared_workstream],
        }
        membership = [
            {"anchor_ref": prior_goal, "episode_ref": episode_ref},
            {"anchor_ref": shared_workstream, "episode_ref": episode_ref},
        ]

        candidates = RetrospectiveOrchestrator._backfill_predecessor_candidates(
            episode,
            [head],
            membership,
        )

        self.assertEqual([], candidates)

        episode["goal_refs"] = [prior_goal]
        candidates = RetrospectiveOrchestrator._backfill_predecessor_candidates(
            episode,
            [head],
            membership,
        )
        self.assertEqual([head], candidates)

    def test_backfill_allows_initial_episode_from_exact_controlled_host(self) -> None:
        partial = self.start_daily(
            "backfill-new-partial",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
            shadow=True,
        )
        holdout = partial.holdout_host(
            REMOTE_HOST,
            reason="shadow_missing_host_holdout",
        )
        successor = self.complete_shadow_partial(partial)
        partial_state = partial.store.read().state

        backfill = self.start_daily(
            "backfill-new-episode",
            hosts=(REMOTE_HOST,),
            backfill_of=partial_state["run_ref"],
            prior_episode_heads=[],
            controlled_gap_receipt=holdout["controlled_gap_receipt"],
            shadow_successor=successor,
            shadow=True,
            durable_history=self.durable_backlog_history(
                partial_state,
                host=REMOTE_HOST,
            ),
        )
        payload = b'{"timestamp":"2026-07-06T01:00:00Z","text":"new host work"}\n'

        def handler(lease):
            if lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value:
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(backfill, handler)
        backfill.advance()
        extractor = backfill.status()["runnable_jobs"][0]
        accepted = backfill.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            self.extractor_result(extractor),
        )
        self.assertEqual("accepted", accepted["outcome"])
        backfill.advance()
        state = backfill.store.read().state

        self.assertEqual(1, len(state["episodes"]))
        new_head = state["episodes"][0]
        self.assertEqual("initial", new_head["lineage_kind"])
        self.assertEqual(1, new_head["revision_ordinal"])
        self.assertIsNone(new_head["supersedes_episode_revision_ref"])
        verified = controlled_gaps.verify_backfill_lineage_receipt(
            backfill.identity,
            state["lineage"]["backfill_lineage_receipt"],
        )
        self.assertEqual(
            holdout["controlled_gap_receipt"]["receipt_ref"],
            verified.controlled_gap_receipt_ref,
        )
        self.assertEqual(
            state["lineage"]["proposed_episode_head_set_ref"],
            verified.proposed_episode_head_set_ref,
        )

    def test_backfill_uses_stable_membership_without_session_fallback(
        self,
    ) -> None:
        partial = self.start_daily(
            "backfill-reset-partial",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
            shadow=True,
        )
        holdout = partial.holdout_host(
            REMOTE_HOST,
            reason="shadow_missing_host_holdout",
        )
        successor = self.complete_shadow_partial(partial)
        partial_state = partial.store.read().state
        gap_receipt = holdout["controlled_gap_receipt"]
        source_ref = typed_ref(
            RefType.SESSION,
            (f"source:{gap_receipt['host_ref']}:{SourceKind.ACTIVE_ROLLOUT.value}"),
        )

        prior_heads = []
        for index in range(2):
            turn_ref = typed_ref(RefType.TURN, f"prior-reset-turn-{index}")
            episode = {
                "boundary_before": None,
                "extraction_confidence": "high",
                "goal_refs": [typed_ref(RefType.GOAL, f"prior-reset-goal-{index}")],
                "internal_boundary_candidates": [],
                "meaningfulness": {
                    "context_only_turn_refs": [],
                    "disposition": "meaningful",
                    "gap_turn_refs": [],
                    "meaningful_turn_refs": [turn_ref],
                    "review_required": True,
                    "semantic_coverage": "complete",
                },
                "risk_flags": ["production"],
                "segmentation_confidence": "high",
                "session_ref": source_ref,
                "turn_refs": [turn_ref],
                "workstream_refs": [
                    typed_ref(RefType.WORKSTREAM, f"prior-reset-workstream-{index}")
                ],
            }
            prior_heads.append(
                episode_review.create_episode_revision(
                    episode,
                    identity_key=self.identity,
                    key_id=self.identity.key_id,
                )
            )

        backfill = self.start_daily(
            "backfill-reset-attempt",
            hosts=(REMOTE_HOST,),
            backfill_of=partial_state["run_ref"],
            prior_episode_heads=prior_heads,
            controlled_gap_receipt=gap_receipt,
            shadow_successor=successor,
            shadow=True,
            durable_history=self.durable_backlog_history(
                partial_state,
                host=REMOTE_HOST,
                episode_heads=prior_heads,
            ),
        )
        payload = b'{"timestamp":"2026-07-06T01:00:00Z","text":"reset attempt"}\n'

        def handler(lease):
            if lease["source_kind"] != SourceKind.ACTIVE_ROLLOUT.value:
                return None
            manifest, records, _source_ref = activity_manifest(lease, [payload])
            return manifest, {"raw_records": {records[0].unit_ref: payload}}

        self.drain_sources(backfill, handler)
        backfill.advance()
        extractor = backfill.status()["runnable_jobs"][0]
        backfill.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            self.extractor_result(extractor),
        )
        backfill.advance()
        state = backfill.store.read().state
        self.assertEqual(1, len(state["episodes"]))
        prior_refs = {item["episode_ref"] for item in prior_heads}
        new_episode = state["episodes"][0]
        self.assertNotIn(new_episode["episode_ref"], prior_refs)
        self.assertEqual("initial", new_episode["lineage_kind"])
        self.assertEqual(1, new_episode["revision_ordinal"])
        proposed = backfill._publication_durable_state(state)
        proposed_by_ref = {
            item["episode_ref"]: item for item in proposed["proposed_episode_heads"]
        }
        for prior in prior_heads:
            self.assertEqual(prior, proposed_by_ref[prior["episode_ref"]])
        self.assertEqual(new_episode, proposed_by_ref[new_episode["episode_ref"]])
        self.assertEqual(3, len(proposed_by_ref))
        self.assertIsNotNone(state["lineage"]["backfill_lineage_receipt"])

    def test_review_screening_composition_requires_explicit_turn_evidence(
        self,
    ) -> None:
        coordinator = self.coordinator("review-screening-composition")
        high_impact_turn = typed_ref(RefType.TURN, "screened-high-impact")
        low_impact_turn = typed_ref(RefType.TURN, "screened-not-high-impact")
        incomplete_turn = typed_ref(RefType.TURN, "screening-evidence-missing")
        absent_turn = typed_ref(RefType.TURN, "screening-turn-absent")
        state = {
            "extracted_turns": {
                high_impact_turn: {
                    "risk_flags": ["high_impact_prompt", "privacy"],
                    "turn_ref": high_impact_turn,
                },
                incomplete_turn: {"turn_ref": incomplete_turn},
                low_impact_turn: {
                    "risk_flags": ["production"],
                    "turn_ref": low_impact_turn,
                },
            }
        }

        decisions = coordinator._compose_episode_screening_results(
            state,
            [low_impact_turn, incomplete_turn, high_impact_turn, absent_turn],
        )

        self.assertEqual(
            [
                {
                    "decision": "not_high_impact",
                    "risk_flags": ["production"],
                    "turn_ref": low_impact_turn,
                },
                {
                    "decision": "high_impact",
                    "risk_flags": ["high_impact_prompt", "privacy"],
                    "turn_ref": high_impact_turn,
                },
            ],
            decisions,
        )

    def test_review_plan_receives_exact_extractor_screening_decision(self) -> None:
        coordinator = self.activity_run("review-screening-integration")
        extractor = coordinator.status()["runnable_jobs"][0]
        result = self.extractor_result(extractor)
        turn_ref = result["turns"][0]["turn_ref"]
        result["turns"][0]["risk_flags"] = ["privacy", "high_impact_prompt"]
        coordinator.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            result,
        )

        with mock.patch.object(
            episode_review,
            "plan_episode_review_jobs",
            wraps=episode_review.plan_episode_review_jobs,
        ) as planner:
            coordinator.advance()

        self.assertEqual(1, planner.call_count)
        self.assertEqual(
            [
                {
                    "decision": "high_impact",
                    "risk_flags": ["high_impact_prompt", "privacy"],
                    "turn_ref": turn_ref,
                }
            ],
            planner.call_args.kwargs["screening_results"],
        )
        plan = next(iter(coordinator.load_state()["review_plans"].values()))
        self.assertIsNone(plan["blocked_reason"])
        self.assertEqual([], plan["high_impact_screen_gap_turn_refs"])
        self.assertIn("high_impact_screen", plan["second_review_reason_codes"])

    def test_primary_review_gap_retries_then_blocks_without_resolution(self) -> None:
        coordinator = self.activity_run("primary-review-gap")
        extractor = coordinator.status()["runnable_jobs"][0]
        coordinator.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            self.extractor_result(extractor),
        )
        coordinator.advance()
        jobs = {job["job_kind"]: job for job in coordinator.status()["runnable_jobs"]}
        primary = jobs[JobKind.EPISODE_REVIEWER.value]
        secondary = jobs[JobKind.INDEPENDENT_RISK_REVIEWER.value]
        coordinator.accept_agent_result(
            secondary["job_ref"],
            secondary["active_attempt_ref"],
            self.review_result(secondary, secondary=True),
        )
        first_gap = coordinator.accept_agent_result(
            primary["job_ref"],
            primary["active_attempt_ref"],
            self.review_gap_result(primary),
        )
        self.assertEqual("retryable", first_gap["outcome"])
        self.assertEqual("primary_review_gap", first_gap["reason"])

        coordinator.advance()
        retry = coordinator.status()["runnable_jobs"][0]
        self.assertEqual(JobKind.EPISODE_REVIEWER.value, retry["job_kind"])
        self.assertNotEqual(primary["job_ref"], retry["job_ref"])
        self.assertNotEqual(primary["reviewer_ref"], retry["reviewer_ref"])
        second_gap = coordinator.accept_agent_result(
            retry["job_ref"],
            retry["active_attempt_ref"],
            self.review_gap_result(retry),
        )
        self.assertEqual("gap", second_gap["outcome"])
        coordinator.advance()

        status = coordinator.status()
        state = coordinator.store.load()
        plan = next(iter(state["review_plans"].values()))
        self.assertEqual(RunStage.BLOCKED.value, status["stage"])
        self.assertEqual("primary_review_gap", status["blocked_reason"])
        self.assertFalse(plan["primary_review_completed"])
        self.assertTrue(plan["secondary_review_completed"])
        self.assertEqual("primary_review_gap", plan["blocked_reason"])
        self.assertEqual({}, state["resolved_reviews"])
        self.assertEqual({}, state["topic_inputs"])
        self.assertEqual("primary", status["gaps"][0]["typed_gap"]["reviewer_slot"])

    def test_secondary_review_gap_retries_then_blocks_without_resolution(self) -> None:
        coordinator = self.activity_run("secondary-review-gap")
        extractor = coordinator.status()["runnable_jobs"][0]
        coordinator.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            self.extractor_result(extractor),
        )
        coordinator.advance()
        jobs = {job["job_kind"]: job for job in coordinator.status()["runnable_jobs"]}
        primary = jobs[JobKind.EPISODE_REVIEWER.value]
        secondary = jobs[JobKind.INDEPENDENT_RISK_REVIEWER.value]
        coordinator.accept_agent_result(
            primary["job_ref"],
            primary["active_attempt_ref"],
            self.review_result(primary, secondary=False),
        )
        first_gap = coordinator.accept_agent_result(
            secondary["job_ref"],
            secondary["active_attempt_ref"],
            self.review_gap_result(secondary),
        )
        self.assertEqual("retryable", first_gap["outcome"])
        self.assertEqual("secondary_review_gap", first_gap["reason"])

        coordinator.advance()
        retry = coordinator.status()["runnable_jobs"][0]
        self.assertEqual(
            JobKind.INDEPENDENT_RISK_REVIEWER.value,
            retry["job_kind"],
        )
        self.assertNotEqual(secondary["job_ref"], retry["job_ref"])
        self.assertNotEqual(secondary["reviewer_ref"], retry["reviewer_ref"])
        coordinator.accept_agent_result(
            retry["job_ref"],
            retry["active_attempt_ref"],
            self.review_gap_result(retry),
        )
        coordinator.advance()

        status = coordinator.status()
        state = coordinator.store.load()
        plan = next(iter(state["review_plans"].values()))
        self.assertEqual(RunStage.BLOCKED.value, status["stage"])
        self.assertEqual("secondary_review_gap", status["blocked_reason"])
        self.assertTrue(plan["primary_review_completed"])
        self.assertFalse(plan["secondary_review_completed"])
        self.assertEqual("secondary_review_gap", plan["blocked_reason"])
        self.assertEqual({}, state["resolved_reviews"])
        self.assertEqual({}, state["topic_inputs"])
        self.assertEqual("secondary", status["gaps"][0]["typed_gap"]["reviewer_slot"])

    def test_high_risk_second_review_hash_adjudication_and_synthesis(self) -> None:
        coordinator = self.activity_run("adjudication")
        extractor = coordinator.status()["runnable_jobs"][0]
        coordinator.accept_agent_result(
            extractor["job_ref"],
            extractor["active_attempt_ref"],
            self.extractor_result(extractor),
        )
        coordinator.advance()
        review_jobs = coordinator.status()["runnable_jobs"]
        self.assertEqual(
            {JobKind.EPISODE_REVIEWER.value, JobKind.INDEPENDENT_RISK_REVIEWER.value},
            {job["job_kind"] for job in review_jobs},
        )
        review_results: dict[str, dict[str, object]] = {}
        for job in review_jobs:
            secondary = job["job_kind"] == JobKind.INDEPENDENT_RISK_REVIEWER.value
            result = self.review_result(job, secondary=secondary)
            result["findings"] = [
                {
                    "kind": "production_risk",
                    "evidence_refs": list(result["evidence_refs"]),
                    "confidence": "low" if secondary else "high",
                    "severity": "high" if secondary else "low",
                }
            ]
            if secondary:
                result["confidence"] = "low"
            review_results[result["reviewer_slot"]] = result
            coordinator.accept_agent_result(
                job["job_ref"], job["active_attempt_ref"], result
            )
        coordinator.advance()
        adjudicator = coordinator.status()["runnable_jobs"][0]
        self.assertEqual(JobKind.ADJUDICATOR.value, adjudicator["job_kind"])
        adjudicator_envelope = self.agent_envelope(coordinator, adjudicator)
        primary = review_results["primary"]
        rejected_primary_only = {
            "schema": result_validation.ADJUDICATION_RESULT_SCHEMA,
            "episode_ref": primary["episode_ref"],
            "episode_revision_ref": primary["episode_revision_ref"],
            "resolution": "primary_supported",
            "events": primary["events"],
            "findings": primary["findings"],
            "strengths": primary["strengths"],
            "risk_flags": primary["risk_flags"],
            "high_impact_turns": primary["high_impact_turns"],
            "evidence_refs": primary["evidence_refs"],
            "confidence": primary["confidence"],
            "candidate_result_hashes": adjudicator_envelope["job_manifest"][
                "candidate_result_hashes"
            ],
        }
        candidates = [review_results["primary"], review_results["secondary"]]
        rejected_primary_only["candidate_item_decisions"] = adjudication_item_decisions(
            candidates, rejected_primary_only
        )
        with self.assertRaisesRegex(
            result_validation.ResultValidationError,
            "dropped a high-severity independent-review decision",
        ):
            result_validation.validate_adjudication_result(
                rejected_primary_only,
                adjudicator["allowed_output_refs"],
                candidate_results=candidates,
            )
        secondary = review_results["secondary"]
        adjudication = {
            **rejected_primary_only,
            "resolution": "merged_supported",
            "findings": secondary["findings"],
            "risk_flags": sorted(
                set(primary["risk_flags"]) | set(secondary["risk_flags"])
            ),
            "high_impact_turns": secondary["high_impact_turns"],
            "confidence": "low",
        }
        adjudication["candidate_item_decisions"] = adjudication_item_decisions(
            candidates, adjudication
        )
        coordinator.accept_agent_result(
            adjudicator["job_ref"],
            adjudicator["active_attempt_ref"],
            adjudication,
        )
        coordinator.advance()
        reducer = coordinator.status()["runnable_jobs"][0]
        self.assertEqual(JobKind.TOPIC_REDUCER.value, reducer["job_kind"])
        self.assertEqual(
            "high",
            reducer["input_payload"]["episode_reviews"][0]["findings"][0]["severity"],
        )
        coordinator.accept_agent_result(
            reducer["job_ref"],
            reducer["active_attempt_ref"],
            result_validation.build_topic_result(
                reducer["input_payload"],
                topic_ref=next(
                    ref
                    for ref in reducer["allowed_output_refs"]
                    if ref.startswith("topic_ref_v2:")
                ),
            ),
        )
        coordinator.advance()
        synthesis = coordinator.status()["runnable_jobs"][0]
        self.assertEqual(JobKind.GLOBAL_SYNTHESIS.value, synthesis["job_kind"])
        secondary_hash = result_validation.canonical_result_hash(
            review_results["secondary"]
        )
        synthesis_envelope = self.agent_envelope(coordinator, synthesis)
        self.assertEqual(
            "high",
            synthesis["input_payload"]["independent_reviews"][0]["findings"][0][
                "severity"
            ],
        )
        self.assertEqual(
            [secondary_hash],
            synthesis_envelope["job_manifest"]["safety_review_hashes"],
        )
        mismatched = coordinator.accept_agent_result(
            synthesis["job_ref"],
            synthesis["active_attempt_ref"],
            synthesis_result(),
        )
        self.assertEqual("retryable", mismatched["outcome"])
        self.assertEqual("schema_violation", mismatched["reason"])
        coordinator.advance()
        synthesis_retry = coordinator.status()["runnable_jobs"][0]
        self.assertEqual(JobKind.GLOBAL_SYNTHESIS.value, synthesis_retry["job_kind"])
        self.assertNotEqual(synthesis["job_ref"], synthesis_retry["job_ref"])
        synthesis_payload = synthesis_result()
        synthesis_payload["topic_result_hashes"] = synthesis_retry["input_payload"][
            "topic_result_hashes"
        ]
        synthesis_payload["signal_commitments"] = synthesis_retry["input_payload"][
            "signal_commitments"
        ]
        synthesis_payload["events"] = [
            {
                "confidence": item["confidence"],
                "evidence_refs": list(item["evidence_refs"]),
                "kind": item["kind"],
            }
            for item in primary["events"]
        ]
        synthesis_payload["findings"] = [
            {
                "confidence": "low",
                "evidence_refs": list(secondary["findings"][0]["evidence_refs"]),
                "kind": "production_risk",
                "severity": "high",
            }
        ]
        episode_ref = primary["episode_ref"]
        high_impact = secondary["high_impact_turns"][0]
        synthesis_payload["prompt_rewrites"] = [
            {
                **copy.deepcopy(high_impact),
                "evidence_refs": [episode_ref],
            }
        ]
        synthesis_payload["strengths"] = [
            {
                "confidence": item["confidence"],
                "evidence_refs": list(item["evidence_refs"]),
                "kind": item["kind"],
            }
            for item in primary["strengths"]
        ]
        synthesis_payload.update(
            result_validation.build_synthesis_signal_exemplars(
                synthesis_retry["input_payload"]["topic_results"]
            )
        )
        synthesis_payload["evidence_refs"] = [episode_ref]
        accepted = coordinator.accept_agent_result(
            synthesis_retry["job_ref"],
            synthesis_retry["active_attempt_ref"],
            synthesis_payload,
        )
        self.assertEqual("accepted", accepted["outcome"], accepted)
        propagated = coordinator.store.load()
        resolved_review = next(iter(propagated["resolved_reviews"].values()))
        topic_result = next(
            task["result"]
            for task in propagated["jobs"].values()
            if task.get("job_kind") == JobKind.TOPIC_REDUCER.value
            and task.get("status") == "accepted"
            and task.get("metadata", {}).get("hierarchy_final") is True
        )
        self.assertEqual("high", resolved_review["findings"][0]["severity"])
        self.assertEqual("high", topic_result["findings"][0]["severity"])
        self.assertEqual("high", synthesis_payload["findings"][0]["severity"])
        coordinator.advance()
        self.assertEqual(RunStage.EXPORT.value, coordinator.status()["stage"])
        run_state, review_data = coordinator.retained_export_inputs()
        self.assertEqual("high", review_data["synthesis"]["findings"][0]["severity"])
        self.assertEqual([coordinator.UNKNOWN_MODEL_ERA], run_state["model_eras"])
        self.assertNotEqual(
            run_state["default_model_era"],
            run_state["model_eras"][0],
        )
        for row in [
            *review_data["episodes"],
            *review_data["topics"],
            *review_data["turn_findings"],
        ]:
            self.assertIn(row["model_era"], run_state["model_eras"])
            self.assertIn(row["policy_era"], run_state["policy_eras"])
        artifacts = reporting.assemble_retained_artifacts(run_state, review_data)
        self.assertEqual(reporting.RETAINED_ARTIFACT_NAMES, tuple(artifacts))

    def test_retained_export_inputs_do_not_expand_the_checkpoint_envelope(self) -> None:
        coordinator = self.start_daily("retained-export-sidecar")
        state = coordinator.store.load()
        run_state = {
            "mode": state["mode"],
            "run_ref": state["run_ref"],
            "window": copy.deepcopy(state["window"]),
        }
        review_data = {
            "episodes": [
                {"summary": "x" * 4096, "turn_ref": f"turn-{index}"}
                for index in range(512)
            ]
        }
        descriptor = coordinator._persist_retained_export_inputs(
            run_state,
            review_data,
        )
        with mock.patch.object(
            retained_inputs.safe_io,
            "read_bounded_bytes",
            wraps=retained_inputs.safe_io.read_bounded_bytes,
        ) as replay_read:
            self.assertEqual(
                descriptor,
                coordinator._persist_retained_export_inputs(run_state, review_data),
            )
        self.assertEqual(
            descriptor["byte_count"],
            replay_read.call_args.kwargs["max_bytes"],
        )
        self.assertIn(
            Path(descriptor["relative_path"]).parts[0],
            orchestrator_module.SHADOW_CLEANUP_ROOTS,
        )
        embedded_state = copy.deepcopy(state)
        embedded_state["retained_export"] = {
            "review_data": review_data,
            "run_state": run_state,
        }
        self.assertEqual(
            (run_state, review_data),
            retained_inputs.load(coordinator.run_dir, embedded_state),
        )
        descriptor_state = copy.deepcopy(state)
        descriptor_state["retained_export"] = descriptor
        checkpoint_limit = len(contracts.canonical_json_bytes(state)) + 128 * 1024
        self.assertGreater(
            len(contracts.canonical_json_bytes(embedded_state)),
            checkpoint_limit,
        )
        self.assertLess(
            len(contracts.canonical_json_bytes(descriptor_state)),
            checkpoint_limit,
        )

        snapshot = coordinator.store.read()
        coordinator.store.max_bytes = checkpoint_limit
        coordinator.store.save(
            descriptor_state,
            expected_revision=snapshot.revision,
        )
        with mock.patch.object(
            retained_inputs.safe_io,
            "read_bounded_bytes",
            wraps=retained_inputs.safe_io.read_bounded_bytes,
        ) as bounded_read:
            loaded_run_state, loaded_review_data = coordinator.retained_export_inputs()
        self.assertEqual(run_state, loaded_run_state)
        self.assertEqual(review_data, loaded_review_data)
        self.assertEqual(
            descriptor["byte_count"], bounded_read.call_args.kwargs["max_bytes"]
        )
        sidecar = coordinator.run_dir / descriptor["relative_path"]
        self.assertEqual(0o600, sidecar.stat().st_mode & 0o777)

        hardlink = sidecar.with_name(f"{sidecar.name}.hardlink")
        os.link(sidecar, hardlink)
        with self.assertRaisesRegex(
            InvalidTransitionError,
            "cannot be authenticated",
        ):
            coordinator.retained_export_inputs()
        hardlink.unlink()
        self.assertEqual(
            (run_state, review_data),
            coordinator.retained_export_inputs(),
        )

        original = sidecar.read_bytes()
        sidecar.write_bytes(original[:-1] + bytes((original[-1] ^ 1,)))
        with self.assertRaisesRegex(
            InvalidTransitionError,
            "sidecar changed",
        ):
            coordinator.retained_export_inputs()

    def test_key_mismatch_partial_backfill_and_retention(self) -> None:
        coordinator = self.start_daily("identity")
        old_identity = self.identity_path.with_suffix(".old")
        self.identity_path.rename(old_identity)
        IdentityKey.create(self.identity_path)
        with self.assertRaises(IdentityKeyMismatchError):
            RetrospectiveOrchestrator(
                coordinator.run_dir,
                identity_path=self.identity_path,
            )
        self.identity_path.unlink()
        old_identity.rename(self.identity_path)

        partial = self.start_daily(
            "partial",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
            shadow=True,
        )
        holdout = partial.holdout_host(
            REMOTE_HOST,
            reason="shadow_missing_host_holdout",
        )
        successor = self.complete_shadow_partial(partial)
        partial_status = partial.status()
        self.assertEqual("partial", partial_status["coverage"]["status"])
        self.assertEqual(
            "backfill_required",
            partial_status["cursors"][REMOTE_HOST]["publication_state"],
        )
        backfill = self.start_daily(
            "backfill",
            hosts=(REMOTE_HOST,),
            backfill_of=partial_status["run_ref"],
            controlled_gap_receipt=holdout["controlled_gap_receipt"],
            shadow_successor=successor,
            shadow=True,
            durable_history=self.durable_backlog_history(
                partial_status,
                host=REMOTE_HOST,
            ),
        )
        self.drain_sources(backfill)
        backfill.advance()
        self.assertEqual(
            partial_status["run_ref"], backfill.status()["lineage"]["backfill_of"]
        )

        exported = self.start_daily("retention")
        self.drain_sources(exported)
        exported.advance()
        exported.mark_exported("a" * 64)
        self.clock.value += dt.timedelta(days=8)
        with self.assertRaisesRegex(Exception, "retention"):
            exported.ensure_retention_active()
        aborted = exported.mark_finalized("aborted")
        self.assertEqual("aborted", aborted["publication"]["phase"])

    def test_expired_retention_rejects_source_acceptance_before_mutation(self) -> None:
        coordinator = self.start_daily("expired-source-acceptance")
        coordinator.advance()
        lease = coordinator.status()["active_source_leases"][0]
        manifest = no_activity_manifest(lease)
        receipt = authenticated_receipt(coordinator, lease, manifest)
        self.clock.value += dt.timedelta(days=8)

        with self.assertRaisesRegex(InvalidTransitionError, "retention"):
            coordinator.accept_source(
                lease["lease_ref"],
                manifest.to_dict(),
                transport_receipt=receipt,
            )

        unchanged = coordinator.load_state()
        self.assertEqual(RunStage.SOURCE_CATALOG.value, unchanged["stage"])
        source_job = next(
            job
            for job in unchanged["jobs"].values()
            if job.get("lease_ref") == lease["lease_ref"]
        )
        self.assertEqual("runnable", source_job["status"])
        cleaned = coordinator.status()
        self.assertEqual(RunStage.BLOCKED.value, cleaned["stage"])
        self.assertEqual("raw_retention_expired", cleaned["blocked_reason"])

    def test_stale_status_projection_cannot_recreate_expired_source_output(
        self,
    ) -> None:
        coordinator = self.start_daily("stale-source-output-projection")
        coordinator.advance()
        stale_snapshot = coordinator.store.read()
        source_job = next(
            job
            for job in stale_snapshot.state["jobs"].values()
            if job.get("category") == "source" and job.get("status") == "runnable"
        )
        output_path = (
            coordinator.run_dir / source_job["source_transport_output_relative"]
        )
        self.assertTrue(output_path.parent.is_dir())

        self.clock.value += dt.timedelta(days=8)
        cleaned = coordinator.gc_expired_raw()

        self.assertTrue(cleaned["cleaned"])
        self.assertFalse((coordinator.run_dir / "raw-inputs").exists())
        with self.assertRaisesRegex(
            InvalidTransitionError,
            "output directory cannot be authenticated",
        ):
            coordinator._status_view(stale_snapshot)
        self.assertFalse((coordinator.run_dir / "raw-inputs").exists())
        self.assertTrue(coordinator.gc_expired_raw()["idempotent"])

    def test_expired_raw_gc_is_retryable_and_prunes_source_inventory(self) -> None:
        coordinator = self.start_daily("expired-raw-gc")
        coordinator.advance()
        lease = coordinator.status()["active_source_leases"][0]
        manifest = no_activity_manifest(lease)
        coordinator.accept_source(
            lease["lease_ref"],
            manifest.to_dict(),
            transport_receipt=authenticated_receipt(coordinator, lease, manifest),
        )

        outside = self.root / "expired-outside"
        outside.mkdir(mode=0o700)
        marker = outside / "marker.bin"
        marker.write_bytes(b"must survive")
        os.chmod(marker, 0o600)
        raw_root = coordinator.run_dir / "raw-inputs"
        _run_path, run_fd = safe_io.open_owner_only_directory(coordinator.run_dir)
        try:
            safe_io.secure_remove_tree_at(
                run_fd,
                "raw-inputs",
                display_path=raw_root,
            )
        finally:
            os.close(run_fd)
        raw_root.symlink_to(outside, target_is_directory=True)
        self.clock.value += dt.timedelta(days=8)

        failed = coordinator.gc_expired_raw()
        self.assertTrue(failed["eligible"])
        self.assertFalse(failed["cleaned"])
        self.assertEqual(b"must survive", marker.read_bytes())
        self.assertEqual("created", coordinator.load_state()["publication"]["phase"])

        raw_root.unlink()
        real_transaction = coordinator.store.transaction
        response_lost = False

        def lose_expired_cleanup_response(*args, **kwargs):
            nonlocal response_lost
            result = real_transaction(*args, **kwargs)
            if (
                result.snapshot.state["publication"].get("phase")
                == "expired_cleanup_complete"
                and not response_lost
            ):
                response_lost = True
                raise RuntimeError("lost expired cleanup response")
            return result

        with mock.patch.object(
            coordinator.store,
            "transaction",
            side_effect=lose_expired_cleanup_response,
        ):
            with self.assertRaisesRegex(RuntimeError, "lost expired cleanup response"):
                coordinator.gc_expired_raw()
        state = coordinator.load_state()
        cleanup_claim = state["publication"]["expired_cleanup_claim"]
        cleanup_receipt = state["publication"]["cleanup_receipt"]
        self.assertEqual(
            cleanup_claim["claim_ref"], cleanup_receipt["cleanup_claim_ref"]
        )
        self.assertEqual(
            cleanup_claim["removed_file_count"],
            cleanup_receipt["removed_file_count"],
        )
        self.assertEqual(RunStage.BLOCKED.value, state["stage"])
        self.assertEqual("raw_retention_expired", state["blocked_reason"])
        self.assertEqual({}, state["actions"])
        self.assertEqual({}, state["jobs"])
        self.assertIsNone(state["source"]["catalog"])
        for cells in state["source"]["cells"].values():
            for cell in cells.values():
                self.assertIsNone(cell["manifest"])
                self.assertIsNone(cell["snapshot_ref"])
                self.assertEqual({}, cell["payloads"])
        self.assertEqual(b"must survive", marker.read_bytes())
        replay = coordinator.gc_expired_raw()
        self.assertTrue(replay["cleaned"])
        self.assertTrue(replay["idempotent"])
        self.assertEqual(
            cleanup_receipt,
            coordinator.load_state()["publication"]["cleanup_receipt"],
        )

        def attach_legacy_terminal_payload(current):
            current["retained_export"] = {
                "review_data": {"legacy": "expired-terminal"},
                "run_state": {"legacy": "expired-terminal"},
            }
            return current, None

        coordinator.store.transaction(attach_legacy_terminal_payload)
        self.assertTrue(coordinator.gc_expired_raw()["idempotent"])
        self.assertIsNone(coordinator.load_state()["retained_export"])

    def test_expired_raw_gc_removes_retained_export_input_sidecar(self) -> None:
        coordinator = self.start_daily("expired-retained-input-sidecar")
        state = coordinator.load_state()
        run_state = {
            "mode": state["mode"],
            "run_ref": state["run_ref"],
            "window": copy.deepcopy(state["window"]),
        }
        descriptor = coordinator._persist_retained_export_inputs(
            run_state,
            {"episodes": []},
        )

        def attach(current):
            current["retained_export"] = copy.deepcopy(descriptor)
            return current, None

        coordinator.store.transaction(attach)
        sidecar_root = (
            coordinator.run_dir / retained_inputs.RETAINED_EXPORT_INPUT_DIRECTORY
        )
        self.assertTrue(sidecar_root.is_dir())
        self.clock.value += dt.timedelta(days=8)

        cleaned = coordinator.gc_expired_raw()

        self.assertTrue(cleaned["cleaned"])
        self.assertFalse(sidecar_root.exists())
        self.assertIsNone(coordinator.load_state()["retained_export"])

    def test_cleanup_v2_replay_and_v5_generation_are_schema_scoped(self) -> None:
        coordinator = self.start_daily("legacy-cleanup-replay")
        state = coordinator.load_state()
        legacy_roots = LEGACY_SHADOW_CLEANUP_ROOTS
        legacy_inventory = coordinator._raw_cleanup_inventory(legacy_roots)
        legacy_claim = coordinator._raw_cleanup_claim_value(
            state,
            disposition="expired",
            durable_commit=None,
            phase_before=state["publication"]["phase"],
            publication_claim_ref=None,
            inventory=legacy_inventory,
            schema="raw_cleanup_claim_v2",
        )
        self.assertEqual(
            legacy_claim,
            coordinator._validate_raw_cleanup_claim(
                state,
                legacy_claim,
                disposition="expired",
                durable_commit=None,
                phase_before=state["publication"]["phase"],
                publication_claim_ref=None,
            ),
        )
        legacy_receipt = coordinator._raw_cleanup_receipt_value(legacy_claim)
        coordinator._delete_claimed_raw_paths(legacy_claim)
        replay_state = copy.deepcopy(state)
        replay_state["publication"]["expired_cleanup_claim"] = legacy_claim
        replay_state["publication"]["cleanup_receipt"] = legacy_receipt
        self.assertEqual(
            legacy_receipt,
            coordinator._validate_completed_raw_cleanup(
                replay_state,
                disposition="expired",
            ),
        )

        current = self.start_daily("current-cleanup-generation")
        current_state = current.load_state()
        current_claim = current._raw_cleanup_claim_value(
            current_state,
            disposition="expired",
            durable_commit=None,
            phase_before=current_state["publication"]["phase"],
            publication_claim_ref=None,
            inventory=current._raw_cleanup_inventory(),
        )
        self.assertEqual("raw_cleanup_claim_v5", current_claim["schema"])
        self.assertNotIn("root_entries", current_claim)
        self.assertEqual(
            cleanup_sidecars.CLEANUP_INVENTORY_DESCRIPTOR_SCHEMA,
            current_claim["inventory_descriptor"]["schema"],
        )
        sidecar = (
            current.run_dir / current_claim["inventory_descriptor"]["relative_path"]
        )
        self.assertTrue(sidecar.is_file())
        self.assertEqual(0o600, stat.S_IMODE(sidecar.stat().st_mode))
        loaded_entries = cleanup_sidecars.load(
            current.run_dir,
            orchestrator_module.SHADOW_CLEANUP_ROOTS,
            current_claim["inventory_descriptor"],
        )
        self.assertEqual(
            set(orchestrator_module.SHADOW_CLEANUP_ROOTS), set(loaded_entries)
        )
        self.assertEqual(
            list(orchestrator_module.SHADOW_CLEANUP_ROOTS),
            current_claim["raw_path_inventory"],
        )
        self.assertEqual(
            "raw_cleanup_receipt_v5",
            current._raw_cleanup_receipt_value(current_claim)["schema"],
        )
        maximal_descriptor = copy.deepcopy(current_claim["inventory_descriptor"])
        maximal_descriptor.update(
            {
                "byte_count": cleanup_sidecars.MAX_CLEANUP_INVENTORY_BYTES,
                "entry_count": cleanup_sidecars.MAX_CLEANUP_INVENTORY_ENTRIES,
                "path_byte_count": cleanup_sidecars.MAX_CLEANUP_INVENTORY_PATH_BYTES,
            }
        )
        bounded_claim = copy.deepcopy(current_claim)
        bounded_claim["inventory_descriptor"] = maximal_descriptor
        self.assertLess(len(canonical_json_bytes(bounded_claim)), 16 * 1024)
        bounded_state = copy.deepcopy(current_state)
        bounded_state["publication"]["expired_cleanup_claim"] = bounded_claim
        self.assertLess(
            len(canonical_json_bytes(bounded_state)),
            DEFAULT_MAX_CHECKPOINT_BYTES,
        )
        cross_schema = copy.deepcopy(legacy_claim)
        cross_schema["schema"] = "raw_cleanup_claim_v5"
        with self.assertRaisesRegex(
            InvalidTransitionError,
            "shape|inventory|authentication",
        ):
            current._validate_raw_cleanup_claim(
                current_state,
                cross_schema,
                disposition="expired",
                durable_commit=None,
                phase_before=current_state["publication"]["phase"],
                publication_claim_ref=None,
            )
        v4_claim = current._raw_cleanup_claim_value(
            current_state,
            disposition="expired",
            durable_commit=None,
            phase_before=current_state["publication"]["phase"],
            publication_claim_ref=None,
            inventory=current._raw_cleanup_inventory(),
            schema="raw_cleanup_claim_v4",
        )
        malformed_mode = copy.deepcopy(v4_claim)
        malformed_mode["root_entries"]["raw-inputs"][0]["mode"] = "0700"
        with self.assertRaisesRegex(InvalidTransitionError, "cleanup inventory"):
            current._validate_raw_cleanup_claim(
                current_state,
                malformed_mode,
                disposition="expired",
                durable_commit=None,
                phase_before=current_state["publication"]["phase"],
                publication_claim_ref=None,
            )

    def test_completed_shadow_cleanup_v2_replays_without_cross_schema_adoption(
        self,
    ) -> None:
        coordinator = self.start_daily(
            "legacy-shadow-cleanup-replay",
            hosts=DEFAULT_HOSTS,
            allow_partial=True,
            shadow=True,
        )
        coordinator.holdout_host(
            REMOTE_HOST,
            reason="shadow_missing_host_holdout",
        )
        self.complete_shadow_partial(coordinator)
        state = coordinator.load_state()
        coverage = coordinator._verified_persisted_shadow_coverage(state)
        legacy_roots = LEGACY_SHADOW_CLEANUP_ROOTS
        legacy_claim = coordinator._shadow_cleanup_claim_value(
            state,
            coverage,
            coordinator._raw_cleanup_inventory(legacy_roots),
            schema="shadow_cleanup_claim_v2",
        )
        current_cleanup = state["publication"]["cleanup_receipt"]
        payload = {
            key: copy.deepcopy(value)
            for key, value in current_cleanup.items()
            if key not in {"authentication_tag", "receipt_ref", "schema"}
        }
        payload["cleanup_claim_ref"] = legacy_claim["claim_ref"]
        payload["raw_path_inventory"] = list(legacy_roots)
        for field in (
            "removed_byte_count",
            "removed_directory_count",
            "removed_file_count",
        ):
            payload[field] = legacy_claim[field]
        legacy_receipt = coordinator._authenticated_run_receipt(
            schema="raw_cleanup_receipt_v2",
            ref_domain="raw_cleanup_receipt_v2",
            auth_domain="raw_cleanup_auth_v2",
            payload=payload,
        )
        replay_state = copy.deepcopy(state)
        replay_state["publication"]["cleanup_claim"] = legacy_claim
        replay_state["publication"]["cleanup_receipt"] = legacy_receipt

        self.assertEqual(
            legacy_receipt,
            coordinator._validate_completed_shadow_cleanup(replay_state),
        )
        cross_schema = copy.deepcopy(legacy_receipt)
        cross_schema["schema"] = "raw_cleanup_receipt_v4"
        with self.assertRaises(authority.ProductionMarkerError):
            authority.verify_shadow_cleanup_receipt(
                coordinator.identity,
                cross_schema,
            )

    def test_expired_raw_gc_cannot_overwrite_interleaved_finalize(self) -> None:
        coordinator = self.start_daily("expired-finalize-race")
        self.drain_sources(coordinator)
        coordinator.advance()
        coordinator.mark_exported("e" * 64)
        self.clock.value += dt.timedelta(days=8)
        original_delete = coordinator._delete_claimed_raw_paths
        interleaved = False

        def delete_with_finalize(cleanup_claim):
            nonlocal interleaved
            original_delete(cleanup_claim)
            if interleaved:
                return
            interleaved = True
            snapshot = coordinator.store.read()
            attempt_ref = "attempt_ref_v2:" + "7" * 64
            plan_digest = "8" * 64
            claim_revision = snapshot.revision + 1

            def take_over(state):
                publication = state["publication"]
                publication["phase"] = cleanup_claim["phase_before"]
                publication.pop("expired_cleanup_claim", None)
                publication["publication_claim"] = coordinator._publication_claim_value(
                    state,
                    attempt_ref=attempt_ref,
                    checkpoint_revision=claim_revision,
                    plan_digest=plan_digest,
                )
                return state, None

            coordinator.store.transaction(
                take_over,
                expected_revision=snapshot.revision,
            )
            coordinator.mark_finalized(
                "committed",
                attempt_ref=attempt_ref,
                claim_revision=claim_revision,
                plan_digest=plan_digest,
            )

        with (
            mock.patch.object(
                coordinator,
                "_validate_published_authority",
                return_value=self.published_history(coordinator),
            ),
            mock.patch.object(
                coordinator,
                "_delete_claimed_raw_paths",
                side_effect=delete_with_finalize,
            ),
        ):
            result = coordinator.gc_expired_raw()

        state = coordinator.load_state()
        self.assertTrue(result["superseded"])
        self.assertTrue(result["published"])
        self.assertFalse(result["cleaned"])
        self.assertEqual(RunStage.COMPLETE.value, state["stage"])
        self.assertEqual("complete", state["publication"]["phase"])
        self.assertEqual(
            "published",
            state["publication"]["cleanup_receipt"]["disposition"],
        )

    def test_expired_cleanup_claim_rejects_replaced_root_after_checkpoint(
        self,
    ) -> None:
        coordinator = self.start_daily("expired-cleanup-replacement")
        raw_root = coordinator.run_dir / "raw-inputs"
        payload = raw_root / "retained.bin"
        payload.write_bytes(b"retained before cleanup claim")
        os.chmod(payload, 0o600)
        self.clock.value += dt.timedelta(days=8)
        original_delete = coordinator._delete_claimed_raw_paths
        replaced = False

        def replace_after_claim(cleanup_claim):
            nonlocal replaced
            if not replaced:
                replaced = True
                os.replace(raw_root, coordinator.run_dir / "claimed-raw-inputs")
                raw_root.mkdir(mode=0o700)
            original_delete(cleanup_claim)

        with mock.patch.object(
            coordinator,
            "_delete_claimed_raw_paths",
            side_effect=replace_after_claim,
        ):
            result = coordinator.gc_expired_raw()

        state = coordinator.load_state()
        claim = state["publication"]["expired_cleanup_claim"]
        self.assertTrue(replaced)
        self.assertFalse(result["cleaned"])
        self.assertEqual("UnsafePathError", result["cleanup_error"])
        self.assertEqual("expired_cleanup_claimed", state["publication"]["phase"])
        self.assertIsNone(state["publication"]["cleanup_receipt"])
        self.assertGreater(claim["removed_file_count"], 0)
        self.assertTrue(raw_root.is_dir())

    def test_expired_cleanup_claim_rejects_same_size_child_replacement(
        self,
    ) -> None:
        coordinator = self.start_daily("expired-cleanup-child-replacement")
        raw_root = coordinator.run_dir / "raw-inputs"
        payload = raw_root / "retained.bin"
        original = b"retained before exact cleanup claim"
        payload.write_bytes(original)
        os.chmod(payload, 0o600)
        original_inode = payload.stat().st_ino
        self.clock.value += dt.timedelta(days=8)
        original_delete = coordinator._delete_claimed_raw_paths

        def replace_after_claim(cleanup_claim):
            replacement = raw_root / "replacement.tmp"
            replacement.write_bytes(b"x" * len(original))
            os.chmod(replacement, 0o600)
            os.replace(replacement, payload)
            original_delete(cleanup_claim)

        with mock.patch.object(
            coordinator,
            "_delete_claimed_raw_paths",
            side_effect=replace_after_claim,
        ):
            result = coordinator.gc_expired_raw()

        state = coordinator.load_state()
        claim = state["publication"]["expired_cleanup_claim"]
        self.assertEqual("raw_cleanup_claim_v5", claim["schema"])
        self.assertFalse(result["cleaned"])
        self.assertEqual("UnsafePathError", result["cleanup_error"])
        self.assertNotEqual(original_inode, payload.stat().st_ino)
        self.assertEqual(b"x" * len(original), payload.read_bytes())

    def test_expired_cleanup_claim_rejects_child_shrink_removal_or_policy_change(
        self,
    ) -> None:
        initial_clock = self.clock.value
        for operation in ("shrink", "remove", "mode"):
            with self.subTest(operation=operation):
                self.clock.value = initial_clock
                coordinator = self.start_daily(f"expired-cleanup-child-{operation}")
                raw_root = coordinator.run_dir / "raw-inputs"
                payload = raw_root / "retained.bin"
                sibling = raw_root / "sibling.bin"
                payload.write_bytes(b"retained before exact cleanup claim")
                sibling.write_bytes(b"must survive failed cleanup")
                os.chmod(payload, 0o600)
                os.chmod(sibling, 0o600)
                self.clock.value += dt.timedelta(days=8)
                original_delete = coordinator._delete_claimed_raw_paths

                def mutate_after_claim(cleanup_claim):
                    if operation == "shrink":
                        payload.write_bytes(b"x")
                    elif operation == "remove":
                        payload.unlink()
                    else:
                        os.chmod(payload, 0o644)
                    original_delete(cleanup_claim)

                with mock.patch.object(
                    coordinator,
                    "_delete_claimed_raw_paths",
                    side_effect=mutate_after_claim,
                ):
                    result = coordinator.gc_expired_raw()

                self.assertFalse(result["cleaned"])
                self.assertEqual("UnsafePathError", result["cleanup_error"])
                self.assertEqual(b"must survive failed cleanup", sibling.read_bytes())

    def test_cleanup_revalidates_every_root_before_deleting_any_root(self) -> None:
        coordinator = self.start_daily("cleanup-complete-second-pass")
        raw_sibling = coordinator.run_dir / "raw-inputs" / "must-survive.bin"
        raw_sibling.write_bytes(b"retained until every root is revalidated")
        os.chmod(raw_sibling, 0o600)
        retained_root = coordinator.run_dir / "retained-inputs"
        retained_root.mkdir(mode=0o700)
        retained_payload = retained_root / "late-change.bin"
        retained_payload.write_bytes(b"claimed retained input")
        os.chmod(retained_payload, 0o600)
        self.clock.value += dt.timedelta(days=8)
        with mock.patch.object(
            coordinator,
            "_delete_claimed_raw_paths",
            side_effect=safe_io.UnsafePathError("hold durable cleanup claim"),
        ):
            claimed = coordinator.gc_expired_raw()
        self.assertFalse(claimed["cleaned"])
        self.assertEqual(
            "expired_cleanup_claimed", coordinator.load_state()["publication"]["phase"]
        )
        real_inspect = cleanup_inventory.safe_io.inspect_tree_inventory_at
        calls = 0

        def mutate_last_root_on_second_pass(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == len(orchestrator_module.SHADOW_CLEANUP_ROOTS) * 2:
                retained_payload.unlink()
            return real_inspect(*args, **kwargs)

        with mock.patch.object(
            cleanup_inventory.safe_io,
            "inspect_tree_inventory_at",
            side_effect=mutate_last_root_on_second_pass,
        ):
            result = coordinator.gc_expired_raw()

        self.assertFalse(result["cleaned"])
        self.assertEqual("UnsafePathError", result["cleanup_error"])
        self.assertEqual(
            b"retained until every root is revalidated",
            raw_sibling.read_bytes(),
        )

    def test_cleanup_inventory_applies_one_budget_across_all_roots(self) -> None:
        coordinator = self.start_daily("cleanup-global-budget")
        roots = ("budget-first", "budget-second")
        for root in roots:
            (coordinator.run_dir / root).mkdir(mode=0o700)
        with (
            mock.patch.object(
                cleanup_sidecars,
                "MAX_CLEANUP_INVENTORY_ENTRIES",
                1,
            ),
            self.assertRaisesRegex(
                safe_io.TreeInventoryLimitExceeded,
                "entry bound",
            ),
        ):
            coordinator._raw_cleanup_inventory(roots)

    def test_run_artifact_capacity_stays_within_cleanup_inventory(self) -> None:
        self.assertLessEqual(
            contracts.MAX_CONSERVATIVE_RUN_CLEANUP_ENTRIES,
            contracts.MAX_CLEANUP_INVENTORY_ENTRIES,
        )

    def test_cleanup_v5_sidecar_tamper_hardlink_and_oversize_fail_closed(
        self,
    ) -> None:
        for operation in ("content", "hardlink", "oversize"):
            with self.subTest(operation=operation):
                coordinator = self.start_daily(f"cleanup-sidecar-{operation}")
                state = coordinator.load_state()
                claim = coordinator._raw_cleanup_claim_value(
                    state,
                    disposition="expired",
                    durable_commit=None,
                    phase_before=state["publication"]["phase"],
                    publication_claim_ref=None,
                    inventory=coordinator._raw_cleanup_inventory(),
                )
                candidate = copy.deepcopy(claim)
                sidecar = (
                    coordinator.run_dir
                    / candidate["inventory_descriptor"]["relative_path"]
                )
                if operation == "content":
                    payload = bytearray(sidecar.read_bytes())
                    payload[-2] = ord(" ") if payload[-2] != ord(" ") else ord("\t")
                    sidecar.write_bytes(payload)
                    os.chmod(sidecar, 0o600)
                elif operation == "hardlink":
                    os.link(sidecar, sidecar.with_suffix(".alias"))
                else:
                    candidate["inventory_descriptor"]["byte_count"] = (
                        cleanup_sidecars.MAX_CLEANUP_INVENTORY_BYTES + 1
                    )
                with self.assertRaisesRegex(
                    InvalidTransitionError,
                    "cleanup inventory",
                ):
                    coordinator._validate_raw_cleanup_claim(
                        state,
                        candidate,
                        disposition="expired",
                        durable_commit=None,
                        phase_before=state["publication"]["phase"],
                        publication_claim_ref=None,
                    )

    def test_cleanup_v5_retries_after_partial_child_deletion(self) -> None:
        coordinator = self.start_daily("cleanup-partial-child-retry")
        payload = coordinator.run_dir / "raw-inputs" / "crash-child.bin"
        payload.write_bytes(b"sensitive raw payload")
        os.chmod(payload, 0o600)
        self.clock.value += dt.timedelta(days=8)
        with mock.patch.object(
            coordinator,
            "_delete_claimed_raw_paths",
            side_effect=safe_io.UnsafePathError("persist claim before cleanup"),
        ):
            self.assertFalse(coordinator.gc_expired_raw()["cleaned"])
        claim = coordinator.load_state()["publication"]["expired_cleanup_claim"]
        real_remove = cleanup_inventory.safe_io.secure_remove_tree_at
        crashed = False

        def remove_one_child_then_crash(parent_fd, name, *, display_path):
            nonlocal crashed
            if not crashed and display_path.name.startswith("root-"):
                root_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=parent_fd,
                )
                try:
                    os.unlink("crash-child.bin", dir_fd=root_fd)
                    os.fsync(root_fd)
                finally:
                    os.close(root_fd)
                crashed = True
                raise OSError("simulated crash after child deletion")
            return real_remove(parent_fd, name, display_path=display_path)

        with mock.patch.object(
            cleanup_inventory.safe_io,
            "secure_remove_tree_at",
            side_effect=remove_one_child_then_crash,
        ):
            interrupted = coordinator.gc_expired_raw()
        self.assertTrue(crashed)
        self.assertFalse(interrupted["cleaned"])
        self.assertEqual("OSError", interrupted["cleanup_error"])
        self.assertEqual("raw_cleanup_claim_v5", claim["schema"])
        self.assertFalse(payload.exists())

        recovered = coordinator.gc_expired_raw()
        self.assertTrue(recovered["cleaned"])
        self.assertFalse((coordinator.run_dir / "raw-inputs").exists())

    def test_cleanup_v5_retries_after_completed_root_deletion(self) -> None:
        coordinator = self.start_daily("cleanup-completed-root-retry")
        payload = coordinator.run_dir / "raw-inputs" / "root-crash.bin"
        payload.write_bytes(b"sensitive raw payload")
        os.chmod(payload, 0o600)
        self.clock.value += dt.timedelta(days=8)
        with mock.patch.object(
            coordinator,
            "_delete_claimed_raw_paths",
            side_effect=safe_io.UnsafePathError("persist claim before cleanup"),
        ):
            self.assertFalse(coordinator.gc_expired_raw()["cleaned"])
        real_remove = cleanup_inventory.safe_io.secure_remove_tree_at
        crashed = False

        def remove_root_then_crash(parent_fd, name, *, display_path):
            nonlocal crashed
            removed = real_remove(parent_fd, name, display_path=display_path)
            if not crashed and display_path.name.startswith("root-"):
                crashed = True
                raise OSError("simulated crash after root deletion")
            return removed

        with mock.patch.object(
            cleanup_inventory.safe_io,
            "secure_remove_tree_at",
            side_effect=remove_root_then_crash,
        ):
            interrupted = coordinator.gc_expired_raw()
        self.assertTrue(crashed)
        self.assertFalse(interrupted["cleaned"])
        self.assertEqual("OSError", interrupted["cleanup_error"])

        recovered = coordinator.gc_expired_raw()
        self.assertTrue(recovered["cleaned"])
        for name in orchestrator_module.SHADOW_CLEANUP_ROOTS:
            self.assertFalse((coordinator.run_dir / name).exists())

    def test_cleanup_v5_rejects_all_roots_missing_without_progress(self) -> None:
        coordinator = self.start_daily("cleanup-unproved-all-missing")
        payload = coordinator.run_dir / "raw-inputs" / "must-survive.bin"
        payload.write_bytes(b"unproved external removal")
        os.chmod(payload, 0o600)
        self.clock.value += dt.timedelta(days=8)
        with mock.patch.object(
            coordinator,
            "_delete_claimed_raw_paths",
            side_effect=safe_io.UnsafePathError("persist claim before cleanup"),
        ):
            self.assertFalse(coordinator.gc_expired_raw()["cleaned"])
        retained_roots = []
        for name in orchestrator_module.SHADOW_CLEANUP_ROOTS:
            original = coordinator.run_dir / name
            if not original.exists():
                continue
            retained = coordinator.run_dir / f"unproved-{name}"
            os.replace(original, retained)
            retained_roots.append(retained)

        rejected = coordinator.gc_expired_raw()

        self.assertFalse(rejected["cleaned"])
        self.assertEqual("UnsafePathError", rejected["cleanup_error"])
        self.assertTrue(all(path.is_dir() for path in retained_roots))
        self.assertEqual(
            b"unproved external removal",
            retained_roots[0].joinpath("must-survive.bin").read_bytes(),
        )

    def test_publication_claim_protects_expired_raw_and_recovers_lost_finalize(
        self,
    ) -> None:
        coordinator = self.start_daily("claimed-publication-recovery")
        self.drain_sources(coordinator)
        coordinator.advance()
        coordinator.mark_exported("f" * 64)
        attempt_ref = "attempt_ref_v2:" + "1" * 64
        plan_digest = "2" * 64

        claimed = coordinator.claim_publication(attempt_ref, plan_digest)
        replay = coordinator.claim_publication(attempt_ref, plan_digest)

        self.assertTrue(claimed["claimed"])
        self.assertTrue(replay["idempotent"])
        self.assertEqual(claimed["checkpoint_revision"], replay["checkpoint_revision"])
        with self.assertRaisesRegex(RunConflictError, "another publication attempt"):
            coordinator.claim_publication(
                "attempt_ref_v2:" + "3" * 64,
                plan_digest,
            )

        raw_input = coordinator.run_dir / "raw-inputs"
        retained = raw_input / "retained.bin"
        retained.write_bytes(b"retained until publication is reachable")
        os.chmod(retained, 0o600)
        self.clock.value += dt.timedelta(days=8)

        with mock.patch.object(
            coordinator,
            "_validate_published_authority",
            side_effect=InvalidTransitionError("history is not durable yet"),
        ):
            protected = coordinator.gc_expired_raw()

        self.assertTrue(protected["publication_claimed"])
        self.assertFalse(protected["durable"])
        self.assertFalse(protected["eligible"])
        self.assertFalse(protected["cleaned"])
        self.assertEqual(
            b"retained until publication is reachable", retained.read_bytes()
        )

        with mock.patch.object(
            coordinator,
            "_validate_published_authority",
            return_value=self.published_history(coordinator),
        ):
            recovered = coordinator.gc_expired_raw()

        state = coordinator.load_state()
        self.assertTrue(recovered["durable"])
        self.assertTrue(recovered["published"])
        self.assertTrue(recovered["cleaned"])
        self.assertEqual(RunStage.COMPLETE.value, state["stage"])
        self.assertEqual("complete", state["publication"]["phase"])
        self.assertNotIn("publication_claim", state["publication"])
        self.assertFalse(raw_input.exists())

    def test_unverified_commit_does_not_claim_published_cleanup_pending(self) -> None:
        coordinator = self.start_daily("unverified-commit")
        self.drain_sources(coordinator)
        coordinator.advance()
        coordinator.mark_exported("d" * 64)
        claim_ack = self.claim_publication_for_test(coordinator)

        with mock.patch.object(
            coordinator,
            "_validate_published_authority",
            side_effect=InvalidTransitionError("history not durable"),
        ):
            with self.assertRaisesRegex(InvalidTransitionError, "history not durable"):
                coordinator.mark_finalized("committed", **claim_ack)

        state = coordinator.load_state()
        self.assertEqual(RunStage.EXPORT.value, state["stage"])
        self.assertEqual("created", state["publication"]["phase"])

    def test_formal_completion_closes_jobs_and_cleans_raw_working_data(
        self,
    ) -> None:
        coordinator = self.start_daily("formal-cleanup")
        self.drain_sources(coordinator)
        coordinator.advance()
        coordinator.mark_exported("a" * 64)

        def attach_legacy_retained_export(current):
            current["retained_export"] = {
                "run_state": {"legacy": "working-only"},
                "review_data": {"legacy": "working-only"},
            }
            return current, None

        coordinator.store.transaction(attach_legacy_retained_export)
        raw_input = coordinator.run_dir / "raw-inputs"
        raw_shards = coordinator.run_dir / "raw-shards"
        raw_input.mkdir(mode=0o700, exist_ok=True)
        raw_shards.mkdir(mode=0o700, exist_ok=True)
        os.chmod(raw_input, 0o700)
        os.chmod(raw_shards, 0o700)
        input_payload = b"sealed raw input"
        shard_payload = b"sealed raw shard"
        input_path = raw_input / "input.bin"
        shard_path = raw_shards / "shard.bin"
        input_path.write_bytes(input_payload)
        shard_path.write_bytes(shard_payload)
        os.chmod(input_path, 0o600)
        os.chmod(shard_path, 0o600)
        working_paths = [
            path
            for root in (
                coordinator.run_dir / name
                for name in orchestrator_module.SHADOW_CLEANUP_ROOTS
            )
            for path in (root, *root.rglob("*"))
        ]
        expected_directories = sum(path.is_dir() for path in working_paths)
        expected_files = [path for path in working_paths if path.is_file()]
        expected_bytes = sum(path.stat().st_size for path in expected_files)
        claim_ack = self.claim_publication_for_test(coordinator)
        real_transaction = coordinator.store.transaction
        response_lost = False

        def lose_published_cleanup_response(*args, **kwargs):
            nonlocal response_lost
            result = real_transaction(*args, **kwargs)
            if (
                result.snapshot.state["publication"].get("phase") == "complete"
                and not response_lost
            ):
                response_lost = True
                raise RuntimeError("lost published cleanup response")
            return result

        with (
            mock.patch.object(
                coordinator,
                "_validate_published_authority",
                return_value=self.published_history(coordinator),
            ),
            mock.patch.object(
                coordinator.store,
                "transaction",
                side_effect=lose_published_cleanup_response,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "lost published cleanup response",
            ):
                coordinator.mark_finalized("committed", **claim_ack)
        completed = coordinator.mark_finalized("committed")
        cleanup = completed["publication"]["cleanup_receipt"]
        cleanup_claim = completed["publication"]["raw_cleanup_claim"]

        self.assertEqual(RunStage.COMPLETE.value, completed["stage"])
        self.assertEqual(cleanup_claim["claim_ref"], cleanup["cleanup_claim_ref"])
        self.assertEqual(expected_directories, cleanup["removed_directory_count"])
        self.assertEqual(len(expected_files), cleanup["removed_file_count"])
        self.assertEqual(expected_bytes, cleanup["removed_byte_count"])
        self.assertFalse(raw_input.exists())
        self.assertFalse(raw_shards.exists())
        self.assertIsNone(coordinator.load_state()["retained_export"])
        replay = coordinator.mark_finalized("committed")
        self.assertEqual(cleanup, replay["publication"]["cleanup_receipt"])

        coordinator.store.transaction(attach_legacy_retained_export)
        replay = coordinator.complete_published_cleanup()
        self.assertTrue(replay["idempotent"])
        self.assertIsNone(coordinator.load_state()["retained_export"])

    def test_nonterminal_worker_blocks_formal_cleanup(self) -> None:
        coordinator = self.start_daily("nonterminal-cleanup")
        self.drain_sources(coordinator)
        coordinator.advance()
        coordinator.mark_exported("b" * 64)
        raw_input = coordinator.run_dir / "raw-inputs"
        raw_input.mkdir(mode=0o700, exist_ok=True)

        def add_worker(state):
            job_ref = typed_ref(RefType.JOB, "still-running-worker")
            state["jobs"][job_ref] = {
                "active_attempt_ref": None,
                "active_job_ref": None,
                "allowed_refs": [],
                "attempts": [],
                "category": "agent",
                "input_payload": {},
                "job_kind": "synthetic_nonterminal_worker",
                "job_ref": job_ref,
                "stage": RunStage.EXPORT.value,
                "status": "runnable",
                "task_ref": typed_ref(RefType.RUN_INPUT, "still-running-worker-task"),
            }
            return state, None

        coordinator.store.transaction(add_worker)
        claim_ack = self.claim_publication_for_test(coordinator)
        with mock.patch.object(
            coordinator,
            "_validate_published_authority",
            return_value=self.published_history(coordinator),
        ):
            with self.assertRaisesRegex(InvalidTransitionError, "accepted or gapped"):
                coordinator.mark_finalized("committed", **claim_ack)

        state = coordinator.store.read().state
        self.assertEqual(RunStage.EXPORT.value, state["stage"])
        self.assertEqual("created", state["publication"]["phase"])
        self.assertIsNone(state["publication"]["cleanup_receipt"])
        self.assertTrue(raw_input.is_dir())

    def test_symlinked_raw_tree_blocks_completion_without_deleting_target(
        self,
    ) -> None:
        coordinator = self.start_daily("unsafe-cleanup")
        self.drain_sources(coordinator)
        coordinator.advance()
        coordinator.mark_exported("c" * 64)
        outside = self.root / "outside-raw"
        outside.mkdir(mode=0o700)
        marker = outside / "marker.bin"
        marker.write_bytes(b"must survive")
        os.chmod(marker, 0o600)
        raw_link = coordinator.run_dir / "raw-inputs"
        _run_path, run_fd = safe_io.open_owner_only_directory(coordinator.run_dir)
        try:
            safe_io.secure_remove_tree_at(
                run_fd,
                "raw-inputs",
                display_path=raw_link,
            )
        finally:
            os.close(run_fd)
        raw_link.symlink_to(outside, target_is_directory=True)
        claim_ack = self.claim_publication_for_test(coordinator)

        with mock.patch.object(
            coordinator,
            "_validate_published_authority",
            return_value=self.published_history(coordinator),
        ):
            pending = coordinator.mark_finalized("committed", **claim_ack)
        self.assertTrue(pending["cleanup_pending"])

        state = coordinator.store.read().state
        self.assertEqual(RunStage.FINALIZE.value, state["stage"])
        self.assertIsNone(state["publication"]["cleanup_receipt"])
        self.assertEqual(b"must survive", marker.read_bytes())
        raw_link.unlink()
        with mock.patch.object(
            coordinator,
            "_validate_published_authority",
            return_value=self.published_history(coordinator),
        ):
            completed = coordinator.complete_published_cleanup()
        self.assertEqual(RunStage.COMPLETE.value, completed["stage"])

    def test_idempotency_conflict_rejects_changed_manifest(self) -> None:
        coordinator = self.start_daily("conflict")
        coordinator.advance()
        lease = coordinator.status()["active_source_leases"][0]
        manifest_value = no_activity_manifest(lease)
        manifest = manifest_value.to_dict()
        receipt = authenticated_receipt(coordinator, lease, manifest_value)
        coordinator.accept_source(
            lease["lease_ref"], manifest, transport_receipt=receipt
        )
        replay = coordinator.accept_source(
            lease["lease_ref"], manifest, transport_receipt=receipt
        )
        self.assertTrue(replay["idempotent"])
        changed = copy.deepcopy(manifest)
        changed["absence_proof"] = "changed_authenticated_input"
        changed_manifest = catalog.SourceTransportManifest.from_dict(changed)
        changed_receipt = authenticated_receipt(
            coordinator, lease, changed_manifest, authorize=False
        )
        with self.assertRaises(InvalidInputError):
            coordinator.accept_source(
                lease["lease_ref"],
                changed,
                transport_receipt=changed_receipt,
            )


if __name__ == "__main__":
    unittest.main()
