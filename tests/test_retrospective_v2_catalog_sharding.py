from __future__ import annotations

import copy
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

from retrospective_v2 import catalog  # noqa: E402
from retrospective_v2 import contracts  # noqa: E402
from retrospective_v2 import raw_shard_staging  # noqa: E402
from retrospective_v2 import sharding  # noqa: E402
from retrospective_v2.identity import IdentityKey  # noqa: E402


WINDOW_START = "2026-07-01T00:00:00Z"
WINDOW_END = "2026-07-02T00:00:00Z"


def candidate(
    unit_ref: str,
    payload: bytes,
    *,
    source_kind: catalog.SourceKind = catalog.SourceKind.ACTIVE_ROLLOUT,
    source_ref: str = "session-stable-1",
    record_ref: str | None = None,
    byte_start: int = 0,
    event_time: str | None = "2026-07-01T12:00:00Z",
    turn_count: int = 1,
) -> catalog.CatalogRecord:
    return catalog.CatalogRecord(
        unit_ref=unit_ref,
        source_kind=source_kind,
        coordinate=catalog.StableSourceCoordinate(
            host_ref="local",
            source_ref=source_ref,
            record_ref=record_ref or unit_ref,
            byte_start=byte_start,
            byte_end=byte_start + len(payload),
        ),
        event_time=event_time,
        content_commitment=catalog.content_commitment(payload),
        turn_count=turn_count,
    )


def raw_record(
    record: catalog.CatalogRecord, payload: bytes
) -> sharding.RawEvidenceRecord:
    return sharding.RawEvidenceRecord(catalog_record=record, payload=payload)


class CatalogTests(unittest.TestCase):
    def test_source_catalog_requires_one_retrospective_window(self) -> None:
        empty_snapshot = catalog.snapshot_commitment_for_records([])
        active = catalog.SourceTransportManifest.create(
            host_ref="local",
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            status=catalog.SourceCellStatus.NO_ACTIVITY,
            snapshot_commitment=empty_snapshot,
        )
        archived_other_window = catalog.SourceTransportManifest.create(
            host_ref="local",
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            window_start="2026-07-02T00:00:00Z",
            window_end="2026-07-03T00:00:00Z",
            status=catalog.SourceCellStatus.NO_ACTIVITY,
            snapshot_commitment=empty_snapshot,
        )

        with self.assertRaisesRegex(
            catalog.CatalogValidationError, "one retrospective window"
        ):
            catalog.SourceCatalog.create([active, archived_other_window])

        archived_same_window = catalog.SourceTransportManifest.create(
            host_ref="local",
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            status=catalog.SourceCellStatus.NO_ACTIVITY,
            snapshot_commitment=empty_snapshot,
        )
        source_catalog = catalog.SourceCatalog.create([active, archived_same_window])
        self.assertEqual(2, len(source_catalog.manifests))

    def test_event_time_uses_source_event_and_never_archive_mtime(self) -> None:
        record = {
            "timestamp": "2026-06-30T23:30:00-02:00",
            "payload": {"timestamp": "2030-01-01T00:00:00Z"},
        }

        event_time = catalog.event_time_from_record(record, mtime=4_102_444_800.0)

        self.assertEqual(event_time, "2026-07-01T01:30:00Z")
        self.assertIsNone(catalog.event_time_from_record({}, mtime=4_102_444_800.0))
        self.assertEqual(
            catalog.event_time_from_record(
                {},
                stable_event_time="2026-07-01T03:00:00+03:00",
                mtime=0.0,
            ),
            "2026-07-01T00:00:00Z",
        )

    def test_real_session_metadata_time_shapes_without_archive_fallback(
        self,
    ) -> None:
        self.assertEqual(
            "2026-07-01T02:03:04Z",
            catalog.event_time_from_record(
                {"id": "session", "updated_at": "2026-07-01T02:03:04Z"}
            ),
        )
        self.assertEqual(
            "2026-07-01T00:00:00Z",
            catalog.event_time_from_record({"ts": 1_782_864_000}),
        )
        self.assertEqual(
            "2026-07-01T00:00:00.500000Z",
            catalog.event_time_from_record({"payload": {"ts": 1_782_864_000.5}}),
        )
        locator = (
            "archived_sessions/2026/07/01/rollout-archived-without-record-time.jsonl"
        )
        fallback = catalog.stable_event_time_from_locator(locator)
        self.assertIsNone(fallback)
        self.assertIsNone(catalog.event_time_from_record({}))
        self.assertIsNone(
            catalog.event_time_from_record(
                {"ts": float("inf")},
                mtime=1_751_328_000.0,
            )
        )

    def test_rollout_filename_date_beats_archive_directory_date(self) -> None:
        active = "sessions/2025/12/31/rollout-2026-07-01T02-03-04-stable-session.jsonl"
        archived = (
            "archived_sessions/2031/01/02/"
            "rollout-2026-07-01T02-03-04-stable-session.jsonl"
        )

        self.assertEqual(
            "2026-07-01T02:03:04Z",
            catalog.stable_event_time_from_locator(active),
        )
        self.assertEqual(
            catalog.stable_event_time_from_locator(active),
            catalog.stable_event_time_from_locator(archived),
        )

    def test_rollout_filename_time_preserves_fraction_and_timezone(self) -> None:
        locator = (
            "archived_sessions/2031/01/02/"
            "rollout-2026-07-01T02-03-04.123456+08-00-stable-session.jsonl"
        )

        self.assertEqual(
            "2026-06-30T18:03:04.123456Z",
            catalog.stable_event_time_from_locator(locator),
        )

    def test_window_comparison_uses_utc_instants_at_microsecond_precision(
        self,
    ) -> None:
        payload = b"x"
        record = candidate(
            "microsecond-start",
            payload,
            event_time="2026-07-01T00:00:00Z",
        )

        manifest = catalog.SourceTransportManifest.create(
            host_ref="local",
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            window_start="2026-07-01T02:00:00+02:00",
            window_end="2026-07-01T00:00:00.000001Z",
            status=catalog.SourceCellStatus.COMPLETE,
            records=[record],
            snapshot_commitment=catalog.snapshot_commitment_for_records([record]),
        )

        self.assertEqual(manifest.window_start, "2026-07-01T00:00:00Z")
        self.assertEqual(manifest.window_end, "2026-07-01T00:00:00.000001Z")
        with self.assertRaises(catalog.CatalogValidationError):
            catalog.SourceTransportManifest.create(
                host_ref="local",
                transport_kind=catalog.TransportKind.LOCAL,
                source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
                window_start="2026-07-01T00:00:00.000001Z",
                window_end="2026-07-01T00:00:00Z",
                status=catalog.SourceCellStatus.COMPLETE,
                records=[record],
                snapshot_commitment=catalog.snapshot_commitment_for_records([record]),
            )

    def test_complete_manifest_binds_snapshot_and_consumed_event_times(self) -> None:
        payload = b"record"
        in_window = candidate("in-window", payload)
        valid_snapshot = catalog.snapshot_commitment_for_records([in_window])

        for snapshot in ("snapshot", "sha256:" + "0" * 64):
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(catalog.CatalogValidationError):
                    catalog.SourceTransportManifest.create(
                        host_ref="local",
                        transport_kind=catalog.TransportKind.LOCAL,
                        source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
                        window_start=WINDOW_START,
                        window_end=WINDOW_END,
                        status=catalog.SourceCellStatus.COMPLETE,
                        records=[in_window],
                        snapshot_commitment=snapshot,
                    )

        for unit_ref, event_time in (
            ("missing-time", None),
            ("at-window-end", WINDOW_END),
            ("before-window", "2026-06-30T23:59:59.999999Z"),
        ):
            record = candidate(unit_ref, payload, event_time=event_time)
            with self.subTest(unit_ref=unit_ref):
                with self.assertRaises(catalog.CatalogValidationError):
                    catalog.SourceTransportManifest.create(
                        host_ref="local",
                        transport_kind=catalog.TransportKind.LOCAL,
                        source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
                        window_start=WINDOW_START,
                        window_end=WINDOW_END,
                        status=catalog.SourceCellStatus.COMPLETE,
                        records=[record],
                        snapshot_commitment=catalog.snapshot_commitment_for_records(
                            [record]
                        ),
                    )

        explicit_gap = catalog.CatalogRecord(
            unit_ref="unit-gap",
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            coordinate=catalog.StableSourceCoordinate(
                "local", "session-stable-1", "unit-gap", 0, len(payload)
            ),
            accounting_class=catalog.AccountingClass.EXPLICIT_GAP,
            content_commitment=catalog.content_commitment(payload),
            turn_count=0,
            gap=catalog.ExplicitGap("transport_failure", "catalog"),
        )
        with self.assertRaises(catalog.CatalogValidationError):
            catalog.SourceTransportManifest.create(
                host_ref="local",
                transport_kind=catalog.TransportKind.LOCAL,
                source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
                window_start=WINDOW_START,
                window_end=WINDOW_END,
                status=catalog.SourceCellStatus.COMPLETE,
                records=[explicit_gap],
                snapshot_commitment=catalog.snapshot_commitment_for_records(
                    [explicit_gap]
                ),
            )

        self.assertRegex(valid_snapshot, r"^sha256:[0-9a-f]{64}$")

    def test_all_catalog_from_dict_layers_require_closed_exact_keys(self) -> None:
        payload = b"record"
        record = candidate("unit-closed", payload)
        manifest = catalog.SourceTransportManifest.create(
            host_ref="local",
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            status=catalog.SourceCellStatus.COMPLETE,
            records=[record],
            snapshot_commitment=catalog.snapshot_commitment_for_records([record]),
        )
        source_catalog = catalog.SourceCatalog.create([manifest])
        gap = catalog.ExplicitGap("transport_failure", "catalog")
        remote = catalog.RemoteTransportBinding(
            process_nonce="nonce-1",
            forced_command_argv=("session-shards",),
        )

        closed_layers = (
            (
                "coordinate",
                catalog.StableSourceCoordinate.from_dict,
                record.coordinate.to_dict(),
            ),
            ("gap", catalog.ExplicitGap.from_dict, gap.to_dict()),
            ("record", catalog.CatalogRecord.from_dict, record.to_dict()),
            ("remote", catalog.RemoteTransportBinding.from_dict, remote.to_dict()),
            ("manifest", catalog.SourceTransportManifest.from_dict, manifest.to_dict()),
            ("catalog", catalog.SourceCatalog.from_dict, source_catalog.to_dict()),
        )
        for label, loader, serialized in closed_layers:
            for key in tuple(serialized):
                missing = copy.deepcopy(serialized)
                del missing[key]
                with self.subTest(layer=label, mutation=f"missing-{key}"):
                    with self.assertRaises(catalog.CatalogValidationError):
                        loader(missing)
            unknown = copy.deepcopy(serialized)
            unknown["unknown_field"] = True
            with self.subTest(layer=label, mutation="unknown"):
                with self.assertRaises(catalog.CatalogValidationError):
                    loader(unknown)

        serialized_catalog = source_catalog.to_dict()
        window_keys = tuple(serialized_catalog["manifests"][0]["window"])
        for key in window_keys:
            missing = copy.deepcopy(serialized_catalog)
            del missing["manifests"][0]["window"][key]
            with self.subTest(layer="window", mutation=f"missing-{key}"):
                with self.assertRaises(catalog.CatalogValidationError):
                    catalog.SourceCatalog.from_dict(missing)
        unknown_window = copy.deepcopy(serialized_catalog)
        unknown_window["manifests"][0]["window"]["unknown_field"] = True
        with self.assertRaises(catalog.CatalogValidationError):
            catalog.SourceCatalog.from_dict(unknown_window)

        count_keys = tuple(serialized_catalog["accounting_counts"])
        for key in count_keys:
            missing = copy.deepcopy(serialized_catalog)
            del missing["accounting_counts"][key]
            with self.subTest(layer="accounting_counts", mutation=f"missing-{key}"):
                with self.assertRaises(catalog.CatalogValidationError):
                    catalog.SourceCatalog.from_dict(missing)
        unknown_counts = copy.deepcopy(serialized_catalog)
        unknown_counts["accounting_counts"]["unknown_field"] = 0
        with self.assertRaises(catalog.CatalogValidationError):
            catalog.SourceCatalog.from_dict(unknown_counts)
        boolean_count = copy.deepcopy(serialized_catalog)
        boolean_count["accounting_counts"]["consumed_candidate"] = True
        with self.assertRaises(catalog.CatalogValidationError):
            catalog.SourceCatalog.from_dict(boolean_count)

    def test_catalog_record_requires_exactly_one_accounting_class_shape(self) -> None:
        payload = b'{"type":"message"}\n'
        record = candidate("unit-1", payload)
        self.assertEqual(
            record.accounting_class, catalog.AccountingClass.CONSUMED_CANDIDATE
        )

        with self.assertRaises(catalog.CatalogValidationError):
            catalog.CatalogRecord(
                unit_ref="excluded",
                source_kind=catalog.SourceKind.HISTORY,
                coordinate=catalog.StableSourceCoordinate(
                    "local", "history", "1", 0, 4
                ),
                accounting_class=catalog.AccountingClass.STRUCTURALLY_EXCLUDED,
                exclusion_reason="not_a_closed_reason",
                turn_count=0,
            )
        with self.assertRaises(catalog.CatalogValidationError):
            catalog.CatalogRecord(
                unit_ref="gap-without-reason",
                source_kind=catalog.SourceKind.HISTORY,
                coordinate=catalog.StableSourceCoordinate(
                    "local", "history", "2", 4, 8
                ),
                accounting_class=catalog.AccountingClass.EXPLICIT_GAP,
                turn_count=0,
            )

    def test_active_archived_dedup_uses_coordinates_not_content_alone(self) -> None:
        payload = b'{"timestamp":"2026-07-01T12:00:00Z"}\n'
        active = candidate(
            "active-copy",
            payload,
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            record_ref="stable-record",
            event_time=None,
        )
        archived = candidate(
            "archived-copy",
            payload,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            record_ref="stable-record",
        )
        legacy_archived = candidate(
            "legacy-archived-copy",
            payload,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            record_ref="stable-record",
        )
        same_content_other_occurrence = candidate(
            "separate-occurrence",
            payload,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            record_ref="other-stable-record",
        )

        records = catalog.deduplicate_active_archived(
            [archived, same_content_other_occurrence, active, legacy_archived]
        )
        by_ref = {record.unit_ref: record for record in records}

        self.assertEqual(
            by_ref["active-copy"].accounting_class,
            catalog.AccountingClass.CONSUMED_CANDIDATE,
        )
        self.assertEqual(by_ref["active-copy"].event_time, "2026-07-01T12:00:00Z")
        self.assertEqual(
            by_ref["archived-copy"].accounting_class,
            catalog.AccountingClass.STRUCTURALLY_EXCLUDED,
        )
        self.assertEqual(
            by_ref["archived-copy"].exclusion_reason,
            catalog.StructuralExclusionReason.DUPLICATE_OF,
        )
        self.assertEqual(by_ref["archived-copy"].duplicate_of, "active-copy")
        self.assertEqual(
            by_ref["legacy-archived-copy"].accounting_class,
            catalog.AccountingClass.STRUCTURALLY_EXCLUDED,
        )
        self.assertEqual(by_ref["legacy-archived-copy"].duplicate_of, "active-copy")
        self.assertEqual(
            by_ref["separate-occurrence"].accounting_class,
            catalog.AccountingClass.CONSUMED_CANDIDATE,
        )

    def test_conflicting_canonical_identity_at_same_physical_occurrence_gaps(
        self,
    ) -> None:
        first_payload = b"first"
        second_payload = b"other"
        physical = "d" * 64
        active = candidate(
            "active-copy",
            first_payload,
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            record_ref=f"record-v2:{physical}:{'a' * 64}",
        )
        archived = candidate(
            "archived-copy",
            second_payload,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            record_ref=f"record-v2:{physical}:{'b' * 64}",
        )

        records = catalog.deduplicate_active_archived([active, archived])

        self.assertEqual(
            {record.accounting_class for record in records},
            {catalog.AccountingClass.EXPLICIT_GAP},
        )
        self.assertEqual(
            {record.gap.reason for record in records if record.gap},
            {"source_coordinate_conflict"},
        )

    def test_distinct_active_occurrences_never_collapse(self) -> None:
        payload = b"same-record"
        canonical = "f" * 64
        active_a = candidate(
            "active-a",
            payload,
            record_ref=f"record-v2:{'a' * 64}:{canonical}",
        )
        active_b = candidate(
            "active-b",
            payload,
            record_ref=f"record-v2:{'b' * 64}:{canonical}",
        )
        archived = candidate(
            "archived",
            payload,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            record_ref=f"record-v2:{'c' * 64}:{canonical}",
        )

        records = catalog.deduplicate_active_archived([archived, active_b, active_a])

        self.assertEqual(3, len({record.coordinate for record in records}))
        self.assertEqual(
            {catalog.AccountingClass.CONSUMED_CANDIDATE},
            {record.accounting_class for record in records},
        )

    def test_one_active_and_archived_occurrence_use_explicit_equivalence(self) -> None:
        payload = b"same-record"
        canonical = "e" * 64
        active = candidate(
            "active",
            payload,
            record_ref=f"record-v2:{'a' * 64}:{canonical}",
        )
        archived = candidate(
            "archived",
            payload,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            record_ref=f"record-v2:{'b' * 64}:{canonical}",
        )

        records = catalog.deduplicate_active_archived([archived, active])
        by_ref = {record.unit_ref: record for record in records}

        self.assertNotEqual(active.coordinate, archived.coordinate)
        self.assertEqual(
            catalog.AccountingClass.CONSUMED_CANDIDATE,
            by_ref["active"].accounting_class,
        )
        self.assertEqual(
            catalog.AccountingClass.STRUCTURALLY_EXCLUDED,
            by_ref["archived"].accounting_class,
        )
        self.assertEqual("active", by_ref["archived"].duplicate_of)

    def test_turn_count_conflict_at_same_coordinate_becomes_explicit_gap(
        self,
    ) -> None:
        payload = b"same-record"
        active = candidate(
            "active-turn-count",
            payload,
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            record_ref="stable-record",
            turn_count=1,
        )
        archived = candidate(
            "archived-turn-count",
            payload,
            source_kind=catalog.SourceKind.ARCHIVED_ROLLOUT,
            record_ref="stable-record",
            turn_count=2,
        )

        records = catalog.deduplicate_active_archived([archived, active])

        self.assertEqual(
            {record.accounting_class for record in records},
            {catalog.AccountingClass.EXPLICIT_GAP},
        )
        self.assertEqual(
            {record.gap.reason for record in records if record.gap},
            {"source_coordinate_conflict"},
        )

    def test_source_manifest_round_trip_and_remote_binding_validation(self) -> None:
        payload_a = b"a"
        payload_b = b"bb"
        records = [
            candidate("unit-b", payload_b, record_ref="record-b", byte_start=10),
            candidate("unit-a", payload_a, record_ref="record-a"),
        ]
        manifest = catalog.SourceTransportManifest.create(
            host_ref="local",
            transport_kind=catalog.TransportKind.LOCAL,
            source_kind=catalog.SourceKind.ACTIVE_ROLLOUT,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            status=catalog.SourceCellStatus.COMPLETE,
            records=records,
            snapshot_commitment=catalog.snapshot_commitment_for_records(records),
        )

        restored = catalog.SourceTransportManifest.from_dict(
            json.loads(manifest.canonical_bytes())
        )

        self.assertEqual(restored, manifest)
        self.assertEqual(manifest.total_records, 2)
        self.assertEqual(manifest.total_bytes, 3)
        self.assertEqual(manifest.canonical_bytes(), restored.canonical_bytes())
        source_catalog = catalog.SourceCatalog.create([manifest])
        self.assertEqual(
            catalog.SourceCatalog.from_dict(
                json.loads(source_catalog.canonical_bytes())
            ),
            source_catalog,
        )
        with self.assertRaises(catalog.CatalogValidationError):
            catalog.SourceTransportManifest.create(
                host_ref="remote-1",
                transport_kind=catalog.TransportKind.REMOTE,
                source_kind=catalog.SourceKind.HISTORY,
                window_start=WINDOW_START,
                window_end=WINDOW_END,
                status=catalog.SourceCellStatus.NO_ACTIVITY,
                snapshot_commitment=catalog.snapshot_commitment_for_records(()),
            )

        remote = catalog.SourceTransportManifest.create(
            host_ref="remote-1",
            transport_kind=catalog.TransportKind.REMOTE,
            source_kind=catalog.SourceKind.HISTORY,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            status=catalog.SourceCellStatus.NO_ACTIVITY,
            snapshot_commitment=catalog.snapshot_commitment_for_records(()),
            remote=catalog.RemoteTransportBinding(
                process_nonce="nonce-1",
                forced_command_argv=("session-shards", "--manifest-fd", "3"),
            ),
        )
        self.assertEqual(remote.total_bytes, 0)


class ShardingTests(unittest.TestCase):
    def test_shards_are_bounded_and_stable_across_cwd_and_input_order(self) -> None:
        raw_records = []
        for index in range(21):
            payload = f'{{"turn":{index}}}\n'.encode()
            record = candidate(
                f"unit-{index:02d}",
                payload,
                record_ref=f"record-{index:02d}",
                byte_start=index * 100,
            )
            raw_records.append(raw_record(record, payload))

        original_cwd = Path.cwd()
        with (
            tempfile.TemporaryDirectory() as first_cwd,
            tempfile.TemporaryDirectory() as second_cwd,
        ):
            try:
                os.chdir(first_cwd)
                forward = sharding.build_raw_shards(raw_records)
                os.chdir(second_cwd)
                reverse = sharding.build_raw_shards(reversed(raw_records))
            finally:
                os.chdir(original_cwd)

        self.assertEqual([item.manifest.turn_count for item in forward.shards], [20, 1])
        self.assertTrue(
            all(
                item.manifest.byte_count <= sharding.DEFAULT_MAX_SHARD_BYTES
                for item in forward.shards
            )
        )
        self.assertEqual(
            forward.canonical_manifest_bytes(),
            reverse.canonical_manifest_bytes(),
        )
        self.assertEqual(
            [item.data for item in forward.shards],
            [item.data for item in reverse.shards],
        )

    def test_shard_count_fails_before_exceeding_cleanup_capacity(self) -> None:
        records = []
        for index in range(21):
            payload = f'{{"turn":{index}}}\n'.encode()
            records.append(
                raw_record(
                    candidate(
                        f"bounded-unit-{index}",
                        payload,
                        byte_start=index * 100,
                    ),
                    payload,
                )
            )
        with (
            mock.patch.object(sharding, "MAX_RUN_RAW_SHARDS", 1),
            self.assertRaisesRegex(
                sharding.ShardingValidationError,
                "cleanup capacity",
            ),
        ):
            sharding.build_raw_shards(records)

    def test_oversized_utf8_record_splits_into_exact_contiguous_ranges(self) -> None:
        payload = ("prefix-" + "\u6c49\u5b57" * 1800 + "-suffix").encode("utf-8")
        record = candidate(
            "large-unit", payload, record_ref="large-record", byte_start=700
        )

        result = sharding.build_raw_shards(
            [raw_record(record, payload)],
            limits=sharding.ShardLimits(max_bytes=4096),
        )

        self.assertFalse(result.gaps)
        self.assertGreater(len(result.shards), 1)
        descriptors = [
            descriptor
            for shard in result.shards
            for descriptor in shard.manifest.ranges
        ]
        self.assertEqual(descriptors[0].range_start, 700)
        self.assertEqual(descriptors[-1].range_end, 700 + len(payload))
        self.assertEqual(
            [descriptor.range_end for descriptor in descriptors[:-1]],
            [descriptor.range_start for descriptor in descriptors[1:]],
        )
        self.assertEqual(
            {descriptor.fragment_count for descriptor in descriptors},
            {len(descriptors)},
        )
        self.assertEqual(
            [descriptor.fragment_index for descriptor in descriptors],
            list(range(len(descriptors))),
        )
        for descriptor in descriptors:
            start = descriptor.range_start - record.coordinate.byte_start
            end = descriptor.range_end - record.coordinate.byte_start
            payload[start:end].decode("utf-8")
        self.assertEqual(result.materialized_raw_bytes, len(payload))
        self.assertTrue(
            all(shard.manifest.byte_count <= 4096 for shard in result.shards)
        )

    def test_mixed_normal_and_600kib_utf8_record_conserves_every_byte(self) -> None:
        before_payload = b'{"turn":"before"}\n'
        large_payload = ("\u6c49\u5b57" * (600 * 1024 // 6 + 1)).encode("utf-8")
        after_payload = b'{"turn":"after"}\n'
        payloads = {
            "unit-before": before_payload,
            "unit-large": large_payload,
            "unit-after": after_payload,
        }
        records = [
            raw_record(
                candidate(
                    "unit-before",
                    before_payload,
                    record_ref="record-00-before",
                    byte_start=0,
                ),
                before_payload,
            ),
            raw_record(
                candidate(
                    "unit-large",
                    large_payload,
                    record_ref="record-01-large",
                    byte_start=len(before_payload),
                ),
                large_payload,
            ),
            raw_record(
                candidate(
                    "unit-after",
                    after_payload,
                    record_ref="record-02-after",
                    byte_start=len(before_payload) + len(large_payload),
                ),
                after_payload,
            ),
        ]

        result = sharding.build_raw_shards(reversed(records))

        self.assertGreater(len(large_payload), 600 * 1024)
        self.assertFalse(result.gaps)
        self.assertEqual(result.source_record_count, 3)
        self.assertEqual(result.source_byte_count, sum(map(len, payloads.values())))
        self.assertEqual(result.materialized_raw_bytes, result.source_byte_count)
        self.assertTrue(
            all(
                shard.manifest.byte_count <= sharding.DEFAULT_MAX_SHARD_BYTES
                for shard in result.shards
            )
        )

        fragments: dict[str, list[tuple[int, bytes]]] = {}
        for shard in result.shards:
            _, body = shard.data.split(b"\n", 1)
            for descriptor in shard.manifest.ranges:
                fragment = body[
                    descriptor.payload_offset : descriptor.payload_offset
                    + descriptor.payload_length
                ]
                fragments.setdefault(descriptor.unit_ref, []).append(
                    (descriptor.fragment_index, fragment)
                )
        self.assertGreater(len(fragments["unit-large"]), 1)
        for unit_ref, expected_payload in payloads.items():
            actual_payload = b"".join(
                fragment for _, fragment in sorted(fragments[unit_ref])
            )
            self.assertEqual(actual_payload, expected_payload)

    def test_over_budget_record_is_one_exact_gap_without_partial_shard(self) -> None:
        payload = b"0123456789"
        record = candidate("over-budget", payload)

        result = sharding.build_raw_shards(
            [raw_record(record, payload)],
            limits=sharding.ShardLimits(record_processing_budget=9),
        )

        self.assertFalse(result.shards)
        self.assertEqual(len(result.gaps), 1)
        self.assertEqual(result.gaps[0].reason, "oversized_record_budget_exceeded")
        self.assertEqual(result.gaps[0].coordinate, record.coordinate)
        self.assertEqual(result.gap_bytes, len(payload))
        self.assertEqual(result.materialized_raw_bytes + result.gap_bytes, len(payload))

    def test_over_budget_catalog_record_is_gapped_before_payload_read(self) -> None:
        payload = b"0123456789"
        record = candidate("deferred-over-budget", payload)
        limits = sharding.ShardLimits(
            max_bytes=8,
            record_processing_budget=9,
        )

        with mock.patch.object(
            raw_shard_staging.safe_io,
            "read_bounded_bytes",
        ) as read_payload:
            staged = raw_shard_staging.prepare(
                Path("/owner-only/run"),
                [record],
                {
                    record.unit_ref: {
                        "relative_path": "raw-inputs/must-not-be-opened.bin"
                    }
                },
                limits,
            )

        read_payload.assert_not_called()
        self.assertFalse(staged.plan.shards)
        self.assertEqual(1, len(staged.plan.gaps))
        self.assertEqual(
            "oversized_record_budget_exceeded",
            staged.plan.gaps[0].reason,
        )

    def test_failed_oversized_record_is_gapped_without_losing_normal_records(
        self,
    ) -> None:
        normal_payload = b'{"turn":"normal"}\n'
        invalid_payload = b"x" * 5000 + b"\xff"
        normal = raw_record(
            candidate(
                "unit-normal",
                normal_payload,
                record_ref="record-00-normal",
            ),
            normal_payload,
        )
        invalid = raw_record(
            candidate(
                "unit-invalid",
                invalid_payload,
                record_ref="record-01-invalid",
                byte_start=len(normal_payload),
            ),
            invalid_payload,
        )

        result = sharding.build_raw_shards(
            [invalid, normal],
            limits=sharding.ShardLimits(max_bytes=4096),
        )

        self.assertEqual(
            {
                descriptor.unit_ref
                for shard in result.shards
                for descriptor in shard.manifest.ranges
            },
            {"unit-normal"},
        )
        self.assertEqual(len(result.gaps), 1)
        self.assertEqual(result.gaps[0].unit_ref, "unit-invalid")
        self.assertEqual(result.gaps[0].reason, "invalid_utf8_oversized_record")
        self.assertEqual(result.materialized_raw_bytes, len(normal_payload))
        self.assertEqual(result.gap_bytes, len(invalid_payload))
        self.assertEqual(
            result.materialized_raw_bytes + result.gap_bytes,
            result.source_byte_count,
        )

    def test_zero_byte_record_still_gets_a_shard_or_an_explicit_gap(self) -> None:
        record = candidate("empty-unit", b"")

        materialized = sharding.build_raw_shards([raw_record(record, b"")])
        gapped = sharding.build_raw_shards(
            [raw_record(record, b"")],
            limits=sharding.ShardLimits(max_bytes=1),
        )

        self.assertEqual(len(materialized.shards), 1)
        self.assertFalse(materialized.gaps)
        self.assertFalse(gapped.shards)
        self.assertEqual(len(gapped.gaps), 1)
        self.assertEqual(gapped.gaps[0].reason, "shard_metadata_budget_exceeded")

    def test_materialization_uses_safe_io_and_fails_closed_without_it(self) -> None:
        payload = b'{"turn":1}\n'
        record = candidate("unit-1", payload)
        self.assertIsNotNone(sharding._safe_io)
        assert sharding._safe_io is not None
        real_ensure = sharding._safe_io.ensure_owner_only_directory
        real_write = sharding._safe_io.atomic_write_bytes

        with tempfile.TemporaryDirectory() as temporary:
            if not sharding._safe_io.secure_io_capability_issues():
                run_directory = Path(temporary) / "raw-run"
                with (
                    mock.patch.object(
                        sharding._safe_io,
                        "ensure_owner_only_directory",
                        wraps=real_ensure,
                    ) as ensure_mock,
                    mock.patch.object(
                        sharding._safe_io,
                        "atomic_write_bytes",
                        wraps=real_write,
                    ) as write_mock,
                ):
                    result = sharding.materialize_raw_shards(
                        [raw_record(record, payload)],
                        run_directory,
                    )

                self.assertGreaterEqual(ensure_mock.call_count, 1)
                self.assertEqual(write_mock.call_count, len(result.shards) + 1)
                self.assertEqual(stat.S_IMODE(run_directory.stat().st_mode), 0o700)
                expected_files = {
                    sharding.RAW_SHARDS_MANIFEST_FILE,
                    *(item.manifest.file_name for item in result.shards),
                }
                self.assertEqual(
                    {path.name for path in run_directory.iterdir()}, expected_files
                )
                for path in run_directory.iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            fallback_directory = Path(temporary) / "fallback-raw-run"
            with mock.patch.object(sharding, "_safe_io", None):
                with self.assertRaisesRegex(
                    sharding.ShardingValidationError,
                    "secure raw shard I/O is unavailable",
                ):
                    sharding.materialize_raw_shards(
                        [raw_record(record, payload)],
                        fallback_directory,
                    )
            self.assertFalse(fallback_directory.exists())

    def test_streaming_plan_and_materialization_keep_raw_working_set_bounded(
        self,
    ) -> None:
        payloads = [
            (f'{{"turn":{index},"text":"' + "x" * 64_000 + '"}}\n').encode()
            for index in range(24)
        ]
        records = [
            raw_record(
                candidate(
                    f"stream-unit-{index:03d}",
                    payload,
                    record_ref=f"record-{index:03d}",
                    byte_start=sum(len(value) for value in payloads[:index]),
                ),
                payload,
            )
            for index, payload in enumerate(payloads)
        ]
        limits = sharding.ShardLimits(max_turns=4, max_bytes=320 * 1024)

        plan = sharding.plan_ordered_raw_shards(iter(records), limits=limits)

        self.assertEqual(len(records), plan.source_record_count)
        self.assertLess(plan.peak_working_byte_count, plan.source_byte_count)
        self.assertLessEqual(
            plan.peak_working_byte_count,
            2 * max(map(len, payloads)) + 2 * limits.max_bytes,
        )
        with tempfile.TemporaryDirectory() as temporary:
            run_directory = Path(temporary) / "streamed-raw-run"
            receipt = sharding.materialize_ordered_raw_shards(
                iter(records),
                run_directory,
                plan=plan,
                limits=limits,
            )
            self.assertEqual(
                plan.canonical_manifest_bytes() + b"\n",
                (run_directory / sharding.RAW_SHARDS_MANIFEST_FILE).read_bytes(),
            )
            self.assertEqual(len(plan.shards) + 1, len(receipt.files))
            sharding.rollback_ordered_raw_shards(receipt)
            self.assertFalse(
                any(
                    path.name == sharding.RAW_SHARDS_MANIFEST_FILE
                    or path.name.startswith("raw-shard-")
                    for path in run_directory.iterdir()
                )
            )

    def test_streaming_shard_rollback_continues_after_receipt_mismatch(self) -> None:
        payloads = [b'{"turn":1}\n', b'{"turn":2}\n']
        records = [
            raw_record(
                candidate(
                    f"rollback-unit-{index}",
                    payload,
                    record_ref=f"rollback-record-{index}",
                    byte_start=sum(len(value) for value in payloads[:index]),
                ),
                payload,
            )
            for index, payload in enumerate(payloads)
        ]
        limits = sharding.ShardLimits(max_turns=1)
        plan = sharding.plan_ordered_raw_shards(records, limits=limits)

        with tempfile.TemporaryDirectory() as temporary:
            run_directory = Path(temporary) / "rollback-run"
            receipt = sharding.materialize_ordered_raw_shards(
                records,
                run_directory,
                plan=plan,
                limits=limits,
            )
            changed = run_directory / plan.shards[0].file_name
            original = changed.with_name("changed-original.jsonl")
            payload = changed.read_bytes()
            changed.rename(original)
            changed.write_bytes(payload)
            os.chmod(changed, 0o600)

            with self.assertRaisesRegex(
                sharding.ShardingValidationError,
                "target changed",
            ):
                sharding.rollback_ordered_raw_shards(receipt)

            self.assertTrue(changed.is_file())
            self.assertTrue(original.is_file())
            self.assertFalse(
                (run_directory / sharding.RAW_SHARDS_MANIFEST_FILE).exists()
            )
            self.assertFalse((run_directory / plan.shards[1].file_name).exists())

    def test_streaming_plan_rejects_shards_beyond_reserved_task_budget_before_io(
        self,
    ) -> None:
        payloads = [b'{"turn":1}\n', b'{"turn":2}\n']
        records = [
            raw_record(
                candidate(
                    f"capacity-unit-{index}",
                    payload,
                    record_ref=f"record-{index}",
                    byte_start=sum(len(value) for value in payloads[:index]),
                ),
                payload,
            )
            for index, payload in enumerate(payloads)
        ]
        limits = sharding.ShardLimits(max_turns=1)

        with self.assertRaisesRegex(
            sharding.ShardingValidationError,
            "reserved extractor task budget",
        ):
            sharding.plan_ordered_raw_shards(
                iter(records),
                limits=limits,
                max_shards=1,
            )
        self.assertEqual(
            contracts.MAX_RUN_AGENT_TASKS,
            contracts.MAX_RUN_RAW_SHARDS + contracts.MAX_RUN_DOWNSTREAM_AGENT_TASKS,
        )

    def test_job_manifest_is_hmac_deterministic_and_enforces_full_input_limit(
        self,
    ) -> None:
        payload = b'{"turn":1}\n'
        record = candidate("unit-1", payload)
        artifact = sharding.build_raw_shards([raw_record(record, payload)]).shards[0]
        arguments = {
            "job_kind": sharding.JobKind.EXTRACTOR_REDACTOR,
            "prompt_version": "extractor-prompt-v2",
            "result_schema_version": "redacted-turn-v2",
            "policy_version": "policy-v2",
            "framing": b"bounded-control-envelope",
            "job_key": b"k" * 32,
        }

        first = sharding.build_job_manifest(artifact, **arguments)
        second = sharding.build_job_manifest(artifact.manifest, **arguments)
        retry = sharding.build_job_manifest(artifact, retry_ordinal=1, **arguments)

        self.assertEqual(first, second)
        self.assertNotEqual(first.job_ref, retry.job_ref)
        self.assertEqual(
            first.input_byte_count, first.shard_byte_count + first.framing_byte_count
        )
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        identity_backed = sharding.build_job_manifest(
            artifact,
            **{**arguments, "job_key": IdentityKey(b"i" * 32)},
        )
        self.assertRegex(identity_backed.job_ref, r"^job_ref_v2:[0-9a-f]{64}$")
        with self.assertRaises(sharding.ShardingValidationError):
            sharding.build_job_manifest(
                artifact,
                **{
                    **arguments,
                    "framing": b"x" * sharding.DEFAULT_MAX_SHARD_BYTES,
                },
            )


if __name__ == "__main__":
    unittest.main()
