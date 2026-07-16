from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "codex-session-retrospective"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS))

from retrospective_v2 import controlled_gaps, transport  # noqa: E402
from retrospective_v2.contracts import (  # noqa: E402
    ControlledGapReason,
    RefType,
    SourceCellStatus,
    SourceKind,
)
from retrospective_v2.identity import IdentityKey  # noqa: E402


class ControlledGapReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.identity = IdentityKey.create(self.root / "identity-v2.key")
        self.run_ref = str(self.identity.derive_ref(RefType.RUN, {"run": "shadow"}))
        self.host_ref = str(
            self.identity.derive_ref(RefType.HOST, {"host": "missing-host"})
        )
        self.receipts = [
            self.source_receipt(source_kind, index)
            for index, source_kind in enumerate(
                controlled_gaps.CONTROLLED_GAP_SOURCE_KINDS,
                start=1,
            )
        ]
        self.receipt_refs = [receipt.receipt_ref for receipt in self.receipts]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def source_receipt(
        self,
        source_kind: SourceKind,
        ordinal: int,
    ) -> transport.TransportReceipt:
        digest = (
            "sha256:"
            + hashlib.sha256(
                f"controlled-gap-{source_kind.value}-{ordinal}".encode("ascii")
            ).hexdigest()
        )
        snapshot = transport.AuthoritativeSourceSnapshot.create(
            host_ref=self.host_ref,
            source_kind=source_kind,
            window_start="2026-07-14T00:00:00Z",
            window_end="2026-07-15T00:00:00Z",
            session_target=None,
            source_content_commitment=digest,
            source_byte_count=0,
            terminal_byte_offset=0,
            catalog_record_count=0,
            catalog_byte_count=0,
            catalog_commitment=None,
            transcript_commitment=digest,
            terminal_proof_commitment=digest,
            terminal_status=SourceCellStatus.GAP,
            terminal_reason=(ControlledGapReason.SHADOW_MISSING_HOST_HOLDOUT.value),
            complete=False,
            resume_position=None,
        )
        placeholder = transport.TransportReceipt(
            receipt_ref=transport.TRANSPORT_RECEIPT_REF_PREFIX + "0" * 64,
            lease_ref=str(
                self.identity.derive_ref(
                    RefType.LEASE,
                    {"ordinal": ordinal, "source_kind": source_kind.value},
                )
            ),
            lease_authentication_tag=(
                transport.TRANSPORT_LEASE_AUTH_PREFIX + f"{ordinal:064x}"
            ),
            lease_binding=digest,
            manifest_commitment=digest,
            source_snapshot=snapshot,
        )
        return replace(
            placeholder,
            receipt_ref=transport.TRANSPORT_RECEIPT_REF_PREFIX
            + self.identity.derive_digest(
                "source-transport-receipt/v2",
                placeholder.unsigned_dict(),
            ),
        )

    def issue(self, **overrides):
        values = {
            "host": "missing-host",
            "host_ref": self.host_ref,
            "identity": self.identity,
            "reason": ControlledGapReason.SHADOW_MISSING_HOST_HOLDOUT,
            "run_ref": self.run_ref,
            "shadow": True,
            "source_kinds": list(controlled_gaps.CONTROLLED_GAP_SOURCE_KINDS),
            "source_receipt_refs": self.receipt_refs,
            "window_end": "2026-07-15T00:00:00Z",
            "window_start": "2026-07-14T00:00:00Z",
        }
        values.update(overrides)
        return controlled_gaps.issue_controlled_gap_receipt(**values)

    def test_round_trip_requires_exact_four_source_coverage(self) -> None:
        receipt = self.issue()
        verified = controlled_gaps.verify_controlled_gap_receipt(
            self.identity,
            receipt.to_dict(),
            source_receipts=self.receipts,
        )

        self.assertEqual(
            controlled_gaps.CONTROLLED_GAP_SOURCE_KINDS,
            verified.source_kinds,
        )
        self.assertTrue(verified.backfill_required)

    def test_missing_source_kind_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "every required source kind",
        ):
            self.issue(
                source_kinds=list(controlled_gaps.CONTROLLED_GAP_SOURCE_KINDS[:-1]),
                source_receipt_refs=self.receipt_refs[:-1],
            )

    def test_calibration_corpus_is_not_a_holdout_source_kind(self) -> None:
        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "every required source kind",
        ):
            self.issue(
                source_kinds=[
                    *controlled_gaps.CONTROLLED_GAP_SOURCE_KINDS,
                    SourceKind.CALIBRATION_CORPUS,
                ],
                source_receipt_refs=[
                    *self.receipt_refs,
                    transport.TRANSPORT_RECEIPT_REF_PREFIX + f"{5:064x}",
                ],
            )

    def test_duplicate_transport_receipt_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "source receipt coverage",
        ):
            self.issue(source_receipt_refs=[self.receipt_refs[0]] * 4)

    def test_authenticated_receipt_rejects_repointed_transport_receipt(self) -> None:
        tampered = self.issue().to_dict()
        tampered["source_receipt_refs"] = [
            transport.TRANSPORT_RECEIPT_REF_PREFIX + f"{index:064x}"
            for index in range(10, 14)
        ]

        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "authentication failed",
        ):
            controlled_gaps.verify_controlled_gap_receipt(self.identity, tampered)

    def test_source_receipts_remain_canonical_and_kind_bound(self) -> None:
        receipt = self.issue(
            source_kinds=list(reversed(controlled_gaps.CONTROLLED_GAP_SOURCE_KINDS)),
            source_receipt_refs=list(reversed(self.receipt_refs)),
        )

        self.assertEqual(tuple(sorted(self.receipt_refs)), receipt.source_receipt_refs)
        controlled_gaps.verify_controlled_gap_receipt(
            self.identity,
            receipt,
            source_receipts=self.receipts,
        )

    def test_independent_verifier_rejects_four_receipts_of_one_kind(self) -> None:
        receipts = [
            self.source_receipt(SourceKind.ACTIVE_ROLLOUT, ordinal)
            for ordinal in range(10, 14)
        ]
        gap = self.issue(
            source_receipt_refs=[receipt.receipt_ref for receipt in receipts]
        )

        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "kind coverage does not match",
        ):
            controlled_gaps.verify_controlled_gap_receipt(
                self.identity,
                gap,
                source_receipts=receipts,
            )

    def test_wrong_identity_cannot_verify_holdout(self) -> None:
        other = IdentityKey.create(self.root / "other-identity-v2.key")
        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "identity does not match",
        ):
            controlled_gaps.verify_controlled_gap_receipt(
                other,
                self.issue().to_dict(),
            )

    def test_window_must_be_ordered_and_timezone_aware(self) -> None:
        for start, end in (
            ("2026-07-15T00:00:00Z", "2026-07-14T00:00:00Z"),
            ("2026-07-14T00:00:00", "2026-07-15T00:00:00Z"),
        ):
            with self.subTest(start=start, end=end):
                with self.assertRaisesRegex(
                    controlled_gaps.ControlledGapError,
                    "window is invalid",
                ):
                    self.issue(window_start=start, window_end=end)

    def test_closed_reason_cannot_be_relabelled(self) -> None:
        tampered = copy.deepcopy(self.issue().to_dict())
        tampered["reason"] = "invalid_json"

        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "reason is not closed",
        ):
            controlled_gaps.verify_controlled_gap_receipt(self.identity, tampered)

    def test_holdout_reason_is_bound_to_shadow_mode(self) -> None:
        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "does not match shadow mode",
        ):
            self.issue(shadow=False)

        production = self.issue(
            shadow=False,
            reason=ControlledGapReason.MISSING_HOST_HOLDOUT,
        )
        self.assertFalse(production.shadow)
        tampered = production.to_dict()
        tampered["shadow"] = True
        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "does not match shadow mode",
        ):
            controlled_gaps.verify_controlled_gap_receipt(self.identity, tampered)

    def test_backfill_lineage_binds_gap_window_sources_and_head_sets(self) -> None:
        gap = self.issue()
        expected = str(
            self.identity.derive_ref(
                RefType.EPISODE_HEAD_SET,
                {"head_set": "expected"},
            )
        )
        proposed = str(
            self.identity.derive_ref(
                RefType.EPISODE_HEAD_SET,
                {"head_set": "proposed"},
            )
        )
        lineage = controlled_gaps.issue_backfill_lineage_receipt(
            self.identity,
            controlled_gap_receipt=gap,
            expected_episode_head_set_ref=expected,
            proposed_episode_head_set_ref=proposed,
            prior_episode_heads=[],
            proposed_episode_heads=[],
        )
        restored = controlled_gaps.verify_backfill_lineage_receipt(
            self.identity,
            lineage.to_dict(),
        )

        self.assertEqual(gap.receipt_ref, restored.controlled_gap_receipt_ref)
        self.assertEqual(gap.run_ref, restored.partial_run_ref)
        self.assertEqual(gap.host_ref, restored.host_ref)
        self.assertEqual(gap.source_receipt_refs, restored.source_receipt_refs)
        self.assertEqual(expected, restored.expected_episode_head_set_ref)
        self.assertEqual(proposed, restored.proposed_episode_head_set_ref)

    def test_backfill_lineage_rejects_repointed_proposed_heads(self) -> None:
        gap = self.issue()
        expected = str(
            self.identity.derive_ref(RefType.EPISODE_HEAD_SET, {"heads": "expected"})
        )
        proposed = str(
            self.identity.derive_ref(RefType.EPISODE_HEAD_SET, {"heads": "proposed"})
        )
        tampered = controlled_gaps.issue_backfill_lineage_receipt(
            self.identity,
            controlled_gap_receipt=gap,
            expected_episode_head_set_ref=expected,
            proposed_episode_head_set_ref=proposed,
            prior_episode_heads=[],
            proposed_episode_heads=[],
        ).to_dict()
        tampered["proposed_episode_head_set_ref"] = str(
            self.identity.derive_ref(RefType.EPISODE_HEAD_SET, {"heads": "forged"})
        )

        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "authentication failed",
        ):
            controlled_gaps.verify_backfill_lineage_receipt(self.identity, tampered)

    def test_receipt_prefix_without_exact_digest_is_rejected(self) -> None:
        tampered = self.issue().to_dict()
        tampered["receipt_ref"] = (
            controlled_gaps.CONTROLLED_GAP_RECEIPT_REF_PREFIX + "arbitrary-string"
        )

        with self.assertRaisesRegex(
            controlled_gaps.ControlledGapError,
            "authentication fields",
        ):
            controlled_gaps.verify_controlled_gap_receipt(self.identity, tampered)


if __name__ == "__main__":
    unittest.main()
