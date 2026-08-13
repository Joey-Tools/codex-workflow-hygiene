from __future__ import annotations

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

from retrospective_v2 import authority, episode_review  # noqa: E402
from retrospective_v2.identity import IdentityKey  # noqa: E402


def ref(kind: str, marker: str) -> str:
    digest = hashlib.sha256(f"{kind}:{marker}".encode("ascii")).hexdigest()
    return f"{kind}_ref_v2:{digest}"


HOST = ref("host", "local")
TURN_A = ref("turn", "a")
TURN_B = ref("turn", "b")
SESSION = ref("session", "session")
GOAL = ref("goal", "goal")
WORKSTREAM = ref("workstream", "workstream")


def episode(turn_refs: list[str]) -> dict[str, object]:
    return {
        "boundary_before": None,
        "extraction_confidence": "high",
        "goal_refs": [GOAL],
        "internal_boundary_candidates": [],
        "meaningfulness": {
            "context_only_turn_refs": [],
            "disposition": "meaningful",
            "gap_turn_refs": [],
            "meaningful_turn_refs": list(turn_refs),
            "review_required": True,
            "semantic_coverage": "complete",
        },
        "risk_flags": [],
        "segmentation_confidence": "high",
        "session_ref": SESSION,
        "turn_refs": list(turn_refs),
        "workstream_refs": [WORKSTREAM],
    }


def cursor_row(boundary: str, marker: str) -> dict[str, object]:
    return {
        "backlog_ref": None,
        "cursor_ref": ref("cursor", marker),
        "host_ref": HOST,
        "logical_boundary": boundary,
    }


def history_state(
    identity: IdentityKey,
    *,
    cursor_rows: tuple[dict[str, object], ...] = (),
    episode_heads: tuple[dict[str, object], ...] = (),
    provider_revision: int = 0,
    head_commit: str = "a" * 40,
) -> authority.DurableHistoryState:
    ordered_cursors = tuple(sorted(cursor_rows, key=lambda row: row["host_ref"]))
    ordered_heads = tuple(sorted(episode_heads, key=lambda row: row["episode_ref"]))
    return authority.DurableHistoryState(
        head_commit=head_commit,
        publication_commit=None,
        identity_key_id=identity.key_id,
        provider_revision=provider_revision,
        cursor_root_ref=authority.derive_cursor_root(ordered_cursors),
        episode_head_root_ref=authority.derive_episode_head_root(
            ordered_heads,
            identity=identity,
        ),
        cursor_rows=ordered_cursors,
        episode_heads=ordered_heads,
        episode_membership=authority.derive_episode_membership(
            ordered_heads,
            identity=identity,
        ),
    )


class DurableTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = IdentityKey(b"k" * 32)
        self.initial_head = episode_review.create_episode_revision(
            episode([TURN_A]),
            identity_key=self.identity,
            key_id=self.identity.key_id,
        )
        self.cursor = cursor_row("2026-07-01T01:00:00Z", "one")

    def manifest(
        self,
        previous: authority.DurableHistoryState,
        *,
        cursor_rows: list[dict[str, object]],
        episode_heads: list[dict[str, object]],
        episode_corrections: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        return authority.durable_state_manifest(
            expected=previous,
            proposed_cursor_rows=cursor_rows,
            proposed_episode_heads=episode_heads,
            identity=self.identity,
            source_snapshot_refs=[],
            backfill_of=None,
            episode_corrections=episode_corrections or [],
        )

    def test_cursor_and_episode_heads_advance_monotonically(self) -> None:
        previous = history_state(
            self.identity,
            cursor_rows=(self.cursor,),
            episode_heads=(self.initial_head,),
        )
        successor = episode_review.create_episode_revision(
            episode([TURN_A, TURN_B]),
            identity_key=self.identity,
            key_id=self.identity.key_id,
            previous_revision=self.initial_head,
        )
        advanced_cursor = cursor_row("2026-07-01T02:00:00Z", "two")

        manifest = self.manifest(
            previous,
            cursor_rows=[advanced_cursor],
            episode_heads=[successor],
        )

        authority.validate_durable_state_transition(
            previous,
            manifest,
            identity=self.identity,
        )
        self.assertEqual(2, successor["revision_ordinal"])
        self.assertEqual(
            self.initial_head["episode_revision_ref"],
            successor["supersedes_episode_revision_ref"],
        )

    def test_transition_rejects_boolean_provider_revisions(self) -> None:
        previous = history_state(self.identity)
        manifest = self.manifest(
            previous,
            cursor_rows=[],
            episode_heads=[],
        )

        for field in ("provider_revision_before", "provider_revision_after"):
            with self.subTest(field=field):
                malformed = dict(manifest)
                malformed[field] = True
                with self.assertRaisesRegex(
                    authority.HistoryValidationError,
                    "provider revision is invalid",
                ):
                    authority.validate_durable_state_transition(
                        previous,
                        malformed,
                        identity=self.identity,
                    )

    def test_transition_rejects_cursor_deletion_rollback_and_head_rollback(
        self,
    ) -> None:
        previous = history_state(
            self.identity,
            cursor_rows=(self.cursor,),
            episode_heads=(self.initial_head,),
        )
        with self.assertRaisesRegex(
            authority.HistoryValidationError, "removes existing host"
        ):
            self.manifest(
                previous,
                cursor_rows=[],
                episode_heads=[self.initial_head],
            )
        with self.assertRaisesRegex(authority.HistoryValidationError, "rolls back"):
            self.manifest(
                previous,
                cursor_rows=[cursor_row("2026-07-01T00:30:00Z", "older")],
                episode_heads=[self.initial_head],
            )
        with self.assertRaisesRegex(
            authority.HistoryValidationError, "without correction lineage"
        ):
            self.manifest(previous, cursor_rows=[self.cursor], episode_heads=[])

        successor = episode_review.create_episode_revision(
            episode([TURN_A, TURN_B]),
            identity_key=self.identity,
            key_id=self.identity.key_id,
            previous_revision=self.initial_head,
        )
        advanced_history = history_state(
            self.identity,
            cursor_rows=(self.cursor,),
            episode_heads=(successor,),
            provider_revision=1,
            head_commit="b" * 40,
        )
        with self.assertRaisesRegex(
            authority.HistoryValidationError, "cannot remove published membership"
        ):
            self.manifest(
                advanced_history,
                cursor_rows=[self.cursor],
                episode_heads=[self.initial_head],
            )

    def test_explicit_correction_conserves_membership_and_uses_new_heads(
        self,
    ) -> None:
        combined = episode_review.create_episode_revision(
            episode([TURN_A, TURN_B]),
            identity_key=self.identity,
            key_id=self.identity.key_id,
        )
        previous = history_state(self.identity, episode_heads=(combined,))
        correction_ref = episode_review.derive_episode_correction_generation(
            self.identity,
            [combined["episode_ref"]],
            [[TURN_A], [TURN_B]],
            correction_ordinal=1,
        )
        successors = []
        for turn_ref in (TURN_A, TURN_B):
            episode_ref = episode_review.derive_corrected_episode_ref(
                self.identity,
                correction_ref,
                [turn_ref],
            )
            successors.append(
                episode_review.create_episode_revision(
                    episode([turn_ref]),
                    identity_key=self.identity,
                    key_id=self.identity.key_id,
                    episode_ref=episode_ref,
                )
            )
        successors.sort(key=lambda row: row["episode_ref"])
        correction = {
            "correction_ordinal": 1,
            "correction_ref": correction_ref,
            "predecessor_episode_refs": [combined["episode_ref"]],
            "segmentation_major_version": "2",
            "successor_episode_refs": sorted(row["episode_ref"] for row in successors),
        }

        manifest = self.manifest(
            previous,
            cursor_rows=[],
            episode_heads=successors,
            episode_corrections=[correction],
        )

        self.assertEqual([correction], manifest["episode_corrections"])
        authority.validate_durable_state_transition(
            previous,
            manifest,
            identity=self.identity,
        )

        forged = {**correction, "correction_ref": ref("episode_correction", "forged")}
        with self.assertRaisesRegex(
            authority.HistoryValidationError, "does not commit"
        ):
            self.manifest(
                previous,
                cursor_rows=[],
                episode_heads=successors,
                episode_corrections=[forged],
            )


class ProviderIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        os.chmod(self.root, 0o700)
        self.identity = IdentityKey(b"p" * 32)
        self.foreign_identity = IdentityKey(b"q" * 32)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_initialization_rejects_foreign_history_before_persisting(self) -> None:
        state_dir = self.root / "provider"
        foreign_history = history_state(self.foreign_identity)

        with self.assertRaisesRegex(
            authority.ProviderCacheError, "foreign identity_key_id"
        ):
            authority.initialize_provider_cache(
                state_dir,
                history=foreign_history,
                expected_revision=0,
                identity=self.identity,
            )

        self.assertFalse(state_dir.exists())

    def test_derivation_rejects_foreign_previous_or_published_identity(self) -> None:
        state_dir = self.root / "provider"
        previous = history_state(self.identity)
        published = history_state(
            self.identity,
            provider_revision=1,
            head_commit="b" * 40,
        )
        authority.initialize_provider_cache(
            state_dir,
            history=previous,
            expected_revision=0,
            identity=self.identity,
        )

        for label, prior, successor in (
            (
                "previous",
                replace(previous, identity_key_id=self.foreign_identity.key_id),
                published,
            ),
            (
                "published",
                previous,
                replace(published, identity_key_id=self.foreign_identity.key_id),
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    authority.ProviderCacheError, "foreign identity_key_id"
                ):
                    authority.derive_provider_cache(
                        state_dir,
                        previous=prior,
                        published=successor,
                        identity=self.identity,
                    )

        cached = authority.assert_provider_cache_matches(
            state_dir,
            previous,
            identity=self.identity,
        )
        self.assertEqual(previous.head_commit, cached["history_commit"])


if __name__ == "__main__":
    unittest.main()
