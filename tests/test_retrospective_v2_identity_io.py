from __future__ import annotations

import base64
from collections.abc import Callable
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
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

from retrospective_v2.contracts import (  # noqa: E402
    JobKind,
    MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
    RefType,
    RunMode,
    RunStage,
    SESSION_SHARDS_RESUME_CURSOR_PREFIX,
    SESSION_SHARDS_SOURCE_TOKEN_PREFIX,
    SessionShardsRequest,
    SourceKind,
    TypedRef,
    canonical_json,
    canonical_json_bytes,
    canonical_sha256,
    parse_typed_ref,
    session_shards_resume_cursor,
    session_shards_resume_cursor_value,
)
from retrospective_v2.identity import (  # noqa: E402
    IDENTITY_KEY_ID_PREFIX,
    IdentityKey,
    IdentityKeyFormatError,
    IdentityKeyMismatchError,
    IdentityKeyMissingError,
)
from retrospective_v2 import safe_io  # noqa: E402
from retrospective_v2.safe_io import (  # noqa: E402
    InvalidJsonError,
    ReadLimitExceeded,
    UnsafePathError,
    atomic_create_bytes,
    atomic_create_bytes_with_receipt,
    atomic_write_bytes,
    atomic_write_json,
    read_bounded_bytes,
    read_bounded_json,
    read_bounded_jsonl,
    remove_atomic_created_bytes,
    require_secure_io_capabilities,
    secure_io_capability_issues,
)


class ContractTests(unittest.TestCase):
    def test_canonical_json_and_hash_are_deterministic(self) -> None:
        first = {"z": [True, None, 3], "a": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"}
        second = {"a": "caf\N{LATIN SMALL LETTER E WITH ACUTE}", "z": [True, None, 3]}

        expected = '{"a":"caf\N{LATIN SMALL LETTER E WITH ACUTE}","z":[true,null,3]}'
        self.assertEqual(expected, canonical_json(first))
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(
            hashlib.sha256(expected.encode("utf-8")).hexdigest(),
            canonical_sha256(first),
        )

    def test_canonical_json_rejects_non_finite_numbers(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({"not_json": float("nan")})
        with self.assertRaises(TypeError):
            canonical_json({1: "non-string key"})  # type: ignore[dict-item]

    def test_contract_enums_are_closed(self) -> None:
        self.assertIs(RunMode("weekly"), RunMode.WEEKLY)
        self.assertIs(RunStage("extraction"), RunStage.EXTRACTION)
        self.assertIs(JobKind("episode_reviewer"), JobKind.EPISODE_REVIEWER)
        self.assertIs(SourceKind("archived_rollout"), SourceKind.ARCHIVED_ROLLOUT)
        for enum_type in (RunMode, RunStage, JobKind, SourceKind):
            with self.assertRaises(ValueError):
                enum_type("future_unreviewed_value")

    def test_typed_refs_require_a_closed_type_and_full_sha256(self) -> None:
        reference = TypedRef(RefType.TURN, "a" * 64)

        self.assertEqual(f"turn_ref_v2:{'a' * 64}", str(reference))
        self.assertEqual(reference, TypedRef.parse(str(reference)))
        self.assertEqual(
            reference, parse_typed_ref(str(reference), expected=RefType.TURN)
        )
        with self.assertRaises(ValueError):
            parse_typed_ref(str(reference), expected=RefType.SESSION)
        with self.assertRaises(ValueError):
            TypedRef(RefType.TURN, "a" * 63)
        with self.assertRaises(ValueError):
            TypedRef(RefType.TURN, "A" * 64)
        with self.assertRaises(ValueError):
            TypedRef.parse(f"unknown_ref_v2:{'a' * 64}")

    def test_resume_cursor_signature_binds_token_and_coordinates(self) -> None:
        source_token = SESSION_SHARDS_SOURCE_TOKEN_PREFIX + "a" * 64
        prefix_commitment = "sha256:" + hashlib.sha256(b"frozen-prefix").hexdigest()
        cursor = session_shards_resume_cursor(
            source_token,
            cursor_kind="records",
            frozen_byte_end=256,
            byte_offset=128,
            next_record_index=7,
            prefix_commitment=prefix_commitment,
        )
        request = SessionShardsRequest(
            rollout="sessions/rollout.jsonl",
            mode="records",
            source_token=source_token,
            byte_start=128,
            byte_end=256,
            shard_bytes=128,
            max_shards=1,
            record_processing_budget_bytes=(MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES),
            resume_cursor=cursor,
        )

        self.assertEqual(7, request.record_start)
        page_request = SessionShardsRequest(
            rollout="sessions/rollout.jsonl",
            mode="records",
            source_token=source_token,
            byte_start=128,
            byte_end=192,
            shard_bytes=128,
            max_shards=1,
            record_processing_budget_bytes=(MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES),
            resume_cursor=cursor,
        )
        self.assertEqual(192, page_request.byte_end)
        with self.assertRaisesRegex(ValueError, "frozen byte end"):
            SessionShardsRequest(
                rollout="sessions/rollout.jsonl",
                mode="records",
                source_token=source_token,
                byte_start=128,
                byte_end=257,
                shard_bytes=128,
                max_shards=1,
                record_processing_budget_bytes=(
                    MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
                ),
                resume_cursor=cursor,
            )
        self.assertTrue(cursor.startswith(SESSION_SHARDS_RESUME_CURSOR_PREFIX))
        self.assertEqual(
            {
                "byte_offset": 128,
                "cursor_kind": "records",
                "frozen_byte_end": 256,
                "next_record_index": 7,
                "prefix_commitment": prefix_commitment,
                "source_token": source_token,
            },
            session_shards_resume_cursor_value(cursor),
        )

        encoded, signature = cursor.removeprefix(
            SESSION_SHARDS_RESUME_CURSOR_PREFIX
        ).split(".", 1)
        payload = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        payload["next_record_index"] = 70_000
        forged_payload = (
            base64.urlsafe_b64encode(canonical_json_bytes(payload))
            .decode("ascii")
            .rstrip("=")
        )
        for forged in (
            cursor[:-1] + ("0" if cursor[-1] != "0" else "1"),
            SESSION_SHARDS_RESUME_CURSOR_PREFIX + forged_payload + "." + signature,
        ):
            with self.subTest(forged=forged[-64:]):
                with self.assertRaisesRegex(ValueError, "signature"):
                    SessionShardsRequest(
                        rollout="sessions/rollout.jsonl",
                        mode="records",
                        source_token=source_token,
                        byte_start=128,
                        byte_end=256,
                        shard_bytes=128,
                        max_shards=1,
                        record_processing_budget_bytes=(
                            MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES
                        ),
                        resume_cursor=forged,
                    )


class SafeIoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        os.chmod(self.root, 0o700)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _add_darwin_acl(self, path: Path, entry: str = "everyone allow read") -> None:
        subprocess.run(
            ["/bin/chmod", "+a", entry, os.fspath(path)],
            check=True,
            capture_output=True,
        )

    def _remove_darwin_acl(self, path: Path) -> None:
        subprocess.run(
            ["/bin/chmod", "-N", os.fspath(path)],
            check=True,
            capture_output=True,
        )

    @staticmethod
    def _inventory_budget(
        *,
        entries: int = 100,
        path_bytes: int = 4096,
        depth: int = 8,
    ) -> safe_io.TreeInventoryBudget:
        return safe_io.TreeInventoryBudget.from_timeout(
            max_entries=entries,
            max_path_bytes=path_bytes,
            max_depth=depth,
            timeout_seconds=30.0,
        )

    def test_capability_probe_uses_real_dir_fd_operations_and_fails_closed(
        self,
    ) -> None:
        safe_io._cached_dir_fd_capability_issues.cache_clear()
        try:
            with mock.patch.object(os, "supports_dir_fd", set()):
                self.assertEqual((), secure_io_capability_issues())

            safe_io._cached_dir_fd_capability_issues.cache_clear()
            with mock.patch.object(
                safe_io,
                "_run_dir_fd_smoke_probe",
                return_value=("simulated_probe_failure",),
            ):
                with self.assertRaisesRegex(UnsafePathError, "simulated_probe_failure"):
                    require_secure_io_capabilities()
        finally:
            safe_io._cached_dir_fd_capability_issues.cache_clear()
            require_secure_io_capabilities()

    def test_atomic_json_write_creates_owner_only_paths_and_replaces(self) -> None:
        target = self.root / "state" / "checkpoint.json"

        atomic_write_json(target, {"generation": 1, "status": "created"})
        atomic_write_json(target, {"generation": 2, "status": "complete"})

        self.assertEqual(
            {"generation": 2, "status": "complete"},
            read_bounded_json(target, max_bytes=1024),
        )
        self.assertEqual(0o700, stat.S_IMODE(target.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
        self.assertEqual([], list(target.parent.glob(".*.tmp")))

    def test_cleanup_inventory_uses_global_bytewise_path_order(self) -> None:
        tree = self.root / "cleanup"
        nested = tree / "a"
        tree.mkdir(mode=0o700)
        nested.mkdir(mode=0o700)
        atomic_write_bytes(nested / "child", b"nested\n")
        atomic_write_bytes(tree / "a.", b"sibling\n")
        parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            snapshot = safe_io.inspect_tree_inventory_at(
                parent_fd,
                tree.name,
                budget=self._inventory_budget(),
                display_path=tree,
            )
        finally:
            os.close(parent_fd)

        self.assertEqual(
            [".", "a", "a.", "a/child"],
            [entry["relative_path"] for entry in snapshot["entries"]],
        )

    def test_cleanup_inventory_budget_is_shared_across_actual_trees(self) -> None:
        for name in ("first", "second"):
            tree = self.root / name
            tree.mkdir(mode=0o700)
            atomic_write_bytes(tree / "child", b"payload\n")
        parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        budget = self._inventory_budget(entries=3)
        try:
            safe_io.inspect_tree_inventory_at(
                parent_fd,
                "first",
                budget=budget,
                display_path=self.root / "first",
            )
            with self.assertRaisesRegex(
                safe_io.TreeInventoryLimitExceeded,
                "entry bound",
            ):
                safe_io.inspect_tree_inventory_at(
                    parent_fd,
                    "second",
                    budget=budget,
                    display_path=self.root / "second",
                )
        finally:
            os.close(parent_fd)

    def test_cleanup_inventory_rejects_actual_path_depth_and_deadline_limits(
        self,
    ) -> None:
        tree = self.root / "bounded"
        nested = tree / "nested"
        tree.mkdir(mode=0o700)
        nested.mkdir(mode=0o700)
        atomic_write_bytes(nested / "child", b"payload\n")
        parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            cases = (
                (self._inventory_budget(path_bytes=1), "path-byte bound"),
                (self._inventory_budget(depth=0), "depth bound"),
                (
                    safe_io.TreeInventoryBudget(
                        max_entries=100,
                        max_path_bytes=4096,
                        max_depth=8,
                        deadline=1.0,
                        clock=lambda: 1.0,
                    ),
                    "deadline",
                ),
            )
            for budget, reason in cases:
                with (
                    self.subTest(reason=reason),
                    self.assertRaisesRegex(
                        safe_io.TreeInventoryLimitExceeded,
                        reason,
                    ),
                ):
                    safe_io.inspect_tree_inventory_at(
                        parent_fd,
                        tree.name,
                        budget=budget,
                        display_path=tree,
                    )
        finally:
            os.close(parent_fd)

    def test_cleanup_inventory_rejects_fifo_without_blocking(self) -> None:
        tree = self.root / "fifo-tree"
        tree.mkdir(mode=0o700)
        fifo = tree / "blocked"
        os.mkfifo(fifo, 0o600)
        parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(UnsafePathError, "regular file"):
                safe_io.inspect_tree_inventory_at(
                    parent_fd,
                    tree.name,
                    budget=self._inventory_budget(),
                    display_path=tree,
                )
        finally:
            os.close(parent_fd)
        self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))

    def test_checked_file_open_rejects_regular_to_fifo_swap_nonblocking(self) -> None:
        target = self.root / "swapped"
        target.write_bytes(b"regular\n")
        os.chmod(target, 0o600)
        parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        original_open = safe_io.os.open
        observed_flags: list[int] = []
        swapped = False

        def swap_then_open(name, flags, *args, **kwargs):
            nonlocal swapped
            if name == target.name and not swapped:
                swapped = True
                target.unlink()
                os.mkfifo(target, 0o600)
                observed_flags.append(flags)
            return original_open(name, flags, *args, **kwargs)

        try:
            with (
                mock.patch.object(safe_io.os, "open", side_effect=swap_then_open),
                self.assertRaisesRegex(UnsafePathError, "regular file"),
            ):
                safe_io.open_checked_file_at(
                    parent_fd,
                    target.name,
                    display_path=target,
                    require_owner_only=True,
                )
        finally:
            os.close(parent_fd)
        self.assertTrue(swapped)
        self.assertTrue(observed_flags[0] & os.O_NONBLOCK)
        self.assertTrue(stat.S_ISFIFO(target.lstat().st_mode))

    def test_atomic_create_never_replaces_an_existing_file(self) -> None:
        target = self.root / "identity.key"
        atomic_create_bytes(target, b"first\n")

        with self.assertRaises(FileExistsError):
            atomic_create_bytes(target, b"second\n")

        self.assertEqual(b"first\n", target.read_bytes())

    def test_atomic_create_receipt_rejects_same_content_object_replacement(
        self,
    ) -> None:
        target = self.root / "staged.json"
        receipt = atomic_create_bytes_with_receipt(target, b'{"value":1}\n')
        original_inode = target.stat().st_ino
        replacement = self.root / "replacement.json"
        replacement.write_bytes(b'{"value":1}\n')
        os.chmod(replacement, 0o600)
        self.assertNotEqual(original_inode, replacement.stat().st_ino)
        os.replace(replacement, target)
        self.assertNotEqual(original_inode, target.stat().st_ino)

        with self.assertRaisesRegex(UnsafePathError, "target changed"):
            remove_atomic_created_bytes(receipt)

        self.assertEqual(b'{"value":1}\n', target.read_bytes())

    def test_atomic_create_receipt_allows_benign_parent_child_churn(self) -> None:
        target = self.root / "staged.json"
        receipt = atomic_create_bytes_with_receipt(target, b"payload\n")
        sibling = self.root / "benign-sibling"
        sibling.write_bytes(b"temporary\n")
        sibling.unlink()

        remove_atomic_created_bytes(receipt)

        self.assertFalse(target.exists())

    def test_atomic_create_slot_rolls_back_linked_base_exception(self) -> None:
        class PublicationInterrupted(BaseException):
            pass

        target = self.root / "interrupted.json"
        slot = safe_io.AtomicCreateReceiptSlot()
        original_link = safe_io.os.link

        def link_then_interrupt(*args, **kwargs):
            original_link(*args, **kwargs)
            if args[1] == target.name:
                raise PublicationInterrupted

        with (
            mock.patch.object(safe_io.os, "link", side_effect=link_then_interrupt),
            self.assertRaises(PublicationInterrupted),
        ):
            atomic_create_bytes_with_receipt(
                target,
                b"sensitive\n",
                receipt_slot=slot,
            )

        self.assertIsNotNone(slot.receipt)
        pending = self.root / slot.receipt.pending_name
        self.assertTrue(target.is_file())
        self.assertTrue(pending.is_file())
        self.assertEqual(target.stat().st_ino, pending.stat().st_ino)
        remove_atomic_created_bytes(slot.receipt)
        self.assertFalse(target.exists())
        self.assertFalse(pending.exists())

    def test_atomic_create_slot_rolls_back_post_publish_base_exception(self) -> None:
        class PublicationInterrupted(BaseException):
            pass

        target = self.root / "post-publish.json"
        slot = safe_io.AtomicCreateReceiptSlot()
        original_hash = safe_io._hash_file_descriptor

        def interrupt_final_hash(descriptor, **kwargs):
            if slot.receipt is not None and target.exists():
                raise PublicationInterrupted
            return original_hash(descriptor, **kwargs)

        with (
            mock.patch.object(
                safe_io,
                "_hash_file_descriptor",
                side_effect=interrupt_final_hash,
            ),
            self.assertRaises(PublicationInterrupted),
        ):
            atomic_create_bytes_with_receipt(
                target,
                b"sensitive\n",
                receipt_slot=slot,
            )

        self.assertIsNotNone(slot.receipt)
        self.assertTrue(target.is_file())
        self.assertFalse((self.root / slot.receipt.pending_name).exists())
        remove_atomic_created_bytes(slot.receipt)
        self.assertFalse(target.exists())

    def test_atomic_create_uses_one_persistent_lock_per_directory(self) -> None:
        first = atomic_create_bytes_with_receipt(self.root / "first.json", b"one\n")
        second = atomic_create_bytes_with_receipt(self.root / "second.json", b"two\n")

        locks = list(self.root.glob(".atomic-create-*.lock"))

        self.assertEqual(
            [".atomic-create-directory.lock"], [item.name for item in locks]
        )
        remove_atomic_created_bytes(first)
        remove_atomic_created_bytes(second)
        self.assertEqual(
            [".atomic-create-directory.lock"],
            [item.name for item in self.root.glob(".atomic-create-*.lock")],
        )

    def test_atomic_create_rollback_close_failure_cannot_reverse_unlink(self) -> None:
        target = self.root / "staged.json"
        receipt = atomic_create_bytes_with_receipt(target, b"payload\n")
        original_open = safe_io.open_checked_file_at
        original_close = os.close
        target_descriptor: int | None = None
        close_failed = False

        def capture_target_descriptor(*args, **kwargs):
            nonlocal target_descriptor
            descriptor = original_open(*args, **kwargs)
            if kwargs.get("display_path") == target:
                target_descriptor = descriptor
            return descriptor

        def close_then_fail(descriptor: int) -> None:
            nonlocal close_failed
            original_close(descriptor)
            if descriptor == target_descriptor and not close_failed:
                close_failed = True
                raise OSError("simulated post-unlink close failure")

        with (
            mock.patch.object(
                safe_io,
                "open_checked_file_at",
                side_effect=capture_target_descriptor,
            ),
            mock.patch.object(safe_io.os, "close", side_effect=close_then_fail),
        ):
            remove_atomic_created_bytes(receipt)

        self.assertTrue(close_failed)
        self.assertFalse(target.exists())

    def test_atomic_create_close_failure_releases_lock_before_raising(self) -> None:
        target = self.root / "close-failure.json"
        slot = safe_io.AtomicCreateReceiptSlot()
        original_hash = safe_io._hash_file_descriptor
        original_close = os.close
        target_descriptor: int | None = None
        close_failed = False

        def capture_final_descriptor(descriptor: int, **kwargs) -> str:
            nonlocal target_descriptor
            if slot.receipt is not None and target.exists():
                target_descriptor = descriptor
            return original_hash(descriptor, **kwargs)

        def close_then_fail(descriptor: int) -> None:
            nonlocal close_failed
            original_close(descriptor)
            if descriptor == target_descriptor and not close_failed:
                close_failed = True
                raise OSError("simulated atomic-create close failure")

        with (
            mock.patch.object(
                safe_io,
                "_hash_file_descriptor",
                side_effect=capture_final_descriptor,
            ),
            mock.patch.object(safe_io.os, "close", side_effect=close_then_fail),
            self.assertRaisesRegex(OSError, "atomic-create close failure"),
        ):
            atomic_create_bytes_with_receipt(
                target,
                b"payload\n",
                receipt_slot=slot,
            )

        self.assertTrue(close_failed)
        self.assertIsNotNone(slot.receipt)
        remove_atomic_created_bytes(slot.receipt)
        followup = atomic_create_bytes_with_receipt(
            self.root / "followup.json",
            b"followup\n",
        )
        remove_atomic_created_bytes(followup)

    def test_atomic_create_receipt_rejects_parent_replacement(self) -> None:
        parent = self.root / "created-parent"
        parent.mkdir(mode=0o700)
        target = parent / "staged.json"
        receipt = atomic_create_bytes_with_receipt(target, b"payload\n")
        original_parent = self.root / "original-parent"
        parent.rename(original_parent)
        parent.mkdir(mode=0o700)
        replacement = parent / target.name
        replacement.write_bytes(b"payload\n")
        os.chmod(replacement, 0o600)

        with self.assertRaisesRegex(UnsafePathError, "parent changed"):
            remove_atomic_created_bytes(receipt)

        self.assertTrue((original_parent / target.name).is_file())
        self.assertTrue(replacement.is_file())

    def test_failed_atomic_write_removes_its_temporary_file(self) -> None:
        target = self.root / "failed.json"
        with mock.patch(
            "retrospective_v2.safe_io.os.write",
            side_effect=OSError("simulated write failure"),
        ):
            with self.assertRaises(OSError):
                atomic_write_bytes(target, b"payload")

        self.assertFalse(target.exists())
        self.assertEqual([], list(self.root.glob(".*.tmp")))

    def test_ancestor_substitution_cannot_redirect_an_openat_chain(self) -> None:
        require_secure_io_capabilities()
        trusted = self.root / "trusted"
        pinned = self.root / "trusted-pinned"
        attacker = self.root / "attacker"
        trusted.mkdir(mode=0o700)
        attacker.mkdir(mode=0o700)
        real_open = os.open
        swapped = False

        def racing_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if path == "trusted" and dir_fd is not None and not swapped:
                trusted.rename(pinned)
                trusted.symlink_to(attacker, target_is_directory=True)
                swapped = True
            return descriptor

        target = trusted / "nested" / "state.json"
        with mock.patch("retrospective_v2.safe_io.os.open", side_effect=racing_open):
            atomic_write_bytes(target, b'{"safe":true}\n')

        self.assertTrue(swapped)
        self.assertFalse((attacker / "nested" / "state.json").exists())
        self.assertEqual(
            b'{"safe":true}\n',
            (pinned / "nested" / "state.json").read_bytes(),
        )

    def test_write_rejects_insecure_parent_and_symlink_target(self) -> None:
        insecure_parent = self.root / "insecure"
        insecure_parent.mkdir(mode=0o700)
        os.chmod(insecure_parent, 0o755)
        with self.assertRaises(UnsafePathError):
            atomic_write_bytes(insecure_parent / "state.json", b"{}\n")

        real_target = self.root / "real.json"
        atomic_write_bytes(real_target, b"{}\n")
        symlink_target = self.root / "link.json"
        symlink_target.symlink_to(real_target)
        with self.assertRaises(UnsafePathError):
            atomic_write_bytes(symlink_target, b'{"changed":true}\n')
        self.assertEqual(b"{}\n", real_target.read_bytes())

    def test_reads_reject_insecure_files_and_symlinks(self) -> None:
        target = self.root / "state.json"
        atomic_write_bytes(target, b"{}\n")
        os.chmod(target, 0o644)
        with self.assertRaises(UnsafePathError):
            read_bounded_json(target)

        os.chmod(target, 0o600)
        symlink = self.root / "state-link.json"
        symlink.symlink_to(target)
        with self.assertRaises(UnsafePathError):
            read_bounded_json(symlink)

        hard_link = self.root / "state-hard-link.json"
        os.link(target, hard_link)
        with self.assertRaises(UnsafePathError):
            read_bounded_json(target)

    def test_json_and_jsonl_reads_enforce_all_limits(self) -> None:
        document = self.root / "document.json"
        atomic_write_bytes(document, b'{"value":"bounded"}\n')
        with self.assertRaises(ReadLimitExceeded):
            read_bounded_json(document, max_bytes=8)

        records = self.root / "records.jsonl"
        atomic_write_bytes(records, b'{"n":1}\n{"n":2}\n{"n":3}\n')
        self.assertEqual(
            [{"n": 1}, {"n": 2}, {"n": 3}],
            read_bounded_jsonl(
                records,
                max_bytes=128,
                max_lines=3,
                max_line_bytes=16,
            ),
        )
        with self.assertRaises(ReadLimitExceeded):
            read_bounded_jsonl(records, max_bytes=128, max_lines=2)
        with self.assertRaises(ReadLimitExceeded):
            read_bounded_jsonl(records, max_bytes=128, max_line_bytes=4)

    def test_jsonl_rejects_blank_and_malformed_records(self) -> None:
        blank = self.root / "blank.jsonl"
        atomic_write_bytes(blank, b"{}\n\n{}\n")
        with self.assertRaises(InvalidJsonError):
            read_bounded_jsonl(blank)

        malformed = self.root / "malformed.jsonl"
        atomic_write_bytes(malformed, b"{}\nnot-json\n")
        with self.assertRaises(InvalidJsonError):
            read_bounded_jsonl(malformed)

    def test_json_reads_reject_duplicate_keys_and_nonfinite_numbers(self) -> None:
        duplicate = self.root / "duplicate.json"
        atomic_write_bytes(duplicate, b'{"same":1,"same":2}\n')
        with self.assertRaises(InvalidJsonError):
            read_bounded_json(duplicate)

        for index, payload in enumerate(
            (b'{"n":NaN}\n', b'{"n":Infinity}\n', b'{"n":1e999}\n')
        ):
            target = self.root / f"nonfinite-{index}.json"
            atomic_write_bytes(target, payload)
            with self.assertRaises(InvalidJsonError):
                read_bounded_json(target)

        records = self.root / "strict.jsonl"
        atomic_write_bytes(records, b'{"same":1,"same":2}\n')
        with self.assertRaises(InvalidJsonError):
            read_bounded_jsonl(records)

    def test_bounded_read_rejects_concurrent_metadata_and_content_changes(
        self,
    ) -> None:
        target = self.root / "racing.bin"
        original = b"a" * (64 * 1024 + 32)
        replacement = b"b" * len(original)
        atomic_write_bytes(target, original)
        real_read = os.read

        appended = False

        def read_and_grow(descriptor: int, size: int) -> bytes:
            nonlocal appended
            chunk = real_read(descriptor, size)
            if chunk and not appended:
                appended = True
                with target.open("ab") as stream:
                    stream.write(b"x")
                    stream.flush()
                    os.fsync(stream.fileno())
            return chunk

        with mock.patch(
            "retrospective_v2.safe_io.os.read",
            side_effect=read_and_grow,
        ):
            with self.assertRaisesRegex(UnsafePathError, "changed while reading"):
                read_bounded_bytes(target, max_bytes=len(original) + 1)

        def racing_reader() -> Callable[[int, int], bytes]:
            changed = False

            def read_and_replace(descriptor: int, size: int) -> bytes:
                nonlocal changed
                chunk = real_read(descriptor, size)
                if chunk and not changed:
                    changed = True
                    with target.open("r+b") as stream:
                        stream.seek(0)
                        stream.write(replacement)
                        stream.flush()
                        os.fsync(stream.fileno())
                return chunk

            return read_and_replace

        atomic_write_bytes(target, original)
        with mock.patch(
            "retrospective_v2.safe_io.os.read",
            side_effect=racing_reader(),
        ):
            with self.assertRaisesRegex(UnsafePathError, "changed while reading"):
                read_bounded_bytes(target, max_bytes=len(original))

        atomic_write_bytes(target, original)
        with (
            mock.patch(
                "retrospective_v2.safe_io.os.read",
                side_effect=racing_reader(),
            ),
            mock.patch(
                "retrospective_v2.safe_io._bounded_read_identity",
                return_value=(1,),
            ),
        ):
            with self.assertRaisesRegex(
                UnsafePathError, "content changed while reading"
            ):
                read_bounded_bytes(target, max_bytes=len(original))

    def test_bounded_read_distinguishes_benign_timestamps_from_policy(self) -> None:
        target = self.root / "metadata.bin"
        original = b"a" * (64 * 1024 + 32)
        atomic_write_bytes(target, original)
        real_read = os.read
        touched = False

        def read_and_touch(descriptor: int, size: int) -> bytes:
            nonlocal touched
            chunk = real_read(descriptor, size)
            if chunk and not touched:
                touched = True
                metadata = target.stat()
                os.utime(
                    target,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                )
            return chunk

        with mock.patch(
            "retrospective_v2.safe_io.os.read",
            side_effect=read_and_touch,
        ):
            self.assertEqual(
                original,
                read_bounded_bytes(target, max_bytes=len(original)),
            )

        policy_changed = False

        def read_and_widen_mode(descriptor: int, size: int) -> bytes:
            nonlocal policy_changed
            chunk = real_read(descriptor, size)
            if chunk and not policy_changed:
                policy_changed = True
                os.chmod(target, 0o640)
            return chunk

        try:
            with (
                mock.patch(
                    "retrospective_v2.safe_io.os.read",
                    side_effect=read_and_widen_mode,
                ),
                self.assertRaisesRegex(UnsafePathError, "file mode must be 0o600"),
            ):
                read_bounded_bytes(target, max_bytes=len(original))
        finally:
            os.chmod(target, 0o600)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin ACL behavior")
    def test_darwin_existing_owner_only_paths_reject_extended_acls(self) -> None:
        directory = self.root / "acl-directory"
        directory.mkdir(mode=0o700)
        target = self.root / "acl-file"
        atomic_write_bytes(target, b"payload")

        self._add_darwin_acl(directory)
        self._add_darwin_acl(target)
        try:
            with self.assertRaisesRegex(UnsafePathError, "extended ACL"):
                safe_io.check_owner_only_directory(directory)
            with self.assertRaisesRegex(UnsafePathError, "extended ACL"):
                read_bounded_bytes(target, max_bytes=64)
        finally:
            self._remove_darwin_acl(directory)
            self._remove_darwin_acl(target)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin ACL behavior")
    def test_darwin_creation_clears_inherited_extended_acls(self) -> None:
        inheriting = self.root / "inheriting"
        inheriting.mkdir(mode=0o700)
        self._add_darwin_acl(
            inheriting,
            "everyone allow read,file_inherit,directory_inherit",
        )
        try:
            created = inheriting / "created" / "state"
            atomic_write_bytes(created, b"payload")
            directory_fd = os.open(created.parent, safe_io._DIRECTORY_FLAGS)
            file_fd = os.open(created, os.O_RDONLY | safe_io._FILE_NOFOLLOW)
            try:
                safe_io.validate_owner_only_directory_descriptor(
                    directory_fd,
                    created.parent,
                )
                safe_io.validate_owner_only_file_descriptor(file_fd, created)
            finally:
                os.close(file_fd)
                os.close(directory_fd)

            cleared: list[Path] = []
            real_clear = safe_io._clear_darwin_extended_acl

            def observe_clear(descriptor: int, display_path: Path) -> None:
                cleared.append(display_path)
                real_clear(descriptor, display_path)

            with mock.patch.object(
                safe_io,
                "_clear_darwin_extended_acl",
                side_effect=observe_clear,
            ):
                atomic_write_bytes(created, b"replacement")
                atomic_create_bytes(inheriting / "created" / "identity", b"key")

            self.assertTrue(any("atomic-write" in path.name for path in cleared))
            self.assertTrue(any(path.name.endswith(".lock") for path in cleared))
            self.assertTrue(any(path.name.endswith(".tmp") for path in cleared))
        finally:
            self._remove_darwin_acl(inheriting)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin ACL behavior")
    def test_darwin_bounded_read_rejects_late_acl_policy_change(self) -> None:
        target = self.root / "late-acl"
        payload = b"x" * (64 * 1024 + 32)
        atomic_write_bytes(target, payload)
        real_read = os.read
        changed = False

        def read_and_add_acl(descriptor: int, size: int) -> bytes:
            nonlocal changed
            chunk = real_read(descriptor, size)
            if chunk and not changed:
                changed = True
                self._add_darwin_acl(target)
            return chunk

        try:
            with (
                mock.patch.object(safe_io.os, "read", side_effect=read_and_add_acl),
                self.assertRaisesRegex(UnsafePathError, "extended ACL"),
            ):
                read_bounded_bytes(target, max_bytes=len(payload))
        finally:
            self._remove_darwin_acl(target)

    def test_darwin_acl_query_distinguishes_absence_from_failure(self) -> None:
        class FakeAclApi:
            def __init__(self, error_number: int) -> None:
                self.error_number = error_number

            def acl_get_fd_np(self, _descriptor: int, _acl_type: int) -> None:
                ctypes.set_errno(self.error_number)
                return None

        with mock.patch.object(
            safe_io,
            "_darwin_acl_api",
            return_value=FakeAclApi(errno.ENOENT),
        ):
            self.assertFalse(safe_io._darwin_descriptor_has_extended_acl(1))
        with mock.patch.object(
            safe_io,
            "_darwin_acl_api",
            return_value=FakeAclApi(errno.EIO),
        ):
            with self.assertRaisesRegex(UnsafePathError, "could not verify"):
                safe_io._darwin_descriptor_has_extended_acl(1)

    def test_non_darwin_acl_hooks_do_not_load_libc_bindings(self) -> None:
        safe_io._darwin_acl_api.cache_clear()
        try:
            with (
                mock.patch.object(safe_io.sys, "platform", "linux"),
                mock.patch.object(safe_io, "_DarwinAclApi") as constructor,
            ):
                self.assertFalse(safe_io._darwin_descriptor_has_extended_acl(1))
                safe_io._clear_darwin_extended_acl(1, Path("synthetic"))
                constructor.assert_not_called()
        finally:
            safe_io._darwin_acl_api.cache_clear()


class IdentityKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        os.chmod(self.root, 0o700)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_load_or_create_persists_key_and_non_sensitive_key_id(self) -> None:
        target = self.root / ".codex" / "session-retrospective" / "identity-v2.key"

        created = IdentityKey.load_or_create(target)
        loaded = IdentityKey.load_or_create(target, expected_key_id=created.key_id)

        self.assertEqual(created.key_id, loaded.key_id)
        self.assertEqual(created.secret, loaded.secret)
        self.assertRegex(
            created.key_id,
            rf"^{IDENTITY_KEY_ID_PREFIX}:[0-9a-f]{{64}}$",
        )
        self.assertNotIn(
            base64.b64encode(created.secret).decode("ascii"), created.key_id
        )
        self.assertNotIn(
            base64.b64encode(created.secret).decode("ascii"), repr(created)
        )
        self.assertEqual(0o700, stat.S_IMODE(target.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))

    def test_default_path_is_resolved_at_call_time(self) -> None:
        home = self.root / "home"
        home.mkdir(mode=0o700)
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            identity = IdentityKey.load_or_create()

        expected = home / ".codex" / "session-retrospective" / "identity-v2.key"
        self.assertEqual(expected, identity.path)
        self.assertTrue(expected.is_file())

    def test_expected_key_id_mismatch_and_missing_key_block(self) -> None:
        target = self.root / "identity" / "identity-v2.key"
        created = IdentityKey.load_or_create(target)
        other_key_id = f"{IDENTITY_KEY_ID_PREFIX}:{'0' * 64}"
        self.assertNotEqual(created.key_id, other_key_id)

        with self.assertRaises(IdentityKeyMismatchError):
            IdentityKey.load_or_create(target, expected_key_id=other_key_id)
        with self.assertRaises(IdentityKeyMismatchError):
            IdentityKey.load_or_create(target, expected_key_id="not-a-key-id")
        with self.assertRaises(IdentityKeyMismatchError):
            IdentityKey.load_or_create(
                target, expected_key_id="identity_key_v2:\N{SNOWMAN}"
            )

        missing = self.root / "missing" / "identity-v2.key"
        with self.assertRaises(IdentityKeyMissingError):
            IdentityKey.load_or_create(missing, expected_key_id=created.key_id)
        self.assertFalse(missing.exists())

    def test_stored_key_id_tampering_blocks_without_replacement(self) -> None:
        target = self.root / "identity" / "identity-v2.key"
        created = IdentityKey.load_or_create(target)
        original_secret = created.secret
        record = json.loads(target.read_text(encoding="utf-8"))
        record["key_id"] = f"{IDENTITY_KEY_ID_PREFIX}:{'f' * 64}"
        atomic_write_json(target, record)

        with self.assertRaises(IdentityKeyMismatchError):
            IdentityKey.load_or_create(target)

        stored = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(
            base64.b64encode(original_secret).decode("ascii"),
            stored["secret_b64"],
        )

    def test_identity_schema_version_rejects_float_alias(self) -> None:
        target = self.root / "identity" / "identity-v2.key"
        IdentityKey.load_or_create(target)
        record = json.loads(target.read_text(encoding="utf-8"))
        record["schema_version"] = 2.0
        atomic_write_json(target, record)

        with self.assertRaises(IdentityKeyFormatError):
            IdentityKey.load(target)

    def test_missing_target_recovers_a_fully_prepared_identity_key(self) -> None:
        require_secure_io_capabilities()
        target = self.root / "identity" / "identity-v2.key"
        expected = IdentityKey(b"r" * 32)

        with mock.patch(
            "retrospective_v2.safe_io.os.link",
            side_effect=OSError("simulated crash before exclusive link"),
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                IdentityKey.create(target, secret=expected.secret)

        self.assertFalse(target.exists())
        self.assertEqual(1, len(list(target.parent.glob(".atomic-create-*.tmp"))))

        recovered = IdentityKey.load_or_create(
            target,
            expected_key_id=expected.key_id,
        )
        self.assertEqual(expected.key_id, recovered.key_id)
        self.assertEqual(expected.secret, recovered.secret)
        self.assertEqual([], list(target.parent.glob(".atomic-create-*.tmp")))

    def test_link_commit_crash_recovers_from_two_links(self) -> None:
        require_secure_io_capabilities()
        target = self.root / "identity" / "identity-v2.key"
        expected = IdentityKey(b"s" * 32)
        real_unlink = os.unlink
        injected = False

        def fail_pending_unlink(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal injected
            if (
                isinstance(path, str)
                and path.startswith(".atomic-create-")
                and path.endswith(".tmp")
                and not injected
            ):
                injected = True
                raise OSError("simulated crash after exclusive link")
            real_unlink(path, dir_fd=dir_fd)

        with mock.patch(
            "retrospective_v2.safe_io.os.unlink",
            side_effect=fail_pending_unlink,
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                IdentityKey.create(target, secret=expected.secret)

        self.assertTrue(injected)
        self.assertEqual(2, target.stat().st_nlink)
        recovered = IdentityKey.load_or_create(
            target,
            expected_key_id=expected.key_id,
        )
        self.assertEqual(expected.secret, recovered.secret)
        self.assertEqual(1, target.stat().st_nlink)

    def test_recovered_pending_key_still_enforces_expected_key_id(self) -> None:
        require_secure_io_capabilities()
        target = self.root / "identity" / "identity-v2.key"
        prepared = IdentityKey(b"t" * 32)
        expected = IdentityKey(b"u" * 32)

        with mock.patch(
            "retrospective_v2.safe_io.os.link",
            side_effect=OSError("simulated crash before exclusive link"),
        ):
            with self.assertRaises(OSError):
                IdentityKey.create(target, secret=prepared.secret)

        with self.assertRaises(IdentityKeyMismatchError):
            IdentityKey.load_or_create(target, expected_key_id=expected.key_id)
        loaded = IdentityKey.load(target, expected_key_id=prepared.key_id)
        self.assertEqual(prepared.secret, loaded.secret)

    def test_stable_refs_ignore_cwd_and_separate_hmac_domains(self) -> None:
        identity = IdentityKey(b"k" * 32)
        payload = {
            "issuer": "trusted-test-issuer",
            "session": "upstream-session",
            "timestamp": "2026-07-14T00:00:00Z",
        }
        first_directory = self.root / "first-worktree"
        second_directory = self.root / "second-worktree"
        first_directory.mkdir()
        second_directory.mkdir()
        original_cwd = Path.cwd()
        try:
            os.chdir(first_directory)
            first = identity.derive_ref(RefType.SESSION, payload)
            os.chdir(second_directory)
            second = identity.derive_ref("session", payload)
        finally:
            os.chdir(original_cwd)

        self.assertEqual(first, second)
        self.assertEqual(64, len(first.digest))
        self.assertNotEqual(
            first.digest, identity.derive_ref(RefType.TURN, payload).digest
        )
        self.assertNotEqual(
            identity.derive_digest("source/content", payload),
            identity.derive_digest("source/unit", payload),
        )
        self.assertNotEqual(
            identity.derive_ref(RefType.JOB, ["left", "right"]),
            identity.derive_ref(RefType.JOB, "left", "right"),
        )


if __name__ == "__main__":
    unittest.main()
