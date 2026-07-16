from __future__ import annotations

import json
import hashlib
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

from retrospective_v2.checkpoints import (  # noqa: E402
    AtomicCheckpointStore,
    CheckpointConflictError,
    CheckpointIntegrityError,
    CheckpointPermissionError,
)
from retrospective_v2.identity import IdentityKey  # noqa: E402
from retrospective_v2.safe_io import (  # noqa: E402
    atomic_write_bytes,
    atomic_write_json,
    require_secure_io_capabilities,
)


class CheckpointSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        require_secure_io_capabilities()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        os.chmod(self.root, 0o700)
        self.identity = IdentityKey.generate()
        self.store = AtomicCheckpointStore(
            self.root / "run",
            identity=self.identity,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _restore(self, payload: bytes) -> None:
        atomic_write_bytes(self.store.path, payload)

    def test_store_requires_an_explicit_identity_secret(self) -> None:
        with self.assertRaises(TypeError):
            AtomicCheckpointStore(self.root / "missing-key")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            AtomicCheckpointStore(
                self.root / "bad-key",
                identity="not-an-identity",  # type: ignore[arg-type]
            )
        with self.assertRaises(ValueError):
            AtomicCheckpointStore(
                self.root / "reserved-name",
                identity=self.identity,
                filename=".checkpoint.lock",
            )

    def test_closed_envelope_binds_format_revision_key_and_state(self) -> None:
        snapshot = self.store.initialize({"stage": "catalog", "value": 1})
        original = self.store.path.read_bytes()
        envelope = json.loads(original)

        self.assertEqual(
            {
                "envelope_hmac",
                "format_version",
                "key_id",
                "revision",
                "state",
            },
            set(envelope),
        )
        self.assertEqual(self.identity.key_id, snapshot.key_id)

        mutations = {
            "format": lambda value: value.__setitem__("format_version", 999),
            "revision": lambda value: value.__setitem__("revision", 99),
            "key": lambda value: value.__setitem__(
                "key_id", IdentityKey.generate().key_id
            ),
            "state": lambda value: value.__setitem__("state", {"stage": "tampered"}),
            "digest": lambda value: value.__setitem__(
                "envelope_hmac", "checkpoint_hmac_v2:" + "f" * 64
            ),
            "extra": lambda value: value.__setitem__("unexpected", True),
            "missing-key": lambda value: value.pop("key_id"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                tampered = json.loads(original)
                mutate(tampered)
                atomic_write_json(self.store.path, tampered)
                with self.assertRaises(CheckpointIntegrityError):
                    self.store.read()
                self._restore(original)

        other_store = AtomicCheckpointStore(
            self.store.run_dir,
            identity=IdentityKey.generate(),
        )
        with self.assertRaises(CheckpointIntegrityError):
            other_store.read()

    def test_public_digest_recomputation_cannot_authenticate_tampering(self) -> None:
        self.store.initialize({"stage": "catalog", "value": 1})
        envelope = json.loads(self.store.path.read_bytes())
        envelope["state"] = {"stage": "catalog", "value": 2}
        body = {
            key: envelope[key]
            for key in ("format_version", "revision", "key_id", "state")
        }
        public_digest = hashlib.sha256(
            json.dumps(
                body,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        envelope["envelope_hmac"] = "checkpoint_hmac_v2:" + public_digest
        atomic_write_json(self.store.path, envelope)

        with self.assertRaises(CheckpointIntegrityError):
            self.store.read()

    def test_strict_cas_rejects_stale_revision_for_equal_desired_state(self) -> None:
        initial = self.store.initialize({"value": 1})
        current = self.store.compare_and_swap(initial.revision, {"value": 2})

        with self.assertRaises(CheckpointConflictError):
            self.store.compare_and_swap(initial.revision, current.state)

    def test_noop_equality_uses_canonical_bytes_and_numeric_types(self) -> None:
        initial = self.store.initialize({"nested": {"b": 2, "a": 1}, "value": 1})
        reordered = self.store.save(
            {"value": 1, "nested": {"a": 1, "b": 2}},
            expected_revision=initial.revision,
        )
        self.assertEqual(initial.revision, reordered.revision)

        changed_type = self.store.save(
            {"value": 1.0, "nested": {"a": 1, "b": 2}},
            expected_revision=reordered.revision,
        )
        self.assertEqual(initial.revision + 1, changed_type.revision)

    def test_checkpoint_read_rejects_duplicate_nonfinite_and_noncanonical_numbers(
        self,
    ) -> None:
        self.store.initialize({"value": 1.0})
        original = self.store.path.read_bytes()
        cases = {
            "duplicate": original.replace(
                b'"revision":1',
                b'"revision":1,"revision":1',
                1,
            ),
            "nan": original.replace(b'"value":1.0', b'"value":NaN', 1),
            "overflow": original.replace(b'"value":1.0', b'"value":1e999', 1),
            "noncanonical": original.replace(b'"value":1.0', b'"value":1e0', 1),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self._restore(payload)
                with self.assertRaises(CheckpointIntegrityError):
                    self.store.read()
                self._restore(original)

    def test_hard_linked_lock_is_rejected_before_chmod_or_flock(self) -> None:
        self.store.run_dir.mkdir(mode=0o700)
        os.chmod(self.store.run_dir, 0o700)
        self.store.lock_path.write_bytes(b"")
        os.chmod(self.store.lock_path, 0o600)
        alias = self.root / "lock-alias"
        os.link(self.store.lock_path, alias)
        original_mode = stat.S_IMODE(alias.stat().st_mode)

        with mock.patch(
            "retrospective_v2.safe_io.os.fchmod",
            wraps=os.fchmod,
        ) as chmod:
            with mock.patch(
                "retrospective_v2.checkpoints.fcntl.flock",
                wraps=__import__("fcntl").flock,
            ) as flock:
                with self.assertRaises(CheckpointPermissionError):
                    self.store.exists()

        chmod.assert_not_called()
        flock.assert_not_called()
        self.assertEqual(original_mode, stat.S_IMODE(alias.stat().st_mode))

    def test_run_directory_substitution_cannot_redirect_lock_or_checkpoint(
        self,
    ) -> None:
        trusted = self.root / "trusted"
        trusted.mkdir(mode=0o700)
        run_dir = trusted / "run"
        run_dir.mkdir(mode=0o700)
        pinned = trusted / "run-pinned"
        attacker = self.root / "attacker"
        attacker.mkdir(mode=0o700)
        store = AtomicCheckpointStore(run_dir, identity=self.identity)
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
            if path == "run" and dir_fd is not None and not swapped:
                run_dir.rename(pinned)
                run_dir.symlink_to(attacker, target_is_directory=True)
                swapped = True
            return descriptor

        with mock.patch("retrospective_v2.safe_io.os.open", side_effect=racing_open):
            store.initialize({"value": "pinned"})

        self.assertTrue(swapped)
        self.assertFalse((attacker / ".checkpoint.lock").exists())
        self.assertFalse((attacker / "checkpoint.json").exists())
        self.assertTrue((pinned / ".checkpoint.lock").is_file())
        self.assertTrue((pinned / "checkpoint.json").is_file())

    def test_checkpoint_replace_failure_preserves_previous_revision(self) -> None:
        initial = self.store.initialize({"value": "before"})

        with mock.patch.object(
            AtomicCheckpointStore,
            "_replace",
            side_effect=OSError("simulated crash before replace"),
        ):
            with self.assertRaisesRegex(OSError, "before replace"):
                self.store.compare_and_swap(
                    initial.revision,
                    {"value": "after"},
                )

        current = self.store.read()
        self.assertEqual(initial, current)
        self.assertEqual([], list(self.store.run_dir.glob(".atomic-write-*.tmp")))

    def test_directory_fsync_failure_exposes_ambiguous_committed_revision(
        self,
    ) -> None:
        initial = self.store.initialize({"value": "before"})
        real_fsync = os.fsync
        injected = False

        def fail_directory_fsync(descriptor: int) -> None:
            nonlocal injected
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not injected:
                injected = True
                raise OSError("simulated crash during directory fsync")
            real_fsync(descriptor)

        with mock.patch(
            "retrospective_v2.safe_io.os.fsync",
            side_effect=fail_directory_fsync,
        ):
            with self.assertRaisesRegex(OSError, "directory fsync"):
                self.store.compare_and_swap(
                    initial.revision,
                    {"value": "after"},
                )

        self.assertTrue(injected)
        committed = self.store.read()
        self.assertEqual(initial.revision + 1, committed.revision)
        self.assertEqual({"value": "after"}, committed.state)
        with self.assertRaises(CheckpointConflictError):
            self.store.compare_and_swap(
                initial.revision,
                {"value": "after"},
            )


if __name__ == "__main__":
    unittest.main()
