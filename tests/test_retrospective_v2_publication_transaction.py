from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Mapping
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "codex-session-retrospective" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import session_retrospective_v2 as cli_module  # noqa: E402
from retrospective_v2 import (  # noqa: E402
    authority,
    calibration,
    finalize as finalize_module,
    git_safety,
    orchestrator as orchestrator_module,
    publication_git_commits,
    publication_support,
    safe_io,
)
from retrospective_v2.contracts import RefType, RunStage  # noqa: E402
from retrospective_v2.checkpoints import CheckpointIntegrityError  # noqa: E402
from retrospective_v2.export import export_retained_bundle  # noqa: E402
from retrospective_v2.finalize import (  # noqa: E402
    AttemptMismatchError,
    DEFAULT_PUBLISHER_UID,
    StateCorruptionError,
    LocalGitPublicationAdapter,
    PublicationRejected,
    PublicationTransaction,
    build_artifact_inventory,
)
from retrospective_v2.identity import IdentityKey  # noqa: E402
from retrospective_v2.orchestrator import (  # noqa: E402
    RetrospectiveOrchestrator,
    RunConflictError,
)
from tests.test_retrospective_v2_orchestrator import (  # noqa: E402
    authenticated_receipt,
    bind_remote_host_context_helper_fixture,
    execution_provenance,
    no_activity_manifest,
    synthesis_result,
)
from tests.test_retrospective_v2_lifecycle_calibration import (  # noqa: E402
    passing_corpus,
)


WINDOW_START = "2026-07-06T00:00:00Z"
WINDOW_END = "2026-07-07T00:00:00Z"
TARGET_REF = "refs/heads/main"


def _publication_test_temp_parent() -> str:
    private_tmp = Path("/private/tmp")
    if private_tmp.is_dir():
        return os.fspath(private_tmp)
    return tempfile.gettempdir()


def run_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        input=input_text,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


class PublicationInvariantUnitTests(unittest.TestCase):
    def test_local_git_completeness_policy_is_closed(self) -> None:
        git_safety.validate_complete_local_repository(
            b"false\n",
            b"core.repositoryformatversion\nremote.origin.url\n",
        )
        for shallow, keys in (
            (b"true\n", b"core.repositoryformatversion\n"),
            (b"false\n", b"extensions.partialClone\n"),
            (b"false\n", b"remote.origin.promisor\n"),
            (b"false\n", b"remote.origin.partialCloneFilter\n"),
            (b"false\n", b"remote.origin.promisor\x00suffix\n"),
        ):
            with self.subTest(shallow=shallow, keys=keys):
                with self.assertRaises(ValueError):
                    git_safety.validate_complete_local_repository(shallow, keys)

    def test_publication_temp_parent_uses_portable_fallback(self) -> None:
        with mock.patch.object(Path, "is_dir", return_value=True):
            self.assertEqual("/private/tmp", _publication_test_temp_parent())
        with (
            mock.patch.object(Path, "is_dir", return_value=False),
            mock.patch.object(tempfile, "gettempdir", return_value="/tmp"),
        ):
            self.assertEqual("/tmp", _publication_test_temp_parent())

    def test_bounded_subprocess_uses_held_working_directory_after_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir=_publication_test_temp_parent()
        ) as temporary_directory:
            root = Path(temporary_directory)
            original = root / "publisher-home"
            displaced = root / "publisher-home-original"
            original.mkdir(mode=0o700)
            original.joinpath("marker").write_text("anchored", encoding="ascii")
            descriptor = os.open(original, os.O_RDONLY | os.O_DIRECTORY)
            original.rename(displaced)
            original.mkdir(mode=0o700)
            original.joinpath("marker").write_text("replacement", encoding="ascii")
            try:
                result = publication_support._run_bounded_subprocess(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        "-S",
                        "-c",
                        "import pathlib; print(pathlib.Path('marker').read_text())",
                    ],
                    cwd_descriptor=descriptor,
                    environment=publication_support._strict_subprocess_environment(
                        home=original
                    ),
                    max_output_bytes=1024,
                    timeout_seconds=5,
                )
            finally:
                os.close(descriptor)

            self.assertEqual(0, result.returncode)
            self.assertEqual(b"anchored\n", result.stdout)

    def test_publisher_keyring_uses_descriptor_binding_across_path_aba(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=_publication_test_temp_parent()
        ) as temporary_directory:
            root = Path(temporary_directory)
            home = root / "gnupg"
            moved_home = root / "gnupg-original"
            replacement_home = root / "gnupg-replacement"
            home.mkdir(mode=0o700)
            original_identity = home.stat()
            fingerprint = "A" * 40

            def inventory(primary: str) -> bytes:
                rows = (
                    ":".join((primary, *("" for _ in range(9)))),
                    ":".join(("fpr", *("" for _ in range(8)), fingerprint)),
                    ":".join(("uid", *("" for _ in range(8)), DEFAULT_PUBLISHER_UID)),
                )
                return ("\n".join(rows) + "\n").encode("ascii")

            calls = 0

            def replace_restore_and_list(command, **kwargs):
                nonlocal calls
                calls += 1
                descriptor_path = command[command.index("--homedir") + 1]
                self.assertEqual(
                    descriptor_path,
                    kwargs["environment"]["GNUPGHOME"],
                )
                self.assertEqual(".", descriptor_path)
                self.assertGreaterEqual(kwargs["cwd_descriptor"], 0)
                if calls == 1:
                    home.rename(moved_home)
                    replacement_home.mkdir(mode=0o700)
                    replacement_home.rename(home)
                    anchored = os.fstat(kwargs["cwd_descriptor"])
                    self.assertEqual(
                        (original_identity.st_dev, original_identity.st_ino),
                        (anchored.st_dev, anchored.st_ino),
                    )
                    home.rename(replacement_home)
                    moved_home.rename(home)
                primary = "sec" if command[-1] == "--list-secret-keys" else "pub"
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout=inventory(primary),
                    stderr=b"",
                )

            with mock.patch.object(
                publication_support,
                "_run_bounded_subprocess",
                side_effect=replace_restore_and_list,
            ):
                identity = publication_support.validate_publisher_keyring(
                    gnupg_home=home,
                    fingerprint=fingerprint,
                    expected_uid=DEFAULT_PUBLISHER_UID,
                    gpg_program=sys.executable,
                )

            self.assertEqual(fingerprint, identity["fingerprint"])
            self.assertEqual(2, calls)

    def test_publisher_keyring_rejects_secret_inventory_before_public_listing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir=_publication_test_temp_parent()
        ) as temporary_directory:
            home = Path(temporary_directory) / "gnupg"
            home.mkdir(mode=0o700)
            calls = 0

            def secret_listing_only(command, **_kwargs):
                nonlocal calls
                calls += 1
                if calls != 1:
                    raise AssertionError("public listing must not start")
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout=b"",
                    stderr=b"",
                )

            with (
                mock.patch.object(
                    publication_support,
                    "_run_bounded_subprocess",
                    side_effect=secret_listing_only,
                ),
                self.assertRaisesRegex(
                    publication_support.LocalGitPublicationError,
                    "exactly the configured secret primary key",
                ),
            ):
                publication_support.validate_publisher_keyring(
                    gnupg_home=home,
                    fingerprint="A" * 40,
                    expected_uid=DEFAULT_PUBLISHER_UID,
                    gpg_program=sys.executable,
                )

            self.assertEqual(1, calls)

    def test_publisher_keyring_rejects_path_replacement_during_gpg(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=_publication_test_temp_parent()
        ) as temporary_directory:
            root = Path(temporary_directory)
            home = root / "gnupg"
            moved_home = root / "gnupg-original"
            home.mkdir(mode=0o700)

            def replace_keyring(*_args, **_kwargs):
                home.rename(moved_home)
                home.mkdir(mode=0o700)
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=b"",
                    stderr=b"",
                )

            with (
                mock.patch.object(
                    publication_support,
                    "_run_bounded_subprocess",
                    side_effect=replace_keyring,
                ),
                self.assertRaisesRegex(
                    publication_support.LocalGitPublicationError,
                    "GNUPGHOME changed after validation",
                ),
            ):
                publication_support.validate_publisher_keyring(
                    gnupg_home=home,
                    fingerprint="A" * 40,
                    expected_uid=DEFAULT_PUBLISHER_UID,
                    gpg_program=sys.executable,
                )

    def test_publisher_keyring_prioritizes_revalidation_after_listing_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir=_publication_test_temp_parent()
        ) as temporary_directory:
            root = Path(temporary_directory)
            home = root / "gnupg"
            moved_home = root / "gnupg-original"
            home.mkdir(mode=0o700)
            operation_error = publication_support.LocalGitPublicationError(
                "subprocess exceeded its deadline"
            )
            calls = 0

            def replace_keyring_and_fail(*_args, **_kwargs):
                nonlocal calls
                calls += 1
                home.rename(moved_home)
                home.mkdir(mode=0o700)
                raise operation_error

            with mock.patch.object(
                publication_support,
                "_run_bounded_subprocess",
                side_effect=replace_keyring_and_fail,
            ):
                with self.assertRaisesRegex(
                    publication_support.LocalGitPublicationError,
                    "GNUPGHOME changed after validation",
                ) as raised:
                    publication_support.validate_publisher_keyring(
                        gnupg_home=home,
                        fingerprint="A" * 40,
                        expected_uid=DEFAULT_PUBLISHER_UID,
                        gpg_program=sys.executable,
                    )

            self.assertIs(operation_error, raised.exception.__cause__)
            self.assertEqual(1, calls)

    def test_bounded_subprocesses_close_group_after_leader_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            helper = root / "leader-exits.py"
            helper.write_text(
                "import subprocess, sys\n"
                "child = subprocess.Popen(\n"
                "    [sys.executable, '-I', '-c', "
                "'import time; time.sleep(60)'],\n"
                "    stdout=sys.stdout,\n"
                "    stderr=sys.stderr,\n"
                ")\n"
                "with open(sys.argv[1], 'w', encoding='ascii') as stream:\n"
                "    stream.write(str(child.pid))\n"
                "    stream.flush()\n",
                encoding="ascii",
            )

            def assert_child_closed(pid_path: Path) -> None:
                child_pid = int(pid_path.read_text(encoding="ascii"))
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        return
                    time.sleep(0.02)
                self.fail(f"bounded subprocess descendant survived: {child_pid}")

            publication_pid = root / "publication.pid"
            started = time.monotonic()
            with self.assertRaisesRegex(
                publication_support.LocalGitPublicationError,
                "subprocess exceeded its deadline",
            ):
                publication_support._run_bounded_subprocess(
                    [sys.executable, "-I", str(helper), str(publication_pid)],
                    environment=dict(os.environ),
                    timeout_seconds=0.25,
                    max_output_bytes=1024,
                )
            self.assertLess(time.monotonic() - started, 2)
            assert_child_closed(publication_pid)

            authority_pid = root / "authority.pid"
            started = time.monotonic()
            with self.assertRaisesRegex(
                authority.HistoryValidationError,
                "history command exceeded its deadline",
            ):
                authority._run_bounded(
                    [sys.executable, "-I", str(helper), str(authority_pid)],
                    env=dict(os.environ),
                    timeout_seconds=0.25,
                    max_output_bytes=1024,
                )
            self.assertLess(time.monotonic() - started, 2)
            assert_child_closed(authority_pid)

            detached_helper = root / "leader-exits-with-detached-output.py"
            detached_helper.write_text(
                "import subprocess, sys\n"
                "child = subprocess.Popen(\n"
                "    [sys.executable, '-I', '-c', "
                "'import time; time.sleep(60)'],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                ")\n"
                "with open(sys.argv[1], 'w', encoding='ascii') as stream:\n"
                "    stream.write(str(child.pid))\n",
                encoding="ascii",
            )

            publication_detached_pid = root / "publication-detached.pid"
            publication_result = publication_support._run_bounded_subprocess(
                [
                    sys.executable,
                    "-I",
                    str(detached_helper),
                    str(publication_detached_pid),
                ],
                environment=dict(os.environ),
                timeout_seconds=2,
                max_output_bytes=1024,
            )
            self.assertEqual(0, publication_result.returncode)
            assert_child_closed(publication_detached_pid)

            authority_detached_pid = root / "authority-detached.pid"
            authority_result = authority._run_bounded(
                [
                    sys.executable,
                    "-I",
                    str(detached_helper),
                    str(authority_detached_pid),
                ],
                env=dict(os.environ),
                timeout_seconds=2,
                max_output_bytes=1024,
            )
            self.assertEqual(0, authority_result.returncode)
            assert_child_closed(authority_detached_pid)

    def test_retained_export_lifecycle_is_injected_through_narrow_protocol(
        self,
    ) -> None:
        calls: list[tuple[str, Path, str, str | None]] = []

        class FakeRetainedExportLifecycle:
            def bind_staged_export(self, output_dir: Path, attempt_ref: str) -> dict:
                calls.append(("bind", Path(output_dir), attempt_ref, None))
                return {}

            def release_staged_export(
                self,
                output_dir: Path,
                attempt_ref: str,
                disposition: str,
            ) -> dict:
                calls.append(("release", Path(output_dir), attempt_ref, disposition))
                return {}

            def release_staged_export_if_bound(
                self,
                output_dir: Path,
                attempt_ref: str,
                disposition: str,
            ) -> dict:
                calls.append(
                    ("release-if-bound", Path(output_dir), attempt_ref, disposition)
                )
                return {}

        with tempfile.TemporaryDirectory() as raw:
            bundle = Path(raw) / "retained"
            bundle.mkdir()
            bundle.with_name(f".{bundle.name}.retention-v2.json").write_text(
                "{}\n",
                encoding="ascii",
            )
            adapter = object.__new__(LocalGitPublicationAdapter)
            adapter._retained_export_lifecycle = FakeRetainedExportLifecycle()
            request = mock.Mock(attempt_ref="attempt_ref_v2:" + "a" * 64)
            units = ({"bundle_dir": str(bundle)},)

            self.assertEqual(
                1,
                adapter._bind_export_retention_sidecars(request, units),
            )
            adapter._release_export_retention_sidecars(
                request,
                units,
                disposition="aborted",
            )

        self.assertEqual(
            calls,
            [
                ("bind", bundle, request.attempt_ref, None),
                ("release-if-bound", bundle, request.attempt_ref, "aborted"),
            ],
        )

    def test_episode_successor_cannot_change_predecessor_session(self) -> None:
        previous = {
            "episode_ref": "episode_ref_v2:" + "a" * 64,
            "episode_revision_ref": "episode_revision_ref_v2:" + "b" * 64,
            "revision_ordinal": 1,
            "session_ref": "session_ref_v2:" + "c" * 64,
            "supersedes_episode_revision_ref": None,
        }
        successor = {
            **previous,
            "episode_revision_ref": "episode_revision_ref_v2:" + "d" * 64,
            "revision_ordinal": 2,
            "session_ref": "session_ref_v2:" + "e" * 64,
            "supersedes_episode_revision_ref": previous["episode_revision_ref"],
        }

        with self.assertRaisesRegex(
            publication_support.AppendOnlyViolation,
            "authenticated successor",
        ):
            publication_support._validate_append_only_episode_heads(
                [previous],
                [successor],
            )

    def test_validsig_uses_primary_fingerprint_for_signing_subkey(self) -> None:
        signing_subkey = "A" * 40
        primary_key = "B" * 40
        status = (
            "[GNUPG:] VALIDSIG "
            f"{signing_subkey} 2026-07-16 1784160000 0 4 0 22 8 00 {primary_key}\n"
        ).encode("ascii")

        self.assertEqual(
            authority.validsig_primary_fingerprints(status),
            [primary_key],
        )

    def test_ref_creation_uses_object_format_width_for_zero_oid(self) -> None:
        adapter = object.__new__(LocalGitPublicationAdapter)
        adapter._git = mock.Mock(
            return_value=subprocess.CompletedProcess([], 0, b"", b"")
        )
        value = "a" * 64

        adapter._update_ref("refs/session-retrospective/test", value, expected=None)

        adapter._git.assert_called_once_with(
            (
                "update-ref",
                "refs/session-retrospective/test",
                value,
                "0" * 64,
            ),
            check=False,
        )


class DurablePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gpg = shutil.which("gpg")
        if cls.gpg is None:
            raise unittest.SkipTest("gpg is required for signed publication tests")
        cls.key_fixture = tempfile.TemporaryDirectory()
        cls.gnupg_home = Path(cls.key_fixture.name) / "gnupg"
        cls.gnupg_home.mkdir(mode=0o700)
        run_command(
            [
                cls.gpg,
                "--homedir",
                str(cls.gnupg_home),
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                DEFAULT_PUBLISHER_UID,
                "ed25519",
                "sign",
                "1d",
            ]
        )
        listing = run_command(
            [
                cls.gpg,
                "--homedir",
                str(cls.gnupg_home),
                "--batch",
                "--with-colons",
                "--list-secret-keys",
            ]
        ).stdout.splitlines()
        cls.fingerprint = next(
            line.split(":")[9]
            for previous, line in zip(listing, listing[1:])
            if previous.startswith("sec:") and line.startswith("fpr:")
        )

    @classmethod
    def tearDownClass(cls) -> None:
        gpgconf = shutil.which("gpgconf")
        if gpgconf is not None:
            subprocess.run(
                [gpgconf, "--homedir", str(cls.gnupg_home), "--kill", "gpg-agent"],
                check=False,
                capture_output=True,
            )
        cls.key_fixture.cleanup()

    def setUp(self) -> None:
        bind_remote_host_context_helper_fixture(self)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.identity_path = self.root / "identity-v2.key"
        self.identity = IdentityKey.create(self.identity_path)
        self.repo = self.root / "history"
        run_command(["git", "init", "-q", "-b", "main", str(self.repo)])
        (self.repo / "README.md").write_text("# Private history\n", encoding="ascii")
        run_command(["git", "add", "README.md"], cwd=self.repo)
        run_command(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "Initialize history",
            ],
            cwd=self.repo,
        )
        self.base_head = self.head()
        self.automation_cutover_record = self.build_automation_cutover_record()
        self.provider_state = self.root / "provider-state"
        self.initial_history = self.load_history()
        authority.initialize_provider_cache(
            self.provider_state,
            history=self.initial_history,
            expected_revision=0,
            identity=self.identity,
        )
        probe = RetrospectiveOrchestrator(
            self.root / "configuration-probe",
            identity_path=self.identity_path,
            require_existing_identity=True,
        )
        self.provenance = execution_provenance()
        provenance = orchestrator_module._build_provenance(
            provenance=self.provenance,
            policy=None,
            model=None,
            versions=None,
        )
        self.configuration_ref = probe._ref(
            RefType.CONFIGURATION, provenance["configuration_root"]
        )
        self.configuration_root = provenance["configuration_root"]
        era_state = {"provenance": provenance}
        self.model_era = probe._model_era(era_state)
        self.policy_era = probe._policy_token(
            era_state,
            "policy",
            "source_policy_v2",
        )
        self.marker_path = self.root / "production-marker.json"
        self.calibration_receipt = calibration.evaluate_calibration_corpus(
            self.identity,
            passing_corpus(),
            production_configuration_root=self.configuration_root,
            model_era=self.model_era,
            policy_era=self.policy_era,
        )
        self.shadow_evidence = self.build_shadow_gate_evidence()
        self.marker = authority.issue_production_marker(
            self.marker_path,
            identity=self.identity,
            history_repo=self.repo,
            target_ref=TARGET_REF,
            configuration_root=self.configuration_root,
            configuration_ref=self.configuration_ref,
            model_era=self.model_era,
            policy_era=self.policy_era,
            calibration_receipt=self.calibration_receipt,
            accepted_shadow_evidence=self.shadow_evidence,
            automation_cutover_record=self.automation_cutover_record,
            installed_commits=(self.base_head,),
        )
        self.adapter = LocalGitPublicationAdapter(
            self.repo,
            self.provider_state,
            signing_key=self.fingerprint,
            gnupg_home=self.gnupg_home,
            expected_signer_uid=DEFAULT_PUBLISHER_UID,
            signing_program=self.gpg,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_automation_cutover_record(self) -> dict[str, object]:
        automation_root = self.root / ".codex" / "automations"
        automation_root.mkdir(mode=0o700, parents=True)
        os.chmod(automation_root, 0o700)
        snapshot = authority.capture_automation_cutover_snapshot(
            self.root / "automation-cutover-pre-update-v2.json",
            identity=self.identity,
            automation_root=automation_root,
        )
        installed_cli = authority.installed_v2_cli_path()
        operations: list[dict[str, object]] = []
        for automation_id, mode in authority.STABLE_AUTOMATION_MODES.items():
            record_dir = automation_root / automation_id
            record_dir.mkdir(parents=True)
            schedule = (
                "FREQ=DAILY;BYHOUR=3" if mode == "daily" else "FREQ=WEEKLY;BYDAY=MO"
            )
            prompt = f"Run python3 {installed_cli} start --mode {mode} for the exact production window."
            (record_dir / "automation.toml").write_text(
                "\n".join(
                    (
                        "version = 1",
                        f'id = "{automation_id}"',
                        'kind = "cron"',
                        f'name = "Session Retrospective {mode.title()}"',
                        f"prompt = {json.dumps(prompt)}",
                        'status = "ACTIVE"',
                        f'rrule = "{schedule}"',
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            operations.append(
                {
                    "automation_id": automation_id,
                    "operation": "register",
                    "previous_record_sha256": None,
                    "record_sha256": hashlib.sha256(
                        (record_dir / "automation.toml").read_bytes()
                    ).hexdigest(),
                    "status": "success",
                }
            )
        capability_result = {
            "available": True,
            "capability": "automation_update",
            "operations": operations,
            "pre_update_snapshot_ref": snapshot["snapshot_ref"],
            "schema": authority.AUTOMATION_UPDATE_RESULT_SCHEMA,
        }
        return authority.issue_automation_cutover_record(
            self.root / "automation-cutover-v2.json",
            identity=self.identity,
            capability_result=capability_result,
            pre_update_snapshot=snapshot,
            installed_commit=self.base_head,
            automation_root=automation_root,
        )

    def head(self) -> str:
        return run_command(
            ["git", "rev-parse", TARGET_REF], cwd=self.repo
        ).stdout.strip()

    def load_history(self) -> authority.DurableHistoryState:
        return authority.load_durable_history(
            self.repo,
            TARGET_REF,
            identity=self.identity,
            expected_fingerprint=self.fingerprint,
            gnupg_home=self.gnupg_home,
            gpg_program=self.gpg,
        )

    def commit_signed_fixture(self, message: str) -> str:
        environment = dict(os.environ)
        environment["GNUPGHOME"] = str(self.gnupg_home)
        run_command(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "gpg.format=openpgp",
                "-c",
                f"user.signingkey={self.fingerprint}",
                "-c",
                f"gpg.program={self.gpg}",
                "commit",
                "-q",
                "-S",
                "-m",
                message,
            ],
            cwd=self.repo,
            env=environment,
        )
        return self.head()

    def commit_signed_tree_fixture(
        self,
        tree: str,
        *,
        parents: tuple[str, ...],
        message: str,
        update_target: bool = True,
    ) -> str:
        environment = dict(os.environ)
        environment["GNUPGHOME"] = str(self.gnupg_home)
        arguments = [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"user.signingkey={self.fingerprint}",
            "-c",
            f"gpg.program={self.gpg}",
            "commit-tree",
            tree,
            f"-S{self.fingerprint}",
            "-m",
            message,
        ]
        for parent in parents:
            arguments.extend(("-p", parent))
        commit = run_command(
            arguments,
            cwd=self.repo,
            env=environment,
        ).stdout.strip()
        if update_target:
            run_command(
                ["git", "update-ref", TARGET_REF, commit, self.head()],
                cwd=self.repo,
            )
        return commit

    def replace_tip_with_tampered_signature(self, commit: str) -> str:
        raw_commit = run_command(
            ["git", "cat-file", "commit", commit], cwd=self.repo
        ).stdout
        lines = raw_commit.splitlines(keepends=True)
        in_signature = False
        changed = False
        for index, line in enumerate(lines):
            if line.startswith("gpgsig -----BEGIN PGP SIGNATURE-----"):
                in_signature = True
                continue
            if in_signature and line.startswith(" -----END PGP SIGNATURE-----"):
                break
            payload = line[1:].rstrip("\n") if in_signature else ""
            if len(payload) > 16 and not payload.startswith("-----"):
                replacement = "A" if payload[0] != "A" else "B"
                newline = "\n" if line.endswith("\n") else ""
                lines[index] = f" {replacement}{payload[1:]}{newline}"
                changed = True
                break
        self.assertTrue(changed, "fixture commit lacked a mutable signature line")
        tampered = run_command(
            ["git", "hash-object", "-t", "commit", "-w", "--stdin"],
            cwd=self.repo,
            input_text="".join(lines),
        ).stdout.strip()
        run_command(
            ["git", "update-ref", TARGET_REF, tampered, commit],
            cwd=self.repo,
        )
        return tampered

    def build_shadow_evidence_run(
        self,
        name: str,
        *,
        mode: str,
        window_start: str,
        window_end: str,
        hosts: tuple[str, ...],
        allow_partial: bool = False,
        holdout_host: str | None = None,
        backfill_of: str | None = None,
        controlled_gap_receipt: Mapping[str, object] | None = None,
        shadow_successor: Mapping[str, object] | None = None,
        history: authority.DurableHistoryState | None = None,
    ) -> tuple[
        RetrospectiveOrchestrator,
        dict[str, object],
        dict[str, object],
    ]:
        coordinator = RetrospectiveOrchestrator(
            self.root / "shadow-gate-runs" / name,
            clock=lambda: "2026-07-15T00:00:00Z",
            identity_path=self.identity_path,
            require_existing_identity=True,
        )
        start = {
            "allow_partial": allow_partial,
            "backfill_of": backfill_of,
            "controlled_gap_receipt": controlled_gap_receipt,
            "created_at": "2026-07-15T00:00:00Z",
            "end": window_end,
            "history_repo": self.repo,
            "history_target_ref": TARGET_REF,
            "hosts": hosts,
            "mode": mode,
            "publisher_fingerprint": self.fingerprint,
            "publisher_gnupg_home": self.gnupg_home,
            "provenance": self.provenance,
            "shadow": True,
            "shadow_successor": shadow_successor,
            "start": window_start,
        }
        if history is None:
            coordinator.start(**start)
        else:
            with mock.patch.object(
                orchestrator_module.authority,
                "load_durable_history",
                return_value=history,
            ):
                coordinator.start(**start)
        if holdout_host is not None:
            coordinator.holdout_host(
                holdout_host,
                reason="shadow_missing_host_holdout",
            )
        for _ in range(80):
            status = coordinator.status()
            if status["stage"] == RunStage.EXPORT.value:
                break
            leases = status["active_source_leases"]
            if leases:
                for lease in leases:
                    manifest = no_activity_manifest(lease)
                    coordinator.accept_source(
                        lease["lease_ref"],
                        manifest.to_dict(),
                        transport_receipt=authenticated_receipt(
                            coordinator,
                            lease,
                            manifest,
                        ),
                    )
            else:
                agent_jobs = [
                    job for job in status["runnable_jobs"] if job["category"] == "agent"
                ]
                if agent_jobs:
                    for job in agent_jobs:
                        dispatcher_ref = str(
                            self.identity.derive_ref(
                                RefType.LEASE,
                                {
                                    "parts": [
                                        "shadow-gate-dispatcher",
                                        job["job_ref"],
                                    ]
                                },
                            )
                        )
                        claimed = coordinator.claim_agent_job(
                            job["job_ref"],
                            job["active_attempt_ref"],
                            dispatcher_ref,
                        )
                        coordinator.accept_agent_result(
                            job["job_ref"],
                            job["active_attempt_ref"],
                            synthesis_result(),
                            claim_ref=claimed["claim_ref"],
                            result_ref=claimed["result_ref"],
                        )
                    continue
                coordinator.advance()
        else:
            self.fail(
                "shadow evidence run did not become exportable: "
                f"stage={status['stage']} blocked={status['blocked_reason']} "
                f"next={status['next_actions']}"
            )

        state = coordinator.load_state()
        run_state, review_data = cli_module._retained_inputs(coordinator, state)
        bundle = (
            self.root / ".codex-local" / "shadow-gate-exports" / name / "retained-v2"
        )
        export_retained_bundle(bundle, run_state, review_data)
        marked = coordinator.mark_shadow_exported(bundle)
        coverage = marked["publication"]["coverage_receipt"]
        completed = coordinator.complete_shadow_export()
        cleanup = completed["publication"]["cleanup_receipt"]
        return coordinator, coverage, cleanup

    def build_shadow_gate_evidence(self) -> list[dict[str, object]]:
        production_hosts = ("local", "miku-bot-dev", "hoteng-srv-01")
        weekly_evidence: list[dict[str, object]] = []
        for index, start, end in (
            (1, "2026-06-22T00:00:00Z", "2026-06-29T00:00:00Z"),
            (2, "2026-06-29T00:00:00Z", "2026-07-06T00:00:00Z"),
        ):
            _run, coverage, cleanup = self.build_shadow_evidence_run(
                f"weekly-{index}",
                mode="weekly",
                window_start=start,
                window_end=end,
                hosts=production_hosts,
            )
            weekly_evidence.append(
                authority.issue_shadow_gate_receipt(
                    self.identity,
                    calibration_receipt=self.calibration_receipt,
                    mode="weekly",
                    coverage_receipts=(coverage,),
                    cleanup_receipts=(cleanup,),
                )
            )

        partial, partial_coverage, partial_cleanup = self.build_shadow_evidence_run(
            "daily-partial",
            mode="daily",
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            hosts=production_hosts,
            allow_partial=True,
            holdout_host="miku-bot-dev",
        )
        successor = partial.shadow_daily_successor()
        backfill, backfill_coverage, backfill_cleanup = self.build_shadow_evidence_run(
            "daily-backfill",
            mode="daily",
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            hosts=(successor["host"],),
            backfill_of=successor["backfill_of"],
            controlled_gap_receipt=successor["controlled_gap_receipt"],
            shadow_successor=successor,
        )
        lineage = backfill.load_state()["lineage"]["backfill_lineage_receipt"]
        daily = authority.issue_shadow_gate_receipt(
            self.identity,
            calibration_receipt=self.calibration_receipt,
            mode="daily",
            coverage_receipts=(partial_coverage, backfill_coverage),
            cleanup_receipts=(partial_cleanup, backfill_cleanup),
            controlled_gap_receipt=successor["controlled_gap_receipt"],
            backfill_lineage_receipt=lineage,
            backfill_run_ref=backfill_coverage["run_ref"],
        )
        return [*weekly_evidence, daily]

    def build_exportable_run(
        self,
        name: str,
        *,
        shadow: bool = False,
        bind_export: bool = True,
    ) -> tuple[RetrospectiveOrchestrator, Path]:
        coordinator = RetrospectiveOrchestrator(
            self.root / "runs" / name,
            clock=lambda: "2026-07-15T00:00:00Z",
            identity_path=self.identity_path,
            require_existing_identity=True,
        )
        coordinator.start(
            mode="daily",
            start=WINDOW_START,
            end=WINDOW_END,
            hosts=orchestrator_module.DEFAULT_HOSTS,
            provenance=self.provenance,
            shadow=shadow,
            created_at="2026-07-15T00:00:00Z",
            history_repo=self.repo,
            history_target_ref=TARGET_REF,
            provider_state=self.provider_state,
            production_marker=self.marker_path,
            publisher_fingerprint=self.fingerprint,
            publisher_gnupg_home=self.gnupg_home,
        )
        for _ in range(40):
            status = coordinator.status()
            if status["stage"] == RunStage.EXPORT.value:
                break
            leases = status["active_source_leases"]
            if leases:
                for lease in leases:
                    manifest = no_activity_manifest(lease)
                    coordinator.accept_source(
                        lease["lease_ref"],
                        manifest.to_dict(),
                        transport_receipt=authenticated_receipt(
                            coordinator, lease, manifest
                        ),
                    )
            else:
                coordinator.advance()
        else:
            self.fail("run did not become exportable")

        state = coordinator.load_state()
        run_state, review_data = cli_module._retained_inputs(coordinator, state)
        run_state["durable_state"] = coordinator.publication_durable_state()
        bundle = self.root / ".codex-local" / "exports" / name / "retained-v2"
        receipt = export_retained_bundle(
            bundle,
            run_state,
            review_data,
        )
        if bind_export:
            if shadow:
                coordinator.mark_shadow_exported(bundle)
            else:
                coordinator.mark_exported(receipt["bundle_digest"])
        return coordinator, bundle

    @staticmethod
    def destination(state: dict[str, object]) -> str:
        run_ref = str(state["run_ref"]).rsplit(":", 1)[1]
        return f"runs/daily/2026-07-06/{run_ref}"

    def transaction(
        self,
        coordinator: RetrospectiveOrchestrator,
        bundle: Path,
        *,
        journal_name: str = "publication-transaction-v2.json",
        destination: str | None = None,
        expected_head: str | None = None,
        adapter: LocalGitPublicationAdapter | None = None,
        failure_injector=None,
    ) -> PublicationTransaction:
        state = coordinator.load_state()
        transaction = PublicationTransaction.create(
            coordinator.run_dir / journal_name,
            bundle_dir=bundle,
            destination=destination or self.destination(state),
            target_ref=TARGET_REF,
            expected_target_head=(
                state["authority"]["history_snapshot"]["history_commit"]
                if expected_head is None
                else expected_head
            ),
            run_dir=coordinator.run_dir,
            identity_path=self.identity_path,
            adapter=adapter or self.adapter,
            failure_injector=failure_injector,
        )
        transaction_state = transaction.status()
        coordinator.claim_publication(
            transaction_state["attempt_ref"],
            transaction_state["plan_digest"],
        )
        return transaction

    def publication_adapter(
        self,
        *,
        failure_injector=None,
    ) -> LocalGitPublicationAdapter:
        return LocalGitPublicationAdapter(
            self.repo,
            self.provider_state,
            signing_key=self.fingerprint,
            gnupg_home=self.gnupg_home,
            expected_signer_uid=DEFAULT_PUBLISHER_UID,
            signing_program=self.gpg,
            failure_injector=failure_injector,
        )

    @staticmethod
    def publish(transaction: PublicationTransaction) -> None:
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()
        transaction.promote()
        transaction.commit()

    def test_real_signed_publication_derives_history_cache_then_cleans_raw(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("signed")
        transaction = self.transaction(coordinator, bundle)
        self.publish(transaction)

        published = self.load_history()
        self.assertEqual(1, published.provider_revision)
        self.assertEqual(self.head(), published.publication_commit)
        prior = authority.load_prior_period_from_history(
            self.repo,
            TARGET_REF,
            identity=self.identity,
            expected_fingerprint=self.fingerprint,
            gnupg_home=self.gnupg_home,
        )
        self.assertEqual(
            self.head(),
            prior["authenticated_history"]["history_commit"],
        )
        self.assertEqual(
            2,
            prior["trend_report"]["schema_version"],
        )
        authority.assert_provider_cache_matches(
            self.provider_state,
            published,
            identity=self.identity,
        )
        verify_env = dict(os.environ)
        verify_env["GNUPGHOME"] = str(self.gnupg_home)
        run_command(
            ["git", "verify-commit", self.head()], cwd=self.repo, env=verify_env
        )
        self.assertEqual("committed", transaction.status()["phase"])
        self.assertEqual(
            "committed",
            PublicationTransaction.open(
                transaction.journal_path, adapter=self.adapter
            ).status()["phase"],
        )

        claim = coordinator.load_state()["publication"]["publication_claim"]
        completed = coordinator.mark_finalized(
            "committed",
            attempt_ref=claim["attempt_ref"],
            claim_revision=claim["checkpoint_revision"],
            plan_digest=claim["plan_digest"],
        )
        self.assertEqual(RunStage.COMPLETE.value, completed["stage"])
        self.assertFalse((coordinator.run_dir / "raw-inputs").exists())
        self.assertIsNotNone(completed["publication"]["cleanup_receipt"])

    def test_history_verification_ignores_repo_configured_gpg_program(self) -> None:
        coordinator, bundle = self.build_exportable_run("untrusted-gpg-config")
        self.publish(self.transaction(coordinator, bundle))

        fake_gpg = self.root / "fake-gpg"
        invocation_marker = self.root / "fake-gpg-invoked"
        fake_gpg.write_text(
            "#!/bin/sh\n"
            f": > {shlex.quote(str(invocation_marker))}\n"
            f'exec {shlex.quote(self.gpg)} "$@"\n',
            encoding="ascii",
        )
        fake_gpg.chmod(0o700)
        run_command(["git", "config", "gpg.program", str(fake_gpg)], cwd=self.repo)
        run_command(
            ["git", "config", "gpg.openpgp.program", str(fake_gpg)],
            cwd=self.repo,
        )
        self.load_history()
        self.assertFalse(invocation_marker.exists())

        self.replace_tip_with_tampered_signature(self.head())

        with self.assertRaisesRegex(
            authority.HistoryValidationError,
            "signature is invalid",
        ):
            authority.load_durable_history(
                self.repo,
                TARGET_REF,
                identity=self.identity,
                expected_fingerprint=self.fingerprint,
                gnupg_home=self.gnupg_home,
                gpg_program=self.gpg,
            )

    def test_history_rejects_signed_retained_artifact_mutation(self) -> None:
        coordinator, bundle = self.build_exportable_run("artifact-mutation")
        self.publish(self.transaction(coordinator, bundle))
        destination = self.destination(coordinator.load_state())
        run_command(["git", "read-tree", self.head()], cwd=self.repo)
        summary = self.repo / destination / "summary.json"
        summary.parent.mkdir(parents=True, exist_ok=True)
        original = run_command(
            ["git", "show", f"{self.head()}:{destination}/summary.json"],
            cwd=self.repo,
        ).stdout
        summary.write_text(original + " ", encoding="ascii")
        run_command(["git", "add", str(summary)], cwd=self.repo)
        self.commit_signed_fixture("Mutate retained artifact")

        with self.assertRaisesRegex(
            authority.HistoryValidationError,
            "publication commit",
        ):
            self.load_history()

    def test_history_rejects_signed_merge_that_rolls_back_retained_tree(self) -> None:
        coordinator, bundle = self.build_exportable_run("merge-rollback")
        self.publish(self.transaction(coordinator, bundle))
        published = self.head()
        base_tree = run_command(
            ["git", "rev-parse", f"{self.base_head}^{{tree}}"],
            cwd=self.repo,
        ).stdout.strip()
        side = self.commit_signed_tree_fixture(
            base_tree,
            parents=(self.base_head,),
            message="Create signed rollback side parent",
            update_target=False,
        )
        self.commit_signed_tree_fixture(
            base_tree,
            parents=(published, side),
            message="Signed merge restoring the pre-publication tree",
        )

        with self.assertRaisesRegex(
            authority.HistoryValidationError,
            "cannot change across a merge",
        ):
            self.load_history()

    def test_history_accepts_merge_when_every_parent_retains_the_same_tree(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("merge-unrelated")
        self.publish(self.transaction(coordinator, bundle))
        published = self.head()
        published_tree = run_command(
            ["git", "rev-parse", f"{published}^{{tree}}"],
            cwd=self.repo,
        ).stdout.strip()
        left = self.commit_signed_tree_fixture(
            published_tree,
            parents=(published,),
            message="Create first unrelated side parent",
            update_target=False,
        )
        right = self.commit_signed_tree_fixture(
            published_tree,
            parents=(published,),
            message="Create second unrelated side parent",
            update_target=False,
        )
        merged = self.commit_signed_tree_fixture(
            published_tree,
            parents=(left, right),
            message="Merge unrelated history without changing retained data",
        )

        history = self.load_history()
        self.assertEqual(merged, history.head_commit)
        self.assertEqual(published, history.publication_commit)
        self.assertEqual(1, history.provider_revision)

    def test_gc_recovers_commit_after_response_and_local_finalize_mark_are_lost(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("lost-commit-response")

        def lose_response(point, _state):
            if point == "commit.after_persist":
                raise RuntimeError("simulated lost commit response")

        transaction = self.transaction(
            coordinator,
            bundle,
            failure_injector=lose_response,
        )
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()
        transaction.promote()
        with self.assertRaisesRegex(RuntimeError, "lost commit response"):
            transaction.commit()

        self.assertEqual("committed", transaction.status()["phase"])
        self.assertEqual(1, self.load_history().provider_revision)
        self.assertTrue((coordinator.run_dir / "raw-inputs").exists())
        self.assertIn(
            "publication_claim",
            coordinator.load_state()["publication"],
        )

        expired = RetrospectiveOrchestrator(
            coordinator.run_dir,
            identity_path=self.identity_path,
            require_existing_identity=True,
            clock=lambda: "2026-07-24T00:00:00Z",
        )
        recovered = expired.gc_expired_raw()
        state = expired.load_state()

        self.assertTrue(recovered["durable"])
        self.assertTrue(recovered["published"])
        self.assertTrue(recovered["cleaned"])
        self.assertEqual(RunStage.COMPLETE.value, state["stage"])
        self.assertEqual("complete", state["publication"]["phase"])
        self.assertNotIn("publication_claim", state["publication"])
        self.assertFalse((coordinator.run_dir / "raw-inputs").exists())
        authority.assert_provider_cache_matches(
            self.provider_state,
            self.load_history(),
            identity=self.identity,
        )

    def test_gc_rejects_same_root_publication_from_another_attempt(self) -> None:
        original, original_bundle = self.build_exportable_run("same-root-original")
        impostor_run_dir = self.root / "runs" / "same-root-impostor"
        shutil.copytree(original.run_dir, impostor_run_dir)
        impostor = RetrospectiveOrchestrator(
            impostor_run_dir,
            clock=lambda: "2026-07-15T00:00:00Z",
            identity_path=self.identity_path,
            require_existing_identity=True,
        )
        impostor_state = impostor.load_state()
        run_state, review_data = cli_module._retained_inputs(
            impostor,
            impostor_state,
        )
        run_state["durable_state"] = impostor.publication_durable_state()
        impostor_bundle = (
            self.root
            / ".codex-local"
            / "exports"
            / "same-root-impostor"
            / "retained-v2"
        )
        impostor_export = export_retained_bundle(
            impostor_bundle,
            run_state,
            review_data,
        )
        self.assertEqual(
            impostor_state["publication"]["bundle_digest"],
            impostor_export["bundle_digest"],
        )
        original_transaction = self.transaction(original, original_bundle)
        impostor_transaction = self.transaction(impostor, impostor_bundle)

        original_durable = original.load_state()["publication"]["durable_state"]
        impostor_durable = impostor.load_state()["publication"]["durable_state"]
        self.assertEqual(
            original_durable["proposed_cursor_root_ref"],
            impostor_durable["proposed_cursor_root_ref"],
        )
        self.assertEqual(
            original_durable["proposed_episode_head_root_ref"],
            impostor_durable["proposed_episode_head_root_ref"],
        )

        self.publish(impostor_transaction)
        published_commitment = authority.load_durable_publication_commitment(
            self.repo,
            self.head(),
            identity=self.identity,
            expected_fingerprint=self.fingerprint,
            gnupg_home=self.gnupg_home,
        )
        self.assertEqual(
            impostor_transaction.attempt_ref,
            published_commitment["attempt_ref"],
        )
        self.assertEqual(
            impostor_transaction.status()["plan_digest"],
            published_commitment["plan_digest"],
        )
        self.assertNotEqual(
            original_transaction.attempt_ref,
            published_commitment["attempt_ref"],
        )

        expired = RetrospectiveOrchestrator(
            original.run_dir,
            identity_path=self.identity_path,
            require_existing_identity=True,
            clock=lambda: "2026-07-24T00:00:00Z",
        )
        rejected = expired.gc_expired_raw()

        self.assertTrue(rejected["publication_claimed"])
        self.assertFalse(rejected["durable"])
        self.assertFalse(rejected["cleaned"])
        self.assertTrue((original.run_dir / "raw-inputs").exists())
        self.assertIn(
            "publication_claim",
            expired.load_state()["publication"],
        )

    def test_core_rejects_shadow_caller_overrides_and_open_jobs(self) -> None:
        shadow, shadow_bundle = self.build_exportable_run("shadow", shadow=True)
        with self.assertRaisesRegex(PublicationRejected, "shadow"):
            self.transaction(shadow, shadow_bundle)

        coordinator, bundle = self.build_exportable_run("overrides")
        with self.assertRaisesRegex(PublicationRejected, "destination"):
            self.transaction(
                coordinator,
                bundle,
                journal_name="wrong-destination.json",
                destination="runs/daily/2026-07-06/" + "f" * 64,
            )
        with self.assertRaisesRegex(PublicationRejected, "expected head"):
            self.transaction(
                coordinator,
                bundle,
                journal_name="wrong-head.json",
                expected_head="f" * 40,
            )

        def add_open_job(state: dict[str, object]):
            state["jobs"]["job_ref_v2:" + "f" * 64] = {
                "attempts": [],
                "status": "runnable",
            }
            return state, None

        coordinator.store.transaction(add_open_job)
        with self.assertRaisesRegex(PublicationRejected, "open"):
            self.transaction(
                coordinator,
                bundle,
                journal_name="open-job.json",
            )

    def test_existing_journal_is_bound_to_current_run_before_claim(self) -> None:
        original, original_bundle = self.build_exportable_run("journal-original")
        original_state = original.load_state()
        PublicationTransaction.create(
            original.run_dir / "publication-transaction-v2.json",
            bundle_dir=original_bundle,
            destination=self.destination(original_state),
            target_ref=TARGET_REF,
            expected_target_head=original_state["authority"]["history_snapshot"][
                "history_commit"
            ],
            run_dir=original.run_dir,
            identity_path=self.identity_path,
            adapter=self.adapter,
        )
        copied_run_dir = self.root / "runs" / "journal-current"
        shutil.copytree(original.run_dir, copied_run_dir)
        current = RetrospectiveOrchestrator(
            copied_run_dir,
            identity_path=self.identity_path,
            require_existing_identity=True,
        )
        copied_journal = copied_run_dir / "publication-transaction-v2.json"
        current_state = current.load_state()

        with self.assertRaisesRegex(
            AttemptMismatchError,
            "current run",
        ):
            PublicationTransaction.inspect_local_for_run(
                copied_journal,
                bundle_dir=original_bundle,
                destination=self.destination(current_state),
                target_ref=TARGET_REF,
                expected_target_head=current_state["authority"]["history_snapshot"][
                    "history_commit"
                ],
                run_dir=current.run_dir,
                identity_path=self.identity_path,
            )

        self.assertNotIn(
            "publication_claim",
            current.load_state()["publication"],
        )

    def test_latest_history_rejects_stale_run_and_local_cache_rollback(self) -> None:
        first, first_bundle = self.build_exportable_run("first")
        stale, stale_bundle = self.build_exportable_run("stale")
        old_cache = (self.provider_state / authority.PROVIDER_CACHE_FILE).read_bytes()
        self.publish(self.transaction(first, first_bundle))

        with self.assertRaisesRegex(PublicationRejected, "history"):
            self.transaction(stale, stale_bundle)

        cache_path = self.provider_state / authority.PROVIDER_CACHE_FILE
        safe_io.atomic_write_bytes(cache_path, old_cache)
        rolled_back = RetrospectiveOrchestrator(
            self.root / "runs" / "rolled-back",
            identity_path=self.identity_path,
            require_existing_identity=True,
        )
        with self.assertRaisesRegex(RunConflictError, "durable history"):
            rolled_back.start(
                mode="daily",
                start=WINDOW_START,
                end=WINDOW_END,
                hosts=orchestrator_module.DEFAULT_HOSTS,
                history_repo=self.repo,
                history_target_ref=TARGET_REF,
                provider_state=self.provider_state,
                production_marker=self.marker_path,
                provenance=self.provenance,
                publisher_fingerprint=self.fingerprint,
                publisher_gnupg_home=self.gnupg_home,
            )

    def test_marker_is_hmac_cutover_state_not_an_active_lease(self) -> None:
        self.assertFalse(any("lease" in key for key in self.marker))
        self.assertEqual(3, len(self.marker["accepted_shadow_refs"]))
        self.assertEqual(
            self.calibration_receipt.receipt_ref,
            self.marker["calibration_receipt"]["receipt_ref"],
        )
        loaded = authority.load_production_marker(
            self.marker_path,
            identity=self.identity,
            history_repo=self.repo,
            target_ref=TARGET_REF,
            configuration_root=self.configuration_root,
            configuration_ref=self.configuration_ref,
            model_era=self.model_era,
            policy_era=self.policy_era,
        )
        self.assertEqual(self.marker, loaded)

        tampered = dict(self.marker)
        tampered["installed_commits"] = ["f" * 40]
        safe_io.atomic_write_json(self.marker_path, tampered)
        with self.assertRaises(authority.ProductionMarkerError):
            authority.load_production_marker(
                self.marker_path,
                identity=self.identity,
                history_repo=self.repo,
                target_ref=TARGET_REF,
                configuration_root=self.configuration_root,
                configuration_ref=self.configuration_ref,
                model_era=self.model_era,
                policy_era=self.policy_era,
            )

    def test_marker_requires_calibration_and_exact_shadow_gate_evidence(self) -> None:
        mismatched_bindings = (
            ("f" * 64, self.configuration_ref, self.model_era, self.policy_era),
            (
                self.configuration_root,
                "configuration_ref_v2:" + "f" * 64,
                self.model_era,
                self.policy_era,
            ),
            (
                self.configuration_root,
                self.configuration_ref,
                "gpt_5_7",
                self.policy_era,
            ),
            (
                self.configuration_root,
                self.configuration_ref,
                self.model_era,
                "source_catalog_v3",
            ),
        )
        for index, (
            configuration_root,
            configuration_ref,
            model_era,
            policy_era,
        ) in enumerate(mismatched_bindings):
            with (
                self.subTest(binding_index=index),
                self.assertRaisesRegex(
                    authority.ProductionMarkerError,
                    "not bound by calibration evidence",
                ),
            ):
                authority.issue_production_marker(
                    self.root / f"mismatched-binding-{index}.json",
                    identity=self.identity,
                    history_repo=self.repo,
                    target_ref=TARGET_REF,
                    configuration_root=configuration_root,
                    configuration_ref=configuration_ref,
                    model_era=model_era,
                    policy_era=policy_era,
                    calibration_receipt=self.calibration_receipt,
                    accepted_shadow_evidence=self.shadow_evidence,
                    automation_cutover_record=self.automation_cutover_record,
                    installed_commits=(self.base_head,),
                )

        self.assertFalse(hasattr(authority, "issue_shadow_coverage_receipt"))
        self.assertFalse(hasattr(authority, "issue_shadow_cleanup_receipt"))

        with self.assertRaisesRegex(
            authority.ProductionMarkerError,
            "exactly three shadow gate results",
        ):
            authority.issue_production_marker(
                self.root / "missing-shadows.json",
                identity=self.identity,
                history_repo=self.repo,
                target_ref=TARGET_REF,
                configuration_root=self.configuration_root,
                configuration_ref=self.configuration_ref,
                model_era=self.model_era,
                policy_era=self.policy_era,
                calibration_receipt=self.calibration_receipt,
                accepted_shadow_evidence=(),
                automation_cutover_record=self.automation_cutover_record,
                installed_commits=(self.base_head,),
            )

        foreign_evidence = json.loads(json.dumps(self.shadow_evidence))
        foreign_evidence[0]["configuration_root"] = "e" * 64
        with self.assertRaisesRegex(
            authority.ProductionMarkerError,
            "shadow gate receipt is invalid",
        ):
            authority.issue_production_marker(
                self.root / "mixed-configuration-evidence.json",
                identity=self.identity,
                history_repo=self.repo,
                target_ref=TARGET_REF,
                configuration_root=self.configuration_root,
                configuration_ref=self.configuration_ref,
                model_era=self.model_era,
                policy_era=self.policy_era,
                calibration_receipt=self.calibration_receipt,
                accepted_shadow_evidence=foreign_evidence,
                automation_cutover_record=self.automation_cutover_record,
                installed_commits=(self.base_head,),
            )

        failed_corpus = passing_corpus()
        failed_corpus["privacy_holdout"]["passed"] = False
        failed_corpus["privacy_holdout"]["raw_prompt_leak_count"] = 1
        failed_receipt = calibration.evaluate_calibration_corpus(
            self.identity,
            failed_corpus,
        )
        with self.assertRaisesRegex(
            authority.ProductionMarkerError,
            "calibration evidence is invalid",
        ):
            authority.issue_production_marker(
                self.root / "failed-calibration.json",
                identity=self.identity,
                history_repo=self.repo,
                target_ref=TARGET_REF,
                configuration_root=self.configuration_root,
                configuration_ref=self.configuration_ref,
                model_era=self.model_era,
                policy_era=self.policy_era,
                calibration_receipt=failed_receipt,
                accepted_shadow_evidence=self.shadow_evidence,
                automation_cutover_record=self.automation_cutover_record,
                installed_commits=(self.base_head,),
            )

        invalid_daily = json.loads(json.dumps(self.shadow_evidence))
        daily = next(item for item in invalid_daily if item["mode"] == "daily")
        daily["coverage_receipts"][0]["source_units"]["expected"] += 1
        with self.assertRaisesRegex(
            authority.ProductionMarkerError,
            "shadow gate receipt is invalid",
        ):
            authority.issue_production_marker(
                self.root / "invalid-daily.json",
                identity=self.identity,
                history_repo=self.repo,
                target_ref=TARGET_REF,
                configuration_root=self.configuration_root,
                configuration_ref=self.configuration_ref,
                model_era=self.model_era,
                policy_era=self.policy_era,
                calibration_receipt=self.calibration_receipt,
                accepted_shadow_evidence=invalid_daily,
                automation_cutover_record=self.automation_cutover_record,
                installed_commits=(self.base_head,),
            )

        forged = json.loads(json.dumps(self.marker))
        daily = next(
            item
            for item in forged["accepted_shadow_evidence"]
            if item["mode"] == "daily"
        )
        daily["cleanup_receipts"][0]["cleanup_complete"] = False
        daily_body = {
            key: value
            for key, value in daily.items()
            if key not in {"authentication_tag", "receipt_ref"}
        }
        daily["authentication_tag"] = (
            "shadow_receipt_auth_v2:"
            + self.identity.derive_digest("shadow_receipt_auth_v2", daily_body)
        )
        daily["receipt_ref"] = "shadow_receipt_v2:" + self.identity.derive_digest(
            "shadow_receipt_v2", daily_body
        )
        forged["accepted_shadow_evidence"].sort(key=lambda item: item["receipt_ref"])
        forged["accepted_shadow_refs"] = [
            item["receipt_ref"] for item in forged["accepted_shadow_evidence"]
        ]
        body = {
            key: value for key, value in forged.items() if key != "authentication_tag"
        }
        forged["authentication_tag"] = (
            "production_marker_auth_v2:"
            + self.identity.derive_digest("production-marker-v2", body)
        )
        safe_io.atomic_write_json(self.marker_path, forged)
        with self.assertRaisesRegex(
            authority.ProductionMarkerError,
            "shadow evidence is invalid",
        ):
            authority.load_production_marker(
                self.marker_path,
                identity=self.identity,
                history_repo=self.repo,
                target_ref=TARGET_REF,
                configuration_root=self.configuration_root,
                configuration_ref=self.configuration_ref,
                model_era=self.model_era,
                policy_era=self.policy_era,
            )

    def test_shadow_authority_rejects_synthetic_state_bundle_and_cleanup_claim(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run(
            "shadow-authority-adversarial",
            shadow=True,
            bind_export=False,
        )

        with self.assertRaisesRegex(
            orchestrator_module.InvalidTransitionError,
            "staging locator",
        ):
            coordinator.mark_exported("a" * 64)

        state = coordinator.load_state()
        first_host = next(iter(state["source"]["cells"]))
        first_kind = next(iter(state["source"]["cells"][first_host]))
        original_receipt_ref = state["source"]["cells"][first_host][first_kind][
            "transport_receipt_ref"
        ]

        def replace_source_receipt(state):
            state["source"]["cells"][first_host][first_kind][
                "transport_receipt_ref"
            ] = "source_transport_receipt_v2:" + "e" * 64
            return state, None

        coordinator.store.transaction(replace_source_receipt)
        with self.assertRaisesRegex(
            orchestrator_module.InvalidTransitionError,
            "differs from its transport evidence",
        ):
            coordinator.mark_shadow_exported(bundle)

        def restore_source_receipt(state):
            state["source"]["cells"][first_host][first_kind][
                "transport_receipt_ref"
            ] = original_receipt_ref
            return state, None

        coordinator.store.transaction(restore_source_receipt)

        manifest_path = bundle / "manifest.json"
        original_manifest = manifest_path.read_bytes()
        manifest_path.write_bytes(b'{"synthetic":true}\n')
        with self.assertRaisesRegex(
            orchestrator_module.InvalidTransitionError,
            "bundle validation failed",
        ):
            coordinator.mark_shadow_exported(bundle)
        manifest_path.write_bytes(original_manifest)

        synthetic_root = self.root / "synthetic-shadow-run"
        shutil.copytree(coordinator.run_dir, synthetic_root)
        checkpoint_path = synthetic_root / "checkpoint.json"
        checkpoint = json.loads(checkpoint_path.read_text(encoding="ascii"))
        checkpoint["state"]["run_ref"] = "run_ref_v2:" + "f" * 64
        safe_io.atomic_write_json(checkpoint_path, checkpoint)
        synthetic = RetrospectiveOrchestrator(
            synthetic_root,
            identity_path=self.identity_path,
            require_existing_identity=True,
        )
        with self.assertRaises(CheckpointIntegrityError):
            synthetic.mark_shadow_exported(bundle)

        marked = coordinator.mark_shadow_exported(bundle)
        coverage = marked["publication"]["coverage_receipt"]
        self.assertEqual(coordinator.load_state()["run_ref"], coverage["run_ref"])
        self.assertEqual(
            export_retained_bundle(
                bundle,
                *cli_module._retained_inputs(
                    coordinator,
                    coordinator.load_state(),
                ),
            )["bundle_digest"],
            coverage["export_bundle_digest"],
        )

        coordinator._prepare_shadow_cleanup_claim()

        def forge_counter(state):
            state["publication"]["cleanup_claim"]["removed_file_count"] += 1
            return state, None

        coordinator.store.transaction(forge_counter)
        with self.assertRaisesRegex(
            orchestrator_module.InvalidTransitionError,
            "cleanup totals",
        ):
            coordinator.complete_shadow_export()
        self.assertIsNone(coordinator.load_state()["publication"]["cleanup_receipt"])

        path_run, path_bundle = self.build_exportable_run(
            "shadow-cleanup-path-replacement",
            shadow=True,
            bind_export=False,
        )
        path_run.mark_shadow_exported(path_bundle)
        path_run._prepare_shadow_cleanup_claim()
        outside = self.root / "outside-shadow-cleanup"
        outside.mkdir(mode=0o700)
        marker = outside / "marker.bin"
        marker.write_bytes(b"must survive")
        os.chmod(marker, 0o600)
        raw_root = path_run.run_dir / "raw-inputs"
        raw_saved = path_run.run_dir / "raw-inputs.saved"
        raw_root.rename(raw_saved)
        raw_root.symlink_to(outside, target_is_directory=True)

        pending = path_run.complete_shadow_export()
        self.assertTrue(pending["cleanup_pending"])
        self.assertEqual(b"must survive", marker.read_bytes())
        self.assertIsNone(path_run.load_state()["publication"]["cleanup_receipt"])

    def test_genuine_shadow_cleanup_is_durable_and_lost_response_idempotent(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run(
            "shadow-cleanup-genuine",
            shadow=True,
            bind_export=False,
        )
        raw_file = coordinator.run_dir / "raw-inputs" / "cleanup-evidence.bin"
        raw_file.write_bytes(b"real shadow cleanup evidence")
        os.chmod(raw_file, 0o600)
        expected = coordinator._raw_cleanup_inventory()

        coordinator.mark_shadow_exported(bundle)
        original_transaction = coordinator.store.transaction

        def lose_response_after_commit(mutator, **kwargs):
            result = original_transaction(mutator, **kwargs)
            if result.snapshot.state["publication"]["phase"] == "shadow_complete":
                raise RuntimeError("simulated lost cleanup response")
            return result

        with (
            mock.patch.object(
                coordinator.store,
                "transaction",
                side_effect=lose_response_after_commit,
            ),
            self.assertRaisesRegex(RuntimeError, "lost cleanup response"),
        ):
            coordinator.complete_shadow_export()
        replay = coordinator.complete_shadow_export()
        cleanup = replay["publication"]["cleanup_receipt"]

        self.assertFalse(replay["cleanup_pending"])
        self.assertTrue(replay["idempotent"])
        self.assertEqual(expected["byte_count"], cleanup["removed_byte_count"])
        self.assertEqual(
            expected["directory_count"], cleanup["removed_directory_count"]
        )
        self.assertEqual(expected["file_count"], cleanup["removed_file_count"])
        self.assertEqual(
            replay["publication"]["coverage_receipt"]["receipt_ref"],
            cleanup["coverage_receipt_ref"],
        )
        for name in orchestrator_module.SHADOW_CLEANUP_ROOTS:
            self.assertFalse((coordinator.run_dir / name).exists())

    def test_provider_initialization_requires_exact_revision_and_request(self) -> None:
        replay = authority.initialize_provider_cache(
            self.provider_state,
            history=self.initial_history,
            expected_revision=0,
            identity=self.identity,
        )
        self.assertTrue(replay["idempotent"])
        with self.assertRaises(authority.ProviderCacheConflict):
            authority.initialize_provider_cache(
                self.provider_state,
                history=self.initial_history,
                expected_revision=1,
                identity=self.identity,
            )
        changed_request = replace(self.initial_history, head_commit="f" * 40)
        with self.assertRaises(authority.ProviderCacheConflict):
            authority.initialize_provider_cache(
                self.provider_state,
                history=changed_request,
                expected_revision=0,
                identity=self.identity,
            )

    def test_provider_cache_rejects_tampered_nonzero_initialization_revision(
        self,
    ) -> None:
        cache_path = self.provider_state / authority.PROVIDER_CACHE_FILE
        tampered = json.loads(cache_path.read_text(encoding="ascii"))
        tampered["initialization_request"]["expected_revision"] = 1
        tampered["initialization_request"]["history_projection"][
            "provider_revision"
        ] = 1
        safe_io.atomic_write_json(cache_path, tampered)

        with self.assertRaisesRegex(
            authority.ProviderCacheError,
            "empty cache",
        ):
            authority.assert_provider_cache_matches(
                self.provider_state,
                self.initial_history,
                identity=self.identity,
            )

    def test_provider_initialization_revision_is_independent_of_history_projection(
        self,
    ) -> None:
        state_dir = self.root / "provider-from-existing-history"
        existing_history = replace(self.initial_history, provider_revision=7)

        initialized = authority.initialize_provider_cache(
            state_dir,
            history=existing_history,
            expected_revision=0,
            identity=self.identity,
        )
        validated = authority.assert_provider_cache_matches(
            state_dir,
            existing_history,
            identity=self.identity,
        )

        self.assertEqual(
            0,
            initialized["state"]["initialization_request"]["expected_revision"],
        )
        self.assertEqual(7, validated["provider_revision"])

    def test_provider_cache_must_be_exact_before_creation_and_promotion(self) -> None:
        coordinator, bundle = self.build_exportable_run("provider-cache-closed")
        cache_path = self.provider_state / authority.PROVIDER_CACHE_FILE
        original_cache = cache_path.read_bytes()
        malformed_cache = b'{"schema":"retrospective_provider_cache_v2"}\n'

        for label, payload in (("missing", None), ("malformed", malformed_cache)):
            with self.subTest(phase="create", case=label):
                if payload is None:
                    cache_path.unlink()
                else:
                    safe_io.atomic_write_bytes(cache_path, payload)
                try:
                    with self.assertRaises(PublicationRejected):
                        self.transaction(
                            coordinator,
                            bundle,
                            journal_name=f"{label}-cache-create.json",
                        )
                    self.assertEqual(self.base_head, self.head())
                    self.assertFalse(
                        (coordinator.run_dir / f"{label}-cache-create.json").exists()
                    )
                finally:
                    safe_io.atomic_write_bytes(cache_path, original_cache)

        transaction = self.transaction(
            coordinator,
            bundle,
            journal_name="provider-cache-promotion.json",
        )
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()
        for label, payload in (("missing", None), ("malformed", malformed_cache)):
            with self.subTest(phase="promote", case=label):
                if payload is None:
                    cache_path.unlink()
                else:
                    safe_io.atomic_write_bytes(cache_path, payload)
                try:
                    with self.assertRaises(authority.ProviderCacheError):
                        transaction.promote()
                    self.assertEqual("compliance_closed", transaction.status()["phase"])
                    self.assertEqual(self.base_head, self.head())
                    with self.assertRaises(authority.ProviderCacheError):
                        PublicationTransaction.open(
                            transaction.journal_path,
                            adapter=self.adapter,
                            expected_attempt_ref=transaction.attempt_ref,
                        )
                    journal = safe_io.read_bounded_json(
                        transaction.journal_path,
                        max_bytes=2 * 1024 * 1024,
                        require_owner_only=True,
                    )
                    self.assertEqual("compliance_closed", journal["phase"])
                finally:
                    safe_io.atomic_write_bytes(cache_path, original_cache)

    def test_state_paths_reject_symlink_ancestors_and_lock_symlinks(self) -> None:
        real_parent = self.root / "path-target"
        real_parent.mkdir(mode=0o700)
        alias = self.root / "path-alias"
        alias.symlink_to(real_parent, target_is_directory=True)

        with self.assertRaises(safe_io.UnsafePathError):
            authority.initialize_provider_cache(
                alias / "provider",
                history=self.initial_history,
                expected_revision=0,
                identity=self.identity,
            )
        self.assertFalse((real_parent / "provider").exists())

        with self.assertRaises(StateCorruptionError):
            LocalGitPublicationAdapter(
                self.repo,
                alias / "adapter-state",
                signing_key=self.fingerprint,
                gnupg_home=self.gnupg_home,
                expected_signer_uid=DEFAULT_PUBLISHER_UID,
                signing_program=self.gpg,
            )
        self.assertFalse((real_parent / "adapter-state").exists())

        coordinator, bundle = self.build_exportable_run("symlink-journal")
        state = coordinator.load_state()
        with self.assertRaises(StateCorruptionError):
            PublicationTransaction.create(
                alias / "journal-state" / "publication.json",
                bundle_dir=bundle,
                destination=self.destination(state),
                target_ref=TARGET_REF,
                expected_target_head=state["authority"]["history_snapshot"][
                    "history_commit"
                ],
                run_dir=coordinator.run_dir,
                identity_path=self.identity_path,
                adapter=self.adapter,
            )
        self.assertFalse((real_parent / "journal-state").exists())

        lock_state = self.root / "lock-state"
        lock_state.mkdir(mode=0o700)
        lock_target = self.root / "lock-target"
        safe_io.atomic_write_bytes(lock_target, b"")
        (lock_state / "publication.lock").symlink_to(lock_target)
        with self.assertRaises((OSError, StateCorruptionError)):
            LocalGitPublicationAdapter(
                self.repo,
                lock_state,
                signing_key=self.fingerprint,
                gnupg_home=self.gnupg_home,
                expected_signer_uid=DEFAULT_PUBLISHER_UID,
                signing_program=self.gpg,
            )

    def test_git_metadata_requires_real_current_user_controlled_directories(
        self,
    ) -> None:
        git_dir = Path(
            run_command(
                ["git", "rev-parse", "--path-format=absolute", "--git-dir"],
                cwd=self.repo,
            ).stdout.strip()
        )
        original_mode = git_dir.stat().st_mode & 0o777
        os.chmod(git_dir, original_mode | 0o020)
        try:
            with self.assertRaisesRegex(
                publication_support.LocalGitPublicationError,
                "current-user controlled|current-user-controlled",
            ):
                self.publication_adapter()
        finally:
            os.chmod(git_dir, original_mode)

        objects = git_dir / "objects"
        real_objects = git_dir / "objects-real"
        objects.rename(real_objects)
        objects.symlink_to(real_objects, target_is_directory=True)
        try:
            with self.assertRaisesRegex(
                publication_support.LocalGitPublicationError,
                "Git object store",
            ):
                self.publication_adapter()
        finally:
            objects.unlink()
            real_objects.rename(objects)

    def test_linked_worktree_uses_validated_real_git_metadata(self) -> None:
        linked = self.root / "linked-history"
        run_command(
            ["git", "worktree", "add", "--detach", str(linked), self.base_head],
            cwd=self.repo,
        )
        common_dir = Path(
            run_command(
                [
                    "git",
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ],
                cwd=linked,
            ).stdout.strip()
        )
        common_mode = common_dir.stat().st_mode & 0o777
        os.chmod(common_dir, common_mode | 0o020)
        try:
            with self.assertRaisesRegex(
                publication_support.LocalGitPublicationError,
                "current-user-controlled real directory",
            ):
                LocalGitPublicationAdapter(
                    linked,
                    self.root / "invalid-linked-provider-state",
                    signing_key=self.fingerprint,
                    gnupg_home=self.gnupg_home,
                    expected_signer_uid=DEFAULT_PUBLISHER_UID,
                    signing_program=self.gpg,
                )
        finally:
            os.chmod(common_dir, common_mode)

        adapter = LocalGitPublicationAdapter(
            linked,
            self.root / "linked-provider-state",
            signing_key=self.fingerprint,
            gnupg_home=self.gnupg_home,
            expected_signer_uid=DEFAULT_PUBLISHER_UID,
            signing_program=self.gpg,
        )

        self.assertEqual(linked, adapter.repo_path)
        self.assertEqual(
            self.base_head,
            adapter._git(("rev-parse", "HEAD")).stdout.decode("ascii").strip(),
        )

    def test_history_git_commands_ignore_replace_refs(self) -> None:
        tree = run_command(
            ["git", "rev-parse", f"{self.base_head}^{{tree}}"], cwd=self.repo
        ).stdout.strip()
        replacement = run_command(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit-tree",
                tree,
                "-m",
                "Replacement history",
            ],
            cwd=self.repo,
        ).stdout.strip()
        run_command(["git", "replace", self.base_head, replacement], cwd=self.repo)
        ordinary = run_command(
            ["git", "show", "-s", "--format=%s", self.base_head], cwd=self.repo
        ).stdout.strip()
        repository = authority._GitRepository(
            self.repo,
            gnupg_home=self.gnupg_home,
            git_binary="git",
            gpg_program=self.gpg,
        )

        publication_subject = (
            self.adapter._git(("show", "-s", "--format=%s", self.base_head))
            .stdout.decode("utf-8")
            .strip()
        )
        authority_subject = repository.text("show", "-s", "--format=%s", self.base_head)

        self.assertEqual("Replacement history", ordinary)
        self.assertEqual("Initialize history", publication_subject)
        self.assertEqual("Initialize history", authority_subject)

    def test_history_git_commands_reject_grafts_that_forge_reachability(self) -> None:
        tree = run_command(
            ["git", "rev-parse", f"{self.base_head}^{{tree}}"], cwd=self.repo
        ).stdout.strip()
        unreachable = run_command(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit-tree",
                tree,
                "-m",
                "Unreachable history",
            ],
            cwd=self.repo,
        ).stdout.strip()
        grafts = self.repo / ".git" / "info" / "grafts"
        grafts.write_text(f"{self.base_head} {unreachable}\n", encoding="ascii")

        forged = subprocess.run(
            ["git", "merge-base", "--is-ancestor", unreachable, self.base_head],
            cwd=self.repo,
            check=False,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(0, forged.returncode)
        with self.assertRaisesRegex(
            publication_support.LocalGitPublicationError,
            "Git grafts are not allowed",
        ):
            self.adapter._is_ancestor(unreachable, self.base_head)
        with self.assertRaisesRegex(
            publication_support.LocalGitPublicationError,
            "Git grafts are not allowed",
        ):
            self.publication_adapter()

    def test_history_git_rejects_promisor_configuration_without_credentials(
        self,
    ) -> None:
        marker = self.root / "credential-helper-ran"
        helper = self.root / "credential-helper"
        helper.write_text(
            f"#!/bin/sh\n/usr/bin/touch {shlex.quote(str(marker))}\nexit 1\n",
            encoding="ascii",
        )
        helper.chmod(0o700)
        run_command(
            [
                "git",
                "config",
                "--local",
                "credential.helper",
                f"!{shlex.quote(str(helper))}",
            ],
            cwd=self.repo,
        )
        run_command(
            ["git", "config", "--local", "remote.origin.promisor", "true"],
            cwd=self.repo,
        )
        try:
            with self.assertRaisesRegex(
                publication_support.LocalGitPublicationError,
                "complete and non-promisor",
            ):
                self.publication_adapter()
            with self.assertRaisesRegex(
                authority.HistoryValidationError,
                "complete and non-promisor",
            ):
                authority._GitRepository(
                    self.repo,
                    gnupg_home=self.gnupg_home,
                    git_binary="git",
                    gpg_program=self.gpg,
                )
            self.assertFalse(marker.exists())
        finally:
            run_command(
                ["git", "config", "--local", "--unset-all", "credential.helper"],
                cwd=self.repo,
            )
            run_command(
                ["git", "config", "--local", "--unset-all", "remote.origin.promisor"],
                cwd=self.repo,
            )

    def test_history_git_commands_disable_lazy_fetch_and_credentials(self) -> None:
        publication_calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        authority_calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        real_publication_run = publication_git_commits._run_bounded_subprocess
        real_authority_run = authority._run_bounded

        def record_publication(argv, **kwargs):
            publication_calls.append((tuple(argv), dict(kwargs["environment"])))
            return real_publication_run(argv, **kwargs)

        def record_authority(argv, **kwargs):
            authority_calls.append((tuple(argv), dict(kwargs["env"])))
            return real_authority_run(argv, **kwargs)

        with mock.patch.object(
            publication_git_commits,
            "_run_bounded_subprocess",
            side_effect=record_publication,
        ):
            adapter = self.publication_adapter()
            adapter._git(("rev-parse", "HEAD"))
        with mock.patch.object(
            authority,
            "_run_bounded",
            side_effect=record_authority,
        ):
            repository = authority._GitRepository(
                self.repo,
                gnupg_home=self.gnupg_home,
                git_binary="git",
                gpg_program=self.gpg,
            )
            repository.text("rev-parse", "HEAD")

        for calls in (publication_calls, authority_calls):
            self.assertTrue(calls)
            for argv, environment in calls:
                self.assertIn("core.askPass=/usr/bin/false", argv)
                self.assertIn("credential.helper=", argv)
                self.assertEqual("/usr/bin/false", environment["GIT_ASKPASS"])
                self.assertEqual("/usr/bin/false", environment["SSH_ASKPASS"])
                self.assertEqual("1", environment["GIT_NO_LAZY_FETCH"])
                self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])
                self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])

    def test_privacy_reread_rejects_replacement_symlink_and_oversize_races(
        self,
    ) -> None:
        _, bundle = self.build_exportable_run("privacy-races")
        target_name = "manifest.json"
        target = bundle / target_name
        original = target.read_bytes()
        real_open = os.open

        for scenario in ("replacement", "symlink", "oversize"):
            with self.subTest(scenario=scenario):
                safe_io.atomic_write_bytes(target, original)
                inventory = build_artifact_inventory(bundle)
                replacement = self.root / f"{scenario}-replacement"
                if scenario == "replacement":
                    changed = bytearray(original)
                    changed[0] ^= 1
                    safe_io.atomic_write_bytes(replacement, bytes(changed))
                elif scenario == "symlink":
                    symlink_source = self.root / "symlink-source"
                    safe_io.atomic_write_bytes(symlink_source, original)
                    replacement.symlink_to(symlink_source)

                triggered = False

                def racing_open(
                    path,
                    flags,
                    mode=0o777,
                    *,
                    dir_fd=None,
                ):
                    nonlocal triggered
                    if path == target_name and dir_fd is not None and not triggered:
                        triggered = True
                        if scenario in {"replacement", "symlink"}:
                            os.replace(replacement, target)
                        else:
                            descriptor = real_open(
                                target,
                                os.O_WRONLY | os.O_APPEND,
                            )
                            try:
                                os.write(descriptor, b"oversize")
                            finally:
                                os.close(descriptor)
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                try:
                    with mock.patch.object(
                        finalize_module.os,
                        "open",
                        side_effect=racing_open,
                    ):
                        with self.assertRaises(finalize_module.ArtifactValidationError):
                            finalize_module._privacy_validate_bundle(
                                bundle,
                                expected_inventory=inventory,
                            )
                    self.assertTrue(triggered)
                finally:
                    target.unlink(missing_ok=True)
                    safe_io.atomic_write_bytes(target, original)
                    replacement.unlink(missing_ok=True)

    def test_recovery_repairs_outer_promoted_after_exact_target_cas_crash(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("crash-after-target-cas")

        def crash(point, _state):
            if point == "promote.after_target_cas":
                raise RuntimeError("simulated target CAS crash")

        crashing = self.publication_adapter(failure_injector=crash)
        transaction = self.transaction(coordinator, bundle, adapter=crashing)
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()
        with self.assertRaisesRegex(RuntimeError, "target CAS crash"):
            transaction.promote()
        self.assertEqual("compliance_closed", transaction.status()["phase"])
        self.assertNotEqual(self.base_head, self.head())

        recovered_adapter = self.publication_adapter()
        recovered = PublicationTransaction.open(
            transaction.journal_path,
            adapter=recovered_adapter,
            expected_attempt_ref=transaction.attempt_ref,
        )
        self.assertEqual("promoted", recovered.status()["phase"])
        self.assertEqual(
            self.head(), recovered.status()["receipts"]["promotion"]["target_head"]
        )
        self.assertEqual(
            "promoted",
            safe_io.read_bounded_json(
                transaction.journal_path,
                max_bytes=2 * 1024 * 1024,
                require_owner_only=True,
            )["phase"],
        )

    def test_missing_retention_sidecar_fails_before_binding_state_persists(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("missing-retention-sidecar")
        sidecar = bundle.with_name(f".{bundle.name}.retention-v2.json")
        sidecar.unlink()
        transaction = self.transaction(coordinator, bundle)

        with self.assertRaisesRegex(StateCorruptionError, "sidecar is missing"):
            transaction.prepare()

        attempt = self.adapter.inspect_attempt(transaction.attempt_ref)
        self.assertIsNotNone(attempt)
        assert attempt is not None
        self.assertFalse(attempt["retention_bound"])

    def test_retention_binding_and_abort_serialize_on_the_attempt_lock(self) -> None:
        for cleanup_first in (False, True):
            with self.subTest(cleanup_first=cleanup_first):
                coordinator, bundle = self.build_exportable_run(
                    f"retention-race-{cleanup_first}"
                )
                adapter = self.publication_adapter()
                abort_adapter = self.publication_adapter()
                transaction = self.transaction(
                    coordinator,
                    bundle,
                    adapter=adapter,
                )
                request = transaction.operation_request("prepare")
                lock_receipt = adapter.acquire_publication_lock(request)
                adapter.reserve(request)

                entered = threading.Event()
                proceed = threading.Event()
                bind_called = threading.Event()
                failures: list[BaseException] = []
                real_bind = adapter._bind_export_retention_sidecars
                real_claim = abort_adapter._local_cleanup_claim

                def blocking_bind(*args, **kwargs):
                    bind_called.set()
                    entered.set()
                    if not proceed.wait(5):
                        raise AssertionError("retention race did not resume")
                    return real_bind(*args, **kwargs)

                def blocking_claim(*args, **kwargs):
                    entered.set()
                    if not proceed.wait(5):
                        raise AssertionError("cleanup race did not resume")
                    return real_claim(*args, **kwargs)

                def release() -> None:
                    try:
                        adapter.release_publication_lock(request, lock_receipt)
                    except BaseException as error:
                        failures.append(error)

                def abort() -> None:
                    try:
                        abort_adapter.abort(request)
                    except BaseException as error:
                        failures.append(error)

                release_thread = threading.Thread(target=release)
                abort_thread = threading.Thread(target=abort)
                if cleanup_first:
                    with (
                        mock.patch.object(
                            abort_adapter,
                            "_local_cleanup_claim",
                            side_effect=blocking_claim,
                        ),
                        mock.patch.object(
                            adapter,
                            "_bind_export_retention_sidecars",
                            wraps=real_bind,
                        ) as bind_mock,
                    ):
                        abort_thread.start()
                        self.assertTrue(entered.wait(5))
                        release_thread.start()
                        proceed.set()
                        abort_thread.join(5)
                        release_thread.join(5)
                        self.assertEqual(0, bind_mock.call_count)
                else:
                    with mock.patch.object(
                        adapter,
                        "_bind_export_retention_sidecars",
                        side_effect=blocking_bind,
                    ):
                        release_thread.start()
                        self.assertTrue(entered.wait(5))
                        abort_thread.start()
                        self.assertTrue(abort_thread.is_alive())
                        proceed.set()
                        release_thread.join(5)
                        abort_thread.join(5)

                self.assertFalse(release_thread.is_alive())
                self.assertFalse(abort_thread.is_alive())
                self.assertEqual([], failures)
                attempt = adapter.inspect_attempt(transaction.attempt_ref)
                self.assertIsNotNone(attempt)
                assert attempt is not None
                self.assertTrue(attempt["aborted"])
                self.assertIn("cleanup", attempt["receipts"])
                self.assertIn("reservation_release", attempt["receipts"])
                self.assertFalse(attempt["capacity_held"])
                self.assertEqual(
                    not cleanup_first,
                    attempt["retention_bound"],
                )
                self.assertEqual(
                    attempt["retention_bound"],
                    attempt["cleanup_claim"]["retention_bound"],
                )

    def test_abort_reconciles_retention_bound_before_attempt_flag_persists(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run(
            "retention-bind-before-attempt-flag"
        )

        def crash(point, _state):
            if point == "release_publication_lock.after_retention_bind":
                raise RuntimeError("simulated retention binding journal crash")

        adapter = self.publication_adapter(failure_injector=crash)
        transaction = self.transaction(coordinator, bundle, adapter=adapter)
        with self.assertRaisesRegex(RuntimeError, "binding journal crash"):
            transaction.prepare()

        attempt = adapter.inspect_attempt(transaction.attempt_ref)
        self.assertIsNotNone(attempt)
        assert attempt is not None
        self.assertFalse(attempt["retention_bound"])
        sidecar = bundle.with_name(f".{bundle.name}.retention-v2.json")
        bound = safe_io.read_bounded_json(
            sidecar,
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        self.assertEqual("publication_bound", bound["status"])
        self.assertEqual(
            transaction.attempt_ref,
            bound["publication_attempt_ref"],
        )

        transaction.abort("retention_binding_interrupted")

        terminal = safe_io.read_bounded_json(
            sidecar,
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        self.assertEqual("publication_terminal", terminal["status"])
        self.assertEqual("aborted", terminal["terminal_disposition"])

    def test_cleanup_claim_blocks_every_stale_forward_transition(self) -> None:
        coordinator, bundle = self.build_exportable_run("cleanup-monotonicity")
        adapter = self.publication_adapter()
        transaction = self.transaction(coordinator, bundle, adapter=adapter)
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()

        def crash(point, _state):
            if point == "cleanup.after_claim_persist":
                raise RuntimeError("simulated cleanup claim crash")

        crashing = self.publication_adapter(failure_injector=crash)
        with self.assertRaisesRegex(RuntimeError, "cleanup claim crash"):
            crashing.cleanup(transaction.operation_request("cleanup"))

        for method_name, phase in (
            ("stage", "stage"),
            ("seal", "seal"),
            ("close_compliance", "close_compliance"),
            ("promote", "promote"),
        ):
            with (
                self.subTest(method=method_name),
                self.assertRaisesRegex(
                    publication_support.InvalidTransitionError,
                    "cleanup-owned",
                ),
            ):
                getattr(adapter, method_name)(transaction.operation_request(phase))

    def test_legacy_capacity_requires_matching_durable_attempt(self) -> None:
        coordinator, bundle = self.build_exportable_run("legacy-capacity-binding")
        adapter = self.publication_adapter()
        transaction = self.transaction(coordinator, bundle, adapter=adapter)
        transaction.prepare()
        request = transaction.operation_request("stage")
        attempt = adapter.inspect_attempt(transaction.attempt_ref)
        self.assertIsNotNone(attempt)
        assert attempt is not None
        capacity = attempt["capacity_bytes"]
        capacity_path = self.provider_state / "capacity.json"
        ledger = safe_io.read_bounded_json(
            capacity_path,
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        ledger["reservations"][transaction.attempt_ref] = capacity
        safe_io.atomic_write_json(capacity_path, ledger)

        self.assertEqual(capacity, adapter._capacity_reservation(request))
        migrated = safe_io.read_bounded_json(
            capacity_path,
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )["reservations"][transaction.attempt_ref]
        self.assertEqual("local_git_capacity_reservation_v2", migrated["schema"])

        orphan_ref = "attempt_ref_v2:" + "f" * 64
        orphan_request = replace(request, attempt_ref=orphan_ref)
        ledger = safe_io.read_bounded_json(
            capacity_path,
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        ledger["reservations"][orphan_ref] = capacity
        safe_io.atomic_write_json(capacity_path, ledger)
        with self.assertRaisesRegex(
            StateCorruptionError,
            "lacks a durable attempt",
        ):
            adapter._capacity_reservation(orphan_request)

    def test_capacity_release_requires_exact_request_and_amount(self) -> None:
        coordinator, bundle = self.build_exportable_run("capacity-release-binding")
        adapter = self.publication_adapter()
        transaction = self.transaction(coordinator, bundle, adapter=adapter)
        transaction.prepare()
        request = transaction.operation_request("stage")
        attempt = adapter.inspect_attempt(transaction.attempt_ref)
        self.assertIsNotNone(attempt)
        assert attempt is not None
        amount = attempt["capacity_bytes"]
        wrong_request = replace(request, destination=f"{request.destination}.other")

        with self.assertRaisesRegex(StateCorruptionError, "binding changed"):
            adapter._release_capacity(wrong_request, amount)
        with self.assertRaisesRegex(StateCorruptionError, "release binding changed"):
            adapter._release_capacity(request, amount + 1)

        ledger = safe_io.read_bounded_json(
            self.provider_state / "capacity.json",
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        self.assertIn(transaction.attempt_ref, ledger["reservations"])
        adapter._release_capacity(request, amount)
        released = safe_io.read_bounded_json(
            self.provider_state / "capacity.json",
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        self.assertNotIn(transaction.attempt_ref, released["reservations"])

    def test_legacy_capacity_migration_rejects_each_attempt_authority_drift(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("legacy-capacity-authority")
        adapter = self.publication_adapter()
        transaction = self.transaction(coordinator, bundle, adapter=adapter)
        transaction.prepare()
        request = transaction.operation_request("stage")
        original = adapter._read_attempt(transaction.attempt_ref)
        self.assertIsNotNone(original)
        assert original is not None
        amount = original["capacity_bytes"]
        capacity_path = self.provider_state / "capacity.json"
        attempt_path = adapter._attempt_state_path(transaction.attempt_ref)

        def reservation_receipt_drift(state):
            state["receipts"]["reservation"]["capacity_bytes"] += 1

        def observation_drift(state):
            state["receipts"]["target_observation"]["destination_exists"] = True

        def unit_plan_drift(state):
            state["unit_plan"] = []

        def inventory_drift(state):
            state["unit_plan"][0]["inventory"]["total_bytes"] += 1

        def status_drift(state):
            state["capacity_held"] = False

        for label, mutate in {
            "inventory": inventory_drift,
            "observation": observation_drift,
            "receipt": reservation_receipt_drift,
            "status": status_drift,
            "unit-plan": unit_plan_drift,
        }.items():
            with self.subTest(authority=label):
                tampered = copy.deepcopy(original)
                mutate(tampered)
                safe_io.atomic_write_json(attempt_path, tampered)
                ledger = safe_io.read_bounded_json(
                    capacity_path,
                    max_bytes=1024 * 1024,
                    require_owner_only=True,
                )
                ledger["reservations"][transaction.attempt_ref] = amount
                safe_io.atomic_write_json(capacity_path, ledger)
                with self.assertRaises(StateCorruptionError):
                    adapter._capacity_reservation(request)

        safe_io.atomic_write_json(attempt_path, original)

    def test_abort_recovers_capacity_persisted_before_attempt_state(self) -> None:
        coordinator, bundle = self.build_exportable_run("capacity-before-attempt-state")

        def crash(point, _state):
            if point == "reserve.after_capacity_persist":
                raise RuntimeError("simulated reservation journal crash")

        adapter = self.publication_adapter(failure_injector=crash)
        transaction = self.transaction(coordinator, bundle, adapter=adapter)
        with self.assertRaisesRegex(RuntimeError, "reservation journal crash"):
            transaction.prepare()
        self.assertEqual("created", transaction.status()["phase"])
        self.assertIsNone(adapter.inspect_attempt(transaction.attempt_ref))

        transaction.abort("reservation_interrupted")
        self.assertEqual("aborted", transaction.status()["phase"])
        attempt = adapter.inspect_attempt(transaction.attempt_ref)
        self.assertIsNotNone(attempt)
        assert attempt is not None
        self.assertGreater(attempt["capacity_bytes"], 0)
        self.assertFalse(attempt["capacity_held"])
        self.assertTrue(attempt["cleanup_claim"]["provider_attempt_reserved"])
        self.assertEqual(
            attempt["capacity_bytes"],
            attempt["cleanup_claim"]["capacity_reservation_observed"],
        )
        ledger = safe_io.read_bounded_json(
            self.provider_state / "capacity.json",
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        self.assertNotIn(transaction.attempt_ref, ledger["reservations"])
        self.assertEqual(
            transaction.status(),
            PublicationTransaction.open(
                transaction.journal_path,
                adapter=self.publication_adapter(),
                expected_attempt_ref=transaction.attempt_ref,
            ).status(),
        )

    def test_target_cas_recovery_does_not_require_lost_local_bundle(self) -> None:
        coordinator, bundle = self.build_exportable_run("target-cas-bundle-lost")

        def crash(point, _state):
            if point == "promote.after_target_cas":
                raise RuntimeError("simulated target CAS crash")

        transaction = self.transaction(
            coordinator,
            bundle,
            adapter=self.publication_adapter(failure_injector=crash),
        )
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()
        with self.assertRaisesRegex(RuntimeError, "target CAS crash"):
            transaction.promote()
        publication_tip = self.head()
        shutil.rmtree(bundle)

        recovered = PublicationTransaction.open(
            transaction.journal_path,
            adapter=self.publication_adapter(),
            expected_attempt_ref=transaction.attempt_ref,
        )
        self.assertEqual("promoted", recovered.status()["phase"])
        self.assertEqual(
            publication_tip,
            recovered.status()["receipts"]["promotion"]["target_head"],
        )
        recovered.commit()

        self.assertEqual("committed", recovered.status()["phase"])
        self.assertEqual(1, self.load_history().provider_revision)

    def test_target_cas_recovery_advances_cache_below_unrelated_successor(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run(
            "target-cas-unrelated-successor"
        )

        def crash(point, _state):
            if point == "promote.after_target_cas":
                raise RuntimeError("simulated target CAS crash")

        crashing = self.publication_adapter(failure_injector=crash)
        transaction = self.transaction(coordinator, bundle, adapter=crashing)
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()
        with self.assertRaisesRegex(RuntimeError, "target CAS crash"):
            transaction.promote()
        publication_tip = self.head()

        run_command(["git", "read-tree", publication_tip], cwd=self.repo)
        (self.repo / "unrelated.txt").write_text("successor\n", encoding="ascii")
        run_command(["git", "add", "unrelated.txt"], cwd=self.repo)
        run_command(
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "Add unrelated successor",
            ],
            cwd=self.repo,
        )
        successor = self.head()
        self.assertNotEqual(publication_tip, successor)

        recovered = PublicationTransaction.open(
            transaction.journal_path,
            adapter=self.publication_adapter(),
            expected_attempt_ref=transaction.attempt_ref,
        )
        self.assertEqual("promoted", recovered.status()["phase"])
        self.assertEqual(
            publication_tip,
            recovered.status()["receipts"]["promotion"]["target_head"],
        )
        recovered.commit()

        published = self.load_history()
        self.assertEqual(successor, published.head_commit)
        self.assertEqual(publication_tip, published.publication_commit)
        authority.assert_provider_cache_matches(
            self.provider_state,
            published,
            identity=self.identity,
        )
        self.assertEqual("committed", recovered.status()["phase"])

    def test_recovery_repairs_outer_committed_after_exact_provider_cas_crash(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("crash-after-provider-cas")

        def crash(point, _state):
            if point == "advance_state.after_provider_cas":
                raise RuntimeError("simulated provider CAS crash")

        crashing = self.publication_adapter(failure_injector=crash)
        transaction = self.transaction(coordinator, bundle, adapter=crashing)
        transaction.prepare()
        transaction.stage()
        transaction.seal()
        transaction.close_compliance()
        transaction.promote()
        with self.assertRaisesRegex(RuntimeError, "provider CAS crash"):
            transaction.commit()
        self.assertEqual("promoted", transaction.status()["phase"])
        authority.assert_provider_cache_matches(
            self.provider_state,
            self.load_history(),
            identity=self.identity,
        )

        recovered_adapter = self.publication_adapter()
        recovered = PublicationTransaction.open(
            transaction.journal_path,
            adapter=recovered_adapter,
            expected_attempt_ref=transaction.attempt_ref,
        )
        self.assertEqual("committed", recovered.status()["phase"])
        self.assertTrue(recovered.status()["state_advanced"])
        self.assertFalse(recovered.status()["reservations_held"])
        reopened = PublicationTransaction.open(
            transaction.journal_path,
            adapter=recovered_adapter,
            expected_attempt_ref=transaction.attempt_ref,
        )
        self.assertEqual("committed", reopened.status()["phase"])

    def test_pre_reservation_abort_recovers_lost_cleanup_responses_exactly_once(
        self,
    ) -> None:
        coordinator, bundle = self.build_exportable_run("abort-before-reservation")
        advanced = False

        def advance_target(point, _state):
            nonlocal advanced
            if point != "prepare.after_inventory" or advanced:
                return
            advanced = True
            (self.repo / "conflict.txt").write_text("conflict\n", encoding="ascii")
            run_command(["git", "add", "conflict.txt"], cwd=self.repo)
            run_command(
                [
                    "git",
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "Advance target before reservation",
                ],
                cwd=self.repo,
            )

        transaction = self.transaction(
            coordinator,
            bundle,
            failure_injector=advance_target,
        )
        with self.assertRaises(finalize_module.TargetHeadConflict):
            transaction.prepare()
        self.assertEqual("abort_pending", transaction.status()["phase"])
        self.assertIsNone(self.adapter.inspect_attempt(transaction.attempt_ref))
        with self.assertRaises(finalize_module.ReceiptValidationError):
            transaction.recover_abort(cleanup_receipt={"synthetic": True})

        claim = coordinator.load_state()["publication"]["publication_claim"]
        inspected = PublicationTransaction.inspect_local_for_run(
            transaction.journal_path,
            bundle_dir=bundle,
            destination=self.destination(coordinator.load_state()),
            target_ref=TARGET_REF,
            expected_target_head=transaction.status()["plan"]["expected_target_head"],
            run_dir=coordinator.run_dir,
            identity_path=self.identity_path,
        )
        self.assertEqual("abort_pending", inspected["phase"])
        coordinator.claim_publication(
            claim["attempt_ref"],
            claim["plan_digest"],
        )
        with self.assertRaises(RunConflictError):
            coordinator.mark_finalized(
                "aborted",
                attempt_ref=claim["attempt_ref"],
                claim_revision=claim["checkpoint_revision"],
                plan_digest=claim["plan_digest"],
            )

        lost = set()

        def lose_response(point, _state):
            if (
                point
                in {
                    "cleanup.after_persist",
                    "release_reservations.after_persist",
                }
                and point not in lost
            ):
                lost.add(point)
                raise RuntimeError(f"lost {point}")

        crashing_adapter = self.publication_adapter(failure_injector=lose_response)
        with self.assertRaisesRegex(RuntimeError, "cleanup.after_persist"):
            PublicationTransaction.open(
                transaction.journal_path,
                adapter=crashing_adapter,
                expected_attempt_ref=transaction.attempt_ref,
            )
        with self.assertRaisesRegex(RuntimeError, "release_reservations.after_persist"):
            PublicationTransaction.open(
                transaction.journal_path,
                adapter=crashing_adapter,
                expected_attempt_ref=transaction.attempt_ref,
            )

        recovered = PublicationTransaction.open(
            transaction.journal_path,
            adapter=self.publication_adapter(),
            expected_attempt_ref=transaction.attempt_ref,
        )
        self.assertEqual("aborted", recovered.status()["phase"])
        self.assertEqual(
            recovered.status(),
            PublicationTransaction.open(
                transaction.journal_path,
                adapter=self.publication_adapter(),
                expected_attempt_ref=transaction.attempt_ref,
            ).status(),
        )
        provider_attempt = self.adapter.inspect_attempt(transaction.attempt_ref)
        self.assertIsNotNone(provider_attempt)
        assert provider_attempt is not None
        self.assertEqual(0, provider_attempt["capacity_bytes"])
        self.assertFalse(provider_attempt["capacity_held"])
        self.assertFalse(provider_attempt["cleanup_claim"]["provider_attempt_reserved"])
        self.assertIsNone(provider_attempt["cleanup_claim"]["staging_tip"])
        ledger = safe_io.read_bounded_json(
            self.provider_state / "capacity.json",
            max_bytes=1024 * 1024,
            require_owner_only=True,
        )
        self.assertNotIn(transaction.attempt_ref, ledger["reservations"])

        completed = coordinator.mark_finalized(
            "aborted",
            attempt_ref=claim["attempt_ref"],
            claim_revision=claim["checkpoint_revision"],
            plan_digest=claim["plan_digest"],
        )
        self.assertEqual("aborted", completed["publication"]["phase"])
        self.assertNotIn("publication_claim", completed["publication"])


if __name__ == "__main__":
    unittest.main()
