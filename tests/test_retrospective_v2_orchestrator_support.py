from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "codex-session-retrospective" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from retrospective_v2 import orchestrator_support  # noqa: E402


class PublisherCanaryProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary_directory.name)
        self.gnupg_home = self.root / "gnupg"
        self.gnupg_home.mkdir(mode=0o700)
        self.gpg_program = self.root / "fake-gpg"
        self.gpg_program.write_text(
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import os
                from pathlib import Path
                import sys
                import time

                arguments = sys.argv[1:]
                phase = "sign" if "--detach-sign" in arguments else "verify"
                mode = os.environ.get("FAKE_GPG_MODE", "success")
                limit = int(os.environ["FAKE_GPG_STREAM_LIMIT"])
                if mode == f"{{phase}}_stdout":
                    stream = sys.stdout.buffer
                elif mode == f"{{phase}}_stderr":
                    stream = sys.stderr.buffer
                else:
                    stream = None
                if stream is not None:
                    stream.write(b"x" * (limit + 1))
                    stream.flush()
                    time.sleep(2)
                    Path(os.environ["FAKE_GPG_SENTINEL"]).write_text(
                        "completed", encoding="utf-8"
                    )
                    raise SystemExit(0)
                if phase == "sign":
                    output = Path(arguments[arguments.index("--output") + 1])
                    output.write_bytes(b"signature")
                    raise SystemExit(0)
                fingerprint = os.environ["FAKE_GPG_FINGERPRINT"]
                print(f"[GNUPG:] VALIDSIG {{fingerprint}} 0")
                """
            ),
            encoding="utf-8",
        )
        self.gpg_program.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def environment(self, *, mode: str, sentinel: Path) -> dict[str, str]:
        return {
            "FAKE_GPG_FINGERPRINT": orchestrator_support.PUBLISHER_FINGERPRINT,
            "FAKE_GPG_MODE": mode,
            "FAKE_GPG_SENTINEL": str(sentinel),
            "FAKE_GPG_STREAM_LIMIT": str(
                orchestrator_support._PUBLISHER_CANARY_STREAM_LIMIT_BYTES
            ),
        }

    def test_bounded_canary_accepts_valid_sign_and_verify_output(self) -> None:
        sentinel = self.root / "unused-sentinel"
        with mock.patch.dict(
            os.environ,
            self.environment(mode="success", sentinel=sentinel),
        ):
            self.assertTrue(
                orchestrator_support.publisher_sign_verify_canary(
                    gnupg_home=self.gnupg_home,
                    gpg_program=self.gpg_program,
                )
            )
        self.assertFalse(sentinel.exists())

    def test_canary_rejects_gpg_content_change_after_sign(self) -> None:
        def mutate_after_sign(command, *, environment):
            del environment
            signature = Path(command[command.index("--output") + 1])
            signature.write_bytes(b"signature")
            self.gpg_program.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
            self.gpg_program.chmod(0o700)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(
            orchestrator_support,
            "_run_bounded_publisher_canary_process",
            side_effect=mutate_after_sign,
        ):
            self.assertFalse(
                orchestrator_support.publisher_sign_verify_canary(
                    gnupg_home=self.gnupg_home,
                    gpg_program=self.gpg_program,
                )
            )

    def test_bounded_canary_terminates_oversized_stdout_during_execution(
        self,
    ) -> None:
        self._assert_oversized_stream_is_terminated("stdout")

    def test_bounded_canary_terminates_oversized_stderr_during_execution(
        self,
    ) -> None:
        self._assert_oversized_stream_is_terminated("stderr")

    def _assert_oversized_stream_is_terminated(self, stream: str) -> None:
        for phase in ("sign", "verify"):
            with self.subTest(phase=phase, stream=stream):
                sentinel = self.root / f"{phase}-{stream}-completed"
                with mock.patch.dict(
                    os.environ,
                    self.environment(
                        mode=f"{phase}_{stream}",
                        sentinel=sentinel,
                    ),
                ):
                    self.assertFalse(
                        orchestrator_support.publisher_sign_verify_canary(
                            gnupg_home=self.gnupg_home,
                            gpg_program=self.gpg_program,
                        )
                    )
                self.assertFalse(
                    sentinel.exists(),
                    "the process reached post-output work before being terminated",
                )


if __name__ == "__main__":
    unittest.main()
