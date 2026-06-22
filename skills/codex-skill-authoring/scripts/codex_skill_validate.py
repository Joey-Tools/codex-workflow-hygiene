#!/usr/bin/env python3
"""Run the installed OpenAI skill validator over one or more skills."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


EXIT_VALIDATION_FAILED = 1
EXIT_RUNTIME_ERROR = 2
MAX_SUMMARY_MESSAGE_LENGTH = 240
VALIDATOR_RELATIVE_PATH = Path(".system/skill-creator/scripts/quick_validate.py")
DEFAULT_VALIDATOR = Path("~/.codex/skills") / VALIDATOR_RELATIVE_PATH


def default_validator_candidates() -> list[Path]:
    candidates: list[Path] = []
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        base = Path(codex_home).expanduser()
        candidates.extend([base / "skills" / VALIDATOR_RELATIVE_PATH, base / VALIDATOR_RELATIVE_PATH])
    candidates.append(DEFAULT_VALIDATOR.expanduser())

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            deduped.append(candidate)
            seen.add(key)
    return deduped


def default_validator_path() -> Path:
    raw = os.environ.get("CODEX_SKILL_VALIDATOR")
    if raw:
        return Path(raw).expanduser()
    candidates = default_validator_candidates()
    return next((candidate for candidate in candidates if candidate.exists()), candidates[0])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate one or more Codex skills via the installed OpenAI validator."
    )
    parser.add_argument(
        "skill_directories",
        metavar="skill_directory",
        nargs="+",
        help="Path to a skill directory containing SKILL.md.",
    )
    parser.add_argument(
        "--report",
        metavar="path",
        help="Write the complete wrapper result as JSON.",
    )
    parser.add_argument(
        "--validator",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-uv",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def validator_command(validator: Path, skill_path: Path, *, use_uv: bool) -> list[str]:
    if use_uv:
        return [
            "uv",
            "run",
            "--isolated",
            "--with",
            "pyyaml",
            "python3",
            str(validator),
            str(skill_path),
        ]
    return [sys.executable, str(validator), str(skill_path)]


def default_uv_cache_dir() -> Path:
    candidate = Path.cwd() / ".codex-tmp" / "skill-validator-wrapper" / "uv-cache"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "codex-skill-validator-wrapper-uv-cache"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def validator_environment(*, use_uv: bool) -> dict[str, str] | None:
    if not use_uv or "UV_CACHE_DIR" in os.environ:
        return None
    env = os.environ.copy()
    env["UV_CACHE_DIR"] = str(default_uv_cache_dir())
    return env


def run_validator(validator: Path, skill_path: Path, *, use_uv: bool) -> dict[str, object]:
    result = subprocess.run(
        validator_command(validator, skill_path, use_uv=use_uv),
        check=False,
        env=validator_environment(use_uv=use_uv),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    message = result.stdout.strip() or result.stderr.strip() or f"validator exited {result.returncode}"
    runtime_error = validator_runtime_error(result.returncode, result.stdout, result.stderr)
    return {
        "path": str(skill_path),
        "resolved_path": str(skill_path.resolve(strict=False)),
        "valid": result.returncode == 0 and not runtime_error,
        "returncode": result.returncode,
        "runtime_error": runtime_error,
        "message": message,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def validator_runtime_error(returncode: int, stdout: str, stderr: str) -> bool:
    if returncode not in (0, 1):
        return True
    return returncode == 1 and "Traceback (most recent call last):" in f"{stdout}\n{stderr}"


def summarize(results: list[dict[str, object]]) -> dict[str, int]:
    total = len(results)
    passed = sum(1 for result in results if result["valid"])
    runtime_errors = sum(1 for result in results if result["runtime_error"])
    failed = total - passed - runtime_errors
    return {"total": total, "passed": passed, "failed": failed, "runtime_errors": runtime_errors}


def compact_message(result: dict[str, object]) -> str:
    raw = str(result["message"])
    message = next((line.strip() for line in raw.splitlines() if line.strip()), "")
    message = message.replace("\t", " ")
    if len(message) > MAX_SUMMARY_MESSAGE_LENGTH:
        return message[: MAX_SUMMARY_MESSAGE_LENGTH - 3] + "..."
    return message or f"validator exited {result['returncode']}"


def print_summary(results: list[dict[str, object]]) -> None:
    if len(results) == 1:
        print(results[0]["message"])
        return
    for result in results:
        status = "ERROR" if result["runtime_error"] else "PASS" if result["valid"] else "FAIL"
        print(f"{status}\t{result['path']}\t{compact_message(result)}")
    summary = summarize(results)
    details = f"{summary['passed']}/{summary['total']} skills valid; {summary['failed']} failed"
    if summary["runtime_errors"]:
        details += f"; {summary['runtime_errors']} runtime errors"
    print(f"Summary: {details}.")


def write_report(report_path: str, results: list[dict[str, object]]) -> None:
    path = Path(report_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"summary": summarize(results), "results": results}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    validator = Path(args.validator).expanduser() if args.validator else default_validator_path()
    if not validator.exists():
        print(f"Installed skill validator not found: {validator}", file=sys.stderr)
        if not args.validator:
            print(
                "Checked: " + ", ".join(str(candidate) for candidate in default_validator_candidates()),
                file=sys.stderr,
            )
        return EXIT_RUNTIME_ERROR

    use_uv = not args.no_uv and shutil.which("uv") is not None
    results = [
        run_validator(validator, Path(skill_path).expanduser(), use_uv=use_uv)
        for skill_path in args.skill_directories
    ]
    print_summary(results)

    if args.report:
        try:
            write_report(args.report, results)
        except OSError as error:
            print(f"Failed to write report: {error}", file=sys.stderr)
            return EXIT_RUNTIME_ERROR

    summary = summarize(results)
    if summary["runtime_errors"]:
        return EXIT_RUNTIME_ERROR
    return EXIT_VALIDATION_FAILED if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
