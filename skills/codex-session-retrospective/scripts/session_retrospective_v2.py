#!/usr/bin/env python3
"""Machine-only CLI for the Session Retrospective v2 engine."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
import datetime as dt
from enum import IntEnum
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, NoReturn, Optional


if sys.version_info < (3, 13):
    sys.stdout.write(
        json.dumps(
            {
                "command": "startup",
                "error": {
                    "code": "unsupported_python_runtime",
                    "message": "Session Retrospective v2 requires Python 3.13 or newer",
                    "reason_code": "readiness_failed",
                    "recovery_action": "satisfy_readiness_gate",
                    "retryable": False,
                },
                "exit_code": 9,
                "ok": False,
                "result": None,
                "schema": "cli_result_v2",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    raise SystemExit(9)


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from retrospective_v2 import checkpoints as checkpoint_api  # noqa: E402
from retrospective_v2 import authority as authority_api  # noqa: E402
from retrospective_v2 import catalog as catalog_api  # noqa: E402
from retrospective_v2 import contracts as contract_api  # noqa: E402
from retrospective_v2 import export as export_api  # noqa: E402
from retrospective_v2 import finalize as finalize_api  # noqa: E402
from retrospective_v2 import identity as identity_api  # noqa: E402
from retrospective_v2 import orchestrator as orchestrator_api  # noqa: E402
from retrospective_v2 import reporting as reporting_api  # noqa: E402
from retrospective_v2 import result_validation as result_validation_api  # noqa: E402
from retrospective_v2 import safe_io  # noqa: E402
import session_retrospective_v2_transcript as transcript_api  # noqa: E402


CLI_SCHEMA = "cli_result_v2"
EXPORT_DESCRIPTOR_SCHEMA = "cli_export_descriptor_v2"
EXPORT_DESCRIPTOR_NAME = "cli-export-v2.json"
PUBLICATION_JOURNAL_NAME = "publication-transaction-v2.json"
MAX_AGENT_RESULT_BYTES = result_validation_api.MAX_RESULT_BYTES
MAX_AGENT_RESULT_JSON_DEPTH = result_validation_api.MAX_RESULT_DEPTH
MAX_DESCRIPTOR_BYTES = 64 * 1024
MAX_DIAGNOSTIC_BYTES = 256
MAX_SESSION_SHARDS_STREAM_BYTES = 384 * 1024 * 1024
MAX_SESSION_SHARDS_STREAM_FRAMES = 1_000_000
MAX_SOURCE_TRANSPORT_STREAM_BYTES = 640 * 1024 * 1024
BASELINE_WINDOW_DAYS = 90
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

_REASON_CODE_ALLOWLIST = frozenset(
    """
    append_only_violation automation_cutover_blocked checkpoint_conflict
    checkpoint_integrity_failed checkpoint_not_found checkpoint_permission_failed
    conflict duplicate_session_shards_binding empty_session_shards_materialization
    export_conflict export_descriptor_conflict export_location_invalid file_not_found
    identity_invalid identity_missing internal_error invalid_controlled_holdout
    invalid_export_descriptor invalid_export_receipt invalid_input invalid_json
    invalid_json_shape invalid_partial_policy invalid_path invalid_publication_identity
    invalid_publication_state invalid_retained_payload invalid_session_shards_binding
    invalid_session_shards_descriptors invalid_session_shards_records
    invalid_session_target invalid_shadow_successor invalid_state invalid_window io_error
    not_found os_io_failed production_identity_path_fixed
    production_readiness_binding_required provider_cache_conflict
    publication_attempt_mismatch publication_authority_invalid
    publication_authority_missing publication_failed publication_not_resumable
    publication_rejected publication_transition_invalid raw_path_outside_run_cache
    read_limit_exceeded readiness_failed retained_export_io_failed
    retained_inventory_invalid retained_payload_unavailable retained_privacy_failed
    run_input_invalid run_not_exportable run_not_started run_state_conflict
    run_transition_invalid security_error session_shards_coverage_mismatch
    session_shards_transcript_changed shadow_identity_required
    shadow_publication_forbidden shadow_successor_mismatch state_corruption_detected
    target_head_conflict transport_bounds_exceeded typed_result_unavailable
    unexpected_internal_failure unsafe_path usage_error
    """.split()
)
_RECOVERY_ACTION_ALLOWLIST = frozenset(
    "correct_request escalate_internal_failure initialize_or_restore_state "
    "inspect_status refresh_state_and_retry repair_trust_boundary retry_bounded_io "
    "satisfy_readiness_gate".split()
)


class ExitCode(IntEnum):
    OK = 0
    USAGE = 2
    INVALID_INPUT = 3
    NOT_FOUND = 4
    CONFLICT = 5
    INVALID_STATE = 6
    SECURITY = 7
    IO = 8
    UNAVAILABLE = 9
    INTERNAL = 70


@dataclass(frozen=True, slots=True)
class CliError:
    code: str
    message: str
    reason_code: str
    recovery_action: str
    retryable: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "reason_code": self.reason_code,
            "recovery_action": self.recovery_action,
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    exit_code: ExitCode
    result: Optional[Mapping[str, Any]] = None
    error: Optional[CliError] = None

    @property
    def ok(self) -> bool:
        return self.exit_code is ExitCode.OK and self.error is None

    def to_json(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "error": None if self.error is None else self.error.to_json(),
            "exit_code": int(self.exit_code),
            "ok": self.ok,
            "result": None if self.result is None else dict(self.result),
            "schema": CLI_SCHEMA,
        }

    @classmethod
    def success(cls, command: str, result: Mapping[str, Any]) -> CommandResult:
        return cls(command=command, exit_code=ExitCode.OK, result=result)

    @classmethod
    def failure(
        cls,
        command: str,
        *,
        exit_code: ExitCode,
        code: str,
        message: str,
        reason_code: Optional[str] = None,
        recovery_action: Optional[str] = None,
        retryable: bool = False,
        result: Optional[Mapping[str, Any]] = None,
    ) -> CommandResult:
        normalized_reason = code if reason_code is None else reason_code
        if normalized_reason not in _REASON_CODE_ALLOWLIST:
            normalized_reason = "unexpected_internal_failure"
        default_recovery = {
            ExitCode.USAGE: "correct_request",
            ExitCode.INVALID_INPUT: "correct_request",
            ExitCode.NOT_FOUND: "initialize_or_restore_state",
            ExitCode.CONFLICT: "refresh_state_and_retry",
            ExitCode.INVALID_STATE: "inspect_status",
            ExitCode.SECURITY: "repair_trust_boundary",
            ExitCode.IO: "retry_bounded_io",
            ExitCode.UNAVAILABLE: "satisfy_readiness_gate",
            ExitCode.INTERNAL: "escalate_internal_failure",
        }[exit_code]
        normalized_recovery = recovery_action or default_recovery
        if normalized_recovery not in _RECOVERY_ACTION_ALLOWLIST:
            normalized_recovery = "escalate_internal_failure"
        return cls(
            command=command,
            exit_code=exit_code,
            result=result,
            error=CliError(
                code=code,
                message=message,
                reason_code=normalized_reason,
                recovery_action=normalized_recovery,
                retryable=retryable,
            ),
        )


class CliContractError(RuntimeError):
    def __init__(
        self,
        *,
        exit_code: ExitCode,
        code: str,
        message: str,
        retryable: bool = False,
    ) -> None:
        super().__init__(code)
        self.exit_code = exit_code
        self.code = code
        self.safe_message = message
        self.retryable = retryable


class HelpRequested(Exception):
    def __init__(self, command: str, usage: str) -> None:
        super().__init__(command)
        self.command = command
        self.usage = usage


class MachineArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise CliContractError(
            exit_code=ExitCode.USAGE,
            code="usage_error",
            message="command arguments are invalid",
        )


class MachineHelpAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Optional[str],
        option_string: Optional[str] = None,
    ) -> NoReturn:
        del namespace, values, option_string
        command = parser.prog.rsplit(" ", 1)[-1]
        if command == parser.prog:
            command = "help"
        raise HelpRequested(command, parser.format_help())


def _add_help(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-h",
        "--help",
        action=MachineHelpAction,
        nargs=0,
        help="emit machine-readable command help",
    )


def _add_identity_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_shadow: bool = False,
) -> None:
    parser.add_argument("--identity-path")
    parser.add_argument("--require-existing-identity", action="store_true")
    if include_shadow:
        parser.add_argument("--shadow", action="store_true")


def build_parser() -> MachineArgumentParser:
    parser = MachineArgumentParser(
        prog="session_retrospective_v2.py",
        description="Deterministic Session Retrospective v2 coordinator",
        add_help=False,
        allow_abbrev=False,
    )
    _add_help(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", add_help=False, allow_abbrev=False)
    _add_help(doctor_parser)
    _add_identity_arguments(doctor_parser, include_shadow=True)
    doctor_parser.add_argument("--run-config", required=True)
    doctor_parser.add_argument("--history-repo", required=True)
    doctor_parser.add_argument("--history-target-ref", required=True)
    doctor_parser.add_argument("--provider-state")
    doctor_parser.add_argument("--production-marker")

    start_parser = subparsers.add_parser("start", add_help=False, allow_abbrev=False)
    _add_help(start_parser)
    _add_identity_arguments(start_parser, include_shadow=True)
    start_parser.add_argument(
        "--mode",
        required=True,
        choices=tuple(mode.value for mode in contract_api.RunMode),
    )
    start_parser.add_argument("--start", required=True)
    start_parser.add_argument("--end", required=True)
    start_parser.add_argument("--run-dir", required=True)
    start_parser.add_argument("--run-config", required=True)
    start_parser.add_argument("--allow-partial", action="store_true")
    start_parser.add_argument("--backfill-of")
    start_parser.add_argument("--controlled-gap-receipt")
    start_parser.add_argument("--shadow-successor-of")
    start_parser.add_argument("--host", action="append", dest="hosts")
    start_parser.add_argument("--session-target")
    start_parser.add_argument("--session-target-selector")
    start_parser.add_argument("--history-repo", required=True)
    start_parser.add_argument("--history-target-ref", required=True)
    start_parser.add_argument("--provider-state")
    start_parser.add_argument("--production-marker")

    status_parser = subparsers.add_parser("status", add_help=False, allow_abbrev=False)
    _add_help(status_parser)
    _add_identity_arguments(status_parser)
    status_parser.add_argument("--run-dir", required=True)
    status_parser.add_argument("--claim-job-ref")
    status_parser.add_argument("--claim-attempt-ref")
    status_parser.add_argument("--dispatcher-ref")
    status_parser.add_argument("--claim-ref")
    status_parser.add_argument(
        "--claim-ttl-seconds",
        type=int,
        default=orchestrator_api.DEFAULT_AGENT_CLAIM_TTL_SECONDS,
    )

    source_parser = subparsers.add_parser(
        "accept-source", add_help=False, allow_abbrev=False
    )
    _add_help(source_parser)
    _add_identity_arguments(source_parser)
    source_parser.add_argument("--run-dir", required=True)
    source_parser.add_argument("--lease-ref", required=True)
    source_parser.add_argument("--transport-stream-file", required=True)
    source_parser.add_argument(
        "--transport-stream",
        action="append",
        nargs=2,
        metavar=("SOURCE_REF", "JSONL_PATH"),
        default=[],
    )

    agent_parser = subparsers.add_parser(
        "accept-agent-result", add_help=False, allow_abbrev=False
    )
    _add_help(agent_parser)
    _add_identity_arguments(agent_parser)
    agent_parser.add_argument("--run-dir", required=True)
    agent_parser.add_argument("--job-ref", required=True)
    agent_parser.add_argument("--attempt-ref", required=True)
    agent_parser.add_argument("--claim-ref", required=True)
    agent_parser.add_argument("--result-ref", required=True)
    agent_parser.add_argument("--result", required=True)

    advance_parser = subparsers.add_parser(
        "advance", add_help=False, allow_abbrev=False
    )
    _add_help(advance_parser)
    _add_identity_arguments(advance_parser)
    advance_parser.add_argument("--run-dir", required=True)
    advance_parser.add_argument("--holdout-host")
    advance_parser.add_argument(
        "--holdout-reason",
        choices=tuple(reason.value for reason in contract_api.ControlledGapReason),
    )

    export_parser = subparsers.add_parser("export", add_help=False, allow_abbrev=False)
    _add_help(export_parser)
    _add_identity_arguments(export_parser)
    export_parser.add_argument("--run-dir", required=True)
    export_parser.add_argument("--output", required=True)
    prior_group = export_parser.add_mutually_exclusive_group()
    prior_group.add_argument("--prior-period")
    prior_group.add_argument("--prior-history", action="store_true")
    export_parser.add_argument("--retention-deadline")

    finalize_parser = subparsers.add_parser(
        "finalize", add_help=False, allow_abbrev=False
    )
    _add_help(finalize_parser)
    _add_identity_arguments(finalize_parser)
    finalize_parser.add_argument("--run-dir", required=True)

    return parser


def _absolute_path(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_path",
            message="a local path argument is invalid",
        )
    try:
        return Path(os.path.abspath(os.path.expanduser(value)))
    except (OSError, ValueError) as error:
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_path",
            message="a local path argument is invalid",
        ) from error


def _command_identity_path(
    args: argparse.Namespace,
    *,
    startup: bool = False,
) -> Optional[Path]:
    value = getattr(args, "identity_path", None)
    path = None if value is None else _absolute_path(value)
    shadow = bool(getattr(args, "shadow", False))
    default_path = identity_api.identity_key_path().absolute()
    if startup and shadow:
        if path is None or not getattr(args, "require_existing_identity", False):
            raise CliContractError(
                exit_code=ExitCode.SECURITY,
                code="shadow_identity_required",
                message=(
                    "shadow doctor/start requires an explicit existing owner-only identity"
                ),
            )
    elif startup and path is not None and path != default_path:
        raise CliContractError(
            exit_code=ExitCode.SECURITY,
            code="production_identity_path_fixed",
            message="production doctor/start uses the fixed identity path",
        )
    if getattr(args, "require_existing_identity", False):
        try:
            identity_api.IdentityKey.load(default_path if path is None else path)
        except FileNotFoundError as error:
            raise CliContractError(
                exit_code=ExitCode.SECURITY,
                code="identity_missing",
                message="the required owner-only identity does not exist",
            ) from error
    return path


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CliContractError(
                exit_code=ExitCode.INVALID_INPUT,
                code="invalid_json",
                message="input JSON is not canonical",
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise CliContractError(
        exit_code=ExitCode.INVALID_INPUT,
        code="invalid_json",
        message="input JSON is not canonical",
    )


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _reject_json_constant(value)
    return parsed


def _parse_bounded_json_int(value: str) -> int:
    if len(value) > 20:
        _reject_json_constant(value)
    try:
        parsed = int(value)
    except ValueError:
        _reject_json_constant(value)
    if abs(parsed) > contract_api.MAX_JSON_INTEGER:
        _reject_json_constant(value)
    return parsed


def _read_json_object(path: str | Path, *, max_bytes: int) -> dict[str, Any]:
    data = safe_io.read_bounded_bytes(
        _absolute_path(str(path)),
        max_bytes=max_bytes,
        require_owner_only=True,
    )
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_json_float,
            parse_int=_parse_bounded_json_int,
        )
    except CliContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_json",
            message="input JSON is not canonical",
        ) from error
    if not isinstance(value, dict):
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_json_shape",
            message="input JSON must be an object",
        )
    return value


class _BoundAgentResultDecodeError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _validate_bound_agent_result_nesting(data: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > MAX_AGENT_RESULT_JSON_DEPTH:
                raise _BoundAgentResultDecodeError("malformed_json")
        elif byte in {0x5D, 0x7D}:
            depth -= 1


def _decode_bound_agent_result(data: bytes) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _BoundAgentResultDecodeError("duplicate_keys")
            result[key] = value
        return result

    def reject_json_constant(_value: str) -> NoReturn:
        raise _BoundAgentResultDecodeError("malformed_json")

    def parse_finite_json_float(raw: str) -> float:
        parsed = float(raw)
        if not math.isfinite(parsed):
            reject_json_constant(raw)
        return parsed

    def parse_bounded_json_int(raw: str) -> int:
        if len(raw) > 20:
            raise _BoundAgentResultDecodeError("malformed_json")
        try:
            parsed = int(raw)
        except ValueError as error:
            raise _BoundAgentResultDecodeError("malformed_json") from error
        if abs(parsed) > contract_api.MAX_JSON_INTEGER:
            raise _BoundAgentResultDecodeError("malformed_json")
        return parsed

    _validate_bound_agent_result_nesting(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _BoundAgentResultDecodeError("malformed_utf8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
            parse_float=parse_finite_json_float,
            parse_int=parse_bounded_json_int,
        )
    except _BoundAgentResultDecodeError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise _BoundAgentResultDecodeError("malformed_json") from error
    if not isinstance(value, dict):
        raise _BoundAgentResultDecodeError("invalid_root_type")
    return value


def _mapping_result(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        result = dict(value)
    elif is_dataclass(value) and not isinstance(value, type):
        result = asdict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise CliContractError(
                exit_code=ExitCode.UNAVAILABLE,
                code="typed_result_unavailable",
                message="the v2 engine did not return a typed command result",
            )
        converted = to_dict()
        if not isinstance(converted, Mapping):
            raise CliContractError(
                exit_code=ExitCode.UNAVAILABLE,
                code="typed_result_unavailable",
                message="the v2 engine did not return a typed command result",
            )
        result = dict(converted)
    contract_api.canonical_json(result)
    return result


def _parse_timestamp(value: str) -> dt.datetime:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as error:
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_window",
            message="the run window is invalid",
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_window",
            message="the run window is invalid",
        )
    return parsed.astimezone(dt.timezone.utc)


def command_doctor(args: argparse.Namespace) -> CommandResult:
    identity_path = _command_identity_path(args, startup=True)
    if not args.shadow and (
        args.provider_state is None or args.production_marker is None
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="production_readiness_binding_required",
            message=(
                "production doctor requires provider state and production marker bindings"
            ),
        )
    provenance = _read_json_object(
        args.run_config,
        max_bytes=MAX_DESCRIPTOR_BYTES,
    )
    report = _mapping_result(
        orchestrator_api.doctor(
            identity_path=identity_path,
            require_existing_identity=True,
            shadow=args.shadow,
            provenance=provenance,
            history_repo=_absolute_path(args.history_repo),
            history_target_ref=args.history_target_ref,
            provider_state=(
                None
                if args.provider_state is None
                else _absolute_path(args.provider_state)
            ),
            production_marker=(
                None
                if args.production_marker is None
                else _absolute_path(args.production_marker)
            ),
        )
    )
    if report.get("ok") is not True:
        return CommandResult.failure(
            "doctor",
            exit_code=ExitCode.UNAVAILABLE,
            code="readiness_failed",
            message="v2 readiness checks failed",
            result=report,
        )
    return CommandResult.success("doctor", report)


def command_start(args: argparse.Namespace) -> CommandResult:
    identity_path = _command_identity_path(args, startup=True)
    provenance = _read_json_object(
        args.run_config,
        max_bytes=MAX_DESCRIPTOR_BYTES,
    )
    successor = None
    if (
        args.shadow
        and args.shadow_successor_of is None
        and (args.backfill_of is not None or args.controlled_gap_receipt is not None)
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_shadow_successor",
            message=("shadow backfill inputs must come from one completed partial run"),
        )
    if args.shadow_successor_of is not None:
        if (
            not args.shadow
            or args.mode != contract_api.RunMode.DAILY.value
            or args.allow_partial
            or args.backfill_of is not None
            or args.controlled_gap_receipt is not None
            or args.hosts is not None
            or args.provider_state is not None
            or args.production_marker is not None
        ):
            raise CliContractError(
                exit_code=ExitCode.INVALID_INPUT,
                code="invalid_shadow_successor",
                message=(
                    "shadow successor must derive an isolated daily backfill from "
                    "one completed partial run"
                ),
            )
        partial_run_dir = _absolute_path(args.shadow_successor_of)
        if partial_run_dir == _absolute_path(args.run_dir):
            raise CliContractError(
                exit_code=ExitCode.INVALID_INPUT,
                code="invalid_shadow_successor",
                message="shadow successor requires a distinct run directory",
            )
        partial = orchestrator_api.RetrospectiveOrchestrator(
            partial_run_dir,
            identity_path=identity_path,
            require_existing_identity=True,
        )
        successor = partial.shadow_daily_successor()
        normalized_provenance = orchestrator_api._build_provenance(
            provenance=provenance,
            policy=None,
            model=None,
            versions=None,
        )
        if (
            args.start != successor["window"]["start"]
            or args.end != successor["window"]["end"]
            or str(_absolute_path(args.history_repo)) != successor["history_repo"]
            or args.history_target_ref != successor["history_target_ref"]
            or normalized_provenance != successor["provenance"]
        ):
            raise CliContractError(
                exit_code=ExitCode.CONFLICT,
                code="shadow_successor_mismatch",
                message=(
                    "shadow successor inputs differ from the completed partial run"
                ),
            )
    if args.allow_partial and args.mode != "daily":
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_partial_policy",
            message="partial publication is unavailable for this mode",
        )
    window_start = _parse_timestamp(args.start)
    window_end = _parse_timestamp(args.end)
    window_duration = window_end - window_start
    required_duration = {
        contract_api.RunMode.WEEKLY.value: dt.timedelta(days=7),
        contract_api.RunMode.BASELINE.value: dt.timedelta(days=BASELINE_WINDOW_DAYS),
    }.get(args.mode)
    if window_duration <= dt.timedelta() or (
        required_duration is not None and window_duration != required_duration
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_window",
            message="the run window is invalid",
        )
    session_mode = args.mode == contract_api.RunMode.SESSION.value
    has_session_binding = (
        args.session_target is not None or args.session_target_selector is not None
    )
    if session_mode != has_session_binding or (
        session_mode
        and (args.session_target is None or not args.session_target_selector)
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_session_target",
            message="session target binding is invalid for this run mode",
        )
    if session_mode:
        try:
            target = str(
                contract_api.parse_typed_ref(
                    args.session_target,
                    expected=contract_api.RefType.SESSION,
                )
            )
            identity = identity_api.IdentityKey.load(
                identity_api.identity_key_path()
                if identity_path is None
                else identity_path
            )
            expected_target = str(
                identity.derive_ref(
                    contract_api.RefType.SESSION,
                    {"session_id": args.session_target_selector},
                )
            )
        except (
            FileNotFoundError,
            TypeError,
            ValueError,
            identity_api.IdentityKeyError,
        ) as error:
            raise CliContractError(
                exit_code=ExitCode.INVALID_INPUT,
                code="invalid_session_target",
                message="session target binding is invalid for this run mode",
            ) from error
        if not hmac.compare_digest(target, expected_target):
            raise CliContractError(
                exit_code=ExitCode.INVALID_INPUT,
                code="invalid_session_target",
                message="session target binding is invalid for this run mode",
            )
    controlled_gap_receipt = (
        successor["controlled_gap_receipt"]
        if successor is not None
        else (
            None
            if args.controlled_gap_receipt is None
            else _read_json_object(
                args.controlled_gap_receipt,
                max_bytes=MAX_DESCRIPTOR_BYTES,
            )
        )
    )
    result = orchestrator_api.start_run(
        _absolute_path(args.run_dir),
        identity_path=identity_path,
        require_existing_identity=True,
        mode=args.mode,
        start=args.start,
        end=args.end,
        allow_partial=args.allow_partial,
        backfill_of=(successor["backfill_of"] if successor else args.backfill_of),
        controlled_gap_receipt=controlled_gap_receipt,
        shadow_successor=successor,
        shadow=args.shadow,
        provenance=provenance,
        hosts=((successor["host"],) if successor else args.hosts),
        session_target=args.session_target,
        session_target_selector=args.session_target_selector,
        history_repo=_absolute_path(args.history_repo),
        history_target_ref=args.history_target_ref,
        provider_state=(
            None if args.provider_state is None else _absolute_path(args.provider_state)
        ),
        production_marker=(
            None
            if args.production_marker is None
            else _absolute_path(args.production_marker)
        ),
    )
    response = _mapping_result(result)
    if successor is not None:
        response["shadow_successor_of"] = successor["backfill_of"]
    return CommandResult.success("start", response)


def command_status(args: argparse.Namespace) -> CommandResult:
    result = orchestrator_api.status(
        _absolute_path(args.run_dir),
        claim_job_ref=args.claim_job_ref,
        claim_attempt_ref=args.claim_attempt_ref,
        dispatcher_ref=args.dispatcher_ref,
        claim_ref=args.claim_ref,
        claim_ttl_seconds=args.claim_ttl_seconds,
        identity_path=_command_identity_path(args),
        require_existing_identity=True,
    )
    return CommandResult.success("status", _mapping_result(result))


def _iter_transport_frames(path_value: str) -> Any:
    path = _absolute_path(path_value)
    _normalized_parent, directory_fd = safe_io.open_owner_only_directory(path.parent)
    descriptor: Optional[int] = None
    try:
        descriptor = safe_io.open_checked_file_at(
            directory_fd,
            path.name,
            display_path=path,
            require_owner_only=True,
        )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            total_bytes = 0
            frame_count = 0
            while True:
                raw_line = handle.readline(
                    orchestrator_api.SESSION_SHARDS_MAX_FRAME_CHARS + 2
                )
                if raw_line == b"":
                    break
                total_bytes += len(raw_line)
                frame_count += 1
                if (
                    len(raw_line) > orchestrator_api.SESSION_SHARDS_MAX_FRAME_CHARS + 1
                    or total_bytes > MAX_SESSION_SHARDS_STREAM_BYTES
                    or frame_count > MAX_SESSION_SHARDS_STREAM_FRAMES
                ):
                    raise CliContractError(
                        exit_code=ExitCode.INVALID_INPUT,
                        code="transport_bounds_exceeded",
                        message="session-shards transport exceeded its bounds",
                    )
                line = raw_line.rstrip(b"\r\n")
                if not line:
                    raise CliContractError(
                        exit_code=ExitCode.INVALID_INPUT,
                        code="invalid_json",
                        message="session-shards transport contains invalid JSON",
                    )
                try:
                    frame = safe_io.decode_json_bytes(
                        line,
                        label="session-shards frame",
                    )
                except safe_io.InvalidJsonError as error:
                    raise CliContractError(
                        exit_code=ExitCode.INVALID_INPUT,
                        code="invalid_json",
                        message="session-shards transport contains invalid JSON",
                    ) from error
                if not isinstance(frame, Mapping):
                    raise CliContractError(
                        exit_code=ExitCode.INVALID_INPUT,
                        code="invalid_json_shape",
                        message="session-shards frames must be objects",
                    )
                yield dict(frame)
            safe_io.validate_owner_only_file_descriptor(
                handle.fileno(),
                path,
                directory_fd=directory_fd,
                name=path.name,
            )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _iter_source_transport_lines(path_value: str) -> Any:
    path = _absolute_path(path_value)
    _normalized_parent, directory_fd = safe_io.open_owner_only_directory(path.parent)
    descriptor: Optional[int] = None
    try:
        descriptor = safe_io.open_checked_file_at(
            directory_fd,
            path.name,
            display_path=path,
            require_owner_only=True,
        )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            total_bytes = 0
            while True:
                raw_line = handle.readline(
                    orchestrator_api.SOURCE_TRANSPORT_MAX_FRAME_BYTES + 2
                )
                if raw_line == b"":
                    break
                total_bytes += len(raw_line)
                if (
                    len(raw_line)
                    > orchestrator_api.SOURCE_TRANSPORT_MAX_FRAME_BYTES + 1
                    or total_bytes > MAX_SOURCE_TRANSPORT_STREAM_BYTES
                ):
                    raise CliContractError(
                        exit_code=ExitCode.INVALID_INPUT,
                        code="transport_bounds_exceeded",
                        message="source transport stream exceeded its bounds",
                    )
                yield raw_line
            safe_io.validate_owner_only_file_descriptor(
                handle.fileno(),
                path,
                directory_fd=directory_fd,
                name=path.name,
            )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _closed_named_paths(
    values: Iterable[Iterable[str]],
    *,
    label: str,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_source_ref, raw_path in values:
        try:
            source_ref = str(
                contract_api.parse_typed_ref(
                    raw_source_ref,
                    expected=contract_api.RefType.SESSION,
                )
            )
        except (TypeError, ValueError) as error:
            raise CliContractError(
                exit_code=ExitCode.INVALID_INPUT,
                code="invalid_session_shards_binding",
                message=f"{label} contains an invalid source reference",
            ) from error
        if source_ref in result:
            raise CliContractError(
                exit_code=ExitCode.CONFLICT,
                code="duplicate_session_shards_binding",
                message=f"{label} contains a duplicate source reference",
            )
        result[source_ref] = raw_path
    return result


def _run_raw_input_path(run_dir: Path, value: str) -> Path:
    path = _absolute_path(value)
    raw_root = run_dir / orchestrator_api.RAW_INPUT_DIRECTORY
    try:
        path.relative_to(raw_root)
    except ValueError as error:
        raise CliContractError(
            exit_code=ExitCode.SECURITY,
            code="raw_path_outside_run_cache",
            message="raw source inputs must be inside the run-owned cache",
        ) from error
    return path


def _session_shard_transcript(
    path: Path,
    *,
    expected_host: str,
) -> Iterable[tuple[Iterable[Mapping[str, Any]], contract_api.SessionShardsRequest]]:
    try:
        segments = transcript_api.session_shard_transcript(
            lambda: _iter_transport_frames(str(path)),
            expected_host=expected_host,
        )
    except transcript_api.SessionShardsTranscriptError as error:
        raise _session_shards_transcript_cli_error(error) from error

    def translated_segments() -> Iterable[
        tuple[Iterable[Mapping[str, Any]], contract_api.SessionShardsRequest]
    ]:
        try:
            for frames, request in segments:

                def translated_frames(
                    source: Iterable[Mapping[str, Any]] = frames,
                ) -> Iterable[Mapping[str, Any]]:
                    try:
                        yield from source
                    except transcript_api.SessionShardsTranscriptError as error:
                        close = getattr(segments, "close", None)
                        if callable(close):
                            close()
                        raise _session_shards_transcript_cli_error(error) from error

                yield translated_frames(), request
        except transcript_api.SessionShardsTranscriptError as error:
            raise _session_shards_transcript_cli_error(error) from error
        finally:
            close = getattr(segments, "close", None)
            if callable(close):
                close()

    return translated_segments()


def _session_shards_transcript_cli_error(
    error: transcript_api.SessionShardsTranscriptError,
) -> CliContractError:
    if error.stage == "descriptors":
        return CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_session_shards_descriptors",
            message="session-shards descriptors do not prove a complete source",
        )
    if error.stage == "empty":
        return CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="empty_session_shards_materialization",
            message="session-shards input has no materialized records",
        )
    return CliContractError(
        exit_code=ExitCode.INVALID_INPUT,
        code="invalid_session_shards_records",
        message="session-shards records violate their transport binding",
    )


def command_accept_source(args: argparse.Namespace) -> CommandResult:
    run_dir = _absolute_path(args.run_dir)
    transport_path = _run_raw_input_path(run_dir, args.transport_stream_file)
    preparation = orchestrator_api.prepare_source(
        run_dir,
        args.lease_ref,
        _iter_source_transport_lines(str(transport_path)),
        identity_path=_command_identity_path(args),
        require_existing_identity=True,
    )
    named_streams = _closed_named_paths(
        args.transport_stream,
        label="session-shards transcripts",
    )
    segments: Optional[
        dict[
            str,
            Iterable[
                tuple[Iterable[Mapping[str, Any]], contract_api.SessionShardsRequest]
            ],
        ]
    ] = None
    raw_records: Optional[Mapping[str, bytes]] = preparation.raw_records
    if named_streams:
        manifest = catalog_api.SourceTransportManifest.from_dict(preparation.manifest)
        expected_refs = {
            record.coordinate.source_ref
            for record in manifest.records
            if record.accounting_class is catalog_api.AccountingClass.CONSUMED_CANDIDATE
        }
        if set(named_streams) != expected_refs:
            raise CliContractError(
                exit_code=ExitCode.INVALID_INPUT,
                code="session_shards_coverage_mismatch",
                message=(
                    "session-shards transcripts must cover exactly consumed sources"
                ),
            )
        segments = {}
        for source_ref in sorted(named_streams):
            segments[source_ref] = _session_shard_transcript(
                _run_raw_input_path(run_dir, named_streams[source_ref]),
                expected_host=preparation.host,
            )
        raw_records = None
    result = orchestrator_api.accept_source(
        run_dir,
        args.lease_ref,
        preparation.manifest,
        transport_receipt=preparation.receipt,
        raw_records=raw_records,
        transport_segments=segments,
        identity_path=_command_identity_path(args),
        require_existing_identity=True,
    )
    return CommandResult.success("accept-source", _mapping_result(result))


def command_accept_agent_result(args: argparse.Namespace) -> CommandResult:
    result_path = _absolute_path(args.result)
    sink = orchestrator_api.resolve_agent_result_sink(
        _absolute_path(args.run_dir),
        args.job_ref,
        args.attempt_ref,
        claim_ref=args.claim_ref,
        result_ref=args.result_ref,
        requested_path=result_path,
        identity_path=_command_identity_path(args),
        require_existing_identity=True,
    )
    result_path = _absolute_path(sink["output_sink"])
    try:
        payload = safe_io.read_bounded_bytes(
            result_path,
            max_bytes=MAX_AGENT_RESULT_BYTES,
            require_owner_only=True,
        )
    except safe_io.ReadLimitExceeded:
        result = orchestrator_api.reject_agent_result_payload(
            _absolute_path(args.run_dir),
            args.job_ref,
            args.attempt_ref,
            claim_ref=args.claim_ref,
            result_ref=args.result_ref,
            payload_digest=safe_io.fingerprint_file_bounded(
                result_path,
                require_owner_only=True,
            ),
            reason="result_too_large",
            identity_path=_command_identity_path(args),
            require_existing_identity=True,
        )
        return CommandResult.success("accept-agent-result", _mapping_result(result))
    try:
        result_manifest = _decode_bound_agent_result(payload)
    except _BoundAgentResultDecodeError as error:
        result = orchestrator_api.reject_agent_result_payload(
            _absolute_path(args.run_dir),
            args.job_ref,
            args.attempt_ref,
            claim_ref=args.claim_ref,
            result_ref=args.result_ref,
            payload_digest=hashlib.sha256(payload).hexdigest(),
            reason=error.reason,
            identity_path=_command_identity_path(args),
            require_existing_identity=True,
        )
        return CommandResult.success("accept-agent-result", _mapping_result(result))
    result = orchestrator_api.accept_agent_result(
        _absolute_path(args.run_dir),
        args.job_ref,
        args.attempt_ref,
        result_manifest,
        claim_ref=args.claim_ref,
        result_ref=args.result_ref,
        identity_path=_command_identity_path(args),
        require_existing_identity=True,
    )
    return CommandResult.success("accept-agent-result", _mapping_result(result))


def command_advance(args: argparse.Namespace) -> CommandResult:
    if (args.holdout_host is None) != (args.holdout_reason is None):
        raise CliContractError(
            exit_code=ExitCode.INVALID_INPUT,
            code="invalid_controlled_holdout",
            message="controlled holdout requires both host and reason",
        )
    if args.holdout_host is None:
        result = orchestrator_api.advance(
            _absolute_path(args.run_dir),
            identity_path=_command_identity_path(args),
            require_existing_identity=True,
        )
    else:
        result = orchestrator_api.holdout_host(
            _absolute_path(args.run_dir),
            args.holdout_host,
            reason=args.holdout_reason,
            identity_path=_command_identity_path(args),
            require_existing_identity=True,
        )
    return CommandResult.success("advance", _mapping_result(result))


def _retained_inputs(
    orchestrator: orchestrator_api.RetrospectiveOrchestrator,
    state: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if state.get("stage") != contract_api.RunStage.EXPORT.value:
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="run_not_exportable",
            message="the v2 run has not reached export",
        )
    try:
        return orchestrator.retained_export_inputs(state)
    except orchestrator_api.OrchestratorError as error:
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_retained_payload",
            message="the retained export payload is unavailable or invalid",
        ) from error


def _load_prior_period(path_value: Optional[str]) -> Optional[dict[str, Any]]:
    if path_value is None:
        return None
    path = _absolute_path(path_value)
    normalized, directory_fd = safe_io.open_owner_only_directory(path)
    try:
        names = os.listdir(directory_fd)
        expected = set(reporting_api.RETAINED_ARTIFACT_NAMES)
        if len(names) != len(expected) or set(names) != expected:
            raise reporting_api.RetainedInventoryError(
                "prior period must contain one exact retained bundle"
            )
        artifacts = {
            name: safe_io.read_bounded_bytes_at(
                directory_fd,
                name,
                display_path=normalized / name,
                max_bytes=reporting_api.MAX_RETAINED_ARTIFACT_BYTES,
                require_owner_only=True,
            )
            for name in reporting_api.RETAINED_ARTIFACT_NAMES
        }
    finally:
        os.close(directory_fd)
    parsed = reporting_api.validate_retained_artifacts(artifacts)
    return {
        "authenticated_history": None,
        "retained_bundle_digest": parsed["manifest"]["retained_bundle_digest_v2"][
            "value"
        ],
        "trend_report": parsed["trend_report"],
    }


def _persist_export_descriptor(
    run_dir: Path,
    output: Path,
    receipt: Mapping[str, Any],
    *,
    publication_role: str,
) -> None:
    bundle_digest = receipt.get("bundle_digest")
    retention_deadline = receipt.get("retention_deadline")
    if not isinstance(bundle_digest, str) or not SHA256_RE.fullmatch(bundle_digest):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_export_receipt",
            message="the retained export receipt is invalid",
        )
    if not isinstance(retention_deadline, str):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_export_receipt",
            message="the retained export receipt is invalid",
        )
    descriptor = {
        "bundle_digest": bundle_digest,
        "output": str(output),
        "publication_role": publication_role,
        "retention_deadline": retention_deadline,
        "schema": EXPORT_DESCRIPTOR_SCHEMA,
    }
    descriptor_path = run_dir / EXPORT_DESCRIPTOR_NAME
    try:
        safe_io.atomic_create_json(descriptor_path, descriptor)
    except FileExistsError:
        existing = _read_json_object(
            descriptor_path,
            max_bytes=MAX_DESCRIPTOR_BYTES,
        )
        if contract_api.canonical_json(existing) != contract_api.canonical_json(
            descriptor
        ):
            raise CliContractError(
                exit_code=ExitCode.CONFLICT,
                code="export_descriptor_conflict",
                message="the immutable export destination conflicts with this request",
            )


def command_export(args: argparse.Namespace) -> CommandResult:
    run_dir = _absolute_path(args.run_dir)
    output = _absolute_path(args.output)
    orchestrator = orchestrator_api.RetrospectiveOrchestrator(
        run_dir,
        identity_path=_command_identity_path(args),
        require_existing_identity=True,
    )
    orchestrator.ensure_retention_active()
    state = orchestrator.load_state()
    run_state, review_data = _retained_inputs(orchestrator, state)
    if args.prior_history:
        run_authority = state["authority"]
        prior_period = authority_api.load_prior_period_from_history(
            run_authority["history_repo"],
            run_authority["history_target_ref"],
            identity=orchestrator.identity,
            expected_fingerprint=run_authority["publisher_fingerprint"],
            gnupg_home=run_authority["publisher_gnupg_home"],
        )
    else:
        prior_period = _load_prior_period(args.prior_period)
    run_state["durable_state"] = orchestrator.publication_durable_state()
    run_state["publication_role"] = "standalone"
    retention_deadline = args.retention_deadline
    if retention_deadline is not None:
        retention_deadline = orchestrator.validate_export_retention_deadline(
            retention_deadline
        )
    elif not output.exists() and not output.is_symlink():
        retention_deadline = orchestrator.validate_export_retention_deadline(
            orchestrator.export_retention_deadline()
        )
    now = dt.datetime.now(dt.timezone.utc)
    receipt = _mapping_result(
        export_api.export_retained_bundle(
            output,
            run_state,
            review_data,
            prior_period=prior_period,
            retention_deadline=retention_deadline,
            now=now,
        )
    )
    bundle_digest = receipt.get("bundle_digest")
    if not isinstance(bundle_digest, str) or SHA256_RE.fullmatch(bundle_digest) is None:
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_export_receipt",
            message="the retained export receipt is invalid",
        )
    receipt_deadline = receipt.get("retention_deadline")
    if not isinstance(receipt_deadline, str):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_export_receipt",
            message="the retained export receipt is invalid",
        )
    receipt_deadline = orchestrator.validate_export_retention_deadline(receipt_deadline)
    _persist_export_descriptor(
        run_dir,
        output,
        receipt,
        publication_role="standalone",
    )
    cleanup = None
    if state.get("shadow") is True:
        marked = orchestrator.mark_shadow_exported(
            output,
            prior_period=prior_period,
        )
        cleanup = orchestrator.complete_shadow_export()
    else:
        marked = orchestrator.mark_exported(
            bundle_digest,
            receipt_deadline,
        )
    result = {
        "action": "export",
        "artifact_names": receipt.get("artifact_names"),
        "bundle_digest": bundle_digest,
        "git_commit_created": receipt.get("git_commit_created", False),
        "idempotent": receipt.get("idempotent", False),
        "publication_role": "standalone",
        "publishable": state.get("shadow") is False,
        "retention_deadline": receipt.get("retention_deadline"),
        "schema_version": receipt.get("schema_version", 2),
        "state_advanced": receipt.get("state_advanced", False),
        "stage": (cleanup or marked).get("stage"),
        "cleanup_pending": (
            None if cleanup is None else cleanup.get("cleanup_pending", False)
        ),
    }
    return CommandResult.success("export", result)


def _load_export_descriptor(run_dir: Path) -> dict[str, Any]:
    descriptor = _read_json_object(
        run_dir / EXPORT_DESCRIPTOR_NAME,
        max_bytes=MAX_DESCRIPTOR_BYTES,
    )
    if (
        set(descriptor)
        != {
            "bundle_digest",
            "output",
            "publication_role",
            "retention_deadline",
            "schema",
        }
        or descriptor.get("schema") != EXPORT_DESCRIPTOR_SCHEMA
        or not isinstance(descriptor.get("output"), str)
        or not isinstance(descriptor.get("bundle_digest"), str)
        or not SHA256_RE.fullmatch(descriptor["bundle_digest"])
        or descriptor.get("publication_role") != "standalone"
        or not isinstance(descriptor.get("retention_deadline"), str)
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_export_descriptor",
            message="the retained export descriptor is invalid",
        )
    return descriptor


def _publication_destination(state: Mapping[str, Any]) -> str:
    window = state.get("window")
    run_ref = state.get("run_ref")
    mode = state.get("mode")
    if (
        not isinstance(window, Mapping)
        or not isinstance(window.get("start"), str)
        or not isinstance(window.get("end"), str)
        or not isinstance(run_ref, str)
        or ":" not in run_ref
        or not isinstance(mode, str)
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_publication_identity",
            message="the run publication identity is incomplete",
        )
    run_digest = run_ref.rsplit(":", 1)[-1]
    if not SHA256_RE.fullmatch(run_digest):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_publication_identity",
            message="the run publication identity is incomplete",
        )
    start_date = window["start"][:10]
    end_date = window["end"][:10]
    if any(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}", item) is None
        for item in (start_date, end_date)
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_publication_identity",
            message="the run publication identity is incomplete",
        )
    window_name = start_date if mode == "daily" else f"{start_date}_to_{end_date}"
    return f"runs/{mode}/{window_name}/{run_digest}"


def command_finalize(args: argparse.Namespace) -> CommandResult:
    run_dir = _absolute_path(args.run_dir)
    identity_path = _command_identity_path(args)
    if identity_path is None:
        identity_path = identity_api.identity_key_path().absolute()
    orchestrator = orchestrator_api.RetrospectiveOrchestrator(
        run_dir,
        identity_path=identity_path,
        require_existing_identity=True,
    )
    run_state = orchestrator.load_state()
    if run_state.get("shadow") is not False:
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="shadow_publication_forbidden",
            message="shadow runs cannot enter formal publication",
        )

    publication = run_state.get("publication")
    if not isinstance(publication, Mapping):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="invalid_publication_state",
            message="the run publication state is invalid",
        )
    if publication.get("phase") == "published_cleanup_pending":
        cleanup = orchestrator.complete_published_cleanup()
        return CommandResult.success("finalize", _mapping_result(cleanup))
    if run_state.get("stage") == contract_api.RunStage.COMPLETE.value:
        return CommandResult.success(
            "finalize",
            {
                "action": "finalize",
                "cleanup_pending": False,
                "idempotent": True,
                "publication_phase": publication.get("phase"),
                "run_ref": run_state.get("run_ref"),
                "stage": run_state.get("stage"),
            },
        )
    if run_state.get("stage") != contract_api.RunStage.EXPORT.value:
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="run_not_exportable",
            message="the v2 run has not reached formal export",
        )

    descriptor = _load_export_descriptor(run_dir)
    bundle_dir = _absolute_path(descriptor["output"])
    binding = run_state.get("authority")
    if not isinstance(binding, Mapping):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="publication_authority_missing",
            message="the run lacks persisted publication authority",
        )
    history_repo = _absolute_path(str(binding.get("history_repo", "")))
    provider_state = _absolute_path(str(binding.get("provider_state", "")))
    target_ref = binding.get("history_target_ref")
    history_snapshot = binding.get("history_snapshot")
    if (
        not isinstance(target_ref, str)
        or not isinstance(history_snapshot, Mapping)
        or not isinstance(history_snapshot.get("history_commit"), str)
    ):
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="publication_authority_invalid",
            message="the persisted publication authority is invalid",
        )
    adapter = finalize_api.LocalGitPublicationAdapter(
        history_repo,
        provider_state,
        signing_key=str(binding.get("publisher_fingerprint", "")),
        gnupg_home=_absolute_path(str(binding.get("publisher_gnupg_home", ""))),
        expected_signer_uid=finalize_api.DEFAULT_PUBLISHER_UID,
    )
    journal = run_dir / PUBLICATION_JOURNAL_NAME
    if journal.exists() or journal.is_symlink():
        local_transaction_state = finalize_api.PublicationTransaction.inspect_local(
            journal
        )
        claim_result = orchestrator.claim_publication(
            local_transaction_state["attempt_ref"],
            local_transaction_state["plan_digest"],
        )
        transaction = finalize_api.PublicationTransaction.open(
            journal,
            adapter=adapter,
        )
    else:
        transaction = finalize_api.PublicationTransaction.create(
            journal,
            bundle_dir=bundle_dir,
            destination=_publication_destination(run_state),
            target_ref=target_ref,
            expected_target_head=history_snapshot["history_commit"],
            run_dir=run_dir,
            identity_path=identity_path,
            adapter=adapter,
        )
        local_transaction_state = transaction.status()
        claim_result = orchestrator.claim_publication(
            local_transaction_state["attempt_ref"],
            local_transaction_state["plan_digest"],
        )

    transaction_state = transaction.status()
    previous_phase = transaction.phase.value
    if previous_phase == "created":
        transaction.prepare()
    elif previous_phase == "prepared":
        transaction.stage()
    elif previous_phase == "staged":
        transaction.seal()
    elif previous_phase == "sealed":
        transaction.close_compliance()
    elif previous_phase == "compliance_closed":
        transaction.promote()
    elif previous_phase == "promoted":
        transaction.commit()
    elif previous_phase == "aborted":
        pass
    elif previous_phase != "committed":
        raise CliContractError(
            exit_code=ExitCode.INVALID_STATE,
            code="publication_not_resumable",
            message="the publication transaction is not resumable",
        )

    transaction_state = transaction.status()
    run_result = orchestrator.mark_finalized(
        transaction_state["phase"],
        attempt_ref=transaction_state["attempt_ref"],
        claim_revision=claim_result["checkpoint_revision"],
        plan_digest=transaction_state["plan_digest"],
    )
    return CommandResult.success(
        "finalize",
        {
            "action": "finalize",
            "attempt_ref": transaction_state["attempt_ref"],
            "cleanup_pending": (
                run_result.get("publication", {}).get("phase")
                == "published_cleanup_pending"
            ),
            "idempotent": transaction_state["phase"] == previous_phase,
            "publication_phase": run_result.get("publication", {}).get("phase"),
            "run_ref": run_result.get("run_ref"),
            "stage": run_result.get("stage"),
            "transaction_phase": transaction_state["phase"],
        },
    )


COMMANDS = {
    "doctor": command_doctor,
    "start": command_start,
    "status": command_status,
    "accept-source": command_accept_source,
    "accept-agent-result": command_accept_agent_result,
    "advance": command_advance,
    "export": command_export,
    "finalize": command_finalize,
}


_EXCEPTION_REASON_CODES = (
    (orchestrator_api.RunConflictError, "run_state_conflict"),
    (checkpoint_api.CheckpointConflictError, "checkpoint_conflict"),
    (export_api.ExportConflictError, "export_conflict"),
    (finalize_api.AppendOnlyViolation, "append_only_violation"),
    (finalize_api.AttemptMismatchError, "publication_attempt_mismatch"),
    (finalize_api.TargetHeadConflict, "target_head_conflict"),
    (authority_api.ProviderCacheConflict, "provider_cache_conflict"),
    (orchestrator_api.RunNotStartedError, "run_not_started"),
    (checkpoint_api.CheckpointNotFoundError, "checkpoint_not_found"),
    (FileNotFoundError, "file_not_found"),
    (orchestrator_api.InvalidTransitionError, "run_transition_invalid"),
    (finalize_api.InvalidTransitionError, "publication_transition_invalid"),
    (finalize_api.PublicationRejected, "publication_rejected"),
    (safe_io.UnsafePathError, "unsafe_path"),
    (checkpoint_api.CheckpointIntegrityError, "checkpoint_integrity_failed"),
    (checkpoint_api.CheckpointPermissionError, "checkpoint_permission_failed"),
    (export_api.ExportLocationError, "export_location_invalid"),
    (reporting_api.RetainedPrivacyError, "retained_privacy_failed"),
    (finalize_api.StateCorruptionError, "state_corruption_detected"),
    (identity_api.IdentityKeyError, "identity_invalid"),
    (PermissionError, "checkpoint_permission_failed"),
    (orchestrator_api.InvalidInputError, "run_input_invalid"),
    (safe_io.InvalidJsonError, "invalid_json"),
    (safe_io.ReadLimitExceeded, "read_limit_exceeded"),
    (reporting_api.RetainedInventoryError, "retained_inventory_invalid"),
    (reporting_api.RetainedReportingError, "retained_inventory_invalid"),
    (finalize_api.ArtifactValidationError, "invalid_retained_payload"),
    (finalize_api.ReceiptValidationError, "invalid_export_receipt"),
    (authority_api.AuthorityError, "publication_authority_invalid"),
    (export_api.RetainedExportError, "retained_export_io_failed"),
    (finalize_api.PublicationError, "publication_failed"),
    (OSError, "os_io_failed"),
    (ValueError, "invalid_input"),
)
_EXCEPTION_POLICIES = (
    (
        (
            orchestrator_api.RunConflictError,
            checkpoint_api.CheckpointConflictError,
            export_api.ExportConflictError,
            finalize_api.AppendOnlyViolation,
            finalize_api.AttemptMismatchError,
            finalize_api.TargetHeadConflict,
            authority_api.ProviderCacheConflict,
        ),
        ExitCode.CONFLICT,
        "conflict",
        "immutable state conflicts with this request",
        True,
    ),
    (
        (
            orchestrator_api.RunNotStartedError,
            checkpoint_api.CheckpointNotFoundError,
            FileNotFoundError,
        ),
        ExitCode.NOT_FOUND,
        "not_found",
        "required local state was not found",
        False,
    ),
    (
        (
            orchestrator_api.InvalidTransitionError,
            finalize_api.InvalidTransitionError,
            finalize_api.PublicationRejected,
        ),
        ExitCode.INVALID_STATE,
        "invalid_state",
        "command is not valid for the current state",
        False,
    ),
    (
        (
            safe_io.UnsafePathError,
            checkpoint_api.CheckpointIntegrityError,
            checkpoint_api.CheckpointPermissionError,
            export_api.ExportLocationError,
            reporting_api.RetainedPrivacyError,
            finalize_api.StateCorruptionError,
            identity_api.IdentityKeyError,
            PermissionError,
        ),
        ExitCode.SECURITY,
        "security_error",
        "path, permission, or privacy validation failed",
        False,
    ),
    (
        (
            orchestrator_api.InvalidInputError,
            safe_io.InvalidJsonError,
            safe_io.ReadLimitExceeded,
            reporting_api.RetainedInventoryError,
            reporting_api.RetainedReportingError,
            finalize_api.ArtifactValidationError,
            finalize_api.ReceiptValidationError,
            authority_api.AuthorityError,
            ValueError,
        ),
        ExitCode.INVALID_INPUT,
        "invalid_input",
        "command input was rejected",
        False,
    ),
    (
        (export_api.RetainedExportError, OSError),
        ExitCode.IO,
        "io_error",
        "bounded local I/O failed",
        True,
    ),
    (
        (finalize_api.PublicationError,),
        ExitCode.INVALID_STATE,
        "invalid_state",
        "command is not valid for the current state",
        False,
    ),
)


def _exception_reason_code(error: Exception) -> str:
    for error_type, reason_code in _EXCEPTION_REASON_CODES:
        if isinstance(error, error_type):
            return reason_code
    return "unexpected_internal_failure"


def _failure_from_exception(command: str, error: Exception) -> CommandResult:
    if isinstance(error, CliContractError):
        return CommandResult.failure(
            command,
            exit_code=error.exit_code,
            code=error.code,
            message=error.safe_message,
            retryable=error.retryable,
        )
    if isinstance(error, authority_api.AutomationCutoverBlocked):
        return CommandResult.failure(
            command,
            exit_code=ExitCode.UNAVAILABLE,
            code="automation_cutover_blocked",
            message="automation_update evidence did not admit v2 cutover",
        )

    for error_types, exit_code, code, message, retryable in _EXCEPTION_POLICIES:
        if isinstance(error, error_types):
            return CommandResult.failure(
                command,
                exit_code=exit_code,
                code=code,
                message=message,
                reason_code=_exception_reason_code(error),
                retryable=retryable,
            )
    return CommandResult.failure(
        command,
        exit_code=ExitCode.INTERNAL,
        code="internal_error",
        message="unexpected v2 command failure",
        reason_code="unexpected_internal_failure",
    )


def dispatch(args: argparse.Namespace) -> CommandResult:
    command = getattr(args, "command", "unknown")
    handler = COMMANDS.get(command)
    if handler is None:
        return CommandResult.failure(
            command,
            exit_code=ExitCode.USAGE,
            code="usage_error",
            message="command arguments are invalid",
        )
    try:
        return handler(args)
    except Exception as error:  # The machine contract owns every failure shape.
        return _failure_from_exception(command, error)


def _emit(result: CommandResult) -> int:
    try:
        payload = contract_api.canonical_json(result.to_json())
    except Exception:
        result = CommandResult.failure(
            result.command,
            exit_code=ExitCode.INTERNAL,
            code="internal_error",
            message="unexpected v2 command failure",
        )
        payload = json.dumps(
            result.to_json(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    sys.stdout.write(payload + "\n")
    if result.error is not None:
        diagnostic = (
            f"session_retrospective_v2: {result.error.code}: {result.error.message}\n"
        )[:MAX_DIAGNOSTIC_BYTES]
        sys.stderr.write(diagnostic)
    return int(result.exit_code)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    command = "unknown"
    arguments = sys.argv[1:] if argv is None else argv
    if arguments and arguments[0] in COMMANDS:
        command = arguments[0]
    try:
        parsed = parser.parse_args(arguments)
    except HelpRequested as help_request:
        return _emit(
            CommandResult.success(
                help_request.command,
                {"action": "help", "usage": help_request.usage},
            )
        )
    except CliContractError as error:
        return _emit(
            CommandResult.failure(
                command,
                exit_code=error.exit_code,
                code=error.code,
                message=error.safe_message,
                retryable=error.retryable,
            )
        )
    return _emit(dispatch(parsed))


if __name__ == "__main__":
    raise SystemExit(main())
