"""Immutable publication value contracts and closed validation helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .identity import IdentityKey

STATE_SCHEMA_VERSION = 2
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
MAX_SUBPROCESS_OUTPUT_BYTES = 4 * 1024 * 1024
DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 30.0
DEFAULT_PUBLICATION_CAPACITY_BYTES = 1024 * 1024 * 1024
PUBLICATION_CAPACITY_OVERHEAD_BYTES = 1024 * 1024
LOCAL_GIT_RECEIPT_PREFIX = "local_git_receipt_v2:"
LOCAL_GIT_TRANSACTION_PREFIX = "local_git_transaction_v2:"
LOCAL_GIT_CHAIN_PREFIX = "local_git_chain_v2:"
LOCAL_GIT_CAPACITY_RESERVATION_SCHEMA = "local_git_capacity_reservation_v2"
LOCAL_GIT_CLEANUP_CLAIM_PREFIX = "local_git_cleanup_claim_v2:"
LOCAL_GIT_CLEANUP_CLAIM_SCHEMA = "local_git_cleanup_claim_v2"
DEFAULT_PUBLISHER_GNUPG_HOME = (
    Path.home() / ".codex/session-retrospective/publisher-gnupg-v2"
)
DEFAULT_PUBLISHER_FINGERPRINT = "40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"
LOCAL_GIT_SIGNER_NAME = "Codex Session Retrospective Publisher"
LOCAL_GIT_SIGNER_EMAIL = "12524680+JoeyTeng@users.noreply.github.com"
DEFAULT_PUBLISHER_UID = f"{LOCAL_GIT_SIGNER_NAME} <{LOCAL_GIT_SIGNER_EMAIL}>"

ARTIFACT_NAMES = (
    "manifest.json",
    "coverage.json",
    "episodes.jsonl",
    "turn_findings.jsonl",
    "topics.jsonl",
    "trend_report.json",
    "report.md",
    "summary.json",
)
ARTIFACT_NAMES_BYTEWISE = tuple(
    sorted(ARTIFACT_NAMES, key=lambda name: name.encode("ascii"))
)

RETAINED_BUNDLE_DOMAIN_V2 = b"session-retrospective-retained-bundle-v2\x00"
ARTIFACT_INVENTORY_DOMAIN_V2 = b"codex-session-retrospective/artifact-inventory/v2\x00"
ATTEMPT_REF_PREFIX = "attempt_ref_v2:"
SHADOW_TRANSACTION_REF_PREFIX = "shadow_transaction_v2:"
SHADOW_RECEIPT_REF_PREFIX = "shadow_receipt_v2:"
FORMAL_AUTHORIZATION_SCHEMA = "durable_publication_authority_v2"
EPISODE_HEAD_UPDATE_SCHEMA = "episode_head_update_v2"
PROVIDER_EPISODE_HEADS_SCHEMA = "provider_episode_heads_v2"
PROVIDER_CAS_JOURNAL_SCHEMA = "provider_cursor_episode_cas_v2"
PUBLICATION_CLAIM_SCHEMA = "publication_claim_v2"
PUBLICATION_ABORT_COMMITMENT_SCHEMA = "publication_abort_commitment_v2"
PUBLICATION_ABORT_COMMITMENT_REF_PREFIX = "publication_abort_commitment_v2:"
PUBLICATION_ABORT_COMMITMENT_AUTH_PREFIX = "publication_abort_auth_v2:"
PUBLICATION_JOURNAL_NAME = "publication-transaction-v2.json"

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SHA1_OR_SHA256_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_ATTEMPT_REF_RE = re.compile(r"attempt_ref_v2:[0-9a-f]{64}\Z")
_PUBLICATION_CLAIM_REF_RE = re.compile(r"publication_claim_v2:[0-9a-f]{64}\Z")
_PUBLICATION_CLAIM_AUTH_RE = re.compile(r"publication_claim_auth_v2:[0-9a-f]{64}\Z")
_SAFE_DESTINATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\Z")
_SAFE_REF_RE = re.compile(r"[ -~]{1,512}\Z")
_SAFE_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_HELPER_GIT_ENV_KEYS = frozenset(
    {
        "GIT_AUTHOR_DATE",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_NAME",
        "GIT_COMMITTER_DATE",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_INDEX_FILE",
    }
)
_CREDENTIAL_KEYS = {
    "access_token",
    "authorization_header",
    "cookie",
    "credentials",
    "git_credentials",
    "password",
    "private_key",
    "secret_key",
}


class PublicationError(RuntimeError):
    """Base class for local publication transaction failures."""


class ArtifactValidationError(PublicationError):
    pass


class AttemptMismatchError(PublicationError):
    pass


class InvalidTransitionError(PublicationError):
    pass


class ReceiptValidationError(PublicationError):
    pass


class StateCorruptionError(PublicationError):
    pass


class AppendOnlyViolation(PublicationError):
    pass


class PublicationRejected(PublicationError):
    pass


class TargetHeadConflict(PublicationError):
    def __init__(self, expected: str | None, actual: str | None) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"target head conflict: expected {expected!r}, found {actual!r}"
        )


class LocalGitPublicationError(PublicationError):
    """Raised when the constrained local Git provider rejects an operation."""


class CapacityReservationError(LocalGitPublicationError):
    pass


class GenerationConflict(PublicationRejected):
    pass


class TransactionKind(str, Enum):
    PUBLISH = "publish"
    SHADOW = "shadow"


class PublicationPhase(str, Enum):
    CREATED = "created"
    PREPARED = "prepared"
    STAGED = "staged"
    SEALED = "sealed"
    COMPLIANCE_CLOSED = "compliance_closed"
    PROMOTED = "promoted"
    COMMITTED = "committed"
    ABORT_PENDING = "abort_pending"
    ABORTED = "aborted"


_NORMAL_PHASES = (
    PublicationPhase.CREATED,
    PublicationPhase.PREPARED,
    PublicationPhase.STAGED,
    PublicationPhase.SEALED,
    PublicationPhase.COMPLIANCE_CLOSED,
    PublicationPhase.PROMOTED,
    PublicationPhase.COMMITTED,
)
_NORMAL_PHASE_INDEX = {phase: index for index, phase in enumerate(_NORMAL_PHASES)}


@dataclass(frozen=True)
class ArtifactRecord:
    name: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ArtifactRecord:
        if set(value) != {"name", "size", "sha256"}:
            raise StateCorruptionError("artifact record has an unexpected shape")
        name = value["name"]
        size = value["size"]
        digest = value["sha256"]
        if name not in ARTIFACT_NAMES:
            raise StateCorruptionError(f"unknown artifact name: {name!r}")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_BUNDLE_BYTES
        ):
            raise StateCorruptionError(f"invalid artifact size for {name}")
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise StateCorruptionError(f"invalid artifact digest for {name}")
        return cls(name=name, size=size, sha256=digest)


@dataclass(frozen=True)
class ArtifactInventory:
    artifacts: tuple[ArtifactRecord, ...]
    total_bytes: int
    retained_bundle_digest_v2: str
    inventory_digest_v2: str

    @property
    def digest_by_name(self) -> dict[str, str]:
        return {artifact.name: artifact.sha256 for artifact in self.artifacts}

    @property
    def size_by_name(self) -> dict[str, int]:
        return {artifact.name: artifact.size for artifact in self.artifacts}

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "total_bytes": self.total_bytes,
            "retained_bundle_digest_v2": self.retained_bundle_digest_v2,
            "inventory_digest_v2": self.inventory_digest_v2,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ArtifactInventory:
        expected_keys = {
            "artifacts",
            "total_bytes",
            "retained_bundle_digest_v2",
            "inventory_digest_v2",
        }
        if set(value) != expected_keys:
            raise StateCorruptionError("artifact inventory has an unexpected shape")
        raw_artifacts = value["artifacts"]
        if not isinstance(raw_artifacts, list):
            raise StateCorruptionError("artifact inventory records must be a list")
        artifacts = tuple(
            ArtifactRecord.from_dict(_require_mapping(row, "artifact"))
            for row in raw_artifacts
        )
        names = tuple(artifact.name for artifact in artifacts)
        if names != ARTIFACT_NAMES_BYTEWISE:
            raise StateCorruptionError(
                "artifact inventory is not the exact bytewise-ordered inventory"
            )
        total_bytes = value["total_bytes"]
        retained_digest = value["retained_bundle_digest_v2"]
        inventory_digest = value["inventory_digest_v2"]
        if (
            not isinstance(total_bytes, int)
            or isinstance(total_bytes, bool)
            or total_bytes < 0
        ):
            raise StateCorruptionError("artifact inventory total is invalid")
        if total_bytes != sum(artifact.size for artifact in artifacts):
            raise StateCorruptionError("artifact inventory byte total is inconsistent")
        if (
            not isinstance(retained_digest, str)
            or _SHA256_RE.fullmatch(retained_digest) is None
        ):
            raise StateCorruptionError("retained bundle digest is invalid")
        expected_inventory_digest = _inventory_digest(artifacts)
        if inventory_digest != expected_inventory_digest:
            raise StateCorruptionError("artifact inventory digest is inconsistent")
        return cls(
            artifacts=artifacts,
            total_bytes=total_bytes,
            retained_bundle_digest_v2=retained_digest,
            inventory_digest_v2=inventory_digest,
        )


@dataclass(frozen=True)
class OperationRequest:
    phase: str
    attempt_ref: str
    kind: str
    target_ref: str
    expected_target_head: str | None
    destination: str
    plan_digest: str
    inventory: ArtifactInventory
    receipts: Mapping[str, Mapping[str, Any]]
    bundle_dir: str = ""
    host_cursor_vector: Mapping[str, Mapping[str, Any]] = dataclass_field(
        default_factory=dict
    )
    episode_head_update: Mapping[str, Any] = dataclass_field(default_factory=dict)
    publication_authority: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def binding(self) -> dict[str, Any]:
        return {
            "attempt_ref": self.attempt_ref,
            "plan_digest": self.plan_digest,
            "inventory_digest": self.inventory.inventory_digest_v2,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "attempt_ref": self.attempt_ref,
            "kind": self.kind,
            "target_ref": self.target_ref,
            "expected_target_head": self.expected_target_head,
            "destination": self.destination,
            "plan_digest": self.plan_digest,
            "inventory": self.inventory.to_dict(),
            "receipts": deepcopy(dict(self.receipts)),
            "bundle_dir": self.bundle_dir,
            "host_cursor_vector": deepcopy(dict(self.host_cursor_vector)),
            "episode_head_update": deepcopy(dict(self.episode_head_update)),
            "publication_authority": deepcopy(dict(self.publication_authority)),
        }


@dataclass(frozen=True)
class HostCursorUpdate:
    """One compare-and-swap cell in the per-host publication cursor vector."""

    expected_cursor: str | None
    proposed_cursor: str | None
    coverage_complete: bool
    expected_backlog_head: str | None = None
    proposed_backlog_head: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage_complete": self.coverage_complete,
            "expected_backlog_head": self.expected_backlog_head,
            "expected_cursor": self.expected_cursor,
            "proposed_backlog_head": self.proposed_backlog_head,
            "proposed_cursor": self.proposed_cursor,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, host_ref: str) -> HostCursorUpdate:
        expected_fields = {
            "coverage_complete",
            "expected_backlog_head",
            "expected_cursor",
            "proposed_backlog_head",
            "proposed_cursor",
        }
        if set(value) != expected_fields:
            raise ValueError(
                f"host cursor update for {host_ref!r} has an unexpected shape"
            )
        coverage_complete = value["coverage_complete"]
        if not isinstance(coverage_complete, bool):
            raise ValueError(
                f"host cursor update for {host_ref!r} requires coverage_complete"
            )
        for field_name in (
            "expected_backlog_head",
            "expected_cursor",
            "proposed_backlog_head",
            "proposed_cursor",
        ):
            _validate_optional_ref(value[field_name], f"{host_ref}.{field_name}")
        if (
            not coverage_complete
            and value["proposed_cursor"] != value["expected_cursor"]
        ):
            raise ValueError(
                f"partial host cursor update for {host_ref!r} cannot advance the source cursor"
            )
        return cls(
            expected_cursor=value["expected_cursor"],
            proposed_cursor=value["proposed_cursor"],
            coverage_complete=coverage_complete,
            expected_backlog_head=value["expected_backlog_head"],
            proposed_backlog_head=value["proposed_backlog_head"],
        )


class PublicationAdapter(Protocol):
    """Idempotent side-effect adapter keyed by ``OperationRequest.attempt_ref``."""

    def acquire_publication_lock(
        self, request: OperationRequest
    ) -> Mapping[str, Any]: ...

    def inspect_target(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def reserve(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def release_publication_lock(
        self,
        request: OperationRequest,
        lock_receipt: Mapping[str, Any],
    ) -> None: ...

    def stage(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def seal(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def close_compliance(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def promote(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def validate_history(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def cleanup(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def release_reservations(self, request: OperationRequest) -> Mapping[str, Any]: ...

    def advance_state(self, request: OperationRequest) -> Mapping[str, Any]: ...


class RetainedExportLifecycle(Protocol):
    """Narrow dependency on retained-export lifecycle operations."""

    def bind_staged_export(
        self,
        output_dir: str | os.PathLike[str],
        attempt_ref: str,
    ) -> Mapping[str, Any]: ...

    def release_staged_export(
        self,
        output_dir: str | os.PathLike[str],
        attempt_ref: str,
        disposition: str,
    ) -> Mapping[str, Any]: ...

    def release_staged_export_if_bound(
        self,
        output_dir: str | os.PathLike[str],
        attempt_ref: str,
        disposition: str,
    ) -> Mapping[str, Any]:
        """Release a bound pair, accept two absent objects, and reject one-sided state."""

        ...


FailureInjector = Callable[[str, Mapping[str, Any]], None]


def new_attempt_ref() -> str:
    return f"{ATTEMPT_REF_PREFIX}{secrets.token_hex(32)}"


def verify_publication_abort_commitment(
    identity: IdentityKey,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "attempt_ref",
        "authentication_tag",
        "cleanup_receipt_ref",
        "identity_key_id",
        "inventory_digest",
        "plan_digest",
        "publication_claim_ref",
        "receipt_ref",
        "reservation_release_receipt_ref",
        "run_ref",
        "schema",
        "status",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReceiptValidationError(
            "publication abort commitment has an unexpected shape"
        )
    commitment = _json_clone(dict(value))
    if (
        commitment["schema"] != PUBLICATION_ABORT_COMMITMENT_SCHEMA
        or commitment["status"] != "publication_abort_complete"
        or commitment["identity_key_id"] != identity.key_id
    ):
        raise ReceiptValidationError("publication abort commitment is invalid")
    try:
        _validate_attempt_ref(commitment["attempt_ref"])
        _validate_ref(commitment["run_ref"], "run_ref")
    except ValueError as exc:
        raise ReceiptValidationError(str(exc)) from exc
    for name in ("inventory_digest", "plan_digest"):
        if (
            not isinstance(commitment[name], str)
            or _SHA256_RE.fullmatch(commitment[name]) is None
        ):
            raise ReceiptValidationError(
                f"publication abort commitment {name} is invalid"
            )
    if (
        not isinstance(commitment["publication_claim_ref"], str)
        or _PUBLICATION_CLAIM_REF_RE.fullmatch(commitment["publication_claim_ref"])
        is None
    ):
        raise ReceiptValidationError(
            "publication abort commitment claim reference is invalid"
        )
    for name in ("cleanup_receipt_ref", "reservation_release_receipt_ref"):
        _validate_ref_value(commitment[name], name)

    unsigned = dict(commitment)
    authentication_tag = unsigned.pop("authentication_tag")
    receipt_ref = unsigned.pop("receipt_ref")
    expected_ref = PUBLICATION_ABORT_COMMITMENT_REF_PREFIX + identity.derive_digest(
        PUBLICATION_ABORT_COMMITMENT_REF_PREFIX,
        unsigned,
    )
    with_ref = {**unsigned, "receipt_ref": expected_ref}
    expected_auth = PUBLICATION_ABORT_COMMITMENT_AUTH_PREFIX + identity.derive_digest(
        PUBLICATION_ABORT_COMMITMENT_AUTH_PREFIX, with_ref
    )
    if not (
        isinstance(receipt_ref, str)
        and isinstance(authentication_tag, str)
        and hmac.compare_digest(receipt_ref, expected_ref)
        and hmac.compare_digest(authentication_tag, expected_auth)
    ):
        raise ReceiptValidationError(
            "publication abort commitment authentication failed"
        )
    return commitment


def _parse_commit_object(raw: bytes) -> tuple[list[tuple[str, str]], bytes]:
    header_bytes, separator, body = raw.partition(b"\n\n")
    if separator != b"\n\n":
        raise LocalGitPublicationError(
            "publication commit object has no message boundary"
        )
    headers: list[tuple[str, str]] = []
    current_name: str | None = None
    current_value: list[str] = []
    for raw_line in header_bytes.splitlines():
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError as exc:
            raise LocalGitPublicationError(
                "publication commit headers must be ASCII"
            ) from exc
        if line.startswith(" "):
            if current_name != "gpgsig":
                raise LocalGitPublicationError(
                    "unexpected folded publication commit header"
                )
            current_value.append(line[1:])
            continue
        if current_name is not None:
            headers.append((current_name, "\n".join(current_value)))
        name, separator_text, value = line.partition(" ")
        if separator_text != " " or not name:
            raise LocalGitPublicationError("malformed publication commit header")
        current_name = name
        current_value = [value]
    if current_name is not None:
        headers.append((current_name, "\n".join(current_value)))
    return headers, body


def _publication_timestamp(attempt_ref: str, ordinal: int) -> int:
    attempt_hex = attempt_ref.removeprefix(ATTEMPT_REF_PREFIX)
    base = 1_704_067_200
    day_offset = int(attempt_hex[:8], 16) % (20 * 366)
    return base + day_offset * 86_400 + ordinal * 60


def _publication_commit_message(
    attempt_ref: str,
    plan_digest: str,
    unit: Mapping[str, Any],
    ordinal: int,
) -> bytes:
    role = unit["publication_role"]
    return (
        "Publish Session Retrospective v2\n\n"
        f"Attempt: {attempt_ref}\n"
        f"Plan-Digest: {plan_digest}\n"
        f"Ordinal: {ordinal}\n"
        f"Role: {role}\n"
    ).encode("ascii")


def _publication_chain_root(prefixes: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256(b"codex-session-retrospective/local-git-chain/v2\x00")
    for prefix in prefixes:
        encoded = _canonical_json_bytes(prefix)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _bounded_git_error(result: subprocess.CompletedProcess[bytes]) -> str:
    payload = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
    return payload[-1000:] or f"exit status {result.returncode}"


def _split_signer_uid(value: str) -> tuple[str, str] | None:
    match = re.fullmatch(r"([^\n<>]+) <([^\n<>]+@[^\n<>]+)>", value)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _decode_gpg_colon_field(value: str) -> str:
    output = bytearray()
    index = 0
    while index < len(value):
        if (
            value[index] == "\\"
            and value[index : index + 2] == "\\x"
            and index + 4 <= len(value)
        ):
            try:
                output.append(int(value[index + 2 : index + 4], 16))
            except ValueError:
                output.extend(value[index].encode("ascii"))
                index += 1
                continue
            index += 4
            continue
        output.extend(value[index].encode("utf-8"))
        index += 1
    return output.decode("utf-8")


def _inventory_digest(artifacts: tuple[ArtifactRecord, ...]) -> str:
    hasher = hashlib.sha256()
    hasher.update(ARTIFACT_INVENTORY_DOMAIN_V2)
    for artifact in artifacts:
        name = artifact.name.encode("ascii")
        hasher.update(b"N")
        hasher.update(len(name).to_bytes(4, "big"))
        hasher.update(name)
        hasher.update(b"L")
        hasher.update(artifact.size.to_bytes(8, "big"))
        hasher.update(b"H")
        hasher.update(bytes.fromhex(artifact.sha256))
    return hasher.hexdigest()


def _parse_json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_artifact_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ArtifactValidationError) as exc:
        raise ArtifactValidationError(
            f"{label} is not valid duplicate-free UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ArtifactValidationError(f"{label} must contain a JSON object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactValidationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_artifact_json_constant(value: str) -> Any:
    raise ArtifactValidationError(f"non-finite JSON value: {value}")


def _normalize_receipt(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptValidationError(f"{label} receipt must be a mapping")
    try:
        encoded = _canonical_json_bytes(dict(value))
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise ReceiptValidationError(f"{label} receipt exceeds the 1 MiB limit")
        normalized = json.loads(encoded.decode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ReceiptValidationError(
            f"{label} receipt is not canonical JSON data"
        ) from exc
    _reject_credential_fields(normalized)
    return normalized


def _reject_credential_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in _CREDENTIAL_KEYS:
                raise ReceiptValidationError(
                    f"receipt must not contain credential field {key!r}"
                )
            _reject_credential_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_credential_fields(item)


def _new_event(
    events: list[Mapping[str, Any]],
    *,
    attempt_ref: str,
    action: str,
    from_phase: str | None,
    to_phase: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    sequence = len(events)
    previous_digest = events[-1]["event_digest"] if events else None
    event = {
        "sequence": sequence,
        "attempt_ref": attempt_ref,
        "action": action,
        "from_phase": from_phase,
        "to_phase": to_phase,
        "previous_event_digest": previous_digest,
        "details": _json_clone(details),
    }
    event["event_digest"] = _sha256_json(event)
    return event


def _validate_event_chain(state: Mapping[str, Any]) -> None:
    events = state["events"]
    if not isinstance(events, list) or not events:
        raise StateCorruptionError("publication event chain is empty")
    if len(events) > 32:
        raise StateCorruptionError(
            "publication event chain exceeds its bounded lifecycle"
        )
    previous_digest: str | None = None
    previous_phase: str | None = None
    for sequence, raw_event in enumerate(events):
        event = _require_mapping(raw_event, "event")
        expected_keys = {
            "sequence",
            "attempt_ref",
            "action",
            "from_phase",
            "to_phase",
            "previous_event_digest",
            "details",
            "event_digest",
        }
        if set(event) != expected_keys:
            raise StateCorruptionError("publication event has an unexpected shape")
        if (
            event["sequence"] != sequence
            or event["attempt_ref"] != state["attempt_ref"]
        ):
            raise StateCorruptionError(
                "publication event identity or sequence is invalid"
            )
        if event["previous_event_digest"] != previous_digest:
            raise StateCorruptionError("publication event chain is discontinuous")
        if event["from_phase"] != previous_phase:
            raise StateCorruptionError("publication event phase chain is discontinuous")
        try:
            PublicationPhase(event["to_phase"])
        except (TypeError, ValueError) as exc:
            raise StateCorruptionError(
                "publication event target phase is invalid"
            ) from exc
        unsigned = dict(event)
        event_digest = unsigned.pop("event_digest")
        if event_digest != _sha256_json(unsigned):
            raise StateCorruptionError("publication event digest is invalid")
        _validate_event_transition(event)
        previous_digest = event_digest
        previous_phase = event["to_phase"]
    if state["revision"] != len(events) - 1:
        raise StateCorruptionError("publication revision does not match event chain")
    if previous_phase != state["phase"]:
        raise StateCorruptionError("publication phase does not match event chain")


def _state_digest(state: Mapping[str, Any]) -> str:
    unsigned = dict(state)
    unsigned.pop("state_digest", None)
    return _sha256_json(unsigned)


def _state_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StateCorruptionError(f"duplicate publication state key: {key}")
        value[key] = item
    return value


def _reject_state_json_constant(value: str) -> Any:
    raise StateCorruptionError(f"non-finite publication state value: {value}")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _json_clone(value: Any) -> Any:
    return json.loads(_canonical_json_bytes(value).decode("utf-8"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StateCorruptionError(f"{label} must be a mapping")
    return value


def _normalize_host_cursor_vector(
    value: Mapping[str, Mapping[str, Any] | HostCursorUpdate],
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise ValueError("host_cursor_vector must be a mapping")
    normalized: dict[str, dict[str, Any]] = {}
    for host_ref, raw_update in sorted(value.items()):
        if not isinstance(host_ref, str):
            raise ValueError("host cursor references must be strings")
        _validate_ref(host_ref, "host_ref")
        if isinstance(raw_update, HostCursorUpdate):
            update = raw_update
        elif isinstance(raw_update, Mapping):
            update = HostCursorUpdate.from_dict(raw_update, host_ref=host_ref)
        else:
            raise ValueError(f"host cursor update for {host_ref!r} must be a mapping")
        normalized[host_ref] = update.to_dict()
    return normalized


def _normalize_episode_head_update(
    value: Mapping[str, Any],
    *,
    required: bool,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("episode_head_update must be a mapping")
    if not value:
        if required:
            raise ValueError("formal publication requires an episode head update")
        return {}
    expected_fields = {
        "backfill_lineage_receipt",
        "expected_episode_head_set_ref",
        "proposed_episode_head_set_ref",
        "proposed_episode_heads",
        "schema",
    }
    if (
        set(value) != expected_fields
        or value.get("schema") != EPISODE_HEAD_UPDATE_SCHEMA
    ):
        raise ValueError("episode_head_update has an unexpected shape")
    expected_ref = value["expected_episode_head_set_ref"]
    proposed_ref = value["proposed_episode_head_set_ref"]
    _validate_ref(expected_ref, "expected_episode_head_set_ref")
    _validate_ref(proposed_ref, "proposed_episode_head_set_ref")
    raw_heads = value["proposed_episode_heads"]
    if not isinstance(raw_heads, Sequence) or isinstance(raw_heads, (str, bytes)):
        raise ValueError("proposed_episode_heads must be an array")
    heads: list[dict[str, Any]] = []
    for raw in raw_heads:
        if not isinstance(raw, Mapping):
            raise ValueError("proposed episode head must be a mapping")
        head = _json_clone(dict(raw))
        for name in ("episode_ref", "episode_revision_ref", "session_ref"):
            _validate_ref(head.get(name), f"proposed episode head {name}")
        revision = head.get("revision_ordinal")
        previous = head.get("supersedes_episode_revision_ref")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("proposed episode head revision_ordinal is invalid")
        _validate_optional_ref(previous, "supersedes_episode_revision_ref")
        heads.append(head)
    heads.sort(key=lambda item: item["episode_ref"])
    if len({item["episode_ref"] for item in heads}) != len(heads):
        raise ValueError("proposed episode heads contain duplicate identities")
    if list(raw_heads) != heads:
        raise ValueError("proposed episode heads are not canonical")
    lineage = value["backfill_lineage_receipt"]
    if lineage is not None:
        if not isinstance(lineage, Mapping):
            raise ValueError("backfill lineage receipt must be a mapping")
        lineage = _json_clone(dict(lineage))
        if (
            lineage.get("schema") != "backfill_lineage_receipt_v2"
            or lineage.get("expected_episode_head_set_ref") != expected_ref
            or lineage.get("proposed_episode_head_set_ref") != proposed_ref
            or not isinstance(lineage.get("receipt_ref"), str)
            or not isinstance(lineage.get("authentication_tag"), str)
        ):
            raise ValueError("backfill lineage receipt does not bind the head update")
    return {
        "backfill_lineage_receipt": lineage,
        "expected_episode_head_set_ref": expected_ref,
        "proposed_episode_head_set_ref": proposed_ref,
        "proposed_episode_heads": heads,
        "schema": EPISODE_HEAD_UPDATE_SCHEMA,
    }


def _normalize_publication_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("publication_authority must be a mapping")
    expected_fields = {
        "candidate_digest",
        "configuration_root",
        "configuration_ref",
        "destination",
        "expected_history",
        "history_repo",
        "identity_key_id",
        "identity_path",
        "marker_authentication_tag",
        "model_era",
        "policy_era",
        "production_marker",
        "proposed_durable_state",
        "provider_state",
        "publisher_fingerprint",
        "publisher_gnupg_home",
        "run_dir",
        "schema",
        "target_ref",
    }
    if (
        set(value) != expected_fields
        or value.get("schema") != FORMAL_AUTHORIZATION_SCHEMA
    ):
        raise ValueError("publication_authority has an unexpected shape")
    for name in (
        "history_repo",
        "identity_path",
        "production_marker",
        "provider_state",
        "publisher_gnupg_home",
        "run_dir",
    ):
        item = value[name]
        if not isinstance(item, str) or not Path(item).is_absolute():
            raise ValueError(f"publication authority {name} must be absolute")
    if (
        not isinstance(value["candidate_digest"], str)
        or _SHA256_RE.fullmatch(value["candidate_digest"]) is None
    ):
        raise ValueError("publication authority candidate digest is invalid")
    if (
        not isinstance(value["configuration_root"], str)
        or _SHA256_RE.fullmatch(value["configuration_root"]) is None
    ):
        raise ValueError("publication authority configuration root is invalid")
    for name in ("model_era", "policy_era"):
        era = value[name]
        if not isinstance(era, str) or not era or len(era) > 128:
            raise ValueError(f"publication authority {name} is invalid")
    if not isinstance(value["identity_key_id"], str) or not value[
        "identity_key_id"
    ].startswith("identity_key_v2:"):
        raise ValueError("publication authority identity is invalid")
    if not isinstance(value["expected_history"], Mapping) or not isinstance(
        value["proposed_durable_state"], Mapping
    ):
        raise ValueError("publication authority durable state is invalid")
    _validate_destination(value["destination"])
    _validate_ref(value["target_ref"], "target_ref")
    return _json_clone(dict(value))


def _validate_destination(value: str) -> None:
    try:
        _validate_destination_state(value)
    except StateCorruptionError as exc:
        raise ValueError(str(exc)) from exc


def _validate_destination_state(value: Any) -> None:
    if (
        not isinstance(value, str)
        or _SAFE_DESTINATION_RE.fullmatch(value) is None
        or "\\" in value
    ):
        raise StateCorruptionError(
            "destination must be a safe printable POSIX relative path"
        )
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise StateCorruptionError(
            "destination must be a normalized POSIX relative path"
        )


def _validate_ref(value: str, label: str) -> None:
    try:
        _validate_ref_state(value, label)
    except StateCorruptionError as exc:
        raise ValueError(str(exc)) from exc


def _validate_attempt_ref(value: Any) -> None:
    if not isinstance(value, str) or _ATTEMPT_REF_RE.fullmatch(value) is None:
        raise ValueError(
            "attempt_ref must have the form attempt_ref_v2:<64 lowercase hex>"
        )


def _validate_ref_value(value: Any, label: str) -> None:
    if not isinstance(value, str):
        raise ReceiptValidationError(f"{label} must be a non-empty printable reference")
    try:
        _validate_ref(value, label)
    except ValueError as exc:
        raise ReceiptValidationError(str(exc)) from exc


def _validate_ref_state(value: Any, label: str) -> None:
    if not isinstance(value, str) or _SAFE_REF_RE.fullmatch(value) is None:
        raise StateCorruptionError(f"{label} must be a non-empty printable reference")


def _validate_optional_ref(value: Any, label: str) -> None:
    if value is None:
        return
    _validate_ref_value(value, label)


def _validate_optional_ref_state(value: Any, label: str) -> None:
    if value is None:
        return
    _validate_ref_state(value, label)


def _validate_owner_only_state_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise StateCorruptionError(
            f"cannot inspect publication state directory: {path}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise StateCorruptionError(
            "publication state directory must be a real directory"
        )
    current_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
    if metadata.st_uid != current_uid:
        raise StateCorruptionError(
            "publication state directory is not owned by the current user"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise StateCorruptionError("publication state directory must have mode 0700")


def _validate_phase_receipts(
    *,
    phase: PublicationPhase,
    kind: TransactionKind,
    receipts: Mapping[str, Any],
    reservations_held: bool,
    state_advanced: bool,
) -> None:
    phase_requirements = {
        PublicationPhase.PREPARED: {"reservation"},
        PublicationPhase.STAGED: {"reservation", "stage"},
        PublicationPhase.SEALED: {"reservation", "stage", "seal"},
        PublicationPhase.COMPLIANCE_CLOSED: {
            "reservation",
            "stage",
            "seal",
            "compliance",
        },
        PublicationPhase.PROMOTED: {
            "reservation",
            "stage",
            "seal",
            "compliance",
            "promotion",
        },
        PublicationPhase.COMMITTED: {
            "reservation",
            "stage",
            "seal",
            "compliance",
            "promotion",
            "history_validation",
        },
    }
    required = phase_requirements.get(phase, set())
    if not required.issubset(receipts):
        missing = sorted(required - set(receipts))
        raise StateCorruptionError(
            f"publication phase is missing required receipts: {missing}"
        )
    if phase is PublicationPhase.COMMITTED:
        terminal_receipt = (
            "shadow_completion" if kind is TransactionKind.SHADOW else "state_advance"
        )
        if terminal_receipt not in receipts:
            raise StateCorruptionError(
                f"committed publication is missing {terminal_receipt}"
            )
    if phase is PublicationPhase.ABORTED and not {
        "abort_commitment",
        "cleanup",
        "reservation_release",
    }.issubset(receipts):
        raise StateCorruptionError(
            "aborted publication lacks cleanup or reservation release"
        )
    if "reservation_release" in receipts and "cleanup" not in receipts:
        raise StateCorruptionError("reservation release exists without durable cleanup")
    if (
        phase not in {PublicationPhase.COMMITTED, PublicationPhase.ABORTED}
        and not reservations_held
    ):
        raise StateCorruptionError(
            "nonterminal publication released reservations early"
        )
    if (
        kind is TransactionKind.PUBLISH
        and phase is PublicationPhase.COMMITTED
        and not state_advanced
    ):
        raise StateCorruptionError("publishing commit did not advance canonical state")


def _validate_event_transition(event: Mapping[str, Any]) -> None:
    action = event["action"]
    from_phase = event["from_phase"]
    to_phase = event["to_phase"]
    exact_transitions = {
        "create": (None, PublicationPhase.CREATED.value),
        "prepare": (PublicationPhase.CREATED.value, PublicationPhase.PREPARED.value),
        "prepare_target_conflict": (
            PublicationPhase.CREATED.value,
            PublicationPhase.ABORT_PENDING.value,
        ),
        "prepare_append_only_conflict": (
            PublicationPhase.CREATED.value,
            PublicationPhase.ABORT_PENDING.value,
        ),
        "stage": (PublicationPhase.PREPARED.value, PublicationPhase.STAGED.value),
        "seal": (PublicationPhase.STAGED.value, PublicationPhase.SEALED.value),
        "close_compliance": (
            PublicationPhase.SEALED.value,
            PublicationPhase.COMPLIANCE_CLOSED.value,
        ),
        "promote": (
            PublicationPhase.COMPLIANCE_CLOSED.value,
            PublicationPhase.PROMOTED.value,
        ),
        "recover_promote": (
            PublicationPhase.COMPLIANCE_CLOSED.value,
            PublicationPhase.PROMOTED.value,
        ),
        "promote_target_conflict": (
            PublicationPhase.COMPLIANCE_CLOSED.value,
            PublicationPhase.ABORT_PENDING.value,
        ),
        "promote_rejected": (
            PublicationPhase.COMPLIANCE_CLOSED.value,
            PublicationPhase.ABORT_PENDING.value,
        ),
        "commit_history_validation": (
            PublicationPhase.PROMOTED.value,
            PublicationPhase.PROMOTED.value,
        ),
        "commit": (PublicationPhase.PROMOTED.value, PublicationPhase.COMMITTED.value),
        "recover_commit": (
            PublicationPhase.PROMOTED.value,
            PublicationPhase.COMMITTED.value,
        ),
        "abort_cleanup": (
            PublicationPhase.ABORT_PENDING.value,
            PublicationPhase.ABORT_PENDING.value,
        ),
        "abort": (PublicationPhase.ABORT_PENDING.value, PublicationPhase.ABORTED.value),
    }
    if action == "abort_pending":
        allowed_sources = {
            phase.value
            for phase in _NORMAL_PHASES
            if phase not in {PublicationPhase.PROMOTED, PublicationPhase.COMMITTED}
        }
        if (
            from_phase not in allowed_sources
            or to_phase != PublicationPhase.ABORT_PENDING.value
        ):
            raise StateCorruptionError(
                "publication event contains an invalid abort transition"
            )
        return
    expected = exact_transitions.get(action)
    if expected is None or expected != (from_phase, to_phase):
        raise StateCorruptionError(
            "publication event contains an invalid state transition"
        )
