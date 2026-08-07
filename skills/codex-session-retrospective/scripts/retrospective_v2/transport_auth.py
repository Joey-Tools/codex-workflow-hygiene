"""Identity-backed issuance and verification for transport contracts."""

from __future__ import annotations

from dataclasses import replace
import hmac
from typing import Mapping, Sequence

from .contracts import JsonValue, SourceKind
from .identity import IdentityKey
from .transport_contracts import (
    TRANSPORT_LEASE_AUTH_PREFIX,
    TRANSPORT_RECEIPT_REF_PREFIX,
    AuthoritativeSourceSnapshot,
    TransportLease,
    TransportReceipt,
    TransportValidationError,
    _canonical_commitment,
)


def issue_transport_lease(
    identity: IdentityKey,
    *,
    lease_ref: str,
    run_ref: str,
    job_ref: str,
    host: str,
    host_ref: str,
    source_kind: SourceKind | str,
    window_start: str,
    window_end: str,
    process_nonce: str,
    command_argv: Sequence[str],
    transport_program_commitment: str,
    source_byte_limit: int,
    record_limit: int,
    frame_byte_limit: int,
    session_target: str | None,
    session_selector_commitment: str | None = None,
    source_cursor: str | None,
    cursor_time: str | None,
    resume_position: Mapping[str, object] | None = None,
) -> TransportLease:
    placeholder = TRANSPORT_LEASE_AUTH_PREFIX + "0" * 64
    lease = TransportLease(
        lease_ref=lease_ref,
        run_ref=run_ref,
        job_ref=job_ref,
        host=host,
        host_ref=host_ref,
        source_kind=source_kind,
        window_start=window_start,
        window_end=window_end,
        process_nonce=process_nonce,
        command_argv=tuple(command_argv),
        transport_program_commitment=transport_program_commitment,
        source_byte_limit=source_byte_limit,
        record_limit=record_limit,
        frame_byte_limit=frame_byte_limit,
        session_target=session_target,
        session_selector_commitment=session_selector_commitment,
        source_cursor=source_cursor,
        cursor_time=cursor_time,
        resume_position=resume_position,
        authentication_tag=placeholder,
    )
    tag = TRANSPORT_LEASE_AUTH_PREFIX + identity.derive_digest(
        "source-transport-lease/v2", lease.unsigned_dict()
    )
    return replace(lease, authentication_tag=tag)


def verify_transport_lease(identity: IdentityKey, lease: TransportLease) -> None:
    expected = TRANSPORT_LEASE_AUTH_PREFIX + identity.derive_digest(
        "source-transport-lease/v2", lease.unsigned_dict()
    )
    if not hmac.compare_digest(expected, lease.authentication_tag):
        raise TransportValidationError("transport lease authentication failed")


def issue_transport_receipt(
    identity: IdentityKey,
    *,
    lease: TransportLease,
    manifest: Mapping[str, JsonValue],
    source_snapshot: AuthoritativeSourceSnapshot,
) -> TransportReceipt:
    verify_transport_lease(identity, lease)
    placeholder = TRANSPORT_RECEIPT_REF_PREFIX + "0" * 64
    receipt = TransportReceipt(
        receipt_ref=placeholder,
        lease_ref=lease.lease_ref,
        lease_authentication_tag=lease.authentication_tag,
        lease_binding=lease.binding,
        manifest_commitment=_canonical_commitment(dict(manifest)),
        source_snapshot=source_snapshot,
    )
    digest = identity.derive_digest(
        "source-transport-receipt/v2", receipt.unsigned_dict()
    )
    return replace(receipt, receipt_ref=TRANSPORT_RECEIPT_REF_PREFIX + digest)


def verify_transport_receipt(
    identity: IdentityKey,
    *,
    lease: TransportLease,
    manifest: Mapping[str, JsonValue],
    receipt: TransportReceipt,
) -> AuthoritativeSourceSnapshot:
    verify_transport_lease(identity, lease)
    expected = issue_transport_receipt(
        identity,
        lease=lease,
        manifest=manifest,
        source_snapshot=receipt.source_snapshot,
    )
    if not hmac.compare_digest(expected.receipt_ref, receipt.receipt_ref):
        raise TransportValidationError("transport receipt authentication failed")
    if receipt.lease_ref != lease.lease_ref or receipt.lease_binding != lease.binding:
        raise TransportValidationError("transport receipt is not bound to the lease")
    if not hmac.compare_digest(
        receipt.lease_authentication_tag, lease.authentication_tag
    ):
        raise TransportValidationError("transport receipt lease authentication changed")
    manifest_commitment = _canonical_commitment(dict(manifest))
    if not hmac.compare_digest(receipt.manifest_commitment, manifest_commitment):
        raise TransportValidationError(
            "transport receipt is not bound to the accepted manifest"
        )
    snapshot = receipt.source_snapshot
    if (
        snapshot.host_ref != lease.host_ref
        or snapshot.source_kind is not lease.source_kind
        or snapshot.window_start != lease.window_start
        or snapshot.window_end != lease.window_end
        or snapshot.session_target != lease.session_target
    ):
        raise TransportValidationError(
            "transport receipt source snapshot is not bound to the lease"
        )
    return snapshot
