"""Stable transport facade over independently bounded implementation modules."""

from __future__ import annotations

import os  # noqa: F401
import pathlib

from .session_shards_relay import (  # noqa: F401
    MAX_SESSION_SHARDS_RECORD_DATA_FRAMES,
    RemoteSessionShardsFilter,
    remote_output_limit as _session_shards_remote_output_limit,
)
from .transport_auth import (  # noqa: F401
    issue_transport_lease,
    issue_transport_receipt,
    verify_transport_lease,
    verify_transport_receipt,
)
from .transport_capture import (  # noqa: F401
    _source_transport_validation_lease,
    _validate_source_transport_relay,
    capture_source_transport,
)
from .transport_contracts import (  # noqa: F401
    _AUTH_RE,
    _LOCATOR_RE,
    _REASON_RE,
    _RECEIPT_REF_RE,
    _SHA256_RE,
    _SNAPSHOT_REF_RE,
    _TOKEN_RE,
    SOURCE_SNAPSHOT_REF_PREFIX,
    SOURCE_SNAPSHOT_SCHEMA,
    SOURCE_TRANSPORT_BOUNDARY_PROBE_BYTES,
    SOURCE_TRANSPORT_MAX_RECORD_BYTES,
    SOURCE_TRANSPORT_PROGRAM_MODULE_ALLOWLIST,
    SOURCE_TRANSPORT_RESUME_SCHEMA,
    SOURCE_TRANSPORT_SCAN_CHUNK_BYTES,
    SOURCE_TRANSPORT_STREAM_SCHEMA,
    TRANSPORT_LEASE_AUTH_PREFIX,
    TRANSPORT_LEASE_SCHEMA,
    TRANSPORT_RECEIPT_REF_PREFIX,
    TRANSPORT_RECEIPT_SCHEMA,
    AuthoritativeSourceSnapshot,
    CapturedSourceRecord,
    SourceTransportCapture,
    TransportLease,
    TransportReceipt,
    TransportValidationError,
    _bounded_token,
    _BoundedLine,
    _canonical_commitment,
    _exact_keys,
    _non_negative_int,
    _normalize_source_resume_position,
    _positive_int,
    _read_bounded_line,
    _reject_stream_constant,
    _sha256,
    _source_transport_inventory_commitment,
    _stream_frame,
    _stream_object,
    transcript_commitment,
)
from .transport_paths import (  # noqa: F401
    ACTIVE_ROLLOUT_RELATIVE_RE,
    ARCHIVED_ROLLOUT_RELATIVE_RE,
    ROOT_ROLLOUT_RELATIVE_RE,
    _resolve_rollout_relative_path,
)
from .transport_program import (  # noqa: F401
    SOURCE_TRANSPORT_MAX_PROGRAM_COMPONENT_BYTES,
    SOURCE_TRANSPORT_PYTHON_FLAGS,
    SOURCE_TRANSPORT_WORKER_MODULE_MANIFEST,
    _package_program_components,
    _program_component,
    _program_component_at,
    _program_stat_identity,
    source_transport_python_flags,
    transport_program_commitment,
)
from .transport_remote_snapshot import snapshot_remote_host_context_helper  # noqa: F401
from .transport_remote import (  # noqa: F401
    REMOTE_HOST_CONTEXT_COMMAND_TIMEOUT_SECONDS,
    REMOTE_HOST_CONTEXT_HELPER_RELATIVE_PATH,
    _relay_remote_host_context_command,
    _relay_valid_utf8,
    _remote_host_context_command,
    _remote_host_context_environment,
    remote_host_context_helper_commitment,
    remote_host_context_helper_path,
)
from .transport_resume import (  # noqa: F401
    _source_transport_boundary_probe,
    _source_transport_candidate_token,
    _source_transport_range_digest,
    decode_source_resume_position,
    encode_source_resume_position,
)
from .transport_session_shards import (  # noqa: F401
    DEFAULT_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
    DEFAULT_SESSION_SHARD_BYTES,
    DEFAULT_SESSION_SHARDS_PER_PAGE,
    HARD_SESSION_RECORD_PROCESSING_CEILING_BYTES,
    MAX_SESSION_SHARD_BYTES,
    MAX_SESSION_SHARDS_FRAME_CHARS,
    MAX_SESSION_SHARDS_PER_PAGE,
    MAX_SESSION_SHARDS_RANGE_BYTES,
    MIN_SESSION_RECORD_PROCESSING_BUDGET_BYTES,
    SESSION_SHARDS_FRAME_METADATA_CHARS,
    SESSION_SHARDS_JSON_VALIDATION_CHUNK_BYTES,
    SESSION_SHARDS_MAX_JSON_NESTING_DEPTH,
    SESSION_SHARDS_PROTOCOL_FEATURES,
    SESSION_SHARDS_RECORD_FRAGMENT_BYTES,
    SESSION_SHARDS_RECORD_SCAN_CHUNK_BYTES,
    SESSION_SHARDS_RECORD_SPOOL_MEMORY_BYTES,
    SESSION_SHARDS_REQUEST_BINDING_PREFIX,
    SESSION_SHARDS_RESUME_CURSOR_PREFIX,
    SESSION_SHARDS_SCHEMA,
    SESSION_SHARDS_SOURCE_TOKEN_PREFIX,
    SessionShardRecord,
    _IncrementalJSONObjectValidator,
    _iter_local_session_shard_frames,
    _iter_session_record_transport_frames,
    _iter_session_shard_descriptors,
    _iter_session_shard_records,
    _session_shards_content_commitment,
    _session_shards_decode_resume_cursor,
    _session_shards_parse_resume_cursor,
    _session_shards_processing_gap_metadata,
    _session_shards_remote_arguments,
    _session_shards_request_binding,
    _session_shards_resume_cursor,
    _session_shards_source_identity,
    _session_shards_source_identity_bytes,
    _session_shards_source_token,
    _SessionShardsProcessingBudgetExceeded,
    _validate_session_shards_boundary,
    _validate_session_shards_json_storage,
)
from .transport_session_shards import (
    _open_session_shard_source as _open_session_shard_source_impl,
)
from .transport_session_shards import (
    cmd_session_shards as _cmd_session_shards,
)
from .transport_source import (  # noqa: F401
    SOURCE_TRANSPORT_MIN_FRAME_BYTES,
    _AnchoredCodexRoot,
    _emit_source_transport_frame,
    _emit_source_transport_gap,
    _local_codex_root,
    _open_lexical_codex_root,
    _open_relative_from_codex_root,
    _open_source_transport_candidate,
    _open_source_transport_path,
    _resolve_safe_codex_root,
    _safe_relative_path,
    _safe_rollout_path,
    _source_inventory_row,
    _source_record_session_identifiers,
    _source_structural_exclusion,
    _source_transport_candidate_paths,
    _source_transport_discovery_commitment,
    _source_transport_header,
    _source_transport_instant,
    _source_transport_json_bytes,
    _source_transport_remote_arguments,
    _source_transport_scan,
    _SourceCandidateDiscovery,
    _window_dates,
    session_selector_commitment,
)

TRANSPORT_REMOTE_HELPER_CONTRACT = (
    ".codex/skills/remote-host-context/scripts/remote_codex_probe.py"
)


def _open_session_shard_source(
    codex_root: pathlib.Path,
    rollout_relative_path: pathlib.PurePosixPath,
    *,
    component_hook=None,
):
    return _open_session_shard_source_impl(
        codex_root,
        rollout_relative_path,
        component_hook=(
            component_hook or globals().get("_SESSION_SHARDS_OPEN_COMPONENT_HOOK")
        ),
    )


def cmd_session_shards(args):
    return _cmd_session_shards(
        args,
        codex_root=_local_codex_root(),
        component_hook=globals().get("_SESSION_SHARDS_OPEN_COMPONENT_HOOK"),
        source_identity_reader=_session_shards_source_identity,
        source_opener=_open_session_shard_source,
        relay_command=_relay_remote_host_context_command,
        max_range_bytes=MAX_SESSION_SHARDS_RANGE_BYTES,
    )
