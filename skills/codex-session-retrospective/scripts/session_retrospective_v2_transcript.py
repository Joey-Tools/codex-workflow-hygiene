"""Bounded two-pass validation for retained session-shards transcripts."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

from retrospective_v2.contracts import SessionShardsRequest
from retrospective_v2 import session_shards_adapter as adapter


FrameFactory = Callable[[], Iterable[Mapping[str, Any]]]
TranscriptSegment = tuple[Iterable[Mapping[str, Any]], SessionShardsRequest]


class SessionShardsTranscriptError(ValueError):
    """A closed transcript-stage failure safe for CLI translation."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage


def _next_stream(frames: Any) -> Iterator[dict[str, Any]] | None:
    try:
        first = dict(next(frames))
    except StopIteration:
        return None

    def stream() -> Iterator[dict[str, Any]]:
        frame = first
        while True:
            yield frame
            if frame.get("kind") == "stream_end":
                return
            try:
                frame = dict(next(frames))
            except StopIteration as error:
                raise adapter.SessionShardsAdapterError(
                    "session-shards stream is truncated"
                ) from error

    return stream()


def _descriptor_plan(
    frames: Iterable[Mapping[str, Any]],
    *,
    expected_host: str,
) -> adapter.SessionShardsDescriptorPlan:
    return adapter.descriptor_plan_from_frames(
        frames,
        expected_host=expected_host,
    )


def session_shard_transcript(
    frame_factory: FrameFactory,
    *,
    expected_host: str,
) -> Iterable[TranscriptSegment]:
    """Validate descriptor pages, then lazily replay their record segments."""

    frames = iter(frame_factory())
    plans: list[adapter.SessionShardsDescriptorPlan] = []
    expected_request: SessionShardsRequest | None = None
    try:
        while True:
            descriptor_stream = _next_stream(frames)
            if descriptor_stream is None:
                raise adapter.SessionShardsAdapterError(
                    "session-shards descriptor chain is empty"
                )
            plan = _descriptor_plan(
                descriptor_stream,
                expected_host=expected_host,
            )
            if (
                expected_request is not None
                and plan.descriptor_request != expected_request
            ):
                raise adapter.SessionShardsAdapterError(
                    "session-shards descriptor continuation request changed"
                )
            plans.append(plan)
            if plan.complete:
                break
            if plan.next_descriptor_request is None:
                raise adapter.SessionShardsAdapterError(
                    "session-shards descriptor chain lost its continuation"
                )
            expected_request = plan.next_descriptor_request
    except adapter.SessionShardsAdapterError as error:
        raise SessionShardsTranscriptError("descriptors", str(error)) from error
    finally:
        close = getattr(frames, "close", None)
        if callable(close):
            close()
    if not any(plan.records_request is not None for plan in plans):
        raise SessionShardsTranscriptError(
            "empty",
            "session-shards input has no materialized records",
        )

    def transcript_segments() -> Iterable[TranscriptSegment]:
        replay_frames: Any | None = None

        def close_replay() -> None:
            nonlocal replay_frames
            if replay_frames is None:
                return
            close = getattr(replay_frames, "close", None)
            replay_frames = None
            if callable(close):
                close()

        def initialized_replay() -> Any:
            nonlocal replay_frames
            if replay_frames is not None:
                return replay_frames
            replay_frames = iter(frame_factory())
            for expected_plan in plans:
                descriptor_stream = _next_stream(replay_frames)
                if (
                    descriptor_stream is None
                    or _descriptor_plan(
                        descriptor_stream,
                        expected_host=expected_host,
                    )
                    != expected_plan
                ):
                    raise adapter.SessionShardsAdapterError(
                        "session-shards descriptor chain changed after validation"
                    )
            return replay_frames

        def record_stream(
            request: SessionShardsRequest,
            consumption: dict[str, bool],
        ) -> Iterable[Mapping[str, Any]]:
            try:
                replay = initialized_replay()
                stream = _next_stream(replay)
                if stream is None:
                    raise adapter.SessionShardsAdapterError(
                        "session-shards records stream is missing"
                    )
                yield from adapter.normalize_record_frames(
                    stream,
                    expected_host=expected_host,
                    expected_rollout=request.rollout,
                )
                consumption["complete"] = True
            except adapter.SessionShardsAdapterError as error:
                close_replay()
                raise SessionShardsTranscriptError("records", str(error)) from error
            finally:
                if not consumption["complete"]:
                    close_replay()

        try:
            for plan in plans:
                request = plan.records_request
                if request is None:
                    continue
                consumption = {"complete": False}
                yield record_stream(request, consumption), request
                if not consumption["complete"]:
                    raise adapter.SessionShardsAdapterError(
                        "session-shards records stream was not fully consumed"
                    )
            replay_frames = initialized_replay()
            try:
                next(replay_frames)
            except StopIteration:
                return
            raise adapter.SessionShardsAdapterError(
                "session-shards transcript contains trailing frames"
            )
        except adapter.SessionShardsAdapterError as error:
            raise SessionShardsTranscriptError("records", str(error)) from error
        finally:
            close_replay()

    return transcript_segments()
