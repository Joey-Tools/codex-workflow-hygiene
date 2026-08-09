from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "codex-session-retrospective"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS))

import retrospective_v2.result_validation as result_validation_module  # noqa: E402
import retrospective_v2.source_overlap as source_overlap_module  # noqa: E402
from retrospective_v2.episode_review import (  # noqa: E402
    construct_episodes,
    create_episode_revision,
    derive_corrected_episode_ref,
    derive_episode_correction_generation,
    derive_episode_meaningfulness,
    material_review_conflict,
    plan_episode_review_jobs,
)
from retrospective_v2.contracts import JobKind  # noqa: E402
from retrospective_v2.identity import IdentityKey  # noqa: E402
from retrospective_v2.result_validation import (  # noqa: E402
    ADJUDICATION_RESULT_SCHEMA,
    EPISODE_REVIEW_RESULT_SCHEMA,
    EXTRACTOR_RESULT_SCHEMA,
    QUESTION_IDS,
    SYNTHESIS_RESULT_SCHEMA,
    TOPIC_INPUT_SCHEMA,
    TOPIC_RESULT_SCHEMA,
    ResultValidationError,
    build_synthesis_signal_exemplars,
    build_synthesis_signal_commitments,
    build_topic_result,
    canonical_result_hash,
    scan_for_leaks,
    validate_adjudication_result,
    validate_episode_review_result,
    validate_extractor_result,
    validate_hierarchical_episode_review_result,
    validate_synthesis_result,
    validate_topic_input,
    validate_topic_result,
)


def ref(kind: str, marker: str) -> str:
    digest = hashlib.sha256(f"{kind}:{marker}".encode("ascii")).hexdigest()
    return f"{kind}_ref_v2:{digest}"


SESSION_A = ref("session", "a")
SESSION_B = ref("session", "b")
TURN_A = ref("turn", "c")
TURN_B = ref("turn", "d")
TURN_C = ref("turn", "e")
SOURCE = ref("source_unit", "f")
EVIDENCE_A = ref("evidence", "g")
EVIDENCE_B = ref("evidence", "h")
SPAN_A = ref("span_commitment", "i")
SPAN_B = ref("span_commitment", "j")
GOAL_A = ref("goal", "k")
GOAL_B = ref("goal", "l")
WORKSTREAM_A = ref("workstream", "m")
WORKSTREAM_B = ref("workstream", "n")
EPISODE = ref("episode", "o")
REVISION_A = ref("episode_revision", "p")
REVISION_B = ref("episode_revision", "q")
TOPIC = ref("topic", "r")
TOPIC_CANDIDATE = ref("topic_candidate", "candidate")
MODEL = ref("model_configuration", "s")
EPISODE_B = ref("episode", "second")
ATTEMPT_PRIMARY = ref("attempt", "primary")
ATTEMPT_SECONDARY = ref("attempt", "secondary")
REVIEWER_PRIMARY = ref("reviewer", "primary")
REVIEWER_SECONDARY = ref("reviewer", "secondary")

ALL_REFS = {
    SESSION_A,
    SESSION_B,
    TURN_A,
    TURN_B,
    TURN_C,
    SOURCE,
    EVIDENCE_A,
    EVIDENCE_B,
    SPAN_A,
    SPAN_B,
    GOAL_A,
    GOAL_B,
    WORKSTREAM_A,
    WORKSTREAM_B,
    EPISODE,
    REVISION_A,
    REVISION_B,
    TOPIC,
    TOPIC_CANDIDATE,
    MODEL,
    EPISODE_B,
    ATTEMPT_PRIMARY,
    ATTEMPT_SECONDARY,
    REVIEWER_PRIMARY,
    REVIEWER_SECONDARY,
}


def signal(kind: str, evidence_ref: str = EVIDENCE_A) -> dict:
    return {"kind": kind, "evidence_refs": [evidence_ref], "confidence": "high"}


def extractor_result() -> dict:
    return {
        "schema": EXTRACTOR_RESULT_SCHEMA,
        "source_unit_ref": SOURCE,
        "turns": [
            {
                "turn_ref": TURN_A,
                "generalized_working_text": "A bounded verification completed.",
                "events": [signal("verification_completed")],
                "findings": [],
                "strengths": [signal("complete_verification")],
                "risk_flags": [],
                "outcome": "completed",
                "confidence": "high",
                "evidence_refs": [EVIDENCE_A],
                "span_commitments": [SPAN_A],
                "goal_ref": GOAL_A,
                "workstream_ref": WORKSTREAM_A,
                "goal_change": "continues",
                "workstream_change": False,
                "task_completed": False,
                "user_redirect": False,
                "meaningfulness_hint": "meaningful",
                "conflicting_signals": False,
            }
        ],
    }


def high_impact(turn_ref: str = TURN_A) -> dict:
    return {
        "turn_ref": turn_ref,
        "problem_statement": "The request left a destructive operation ambiguous.",
        "cause": "The desired recovery boundary was not explicit.",
        "rewritten_prompt": "Inspect state first and require confirmation before destructive changes.",
        "expected_effect": "The operation remains reversible until intent is confirmed.",
        "evidence_refs": [EVIDENCE_A],
        "confidence": "high",
        "severity": "high",
    }


def adjudication_item_decisions(
    candidates: list[dict], adjudication: dict
) -> list[dict]:
    fields = (
        "events",
        "findings",
        "strengths",
        "risk_flags",
        "high_impact_turns",
        "evidence_refs",
    )

    def canonical(value: object) -> str:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    rows = []
    for candidate in candidates:
        candidate_hash = canonical_result_hash(candidate)
        for field in fields:
            retained = {canonical(item) for item in adjudication[field]}
            for item in candidate[field]:
                item_value = canonical(item)
                duplicate = (
                    sum(
                        item_value
                        in {canonical(other) for other in other_candidate[field]}
                        for other_candidate in candidates
                    )
                    > 1
                )
                is_retained = item_value in retained
                rows.append(
                    {
                        "attempt_ref": candidate["attempt_ref"],
                        "candidate_result_hash": candidate_hash,
                        "disposition": (
                            "merged"
                            if is_retained and duplicate
                            else "selected"
                            if is_retained
                            else "rejected"
                        ),
                        "field": field,
                        "item_hash": hashlib.sha256(
                            item_value.encode("utf-8")
                        ).hexdigest(),
                        "reason": (
                            "duplicate_supported"
                            if is_retained and duplicate
                            else "retained_supported"
                            if is_retained
                            else "lower_confidence"
                        ),
                        "reviewer_ref": candidate["reviewer_ref"],
                        "reviewer_slot": candidate["reviewer_slot"],
                    }
                )
    return rows


def episode_review(
    *,
    episode_ref: str = EPISODE,
    revision_ref: str = REVISION_A,
    reviewer_slot: str = "primary",
    findings: list[dict] | None = None,
    risks: list[str] | None = None,
    high_impact_turns: list[dict] | None = None,
    attempt_ref: str | None = None,
    reviewer_ref: str | None = None,
) -> dict:
    if attempt_ref is None:
        attempt_ref = (
            ATTEMPT_PRIMARY if reviewer_slot == "primary" else ATTEMPT_SECONDARY
        )
    if reviewer_ref is None:
        reviewer_ref = (
            REVIEWER_PRIMARY if reviewer_slot == "primary" else REVIEWER_SECONDARY
        )
    return {
        "schema": EPISODE_REVIEW_RESULT_SCHEMA,
        "episode_ref": episode_ref,
        "episode_revision_ref": revision_ref,
        "disposition": "reviewed",
        "events": [signal("verification_completed")],
        "findings": [] if findings is None else findings,
        "strengths": [signal("complete_verification")],
        "risk_flags": [] if risks is None else risks,
        "high_impact_turns": [] if high_impact_turns is None else high_impact_turns,
        "evidence_refs": [EVIDENCE_A],
        "confidence": "high",
        "reviewer_slot": reviewer_slot,
        "attempt_ref": attempt_ref,
        "reviewer_ref": reviewer_ref,
        "second_review_recommended": False,
        "conflicting_signals": False,
    }


def episode_review_gap(
    *,
    episode_ref: str,
    revision_ref: str,
    reviewer_slot: str,
    gap_reason: str = "review_failure",
) -> dict:
    result = episode_review(
        episode_ref=episode_ref,
        revision_ref=revision_ref,
        reviewer_slot=reviewer_slot,
    )
    result.update(
        {
            "disposition": "review_gap",
            "events": [],
            "findings": [],
            "strengths": [],
            "risk_flags": [],
            "high_impact_turns": [],
            "evidence_refs": [],
            "confidence": "low",
            "gap_reason": gap_reason,
        }
    )
    return result


def turn(
    turn_ref: str,
    *,
    session_ref: str = SESSION_A,
    timestamp: str,
    goal_ref: str = GOAL_A,
    workstream_ref: str = WORKSTREAM_A,
    meaningfulness: str = "meaningful",
    sequence: int = 0,
    **overrides: object,
) -> dict:
    row = {
        "turn_ref": turn_ref,
        "session_ref": session_ref,
        "canonical_time": timestamp,
        "sequence": sequence,
        "goal_ref": goal_ref,
        "workstream_ref": workstream_ref,
        "meaningfulness": meaningfulness,
        "risk_flags": [],
        "confidence": "high",
    }
    row.update(overrides)
    return row


def synthesis_result() -> dict:
    return {
        "schema": SYNTHESIS_RESULT_SCHEMA,
        "question_answers": [
            {
                "question_id": question_id,
                "disposition": "not_observed",
                "event_kinds": [],
                "finding_kinds": [],
                "strength_kinds": [],
                "evidence_refs": [],
                "confidence": "high",
            }
            for question_id in QUESTION_IDS
        ],
        "events": [],
        "findings": [],
        "strengths": [],
        "prompt_rewrites": [],
        "guidance_candidates": [],
        "skill_candidates": [],
        "signal_commitments": build_synthesis_signal_commitments(()),
        "follow_up_actions": [],
        "confidence": {
            "coverage": "high",
            "extraction": "high",
            "review": "high",
            "comparability": "high",
        },
        "evidence_refs": [],
        "era_comparison": {"status": "compatible", "change": "unchanged"},
        "topic_result_hashes": [],
    }


class ResultValidationTests(unittest.TestCase):
    def test_source_overlap_windows_preserve_normalized_boundaries(self) -> None:
        phrase = "cross window phrase"
        source = "AA  " + "x" * 10 + phrase.upper() + "y" * 20
        payload = json.dumps({"content": source}, separators=(",", ":"))
        windows = list(
            source_overlap_module.json_string_value_batches(
                (payload[:13], payload[13:31], payload[31:]),
                query_chars=len(phrase),
                maximum_batch_chars=24,
                maximum_batch_items=2,
            )
        )

        self.assertTrue(windows)
        self.assertTrue(all(len(batch) == 1 for batch in windows))
        self.assertTrue(all(len(batch[0]) == 24 for batch in windows))
        self.assertTrue(any(phrase in batch[0] for batch in windows))
        self.assertTrue(
            any(window.startswith("aa x") for batch in windows for window in batch)
        )

    def test_json_value_batches_skip_keys_and_bound_memory(self) -> None:
        long_key = "never-retain-this-key-" * 3
        batches = list(
            source_overlap_module.json_string_value_batches(
                (
                    '{"role":"us',
                    f'er","{long_key}":"Acme","escaped":"line\\nvalue",',
                    '"oversized":"xxxxxxxxxxxxxxxx","unicode":"\\ud83d\\ude00",'
                    '"status":"complete","session_id":"session-value"}',
                ),
                query_chars=4,
                maximum_batch_chars=20,
                maximum_batch_items=2,
            )
        )
        values = [value for batch in batches for value in batch]

        self.assertNotIn("user", values)
        self.assertIn("acme", values)
        self.assertIn("line value", values)
        self.assertIn("😀", values)
        self.assertNotIn("complete", values)
        self.assertIn("session-value", values)
        self.assertNotIn("role", values)
        self.assertFalse(any("never-retain" in value for value in values))
        self.assertTrue(any(value == "x" * 16 for value in values))
        self.assertTrue(all(len(batch) <= 2 for batch in batches))
        self.assertTrue(all(sum(map(len, batch)) <= 20 for batch in batches))

        whitespace_dense = list(
            source_overlap_module.json_string_value_batches(
                ('{"content":"                        x"}',),
                query_chars=4,
                maximum_batch_chars=8,
                maximum_batch_items=2,
            )
        )
        self.assertEqual([("x",)], whitespace_dense)
        with self.assertRaisesRegex(ValueError, "unbalanced"):
            list(
                source_overlap_module.json_string_value_batches(
                    ('{"content":"safe",}',),
                    query_chars=4,
                    maximum_batch_chars=8,
                    maximum_batch_items=2,
                )
            )

        malformed_primitives = (
            '{"content":oops"secret"}',
            '{"content":tru,"next":"secret"}',
            '{"content":01,"next":"secret"}',
            '{"content":1.,"next":"secret"}',
            '{"content":1e+,"next":"secret"}',
        )
        for payload in malformed_primitives:
            with (
                self.subTest(payload=payload),
                self.assertRaisesRegex(
                    ValueError,
                    "primitive",
                ),
            ):
                list(
                    source_overlap_module.json_string_value_batches(
                        (payload,),
                        query_chars=4,
                        maximum_batch_chars=16,
                        maximum_batch_items=2,
                    )
                )

    def test_normalized_windows_batch_single_character_parser_feeds(self) -> None:
        class CountingWindows(source_overlap_module._NormalizedValueWindows):
            __slots__ = ("append_calls",)

            def __init__(self, **kwargs: int) -> None:
                super().__init__(**kwargs)
                self.append_calls = 0

            def _append_chunk(self, value: str) -> list[str]:
                self.append_calls += 1
                return super()._append_chunk(value)

        maximum_chars = result_validation_module.MAX_SOURCE_OVERLAP_CHARS
        source_chars = maximum_chars * 2
        windows = CountingWindows(query_chars=4, maximum_chars=maximum_chars)
        emitted = 0

        for _ in range(source_chars):
            emitted += len(windows.feed("x"))
        emitted += len(windows.finish())

        maximum_chunk_appends = source_chars // min(8_192, maximum_chars) + 2
        self.assertLessEqual(windows.append_calls, maximum_chunk_appends)
        self.assertGreaterEqual(emitted, 2)
        self.assertLess(windows._buffered_chars, maximum_chars)
        self.assertEqual(0, windows._pending_chars)
        self.assertLessEqual(
            len(windows._chunks),
            maximum_chars // min(8_192, maximum_chars) + 1,
        )

    def test_source_overlap_excludes_safe_metadata_but_keeps_instance_values(
        self,
    ) -> None:
        batches = list(
            source_overlap_module.json_string_value_batches(
                ('{"role":"user","content":"Acme"}',),
                query_chars=4,
                maximum_batch_chars=16,
                maximum_batch_items=2,
            )
        )
        candidates = [candidate for batch in batches for candidate in batch]

        self.assertEqual(["acme"], candidates)
        self.assertEqual(
            (), scan_for_leaks({"safe": "user"}, original_prompts=candidates)
        )
        self.assertTrue(scan_for_leaks({"unsafe": "Acme"}, original_prompts=candidates))
        self.assertTrue(
            scan_for_leaks(
                {"unsafe": "Acme rollout failed"},
                original_prompts=candidates,
            )
        )
        self.assertEqual(
            (),
            scan_for_leaks(
                {"safe": "Acmeology rollout failed"},
                original_prompts=candidates,
            ),
        )

        embedded = extractor_result()
        embedded["turns"][0]["generalized_working_text"] = "Acme rollout failed"
        validated = validate_extractor_result(
            embedded,
            ALL_REFS,
            original_prompts=candidates,
        )
        self.assertEqual(
            "[REDACTED_ORIGINAL_PROMPT] rollout failed",
            validated["turns"][0]["generalized_working_text"],
        )

        nested_control_batches = list(
            source_overlap_module.json_string_value_batches(
                (
                    '{"request_id":{"content":"Nested secret"},'
                    '"evidence_ref":["Array secret"]}',
                ),
                query_chars=4,
                maximum_batch_chars=32,
                maximum_batch_items=2,
            )
        )
        nested_control_candidates = [
            candidate for batch in nested_control_batches for candidate in batch
        ]

        self.assertIn("nested secret", nested_control_candidates)
        self.assertIn("array secret", nested_control_candidates)
        self.assertTrue(
            scan_for_leaks(
                {"unsafe": "Nested secret"},
                original_prompts=nested_control_candidates,
            )
        )

        untrusted_suffix_batches = list(
            source_overlap_module.json_string_value_batches(
                (
                    '{"customer_ref":"Discuss frosted meadow launch carefully",'
                    '"session_id":"valid-session",'
                    '"timestamp":"2026-07-06T01:00:00Z",'
                    '"STATUS":"uppercase-secret",'
                    '"\\u017ftatus":"unicode-secret",'
                    '"created_at":"2026-99-01T01:00:00Z",'
                    '"started_at":"2026-01-01T99:00:00Z",'
                    '"updated_at":"2026-01-01T01:00:00+99:00",'
                    '"completed_at":"2025-02-29T01:00:00Z",'
                    '"request_id":"Raw prompt hidden as a request id"}',
                ),
                query_chars=8,
                maximum_batch_chars=64,
                maximum_batch_items=4,
            )
        )
        untrusted_suffix_candidates = [
            candidate for batch in untrusted_suffix_batches for candidate in batch
        ]

        self.assertIn(
            "discuss frosted meadow launch carefully",
            untrusted_suffix_candidates,
        )
        self.assertIn(
            "raw prompt hidden as a request id",
            untrusted_suffix_candidates,
        )
        self.assertIn("valid-session", untrusted_suffix_candidates)
        self.assertNotIn("2026-07-06t01:00:00z", untrusted_suffix_candidates)
        self.assertIn("uppercase-secret", untrusted_suffix_candidates)
        self.assertIn("unicode-secret", untrusted_suffix_candidates)
        self.assertIn(
            "2026-99-01t01:00:00z",
            untrusted_suffix_candidates,
        )
        self.assertIn(
            "2026-01-01t99:00:00z",
            untrusted_suffix_candidates,
        )
        self.assertIn(
            "2026-01-01t01:00:00+99:00",
            untrusted_suffix_candidates,
        )
        self.assertIn(
            "2025-02-29t01:00:00z",
            untrusted_suffix_candidates,
        )
        self.assertTrue(
            scan_for_leaks(
                {"finding": "valid-session"},
                original_prompts=untrusted_suffix_candidates,
            )
        )

        instance_values = {
            "id": "customer-secret-42",
            "call_id": "call-secret-42",
            "event_id": "event-secret-42",
            "item_id": "item-secret-42",
            "request_id": "request-secret-42",
            "response_id": "response-secret-42",
            "session_id": "session-secret-42",
            "host": "private-host-42",
            "cwd": "/private/workspace-42",
            "attempt_ref": "attempt_ref_v2:" + "0" * 64,
            "bundle_digest": "sha256:" + "a" * 64,
        }
        instance_batches = list(
            source_overlap_module.json_string_value_batches(
                (json.dumps(instance_values, separators=(",", ":")),),
                query_chars=8,
                maximum_batch_chars=128,
                maximum_batch_items=8,
            )
        )
        instance_candidates = [
            candidate for batch in instance_batches for candidate in batch
        ]
        for value in instance_values.values():
            with self.subTest(value=value):
                self.assertIn(value.casefold(), instance_candidates)
        findings = scan_for_leaks(
            {"generalized_working_text": "customer-secret-42"},
            original_prompts=instance_candidates,
        )
        self.assertIn("original_prompt", {finding.category for finding in findings})
        attempt_ref = "attempt_ref_v2:" + "0" * 64
        unallowed_reference_findings = scan_for_leaks(
            {"attempt_ref": attempt_ref},
            original_prompts=instance_candidates,
        )
        self.assertIn(
            "original_prompt",
            {finding.category for finding in unallowed_reference_findings},
        )
        self.assertEqual(
            (),
            scan_for_leaks(
                {"attempt_ref": attempt_ref},
                original_prompts=instance_candidates,
                allowed_reference_values={attempt_ref},
            ),
        )
        malformed_reference_findings = scan_for_leaks(
            {"attempt_ref": "customer-secret-42"},
            original_prompts=instance_candidates,
        )
        self.assertIn(
            "original_prompt",
            {finding.category for finding in malformed_reference_findings},
        )

    def test_result_complexity_is_bounded_before_privacy_processing(self) -> None:
        value = extractor_result()
        value["turns"][0]["generalized_working_text"] = "x" * (
            result_validation_module.MAX_RESULT_STRING_CHARS + 1
        )

        with (
            mock.patch.object(
                result_validation_module,
                "_post_redact_text",
                side_effect=AssertionError("privacy processing started"),
            ),
            self.assertRaisesRegex(ResultValidationError, "must be at most 4096"),
        ):
            validate_extractor_result(value, ALL_REFS)

        with self.assertRaisesRegex(
            ResultValidationError,
            "source characters",
        ):
            scan_for_leaks(
                {"safe": "bounded"},
                original_prompts=[
                    "x" * (result_validation_module.MAX_SOURCE_OVERLAP_CHARS + 1)
                ],
            )

    def test_overlap_scan_preindexes_large_nonmatching_source(self) -> None:
        source = "".join(
            chr(0x400 + index % 1024)
            for index in range(result_validation_module.MAX_SOURCE_OVERLAP_CHARS)
        )
        with mock.patch.object(
            result_validation_module,
            "_build_source_overlap_index",
            wraps=result_validation_module._build_source_overlap_index,
        ) as build_index:
            findings = scan_for_leaks(
                {"safe": "z" * result_validation_module.MAX_RESULT_STRING_CHARS},
                original_prompts=[source],
            )

        self.assertEqual((), findings)
        self.assertEqual(2, build_index.call_count)

    def test_extractor_accepts_closed_structured_result(self) -> None:
        result = validate_extractor_result(extractor_result(), ALL_REFS)

        self.assertEqual(
            result["turns"][0]["events"][0]["kind"], "verification_completed"
        )
        self.assertEqual(scan_for_leaks(result), ())

    def test_extractor_binds_two_goal_and_workstream_pairs_per_turn(self) -> None:
        value = extractor_result()
        second = copy.deepcopy(value["turns"][0])
        second.update(
            {
                "turn_ref": TURN_B,
                "events": [signal("verification_completed", EVIDENCE_B)],
                "strengths": [signal("complete_verification", EVIDENCE_B)],
                "evidence_refs": [EVIDENCE_B],
                "span_commitments": [SPAN_B],
                "goal_ref": GOAL_B,
                "workstream_ref": WORKSTREAM_B,
            }
        )
        value["turns"].append(second)
        bindings = {
            TURN_A: {
                "evidence_refs": [EVIDENCE_A],
                "span_refs": [SPAN_A],
                "goal_ref": GOAL_A,
                "workstream_ref": WORKSTREAM_A,
            },
            TURN_B: {
                "evidence_refs": [EVIDENCE_B],
                "span_refs": [SPAN_B],
                "goal_ref": GOAL_B,
                "workstream_ref": WORKSTREAM_B,
            },
        }

        result = validate_extractor_result(
            value,
            ALL_REFS,
            turn_bindings=bindings,
        )

        self.assertEqual(
            [(turn["goal_ref"], turn["workstream_ref"]) for turn in result["turns"]],
            [(GOAL_A, WORKSTREAM_A), (GOAL_B, WORKSTREAM_B)],
        )

    def test_extractor_rejects_goal_or_workstream_from_shard_union(self) -> None:
        value = extractor_result()
        bindings = {
            TURN_A: {
                "evidence_refs": [EVIDENCE_A],
                "span_refs": [SPAN_A],
                "goal_ref": GOAL_A,
                "workstream_ref": WORKSTREAM_A,
            }
        }
        value["turns"][0]["goal_ref"] = GOAL_B

        with self.assertRaisesRegex(ResultValidationError, "allow-list"):
            validate_extractor_result(
                value,
                ALL_REFS,
                turn_bindings=bindings,
            )

        value["turns"][0]["goal_ref"] = GOAL_A
        value["turns"][0]["workstream_ref"] = WORKSTREAM_B
        with self.assertRaisesRegex(ResultValidationError, "allow-list"):
            validate_extractor_result(
                value,
                ALL_REFS,
                turn_bindings=bindings,
            )

    def test_post_redaction_removes_all_deterministic_leak_families(self) -> None:
        value = extractor_result()
        original_prompt = "Deploy the service with the emergency override."
        tool_output = "command failed with private diagnostic text"
        value["turns"][0]["generalized_working_text"] = (
            "token=abcdefgh12345678 at https://build.corp/run from "
            "/Users/operator/private/repo with id 550e8400-e29b-41d4-a716-446655440000. "
            f"Prompt: {original_prompt} Output: {tool_output}"
        )

        result = validate_extractor_result(
            value,
            ALL_REFS,
            original_prompts=[original_prompt],
            tool_outputs=[tool_output],
        )

        text = result["turns"][0]["generalized_working_text"]
        self.assertIn("[REDACTED_CREDENTIAL]", text)
        self.assertIn("[REDACTED_URL]", text)
        self.assertIn("[REDACTED_PATH]", text)
        self.assertIn("[REDACTED_RAW_ID]", text)
        self.assertIn("[REDACTED_ORIGINAL_PROMPT]", text)
        self.assertIn("[REDACTED_TOOL_OUTPUT]", text)
        self.assertEqual(
            scan_for_leaks(
                result, original_prompts=[original_prompt], tool_outputs=[tool_output]
            ),
            (),
        )

    def test_post_redaction_removes_non_http_uri_schemes(self) -> None:
        for uri in (
            "x://private-endpoint/resource",
            "wss://build.internal/events",
            "s3://private-bucket/report",
            "postgresql://database.internal/history",
        ):
            with self.subTest(uri=uri):
                value = extractor_result()
                value["turns"][0]["generalized_working_text"] = (
                    f"Inspect {uri} before continuing."
                )

                result = validate_extractor_result(value, ALL_REFS)

                self.assertEqual(
                    result["turns"][0]["generalized_working_text"],
                    "Inspect [REDACTED_URL] before continuing.",
                )
                self.assertEqual(scan_for_leaks(result), ())

    def test_post_redaction_covers_posix_paths_under_unlisted_roots(self) -> None:
        for source_path in (
            "/root/acme/customer.txt",
            "/usr/local/share/private.dat",
            "/workspace/project/review.log",
        ):
            with self.subTest(source_path=source_path):
                value = extractor_result()
                value["turns"][0]["generalized_working_text"] = (
                    f"Read {source_path} before continuing."
                )

                result = validate_extractor_result(value, ALL_REFS)

                text = result["turns"][0]["generalized_working_text"]
                self.assertEqual(text, "Read [REDACTED_PATH] before continuing.")
                self.assertEqual(scan_for_leaks(result), ())

    def test_post_redaction_covers_relative_source_paths(self) -> None:
        for source_path in ("src/a.py", "./src/a.py", "../src/a.py", r"src\a.py"):
            with self.subTest(source_path=source_path):
                value = extractor_result()
                value["turns"][0]["generalized_working_text"] = (
                    f"Read {source_path} before continuing."
                )

                result = validate_extractor_result(value, ALL_REFS)

                text = result["turns"][0]["generalized_working_text"]
                self.assertEqual(text, "Read [REDACTED_PATH] before continuing.")
                self.assertEqual(scan_for_leaks(result), ())

    def test_leak_scan_reports_locations_without_secret_values(self) -> None:
        secret = "s" + "k-abcdefghijklmnopqrstuvwxyz123456"
        findings = scan_for_leaks({"safe": f"credential {secret}"})

        self.assertEqual({finding.category for finding in findings}, {"credential"})
        self.assertTrue(all(secret not in repr(finding) for finding in findings))

    def test_original_prompt_is_removed_before_embedded_path_redaction(self) -> None:
        original_prompt = (
            "Inspect /Users/operator/private/repo and report the exact state."
        )
        value = extractor_result()
        value["turns"][0]["generalized_working_text"] = original_prompt

        result = validate_extractor_result(
            value, ALL_REFS, original_prompts=[original_prompt]
        )

        self.assertEqual(
            result["turns"][0]["generalized_working_text"],
            "[REDACTED_ORIGINAL_PROMPT]",
        )

    def test_substantial_original_prompt_excerpt_is_rejected_after_redaction(
        self,
    ) -> None:
        original_prompt = (
            "First inspect the current state and preserve every reversible recovery option "
            "before proposing a narrowly scoped change."
        )
        value = extractor_result()
        value["turns"][0]["generalized_working_text"] = (
            "The user said to inspect the current state and preserve every reversible recovery "
            "option before acting."
        )

        with self.assertRaisesRegex(ResultValidationError, "original_prompt"):
            validate_extractor_result(
                value, ALL_REFS, original_prompts=[original_prompt]
            )

    def test_private_key_block_and_bare_internal_url_are_fully_redacted(self) -> None:
        value = extractor_result()
        key_label = " ".join(("PRI" + "VATE", "K" + "EY"))
        value["turns"][0]["generalized_working_text"] = (
            f"-----BEGIN {key_label}-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n"
            f"-----END {key_label}----- "
            "at build.internal/job/42"
        )

        result = validate_extractor_result(value, ALL_REFS)

        text = result["turns"][0]["generalized_working_text"]
        self.assertEqual(text, "[REDACTED_SECRET] at [REDACTED_URL]")
        self.assertEqual(scan_for_leaks(result), ())

        value = extractor_result()
        value["turns"][0]["generalized_working_text"] = (
            "The failure involved jira.cisco.example before retry."
        )

        result = validate_extractor_result(value, ALL_REFS)

        text = result["turns"][0]["generalized_working_text"]
        self.assertEqual(
            text,
            "The failure involved [REDACTED_URL] before retry.",
        )
        self.assertEqual(scan_for_leaks(result), ())

    def test_raw_and_excerpt_fields_are_rejected_recursively(self) -> None:
        for forbidden_field in (
            "raw_text",
            "excerpt",
            "tool_output",
            "original_prompt",
        ):
            with self.subTest(forbidden_field=forbidden_field):
                value = extractor_result()
                value["turns"][0][forbidden_field] = "must not survive"
                with self.assertRaises(ResultValidationError):
                    validate_extractor_result(value, ALL_REFS)

    def test_unknown_structured_taxonomy_is_rejected(self) -> None:
        value = extractor_result()
        value["turns"][0]["events"] = [signal("approval_word_match_only")]

        with self.assertRaisesRegex(ResultValidationError, "must be one of"):
            validate_extractor_result(value, ALL_REFS)

    def test_reference_allow_list_is_enforced(self) -> None:
        value = extractor_result()
        value["turns"][0]["evidence_refs"] = [ref("evidence", "z")]

        with self.assertRaisesRegex(ResultValidationError, "allow-list"):
            validate_extractor_result(value, ALL_REFS)

    def test_episode_review_requires_every_high_impact_rewrite_field(self) -> None:
        value = episode_review(high_impact_turns=[high_impact()])
        del value["high_impact_turns"][0]["cause"]

        with self.assertRaisesRegex(
            ResultValidationError, "missing required fields: cause"
        ):
            validate_episode_review_result(value, ALL_REFS, allowed_turn_refs={TURN_A})

    def test_episode_review_post_redacts_original_prompt_from_rewrite(self) -> None:
        original_prompt = "Delete every environment immediately without asking."
        value = episode_review(high_impact_turns=[high_impact()])
        value["high_impact_turns"][0]["rewritten_prompt"] = original_prompt

        result = validate_episode_review_result(
            value,
            ALL_REFS,
            allowed_turn_refs={TURN_A},
            original_prompts=[original_prompt],
        )

        self.assertEqual(
            result["high_impact_turns"][0]["rewritten_prompt"],
            "[REDACTED_ORIGINAL_PROMPT]",
        )

    def test_episode_review_redacts_relative_paths_from_all_rewrite_fields(
        self,
    ) -> None:
        for field in (
            "problem_statement",
            "cause",
            "rewritten_prompt",
            "expected_effect",
        ):
            with self.subTest(field=field):
                value = episode_review(high_impact_turns=[high_impact()])
                value["high_impact_turns"][0][field] = "Inspect src/a.py first."

                result = validate_episode_review_result(
                    value,
                    ALL_REFS,
                    allowed_turn_refs={TURN_A},
                    original_prompts=["Please edit src/a.py."],
                )

                self.assertEqual(
                    result["high_impact_turns"][0][field],
                    "Inspect [REDACTED_PATH] first.",
                )
                self.assertEqual(scan_for_leaks(result), ())

    def test_hierarchical_episode_review_rejects_omitted_child_risk(self) -> None:
        child = episode_review(
            findings=[
                {
                    **signal("verification_gap", EVIDENCE_B),
                    "severity": "critical",
                }
            ],
            risks=["safety"],
            high_impact_turns=[high_impact(TURN_B)],
        )
        child["evidence_refs"] = [EVIDENCE_A, EVIDENCE_B]
        parent = episode_review()

        with self.assertRaisesRegex(
            ResultValidationError,
            "dropped a high-severity child decision",
        ):
            validate_hierarchical_episode_review_result(
                parent,
                [child],
                ALL_REFS,
                allowed_turn_refs={TURN_A, TURN_B},
                expected_child_result_hashes=[canonical_result_hash(child)],
                expected_reviewer_slot="primary",
            )

    def test_hierarchical_episode_review_conserves_child_risk_provenance(self) -> None:
        finding = {
            **signal("verification_gap", EVIDENCE_B),
            "severity": "critical",
        }
        rewrite = high_impact(TURN_B)
        child = episode_review(
            findings=[finding],
            risks=["safety"],
            high_impact_turns=[rewrite],
        )
        child["evidence_refs"] = [EVIDENCE_A, EVIDENCE_B]
        child["second_review_recommended"] = True
        child["conflicting_signals"] = True
        parent = episode_review(
            findings=[finding],
            risks=["safety"],
            high_impact_turns=[rewrite],
        )
        parent["evidence_refs"] = [EVIDENCE_A, EVIDENCE_B]
        parent["second_review_recommended"] = True
        parent["conflicting_signals"] = True

        result = validate_hierarchical_episode_review_result(
            parent,
            [child],
            ALL_REFS,
            allowed_turn_refs={TURN_A, TURN_B},
            expected_child_result_hashes=[canonical_result_hash(child)],
            expected_reviewer_slot="primary",
        )

        self.assertEqual([finding], result["findings"])
        self.assertEqual([rewrite], result["high_impact_turns"])
        self.assertEqual(["safety"], result["risk_flags"])

    def test_adjudication_cannot_invent_structured_findings(self) -> None:
        primary = episode_review(findings=[signal("verification_gap")])
        secondary = episode_review(
            reviewer_slot="secondary",
            findings=[signal("verification_gap")],
        )
        adjudication = {
            "schema": ADJUDICATION_RESULT_SCHEMA,
            "episode_ref": EPISODE,
            "episode_revision_ref": REVISION_A,
            "resolution": "merged_supported",
            "events": [signal("verification_completed")],
            "findings": [signal("over_exploration")],
            "strengths": [signal("complete_verification")],
            "risk_flags": [],
            "high_impact_turns": [],
            "evidence_refs": [EVIDENCE_A],
            "confidence": "high",
            "candidate_result_hashes": [
                canonical_result_hash(primary),
                canonical_result_hash(secondary),
            ],
        }
        adjudication["candidate_item_decisions"] = adjudication_item_decisions(
            [primary, secondary], adjudication
        )

        with self.assertRaisesRegex(ResultValidationError, "invented"):
            validate_adjudication_result(
                adjudication,
                ALL_REFS,
                candidate_results=[primary, secondary],
            )

    def test_adjudication_accounts_for_candidate_unique_items_and_provenance(
        self,
    ) -> None:
        primary = episode_review(findings=[signal("verification_gap")])
        secondary_rewrite = high_impact(TURN_B)
        secondary_rewrite["severity"] = "low"
        secondary = episode_review(
            reviewer_slot="secondary",
            findings=[
                {
                    **signal("prompt_ambiguity", EVIDENCE_B),
                    "severity": "low",
                }
            ],
            high_impact_turns=[secondary_rewrite],
        )
        secondary["strengths"] = [signal("clear_communication", EVIDENCE_B)]
        adjudication = {
            "schema": ADJUDICATION_RESULT_SCHEMA,
            "episode_ref": EPISODE,
            "episode_revision_ref": REVISION_A,
            "resolution": "primary_supported",
            **{
                field: copy.deepcopy(primary[field])
                for field in (
                    "events",
                    "findings",
                    "strengths",
                    "risk_flags",
                    "high_impact_turns",
                    "evidence_refs",
                    "confidence",
                )
            },
            "candidate_result_hashes": [
                canonical_result_hash(primary),
                canonical_result_hash(secondary),
            ],
        }
        adjudication["candidate_item_decisions"] = adjudication_item_decisions(
            [primary, secondary], adjudication
        )

        validated = validate_adjudication_result(
            adjudication,
            ALL_REFS,
            allowed_turn_refs={TURN_A, TURN_B},
            candidate_results=[primary, secondary],
        )
        self.assertEqual(
            {"findings", "strengths", "high_impact_turns"},
            {
                row["field"]
                for row in validated["candidate_item_decisions"]
                if row["candidate_result_hash"] == canonical_result_hash(secondary)
                and row["disposition"] == "rejected"
            },
        )

        for field in ("findings", "strengths", "high_impact_turns"):
            with self.subTest(field=field):
                omitted = copy.deepcopy(adjudication)
                omitted["candidate_item_decisions"] = [
                    row
                    for row in omitted["candidate_item_decisions"]
                    if not (
                        row["candidate_result_hash"] == canonical_result_hash(secondary)
                        and row["field"] == field
                    )
                ]
                with self.assertRaisesRegex(ResultValidationError, "account for every"):
                    validate_adjudication_result(
                        omitted,
                        ALL_REFS,
                        allowed_turn_refs={TURN_A, TURN_B},
                        candidate_results=[primary, secondary],
                    )

        forged_provenance = copy.deepcopy(adjudication)
        forged_provenance["candidate_item_decisions"][-1]["reviewer_ref"] = (
            REVIEWER_PRIMARY
        )
        with self.assertRaisesRegex(ResultValidationError, "provenance"):
            validate_adjudication_result(
                forged_provenance,
                ALL_REFS,
                allowed_turn_refs={TURN_A, TURN_B},
                candidate_results=[primary, secondary],
            )

        topic_input = {
            "adjudication_candidate_results": {REVISION_A: [primary, secondary]},
            "adjudication_required_episode_revision_refs": [REVISION_A],
            "episode_contexts": [
                {
                    "episode_ref": EPISODE,
                    "episode_revision_ref": REVISION_A,
                    "session_ref": SESSION_A,
                }
            ],
            "episode_reviews": [adjudication],
            "expected_episode_revision_refs": [REVISION_A],
            "schema": TOPIC_INPUT_SCHEMA,
            "topic_ref": TOPIC,
            "workstream_ref": WORKSTREAM_A,
        }
        downstream = validate_topic_input(
            topic_input,
            ALL_REFS,
            allowed_turn_refs={TURN_A, TURN_B},
        )
        self.assertEqual(
            secondary["high_impact_turns"],
            downstream["adjudication_candidate_results"][REVISION_A][1][
                "high_impact_turns"
            ],
        )
        self.assertEqual(
            adjudication["candidate_item_decisions"],
            downstream["episode_reviews"][0]["candidate_item_decisions"],
        )

    def test_topic_input_requires_exact_episode_revision_coverage(self) -> None:
        first = episode_review(revision_ref=REVISION_A)
        second = episode_review(revision_ref=REVISION_B)
        value = {
            "adjudication_candidate_results": {},
            "schema": TOPIC_INPUT_SCHEMA,
            "workstream_ref": WORKSTREAM_A,
            "topic_ref": TOPIC,
            "episode_contexts": [
                {
                    "episode_ref": EPISODE,
                    "episode_revision_ref": REVISION_A,
                    "session_ref": SESSION_A,
                },
                {
                    "episode_ref": EPISODE,
                    "episode_revision_ref": REVISION_B,
                    "session_ref": SESSION_A,
                },
            ],
            "model_configuration_ref": MODEL,
            "episode_reviews": [first, second],
            "expected_episode_revision_refs": [REVISION_A],
            "adjudication_required_episode_revision_refs": [],
        }

        with self.assertRaisesRegex(ResultValidationError, "exactly cover"):
            validate_topic_input(value, ALL_REFS)

    def test_topic_input_accepts_validated_redacted_reviews(self) -> None:
        value = {
            "adjudication_candidate_results": {},
            "schema": TOPIC_INPUT_SCHEMA,
            "workstream_ref": WORKSTREAM_A,
            "topic_ref": TOPIC,
            "episode_contexts": [
                {
                    "episode_ref": EPISODE,
                    "episode_revision_ref": REVISION_A,
                    "session_ref": SESSION_A,
                }
            ],
            "episode_reviews": [episode_review()],
            "expected_episode_revision_refs": [REVISION_A],
            "adjudication_required_episode_revision_refs": [],
        }

        result = validate_topic_input(value, ALL_REFS)

        self.assertEqual(result["expected_episode_revision_refs"], [REVISION_A])

    def test_topic_result_supports_existing_topic_ref_input(self) -> None:
        topic_input = validate_topic_input(
            {
                "adjudication_candidate_results": {},
                "schema": TOPIC_INPUT_SCHEMA,
                "workstream_ref": WORKSTREAM_A,
                "topic_ref": TOPIC,
                "episode_contexts": [
                    {
                        "episode_ref": EPISODE,
                        "episode_revision_ref": REVISION_A,
                        "session_ref": SESSION_A,
                    }
                ],
                "episode_reviews": [episode_review()],
                "expected_episode_revision_refs": [REVISION_A],
                "adjudication_required_episode_revision_refs": [],
            },
            ALL_REFS,
        )

        result = build_topic_result(topic_input, topic_ref=TOPIC)
        validated = validate_topic_result(
            result,
            topic_input,
            ALL_REFS,
            expected_topic_ref=TOPIC,
        )

        self.assertEqual(TOPIC, validated["topic_ref"])
        self.assertNotIn("topic_candidate_ref", validated)
        with self.assertRaises(ResultValidationError):
            build_topic_result(topic_input, topic_ref=ref("topic", "other"))

    def test_topic_result_is_real_cross_session_aggregation_consumed_by_synthesis(
        self,
    ) -> None:
        secondary = episode_review(
            episode_ref=EPISODE_B,
            revision_ref=REVISION_B,
            reviewer_slot="secondary",
            findings=[
                {
                    "kind": "production_risk",
                    "severity": "high",
                    "evidence_refs": [EVIDENCE_A],
                    "confidence": "low",
                }
            ],
        )
        resolved = episode_review(
            episode_ref=EPISODE_B,
            revision_ref=REVISION_B,
            findings=copy.deepcopy(secondary["findings"]),
        )
        topic_input = {
            "adjudication_candidate_results": {},
            "schema": TOPIC_INPUT_SCHEMA,
            "workstream_ref": WORKSTREAM_A,
            "topic_candidate_ref": TOPIC_CANDIDATE,
            "episode_contexts": [
                {
                    "episode_ref": EPISODE,
                    "episode_revision_ref": REVISION_A,
                    "session_ref": SESSION_A,
                },
                {
                    "episode_ref": EPISODE_B,
                    "episode_revision_ref": REVISION_B,
                    "session_ref": SESSION_B,
                },
            ],
            "episode_reviews": [
                episode_review(
                    episode_ref=EPISODE,
                    revision_ref=REVISION_A,
                    findings=[
                        {
                            "kind": "production_risk",
                            "severity": "medium",
                            "evidence_refs": [EVIDENCE_B],
                            "confidence": "medium",
                        }
                    ],
                ),
                resolved,
            ],
            "expected_episode_revision_refs": [REVISION_A, REVISION_B],
            "adjudication_required_episode_revision_refs": [],
        }
        validated_input = validate_topic_input(topic_input, ALL_REFS)
        result = build_topic_result(validated_input, topic_ref=TOPIC)
        validated = validate_topic_result(
            result,
            validated_input,
            ALL_REFS,
            expected_topic_ref=TOPIC,
        )

        self.assertEqual(TOPIC_RESULT_SCHEMA, validated["schema"])
        self.assertTrue(validated["cross_session"])
        self.assertEqual([SESSION_A, SESSION_B], validated["session_refs"])
        self.assertEqual([REVISION_A, REVISION_B], validated["episode_revision_refs"])
        self.assertEqual(2, len(validated["review_result_hashes"]))
        with self.assertRaises(ResultValidationError):
            validate_topic_result(
                validated_input,
                validated_input,
                ALL_REFS,
                expected_topic_ref=TOPIC,
            )
        invented = dict(result)
        invented["cross_session"] = False
        with self.assertRaisesRegex(ResultValidationError, "exactly preserve"):
            validate_topic_result(
                invented,
                validated_input,
                ALL_REFS,
                expected_topic_ref=TOPIC,
            )

        synthesis = synthesis_result()
        synthesis["topic_result_hashes"] = [canonical_result_hash(validated)]
        synthesis["signal_commitments"] = build_synthesis_signal_commitments(
            [validated]
        )
        synthesis.update(build_synthesis_signal_exemplars([validated]))
        synthesis["evidence_refs"] = list(validated["episode_refs"])
        validated_synthesis = validate_synthesis_result(
            synthesis,
            ALL_REFS,
            independent_review_results=[secondary],
            topic_results=[validated],
        )
        self.assertEqual(
            {(EVIDENCE_A,), (EVIDENCE_B,)},
            {
                tuple(finding["evidence_refs"])
                for finding in validated_synthesis["findings"]
            },
        )
        substituted = copy.deepcopy(synthesis)
        substituted["findings"][0]["confidence"] = "high"
        with self.assertRaisesRegex(
            ResultValidationError,
            "deterministic bounded topic-signal exemplars",
        ):
            validate_synthesis_result(
                substituted,
                ALL_REFS,
                independent_review_results=[secondary],
                topic_results=[validated],
            )
        over_attributed = copy.deepcopy(synthesis)
        original_refs = over_attributed["findings"][0]["evidence_refs"]
        extra_ref = EVIDENCE_A if original_refs == [EVIDENCE_B] else EVIDENCE_B
        original_refs.append(extra_ref)
        with self.assertRaisesRegex(
            ResultValidationError,
            "deterministic bounded topic-signal exemplars",
        ):
            validate_synthesis_result(
                over_attributed,
                ALL_REFS,
                independent_review_results=[secondary],
                topic_results=[validated],
            )
        synthesis["topic_result_hashes"] = []
        with self.assertRaisesRegex(ResultValidationError, "every validated topic"):
            validate_synthesis_result(
                synthesis,
                ALL_REFS,
                topic_results=[validated],
            )

    def test_synthesis_requires_all_ten_closed_questions(self) -> None:
        value = synthesis_result()
        value["question_answers"].pop()

        with self.assertRaisesRegex(
            ResultValidationError, "ten retrospective questions"
        ):
            validate_synthesis_result(value, ALL_REFS)

    def test_hierarchical_synthesis_separates_source_and_output_refs(self) -> None:
        topic_result = {
            "episode_lineage": [{"episode_ref": EPISODE, "session_ref": SESSION_A}],
            "episode_refs": [EPISODE],
            "events": [],
            "findings": [],
            "schema": TOPIC_RESULT_SCHEMA,
            "session_refs": [SESSION_A],
            "strengths": [],
        }
        value = synthesis_result()
        value["topic_result_hashes"] = [canonical_result_hash(topic_result)]
        value["signal_commitments"] = build_synthesis_signal_commitments([topic_result])

        with self.assertRaises(ResultValidationError):
            validate_synthesis_result(value, set(), topic_results=[topic_result])
        validated = validate_synthesis_result(
            value,
            set(),
            source_allowed_refs={EPISODE, SESSION_A},
            topic_results=[topic_result],
        )

        self.assertEqual(value, validated)

    def test_synthesis_commits_more_than_64_distinct_topic_signals(self) -> None:
        topic_results = []
        allowed_refs = set(ALL_REFS)
        for index in range(70):
            episode_ref = ref("episode", f"many-signals-episode-{index}")
            evidence_ref = ref("evidence", f"many-signals-evidence-{index}")
            session_ref = ref("session", f"many-signals-session-{index}")
            allowed_refs.update({episode_ref, evidence_ref, session_ref})
            topic_results.append(
                {
                    "episode_lineage": [
                        {
                            "episode_ref": episode_ref,
                            "session_ref": session_ref,
                        }
                    ],
                    "episode_refs": [episode_ref],
                    "events": [
                        {
                            "confidence": "high",
                            "evidence_refs": [evidence_ref],
                            "kind": "verification_completed",
                        }
                    ],
                    "findings": [],
                    "schema": TOPIC_RESULT_SCHEMA,
                    "strengths": [],
                }
            )
        synthesis = synthesis_result()
        synthesis["topic_result_hashes"] = sorted(
            canonical_result_hash(topic) for topic in topic_results
        )
        synthesis["signal_commitments"] = build_synthesis_signal_commitments(
            topic_results
        )
        synthesis.update(build_synthesis_signal_exemplars(topic_results))

        validated = validate_synthesis_result(
            synthesis,
            allowed_refs,
            topic_results=topic_results,
        )

        self.assertEqual(64, len(validated["events"]))
        self.assertEqual(
            70,
            validated["signal_commitments"]["events"]["canonical_count"],
        )
        tampered = copy.deepcopy(synthesis)
        tampered["signal_commitments"]["events"]["canonical_count"] = 64
        with self.assertRaisesRegex(ResultValidationError, "every canonical topic"):
            validate_synthesis_result(
                tampered,
                allowed_refs,
                topic_results=topic_results,
            )

    def test_synthesis_rejects_under_supported_durable_guidance(self) -> None:
        topic_result = {
            "episode_lineage": [{"episode_ref": EPISODE, "session_ref": SESSION_A}],
            "episode_refs": [EPISODE],
            "events": [],
            "findings": [],
            "schema": TOPIC_RESULT_SCHEMA,
            "session_refs": [SESSION_A],
            "strengths": [],
        }
        value = synthesis_result()
        value["topic_result_hashes"] = [canonical_result_hash(topic_result)]
        value["signal_commitments"] = build_synthesis_signal_commitments([topic_result])
        value["guidance_candidates"] = [
            {
                "kind": "verification",
                "episode_lineage": [{"episode_ref": EPISODE, "session_ref": SESSION_A}],
                "confidence": "high",
                "exception": "none",
            }
        ]

        with self.assertRaisesRegex(ResultValidationError, "three episode lineages"):
            validate_synthesis_result(value, ALL_REFS, topic_results=[topic_result])

    def test_durable_candidate_requires_exact_episode_session_lineage(self) -> None:
        episode_three = ref("episode", "candidate-three")
        session_three = ref("session", "candidate-unrelated")
        lineage = [
            {"episode_ref": EPISODE, "session_ref": SESSION_A},
            {"episode_ref": EPISODE_B, "session_ref": SESSION_A},
            {"episode_ref": episode_three, "session_ref": SESSION_B},
        ]
        topic_result = {
            "episode_lineage": lineage,
            "episode_refs": [EPISODE, EPISODE_B, episode_three],
            "events": [],
            "findings": [],
            "schema": TOPIC_RESULT_SCHEMA,
            "session_refs": [SESSION_A, SESSION_B],
            "strengths": [],
        }
        allowed_refs = set(ALL_REFS) | {episode_three, session_three}
        value = synthesis_result()
        value["topic_result_hashes"] = [canonical_result_hash(topic_result)]
        value["signal_commitments"] = build_synthesis_signal_commitments([topic_result])
        value["guidance_candidates"] = [
            {
                "confidence": "high",
                "episode_lineage": copy.deepcopy(lineage),
                "exception": "none",
                "kind": "verification",
            }
        ]
        validate_synthesis_result(
            value,
            allowed_refs,
            topic_results=[topic_result],
        )

        mismatched = copy.deepcopy(value)
        mismatched["guidance_candidates"][0]["episode_lineage"][2]["session_ref"] = (
            session_three
        )
        with self.assertRaisesRegex(ResultValidationError, "does not match"):
            validate_synthesis_result(
                mismatched,
                allowed_refs,
                topic_results=[topic_result],
            )

        unrelated = copy.deepcopy(value)
        unrelated["guidance_candidates"][0]["episode_lineage"][2]["episode_ref"] = ref(
            "episode", "not-in-topic"
        )
        allowed_refs.add(
            unrelated["guidance_candidates"][0]["episode_lineage"][2]["episode_ref"]
        )
        with self.assertRaisesRegex(ResultValidationError, "does not match"):
            validate_synthesis_result(
                unrelated,
                allowed_refs,
                topic_results=[topic_result],
            )


class EpisodeConstructionTests(unittest.TestCase):
    def test_72_hour_gap_is_candidate_not_boundary(self) -> None:
        rows = [
            turn(
                TURN_A,
                timestamp="2026-07-01T00:00:00Z",
                sequence=0,
                archive_state="active",
                mtime="2026-07-01T00:01:00Z",
            ),
            turn(
                TURN_B,
                timestamp="2026-07-05T00:00:00Z",
                sequence=1,
                archive_state="archived",
                mtime="2026-07-14T23:59:00Z",
                goal_change="continues",
            ),
        ]

        episodes = construct_episodes(rows)

        self.assertEqual(len(episodes), 1)
        self.assertEqual(episodes[0]["turn_refs"], [TURN_A, TURN_B])
        self.assertEqual(
            episodes[0]["internal_boundary_candidates"][0]["candidate_reasons"],
            ["elapsed_72h_candidate"],
        )
        self.assertFalse(
            episodes[0]["internal_boundary_candidates"][0]["accepted_boundary"]
        )

    def test_goal_change_splits_inside_one_thread(self) -> None:
        rows = [
            turn(TURN_A, timestamp="2026-07-01T00:00:00Z", sequence=0),
            turn(
                TURN_B,
                timestamp="2026-07-01T01:00:00Z",
                sequence=1,
                goal_ref=GOAL_B,
                goal_change="new_goal",
            ),
        ]

        episodes = construct_episodes(rows)

        self.assertEqual(
            [episode["turn_refs"] for episode in episodes], [[TURN_A], [TURN_B]]
        )
        self.assertEqual(
            episodes[1]["boundary_before"]["accepted_reasons"], ["goal_change"]
        )

    def test_contradictory_goal_continuity_becomes_a_segmentation_failure(self) -> None:
        rows = [
            turn(TURN_A, timestamp="2026-07-01T00:00:00Z", sequence=0),
            turn(
                TURN_B,
                timestamp="2026-07-01T01:00:00Z",
                sequence=1,
                goal_ref=GOAL_B,
                goal_change="continues",
            ),
        ]

        with self.assertRaisesRegex(ResultValidationError, "conflicts"):
            construct_episodes(rows)

    def test_same_goal_in_different_threads_remains_distinct(self) -> None:
        rows = [
            turn(TURN_A, timestamp="2026-07-01T00:00:00Z", sequence=0),
            turn(
                TURN_B,
                session_ref=SESSION_B,
                timestamp="2026-07-01T01:00:00Z",
                sequence=0,
            ),
        ]

        episodes = construct_episodes(rows)

        self.assertEqual(len(episodes), 2)
        self.assertEqual(
            {episode["session_ref"] for episode in episodes}, {SESSION_A, SESSION_B}
        )

    def test_archive_and_mtime_changes_never_create_candidates(self) -> None:
        rows = [
            turn(
                TURN_A,
                timestamp="2026-07-01T00:00:00Z",
                sequence=0,
                archive_state="active",
                archive_time="2026-07-02T00:00:00Z",
                mtime="2026-07-03T00:00:00Z",
            ),
            turn(
                TURN_B,
                timestamp="2026-07-01T01:00:00Z",
                sequence=1,
                archive_state="archived",
                archive_time="2026-07-14T00:00:00Z",
                mtime="2026-07-14T00:00:00Z",
            ),
        ]

        episodes = construct_episodes(rows)

        self.assertEqual(len(episodes), 1)
        self.assertEqual(episodes[0]["internal_boundary_candidates"], [])

    def test_meaningfulness_gap_cannot_be_review_not_required(self) -> None:
        rows = [
            turn(
                TURN_A,
                timestamp="2026-07-01T00:00:00Z",
                meaningfulness="context_only",
            ),
            turn(
                TURN_B,
                timestamp="2026-07-01T01:00:00Z",
                meaningfulness="meaningfulness_gap",
                sequence=1,
            ),
        ]

        result = derive_episode_meaningfulness(rows)

        self.assertEqual(result["disposition"], "meaningfulness_gap")
        self.assertEqual(result["semantic_coverage"], "gap")
        self.assertNotEqual(result["disposition"], "review_not_required")


class EpisodeLineageAndPlanningTests(unittest.TestCase):
    identity_key = IdentityKey(b"k" * 32)

    def episode(self, turn_refs: list[str]) -> dict:
        return {
            "session_ref": SESSION_A,
            "turn_refs": turn_refs,
            "goal_refs": [GOAL_A],
            "workstream_refs": [WORKSTREAM_A],
            "boundary_before": None,
            "internal_boundary_candidates": [],
            "meaningfulness": {
                "disposition": "meaningful",
                "semantic_coverage": "complete",
                "review_required": True,
                "meaningful_turn_refs": turn_refs,
                "context_only_turn_refs": [],
                "gap_turn_refs": [],
            },
            "risk_flags": [],
            "extraction_confidence": "high",
            "segmentation_confidence": "high",
        }

    def test_earlier_backfill_preserves_anchor_and_appends_revision(self) -> None:
        initial = create_episode_revision(
            self.episode([TURN_B]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        backfilled = create_episode_revision(
            self.episode([TURN_A, TURN_B]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
            previous_revision=initial,
        )

        self.assertEqual(backfilled["episode_ref"], initial["episode_ref"])
        self.assertNotEqual(
            backfilled["episode_revision_ref"], initial["episode_revision_ref"]
        )
        self.assertEqual(
            backfilled["supersedes_episode_revision_ref"],
            initial["episode_revision_ref"],
        )
        self.assertEqual(backfilled["lineage_kind"], "extension")

    def test_noop_revision_is_idempotent(self) -> None:
        initial = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        replay = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
            previous_revision=initial,
        )

        self.assertEqual(replay, initial)

    def test_review_planning_verifies_closed_revision_before_using_decisions(
        self,
    ) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        opened = {**revision, "unexpected_risk_override": True}
        with self.assertRaisesRegex(ResultValidationError, "unknown fields"):
            plan_episode_review_jobs(opened, identity_key=self.identity_key)

        tampered_revisions = {
            "risk": {**revision, "risk_flags": ["privacy"]},
            "meaningfulness": {
                **revision,
                "meaningfulness": {
                    "disposition": "review_not_required",
                    "semantic_coverage": "complete",
                    "review_required": False,
                    "meaningful_turn_refs": [],
                    "context_only_turn_refs": [TURN_A],
                    "gap_turn_refs": [],
                },
            },
            "confidence": {**revision, "extraction_confidence": "low"},
        }
        for field, tampered in tampered_revisions.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(ResultValidationError, "does not commit"):
                    plan_episode_review_jobs(tampered, identity_key=self.identity_key)

        with self.assertRaisesRegex(ResultValidationError, "identity key"):
            plan_episode_review_jobs(
                revision,
                identity_key=IdentityKey(b"z" * 32),
            )

    def test_revision_ref_binds_ordinal_and_lineage(self) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        tampered = {
            **revision,
            "revision_ordinal": 2,
            "lineage_kind": "extension",
            "supersedes_episode_revision_ref": REVISION_A,
        }

        with self.assertRaisesRegex(ResultValidationError, "does not commit"):
            create_episode_revision(
                self.episode([TURN_A, TURN_B]),
                identity_key=self.identity_key,
                previous_revision=tampered,
            )
        with self.assertRaisesRegex(ResultValidationError, "does not commit"):
            plan_episode_review_jobs(tampered, identity_key=self.identity_key)

    def test_ordinary_revision_cannot_remove_membership(self) -> None:
        initial = create_episode_revision(
            self.episode([TURN_A, TURN_B]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        with self.assertRaisesRegex(ResultValidationError, "cannot remove"):
            create_episode_revision(
                self.episode([TURN_B]),
                identity_key=self.identity_key,
                key_id=self.identity_key.key_id,
                previous_revision=initial,
            )

    def test_ordinary_revision_cannot_reorder_membership(self) -> None:
        initial = create_episode_revision(
            self.episode([TURN_A, TURN_B]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        with self.assertRaisesRegex(ResultValidationError, "cannot reorder"):
            create_episode_revision(
                self.episode([TURN_B, TURN_A, TURN_C]),
                identity_key=self.identity_key,
                key_id=self.identity_key.key_id,
                previous_revision=initial,
            )

    def test_correction_generation_is_order_independent_and_successor_is_new(
        self,
    ) -> None:
        generation_a = derive_episode_correction_generation(
            self.identity_key,
            [EPISODE, ref("episode", "t")],
            [[TURN_A], [TURN_B]],
            correction_ordinal=1,
        )
        generation_b = derive_episode_correction_generation(
            self.identity_key,
            [ref("episode", "t"), EPISODE],
            [[TURN_B], [TURN_A]],
            correction_ordinal=1,
        )
        successor = derive_corrected_episode_ref(
            self.identity_key,
            generation_a,
            [TURN_A],
        )

        self.assertEqual(generation_a, generation_b)
        self.assertNotEqual(successor, EPISODE)

    def test_risk_schedules_primary_and_independent_secondary_reviews(self) -> None:
        revision = create_episode_revision(
            {**self.episode([TURN_A]), "risk_flags": ["privacy"]},
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        plan = plan_episode_review_jobs(revision, identity_key=self.identity_key)

        self.assertTrue(plan["second_review_required"])
        self.assertEqual(
            [(job["kind"], job.get("reviewer_slot")) for job in plan["jobs"]],
            [
                (JobKind.EPISODE_REVIEWER.value, "primary"),
                (JobKind.INDEPENDENT_RISK_REVIEWER.value, "secondary"),
            ],
        )
        self.assertIn("privacy_risk", plan["second_review_reason_codes"])

    def test_low_risk_episode_schedules_only_primary_review(self) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            screening_results=[
                {
                    "turn_ref": TURN_A,
                    "decision": "not_high_impact",
                    "risk_flags": [],
                }
            ],
        )

        self.assertFalse(plan["second_review_required"])
        self.assertEqual(len(plan["jobs"]), 1)
        self.assertEqual(plan["jobs"][0]["reviewer_slot"], "primary")

    def test_screening_must_exactly_cover_every_episode_turn(self) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A, TURN_B]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            screening_results=[
                {
                    "turn_ref": TURN_A,
                    "decision": "not_high_impact",
                    "risk_flags": [],
                }
            ],
        )

        self.assertEqual("high_impact_screen_gap", plan["blocked_reason"])
        self.assertEqual([TURN_B], plan["high_impact_screen_gap_turn_refs"])
        self.assertEqual(
            [
                {
                    "kind": "high_impact_screen_gap",
                    "turn_ref": TURN_B,
                    "gap_reason": "missing_decision",
                }
            ],
            plan["screening_gaps"],
        )
        self.assertTrue(plan["second_review_required"])
        self.assertIn("high_impact_screen_gap", plan["second_review_reason_codes"])

    def test_failed_screening_is_an_explicit_gap_not_a_negative_result(self) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            screening_results={
                "schema": "agent_failure_v2",
                "failure_kind": "timeout",
            },
        )

        self.assertEqual("high_impact_screen_gap", plan["blocked_reason"])
        self.assertEqual([TURN_A], plan["high_impact_screen_gap_turn_refs"])
        self.assertEqual("screening_failure", plan["screening_gaps"][0]["gap_reason"])
        self.assertTrue(plan["second_review_required"])
        self.assertIn("high_impact_screen_gap", plan["second_review_reason_codes"])

    def test_primary_review_gap_is_typed_and_blocks_completion(self) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        primary = episode_review_gap(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
            reviewer_slot="primary",
        )

        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            screening_results=[
                {
                    "turn_ref": TURN_A,
                    "decision": "not_high_impact",
                    "risk_flags": [],
                }
            ],
            primary_review=primary,
        )

        self.assertFalse(plan["primary_review_completed"])
        self.assertEqual(plan["blocked_reason"], "primary_review_gap")
        self.assertEqual(plan["jobs"], [])
        self.assertEqual(
            plan["review_gaps"],
            [
                {
                    "kind": "episode_review_gap",
                    "reviewer_slot": "primary",
                    "gap_reason": "review_failure",
                    "attempt_ref": ATTEMPT_PRIMARY,
                }
            ],
        )

    def test_secondary_review_gap_is_typed_and_blocks_completion(self) -> None:
        revision = create_episode_revision(
            {**self.episode([TURN_A]), "risk_flags": ["privacy"]},
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        primary = episode_review(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
        )
        secondary = episode_review_gap(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
            reviewer_slot="secondary",
            gap_reason="insufficient_support",
        )

        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            screening_results=[
                {
                    "turn_ref": TURN_A,
                    "decision": "not_high_impact",
                    "risk_flags": [],
                }
            ],
            primary_review=primary,
            secondary_review=secondary,
        )

        self.assertTrue(plan["primary_review_completed"])
        self.assertFalse(plan["secondary_review_completed"])
        self.assertTrue(plan["second_review_required"])
        self.assertEqual(plan["blocked_reason"], "secondary_review_gap")
        self.assertEqual(plan["jobs"], [])
        self.assertEqual(plan["review_gaps"][0]["gap_reason"], "insufficient_support")

    def test_reviewer_escalation_forces_secondary_and_adjudication(self) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        primary = episode_review(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
            high_impact_turns=[high_impact()],
        )
        secondary = episode_review(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
            reviewer_slot="secondary",
            high_impact_turns=[high_impact()],
        )
        screens = [
            {"turn_ref": TURN_A, "decision": "not_high_impact", "risk_flags": []},
            {"turn_ref": TURN_A, "decision": "not_high_impact", "risk_flags": []},
        ]

        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            screening_results=screens,
            primary_review=primary,
            secondary_review=secondary,
        )

        self.assertTrue(plan["second_review_required"])
        self.assertTrue(plan["adjudication_required"])
        self.assertEqual(plan["reviewer_escalation_turn_refs"], [TURN_A])
        self.assertEqual(plan["jobs"][0]["kind"], JobKind.ADJUDICATOR.value)

    def test_material_review_conflict_schedules_adjudication(self) -> None:
        revision = create_episode_revision(
            {**self.episode([TURN_A]), "risk_flags": ["privacy"]},
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        primary = episode_review(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
            findings=[signal("verification_gap")],
            risks=["privacy"],
        )
        secondary = episode_review(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
            reviewer_slot="secondary",
            findings=[signal("assumption_risk")],
            risks=["privacy"],
        )

        self.assertTrue(material_review_conflict(primary, secondary))
        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            primary_review=primary,
            secondary_review=secondary,
        )

        self.assertTrue(plan["adjudication_required"])
        self.assertIn("material_review_conflict", plan["adjudication_reason_codes"])

    def test_review_binding_to_another_episode_is_rejected(self) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        with self.assertRaisesRegex(ResultValidationError, "not bound"):
            plan_episode_review_jobs(
                revision,
                identity_key=self.identity_key,
                primary_review=episode_review(),
            )

    def test_primary_high_impact_failsafe_schedules_secondary_without_screen_signal(
        self,
    ) -> None:
        revision = create_episode_revision(
            self.episode([TURN_A]),
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )
        primary = episode_review(
            episode_ref=revision["episode_ref"],
            revision_ref=revision["episode_revision_ref"],
            high_impact_turns=[high_impact()],
        )

        plan = plan_episode_review_jobs(
            revision,
            identity_key=self.identity_key,
            primary_review=primary,
        )

        self.assertTrue(plan["second_review_required"])
        self.assertEqual(
            plan["jobs"][0]["kind"], JobKind.INDEPENDENT_RISK_REVIEWER.value
        )

    def test_context_only_episode_has_no_review_jobs(self) -> None:
        episode = self.episode([TURN_A])
        episode["meaningfulness"] = {
            "disposition": "review_not_required",
            "semantic_coverage": "complete",
            "review_required": False,
            "meaningful_turn_refs": [],
            "context_only_turn_refs": [TURN_A],
            "gap_turn_refs": [],
        }
        revision = create_episode_revision(
            episode,
            identity_key=self.identity_key,
            key_id=self.identity_key.key_id,
        )

        plan = plan_episode_review_jobs(revision, identity_key=self.identity_key)

        self.assertFalse(plan["review_required"])
        self.assertEqual(plan["jobs"], [])


if __name__ == "__main__":
    unittest.main()
