from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


SCRIPTS_DIR = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "codex-session-retrospective"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS_DIR))

import retrospective_v2.export as export_module  # noqa: E402
import retrospective_v2.reporting as reporting_module  # noqa: E402
from retrospective_v2.export import (  # noqa: E402
    ExportConflictError,
    ExportLocationError,
    bind_staged_export,
    export_retained_bundle,
    garbage_collect_expired_exports,
    release_committed_staged_export,
    release_staged_export,
    release_staged_export_if_bound,
    stage_retained_artifacts,
    validate_staged_export,
)
from retrospective_v2.finalize import compute_retained_bundle_digest  # noqa: E402
from retrospective_v2.result_validation import (  # noqa: E402
    build_synthesis_signal_commitments,
    build_synthesis_signal_exemplars,
)
from retrospective_v2.reporting import (  # noqa: E402
    REPORT_SECTIONS,
    RETAINED_ARTIFACT_NAMES,
    RetainedInventoryError,
    RetainedPrivacyError,
    assemble_retained_artifacts,
    canonical_json_bytes,
    retained_bundle_digest,
    validate_retained_artifacts,
)


def ref(kind: str, character: str) -> str:
    return f"{kind}_ref_v2:{character * 64}"


RUN_REF = ref("run", "a")
CONFIGURATION_REF = ref("configuration", "b")
EPISODE_ONE = ref("episode", "c")
EPISODE_TWO = ref("episode", "d")
EPISODE_THREE = ref("episode", "8")
SESSION_ONE = ref("session", "9")
SESSION_TWO = ref("session", "0")
TOPIC_ONE = ref("topic", "e")
EVIDENCE_ONE = ref("evidence", "f")
EVIDENCE_TWO = ref("evidence", "0")
TURN_ONE = ref("turn", "1")
TURN_TWO = ref("turn", "2")
TURN_THREE = ref("turn", "3")
TURN_FOUR = ref("turn", "4")
REVISION_ONE = ref("episode_revision", "5")
REVISION_TWO = ref("episode_revision", "6")
REVISION_THREE = ref("episode_revision", "7")
REVISION_OLD = ref("episode_revision", "4")
ATTEMPT_ONE = ref("attempt", "7")
ATTEMPT_TWO = ref("attempt", "8")
ATTEMPT_THREE = ref("attempt", "9")
REVIEWER_ONE = ref("reviewer", "a")
REVIEWER_TWO = ref("reviewer", "b")
REVIEWER_THREE = ref("reviewer", "c")
REVIEW_HASH_ONE = "1" * 64
REVIEW_HASH_TWO = "2" * 64
REVIEW_HASH_THREE = "3" * 64
MODEL_ERA = "gpt_5_6_sol_r1"
POLICY_ERA = "retained_policy_v2"
QUESTION_IDS = (
    "what_happened",
    "what_worked_well",
    "noise_delay_confusion",
    "errors_retries_verification",
    "exploration_asking_context_assumptions",
    "safety_privacy",
    "prompt_improvements",
    "durable_guidance",
    "reusable_skills",
    "follow_up_actions",
)


def run_state(*, meaningful_turn_count: int = 4) -> dict[str, object]:
    return {
        "coverage": {
            "context_only_turn_count": 1,
            "coverage_complete": True,
            "extraction_gap_count": 0,
            "meaningful_turn_count": meaningful_turn_count,
            "meaningfulness_gap_count": 0,
            "source_units": {
                "consumed_candidate": 5,
                "expected": 6,
                "explicit_gap": 0,
                "structurally_excluded": 1,
            },
        },
        "default_model_era": MODEL_ERA,
        "default_policy_era": POLICY_ERA,
        "durable_state": {
            "backfill_of": None,
            "expected_cursor_root_ref": ref("cursor_root", "5"),
            "expected_episode_head_root_ref": ref("episode_head_set", "6"),
            "expected_history_commit": "7" * 40,
            "identity_key_id": "identity_key_v2:" + "8" * 64,
            "provider_revision_after": 1,
            "provider_revision_before": 0,
            "proposed_cursor_root_ref": ref("cursor_root", "9"),
            "proposed_cursor_rows": [],
            "proposed_episode_head_root_ref": ref("episode_head_set", "a"),
            "proposed_episode_heads": [],
            "proposed_episode_membership": [],
            "schema": "durable_history_state_v2",
            "source_snapshot_refs": [],
        },
        "mode": "weekly",
        "provenance": {
            "agent_execution": {
                "jobs": [],
                "result_count": 0,
                "retry_count": 0,
                "schema": "agent_execution_provenance_v2",
                "task_cache": {"hits": 0, "misses": 0, "reuses": 0},
            },
            "configuration_root": "c" * 64,
            "engine_version": "2.0.0",
            "model": {
                "model": "gpt-5.6-sol",
                "parameters": {
                    "reasoning_effort": "xhigh",
                    "service_tier": "priority",
                },
                "provider": "openai",
            },
            "production_configuration_ref": CONFIGURATION_REF,
            "prompt": {
                "digest": "d" * 64,
                "version": "session_retrospective_agent_prompts_v2",
            },
            "schema": "retrospective_execution_contract_v2",
            "transport": {
                "remote_host_context_helper_commitment": "e" * 64,
                "source_transport_schema": "retrospective_source_transport_v2",
            },
            "versions": {
                "detector": "episode_detector_v2",
                "policy": "source_and_partial_policy_v2",
                "redaction": "extractor_redaction_v2",
                "schema": "retrospective_schema_v2",
                "segmentation": "episode_segmentation_v2",
            },
        },
        "publication_role": "standalone",
        "run_ref": RUN_REF,
        "window": {
            "end": "2026-07-13T00:00:00Z",
            "start": "2026-07-06T00:00:00Z",
        },
    }


def review_data() -> dict[str, object]:
    episodes = [
        {
            "episode_ref": EPISODE_TWO,
            "episode_revision_ref": REVISION_TWO,
            "event_counts": {"retry": 1},
            "finding_counts": {"assumption_risk": 1},
            "findings": [
                {
                    "confidence": "high",
                    "evidence_refs": [EVIDENCE_TWO],
                    "kind": "assumption_risk",
                }
            ],
            "lineage_kind": "initial",
            "meaningful_turn_count": 2,
            "model_era": MODEL_ERA,
            "policy_era": POLICY_ERA,
            "review_provenance": [
                {
                    "attempt_ref": ATTEMPT_TWO,
                    "job_kind": "episode_reviewer",
                    "result_hash": REVIEW_HASH_TWO,
                    "result_schema": "episode_review_result_v2",
                    "reviewer_ref": REVIEWER_TWO,
                    "reviewer_slot": "primary",
                }
            ],
            "review_disposition": "reviewed",
            "review_result_hash": REVIEW_HASH_TWO,
            "revision_ordinal": 1,
            "risk_counts": {},
            "session_ref": SESSION_TWO,
            "strength_counts": {"clear_communication": 1},
            "supersedes_episode_revision_ref": None,
        },
        {
            "episode_ref": EPISODE_ONE,
            "episode_revision_ref": REVISION_ONE,
            "event_counts": {"failed_command": 1},
            "finding_counts": {"over_exploration": 1},
            "findings": [
                {
                    "confidence": "high",
                    "evidence_refs": [EVIDENCE_ONE],
                    "kind": "over_exploration",
                }
            ],
            "lineage_kind": "initial",
            "meaningful_turn_count": 2,
            "model_era": MODEL_ERA,
            "policy_era": POLICY_ERA,
            "review_provenance": [
                {
                    "attempt_ref": ATTEMPT_ONE,
                    "job_kind": "episode_reviewer",
                    "result_hash": REVIEW_HASH_ONE,
                    "result_schema": "episode_review_result_v2",
                    "reviewer_ref": REVIEWER_ONE,
                    "reviewer_slot": "primary",
                }
            ],
            "review_disposition": "reviewed",
            "review_result_hash": REVIEW_HASH_ONE,
            "revision_ordinal": 1,
            "risk_counts": {"privacy": 0},
            "session_ref": SESSION_ONE,
            "strength_counts": {"bounded_exploration": 2},
            "supersedes_episode_revision_ref": None,
        },
    ]
    turn_findings = [
        {
            "disposition": "not_high_impact",
            "episode_ref": EPISODE_TWO,
            "model_era": MODEL_ERA,
            "policy_era": POLICY_ERA,
            "turn_ref": TURN_FOUR,
        },
        {
            "disposition": "high_impact",
            "episode_ref": EPISODE_ONE,
            "cause": "The requested recovery boundary was underspecified.",
            "confidence": "high",
            "evidence_refs": [EVIDENCE_ONE],
            "expected_effect": "The bounded operation reduces avoidable rework.",
            "model_era": MODEL_ERA,
            "policy_era": POLICY_ERA,
            "problem_statement": "The requested operation had an ambiguous scope.",
            "rewritten_prompt": "Inspect the scope and preserve a recovery boundary.",
            "turn_ref": TURN_ONE,
        },
        {
            "disposition": "not_high_impact",
            "episode_ref": EPISODE_ONE,
            "model_era": MODEL_ERA,
            "policy_era": POLICY_ERA,
            "turn_ref": TURN_TWO,
        },
        {
            "disposition": "not_high_impact",
            "episode_ref": EPISODE_TWO,
            "model_era": MODEL_ERA,
            "policy_era": POLICY_ERA,
            "turn_ref": TURN_THREE,
        },
    ]
    return {
        "agents_guidance_candidates": {"scope_control": 1},
        "episodes": episodes,
        "follow_up_actions": {"rerun_verification": 1},
        "skill_candidates": {"review_orchestration": 1},
        "topics": [
            {
                "episode_lineage": [
                    {
                        "episode_ref": EPISODE_ONE,
                        "session_ref": SESSION_ONE,
                    },
                    {
                        "episode_ref": EPISODE_TWO,
                        "session_ref": SESSION_TWO,
                    },
                ],
                "episode_refs": [EPISODE_TWO, EPISODE_ONE],
                "findings": [
                    {
                        "confidence": "high",
                        "evidence_refs": [EVIDENCE_TWO],
                        "kind": "assumption_risk",
                    },
                    {
                        "confidence": "high",
                        "evidence_refs": [EVIDENCE_ONE],
                        "kind": "over_exploration",
                    },
                ],
                "model_era": MODEL_ERA,
                "policy_era": POLICY_ERA,
                "topic_ref": TOPIC_ONE,
            }
        ],
        "turn_findings": turn_findings,
    }


def prior_trend() -> dict[str, object]:
    prior_review = review_data()
    prior_review["episodes"] = [copy.deepcopy(prior_review["episodes"][1])]
    prior_review["episodes"][0]["meaningful_turn_count"] = 2
    prior_review["turn_findings"] = [
        copy.deepcopy(prior_review["turn_findings"][1]),
        copy.deepcopy(prior_review["turn_findings"][2]),
    ]
    prior_review["topics"] = []
    prior_state = run_state(meaningful_turn_count=2)
    prior_state["window"] = {
        "end": "2026-07-06T00:00:00Z",
        "start": "2026-06-29T00:00:00Z",
    }
    artifacts = assemble_retained_artifacts(prior_state, prior_review)
    return json.loads(artifacts["trend_report.json"])


def synthesis_data() -> dict[str, object]:
    answers = []
    for question_id in QUESTION_IDS:
        observed = question_id == "what_worked_well"
        answers.append(
            {
                "confidence": "high",
                "disposition": "observed" if observed else "not_observed",
                "event_kinds": [],
                "evidence_refs": [EPISODE_ONE] if observed else [],
                "finding_kinds": [],
                "question_id": question_id,
                "strength_kinds": ["focused_execution"] if observed else [],
            }
        )
    return {
        "confidence": {
            "comparability": "high",
            "coverage": "high",
            "extraction": "high",
            "review": "high",
        },
        "era_comparison": {"change": "unchanged", "status": "compatible"},
        "events": {"failed_command": 1, "retry": 1},
        "evidence_refs": [EPISODE_ONE],
        "findings": [
            {
                "confidence": "high",
                "evidence_refs": [EVIDENCE_TWO],
                "kind": "assumption_risk",
            },
            {
                "confidence": "high",
                "evidence_refs": [EVIDENCE_ONE],
                "kind": "over_exploration",
            },
        ],
        "follow_up_actions": [
            {
                "confidence": "high",
                "evidence_refs": [EPISODE_ONE],
                "kind": "rerun_verification",
            }
        ],
        "guidance_candidates": [
            {
                "confidence": "high",
                "episode_lineage": [
                    {
                        "episode_ref": EPISODE_THREE,
                        "session_ref": SESSION_ONE,
                    },
                    {
                        "episode_ref": EPISODE_ONE,
                        "session_ref": SESSION_ONE,
                    },
                    {
                        "episode_ref": EPISODE_TWO,
                        "session_ref": SESSION_TWO,
                    },
                ],
                "exception": "none",
                "kind": "scope_control",
            }
        ],
        "prompt_rewrites": [
            {
                "cause": "Working-only arbitrary cause text",
                "confidence": "high",
                "evidence_refs": [EPISODE_ONE],
                "expected_effect": "Working-only arbitrary expected effect",
                "problem_statement": "Working-only arbitrary problem statement",
                "rewritten_prompt": "Working-only arbitrary rewritten prompt",
                "turn_ref": TURN_ONE,
            }
        ],
        "question_answers": answers,
        "schema": "global_synthesis_result_v2",
        "skill_candidates": [
            {
                "confidence": "high",
                "episode_lineage": [
                    {
                        "episode_ref": EPISODE_THREE,
                        "session_ref": SESSION_ONE,
                    },
                    {
                        "episode_ref": EPISODE_ONE,
                        "session_ref": SESSION_ONE,
                    },
                    {
                        "episode_ref": EPISODE_TWO,
                        "session_ref": SESSION_TWO,
                    },
                ],
                "exception": "none",
                "kind": "workflow_hygiene",
            }
        ],
        "strengths": {"bounded_exploration": 2, "clear_communication": 1},
    }


def refresh_bundle_digest(artifacts: dict[str, bytes]) -> None:
    manifest = json.loads(artifacts["manifest.json"])
    manifest["retained_bundle_digest_v2"]["value"] = retained_bundle_digest(artifacts)
    artifacts["manifest.json"] = canonical_json_bytes(manifest)


class RetrospectiveV2ReportingTests(unittest.TestCase):
    def test_reporting_remains_directly_loadable_under_isolated_python(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(SCRIPTS_DIR / "retrospective_v2" / "reporting.py"),
            ),
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(b"", completed.stdout)
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(0, completed.returncode)

    def test_assembly_is_deterministic_and_reports_required_metrics(self) -> None:
        previous = prior_trend()
        first = assemble_retained_artifacts(
            run_state(),
            review_data(),
            prior_period={"trend_report": previous},
        )
        reordered = review_data()
        reordered["episodes"] = list(reversed(reordered["episodes"]))
        reordered["turn_findings"] = list(reversed(reordered["turn_findings"]))
        second = assemble_retained_artifacts(
            run_state(),
            reordered,
            prior_period={"trend_report": previous},
        )

        self.assertEqual(tuple(first), RETAINED_ARTIFACT_NAMES)
        self.assertEqual(first, second)
        parsed = validate_retained_artifacts(first)
        trend = parsed["trend_report"]
        self.assertEqual(
            trend["metrics"]["turn_disposition.high_impact"]["rate_per_100"],
            25.0,
        )
        self.assertEqual(
            trend["normalized_changes"]["changes"]["turn_disposition.high_impact"][
                "normalized_change_per_100"
            ],
            -25.0,
        )
        self.assertEqual(trend["confidence"]["comparability"]["score"], 1.0)
        self.assertIn(MODEL_ERA, trend["model_eras"])
        self.assertIn(POLICY_ERA, trend["policy_eras"])
        self.assertEqual(
            retained_bundle_digest(first),
            parsed["manifest"]["retained_bundle_digest_v2"]["value"],
        )
        report = first["report.md"].decode("ascii")
        for index, (_section_id, title) in enumerate(REPORT_SECTIONS, 1):
            self.assertIn(f"## {index}. {title}", report)
        self.assertIn("## Strengths", report)
        self.assertIn("## Four-Dimensional Confidence", report)
        self.assertIn("## Compatible-Period Normalized Changes", report)
        self.assertIn("## Model Era Stratification", report)
        self.assertIn("## Policy Era Stratification", report)
        self.assertIn("## Coverage Gaps", report)
        self.assertIn("## Follow-up Summary", report)

    def test_retains_lineage_review_rewrite_and_execution_provenance(self) -> None:
        state = run_state()
        state["provenance"]["agent_execution"] = {
            "jobs": [
                {
                    "attempts": [
                        {
                            "attempt_ref": ATTEMPT_ONE,
                            "claimed_at": "2026-07-14T12:00:01Z",
                            "completed_at": "2026-07-14T12:00:02Z",
                            "issued_at": "2026-07-14T12:00:00Z",
                            "job_ref": ref("job", "a"),
                            "ordinal": 0,
                            "reason": None,
                            "result_ref": ref("result", "b"),
                            "reviewer_ref": REVIEWER_ONE,
                            "status": "accepted",
                        }
                    ],
                    "job_kind": "episode_reviewer",
                    "partition_commitment": REVISION_ONE,
                    "result_hash": REVIEW_HASH_ONE,
                    "reuse_count": 0,
                    "stage": "episode_review",
                    "status": "accepted",
                    "task_ref": ref("run_input", "c"),
                }
            ],
            "result_count": 1,
            "retry_count": 0,
            "schema": "agent_execution_provenance_v2",
            "task_cache": {"hits": 0, "misses": 1, "reuses": 0},
        }
        reviews = review_data()
        episode = next(
            row for row in reviews["episodes"] if row["episode_ref"] == EPISODE_ONE
        )
        episode.update(
            {
                "episode_revision_ref": REVISION_ONE,
                "lineage_kind": "extension",
                "revision_ordinal": 2,
                "supersedes_episode_revision_ref": REVISION_OLD,
            }
        )

        parsed = validate_retained_artifacts(
            assemble_retained_artifacts(state, reviews)
        )

        retained_episode = next(
            row for row in parsed["episodes"] if row["episode_ref"] == EPISODE_ONE
        )
        self.assertEqual(
            REVISION_OLD, retained_episode["supersedes_episode_revision_ref"]
        )
        self.assertEqual(REVIEW_HASH_ONE, retained_episode["review_result_hash"])
        self.assertEqual(
            ATTEMPT_ONE, retained_episode["review_provenance"][0]["attempt_ref"]
        )
        high_impact = next(
            row
            for row in parsed["turn_findings"]
            if row["disposition"] == "high_impact"
        )
        self.assertEqual(
            "Inspect the scope and preserve a recovery boundary.",
            high_impact["rewritten_prompt"],
        )
        self.assertEqual([EVIDENCE_ONE], high_impact["evidence_refs"])
        provenance = parsed["manifest"]["provenance"]
        self.assertEqual("openai", provenance["model"]["provider"])
        self.assertEqual("xhigh", provenance["model"]["parameters"]["reasoning_effort"])
        self.assertEqual(1, provenance["agent_execution"]["result_count"])
        self.assertEqual(
            REVIEW_HASH_ONE,
            provenance["agent_execution"]["jobs"][0]["result_hash"],
        )
        self.assertEqual(
            {"hits": 0, "misses": 1, "reuses": 0},
            provenance["agent_execution"]["task_cache"],
        )

    def test_rejects_nonconserving_agent_task_cache_metrics(self) -> None:
        artifacts = assemble_retained_artifacts(run_state(), review_data())
        manifest = json.loads(artifacts["manifest.json"])
        manifest["provenance"]["agent_execution"]["task_cache"]["hits"] = 1
        artifacts["manifest.json"] = canonical_json_bytes(manifest)
        refresh_bundle_digest(artifacts)

        with self.assertRaisesRegex(
            RetainedInventoryError,
            "task-cache metrics do not conserve",
        ):
            validate_retained_artifacts(artifacts)

    def test_rejects_incomplete_manifest_execution_provenance(self) -> None:
        state = run_state()
        del state["provenance"]["model"]["provider"]

        with self.assertRaisesRegex(
            RetainedInventoryError,
            "model provenance is incomplete",
        ):
            assemble_retained_artifacts(state, review_data())

    def test_comparability_configuration_comes_only_from_validated_provenance(
        self,
    ) -> None:
        state = run_state()
        state["production_configuration_ref"] = ref("configuration", "a")
        parsed = validate_retained_artifacts(
            assemble_retained_artifacts(state, review_data())
        )
        self.assertEqual(
            CONFIGURATION_REF,
            parsed["trend_report"]["compatibility_key"]["configuration_ref"],
        )

        unavailable = run_state()
        unavailable["provenance"]["production_configuration_ref"] = (
            "configuration_ref_unavailable"
        )
        with self.assertRaisesRegex(
            RetainedInventoryError,
            "unavailable or invalid",
        ):
            assemble_retained_artifacts(unavailable, review_data())

    def test_bundle_validation_binds_comparability_to_provenance(self) -> None:
        artifacts = assemble_retained_artifacts(run_state(), review_data())
        replacement = ref("configuration", "a")
        manifest = json.loads(artifacts["manifest.json"])
        trend = json.loads(artifacts["trend_report.json"])
        manifest["compatibility_key"]["configuration_ref"] = replacement
        trend["compatibility_key"]["configuration_ref"] = replacement
        artifacts["manifest.json"] = canonical_json_bytes(manifest)
        artifacts["trend_report.json"] = canonical_json_bytes(trend)
        refresh_bundle_digest(artifacts)

        with self.assertRaisesRegex(
            RetainedInventoryError,
            "bound to validated provenance",
        ):
            validate_retained_artifacts(artifacts)

    def test_closed_synthesis_is_compiled_without_working_prose(self) -> None:
        reviews = review_data()
        reviews.pop("agents_guidance_candidates")
        reviews.pop("follow_up_actions")
        reviews.pop("skill_candidates")
        reviews["episodes"].append(
            {
                "episode_ref": EPISODE_THREE,
                "episode_revision_ref": REVISION_THREE,
                "event_counts": {},
                "finding_counts": {},
                "findings": [],
                "lineage_kind": "initial",
                "meaningful_turn_count": 0,
                "model_era": MODEL_ERA,
                "policy_era": POLICY_ERA,
                "review_provenance": [
                    {
                        "attempt_ref": ATTEMPT_THREE,
                        "job_kind": "episode_reviewer",
                        "result_hash": REVIEW_HASH_THREE,
                        "result_schema": "episode_review_result_v2",
                        "reviewer_ref": REVIEWER_THREE,
                        "reviewer_slot": "primary",
                    }
                ],
                "review_disposition": "reviewed",
                "review_result_hash": REVIEW_HASH_THREE,
                "revision_ordinal": 1,
                "risk_counts": {},
                "session_ref": SESSION_ONE,
                "strength_counts": {},
                "supersedes_episode_revision_ref": None,
            }
        )
        reviews["topics"][0]["episode_refs"].append(EPISODE_THREE)
        reviews["topics"][0]["episode_lineage"].insert(
            0,
            {
                "episode_ref": EPISODE_THREE,
                "session_ref": SESSION_ONE,
            },
        )
        reviews["synthesis"] = synthesis_data()

        artifacts = assemble_retained_artifacts(run_state(), reviews)
        parsed = validate_retained_artifacts(artifacts)
        sections = parsed["summary"]["report_sections"]
        worked_well = next(
            row for row in sections if row["section_id"] == "what_worked_well"
        )
        self.assertEqual(worked_well["disposition"], "observed")
        self.assertEqual(worked_well["strength_kinds"], ["focused_execution"])
        self.assertEqual(
            parsed["trend_report"]["aggregate_counts"]["agents_guidance_candidates"], 1
        )
        retained_bytes = b"".join(artifacts.values())
        self.assertNotIn(b"Working-only arbitrary", retained_bytes)
        self.assertIn(
            b"Inspect the scope and preserve a recovery boundary.", retained_bytes
        )
        self.assertNotIn(EPISODE_ONE.encode("ascii"), artifacts["report.md"])
        self.assertEqual(
            parsed["summary"]["guidance_candidates"][0]["episode_lineage"],
            synthesis_data()["guidance_candidates"][0]["episode_lineage"],
        )

        tampered = dict(artifacts)
        summary = json.loads(tampered["summary.json"])
        summary["guidance_candidates"][0]["episode_lineage"][0]["session_ref"] = (
            SESSION_TWO
        )
        tampered["summary.json"] = canonical_json_bytes(summary)
        refresh_bundle_digest(tampered)
        with self.assertRaisesRegex(RetainedInventoryError, "not in retained episodes"):
            validate_retained_artifacts(tampered)

    def test_retained_findings_preserve_exact_evidence_at_every_level(self) -> None:
        reviews = review_data()
        reviews["synthesis"] = synthesis_data()
        artifacts = assemble_retained_artifacts(run_state(), reviews)
        parsed = validate_retained_artifacts(artifacts)

        expected = {
            ("assumption_risk", (EVIDENCE_TWO,)),
            ("over_exploration", (EVIDENCE_ONE,)),
        }
        for rows in (
            parsed["episodes"],
            parsed["topics"],
            (parsed["summary"],),
        ):
            retained = {
                (finding["kind"], tuple(finding["evidence_refs"]))
                for row in rows
                for finding in row["findings"]
            }
            self.assertEqual(expected, retained)

        missing = review_data()
        missing["episodes"][0].pop("findings")
        with self.assertRaisesRegex(RetainedInventoryError, "exact finding evidence"):
            assemble_retained_artifacts(run_state(), missing)

        topic_drift = review_data()
        topic_drift["topics"][0]["findings"][0]["evidence_refs"] = [
            ref("evidence", "9")
        ]
        with self.assertRaisesRegex(RetainedInventoryError, "exact episode evidence"):
            assemble_retained_artifacts(run_state(), topic_drift)

        global_drift = review_data()
        synthesis = synthesis_data()
        synthesis["findings"][0]["evidence_refs"] = [ref("evidence", "9")]
        global_drift["synthesis"] = synthesis
        with self.assertRaisesRegex(RetainedInventoryError, "exact topic evidence"):
            assemble_retained_artifacts(run_state(), global_drift)

        tampered = dict(artifacts)
        summary = json.loads(tampered["summary.json"])
        summary["findings"][0]["evidence_refs"] = [ref("evidence", "9")]
        tampered["summary.json"] = canonical_json_bytes(summary)
        refresh_bundle_digest(tampered)
        with self.assertRaisesRegex(RetainedInventoryError, "exact topic evidence"):
            validate_retained_artifacts(tampered)

    def test_retained_global_findings_expand_exact_bounded_commitment(self) -> None:
        reviews = review_data()
        findings = [
            {
                "confidence": "high",
                "evidence_refs": [
                    "evidence_ref_v2:"
                    + hashlib.sha256(
                        f"retained-finding-{index}".encode("ascii")
                    ).hexdigest()
                ],
                "kind": "over_exploration",
            }
            for index in range(70)
        ]
        findings.sort(key=canonical_json_bytes)
        reviews["episodes"][0]["finding_counts"] = {}
        reviews["episodes"][0]["findings"] = []
        reviews["episodes"][1]["finding_counts"] = {"over_exploration": 70}
        reviews["episodes"][1]["findings"] = copy.deepcopy(findings)
        reviews["topics"][0]["findings"] = copy.deepcopy(findings)
        topic_signals = {
            "events": [],
            "findings": copy.deepcopy(findings),
            "strengths": [],
        }
        synthesis = synthesis_data()
        synthesis["events"] = []
        synthesis["findings"] = build_synthesis_signal_exemplars([topic_signals])[
            "findings"
        ]
        synthesis["signal_commitments"] = build_synthesis_signal_commitments(
            [topic_signals]
        )
        synthesis["strengths"] = []
        reviews["synthesis"] = synthesis

        artifacts = assemble_retained_artifacts(run_state(), reviews)
        parsed = validate_retained_artifacts(artifacts)
        self.assertEqual(64, len(synthesis["findings"]))
        self.assertEqual(findings, parsed["summary"]["findings"])

        tampered = copy.deepcopy(reviews)
        tampered["synthesis"]["signal_commitments"]["findings"]["canonical_count"] = 69
        with self.assertRaisesRegex(RetainedInventoryError, "commitment"):
            assemble_retained_artifacts(run_state(), tampered)

    def test_incompatible_era_never_emits_direct_normalized_change(self) -> None:
        previous = prior_trend()
        previous["model_eras"] = {
            "legacy_model_era": next(iter(previous["model_eras"].values()))
        }
        previous["compatibility_key"]["model_eras"] = ["legacy_model_era"]
        for row in previous["compatibility_key"]["model_policy_strata"]:
            row["model_era"] = "legacy_model_era"

        artifacts = assemble_retained_artifacts(
            run_state(),
            review_data(),
            prior_period={"trend_report": previous},
        )
        parsed = validate_retained_artifacts(artifacts)
        comparison = parsed["trend_report"]["normalized_changes"]
        self.assertEqual(comparison["status"], "incompatible")
        self.assertEqual(comparison["changes"], {})
        self.assertIsNone(
            parsed["trend_report"]["confidence"]["comparability"]["score"]
        )
        self.assertIn(b"Status: incompatible", artifacts["report.md"])

    def test_prior_trend_rejects_a_forged_normalized_rate(self) -> None:
        previous = prior_trend()
        metric = previous["metrics"]["turn_disposition.high_impact"]
        metric["rate_per_100"] = float(metric["rate_per_100"] or 0.0) + 1.0

        with self.assertRaisesRegex(RetainedInventoryError, "availability or rate"):
            assemble_retained_artifacts(
                run_state(),
                review_data(),
                prior_period={"trend_report": previous},
            )

    def test_prior_window_must_be_strictly_earlier_and_non_overlapping(self) -> None:
        windows = {
            "same": copy.deepcopy(run_state()["window"]),
            "overlap": {
                "end": "2026-07-07T00:00:00Z",
                "start": "2026-06-30T00:00:00Z",
            },
            "future": {
                "end": "2026-07-20T00:00:00Z",
                "start": "2026-07-13T00:00:00Z",
            },
        }
        for case, window in windows.items():
            with self.subTest(case=case):
                previous = prior_trend()
                previous["window"] = window
                with self.assertRaisesRegex(
                    RetainedInventoryError,
                    "strictly earlier and non-overlapping",
                ):
                    assemble_retained_artifacts(
                        run_state(),
                        review_data(),
                        prior_period={"trend_report": previous},
                    )

    def test_run_state_gap_disables_rates_without_retaining_raw_host(self) -> None:
        state = run_state()
        state["coverage"]["coverage_complete"] = False
        state["gaps"] = [
            {
                "dependency_ref": RUN_REF,
                "gap_ref": ref("run_input", "7"),
                "host": "raw_host_label",
                "reason": "agent_result_gap",
                "repairable": True,
                "source_kind": "active_rollout",
                "stage": "episode_review",
            }
        ]

        artifacts = assemble_retained_artifacts(state, review_data())
        parsed = validate_retained_artifacts(artifacts)
        self.assertFalse(parsed["coverage"]["coverage_complete"])
        self.assertNotIn("host", parsed["coverage"]["gaps"][0])
        self.assertIsNone(
            parsed["trend_report"]["metrics"]["event.failed_command"]["rate_per_100"]
        )
        self.assertNotIn(b"raw_host_label", b"".join(artifacts.values()))

    def test_empty_and_gap_evidence_never_report_high_confidence(self) -> None:
        empty_state = run_state(meaningful_turn_count=0)
        empty_state["coverage"].update(
            {
                "context_only_turn_count": 0,
                "extraction_gap_count": 0,
                "meaningfulness_gap_count": 0,
                "source_units": {
                    "consumed_candidate": 0,
                    "expected": 0,
                    "explicit_gap": 0,
                    "structurally_excluded": 0,
                },
            }
        )
        empty_review = {
            "agents_guidance_candidates": {},
            "episodes": [],
            "follow_up_actions": {},
            "skill_candidates": {},
            "topics": [],
            "turn_findings": [],
        }
        empty = validate_retained_artifacts(
            assemble_retained_artifacts(empty_state, empty_review)
        )["trend_report"]["confidence"]
        self.assertEqual(
            {"unavailable"}, {dimension["level"] for dimension in empty.values()}
        )
        self.assertTrue(all(dimension["score"] is None for dimension in empty.values()))

        all_gap_state = copy.deepcopy(empty_state)
        all_gap_state["coverage"].update(
            {
                "coverage_complete": False,
                "extraction_gap_count": 1,
                "source_units": {
                    "consumed_candidate": 0,
                    "expected": 1,
                    "explicit_gap": 1,
                    "structurally_excluded": 0,
                },
            }
        )
        all_gap = validate_retained_artifacts(
            assemble_retained_artifacts(all_gap_state, empty_review)
        )["trend_report"]["confidence"]
        self.assertEqual("low", all_gap["coverage"]["level"])
        self.assertEqual("low", all_gap["extraction"]["level"])
        self.assertNotIn("high", {dimension["level"] for dimension in all_gap.values()})

        gap_state = run_state()
        gap_state["coverage"]["coverage_complete"] = False
        gap_state["coverage"]["meaningfulness_gap_count"] = 1
        parsed = validate_retained_artifacts(
            assemble_retained_artifacts(gap_state, review_data())
        )
        extraction = parsed["trend_report"]["confidence"]["extraction"]
        self.assertEqual(
            {"denominator": 6, "numerator": 5},
            {
                "denominator": extraction["denominator"],
                "numerator": extraction["numerator"],
            },
        )
        self.assertNotEqual("high", extraction["level"])

    def test_episode_review_gap_disables_event_rates_and_review_confidence(
        self,
    ) -> None:
        state = run_state()
        state["coverage"]["coverage_complete"] = False
        reviews = review_data()
        episode = next(
            row for row in reviews["episodes"] if row["episode_ref"] == EPISODE_TWO
        )
        episode.update(
            {
                "event_counts": {},
                "finding_counts": {},
                "findings": [],
                "review_disposition": "review_gap",
                "review_provenance": [],
                "review_result_hash": None,
                "risk_counts": {},
                "strength_counts": {},
            }
        )
        for row in reviews["turn_findings"]:
            if row["episode_ref"] == EPISODE_TWO:
                row["disposition"] = "turn_review_gap"
        reviews["topics"] = []

        parsed = validate_retained_artifacts(
            assemble_retained_artifacts(state, reviews)
        )
        trend = parsed["trend_report"]
        self.assertFalse(trend["metrics"]["event.failed_command"]["available"])
        self.assertEqual(
            "episode_review_coverage_gap",
            trend["metrics"]["event.failed_command"]["unavailable_reason"],
        )
        self.assertEqual("low", trend["confidence"]["review"]["level"])

    def test_review_confidence_uses_conservative_episode_completion_rate(
        self,
    ) -> None:
        state = run_state()
        state["coverage"]["coverage_complete"] = False
        reviews = review_data()
        episode = next(
            row for row in reviews["episodes"] if row["episode_ref"] == EPISODE_TWO
        )
        episode.update(
            {
                "event_counts": {},
                "finding_counts": {},
                "findings": [],
                "review_disposition": "review_gap",
                "review_provenance": [],
                "review_result_hash": None,
                "risk_counts": {},
                "strength_counts": {},
            }
        )
        reviews["topics"] = []

        confidence = validate_retained_artifacts(
            assemble_retained_artifacts(state, reviews)
        )["trend_report"]["confidence"]["review"]
        self.assertEqual(
            {
                "denominator": 2,
                "level": "low",
                "numerator": 1,
                "score": 0.5,
            },
            confidence,
        )

    def test_zero_transition_metrics_cover_prior_only_and_current_only_categories(
        self,
    ) -> None:
        previous = prior_trend()
        current = review_data()
        episode_one = next(
            row for row in current["episodes"] if row["episode_ref"] == EPISODE_ONE
        )
        episode_one["event_counts"] = {}

        parsed = validate_retained_artifacts(
            assemble_retained_artifacts(
                run_state(),
                current,
                prior_period={"trend_report": previous},
            )
        )
        trend = parsed["trend_report"]
        failed = trend["normalized_changes"]["changes"]["event.failed_command"]
        retry = trend["normalized_changes"]["changes"]["event.retry"]
        self.assertEqual("prior_only", failed["category_presence"])
        self.assertEqual(0.0, failed["current_rate_per_100"])
        self.assertLess(failed["normalized_change_per_100"], 0.0)
        self.assertEqual("current_only", retry["category_presence"])
        self.assertEqual(0.0, retry["prior_rate_per_100"])
        self.assertGreater(retry["normalized_change_per_100"], 0.0)

    def test_mixed_and_unknown_joint_eras_never_compare_aggregate_rates(self) -> None:
        def era_data(first: tuple[str, str], second: tuple[str, str]):
            reviews = review_data()
            for episode in reviews["episodes"]:
                model, policy = (
                    first if episode["episode_ref"] == EPISODE_ONE else second
                )
                episode["model_era"] = model
                episode["policy_era"] = policy
            episode_eras = {
                row["episode_ref"]: (row["model_era"], row["policy_era"])
                for row in reviews["episodes"]
            }
            for turn in reviews["turn_findings"]:
                turn["model_era"], turn["policy_era"] = episode_eras[
                    turn["episode_ref"]
                ]
            reviews["topics"][0]["model_era"] = first[0]
            reviews["topics"][0]["policy_era"] = first[1]
            return reviews

        current_state = run_state()
        current_state["model_eras"] = ["model_a", "model_b"]
        current_state["policy_eras"] = ["policy_x", "policy_y"]
        current_reviews = era_data(("model_a", "policy_x"), ("model_b", "policy_y"))
        prior_state = copy.deepcopy(current_state)
        prior_state["window"] = {
            "end": "2026-07-06T00:00:00Z",
            "start": "2026-06-29T00:00:00Z",
        }
        prior_reviews = era_data(("model_a", "policy_y"), ("model_b", "policy_x"))
        prior = json.loads(
            assemble_retained_artifacts(prior_state, prior_reviews)["trend_report.json"]
        )
        parsed = validate_retained_artifacts(
            assemble_retained_artifacts(
                current_state,
                current_reviews,
                prior_period={"trend_report": prior},
            )
        )
        comparison = parsed["trend_report"]["normalized_changes"]
        strata = parsed["trend_report"]["model_eras"]
        self.assertEqual(1, strata["model_a"]["meaningful_episode_count"])
        self.assertEqual(2, strata["model_a"]["meaningful_turn_count"])
        self.assertEqual(1, strata["model_b"]["meaningful_episode_count"])
        self.assertEqual(2, strata["model_b"]["meaningful_turn_count"])
        for stratum in strata.values():
            for metric_id in (
                "agents_guidance_candidates",
                "follow_up_actions",
                "skill_candidates",
            ):
                metric = stratum["metrics"][metric_id]
                self.assertEqual(0, metric["count"])
                self.assertFalse(metric["available"])
                self.assertEqual(
                    "missing_era_lineage",
                    metric["unavailable_reason"],
                )
        self.assertEqual("incompatible", comparison["status"])
        self.assertEqual("mixed_model_policy_strata", comparison["reason"])
        self.assertEqual({}, comparison["changes"])

        unknown_state = run_state()
        unknown_state["model_eras"] = ["unknown_model_era"]
        unknown_reviews = review_data()
        for family in ("episodes", "topics", "turn_findings"):
            for row in unknown_reviews[family]:
                row["model_era"] = "unknown_model_era"
        unknown_prior_state = copy.deepcopy(unknown_state)
        unknown_prior_state["window"] = {
            "end": "2026-07-06T00:00:00Z",
            "start": "2026-06-29T00:00:00Z",
        }
        unknown_prior = json.loads(
            assemble_retained_artifacts(unknown_prior_state, unknown_reviews)[
                "trend_report.json"
            ]
        )
        unknown = validate_retained_artifacts(
            assemble_retained_artifacts(
                unknown_state,
                unknown_reviews,
                prior_period={"trend_report": unknown_prior},
            )
        )["trend_report"]["normalized_changes"]
        self.assertEqual("unknown_model_or_policy_era", unknown["reason"])
        self.assertEqual({}, unknown["changes"])

    def test_manifest_rejects_unknown_fields_even_with_recomputed_digest(self) -> None:
        artifacts = assemble_retained_artifacts(run_state(), review_data())
        tampered = dict(artifacts)
        manifest = json.loads(tampered["manifest.json"])
        manifest["unexpected_count"] = 1
        tampered["manifest.json"] = canonical_json_bytes(manifest)
        manifest["retained_bundle_digest_v2"]["value"] = retained_bundle_digest(
            tampered
        )
        tampered["manifest.json"] = canonical_json_bytes(manifest)

        with self.assertRaises(RetainedInventoryError):
            validate_retained_artifacts(tampered)

    def test_assembly_rejects_raw_excerpt_and_arbitrary_prose(self) -> None:
        for field in ("raw_excerpt", "original_prompt", "tool_output"):
            with self.subTest(field=field):
                raw_review = review_data()
                raw_review["episodes"][0][field] = "source_literal"
                with self.assertRaises(RetainedPrivacyError):
                    assemble_retained_artifacts(run_state(), raw_review)

        prose_review = review_data()
        prose_review["turn_findings"][0]["summary"] = "apparently_safe_but_unreviewed"
        with self.assertRaises(RetainedPrivacyError):
            assemble_retained_artifacts(run_state(), prose_review)

        locator_review = review_data()
        locator_review["turn_findings"][1]["rewritten_prompt"] = (
            "Inspect https://internal.example.invalid before continuing."
        )
        with self.assertRaisesRegex(RetainedPrivacyError, "URL"):
            assemble_retained_artifacts(run_state(), locator_review)

        bare_locator_review = review_data()
        bare_locator_review["turn_findings"][1]["rewritten_prompt"] = (
            "Inspect jira.cisco.example before continuing."
        )
        with self.assertRaisesRegex(RetainedPrivacyError, "URL"):
            assemble_retained_artifacts(run_state(), bare_locator_review)

        for network_locator in (
            "localhost",
            "10.0.0.1",
            "203.0.113.7",
            "2001:db8::1",
            "::",
        ):
            contexts = [f"Inspect {network_locator} before continuing."]
            if network_locator == "::":
                contexts.append('He wrote "Inspect ::."')
            for context in contexts:
                with self.subTest(
                    network_locator=network_locator,
                    context=context,
                    phase="assembly",
                ):
                    network_review = review_data()
                    network_review["turn_findings"][1]["rewritten_prompt"] = context
                    with self.assertRaisesRegex(RetainedPrivacyError, "IP address"):
                        assemble_retained_artifacts(run_state(), network_review)

                with self.subTest(
                    network_locator=network_locator,
                    context=context,
                    phase="reread",
                ):
                    network_artifacts = assemble_retained_artifacts(
                        run_state(), review_data()
                    )
                    network_tampered = dict(network_artifacts)
                    network_rows = [
                        json.loads(line)
                        for line in network_tampered["turn_findings.jsonl"].splitlines()
                    ]
                    network_high_impact = next(
                        row
                        for row in network_rows
                        if row["disposition"] == "high_impact"
                    )
                    network_high_impact["rewritten_prompt"] = context
                    network_tampered["turn_findings.jsonl"] = b"".join(
                        canonical_json_bytes(row) for row in network_rows
                    )
                    refresh_bundle_digest(network_tampered)
                    with self.assertRaisesRegex(RetainedPrivacyError, "IP address"):
                        validate_retained_artifacts(network_tampered)

        syntax_review = review_data()
        syntax_text = "Keep Python 3.13:: section and field:1:: marker unchanged."
        syntax_review["turn_findings"][1]["rewritten_prompt"] = syntax_text
        syntax_artifacts = assemble_retained_artifacts(run_state(), syntax_review)
        syntax_rows = [
            json.loads(line)
            for line in syntax_artifacts["turn_findings.jsonl"].splitlines()
        ]
        syntax_high_impact = next(
            row for row in syntax_rows if row["disposition"] == "high_impact"
        )
        self.assertEqual(syntax_text, syntax_high_impact["rewritten_prompt"])
        validate_retained_artifacts(syntax_artifacts)

        artifacts = assemble_retained_artifacts(run_state(), review_data())
        tampered = dict(artifacts)
        rows = [
            json.loads(line) for line in tampered["turn_findings.jsonl"].splitlines()
        ]
        high_impact = next(row for row in rows if row["disposition"] == "high_impact")
        high_impact["rewritten_prompt"] = (
            "Inspect jira.cisco.example before continuing."
        )
        tampered["turn_findings.jsonl"] = b"".join(
            canonical_json_bytes(row) for row in rows
        )
        refresh_bundle_digest(tampered)
        with self.assertRaisesRegex(RetainedPrivacyError, "URL"):
            validate_retained_artifacts(tampered)

        path_review = review_data()
        path_review["turn_findings"][1]["rewritten_prompt"] = (
            "Inspect /root/acme/customer.txt before continuing."
        )
        with self.assertRaisesRegex(RetainedPrivacyError, "local path"):
            assemble_retained_artifacts(run_state(), path_review)

        for field in (
            "problem_statement",
            "cause",
            "rewritten_prompt",
            "expected_effect",
        ):
            with self.subTest(relative_path_field=field):
                relative_path_review = review_data()
                relative_path_review["turn_findings"][1][field] = (
                    "Inspect src/a.py before continuing."
                )
                with self.assertRaisesRegex(RetainedPrivacyError, "local path"):
                    assemble_retained_artifacts(run_state(), relative_path_review)

                artifacts = assemble_retained_artifacts(run_state(), review_data())
                tampered = dict(artifacts)
                rows = [
                    json.loads(line)
                    for line in tampered["turn_findings.jsonl"].splitlines()
                ]
                high_impact = next(
                    row for row in rows if row["disposition"] == "high_impact"
                )
                high_impact[field] = "Inspect src/a.py before continuing."
                tampered["turn_findings.jsonl"] = b"".join(
                    canonical_json_bytes(row) for row in rows
                )
                refresh_bundle_digest(tampered)
                with self.assertRaisesRegex(RetainedPrivacyError, "local path"):
                    validate_retained_artifacts(tampered)

        for network_locator, report_line in (
            ("203.0.113.7", "Inspect 203.0.113.7."),
            ("::", "Inspect ::."),
            ("::", 'He wrote "Inspect ::."'),
        ):
            with self.subTest(
                network_locator=network_locator,
                report_line=report_line,
                phase="report",
            ):
                report_artifacts = assemble_retained_artifacts(
                    run_state(), review_data()
                )
                report_tampered = dict(report_artifacts)
                report_tampered["report.md"] += f"\n{report_line}\n".encode("ascii")
                refresh_bundle_digest(report_tampered)
                with self.assertRaisesRegex(RetainedPrivacyError, "forbidden locator"):
                    validate_retained_artifacts(report_tampered)

    def test_non_http_uri_schemes_are_rejected_before_and_after_assembly(self) -> None:
        prefixed_mixed_scheme_uri = f"locator_a{'9' * 32}+.-x://?prod-build-queue"
        for uri in (
            "x://private-endpoint/resource",
            "wss://build.internal/events",
            "s3://private-bucket/report",
            "postgresql://database.internal/history",
            prefixed_mixed_scheme_uri,
        ):
            with self.subTest(uri=uri, phase="assembly"):
                unsafe = review_data()
                unsafe["turn_findings"][1]["rewritten_prompt"] = (
                    f"Inspect {uri} before continuing."
                )
                with self.assertRaisesRegex(RetainedPrivacyError, "URL"):
                    assemble_retained_artifacts(run_state(), unsafe)

            with self.subTest(uri=uri, phase="retained-reread"):
                artifacts = assemble_retained_artifacts(run_state(), review_data())
                tampered = dict(artifacts)
                rows = [
                    json.loads(line)
                    for line in tampered["turn_findings.jsonl"].splitlines()
                ]
                high_impact = next(
                    row for row in rows if row["disposition"] == "high_impact"
                )
                high_impact["rewritten_prompt"] = f"Inspect {uri} before continuing."
                tampered["turn_findings.jsonl"] = b"".join(
                    canonical_json_bytes(row) for row in rows
                )
                refresh_bundle_digest(tampered)
                with self.assertRaisesRegex(RetainedPrivacyError, "URL"):
                    validate_retained_artifacts(tampered)

            with self.subTest(uri=uri, phase="report"):
                artifacts = assemble_retained_artifacts(run_state(), review_data())
                tampered = dict(artifacts)
                tampered["report.md"] += f"\nInspect {uri} before continuing.\n".encode(
                    "ascii"
                )
                refresh_bundle_digest(tampered)
                with self.assertRaisesRegex(RetainedPrivacyError, "forbidden locator"):
                    validate_retained_artifacts(tampered)

        untyped_review = review_data()
        untyped_review["turn_findings"][0]["note"] = "source_literal"
        with self.assertRaises(RetainedPrivacyError):
            assemble_retained_artifacts(run_state(), untyped_review)

    def test_reviewed_prose_rejects_source_payload_and_internal_id_markers(
        self,
    ) -> None:
        probes = (
            "Original prompt: delete all records now.",
            "Tool output: status=failed.",
            "Please delete all records now.",
            "Inspect session_id=019e4eac-db79-7410-824f-d326575c2ac8.",
        )
        for probe in probes:
            with self.subTest(probe=probe):
                artifacts = assemble_retained_artifacts(run_state(), review_data())
                tampered = dict(artifacts)
                rows = [
                    json.loads(line)
                    for line in tampered["turn_findings.jsonl"].splitlines()
                ]
                high_impact = next(
                    row for row in rows if row["disposition"] == "high_impact"
                )
                high_impact["rewritten_prompt"] = probe
                tampered["turn_findings.jsonl"] = b"".join(
                    canonical_json_bytes(row) for row in rows
                )
                refresh_bundle_digest(tampered)

                with self.assertRaisesRegex(
                    RetainedPrivacyError,
                    "derived-summary retained content policy",
                ):
                    validate_retained_artifacts(tampered)

        parsed = validate_retained_artifacts(
            assemble_retained_artifacts(run_state(), review_data())
        )
        useful = next(
            row
            for row in parsed["turn_findings"]
            if row["disposition"] == "high_impact"
        )
        self.assertEqual(
            "Inspect the scope and preserve a recovery boundary.",
            useful["rewritten_prompt"],
        )

    def test_customer_identifier_is_rejected_in_assembly_and_final_validation(
        self,
    ) -> None:
        customer_review = review_data()
        customer_review["episodes"][0]["customer_id"] = "AcmeSecret"
        with self.assertRaises(RetainedPrivacyError):
            assemble_retained_artifacts(run_state(), customer_review)

        artifacts = assemble_retained_artifacts(run_state(), review_data())
        tampered = dict(artifacts)
        rows = [json.loads(line) for line in tampered["episodes.jsonl"].splitlines()]
        rows[0]["customer_id"] = "AcmeSecret"
        tampered["episodes.jsonl"] = b"".join(canonical_json_bytes(row) for row in rows)
        manifest = json.loads(tampered["manifest.json"])
        manifest["retained_bundle_digest_v2"]["value"] = retained_bundle_digest(
            tampered
        )
        tampered["manifest.json"] = canonical_json_bytes(manifest)
        with self.assertRaises(RetainedPrivacyError):
            validate_retained_artifacts(tampered)

    def test_closed_taxonomy_rejects_arbitrary_safe_tokens(self) -> None:
        invalid_review = review_data()
        invalid_review["episodes"][0]["strength_counts"] = {"customer_project": 1}
        with self.assertRaises(RetainedInventoryError):
            assemble_retained_artifacts(run_state(), invalid_review)

        artifacts = assemble_retained_artifacts(run_state(), review_data())
        tampered = dict(artifacts)
        trend = json.loads(tampered["trend_report.json"])
        trend["aggregate_counts"]["strengths"] = {"customer_project": 1}
        tampered["trend_report.json"] = canonical_json_bytes(trend)
        manifest = json.loads(tampered["manifest.json"])
        manifest["retained_bundle_digest_v2"]["value"] = retained_bundle_digest(
            tampered
        )
        tampered["manifest.json"] = canonical_json_bytes(manifest)
        with self.assertRaises(RetainedInventoryError):
            validate_retained_artifacts(tampered)

    def test_turn_inventory_must_match_meaningful_coverage(self) -> None:
        state = run_state()
        state["coverage"]["meaningful_turn_refs"] = [TURN_ONE, TURN_TWO, TURN_THREE]
        with self.assertRaises(RetainedInventoryError):
            assemble_retained_artifacts(state, review_data())

    def test_synthesis_categories_must_reconcile_with_episode_rows(self) -> None:
        reviews = review_data()
        synthesis = synthesis_data()
        synthesis["strengths"] = {"focused_execution": 1}
        reviews["synthesis"] = synthesis

        with self.assertRaisesRegex(RetainedInventoryError, "does not reconcile"):
            assemble_retained_artifacts(run_state(), reviews)

    def test_rows_cannot_introduce_undeclared_model_or_policy_eras(self) -> None:
        state = run_state()
        state["model_eras"] = [MODEL_ERA]
        state["policy_eras"] = [POLICY_ERA]
        reviews = review_data()
        reviews["episodes"][0]["model_era"] = "undeclared_model_era"
        for turn in reviews["turn_findings"]:
            if turn["episode_ref"] == reviews["episodes"][0]["episode_ref"]:
                turn["model_era"] = "undeclared_model_era"

        with self.assertRaisesRegex(RetainedInventoryError, "not a declared era"):
            assemble_retained_artifacts(state, reviews)

    def test_turn_era_must_match_its_episode_lineage(self) -> None:
        state = run_state()
        state["model_eras"] = [MODEL_ERA, "next_model_era"]
        reviews = review_data()
        reviews["turn_findings"][0]["model_era"] = "next_model_era"

        with self.assertRaisesRegex(
            RetainedInventoryError,
            "does not match its episode era lineage",
        ):
            assemble_retained_artifacts(state, reviews)

    def test_compatibility_eras_and_strata_exactly_reconcile(self) -> None:
        artifacts = assemble_retained_artifacts(run_state(), review_data())
        parsed = validate_retained_artifacts(artifacts)
        trend = parsed["trend_report"]
        compatibility = trend["compatibility_key"]
        self.assertEqual(compatibility["model_eras"], sorted(trend["model_eras"]))
        self.assertEqual(compatibility["policy_eras"], sorted(trend["policy_eras"]))

        stratified_metric_ids = set(trend["metrics"])
        self.assertTrue(
            {
                "agents_guidance_candidates",
                "follow_up_actions",
                "skill_candidates",
            }
            <= stratified_metric_ids
        )
        for field in ("model_eras", "policy_eras"):
            for metric_id in stratified_metric_ids:
                strata = [row["metrics"][metric_id] for row in trend[field].values()]
                self.assertEqual(
                    sum(row["count"] for row in strata),
                    trend["metrics"][metric_id]["count"],
                )
                self.assertEqual(
                    sum(row["denominator"] for row in strata),
                    trend["metrics"][metric_id]["denominator"],
                )

    def test_validator_rejects_compatibility_or_stratum_drift(self) -> None:
        artifacts = assemble_retained_artifacts(run_state(), review_data())
        incompatible = dict(artifacts)
        trend = json.loads(incompatible["trend_report.json"])
        trend["compatibility_key"]["model_eras"].append("unused_model_era")
        incompatible["trend_report.json"] = canonical_json_bytes(trend)
        manifest = json.loads(incompatible["manifest.json"])
        manifest["compatibility_key"] = copy.deepcopy(trend["compatibility_key"])
        incompatible["manifest.json"] = canonical_json_bytes(manifest)
        refresh_bundle_digest(incompatible)
        with self.assertRaisesRegex(RetainedInventoryError, "actual strata"):
            validate_retained_artifacts(incompatible)

        drifted = dict(artifacts)
        trend = json.loads(drifted["trend_report.json"])
        metric = trend["model_eras"][MODEL_ERA]["metrics"][
            "turn_disposition.high_impact"
        ]
        metric["count"] += 1
        metric["rate_per_100"] = round(
            metric["count"] * 100.0 / metric["denominator"], 2
        )
        drifted["trend_report.json"] = canonical_json_bytes(trend)
        refresh_bundle_digest(drifted)
        with self.assertRaisesRegex(RetainedInventoryError, "not reproducible"):
            validate_retained_artifacts(drifted)

    def test_retained_input_budgets_apply_before_json_parsing(self) -> None:
        artifacts = assemble_retained_artifacts(run_state(), review_data())
        with (
            mock.patch.object(reporting_module, "MAX_RETAINED_BUNDLE_BYTES", 1),
            mock.patch.object(reporting_module, "_json_loads_no_duplicates") as parse,
        ):
            with self.assertRaisesRegex(RetainedInventoryError, "aggregate limit"):
                validate_retained_artifacts(artifacts)
            parse.assert_not_called()

        wrong_type = dict(artifacts)
        wrong_type["report.md"] = bytearray(wrong_type["report.md"])
        with mock.patch.object(reporting_module, "_json_loads_no_duplicates") as parse:
            with self.assertRaisesRegex(RetainedInventoryError, "immutable bytes"):
                validate_retained_artifacts(wrong_type)
            parse.assert_not_called()

        with mock.patch.object(reporting_module, "MAX_JSONL_ROWS", 1):
            with self.assertRaisesRegex(RetainedInventoryError, "JSONL row limit"):
                validate_retained_artifacts(artifacts)
        with mock.patch.object(reporting_module, "MAX_JSON_DEPTH", 2):
            with self.assertRaisesRegex(RetainedInventoryError, "nesting depth"):
                reporting_module._json_loads_no_duplicates(
                    b'{"a":{"b":{"c":1}}}\n', label="deep.json"
                )


class RetrospectiveV2ExportTests(unittest.TestCase):
    def test_artifact_hardening_precedes_the_first_payload_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            hardened = False
            real_harden = (
                export_module.safe_io.harden_created_owner_only_file_descriptor
            )
            real_write = os.write

            def observe_hardening(*args, **kwargs) -> None:
                nonlocal hardened
                real_harden(*args, **kwargs)
                hardened = True

            def reject_unhardened_write(descriptor: int, content: bytes) -> int:
                if not hardened:
                    raise AssertionError("payload reached an unhardened artifact")
                return real_write(descriptor, content)

            try:
                with (
                    mock.patch.object(
                        export_module.safe_io,
                        "harden_created_owner_only_file_descriptor",
                        side_effect=observe_hardening,
                    ),
                    mock.patch.object(
                        export_module.os,
                        "write",
                        side_effect=reject_unhardened_write,
                    ),
                ):
                    export_module._write_artifact_at(
                        directory_fd,
                        "artifact.json",
                        b"{}\n",
                        display_path=root / "artifact.json",
                    )
            finally:
                os.close(directory_fd)

            self.assertTrue(hardened)
            self.assertEqual((root / "artifact.json").read_bytes(), b"{}\n")

    def test_artifact_read_rejects_late_access_policy_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            display_path = root / "artifact.json"
            export_module._write_artifact_at(
                directory_fd,
                "artifact.json",
                b"{}\n",
                display_path=display_path,
            )
            real_validate = export_module.safe_io.validate_owner_only_file_descriptor
            validation_count = 0

            def change_after_read(*args, **kwargs) -> None:
                nonlocal validation_count
                validation_count += 1
                if validation_count == 2:
                    raise export_module.safe_io.UnsafePathError(
                        "simulated late ACL drift"
                    )
                real_validate(*args, **kwargs)

            try:
                with (
                    mock.patch.object(
                        export_module.safe_io,
                        "validate_owner_only_file_descriptor",
                        side_effect=change_after_read,
                    ),
                    self.assertRaisesRegex(
                        RetainedInventoryError,
                        "access policy changed while read",
                    ),
                ):
                    export_module._read_artifact_at(
                        directory_fd,
                        "artifact.json",
                        display_path=display_path,
                    )
            finally:
                os.close(directory_fd)

            self.assertEqual(validation_count, 2)

    def test_export_is_owner_only_atomic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = (
                Path(temporary)
                / ".codex-local"
                / "session-retrospective-v2"
                / "runs"
                / "weekly"
                / "publication-staging"
                / "retained-v2"
            )
            state = run_state()
            reviews = review_data()
            original_state = copy.deepcopy(state)
            original_reviews = copy.deepcopy(reviews)
            first = export_retained_bundle(output, state, reviews)
            mtimes = {path.name: path.stat().st_mtime_ns for path in output.iterdir()}
            second = export_retained_bundle(output, state, reviews)

            self.assertFalse(first["idempotent"])
            self.assertTrue(second["idempotent"])
            self.assertFalse(first["git_commit_created"])
            self.assertFalse(first["state_advanced"])
            self.assertEqual(state, original_state)
            self.assertEqual(reviews, original_reviews)
            self.assertEqual(
                mtimes,
                {path.name: path.stat().st_mtime_ns for path in output.iterdir()},
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(
                set(path.name for path in output.iterdir()),
                set(RETAINED_ARTIFACT_NAMES),
            )
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            validation = validate_staged_export(output)
            self.assertEqual(validation["bundle_digest"], first["bundle_digest"])
            self.assertEqual(
                compute_retained_bundle_digest(output), first["bundle_digest"]
            )

            symlink = output.parent / "retained-v2-symlink"
            symlink.symlink_to(output, target_is_directory=True)
            with self.assertRaises(ExportLocationError):
                validate_staged_export(symlink)
            with self.assertRaises(ExportLocationError):
                export_retained_bundle(symlink, run_state(), review_data())

    def test_export_rejects_outside_ignored_area_and_conflicting_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary) / "retained-v2"
            with self.assertRaises(ExportLocationError):
                export_retained_bundle(outside, run_state(), review_data())

            output = Path(temporary) / ".codex-local" / "run" / "retained-v2"
            export_retained_bundle(output, run_state(), review_data())
            changed = review_data()
            changed["episodes"][0]["strength_counts"] = {"clear_communication": 2}
            with self.assertRaises(ExportConflictError):
                export_retained_bundle(output, run_state(), changed)

    def test_staged_validation_rejects_extra_files_and_weak_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / ".codex-local" / "run" / "retained-v2"
            export_retained_bundle(output, run_state(), review_data())
            extra = output / "receipt.json"
            extra.write_text("{}\n", encoding="ascii")
            with self.assertRaises(RetainedInventoryError):
                validate_staged_export(output)
            extra.unlink()

            manifest = output / "manifest.json"
            hard_link = output.parent / "manifest-hard-link"
            os.link(manifest, hard_link)
            with self.assertRaises(RetainedInventoryError):
                validate_staged_export(output)
            hard_link.unlink()

            os.chmod(manifest, 0o644)
            with self.assertRaises(RetainedInventoryError):
                validate_staged_export(output)

    def test_retention_deadline_is_immutable_and_gc_removes_only_expired_export(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "retention"
            output = root / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            deadline = now + dt.timedelta(hours=2)
            receipt = export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
                retention_deadline=deadline,
            )

            self.assertEqual(receipt["retention_deadline"], "2026-07-15T02:00:00Z")
            retry = export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now + dt.timedelta(hours=1),
                retention_deadline=deadline,
            )
            self.assertTrue(retry["idempotent"])
            with self.assertRaises(ExportConflictError):
                export_retained_bundle(
                    output,
                    run_state(),
                    review_data(),
                    now=now,
                    retention_deadline=deadline + dt.timedelta(hours=1),
                )

            before = garbage_collect_expired_exports(
                root,
                now=deadline - dt.timedelta(seconds=1),
            )
            self.assertEqual(before["deleted"], [])
            self.assertTrue(output.exists())
            after = garbage_collect_expired_exports(
                root,
                now=deadline,
            )
            self.assertEqual(after["deleted"], [str(output.resolve())])
            self.assertFalse(output.exists())

    def test_gc_collects_installed_bundle_orphan_after_maximum_retention(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "installed-orphan"
            output = root / "retained-v2"
            exported_at = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=exported_at,
                retention_deadline=exported_at + dt.timedelta(hours=1),
            )
            (root / ".retained-v2.retention-v2.json").unlink()
            timestamp = exported_at.timestamp()
            os.utime(output, (timestamp, timestamp), follow_symlinks=False)

            before = garbage_collect_expired_exports(
                root,
                now=exported_at
                + export_module.MAX_EXPORT_RETENTION
                - dt.timedelta(seconds=1),
            )
            self.assertEqual(before["retained"], [str(output.resolve())])
            self.assertTrue(output.is_dir())

            after = garbage_collect_expired_exports(
                root,
                now=exported_at + export_module.MAX_EXPORT_RETENTION,
            )
            self.assertEqual(after["deleted"], [str(output.resolve())])
            self.assertFalse(output.exists())

    def test_gc_collects_partial_hidden_staging_orphan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "temporary-orphan"
            root.mkdir(mode=0o700, parents=True)
            staging = root / f".retained-v2.staging-123-{'a' * 24}"
            staging.mkdir(mode=0o700)
            artifact = staging / "manifest.json"
            artifact.write_bytes(b"{}\n")
            os.chmod(artifact, 0o600)
            created_at = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            timestamp = created_at.timestamp()
            os.utime(staging, (timestamp, timestamp), follow_symlinks=False)

            result = garbage_collect_expired_exports(
                root,
                now=created_at + export_module.MAX_EXPORT_RETENTION,
            )

            self.assertEqual(result["deleted"], [str(staging.resolve())])
            self.assertFalse(staging.exists())

    def test_gc_does_not_check_deadline_inside_delete_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "gc-delete-commit"
            root.mkdir(mode=0o700, parents=True)
            staging = root / f".retained-v2.staging-123-{'b' * 24}"
            staging.mkdir(mode=0o700)
            artifact = staging / "manifest.json"
            artifact.write_bytes(b"{}\n")
            os.chmod(artifact, 0o600)
            created_at = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            timestamp = created_at.timestamp()
            os.utime(staging, (timestamp, timestamp), follow_symlinks=False)

            real_checkpoint = export_module._GcBudget.checkpoint
            real_remove = export_module.safe_io.secure_remove_tree_at
            real_fsync = os.fsync
            delete_pending = False
            delete_fsynced = False

            def guarded_checkpoint(budget) -> None:
                if delete_pending and not delete_fsynced:
                    self.fail("GC checked its deadline inside a delete commit")
                real_checkpoint(budget)

            def tracked_remove(*args, **kwargs) -> None:
                nonlocal delete_pending
                real_remove(*args, **kwargs)
                delete_pending = True

            def tracked_fsync(descriptor: int) -> None:
                nonlocal delete_fsynced
                real_fsync(descriptor)
                if delete_pending:
                    delete_fsynced = True

            with (
                mock.patch.object(
                    export_module._GcBudget,
                    "checkpoint",
                    guarded_checkpoint,
                ),
                mock.patch.object(
                    export_module.safe_io,
                    "secure_remove_tree_at",
                    side_effect=tracked_remove,
                ),
                mock.patch.object(
                    export_module.os,
                    "fsync",
                    side_effect=tracked_fsync,
                ),
            ):
                result = garbage_collect_expired_exports(
                    root,
                    now=created_at + export_module.MAX_EXPORT_RETENTION,
                )

            self.assertTrue(delete_pending)
            self.assertTrue(delete_fsynced)
            self.assertEqual([str(staging.resolve())], result["deleted"])
            self.assertFalse(staging.exists())

    def test_gc_reports_wide_tree_entry_budget_exhaustion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "wide-gc"
            root.mkdir(mode=0o700, parents=True)
            for index in range(4):
                (root / f"branch-{index}").mkdir(mode=0o700)

            with mock.patch.object(export_module, "_GC_MAX_ENTRIES", 3):
                result = garbage_collect_expired_exports(root)

            self.assertEqual("incomplete", result["status"])
            self.assertEqual(
                "entry_budget_exhausted",
                result["incomplete_reason"],
            )
            self.assertEqual(4, result["budget"]["entries_observed"])
            self.assertEqual([], result["deleted"])

    def test_gc_checks_deadline_before_each_ordinary_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "deadline-gc"
            root.mkdir(mode=0o700, parents=True)
            (root / "ordinary.txt").write_text("retained\n", encoding="ascii")

            monotonic_values = [0.0, 0.0, 0.0, 0.0, 0.0, 61.0]
            with mock.patch.object(
                export_module.time,
                "monotonic",
                side_effect=monotonic_values,
            ):
                result = garbage_collect_expired_exports(root)

            self.assertEqual("incomplete", result["status"])
            self.assertEqual("deadline_exhausted", result["incomplete_reason"])
            self.assertEqual(1, result["budget"]["entries_observed"])
            self.assertTrue((root / "ordinary.txt").is_file())

    def test_gc_reports_deep_tree_budget_without_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "deep-gc"
            current = root
            for index in range(5):
                current.mkdir(mode=0o700, parents=True)
                current = current / f"level-{index}"

            with mock.patch.object(export_module, "_GC_MAX_DEPTH", 2):
                result = garbage_collect_expired_exports(root)

            self.assertEqual("incomplete", result["status"])
            self.assertEqual(
                "depth_budget_exhausted",
                result["incomplete_reason"],
            )
            self.assertEqual(2, result["budget"]["max_depth_observed"])

    def test_gc_bounds_retained_samples_while_preserving_full_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "bounded-gc-results"
            for index in range(3):
                output = root / f"retained-{index}"
                export_retained_bundle(output, run_state(), review_data())
                bind_staged_export(
                    output,
                    f"attempt_ref_v2:{index + 1:064x}",
                )

            with mock.patch.object(export_module, "_GC_MAX_RESULT_SAMPLES", 2):
                result = garbage_collect_expired_exports(
                    root,
                    now=dt.datetime(2100, 1, 1, tzinfo=dt.UTC),
                )

            self.assertEqual("complete", result["status"])
            self.assertEqual(3, result["retained_count"])
            self.assertEqual(2, len(result["retained"]))
            self.assertTrue(result["retained_truncated"])

    def test_publication_bound_export_requires_attempt_terminal_before_gc(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "bound-retention"
            output = root / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            deadline = now + dt.timedelta(hours=1)
            export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
                retention_deadline=deadline,
            )
            attempt_ref = f"attempt_ref_v2:{'a' * 64}"
            bound = bind_staged_export(output, attempt_ref, now=now)

            self.assertEqual(bound["status"], "publication_bound")
            result = garbage_collect_expired_exports(
                root,
                now=deadline + dt.timedelta(days=1),
            )
            self.assertEqual(result["deleted"], [])
            self.assertEqual(result["retained"], [str(output.resolve())])
            self.assertTrue(output.exists())
            expired = garbage_collect_expired_exports(
                root,
                now=now + dt.timedelta(days=8),
            )
            self.assertEqual(expired["deleted"], [])
            self.assertEqual(expired["retained"], [str(output.resolve())])
            self.assertTrue(output.exists())
            retention = json.loads(
                (root / ".retained-v2.retention-v2.json").read_text(encoding="utf-8")
            )
            self.assertEqual("publication_bound", retention["status"])
            self.assertEqual(attempt_ref, retention["publication_attempt_ref"])

            release_staged_export(
                output,
                attempt_ref,
                "aborted",
                now=now + dt.timedelta(days=8),
            )
            collected = garbage_collect_expired_exports(
                root,
                now=now + dt.timedelta(days=8),
            )
            self.assertEqual(collected["deleted"], [str(output.resolve())])
            self.assertFalse(output.exists())

    def test_recent_publication_resume_heartbeat_prevents_stale_gc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "live-bound-retention"
            output = root / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
                retention_deadline=now + dt.timedelta(hours=1),
            )
            attempt_ref = f"attempt_ref_v2:{'b' * 64}"
            bind_staged_export(output, attempt_ref, now=now)
            resumed = bind_staged_export(
                output,
                attempt_ref,
                now=now + dt.timedelta(days=6),
            )

            self.assertTrue(resumed["idempotent"])
            self.assertEqual(
                resumed["publication_heartbeat_at"],
                "2026-07-21T00:00:00Z",
            )
            result = garbage_collect_expired_exports(
                root,
                now=now + dt.timedelta(days=8),
            )
            self.assertEqual(result["deleted"], [])
            self.assertEqual(result["retained"], [str(output.resolve())])
            self.assertTrue(output.exists())

    def test_stage_checks_bundle_budget_before_deep_validation(self) -> None:
        artifacts = assemble_retained_artifacts(run_state(), review_data())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / ".codex-local" / "bounded" / "retained-v2"
            with (
                mock.patch.object(export_module, "MAX_RETAINED_BUNDLE_BYTES", 1),
                mock.patch.object(
                    export_module, "validate_retained_artifacts"
                ) as validate,
            ):
                with self.assertRaisesRegex(
                    RetainedInventoryError, "preparation limit"
                ):
                    stage_retained_artifacts(output, artifacts)
                validate.assert_not_called()

    def test_bind_and_deadline_gc_serialize_on_the_bundle_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "retention-interleave"
            output = root / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            deadline = now + dt.timedelta(hours=1)
            export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
                retention_deadline=deadline,
            )
            attempt_ref = f"attempt_ref_v2:{'b' * 64}"
            bind_entered = threading.Event()
            allow_bind = threading.Event()
            original_write = export_module._write_retention_at
            errors: list[BaseException] = []
            gc_results: list[dict[str, object]] = []

            def delayed_write(anchor, value):
                if value.get("status") == "publication_bound":
                    bind_entered.set()
                    if not allow_bind.wait(timeout=5):
                        raise RuntimeError("timed out waiting to finish bind")
                return original_write(anchor, value)

            def run_bind() -> None:
                try:
                    bind_staged_export(output, attempt_ref, now=now)
                except BaseException as exc:  # pragma: no cover - assertion payload
                    errors.append(exc)

            def run_gc() -> None:
                try:
                    gc_results.append(
                        garbage_collect_expired_exports(root, now=deadline)
                    )
                except BaseException as exc:  # pragma: no cover - assertion payload
                    errors.append(exc)

            with mock.patch.object(
                export_module, "_write_retention_at", side_effect=delayed_write
            ):
                bind_thread = threading.Thread(target=run_bind)
                bind_thread.start()
                self.assertTrue(bind_entered.wait(timeout=5))
                gc_thread = threading.Thread(target=run_gc)
                gc_thread.start()
                time.sleep(0.05)
                self.assertTrue(gc_thread.is_alive())
                allow_bind.set()
                bind_thread.join(timeout=5)
                gc_thread.join(timeout=5)

            self.assertFalse(bind_thread.is_alive())
            self.assertFalse(gc_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(gc_results[0]["deleted"], [])
            self.assertEqual(gc_results[0]["retained"], [str(output.resolve())])

    def test_stage_parent_replacement_cannot_redirect_bundle_or_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / ".codex-local" / "stage-parent-race"
            output = parent / "retained-v2"
            moved_parent = parent.with_name("stage-parent-race-original")
            artifacts = assemble_retained_artifacts(run_state(), review_data())
            original_write = export_module._write_artifact_at
            swapped = False

            def replace_parent(directory_fd, name, content, *, display_path):
                nonlocal swapped
                if not swapped:
                    parent.rename(moved_parent)
                    parent.mkdir(mode=0o700)
                    swapped = True
                return original_write(
                    directory_fd,
                    name,
                    content,
                    display_path=display_path,
                )

            with mock.patch.object(
                export_module,
                "_write_artifact_at",
                side_effect=replace_parent,
            ):
                with self.assertRaisesRegex(ExportLocationError, "parent changed"):
                    stage_retained_artifacts(output, artifacts)

            self.assertTrue(swapped)
            self.assertEqual([], list(parent.iterdir()))
            self.assertFalse(output.exists())
            self.assertTrue((moved_parent / "retained-v2").is_dir())
            self.assertTrue((moved_parent / ".retained-v2.retention-v2.json").is_file())

    def test_runtime_bundle_symlink_swap_is_rejected_without_following_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / ".codex-local" / "bundle-symlink-race"
            output = parent / "retained-v2"
            moved_output = parent / "retained-v2-original"
            outside = Path(temporary) / "outside-target"
            outside.mkdir(mode=0o700)
            marker = outside / "marker.bin"
            marker.write_bytes(b"must remain untouched")
            os.chmod(marker, 0o600)
            export_retained_bundle(output, run_state(), review_data())
            original_read = export_module._read_exact_artifacts_at
            swapped = False

            def replace_bundle(anchor, *, child_name=None):
                nonlocal swapped
                if not swapped:
                    output.rename(moved_output)
                    output.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return original_read(anchor, child_name=child_name)

            with mock.patch.object(
                export_module,
                "_read_exact_artifacts_at",
                side_effect=replace_bundle,
            ):
                with self.assertRaisesRegex(
                    RetainedInventoryError,
                    "cannot anchor retained staging directory",
                ):
                    bind_staged_export(
                        output,
                        f"attempt_ref_v2:{'d' * 64}",
                    )

            self.assertTrue(swapped)
            self.assertEqual(b"must remain untouched", marker.read_bytes())
            output.unlink()
            moved_output.rename(output)
            validate_staged_export(output)
            anchor = export_module._AnchoredExport.open(
                output,
                create_parent=False,
            )
            try:
                self.assertEqual(
                    "exported",
                    export_module._read_retention_at(anchor)["status"],
                )
            finally:
                anchor.close()

    def test_gc_parent_replacement_cannot_redirect_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "gc-parent-race"
            moved_root = root.with_name("gc-parent-race-original")
            output = root / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            deadline = now + dt.timedelta(hours=1)
            export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
                retention_deadline=deadline,
            )
            original_remove = export_module.safe_io.secure_remove_tree_at
            swapped = False

            def replace_parent(directory_fd, name, *, display_path):
                nonlocal swapped
                if not swapped:
                    root.rename(moved_root)
                    root.mkdir(mode=0o700)
                    replacement_marker = root / "replacement-marker.bin"
                    replacement_marker.write_bytes(b"replacement must survive")
                    os.chmod(replacement_marker, 0o600)
                    swapped = True
                return original_remove(
                    directory_fd,
                    name,
                    display_path=display_path,
                )

            with mock.patch.object(
                export_module.safe_io,
                "secure_remove_tree_at",
                side_effect=replace_parent,
            ):
                with self.assertRaisesRegex(ExportLocationError, "parent changed"):
                    garbage_collect_expired_exports(root, now=deadline)

            self.assertTrue(swapped)
            self.assertEqual(
                b"replacement must survive",
                (root / "replacement-marker.bin").read_bytes(),
            )
            self.assertFalse((moved_root / "retained-v2").exists())

    def test_terminal_publication_release_allows_safe_gc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "terminal-retention"
            output = root / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
                retention_deadline=now + dt.timedelta(hours=1),
            )
            attempt_ref = f"attempt_ref_v2:{'c' * 64}"
            bind_staged_export(output, attempt_ref, now=now)
            terminal = release_staged_export(
                output,
                attempt_ref,
                "aborted",
                now=now + dt.timedelta(minutes=1),
            )

            self.assertEqual(terminal["status"], "publication_terminal")
            self.assertEqual(terminal["terminal_disposition"], "aborted")
            collected = garbage_collect_expired_exports(
                root,
                now=now + dt.timedelta(minutes=1),
            )
            self.assertEqual(collected["deleted"], [str(output.resolve())])
            self.assertFalse(output.exists())

    def test_committed_release_accepts_only_a_fully_collected_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "collected-retention"
            root.mkdir(parents=True, mode=0o700)
            output = root / "retained-v2"
            attempt_ref = f"attempt_ref_v2:{'f' * 64}"

            collected = release_committed_staged_export(output, attempt_ref)

            self.assertTrue(collected["idempotent"])
            self.assertEqual("collected", collected["status"])
            self.assertEqual("committed", collected["terminal_disposition"])

            export_retained_bundle(output, run_state(), review_data())
            output.rename(root / "displaced-retained-v2")
            with self.assertRaisesRegex(
                ExportConflictError,
                "bundle and retention state presence differ",
            ):
                release_committed_staged_export(output, attempt_ref)

    def test_conditional_publication_release_leaves_unbound_export_unchanged(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / ".codex-local" / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            exported = export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
            )

            unchanged = release_staged_export_if_bound(
                output,
                f"attempt_ref_v2:{'d' * 64}",
                "aborted",
                now=now,
            )

            self.assertEqual("exported", unchanged["status"])
            self.assertIsNone(unchanged["publication_attempt_ref"])
            self.assertEqual(exported["bundle_digest"], unchanged["bundle_digest"])

    def test_conditional_release_accepts_only_a_fully_collected_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".codex-local" / "collected-retention"
            root.mkdir(parents=True, mode=0o700)
            output = root / "retained-v2"
            sidecar = output.with_name(f".{output.name}.retention-v2.json")
            attempt_ref = f"attempt_ref_v2:{'c' * 64}"

            collected = release_staged_export_if_bound(
                output,
                attempt_ref,
                "aborted",
            )

            self.assertTrue(collected["idempotent"])
            self.assertEqual("collected", collected["status"])
            self.assertEqual("aborted", collected["terminal_disposition"])

            output.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                ExportConflictError,
                "bundle and retention state presence differ",
            ):
                release_staged_export_if_bound(output, attempt_ref, "aborted")
            output.rmdir()

            sidecar.write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(
                ExportConflictError,
                "bundle and retention state presence differ",
            ):
                release_staged_export_if_bound(output, attempt_ref, "aborted")

    def test_conditional_unbound_release_does_not_validate_corrupt_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / ".codex-local" / "retained-v2"
            now = dt.datetime(2026, 7, 15, 0, 0, tzinfo=dt.UTC)
            exported = export_retained_bundle(
                output,
                run_state(),
                review_data(),
                now=now,
            )
            (output / "report.md").write_text(
                "corrupt after export\n", encoding="ascii"
            )

            unchanged = release_staged_export_if_bound(
                output,
                f"attempt_ref_v2:{'e' * 64}",
                "aborted",
                now=now,
            )

            self.assertEqual("exported", unchanged["status"])
            self.assertEqual(exported["bundle_digest"], unchanged["bundle_digest"])
            with self.assertRaises(RetainedInventoryError):
                validate_staged_export(output)


if __name__ == "__main__":
    unittest.main()
