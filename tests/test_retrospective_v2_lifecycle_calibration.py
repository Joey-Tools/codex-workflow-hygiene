from __future__ import annotations

import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "codex-session-retrospective"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS))

from retrospective_v2 import calibration  # noqa: E402
from retrospective_v2.identity import IdentityKey  # noqa: E402


def commitment(character: str) -> str:
    return "sha256:" + character * 64


def case_ref(index: int) -> str:
    return "calibration_case_v2:" + f"{index:064x}"


def pair_ref(index: int) -> str:
    return "calibration_pair_v2:" + f"{index:064x}"


def privacy_ref(index: int) -> str:
    return "privacy_holdout_v2:" + f"{index:064x}"


def detector_cases(
    *,
    category: str,
    detector: str,
    start: int,
    true_positive: int,
    false_negative: int,
    false_positive: int,
    true_negative: int,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    index = start
    for expected, predicted, count in (
        (True, True, true_positive),
        (True, False, false_negative),
        (False, True, false_positive),
        (False, False, true_negative),
    ):
        for _ in range(count):
            rows.append(
                {
                    "case_ref": case_ref(index),
                    "category": category,
                    "detector": detector,
                    "expected": expected,
                    "predicted": predicted,
                }
            )
            index += 1
    return rows


def passing_corpus() -> dict[str, object]:
    configuration = {
        name: commitment(f"{index:x}")
        for index, name in enumerate(
            sorted(
                {
                    "detector",
                    "engine",
                    "history_validator",
                    "model",
                    "parameters",
                    "prompt",
                    "redaction",
                    "schema",
                    "segmentation",
                    "transport",
                }
            ),
            start=1,
        )
    }
    classification_cases = [
        *detector_cases(
            category="approval_auth_safety",
            detector="approval",
            start=1,
            true_positive=20,
            false_negative=0,
            false_positive=0,
            true_negative=20,
        ),
        *detector_cases(
            category="approval_auth_safety",
            detector="auth",
            start=101,
            true_positive=20,
            false_negative=0,
            false_positive=0,
            true_negative=20,
        ),
        *detector_cases(
            category="approval_auth_safety",
            detector="safety",
            start=201,
            true_positive=20,
            false_negative=0,
            false_positive=0,
            true_negative=20,
        ),
        *detector_cases(
            category="semantic_friction",
            detector="scope_drift",
            start=301,
            true_positive=20,
            false_negative=0,
            false_positive=0,
            true_negative=20,
        ),
    ]
    return {
        "classification_cases": classification_cases,
        "configuration": configuration,
        "episode_pairs": [
            {
                "expected_same_episode": True,
                "pair_ref": pair_ref(index),
                "predicted_same_episode": True,
            }
            for index in range(1, 21)
        ],
        "privacy_holdout": {
            "case_count": calibration.MIN_PRIVACY_HOLDOUT_SAMPLES,
            "holdout_ref": privacy_ref(1),
            "passed": True,
            "raw_prompt_leak_count": 0,
            "sensitive_value_leak_count": 0,
            "tool_output_leak_count": 0,
        },
        "schema": calibration.CALIBRATION_CORPUS_SCHEMA,
    }


class CalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.identity = IdentityKey.create(self.root / "identity-v2.key")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def evaluate(self, corpus: dict[str, object]) -> calibration.CalibrationReceipt:
        return calibration.evaluate_calibration_corpus(
            self.identity,
            corpus,
        )

    def test_pass_receipt_binds_every_configuration_dimension(self) -> None:
        receipt = self.evaluate(passing_corpus())
        self.assertTrue(receipt.passed)
        verified = calibration.verify_calibration_receipt(
            self.identity,
            receipt.to_dict(),
            expected_configuration_root=receipt.configuration_root,
        )
        self.assertEqual(receipt.receipt_ref, verified.receipt_ref)

        changed = passing_corpus()
        changed["configuration"]["transport"] = commitment("e")
        changed_receipt = self.evaluate(changed)
        self.assertNotEqual(
            receipt.configuration_root,
            changed_receipt.configuration_root,
        )
        self.assertNotEqual(
            receipt.production_configuration_ref,
            changed_receipt.production_configuration_ref,
        )

    def test_receipt_derives_and_authenticates_the_production_configuration_ref(
        self,
    ) -> None:
        production_root = "f" * 64
        production_ref = str(
            self.identity.derive_ref(
                "configuration",
                {"parts": [production_root]},
            )
        )
        receipt = calibration.evaluate_calibration_corpus(
            self.identity,
            passing_corpus(),
            production_configuration_root=production_root,
            model_era="gpt_5_6",
            policy_era="source_catalog_v2",
        )

        self.assertEqual(production_root, receipt.production_configuration_root)
        self.assertEqual(production_ref, receipt.production_configuration_ref)
        self.assertEqual("gpt_5_6", receipt.model_era)
        tampered = receipt.to_dict()
        tampered["production_configuration_ref"] = "configuration_ref_v2:" + "f" * 64
        with self.assertRaisesRegex(
            calibration.CalibrationError,
            "authentication failed|not derived from its signed root",
        ):
            calibration.verify_calibration_receipt(self.identity, tampered)

    def test_metric_gates_fail_closed_without_denominators(self) -> None:
        corpus = passing_corpus()
        corpus["classification_cases"] = []
        corpus["episode_pairs"] = []
        receipt = self.evaluate(corpus)
        self.assertFalse(receipt.passed)
        with self.assertRaisesRegex(calibration.CalibrationError, "did not pass"):
            calibration.verify_calibration_receipt(self.identity, receipt.to_dict())

    def test_receipt_rejects_sample_counts_detached_from_metric_support(self) -> None:
        receipt = self.evaluate(passing_corpus())
        tampered_detector = receipt.to_dict()
        tampered_detector["sample_counts"]["detector_precision"]["approval"][
            "metric_support"
        ] += 1
        with self.assertRaisesRegex(
            calibration.CalibrationError,
            "does not match metric support",
        ):
            calibration.verify_calibration_receipt(
                self.identity,
                tampered_detector,
            )

        invalid_matrix = receipt.to_dict()
        invalid_matrix["metrics"]["detector_precision"]["approval"]["numerator"] = 19
        invalid_matrix["metrics"]["approval_auth_safety_recall"]["numerator"] = 59
        invalid_matrix["sample_counts"]["detector_precision"]["approval"][
            "expected_negative"
        ] = 0
        with self.assertRaisesRegex(
            calibration.CalibrationError,
            "valid confusion matrix",
        ):
            calibration.verify_calibration_receipt(self.identity, invalid_matrix)

        tampered_pair = receipt.to_dict()
        tampered_pair["sample_counts"]["episode_boundary_pairwise_f1"] += 1
        with self.assertRaisesRegex(
            calibration.CalibrationError,
            "confusion-matrix support",
        ):
            calibration.verify_calibration_receipt(self.identity, tampered_pair)

    def test_each_detector_requires_positive_and_negative_support(self) -> None:
        for retained_expected, missing_field in (
            (True, "expected_negative"),
            (False, "expected_positive"),
        ):
            with self.subTest(retained_expected=retained_expected):
                corpus = passing_corpus()
                corpus["classification_cases"] = [
                    item
                    for item in corpus["classification_cases"]
                    if item["detector"] != "scope_drift"
                    or item["expected"] is retained_expected
                ]
                receipt = self.evaluate(corpus)
                support = receipt.sample_counts["detector_precision"]["scope_drift"]
                self.assertEqual(0, support[missing_field])
                self.assertFalse(receipt.passed)

    def test_always_positive_and_always_negative_detectors_cannot_pass(self) -> None:
        for prediction in (True, False):
            with self.subTest(prediction=prediction):
                corpus = passing_corpus()
                for item in corpus["classification_cases"]:
                    if item["detector"] == "scope_drift":
                        item["predicted"] = prediction
                receipt = self.evaluate(corpus)
                support = receipt.sample_counts["detector_precision"]["scope_drift"]
                self.assertEqual(20, support["expected_positive"])
                self.assertEqual(20, support["expected_negative"])
                self.assertFalse(receipt.passed)

    def test_threshold_boundary_and_tamper_are_adversarially_checked(self) -> None:
        corpus = passing_corpus()
        approval_cases = detector_cases(
            category="approval_auth_safety",
            detector="approval",
            start=1_000,
            true_positive=18,
            false_negative=2,
            false_positive=2,
            true_negative=18,
        )
        corpus["classification_cases"] = [
            *approval_cases,
            *[
                item
                for item in passing_corpus()["classification_cases"]
                if item["detector"] != "approval"
            ],
        ]
        receipt = self.evaluate(corpus)
        self.assertTrue(receipt.passed)
        below = copy.deepcopy(corpus)
        below["classification_cases"][17]["expected"] = False
        below["classification_cases"][22]["expected"] = True
        self.assertFalse(self.evaluate(below).passed)

        tampered = receipt.to_dict()
        tampered["metrics"]["detector_precision"]["approval"]["numerator"] = 10
        with self.assertRaises(calibration.CalibrationError):
            calibration.verify_calibration_receipt(self.identity, tampered)

    def test_recall_and_minimum_sample_gates_fail_closed(self) -> None:
        poor_recall = passing_corpus()
        poor_recall["classification_cases"].extend(
            {
                "case_ref": case_ref(2_000 + index),
                "category": "approval_auth_safety",
                "detector": "approval",
                "expected": True,
                "predicted": False,
            }
            for index in range(20)
        )
        receipt = self.evaluate(poor_recall)
        self.assertEqual(
            {"denominator": 80, "numerator": 60},
            receipt.metrics["approval_auth_safety_recall"],
        )
        self.assertFalse(receipt.passed)

        tiny = passing_corpus()
        tiny["classification_cases"] = [
            next(
                item
                for item in tiny["classification_cases"]
                if item["detector"] == "approval" and item["expected"]
            ),
            next(
                item
                for item in tiny["classification_cases"]
                if item["detector"] == "scope_drift" and item["expected"]
            ),
        ]
        tiny["episode_pairs"] = [tiny["episode_pairs"][0]]
        tiny_receipt = self.evaluate(tiny)
        self.assertFalse(tiny_receipt.passed)
        self.assertEqual(
            1,
            tiny_receipt.sample_counts["detector_precision"]["approval"][
                "metric_support"
            ],
        )

    def test_precision_gates_are_independent_per_detector(self) -> None:
        poor_control = passing_corpus()
        poor_control["classification_cases"] = [
            *[
                item
                for item in poor_control["classification_cases"]
                if item["detector"] != "approval"
            ],
            *detector_cases(
                category="approval_auth_safety",
                detector="approval",
                start=3_000,
                true_positive=17,
                false_negative=3,
                false_positive=3,
                true_negative=17,
            ),
        ]
        control_receipt = self.evaluate(poor_control)
        self.assertEqual(
            {"denominator": 20, "numerator": 17},
            control_receipt.metrics["detector_precision"]["approval"],
        )
        self.assertFalse(control_receipt.passed)

        poor_semantic = passing_corpus()
        poor_semantic["classification_cases"] = [
            item
            for item in poor_semantic["classification_cases"]
            if item["category"] != "semantic_friction"
        ]
        poor_semantic["classification_cases"].extend(
            detector_cases(
                category="semantic_friction",
                detector="scope_drift",
                start=4_000,
                true_positive=20,
                false_negative=0,
                false_positive=0,
                true_negative=20,
            )
        )
        poor_semantic["classification_cases"].extend(
            detector_cases(
                category="semantic_friction",
                detector="verification_gap",
                start=4_100,
                true_positive=15,
                false_negative=5,
                false_positive=5,
                true_negative=15,
            )
        )
        semantic_receipt = self.evaluate(poor_semantic)
        self.assertEqual(
            {"denominator": 20, "numerator": 15},
            semantic_receipt.metrics["detector_precision"]["verification_gap"],
        )
        self.assertFalse(semantic_receipt.passed)

    def test_semantic_precision_accepts_exact_eighty_percent(self) -> None:
        corpus = passing_corpus()
        corpus["classification_cases"] = [
            item
            for item in corpus["classification_cases"]
            if item["detector"] != "scope_drift"
        ]
        corpus["classification_cases"].extend(
            detector_cases(
                category="semantic_friction",
                detector="scope_drift",
                start=4_500,
                true_positive=16,
                false_negative=4,
                false_positive=4,
                true_negative=16,
            )
        )
        receipt = self.evaluate(corpus)
        self.assertEqual(
            {"denominator": 20, "numerator": 16},
            receipt.metrics["detector_precision"]["scope_drift"],
        )
        self.assertTrue(receipt.passed)

        below = copy.deepcopy(corpus)
        scope_rows = [
            item
            for item in below["classification_cases"]
            if item["detector"] == "scope_drift"
        ]
        scope_rows[0]["predicted"] = False
        scope_rows[-1]["predicted"] = True
        self.assertFalse(self.evaluate(below).passed)

    def test_episode_pairwise_f1_accepts_exact_eighty_five_percent(self) -> None:
        corpus = passing_corpus()
        corpus["episode_pairs"] = [
            *[
                {
                    "expected_same_episode": True,
                    "pair_ref": pair_ref(5_000 + index),
                    "predicted_same_episode": True,
                }
                for index in range(51)
            ],
            *[
                {
                    "expected_same_episode": False,
                    "pair_ref": pair_ref(5_100 + index),
                    "predicted_same_episode": True,
                }
                for index in range(9)
            ],
            *[
                {
                    "expected_same_episode": True,
                    "pair_ref": pair_ref(5_200 + index),
                    "predicted_same_episode": False,
                }
                for index in range(9)
            ],
        ]
        receipt = self.evaluate(corpus)
        self.assertEqual(
            {"denominator": 120, "numerator": 102},
            receipt.metrics["episode_boundary_pairwise_f1"],
        )
        self.assertTrue(receipt.passed)

        below = copy.deepcopy(corpus)
        below["episode_pairs"][0]["predicted_same_episode"] = False
        self.assertFalse(self.evaluate(below).passed)

    def test_pairwise_sample_gate_ignores_true_negative_padding(self) -> None:
        corpus = passing_corpus()
        corpus["episode_pairs"] = [
            *[
                {
                    "expected_same_episode": True,
                    "pair_ref": pair_ref(6_000 + index),
                    "predicted_same_episode": True,
                }
                for index in range(5)
            ],
            *[
                {
                    "expected_same_episode": False,
                    "pair_ref": pair_ref(6_100 + index),
                    "predicted_same_episode": False,
                }
                for index in range(100)
            ],
        ]
        receipt = self.evaluate(corpus)
        self.assertEqual(
            {"denominator": 10, "numerator": 10},
            receipt.metrics["episode_boundary_pairwise_f1"],
        )
        self.assertEqual(
            5,
            receipt.sample_counts["episode_boundary_pairwise_f1"],
        )
        self.assertFalse(receipt.passed)

    def test_privacy_holdout_is_closed_and_required_to_pass(self) -> None:
        leaked = passing_corpus()
        leaked["privacy_holdout"]["raw_prompt_leak_count"] = 1
        leaked["privacy_holdout"]["passed"] = False
        receipt = self.evaluate(leaked)
        self.assertFalse(receipt.passed)
        with self.assertRaisesRegex(calibration.CalibrationError, "did not pass"):
            calibration.verify_calibration_receipt(self.identity, receipt.to_dict())

        malformed = passing_corpus()
        malformed["privacy_holdout"].pop("tool_output_leak_count")
        with self.assertRaisesRegex(calibration.CalibrationError, "closed field"):
            self.evaluate(malformed)

    def test_corpus_commitment_is_derived_from_validated_corpus(self) -> None:
        original = passing_corpus()
        changed = copy.deepcopy(original)
        changed["classification_cases"][0]["case_ref"] = case_ref(900)

        original_receipt = self.evaluate(original)
        changed_receipt = self.evaluate(changed)

        self.assertEqual(original_receipt.metrics, changed_receipt.metrics)
        self.assertEqual(
            original_receipt.configuration_root,
            changed_receipt.configuration_root,
        )
        self.assertNotEqual(
            original_receipt.corpus_commitment,
            changed_receipt.corpus_commitment,
        )
        self.assertNotEqual(original_receipt.receipt_ref, changed_receipt.receipt_ref)

    def test_calibration_case_count_is_bounded_before_iteration(self) -> None:
        corpus = passing_corpus()
        corpus["classification_cases"] = [corpus["classification_cases"][0]] * (
            calibration.MAX_CLASSIFICATION_CASES + 1
        )

        with self.assertRaisesRegex(calibration.CalibrationError, "bounded arrays"):
            self.evaluate(corpus)
