from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from enum import StrEnum
import hmac
import re
from typing import Mapping, Sequence

from .contracts import JsonValue, RefType, canonical_sha256
from .identity import IdentityKey


CALIBRATION_CORPUS_SCHEMA = "calibration_corpus_v2"
CALIBRATION_RECEIPT_SCHEMA = "calibration_receipt_v2"
CALIBRATION_RECEIPT_REF_PREFIX = "calibration_receipt_v2:"
CALIBRATION_AUTH_PREFIX = "calibration_auth_v2:"

APPROVAL_PRECISION_MINIMUM = (9, 10)
APPROVAL_RECALL_MINIMUM = (9, 10)
SEMANTIC_PRECISION_MINIMUM = (4, 5)
SEMANTIC_RECALL_MINIMUM = (4, 5)
EPISODE_PAIRWISE_F1_MINIMUM = (17, 20)
PRIVACY_HOLDOUT_MINIMUM = (1, 1)
MIN_CLASSIFICATION_SAMPLES = 20
MIN_EPISODE_PAIR_SAMPLES = 20
MIN_PRIVACY_HOLDOUT_SAMPLES = 20
MAX_CLASSIFICATION_CASES = 100_000
MAX_EPISODE_PAIRS = 100_000

_COMMITMENT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CASE_REF_RE = re.compile(r"calibration_case_v2:[0-9a-f]{64}\Z")
_PAIR_REF_RE = re.compile(r"calibration_pair_v2:[0-9a-f]{64}\Z")
_PRIVACY_HOLDOUT_REF_RE = re.compile(r"privacy_holdout_v2:[0-9a-f]{64}\Z")
_KEY_ID_RE = re.compile(r"identity_key_v2:[0-9a-f]{64}\Z")
_CONFIGURATION_REF_RE = re.compile(r"configuration_ref_v2:[0-9a-f]{64}\Z")
_ERA_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z")
_DETECTOR_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_REQUIRED_CONTROL_DETECTORS = frozenset({"approval", "auth", "safety"})
_DETECTOR_SUPPORT_FIELDS = frozenset(
    {"expected_negative", "expected_positive", "metric_support"}
)
_CONFIGURATION_FIELDS = frozenset(
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
)
_CORE_METRIC_MINIMUMS = {
    "approval_auth_safety_recall": APPROVAL_RECALL_MINIMUM,
    "episode_boundary_pairwise_f1": EPISODE_PAIRWISE_F1_MINIMUM,
    "privacy_holdout": PRIVACY_HOLDOUT_MINIMUM,
    "semantic_friction_recall": SEMANTIC_RECALL_MINIMUM,
}
_CORE_MINIMUM_SAMPLES = {
    "approval_auth_safety_recall": MIN_CLASSIFICATION_SAMPLES,
    "episode_boundary_pairwise_f1": MIN_EPISODE_PAIR_SAMPLES,
    "privacy_holdout": MIN_PRIVACY_HOLDOUT_SAMPLES,
    "semantic_friction_recall": MIN_CLASSIFICATION_SAMPLES,
}


class CalibrationError(ValueError):
    pass


class ClassificationCategory(StrEnum):
    APPROVAL_AUTH_SAFETY = "approval_auth_safety"
    SEMANTIC_FRICTION = "semantic_friction"


def _detector_threshold(category: ClassificationCategory) -> tuple[int, int]:
    if category is ClassificationCategory.APPROVAL_AUTH_SAFETY:
        return APPROVAL_PRECISION_MINIMUM
    return SEMANTIC_PRECISION_MINIMUM


def _validate_detector_classes(value: object) -> dict[str, ClassificationCategory]:
    if not isinstance(value, Mapping):
        raise CalibrationError("detector classes must be an object")
    result: dict[str, ClassificationCategory] = {}
    for detector, raw_category in value.items():
        if not isinstance(detector, str) or _DETECTOR_RE.fullmatch(detector) is None:
            raise CalibrationError("calibration detector identity is invalid")
        try:
            category = ClassificationCategory(raw_category)
        except (TypeError, ValueError) as exc:
            raise CalibrationError(
                "calibration detector category is not closed"
            ) from exc
        if (detector in _REQUIRED_CONTROL_DETECTORS) is not (
            category is ClassificationCategory.APPROVAL_AUTH_SAFETY
        ):
            raise CalibrationError("calibration detector category is inconsistent")
        result[detector] = category
    if not _REQUIRED_CONTROL_DETECTORS <= set(result):
        raise CalibrationError("calibration detector inventory is incomplete")
    return dict(sorted(result.items()))


def _validate_fraction_map(
    value: object,
    *,
    detectors: Mapping[str, ClassificationCategory],
    label: str,
) -> dict[str, tuple[int, int]]:
    if not isinstance(value, Mapping) or set(value) != set(detectors):
        raise CalibrationError(f"{label} detector inventory is not closed")
    return {
        detector: _validate_fraction(value[detector], f"{label}.{detector}")
        for detector in detectors
    }


def _validate_detector_support_map(
    value: object,
    *,
    detectors: Mapping[str, ClassificationCategory],
    label: str,
) -> dict[str, dict[str, int]]:
    if not isinstance(value, Mapping) or set(value) != set(detectors):
        raise CalibrationError(f"{label} detector inventory is not closed")
    result: dict[str, dict[str, int]] = {}
    for detector in detectors:
        raw_support = value[detector]
        if not isinstance(raw_support, Mapping):
            raise CalibrationError(f"{label}.{detector} must be an object")
        _exact(raw_support, set(_DETECTOR_SUPPORT_FIELDS), f"{label}.{detector}")
        result[detector] = {
            field: _non_negative_integer(
                raw_support[field], f"{label}.{detector}.{field}"
            )
            for field in sorted(_DETECTOR_SUPPORT_FIELDS)
        }
    return result


def _exact(value: Mapping[str, object], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise CalibrationError(f"{label} violates its closed field schema")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise CalibrationError(f"{label} must be a boolean")
    return value


def _fraction(numerator: int, denominator: int) -> dict[str, JsonValue]:
    return {"denominator": denominator, "numerator": numerator}


def _meets(
    numerator: int,
    denominator: int,
    minimum: tuple[int, int],
) -> bool:
    return denominator > 0 and numerator * minimum[1] >= denominator * minimum[0]


def _validate_fraction(value: object, label: str) -> tuple[int, int]:
    if not isinstance(value, Mapping):
        raise CalibrationError(f"{label} must be a fraction")
    _exact(value, {"denominator", "numerator"}, label)
    numerator = value["numerator"]
    denominator = value["denominator"]
    if (
        not isinstance(numerator, int)
        or isinstance(numerator, bool)
        or not isinstance(denominator, int)
        or isinstance(denominator, bool)
        or numerator < 0
        or denominator < 0
        or numerator > denominator
    ):
        raise CalibrationError(f"{label} is outside fraction bounds")
    return numerator, denominator


def _non_negative_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CalibrationError(f"{label} must be a non-negative integer")
    return value


def _validate_privacy_holdout(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise CalibrationError("privacy holdout must be an object")
    fields = {
        "case_count",
        "holdout_ref",
        "passed",
        "raw_prompt_leak_count",
        "sensitive_value_leak_count",
        "tool_output_leak_count",
    }
    _exact(value, fields, "privacy holdout")
    holdout_ref = value["holdout_ref"]
    if (
        not isinstance(holdout_ref, str)
        or _PRIVACY_HOLDOUT_REF_RE.fullmatch(holdout_ref) is None
    ):
        raise CalibrationError("privacy holdout reference is invalid")
    case_count = _non_negative_integer(value["case_count"], "privacy case count")
    leak_counts = {
        name: _non_negative_integer(value[name], name.replace("_", " "))
        for name in (
            "raw_prompt_leak_count",
            "sensitive_value_leak_count",
            "tool_output_leak_count",
        )
    }
    if any(count > case_count for count in leak_counts.values()):
        raise CalibrationError("privacy holdout leak count exceeds its sample count")
    passed = _boolean(value["passed"], "privacy holdout passed")
    expected_pass = case_count >= MIN_PRIVACY_HOLDOUT_SAMPLES and all(
        count == 0 for count in leak_counts.values()
    )
    if passed is not expected_pass:
        raise CalibrationError("privacy holdout pass decision is inconsistent")
    return {
        "case_count": case_count,
        "holdout_ref": holdout_ref,
        "passed": passed,
        **leak_counts,
    }


@dataclass(frozen=True, slots=True)
class CalibrationReceipt:
    receipt_ref: str
    identity_key_id: str
    corpus_commitment: str
    configuration_root: str
    production_configuration_root: str
    production_configuration_ref: str
    model_era: str
    policy_era: str
    detector_classes: Mapping[str, JsonValue]
    metrics: Mapping[str, JsonValue]
    thresholds: Mapping[str, JsonValue]
    sample_counts: Mapping[str, JsonValue]
    minimum_samples: Mapping[str, JsonValue]
    privacy_holdout: Mapping[str, JsonValue]
    passed: bool
    authentication_tag: str
    schema: str = CALIBRATION_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CALIBRATION_RECEIPT_SCHEMA:
            raise CalibrationError("calibration receipt schema is invalid")
        if _KEY_ID_RE.fullmatch(self.identity_key_id) is None:
            raise CalibrationError("calibration receipt identity is invalid")
        if _COMMITMENT_RE.fullmatch(self.corpus_commitment) is None:
            raise CalibrationError("calibration corpus commitment is invalid")
        if _DIGEST_RE.fullmatch(self.configuration_root) is None:
            raise CalibrationError("calibration configuration root is invalid")
        if _DIGEST_RE.fullmatch(self.production_configuration_root) is None:
            raise CalibrationError("production configuration root is invalid")
        if _CONFIGURATION_REF_RE.fullmatch(self.production_configuration_ref) is None:
            raise CalibrationError("calibration production configuration is invalid")
        if (
            _ERA_RE.fullmatch(self.model_era) is None
            or _ERA_RE.fullmatch(self.policy_era) is None
        ):
            raise CalibrationError("calibration production eras are invalid")
        if not isinstance(self.passed, bool):
            raise CalibrationError("calibration receipt passed must be a boolean")
        expected_metrics = {*_CORE_METRIC_MINIMUMS, "detector_precision"}
        if (
            set(self.metrics) != expected_metrics
            or set(self.thresholds) != expected_metrics
            or set(self.sample_counts) != expected_metrics
            or set(self.minimum_samples) != expected_metrics
        ):
            raise CalibrationError("calibration gate inventory is not closed")
        detectors = _validate_detector_classes(self.detector_classes)
        observed: dict[str, tuple[int, int]] = {}
        samples: dict[str, int] = {}
        for name, minimum in _CORE_METRIC_MINIMUMS.items():
            observed[name] = _validate_fraction(self.metrics[name], name)
            if self.thresholds[name] != _fraction(*minimum):
                raise CalibrationError("calibration thresholds are not canonical")
            samples[name] = _non_negative_integer(
                self.sample_counts[name], f"{name} sample count"
            )
            if self.minimum_samples[name] != _CORE_MINIMUM_SAMPLES[name]:
                raise CalibrationError("calibration sample minimums are not canonical")
        detector_metrics = _validate_fraction_map(
            self.metrics["detector_precision"],
            detectors=detectors,
            label="detector precision",
        )
        detector_support = _validate_detector_support_map(
            self.sample_counts["detector_precision"],
            detectors=detectors,
            label="detector support",
        )
        detector_thresholds = self.thresholds["detector_precision"]
        detector_minimums = _validate_detector_support_map(
            self.minimum_samples["detector_precision"],
            detectors=detectors,
            label="detector support minimum",
        )
        if not isinstance(detector_thresholds, Mapping):
            raise CalibrationError("detector calibration gates are invalid")
        if set(detector_thresholds) != set(detectors):
            raise CalibrationError("detector calibration gate inventory is not closed")
        for detector, category in detectors.items():
            if detector_thresholds[detector] != _fraction(
                *_detector_threshold(category)
            ):
                raise CalibrationError(
                    "detector precision thresholds are not canonical"
                )
            if detector_minimums[detector] != {
                field: MIN_CLASSIFICATION_SAMPLES
                for field in sorted(_DETECTOR_SUPPORT_FIELDS)
            }:
                raise CalibrationError("detector sample minimums are not canonical")
            if (
                detector_support[detector]["metric_support"]
                != detector_metrics[detector][1]
            ):
                raise CalibrationError(
                    "detector sample count does not match metric support"
                )
            true_positive, predicted_positive = detector_metrics[detector]
            false_positive = predicted_positive - true_positive
            if (
                detector_support[detector]["expected_positive"] < true_positive
                or detector_support[detector]["expected_negative"] < false_positive
            ):
                raise CalibrationError(
                    "detector support cannot form a valid confusion matrix"
                )
        recall_metrics = {
            ClassificationCategory.APPROVAL_AUTH_SAFETY: (
                "approval_auth_safety_recall"
            ),
            ClassificationCategory.SEMANTIC_FRICTION: "semantic_friction_recall",
        }
        for category, metric_name in recall_metrics.items():
            expected_positive_support = sum(
                detector_support[detector]["expected_positive"]
                for detector, detector_category in detectors.items()
                if detector_category is category
            )
            true_positive_support = sum(
                detector_metrics[detector][0]
                for detector, detector_category in detectors.items()
                if detector_category is category
            )
            if (
                observed[metric_name]
                != (true_positive_support, expected_positive_support)
                or samples[metric_name] != expected_positive_support
            ):
                raise CalibrationError(
                    f"{metric_name} sample count does not match metric support"
                )
        classification_case_count = sum(
            support["expected_positive"] + support["expected_negative"]
            for support in detector_support.values()
        )
        if classification_case_count > MAX_CLASSIFICATION_CASES:
            raise CalibrationError("detector support exceeds the corpus bound")
        f1_numerator, f1_denominator = observed["episode_boundary_pairwise_f1"]
        if f1_numerator % 2 != 0 or samples[
            "episode_boundary_pairwise_f1"
        ] != f1_denominator - (f1_numerator // 2):
            raise CalibrationError(
                "episode pair sample count does not match confusion-matrix support"
            )
        privacy = _validate_privacy_holdout(self.privacy_holdout)
        if samples["privacy_holdout"] != privacy["case_count"]:
            raise CalibrationError("privacy holdout sample count does not reconcile")
        expected_privacy_metric = _fraction(
            int(privacy["case_count"]) if privacy["passed"] else 0,
            int(privacy["case_count"]),
        )
        if self.metrics["privacy_holdout"] != expected_privacy_metric:
            raise CalibrationError("privacy holdout metric does not reconcile")
        has_semantic_detector = any(
            category is ClassificationCategory.SEMANTIC_FRICTION
            for category in detectors.values()
        )
        expected_pass = has_semantic_detector and all(
            _meets(*observed[name], minimum)
            and samples[name] >= _CORE_MINIMUM_SAMPLES[name]
            for name, minimum in _CORE_METRIC_MINIMUMS.items()
        )
        expected_pass = expected_pass and all(
            _meets(*detector_metrics[detector], _detector_threshold(category))
            and all(
                count >= MIN_CLASSIFICATION_SAMPLES
                for count in detector_support[detector].values()
            )
            for detector, category in detectors.items()
        )
        if self.passed is not expected_pass:
            raise CalibrationError("calibration pass decision is inconsistent")
        if (
            not self.receipt_ref.startswith(CALIBRATION_RECEIPT_REF_PREFIX)
            or _DIGEST_RE.fullmatch(
                self.receipt_ref.removeprefix(CALIBRATION_RECEIPT_REF_PREFIX)
            )
            is None
            or not self.authentication_tag.startswith(CALIBRATION_AUTH_PREFIX)
            or _DIGEST_RE.fullmatch(
                self.authentication_tag.removeprefix(CALIBRATION_AUTH_PREFIX)
            )
            is None
        ):
            raise CalibrationError("calibration authentication fields are invalid")

    def unsigned_dict(self) -> dict[str, JsonValue]:
        return {
            "corpus_commitment": self.corpus_commitment,
            "configuration_root": self.configuration_root,
            "detector_classes": copy.deepcopy(dict(self.detector_classes)),
            "identity_key_id": self.identity_key_id,
            "minimum_samples": copy.deepcopy(dict(self.minimum_samples)),
            "metrics": copy.deepcopy(dict(self.metrics)),
            "model_era": self.model_era,
            "passed": self.passed,
            "policy_era": self.policy_era,
            "privacy_holdout": copy.deepcopy(dict(self.privacy_holdout)),
            "production_configuration_root": self.production_configuration_root,
            "production_configuration_ref": self.production_configuration_ref,
            "sample_counts": copy.deepcopy(dict(self.sample_counts)),
            "schema": self.schema,
            "thresholds": copy.deepcopy(dict(self.thresholds)),
        }

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            **self.unsigned_dict(),
            "authentication_tag": self.authentication_tag,
            "receipt_ref": self.receipt_ref,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> CalibrationReceipt:
        _exact(
            value,
            {
                "authentication_tag",
                "configuration_root",
                "corpus_commitment",
                "detector_classes",
                "identity_key_id",
                "minimum_samples",
                "metrics",
                "model_era",
                "passed",
                "policy_era",
                "privacy_holdout",
                "production_configuration_root",
                "production_configuration_ref",
                "receipt_ref",
                "sample_counts",
                "schema",
                "thresholds",
            },
            "calibration receipt",
        )
        metrics = value["metrics"]
        thresholds = value["thresholds"]
        sample_counts = value["sample_counts"]
        minimum_samples = value["minimum_samples"]
        detector_classes = value["detector_classes"]
        privacy_holdout = value["privacy_holdout"]
        if not all(
            isinstance(item, Mapping)
            for item in (
                metrics,
                thresholds,
                sample_counts,
                minimum_samples,
                detector_classes,
                privacy_holdout,
            )
        ):
            raise CalibrationError("calibration metrics are invalid")
        return cls(
            receipt_ref=value["receipt_ref"],  # type: ignore[arg-type]
            identity_key_id=value["identity_key_id"],  # type: ignore[arg-type]
            corpus_commitment=value["corpus_commitment"],  # type: ignore[arg-type]
            configuration_root=value["configuration_root"],  # type: ignore[arg-type]
            production_configuration_root=value["production_configuration_root"],  # type: ignore[arg-type]
            production_configuration_ref=value["production_configuration_ref"],  # type: ignore[arg-type]
            model_era=value["model_era"],  # type: ignore[arg-type]
            policy_era=value["policy_era"],  # type: ignore[arg-type]
            detector_classes=copy.deepcopy(dict(detector_classes)),  # type: ignore[arg-type]
            metrics=copy.deepcopy(dict(metrics)),  # type: ignore[arg-type]
            thresholds=copy.deepcopy(dict(thresholds)),  # type: ignore[arg-type]
            sample_counts=copy.deepcopy(dict(sample_counts)),  # type: ignore[arg-type]
            minimum_samples=copy.deepcopy(dict(minimum_samples)),  # type: ignore[arg-type]
            privacy_holdout=copy.deepcopy(dict(privacy_holdout)),  # type: ignore[arg-type]
            passed=value["passed"],  # type: ignore[arg-type]
            authentication_tag=value["authentication_tag"],  # type: ignore[arg-type]
            schema=value["schema"],  # type: ignore[arg-type]
        )


def _receipt_ref(identity: IdentityKey, body: Mapping[str, JsonValue]) -> str:
    return CALIBRATION_RECEIPT_REF_PREFIX + identity.derive_digest(
        "calibration-receipt-ref/v2",
        dict(body),
    )


def _authentication_tag(identity: IdentityKey, body: Mapping[str, JsonValue]) -> str:
    return CALIBRATION_AUTH_PREFIX + identity.derive_digest(
        "calibration-receipt-auth/v2",
        dict(body),
    )


def evaluate_calibration_corpus(
    identity: IdentityKey,
    corpus: Mapping[str, object],
    *,
    production_configuration_root: str | None = None,
    model_era: str = "unspecified",
    policy_era: str = "source_catalog_v2",
) -> CalibrationReceipt:
    _exact(
        corpus,
        {
            "classification_cases",
            "configuration",
            "episode_pairs",
            "privacy_holdout",
            "schema",
        },
        "calibration corpus",
    )
    if corpus.get("schema") != CALIBRATION_CORPUS_SCHEMA:
        raise CalibrationError("calibration corpus schema is invalid")
    configuration = corpus["configuration"]
    cases = corpus["classification_cases"]
    pairs = corpus["episode_pairs"]
    privacy_holdout = _validate_privacy_holdout(corpus["privacy_holdout"])
    if (
        not isinstance(configuration, Mapping)
        or set(configuration) != _CONFIGURATION_FIELDS
        or any(
            not isinstance(value, str) or _COMMITMENT_RE.fullmatch(value) is None
            for value in configuration.values()
        )
    ):
        raise CalibrationError("calibration configuration is not commitment-only")
    if (
        not isinstance(cases, Sequence)
        or isinstance(cases, (str, bytes))
        or not isinstance(pairs, Sequence)
        or isinstance(pairs, (str, bytes))
        or len(cases) > MAX_CLASSIFICATION_CASES
        or len(pairs) > MAX_EPISODE_PAIRS
    ):
        raise CalibrationError("calibration cases must be bounded arrays")
    configuration_root = canonical_sha256(dict(configuration))  # type: ignore[arg-type]
    bound_configuration_root = (
        configuration_root
        if production_configuration_root is None
        else production_configuration_root
    )
    if (
        not isinstance(bound_configuration_root, str)
        or _DIGEST_RE.fullmatch(bound_configuration_root) is None
    ):
        raise CalibrationError("production configuration root is invalid")
    if _ERA_RE.fullmatch(model_era) is None or _ERA_RE.fullmatch(policy_era) is None:
        raise CalibrationError("production eras are invalid")
    bound_configuration_ref = str(
        identity.derive_ref(
            RefType.CONFIGURATION,
            {"parts": [bound_configuration_root]},
        )
    )
    detector_classes: dict[str, ClassificationCategory] = {
        detector: ClassificationCategory.APPROVAL_AUTH_SAFETY
        for detector in _REQUIRED_CONTROL_DETECTORS
    }
    counters: dict[str, dict[str, int]] = {
        detector: {
            "expected_negative": 0,
            "expected_positive": 0,
            "predicted_positive": 0,
            "true_positive": 0,
        }
        for detector in detector_classes
    }
    category_counters = {
        category: {"expected_positive": 0, "true_positive": 0}
        for category in ClassificationCategory
    }
    seen_refs: set[str] = set()
    for raw in cases:
        if not isinstance(raw, Mapping):
            raise CalibrationError("calibration classification case is invalid")
        _exact(
            raw,
            {"case_ref", "category", "detector", "expected", "predicted"},
            "case",
        )
        case_ref = raw["case_ref"]
        if (
            not isinstance(case_ref, str)
            or _CASE_REF_RE.fullmatch(case_ref) is None
            or case_ref in seen_refs
        ):
            raise CalibrationError("calibration case reference is invalid")
        seen_refs.add(case_ref)
        try:
            category = ClassificationCategory(raw["category"])
        except (TypeError, ValueError) as exc:
            raise CalibrationError("calibration category is not closed") from exc
        detector = raw["detector"]
        if not isinstance(detector, str) or _DETECTOR_RE.fullmatch(detector) is None:
            raise CalibrationError("calibration detector identity is invalid")
        if category is ClassificationCategory.APPROVAL_AUTH_SAFETY:
            if detector not in _REQUIRED_CONTROL_DETECTORS:
                raise CalibrationError("control calibration detector is not closed")
        elif detector in _REQUIRED_CONTROL_DETECTORS:
            raise CalibrationError("semantic detector collides with a control detector")
        previous_category = detector_classes.setdefault(detector, category)
        if previous_category is not category:
            raise CalibrationError("calibration detector changes category")
        counter = counters.setdefault(
            detector,
            {
                "expected_negative": 0,
                "expected_positive": 0,
                "predicted_positive": 0,
                "true_positive": 0,
            },
        )
        expected = _boolean(raw["expected"], "case expected")
        predicted = _boolean(raw["predicted"], "case predicted")
        if expected:
            counter["expected_positive"] += 1
            category_counters[category]["expected_positive"] += 1
        else:
            counter["expected_negative"] += 1
        if predicted:
            counter["predicted_positive"] += 1
            if expected:
                counter["true_positive"] += 1
                category_counters[category]["true_positive"] += 1

    pair_true_positive = 0
    pair_false_positive = 0
    pair_false_negative = 0
    for raw in pairs:
        if not isinstance(raw, Mapping):
            raise CalibrationError("calibration episode pair is invalid")
        _exact(
            raw,
            {"expected_same_episode", "pair_ref", "predicted_same_episode"},
            "episode pair",
        )
        pair_ref = raw["pair_ref"]
        if (
            not isinstance(pair_ref, str)
            or _PAIR_REF_RE.fullmatch(pair_ref) is None
            or pair_ref in seen_refs
        ):
            raise CalibrationError("calibration pair reference is invalid")
        seen_refs.add(pair_ref)
        expected = _boolean(raw["expected_same_episode"], "pair expected")
        predicted = _boolean(raw["predicted_same_episode"], "pair predicted")
        if expected and predicted:
            pair_true_positive += 1
        elif predicted:
            pair_false_positive += 1
        elif expected:
            pair_false_negative += 1

    ordered_detectors = dict(sorted(detector_classes.items()))
    detector_metrics: dict[str, JsonValue] = {
        detector: _fraction(
            counters[detector]["true_positive"],
            counters[detector]["predicted_positive"],
        )
        for detector in ordered_detectors
    }
    metrics: dict[str, JsonValue] = {
        "detector_precision": detector_metrics,
        "approval_auth_safety_recall": _fraction(
            category_counters[ClassificationCategory.APPROVAL_AUTH_SAFETY][
                "true_positive"
            ],
            category_counters[ClassificationCategory.APPROVAL_AUTH_SAFETY][
                "expected_positive"
            ],
        ),
        "semantic_friction_recall": _fraction(
            category_counters[ClassificationCategory.SEMANTIC_FRICTION][
                "true_positive"
            ],
            category_counters[ClassificationCategory.SEMANTIC_FRICTION][
                "expected_positive"
            ],
        ),
        "episode_boundary_pairwise_f1": _fraction(
            2 * pair_true_positive,
            2 * pair_true_positive + pair_false_positive + pair_false_negative,
        ),
        "privacy_holdout": _fraction(
            int(privacy_holdout["case_count"]) if privacy_holdout["passed"] else 0,
            int(privacy_holdout["case_count"]),
        ),
    }
    thresholds: dict[str, JsonValue] = {
        **{
            name: _fraction(*minimum) for name, minimum in _CORE_METRIC_MINIMUMS.items()
        },
        "detector_precision": {
            detector: _fraction(*_detector_threshold(category))
            for detector, category in ordered_detectors.items()
        },
    }
    sample_counts: dict[str, JsonValue] = {
        "detector_precision": {
            detector: {
                "expected_negative": counters[detector]["expected_negative"],
                "expected_positive": counters[detector]["expected_positive"],
                "metric_support": counters[detector]["predicted_positive"],
            }
            for detector in ordered_detectors
        },
        "approval_auth_safety_recall": category_counters[
            ClassificationCategory.APPROVAL_AUTH_SAFETY
        ]["expected_positive"],
        "semantic_friction_recall": category_counters[
            ClassificationCategory.SEMANTIC_FRICTION
        ]["expected_positive"],
        "episode_boundary_pairwise_f1": (
            pair_true_positive + pair_false_positive + pair_false_negative
        ),
        "privacy_holdout": int(privacy_holdout["case_count"]),
    }
    minimum_samples: dict[str, JsonValue] = {
        **dict(_CORE_MINIMUM_SAMPLES),
        "detector_precision": {
            detector: {
                field: MIN_CLASSIFICATION_SAMPLES
                for field in sorted(_DETECTOR_SUPPORT_FIELDS)
            }
            for detector in ordered_detectors
        },
    }
    passed = any(
        category is ClassificationCategory.SEMANTIC_FRICTION
        for category in ordered_detectors.values()
    ) and all(
        _meets(
            metrics[name]["numerator"],  # type: ignore[index]
            metrics[name]["denominator"],  # type: ignore[index]
            minimum,
        )
        and int(sample_counts[name]) >= _CORE_MINIMUM_SAMPLES[name]
        for name, minimum in _CORE_METRIC_MINIMUMS.items()
    )
    passed = passed and all(
        _meets(
            detector_metrics[detector]["numerator"],  # type: ignore[index]
            detector_metrics[detector]["denominator"],  # type: ignore[index]
            _detector_threshold(category),
        )
        and all(
            counters[detector][field] >= MIN_CLASSIFICATION_SAMPLES
            for field in (
                "expected_negative",
                "expected_positive",
                "predicted_positive",
            )
        )
        for detector, category in ordered_detectors.items()
    )
    corpus_commitment = "sha256:" + canonical_sha256(dict(corpus))  # type: ignore[arg-type]
    placeholder = "0" * 64
    draft = CalibrationReceipt(
        receipt_ref=CALIBRATION_RECEIPT_REF_PREFIX + placeholder,
        identity_key_id=identity.key_id,
        corpus_commitment=corpus_commitment,
        configuration_root=configuration_root,
        production_configuration_root=bound_configuration_root,
        production_configuration_ref=bound_configuration_ref,
        model_era=model_era,
        policy_era=policy_era,
        detector_classes={
            detector: category.value for detector, category in ordered_detectors.items()
        },
        metrics=metrics,
        thresholds=thresholds,
        sample_counts=sample_counts,
        minimum_samples=minimum_samples,
        privacy_holdout=privacy_holdout,
        passed=passed,
        authentication_tag=CALIBRATION_AUTH_PREFIX + placeholder,
    )
    body = draft.unsigned_dict()
    return replace(
        draft,
        receipt_ref=_receipt_ref(identity, body),
        authentication_tag=_authentication_tag(identity, body),
    )


def verify_calibration_receipt(
    identity: IdentityKey,
    receipt: CalibrationReceipt | Mapping[str, object],
    *,
    expected_configuration_root: str | None = None,
    expected_production_configuration_root: str | None = None,
    expected_model_era: str | None = None,
    expected_policy_era: str | None = None,
) -> CalibrationReceipt:
    restored = CalibrationReceipt.from_dict(
        receipt.to_dict() if isinstance(receipt, CalibrationReceipt) else receipt
    )
    if restored.identity_key_id != identity.key_id:
        raise CalibrationError("calibration receipt identity does not match")
    if (
        expected_configuration_root is not None
        and restored.configuration_root != expected_configuration_root
    ):
        raise CalibrationError("calibration configuration root does not match")
    if (
        expected_production_configuration_root is not None
        and restored.production_configuration_root
        != expected_production_configuration_root
    ):
        raise CalibrationError("production configuration root does not match")
    if expected_model_era is not None and restored.model_era != expected_model_era:
        raise CalibrationError("production model era does not match")
    if expected_policy_era is not None and restored.policy_era != expected_policy_era:
        raise CalibrationError("production policy era does not match")
    derived_configuration_ref = str(
        identity.derive_ref(
            RefType.CONFIGURATION,
            {"parts": [restored.production_configuration_root]},
        )
    )
    if not hmac.compare_digest(
        restored.production_configuration_ref,
        derived_configuration_ref,
    ):
        raise CalibrationError(
            "production configuration ref is not derived from its signed root"
        )
    body = restored.unsigned_dict()
    if not hmac.compare_digest(
        restored.receipt_ref, _receipt_ref(identity, body)
    ) or not hmac.compare_digest(
        restored.authentication_tag,
        _authentication_tag(identity, body),
    ):
        raise CalibrationError("calibration receipt authentication failed")
    if restored.passed is not True:
        raise CalibrationError("calibration gate did not pass")
    return restored
