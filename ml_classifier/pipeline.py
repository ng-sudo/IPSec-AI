from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import (
        accuracy_score,
        balanced_accuracy_score,
        confusion_matrix,
        f1_score,
        log_loss,
        precision_score,
        recall_score,
    )
    from sklearn.pipeline import Pipeline
except ImportError as exc:  # pragma: no cover - gives a useful runtime message
    raise ImportError("ML classification requires scikit-learn, joblib, and numpy") from exc

from dataset.models import DatasetManifest, DatasetRecord

MODEL_VERSION = "ipsec-esp-traffic-classifier/1.0"
TARGET_FIELD = "traffic_type"
SPLITS = ("train", "validation", "test")


class EvaluationMetrics:
    """JSON-serializable classification metrics for one dataset split."""

    def __init__(self, split: str, labels: Sequence[str], y_true: Sequence[str], y_pred: Sequence[str], probabilities: Any):
        self.split = split
        self.sample_count = len(y_true)
        self.labels = list(labels)
        self.accuracy = float(accuracy_score(y_true, y_pred))
        self.precision_macro = float(precision_score(y_true, y_pred, labels=self.labels, average="macro", zero_division=0))
        self.recall_macro = float(recall_score(y_true, y_pred, labels=self.labels, average="macro", zero_division=0))
        self.f1_macro = float(f1_score(y_true, y_pred, labels=self.labels, average="macro", zero_division=0))
        self.precision_weighted = float(precision_score(y_true, y_pred, labels=self.labels, average="weighted", zero_division=0))
        self.recall_weighted = float(recall_score(y_true, y_pred, labels=self.labels, average="weighted", zero_division=0))
        self.f1_weighted = float(f1_score(y_true, y_pred, labels=self.labels, average="weighted", zero_division=0))
        self.balanced_accuracy = float(balanced_accuracy_score(y_true, y_pred))
        self.confusion_matrix = confusion_matrix(y_true, y_pred, labels=self.labels).tolist()
        self.log_loss = float(log_loss(y_true, probabilities, labels=self.labels)) if probabilities is not None else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "split": self.split,
            "sample_count": self.sample_count,
            "labels": self.labels,
            "accuracy": self.accuracy,
            "precision_macro": self.precision_macro,
            "recall_macro": self.recall_macro,
            "f1_macro": self.f1_macro,
            "precision_weighted": self.precision_weighted,
            "recall_weighted": self.recall_weighted,
            "f1_weighted": self.f1_weighted,
            "balanced_accuracy": self.balanced_accuracy,
            "log_loss": self.log_loss,
            "confusion_matrix": self.confusion_matrix,
        }


class Prediction:
    def __init__(self, predicted_traffic_type: str, confidence: float, model_version: str):
        self.predicted_traffic_type = predicted_traffic_type
        self.confidence = confidence
        self.model_version = model_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predicted_traffic_type": self.predicted_traffic_type,
            "confidence": self.confidence,
            "model_version": self.model_version,
        }


class ClassifierBundle:
    def __init__(
        self,
        model_version: str,
        model_name: str,
        feature_names: Sequence[str],
        classes: Sequence[str],
        pipeline: Pipeline,
        validation_metrics: Mapping[str, Any],
        test_metrics: Mapping[str, Any],
        training_metadata: Mapping[str, Any],
    ):
        self.model_version = model_version
        self.model_name = model_name
        self.feature_names = list(feature_names)
        self.classes = list(classes)
        self.pipeline = pipeline
        self.validation_metrics = dict(validation_metrics)
        self.test_metrics = dict(test_metrics)
        self.training_metadata = dict(training_metadata)


def _numeric_value(value: Any) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return float("nan")


def _feature_names(records: Iterable[DatasetRecord]) -> List[str]:
    names = set()
    for record in records:
        for name, value in record.flow_features.items():
            if isinstance(value, (int, float, bool)) and not isinstance(value, str):
                names.add(name)
    if not names:
        raise ValueError("dataset contains no numeric flow features")
    return sorted(names)


def _matrix(records: Sequence[DatasetRecord], feature_names: Sequence[str]) -> np.ndarray:
    return np.asarray(
        [[_numeric_value(record.flow_features.get(name)) for name in feature_names] for record in records],
        dtype=float,
    )


def _labels(records: Sequence[DatasetRecord]) -> List[str]:
    values = [record.traffic_type for record in records]
    if any(not value for value in values):
        raise ValueError("dataset contains missing traffic labels")
    return values


def _load_manifest(path: str | Path) -> DatasetManifest:
    manifest_path = Path(path)
    try:
        return DatasetManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot load dataset manifest {manifest_path}: {exc}") from exc


def _split_records(manifest: DatasetManifest, split: str) -> List[DatasetRecord]:
    if split not in SPLITS:
        raise ValueError(f"unknown split: {split}")
    records = [record for record in manifest.records if record.split == split]
    if not records:
        raise ValueError(f"dataset split is empty: {split}")
    return records


def _candidate_models(seed: int) -> Dict[str, Pipeline]:
    return {
        "random_forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(
                n_estimators=200,
                class_weight="balanced",
                random_state=seed,
                n_jobs=-1,
            )),
        ]),
        "gradient_boosting": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", GradientBoostingClassifier(random_state=seed)),
        ]),
    }


def _validate_group_boundary(manifest: DatasetManifest) -> None:
    groups: Dict[str, set[str]] = {}
    for record in manifest.records:
        groups.setdefault(record.scenario_id, set()).add(record.split)
    leaked = {group: sorted(splits) for group, splits in groups.items() if len(splits) > 1}
    if leaked:
        raise ValueError(f"scenario leakage detected before training: {leaked}")
    captures: Dict[str, set[str]] = {}
    for record in manifest.records:
        captures.setdefault(record.capture_id, set()).add(record.split)
    capture_leaks = {capture: sorted(splits) for capture, splits in captures.items() if len(splits) > 1}
    if capture_leaks:
        raise ValueError(f"capture leakage detected before training: {capture_leaks}")


def _evaluate(model: Pipeline, records: Sequence[DatasetRecord], feature_names: Sequence[str], labels: Sequence[str], split: str) -> EvaluationMetrics:
    x_values = _matrix(records, feature_names)
    y_values = _labels(records)
    predictions = model.predict(x_values)
    probabilities = model.predict_proba(x_values) if hasattr(model, "predict_proba") else None
    return EvaluationMetrics(split, labels, y_values, predictions, probabilities)


def train_classifier(
    manifest_path: str | Path,
    model_path: str | Path,
    *,
    seed: int = 26160,
) -> ClassifierBundle:
    """Select, train, evaluate, and persist the best flow-feature classifier."""

    manifest = _load_manifest(manifest_path)
    _validate_group_boundary(manifest)
    train_records = _split_records(manifest, "train")
    validation_records = _split_records(manifest, "validation")
    test_records = _split_records(manifest, "test")
    all_records = train_records + validation_records + test_records
    feature_names = _feature_names(all_records)
    y_train = _labels(train_records)
    classes = sorted(set(_labels(all_records)))
    if len(set(y_train)) < 2:
        raise ValueError("training split must contain at least two traffic classes")
    if not set(classes).issubset(set(y_train)):
        missing = sorted(set(classes) - set(y_train))
        raise ValueError(f"training split is missing traffic classes present elsewhere: {missing}")

    candidates = _candidate_models(seed)
    validation_results: Dict[str, Dict[str, Any]] = {}
    best_name = ""
    best_score = -1.0
    best_model: Pipeline | None = None
    for name, candidate in candidates.items():
        candidate.fit(_matrix(train_records, feature_names), y_train)
        metrics = _evaluate(candidate, validation_records, feature_names, classes, "validation")
        validation_results[name] = metrics.to_dict()
        if metrics.f1_macro > best_score:
            best_name = name
            best_score = metrics.f1_macro
            best_model = candidate
    if best_model is None:
        raise RuntimeError("no classifier was selected")

    test_metrics = _evaluate(best_model, test_records, feature_names, classes, "test")
    bundle = ClassifierBundle(
        model_version=MODEL_VERSION,
        model_name=best_name,
        feature_names=feature_names,
        classes=classes,
        pipeline=best_model,
        validation_metrics={"selected_model": best_name, "candidates": validation_results},
        test_metrics=test_metrics.to_dict(),
        training_metadata={
            "target": TARGET_FIELD,
            "feature_source": "dataset_record.flow_features",
            "payload_contents_used": False,
            "scenario_group_boundary_checked": True,
            "seed": seed,
            "train_count": len(train_records),
            "validation_count": len(validation_records),
            "test_count": len(test_records),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    save_bundle(bundle, model_path)
    return bundle


def save_bundle(bundle: ClassifierBundle, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_bundle(path: str | Path) -> ClassifierBundle:
    try:
        bundle = joblib.load(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot load model bundle {path}: {exc}") from exc
    if not isinstance(bundle, ClassifierBundle):
        raise ValueError(f"invalid classifier bundle: {path}")
    return bundle


def predict_record(bundle_or_path: ClassifierBundle | str | Path, record: DatasetRecord) -> Prediction:
    bundle = bundle_or_path if isinstance(bundle_or_path, ClassifierBundle) else load_bundle(bundle_or_path)
    return predict_flow_features(bundle, record.flow_features)


def predict_flow_features(bundle_or_path: ClassifierBundle | str | Path, flow_features: Mapping[str, Any]) -> Prediction:
    """Predict from extracted flow features without requiring a ground-truth label."""

    bundle = bundle_or_path if isinstance(bundle_or_path, ClassifierBundle) else load_bundle(bundle_or_path)
    values = np.asarray([[_numeric_value(flow_features.get(name)) for name in bundle.feature_names]], dtype=float)
    probabilities = bundle.pipeline.predict_proba(values)[0]
    index = int(np.argmax(probabilities))
    return Prediction(
        predicted_traffic_type=str(bundle.classes[index]),
        confidence=float(probabilities[index]),
        model_version=bundle.model_version,
    )


def evaluate_bundle(bundle_or_path: ClassifierBundle | str | Path, manifest_path: str | Path) -> Dict[str, Any]:
    bundle = bundle_or_path if isinstance(bundle_or_path, ClassifierBundle) else load_bundle(bundle_or_path)
    manifest = _load_manifest(manifest_path)
    _validate_group_boundary(manifest)
    records = _split_records(manifest, "test")
    metrics = _evaluate(bundle.pipeline, records, bundle.feature_names, bundle.classes, "test")
    return metrics.to_dict()
