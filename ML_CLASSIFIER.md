# Encrypted ESP Traffic Classifier

The `ml_classifier` package predicts the traffic type of an encrypted ESP flow from the prepared dataset's scalar `flow_features`. It does not inspect encrypted payload contents and does not use VPN configuration, scenario identifiers, or ground-truth labels as model features.

## Training

```bash
python3 -m ml_classifier train dataset/processed/manifest.json models/esp-traffic.joblib
```

The trainer:

1. Reads the existing scenario-level train, validation, and test assignments.
2. Selects numeric flow features only.
3. Imputes missing numeric values with training medians.
4. Fits Random Forest and Gradient Boosting candidates.
5. Selects the candidate with the highest measured validation macro-F1, with deterministic candidate order for ties.
6. Evaluates the selected model once on the held-out test split.
7. Persists preprocessing, model, feature names, class order, version, and measured metrics with `joblib`.

XGBoost and LightGBM are not used because they are not present in the current environment and are not required for this component.

## Prediction

```bash
python3 -m ml_classifier predict models/esp-traffic.joblib record.json
```

Prediction output contains `predicted_traffic_type`, probability-based `confidence`, and `model_version`.

## Metrics

The trainer reports accuracy, macro and weighted precision/recall/F1, balanced accuracy, log loss, and a confusion matrix for validation candidates and the selected test model. No performance values are hard-coded; all values come from the supplied dataset.

## Limitations

- Performance is only meaningful when the capture collection covers representative traffic and scenario diversity.
- Scenario-level splitting prevents direct scenario leakage, but cannot remove all environmental correlation in a controlled testbed.
- Confidence is the highest class probability returned by the fitted model, not a calibrated guarantee of correctness.
- Missing flow features are median-imputed from training data; excessive missingness can make predictions unreliable.
- The classifier predicts only the traffic classes present in training and cannot identify an unseen class.
- The model uses packet sizes, timing, counts, rates, directionality, and ESP metadata derived by the feature layer; encrypted payload contents are excluded.
