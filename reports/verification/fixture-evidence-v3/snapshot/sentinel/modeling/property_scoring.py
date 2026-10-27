"""Strict property-level metrics that do not treat invalid output as a true negative."""

import json
from collections import Counter

from sentinel.modeling.properties import PROPERTIES


def parse_property(text: str, swc: str | None = None) -> dict:
    text = text.strip()
    if text.startswith("```json") and text.endswith("```"):
        text = text[7:-3].strip()
    result = json.loads(text)
    if not isinstance(result, dict) or set(result) != {"swc", "vulnerable"}:
        raise ValueError("Expected only swc and vulnerable fields")
    if not isinstance(result["swc"], str) or result["swc"] not in PROPERTIES or type(result["vulnerable"]) is not bool:
        raise ValueError("Unsupported SWC or non-Boolean prediction")
    if swc is not None and result["swc"] != swc:
        raise ValueError("Prediction assesses a different SWC property")
    return result


def _metrics(counts: Counter) -> dict:
    tp, fp, tn, fn, invalid_positive, invalid_negative = (counts[key] for key in ("tp", "fp", "tn", "fn", "invalid_positive", "invalid_negative"))
    positives = tp + fn + invalid_positive
    negatives = tn + fp + invalid_negative
    cases = positives + negatives
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / positives if positives else None
    specificity = tn / negatives if negatives else None
    return {
        "cases": cases, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "invalid_positive": invalid_positive, "invalid_negative": invalid_negative,
        "precision": precision, "recall": recall,
        "f1": 2 * tp / (2 * tp + fp + fn + invalid_positive) if 2 * tp + fp + fn + invalid_positive else None,
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None,
        "false_positive_rate": fp / negatives if negatives else None,
        "negative_error_rate": (fp + invalid_negative) / negatives if negatives else None,
        "accuracy": (tp + tn) / cases if cases else None,
        "valid_rate": (tp + fp + tn + fn) / cases if cases else None,
    }


def score_properties(rows: list[dict]) -> dict:
    counts = Counter()
    per_swc = {swc: Counter() for swc in PROPERTIES}
    details = []
    for row in rows:
        target = parse_property(row["expected"])
        error = ""
        try:
            actual = parse_property(row["prediction"], target["swc"])
            label = ("tp" if actual["vulnerable"] else "fn") if target["vulnerable"] else ("fp" if actual["vulnerable"] else "tn")
        except (ValueError, TypeError) as exc:
            label = "invalid_positive" if target["vulnerable"] else "invalid_negative"
            error = str(exc)
        counts[label] += 1
        per_swc[target["swc"]][label] += 1
        details.append({"id": row["id"], "swc": target["swc"], "outcome": label, "format_error": error})
    return {**_metrics(counts), "per_swc": {swc: _metrics(value) for swc, value in per_swc.items()},
            "scope": "Property-level historical CGT labels, not whole-contract safety or line localization. Invalid answers are failures, never true negatives.",
            "cases_detail": details}


def property_baselines(train: list[dict], evaluation: list[dict]) -> dict:
    labels = {swc: Counter() for swc in PROPERTIES}
    for row in train:
        target = parse_property(row["messages"][-1]["content"])
        labels[target["swc"]][target["vulnerable"]] += 1
    if any(not values for values in labels.values()):
        raise ValueError("Every property needs training labels for its majority baseline")
    majority = {swc: values[True] > values[False] for swc, values in labels.items()}
    results = {}
    for name in ("always_negative", "always_positive", "training_majority"):
        rows = []
        for row in evaluation:
            target = parse_property(row["messages"][-1]["content"])
            prediction = {"swc": target["swc"], "vulnerable": majority[target["swc"]] if name == "training_majority" else name == "always_positive"}
            rows.append({"id": row["id"], "expected": row["messages"][-1]["content"], "prediction": json.dumps(prediction)})
        results[name] = score_properties(rows)
    return results


def validation_gate(scores: dict, baselines: dict) -> dict:
    thresholds = {"valid_rate": 1.0, "balanced_accuracy": 0.65, "recall": 0.5, "specificity": 0.8}
    failures = [f"{key} below {threshold}" for key, threshold in thresholds.items()
                if scores.get(key) is None or scores[key] < threshold]
    best_baseline = max(result["accuracy"] for result in baselines.values())
    if scores["accuracy"] <= best_baseline:
        failures.append("Accuracy does not exceed the strongest simple baseline")
    return {"passed": not failures, "thresholds": thresholds, "best_baseline_accuracy": best_baseline,
            "failures": failures, "scope": "A development gate for further evaluation, not permission for production use."}
