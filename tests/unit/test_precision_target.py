import copy
import hashlib
import json

import pytest

from sentinel.modeling.properties import property_messages
from training.frozen_probe import evaluate
from training.precision_target import assess, verify_report


def row(key, truth):
    source = f"contract Example_{key} {{}}"
    return {"id": key, "swc": "104", "task": "swc_property", "contract": f"Example_{key}",
            "source_hash": hashlib.sha256(source.encode()).hexdigest(),
            "messages": [*property_messages(source, "104", f"Example_{key}"),
                         {"role": "assistant", "content": json.dumps({"swc": "104", "vulnerable": truth})}]}


def test_zero_false_positives_without_positive_predictions_never_passes():
    rows = [row("positive", True), row("negative", False)]
    report = evaluate(rows, {"positive": -1.0, "negative": -1.0})
    result = assess(report["scores"])
    assert not result["numerical_requirements_met"]
    assert result["precision_intervals"]["overall"]["lower"] is None
    assert result["failures"]["104"]
    assert not result["independent_99_percent_claim_supported"]


def test_tiny_perfect_subset_cannot_establish_the_target():
    rows = [row("positive", True), row("negative", False)]
    report = evaluate(rows, {"positive": 1.0, "negative": -1.0})
    assert report["scores"]["precision"] == 1
    result = assess(report["scores"])
    assert not result["numerical_requirements_met"]
    assert any("support" in error for error in result["failures"]["104"])


def test_overall_success_cannot_hide_an_unassessed_or_failed_property():
    rows = [row("positive", True), row("negative", False)]
    scores = evaluate(rows, {"positive": 1.0, "negative": -1.0})["scores"]
    scores.update(tp=400, fp=0, tn=400, fn=0, precision=1.0, recall=1.0, specificity=1.0)
    result = assess(scores)
    assert result["failures"]["overall"] == []
    assert result["failures"]["107"]
    assert not result["numerical_requirements_met"]


@pytest.mark.parametrize("mode", ["valid", "missing", "duplicate", "label", "margin", "score", "metrics", "decision"])
def test_full_prediction_evidence_is_recomputed_before_claim_audit(mode):
    rows = [row("positive", True), row("negative", False)]
    report = copy.deepcopy(evaluate(rows, {"positive": 1.0, "negative": -1.0}))
    if mode == "missing":
        report["predictions"].pop()
    elif mode == "duplicate":
        report["predictions"][1] = report["predictions"][0]
    elif mode == "label":
        report["predictions"][0]["expected"] = '{"swc":"104","vulnerable":false}'
    elif mode == "margin":
        report["predictions"][0]["classifier_margin"] = float("nan")
    elif mode == "score":
        report["predictions"][0]["classifier_score"] = 0.99
    elif mode == "metrics":
        report["scores"]["precision"] = 0.99
    elif mode == "decision":
        report["predictions"][0]["prediction"] = '{"swc":"104","vulnerable":false}'
    if mode == "valid":
        verify_report(report, rows)
    else:
        with pytest.raises(ValueError):
            verify_report(report, rows)
