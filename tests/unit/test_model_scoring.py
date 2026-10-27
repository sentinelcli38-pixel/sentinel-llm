import json

import pytest

from sentinel.modeling.scoring import (
    majority_category_baseline,
    parse_findings,
    score_predictions,
)


def test_majority_baseline_selects_from_training_only() -> None:
    def row(category):
        return {"messages": [{"content": json.dumps({"findings": [{"category": category, "lines": [1]}]})}]}

    train = [row("reentrancy"), row("reentrancy"), row("arithmetic")]
    test = [row("arithmetic"), row("arithmetic"), row("reentrancy")]
    result = majority_category_baseline(train, test)
    assert result["category"] == "reentrancy"
    assert result["category_recall"] == pytest.approx(1 / 3)


def test_unrelated_warning_cannot_count_as_expected_vulnerability() -> None:
    report = score_predictions([
        {"id": "wrong", "expected": '{"findings":[{"category":"arithmetic","lines":[8]}]}',
         "prediction": '{"findings":[{"category":"access_control","lines":[8]}]}'},
        {"id": "wrong-line", "expected": '{"findings":[{"category":"arithmetic","lines":[8]}]}',
         "prediction": '{"findings":[{"category":"arithmetic","lines":[3]}]}'},
        {"id": "bad-json", "expected": '{"findings":[{"category":"arithmetic","lines":[8]}]}',
         "prediction": "The contract looks safe."},
    ])
    assert report["category_recall"] == pytest.approx(1 / 3)
    assert report["localized_category_recall"] == 0.0
    assert report["json_valid_rate"] == pytest.approx(2 / 3)


def test_invalid_lines_and_categories_are_rejected() -> None:
    with pytest.raises(ValueError):
        parse_findings('{"findings":[{"category":"solc-version","lines":[1]}]}')
    with pytest.raises(ValueError):
        parse_findings('{"findings":[{"category":"reentrancy","lines":[true]}]}')
