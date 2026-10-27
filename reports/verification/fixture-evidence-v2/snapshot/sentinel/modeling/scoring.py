import json
from collections import Counter

from sentinel.modeling.data import CATEGORIES


def majority_category_baseline(training_rows: list[dict], test_rows: list[dict]) -> dict:
    counts = Counter(
        category for row in training_rows
        for category in {finding["category"] for finding in parse_findings(row["messages"][-1]["content"])}
    )
    if not counts:
        raise ValueError("Training labels are required for the majority baseline")
    category = min(counts, key=lambda candidate: (-counts[candidate], candidate))
    labels = [
        {finding["category"] for finding in parse_findings(row["messages"][-1]["content"])}
        for row in test_rows
    ]
    total = sum(len(categories) for categories in labels)
    return {
        "category": category,
        "category_recall": sum(category in categories for categories in labels) / total if total else None,
        "scope": "Always predicts the most frequent training category; does not localize source lines.",
    }


def parse_findings(text: str) -> list[dict]:
    text = text.strip()
    if text.startswith("```json") and text.endswith("```"):
        text = text[7:-3].strip()
    document = json.loads(text)
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise TypeError("Expected a findings array")
    for finding in document["findings"]:
        if not isinstance(finding, dict) or finding.get("category") not in CATEGORIES:
            raise ValueError("Unsupported finding category")
        lines = finding.get("lines")
        if not isinstance(lines, list) or not lines or any(type(line) is not int or line < 1 for line in lines):
            raise ValueError("Expected positive original source line numbers")
    return document["findings"]


def score_predictions(rows: list[dict]) -> dict:
    categories_total = categories_found = locations_found = valid = 0
    details = []
    for row in rows:
        expected = parse_findings(row["expected"])
        try:
            actual = parse_findings(row["prediction"])
            error = ""
            valid += 1
        except (ValueError, TypeError) as exc:
            actual = []
            error = str(exc)
        expected_categories = {finding["category"] for finding in expected}
        predicted_categories = {finding["category"] for finding in actual}
        matched = expected_categories & predicted_categories
        localized = {
            finding["category"] for finding in expected
            if any(candidate["category"] == finding["category"] and set(candidate["lines"]) & set(finding["lines"]) for candidate in actual)
        }
        categories_total += len(expected_categories)
        categories_found += len(matched)
        locations_found += len(localized)
        details.append({"id": row["id"], "category_matches": sorted(matched), "localized_matches": sorted(localized), "format_error": error})
    return {
        "cases": len(rows), "expected_case_category_pairs": categories_total,
        "category_recall": categories_found / categories_total if categories_total else None,
        "localized_category_recall": locations_found / categories_total if categories_total else None,
        "json_valid_rate": valid / len(rows) if rows else None,
        "precision": None, "f1": None,
        "scope": "Recall against annotated categories; precision/F1 require reviewed clean controls and complete annotation.",
        "cases_detail": details,
    }
